"""Identity authentication and session management."""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import uuid
from datetime import datetime
from typing import Any

import asyncpg
import redis.asyncio as aioredis

from interlock.admin.auth import verify_password
from interlock.config import AuthConfig
from interlock.core.oidc import OIDCProvider, OIDCVerificationError
from interlock.errors import IdentityNotFoundError
from interlock.models import AgentType, IdentityContext
from interlock.security.api_keys import (
    HMAC_SHA256,
    candidate_api_key_hashes,
    hash_api_key_for_storage,
    legacy_api_key_hash,
)

logger = logging.getLogger(__name__)

_IDENTITY_QUERY = """
SELECT id, name, agent_type, team, roles, mapped_pg_role, metadata,
       api_key_hash, COALESCE(api_key_hash_version, 'sha256-v1') AS api_key_hash_version
FROM identities
WHERE api_key_hash = ANY($1::text[]) AND enabled = TRUE
"""

_IDENTITY_BY_ID_QUERY = """
SELECT id, name, agent_type, team, roles, mapped_pg_role, metadata
FROM identities
WHERE id = $1 AND enabled = TRUE
"""

_PG_IDENTITY_QUERY = """
SELECT id, name, agent_type, team, roles, mapped_pg_role, metadata, pg_password_hash
FROM identities
WHERE enabled = TRUE
  AND pg_password_hash IS NOT NULL
  AND (
    LOWER(pg_username) = LOWER($1)
    OR (pg_username IS NULL AND LOWER(name) = LOWER($1))
  )
ORDER BY CASE WHEN LOWER(pg_username) = LOWER($1) THEN 0 ELSE 1 END
LIMIT 1
"""

_OIDC_IDENTITY_QUERY = """
SELECT id, name, agent_type, team, roles, mapped_pg_role, metadata
FROM identities
WHERE oidc_subject = $1 AND enabled = TRUE
LIMIT 1
"""


def _agent_type_or_default(raw: object, identity_name: object) -> AgentType:
    """Read an identity's agent_type, tolerating a value the enum does not know.

    `agent_type` is descriptive - it names the kind of client, and no
    authorization decision reads it. But parsing it strictly meant a row with
    an unrecognised value raised while the identity context was being built,
    and the failure reached the caller as 401 "Invalid API key". That sends an
    operator to re-issue a credential that was never wrong; it cost several
    rounds of diagnosis here, against a key whose hash matched exactly.

    So this fails *soft* and loud: the identity still works, and the log names
    the identity and the offending value so the row can be corrected. The
    write path now rejects such values outright, so this only ever sees rows
    written before that validation existed or by direct SQL.
    """
    try:
        return AgentType(raw)
    except ValueError:
        logger.warning(
            "identity %r has an unrecognised agent_type %r; treating it as %r. "
            "Correct the row: agent_type must be one of %s.",
            identity_name,
            raw,
            AgentType.CUSTOM.value,
            sorted(member.value for member in AgentType),
        )
        return AgentType.CUSTOM


class AuthManager:
    """Validates API keys and manages Redis-backed sessions."""

    def __init__(
        self,
        pg_pool: asyncpg.Pool,
        redis_client: aioredis.Redis | None,
        config: AuthConfig,
        oidc_provider: OIDCProvider | None = None,
    ) -> None:
        self._pool = pg_pool
        self._redis = redis_client
        self._config = config
        self._oidc_provider = oidc_provider

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def current_identity(self, identity_id: int) -> IdentityContext:
        """Reload a queued actor and active grants without an API key/session."""
        row = await self._fetch_identity_by_id(identity_id)
        if row is None:
            raise IdentityNotFoundError("Original approval actor is disabled or missing")
        return await self._build_context(row, auth_method="approval")

    async def authenticate(self, api_key: str) -> IdentityContext:
        """Authenticate an API key and return an IdentityContext.

        Flow:
        1. Hash the key, check Redis for a cached session.
        2. On cache miss, query the identities table.
        3. Build an IdentityContext, cache it in Redis, and return it.
        """
        if self._looks_like_jwt(api_key):
            return await self.authenticate_oidc(api_key)

        candidates = candidate_api_key_hashes(api_key, self._config)
        key_hash, _ = candidates[0]
        cache_key = f"session:{key_hash}"

        # 1 - try Redis session cache (best-effort)
        cached = await self._redis_get(cache_key)
        if cached is not None:
            ctx = IdentityContext.model_validate_json(cached)
            refreshed = await self._refresh_cached_context(cache_key, ctx)
            if refreshed is None:
                raise IdentityNotFoundError("Unknown or disabled API key")
            return refreshed

        # 2 - query PG
        row = await self._fetch_identity([value for value, _ in candidates])
        if row is None:
            raise IdentityNotFoundError("Unknown or disabled API key")

        await self._upgrade_legacy_api_key(row, api_key)

        # Bookkeeping: record that this key was used. Best-effort; we
        # never want auth to fail because the bookkeeping update did.
        # Migration 003 added ``last_used_at``; the column may not exist
        # in older installs, so we swallow exceptions silently here.
        try:
            await self._pool.execute(
                "UPDATE identities SET last_used_at = NOW() WHERE id = $1",
                row["id"],
            )
        except Exception:
            logger.debug("identities.last_used_at update failed", exc_info=True)

        # 3 - build context
        ctx = await self._build_context(row)

        # cache under both the key-hash lookup key and the session-id key
        payload = ctx.model_dump_json().encode()
        ttl = self._config.session_ttl_seconds
        await self._redis_set(cache_key, payload, ttl)
        await self._redis_set(f"session:{ctx.session_id}", payload, ttl)

        return ctx

    async def authenticate_oidc(self, bearer_token: str) -> IdentityContext:
        """Verify an agent JWT and map it to a pre-provisioned identity.

        IdP claims identify the caller only. Roles, mapped database roles, and
        source access are always loaded from the InterLock control database.
        """
        if not self._config.oidc.enabled or self._oidc_provider is None:
            raise IdentityNotFoundError("OIDC agent authentication is not enabled")
        try:
            user_info = await self._oidc_provider.verify_token(bearer_token)
        except OIDCVerificationError as exc:
            raise IdentityNotFoundError("Invalid bearer token") from exc
        except Exception as exc:
            logger.warning("OIDC verification backend unavailable", exc_info=True)
            raise IdentityNotFoundError("Bearer token could not be verified") from exc

        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(_OIDC_IDENTITY_QUERY, user_info.sub)
        if row is None:
            raise IdentityNotFoundError("OIDC identity is not provisioned or is disabled")

        try:
            await self._pool.execute(
                "UPDATE identities SET last_used_at = NOW() WHERE id = $1",
                row["id"],
            )
        except Exception:
            logger.debug("identities.last_used_at update failed", exc_info=True)

        ctx = await self._build_context(row, auth_method="oidc_jwt")
        if ctx.session_id:
            await self._redis_set(
                f"session:{ctx.session_id}",
                ctx.model_dump_json().encode(),
                self._config.session_ttl_seconds,
            )
        return ctx

    async def authenticate_pg(self, username: str, password: str) -> IdentityContext:
        """Authenticate a PostgreSQL client login.

        PG wire clients authenticate with a username plus password. InterLock
        accepts either an InterLock API key in the password field or a
        dedicated PostgreSQL-style password hash stored on the identity. The
        returned IdentityContext is always the InterLock identity, never an
        upstream database role.
        """
        if not password:
            raise IdentityNotFoundError("Missing PostgreSQL password")

        # First-class InterLock API key path. The startup username is treated
        # as a client hint; the API key determines the authoritative identity.
        try:
            return await self.authenticate(password)
        except IdentityNotFoundError:
            pass

        if not username:
            raise IdentityNotFoundError("Missing PostgreSQL username")

        row = await self._fetch_pg_identity(username)
        if row is None or not row["pg_password_hash"]:
            raise IdentityNotFoundError("Unknown or disabled PostgreSQL identity")
        if not verify_password(password, row["pg_password_hash"]):
            raise IdentityNotFoundError("Invalid PostgreSQL password")

        try:
            await self._pool.execute(
                "UPDATE identities SET last_used_at = NOW() WHERE id = $1",
                row["id"],
            )
        except Exception:
            logger.debug("identities.last_used_at update failed", exc_info=True)

        ctx = await self._build_context(row, auth_method="postgres_password")
        payload = ctx.model_dump_json().encode()
        ttl = self._config.session_ttl_seconds
        if ctx.session_id:
            await self._redis_set(f"session:{ctx.session_id}", payload, ttl)
        return ctx

    async def get_session(self, session_id: str) -> IdentityContext | None:
        """Look up an existing session by its ID."""
        data = await self._redis_get(f"session:{session_id}")
        if data is None:
            return None
        ctx = IdentityContext.model_validate_json(data)
        return await self._refresh_cached_context(f"session:{session_id}", ctx)

    async def invalidate_session(self, session_id: str) -> None:
        """Remove a session from Redis."""
        try:
            await self._redis.delete(f"session:{session_id}")
        except Exception:
            logger.warning("Failed to invalidate session %s in Redis", session_id)

    @staticmethod
    def hash_api_key(api_key: str) -> str:
        """Return the compatibility SHA-256 digest used by legacy/dev seeds."""
        return legacy_api_key_hash(api_key)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _fetch_identity(self, key_hashes: list[str]) -> asyncpg.Record | None:
        async with self._pool.acquire() as conn:
            return await conn.fetchrow(_IDENTITY_QUERY, key_hashes)

    async def _upgrade_legacy_api_key(self, row: asyncpg.Record, api_key: str) -> None:
        if not self._config.api_key_pepper:
            return
        version = _record_value(row, "api_key_hash_version", "sha256-v1")
        if version == HMAC_SHA256:
            return
        new_hash, new_version = hash_api_key_for_storage(api_key, self._config)
        try:
            await self._pool.execute(
                """
                UPDATE identities
                SET api_key_hash = $1,
                    api_key_hash_version = $2,
                    updated_at = NOW()
                WHERE id = $3 AND api_key_hash = $4
                """,
                new_hash,
                new_version,
                row["id"],
                _record_value(row, "api_key_hash"),
            )
        except Exception:
            logger.exception("failed to upgrade legacy API-key hash for identity %s", row["id"])

    async def _fetch_identity_by_id(self, identity_id: int) -> asyncpg.Record | None:
        async with self._pool.acquire() as conn:
            return await conn.fetchrow(_IDENTITY_BY_ID_QUERY, identity_id)

    async def _fetch_pg_identity(self, username: str) -> asyncpg.Record | None:
        async with self._pool.acquire() as conn:
            return await conn.fetchrow(_PG_IDENTITY_QUERY, username)

    async def _build_context(
        self,
        row: asyncpg.Record,
        *,
        session_id: str | None = None,
        auth_method: str = "api_key",
    ) -> IdentityContext:
        session_id = session_id or uuid.uuid4().hex
        source_roles, grants_version, _ = await self._fetch_source_role_grants(row["id"])
        return IdentityContext(
            identity_id=row["id"],
            user=row["name"],
            agent_type=_agent_type_or_default(row["agent_type"], row["name"]),
            team=row["team"],
            roles=list(row["roles"]) if row["roles"] else [],
            source_roles=source_roles,
            mapped_pg_role=row["mapped_pg_role"],
            session_id=session_id,
            grants_version=grants_version,
            auth_method=auth_method,
        )

    async def _refresh_cached_context(
        self, cache_key: str, cached_ctx: IdentityContext
    ) -> IdentityContext | None:
        """Revalidate cached identities against the DB and grant table.

        Redis sessions are a performance hint only. Identity status, global
        roles, mapped PG role, and source-role grants remain authoritative in
        Postgres so revocation takes effect on the next request.
        """
        row = await self._fetch_identity_by_id(cached_ctx.identity_id)
        if row is None:
            await self._redis_delete(cache_key)
            if cached_ctx.session_id:
                await self._redis_delete(f"session:{cached_ctx.session_id}")
            return None

        fresh_ctx = await self._build_context(
            row,
            session_id=cached_ctx.session_id,
            auth_method=cached_ctx.auth_method,
        )
        if fresh_ctx.model_dump() != cached_ctx.model_dump():
            await self._cache_context(cache_key, fresh_ctx)
        return fresh_ctx

    async def _cache_context(self, cache_key: str, ctx: IdentityContext) -> None:
        payload = ctx.model_dump_json().encode()
        ttl = self._config.session_ttl_seconds
        await self._redis_set(cache_key, payload, ttl)
        if ctx.session_id:
            await self._redis_set(f"session:{ctx.session_id}", payload, ttl)

    async def _fetch_source_role_grants(
        self, identity_id: int
    ) -> tuple[list[dict[str, Any]], str | None, bool]:
        """Load active source-scoped grants from the authoritative grant table.

        Legacy metadata is intentionally not used as a fallback. Source access
        must come from the authoritative grant table, and lookup failures
        should fail closed.
        """
        query = """
        SELECT g.source_id,
               g.role_id,
               r.role_key,
               r.name AS role_name,
               r.review_required,
               g.expires_at,
               g.updated_at
        FROM identity_source_role_grants g
        JOIN source_roles r
          ON r.id = g.role_id
         AND r.source_id = g.source_id
         AND r.enabled = TRUE
        WHERE g.identity_id = $1
          AND g.enabled = TRUE
          AND (g.expires_at IS NULL OR g.expires_at > NOW())
        ORDER BY g.source_id, r.role_key, g.role_id
        """
        try:
            async with self._pool.acquire() as conn:
                rows = await conn.fetch(query, identity_id)
        except Exception:
            logger.debug("identity source-role grant lookup failed", exc_info=True)
            return [], "grants-unavailable", True

        if rows is None:
            rows = []
        elif not isinstance(rows, (list, tuple)):
            try:
                rows = list(rows)
            except TypeError:
                logger.debug("identity source-role grant lookup returned non-iterable")
                return [], "grants-unavailable", True

        grants: list[dict[str, Any]] = []
        version_parts: list[str] = []
        for row in rows or []:
            role_id = int(row["role_id"])
            updated = row["updated_at"]
            updated_text = (
                updated.isoformat() if isinstance(updated, datetime) else str(updated or "")
            )
            version_parts.append(f"{role_id}:{updated_text}")
            grants.append(
                {
                    "source_id": str(row["source_id"]),
                    "role_id": role_id,
                    "role": str(row["role_key"]),
                    "role_key": str(row["role_key"]),
                    "role_name": str(row["role_name"] or row["role_key"]),
                    "review_required": bool(row["review_required"]),
                    "authority": "identity_source_role_grants",
                }
            )

        if not grants:
            return [], "grants-empty", True
        grants_version = hashlib.sha256("|".join(version_parts).encode()).hexdigest()
        return grants, grants_version, True

    async def _redis_get(self, key: str) -> bytes | None:
        """Best-effort Redis GET - returns None on failure."""
        if self._redis is None:
            return None
        try:
            return await self._redis.get(key)
        except Exception:
            logger.warning("Redis GET failed for %s, falling through to PG", key)
            return None

    async def _redis_set(self, key: str, value: bytes, ttl: int) -> None:
        """Best-effort Redis SET with TTL."""
        if self._redis is None:
            return
        try:
            await self._redis.set(key, value, ex=ttl)
        except Exception:
            logger.warning("Redis SET failed for %s", key)

    async def _redis_delete(self, key: str) -> None:
        """Best-effort Redis DELETE."""
        if self._redis is None:
            return
        try:
            await self._redis.delete(key)
        except Exception:
            logger.warning("Redis DELETE failed for %s", key)

    @staticmethod
    def _looks_like_jwt(value: str) -> bool:
        """Return true only for a structurally valid JWT header."""
        parts = value.split(".")
        if len(parts) != 3:
            return False
        try:
            padding = "=" * (-len(parts[0]) % 4)
            header = json.loads(base64.urlsafe_b64decode(parts[0] + padding))
        except (ValueError, json.JSONDecodeError, UnicodeDecodeError):
            return False
        return isinstance(header, dict) and bool(header.get("alg"))


def _record_value(row: Any, key: str, default: Any = None) -> Any:
    try:
        return row[key]
    except (KeyError, TypeError):
        return default
