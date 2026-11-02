"""Encrypted Fabric credentials with transaction-owned refresh and OAuth state."""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
import secrets
from collections.abc import AsyncIterator, Mapping
from contextlib import asynccontextmanager
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from asyncpg import Connection
from cryptography.fernet import Fernet, InvalidToken

from interlock.connections.fabric.config import FabricConfig, require_secret_reference
from interlock.secrets.resolver import MissingSecretError, resolve


class FabricCredentialError(RuntimeError):
    """Credential storage, ownership, or lifecycle validation failed closed."""


class FabricKeyring:
    """Versioned encryption keys, obtained only from the existing secret resolver."""

    def __init__(self, active_version: str, key_refs: Mapping[str, str]) -> None:
        self.active_version = active_version
        self._keys: dict[str, Fernet] = {}
        try:
            if not key_refs or active_version not in key_refs:
                raise ValueError("missing active key")
            for version, ref in key_refs.items():
                if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", version):
                    raise ValueError("invalid key version")
                require_secret_reference(ref)
                key = resolve(ref)
                if not key:
                    raise ValueError("missing encryption key")
                self._keys[version] = Fernet(key.strip().encode())
        except (ValueError, TypeError, MissingSecretError) as exc:
            raise FabricCredentialError("Fabric encryption keyring is unavailable") from exc

    def encrypt(self, plaintext: str, *, source_id: str, purpose: str) -> bytes:
        payload = json.dumps([source_id, purpose, plaintext]).encode()
        return (
            self.active_version.encode() + b":" + self._keys[self.active_version].encrypt(payload)
        )

    def decrypt(self, ciphertext: bytes, *, source_id: str, purpose: str) -> str:
        try:
            version, token = ciphertext.split(b":", 1)
            owner, kind, plaintext = json.loads(self._keys[version.decode()].decrypt(token))
            if owner != source_id or kind != purpose or not isinstance(plaintext, str):
                raise ValueError("encrypted record ownership mismatch")
            return plaintext
        except (ValueError, KeyError, InvalidToken, UnicodeError, TypeError) as exc:
            raise FabricCredentialError("Fabric encrypted credential cannot be read") from exc


@dataclass(frozen=True, slots=True)
class FabricCredentialContext:
    source_id: str
    generation: int
    tenant_id: str
    client_id: str
    account_id: str | None
    auth_mode: Literal["oauth", "spn"]
    status: str
    incarnation: str = ""


@dataclass(frozen=True, slots=True)
class FabricCurrentSource:
    """Authoritative, non-secret source identity for delivery/publish boundaries."""

    config: FabricConfig
    context: FabricCredentialContext


@dataclass(slots=True)
class LockedFabricCredential:
    context: FabricCredentialContext
    revision: int
    config: FabricConfig
    decrypted_cache: str = field(repr=False)
    _connection: Any = field(repr=False)
    _owner: Any = field(repr=False)
    _active: bool = field(default=True, repr=False)


def _context(row: Any) -> FabricCredentialContext:
    return FabricCredentialContext(
        source_id=row["source_id"],
        generation=row["generation"],
        tenant_id=row["tenant_id"],
        client_id=row["client_id"],
        account_id=row["account_id"],
        auth_mode=row["auth_mode"],
        status=row["status"],
        incarnation=str(row["incarnation"]),
    )


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


class FabricCredentialStore:
    """One source lock serializes refresh, lifecycle changes and pending flows.

    Source rows are locked before credential rows so source edits/deletes and
    their database trigger follow the same lock order. The deadline includes
    waiting for the pool, database locks and the caller's refresh operation.
    """

    def __init__(
        self, pool: Any, keyring: FabricKeyring, *, lock_timeout_seconds: float = 30
    ) -> None:
        if not 0 < lock_timeout_seconds <= 120:
            raise ValueError("credential lock deadline must be within 0–120 seconds")
        self._pool = pool
        self._keyring = keyring
        self._lock_timeout_seconds = lock_timeout_seconds

    @asynccontextmanager
    async def _locked_row(
        self, source_id: str, *, require_enabled: bool = True
    ) -> AsyncIterator[tuple[Any, Any, FabricConfig]]:
        """Lock lifecycle metadata without requiring the cache to be readable."""
        async with asyncio.timeout(self._lock_timeout_seconds):
            async with self._pool.acquire() as conn:
                async with conn.transaction():
                    source = await conn.fetchrow(
                        "SELECT connection_config, enabled, source_type, metadata "
                        "FROM data_sources WHERE source_id = $1 FOR SHARE",
                        source_id,
                    )
                    if source is None:
                        raise FabricCredentialError("Fabric source does not exist")
                    if require_enabled and not source["enabled"]:
                        raise FabricCredentialError("Fabric source is disabled")
                    metadata = source["metadata"] or {}
                    if isinstance(metadata, str):
                        metadata = json.loads(metadata)
                    from interlock.connections.connectors import connector_key_for

                    if (
                        source["source_type"] not in ("database", "fabric_sql")
                        or connector_key_for(source["source_type"], metadata) != "fabric_sql"
                    ):
                        raise FabricCredentialError("Fabric source configuration changed")
                    config = source["connection_config"]
                    if isinstance(config, str):
                        config = json.loads(config)
                    cfg = FabricConfig.from_mapping(config)
                    await conn.execute(
                        """INSERT INTO fabric_credentials (source_id, tenant_id, client_id, auth_mode, status)
                        VALUES ($1, $2, $3, $4, $5) ON CONFLICT (source_id) DO NOTHING""",
                        source_id,
                        cfg.tenant_id,
                        cfg.client_id,
                        cfg.auth_mode,
                        "connected" if cfg.auth_mode == "spn" else "disconnected",
                    )
                    row = await conn.fetchrow(
                        "SELECT * FROM fabric_credentials WHERE source_id = $1 FOR UPDATE",
                        source_id,
                    )
                    yield conn, row, cfg

    @asynccontextmanager
    async def locked(self, source_id: str) -> AsyncIterator[LockedFabricCredential]:
        async with self._locked_row(source_id) as (conn, row, cfg):
            cache = row["encrypted_cache"]
            locked = LockedFabricCredential(
                context=_context(row),
                revision=row["revision"],
                config=cfg,
                decrypted_cache=(
                    self._keyring.decrypt(bytes(cache), source_id=source_id, purpose="cache")
                    if cache is not None
                    else ""
                ),
                _connection=conn,
                _owner=self,
            )
            try:
                yield locked
            finally:
                locked._active = False
                locked.decrypted_cache = ""

    def _check_lock(self, locked: LockedFabricCredential) -> Any:
        if locked._owner is not self or not locked._active:
            raise FabricCredentialError("credential lock is no longer owned")
        return locked._connection

    async def get_context(self, source_id: str) -> FabricCredentialContext:
        return (await self.current_source(source_id)).context

    async def current_source(self, source_id: str) -> FabricCurrentSource:
        """Read enabled/config/identity under the source lock, without decrypting tokens.

        A missing, disabled or changed connector fails closed even when the
        caller's process registry and all cache notifications are stale.
        """
        async with self._locked_row(source_id) as (_conn, row, config):
            return FabricCurrentSource(config, _context(row))

    @asynccontextmanager
    async def guard_current(
        self, context: FabricCredentialContext, config: FabricConfig
    ) -> AsyncIterator[Connection]:
        """Hold current identity across a short control-DB publication transaction.

        Use the yielded connection for publication. Never hold this guard while
        authenticating or collecting backend SQL; those operations use their
        own bounded execution and an assertion at the next delivery boundary.
        """
        async with self._locked_row(context.source_id) as (conn, row, current_config):
            if _context(row) != context or current_config != config:
                raise FabricCredentialError("Fabric source configuration or identity changed")
            if context.status != "connected":
                raise FabricCredentialError("Fabric source requires reconnecting")
            yield conn

    async def assert_current(self, context: FabricCredentialContext, config: FabricConfig) -> None:
        """Validate an earlier identity at a delivery or SQL submission boundary."""
        async with self.guard_current(context, config):
            pass

    async def save_cache(self, locked: LockedFabricCredential, serialized_cache: str) -> None:
        conn = self._check_lock(locked)
        ciphertext = self._keyring.encrypt(
            serialized_cache, source_id=locked.context.source_id, purpose="cache"
        )
        row = await conn.fetchrow(
            """UPDATE fabric_credentials SET encrypted_cache=$4, revision=revision+1,
            status=CASE WHEN auth_mode='spn' THEN 'connected' ELSE status END, updated_at=NOW()
            WHERE source_id=$1 AND generation=$2 AND revision=$3 RETURNING revision, status""",
            locked.context.source_id,
            locked.context.generation,
            locked.revision,
            ciphertext,
        )
        if row is None:
            raise FabricCredentialError("credential generation or revision changed")
        locked.revision = row["revision"]
        locked.context = replace(locked.context, status=row["status"])
        locked.decrypted_cache = serialized_cache

    async def save_identity(
        self, locked: LockedFabricCredential, *, account_id: str, status: str = "connected"
    ) -> FabricCredentialContext:
        conn = self._check_lock(locked)
        if not account_id or status != "connected":
            raise FabricCredentialError("OAuth completion requires a connected account")
        row = await conn.fetchrow(
            """UPDATE fabric_credentials SET account_id=$4, status=$5, generation=generation+1,
            revision=revision+1, encrypted_cache=NULL, updated_at=NOW()
            WHERE source_id=$1 AND generation=$2 AND revision=$3 RETURNING *""",
            locked.context.source_id,
            locked.context.generation,
            locked.revision,
            account_id,
            status,
        )
        if row is None:
            raise FabricCredentialError("credential generation or revision changed")
        await conn.execute(
            "DELETE FROM fabric_pending_oauth WHERE source_id=$1", locked.context.source_id
        )
        locked.context, locked.revision, locked.decrypted_cache = _context(row), row["revision"], ""
        return locked.context

    async def invalidate(
        self, source_id: str, *, reason: str, delete_cache: bool
    ) -> FabricCredentialContext:
        async with self._locked_row(source_id, require_enabled=False) as (conn, current, _cfg):
            row = await self._invalidate_row(
                conn, _context(current), current["revision"], reason, delete_cache
            )
            return _context(row)

    async def _invalidate_row(
        self,
        conn: Any,
        context: FabricCredentialContext,
        revision: int,
        reason: str,
        delete_cache: bool,
    ) -> Any:
        row = await conn.fetchrow(
            """UPDATE fabric_credentials SET generation=generation+1, revision=revision+1,
                status=$2, encrypted_cache=CASE WHEN $3 THEN NULL ELSE encrypted_cache END,
                account_id=CASE WHEN $3 THEN NULL ELSE account_id END, updated_at=NOW()
                WHERE source_id=$1 AND generation=$4 AND revision=$5 RETURNING *""",
            context.source_id,
            "disconnected" if reason == "disconnect" else "reconnect_required",
            delete_cache,
            context.generation,
            revision,
        )
        if row is None:
            raise FabricCredentialError("credential generation or revision changed")
        await conn.execute("DELETE FROM fabric_pending_oauth WHERE source_id=$1", context.source_id)
        return row

    async def invalidate_locked(
        self, locked: LockedFabricCredential, *, reason: str, delete_cache: bool
    ) -> FabricCredentialContext:
        """Revoke within an existing refresh transaction without releasing ownership."""
        row = await self._invalidate_row(
            self._check_lock(locked), locked.context, locked.revision, reason, delete_cache
        )
        locked.context, locked.revision = _context(row), row["revision"]
        if delete_cache:
            locked.decrypted_cache = ""
        return locked.context

    async def save_pending(
        self,
        source_id: str,
        session_binding: str,
        flow: dict[str, Any],
        expires_at: datetime,
        expected_generation: int,
        *,
        state: str | None = None,
        expected_incarnation: str | None = None,
    ) -> str:
        if not session_binding or any(
            k in flow for k in ("_fabric_source_id", "_fabric_generation", "_fabric_incarnation")
        ):
            raise FabricCredentialError("invalid pending OAuth ownership")
        now = datetime.now(UTC)
        if expires_at.tzinfo is None or not now < expires_at <= now + timedelta(seconds=600):
            raise FabricCredentialError("OAuth state must expire within 600 seconds")
        if state is None:
            state = secrets.token_urlsafe(32)
        elif not re.fullmatch(r"[A-Za-z0-9_-]{43,128}", state):
            raise FabricCredentialError("OAuth state must be a high-entropy opaque handle")
        async with self.locked(source_id) as locked:
            if locked.context.generation != expected_generation or (
                expected_incarnation is not None
                and locked.context.incarnation != expected_incarnation
            ):
                raise FabricCredentialError("credential generation or incarnation changed")
            ciphertext = self._keyring.encrypt(
                json.dumps(flow), source_id=source_id, purpose="pending"
            )
            await locked._connection.execute(
                """INSERT INTO fabric_pending_oauth
                (state_hash, source_id, generation, session_hash, encrypted_flow, expires_at, created_at)
                VALUES ($1,$2,$3,$4,$5,$6,$7)""",
                _digest(state),
                source_id,
                expected_generation,
                _digest(session_binding),
                ciphertext,
                expires_at,
                now,
            )
        return state

    async def consume_pending(self, state: str, session_binding: str) -> dict[str, Any]:
        # Discovery is read-only; ownership and consumption happen under the source
        # lock. Never lock a pending row before its parent credential row.
        async with asyncio.timeout(self._lock_timeout_seconds):
            source_id = await self._pool.fetchval(
                "SELECT source_id FROM fabric_pending_oauth WHERE state_hash=$1", _digest(state)
            )
            if source_id is None:
                raise FabricCredentialError("OAuth state is invalid or already consumed")
            invalid = False
            flow: dict[str, Any] = {}
            async with self.locked(source_id) as locked:
                row = await locked._connection.fetchrow(
                    "SELECT * FROM fabric_pending_oauth WHERE state_hash=$1 FOR UPDATE",
                    _digest(state),
                )
                if row is None or not secrets.compare_digest(
                    row["session_hash"], _digest(session_binding)
                ):
                    raise FabricCredentialError(
                        "OAuth state is invalid or owned by another session"
                    )
                await locked._connection.execute(
                    "DELETE FROM fabric_pending_oauth WHERE state_hash=$1", _digest(state)
                )
                invalid = (
                    row["expires_at"] <= datetime.now(UTC)
                    or row["generation"] != locked.context.generation
                )
                if not invalid:
                    flow = json.loads(
                        self._keyring.decrypt(
                            bytes(row["encrypted_flow"]), source_id=source_id, purpose="pending"
                        )
                    )
                    flow["_fabric_source_id"] = source_id
                    flow["_fabric_generation"] = locked.context.generation
                    flow["_fabric_incarnation"] = locked.context.incarnation
            if invalid:
                raise FabricCredentialError("OAuth state expired or credential generation changed")
            return flow
