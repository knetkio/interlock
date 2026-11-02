"""Encrypted Fabric credentials with transaction-owned refresh and OAuth state."""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
import secrets
from collections.abc import AsyncIterator, Mapping
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

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


@dataclass(slots=True)
class LockedFabricCredential:
    context: FabricCredentialContext
    revision: int
    decrypted_cache: str = field(repr=False)
    _connection: Any = field(repr=False)
    _owner: Any = field(repr=False)
    _active: bool = field(default=True, repr=False)


def _context(row: Any) -> FabricCredentialContext:
    return FabricCredentialContext(
        **{name: row[name] for name in FabricCredentialContext.__dataclass_fields__}
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
    async def locked(self, source_id: str) -> AsyncIterator[LockedFabricCredential]:
        async with asyncio.timeout(self._lock_timeout_seconds):
            async with self._pool.acquire() as conn:
                async with conn.transaction():
                    source = await conn.fetchrow(
                        "SELECT connection_config FROM data_sources WHERE source_id = $1 FOR SHARE",
                        source_id,
                    )
                    if source is None:
                        raise FabricCredentialError("Fabric source does not exist")
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
                    cache = row["encrypted_cache"]
                    locked = LockedFabricCredential(
                        context=_context(row),
                        revision=row["revision"],
                        decrypted_cache=(
                            self._keyring.decrypt(
                                bytes(cache), source_id=source_id, purpose="cache"
                            )
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
        async with self.locked(source_id) as locked:
            return locked.context

    async def save_cache(self, locked: LockedFabricCredential, serialized_cache: str) -> None:
        conn = self._check_lock(locked)
        ciphertext = self._keyring.encrypt(
            serialized_cache, source_id=locked.context.source_id, purpose="cache"
        )
        row = await conn.fetchrow(
            """UPDATE fabric_credentials SET encrypted_cache=$4, revision=revision+1, updated_at=NOW()
            WHERE source_id=$1 AND generation=$2 AND revision=$3 RETURNING revision""",
            locked.context.source_id,
            locked.context.generation,
            locked.revision,
            ciphertext,
        )
        if row is None:
            raise FabricCredentialError("credential generation or revision changed")
        locked.revision = row["revision"]
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
        async with self.locked(source_id) as locked:
            row = await locked._connection.fetchrow(
                """UPDATE fabric_credentials SET generation=generation+1, revision=revision+1,
                status=$2, encrypted_cache=CASE WHEN $3 THEN NULL ELSE encrypted_cache END,
                account_id=CASE WHEN $3 THEN NULL ELSE account_id END, updated_at=NOW()
                WHERE source_id=$1 RETURNING *""",
                source_id,
                "disconnected" if reason == "disconnect" else "reconnect_required",
                delete_cache,
            )
            await locked._connection.execute(
                "DELETE FROM fabric_pending_oauth WHERE source_id=$1", source_id
            )
            return _context(row)

    async def save_pending(
        self,
        source_id: str,
        session_binding: str,
        flow: dict[str, Any],
        expires_at: datetime,
        expected_generation: int,
    ) -> str:
        if not session_binding or any(
            k in flow for k in ("_fabric_source_id", "_fabric_generation")
        ):
            raise FabricCredentialError("invalid pending OAuth ownership")
        now = datetime.now(UTC)
        if expires_at.tzinfo is None or not now < expires_at <= now + timedelta(seconds=600):
            raise FabricCredentialError("OAuth state must expire within 600 seconds")
        state = secrets.token_urlsafe(32)
        async with self.locked(source_id) as locked:
            if locked.context.generation != expected_generation:
                raise FabricCredentialError("credential generation changed")
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
            if invalid:
                raise FabricCredentialError("OAuth state expired or credential generation changed")
            return flow
