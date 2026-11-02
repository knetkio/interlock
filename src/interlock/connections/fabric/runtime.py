"""Explicit process-owned Fabric services; optional drivers load only when configured."""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import asdict, dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from interlock.config import FabricSettings
    from interlock.connections.fabric.auth import FabricAuth, FabricToken
    from interlock.connections.fabric.config import FabricConfig
    from interlock.connections.fabric.credentials import FabricCredentialStore
    from interlock.connections.sqlserver import SqlServerTransport


@dataclass(frozen=True, slots=True)
class FabricAuthenticatedSource:
    """Internal request capability; never accept it from JSON or source metadata."""

    config: FabricConfig
    token: FabricToken = field(repr=False)
    _services: FabricServices = field(repr=False, compare=False)

    async def assert_current(self) -> None:
        await self._services.assert_current(self)

    @property
    def upstream_identity(self) -> dict[str, Any]:
        return asdict(self.token.context)

    @property
    def cache_scope(self) -> str:
        payload = [self.upstream_identity, self.config.model_dump()]
        return hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()


@dataclass(slots=True)
class FabricServices:
    store: FabricCredentialStore
    auth: FabricAuth
    transport: SqlServerTransport

    async def prepare_source(
        self, source_id: str, config: FabricConfig
    ) -> FabricAuthenticatedSource:
        """One auth acquisition/renewal owner for cache lookup and origin use."""
        token = await self.auth.acquire(source_id, config)
        return FabricAuthenticatedSource(config, token, self)

    async def assert_current(self, source: FabricAuthenticatedSource) -> None:
        """Refuse stale capabilities at each distinct use/delivery boundary."""
        from interlock.connections.fabric.auth import FabricAuthError
        from interlock.connections.fabric.credentials import FabricCredentialError

        if source._services is not self or source.token.expires_at <= time.time():
            raise FabricAuthError("reconnect_required")
        try:
            await self.store.assert_current(source.token.context, source.config)
        except FabricCredentialError:
            raise FabricAuthError("configuration_changed") from None
        except FabricAuthError:
            raise
        except Exception:
            raise FabricAuthError("authentication_unavailable") from None

    async def close(self) -> None:
        # Auth retains no clients or tokens between calls; the control pool is
        # owned by the process, not this service.
        await self.transport.close()


def build_fabric_services(pool: Any, settings: FabricSettings) -> FabricServices | None:
    if not settings.active_key_version:
        return None
    # A missing optional SDK or operator key makes Fabric unavailable, not the
    # unrelated connectors in the same process. Never fall back to an identity.
    from interlock.connections.fabric.credentials import FabricCredentialError

    try:
        from interlock.connections.fabric.auth import FabricAuth
        from interlock.connections.fabric.credentials import FabricCredentialStore, FabricKeyring
        from interlock.connections.sqlserver import SqlServerTransport

        store = FabricCredentialStore(
            pool,
            FabricKeyring(settings.active_key_version, settings.key_refs),
            lock_timeout_seconds=settings.lock_timeout_seconds,
        )
        return FabricServices(store, FabricAuth(store, settings), SqlServerTransport())
    except (ImportError, FabricCredentialError):
        return None
