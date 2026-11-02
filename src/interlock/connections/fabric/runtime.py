"""Explicit process-owned Fabric services; optional drivers load only when configured."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from interlock.config import FabricSettings
    from interlock.connections.fabric.auth import FabricAuth
    from interlock.connections.fabric.credentials import FabricCredentialStore
    from interlock.connections.sqlserver import SqlServerTransport


@dataclass(slots=True)
class FabricServices:
    store: FabricCredentialStore
    auth: FabricAuth
    transport: SqlServerTransport

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
