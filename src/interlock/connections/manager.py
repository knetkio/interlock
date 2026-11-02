"""Connection manager - lazy role-mapped connection pools to upstream data sources."""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import ssl
import time
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

import asyncpg

from interlock.connections.circuit_breaker import CircuitBreakerRegistry
from interlock.connections.connectors import (
    get_adapter,
    get_connector,
    http_probe_error,
    http_probe_url,
)
from interlock.connections.source_config import (
    VERIFYING_TLS_MODES,
    config_bool,
    read_connection_field,
    upstream_tls_refusal,
    validate_source_config,
)
from interlock.errors import DataSourceNotFoundError, DataSourceUnavailableError
from interlock.metadata.registry import MetadataRegistry
from interlock.models import HealthStatus
from interlock.security.egress import (
    build_safe_async_http_transport,
    validate_host_egress,
    validate_http_egress_url,
)

if TYPE_CHECKING:
    from interlock.connections.fabric.runtime import FabricServices

logger = logging.getLogger(__name__)


def _ssl_argument(mode: str, connection_config: dict[str, object]) -> object:
    """Translate a stored TLS mode into what asyncpg expects.

    `sslmode` and `ssl` are both accepted spellings, and `verify_ssl` /
    `ssl_verify` may explicitly opt out of certificate verification - which
    operators do for managed clusters whose CA bundle is not distributed with
    the deployment.

    A verifying mode with a CA configured returns a real `SSLContext` built
    from that CA. Handing asyncpg the bare mode string instead meant the
    operator's CA was never used: asyncpg fell back to libpq's default trust
    store at `~/.postgresql/root.crt`, which does not exist in the published
    image, so `verify-full` could not work in a container at all while the
    PG-wire path - reading the same stored field - connected fine.

    Verification is only ever *downgraded* when it was explicitly disabled.
    Nothing here silently weakens a stronger mode, and an unrecognised value
    is passed through to asyncpg rather than being guessed at, so a typo
    surfaces as a connection error instead of as a quietly weaker connection.
    """
    normalized = mode.strip().lower()
    if normalized in {"disable", "false", "off", "0"}:
        return False
    if normalized in {"true", "on", "1"}:
        return True

    verify = read_connection_field(connection_config, "ssl_verify")
    verifying = normalized in VERIFYING_TLS_MODES
    if verify is not None and not config_bool(verify) and verifying:
        # Encrypt, but do not verify: the operator asked for exactly this,
        # and a CA sitting in the config must not quietly re-enable it.
        return "require"

    if verifying:
        # Reads the alias group, so `sslrootcert` and `ssl_ca_ref` work too,
        # and a secret reference is resolved before it reaches the handshake.
        ca_file = read_connection_field(connection_config, "ssl_ca")
        if ca_file:
            # A missing or unreadable file raises here rather than falling
            # back to the mode string. Falling back would reproduce the
            # original defect, where a configured-but-unusable CA looked
            # exactly like a working one.
            context = ssl.create_default_context(cafile=str(ca_file))
            if normalized == "verify-ca":
                # Chain verified, hostname not - the whole difference between
                # the two modes, so collapsing them would silently strengthen
                # a mode the operator chose deliberately.
                context.check_hostname = False
            return context
    return normalized


class ConnectionManager:
    """Maintains lazily-created asyncpg pools keyed by (source_id, pg_role).

    Pools are created on first request and reused only while the source's
    configuration is unchanged.

    They used to be reused unconditionally: the cache lookup returned before
    the registry was consulted, and nothing evicted a pool when a source's
    config changed. Repointing a source at a different host, correcting a
    misconfiguration, or rotating a credential therefore had no effect until
    the gateway process restarted - a revoked credential kept working through
    the proxy indefinitely, while the console reported the change saved.
    """

    def __init__(
        self,
        registry: MetadataRegistry,
        circuit_breakers: CircuitBreakerRegistry | None = None,
        *,
        allow_insecure_upstream_tls: bool = True,
        fabric_services: FabricServices | None = None,
    ) -> None:
        self.fabric_services = fabric_services
        self._registry = registry
        self._circuit_breakers = circuit_breakers or CircuitBreakerRegistry()
        # Production refuses an unencrypted or unverified upstream. The gate
        # used to be handed only to the PG-wire listener, so this path served
        # sources that one refused. Defaults permissive so a caller that has
        # no configuration - a test, a script - behaves as it always did.
        self._allow_insecure_upstream_tls = allow_insecure_upstream_tls
        # (source_id, pg_role) -> (config fingerprint, pool)
        self._pools: dict[tuple[str, str | None], tuple[str, asyncpg.Pool]] = {}

    @staticmethod
    def _config_fingerprint(config: Any, pg_role: str | None) -> str:
        """Digest of everything that decides which upstream this pool reaches.

        Computed from the *stored* configuration rather than from resolved
        secret values, so the hot path stays free of secret-store round trips.
        The consequence is stated rather than hidden: rotating a value behind
        an unchanged reference - the same `env://NAME` now holding a new
        password - is not visible here. That case needs `invalidate()` or a
        restart, and `invalidate()` exists so an operator has something to call.
        """
        payload = json.dumps(
            {
                "host": getattr(config, "host", None),
                "port": getattr(config, "port", None),
                "database": getattr(config, "database", None),
                "connection_string": getattr(config, "connection_string", None),
                "connection_config": getattr(config, "connection_config", {}) or {},
                "enabled": getattr(config, "enabled", True),
                "pg_role": pg_role,
            },
            sort_keys=True,
            default=str,
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    async def invalidate(self, source_id: str | None = None) -> int:
        """Close and forget pooled connections, so the next call rebuilds them.

        Call after rotating a credential that a source reaches by reference,
        since the stored configuration does not change in that case and the
        fingerprint cannot see it.
        """
        keys = [key for key in self._pools if source_id is None or key[0] == source_id]
        for key in keys:
            _, pool = self._pools.pop(key)
            try:
                await pool.close()
            except Exception:  # noqa: BLE001 - a pool that will not close is still gone
                logger.warning("Failed to close pool for %s", key[0], exc_info=True)
        if keys:
            logger.info("Invalidated %d pool(s) for source=%s", len(keys), source_id or "*")
        return len(keys)

    async def get_pool(self, source_id: str, pg_role: str | None = None) -> asyncpg.Pool:
        """Return a pool for the given source and optional PG role.

        Creates the pool lazily, and rebuilds it whenever the source's stored
        configuration has changed since the pool was opened.
        Raises ValueError if source_id is not in the registry.
        Raises DataSourceUnavailableError if the circuit breaker is open.
        """
        # Check circuit breaker before proceeding
        breaker = self._circuit_breakers.get(source_id)
        if not breaker.can_execute():
            raise DataSourceUnavailableError(f"Circuit open for data source: {source_id}")

        config = self._registry.get(source_id)
        if config is None:
            raise DataSourceNotFoundError(f"Unknown data source: {source_id}")

        # The registry is in memory, so consulting it before reusing a pool is
        # cheap - and it is the whole fix. Returning a cached pool without
        # looking is what made configuration changes inert.
        key = (source_id, pg_role)
        fingerprint = self._config_fingerprint(config, pg_role)
        cached = self._pools.get(key)
        if cached is not None:
            cached_fingerprint, pool = cached
            if cached_fingerprint == fingerprint:
                breaker.record_success()
                return pool
            logger.info(
                "Configuration changed for source=%s; rebuilding its connection pool",
                source_id,
            )
            self._pools.pop(key, None)
            try:
                await pool.close()
            except Exception:  # noqa: BLE001 - the stale pool must not block the new one
                logger.warning("Failed to close stale pool for %s", source_id, exc_info=True)

        if not config.enabled:
            raise DataSourceUnavailableError(f"Data source is disabled: {source_id}")

        # Scoped to PostgreSQL: this judges the ssl/sslmode fields a database
        # upstream declares, and a connector carrying none of them - object
        # storage, a SaaS API - must not be refused for their absence.
        if config.source_type.value == "postgresql":
            refusal = upstream_tls_refusal(
                config.connection_config,
                allow_insecure_tls=self._allow_insecure_upstream_tls,
            )
            if refusal:
                raise DataSourceUnavailableError(f"{refusal}: {source_id}")

        connector = get_connector(config.source_type.value, config.metadata)
        validate_source_config(
            config.connection_config,
            connector_key=connector.key,
            source_type=config.source_type.value,
            source_id=source_id,
            allowed_fields=connector.credential_fields,
            secret_fields=connector.secret_fields,
        )

        connect_kwargs: dict[str, object] = {}
        if config.connection_string:
            connect_kwargs["dsn"] = config.connection_string
        else:
            if config.host:
                connect_kwargs["host"] = config.host
            if config.port:
                connect_kwargs["port"] = config.port
            if config.database:
                connect_kwargs["database"] = config.database
            # Read through the shared accessor rather than with .get, so this
            # path resolves secret references and accepts the same spellings
            # the PG-wire path has always accepted. Reading the raw keys meant
            # a source configured with `password_ref` connected with no
            # password over MCP, and one configured with `sslmode` connected
            # with no encryption - silently, and only on this protocol.
            user = read_connection_field(config.connection_config, "user")
            password = read_connection_field(config.connection_config, "password")
            ssl_config = read_connection_field(config.connection_config, "ssl")
            if user:
                connect_kwargs["user"] = user
            if password:
                connect_kwargs["password"] = password
            if ssl_config is not None:
                connect_kwargs["ssl"] = _ssl_argument(ssl_config, config.connection_config)

        if pg_role is not None:
            # asyncpg supports server_settings to SET ROLE at connection time
            connect_kwargs["server_settings"] = {"role": pg_role}

        try:
            pool = await asyncpg.create_pool(
                **connect_kwargs,  # type: ignore[arg-type]
                min_size=1,
                max_size=5,
                statement_cache_size=0,
            )
        except Exception:
            breaker.record_failure()
            raise

        self._pools[key] = (fingerprint, pool)
        breaker.record_success()
        logger.info("Created pool for source=%s role=%s", source_id, pg_role)
        return pool

    @staticmethod
    async def probe_unsaved(
        source_type: str,
        connection_config: dict,
        *,
        timeout_seconds: float = 5.0,
        connector_key: str | None = None,
        allow_insecure_tls: bool = True,
    ) -> HealthStatus:
        """Probe a candidate upstream WITHOUT persisting it.

        `allow_insecure_tls` must come from the same policy the real connection
        path uses (`allows_insecure_upstream_tls`). The probe used to skip the
        production TLS gate entirely, so Test Connection reported healthy a
        PostgreSQL configuration every query path would refuse once saved.

        Used by the source-onboarding UI so the user can validate the
        configuration before hitting Save. Mirrors the shape of
        ``health_check`` (returns a ``HealthStatus``) but does not
        require the source to be registered or any pool to exist.

        Supported source types:
          - ``postgresql`` - open a one-shot asyncpg connection and
            run ``SELECT 1``. Required keys: ``host``, ``port``.
            Optional: ``database``, ``user``, ``password``.
          - ``http`` - send an HTTP GET to ``base_url`` and report
            status code as the success signal. Required keys:
            ``base_url``.
          - enterprise connectors - routed through the connector registry
            when ``connector_key`` is provided or the source type maps to a
            first-class connector.
        """
        start = time.monotonic()
        kind = (source_type or "").lower()
        cfg = connection_config or {}

        try:
            connector = get_connector(
                connector_key or source_type,
                {"connector_key": connector_key} if connector_key else None,
            )
            validate_source_config(
                cfg,
                connector_key=connector.key,
                source_type=source_type,
                allowed_fields=connector.credential_fields,
                secret_fields=connector.secret_fields,
            )
            if kind == "postgresql":
                host = cfg.get("host")
                port = int(cfg.get("port", 5432))
                if not host:
                    return HealthStatus(
                        source_id="<unsaved>",
                        healthy=False,
                        latency_ms=0.0,
                        error="connection_config.host is required",
                        checked_at=datetime.now(UTC),
                    )
                # Judged before any network contact, with the gate get_pool
                # and the PG-wire proxy use, so all three give one answer.
                refusal = upstream_tls_refusal(cfg, allow_insecure_tls=allow_insecure_tls)
                if refusal:
                    return HealthStatus(
                        source_id="<unsaved>",
                        healthy=False,
                        latency_ms=0.0,
                        error=refusal,
                        checked_at=datetime.now(UTC),
                    )
                # Same accessor as the real connection path. A probe that read
                # different keys would report success on a configuration that
                # cannot actually connect - which is exactly the shape of the
                # earlier defect where Test Connection accepted a config that
                # Save then rejected.
                probe_ssl = read_connection_field(cfg, "ssl")
                conn = await asyncio.wait_for(
                    asyncpg.connect(
                        host=host,
                        port=port,
                        database=read_connection_field(cfg, "database") or "postgres",
                        user=read_connection_field(cfg, "user") or "postgres",
                        password=read_connection_field(cfg, "password") or "",
                        ssl=_ssl_argument(probe_ssl, cfg) if probe_ssl is not None else None,
                    ),
                    timeout=timeout_seconds,
                )
                try:
                    await conn.fetchval("SELECT 1")
                finally:
                    await conn.close()
                return HealthStatus(
                    source_id="<unsaved>",
                    healthy=True,
                    latency_ms=(time.monotonic() - start) * 1000,
                    checked_at=datetime.now(UTC),
                )

            if kind == "http":
                base_url = cfg.get("base_url")
                if not base_url:
                    return HealthStatus(
                        source_id="<unsaved>",
                        healthy=False,
                        latency_ms=0.0,
                        error="connection_config.base_url is required",
                        checked_at=datetime.now(UTC),
                    )
                import httpx

                probe_url = http_probe_url(cfg)
                validate_http_egress_url(
                    probe_url,
                    allow_private=config_bool(cfg.get("allow_private_egress")),
                )
                async with httpx.AsyncClient(
                    timeout=timeout_seconds,
                    follow_redirects=False,
                    trust_env=False,
                    transport=build_safe_async_http_transport(
                        allow_private=config_bool(cfg.get("allow_private_egress"))
                    ),
                ) as client:
                    resp = await client.get(probe_url)
                latency = (time.monotonic() - start) * 1000
                return HealthStatus(
                    source_id="<unsaved>",
                    healthy=resp.status_code < 400,
                    latency_ms=latency,
                    error=(
                        None
                        if resp.status_code < 400
                        else http_probe_error(resp.status_code, probe_url, cfg)
                    ),
                    checked_at=datetime.now(UTC),
                )

            known_connector_types = {
                "s3",
                "saas",
                "warehouse",
                "database",
                "object_storage",
                "search",
                "collaboration",
                "mysql",
                "mariadb",
                "snowflake",
                "zendesk",
                "slack",
                "github",
                "gitlab",
                "digitalocean_spaces",
                "opensearch",
                "elasticsearch",
                "qdrant",
                "mongodb",
                "salesforce",
                "atlassian",
                "google_workspace",
                "bigquery",
                "servicenow",
                "mssql",
                "notion",
            }
            if connector_key is None and kind not in known_connector_types:
                return HealthStatus(
                    source_id="<unsaved>",
                    healthy=False,
                    latency_ms=0.0,
                    error=f"probe not supported for source_type={source_type!r}",
                    checked_at=datetime.now(UTC),
                )

            adapter = get_adapter(
                connector_key or source_type,
                {"connector_key": connector_key} if connector_key else None,
            )
            status = await adapter.probe(
                cfg,
                timeout_seconds=timeout_seconds,
            )
            status.source_id = "<unsaved>"
            return status
        except TimeoutError:
            return HealthStatus(
                source_id="<unsaved>",
                healthy=False,
                latency_ms=(time.monotonic() - start) * 1000,
                error=f"timeout after {timeout_seconds}s",
                checked_at=datetime.now(UTC),
            )
        except Exception as exc:
            return HealthStatus(
                source_id="<unsaved>",
                healthy=False,
                latency_ms=(time.monotonic() - start) * 1000,
                error=str(exc),
                checked_at=datetime.now(UTC),
            )

    async def health_check(self, source_id: str) -> HealthStatus:
        """Ping upstream data source using its native connector."""
        start = time.monotonic()
        try:
            config = self._registry.get(source_id)
            if config is not None and config.source_type.value != "postgresql":
                connector = get_connector(config.source_type.value, config.metadata)
                validate_source_config(
                    config.connection_config,
                    connector_key=connector.key,
                    source_type=config.source_type.value,
                    source_id=source_id,
                    allowed_fields=connector.credential_fields,
                    secret_fields=connector.secret_fields,
                )
                adapter = get_adapter(
                    config.source_type.value,
                    config.metadata,
                    fabric_services=self.fabric_services,
                    source_id=source_id,
                )
                status = await adapter.probe(config.connection_config)
                status.source_id = source_id
                return status
            pool = await self.get_pool(source_id)
            await pool.fetchval("SELECT 1")
            latency = (time.monotonic() - start) * 1000
            return HealthStatus(
                source_id=source_id,
                healthy=True,
                latency_ms=latency,
                checked_at=datetime.now(UTC),
            )
        except Exception as exc:
            latency = (time.monotonic() - start) * 1000
            return HealthStatus(
                source_id=source_id,
                healthy=False,
                latency_ms=latency,
                error=str(exc),
                checked_at=datetime.now(UTC),
            )

    async def close_all(self) -> None:
        """Close all managed pools."""
        for key, (_fingerprint, pool) in self._pools.items():
            try:
                await pool.close()
                logger.info("Closed pool for %s", key)
            except Exception:
                logger.exception("Error closing pool for %s", key)
        self._pools.clear()


def _validate_probe_egress(cfg: dict) -> None:
    allow_private = config_bool(cfg.get("allow_private_egress"))
    for key in ("base_url", "endpoint_url", "instance_url", "url"):
        value = cfg.get(key)
        if value:
            validate_http_egress_url(str(value), allow_private=allow_private)
    host = cfg.get("host")
    if host:
        port_value = cfg.get("port")
        try:
            port = int(port_value) if port_value else None
        except (TypeError, ValueError):
            port = None
        validate_host_egress(str(host), port=port, allow_private=allow_private)
