"""Gateway application - data plane ASGI app + PG proxy."""

from __future__ import annotations

import inspect
import logging
import ssl
import time
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from typing import Any

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from interlock.audit.buffer import AuditBuffer
from interlock.audit.logger import AuditLogger
from interlock.cache.embedding import EmbeddingEngine
from interlock.cache.faiss_index import FAISSIndex
from interlock.cache.faiss_sync import FAISSIndexSync
from interlock.cache.generation import SourceGenerationBarrier
from interlock.cache.invalidation import CacheInvalidator
from interlock.cache.l1 import L1Cache
from interlock.cache.l2 import L2Cache
from interlock.cache.strategy import CacheStrategyResolver
from interlock.catalog.naming import CatalogNamingResolver
from interlock.config import InterLockConfig, allows_insecure_upstream_tls, load_config
from interlock.connections.circuit_breaker import CircuitBreakerRegistry
from interlock.connections.fabric.runtime import build_fabric_services
from interlock.connections.manager import ConnectionManager
from interlock.core.approval_queue import ApprovalQueue
from interlock.core.auth import AuthManager
from interlock.core.oidc import OIDCProvider
from interlock.core.policy import PolicyEngine
from interlock.core.rate_limiter import RateLimiter
from interlock.core.source_roles import SourceRoleEvaluator
from interlock.core.write_classifier import WriteClassifier
from interlock.db.migrations import verify_migration_head
from interlock.db.pool import close_pg_pool, create_pg_pool
from interlock.db.redis import close_redis_client, create_redis_client
from interlock.discovery.search import DiscoverySearch
from interlock.errors import (
    AuditUnavailableError,
    AuthError,
    ConfigValidationError,
    DependencyNotReadyError,
)
from interlock.gateway.http_proxy import HTTPProxy
from interlock.gateway.mcp_adapter import MCPAdapter
from interlock.gateway.multi_instance import GatewayInstanceManager
from interlock.gateway.pg_proxy import PGProxy
from interlock.gateway.pipeline import bearer_token_from_headers
from interlock.metadata.registry import MetadataRegistry
from interlock.notifications.factory import build_approval_notifier
from interlock.observability.health import control_plane_response, run_dependency_checks
from interlock.observability.otel import configure_service_otel
from interlock.pipeline.pii_deep import PIIDeepScanner
from interlock.pipeline.pii_fast import PIIFastScanner
from interlock.pipeline.processor import ResponseProcessor

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


def _validate_runtime_security(config: InterLockConfig) -> None:
    if config.environment != "production":
        return
    errors: list[str] = []
    if config.database.ssl_mode != "verify-full":
        errors.append("database.ssl_mode must be verify-full")
    if not config.database.ssl_ca_file:
        errors.append("database.ssl_ca_file is required")
    if errors:
        raise ConfigValidationError("unsafe gateway production runtime: " + "; ".join(errors))


def _require_state_value(state: Any, name: str) -> Any:
    value = getattr(state, name, None)
    if value is None:
        raise DependencyNotReadyError(f"{name} is not initialized")
    return value


async def _audit_unavailable_handler(
    _request: Request, _exc: AuditUnavailableError
) -> JSONResponse:
    return JSONResponse(
        {"error": "audit_unavailable"},
        status_code=503,
        headers={"Retry-After": "1"},
    )


async def _check_migrations(pool: Any) -> dict[str, Any]:
    """Prove code and schema agree, reporting unreachability distinctly.

    A migration mismatch and an unreachable database are different problems
    with different fixes, and both used to arrive as a bare exception type.
    """
    try:
        return dict(await verify_migration_head(pool, "migrations"))
    except DependencyNotReadyError:
        raise
    except Exception as exc:
        raise DependencyNotReadyError(
            f"migration state could not be verified ({type(exc).__name__}); "
            "the control database may be unreachable"
        ) from exc


async def _check_pg_pool(pool: Any) -> dict[str, str]:
    fetchval = getattr(pool, "fetchval", None)
    if not callable(fetchval):
        raise DependencyNotReadyError("pg_pool does not support fetchval")
    try:
        await fetchval("SELECT 1")
    except Exception as exc:
        # Name the dependency and the failure class, and nothing else. A raw
        # driver exception routinely carries the DSN, and only our own
        # readiness errors have their message surfaced in the /ready payload -
        # so this is the boundary where a safe message gets written. Without
        # it a control-plane outage reported "postgres: ConnectionError" with
        # no indication of which dependency that was.
        raise DependencyNotReadyError(
            f"the control database is not reachable ({type(exc).__name__})"
        ) from exc
    return {"kind": "postgres"}


async def _check_redis(redis: Any) -> dict[str, str]:
    ping = getattr(redis, "ping", None)
    if not callable(ping):
        raise DependencyNotReadyError("redis does not support ping")
    try:
        result = ping()
        if inspect.isawaitable(result):
            result = await result
    except Exception as exc:
        raise DependencyNotReadyError(f"redis is not reachable ({type(exc).__name__})") from exc
    if result is False:
        raise DependencyNotReadyError("redis ping failed")
    return {"kind": "redis"}


def _forget_removed_sources(
    *, cache_invalidator: CacheInvalidator, conn_manager: ConnectionManager
) -> Callable[[frozenset[str]], Awaitable[None]]:
    """Drop cached answers and pooled connections for sources no longer served.

    Without this, a source disabled in the console kept answering cached
    statements until their TTL expired.
    """

    async def forget(source_ids: frozenset[str]) -> None:
        for source_id in sorted(source_ids):
            await cache_invalidator.invalidate_for_source(source_id)
            await conn_manager.invalidate(source_id)

    return forget


def _check_registry(registry: Any) -> dict[str, int | str]:
    get_all = getattr(registry, "get_all", None)
    if not callable(get_all):
        raise DependencyNotReadyError("registry does not support get_all")
    return {"kind": "metadata_registry", "sources": len(get_all())}


def _check_pg_proxy(proxy: PGProxy) -> dict[str, int | str]:
    return {"kind": "pg_proxy", "active_connections": int(proxy.active_connections)}


def _check_audit_buffer(buffer: AuditBuffer) -> dict[str, Any]:
    health = buffer.health()
    if health.degraded:
        # Name the reason. The readiness payload used to carry only the
        # exception type, so an operator saw "DependencyNotReadyError" with no
        # indication of which of four conditions had fired - and had no way to
        # tell a transient backlog from a permanent one.
        reasons = []
        if health.memory_backlog:
            reasons.append(f"{health.memory_backlog} event(s) held in memory")
        if health.spool_pending:
            reasons.append(f"{health.spool_pending} event(s) pending in the spool")
        if health.last_error:
            reasons.append(f"last delivery error: {health.last_error}")
        if health.partition is not None and health.partition.degraded:
            reasons.append("audit partition maintenance is degraded")
        raise DependencyNotReadyError("audit delivery is degraded: " + "; ".join(reasons))
    return {
        "kind": "audit",
        "queue_depth": health.queue_depth,
        "spool_pending": health.spool_pending,
        # Reported, never gating: see AuditHealth.degraded. A non-zero value
        # here is worth an alert - events were set aside as unpersistable -
        # but it must not remove a serving gateway from the load balancer.
        "dlq_count": health.dlq_count,
        "has_dead_letters": health.has_dead_letters,
    }


def _check_background_listener(component: Any, attribute: str, name: str) -> dict[str, str]:
    if not bool(getattr(component, attribute, False)):
        raise DependencyNotReadyError(f"{name} listener is not healthy")
    return {"kind": name}


async def _check_vector_index(index: FAISSIndex) -> dict[str, Any]:
    freshness = await index.freshness()
    if not freshness["fresh"]:
        raise DependencyNotReadyError("vector index generation is stale")
    return {"kind": "vector_index", **freshness}


async def _authorize_stats(request: Request) -> JSONResponse | None:
    config: InterLockConfig = request.app.state.config
    if config.observability.public_stats_enabled:
        return None

    token = bearer_token_from_headers(request.headers)
    if not token:
        started = time.monotonic()
        return control_plane_response(
            request,
            {"error": "Authentication required"},
            status_code=401,
            service="gateway",
            route="/stats",
            status="unauthenticated",
            started_at=started,
            headers={"WWW-Authenticate": "Bearer"},
        )

    auth_manager: AuthManager | None = getattr(request.app.state, "auth_manager", None)
    if auth_manager is None:
        started = time.monotonic()
        return control_plane_response(
            request,
            {"error": "Auth backend unavailable"},
            status_code=503,
            service="gateway",
            route="/stats",
            status="auth_unavailable",
            started_at=started,
        )
    try:
        request.state.identity = await auth_manager.authenticate(token)
    except AuthError:
        started = time.monotonic()
        return control_plane_response(
            request,
            {"error": "Authentication required"},
            status_code=401,
            service="gateway",
            route="/stats",
            status="unauthenticated",
            started_at=started,
            headers={"WWW-Authenticate": "Bearer"},
        )
    except Exception:
        logger.exception("Gateway stats authentication failed")
        started = time.monotonic()
        return control_plane_response(
            request,
            {"error": "Auth backend unavailable"},
            status_code=503,
            service="gateway",
            route="/stats",
            status="auth_error",
            started_at=started,
        )
    return None


async def health(request: Request) -> JSONResponse:
    """Return basic health status and active proxy connection count."""
    started = time.monotonic()
    proxy: PGProxy | None = getattr(request.app.state, "pg_proxy", None)
    active = proxy.active_connections if proxy is not None else 0
    im: GatewayInstanceManager | None = getattr(request.app.state, "instance_manager", None)
    return control_plane_response(
        request,
        {
            "status": "ok",
            "service": "gateway",
            "instance_id": im.instance_id if im is not None else None,
            "active_connections": active,
        },
        status_code=200,
        service="gateway",
        route="/health",
        status="ok",
        started_at=started,
    )


async def ready(request: Request) -> JSONResponse:
    """Return dependency-backed readiness for load balancers."""
    started = time.monotonic()
    state = request.app.state
    config: InterLockConfig = state.config
    timeout = config.observability.readiness_timeout_seconds
    checks = {
        "postgres": lambda: _check_pg_pool(_require_state_value(state, "pg_pool")),
        "migrations": lambda: _check_migrations(_require_state_value(state, "pg_pool")),
        "redis": lambda: _check_redis(_require_state_value(state, "redis_client")),
        "registry": lambda: _check_registry(_require_state_value(state, "registry")),
        "pg_proxy": lambda: _check_pg_proxy(_require_state_value(state, "pg_proxy")),
        "audit": lambda: _check_audit_buffer(_require_state_value(state, "audit_buffer")),
        "cache_invalidation": lambda: _check_background_listener(
            _require_state_value(state, "cache_invalidator"),
            "listener_healthy",
            "cache_invalidation",
        ),
        "faiss_sync": lambda: _check_background_listener(
            _require_state_value(state, "faiss_sync"), "healthy", "faiss_sync"
        ),
        "discovery_vector": lambda: _check_vector_index(
            _require_state_value(state, "discovery_index")
        ),
    }
    ok, results = await run_dependency_checks(checks, timeout_seconds=timeout)
    status = "ready" if ok else "not_ready"
    return control_plane_response(
        request,
        {"status": status, "service": "gateway", "checks": results},
        status_code=200 if ok else 503,
        service="gateway",
        route="/ready",
        status=status,
        started_at=started,
    )


async def stats(request: Request) -> JSONResponse:
    """Return cache stats, active connections, and registry source count."""
    started = time.monotonic()
    auth_response = await _authorize_stats(request)
    if auth_response is not None:
        return auth_response

    state = request.app.state

    l1: L1Cache | None = getattr(state, "l1_cache", None)
    l2: L2Cache | None = getattr(state, "l2_cache", None)
    proxy: PGProxy | None = getattr(state, "pg_proxy", None)
    registry: MetadataRegistry | None = getattr(state, "registry", None)

    return control_plane_response(
        request,
        {
            "cache": {
                "l1": l1.stats if l1 is not None else {},
                "l2": l2.stats if l2 is not None else {},
            },
            "active_connections": proxy.active_connections if proxy is not None else 0,
            "registry_sources": len(registry.get_all()) if registry is not None else 0,
        },
        status_code=200,
        service="gateway",
        route="/stats",
        status="ok",
        started_at=started,
    )


# ---------------------------------------------------------------------------
# Lifespan
# ---------------------------------------------------------------------------


@asynccontextmanager
async def lifespan(app: Starlette) -> AsyncIterator[None]:
    """Manage startup and shutdown of all gateway dependencies.

    AUDIT-COVERS: P0-A
        The HTTPProxy and MCPAdapter instances are constructed in
        ``create_app`` and stashed on ``app.state``. Lifespan looks them
        up by name and calls ``initialize()`` on the same instance whose
        routes were registered, eliminating the double-construction bug
        that caused live ``/proxy/...`` requests to return
        "HTTP proxy not initialized".
    """
    config: InterLockConfig = app.state.config

    # -- Startup ----------------------------------------------------------
    logger.info("Gateway starting up")

    pg_pool = await create_pg_pool(config.database)
    app.state.pg_pool = pg_pool

    redis_client = await create_redis_client(config.redis)
    app.state.redis_client = redis_client

    # Multi-instance coordination
    instance_manager = GatewayInstanceManager(redis_client=redis_client)
    await instance_manager.start()
    app.state.instance_manager = instance_manager

    registry = MetadataRegistry(pg_pool)
    await registry.load()
    await registry.setup_listener()
    app.state.registry = registry

    l1_cache = L1Cache(
        max_size=config.cache.l1_max_size,
        ttl_seconds=config.cache.l1_ttl_seconds,
    )
    app.state.l1_cache = l1_cache

    l2_cache = L2Cache(
        redis_client=redis_client,
        ttl_seconds=config.cache.l2_ttl_seconds,
    )
    app.state.l2_cache = l2_cache

    # P1-E: async buffered audit writer. Writes are batched via
    # asyncpg.copy_records_to_table on a background flusher; logging
    # from the request path is non-blocking.
    audit_buffer = AuditBuffer(
        pg_pool,
        max_size=config.audit.buffer_max_size,
        flush_interval_ms=config.audit.flush_interval_ms,
        flush_batch_size=config.audit.flush_batch_size,
        retry_attempts=config.audit.retry_max_attempts,
        retry_base_seconds=config.audit.retry_base_delay_ms / 1000.0,
        spool_dir=config.audit.spool_path,
        durability_mode=config.audit.durability_mode,
        partition_interval_seconds=config.audit.partition_maintenance_interval_seconds,
        partition_months_back=config.audit.partition_months_back,
        partition_months_forward=config.audit.partition_months_ahead,
    )
    await audit_buffer.start()
    app.state.audit_buffer = audit_buffer

    audit_logger = AuditLogger(pg_pool, buffer=audit_buffer)
    app.state.audit_logger = audit_logger

    # Circuit breaker registry
    circuit_breakers = CircuitBreakerRegistry()
    app.state.circuit_breakers = circuit_breakers

    fabric_services = build_fabric_services(pg_pool, config.fabric)
    app.state.fabric_services = fabric_services
    conn_manager = ConnectionManager(
        registry,
        circuit_breakers=circuit_breakers,
        # The same judgement the PG-wire listener has always applied, so
        # one stored source cannot be refused on one protocol and served
        # on another.
        allow_insecure_upstream_tls=allows_insecure_upstream_tls(config),
        fabric_services=fabric_services,
    )
    app.state.conn_manager = conn_manager

    # PII scanner and response processor
    pii_fast_scanner = PIIFastScanner()
    pii_deep_scanner: PIIDeepScanner | None = None
    if config.pii.deep_enabled:
        pii_deep_scanner = PIIDeepScanner(max_workers=config.pii.deep_max_workers)
        await pii_deep_scanner.initialize()
        if not pii_deep_scanner.available:
            logger.warning(
                "Deep PII scanning requested but unavailable; install interlock-runtime[pii] "
                "and the configured NLP model to enable contextual detection."
            )
    pii_scanner = ResponseProcessor(
        fast_scanner=pii_fast_scanner,
        deep_scanner=pii_deep_scanner,
        config=config.pii,
    )
    app.state.pii_scanner = pii_scanner
    app.state.pii_fast_scanner = pii_fast_scanner
    app.state.pii_deep_scanner = pii_deep_scanner

    # Embedding engine - shared by semantic cache strategy and the
    # discovery search engine. P1-D / P0-E both depend on this being
    # constructed in lifespan and stored on app.state. We tolerate
    # missing ML extras (sentence-transformers) by falling back to a
    # disabled engine that returns None on encode().
    embedding_engine = EmbeddingEngine()
    try:
        await embedding_engine.initialize()
    except Exception:
        logger.warning(
            "Embedding engine unavailable; semantic cache and discovery "
            "vector search will be disabled until ML extras are installed."
        )
        embedding_engine = None
    app.state.embedding_engine = embedding_engine

    # Separate semantic indexes are required: cache entries and discovery
    # assets have different lifecycles and metadata. Keeping them in
    # separate Redis/FAISS namespaces prevents cache hits from appearing
    # as discovery results and lets workers publish discovery vectors
    # independently.
    semantic_index = FAISSIndex(
        dimension=config.semantic_cache.embedding_dimension,
        redis_client=redis_client,
        namespace="cache",
    )
    await semantic_index.initialize()
    app.state.semantic_index = semantic_index

    discovery_index = FAISSIndex(
        dimension=config.semantic_cache.embedding_dimension,
        redis_client=redis_client,
        namespace="discovery",
    )
    await discovery_index.initialize()
    app.state.discovery_index = discovery_index

    # Discovery search engine. AUDIT-COVERS: P0-E. The MCPAdapter looks
    # up app.state.discovery_search at request time, so wiring it here
    # closes the gap reported in mcp_adapter.py:320-325.
    discovery_search = DiscoverySearch(
        pg_pool=pg_pool,
        semantic_index=discovery_index,
        embedding_engine=embedding_engine,
    )
    app.state.discovery_search = discovery_search

    faiss_sync = FAISSIndexSync(
        cache_index=semantic_index,
        discovery_index=discovery_index,
        redis_client=redis_client,
        reconnect_backoff_seconds=config.cache.pubsub_reconnect_seconds,
    )
    await faiss_sync.start()
    app.state.faiss_sync = faiss_sync

    # Adaptive cache strategy (L1 -> L2 -> Semantic).
    #
    # The resolver is what makes a source's own cache_strategy mean anything.
    # A single shared strategy used to serve every source, so the column was
    # written, displayed and editable while having no effect - a source set to
    # `bypass` was cached like any other.
    cache_strategies = CacheStrategyResolver(
        l1=l1_cache,
        l2=l2_cache,
        semantic_index=semantic_index,
    )
    app.state.cache_strategies = cache_strategies
    # Retained as the default for callers that have no source in hand.
    cache_strategy = cache_strategies.by_name(None)
    app.state.cache_strategy = cache_strategy

    # Cache invalidator
    cache_invalidator = CacheInvalidator(
        l1=l1_cache,
        l2=l2_cache,
        semantic_index=semantic_index,
        redis_client=redis_client,
        pg_pool=pg_pool,
        instance_id=instance_manager.instance_id,
        source_generation_barrier=SourceGenerationBarrier.for_prefix(
            redis_client, config.cache.source_generation_prefix
        ),
        reconnect_backoff_seconds=config.cache.pubsub_reconnect_seconds,
    )
    await cache_invalidator.start_listener()
    app.state.cache_invalidator = cache_invalidator
    registry.add_removal_listener(
        _forget_removed_sources(cache_invalidator=cache_invalidator, conn_manager=conn_manager)
    )
    cache_barrier_strict = config.cache.strict_write_barrier
    app.state.cache_barrier_strict = cache_barrier_strict

    # HTTP/REST reverse proxy.
    # The instance was constructed in create_app() so that get_routes()
    # binds to the same object we now initialize. This is the P0-A fix.
    http_proxy: HTTPProxy = app.state.http_proxy
    await http_proxy.initialize()

    # Auth, policy, write classifier, approval queue
    oidc_provider: OIDCProvider | None = None
    if config.auth.oidc.enabled:
        oidc_provider = OIDCProvider(
            issuer_url=config.auth.oidc.issuer_url,
            client_id=config.auth.oidc.agent_audience,
            client_secret="",
            scopes=config.auth.oidc.scopes,
            allow_insecure_endpoints=config.auth.oidc.allow_insecure_endpoints,
        )
        await oidc_provider.initialize()
    auth_manager = AuthManager(
        pg_pool,
        redis_client,
        config.auth,
        oidc_provider=oidc_provider,
    )
    app.state.oidc_provider = oidc_provider
    app.state.auth_manager = auth_manager

    policy_engine = PolicyEngine(pg_pool)
    await policy_engine.load()
    await policy_engine.setup_listener()
    app.state.policy_engine = policy_engine

    source_role_evaluator = SourceRoleEvaluator(pg_pool)
    app.state.source_role_evaluator = source_role_evaluator

    # How each SQL source resolves a bare table name, from the source catalog.
    sql_naming_resolver = CatalogNamingResolver(pg_pool, registry, fabric_services=fabric_services)
    await sql_naming_resolver.setup_listener()
    app.state.sql_naming_resolver = sql_naming_resolver

    write_classifier = WriteClassifier(critical_tables=set())
    app.state.write_classifier = write_classifier

    rate_limiter = RateLimiter(redis_client)
    await rate_limiter.initialize()
    app.state.rate_limiter = rate_limiter

    approval_notifier = build_approval_notifier(config)
    app.state.approval_notifier = approval_notifier
    approval_queue = ApprovalQueue(
        pg_pool,
        conn_manager,
        expiry_seconds=config.approvals.expiry_seconds,
        cache_invalidator=cache_invalidator,
        registry=registry,
        cache_barrier_strict=cache_barrier_strict,
        notifier=approval_notifier,
        fabric_services=fabric_services,
        expiry_sweep_interval_seconds=config.approvals.expiry_sweep_interval_seconds,
    )
    await approval_queue.start_expiry_task()
    app.state.approval_queue = approval_queue

    pg_client_ssl_context: ssl.SSLContext | None = None
    if config.gateway.pg_tls_cert_file and config.gateway.pg_tls_key_file:
        pg_client_ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        pg_client_ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2
        pg_client_ssl_context.load_cert_chain(
            config.gateway.pg_tls_cert_file,
            config.gateway.pg_tls_key_file,
        )

    pg_proxy = PGProxy(
        listen_host=config.gateway.host,
        listen_port=config.gateway.pg_port,
        upstream_host=config.gateway.upstream_pg_host,
        upstream_port=config.gateway.upstream_pg_port,
        l1_cache=l1_cache,
        l2_cache=l2_cache,
        audit_logger=audit_logger,
        auth_manager=auth_manager,
        policy_engine=policy_engine,
        write_classifier=write_classifier,
        approval_queue=approval_queue,
        pii_scanner=pii_fast_scanner,
        cache_strategy=cache_strategy,
        cache_strategies=cache_strategies,
        rate_limiter=rate_limiter,
        # P1-C: route via Metadata Registry. Falls back to the
        # configured upstream when no source matches the requested
        # database name.
        registry=registry,
        # P1-D: pass the embedding engine in so the proxy can produce
        # intent embeddings for the semantic cache strategy.
        embedding_engine=embedding_engine,
        source_role_evaluator=source_role_evaluator,
        sql_naming=sql_naming_resolver,
        cache_invalidator=cache_invalidator,
        max_startup_bytes=config.gateway.pg_max_startup_bytes,
        max_message_bytes=config.gateway.pg_max_message_bytes,
        max_result_bytes=config.gateway.pg_max_result_bytes,
        startup_timeout_seconds=config.gateway.pg_startup_timeout_seconds,
        auth_timeout_seconds=config.gateway.pg_auth_timeout_seconds,
        frame_timeout_seconds=config.gateway.pg_frame_timeout_seconds,
        max_connections=config.gateway.pg_max_clients,
        allow_insecure_upstream_tls=allows_insecure_upstream_tls(config),
        cache_barrier_strict=cache_barrier_strict,
        client_ssl_context=pg_client_ssl_context,
        require_client_tls=(
            config.gateway.pg_require_client_tls and not config.gateway.pg_trusted_tls_offload
        ),
    )
    await pg_proxy.start()
    app.state.pg_proxy = pg_proxy

    logger.info("Gateway startup complete")

    yield

    # -- Shutdown ---------------------------------------------------------
    logger.info("Gateway shutting down")

    await approval_queue.stop_expiry_task()
    await sql_naming_resolver.close()
    if approval_notifier is not None:
        await approval_notifier.aclose()
    await cache_invalidator.stop_listener()
    await faiss_sync.stop()
    await http_proxy.shutdown()
    await pg_proxy.stop()
    if pii_deep_scanner is not None:
        await pii_deep_scanner.shutdown()
    await audit_buffer.shutdown()
    await instance_manager.stop()
    await conn_manager.close_all()
    if fabric_services is not None:
        await fabric_services.close()
    await close_redis_client(redis_client)
    await close_pg_pool(pg_pool)

    logger.info("Gateway shutdown complete")


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------


def create_app(config: InterLockConfig | None = None) -> Starlette:
    """Create and return the Gateway Starlette application.

    Parameters
    ----------
    config:
        If *None*, configuration is loaded from the default YAML / env
        sources via ``load_config()``.
    """
    if config is None:
        config = load_config()
    _validate_runtime_security(config)

    # P0-A fix: construct the HTTPProxy and MCPAdapter once, here, and
    # register their routes from those exact instances. Lifespan then
    # looks them up on app.state and calls initialize() on the same
    # objects, so live /proxy/... requests reach an initialized client.
    mcp_adapter = MCPAdapter(
        max_request_bytes=config.gateway.mcp_max_body_bytes,
        max_tool_limit=config.gateway.mcp_max_results,
    )
    http_proxy = HTTPProxy(
        max_request_bytes=config.gateway.http_max_request_body_bytes,
        max_response_bytes=config.gateway.http_max_response_body_bytes,
        max_connections=config.gateway.http_max_connections,
        max_keepalive_connections=config.gateway.http_max_keepalive_connections,
        timeout_seconds=config.gateway.http_timeout_seconds,
    )

    routes = [
        Route("/health", health),
        Route("/ready", ready),
        Route("/stats", stats),
        *mcp_adapter.get_routes(),
        *http_proxy.get_routes(),
    ]

    app = Starlette(
        routes=routes,
        lifespan=lifespan,
        exception_handlers={AuditUnavailableError: _audit_unavailable_handler},
    )
    app.state.config = config
    app.state.http_proxy = http_proxy
    app.state.mcp_adapter = mcp_adapter
    app.state.mcp_allowed_origins = tuple(config.gateway.mcp_allowed_origins)
    app.state.otel = configure_service_otel(
        service_name="interlock-gateway",
        config=config,
        app=app,
    )
    return app
