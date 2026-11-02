"""Admin API application - management plane.

AUDIT-COVERS: P0-F (admin auth), SR-7/SR-8 (CSRF, secure cookies)
"""

from __future__ import annotations

import asyncio
import inspect
import json
import logging
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager, suppress
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.responses import JSONResponse

from interlock import __version__, release_version
from interlock.admin.auth import env_secret_or_default, hash_password
from interlock.admin.auth_middleware import AdminAuthMiddleware
from interlock.admin.defaults import DEFAULT_ADMIN_PASSWORD, DEFAULT_ADMIN_USERNAME
from interlock.admin.identity_labels import identity_label
from interlock.admin.middleware import AdminRateLimitMiddleware, SecurityHeadersMiddleware
from interlock.cache.embedding import EmbeddingEngine
from interlock.cache.faiss_index import FAISSIndex
from interlock.cache.faiss_sync import FAISSIndexSync
from interlock.cache.generation import SourceGenerationBarrier
from interlock.cache.invalidation import CacheInvalidator
from interlock.catalog.naming import CatalogNamingResolver
from interlock.catalog.queue import enqueue_many
from interlock.config import InterLockConfig, allows_insecure_upstream_tls, load_config
from interlock.connections.circuit_breaker import CircuitBreakerRegistry
from interlock.connections.fabric.runtime import build_fabric_services
from interlock.connections.manager import ConnectionManager
from interlock.core.approval_queue import ApprovalQueue
from interlock.core.oidc import OIDCProvider
from interlock.db.migrations import verify_migration_head
from interlock.db.pool import close_pg_pool, create_pg_pool
from interlock.db.redis import close_redis_client, create_redis_client
from interlock.discovery.category import CategoryManager
from interlock.discovery.entities import EntityManager
from interlock.discovery.search import DiscoverySearch
from interlock.errors import ConfigValidationError, DependencyNotReadyError
from interlock.metadata.registry import MetadataRegistry
from interlock.notifications.factory import build_approval_notifier
from interlock.observability.health import control_plane_response, run_dependency_checks
from interlock.observability.otel import configure_service_otel

logger = logging.getLogger(__name__)

_ADMIN_DIR = Path(__file__).resolve().parent
_TEMPLATES_DIR = _ADMIN_DIR / "templates"
_STATIC_DIR = _ADMIN_DIR / "static"


def _format_datetime(value: Any, fallback: str = "-") -> str:
    """Render timestamps consistently for the operational dashboard."""
    if value in (None, ""):
        return fallback
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return value
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=UTC)
        value = value.astimezone(UTC)
        return value.strftime("%Y-%m-%d %H:%M:%S UTC")
    return str(value)


def _format_duration_ms(value: Any, fallback: str = "-") -> str:
    if value in (None, ""):
        return fallback
    try:
        numeric = float(value)
    except (TypeError, ValueError):
        return str(value)
    if numeric >= 1000:
        return f"{numeric / 1000:.2f}s"
    if numeric >= 10:
        return f"{numeric:.0f}ms"
    return f"{numeric:.1f}ms"


def _short_identifier(value: Any, size: int = 18, fallback: str = "-") -> str:
    if value in (None, ""):
        return fallback
    text = str(value)
    if len(text) <= size:
        return text
    keep = max(4, (size - 1) // 2)
    return f"{text[:keep]}...{text[-keep:]}"


def _pretty_json(value: Any, fallback: str = "-") -> str:
    """Structured audit fields as indented JSON rather than Python's repr."""
    if value in (None, "", {}, []):
        return fallback
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except ValueError:
            return str(value)
    return json.dumps(value, indent=2, sort_keys=True, default=str)


def _install_template_filters(templates: Jinja2Templates) -> None:
    templates.env.filters["fmt_dt"] = _format_datetime
    templates.env.filters["fmt_ms"] = _format_duration_ms
    templates.env.filters["identity_label"] = identity_label
    templates.env.filters["short_id"] = _short_identifier
    templates.env.filters["pretty_json"] = _pretty_json
    # The shell prints this in the sidebar. It is a global rather than per-route
    # context because base.html renders on every page.
    templates.env.globals["interlock_version"] = release_version()


def _validate_runtime_security(config: InterLockConfig) -> None:
    if config.environment != "production":
        return
    errors: list[str] = []
    if not config.admin.cookie_secure:
        errors.append("admin.cookie_secure must be true")
    if len(config.admin.secret_key) < 32:
        errors.append("admin.secret_key must be at least 32 characters")
    if config.database.ssl_mode != "verify-full":
        errors.append("database.ssl_mode must be verify-full")
    if not config.database.ssl_ca_file:
        errors.append("database.ssl_ca_file is required")
    if errors:
        raise ConfigValidationError("unsafe admin production runtime: " + "; ".join(errors))


def _require_state_value(state: Any, name: str) -> Any:
    value = getattr(state, name, None)
    if value is None:
        raise DependencyNotReadyError(f"{name} is not initialized")
    return value


async def _check_pg_pool(pool: Any) -> dict[str, str]:
    fetchval = getattr(pool, "fetchval", None)
    if not callable(fetchval):
        raise DependencyNotReadyError("pg_pool does not support fetchval")
    await fetchval("SELECT 1")
    return {"kind": "postgres"}


async def _check_redis(redis: Any) -> dict[str, str]:
    ping = getattr(redis, "ping", None)
    if not callable(ping):
        raise DependencyNotReadyError("redis does not support ping")
    result = ping()
    if inspect.isawaitable(result):
        result = await result
    if result is False:
        raise DependencyNotReadyError("redis ping failed")
    return {"kind": "redis"}


def _check_registry(registry: Any) -> dict[str, int | str]:
    get_all = getattr(registry, "get_all", None)
    if not callable(get_all):
        raise DependencyNotReadyError("registry does not support get_all")
    return {"kind": "metadata_registry", "sources": len(get_all())}


def _check_faiss_sync(sync: FAISSIndexSync) -> dict[str, str]:
    if not sync.healthy:
        raise DependencyNotReadyError("FAISS synchronization listener is not healthy")
    return {"kind": "faiss_sync"}


async def _check_vector_index(index: FAISSIndex) -> dict[str, Any]:
    freshness = await index.freshness()
    if not freshness["fresh"]:
        raise DependencyNotReadyError("vector index generation is stale")
    return {"kind": "vector_index", **freshness}


async def _bootstrap_admin_if_needed(pg_pool, config: InterLockConfig) -> None:
    """Create the first admin when there is none.

    The password is `INTERLOCK_ADMIN__BOOTSTRAP_PASSWORD` when set, otherwise
    the documented default `admin`. An account created with the default must
    change its password before it can do anything else; an operator-supplied
    password is trusted as chosen. Idempotent: any existing admin row makes
    this a no-op.
    """
    existing = await pg_pool.fetchval("SELECT COUNT(*) FROM admin_identities")
    if existing and int(existing) > 0:
        return
    password = config.admin.bootstrap_password or DEFAULT_ADMIN_PASSWORD
    must_change = password == DEFAULT_ADMIN_PASSWORD
    await pg_pool.execute(
        """
        INSERT INTO admin_identities
            (username, password_hash, roles, enabled, must_change_password)
        VALUES ($1, $2, $3, TRUE, $4)
        ON CONFLICT (username) DO NOTHING
        """,
        DEFAULT_ADMIN_USERNAME,
        hash_password(password),
        ["owner"],
        must_change,
    )
    if must_change:
        logger.warning(
            "Bootstrapped admin user 'admin' with the default password 'admin'. "
            "It must be changed at first sign-in, before the console is usable."
        )
    else:
        logger.warning(
            "Bootstrapped admin user 'admin' from INTERLOCK_ADMIN__BOOTSTRAP_PASSWORD. "
            "Unset the variable once you have signed in."
        )


async def _warn_if_default_password_pending(pg_pool: Any) -> None:
    """Say so at every start while an admin still has to change its password."""
    pending = await pg_pool.fetchval(
        "SELECT COUNT(*) FROM admin_identities WHERE must_change_password AND enabled"
    )
    if pending and int(pending) > 0:
        logger.warning(
            "%d admin account(s) still use a default password and must change it "
            "at next sign-in. Do this before exposing the console.",
            int(pending),
        )


@asynccontextmanager
async def _lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Create PG pool and Redis client on startup, close on shutdown."""
    config: InterLockConfig = app.state.config
    app.state.pg_pool = await create_pg_pool(config.database)
    app.state.redis = await create_redis_client(config.redis)
    app.state.oidc_provider = None
    if config.auth.oidc.enabled:
        oidc = config.auth.oidc
        provider = OIDCProvider(
            issuer_url=oidc.issuer_url,
            client_id=oidc.admin_client_id,
            client_secret=oidc.admin_client_secret,
            redirect_uri=oidc.admin_redirect_uri,
            scopes=oidc.scopes,
            allow_insecure_endpoints=oidc.allow_insecure_endpoints,
        )
        try:
            await provider.initialize()
        except Exception:
            if config.environment == "production":
                raise
            logger.warning("OIDC discovery failed; SSO is unavailable", exc_info=True)
        else:
            app.state.oidc_provider = provider
    registry = MetadataRegistry(app.state.pg_pool)
    await registry.load()
    await registry.setup_listener()
    app.state.registry = registry
    fabric_services = build_fabric_services(app.state.pg_pool, config.fabric)
    app.state.fabric_services = fabric_services
    # The dry-runs resolve SQL names exactly as the gateway does.
    sql_naming_resolver = CatalogNamingResolver(
        app.state.pg_pool, registry, fabric_services=fabric_services
    )
    await sql_naming_resolver.setup_listener()
    app.state.sql_naming_resolver = sql_naming_resolver
    # The signing key was resolved once in create_app() and stored on
    # app.state.admin_secret_key; we MUST NOT re-resolve here because
    # env_secret_or_default() returns a fresh random value when no key
    # is configured, which would desync the AuthMiddleware (constructed
    # from create_app's value) from the login route (which reads
    # app.state). See https://(none) - regression for this exact bug.
    if (
        not config.admin.secret_key
        and "INTERLOCK_ADMIN__SECRET_KEY" not in __import__("os").environ
    ):
        logger.warning(
            "Admin signing key not configured; using ephemeral random key. "
            "Set INTERLOCK_ADMIN__SECRET_KEY in production."
        )
    try:
        await _bootstrap_admin_if_needed(app.state.pg_pool, config)
        await _warn_if_default_password_pending(app.state.pg_pool)
    except Exception:
        logger.exception("admin bootstrap failed; continuing without seed")

    # Discovery subsystem. Mirrors gateway/app.py so the admin process
    # can serve /dashboard/discovery search and rescan controls.
    # Components degrade gracefully when ML extras are missing.
    embedding_engine: EmbeddingEngine | None = EmbeddingEngine()
    try:
        await embedding_engine.initialize()
    except Exception:
        logger.warning(
            "Embedding engine unavailable in admin; discovery vector "
            "search will be disabled until ML extras are installed."
        )
        embedding_engine = None
    app.state.embedding_engine = embedding_engine

    semantic_index = FAISSIndex(
        dimension=config.semantic_cache.embedding_dimension,
        redis_client=app.state.redis,
        namespace="cache",
    )
    try:
        await semantic_index.initialize()
    except Exception:
        logger.warning(
            "FAISS index unavailable in admin; falling back to PG-only " "discovery search."
        )
    app.state.semantic_index = semantic_index

    # The barrier prefix must be the one the gateway reads, or an admin
    # invalidation advances a generation counter no gateway ever consults.
    cache_invalidator = CacheInvalidator(
        semantic_index=semantic_index,
        redis_client=app.state.redis,
        source_generation_barrier=SourceGenerationBarrier.for_prefix(
            app.state.redis, config.cache.source_generation_prefix
        ),
    )
    app.state.cache_invalidator = cache_invalidator

    discovery_index = FAISSIndex(
        dimension=config.semantic_cache.embedding_dimension,
        redis_client=app.state.redis,
        namespace="discovery",
    )
    try:
        await discovery_index.initialize()
    except Exception:
        logger.warning(
            "Discovery FAISS index unavailable in admin; falling back to PG-only "
            "discovery search."
        )
    app.state.discovery_index = discovery_index

    faiss_sync = FAISSIndexSync(
        cache_index=semantic_index,
        discovery_index=discovery_index,
        redis_client=app.state.redis,
        reconnect_backoff_seconds=config.cache.pubsub_reconnect_seconds,
    )
    await faiss_sync.start()
    app.state.faiss_sync = faiss_sync

    app.state.discovery_search = DiscoverySearch(
        pg_pool=app.state.pg_pool,
        semantic_index=discovery_index,
        embedding_engine=embedding_engine,
    )

    circuit_breakers = CircuitBreakerRegistry()
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
    # The Admin resolves approvals, so it emits the approved, rejected and
    # failed events; the Gateway emits pending and expired.
    approval_notifier = build_approval_notifier(config)
    app.state.approval_notifier = approval_notifier
    approval_queue = ApprovalQueue(
        app.state.pg_pool,
        conn_manager,
        expiry_seconds=config.approvals.expiry_seconds,
        cache_invalidator=cache_invalidator,
        registry=registry,
        notifier=approval_notifier,
        fabric_services=fabric_services,
        expiry_sweep_interval_seconds=config.approvals.expiry_sweep_interval_seconds,
    )
    app.state.approval_queue = approval_queue

    entity_manager = EntityManager(app.state.pg_pool)
    category_manager = CategoryManager(app.state.pg_pool)
    app.state.entity_manager = entity_manager
    app.state.category_manager = category_manager

    # The admin no longer scans sources itself: the catalog belongs to the
    # workers, which hold the source credentials and apply the same TLS gate as
    # the gateway. At startup it only queues a first scan for sources that have
    # never had one, so a fresh install's catalog fills without a click.
    if config.admin.catalog_on_startup and config.catalog.enabled:

        async def _initial_catalog_scans() -> None:
            try:
                queued, _ = await enqueue_many(
                    app.state.pg_pool, trigger="startup", only_never_scanned=True
                )
                if queued:
                    logger.info("Queued first catalog scans for %d source(s)", len(queued))
            except Exception:
                logger.warning("Could not queue startup catalog scans", exc_info=True)

        app.state.initial_rescan_task = asyncio.create_task(
            _initial_catalog_scans(), name="catalog-startup-scans"
        )
    try:
        yield
    finally:
        task = getattr(app.state, "initial_rescan_task", None)
        if task is not None and not task.done():
            task.cancel()
            with suppress(asyncio.CancelledError, Exception):
                await task
        await faiss_sync.stop()
        await sql_naming_resolver.close()
        if approval_notifier is not None:
            await approval_notifier.aclose()
        await conn_manager.close_all()
        if fabric_services is not None:
            await fabric_services.close()
        await close_pg_pool(app.state.pg_pool)
        await close_redis_client(app.state.redis)


def create_app(config: InterLockConfig | None = None) -> FastAPI:
    """Create the Admin API application."""
    if config is None:
        config = load_config()
    _validate_runtime_security(config)

    app = FastAPI(
        title="InterLock Admin",
        description="Management plane for InterLock",
        version=__version__,
        docs_url="/docs",
        lifespan=_lifespan,
    )
    app.state.config = config
    app.state.otel = configure_service_otel(
        service_name="interlock-admin",
        config=config,
        app=app,
    )

    # --- templates & static ---
    app.state.templates = Jinja2Templates(directory=str(_TEMPLATES_DIR))
    _install_template_filters(app.state.templates)
    app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")

    # --- routes ---
    from interlock.admin.routes.admin_users import router as admin_users_router
    from interlock.admin.routes.approvals import router as approvals_router
    from interlock.admin.routes.auth import router as auth_router
    from interlock.admin.routes.catalog import router as catalog_router
    from interlock.admin.routes.connectors import router as connectors_router
    from interlock.admin.routes.dashboard import router as dashboard_router
    from interlock.admin.routes.dashboard_admin_users import router as admin_users_pages_router
    from interlock.admin.routes.data_sources import router as ds_router
    from interlock.admin.routes.fabric_auth import install_callback_log_redaction
    from interlock.admin.routes.fabric_auth import router as fabric_router
    from interlock.admin.routes.identities import router as id_router
    from interlock.admin.routes.ingestion import router as ingestion_router
    from interlock.admin.routes.oidc_mappings import router as oidc_mappings_router
    from interlock.admin.routes.password import router as password_router
    from interlock.admin.routes.policies import router as pol_router

    app.include_router(auth_router)
    app.include_router(password_router)
    install_callback_log_redaction()
    app.include_router(fabric_router)
    app.include_router(ds_router)
    app.include_router(pol_router)
    app.include_router(id_router)
    app.include_router(approvals_router)
    app.include_router(ingestion_router)
    app.include_router(oidc_mappings_router)
    app.include_router(admin_users_router)
    # Before the dashboard router, whose /dashboard/data-sources/{source_id}/...
    # routes would otherwise be tried first.
    app.include_router(catalog_router)
    app.include_router(connectors_router)
    app.include_router(admin_users_pages_router)
    app.include_router(dashboard_router)

    # --- middleware ---
    # NOTE: FastAPI/Starlette wraps the most recently added middleware around
    # earlier entries. SecurityHeadersMiddleware is therefore added last so
    # auth, CSRF, and rate-limit early returns still receive CSP/security
    # headers.
    # secret_key is resolved at lifespan startup. We wire the middleware with
    # a closure that defers the lookup so tests can construct the app without
    # Redis available.
    secret_key = env_secret_or_default(config.admin.secret_key)
    app.state.admin_secret_key = secret_key

    app.add_middleware(
        AdminAuthMiddleware,
        cookie_name=config.admin.cookie_name,
        secret_key=secret_key,
    )
    app.add_middleware(AdminRateLimitMiddleware, max_requests=100, window_seconds=60)
    app.add_middleware(SecurityHeadersMiddleware)

    @app.get("/health")
    async def health(request: Request) -> JSONResponse:
        started = time.monotonic()
        return control_plane_response(
            request,
            {"status": "ok", "service": "admin"},
            status_code=200,
            service="admin",
            route="/health",
            status="ok",
            started_at=started,
        )

    @app.get("/ready")
    async def ready(request: Request) -> JSONResponse:
        started = time.monotonic()
        state = request.app.state
        config: InterLockConfig = state.config
        timeout = config.observability.readiness_timeout_seconds
        checks = {
            "postgres": lambda: _check_pg_pool(_require_state_value(state, "pg_pool")),
            "migrations": lambda: verify_migration_head(
                _require_state_value(state, "pg_pool"), "migrations"
            ),
            "redis": lambda: _check_redis(_require_state_value(state, "redis")),
            "registry": lambda: _check_registry(_require_state_value(state, "registry")),
            "faiss_sync": lambda: _check_faiss_sync(_require_state_value(state, "faiss_sync")),
            "discovery_vector": lambda: _check_vector_index(
                _require_state_value(state, "discovery_index")
            ),
        }
        ok, results = await run_dependency_checks(checks, timeout_seconds=timeout)
        status = "ready" if ok else "not_ready"
        return control_plane_response(
            request,
            {"status": status, "service": "admin", "checks": results},
            status_code=200 if ok else 503,
            service="admin",
            route="/ready",
            status=status,
            started_at=started,
        )

    return app
