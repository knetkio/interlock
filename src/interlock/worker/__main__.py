"""Ingestion worker entrypoint - creates and runs the IngestionWorker."""

from __future__ import annotations

import asyncio
import logging
import os
import signal
import uuid
from dataclasses import dataclass
from typing import Any

from interlock.cache.embedding import EmbeddingEngine
from interlock.cache.faiss_index import FAISSIndex
from interlock.catalog.runner import CatalogScanRunner
from interlock.catalog.scheduler import CatalogScheduler
from interlock.config import InterLockConfig, allows_insecure_upstream_tls, load_config
from interlock.connections.fabric.runtime import FabricServices, build_fabric_services
from interlock.connections.manager import ConnectionManager
from interlock.db.pool import close_pg_pool, create_pg_pool
from interlock.db.redis import close_redis_client, create_redis_client
from interlock.discovery.category import CategoryManager
from interlock.discovery.entities import EntityManager
from interlock.discovery.schema_indexer import SchemaIndexer
from interlock.errors import DependencyNotReadyError
from interlock.metadata.registry import MetadataRegistry
from interlock.observability.otel import OTelBootstrapResult, configure_service_otel
from interlock.worker.extractors.base import create_default_registry
from interlock.worker.indexer import DocumentIndexer
from interlock.worker.loop import IngestionWorker
from interlock.worker.sampler import ContentSampler
from interlock.worker.summarizer import DocumentSummarizer

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class WorkerRuntime:
    worker: IngestionWorker
    pg_pool: Any
    redis_client: Any | None
    embedding_engine: EmbeddingEngine | None
    catalog_runner: CatalogScanRunner | None = None
    catalog_scheduler: CatalogScheduler | None = None
    conn_manager: ConnectionManager | None = None
    fabric_services: FabricServices | None = None


def _configure_worker_observability(worker_id: str) -> OTelBootstrapResult:
    """Configure worker process telemetry before long-running work starts."""
    result = configure_service_otel(service_name="interlock-worker")
    logger.info(
        "Worker %s observability bootstrap: configured=%s instrumented=%s reason=%s",
        worker_id,
        result.configured,
        result.instrumented,
        result.reason,
    )
    return result


async def _create_worker_runtime(config: InterLockConfig) -> WorkerRuntime:
    """Initialize worker dependencies from the shared configuration model."""
    worker_id = (
        os.environ.get("WORKER_ID") or config.worker.worker_id or f"worker-{uuid.uuid4().hex[:8]}"
    )
    _configure_worker_observability(worker_id)

    pg_pool = await create_pg_pool(config.database)

    redis_client = None
    candidate = None
    try:
        candidate = await create_redis_client(config.redis)
        await candidate.ping()
        redis_client = candidate
        logger.info("Redis connected at %s", config.redis.url)
    except Exception as exc:
        logger.warning("Redis unavailable for worker runtime", exc_info=True)
        if candidate is not None:
            await close_redis_client(candidate)
        if config.environment == "production":
            await close_pg_pool(pg_pool)
            raise DependencyNotReadyError("Redis is required for production workers") from exc
        redis_client = None

    extraction_registry = create_default_registry()
    sampler = ContentSampler()
    summarizer = DocumentSummarizer(
        api_key=os.environ.get("ANTHROPIC_API_KEY"),
    )

    embedding_engine: EmbeddingEngine | None
    embedding_candidate = EmbeddingEngine()
    try:
        await embedding_candidate.initialize()
        embedding_engine = embedding_candidate
    except Exception:
        logger.warning("Embedding engine unavailable, semantic indexing disabled")
        embedding_engine = None

    semantic_index = None
    if embedding_engine is not None and embedding_engine.available:
        if embedding_engine.dimension != config.semantic_cache.embedding_dimension:
            await embedding_engine.shutdown()
            if redis_client is not None:
                await close_redis_client(redis_client)
            await close_pg_pool(pg_pool)
            raise DependencyNotReadyError(
                "Worker embedding dimension does not match configured vector dimension"
            )
        semantic_index = FAISSIndex(
            dimension=config.semantic_cache.embedding_dimension,
            namespace="discovery",
            redis_client=redis_client,
        )
        await semantic_index.initialize()

    entity_manager = EntityManager(pg_pool)
    category_manager = CategoryManager(pg_pool)
    indexer = DocumentIndexer(
        pg_pool=pg_pool,
        entity_manager=entity_manager,
        category_manager=category_manager,
        semantic_index=semantic_index,
        embedding_engine=embedding_engine,
    )

    fabric_services = build_fabric_services(pg_pool, config.fabric)
    worker = IngestionWorker(
        fabric_services=fabric_services,
        worker_id=worker_id,
        pg_pool=pg_pool,
        redis_client=redis_client,
        extraction_registry=extraction_registry,
        sampler=sampler,
        summarizer=summarizer,
        indexer=indexer,
        heartbeat_interval=config.worker.heartbeat_interval,
        max_retries=config.ingestion.max_retries,
        concurrency=config.worker.concurrency,
        lease_seconds=config.worker.lease_seconds,
    )
    catalog_runner: CatalogScanRunner | None = None
    catalog_scheduler: CatalogScheduler | None = None
    conn_manager: ConnectionManager | None = None
    if config.catalog.enabled:
        # Catalog scans connect to sources, so the worker now needs what the
        # gateway has: a registry of source configurations and a connection
        # manager that resolves secret references and enforces the production
        # TLS rule. It had neither before.
        registry = MetadataRegistry(pg_pool)
        await registry.load()
        await registry.setup_listener()
        conn_manager = ConnectionManager(
            registry,
            allow_insecure_upstream_tls=allows_insecure_upstream_tls(config),
            fabric_services=fabric_services,
        )
        # Discovery follows the catalog: after a scan changes a SQL source, its
        # tables are re-indexed from what the scan recorded instead of being
        # introspected a second time.
        schema_indexer = SchemaIndexer(
            control_pool=pg_pool,
            embedding_engine=embedding_engine,
            document_indexer=indexer,
        )
        catalog_runner = CatalogScanRunner(
            pg_pool=pg_pool,
            registry=registry,
            conn_manager=conn_manager,
            config=config.catalog,
            worker_id=worker_id,
            on_scanned=schema_indexer.index_from_catalog,
            fabric_services=fabric_services,
        )
        if config.catalog.scheduled_refresh_enabled:
            catalog_scheduler = CatalogScheduler(pg_pool=pg_pool, config=config.catalog)

    return WorkerRuntime(
        worker=worker,
        pg_pool=pg_pool,
        redis_client=redis_client,
        embedding_engine=embedding_engine,
        catalog_runner=catalog_runner,
        catalog_scheduler=catalog_scheduler,
        conn_manager=conn_manager,
        fabric_services=fabric_services,
    )


async def _create_and_run_worker() -> None:
    """Initialize all components and run the ingestion worker."""
    runtime = await _create_worker_runtime(load_config())

    # Signal handling for graceful shutdown
    loop = asyncio.get_running_loop()
    shutdown_event = asyncio.Event()

    def _signal_handler() -> None:
        logger.info("Received shutdown signal")
        shutdown_event.set()

    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, _signal_handler)

    # Start worker
    await runtime.worker.start()
    if runtime.catalog_runner is not None:
        await runtime.catalog_runner.start()
    if runtime.catalog_scheduler is not None:
        await runtime.catalog_scheduler.start()
    logger.info("Worker %s running", runtime.worker.worker_id)

    try:
        # Wait for shutdown signal
        await shutdown_event.wait()
    finally:
        # Graceful shutdown
        if runtime.catalog_scheduler is not None:
            await runtime.catalog_scheduler.stop()
        if runtime.catalog_runner is not None:
            await runtime.catalog_runner.stop()
        await runtime.worker.stop()
        if runtime.conn_manager is not None:
            await runtime.conn_manager.close_all()

        if runtime.fabric_services is not None:
            await runtime.fabric_services.close()
        if runtime.redis_client is not None:
            await close_redis_client(runtime.redis_client)
        await close_pg_pool(runtime.pg_pool)

        if runtime.embedding_engine is not None:
            await runtime.embedding_engine.shutdown()

        logger.info("Worker %s shut down cleanly", runtime.worker.worker_id)


def main() -> None:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )
    # uvloop is mandatory for performance parity with the gateway/admin.
    import uvloop

    uvloop.install()
    asyncio.run(_create_and_run_worker())


if __name__ == "__main__":
    main()
