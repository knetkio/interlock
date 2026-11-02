"""Running queued catalog scans in the worker.

Claims with `FOR UPDATE SKIP LOCKED`, so several workers share the queue
without contention, and holds a lease it renews while a scan runs. A worker
that dies mid-scan leaves a lease that expires; another worker reclaims the
scan, up to `max_attempts`. The partial unique index on running scans means a
source is never scanned by two workers at once.

JSON parameters are typed as text and cast in SQL: the worker's pool registers
a JSONB codec, and a JSON string passed straight into a `jsonb` parameter would
be stored as a string scalar rather than an object.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING, Any

import asyncpg

from interlock.catalog.collectors import CollectContext, collector_for
from interlock.catalog.errors import classify_error
from interlock.catalog.exposure import record_exposure
from interlock.catalog.model import ScanLimits
from interlock.catalog.store import apply_snapshot
from interlock.config import CatalogConfig

if TYPE_CHECKING:
    from interlock.connections.fabric.runtime import FabricServices

logger = logging.getLogger(__name__)

CATALOG_CHANGED_CHANNEL = "interlock_catalog_changed"

_CLAIM_SQL = """
UPDATE source_catalog_scans
SET status = 'running',
    worker_id = $1,
    started_at = NOW(),
    lease_expires_at = NOW() + make_interval(secs => $2),
    attempt = attempt + 1
WHERE id = (
    SELECT s.id FROM source_catalog_scans s
    WHERE ((s.status = 'pending' AND s.not_before <= NOW())
           OR (s.status = 'running' AND s.lease_expires_at < NOW() AND s.attempt < $3))
      AND NOT EXISTS (
          SELECT 1 FROM source_catalog_scans r
          WHERE r.source_id = s.source_id AND r.status = 'running'
            AND r.id <> s.id AND r.lease_expires_at >= NOW()
      )
    ORDER BY s.not_before
    LIMIT 1
    FOR UPDATE SKIP LOCKED
)
RETURNING id, source_id, trigger, attempt
"""

_ABANDON_SQL = """
UPDATE source_catalog_scans
SET status = 'failed', finished_at = NOW(), lease_expires_at = NULL,
    error_code = 'abandoned',
    error_message = 'the scan was interrupted too many times to retry'
WHERE status = 'running' AND lease_expires_at < NOW() AND attempt >= $1
"""

_RENEW_SQL = """
UPDATE source_catalog_scans
SET lease_expires_at = NOW() + make_interval(secs => $3)
WHERE id = $1 AND worker_id = $2 AND status = 'running'
"""

_FINISH_SQL = """
UPDATE source_catalog_scans
SET status = $2, finished_at = NOW(), lease_expires_at = NULL, collector = $3,
    nodes_seen = $4, added_count = $5, removed_count = $6, changed_count = $7,
    truncated = $8, truncation = ($9::text)::jsonb, baseline = $10,
    changes_truncated = $11, error_code = $12, error_message = $13
WHERE id = $1
"""


def scan_limits(config: CatalogConfig) -> ScanLimits:
    return ScanLimits(
        max_nodes=config.max_nodes,
        max_schemas=config.max_schemas,
        max_tables=config.max_tables,
        max_columns_per_table=config.max_columns_per_table,
    )


class CatalogScanRunner:
    """Claims and runs catalog scans until stopped."""

    def __init__(
        self,
        *,
        pg_pool: Any,
        registry: Any,
        conn_manager: Any,
        config: CatalogConfig,
        worker_id: str,
        fabric_services: FabricServices | None = None,
        on_scanned: Callable[[str], Awaitable[Any]] | None = None,
    ) -> None:
        self._fabric_services = fabric_services
        self._on_scanned = on_scanned
        self._pool = pg_pool
        self._registry = registry
        self._conn_manager = conn_manager
        self._config = config
        self._worker_id = worker_id
        self._tasks: list[asyncio.Task[None]] = []
        self._stopping = asyncio.Event()

    async def start(self) -> None:
        self._stopping.clear()
        for index in range(self._config.worker_concurrency):
            self._tasks.append(
                asyncio.create_task(self._loop(), name=f"catalog-scan-{self._worker_id}-{index}")
            )
        logger.info(
            "Catalog scan runner started on %s with concurrency %d",
            self._worker_id,
            self._config.worker_concurrency,
        )

    async def stop(self) -> None:
        self._stopping.set()
        for task in self._tasks:
            task.cancel()
        for task in self._tasks:
            with contextlib.suppress(asyncio.CancelledError):
                await task
        self._tasks.clear()

    async def _loop(self) -> None:
        while not self._stopping.is_set():
            try:
                ran = await self.run_once()
            except asyncio.CancelledError:
                raise
            except Exception:
                # A transient control-database problem must not end the loop;
                # the ingestion worker behaves the same way.
                logger.warning("Catalog scan loop error", exc_info=True)
                ran = None
            if ran is None:
                with contextlib.suppress(asyncio.TimeoutError):
                    await asyncio.wait_for(
                        self._stopping.wait(), timeout=self._config.poll_interval_seconds
                    )

    async def claim(self) -> Any | None:
        await self._pool.execute(_ABANDON_SQL, self._config.max_attempts)
        try:
            return await self._pool.fetchrow(
                _CLAIM_SQL,
                self._worker_id,
                float(self._config.lease_seconds),
                self._config.max_attempts,
            )
        except asyncpg.UniqueViolationError:
            # Another row for the same source is still marked running with an
            # expired lease; it is reclaimed on a later pass, then this one runs.
            return None

    async def run_once(self) -> int | None:
        """Claim and run one scan. Returns its id, or None when nothing was due."""
        claimed = await self.claim()
        if claimed is None:
            return None
        await self._run(int(claimed["id"]), str(claimed["source_id"]))
        return int(claimed["id"])

    async def _renew_lease(self, scan_id: int) -> None:
        # Renew three times per lease. One failed renewal must not end the task:
        # a lease left to expire lets another worker reclaim a scan that is
        # still running.
        interval = max(self._config.lease_seconds / 3, 1)
        while True:
            await asyncio.sleep(interval)
            try:
                await self._pool.execute(
                    _RENEW_SQL, scan_id, self._worker_id, float(self._config.lease_seconds)
                )
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.warning("Could not renew the lease on catalog scan %d", scan_id)

    async def _finish(
        self,
        scan_id: int,
        *,
        status: str,
        collector: str | None = None,
        result: Any = None,
        truncated: bool = False,
        truncation: dict[str, Any] | None = None,
        error: tuple[str, str] | None = None,
    ) -> None:
        await self._pool.execute(
            _FINISH_SQL,
            scan_id,
            status,
            collector,
            getattr(result, "nodes_seen", None),
            getattr(result, "added", None),
            getattr(result, "removed", None),
            getattr(result, "changed", None),
            truncated,
            json.dumps(truncation or {}, sort_keys=True),
            bool(getattr(result, "baseline", False)),
            bool(getattr(result, "changes_truncated", False)),
            error[0] if error else None,
            error[1] if error else None,
        )

    async def _run(self, scan_id: int, source_id: str) -> None:
        # Read the source afresh: the save that queued this scan notified the
        # registry, but a scan should never run against a stale configuration.
        await self._registry.load()
        source = self._registry.get(source_id)
        if source is None or not source.enabled:
            await self._finish(
                scan_id,
                status="cancelled",
                error=("disabled", "the source is disabled or no longer exists"),
            )
            return

        connector_key = source.connector_key
        collector = collector_for(connector_key)
        if collector is None:
            await self._finish(
                scan_id,
                status="cancelled",
                error=("unsupported", f"no catalog collector for {connector_key}"),
            )
            return

        context = CollectContext(
            source_id=source_id,
            connector_key=connector_key,
            connection_config=dict(source.connection_config),
            limits=scan_limits(self._config),
            conn_manager=self._conn_manager,
            fabric_services=self._fabric_services,
        )
        lease = asyncio.create_task(self._renew_lease(scan_id))
        try:
            snapshot = await asyncio.wait_for(
                collector(context), timeout=self._config.scan_timeout_seconds
            )
            async with self._pool.acquire() as conn:
                result = await apply_snapshot(
                    conn,
                    source_id=source_id,
                    scan_id=scan_id,
                    snapshot=snapshot,
                    max_change_rows=self._config.max_change_rows_per_scan,
                )
                if result.added and not result.baseline:
                    try:
                        await record_exposure(conn, source_id=source_id, scan_id=scan_id)
                    except Exception:
                        logger.warning(
                            "Could not record drift exposure for scan %d", scan_id, exc_info=True
                        )
            await self._finish(
                scan_id,
                status="succeeded",
                collector=connector_key,
                result=result,
                truncated=snapshot.truncated,
                truncation=snapshot.truncation,
            )
            await self._pool.execute("SELECT pg_notify($1, $2)", CATALOG_CHANGED_CHANNEL, source_id)
            if self._on_scanned is not None and (
                result.baseline or result.added or result.removed or result.changed
            ):
                # Downstream consumers such as discovery indexing follow the
                # catalog; their failure is theirs, and must not turn a scan
                # that succeeded into one recorded as failed.
                try:
                    await self._on_scanned(source_id)
                except Exception:
                    logger.warning("Post-scan processing failed for %s", source_id, exc_info=True)
            logger.info(
                "Catalog scan %d of %s: %d nodes, +%d -%d ~%d%s",
                scan_id,
                source_id,
                result.nodes_seen,
                result.added,
                result.removed,
                result.changed,
                " (truncated)" if snapshot.truncated else "",
            )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            code, message = classify_error(exc)
            logger.warning(
                "Catalog scan %d of %s failed: %s", scan_id, source_id, code, exc_info=True
            )
            await self._finish(
                scan_id, status="failed", collector=connector_key, error=(code, message)
            )
        finally:
            lease.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await lease
