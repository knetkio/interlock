"""Ingestion worker core loop - claims and processes jobs from the PG queue."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import tempfile
import time
from contextlib import suppress
from pathlib import Path
from typing import TYPE_CHECKING, Any

import asyncpg

from interlock.connections.connectors import get_adapter
from interlock.worker.extractors.base import ExtractedContent, ExtractionRegistry
from interlock.worker.indexer import DocumentIndexer
from interlock.worker.sampler import ContentSampler
from interlock.worker.summarizer import DocumentSummarizer

if TYPE_CHECKING:
    from interlock.connections.fabric.runtime import FabricServices

logger = logging.getLogger(__name__)

ACTIVE_JOB_STATUSES = ("extracting", "summarizing", "indexing", "processing")
ACTIVE_JOB_STATUS_SQL = "'extracting', 'summarizing', 'indexing', 'processing'"


class JobLeaseLostError(RuntimeError):
    """Raised when a worker no longer owns an active job lease."""


def _updated_count(result: object) -> int | None:
    """Return asyncpg UPDATE count when available."""
    if not isinstance(result, str):
        return None
    parts = result.split()
    if len(parts) == 2 and parts[0].upper() == "UPDATE":
        try:
            return int(parts[1])
        except ValueError:
            return None
    return None


# SQL for atomic job claim with advisory locking
_CLAIM_SQL = """
WITH quarantine AS (
    UPDATE ingestion_jobs
    SET status = 'failed',
        stage = 'quarantined',
        worker_id = NULL,
        lease_expires_at = NULL,
        completed_at = NOW(),
        last_error_at = NOW(),
        error_message = 'Worker lease reclaim limit exceeded',
        updated_at = NOW(),
        metadata = COALESCE(metadata, '{}'::jsonb)
                   || jsonb_build_object(
                       'quarantined_at', NOW(),
                       'quarantine_reason', 'lease_reclaim_limit_exceeded',
                       'lease_reclaim_limit', $3::int
                   )
    WHERE status IN ('extracting', 'summarizing', 'indexing', 'processing')
      AND lease_expires_at IS NOT NULL
      AND lease_expires_at < NOW()
      AND CASE
            WHEN COALESCE(metadata->>'lease_reclaim_count', '') ~ '^[0-9]+$'
            THEN (metadata->>'lease_reclaim_count')::int
            ELSE 0
          END >= $3::int
    RETURNING id
),
next_job AS (
    SELECT id,
           status AS previous_status,
           CASE
             WHEN COALESCE(metadata->>'lease_reclaim_count', '') ~ '^[0-9]+$'
             THEN (metadata->>'lease_reclaim_count')::int
             ELSE 0
           END AS previous_reclaim_count
    FROM ingestion_jobs
    WHERE status = 'queued'
       OR (status IN ('extracting', 'summarizing', 'indexing', 'processing')
           AND lease_expires_at IS NOT NULL
           AND lease_expires_at < NOW()
           AND CASE
                 WHEN COALESCE(metadata->>'lease_reclaim_count', '') ~ '^[0-9]+$'
                 THEN (metadata->>'lease_reclaim_count')::int
                 ELSE 0
               END < $3::int)
    ORDER BY priority_score DESC, created_at ASC
    LIMIT 1
    FOR UPDATE SKIP LOCKED
)
UPDATE ingestion_jobs
SET status = 'extracting',
    stage = 'extracting',
    worker_id = $1,
    started_at = COALESCE(started_at, NOW()),
    lease_expires_at = NOW() + ($2 || ' seconds')::INTERVAL,
    updated_at = NOW(),
    metadata = CASE
        WHEN next_job.previous_status = 'queued' THEN COALESCE(ingestion_jobs.metadata, '{}'::jsonb)
        ELSE COALESCE(ingestion_jobs.metadata, '{}'::jsonb)
             || jsonb_build_object(
                 'lease_reclaim_count', next_job.previous_reclaim_count + 1,
                 'last_reclaimed_at', NOW(),
                 'last_reclaimed_by', $1::text
             )
    END
FROM next_job
WHERE ingestion_jobs.id = next_job.id
RETURNING ingestion_jobs.*
"""


class IngestionWorker:
    """Claims and processes ingestion jobs from the PG queue.

    Pipeline: extract -> sample -> summarize -> index

    Uses SELECT FOR UPDATE SKIP LOCKED for distributed job claiming,
    heartbeat via Redis for liveness monitoring, and automatic retry
    for transient failures.
    """

    def __init__(
        self,
        worker_id: str,
        pg_pool: asyncpg.Pool,
        redis_client: Any | None = None,
        extraction_registry: ExtractionRegistry | None = None,
        sampler: ContentSampler | None = None,
        summarizer: DocumentSummarizer | None = None,
        indexer: DocumentIndexer | None = None,
        heartbeat_interval: float = 30.0,
        max_retries: int = 3,
        poll_interval: float = 2.0,
        concurrency: int = 1,
        lease_seconds: int = 300,
        max_lease_reclaims: int = 3,
        *,
        fabric_services: FabricServices | None = None,
    ) -> None:
        self._fabric_services = fabric_services
        self._worker_id = worker_id
        self._pool = pg_pool
        self._redis = redis_client
        self._extraction_registry = extraction_registry
        self._sampler = sampler or ContentSampler()
        self._summarizer = summarizer
        self._indexer = indexer
        self._heartbeat_interval = heartbeat_interval
        self._max_retries = max_retries
        self._poll_interval = poll_interval
        self._concurrency = max(1, concurrency)
        self._lease_seconds = lease_seconds
        self._max_lease_reclaims = max(1, max_lease_reclaims)

        self._running = False
        self._claim_task: asyncio.Task[None] | None = None
        self._heartbeat_task: asyncio.Task[None] | None = None
        self._current_job_id: int | None = None
        self._active_job_ids: set[int] = set()
        self._active_tasks: set[asyncio.Task[None]] = set()

    @property
    def worker_id(self) -> str:
        return self._worker_id

    @property
    def running(self) -> bool:
        return self._running

    async def start(self) -> None:
        """Start the claim loop and heartbeat task."""
        if self._running:
            return

        self._running = True
        logger.info("Worker %s starting", self._worker_id)

        self._claim_task = asyncio.create_task(
            self._claim_loop(), name=f"worker-{self._worker_id}-claim"
        )
        self._heartbeat_task = asyncio.create_task(
            self._heartbeat(), name=f"worker-{self._worker_id}-heartbeat"
        )

    async def stop(self) -> None:
        """Stop processing gracefully."""
        if not self._running:
            return

        logger.info("Worker %s stopping", self._worker_id)
        self._running = False

        for task in (self._claim_task, self._heartbeat_task):
            if task is not None and not task.done():
                task.cancel()
                with suppress(asyncio.CancelledError):
                    await task

        self._claim_task = None
        self._heartbeat_task = None
        for task in list(self._active_tasks):
            if not task.done():
                task.cancel()
        if self._active_tasks:
            await asyncio.gather(*self._active_tasks, return_exceptions=True)
        self._active_tasks.clear()
        self._active_job_ids.clear()
        logger.info("Worker %s stopped", self._worker_id)

    async def _claim_loop(self) -> None:
        """Main loop: claim jobs up to concurrency and process them."""
        logger.info("Worker %s claim loop started", self._worker_id)
        try:
            while self._running:
                try:
                    self._active_tasks = {t for t in self._active_tasks if not t.done()}
                    if len(self._active_tasks) >= self._concurrency:
                        await asyncio.wait(
                            self._active_tasks,
                            timeout=0.5,
                            return_when=asyncio.FIRST_COMPLETED,
                        )
                        continue

                    job = await self._claim_job()
                    if job is None:
                        # No jobs available - back off
                        await asyncio.sleep(self._poll_interval)
                        continue

                    task = asyncio.create_task(
                        self._run_claimed_job(job),
                        name=f"worker-{self._worker_id}-job-{job['id']}",
                    )
                    self._active_tasks.add(task)
                except asyncio.CancelledError:
                    raise
                except Exception:
                    # A transient failure must not end the loop. Only
                    # CancelledError did before, so any other exception -
                    # notably the connection error raised by `_claim_job` when
                    # the control database goes away - escaped the `while` and
                    # terminated claiming for the life of the process. The
                    # worker stayed alive and its container stayed healthy
                    # while ingestion was silently dead, and jobs accumulated
                    # as `queued` with nothing surfacing the fault.
                    #
                    # Verified: a 15s control-database outage left a worker
                    # that never claimed again, and only a restart recovered
                    # it. Backing off and continuing is what makes the outage
                    # transient rather than terminal.
                    logger.exception(
                        "Worker %s claim iteration failed; retrying after %.1fs",
                        self._worker_id,
                        self._poll_interval,
                    )
                    await asyncio.sleep(self._poll_interval)

        except asyncio.CancelledError:
            logger.info("Worker %s claim loop cancelled", self._worker_id)

    async def _claim_job(self) -> dict[str, Any] | None:
        """Atomically claim the highest-priority queued job.

        Uses SELECT FOR UPDATE SKIP LOCKED so multiple workers
        never claim the same job.
        """
        row = await self._pool.fetchrow(
            _CLAIM_SQL,
            self._worker_id,
            str(self._lease_seconds),
            self._max_lease_reclaims,
        )
        if row is None:
            return None
        return dict(row)

    async def _run_claimed_job(self, job: dict[str, Any]) -> None:
        """Process one claimed job and persist its terminal state."""
        job_id = job["id"]
        self._current_job_id = job_id
        self._active_job_ids.add(job_id)
        logger.info(
            "Worker %s claimed job %d: %s",
            self._worker_id,
            job_id,
            job.get("file_path", "unknown"),
        )

        try:
            await self._process_job(job)
            completed = await self._mark_complete(job_id)
            if completed:
                logger.info("Worker %s completed job %d", self._worker_id, job_id)
            else:
                logger.info(
                    "Worker %s skipped completion for job %d because the lease/status changed",
                    self._worker_id,
                    job_id,
                )
        except asyncio.CancelledError:
            await self._release_claimed_job(job_id)
            raise
        except JobLeaseLostError:
            logger.info(
                "Worker %s stopped job %d because the active lease was lost",
                self._worker_id,
                job_id,
            )
        except Exception as exc:
            error_msg = f"{type(exc).__name__}: {exc}"
            logger.exception(
                "Worker %s failed job %d: %s",
                self._worker_id,
                job_id,
                error_msg,
            )
            await self._mark_failed(job_id, error_msg)
        finally:
            self._active_job_ids.discard(job_id)
            self._current_job_id = next(iter(self._active_job_ids), None)

    async def _release_claimed_job(self, job_id: int) -> None:
        """Release a claimed job back to the queue when this worker is cancelled."""
        await self._pool.execute(
            """
            UPDATE ingestion_jobs
            SET status = 'queued',
                stage = 'queued',
                worker_id = NULL,
                started_at = NULL,
                lease_expires_at = NULL,
                updated_at = NOW(),
                metadata = COALESCE(metadata, '{}'::jsonb)
                           || jsonb_build_object(
                               'released_by_worker', $2::text,
                               'release_reason', 'worker_cancelled',
                               'released_at', NOW()
                           )
            WHERE id = $1
              AND worker_id = $2
              AND status IN ('extracting', 'summarizing', 'indexing', 'processing')
            """,
            job_id,
            self._worker_id,
        )

    async def _process_job(self, job: dict[str, Any]) -> None:
        """Execute the full ingestion pipeline: extract -> sample -> summarize -> index."""
        original_file_path = job["file_path"]
        file_path = original_file_path
        source_id = job["source_id"]
        job_metadata = job.get("metadata", {})
        if isinstance(job_metadata, str):
            job_metadata = json.loads(job_metadata)

        # Step 1: Extract content
        await self._set_stage(job["id"], "extracting", status="extracting")
        materialized_path: str | None = None
        try:
            file_path, materialized_path = await self._materialize_asset_if_needed(
                source_id=source_id,
                file_path=original_file_path,
                metadata=job_metadata,
            )
            extracted = await self._extract(file_path)
        finally:
            if materialized_path:
                with suppress(OSError):
                    os.unlink(materialized_path)

        # Step 2: Sample content
        sampled = self._sampler.sample(extracted.text, page_count=extracted.page_count)

        # Step 3: Summarize
        await self._set_stage(job["id"], "summarizing", status="summarizing")
        summary = None
        if self._summarizer is not None:
            summary = await self._summarizer.summarize(
                content=sampled.text,
                file_path=original_file_path,
                metadata=extracted.metadata,
            )
        else:
            # Minimal fallback summary
            from interlock.worker.summarizer import DocumentSummary

            summary = DocumentSummary(
                title=file_path.rsplit("/", 1)[-1] if "/" in file_path else file_path,
                summary=sampled.text[:500],
            )

        # Step 4: Generate embedding if engine available
        await self._set_stage(job["id"], "indexing", status="indexing")
        embedding: list[float] | None = None
        if self._indexer and self._indexer._embedding_engine:
            engine = self._indexer._embedding_engine
            if engine.available:
                embed_text = f"{summary.title} {summary.summary}"
                embedding = await engine.embed(embed_text)
                if not embedding:
                    embedding = None

        # Step 5: Index
        if self._indexer is not None:
            # Embedding can be slow; re-check ownership before side effects.
            await self._set_stage(job["id"], "indexing", status="indexing")
            # Determine asset type from file extension or metadata
            asset_type = job_metadata.get("asset_type", "file")
            await self._indexer.index_document(
                source_id=source_id,
                asset_path=original_file_path,
                asset_type=asset_type,
                content=extracted.text,
                summary=summary,
                embedding=embedding,
            )

    async def _materialize_asset_if_needed(
        self,
        *,
        source_id: str,
        file_path: str,
        metadata: dict[str, Any],
    ) -> tuple[str, str | None]:
        """Download connector-backed assets to a temporary local file.

        Extractors operate on local paths. Connector ingestion jobs keep the
        canonical asset URI in ``file_path`` and use this helper to briefly
        materialize remote content for extraction without changing the indexed
        asset path.
        """
        connector_key = metadata.get("connector_key")
        if not connector_key and not str(file_path).startswith(
            ("s3://", "zendesk://", "slack://", "github://", "gitlab://")
        ):
            return file_path, None

        row = await self._pool.fetchrow(
            "SELECT source_type, connection_config, metadata FROM data_sources WHERE source_id = $1",
            source_id,
        )
        if row is None:
            return file_path, None

        source_metadata = row["metadata"] or {}
        if isinstance(source_metadata, str):
            source_metadata = json.loads(source_metadata)
        connection_config = row["connection_config"] or {}
        if isinstance(connection_config, str):
            connection_config = json.loads(connection_config)

        adapter = get_adapter(
            str(row["source_type"]),
            {"connector_key": connector_key or source_metadata.get("connector_key")},
            fabric_services=self._fabric_services,
            source_id=source_id,
        )
        data = await adapter.fetch_asset(connection_config, file_path)
        suffix = Path(file_path).suffix or ".txt"
        with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as fh:
            fh.write(data)
            return fh.name, fh.name

    async def _set_stage(self, job_id: int, stage: str, *, status: str | None = None) -> None:
        """Persist current processing stage and refresh the worker lease."""
        result = await self._pool.execute(
            """
            UPDATE ingestion_jobs
            SET stage = $2,
                status = COALESCE($3, status),
                lease_expires_at = NOW() + ($4 || ' seconds')::INTERVAL,
                updated_at = NOW()
            WHERE id = $1 AND worker_id = $5
              AND status IN ('extracting', 'summarizing', 'indexing', 'processing')
            """,
            job_id,
            stage,
            status,
            str(self._lease_seconds),
            self._worker_id,
        )
        if _updated_count(result) == 0:
            raise JobLeaseLostError(f"job {job_id} is no longer leased by {self._worker_id}")

    async def _extract(self, file_path: str) -> ExtractedContent:
        """Extract content from a file using the extraction registry."""
        if self._extraction_registry is not None:
            extractor = self._extraction_registry.get_extractor(file_path)
            if extractor is not None:
                return await extractor.extract(file_path)

        # Fallback: return empty content
        logger.warning("No extractor found for %s", file_path)
        return ExtractedContent(text="", metadata={"file_path": file_path})

    async def _mark_complete(self, job_id: int) -> bool:
        """Mark a job as completed."""
        result = await self._pool.execute(
            """
            UPDATE ingestion_jobs
            SET status = CASE
                    WHEN COALESCE(metadata, '{}'::jsonb) ? 'pending_refresh_metadata'
                    THEN 'queued'
                    ELSE 'completed'
                END,
                stage = CASE
                    WHEN COALESCE(metadata, '{}'::jsonb) ? 'pending_refresh_metadata'
                    THEN 'queued'
                    ELSE 'completed'
                END,
                error_message = NULL,
                completed_at = CASE
                    WHEN COALESCE(metadata, '{}'::jsonb) ? 'pending_refresh_metadata'
                    THEN NULL
                    ELSE NOW()
                END,
                started_at = CASE
                    WHEN COALESCE(metadata, '{}'::jsonb) ? 'pending_refresh_metadata'
                    THEN NULL
                    ELSE started_at
                END,
                worker_id = CASE
                    WHEN COALESCE(metadata, '{}'::jsonb) ? 'pending_refresh_metadata'
                    THEN NULL
                    ELSE worker_id
                END,
                lease_expires_at = NULL,
                retry_count = CASE
                    WHEN COALESCE(metadata, '{}'::jsonb) ? 'pending_refresh_metadata'
                    THEN 0
                    ELSE retry_count
                END,
                metadata = CASE
                    WHEN COALESCE(metadata, '{}'::jsonb) ? 'pending_refresh_metadata'
                    THEN (
                        COALESCE(metadata, '{}'::jsonb)
                        - 'pending_refresh_metadata'
                        - 'pending_refresh_requested_at'
                        - 'pending_refresh_reason'
                    )
                    || COALESCE(metadata->'pending_refresh_metadata', '{}'::jsonb)
                    || jsonb_build_object(
                        'requeued_after_active_completion', NOW(),
                        'requeue_reason', 'asset_changed_while_active'
                    )
                    ELSE metadata
                END,
                updated_at = NOW()
            WHERE id = $1 AND worker_id = $2
              AND status = 'indexing'
            """,
            job_id,
            self._worker_id,
        )
        count = _updated_count(result)
        return True if count is None else count > 0

    async def _mark_failed(self, job_id: int, error: str) -> None:
        """Mark a job as failed. If retry_count < max_retries, requeue for retry."""
        row = await self._pool.fetchrow(
            """
            SELECT retry_count
            FROM ingestion_jobs
            WHERE id = $1
              AND worker_id = $2
              AND status IN ('extracting', 'summarizing', 'indexing', 'processing')
            """,
            job_id,
            self._worker_id,
        )
        if row is None:
            return

        current_retries = row["retry_count"]
        new_retry_count = current_retries + 1

        if new_retry_count < self._max_retries:
            # Requeue for retry
            await self._pool.execute(
                """
                UPDATE ingestion_jobs
                SET status = 'queued',
                    stage = 'queued',
                    error_message = $1,
                    retry_count = $2,
                    worker_id = NULL,
                    started_at = NULL,
                    lease_expires_at = NULL,
                    last_error_at = NOW(),
                    updated_at = NOW()
                WHERE id = $3 AND worker_id = $4
                  AND status IN ('extracting', 'summarizing', 'indexing', 'processing')
                """,
                error,
                new_retry_count,
                job_id,
                self._worker_id,
            )
            logger.info(
                "Job %d requeued for retry (%d/%d)",
                job_id,
                new_retry_count,
                self._max_retries,
            )
        else:
            # Max retries exceeded - mark permanently failed
            await self._pool.execute(
                """
                UPDATE ingestion_jobs
                SET status = 'failed',
                    stage = 'failed',
                    error_message = $1,
                    retry_count = $2,
                    completed_at = NOW(),
                    lease_expires_at = NULL,
                    last_error_at = NOW(),
                    updated_at = NOW()
                WHERE id = $3 AND worker_id = $4
                  AND status IN ('extracting', 'summarizing', 'indexing', 'processing')
                """,
                error,
                new_retry_count,
                job_id,
                self._worker_id,
            )
            logger.warning(
                "Job %d permanently failed after %d retries",
                job_id,
                new_retry_count,
            )

    async def _heartbeat(self) -> None:
        """Write heartbeat to Redis every N seconds for liveness monitoring."""
        try:
            while self._running:
                if self._redis is not None:
                    try:
                        key = f"worker:heartbeat:{self._worker_id}"
                        lease_expires_at = time.time() + self._lease_seconds
                        active_job_ids = sorted(self._active_job_ids)
                        value = json.dumps(
                            {
                                "worker_id": self._worker_id,
                                "timestamp": time.time(),
                                "current_job_id": self._current_job_id,
                                "active_job_ids": active_job_ids,
                                "status": "active",
                                "metadata": {
                                    "concurrency": self._concurrency,
                                    "active_jobs": len(active_job_ids),
                                    "current_job": self._current_job_id,
                                    "current_job_id": self._current_job_id,
                                    "active_job_ids": active_job_ids,
                                    "lease_expires_at": (
                                        lease_expires_at if active_job_ids else None
                                    ),
                                    "lease_seconds": self._lease_seconds,
                                },
                            }
                        )
                        await self._redis.set(key, value, ex=int(self._heartbeat_interval * 3))
                    except Exception:
                        logger.exception("Heartbeat write failed for %s", self._worker_id)

                await asyncio.sleep(self._heartbeat_interval)
        except asyncio.CancelledError:
            pass
