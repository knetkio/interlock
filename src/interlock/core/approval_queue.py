"""Write approval queue - manages pending write approvals with expiry."""

from __future__ import annotations

import asyncio
import base64
import contextlib
import json
import logging
import re
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

import asyncpg
import httpx

from interlock.connections.connectors import get_adapter
from interlock.connections.manager import ConnectionManager
from interlock.connections.source_config import config_bool
from interlock.errors import InterLockError, WriteApprovalRequiredError
from interlock.gateway.pipeline import advance_cache_write_barrier
from interlock.models import RiskLevel
from interlock.notifications.events import ApprovalEvent, event_from_row
from interlock.notifications.service import ApprovalNotifierProtocol
from interlock.security.egress import build_safe_async_http_transport, validate_http_egress_url

if TYPE_CHECKING:
    from interlock.connections.fabric.runtime import FabricServices

if TYPE_CHECKING:
    from interlock.cache.invalidation import CacheInvalidator
    from interlock.metadata.registry import MetadataRegistry

logger = logging.getLogger(__name__)

_INSERT_SQL = """
INSERT INTO write_approval_queue
    (identity_id, source_id, sql_text, risk_level, status, expires_at, request_metadata)
VALUES
    ($1, $2, $3, $4, 'pending', NOW() + ($5 || ' seconds')::INTERVAL, $6)
RETURNING id
"""

_APPROVE_SQL = """
UPDATE write_approval_queue
SET status = 'approved', approved_by = $2
WHERE id = $1
  AND status = 'pending'
  AND (expires_at IS NULL OR expires_at > NOW())
"""

_MARK_EXECUTED_SQL = """
UPDATE write_approval_queue
SET status = 'executed', executed_at = NOW()
WHERE id = $1
"""

# `$2::text` is load-bearing: jsonb_build_object is variadic "any", so without
# an explicit cast PostgreSQL cannot infer the parameter type and the statement
# fails with IndeterminateDatatypeError. That failure used to leave a failed
# write sitting at status='approved' with no error recorded, which the console
# then rendered as a successful approval.
#
# The CASE guards rows written before request_metadata was stored as a real
# object: concatenating a jsonb scalar with an object yields an *array* rather
# than an error, silently corrupting the record instead of annotating it.
_MARK_FAILED_SQL = """
UPDATE write_approval_queue
SET status = 'failed',
    request_metadata = CASE
            WHEN jsonb_typeof(request_metadata) = 'object' THEN request_metadata
            WHEN request_metadata IS NULL THEN '{}'::jsonb
            ELSE jsonb_build_object('original_metadata', request_metadata)
        END
        || jsonb_build_object('execution_error', $2::text, 'failed_at', NOW())
WHERE id = $1
"""

_REJECT_SQL = """
UPDATE write_approval_queue
SET status = 'rejected', approved_by = $2
WHERE id = $1 AND status = 'pending'
"""

_GET_SQL = """
SELECT id, identity_id, source_id, sql_text, risk_level,
       status, approved_by, executed_at, expires_at,
       request_metadata, created_at
FROM write_approval_queue
WHERE id = $1
"""

_LIST_PENDING_SQL = """
SELECT id, identity_id, source_id, sql_text, risk_level,
       status, approved_by, executed_at, expires_at,
       request_metadata, created_at
FROM write_approval_queue
WHERE status = 'pending'
ORDER BY created_at DESC
LIMIT $1
"""

_EXPIRE_SQL = """
UPDATE write_approval_queue
SET status = 'expired'
WHERE status = 'pending' AND expires_at < NOW()
RETURNING id, identity_id, source_id, sql_text, risk_level, expires_at, request_metadata
"""


def _row_to_dict(row: asyncpg.Record) -> dict:
    """Convert an asyncpg Record to a plain dict."""
    result = dict(row)
    # Ensure datetimes are serializable and metadata is a dict
    for key in ("created_at", "expires_at", "executed_at"):
        val = result.get(key)
        if isinstance(val, datetime):
            result[key] = val.isoformat()
    meta = result.get("request_metadata")
    if isinstance(meta, str):
        result["request_metadata"] = json.loads(meta)
    return result


def _parse_metadata(raw: object) -> dict:
    if raw is None:
        return {}
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str):
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return {}
    return {}


def _decode_http_body(body_meta: object) -> bytes | None:
    if not isinstance(body_meta, dict):
        return None
    if body_meta.get("truncated"):
        raise InterLockError("HTTP approval body was truncated and cannot be executed safely")
    data = body_meta.get("data")
    if data is None:
        return None
    if body_meta.get("encoding") == "base64":
        return base64.b64decode(str(data))
    if body_meta.get("encoding") == "json":
        return json.dumps(data).encode("utf-8")
    return str(data).encode("utf-8")


class ApprovalQueue:
    """Manages the write_approval_queue table.

    Writes classified as medium or high risk are submitted here for
    human approval before execution.
    """

    def __init__(
        self,
        pg_pool: asyncpg.Pool,
        connection_manager: ConnectionManager | None = None,
        expiry_seconds: int = 900,
        cache_invalidator: CacheInvalidator | None = None,
        registry: MetadataRegistry | None = None,
        http_client: httpx.AsyncClient | None = None,
        cache_barrier_strict: bool = False,
        *,
        fabric_services: FabricServices | None = None,
        notifier: ApprovalNotifierProtocol | None = None,
        expiry_sweep_interval_seconds: int = 30,
    ) -> None:
        self._fabric_services = fabric_services
        self._pool = pg_pool
        self._conn_mgr = connection_manager
        self._expiry_seconds = expiry_seconds
        self._cache_invalidator = cache_invalidator
        self._registry = registry
        self._http_client = http_client
        self._cache_barrier_strict = cache_barrier_strict
        self._notifier = notifier
        self._expiry_sweep_interval_seconds = expiry_sweep_interval_seconds
        self._expiry_task: asyncio.Task | None = None

    async def submit(
        self,
        identity_id: int,
        source_id: str,
        sql_text: str,
        risk_level: RiskLevel,
        metadata: dict | None = None,
    ) -> int:
        """Submit a write for approval. Returns the approval_id.

        Inserts into write_approval_queue with status='pending' and
        raises WriteApprovalRequiredError so the caller knows the write
        was queued rather than executed.
        """
        # The pool registers json.dumps as the jsonb encoder (db/pool.py), so
        # the dict is passed straight through. Dumping it here as well encoded
        # it twice and stored a JSON *string* in a jsonb column, which made
        # every downstream jsonb operator behave unexpectedly.
        meta_json = metadata or {}
        approval_id: int = await self._pool.fetchval(
            _INSERT_SQL,
            identity_id,
            source_id,
            sql_text,
            risk_level.value,
            str(self._expiry_seconds),
            meta_json,
        )
        self._emit(
            event_from_row(
                "pending",
                {
                    "id": approval_id,
                    "source_id": source_id,
                    "identity_id": identity_id,
                    "risk_level": risk_level.value,
                    "sql_text": sql_text,
                    "request_metadata": meta_json,
                },
                expires_at=datetime.now(UTC) + timedelta(seconds=self._expiry_seconds),
            )
        )
        raise WriteApprovalRequiredError(
            approval_id=approval_id,
            risk_level=risk_level.value,
        )

    def _emit(self, event: ApprovalEvent) -> None:
        """Hand an event to the notifier without ever failing the caller.

        A governance decision has already been made and persisted by the time
        this runs. A notification problem must not become an agent-visible
        error, so every failure mode ends here.
        """
        if self._notifier is None:
            return
        try:
            self._notifier.notify(event)
        except Exception as exc:
            logger.warning(
                "approval notification for %d could not be scheduled: %s",
                event.approval_id,
                type(exc).__name__,
            )

    async def approve(self, approval_id: int, approved_by: str) -> dict:
        """Approve a pending write and optionally execute it.

        Returns {"status": "approved", "executed": bool}.
        Raises InterLockError if the entry is not in pending state.
        """
        result = await self._pool.execute(_APPROVE_SQL, approval_id, approved_by)
        if result == "UPDATE 0":
            with contextlib.suppress(Exception):
                await self._expire_old_approvals()
            raise InterLockError(
                f"Approval {approval_id} cannot be approved "
                "(not found, expired, or not in pending state)"
            )

        executed = False
        row = await self._pool.fetchrow(_GET_SQL, approval_id)
        if row is not None:
            metadata = _parse_metadata(row["request_metadata"])
            # Execution is always attempted. Gating it on whether a
            # ConnectionManager happened to be wired meant a source reached
            # through its own connector was marked approved without the write
            # ever being tried. The executors raise when they cannot run the
            # write, which marks the row failed rather than leaving it reading
            # as a completed write.
            try:
                protocol = metadata.get("protocol", "postgresql")
                source_generation = await advance_cache_write_barrier(
                    self._cache_invalidator,
                    row["source_id"],
                    strict=self._cache_barrier_strict,
                )
                if protocol == "http":
                    await self._execute_http(row, metadata)
                else:
                    await self._execute_sql(row, metadata)
                await self._pool.execute(_MARK_EXECUTED_SQL, approval_id)
                executed = True

                # Invalidate caches after successful write
                await self._invalidate_after_execution(
                    row,
                    metadata,
                    source_generation=source_generation,
                )

            except Exception as exc:
                logger.warning(
                    "Failed to execute approved write %d: %s",
                    approval_id,
                    exc,
                )
                try:
                    await self._pool.execute(_MARK_FAILED_SQL, approval_id, str(exc))
                except Exception:
                    logger.warning(
                        "Failed to mark approval %d as failed",
                        approval_id,
                        exc_info=True,
                    )
                self._emit(
                    event_from_row(
                        "failed",
                        dict(row),
                        actor=approved_by,
                        executed=False,
                        # Class name only: an upstream database error routinely
                        # echoes the values that caused it.
                        failure_kind=type(exc).__name__,
                    )
                )
                raise InterLockError(
                    f"Approved write {approval_id} failed during execution: {exc}"
                ) from exc

        # Fire NOTIFY so listeners know about the approval
        try:
            await self._pool.execute(
                "SELECT pg_notify('onyx_write_approval', $1)",
                json.dumps({"approval_id": approval_id, "status": "approved"}),
            )
        except Exception as exc:
            logger.warning("NOTIFY failed: %s", exc)

        if row is not None:
            # `row` is None when the entry could not be re-read; the approval
            # still stands, there is simply nothing to describe in a message.
            self._emit(
                event_from_row(
                    "approved",
                    dict(row),
                    actor=approved_by,
                    executed=executed,
                )
            )
        return {"status": "approved", "executed": executed}

    async def _execute_sql(self, row: asyncpg.Record, metadata: dict) -> None:
        """Execute an approved SQL write against whatever the source speaks.

        ConnectionManager hands out asyncpg pools, so routing every non-HTTP
        approval through it silently attempted the PostgreSQL wire protocol
        against MySQL and anything else. Dispatch on the source's own type and
        fail closed when nothing can execute it, rather than reporting a write
        as approved that never ran.
        """
        source_id = row["source_id"]
        source = self._registry.get(source_id) if self._registry is not None else None
        source_type = getattr(getattr(source, "source_type", None), "value", None)

        # PostgreSQL keeps the pooled path: it carries the mapped role, which
        # is how row- and column-level grants are enforced upstream.
        if source is None or source_type in (None, "postgresql"):
            if self._conn_mgr is None:
                raise InterLockError("ConnectionManager is required to execute SQL approvals")
            role = (
                metadata.get("mapped_pg_role")
                or metadata.get("identity_mapped_pg_role")
                or metadata.get("pg_role")
            )
            if role:
                pool = await self._conn_mgr.get_pool(source_id, pg_role=role)
            else:
                pool = await self._conn_mgr.get_pool(source_id)
            await pool.execute(row["sql_text"])
            return

        await self._execute_via_adapter(row, source, source_type)

    async def _execute_via_adapter(
        self, row: asyncpg.Record, source: Any, source_type: str
    ) -> None:
        """Run the approved write through the source's own connector."""
        adapter = get_adapter(
            source_type,
            getattr(source, "metadata", None) or {},
            fabric_services=self._fabric_services,
            source_id=row["source_id"],
        )
        execute_write = getattr(adapter, "execute_write", None)
        if execute_write is None:
            raise InterLockError(
                f"Connector for source_type '{source_type}' cannot execute writes; "
                f"approval {row['id']} was not executed"
            )

        request = {
            "source_id": row["source_id"],
            "identity_id": row["identity_id"],
            "connection_config": getattr(source, "connection_config", {}) or {},
            "query": row["sql_text"],
        }
        # Connectors that are not SQL-shaped need a structured request rather
        # than a statement: object storage wants an operation, an asset
        # reference and a body. Forward whatever the approval recorded, so a
        # caller that supplies them reaches the connector intact instead of
        # having them silently dropped here.
        metadata = _parse_metadata(row["request_metadata"])
        for key in ("operation", "asset_ref", "path", "body", "parameters"):
            if metadata.get(key) is not None:
                request[key] = metadata[key]

        try:
            from interlock.connections.fabric.adapter import FabricSQLAdapter
            from interlock.connections.fabric.config import FabricConfig

            if isinstance(adapter, FabricSQLAdapter):
                services = self._fabric_services
                if services is None:
                    raise InterLockError("Fabric authentication services are unavailable")
                config = FabricConfig.from_mapping(request["connection_config"])
                adapter.validate_sql(row["sql_text"], database=config.database)
                authenticated = await services.prepare_source(row["source_id"], config)
                if metadata.get("upstream_identity") != authenticated.upstream_identity:
                    raise InterLockError("Fabric approval identity changed; submit a new request")
                await adapter.execute_prepared(request, authenticated, write=True)
            else:
                await execute_write(request)
        except NotImplementedError as exc:
            # BaseConnectorAdapter.execute_write is a stub for read-only
            # connectors. Treat it as a refusal, not a silent success.
            raise InterLockError(
                f"Connector for source_type '{source_type}' does not implement writes; "
                f"approval {row['id']} was not executed"
            ) from exc
        except (ValueError, KeyError) as exc:
            # The connector rejected the request's *shape*, not its content -
            # typically a structured write reaching it with only a SQL
            # statement. This used to fall through to the generic failure
            # path, so an approval that could never have executed was recorded
            # as a failed write with an opaque message, sending an operator
            # looking for an upstream problem that did not exist.
            raise InterLockError(
                f"Connector for source_type '{source_type}' could not execute approval "
                f"{row['id']}: it requires a structured write request and the approval "
                f"carries only a statement ({type(exc).__name__}: {exc}). "
                "This connector has no governed write entry point yet."
            ) from exc

    async def _execute_http(self, row: asyncpg.Record, metadata: dict) -> None:
        if self._registry is None:
            raise InterLockError("MetadataRegistry is required to execute HTTP approvals")
        source_id = row["source_id"]
        source = self._registry.get(source_id)
        if source is None:
            raise InterLockError(f"Unknown source for HTTP approval: {source_id}")
        base_url = source.base_url
        if not base_url:
            raise InterLockError(f"Source {source_id} has no base_url")

        method = metadata.get("method")
        path = metadata.get("path")
        if not method or path is None:
            raise InterLockError("HTTP approval metadata missing method/path")

        body = _decode_http_body(metadata.get("body"))
        headers = metadata.get("headers") or {}
        params = metadata.get("parameters") or {}
        upstream_url = f"{base_url.rstrip('/')}/{str(path).lstrip('/')}"
        validate_http_egress_url(
            upstream_url,
            allow_private=config_bool(source.connection_config.get("allow_private_egress")),
        )

        if self._http_client is not None:
            response = await self._http_client.request(
                method=method,
                url=upstream_url,
                content=body,
                headers=headers,
                params=params,
            )
        else:
            async with httpx.AsyncClient(
                timeout=30.0,
                follow_redirects=False,
                trust_env=False,
                transport=build_safe_async_http_transport(
                    allow_private=config_bool(source.connection_config.get("allow_private_egress"))
                ),
            ) as client:
                response = await client.request(
                    method=method,
                    url=upstream_url,
                    content=body,
                    headers=headers,
                    params=params,
                )
        if response.status_code >= 400:
            raise InterLockError(
                f"HTTP approval execution failed with status {response.status_code}"
            )

    async def _invalidate_after_execution(
        self,
        row: asyncpg.Record,
        metadata: dict,
        *,
        source_generation: int | None = None,
    ) -> None:
        if self._cache_invalidator is None:
            return
        source_id = row["source_id"]
        try:
            if metadata.get("protocol") == "http":
                if source_generation is not None:
                    await self._cache_invalidator.invalidate_for_tables(
                        source_id,
                        [],
                        source_generation=source_generation,
                    )
                else:
                    await self._cache_invalidator.invalidate_for_source(source_id)
                return

            tables = _extract_tables_from_sql(row["sql_text"])
            if tables or source_generation is not None:
                kwargs = (
                    {"source_generation": source_generation}
                    if source_generation is not None
                    else {}
                )
                await self._cache_invalidator.invalidate_for_tables(
                    source_id,
                    tables,
                    **kwargs,
                )
            else:
                await self._cache_invalidator.invalidate_for_source(source_id)
        except Exception as inv_exc:
            logger.warning(
                "Cache invalidation failed for write %s: %s",
                row["id"],
                inv_exc,
            )

    async def reject(self, approval_id: int, rejected_by: str) -> None:
        """Reject a pending write."""
        result = await self._pool.execute(_REJECT_SQL, approval_id, rejected_by)
        if result == "UPDATE 0":
            raise InterLockError(
                f"Approval {approval_id} cannot be rejected " "(not found or not in pending state)"
            )
        # One extra read on the admin path so the notification can name the
        # source and identity rather than only the id.
        row = await self._pool.fetchrow(_GET_SQL, approval_id)
        if row is not None:
            self._emit(event_from_row("rejected", dict(row), actor=rejected_by))

    async def get(self, approval_id: int) -> dict | None:
        """Get approval details by ID."""
        row = await self._pool.fetchrow(_GET_SQL, approval_id)
        if row is None:
            return None
        return _row_to_dict(row)

    async def list_pending(self, limit: int = 50) -> list[dict]:
        """List pending approvals ordered by created_at DESC."""
        rows = await self._pool.fetch(_LIST_PENDING_SQL, limit)
        return [_row_to_dict(r) for r in rows]

    async def start_expiry_task(self) -> None:
        """Start a background task that expires old pending approvals."""
        if self._expiry_task is not None:
            return

        async def _loop() -> None:
            while True:
                try:
                    count = await self._expire_old_approvals()
                    if count > 0:
                        logger.info("Expired %d pending approvals", count)
                except Exception as exc:
                    logger.warning("Expiry sweep error: %s", exc)
                await asyncio.sleep(self._expiry_sweep_interval_seconds)

        self._expiry_task = asyncio.create_task(_loop())

    async def stop_expiry_task(self) -> None:
        """Stop the background expiry task."""
        if self._expiry_task is not None:
            self._expiry_task.cancel()
            try:
                await self._expiry_task
            except asyncio.CancelledError:
                pass
            self._expiry_task = None

    async def _expire_old_approvals(self) -> int:
        """Mark expired pending approvals as 'expired'. Returns count.

        RETURNING rather than a bare UPDATE so each expired row can be
        notified. The flip out of 'pending' is atomic, so with several
        gateways sweeping concurrently a given row is returned to exactly one
        of them and produces exactly one notification.
        """
        rows = await self._pool.fetch(_EXPIRE_SQL)
        for row in rows:
            self._emit(event_from_row("expired", dict(row)))
        return len(rows)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Regex to extract table names from common DML statements
_TABLE_PATTERN = re.compile(
    r"""
    (?:INSERT\s+INTO|UPDATE|DELETE\s+FROM|TRUNCATE(?:\s+TABLE)?|ALTER\s+TABLE|DROP\s+TABLE)
    \s+
    (?:IF\s+EXISTS\s+)?
    ([A-Za-z_][A-Za-z0-9_."]*)
    """,
    re.IGNORECASE | re.VERBOSE,
)


def _extract_tables_from_sql(sql: str) -> list[str]:
    """Best-effort extraction of table names from a write SQL statement."""
    tables: list[str] = []
    for match in _TABLE_PATTERN.finditer(sql):
        table = match.group(1).strip('"').strip("'")
        if table and table not in tables:
            tables.append(table)
    return tables
