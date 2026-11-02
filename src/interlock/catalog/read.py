"""Read-side queries over the source catalog, for the admin console.

Kept apart from the store so the console never imports the write path, and
typed so the admin routes stay thin. Nothing here reads a source: every answer
comes from what the workers' scans recorded.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from interlock.catalog.collectors import has_collector
from interlock.catalog.model import PII_NAME_HINTS, TABLE_LIKE_NODE_TYPES, looks_like_pii
from interlock.connections.connectors import connector_key_for

# What the console lists per level before asking the admin to search instead.
CHILD_LIMIT = 500
SEARCH_LIMIT = 200
CHANGE_LIMIT = 200
HISTORY_LIMIT = 20


def _json(value: Any) -> dict[str, Any]:
    if isinstance(value, str):
        try:
            value = json.loads(value or "{}")
        except ValueError:
            return {}
    return value if isinstance(value, dict) else {}


@dataclass(frozen=True, slots=True)
class ScanSummary:
    id: int
    trigger: str
    status: str
    requested_by: str | None
    requested_at: datetime | None
    started_at: datetime | None
    finished_at: datetime | None
    nodes_seen: int | None
    added: int | None
    removed: int | None
    changed: int | None
    truncated: bool
    truncation: dict[str, Any]
    baseline: bool
    error_code: str | None
    error_message: str | None

    @classmethod
    def from_row(cls, row: Any) -> ScanSummary:
        return cls(
            id=int(row["id"]),
            trigger=str(row["trigger"]),
            status=str(row["status"]),
            requested_by=row["requested_by"],
            requested_at=row["requested_at"],
            started_at=row["started_at"],
            finished_at=row["finished_at"],
            nodes_seen=row["nodes_seen"],
            added=row["added_count"],
            removed=row["removed_count"],
            changed=row["changed_count"],
            truncated=bool(row["truncated"]),
            truncation=_json(row["truncation"]),
            baseline=bool(row["baseline"]),
            error_code=row["error_code"],
            error_message=row["error_message"],
        )


@dataclass(frozen=True, slots=True)
class CatalogNodeView:
    id: int
    node_type: str
    path: list[str]
    name: str
    resource_key: str
    data_type: str | None
    heuristic_class: str | None
    attributes: dict[str, Any]
    removed: bool
    last_seen_at: datetime | None
    classification: str | None = None
    classification_source: str | None = None
    child_count: int = 0
    source_id: str = ""

    @property
    def expandable(self) -> bool:
        return self.child_count > 0

    @property
    def likely_pii(self) -> bool:
        """A column whose name suggests personal data, until an admin decides."""
        return self.node_type == "column" and looks_like_pii(self.name)

    @property
    def path_param(self) -> str:
        # Path segments can contain dots and slashes, so the console passes a
        # path as JSON rather than joining it.
        return json.dumps(self.path, separators=(",", ":"))


@dataclass(slots=True)
class SourceCatalogStatus:
    source_id: str
    collectable: bool
    enabled: bool
    last_scan: ScanSummary | None = None
    last_success: ScanSummary | None = None
    pending: bool = False
    running: bool = False
    counts: dict[str, int] = field(default_factory=dict)
    unacknowledged_changes: int = 0
    source_attributes: dict[str, Any] = field(default_factory=dict)


_SCAN_COLUMNS = """
    id, trigger, status, requested_by, requested_at, started_at, finished_at,
    nodes_seen, added_count, removed_count, changed_count, truncated, truncation,
    baseline, error_code, error_message
"""


def connector_key_of(row: Any) -> str:
    metadata = _json(row["metadata"])
    return connector_key_for(str(row["source_type"]), metadata)


async def source_status(pool: Any, source_id: str) -> SourceCatalogStatus | None:
    source = await pool.fetchrow(
        "SELECT source_id, source_type, enabled, metadata FROM data_sources WHERE source_id = $1",
        source_id,
    )
    if source is None:
        return None
    status = SourceCatalogStatus(
        source_id=source_id,
        collectable=has_collector(connector_key_of(source)),
        enabled=bool(source["enabled"]),
    )
    scans = await pool.fetch(
        f"SELECT {_SCAN_COLUMNS} FROM source_catalog_scans WHERE source_id = $1 "
        "ORDER BY requested_at DESC, id DESC LIMIT $2",
        source_id,
        HISTORY_LIMIT,
    )
    for row in scans:
        scan = ScanSummary.from_row(row)
        if scan.status == "pending":
            status.pending = True
        elif scan.status == "running":
            status.running = True
        elif status.last_scan is None:
            status.last_scan = scan
        if scan.status == "succeeded" and status.last_success is None:
            status.last_success = scan
    if status.last_success is None:
        row = await pool.fetchrow(
            f"SELECT {_SCAN_COLUMNS} FROM source_catalog_scans "
            "WHERE source_id = $1 AND status = 'succeeded' "
            "ORDER BY finished_at DESC LIMIT 1",
            source_id,
        )
        if row is not None:
            status.last_success = ScanSummary.from_row(row)
    count_rows = await pool.fetch(
        "SELECT node_type, COUNT(*) AS n FROM source_catalog "
        "WHERE source_id = $1 AND removed_at IS NULL GROUP BY node_type",
        source_id,
    )
    status.counts = {str(r["node_type"]): int(r["n"]) for r in count_rows}
    status.unacknowledged_changes = int(
        await pool.fetchval(
            "SELECT COUNT(*) FROM source_catalog_changes "
            "WHERE source_id = $1 AND acknowledged_at IS NULL",
            source_id,
        )
        or 0
    )
    root = await pool.fetchval(
        "SELECT attributes FROM source_catalog "
        "WHERE source_id = $1 AND node_type = 'source' AND removed_at IS NULL",
        source_id,
    )
    status.source_attributes = _json(root)
    return status


async def scan_history(pool: Any, source_id: str) -> list[ScanSummary]:
    rows = await pool.fetch(
        f"SELECT {_SCAN_COLUMNS} FROM source_catalog_scans WHERE source_id = $1 "
        "ORDER BY requested_at DESC, id DESC LIMIT $2",
        source_id,
        HISTORY_LIMIT,
    )
    return [ScanSummary.from_row(row) for row in rows]


_NODE_SELECT = """
SELECT n.id, n.source_id, n.node_type, n.path, n.name, n.resource_key, n.data_type,
       n.heuristic_class, n.attributes, n.removed_at, n.last_seen_at,
       a.classification, a.classification_source,
       (SELECT COUNT(*) FROM source_catalog c
         WHERE c.source_id = n.source_id AND c.parent_path = n.path
           AND c.removed_at IS NULL) AS child_count
FROM source_catalog n
LEFT JOIN source_catalog_annotations a
       ON a.source_id = n.source_id AND a.path = n.path
"""


def _node_from_row(row: Any) -> CatalogNodeView:
    return CatalogNodeView(
        id=int(row["id"]),
        source_id=str(row["source_id"]),
        node_type=str(row["node_type"]),
        path=list(row["path"]),
        name=str(row["name"]),
        resource_key=str(row["resource_key"]),
        data_type=row["data_type"],
        heuristic_class=row["heuristic_class"],
        attributes=_json(row["attributes"]),
        removed=row["removed_at"] is not None,
        last_seen_at=row["last_seen_at"],
        classification=row["classification"],
        classification_source=row["classification_source"],
        child_count=int(row["child_count"] or 0),
    )


async def children(pool: Any, source_id: str, parent_path: list[str]) -> list[CatalogNodeView]:
    """The live children of a node; the source's top level for an empty path."""
    if parent_path:
        where = "n.source_id = $1 AND n.parent_path = $2::text[]"
        args: tuple[Any, ...] = (source_id, parent_path)
    else:
        # The root 'source' node is metadata, not something to browse into:
        # the top level is whatever hangs directly beneath it.
        where = "n.source_id = $1 AND n.depth = 1"
        args = (source_id,)
    rows = await pool.fetch(
        f"{_NODE_SELECT} WHERE {where} AND n.removed_at IS NULL "
        f"ORDER BY n.ordinal NULLS LAST, n.name LIMIT {CHILD_LIMIT}",
        *args,
    )
    return [_node_from_row(row) for row in rows]


async def search(
    pool: Any,
    *,
    query: str = "",
    source_id: str = "",
    node_type: str = "",
    classification: str = "",
) -> list[CatalogNodeView]:
    """Cross-source search over live nodes, by name or resource key."""
    clauses = ["n.removed_at IS NULL", "n.node_type <> 'source'"]
    args: list[Any] = []
    if query:
        args.append(f"%{query.lower()}%")
        clauses.append(
            f"(lower(n.name) LIKE ${len(args)} OR lower(n.resource_key) LIKE ${len(args)})"
        )
    if source_id:
        args.append(source_id)
        clauses.append(f"n.source_id = ${len(args)}")
    if node_type == "table":
        args.append(sorted(TABLE_LIKE_NODE_TYPES))
        clauses.append(f"n.node_type = ANY(${len(args)}::text[])")
    elif node_type:
        args.append(node_type)
        clauses.append(f"n.node_type = ${len(args)}")
    if classification == "pii_any":
        # The same name hints `looks_like_pii` applies, as one regex.
        args.append("(" + "|".join(PII_NAME_HINTS) + ")")
        clauses.append(
            "(a.classification IN ('pii', 'sensitive') "
            "OR (a.classification IS NULL AND n.node_type = 'column' "
            f"AND lower(n.name) ~ ${len(args)}))"
        )
    elif classification:
        args.append(classification)
        clauses.append(f"a.classification = ${len(args)}")
    rows = await pool.fetch(
        f"{_NODE_SELECT} WHERE {' AND '.join(clauses)} "
        f"ORDER BY n.source_id, n.path LIMIT {SEARCH_LIMIT}",
        *args,
    )
    return [_node_from_row(row) for row in rows]


@dataclass(frozen=True, slots=True)
class ChangeView:
    id: int
    scan_id: int
    node_type: str
    path: list[str]
    change: str
    before: dict[str, Any]
    after: dict[str, Any]
    created_at: datetime | None
    acknowledged_at: datetime | None
    acknowledged_by: str | None
    exposure: dict[str, Any] = field(default_factory=dict)


async def changes(
    pool: Any, source_id: str, *, include_acknowledged: bool = False
) -> list[ChangeView]:
    rows = await pool.fetch(
        "SELECT id, scan_id, node_type, path, change, before, after, created_at, "
        "acknowledged_at, acknowledged_by, exposure FROM source_catalog_changes "
        "WHERE source_id = $1 AND ($2 OR acknowledged_at IS NULL) "
        f"ORDER BY created_at DESC, id DESC LIMIT {CHANGE_LIMIT}",
        source_id,
        include_acknowledged,
    )
    return [
        ChangeView(
            id=int(r["id"]),
            scan_id=int(r["scan_id"]),
            node_type=str(r["node_type"]),
            path=list(r["path"]),
            change=str(r["change"]),
            before=_json(r["before"]),
            after=_json(r["after"]),
            created_at=r["created_at"],
            acknowledged_at=r["acknowledged_at"],
            acknowledged_by=r["acknowledged_by"],
            exposure=_json(r["exposure"]),
        )
        for r in rows
    ]


@dataclass(frozen=True, slots=True)
class CatalogOverview:
    """Across every source: the numbers the discovery page reports."""

    sources_scanned: int
    succeeded: int
    failed: int
    pending: int
    running: int
    tables: int
    columns: int
    last_finished_at: datetime | None
    failures: list[tuple[str, str]]


async def overview(pool: Any) -> CatalogOverview:
    latest = await pool.fetch("""
        SELECT DISTINCT ON (source_id) source_id, status, error_code, finished_at
        FROM source_catalog_scans
        WHERE status IN ('succeeded', 'failed')
        ORDER BY source_id, finished_at DESC NULLS LAST, id DESC
        """)
    queue = await pool.fetchrow(
        "SELECT COUNT(*) FILTER (WHERE status = 'pending') AS pending, "
        "COUNT(*) FILTER (WHERE status = 'running') AS running FROM source_catalog_scans"
    )
    sizes = await pool.fetchrow(
        "SELECT COUNT(*) FILTER (WHERE node_type = ANY($1::text[])) AS tables, "
        "COUNT(*) FILTER (WHERE node_type = 'column') AS columns "
        "FROM source_catalog WHERE removed_at IS NULL",
        sorted(TABLE_LIKE_NODE_TYPES),
    )
    finished = [r["finished_at"] for r in latest if r["finished_at"] is not None]
    return CatalogOverview(
        sources_scanned=len(latest),
        succeeded=sum(1 for r in latest if r["status"] == "succeeded"),
        failed=sum(1 for r in latest if r["status"] == "failed"),
        pending=int(queue["pending"] or 0),
        running=int(queue["running"] or 0),
        tables=int(sizes["tables"] or 0),
        columns=int(sizes["columns"] or 0),
        last_finished_at=max(finished) if finished else None,
        failures=[
            (str(r["source_id"]), str(r["error_code"] or "failed"))
            for r in latest
            if r["status"] == "failed"
        ],
    )
