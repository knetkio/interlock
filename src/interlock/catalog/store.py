"""Recording a scan's snapshot, with drift against what was there before.

Everything happens in one transaction on the control database, so readers see
either the previous catalog or the new one, never half of each.

Three rules keep the recorded drift honest:

- A source's first successful scan is a **baseline**: nodes are recorded and
  counted, but no change rows are written - otherwise the first scan of a large
  warehouse would report a hundred thousand "added" objects.
- A node is marked removed only if it falls under a subtree the collector
  reports as completely enumerated. A scan that hit a cap never invents
  removals for what it simply did not reach.
- Change rows are capped per scan; hitting the cap sets `changes_truncated`
  rather than silently dropping the rest.

JSON goes through TEXT staging columns cast with `::jsonb` in SQL. The control
pools register a JSONB codec that serialises Python objects, so passing a
pre-serialised string would store a JSON string scalar instead of an object -
the defect migration 015 had to repair. Casting TEXT is correct with or without
the codec.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from interlock.catalog.model import CatalogNode, CatalogSnapshot

_STAGE_COLUMNS = (
    "node_type",
    "path",
    "parent_path",
    "depth",
    "name",
    "resource_key",
    "ordinal",
    "data_type",
    "heuristic_class",
    "attributes",
    "attributes_hash",
)


@dataclass(frozen=True, slots=True)
class ApplyResult:
    nodes_seen: int
    added: int
    removed: int
    changed: int
    baseline: bool
    changes_truncated: bool


def _root_node(source_id: str, snapshot: CatalogSnapshot) -> CatalogNode:
    """The source itself, carrying facts later stages resolve names with -
    default schema, search path, the login the scan ran as."""
    return CatalogNode(
        node_type="source",
        path=(),
        name=source_id,
        resource_key="",
        attributes=dict(snapshot.source_attributes),
    )


def _snapshot_view(node: CatalogNode) -> dict[str, Any]:
    return {
        "node_type": node.node_type,
        "data_type": node.data_type,
        "ordinal": node.ordinal,
        "attributes": node.attributes,
    }


def _existing_view(row: Any) -> dict[str, Any]:
    attributes = row["attributes"]
    if isinstance(attributes, str):
        attributes = json.loads(attributes or "{}")
    return {
        "node_type": row["node_type"],
        "data_type": row["data_type"],
        "ordinal": row["ordinal"],
        "attributes": attributes,
    }


async def apply_snapshot(
    conn: Any,
    *,
    source_id: str,
    scan_id: int,
    snapshot: CatalogSnapshot,
    max_change_rows: int,
) -> ApplyResult:
    """Record `snapshot` as the current structure of `source_id`."""
    nodes = [_root_node(source_id, snapshot), *snapshot.nodes]
    by_path: dict[tuple[str, ...], CatalogNode] = {}
    for node in nodes:
        # A collector should never emit a path twice; if one does, the last
        # wins rather than failing the whole scan on a unique violation.
        by_path[node.path] = node

    async with conn.transaction():
        baseline = not await conn.fetchval(
            """
            SELECT EXISTS (
                SELECT 1 FROM source_catalog_scans
                WHERE source_id = $1 AND status = 'succeeded' AND id <> $2
            )
            """,
            source_id,
            scan_id,
        )
        existing_rows = await conn.fetch(
            """
            SELECT id, path, node_type, data_type, ordinal, attributes,
                   attributes_hash, removed_at
            FROM source_catalog WHERE source_id = $1
            """,
            source_id,
        )
        existing = {tuple(row["path"]): row for row in existing_rows}

        added: list[CatalogNode] = []
        changed: list[tuple[Any, CatalogNode]] = []
        for path, node in by_path.items():
            row = existing.get(path)
            if row is None or row["removed_at"] is not None:
                added.append(node)
            elif row["attributes_hash"] != node.attributes_hash:
                changed.append((row, node))

        prior_root = existing.get(())
        prior_attributes = (
            _existing_view(prior_root)["attributes"] if prior_root is not None else {}
        )
        binding = snapshot.source_attributes.get("upstream_identity")
        identity_changed = binding is not None and binding != prior_attributes.get(
            "upstream_identity"
        )
        # Truncation retains unseen nodes only within the same upstream epoch.
        # Tombstones retain history/annotations when the saved identity changes.
        removed = [
            row
            for path, row in existing.items()
            if row["removed_at"] is None
            and path not in by_path
            and path != ()
            and (identity_changed or snapshot.is_complete_under(path))
        ]

        await conn.execute("""
            CREATE TEMP TABLE _catalog_stage (
                node_type TEXT, path TEXT[], parent_path TEXT[], depth SMALLINT,
                name TEXT, resource_key TEXT, ordinal INT, data_type TEXT,
                heuristic_class TEXT, attributes TEXT, attributes_hash TEXT
            ) ON COMMIT DROP
            """)
        await conn.copy_records_to_table(
            "_catalog_stage",
            records=[
                (
                    node.node_type,
                    list(node.path),
                    list(node.parent_path),
                    node.depth,
                    node.name,
                    node.resource_key,
                    node.ordinal,
                    node.data_type,
                    node.heuristic_class,
                    json.dumps(node.attributes, sort_keys=True, default=str),
                    node.attributes_hash,
                )
                for node in by_path.values()
            ],
            columns=_STAGE_COLUMNS,
        )
        await conn.execute(
            """
            INSERT INTO source_catalog (
                source_id, node_type, path, parent_path, depth, name, resource_key,
                ordinal, data_type, heuristic_class, attributes, attributes_hash,
                first_seen_scan_id, last_seen_scan_id
            )
            SELECT $1, node_type, path, parent_path, depth, name, resource_key,
                   ordinal, data_type, heuristic_class, attributes::jsonb,
                   attributes_hash, $2, $2
            FROM _catalog_stage
            ON CONFLICT (source_id, path) DO UPDATE SET
                node_type = EXCLUDED.node_type,
                parent_path = EXCLUDED.parent_path,
                depth = EXCLUDED.depth,
                name = EXCLUDED.name,
                resource_key = EXCLUDED.resource_key,
                ordinal = EXCLUDED.ordinal,
                data_type = EXCLUDED.data_type,
                heuristic_class = EXCLUDED.heuristic_class,
                attributes = EXCLUDED.attributes,
                changed_at = CASE
                    WHEN source_catalog.attributes_hash <> EXCLUDED.attributes_hash
                         AND source_catalog.removed_at IS NULL
                    THEN NOW() ELSE source_catalog.changed_at END,
                attributes_hash = EXCLUDED.attributes_hash,
                first_seen_scan_id = CASE
                    WHEN source_catalog.removed_at IS NOT NULL
                    THEN EXCLUDED.first_seen_scan_id
                    ELSE source_catalog.first_seen_scan_id END,
                first_seen_at = CASE
                    WHEN source_catalog.removed_at IS NOT NULL
                    THEN NOW() ELSE source_catalog.first_seen_at END,
                last_seen_scan_id = EXCLUDED.last_seen_scan_id,
                last_seen_at = NOW(),
                removed_at = NULL
            """,
            source_id,
            scan_id,
        )
        if removed:
            await conn.execute(
                "UPDATE source_catalog SET removed_at = NOW() WHERE id = ANY($1::bigint[])",
                [row["id"] for row in removed],
            )

        change_rows: list[tuple[Any, ...]] = []
        changes_truncated = False
        if not baseline:
            candidates: list[tuple[str, str, list[str], Any, Any]] = []
            for node in added:
                candidates.append(
                    ("added", node.node_type, list(node.path), None, _snapshot_view(node))
                )
            for row, node in changed:
                candidates.append(
                    (
                        "changed",
                        node.node_type,
                        list(node.path),
                        _existing_view(row),
                        _snapshot_view(node),
                    )
                )
            for row in removed:
                candidates.append(
                    ("removed", row["node_type"], list(row["path"]), _existing_view(row), None)
                )
            if len(candidates) > max_change_rows:
                changes_truncated = True
                candidates = candidates[:max_change_rows]
            change_rows = [
                (
                    change,
                    node_type,
                    path,
                    None if before is None else json.dumps(before, sort_keys=True, default=str),
                    None if after is None else json.dumps(after, sort_keys=True, default=str),
                )
                for change, node_type, path, before, after in candidates
            ]

        if change_rows:
            await conn.execute("""
                CREATE TEMP TABLE _catalog_change_stage (
                    change TEXT, node_type TEXT, path TEXT[], before TEXT, after TEXT
                ) ON COMMIT DROP
                """)
            await conn.copy_records_to_table(
                "_catalog_change_stage",
                records=change_rows,
                columns=("change", "node_type", "path", "before", "after"),
            )
            await conn.execute(
                """
                INSERT INTO source_catalog_changes
                    (scan_id, source_id, node_type, path, change, before, after)
                SELECT $1, $2, node_type, path, change, before::jsonb, after::jsonb
                FROM _catalog_change_stage
                """,
                scan_id,
                source_id,
            )

    return ApplyResult(
        nodes_seen=len(by_path),
        added=len(added),
        removed=len(removed),
        changed=len(changed),
        baseline=baseline,
        changes_truncated=changes_truncated,
    )
