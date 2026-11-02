"""Bounded, metadata-only Fabric inventory under one saved upstream identity."""

from __future__ import annotations

from collections.abc import AsyncIterator
from dataclasses import asdict
from typing import TYPE_CHECKING, Any

from interlock.catalog.collectors import CollectContext
from interlock.catalog.errors import CatalogScanError
from interlock.catalog.model import CatalogNode, CatalogSnapshot, ScanLimits
from interlock.connections.fabric.config import FabricConfig
from interlock.connections.fabric.credentials import FabricCurrentSource

if TYPE_CHECKING:
    from interlock.connections.fabric.runtime import FabricServices

# The CI subset is deliberately explicit: these Latin1 collations have ASCII
# case equivalence. A comparison on a catalog column confirms its actual mode;
# database/data collation is independent and never supplies identifier semantics.
_CI_COLLATIONS = frozenset(
    {
        "Latin1_General_100_CI_AS",
        "Latin1_General_100_CI_AS_SC",
        "Latin1_General_100_CI_AS_SC_UTF8",
        "SQL_Latin1_General_CP1_CI_AS",
    }
)
_FACTS = """
SELECT DB_NAME() AS [database], SCHEMA_NAME() AS default_schema,
       CAST(DATABASEPROPERTYEX(DB_NAME(), 'Collation') AS nvarchar(128)) AS collation,
       (SELECT collation_name FROM sys.all_columns
        WHERE object_id = OBJECT_ID(N'sys.schemas') AND name = N'name') AS catalog_collation,
       CASE WHEN EXISTS (SELECT 1 FROM sys.schemas WHERE name = N'sys' AND name = N'SYS')
            THEN 1
            WHEN EXISTS (SELECT 1 FROM sys.schemas WHERE name = N'sys')
            THEN 0 ELSE NULL END AS ascii_case_equivalent
"""
_SCHEMAS = """
SELECT TOP (?) schema_id, name AS schema_name FROM sys.schemas
WHERE schema_id > ? AND name NOT IN ('sys', 'INFORMATION_SCHEMA') ORDER BY schema_id
"""
_TABLES = """
SELECT TOP (?) object_id, name AS relation_name, type AS kind FROM sys.objects
WHERE schema_id = ? AND object_id > ? AND type IN ('U', 'V') AND is_ms_shipped = 0
ORDER BY object_id
"""
_COLUMNS = """
SELECT TOP (?) c.column_id, c.name AS column_name, t.name AS data_type, c.is_nullable
FROM sys.columns c JOIN sys.types t ON t.user_type_id = c.user_type_id
WHERE c.object_id = ? AND c.column_id > ? ORDER BY c.column_id
"""


def _case_mode(facts: dict[str, Any]) -> bool | None:
    collation = str(facts.get("catalog_collation") or "")
    if ("_BIN2" in collation or "_CS_" in collation) and facts.get("ascii_case_equivalent") == 0:
        return True
    if collation in _CI_COLLATIONS and facts.get("ascii_case_equivalent") == 1:
        return False
    return None


async def metadata_snapshot(
    services: FabricServices,
    source_id: str,
    config: FabricConfig,
    limits: ScanLimits,
) -> CatalogSnapshot:
    """One auth capability; keyset pages never exceed transport or scan bounds.

    Completion belongs to this collector; result byte/row bounds remain owned
    by transport. A failed page aborts publication, never becomes an empty page.
    """
    source = await services.prepare_source(source_id, config)

    async def query(sql: str, params: tuple[Any, ...]) -> list[dict[str, Any]]:
        result = await services.transport.execute(config, source.token, sql, params, write=False)
        return [dict(row) for row in result["rows"]]

    rows = await query(_FACTS, ())
    if (
        len(rows) != 1
        or rows[0].get("database") != config.database
        or not rows[0].get("default_schema")
    ):
        raise CatalogScanError(
            "naming_unavailable", "Fabric returned unresolved database naming facts"
        )
    facts = rows[0]
    snapshot = CatalogSnapshot(
        source_attributes={
            "dialect": "tsql",
            "database": facts["database"],
            "default_schema": facts["default_schema"],
            "collation": facts.get("collation"),
            "catalog_collation": facts.get("catalog_collation"),
            "identifier_case_sensitive": _case_mode(facts),
            "upstream_identity": source.upstream_identity,
        },
        publication_context=FabricCurrentSource(config, source.token.context),
    )

    def truncate(cap: str) -> None:
        snapshot.truncation[cap] = getattr(limits, cap)
        snapshot.truncated = True

    def append(kind: str, path: tuple[str, ...], **kwargs: Any) -> bool:
        if len(snapshot.nodes) >= limits.max_nodes:
            truncate("max_nodes")
            return False
        snapshot.nodes.append(CatalogNode(kind, path, path[-1], ".".join(path), **kwargs))
        return True

    async def pages(
        sql: str, parent: tuple[Any, ...], key: str, cap: int
    ) -> AsyncIterator[dict[str, Any]]:
        after, seen = 0, 0
        while True:
            take = min(config.max_rows, 256, max(cap - seen + 1, 1))
            page = await query(sql, (take, *parent, after))
            for row in page:
                yield row
                seen += 1
                after = int(row[key])
            if len(page) < take or seen > cap:
                break

    schemas = tables = 0
    async for schema in pages(_SCHEMAS, (), "schema_id", limits.max_schemas):
        if schemas >= limits.max_schemas:
            truncate("max_schemas")
            break
        sp = (schema["schema_name"],)
        if not append("schema", sp):
            break
        schemas += 1
        schema_complete = True
        async for table in pages(
            _TABLES, (schema["schema_id"],), "object_id", limits.max_tables - tables
        ):
            if tables >= limits.max_tables:
                truncate("max_tables")
                schema_complete = False
                break
            tp = (*sp, table["relation_name"])
            if not append("view" if table["kind"].strip() == "V" else "table", tp):
                schema_complete = False
                break
            tables += 1
            columns = 0
            table_complete = True
            async for column in pages(
                _COLUMNS, (table["object_id"],), "column_id", limits.max_columns_per_table
            ):
                if columns >= limits.max_columns_per_table:
                    truncate("max_columns_per_table")
                    table_complete = False
                    break
                if not append(
                    "column",
                    (*tp, column["column_name"]),
                    ordinal=column["column_id"],
                    data_type=column["data_type"],
                    attributes={"nullable": bool(column["is_nullable"])},
                ):
                    table_complete = False
                    break
                columns += 1
            if table_complete:
                snapshot.complete_subtrees.append(tp)
            else:
                schema_complete = False
        if schema_complete:
            snapshot.complete_subtrees.append(sp)
        if "max_nodes" in snapshot.truncation:
            break
    if not snapshot.truncated:
        snapshot.complete_subtrees = [()]
    return snapshot


async def collect_fabric(ctx: CollectContext) -> CatalogSnapshot:
    if ctx.fabric_services is None:
        raise RuntimeError("Fabric authentication services are unavailable")
    return await metadata_snapshot(
        ctx.fabric_services,
        ctx.source_id,
        FabricConfig.from_mapping(ctx.connection_config),
        ctx.limits,
    )


def public_snapshot(snapshot: CatalogSnapshot) -> dict[str, Any]:
    """No internal capability/config or credentials in introspection results."""
    return {
        "source_attributes": snapshot.source_attributes,
        "nodes": [asdict(n) for n in snapshot.nodes],
        "truncated": snapshot.truncated,
        "truncation": snapshot.truncation,
        "complete_subtrees": snapshot.complete_subtrees,
        "warnings": snapshot.warnings,
    }
