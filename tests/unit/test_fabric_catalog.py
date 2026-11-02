"""Metadata uses bounded system views, native names and honest completeness."""

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from interlock.catalog.collectors import CollectContext, collector_for, is_enforced
from interlock.catalog.model import ScanLimits
from interlock.connections.fabric.credentials import FabricCurrentSource
from tests.unit.test_fabric_cache_scope import setup


class MetadataTransport:
    def __init__(
        self,
        *,
        collation="Latin1_General_100_BIN2_UTF8",
        catalog_collation="Latin1_General_100_BIN2_UTF8",
        ascii_case_equivalent=0,
        empty=False,
    ):
        self.calls = []
        self.collation = collation
        self.catalog_collation = catalog_collation
        self.ascii_case_equivalent = ascii_case_equivalent
        self.schemas = (
            []
            if empty
            else [
                {"schema_id": 1, "schema_name": "Sales"},
                {"schema_id": 2, "schema_name": "sales"},
            ]
        )
        self.tables = {
            1: [{"object_id": 10, "relation_name": "People", "kind": "U"}],
            2: [{"object_id": 20, "relation_name": "people", "kind": "V"}],
        }
        self.columns = {
            10: [
                {
                    "column_id": 1,
                    "column_name": "Name",
                    "data_type": "nvarchar",
                    "is_nullable": True,
                },
                {
                    "column_id": 2,
                    "column_name": "name",
                    "data_type": "nvarchar",
                    "is_nullable": False,
                },
            ],
            20: [
                {
                    "column_id": 1,
                    "column_name": "Email",
                    "data_type": "varchar",
                    "is_nullable": True,
                }
            ],
        }

    async def execute(self, config, token, sql, parameters, *, write, **kwargs):
        assert not write and sql.lstrip().upper().startswith("SELECT")
        self.calls.append((sql, parameters))
        if "DB_NAME()" in sql:
            return {
                "rows": [
                    {
                        "database": config.database,
                        "default_schema": "Sales",
                        "collation": self.collation,
                        "catalog_collation": self.catalog_collation,
                        "ascii_case_equivalent": self.ascii_case_equivalent,
                    }
                ]
            }
        assert "TOP (?)" in sql and parameters[0] <= config.max_rows
        take, *args = parameters
        if "FROM sys.schemas" in sql:
            rows, key, after = self.schemas, "schema_id", args[0]
        elif "FROM sys.objects" in sql:
            rows, key, after = self.tables[args[0]], "object_id", args[1]
        elif "FROM sys.columns" in sql:
            rows, key, after = self.columns[args[0]], "column_id", args[1]
        else:
            raise AssertionError("Unexpected non-metadata SQL")
        return {"rows": [r for r in rows if r[key] > after][:take]}


def context(**kwargs):
    store, auth, _, _, source, request, _ = setup()
    store.current_source = AsyncMock(return_value=FabricCurrentSource(store.config, store.context))
    services = request.app.state.fabric_services
    services.transport = MetadataTransport(**kwargs)
    return (
        CollectContext(
            "saved", "FABRIC_SQL", source.connection_config, ScanLimits(), fabric_services=services
        ),
        services,
    )


@pytest.mark.asyncio
async def test_collector_preserves_case_distinct_objects_and_actual_naming_facts():
    ctx, services = context()
    collector = collector_for(ctx.connector_key)
    assert collector is not None and is_enforced(ctx.connector_key)
    snapshot = await collector(ctx)
    assert snapshot.complete_subtrees == [()]
    assert [n.resource_key for n in snapshot.nodes if n.node_type == "column"] == [
        "Sales.People.Name",
        "Sales.People.name",
        "sales.people.Email",
    ]
    assert snapshot.source_attributes["default_schema"] == "Sales"
    assert snapshot.source_attributes["identifier_case_sensitive"] is True
    assert snapshot.source_attributes["upstream_identity"]["generation"] == 1
    assert services.auth.calls == 1
    assert not any("private-access-token" in str(n) for n in snapshot.nodes)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "limits,incomplete",
    [
        (ScanLimits(max_nodes=3), ("Sales", "People")),
        (ScanLimits(max_columns_per_table=1), ("Sales", "People")),
        (ScanLimits(max_tables=1), ("sales",)),
        (ScanLimits(max_schemas=1), ("sales",)),
    ],
)
async def test_truncated_scans_do_not_claim_unvisited_subtrees(limits, incomplete):
    from dataclasses import replace

    ctx, _ = context()
    snapshot = await collector_for("fabric_sql")(replace(ctx, limits=limits))
    assert snapshot.truncated
    assert len(snapshot.nodes) <= limits.max_nodes
    assert not snapshot.is_complete_under(incomplete)


@pytest.mark.asyncio
async def test_empty_metadata_is_complete_but_permission_failure_is_not_empty_success():
    ctx, services = context(empty=True)
    snapshot = await collector_for("fabric_sql")(ctx)
    assert snapshot.nodes == [] and snapshot.complete_subtrees == [()]
    services.transport.execute = AsyncMock(side_effect=PermissionError("denied"))
    with pytest.raises(PermissionError):
        await collector_for("fabric_sql")(ctx)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "catalog_collation,ascii_case_equivalent,expected",
    [
        ("Latin1_General_100_CI_AS_SC_UTF8", 1, False),
        ("Latin1_General_100_CI_AS_KS_WS_SC_UTF8", 1, False),
        ("Latin1_General_100_CI_AS_KS_WS_SC_UTF8", 0, None),
        ("Latin1_General_100_CS_AS", 0, True),
        ("Turkish_CI_AS", 1, None),
        ("unknown", 0, None),
        (None, 0, None),
        ("Latin1_General_100_CI_AS_SC_UTF8", None, None),
        ("Latin1_General_100_BIN2_UTF8", 1, None),
    ],
)
async def test_only_verified_identifier_collations_enable_scope(
    catalog_collation, ascii_case_equivalent, expected
):
    ctx, _ = context(
        catalog_collation=catalog_collation, ascii_case_equivalent=ascii_case_equivalent
    )
    snapshot = await collector_for("fabric_sql")(ctx)
    assert snapshot.source_attributes["identifier_case_sensitive"] is expected
    if expected is None:
        from interlock.core.sql_governance import naming_for, resolve_table

        naming = naming_for(
            "fabric_sql",
            ctx.connection_config,
            snapshot.source_attributes,
            frozenset({("Sales", "People")}),
        )
        assert resolve_table("Sales.People", naming).refusal


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "collation,catalog_collation,ascii_case_equivalent,expected",
    [
        ("Latin1_General_100_BIN2_UTF8", "Latin1_General_100_CI_AS", 1, False),
        ("Latin1_General_100_CI_AS", "Latin1_General_100_BIN2_UTF8", 0, True),
    ],
)
async def test_identifier_scope_uses_catalog_collation_independently_of_data_collation(
    collation, catalog_collation, ascii_case_equivalent, expected
):
    ctx, services = context(
        collation=collation,
        catalog_collation=catalog_collation,
        ascii_case_equivalent=ascii_case_equivalent,
    )
    snapshot = await collector_for("fabric_sql")(ctx)
    assert snapshot.source_attributes["collation"] == collation
    assert snapshot.source_attributes["catalog_collation"] == catalog_collation
    assert snapshot.source_attributes["identifier_case_sensitive"] is expected
    facts_sql = services.transport.calls[0][0]
    assert "sys.all_columns" in facts_sql
    assert "OBJECT_ID(N'sys.schemas')" in facts_sql
    assert "DATABASE_DEFAULT" not in facts_sql
    assert "name = N'sys'" in facts_sql and "name = N'SYS'" in facts_sql


@pytest.mark.asyncio
async def test_small_transport_pages_scan_more_than_agent_row_limit():
    from dataclasses import replace

    ctx, services = context()
    config = services.auth.store.config.model_copy(update={"max_rows": 1})
    services.auth.store.config = config
    snapshot = await collector_for("fabric_sql")(
        replace(ctx, connection_config=config.model_dump())
    )
    assert not snapshot.truncated
    assert len(snapshot.nodes) == 7
    assert sum("FROM sys.columns" in sql for sql, _ in services.transport.calls) >= 5


@pytest.mark.asyncio
async def test_native_case_catalog_validation_and_provider_only_resolution():
    from datetime import UTC, datetime

    from interlock.catalog.read import connector_key_of
    from interlock.catalog.validation import lint_policy, lint_statements, load_catalog_view

    pool = SimpleNamespace(
        fetchrow=AsyncMock(
            side_effect=[
                {
                    "source_type": "database",
                    "metadata": {"provider": "FABRIC_SQL"},
                    "connection_config": {},
                },
                {
                    "attributes": {
                        "database": "Demo",
                        "default_schema": "dbo",
                        "identifier_case_sensitive": True,
                    },
                    "last_seen_at": datetime.now(UTC),
                },
            ]
        ),
        fetch=AsyncMock(
            return_value=[
                {"table_key": "dbo.Users", "column_name": "Name"},
                {"table_key": "dbo.users", "column_name": "name"},
            ]
        ),
    )
    view = await load_catalog_view(pool, "saved")
    assert view.tables == {"dbo.Users": ["Name"], "dbo.users": ["name"]}
    assert view.collectable
    assert not lint_policy(
        view, tables=["dbo.Users"], columns=["Name"], redact_columns=[], effect="deny"
    )
    warnings = lint_statements(
        view,
        [
            {
                "action": "db.table.select",
                "resource_type": "db.column",
                "resource_pattern": "dbo.Users.name",
                "effect": "deny",
            }
        ],
    )
    assert "matches_nothing" in {w.code for w in warnings}
    assert connector_key_of({"source_type": "database", "metadata": {}}) == "database"


@pytest.mark.asyncio
async def test_introspection_returns_only_public_metadata_and_checks_saved_config():
    from interlock.connections.connectors import get_adapter

    ctx, services = context()
    adapter = get_adapter("fabric_sql", fabric_services=services, source_id="saved")
    result = await adapter.introspect(ctx.connection_config)
    assert result["nodes"][0]["path"] == ("Sales",)
    assert "publication_context" not in result
    assert "private-access-token" not in str(result)
    with pytest.raises(ValueError):
        await adapter.introspect(ctx.connection_config | {"database": "other"})
