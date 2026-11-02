from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from interlock.connections.connectors import get_adapter, get_connector
from interlock.core.normalizer import dialect_for, normalize_sql

CONFIG = dict(
    host="example.datawarehouse.fabric.microsoft.com",
    database="Demo",
    tenant_id="tenant-id",
    client_id="client-id",
    endpoint_type="warehouse",
    auth_mode="spn",
    client_secret_ref="env://FABRIC_SECRET",
)


def adapter():
    services = SimpleNamespace(
        auth=SimpleNamespace(acquire=AsyncMock(return_value=object())),
        transport=SimpleNamespace(
            execute=AsyncMock(
                return_value={
                    "rows": [{"one": 1}],
                    "columns": ["one"],
                    "row_count": 1,
                    "permission_request": None,
                }
            )
        ),
    )
    return get_adapter("fabric_sql", fabric_services=services, source_id="fabric"), services


@pytest.mark.asyncio
async def test_probe_uses_saved_source_identity_and_select_one():
    target, services = adapter()
    status = await target.probe(CONFIG)
    assert status.healthy
    assert services.auth.acquire.call_args.args[0] == "fabric"
    assert services.transport.execute.call_args.args[2:4] == ("SELECT 1", ())
    assert services.transport.execute.call_args.kwargs["write"] is False


@pytest.mark.asyncio
async def test_read_preserves_transport_envelope_and_measures_permissions_before_commit():
    target, services = adapter()
    result = await target.execute_read(
        dict(
            connection_config=CONFIG,
            query="SELECT TOP 1 [Name] FROM [dbo].[Users]",
            source_id="fabric",
        )
    )
    assert result == services.transport.execute.return_value
    permission = services.transport.execute.call_args.kwargs["permission_request"]
    assert permission["tables"] == ["dbo.Users"]
    assert permission["columns"] == ["Name"]
    assert permission["action"] == "db.table.select"


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT * INTO dbo.copy FROM dbo.Users",
        "SELECT 1; SELECT 2",
        "EXEC sp_executesql N'SELECT 1'",
        "MERGE dbo.t USING dbo.s ON 1=1 WHEN MATCHED THEN DELETE;",
        "CREATE TABLE dbo.t (id int)",
        "DROP TABLE dbo.t",
        "TRUNCATE TABLE dbo.t",
        "SELECT * FROM OPENQUERY(server, 'SELECT 1')",
        "SELECT * FROM dbo.f(1)",
        "SELECT * FROM server.Demo.dbo.Users",
        "SELECT * FROM other.dbo.Users",
        "SELECT * FROM Demo..Users",
        "SELECT * FROM [dbo].[a.b]",
    ],
)
@pytest.mark.asyncio
async def test_unsupported_scope_never_reaches_auth_or_driver(sql):
    target, services = adapter()
    with pytest.raises(ValueError):
        await target.execute_read(dict(connection_config=CONFIG, query=sql))
    services.auth.acquire.assert_not_called()
    services.transport.execute.assert_not_called()


@pytest.mark.parametrize(
    "sql,action",
    [
        ("INSERT INTO dbo.Users (Name) VALUES (?)", "insert"),
        ("UPDATE dbo.Users SET Name=? WHERE id=1", "update"),
        ("DELETE FROM dbo.Users WHERE id=1", "delete_rows"),
    ],
)
@pytest.mark.asyncio
async def test_dml_recognized_and_lakehouse_denied_before_auth(sql, action):
    target, services = adapter()
    request = target.build_permission_request(
        source_id="fabric", identity_id=2, operation="write", metadata={"query": sql}
    )
    assert request.action == "db.table." + action
    with pytest.raises(ValueError, match="Lakehouse"):
        await target.execute_write(
            dict(connection_config={**CONFIG, "endpoint_type": "lakehouse_sql"}, query=sql)
        )
    services.auth.acquire.assert_not_called()
    await target.execute_write(dict(connection_config=CONFIG, query=sql, parameters=["x"]))
    assert services.transport.execute.call_args.kwargs["write"] is True
    assert services.transport.execute.call_args.args[3] == ("x",)


def test_tsql_normalization_preserves_case_distinct_fingerprints_and_cte_scope():
    assert dialect_for("fabric_sql") == "tsql"
    a = normalize_sql(
        "WITH C AS (SELECT TOP 2 [Name] FROM [dbo].[Users]) SELECT * FROM C JOIN dbo.Teams t ON 1=1",
        "fabric",
        dialect="tsql",
    )
    assert a.tables == ["dbo.Teams", "dbo.Users"]
    b = normalize_sql("SELECT Name FROM dbo.Users", "fabric", dialect="tsql")
    c = normalize_sql("SELECT name FROM dbo.users", "fabric", dialect="tsql")
    assert b.fingerprint != c.fingerprint


@pytest.mark.asyncio
async def test_unsaved_and_unconfigured_sources_cannot_borrow_runtime_from_metadata():
    target = get_adapter("fabric_sql", {"fabric_services": object(), "source_id": "other"})
    status = await target.probe(CONFIG)
    assert not status.healthy and "Save" in status.error
    target = get_adapter("fabric_sql", source_id="saved")
    status = await target.probe(CONFIG)
    assert not status.healthy and "unavailable" in status.error


def test_registry_exposes_beta_sql_only_and_preserves_generic_mssql():
    definition = get_connector("fabric_sql")
    assert definition.key == "fabric_sql" and definition.status == "beta"
    assert definition.capabilities.supports_query
    assert not definition.capabilities.supports_ingestion
    assert get_connector("mssql").status == "planned"


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT NEXT VALUE FOR dbo.sequence",
        "WITH X AS (DELETE FROM dbo.Users OUTPUT deleted.*) SELECT * FROM X",
    ],
)
@pytest.mark.asyncio
async def test_read_cannot_hide_a_write_in_expression_or_cte(sql):
    target, services = adapter()
    with pytest.raises(ValueError):
        await target.execute_read(dict(connection_config=CONFIG, query=sql))
    services.auth.acquire.assert_not_called()


@pytest.mark.asyncio
async def test_same_database_qualification_only_changes_permission_scope():
    target, services = adapter()
    sql = "SELECT Name FROM Demo.dbo.Users"
    await target.execute_read(dict(connection_config=CONFIG, query=sql))
    call = services.transport.execute.call_args
    assert call.args[2] == sql
    assert call.kwargs["permission_request"]["tables"] == ["dbo.Users"]


@pytest.mark.asyncio
async def test_invalid_config_never_exposes_rejected_secret_in_probe_or_execution():
    target, services = adapter()
    config = {**CONFIG, "password": "DO_NOT_EXPOSE_LITERAL_PASSWORD"}
    status = await target.probe(config)
    assert not status.healthy
    assert "DO_NOT_EXPOSE" not in status.error
    with pytest.raises(ValueError) as caught:
        await target.execute_read(dict(connection_config=config, query="SELECT 1"))
    assert "DO_NOT_EXPOSE" not in str(caught.value)
    assert caught.value.__suppress_context__
    services.auth.acquire.assert_not_called()


@pytest.mark.asyncio
async def test_schema_qualified_scalar_function_cannot_hide_table_reads():
    target, services = adapter()
    with pytest.raises(ValueError):
        await target.execute_read(dict(connection_config=CONFIG, query="SELECT dbo.read_secret()"))
    services.auth.acquire.assert_not_called()


def test_read_set_expression_stays_a_select_permission():
    target, _ = adapter()
    sql = "SELECT Name FROM dbo.Users UNION SELECT Name FROM dbo.Teams"
    request = target.build_permission_request(
        source_id="fabric", identity_id=2, operation="read", metadata={"query": sql}
    )
    assert request.action == "db.table.select"
    assert normalize_sql(sql, "fabric", dialect="tsql").operation == "SELECT"


@pytest.mark.parametrize(
    "sql",
    [
        "UPDATE dbo.Users SET Name='new' OUTPUT inserted.Secret WHERE id=1",
        "DELETE FROM dbo.Users OUTPUT deleted.Secret WHERE id=1",
        "INSERT INTO dbo.Users (Name) OUTPUT inserted.Secret VALUES ('new')",
    ],
)
@pytest.mark.asyncio
async def test_write_cannot_return_sensitive_output_columns_outside_write_scope(sql):
    target, services = adapter()
    services.transport.execute.return_value = {"rows": [{"Secret": "private"}]}
    with pytest.raises(ValueError):
        await target.execute_write(dict(connection_config=CONFIG, query=sql))
    services.auth.acquire.assert_not_called()
    services.transport.execute.assert_not_called()
