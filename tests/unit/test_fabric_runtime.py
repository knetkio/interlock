import subprocess
import sys
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest


def test_absent_settings_do_not_load_optional_drivers():
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            """
import sys
from interlock.connections.fabric.runtime import build_fabric_services
from interlock.config import FabricSettings
assert build_fabric_services(object(), FabricSettings()) is None
assert 'msal' not in sys.modules
assert 'pyodbc' not in sys.modules
from interlock.connections.connectors import get_adapter
get_adapter('postgresql')
get_adapter('fabric_sql')
assert 'msal' not in sys.modules
assert 'pyodbc' not in sys.modules
""",
        ],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr


@pytest.mark.asyncio
async def test_service_close_closes_transport_without_owning_control_pool():
    from interlock.connections.fabric.runtime import FabricServices

    transport = SimpleNamespace(close=AsyncMock())
    service = FabricServices(object(), object(), transport)
    await service.close()
    transport.close.assert_awaited_once()


@pytest.mark.asyncio
async def test_registered_health_probe_uses_process_service_and_saved_source():
    from interlock.connections.manager import ConnectionManager
    from tests.unit.test_fabric_adapter import CONFIG

    source = SimpleNamespace(
        source_type=SimpleNamespace(value="database"),
        metadata={"connector_key": "fabric_sql"},
        connection_config=CONFIG,
    )
    services = SimpleNamespace(
        auth=SimpleNamespace(acquire=AsyncMock(return_value=object())),
        transport=SimpleNamespace(execute=AsyncMock(return_value={"rows": [{"one": 1}]})),
    )
    manager = ConnectionManager(
        SimpleNamespace(get=lambda source_id: source), fabric_services=services
    )
    status = await manager.health_check("saved")
    assert status.healthy, status.error
    assert services.auth.acquire.call_args.args[0] == "saved"
    assert services.transport.execute.call_args.args[2] == "SELECT 1"


@pytest.mark.asyncio
async def test_approval_routes_database_source_through_fabric_identity_without_retry():
    from interlock.core.approval_queue import ApprovalQueue
    from tests.unit.test_fabric_adapter import CONFIG

    source = SimpleNamespace(
        source_type=SimpleNamespace(value="database"),
        metadata={"connector_key": "fabric_sql"},
        connection_config=CONFIG,
    )
    services = SimpleNamespace(
        auth=SimpleNamespace(acquire=AsyncMock(return_value=object())),
        transport=SimpleNamespace(execute=AsyncMock(side_effect=RuntimeError("uncertain write"))),
    )
    queue = ApprovalQueue(object(), fabric_services=services)
    row = dict(
        id=1,
        source_id="saved",
        identity_id=3,
        sql_text="UPDATE dbo.Users SET Name=?",
        request_metadata={"parameters": ["name"]},
    )
    with pytest.raises(RuntimeError, match="uncertain"):
        await queue._execute_via_adapter(row, source, "database")
    assert services.auth.acquire.call_args.args[0] == "saved"
    services.transport.execute.assert_awaited_once()
    assert services.transport.execute.call_args.args[3] == ("name",)


def test_missing_operator_key_disables_fabric_without_breaking_other_connectors(monkeypatch):
    from interlock.config import FabricSettings
    from interlock.connections.connectors import get_adapter
    from interlock.connections.fabric.runtime import build_fabric_services

    monkeypatch.delenv("MISSING_FABRIC_TEST_KEY", raising=False)
    settings = FabricSettings(
        active_key_version="v1", key_refs={"v1": "env://MISSING_FABRIC_TEST_KEY"}
    )
    assert build_fabric_services(object(), settings) is None
    assert get_adapter("mysql").definition.key == "mysql"


def test_mcp_routes_saved_fabric_identity_and_refuses_unsupported_sql_before_execution():
    from starlette.testclient import TestClient

    from interlock.gateway.mcp_adapter import MCPAdapter
    from interlock.models import DataSourceConfig, DataSourceType
    from tests.unit.test_fabric_adapter import CONFIG
    from tests.unit.test_mcp_adapter import _make_app

    source = DataSourceConfig(
        source_id="saved",
        name="Fabric",
        source_type=DataSourceType.DATABASE,
        connection_config=CONFIG,
        metadata={"connector_key": "fabric_sql"},
    )
    registry = SimpleNamespace(get=lambda source_id: source if source_id == "saved" else None)
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
    app = _make_app(MCPAdapter(pg_pool=object(), registry=registry))
    app.state.fabric_services = services
    with TestClient(app) as client:
        response = client.post(
            "/mcp/tools/call",
            json={"name": "query", "arguments": {"source_id": "saved", "sql": "SELECT 1"}},
        )
        assert response.status_code == 200, response.text
        assert services.auth.acquire.call_args.args[0] == "saved"
        response = client.post(
            "/mcp/tools/call",
            json={
                "name": "query",
                "arguments": {"source_id": "saved", "sql": "SELECT NEXT VALUE FOR dbo.sequence"},
            },
        )
        assert response.status_code == 400
        services.transport.execute.assert_awaited_once()
