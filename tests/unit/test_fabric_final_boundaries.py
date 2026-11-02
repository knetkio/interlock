"""Final-review regressions at grammar, admission and terminal-audit boundaries."""

import asyncio
import json
import time
from dataclasses import asdict, replace
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from interlock.connections.connectors import get_adapter
from interlock.connections.fabric.auth import FabricAuthError, FabricToken
from interlock.connections.fabric.config import FabricConfig
from interlock.connections.fabric.runtime import FabricServices
from interlock.connections.sqlserver import SqlServerTransport, SqlServerTransportError
from interlock.core.approval_queue import ApprovalQueue
from interlock.errors import InterLockError
from tests.unit.test_fabric_adapter import CONFIG
from tests.unit.test_fabric_cache_scope import IdentityStore
from tests.unit.test_fabric_governance import call_query, governed, run_query
from tests.unit.test_source_roles import stmt
from tests.unit.test_sqlserver_transport import install as transport_install

install = transport_install


@pytest.mark.asyncio
@pytest.mark.parametrize("cs", [True, False])
@pytest.mark.parametrize("rhs", ["name", "UPPER(name)", "Name + name", "COALESCE(name, 'x')"])
async def test_data_derived_update_is_refused_before_queue_and_again_for_saved_approval(cs, rhs):
    sql = f"UPDATE dbo.Users SET Name = {rhs} WHERE Name = ?"
    _, auth, transport, cache, source, request, mcp = governed(
        cs=cs,
        statements=[
            stmt(
                permission_id=1,
                action="db.table.update",
                resource_type="db.column",
                resource_pattern="dbo.Users.Name",
            ),
            stmt(
                permission_id=2,
                effect="deny",
                action="db.table.update",
                resource_type="db.column",
                resource_pattern="dbo.Users.name",
            ),
        ],
    )
    queue_submit = AsyncMock(return_value=73)
    request.app.state.approval_queue = SimpleNamespace(submit=queue_submit)
    response = await call_query(request, mcp, sql, parameters=["x"])
    assert response.status_code in (400, 403)
    queue_submit.assert_not_awaited()
    assert auth.calls == 0 and not cache.lookups
    transport.execute.assert_not_awaited()
    # Existing queued rows must hit the same real adapter grammar guard.
    queue = ApprovalQueue(object(), fabric_services=request.app.state.fabric_services)
    row = {
        "id": 1,
        "source_id": "saved",
        "identity_id": 2,
        "sql_text": sql,
        "request_metadata": {"parameters": ["x"]},
    }
    with pytest.raises(InterLockError, match="assignment"):
        await queue._execute_via_adapter(row, source, "database")
    assert auth.calls == 0
    transport.execute.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("rhs,parameters", [("'literal'", ["x"]), ("?", ["value", "x"])])
@pytest.mark.parametrize("cs", [True, False])
async def test_safe_update_assignments_keep_governed_queue_and_execution(cs, rhs, parameters):
    sql = f"UPDATE dbo.Users SET Name = {rhs} WHERE Name = ?"
    store, _, transport, _, source, request, mcp = governed(
        cs=cs,
        statements=[
            stmt(permission_id=1, action="db.table.update", resource_pattern="dbo.Users.*")
        ],
    )
    submit = AsyncMock(return_value=73)
    request.app.state.approval_queue = SimpleNamespace(submit=submit)
    response = await run_query(
        request, mcp, {"source_id": "saved", "sql": sql, "parameters": parameters}
    )
    assert response.status_code == 202
    transport.execute.assert_not_awaited()
    # Acceptance governance is covered separately; this checks the actual saved
    # approval/adapter handoff preserves these allowed SQL shapes and parameters.
    queue = ApprovalQueue(object(), fabric_services=request.app.state.fabric_services)
    queue._revalidate_fabric_approval = AsyncMock()
    row = {
        "id": 1,
        "source_id": "saved",
        "identity_id": 2,
        "sql_text": sql,
        "request_metadata": {"parameters": parameters, "upstream_identity": asdict(store.context)},
    }
    await queue._execute_via_adapter(row, source, "database")
    assert transport.execute.call_args.args[2:4] == (sql, tuple(parameters))


@pytest.mark.asyncio
@pytest.mark.parametrize("write", [False, True])
@pytest.mark.parametrize(
    "change", ["disconnect", "generation", "incarnation", "disable", "delete", "config"]
)
async def test_queued_revoked_capability_never_connects_and_releases_admission(
    install, write, change
):
    driver = install(columns=[], rows=[], rowcount=1)
    transport = SqlServerTransport()
    store = IdentityStore()
    auth = SimpleNamespace(
        acquire=AsyncMock(return_value=FabricToken("token", time.time() + 300, store.context))
    )
    services = FabricServices(store, auth, transport)
    target = get_adapter("fabric_sql", fabric_services=services, source_id="saved")
    sql = "INSERT INTO dbo.Users (Name) VALUES (?)" if write else "SELECT Name FROM dbo.Users"
    for _ in range(8):
        await transport._slots.acquire()
    task = asyncio.create_task(
        target._execute(
            {"query": sql, "parameters": ["safe"], "connection_config": CONFIG}, write=write
        )
    )
    try:
        async with asyncio.timeout(2):
            while not transport._admitted:
                await asyncio.sleep(0)
        if change == "disconnect":
            store.context = replace(store.context, status="disconnected", generation=2)
        elif change == "generation":
            store.context = replace(store.context, generation=2)
        elif change == "incarnation":
            store.context = replace(store.context, incarnation="replacement")
        elif change in ("disable", "delete"):
            store.enabled = False
        else:
            store.config = FabricConfig.from_mapping(CONFIG | {"database": "Other"})
        transport._slots.release()
        with pytest.raises(FabricAuthError):
            await task
        assert not driver.connections and not driver.submissions and not driver.committed
        assert transport._admitted == 0 and transport._slots._value == 1
        auth.acquire.assert_awaited_once()
    finally:
        if not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
        await transport.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "failure",
    ["auth", "binding", "cache", "cache_delivery", "origin", "before_cache_put", "delivery"],
)
async def test_fabric_failure_audit_retains_attempt_identity_category_and_correlation(failure):
    store, auth, transport, cache, _, request, mcp = governed()
    request.headers = {"x-correlation-id": "fabric-final-correlation"}
    sql = "SELECT Name FROM dbo.Users"
    args = {"source_id": "saved", "sql": sql}
    expected = asdict(store.context)
    if failure == "auth":
        auth.failure = "reconnect_required"
    elif failure == "binding":
        acquire = auth.acquire

        async def changed_binding(*args):
            store.context = replace(store.context, generation=2)
            return await acquire(*args)

        auth.acquire = changed_binding
        expected = asdict(replace(store.context, generation=2))
    elif failure == "origin":
        transport.execute.side_effect = SqlServerTransportError("PRIVATE_DRIVER_DIAGNOSTIC")
    elif failure in ("cache", "cache_delivery"):
        assert (await run_query(request, mcp, args)).status_code == 200
        request.app.state.audit_logger.log.reset_mock()

        async def revoke():
            store.context = replace(store.context, generation=2)

        if failure == "cache":
            cache.on_get = revoke
        else:

            async def revoke_after_success(event):
                if event.status == "success":
                    await revoke()

            request.app.state.audit_logger.log.side_effect = revoke_after_success
    elif failure == "before_cache_put":

        async def redact(*args):
            store.context = replace(store.context, generation=2)
            return [{"Name": "private-value"}], False, [], {}

        mcp._redact_rows = redact
    else:

        async def revoke_on_put(*args, **kwargs):
            store.context = replace(store.context, generation=2)

        cache.put = revoke_on_put
    response = await run_query(request, mcp, args)
    assert response.status_code == 400
    body = json.loads(response.body)
    events = [call.args[0] for call in request.app.state.audit_logger.log.call_args_list]
    errors = [event for event in events if event.status == "error"]
    assert [event.status for event in events] == (
        ["success", "error"] if failure in ("delivery", "cache_delivery") else ["error"]
    )
    assert len(errors) == 1 and events[-1].status == "error"
    event = errors[0]
    assert event.identity_id == request.state.identity.identity_id and event.source_id == "saved"
    assert event.request_metadata["upstream_identity"] == expected
    assert (
        event.request_metadata["correlation_id"]
        == body["correlation_id"]
        == "fabric-final-correlation"
    )
    assert event.request_metadata["failure_category"] in {
        "reconnect_required",
        "configuration_changed",
        "fabric_identity_changed",
        "fabric_origin_failed",
    }
    assert event.error_message == event.request_metadata["failure_category"]
    assert all(
        secret not in str(event)
        for secret in ("PRIVATE_DRIVER_DIAGNOSTIC", "private-access-token", "private-value")
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("repeated", [False, True])
async def test_cancellation_during_submission_check_restores_capacity_without_driver(
    install, repeated
):
    driver = install()
    transport = SqlServerTransport()
    entered, release = asyncio.Event(), asyncio.Event()

    async def check():
        entered.set()
        try:
            await release.wait()
        except asyncio.CancelledError:
            if repeated:
                await release.wait()
            raise

    from tests.unit.test_sqlserver_transport import config, token

    task = asyncio.create_task(
        transport.execute(config(), token(), "SELECT 1", (), write=False, before_submit=check)
    )
    try:
        await asyncio.wait_for(entered.wait(), 2)
        task.cancel()
        await asyncio.sleep(0)
        if repeated:
            task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert transport._admitted == 0 and transport._slots._value == 8
        assert not driver.connections and not driver.submissions
    finally:
        release.set()
        await transport.close()


@pytest.mark.asyncio
async def test_cache_barrier_failure_has_trusted_preflight_audit_before_acquisition(monkeypatch):
    from interlock.errors import CacheBarrierUnavailableError
    from interlock.gateway import mcp_adapter as module

    store, auth, transport, _, _, request, mcp = governed()
    request.headers = {"x-correlation-id": "barrier-correlation"}
    monkeypatch.setattr(
        module,
        "current_cache_source_generation",
        AsyncMock(side_effect=CacheBarrierUnavailableError("private-barrier-diagnostic")),
    )
    response = await run_query(
        request, mcp, {"source_id": "saved", "sql": "SELECT Name FROM dbo.Users"}
    )
    assert response.status_code == 503
    events = request.app.state.audit_logger.log.call_args_list
    assert len(events) == 1 and events[0].args[0].status == "error"
    event = events[0].args[0]
    assert event.request_metadata["upstream_identity"] == asdict(store.context)
    assert event.request_metadata["failure_category"] == "fabric_cache_unavailable"
    assert (
        json.loads(response.body)["correlation_id"]
        == event.request_metadata["correlation_id"]
        == "barrier-correlation"
    )
    assert "private-barrier-diagnostic" not in str(event)
    assert auth.calls == 0
    transport.execute.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "sqlstate,category",
    [
        ("IM002", "driver_unavailable"),
        ("08001", "network_unavailable"),
        ("42501", "permission_denied"),
        ("42000", "query_failed"),
    ],
)
async def test_probe_preserves_fixed_driver_failure_categories_without_raw_details(
    install, monkeypatch, sqlstate, category
):
    driver = install()

    def fail(*args, **kwargs):
        raise RuntimeError(sqlstate, "PRIVATE_DRIVER_DIAGNOSTIC")

    monkeypatch.setattr(driver, "connect", fail)
    store = IdentityStore()
    transport = SqlServerTransport()
    services = FabricServices(
        store,
        SimpleNamespace(
            acquire=AsyncMock(return_value=FabricToken("token", time.time() + 300, store.context))
        ),
        transport,
    )
    from interlock.admin.routes.fabric_auth import probe_saved

    request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(fabric_services=services)))
    try:
        result = await probe_saved(request, "saved", CONFIG)
        assert not result.healthy and category in result.error
        assert "PRIVATE" not in result.error and "reconnect" not in result.error
        assert not driver.submissions
    finally:
        await transport.close()


@pytest.mark.asyncio
async def test_queued_catalog_page_rechecks_prepared_source_before_driver(install):
    from interlock.catalog.collectors.fabric import metadata_snapshot
    from interlock.catalog.model import ScanLimits

    driver = install()
    store = IdentityStore()
    transport = SqlServerTransport()
    auth = SimpleNamespace(
        acquire=AsyncMock(return_value=FabricToken("token", time.time() + 300, store.context))
    )
    services = FabricServices(store, auth, transport)
    for _ in range(8):
        await transport._slots.acquire()
    task = asyncio.create_task(metadata_snapshot(services, "saved", store.config, ScanLimits()))
    try:
        async with asyncio.timeout(2):
            while not transport._admitted:
                await asyncio.sleep(0)
        store.context = replace(store.context, generation=2)
        transport._slots.release()
        with pytest.raises(FabricAuthError):
            await task
        assert not driver.connections and not driver.submissions
        assert transport._admitted == 0 and transport._slots._value == 1
        auth.acquire.assert_awaited_once()
    finally:
        if not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
        await transport.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("literal", ["N'café'", "0xAB", "NULL", "-1", "1.2"])
async def test_literal_forms_remain_available_without_sql_or_parameter_rewriting(literal):
    from tests.unit.test_fabric_adapter import adapter

    target, services = adapter()
    sql = f"UPDATE dbo.Users SET Name = {literal} WHERE id = ?"
    await target.execute_write({"query": sql, "parameters": [1], "connection_config": CONFIG})
    assert services.transport.execute.call_args.args[2:4] == (sql, (1,))


@pytest.mark.asyncio
async def test_probe_recognizes_sqlserver_permission_native_code_without_publishing_diagnostic(
    install, monkeypatch
):
    driver = install()

    def fail(*args, **kwargs):
        raise RuntimeError(
            "42000", "[SQL Server] SELECT permission denied on private-table (229) (SQLExecDirectW)"
        )

    monkeypatch.setattr(driver, "connect", fail)
    store = IdentityStore()
    transport = SqlServerTransport()
    services = FabricServices(
        store,
        SimpleNamespace(
            acquire=AsyncMock(return_value=FabricToken("token", time.time() + 300, store.context))
        ),
        transport,
    )
    try:
        target = get_adapter("fabric_sql", fabric_services=services, source_id="saved")
        result = await target.probe(CONFIG)
        assert not result.healthy and "permission_denied" in result.error
        assert "private-table" not in result.error and "(229)" not in result.error
    finally:
        await transport.close()
