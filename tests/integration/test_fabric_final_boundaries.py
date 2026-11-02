"""Final fixes with committed control records; ODBC/provider remain offline doubles."""

import asyncio
import json
import os
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock

import asyncpg
import pytest
import pytest_asyncio

from interlock.catalog.model import CatalogNode, CatalogSnapshot
from interlock.catalog.store import apply_snapshot
from interlock.connections.connectors import get_adapter
from interlock.connections.fabric.auth import FabricAuthError, FabricToken
from interlock.connections.fabric.config import FabricConfig
from interlock.connections.fabric.runtime import FabricServices
from interlock.connections.sqlserver import SqlServerTransport
from interlock.core.approval_queue import ApprovalQueue
from interlock.db.pool import _init_connection
from interlock.errors import InterLockError
from tests.integration.test_fabric_credentials_store import store_db as control_store
from tests.integration.test_fabric_lifecycle import SPN, runtime
from tests.unit.test_sqlserver_transport import install as transport_driver

store_db = control_store
install = transport_driver
pytestmark = [pytest.mark.integration, pytest.mark.asyncio(loop_scope="session")]


@pytest_asyncio.fixture(loop_scope="session")
async def approval_pool(store_db):
    # Match production JSON codecs for real queue writes and audit persistence;
    # the shared lifecycle fixture deliberately uses raw JSON strings instead.
    _, raw, _ = store_db
    search_path = await raw.fetchval("SHOW search_path")
    pool = await asyncpg.create_pool(
        host=os.environ["TEST_PG_HOST"],
        port=int(os.environ["TEST_PG_PORT"]),
        user=os.environ["TEST_PG_USER"],
        password=os.environ["TEST_PG_PASSWORD"],
        database=os.environ["TEST_PG_DATABASE"],
        min_size=1,
        max_size=5,
        server_settings={"search_path": search_path},
        init=_init_connection,
    )
    try:
        yield pool
    finally:
        await pool.close()


@pytest.mark.parametrize("cs", [True, False])
@pytest.mark.parametrize("rhs", ["name", "UPPER(name)", "'literal'", "?"])
async def test_saved_update_approval_revalidates_current_native_column_scope(
    store_db, approval_pool, monkeypatch, cs, rhs
):
    store, pool, _ = store_db
    await pool.execute(
        "UPDATE data_sources SET connection_config=$1 WHERE source_id='one'", json.dumps(SPN)
    )
    services, source = runtime(store, monkeypatch)
    prepared = await services.prepare_source("one", FabricConfig.from_mapping(SPN))
    actor = await pool.fetchval(
        "INSERT INTO identities(name,api_key_hash) VALUES ('writer','offline-hash') RETURNING id"
    )
    role = await pool.fetchval(
        "INSERT INTO source_roles(source_id,role_key,name) VALUES ('one','writer','Writer') RETURNING id"
    )
    await pool.execute(
        "INSERT INTO identity_source_role_grants(identity_id,source_id,role_id) VALUES ($1,'one',$2)",
        actor,
        role,
    )
    # Distinct Name/name exist only under CS. Under CI the separate secret
    # column keeps the explicit-deny condition without denying the destination.
    secret = "name" if cs else "Secret"
    await pool.execute(
        "INSERT INTO source_role_permissions(role_id,effect,action,resource_type,resource_pattern) VALUES ($1,'allow','db.table.update','db.column','dbo.Users.Name'),($1,'deny','db.table.update','db.column',$2)",
        role,
        f"dbo.Users.{secret}",
    )
    await pool.execute(
        "INSERT INTO policy_rules(name,conditions,actions) VALUES ('allow','{}','{\"effect\":\"allow\"}')"
    )
    scan = await pool.fetchval(
        "INSERT INTO source_catalog_scans(source_id,trigger,status) VALUES ('one','manual','running') RETURNING id"
    )
    snapshot = CatalogSnapshot(
        source_attributes={
            "database": SPN["database"],
            "default_schema": "dbo",
            "identifier_case_sensitive": cs,
            "upstream_identity": prepared.upstream_identity,
        },
        nodes=[
            CatalogNode("table", ("dbo", "Users"), "Users", "dbo.Users"),
            CatalogNode("column", ("dbo", "Users", "Name"), "Name", "dbo.Users.Name"),
            CatalogNode("column", ("dbo", "Users", secret), secret, f"dbo.Users.{secret}"),
        ],
        complete_subtrees=[()],
    )
    async with store.guard_current(prepared.token.context, prepared.config) as conn:
        await apply_snapshot(
            conn, source_id="one", scan_id=scan, snapshot=snapshot, max_change_rows=100
        )
    value = rhs if cs else rhs.replace("name", "Secret")
    sql = f"UPDATE dbo.Users SET Name = {value} WHERE Name = ?"
    parameters = ["value", "old"] if rhs == "?" else ["old"]
    metadata = {"upstream_identity": prepared.upstream_identity, "parameters": parameters}
    approval_id = await pool.fetchval(
        "INSERT INTO write_approval_queue(identity_id,source_id,sql_text,risk_level,status,expires_at,request_metadata) VALUES ($1,'one',$2,'medium','pending',NOW()+INTERVAL '15 minutes',$3) RETURNING id",
        actor,
        sql,
        json.dumps(metadata),
    )
    queue = ApprovalQueue(
        approval_pool, registry=SimpleNamespace(get=lambda _: source), fabric_services=services
    )
    if rhs in ("name", "UPPER(name)"):
        with pytest.raises(InterLockError):
            await queue.approve(approval_id, "offline-reviewer")
        assert (
            await pool.fetchval("SELECT status FROM write_approval_queue WHERE id=$1", approval_id)
            == "failed"
        )
        services.transport.execute.assert_not_awaited()
    else:
        result = await queue.approve(approval_id, "offline-reviewer")
        assert result["executed"] is True
        assert (
            await pool.fetchval("SELECT status FROM write_approval_queue WHERE id=$1", approval_id)
            == "executed"
        )
        assert services.transport.execute.call_args.args[2:4] == (sql, tuple(parameters))
    # Audit persistence uses the same saved identity on success and refusal.
    events = await approval_pool.fetch(
        "SELECT status,request_metadata FROM audit_log WHERE source_id='one'"
    )
    assert len(events) == 1
    assert events[0]["status"] == ("error" if rhs in ("name", "UPPER(name)") else "success")
    assert events[0]["request_metadata"]["upstream_identity"] == prepared.upstream_identity


@pytest.mark.parametrize(
    "mutation", ["disconnect", "generation", "incarnation", "disable", "delete", "config"]
)
async def test_committed_revocation_prevents_queued_native_submission(store_db, install, mutation):
    store, pool, _ = store_db
    await pool.execute(
        "UPDATE data_sources SET connection_config=$1 WHERE source_id='one'", json.dumps(SPN)
    )
    current = await store.current_source("one")
    driver = install(columns=[], rows=[], rowcount=1)
    transport = SqlServerTransport()
    auth = SimpleNamespace(
        acquire=AsyncMock(return_value=FabricToken("token", time.time() + 300, current.context))
    )
    services = FabricServices(store, auth, transport)
    target = get_adapter("fabric_sql", fabric_services=services, source_id="one")
    for _ in range(8):
        await transport._slots.acquire()
    task = asyncio.create_task(
        target.execute_write(
            {
                "query": "INSERT INTO dbo.Users (Name) VALUES (?)",
                "parameters": ["safe"],
                "connection_config": SPN,
            }
        )
    )
    try:
        async with asyncio.timeout(2):
            while not transport._admitted:
                await asyncio.sleep(0)
        # Each mutation commits while the SQL task is waiting, proving no
        # control-DB lock is held over admission or the eventual native call.
        if mutation == "disconnect":
            await store.invalidate("one", reason="disconnect", delete_cache=True)
        elif mutation == "generation":
            await pool.execute(
                "UPDATE fabric_credentials SET generation=generation+1 WHERE source_id='one'"
            )
        elif mutation == "incarnation":
            await pool.execute(
                "UPDATE fabric_credentials SET incarnation=gen_random_uuid() WHERE source_id='one'"
            )
        elif mutation == "disable":
            await pool.execute("UPDATE data_sources SET enabled=FALSE WHERE source_id='one'")
        elif mutation == "delete":
            await pool.execute("DELETE FROM data_sources WHERE source_id='one'")
        else:
            await pool.execute(
                "UPDATE data_sources SET connection_config=$1 WHERE source_id='one'",
                json.dumps(SPN | {"database": "other"}),
            )
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
