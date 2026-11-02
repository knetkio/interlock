"""Real control records decide queued Fabric writes; provider/ODBC only are fake."""

import asyncio
import json
from dataclasses import asdict
from unittest.mock import AsyncMock

import pytest
import pytest_asyncio

from interlock.catalog.collectors.fabric import metadata_snapshot
from interlock.catalog.model import ScanLimits
from interlock.catalog.store import apply_snapshot
from interlock.connections.fabric.config import FabricConfig
from interlock.core.approval_queue import ApprovalQueue
from interlock.errors import InterLockError, WriteApprovalRequiredError
from interlock.metadata.registry import MetadataRegistry
from interlock.models import RiskLevel
from tests.integration.test_fabric_credentials_store import store_db  # noqa: F401
from tests.integration.test_fabric_lifecycle import SPN, runtime
from tests.unit.test_fabric_catalog import MetadataTransport

pytestmark = [pytest.mark.integration, pytest.mark.asyncio(loop_scope="session")]


@pytest_asyncio.fixture(loop_scope="session")
async def acceptance(store_db, monkeypatch):  # noqa: F811
    store, pool, _ = store_db
    monkeypatch.setenv("FABRIC_LIFECYCLE_SECRET", "test-only-secret")
    await pool.execute(
        "UPDATE data_sources SET connection_config=$1 WHERE source_id='one'", json.dumps(SPN)
    )
    # Production pools encode JSONB values. Configure every connection in this
    # disposable test pool before exercising the real queue/auth/audit owners.
    conns = [await pool.acquire() for _ in range(5)]
    for conn in conns:
        await conn.set_type_codec(
            "jsonb", schema="pg_catalog", encoder=json.dumps, decoder=json.loads
        )
    for conn in conns:
        await pool.release(conn)
    services, source = runtime(store, monkeypatch)
    await services.prepare_source("one", FabricConfig.from_mapping(SPN))
    services.transport = MetadataTransport()
    snapshot = await metadata_snapshot(
        services, "one", FabricConfig.from_mapping(SPN), ScanLimits()
    )
    scan_id = await pool.fetchval(
        "INSERT INTO source_catalog_scans (source_id,trigger,status) VALUES ('one','manual','running') RETURNING id"
    )
    async with store.guard_current(
        snapshot.publication_context.context, snapshot.publication_context.config
    ) as conn:
        await apply_snapshot(
            conn, source_id="one", scan_id=scan_id, snapshot=snapshot, max_change_rows=100
        )
    await pool.execute(
        "UPDATE source_catalog_scans SET status='succeeded',finished_at=NOW() WHERE id=$1", scan_id
    )
    identity = await pool.fetchval(
        "INSERT INTO identities(name,api_key_hash) VALUES ('original','not-a-raw-api-key') RETURNING id"
    )
    role = await pool.fetchval(
        "INSERT INTO source_roles(source_id,role_key,name) VALUES ('one','writer','Writer') RETURNING id"
    )
    await pool.execute(
        "INSERT INTO source_role_permissions(role_id,effect,action,resource_type,resource_pattern) VALUES ($1,'allow','db.table.update','db.table','Sales.People.*')",
        role,
    )
    await pool.execute(
        "INSERT INTO identity_source_role_grants(identity_id,source_id,role_id) VALUES ($1,'one',$2)",
        identity,
        role,
    )
    await pool.execute(
        "INSERT INTO policy_rules(name,conditions,actions) VALUES ('allow','{}','{\"effect\":\"allow\"}')"
    )
    registry = MetadataRegistry(pool)
    await registry.load()
    services.transport = type(
        "Transport",
        (),
        {"execute": AsyncMock(return_value={"rows": [], "columns": [], "row_count": 1})},
    )()
    queue = ApprovalQueue(pool, registry=registry, fabric_services=services)
    binding = asdict(await store.get_context("one"))
    with pytest.raises(WriteApprovalRequiredError) as exc:
        await queue.submit(
            identity,
            "one",
            "UPDATE Sales.People SET Name = ?",
            RiskLevel.HIGH,
            {
                "protocol": "mcp",
                "connector_key": "fabric_sql",
                "parameters": ["preserved-value"],
                "upstream_identity": binding,
            },
        )
    return queue, exc.value.approval_id, store, pool, services, identity


@pytest.mark.parametrize(
    "mutation",
    [
        "actor_disabled",
        "grant_revoked",
        "role_disabled",
        "policy_denied",
        "policy_risk_cap",
        "catalog_removed",
        "catalog_stale_binding",
        "catalog_view",
        "generation",
        "incarnation",
        "source_disabled",
        "connector_changed",
    ],
)
async def test_pending_write_rechecks_current_actor_grants_policy_catalog_and_upstream(
    acceptance, mutation
):
    queue, approval_id, store, pool, services, identity = acceptance
    if mutation == "actor_disabled":
        await pool.execute("UPDATE identities SET enabled=FALSE WHERE id=$1", identity)
    elif mutation == "grant_revoked":
        await pool.execute("DELETE FROM identity_source_role_grants WHERE identity_id=$1", identity)
    elif mutation == "role_disabled":
        await pool.execute("UPDATE source_roles SET enabled=FALSE WHERE source_id='one'")
    elif mutation in {"policy_denied", "policy_risk_cap"}:
        await pool.execute(
            "UPDATE policy_rules SET actions=$1",
            (
                {"effect": "deny"}
                if mutation == "policy_denied"
                else {"effect": "allow", "write_risk_cap": "low"}
            ),
        )
    elif mutation == "catalog_removed":
        await pool.execute("UPDATE source_catalog SET removed_at=NOW() WHERE source_id='one'")
    elif mutation == "catalog_stale_binding":
        await pool.execute(
            "UPDATE source_catalog SET attributes=jsonb_set(attributes,'{upstream_identity,generation}','0') WHERE source_id='one' AND node_type='source'"
        )
    elif mutation == "catalog_view":
        await pool.execute(
            "UPDATE source_catalog SET node_type='view' WHERE source_id='one' AND node_type='table'"
        )
    elif mutation == "generation":
        await store.invalidate("one", reason="disconnect", delete_cache=True)
    elif mutation == "incarnation":
        await pool.execute(
            "UPDATE fabric_credentials SET incarnation=gen_random_uuid() WHERE source_id='one'"
        )
    elif mutation == "source_disabled":
        await pool.execute("UPDATE data_sources SET enabled=FALSE WHERE source_id='one'")
    else:
        await pool.execute(
            "UPDATE data_sources SET metadata='{\"connector_key\":\"mysql\"}' WHERE source_id='one'"
        )
    with pytest.raises(InterLockError):
        await queue.approve(approval_id, "reviewer")
    services.transport.execute.assert_not_awaited()
    row = await pool.fetchrow(
        "SELECT status,request_metadata FROM write_approval_queue WHERE id=$1", approval_id
    )
    assert row["status"] == "failed"
    assert (
        await pool.fetchval(
            "SELECT count(*) FROM audit_log WHERE approval_id=$1 AND status='error'", approval_id
        )
        == 1
    )


async def test_concurrent_approval_executes_once_with_original_ordered_parameters_and_audit(
    acceptance,
):
    queue, approval_id, _, pool, services, _ = acceptance
    results = await asyncio.gather(
        queue.approve(approval_id, "a"), queue.approve(approval_id, "b"), return_exceptions=True
    )
    assert sum(isinstance(r, dict) and r.get("executed") for r in results) == 1
    services.transport.execute.assert_awaited_once()
    assert services.transport.execute.call_args.args[3] == ("preserved-value",)
    assert (
        await pool.fetchval(
            "SELECT count(*) FROM audit_log WHERE approval_id=$1 AND status='success'", approval_id
        )
        == 1
    )


async def test_transport_failure_is_failed_once_and_audited_without_echoing_values(acceptance):
    queue, approval_id, _, pool, services, _ = acceptance
    services.transport.execute.side_effect = RuntimeError("sensitive row value")
    with pytest.raises(InterLockError) as exc:
        await queue.approve(approval_id, "reviewer")
    assert "sensitive row value" not in str(exc.value)
    assert (
        await pool.fetchval("SELECT status FROM write_approval_queue WHERE id=$1", approval_id)
        == "failed"
    )
    assert (
        await pool.fetchval(
            "SELECT count(*) FROM audit_log WHERE approval_id=$1 AND status='error'", approval_id
        )
        == 1
    )
    services.transport.execute.assert_awaited_once()


@pytest.mark.parametrize("new_identity", [False, True])
async def test_partial_catalog_retention_is_scoped_to_upstream_identity(acceptance, new_identity):
    from interlock.catalog.model import CatalogSnapshot

    queue, _, store, pool, _, _ = acceptance
    old = await store.get_context("one")
    if new_identity:
        await pool.execute(
            "UPDATE fabric_credentials SET generation=generation+1 WHERE source_id='one'"
        )
    current = await store.current_source("one")
    root = await pool.fetchval(
        "SELECT attributes FROM source_catalog WHERE source_id='one' AND path='{}'"
    )
    partial = CatalogSnapshot(
        source_attributes=root | {"upstream_identity": asdict(current.context)},
        truncated=True,
        truncation={"max_nodes": 1},
        complete_subtrees=[],
    )
    scan = await pool.fetchval(
        "INSERT INTO source_catalog_scans(source_id,trigger,status) VALUES ('one','manual','running') RETURNING id"
    )
    async with store.guard_current(current.context, current.config) as conn:
        await apply_snapshot(
            conn, source_id="one", scan_id=scan, snapshot=partial, max_change_rows=100
        )
    count = await pool.fetchval(
        "SELECT count(*) FROM source_catalog WHERE source_id='one' AND node_type='table' AND removed_at IS NULL"
    )
    assert count == (0 if new_identity else 1)
    # Old inventory stays inspectable for audit; it is never destroyed.
    assert (
        await pool.fetchval(
            "SELECT count(*) FROM source_catalog WHERE source_id='one' AND node_type='table'"
        )
        == 1
    )


async def test_runner_discards_scan_if_identity_changes_during_metadata_io(acceptance):
    from interlock.catalog.runner import CatalogScanRunner
    from interlock.config import CatalogConfig

    _, _, store, pool, services, _ = acceptance
    base = MetadataTransport()

    async def execute(*args, **kwargs):
        result = await base.execute(*args, **kwargs)
        if "FROM sys.columns" in args[2]:
            await pool.execute("UPDATE data_sources SET enabled=FALSE WHERE source_id='one'")
        return result

    services.transport = type("Transport", (), {"execute": staticmethod(execute)})()
    registry = MetadataRegistry(pool)
    scan = await pool.fetchval(
        "INSERT INTO source_catalog_scans(source_id,trigger,status) VALUES ('one','manual','running') RETURNING id"
    )
    runner = CatalogScanRunner(
        pg_pool=pool,
        registry=registry,
        conn_manager=None,
        config=CatalogConfig(),
        worker_id="test",
        fabric_services=services,
    )
    await runner._run(scan, "one")
    row = await pool.fetchrow(
        "SELECT status,error_code FROM source_catalog_scans WHERE id=$1", scan
    )
    assert dict(row) == {"status": "failed", "error_code": "stale_identity"}
    assert not await pool.fetchval(
        "SELECT count(*) FROM source_catalog WHERE last_seen_scan_id=$1", scan
    )


async def test_runner_uses_guard_connection_and_rolls_back_failed_catalog_publication(
    acceptance, monkeypatch
):
    import interlock.catalog.runner as runner_module
    from interlock.catalog.runner import CatalogScanRunner
    from interlock.config import CatalogConfig

    _, _, store, pool, services, _ = acceptance
    services.transport = MetadataTransport()
    registry = MetadataRegistry(pool)
    scan = await pool.fetchval(
        "INSERT INTO source_catalog_scans(source_id,trigger,status) VALUES ('one','manual','running') RETURNING id"
    )
    original_apply = runner_module.apply_snapshot

    async def fail_after_apply(conn, **kwargs):
        # A held source lock on this same connection proves the runner uses the
        # guard owner; a second pool transaction would deadlock this operation.
        await conn.execute("UPDATE data_sources SET name='rollback-only' WHERE source_id='one'")
        await original_apply(conn, **kwargs)
        raise RuntimeError("controlled publication failure")

    monkeypatch.setattr(runner_module, "apply_snapshot", fail_after_apply)
    runner = CatalogScanRunner(
        pg_pool=pool,
        registry=registry,
        conn_manager=None,
        config=CatalogConfig(),
        worker_id="test",
        fabric_services=services,
    )
    await asyncio.wait_for(runner._run(scan, "one"), timeout=5)
    assert await pool.fetchval("SELECT name FROM data_sources WHERE source_id='one'") == "Fabric"
    assert not await pool.fetchval(
        "SELECT count(*) FROM source_catalog WHERE last_seen_scan_id=$1", scan
    )
    assert (
        await pool.fetchval("SELECT status FROM source_catalog_scans WHERE id=$1", scan) == "failed"
    )


async def test_actor_revoked_during_token_acquisition_is_rechecked_before_sql(acceptance):
    queue, approval_id, _, pool, services, identity = acceptance
    acquire = services.auth.acquire

    async def revoke(*args):
        token = await acquire(*args)
        await pool.execute("UPDATE identities SET enabled=FALSE WHERE id=$1", identity)
        return token

    services.auth.acquire = revoke
    with pytest.raises(InterLockError):
        await queue.approve(approval_id, "reviewer")
    services.transport.execute.assert_not_awaited()


async def test_native_case_role_and_policy_create_read_routes_preserve_stored_spelling(acceptance):
    from httpx import ASGITransport, AsyncClient

    from tests.unit.test_source_role_editor import _make_app

    _, _, _, pool, _, _ = acceptance
    async with AsyncClient(
        transport=ASGITransport(app=_make_app(pool)), base_url="http://test"
    ) as client:
        created_role = await client.post(
            "/dashboard/data-sources/one/roles",
            data={
                "role_key": "case_reader",
                "name": "Native case reader",
                "enabled": "on",
                "permission_effect": ["allow", "deny"],
                "permission_action": ["db.table.select", "db.table.select"],
                "permission_resource_type": ["db.column", "db.column"],
                "permission_resource_pattern": ["Sales.People.Name", "Sales.People.name"],
                "permission_constraints": ["{}", "{}"],
            },
        )
        assert created_role.status_code == 303, created_role.text
        role_id = await pool.fetchval(
            "SELECT id FROM source_roles WHERE source_id='one' AND role_key='case_reader'"
        )
        stored = await pool.fetch(
            "SELECT resource_pattern FROM source_role_permissions WHERE role_id=$1 ORDER BY id",
            role_id,
        )
        assert [row["resource_pattern"] for row in stored] == [
            "Sales.People.Name",
            "Sales.People.name",
        ]
        read_role = await client.get(f"/dashboard/data-sources/one/roles/{role_id}/edit")
        assert read_role.status_code == 200
        assert 'value="Sales.People.Name"' in read_role.text
        assert 'value="Sales.People.name"' in read_role.text

        policy = {
            "name": "Native case policy",
            "conditions": {
                "source_id": "one",
                "tables": ["Sales.People", "sales.people"],
                "columns": ["Name", "name"],
            },
            "actions": {"effect": "allow", "redact_columns": ["Name", "name"]},
        }
        created_policy = await client.post("/api/policies", json=policy)
        assert created_policy.status_code == 201, created_policy.text
        policy_id = created_policy.json()["id"]
        stored_policy = await pool.fetchrow(
            "SELECT conditions,actions FROM policy_rules WHERE id=$1", policy_id
        )
        read_policy = await client.get(f"/api/policies/{policy_id}")
        assert read_policy.status_code == 200
        for key in ("conditions", "actions"):
            assert stored_policy[key] == policy[key]
            assert created_policy.json()[key] == policy[key]
            assert read_policy.json()[key] == policy[key]
