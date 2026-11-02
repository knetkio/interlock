"""Two Fabric runtimes sharing real control PostgreSQL/Redis; provider I/O is replaced."""

import asyncio
import json
import os
import time
import uuid
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
import redis.asyncio as redis

from interlock.cache.l1 import L1Cache
from interlock.cache.l2 import L2Cache
from interlock.cache.strategy import DeterministicFirstStrategy
from interlock.config import FabricSettings
from interlock.connections.fabric.auth import FabricAuth
from interlock.connections.fabric.config import FabricConfig
from interlock.connections.fabric.credentials import FabricCredentialError, FabricCredentialStore
from interlock.connections.fabric.runtime import FabricServices
from interlock.core.approval_queue import ApprovalQueue
from interlock.errors import InterLockError
from interlock.gateway.mcp_adapter import MCPAdapter
from interlock.models import DataSourceConfig, DataSourceType
from tests.integration.test_fabric_credentials_store import BASE
from tests.integration.test_fabric_credentials_store import store_db as _store_db
from tests.unit.test_fabric_auth import connect
from tests.unit.test_fabric_auth import setup_auth as _setup_auth

store_db = _store_db
setup_auth = _setup_auth

pytestmark = [pytest.mark.integration, pytest.mark.asyncio(loop_scope="session")]
SPN = BASE | {"auth_mode": "spn", "client_secret_ref": "env://FABRIC_LIFECYCLE_SECRET"}


def runtime(store, monkeypatch, config=SPN):
    auth = FabricAuth(store, FabricSettings())
    # This is the one external MSAL boundary. Store locking, encryption,
    # generation, current-source reads and the cache/MCP implementations are real.
    monkeypatch.setattr(
        auth,
        "_acquire_sync",
        lambda *_: ("private-token", time.time() + 3600, "encrypted-test-cache"),
    )
    transport = SimpleNamespace(execute=AsyncMock(return_value={"rows": [{"principal": "old"}]}))
    services = FabricServices(store, auth, transport)
    source = DataSourceConfig(
        source_id="one",
        name="Fabric",
        source_type=DataSourceType.DATABASE,
        metadata={"connector_key": "fabric_sql"},
        connection_config=config,
    )
    return services, source


def request_for(services, source, strategy):
    request = MagicMock()
    request.app.state = SimpleNamespace(
        fabric_services=services,
        cache_strategy=strategy,
        registry=SimpleNamespace(get=lambda _: source),
        audit_logger=None,
        write_classifier=None,
        approval_queue=None,
        pii_scanner=None,
        policy_engine=None,
    )
    request.state = SimpleNamespace(identity=None, gateway_decision=None)
    return request


async def query(request):
    request.state.gateway_decision = None
    return await MCPAdapter(pg_pool=object())._execute_query(
        request, {"source_id": "one", "sql": "SELECT 1"}
    )


@pytest.mark.parametrize(
    "mutation", ["disconnect", "disable", "delete", "database", "host", "auth", "connector"]
)
async def test_stale_second_gateway_refuses_retained_cache_after_committed_mutation(
    store_db, monkeypatch, mutation
):
    store, pool, keys = store_db
    await pool.execute(
        "UPDATE data_sources SET connection_config=$1 WHERE source_id='one'", json.dumps(SPN)
    )
    first, source = runtime(store, monkeypatch)
    second, _ = runtime(FabricCredentialStore(pool, keys), monkeypatch)
    client = redis.from_url(os.environ["TEST_REDIS_URL"])
    prefix = "fabric-lifecycle:" + uuid.uuid4().hex + ":"
    l2 = L2Cache(client, key_prefix=prefix)
    strategy1 = DeterministicFirstStrategy(L1Cache(), l2)
    strategy2 = DeterministicFirstStrategy(L1Cache(), l2)
    request1 = request_for(first, source, strategy1)
    request2 = request_for(second, source, strategy2)
    try:
        assert (await query(request1)).status_code == 200
        assert (await query(request2)).status_code == 200  # Promote real L2 to gateway 2 L1.
        second.transport.execute.assert_not_awaited()
        before = await store.get_context("one")
        # No notification or invalidation is delivered to either gateway.
        if mutation == "disconnect":
            await store.invalidate("one", reason="disconnect", delete_cache=True)
        elif mutation == "disable":
            await pool.execute("UPDATE data_sources SET enabled=FALSE WHERE source_id='one'")
        elif mutation == "delete":
            await pool.execute("DELETE FROM data_sources WHERE source_id='one'")
        elif mutation == "connector":
            await pool.execute(
                "UPDATE data_sources SET metadata=$1 WHERE source_id='one'",
                json.dumps({"connector_key": "mysql"}),
            )
        else:
            changes = (
                {"database": "other"}
                if mutation == "database"
                else (
                    {"host": "other.datawarehouse.fabric.microsoft.com"}
                    if mutation == "host"
                    else {"auth_mode": "oauth", "client_secret_ref": None}
                )
            )
            await pool.execute(
                "UPDATE data_sources SET connection_config=$1 WHERE source_id='one'",
                json.dumps(SPN | changes),
            )
        response = await query(request2)
        assert response.status_code != 200 and b'"principal"' not in response.body
        second.transport.execute.assert_not_awaited()
        if mutation != "delete":
            row = await pool.fetchrow(
                "SELECT generation,encrypted_cache FROM fabric_credentials WHERE source_id='one'"
            )
            assert row["generation"] == before.generation + 1 and row["encrypted_cache"] is None
        assert await client.scan_iter(
            match=prefix + "*"
        ).__anext__()  # Old cache deliberately remains.
    finally:
        await l2.clear()
        await client.aclose()


async def test_disabled_uninitialized_source_never_initializes_credentials_or_authenticates(
    store_db, monkeypatch
):
    store, pool, _ = store_db
    await pool.execute(
        "UPDATE data_sources SET connection_config=$1,enabled=FALSE WHERE source_id='one'",
        json.dumps(SPN),
    )
    services, source = runtime(store, monkeypatch)
    response = await query(request_for(services, source, DeterministicFirstStrategy(L1Cache())))
    assert response.status_code != 200
    assert await pool.fetchval("SELECT count(*) FROM fabric_credentials") == 0
    services.transport.execute.assert_not_awaited()


async def test_delete_and_recreate_never_reuses_previous_identity_or_cache_namespace(
    store_db, monkeypatch
):
    store, pool, _ = store_db
    await pool.execute(
        "UPDATE data_sources SET connection_config=$1 WHERE source_id='one'", json.dumps(SPN)
    )
    services, source = runtime(store, monkeypatch)
    strategy = DeterministicFirstStrategy(L1Cache())
    request = request_for(services, source, strategy)
    assert (await query(request)).status_code == 200
    before = await services.prepare_source("one", FabricConfig.from_mapping(SPN))
    await pool.execute("DELETE FROM data_sources WHERE source_id='one'")
    await pool.execute(
        "INSERT INTO data_sources (source_id,name,source_type,connection_config,metadata) VALUES ('one','New','database',$1,'{\"connector_key\":\"fabric_sql\"}'::jsonb)",
        json.dumps(SPN),
    )
    after = await services.prepare_source("one", FabricConfig.from_mapping(SPN))
    assert before.token.context.generation == after.token.context.generation == 1
    assert before.token.context.incarnation != after.token.context.incarnation
    assert before.cache_scope != after.cache_scope
    with pytest.raises(FabricCredentialError):
        await store.assert_current(before.token.context, before.config)
    services.transport.execute.return_value = {"rows": [{"principal": "new"}]}
    response = await query(request)
    assert response.status_code == 200
    assert services.transport.execute.await_count == 2


async def test_inflight_read_finishing_after_database_change_is_not_published(
    store_db, monkeypatch
):
    store, pool, _ = store_db
    await pool.execute(
        "UPDATE data_sources SET connection_config=$1 WHERE source_id='one'", json.dumps(SPN)
    )
    services, source = runtime(store, monkeypatch)
    l1 = L1Cache()
    strategy = DeterministicFirstStrategy(l1)
    entered, release = asyncio.Event(), asyncio.Event()

    async def execute(*args, **kwargs):
        entered.set()
        await release.wait()
        return {"rows": [{"principal": "old"}]}

    services.transport.execute.side_effect = execute
    task = asyncio.create_task(query(request_for(services, source, strategy)))
    await asyncio.wait_for(entered.wait(), timeout=2)
    await pool.execute(
        "UPDATE data_sources SET connection_config=$1 WHERE source_id='one'",
        json.dumps(SPN | {"database": "other"}),
    )
    release.set()
    response = await task
    assert response.status_code != 200
    assert not l1._cache


@pytest.mark.parametrize("mutation", ["reconnect", "recreate"])
async def test_queued_approval_does_not_execute_with_replacement_principal(
    store_db, monkeypatch, mutation
):
    store, pool, _ = store_db
    await pool.execute(
        "UPDATE data_sources SET connection_config=$1 WHERE source_id='one'", json.dumps(SPN)
    )
    services, source = runtime(store, monkeypatch)
    before = await services.prepare_source("one", FabricConfig.from_mapping(SPN))
    row = dict(
        id=1,
        source_id="one",
        identity_id=2,
        sql_text="DELETE FROM dbo.Users WHERE id=?",
        request_metadata={"upstream_identity": before.upstream_identity, "parameters": [1]},
    )
    if mutation == "reconnect":
        await store.invalidate("one", reason="rotation", delete_cache=True)
    else:
        await pool.execute("DELETE FROM data_sources WHERE source_id='one'")
        await pool.execute(
            "INSERT INTO data_sources (source_id,name,source_type,connection_config,metadata) VALUES ('one','New','database',$1,'{\"connector_key\":\"fabric_sql\"}'::jsonb)",
            json.dumps(SPN),
        )
    with pytest.raises(InterLockError, match="identity changed"):
        await ApprovalQueue(pool, fabric_services=services)._execute_via_adapter(
            row, source, "database"
        )
    services.transport.execute.assert_not_awaited()


@pytest.mark.parametrize("route", ["api", "dashboard"])
async def test_admin_disable_commits_revocation_even_when_notification_and_invalidation_fail(
    store_db, monkeypatch, route
):
    from contextlib import asynccontextmanager

    from interlock.admin.routes import dashboard, data_sources
    from interlock.connections.fabric.auth import FabricAuthError

    store, pool, _ = store_db
    await pool.execute(
        "UPDATE data_sources SET connection_config=$1 WHERE source_id='one'", json.dumps(SPN)
    )
    services, source = runtime(store, monkeypatch)
    prepared = await services.prepare_source("one", FabricConfig.from_mapping(SPN))
    request = request_for(services, source, DeterministicFirstStrategy(L1Cache()))

    class FailedNotificationPool:
        @asynccontextmanager
        async def acquire(self):
            async with pool.acquire() as conn:

                class Connection:
                    fetchrow = conn.fetchrow

                    async def execute(self, query, *args):
                        if query.startswith("NOTIFY"):
                            raise ConnectionError("notification unavailable")
                        return await conn.execute(query, *args)

                yield Connection()

        fetchrow = pool.fetchrow

    request.app.state.pg_pool = FailedNotificationPool()
    invalidator = SimpleNamespace(
        invalidate_for_source=AsyncMock(side_effect=ConnectionError("cache unavailable"))
    )
    request.app.state.cache_invalidator = invalidator
    module = data_sources if route == "api" else dashboard
    monkeypatch.setattr(module, "after_source_saved", AsyncMock())
    monkeypatch.setattr(module, "audit_admin_action", AsyncMock())
    if route == "api":
        result = await data_sources.update_data_source(
            "one", data_sources.DataSourceUpdate(enabled=False), request
        )
        assert result["enabled"] is False
    else:
        response = await dashboard.toggle_data_source_enabled("one", request)
        assert response.status_code in (200, 303)
    invalidator.invalidate_for_source.assert_awaited_once_with("one")
    assert await pool.fetchval("SELECT enabled FROM data_sources WHERE source_id='one'") is False
    row = await pool.fetchrow(
        "SELECT generation,encrypted_cache FROM fabric_credentials WHERE source_id='one'"
    )
    assert (
        row["generation"] == prepared.token.context.generation + 1
        and row["encrypted_cache"] is None
    )
    with pytest.raises(FabricAuthError):
        await services.assert_current(prepared)


async def test_publication_guard_holds_lifecycle_lock_and_commits_using_its_own_connection(
    store_db, monkeypatch
):
    store, pool, _ = store_db
    await pool.execute(
        "UPDATE data_sources SET connection_config=$1 WHERE source_id='one'", json.dumps(SPN)
    )
    services, _ = runtime(store, monkeypatch)
    prepared = await services.prepare_source("one", FabricConfig.from_mapping(SPN))
    await pool.execute("CREATE TABLE publication_probe (value TEXT)")
    started = asyncio.Event()

    async def disable():
        started.set()
        await pool.execute("UPDATE data_sources SET enabled=FALSE WHERE source_id='one'")

    async with store.guard_current(prepared.token.context, prepared.config) as conn:
        await conn.execute("INSERT INTO publication_probe VALUES ('coherent snapshot')")
        mutation = asyncio.create_task(disable())
        await asyncio.wait_for(started.wait(), timeout=2)
        with pytest.raises(TimeoutError):
            await asyncio.wait_for(asyncio.shield(mutation), timeout=0.05)
        # Publication uses this exact transaction, and is not visible early.
        assert await pool.fetchval("SELECT count(*) FROM publication_probe") == 0
    await mutation
    assert await pool.fetchval("SELECT value FROM publication_probe") == "coherent snapshot"
    with pytest.raises(FabricCredentialError):
        async with store.guard_current(prepared.token.context, prepared.config):
            pytest.fail("obsolete identity acquired a publication guard")


@pytest.mark.parametrize("replacement", ["oauth_account", "spn_secret"])
async def test_real_auth_replacement_bypasses_warmed_cache_under_new_generation(
    store_db, setup_auth, monkeypatch, replacement
):
    store, pool, _ = store_db
    _, behavior, calls, settings = setup_auth
    config = (
        BASE
        if replacement == "oauth_account"
        else SPN | {"client_secret_ref": "env://FABRIC_CLIENT_SECRET"}
    )
    await pool.execute(
        "UPDATE data_sources SET connection_config=$1 WHERE source_id='one'", json.dumps(config)
    )
    auth = FabricAuth(store, settings)
    if replacement == "oauth_account":
        await connect(auth, store)
    transport = SimpleNamespace(execute=AsyncMock(return_value={"rows": [{"principal": "old"}]}))
    services = FabricServices(store, auth, transport)
    source = DataSourceConfig(
        source_id="one",
        name="Fabric",
        source_type=DataSourceType.DATABASE,
        metadata={"connector_key": "fabric_sql"},
        connection_config=config,
    )
    request = request_for(services, source, DeterministicFirstStrategy(L1Cache()))
    assert (await query(request)).status_code == 200
    assert (await query(request)).status_code == 200
    before = await store.get_context("one")
    if replacement == "oauth_account":
        behavior.account = {
            "home_account_id": "replacement.tenant",
            "local_account_id": "replacement",
            "realm": "tenant",
        }
        await connect(auth, store)
    else:
        monkeypatch.setenv("FABRIC_CLIENT_SECRET", "rotated-private-secret")
    transport.execute.return_value = {"rows": [{"principal": "new"}]}
    response = await query(request)
    if replacement == "spn_secret":
        # Rotation was discovered inside auth, after governance captured the
        # prior generation. The changed binding requires a fresh preflight.
        assert response.status_code != 200
        assert transport.execute.await_count == 1
        response = await query(request)
    assert response.status_code == 200
    assert "new" in json.loads(response.body)["content"][0]["text"]
    assert transport.execute.await_count == 2
    current = await store.get_context("one")
    assert current.generation == before.generation + 1
    assert current.incarnation == before.incarnation
    assert current.account_id == ("replacement.tenant" if replacement == "oauth_account" else None)


@pytest.mark.parametrize(
    "before_metadata,after_metadata",
    [
        ({"connector_key": "fabric_sql"}, {}),
        ({"connector_key": "FABRIC_SQL"}, {}),
        ({"provider": "fabric_sql"}, {"provider": "mysql"}),
        ({"connector_key": "fabric_sql", "provider": "mysql"}, {"provider": "mysql"}),
        (
            {"connector_key": "", "provider": "fabric_sql"},
            {"connector_key": "", "provider": "mysql"},
        ),
    ],
    ids=[
        "key-removed",
        "uppercase-key-removed",
        "provider-replaced",
        "key-removed-reveals-provider",
        "empty-key-provider-replaced",
    ],
)
async def test_connector_replacement_blocks_stale_gateways_with_retained_l1_and_l2(
    store_db, monkeypatch, before_metadata, after_metadata
):
    store, pool, keys = store_db
    await pool.execute(
        "UPDATE data_sources SET connection_config=$1,metadata=$2 WHERE source_id='one'",
        json.dumps(SPN),
        json.dumps(before_metadata),
    )
    first, source = runtime(store, monkeypatch)
    source.metadata = before_metadata
    second, _ = runtime(FabricCredentialStore(pool, keys), monkeypatch)
    first_provider = MagicMock(wraps=first.auth._acquire_sync)
    second_provider = MagicMock(wraps=second.auth._acquire_sync)
    monkeypatch.setattr(first.auth, "_acquire_sync", first_provider)
    monkeypatch.setattr(second.auth, "_acquire_sync", second_provider)
    client = redis.from_url(os.environ["TEST_REDIS_URL"])
    l2 = L2Cache(client, key_prefix="fabric-connector-change:" + uuid.uuid4().hex + ":")
    l1_first, l1_second = L1Cache(), L1Cache()
    request1 = request_for(first, source, DeterministicFirstStrategy(l1_first, l2))
    request2 = request_for(second, source, DeterministicFirstStrategy(l1_second, l2))
    try:
        assert (await query(request1)).status_code == 200
        assert (await query(request2)).status_code == 200
        current = await store.current_source("one")
        old_key = next(iter(l1_first._cache))
        assert (await l2.get(old_key)).hit and (await l1_second.get(old_key)).hit
        provider_calls = (first_provider.call_count, second_provider.call_count)
        # Both registries and all retained caches deliberately stay unchanged.
        await pool.execute(
            "UPDATE data_sources SET metadata=$1 WHERE source_id='one'", json.dumps(after_metadata)
        )
        row = await pool.fetchrow(
            "SELECT generation,encrypted_cache FROM fabric_credentials WHERE source_id='one'"
        )
        assert (
            row["generation"] == current.context.generation + 1 and row["encrypted_cache"] is None
        )
        with pytest.raises(FabricCredentialError):
            await store.current_source("one")
        with pytest.raises(FabricCredentialError):
            await store.assert_current(current.context, current.config)
        for request in (request1, request2):
            response = await query(request)
            assert response.status_code != 200 and b'"principal"' not in response.body
        assert (first_provider.call_count, second_provider.call_count) == provider_calls
        first.transport.execute.assert_awaited_once()
        second.transport.execute.assert_not_awaited()
        assert (await l1_first.get(old_key)).hit and (await l2.get(old_key)).hit
    finally:
        await l2.clear()
        await client.aclose()


@pytest.mark.parametrize(
    "metadata,allowed",
    [
        ({}, False),
        ({"provider": "mysql"}, False),
        ({"provider": "fabric_sql"}, True),
        ({"connector_key": "", "provider": "fabric_sql"}, True),
        ({"connector_key": None, "provider": "fabric_sql"}, True),
        ({"connector_key": "FABRIC_SQL", "provider": "mysql"}, True),
        ({"connector_key": "fabric_sql", "provider": "mysql"}, True),
        ({"connector_key": "mysql", "provider": "fabric_sql"}, False),
    ],
)
async def test_authoritative_connector_resolution_matches_registry_precedence(
    store_db, metadata, allowed
):
    from interlock.connections.connectors import connector_key_for

    store, pool, _ = store_db
    await pool.execute(
        "UPDATE data_sources SET metadata=$1 WHERE source_id='one'", json.dumps(metadata)
    )
    assert (connector_key_for("database", metadata) == "fabric_sql") is allowed
    if allowed:
        current = await store.current_source("one")
        assert current.config == FabricConfig.from_mapping(BASE)
    else:
        with pytest.raises(FabricCredentialError):
            await store.current_source("one")
        assert await pool.fetchval("SELECT count(*) FROM fabric_credentials") == 0


async def test_ignored_provider_edit_does_not_revoke_explicit_fabric_connector(
    store_db, monkeypatch
):
    store, pool, _ = store_db
    await pool.execute(
        "UPDATE data_sources SET connection_config=$1,metadata=$2 WHERE source_id='one'",
        json.dumps(SPN),
        json.dumps({"connector_key": "fabric_sql", "provider": "mysql"}),
    )
    services, _ = runtime(store, monkeypatch)
    prepared = await services.prepare_source("one", FabricConfig.from_mapping(SPN))
    await pool.execute(
        "UPDATE data_sources SET metadata=$1 WHERE source_id='one'",
        json.dumps({"connector_key": "fabric_sql", "provider": "postgresql"}),
    )
    await store.assert_current(prepared.token.context, prepared.config)
    assert (await store.get_context("one")).generation == prepared.token.context.generation


@pytest.mark.parametrize("metadata", [{"connector_key": "FABRIC_SQL"}, {"provider": "fabric_sql"}])
async def test_alias_fabric_approval_preserves_original_principal_check(
    store_db, monkeypatch, metadata
):
    store, pool, _ = store_db
    await pool.execute(
        "UPDATE data_sources SET connection_config=$1,metadata=$2 WHERE source_id='one'",
        json.dumps(SPN),
        json.dumps(metadata),
    )
    services, source = runtime(store, monkeypatch)
    source.metadata = metadata
    prepared = await services.prepare_source("one", FabricConfig.from_mapping(SPN))
    # Approval now reloads the original actor, roles, policy and native catalog.
    # Seed those real control records; this test still focuses on alias/principal
    # routing and does not stub away the new acceptance owner.
    from interlock.catalog.model import CatalogNode, CatalogSnapshot
    from interlock.catalog.store import apply_snapshot

    actor = await pool.fetchval(
        "INSERT INTO identities(name,api_key_hash) VALUES ('writer','test-hash') RETURNING id"
    )
    role = await pool.fetchval(
        "INSERT INTO source_roles(source_id,role_key,name) VALUES ('one','writer','Writer') RETURNING id"
    )
    await pool.execute(
        "INSERT INTO identity_source_role_grants(identity_id,source_id,role_id) VALUES ($1,'one',$2)",
        actor,
        role,
    )
    await pool.execute(
        "INSERT INTO source_role_permissions(role_id,effect,action,resource_type,resource_pattern) VALUES ($1,'allow','db.table.delete_rows','db.table','dbo.Users.*')",
        role,
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
            "identifier_case_sensitive": True,
            "upstream_identity": prepared.upstream_identity,
        },
        nodes=[
            CatalogNode("table", ("dbo", "Users"), "Users", "dbo.Users"),
            CatalogNode("column", ("dbo", "Users", "id"), "id", "dbo.Users.id"),
        ],
        complete_subtrees=[()],
    )
    async with store.guard_current(prepared.token.context, prepared.config) as conn:
        await apply_snapshot(
            conn, source_id="one", scan_id=scan, snapshot=snapshot, max_change_rows=100
        )
    row = dict(
        id=1,
        source_id="one",
        identity_id=actor,
        sql_text="DELETE FROM dbo.Users WHERE id=?",
        request_metadata={"upstream_identity": prepared.upstream_identity, "parameters": [1]},
    )
    queue = ApprovalQueue(
        pool, registry=SimpleNamespace(get=lambda _: source), fabric_services=services
    )
    await queue._execute_sql(row, row["request_metadata"])
    services.transport.execute.assert_awaited_once()
    await store.invalidate("one", reason="rotation", delete_cache=True)
    with pytest.raises(InterLockError, match="identity changed"):
        await queue._execute_sql(row, row["request_metadata"])
    services.transport.execute.assert_awaited_once()


@pytest.mark.parametrize("empty_marker", [None, "", False, 0, [], {}])
async def test_provider_fallback_changes_revoke_for_python_empty_marker_values(
    store_db, monkeypatch, empty_marker
):
    store, pool, _ = store_db
    before_metadata = {"connector_key": empty_marker, "provider": "fabric_sql"}
    await pool.execute(
        "UPDATE data_sources SET connection_config=$1,metadata=$2 WHERE source_id='one'",
        json.dumps(SPN),
        json.dumps(before_metadata),
    )
    services, _ = runtime(store, monkeypatch)
    prepared = await services.prepare_source("one", FabricConfig.from_mapping(SPN))
    await pool.execute(
        "UPDATE data_sources SET metadata=$1 WHERE source_id='one'",
        json.dumps({"connector_key": empty_marker, "provider": "mysql"}),
    )
    assert (
        await pool.fetchval("SELECT generation FROM fabric_credentials WHERE source_id='one'")
        == prepared.token.context.generation + 1
    )
    with pytest.raises(FabricCredentialError):
        await store.assert_current(prepared.token.context, prepared.config)


async def test_standalone_disconnect_still_revokes_disabled_unreadable_credentials(
    store_db, monkeypatch
):
    store, pool, _ = store_db
    await pool.execute(
        "UPDATE data_sources SET connection_config=$1 WHERE source_id='one'", json.dumps(SPN)
    )
    services, _ = runtime(store, monkeypatch)
    prepared = await services.prepare_source("one", FabricConfig.from_mapping(SPN))
    await pool.execute("UPDATE data_sources SET enabled=FALSE WHERE source_id='one'")
    await pool.execute(
        "UPDATE fabric_credentials SET encrypted_cache=$1 WHERE source_id='one'", b"unreadable"
    )
    disconnected = await store.invalidate("one", reason="disconnect", delete_cache=True)
    assert disconnected.generation == prepared.token.context.generation + 2
    assert disconnected.status == "disconnected"
    assert (
        await pool.fetchval("SELECT encrypted_cache FROM fabric_credentials WHERE source_id='one'")
        is None
    )
