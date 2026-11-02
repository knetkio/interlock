"""Fabric cache hits must pass the same current-identity boundary as origin reads."""

import asyncio
import json
import time
from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from interlock.connections.fabric.auth import FabricAuthError, FabricToken
from interlock.connections.fabric.config import FabricConfig
from interlock.connections.fabric.credentials import FabricCredentialContext
from interlock.connections.fabric.runtime import FabricServices
from interlock.gateway.mcp_adapter import MCPAdapter
from interlock.models import CacheResult, DataSourceConfig, DataSourceType
from tests.unit.test_fabric_adapter import CONFIG


class IdentityStore:
    def __init__(self):
        self.config = FabricConfig.from_mapping(CONFIG)
        self.context = FabricCredentialContext(
            "saved", 1, "tenant-id", "client-id", None, "spn", "connected"
        )
        self.enabled = True

    async def current_source(self, source_id):
        from interlock.connections.fabric.credentials import FabricCurrentSource

        await self.assert_current(self.context, self.config)
        return FabricCurrentSource(self.config, self.context)

    async def assert_current(self, context, config):
        if not self.enabled or context != self.context or config != self.config:
            raise FabricAuthError("configuration_changed")


class Auth:
    def __init__(self, store):
        self.store = store
        self.calls = 0
        self.failure = None

    async def acquire(self, source_id, config):
        self.calls += 1
        assert source_id == "saved"
        if self.failure:
            raise FabricAuthError(self.failure)
        if not self.store.enabled or config != self.store.config:
            raise FabricAuthError("configuration_changed")
        if self.store.context.status != "connected":
            raise FabricAuthError("reconnect_required")
        return FabricToken("private-access-token", time.time() + 300, self.store.context)


class Cache:
    def __init__(self, tier):
        self.entries = {}
        self.tier = tier
        self.lookups = []
        self.on_get = None

    async def get(self, key, **kwargs):
        self.lookups.append(key)
        if self.on_get:
            await self.on_get()
        if key in self.entries:
            data, metadata = self.entries[key]
            return CacheResult(hit=True, data=data, tier=self.tier, metadata=metadata)
        return CacheResult(hit=False)

    async def put(self, key, data, metadata, **kwargs):
        self.entries[key] = (data, metadata)


def setup(tier="l1"):
    store = IdentityStore()
    auth = Auth(store)
    transport = SimpleNamespace(execute=AsyncMock(return_value={"rows": [{"principal": "old"}]}))
    services = FabricServices(store, auth, transport)
    cache = Cache(tier)
    source = DataSourceConfig(
        source_id="saved",
        name="Fabric",
        source_type=DataSourceType.DATABASE,
        connection_config=CONFIG,
        metadata={"connector_key": "fabric_sql"},
    )
    state = SimpleNamespace(
        fabric_services=services,
        cache_strategy=cache,
        registry=SimpleNamespace(get=lambda _: source),
        audit_logger=None,
        write_classifier=None,
        approval_queue=None,
        pii_scanner=None,
        policy_engine=None,
    )
    request = MagicMock()
    request.app.state = state
    request.state = SimpleNamespace(gateway_decision=None, identity=None)
    adapter = MCPAdapter(pg_pool=AsyncMock())
    return store, auth, transport, cache, source, request, adapter


async def query(request, adapter):
    request.state.gateway_decision = None
    return await adapter._execute_query(request, {"source_id": "saved", "sql": "SELECT 1"})


@pytest.mark.asyncio
@pytest.mark.parametrize("tier", ["l1", "l2", "semantic"])
@pytest.mark.parametrize("failure", ["disconnect", "expired", "disabled", "deleted", "unavailable"])
async def test_warmed_cache_cannot_bypass_current_auth_even_when_notifications_fail(tier, failure):
    store, auth, transport, cache, source, request, adapter = setup(tier)
    assert (await query(request, adapter)).status_code == 200
    assert len(cache.entries) == 1
    if failure == "disconnect":
        store.context = replace(store.context, generation=2, status="disconnected")
    elif failure in {"disabled", "deleted"}:
        store.enabled = False  # Registry deliberately stays stale.
    else:
        auth.failure = (
            "reconnect_required" if failure == "expired" else "authentication_unavailable"
        )
    response = await query(request, adapter)
    assert response.status_code != 200
    assert b'"principal"' not in response.body
    assert len(cache.lookups) == 1
    transport.execute.assert_awaited_once()


@pytest.mark.asyncio
@pytest.mark.parametrize("change", ["account", "secret_rotation", "reconnect"])
async def test_replacement_identity_uses_new_namespace_and_current_audit_principal(change):
    store, auth, transport, cache, source, request, adapter = setup()
    if change == "account":
        store.config = FabricConfig.from_mapping(
            CONFIG | {"auth_mode": "oauth", "client_secret_ref": None}
        )
        source.connection_config = store.config.model_dump()
        store.context = replace(store.context, auth_mode="oauth", account_id="old-account")
    audit = AsyncMock()
    request.app.state.audit_logger = audit
    assert (await query(request, adapter)).status_code == 200
    store.context = replace(
        store.context, generation=2, account_id="new-account" if change == "account" else None
    )
    transport.execute.return_value = {"rows": [{"principal": "new"}]}
    response = await query(request, adapter)
    assert response.status_code == 200
    assert "new" in json.loads(response.body)["content"][0]["text"]
    assert len(set(cache.lookups)) == 2
    assert auth.calls == 2  # Exactly one acquire per request, including cache+origin.
    response = await query(request, adapter)
    assert response.status_code == 200 and auth.calls == 3
    assert transport.execute.await_count == 2
    event = audit.log.call_args.args[0]
    assert event.request_metadata["upstream_identity"]["generation"] == 2
    assert event.request_metadata["upstream_identity"]["account_id"] == store.context.account_id
    assert "private-access-token" not in str(event)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "changes",
    [
        {"database": "Other"},
        {"host": "other.datawarehouse.fabric.microsoft.com"},
        {"auth_mode": "oauth", "client_secret_ref": None},
    ],
)
async def test_config_edits_refuse_stale_registry_before_cache_lookup(changes):
    store, auth, transport, cache, source, request, adapter = setup()
    assert (await query(request, adapter)).status_code == 200
    store.config = FabricConfig.from_mapping(CONFIG | changes)
    store.context = replace(store.context, generation=2)
    response = await query(request, adapter)
    assert response.status_code != 200
    assert len(cache.lookups) == 1
    transport.execute.assert_awaited_once()


@pytest.mark.asyncio
async def test_inflight_old_identity_result_is_neither_served_nor_cached():
    store, auth, transport, cache, source, request, adapter = setup()
    entered, release = asyncio.Event(), asyncio.Event()

    async def execute(*args, **kwargs):
        entered.set()
        await release.wait()
        return {"rows": [{"principal": "old"}]}

    transport.execute.side_effect = execute
    task = asyncio.create_task(query(request, adapter))
    await asyncio.wait_for(entered.wait(), timeout=2)
    store.context = replace(store.context, generation=2)
    release.set()
    response = await task
    assert response.status_code != 200
    assert not cache.entries
    assert b'"principal"' not in response.body


@pytest.mark.asyncio
async def test_identity_change_while_cache_get_waits_cannot_deliver_hit():
    store, auth, transport, cache, source, request, adapter = setup()
    assert (await query(request, adapter)).status_code == 200

    async def change_identity():
        store.context = replace(store.context, generation=2)

    cache.on_get = change_identity
    response = await query(request, adapter)
    assert response.status_code != 200
    transport.execute.assert_awaited_once()


@pytest.mark.asyncio
async def test_prepared_token_expiring_during_cache_lookup_is_not_delivered(monkeypatch):
    store, auth, transport, cache, source, request, adapter = setup()
    assert (await query(request, adapter)).status_code == 200
    clock = [time.time()]
    monkeypatch.setattr("interlock.connections.fabric.runtime.time.time", lambda: clock[0])

    async def expire():
        clock[0] += 301

    cache.on_get = expire
    response = await query(request, adapter)
    assert response.status_code != 200
    transport.execute.assert_awaited_once()


@pytest.mark.parametrize(
    "metadata",
    [
        {"connector_key": "fabric_sql"},
        {"connector_key": "FABRIC_SQL"},
        {"provider": "fabric_sql"},
    ],
)
def test_denied_mcp_request_never_acquires_provider_token_and_queue_metadata_has_original_binding(
    monkeypatch,
    metadata,
):
    from dataclasses import asdict

    from starlette.testclient import TestClient

    from interlock.gateway.pipeline import GatewayDecision, GatewayPipeline
    from tests.unit.test_fabric_adapter import fabric_services
    from tests.unit.test_mcp_adapter import _make_app

    services = fabric_services("saved")
    source = DataSourceConfig(
        source_id="saved",
        name="Fabric",
        source_type=DataSourceType.DATABASE,
        connection_config=CONFIG,
        metadata=metadata,
    )
    registry = SimpleNamespace(get=lambda _: source)
    captured = []

    async def preflight(self, gateway_request, **kwargs):
        captured.append(gateway_request)
        return GatewayDecision(False, status_code=401, reason="No caller identity")

    monkeypatch.setattr(GatewayPipeline, "preflight", preflight)
    app = _make_app(MCPAdapter(pg_pool=object(), registry=registry))
    app.state.fabric_services = services
    with TestClient(app) as client:
        response = client.post(
            "/mcp/tools/call",
            json={
                "name": "query",
                "arguments": {
                    "source_id": "saved",
                    "sql": "SELECT 1",
                    "upstream_identity": {"generation": 999},
                },
            },
        )
    assert response.status_code == 401
    assert captured[0].metadata["connector_key"] == "fabric_sql"
    assert captured[0].metadata["upstream_identity"] == asdict(
        services.auth.acquire.return_value.context
    )
    services.auth.acquire.assert_not_awaited()
    services.transport.execute.assert_not_awaited()


@pytest.mark.asyncio
async def test_prepared_capability_from_another_runtime_cannot_submit_sql():
    from interlock.connections.connectors import get_adapter

    store, auth, transport, cache, source, request, adapter = setup()
    first = request.app.state.fabric_services
    prepared = await first.prepare_source("saved", store.config)
    second = FabricServices(store, auth, transport)
    target = get_adapter("fabric_sql", fabric_services=second, source_id="saved")
    with pytest.raises(FabricAuthError):
        await target.execute_prepared(
            {"query": "SELECT 1", "connection_config": CONFIG}, prepared, write=False
        )
    transport.execute.assert_not_awaited()
