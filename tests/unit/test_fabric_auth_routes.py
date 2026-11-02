"""Admin Fabric boundaries; provider/network behavior is covered by auth tests."""

import logging
from contextlib import asynccontextmanager
from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx
import pytest
from fastapi import FastAPI

from interlock.admin.auth import create_session, sign_cookie
from interlock.admin.auth_middleware import AdminAuthMiddleware
from interlock.config import FabricSettings
from interlock.connections.fabric.auth import FabricAuthError
from interlock.connections.fabric.config import FabricConfig
from interlock.connections.fabric.credentials import FabricCredentialContext

CFG = dict(
    host="test.fabric.microsoft.com",
    database="db",
    tenant_id="tenant",
    client_id="client",
    endpoint_type="warehouse",
    auth_mode="oauth",
)


class Redis:
    def __init__(self):
        self.values = {}

    async def set(self, key, value, **kwargs):
        self.values[key] = value

    async def get(self, key):
        return self.values.get(key)

    async def delete(self, *keys):
        for key in keys:
            self.values.pop(key, None)


@pytest.fixture
async def client(monkeypatch):
    from interlock.admin.routes.fabric_auth import router

    app = FastAPI()
    app.include_router(router)
    app.add_middleware(AdminAuthMiddleware, cookie_name="admin", secret_key="secret")
    app.state.redis = Redis()
    row = dict(
        source_id="fabric",
        source_type="database",
        metadata={"connector_key": "fabric_sql"},
        enabled=True,
        connection_config=CFG,
    )

    async def fetchrow(query, *args):
        if "admin_identities" in query:
            return dict(enabled=True, authorization_version=1)
        return row if args[0] == "fabric" else None

    app.state.pg_pool = SimpleNamespace(fetchrow=fetchrow, execute=AsyncMock())
    context = FabricCredentialContext(
        "fabric", 1, "tenant", "client", "account", "oauth", "connected", "incarnation"
    )

    @asynccontextmanager
    async def locked(source_id):
        yield SimpleNamespace(
            context=context, config=FabricConfig(**CFG), decrypted_cache="SECRET CACHE"
        )

    store = SimpleNamespace(locked=locked, invalidate=AsyncMock(return_value=context))
    auth = SimpleNamespace(
        begin_oauth=AsyncMock(
            return_value="https://login.microsoftonline.com/tenant/authorize?state=opaque"
        ),
        complete_oauth=AsyncMock(return_value=context),
    )
    app.state.fabric_services = SimpleNamespace(store=store, auth=auth)
    app.state.config = SimpleNamespace(
        fabric=FabricSettings(
            oauth_client_id="client",
            oauth_client_secret_ref="env://OPERATOR_SECRET",
            oauth_allowed_tenants=["tenant"],
            oauth_redirect_uri="http://localhost/api/fabric/oauth/callback",
        )
    )
    monkeypatch.setattr("interlock.admin.routes.fabric_auth._changed", AsyncMock())
    sid, csrf = await create_session(app.state.redis, 1, "admin", ["source_admin"], 1, 3600)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://localhost"
    ) as c:
        c.cookies.set("admin", sign_cookie({"sid": sid}, "secret"))
        c.headers["X-CSRF-Token"] = csrf
        yield c, app, row, sid


@pytest.mark.asyncio
async def test_connect_requires_live_session_and_csrf(client):
    c, app, row, sid = client
    assert (await c.post("/api/data-sources/fabric/fabric/connect")).status_code == 303
    assert app.state.fabric_services.auth.begin_oauth.call_args.args == ("fabric", sid)
    c.headers.pop("X-CSRF-Token")
    assert (await c.post("/api/data-sources/fabric/fabric/connect")).status_code == 403
    c.cookies.clear()
    assert (await c.post("/api/data-sources/fabric/fabric/connect")).status_code == 401


@pytest.mark.asyncio
async def test_wrong_source_and_origin_fail_closed(client):
    c, app, row, sid = client
    assert (await c.post("/api/data-sources/missing/fabric/connect")).status_code == 404
    row["metadata"] = {}
    assert (await c.post("/api/data-sources/fabric/fabric/connect")).status_code == 422
    row["metadata"] = {"connector_key": "fabric_sql"}
    assert (
        await c.post("http://127.0.0.1/api/data-sources/fabric/fabric/connect")
    ).status_code == 409
    app.state.fabric_services.auth.begin_oauth.assert_not_called()


@pytest.mark.asyncio
async def test_callback_uses_current_session_no_arbitrary_return(client):
    c, app, row, sid = client
    response = await c.get(
        "/api/fabric/oauth/callback?code=PRIVATE&state=opaque&return_to=https://evil.test"
    )
    assert response.status_code == 303
    assert response.headers["location"] == "/dashboard/data-sources/fabric"
    assert app.state.fabric_services.auth.complete_oauth.call_args.args[2] == sid
    assert "PRIVATE" not in response.text


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "code", ["authentication_denied", "reconnect_required", "configuration_changed"]
)
async def test_callback_auth_failures_are_sanitized(client, code):
    c, app, row, sid = client
    app.state.fabric_services.auth.complete_oauth.side_effect = FabricAuthError(code)
    response = await c.get(
        "/api/fabric/oauth/callback?code=PRIVATE&state=stolen&error_description=RAW_PROVIDER"
    )
    assert response.status_code == 400
    assert "PRIVATE" not in response.text and "RAW_PROVIDER" not in response.text


@pytest.mark.asyncio
async def test_status_never_serializes_cache_or_secret_and_checks_decryption(client):
    c, app, row, sid = client
    response = await c.get("/api/data-sources/fabric/fabric/auth-status")
    assert response.json() == {"auth_mode": "oauth", "status": "connected", "account_id": "account"}

    @asynccontextmanager
    async def broken(source):
        from interlock.connections.fabric.credentials import FabricCredentialError

        raise FabricCredentialError("secret ciphertext")
        yield

    app.state.fabric_services.store.locked = broken
    assert (await c.get("/api/data-sources/fabric/fabric/auth-status")).json()[
        "status"
    ] == "reconnect_required"


@pytest.mark.asyncio
async def test_rotate_refuses_oauth_and_disconnect_clears_cache(client):
    c, app, row, sid = client
    assert (await c.post("/api/data-sources/fabric/fabric/rotate")).status_code == 422
    assert (await c.post("/api/data-sources/fabric/fabric/disconnect")).status_code == 200
    app.state.fabric_services.store.invalidate.assert_awaited_once_with(
        "fabric", reason="disconnect", delete_cache=True
    )


def test_callback_log_redaction_covers_uvicorn_and_dependency_urls():
    from interlock.admin.routes.fabric_auth import FabricCallbackLogFilter

    filt = FabricCallbackLogFilter()
    record = logging.LogRecord(
        "httpx",
        logging.INFO,
        "",
        1,
        "HTTP Request: %s",
        (httpx.URL("http://localhost/api/fabric/oauth/callback?code=PRIVATE"),),
        None,
    )
    filt.filter(record)
    assert "PRIVATE" not in record.getMessage()
    for msg, args in [
        (
            "%s - %s %s HTTP/1.1",
            ("127.0.0.1", "GET", "/api/fabric/oauth/callback?code=PRIVATE&state=SECRET"),
        ),
        (
            'HTTP Request: GET %s "200"',
            ("http://localhost/api/fabric/oauth/callback?code=PRIVATE&state=SECRET",),
        ),
    ]:
        record = logging.LogRecord("uvicorn.access", logging.INFO, "", 1, msg, args, None)
        filt.filter(record)
        assert "PRIVATE" not in record.getMessage() and "SECRET" not in record.getMessage()


@pytest.mark.asyncio
async def test_callback_requires_mutation_role_and_rechecks_authorization(client):
    c, app, row, sid = client
    import json

    key = "admin:session:" + sid
    saved = json.loads(app.state.redis.values[key])
    saved["roles"] = ["viewer"]
    app.state.redis.values[key] = json.dumps(saved)
    assert (await c.get("/api/fabric/oauth/callback?state=opaque&code=PRIVATE")).status_code == 403
    app.state.fabric_services.auth.complete_oauth.assert_not_called()
    saved["roles"] = ["source_admin"]
    saved["authorization_version"] = 0
    app.state.redis.values[key] = json.dumps(saved)
    assert (await c.get("/api/fabric/oauth/callback?state=opaque&code=PRIVATE")).status_code == 401


@pytest.mark.asyncio
async def test_callback_and_real_auth_reject_cross_session_replay_and_config_edits(
    client, setup_auth
):
    from dataclasses import replace
    from urllib.parse import parse_qs, urlsplit

    c, app, row, sid = client
    create, behavior, calls, settings = setup_auth
    auth, store, config = create(oauth=True)
    settings.oauth_redirect_uri = "http://localhost/api/fabric/oauth/callback"
    app.state.fabric_services = SimpleNamespace(store=store, auth=auth)
    # Begin via the real auth owner (test store source is 'one').
    uri = await auth.begin_oauth("one", sid)
    state = parse_qs(urlsplit(uri).query)["state"][0]
    stolen = await c.get("/api/fabric/oauth/callback", params={"state": state, "code": "PRIVATE"})
    assert stolen.status_code == 303
    assert stolen.headers["location"] == "/dashboard/data-sources/one"
    replay = await c.get("/api/fabric/oauth/callback", params={"state": state, "code": "PRIVATE"})
    assert replay.status_code == 400
    # Same username in a different login cannot complete the flow.
    uri = await auth.begin_oauth("one", "other-session-nonce")
    state = parse_qs(urlsplit(uri).query)["state"][0]
    assert (
        await c.get("/api/fabric/oauth/callback", params={"state": state, "code": "PRIVATE"})
    ).status_code == 400
    uri = await auth.begin_oauth("one", sid)
    state = parse_qs(urlsplit(uri).query)["state"][0]
    store.context = replace(store.context, generation=store.context.generation + 1)
    assert (
        await c.get("/api/fabric/oauth/callback", params={"state": state, "code": "PRIVATE"})
    ).status_code == 400


@pytest.mark.asyncio
@pytest.mark.parametrize("scenario", ["tenant", "account", "consent"])
async def test_callback_real_auth_rejects_wrong_identity_and_denied_consent(
    client, setup_auth, scenario
):
    from urllib.parse import parse_qs, urlsplit

    c, app, row, sid = client
    create, behavior, calls, settings = setup_auth
    auth, store, config = create(oauth=True)
    settings.oauth_redirect_uri = "http://localhost/api/fabric/oauth/callback"
    app.state.fabric_services = SimpleNamespace(store=store, auth=auth)
    uri = await auth.begin_oauth("one", sid)
    state = parse_qs(urlsplit(uri).query)["state"][0]
    if scenario == "tenant":
        behavior.account["realm"] = "wrong-tenant"
    elif scenario == "account":
        behavior.account["home_account_id"] = ""
    else:
        behavior.result = {"error": "access_denied", "error_description": "RAW PROVIDER PRIVATE"}
    response = await c.get("/api/fabric/oauth/callback", params={"state": state, "code": "PRIVATE"})
    assert response.status_code == 400
    assert "PRIVATE" not in response.text and "RAW" not in response.text
    assert store.context.status != "connected"


# Share only the external MSAL test double; routes exercise the real auth owner.
from tests.unit.test_fabric_auth import setup_auth as external_msal_fixture  # noqa: E402

setup_auth = external_msal_fixture


@pytest.mark.asyncio
async def test_saved_probe_uses_exact_source_credentials_and_never_queues_catalog(client):
    import time

    from interlock.admin.routes.data_sources import router as source_router
    from interlock.connections.fabric.auth import FabricToken
    from interlock.connections.fabric.runtime import FabricServices

    c, app, row, sid = client
    app.include_router(source_router)
    context = FabricCredentialContext(
        "fabric", 1, "tenant", "client", "account", "oauth", "connected", "incarnation"
    )

    class SQL:
        async def execute(self, config, token, sql, parameters, **kwargs):
            assert token.context.source_id == "fabric"
            assert config.database == "db" and sql == "SELECT 1"
            return {"rows": [{"result": 1}], "columns": ["result"], "row_count": 1}

    store = SimpleNamespace(assert_current=AsyncMock())
    auth = SimpleNamespace(
        acquire=AsyncMock(return_value=FabricToken("PRIVATE_TOKEN", time.time() + 3600, context))
    )
    app.state.fabric_services = FabricServices(store, auth, SQL())
    result = await c.post("/api/data-sources/fabric/test")
    assert result.status_code == 200 and result.json()["ok"] is True
    auth.acquire.assert_awaited_once_with("fabric", FabricConfig(**CFG))
    unsaved = await c.post(
        "/api/data-sources/test",
        json={
            "source_type": "database",
            "connector_key": "fabric_sql",
            "source_id": "fabric",
            "connection_config": CFG,
        },
    )
    assert unsaved.json()["ok"] is False and "Save" in unsaved.json()["error"]
    assert auth.acquire.await_count == 1
    assert "PRIVATE_TOKEN" not in result.text
