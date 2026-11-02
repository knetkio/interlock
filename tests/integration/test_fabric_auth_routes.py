"""Real control-store state through admin routes; no provider or customer login."""

import hashlib
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
from fastapi import FastAPI

from interlock.admin.auth import create_session, sign_cookie
from interlock.admin.auth_middleware import AdminAuthMiddleware
from interlock.admin.routes.fabric_auth import router
from interlock.connections.fabric.auth import FabricAuth
from tests.integration.test_fabric_credentials_store import store_db as database_fixture
from tests.unit.test_fabric_auth import setup_auth as msal_fixture
from tests.unit.test_fabric_auth_routes import Redis

store_db = database_fixture
setup_auth = msal_fixture
pytestmark = [pytest.mark.integration, pytest.mark.asyncio(loop_scope="session")]


async def test_real_pending_flow_expiry_replay_session_and_config_binding(
    store_db, setup_auth, monkeypatch
):
    store, pool, _ = store_db
    _, behavior, calls, settings = setup_auth
    settings.oauth_redirect_uri = "http://localhost/api/fabric/oauth/callback"
    app = FastAPI()
    app.include_router(router)
    app.add_middleware(AdminAuthMiddleware, cookie_name="admin", secret_key="test-key")
    app.state.redis = Redis()

    async def fetchrow(query, *args):
        if "admin_identities" in query:
            return {"enabled": True, "authorization_version": 1}
        return await pool.fetchrow(query, *args)

    app.state.pg_pool = SimpleNamespace(fetchrow=fetchrow, execute=AsyncMock())
    app.state.fabric_services = SimpleNamespace(store=store, auth=FabricAuth(store, settings))
    app.state.config = SimpleNamespace(fabric=settings)
    monkeypatch.setattr("interlock.admin.routes.fabric_auth._changed", AsyncMock())
    sid, csrf = await create_session(app.state.redis, 1, "admin", ["source_admin"], 1, 3600)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://localhost"
    ) as client:
        client.cookies.set("admin", sign_cookie({"sid": sid}, "test-key"))
        client.headers["X-CSRF-Token"] = csrf

        async def begin():
            response = await client.post("/api/data-sources/one/fabric/connect")
            assert response.status_code == 303
            return parse_qs(urlsplit(response.headers["location"]).query)["state"][0]

        async def finish(state):
            return await client.get(
                "/api/fabric/oauth/callback", params={"state": state, "code": "PRIVATE_CODE"}
            )

        state = await begin()
        response = await finish(state)
        assert response.status_code == 303
        context = await store.get_context("one")
        assert context.status == "connected" and context.account_id == "uid.tenant"
        assert (await finish(state)).status_code == 400
        state = await begin()
        other_sid, _ = await create_session(app.state.redis, 1, "admin", ["source_admin"], 1, 3600)
        client.cookies.set("admin", sign_cookie({"sid": other_sid}, "test-key"))
        assert (await finish(state)).status_code == 400
        client.cookies.set("admin", sign_cookie({"sid": sid}, "test-key"))
        # The real store atomically expires pending flows before exchanging codes.
        state = await begin()
        await pool.execute(
            "UPDATE fabric_pending_oauth SET expires_at=$1 WHERE state_hash=$2",
            datetime.now(UTC) - timedelta(seconds=1),
            hashlib.sha256(state.encode()).hexdigest(),
        )
        assert (await finish(state)).status_code == 400
        state = await begin()
        await pool.execute(
            "UPDATE data_sources SET connection_config=jsonb_set(connection_config,'{database}', '\"changed\"') WHERE source_id='one'"
        )
        assert (await finish(state)).status_code == 400
        # Pending handles never let a source recreated under the same ID inherit credentials.
        assert (await store.get_context("one")).generation > context.generation
        # Rotation with an unchanged secret reference must revoke the old epoch
        # and clear persisted MSAL application tokens before next acquisition.
        import json

        spn_config = dict(
            host="example.datawarehouse.fabric.microsoft.com",
            database="changed",
            tenant_id="tenant",
            client_id="client",
            endpoint_type="warehouse",
            auth_mode="spn",
            client_secret_ref="env://FABRIC_CLIENT_SECRET",
        )
        await pool.execute(
            "UPDATE data_sources SET connection_config=$1::jsonb WHERE source_id='one'",
            json.dumps(spn_config),
        )
        config = (await store.current_source("one")).config
        token = await app.state.fabric_services.auth.acquire("one", config)
        assert (
            await pool.fetchval(
                "SELECT encrypted_cache IS NOT NULL FROM fabric_credentials WHERE source_id='one'"
            )
        ) is True
        response = await client.post("/api/data-sources/one/fabric/rotate")
        assert response.status_code == 200
        rotated = await store.get_context("one")
        assert rotated.generation == token.context.generation + 1
        assert (
            await pool.fetchval(
                "SELECT encrypted_cache FROM fabric_credentials WHERE source_id='one'"
            )
            is None
        )
        renewed = await app.state.fabric_services.auth.acquire("one", config)
        assert renewed.context.generation == rotated.generation
        # Recovery status distrusts unreadable encrypted cache; metadata-only
        # disconnect still revokes it without needing the old decryption key.
        await pool.execute(
            "UPDATE fabric_credentials SET encrypted_cache=$1 WHERE source_id='one'",
            b"UNREADABLE-CIPHERTEXT",
        )
        status = await client.get("/api/data-sources/one/fabric/auth-status")
        assert status.json()["status"] == "reconnect_required"
        assert "CIPHERTEXT" not in status.text and "FABRIC_CLIENT_SECRET" not in status.text
        assert (await client.post("/api/data-sources/one/fabric/disconnect")).status_code == 200
        assert (await store.get_context("one")).status == "disconnected"
