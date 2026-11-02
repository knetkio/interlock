"""Auth uses real encrypted PostgreSQL state; MSAL provider I/O is replaced."""

from __future__ import annotations

import asyncio
import json
import threading
from dataclasses import replace
from urllib.parse import parse_qs, urlsplit

import pytest

from interlock.connections.fabric.auth import FabricAuth, FabricAuthError
from interlock.connections.fabric.config import FabricConfig
from interlock.connections.fabric.credentials import FabricCredentialError, FabricCredentialStore
from tests.integration.test_fabric_credentials_store import BASE
from tests.integration.test_fabric_credentials_store import store_db as _store_db
from tests.unit.test_fabric_auth import connect
from tests.unit.test_fabric_auth import setup_auth as _setup_auth

store_db = _store_db
setup_auth = _setup_auth

pytestmark = [pytest.mark.integration, pytest.mark.asyncio(loop_scope="session")]


async def test_oauth_state_and_cache_are_encrypted_and_survive_service_restart(
    store_db, setup_auth
):
    store, pool, keys = store_db
    _, _, calls, settings = setup_auth
    auth = FabricAuth(store, settings)
    url = await auth.begin_oauth("one", "admin-session")
    state = parse_qs(urlsplit(url).query)["state"][0]
    row = await pool.fetchrow("SELECT * FROM fabric_pending_oauth")
    assert row["state_hash"] != state
    assert b"pkce-private-verifier" not in bytes(row["encrypted_flow"])
    context = await auth.complete_oauth(state, {"state": state, "code": "code"}, "admin-session")
    revision = await pool.fetchval("SELECT revision FROM fabric_credentials")
    ciphertext = await pool.fetchval("SELECT encrypted_cache FROM fabric_credentials")
    assert b"access-private-token" not in bytes(ciphertext)
    assert b"secret_fingerprint" not in bytes(ciphertext)
    restarted = FabricAuth(FabricCredentialStore(pool, keys), settings)
    token = await restarted.acquire("one", FabricConfig(**BASE))
    assert token.context == context and token.access_token == "access-private-token"
    assert len([c for c in calls if c[0] == "network"]) == 1
    assert await pool.fetchval("SELECT revision FROM fabric_credentials") == revision
    with pytest.raises(FabricAuthError):
        await restarted.complete_oauth(state, {"state": state, "code": "code"}, "admin-session")


async def test_locked_config_matches_saved_source_and_stale_gateway_is_denied(store_db, setup_auth):
    store, pool, _ = store_db
    _, _, calls, settings = setup_auth
    async with store.locked("one") as locked:
        assert locked.config == FabricConfig(**BASE)
    await pool.execute(
        "UPDATE data_sources SET connection_config=$1 WHERE source_id='one'",
        json.dumps(BASE | {"database": "new-database"}),
    )
    with pytest.raises(FabricAuthError) as error:
        await FabricAuth(store, settings).acquire("one", FabricConfig(**BASE))
    assert error.value.code == "configuration_changed"
    assert not calls


async def test_callback_rechecks_generation_after_one_time_state_consumption(
    store_db, setup_auth, monkeypatch
):
    store, pool, _ = store_db
    _, _, calls, settings = setup_auth
    auth = FabricAuth(store, settings)
    url = await auth.begin_oauth("one", "admin-session")
    state = parse_qs(urlsplit(url).query)["state"][0]
    original = store.consume_pending

    async def consume_then_edit(*args):
        flow = await original(*args)
        await pool.execute(
            "UPDATE data_sources SET connection_config=$1 WHERE source_id='one'",
            json.dumps(BASE | {"database": "new-database"}),
        )
        return flow

    monkeypatch.setattr(store, "consume_pending", consume_then_edit)
    with pytest.raises(FabricAuthError) as error:
        await auth.complete_oauth(state, {"state": state, "code": "code"}, "admin-session")
    assert error.value.code == "reconnect_required"
    assert not [c for c in calls if c[0] == "complete"]
    assert not await pool.fetchval("SELECT count(*) FROM fabric_pending_oauth")


async def test_two_services_serialize_refresh_and_reuse_latest_persisted_cache(
    store_db, setup_auth
):
    store, pool, keys = store_db
    _, behavior, calls, settings = setup_auth
    auth = FabricAuth(store, settings)
    await connect(auth, store)
    async with store.locked("one") as locked:
        envelope = json.loads(locked.decrypted_cache)
        data = json.loads(envelope["msal"])
        data.pop("AccessToken")
        envelope["msal"] = json.dumps(data)
        await store.save_cache(locked, json.dumps(envelope))
    behavior.entered, behavior.release = threading.Event(), threading.Event()
    behavior.result = {"access_token": "latest-access-token", "expires_in": 3600}
    first = asyncio.create_task(auth.acquire("one", FabricConfig(**BASE)))
    assert await asyncio.to_thread(behavior.entered.wait, 2)
    other = FabricAuth(FabricCredentialStore(pool, keys), settings)
    second = asyncio.create_task(other.acquire("one", FabricConfig(**BASE)))
    await asyncio.sleep(0.03)
    assert not second.done()
    behavior.release.set()
    tokens = await asyncio.gather(first, second)
    assert [token.access_token for token in tokens] == [
        "latest-access-token",
        "latest-access-token",
    ]
    assert len([c for c in calls if c[0] == "network"]) == 2  # Initial connect and one refresh.
    async with store.locked("one") as locked:
        assert "latest-access-token" in locked.decrypted_cache


async def test_lost_consent_transition_commits_before_authentication_error(store_db, setup_auth):
    store, pool, _ = store_db
    _, behavior, _, settings = setup_auth
    auth = FabricAuth(store, settings)
    await connect(auth, store)
    async with store.locked("one") as locked:
        envelope = json.loads(locked.decrypted_cache)
        data = json.loads(envelope["msal"])
        data.pop("AccessToken")
        envelope["msal"] = json.dumps(data)
        await store.save_cache(locked, json.dumps(envelope))
    behavior.result = {"error": "invalid_grant", "error_description": "private-refresh-token"}
    with pytest.raises(FabricAuthError) as error:
        await auth.acquire("one", FabricConfig(**BASE))
    assert error.value.code == "reconnect_required"
    row = await pool.fetchrow("SELECT * FROM fabric_credentials")
    assert row["status"] == "reconnect_required" and row["generation"] == 3
    assert b"private-refresh-token" not in bytes(row["encrypted_cache"])


async def test_spn_in_place_secret_rotation_revokes_and_persists_new_generation(
    store_db, setup_auth, monkeypatch
):
    store, pool, _ = store_db
    _, behavior, _, settings = setup_auth
    config = FabricConfig(
        **(BASE | {"auth_mode": "spn", "client_secret_ref": "env://FABRIC_CLIENT_SECRET"})
    )
    await pool.execute(
        "UPDATE data_sources SET connection_config=$1 WHERE source_id='one'",
        config.model_dump_json(),
    )
    auth = FabricAuth(store, settings)
    first = await auth.acquire("one", config)
    monkeypatch.setenv("FABRIC_CLIENT_SECRET", "rotated-private-secret")
    behavior.result = {"access_token": "rotated-token", "expires_in": 3600}
    second = await auth.acquire("one", config)
    assert second.context.generation == first.context.generation + 1
    assert second.context.status == "connected" and second.access_token == "rotated-token"
    ciphertext = await pool.fetchval("SELECT encrypted_cache FROM fabric_credentials")
    assert b"rotated-token" not in bytes(ciphertext)


async def test_invalidate_locked_rejects_stale_revision_without_revoking_current(store_db):
    store, _, _ = store_db
    before = await store.get_context("one")
    async with store.locked("one") as locked:
        locked.context = replace(locked.context, generation=99)
        with pytest.raises(FabricCredentialError):
            await store.invalidate_locked(locked, reason="consent_lost", delete_cache=True)
    assert await store.get_context("one") == before


@pytest.mark.parametrize("state", ["short", "x" * 129, "!" * 43])
async def test_caller_supplied_state_requires_long_opaque_urlsafe_handle(store_db, state):
    from datetime import UTC, datetime, timedelta

    store, _, _ = store_db
    with pytest.raises(FabricCredentialError):
        await store.save_pending(
            "one", "session", {}, datetime.now(UTC) + timedelta(seconds=599), 1, state=state
        )


async def test_invalidation_queued_during_refresh_prevents_delivery_of_old_generation(
    store_db, setup_auth
):
    store, pool, keys = store_db
    _, behavior, _, settings = setup_auth
    config = FabricConfig(
        **(BASE | {"auth_mode": "spn", "client_secret_ref": "env://FABRIC_CLIENT_SECRET"})
    )
    await pool.execute(
        "UPDATE data_sources SET connection_config=$1 WHERE source_id='one'",
        config.model_dump_json(),
    )
    behavior.entered, behavior.release = threading.Event(), threading.Event()
    refresh = asyncio.create_task(FabricAuth(store, settings).acquire("one", config))
    assert await asyncio.to_thread(behavior.entered.wait, 2)
    other_store = FabricCredentialStore(pool, keys)
    revoke = asyncio.create_task(
        other_store.invalidate("one", reason="disconnect", delete_cache=True)
    )
    await asyncio.sleep(0.03)
    assert not revoke.done()
    behavior.release.set()
    await revoke
    with pytest.raises(FabricAuthError) as error:
        await refresh
    assert error.value.code == "reconnect_required"
    row = await pool.fetchrow("SELECT * FROM fabric_credentials")
    assert row["encrypted_cache"] is None and row["status"] == "disconnected"


async def test_unreadable_ciphertext_is_sanitized_and_metadata_disconnect_can_recover(
    store_db, setup_auth
):
    store, pool, _ = store_db
    _, _, _, settings = setup_auth
    await store.get_context("one")
    await pool.execute(
        "UPDATE fabric_credentials SET status='connected', encrypted_cache=$1 WHERE source_id='one'",
        b"v1:private-invalid-ciphertext",
    )
    with pytest.raises(FabricAuthError) as error:
        await FabricAuth(store, settings).acquire("one", FabricConfig(**BASE))
    assert error.value.code == "reconnect_required"
    assert "ciphertext" not in str(error.value) and "private" not in repr(error.value)
    assert error.value.__suppress_context__
    context = await store.invalidate("one", reason="disconnect", delete_cache=True)
    assert context.status == "disconnected"
