"""Credential lifecycle against the disposable control PostgreSQL, never Fabric."""

from __future__ import annotations

import asyncio
import json
import uuid
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import asyncpg
import pytest
import pytest_asyncio
from cryptography.fernet import Fernet

from interlock.connections.fabric.credentials import (
    FabricCredentialError,
    FabricCredentialStore,
    FabricKeyring,
)
from interlock.db.migrations import apply_migrations

pytestmark = [pytest.mark.integration, pytest.mark.asyncio(loop_scope="session")]
BASE = dict(
    host="example.datawarehouse.fabric.microsoft.com",
    database="sales",
    tenant_id="tenant",
    client_id="client",
    endpoint_type="warehouse",
    auth_mode="oauth",
)


@pytest_asyncio.fixture(loop_scope="session")
async def store_db(pg_pool, monkeypatch):
    schema = "fabric_test_" + uuid.uuid4().hex
    async with pg_pool.acquire() as conn:
        await conn.execute("CREATE EXTENSION IF NOT EXISTS ltree WITH SCHEMA public")
        await conn.execute("CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public")
        await conn.execute(f'CREATE SCHEMA "{schema}"')
    import os

    pool = await asyncpg.create_pool(
        host=os.environ["TEST_PG_HOST"],
        port=int(os.environ["TEST_PG_PORT"]),
        user=os.environ["TEST_PG_USER"],
        password=os.environ["TEST_PG_PASSWORD"],
        database=os.environ["TEST_PG_DATABASE"],
        min_size=1,
        max_size=5,
        server_settings={"search_path": f"{schema},public"},
    )
    try:
        async with pool.acquire() as conn:
            migrations = Path(__file__).resolve().parents[2] / "migrations"
            first = await apply_migrations(conn, migrations, baseline_existing=False)
            second = await apply_migrations(conn, migrations, baseline_existing=False)
            assert first.applied[-1] == "021_fabric_source_lifecycle.sql"
            assert second.applied == [] and len(second.skipped) == 21
        await pool.execute(
            "INSERT INTO data_sources (source_id,name,source_type,connection_config) VALUES ('one','Fabric','database',$1)",
            json.dumps(BASE),
        )
        monkeypatch.setenv("FABRIC_STORE_KEY", Fernet.generate_key().decode())
        keys = FabricKeyring("v1", {"v1": "env://FABRIC_STORE_KEY"})
        yield FabricCredentialStore(pool, keys), pool, keys
    finally:
        await pool.close()
        async with pg_pool.acquire() as conn:
            await conn.execute(f'DROP SCHEMA "{schema}" CASCADE')


async def pending(store, **kwargs):
    context = await store.get_context("one")
    return await store.save_pending(
        "one",
        "session",
        {"state": "msal-state", "token": "secret-token"},
        datetime.now(UTC) + timedelta(seconds=599),
        kwargs.get("generation", context.generation),
    )


async def test_cache_is_encrypted_source_delete_cascades_and_handles_cannot_escape_lock(store_db):
    store, pool, _ = store_db
    async with store.locked("one") as locked:
        await store.save_cache(locked, '{"refresh_token":"private-refresh"}')
        assert "private-refresh" not in repr(locked)
    row = await pool.fetchrow("SELECT * FROM fabric_credentials WHERE source_id='one'")
    assert b"private-refresh" not in bytes(row["encrypted_cache"])
    async with store.locked("one") as current:
        assert current.decrypted_cache == '{"refresh_token":"private-refresh"}'
        assert current.revision == 1
    with pytest.raises(FabricCredentialError):
        await store.save_cache(locked, "stale")
    await pending(store)
    await pool.execute("DELETE FROM data_sources WHERE source_id='one'")
    assert await pool.fetchval("SELECT count(*) FROM fabric_credentials") == 0
    assert await pool.fetchval("SELECT count(*) FROM fabric_pending_oauth") == 0


async def test_pending_is_encrypted_session_bound_single_use_and_returns_bound_context(store_db):
    store, pool, _ = store_db
    state = await pending(store)
    row = await pool.fetchrow("SELECT * FROM fabric_pending_oauth")
    assert row["state_hash"] != state and row["session_hash"] != "session"
    assert b"secret-token" not in bytes(row["encrypted_flow"])
    with pytest.raises(FabricCredentialError):
        await store.consume_pending(state, "other-session")
    flow = await store.consume_pending(state, "session")
    assert flow == {
        "state": "msal-state",
        "token": "secret-token",
        "_fabric_source_id": "one",
        "_fabric_generation": 1,
        "_fabric_incarnation": str(
            await pool.fetchval("SELECT incarnation FROM fabric_credentials WHERE source_id='one'")
        ),
    }
    with pytest.raises(FabricCredentialError):
        await store.consume_pending(state, "session")


@pytest.mark.parametrize("seconds", [-1, 601])
async def test_pending_rejects_expired_or_excessive_lifetime(store_db, seconds):
    store, _, _ = store_db
    await store.get_context("one")
    with pytest.raises(FabricCredentialError):
        await store.save_pending(
            "one", "session", {}, datetime.now(UTC) + timedelta(seconds=seconds), 1
        )


async def test_expired_state_is_consumed_without_returning_flow(store_db):
    store, pool, _ = store_db
    state = await pending(store)
    await pool.execute("UPDATE fabric_pending_oauth SET expires_at=NOW()-INTERVAL '1 second'")
    with pytest.raises(FabricCredentialError):
        await store.consume_pending(state, "session")
    assert await pool.fetchval("SELECT count(*) FROM fabric_pending_oauth") == 0


async def test_config_change_revokes_pending_and_cached_identity(store_db):
    store, pool, _ = store_db
    async with store.locked("one") as locked:
        await store.save_identity(locked, account_id="saved-account")
        await store.save_cache(locked, "token-cache")
    state = await pending(store)
    await pool.execute(
        "UPDATE data_sources SET connection_config=$1 WHERE source_id='one'",
        json.dumps(BASE | {"tenant_id": "other-tenant"}),
    )
    context = await store.get_context("one")
    assert (context.generation, context.tenant_id, context.status, context.account_id) == (
        3,
        "other-tenant",
        "reconnect_required",
        None,
    )
    async with store.locked("one") as locked:
        assert locked.decrypted_cache == ""
    with pytest.raises(FabricCredentialError):
        await store.consume_pending(state, "session")
    with pytest.raises(FabricCredentialError):
        await pending(store, generation=2)


async def test_invalidation_changes_generation_and_can_keep_encrypted_cache(store_db):
    store, _, _ = store_db
    async with store.locked("one") as locked:
        await store.save_cache(locked, "old-cache")
    context = await store.invalidate("one", reason="refresh_failed", delete_cache=False)
    assert (context.generation, context.status) == (2, "reconnect_required")
    async with store.locked("one") as locked:
        assert locked.decrypted_cache == "old-cache"
    disconnected = await store.invalidate("one", reason="disconnect", delete_cache=True)
    assert (disconnected.generation, disconnected.status) == (3, "disconnected")
    async with store.locked("one") as locked:
        assert locked.decrypted_cache == ""


async def test_concurrent_refresh_serializes_and_preserves_both_updates(store_db):
    store, _, _ = store_db
    entered = asyncio.Event()
    release = asyncio.Event()

    async def first():
        async with store.locked("one") as locked:
            entered.set()
            await release.wait()
            await store.save_cache(locked, "first-cache")

    async def second():
        async with store.locked("one") as locked:
            assert locked.decrypted_cache == "first-cache"
            assert locked.revision == 1
            await store.save_cache(locked, "second-cache")

    task1 = asyncio.create_task(first())
    await entered.wait()
    task2 = asyncio.create_task(second())
    await asyncio.sleep(0.03)
    assert not task2.done()
    release.set()
    await asyncio.gather(task1, task2)
    async with store.locked("one") as locked:
        assert locked.decrypted_cache == "second-cache" and locked.revision == 2


async def test_cancelled_refresh_rolls_back_and_releases_transaction(store_db):
    store, _, _ = store_db
    entered = asyncio.Event()

    async def refresh():
        async with store.locked("one") as locked:
            await store.save_cache(locked, "never-commit")
            entered.set()
            await asyncio.Event().wait()

    task = asyncio.create_task(refresh())
    await entered.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    async with store.locked("one") as locked:
        assert locked.decrypted_cache == "" and locked.revision == 0
    assert (await store.invalidate("one", reason="disconnect", delete_cache=True)).generation == 2


async def test_lock_deadline_rolls_back_and_allows_next_refresh(store_db):
    _, pool, keys = store_db
    store = FabricCredentialStore(pool, keys, lock_timeout_seconds=0.05)
    with pytest.raises(TimeoutError):
        async with store.locked("one") as locked:
            await store.save_cache(locked, "never-commit")
            await asyncio.Event().wait()
    async with store.locked("one") as locked:
        assert locked.decrypted_cache == ""


@pytest.mark.parametrize("field", ["revision", "generation"])
async def test_stale_revision_or_generation_cannot_overwrite_cache(store_db, field):
    store, _, _ = store_db
    async with store.locked("one") as locked:
        if field == "revision":
            locked.revision += 1
        else:
            locked.context = replace(locked.context, generation=99)
        with pytest.raises(FabricCredentialError):
            await store.save_cache(locked, "stale")


async def test_wrong_key_cannot_read_stored_cache(store_db, monkeypatch):
    store, pool, _ = store_db
    async with store.locked("one") as locked:
        await store.save_cache(locked, "private-refresh")
    monkeypatch.setenv("OTHER_FABRIC_KEY", Fernet.generate_key().decode())
    wrong = FabricCredentialStore(pool, FabricKeyring("v1", {"v1": "env://OTHER_FABRIC_KEY"}))
    with pytest.raises(FabricCredentialError):
        async with wrong.locked("one"):
            pytest.fail("wrong encryption key read a cache")


async def test_concurrent_callbacks_consume_state_exactly_once(store_db):
    store, _, _ = store_db
    state = await pending(store)
    results = await asyncio.gather(
        store.consume_pending(state, "session"),
        store.consume_pending(state, "session"),
        return_exceptions=True,
    )
    assert sum(isinstance(result, dict) for result in results) == 1
    assert sum(isinstance(result, FabricCredentialError) for result in results) == 1


async def test_state_with_obsolete_generation_is_deleted(store_db):
    store, pool, _ = store_db
    state = await pending(store)
    await pool.execute(
        "UPDATE fabric_credentials SET generation=generation+1 WHERE source_id='one'"
    )
    with pytest.raises(FabricCredentialError):
        await store.consume_pending(state, "session")
    assert await pool.fetchval("SELECT count(*) FROM fabric_pending_oauth") == 0


@pytest.mark.parametrize(
    "reserved", ["_fabric_source_id", "_fabric_generation", "_fabric_incarnation"]
)
async def test_reserved_flow_metadata_cannot_override_source_binding(store_db, reserved):
    store, _, _ = store_db
    await store.get_context("one")
    with pytest.raises(FabricCredentialError):
        await store.save_pending(
            "one",
            "session",
            {reserved: "another-source"},
            datetime.now(UTC) + timedelta(seconds=599),
            1,
        )


async def test_rotation_reads_database_cache_then_reencrypts_with_new_version(
    store_db, monkeypatch
):
    store, pool, _ = store_db
    async with store.locked("one") as locked:
        await store.save_cache(locked, "old-token")
    monkeypatch.setenv("FABRIC_STORE_KEY_NEW", Fernet.generate_key().decode())
    keys = FabricKeyring("v2", {"v1": "env://FABRIC_STORE_KEY", "v2": "env://FABRIC_STORE_KEY_NEW"})
    rotated = FabricCredentialStore(pool, keys)
    async with rotated.locked("one") as locked:
        assert locked.decrypted_cache == "old-token"
        await rotated.save_cache(locked, "new-token")
    ciphertext = bytes(
        await pool.fetchval("SELECT encrypted_cache FROM fabric_credentials WHERE source_id='one'")
    )
    assert ciphertext.startswith(b"v2:") and b"new-token" not in ciphertext


@pytest.mark.parametrize("unreadable", ["corrupt_cache", "retired_version", "wrong_key"])
async def test_disconnect_revokes_unreadable_cache_and_pending_flow(
    store_db, monkeypatch, unreadable
):
    store, pool, _ = store_db
    async with store.locked("one") as locked:
        await store.save_identity(locked, account_id="saved-account")
        await store.save_cache(locked, "private-refresh")
        previous_generation = locked.context.generation
        previous_revision = locked.revision
    await pending(store)
    if unreadable == "corrupt_cache":
        await pool.execute(
            "UPDATE fabric_credentials SET encrypted_cache=$1 WHERE source_id='one'",
            b"v1:corrupted-cache",
        )
    else:
        monkeypatch.setenv("FABRIC_REPLACEMENT_KEY", Fernet.generate_key().decode())
        version = "v2" if unreadable == "retired_version" else "v1"
        store = FabricCredentialStore(
            pool, FabricKeyring(version, {version: "env://FABRIC_REPLACEMENT_KEY"})
        )
    with pytest.raises(FabricCredentialError):
        async with store.locked("one"):
            pytest.fail("an unreadable cache became accessible")

    context = await store.invalidate("one", reason="disconnect", delete_cache=True)

    assert context.generation == previous_generation + 1
    assert context.status == "disconnected" and context.account_id is None
    row = await pool.fetchrow("SELECT * FROM fabric_credentials WHERE source_id='one'")
    assert row["revision"] == previous_revision + 1
    assert row["encrypted_cache"] is None and row["account_id"] is None
    assert await pool.fetchval("SELECT count(*) FROM fabric_pending_oauth") == 0
    async with store.locked("one") as locked:
        assert locked.decrypted_cache == ""
