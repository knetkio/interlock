"""Opt-in native probes using the explicit saved-source Fabric live manifest.

Requires FABRIC_SQL_INTEGRATION=1 plus FABRIC_LIVE_MANIFEST and ordinary explicit
control DB/key settings. Never accepts a pasted access token or a global login.
Writes require FABRIC_SQL_WRITE_SOURCE_ID matching the designated source AND
FABRIC_SQL_DISPOSABLE_WRITE_AUTHORIZED=1: permission to create/drop a uniquely
named dbo.interlock_transport_test_* table in that disposable SQL Database.
Cancellation server-observation additionally requires explicit authorization to
query sys.dm_exec_requests (FABRIC_SQL_OBSERVE_SESSION_AUTHORIZED=1). Without
it, report cancellation acceptance pending; do not silently require DBA grants.
"""

from __future__ import annotations

import asyncio
import os
import struct
import time
import uuid
from types import SimpleNamespace

import pytest

from interlock.connections.sqlserver import SqlServerResultLimitError, SqlServerTransport
from interlock.security.egress import validate_host_egress
from tests.integration.test_fabric_live import native_cell as native_cell

pytestmark = [
    pytest.mark.live,
    pytest.mark.skipif(
        os.environ.get("FABRIC_SQL_INTEGRATION") != "1",
        reason="UNVERIFIED: FABRIC_SQL_INTEGRATION != 1",
    ),
    pytest.mark.parametrize(
        "native_cell",
        [("sql_database", "oauth"), ("sql_database", "spn")],
        indirect=True,
        ids=["sql-database-oauth", "sql-database-spn"],
    ),
]


@pytest.fixture
async def endpoint(native_cell):
    cell, config, services, _ = native_cell
    source = await services.prepare_source(cell.source_id, config)
    driver = pytest.importorskip("pyodbc")
    return cell, config, source.token, driver


@pytest.fixture
async def transport():
    instance = SqlServerTransport()
    yield instance
    await instance.close()


async def test_native_output_limit_rolls_back_and_valid_output_commits(endpoint, transport):
    cell, config, token, driver = endpoint
    if (
        os.environ.get("FABRIC_SQL_DISPOSABLE_WRITE_AUTHORIZED") != "1"
        or os.environ.get("FABRIC_SQL_WRITE_SOURCE_ID") != cell.source_id
    ):
        pytest.skip("PENDING: explicit disposable-object write authorization absent")
    # Only fixture setup/teardown use direct DDL; runtime transport remains SQL-agnostic.
    table = "[dbo].[interlock_transport_test_" + uuid.uuid4().hex + "]"
    raw_token = token.access_token.encode("utf-16-le")
    driver.pooling = False
    validate_host_egress(config.host, port=config.port, allow_private=config.allow_private_egress)
    setup = driver.connect(
        "DRIVER={ODBC Driver 18 for SQL Server};"
        f"SERVER={{tcp:{config.host},{config.port}}};DATABASE={{{config.database}}};"
        "Encrypt=yes;TrustServerCertificate=no;",
        attrs_before={1256: struct.pack("<I", len(raw_token)) + raw_token},
        timeout=config.connect_timeout_seconds,
        autocommit=True,
    )
    cursor = setup.cursor()
    try:
        cursor.execute(f"CREATE TABLE {table} (id INT, value VARCHAR(2000))")
        limited = config.model_copy(update={"max_rows": 1})
        with pytest.raises(SqlServerResultLimitError):
            await transport.execute(
                limited,
                token,
                f"INSERT INTO {table} (id, value) OUTPUT inserted.id VALUES (?, ?), (?, ?)",
                (1, "one", 2, "two"),
                write=True,
            )
        result = await transport.execute(config, token, f"SELECT id FROM {table}", (), write=False)
        assert result["rows"] == []
        result = await transport.execute(
            config,
            token,
            f"INSERT INTO {table} (id, value) OUTPUT inserted.id VALUES (?, ?)",
            (3, "three"),
            write=True,
        )
        assert result["rows"] == [{"id": 3}]
        result = await transport.execute(config, token, f"SELECT id FROM {table}", (), write=False)
        assert result["rows"] == [{"id": 3}]
    finally:
        try:
            cursor.execute(f"DROP TABLE {table}")
        finally:
            try:
                cursor.close()
            finally:
                setup.close()


class _TrackedHandle:
    """Test-only observer: record successful native close, never infer it from return latency."""

    def __init__(self, handle):
        object.__setattr__(self, "handle", handle)
        object.__setattr__(self, "closed", False)
        object.__setattr__(self, "cursors", [])

    def __getattr__(self, name):
        return getattr(self.handle, name)

    def __setattr__(self, name, value):
        setattr(self.handle, name, value)

    def cursor(self):
        wrapped = _TrackedHandle(self.handle.cursor())
        self.cursors.append(wrapped)
        return wrapped

    def close(self):
        self.handle.close()
        object.__setattr__(self, "closed", True)


async def test_native_cancellation_closes_handles_worker_and_server_request(endpoint, transport):
    _, config, token, driver = endpoint
    if os.environ.get("FABRIC_SQL_OBSERVE_SESSION_AUTHORIZED") != "1":
        pytest.skip("PENDING: server request observation not explicitly authorized")
    native_connect = driver.connect
    handles = []
    sessions = []

    def tracked_connect(*args, **kwargs):
        connection = native_connect(*args, **kwargs)
        cursor = connection.cursor()
        try:
            cursor.execute("SELECT @@SPID")
            sessions.append(int(cursor.fetchone()[0]))
        finally:
            cursor.close()
        connection.rollback()
        wrapped = _TrackedHandle(connection)
        handles.append(wrapped)
        return wrapped

    transport._driver = SimpleNamespace(connect=tracked_connect)
    task = asyncio.create_task(
        transport.execute(
            config, token, "WAITFOR DELAY '00:00:20'; SELECT 1 AS value", (), write=False
        )
    )
    try:
        deadline = time.monotonic() + config.connect_timeout_seconds + 2
        while not sessions and not task.done() and time.monotonic() < deadline:
            await asyncio.sleep(0.05)
        assert sessions and not task.done(), "Native statement never became observable"
        await asyncio.sleep(0.5)
        observed = await transport.execute(
            config,
            token,
            "SELECT session_id FROM sys.dm_exec_requests WHERE session_id = ?",
            (sessions[0],),
            write=False,
        )
        assert observed["rows"] == [
            {"session_id": sessions[0]}
        ], "Observer cannot establish the original request is active; cleanup unverified"
        started = time.monotonic()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert time.monotonic() - started < 7
        # A spare worker cannot make this pass: the original future must finish,
        # native close calls must return successfully, and its server request must disappear.
        deadline = time.monotonic() + 5
        while transport._running and time.monotonic() < deadline:
            await asyncio.sleep(0.05)
        assert not transport._running, "Original native worker still running"
        assert all(h.closed and all(c.closed for c in h.cursors) for h in handles)
        result = await transport.execute(
            config,
            token,
            "SELECT session_id FROM sys.dm_exec_requests WHERE session_id = ?",
            (sessions[0],),
            write=False,
        )
        assert result["rows"] == [], "Cancelled server operation remains active"
    finally:
        if not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
