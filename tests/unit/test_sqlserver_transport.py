"""Transport behavior at the external ODBC boundary; no live provider access."""

from __future__ import annotations

import asyncio
import datetime as dt
import ipaddress
import json
import struct
import sys
import threading
import time
import uuid
from decimal import Decimal
from types import SimpleNamespace

import pytest

from interlock.connections.fabric.config import FabricConfig
from interlock.connections.sqlserver import (
    SqlServerBusyError,
    SqlServerResultLimitError,
    SqlServerTransport,
    SqlServerTransportError,
)


class Cursor:
    def __init__(self, driver):
        self.driver = driver
        self.description = [(c,) for c in driver.columns] if driver.columns else None
        self.rowcount = driver.rowcount
        self.rows = iter(driver.rows)
        self.closed = False
        self.cancelled = threading.Event()
        self.submitted = threading.Event()
        self.fetch_sizes = []
        self.extra = driver.extra

    def execute(self, sql, parameters):
        self.driver.submissions.append((sql, parameters))
        self.submitted.set()
        if self.driver.block:
            self.driver.started.set()
            self.driver.release.wait(10)
        if self.cancelled.is_set():
            raise RuntimeError("cancelled secret driver diagnostic")
        if self.driver.fail:
            raise RuntimeError("SECRET TOKEN sensitive SQL")
        return self

    def fetchmany(self, size):
        self.fetch_sizes.append(size)
        result = []
        for _ in range(size):
            try:
                result.append(next(self.rows))
            except StopIteration:
                break
        return result

    def nextset(self):
        value, self.extra = self.extra, False
        return value

    def cancel(self):
        self.cancelled.set()
        if not self.driver.ignore_cancel:
            self.driver.release.set()

    def close(self):
        self.closed = True


class Connection:
    def __init__(self, driver):
        self.driver = driver
        self.handle = Cursor(driver)
        self.closed = False
        self.committed = False
        self.rolled_back = False
        self.rollback_count = 0

    def cursor(self):
        return self.handle

    def commit(self):
        self.committed = True
        self.driver.committed.extend(self.driver.submissions[-1:])

    def rollback(self):
        self.rolled_back = True
        self.rollback_count += 1

    def close(self):
        self.closed = True


class Driver:
    pooling = True

    def __init__(
        self,
        *,
        columns=("value",),
        rows=((1,),),
        rowcount=-1,
        extra=False,
        block=False,
        fail=False,
        ignore_cancel=False,
    ):
        self.columns, self.rows, self.rowcount = columns, rows, rowcount
        self.extra, self.block, self.fail = extra, block, fail
        self.ignore_cancel = ignore_cancel
        self.connections, self.submissions, self.committed = [], [], []
        self.started, self.release = threading.Event(), threading.Event()

    def connect(self, connection_string, **kwargs):
        # A permissive fake would miss token/TLS/pooling regressions.
        assert self.pooling is False
        assert "DRIVER={ODBC Driver 18 for SQL Server};" in connection_string
        assert "Encrypt=yes;" in connection_string
        assert "TrustServerCertificate=no;" in connection_string
        for forbidden in ("UID=", "PWD=", "Authentication=", "DSN="):
            assert forbidden.lower() not in connection_string.lower()
        assert kwargs["autocommit"] is False
        packed = kwargs["attrs_before"][1256]
        assert packed == struct.pack("<I", 10) + b"t\x00o\x00k\x00e\x00n\x00"
        assert kwargs["timeout"] == 15 or kwargs["timeout"] == 1
        self.connection_string = connection_string
        connection = Connection(self)
        self.connections.append(connection)
        return connection


@pytest.fixture
def install(monkeypatch):
    monkeypatch.setattr(
        "interlock.security.egress._resolve_host_addresses",
        lambda host, port: {ipaddress.ip_address("20.1.2.3")},
    )

    def bind(**kwargs):
        driver = Driver(**kwargs)
        monkeypatch.setitem(sys.modules, "pyodbc", driver)
        return driver

    return bind


def config(**kwargs):
    return FabricConfig.from_mapping(
        dict(
            host="example.database.fabric.microsoft.com",
            database="A] Data",
            tenant_id="tenant",
            client_id="client",
            endpoint_type="warehouse",
            auth_mode="oauth",
            **kwargs,
        )
    )


def token(expires_at=None):
    return SimpleNamespace(access_token="token", expires_at=expires_at or time.time() + 10000)


async def eventually(predicate):
    async with asyncio.timeout(2):
        while not predicate():
            await asyncio.sleep(0.002)


async def test_fixed_secure_token_connection_and_bound_values(install):
    driver = install()
    transport = SqlServerTransport()
    values = ("'; DROP TABLE x", None, Decimal("1.20"))
    result = await transport.execute(config(), token(), "SELECT ?", values, write=False)
    assert result == {
        "rows": [{"value": 1}],
        "columns": ["value"],
        "row_count": 1,
        "permission_request": None,
    }
    assert driver.submissions == [("SELECT ?", values)]
    assert "DATABASE={A] Data};" in driver.connection_string
    connection = driver.connections[0]
    assert connection.timeout == 30
    assert connection.handle.closed and connection.closed and connection.rolled_back
    assert not driver.committed
    await transport.close()


@pytest.mark.parametrize("field", ["driver", "dsn", "UID", "PWD", "Authentication"])
async def test_config_cannot_override_driver_or_authentication(install, field):
    driver = install()
    with pytest.raises(ValueError):
        config(**{field: "attacker"})
    assert not driver.connections


async def test_serialized_types_are_exact_and_returned_json_fits_budget(install):
    values = (
        Decimal("123456789.00100"),
        dt.date(2026, 1, 2),
        dt.time(3, 4, 5),
        dt.datetime(2026, 1, 2, 3, 4, 5),
        uuid.UUID(int=1),
        b"\x00\xff",
        None,
    )
    install(columns=("d", "date", "time", "stamp", "id", "binary", "nil"), rows=(values,))
    transport = SqlServerTransport()
    result = await transport.execute(config(), token(), "SELECT types", (), write=False)
    assert result["rows"] == [
        dict(
            d="123456789.00100",
            date="2026-01-02",
            time="03:04:05",
            stamp="2026-01-02T03:04:05",
            id="00000000-0000-0000-0000-000000000001",
            binary="AP8=",
            nil=None,
        )
    ]
    assert len(json.dumps(result).encode()) < 1024
    await transport.close()


@pytest.mark.parametrize("columns", [("A", "A"), ("A", "a")])
async def test_duplicate_columns_rejected_without_committing_output(install, columns):
    driver = install(columns=columns, rows=((1, 2),))
    transport = SqlServerTransport()
    with pytest.raises(SqlServerTransportError, match="[Dd]uplicate"):
        await transport.execute(config(), token(), "UPDATE x OUTPUT inserted.*", (), write=True)
    assert not driver.committed
    assert driver.connections[0].rolled_back and driver.connections[0].closed
    await transport.close()


@pytest.mark.parametrize("write", [False, True])
@pytest.mark.parametrize(
    "rows,limits",
    [
        ([(i,) for i in range(1001)], {}),
        ([("x" * (8 * 1024 * 1024 + 1),)], {}),
        ([("\x00" * 200,)], {"max_bytes": 1024}),
        ([("é" * 600,)], {"max_bytes": 1024}),
        ([(b"x" * 800,)], {"max_bytes": 1024}),
    ],
)
async def test_limits_cover_returned_encoding_and_output_rolls_back(install, write, rows, limits):
    driver = install(rows=rows)
    transport = SqlServerTransport()
    with pytest.raises(SqlServerResultLimitError):
        await transport.execute(
            config(**limits),
            token(),
            "UPDATE x OUTPUT value" if write else "SELECT value",
            (),
            write=write,
        )
    connection = driver.connections[0]
    assert connection.closed and connection.handle.closed and connection.rolled_back
    assert not driver.committed
    assert max(connection.handle.fetch_sizes) <= 128
    await transport.close()


async def test_json_envelope_overhead_counts_toward_limit(install):
    driver = install(rows=(("x" * 950,),))
    transport = SqlServerTransport()
    with pytest.raises(SqlServerResultLimitError):
        await transport.execute(config(max_bytes=1024), token(), "SELECT value", (), write=False)
    assert driver.connections[0].closed
    await transport.close()


@pytest.mark.parametrize("write", [False, True])
async def test_extra_result_set_is_not_silently_discarded(install, write):
    driver = install(extra=True)
    transport = SqlServerTransport()
    with pytest.raises(SqlServerTransportError, match="result set"):
        await transport.execute(config(), token(), "query", (), write=write)
    assert driver.connections[0].rolled_back and not driver.committed
    await transport.close()


@pytest.mark.parametrize("rowcount,want", [(-1, None), (0, 0), (2, 2)])
async def test_write_without_output_commits_and_preserves_unknown_count(install, rowcount, want):
    driver = install(columns=(), rowcount=rowcount)
    transport = SqlServerTransport()
    result = await transport.execute(config(), token(), "UPDATE x SET y=?", (1,), write=True)
    assert result == dict(rows=[], columns=[], row_count=want, permission_request=None)
    assert driver.committed == [("UPDATE x SET y=?", (1,))]
    assert driver.connections[0].closed
    await transport.close()


async def test_valid_output_consumed_before_write_commits(install):
    driver = install(rows=((7,),))
    transport = SqlServerTransport()
    result = await transport.execute(config(), token(), "UPDATE x OUTPUT value", (), write=True)
    assert result["rows"] == [{"value": 7}] and driver.committed
    assert driver.connections[0].handle.fetch_sizes
    await transport.close()


async def test_driver_error_is_sanitized_and_write_is_rolled_back_once(install):
    driver = install(fail=True)
    transport = SqlServerTransport()
    with pytest.raises(SqlServerTransportError) as error:
        await transport.execute(config(), token(), "UPDATE secret", (), write=True)
    assert "SECRET" not in str(error.value) and "sensitive" not in str(error.value)
    assert len(driver.submissions) == 1 and not driver.committed
    assert driver.connections[0].rolled_back and driver.connections[0].closed
    await transport.close()


async def test_cancel_reaches_driver_and_waits_for_cleanup_without_retry(install):
    driver = install(block=True)
    transport = SqlServerTransport()
    task = asyncio.create_task(transport.execute(config(), token(), "UPDATE x", (), write=True))
    await eventually(lambda: driver.started.is_set())
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    connection = driver.connections[0]
    assert connection.handle.cancelled.is_set()
    assert connection.closed and connection.handle.closed and connection.rolled_back
    assert len(driver.submissions) == 1 and not driver.committed
    await transport.close()


async def test_wall_deadline_cancels_driver_and_rolls_back(install):
    driver = install(block=True)
    transport = SqlServerTransport()
    with pytest.raises(SqlServerTransportError, match="[Tt]ime"):
        await transport.execute(
            config(connect_timeout_seconds=1, statement_timeout_seconds=1),
            token(),
            "UPDATE x",
            (),
            write=True,
        )
    connection = driver.connections[0]
    assert connection.handle.cancelled.is_set() and connection.closed
    assert connection.rolled_back and len(driver.submissions) == 1 and not driver.committed
    await transport.close()


async def test_eight_workers_sixteen_waiters_and_queued_cancel_releases_capacity(install):
    driver = install(block=True)
    transport = SqlServerTransport()
    tasks = [
        asyncio.create_task(transport.execute(config(), token(), "SELECT 1", (), write=False))
        for _ in range(24)
    ]
    await eventually(lambda: len(driver.submissions) == 8)
    with pytest.raises(SqlServerBusyError):
        await transport.execute(config(), token(), "SELECT overflow", (), write=False)
    assert len(driver.connections) == 8
    tasks[-1].cancel()
    with pytest.raises(asyncio.CancelledError):
        await tasks.pop()
    replacement = asyncio.create_task(
        transport.execute(config(), token(), "SELECT replacement", (), write=False)
    )
    driver.release.set()
    results = await asyncio.gather(*tasks, replacement)
    assert len(results) == 24 and len(driver.submissions) == 24
    assert all(c.closed for c in driver.connections)
    await transport.close()


async def test_queued_token_expiry_blocks_connection_without_refresh(install, monkeypatch):
    driver = install(block=True)
    transport = SqlServerTransport()
    now = [1000.0]
    monkeypatch.setattr("interlock.connections.sqlserver.time.time", lambda: now[0])
    tasks = [
        asyncio.create_task(transport.execute(config(), token(2000), "SELECT 1", (), write=False))
        for _ in range(8)
    ]
    await eventually(lambda: len(driver.submissions) == 8)
    queued = asyncio.create_task(
        transport.execute(config(), token(1100), "SELECT expired", (), write=False)
    )
    await asyncio.sleep(0)
    now[0] = 1101
    driver.release.set()
    await asyncio.gather(*tasks)
    with pytest.raises(SqlServerTransportError, match="[Tt]oken"):
        await queued
    assert len(driver.connections) == 8 and len(driver.submissions) == 8
    await transport.close()


async def test_egress_blocks_private_host_before_driver_submission(install, monkeypatch):
    driver = install()
    monkeypatch.setattr(
        "interlock.security.egress._resolve_host_addresses",
        lambda host, port: {ipaddress.ip_address("127.0.0.1")},
    )
    transport = SqlServerTransport()
    with pytest.raises(SqlServerTransportError, match="[Ee]gress"):
        await transport.execute(config(), token(), "SELECT 1", (), write=False)
    assert not driver.connections
    await transport.close()


async def test_uncooperative_driver_cleanup_is_bounded_and_close_cancels_active_work(install):
    driver = install(block=True, ignore_cancel=True)
    transport = SqlServerTransport(cleanup_timeout_seconds=0.05)
    task = asyncio.create_task(transport.execute(config(), token(), "UPDATE x", (), write=True))
    await eventually(lambda: driver.started.is_set())
    started = time.monotonic()
    await transport.close()
    assert time.monotonic() - started < 0.5
    assert driver.connections[0].handle.cancelled.is_set()
    driver.release.set()
    with pytest.raises(SqlServerTransportError):
        await task
    await eventually(lambda: driver.connections[0].closed)
    assert driver.connections[0].rolled_back and not driver.committed
    with pytest.raises(SqlServerTransportError, match="closed"):
        await transport.execute(config(), token(), "SELECT 1", (), write=False)


async def test_exact_json_byte_boundary_includes_count_columns_and_escaping(install):
    # Hand-checked standard JSON envelope is 91 bytes plus the string's ASCII payload.
    # 933 payload bytes therefore fit exactly in a 1024-byte envelope.
    driver = install(rows=(("x" * 933,),))
    transport = SqlServerTransport()
    result = await transport.execute(
        config(max_bytes=1024), token(), "SELECT value", (), write=False
    )
    assert len(json.dumps(result).encode("utf-8")) == 1024
    driver.rows = (("x" * 934,),)
    with pytest.raises(SqlServerResultLimitError):
        await transport.execute(config(max_bytes=1024), token(), "SELECT value", (), write=False)
    await transport.close()


async def test_cancel_during_connect_never_submits_sql_and_closes_late_handle(install):
    driver = install()
    connect = driver.connect
    started, release = threading.Event(), threading.Event()

    def slow_connect(*args, **kwargs):
        started.set()
        release.wait(3)
        return connect(*args, **kwargs)

    driver.connect = slow_connect
    transport = SqlServerTransport(cleanup_timeout_seconds=0.05)
    task = asyncio.create_task(transport.execute(config(), token(), "UPDATE x", (), write=True))
    await eventually(started.is_set)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    release.set()
    await eventually(lambda: driver.connections and driver.connections[0].closed)
    assert not driver.submissions and not driver.committed
    assert driver.connections[0].rolled_back
    await transport.close()


async def test_cancellation_during_fetch_rolls_back_output(install, monkeypatch):
    driver = install()
    fetch = Cursor.fetchmany
    started, release = threading.Event(), threading.Event()

    def blocking_fetch(cursor, size):
        started.set()
        release.wait(3)
        return fetch(cursor, size)

    monkeypatch.setattr(Cursor, "fetchmany", blocking_fetch)
    transport = SqlServerTransport()
    task = asyncio.create_task(
        transport.execute(config(), token(), "UPDATE x OUTPUT value", (), write=True)
    )
    await eventually(started.is_set)
    task.cancel()
    await eventually(lambda: driver.connections[0].handle.cancelled.is_set())
    release.set()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert driver.connections[0].closed and driver.connections[0].rolled_back
    assert not driver.committed
    await transport.close()


async def test_close_wakes_queued_calls_even_when_all_driver_workers_are_stuck(install):
    driver = install(block=True, ignore_cancel=True)
    transport = SqlServerTransport(cleanup_timeout_seconds=0.05)
    tasks = [
        asyncio.create_task(transport.execute(config(), token(), "UPDATE x", (), write=True))
        for _ in range(24)
    ]
    await eventually(lambda: len(driver.connections) == 8)
    await transport.close()
    async with asyncio.timeout(0.5):
        results = await asyncio.gather(*tasks, return_exceptions=True)
    assert all(isinstance(result, SqlServerTransportError) for result in results)
    assert len(driver.connections) == 8 and not driver.committed
    driver.release.set()
    await eventually(lambda: all(c.closed for c in driver.connections))


async def test_transaction_is_finished_once_on_success_or_failure(install):
    driver = install()
    transport = SqlServerTransport()
    await transport.execute(config(), token(), "SELECT 1", (), write=False)
    assert driver.connections[0].rollback_count == 1
    await transport.execute(config(), token(), "UPDATE x OUTPUT value", (), write=True)
    assert driver.connections[1].committed and driver.connections[1].rollback_count == 0
    await transport.close()


async def test_unicode_token_is_length_prefixed_utf16le(install):
    driver = install()
    connect = driver.connect

    def unicode_connect(connection_string, **kwargs):
        assert kwargs["attrs_before"][1256] == b"\x08\x00\x00\x00A\x00\xe9\x00=\xd8\x00\xde"
        kwargs["attrs_before"][1256] = b"\x0a\x00\x00\x00t\x00o\x00k\x00e\x00n\x00"
        return connect(connection_string, **kwargs)

    driver.connect = unicode_connect
    transport = SqlServerTransport()
    credential = SimpleNamespace(access_token="Aé😀", expires_at=time.time() + 10000)
    result = await transport.execute(config(), credential, "SELECT 1", (), write=False)
    assert result["rows"] == [{"value": 1}]
    await transport.close()


async def test_cancelled_stuck_workers_keep_their_slots_until_they_exit(install):
    driver = install(block=True, ignore_cancel=True)
    transport = SqlServerTransport(cleanup_timeout_seconds=0.05)
    active = [
        asyncio.create_task(transport.execute(config(), token(), "UPDATE x", (), write=True))
        for _ in range(8)
    ]
    await eventually(lambda: len(driver.submissions) == 8)
    for task in active:
        task.cancel()
    results = await asyncio.gather(*active, return_exceptions=True)
    assert all(isinstance(result, asyncio.CancelledError) for result in results)
    queued = [
        asyncio.create_task(transport.execute(config(), token(), "SELECT queued", (), write=False))
        for _ in range(16)
    ]
    await asyncio.sleep(0.01)
    with pytest.raises(SqlServerBusyError):
        await transport.execute(config(), token(), "SELECT overflow", (), write=False)
    assert len(driver.connections) == 8
    driver.release.set()
    await asyncio.gather(*queued)
    assert len(driver.connections) == 24 and not driver.committed
    await transport.close()


async def test_blocking_native_cancel_cannot_block_event_loop_or_cleanup_deadline(
    install, monkeypatch
):
    driver = install(block=True)
    started, release = threading.Event(), threading.Event()
    cancel = Cursor.cancel

    def blocking_cancel(cursor):
        started.set()
        release.wait(3)
        cancel(cursor)

    monkeypatch.setattr(Cursor, "cancel", blocking_cancel)
    transport = SqlServerTransport(cleanup_timeout_seconds=0.05)
    task = asyncio.create_task(transport.execute(config(), token(), "UPDATE x", (), write=True))
    await eventually(driver.started.is_set)
    before = time.monotonic()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert started.is_set() and time.monotonic() - before < 0.5
    release.set()
    await eventually(lambda: driver.connections[0].closed)
    assert driver.connections[0].rolled_back and not driver.committed
    await transport.close()


async def test_cursor_close_error_still_closes_connection(install, monkeypatch):
    driver = install()

    def fail_close(cursor):
        raise RuntimeError("native close error")

    monkeypatch.setattr(Cursor, "close", fail_close)
    transport = SqlServerTransport()
    result = await transport.execute(config(), token(), "SELECT 1", (), write=False)
    assert result["rows"] == [{"value": 1}] and driver.connections[0].closed
    await transport.close()


async def test_permission_envelope_is_returned_and_budgeted_before_output_commit(install):
    driver = install()
    transport = SqlServerTransport()
    permission = {"resource": "dbo.items", "action": "write"}
    result = await transport.execute(
        config(max_bytes=1024),
        token(),
        "UPDATE x OUTPUT value",
        (),
        write=True,
        permission_request=permission,
    )
    assert result["permission_request"] == permission
    assert len(json.dumps(result).encode("utf-8")) <= 1024
    assert len(driver.committed) == 1
    with pytest.raises(SqlServerResultLimitError):
        await transport.execute(
            config(max_bytes=1024),
            token(),
            "UPDATE x OUTPUT value",
            (),
            write=True,
            permission_request={"resource": "x" * 1000},
        )
    assert len(driver.committed) == 1
    assert driver.connections[1].rolled_back and driver.connections[1].closed
    await transport.close()


async def test_blocked_native_cancellers_cannot_create_an_unbounded_cleanup_queue(
    install, monkeypatch
):
    driver = install(block=True)
    release_cancel = threading.Event()
    cancel = Cursor.cancel

    def blocking_cancel(cursor):
        release_cancel.wait(3)
        cancel(cursor)

    monkeypatch.setattr(Cursor, "cancel", blocking_cancel)
    transport = SqlServerTransport(cleanup_timeout_seconds=0.05)
    active = [
        asyncio.create_task(transport.execute(config(), token(), "UPDATE x", (), write=True))
        for _ in range(8)
    ]
    queued = []
    try:
        await eventually(lambda: len(driver.submissions) == 8)
        for task in active:
            task.cancel()
        await asyncio.gather(*active, return_exceptions=True)
        driver.release.set()  # SQL finishes independently while native cancel is still blocked.
        await asyncio.sleep(0.02)
        queued = [
            asyncio.create_task(
                transport.execute(config(), token(), "SELECT queued", (), write=False)
            )
            for _ in range(16)
        ]
        await asyncio.sleep(0.02)
        with pytest.raises(SqlServerBusyError):
            await transport.execute(config(), token(), "SELECT overflow", (), write=False)
        assert len(driver.connections) == 8
    finally:
        release_cancel.set()
        driver.release.set()
        await asyncio.gather(*active, *queued, return_exceptions=True)
        await transport.close()


async def test_repeated_queued_cancellation_restores_all_sixteen_waiting_slots(install):
    driver = install(block=True)
    transport = SqlServerTransport()
    active = [
        asyncio.create_task(transport.execute(config(), token(), "SELECT active", (), write=False))
        for _ in range(8)
    ]
    waiting = []
    victim = None
    try:
        await eventually(lambda: len(driver.submissions) == 8)
        victim = asyncio.create_task(
            transport.execute(config(), token(), "SELECT cancelled", (), write=False)
        )
        await asyncio.sleep(0)  # Enter admission and wait behind the eight workers.
        victim.cancel()
        await asyncio.sleep(0)  # Enter queued cleanup, awaiting its cancelled acquire task.
        victim.cancel()
        with pytest.raises(asyncio.CancelledError):
            await victim
        waiting = [
            asyncio.create_task(
                transport.execute(config(), token(), "SELECT waiting", (), write=False)
            )
            for _ in range(16)
        ]
        await asyncio.sleep(0)
        # Every replacement must still be queued; a leaked admission rejects the sixteenth.
        assert all(not task.done() for task in waiting)
        with pytest.raises(SqlServerBusyError):
            await transport.execute(config(), token(), "SELECT overflow", (), write=False)
        assert len(driver.connections) == 8
        driver.release.set()
        results = await asyncio.gather(*active, *waiting)
        assert len(results) == 24
        assert len(driver.submissions) == 24
        assert all(sql != "SELECT cancelled" for sql, _ in driver.submissions)
        assert all(connection.closed for connection in driver.connections)
    finally:
        driver.release.set()
        if victim is not None and not victim.done():
            victim.cancel()
        await asyncio.gather(*active, *waiting, return_exceptions=True)
        await transport.close()
