"""Bounded token-authenticated ODBC SQL execution, independent of authentication.

The existing egress guard checks the configured host and its DNS answers. ODBC
resolves that host again and can follow server routing redirects internally; this
is not a DNS-pinned transport. Deployment network controls must constrain those
paths. No credentials, SQL text, parameters or driver diagnostics are logged.
"""

from __future__ import annotations

import asyncio
import base64
import datetime as dt
import importlib
import json
import math
import struct
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from decimal import Decimal
from typing import TYPE_CHECKING, Any, cast

from interlock.errors import EgressBlockedError
from interlock.security.egress import validate_host_egress

if TYPE_CHECKING:
    from interlock.connections.fabric.auth import FabricToken
    from interlock.connections.fabric.config import FabricConfig


class SqlServerTransportError(RuntimeError):
    """Safe transport failure; a submitted write must never be automatically retried."""


class SqlServerResultLimitError(SqlServerTransportError):
    """Returned JSON exceeded its configured row or byte limit."""


class SqlServerBusyError(SqlServerTransportError):
    """All eight execution slots and sixteen waiting slots are occupied."""


@dataclass(eq=False)
class _Operation:
    cancelled: threading.Event = field(default_factory=threading.Event)
    cancel_done: threading.Event = field(default_factory=threading.Event)
    lock: threading.Lock = field(default_factory=threading.Lock)
    cursor: Any = None
    cancel_future: asyncio.Future[Any] | None = None


class SqlServerTransport:
    """Process-lifetime owner of bounded ODBC workers and cancellation workers.

    Login and statement timeouts are also set on the driver. The async wall
    deadline covers their combined budgets. Cancellation requests cursor.cancel
    outside the blocked worker and waits at most cleanup_timeout_seconds; native
    calls cannot be forcibly terminated safely. A stuck worker retains its slot.
    """

    def __init__(self, *, cleanup_timeout_seconds: float = 5.0) -> None:
        if not 0 < cleanup_timeout_seconds <= 60:
            raise ValueError("cleanup timeout must be between zero and sixty seconds")
        self._cleanup_timeout = cleanup_timeout_seconds
        self._driver = cast("Any", importlib.import_module("pyodbc"))
        # pyodbc pooling is process-global and must be disabled before connecting.
        self._driver.pooling = False
        self._workers = ThreadPoolExecutor(max_workers=8, thread_name_prefix="sqlserver")
        self._cancellers = ThreadPoolExecutor(max_workers=8, thread_name_prefix="sqlserver-cancel")
        self._slots = asyncio.Semaphore(8)
        self._admitted = 0
        self._closing = asyncio.Event()
        self._running: dict[asyncio.Future[dict[str, Any]], _Operation] = {}

    async def execute(
        self,
        config: FabricConfig,
        token: FabricToken,
        sql: str,
        parameters: tuple[Any, ...],
        *,
        write: bool,
        permission_request: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        if self._closing.is_set():
            raise SqlServerTransportError("SQL Server transport is closed")
        if self._admitted >= 24:
            raise SqlServerBusyError("SQL Server execution queue is full")
        self._admitted += 1
        acquire = asyncio.create_task(self._slots.acquire())
        closing = asyncio.create_task(self._closing.wait())
        submitted = False
        try:
            await asyncio.wait((acquire, closing), return_when=asyncio.FIRST_COMPLETED)
            if self._closing.is_set():
                raise SqlServerTransportError("SQL Server transport is closed")
            acquire.result()
            operation = _Operation()
            loop = asyncio.get_running_loop()
            future = loop.run_in_executor(
                self._workers,
                self._execute,
                config,
                token,
                sql,
                parameters,
                write,
                operation,
                permission_request,
            )
            self._running[future] = operation
            future.add_done_callback(self._finished)
            submitted = True
            try:
                done, _ = await asyncio.wait(
                    (future, closing),
                    timeout=config.connect_timeout_seconds + config.statement_timeout_seconds,
                    return_when=asyncio.FIRST_COMPLETED,
                )
                if future in done:
                    return future.result()
                await self._cancel_and_cleanup(future, operation)
                if self._closing.is_set():
                    raise SqlServerTransportError(
                        "SQL Server transport is closed; write outcome may be unknown"
                    )
                raise SqlServerTransportError("SQL Server timeout; write outcome may be unknown")
            except asyncio.CancelledError:
                await self._cancel_and_cleanup(future, operation)
                raise
        finally:
            # Cancellation can race a semaphore grant before this coroutine resumes.
            if not submitted:
                if not acquire.done():
                    acquire.cancel()
                if acquire.done():
                    self._discard_queued(acquire)
                else:
                    # A second caller cancellation must not interrupt resource
                    # accounting while the semaphore processes the first one.
                    acquire.add_done_callback(self._discard_queued)
            closing.cancel()
            await asyncio.gather(closing, return_exceptions=True)

    def _discard_queued(self, acquire: asyncio.Task[bool]) -> None:
        self._admitted -= 1
        if not acquire.cancelled() and acquire.exception() is None and acquire.result():
            self._slots.release()

    def _finished(self, future: asyncio.Future[dict[str, Any]]) -> None:
        self._running.pop(future, None)
        self._slots.release()
        self._admitted -= 1
        # Timed-out callers may already have returned. Retrieve late exceptions.
        if not future.cancelled():
            future.exception()
        if self._closing.is_set() and not self._running:
            self._cancellers.shutdown(wait=False)

    def _request_cancel(self, operation: _Operation) -> asyncio.Future[Any] | None:
        operation.cancelled.set()
        with operation.lock:
            if operation.cursor is not None and operation.cancel_future is None:
                operation.cancel_future = asyncio.get_running_loop().run_in_executor(
                    self._cancellers,
                    _cancel_cursor,
                    operation.cursor,
                    operation.cancel_done,
                )
        return operation.cancel_future

    async def _cancel_and_cleanup(
        self,
        future: asyncio.Future[dict[str, Any]],
        operation: _Operation,
    ) -> None:
        cancel = self._request_cancel(operation)
        pending: set[asyncio.Future[Any]] = {future}
        if cancel is not None:
            pending.add(cancel)
        await asyncio.wait(pending, timeout=self._cleanup_timeout)

    async def close(self) -> None:
        if self._closing.is_set():
            return
        self._closing.set()
        pending: set[asyncio.Future[Any]] = set(self._running)
        for operation in list(self._running.values()):
            cancel = self._request_cancel(operation)
            if cancel is not None:
                pending.add(cancel)
        if pending:
            await asyncio.wait(pending, timeout=self._cleanup_timeout)
        self._workers.shutdown(wait=False, cancel_futures=True)
        if not self._running:
            self._cancellers.shutdown(wait=False)

    def _execute(
        self,
        config: FabricConfig,
        token: FabricToken,
        sql: str,
        parameters: tuple[Any, ...],
        write: bool,
        operation: _Operation,
        permission_request: dict[str, Any] | None,
    ) -> dict[str, Any]:
        connection = cursor = None
        transaction_finished = False
        try:
            _check_cancelled(operation)
            validate_host_egress(
                config.host, port=config.port, allow_private=config.allow_private_egress
            )
            _check_cancelled(operation)
            # The token authenticates the connection; it need not cover the query.
            if token.expires_at <= time.time() + config.connect_timeout_seconds:
                raise SqlServerTransportError("SQL token has insufficient remaining lifetime")
            encoded = token.access_token.encode("utf-16-le")
            packed = struct.pack("<I", len(encoded)) + encoded
            connection_string = (
                "DRIVER={ODBC Driver 18 for SQL Server};"
                f'SERVER={_odbc_field("tcp:" + config.host + "," + str(config.port))};'
                f"DATABASE={_odbc_field(config.database)};"
                "Encrypt=yes;TrustServerCertificate=no;"
            )
            connection = self._driver.connect(
                connection_string,
                attrs_before={1256: packed},
                timeout=config.connect_timeout_seconds,
                autocommit=False,
            )
            connection.timeout = config.statement_timeout_seconds
            _check_cancelled(operation)
            cursor = connection.cursor()
            with operation.lock:
                operation.cursor = cursor
            _check_cancelled(operation)
            cursor.execute(sql, parameters)
            _check_cancelled(operation)
            result = _consume(cursor, config, operation, permission_request)
            if cursor.nextset():
                raise SqlServerTransportError("Multiple SQL result sets are unsupported")
            _check_cancelled(operation)
            if write:
                connection.commit()
            else:
                connection.rollback()
            transaction_finished = True
            return result
        except EgressBlockedError:
            raise SqlServerTransportError("SQL endpoint egress blocked") from None
        except SqlServerTransportError:
            raise
        except Exception:
            raise SqlServerTransportError(
                "SQL Server execution failed; submitted write outcome may be unknown"
            ) from None
        finally:
            with operation.lock:
                operation.cursor = None
                cancelling = operation.cancel_future is not None
            # Keep the worker/slot and native handles alive until concurrent cancel
            # finishes. Otherwise stuck cancellers could accumulate an unbounded
            # executor queue across subsequent generations of SQL workers.
            if cancelling:
                operation.cancel_done.wait()
            # Failed OUTPUT validation and failed/cancelled submissions never commit.
            # Rollback is best effort if the native connection itself is broken.
            if connection is not None and not transaction_finished:
                try:
                    connection.rollback()
                except Exception:
                    pass
            for handle in (cursor, connection):
                if handle is not None:
                    try:
                        handle.close()
                    except Exception:
                        pass


def _cancel_cursor(cursor: Any, done: threading.Event) -> None:
    try:
        cursor.cancel()
    except Exception:
        pass
    finally:
        done.set()


def _check_cancelled(operation: _Operation) -> None:
    if operation.cancelled.is_set():
        raise SqlServerTransportError("SQL execution cancelled; write outcome may be unknown")


def _odbc_field(value: str) -> str:
    return "{" + value.replace("}", "}}") + "}"


def _encoded_length(value: Any) -> int:
    # Default JSON escaping is conservative for the application's JSON encoders.
    return len(json.dumps(value, allow_nan=False).encode("utf-8"))


def _value(value: Any) -> Any:
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise SqlServerTransportError("Non-finite SQL numeric result is unsupported")
        return value
    if isinstance(value, (Decimal, uuid.UUID)):
        return str(value)
    if isinstance(value, (dt.datetime, dt.date, dt.time)):
        return value.isoformat()
    if isinstance(value, (bytes, bytearray, memoryview)):
        return base64.b64encode(value).decode("ascii")
    raise SqlServerTransportError("Unsupported SQL result value type")


def _consume(
    cursor: Any,
    config: FabricConfig,
    operation: _Operation,
    permission_request: dict[str, Any] | None,
) -> dict[str, Any]:
    columns = [str(item[0]) for item in cursor.description] if cursor.description else []
    if len({name.casefold() for name in columns}) != len(columns):
        raise SqlServerTransportError("Duplicate SQL output column names are unsupported")
    rows: list[dict[str, Any]] = []
    count = (cursor.rowcount if cursor.rowcount >= 0 else None) if not columns else 0
    result = dict(
        rows=rows, columns=columns, row_count=count, permission_request=permission_request
    )
    base_size = _encoded_length(result)
    row_bytes = 0
    if base_size > config.max_bytes:
        raise SqlServerResultLimitError("SQL result byte limit exceeded")
    if columns:
        while True:
            _check_cancelled(operation)
            batch = cursor.fetchmany(min(128, config.max_rows + 1 - len(rows)))
            if not batch:
                break
            for record in batch:
                if len(rows) >= config.max_rows:
                    raise SqlServerResultLimitError("SQL result row limit exceeded")
                row = {name: _value(value) for name, value in zip(columns, record, strict=True)}
                row_bytes += _encoded_length(row) + (2 if rows else 0)
                # Account for the changing row_count digit width as rows arrive.
                size = base_size + row_bytes + len(str(len(rows) + 1)) - 1
                if size > config.max_bytes:
                    raise SqlServerResultLimitError("SQL result byte limit exceeded")
                rows.append(row)
        result["row_count"] = len(rows)
    return result
