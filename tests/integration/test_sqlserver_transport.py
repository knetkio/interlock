"""Opt-in native Driver 18 proof against an explicitly designated disposable DB.

Run only with FABRIC_SQL_INTEGRATION=1, FABRIC_SQL_TEST_HOST,
FABRIC_SQL_TEST_DATABASE, FABRIC_SQL_TEST_TOKEN (short-lived Entra SQL token), and
FABRIC_SQL_TEST_CUSTOMER_CHECKED=1 after the project's customer selector and
identity/workspace/database have been verified. Never point at production: the
transaction test creates/drops a uniquely named table. No global login fallback.
Requires Microsoft ODBC Driver 18 and a test identity with CREATE TABLE rights.
No SQL Server/Fabric endpoint is configured by the unit-test suite.
"""

from __future__ import annotations

import asyncio
import os
import struct
import time
import uuid

import pytest

from interlock.connections.fabric.auth import FabricToken
from interlock.connections.fabric.config import FabricConfig
from interlock.connections.fabric.credentials import FabricCredentialContext
from interlock.connections.sqlserver import SqlServerResultLimitError, SqlServerTransport
from interlock.security.egress import validate_host_egress

pytestmark = [
    pytest.mark.live,
    pytest.mark.skipif(
        os.environ.get("FABRIC_SQL_INTEGRATION") != "1",
        reason="No opt-in SQL Server/Fabric test endpoint: FABRIC_SQL_INTEGRATION != 1",
    ),
]


@pytest.fixture
def endpoint():
    if os.environ.get("FABRIC_SQL_TEST_CUSTOMER_CHECKED") != "1":
        pytest.fail("Verify project customer, identity and disposable database before native tests")
    required = ["FABRIC_SQL_TEST_HOST", "FABRIC_SQL_TEST_DATABASE", "FABRIC_SQL_TEST_TOKEN"]
    if any(not os.environ.get(key) for key in required):
        pytest.fail("Explicit disposable SQL endpoint/database/token are required")
    driver = pytest.importorskip("pyodbc")
    if "ODBC Driver 18 for SQL Server" not in driver.drivers():
        pytest.skip("Microsoft ODBC Driver 18 for SQL Server is not installed")
    config = FabricConfig.from_mapping(
        dict(
            host=os.environ["FABRIC_SQL_TEST_HOST"],
            database=os.environ["FABRIC_SQL_TEST_DATABASE"],
            tenant_id="explicit-test-tenant",
            client_id="explicit-test-client",
            endpoint_type=os.environ.get("FABRIC_SQL_TEST_ENDPOINT_TYPE", "sql_database"),
            auth_mode="oauth",
            allow_private_egress=os.environ.get("FABRIC_SQL_TEST_PRIVATE") == "1",
        )
    )
    # This test token is explicitly supplied, never acquired from ambient identity.
    token = FabricToken(
        access_token=os.environ["FABRIC_SQL_TEST_TOKEN"],
        expires_at=time.time() + 3600,
        context=FabricCredentialContext(
            source_id="explicit-native-test",
            generation=1,
            tenant_id=config.tenant_id,
            client_id=config.client_id,
            account_id=None,
            auth_mode="oauth",
            status="connected",
        ),
    )
    return config, token, driver


@pytest.fixture
async def transport():
    instance = SqlServerTransport()
    yield instance
    await instance.close()


async def test_native_output_limit_rolls_back_and_valid_output_commits(endpoint, transport):
    config, token, driver = endpoint
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


async def test_native_cancellation_returns_and_transport_can_execute_again(endpoint, transport):
    config, token, _ = endpoint
    if config.endpoint_type != "sql_database":
        pytest.skip("WAITFOR cancellation probe targets SQL Database/SQL Server only")
    task = asyncio.create_task(
        transport.execute(
            config,
            token,
            "WAITFOR DELAY '00:00:20'; SELECT 1 AS value",
            (),
            write=False,
        )
    )
    try:
        await asyncio.sleep(0.5)
        assert not task.done(), "Native cancellation probe completed before cancellation"
        started = time.monotonic()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert time.monotonic() - started < 7
        result = await transport.execute(config, token, "SELECT 7 AS value", (), write=False)
        assert result["rows"] == [{"value": 7}]
    finally:
        if not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
