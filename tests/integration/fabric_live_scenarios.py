"""Opt-in operator fixtures, with independent observations; never certification flags.

Hooks operate only supplied test infrastructure. Responses, new audit rows,
credential state and fresh trusted-observer events decide acceptance. Offline
unit doubles exercise this tooling only and are never native evidence.
"""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
import time
import uuid
from dataclasses import asdict
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlsplit

import httpx
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator
from sqlglot import exp

from interlock.connections.connectors import get_adapter
from interlock.connections.fabric.auth import FabricAuthError
from interlock.connections.fabric.config import require_secret_reference
from interlock.secrets.resolver import resolve
from tests.integration.fabric_live_support import validate_binding

KINDS = Literal[
    "denial",
    "redaction",
    "audit",
    "restart_refresh",
    "oauth_reconnect_lost_consent",
    "spn_rotation",
    "multi_instance_cache",
    "login_cancellation",
    "statement_cancellation",
    "tls_certificate_failure",
    "driver_redirect_egress",
    "writes",
]
MASK = "[REDACTED:POLICY]"
HOOKS = {
    "restart_refresh": {"restart", "refresh"},
    "oauth_reconnect_lost_consent": {"lose_consent", "reconnect"},
    "spn_rotation": {"rotate"},
    "multi_instance_cache": {"reset_cache", "invalidate"},
    "login_cancellation": {"prepare", "cleanup"},
    "tls_certificate_failure": {"prepare", "cleanup"},
    "driver_redirect_egress": {"prepare", "cleanup"},
}


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class OperatorHook(Strict):
    argv: list[str] = Field(min_length=1)
    secret_env: dict[str, str] = Field(default_factory=dict)
    timeout_seconds: int = Field(default=30, ge=1, le=60)

    @model_validator(mode="after")
    def explicit_command(self):
        if not Path(self.argv[0]).is_absolute() or any("\x00" in arg for arg in self.argv):
            raise ValueError("Explicit executable required")
        if any(arg in {"-c", "--command"} or "://" in arg for arg in self.argv[1:]):
            raise ValueError("No shell command or secret reference in argv")
        for key, ref in self.secret_env.items():
            if not key.isidentifier() or key.startswith("FABRIC_ACCEPTANCE_"):
                raise ValueError("Invalid hook environment key")
            require_secret_reference(ref)
        return self


class Probe(Strict):
    gateway_url: str
    actor_key_ref: str
    actor_id: int = Field(gt=0)
    sql: str
    parameters: list[Any] = Field(default_factory=list)
    expected_rows: list[dict[str, Any]] | None = None

    @field_validator("actor_key_ref")
    @classmethod
    def secret_reference(cls, value):
        return require_secret_reference(value)

    @field_validator("sql")
    @classmethod
    def read_only(cls, value):
        if not isinstance(get_adapter("fabric_sql").validate_sql(value), exp.Query):
            raise ValueError("Probe must be a supported read")
        return value


class WriteStep(Strict):
    sql: str
    parameters: list[Any] = Field(default_factory=list)
    read_sql: str
    expected_rows: list[dict[str, Any]]


class WriteFixture(Strict):
    authorization: Literal["disposable_objects_only"]
    table: str
    steps: list[WriteStep] = Field(min_length=3, max_length=3)

    @model_validator(mode="after")
    def table_scope(self):
        adapter = get_adapter("fabric_sql")
        for step, kind in zip(self.steps, (exp.Insert, exp.Update, exp.Delete), strict=True):
            write = adapter.validate_sql(step.sql)
            read = adapter.validate_sql(step.read_sql)
            if not isinstance(write, kind) or not isinstance(read, exp.Query):
                raise ValueError("Expected INSERT VALUES, UPDATE, DELETE and read-back")
            for statement in (write, read):
                tables = list(statement.find_all(exp.Table))
                if not tables or any(t.catalog or f"{t.db}.{t.name}" != self.table for t in tables):
                    raise ValueError("Fixture SQL must stay within its designated disposable table")
        return self


class NetworkFixture(Strict):
    observer_path: str
    allowed_destination: str
    blocked_destination: str | None = None
    cleanup_seconds: int = Field(default=20, ge=1, le=60)

    @field_validator("observer_path")
    @classmethod
    def absolute_observer(cls, value):
        if not Path(value).is_absolute():
            raise ValueError("Explicit observer file required")
        return value


class Scenario(Strict):
    probe: Probe | None = None
    hooks: dict[str, OperatorHook] = Field(default_factory=dict)
    masked_columns: list[str] = Field(default_factory=list)
    second_gateway_url: str | None = None
    network: NetworkFixture | None = None
    write: WriteFixture | None = None
    restart_observer_path: str | None = None


class ScenarioBook(Strict):
    allowed_gateway_origins: list[str]
    cells: dict[str, dict[KINDS, Scenario]]

    @model_validator(mode="after")
    def required_fixtures(self):
        for origin in self.allowed_gateway_origins:
            parsed = urlsplit(origin)
            if (
                parsed.scheme not in {"http", "https"}
                or not parsed.hostname
                or parsed.username
                or parsed.password
                or parsed.path
                or parsed.query
                or parsed.fragment
            ):
                raise ValueError("Gateway origins must be exact origins without credentials/path")
        for cell, scenarios in self.cells.items():
            if cell not in {
                f"{e}/{a}"
                for e in ("warehouse", "lakehouse_sql", "sql_database")
                for a in ("oauth", "spn")
            }:
                raise ValueError("Unknown endpoint/auth cell")
            for kind, scenario in scenarios.items():
                if not HOOKS.get(kind, set()).issubset(scenario.hooks):
                    raise ValueError("Lifecycle scenario requires explicit operator steps")
                if (
                    kind
                    not in {
                        "login_cancellation",
                        "statement_cancellation",
                        "tls_certificate_failure",
                        "driver_redirect_egress",
                    }
                    and not scenario.probe
                ):
                    raise ValueError("Governed probe required")
                for origin in [
                    scenario.probe.gateway_url if scenario.probe else None,
                    scenario.second_gateway_url,
                ]:
                    if origin is not None and origin not in self.allowed_gateway_origins:
                        raise ValueError("Gateway must match an explicitly allowed origin")
                if kind == "restart_refresh" and (
                    not scenario.restart_observer_path
                    or not Path(scenario.restart_observer_path).is_absolute()
                ):
                    raise ValueError("Trusted restart observer file required")
                if kind == "redaction" and not scenario.masked_columns:
                    raise ValueError("Expected masked output columns required")
                if kind == "multi_instance_cache" and (
                    not scenario.second_gateway_url
                    or scenario.second_gateway_url == scenario.probe.gateway_url
                ):
                    raise ValueError("Two distinct explicit gateway origins required")
                if kind in {
                    "login_cancellation",
                    "tls_certificate_failure",
                    "driver_redirect_egress",
                }:
                    if not scenario.network:
                        raise ValueError("Network observation fixture required")
                    if kind == "driver_redirect_egress" and (
                        not scenario.network.blocked_destination
                        or scenario.network.blocked_destination
                        == scenario.network.allowed_destination
                    ):
                        raise ValueError("Separate disallowed redirect destination required")
                if kind == "writes" and (not scenario.write or cell.startswith("lakehouse_sql/")):
                    raise ValueError(
                        "Explicit disposable Warehouse/SQL Database write fixture required"
                    )
        return self


def load_scenarios(value: object) -> ScenarioBook:
    try:
        return ScenarioBook.model_validate(value)
    except (ValidationError, ValueError):
        raise ValueError("Invalid Fabric acceptance scenario configuration") from None


async def run_hook(
    hook: OperatorHook, *, source_id: str, nonce: str, approval_id: int | None = None
):
    # No ambient API keys/default credential environment is inherited.
    environment = {
        "PATH": os.environ.get("PATH", ""),
        "FABRIC_ACCEPTANCE_SOURCE_ID": source_id,
        "FABRIC_ACCEPTANCE_NONCE": nonce,
    }
    environment.update({key: resolve(ref) for key, ref in hook.secret_env.items()})
    if approval_id is not None:
        environment["FABRIC_ACCEPTANCE_APPROVAL_ID"] = str(approval_id)
    try:
        result = await asyncio.to_thread(
            subprocess.run,
            hook.argv,
            shell=False,
            env=environment,
            timeout=hook.timeout_seconds,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        assert result.returncode == 0, "Operator scenario step failed (output suppressed)"
    except subprocess.TimeoutExpired:
        raise AssertionError("Operator scenario step exceeded its deadline") from None


def response_rows(response):
    payload = response.json()
    if isinstance(payload, dict) and "content" in payload:
        payload = json.loads(payload["content"][0]["text"])
    return payload


async def gateway_response(
    probe, source_id, *, sql=None, parameters=None, client=None, correlation_id=None
):
    owned = client is None
    if owned:
        client = httpx.AsyncClient(timeout=30, follow_redirects=False)
    try:
        return await client.post(
            probe.gateway_url + "/mcp/tools/call",
            follow_redirects=False,
            headers={
                "Authorization": "Bearer " + resolve(probe.actor_key_ref),
                "X-Correlation-ID": correlation_id or uuid.uuid4().hex,
            },
            json={
                "name": "interlock_query",
                "arguments": {
                    "source_id": source_id,
                    "sql": sql or probe.sql,
                    "parameters": probe.parameters if parameters is None else parameters,
                },
            },
        )
    finally:
        if owned:
            await client.aclose()


async def query_gateway(
    probe, source_id, *, client=None, masked_columns=(), denied=False, correlation_id=None
):
    response = await gateway_response(
        probe, source_id, client=client, correlation_id=correlation_id
    )
    assert response.status_code == (403 if denied else 200), "Unexpected governed probe status"
    if denied:
        return None
    rows = response_rows(response)
    assert isinstance(rows, list) and rows, "Expected nonempty fixture rows"
    if masked_columns:
        assert all(
            row.get(column) == MASK for row in rows for column in masked_columns
        ), "Expected policy-masked output column was returned unmasked"
    elif probe.expected_rows is not None:
        assert rows == probe.expected_rows, "Governed read differs from designated fixture"
    return rows


async def audit_watermark(pool):
    return await pool.fetchval("SELECT COALESCE(MAX(id),0) FROM audit_log")


async def observed_audit(
    pool,
    watermark,
    source_id,
    actor_id,
    status,
    *,
    operation="read",
    correlation_id=None,
    approval_id=None,
):
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        predicate = (
            "approval_id=$6"
            if approval_id is not None
            else "request_metadata->>'correlation_id'=$6"
        )
        row = await pool.fetchrow(
            "SELECT * FROM audit_log WHERE id>$1 AND source_id=$2 AND identity_id=$3 "
            "AND status=$4 AND operation=$5 AND " + predicate + " ORDER BY id DESC LIMIT 1",
            watermark,
            source_id,
            actor_id,
            status,
            operation,
            approval_id if approval_id is not None else correlation_id,
        )
        if row:
            return row
        await asyncio.sleep(0.05)
    raise AssertionError("No new matching source/actor audit event observed")


async def governed_evidence(scenario, cell, pool, *, client=None, cache_hit=None, binding=None):
    mark = await audit_watermark(pool)
    correlation_id = uuid.uuid4().hex
    await query_gateway(
        scenario.probe,
        cell.source_id,
        client=client,
        masked_columns=scenario.masked_columns,
        correlation_id=correlation_id,
    )
    row = await observed_audit(
        pool,
        mark,
        cell.source_id,
        scenario.probe.actor_id,
        "success",
        correlation_id=correlation_id,
    )
    if cache_hit is not None:
        assert row["cache_hit"] is cache_hit, "Unexpected multi-instance cache result"
    if binding is not None:
        metadata = row["request_metadata"]
        if isinstance(metadata, str):
            metadata = json.loads(metadata)
        assert metadata.get("upstream_identity") == binding, "Audit identity/generation mismatch"


def assert_network_evidence(
    fixture, offset, *, nonce, source_id, target_host, started_at, dimension
):
    with Path(fixture.observer_path).open("rb") as stream:
        assert stream.seek(0, 2) >= offset, "Observer file was truncated/replaced"
        stream.seek(offset)
        events = [json.loads(line) for line in stream if line.strip()]
    events = [
        e
        for e in events
        if e.get("nonce") == nonce
        and e.get("source_id") == source_id
        and e.get("target_host") == target_host
        and e.get("timestamp", 0) >= started_at
    ]
    assert any(
        e.get("destination") == fixture.allowed_destination and e.get("action") == "allowed"
        for e in events
    ), "No fresh positive allowed connection observation"
    if dimension == "driver_redirect_egress":
        target = [e for e in events if e.get("destination") == fixture.blocked_destination]
        assert not any(e.get("action") == "allowed" for e in target), "Unauthorized redirect bypass"
        assert any(
            e.get("action") == "blocked" and e.get("event") == "redirect" for e in target
        ), "No fresh blocked redirect observation"
    else:
        wanted = (
            "tls_certificate_rejected" if dimension == "tls_certificate_failure" else "login_closed"
        )
        assert any(
            e.get("event") == wanted for e in events
        ), "Expected native failure/cleanup not observed"


async def assert_native_identity(services, prepared, cell):
    await prepared.assert_current()
    actual = await services.transport.execute(
        prepared.config,
        prepared.token,
        "SELECT TOP (1) DB_NAME() AS database_name, SUSER_SNAME() AS upstream_identity",
        (),
        write=False,
    )
    assert actual["rows"] == [
        {"database_name": cell.database, "upstream_identity": cell.expected_sql_identity}
    ], "Native identity/database differs from designated fixture"
    await prepared.assert_current()


async def run_scenario(dimension, scenario, cell, config, services, pool, *, client=None):
    nonce = uuid.uuid4().hex

    async def step(name, **kwargs):
        await run_hook(scenario.hooks[name], source_id=cell.source_id, nonce=nonce, **kwargs)

    if dimension in {"denial", "redaction", "audit"}:
        if dimension == "denial":
            mark = await audit_watermark(pool)
            await query_gateway(
                scenario.probe, cell.source_id, client=client, denied=True, correlation_id=nonce
            )
            await observed_audit(
                pool, mark, cell.source_id, scenario.probe.actor_id, "denied", correlation_id=nonce
            )
        else:
            await governed_evidence(scenario, cell, pool, client=client)
        return
    before = await services.prepare_source(cell.source_id, config)
    if dimension in {
        "restart_refresh",
        "spn_rotation",
        "oauth_reconnect_lost_consent",
        "multi_instance_cache",
    }:
        if dimension == "restart_refresh":
            observer = Path(scenario.restart_observer_path)
            offset = observer.stat().st_size
            started = time.time()
            await step("restart")
            with observer.open("rb") as stream:
                stream.seek(offset)
                events = [json.loads(line) for line in stream if line.strip()]
            assert any(
                e.get("nonce") == nonce
                and e.get("source_id") == cell.source_id
                and e.get("gateway_origin") == scenario.probe.gateway_url
                and e.get("timestamp", 0) >= started
                and e.get("event") == "process_restart"
                and e.get("previous_instance")
                and e.get("current_instance")
                and e["previous_instance"] != e["current_instance"]
                for e in events
            ), "No fresh independently observed process restart"
            await step("refresh")
        elif dimension == "spn_rotation":
            assert cell.auth_mode == "spn", "SPN rotation requires SPN cell"
            await step("rotate")
        elif dimension == "oauth_reconnect_lost_consent":
            assert cell.auth_mode == "oauth", "Consent scenario requires OAuth cell"
            await step("lose_consent")
            try:
                await services.auth.acquire(cell.source_id, config)
            except FabricAuthError as error:
                assert error.code == "reconnect_required", "Unexpected consent-loss outcome"
            else:
                raise AssertionError("Lost consent did not require reconnect")
            await step("reconnect")
        else:
            await step("reset_cache")
            await governed_evidence(scenario, cell, pool, client=client, cache_hit=False)
            second = scenario.model_copy(
                update={
                    "probe": scenario.probe.model_copy(
                        update={"gateway_url": scenario.second_gateway_url}
                    )
                }
            )
            await governed_evidence(second, cell, pool, client=client, cache_hit=True)
            await step("invalidate")
        current = await services.store.current_source(cell.source_id)
        validate_binding(cell, current.config, current.context)
        after = await services.prepare_source(cell.source_id, current.config)
        if dimension == "restart_refresh":
            assert after.token.context == before.token.context, "Silent refresh changed identity"
            assert (
                after.token.expires_at > before.token.expires_at
            ), "No actual token renewal observed"
        else:
            assert (
                after.token.context.generation > before.token.context.generation
            ), "Generation did not advance"
            with_current = False
            try:
                await before.assert_current()
                with_current = True
            except FabricAuthError:
                pass
            assert not with_current, "Old prepared capability survived invalidation"
        await assert_native_identity(services, after, cell)
        await governed_evidence(
            scenario,
            cell,
            pool,
            client=client,
            cache_hit=False if dimension == "multi_instance_cache" else None,
            binding=asdict(after.token.context),
        )
        if dimension == "multi_instance_cache":
            await governed_evidence(
                second,
                cell,
                pool,
                client=client,
                cache_hit=True,
                binding=asdict(after.token.context),
            )
        return
    if dimension == "statement_cancellation":
        import pyodbc

        from tests.integration.test_sqlserver_transport import (
            test_native_cancellation_closes_handles_worker_and_server_request,
        )

        await test_native_cancellation_closes_handles_worker_and_server_request(
            (cell, config, before.token, pyodbc), services.transport
        )
        return
    if dimension == "writes":
        await assert_native_identity(services, before, cell)
        await run_writes(scenario, cell, pool, nonce, client=client)
        return
    await step("prepare")
    fixture = scenario.network
    offset = Path(fixture.observer_path).stat().st_size
    started = time.time()
    task = asyncio.create_task(
        services.transport.execute(config, before.token, "SELECT 1 AS value", (), write=False)
    )
    try:
        if dimension == "login_cancellation":
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                with Path(fixture.observer_path).open("rb") as stream:
                    stream.seek(offset)
                    events = [json.loads(line) for line in stream if line.strip()]
                if any(
                    e.get("nonce") == nonce
                    and e.get("source_id") == cell.source_id
                    and e.get("target_host") == cell.host
                    and e.get("event") == "login_started"
                    and e.get("timestamp", 0) >= started
                    for e in events
                ):
                    break
                await asyncio.sleep(0.05)
            else:
                raise AssertionError("Native login never became observable")
            assert not task.done(), "Login completed before cancellation"
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
            else:
                raise AssertionError("Native login cancellation was ignored")
            async with asyncio.timeout(fixture.cleanup_seconds):
                while services.transport._running:
                    await asyncio.sleep(0.05)
        else:
            from interlock.connections.sqlserver import SqlServerTransportError

            try:
                await task
            except SqlServerTransportError:
                pass
            else:
                raise AssertionError("Native TLS/redirect rejection did not occur")
        assert_network_evidence(
            fixture,
            offset,
            nonce=nonce,
            source_id=cell.source_id,
            target_host=cell.host,
            started_at=started,
            dimension=dimension,
        )
    finally:
        if not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
        await step("cleanup")


async def run_writes(scenario, cell, pool, nonce, *, client=None):
    for step in scenario.write.steps:
        mark = await audit_watermark(pool)
        correlation_id = uuid.uuid4().hex
        approval_id = None
        response = await gateway_response(
            scenario.probe,
            cell.source_id,
            sql=step.sql,
            parameters=step.parameters,
            client=client,
            correlation_id=correlation_id,
        )
        assert response.status_code in {200, 202}, "Governed fixture write was refused"
        if response.status_code == 202:
            approval_id = response_rows(response).get("approval_id")
            assert (
                isinstance(approval_id, int) and approval_id > 0
            ), "No valid write approval returned"
            assert "approve" in scenario.hooks, "Explicit operator approval step required"
            await run_hook(
                scenario.hooks["approve"],
                source_id=cell.source_id,
                nonce=nonce,
                approval_id=approval_id,
            )
            row = await pool.fetchrow(
                "SELECT status FROM write_approval_queue WHERE id=$1 AND source_id=$2",
                approval_id,
                cell.source_id,
            )
            assert row and row["status"] == "executed", "Approved fixture write did not execute"
        await observed_audit(
            pool,
            mark,
            cell.source_id,
            scenario.probe.actor_id,
            "success",
            operation="write",
            correlation_id=correlation_id,
            approval_id=approval_id,
        )
        response = await gateway_response(
            scenario.probe, cell.source_id, sql=step.read_sql, parameters=[], client=client
        )
        assert response.status_code == 200, "Write read-back refused"
        assert (
            response_rows(response) == step.expected_rows
        ), "Write read-back differs from expected state"
