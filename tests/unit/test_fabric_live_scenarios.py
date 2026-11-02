"""Synthetic tooling checks only; no native or customer acceptance evidence."""

from __future__ import annotations

import importlib
import importlib.util
import json
import sys

import httpx
import pytest


def runner():
    assert (
        importlib.util.find_spec("tests.integration.fabric_live_scenarios") is not None
    ), "Executable Fabric acceptance scenarios are missing"
    return importlib.import_module("tests.integration.fabric_live_scenarios")


def book(kind="audit"):
    return {
        "allowed_gateway_origins": ["http://127.0.0.1:23001"],
        "cells": {
            "warehouse/oauth": {
                kind: {
                    "probe": {
                        "gateway_url": "http://127.0.0.1:23001",
                        "actor_key_ref": "env://SCENARIO_ACTOR",
                        "actor_id": 7,
                        "sql": "SELECT Name FROM dbo.Fixture",
                        "expected_rows": [{"Name": "visible"}],
                    }
                }
            }
        },
    }


def test_scenario_schema_requires_explicit_origins_and_rejects_pass_flags_and_shell():
    mod = runner()
    assert mod.load_scenarios(book()).cells["warehouse/oauth"]["audit"].probe.actor_id == 7
    for mutate in [
        lambda x: x.update(passed=True),
        lambda x: x["cells"]["warehouse/oauth"]["audit"]["probe"].update(
            gateway_url="https://different.example"
        ),
        lambda x: x["cells"]["warehouse/oauth"]["audit"].update(
            hooks={"prepare": {"argv": ["sh", "-c", "true"]}}
        ),
    ]:
        value = book()
        mutate(value)
        with pytest.raises(ValueError, match="scenario"):
            mod.load_scenarios(value)


def test_read_probe_rejects_writes_and_missing_lifecycle_actions():
    mod = runner()
    value = book()
    value["cells"]["warehouse/oauth"]["audit"]["probe"]["sql"] = "DELETE FROM dbo.Fixture"
    with pytest.raises(ValueError, match="scenario"):
        mod.load_scenarios(value)
    with pytest.raises(ValueError, match="scenario"):
        mod.load_scenarios(book("spn_rotation"))


async def test_operator_hook_executes_bounded_command_without_inheriting_ambient_keys(
    tmp_path, monkeypatch
):
    mod = runner()
    output = tmp_path / "observed.json"
    program = tmp_path / "step.py"
    program.write_text(
        "import os,json,pathlib; pathlib.Path(os.environ['OUTPUT_PATH']).write_text("
        "json.dumps({'source':os.environ['FABRIC_ACCEPTANCE_SOURCE_ID'],"
        "'nonce':os.environ['FABRIC_ACCEPTANCE_NONCE'],"
        "'ambient':os.environ.get('ANTHROPIC_API_KEY')}))"
    )
    monkeypatch.setenv("ANTHROPIC_API_KEY", "must-not-inherit")
    monkeypatch.setenv("TEST_OUTPUT_PATH", str(output))
    hook = mod.OperatorHook(
        argv=[sys.executable, str(program)],
        secret_env={"OUTPUT_PATH": "env://TEST_OUTPUT_PATH"},
        timeout_seconds=3,
    )
    await mod.run_hook(hook, source_id="saved", nonce="run-1")
    assert json.loads(output.read_text()) == {"source": "saved", "nonce": "run-1", "ambient": None}
    with pytest.raises(ValueError):
        mod.OperatorHook(argv=[sys.executable], timeout_seconds=61)


def test_network_evidence_requires_fresh_bound_positive_allowed_and_blocked_events(tmp_path):
    mod = runner()
    path = tmp_path / "events.jsonl"
    event = {
        "nonce": "run-1",
        "source_id": "saved",
        "target_host": "sql.example",
        "destination": "sql.example:1433",
        "action": "allowed",
        "event": "connect",
        "timestamp": 1234.0,
    }
    path.write_text(json.dumps(event) + "\n")
    offset = path.stat().st_size
    blocked = event | {
        "destination": "forbidden.example:1433",
        "action": "blocked",
        "event": "redirect",
    }
    with path.open("a") as stream:
        stream.write(json.dumps(blocked | {"nonce": "older-run"}) + "\n")
    fixture = mod.NetworkFixture(
        observer_path=str(path),
        allowed_destination="sql.example:1433",
        blocked_destination="forbidden.example:1433",
    )
    with pytest.raises(AssertionError):
        mod.assert_network_evidence(
            fixture,
            offset,
            nonce="run-1",
            source_id="saved",
            target_host="sql.example",
            started_at=1233.0,
            dimension="driver_redirect_egress",
        )
    with path.open("a") as stream:
        stream.write(json.dumps(event) + "\n" + json.dumps(blocked) + "\n")
    mod.assert_network_evidence(
        fixture,
        offset,
        nonce="run-1",
        source_id="saved",
        target_host="sql.example",
        started_at=1233.0,
        dimension="driver_redirect_egress",
    )
    with path.open("a") as stream:
        stream.write(json.dumps(blocked | {"action": "allowed"}) + "\n")
    with pytest.raises(AssertionError, match="redirect"):
        mod.assert_network_evidence(
            fixture,
            offset,
            nonce="run-1",
            source_id="saved",
            target_host="sql.example",
            started_at=1233.0,
            dimension="driver_redirect_egress",
        )


async def test_governed_probe_denies_redirect_and_asserts_actual_masked_columns(monkeypatch):
    mod = runner()
    monkeypatch.setenv("SCENARIO_ACTOR", "synthetic-only-key")
    probe = mod.load_scenarios(book()).cells["warehouse/oauth"]["audit"].probe

    def handler(request):
        assert request.url.path == "/mcp/tools/call"
        assert request.headers["authorization"] == "Bearer synthetic-only-key"
        assert json.loads(request.content)["arguments"]["source_id"] == "saved"
        return httpx.Response(
            200, json={"content": [{"type": "text", "text": '[{"Name":"[REDACTED:POLICY]"}]'}]}
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        rows = await mod.query_gateway(probe, "saved", client=client, masked_columns=["Name"])
        assert rows == [{"Name": "[REDACTED:POLICY]"}]
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(
            lambda _: httpx.Response(302, headers={"location": "https://different.example"})
        )
    ) as client:
        with pytest.raises(AssertionError, match="status"):
            await mod.query_gateway(probe, "saved", client=client)


def test_write_fixture_requires_disposable_scope_and_readback_for_each_supported_action():
    mod = runner()
    with pytest.raises(ValueError):
        mod.WriteFixture(authorization="disposable_objects_only", table="dbo.Fixture", steps=[])
    steps = [
        {
            "sql": "INSERT INTO dbo.Fixture (id) VALUES (?)",
            "parameters": [1],
            "read_sql": "SELECT id FROM dbo.Fixture",
            "expected_rows": [{"id": 1}],
        },
        {
            "sql": "UPDATE dbo.Fixture SET id = ?",
            "parameters": [2],
            "read_sql": "SELECT id FROM dbo.Fixture",
            "expected_rows": [{"id": 2}],
        },
        {
            "sql": "DELETE FROM dbo.Fixture",
            "read_sql": "SELECT id FROM dbo.Fixture",
            "expected_rows": [],
        },
    ]
    assert (
        len(
            mod.WriteFixture(
                authorization="disposable_objects_only", table="dbo.Fixture", steps=steps
            ).steps
        )
        == 3
    )
    steps[0]["sql"] = "INSERT INTO dbo.Other (id) VALUES (?)"
    with pytest.raises(ValueError):
        mod.WriteFixture(authorization="disposable_objects_only", table="dbo.Fixture", steps=steps)


class AuditPool:
    """Synthetic control boundary; requires actual request correlation before returning a row."""

    def __init__(self):
        self.events = []
        self.approval_executed = False

    async def fetchval(self, sql):
        assert "MAX(id)" in sql
        return len(self.events)

    async def fetchrow(self, sql, *args):
        if "write_approval_queue" in sql:
            assert args == (23, "saved")
            return {"status": "executed" if self.approval_executed else "pending"}
        assert args[:3] == (len(self.events) - 1, "saved", 7)
        assert "request_metadata->>'correlation_id'=$6" in sql or "approval_id=$6" in sql
        event = self.events[-1]
        assert args[3] == event["status"] and args[4] == event["operation"]
        assert args[5] == (23 if "approval_id=$6" in sql else event["correlation_id"])
        return {"cache_hit": False, "request_metadata": {"upstream_identity": {"generation": 2}}}


async def test_audit_scenario_observes_correlated_actor_event_and_unmasked_redaction_fails(
    monkeypatch,
):
    from types import SimpleNamespace

    mod = runner()
    monkeypatch.setenv("SCENARIO_ACTOR", "synthetic-only-key")
    scenario = mod.load_scenarios(book()).cells["warehouse/oauth"]["audit"]
    pool = AuditPool()

    def handler(request):
        pool.events.append(
            {
                "correlation_id": request.headers["x-correlation-id"],
                "status": "success",
                "operation": "read",
            }
        )
        return httpx.Response(200, json={"content": [{"text": '[{"Name":"visible"}]'}]})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        await mod.run_scenario(
            "audit", scenario, SimpleNamespace(source_id="saved"), None, None, pool, client=client
        )
        scenario.masked_columns = ["Name"]
        with pytest.raises(AssertionError, match="unmasked"):
            await mod.run_scenario(
                "redaction",
                scenario,
                SimpleNamespace(source_id="saved"),
                None,
                None,
                pool,
                client=client,
            )


async def test_write_scenario_uses_governed_parameters_and_independent_readback(monkeypatch):
    from types import SimpleNamespace

    mod = runner()
    monkeypatch.setenv("SCENARIO_ACTOR", "synthetic-only-key")
    steps = [
        {
            "sql": "INSERT INTO dbo.Fixture (id) VALUES (?)",
            "parameters": [1],
            "read_sql": "SELECT id FROM dbo.Fixture",
            "expected_rows": [{"id": 1}],
        },
        {
            "sql": "UPDATE dbo.Fixture SET id = ?",
            "parameters": [2],
            "read_sql": "SELECT id FROM dbo.Fixture",
            "expected_rows": [{"id": 2}],
        },
        {
            "sql": "DELETE FROM dbo.Fixture",
            "read_sql": "SELECT id FROM dbo.Fixture",
            "expected_rows": [],
        },
    ]
    value = book("writes")
    value["cells"]["warehouse/oauth"]["writes"]["write"] = {
        "authorization": "disposable_objects_only",
        "table": "dbo.Fixture",
        "steps": steps,
    }
    scenario = mod.load_scenarios(value).cells["warehouse/oauth"]["writes"]
    pool = AuditPool()
    state = []

    def handler(request):
        args = json.loads(request.content)["arguments"]
        query = args["sql"]
        if not query.startswith("SELECT"):
            assert args["parameters"] == (
                [1] if query.startswith("INSERT") else [2] if query.startswith("UPDATE") else []
            )
            state[:] = [{"id": args["parameters"][0]}] if args["parameters"] else []
            pool.events.append(
                {
                    "correlation_id": request.headers["x-correlation-id"],
                    "status": "success",
                    "operation": "write",
                }
            )
        return httpx.Response(200, json={"content": [{"text": json.dumps(state)}]})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        await mod.run_writes(
            scenario, SimpleNamespace(source_id="saved"), pool, "run", client=client
        )
        assert state == [] and len(pool.events) == 3
        scenario.write.steps[0].expected_rows = [{"id": 99}]
        with pytest.raises(AssertionError, match="read-back"):
            await mod.run_writes(
                scenario, SimpleNamespace(source_id="saved"), pool, "run", client=client
            )


async def test_rotation_step_cannot_pass_without_a_new_generation(tmp_path, monkeypatch):
    from types import SimpleNamespace
    from unittest.mock import AsyncMock

    from interlock.connections.fabric.config import FabricConfig
    from interlock.connections.fabric.credentials import FabricCredentialContext
    from tests.integration.fabric_live_support import load_manifest
    from tests.unit.test_fabric_live_manifest import sample

    mod = runner()
    value = book("spn_rotation")
    case = value["cells"].pop("warehouse/oauth")
    case["spn_rotation"]["hooks"] = {
        "rotate": {"argv": [sys.executable, str(tmp_path / "noop.py")]}
    }
    (tmp_path / "noop.py").write_text("pass\n")
    value["cells"]["warehouse/spn"] = case
    scenario = mod.load_scenarios(value).cells["warehouse/spn"]["spn_rotation"]
    designation = sample()
    designation["cells"][0].update(auth_mode="spn", expected_account_id=None)
    cell = load_manifest(designation).cells[0]
    config = FabricConfig.from_mapping(
        dict(
            host=cell.host,
            database=cell.database,
            tenant_id=cell.tenant_id,
            client_id=cell.client_id,
            auth_mode="spn",
            endpoint_type="warehouse",
            client_secret_ref="env://DESIGNATED_SPN",
        )
    )
    context = FabricCredentialContext(
        cell.source_id, 1, cell.tenant_id, cell.client_id, None, "spn", "connected"
    )
    prepared = SimpleNamespace(token=SimpleNamespace(context=context, expires_at=2000))
    services = SimpleNamespace(
        prepare_source=AsyncMock(return_value=prepared),
        store=SimpleNamespace(
            current_source=AsyncMock(return_value=SimpleNamespace(config=config, context=context))
        ),
    )
    with pytest.raises(AssertionError, match="Generation"):
        await mod.run_scenario("spn_rotation", scenario, cell, config, services, None)


async def test_approval_hook_must_execute_before_successful_write_acceptance(tmp_path, monkeypatch):
    from types import SimpleNamespace

    mod = runner()
    monkeypatch.setenv("SCENARIO_ACTOR", "synthetic-only-key")
    approved = tmp_path / "approved.txt"
    monkeypatch.setenv("APPROVAL_OBSERVATION_FILE", str(approved))
    program = tmp_path / "approve.py"
    program.write_text(
        "import os,pathlib; pathlib.Path(os.environ['OUTPUT']).write_text(os.environ['FABRIC_ACCEPTANCE_APPROVAL_ID'])"
    )
    steps = [
        {
            "sql": "INSERT INTO dbo.Fixture (id) VALUES (?)",
            "parameters": [1],
            "read_sql": "SELECT id FROM dbo.Fixture",
            "expected_rows": [{"id": 1}],
        },
        {
            "sql": "UPDATE dbo.Fixture SET id = ?",
            "parameters": [2],
            "read_sql": "SELECT id FROM dbo.Fixture",
            "expected_rows": [{"id": 2}],
        },
        {
            "sql": "DELETE FROM dbo.Fixture",
            "read_sql": "SELECT id FROM dbo.Fixture",
            "expected_rows": [],
        },
    ]
    value = book("writes")
    value["cells"]["warehouse/oauth"]["writes"].update(
        write={"authorization": "disposable_objects_only", "table": "dbo.Fixture", "steps": steps},
        hooks={
            "approve": {
                "argv": [sys.executable, str(program)],
                "secret_env": {"OUTPUT": "env://APPROVAL_OBSERVATION_FILE"},
            }
        },
    )
    scenario = mod.load_scenarios(value).cells["warehouse/oauth"]["writes"]

    class Pool(AuditPool):
        async def fetchrow(self, sql, *args):
            if "write_approval_queue" in sql:
                assert approved.read_text() == "23"
                self.events.append(
                    {"status": "success", "operation": "write", "correlation_id": "approval"}
                )
                return {"status": "executed"}
            return await super().fetchrow(sql, *args)

    pool = Pool()
    state = []

    def handler(request):
        args = json.loads(request.content)["arguments"]
        if args["sql"].startswith("INSERT"):
            state[:] = [{"id": 1}]
            return httpx.Response(202, json={"approval_id": 23})
        if not args["sql"].startswith("SELECT"):
            state[:] = [{"id": 2}] if args["parameters"] else []
            pool.events.append(
                {
                    "status": "success",
                    "operation": "write",
                    "correlation_id": request.headers["x-correlation-id"],
                }
            )
        return httpx.Response(200, json={"content": [{"text": json.dumps(state)}]})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        await mod.run_writes(
            scenario, SimpleNamespace(source_id="saved"), pool, "run", client=client
        )
    assert approved.read_text() == "23" and len(pool.events) == 3


@pytest.mark.parametrize("failure", ["prepare", "observer"])
@pytest.mark.parametrize("cleanup_fails", [False, True])
async def test_network_setup_failures_always_cleanup_and_preserve_primary_error(
    tmp_path, monkeypatch, failure, cleanup_fails
):
    from types import SimpleNamespace
    from unittest.mock import AsyncMock

    mod = runner()
    changed = tmp_path / "network-changed"
    cleaned = tmp_path / "cleanup-receipt"
    observer = tmp_path / "missing-observer.jsonl"
    prepare = tmp_path / "prepare.py"
    cleanup = tmp_path / "cleanup.py"
    prepare.write_text(
        'import os,pathlib,sys; pathlib.Path(os.environ["CHANGED"]).touch(); '
        f'sys.exit({3 if failure == "prepare" else 0})\n'
    )
    cleanup.write_text(
        'import os,pathlib,sys; pathlib.Path(os.environ["CHANGED"]).unlink(missing_ok=True); '
        'pathlib.Path(os.environ["CLEANED"]).touch(); '
        f"sys.exit({4 if cleanup_fails else 0})\n"
    )
    monkeypatch.setenv("SCENARIO_CHANGED", str(changed))
    monkeypatch.setenv("SCENARIO_CLEANED", str(cleaned))
    scenario = mod.Scenario(
        hooks={
            "prepare": mod.OperatorHook(
                argv=[sys.executable, str(prepare)],
                secret_env={"CHANGED": "env://SCENARIO_CHANGED"},
            ),
            "cleanup": mod.OperatorHook(
                argv=[sys.executable, str(cleanup)],
                secret_env={
                    "CHANGED": "env://SCENARIO_CHANGED",
                    "CLEANED": "env://SCENARIO_CLEANED",
                },
            ),
        },
        network=mod.NetworkFixture(
            observer_path=str(observer), allowed_destination="sql.example:1433"
        ),
    )
    services = SimpleNamespace(
        prepare_source=AsyncMock(return_value=SimpleNamespace(token=object())),
        transport=SimpleNamespace(execute=AsyncMock()),
    )
    error_type = AssertionError if failure == "prepare" else FileNotFoundError
    with pytest.raises(error_type) as raised:
        await mod.run_scenario(
            "tls_certificate_failure",
            scenario,
            SimpleNamespace(source_id="saved", host="sql.example"),
            None,
            services,
            None,
        )
    if failure == "prepare":
        assert "Operator scenario step failed" in str(raised.value)
    else:
        assert raised.value.filename == str(observer)
    assert cleaned.exists() and not changed.exists()
    services.transport.execute.assert_not_awaited()
    if cleanup_fails:
        assert "cleanup failed" in " ".join(raised.value.__notes__).lower()


async def test_network_observer_failure_cancels_and_awaits_started_transport(tmp_path, monkeypatch):
    import asyncio
    from types import SimpleNamespace
    from unittest.mock import AsyncMock

    mod = runner()
    observer = tmp_path / "observer.jsonl"
    cleaned = tmp_path / "cleaned"
    prepare = tmp_path / "prepare.py"
    cleanup = tmp_path / "cleanup.py"
    prepare.write_text('import os,pathlib; pathlib.Path(os.environ["OBSERVER"]).touch()\n')
    cleanup.write_text('import os,pathlib; pathlib.Path(os.environ["CLEANED"]).touch()\n')
    monkeypatch.setenv("SCENARIO_OBSERVER", str(observer))
    monkeypatch.setenv("SCENARIO_CLEANED", str(cleaned))
    scenario = mod.Scenario(
        hooks={
            "prepare": mod.OperatorHook(
                argv=[sys.executable, str(prepare)],
                secret_env={"OBSERVER": "env://SCENARIO_OBSERVER"},
            ),
            "cleanup": mod.OperatorHook(
                argv=[sys.executable, str(cleanup)],
                secret_env={"CLEANED": "env://SCENARIO_CLEANED"},
            ),
        },
        network=mod.NetworkFixture(
            observer_path=str(observer), allowed_destination="sql.example:1433"
        ),
    )
    stopped = asyncio.Event()

    async def native_boundary(*args, **kwargs):
        with observer.open("a") as stream:
            stream.write("invalid-json\n")
        try:
            await asyncio.Event().wait()
        finally:
            stopped.set()

    services = SimpleNamespace(
        prepare_source=AsyncMock(return_value=SimpleNamespace(token=object())),
        transport=SimpleNamespace(execute=native_boundary),
    )
    with pytest.raises(json.JSONDecodeError):
        await mod.run_scenario(
            "login_cancellation",
            scenario,
            SimpleNamespace(source_id="saved", host="sql.example"),
            None,
            services,
            None,
        )
    assert stopped.is_set() and cleaned.exists()
