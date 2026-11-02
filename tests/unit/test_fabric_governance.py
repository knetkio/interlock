"""Final Fabric results and approval acceptance use real governance components."""

import json
from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from interlock.core.source_roles import SourceRoleEvaluator
from interlock.core.write_classifier import WriteClassifier
from tests.unit.test_fabric_cache_scope import setup
from tests.unit.test_fabric_naming import naming
from tests.unit.test_policy import _identity, _make_engine, _rule
from tests.unit.test_source_roles import FakePool, stmt


def governed(*, statements=None, rules=None, cs=True):
    parts = setup()
    _, _, transport, _, _, request, _ = parts
    state = request.app.state
    state.sql_naming_resolver = SimpleNamespace(
        naming_for_source=AsyncMock(
            return_value=replace(
                naming(cs), relation_types={pair: "table" for pair in naming(cs).known_tables}
            )
        )
    )
    state.source_role_evaluator = SourceRoleEvaluator(
        FakePool(
            statements
            if statements is not None
            else [stmt(permission_id=1, resource_pattern="dbo.Users.*")]
        )
    )
    state.policy_engine = _make_engine(rules or [_rule()])
    state.write_classifier = WriteClassifier(dialect="tsql")
    state.audit_logger = AsyncMock()
    request.state.identity = _identity()
    transport.execute.return_value = {
        "rows": [{"Name": "visible", "name": "private"}],
        "columns": ["Name", "name"],
    }
    return parts


async def run_query(request, adapter, args):
    from starlette.responses import JSONResponse

    from interlock.gateway.pipeline import GatewayPipeline, sql_gateway_request

    gw = sql_gateway_request(
        args["sql"],
        protocol="mcp",
        source_id="saved",
        dialect="tsql",
        metadata={"connector_key": "fabric_sql"},
    )
    gw.metadata["upstream_identity"] = await adapter._fabric_identity_binding(
        request, request.app.state.registry.get("saved")
    )
    gw.identity = request.state.identity
    gw.parameters = args
    decision = await GatewayPipeline.from_state(request.app.state).preflight(gw)
    request.state.gateway_decision = decision
    if not decision.allowed:
        return JSONResponse({"error": decision.reason}, status_code=decision.status_code)
    return await adapter._execute_query(request, args)


@pytest.mark.asyncio
async def test_stale_star_cannot_return_or_cache_new_sensitive_column():
    _, _, transport, cache, _, request, adapter = governed(
        statements=[
            stmt(permission_id=1, resource_type="db.column", resource_pattern="dbo.Users.Name"),
            stmt(permission_id=2, resource_type="db.column", resource_pattern="dbo.Users.name"),
        ]
    )
    # Snapshot knew Name/name, origin now also has a sensitive new column.
    transport.execute.return_value = {
        "rows": [{"Name": "visible", "name": "ok", "Secret": "DO-NOT-RETURN"}],
        "columns": ["Name", "name", "Secret"],
    }
    response = await run_query(
        request, adapter, {"source_id": "saved", "sql": "SELECT * FROM dbo.Users"}
    )
    assert response.status_code != 200
    assert b"DO-NOT-RETURN" not in response.body
    assert not cache.entries
    assert request.app.state.audit_logger.log.call_args.args[0].status == "error"


@pytest.mark.asyncio
async def test_native_case_redaction_follows_expression_alias_without_redacting_other_column():
    _, _, transport, _, _, request, adapter = governed(
        rules=[_rule(actions={"effect": "allow", "redact_columns": ["dbo.Users.Name"]})]
    )
    transport.execute.return_value = {
        "rows": [{"Public": "hidden", "public": "visible"}],
        "columns": ["Public", "public"],
    }
    response = await run_query(
        request,
        adapter,
        {"source_id": "saved", "sql": "SELECT Name AS Public, name AS public FROM dbo.Users"},
    )
    assert response.status_code == 200
    payload = json.loads(json.loads(response.body)["content"][0]["text"])
    assert payload == [{"Public": "[REDACTED:POLICY]", "public": "visible"}]
    assert request.app.state.audit_logger.log.call_args.args[0].status == "success"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "sql",
    [
        "UPDATE dbo.Users SET Name = ?",
        "DELETE FROM dbo.Users",
        "INSERT INTO dbo.Users (Name) VALUES (?)",
    ],
)
async def test_read_role_denies_supported_parameterized_dml_before_transport(sql):
    _, _, transport, _, _, request, adapter = governed()
    response = await run_query(
        request, adapter, {"source_id": "saved", "sql": sql, "parameters": ["private"]}
    )
    assert response.status_code == 403
    transport.execute.assert_not_awaited()


@pytest.mark.asyncio
async def test_queued_fabric_write_preserves_ordered_sql_parameters():
    from interlock.core.approval_queue import ApprovalQueue
    from interlock.gateway.pipeline import GatewayPipeline, sql_gateway_request

    pool = SimpleNamespace(fetchval=AsyncMock(return_value=17))
    queue = ApprovalQueue(pool)
    _, _, _, _, _, request, _ = governed(
        statements=[stmt(permission_id=1, action="db.table.update", resource_pattern="dbo.Users.*")]
    )
    pipeline = GatewayPipeline(
        policy_engine=request.app.state.policy_engine,
        source_role_evaluator=request.app.state.source_role_evaluator,
        sql_naming=request.app.state.sql_naming_resolver,
        write_classifier=WriteClassifier(),
        approval_queue=queue,
    )
    gw = sql_gateway_request(
        "UPDATE dbo.Users SET Name = ?",
        protocol="mcp",
        source_id="saved",
        dialect="tsql",
        metadata={"connector_key": "fabric_sql"},
    )
    gw.identity = _identity()
    gw.parameters = {"parameters": ["safe-value"]}
    decision = await pipeline.preflight(gw)
    assert decision.status_code == 202
    assert pool.fetchval.call_args.args[-1]["parameters"] == ["safe-value"]


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT (SELECT t.* FOR JSON PATH) AS payload FROM dbo.Users AS t",
        "SELECT t.* FROM dbo.Users AS t FOR JSON PATH",
        "SELECT * FROM dbo.Users FOR XML PATH",
        "SELECT (SELECT t.* FOR XML PATH) AS payload FROM dbo.Users AS t",
    ],
)
def test_structured_wildcard_serialization_is_refused_at_fabric_grammar_boundary(sql):
    from interlock.connections.connectors import get_adapter

    with pytest.raises(ValueError):
        get_adapter("fabric_sql").validate_sql(sql)


@pytest.mark.asyncio
async def test_parameter_values_are_part_of_fabric_read_cache_identity():
    _, _, transport, _, _, request, adapter = governed()
    args = {
        "source_id": "saved",
        "sql": "SELECT Name FROM dbo.Users WHERE Name = ?",
        "parameters": ["first"],
    }
    transport.execute.return_value = {"rows": [{"Name": "first"}], "columns": ["Name"]}
    assert (await run_query(request, adapter, args)).status_code == 200
    transport.execute.return_value = {"rows": [{"Name": "second"}], "columns": ["Name"]}
    response = await run_query(request, adapter, args | {"parameters": ["second"]})
    assert json.loads(json.loads(response.body)["content"][0]["text"]) == [{"Name": "second"}]
    assert transport.execute.await_count == 2


@pytest.mark.asyncio
async def test_generation_change_after_governance_cannot_use_new_principal():
    from dataclasses import asdict, replace

    from interlock.gateway.pipeline import GatewayPipeline, sql_gateway_request

    store, _, transport, _, _, request, adapter = governed()
    gw = sql_gateway_request(
        "SELECT Name FROM dbo.Users",
        protocol="mcp",
        source_id="saved",
        dialect="tsql",
        metadata={"connector_key": "fabric_sql", "upstream_identity": asdict(store.context)},
    )
    gw.identity = request.state.identity
    request.state.gateway_decision = await GatewayPipeline.from_state(request.app.state).preflight(
        gw
    )
    assert request.state.gateway_decision.allowed
    store.context = replace(store.context, generation=2)
    response = await adapter._execute_query(request, {"source_id": "saved", "sql": gw.sql})
    assert response.status_code != 200
    transport.execute.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "cs,sql,allow",
    [
        (True, "SELECT Name FROM dbo.Users", True),
        (True, "SELECT name FROM dbo.Users", False),
        (True, "SELECT Name FROM dbo.users", False),
        (False, "SELECT NAME FROM DBO.USERS", False),
    ],
)
async def test_native_case_allow_and_deny_survive_final_query_pipeline(cs, sql, allow):
    _, _, transport, _, _, request, adapter = governed(
        cs=cs,
        statements=[
            stmt(permission_id=1, resource_type="db.column", resource_pattern="dbo.Users.Name"),
            stmt(
                permission_id=2,
                effect="deny",
                resource_type="db.column",
                resource_pattern="dbo.Users.name",
            ),
        ],
    )
    transport.execute.return_value = {"rows": [{"Name": "visible"}], "columns": ["Name"]}
    response = await run_query(request, adapter, {"source_id": "saved", "sql": sql})
    assert (response.status_code == 200) is allow
    assert transport.execute.await_count == int(allow)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "sql",
    [
        "WITH x AS (SELECT Name FROM dbo.Users) SELECT Name FROM x",
        "SELECT a.Name FROM dbo.Users a JOIN dbo.users b ON a.Name=b.Name",
    ],
)
async def test_ctes_and_joins_enforce_every_base_column_through_final_pipeline(sql):
    _, _, transport, _, _, request, adapter = governed(
        statements=[
            stmt(permission_id=1, resource_type="db.column", resource_pattern="dbo.Users.Name")
        ]
    )
    transport.execute.return_value = {"rows": [{"Name": "visible"}], "columns": ["Name"]}
    response = await run_query(request, adapter, {"source_id": "saved", "sql": sql})
    assert response.status_code == (403 if "JOIN" in sql else 200)
    assert transport.execute.await_count == (0 if "JOIN" in sql else 1)


@pytest.mark.asyncio
async def test_ci_unsupported_deny_spelling_cannot_silently_miss():
    _, _, transport, _, _, request, adapter = governed(
        cs=False,
        statements=[
            stmt(permission_id=1, resource_pattern="dbo.Users.*"),
            stmt(
                permission_id=2,
                effect="deny",
                resource_type="db.column",
                resource_pattern="dbo.Users.Naｍe",
            ),
        ],
    )
    response = await run_query(
        request, adapter, {"source_id": "saved", "sql": "SELECT Name FROM dbo.Users"}
    )
    assert response.status_code == 403
    transport.execute.assert_not_awaited()


@pytest.mark.asyncio
async def test_ci_unsupported_policy_spelling_cannot_silently_miss():
    _, _, transport, _, _, request, adapter = governed(
        cs=False, rules=[_rule(effect="deny", conditions={"columns": ["Naｍe"]}), _rule(rule_id=2)]
    )
    response = await run_query(
        request, adapter, {"source_id": "saved", "sql": "SELECT Name FROM dbo.Users"}
    )
    assert response.status_code == 403
    transport.execute.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "sql",
    [
        "SELECT Name AS x FROM dbo.Users UNION ALL SELECT Name AS y FROM dbo.users",
        "SELECT q.x FROM (SELECT Name AS x FROM dbo.Users UNION ALL SELECT Name AS y FROM dbo.users) q",
        "SELECT (SELECT MAX(Name) FROM dbo.Users) AS x",
    ],
)
async def test_policy_redaction_follows_union_and_scalar_subquery_lineage(sql):
    _, _, transport, _, _, request, adapter = governed(
        statements=[stmt(permission_id=1, resource_pattern="*.*")],
        rules=[_rule(redact_columns=["dbo.Users.Name"])],
    )
    transport.execute.return_value = {"rows": [{"x": "must-be-masked"}], "columns": ["x"]}
    response = await run_query(request, adapter, {"source_id": "saved", "sql": sql})
    assert response.status_code == 200
    assert json.loads(json.loads(response.body)["content"][0]["text"]) == [
        {"x": "[REDACTED:POLICY]"}
    ]


@pytest.mark.asyncio
async def test_low_risk_insert_executes_with_parameters_without_approval_queue():
    _, _, transport, _, _, request, adapter = governed(
        statements=[
            stmt(
                permission_id=1,
                action="db.table.insert",
                resource_type="db.column",
                resource_pattern="dbo.Users.Name",
            )
        ]
    )
    request.app.state.approval_queue = SimpleNamespace(submit=AsyncMock())
    transport.execute.return_value = {"rows": [], "columns": [], "row_count": 1}
    response = await run_query(
        request,
        adapter,
        {
            "source_id": "saved",
            "sql": "INSERT INTO dbo.Users (Name) VALUES (?)",
            "parameters": ["exact-value"],
        },
    )
    assert response.status_code == 200
    assert transport.execute.call_args.args[3] == ("exact-value",)
    assert transport.execute.call_args.kwargs["write"] is True
    request.app.state.approval_queue.submit.assert_not_awaited()


@pytest.mark.asyncio
async def test_cached_unknown_star_shape_is_not_delivered():
    _, _, transport, cache, _, request, adapter = governed()
    args = {"source_id": "saved", "sql": "SELECT * FROM dbo.Users"}
    assert (await run_query(request, adapter, args)).status_code == 200
    key = next(iter(cache.entries))
    _, metadata = cache.entries[key]
    cache.entries[key] = (b'[{"Name":"fine","name":"fine","Secret":"never-deliver"}]', metadata)
    transport.execute.return_value = {
        "rows": [{"Name": "fresh", "name": "fine"}],
        "columns": ["Name", "name"],
    }
    response = await run_query(request, adapter, args)
    assert response.status_code == 200 and b"never-deliver" not in response.body
    assert transport.execute.await_count == 2


@pytest.mark.asyncio
async def test_access_description_uses_native_case_for_provider_only_uppercase_fabric():
    _, _, _, _, source, request, adapter = governed(
        statements=[
            stmt(permission_id=1, resource_type="db.column", resource_pattern="dbo.Users.Name"),
            stmt(
                permission_id=2,
                effect="deny",
                resource_type="db.column",
                resource_pattern="dbo.Users.name",
            ),
        ]
    )
    source.metadata = {"provider": "FABRIC_SQL"}
    view = await adapter._resources_view(request, request.state.identity, "saved")
    assert view["enforced"] is True
    assert [entry["table"] for entry in view["tables"]] == ["dbo.Users"]
    assert view["tables"][0]["columns"] == ["Name"]


@pytest.mark.asyncio
async def test_quoted_space_and_unicode_native_identifiers_keep_exact_permissions():
    from interlock.core.sql_governance import naming_for

    _, _, transport, _, _, request, adapter = governed(
        statements=[
            stmt(
                permission_id=1,
                resource_type="db.column",
                resource_pattern="Sales Team.People List.Náme",
            )
        ]
    )
    request.app.state.sql_naming_resolver.naming_for_source.return_value = naming_for(
        "fabric_sql",
        {"database": "Demo"},
        {"database": "Demo", "default_schema": "Sales Team", "identifier_case_sensitive": True},
        frozenset({("Sales Team", "People List")}),
        {("Sales Team", "People List"): ("Náme",)},
    )
    transport.execute.return_value = {"rows": [{"Náme": "visible"}], "columns": ["Náme"]}
    response = await run_query(
        request,
        adapter,
        {"source_id": "saved", "sql": "SELECT [Náme] FROM [Sales Team].[People List]"},
    )
    assert response.status_code == 200
    transport.execute.assert_awaited_once()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "sql,want",
    [
        ("SELECT Name FROM dbo.Users", 200),
        ("INSERT INTO dbo.Users (Name) VALUES (?)", 403),
        ("UPDATE dbo.Users SET Name=?", 403),
        ("DELETE FROM dbo.Users", 403),
    ],
)
async def test_views_are_readable_but_never_become_supported_write_targets(sql, want):
    from dataclasses import replace

    _, _, transport, _, _, request, adapter = governed(
        statements=[stmt(permission_id=1, action="*", resource_pattern="dbo.Users.*")]
    )
    current = request.app.state.sql_naming_resolver.naming_for_source.return_value
    request.app.state.sql_naming_resolver.naming_for_source.return_value = replace(
        current, relation_types={("dbo", "Users"): "view"}
    )
    transport.execute.return_value = {"rows": [{"Name": "visible"}], "columns": ["Name"]}
    response = await run_query(
        request, adapter, {"source_id": "saved", "sql": sql, "parameters": ["value"]}
    )
    assert response.status_code == want
    assert transport.execute.await_count == int(want == 200)


@pytest.mark.asyncio
async def test_unknown_relation_kind_does_not_imply_writable_table():
    _, _, transport, _, _, request, adapter = governed(
        statements=[stmt(permission_id=1, action="db.table.insert", resource_pattern="dbo.Users.*")]
    )
    current = request.app.state.sql_naming_resolver.naming_for_source.return_value
    request.app.state.sql_naming_resolver.naming_for_source.return_value = replace(
        current, relation_types=None
    )
    response = await run_query(
        request,
        adapter,
        {
            "source_id": "saved",
            "sql": "INSERT INTO dbo.Users (Name) VALUES (?)",
            "parameters": ["value"],
        },
    )
    assert response.status_code == 403
    transport.execute.assert_not_awaited()


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT Name AS x FROM dbo.users UNION ALL SELECT * FROM dbo.Users",
        "SELECT (SELECT t.*) AS payload FROM dbo.Users AS t",
    ],
)
def test_fixed_output_alias_cannot_hide_a_changed_wildcard_origin(sql):
    from interlock.connections.connectors import get_adapter

    with pytest.raises(ValueError):
        get_adapter("fabric_sql").validate_sql(sql)


@pytest.mark.parametrize(
    "sql",
    [
        "WITH c(x) AS (SELECT * FROM dbo.Users) SELECT x FROM c",
        "SELECT x FROM (SELECT * FROM dbo.Users) AS c(x)",
    ],
)
def test_positional_alias_lists_cannot_hide_changed_wildcard_origins(sql):
    from interlock.connections.connectors import get_adapter

    with pytest.raises(ValueError):
        get_adapter("fabric_sql").validate_sql(sql)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "sql",
    [
        "WITH c(x) AS (SELECT Name FROM dbo.Users) SELECT x FROM c",
        "SELECT x FROM (SELECT Name FROM dbo.Users) AS c(x)",
    ],
)
async def test_explicit_positional_alias_lists_keep_native_redaction(sql):
    _, _, transport, _, _, request, adapter = governed(
        rules=[_rule(redact_columns=["dbo.Users.Name"])]
    )
    transport.execute.return_value = {"rows": [{"x": "must-be-masked"}], "columns": ["x"]}
    response = await run_query(request, adapter, {"source_id": "saved", "sql": sql})
    assert response.status_code == 200
    assert json.loads(json.loads(response.body)["content"][0]["text"]) == [
        {"x": "[REDACTED:POLICY]"}
    ]
