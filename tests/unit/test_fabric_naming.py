import pytest

from interlock.core.source_roles import SourceRoleEvaluator, build_permission_request
from interlock.core.sql_columns import column_access
from interlock.core.sql_governance import naming_for, resolve_table
from tests.unit.test_source_roles import FakePool, stmt


def naming(cs):
    return naming_for(
        "fabric_sql",
        {"database": "Demo"},
        {"database": "Demo", "default_schema": "dbo", "identifier_case_sensitive": cs},
        frozenset({("dbo", "Users"), ("dbo", "users")} if cs else {("dbo", "Users")}),
        (
            {("dbo", "Users"): ("Name", "name"), ("dbo", "users"): ("Name",)}
            if cs
            else {("dbo", "Users"): ("Name",)}
        ),
    )


@pytest.mark.parametrize(
    "cs,table,column,allowed",
    [
        (True, "dbo.Users", "Name", True),
        (True, "dbo.users", "Name", False),
        (True, "dbo.Users", "name", False),
        (False, "DBO.USERS", "NAME", False),
    ],
)
@pytest.mark.asyncio
async def test_case_distinct_column_grants_and_denies(cs, table, column, allowed):
    evaluator = SourceRoleEvaluator(
        FakePool(
            [
                stmt(permission_id=1, resource_pattern="dbo.Users.Name", resource_type="db.column"),
                stmt(permission_id=2, effect="deny", resource_pattern="dbo.users.*"),
                stmt(
                    permission_id=3,
                    effect="deny",
                    resource_pattern="dbo.Users.name",
                    resource_type="db.column",
                ),
            ]
        )
    )
    request = build_permission_request(
        protocol="fabric_sql",
        source_id="fabric",
        identity_id=1,
        operation="SELECT",
        tables=[table],
        columns=[column],
        naming=naming(cs),
    )
    assert (await evaluator.evaluate(request)).allowed is allowed


@pytest.mark.parametrize(
    "cs,table,allowed",
    [(True, "dbo.Users", True), (True, "dbo.users", False), (False, "DBO.USERS", False)],
)
@pytest.mark.asyncio
async def test_case_distinct_table_grants_and_denies(cs, table, allowed):
    evaluator = SourceRoleEvaluator(
        FakePool(
            [
                stmt(permission_id=1, resource_pattern="dbo.Users.*"),
                stmt(permission_id=2, effect="deny", resource_pattern="dbo.users.*"),
            ]
        )
    )
    request = build_permission_request(
        protocol="fabric_sql",
        source_id="fabric",
        identity_id=1,
        operation="SELECT",
        tables=[table],
        naming=naming(cs),
    )
    assert (await evaluator.evaluate(request)).allowed is allowed


def test_unknown_fabric_naming_refuses_scope_without_guessing_dbo_or_collation():
    resolved = resolve_table("Users", naming_for("fabric_sql", {"endpoint_type": "warehouse"}))
    assert resolved.refusal and "catalog" in resolved.refusal.lower()


def test_same_database_resolves_but_cross_database_and_ambiguous_scope_refused():
    n = naming(True)
    assert resolve_table("Demo.dbo.Users", n).canonical == "dbo.Users"
    assert resolve_table("other.dbo.Users", n).refusal
    assert resolve_table("server.Demo.dbo.Users", n).refusal


def test_column_analysis_preserves_native_case():
    n = naming(True)
    access = column_access(
        "SELECT Name FROM dbo.Users WHERE name = 1",
        dialect="tsql",
        resolve=lambda t: resolve_table(t, n).canonical,
        catalog=n.columns,
        case_sensitive=True,
    )
    assert access.columns == {"dbo.Users": {"Name", "name"}}


@pytest.mark.parametrize(
    "cs,condition,allowed",
    [
        (True, {"tables": ["dbo.users"]}, True),
        (True, {"columns": ["name"]}, True),
        (True, {"columns": ["Name"]}, False),
        (False, {"tables": ["DBO.USERS"]}, False),
        (False, {"columns": ["NAME"]}, False),
    ],
)
def test_policy_denies_respect_database_identifier_comparison(cs, condition, allowed):
    from tests.unit.test_policy import _identity, _make_engine, _rule

    engine = _make_engine([_rule(effect="deny", conditions=condition), _rule(rule_id=2)])
    result = engine.evaluate(
        _identity(),
        "fabric",
        "read",
        tables=["dbo.Users"],
        columns=["Name"],
        deny_table_spellings={"dbo.Users", "Users"},
        deny_column_spellings={"Name", "Users.Name", "dbo.Users.Name"},
        identifier_case_sensitive=cs,
    )
    assert result.allowed is allowed


def test_ci_column_analysis_resolves_ascii_aliases_to_catalog_native_names():
    n = naming(False)
    access = column_access(
        "SELECT NAME FROM DBO.USERS",
        dialect="tsql",
        resolve=lambda t: resolve_table(t, n).canonical,
        catalog=n.columns,
        native_identifiers=True,
    )
    assert access.columns == {"dbo.Users": {"Name"}}


@pytest.mark.parametrize("table", ["dbo.Users ", "dbo.Üsers"])
def test_ci_scope_refuses_unsupported_equivalences(table):
    assert resolve_table(table, naming(False)).refusal


@pytest.mark.asyncio
async def test_gateway_preserves_native_columns_before_real_role_evaluation():
    from types import SimpleNamespace
    from unittest.mock import AsyncMock

    from interlock.gateway.pipeline import GatewayPipeline, sql_gateway_request

    pipeline = GatewayPipeline(
        sql_naming=SimpleNamespace(naming_for_source=AsyncMock(return_value=naming(True)))
    )
    view = await pipeline.governance_view(
        sql_gateway_request(
            "SELECT Name FROM dbo.Users", protocol="mcp", source_id="fabric", dialect="tsql"
        ),
        identity_id=1,
    )
    evaluator = SourceRoleEvaluator(
        FakePool(
            [
                stmt(permission_id=1, resource_pattern="dbo.Users.Name", resource_type="db.column"),
                stmt(
                    permission_id=2,
                    effect="deny",
                    resource_pattern="dbo.Users.name",
                    resource_type="db.column",
                ),
            ]
        )
    )
    assert view.permission_request.resources == ["dbo.Users.Name"]
    assert (await evaluator.evaluate(view.permission_request)).allowed


@pytest.mark.asyncio
async def test_gateway_with_missing_naming_resolver_refuses_fabric_table_scope():
    from interlock.gateway.pipeline import GatewayPipeline, sql_gateway_request

    view = await GatewayPipeline().governance_view(
        sql_gateway_request(
            "SELECT Name FROM dbo.Users",
            protocol="mcp",
            source_id="fabric",
            dialect="tsql",
            metadata={"connector_key": "fabric_sql"},
        ),
        identity_id=1,
    )
    assert view.permission_request.naming_refusals
