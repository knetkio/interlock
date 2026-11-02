"""SQL Normalizer and Fingerprinter.

Normalizes SQL queries for deterministic cache keying by:
- Parsing with ``sqlglot``.
- Replacing literal constants with ``$N`` placeholders.
- Sorting AND-joined WHERE conditions for deterministic fingerprints.
- Generating a SHA-256 fingerprint from source_id + normalized SQL + role context.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Literal, get_args

import sqlglot
from sqlglot import exp
from sqlglot.errors import ParseError

from interlock.models import NormalizedQuery

# SQL dialect per connector, for parsing only.
#
# The normalizer used to parse every statement as PostgreSQL. MySQL's own
# identifier quoting - backticks - is not PostgreSQL syntax, so a plain
# `SELECT label FROM `tbl`` failed to parse and was classified as an unknown
# high-risk write with no tables, which source roles then refused. Backticks
# are idiomatic MySQL, are emitted by ORMs and by mysqldump, and are *required*
# for reserved-word identifiers, so those were unreachable through the proxy.
#
# The dialect has to be correct rather than guessed. Trying dialects until one
# parses would risk reading a write as a read under the wrong grammar, which
# is the one direction that must never happen.
_SQLGLOT_DIALECTS: dict[str, str] = {
    "postgresql": "postgres",
    "postgres": "postgres",
    "mysql": "mysql",
    "mariadb": "mysql",
    "snowflake": "snowflake",
    "bigquery": "bigquery",
    "mssql": "tsql",
    "fabric_sql": "tsql",
    "sqlserver": "tsql",
}

DEFAULT_DIALECT = "postgres"


def dialect_for(source_type: str | None) -> str:
    """Map a connector key or source type to a sqlglot dialect.

    Unknown values fall back to PostgreSQL, which is what every caller got
    before this existed - so an unmapped connector is no worse off than it was,
    and a mapped one is correct.
    """
    if not source_type:
        return DEFAULT_DIALECT
    return _SQLGLOT_DIALECTS.get(str(source_type).strip().lower(), DEFAULT_DIALECT)


def normalize_sql(
    sql: str,
    source_id: str,
    role_context: str | None = None,
    dialect: str = DEFAULT_DIALECT,
) -> NormalizedQuery | list[NormalizedQuery]:
    """Normalize a SQL query for deterministic cache keying.

    `dialect` selects the grammar used to *parse*. The normalized output stays
    in one canonical dialect regardless, so cache keys are unaffected by which
    grammar read the statement - and normalized SQL is never executed, only
    keyed on.
    """

    if not sql or not sql.strip():
        fingerprint = _make_fingerprint("", source_id, role_context)
        return NormalizedQuery(
            original_sql=sql or "",
            normalized_sql=None,
            fingerprint=fingerprint,
            parse_error=True,
        )

    try:
        statements = sqlglot.parse(sql, read=dialect)
    except ParseError:
        fingerprint = _make_fingerprint(sql, source_id, role_context)
        return NormalizedQuery(
            original_sql=sql,
            normalized_sql=None,
            fingerprint=fingerprint,
            parse_error=True,
        )

    statements = [stmt for stmt in statements if stmt is not None]
    if not statements:
        fingerprint = _make_fingerprint("", source_id, role_context)
        return NormalizedQuery(
            original_sql=sql,
            normalized_sql=None,
            fingerprint=fingerprint,
            parse_error=True,
        )
    if len(statements) > 1:
        return [
            _normalize_expression(
                stmt,
                stmt.sql(dialect="postgres"),
                source_id,
                role_context,
                preserve_case=dialect == "tsql",
            )
            for stmt in statements
        ]
    return _normalize_expression(
        statements[0], sql, source_id, role_context, preserve_case=dialect == "tsql"
    )


def _normalize_expression(
    statement: exp.Expression,
    original_sql: str,
    source_id: str,
    role_context: str | None,
    *,
    preserve_case: bool = False,
) -> NormalizedQuery:
    tables = _extract_tables(statement)
    operation = (
        "SELECT"
        if preserve_case and isinstance(statement, exp.Query)
        else _detect_operation(statement)
    )
    normalized_tree = statement.copy()
    normalized_tree = _sort_and_conditions(normalized_tree)
    params = _replace_literals(normalized_tree)
    normalized = normalized_tree.sql(dialect="postgres", normalize=not preserve_case)
    fingerprint = _make_fingerprint(normalized, source_id, role_context)
    return NormalizedQuery(
        original_sql=original_sql,
        normalized_sql=normalized,
        fingerprint=fingerprint,
        parameters=params,
        tables=sorted(tables),
        operation=operation,
        parse_error=False,
    )


def _make_fingerprint(
    normalized_sql: str,
    source_id: str,
    role_context: str | None,
) -> str:
    sep = "\x1f"
    payload = sep.join((source_id, normalized_sql, role_context or ""))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


CacheProtocol = Literal["postgresql", "mcp"]
"""The wire format a cached entry is stored in.

PostgreSQL caches raw wire-protocol bytes and writes them straight to the
socket; MCP caches the JSON it returns to the agent. The two are not
interchangeable, so the protocol is part of every key.
"""


def compute_cache_key(
    source_id: str,
    normalized_sql: str,
    *,
    protocol: CacheProtocol,
    parameters: list[Any] | tuple[Any, ...] | dict[str, Any] | None = None,
    identity_role: str | None = None,
    mapped_pg_role: str | None = None,
    tenant_id: str | None = None,
    grants_version: str | None = None,
    policy_scope_hash: str | None = None,
    source_generation: int | None = None,
    upstream_identity_scope: str | None = None,
) -> str:
    """Identity-aware cache key.

    `source_role_scope_hash` used to sit between `grants_version` and
    `policy_scope_hash`. No call site ever populated it, and it read as a
    security-relevant dimension that was silently always empty - which is what
    led an earlier audit to report a cache-isolation hole that did not exist.
    Source-role scope does reach the key, by a different door:
    `_decision_scope_hash` folds the source-role decision into its payload and
    the call sites pass that digest as `policy_scope_hash`.

    Removing it changed the key format, since the payload is positional and
    separator-delimited, so the version tag moved to v5. That tag exists for
    exactly this. Stranding is bounded: L2 is Redis with a 300s TTL, and a
    changed key is a miss rather than a wrong hit.

    v6 adds `protocol`, which is required. Before it, identical SQL from the
    same identity over MCP and over PostgreSQL shared one entry, and whichever
    protocol read second was handed the other's format: `psql` received MCP's
    JSON as wire bytes and lost synchronization, and an MCP agent could
    receive PostgreSQL wire bytes as its result. Found by an independent
    evaluation of rc.13.
    """

    if protocol not in get_args(CacheProtocol):
        raise ValueError(f"unknown cache protocol: {protocol!r}")
    sep = "\x1f"
    payload = sep.join(
        (
            "v6",
            protocol,
            source_id or "",
            normalized_sql or "",
            _stable_hash(parameters),
            str(0 if source_generation is None else int(source_generation)),
            tenant_id or "",
            identity_role or "",
            mapped_pg_role or "",
            grants_version or "",
            policy_scope_hash or "",
        )
    )
    if upstream_identity_scope is not None:
        # Existing connectors retain v6 byte-for-byte. Fabric binds every tier
        # to its authoritative saved principal/config and credential incarnation.
        payload = sep.join(("v7", payload, upstream_identity_scope))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _stable_hash(value: Any) -> str:
    if value in (None, [], {}, ()):
        return ""
    payload = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _replace_literals(tree: exp.Expression) -> list[Any]:
    params: list[Any] = []

    def replace(node: exp.Expression) -> exp.Expression:
        if isinstance(node, exp.Null):
            params.append(None)
            return exp.Var(this=f"${len(params)}")
        if isinstance(node, exp.Boolean):
            params.append(bool(node.this))
            return exp.Var(this=f"${len(params)}")
        if isinstance(node, exp.Literal):
            raw = str(node.this)
            if node.is_number and "." in raw:
                params.append(float(raw))
            else:
                params.append(node.to_py())
            return exp.Var(this=f"${len(params)}")
        if isinstance(node, exp.Placeholder):
            params.append(f"${node.name}")
            return exp.Var(this=f"${len(params)}")
        return node

    tree.transform(replace, copy=False)
    return params


def _sort_and_conditions(tree: exp.Expression) -> exp.Expression:
    def sort_node(node: exp.Expression) -> exp.Expression:
        if not isinstance(node, exp.And):
            return node
        terms = _flatten_and(node)
        terms = sorted(terms, key=lambda item: item.sql(dialect="postgres", normalize=True))
        return _build_and(terms)

    tree.transform(sort_node, copy=False)
    return tree


def _flatten_and(node: exp.Expression) -> list[exp.Expression]:
    if isinstance(node, exp.And):
        return _flatten_and(node.this) + _flatten_and(node.expression)
    return [node]


def _build_and(terms: list[exp.Expression]) -> exp.Expression:
    if not terms:
        return exp.true()
    current = terms[0]
    for term in terms[1:]:
        current = exp.and_(current, term, copy=False)
    return current


def _extract_tables(statement: exp.Expression) -> list[str]:
    cte_aliases = {
        str(cte.alias) for cte in statement.find_all(exp.CTE) if getattr(cte, "alias", None)
    }
    tables: list[str] = []
    for table in statement.find_all(exp.Table):
        name = _table_name(table)
        if not name or name in cte_aliases:
            continue
        if name not in tables:
            tables.append(name)
    return tables


def _table_name(table: exp.Table) -> str:
    # All three parts: dropping the database let `otherdb.sch.t` pass as
    # `sch.t`, which a role scoped to the configured database would match.
    if not table.name:
        return ""
    return ".".join(part for part in (table.catalog, table.db, table.name) if part)


def _detect_operation(statement: exp.Expression) -> str | None:
    if isinstance(statement, exp.TruncateTable):
        return "TRUNCATE"
    key = statement.key
    return key.upper() if key else type(statement).__name__.upper()
