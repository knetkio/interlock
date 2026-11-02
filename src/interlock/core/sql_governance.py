"""One derivation of what an SQL request touches, for enforcement and dry-runs.

Governance used to be derived three ways: the gateway parsed SQL one way, the
policy dry-run another, and the source-role dry-run not at all - it handed raw
SQL to a connector adapter that never parsed it and reported `db.execute_raw`
on `*` for a plain SELECT. A dry-run that disagrees with the
gateway tells an operator their roles are broken when they are not, or fine
when they are not. Everything that derives a permission request from SQL now
comes through here.

It also resolves table names the way the database does. Every unqualified
table used to become `public.<name>`, which is right only for a PostgreSQL
source whose search path starts with `public`. MySQL has no `public` schema,
so a role written against the real database name never matched; a PostgreSQL
login whose search path starts elsewhere was governed against the wrong
table. The source catalog records each source's search path and tables, so a
bare name resolves to the schema that actually holds it:

- PostgreSQL: the first schema on the scanning login's effective search path
  that holds the table. Schemas earlier on the path become deny-only shadows:
  the catalog can be stale, and a table created there since the last scan would
  win the lookup, so a deny on it must still fire.
- MySQL and MariaDB: the configured database.
- Snowflake: the configured schema, in the configured database. A reference
  into another database is refused rather than guessed at.

A legacy alias keeps roles written before this change working on MySQL and
Snowflake, where every bare name used to read `public.<table>`: allows and
denies are both checked against it, so an old deny cannot silently stop firing.
With no catalog yet, names resolve as they always did.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from interlock.core.normalizer import dialect_for, normalize_sql
from interlock.models import NormalizedQuery

LEGACY_SCHEMA = "public"

# Connector keys whose SQL names this module resolves.
_POSTGRES = frozenset({"postgresql", "postgres"})
_MYSQL = frozenset({"mysql", "mariadb"})
_SNOWFLAKE = frozenset({"snowflake"})


@dataclass(frozen=True, slots=True)
class SqlNaming:
    """How one source's database resolves a table name.

    `known_tables` is the catalog's `(schema, table)` pairs, lower-cased, or
    None when the source has no catalog yet - resolution then falls back to the
    configured default without claiming to have checked.
    """

    connector_key: str = "postgresql"
    default_schema: str = LEGACY_SCHEMA
    search_path: tuple[str, ...] = (LEGACY_SCHEMA,)
    database: str | None = None
    known_tables: frozenset[tuple[str, str]] | None = None
    # (schema, table) -> column names in ordinal order, lower-cased; None
    # before the source's first scan.
    columns: Mapping[tuple[str, str], tuple[str, ...]] | None = None

    identifier_case_sensitive: bool | None = None
    relation_types: Mapping[tuple[str, str], str] | None = None

    def identifier(self, value: str) -> str:
        return value if self.identifier_case_sensitive is True else value.lower()

    @property
    def dialect(self) -> str:
        return dialect_for(self.connector_key)

    @property
    def catalogued(self) -> bool:
        return self.known_tables is not None

    @property
    def legacy_alias(self) -> bool:
        return self.connector_key in _MYSQL or self.connector_key in _SNOWFLAKE


def legacy_naming(connector_key: str = "postgresql") -> SqlNaming:
    """Naming before the catalog: every bare name in `public`."""
    return SqlNaming(connector_key=connector_key)


def naming_for(
    connector_key: str,
    connection_config: dict[str, Any] | None = None,
    catalog_attributes: dict[str, Any] | None = None,
    known_tables: frozenset[tuple[str, str]] | None = None,
    columns: Mapping[tuple[str, str], tuple[str, ...]] | None = None,
    relation_types: Mapping[tuple[str, str], str] | None = None,
) -> SqlNaming:
    """Naming for one source, from its configuration and, if scanned, its catalog."""
    config = connection_config or {}
    facts = catalog_attributes or {}
    key = str(connector_key or "").lower()
    if key == "fabric_sql":
        case_sensitive = facts.get("identifier_case_sensitive")
        if not isinstance(case_sensitive, bool):
            case_sensitive = None
        return SqlNaming(
            connector_key=key,
            default_schema=str(facts.get("default_schema") or ""),
            search_path=(),
            database=str(facts.get("database") or config.get("database") or "") or None,
            known_tables=known_tables,
            columns=columns,
            identifier_case_sensitive=case_sensitive,
            relation_types=relation_types,
        )
    if key in _MYSQL:
        database = _lower(facts.get("default_schema") or config.get("database"))
        default = database or LEGACY_SCHEMA
        return SqlNaming(
            connector_key=key,
            default_schema=default,
            search_path=(default,),
            database=database,
            known_tables=known_tables,
            columns=columns,
        )
    if key in _SNOWFLAKE:
        default = _lower(facts.get("default_schema") or config.get("schema")) or LEGACY_SCHEMA
        return SqlNaming(
            connector_key=key,
            default_schema=default,
            search_path=(default,),
            database=_lower(facts.get("database") or config.get("database")),
            known_tables=known_tables,
            columns=columns,
        )
    if key in _POSTGRES:
        path = tuple(
            schema for schema in (_lower(s) for s in facts.get("effective_schemas") or []) if schema
        )
        if not path:
            return SqlNaming(connector_key="postgresql", known_tables=known_tables, columns=columns)
        return SqlNaming(
            connector_key="postgresql",
            default_schema=path[0],
            search_path=path,
            database=_lower(facts.get("database") or config.get("database")),
            known_tables=known_tables,
            columns=columns,
        )
    return legacy_naming(key or "postgresql")


def _lower(value: Any) -> str | None:
    text = str(value or "").strip().lower()
    return text or None


@dataclass(frozen=True, slots=True)
class ResolvedTable:
    """One table reference, as governance evaluates it."""

    written: str
    canonical: str
    aliases: tuple[str, ...] = ()
    shadows: tuple[str, ...] = ()
    resolved: bool = False
    refusal: str | None = None
    case_sensitive: bool = False


def resolve_table(written: str, naming: SqlNaming) -> ResolvedTable:
    """Resolve a table reference as written in SQL to `schema.table`."""
    if naming.connector_key == "fabric_sql":
        parts = written.split(".")
        canonical = written
        refusal = None
        if (
            naming.identifier_case_sensitive is None
            or not naming.default_schema
            or not naming.catalogued
        ):
            refusal = "Fabric catalog required: identifier collation, default schema, and native tables must be known"
        elif len(parts) > 3 or any(
            not p or p != p.strip() or any(c in p for c in '[]"`*?') for p in parts
        ):
            refusal = "Ambiguous Fabric table scope"
        elif naming.identifier_case_sensitive is False and any(not p.isascii() for p in parts):
            refusal = "Fabric CI identifier equivalence is supported only for ASCII identifiers"
        else:
            if len(parts) == 3:
                if naming.identifier(parts[0]) != naming.identifier(naming.database or ""):
                    refusal = "Cross-database Fabric table scope refused"
                parts = parts[1:]
            if len(parts) == 1:
                parts.insert(0, naming.default_schema)
            matches = [
                pair
                for pair in naming.known_tables or ()
                if tuple(naming.identifier(p) for p in pair)
                == tuple(naming.identifier(p) for p in parts)
            ]
            if len(matches) != 1:
                refusal = refusal or "Fabric table scope is absent or ambiguous in the catalog"
            else:
                canonical = ".".join(matches[0])
                if any(
                    p != p.strip()
                    or (naming.identifier_case_sensitive is False and not p.isascii())
                    for p in matches[0]
                ):
                    refusal = "Unsupported Fabric catalog identifier equivalence"
        return ResolvedTable(
            written=written,
            canonical=canonical,
            resolved=not refusal,
            refusal=refusal,
            case_sensitive=naming.identifier_case_sensitive is not False,
        )
    parts = [part.strip().strip('"`').lower() for part in written.split(".") if part.strip()]
    if not parts:
        return ResolvedTable(written=written, canonical=written.lower())

    if len(parts) >= 3:
        database, schema, table = parts[-3], parts[-2], parts[-1]
        if naming.connector_key in _SNOWFLAKE and naming.database and database != naming.database:
            return ResolvedTable(
                written=written,
                canonical=f"{database}.{schema}.{table}",
                refusal=(
                    f"Cross-database reference refused: {written} is outside the "
                    f"configured database {naming.database}"
                ),
            )
        return ResolvedTable(
            written=written,
            canonical=f"{schema}.{table}",
            resolved=naming.catalogued and (schema, table) in (naming.known_tables or ()),
        )

    if len(parts) == 2:
        schema, table = parts
        return ResolvedTable(
            written=written,
            canonical=f"{schema}.{table}",
            resolved=naming.catalogued and (schema, table) in (naming.known_tables or ()),
        )

    table = parts[0]
    aliases: tuple[str, ...] = ()
    if naming.legacy_alias and naming.default_schema != LEGACY_SCHEMA:
        aliases = (f"{LEGACY_SCHEMA}.{table}",)

    if naming.connector_key not in _POSTGRES:
        return ResolvedTable(
            written=written,
            canonical=f"{naming.default_schema}.{table}",
            aliases=aliases,
            resolved=naming.catalogued
            and (naming.default_schema, table) in (naming.known_tables or ()),
        )

    path = naming.search_path or (LEGACY_SCHEMA,)
    known = naming.known_tables
    extra_shadows: tuple[str, ...] = ()
    if table.startswith("pg_"):
        # pg_catalog is searched before the path. The catalog never records it,
        # so a system relation cannot be resolved here - but a deny on it must
        # still reach a bare reference.
        extra_shadows = (f"pg_catalog.{table}",)
    if known is not None:
        for index, schema in enumerate(path):
            if (schema, table) in known:
                earlier = tuple(f"{s}.{table}" for s in path[:index])
                return ResolvedTable(
                    written=written,
                    canonical=f"{schema}.{table}",
                    shadows=extra_shadows + earlier,
                    resolved=True,
                )
    # Not in the catalog, or no catalog: the database would take the first
    # schema on the path that holds it, which could be any of them.
    return ResolvedTable(
        written=written,
        canonical=f"{path[0]}.{table}",
        shadows=extra_shadows + tuple(f"{s}.{table}" for s in path[1:]),
        resolved=False,
    )


# --------------------------------------------------------------------------
# From SQL to the inputs governance evaluates
# --------------------------------------------------------------------------


@dataclass(slots=True)
class SqlDerivation:
    """What a statement, or several, touch: verb and every table written."""

    operation: str | None
    tables: list[str]
    statements: list[NormalizedQuery] = field(default_factory=list)
    parse_error: bool = False

    @property
    def first(self) -> NormalizedQuery | None:
        return self.statements[0] if self.statements else None


def derive_sql(sql: str, *, source_id: str, dialect: str) -> SqlDerivation:
    """Every statement's tables, and the first statement's operation.

    Every statement, not the first: keeping only the first let
    `SELECT 1; SELECT * FROM orders` past a deny on `orders`.
    """
    normalized = normalize_sql(sql, source_id, dialect=dialect)
    statements = normalized if isinstance(normalized, list) else [normalized]
    seen: dict[str, None] = {}
    for statement in statements:
        for table in statement.tables or []:
            seen.setdefault(table, None)
    first = statements[0] if statements else None
    return SqlDerivation(
        operation=first.operation if first is not None else None,
        tables=list(seen),
        statements=list(statements),
        parse_error=any(statement.parse_error for statement in statements),
    )


def governance_inputs(
    *,
    operation: str,
    tables: list[str] | None,
    metadata: dict[str, Any],
    sql: str | None,
    write_classification: Any | None,
) -> tuple[str, list[str] | None, dict[str, Any]]:
    """The operation, tables and metadata governance evaluates for a request.

    A classified write is governed as a write of its classified type, over the
    union of the parsed tables and the classifier's. The gateway and the
    dry-runs both call this, so they cannot disagree about a write.
    """
    governance_metadata = dict(metadata)
    governance_tables = tables
    governance_operation = operation
    if sql and write_classification is not None:
        governance_operation = "write"
        classified = list(getattr(write_classification, "tables", []) or [])
        if classified:
            governance_tables = sorted(set(list(governance_tables or []) + classified))
        governance_metadata.setdefault(
            "write_operation_type",
            getattr(write_classification, "operation_type", "UNKNOWN"),
        )
        has_where = getattr(write_classification, "has_where", None)
        if has_where is not None:
            governance_metadata.setdefault("has_where", bool(has_where))
    return governance_operation, governance_tables, governance_metadata


def table_spellings(resolved: list[ResolvedTable]) -> set[str]:
    """Every spelling a deny rule on these tables may have been written in.

    Deny rules match broadly - as written, bare, canonical, legacy alias and
    shadow - so a rule keeps firing whichever form its author chose. Allow
    rules are never matched this way: the policy engine is first-match by
    priority, and a broader allow could pre-empt a lower-priority deny.
    """
    spellings: set[str] = set()
    for table in resolved:
        spellings.add(table.written if table.case_sensitive else table.written.lower())
        spellings.add(table.canonical)
        spellings.add(table.canonical.rsplit(".", 1)[-1])
        spellings.update(table.aliases)
        spellings.update(table.shadows)
    return spellings
