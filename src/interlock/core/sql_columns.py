"""Which columns of which tables a SQL statement reads or writes.

Column-level rules were accepted by the role editor and then did nothing: no
live path recorded which columns a query touched, so a request's resource was
always the whole table, a deny on `customers.ssn` never matched, and an allow
on `customers.name` refused every query on the table. This resolves each
column a statement touches to its table, with the catalog as the schema:

- every column any SELECT scope takes from a base table, including through
  joins, subqueries and CTEs, with `SELECT *` expanded from the catalog;
- the columns an UPDATE sets and filters on, an INSERT writes, and a DELETE
  filters on - a DELETE also needs the whole table, since it removes rows;
- for the outermost SELECT, which base columns each output column derives
  from, so `SELECT ssn AS x` can still be redacted as `ssn`.

What cannot be determined is reported per table rather than guessed: a table
missing from the catalog, a column the catalog does not have, a whole-row
reference such as `to_jsonb(c)`. Governance refuses the request when
column-level rules apply to that table, and otherwise treats it as a read of the
whole table.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field

import sqlglot
from sqlglot import exp
from sqlglot.errors import OptimizeError, ParseError, SqlglotError
from sqlglot.optimizer.qualify import qualify
from sqlglot.optimizer.scope import Scope, build_scope, traverse_scope
from sqlglot.schema import MappingSchema

# (schema, table) -> ordered column names, lower-cased
ColumnCatalog = Mapping[tuple[str, str], tuple[str, ...]]
Resolver = Callable[[str], str]  # written table -> canonical "schema.table"


@dataclass(slots=True)
class ColumnAccess:
    """Columns each table's rows are read or written through, by canonical table.

    `columns[t]` empty means the table is touched but no column of it is named -
    `COUNT(*)`, or a DELETE - which needs table-level access. `gaps[t]` says why
    the columns of `t` could not be determined; with column-level rules on `t`
    that refuses the request.
    """

    case_sensitive: bool = False
    refusals: list[str] = field(default_factory=list)
    columns: dict[str, set[str]] = field(default_factory=dict)
    whole_table: set[str] = field(default_factory=set)
    gaps: dict[str, str] = field(default_factory=dict)
    # Output column name -> base columns ("schema.table.col") it derives from,
    # for the outermost SELECT only.
    lineage: dict[str, set[str]] = field(default_factory=dict)

    def touch(self, table: str) -> None:
        self.columns.setdefault(table, set())

    def add(self, table: str, column: str) -> None:
        self.columns.setdefault(table, set()).add(column if self.case_sensitive else column.lower())


def _table_key(table: exp.Table, case_sensitive: bool = False) -> str:
    key = ".".join(part for part in (table.db, table.name) if part)
    return key if case_sensitive else key.lower()


def _pair(key: str) -> tuple[str, str]:
    schema, _, name = key.partition(".")
    return schema, name


def _mapping_schema(
    tables: set[str], catalog: ColumnCatalog
) -> dict[str, dict[str, dict[str, str]]]:
    schema: dict[str, dict[str, dict[str, str]]] = {}
    for key in tables:
        if "." not in key:
            continue
        s, t = key.split(".", 1)
        cols = catalog.get((s, t))
        if cols is None:
            continue
        schema.setdefault(s, {})[t] = {c: "unknown" for c in cols}
    return schema


def column_access(
    sql: str,
    *,
    dialect: str,
    resolve: Resolver,
    catalog: ColumnCatalog | None,
    case_sensitive: bool = False,
    native_identifiers: bool = False,
) -> ColumnAccess:
    if native_identifiers and not case_sensitive and catalog is not None:
        # The initial CI contract is ASCII case equivalence only. Preserve the
        # catalog-native spelling at the authorization boundary while sqlglot
        # resolves equivalent spellings using its case-insensitive grammar.
        try:
            parsed = sqlglot.parse_one(sql, read=dialect)
        except SqlglotError:
            return ColumnAccess(refusals=["Fabric SQL column scope could not be parsed"])
        touched = {
            resolve(".".join(p.name for p in table.parts)) for table in parsed.find_all(exp.Table)
        }
        relevant = {pair: cols for pair, cols in catalog.items() if ".".join(pair) in touched}
        raw_tables = {f"{s}.{t}".lower(): f"{s}.{t}" for s, t in relevant}
        raw_columns = {f"{s}.{t}.{c}".lower(): c for (s, t), cols in relevant.items() for c in cols}
        identifiers = [i.name for i in parsed.find_all(exp.Identifier)]
        identifiers += [part for pair, cols in relevant.items() for part in (*pair, *cols)]
        ambiguous = len(raw_columns) != sum(len(cols) for cols in relevant.values())
        if ambiguous or any(not i.isascii() or i != i.strip() for i in identifiers):
            access = ColumnAccess(refusals=["Unsupported Fabric CI identifier equivalence"])
            for key in touched:
                access.touch(key)
                access.gaps[key] = "unsupported Fabric CI identifier equivalence"
            return access
        folded = column_access(
            sql,
            dialect=dialect,
            resolve=lambda name: resolve(name).lower(),
            catalog={
                (s.lower(), t.lower()): tuple(c.lower() for c in cols)
                for (s, t), cols in relevant.items()
            },
        )
        folded.columns = {
            raw_tables.get(t, t): {raw_columns.get(f"{t}.{c}", c) for c in cols}
            for t, cols in folded.columns.items()
        }
        folded.gaps = {raw_tables.get(t, t): reason for t, reason in folded.gaps.items()}
        folded.whole_table = {raw_tables.get(t, t) for t in folded.whole_table}

        def native_column(name: str) -> str:
            table, _, column = name.rpartition(".")
            return f"{raw_tables.get(table, table)}.{raw_columns.get(name, column)}"

        folded.lineage = {
            alias: {native_column(name) for name in names}
            for alias, names in folded.lineage.items()
        }
        return folded
    access = ColumnAccess(case_sensitive=case_sensitive)
    try:
        statements = [s for s in sqlglot.parse(sql, read=dialect) if s is not None]
    except (ParseError, SqlglotError):
        return access
    for statement in statements:
        _statement_access(
            statement,
            dialect=dialect,
            resolve=resolve,
            catalog=catalog,
            access=access,
            outermost=len(statements) == 1,
        )
    return access


def _rewrite_tables(
    statement: exp.Expression, resolve: Resolver, case_sensitive: bool = False
) -> set[str]:
    """Replace each table reference with its canonical schema.table, in place."""
    normalize = (lambda value: value) if case_sensitive else str.lower
    ctes = {normalize(str(c.alias)) for c in statement.find_all(exp.CTE) if c.alias}
    canonical: set[str] = set()
    for table in list(statement.find_all(exp.Table)):
        if not table.name:
            continue
        written = ".".join(p for p in (table.catalog, table.db, table.name) if p)
        if not table.db and normalize(table.name) in ctes:
            continue
        key = resolve(written)
        if "." not in key:
            continue
        schema, name = key.rsplit(".", 1)
        table.set("catalog", None)
        table.set("db", exp.to_identifier(schema))
        table.set("this", exp.to_identifier(name))
        canonical.add(key)
    return canonical


def _statement_access(
    statement: exp.Expression,
    *,
    dialect: str,
    resolve: Resolver,
    catalog: ColumnCatalog | None,
    access: ColumnAccess,
    outermost: bool,
) -> None:
    statement = statement.copy()
    tables = _rewrite_tables(statement, resolve, access.case_sensitive)
    for table in tables:
        access.touch(table)
    if catalog is None:
        for table in tables:
            access.gaps.setdefault(table, "the source has no catalog, so its columns are unknown")
        return
    missing = [t for t in tables if _pair(t) not in catalog]
    for table in missing:
        access.gaps.setdefault(table, "the table is not in the source catalog")

    if access.case_sensitive:
        # sqlglot honors case_sensitive metadata even for unquoted identifiers.
        for identifier in statement.find_all(exp.Identifier):
            identifier.meta["case_sensitive"] = True
    try:
        qualified = qualify(
            statement,
            schema=MappingSchema(
                _mapping_schema(tables, catalog),
                dialect=dialect,
                normalize=not access.case_sensitive,
            ),
            dialect=dialect,
            validate_qualify_columns=True,
            quote_identifiers=False,
            identify=False,
        )
    except (OptimizeError, SqlglotError) as exc:
        for table in tables:
            access.gaps.setdefault(table, f"a column could not be resolved ({exc})")
        return

    # Reads: every column any SELECT scope takes from a base table.
    for scope in traverse_scope(qualified):
        _scope_reads(scope, access)

    # Writes are not scopes; their columns are read off the statement.
    if isinstance(qualified, exp.Update):
        key = (
            _table_key(qualified.this, access.case_sensitive)
            if isinstance(qualified.this, exp.Table)
            else None
        )
        if key:
            for assignment in qualified.expressions:
                if isinstance(assignment, exp.EQ) and isinstance(assignment.left, exp.Column):
                    access.add(key, assignment.left.name)
            _where_columns(qualified, key, access)
    elif isinstance(qualified, exp.Delete):
        key = (
            _table_key(qualified.this, access.case_sensitive)
            if isinstance(qualified.this, exp.Table)
            else None
        )
        if key:
            # Deleting removes whole rows: it needs the whole table.
            access.whole_table.add(key)
            _where_columns(qualified, key, access)
    elif isinstance(qualified, exp.Insert):
        into = qualified.this
        table = into.this if isinstance(into, exp.Schema) else into
        key = _table_key(table, access.case_sensitive) if isinstance(table, exp.Table) else None
        if key:
            if isinstance(into, exp.Schema) and into.expressions:
                for column in into.expressions:
                    access.add(key, column.name)
            else:
                schema, _, name = key.partition(".")
                cols = catalog.get((schema, name))
                if cols:
                    for column in cols:
                        access.add(key, column)
                else:
                    access.gaps.setdefault(key, "INSERT without a column list")

    if outermost and isinstance(qualified, exp.Select):
        access.lineage = _lineage(qualified, access.case_sensitive)


def _where_columns(statement: exp.Expression, key: str, access: ColumnAccess) -> None:
    where = statement.args.get("where")
    if where is None:
        return
    for column in where.find_all(exp.Column):
        if column.table in ("", key.rsplit(".", 1)[-1]):
            access.add(key, column.name)


def _scope_reads(scope: Scope, access: ColumnAccess) -> None:
    for column in scope.columns:
        source = scope.sources.get(column.table)
        if isinstance(source, exp.Table):
            access.add(_table_key(source, access.case_sensitive), column.name)
    # A table alias used as a value - to_jsonb(c), row_to_json(c) - reads every
    # column, and no column list names them.
    for node in scope.expression.find_all(exp.TableColumn, exp.Column):
        if isinstance(node, exp.TableColumn):
            alias = node.name
        elif isinstance(node.this, exp.Star) and node.table:
            # c.* that qualify left unexpanded, as inside a function call
            alias = node.table
        else:
            continue
        source = scope.sources.get(alias)
        if isinstance(source, exp.Table):
            access.gaps.setdefault(
                _table_key(source, access.case_sensitive),
                f"a whole-row reference to {alias} reads every column",
            )


def _lineage(select: exp.Select, case_sensitive: bool = False) -> dict[str, set[str]]:
    root = build_scope(select)
    if root is None:
        return {}
    out: dict[str, set[str]] = {}
    for projection in select.expressions:
        name = projection.alias_or_name
        out[name if case_sensitive else name.lower()] = _projection_sources(
            root, projection, case_sensitive
        )
    return out


def _projection_sources(
    scope: Scope, projection: exp.Expression, case_sensitive: bool = False
) -> set[str]:
    normalize = (lambda value: value) if case_sensitive else str.lower
    found: set[str] = set()
    for column in projection.find_all(exp.Column):
        source = scope.sources.get(column.table)
        if isinstance(source, exp.Table):
            found.add(f"{_table_key(source, case_sensitive)}.{normalize(column.name)}")
        elif isinstance(source, Scope):
            select = source.expression
            if isinstance(select, exp.Select):
                for inner in select.expressions:
                    if normalize(inner.alias_or_name) == normalize(column.name):
                        found |= _projection_sources(source, inner, case_sensitive)
    return found
