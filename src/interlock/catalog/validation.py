"""Warnings for role statements and policy rules, checked against the catalog.

Nothing here blocks a save. A pattern that matches nothing may be written ahead
of a table that does not exist yet, and a catalog can be stale; the job is to
tell the author what the statement will actually cover before an agent finds
out the hard way.
"""

from __future__ import annotations

import fnmatch
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from typing import Any

from interlock.catalog.collectors import has_collector, is_enforced
from interlock.catalog.compat import findings_for_statement
from interlock.catalog.model import TABLE_LIKE_NODE_TYPES
from interlock.catalog.read import connector_key_of
from interlock.core.sql_governance import SqlNaming, naming_for


@dataclass(frozen=True, slots=True)
class LintWarning:
    code: str
    message: str
    index: int | None = None
    field: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class CatalogView:
    """What the lint rules need from one source's catalog."""

    source_id: str
    connector_key: str
    collectable: bool
    naming: SqlNaming
    # "schema.table" -> column names; empty before the first scan.
    tables: dict[str, list[str]]
    scanned_at: datetime | None

    @property
    def scanned(self) -> bool:
        return self.scanned_at is not None

    def age_text(self, now: datetime | None = None) -> str:
        if self.scanned_at is None:
            return "the source has not been scanned"
        delta = (now or datetime.now(UTC)) - self.scanned_at
        hours = int(delta.total_seconds() // 3600)
        if hours < 1:
            return "the last scan finished less than an hour ago"
        if hours < 48:
            return f"the last scan finished {hours} hours ago"
        return f"the last scan finished {hours // 24} days ago"

    def candidates(self) -> list[str]:
        out: list[str] = []
        for table, columns in self.tables.items():
            out.append(f"{table}.*")
            out.extend(f"{table}.{column}" for column in columns)
        return out


async def load_catalog_view(pool: Any, source_id: str) -> CatalogView | None:
    source = await pool.fetchrow(
        "SELECT source_type, metadata, connection_config FROM data_sources WHERE source_id = $1",
        source_id,
    )
    if source is None:
        return None
    connector_key = connector_key_of(source)
    root = await pool.fetchrow(
        "SELECT attributes, last_seen_at FROM source_catalog "
        "WHERE source_id = $1 AND node_type = 'source' AND removed_at IS NULL",
        source_id,
    )
    rows = await pool.fetch(
        """
        SELECT t.resource_key AS table_key, c.name AS column_name
        FROM source_catalog t
        LEFT JOIN source_catalog c
               ON c.source_id = t.source_id AND c.parent_path = t.path
              AND c.node_type = 'column' AND c.removed_at IS NULL
        WHERE t.source_id = $1 AND t.node_type = ANY($2::text[]) AND t.removed_at IS NULL
        ORDER BY t.resource_key, c.ordinal
        """,
        source_id,
        sorted(TABLE_LIKE_NODE_TYPES),
    )
    tables: dict[str, list[str]] = {}
    for row in rows:
        columns = tables.setdefault(str(row["table_key"]), [])
        if row["column_name"] is not None:
            columns.append(
                str(row["column_name"])
                if connector_key == "fabric_sql"
                else str(row["column_name"]).lower()
            )
    config = source["connection_config"]
    if not isinstance(config, dict):
        import json

        try:
            config = json.loads(config or "{}")
        except (TypeError, ValueError):
            config = {}
    attributes = root["attributes"] if root is not None else None
    if isinstance(attributes, str):
        import json

        attributes = json.loads(attributes or "{}")
    return CatalogView(
        source_id=source_id,
        connector_key=connector_key,
        collectable=has_collector(connector_key),
        naming=naming_for(connector_key, config, attributes if root is not None else None),
        tables=tables,
        scanned_at=root["last_seen_at"] if root is not None else None,
    )


# Families whose agent paths decide on the action alone: their resource
# patterns are evaluated by the console's dry-runs, not by the gateway. HTTP is
# not among them - the proxy matches request paths against patterns.
_PATTERNS_NOT_ENFORCED = frozenset(
    {"object_storage", "collaboration", "repo", "saas", "search", "workspace"}
)


def _family(connector_key: str) -> str:
    from interlock.connections.connectors import CONNECTOR_DEFINITIONS

    definition = CONNECTOR_DEFINITIONS.get(connector_key)
    return str(getattr(definition, "family", "")) if definition is not None else ""


def _is_sql_statement(statement: dict[str, Any]) -> bool:
    action = str(statement.get("action") or "")
    resource_type = str(statement.get("resource_type") or "")
    return action.startswith("db.") or resource_type.startswith("db.") or action == "*"


def _is_column_scoped(statement: dict[str, Any]) -> bool:
    parts = str(statement.get("resource_pattern") or "").strip().lower().split(".")
    return statement.get("resource_type") == "db.column" or (len(parts) >= 3 and parts[-1] != "*")


def lint_statements(view: CatalogView, statements: list[dict[str, Any]]) -> list[LintWarning]:
    """Warnings for one role's statements on one source."""
    warnings: list[LintWarning] = []
    sql_source = is_enforced(view.connector_key)
    if _family(view.connector_key) in _PATTERNS_NOT_ENFORCED and statements:
        warnings.append(
            LintWarning(
                code="not_enforced",
                message=(
                    f"{view.connector_key} requests are not yet checked against resource "
                    "patterns on agent paths: these statements decide dry-runs, but an "
                    "agent's access to this source is decided by the action alone."
                ),
            )
        )
        return warnings

    candidates = view.candidates()
    for index, statement in enumerate(statements):
        pattern = str(statement.get("resource_pattern") or "").strip()
        if view.naming.identifier_case_sensitive is not True:
            pattern = pattern.lower()
        if not pattern or not _is_sql_statement(statement):
            continue
        for finding in findings_for_statement(
            source_id=view.source_id,
            naming=view.naming,
            role_key="",
            effect=str(statement.get("effect") or "allow"),
            pattern=pattern,
        ):
            warnings.append(
                LintWarning(
                    code=finding.kind,
                    message=finding.message,
                    index=index,
                    field="resource_pattern",
                )
            )
        if pattern not in {"*", "*.*"} and view.scanned and candidates:
            if not any(
                fnmatch.fnmatchcase(view.naming.identifier(candidate), pattern)
                for candidate in candidates
            ):
                warnings.append(
                    LintWarning(
                        code="matches_nothing",
                        message=(
                            f"{pattern} matches no table or column in the catalog "
                            f"({view.age_text()}). Rescan if the table is new."
                        ),
                        index=index,
                        field="resource_pattern",
                    )
                )
        if statement.get("effect", "allow") == "allow" and _is_column_scoped(statement):
            table = ".".join(pattern.split(".")[:-1])
            warnings.append(
                LintWarning(
                    code="column_scoped",
                    message=(
                        f"Column-level allow: queries on {table} must name their columns. "
                        "SELECT *, COUNT(*) and DELETE need an allow on the whole table."
                    ),
                    index=index,
                    field="resource_pattern",
                )
            )
    if sql_source and not view.scanned:
        warnings.append(
            LintWarning(
                code="not_scanned",
                message=(
                    "This source has not been scanned, so patterns cannot be checked and "
                    "column-level rules fail closed on every query they apply to."
                ),
            )
        )
    return warnings


def lint_policy(
    view: CatalogView | None,
    *,
    tables: list[str],
    columns: list[str],
    redact_columns: list[str],
    effect: str,
) -> list[LintWarning]:
    """Warnings for a policy's table and column names on one source."""
    warnings: list[LintWarning] = []
    if columns and effect == "allow":
        warnings.append(
            LintWarning(
                code="allow_columns_never_match",
                message=(
                    "An allow rule with a columns condition never matches: rules are "
                    "first-match by priority, so only deny rules match on columns."
                ),
                field="columns",
            )
        )
    if redact_columns and effect != "allow":
        warnings.append(
            LintWarning(
                code="redact_on_deny",
                message="Redact columns only apply when the effect is allow.",
                field="redact_columns",
            )
        )
    if view is None or not view.scanned:
        return warnings
    known_tables = {view.naming.identifier(t) for t in view.tables}
    bare_tables: dict[str, list[str]] = {}
    for table in known_tables:
        bare_tables.setdefault(table.rsplit(".", 1)[-1], []).append(table)
    all_columns = {
        view.naming.identifier(column) for cols in view.tables.values() for column in cols
    }

    for name in tables:
        key = view.naming.identifier(name.strip())
        if not key:
            continue
        if "." in key:
            if key not in known_tables:
                warnings.append(
                    LintWarning(
                        code="unknown_table",
                        message=f"{name} is not a table in the catalog ({view.age_text()}).",
                        field="tables",
                    )
                )
        elif key not in bare_tables:
            warnings.append(
                LintWarning(
                    code="unknown_table",
                    message=f"No table named {name} in the catalog ({view.age_text()}).",
                    field="tables",
                )
            )
        elif len(bare_tables[key]) > 1:
            warnings.append(
                LintWarning(
                    code="ambiguous_table",
                    message=(
                        f"{name} exists in several schemas "
                        f"({', '.join(sorted(bare_tables[key]))}). A deny matches every one; "
                        "qualify the name to be explicit."
                    ),
                    field="tables",
                )
            )
    for field_name, names in (("columns", columns), ("redact_columns", redact_columns)):
        for name in names:
            last = view.naming.identifier(name.strip()).rsplit(".", 1)[-1]
            if last and last not in all_columns:
                warnings.append(
                    LintWarning(
                        code="unknown_column",
                        message=f"No column named {name} in the catalog ({view.age_text()}).",
                        field=field_name,
                    )
                )
    return warnings
