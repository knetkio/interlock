"""Which existing roles and policies catalog naming changes, and how.

Resolving table names from the catalog changes what some existing statements
match. Nothing here changes a role; it tells the operator where to look:

- `legacy_alias` - a MySQL or Snowflake statement written as `public.<table>`.
  It still matches, through the legacy alias, but bare names now resolve to the
  real database or schema; rewrite it before the alias is retired.
- `no_longer_covers_bare_names` - a PostgreSQL allow written as `public.<...>`
  on a source whose search path starts elsewhere. Bare names now resolve to
  that schema, so the allow stops covering them: the change fails closed.
- `deny_now_scoped` - the same situation for a deny. It still fires on reads of
  `public.<table>`, but no longer on bare names that resolve elsewhere.
- `deny_broadened` - a deny policy with a `tables` condition. It now matches
  every spelling of those tables, bare or qualified.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from typing import Any

from interlock.core.sql_governance import LEGACY_SCHEMA, SqlNaming, naming_for

_SQL_KEYS = frozenset({"postgresql", "mysql", "mariadb", "snowflake"})


@dataclass(frozen=True, slots=True)
class NamingFinding:
    source_id: str
    connector_key: str
    kind: str
    effect: str
    pattern: str
    message: str
    role_key: str | None = None
    policy: str | None = None
    suggestion: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def _json(value: Any) -> dict[str, Any]:
    if isinstance(value, str):
        try:
            value = json.loads(value or "{}")
        except ValueError:
            return {}
    return value if isinstance(value, dict) else {}


def _connector_key(row: Any) -> str:
    metadata = _json(row["metadata"])
    from interlock.connections.connectors import connector_key_for

    return connector_key_for(str(row["source_type"]), metadata)


def findings_for_statement(
    *,
    source_id: str,
    naming: SqlNaming,
    role_key: str,
    effect: str,
    pattern: str,
) -> list[NamingFinding]:
    """What catalog naming changes about one role statement."""
    if naming.connector_key == "fabric_sql":
        return []
    lowered = pattern.strip().lower()
    if not lowered.startswith(f"{LEGACY_SCHEMA}.") or naming.default_schema == LEGACY_SCHEMA:
        return []
    rest = lowered[len(LEGACY_SCHEMA) + 1 :]
    suggestion = f"{naming.default_schema}.{rest}"
    if naming.legacy_alias:
        return [
            NamingFinding(
                source_id=source_id,
                connector_key=naming.connector_key,
                kind="legacy_alias",
                effect=effect,
                pattern=pattern,
                role_key=role_key,
                suggestion=suggestion,
                message=(
                    f"Matches through the legacy public. alias. Bare table names on this "
                    f"source resolve to {naming.default_schema}; rewrite as {suggestion}."
                ),
            )
        ]
    kind = "no_longer_covers_bare_names" if effect == "allow" else "deny_now_scoped"
    what = "no longer covers" if effect == "allow" else "no longer applies to"
    return [
        NamingFinding(
            source_id=source_id,
            connector_key=naming.connector_key,
            kind=kind,
            effect=effect,
            pattern=pattern,
            role_key=role_key,
            suggestion=suggestion,
            message=(
                f"Bare table names resolve to {naming.default_schema}, the first schema on "
                f"the source's search path, so this {effect} {what} them. Add {suggestion} "
                f"if bare names should be covered."
            ),
        )
    ]


async def naming_report(pool: Any) -> list[NamingFinding]:
    """Every role statement and deny policy whose meaning catalog naming changes."""
    sources = await pool.fetch(
        "SELECT source_id, source_type, metadata, connection_config FROM data_sources "
        "ORDER BY source_id"
    )
    findings: list[NamingFinding] = []
    for source in sources:
        source_id = str(source["source_id"])
        connector_key = _connector_key(source)
        if connector_key not in _SQL_KEYS:
            continue
        root = await pool.fetchval(
            "SELECT attributes FROM source_catalog "
            "WHERE source_id = $1 AND node_type = 'source' AND removed_at IS NULL",
            source_id,
        )
        naming = naming_for(
            connector_key,
            _json(source["connection_config"]),
            _json(root) if root is not None else None,
        )
        statements = await pool.fetch(
            """
            SELECT r.role_key, p.effect, p.resource_pattern
            FROM source_role_permissions p
            JOIN source_roles r ON r.id = p.role_id
            WHERE r.source_id = $1 AND (p.action LIKE 'db.%' OR p.resource_type LIKE 'db.%')
            ORDER BY r.role_key, p.id
            """,
            source_id,
        )
        for statement in statements:
            findings.extend(
                findings_for_statement(
                    source_id=source_id,
                    naming=naming,
                    role_key=str(statement["role_key"]),
                    effect=str(statement["effect"]),
                    pattern=str(statement["resource_pattern"]),
                )
            )

    policies = await pool.fetch(
        "SELECT name, conditions, actions FROM policy_rules WHERE enabled ORDER BY priority DESC"
    )
    for policy in policies:
        conditions = _json(policy["conditions"])
        actions = _json(policy["actions"])
        tables = conditions.get("tables") or []
        if not tables or actions.get("effect", "deny") == "allow":
            continue
        scope = conditions.get("source_ids") or (
            [conditions["source_id"]] if conditions.get("source_id") else []
        )
        findings.append(
            NamingFinding(
                source_id=",".join(str(s) for s in scope) or "*",
                connector_key="",
                kind="deny_broadened",
                effect="deny",
                pattern=", ".join(str(t) for t in tables),
                policy=str(policy["name"]),
                message=(
                    "This deny now matches every spelling of its tables - bare, "
                    "schema-qualified, or the legacy public. form - not only the exact text."
                ),
            )
        )
    return findings
