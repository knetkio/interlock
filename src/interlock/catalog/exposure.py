"""Who can already read what a scan just found.

A table or column that appears upstream is readable at once by every role whose
patterns already cover it - `sales.*` covers a new `sales.payroll` the moment it
exists. Drift review is where an admin should learn that, so each change row a
scan adds for a SQL table or column records its exposure: the enabled roles on
the source that would allow reading it and do not deny it, and how many
identities hold one of them. Computed once, when the scan is applied, so the
record says what was true when the object appeared.
"""

from __future__ import annotations

import json
from typing import Any

from interlock.catalog.model import TABLE_LIKE_NODE_TYPES
from interlock.core.source_roles import PermissionStatement, statements_allow

_ROLE_STATEMENTS_SQL = """
SELECT r.id AS role_id, r.role_key, p.id AS permission_id, p.effect, p.action,
       p.resource_type, p.resource_pattern, p.constraints
FROM source_roles r
JOIN source_role_permissions p ON p.role_id = r.id
WHERE r.source_id = $1 AND r.enabled
ORDER BY r.role_key, p.id
"""

_HOLDERS_SQL = """
SELECT DISTINCT r.role_key, g.identity_id
FROM identity_source_role_grants g
JOIN source_roles r ON r.id = g.role_id
JOIN identities i ON i.id = g.identity_id
WHERE g.source_id = $1 AND g.enabled AND i.enabled
  AND (g.expires_at IS NULL OR g.expires_at > NOW())
"""

_ADDED_SQL = """
SELECT id, node_type, path FROM source_catalog_changes
WHERE scan_id = $1 AND change = 'added' AND node_type = ANY($2::text[])
"""


def _statement(row: Any) -> PermissionStatement:
    constraints = row["constraints"] or {}
    if isinstance(constraints, str):
        constraints = json.loads(constraints or "{}")
    return PermissionStatement(
        permission_id=int(row["permission_id"]),
        role_id=int(row["role_id"]),
        role_key=str(row["role_key"]),
        effect=str(row["effect"]),
        action=str(row["action"]),
        resource_type=str(row["resource_type"]),
        resource_pattern=str(row["resource_pattern"]),
        constraints=constraints if isinstance(constraints, dict) else {},
    )


def exposing_roles(
    statements: list[PermissionStatement],
    *,
    node_type: str,
    path: list[str],
    case_sensitive: bool = False,
    native_identifiers: bool = False,
) -> list[str]:
    """Role keys that alone would allow reading this node, without denying it."""
    normalize = str if case_sensitive else str.lower
    if node_type == "column":
        resource = ".".join(normalize(part) for part in path)
        resource_type = "db.column"
    else:
        resource = ".".join(normalize(part) for part in path) + ".*"
        resource_type = "db.table"
    by_role: dict[str, list[PermissionStatement]] = {}
    for statement in statements:
        by_role.setdefault(statement.role_key, []).append(statement)
    return sorted(
        role_key
        for role_key, role_statements in by_role.items()
        if statements_allow(
            role_statements,
            action="db.table.select",
            resource_type=resource_type,
            resource=resource,
            case_sensitive=case_sensitive,
            native_identifiers=native_identifiers,
        )
    )


async def record_exposure(
    conn: Any,
    *,
    source_id: str,
    scan_id: int,
    case_sensitive: bool = False,
    native_identifiers: bool = False,
) -> int:
    """Write the exposure of every table or column this scan added. Returns rows written."""
    added = await conn.fetch(_ADDED_SQL, scan_id, sorted({*TABLE_LIKE_NODE_TYPES, "column"}))
    if not added:
        return 0
    statements = [_statement(row) for row in await conn.fetch(_ROLE_STATEMENTS_SQL, source_id)]
    holders: dict[str, set[int]] = {}
    for row in await conn.fetch(_HOLDERS_SQL, source_id):
        holders.setdefault(str(row["role_key"]), set()).add(int(row["identity_id"]))
    written = 0
    for change in added:
        roles = exposing_roles(
            statements,
            node_type=str(change["node_type"]),
            path=list(change["path"]),
            case_sensitive=case_sensitive,
            native_identifiers=native_identifiers,
        )
        identities: set[int] = set()
        for role in roles:
            identities |= holders.get(role, set())
        exposure = {"roles": roles, "identities": len(identities)}
        await conn.execute(
            "UPDATE source_catalog_changes SET exposure = ($2::text)::jsonb WHERE id = $1",
            int(change["id"]),
            json.dumps(exposure),
        )
        written += 1
    return written
