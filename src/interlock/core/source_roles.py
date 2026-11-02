"""Source-scoped IAM-style role evaluation."""

from __future__ import annotations

import fnmatch
import json
from dataclasses import dataclass
from typing import Any

import asyncpg

from interlock.core.sql_governance import ResolvedTable, SqlNaming, resolve_table
from interlock.models import PermissionRequest, SourceRoleDecision


@dataclass(slots=True)
class PermissionStatement:
    permission_id: int
    role_id: int
    role_key: str
    effect: str
    action: str
    resource_type: str
    resource_pattern: str
    constraints: dict[str, Any]


_STATEMENTS_QUERY = """
SELECT r.id AS role_id,
       r.role_key,
       p.id AS permission_id,
       p.effect,
       p.action,
       p.resource_type,
       p.resource_pattern,
       p.constraints
FROM identity_source_role_grants g
JOIN source_roles r
  ON r.id = g.role_id
 AND r.source_id = g.source_id
 AND r.enabled = TRUE
JOIN source_role_permissions p
  ON p.role_id = r.id
WHERE g.identity_id = $1
  AND g.source_id = $2
  AND g.enabled = TRUE
  AND (g.expires_at IS NULL OR g.expires_at > NOW())
ORDER BY r.role_key, p.effect DESC, p.id
"""


class SourceRoleEvaluator:
    """Evaluates source role permission statements with IAM-style semantics."""

    def __init__(self, pg_pool: asyncpg.Pool) -> None:
        self._pool = pg_pool

    async def evaluate(self, request: PermissionRequest) -> SourceRoleDecision:
        if request.identity_id is None:
            return SourceRoleDecision(
                allowed=False,
                reason="No identity resolved for source-role evaluation",
                missing_permissions=[_missing(request)],
            )

        statements = await self._load_statements(request.identity_id, request.source_id)
        if not statements:
            return SourceRoleDecision(
                allowed=False,
                reason="No source role grants matched this identity and source",
                missing_permissions=[_missing(request)],
            )

        if request.naming_refusals:
            return SourceRoleDecision(
                allowed=False,
                explicit_deny=True,
                reason=request.naming_refusals[0],
                explanation={"action": request.action, "refused": request.naming_refusals},
            )

        for table, why in request.column_gaps.items():
            scoped = [
                stmt
                for stmt in statements
                if _is_column_scoped_on(stmt, table, case_sensitive=request.resource_case_sensitive)
                and _action_matches(stmt.action, request.action)
            ]
            if any(stmt.effect == "deny" for stmt in scoped):
                return SourceRoleDecision(
                    allowed=False,
                    explicit_deny=True,
                    matched_role_ids=sorted({stmt.role_id for stmt in scoped}),
                    matched_permission_ids=sorted({stmt.permission_id for stmt in scoped}),
                    reason=(
                        f"Column-level rules apply to {table}, and the columns this "
                        f"query reads there could not be determined: {why}"
                    ),
                    explanation={"action": request.action, "table": table, "gap": why},
                )

        resources = request.resources or ["*"]
        matched_role_ids: set[int] = set()
        matched_permission_ids: set[int] = set()
        missing: list[dict[str, Any]] = []

        for resource in resources:
            variants = request.resource_variants.get(resource, {})
            aliases = [resource, *variants.get("aliases", [])]
            deny_forms = [*aliases, *variants.get("shadows", [])]
            denied = [
                stmt
                for stmt in statements
                if stmt.effect == "deny"
                and any(_matches_statement(stmt, request, form) for form in deny_forms)
            ]
            if denied:
                return SourceRoleDecision(
                    allowed=False,
                    explicit_deny=True,
                    matched_role_ids=sorted({stmt.role_id for stmt in denied}),
                    matched_permission_ids=sorted({stmt.permission_id for stmt in denied}),
                    reason="Explicit deny matched source role permission",
                    explanation={
                        "action": request.action,
                        "resource": resource,
                        "roles": sorted({stmt.role_key for stmt in denied}),
                    },
                )

            allowed = [
                stmt
                for stmt in statements
                if stmt.effect == "allow"
                and any(_matches_statement(stmt, request, form) for form in aliases)
            ]
            if not allowed:
                missing.append(
                    {
                        "action": request.action,
                        "resource": resource,
                        "resource_type": _resource_type_for(request),
                    }
                )
                continue

            matched_role_ids.update(stmt.role_id for stmt in allowed)
            matched_permission_ids.update(stmt.permission_id for stmt in allowed)

        if missing:
            gap_tables = [
                table
                for table in request.column_gaps
                if any(str(m.get("resource", "")).startswith(f"{table}.") for m in missing)
            ]
            reason = "No source role permission allowed every requested resource"
            if gap_tables:
                table = gap_tables[0]
                reason = (
                    f"{reason}; the columns this query reads on {table} could not be "
                    f"determined ({request.column_gaps[table]}), so it needs access to "
                    "the whole table"
                )
            return SourceRoleDecision(
                allowed=False,
                matched_role_ids=sorted(matched_role_ids),
                matched_permission_ids=sorted(matched_permission_ids),
                missing_permissions=missing,
                reason=reason,
                explanation={"action": request.action, "missing": missing},
            )

        return SourceRoleDecision(
            allowed=True,
            matched_role_ids=sorted(matched_role_ids),
            matched_permission_ids=sorted(matched_permission_ids),
            reason="Source role permissions allowed request",
            explanation={
                "action": request.action,
                "resources": resources,
            },
        )

    async def allowed_resources(
        self,
        identity_id: int,
        source_id: str,
        *,
        action: str,
        resource_type: str,
        resources: list[str],
        aliases: dict[str, list[str]] | None = None,
        case_sensitive: bool = False,
    ) -> set[str]:
        """Which of `resources` this identity's roles allow for `action`.

        Each resource on its own, with evaluate's rules: an explicit deny wins,
        otherwise an allow must match. `aliases` are other spellings of a
        resource that evaluate also checks - the legacy `public.` form on MySQL
        and Snowflake - so a role written that way is described as reaching
        what it can in fact read. Used to describe what an agent may reach
        without naming anything it may not.
        """
        statements = await self._load_statements(identity_id, source_id)
        if not statements:
            return set()
        probe = PermissionRequest(
            protocol="mcp",
            source_id=source_id,
            identity_id=identity_id,
            action=action,
            resource_type=resource_type,
            resource_case_sensitive=case_sensitive,
        )
        allowed: set[str] = set()
        for resource in resources:
            forms = [resource, *(aliases or {}).get(resource, [])]
            matching = [
                s for s in statements if any(_matches_statement(s, probe, form) for form in forms)
            ]
            if any(s.effect == "deny" for s in matching):
                continue
            if any(s.effect == "allow" for s in matching):
                allowed.add(resource)
        return allowed

    async def describe_access(self, identity_id: int, source_id: str) -> dict[str, Any]:
        """What this identity may do on this source, without attempting it.

        An agent could previously only discover its own authority by making a
        call and being refused, which costs a turn per boundary and reads to a
        model like a malfunction rather than a decision. This returns the same
        statements `evaluate` decides from, so the answer cannot drift from the
        enforcement.

        Deliberately scoped to one identity and one source: it describes the
        caller's own authority and nothing else. Explicit denials are included
        because a deny is the most useful thing an agent can know in advance.
        """
        statements = await self._load_statements(identity_id, source_id)
        allow = [
            {"action": s.action, "resource": s.resource_pattern}
            for s in statements
            if s.effect == "allow"
        ]
        deny = [
            {"action": s.action, "resource": s.resource_pattern}
            for s in statements
            if s.effect == "deny"
        ]
        return {
            "roles": sorted({s.role_key for s in statements}),
            "allow": allow,
            "deny": deny,
        }

    async def _load_statements(self, identity_id: int, source_id: str) -> list[PermissionStatement]:
        rows = await self._pool.fetch(_STATEMENTS_QUERY, identity_id, source_id)
        return [_statement_from_row(row) for row in rows]


def build_permission_request(
    *,
    protocol: str,
    source_id: str,
    identity_id: int | None,
    operation: str,
    method: str | None = None,
    path: str | None = None,
    tables: list[str] | None = None,
    columns: list[str] | None = None,
    normalized_request: Any | None = None,
    risk_level: str | None = None,
    metadata: dict[str, Any] | None = None,
    naming: SqlNaming | None = None,
    column_gaps: dict[str, str] | None = None,
) -> PermissionRequest:
    """Build the request source roles evaluate.

    With `naming`, SQL table references are resolved the way the source's
    database resolves them (see `core.sql_governance`). Without it, a bare name
    is read as `public.<name>`, as it always was.
    """
    action = _action_for(
        protocol=protocol,
        operation=operation,
        method=method,
        normalized_request=normalized_request,
        metadata=metadata or {},
    )
    resolved: list[ResolvedTable] | None = None
    if naming is not None and action.startswith("db.") and tables:
        resolved = [resolve_table(table, naming) for table in tables if table.strip()]
    resources, variants = _resources_for(
        action=action,
        method=method,
        path=path,
        tables=tables,
        columns=columns,
        resolved=resolved,
    )
    refusals = [t.refusal for t in resolved or [] if t.refusal]
    if naming is not None and naming.connector_key == "fabric_sql":
        if any(
            c != c.strip() or (naming.identifier_case_sensitive is False and not c.isascii())
            for c in columns or []
        ):
            refusals.append("Unsupported Fabric column identifier equivalence")
    schemas = sorted({resource.split(".", 1)[0] for resource in resources if "." in resource})
    return PermissionRequest(
        protocol=protocol,
        source_id=source_id,
        identity_id=identity_id,
        action=action,
        resource_type=_resource_type_from_action(action, columns=columns),
        resources=resources,
        operation=_normalized_operation(operation, normalized_request),
        method=method.upper() if method else None,
        path=_normalize_path(path) if path else None,
        schemas=schemas,
        tables=tables or [],
        columns=columns or [],
        risk_level=risk_level,
        metadata=metadata or {},
        resource_variants=variants,
        naming_refusals=refusals,
        naming_resolved=None if resolved is None else all(t.resolved for t in resolved),
        column_gaps=dict(column_gaps or {}),
        resource_case_sensitive=naming is not None
        and naming.connector_key == "fabric_sql"
        and naming.identifier_case_sensitive is not False,
    )


def statements_allow(
    statements: list[PermissionStatement],
    *,
    action: str,
    resource_type: str,
    resource: str,
) -> bool:
    """Whether these statements allow `action` on `resource`: an allow matches
    and no deny does - the evaluator's rule for one resource."""
    probe = PermissionRequest(
        protocol="mcp", source_id="", action=action, resource_type=resource_type
    )
    matching = [s for s in statements if _matches_statement(s, probe, resource)]
    return any(s.effect == "allow" for s in matching) and not any(
        s.effect == "deny" for s in matching
    )


def _statement_from_row(row: Any) -> PermissionStatement:
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


# The source-role action an MCP tool is checked against, by its internal name.
# `interlock_query` is not here: its action comes from the SQL it runs
# (`db.table.select`, `db.table.insert`, ...). `interlock_list_sources` and
# `interlock_describe_access` report only what the caller is granted and need
# no action of their own. The MCP tools reference page is generated from this.
MCP_TOOL_ACTIONS: dict[str, str] = {
    "agentgate_describe_source": "db.table.describe",
    "agentgate_discover": "discovery.search",
    "agentgate_related_documents": "discovery.asset.read",
}


def _action_for(
    *,
    protocol: str,
    operation: str,
    method: str | None,
    normalized_request: Any | None,
    metadata: dict[str, Any] | None = None,
) -> str:
    metadata = metadata or {}
    if protocol == "mcp":
        tool = str(
            metadata.get("tool_name")
            or getattr(normalized_request, "tool", None)
            or getattr(normalized_request, "name", None)
            or operation
            or ""
        ).strip()
        if tool in {"discovery", "related_documents"}:
            tool = f"agentgate_{tool}"
        if tool in MCP_TOOL_ACTIONS:
            return MCP_TOOL_ACTIONS[tool]

    if protocol == "http":
        return f"http.{(method or 'GET').lower()}"
    if protocol == "object_storage":
        op = str(operation or "").lower()
        if op in {"list", "bucket.list"}:
            return "storage.bucket.list"
        if op in {"prefix.list", "browse"}:
            return "storage.prefix.list"
        if op in {"write", "put", "upload"}:
            return "storage.object.write"
        if op in {"delete", "remove"}:
            return "storage.object.delete"
        return "storage.object.read"
    if protocol == "saas":
        op = str(operation or "").lower()
        if op in {"describe", "metadata"}:
            return "saas.object.describe"
        if op in {"search", "discovery"}:
            return "saas.object.search"
        if op in {"write", "update", "create"}:
            return "saas.object.write"
        if op in {"delete", "remove"}:
            return "saas.object.delete"
        return "saas.object.read"
    if protocol == "collaboration":
        op = str(operation or "").lower()
        if op in {"channel", "channels", "list"}:
            return "collab.channel.read"
        if op in {"file", "files"}:
            return "collab.file.read"
        return "collab.message.read"
    if protocol == "repo":
        op = str(operation or "").lower()
        if op in {"issue", "issues"}:
            return "repo.issue.read"
        if op in {"pr", "pull_request", "merge_request"}:
            return "repo.pr.read"
        if op in {"code", "file", "path"}:
            return "repo.code.read"
        if op in {"execute", "workflow", "pipeline"}:
            return "repo.action.execute"
        return "repo.read"
    if protocol == "workspace":
        op = str(operation or "").lower()
        if op in {"gmail", "gmail_message", "message"}:
            return "workspace.gmail.message.read"
        if op in {"calendar", "event", "calendar_event"}:
            return "workspace.calendar.event.read"
        if op in {"doc", "document", "docs"}:
            return "workspace.docs.document.read"
        if op in {"sheet", "spreadsheet", "sheets"}:
            return "workspace.sheets.spreadsheet.read"
        if op in {"slide", "presentation", "slides"}:
            return "workspace.slides.presentation.read"
        if op in {"chat", "chat_message"}:
            return "workspace.chat.message.read"
        if op in {"admin", "report", "admin_report"}:
            return "workspace.admin.report.read"
        if op in {"download", "export"}:
            return "workspace.drive.file.download"
        return "workspace.drive.file.read"
    if protocol == "search":
        op = str(operation or "").lower()
        if op in {"describe", "index"}:
            return "search.index.describe"
        if op in {"document", "get"}:
            return "search.document.read"
        return "search.query"

    forced_write_op = str((metadata or {}).get("write_operation_type") or "").upper()
    op = forced_write_op or _normalized_operation(operation, normalized_request)
    if op in {"SELECT", "SHOW", "DESCRIBE", "EXPLAIN"}:
        return "db.table.select"
    if op == "INSERT":
        return "db.table.insert"
    if op == "UPDATE":
        return "db.table.update"
    if op == "DELETE":
        return "db.table.delete_rows"
    if op == "TRUNCATE":
        return "db.table.truncate"
    if op in {"CREATE", "CREATE TABLE"}:
        return "db.schema.create_table"
    if op in {"ALTER", "ALTER TABLE"}:
        return "db.schema.alter_table"
    if op in {"DROP", "DROP TABLE"}:
        return "db.schema.drop_table"
    if operation == "discovery":
        return "db.table.describe"
    return "db.execute_raw"


def _normalized_operation(operation: str, normalized_request: Any | None) -> str:
    op = getattr(normalized_request, "operation", None) or operation
    return str(op or "").upper()


def _resources_for(
    *,
    action: str,
    method: str | None,
    path: str | None,
    tables: list[str] | None,
    columns: list[str] | None,
    resolved: list[ResolvedTable] | None = None,
) -> tuple[list[str], dict[str, dict[str, list[str]]]]:
    if action.startswith("discovery."):
        return ["*"], {}

    if action.startswith("http."):
        return [_normalize_path(path)], {}

    if action.startswith(("storage.", "saas.", "collab.", "repo.", "search.", "workspace.")):
        return [_normalize_path(path) if path else "*"], {}

    if not tables and action.startswith("db.table."):
        return ["*.*"], {}
    if not tables:
        return ["*"], {}

    if resolved is None:
        resolved = [
            ResolvedTable(
                written=table.strip(),
                canonical=table.strip() if "." in table else f"public.{table.strip()}",
            )
            for table in tables
            if table.strip()
        ]

    resources: list[str] = []
    variants: dict[str, dict[str, list[str]]] = {}
    for table in resolved:
        for suffix in _column_suffixes(table, resolved, columns):
            resource = f"{table.canonical}.{suffix}"
            if resource in resources:
                continue
            resources.append(resource)
            entry: dict[str, list[str]] = {}
            if table.aliases:
                entry["aliases"] = [f"{alias}.{suffix}" for alias in table.aliases]
            if table.shadows:
                entry["shadows"] = [f"{shadow}.{suffix}" for shadow in table.shadows]
            if entry:
                variants[resource] = entry
    return resources or ["*"], variants


def _column_suffixes(
    table: ResolvedTable, resolved: list[ResolvedTable], columns: list[str] | None
) -> list[str]:
    """The columns of `table` a request names, or `*` for the whole table.

    A column written with its table - `customers.email` - belongs to that table
    only. An unqualified column belongs to the one table when there is one; with
    several, it cannot be placed without the catalog, so it is kept on each.
    """
    if not columns:
        return ["*"]
    normalize = (lambda value: value) if table.case_sensitive else str.lower
    names = {
        normalize(table.written),
        normalize(table.canonical),
        normalize(table.canonical.rsplit(".", 1)[-1]),
    }
    mine: list[str] = []
    for column in columns:
        column = column.strip()
        if not column:
            continue
        owner, _, name = column.rpartition(".")
        if owner:
            if normalize(owner) in names:
                mine.append(name)
        else:
            mine.append(column)
    if not mine:
        # Columns were named, none of them of this table: the table itself is
        # still read (for a join or a filter), so it is governed as a whole.
        return ["*"]
    return mine


def _normalize_path(path: str | None) -> str:
    if not path:
        return "/"
    path = path.strip()
    if "://" in path:
        return path
    return path if path.startswith("/") else f"/{path}"


def _matches_statement(
    stmt: PermissionStatement,
    request: PermissionRequest,
    resource: str,
) -> bool:
    if not _action_matches(stmt.action, request.action):
        return False
    if not _resource_type_matches(stmt.resource_type, request):
        return False
    if not _resource_matches(
        stmt.resource_pattern, resource, case_sensitive=request.resource_case_sensitive
    ):
        return False
    return _constraints_match(stmt.constraints, request)


def _is_column_scoped_on(
    stmt: PermissionStatement, table: str, *, case_sensitive: bool = False
) -> bool:
    """Whether a statement names columns of `table` rather than the whole table."""
    parts = _normalize_resource_pattern(stmt.resource_pattern, case_sensitive=case_sensitive).split(
        "."
    )
    column_scoped = stmt.resource_type == "db.column" or (len(parts) >= 3 and parts[-1] != "*")
    if not column_scoped or len(parts) < 3:
        return False
    return fnmatch.fnmatchcase(
        _normalize_resource_pattern(table, case_sensitive=case_sensitive), ".".join(parts[:-1])
    )


def _action_matches(pattern: str, action: str) -> bool:
    return pattern == "*" or pattern == action or fnmatch.fnmatchcase(action, pattern)


def _resource_type_matches(pattern: str, request: PermissionRequest) -> bool:
    if pattern == "*":
        return True
    actual = _resource_type_for(request)
    if pattern == actual:
        return True
    return pattern == "db.table" and actual == "db.column"


def _resource_type_for(request: PermissionRequest) -> str:
    if request.resource_type:
        return request.resource_type
    return _resource_type_from_action(
        request.action, columns=request.columns, metadata=request.metadata
    )


def _resource_type_from_action(
    action: str,
    *,
    columns: list[str] | None = None,
    metadata: dict[str, Any] | None = None,
) -> str:
    if action.startswith("discovery."):
        return "discovery.asset"
    if action.startswith("storage.bucket."):
        return "storage.bucket"
    if action.startswith("storage.prefix."):
        return "storage.prefix"
    if action.startswith("storage.object."):
        return "storage.object"
    if action.startswith("saas."):
        return "saas.object"
    if action.startswith("collab.channel."):
        return "collab.channel"
    if action.startswith("collab.message."):
        return "collab.message"
    if action.startswith("collab.file."):
        return "collab.file"
    if action.startswith("repo.issue."):
        return "repo.issue"
    if action.startswith("repo.pr."):
        return "repo.pull_request"
    if action.startswith("repo.code."):
        return "repo.path"
    if action == "repo.action.execute":
        object_type = str((metadata or {}).get("object_type") or "")
        if object_type == "issue":
            return "repo.issue"
        if object_type in {"pr", "pull_request", "merge_request"}:
            return "repo.pull_request"
        if object_type in {"workflow", "pipeline"}:
            return "repo.workflow"
    if action.startswith("repo."):
        return "repo.repository"
    if action.startswith("workspace.drive."):
        return "workspace.drive.file"
    if action.startswith("workspace.gmail."):
        return "workspace.gmail.message"
    if action.startswith("workspace.calendar."):
        return "workspace.calendar.event"
    if action.startswith("workspace.docs."):
        return "workspace.docs.document"
    if action.startswith("workspace.sheets."):
        return "workspace.sheets.spreadsheet"
    if action.startswith("workspace.slides."):
        return "workspace.slides.presentation"
    if action.startswith("workspace.chat."):
        return "workspace.chat.message"
    if action.startswith("workspace.admin."):
        return "workspace.admin.report"
    if action.startswith("search.index."):
        return "search.index"
    if action.startswith("search.collection."):
        return "search.collection"
    if action.startswith("search.document."):
        return "search.document"
    if action.startswith("search."):
        return "search.index"
    if action.startswith("http."):
        return "http.path"
    if columns:
        return "db.column"
    if action.startswith("db.schema."):
        return "db.schema"
    return "db.table"


def _resource_matches(pattern: str, resource: str, *, case_sensitive: bool = False) -> bool:
    normalized_pattern = _normalize_resource_pattern(pattern, case_sensitive=case_sensitive)
    normalized_resource = _normalize_resource_pattern(resource, case_sensitive=case_sensitive)
    return (
        normalized_pattern == "*"
        or fnmatch.fnmatchcase(normalized_resource, normalized_pattern)
        or _path_template_matches(normalized_pattern, normalized_resource)
    )


def _normalize_resource_pattern(value: str, *, case_sensitive: bool = False) -> str:
    value = value.strip()
    if case_sensitive or value.startswith("/"):
        return value
    return value.lower()


def _path_template_matches(pattern: str, resource: str) -> bool:
    if "{" not in pattern:
        return False
    wildcard = []
    in_var = False
    for char in pattern:
        if char == "{":
            in_var = True
            wildcard.append("*")
        elif char == "}":
            in_var = False
        elif not in_var:
            wildcard.append(char)
    return fnmatch.fnmatchcase(resource, "".join(wildcard))


# Constraint keys compared against one request metadata key each.
CONSTRAINT_METADATA_KEYS: dict[str, str] = {
    "brand_ids": "brand_id",
    "group_ids": "group_id",
    "organization_ids": "organization_id",
    "statuses": "status",
    "indices": "index",
    "collections": "collection",
    "object_ids": "object_id",
    "property_names": "property_name",
    "page_ids": "page_id",
    "database_ids": "database_id",
    "workspace_ids": "workspace",
    "orgs": "org",
    "repos": "repo",
    "projects": "project_id",
    "branches": "branch",
    "visibility": "visibility",
    "workflows": "workflow",
    "workspaces": "workspace",
    "channel_ids": "channel_id",
    "channel_names": "channel_name",
    "channel_types": "channel_type",
    "user_ids": "user_id",
    "file_types": "file_type",
}

# Every constraint key the evaluator reads. A key outside this set is ignored
# by `_constraints_match`, so a statement relying on it matches more than its
# author intended; the role editor refuses such keys (role_vocabulary.py).
EVALUATED_CONSTRAINT_KEYS: frozenset[str] = frozenset(
    {
        *CONSTRAINT_METADATA_KEYS,
        "methods",
        "risk_levels",
        "require_where",
        "require_where_clause",
        "file_extensions",
        "max_object_size",
        "max_size",
        "classifications",
        "object_types",
        "tags",
        "tag_match",
        "allowed_fields",
        "path_prefixes",
        "labels",
        "label_match",
    }
)


def _constraints_match(constraints: dict[str, Any], request: PermissionRequest) -> bool:
    methods = constraints.get("methods")
    if methods and request.method not in {str(method).upper() for method in methods}:
        return False
    risk_levels = constraints.get("risk_levels")
    if risk_levels and request.risk_level not in {str(level) for level in risk_levels}:
        return False
    if constraints.get("require_where") or constraints.get("require_where_clause"):
        if request.action in {"db.table.update", "db.table.delete_rows"} and not bool(
            request.metadata.get("has_where")
        ):
            return False
    file_extensions = constraints.get("file_extensions")
    if file_extensions:
        allowed = {
            _normalize_extension(str(extension))
            for extension in file_extensions
            if str(extension).strip()
        }
        extension = _normalize_extension(str(request.metadata.get("file_extension") or ""))
        if extension not in allowed:
            return False
    max_size = constraints.get("max_object_size") or constraints.get("max_size")
    if max_size is not None and request.metadata.get("size") is not None:
        try:
            if int(request.metadata["size"]) > int(max_size):
                return False
        except (TypeError, ValueError):
            return False
    classifications = constraints.get("classifications")
    if classifications:
        actual = request.metadata.get("classification")
        if actual not in {str(value) for value in classifications}:
            return False
    object_types = constraints.get("object_types")
    if object_types and str(request.metadata.get("object_type") or "") not in {
        str(value) for value in object_types
    }:
        return False
    for constraint_key, metadata_key in CONSTRAINT_METADATA_KEYS.items():
        allowed_values = constraints.get(constraint_key)
        if allowed_values and str(request.metadata.get(metadata_key) or "") not in {
            str(value) for value in allowed_values
        }:
            return False
    tags = constraints.get("tags")
    if tags:
        actual_tags = request.metadata.get("tags") or []
        if isinstance(actual_tags, str):
            actual_tags = [actual_tags]
        actual = {str(tag) for tag in actual_tags}
        required = {str(tag) for tag in tags}
        mode = str(constraints.get("tag_match") or "any").lower()
        if mode == "all":
            if not required.issubset(actual):
                return False
        elif actual.isdisjoint(required):
            return False
    allowed_fields = constraints.get("allowed_fields")
    if allowed_fields and request.metadata.get("fields"):
        requested = request.metadata.get("fields") or []
        if isinstance(requested, str):
            requested = [requested]
        if not {str(field) for field in requested}.issubset(
            {str(field) for field in allowed_fields}
        ):
            return False
    path_prefixes = constraints.get("path_prefixes")
    if path_prefixes and request.metadata.get("path"):
        path = str(request.metadata["path"]).lstrip("/")
        if not any(
            path.startswith(str(prefix).lstrip("/"))
            for prefix in path_prefixes
            if str(prefix).strip()
        ):
            return False
    labels = constraints.get("labels")
    if labels:
        actual_labels = request.metadata.get("labels") or []
        if isinstance(actual_labels, str):
            actual_labels = [actual_labels]
        actual = {str(label) for label in actual_labels}
        required = {str(label) for label in labels}
        mode = str(constraints.get("label_match") or "any").lower()
        if mode == "all":
            if not required.issubset(actual):
                return False
        elif actual.isdisjoint(required):
            return False
    return True


def _normalize_extension(value: str) -> str:
    value = value.strip().lower()
    if not value:
        return ""
    return value if value.startswith(".") else f".{value}"


def _missing(request: PermissionRequest) -> dict[str, Any]:
    return {
        "action": request.action,
        "resources": request.resources or ["*"],
        "resource_type": _resource_type_for(request),
    }
