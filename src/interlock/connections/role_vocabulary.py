"""What a source role statement can say, per connector.

The role editor used to take any action, resource type and constraint as free
text. A Slack role could be written with `db.table.select`, which no Slack
request ever carries, and a constraint key the evaluator does not read was
silently ignored - so `{"columns": [...]}` on an allow granted every column.

This module is the one description of each connector's vocabulary: the
actions its requests carry, the resource types each action is checked
against, how to write a pattern for each, and the constraint keys that can
actually narrow a statement for that connector. The editor offers only these,
and `validate_statements` refuses anything else on save.

It is held to the code by tests/unit/test_role_vocabulary.py: every action and
resource type a builder can emit is listed here, every shipped template
validates, every constraint key is one `_constraints_match` reads, and a key is
only offered where the connector's requests carry the value it is compared to.
"""

from __future__ import annotations

import fnmatch
import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from functools import cache
from typing import Any, Literal

from interlock.catalog.collectors import is_enforced
from interlock.connections.connectors import CONNECTOR_DEFINITIONS, connector_key_for
from interlock.core.source_roles import EVALUATED_CONSTRAINT_KEYS

ConstraintType = Literal["list", "bool", "enum_list"]
Group = Literal["read", "write", "admin", "discovery"]
Severity = Literal["error", "warning"]

GROUP_LABELS: dict[str, str] = {
    "read": "Read",
    "write": "Write",
    "admin": "Admin and schema",
    "discovery": "Discovery",
}

_GLOB_CHARS = frozenset("*?[")


@dataclass(frozen=True, slots=True)
class ConstraintSpec:
    key: str
    label: str
    help: str
    type: ConstraintType
    choices: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ResourceTypeSpec:
    key: str
    label: str
    pattern_hint: str
    examples: tuple[str, ...] = ()
    # A pattern for this type starts with this, e.g. "s3://"; None for SQL
    # dotted names and anything free-form.
    scheme: str | None = None


@dataclass(frozen=True, slots=True)
class ActionSpec:
    key: str
    label: str
    description: str
    group: Group
    resource_types: tuple[str, ...]
    constraints: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class Vocabulary:
    connector_key: str
    family: str
    actions: Mapping[str, ActionSpec]
    resource_types: Mapping[str, ResourceTypeSpec]
    constraints: Mapping[str, ConstraintSpec]
    # Whether resource patterns are enforced on agent paths for this source.
    # Elsewhere only the action is, and patterns decide dry-runs.
    patterns_enforced: bool

    def actions_matching(self, pattern: str) -> list[str]:
        """Vocabulary actions an action value covers (`*` and globs included)."""
        if pattern == "*":
            return list(self.actions)
        if _GLOB_CHARS & set(pattern):
            return [a for a in self.actions if fnmatch.fnmatchcase(a, pattern)]
        return [pattern] if pattern in self.actions else []

    def resource_types_for(self, action: str) -> tuple[str, ...]:
        """Resource types a statement with this action may name."""
        keys: list[str] = []
        for matched in self.actions_matching(action):
            for rtype in self.actions[matched].resource_types:
                if rtype not in keys:
                    keys.append(rtype)
        return tuple(keys)

    def constraints_for(self, action: str) -> tuple[str, ...]:
        keys: list[str] = []
        for matched in self.actions_matching(action):
            for key in self.actions[matched].constraints:
                if key not in keys:
                    keys.append(key)
        return tuple(keys)

    def grouped_actions(self) -> list[tuple[str, list[ActionSpec]]]:
        groups: list[tuple[str, list[ActionSpec]]] = []
        for group, label in GROUP_LABELS.items():
            members = [a for a in self.actions.values() if a.group == group]
            if members:
                groups.append((label, members))
        return groups


# --- constraints ----------------------------------------------------------------

_CONSTRAINTS: dict[str, ConstraintSpec] = {
    spec.key: spec
    for spec in (
        ConstraintSpec(
            "risk_levels",
            "Risk levels",
            "Only requests InterLock classifies at these risk levels.",
            "enum_list",
            ("low", "medium", "high"),
        ),
        ConstraintSpec(
            "require_where",
            "Require a WHERE clause",
            "Only UPDATE or DELETE statements that have a WHERE clause.",
            "bool",
        ),
        ConstraintSpec(
            "methods",
            "HTTP methods",
            "Only requests with these methods.",
            "enum_list",
            ("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"),
        ),
        ConstraintSpec(
            "file_extensions", "File extensions", "Only objects with these extensions.", "list"
        ),
        ConstraintSpec(
            "path_prefixes",
            "Path prefixes",
            "Only paths starting with one of these. Ignored when a request has no path.",
            "list",
        ),
        ConstraintSpec("channel_ids", "Channels", "Only these Slack channel ids.", "list"),
        ConstraintSpec("orgs", "Organizations", "Only repositories in these orgs.", "list"),
        ConstraintSpec("repos", "Repositories", "Only these repositories (name only).", "list"),
        ConstraintSpec("workflows", "Workflows", "Only these workflow files.", "list"),
        ConstraintSpec("projects", "Projects", "Only these GitLab project ids.", "list"),
        ConstraintSpec(
            "object_types", "Object types", "Only these object types (e.g. ticket, issue).", "list"
        ),
        ConstraintSpec("object_ids", "Object ids", "Only these object ids.", "list"),
        ConstraintSpec("indices", "Indices", "Only these search indices.", "list"),
        ConstraintSpec("collections", "Collections", "Only these vector collections.", "list"),
    )
}

# --- resource types -------------------------------------------------------------


def _rt(
    key: str, label: str, hint: str, examples: tuple[str, ...] = (), scheme: str | None = None
) -> ResourceTypeSpec:
    return ResourceTypeSpec(key, label, hint, examples, scheme)


_SQL_TYPES = (
    _rt(
        "db.table",
        "Table",
        "schema.table.* covers a whole table; schema.* a whole schema; *.* everything.",
        ("sales.customers.*", "sales.*", "*.*"),
    ),
    _rt(
        "db.column",
        "Column",
        "schema.table.column; a column-level allow makes SELECT * on that table fail.",
        ("sales.customers.email",),
    ),
    _rt("db.schema", "Schema", "A schema name, or * for every schema.", ("sales", "*")),
    _rt("db.raw", "Raw SQL", "Use * - raw statements have no table to scope by.", ("*",)),
)
_STORAGE_TYPES = (
    _rt(
        "storage.object",
        "Object",
        "s3://bucket/prefix/* for everything under a prefix, or one object's full key.",
        ("s3://bucket/reports/*",),
        "s3://",
    ),
    _rt(
        "storage.prefix",
        "Prefix (folder listing)",
        "s3://bucket/prefix/* for the listings allowed under a prefix.",
        ("s3://bucket/reports/*",),
        "s3://",
    ),
    _rt("storage.bucket", "Bucket", "s3://bucket, or * for any bucket.", ("s3://bucket",), "s3://"),
)
_COLLAB_TYPES = (
    _rt(
        "collab.message",
        "Messages",
        "slack://channel/<channel id>/* for a channel's messages.",
        ("slack://channel/C0123456789/*",),
        "slack://",
    ),
    _rt(
        "collab.channel",
        "Channel",
        "slack://channel/<channel id>, or * for every channel.",
        ("slack://channel/C0123456789",),
        "slack://",
    ),
    _rt("collab.file", "File", "slack://file/* for files.", ("slack://file/*",), "slack://"),
)
_SAAS_TYPES = (
    _rt(
        "saas.object",
        "Object",
        "<connector>:<ObjectType>/* for every object of a type, e.g. salesforce:Account/*.",
        ("salesforce:Account/*", "zendesk:ticket/*"),
    ),
)
_SEARCH_TYPES = (
    _rt("search.index", "Index", "An index name, or * for every index.", ("logs-*",)),
    _rt(
        "search.document",
        "Document",
        "opensearch://<index>/* for an index's documents.",
        ("opensearch://logs/*",),
    ),
)
_QDRANT_TYPES = (
    _rt(
        "search.collection",
        "Collection",
        "A collection name, or * for every collection.",
        ("claims",),
    ),
    _rt("search.index", "Collection (as an index)", "A collection name, or *.", ("claims",)),
    _rt(
        "search.document",
        "Point",
        "qdrant://<collection>/point/* for a collection's points.",
        ("qdrant://claims/point/*",),
        "qdrant://",
    ),
)
_HTTP_TYPES = (
    _rt(
        "http.path",
        "Path",
        "A path on the API, /* for everything; {id} matches one segment.",
        ("/users/*", "/*"),
        "/",
    ),
)
_DISCOVERY_TYPES = (
    _rt("discovery.asset", "Discovered asset", "Use * for every indexed asset.", ("*",)),
)


def _repo_types(scheme: str) -> tuple[ResourceTypeSpec, ...]:
    return (
        _rt(
            "repo.repository",
            "Repository",
            f"{scheme}://repo/<org>/<repo>, or * for every repository.",
            (f"{scheme}://repo/org/repo",),
            f"{scheme}://",
        ),
        _rt(
            "repo.issue",
            "Issue",
            f"{scheme}://issue/<org>/<repo>/* for a repository's issues.",
            (f"{scheme}://issue/org/repo/*",),
            f"{scheme}://",
        ),
        _rt(
            "repo.pull_request",
            "Pull request",
            f"{scheme}://pr/<org>/<repo>/* for a repository's pull requests.",
            (f"{scheme}://pr/org/repo/*",),
            f"{scheme}://",
        ),
        _rt(
            "repo.path",
            "File path",
            f"{scheme}://file/<org>/<repo>/* for a repository's files.",
            (f"{scheme}://file/org/repo/*",),
            f"{scheme}://",
        ),
        _rt(
            "repo.workflow",
            "Workflow",
            f"{scheme}://workflow/<org>/<repo>/* for a repository's workflows.",
            (f"{scheme}://workflow/org/repo/*",),
            f"{scheme}://",
        ),
    )


def _workspace_types() -> tuple[ResourceTypeSpec, ...]:
    return tuple(
        _rt(key, label, "Use *, or a document id.", ("*",))
        for key, label in (
            ("workspace.drive.file", "Drive file"),
            ("workspace.docs.document", "Document"),
            ("workspace.sheets.spreadsheet", "Spreadsheet"),
            ("workspace.slides.presentation", "Presentation"),
            ("workspace.gmail.message", "Email message"),
            ("workspace.calendar.event", "Calendar event"),
            ("workspace.chat.message", "Chat message"),
            ("workspace.admin.report", "Admin report"),
        )
    )


# --- actions --------------------------------------------------------------------


def _a(
    key: str,
    label: str,
    description: str,
    group: Group,
    types: tuple[str, ...],
    constraints: tuple[str, ...] = (),
) -> ActionSpec:
    return ActionSpec(key, label, description, group, types, constraints)


_DISCOVERY_ACTIONS = (
    _a(
        "discovery.search",
        "Search the discovery index",
        "Find assets in the source by keyword.",
        "discovery",
        ("discovery.asset",),
    ),
    _a(
        "discovery.asset.read",
        "Read a discovered asset",
        "Open an asset found through discovery.",
        "discovery",
        ("discovery.asset",),
    ),
)

_SQL_WRITE_CONSTRAINTS = ("risk_levels",)
_SQL_ACTIONS = (
    _a(
        "db.table.select",
        "Read rows (SELECT)",
        "Query rows and columns.",
        "read",
        ("db.table", "db.column"),
    ),
    _a(
        "db.table.describe",
        "Describe tables",
        "Read table structure, not rows.",
        "read",
        ("db.table",),
    ),
    _a("db.schema.list", "List schemas", "See which schemas exist.", "read", ("db.schema",)),
    _a(
        "db.table.insert",
        "Insert rows",
        "INSERT statements.",
        "write",
        ("db.table", "db.column"),
        _SQL_WRITE_CONSTRAINTS,
    ),
    _a(
        "db.table.update",
        "Update rows",
        "UPDATE statements; can require a WHERE clause.",
        "write",
        ("db.table", "db.column"),
        ("risk_levels", "require_where"),
    ),
    _a(
        "db.table.delete_rows",
        "Delete rows",
        "DELETE statements; can require a WHERE clause.",
        "write",
        ("db.table", "db.column"),
        ("risk_levels", "require_where"),
    ),
    _a(
        "db.table.truncate",
        "Truncate tables",
        "TRUNCATE statements.",
        "admin",
        ("db.table",),
        _SQL_WRITE_CONSTRAINTS,
    ),
    _a(
        "db.schema.create_table",
        "Create tables",
        "CREATE TABLE.",
        "admin",
        ("db.schema", "db.table"),
        _SQL_WRITE_CONSTRAINTS,
    ),
    _a(
        "db.schema.alter_table",
        "Alter tables",
        "ALTER TABLE.",
        "admin",
        ("db.schema", "db.table"),
        _SQL_WRITE_CONSTRAINTS,
    ),
    _a(
        "db.schema.drop_table",
        "Drop tables",
        "DROP TABLE.",
        "admin",
        ("db.schema", "db.table"),
        _SQL_WRITE_CONSTRAINTS,
    ),
    _a(
        "db.execute_raw",
        "Run other SQL",
        "Statements InterLock cannot classify, such as procedures.",
        "admin",
        ("db.table", "db.column", "db.raw"),
        _SQL_WRITE_CONSTRAINTS,
    ),
)

_STORAGE_OBJECT = ("file_extensions",)
_STORAGE_ACTIONS = (
    _a(
        "storage.object.read",
        "Read objects",
        "Download object contents.",
        "read",
        ("storage.object",),
        _STORAGE_OBJECT,
    ),
    _a(
        "storage.object.metadata.read",
        "Read object metadata",
        "Size, type and modification time, not contents.",
        "read",
        ("storage.object",),
    ),
    _a(
        "storage.prefix.list",
        "List folders",
        "List the objects under a prefix.",
        "read",
        ("storage.prefix",),
    ),
    _a(
        "storage.bucket.list",
        "List buckets",
        "See which buckets exist.",
        "read",
        ("storage.bucket",),
    ),
    _a(
        "storage.object.write",
        "Write objects",
        "Upload or overwrite objects.",
        "write",
        ("storage.object",),
        _STORAGE_OBJECT,
    ),
    _a(
        "storage.object.delete",
        "Delete objects",
        "Remove objects.",
        "admin",
        ("storage.object",),
        _STORAGE_OBJECT,
    ),
)

_COLLAB_ACTIONS = (
    _a(
        "collab.message.read",
        "Read messages",
        "Read messages in channels.",
        "read",
        ("collab.message",),
        ("channel_ids",),
    ),
    _a(
        "collab.channel.read",
        "Read channels",
        "See channels and their details.",
        "read",
        ("collab.channel",),
        ("channel_ids",),
    ),
    _a(
        "collab.file.read",
        "Read files",
        "Download files shared in channels.",
        "read",
        ("collab.file",),
        ("channel_ids",),
    ),
)


def _repo_actions(connector_key: str) -> tuple[ActionSpec, ...]:
    if connector_key == "github":
        scope: tuple[str, ...] = ("orgs", "repos", "object_types")
        execute: tuple[str, ...] = ("orgs", "repos", "object_types", "workflows")
    else:
        scope = ("object_types",)
        execute = ("object_types", "projects")
    return (
        _a(
            "repo.read",
            "Read repositories",
            "Repository details.",
            "read",
            ("repo.repository",),
            scope,
        ),
        _a(
            "repo.code.read",
            "Read code",
            "File contents.",
            "read",
            ("repo.path",),
            ("orgs", "repos") if connector_key == "github" else (),
        ),
        _a(
            "repo.issue.read", "Read issues", "Issues and comments.", "read", ("repo.issue",), scope
        ),
        _a(
            "repo.pr.read",
            "Read pull requests",
            "Pull or merge requests.",
            "read",
            ("repo.pull_request",),
            scope,
        ),
        _a(
            "repo.action.execute",
            "Act on a repository",
            "Comment, label, or run a workflow.",
            "admin",
            ("repo.issue", "repo.pull_request", "repo.workflow", "repo.repository"),
            execute,
        ),
    )


def _saas_actions(connector_key: str) -> tuple[ActionSpec, ...]:
    extra: tuple[str, ...] = (
        ("object_ids", "risk_levels") if connector_key in {"salesforce", "notion"} else ()
    )
    read = ("object_types", *extra)
    return (
        _a("saas.object.read", "Read records", "Read records.", "read", ("saas.object",), read),
        _a(
            "saas.object.search",
            "Search records",
            "Search across records.",
            "read",
            ("saas.object",),
            read,
        ),
        _a(
            "saas.object.describe",
            "Describe objects",
            "Object types and fields, not records.",
            "read",
            ("saas.object",),
            read,
        ),
        _a(
            "saas.object.write",
            "Write records",
            "Create or update.",
            "write",
            ("saas.object",),
            read,
        ),
        _a("saas.object.delete", "Delete records", "Delete.", "admin", ("saas.object",), read),
    )


def _search_actions(connector_key: str) -> tuple[ActionSpec, ...]:
    index_types: tuple[str, ...]
    if connector_key == "qdrant":
        # Collection-scoped through the connector; the core evaluator path
        # derives `search.index` from the action, so both are accepted.
        index_types, scope = ("search.collection", "search.index"), ("collections", "risk_levels")
    else:
        index_types, scope = ("search.index",), ("indices", "risk_levels")
    return (
        _a("search.query", "Search", "Run queries.", "read", index_types, scope),
        _a(
            "search.index.describe",
            "Describe",
            "Mappings and settings, not documents.",
            "read",
            index_types,
            scope,
        ),
        _a(
            "search.document.read",
            "Read documents",
            "Fetch documents by id.",
            "read",
            ("search.document",),
            scope,
        ),
        _a(
            "search.document.write",
            "Write documents",
            "Index or update.",
            "write",
            ("search.document",),
            scope,
        ),
        _a(
            "search.document.delete",
            "Delete documents",
            "Delete.",
            "admin",
            ("search.document",),
            scope,
        ),
    )


def _workspace_actions() -> tuple[ActionSpec, ...]:
    # Drive and Gmail requests are built by the connector, which classifies
    # risk and names the object type; the others carry neither.
    built = {"workspace.drive.file", "workspace.gmail.message"}
    rows: list[tuple[str, str, Group, str]] = [
        ("workspace.drive.file.read", "Read Drive files", "read", "workspace.drive.file"),
        ("workspace.drive.file.download", "Download Drive files", "read", "workspace.drive.file"),
        ("workspace.docs.document.read", "Read Docs", "read", "workspace.docs.document"),
        (
            "workspace.sheets.spreadsheet.read",
            "Read Sheets",
            "read",
            "workspace.sheets.spreadsheet",
        ),
        (
            "workspace.slides.presentation.read",
            "Read Slides",
            "read",
            "workspace.slides.presentation",
        ),
        ("workspace.gmail.message.read", "Read Gmail", "read", "workspace.gmail.message"),
        ("workspace.calendar.event.read", "Read Calendar", "read", "workspace.calendar.event"),
        ("workspace.chat.message.read", "Read Chat", "read", "workspace.chat.message"),
        ("workspace.admin.report.read", "Read admin reports", "read", "workspace.admin.report"),
        ("workspace.drive.file.write", "Write Drive files", "write", "workspace.drive.file"),
        ("workspace.gmail.message.send", "Send Gmail", "write", "workspace.gmail.message"),
        ("workspace.drive.file.delete", "Delete Drive files", "admin", "workspace.drive.file"),
    ]
    return tuple(
        _a(
            key,
            label,
            label + ".",
            group,
            (rt,),
            ("risk_levels", "object_types") if rt in built else (),
        )
        for key, label, group, rt in rows
    )


_HTTP_METHOD_GROUPS: tuple[tuple[str, Group], ...] = (
    ("GET", "read"),
    ("HEAD", "read"),
    ("POST", "write"),
    ("PUT", "write"),
    ("PATCH", "write"),
    ("DELETE", "admin"),
)
_HTTP_ACTIONS = tuple(
    _a(
        f"http.{method.lower()}",
        f"{method} requests",
        f"HTTP {method}.",
        group,
        ("http.path",),
        ("methods",),
    )
    for method, group in _HTTP_METHOD_GROUPS
)


def _family_parts(
    connector_key: str, family: str
) -> tuple[tuple[ActionSpec, ...], tuple[ResourceTypeSpec, ...]]:
    if family in {"database", "warehouse"}:
        return _SQL_ACTIONS, _SQL_TYPES
    if family == "object_storage":
        return _STORAGE_ACTIONS, _STORAGE_TYPES
    if family == "collaboration":
        return _COLLAB_ACTIONS, _COLLAB_TYPES
    if family == "repo":
        return _repo_actions(connector_key), _repo_types(connector_key)
    if family == "saas":
        return _saas_actions(connector_key), _SAAS_TYPES
    if family == "search":
        types = _QDRANT_TYPES if connector_key == "qdrant" else _SEARCH_TYPES
        return _search_actions(connector_key), types
    if family == "workspace":
        return _workspace_actions(), _workspace_types()
    return _HTTP_ACTIONS, _HTTP_TYPES


@cache
def constraint_specs() -> tuple[ConstraintSpec, ...]:
    """Every role-statement condition, for the generated reference."""
    return tuple(_CONSTRAINTS[key] for key in sorted(_CONSTRAINTS))


def vocabulary_for(connector_key: str) -> Vocabulary:
    """The vocabulary for a connector; an unknown key gets HTTP/REST's."""
    connector_key = connector_key_for(connector_key)
    definition = CONNECTOR_DEFINITIONS.get(connector_key) or CONNECTOR_DEFINITIONS["generic_rest"]
    actions, types = _family_parts(definition.key, definition.family)
    actions = (*actions, *_DISCOVERY_ACTIONS)
    types = (*types, *_DISCOVERY_TYPES)
    used = {key for action in actions for key in action.constraints}
    return Vocabulary(
        connector_key=definition.key,
        family=definition.family,
        actions={a.key: a for a in actions},
        resource_types={t.key: t for t in types},
        constraints={k: _CONSTRAINTS[k] for k in _CONSTRAINTS if k in used},
        patterns_enforced=is_enforced(definition.key) or definition.family == "http",
    )


# --- validation -----------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class StatementIssue:
    index: int
    field: str
    severity: Severity
    code: str
    message: str


def _normalized(statement: Mapping[str, Any]) -> tuple[str, str, str, str, str]:
    constraints = statement.get("constraints") or {}
    if isinstance(constraints, str):
        try:
            constraints = json.loads(constraints or "{}")
        except (TypeError, ValueError):
            pass
    return (
        str(statement.get("effect") or "").strip().lower(),
        str(statement.get("action") or "").strip(),
        str(statement.get("resource_type") or "").strip(),
        str(statement.get("resource_pattern") or "").strip(),
        json.dumps(constraints, sort_keys=True, default=str),
    )


def _type_error(spec: ConstraintSpec, value: Any) -> str | None:
    if spec.type == "bool":
        return None if isinstance(value, bool) else "must be true or false"
    if not isinstance(value, list) or not all(isinstance(v, (str, int)) for v in value):
        return "must be a list of values"
    if spec.type == "enum_list":
        unknown = [str(v) for v in value if str(v) not in spec.choices]
        if unknown:
            return f"accepts only {', '.join(spec.choices)} (got {', '.join(unknown)})"
    return None


@dataclass
class _Collector:
    index: int
    issues: list[StatementIssue] = field(default_factory=list)

    def add(self, field_name: str, severity: Severity, code: str, message: str) -> None:
        self.issues.append(StatementIssue(self.index, field_name, severity, code, message))


def validate_statements(
    vocab: Vocabulary,
    statements: Iterable[Mapping[str, Any]],
    *,
    stored: Iterable[Mapping[str, Any]] = (),
) -> list[StatementIssue]:
    """Errors block a save; warnings are advice.

    A statement identical to one already stored on the role is kept as saved:
    its errors become one warning, so every existing role stays saveable. Any
    edit to it must validate.
    """
    kept = {_normalized(s) for s in stored}
    issues: list[StatementIssue] = []
    for index, statement in enumerate(statements):
        found = _Collector(index)
        _check_statement(vocab, statement, found)
        if _normalized(statement) in kept and any(i.severity == "error" for i in found.issues):
            issues.append(
                StatementIssue(
                    index,
                    "action",
                    "warning",
                    "kept_as_saved",
                    "Kept as saved: this statement is outside the connector's vocabulary. "
                    "It saves unchanged, but any edit must use the connector's options.",
                )
            )
            continue
        issues.extend(found.issues)
    return issues


def _check_statement(vocab: Vocabulary, statement: Mapping[str, Any], out: _Collector) -> None:
    effect = str(statement.get("effect") or "allow").lower()
    action = str(statement.get("action") or "").strip()
    rtype = str(statement.get("resource_type") or "").strip()
    pattern = str(statement.get("resource_pattern") or "").strip()
    constraints = statement.get("constraints") or {}

    matched = vocab.actions_matching(action)
    if not matched:
        out.add(
            "action",
            "error",
            "unknown_action",
            f"{action!r} is not an action on this connector. Choose one of its actions, or *.",
        )
    elif rtype != "*" and rtype not in vocab.resource_types_for(action):
        allowed = ", ".join(vocab.resource_types_for(action)) or "none"
        out.add(
            "resource_type",
            "error",
            "resource_type_not_for_action",
            f"{rtype!r} is not a resource type for {action!r}. Use one of: {allowed}, or *.",
        )

    spec = vocab.resource_types.get(rtype)
    if spec and spec.scheme and pattern not in {"", "*"} and not pattern.startswith(spec.scheme):
        out.add(
            "resource_pattern",
            "warning",
            "pattern_shape",
            f"Patterns for {spec.label.lower()} usually look like {spec.examples[0]!r}; "
            f"{pattern!r} may match nothing.",
        )

    if not isinstance(constraints, dict):
        out.add("constraints", "error", "constraints_not_object", "Conditions must be an object.")
        return
    applicable = set(vocab.constraints_for(action)) if matched else set()
    for key, value in constraints.items():
        if key not in EVALUATED_CONSTRAINT_KEYS:
            out.add(
                "constraints",
                "error",
                "unknown_constraint",
                f"{key!r} is not a condition InterLock checks; the statement would apply "
                "without it.",
            )
            continue
        cspec = _CONSTRAINTS.get(key)
        if cspec is not None:
            problem = _type_error(cspec, value)
            if problem:
                out.add("constraints", "error", "constraint_type", f"{key}: {problem}.")
                continue
        if key not in applicable:
            if effect == "deny":
                out.add(
                    "constraints",
                    "error",
                    "deny_never_fires",
                    f"{key!r} is never set on requests for {action!r} on this connector, so "
                    "this deny would never apply. Remove the condition.",
                )
            else:
                out.add(
                    "constraints",
                    "warning",
                    "constraint_never_matches",
                    f"{key!r} is never set on requests for {action!r} on this connector, so "
                    "this allow will never match.",
                )


# --- defaults and picks -----------------------------------------------------------


def default_template(connector_key: str) -> tuple[str, list[dict[str, Any]]]:
    """The reader template a new role starts from: `(role key, statements)`."""
    definition = CONNECTOR_DEFINITIONS.get(connector_key)
    if definition is None:
        return "", []
    vocab = vocabulary_for(connector_key)
    templates = definition.role_templates
    for key, statements in templates.items():
        if "read" in key:
            return key, [dict(s) for s in statements]
    for key, statements in templates.items():
        if statements and all(
            s.get("effect", "allow") == "allow"
            and s.get("action") in vocab.actions
            and vocab.actions[str(s["action"])].group in {"read", "discovery"}
            for s in statements
        ):
            return key, [dict(s) for s in statements]
    return "", []


@dataclass(frozen=True, slots=True)
class PickTargets:
    default_type: str
    patterns: dict[str, str]


def pick_targets(connector_key: str, node_type: str, resource_key: str) -> PickTargets | None:
    """The statement pattern a catalog node stands for, per resource type.

    Catalog keys are not always the resource a request carries: an S3 prefix
    needs `*` to cover the objects under it, and Salesforce, OpenSearch and
    Qdrant requests name objects differently from their catalog keys.
    """
    family = vocabulary_for(connector_key).family
    key = resource_key
    if family in {"database", "warehouse"}:
        if node_type == "column":
            return PickTargets("db.column", {"db.column": key, "db.table": key})
        if node_type in {"table", "view", "materialized_view", "foreign_table"}:
            return PickTargets("db.table", {"db.table": f"{key}.*"})
        if node_type == "schema":
            return PickTargets("db.table", {"db.table": f"{key}.*", "db.schema": key})
        return None
    if family == "object_storage" and node_type in {"bucket", "prefix"}:
        base = key if key.endswith("/") else f"{key}/"
        patterns = {"storage.object": f"{base}*", "storage.prefix": f"{base}*"}
        if node_type == "bucket":
            bucket = key.split("/")[2] if key.startswith("s3://") else key
            patterns["storage.bucket"] = f"s3://{bucket}"
        return PickTargets("storage.object", patterns)
    if family == "collaboration" and node_type == "channel":
        return PickTargets("collab.message", {"collab.channel": key, "collab.message": f"{key}/*"})
    if family == "repo" and node_type == "repository":
        scheme, _, rest = key.partition("://repo/")
        if not rest:
            return None
        return PickTargets(
            "repo.repository",
            {
                "repo.repository": key,
                "repo.issue": f"{scheme}://issue/{rest}/*",
                "repo.pull_request": f"{scheme}://pr/{rest}/*",
                "repo.path": f"{scheme}://file/{rest}/*",
                "repo.workflow": f"{scheme}://workflow/{rest}/*",
            },
        )
    if family == "saas" and node_type == "object" and "://" in key:
        scheme, _, name = key.partition("://")
        return PickTargets("saas.object", {"saas.object": f"{scheme}:{name}/*"})
    if family == "search" and node_type in {"index", "collection"} and "://" in key:
        scheme, _, name = key.partition("://")
        if connector_key == "qdrant":
            return PickTargets(
                "search.collection",
                {"search.collection": name, "search.document": f"qdrant://{name}/point/*"},
            )
        return PickTargets(
            "search.index", {"search.index": name, "search.document": f"{scheme}://{name}/*"}
        )
    return None
