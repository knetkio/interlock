"""Dashboard routes serving HTMX + Jinja2 HTML views."""

from __future__ import annotations

import json
import logging
import math
import re
import secrets
import time
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlsplit

from fastapi import APIRouter, Form, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse

from interlock.admin.audit import (
    audit_admin_action,
    mutation_audit_detail,
    summarize_admin_resource,
)
from interlock.admin.auth import hash_password
from interlock.admin.catalog_hooks import after_source_saved
from interlock.admin.identity_labels import IDENTITY_NAME_COLUMNS, identity_joins
from interlock.admin.policy_summary import (
    applies_to_source,
    describe_conditions,
    describe_policy,
    effect_of,
)
from interlock.admin.policy_summary import as_dict as as_policy_dict
from interlock.admin.roles import is_console_admin, is_read_only
from interlock.admin.source_cache import invalidate_source_cache
from interlock.admin.source_ids import (
    InvalidSourceIdError,
    generate_source_id,
    validate_source_id,
)
from interlock.audit.cost import DEFAULT_RANGE as DEFAULT_USAGE_RANGE
from interlock.audit.cost import OUTCOMES as USAGE_OUTCOMES
from interlock.audit.cost import RANGES as USAGE_RANGES
from interlock.audit.cost import UsageAggregator, bar_segments
from interlock.audit.cost import since_for as usage_since
from interlock.catalog.model import looks_like_pii
from interlock.config import allows_insecure_upstream_tls
from interlock.connections.activation import (
    ConnectorNotActiveError,
    active_connector_groups,
    active_connector_keys,
    connector_rows,
    require_active,
    set_active,
)
from interlock.connections.connectors import (
    CONNECTOR_DEFINITIONS,
    connector_key_for,
    get_adapter,
    get_connector,
    role_templates_for_connector,
    sanitize_config,
    source_metadata_for_connector,
)
from interlock.connections.manager import ConnectionManager, _ssl_argument
from interlock.connections.role_vocabulary import (
    Vocabulary,
    pick_targets,
    validate_statements,
    vocabulary_for,
)
from interlock.connections.role_vocabulary import default_template as default_role_template
from interlock.connections.source_config import (
    CONFIG_ALIASES,
    config_bool,
    upstream_tls_refusal,
)
from interlock.core import source_role_grants
from interlock.core.normalizer import dialect_for
from interlock.core.policy import PolicyEngine, rule_source_ids
from interlock.core.source_roles import SourceRoleEvaluator
from interlock.core.write_classifier import WriteClassifier
from interlock.gateway.pipeline import GatewayPipeline, GatewayRequest, sql_gateway_request
from interlock.models import AgentType, IdentityContext
from interlock.security.api_keys import hash_api_key_for_storage, validate_custom_api_key
from interlock.utils.sanitizer import RequestSanitizer

logger = logging.getLogger(__name__)

router = APIRouter(tags=["dashboard"])

PAGE_SIZE = 25
STALE_HEARTBEAT_SECONDS = 90
WARN_HEARTBEAT_SECONDS = 30
WIZARD_DRAFT_TTL_SECONDS = 1800


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _is_htmx(request: Request) -> bool:
    """Return True when the request comes from an HTMX fetch."""
    return request.headers.get("HX-Request") == "true"


def _is_sidebar_htmx(request: Request) -> bool:
    """Return True for sidebar navigation HTMX requests.

    Sidebar links target #main-content. These should return the page
    content block WITHOUT the base layout (no duplicate sidebar).
    """
    if not _is_htmx(request):
        return False
    return request.headers.get("HX-Target", "") == "main-content"


def _is_inner_htmx(request: Request) -> bool:
    """Return True for in-page HTMX requests (NOT sidebar navigation).

    In-page interactions (filter tabs, search inputs, auto-refresh)
    target specific containers and should return only the inner partial.
    """
    return _is_htmx(request) and not _is_sidebar_htmx(request)


def _render_page(
    request: Request,
    page_template: str,
    partial_template: str,
    ctx: dict[str, Any],
) -> HTMLResponse:
    """Two-tier render: inner partial or page (with conditional extends)."""
    if _is_inner_htmx(request):
        return _render(request, partial_template, ctx)
    if _is_sidebar_htmx(request):
        ctx["content_only"] = True
    return _render(request, page_template, ctx)


def _row_to_dict(row: Any) -> dict[str, Any]:
    d = dict(row)
    for key in ("config",):
        val = d.get(key)
        if isinstance(val, str):
            d[key] = json.loads(val)
    return d


# P2-B helper: produce a connection summary that never leaks secrets.
_SAFE_CONFIG_KEYS = {
    "host",
    "port",
    "database",
    "base_url",
    "bucket",
    "region",
    "region_name",
    "prefix",
    "account",
    "warehouse",
    "schema",
    "role",
    "subdomain",
    "workspace",
    "org",
    "group",
    "project",
    "instance_url",
    "workspace_domain",
    "location",
}
_SECRET_CONFIG_KEYS = {
    "password",
    "token",
    "api_key",
    "authorization",
    "auth_header",
    "client_secret",
    "api_token",
    "bot_token",
    "aws_access_key_id",
    "aws_secret_access_key",
    "service_account_json",
    "connection_string",
    "private_key",
}
_SENSITIVE_METADATA_MARKERS = (
    "password",
    "passwd",
    "token",
    "api_key",
    "apikey",
    "secret",
    "authorization",
    "cookie",
    "credential",
)


def _safe_connection_summary(ds: dict[str, Any]) -> str:
    cfg = ds.get("connection_config") or ds.get("config") or {}
    if isinstance(cfg, str):
        try:
            cfg = json.loads(cfg)
        except (TypeError, ValueError):
            cfg = {}
    if not isinstance(cfg, dict):
        return "-"
    visible = {k: v for k, v in cfg.items() if k in _SAFE_CONFIG_KEYS and v}
    if not visible:
        return "-"
    if "host" in visible and "port" in visible:
        return f"{visible['host']}:{visible['port']}"
    return ", ".join(f"{k}={v}" for k, v in visible.items())


def _admin_has_role(request: Request, role: str) -> bool:
    admin = getattr(request.state, "admin", None)
    roles = getattr(admin, "roles", None) or []
    return role in set(roles)


def _redact_admin_metadata(value: Any) -> Any:
    """Redact secret-looking payload fields before rendering Admin details."""
    if isinstance(value, dict):
        redacted: dict[str, Any] = {}
        for key, item in value.items():
            if _looks_admin_sensitive_key(str(key)):
                redacted[key] = "[REDACTED]"
            else:
                redacted[key] = _redact_admin_metadata(item)
        return redacted
    if isinstance(value, list):
        return [_redact_admin_metadata(item) for item in value]
    if isinstance(value, str):
        return _redact_secret_like_text(value)
    return value


def _looks_admin_sensitive_key(key: str) -> bool:
    lowered = key.lower().replace("-", "_")
    return any(marker in lowered for marker in _SENSITIVE_METADATA_MARKERS)


def _redact_secret_like_text(text: str) -> str:
    redacted = text
    for marker in _SENSITIVE_METADATA_MARKERS:
        redacted = re.sub(
            rf"(?i)({re.escape(marker)}\s*[=:]\s*)([^\s&;,}}]+)",
            r"\1[REDACTED]",
            redacted,
        )
    return redacted


def _redact_sql_literals(sql_text: str) -> str:
    """Hide literal values in SQL previews for non-owner Admin views."""
    return re.sub(r"'(?:''|[^'])*'", "'[REDACTED_LITERAL]'", sql_text)


def _prepare_approval_for_admin(request: Request, row: Any) -> dict[str, Any]:
    approval = dict(row)
    metadata = approval.get("request_metadata") or {}
    if isinstance(metadata, str):
        try:
            metadata = json.loads(metadata)
        except (TypeError, ValueError):
            metadata = {}
    if not isinstance(metadata, dict):
        metadata = {}
    approval["request_metadata"] = metadata
    if not _admin_has_role(request, "owner"):
        approval["request_metadata"] = _redact_admin_metadata(metadata)
        sql_text = approval.get("sql_text")
        if isinstance(sql_text, str):
            approval["sql_text"] = _redact_sql_literals(sql_text)
        approval["sensitive_metadata_redacted"] = True
    return approval


def _connection_config(ds: dict[str, Any] | Any) -> dict[str, Any]:
    cfg = (
        dict(ds).get("connection_config")
        if not isinstance(ds, dict)
        else (ds.get("connection_config") or ds.get("config"))
    )
    if isinstance(cfg, str):
        try:
            cfg = json.loads(cfg)
        except (TypeError, ValueError):
            cfg = {}
    return cfg if isinstance(cfg, dict) else {}


def _credential_mode(cfg: dict[str, Any]) -> str:
    has_literal = any(cfg.get(k) for k in _SECRET_CONFIG_KEYS)
    has_ref = any(k.endswith("_ref") and cfg.get(k) for k in cfg)
    if has_literal and has_ref:
        return "mixed"
    if has_ref:
        return "secret-ref"
    if has_literal:
        return "inline"
    return "none"


def _masked_config(cfg: dict[str, Any]) -> dict[str, Any]:
    masked: dict[str, Any] = {}
    for key, value in cfg.items():
        if key in _SECRET_CONFIG_KEYS:
            masked[key] = "********" if value else ""
        elif key.endswith("_ref"):
            masked[key] = value
        else:
            masked[key] = value
    return masked


def _masked_notification_target(value: Any) -> str | None:
    """Return a useful target label without exposing webhook paths or tokens."""
    raw = str(value or "").strip()
    if not raw:
        return None
    parsed = urlsplit(raw)
    if parsed.scheme in {"http", "https"} and parsed.hostname:
        return f"{parsed.scheme}://{parsed.hostname}/[REDACTED]"
    if "@" in raw and " " not in raw:
        local, _, domain = raw.rpartition("@")
        if local and domain:
            return f"{local[:1]}***@{domain}"
    return "[configured]"


def _policy_summary(conditions: Any) -> str:
    """The rule's conditions as a sentence fragment, capitalised for a table cell."""
    text = describe_conditions(conditions)
    return text[:1].upper() + text[1:]


def _default_identity_form(**overrides: Any) -> dict[str, Any]:
    form = {
        "name": "",
        "agent_type": "custom",
        "team": "",
        "roles": "",
        "source_roles": [],
        "mapped_pg_role": "",
        "pg_username": "",
        "pg_password": "",
        "generate_key": "on",
        "api_key": "",
    }
    form.update(overrides)
    return form


_DEFAULT_SOURCE_ROLE_OPTIONS = {
    "postgresql": ["read", "analyst", "write", "owner"],
    "mysql": ["read", "analyst", "write", "owner"],
    "http": ["read", "write", "owner"],
    "s3": ["browser", "reader", "writer", "maintainer"],
    "saas": ["support_reader", "support_analyst"],
    "warehouse": ["analyst", "power_analyst", "writer", "warehouse_admin"],
    "search": ["query_reader"],
}


def _source_role_options(source: dict[str, Any]) -> list[str]:
    metadata = source.get("metadata") or {}
    if isinstance(metadata, str):
        try:
            metadata = json.loads(metadata)
        except (TypeError, ValueError):
            metadata = {}
    configured = metadata.get("role_types") if isinstance(metadata, dict) else None
    if isinstance(configured, list):
        roles = [str(role).strip() for role in configured if str(role).strip()]
        if roles:
            return roles
    return _DEFAULT_SOURCE_ROLE_OPTIONS.get(
        str(source.get("source_type") or "").lower(),
        ["read", "write", "owner"],
    )


def _default_source_role_types(source_type: str) -> list[str]:
    if source_type in CONNECTOR_DEFINITIONS:
        return list(role_templates_for_connector(source_type).keys())
    return _DEFAULT_SOURCE_ROLE_OPTIONS.get(
        str(source_type or "").lower(),
        ["read", "write", "owner"],
    )


def _role_types_text(source_type: str, role_types: list[str] | None = None) -> str:
    roles = role_types or _default_source_role_types(source_type)
    return ", ".join(roles)


def _parse_role_types(raw: str | None, source_type: str) -> list[str]:
    text = raw or ""
    roles: list[str] = []
    seen: set[str] = set()
    for part in text.replace("\n", ",").split(","):
        role = part.strip().lower().replace(" ", "_")
        if not role or role in seen:
            continue
        seen.add(role)
        roles.append(role)
    return roles or _default_source_role_types(source_type)


def _source_metadata(*, source_type: str, role_types: str | None) -> dict[str, Any]:
    return {"role_types": _parse_role_types(role_types, source_type)}


def _blank_source_metadata() -> dict[str, Any]:
    return {"source_roles_version": 1}


def _connector_config_from_form(connector_key: str, form: Any) -> dict[str, Any]:
    definition = get_connector(connector_key)
    allowed = set(definition.credential_fields) | {
        "base_url",
        "auth_header",
        "token",
        "token_ref",
        "probe_path",
        "host",
        "port",
        "database",
        "user",
        "username",
        "password",
        "password_ref",
        "bucket",
        "prefix",
        "region_name",
        "endpoint_url",
        "aws_access_key_id",
        "aws_access_key_id_ref",
        "aws_secret_access_key",
        "aws_secret_access_key_ref",
        "account",
        "warehouse",
        "schema",
        "role",
        "subdomain",
        "email",
        "api_token",
        "api_token_ref",
        "workspace",
        "bot_token",
        "bot_token_ref",
        "channel_types",
        "include_messages",
        "include_threads",
        "include_files",
        "max_channels",
        "max_messages_per_channel",
        "max_replies_per_thread",
        "max_files",
        "org",
        "owner",
        "repo_names",
        "group",
        "project",
        "ref",
        "include_code_paths",
        "max_repos",
        "max_projects",
        "max_issues_per_repo",
        "max_prs_per_repo",
        "max_releases_per_repo",
        "max_workflows_per_repo",
        "max_issues_per_project",
        "max_mrs_per_project",
        "max_pipelines_per_project",
        "brand_id",
        "group_id",
        "organization_id",
        "status",
        "include_users",
        "include_organizations",
        "include_ticket_comments",
        "max_tickets",
        "max_articles",
        "max_users",
        "max_organizations",
        "client_id",
        "client_secret",
        "client_secret_ref",
        "authenticator",
        "application",
        "private_key",
        "private_key_ref",
        "collect_query_history",
        "instance_url",
        "workspace_domain",
        "enabled_services",
        "access_token",
        "access_token_ref",
        "credentials_file",
        "credentials_file_ref",
        "service_account_json",
        "service_account_json_ref",
        "gws_config_dir",
        "project_id",
        "subject_user",
        "drive_id",
        "drive_query",
        "max_drive_files",
        "gmail_users",
        "gmail_labels",
        "gmail_query",
        "max_gmail_messages",
        "calendar_ids",
        "calendar_time_min",
        "calendar_time_max",
        "max_calendar_events",
        "max_chat_spaces",
        "admin_report_applications",
        "admin_report_user_key",
        "max_admin_activities",
        "location",
        "driver",
        "connection_string",
        "connection_string_ref",
        "api_key",
        "api_key_ref",
        "indices",
        "max_docs_per_index",
        "collections",
        "max_points_per_collection",
        "security_token",
        "security_token_ref",
        "session_id",
        "session_id_ref",
        "domain",
        "objects",
        "max_records_per_object",
        "integration_token",
        "integration_token_ref",
        "notion_version",
        "max_results",
    }
    cfg: dict[str, Any] = {}
    for key in allowed:
        value = form.get(key)
        if value is None:
            continue
        text = str(value).strip()
        if not text:
            continue
        if key == "port":
            try:
                cfg[key] = int(text)
            except ValueError:
                cfg[key] = text
        else:
            cfg[key] = text
    return cfg


_EDITABLE_CONFIG_KEYS = _SAFE_CONFIG_KEYS | {
    "password_ref",
    "token_ref",
    "api_token_ref",
    "bot_token_ref",
    "aws_access_key_id_ref",
    "aws_secret_access_key_ref",
    "client_secret_ref",
    "private_key_ref",
    "access_token_ref",
    "credentials_file_ref",
    "service_account_json_ref",
    "connection_string_ref",
    "api_key_ref",
    "security_token_ref",
    "session_id_ref",
    "integration_token_ref",
    "enabled_services",
    "drive_query",
    "gmail_users",
    "gmail_query",
    "calendar_ids",
    "calendar_time_min",
    "calendar_time_max",
    "indices",
    "collections",
    "objects",
    "sslmode",
    "ssl_ca",
    "sslrootcert",
    "probe_path",
}

# The TLS modes the edit page offers for a PostgreSQL upstream, strongest first.
# Production accepts only the verifying two (`upstream_tls_refusal`).
_POSTGRES_TLS_MODES = ("verify-full", "verify-ca", "require", "disable")
# The console writes `sslmode` and `ssl_ca`. Other spellings of the same field
# outrank or sit beside them in `read_connection_field`, so a console edit
# removes those rather than leaving the old posture in effect.
_POSTGRES_TLS_EDIT_GROUPS = {
    "sslmode": CONFIG_ALIASES["ssl"],
    "ssl_ca": CONFIG_ALIASES["ssl_ca"],
}


def _postgres_tls_config(values: Any) -> dict[str, Any]:
    """The TLS fields a console form or wizard draft carries for PostgreSQL."""
    tls: dict[str, Any] = {}
    for key in ("sslmode", "ssl_ca"):
        text = str(values.get(key) or "").strip()
        if text:
            tls[key] = text
    return tls


def _private_egress_config(values: Any) -> dict[str, Any]:
    """`allow_private_egress` from a console form or wizard draft's checkbox.

    Sources on a private network (a Compose service, a VPC address) are refused
    unless the source opts in, exactly as through the API. The console had no
    way to opt in, so the quick start had to leave it for curl. The API accepts
    the flag in every environment and logs each use; the console does the same.
    """
    value = str(values.get("allow_private_egress") or "").strip().lower()
    return {"allow_private_egress": True} if value in {"on", "true", "1", "yes"} else {}


def _http_probe_config(values: Any, connector_key: str) -> dict[str, Any]:
    """An HTTP source's `probe_path`: the route Test Connection requests."""
    text = str(values.get("probe_path") or "").strip()
    return {"probe_path": text} if text and connector_key == "generic_rest" else {}


def _console_tls_refusal(request: Request, source_type: str, cfg: dict[str, Any]) -> str | None:
    """Refuse at save what the production TLS gate would refuse at connect.

    No console write path could set a PostgreSQL source's TLS, and none
    consulted the gate, so a source registered through the console in
    production looked saved and was then refused on every protocol.
    """
    if source_type != "postgresql":
        return None
    return upstream_tls_refusal(
        cfg, allow_insecure_tls=allows_insecure_upstream_tls(request.app.state.config)
    )


def _postgres_tls_edit_fields(cfg: dict[str, Any]) -> dict[str, Any]:
    """The stored TLS posture as the edit page presents it: the spelling in effect."""
    current: dict[str, Any] = {}
    for key, group in _POSTGRES_TLS_EDIT_GROUPS.items():
        current[key] = next(
            (str(cfg[alias]) for alias in group if cfg.get(alias) not in (None, "")), ""
        )
    modes = list(_POSTGRES_TLS_MODES)
    if current["sslmode"] and current["sslmode"] not in modes:
        # Offer a stored mode the console would not suggest, so saving an
        # unrelated field does not silently change it.
        modes.append(current["sslmode"])
    current["modes"] = modes
    return current


def _editable_connection_fields(
    cfg: dict[str, Any], *, exclude: frozenset[str] = frozenset()
) -> list[dict[str, str]]:
    fields: list[dict[str, str]] = []
    for key in sorted(cfg):
        if key not in _EDITABLE_CONFIG_KEYS or key in exclude:
            continue
        value = cfg.get(key)
        if isinstance(value, (dict, list)):
            text = json.dumps(value, sort_keys=True)
        elif value is None:
            text = ""
        else:
            text = str(value)
        fields.append({"key": key, "value": text})
    return fields


def _connector_key_from_source_type(source_type: str, connector_key: str | None = None) -> str:
    if connector_key:
        return connector_key
    return connector_key_for(source_type, None)


def _source_role_templates(
    source_type: str,
    connector_key: str | None = None,
) -> dict[str, list[dict[str, Any]]]:
    key = _connector_key_from_source_type(source_type, connector_key)
    templates = role_templates_for_connector(key)
    if templates:
        return templates
    kind = (source_type or "").lower()
    if kind in {"postgresql", "mysql"}:
        base = [
            {
                "effect": "allow",
                "action": "db.schema.list",
                "resource_type": "db.schema",
                "resource_pattern": "*",
            },
            {
                "effect": "allow",
                "action": "db.table.describe",
                "resource_type": "db.table",
                "resource_pattern": "*.*",
            },
            {
                "effect": "allow",
                "action": "db.table.select",
                "resource_type": "db.table",
                "resource_pattern": "*.*",
            },
        ]
        return {
            "read": base,
            "analyst": base,
            "write": [
                *base,
                {
                    "effect": "allow",
                    "action": "db.table.insert",
                    "resource_type": "db.table",
                    "resource_pattern": "*.*",
                },
                {
                    "effect": "allow",
                    "action": "db.table.update",
                    "resource_type": "db.table",
                    "resource_pattern": "*.*",
                },
            ],
            "owner": [
                {"effect": "allow", "action": "*", "resource_type": "*", "resource_pattern": "*"},
            ],
            "blocked": [
                {"effect": "deny", "action": "*", "resource_type": "*", "resource_pattern": "*"},
            ],
        }
    if kind == "http":
        read = [
            {
                "effect": "allow",
                "action": "http.get",
                "resource_type": "http.path",
                "resource_pattern": "/*",
            },
            {
                "effect": "allow",
                "action": "http.head",
                "resource_type": "http.path",
                "resource_pattern": "/*",
            },
        ]
        write = [
            *read,
            {
                "effect": "allow",
                "action": "http.post",
                "resource_type": "http.path",
                "resource_pattern": "/*",
            },
            {
                "effect": "allow",
                "action": "http.put",
                "resource_type": "http.path",
                "resource_pattern": "/*",
            },
            {
                "effect": "allow",
                "action": "http.patch",
                "resource_type": "http.path",
                "resource_pattern": "/*",
            },
        ]
        return {
            "read": read,
            "writer": write,
            "write": write,
            "owner": [
                {"effect": "allow", "action": "*", "resource_type": "*", "resource_pattern": "*"}
            ],
            "blocked": [
                {"effect": "deny", "action": "*", "resource_type": "*", "resource_pattern": "*"}
            ],
        }
    return {
        "read": [{"effect": "allow", "action": "*", "resource_type": "*", "resource_pattern": "*"}],
        "write": [
            {"effect": "allow", "action": "*", "resource_type": "*", "resource_pattern": "*"}
        ],
        "owner": [
            {"effect": "allow", "action": "*", "resource_type": "*", "resource_pattern": "*"}
        ],
        "blocked": [
            {"effect": "deny", "action": "*", "resource_type": "*", "resource_pattern": "*"}
        ],
    }


async def _ensure_default_source_roles(
    pool: Any,
    *,
    source_id: str,
    source_type: str,
    connector_key: str | None = None,
    review_required: bool = False,
) -> None:
    for role_key, permissions in _source_role_templates(source_type, connector_key).items():
        role_id = await pool.fetchval(
            """
            INSERT INTO source_roles
                (source_id, role_key, name, description, review_required, metadata)
            VALUES ($1, $2, $3, $4, $5, $6::jsonb)
            ON CONFLICT (source_id, role_key) DO UPDATE
            SET name = EXCLUDED.name,
                description = EXCLUDED.description,
                updated_at = NOW()
            RETURNING id
            """,
            source_id,
            role_key,
            role_key.replace("_", " ").title(),
            "Default source role template",
            review_required,
            {"template": True},
        )
        await pool.execute(
            "DELETE FROM source_role_permissions WHERE role_id = $1",
            role_id,
        )
        for perm in permissions:
            await pool.execute(
                """
                INSERT INTO source_role_permissions
                    (role_id, effect, action, resource_type, resource_pattern, constraints)
                VALUES ($1, $2, $3, $4, $5, $6::jsonb)
                """,
                role_id,
                perm["effect"],
                perm["action"],
                perm["resource_type"],
                perm["resource_pattern"],
                perm.get("constraints", {}),
            )


def _role_rows_by_source(rows: list[Any]) -> dict[str, list[dict[str, Any]]]:
    by_source: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        role = dict(row)
        by_source.setdefault(role["source_id"], []).append(role)
    return by_source


def _identity_source_roles(row: dict[str, Any]) -> list[dict[str, str]]:
    metadata = row.get("metadata") or {}
    if isinstance(metadata, str):
        try:
            metadata = json.loads(metadata)
        except (TypeError, ValueError):
            metadata = {}
    grants = metadata.get("source_roles", []) if isinstance(metadata, dict) else []
    out: list[dict[str, str]] = []
    for grant in grants:
        if not isinstance(grant, dict):
            continue
        source_id = str(grant.get("source_id") or "").strip()
        role = str(grant.get("role") or "").strip()
        if source_id and role:
            out.append({"source_id": source_id, "role": role})
    return out


def _flatten_source_roles(source_roles: list[dict[str, str]]) -> list[str]:
    roles: list[str] = []
    for grant in source_roles:
        source_id = grant.get("source_id")
        role = grant.get("role")
        if source_id and role:
            roles.append(f"{source_id}:{role}")
            roles.append(role)
    return roles


async def _identity_grants_by_identities(
    pool: Any,
    identity_ids: list[int],
) -> dict[int, list[dict[str, Any]]]:
    if not identity_ids:
        return {}
    try:
        rows = await pool.fetch(
            """
            SELECT g.id AS grant_id,
                   g.identity_id,
                   g.source_id,
                   g.role_id,
                   r.role_key AS role,
                   r.name AS role_name,
                   r.review_required,
                   ds.name AS source_name
            FROM identity_source_role_grants g
            JOIN source_roles r ON r.id = g.role_id
            LEFT JOIN data_sources ds ON ds.source_id = g.source_id
            WHERE g.identity_id = ANY($1::bigint[])
              AND g.enabled = TRUE
              AND r.enabled = TRUE
              AND (g.expires_at IS NULL OR g.expires_at > NOW())
            ORDER BY g.identity_id, ds.name, r.name
            """,
            identity_ids,
        )
    except Exception:
        logger.debug("source-role grant lookup failed", exc_info=True)
        return {}
    grants: dict[int, list[dict[str, Any]]] = {}
    for row in rows:
        grant = dict(row)
        grants.setdefault(int(grant["identity_id"]), []).append(grant)
    return grants


def _parse_source_role_form(form: Any) -> list[dict[str, str]]:
    getlist = getattr(form, "getlist", None)
    if getlist is None:
        return []
    source_ids = list(getlist("grant_source_id"))
    roles = list(getlist("grant_role"))
    role_ids = list(getlist("grant_role_id"))
    grants: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    max_len = max(len(source_ids), len(roles), len(role_ids))
    for idx in range(max_len):
        source_id = str(source_ids[idx] if idx < len(source_ids) else "").strip()
        role = str(roles[idx] if idx < len(roles) else "").strip()
        role_id = str(role_ids[idx] if idx < len(role_ids) else "").strip()
        source_id = str(source_id or "").strip()
        role = str(role or "").strip()
        if not source_id or not (role or role_id):
            continue
        key = (source_id, role_id or role)
        if key in seen:
            continue
        seen.add(key)
        grant = {"source_id": source_id, "role": role}
        if role_id:
            grant["role_id"] = role_id
        grants.append(grant)
    return grants


async def _persist_identity_source_role_grants(
    pool: Any,
    *,
    identity_id: int,
    source_roles: list[dict[str, str]],
    granted_by: int | None = None,
) -> None:
    """Apply the grants chosen on the identity form.

    Delegates to `core.source_role_grants` so this path cannot drift from the
    API's. It used to resolve a `role_key` scoped to the source but accept a
    supplied `role_id` unchecked, which stored a grant the read path can never
    match - a silent no-op that reads as success.

    A grant that cannot be applied is logged and skipped rather than failing
    the request, because the identity row already exists by this point and
    aborting here would leave it without its key shown. That is a deliberate
    trade, and the warning is how an operator finds out.
    """
    if not source_roles:
        return
    for requested in source_roles:
        source_id = requested.get("source_id")
        if not source_id:
            continue
        raw_role_id = requested.get("role_id")
        try:
            await source_role_grants.grant(
                pool,
                identity_id=identity_id,
                source_id=source_id,
                role_key=requested.get("role") or None,
                role_id=int(raw_role_id) if raw_role_id else None,
                granted_by=granted_by,
                metadata={"created_from": "admin_identity_form"},
            )
        except source_role_grants.GrantError:
            logger.warning(
                "Skipped a source-role grant for identity=%s source=%s: the role "
                "could not be resolved for that source",
                identity_id,
                source_id,
                exc_info=True,
            )


async def _hydrate_source_role_keys(
    pool: Any,
    source_roles: list[dict[str, str]],
) -> list[dict[str, str]]:
    hydrated: list[dict[str, str]] = []
    for grant in source_roles:
        if grant.get("role") or not grant.get("role_id"):
            hydrated.append(grant)
            continue
        row = await pool.fetchrow(
            "SELECT role_key FROM source_roles WHERE id = $1",
            int(grant["role_id"]),
        )
        hydrated.append(
            {
                **grant,
                "role": str(row["role_key"]) if row else "",
            }
        )
    return hydrated


def _default_source_role_form(
    source_id: str,
    connector_key: str,
    **overrides: Any,
) -> dict[str, Any]:
    # The connector's own reader template: S3 starts from `reader`, Slack from
    # `channel_reader`. Resolving from source_type alone gave every SaaS source
    # (Slack, GitHub, Zendesk...) HTTP/REST's `http.get` statements.
    _template_key, default_permissions = default_role_template(connector_key)
    form = {
        "source_id": source_id,
        "role_key": "",
        "name": "",
        "description": "",
        "enabled": "on",
        "review_required": "",
        "permissions": default_permissions,
    }
    form.update(overrides)
    return form


def _parse_permissions_form(form: Any) -> tuple[list[dict[str, Any]], str | None]:
    getlist = getattr(form, "getlist", None)
    if getlist is None:
        return [], None
    effects = list(getlist("permission_effect"))
    actions = list(getlist("permission_action"))
    resource_types = list(getlist("permission_resource_type"))
    patterns = list(getlist("permission_resource_pattern"))
    constraints = list(getlist("permission_constraints"))
    permissions: list[dict[str, Any]] = []
    max_len = max(len(effects), len(actions), len(resource_types), len(patterns), 1)
    for idx in range(max_len):
        effect = str(effects[idx] if idx < len(effects) else "allow").strip()
        action = str(actions[idx] if idx < len(actions) else "").strip()
        resource_type = str(resource_types[idx] if idx < len(resource_types) else "").strip()
        pattern = str(patterns[idx] if idx < len(patterns) else "").strip()
        constraint_text = str(constraints[idx] if idx < len(constraints) else "").strip()
        if not action and not resource_type and not pattern:
            continue
        if effect not in {"allow", "deny"}:
            return [], "Permission effect must be allow or deny."
        if not action or not resource_type or not pattern:
            return (
                [],
                "Every permission statement needs an action, resource type, and resource pattern.",
            )
        try:
            parsed_constraints = json.loads(constraint_text) if constraint_text else {}
        except json.JSONDecodeError as exc:
            return [], f"Invalid constraints JSON on permission {idx + 1}: {exc}"
        if not isinstance(parsed_constraints, dict):
            return [], "Permission constraints must be a JSON object."
        permissions.append(
            {
                "effect": effect,
                "action": action,
                "resource_type": resource_type,
                "resource_pattern": pattern,
                "constraints": parsed_constraints,
            }
        )
    if not permissions:
        return [], "Add at least one allow or deny permission statement."
    return permissions, None


def _role_connector_key(source: dict[str, Any]) -> str:
    metadata = source.get("metadata") or {}
    if isinstance(metadata, str):
        try:
            metadata = json.loads(metadata)
        except (TypeError, ValueError):
            metadata = {}
    return get_connector(str(source.get("source_type") or ""), metadata or None).key


async def _role_vocabulary(pool: Any, source_id: str) -> Vocabulary:
    row = await pool.fetchrow(
        "SELECT source_type, metadata FROM data_sources WHERE source_id = $1", source_id
    )
    return vocabulary_for(_role_connector_key(dict(row)) if row is not None else "generic_rest")


def _vocabulary_error(
    vocab: Vocabulary,
    permissions: list[dict[str, Any]],
    stored: list[dict[str, Any]],
) -> str | None:
    """Why these statements cannot be saved for this connector, or None.

    Statements identical to ones already stored are kept as saved, so every
    existing role stays saveable; changed statements must fit the connector.
    """
    errors = [
        issue
        for issue in validate_statements(vocab, permissions, stored=stored)
        if issue.severity == "error"
    ]
    if not errors:
        return None
    return " ".join(f"Statement {issue.index + 1}: {issue.message}" for issue in errors)


async def _pattern_suggestions(
    pool: Any, source_id: str, connector_key: str
) -> dict[str, list[tuple[str, str]]]:
    """Catalogued names as ready-made patterns, per resource type."""
    try:
        rows = await pool.fetch(
            """
            SELECT node_type, resource_key, name
            FROM source_catalog
            WHERE source_id = $1 AND removed_at IS NULL
              AND node_type IN ('schema', 'table', 'view', 'materialized_view',
                                'foreign_table', 'bucket', 'prefix', 'channel',
                                'repository', 'object', 'index', 'collection')
            ORDER BY resource_key
            LIMIT 500
            """,
            source_id,
        )
    except Exception:
        logger.debug("pattern suggestions failed", exc_info=True)
        return {}
    suggestions: dict[str, list[tuple[str, str]]] = {}
    for row in rows:
        targets = pick_targets(connector_key, str(row["node_type"]), str(row["resource_key"]))
        if targets is None:
            continue
        label = f"{row['node_type']} {row['name']}"
        for rtype, pattern in targets.patterns.items():
            bucket = suggestions.setdefault(rtype, [])
            if len(bucket) < 200 and all(value != pattern for value, _ in bucket):
                bucket.append((pattern, label))
    return suggestions


_COMMON_FILE_EXTENSIONS = (".csv", ".json", ".txt", ".md", ".pdf", ".parquet", ".xlsx", ".docx")


async def _constraint_suggestions(pool: Any, source_id: str) -> dict[str, list[tuple[str, str]]]:
    """Values the conditions builder can offer, from the source's catalog."""
    suggestions: dict[str, list[tuple[str, str]]] = {
        "file_extensions": [(ext, ext) for ext in _COMMON_FILE_EXTENSIONS]
    }
    try:
        rows = await pool.fetch(
            """
            SELECT node_type, resource_key, name
            FROM source_catalog
            WHERE source_id = $1 AND removed_at IS NULL
              AND node_type IN ('channel', 'repository', 'index', 'collection')
            ORDER BY name
            LIMIT 500
            """,
            source_id,
        )
    except Exception:
        logger.debug("constraint suggestions failed", exc_info=True)
        return suggestions

    def add(key: str, value: str, label: str) -> None:
        values = suggestions.setdefault(key, [])
        if value and all(existing != value for existing, _ in values):
            values.append((value, label))

    for row in rows:
        node_type, key, name = str(row["node_type"]), str(row["resource_key"]), str(row["name"])
        if node_type == "channel":
            add("channel_ids", key.rsplit("/", 1)[-1], f"#{name}")
        elif node_type == "repository":
            parts = key.split("://repo/", 1)[-1].split("/")
            if len(parts) == 2:
                add("orgs", parts[0], parts[0])
                add("repos", parts[1], "/".join(parts))
        elif node_type == "index":
            add("indices", name, name)
        elif node_type == "collection":
            add("collections", name, name)
    return suggestions


def _role_form_from_post(
    form: Any,
    permissions: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "role_key": str(form.get("role_key") or "").strip(),
        "name": str(form.get("name") or "").strip(),
        "description": str(form.get("description") or "").strip(),
        "enabled": "on" if form.get("enabled") == "on" else "",
        "review_required": "on" if form.get("review_required") == "on" else "",
        "permissions": permissions,
    }


async def _source_role_context(
    request: Request,
    *,
    source_id: str,
    form: dict[str, Any] | None = None,
    role_id: int | None = None,
    error: str | None = None,
) -> dict[str, Any]:
    pool = request.app.state.pg_pool
    source = await pool.fetchrow(
        "SELECT source_id, name, source_type, metadata FROM data_sources WHERE source_id = $1",
        source_id,
    )
    if source is None:
        return {
            "active_page": "data-sources",
            "source": None,
            "form": form,
            "role_id": role_id,
            "error": f"Data source {source_id!r} not found.",
        }
    source_dict = dict(source)
    connector_key = _role_connector_key(source_dict)
    if form is None and role_id is not None:
        role = await pool.fetchrow(
            "SELECT * FROM source_roles WHERE id = $1 AND source_id = $2",
            role_id,
            source_id,
        )
        if role is not None:
            perm_rows = await pool.fetch(
                """
                SELECT effect, action, resource_type, resource_pattern, constraints
                FROM source_role_permissions
                WHERE role_id = $1
                ORDER BY id
                """,
                role_id,
            )
            role_dict = dict(role)
            form = {
                "role_key": role_dict["role_key"],
                "name": role_dict["name"],
                "description": role_dict.get("description") or "",
                "enabled": "on" if role_dict.get("enabled") else "",
                "review_required": "on" if role_dict.get("review_required") else "",
                "permissions": [dict(r) for r in perm_rows],
            }
    if form is None:
        form = _default_source_role_form(source_id, connector_key)
    vocab = vocabulary_for(connector_key)
    return {
        "active_page": "data-sources",
        "source": source_dict,
        "connector": CONNECTOR_DEFINITIONS.get(connector_key),
        "vocab": vocab,
        "pattern_suggestions": await _pattern_suggestions(pool, source_id, connector_key),
        "constraint_suggestions": await _constraint_suggestions(pool, source_id),
        "form": form,
        "role_id": role_id,
        "error": error,
    }


async def _identity_form_context(
    request: Request,
    *,
    form: dict[str, Any] | None = None,
    error: str | None = None,
    revealed_key: str | None = None,
) -> dict[str, Any]:
    pool = request.app.state.pg_pool
    rows = await pool.fetch(
        "SELECT source_id, name, source_type, metadata "
        "FROM data_sources WHERE enabled = TRUE ORDER BY name"
    )
    data_sources = [dict(r) for r in rows]
    try:
        role_rows = await pool.fetch("""
            SELECT id, source_id, role_key, name, review_required
            FROM source_roles
            WHERE enabled = TRUE
            ORDER BY source_id, name
            """)
        role_options_by_source = _role_rows_by_source(role_rows)
    except Exception:
        role_options_by_source = {
            src["source_id"]: [
                {"id": "", "role_key": role, "name": role, "source_id": src["source_id"]}
                for role in _source_role_options(src)
            ]
            for src in data_sources
        }
    return {
        "active_page": "identities",
        "form": form or _default_identity_form(),
        "data_sources": data_sources,
        "role_options_by_source": role_options_by_source,
        "error": error,
        "revealed_key": revealed_key,
    }


def _default_policy_form(**overrides: Any) -> dict[str, Any]:
    form = {
        "name": "",
        "priority": 0,
        "cond_source_id": "",
        "cond_operation": "",
        "cond_roles": "",
        "cond_identity_roles": "",
        "cond_tables": "",
        "cond_columns": "",
        "action_effect": "allow",
        "action_rate_limit": "",
        "action_redact_columns": "",
        "raw_conditions": "",
        "raw_actions": "",
    }
    form.update(overrides)
    return form


def _default_alert_form(**overrides: Any) -> dict[str, Any]:
    form = {
        "name": "",
        "description": "",
        "condition_type": "error_rate",
        "comparator": ">",
        "threshold": "0.1",
        "window_seconds": "300",
        "source_id": "",
        "identity_id": "",
        "notification_channel": "log",
        "notification_target": "",
    }
    form.update(overrides)
    return form


def _alert_channels(request: Request) -> list[dict[str, Any]]:
    config = getattr(request.app.state, "config", None)
    notifications = getattr(config, "notifications", None)
    slack_enabled = bool(getattr(notifications, "slack_webhook_url", None))
    email_enabled = bool(getattr(notifications, "smtp_host", None))
    webhook_enabled = bool(getattr(notifications, "webhook_url", None))
    return [
        {"name": "log", "enabled": True, "note": "Always available"},
        {
            "name": "slack",
            "enabled": slack_enabled,
            "note": "Configure Slack webhook to enable",
        },
        {
            "name": "email",
            "enabled": email_enabled,
            "note": "Configure SMTP settings to enable",
        },
        {
            "name": "webhook",
            "enabled": webhook_enabled,
            "note": "Configure outbound webhook URL to enable",
        },
    ]


THEME_COOKIE = "interlock_theme"
_VALID_THEMES = frozenset({"light", "dark"})


def _resolved_theme(request: Request) -> str:
    """The operator's explicit theme choice, or "" to follow the OS.

    Returned into every template so base.html can stamp `data-theme` on
    <html> before first paint. The usual way to do this is an inline script in
    <head>, which `script-src 'self'` forbids, so the server does it instead.
    """
    value = request.cookies.get(THEME_COOKIE, "")
    return value if value in _VALID_THEMES else ""


def _admin_username(request: Request) -> str:
    admin = getattr(request.state, "admin", None)
    for attr in ("username", "name", "email"):
        value = getattr(admin, attr, None)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def build_sparkline(
    values: list[int],
    *,
    width: int = 640,
    height: int = 40,
) -> dict[str, Any]:
    """Turn a series into SVG geometry for an inline sparkline.

    Server-rendered because the Admin CSP is `script-src 'self'` with no
    bundler: a charting library would need either a CSP exception or a build
    step. An SVG path is just markup, so it needs neither.

    Returns empty strings for a series that cannot be drawn, letting the
    template fall back to an empty state instead of rendering a flat line that
    looks like real "zero traffic" data.
    """
    points = [max(0, int(v)) for v in values]
    if len(points) < 2:
        return {"line": "", "area": "", "width": width, "height": height, "max": 0}

    peak = max(points)
    span = len(points) - 1
    step = width / span
    # A flat series sits on the baseline rather than mid-height.
    scale = (height - 2) / peak if peak > 0 else 0

    coords = [(round(i * step, 2), round(height - 1 - v * scale, 2)) for i, v in enumerate(points)]
    line = " ".join(f"{x},{y}" for x, y in coords)
    area = f"0,{height} " + line + f" {width},{height}"
    return {"line": line, "area": area, "width": width, "height": height, "max": peak}


def _session_roles(request: Request) -> tuple[str, ...] | None:
    """The signed-in admin's roles, or None when there is no session."""
    admin = getattr(request.state, "admin", None)
    if admin is None:
        return None
    return tuple(getattr(admin, "roles", None) or ())


def _render(request: Request, template: str, context: dict[str, Any]) -> HTMLResponse:
    """Render a template. Uses request.app.state.templates (Jinja2Templates)."""
    templates = request.app.state.templates
    context.setdefault("theme", _resolved_theme(request))
    context.setdefault("admin_username", _admin_username(request))
    roles = _session_roles(request)
    # With authentication disabled (unit tests) there is no session: show the
    # console as an administrator would see it.
    context.setdefault("is_console_admin", roles is None or is_console_admin(roles))
    context.setdefault("is_read_only", roles is not None and is_read_only(roles))
    return templates.TemplateResponse(request, template, context)


def _admin_session_key(request: Request) -> str:
    admin = getattr(request.state, "admin", None)
    admin_id = getattr(admin, "admin_id", None)
    if admin_id is not None:
        return f"admin:{admin_id}"
    if getattr(request.app.state, "auth_disabled", False):
        return "test-admin"
    return "anonymous"


def _wizard_redis_key(request: Request, wizard_id: str) -> str:
    return f"admin:wizard:{_admin_session_key(request)}:{wizard_id}"


def _new_wizard_id() -> str:
    return secrets.token_urlsafe(18)


async def _maybe_await(value: Any) -> Any:
    if hasattr(value, "__await__"):
        return await value
    return value


async def _save_wizard_draft(
    request: Request,
    wizard_id: str,
    state: dict[str, Any],
) -> None:
    payload = json.dumps(state)
    if getattr(request.app.state, "auth_disabled", False):
        drafts = getattr(request.app.state, "_wizard_drafts", None)
        if drafts is None:
            drafts = {}
            request.app.state._wizard_drafts = drafts
        drafts[_wizard_redis_key(request, wizard_id)] = payload
        return
    redis = getattr(request.app.state, "redis", None)
    if redis is not None and hasattr(redis, "set"):
        await _maybe_await(
            redis.set(
                _wizard_redis_key(request, wizard_id),
                payload,
                ex=WIZARD_DRAFT_TTL_SECONDS,
            )
        )
        return
    raise RuntimeError("Source wizard draft store is unavailable")


async def _load_wizard_draft(request: Request, wizard_id: str) -> dict[str, Any]:
    if not wizard_id:
        return {}
    raw: Any = None
    if getattr(request.app.state, "auth_disabled", False):
        drafts = getattr(request.app.state, "_wizard_drafts", {})
        raw = drafts.get(_wizard_redis_key(request, wizard_id))
    else:
        redis = getattr(request.app.state, "redis", None)
        if redis is not None and hasattr(redis, "get"):
            raw = await _maybe_await(redis.get(_wizard_redis_key(request, wizard_id)))
    if isinstance(raw, bytes):
        raw = raw.decode()
    if not raw:
        return {}
    try:
        data = json.loads(raw)
    except (TypeError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


async def _delete_wizard_draft(request: Request, wizard_id: str) -> None:
    if not wizard_id:
        return
    if getattr(request.app.state, "auth_disabled", False):
        drafts = getattr(request.app.state, "_wizard_drafts", None)
        if isinstance(drafts, dict):
            drafts.pop(_wizard_redis_key(request, wizard_id), None)
        return
    redis = getattr(request.app.state, "redis", None)
    if redis is not None and hasattr(redis, "delete"):
        await _maybe_await(redis.delete(_wizard_redis_key(request, wizard_id)))
        return


async def _policies_for_source(pool: Any, source_id: str) -> list[dict[str, Any]]:
    """Enabled rules the engine would consider for this source, in evaluation order.

    Matching uses the engine's own source test, so a rule scoped to another
    source through `source_ids` is not listed and an unscoped rule is.
    Disabled rules are left out because the engine never loads them.
    """
    rows = await pool.fetch("""
        SELECT id, name, priority, conditions, actions
        FROM policy_rules
        WHERE enabled = TRUE
        ORDER BY priority DESC, name
        """)
    try:
        hit_rows = await pool.fetch(
            """
            SELECT policy_decision->>'rule_id' AS rule_id, count(*) AS hits
            FROM audit_log
            WHERE source_id = $1
              AND created_at >= NOW() - INTERVAL '7 days'
              AND policy_decision->>'rule_id' IS NOT NULL
            GROUP BY 1
            """,
            source_id,
        )
        hits = {str(r["rule_id"]): int(r["hits"]) for r in hit_rows}
    except Exception:
        logger.debug("policy hit counts failed", exc_info=True)
        hits = {}
    policies = []
    for row in rows:
        policy = dict(row)
        if not applies_to_source(policy.get("conditions"), source_id):
            continue
        policy["effect"] = effect_of(policy.get("actions"))
        policy["description"] = describe_policy(policy.get("conditions"), policy.get("actions"))
        policy["scoped"] = bool(rule_source_ids(as_policy_dict(policy.get("conditions"))))
        policy["hits_7d"] = hits.get(str(policy["id"]), 0)
        policies.append(policy)
    return policies


def _source_id_refusal(source_id: str) -> str | None:
    try:
        validate_source_id(source_id)
    except InvalidSourceIdError as exc:
        return str(exc)
    return None


async def _inactive_connector_error(pool: Any, connector_key: str) -> str | None:
    """Why a source cannot be registered on this connector, or None."""
    try:
        await require_active(pool, connector_key)
    except ConnectorNotActiveError as exc:
        return str(exc)
    return None


def _mutation_redirect(request: Request, url: str) -> Response:
    """Redirect after a mutation without swapping full pages into HTMX targets."""
    if _is_htmx(request):
        return HTMLResponse("", headers={"HX-Redirect": url})
    return RedirectResponse(url=url, status_code=303)


# ---------------------------------------------------------------------------
# Index redirect
# ---------------------------------------------------------------------------


@router.get("/", response_class=HTMLResponse)
async def dashboard_index(request: Request) -> RedirectResponse:
    """Redirect root to overview."""
    return RedirectResponse(url="/dashboard/overview", status_code=302)


@router.post("/dashboard/theme")
async def set_theme(
    request: Request,
    theme: str = Form(""),
    next: str = Form("/dashboard/overview"),
) -> Response:
    """Persist the operator's colour-theme choice in a cookie.

    A plain form post rather than JavaScript, so the toggle works under
    `script-src 'self'` and with scripting disabled. `next` is constrained to
    a local absolute path so the control cannot be turned into an open
    redirect.
    """
    target = next if next.startswith("/") and not next.startswith("//") else "/dashboard/overview"
    response = _mutation_redirect(request, target)
    if theme in _VALID_THEMES:
        response.set_cookie(
            THEME_COOKIE,
            theme,
            max_age=60 * 60 * 24 * 365,
            httponly=False,
            samesite="lax",
            secure=request.url.scheme == "https",
            path="/",
        )
    else:
        response.delete_cookie(THEME_COOKIE, path="/")
    return response


# ---------------------------------------------------------------------------
# Overview
# ---------------------------------------------------------------------------


@router.get("/dashboard/overview", response_class=HTMLResponse)
async def overview_page(request: Request) -> HTMLResponse:
    """System overview with stats and recent activity."""
    pool = request.app.state.pg_pool

    # Requests in last 24h
    requests_24h = (
        await pool.fetchval(
            "SELECT count(*) FROM audit_log WHERE created_at >= NOW() - INTERVAL '24 hours'"
        )
        or 0
    )

    # Cache hit rate (24h)
    cache_rate_row = await pool.fetchrow(
        "SELECT COALESCE(AVG(CASE WHEN cache_hit THEN 1.0 ELSE 0.0 END), 0) AS rate "
        "FROM audit_log WHERE created_at >= NOW() - INTERVAL '24 hours'"
    )
    cache_hit_rate = round((cache_rate_row["rate"] if cache_rate_row else 0) * 100)

    # Active sources
    active_sources = (
        await pool.fetchval("SELECT count(*) FROM data_sources WHERE enabled = true") or 0
    )

    worker_ctx = await _worker_status_context(request)

    # Pending approvals
    pending_approvals = (
        await pool.fetchval("SELECT count(*) FROM write_approval_queue WHERE status = 'pending'")
        or 0
    )

    # Errors in last 24h
    errors_24h = (
        await pool.fetchval(
            "SELECT count(*) FROM audit_log WHERE status = 'error' "
            "AND created_at >= NOW() - INTERVAL '24 hours'"
        )
        or 0
    )

    # Job pipeline counts
    job_counts = await pool.fetch(
        "SELECT status, count(*) AS cnt FROM ingestion_jobs GROUP BY status"
    )
    jc = {r["status"]: r["cnt"] for r in job_counts}

    # Recent activity (last 10 audit entries)
    recent_rows = await pool.fetch(f"""
        SELECT a.created_at, a.identity_id, {IDENTITY_NAME_COLUMNS},
               a.source_id, a.operation, a.status
        FROM audit_log a
        {identity_joins("a.identity_id")}
        ORDER BY a.created_at DESC LIMIT 10
        """)
    recent_activity = [dict(r) for r in recent_rows]

    # Cache tier distribution (24h)
    tier_rows = await pool.fetch(
        "SELECT COALESCE(cache_tier, 'miss') AS tier, count(*) AS cnt "
        "FROM audit_log WHERE created_at >= NOW() - INTERVAL '24 hours' "
        "GROUP BY COALESCE(cache_tier, 'miss') ORDER BY cnt DESC"
    )
    total_tier = sum(r["cnt"] for r in tier_rows) or 1
    cache_tiers = [
        {"name": r["tier"], "count": r["cnt"], "pct": round(r["cnt"] / total_tier * 100)}
        for r in tier_rows
    ]

    components = await _gather_component_health(request, worker_ctx)

    ctx = {
        "active_page": "overview",
        "requests_24h": requests_24h,
        "cache_hit_rate": cache_hit_rate,
        "active_sources": active_sources,
        "healthy_workers": worker_ctx["healthy_count"],
        "active_workers": worker_ctx["healthy_count"],
        "active_jobs": worker_ctx["active_jobs"],
        "stale_workers": worker_ctx["stale_count"],
        "queue_depth": worker_ctx["queue_depth"],
        "pending_approvals": pending_approvals,
        "errors_24h": errors_24h,
        "job_queued": jc.get("queued", 0),
        "job_processing": jc.get("processing", 0),
        "job_completed": jc.get("completed", 0),
        "job_failed": jc.get("failed", 0),
        "recent_activity": recent_activity,
        "cache_tiers": cache_tiers,
        "components": components,
    }

    return _render_page(request, "pages/overview.html", "pages/overview.html", ctx)


# P1-B: real component health for the overview page. Probes the
# dependencies the admin can see without RPC into the gateway: PG, Redis,
# worker heartbeats, pending-approval count. Returns a list of dicts the
# template can render directly. Status is one of ok / degraded / down /
# unknown.
async def _gather_component_health(
    request: Request,
    worker_metrics: dict[str, Any] | int,
) -> list[dict[str, Any]]:
    pool = request.app.state.pg_pool
    redis = getattr(request.app.state, "redis", None)
    out: list[dict[str, Any]] = []

    # PostgreSQL
    try:
        await pool.fetchval("SELECT 1")
        out.append({"name": "PostgreSQL", "detail": "primary", "status": "ok"})
    except Exception:
        out.append({"name": "PostgreSQL", "detail": "primary", "status": "down"})

    # Redis
    if redis is None:
        out.append({"name": "Redis", "detail": "not configured", "status": "unknown"})
    else:
        try:
            ping = getattr(redis, "ping", None)
            if ping is None:
                out.append({"name": "Redis", "detail": "no ping", "status": "unknown"})
            else:
                result = await ping()
                if result:
                    out.append({"name": "Redis", "detail": "online", "status": "ok"})
                else:
                    out.append({"name": "Redis", "detail": "no pong", "status": "degraded"})
        except Exception:
            out.append({"name": "Redis", "detail": "unreachable", "status": "down"})

    if isinstance(worker_metrics, int):
        healthy_workers = worker_metrics
        active_jobs = worker_metrics
        stale_workers = 0
        queue_depth = 0
    else:
        healthy_workers = int(worker_metrics.get("healthy_count", 0) or 0)
        active_jobs = int(worker_metrics.get("active_jobs", 0) or 0)
        stale_workers = int(worker_metrics.get("stale_count", 0) or 0)
        queue_depth = int(worker_metrics.get("queue_depth", 0) or 0)

    # Workers
    out.append(
        {
            "name": "Workers",
            "detail": (
                f"{healthy_workers} healthy, {active_jobs} active jobs, "
                f"{queue_depth} queued, {stale_workers} stale"
            ),
            "status": "ok" if healthy_workers > 0 and stale_workers == 0 else "degraded",
        }
    )

    # Pending approvals (informational status)
    try:
        pending = (
            await pool.fetchval(
                "SELECT count(*) FROM write_approval_queue WHERE status = 'pending'"
            )
            or 0
        )
        out.append(
            {
                "name": "Write Approvals",
                "detail": f"{pending} pending",
                "status": "ok" if pending == 0 else "degraded",
            }
        )
    except Exception:
        out.append({"name": "Write Approvals", "detail": "n/a", "status": "unknown"})

    return out


@router.get("/dashboard/overview/components", response_class=HTMLResponse)
async def overview_components_partial(request: Request) -> HTMLResponse:
    """HTMX partial: refresh just the component-grid contents."""
    worker_ctx = await _worker_status_context(request)
    components = await _gather_component_health(request, worker_ctx)
    return _render(
        request,
        "partials/component_grid.html",
        {"components": components},
    )


# ---------------------------------------------------------------------------
# Data Sources
# ---------------------------------------------------------------------------


async def _data_source_list(pool: Any) -> list[dict[str, Any]]:
    """Rows for the data sources table, with 24-hour request counts."""
    rows = await pool.fetch("""
        SELECT ds.*,
               COALESCE(al.req_count, 0) AS request_count,
               al.last_request_at,
               al.error_count
        FROM data_sources ds
        LEFT JOIN (
            SELECT source_id, count(*) AS req_count,
                   max(created_at) AS last_request_at,
                   count(*) FILTER (WHERE status = 'error') AS error_count
            FROM audit_log
            WHERE created_at >= NOW() - INTERVAL '24 hours'
            GROUP BY source_id
        ) al ON ds.source_id = al.source_id
        ORDER BY ds.name
        """)
    data_sources = [_row_to_dict(r) for r in rows]
    for ds in data_sources:
        connector = get_connector(ds.get("source_type") or "", ds.get("metadata") or {})
        ds["connector_key"] = connector.key
        ds["connector_name"] = connector.name
        ds["connector_status"] = connector.status
        ds["credential_mode"] = _credential_mode(_connection_config(ds))
        ds["health_status"] = "error" if ds.get("error_count") else "ok"
    return data_sources


@router.get("/dashboard/data-sources", response_class=HTMLResponse)
async def data_sources_page(request: Request) -> HTMLResponse:
    """Data sources listing with request counts."""
    ctx = {
        "active_page": "data-sources",
        "data_sources": await _data_source_list(request.app.state.pg_pool),
    }
    return _render_page(request, "pages/data_sources.html", "pages/data_sources.html", ctx)


@router.get("/dashboard/connectors", response_class=HTMLResponse)
async def connectors_page(request: Request) -> HTMLResponse:
    """Which connectors new sources can be registered on, and how many use each."""
    return _render_page(
        request,
        "pages/connectors.html",
        "pages/connectors.html",
        await _connectors_context(request),
    )


async def _connectors_context(request: Request, error: str | None = None) -> dict[str, Any]:
    rows = await connector_rows(request.app.state.pg_pool)
    return {
        "active_page": "connectors",
        "active_connectors": [r for r in rows if r["active"]],
        "inactive_connectors": [r for r in rows if not r["active"]],
        "error": error,
    }


@router.post("/dashboard/connectors/{connector_key}/activation", response_class=HTMLResponse)
async def set_connector_activation(connector_key: str, request: Request) -> HTMLResponse:
    """Activate or deactivate a connector for new sources. Existing sources keep working."""
    form = await request.form()
    active = str(form.get("active") or "") == "on"
    admin = getattr(request.state, "admin", None)
    try:
        await set_active(
            request.app.state.pg_pool,
            connector_key,
            active,
            getattr(admin, "admin_id", None),
        )
    except ConnectorNotActiveError as exc:
        return _render_page(
            request,
            "pages/connectors.html",
            "pages/connectors.html",
            await _connectors_context(request, error=str(exc)),
        )
    await audit_admin_action(
        request,
        action="connector.activate" if active else "connector.deactivate",
        resource="connector",
        resource_id=connector_key,
        success=True,
        strict=True,
        detail=mutation_audit_detail(
            after={"connector_key": connector_key, "active": active},
            changed_fields=("active",),
            status_code=200,
        ),
    )
    return _render_page(
        request,
        "pages/connectors.html",
        "pages/connectors.html",
        await _connectors_context(request),
    )


# ---------------------------------------------------------------------------
# Access Control
# ---------------------------------------------------------------------------


async def _load_identities_context(pool: Any) -> dict[str, Any]:
    id_rows = await pool.fetch("SELECT * FROM identities ORDER BY name")
    grant_lookup = await _identity_grants_by_identities(
        pool,
        [int(r["id"]) for r in id_rows],
    )
    identities = []
    for r in id_rows:
        d = dict(r)
        # Parse roles from JSON if stored as string
        roles_val = d.get("roles")
        if isinstance(roles_val, str):
            try:
                d["roles"] = json.loads(roles_val)
            except (json.JSONDecodeError, TypeError):
                d["roles"] = [roles_val] if roles_val else []
        elif roles_val is None:
            d["roles"] = []
        d["source_roles"] = grant_lookup.get(int(d["id"])) or _identity_source_roles(d)
        identities.append(d)

    return {
        "active_page": "identities",
        "identities": identities,
    }


async def _load_policy_context(pool: Any) -> dict[str, Any]:
    id_rows = await pool.fetch("SELECT id, name FROM identities ORDER BY name")
    source_rows = await pool.fetch(
        "SELECT source_id, name, source_type FROM data_sources WHERE enabled = TRUE ORDER BY name"
    )
    role_rows = await pool.fetch("""
        SELECT source_id, role_key, name, id
        FROM source_roles
        WHERE enabled = TRUE
        ORDER BY source_id, role_key
        """)
    source_role_options: dict[str, list[dict[str, Any]]] = {}
    for row in role_rows:
        source_role_options.setdefault(str(row["source_id"]), []).append(dict(row))

    pol_rows = await pool.fetch("SELECT * FROM policy_rules ORDER BY priority DESC, name")
    policy_rules = []
    for r in pol_rows:
        d = dict(r)
        conds = d.get("conditions")
        if isinstance(conds, str):
            try:
                conds = json.loads(conds)
            except (json.JSONDecodeError, TypeError):
                conds = {}
        d["conditions_summary"] = _policy_summary(conds)
        # P2-D: parse actions JSON so the template can reach
        # ``rule.actions.effect`` directly.
        actions = d.get("actions")
        if isinstance(actions, str):
            try:
                d["actions"] = json.loads(actions)
            except (json.JSONDecodeError, TypeError):
                d["actions"] = {}
        elif actions is None:
            d["actions"] = {}
        policy_rules.append(d)

    return {
        "active_page": "policies",
        "identities": [dict(row) for row in id_rows],
        "policy_rules": policy_rules,
        "data_sources": [dict(row) for row in source_rows],
        "source_role_options": source_role_options,
    }


@router.get("/dashboard/access-control", response_class=HTMLResponse)
async def access_control_page_alias(request: Request) -> RedirectResponse:
    """Backward-compatible URL for the split Access Control section."""
    return RedirectResponse(url="/dashboard/access-control/identities", status_code=307)


@router.get("/dashboard/access-control/identities", response_class=HTMLResponse)
async def identities_page(request: Request) -> HTMLResponse:
    """Identity directory."""
    pool = request.app.state.pg_pool
    ctx = await _load_identities_context(pool)
    return _render_page(request, "pages/identities.html", "pages/identities.html", ctx)


@router.get("/dashboard/policies", response_class=HTMLResponse)
async def policies_page(request: Request) -> HTMLResponse:
    """Policy rule management."""
    pool = request.app.state.pg_pool
    ctx = await _load_policy_context(pool)
    return _render_page(request, "pages/policies.html", "pages/policies.html", ctx)


# ---------------------------------------------------------------------------
# Ingestion
# ---------------------------------------------------------------------------


@router.get("/dashboard/ingestion", response_class=HTMLResponse)
async def ingestion_page(
    request: Request,
    status: str = "all",
    source: str = "",
    since: str = "",
    until: str = "",
    page: int = 1,
) -> HTMLResponse:
    """Full page or HTMX partial for ingestion jobs."""
    ctx = await _ingestion_table_context(request, status, source, since, until, page)

    return _render_page(
        request,
        page_template="pages/ingestion.html",
        partial_template="partials/job_table.html",
        ctx=ctx,
    )


async def _ingestion_table_context(
    request: Request,
    status: str = "all",
    source: str = "",
    since: str = "",
    until: str = "",
    page: int = 1,
) -> dict[str, Any]:
    pool = request.app.state.pg_pool

    conditions = []
    params: list[Any] = []
    idx = 1
    if status != "all":
        conditions.append(f"status = ${idx}")
        params.append(status)
        idx += 1
    if source:
        conditions.append(f"source_id = ${idx}")
        params.append(source)
        idx += 1
    if since:
        conditions.append(f"created_at >= ${idx}::timestamptz")
        params.append(since)
        idx += 1
    if until:
        conditions.append(f"created_at <= ${idx}::timestamptz")
        params.append(until)
        idx += 1
    where = (" WHERE " + " AND ".join(conditions)) if conditions else ""

    total = await pool.fetchval(f"SELECT count(*) FROM ingestion_jobs{where}", *params)
    total = total or 0
    total_pages = max(1, math.ceil(total / PAGE_SIZE))
    page = max(1, min(page, total_pages))
    offset = (page - 1) * PAGE_SIZE

    rows = await pool.fetch(
        f"SELECT * FROM ingestion_jobs{where} ORDER BY created_at DESC "
        f"LIMIT ${idx} OFFSET ${idx + 1}",
        *params,
        PAGE_SIZE,
        offset,
    )
    jobs = [_row_to_dict(r) for r in rows]

    # Job status counts for summary stats
    count_rows = await pool.fetch(
        "SELECT status, count(*) AS cnt FROM ingestion_jobs GROUP BY status"
    )
    status_counts = {r["status"]: r["cnt"] for r in count_rows}
    visible_sources = sorted({j["source_id"] for j in jobs if j.get("source_id")})

    ctx = {
        "jobs": jobs,
        "status": status,
        "filter_source": source,
        "filter_since": since,
        "filter_until": until,
        "sources": visible_sources,
        "page": page,
        "total_pages": total_pages,
        "active_page": "ingestion",
        "status_counts": status_counts,
    }

    return ctx


@router.post(
    "/dashboard/ingestion/jobs/{job_id}/retry",
    response_class=HTMLResponse,
    response_model=None,
)
async def retry_ingestion_job_htmx(
    job_id: int,
    request: Request,
) -> Response:
    """Retry a failed/cancelled job and return the refreshed HTMX table."""
    pool = request.app.state.pg_pool
    await pool.fetchrow(
        """
        UPDATE ingestion_jobs
        SET status = 'queued',
            stage = 'queued',
            error_message = NULL,
            worker_id = NULL,
            started_at = NULL,
            completed_at = NULL,
            lease_expires_at = NULL,
            updated_at = NOW()
        WHERE id = $1 AND status IN ('failed', 'cancelled')
        RETURNING id
        """,
        job_id,
    )
    if not _is_htmx(request):
        return RedirectResponse("/dashboard/ingestion", status_code=303)
    filters = await _ingestion_filters_from_request(request)
    ctx = await _ingestion_table_context(request, **filters)
    return _render(request, "partials/job_table.html", ctx)


@router.post(
    "/dashboard/ingestion/jobs/{job_id}/cancel",
    response_class=HTMLResponse,
    response_model=None,
)
async def cancel_ingestion_job_htmx(
    job_id: int,
    request: Request,
) -> Response:
    """Cancel an active queued/processing job and return the refreshed table."""
    pool = request.app.state.pg_pool
    await pool.fetchrow(
        """
        UPDATE ingestion_jobs
        SET status = 'cancelled',
            stage = 'cancelled',
            updated_at = NOW()
        WHERE id = $1
          AND status IN ('queued', 'processing', 'extracting', 'summarizing', 'indexing')
        RETURNING id
        """,
        job_id,
    )
    if not _is_htmx(request):
        return RedirectResponse("/dashboard/ingestion", status_code=303)
    filters = await _ingestion_filters_from_request(request)
    ctx = await _ingestion_table_context(request, **filters)
    return _render(request, "partials/job_table.html", ctx)


async def _ingestion_filters_from_request(request: Request) -> dict[str, Any]:
    """Read ingestion filter state from HTMX form body or query params."""
    try:
        page = int(request.query_params.get("page") or 1)
    except (TypeError, ValueError):
        page = 1
    params: dict[str, Any] = {
        "status": request.query_params.get("status") or "all",
        "source": request.query_params.get("source") or "",
        "since": request.query_params.get("since") or "",
        "until": request.query_params.get("until") or "",
        "page": page,
    }
    try:
        form = await request.form()
    except Exception:
        return params
    for key in ("status", "source", "since", "until"):
        value = form.get(key)
        if value is not None:
            params[key] = str(value)
    if form.get("page"):
        try:
            params["page"] = int(str(form["page"]))
        except (TypeError, ValueError):
            params["page"] = 1
    return params


@router.get("/dashboard/ingestion/jobs/{job_id}", response_class=HTMLResponse)
async def ingestion_job_detail(job_id: int, request: Request) -> HTMLResponse:
    pool = request.app.state.pg_pool
    row = await pool.fetchrow("SELECT * FROM ingestion_jobs WHERE id = $1", job_id)
    if row is None:
        return _render_page(
            request,
            "pages/not_found.html",
            "pages/not_found.html",
            {"active_page": "ingestion", "what": f"ingestion job #{job_id}"},
        )
    return _render_page(
        request,
        "pages/ingestion_job_detail.html",
        "pages/ingestion_job_detail.html",
        {"active_page": "ingestion", "job": _row_to_dict(row)},
    )


# ---------------------------------------------------------------------------
# Workers
# ---------------------------------------------------------------------------


async def _worker_status_context(request: Request) -> dict[str, Any]:
    """Build the shared worker metrics used by Overview and Workers pages."""
    redis = getattr(request.app.state, "redis", None)
    pool = request.app.state.pg_pool
    now = time.time()
    workers_map: dict[str, dict[str, Any]] = {}

    # Source 1: Redis heartbeats (live workers)
    try:
        cursor = b"0"
        while True:
            cursor, keys = await redis.scan(cursor, match="worker:heartbeat:*", count=100)
            for key in keys:
                worker_id = (
                    key.decode().split(":", 2)[-1]
                    if isinstance(key, bytes)
                    else key.split(":", 2)[-1]
                )
                raw = await redis.get(key)
                if raw is None:
                    continue
                data = json.loads(raw)
                last_hb = data.get("timestamp", 0)
                age = now - last_hb

                if age <= WARN_HEARTBEAT_SECONDS:
                    health = "green"
                elif age <= STALE_HEARTBEAT_SECONDS:
                    health = "yellow"
                else:
                    health = "red"

                if age < 60:
                    ago = f"{int(age)}s ago"
                elif age < 3600:
                    ago = f"{int(age // 60)}m ago"
                else:
                    ago = f"{int(age // 3600)}h ago"

                metadata = data.get("metadata") or {}
                active_job_ids = metadata.get("active_job_ids") or data.get("active_job_ids") or []
                current_job = (
                    metadata.get("current_job")
                    if metadata.get("current_job") is not None
                    else data.get("current_job_id")
                )
                workers_map[worker_id] = {
                    "worker_id": worker_id,
                    "health": health,
                    "status": (
                        "Healthy"
                        if health == "green"
                        else ("Warning" if health == "yellow" else "Stale")
                    ),
                    "last_heartbeat_ago": ago,
                    "current_job": current_job,
                    "active_job_ids": active_job_ids,
                    "lease_expires_at": metadata.get("lease_expires_at"),
                    "throughput": metadata.get("throughput"),
                    "source_throttles": metadata.get("source_throttles") or {},
                    "budget_state": metadata.get("budget_state") or {},
                    "source": "heartbeat",
                }
            if cursor == b"0" or cursor == 0:
                break
    except Exception:
        pass  # Redis unavailable - fall through to PG

    # Source 2: PG ingestion_jobs (workers assigned to jobs)
    try:
        rows = await pool.fetch("""
            SELECT worker_id,
                   count(*) FILTER (
                       WHERE status IN ('extracting', 'summarizing', 'indexing', 'processing')
                   ) AS active_jobs,
                   array_remove(array_agg(id) FILTER (
                       WHERE status IN ('extracting', 'summarizing', 'indexing', 'processing')
                   ), NULL) AS active_job_ids,
                   max(lease_expires_at) FILTER (
                       WHERE status IN ('extracting', 'summarizing', 'indexing', 'processing')
                   ) AS lease_expires_at,
                   count(*) FILTER (WHERE status = 'completed') AS completed_jobs,
                   count(*) FILTER (WHERE status = 'failed') AS failed_jobs,
                   max(started_at) AS last_active
            FROM ingestion_jobs
            WHERE worker_id IS NOT NULL
            GROUP BY worker_id
            ORDER BY worker_id
            """)
        for row in rows:
            row_dict = dict(row)
            wid = row["worker_id"]
            if wid not in workers_map:
                active = row["active_jobs"] or 0
                health = "green" if active > 0 else "yellow"
                workers_map[wid] = {
                    "worker_id": wid,
                    "health": health,
                    "status": "Active" if active > 0 else "Idle",
                    "last_heartbeat_ago": "from jobs",
                    "current_job": None,
                    "source": "jobs",
                }
            # Enrich with job stats
            workers_map[wid]["active_jobs"] = row["active_jobs"] or 0
            workers_map[wid]["completed_jobs"] = row["completed_jobs"] or 0
            workers_map[wid]["failed_jobs"] = row["failed_jobs"] or 0
            workers_map[wid]["active_job_ids"] = row_dict.get("active_job_ids") or workers_map[
                wid
            ].get("active_job_ids", [])
            workers_map[wid]["lease_expires_at"] = row_dict.get("lease_expires_at") or workers_map[
                wid
            ].get("lease_expires_at")
    except Exception:
        pass

    workers = sorted(workers_map.values(), key=lambda w: w["worker_id"])

    # Aggregate stats
    healthy_count = sum(1 for w in workers if w["health"] == "green")
    warning_count = sum(1 for w in workers if w["health"] == "yellow")
    stale_count = sum(1 for w in workers if w["health"] == "red")
    active_jobs = sum(int(w.get("active_jobs") or 0) for w in workers)
    queue_depth = (
        await pool.fetchval("SELECT count(*) FROM ingestion_jobs WHERE status = 'queued'") or 0
    )

    return {
        "workers": workers,
        "active_page": "workers",
        "total_workers": len(workers),
        "healthy_count": healthy_count,
        "warning_count": warning_count,
        "stale_count": stale_count,
        "active_jobs": active_jobs,
        "queue_depth": int(queue_depth),
    }


@router.get("/dashboard/workers", response_class=HTMLResponse)
async def workers_page(request: Request) -> HTMLResponse:
    """Worker status page - combines Redis heartbeats with PG job data."""
    ctx = await _worker_status_context(request)
    return _render_page(
        request,
        page_template="pages/workers.html",
        partial_template="partials/worker_cards.html",
        ctx=ctx,
    )


# ---------------------------------------------------------------------------
# Discovery (unified categories + entities)
# ---------------------------------------------------------------------------


async def _discovery_tab_context(
    pool: Any,
    tab: str,
    q: str,
    source: str = "",
    doc_type: str = "",
    category: str = "",
    entity: str = "",
) -> dict[str, Any]:
    """Build the context dict for whichever tab is active.

    Pulled out so /dashboard/discovery and the inner-HTMX tab switch
    share exactly the same shape and stay in sync.
    """
    ctx: dict[str, Any] = {
        "active_tab": tab,
        "q": q,
        "assets": [],
        "entities": [],
        "categories": [],
        "filter_source": source,
        "filter_doc_type": doc_type,
        "filter_category": category,
        "filter_entity": entity,
    }

    if tab == "entities":
        if q:
            rows = await pool.fetch(
                """
                SELECT entity_text AS text, entity_type,
                       count(DISTINCT document_id) AS doc_count
                FROM entity_document_xref
                WHERE entity_text ILIKE $1
                GROUP BY entity_text, entity_type
                ORDER BY doc_count DESC
                LIMIT 200
                """,
                f"%{q}%",
            )
        else:
            rows = await pool.fetch("""
                SELECT entity_text AS text, entity_type,
                       count(DISTINCT document_id) AS doc_count
                FROM entity_document_xref
                GROUP BY entity_text, entity_type
                ORDER BY doc_count DESC, entity_text ASC
                LIMIT 200
                """)
        ctx["entities"] = [dict(r) for r in rows]
    elif tab == "assets":
        conditions: list[str] = []
        params: list[Any] = []
        idx = 1
        if q:
            conditions.append(f"(title ILIKE ${idx} OR asset_path ILIKE ${idx})")
            params.append(f"%{q}%")
            idx += 1
        if source:
            conditions.append(f"source_id = ${idx}")
            params.append(source)
            idx += 1
        if doc_type:
            conditions.append(f"asset_type = ${idx}")
            params.append(doc_type)
            idx += 1
        if category:
            conditions.append(f"category_path <@ ${idx}::ltree")
            params.append(category)
            idx += 1
        if entity:
            conditions.append(
                "id IN (SELECT document_id FROM entity_document_xref "
                f"WHERE entity_text ILIKE ${idx})"
            )
            params.append(f"%{entity}%")
            idx += 1
        where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
        rows = await pool.fetch(
            f"""
            SELECT id, source_id, asset_type, asset_path, title,
                   summary::text AS summary,
                   coalesce(category_path::text, '') AS category_path,
                   updated_at
            FROM discovery_assets
            {where}
            ORDER BY updated_at DESC NULLS LAST
            LIMIT 200
            """,
            *params,
        )
        ctx["assets"] = [dict(r) for r in rows]
    else:
        rows = await pool.fetch("""
            SELECT id, name, path::text AS path,
                   document_count AS doc_count,
                   exists(
                     SELECT 1 FROM category_taxonomy ch
                     WHERE ch.path <@ ct.path
                       AND nlevel(ch.path) = nlevel(ct.path) + 1
                   ) AS has_children
            FROM category_taxonomy ct
            ORDER BY path::text
            """)
        ctx["categories"] = [dict(r) for r in rows]

    return ctx


async def _discovery_stats(pool: Any) -> dict[str, Any]:
    """Quick counts for the page header so the operator sees scale at a glance."""
    row = await pool.fetchrow("""
        SELECT
            (SELECT count(*) FROM discovery_assets) AS assets,
            (SELECT count(DISTINCT (entity_text, entity_type))
             FROM entity_document_xref) AS entities,
            (SELECT count(*) FROM category_taxonomy) AS categories,
            (SELECT count(DISTINCT source_id) FROM discovery_assets) AS sources
        """)
    return (
        dict(row)
        if row
        else {
            "assets": 0,
            "entities": 0,
            "categories": 0,
            "sources": 0,
        }
    )


async def _last_run_summary(request: Request) -> Any | None:
    """The catalog's state across sources, or None before any scan finished."""
    from interlock.catalog import read as catalog_read

    try:
        summary = await catalog_read.overview(request.app.state.pg_pool)
    except Exception:
        logger.warning("Could not read the catalog overview", exc_info=True)
        return None
    if not (summary.sources_scanned or summary.pending or summary.running):
        return None
    return summary


@router.get("/dashboard/discovery", response_class=HTMLResponse)
async def discovery_page(
    request: Request,
    tab: str = "assets",
    q: str = "",
    source: str = "",
    doc_type: str = "",
    category: str = "",
    entity: str = "",
) -> HTMLResponse:
    """Discovery landing page: search + Assets / Entities / Categories tabs."""
    pool = request.app.state.pg_pool
    tab_ctx = await _discovery_tab_context(
        pool,
        tab,
        q,
        source=source,
        doc_type=doc_type,
        category=category,
        entity=entity,
    )
    stats = await _discovery_stats(pool)
    source_rows = await pool.fetch(
        "SELECT DISTINCT source_id FROM discovery_assets WHERE source_id IS NOT NULL ORDER BY source_id"
    )
    type_rows = await pool.fetch(
        "SELECT DISTINCT asset_type FROM discovery_assets WHERE asset_type IS NOT NULL ORDER BY asset_type"
    )
    category_rows = await pool.fetch(
        "SELECT path::text AS path FROM category_taxonomy ORDER BY path::text LIMIT 500"
    )

    ctx: dict[str, Any] = {
        "active_page": "discovery",
        "stats": stats,
        "last_run": await _last_run_summary(request),
        "sources": [r["source_id"] for r in source_rows],
        "doc_types": [r["asset_type"] for r in type_rows],
        "filter_categories": [r["path"] for r in category_rows],
        **tab_ctx,
    }

    if _is_inner_htmx(request):
        return _render(request, "partials/discovery_tab.html", ctx)

    if _is_sidebar_htmx(request):
        ctx["content_only"] = True
    return _render(request, "pages/discovery.html", ctx)


@router.get("/dashboard/discovery/search", response_class=HTMLResponse)
async def discovery_search(request: Request, q: str = "") -> HTMLResponse:
    """HTMX partial: unified search across the whole catalog.

    Uses DiscoverySearch when wired (vector + fulltext + metadata),
    falling back to PG-only when embedding/FAISS are unavailable.
    """
    q = (q or "").strip()
    if not q:
        return _render(
            request,
            "partials/discovery_search_results.html",
            {"q": "", "results": [], "engine_available": False},
        )

    engine_available = False
    results_payload: list[dict[str, Any]] = []
    discovery = getattr(request.app.state, "discovery_search", None)
    if discovery is not None:
        try:
            results = await discovery.search(query=q, limit=30)
            for r in results:
                payload = {
                    "asset_id": r.asset_id,
                    "source_id": r.source_id,
                    "asset_type": r.asset_type,
                    "asset_path": r.asset_path,
                    "title": r.title,
                    "summary": r.summary,
                    "score": round(float(r.score), 4),
                    "strategy": r.strategy,
                }
                results_payload.append(payload)
            engine_available = True
        except Exception:
            logger.exception("DiscoverySearch failed; falling back to PG-only")
            engine_available = False

    if not engine_available or not results_payload:
        # Plain SQL fallback so the search box still works even when
        # the embedding/FAISS path is down.
        rows = await request.app.state.pg_pool.fetch(
            """
            SELECT id AS asset_id, source_id, asset_type, asset_path, title,
                   summary::text AS summary
            FROM discovery_assets
            WHERE title ILIKE $1 OR asset_path ILIKE $1
            ORDER BY updated_at DESC NULLS LAST
            LIMIT 30
            """,
            f"%{q}%",
        )
        results_payload = [
            {
                "asset_id": r["asset_id"],
                "source_id": r["source_id"],
                "asset_type": r["asset_type"],
                "asset_path": r["asset_path"],
                "title": r["title"],
                "summary": r["summary"],
                "score": 0.0,
                "strategy": "fallback",
            }
            for r in rows
        ]

    return _render(
        request,
        "partials/discovery_search_results.html",
        {
            "q": q,
            "results": results_payload,
            "engine_available": engine_available,
        },
    )


@router.post("/dashboard/discovery/rescan", response_class=HTMLResponse)
async def discovery_rescan(request: Request) -> HTMLResponse:
    """Queue a catalog scan of every enabled source and report what was queued.

    The workers run the scans and re-index discovery as each one finishes, so
    this returns at once instead of holding the request open while every source
    is introspected from the admin process.
    """
    from interlock.catalog.queue import enqueue_many

    admin = getattr(request.state, "admin", None)
    result: dict[str, Any]
    try:
        queued, skipped = await enqueue_many(
            request.app.state.pg_pool,
            trigger="manual",
            requested_by=getattr(admin, "username", None),
        )
        result = {"queued": queued, "skipped": skipped}
    except Exception as exc:
        logger.exception("Queueing the discovery rescan failed")
        result = {"error": exc.__class__.__name__}
    await audit_admin_action(
        request,
        action="discovery.rescan",
        resource="source_catalog",
        resource_id="all",
        success="error" not in result,
        detail=mutation_audit_detail(status_code=200, extra={"result": result}),
        error=result.get("error"),
    )
    return _render(
        request,
        "partials/discovery_rescan_status.html",
        {"result": result, "last_run": await _last_run_summary(request)},
    )


@router.get(
    "/dashboard/discovery/assets/{asset_id:int}",
    response_class=HTMLResponse,
)
async def discovery_asset_detail(asset_id: int, request: Request) -> HTMLResponse:
    """Asset detail: summary, columns, category, entities, related assets."""
    pool = request.app.state.pg_pool
    row = await pool.fetchrow(
        """
        SELECT id, source_id, asset_type, asset_path, title,
               summary::text AS summary_json,
               coalesce(category_path::text, '') AS category_path,
               topics, quality_score, created_at, updated_at
        FROM discovery_assets WHERE id = $1
        """,
        asset_id,
    )
    if row is None:
        return _render_page(
            request,
            "pages/not_found.html",
            "pages/not_found.html",
            {"active_page": "discovery", "what": f"discovery asset #{asset_id}"},
        )
    asset = dict(row)
    raw_summary = asset.pop("summary_json", "") or "{}"
    summary_obj: Any = {}
    try:
        decoded = json.loads(raw_summary)
        # Some seed rows store summary as a JSON-encoded string instead
        # of an object. Decode once more if that's the case so the
        # template logic stays simple.
        if isinstance(decoded, str):
            try:
                decoded = json.loads(decoded)
            except (TypeError, ValueError):
                decoded = {}
        if isinstance(decoded, dict):
            summary_obj = decoded
    except (TypeError, ValueError):
        summary_obj = {}
    asset["summary"] = summary_obj

    columns = summary_obj.get("columns", []) if isinstance(summary_obj, dict) else []
    row_estimate = summary_obj.get("row_estimate") if isinstance(summary_obj, dict) else None

    entity_rows = await pool.fetch(
        """
        SELECT entity_text, entity_type, prominence
        FROM entity_document_xref
        WHERE document_id = $1
        ORDER BY prominence DESC, entity_text ASC
        """,
        asset_id,
    )
    entities = [dict(r) for r in entity_rows]

    related_rows = await pool.fetch(
        """
        SELECT x2.document_id AS asset_id,
               count(*) AS shared_entities,
               d.source_id, d.asset_type, d.asset_path, d.title
        FROM entity_document_xref x1
        JOIN entity_document_xref x2
          ON x1.entity_text = x2.entity_text
         AND x1.entity_type = x2.entity_type
         AND x2.document_id != $1
        JOIN discovery_assets d ON d.id = x2.document_id
        WHERE x1.document_id = $1
        GROUP BY x2.document_id, d.source_id, d.asset_type,
                 d.asset_path, d.title
        ORDER BY shared_entities DESC
        LIMIT 10
        """,
        asset_id,
    )
    related = [dict(r) for r in related_rows]

    ctx = {
        "active_page": "discovery",
        "asset": asset,
        "columns": columns,
        "row_estimate": row_estimate,
        "entities": entities,
        "related": related,
    }
    if _is_sidebar_htmx(request):
        ctx["content_only"] = True
    return _render(request, "pages/discovery_asset_detail.html", ctx)


@router.get(
    "/dashboard/discovery/entities/{entity_type}/{entity_text}",
    response_class=HTMLResponse,
)
async def discovery_entity_detail(
    entity_type: str, entity_text: str, request: Request
) -> HTMLResponse:
    """Entity detail: assets that reference it, co-occurring entities."""
    pool = request.app.state.pg_pool

    asset_rows = await pool.fetch(
        """
        SELECT x.document_id AS asset_id, x.prominence,
               d.source_id, d.asset_type, d.asset_path, d.title,
               coalesce(d.category_path::text, '') AS category_path
        FROM entity_document_xref x
        JOIN discovery_assets d ON d.id = x.document_id
        WHERE x.entity_text = $1 AND x.entity_type = $2
        ORDER BY x.prominence DESC, d.title ASC
        LIMIT 100
        """,
        entity_text,
        entity_type,
    )
    assets = [dict(r) for r in asset_rows]

    co_rows = await pool.fetch(
        """
        SELECT x2.entity_text, x2.entity_type,
               count(DISTINCT x2.document_id) AS co_occurrence_count
        FROM entity_document_xref x1
        JOIN entity_document_xref x2
          ON x1.document_id = x2.document_id
         AND (x2.entity_text != $1 OR x2.entity_type != x1.entity_type)
        WHERE x1.entity_text = $1 AND x1.entity_type = $2
        GROUP BY x2.entity_text, x2.entity_type
        ORDER BY co_occurrence_count DESC
        LIMIT 25
        """,
        entity_text,
        entity_type,
    )
    co_occurring = [dict(r) for r in co_rows]

    ctx = {
        "active_page": "discovery",
        "entity_text": entity_text,
        "entity_type": entity_type,
        "assets": assets,
        "co_occurring": co_occurring,
    }
    if _is_sidebar_htmx(request):
        ctx["content_only"] = True
    return _render(request, "pages/discovery_entity_detail.html", ctx)


@router.get(
    "/dashboard/discovery/categories/{path:path}",
    response_class=HTMLResponse,
)
async def discovery_category_detail(path: str, request: Request) -> HTMLResponse:
    """Category detail: breadcrumb, children, assets under this path."""
    pool = request.app.state.pg_pool

    # Validate the path looks like ltree input. Anything with quote
    # marks or unicode whitespace gets rejected so we never inject.
    if not path or any(ch in path for ch in ("'", '"', ";", " ")):
        return HTMLResponse("<h1>Invalid category path</h1>", status_code=400)

    cat = await pool.fetchrow(
        """
        SELECT id, name, path::text AS path, description,
               document_count, created_at
        FROM category_taxonomy WHERE path = $1::ltree
        """,
        path,
    )
    if cat is None:
        return HTMLResponse("<h1>Category not found</h1>", status_code=404)

    children_rows = await pool.fetch(
        """
        SELECT id, name, path::text AS path, document_count AS doc_count,
               exists(
                 SELECT 1 FROM category_taxonomy ch
                 WHERE ch.path <@ ct.path
                   AND nlevel(ch.path) = nlevel(ct.path) + 1
               ) AS has_children
        FROM category_taxonomy ct
        WHERE path ~ ($1 || '.*{1}')::lquery
        ORDER BY name
        """,
        path,
    )
    children = [dict(r) for r in children_rows]

    asset_rows = await pool.fetch(
        """
        SELECT id, source_id, asset_type, asset_path, title,
               summary::text AS summary,
               updated_at
        FROM discovery_assets
        WHERE category_path <@ $1::ltree
        ORDER BY updated_at DESC NULLS LAST
        LIMIT 100
        """,
        path,
    )
    assets = [dict(r) for r in asset_rows]

    # Breadcrumb: prefix segments of the path
    segments = path.split(".")
    breadcrumb = []
    for i in range(1, len(segments) + 1):
        breadcrumb.append(
            {
                "label": segments[i - 1],
                "path": ".".join(segments[:i]),
            }
        )

    ctx = {
        "active_page": "discovery",
        "category": dict(cat),
        "children": children,
        "assets": assets,
        "breadcrumb": breadcrumb,
    }
    if _is_sidebar_htmx(request):
        ctx["content_only"] = True
    return _render(request, "pages/discovery_category_detail.html", ctx)


# ---------------------------------------------------------------------------
# Categories (backward compat)
# ---------------------------------------------------------------------------


@router.get("/dashboard/categories", response_class=HTMLResponse)
async def categories_page(request: Request) -> HTMLResponse:
    """Category browser - taxonomy roots, including orphaned seeded paths."""
    pool = request.app.state.pg_pool
    rows = await pool.fetch("""
        SELECT id, name, path::text AS path, document_count AS doc_count,
               exists(SELECT 1 FROM category_taxonomy ch WHERE ch.path <@ ct.path AND nlevel(ch.path) = nlevel(ct.path) + 1) AS has_children
        FROM category_taxonomy ct
        WHERE nlevel(path) = 1
           OR NOT EXISTS (
                SELECT 1
                FROM category_taxonomy parent
                WHERE parent.path = subpath(ct.path, 0, nlevel(ct.path) - 1)
           )
        ORDER BY path::text
        """)
    categories = [dict(r) for r in rows]

    ctx = {"categories": categories, "active_page": "categories"}

    return _render_page(
        request,
        page_template="pages/categories.html",
        partial_template="partials/category_tree.html",
        ctx=ctx,
    )


@router.get("/dashboard/categories/{path:path}/children", response_class=HTMLResponse)
async def category_children(request: Request, path: str) -> HTMLResponse:
    """HTMX partial: children of a category node (ltree direct children)."""
    pool = request.app.state.pg_pool
    parent_depth = path.count(".") + 1
    child_depth = parent_depth + 1
    rows = await pool.fetch(
        """
        SELECT id, name, path::text AS path, document_count AS doc_count,
               exists(SELECT 1 FROM category_taxonomy ch2 WHERE ch2.path <@ ct.path AND nlevel(ch2.path) = nlevel(ct.path) + 1) AS has_children
        FROM category_taxonomy ct
        WHERE path <@ $1::ltree AND nlevel(path) = $2
        ORDER BY name
        """,
        path,
        child_depth,
    )
    categories = [dict(r) for r in rows]
    return _render(request, "partials/category_tree.html", {"categories": categories})


# ---------------------------------------------------------------------------
# Entities (backward compat)
# ---------------------------------------------------------------------------


@router.get("/dashboard/entities", response_class=HTMLResponse)
async def entities_page(request: Request, q: str = "") -> HTMLResponse:
    """Entity explorer page. Shows all entities by default, filtered on search."""
    pool = request.app.state.pg_pool
    if q:
        rows = await pool.fetch(
            """
            SELECT entity_text AS text, entity_type,
                   count(DISTINCT document_id) AS doc_count
            FROM entity_document_xref
            WHERE entity_text ILIKE $1
            GROUP BY entity_text, entity_type
            ORDER BY doc_count DESC
            LIMIT 100
            """,
            f"%{q}%",
        )
    else:
        rows = await pool.fetch("""
            SELECT entity_text AS text, entity_type,
                   count(DISTINCT document_id) AS doc_count
            FROM entity_document_xref
            GROUP BY entity_text, entity_type
            ORDER BY doc_count DESC, entity_text ASC
            LIMIT 100
            """)
    entities = [dict(r) for r in rows]

    ctx = {"entities": entities, "q": q, "active_page": "entities"}

    return _render_page(
        request,
        page_template="pages/entities.html",
        partial_template="partials/entity_results.html",
        ctx=ctx,
    )


@router.get("/dashboard/entities/search", response_class=HTMLResponse)
async def entity_search(request: Request, q: str = "") -> HTMLResponse:
    """HTMX partial: entity search results."""
    pool = request.app.state.pg_pool
    if q:
        rows = await pool.fetch(
            """
            SELECT entity_text AS text, entity_type,
                   count(DISTINCT document_id) AS doc_count
            FROM entity_document_xref
            WHERE entity_text ILIKE $1
            GROUP BY entity_text, entity_type
            ORDER BY doc_count DESC
            LIMIT 100
            """,
            f"%{q}%",
        )
    else:
        rows = await pool.fetch("""
            SELECT entity_text AS text, entity_type,
                   count(DISTINCT document_id) AS doc_count
            FROM entity_document_xref
            GROUP BY entity_text, entity_type
            ORDER BY doc_count DESC, entity_text ASC
            LIMIT 100
            """)
    entities = [dict(r) for r in rows]

    return _render(request, "partials/entity_results.html", {"entities": entities, "q": q})


# ---------------------------------------------------------------------------
# Audit & Costs
# ---------------------------------------------------------------------------


@router.get("/dashboard/audit-costs", response_class=HTMLResponse)
async def audit_costs_page(
    request: Request,
    source: str = "",
    operation: str = "",
    status: str = "",
    identity_id: str = "",
    cache_tier: str = "",
    pii: str = "",
    since: str = "",
    until: str = "",
    protocol: str = "",
    page: int = 1,
    usage_range: str = DEFAULT_USAGE_RANGE,
) -> HTMLResponse:
    """Audit log and usage breakdown page."""
    pool = request.app.state.pg_pool
    if usage_range not in USAGE_RANGES:
        usage_range = DEFAULT_USAGE_RANGE
    usage_ctx = await _usage_context(pool, usage_range)

    # Filter options
    source_rows = await pool.fetch(
        "SELECT DISTINCT source_id FROM audit_log WHERE source_id IS NOT NULL ORDER BY source_id"
    )
    sources = [r["source_id"] for r in source_rows]

    op_rows = await pool.fetch(
        "SELECT DISTINCT operation FROM audit_log WHERE operation IS NOT NULL ORDER BY operation"
    )
    operations = [r["operation"] for r in op_rows]

    status_rows = await pool.fetch(
        "SELECT DISTINCT status FROM audit_log WHERE status IS NOT NULL ORDER BY status"
    )
    statuses = [r["status"] for r in status_rows]

    # Audit log with filters and pagination
    audit_ctx = await _fetch_audit_log(
        pool,
        source=source,
        operation=operation,
        status=status,
        page=page,
        identity_id=identity_id,
        cache_tier=cache_tier,
        pii=pii,
        since=since,
        until=until,
        protocol=protocol,
    )

    # Cache tier dropdown values (driven by the data, plus 'miss' sentinel).
    tier_rows = await pool.fetch(
        "SELECT DISTINCT cache_tier FROM audit_log "
        "WHERE cache_tier IS NOT NULL ORDER BY cache_tier"
    )
    cache_tiers = [r["cache_tier"] for r in tier_rows] + ["miss"]

    protocol_rows = await pool.fetch(
        "SELECT DISTINCT protocol FROM audit_log WHERE protocol IS NOT NULL ORDER BY protocol"
    )
    protocols = [r["protocol"] for r in protocol_rows]

    ctx = {
        "active_page": "audit-costs",
        **usage_ctx,
        "sources": sources,
        "operations": operations,
        "statuses": statuses,
        "cache_tiers": cache_tiers,
        "protocols": protocols,
        "filter_protocol": protocol,
        "filter_source": source,
        "filter_operation": operation,
        "filter_status": status,
        "filter_identity_id": identity_id,
        "filter_cache_tier": cache_tier,
        "filter_pii": pii,
        "filter_since": since,
        "filter_until": until,
        "quick_since_hour": (datetime.now(UTC) - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M"),
        "quick_since_day": (datetime.now(UTC) - timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M"),
        **audit_ctx,
    }

    return _render_page(request, "pages/audit_costs.html", "partials/audit_log_table.html", ctx)


async def _usage_context(pool: Any, usage_range: str) -> dict[str, Any]:
    """Summary cards and outcome breakdowns for one time window."""
    aggregator = UsageAggregator(pool)
    since = usage_since(usage_range, datetime.now(UTC))

    def with_bars(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        scale = max((int(r["total"]) for r in rows), default=0)
        return [{**r, "segments": bar_segments(r, scale)} for r in rows]

    return {
        "usage": await aggregator.summary(since),
        "usage_range": usage_range,
        "usage_ranges": [(key, label) for key, (label, _) in USAGE_RANGES.items()],
        "usage_outcomes": USAGE_OUTCOMES,
        "usage_by_identity": with_bars(await aggregator.by_identity(since)),
        "usage_by_source": with_bars(await aggregator.by_source(since)),
        "usage_by_team": with_bars(await aggregator.by_team(since)),
    }


@router.get("/dashboard/audit-costs/usage", response_class=HTMLResponse)
async def audit_usage_partial(
    request: Request, usage_range: str = DEFAULT_USAGE_RANGE
) -> HTMLResponse:
    """The usage section alone, for the range selector."""
    if usage_range not in USAGE_RANGES:
        usage_range = DEFAULT_USAGE_RANGE
    return _render(
        request,
        "partials/usage_breakdown.html",
        await _usage_context(request.app.state.pg_pool, usage_range),
    )


@router.get("/dashboard/audit-costs/log", response_class=HTMLResponse)
async def audit_log_partial(
    request: Request,
    source: str = "",
    operation: str = "",
    status: str = "",
    identity_id: str = "",
    cache_tier: str = "",
    pii: str = "",
    since: str = "",
    until: str = "",
    protocol: str = "",
    page: int = 1,
) -> HTMLResponse:
    """HTMX partial for filtered audit log."""
    pool = request.app.state.pg_pool
    ctx = await _fetch_audit_log(
        pool,
        source=source,
        operation=operation,
        status=status,
        page=page,
        identity_id=identity_id,
        cache_tier=cache_tier,
        pii=pii,
        since=since,
        until=until,
        protocol=protocol,
    )
    ctx["filter_source"] = source
    ctx["filter_operation"] = operation
    ctx["filter_status"] = status
    ctx["filter_identity_id"] = identity_id
    ctx["filter_cache_tier"] = cache_tier
    ctx["filter_pii"] = pii
    ctx["filter_since"] = since
    ctx["filter_until"] = until
    ctx["filter_protocol"] = protocol
    return _render(request, "partials/audit_log_table.html", ctx)


@router.get("/dashboard/audit-costs/events/{audit_id:int}", response_class=HTMLResponse)
async def audit_event_detail(audit_id: int, request: Request) -> HTMLResponse:
    pool = request.app.state.pg_pool
    row = await pool.fetchrow(
        f"""
        SELECT a.*, {IDENTITY_NAME_COLUMNS}
        FROM audit_log a
        {identity_joins("a.identity_id")}
        WHERE a.id = $1
        """,
        audit_id,
    )
    if row is None:
        return _render_page(
            request,
            "pages/not_found.html",
            "pages/not_found.html",
            {"active_page": "audit-costs", "what": f"audit event #{audit_id}"},
        )
    event = dict(row)
    for key in (
        "pii_types",
        "policy_decision",
        "redaction_stats",
        "cost_metadata",
        "request_metadata",
        "metadata",
    ):
        value = event.get(key)
        if isinstance(value, str):
            try:
                event[key] = json.loads(value)
            except (TypeError, ValueError):
                pass
    # audit_log has no correlation column; the ID travels in the request
    # metadata, which is where the page has to read it from.
    for key in ("request_metadata", "metadata"):
        recorded = event.get(key)
        if not event.get("correlation_id") and isinstance(recorded, dict):
            event["correlation_id"] = recorded.get("correlation_id")
    if not _admin_has_role(request, "owner"):
        for key in ("request_metadata", "metadata"):
            event[key] = _redact_admin_metadata(event.get(key))
        event["sensitive_metadata_redacted"] = True
    return _render_page(
        request,
        "pages/audit_event_detail.html",
        "pages/audit_event_detail.html",
        {"active_page": "audit-costs", "event": event},
    )


@router.get("/dashboard/audit-costs/export.csv")
async def audit_log_csv_export(
    request: Request,
    source: str = "",
    operation: str = "",
    status: str = "",
    identity_id: str = "",
    cache_tier: str = "",
    pii: str = "",
    since: str = "",
    until: str = "",
    protocol: str = "",
    limit: int = 100_000,
) -> StreamingResponse:
    """Stream the filtered audit log as CSV.

    Honours the same filters as the dashboard table. Caps output at
    ``limit`` rows (default 100k) to protect the gateway and browser.
    The download is streamed: rows are yielded in chunks of 1000 so
    memory stays bounded regardless of result-set size.
    """
    from fastapi.responses import StreamingResponse

    pool = request.app.state.pg_pool

    where, params = _build_audit_filter(
        source=source,
        operation=operation,
        status=status,
        identity_id=identity_id,
        cache_tier=cache_tier,
        pii=pii,
        since=since,
        until=until,
        protocol=protocol,
    )
    next_idx = len(params) + 1
    # The name column is appended rather than placed beside identity_id so
    # existing consumers reading columns by position keep working.
    fetch_sql = (
        f"SELECT e.*, COALESCE(i.name, it.name) AS identity_name FROM ("
        f"SELECT id, created_at, identity_id, source_id, operation, "
        f"       sql_fingerprint, cache_hit, cache_tier, latency_ms, "
        f"       pii_detected, pii_types, risk_level, status, error_message, "
        f"       protocol, request_metadata->>'correlation_id' AS correlation_id "
        f"FROM audit_log{where} "
        f"ORDER BY created_at DESC LIMIT ${next_idx}) e "
        f"{identity_joins('e.identity_id')} "
        f"ORDER BY e.created_at DESC"
    )

    columns = [
        "id",
        "created_at",
        "identity_id",
        "source_id",
        "operation",
        "sql_fingerprint",
        "cache_hit",
        "cache_tier",
        "latency_ms",
        "pii_detected",
        "pii_types",
        "risk_level",
        "status",
        "error_message",
        "identity_name",
        "protocol",
        "correlation_id",
    ]

    async def _generate() -> Any:
        import csv
        import io

        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(columns)
        yield buf.getvalue()
        buf.seek(0)
        buf.truncate()

        rows = await pool.fetch(fetch_sql, *params, max(1, min(limit, 1_000_000)))
        for r in rows:
            values = []
            for col in columns:
                v = r[col] if col in r else None
                if isinstance(v, list):
                    v = ",".join(str(x) for x in v)
                values.append("" if v is None else str(v))
            writer.writerow(values)
            if buf.tell() > 64 * 1024:
                yield buf.getvalue()
                buf.seek(0)
                buf.truncate()
        if buf.tell():
            yield buf.getvalue()

    from datetime import datetime as _dt

    ts = _dt.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    return StreamingResponse(
        _generate(),
        media_type="text/csv",
        headers={
            "Content-Disposition": f'attachment; filename="interlock-audit-{ts}.csv"',
            "Cache-Control": "no-store",
        },
    )


def _build_audit_filter(
    *,
    source: str = "",
    operation: str = "",
    status: str = "",
    identity_id: str = "",
    cache_tier: str = "",
    pii: str = "",
    since: str = "",
    until: str = "",
    protocol: str = "",
) -> tuple[str, list[Any]]:
    """Build a parameterised WHERE clause for the audit_log table.

    Shared by the paginated dashboard view, the HTMX filter partial,
    and the CSV export. Returns (where_sql, params). Empty filter
    strings are ignored.
    """
    conditions: list[str] = []
    params: list[Any] = []
    idx = 1

    if source:
        conditions.append(f"source_id = ${idx}")
        params.append(source)
        idx += 1
    if operation:
        conditions.append(f"operation = ${idx}")
        params.append(operation)
        idx += 1
    if status:
        conditions.append(f"status = ${idx}")
        params.append(status)
        idx += 1
    if identity_id:
        try:
            _id = int(identity_id)
        except ValueError:
            _id = None
        if _id is not None:
            conditions.append(f"identity_id = ${idx}")
            params.append(_id)
            idx += 1
    if cache_tier:
        if cache_tier == "miss":
            conditions.append("cache_tier IS NULL")
        else:
            conditions.append(f"cache_tier = ${idx}")
            params.append(cache_tier)
            idx += 1
    if protocol:
        conditions.append(f"protocol = ${idx}")
        params.append(protocol)
        idx += 1
    if pii == "yes":
        conditions.append("pii_detected = TRUE")
    elif pii == "no":
        conditions.append("pii_detected = FALSE")
    if since:
        conditions.append(f"created_at >= ${idx}::timestamptz")
        params.append(since)
        idx += 1
    if until:
        conditions.append(f"created_at <= ${idx}::timestamptz")
        params.append(until)
        idx += 1

    where = (" WHERE " + " AND ".join(conditions)) if conditions else ""
    return where, params


async def _fetch_audit_log(
    pool: Any,
    source: str = "",
    operation: str = "",
    status: str = "",
    page: int = 1,
    **filters: Any,
) -> dict[str, Any]:
    """Build filtered audit log query with pagination."""
    where, params = _build_audit_filter(
        source=source,
        operation=operation,
        status=status,
        **{
            k: v
            for k, v in filters.items()
            if k in {"identity_id", "cache_tier", "pii", "since", "until", "protocol"}
        },
    )
    next_idx = len(params) + 1

    count_sql = f"SELECT count(*) FROM audit_log{where}"
    total = await pool.fetchval(count_sql, *params) or 0
    total_pages = max(1, math.ceil(total / PAGE_SIZE))
    page = max(1, min(page, total_pages))
    offset = (page - 1) * PAGE_SIZE

    aliased_where = where
    for column in (
        "source_id",
        "operation",
        "status",
        "identity_id",
        "cache_tier",
        "pii_detected",
        "created_at",
    ):
        aliased_where = aliased_where.replace(column, f"a.{column}")

    fetch_sql = (
        f"SELECT a.*, {IDENTITY_NAME_COLUMNS} "
        f"FROM audit_log a "
        f"{identity_joins('a.identity_id')}"
        f"{aliased_where} "
        f"ORDER BY a.created_at DESC LIMIT ${next_idx} OFFSET ${next_idx + 1}"
    )
    rows = await pool.fetch(fetch_sql, *params, PAGE_SIZE, offset)
    audit_rows = [dict(r) for r in rows]

    return {
        "audit_rows": audit_rows,
        "audit_page": page,
        "audit_total_pages": total_pages,
        "audit_total": total,
    }


# ---------------------------------------------------------------------------
# Write Safety
# ---------------------------------------------------------------------------


@router.get("/dashboard/write-safety", response_class=HTMLResponse)
async def write_safety_page(request: Request) -> HTMLResponse:
    """Write approval queue with pending cards and history."""
    pool = request.app.state.pg_pool

    counts = await pool.fetchrow("""
        SELECT
            count(*) FILTER (WHERE status = 'pending') AS pending,
            count(*) FILTER (WHERE status = 'approved'
                AND created_at >= NOW() - INTERVAL '24 hours') AS approved_24h,
            count(*) FILTER (WHERE status = 'rejected'
                AND created_at >= NOW() - INTERVAL '24 hours') AS rejected_24h,
            count(*) FILTER (WHERE status = 'expired'
                AND created_at >= NOW() - INTERVAL '24 hours') AS expired_24h
        FROM write_approval_queue
        """)

    pending = await pool.fetch(f"""
        SELECT w.*, {IDENTITY_NAME_COLUMNS}
        FROM write_approval_queue w
        {identity_joins("w.identity_id")}
        WHERE w.status = 'pending'
        ORDER BY w.created_at DESC
        """)

    history = await pool.fetch(f"""
        SELECT w.*, {IDENTITY_NAME_COLUMNS}
        FROM write_approval_queue w
        {identity_joins("w.identity_id")}
        WHERE w.status != 'pending'
        ORDER BY w.created_at DESC LIMIT 25
        """)

    ctx = {
        "active_page": "write-safety",
        "pending_count": counts["pending"] if counts else 0,
        "approved_24h": counts["approved_24h"] if counts else 0,
        "rejected_24h": counts["rejected_24h"] if counts else 0,
        "expired_24h": counts["expired_24h"] if counts else 0,
        "pending_approvals": [_prepare_approval_for_admin(request, r) for r in pending],
        "history": [_prepare_approval_for_admin(request, r) for r in history],
    }

    return _render_page(request, "pages/write_safety.html", "pages/write_safety.html", ctx)


@router.get("/dashboard/write-safety/{approval_id:int}", response_class=HTMLResponse)
async def write_safety_detail(approval_id: int, request: Request) -> HTMLResponse:
    pool = request.app.state.pg_pool
    row = await pool.fetchrow(
        f"""
        SELECT w.*, {IDENTITY_NAME_COLUMNS}, ds.name AS source_name
        FROM write_approval_queue w
        {identity_joins("w.identity_id")}
        LEFT JOIN data_sources ds ON w.source_id = ds.source_id
        WHERE w.id = $1
        """,
        approval_id,
    )
    if row is None:
        return _render_page(
            request,
            "pages/not_found.html",
            "pages/not_found.html",
            {"active_page": "write-safety", "what": f"approval #{approval_id}"},
        )
    approval = _prepare_approval_for_admin(request, row)
    audit_rows = await pool.fetch(
        """
        SELECT id, created_at, status, operation, approval_status
        FROM audit_log
        WHERE approval_id = $1
        ORDER BY created_at DESC
        LIMIT 10
        """,
        approval_id,
    )
    return _render_page(
        request,
        "pages/write_safety_detail.html",
        "pages/write_safety_detail.html",
        {
            "active_page": "write-safety",
            "approval": approval,
            "audit_rows": [dict(r) for r in audit_rows],
        },
    )


# ---------------------------------------------------------------------------
# Proxy Monitor
# ---------------------------------------------------------------------------


@router.get("/dashboard/proxy", response_class=HTMLResponse)
async def proxy_monitor_page(request: Request) -> HTMLResponse:
    """Proxy performance: latency, cache tiers, fingerprints, PII."""
    pool = request.app.state.pg_pool

    queries_today = (
        await pool.fetchval(
            "SELECT count(*) FROM audit_log " "WHERE created_at >= NOW() - INTERVAL '24 hours'"
        )
        or 0
    )

    avg_latency = (
        await pool.fetchval(
            "SELECT COALESCE(avg(latency_ms), 0) FROM audit_log "
            "WHERE created_at >= NOW() - INTERVAL '24 hours' AND latency_ms IS NOT NULL"
        )
        or 0
    )

    cache_rate = (
        await pool.fetchval(
            "SELECT COALESCE(avg(CASE WHEN cache_hit THEN 1.0 ELSE 0.0 END), 0) "
            "FROM audit_log WHERE created_at >= NOW() - INTERVAL '24 hours'"
        )
        or 0
    )

    pii_count = (
        await pool.fetchval(
            "SELECT count(*) FROM audit_log WHERE pii_detected = true "
            "AND created_at >= NOW() - INTERVAL '24 hours'"
        )
        or 0
    )

    percentiles = await pool.fetchrow(
        "SELECT percentile_cont(0.5) WITHIN GROUP (ORDER BY latency_ms) AS p50, "
        "percentile_cont(0.95) WITHIN GROUP (ORDER BY latency_ms) AS p95, "
        "percentile_cont(0.99) WITHIN GROUP (ORDER BY latency_ms) AS p99 "
        "FROM audit_log WHERE created_at >= NOW() - INTERVAL '24 hours' "
        "AND latency_ms IS NOT NULL"
    )

    tier_rows = await pool.fetch(
        "SELECT COALESCE(cache_tier, 'miss') AS tier, count(*) AS cnt "
        "FROM audit_log WHERE created_at >= NOW() - INTERVAL '24 hours' "
        "GROUP BY COALESCE(cache_tier, 'miss') ORDER BY cnt DESC"
    )
    total_tier = sum(r["cnt"] for r in tier_rows) or 1
    cache_tiers = [
        {"name": r["tier"], "count": r["cnt"], "pct": round(r["cnt"] / total_tier * 100)}
        for r in tier_rows
    ]

    fingerprints = await pool.fetch(
        "SELECT COALESCE(protocol, 'unknown') AS protocol, source_id, sql_fingerprint, count(*) AS cnt, "
        "round(avg(latency_ms)::numeric, 1) AS avg_lat, "
        "round(avg(CASE WHEN cache_hit THEN 1.0 ELSE 0.0 END)::numeric * 100, 0) AS hit_rate "
        "FROM audit_log WHERE sql_fingerprint IS NOT NULL "
        "AND created_at >= NOW() - INTERVAL '24 hours' "
        "GROUP BY protocol, source_id, sql_fingerprint ORDER BY cnt DESC LIMIT 10"
    )
    protocol_rows = await pool.fetch("""
        SELECT COALESCE(protocol, 'unknown') AS protocol,
               count(*) AS cnt,
               round(avg(latency_ms)::numeric, 1) AS avg_lat,
               count(*) FILTER (WHERE status = 'error') AS errors
        FROM audit_log
        WHERE created_at >= NOW() - INTERVAL '24 hours'
        GROUP BY COALESCE(protocol, 'unknown')
        ORDER BY cnt DESC
        """)

    pii_log = await pool.fetch(
        "SELECT created_at, source_id, operation, pii_types "
        "FROM audit_log WHERE pii_detected = true "
        "ORDER BY created_at DESC LIMIT 20"
    )

    ctx = {
        "active_page": "proxy",
        "queries_today": queries_today,
        "avg_latency": round(float(avg_latency), 1),
        "cache_hit_rate": round(float(cache_rate) * 100),
        "pii_count": pii_count,
        "p50": round(float(percentiles["p50"] or 0), 1) if percentiles else 0,
        "p95": round(float(percentiles["p95"] or 0), 1) if percentiles else 0,
        "p99": round(float(percentiles["p99"] or 0), 1) if percentiles else 0,
        "cache_tiers": cache_tiers,
        "fingerprints": [dict(r) for r in fingerprints],
        "protocols": [dict(r) for r in protocol_rows],
        "pii_log": [dict(r) for r in pii_log],
    }

    return _render_page(request, "pages/proxy_monitor.html", "pages/proxy_monitor.html", ctx)


@router.get("/dashboard/proxy-monitor", response_class=HTMLResponse)
async def proxy_monitor_page_alias(request: Request) -> RedirectResponse:
    """Backward-compatible shareable URL for Proxy Monitor."""
    return RedirectResponse(url="/dashboard/proxy", status_code=307)


# ---------------------------------------------------------------------------
# Policy Analytics
# ---------------------------------------------------------------------------


@router.get("/dashboard/policy-analytics", response_class=HTMLResponse)
async def policy_analytics_page(request: Request) -> HTMLResponse:
    """Policy decision analytics: allows, denies, per-source breakdown."""
    pool = request.app.state.pg_pool
    time_range = request.query_params.get("range", "24h")
    interval = {
        "1h": "1 hour",
        "24h": "24 hours",
        "7d": "7 days",
    }.get(time_range, "24 hours")
    source_filter = (request.query_params.get("source") or "").strip()
    where = f"created_at >= NOW() - INTERVAL '{interval}'"
    params: list[Any] = []
    if source_filter:
        params.append(source_filter)
        where += f" AND source_id = ${len(params)}"

    decision_rows = await pool.fetch(
        f"SELECT status, count(*) AS cnt FROM audit_log WHERE {where} GROUP BY status",
        *params,
    )
    dc = {r["status"]: r["cnt"] for r in decision_rows}
    total_decisions = sum(dc.values()) or 1

    source_rows = await pool.fetch(
        f"SELECT source_id, status, count(*) AS cnt FROM audit_log "
        f"WHERE {where} AND source_id IS NOT NULL "
        "GROUP BY source_id, status ORDER BY source_id",
        *params,
    )
    sources: dict[str, dict[str, int]] = {}
    for r in source_rows:
        sid = r["source_id"]
        if sid not in sources:
            sources[sid] = {
                "success": 0,
                "denied": 0,
                "queued": 0,
                "error": 0,
                "total": 0,
            }
        status = r["status"]
        if status not in sources[sid]:
            sources[sid][status] = 0
        sources[sid][status] += r["cnt"]
        sources[sid]["total"] += r["cnt"]

    denied_identities = await pool.fetch(
        f"SELECT d.identity_id, d.cnt, {IDENTITY_NAME_COLUMNS} FROM ("
        f"SELECT identity_id, count(*) AS cnt FROM audit_log "
        f"WHERE status = 'denied' AND {where} "
        "GROUP BY identity_id ORDER BY cnt DESC LIMIT 10) d "
        f"{identity_joins('d.identity_id')} ORDER BY d.cnt DESC",
        *params,
    )

    op_rows = await pool.fetch(
        f"SELECT operation, status, count(*) AS cnt FROM audit_log "
        f"WHERE {where} "
        "GROUP BY operation, status ORDER BY operation",
        *params,
    )
    ops: dict[str, dict[str, int]] = {}
    for r in op_rows:
        op = r["operation"]
        if op not in ops:
            ops[op] = {"success": 0, "denied": 0, "queued": 0, "error": 0}
        status = r["status"]
        if status in ops[op]:
            ops[op][status] += r["cnt"]
    try:
        rule_rows = await pool.fetch(
            f"""
            SELECT COALESCE(
                       policy_decision->>'rule_id',
                       request_metadata->'policy_decision'->>'rule_id',
                       request_metadata->>'matched_policy_rule_id',
                       'unmatched'
                   ) AS rule_id,
                   status,
                   count(*) AS cnt
            FROM audit_log
            WHERE {where}
            GROUP BY rule_id, status
            ORDER BY rule_id
            """,
            *params,
        )
    except Exception:
        logger.debug("policy analytics rule breakdown query failed", exc_info=True)
        rule_rows = []
    rules: dict[str, dict[str, int]] = {}
    for r in rule_rows:
        rule_id = r["rule_id"] or "unmatched"
        rules.setdefault(rule_id, {"success": 0, "denied": 0, "queued": 0, "error": 0})
        if r["status"] in rules[rule_id]:
            rules[rule_id][r["status"]] += r["cnt"]
    denied_examples = await pool.fetch(
        f"""
        SELECT d.*, {IDENTITY_NAME_COLUMNS}
        FROM (
            SELECT id, created_at, source_id, identity_id, operation, error_message
            FROM audit_log
            WHERE status = 'denied' AND {where}
            ORDER BY created_at DESC
            LIMIT 10
        ) d
        {identity_joins("d.identity_id")}
        ORDER BY d.created_at DESC
        """,
        *params,
    )
    sources_for_filter = await pool.fetch(
        "SELECT source_id, name FROM data_sources ORDER BY name LIMIT 200"
    )

    # Decisions over time. The bucket width tracks the selected range so the
    # series is always ~24-48 points regardless of window.
    bucket = {"1h": "minute", "24h": "hour", "7d": "day"}.get(time_range, "hour")
    try:
        trend_rows = await pool.fetch(
            f"SELECT date_trunc('{bucket}', created_at) AS bucket, status, count(*) AS cnt "
            f"FROM audit_log WHERE {where} GROUP BY bucket, status ORDER BY bucket",
            *params,
        )
    except Exception:
        logger.debug("policy analytics trend query failed", exc_info=True)
        trend_rows = []

    totals_by_bucket: dict[Any, int] = {}
    denies_by_bucket: dict[Any, int] = {}
    for row in trend_rows:
        key = row["bucket"]
        totals_by_bucket[key] = totals_by_bucket.get(key, 0) + row["cnt"]
        if row["status"] == "denied":
            denies_by_bucket[key] = denies_by_bucket.get(key, 0) + row["cnt"]
    ordered_buckets = sorted(totals_by_bucket)

    ctx = {
        "active_page": "policy-analytics",
        "trend_bucket": bucket,
        "trend_total": build_sparkline([totals_by_bucket[b] for b in ordered_buckets]),
        "trend_denied": build_sparkline([denies_by_bucket.get(b, 0) for b in ordered_buckets]),
        "range": time_range,
        "source_filter": source_filter,
        "sources_for_filter": [dict(r) for r in sources_for_filter],
        "total_decisions": total_decisions,
        "allow_count": dc.get("success", 0),
        "deny_count": dc.get("denied", 0),
        "queued_count": dc.get("queued", 0),
        "error_count": dc.get("error", 0),
        "allow_rate": round(dc.get("success", 0) / total_decisions * 100),
        "deny_rate": round(dc.get("denied", 0) / total_decisions * 100),
        "source_decisions": sources,
        "denied_identities": [dict(r) for r in denied_identities],
        "operations": ops,
        "rule_decisions": rules,
        "denied_examples": [dict(r) for r in denied_examples],
    }

    return _render_page(request, "pages/policy_analytics.html", "pages/policy_analytics.html", ctx)


# ---------------------------------------------------------------------------
# Source Onboarding (P3-T03 subset)
# ---------------------------------------------------------------------------


@router.get("/dashboard/data-sources/new", response_class=HTMLResponse)
async def new_data_source_form(request: Request) -> HTMLResponse:
    """Return the new-source form as a fragment or full Admin page."""
    ctx = {
        "active_page": "data-sources",
        "form": {
            "source_id": "",
            "name": "",
            "source_type": "postgresql",
            "connector_key": "postgresql",
            "host": "",
            "port": 5432,
            "database": "",
            "user": "",
            "password": "",
            "password_ref": "",
            "sslmode": "verify-full",
            "ssl_ca": "",
            "base_url": "",
            "auth_header": "",
            "token": "",
            "token_ref": "",
            "subdomain": "",
            "email": "",
            "api_token_ref": "",
            "workspace": "",
            "bot_token_ref": "",
            "channel_types": "public_channel,private_channel",
            "include_messages": "on",
            "include_threads": "on",
            "include_files": "on",
            "max_channels": "25",
            "max_messages_per_channel": "25",
            "max_replies_per_thread": "25",
            "max_files": "25",
            "org": "",
            "owner": "",
            "repo_names": "",
            "group": "",
            "project": "",
            "ref": "",
            "include_code_paths": "",
            "max_repos": "50",
            "max_projects": "50",
            "max_issues_per_repo": "10",
            "max_prs_per_repo": "10",
            "max_releases_per_repo": "5",
            "max_workflows_per_repo": "10",
            "max_issues_per_project": "10",
            "max_mrs_per_project": "10",
            "max_pipelines_per_project": "5",
            "brand_id": "",
            "group_id": "",
            "organization_id": "",
            "status": "",
            "include_users": "on",
            "include_organizations": "on",
            "include_ticket_comments": "on",
            "max_tickets": "25",
            "max_articles": "25",
            "max_users": "25",
            "max_organizations": "25",
            "account": "",
            "warehouse": "",
            "schema": "",
            "role": "",
            "private_key_ref": "",
            "authenticator": "",
            "application": "InterLock",
            "collect_query_history": "on",
            "cache_strategy": "deterministic_first",
            "create_default_roles": "on",
        },
        "connector_groups": await active_connector_groups(request.app.state.pg_pool),
        "connectors": CONNECTOR_DEFINITIONS,
        "error": None,
    }
    return _render_page(
        request, "pages/data_source_form.html", "partials/data_source_form.html", ctx
    )


@router.post("/dashboard/data-sources/test", response_class=HTMLResponse)
async def test_new_data_source(
    request: Request,
    source_type: str = Form(...),
    connector_key: str = Form(""),
    host: str = Form(""),
    port: int = Form(5432),
    database: str = Form(""),
    user: str = Form(""),
    password: str = Form(""),
    password_ref: str = Form(""),
    base_url: str = Form(""),
    auth_header: str = Form(""),
    token: str = Form(""),
    token_ref: str = Form(""),
) -> HTMLResponse:
    """Probe the upstream and return the result strip partial.

    Bound to the form's Test button. Does not persist.
    """
    form = await request.form()
    connector = get_connector(
        source_type, {"connector_key": connector_key} if connector_key else None
    )
    inactive = await _inactive_connector_error(
        request.app.state.pg_pool, connector_key or connector.key
    )
    if inactive:
        return _render(
            request,
            "partials/connection_test_result.html",
            {"ok": False, "latency_ms": 0.0, "error": inactive},
        )
    if source_type in {"postgresql", "mysql"} or connector.family == "database":
        cfg = {"host": host, "port": port}
        if database:
            cfg["database"] = database
        if user:
            cfg["user"] = user
        if password:
            cfg["password"] = password
        if password_ref:
            cfg["password_ref"] = password_ref
        if connector.source_type == "postgresql":
            cfg.update(_postgres_tls_config(form))
    elif source_type == "http" or connector.family == "http":
        cfg = {"base_url": base_url}
        if auth_header:
            cfg["auth_header"] = auth_header
        if token:
            cfg["token"] = token
        if token_ref:
            cfg["token_ref"] = token_ref
    else:
        cfg = _connector_config_from_form(connector.key, form)
    cfg.update(_private_egress_config(form))
    cfg.update(_http_probe_config(form, connector.key))

    status = await ConnectionManager.probe_unsaved(
        source_type,
        cfg,
        connector_key=connector.key,
        allow_insecure_tls=allows_insecure_upstream_tls(request.app.state.config),
    )
    return _render(
        request,
        "partials/connection_test_result.html",
        {
            "ok": status.healthy,
            "latency_ms": round(status.latency_ms, 1),
            "error": status.error,
        },
    )


@router.post("/dashboard/data-sources/create", response_class=HTMLResponse)
async def create_data_source_form(
    request: Request,
    name: str = Form(...),
    source_id: str = Form(""),
    source_type: str = Form(...),
    connector_key: str = Form(""),
    cache_strategy: str = Form("deterministic_first"),
    host: str = Form(""),
    port: int = Form(5432),
    database: str = Form(""),
    user: str = Form(""),
    password: str = Form(""),
    password_ref: str = Form(""),
    base_url: str = Form(""),
    auth_header: str = Form(""),
    token: str = Form(""),
    token_ref: str = Form(""),
    create_default_roles: str = Form(""),
) -> HTMLResponse:
    """Persist a new data source from a browser form submission.

    Replies with the updated data sources table partial on success or
    the form partial with an error banner on failure.
    """
    pool = request.app.state.pg_pool
    form = await request.form()
    connector = get_connector(
        source_type, {"connector_key": connector_key} if connector_key else None
    )
    metadata = {
        **_blank_source_metadata(),
        **source_metadata_for_connector(connector.key),
    }

    if source_type in {"postgresql", "mysql"} or connector.family == "database":
        cfg = {"host": host, "port": port}
        if database:
            cfg["database"] = database
        if user:
            cfg["user"] = user
        if password:
            cfg["password"] = password
        if password_ref:
            cfg["password_ref"] = password_ref
        if connector.source_type == "postgresql":
            cfg.update(_postgres_tls_config(form))
    elif source_type == "http" or connector.family == "http":
        cfg = {"base_url": base_url}
        if auth_header:
            cfg["auth_header"] = auth_header
        if token:
            cfg["token"] = token
        if token_ref:
            cfg["token_ref"] = token_ref
    else:
        cfg = _connector_config_from_form(connector.key, form)
    cfg.update(_private_egress_config(form))
    cfg.update(_http_probe_config(form, connector.key))

    # An inactive connector, a TLS posture production would refuse, then the id:
    # generated from the display name unless a caller supplied one.
    refusal = await _inactive_connector_error(
        pool, connector_key or connector.key
    ) or _console_tls_refusal(request, connector.source_type, cfg)
    existing = None
    if not refusal:
        source_id = source_id.strip()
        if source_id:
            refusal = _source_id_refusal(source_id)
            existing = (
                None
                if refusal
                else await pool.fetchval(
                    "SELECT 1 FROM data_sources WHERE source_id = $1", source_id
                )
            )
        else:
            source_id = await generate_source_id(pool, name)
    if refusal or existing:
        return _render(
            request,
            "partials/data_source_form.html",
            {
                "form": {
                    "source_id": source_id,
                    "name": name,
                    "source_type": source_type,
                    "connector_key": connector.key,
                    "host": host,
                    "port": port,
                    "database": database,
                    "user": user,
                    "password": "",
                    "password_ref": password_ref,
                    "base_url": base_url,
                    "auth_header": auth_header,
                    "token": "",
                    "token_ref": token_ref,
                    "sslmode": str(form.get("sslmode") or ""),
                    "allow_private_egress": bool(_private_egress_config(form)),
                    "ssl_ca": str(form.get("ssl_ca") or ""),
                    "cache_strategy": cache_strategy,
                    "create_default_roles": create_default_roles,
                },
                "connector_groups": await active_connector_groups(request.app.state.pg_pool),
                "connectors": CONNECTOR_DEFINITIONS,
                "error": refusal or f'A data source with source_id "{source_id}" already exists.',
            },
        )

    await pool.execute(
        """
        INSERT INTO data_sources (source_id, name, source_type, connection_config,
                                  cache_strategy, enabled, metadata)
        VALUES ($1, $2, $3, $4::jsonb, $5, TRUE, $6::jsonb)
        """,
        source_id,
        name,
        source_type,
        cfg,
        cache_strategy,
        metadata,
    )
    if create_default_roles == "on":
        await _ensure_default_source_roles(
            pool,
            source_id=source_id,
            source_type=source_type,
            connector_key=connector.key,
        )
    async with pool.acquire() as conn:
        await conn.execute("NOTIFY onyx_config_changed")
    await after_source_saved(request, source_id)

    # Return the freshly built table so HTMX can swap it in.
    return await _render_data_sources_table(request)


async def _render_data_sources_table(request: Request) -> HTMLResponse:
    return _render(
        request,
        "partials/data_sources_table.html",
        {"data_sources": await _data_source_list(request.app.state.pg_pool)},
    )


# ---------------------------------------------------------------------------
# Identity onboarding
# ---------------------------------------------------------------------------


@router.get("/dashboard/access-control/identities/new", response_class=HTMLResponse)
async def new_identity_form(request: Request) -> HTMLResponse:
    ctx = await _identity_form_context(request)
    return _render_page(request, "pages/identity_form.html", "partials/identity_form.html", ctx)


@router.post("/dashboard/access-control/identities/create", response_class=HTMLResponse)
async def create_identity_form(
    request: Request,
    name: str = Form(...),
    agent_type: str = Form("custom"),
    team: str = Form(""),
    roles: str = Form(""),
    mapped_pg_role: str = Form(""),
    pg_username: str = Form(""),
    pg_password: str = Form(""),
    generate_key: str = Form(""),
    api_key: str = Form(""),
) -> HTMLResponse:
    pool = request.app.state.pg_pool
    form_data = await request.form()
    source_roles = await _hydrate_source_role_keys(
        pool,
        _parse_source_role_form(form_data),
    )

    legacy_roles = [r.strip() for r in roles.split(",") if r.strip()]
    role_list = sorted(set(legacy_roles))
    if generate_key == "on" or not api_key:
        raw_key = secrets.token_urlsafe(32)
    else:
        if not RequestSanitizer.validate_api_key_format(api_key) or not validate_custom_api_key(
            api_key, request.app.state.config.auth
        ):
            ctx = await _identity_form_context(
                request,
                form=_default_identity_form(
                    name=name,
                    agent_type=agent_type,
                    team=team,
                    roles=roles,
                    mapped_pg_role=mapped_pg_role,
                    pg_username=pg_username,
                    generate_key=generate_key,
                    api_key="",
                    source_roles=source_roles,
                ),
                error=(
                    "Custom API keys must be at least 32 printable ASCII characters, "
                    "must not contain quotes, angle brackets, backticks, or whitespace, "
                    "and must not be a repeated single character."
                ),
            )
            return _render(request, "partials/identity_form.html", ctx)
        raw_key = api_key
    key_hash, key_hash_version = hash_api_key_for_storage(raw_key, request.app.state.config.auth)

    # Duplicate-name check.
    existing = await pool.fetchval("SELECT 1 FROM identities WHERE name = $1", name)
    if existing:
        ctx = await _identity_form_context(
            request,
            form=_default_identity_form(
                name=name,
                agent_type=agent_type,
                team=team,
                roles=roles,
                mapped_pg_role=mapped_pg_role,
                pg_username=pg_username,
                generate_key=generate_key,
                api_key="",
                source_roles=source_roles,
            ),
            error=f'An identity with name "{name}" already exists.',
        )
        return _render(request, "partials/identity_form.html", ctx)

    pg_password_hash = hash_password(pg_password) if pg_password else None
    metadata = {
        "source_roles": source_roles,
        "source_roles_authority": "identity_source_role_grants",
        "source_roles_derived": True,
    }

    identity_id = await pool.fetchval(
        """
        INSERT INTO identities (name, agent_type, team, roles, mapped_pg_role,
                                api_key_hash, api_key_hash_version, pg_username,
                                pg_password_hash, enabled,
                                metadata)
        VALUES ($1, $2, $3, $4::text[], $5, $6, $7, $8, $9, TRUE, $10::jsonb)
        RETURNING id
        """,
        name,
        agent_type,
        team or None,
        role_list,
        mapped_pg_role or None,
        key_hash,
        key_hash_version,
        pg_username or None,
        pg_password_hash,
        metadata,
    )
    await _persist_identity_source_role_grants(
        pool,
        identity_id=int(identity_id),
        source_roles=source_roles,
        granted_by=getattr(getattr(request.state, "admin", None), "admin_id", None),
    )
    await pool.execute(
        "SELECT pg_notify('onyx_identity_changed', $1)",
        json.dumps({"identity_id": int(identity_id), "source_roles_changed": True}),
    )
    await audit_admin_action(
        request,
        action="identity.create",
        resource="identity",
        resource_id=str(identity_id),
        success=True,
        detail=mutation_audit_detail(
            after={
                "id": int(identity_id),
                "name": name,
                "agent_type": agent_type,
                "team": team or None,
                "roles": role_list,
                "mapped_pg_role": mapped_pg_role or None,
                "pg_username": pg_username or None,
                "source_role_grants": source_roles,
                "api_key_created": True,
            },
            changed_fields=[
                "name",
                "agent_type",
                "team",
                "roles",
                "mapped_pg_role",
                "pg_username",
                "api_key_hash",
                "pg_password_hash",
                "source_role_grants",
            ],
            status_code=200,
        ),
    )
    return _render(
        request,
        "partials/identity_created.html",
        {
            "name": name,
            "api_key": raw_key,
            "roles": role_list,
            "source_roles": source_roles,
        },
    )


# ---------------------------------------------------------------------------
# Policy visual builder
# ---------------------------------------------------------------------------


def _build_policy_jsonb(
    *,
    cond_source_id: str,
    cond_operation: str,
    cond_roles: str,
    cond_identity_roles: str,
    cond_tables: str,
    cond_columns: str = "",
    action_effect: str,
    action_rate_limit: str,
    action_redact_columns: str,
    raw_conditions: str,
    raw_actions: str,
) -> tuple[dict[str, Any], dict[str, Any], str | None]:
    """Translate flat form fields into the JSONB shapes policy_rules wants.

    Raw JSON textareas, when non-empty, *replace* the field-built dicts.
    Returns (conditions, actions, error_message).
    """
    if raw_conditions.strip():
        try:
            conditions = json.loads(raw_conditions)
            if not isinstance(conditions, dict):
                return {}, {}, "raw conditions must be a JSON object"
        except json.JSONDecodeError as exc:
            return {}, {}, f"raw conditions invalid JSON: {exc}"
    else:
        conditions = {}
        if cond_source_id.strip():
            conditions["source_id"] = cond_source_id.strip()
        if cond_operation:
            conditions["operation_types"] = [cond_operation]
        roles = [r.strip() for r in cond_roles.split(",") if r.strip()]
        if roles:
            conditions["roles"] = roles
        identity_roles = [r.strip() for r in cond_identity_roles.split(",") if r.strip()]
        if identity_roles:
            conditions["identity_roles"] = identity_roles
        tables = [t.strip() for t in cond_tables.split(",") if t.strip()]
        if tables:
            conditions["tables"] = tables
        columns = [c.strip() for c in cond_columns.split(",") if c.strip()]
        if columns:
            conditions["columns"] = columns

    if raw_actions.strip():
        try:
            actions = json.loads(raw_actions)
            if not isinstance(actions, dict):
                return {}, {}, "raw actions must be a JSON object"
        except json.JSONDecodeError as exc:
            return {}, {}, f"raw actions invalid JSON: {exc}"
    else:
        actions = {"effect": action_effect or "allow"}
        if action_redact_columns.strip():
            actions["redact_columns"] = [
                c.strip() for c in action_redact_columns.split(",") if c.strip()
            ]
        if action_rate_limit.strip():
            try:
                actions["rate_limit"] = int(action_rate_limit)
            except ValueError:
                return {}, {}, "rate_limit must be an integer"

    return conditions, actions, None


def _load_policy_payload(text: str) -> tuple[list[dict[str, Any]], str | None]:
    raw = (text or "").strip()
    if not raw:
        return [], "Policy import payload is empty."
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        try:
            import yaml  # type: ignore

            data = yaml.safe_load(raw)
        except Exception as exc:
            return [], f"Policy import payload is not valid JSON/YAML: {exc}"
    if isinstance(data, dict) and "policies" in data:
        data = data["policies"]
    if not isinstance(data, list):
        return [], "Policy import must be a list or a mapping with a policies list."
    policies: list[dict[str, Any]] = []
    for idx, item in enumerate(data, start=1):
        if not isinstance(item, dict):
            return [], f"Policy #{idx} must be an object."
        if not item.get("name"):
            return [], f"Policy #{idx} is missing name."
        if not isinstance(item.get("conditions", {}), dict):
            return [], f"Policy {item.get('name')} conditions must be an object."
        if not isinstance(item.get("actions", {}), dict):
            return [], f"Policy {item.get('name')} actions must be an object."
        policies.append(item)
    return policies, None


def _dump_policies_yaml(policies: list[dict[str, Any]]) -> str:
    try:
        import yaml  # type: ignore

        return yaml.safe_dump({"policies": policies}, sort_keys=False)
    except Exception:
        return json.dumps({"policies": policies}, indent=2)


async def _policy_import_preview(
    pool: Any,
    policies: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    preview: list[dict[str, Any]] = []
    for policy in policies:
        existing = await pool.fetchrow(
            "SELECT name, priority, conditions, actions, enabled FROM policy_rules WHERE name = $1",
            policy["name"],
        )
        normalized = {
            "name": policy["name"],
            "priority": int(policy.get("priority", 0) or 0),
            "conditions": policy.get("conditions") or {},
            "actions": policy.get("actions") or {},
            "enabled": bool(policy.get("enabled", True)),
        }
        if not existing:
            action = "create"
        else:
            existing_dict = dict(existing)
            for key in ("conditions", "actions"):
                if isinstance(existing_dict.get(key), str):
                    try:
                        existing_dict[key] = json.loads(existing_dict[key] or "{}")
                    except (TypeError, ValueError):
                        existing_dict[key] = {}
            action = "unchanged"
            for key, value in normalized.items():
                if existing_dict.get(key) != value:
                    action = "update"
                    break
        preview.append({**normalized, "action": action})
    return preview


class _NoopAsyncContext:
    async def __aenter__(self) -> "_NoopAsyncContext":
        return self

    async def __aexit__(self, *_exc: Any) -> bool:
        return False


async def _apply_policy_import(conn: Any, policies: list[dict[str, Any]]) -> None:
    for policy in policies:
        values = (
            policy["name"],
            int(policy.get("priority", 0) or 0),
            policy.get("conditions") or {},
            policy.get("actions") or {},
            bool(policy.get("enabled", True)),
        )
        await conn.execute(
            """
            INSERT INTO policy_rules (name, priority, conditions, actions, enabled)
            VALUES ($1, $2, $3::jsonb, $4::jsonb, $5)
            ON CONFLICT (name) DO UPDATE
            SET priority = EXCLUDED.priority,
                conditions = EXCLUDED.conditions,
                actions = EXCLUDED.actions,
                enabled = EXCLUDED.enabled
            """,
            *values,
        )


def _policy_matches(
    conditions: dict[str, Any], *, source_id: str, operation: str, roles: list[str]
) -> bool:
    if conditions.get("source_id") and conditions["source_id"] != source_id:
        return False
    operations = conditions.get("operation_types") or conditions.get("operations")
    if operations and operation not in operations:
        return False
    condition_roles = conditions.get("roles") or []
    if condition_roles and not set(condition_roles).intersection(roles):
        return False
    return True


async def _admin_identity_context(
    pool: Any,
    identity_id: int,
) -> IdentityContext | None:
    row = await pool.fetchrow(
        """
        SELECT id, name, agent_type, team, roles, mapped_pg_role
        FROM identities
        WHERE id = $1 AND enabled = TRUE
        """,
        identity_id,
    )
    if row is None:
        return None
    roles = row["roles"] or []
    if isinstance(roles, str):
        try:
            roles = json.loads(roles)
        except (TypeError, ValueError):
            roles = [roles] if roles else []
    grants = await _identity_grants_by_identities(pool, [identity_id])
    try:
        agent_type = AgentType(str(row["agent_type"]))
    except ValueError:
        agent_type = AgentType.CUSTOM
    return IdentityContext(
        identity_id=int(row["id"]),
        user=str(row["name"]),
        agent_type=agent_type,
        team=row["team"],
        roles=list(roles),
        source_roles=grants.get(identity_id, []),
        mapped_pg_role=row["mapped_pg_role"],
        grants_version="admin-dry-run",
    )


@router.get("/dashboard/policies/export.yaml")
async def export_policies_yaml(request: Request) -> StreamingResponse:
    pool = request.app.state.pg_pool
    rows = await pool.fetch(
        "SELECT name, priority, conditions, actions, enabled "
        "FROM policy_rules ORDER BY priority DESC, name"
    )
    policies = []
    for row in rows:
        item = dict(row)
        for key in ("conditions", "actions"):
            if isinstance(item.get(key), str):
                try:
                    item[key] = json.loads(item[key] or "{}")
                except (TypeError, ValueError):
                    item[key] = {}
        policies.append(item)
    body = _dump_policies_yaml(policies)
    return StreamingResponse(
        iter([body]),
        media_type="application/x-yaml",
        headers={"Content-Disposition": 'attachment; filename="interlock-policies.yaml"'},
    )


@router.post("/dashboard/policies/import", response_class=HTMLResponse)
async def import_policies_compat_preview(
    request: Request,
    policy_payload: str = Form(""),
) -> HTMLResponse:
    return await import_policies_preview(request, policy_payload)


@router.post("/dashboard/policies/import/preview", response_class=HTMLResponse)
async def import_policies_preview(
    request: Request,
    policy_payload: str = Form(""),
) -> HTMLResponse:
    policies, error = _load_policy_payload(policy_payload)
    if error:
        return _render(
            request,
            "partials/policy_import_result.html",
            {
                "error": error,
                "preview": [],
                "policy_payload": policy_payload,
                "mode": "preview",
            },
        )
    pool = request.app.state.pg_pool
    preview = await _policy_import_preview(pool, policies)
    return _render(
        request,
        "partials/policy_import_result.html",
        {
            "error": None,
            "preview": preview,
            "policy_payload": policy_payload,
            "mode": "preview",
        },
    )


@router.post("/dashboard/policies/import/apply", response_class=HTMLResponse)
async def import_policies_apply(
    request: Request,
    policy_payload: str = Form(""),
) -> HTMLResponse:
    policies, error = _load_policy_payload(policy_payload)
    if error:
        return _render(
            request,
            "partials/policy_import_result.html",
            {
                "error": error,
                "preview": [],
                "policy_payload": policy_payload,
                "mode": "apply",
            },
        )
    pool = request.app.state.pg_pool
    preview = await _policy_import_preview(pool, policies)
    async with pool.acquire() as conn:
        tx = conn.transaction() if hasattr(conn, "transaction") else _NoopAsyncContext()
        async with tx:
            await _apply_policy_import(conn, policies)
            await conn.execute("NOTIFY onyx_policy_changed")
    await audit_admin_action(
        request,
        action="policy.import_apply",
        resource="policy_rules",
        resource_id="bulk_import",
        success=True,
        detail=mutation_audit_detail(
            changed_fields=["policy_rules"],
            status_code=200,
            extra={
                "created": sum(1 for item in preview if item["action"] == "create"),
                "updated": sum(1 for item in preview if item["action"] == "update"),
                "unchanged": sum(1 for item in preview if item["action"] == "unchanged"),
                "policy_names": [item["name"] for item in preview],
            },
        ),
    )
    return _render(
        request,
        "partials/policy_import_result.html",
        {
            "error": None,
            "preview": preview,
            "policy_payload": policy_payload,
            "mode": "applied",
        },
    )


@router.post("/dashboard/policies/dry-run", response_class=HTMLResponse)
async def policy_dry_run(
    request: Request,
    identity_id: str = Form(""),
    source_id: str = Form(""),
    operation: str = Form("read"),
    tables: str = Form(""),
    columns: str = Form(""),
    method: str = Form(""),
    path: str = Form(""),
    classification_tags: str = Form(""),
    sql: str = Form(""),
) -> HTMLResponse:
    pool = request.app.state.pg_pool
    identity = None
    if identity_id.strip():
        identity = await _admin_identity_context(pool, int(identity_id))
    if identity is None:
        return _render(
            request,
            "partials/policy_dry_run_result.html",
            {
                "decision": {
                    "allow": False,
                    "effect": "deny",
                    "reason": "Select an enabled identity so dry-run uses real grants.",
                    "redactions": [],
                    "rate_limit": None,
                    "write_risk_cap": None,
                    "classification_tags": [],
                },
                "matched": [],
                "source_role_decision": None,
                "permission_request": None,
            },
        )

    table_list = [t.strip() for t in tables.split(",") if t.strip()]
    column_list = [c.strip() for c in columns.split(",") if c.strip()]
    sql = sql.strip()
    source_row = await pool.fetchrow(
        "SELECT source_type, metadata FROM data_sources WHERE source_id = $1",
        source_id,
    )
    source_type = str(source_row["source_type"]) if source_row else "postgresql"
    source_metadata = source_row["metadata"] if source_row else {}
    if isinstance(source_metadata, str):
        source_metadata = json.loads(source_metadata or "{}")
    dry_run_metadata = {
        "classification_tags": [
            tag.strip() for tag in classification_tags.split(",") if tag.strip()
        ],
        "dry_run": True,
    }
    connector = get_connector(source_type, source_metadata)
    deny_spellings: set[str] | None = None
    deny_column_spellings: set[str] | None = None
    identifier_case_sensitive: bool | None = None
    if sql and connector.key in _SQL_DRY_RUN_CONNECTORS:
        # The gateway's own derivation - verb, every statement's tables, write
        # classification, catalog naming - so the dry-run explains the decision
        # the gateway would make.
        view = await _dry_run_pipeline(request).governance_view(
            sql_gateway_request(
                sql,
                protocol=source_type,
                source_id=source_id,
                dialect=dialect_for(connector.key),
                metadata={"query": sql, "connector_key": connector.key, **dry_run_metadata},
            ),
            identity_id=identity.identity_id,
        )
        permission_request = view.permission_request
        operation = view.operation
        table_list = list(view.tables or [])
        column_list = permission_request.columns
        deny_spellings = view.deny_table_spellings
        deny_column_spellings = view.deny_column_spellings
        identifier_case_sensitive = view.metadata.get("fabric_identifier_case_sensitive")
    elif sql:
        permission_request = get_adapter(
            connector.key,
            {"connector_key": connector.key},
        ).build_permission_request(
            source_id=source_id,
            identity_id=identity.identity_id,
            operation=sql,
            metadata={"query": sql, "connector_key": connector.key, **dry_run_metadata},
        )
        operation = (
            "read"
            if permission_request.action
            in {
                "db.table.select",
                "db.schema.list",
                "db.table.describe",
            }
            else "write"
        )
        table_list = permission_request.tables
        column_list = permission_request.columns
    else:
        view = await _dry_run_pipeline(request).governance_view(
            GatewayRequest(
                protocol="http" if method else source_type,
                source_id=source_id,
                operation=operation,
                method=method or None,
                path=path or None,
                tables=table_list or None,
                columns=column_list or None,
                metadata=dry_run_metadata,
            ),
            identity_id=identity.identity_id,
        )
        permission_request = view.permission_request
        deny_spellings = view.deny_table_spellings
        deny_column_spellings = view.deny_column_spellings
        identifier_case_sensitive = view.metadata.get("fabric_identifier_case_sensitive")
    source_role_decision = await SourceRoleEvaluator(pool).evaluate(permission_request)

    policy_engine = PolicyEngine(pool)
    await policy_engine.load()
    policy_decision = policy_engine.evaluate(
        identity=identity,
        source_id=source_id,
        operation=operation,
        tables=table_list,
        columns=column_list,
        classification_tags=dry_run_metadata["classification_tags"],
        deny_table_spellings=deny_spellings,
        deny_column_spellings=deny_column_spellings,
        identifier_case_sensitive=identifier_case_sensitive,
    )
    matched = []
    if policy_decision.rule_id:
        matched.append(
            {
                "id": policy_decision.rule_id,
                "name": policy_decision.rule_name,
                "priority": "",
            }
        )
    effective_allow = source_role_decision.allowed and policy_decision.allowed
    decision = {
        "allow": effective_allow,
        "effect": "allow" if effective_allow else "deny",
        "reason": (
            policy_decision.reason if source_role_decision.allowed else source_role_decision.reason
        ),
        "redactions": policy_decision.redact_columns,
        "rate_limit": policy_decision.rate_limit,
        "write_risk_cap": policy_decision.write_risk_cap,
        "classification_tags": [
            tag.strip() for tag in classification_tags.split(",") if tag.strip()
        ],
        "policy_allowed": policy_decision.allowed,
    }
    return _render(
        request,
        "partials/policy_dry_run_result.html",
        {
            "decision": decision,
            "matched": matched,
            "source_role_decision": source_role_decision.model_dump(),
            "permission_request": permission_request.model_dump(),
        },
    )


@router.get("/dashboard/policies/new", response_class=HTMLResponse)
async def new_policy_form(request: Request) -> HTMLResponse:
    return _render_page(
        request,
        "pages/policy_form.html",
        "partials/policy_form.html",
        {
            "active_page": "policies",
            "mode": "new",
            "form": _default_policy_form(),
            "error": None,
        },
    )


@router.get("/dashboard/policies/{policy_id}/edit", response_class=HTMLResponse)
async def edit_policy_form(policy_id: int, request: Request) -> HTMLResponse:
    pool = request.app.state.pg_pool
    row = await pool.fetchrow(
        "SELECT id, name, priority, conditions, actions FROM policy_rules WHERE id = $1",
        policy_id,
    )
    if row is None:
        return _render_page(
            request,
            "pages/policy_form.html",
            "partials/policy_form.html",
            {
                "active_page": "policies",
                "mode": "new",
                "form": _default_policy_form(),
                "error": f"Policy {policy_id} not found",
            },
        )
    conds = (
        row["conditions"]
        if isinstance(row["conditions"], dict)
        else json.loads(row["conditions"] or "{}")
    )
    acts = (
        row["actions"] if isinstance(row["actions"], dict) else json.loads(row["actions"] or "{}")
    )
    return _render_page(
        request,
        "pages/policy_form.html",
        "partials/policy_form.html",
        {
            "active_page": "policies",
            "mode": "edit",
            "form": {
                "policy_id": policy_id,
                "name": row["name"],
                "priority": row["priority"],
                "cond_source_id": conds.get("source_id", "") or "",
                "cond_operation": (conds.get("operation_types") or [""])[0],
                "cond_roles": ",".join(conds.get("roles", []) or []),
                "cond_identity_roles": ",".join(
                    conds.get("identity_roles", []) or conds.get("global_roles", []) or []
                ),
                "cond_tables": ",".join(conds.get("tables", []) or []),
                "cond_columns": ",".join(conds.get("columns", []) or []),
                "action_effect": acts.get("effect", "allow"),
                "action_rate_limit": str(acts.get("rate_limit", "") or ""),
                "action_redact_columns": ",".join(acts.get("redact_columns", []) or []),
                "raw_conditions": "",
                "raw_actions": "",
            },
            "error": None,
        },
    )


@router.post("/dashboard/policies/create", response_class=HTMLResponse)
async def create_policy_form(
    request: Request,
    name: str = Form(...),
    priority: int = Form(0),
    cond_source_id: str = Form(""),
    cond_operation: str = Form(""),
    cond_roles: str = Form(""),
    cond_identity_roles: str = Form(""),
    cond_tables: str = Form(""),
    cond_columns: str = Form(""),
    action_effect: str = Form("allow"),
    action_rate_limit: str = Form(""),
    action_redact_columns: str = Form(""),
    raw_conditions: str = Form(""),
    raw_actions: str = Form(""),
) -> HTMLResponse:
    pool = request.app.state.pg_pool

    conditions, actions, err = _build_policy_jsonb(
        cond_source_id=cond_source_id,
        cond_operation=cond_operation,
        cond_roles=cond_roles,
        cond_identity_roles=cond_identity_roles,
        cond_tables=cond_tables,
        cond_columns=cond_columns,
        action_effect=action_effect,
        action_rate_limit=action_rate_limit,
        action_redact_columns=action_redact_columns,
        raw_conditions=raw_conditions,
        raw_actions=raw_actions,
    )
    if err:
        return _render(
            request,
            "partials/policy_form.html",
            {
                "mode": "new",
                "form": {
                    "name": name,
                    "priority": priority,
                    "cond_source_id": cond_source_id,
                    "cond_operation": cond_operation,
                    "cond_roles": cond_roles,
                    "cond_identity_roles": cond_identity_roles,
                    "cond_tables": cond_tables,
                    "cond_columns": cond_columns,
                    "action_effect": action_effect,
                    "action_rate_limit": action_rate_limit,
                    "action_redact_columns": action_redact_columns,
                    "raw_conditions": raw_conditions,
                    "raw_actions": raw_actions,
                },
                "error": err,
            },
        )

    existing = await pool.fetchval("SELECT 1 FROM policy_rules WHERE name = $1", name)
    if existing:
        return _render(
            request,
            "partials/policy_form.html",
            {
                "mode": "new",
                "form": {
                    "name": name,
                    "priority": priority,
                    "cond_source_id": cond_source_id,
                    "cond_operation": cond_operation,
                    "cond_roles": cond_roles,
                    "cond_identity_roles": cond_identity_roles,
                    "cond_tables": cond_tables,
                    "cond_columns": cond_columns,
                    "action_effect": action_effect,
                    "action_rate_limit": action_rate_limit,
                    "action_redact_columns": action_redact_columns,
                    "raw_conditions": raw_conditions,
                    "raw_actions": raw_actions,
                },
                "error": f'A policy named "{name}" already exists.',
            },
        )

    await pool.execute(
        """
        INSERT INTO policy_rules (name, priority, conditions, actions, enabled)
        VALUES ($1, $2, $3::jsonb, $4::jsonb, TRUE)
        """,
        name,
        priority,
        conditions,
        actions,
    )
    async with pool.acquire() as conn:
        await conn.execute("NOTIFY onyx_policy_changed")
    return _mutation_redirect(request, "/dashboard/policies")


@router.post("/dashboard/policies/{policy_id}/update", response_class=HTMLResponse)
async def update_policy_form(
    policy_id: int,
    request: Request,
    name: str = Form(...),
    priority: int = Form(0),
    cond_source_id: str = Form(""),
    cond_operation: str = Form(""),
    cond_roles: str = Form(""),
    cond_identity_roles: str = Form(""),
    cond_tables: str = Form(""),
    cond_columns: str = Form(""),
    action_effect: str = Form("allow"),
    action_rate_limit: str = Form(""),
    action_redact_columns: str = Form(""),
    raw_conditions: str = Form(""),
    raw_actions: str = Form(""),
) -> HTMLResponse:
    pool = request.app.state.pg_pool
    conditions, actions, err = _build_policy_jsonb(
        cond_source_id=cond_source_id,
        cond_operation=cond_operation,
        cond_roles=cond_roles,
        cond_identity_roles=cond_identity_roles,
        cond_tables=cond_tables,
        cond_columns=cond_columns,
        action_effect=action_effect,
        action_rate_limit=action_rate_limit,
        action_redact_columns=action_redact_columns,
        raw_conditions=raw_conditions,
        raw_actions=raw_actions,
    )
    if err:
        return _render(
            request,
            "partials/policy_form.html",
            {
                "mode": "edit",
                "form": {
                    "policy_id": policy_id,
                    "name": name,
                    "priority": priority,
                    "cond_source_id": cond_source_id,
                    "cond_operation": cond_operation,
                    "cond_roles": cond_roles,
                    "cond_identity_roles": cond_identity_roles,
                    "cond_tables": cond_tables,
                    "cond_columns": cond_columns,
                    "action_effect": action_effect,
                    "action_rate_limit": action_rate_limit,
                    "action_redact_columns": action_redact_columns,
                    "raw_conditions": raw_conditions,
                    "raw_actions": raw_actions,
                },
                "error": err,
            },
        )
    await pool.execute(
        """
        UPDATE policy_rules
        SET name = $1, priority = $2, conditions = $3::jsonb, actions = $4::jsonb
        WHERE id = $5
        """,
        name,
        priority,
        conditions,
        actions,
        policy_id,
    )
    async with pool.acquire() as conn:
        await conn.execute("NOTIFY onyx_policy_changed")
    return _mutation_redirect(request, "/dashboard/policies")


# ---------------------------------------------------------------------------
# Source detail
# ---------------------------------------------------------------------------


@router.get("/dashboard/data-sources/{source_id}/edit", response_class=HTMLResponse)
async def edit_data_source_page(source_id: str, request: Request) -> HTMLResponse:
    pool = request.app.state.pg_pool
    row = await pool.fetchrow("SELECT * FROM data_sources WHERE source_id = $1", source_id)
    if row is None:
        return _render_page(
            request,
            "pages/not_found.html",
            "pages/not_found.html",
            {"active_page": "data-sources", "what": f"data source {source_id!r}"},
        )
    ds = _row_to_dict(row)
    return _render_page(
        request,
        "pages/data_source_edit.html",
        "pages/data_source_edit.html",
        _data_source_edit_context(ds, _connection_config(ds)),
    )


def _data_source_edit_context(
    ds: dict[str, Any],
    cfg: dict[str, Any],
    *,
    stored_cfg: dict[str, Any] | None = None,
    error: str | None = None,
) -> dict[str, Any]:
    connector = get_connector(ds.get("source_type") or "", ds.get("metadata") or {})
    ds["connector_key"] = connector.key
    ds["connector_name"] = connector.name
    exclude: frozenset[str] = frozenset()
    if connector.source_type == "postgresql":
        ds["tls"] = _postgres_tls_edit_fields(cfg)
        exclude = frozenset(
            alias for group in _POSTGRES_TLS_EDIT_GROUPS.values() for alias in group
        )
    # Edited through its own checkbox, never as free text.
    exclude = exclude | {"allow_private_egress"}
    ds["allow_private_egress"] = config_bool(cfg.get("allow_private_egress"))
    ds["editable_connection_fields"] = _editable_connection_fields(cfg, exclude=exclude)
    ds["masked_connection_config"] = sanitize_config(
        cfg if stored_cfg is None else stored_cfg, connector
    )
    return {"active_page": "data-sources", "ds": ds, "error": error}


@router.post("/dashboard/data-sources/{source_id}/edit", response_class=HTMLResponse)
async def update_data_source_page(source_id: str, request: Request) -> Response:
    pool = request.app.state.pg_pool
    form = await request.form()
    before_row = await pool.fetchrow("SELECT * FROM data_sources WHERE source_id = $1", source_id)
    if before_row is None:
        return _mutation_redirect(request, "/dashboard/data-sources")
    before = _row_to_dict(before_row)
    stored_cfg = dict(_connection_config(before))
    cfg = dict(stored_cfg)
    is_postgres = before.get("source_type") == "postgresql"
    keys = list(form.getlist("config_key")) if hasattr(form, "getlist") else []
    values = list(form.getlist("config_value")) if hasattr(form, "getlist") else []
    applied_config_keys: list[str] = []
    for key, value in zip(keys, values, strict=False):
        key = str(key)
        if key not in _EDITABLE_CONFIG_KEYS:
            continue
        applied_config_keys.append(key)
        if is_postgres and key in _POSTGRES_TLS_EDIT_GROUPS:
            for alias in _POSTGRES_TLS_EDIT_GROUPS[key]:
                cfg.pop(alias, None)
        text = str(value).strip()
        if key == "port" and text:
            try:
                cfg[key] = int(text)
            except ValueError:
                cfg[key] = text
        elif text:
            cfg[key] = text
        else:
            cfg.pop(key, None)
    # The edit page renders the private-network checkbox with a marker, so an
    # unticked box means "turn it off" rather than "not on this form".
    if form.get("allow_private_egress_field"):
        cfg.pop("allow_private_egress", None)
        cfg.update(_private_egress_config(form))
    name = str(form.get("name") or before.get("name") or source_id).strip()
    cache_strategy = str(form.get("cache_strategy") or before.get("cache_strategy") or "bypass")
    enabled = str(form.get("enabled") or "") == "on"
    refusal = _console_tls_refusal(request, str(before.get("source_type") or ""), cfg)
    if refusal:
        edited = {**before, "name": name, "cache_strategy": cache_strategy, "enabled": enabled}
        return _render_page(
            request,
            "pages/data_source_edit.html",
            "pages/data_source_edit.html",
            _data_source_edit_context(edited, cfg, stored_cfg=stored_cfg, error=refusal),
        )
    await pool.fetchrow(
        """
        UPDATE data_sources
        SET name = $2,
            connection_config = $3::jsonb,
            cache_strategy = $4,
            enabled = $5,
            updated_at = NOW()
        WHERE source_id = $1
        RETURNING source_id
        """,
        source_id,
        name,
        cfg,
        cache_strategy,
        enabled,
    )
    async with pool.acquire() as conn:
        await conn.execute("NOTIFY onyx_config_changed")
    await invalidate_source_cache(request, source_id)
    await after_source_saved(request, source_id)
    await audit_admin_action(
        request,
        action="data_source.edit",
        resource="data_source",
        resource_id=source_id,
        success=True,
        detail=mutation_audit_detail(
            before=summarize_admin_resource(
                before,
                fields=("source_id", "name", "source_type", "cache_strategy", "enabled"),
            ),
            after={
                "source_id": source_id,
                "name": name,
                "source_type": before.get("source_type"),
                "cache_strategy": cache_strategy,
                "enabled": enabled,
                "editable_config_keys": sorted(applied_config_keys),
                "credential_mode": _credential_mode(cfg),
            },
            changed_fields=("name", "connection_config", "cache_strategy", "enabled"),
            status_code=303,
        ),
    )
    return _mutation_redirect(request, f"/dashboard/data-sources/{source_id}")


@router.get("/dashboard/data-sources/{source_id}", response_class=HTMLResponse)
async def data_source_detail(source_id: str, request: Request) -> HTMLResponse:
    pool = request.app.state.pg_pool

    ds = await pool.fetchrow("SELECT * FROM data_sources WHERE source_id = $1", source_id)
    if ds is None:
        return _render_page(
            request,
            "pages/not_found.html",
            "pages/not_found.html",
            {"active_page": "data-sources", "what": f"data source {source_id!r}"},
        )

    ds_dict = _row_to_dict(ds)
    connector = get_connector(
        ds_dict.get("source_type") or "",
        ds_dict.get("metadata") or {},
    )
    ds_dict["connector_key"] = connector.key
    ds_dict["connector_name"] = connector.name
    ds_dict["connector_family"] = connector.family
    ds_dict["connector_status"] = connector.status
    ds_dict["connector_capabilities"] = connector.capabilities
    ds_dict["connection_summary"] = _safe_connection_summary(ds_dict)
    cfg = _connection_config(ds_dict)
    ds_dict["credential_mode"] = _credential_mode(cfg)
    ds_dict["masked_connection_config"] = sanitize_config(cfg, connector)
    try:
        ds_dict["connector_active"] = connector.key in await active_connector_keys(pool)
    except Exception:
        logger.debug("connector activation lookup failed", exc_info=True)
        ds_dict["connector_active"] = True
    try:
        role_rows = await pool.fetch(
            """
            SELECT r.*,
                   COUNT(DISTINCT p.id) AS permission_count,
                   COUNT(DISTINCT g.id) AS grant_count,
                   COUNT(DISTINCT g.id) FILTER (
                       WHERE g.expires_at IS NULL OR g.expires_at > NOW()
                   ) AS active_grant_count
            FROM source_roles r
            LEFT JOIN source_role_permissions p ON p.role_id = r.id
            LEFT JOIN identity_source_role_grants g
              ON g.role_id = r.id AND g.enabled = TRUE
            WHERE r.source_id = $1
            GROUP BY r.id
            ORDER BY r.enabled DESC, r.role_key
            """,
            source_id,
        )
        source_roles = [dict(r) for r in role_rows]
        referencing = await _policies_naming_roles(pool, [r["role_key"] for r in source_roles])
        for role in source_roles:
            role["referencing_policies"] = referencing.get(role["role_key"], [])
    except Exception:
        logger.debug("source role list failed", exc_info=True)
        source_roles = []

    stats_row = await pool.fetchrow(
        """
        SELECT COUNT(*)                                                                AS requests_24h,
               COUNT(*) FILTER (WHERE cache_hit)                                       AS cache_hits,
               COUNT(*) FILTER (WHERE status = 'error')                                AS errors,
               COUNT(*) FILTER (WHERE status = 'denied')                               AS denials,
               COALESCE(AVG(latency_ms), 0)                                            AS avg_ms,
               COALESCE(PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY latency_ms), 0)   AS p95_ms
        FROM audit_log
        WHERE source_id = $1 AND created_at >= NOW() - INTERVAL '24 hours'
        """,
        source_id,
    )
    requests_24h = int((stats_row or {}).get("requests_24h", 0) or 0)
    cache_hit_pct = 0
    if requests_24h > 0:
        cache_hit_pct = round(int(stats_row["cache_hits"]) / requests_24h * 100)

    recent = await pool.fetch(
        f"""
        SELECT a.created_at, a.identity_id, {IDENTITY_NAME_COLUMNS}, a.operation,
               a.cache_hit, a.cache_tier, a.latency_ms, a.pii_detected, a.status,
               a.error_message
        FROM audit_log a
        {identity_joins("a.identity_id")}
        WHERE a.source_id = $1
        ORDER BY a.created_at DESC
        LIMIT 25
        """,
        source_id,
    )
    policies = await _policies_for_source(pool, source_id)
    approval_rows = await pool.fetch(
        f"""
        SELECT w.id, w.identity_id, {IDENTITY_NAME_COLUMNS}, w.status, w.risk_level,
               w.created_at, w.expires_at
        FROM write_approval_queue w
        {identity_joins("w.identity_id")}
        WHERE w.source_id = $1
        ORDER BY w.created_at DESC
        LIMIT 10
        """,
        source_id,
    )

    ctx = {
        "active_page": "data-sources",
        "ds": ds_dict,
        "stats": {
            "requests_24h": requests_24h,
            "cache_hit_pct": cache_hit_pct,
            "errors": int((stats_row or {}).get("errors", 0) or 0),
            "denials": int((stats_row or {}).get("denials", 0) or 0),
            "avg_ms": round(float((stats_row or {}).get("avg_ms", 0) or 0), 1),
            "p95_ms": round(float((stats_row or {}).get("p95_ms", 0) or 0), 1),
        },
        "recent": [dict(r) for r in recent],
        "policies": policies,
        "approvals": [dict(r) for r in approval_rows],
        "source_roles": source_roles,
    }
    return _render_page(
        request,
        "pages/data_source_detail.html",
        "pages/data_source_detail.html",
        ctx,
    )


@router.post("/dashboard/data-sources/{source_id}/test", response_class=HTMLResponse)
async def test_registered_source_form(source_id: str, request: Request) -> HTMLResponse:
    """Probe a registered source. Returns the same strip the New Source form uses."""
    pool = request.app.state.pg_pool
    row = await pool.fetchrow(
        "SELECT source_type, connection_config, metadata FROM data_sources WHERE source_id = $1",
        source_id,
    )
    if row is None:
        return _render(
            request,
            "partials/connection_test_result.html",
            {
                "ok": False,
                "latency_ms": 0,
                "error": "source not found",
            },
        )
    cfg = row["connection_config"]
    if isinstance(cfg, str):
        cfg = json.loads(cfg)
    try:
        metadata = row["metadata"] or {}
    except (KeyError, TypeError):
        metadata = {}
    if isinstance(metadata, str):
        metadata = json.loads(metadata)
    status = await ConnectionManager.probe_unsaved(
        row["source_type"],
        cfg or {},
        connector_key=connector_key_for(row["source_type"], metadata),
        allow_insecure_tls=allows_insecure_upstream_tls(request.app.state.config),
    )
    await audit_admin_action(
        request,
        action="data_source.probe",
        resource="data_source",
        resource_id=source_id,
        success=status.healthy,
        detail=mutation_audit_detail(
            status_code=200,
            extra={
                "source_type": row["source_type"],
                "connector_key": connector_key_for(row["source_type"], metadata),
                "healthy": status.healthy,
                "latency_ms": round(status.latency_ms, 1),
            },
        ),
        error=status.error,
    )
    return _render(
        request,
        "partials/connection_test_result.html",
        {
            "ok": status.healthy,
            "latency_ms": round(status.latency_ms, 1),
            "error": status.error,
        },
    )


@router.post("/dashboard/data-sources/{source_id}/toggle-enabled", response_class=HTMLResponse)
async def toggle_data_source_enabled(source_id: str, request: Request) -> Response:
    pool = request.app.state.pg_pool
    before_row = await pool.fetchrow(
        "SELECT source_id, name, source_type, enabled FROM data_sources WHERE source_id = $1",
        source_id,
    )
    if before_row is None:
        return _mutation_redirect(request, "/dashboard/data-sources")
    after_row = await pool.fetchrow(
        """
        UPDATE data_sources
        SET enabled = NOT enabled, updated_at = NOW()
        WHERE source_id = $1
        RETURNING source_id, name, source_type, enabled
        """,
        source_id,
    )
    async with pool.acquire() as conn:
        await conn.execute("NOTIFY onyx_config_changed")
    await invalidate_source_cache(request, source_id)
    await after_source_saved(request, source_id)
    await audit_admin_action(
        request,
        action="data_source.toggle_enabled",
        resource="data_source",
        resource_id=source_id,
        success=True,
        detail=mutation_audit_detail(
            before=summarize_admin_resource(
                before_row,
                fields=("source_id", "name", "source_type", "enabled"),
            ),
            after=summarize_admin_resource(
                after_row,
                fields=("source_id", "name", "source_type", "enabled"),
            ),
            changed_fields=("enabled",),
            status_code=303,
        ),
    )
    return _mutation_redirect(request, f"/dashboard/data-sources/{source_id}")


@router.post("/dashboard/data-sources/{source_id}/invalidate-cache", response_class=HTMLResponse)
async def invalidate_data_source_cache(source_id: str, request: Request) -> Response:
    invalidator = getattr(request.app.state, "cache_invalidator", None)
    if invalidator is not None:
        await invalidator.invalidate_for_source(source_id)
    else:
        redis = getattr(request.app.state, "redis", None)
        if redis is not None and hasattr(redis, "publish"):
            await _maybe_await(
                redis.publish(
                    "onyx:cache_invalidate",
                    json.dumps({"source_id": source_id, "scope": "source"}),
                )
            )
    await audit_admin_action(
        request,
        action="data_source.invalidate_cache",
        resource="data_source",
        resource_id=source_id,
        success=True,
        detail=mutation_audit_detail(
            changed_fields=("cache_entries",),
            status_code=303,
            extra={"scope": "source"},
        ),
    )
    return _mutation_redirect(request, f"/dashboard/data-sources/{source_id}")


@router.post("/dashboard/data-sources/{source_id}/delete", response_class=HTMLResponse)
async def delete_data_source_from_dashboard(source_id: str, request: Request) -> Response:
    pool = request.app.state.pg_pool
    before_row = await pool.fetchrow(
        "SELECT source_id, name, source_type, enabled FROM data_sources WHERE source_id = $1",
        source_id,
    )
    if before_row is None:
        return _mutation_redirect(request, "/dashboard/data-sources")
    await pool.execute("DELETE FROM data_sources WHERE source_id = $1", source_id)
    async with pool.acquire() as conn:
        await conn.execute("NOTIFY onyx_config_changed")
    await invalidate_source_cache(request, source_id)
    await audit_admin_action(
        request,
        action="data_source.delete",
        resource="data_source",
        resource_id=source_id,
        success=True,
        detail=mutation_audit_detail(
            before=summarize_admin_resource(
                before_row,
                fields=("source_id", "name", "source_type", "enabled"),
            ),
            changed_fields=("deleted",),
            status_code=303,
        ),
    )
    return _mutation_redirect(request, "/dashboard/data-sources")


@router.get("/dashboard/data-sources/{source_id}/roles", response_class=HTMLResponse)
async def source_roles_page(source_id: str, request: Request) -> HTMLResponse:
    return await data_source_detail(source_id, request)


@router.get("/dashboard/data-sources/{source_id}/roles/statement-row", response_class=HTMLResponse)
async def source_role_statement_row(source_id: str, request: Request) -> HTMLResponse:
    """One statement row, re-rendered when its action or resource type changes.

    With no statement in the query it is a new row seeded with the connector's
    first read action. A resource type the chosen action is never checked
    against is swapped for the action's first; the pattern and conditions are
    kept as typed.
    """
    pool = request.app.state.pg_pool
    vocab = await _role_vocabulary(pool, source_id)
    params = request.query_params
    action = str(params.get("permission_action") or "").strip()
    resource_type = str(params.get("permission_resource_type") or "").strip()
    if not action:
        action = next(
            (a.key for a in vocab.actions.values() if a.group == "read"),
            next(iter(vocab.actions)),
        )
    allowed = vocab.resource_types_for(action)
    if resource_type != "*" and resource_type not in allowed:
        resource_type = allowed[0] if allowed else "*"
    constraints_text = str(params.get("permission_constraints") or "{}")
    try:
        constraints = json.loads(constraints_text) if constraints_text.strip() else {}
    except ValueError:
        constraints = constraints_text
    perm = {
        "effect": "deny" if params.get("permission_effect") == "deny" else "allow",
        "action": action,
        "resource_type": resource_type,
        "resource_pattern": str(params.get("permission_resource_pattern") or ""),
        "constraints": constraints,
    }
    uid = str(params.get("row_uid") or "") or secrets.token_hex(4)
    return _render(
        request,
        "partials/source_role_statement_row.html",
        {"perm": perm, "vocab": vocab, "uid": uid, "source_id": source_id},
    )


@router.get("/dashboard/data-sources/{source_id}/roles/new", response_class=HTMLResponse)
async def new_source_role_form(source_id: str, request: Request) -> HTMLResponse:
    ctx = await _source_role_context(request, source_id=source_id)
    return _render_page(
        request,
        "pages/source_role_form.html",
        "partials/source_role_form.html",
        ctx,
    )


@router.post("/dashboard/data-sources/{source_id}/roles", response_class=HTMLResponse)
async def create_source_role(source_id: str, request: Request) -> HTMLResponse:
    pool = request.app.state.pg_pool
    form = await request.form()
    permissions, error = _parse_permissions_form(form)
    role_form = _role_form_from_post(form, permissions)
    role_key = role_form["role_key"].lower().replace(" ", "_")
    name = role_form["name"]
    if not role_key or not name:
        error = "Role key and display name are required."
    if not error:
        error = _vocabulary_error(await _role_vocabulary(pool, source_id), permissions, [])
    if error:
        ctx = await _source_role_context(
            request,
            source_id=source_id,
            form={**role_form, "role_key": role_key},
            error=error,
        )
        return _render(request, "partials/source_role_form.html", ctx)

    try:
        role_id = await pool.fetchval(
            """
            INSERT INTO source_roles
                (source_id, role_key, name, description, enabled,
                 review_required, metadata)
            VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb)
            RETURNING id
            """,
            source_id,
            role_key,
            name,
            role_form["description"] or None,
            role_form["enabled"] == "on",
            role_form["review_required"] == "on",
            {"created_from": "admin_role_editor"},
        )
    except Exception as exc:
        ctx = await _source_role_context(
            request,
            source_id=source_id,
            form={**role_form, "role_key": role_key},
            error=f"Could not create source role: {exc}",
        )
        return _render(request, "partials/source_role_form.html", ctx)

    for perm in permissions:
        await pool.execute(
            """
            INSERT INTO source_role_permissions
                (role_id, effect, action, resource_type, resource_pattern,
                 constraints)
            VALUES ($1, $2, $3, $4, $5, $6::jsonb)
            """,
            role_id,
            perm["effect"],
            perm["action"],
            perm["resource_type"],
            perm["resource_pattern"],
            perm.get("constraints") or {},
        )
    await audit_admin_action(
        request,
        action="source_role.create",
        resource="source_role",
        resource_id=str(role_id),
        success=True,
        detail=mutation_audit_detail(
            after={
                "id": int(role_id),
                "source_id": source_id,
                "role_key": role_key,
                "name": name,
                "description": role_form["description"] or None,
                "enabled": role_form["enabled"] == "on",
                "review_required": role_form["review_required"] == "on",
                "permissions": permissions,
            },
            changed_fields=(
                "source_id",
                "role_key",
                "name",
                "description",
                "enabled",
                "review_required",
                "permissions",
            ),
            status_code=303 if _is_htmx(request) else 303,
        ),
    )
    await pool.execute(
        "SELECT pg_notify('onyx_identity_changed', $1)",
        json.dumps({"source_id": source_id, "source_role_id": int(role_id)}),
    )
    return _mutation_redirect(request, f"/dashboard/data-sources/{source_id}")


async def _source_role_row(pool: Any, source_id: str, role_id: int) -> Any:
    return await pool.fetchrow(
        """
        SELECT id, source_id, role_key, name, description, enabled,
               review_required, metadata
        FROM source_roles
        WHERE id = $1 AND source_id = $2
        """,
        role_id,
        source_id,
    )


def _source_role_not_found(request: Request, source_id: str, role_id: int) -> HTMLResponse:
    response = _render_page(
        request,
        "pages/not_found.html",
        "pages/not_found.html",
        {"active_page": "data-sources", "what": f"source role #{role_id} on {source_id}"},
    )
    response.status_code = 404
    return response


_ACTIVE_ROLE_HOLDERS_SQL = """
SELECT i.id, i.name
FROM identity_source_role_grants g
JOIN identities i ON i.id = g.identity_id
WHERE g.role_id = $1
  AND g.enabled = TRUE
  AND (g.expires_at IS NULL OR g.expires_at > NOW())
ORDER BY i.name
"""


async def _policies_naming_roles(pool: Any, role_keys: list[str]) -> dict[str, list[str]]:
    """Policy names whose `roles` condition lists each role key."""
    if not role_keys:
        return {}
    rows = await pool.fetch(
        """
        SELECT name, conditions->'roles' AS roles
        FROM policy_rules
        WHERE jsonb_typeof(conditions->'roles') = 'array'
          AND conditions->'roles' ?| $1::text[]
        ORDER BY priority DESC, name
        """,
        role_keys,
    )
    named: dict[str, list[str]] = {}
    for row in rows:
        roles = row["roles"]
        if isinstance(roles, str):
            roles = json.loads(roles)
        for key in roles or []:
            if key in role_keys:
                named.setdefault(key, []).append(row["name"])
    return named


@router.post(
    "/dashboard/data-sources/{source_id}/roles/{role_id:int}/delete",
    response_class=HTMLResponse,
)
async def delete_source_role(source_id: str, role_id: int, request: Request) -> Response:
    """Delete a role nobody holds.

    Refused while any identity holds an active grant: deleting would cascade
    through `identity_source_role_grants` and silently revoke them. Revoked
    grant rows do cascade, so the role, its statements and those rows are
    snapshotted into the admin audit log first - that entry is the history
    `core/source_role_grants.py` promises a revoke keeps.
    """
    pool = request.app.state.pg_pool
    role = await _source_role_row(pool, source_id, role_id)
    if role is None:
        return _source_role_not_found(request, source_id, role_id)
    role_key = str(role["role_key"])
    holders = await pool.fetch(_ACTIVE_ROLE_HOLDERS_SQL, role_id)
    if holders:
        names = ", ".join(f"{h['name']} (#{h['id']})" for h in holders)
        message = (
            f"Role {role_key} is still granted to {names}. "
            "Revoke those grants before deleting it."
        )
        await audit_admin_action(
            request,
            action="source_role.delete",
            resource="source_role",
            resource_id=str(role_id),
            success=False,
            detail=mutation_audit_detail(
                status_code=409,
                extra={"reason": "active_grants", "holders": [int(h["id"]) for h in holders]},
            ),
        )
        response = _render(request, "partials/source_role_delete_result.html", {"error": message})
        # htmx only swaps 2xx responses, so the refusal reaches the console as
        # 200; everything else gets the conflict status.
        if not _is_htmx(request):
            response.status_code = 409
        return response

    permissions = await pool.fetch(
        """
        SELECT effect, action, resource_type, resource_pattern, constraints
        FROM source_role_permissions
        WHERE role_id = $1
        ORDER BY id
        """,
        role_id,
    )
    grants = await pool.fetch(
        """
        SELECT id, identity_id, enabled, expires_at, granted_by, created_at, updated_at
        FROM identity_source_role_grants
        WHERE role_id = $1
        ORDER BY id
        """,
        role_id,
    )
    referencing = (await _policies_naming_roles(pool, [role_key])).get(role_key, [])
    async with pool.acquire() as conn:
        tx = conn.transaction() if hasattr(conn, "transaction") else _NoopAsyncContext()
        async with tx:
            await conn.execute(
                "DELETE FROM source_roles WHERE id = $1 AND source_id = $2",
                role_id,
                source_id,
            )
    before = summarize_admin_resource(
        role,
        fields=(
            "id",
            "source_id",
            "role_key",
            "name",
            "description",
            "enabled",
            "review_required",
            "metadata",
        ),
    )
    if before is not None:
        before["permissions"] = [dict(row) for row in permissions]
        before["grants"] = [dict(row) for row in grants]
    await audit_admin_action(
        request,
        action="source_role.delete",
        resource="source_role",
        resource_id=str(role_id),
        success=True,
        detail=mutation_audit_detail(
            before=before,
            changed_fields=("deleted",),
            status_code=303,
            extra={"referencing_policies": referencing},
        ),
    )
    await pool.execute(
        "SELECT pg_notify('onyx_identity_changed', $1)",
        json.dumps({"source_id": source_id, "source_role_id": int(role_id)}),
    )
    return _mutation_redirect(request, f"/dashboard/data-sources/{source_id}")


@router.get("/dashboard/data-sources/{source_id}/roles/{role_id}/edit", response_class=HTMLResponse)
async def edit_source_role_form(
    source_id: str,
    role_id: int,
    request: Request,
) -> HTMLResponse:
    if await _source_role_row(request.app.state.pg_pool, source_id, role_id) is None:
        return _source_role_not_found(request, source_id, role_id)
    ctx = await _source_role_context(
        request,
        source_id=source_id,
        role_id=role_id,
    )
    return _render_page(
        request,
        "pages/source_role_form.html",
        "partials/source_role_form.html",
        ctx,
    )


# `{role_id:int}` rather than `{role_id}`: this route is declared before
# `/roles/dry-run`, and an unconstrained parameter swallowed it - the console
# posted the Dry-run panel and got 422 "unable to parse dry-run as an integer",
# so the explain feature was dead in the shipped product.
@router.post("/dashboard/data-sources/{source_id}/roles/{role_id:int}", response_class=HTMLResponse)
async def update_source_role(
    source_id: str,
    role_id: int,
    request: Request,
) -> HTMLResponse:
    pool = request.app.state.pg_pool
    # The role must belong to the source in the URL before anything is read or
    # written: the statement rows are keyed by role id alone, so a role id from
    # another source would otherwise have its statements replaced.
    before_role = await _source_role_row(pool, source_id, role_id)
    if before_role is None:
        return _source_role_not_found(request, source_id, role_id)
    before_permissions = await pool.fetch(
        """
        SELECT effect, action, resource_type, resource_pattern, constraints
        FROM source_role_permissions
        WHERE role_id = $1
        ORDER BY id
        """,
        role_id,
    )
    form = await request.form()
    permissions, error = _parse_permissions_form(form)
    role_form = _role_form_from_post(form, permissions)
    role_key = role_form["role_key"].lower().replace(" ", "_")
    name = role_form["name"]
    if not role_key or not name:
        error = "Role key and display name are required."
    if not error:
        error = _vocabulary_error(
            await _role_vocabulary(pool, source_id),
            permissions,
            [dict(row) for row in before_permissions],
        )
    if error:
        ctx = await _source_role_context(
            request,
            source_id=source_id,
            role_id=role_id,
            form={**role_form, "role_key": role_key},
            error=error,
        )
        return _render(request, "partials/source_role_form.html", ctx)

    async with pool.acquire() as conn:
        tx = conn.transaction() if hasattr(conn, "transaction") else _NoopAsyncContext()
        async with tx:
            await conn.execute(
                """
                UPDATE source_roles
                SET role_key = $1,
                    name = $2,
                    description = $3,
                    enabled = $4,
                    review_required = $5,
                    updated_at = NOW()
                WHERE id = $6 AND source_id = $7
                """,
                role_key,
                name,
                role_form["description"] or None,
                role_form["enabled"] == "on",
                role_form["review_required"] == "on",
                role_id,
                source_id,
            )
            await conn.execute(
                """
                DELETE FROM source_role_permissions p
                USING source_roles r
                WHERE p.role_id = r.id AND r.id = $1 AND r.source_id = $2
                """,
                role_id,
                source_id,
            )
            for perm in permissions:
                await conn.execute(
                    """
                    INSERT INTO source_role_permissions
                        (role_id, effect, action, resource_type, resource_pattern,
                         constraints)
                    VALUES ($1, $2, $3, $4, $5, $6::jsonb)
                    """,
                    role_id,
                    perm["effect"],
                    perm["action"],
                    perm["resource_type"],
                    perm["resource_pattern"],
                    perm.get("constraints") or {},
                )
    before_summary = summarize_admin_resource(
        before_role,
        fields=(
            "id",
            "source_id",
            "role_key",
            "name",
            "description",
            "enabled",
            "review_required",
            "metadata",
        ),
    )
    if before_summary is not None:
        before_summary["permissions"] = [dict(row) for row in before_permissions]
    await audit_admin_action(
        request,
        action="source_role.update",
        resource="source_role",
        resource_id=str(role_id),
        success=True,
        detail=mutation_audit_detail(
            before=before_summary,
            after={
                "id": int(role_id),
                "source_id": source_id,
                "role_key": role_key,
                "name": name,
                "description": role_form["description"] or None,
                "enabled": role_form["enabled"] == "on",
                "review_required": role_form["review_required"] == "on",
                "permissions": permissions,
            },
            changed_fields=(
                "role_key",
                "name",
                "description",
                "enabled",
                "review_required",
                "permissions",
            ),
            status_code=303 if _is_htmx(request) else 303,
        ),
    )
    await pool.execute(
        "SELECT pg_notify('onyx_identity_changed', $1)",
        json.dumps({"source_id": source_id, "source_role_id": int(role_id)}),
    )
    return _mutation_redirect(request, f"/dashboard/data-sources/{source_id}")


@router.post("/dashboard/data-sources/{source_id}/roles/dry-run", response_class=HTMLResponse)
async def dry_run_source_role(source_id: str, request: Request) -> HTMLResponse:
    pool = request.app.state.pg_pool
    form = await request.form()
    identity_id_raw = str(form.get("identity_id") or "").strip()
    if not identity_id_raw.isdigit():
        return _render(
            request,
            "partials/source_role_dry_run_result.html",
            {
                "decision": None,
                "error": "Select an identity id with assigned source roles to evaluate.",
            },
        )
    source_row = await pool.fetchrow(
        "SELECT source_type, metadata FROM data_sources WHERE source_id = $1",
        source_id,
    )
    source_type = str(source_row["source_type"]) if source_row else "postgresql"
    source_metadata = source_row["metadata"] if source_row else {}
    if isinstance(source_metadata, str):
        source_metadata = json.loads(source_metadata or "{}")
    tables = [
        part.strip()
        for part in str(form.get("tables") or "").replace("\n", ",").split(",")
        if part.strip()
    ]
    columns = [
        part.strip()
        for part in str(form.get("columns") or "").replace("\n", ",").split(",")
        if part.strip()
    ]
    sql = str(form.get("sql") or "").strip()
    protocol = str(form.get("protocol") or source_type or "postgresql")
    connector = get_connector(source_type, source_metadata)
    if sql and connector.key in _SQL_DRY_RUN_CONNECTORS:
        view = await _dry_run_pipeline(request).governance_view(
            sql_gateway_request(
                sql,
                protocol=protocol,
                source_id=source_id,
                dialect=dialect_for(connector.key),
                metadata={"query": sql, "dry_run": True},
            ),
            identity_id=int(identity_id_raw),
        )
        permission_request = view.permission_request
    elif sql:
        permission_request = get_adapter(
            connector.key,
            {"connector_key": connector.key},
        ).build_permission_request(
            source_id=source_id,
            identity_id=int(identity_id_raw),
            operation=sql,
            metadata={"query": sql, "dry_run": True},
        )
    else:
        view = await _dry_run_pipeline(request).governance_view(
            GatewayRequest(
                protocol=protocol,
                source_id=source_id,
                operation=str(form.get("operation") or "SELECT"),
                method=str(form.get("method") or "") or None,
                path=str(form.get("path") or "") or None,
                tables=tables or None,
                columns=columns or None,
            ),
            identity_id=int(identity_id_raw),
        )
        permission_request = view.permission_request
    decision = await SourceRoleEvaluator(pool).evaluate(permission_request)
    return _render(
        request,
        "partials/source_role_dry_run_result.html",
        {
            "decision": decision.model_dump(),
            "permission_request": permission_request.model_dump(),
            "error": None,
        },
    )


# ---------------------------------------------------------------------------
# Identity detail + activity
# ---------------------------------------------------------------------------


@router.get("/dashboard/access-control/identities/{ident_id}", response_class=HTMLResponse)
async def identity_detail(ident_id: int, request: Request) -> HTMLResponse:
    pool = request.app.state.pg_pool

    ident = await pool.fetchrow(
        """
        SELECT id, name, agent_type, team, roles, mapped_pg_role, enabled,
               pg_username, pg_password_hash, api_key_hash, metadata,
               created_at, updated_at, last_used_at, rotated_at
        FROM identities WHERE id = $1
        """,
        ident_id,
    )
    if ident is None:
        return _render_page(
            request,
            "pages/not_found.html",
            "pages/not_found.html",
            {"active_page": "identities", "what": f"identity #{ident_id}"},
        )

    ident_dict = dict(ident)
    if ident_dict.get("roles") is None:
        ident_dict["roles"] = []
    grant_lookup = await _identity_grants_by_identities(pool, [ident_id])
    ident_dict["source_roles"] = grant_lookup.get(ident_id) or _identity_source_roles(ident_dict)
    if ident_dict.get("api_key_hash"):
        ident_dict["api_key_hash_prefix"] = str(ident_dict["api_key_hash"])[:12]
    if ident_dict.get("pg_password_hash"):
        ident_dict["pg_password_hash_prefix"] = str(ident_dict["pg_password_hash"])[:12]

    stats_row = await pool.fetchrow(
        """
        SELECT COUNT(*)                                                                AS requests_24h,
               COUNT(*) FILTER (WHERE status = 'denied')                               AS denials,
               COUNT(*) FILTER (WHERE status = 'error')                                AS errors,
               COUNT(*) FILTER (WHERE cache_hit)                                       AS cache_hits,
               COALESCE(PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY latency_ms), 0)   AS p95_ms
        FROM audit_log
        WHERE identity_id = $1 AND created_at >= NOW() - INTERVAL '24 hours'
        """,
        ident_id,
    )
    requests_24h = int((stats_row or {}).get("requests_24h", 0) or 0)
    cache_hit_pct = 0
    if requests_24h > 0:
        cache_hit_pct = round(int(stats_row["cache_hits"]) / requests_24h * 100)

    recent = await pool.fetch(
        """
        SELECT created_at, source_id, operation, cache_hit, cache_tier,
               latency_ms, status, error_message
        FROM audit_log
        WHERE identity_id = $1
        ORDER BY created_at DESC
        LIMIT 25
        """,
        ident_id,
    )

    sources_row = await pool.fetch(
        """
        SELECT source_id, COUNT(*) AS cnt
        FROM audit_log
        WHERE identity_id = $1 AND created_at >= NOW() - INTERVAL '24 hours'
        GROUP BY source_id ORDER BY cnt DESC LIMIT 10
        """,
        ident_id,
    )

    ctx = {
        "active_page": "identities",
        "ident": ident_dict,
        "stats": {
            "requests_24h": requests_24h,
            "cache_hit_pct": cache_hit_pct,
            "errors": int((stats_row or {}).get("errors", 0) or 0),
            "denials": int((stats_row or {}).get("denials", 0) or 0),
            "p95_ms": round(float((stats_row or {}).get("p95_ms", 0) or 0), 1),
        },
        "recent": [dict(r) for r in recent],
        "top_sources": [dict(r) for r in sources_row],
        # The grants panel is an included partial that htmx later swaps on its
        # own, so the page must seed it with the same context that route
        # returns - otherwise the first render and every later one differ.
        **await _identity_grants_context(pool, ident_id),
        "error": None,
    }
    return _render_page(
        request,
        "pages/identity_detail.html",
        "pages/identity_detail.html",
        ctx,
    )


async def _identity_grants_context(pool: Any, ident_id: int) -> dict[str, Any]:
    """Everything the grants panel needs: current holds and what can be added."""
    grants = (await _identity_grants_by_identities(pool, [ident_id])).get(ident_id) or []
    try:
        available = await pool.fetch("""
            SELECT r.id AS role_id, r.role_key, r.name AS role_name,
                   r.source_id, ds.name AS source_name
            FROM source_roles r
            LEFT JOIN data_sources ds ON ds.source_id = r.source_id
            WHERE r.enabled = TRUE
            ORDER BY ds.name NULLS LAST, r.source_id, r.role_key
            """)
    except Exception:
        logger.debug("available source-role lookup failed", exc_info=True)
        available = []
    held = {(g["source_id"], int(g["role_id"])) for g in grants}
    return {
        "ident_id": ident_id,
        "grants": grants,
        # Offering a role the identity already holds would make the form look
        # like it does nothing, since granting it again is a no-op.
        "available_roles": [
            dict(row) for row in available if (row["source_id"], int(row["role_id"])) not in held
        ],
    }


@router.post("/dashboard/access-control/identities/{ident_id}/grants", response_class=HTMLResponse)
async def grant_identity_source_role(ident_id: int, request: Request) -> HTMLResponse:
    """Give an existing identity a role on a source, without re-keying it."""
    pool = request.app.state.pg_pool
    form = await request.form()
    choice = str(form.get("source_role") or "")
    source_id, _, role_id = choice.partition(":")
    error: str | None = None
    if not source_id or not role_id:
        error = "Choose a source role to grant."
    else:
        try:
            created = await source_role_grants.grant(
                pool,
                identity_id=ident_id,
                source_id=source_id,
                role_id=int(role_id),
                granted_by=getattr(getattr(request.state, "admin", None), "admin_id", None),
                metadata={"created_from": "admin_identity_detail"},
            )
            await audit_admin_action(
                request,
                action="identity.grant.create",
                resource="identity_source_role_grant",
                resource_id=str(created.id),
                success=True,
                detail={"source_id": source_id, "role_key": created.role_key},
            )
        except source_role_grants.GrantError as exc:
            error = str(exc)
            await audit_admin_action(
                request,
                action="identity.grant.create",
                resource="identity_source_role_grant",
                resource_id=str(ident_id),
                success=False,
                error=error,
            )

    ctx = await _identity_grants_context(pool, ident_id)
    ctx["error"] = error
    return _render(request, "partials/identity_grants.html", ctx)


@router.post(
    "/dashboard/access-control/identities/{ident_id}/grants/{grant_id}/revoke",
    response_class=HTMLResponse,
)
async def revoke_identity_source_role(
    ident_id: int, grant_id: int, request: Request
) -> HTMLResponse:
    """Withdraw one grant. The key is untouched; the next request sees it."""
    pool = request.app.state.pg_pool
    revoked = await source_role_grants.revoke(pool, identity_id=ident_id, grant_id=grant_id)
    await audit_admin_action(
        request,
        action="identity.grant.revoke",
        resource="identity_source_role_grant",
        resource_id=str(grant_id),
        success=revoked is not None,
        detail={"source_id": revoked.source_id, "role_key": revoked.role_key} if revoked else None,
        error=None if revoked else "Grant not found for this identity",
    )
    ctx = await _identity_grants_context(pool, ident_id)
    ctx["error"] = None if revoked else "That grant no longer exists."
    return _render(request, "partials/identity_grants.html", ctx)


@router.post(
    "/dashboard/access-control/identities/{ident_id}/rotate-key", response_class=HTMLResponse
)
async def rotate_identity_key(ident_id: int, request: Request) -> HTMLResponse:
    pool = request.app.state.pg_pool
    redis = getattr(request.app.state, "redis", None)

    ident = await pool.fetchrow(
        "SELECT id, name, roles, api_key_hash FROM identities WHERE id = $1",
        ident_id,
    )
    if ident is None:
        ctx = await _identity_form_context(
            request,
            form=_default_identity_form(),
            error=f"identity #{ident_id} not found",
        )
        return _render(request, "partials/identity_form.html", ctx)

    old_hash = ident["api_key_hash"]
    raw_key = secrets.token_urlsafe(32)
    new_hash, new_hash_version = hash_api_key_for_storage(raw_key, request.app.state.config.auth)

    await pool.execute(
        """
        UPDATE identities
        SET api_key_hash = $1,
            api_key_hash_version = $2,
            rotated_at = NOW(),
            updated_at = NOW()
        WHERE id = $3
        """,
        new_hash,
        new_hash_version,
        ident_id,
    )

    # Invalidate the old session cache so the previously-cached key is
    # not silently accepted until its TTL expires.
    if redis is not None and old_hash:
        try:
            await redis.delete(f"session:{old_hash}")
        except Exception:
            logger.warning("failed to invalidate session:%s on key rotation", old_hash[:8])

    await audit_admin_action(
        request,
        action="identity.api_key.rotate",
        resource="identity",
        resource_id=str(ident_id),
        success=True,
        detail=mutation_audit_detail(
            before=summarize_admin_resource(
                ident,
                fields=("id", "name", "roles"),
            ),
            after={
                "id": ident_id,
                "name": ident["name"],
                "roles": list(ident["roles"] or []),
                "rotated": True,
                "cache_invalidated": bool(redis is not None and old_hash),
            },
            changed_fields=("api_key_hash", "rotated_at", "updated_at"),
            status_code=200,
        ),
    )

    return _render(
        request,
        "partials/identity_created.html",
        {
            "name": ident["name"],
            "api_key": raw_key,
            "roles": list(ident["roles"] or []),
            "source_roles": [],
        },
    )


# ---------------------------------------------------------------------------
# Source onboarding wizard (multi-step)
# ---------------------------------------------------------------------------


# Heuristic for "this column looks PII-ish based on its name". Used to
# pre-check checkboxes in the schema preview. Not a security guarantee.


def _wizard_state(form: dict[str, Any]) -> dict[str, Any]:
    """Pluck wizard state out of the posted form data."""
    state: dict[str, Any] = {
        "wizard_id": form.get("wizard_id", ""),
        "source_id": form.get("source_id", "").strip(),
        "name": form.get("name", "").strip(),
        "source_type": form.get("source_type", "postgresql"),
        "connector_key": form.get("connector_key", "")
        or connector_key_for(
            form.get("source_type", "postgresql"),
            None,
        ),
        "host": form.get("host", ""),
        "port": form.get("port", "") or 5432,
        "database": form.get("database", ""),
        "user": form.get("user", ""),
        "password": form.get("password", ""),
        "password_ref": form.get("password_ref", ""),
        "sslmode": form.get("sslmode", ""),
        "ssl_ca": form.get("ssl_ca", ""),
        "base_url": form.get("base_url", ""),
        "auth_header": form.get("auth_header", ""),
        "token": form.get("token", ""),
        "token_ref": form.get("token_ref", ""),
        "bucket": form.get("bucket", ""),
        "prefix": form.get("prefix", ""),
        "region_name": form.get("region_name", "us-east-1"),
        "endpoint_url": form.get("endpoint_url", ""),
        "aws_access_key_id_ref": form.get("aws_access_key_id_ref", ""),
        "aws_secret_access_key_ref": form.get("aws_secret_access_key_ref", ""),
        "account": form.get("account", ""),
        "warehouse": form.get("warehouse", ""),
        "schema": form.get("schema", ""),
        "role": form.get("role", ""),
        "subdomain": form.get("subdomain", ""),
        "email": form.get("email", ""),
        "api_token_ref": form.get("api_token_ref", ""),
        "workspace": form.get("workspace", ""),
        "bot_token_ref": form.get("bot_token_ref", ""),
        "org": form.get("org", ""),
        "group": form.get("group", ""),
        "cache_strategy": form.get("cache_strategy", "deterministic_first"),
        "create_default_roles": form.get("create_default_roles", "off"),
        "allow_private_egress": form.get("allow_private_egress", ""),
        "probe_path": form.get("probe_path", ""),
    }
    cols = form.get("pii_columns")
    if isinstance(cols, list):
        state["pii_columns"] = cols
    elif isinstance(cols, str) and cols:
        state["pii_columns"] = [cols]
    else:
        state["pii_columns"] = []
    return state


async def _wizard_state_from_form(request: Request, form: Any) -> dict[str, Any]:
    """Merge posted wizard fields into the server-side wizard draft."""
    form_dict = dict(form)
    wizard_id = str(form_dict.get("wizard_id") or "").strip() or _new_wizard_id()
    draft = await _load_wizard_draft(request, wizard_id)
    for secret_field in ("password", "token", "auth_header"):
        if form_dict.get(secret_field) == "" and draft.get(secret_field):
            form_dict.pop(secret_field, None)
    merged = {**draft, **form_dict, "wizard_id": wizard_id}
    state = _wizard_state(merged)
    if hasattr(form, "getlist"):
        posted_pii = list(form.getlist("pii_columns"))
        if posted_pii:
            state["pii_columns"] = posted_pii
        elif "pii_columns" in draft:
            state["pii_columns"] = list(draft.get("pii_columns") or [])
    state["pii_labels"] = [".".join(path) for path in _wizard_pii_paths(state["pii_columns"])]
    await _save_wizard_draft(request, wizard_id, state)
    return state


# Connectors whose SQL the gateway governs through its own derivation; the
# dry-runs take the same path for them.
_SQL_DRY_RUN_CONNECTORS = frozenset({"postgresql", "mysql", "mariadb", "snowflake", "fabric_sql"})


def _dry_run_pipeline(request: Request) -> GatewayPipeline:
    """A pipeline that derives governance exactly as the gateway's does."""
    return GatewayPipeline(
        write_classifier=WriteClassifier(critical_tables=set()),
        sql_naming=getattr(request.app.state, "sql_naming_resolver", None),
    )


def _wizard_pii_paths(values: list[str]) -> list[list[str]]:
    """Catalog paths for the wizard's PII checkboxes.

    Each checkbox carries its path as a JSON array - schema, table, column - so
    identifiers containing dots survive. A plain dotted value from a wizard
    started before that change is read as `table.column` in `public`, or
    `schema.table.column`.
    """
    paths: list[list[str]] = []
    for value in values:
        path: Any = None
        if value.startswith("["):
            try:
                path = json.loads(value)
            except ValueError:
                path = None
        else:
            parts = value.split(".")
            if len(parts) == 2:
                path = ["public", *parts]
            elif len(parts) == 3:
                path = parts
        if (
            isinstance(path, list)
            and len(path) == 3
            and all(isinstance(part, str) and part for part in path)
            and path not in paths
        ):
            paths.append(path)
    return paths


_looks_like_pii = looks_like_pii


async def _introspect_postgres(
    state: dict[str, Any], *, allow_insecure_tls: bool = True
) -> tuple[list[dict], str | None]:
    """Connect with the wizard's connection details and list tables/columns.

    Returns ``(tables, error)``. On failure the tables list is empty and
    the error message is suitable for surfacing in the UI.
    """
    import asyncio

    import asyncpg

    host = state.get("host")
    port = int(state.get("port") or 5432)
    if not host:
        return [], "host is required"
    tls = _postgres_tls_config(state)
    # Test Connection and every query path apply this judgement, so the
    # wizard cannot reach an upstream that production would refuse either.
    refusal = upstream_tls_refusal(tls, allow_insecure_tls=allow_insecure_tls)
    if refusal:
        return [], refusal

    try:
        conn = await asyncio.wait_for(
            asyncpg.connect(
                host=host,
                port=port,
                database=state.get("database") or "postgres",
                user=state.get("user") or "postgres",
                password=state.get("password") or "",
                ssl=_ssl_argument(tls["sslmode"], tls) if "sslmode" in tls else None,
            ),
            timeout=5.0,
        )
    except Exception as exc:
        return [], str(exc)
    try:
        rows = await conn.fetch("""
            SELECT table_schema, table_name, column_name, data_type
            FROM information_schema.columns
            WHERE table_schema NOT IN ('pg_catalog', 'information_schema')
            ORDER BY table_schema, table_name, ordinal_position
            LIMIT 1000
            """)
    except Exception as exc:
        await conn.close()
        return [], str(exc)
    await conn.close()

    grouped: dict[tuple[str, str], list[dict]] = {}
    for r in rows:
        grouped.setdefault((r["table_schema"], r["table_name"]), []).append(
            {
                "name": r["column_name"],
                "type": r["data_type"],
                "likely_pii": _looks_like_pii(r["column_name"]),
            }
        )
    return [
        {
            "name": table if schema == "public" else f"{schema}.{table}",
            "schema": schema,
            "table": table,
            "columns": columns,
        }
        for (schema, table), columns in grouped.items()
    ], None


@router.get("/dashboard/source-wizard", response_class=HTMLResponse)
async def wizard_start(request: Request) -> HTMLResponse:
    wizard_id = _new_wizard_id()
    state = {
        "wizard_id": wizard_id,
        "source_type": "postgresql",
        "connector_key": "postgresql",
        "create_default_roles": "on",
    }
    await _save_wizard_draft(request, wizard_id, state)
    ctx = {
        "active_page": "data-sources",
        "state": state,
        "connector_groups": await active_connector_groups(request.app.state.pg_pool),
        "error": None,
    }
    if _is_htmx(request) and request.headers.get("HX-Target") == "source-modal-root":
        return _render(request, "partials/source_wizard_modal.html", ctx)
    return _render_page(
        request,
        "pages/source_wizard.html",
        "partials/wizard/step1_type.html",
        ctx,
    )


@router.post("/dashboard/source-wizard/step1", response_class=HTMLResponse)
async def wizard_step1(request: Request) -> HTMLResponse:
    form = await request.form()
    state = await _wizard_state_from_form(request, form)
    return _render(
        request,
        "partials/wizard/step1_type.html",
        {
            "state": state,
            "connector_groups": await active_connector_groups(request.app.state.pg_pool),
            "error": None,
        },
    )


@router.post("/dashboard/source-wizard/step2", response_class=HTMLResponse)
async def wizard_step2(request: Request) -> HTMLResponse:
    form = await request.form()
    state = await _wizard_state_from_form(request, form)
    err = None
    if not state["name"]:
        err = "Display name is required."
    elif state["source_id"]:
        err = _source_id_refusal(state["source_id"])
    if not err:
        err = await _inactive_connector_error(request.app.state.pg_pool, state["connector_key"])
    if err:
        return _render(
            request,
            "partials/wizard/step1_type.html",
            {
                "state": state,
                "connector_groups": await active_connector_groups(request.app.state.pg_pool),
                "error": err,
            },
        )
    return _render(
        request,
        "partials/wizard/step2_connection.html",
        {
            "state": state,
            "error": None,
        },
    )


@router.post("/dashboard/source-wizard/test", response_class=HTMLResponse)
async def wizard_test(request: Request) -> HTMLResponse:
    form = await request.form()
    state = await _wizard_state_from_form(request, form)
    inactive = await _inactive_connector_error(request.app.state.pg_pool, state["connector_key"])
    if inactive:
        return _render(
            request,
            "partials/connection_test_result.html",
            {"ok": False, "latency_ms": 0.0, "error": inactive},
        )
    connector = get_connector(state["source_type"], {"connector_key": state["connector_key"]})
    if state["source_type"] in {"postgresql", "mysql"} or connector.family == "database":
        cfg: dict[str, Any] = {
            "host": state["host"],
            "port": int(state["port"] or 5432),
        }
        if state["database"]:
            cfg["database"] = state["database"]
        if state["user"]:
            cfg["user"] = state["user"]
        if state["password"]:
            cfg["password"] = state["password"]
        if state.get("password_ref"):
            cfg["password_ref"] = state["password_ref"]
        if connector.source_type == "postgresql":
            cfg.update(_postgres_tls_config(state))
    elif state["source_type"] == "http" or connector.family == "http":
        cfg = {"base_url": state["base_url"]}
        if state.get("auth_header"):
            cfg["auth_header"] = state["auth_header"]
        if state.get("token"):
            cfg["token"] = state["token"]
        if state.get("token_ref"):
            cfg["token_ref"] = state["token_ref"]
    else:
        cfg = _connector_config_from_form(state["connector_key"], state)
    cfg.update(_private_egress_config(state))
    cfg.update(_http_probe_config(state, connector.key))
    status = await ConnectionManager.probe_unsaved(
        state["source_type"],
        cfg,
        connector_key=state["connector_key"],
        allow_insecure_tls=allows_insecure_upstream_tls(request.app.state.config),
    )
    return _render(
        request,
        "partials/connection_test_result.html",
        {
            "ok": status.healthy,
            "latency_ms": round(status.latency_ms, 1),
            "error": status.error,
        },
    )


@router.post("/dashboard/source-wizard/step3", response_class=HTMLResponse)
async def wizard_step3(request: Request) -> HTMLResponse:
    form = await request.form()
    state = await _wizard_state_from_form(request, form)
    tables: list[dict] = []
    schema_error: str | None = None
    if state["source_type"] == "postgresql":
        tables, schema_error = await _introspect_postgres(
            state,
            allow_insecure_tls=allows_insecure_upstream_tls(request.app.state.config),
        )
    return _render(
        request,
        "partials/wizard/step3_schema.html",
        {
            "state": state,
            "tables": tables,
            "schema_error": schema_error,
        },
    )


@router.post("/dashboard/source-wizard/step4", response_class=HTMLResponse)
async def wizard_step4(request: Request) -> HTMLResponse:
    form = await request.form()
    state = await _wizard_state_from_form(request, form)
    if not state["cache_strategy"]:
        # Default based on type.
        state["cache_strategy"] = (
            "deterministic_first"
            if state["source_type"] in {"postgresql", "mysql"}
            else "semantic_first"
        )
    return _render(request, "partials/wizard/step4_cache.html", {"state": state})


@router.post("/dashboard/source-wizard/step5", response_class=HTMLResponse)
async def wizard_step5(request: Request) -> HTMLResponse:
    form = await request.form()
    state = await _wizard_state_from_form(request, form)
    return _render(
        request,
        "partials/wizard/step5_review.html",
        {
            "state": state,
            "planned_source_id": state["source_id"]
            or await generate_source_id(request.app.state.pg_pool, state["name"]),
            "error": None,
        },
    )


@router.post("/dashboard/source-wizard/save", response_class=HTMLResponse)
async def wizard_save(request: Request) -> HTMLResponse:
    pool = request.app.state.pg_pool
    form = await request.form()
    state = await _wizard_state_from_form(request, form)

    inactive = await _inactive_connector_error(pool, state["connector_key"])
    if inactive:
        return _render(
            request,
            "partials/wizard/step5_review.html",
            {"state": state, "error": inactive},
        )
    connector = get_connector(state["source_type"], {"connector_key": state["connector_key"]})
    if state["source_type"] in {"postgresql", "mysql"} or connector.family == "database":
        cfg: dict[str, Any] = {"host": state["host"], "port": int(state["port"] or 5432)}
        if state["database"]:
            cfg["database"] = state["database"]
        if state["user"]:
            cfg["user"] = state["user"]
        if state["password"]:
            cfg["password"] = state["password"]
        if state.get("password_ref"):
            cfg["password_ref"] = state["password_ref"]
        if connector.source_type == "postgresql":
            cfg.update(_postgres_tls_config(state))
    elif state["source_type"] == "http" or connector.family == "http":
        cfg = {"base_url": state["base_url"]}
        if state.get("auth_header"):
            cfg["auth_header"] = state["auth_header"]
        if state.get("token"):
            cfg["token"] = state["token"]
        if state.get("token_ref"):
            cfg["token_ref"] = state["token_ref"]
    else:
        cfg = _connector_config_from_form(state["connector_key"], state)
    cfg.update(_private_egress_config(state))
    cfg.update(_http_probe_config(state, connector.key))

    refusal = _console_tls_refusal(request, connector.source_type, cfg)
    if refusal:
        return _render(
            request,
            "partials/wizard/step5_review.html",
            {"state": state, "error": refusal},
        )

    if state["source_id"]:
        id_error = _source_id_refusal(state["source_id"])
        if not id_error and await pool.fetchval(
            "SELECT 1 FROM data_sources WHERE source_id = $1", state["source_id"]
        ):
            id_error = f"A data source with source_id '{state['source_id']}' already exists."
        if id_error:
            return _render(
                request,
                "partials/wizard/step5_review.html",
                {"state": state, "error": id_error},
            )
    else:
        # Generated at save, not taken from the review step's preview, so a
        # source registered in between cannot collide with this one.
        state["source_id"] = await generate_source_id(pool, state["name"])

    await pool.execute(
        """
        INSERT INTO data_sources (source_id, name, source_type, connection_config,
                                  cache_strategy, enabled, metadata)
        VALUES ($1, $2, $3, $4::jsonb, $5, TRUE, $6::jsonb)
        """,
        state["source_id"],
        state["name"],
        state["source_type"],
        cfg,
        state["cache_strategy"],
        {
            **_blank_source_metadata(),
            **source_metadata_for_connector(state["connector_key"]),
        },
    )
    if state.get("create_default_roles") == "on":
        await _ensure_default_source_roles(
            pool,
            source_id=state["source_id"],
            source_type=state["source_type"],
            connector_key=state["connector_key"],
        )

    # Record the columns the admin flagged as PII in the source catalog's
    # annotations, which rescans never overwrite. Best-effort: a flag that
    # cannot be stored must not undo a saved source.
    for path in _wizard_pii_paths(state["pii_columns"]):
        try:
            await pool.execute(
                """
                INSERT INTO source_catalog_annotations
                    (source_id, path, classification, classification_source, applied_by)
                VALUES ($1, $2::text[], 'pii', 'wizard', $3)
                ON CONFLICT (source_id, path) DO NOTHING
                """,
                state["source_id"],
                path,
                getattr(getattr(request.state, "admin", None), "username", None),
            )
        except Exception:
            logger.warning("Could not record a wizard PII flag", exc_info=True)

    async with pool.acquire() as conn:
        await conn.execute("NOTIFY onyx_config_changed")
    await after_source_saved(request, state["source_id"])

    await audit_admin_action(
        request,
        action="data_source.wizard_create",
        resource="data_source",
        resource_id=state["source_id"],
        success=True,
        detail=mutation_audit_detail(
            after={
                "source_id": state["source_id"],
                "name": state["name"],
                "source_type": state["source_type"],
                "connector_key": state["connector_key"],
                "cache_strategy": state["cache_strategy"],
                "credential_mode": _credential_mode(cfg),
                "default_roles_created": state.get("create_default_roles") == "on",
                "pii_columns_count": len(state.get("pii_columns") or []),
            },
            changed_fields=[
                "source_id",
                "name",
                "source_type",
                "connection_config",
                "cache_strategy",
                "metadata",
            ],
            status_code=303,
        ),
    )
    await _delete_wizard_draft(request, state.get("wizard_id", ""))
    return _mutation_redirect(request, f"/dashboard/data-sources/{state['source_id']}")


@router.post("/dashboard/source-wizard/cancel", response_class=HTMLResponse)
async def wizard_cancel(request: Request) -> Response:
    form = await request.form()
    wizard_id = str(form.get("wizard_id") or "")
    await _delete_wizard_draft(request, wizard_id)
    await audit_admin_action(
        request,
        action="data_source.wizard_cancel",
        resource="data_source_wizard",
        resource_id=wizard_id or None,
        success=True,
        detail=mutation_audit_detail(status_code=303, extra={"draft_deleted": bool(wizard_id)}),
    )
    return _mutation_redirect(request, "/dashboard/data-sources")


# ---------------------------------------------------------------------------
# Alerting
# ---------------------------------------------------------------------------


@router.get("/dashboard/alerts", response_class=HTMLResponse)
async def alerts_page(request: Request) -> HTMLResponse:
    pool = request.app.state.pg_pool
    rules = []
    try:
        rule_rows = await pool.fetch(
            f"SELECT r.*, {IDENTITY_NAME_COLUMNS} FROM alert_rules r "
            f"{identity_joins('r.identity_id')} ORDER BY r.enabled DESC, r.name"
        )
        for row in rule_rows:
            rule = dict(row)
            raw_target = rule.pop("notification_target", None)
            rule["notification_target_display"] = _masked_notification_target(raw_target)
            rules.append(rule)
    except Exception:
        logger.debug("alert_rules query failed (migration 004 not applied?)", exc_info=True)
    history = []
    try:
        history_rows = await pool.fetch("""
            SELECT id, rule_name, fired_at, observed_value, message,
                   acknowledged_at, acknowledged_by
            FROM alert_history
            ORDER BY fired_at DESC
            LIMIT 50
            """)
        history = [dict(r) for r in history_rows]
    except Exception:
        logger.debug("alert_history query failed", exc_info=True)

    return _render_page(
        request,
        "pages/alerts.html",
        "pages/alerts.html",
        {
            "active_page": "alerts",
            "rules": rules,
            "history": history,
            "channels": _alert_channels(request),
        },
    )


@router.get("/dashboard/alerts/new", response_class=HTMLResponse)
async def new_alert_form(request: Request) -> HTMLResponse:
    return _render_page(
        request,
        "pages/alert_form.html",
        "partials/alert_form.html",
        {
            "active_page": "alerts",
            "form": _default_alert_form(),
            "error": None,
            "channels": _alert_channels(request),
        },
    )


@router.post("/dashboard/alerts/create", response_class=HTMLResponse)
async def create_alert_rule(
    request: Request,
    name: str = Form(...),
    description: str = Form(""),
    condition_type: str = Form(...),
    comparator: str = Form(">"),
    threshold: float = Form(...),
    window_seconds: int = Form(300),
    source_id: str = Form(""),
    identity_id: str = Form(""),
    notification_channel: str = Form("log"),
    notification_target: str = Form(""),
) -> HTMLResponse:
    pool = request.app.state.pg_pool

    existing = await pool.fetchval("SELECT 1 FROM alert_rules WHERE name = $1", name)
    if existing:
        return _render(
            request,
            "partials/alert_form.html",
            {
                "form": {
                    "name": name,
                    "description": description,
                    "condition_type": condition_type,
                    "comparator": comparator,
                    "threshold": threshold,
                    "window_seconds": window_seconds,
                    "source_id": source_id,
                    "identity_id": identity_id,
                    "notification_channel": notification_channel,
                    "notification_target": "",
                    "notification_target_supplied": bool(notification_target),
                },
                "error": f'An alert rule named "{name}" already exists.',
            },
        )

    await pool.execute(
        """
        INSERT INTO alert_rules
            (name, description, condition_type, comparator, threshold,
             window_seconds, source_id, identity_id,
             notification_channel, notification_target, enabled)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, TRUE)
        """,
        name,
        description or None,
        condition_type,
        comparator,
        threshold,
        window_seconds,
        source_id or None,
        int(identity_id) if identity_id else None,
        notification_channel,
        notification_target or None,
    )
    await audit_admin_action(
        request,
        action="alert_rule.create",
        resource="alert_rule",
        resource_id=name,
        success=True,
        detail=mutation_audit_detail(
            after={
                "name": name,
                "description": description or None,
                "condition_type": condition_type,
                "comparator": comparator,
                "threshold": threshold,
                "window_seconds": window_seconds,
                "source_id": source_id or None,
                "identity_id": int(identity_id) if identity_id else None,
                "notification_channel": notification_channel,
                "notification_target": notification_target or None,
                "enabled": True,
            },
            changed_fields=(
                "name",
                "description",
                "condition_type",
                "comparator",
                "threshold",
                "window_seconds",
                "source_id",
                "identity_id",
                "notification_channel",
                "notification_target",
                "enabled",
            ),
            status_code=303,
        ),
    )
    return _mutation_redirect(request, "/dashboard/alerts")


@router.post("/dashboard/alerts/dry-run", response_class=HTMLResponse)
async def dry_run_alert_rule(
    request: Request,
    name: str = Form("unsaved-rule"),
    condition_type: str = Form("error_rate"),
    comparator: str = Form(">"),
    threshold: float = Form(0.1),
    window_seconds: int = Form(300),
    source_id: str = Form(""),
    identity_id: str = Form(""),
    notification_channel: str = Form("log"),
) -> HTMLResponse:
    from interlock.admin.alerts import evaluate_rule

    pool = request.app.state.pg_pool
    rule = {
        "id": None,
        "name": name or "unsaved-rule",
        "condition_type": condition_type,
        "comparator": comparator,
        "threshold": threshold,
        "window_seconds": window_seconds,
        "source_id": source_id or None,
        "identity_id": int(identity_id) if identity_id else None,
        "notification_channel": notification_channel,
    }
    result = await evaluate_rule(pool, rule)
    return _render(
        request,
        "partials/alert_eval_result.html",
        {
            "result": {
                "fired": result.fired,
                "observed_value": result.observed_value,
                "message": result.message,
            },
            "error": None,
        },
    )


@router.post("/dashboard/alerts/{rule_id}/evaluate", response_class=HTMLResponse)
async def evaluate_alert_rule(rule_id: int, request: Request) -> HTMLResponse:
    """Manually evaluate a rule and record the result if it fires."""
    from interlock.admin.alerts import evaluate_rule

    pool = request.app.state.pg_pool
    rule_row = await pool.fetchrow("SELECT * FROM alert_rules WHERE id = $1", rule_id)
    if rule_row is None:
        return _render(
            request,
            "partials/alert_eval_result.html",
            {
                "result": None,
                "error": f"alert rule #{rule_id} not found",
            },
        )
    result = await evaluate_rule(pool, dict(rule_row))

    # Update last_evaluated_at always; last_fired_at on fire.
    await pool.execute(
        "UPDATE alert_rules SET last_evaluated_at = NOW() WHERE id = $1",
        rule_id,
    )
    if result.fired:
        await pool.execute(
            """
            INSERT INTO alert_history
                (rule_id, rule_name, observed_value, message)
            VALUES ($1, $2, $3, $4)
            """,
            rule_id,
            rule_row["name"],
            result.observed_value,
            result.message,
        )
        await pool.execute(
            "UPDATE alert_rules SET last_fired_at = NOW() WHERE id = $1",
            rule_id,
        )
    await audit_admin_action(
        request,
        action="alert_rule.evaluate",
        resource="alert_rule",
        resource_id=str(rule_id),
        success=True,
        detail=mutation_audit_detail(
            before=summarize_admin_resource(
                rule_row,
                fields=(
                    "id",
                    "name",
                    "condition_type",
                    "comparator",
                    "threshold",
                    "source_id",
                    "identity_id",
                    "enabled",
                ),
            ),
            after={
                "fired": result.fired,
                "observed_value": result.observed_value,
                "message": result.message,
            },
            changed_fields=(
                ("last_evaluated_at", "last_fired_at") if result.fired else ("last_evaluated_at",)
            ),
            status_code=200,
        ),
    )

    return _render(
        request,
        "partials/alert_eval_result.html",
        {
            "result": {
                "fired": result.fired,
                "observed_value": result.observed_value,
                "message": result.message,
            },
            "error": None,
        },
    )


@router.post("/dashboard/alerts/{rule_id}/toggle", response_class=HTMLResponse)
async def toggle_alert_rule(rule_id: int, request: Request) -> HTMLResponse:
    pool = request.app.state.pg_pool
    before_row = await pool.fetchrow(
        "SELECT id, name, enabled FROM alert_rules WHERE id = $1",
        rule_id,
    )
    await pool.execute(
        "UPDATE alert_rules SET enabled = NOT enabled, updated_at = NOW() WHERE id = $1",
        rule_id,
    )
    before = summarize_admin_resource(before_row, fields=("id", "name", "enabled"))
    after = None
    if before is not None:
        after = {**before, "enabled": not bool(before.get("enabled"))}
    await audit_admin_action(
        request,
        action="alert_rule.toggle",
        resource="alert_rule",
        resource_id=str(rule_id),
        success=True,
        detail=mutation_audit_detail(
            before=before,
            after=after,
            changed_fields=("enabled",),
            status_code=303,
        ),
    )
    return _mutation_redirect(request, "/dashboard/alerts")


@router.post("/dashboard/alerts/history/{event_id}/ack", response_class=HTMLResponse)
async def acknowledge_alert(event_id: int, request: Request) -> HTMLResponse:
    pool = request.app.state.pg_pool
    actor = getattr(getattr(request.state, "admin", None), "username", "admin")
    await pool.execute(
        """
        UPDATE alert_history
        SET acknowledged_at = NOW(), acknowledged_by = $1
        WHERE id = $2 AND acknowledged_at IS NULL
        """,
        actor,
        event_id,
    )
    await audit_admin_action(
        request,
        action="alert_history.acknowledge",
        resource="alert_history",
        resource_id=str(event_id),
        success=True,
        detail=mutation_audit_detail(
            after={"event_id": event_id, "acknowledged_by": actor},
            changed_fields=("acknowledged_at", "acknowledged_by"),
            status_code=303,
        ),
    )
    return _mutation_redirect(request, "/dashboard/alerts")
