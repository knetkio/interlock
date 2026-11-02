"""RBAC policy engine - evaluates policy rules against requests.

Rules are loaded from the policy_rules table and cached in memory.
PG NOTIFY on onyx_policy_changed triggers a full reload.
Default-deny: if no rule matches, the request is denied.
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

import asyncpg

from interlock.models import IdentityContext, PolicyDecision, PolicyRule

logger = logging.getLogger(__name__)

_RULES_QUERY = """
SELECT id, name, priority, conditions, actions, enabled
FROM policy_rules
WHERE enabled = TRUE
ORDER BY priority DESC
"""


class PolicyEngine:
    """Evaluates RBAC policy rules against incoming requests.

    Rules are sorted by priority descending. First matching rule wins.
    If no rule matches, the request is denied (default-deny).
    """

    def __init__(self, pg_pool: asyncpg.Pool) -> None:
        self._pool = pg_pool
        self._rules: list[PolicyRule] = []
        self._listener_conn: asyncpg.Connection | None = None
        self._reload_generation = 0
        self._applied_reload_generation = 0
        self._reload_task: asyncio.Task[None] | None = None
        self._reload_lock = asyncio.Lock()

    async def load(self) -> None:
        """Load all enabled policy rules from policy_rules table, sorted by priority DESC."""
        rows = await self._pool.fetch(_RULES_QUERY)
        rules: list[PolicyRule] = []
        for row in rows:
            conditions = row["conditions"]
            if isinstance(conditions, str):
                conditions = json.loads(conditions)
            actions = row["actions"]
            if isinstance(actions, str):
                actions = json.loads(actions)
            rules.append(
                PolicyRule(
                    id=row["id"],
                    name=row["name"],
                    priority=row["priority"],
                    conditions=conditions,
                    actions=actions,
                    enabled=row["enabled"],
                )
            )
        self._rules = rules
        logger.info("Loaded %d policy rule(s)", len(self._rules))

    async def setup_listener(self) -> None:
        """LISTEN on onyx_policy_changed, reload on notify."""
        self._listener_conn = await self._pool.acquire()
        await self._listener_conn.add_listener("onyx_policy_changed", self._on_notify)
        logger.info("PolicyEngine listening on onyx_policy_changed")

    def _on_notify(
        self,
        connection: asyncpg.Connection,
        pid: int,
        channel: str,
        payload: str,
    ) -> None:
        """Synchronous callback required by asyncpg - schedules async reload."""
        self._schedule_reload()

    def _schedule_reload(self) -> None:
        self._reload_generation += 1
        if self._reload_task is not None and not self._reload_task.done():
            return
        self._reload_task = asyncio.create_task(self._reload_until_current())
        self._reload_task.add_done_callback(self._log_reload_task_result)

    def _log_reload_task_result(self, task: asyncio.Task[None]) -> None:
        try:
            task.result()
        except Exception:
            logger.exception("PolicyEngine reload task failed unexpectedly")

    async def _reload_until_current(self) -> None:
        while self._applied_reload_generation < self._reload_generation:
            target_generation = self._reload_generation
            success = await self._reload()
            if not success:
                return
            self._applied_reload_generation = target_generation

    async def _reload(self) -> bool:
        """Reload all rules from PG (full reload)."""
        async with self._reload_lock:
            try:
                await self.load()
                logger.info("PolicyEngine reloaded via NOTIFY")
                return True
            except Exception:
                logger.exception("Failed to reload policy rules on NOTIFY")
                return False

    def evaluate(
        self,
        identity: IdentityContext,
        source_id: str,
        operation: str,
        tables: list[str] | None = None,
        columns: list[str] | None = None,
        classification_tags: list[str] | None = None,
        sql: str | None = None,
        deny_table_spellings: set[str] | None = None,
        deny_column_spellings: set[str] | None = None,
        identifier_case_sensitive: bool | None = None,
    ) -> PolicyDecision:
        """Evaluate all rules against a request. Default-deny.

        Rules are evaluated in priority order (highest first).
        First matching rule wins.
        If no rule matches, deny.

        `deny_column_spellings` does the same for a deny rule's `columns`
        condition, from the columns the statement was resolved to touch; allow
        rules never match on columns, as before.

        `deny_table_spellings` widens a deny rule's `tables` condition to every
        spelling of the request's tables - as written, bare, schema-qualified,
        legacy alias - so a deny on `sales.payroll` fires for `payroll` and the
        other way round. Allow rules match only the tables as written: first
        match wins, so a broader allow could pre-empt a lower-priority deny.
        """
        for rule in self._rules:
            is_deny = rule.actions.get("effect", "deny") != "allow"
            if self._matches(
                rule,
                identity,
                source_id,
                operation,
                tables,
                columns,
                classification_tags,
                deny_table_spellings if is_deny else None,
                deny_column_spellings if is_deny else None,
                identifier_case_sensitive,
            ):
                effect = rule.actions.get("effect", "deny")
                allowed = effect == "allow"
                redact_columns = rule.actions.get("redact_columns", [])
                rate_limit = _normalize_rate_limit(rule.actions.get("rate_limit"))
                write_risk_cap = _normalize_write_risk_cap(
                    rule.actions.get("write_risk_cap")
                    or rule.actions.get("max_write_risk")
                    or rule.actions.get("max_risk")
                )
                return PolicyDecision(
                    allowed=allowed,
                    rule_id=rule.id,
                    rule_name=rule.name,
                    redact_columns=redact_columns,
                    rate_limit=rate_limit,
                    write_risk_cap=write_risk_cap,
                    reason=f"Matched rule '{rule.name}' (id={rule.id}, effect={effect})",
                )

        return PolicyDecision(
            allowed=False,
            reason="No matching policy rule - default deny",
        )

    @staticmethod
    def _matches(
        rule: PolicyRule,
        identity: IdentityContext,
        source_id: str,
        operation: str,
        tables: list[str] | None,
        columns: list[str] | None,
        classification_tags: list[str] | None,
        table_spellings: set[str] | None = None,
        column_spellings: set[str] | None = None,
        identifier_case_sensitive: bool | None = None,
    ) -> bool:
        """Check whether a rule matches the given request context.

        A rule matches if ALL specified conditions match.
        If a condition key is missing or its value is empty/None, it matches everything.
        """
        cond = rule.conditions

        # source_ids
        source_ids = rule_source_ids(cond)
        if source_ids:
            if source_id not in source_ids:
                return False

        # roles are source-scoped role keys for the current source. Global
        # identity labels must use identity_roles so policy rules cannot
        # accidentally grant source access from legacy identity.roles.
        roles = cond.get("roles")
        if roles:
            source_role_matches = _authoritative_source_role_keys(identity, source_id)
            if not source_role_matches & set(roles):
                return False

        # identity_roles are compatibility/global identity labels. They are
        # useful for organization-level policy targeting but do not substitute
        # for source-role grants.
        identity_roles = cond.get("identity_roles") or cond.get("global_roles")
        if identity_roles:
            if not set(identity.roles) & set(identity_roles):
                return False

        # operation_types
        op_types = cond.get("operation_types")
        if op_types:
            if operation not in op_types:
                return False

        # Fabric comparison is supplied by trusted source catalog naming. None
        # preserves the legacy comparison used by every other connector.
        normalize = (
            (lambda value: str(value).strip())
            if identifier_case_sensitive
            else (lambda value: str(value).strip().lower())
        )
        if identifier_case_sensitive is not None:
            tables = [normalize(t) for t in tables or []]
            columns = [normalize(c) for c in columns or []]
            table_spellings = {normalize(t) for t in table_spellings or []}
            column_spellings = {normalize(c) for c in column_spellings or []}
        # tables
        rule_tables = cond.get("tables")
        if rule_tables:
            if identifier_case_sensitive is not None:
                rule_tables = [normalize(t) for t in rule_tables]
            if table_spellings:
                wanted = {normalize(table) for table in rule_tables}
                if not (wanted & table_spellings):
                    return False
            elif not tables or not (set(tables) & set(rule_tables)):
                return False

        # columns
        rule_columns = cond.get("columns")
        if rule_columns:
            if identifier_case_sensitive is not None:
                rule_columns = [normalize(c) for c in rule_columns]
            if column_spellings:
                # `*` marks columns that could not be determined: the query may
                # read the denied ones, so the deny applies.
                wanted = {normalize(column) for column in rule_columns}
                if "*" not in column_spellings and not (wanted & column_spellings):
                    return False
            elif not columns or not (set(columns) & set(rule_columns)):
                return False

        rule_classifications = cond.get("classification_tags") or cond.get("classifications")
        if rule_classifications:
            actual = set(classification_tags or [])
            if not actual or not (actual & {str(tag) for tag in rule_classifications}):
                return False

        return True


def rule_source_ids(conditions: dict[str, Any]) -> list[str]:
    """The sources a rule is limited to; empty means every source.

    `source_ids` wins; the singular `source_id` the console builder writes is
    read when it is absent. The admin reads this too, so a page listing the
    rules that apply to a source uses the engine's own test.
    """
    source_ids = conditions.get("source_ids")
    if not source_ids and conditions.get("source_id"):
        source_ids = [conditions["source_id"]]
    if isinstance(source_ids, str):
        source_ids = [source_ids]
    return [str(s) for s in source_ids or []]


def _authoritative_source_role_keys(identity: IdentityContext, source_id: str) -> set[str]:
    return {
        str(grant.get("role") or grant.get("role_key") or "")
        for grant in identity.effective_source_roles(source_id)
        if (grant.get("role") or grant.get("role_key"))
        and str(grant.get("authority") or "identity_source_role_grants") != "legacy_metadata"
    }


def _normalize_rate_limit(value: object) -> dict[str, int] | None:
    if value is None or value == "":
        return None
    if isinstance(value, int):
        return {"limit": value, "window_seconds": 60}
    if isinstance(value, dict):
        limit = (
            value.get("limit")
            or value.get("requests")
            or value.get("requests_per_minute")
            or value.get("max")
        )
        window = (
            value.get("window_seconds") or value.get("window") or value.get("period_seconds") or 60
        )
        try:
            return {"limit": int(limit), "window_seconds": int(window)}
        except (TypeError, ValueError):
            return None
    return None


def _normalize_write_risk_cap(value: object) -> str | None:
    if value is None or value == "":
        return None
    normalized = str(value).strip().lower()
    return normalized if normalized in {"low", "medium", "high"} else None
