"""Shared gateway governance pipeline.

The protocol adapters still own protocol-specific parsing and origin I/O, but
they should all enter this module for the common governance spine: identity
resolution, rate limits, policy decisions, and canonical audit emission.
"""

from __future__ import annotations

import inspect
import logging
import time
import uuid
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from interlock.core.source_roles import build_permission_request
from interlock.core.sql_columns import ColumnAccess, column_access
from interlock.core.sql_governance import (
    governance_inputs,
    legacy_naming,
    naming_for,
    resolve_table,
    table_spellings,
)
from interlock.errors import (
    AuditUnavailableError,
    CacheBarrierUnavailableError,
    WriteApprovalRequiredError,
)
from interlock.models import (
    AuditRecord,
    IdentityContext,
    PermissionRequest,
    PolicyDecision,
    RateLimitResult,
    RiskLevel,
    WriteClassification,
)

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class GatewayRequest:
    """Canonical request envelope used by protocol adapters."""

    protocol: str
    source_id: str
    operation: str
    identity: IdentityContext | None = None
    normalized_request: Any | None = None
    intent: str | None = None
    method: str | None = None
    sql: str | None = None
    path: str | None = None
    parameters: Mapping[str, Any] | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    tables: list[str] | None = None
    columns: list[str] | None = None
    # The SQL grammar this source speaks. Adapters set it from the registered
    # connector; unset means the default, which is what every caller got
    # before dialects existed.
    dialect: str | None = None


def _column_resources(access: ColumnAccess) -> tuple[list[str], dict[str, str]]:
    """The `schema.table.column` names a request carries, and its gaps.

    A table with a gap, or one a DELETE removes rows from, is carried whole
    (`schema.table.*`); a table touched without naming a column - COUNT(*) - is
    carried whole by `build_permission_request` on its own.
    """
    columns: list[str] = []
    for table, names in access.columns.items():
        if table in access.gaps or table in access.whole_table:
            columns.append(f"{table}.*")
        if table in access.gaps:
            continue
        columns.extend(f"{table}.{name}" for name in sorted(names))
    return columns, dict(access.gaps)


def _column_spellings(access: ColumnAccess) -> set[str]:
    """Every spelling a deny policy's `columns` condition may name a column by.

    `*` stands for columns that could not be determined: a deny rule on columns
    then matches, since the query may read them.
    """
    spellings: set[str] = set()
    for table, names in access.columns.items():
        bare_table = table.rsplit(".", 1)[-1]
        for name in names:
            spellings.update({name, f"{bare_table}.{name}", f"{table}.{name}"})
    if access.gaps:
        spellings.add("*")
    return spellings


def sql_gateway_request(
    sql: str,
    *,
    protocol: str,
    source_id: str,
    dialect: str,
    metadata: dict[str, Any] | None = None,
) -> GatewayRequest:
    """The request an SQL statement becomes, the way the MCP adapter builds it.

    Read or write is judged by the write classifier in the source's grammar;
    the tables are every statement's.
    """
    from interlock.core.sql_governance import derive_sql
    from interlock.core.write_classifier import WriteClassifier

    derivation = derive_sql(sql, source_id=source_id, dialect=dialect)
    operation = "write" if WriteClassifier(dialect=dialect).classify(sql) is not None else "read"
    return GatewayRequest(
        protocol=protocol,
        source_id=source_id,
        operation=operation,
        normalized_request=derivation.first,
        sql=sql,
        tables=derivation.tables or None,
        metadata=dict(metadata or {}),
        dialect=dialect,
    )


@dataclass(slots=True)
class GovernanceView:
    """What governance evaluates for one request."""

    operation: str
    tables: list[str] | None
    metadata: dict[str, Any]
    permission_request: PermissionRequest
    write_classification: WriteClassification | None
    deny_table_spellings: set[str] | None
    deny_column_spellings: set[str] | None = None
    # Output column -> base columns it derives from, for redact_columns.
    column_lineage: dict[str, set[str]] = field(default_factory=dict)


@dataclass(slots=True)
class GatewayDecision:
    """Decision produced before protocol adapters execute origin work."""

    allowed: bool
    status_code: int = 200
    reason: str = ""
    identity: IdentityContext | None = None
    policy_decision: PolicyDecision | None = None
    rate_limit_result: RateLimitResult | None = None
    cache_strategy: str | None = None
    write_risk: str | None = None
    write_classification: WriteClassification | None = None
    approval_id: int | None = None
    approval_state: str | None = None
    redaction_required: bool = False
    source_generation: int | None = None
    source_role_decision: Any | None = None
    audit_metadata: dict[str, Any] = field(default_factory=dict)
    # Output column -> the base columns it derives from, so `redact_columns`
    # follows `SELECT ssn AS x` to `ssn`.
    column_lineage: dict[str, set[str]] = field(default_factory=dict)
    identifier_case_sensitive: bool | None = None
    upstream_identity: dict[str, Any] | None = None


@dataclass(slots=True)
class GatewayResult:
    """Canonical result metadata adapters can return or audit."""

    status: str
    body: Any | None = None
    cache_hit: bool = False
    cache_tier: str | None = None
    redaction_stats: dict[str, Any] = field(default_factory=dict)
    audit_payload: dict[str, Any] = field(default_factory=dict)


class GatewayPipeline:
    """Shared identity/policy/rate/audit path for all gateway protocols."""

    def __init__(
        self,
        *,
        auth_manager: Any | None = None,
        policy_engine: Any | None = None,
        rate_limiter: Any | None = None,
        audit_logger: Any | None = None,
        write_classifier: Any | None = None,
        approval_queue: Any | None = None,
        source_role_evaluator: Any | None = None,
        cache_invalidator: Any | None = None,
        cache_barrier_strict: bool = False,
        sql_naming: Any | None = None,
    ) -> None:
        self._sql_naming = sql_naming
        self._auth = auth_manager
        self._policy = policy_engine
        self._rate_limiter = rate_limiter
        self._audit = audit_logger
        self._write_classifier = write_classifier
        self._approval_queue = approval_queue
        self._source_role_evaluator = source_role_evaluator
        self._cache_invalidator = cache_invalidator
        self._cache_barrier_strict = cache_barrier_strict

    @classmethod
    def from_state(cls, state: Any | None) -> "GatewayPipeline":
        """Build a pipeline from a Starlette/FastAPI app.state object."""
        return cls(
            auth_manager=getattr(state, "auth_manager", None) if state else None,
            policy_engine=getattr(state, "policy_engine", None) if state else None,
            rate_limiter=getattr(state, "rate_limiter", None) if state else None,
            audit_logger=getattr(state, "audit_logger", None) if state else None,
            write_classifier=getattr(state, "write_classifier", None) if state else None,
            approval_queue=getattr(state, "approval_queue", None) if state else None,
            source_role_evaluator=(
                getattr(state, "source_role_evaluator", None) if state else None
            ),
            cache_invalidator=getattr(state, "cache_invalidator", None) if state else None,
            cache_barrier_strict=bool(
                getattr(state, "cache_barrier_strict", False) if state else False
            ),
            sql_naming=getattr(state, "sql_naming_resolver", None) if state else None,
        )

    async def preflight(
        self,
        request: GatewayRequest,
        *,
        bearer_token: str | None = None,
        require_auth: bool | None = None,
        approval_accepted: bool = False,
    ) -> GatewayDecision:
        """Resolve identity, rate limit, and evaluate policy."""
        identity = request.identity

        if identity is None and self._auth is not None:
            if not bearer_token:
                return GatewayDecision(
                    allowed=False,
                    status_code=401,
                    reason="Missing or invalid Authorization header",
                )
            try:
                identity = await self._auth.authenticate(bearer_token)
            except Exception:
                return GatewayDecision(
                    allowed=False,
                    status_code=401,
                    reason="Invalid API key",
                )
        elif require_auth and identity is None:
            return GatewayDecision(
                allowed=False,
                status_code=401,
                reason="Authentication required",
            )

        rate_result = None

        view = await self.governance_view(
            request, identity_id=identity.identity_id if identity is not None else None
        )
        write_classification = view.write_classification
        governance_operation = view.operation
        governance_tables = view.tables
        governance_metadata = view.metadata

        source_role_decision = None
        permission_request = None
        if identity is not None and self._source_role_evaluator is not None:
            permission_request = view.permission_request
            source_role_decision = await self._source_role_evaluator.evaluate(permission_request)
            if not source_role_decision.allowed:
                return GatewayDecision(
                    allowed=False,
                    status_code=403,
                    reason=f"Source role denied: {source_role_decision.reason}",
                    identity=identity,
                    rate_limit_result=rate_result,
                    source_role_decision=source_role_decision,
                    audit_metadata={
                        **_governance_metadata(
                            source_role_decision=source_role_decision,
                            permission_request=permission_request,
                            policy_decision=None,
                            identity=identity,
                            source_id=request.source_id,
                        ),
                        "permission_request": permission_request.model_dump(),
                        "rate_limit": rate_result.model_dump() if rate_result else None,
                    },
                )

        if identity is not None and self._policy is not None:
            policy_decision = self._policy.evaluate(
                identity=identity,
                source_id=request.source_id,
                operation=governance_operation,
                tables=governance_tables,
                columns=request.columns,
                classification_tags=_classification_tags(governance_metadata),
                sql=request.sql,
                deny_table_spellings=view.deny_table_spellings,
                deny_column_spellings=view.deny_column_spellings,
                identifier_case_sensitive=view.metadata.get("fabric_identifier_case_sensitive"),
            )
            if not policy_decision.allowed:
                return GatewayDecision(
                    allowed=False,
                    status_code=403,
                    reason=f"Policy denied: {policy_decision.reason}",
                    identity=identity,
                    policy_decision=policy_decision,
                    rate_limit_result=rate_result,
                    source_role_decision=source_role_decision,
                    audit_metadata={
                        **_governance_metadata(
                            source_role_decision=source_role_decision,
                            permission_request=permission_request,
                            policy_decision=policy_decision,
                            identity=identity,
                            source_id=request.source_id,
                        ),
                    },
                )
        else:
            policy_decision = None

        if identity is not None and self._rate_limiter is not None:
            rate_result = await self._check_rate_limit(
                identity,
                request,
                policy_decision=policy_decision,
            )
            if not rate_result.allowed:
                return GatewayDecision(
                    allowed=False,
                    status_code=429,
                    reason="Rate limit exceeded",
                    identity=identity,
                    policy_decision=policy_decision,
                    rate_limit_result=rate_result,
                    source_role_decision=source_role_decision,
                    audit_metadata={
                        **_governance_metadata(
                            source_role_decision=source_role_decision,
                            permission_request=permission_request,
                            policy_decision=policy_decision,
                            identity=identity,
                            source_id=request.source_id,
                        ),
                        "rate_limit": rate_result.model_dump(),
                    },
                )

        write_decision = await self._check_write_safety(
            request,
            identity,
            classification=write_classification,
            policy_decision=policy_decision,
            approval_accepted=approval_accepted,
        )
        if write_decision is not None:
            write_decision.identity = identity
            write_decision.policy_decision = policy_decision
            write_decision.rate_limit_result = rate_result
            write_decision.source_role_decision = source_role_decision
            write_decision.audit_metadata.update(
                {
                    **_governance_metadata(
                        source_role_decision=source_role_decision,
                        permission_request=permission_request,
                        policy_decision=policy_decision,
                        identity=identity,
                        source_id=request.source_id,
                    ),
                    "rate_limit": rate_result.model_dump() if rate_result else None,
                }
            )
            return write_decision

        decision = GatewayDecision(
            allowed=True,
            column_lineage=view.column_lineage,
            identifier_case_sensitive=view.metadata.get("fabric_identifier_case_sensitive"),
            upstream_identity=(
                request.metadata.get("upstream_identity")
                if request.metadata.get("connector_key") == "fabric_sql"
                else None
            ),
            identity=identity,
            policy_decision=policy_decision,
            rate_limit_result=rate_result,
            source_role_decision=source_role_decision,
            write_risk=_risk_value(write_classification) if write_classification else None,
            write_classification=write_classification,
            redaction_required=True,
            audit_metadata={
                **_governance_metadata(
                    source_role_decision=source_role_decision,
                    permission_request=permission_request,
                    policy_decision=policy_decision,
                    identity=identity,
                    source_id=request.source_id,
                ),
                "rate_limit": rate_result.model_dump() if rate_result else None,
            },
        )
        if _is_governed_write(request, write_classification):
            decision = await self._attach_write_barrier(request, decision)
        return decision

    async def source_generation(self, source_id: str) -> int:
        """Return the current source generation for deterministic read keys."""
        return await current_cache_source_generation(
            self._cache_invalidator,
            source_id,
            strict=self._cache_barrier_strict,
        )

    async def _attach_write_barrier(
        self,
        request: GatewayRequest,
        decision: GatewayDecision,
    ) -> GatewayDecision:
        try:
            source_generation = await advance_cache_write_barrier(
                self._cache_invalidator,
                request.source_id,
                strict=self._cache_barrier_strict,
            )
        except CacheBarrierUnavailableError as exc:
            return GatewayDecision(
                allowed=False,
                status_code=503,
                reason=str(exc),
                identity=decision.identity,
                policy_decision=decision.policy_decision,
                rate_limit_result=decision.rate_limit_result,
                cache_strategy=decision.cache_strategy,
                write_risk=decision.write_risk,
                write_classification=decision.write_classification,
                redaction_required=decision.redaction_required,
                source_role_decision=decision.source_role_decision,
                audit_metadata={
                    **decision.audit_metadata,
                    "error_type": CacheBarrierUnavailableError.__name__,
                },
            )
        if source_generation is not None:
            decision.source_generation = source_generation
            decision.audit_metadata["source_generation"] = source_generation
        return decision

    async def _check_write_safety(
        self,
        request: GatewayRequest,
        identity: IdentityContext | None,
        *,
        classification: WriteClassification | None = None,
        policy_decision: PolicyDecision | None = None,
        approval_accepted: bool = False,
    ) -> GatewayDecision | None:
        if request.operation != "write" and classification is None:
            return None

        if classification is None:
            return None

        if classification.blocked:
            return GatewayDecision(
                allowed=False,
                status_code=403,
                reason=f"{classification.operation_type} blocks not permitted",
                write_risk=_risk_value(classification),
                write_classification=classification,
                audit_metadata={"write_classification": _write_metadata(classification)},
            )

        risk_level = _risk_level(classification)
        risk_cap = _policy_write_risk_cap(policy_decision)
        if risk_cap is not None and _risk_rank(risk_level) > _risk_rank(risk_cap):
            return GatewayDecision(
                allowed=False,
                status_code=403,
                reason=(
                    f"Policy write risk cap exceeded: {risk_level.value} "
                    f"exceeds {risk_cap.value}"
                ),
                write_risk=risk_level.value,
                write_classification=classification,
                audit_metadata={
                    "write_classification": _write_metadata(classification),
                    "policy_write_risk_cap": risk_cap.value,
                },
            )

        if identity is None or not request.source_id:
            should_require_identity = (
                request.metadata.get("mode") == "extended"
                or self._auth is not None
                or self._approval_queue is not None
            )
            if not should_require_identity:
                return None
            return GatewayDecision(
                allowed=False,
                status_code=403,
                reason="Write blocked: identity/source unresolved",
                write_risk=risk_level.value,
                write_classification=classification,
                audit_metadata={"write_classification": _write_metadata(classification)},
            )

        if approval_accepted or risk_level not in (RiskLevel.HIGH, RiskLevel.MEDIUM):
            return None

        if self._approval_queue is None:
            return GatewayDecision(
                allowed=False,
                status_code=403,
                reason=f"{risk_level.value.title()} risk write requires approval",
                write_risk=risk_level.value,
                write_classification=classification,
                approval_state="required",
                audit_metadata={"write_classification": _write_metadata(classification)},
            )

        metadata = {
            "protocol": request.protocol,
            "method": request.method,
            "path": request.path,
            "intent": request.intent,
            "parameters": dict(request.parameters or {}),
            "identity_id": identity.identity_id,
            "identity_name": getattr(identity, "name", None) or getattr(identity, "user", None),
            "identity_mapped_pg_role": identity.mapped_pg_role,
            "identity_grants_version": (
                getattr(identity, "metadata", {}).get("grants_version")
                if isinstance(getattr(identity, "metadata", {}), dict)
                else None
            ),
            "normalized_operation": classification.operation_type,
            **request.metadata,
        }
        if request.metadata.get("connector_key") == "fabric_sql":
            metadata["parameters"] = (request.parameters or {}).get("parameters") or []
        try:
            submitted = await self._approval_queue.submit(
                identity_id=identity.identity_id,
                source_id=request.source_id,
                sql_text=request.sql or _synthetic_write_text(request),
                risk_level=risk_level,
                metadata=_drop_none(metadata),
            )
            approval_id = int(submitted)
        except WriteApprovalRequiredError as exc:
            approval_id = exc.approval_id

        return GatewayDecision(
            allowed=False,
            status_code=202,
            reason=f"Write queued for approval, ID: {approval_id}",
            identity=identity,
            write_risk=risk_level.value,
            write_classification=classification,
            approval_id=approval_id,
            approval_state="pending",
            audit_metadata={
                "approval_id": approval_id,
                "approval_state": "pending",
                "write_classification": _write_metadata(classification),
            },
        )

    async def governance_view(
        self, request: GatewayRequest, *, identity_id: int | None
    ) -> GovernanceView:
        """Everything governance evaluates for a request, before evaluating it.

        `preflight` decides from this, and the console's dry-runs call it
        directly, so a dry-run explains the decision the gateway would make
        rather than an approximation of it.
        """
        write_classification = self._classify_write(request)
        operation, tables, metadata = governance_inputs(
            operation=request.operation,
            tables=request.tables,
            metadata=request.metadata,
            sql=request.sql,
            write_classification=write_classification,
        )
        naming = await self._naming_for(request)
        if naming is not None and naming.connector_key == "fabric_sql":
            metadata["fabric_identifier_case_sensitive"] = naming.identifier_case_sensitive
        else:
            metadata.pop("fabric_identifier_case_sensitive", None)
        columns = request.columns
        column_gaps: dict[str, str] = {}
        lineage: dict[str, set[str]] = {}
        deny_columns: set[str] | None = None
        scope_refusals: list[str] = []
        if request.sql and naming is not None and not request.columns:
            access = column_access(
                request.sql,
                dialect=naming.dialect,
                resolve=lambda written: resolve_table(written, naming).canonical,
                catalog=naming.columns,
                case_sensitive=naming.connector_key == "fabric_sql"
                and naming.identifier_case_sensitive is not False,
                native_identifiers=naming.connector_key == "fabric_sql",
            )
            scope_refusals = access.refusals
            columns, column_gaps = _column_resources(access)
            lineage = access.lineage
            deny_columns = _column_spellings(access)
        if (
            naming is not None
            and naming.connector_key == "fabric_sql"
            and write_classification is not None
        ):
            for table in tables or []:
                resolved = resolve_table(table, naming)
                pair = tuple(resolved.canonical.split("."))
                if (
                    len(pair) != 2
                    or (naming.relation_types or {}).get((pair[0], pair[1])) != "table"
                ):
                    scope_refusals.append(
                        "Fabric writes require a catalog-verified table target; views and unknown relation types are unsupported"
                    )
        permission_request = build_permission_request(
            protocol=request.protocol,
            source_id=request.source_id,
            identity_id=identity_id,
            operation=operation,
            method=request.method,
            path=request.path,
            tables=tables,
            columns=columns,
            normalized_request=request.normalized_request,
            risk_level=_risk_value(write_classification) if write_classification else None,
            metadata=metadata,
            naming=naming,
            column_gaps=column_gaps,
        )
        permission_request.naming_refusals.extend(scope_refusals)
        spellings = (
            table_spellings([resolve_table(table, naming or legacy_naming()) for table in tables])
            if tables
            else None
        )
        return GovernanceView(
            operation=operation,
            tables=tables,
            metadata=metadata,
            permission_request=permission_request,
            write_classification=write_classification,
            deny_table_spellings=spellings,
            deny_column_spellings=deny_columns,
            column_lineage=lineage,
        )

    async def _naming_for(self, request: GatewayRequest) -> Any | None:
        """How this source's database resolves table names, when it speaks SQL."""
        fallback = (
            naming_for("fabric_sql")
            if request.metadata.get("connector_key") == "fabric_sql"
            else None
        )
        if self._sql_naming is None or not (request.sql or request.tables):
            return fallback
        try:
            return await self._sql_naming.naming_for_source(request.source_id) or fallback
        except Exception:
            logger.warning(
                "SQL naming unavailable for %s; using connector fallback",
                request.source_id,
                exc_info=True,
            )
            return fallback

    def _classify_write(self, request: GatewayRequest) -> WriteClassification | None:
        if request.sql and self._write_classifier is not None:
            return self._write_classifier.classify(request.sql, request.dialect)

        method = (request.method or "").upper()
        if method in {"DELETE"}:
            return WriteClassification(
                risk_level=RiskLevel.HIGH,
                operation_type=method,
                reason="HTTP DELETE is destructive",
            )
        if method in {"PUT", "PATCH"}:
            return WriteClassification(
                risk_level=RiskLevel.MEDIUM,
                operation_type=method,
                reason="HTTP mutation requires approval",
            )
        if method == "POST":
            return WriteClassification(
                risk_level=RiskLevel.LOW,
                operation_type=method,
                reason="HTTP create/action request",
            )
        return None

    async def audit(
        self,
        request: GatewayRequest,
        *,
        decision: GatewayDecision | None = None,
        result: GatewayResult | None = None,
        fingerprint: str | None = None,
        cache_hit: bool = False,
        cache_tier: str | None = None,
        latency_ms: float | None = None,
        status: str = "success",
        error_message: str | None = None,
        pii_detected: bool = False,
        pii_types: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """Emit a canonical audit event, preserving strict durability failures."""
        if self._audit is None:
            return

        identity = (
            decision.identity
            if decision is not None and decision.identity is not None
            else request.identity
        )
        result_metadata = result.audit_payload if result else {}
        merged_metadata = {
            "protocol": request.protocol,
            "method": request.method,
            "path": request.path,
            "intent": request.intent,
            **request.metadata,
            **(decision.audit_metadata if decision else {}),
            **result_metadata,
            **(metadata or {}),
        }
        merged_metadata.setdefault(
            "correlation_id",
            request.metadata.get("correlation_id") or str(uuid.uuid4()),
        )
        audit_operation = (
            "write"
            if decision is not None and decision.write_classification is not None
            else request.operation
        )
        normalized_operation = (
            getattr(decision.write_classification, "operation_type", None)
            if decision is not None and decision.write_classification is not None
            else request.operation
        )
        redaction_stats = result.redaction_stats if result else None
        try:
            await self._audit.log(
                AuditRecord(
                    identity_id=getattr(identity, "identity_id", None),
                    source_id=request.source_id,
                    operation=audit_operation,
                    sql_fingerprint=fingerprint,
                    cache_hit=cache_hit or (result.cache_hit if result else False),
                    cache_tier=cache_tier or (result.cache_tier if result else None),
                    latency_ms=latency_ms,
                    pii_detected=pii_detected,
                    pii_types=pii_types or [],
                    risk_level=(
                        decision.write_risk
                        if decision is not None and decision.write_risk is not None
                        else merged_metadata.get("risk_level")
                    ),
                    status=status,
                    error_message=error_message,
                    request_metadata=_drop_none(merged_metadata),
                    protocol=request.protocol,
                    route=request.path or merged_metadata.get("route"),
                    normalized_operation=(
                        str(normalized_operation) if normalized_operation is not None else None
                    ),
                    intent=request.intent,
                    upstream_target=merged_metadata.get("upstream_target")
                    or merged_metadata.get("upstream_url"),
                    policy_decision=merged_metadata.get("policy_decision"),
                    approval_id=(
                        decision.approval_id
                        if decision is not None and decision.approval_id is not None
                        else merged_metadata.get("approval_id")
                    ),
                    approval_status=(
                        decision.approval_state
                        if decision is not None and decision.approval_state is not None
                        else merged_metadata.get("approval_status")
                        or merged_metadata.get("approval_state")
                    ),
                    redaction_stats=redaction_stats or merged_metadata.get("redaction_stats"),
                    cost_metadata=merged_metadata.get("cost_metadata"),
                )
            )
        except AuditUnavailableError:
            logger.error("Strict Gateway audit delivery is unavailable", exc_info=True)
            raise
        except Exception:
            logger.debug("Gateway audit emit failed", exc_info=True)

    async def _check_rate_limit(
        self,
        identity: IdentityContext,
        request: GatewayRequest,
        *,
        policy_decision: PolicyDecision | None = None,
    ) -> RateLimitResult:
        policy_limits = _policy_rate_limits(identity, request, policy_decision)
        check_multi = getattr(self._rate_limiter, "check_multi", None)
        check_multi_known = "check_multi" in getattr(
            type(self._rate_limiter), "__dict__", {}
        ) or "check_multi" in getattr(self._rate_limiter, "__dict__", {})
        if check_multi is not None and check_multi_known:
            result = check_multi(
                identity_id=identity.identity_id,
                source_id=request.source_id,
                session_id=identity.session_id,
                limits=policy_limits,
            )
            if inspect.isawaitable(result):
                return await result
            if isinstance(result, RateLimitResult):
                return result
        if policy_limits:
            key, (limit, window_seconds) = next(iter(policy_limits.items()))
        else:
            key, limit, window_seconds = f"user:{identity.identity_id}", 100, 60
        return await self._rate_limiter.check(
            key,
            limit=limit,
            window_seconds=window_seconds,
        )


def _policy_metadata(decision: PolicyDecision) -> dict[str, Any]:
    return {
        "allowed": decision.allowed,
        "rule_id": decision.rule_id,
        "rule_name": decision.rule_name,
        "reason": decision.reason,
        "redact_columns": decision.redact_columns,
        "rate_limit": decision.rate_limit,
        "write_risk_cap": decision.write_risk_cap,
    }


async def advance_cache_write_barrier(
    cache_invalidator: Any | None,
    source_id: str,
    *,
    strict: bool = False,
) -> int | None:
    """Advance the source generation before a governed write.

    In strict mode the increment must happen on the shared Redis-backed
    barrier. In non-strict mode, the invalidator's local fallback is allowed.
    """
    if not source_id or cache_invalidator is None:
        if strict:
            raise CacheBarrierUnavailableError("Cache write barrier unavailable")
        return None

    if strict:
        return await _advance_shared_barrier(cache_invalidator, source_id)

    prepare = _explicit_attr(cache_invalidator, "prepare_source_write")
    if prepare is None:
        return None
    try:
        token = prepare(source_id)
        if inspect.isawaitable(token):
            token = await token
        return _coerce_source_generation(token)
    except Exception:
        logger.debug(
            "Cache write barrier advance failed source=%s; continuing non-strict",
            source_id,
            exc_info=True,
        )
        return None


async def current_cache_source_generation(
    cache_invalidator: Any | None,
    source_id: str,
    *,
    strict: bool = False,
) -> int:
    """Return the current source generation, defaulting closed to zero."""
    if not source_id or cache_invalidator is None:
        return 0
    current = _explicit_attr(
        cache_invalidator,
        "shared_source_generation" if strict else "source_generation",
    )
    if current is None:
        if strict:
            raise CacheBarrierUnavailableError("Cache write barrier unavailable")
        return 0
    try:
        generation = current(source_id)
        if inspect.isawaitable(generation):
            generation = await generation
        return max(0, int(generation))
    except Exception as exc:
        if strict:
            raise CacheBarrierUnavailableError("Cache write barrier unavailable") from exc
        logger.debug(
            "Cache source generation read failed source=%s; using generation 0",
            source_id,
            exc_info=True,
        )
        return 0


async def _advance_shared_barrier(cache_invalidator: Any, source_id: str) -> int:
    prepare = _explicit_attr(cache_invalidator, "prepare_shared_source_write")
    if prepare is None:
        raise CacheBarrierUnavailableError("Cache write barrier unavailable")
    try:
        token = prepare(source_id)
        if inspect.isawaitable(token):
            token = await token
        generation = _coerce_source_generation(token)
        if generation is None:
            raise CacheBarrierUnavailableError("Cache write barrier unavailable")
        return generation
    except Exception as exc:
        raise CacheBarrierUnavailableError("Cache write barrier unavailable") from exc


def _coerce_source_generation(token: Any) -> int | None:
    if token is None:
        return None
    if isinstance(token, int):
        return max(0, token)
    generation = getattr(token, "generation", None)
    if generation is None:
        return None
    return max(0, int(generation))


def _explicit_attr(obj: Any, name: str) -> Any | None:
    """Return attrs that are real or explicitly assigned, not mock fabrications."""
    if obj is None:
        return None
    if name in getattr(type(obj), "__dict__", {}):
        return getattr(obj, name)
    if name in getattr(obj, "__dict__", {}):
        return getattr(obj, name)
    return None


def _is_governed_write(
    request: GatewayRequest,
    classification: WriteClassification | None,
) -> bool:
    return request.operation == "write" or classification is not None


def _policy_rate_limits(
    identity: IdentityContext,
    request: GatewayRequest,
    policy_decision: PolicyDecision | None,
) -> dict[str, tuple[int, int]] | None:
    if policy_decision is None or not policy_decision.rate_limit:
        return None
    raw = policy_decision.rate_limit
    if isinstance(raw, int):
        limit, window_seconds = raw, 60
    else:
        try:
            limit = int(raw.get("limit", 0))
            window_seconds = int(raw.get("window_seconds", raw.get("window", 60)))
        except (TypeError, ValueError, AttributeError):
            return None
    if limit <= 0 or window_seconds <= 0:
        return None
    return {
        f"ratelimit:policy:{request.source_id}:user:{identity.identity_id}": (
            limit,
            window_seconds,
        )
    }


def _policy_write_risk_cap(policy_decision: PolicyDecision | None) -> RiskLevel | None:
    if policy_decision is None or not policy_decision.write_risk_cap:
        return None
    try:
        return RiskLevel(str(policy_decision.write_risk_cap).lower())
    except ValueError:
        return None


def _classification_tags(metadata: Mapping[str, Any]) -> list[str]:
    tags: list[str] = []
    raw_tags = metadata.get("classification_tags") or metadata.get("classifications")
    if isinstance(raw_tags, str):
        tags.extend(tag.strip() for tag in raw_tags.split(",") if tag.strip())
    elif isinstance(raw_tags, list | tuple | set):
        tags.extend(str(tag) for tag in raw_tags if str(tag))
    single = metadata.get("classification")
    if single:
        tags.append(str(single))
    return sorted(set(tags))


def _source_role_metadata(decision: Any) -> dict[str, Any]:
    return {
        "allowed": bool(decision.allowed),
        "explicit_deny": bool(decision.explicit_deny),
        "matched_role_ids": list(decision.matched_role_ids),
        "matched_permission_ids": list(decision.matched_permission_ids),
        "missing_permissions": list(decision.missing_permissions),
        "reason": decision.reason,
        "explanation": dict(decision.explanation or {}),
    }


def _governance_metadata(
    *,
    source_role_decision: Any | None,
    permission_request: Any | None,
    policy_decision: PolicyDecision | None,
    identity: IdentityContext | None,
    source_id: str,
) -> dict[str, Any]:
    source_role = _source_role_metadata(source_role_decision) if source_role_decision else None
    policy = _policy_metadata(policy_decision) if policy_decision else None
    legacy_role_keys = _legacy_source_role_keys(identity, source_id)
    return {
        "source_role_decision": source_role,
        "permission_request": (permission_request.model_dump() if permission_request else None),
        "policy_decision": policy,
        "matched_role_ids": (source_role.get("matched_role_ids") if source_role else []),
        "matched_permission_ids": (
            source_role.get("matched_permission_ids") if source_role else []
        ),
        "matched_policy_rule_ids": (
            [policy_decision.rule_id] if policy_decision and policy_decision.rule_id else []
        ),
        "missing_permissions": (source_role.get("missing_permissions") if source_role else []),
        "identity_grants_version": (
            getattr(identity, "grants_version", None) if identity else None
        ),
        "legacy_role_match": bool(legacy_role_keys),
        "legacy_role_keys": legacy_role_keys,
    }


def _legacy_source_role_keys(identity: IdentityContext | None, source_id: str) -> list[str]:
    if identity is None:
        return []
    keys = {
        str(grant.get("role") or grant.get("role_key") or "")
        for grant in identity.effective_source_roles(source_id)
        if str(grant.get("authority") or "") == "legacy_metadata"
        and (grant.get("role") or grant.get("role_key"))
    }
    return sorted(keys)


def _write_metadata(classification: WriteClassification) -> dict[str, Any]:
    return {
        "risk_level": _risk_value(classification),
        "operation_type": getattr(classification, "operation_type", "UNKNOWN"),
        "tables": list(getattr(classification, "tables", []) or []),
        "reason": getattr(classification, "reason", ""),
        "blocked": bool(getattr(classification, "blocked", False)),
        "has_where": getattr(classification, "has_where", None),
    }


def _risk_level(classification: WriteClassification) -> RiskLevel:
    risk = getattr(classification, "risk_level", RiskLevel.HIGH)
    if isinstance(risk, RiskLevel):
        return risk
    try:
        return RiskLevel(str(risk))
    except ValueError:
        return RiskLevel.HIGH


def _risk_value(classification: WriteClassification) -> str:
    return _risk_level(classification).value


def _risk_rank(risk: RiskLevel) -> int:
    return {RiskLevel.LOW: 1, RiskLevel.MEDIUM: 2, RiskLevel.HIGH: 3}[risk]


def _synthetic_write_text(request: GatewayRequest) -> str:
    return " ".join(
        part
        for part in (
            request.protocol.upper(),
            request.method,
            request.source_id,
            request.path,
        )
        if part
    )


def _drop_none(value: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in value.items() if v is not None}


def bearer_token_from_headers(headers: Mapping[str, str]) -> str | None:
    header = headers.get("authorization") or headers.get("Authorization") or ""
    if not header.startswith("Bearer "):
        return None
    return header[7:]


def now_ms(started: float) -> float:
    return (time.monotonic() - started) * 1000
