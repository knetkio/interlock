"""Shared data models used across InterLock services."""

from __future__ import annotations

import enum
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

# -- Identity & Auth --


class AgentType(str, enum.Enum):
    CLAUDE_CODE = "claude_code"
    CODEX = "codex"
    COPILOT = "copilot"
    CUSTOM = "custom"


class IdentityContext(BaseModel):
    """Identity resolved from API key during auth."""

    identity_id: int
    user: str
    agent_type: AgentType
    team: str | None = None
    roles: list[str] = Field(default_factory=list)
    source_roles: list[dict[str, Any]] = Field(default_factory=list)
    mapped_pg_role: str | None = None
    session_id: str | None = None
    grants_version: str | None = None
    auth_method: str = "api_key"

    def effective_source_roles(self, source_id: str) -> list[dict[str, Any]]:
        """Return active source-role grants scoped to a source."""
        return [
            grant for grant in self.source_roles if str(grant.get("source_id") or "") == source_id
        ]

    def effective_source_role_keys(self, source_id: str) -> set[str]:
        """Return role keys granted on a source."""
        return {
            str(grant.get("role") or grant.get("role_key") or "")
            for grant in self.effective_source_roles(source_id)
            if grant.get("role") or grant.get("role_key")
        }


# -- Data source --


class DataSourceType(str, enum.Enum):
    POSTGRESQL = "postgresql"
    MYSQL = "mysql"
    HTTP = "http"
    S3 = "s3"
    SAAS = "saas"
    DATABASE = "database"
    WAREHOUSE = "warehouse"
    OBJECT_STORAGE = "object_storage"
    SEARCH = "search"
    COLLABORATION = "collaboration"


class DataSourceConfig(BaseModel):
    """Configuration for a registered data source."""

    source_id: str
    name: str
    source_type: DataSourceType
    connection_config: dict[str, Any] = Field(default_factory=dict)
    cache_strategy: str = "deterministic_first"
    enabled: bool = True
    metadata: dict[str, Any] = Field(default_factory=dict)

    @property
    def connector_key(self) -> str:
        return str(
            self.metadata.get("connector_key")
            or self.metadata.get("provider")
            or self.source_type.value
        )

    @property
    def connector_family(self) -> str:
        return str(self.metadata.get("connector_family") or self.source_type.value)

    @property
    def connection_string(self) -> str | None:
        return self.connection_config.get("connection_string")

    @property
    def host(self) -> str | None:
        return self.connection_config.get("host")

    @property
    def port(self) -> int | None:
        return self.connection_config.get("port")

    @property
    def database(self) -> str | None:
        return self.connection_config.get("database")

    @property
    def base_url(self) -> str | None:
        return self.connection_config.get("base_url")

    @property
    def bucket(self) -> str | None:
        return self.connection_config.get("bucket")


# -- Cache --


class CacheResult(BaseModel):
    """Result from a cache lookup."""

    hit: bool
    data: bytes | None = None
    tier: str | None = None  # "l1", "l2", "semantic"
    confidence: float | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class CacheStrategyType(str, enum.Enum):
    DETERMINISTIC_FIRST = "deterministic_first"
    SEMANTIC_FIRST = "semantic_first"
    SEMANTIC_ONLY = "semantic_only"
    DETERMINISTIC_ONLY = "deterministic_only"
    BYPASS = "bypass"


# -- Audit --


class AuditRecord(BaseModel):
    """Single audit log entry."""

    identity_id: int | None = None
    source_id: str | None = None
    operation: str  # "read", "write", "discovery"
    protocol: str | None = None
    route: str | None = None
    normalized_operation: str | None = None
    intent: str | None = None
    upstream_target: str | None = None
    policy_decision: dict[str, Any] | None = None
    approval_id: int | None = None
    approval_status: str | None = None
    redaction_stats: dict[str, Any] | None = None
    cost_metadata: dict[str, Any] | None = None
    sql_fingerprint: str | None = None
    cache_hit: bool = False
    cache_tier: str | None = None
    latency_ms: float | None = None
    pii_detected: bool = False
    pii_types: list[str] = Field(default_factory=list)
    risk_level: str | None = None
    status: str = "success"  # "success", "denied", "error", "queued"
    error_message: str | None = None
    request_metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime | None = None


# -- SQL normalization --


class NormalizedQuery(BaseModel):
    """Result of SQL normalization."""

    original_sql: str
    normalized_sql: str | None = None
    fingerprint: str
    parameters: list[Any] = Field(default_factory=list)
    tables: list[str] = Field(default_factory=list)
    operation: str | None = None  # SELECT, INSERT, UPDATE, DELETE, etc.
    parse_error: bool = False


# -- Write safety --


class RiskLevel(str, enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class WriteClassification(BaseModel):
    """Result of write risk classification."""

    risk_level: RiskLevel
    operation_type: str  # INSERT, UPDATE, DELETE, DROP, TRUNCATE, etc.
    tables: list[str] = Field(default_factory=list)
    reason: str = ""
    blocked: bool = False  # True for EXECUTE/DO blocks
    has_where: bool | None = None


class ApprovalStatus(str, enum.Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"
    EXECUTED = "executed"
    FAILED = "failed"


# -- Health --


class HealthStatus(BaseModel):
    """Health check result for a data source."""

    source_id: str
    healthy: bool
    latency_ms: float | None = None
    error: str | None = None
    checked_at: datetime | None = None


# -- Rate limiting --


class RateLimitResult(BaseModel):
    """Result from a rate limit check."""

    allowed: bool
    remaining: int
    limit: int
    reset_at: float  # Unix timestamp when the current window resets
    dimension: str = ""  # which dimension triggered denial


# -- PII detection --


class PIIMatch(BaseModel):
    """A single PII match found by the scanner."""

    entity_type: str  # "SSN", "CREDIT_CARD", "EMAIL", etc.
    start: int
    end: int
    text: str


# -- Policy / RBAC --


class PolicyRule(BaseModel):
    """A single RBAC policy rule loaded from the policy_rules table."""

    id: int
    name: str
    priority: int = 0
    conditions: dict  # {"source_ids": [...], "roles": [...], "operation_types": [...], "tables": [...], "columns": [...]}
    actions: dict  # {"effect": "allow"|"deny", "redact_columns": [...], "rate_limit": {...}}
    enabled: bool = True


class PolicyDecision(BaseModel):
    """Result of evaluating policy rules against a request."""

    allowed: bool
    rule_id: int | None = None
    rule_name: str | None = None
    redact_columns: list[str] = Field(default_factory=list)
    rate_limit: dict[str, Any] | int | None = None
    write_risk_cap: str | None = None
    reason: str = ""


class PermissionRequest(BaseModel):
    """Canonical source-role permission request."""

    protocol: str
    source_id: str
    identity_id: int | None = None
    action: str
    resource_type: str | None = None
    resources: list[str] = Field(default_factory=list)
    operation: str | None = None
    method: str | None = None
    path: str | None = None
    schemas: list[str] = Field(default_factory=list)
    tables: list[str] = Field(default_factory=list)
    columns: list[str] = Field(default_factory=list)
    risk_level: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    # Other spellings of a resource, keyed by the resource. `aliases` are
    # checked by allow and deny statements alike (legacy `public.` names on
    # MySQL and Snowflake); `shadows` only by deny statements (schemas earlier
    # on a PostgreSQL search path, which a stale catalog could miss).
    resource_variants: dict[str, dict[str, list[str]]] = Field(default_factory=dict)
    # Table references governance refuses outright, such as a Snowflake name in
    # another database. Any entry denies the request.
    naming_refusals: list[str] = Field(default_factory=list)
    # True when every table was found in the source catalog; False when any
    # name fell back to the configured default; None for non-SQL requests.
    naming_resolved: bool | None = None
    # Tables whose columns could not be determined, with the reason. Their
    # resource is the whole table; where column-level rules apply to one, the
    # request is refused rather than evaluated on a guess.
    column_gaps: dict[str, str] = Field(default_factory=dict)
    resource_case_sensitive: bool = False


class SourceRoleDecision(BaseModel):
    """IAM-style source-role evaluation result."""

    allowed: bool
    explicit_deny: bool = False
    matched_role_ids: list[int] = Field(default_factory=list)
    matched_permission_ids: list[int] = Field(default_factory=list)
    missing_permissions: list[dict[str, Any]] = Field(default_factory=list)
    reason: str = ""
    explanation: dict[str, Any] = Field(default_factory=dict)


# -- LLM Verification --


class LLMVerifyResult(BaseModel):
    """Result from LLM semantic equivalence verification."""

    equivalent: bool = False
    confidence: float = 0.0
    reason: str = ""


# -- Semantic index --


class SemanticMatch(BaseModel):
    """A single match from a semantic similarity search."""

    key: str
    score: float  # cosine similarity (0-1)
    metadata: dict[str, Any] = Field(default_factory=dict)


class SearchResult(BaseModel):
    """A single result from the parallel discovery search."""

    asset_id: int
    source_id: str
    asset_type: str
    asset_path: str
    title: str | None = None
    summary: str | None = None
    score: float = 0.0
    strategy: str = ""  # "vector", "fulltext", "metadata"
    metadata: dict[str, Any] = Field(default_factory=dict)


# -- S3 --


class S3FileInfo(BaseModel):
    """Metadata for a file in an S3 bucket."""

    key: str
    size: int
    last_modified: datetime | None = None
    etag: str | None = None


# -- OIDC --


class OIDCTokens(BaseModel):
    """Token set returned from OIDC token exchange."""

    access_token: str
    id_token: str | None = None
    refresh_token: str | None = None
    expires_in: int | None = None
    token_type: str = "Bearer"


class OIDCUserInfo(BaseModel):
    """User info from OIDC claims or userinfo endpoint."""

    sub: str  # subject identifier
    email: str | None = None
    name: str | None = None
    preferred_username: str | None = None
    groups: list[str] = Field(default_factory=list)


# -- Chunking --


class Chunk(BaseModel):
    """A single chunk of text from a document."""

    text: str
    index: int
    start_word: int
    end_word: int
    metadata: dict[str, Any] = Field(default_factory=dict)
