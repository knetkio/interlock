"""InterLock configuration schema with YAML loading and env var overrides.

Phase 0 hardening (P0-T01):
- Top-level model rejects unknown keys (extra='forbid') so typos in
  config.yaml fail fast at startup instead of silently being dropped.
- YAML parse errors raise ConfigValidationError instead of being
  swallowed into an empty dict.
- Numeric ranges (ports, pool sizes, TTLs, thresholds) are validated.
"""

from __future__ import annotations

import os
import warnings
from collections.abc import MutableMapping
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from interlock.errors import ConfigValidationError

# ---------------------------------------------------------------------------
# Sub-config models
# ---------------------------------------------------------------------------

_STRICT = ConfigDict(extra="forbid")


class GatewayConfig(BaseModel):
    """Gateway listener configuration."""

    model_config = _STRICT

    host: str = Field(
        default="0.0.0.0",
        description="Interface the gateway's HTTP/MCP and PostgreSQL listeners bind to.",
    )
    http_port: int = Field(
        default=3000, ge=1, le=65535, description="Port for the HTTP proxy and MCP endpoints."
    )
    pg_port: int = Field(
        default=5432, ge=1, le=65535, description="Port for the PostgreSQL wire listener."
    )
    upstream_pg_host: str = Field(
        default="localhost",
        description="Default upstream PostgreSQL host, used when a source does not name its own.",
    )
    upstream_pg_port: int = Field(
        default=5433,
        ge=1,
        le=65535,
        description="Default upstream PostgreSQL port, used when a source does not name its own.",
    )
    mcp_port: int = Field(
        default=8001, ge=1, le=65535, description="Reserved: not read by the current runtime."
    )
    http_workers: int = Field(
        default=4, ge=1, le=256, description="Reserved: not read by the current runtime."
    )
    pg_workers: int = Field(
        default=2, ge=1, le=256, description="Reserved: not read by the current runtime."
    )
    mcp_workers: int = Field(
        default=2, ge=1, le=256, description="Reserved: not read by the current runtime."
    )
    pg_max_startup_bytes: int = Field(
        default=10_000,
        ge=8,
        le=1_048_576,
        description="Largest PostgreSQL startup packet accepted, in bytes.",
    )
    pg_max_message_bytes: int = Field(
        default=16 * 1024 * 1024,
        ge=5,
        le=256 * 1024 * 1024,
        description="Largest single PostgreSQL protocol message accepted, in bytes.",
    )
    pg_max_result_bytes: int = Field(
        default=64 * 1024 * 1024,
        ge=1024,
        le=1024**3,
        description="Largest result the PostgreSQL listener buffers for one query, in bytes.",
    )
    pg_startup_timeout_seconds: float = Field(
        default=10.0, gt=0.0, le=300.0, description="Time a client has to send its startup packet."
    )
    pg_auth_timeout_seconds: float = Field(
        default=15.0, gt=0.0, le=300.0, description="Time a client has to complete authentication."
    )
    pg_frame_timeout_seconds: float = Field(
        default=30.0,
        gt=0.0,
        le=3600.0,
        description="Time allowed to receive the rest of a partly sent message.",
    )
    pg_idle_timeout_seconds: float = Field(
        default=300.0, gt=0.0, le=86400.0, description="Reserved: not read by the current runtime."
    )
    pg_max_clients: int = Field(
        default=256, ge=1, le=100_000, description="Most concurrent PostgreSQL client connections."
    )
    pg_tls_cert_file: str | None = Field(
        default=None, description="Certificate for TLS on the PostgreSQL listener."
    )
    pg_tls_key_file: str | None = Field(
        default=None, description="Private key for TLS on the PostgreSQL listener."
    )
    pg_require_client_tls: bool = Field(
        default=False, description="Refuse PostgreSQL clients that do not negotiate TLS."
    )
    pg_trusted_tls_offload: bool = Field(
        default=False,
        description="TLS is terminated in front of the gateway, so client TLS is not required here.",
    )
    mcp_max_body_bytes: int = Field(
        default=1024 * 1024,
        ge=1024,
        le=64 * 1024 * 1024,
        description="Largest MCP request body accepted, in bytes.",
    )
    mcp_max_results: int = Field(
        default=1000,
        ge=1,
        le=100_000,
        description="Upper bound on rows or results an MCP tool returns.",
    )
    mcp_allowed_origins: list[str] = Field(
        default_factory=list,
        description="Browser Origin values allowed to call /mcp; empty allows none.",
    )
    http_max_request_body_bytes: int = Field(
        default=10 * 1024 * 1024,
        ge=1024,
        le=1024**3,
        description="Largest request body the HTTP proxy forwards, in bytes.",
    )
    http_max_response_body_bytes: int = Field(
        default=50 * 1024 * 1024,
        ge=1024,
        le=1024**3,
        description="Largest upstream response the HTTP proxy relays, in bytes.",
    )
    http_max_connections: int = Field(
        default=100,
        ge=1,
        le=100_000,
        description="Most concurrent upstream connections the HTTP proxy opens.",
    )
    http_max_keepalive_connections: int = Field(
        default=20,
        ge=0,
        le=100_000,
        description="Most idle upstream connections the HTTP proxy keeps.",
    )
    http_timeout_seconds: float = Field(
        default=30.0, gt=0.0, le=600.0, description="Upstream request timeout for the HTTP proxy."
    )


class AdminConfig(BaseModel):
    """Admin API configuration."""

    model_config = _STRICT

    host: str = Field(
        default="127.0.0.1",
        description="Interface the Admin console binds to. Containers set 0.0.0.0.",
    )
    port: int = Field(
        default=9090, ge=1, le=65535, description="Port for the Admin console and API."
    )
    # Auth secret used to sign session cookies and CSRF tokens. Must be
    # set in production via INTERLOCK_ADMIN__SECRET_KEY. The empty default
    # triggers an in-memory random key on first boot (development only,
    # invalidates sessions on restart).
    secret_key: str = Field(
        default="",
        description="Key that signs session and CSRF cookies. Required in production (32+ characters); empty uses a random key that resets on restart.",
    )
    # First-admin password. Unset, the first admin is admin/admin and is
    # forced to change it at first sign-in; set, it is trusted as chosen.
    bootstrap_password: str = Field(
        default="",
        description="Password for the first admin, `admin`, when none exists. Unset, the first admin gets the default `admin` and must change it at first sign-in.",
    )
    session_ttl_seconds: int = Field(
        default=8 * 3600, ge=60, le=86400 * 7, description="Lifetime of an Admin session."
    )
    cookie_secure: bool = Field(
        default=False, description="Mark Admin cookies Secure (HTTPS only). Required in production."
    )
    cookie_name: str = Field(
        default="interlock_admin_session", description="Name of the Admin session cookie."
    )
    csrf_cookie_name: str = Field(
        default="interlock_admin_csrf", description="Name of the cookie carrying the CSRF token."
    )
    # When True, the admin queues a first catalog scan at startup for every
    # enabled source that has never been scanned. The workers run the scans;
    # the admin itself never connects to a source for this.
    catalog_on_startup: bool = Field(
        default=True,
        description="At start, queue a first catalog scan for every enabled source never scanned.",
    )


class WorkerConfig(BaseModel):
    """Background worker configuration."""

    model_config = _STRICT

    worker_id: str = Field(
        default="worker-1", description="Name this worker reports in heartbeats and job leases."
    )
    concurrency: int = Field(
        default=8, ge=1, le=512, description="Jobs a worker processes at once."
    )
    heartbeat_interval: float = Field(
        default=5.0, gt=0.0, description="Seconds between worker heartbeats."
    )
    lease_seconds: int = Field(
        default=300,
        ge=10,
        le=86400,
        description="How long a claimed job stays leased before another worker may take it.",
    )


class DatabaseConfig(BaseModel):
    """PostgreSQL connection configuration."""

    model_config = _STRICT

    host: str = Field(default="localhost", description="Control database host.")
    port: int = Field(default=5432, ge=1, le=65535, description="Control database port.")
    database: str = Field(default="onyx", description="Control database name.")
    user: str = Field(default="onyx", description="Control database user.")
    password: str = Field(default="", description="Control database password.")
    min_pool: int = Field(
        default=2, ge=0, le=1024, description="Connections kept open to the control database."
    )
    max_pool: int = Field(
        default=10, ge=1, le=1024, description="Most connections opened to the control database."
    )
    ssl_mode: Literal["disable", "require", "verify-ca", "verify-full"] = Field(
        default="disable",
        description="TLS mode for the control database. Production requires verify-full.",
    )
    ssl_ca_file: str | None = Field(
        default=None, description="CA certificate used to verify the control database."
    )
    ssl_cert_file: str | None = Field(
        default=None, description="Client certificate for the control database."
    )
    ssl_key_file: str | None = Field(
        default=None, description="Client key for the control database."
    )


class RedisConfig(BaseModel):
    """Redis connection configuration."""

    model_config = _STRICT

    url: str = Field(
        default="redis://localhost:6379/0",
        description="Redis URL, for sessions, rate limits, cache and coordination.",
    )
    max_connections: int = Field(
        default=20, ge=1, le=4096, description="Most connections in the Redis pool."
    )


class OIDCConfig(BaseModel):
    """OpenID Connect settings shared by Admin SSO and agent JWT auth."""

    model_config = _STRICT

    enabled: bool = Field(
        default=False, description="Use OpenID Connect for Admin sign-in and agent JWTs."
    )
    issuer_url: str = Field(default="", description="OIDC issuer; must be https in production.")
    admin_client_id: str = Field(default="", description="Client id for Admin sign-in.")
    admin_client_secret: str = Field(default="", description="Client secret for Admin sign-in.")
    admin_redirect_uri: str = Field(
        default="http://localhost:9090/auth/oidc/callback",
        description="Callback URL registered with the identity provider.",
    )
    agent_audience: str = Field(default="", description="Audience agent JWTs must carry.")
    scopes: list[str] = Field(
        default_factory=lambda: ["openid", "profile", "email", "groups"],
        description="Scopes requested at sign-in; must include openid.",
    )
    flow_ttl_seconds: int = Field(
        default=600, ge=60, le=3600, description="Time allowed to complete a sign-in round trip."
    )
    local_break_glass_enabled: bool = Field(
        default=True,
        description="Keep password sign-in for local owner/admin accounts while OIDC is on.",
    )
    allow_insecure_endpoints: bool = Field(
        default=False, description="Allow http identity-provider endpoints. Development only."
    )
    admin_group_role_map: dict[str, list[str]] = Field(
        default_factory=dict, description="Identity-provider group names mapped to Admin roles."
    )

    @model_validator(mode="after")
    def validate_oidc_contract(self) -> OIDCConfig:
        if self.enabled and "openid" not in self.scopes:
            raise ValueError("auth.oidc.scopes must include openid")
        return self


class AuthConfig(BaseModel):
    """Authentication configuration."""

    model_config = _STRICT

    enabled: bool = Field(default=True, description="Require agent authentication.")
    session_ttl_seconds: int = Field(
        default=3600,
        ge=1,
        le=86400 * 30,
        description="How long an authenticated agent session is cached.",
    )
    api_key_pepper: str = Field(
        default="",
        description="Server-side secret mixed into API key hashes. Required in production (32+ characters); changing it invalidates every key.",
    )
    allow_legacy_sha256_keys: bool = Field(
        default=True,
        description="Accept keys stored as plain SHA-256. Must be false in production.",
    )
    custom_api_key_min_length: int = Field(
        default=32, ge=24, le=256, description="Shortest API key an operator may supply."
    )
    oidc: OIDCConfig = Field(default_factory=OIDCConfig, description="OpenID Connect settings.")


class CacheConfig(BaseModel):
    """Multi-layer cache configuration."""

    model_config = _STRICT

    l1_max_size: int = Field(
        default=1000,
        ge=0,
        le=10_000_000,
        description="Entries held in each process's in-memory cache.",
    )
    l1_ttl_seconds: int = Field(
        default=60, ge=0, le=86400, description="Lifetime of an in-memory cache entry."
    )
    l2_ttl_seconds: int = Field(
        default=300, ge=0, le=86400, description="Lifetime of a Redis cache entry."
    )
    default_strategy: str = Field(
        default="lru",
        description="Reserved: not read by the current runtime. Each source chooses its own cache strategy.",
    )
    strict_write_barrier: bool = Field(
        default=True,
        description="Refuse to serve from cache when the write-generation barrier is unavailable.",
    )
    source_generation_prefix: str = Field(
        default="interlock:cache:generation",
        description="Redis key prefix for per-source write generations. Every gateway and admin must share it.",
    )
    pubsub_reconnect_seconds: float = Field(
        default=1.0,
        gt=0.0,
        le=300.0,
        description="Delay before reconnecting to the cache-invalidation channel.",
    )


class PIIConfig(BaseModel):
    """PII detection and masking configuration."""

    model_config = _STRICT

    fast_enabled: bool = Field(default=True, description="Run the regex PII scanner on responses.")
    deep_enabled: bool = Field(
        default=False, description="Also run the Presidio scanner (needs the pii extra)."
    )
    deep_max_workers: int = Field(
        default=2, ge=1, le=64, description="Threads for the deep scanner."
    )
    free_text_column_patterns: list[str] = Field(
        default_factory=lambda: [
            "description",
            "notes",
            "comment",
            "bio",
            "message",
            "body",
            "content",
            "remarks",
            "summary",
            "text",
        ],
        description="Column-name fragments treated as free text and scanned for PII.",
    )


class AuditConfig(BaseModel):
    """Audit logging configuration."""

    model_config = _STRICT

    enabled: bool = Field(
        default=True, description="Write an audit row for every governed request."
    )
    partition_interval: str = Field(
        default="monthly",
        description="Reserved: not read by the current runtime. Partitions are monthly.",
    )
    buffer_max_size: int = Field(
        default=50_000,
        ge=0,
        le=10_000_000,
        description="Audit events held in memory before back-pressure.",
    )
    flush_interval_ms: int = Field(
        default=100, ge=1, le=60_000, description="How often the buffer is written."
    )
    flush_batch_size: int = Field(
        default=1000, ge=1, le=100_000, description="Events written per batch."
    )
    durability_mode: Literal["best_effort", "retriable", "strict"] = Field(
        default="retriable",
        description="best_effort drops on failure, retriable spools and retries, strict refuses the request when its audit row cannot be kept. Production requires strict.",
    )
    retry_max_attempts: int = Field(
        default=5, ge=1, le=100, description="Attempts to write a batch before spooling it."
    )
    retry_base_delay_ms: int = Field(
        default=100, ge=1, le=60_000, description="First retry delay; later ones back off."
    )
    spool_path: str = Field(
        default="/var/lib/interlock/audit-spool",
        description="Directory where unwritten audit events are spooled to disk.",
    )
    partition_maintenance_interval_seconds: int = Field(
        default=3600,
        ge=60,
        le=86400,
        description="How often audit partitions are created and checked.",
    )
    partition_months_back: int = Field(
        default=1, ge=0, le=24, description="Past monthly partitions kept attached."
    )
    partition_months_ahead: int = Field(
        default=3, ge=1, le=60, description="Future monthly partitions created in advance."
    )


class IngestionConfig(BaseModel):
    """Data ingestion configuration."""

    model_config = _STRICT

    enabled: bool = Field(default=False, description="Run ingestion (discovery indexing) jobs.")
    max_retries: int = Field(
        default=3,
        ge=0,
        le=100,
        description="Attempts per ingestion job before it is marked failed.",
    )
    heartbeat_interval_seconds: float = Field(
        default=10.0, gt=0.0, description="Reserved: not read by the current runtime."
    )
    job_timeout_seconds: float = Field(
        default=300.0, gt=0.0, description="Reserved: not read by the current runtime."
    )


class NotificationConfig(BaseModel):
    """Outbound notification configuration.

    Only Slack is implemented. Credentials arrive as secret references
    (`env://`, `file://`, `vault://`, `aws-sm://`) resolved at startup, never
    as literals in a values file or a ConfigMap - a webhook URL is itself a
    credential, which is why it has a `_ref` field of its own.
    """

    model_config = _STRICT

    enabled: bool = Field(
        default=False, description="Send Slack notifications about write approvals."
    )
    # Deprecated: a literal URL, honoured only when slack_webhook_url_ref is
    # unset. Kept for one minor release; prefer the reference field.
    slack_webhook_url: str | None = Field(
        default=None, description="Deprecated literal webhook URL; use slack_webhook_url_ref."
    )
    slack_webhook_url_ref: str | None = Field(
        default=None, description="Secret reference to a Slack incoming-webhook URL."
    )
    slack_bot_token_ref: str | None = Field(
        default=None, description="Secret reference to a Slack bot token; needs slack_channel."
    )
    slack_channel: str | None = Field(default=None, description="Channel the bot posts to.")
    slack_api_base_url: str = Field(
        default="https://slack.com/api", description="Slack Web API base URL."
    )
    admin_base_url: str | None = Field(
        default=None, description="Console URL used to link a message to its approval."
    )
    approval_events: list[str] = Field(
        default_factory=lambda: ["pending", "approved", "rejected", "expired", "failed"],
        description="Approval events that send a message.",
    )
    timeout_seconds: float = Field(
        default=5.0, gt=0.0, le=30.0, description="Timeout per delivery attempt."
    )
    max_attempts: int = Field(default=3, ge=1, le=10, description="Delivery attempts per message.")
    # Delivery targets are normally public endpoints. Allow private ones only
    # deliberately, for example a fake receiver on a compose network.
    allow_private_egress: bool = Field(
        default=False, description="Allow delivery to private network addresses."
    )

    @model_validator(mode="after")
    def _validate_targets(self) -> "NotificationConfig":
        for field in ("slack_webhook_url_ref", "slack_bot_token_ref"):
            value = getattr(self, field)
            if value and "://" not in value:
                raise ValueError(
                    f"notifications.{field} must be a secret reference "
                    "(env://, file://, vault:// or aws-sm://), not a literal value"
                )
        if not self.enabled:
            return self
        if not (self.slack_bot_token_ref or self.slack_webhook_url_ref or self.slack_webhook_url):
            raise ValueError(
                "notifications.enabled requires slack_bot_token_ref, "
                "slack_webhook_url_ref, or slack_webhook_url"
            )
        if self.slack_bot_token_ref and not self.slack_channel:
            raise ValueError("notifications.slack_bot_token_ref requires slack_channel")
        return self


class FabricSettings(BaseModel):
    """Process settings; Fernet keys are resolved from operator secret references."""

    model_config = _STRICT

    active_key_version: str | None = Field(
        default=None,
        description="Active credential-encryption key version; absent disables Fabric services.",
    )
    key_refs: dict[str, str] = Field(
        default_factory=dict,
        description="Version-to-secret-reference map for active and retained Fernet keys.",
    )
    oauth_redirect_uri: str | None = Field(
        default=None, description="Exact registered console origin plus /api/fabric/oauth/callback."
    )
    oauth_client_id: str | None = Field(
        default=None, description="Explicit confidential Web application ID for saved-user OAuth."
    )
    oauth_client_secret_ref: str | None = Field(
        default=None,
        description="Secret reference for the confidential OAuth application credential.",
    )
    oauth_allowed_tenants: list[str] = Field(
        default_factory=list, description="Explicit tenant IDs allowed for saved-user OAuth."
    )
    lock_timeout_seconds: float = Field(
        default=30.0,
        gt=0,
        le=120,
        description="Deadline for credential pool/lock/auth lifecycle operations, in seconds.",
    )
    refresh_skew_seconds: int = Field(
        default=120,
        ge=0,
        le=600,
        description="Renew saved SQL access tokens this many seconds before expiry.",
    )
    max_concurrent_operations: int = Field(
        default=8,
        ge=1,
        le=128,
        description="Reserved concurrency setting; current transport uses eight active slots.",
    )
    max_waiting_operations: int = Field(
        default=16,
        ge=1,
        le=1024,
        description="Reserved queue setting; current transport allows sixteen waiting submissions.",
    )

    @model_validator(mode="after")
    def validate_keyring(self) -> FabricSettings:
        from interlock.connections.fabric.config import require_secret_reference

        for ref in self.key_refs.values():
            require_secret_reference(ref)
        if self.oauth_client_secret_ref is not None:
            require_secret_reference(self.oauth_client_secret_ref)
        if self.active_key_version is not None and self.active_key_version not in self.key_refs:
            raise ValueError("fabric.active_key_version must name a configured secret reference")
        return self


class ApprovalConfig(BaseModel):
    """Write-approval queue behaviour.

    `expiry_seconds` was hard-coded to 900. A reviewer who is told about a
    pending approval by a notification needs longer than fifteen minutes to
    act on it, so it is configurable.
    """

    model_config = _STRICT

    expiry_seconds: int = Field(
        default=900,
        ge=60,
        le=7 * 86400,
        description="How long a queued write waits for a decision before it expires.",
    )
    expiry_sweep_interval_seconds: int = Field(
        default=30, ge=1, le=3600, description="How often expired approvals are swept."
    )


class CatalogConfig(BaseModel):
    """The source catalog: structure captured per source, and how often.

    Scans run in the worker. A save queues one; so does the Rescan button; and
    the scheduler refreshes any source whose last successful scan is older than
    `refresh_interval_seconds`. Every scan is bounded by the caps below and
    records `truncated` when it hits one rather than silently stopping.
    """

    model_config = _STRICT

    enabled: bool = Field(
        default=True, description="Capture each source's structure into the catalog."
    )
    scan_on_save: bool = Field(default=True, description="Queue a scan whenever a source is saved.")
    scheduled_refresh_enabled: bool = Field(
        default=True, description="Rescan sources on a schedule."
    )
    refresh_interval_seconds: int = Field(
        default=86400, ge=900, description="Age at which a successful scan is refreshed."
    )
    failure_retry_seconds: int = Field(
        default=3600, ge=60, description="Wait before retrying a source whose scan failed."
    )
    scheduler_tick_seconds: int = Field(
        default=300, ge=10, description="How often the scheduler looks for due sources."
    )
    scheduler_jitter_seconds: int = Field(
        default=120, ge=0, description="Random delay added so scans do not start together."
    )
    worker_concurrency: int = Field(
        default=1, ge=1, le=16, description="Scans one worker runs at once."
    )
    poll_interval_seconds: float = Field(
        default=5.0, gt=0, le=300, description="How often a worker checks for queued scans."
    )
    scan_timeout_seconds: int = Field(
        default=600, ge=10, description="Longest a single scan may run."
    )
    lease_seconds: int = Field(
        default=120, ge=30, description="How long a claimed scan stays leased."
    )
    max_attempts: int = Field(
        default=3, ge=1, le=10, description="Attempts per scan before it is marked failed."
    )
    max_nodes: int = Field(
        default=250_000, ge=100, description="Most catalog nodes one scan records."
    )
    max_schemas: int = Field(default=500, ge=1, description="Most schemas one scan records.")
    max_tables: int = Field(default=20_000, ge=1, description="Most tables one scan records.")
    max_columns_per_table: int = Field(
        default=2_000, ge=1, description="Most columns recorded per table."
    )
    max_change_rows_per_scan: int = Field(
        default=5_000, ge=0, description="Most drift rows one scan records."
    )
    scan_history_retention: int = Field(default=50, ge=1, description="Scans kept per source.")
    change_retention_days: int = Field(default=90, ge=1, description="Days drift rows are kept.")


class SemanticCacheConfig(BaseModel):
    """Semantic cache configuration."""

    model_config = _STRICT

    default_auto_serve_threshold: float = Field(
        default=0.98,
        ge=0.0,
        le=1.0,
        description="Reserved: not read by the current runtime. Semantic cache serving is disabled.",
    )
    default_verify_threshold: float = Field(
        default=0.92,
        ge=0.0,
        le=1.0,
        description="Reserved: not read by the current runtime. Semantic cache serving is disabled.",
    )
    llm_timeout_ms: int = Field(
        default=500, ge=1, le=60_000, description="Reserved: not read by the current runtime."
    )
    embedding_model: str = Field(
        default="all-MiniLM-L6-v2", description="Reserved: not read by the current runtime."
    )
    embedding_dimension: int = Field(
        default=384, ge=8, le=8192, description="Dimension of the discovery embedding vectors."
    )
    use_onnx: bool = Field(default=False, description="Reserved: not read by the current runtime.")


class ObservabilityConfig(BaseModel):
    """Tracing and metrics export configuration."""

    model_config = _STRICT

    enabled: bool = Field(
        default=True, description="Export traces and metrics over OTLP when an endpoint is set."
    )
    otlp_endpoint: str | None = Field(
        default=None, description="OTLP HTTP endpoint; unset exports nothing."
    )
    instrument_asgi: bool = Field(default=True, description="Trace each HTTP request.")
    readiness_enabled: bool = Field(
        default=True, description="Reserved: not read by the current runtime."
    )
    public_stats_enabled: bool = Field(
        default=False, description="Serve the gateway's /stats without authentication."
    )
    readiness_timeout_seconds: float = Field(
        default=2.0, gt=0.0, le=30.0, description="Timeout for each dependency check in /ready."
    )


# ---------------------------------------------------------------------------
# Root config
# ---------------------------------------------------------------------------

_DEFAULT_CONFIG_PATHS = ("config.yaml", "config.yml")


class InterLockConfig(BaseSettings):
    """Root configuration for InterLock.

    Loading order (later wins):
      1. Field defaults (defined above)
      2. YAML config file
      3. Environment variables prefixed with INTERLOCK_

    Unknown top-level keys raise a validation error so typos surface
    immediately at boot rather than as silent default-value usage.
    """

    model_config = SettingsConfigDict(
        env_prefix="INTERLOCK_",
        env_nested_delimiter="__",
        extra="forbid",
    )

    environment: Literal["development", "test", "production"] = Field(
        default="development",
        description="development, test or production. Production enforces the security settings.",
    )
    service_role: Literal["all", "gateway", "admin", "worker", "migration"] = Field(
        default="all",
        description="Which service this process runs; production checks apply only to the settings that service uses.",
    )
    gateway: GatewayConfig = Field(
        default_factory=GatewayConfig, description="Gateway listeners and limits."
    )
    admin: AdminConfig = Field(default_factory=AdminConfig, description="Admin console.")
    worker: WorkerConfig = Field(default_factory=WorkerConfig, description="Background workers.")
    database: DatabaseConfig = Field(
        default_factory=DatabaseConfig, description="Control database."
    )
    redis: RedisConfig = Field(default_factory=RedisConfig, description="Redis.")
    auth: AuthConfig = Field(default_factory=AuthConfig, description="Agent authentication.")
    cache: CacheConfig = Field(default_factory=CacheConfig, description="Response cache.")
    pii: PIIConfig = Field(default_factory=PIIConfig, description="PII detection.")
    audit: AuditConfig = Field(default_factory=AuditConfig, description="Audit log.")
    ingestion: IngestionConfig = Field(
        default_factory=IngestionConfig, description="Discovery ingestion."
    )
    notifications: NotificationConfig = Field(
        default_factory=NotificationConfig, description="Approval notifications."
    )
    fabric: FabricSettings = Field(
        default_factory=FabricSettings,
        description="Explicit Fabric SQL authentication and credential-encryption settings.",
    )
    approvals: ApprovalConfig = Field(
        default_factory=ApprovalConfig, description="Write approvals."
    )
    semantic_cache: SemanticCacheConfig = Field(
        default_factory=SemanticCacheConfig,
        description="Discovery embeddings; semantic cache serving is disabled.",
    )
    catalog: CatalogConfig = Field(default_factory=CatalogConfig, description="Source catalog.")
    observability: ObservabilityConfig = Field(
        default_factory=ObservabilityConfig, description="Tracing, metrics and readiness."
    )

    @model_validator(mode="after")
    def validate_production_security(self) -> InterLockConfig:
        if self.environment != "production":
            return self
        errors: list[str] = []
        if self.service_role in {"all", "admin"}:
            if len(self.admin.secret_key) < 32:
                errors.append("admin.secret_key must be at least 32 characters")
            if not self.admin.cookie_secure:
                errors.append("admin.cookie_secure must be true")
        if self.service_role in {"all", "gateway", "admin"}:
            if len(self.auth.api_key_pepper) < 32:
                errors.append("auth.api_key_pepper must be at least 32 characters")
            if self.auth.allow_legacy_sha256_keys:
                errors.append("auth.allow_legacy_sha256_keys must be false")
        if self.auth.oidc.enabled and self.service_role in {"all", "gateway", "admin"}:
            if not self.auth.oidc.issuer_url.startswith("https://"):
                errors.append("auth.oidc.issuer_url must use https")
            if self.service_role in {"all", "admin"}:
                if not self.auth.oidc.admin_client_id:
                    errors.append("auth.oidc.admin_client_id is required")
                if not self.auth.oidc.admin_client_secret:
                    errors.append("auth.oidc.admin_client_secret is required")
                if not self.auth.oidc.admin_redirect_uri.startswith("https://"):
                    errors.append("auth.oidc.admin_redirect_uri must use https")
            if self.service_role in {"all", "gateway"} and not self.auth.oidc.agent_audience:
                errors.append("auth.oidc.agent_audience is required")
            if self.auth.oidc.allow_insecure_endpoints:
                errors.append("auth.oidc.allow_insecure_endpoints must be false")
        if self.service_role in {"all", "gateway"}:
            has_pg_listener_tls = bool(
                self.gateway.pg_tls_cert_file and self.gateway.pg_tls_key_file
            )
            if not has_pg_listener_tls and not self.gateway.pg_trusted_tls_offload:
                errors.append(
                    "gateway PostgreSQL client credentials require listener TLS "
                    "or trusted TLS offload"
                )
            if has_pg_listener_tls and not self.gateway.pg_require_client_tls:
                errors.append(
                    "gateway.pg_require_client_tls must be true when listener TLS is configured"
                )
        if self.database.ssl_mode != "verify-full":
            errors.append("database.ssl_mode must be verify-full")
        if not self.database.ssl_ca_file:
            errors.append("database.ssl_ca_file is required")
        if self.audit.durability_mode != "strict":
            errors.append("audit.durability_mode must be strict")
        if errors:
            raise ValueError("unsafe production configuration: " + "; ".join(errors))
        return self

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: Any,
        env_settings: Any,
        dotenv_settings: Any,
        file_secret_settings: Any,
    ) -> tuple[Any, ...]:
        """Env vars override YAML, which overrides defaults."""
        return (
            init_settings,
            env_settings,
            YamlConfigSource(settings_cls),
        )


# ---------------------------------------------------------------------------
# YAML config source
# ---------------------------------------------------------------------------


class YamlConfigSource:
    """Pydantic-settings custom source that reads a YAML file."""

    def __init__(self, settings_cls: type[BaseSettings]) -> None:
        self.settings_cls = settings_cls

    def __call__(self) -> dict[str, Any]:
        path = os.environ.get("INTERLOCK_CONFIG_PATH") or os.environ.get("ONYX_CONFIG_PATH")
        if path:
            return _load_yaml(Path(path))

        for candidate in _DEFAULT_CONFIG_PATHS:
            p = Path(candidate)
            if p.is_file():
                return _load_yaml(p)

        return {}


def _load_yaml(path: Path) -> dict[str, Any]:
    """Read and parse a YAML config file.

    A missing file falls through to defaults (preserves prior behavior).
    But a *present* file that is unreadable or unparseable raises
    ConfigValidationError so a corrupt config fails fast.
    """
    if not path.is_file():
        return {}
    try:
        with path.open() as f:
            data = yaml.safe_load(f)
    except OSError as exc:
        raise ConfigValidationError(f"Cannot read config file {path}: {exc}") from exc
    except yaml.YAMLError as exc:
        raise ConfigValidationError(f"Invalid YAML in {path}: {exc}") from exc

    if data is None:
        return {}
    if not isinstance(data, dict):
        raise ConfigValidationError(
            f"Config file {path} must contain a YAML mapping at the top level"
        )
    return data


# ---------------------------------------------------------------------------
# Module-level convenience
# ---------------------------------------------------------------------------


LEGACY_ENV_PREFIX = "ONYX_"
ENV_PREFIX = "INTERLOCK_"


def apply_legacy_env_prefix(environ: MutableMapping[str, str] | None = None) -> list[str]:
    """Map legacy ``ONYX_*`` variables onto their ``INTERLOCK_*`` equivalents.

    The project was renamed from InterLock to InterLock. Deployments pinned to the
    old prefix keep working for the compatibility window documented in
    ``docs-site/src/content/docs/reference/contracts/compatibility-policy.md``.

    Precedence is deliberate: an explicitly set ``INTERLOCK_*`` value always
    wins, so a half-migrated environment resolves to the new name rather than
    silently preferring the stale one. Each legacy variable that is actually
    consulted emits a single deprecation warning naming the replacement.

    Returns the list of legacy variable names that were applied, so callers
    and tests can assert on the migration surface.
    """
    env = os.environ if environ is None else environ
    applied: list[str] = []

    for legacy_name in [k for k in env if k.startswith(LEGACY_ENV_PREFIX)]:
        modern_name = ENV_PREFIX + legacy_name[len(LEGACY_ENV_PREFIX) :]
        if modern_name in env:
            # Already migrated; the new value governs. Still warn so the
            # operator knows there is a stale variable to delete.
            warnings.warn(
                f"{legacy_name} is deprecated and ignored because {modern_name} "
                "is also set. Remove the legacy variable.",
                DeprecationWarning,
                stacklevel=2,
            )
            continue
        env[modern_name] = env[legacy_name]
        applied.append(legacy_name)
        warnings.warn(
            f"{legacy_name} is deprecated; use {modern_name} instead.",
            DeprecationWarning,
            stacklevel=2,
        )

    return applied


def load_config(path: str | Path | None = None) -> InterLockConfig:
    """Load configuration, optionally from a specific YAML path.

    Args:
        path: Explicit path to a YAML config file. If provided, it is set
              as the INTERLOCK_CONFIG_PATH env var so the settings source picks
              it up.

    Returns:
        Fully resolved InterLockConfig instance.

    Raises:
        ConfigValidationError: If the YAML file cannot be parsed, contains
            unknown keys, or fails field validation. This is intentional:
            we'd rather refuse to boot than start with silently-wrong
            defaults.
    """
    apply_legacy_env_prefix()
    prior = os.environ.get("INTERLOCK_CONFIG_PATH")
    if path is not None:
        os.environ["INTERLOCK_CONFIG_PATH"] = str(path)
    try:
        return InterLockConfig()
    except ValidationError as exc:
        raise ConfigValidationError(str(exc)) from exc
    finally:
        if path is not None:
            if prior is None:
                os.environ.pop("INTERLOCK_CONFIG_PATH", None)
            else:
                os.environ["INTERLOCK_CONFIG_PATH"] = prior


def allows_insecure_upstream_tls(config: InterLockConfig) -> bool:
    """Whether an upstream PostgreSQL may be reached without verified TLS.

    One derivation, used by both apps and by every admin route that probes or
    stores a source. The apps each spelled `config.environment != "production"`
    inline and the Test Connection routes never asked at all, which is how a
    probe came to report healthy a configuration production refuses.
    """
    return config.environment != "production"
