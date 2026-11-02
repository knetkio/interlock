"""Validation helpers for connector connection_config dictionaries."""

from __future__ import annotations

import logging
from collections.abc import Iterable
from typing import Any
from urllib.parse import urlparse

from interlock.errors import EgressBlockedError
from interlock.security.egress import validate_host_egress, validate_http_egress_url

logger = logging.getLogger(__name__)


class SourceConfigValidationError(ValueError):
    """Raised when a connector connection_config is unsafe or malformed."""


EXECUTABLE_CONFIG_KEYS = frozenset(
    {
        "binary",
        "executable",
        "gws_binary",
        "command",
        "cmd",
        "shell",
    }
)
HTTP_URL_CONFIG_KEYS = frozenset({"base_url", "endpoint_url", "instance_url", "url"})
DB_DSN_CONFIG_KEYS = frozenset({"connection_string", "dsn"})
HOST_CONFIG_KEYS = frozenset({"host"})
COMMON_CONFIG_KEYS = frozenset(
    {
        "allow_private_egress",
        "timeout_seconds",
        "ssl",
        "ssl_verify",
        "ssl_ca",
        "ssl_ca_ref",
        "user",
        "username",
        "password",
        "password_ref",
        "token",
        "token_ref",
        "api_key",
        "api_key_ref",
        "auth_header",
        "port",
        *HTTP_URL_CONFIG_KEYS,
        *DB_DSN_CONFIG_KEYS,
        *HOST_CONFIG_KEYS,
    }
)


# The modes that verify the upstream's certificate. Production accepts only
# these. Shared with ConnectionManager so the gate and the connection it guards
# cannot disagree about which modes verify.
VERIFYING_TLS_MODES = frozenset({"verify-ca", "verify-full"})


def upstream_tls_refusal(
    connection_config: dict[str, Any],
    *,
    allow_insecure_tls: bool,
) -> str | None:
    """Why this source's upstream TLS posture is not permitted, or None.

    One judgement, consulted by every protocol. The production gate used to
    live inline in `pg_proxy._open_upstream_connection` and was handed only to
    the PG-wire listener, so the connector path - MCP and HTTP - had no
    equivalent check. The same stored source was therefore refused on one
    protocol and served on another, and an operator could satisfy themselves
    that it worked while it was in fact unverified wherever it did connect.

    Returns a message rather than raising, so each caller can raise the error
    type its own surface expects while both report the same wording.

    Only a verifying mode passes in production. `require` encrypts without
    checking the certificate - asyncpg's require with no root.crt sets
    CERT_NONE - and it used to pass here while the PG-wire path, building a
    default verifying context, checked the same source. The refusal message
    promises verified TLS, so the gate now requires exactly that.

    Scope is deliberately PostgreSQL: it judges the `ssl`/`sslmode` and
    `ssl_verify`/`verify_ssl` fields that a database upstream declares. A
    connector that carries none of them - object storage, a SaaS API - has no
    posture to read here and must not be failed for its absence.
    """
    if allow_insecure_tls:
        return None

    mode = read_connection_field(connection_config, "ssl")
    if mode is None or str(mode).strip().lower() not in VERIFYING_TLS_MODES:
        return "Verified upstream PostgreSQL TLS is required"

    verify = read_connection_field(connection_config, "ssl_verify")
    if verify is not None and not config_bool(verify):
        return "Unverified upstream PostgreSQL TLS is disabled"

    return None


def _with_alias_siblings(allowed: set[str]) -> set[str]:
    """Add every other spelling of a field that is already allowed.

    `read_connection_field` resolves each `CONFIG_ALIASES` group identically at
    connect time, so a spelling the connect path honours must also be storable.
    The strict allowlist was maintained separately from the alias table and
    drifted apart from it: `sslrootcert` - the libpq parameter name, and the
    one a PostgreSQL operator is most likely to type - was refused by
    `POST`/`PUT /api/data-sources` while the less familiar `ssl_ca` was
    accepted, even though both reach the handshake identically.

    Deriving the set rather than listing it means adding a spelling to the
    alias table cannot reintroduce the gap. Nothing new is permitted here: a
    group is expanded only when one of its members was already allowed, and
    `EXECUTABLE_CONFIG_KEYS` is rejected before this is consulted.
    """
    expanded = set(allowed)
    for group in CONFIG_ALIASES.values():
        if expanded.intersection(group):
            expanded.update(group)
    return expanded


def validate_source_config(
    connection_config: dict[str, Any] | None,
    *,
    connector_key: str | None = None,
    source_type: str | None = None,
    source_id: str | None = None,
    allowed_fields: Iterable[str] = (),
    secret_fields: Iterable[str] = (),
    strict_unknown: bool = False,
) -> dict[str, Any]:
    """Validate and return a connector config.

    The default mode is compatibility-oriented: it rejects known-dangerous
    fields and unsafe network targets, but does not fail legacy deployments for
    harmless unknown fields. Callers can opt into strict_unknown for admin-time
    hardening once stored source configs have been migrated.
    """

    cfg = connection_config or {}
    if not isinstance(cfg, dict):
        raise SourceConfigValidationError("connection_config must be an object")

    if connector_key == "fabric_sql":
        from pydantic import ValidationError

        from interlock.connections.fabric.config import FabricConfig

        try:
            FabricConfig.from_mapping(cfg)
        except ValidationError as exc:
            # Do not echo values: rejected fields can contain literal secrets.
            raise SourceConfigValidationError(
                "invalid Fabric SQL connection configuration"
            ) from exc

    allowed = _with_alias_siblings(
        {
            str(field)
            for field in (
                set(allowed_fields)
                | set(secret_fields)
                | {f"{field}_ref" for field in secret_fields}
                | COMMON_CONFIG_KEYS
            )
        }
    )
    unknown: list[str] = []
    for raw_key in cfg:
        key = str(raw_key)
        lowered = key.lower()
        if lowered in EXECUTABLE_CONFIG_KEYS:
            raise SourceConfigValidationError(
                f"connection_config.{key} is not allowed for connector runtime"
            )
        if strict_unknown and key not in allowed:
            unknown.append(key)
    if unknown:
        raise SourceConfigValidationError(
            "unsupported connection_config field(s): " + ", ".join(sorted(unknown))
        )

    allow_private = config_bool(cfg.get("allow_private_egress"))
    if allow_private:
        logger.warning(
            "allow_private_egress enabled connector=%s source_type=%s source_id=%s",
            connector_key,
            source_type,
            source_id,
        )

    for key in HTTP_URL_CONFIG_KEYS:
        value = cfg.get(key)
        if value:
            _validate_http_url(str(value), key=key, allow_private=allow_private)

    for key in DB_DSN_CONFIG_KEYS:
        value = cfg.get(key)
        if value:
            _validate_dsn(str(value), key=key, allow_private=allow_private)

    host = cfg.get("host")
    if host:
        validate_host_egress(
            str(host),
            port=_optional_int(cfg.get("port")),
            allow_private=allow_private,
        )

    return cfg


def _validate_http_url(url: str, *, key: str, allow_private: bool) -> None:
    try:
        validate_http_egress_url(url, allow_private=allow_private)
    except EgressBlockedError:
        raise
    except Exception as exc:
        raise SourceConfigValidationError(f"connection_config.{key} is invalid") from exc


def _validate_dsn(dsn: str, *, key: str, allow_private: bool) -> None:
    parsed = urlparse(dsn)
    if not parsed.scheme:
        return
    if parsed.scheme in {"http", "https"}:
        validate_http_egress_url(dsn, allow_private=allow_private)
        return
    if parsed.hostname:
        validate_host_egress(
            parsed.hostname,
            port=parsed.port,
            allow_private=allow_private,
        )
        return
    raise SourceConfigValidationError(f"connection_config.{key} must include a hostname")


def _optional_int(value: Any) -> int | None:
    if value in (None, ""):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def config_bool(value: Any) -> bool:
    """Parse persisted configuration booleans without truthiness traps."""
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


# ---------------------------------------------------------------------------
# Connection-config reading
#
# One definition of what a stored connection_config *means*, so every path
# that opens an upstream connection agrees.
#
# This exists because they did not. `pg_proxy` resolved secret references and
# accepted both `ssl` and `sslmode`; `ConnectionManager`, which serves the MCP
# and HTTP paths, read `connection_config["password"]` and
# `connection_config["ssl"]` literally. The same stored source therefore
# connected with no password over MCP and with no encryption when its TLS mode
# was spelled `sslmode` - silently, and differently depending on which
# protocol the agent happened to use.
# ---------------------------------------------------------------------------

# Accepted spellings, in precedence order. A reference wins over a literal so
# that adding a `*_ref` to an existing source takes effect without having to
# clear the old inline value first.
CONFIG_ALIASES: dict[str, tuple[str, ...]] = {
    "user": ("user_ref", "username_ref", "user", "username"),
    "password": ("password_ref", "password"),
    "database": ("database_ref", "database", "dbname"),
    "host": ("host_ref", "host"),
    "port": ("port_ref", "port"),
    # pg_proxy has always accepted either spelling; ConnectionManager did not.
    "ssl": ("ssl", "sslmode"),
    "ssl_verify": ("ssl_verify", "verify_ssl"),
    "ssl_ca": ("ssl_ca_ref", "ssl_ca", "sslrootcert"),
}


def resolve_config_value(config: dict[str, Any], *keys: str) -> str | None:
    """Return the first present key's value, resolving any secret reference.

    Values may be literals or references (`env://NAME`, `file://...`,
    `vault://...`, `aws-sm://...`). A literal is passed through `resolve`
    too, so a plain field may itself hold a reference.
    """
    from interlock.secrets.resolver import resolve as resolve_secret

    for key in keys:
        raw = config.get(key)
        if raw is None:
            continue
        return resolve_secret(str(raw))
    return None


def read_connection_field(config: dict[str, Any], field: str) -> str | None:
    """Read one logical connection field, honouring every accepted spelling.

    Prefer this over `config.get(...)` anywhere a connection is being opened.
    A direct `.get` silently ignores the `_ref` form and any alias, which is
    how a source configured through the admin console - where `password_ref`
    is a first-class field with an `env://` placeholder - could produce a
    connection with no password at all.
    """
    aliases = CONFIG_ALIASES.get(field, (field,))
    return resolve_config_value(config, *aliases)
