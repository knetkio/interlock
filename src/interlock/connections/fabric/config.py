"""Fabric endpoint configuration; credentials live only in the encrypted store."""

from __future__ import annotations

import re
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

SECRET_SCHEMES = ("env://", "file://", "vault://", "aws-sm://")


def require_secret_reference(value: str) -> str:
    if not value.startswith(SECRET_SCHEMES) or not value.split("://", 1)[1].strip():
        raise ValueError("must be an env, file, vault or aws-sm secret reference")
    return value


class FabricConfig(BaseModel):
    """Allowlisted ODBC inputs. TLS and the driver are fixed by the transport."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    host: str = Field(min_length=1, max_length=253)
    database: str = Field(min_length=1, max_length=128)
    tenant_id: str = Field(min_length=1, max_length=128)
    client_id: str = Field(min_length=1, max_length=128)
    endpoint_type: Literal["warehouse", "lakehouse_sql", "sql_database"]
    auth_mode: Literal["oauth", "spn"]
    client_secret_ref: str | None = None
    port: int = Field(default=1433, ge=1, le=65535)
    connect_timeout_seconds: int = Field(default=15, ge=1, le=120)
    statement_timeout_seconds: int = Field(default=30, ge=1, le=3600)
    max_rows: int = Field(default=1000, ge=1, le=100_000)
    max_bytes: int = Field(default=8 * 1024 * 1024, ge=1024, le=256 * 1024 * 1024)
    allow_private_egress: bool = False

    @field_validator("host")
    @classmethod
    def validate_host(cls, value: str) -> str:
        if not all(
            re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label)
            for label in value.split(".")
        ):
            raise ValueError("host must be a plain DNS hostname without ODBC syntax")
        return value

    @field_validator("database", "tenant_id", "client_id")
    @classmethod
    def validate_identifier(cls, value: str) -> str:
        if value != value.strip() or any(c in value for c in ";{}\\/\x00\r\n"):
            raise ValueError("identifier contains unsafe characters")
        return value

    @field_validator("tenant_id", "client_id")
    @classmethod
    def validate_auth_identifier(cls, value: str) -> str:
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", value):
            raise ValueError("authentication identifier must be a tenant domain or application ID")
        return value

    @field_validator("tenant_id")
    @classmethod
    def require_specific_tenant(cls, value: str) -> str:
        if value.lower() in {"common", "organizations", "consumers"}:
            raise ValueError("a specific Fabric tenant is required")
        return value

    @field_validator("client_secret_ref")
    @classmethod
    def validate_secret(cls, value: str | None) -> str | None:
        return require_secret_reference(value) if value is not None else None

    @model_validator(mode="after")
    def require_spn_secret(self) -> FabricConfig:
        if self.auth_mode == "spn" and not self.client_secret_ref:
            raise ValueError("spn authentication requires client_secret_ref")
        return self

    @classmethod
    def from_mapping(cls, config: dict[str, Any]) -> FabricConfig:
        return cls.model_validate(config)
