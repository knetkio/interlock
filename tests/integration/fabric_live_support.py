"""Explicit native acceptance manifest and inventory; never a credential bootstrap.

Only tests/tooling consume this module. No token, DSN, policy seed, or write SQL
is accepted in the manifest. Pending dimensions are not certification evidence.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from interlock.connections.fabric.config import FabricConfig
from interlock.connections.fabric.credentials import FabricCredentialContext

NonEmpty = Annotated[str, Field(min_length=1)]
ENDPOINTS = ("warehouse", "lakehouse_sql", "sql_database")
AUTH_MODES = ("oauth", "spn")
DIMENSIONS = (
    "connection",
    "bounded_select",
    "catalog_visibility",
    "denial",
    "redaction",
    "audit",
    "restart_refresh",
    "oauth_reconnect_lost_consent",
    "spn_rotation",
    "multi_instance_cache",
    "token_packing",
    "login_cancellation",
    "statement_cancellation",
    "tls_certificate_failure",
    "driver_redirect_egress",
    "lakehouse_mutation_rejection",
)


class LiveCell(BaseModel):
    model_config = ConfigDict(extra="forbid")
    endpoint_type: Literal["warehouse", "lakehouse_sql", "sql_database"]
    auth_mode: Literal["oauth", "spn"]
    source_id: NonEmpty
    tenant_id: NonEmpty
    workspace_id: NonEmpty
    database: NonEmpty
    host: NonEmpty
    client_id: NonEmpty
    # Explicit null for SPN; OAuth must identify the saved MSAL home_account_id.
    expected_account_id: NonEmpty | None
    expected_sql_identity: NonEmpty

    @model_validator(mode="after")
    def account_binding(self):
        if self.auth_mode == "oauth" and not self.expected_account_id:
            raise ValueError("OAuth account designation required")
        if self.auth_mode == "spn" and self.expected_account_id is not None:
            raise ValueError("SPN account designation must be null")
        return self


class LiveManifest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    project: NonEmpty
    customer: Literal["radiance", "stretchzone", "exhale", "blendx", "breezydata"]
    cells: list[LiveCell]

    @model_validator(mode="after")
    def scope(self):
        if not Path(self.project).is_absolute():
            raise ValueError("Absolute designated project required")
        keys = [(cell.endpoint_type, cell.auth_mode) for cell in self.cells]
        if len(keys) != len(set(keys)):
            raise ValueError("Duplicate acceptance cell")
        return self


def load_manifest(value: object) -> LiveManifest:
    try:
        return LiveManifest.model_validate(value)
    except ValidationError:
        # Pydantic errors include input values. A mistakenly pasted secret must
        # not appear in the report/log through a validation error.
        raise ValueError("Invalid Fabric live manifest: explicit scope/identity required") from None


def inventory(manifest: LiveManifest) -> dict[str, dict[str, str]]:
    supplied = {(cell.endpoint_type, cell.auth_mode) for cell in manifest.cells}
    return {
        f"{endpoint}/{auth}": {
            **{
                dimension: (
                    "pending" if (endpoint, auth) in supplied else "unverified_missing_cell"
                )
                for dimension in DIMENSIONS
            },
            "writes": "pending_explicit_authorization",
        }
        for endpoint in ENDPOINTS
        for auth in AUTH_MODES
    }


def validate_binding(
    cell: LiveCell, config: FabricConfig, context: FabricCredentialContext
) -> None:
    if any(
        getattr(config, field) != getattr(cell, field)
        for field in ("endpoint_type", "auth_mode", "host", "database", "tenant_id", "client_id")
    ) or (
        context.source_id != cell.source_id
        or context.tenant_id != cell.tenant_id
        or context.client_id != cell.client_id
        or context.auth_mode != cell.auth_mode
        or context.account_id != cell.expected_account_id
    ):
        raise ValueError("Fabric live source binding does not match designated manifest")


def check_selector(manifest: LiveManifest) -> None:
    """Must run before opening a control pool or reading/acquiring credentials."""
    result = subprocess.run(
        [
            "/Users/avouk/.local/bin/fabric-customer",
            "status",
            "--project",
            manifest.project,
        ],
        text=True,
        capture_output=True,
        timeout=15,
        check=True,
    )
    selected = json.loads(result.stdout)
    if (
        selected.get("customer") != manifest.customer
        or selected.get("project") != str(Path(manifest.project).resolve())
        or not selected.get("fabric")
        or not selected.get("sql")
    ):
        raise ValueError("Project selector is mismatched or SQL connection is disabled")
    if any(cell.tenant_id != selected["fabric"]["tenantId"] for cell in manifest.cells):
        raise ValueError("Project selector tenant does not match live manifest")


def require_control_config(path: str | None) -> Path:
    """An explicit private file must designate the control DB; defaults are unsafe here."""
    import yaml

    try:
        if not path or not Path(path).is_absolute():
            raise ValueError
        selected = Path(path)
        content = yaml.safe_load(selected.read_text())
        database = content.get("database") if isinstance(content, dict) else None
        if not isinstance(database, dict) or not all(
            database.get(key) for key in ("host", "port", "user", "database")
        ):
            raise ValueError
        return selected
    except (ValueError, OSError, yaml.YAMLError):
        raise ValueError("Fabric live tests require explicit control database settings") from None
