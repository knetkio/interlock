"""Offline live-acceptance safety: explicit scope before credentials or network."""

from __future__ import annotations

import copy

import pytest


def sample():
    return {
        "project": "/designated/project",
        "customer": "blendx",
        "cells": [
            {
                "endpoint_type": "warehouse",
                "auth_mode": "oauth",
                "source_id": "explicit-source",
                "tenant_id": "test-tenant",
                "workspace_id": "test-workspace",
                "database": "test-database",
                "host": "test.datawarehouse.fabric.microsoft.com",
                "client_id": "test-client",
                "expected_account_id": "test-account",
                "expected_sql_identity": "test-sql-principal",
            }
        ],
    }


def test_missing_cells_are_unverified_and_scoped_cell_is_not_certified():
    from tests.integration.fabric_live_support import inventory, load_manifest

    manifest = load_manifest(sample())
    report = inventory(manifest)
    assert len(report) == 6
    configured = report["warehouse/oauth"]
    assert configured["connection"] == "pending"
    assert configured["writes"] == "pending_explicit_authorization"
    assert report["warehouse/spn"]["connection"] == "unverified_missing_cell"
    assert configured["driver_redirect_egress"] == "pending"


@pytest.mark.parametrize(
    "field",
    [
        "tenant_id",
        "workspace_id",
        "database",
        "host",
        "client_id",
        "expected_account_id",
        "expected_sql_identity",
    ],
)
def test_manifest_refuses_incomplete_identity_and_scope(field):
    from tests.integration.fabric_live_support import load_manifest

    value = sample()
    value["cells"][0].pop(field)
    with pytest.raises(ValueError, match="manifest"):
        load_manifest(value)


def test_manifest_refuses_duplicates_secrets_and_unassigned_customer():
    from tests.integration.fabric_live_support import load_manifest

    for value in [sample() | {"customer": "unassigned"}, sample() | {"access_token": "secret"}]:
        with pytest.raises(ValueError, match="manifest"):
            load_manifest(value)
    value = sample()
    value["cells"].append(copy.deepcopy(value["cells"][0]))
    with pytest.raises(ValueError, match="manifest"):
        load_manifest(value)


def test_source_binding_refuses_wrong_endpoint_or_identity_before_acquiring_token():
    from interlock.connections.fabric.config import FabricConfig
    from interlock.connections.fabric.credentials import FabricCredentialContext
    from tests.integration.fabric_live_support import load_manifest, validate_binding

    cell = load_manifest(sample()).cells[0]
    config = FabricConfig.from_mapping(
        dict(
            host=cell.host,
            database=cell.database,
            tenant_id=cell.tenant_id,
            client_id=cell.client_id,
            endpoint_type="warehouse",
            auth_mode="oauth",
        )
    )
    context = FabricCredentialContext(
        source_id=cell.source_id,
        generation=1,
        tenant_id=cell.tenant_id,
        client_id=cell.client_id,
        account_id=cell.expected_account_id,
        auth_mode="oauth",
        status="connected",
    )
    validate_binding(cell, config, context)
    with pytest.raises(ValueError, match="binding"):
        validate_binding(cell, config.model_copy(update={"database": "other"}), context)
    with pytest.raises(ValueError, match="binding"):
        validate_binding(
            cell, config, __import__("dataclasses").replace(context, account_id="other")
        )


def test_live_control_settings_cannot_fall_back_to_evaluation_database_defaults(tmp_path):
    from tests.integration.fabric_live_support import require_control_config

    path = tmp_path / "private.yaml"
    path.write_text("fabric: {}\n")
    with pytest.raises(ValueError, match="explicit control database"):
        require_control_config(str(path))
    path.write_text(
        "database:\n  host: control.example\n  port: 5432\n  user: test\n  database: designated\n"
    )
    assert require_control_config(str(path)) == path
