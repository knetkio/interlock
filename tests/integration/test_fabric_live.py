"""Opt-in six-cell native acceptance using explicitly authorized operator fixtures.

FABRIC_LIVE=1 FABRIC_LIVE_MANIFEST=/private/manifest.json uv run pytest \\
  tests/integration/test_fabric_live.py -m live -q -rA

Configure the ordinary application control DB/key refs explicitly. OAuth login
must already be saved through the administrator's approved browser flow. This
suite neither discovers ambient accounts nor accepts pasted tokens. Use JUnit
output for durable per-dimension pass/skip evidence. A pass for SELECT is not
acceptance for governance, lifecycle, cancellation, TLS failure, or egress.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from tests.integration.fabric_live_support import (
    AUTH_MODES,
    DIMENSIONS,
    ENDPOINTS,
    check_selector,
    load_manifest,
    require_control_config,
    validate_binding,
)

pytestmark = [
    pytest.mark.live,
    pytest.mark.skipif(os.environ.get("FABRIC_LIVE") != "1", reason="UNVERIFIED: FABRIC_LIVE != 1"),
]


@pytest.fixture
async def native_cell(request):
    path = os.environ.get("FABRIC_LIVE_MANIFEST")
    if not path:
        pytest.skip("UNVERIFIED: no explicit Fabric live manifest")
    manifest = load_manifest(json.loads(Path(path).read_text()))
    endpoint, mode = request.param
    cell = next(
        (
            cell
            for cell in manifest.cells
            if cell.endpoint_type == endpoint and cell.auth_mode == mode
        ),
        None,
    )
    if cell is None:
        pytest.skip("UNVERIFIED: designated endpoint/auth cell absent")
    check_selector(manifest)
    from interlock.config import load_config
    from interlock.connections.fabric.runtime import build_fabric_services
    from interlock.db.pool import create_pg_pool

    config_path = require_control_config(os.environ.get("FABRIC_LIVE_CONFIG_PATH"))
    config = load_config(config_path)
    pool = await create_pg_pool(config.database)
    services = None
    try:
        services = build_fabric_services(pool, config.fabric)
        assert (
            services is not None
        ), "Configure explicit Fabric key references and native dependencies"
        current = await services.store.current_source(cell.source_id)
        validate_binding(cell, current.config, current.context)
        yield cell, current.config, services, pool
    finally:
        if services:
            await services.close()
        await pool.close()


@pytest.mark.parametrize(
    "native_cell",
    [(e, a) for e in ENDPOINTS for a in AUTH_MODES],
    indirect=True,
    ids=[f"{e}-{a}" for e in ENDPOINTS for a in AUTH_MODES],
)
@pytest.mark.parametrize("dimension", DIMENSIONS)
async def test_fabric_native_acceptance(native_cell, dimension, record_property):
    cell, config, services, pool = native_cell
    record_property("workspace_designation", cell.workspace_id)
    record_property("workspace_verification", "operator-designated; not independently queried")
    if dimension in {"connection", "bounded_select", "token_packing"}:
        prepared = await services.prepare_source(cell.source_id, config)
        validate_binding(cell, config, prepared.token.context)
        result = await services.transport.execute(
            config,
            prepared.token,
            "SELECT TOP (1) DB_NAME() AS database_name, SUSER_SNAME() AS upstream_identity",
            (),
            write=False,
        )
        assert result["rows"] == [
            {"database_name": cell.database, "upstream_identity": cell.expected_sql_identity}
        ]
        await prepared.assert_current()
    elif dimension == "catalog_visibility":
        from interlock.catalog.collectors.fabric import metadata_snapshot
        from interlock.catalog.model import ScanLimits

        snapshot = await metadata_snapshot(
            services,
            cell.source_id,
            config,
            ScanLimits(max_nodes=1000, max_schemas=20, max_tables=100, max_columns_per_table=100),
        )
        assert snapshot.source_attributes["database"] == cell.database
        assert snapshot.nodes, "Expected visible catalog objects for designated fixture identity"
    elif dimension == "lakehouse_mutation_rejection" and cell.endpoint_type == "lakehouse_sql":
        from interlock.connections.connectors import get_adapter

        # No services are supplied: a broken rejection cannot submit SQL.
        adapter = get_adapter("fabric_sql", source_id=cell.source_id)
        with pytest.raises(ValueError, match="Lakehouse"):
            await adapter.execute_write(
                {
                    "connection_config": config.model_dump(),
                    "query": "DELETE FROM dbo.interlock_disposable",
                }
            )
    else:
        if dimension == "lakehouse_mutation_rejection":
            pytest.skip("Not applicable: table writes are supported by this endpoint type")
        scenario = configured_scenario(cell, dimension)
        from tests.integration.fabric_live_scenarios import run_scenario

        await run_scenario(dimension, scenario, cell, config, services, pool)


def configured_scenario(cell, dimension):
    from tests.integration.fabric_live_scenarios import load_scenarios

    path = os.environ.get("FABRIC_LIVE_SCENARIOS")
    if not path:
        pytest.skip("UNVERIFIED: no authorized scenario fixtures supplied")
    assert Path(path).is_absolute(), "Private scenario file must use an absolute path"
    book = load_scenarios(json.loads(Path(path).read_text()))
    scenario = book.cells.get(f"{cell.endpoint_type}/{cell.auth_mode}", {}).get(dimension)
    if scenario is None:
        pytest.skip("UNVERIFIED: this authorized scenario fixture was not supplied")
    return scenario


@pytest.mark.parametrize(
    "native_cell",
    [(e, a) for e in ENDPOINTS for a in AUTH_MODES],
    indirect=True,
    ids=[f"{e}-{a}" for e in ENDPOINTS for a in AUTH_MODES],
)
async def test_fabric_live_disposable_write_acceptance(native_cell):
    cell, config, services, pool = native_cell
    if cell.endpoint_type == "lakehouse_sql":
        pytest.skip("Not applicable: Lakehouse mutation rejection has a separate read-only probe")
    scenario = configured_scenario(cell, "writes")
    from tests.integration.fabric_live_scenarios import run_scenario

    await run_scenario("writes", scenario, cell, config, services, pool)
