"""CRUD routes for the data_sources table."""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from interlock.admin.audit import (
    audit_admin_action,
    mutation_audit_detail,
    summarize_admin_resource,
)
from interlock.admin.catalog_hooks import after_source_saved
from interlock.admin.source_cache import invalidate_source_cache, notify_source_change
from interlock.admin.source_ids import (
    InvalidSourceIdError,
    generate_source_id,
    validate_source_id,
)
from interlock.config import allows_insecure_upstream_tls
from interlock.connections.activation import ConnectorNotActiveError, require_active
from interlock.connections.connectors import (
    get_connector,
    sanitize_config,
    source_metadata_for_connector,
)
from interlock.connections.source_config import (
    SourceConfigValidationError,
    upstream_tls_refusal,
    validate_source_config,
)
from interlock.security.egress import EgressBlockedError

router = APIRouter(prefix="/api/data-sources", tags=["data-sources"])


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class DataSourceCreate(BaseModel):
    # Generated from `name` when omitted; see admin/source_ids.py.
    source_id: str | None = None
    name: str
    source_type: str  # postgresql, http, s3, saas
    connector_key: str | None = None
    connection_config: dict[str, Any] = Field(default_factory=dict)
    cache_strategy: str = "deterministic_first"

    model_config = {"extra": "ignore"}
    enabled: bool = True
    metadata: dict[str, Any] = Field(default_factory=dict)


class DataSourceUpdate(BaseModel):
    name: str | None = None
    source_type: str | None = None
    connection_config: dict[str, Any] | None = None
    cache_strategy: str | None = None
    enabled: bool | None = None
    metadata: dict[str, Any] | None = None


class DataSourceResponse(BaseModel):
    id: int
    source_id: str
    name: str
    source_type: str
    connection_config: dict[str, Any]
    cache_strategy: str
    enabled: bool
    metadata: dict[str, Any]
    created_at: datetime | None = None
    updated_at: datetime | None = None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _row_to_dict(row) -> dict[str, Any]:  # asyncpg.Record
    d = dict(row)
    # With the custom JSON codec on the pool, JSONB columns come back as dicts.
    # Guard against str for environments without the codec (e.g. test mocks).
    for key in ("connection_config", "metadata"):
        val = d.get(key)
        if isinstance(val, str):
            d[key] = json.loads(val)
        elif val is None:
            d[key] = {}
    connector = get_connector(str(d.get("source_type") or ""), d.get("metadata") or {})
    d["connection_config"] = sanitize_config(d.get("connection_config") or {}, connector)
    return d


async def _notify(request: Request, channel: str = "onyx_config_changed") -> None:
    await notify_source_change(request, channel)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("", response_model=list[DataSourceResponse])
async def list_data_sources(request: Request) -> list[dict[str, Any]]:
    pool = request.app.state.pg_pool
    async with pool.acquire() as conn:
        rows = await conn.fetch("SELECT * FROM data_sources ORDER BY id")
    return [_row_to_dict(r) for r in rows]


@router.get("/{source_id}", response_model=DataSourceResponse)
async def get_data_source(source_id: str, request: Request) -> dict[str, Any]:
    pool = request.app.state.pg_pool
    async with pool.acquire() as conn:
        row = await conn.fetchrow("SELECT * FROM data_sources WHERE source_id = $1", source_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Data source not found")
    return _row_to_dict(row)


class TestConnectionRequest(BaseModel):
    """Body for the Test Connection probe endpoint.

    Same shape as ``DataSourceCreate`` minus the requirement on
    ``source_id`` (the connection is not persisted).
    """

    source_id: str | None = None
    name: str | None = None
    source_type: str
    connector_key: str | None = None
    connection_config: dict[str, Any] = Field(default_factory=dict)

    model_config = {"extra": "ignore"}


class ConnectionTestResult(BaseModel):
    ok: bool
    latency_ms: float
    error: str | None = None


@router.post("/test", response_model=ConnectionTestResult)
async def test_connection(
    body: TestConnectionRequest,
    request: Request,
) -> dict[str, Any]:
    """Probe an upstream's connectivity without persisting it.

    Used by the source-onboarding UI. Does NOT touch the database;
    safe to call repeatedly.
    """
    from interlock.connections.manager import ConnectionManager

    requested = body.connector_key or get_connector(body.source_type).key
    if requested == "fabric_sql":
        return {
            "ok": False,
            "latency_ms": 0,
            "error": "Save the Fabric source before testing its connection",
        }
    try:
        await require_active(request.app.state.pg_pool, requested)
    except ConnectorNotActiveError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    status = await ConnectionManager.probe_unsaved(
        body.source_type,
        body.connection_config,
        connector_key=body.connector_key,
        allow_insecure_tls=allows_insecure_upstream_tls(request.app.state.config),
    )
    return {
        "ok": status.healthy,
        "latency_ms": status.latency_ms,
        "error": status.error,
    }


@router.post("/{source_id}/test", response_model=ConnectionTestResult)
async def test_registered_source(source_id: str, request: Request) -> dict[str, Any]:
    """Probe a previously registered source."""
    from interlock.connections.manager import ConnectionManager

    pool = request.app.state.pg_pool
    row = await pool.fetchrow(
        "SELECT source_type, connection_config, metadata FROM data_sources WHERE source_id = $1",
        source_id,
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Data source not found")
    cfg = row["connection_config"]
    if isinstance(cfg, str):
        cfg = json.loads(cfg)
    meta = row["metadata"] or {}
    if isinstance(meta, str):
        meta = json.loads(meta)
    connector = get_connector(row["source_type"], meta)
    if connector.key == "fabric_sql":
        from interlock.admin.routes.fabric_auth import probe_saved

        status = await probe_saved(request, source_id, cfg or {})
    else:
        status = await ConnectionManager.probe_unsaved(
            row["source_type"],
            cfg or {},
            connector_key=connector.key,
            allow_insecure_tls=allows_insecure_upstream_tls(request.app.state.config),
        )
    return {
        "ok": status.healthy,
        "latency_ms": status.latency_ms,
        "error": status.error,
    }


@router.post("", response_model=DataSourceResponse, status_code=201)
async def create_data_source(body: DataSourceCreate, request: Request) -> dict[str, Any]:
    pool = request.app.state.pg_pool
    async with pool.acquire() as conn:
        if body.source_id:
            try:
                source_id = validate_source_id(body.source_id)
            except InvalidSourceIdError as exc:
                raise HTTPException(status_code=422, detail=str(exc)) from exc
            existing = await conn.fetchval(
                "SELECT 1 FROM data_sources WHERE source_id = $1", source_id
            )
            if existing:
                raise HTTPException(
                    status_code=409, detail=f"Data source '{source_id}' already exists"
                )
        else:
            source_id = await generate_source_id(conn, body.name)
        connector = get_connector(
            body.source_type,
            {"connector_key": body.connector_key} if body.connector_key else body.metadata,
        )
        try:
            await require_active(conn, body.connector_key or connector.key)
        except ConnectorNotActiveError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        try:
            validate_source_config(
                body.connection_config,
                connector_key=connector.key,
                source_type=connector.source_type,
                source_id=source_id,
                allowed_fields=connector.credential_fields,
                secret_fields=connector.secret_fields,
                strict_unknown=True,
            )
        except (SourceConfigValidationError, EgressBlockedError) as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        if connector.source_type == "postgresql":
            # Refused at registration rather than at the first agent query:
            # storing a configuration production will never connect with only
            # moves the failure to where no operator is looking.
            refusal = upstream_tls_refusal(
                body.connection_config,
                allow_insecure_tls=allows_insecure_upstream_tls(request.app.state.config),
            )
            if refusal:
                raise HTTPException(status_code=422, detail=refusal)
        metadata = {
            **(body.metadata or {}),
            **source_metadata_for_connector(connector.key),
        }
        row = await conn.fetchrow(
            """
            INSERT INTO data_sources (source_id, name, source_type, connection_config,
                                      cache_strategy, enabled, metadata)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING *
            """,
            source_id,
            body.name,
            body.source_type,
            body.connection_config,
            body.cache_strategy,
            body.enabled,
            metadata,
        )
    await _notify(request)
    await after_source_saved(request, source_id)
    response = _row_to_dict(row)
    await audit_admin_action(
        request,
        action="data_source.create",
        resource="data_source",
        resource_id=str(response["source_id"]),
        success=True,
        detail=mutation_audit_detail(
            after=summarize_admin_resource(
                response,
                fields=(
                    "source_id",
                    "name",
                    "source_type",
                    "connection_config",
                    "cache_strategy",
                    "enabled",
                    "metadata",
                ),
            ),
            changed_fields=(
                "source_id",
                "name",
                "source_type",
                "connection_config",
                "cache_strategy",
                "enabled",
                "metadata",
            ),
            status_code=201,
        ),
    )
    return response


@router.put("/{source_id}", response_model=DataSourceResponse)
async def update_data_source(
    source_id: str, body: DataSourceUpdate, request: Request
) -> dict[str, Any]:
    pool = request.app.state.pg_pool

    updates = body.model_dump(exclude_unset=True)
    if not updates:
        raise HTTPException(status_code=400, detail="No fields to update")

    set_clauses: list[str] = []
    values: list[Any] = []
    idx = 1

    for field, value in updates.items():
        if field in ("connection_config", "metadata"):
            set_clauses.append(f"{field} = ${idx}")
            values.append(value)
        else:
            set_clauses.append(f"{field} = ${idx}")
            values.append(value)
        idx += 1

    set_clauses.append("updated_at = NOW()")
    values.append(source_id)

    query = f"""
        UPDATE data_sources
        SET {', '.join(set_clauses)}
        WHERE source_id = ${idx}
        RETURNING *
    """

    async with pool.acquire() as conn:
        before_row = await conn.fetchrow(
            "SELECT * FROM data_sources WHERE source_id = $1",
            source_id,
        )
        if before_row is None:
            raise HTTPException(status_code=404, detail="Data source not found")
        if "connection_config" in updates or "source_type" in updates or "metadata" in updates:
            current = _row_to_dict(before_row)
            effective_type = updates.get("source_type", current["source_type"])
            effective_metadata = updates.get("metadata", current.get("metadata") or {})
            connector = get_connector(effective_type, effective_metadata)
            effective_config = updates.get(
                "connection_config", current.get("connection_config") or {}
            )
            try:
                validate_source_config(
                    effective_config,
                    connector_key=connector.key,
                    source_type=connector.source_type,
                    source_id=source_id,
                    allowed_fields=connector.credential_fields,
                    secret_fields=connector.secret_fields,
                    strict_unknown=True,
                )
            except (SourceConfigValidationError, EgressBlockedError) as exc:
                raise HTTPException(status_code=422, detail=str(exc)) from exc
            if connector.source_type == "postgresql":
                refusal = upstream_tls_refusal(
                    effective_config,
                    allow_insecure_tls=allows_insecure_upstream_tls(request.app.state.config),
                )
                if refusal:
                    raise HTTPException(status_code=422, detail=refusal)
        row = await conn.fetchrow(query, *values)
    if row is None:
        raise HTTPException(status_code=404, detail="Data source not found")
    await _notify(request)
    await invalidate_source_cache(request, source_id)
    await after_source_saved(request, source_id)
    response = _row_to_dict(row)
    before = _row_to_dict(before_row) if before_row is not None else None
    await audit_admin_action(
        request,
        action="data_source.update",
        resource="data_source",
        resource_id=source_id,
        success=True,
        detail=mutation_audit_detail(
            before=summarize_admin_resource(
                before,
                fields=(
                    "source_id",
                    "name",
                    "source_type",
                    "connection_config",
                    "cache_strategy",
                    "enabled",
                    "metadata",
                ),
            ),
            after=summarize_admin_resource(
                response,
                fields=(
                    "source_id",
                    "name",
                    "source_type",
                    "connection_config",
                    "cache_strategy",
                    "enabled",
                    "metadata",
                ),
            ),
            changed_fields=tuple(updates.keys()),
            status_code=200,
        ),
    )
    return response


@router.delete("/{source_id}", status_code=204)
async def delete_data_source(source_id: str, request: Request) -> None:
    pool = request.app.state.pg_pool
    async with pool.acquire() as conn:
        before_row = await conn.fetchrow(
            "SELECT * FROM data_sources WHERE source_id = $1",
            source_id,
        )
        result = await conn.execute("DELETE FROM data_sources WHERE source_id = $1", source_id)
    if result == "DELETE 0":
        raise HTTPException(status_code=404, detail="Data source not found")
    await _notify(request)
    await invalidate_source_cache(request, source_id)
    before = _row_to_dict(before_row) if before_row is not None else None
    await audit_admin_action(
        request,
        action="data_source.delete",
        resource="data_source",
        resource_id=source_id,
        success=True,
        detail=mutation_audit_detail(
            before=summarize_admin_resource(
                before,
                fields=(
                    "source_id",
                    "name",
                    "source_type",
                    "connection_config",
                    "cache_strategy",
                    "enabled",
                    "metadata",
                ),
            ),
            status_code=204,
        ),
    )


# ---------------------------------------------------------------------------
# Source catalog scans
# ---------------------------------------------------------------------------


_SCAN_COLUMNS = (
    "id, source_id, trigger, status, requested_by, requested_at, started_at, "
    "finished_at, attempt, collector, nodes_seen, added_count, removed_count, "
    "changed_count, truncated, truncation, baseline, changes_truncated, "
    "error_code, error_message"
)


def _scan_to_dict(row: Any) -> dict[str, Any]:
    scan = dict(row)
    for key in ("requested_at", "started_at", "finished_at"):
        if isinstance(scan.get(key), datetime):
            scan[key] = scan[key].isoformat()
    if isinstance(scan.get("truncation"), str):
        scan["truncation"] = json.loads(scan["truncation"] or "{}")
    return scan


@router.post("/{source_id}/catalog/scans", status_code=202)
async def request_catalog_scan(source_id: str, request: Request) -> dict[str, Any]:
    """Queue a scan of the source's structure now, rather than waiting for the
    next save or scheduled refresh. Idempotent: a scan already waiting is
    returned rather than a second one queued."""
    from interlock.catalog.queue import enqueue_catalog_scan

    pool = request.app.state.pg_pool
    exists = await pool.fetchval("SELECT 1 FROM data_sources WHERE source_id = $1", source_id)
    if not exists:
        raise HTTPException(status_code=404, detail=f"Unknown data source: {source_id}")
    admin = getattr(request.state, "admin", None)
    scan_id = await enqueue_catalog_scan(
        pool, source_id, trigger="api", requested_by=getattr(admin, "username", None)
    )
    if scan_id is None:
        raise HTTPException(
            status_code=409,
            detail="This source is disabled, or its connector has no catalog collector yet",
        )
    await audit_admin_action(
        request,
        action="data_source.catalog_scan",
        resource="data_source",
        resource_id=source_id,
        success=True,
        detail={"scan_id": scan_id},
    )
    row = await pool.fetchrow(
        f"SELECT {_SCAN_COLUMNS} FROM source_catalog_scans WHERE id = $1", scan_id
    )
    return _scan_to_dict(row)


@router.get("/{source_id}/catalog/scans")
async def list_catalog_scans(
    source_id: str, request: Request, limit: int = 20
) -> list[dict[str, Any]]:
    """The source's recent scans, newest first."""
    pool = request.app.state.pg_pool
    rows = await pool.fetch(
        f"""
        SELECT {_SCAN_COLUMNS} FROM source_catalog_scans
        WHERE source_id = $1 ORDER BY requested_at DESC LIMIT $2
        """,
        source_id,
        max(1, min(limit, 200)),
    )
    return [_scan_to_dict(row) for row in rows]
