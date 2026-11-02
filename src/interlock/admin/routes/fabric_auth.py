"""Source-bound Fabric onboarding. MSAL flow and credential ownership stay in FabricAuth."""

from __future__ import annotations

import json
import logging
import re
from typing import TYPE_CHECKING, Any, cast
from urllib.parse import quote, urlsplit

from fastapi import APIRouter, HTTPException, Request
from starlette.responses import JSONResponse, RedirectResponse, Response

from interlock.admin.audit import audit_admin_action
from interlock.admin.catalog_hooks import after_source_saved
from interlock.admin.source_cache import invalidate_source_cache, notify_source_change
from interlock.connections.connectors import get_connector
from interlock.connections.fabric.credentials import FabricCredentialError
from interlock.models import HealthStatus

if TYPE_CHECKING:
    from interlock.connections.fabric.runtime import FabricServices

router = APIRouter(tags=["fabric"])
_CALLBACK = "/api/fabric/oauth/callback"
_QUERY = re.compile(r"(/api/fabric/oauth/callback)\?[^\s\"'<>]*")


class FabricCallbackLogFilter(logging.Filter):
    """Redact only this OAuth callback at the log-record boundary, before formatting."""

    def filter(self, record: logging.LogRecord) -> bool:
        message = record.getMessage()
        if _CALLBACK + "?" in message:
            record.msg = _QUERY.sub(r"\1?[redacted]", message)
            record.args = ()
        return True


def install_callback_log_redaction() -> None:
    # A factory covers dependency/uvicorn loggers too, including handlers added
    # after application construction. Other URLs and log records are unchanged.
    previous = logging.getLogRecordFactory()
    if getattr(previous, "_fabric_redaction", False):
        return
    redactor = FabricCallbackLogFilter()

    def factory(*args: Any, **kwargs: Any) -> logging.LogRecord:
        record = previous(*args, **kwargs)
        redactor.filter(record)
        return record

    factory._fabric_redaction = True  # type: ignore[attr-defined]
    logging.setLogRecordFactory(factory)


def _auth_code(exc: RuntimeError) -> str:
    code = getattr(exc, "code", None)
    allowed = {
        "reconnect_required",
        "authentication_denied",
        "authentication_unavailable",
        "configuration_changed",
    }
    return str(code) if code in allowed else "authentication_unavailable"


def _services(request: Request) -> FabricServices:
    services = getattr(request.app.state, "fabric_services", None)
    if services is None:
        raise HTTPException(503, "Fabric authentication is not configured")
    return cast("FabricServices", services)


def _session(request: Request) -> str:
    admin = getattr(request.state, "admin", None)
    if admin is None or not admin.session_id:
        raise HTTPException(401, "An active administrator session is required")
    return str(admin.session_id)  # random, server-side, per-login opaque nonce


def _canonical_origin(request: Request) -> None:
    redirect = request.app.state.config.fabric.oauth_redirect_uri
    target = urlsplit(redirect or "")
    actual = urlsplit(str(request.url))
    if target.path != _CALLBACK or (target.scheme, target.netloc) != (actual.scheme, actual.netloc):
        raise HTTPException(
            409,
            "Open the console at the configured Fabric callback origin before signing in (localhost and 127.0.0.1 use different sessions)",
        )


async def _source(request: Request, source_id: str) -> dict[str, Any]:
    row = await request.app.state.pg_pool.fetchrow(
        "SELECT source_id, source_type, metadata, connection_config, enabled FROM data_sources WHERE source_id = $1",
        source_id,
    )
    if row is None:
        raise HTTPException(404, "Data source not found")
    source = dict(row)
    for field in ("metadata", "connection_config"):
        if isinstance(source[field], str):
            source[field] = json.loads(source[field])
    if get_connector(source["source_type"], source["metadata"] or {}).key != "fabric_sql":
        raise HTTPException(422, "This source does not use Fabric SQL")
    return source


def oauth_ready(request: Request, config: dict[str, Any]) -> bool:
    settings = request.app.state.config.fabric
    return bool(
        settings.oauth_redirect_uri
        and settings.oauth_client_secret_ref
        and settings.oauth_client_id == config.get("client_id")
        and str(config.get("tenant_id", "")).lower()
        in {tenant.lower() for tenant in settings.oauth_allowed_tenants}
        and getattr(request.app.state, "fabric_services", None)
    )


async def safe_auth_status(
    request: Request, source_id: str, config: dict[str, Any]
) -> dict[str, Any]:
    mode = config.get("auth_mode", "oauth")
    try:
        # Opening the existing owner validates encrypted bytes without calling a
        # provider. A persisted 'connected' flag alone is insufficient recovery UX.
        async with _services(request).store.locked(source_id) as locked:
            context = locked.context
            return {
                "auth_mode": context.auth_mode,
                "status": context.status,
                "account_id": context.account_id,
            }
    except FabricCredentialError:
        return {"auth_mode": mode, "status": "reconnect_required", "account_id": None}
    except Exception:
        return {"auth_mode": mode, "status": "unavailable", "account_id": None}


async def _changed(request: Request, source_id: str, *, scan: bool) -> None:
    await invalidate_source_cache(request, source_id)
    await notify_source_change(request)
    if scan:
        await after_source_saved(request, source_id)
    await audit_admin_action(
        request,
        action="data_source.fabric_credentials",
        resource="data_source",
        resource_id=source_id,
        success=True,
        detail={"catalog_scan_requested": scan},
    )


def _result(request: Request, source_id: str) -> Response:
    if request.headers.get("hx-request") == "true":
        return Response(
            headers={"HX-Redirect": f"/dashboard/data-sources/{quote(source_id, safe='')}"}
        )
    return JSONResponse({"status": "updated"})


@router.post("/api/data-sources/{source_id}/fabric/connect")
async def connect(source_id: str, request: Request) -> Response:
    binding = _session(request)
    source = await _source(request, source_id)
    if not source["enabled"] or source["connection_config"].get("auth_mode") != "oauth":
        raise HTTPException(422, "Enable and save an OAuth source before signing in")
    _canonical_origin(request)
    try:
        url = await _services(request).auth.begin_oauth(source_id, binding)
    except RuntimeError as exc:
        raise HTTPException(400, _auth_code(exc)) from None
    if request.headers.get("hx-request") == "true":
        return Response(headers={"HX-Redirect": url})
    return RedirectResponse(url, status_code=303)


@router.get(_CALLBACK)
async def callback(request: Request) -> Response:
    binding = _session(request)
    _canonical_origin(request)
    try:
        context = await _services(request).auth.complete_oauth(
            request.query_params.get("state", ""), dict(request.query_params), binding
        )
    except RuntimeError as exc:
        code = _auth_code(exc)
        await audit_admin_action(
            request,
            action="fabric.oauth_callback",
            resource="data_source",
            success=False,
            detail={"reason": code},
            error=code,
        )
        raise HTTPException(400, code) from None
    await _changed(request, context.source_id, scan=True)
    return RedirectResponse(
        f"/dashboard/data-sources/{quote(context.source_id, safe='')}", status_code=303
    )


@router.get("/api/data-sources/{source_id}/fabric/auth-status")
async def status(source_id: str, request: Request) -> dict[str, Any]:
    source = await _source(request, source_id)
    return await safe_auth_status(request, source_id, source["connection_config"])


@router.post("/api/data-sources/{source_id}/fabric/disconnect")
async def disconnect(source_id: str, request: Request) -> Response:
    _session(request)
    await _source(request, source_id)
    try:
        await _services(request).store.invalidate(source_id, reason="disconnect", delete_cache=True)
    except FabricCredentialError:
        raise HTTPException(400, "Fabric credentials could not be disconnected") from None
    await _changed(request, source_id, scan=False)
    return _result(request, source_id)


@router.post("/api/data-sources/{source_id}/fabric/rotate")
async def rotate(source_id: str, request: Request) -> Response:
    _session(request)
    source = await _source(request, source_id)
    if source["connection_config"].get("auth_mode") != "spn":
        raise HTTPException(422, "Credential rotation requires service principal authentication")
    try:
        store = _services(request).store
        async with store.locked(source_id) as locked:
            if locked.config.auth_mode != "spn":
                raise HTTPException(
                    422, "Credential rotation requires service principal authentication"
                )
            await store.invalidate_locked(locked, reason="secret_rotation", delete_cache=True)
    except FabricCredentialError:
        raise HTTPException(400, "Fabric credentials could not be rotated") from None
    await _changed(request, source_id, scan=True)
    return _result(request, source_id)


async def probe_saved(request: Request, source_id: str, config: dict[str, Any]) -> HealthStatus:
    """SELECT 1 only, using credentials belonging to this saved source."""
    from interlock.connections.connectors import get_adapter

    services = getattr(request.app.state, "fabric_services", None)
    if services is None:
        return HealthStatus(
            source_id=source_id,
            healthy=False,
            latency_ms=0,
            error="Fabric authentication is not configured",
        )
    adapter = get_adapter("fabric_sql", fabric_services=services, source_id=source_id)
    status = await adapter.probe(config)
    return status
