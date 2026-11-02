"""Admin authentication and CSRF middleware.

AUDIT-COVERS: P0-F (admin auth), SR-7 (CSRF), SR-8 (secure cookies).

Sequence per request:
  1. Bypass list (``_BYPASS_PREFIXES``: /health, /ready, /auth/login,
     /auth/oidc, /auth/csrf, /static/) - pass through.
  2. Look up signed session cookie. If invalid/expired -> 302 to /auth/login
     for HTML or 401 JSON for non-HTML clients.
  3. An admin still on a default password reaches only the change-password
     page and logout: HTML is redirected there, htmx gets ``HX-Redirect`` and
     API calls a 403 ``password_change_required``.
  4. For unsafe methods (POST/PUT/PATCH/DELETE), check the ``X-CSRF-Token``
     header against Redis. Missing or mismatching -> 403.
  5. Inject the resolved AdminSession into ``request.state.admin``.

The header is the only accepted carrier, deliberately. This docstring once
also promised a form-field alternative; no such support ever existed - the
request body is never read here - and adding it would make the control
*weaker*, not more convenient. A cross-origin HTML form can post fields but
cannot set a custom header, which is exactly why a header-only check defeats
form-POST CSRF. It would also mean consuming the request body in middleware
and replaying it to the route beneath.

Every admin mutation goes through htmx, and ``static/js/dashboard.js`` attaches
the header globally for all four unsafe verbs, so no form needs to carry it.

The middleware is intentionally Redis-backed so the admin can scale
horizontally (SR-6 will reuse the same backend for the rate limiter in
Phase 2).
"""

from __future__ import annotations

import hmac
import logging
from collections.abc import Callable
from typing import Any

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse, Response

from interlock.admin.audit import audit_admin_action
from interlock.admin.auth import (
    UNSAFE_METHODS,
    get_csrf_token,
    invalidate_session,
    resolve_session,
    verify_cookie,
)
from interlock.admin.roles import CONSOLE_ADMIN_ROLES

logger = logging.getLogger(__name__)


# Paths that bypass auth entirely.
_BYPASS_PREFIXES = (
    "/health",
    "/ready",
    "/auth/login",
    "/auth/oidc",
    "/auth/csrf",
    "/static/",
)

_ADMIN_OWNER_ROLES = CONSOLE_ADMIN_ROLES
# Read-only console users. Added to every read rule below that names a role,
# and never to a mutation rule or the mutation fallback.
_ADMIN_VIEWER_ROLES = frozenset({"viewer"})
_ADMIN_OPERATOR_READ_ROLES = (
    frozenset({"auditor", "source_admin", "policy_admin", "approval_reviewer", "security_admin"})
    | _ADMIN_VIEWER_ROLES
)
_ADMIN_MUTATION_FALLBACK_ROLES = frozenset({"security_admin"})
# An empty rule admits only owner and admin.
_ADMIN_ONLY: frozenset[str] = frozenset()

_ADMIN_MUTATION_RULES: tuple[tuple[str, frozenset[str]], ...] = (
    # Console users, and the SSO subjects that decide which console account an
    # SSO login becomes, are for administrators only.
    ("/dashboard/admin-users", _ADMIN_ONLY),
    ("/api/admin-users", _ADMIN_ONLY),
    ("/api/admin-auth/oidc/admins", _ADMIN_ONLY),
    ("/dashboard/source-wizard", frozenset({"source_admin", "security_admin"})),
    ("/dashboard/data-sources", frozenset({"source_admin", "security_admin"})),
    ("/api/data-sources", frozenset({"source_admin", "security_admin"})),
    ("/dashboard/connectors", frozenset({"source_admin", "security_admin"})),
    ("/api/connectors", frozenset({"source_admin", "security_admin"})),
    ("/dashboard/discovery/rescan", frozenset({"source_admin", "security_admin"})),
    ("/dashboard/policies", frozenset({"policy_admin", "security_admin"})),
    ("/api/policies", frozenset({"policy_admin", "security_admin"})),
    ("/dashboard/access-control", frozenset({"security_admin"})),
    ("/api/identities", frozenset({"security_admin"})),
    ("/api/source-roles", frozenset({"security_admin"})),
    ("/api/admin-auth/oidc", frozenset({"security_admin"})),
    ("/api/approvals", frozenset({"approval_reviewer", "security_admin"})),
    ("/dashboard/write-safety", frozenset({"approval_reviewer", "security_admin"})),
    ("/dashboard/alerts", frozenset({"security_admin"})),
    ("/api/alerts", frozenset({"security_admin"})),
    ("/dashboard/ingestion", frozenset({"source_admin", "security_admin"})),
    ("/api/ingestion", frozenset({"source_admin", "security_admin"})),
)


def _readable_by_viewer(
    rules: tuple[tuple[str, frozenset[str]], ...],
) -> tuple[tuple[str, frozenset[str]], ...]:
    """Let read-only console users read everything an operator role may read."""
    return tuple(
        (prefix, roles | _ADMIN_VIEWER_ROLES if roles else roles) for prefix, roles in rules
    )


_ADMIN_READ_RULES: tuple[tuple[str, frozenset[str]], ...] = _readable_by_viewer(
    (
        ("/dashboard/admin-users", _ADMIN_ONLY),
        ("/api/admin-users", _ADMIN_ONLY),
        ("/api/admin-auth/oidc/admins", _ADMIN_ONLY),
        ("/", _ADMIN_OPERATOR_READ_ROLES),
        ("/openapi.json", frozenset({"security_admin"})),
        ("/docs", frozenset({"security_admin"})),
        ("/redoc", frozenset({"security_admin"})),
        ("/dashboard/overview", _ADMIN_OPERATOR_READ_ROLES),
        ("/dashboard/source-wizard", frozenset({"source_admin", "security_admin"})),
        ("/dashboard/data-sources", frozenset({"source_admin", "security_admin"})),
        ("/dashboard/connectors", frozenset({"source_admin", "security_admin"})),
        ("/dashboard/access-control", frozenset({"security_admin"})),
        ("/dashboard/policies", frozenset({"policy_admin", "security_admin"})),
        ("/dashboard/policy-analytics", frozenset({"policy_admin", "security_admin"})),
        ("/dashboard/audit-costs", frozenset({"auditor", "security_admin"})),
        ("/dashboard/audit-costs/export.csv", frozenset({"auditor", "security_admin"})),
        ("/dashboard/write-safety", frozenset({"approval_reviewer", "security_admin"})),
        ("/dashboard/proxy", frozenset({"auditor", "security_admin"})),
        ("/dashboard/proxy-monitor", frozenset({"auditor", "security_admin"})),
        ("/dashboard/ingestion", frozenset({"source_admin", "security_admin"})),
        ("/dashboard/workers", frozenset({"source_admin", "security_admin"})),
        ("/dashboard/discovery", frozenset({"source_admin", "security_admin", "auditor"})),
        (
            "/dashboard/catalog",
            frozenset({"source_admin", "security_admin", "auditor", "policy_admin"}),
        ),
        ("/dashboard/categories", frozenset({"source_admin", "security_admin", "auditor"})),
        ("/dashboard/entities", frozenset({"source_admin", "security_admin", "auditor"})),
        ("/dashboard/alerts", frozenset({"security_admin"})),
        ("/api/data-sources", frozenset({"source_admin", "security_admin"})),
        ("/api/connectors", frozenset({"source_admin", "security_admin"})),
        ("/api/identities", frozenset({"security_admin"})),
        ("/api/source-roles", frozenset({"security_admin"})),
        ("/api/policies", frozenset({"policy_admin", "security_admin"})),
        ("/api/approvals", frozenset({"approval_reviewer", "security_admin"})),
        ("/api/ingestion", frozenset({"source_admin", "security_admin"})),
        (
            "/api/catalog",
            frozenset({"source_admin", "security_admin", "auditor", "policy_admin"}),
        ),
    )
)
_ADMIN_ROUTE_PREFIXES = (
    "/dashboard",
    "/api",
    "/docs",
    "/redoc",
    "/openapi.json",
)


def _is_bypass(path: str) -> bool:
    return any(
        path == p
        or path.startswith(p + "/")
        or path == p
        or (p.endswith("/") and path.startswith(p))
        for p in _BYPASS_PREFIXES
    )


def _wants_html(request: Request) -> bool:
    accept = request.headers.get("accept", "")
    # HTMX adds HX-Request: true; we treat HTMX as JSON-flavored to keep
    # error swap simple. Browsers without HTMX get 302 redirect to login.
    if request.headers.get("hx-request") == "true":
        return False
    return "text/html" in accept and "application/json" not in accept


def _unauthenticated(request: Request, message: str) -> Response:
    if _wants_html(request):
        return RedirectResponse(url="/auth/login", status_code=302)
    return JSONResponse({"error": message}, status_code=401)


# All an admin on a default password may reach until it is changed. /auth/csrf
# and /static/ already bypass authentication entirely.
_PASSWORD_CHANGE_ALLOWED = ("/auth/change-password", "/auth/logout")


def _reachable_before_password_change(path: str) -> bool:
    return path in _PASSWORD_CHANGE_ALLOWED


def _password_change_required(request: Request) -> Response:
    """Send an admin on a default password to the change page, whatever they asked for."""
    target = _PASSWORD_CHANGE_ALLOWED[0]
    if request.headers.get("hx-request") == "true":
        return Response(status_code=200, headers={"HX-Redirect": target})
    if _wants_html(request):
        return RedirectResponse(url=target, status_code=302)
    return JSONResponse({"error": "password_change_required"}, status_code=403)


def _has_any_role(session_roles: tuple[str, ...], allowed: frozenset[str]) -> bool:
    roles = {role.strip().lower() for role in session_roles}
    return bool(roles & _ADMIN_OWNER_ROLES) or bool(roles & allowed)


def _required_admin_roles(path: str, method: str) -> frozenset[str] | None:
    if path == "/api/fabric/oauth/callback":
        return frozenset({"source_admin", "security_admin"})
    unsafe = method.upper() in UNSAFE_METHODS
    if unsafe:
        for prefix, roles in _ADMIN_MUTATION_RULES:
            if path == prefix or path.startswith(prefix + "/"):
                return roles
        if _is_admin_route(path):
            return _ADMIN_MUTATION_FALLBACK_ROLES
    for prefix, roles in _ADMIN_READ_RULES:
        if path == prefix or path.startswith(prefix + "/"):
            return roles
    if _is_admin_route(path):
        return _ADMIN_OPERATOR_READ_ROLES
    return None


def required_roles(path: str, method: str) -> frozenset[str] | None:
    """Admin roles, besides owner and admin, that may make this request.

    None means the route needs a session but no particular role. Public so the
    documentation's admin-roles reference is generated from the rules the
    middleware enforces rather than restated by hand.
    """
    return _required_admin_roles(path, method)


def _is_admin_route(path: str) -> bool:
    return any(path == prefix or path.startswith(prefix + "/") for prefix in _ADMIN_ROUTE_PREFIXES)


class AdminAuthMiddleware(BaseHTTPMiddleware):
    """Require an authenticated admin session for all non-bypass routes."""

    def __init__(
        self,
        app: Any,
        cookie_name: str,
        secret_key: str,
    ) -> None:
        super().__init__(app)
        self._cookie_name = cookie_name
        self._secret_key = secret_key

    async def dispatch(self, request: Request, call_next: Callable[..., Any]) -> Response:
        path = request.url.path
        if _is_bypass(path):
            return await call_next(request)

        # Test-only seam: when an explicit flag is set on app.state the
        # middleware lets the request through. The flag is per-app-instance
        # and never read from the environment, so production deployments
        # cannot accidentally enable it. Used by unit tests that mount the
        # admin app with mocked dependencies.
        if getattr(request.app.state, "auth_disabled", False):
            return await call_next(request)

        cookie_token = request.cookies.get(self._cookie_name)
        payload = verify_cookie(cookie_token or "", self._secret_key)
        if not payload:
            return _unauthenticated(request, "Authentication required")

        sid = payload.get("sid")
        if not sid:
            return _unauthenticated(request, "Authentication required")

        redis = getattr(request.app.state, "redis", None)
        if redis is None:
            # Fail closed if Redis is missing - never silently allow.
            return JSONResponse({"error": "Auth backend unavailable"}, status_code=503)

        session = await resolve_session(redis, sid)
        if session is None:
            return _unauthenticated(request, "Session expired")

        pool = getattr(request.app.state, "pg_pool", None)
        if pool is None:
            return JSONResponse({"error": "Auth backend unavailable"}, status_code=503)
        try:
            current_admin = await pool.fetchrow(
                """
                SELECT enabled, authorization_version
                FROM admin_identities
                WHERE id = $1
                """,
                session.admin_id,
            )
        except Exception:
            logger.exception("Admin authorization-version check failed")
            return JSONResponse({"error": "Auth backend unavailable"}, status_code=503)
        if (
            current_admin is None
            or not current_admin["enabled"]
            or int(current_admin["authorization_version"]) != session.authorization_version
        ):
            await invalidate_session(redis, sid)
            return _unauthenticated(request, "Session revoked")

        if session.must_change_password and not _reachable_before_password_change(path):
            return _password_change_required(request)

        required_roles = _required_admin_roles(path, request.method)
        if required_roles is not None and not _has_any_role(session.roles, required_roles):
            request.state.admin = session
            await audit_admin_action(
                request,
                action=f"{request.method.upper()} {path}",
                resource="admin_route",
                resource_id=path,
                success=False,
                detail={
                    "required_roles": sorted(required_roles),
                    "admin_roles": list(session.roles),
                    "status_code": 403,
                    "reason": "rbac_denied",
                },
                error="Admin role does not allow this action",
            )
            return JSONResponse(
                {"error": "Admin role does not allow this action"},
                status_code=403,
            )

        # CSRF enforcement for unsafe methods. Unconditional: a comment here
        # once described a Bearer-token bypass for the bootstrap admin API key
        # flow, but no such branch exists in this file or anywhere else - the
        # check below runs for every unsafe method regardless of Authorization.
        if request.method.upper() in UNSAFE_METHODS:
            csrf_header = request.headers.get("x-csrf-token", "")
            expected = await get_csrf_token(redis, sid)
            if not expected or not csrf_header or not hmac.compare_digest(csrf_header, expected):
                request.state.admin = session
                await audit_admin_action(
                    request,
                    action=f"{request.method.upper()} {path}",
                    resource="admin_route",
                    resource_id=path,
                    success=False,
                    detail={"status_code": 403, "reason": "csrf_failed"},
                    error="Invalid or missing CSRF token",
                )
                return JSONResponse(
                    {"error": "Invalid or missing CSRF token"},
                    status_code=403,
                )

        request.state.admin = session
        try:
            response = await call_next(request)
        except Exception as exc:
            if request.method.upper() in UNSAFE_METHODS:
                await audit_admin_action(
                    request,
                    action=f"{request.method.upper()} {path}",
                    resource="admin_route",
                    resource_id=path,
                    success=False,
                    detail={"reason": "exception"},
                    error=f"{type(exc).__name__}: {exc}",
                )
            raise
        if request.method.upper() in UNSAFE_METHODS:
            await audit_admin_action(
                request,
                action=f"{request.method.upper()} {path}",
                resource="admin_route",
                resource_id=path,
                success=response.status_code < 400,
                detail={
                    "status_code": response.status_code,
                    "required_roles": sorted(required_roles) if required_roles else [],
                    "admin_roles": list(session.roles),
                },
                error=None if response.status_code < 400 else f"HTTP {response.status_code}",
            )
        return response
