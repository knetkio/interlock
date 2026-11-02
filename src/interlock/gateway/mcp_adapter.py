"""MCP (Model Context Protocol) adapter - exposes InterLock tools via HTTP endpoints.

Provides the MCP JSON-RPC Streamable HTTP endpoint plus legacy compatibility
routes for one beta release cycle.

Endpoints:
    POST /mcp             -> JSON-RPC 2.0 (JSON or request-scoped SSE)
    POST /mcp/tools/list  -> {"tools": [...]}
    POST /mcp/tools/call  -> {"content": [...]}
    GET  /mcp/sse         -> event: tools
"""

from __future__ import annotations

import base64
import contextvars
import hashlib
import json
import logging
import time
from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

import asyncpg
from starlette.requests import Request
from starlette.responses import JSONResponse, Response, StreamingResponse
from starlette.routing import Route

from interlock import release_version
from interlock.cache.provenance import redaction_of, with_redaction
from interlock.catalog.collectors import ENFORCED_CONNECTOR_KEYS as _CATALOG_ENFORCED_CONNECTORS
from interlock.connections.connectors import connector_key_for, get_adapter
from interlock.connections.fabric.runtime import FabricAuthenticatedSource
from interlock.core.normalizer import (
    DEFAULT_DIALECT,
    compute_cache_key,
    normalize_sql,
)
from interlock.core.sql_governance import resolve_table, table_spellings
from interlock.core.write_classifier import WriteClassifier
from interlock.discovery.search import DiscoverySearch
from interlock.errors import (
    CacheBarrierUnavailableError,
    DataSourceNotFoundError,
    DataSourceUnavailableError,
)
from interlock.gateway.pipeline import (
    GatewayPipeline,
    GatewayRequest,
    bearer_token_from_headers,
    current_cache_source_generation,
)
from interlock.metadata.registry import MetadataRegistry
from interlock.models import CacheResult, IdentityContext
from interlock.observability.health import correlation_id_from_request

logger = logging.getLogger(__name__)

# The correlation ID of the tool call being handled. Set once per call so every
# audit row it writes, success, cache hit, denial or failure, carries the ID the
# client sent (or one chosen for it), and the agent's error text can quote it.
_CALL_CORRELATION_ID: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "mcp_call_correlation_id", default=None
)


# ---------------------------------------------------------------------------
# Tool definitions (MCP schema)
# ---------------------------------------------------------------------------

_INTERLOCK_MCP_TOOLS: list[dict[str, Any]] = [
    {
        "name": "interlock_query",
        "description": "Execute a SQL query against a registered data source",
        "inputSchema": {
            "type": "object",
            "properties": {
                "source_id": {
                    "type": "string",
                    "description": "Data source identifier",
                },
                "sql": {
                    "type": "string",
                    "description": "SQL query to execute",
                },
            },
            "required": ["source_id", "sql"],
        },
    },
    {
        "name": "interlock_list_sources",
        "description": "List registered data sources visible to the caller",
        "inputSchema": {
            "type": "object",
            "properties": {},
        },
    },
    {
        "name": "interlock_describe_source",
        "description": "Get schema information for a data source",
        "inputSchema": {
            "type": "object",
            "properties": {
                "source_id": {
                    "type": "string",
                    "description": "Data source identifier",
                },
            },
            "required": ["source_id"],
        },
    },
    {
        "name": "interlock_discover",
        "description": "Search the discovery index for relevant data assets",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Natural language search query",
                },
                "source_id": {
                    "type": "string",
                    "description": "Required data source scope",
                },
                "source_types": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Optional source type filters",
                },
                "doc_types": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Optional document type filters",
                },
                "category_path": {
                    "type": "string",
                    "description": "Optional hierarchical category path",
                },
                "time_range": {
                    "type": "object",
                    "description": "Optional time range filter",
                },
                "audience": {
                    "type": "string",
                    "description": "Optional audience filter",
                },
                "entities": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Optional entity filters",
                },
                "include_related": {
                    "type": "boolean",
                    "description": "Whether to include related documents",
                    "default": False,
                },
                "limit": {
                    "type": "integer",
                    "description": "Maximum number of results (default 10)",
                    "default": 10,
                },
            },
            "required": ["query", "source_id"],
        },
    },
    {
        "name": "interlock_related_documents",
        "description": "Find documents related to a discovery asset within the same authorized source",
        "inputSchema": {
            "type": "object",
            "properties": {
                "asset_id": {
                    "type": "integer",
                    "description": "Discovery asset identifier",
                },
                "limit": {
                    "type": "integer",
                    "description": "Maximum number of related documents (default 10)",
                    "default": 10,
                },
            },
            "required": ["asset_id"],
        },
    },
]

MCP_TOOLS: list[dict[str, Any]] = [*_INTERLOCK_MCP_TOOLS]
for _tool in _INTERLOCK_MCP_TOOLS:
    _legacy = dict(_tool)
    _legacy["name"] = str(_tool["name"]).replace("interlock_", "agentgate_", 1)
    _legacy["description"] = "Deprecated InterLock compatibility alias; use " + str(_tool["name"])
    MCP_TOOLS.append(_legacy)

# Added after the alias loop on purpose: this tool never existed under an
# `agentgate_` name, and minting a deprecated alias for something new would
# advertise a surface nobody can have been using.
DESCRIBE_ACCESS_TOOL: dict[str, Any] = {
    "name": "interlock_describe_access",
    "description": (
        "List the actions the caller's source roles allow and deny on each granted "
        "data source, and for SQL sources the tables and columns the caller may "
        "read, with any table a policy would refuse marked. Use this to plan "
        "before querying rather than discovering limits by being refused. Policy "
        "rules may still restrict an individual request, so an allowed action "
        "here is permission to attempt, not a guarantee of success."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            "source_id": {
                "type": "string",
                "description": "Limit the answer to one source. Omit for every granted source.",
            },
        },
        "required": [],
    },
}
MCP_TOOLS.append(DESCRIBE_ACCESS_TOOL)

_LEGACY_TOOL_ALIASES = {
    "query": "agentgate_query",
    "list_sources": "agentgate_list_sources",
    "describe_source": "agentgate_describe_source",
    "discover": "agentgate_discover",
    "related_documents": "agentgate_related_documents",
    "interlock_query": "agentgate_query",
    "interlock_list_sources": "agentgate_list_sources",
    "interlock_describe_source": "agentgate_describe_source",
    "interlock_discover": "agentgate_discover",
    "interlock_related_documents": "agentgate_related_documents",
}

_DEFAULT_MAX_MCP_REQUEST_BYTES = 1_048_576
_MAX_CONFIGURED_MCP_REQUEST_BYTES = 16 * 1_048_576
_DEFAULT_MAX_TOOL_LIMIT = 100
_MAX_CONFIGURED_TOOL_LIMIT = 1_000
MCP_PROTOCOL_VERSION = "2026-07-28"
# The handshake-era versions every mainstream client speaks. They negotiate
# with `initialize` and send none of the mirrored headers the 2026 dialect
# requires, so the two are served as separate dialects rather than one relaxed
# superset - relaxing 2026 would drop a real integrity check for the clients
# that do implement it.
MCP_HANDSHAKE_PROTOCOL_VERSIONS = ("2025-03-26", "2025-06-18", "2025-11-25")
MCP_LATEST_HANDSHAKE_PROTOCOL_VERSION = "2025-11-25"
# MCP 2025-06-18: when the header is absent on a non-initialize request the
# server "SHOULD assume protocol version 2025-03-26".
_MCP_DEFAULT_HANDSHAKE_VERSION = "2025-03-26"
_MODERN_MCP_PROTOCOL_VERSIONS = frozenset({MCP_PROTOCOL_VERSION})
_SUPPORTED_MCP_PROTOCOL_VERSIONS = frozenset(MCP_HANDSHAKE_PROTOCOL_VERSIONS) | (
    _MODERN_MCP_PROTOCOL_VERSIONS
)
# `version` is what every connected agent reads back from `serverInfo`, so it
# comes from the package rather than a literal - the console sidebar carried a
# literal here for six releases before anybody noticed.
_MCP_SERVER_INFO = {
    "name": "interlock",
    "title": "InterLock",
    "version": release_version(),
    "description": "Governed agent access to enterprise data sources.",
}


class _MCPIngressError(Exception):
    """Deterministic client-facing ingress error."""

    def __init__(self, status_code: int, error: str) -> None:
        super().__init__(error)
        self.status_code = status_code
        self.error = error


# ---------------------------------------------------------------------------
# Serialization helper
# ---------------------------------------------------------------------------


def _default_serializer(obj: Any) -> Any:
    """JSON fallback serializer for datetime and other non-standard types."""
    if hasattr(obj, "isoformat"):
        return obj.isoformat()
    return str(obj)


# ---------------------------------------------------------------------------
# MCPAdapter
# ---------------------------------------------------------------------------


def _detection_entity_type(detection: Any) -> str | None:
    """The entity type of one scanner detection, whatever shape it arrives in.

    The scanner returns `PIIMatch` models whose field is `entity_type`. This
    used to read `d["type"]` behind an `isinstance(d, dict)` guard, so no
    detection ever matched: `pii_detected` was set while `pii_types` stayed
    empty on every row the scanner touched.
    """
    entity = getattr(detection, "entity_type", None)
    if entity:
        return str(entity)
    if isinstance(detection, dict):
        value = detection.get("entity_type") or detection.get("type")
        if value:
            return str(value)
    return None


class MCPAdapter:
    """Exposes InterLock capabilities as MCP-compatible tool endpoints.

    Dependencies (pg_pool, registry) can be supplied at init time for
    testing, or resolved at request time from ``request.app.state`` for
    production use where the adapter is instantiated before the lifespan
    wires up the real resources.
    """

    def __init__(
        self,
        pg_pool: asyncpg.Pool | None = None,
        registry: MetadataRegistry | None = None,
        discovery_search: DiscoverySearch | None = None,
        *,
        max_request_bytes: int = _DEFAULT_MAX_MCP_REQUEST_BYTES,
        max_tool_limit: int = _DEFAULT_MAX_TOOL_LIMIT,
    ) -> None:
        self._pool = pg_pool
        self._registry = registry
        self._discovery = discovery_search
        self._max_request_bytes = _clamp_int(
            max_request_bytes,
            default=_DEFAULT_MAX_MCP_REQUEST_BYTES,
            minimum=1,
            maximum=_MAX_CONFIGURED_MCP_REQUEST_BYTES,
        )
        self._max_tool_limit = _clamp_int(
            max_tool_limit,
            default=_DEFAULT_MAX_TOOL_LIMIT,
            minimum=1,
            maximum=_MAX_CONFIGURED_TOOL_LIMIT,
        )

    # -- Route wiring -------------------------------------------------------

    def get_routes(self) -> list[Route]:
        """Return Starlette routes for MCP endpoints."""
        return [
            Route("/mcp", self.streamable_http, methods=["POST"]),
            Route("/mcp/tools/list", self.list_tools, methods=["POST", "GET"]),
            Route("/mcp/tools/call", self.call_tool, methods=["POST"]),
            Route("/mcp/sse", self.sse, methods=["GET"]),
        ]

    async def streamable_http(self, request: Request) -> Response:
        """Serve stateless MCP Streamable HTTP over JSON-RPC 2.0."""
        origin_error = _validate_mcp_origin(request)
        if origin_error is not None:
            return origin_error
        content_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
        if content_type != "application/json":
            return _jsonrpc_http_error(None, -32600, "Content-Type must be application/json", 415)
        accept = request.headers.get("accept", "").lower()
        if "application/json" not in accept or "text/event-stream" not in accept:
            return _jsonrpc_http_error(
                None,
                -32600,
                "Accept must include application/json and text/event-stream",
                406,
            )
        try:
            message = await _read_mcp_json_body(request, max_bytes=self._max_request_bytes)
        except _MCPIngressError as exc:
            code = -32700 if exc.error == "invalid_json" else -32600
            return _jsonrpc_http_error(None, code, exc.error, exc.status_code)

        request_id = message.get("id")
        if message.get("jsonrpc") != "2.0" or not isinstance(message.get("method"), str):
            return _jsonrpc_http_error(request_id, -32600, "Invalid Request", 400)
        method = str(message["method"])
        params = message.get("params", {})
        if params is None:
            params = {}
        if not isinstance(params, dict):
            return _jsonrpc_http_error(request_id, -32602, "Invalid params", 400)

        dialect = _resolve_mcp_dialect(
            request,
            request_id=request_id,
            method=method,
            params=params,
        )
        if isinstance(dialect, JSONResponse):
            return dialect

        if dialect.modern:
            metadata_error = _validate_streamable_request_metadata(
                request,
                request_id=request_id,
                method=method,
                params=params,
                version=dialect.version,
            )
            if metadata_error is not None:
                return metadata_error

        if request_id is None:
            if method.startswith("notifications/"):
                return Response(status_code=202)
            return _jsonrpc_http_error(None, -32600, "Request id is required", 400)

        if method == "initialize" and not dialect.modern:
            # Not wrapped by _complete_mcp_result: handshake clients validate
            # this result strictly and reject unknown keys.
            payload = {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": _initialize_result(dialect.version),
            }
            if _prefers_sse(accept):
                return _jsonrpc_sse_response(payload)
            return JSONResponse(payload)
        if method == "ping" and not dialect.modern:
            # The deployed TypeScript SDK validates EmptyResult strictly, so
            # this must be exactly {} - no resultType, no _meta.
            payload = {"jsonrpc": "2.0", "id": request_id, "result": {}}
            if _prefers_sse(accept):
                return _jsonrpc_sse_response(payload)
            return JSONResponse(payload)

        if method == "server/discover":
            result: dict[str, Any] = _complete_mcp_result(
                {
                    "supportedVersions": [MCP_PROTOCOL_VERSION],
                    "capabilities": {"tools": {"listChanged": False}},
                    "instructions": (
                        "All tool execution is governed by InterLock source roles and policy."
                    ),
                    "ttlMs": 3_600_000,
                    "cacheScope": "public",
                }
            )
        elif method == "tools/list":
            result = _complete_mcp_result(
                {"tools": MCP_TOOLS, "ttlMs": 60_000, "cacheScope": "public"}
            )
        elif method == "tools/call":
            name = params.get("name")
            arguments = params.get("arguments", {})
            if not isinstance(name, str) or not isinstance(arguments, dict):
                return _jsonrpc_http_error(request_id, -32602, "Invalid tool call params", 400)
            try:
                if _prefers_sse(accept):
                    return _jsonrpc_sse_factory_response(
                        request_id,
                        lambda: self._execute_streamable_tool(
                            request, name, arguments, modern=dialect.modern
                        ),
                    )
                result = await self._execute_streamable_tool(
                    request, name, arguments, modern=dialect.modern
                )
            except _MCPIngressError as exc:
                return _jsonrpc_http_error(
                    request_id,
                    -32602 if exc.status_code < 500 else -32603,
                    exc.error,
                    exc.status_code,
                )
        else:
            return _jsonrpc_http_error(request_id, -32601, "Method not found", 404)

        payload = {"jsonrpc": "2.0", "id": request_id, "result": result}
        if _prefers_sse(accept):
            return _jsonrpc_sse_response(payload)
        return JSONResponse(payload)

    async def _execute_streamable_tool(
        self,
        request: Request,
        name: str,
        arguments: dict[str, Any],
        *,
        modern: bool = True,
    ) -> dict[str, Any]:
        """Execute a tool lazily so SSE disconnect cancellation reaches upstream work."""
        legacy_payload = json.dumps({"name": name, "arguments": arguments}).encode("utf-8")
        consumed = False

        async def receive() -> dict[str, Any]:
            nonlocal consumed
            if consumed:
                return {"type": "http.request", "body": b"", "more_body": False}
            consumed = True
            return {"type": "http.request", "body": legacy_payload, "more_body": False}

        delegated = Request(request.scope, receive)
        response = await self.call_tool(delegated)
        try:
            result_payload = json.loads(response.body)
        except (AttributeError, json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise _MCPIngressError(500, "Internal error") from exc
        if response.status_code == 202:
            return _complete_mcp_result(_queued_write_result(result_payload))
        if response.status_code >= 400:
            message_text = result_payload.get("error", "Tool call failed")
            if isinstance(result_payload.get("content"), list):
                content = result_payload["content"]
                if content and isinstance(content[0], dict):
                    message_text = content[0].get("text", message_text)
            if not modern and response.status_code in _HANDSHAKE_TOOL_ERROR_STATUSES:
                return _complete_mcp_result(
                    _refusal_result(str(message_text), response.status_code)
                )
            raise _MCPIngressError(response.status_code, str(message_text))
        return _complete_mcp_result(result_payload)

    # -- Dependency resolution ----------------------------------------------

    def _resolve_pool(self, request: Request) -> asyncpg.Pool | None:
        """Return the PG pool - prefer init-time, fall back to app.state."""
        if self._pool is not None:
            return self._pool
        state = getattr(getattr(request, "app", None), "state", None)
        if state is None:
            return None
        return getattr(state, "pg_pool", None)

    def _resolve_registry(self, request: Request) -> MetadataRegistry | None:
        """Return the registry - prefer init-time, fall back to app.state."""
        if self._registry is not None:
            return self._registry
        state = getattr(getattr(request, "app", None), "state", None)
        if state is None:
            return None
        return getattr(state, "registry", None)

    def _resolve_discovery(self, request: Request) -> DiscoverySearch | None:
        """Return the DiscoverySearch - prefer init-time, fall back to app.state."""
        if self._discovery is not None:
            return self._discovery
        state = getattr(getattr(request, "app", None), "state", None)
        if state is None:
            return None
        return getattr(state, "discovery_search", None)

    # -- Auth helpers -------------------------------------------------------

    async def _authenticate_request(self, request: Request) -> IdentityContext | None:
        """Extract API key from Authorization header and authenticate."""
        auth_header = request.headers.get("authorization", "")
        if not auth_header.startswith("Bearer "):
            return None
        api_key = auth_header[7:]
        auth_mgr = getattr(getattr(request, "app", None), "state", None)
        auth_mgr = getattr(auth_mgr, "auth_manager", None) if auth_mgr else None
        if auth_mgr is None:
            return None  # Auth not configured
        try:
            return await auth_mgr.authenticate(api_key)
        except Exception:
            return None

    # Map MCP tool names to policy operation types
    _TOOL_OPERATION_MAP: dict[str, str] = {
        "agentgate_query": "read",
        "interlock_describe_access": "read",
        "agentgate_list_sources": "read",
        "agentgate_describe_source": "read",
        "agentgate_discover": "discovery",
        "agentgate_related_documents": "discovery",
    }

    async def _check_policy(
        self,
        request: Request,
        identity: IdentityContext,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> JSONResponse | None:
        """Evaluate policy for the given identity and tool. Returns error response if denied, else None."""
        state = getattr(getattr(request, "app", None), "state", None)
        policy_engine = getattr(state, "policy_engine", None) if state else None
        if policy_engine is None:
            return None  # Policy not configured
        operation = self._TOOL_OPERATION_MAP.get(tool_name, tool_name)
        source_id = arguments.get("source_id") or "__control__"
        decision = policy_engine.evaluate(
            identity=identity,
            source_id=source_id,
            operation=operation,
        )
        if not decision.allowed:
            return JSONResponse(
                {"error": f"Policy denied: {decision.reason}"},
                status_code=403,
            )
        return None

    # -- Handlers -----------------------------------------------------------

    async def list_tools(self, request: Request) -> JSONResponse:
        """Return the catalogue of available MCP tools."""
        return JSONResponse({"tools": MCP_TOOLS})

    async def sse(self, request: Request) -> StreamingResponse:
        """Return a finite SSE catalogue event for HTTP/SSE MCP clients."""

        async def events():
            yield (
                "event: tools\n"
                f"data: {json.dumps({'tools': MCP_TOOLS}, default=_default_serializer)}\n\n"
            )

        return StreamingResponse(
            events(),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "X-Accel-Buffering": "no",
            },
        )

    async def call_tool(self, request: Request) -> JSONResponse:
        """Dispatch an MCP tool call to the appropriate handler."""
        token = _CALL_CORRELATION_ID.set(correlation_id_from_request(request))
        try:
            return await self._call_tool(request)
        finally:
            _CALL_CORRELATION_ID.reset(token)

    async def _call_tool(self, request: Request) -> JSONResponse:
        try:
            body = await _read_mcp_json_body(request, max_bytes=self._max_request_bytes)
            tool_name = _parse_tool_name(body)
            arguments = _parse_tool_arguments(body, tool_name, self._max_tool_limit)
        except _MCPIngressError as exc:
            return JSONResponse({"error": exc.error}, status_code=exc.status_code)

        # Errors quote the name the caller used. Canonicalising first and then
        # reporting `agentgate_query` to a client that called `interlock_query`
        # sends the operator looking for a tool they never invoked, and
        # advertises a deprecated alias while doing it.
        requested_name = tool_name
        tool_name = _LEGACY_TOOL_ALIASES.get(tool_name, tool_name)
        handler = {
            "agentgate_query": self._execute_query,
            "agentgate_list_sources": self._list_sources,
            "interlock_describe_access": self._describe_access,
            "agentgate_describe_source": self._describe_source,
            "agentgate_discover": self._discover,
            "agentgate_related_documents": self._related_documents,
        }.get(tool_name)
        if handler is None:
            return JSONResponse(
                {"error": f"Unknown tool: {tool_name}"},
                status_code=404,
            )

        operation = self._TOOL_OPERATION_MAP.get(tool_name, "read")
        normalized_request = None
        tables: list[str] | None = None
        sql = arguments.get("sql")
        if tool_name == "agentgate_related_documents" and not arguments.get("source_id"):
            asset_id = arguments.get("asset_id")
            if asset_id is None:
                return JSONResponse(_text_content("asset_id is required"), status_code=400)
            pool = self._resolve_pool(request)
            if pool is not None:
                try:
                    seed = await pool.fetchrow(
                        "SELECT source_id FROM discovery_assets WHERE id = $1",
                        int(asset_id),
                    )
                except Exception:
                    logger.debug("MCP related-documents source lookup failed", exc_info=True)
                else:
                    if seed is None:
                        return JSONResponse(_text_content("Asset not found"), status_code=404)
                    arguments["source_id"] = str(seed["source_id"])
            if not arguments.get("source_id"):
                return JSONResponse(
                    _text_content("Unable to resolve the asset source safely"),
                    status_code=503,
                )
        source_registry = self._resolve_registry(request)
        saved_source = (
            source_registry.get(str(arguments.get("source_id") or ""))
            if source_registry is not None
            else None
        )
        saved_connector_key = (
            connector_key_for(saved_source.source_type.value, saved_source.metadata)
            if saved_source is not None
            else None
        )
        if (
            tool_name == "agentgate_query"
            and isinstance(sql, str)
            and saved_source is not None
            and saved_connector_key == "fabric_sql"
        ):
            from interlock.connections.fabric.adapter import FabricSQLAdapter

            fabric_adapter = get_adapter("fabric_sql")
            assert isinstance(fabric_adapter, FabricSQLAdapter)
            try:
                fabric_adapter.validate_sql(
                    sql, database=saved_source.connection_config.get("database")
                )
            except ValueError as exc:
                return JSONResponse({"error": str(exc)}, status_code=400)
        if tool_name == "agentgate_query" and isinstance(sql, str):
            source_id_for_parse = str(arguments.get("source_id") or "")
            operation = _sql_operation(sql, self._dialect_for_source(request, source_id_for_parse))
            try:
                normalized = normalize_sql(
                    sql,
                    source_id_for_parse,
                    dialect=self._dialect_for_source(request, source_id_for_parse),
                )
                normalized_request = normalized[0] if isinstance(normalized, list) else normalized
                statements = normalized if isinstance(normalized, list) else [normalized]
                # Every statement's tables, not the first statement's: the PG wire
                # let `SELECT 1; SELECT * FROM orders` past a deny on `orders` this
                # way. MCP is contained by asyncpg refusing several commands per
                # call, but governance should not depend on the driver for that.
                seen: dict[str, None] = {}
                for statement in statements:
                    for table in getattr(statement, "tables", []) or []:
                        seen.setdefault(table, None)
                tables = list(seen)
            except Exception:
                logger.debug("MCP SQL normalization failed before preflight", exc_info=True)

        if (
            tool_name in {"agentgate_query", "agentgate_describe_source"}
            and not arguments.get("source_id")
            and not bearer_token_from_headers(request.headers)
        ):
            return JSONResponse(
                {"error": "Missing or invalid Authorization header"},
                status_code=401,
            )

        if tool_name in {
            "agentgate_query",
            "agentgate_describe_source",
            "agentgate_discover",
        }:
            if not arguments.get("source_id"):
                return JSONResponse(
                    {"error": f"{requested_name} requires source_id"},
                    status_code=400,
                )

        # A blank `sql` used to reach governance, where the empty statement made
        # `build_permission_request` derive `db.execute_raw` on `*`. No correctly
        # scoped role allows that, so a malformed call was reported to the agent
        # as a source-role denial and sent its operator into role configuration
        # to debug a missing argument.
        if tool_name == "agentgate_query" and not str(arguments.get("sql") or "").strip():
            return JSONResponse(
                {"error": f"{requested_name} requires sql"},
                status_code=400,
            )

        state = getattr(getattr(request, "app", None), "state", None)
        pipeline = GatewayPipeline.from_state(state)

        if tool_name in {"agentgate_list_sources", "interlock_describe_access"}:
            auth = getattr(state, "auth_manager", None) if state else None
            identity = getattr(request.state, "identity", None)
            if auth is not None:
                token = bearer_token_from_headers(request.headers)
                if not token:
                    return JSONResponse(
                        {"error": "Missing or invalid Authorization header"},
                        status_code=401,
                    )
                try:
                    identity = await auth.authenticate(token)
                except Exception:
                    return JSONResponse({"error": "Invalid API key"}, status_code=401)
            if identity is not None:
                request.state.identity = identity
            if tool_name == "interlock_describe_access":
                return await self._describe_access(request, arguments)
            return await self._list_sources(request, arguments)

        early_identity: IdentityContext | None = None
        if tool_name == "agentgate_describe_source":
            # A table-scoped role used to block this tool outright, because
            # the request asked to describe `*.*`. With a catalog, the request
            # names only the tables this caller may describe, and the handler
            # returns only those; that needs the identity before preflight.
            auth = getattr(state, "auth_manager", None) if state else None
            token = bearer_token_from_headers(request.headers)
            if auth is not None and token:
                try:
                    early_identity = await auth.authenticate(token)
                except Exception:
                    return JSONResponse({"error": "Invalid API key"}, status_code=401)
            describable = await self._describable_tables(
                request, str(arguments["source_id"]), early_identity
            )
            if describable:
                tables = describable
                request.state.describable_tables = describable

        upstream_identity = None
        if tool_name == "agentgate_query" and saved_connector_key == "fabric_sql":
            try:
                upstream_identity = await self._fabric_identity_binding(request, saved_source)
            except Exception as exc:
                return _tool_failure_response(exc, _call_correlation_id(request))

        gateway_request = GatewayRequest(
            protocol="mcp",
            source_id=str(arguments["source_id"]),
            operation=operation,
            identity=early_identity,
            normalized_request=normalized_request,
            method="tools/call",
            path=str(tool_name),
            sql=sql,
            parameters=arguments,
            metadata={
                "tool_name": tool_name,
                "correlation_id": _call_correlation_id(request),
                "connector_key": saved_connector_key,
                **({"upstream_identity": upstream_identity} if upstream_identity else {}),
            },
            tables=tables,
            dialect=self._dialect_for_source(request, str(arguments["source_id"])),
        )
        decision = await pipeline.preflight(
            gateway_request,
            bearer_token=bearer_token_from_headers(request.headers),
        )
        request.state.gateway_decision = decision
        if not decision.allowed:
            await pipeline.audit(
                gateway_request,
                decision=decision,
                status=(
                    "queued"
                    if decision.approval_state == "pending"
                    else ("denied" if decision.status_code in (403, 429) else "error")
                ),
                error_message=decision.reason,
            )
            refusal: dict[str, Any] = {"error": decision.reason}
            if decision.approval_id is not None or decision.approval_state is not None:
                # Parity with the HTTP proxy, which has always returned these.
                refusal["approval_id"] = decision.approval_id
                refusal["approval_state"] = decision.approval_state
            return JSONResponse(refusal, status_code=decision.status_code)
        identity = decision.identity

        # Make identity available to tool handlers so they can scope
        # cache, audit, and policy decisions correctly.
        if identity is not None:
            request.state.identity = identity

        return await handler(request, arguments)

    # -- Tool implementations -----------------------------------------------

    async def _execute_query(self, request: Request, args: dict[str, Any]) -> JSONResponse:
        """Execute SQL through the same governance pipeline used by PG.

        AUDIT-COVERS: P0-B

        Steps mirror pg_proxy._handle_simple_query:
          1. Resolve identity (already authenticated by call_tool).
          2. Normalize SQL with identity-scoped role context.
          3. Classify writes: BLOCKED -> 403, MEDIUM/HIGH -> approval queue.
          4. Cache lookup using identity-aware key.
          5. Origin fetch via ConnectionManager when registered, else
             the gateway control pool as a fallback for backwards compat.
          6. Response processor (PII fast-tier scan + redaction) on every
             row dict before returning.
          7. Cache write under the identity-aware key.
          8. Audit emit with operation/cache/PII metadata.
        """
        import time

        t0 = time.monotonic()
        sql = args.get("sql", "")
        source_id = str(args["source_id"])

        identity = getattr(request.state, "identity", None)
        state = getattr(getattr(request, "app", None), "state", None)

        pool = self._resolve_pool(request)
        if pool is None:
            return JSONResponse(
                _text_content("No database pool available"),
                status_code=503,
            )

        # 2. Normalize ----------------------------------------------------
        role_context = None
        if identity is not None:
            role_context = identity.mapped_pg_role or (
                identity.roles[0] if identity.roles else None
            )
        # Parse with the source's own SQL grammar. Parsing everything as
        # PostgreSQL meant a MySQL source could not use backtick-quoted
        # identifiers - its own standard quoting - because the parse failed
        # and the statement was classified as an unknown high-risk write with
        # no tables, which source roles then refused.
        nq = normalize_sql(
            sql,
            source_id,
            role_context=role_context,
            dialect=self._dialect_for_source(request, source_id),
        )
        is_multi_statement = isinstance(nq, list)
        if isinstance(nq, list):
            nq = nq[0] if nq else None

        fingerprint = None
        operation = nq.operation if nq is not None and not is_multi_statement else None
        op_type = (
            "write"
            if (operation or "").upper()
            in ("INSERT", "UPDATE", "DELETE", "DROP", "TRUNCATE", "ALTER", "CREATE", "EXECUTE")
            else "read"
        )

        fabric_source: FabricAuthenticatedSource | None = None

        async def fabric_failure(
            exc: Exception, category: str, *, status_code: int | None = None
        ) -> JSONResponse:
            from interlock.connections.fabric.auth import FabricAuthError

            correlation_id = _call_correlation_id(request)
            if isinstance(exc, FabricAuthError):
                category = exc.code
            audit = getattr(state, "audit_logger", None) if state else None
            if audit is not None:
                await self._safe_audit(
                    audit,
                    identity=identity,
                    source_id=source_id,
                    operation=op_type,
                    method="tools/call",
                    path="agentgate_query",
                    fingerprint=fingerprint,
                    cache_hit=False,
                    latency_ms=(time.monotonic() - t0) * 1000,
                    status="error",
                    error_message=category,
                    failure_category=category,
                    correlation_id=correlation_id,
                    upstream_identity=(
                        fabric_source.upstream_identity
                        if fabric_source is not None
                        else getattr(
                            getattr(request.state, "gateway_decision", None),
                            "upstream_identity",
                            None,
                        )
                    ),
                )
            response = _tool_failure_response(exc, correlation_id)
            body = json.loads(bytes(response.body))
            body["correlation_id"] = correlation_id
            return JSONResponse(body, status_code=status_code or response.status_code)

        try:
            source_generation = await current_cache_source_generation(
                getattr(state, "cache_invalidator", None) if state else None,
                source_id,
                strict=bool(getattr(state, "cache_barrier_strict", False)) if state else False,
            )
        except CacheBarrierUnavailableError as exc:
            if getattr(getattr(request.state, "gateway_decision", None), "upstream_identity", None):
                return await fabric_failure(exc, "fabric_cache_unavailable", status_code=503)
            return JSONResponse(
                _text_content("Cache consistency barrier unavailable"),
                status_code=503,
            )
        # 3. Operation type was already governed by GatewayPipeline.call_tool
        gateway_decision = getattr(request.state, "gateway_decision", None)
        if gateway_decision is not None and gateway_decision.write_classification is not None:
            op_type = "write"
        if getattr(request.state, "gateway_decision", None) is None:
            registry = self._resolve_registry(request)
            saved = registry.get(source_id) if registry else None
            key = connector_key_for(saved.source_type.value, saved.metadata) if saved else ""
            fallback_metadata: dict[str, Any] = {
                "tool_name": "agentgate_query",
                "connector_key": key,
            }
            if key == "fabric_sql":
                try:
                    fallback_metadata["upstream_identity"] = await self._fabric_identity_binding(
                        request, saved
                    )
                except Exception as exc:
                    return _tool_failure_response(exc, _call_correlation_id(request))
            gateway_request = GatewayRequest(
                protocol="mcp",
                source_id=source_id,
                operation=op_type,
                identity=identity,
                method="tools/call",
                path="agentgate_query",
                sql=sql,
                parameters=args,
                metadata=fallback_metadata,
                normalized_request=nq,
                tables=list(getattr(nq, "tables", []) or []),
                dialect=self._dialect_for_source(request, source_id),
            )
            decision = await GatewayPipeline.from_state(state).preflight(gateway_request)
            if not decision.allowed:
                return JSONResponse(
                    _text_content(decision.reason),
                    status_code=decision.status_code,
                )
            request.state.gateway_decision = decision
            if decision.write_classification is not None:
                op_type = "write"
                classified_tables = list(decision.write_classification.tables or [])
                if classified_tables and nq is not None:
                    existing_tables = list(getattr(nq, "tables", []) or [])
                    nq.tables = sorted(set(existing_tables + classified_tables))

        # 4. Cache lookup -----------------------------------------------
        # A source that is disabled or deleted has left the registry, and a
        # cached answer must not outlive it: refuse here, before the cache,
        # exactly as `get_pool` would on a miss.
        live_registry = self._resolve_registry(request)
        if live_registry is not None and live_registry.get(source_id) is None:
            missing = DataSourceNotFoundError(f"Unknown data source: {source_id}")
            if getattr(getattr(request.state, "gateway_decision", None), "upstream_identity", None):
                return await fabric_failure(missing, "fabric_source_unavailable")
            return _tool_failure_response(missing)

        source_config = live_registry.get(source_id) if live_registry is not None else None
        if (
            source_config is not None
            and connector_key_for(source_config.source_type.value, source_config.metadata)
            == "fabric_sql"
        ):
            try:
                from interlock.connections.fabric.config import FabricConfig

                services = getattr(state, "fabric_services", None)
                if services is None:
                    raise DataSourceUnavailableError(
                        "Fabric authentication services are unavailable"
                    )
                fabric_source = await services.prepare_source(
                    source_id, FabricConfig.from_mapping(source_config.connection_config)
                )
                governed_identity = getattr(
                    getattr(request.state, "gateway_decision", None), "upstream_identity", None
                )
                if governed_identity != fabric_source.upstream_identity:
                    raise ValueError("Fabric identity changed after authorization; retry request")
            except Exception as exc:
                return await fabric_failure(exc, "fabric_identity_changed")

        if nq is not None and not is_multi_statement:
            fingerprint = compute_cache_key(
                protocol="mcp",
                source_id=source_id,
                normalized_sql=nq.normalized_sql or sql,
                parameters=(
                    {
                        "normalized": getattr(nq, "parameters", None),
                        "bound": args.get("parameters") or [],
                    }
                    if fabric_source
                    else getattr(nq, "parameters", None)
                ),
                identity_role=role_context,
                mapped_pg_role=getattr(identity, "mapped_pg_role", None),
                tenant_id=getattr(identity, "team", None),
                grants_version=_grants_version(identity),
                policy_scope_hash=_decision_scope_hash(
                    getattr(request.state, "gateway_decision", None)
                ),
                source_generation=source_generation,
                upstream_identity_scope=fabric_source.cache_scope if fabric_source else None,
            )

        # Resolve the strategy this *source* is configured to use, not the
        # gateway-wide default. A source set to `bypass` must not be served
        # from cache.
        cache_strategy = self._cache_strategy_for(request, source_id)
        cache_tier: str | None = None
        if op_type == "read" and fingerprint is not None and cache_strategy is not None:
            try:
                result = await cache_strategy.get(fingerprint, intent_text=None)
                if result.hit and result.data is not None and not _is_json_payload(result.data):
                    # The key separates protocols; this keeps a future collision
                    # a cache miss rather than bytes an agent cannot read.
                    logger.warning(
                        "Ignoring a cached entry that is not an MCP result source=%s", source_id
                    )
                    result = CacheResult(hit=False)
                if result.hit and result.data is not None:
                    if fabric_source is not None:
                        try:
                            await fabric_source.assert_current()
                        except Exception as exc:
                            return await fabric_failure(exc, "fabric_delivery_refused")
                    if fabric_source is not None:
                        cached_rows = json.loads(result.data)
                        _validate_fabric_result_columns(
                            sql,
                            [key for row in cached_rows for key in row],
                            getattr(request.state, "gateway_decision", None),
                        )
                    cache_tier = result.tier
                    # The cached JSON was redacted when stored; record that
                    # redaction, since no scanner runs on a hit.
                    cached_pii, cached_pii_types, cached_stats = redaction_of(result.metadata)
                    audit = getattr(state, "audit_logger", None) if state else None
                    if audit is not None:
                        await self._safe_audit(
                            audit,
                            identity=identity,
                            source_id=source_id,
                            operation=op_type,
                            method="tools/call",
                            path="agentgate_query",
                            sql=sql,
                            parameters=args,
                            tables=list(getattr(nq, "tables", []) or []),
                            decision=getattr(request.state, "gateway_decision", None),
                            fingerprint=fingerprint,
                            cache_hit=True,
                            cache_tier=cache_tier,
                            latency_ms=(time.monotonic() - t0) * 1000,
                            pii_detected=cached_pii,
                            pii_types=cached_pii_types,
                            redaction_stats=cached_stats,
                            upstream_identity=(
                                fabric_source.upstream_identity if fabric_source else None
                            ),
                        )
                    if fabric_source is not None:
                        try:
                            await fabric_source.assert_current()
                        except Exception as exc:
                            return await fabric_failure(exc, "fabric_delivery_refused")
                    return JSONResponse(
                        _text_content(result.data.decode("utf-8")),
                    )
            except Exception:
                logger.debug("MCP cache lookup failed", exc_info=True)

        # 5. Origin fetch ------------------------------------------------
        try:
            rows_dicts: list[dict[str, Any]]
            conn_mgr = getattr(state, "conn_manager", None) if state else None
            registry = self._resolve_registry(request)
            source_config = registry.get(source_id) if registry is not None else None
            if source_config is not None and source_config.source_type.value != "postgresql":
                adapter = get_adapter(
                    source_config.connector_key,
                    source_config.metadata,
                    fabric_services=getattr(request.app.state, "fabric_services", None),
                    source_id=source_id,
                )
                connector_request = {
                    "source_id": source_id,
                    "identity_id": getattr(identity, "identity_id", None),
                    "query": sql,
                    "parameters": args.get("parameters") or (),
                    "connection_config": source_config.connection_config,
                }
                if fabric_source is not None:
                    from interlock.connections.fabric.adapter import FabricSQLAdapter

                    assert isinstance(adapter, FabricSQLAdapter)
                    connector_result = await adapter.execute_prepared(
                        connector_request, fabric_source, write=op_type == "write"
                    )
                    rows_dicts = (
                        [connector_result]
                        if op_type == "write"
                        else [dict(row) for row in connector_result.get("rows", [])]
                    )
                    if op_type == "read":
                        _validate_fabric_result_columns(
                            sql,
                            connector_result.get("columns")
                            or [key for row in rows_dicts for key in row],
                            getattr(request.state, "gateway_decision", None),
                        )
                elif op_type == "write":
                    connector_result = await adapter.execute_write(connector_request)
                    rows_dicts = [connector_result]
                else:
                    connector_result = await adapter.execute_read(connector_request)
                    connector_rows = connector_result.get("rows", [])
                    rows_dicts = [dict(row) for row in connector_rows]
            elif conn_mgr is not None:
                role = getattr(identity, "mapped_pg_role", None) if identity else None
                origin_pool = await conn_mgr.get_pool(source_id, pg_role=role)
                rows = await origin_pool.fetch(sql)
                rows_dicts = [dict(r) for r in rows]
            elif getattr(state, "allow_mcp_control_db_fallback", False) or (
                source_config is None and conn_mgr is None and self._pool is not None
            ):
                # Unit-test fallback only. Production app.state wires a
                # ConnectionManager and should never query the control DB
                # for registered source data.
                rows = await pool.fetch(sql)
                rows_dicts = [dict(r) for r in rows]
            else:
                return JSONResponse(
                    _text_content("ConnectionManager is required for MCP source queries"),
                    status_code=503,
                )
        except Exception as exc:
            if fabric_source is not None:
                return await fabric_failure(exc, "fabric_origin_failed")
            logger.warning("MCP query error: %s", exc)
            # The agent's answer and the audit row carry the same ID; an inbound
            # X-Correlation-ID is honoured.
            correlation_id = _call_correlation_id(request)
            audit = getattr(state, "audit_logger", None) if state else None
            if audit is not None:
                await self._safe_audit(
                    audit,
                    identity=identity,
                    source_id=source_id,
                    operation=op_type,
                    fingerprint=fingerprint,
                    cache_hit=False,
                    cache_tier=None,
                    latency_ms=(time.monotonic() - t0) * 1000,
                    status="error",
                    error_message=str(exc),
                    correlation_id=correlation_id,
                )
            return _tool_failure_response(exc, correlation_id)

        # 6. Response processing (PII redact) ----------------------------
        # Shared with every other content-returning tool. This loop used to
        # live here alone, which is how _discover, _related_documents and
        # _describe_source came to return unredacted payloads.
        rows_dicts, pii_detected, pii_types, redaction_stats = await self._redact_rows(
            request, rows_dicts
        )
        gateway_decision = getattr(request.state, "gateway_decision", None)
        policy_decision = getattr(gateway_decision, "policy_decision", None)
        redact_fields = list(getattr(policy_decision, "redact_columns", None) or [])
        if redact_fields and op_type != "write":
            rows_dicts, policy_stats = redact_policy_columns(
                rows_dicts,
                redact_fields,
                getattr(gateway_decision, "column_lineage", None) or {},
                identifier_case_sensitive=getattr(
                    gateway_decision, "identifier_case_sensitive", None
                ),
            )
            if policy_stats["count"]:
                redaction_stats = {**(redaction_stats or {}), "policy": policy_stats}

        payload = json.dumps(rows_dicts, default=_default_serializer)
        tables = list(getattr(nq, "tables", []) or [])

        if op_type == "write":
            invalidator = getattr(state, "cache_invalidator", None) if state else None
            if invalidator is not None:
                try:
                    write_generation = getattr(
                        getattr(request.state, "gateway_decision", None),
                        "source_generation",
                        None,
                    )
                    if tables:
                        kwargs = (
                            {"source_generation": write_generation}
                            if write_generation is not None
                            else {}
                        )
                        await invalidator.invalidate_for_tables(source_id, tables, **kwargs)
                    elif write_generation is not None:
                        await invalidator.invalidate_for_tables(
                            source_id,
                            [],
                            source_generation=write_generation,
                        )
                    else:
                        await invalidator.invalidate_for_source(source_id)
                except Exception:
                    logger.warning(
                        "MCP cache invalidation failed source=%s tables=%s",
                        source_id,
                        tables,
                        exc_info=True,
                    )

        if fabric_source is not None and op_type == "read":
            try:
                await fabric_source.assert_current()
            except Exception as exc:
                return await fabric_failure(exc, "fabric_delivery_refused")

        # 7. Cache write ------------------------------------------------
        if op_type == "read" and fingerprint is not None and cache_strategy is not None:
            try:
                await cache_strategy.put(
                    fingerprint,
                    payload.encode("utf-8"),
                    with_redaction(
                        {
                            "source_id": source_id,
                            "protocol": "mcp",
                            "tables": tables,
                            **(
                                {"upstream_identity": fabric_source.upstream_identity}
                                if fabric_source
                                else {}
                            ),
                        },
                        pii_detected=pii_detected,
                        pii_types=pii_types,
                        redaction_stats=redaction_stats,
                    ),
                    intent_text=None,
                )
                invalidator = getattr(state, "cache_invalidator", None) if state else None
                if invalidator is not None:
                    await invalidator.record_dependency(
                        fingerprint,
                        source_id=source_id,
                        tables=tables,
                        protocol="mcp",
                        metadata={"source_id": source_id, "protocol": "mcp", "tables": tables},
                    )
            except Exception:
                logger.debug("MCP cache put failed", exc_info=True)

        # 8. Audit emit -------------------------------------------------
        audit = getattr(state, "audit_logger", None) if state else None
        if audit is not None:
            await self._safe_audit(
                audit,
                identity=identity,
                source_id=source_id,
                operation=op_type,
                method="tools/call",
                path="agentgate_query",
                sql=sql,
                parameters=args,
                tables=tables,
                decision=getattr(request.state, "gateway_decision", None),
                fingerprint=fingerprint,
                cache_hit=False,
                cache_tier=None,
                latency_ms=(time.monotonic() - t0) * 1000,
                pii_detected=pii_detected,
                pii_types=pii_types,
                redaction_stats=redaction_stats,
                row_count=len(rows_dicts),
                upstream_identity=(fabric_source.upstream_identity if fabric_source else None),
            )

        if fabric_source is not None and op_type == "read":
            try:
                await fabric_source.assert_current()
            except Exception as exc:
                return await fabric_failure(exc, "fabric_delivery_refused")
        return JSONResponse(_text_content(payload))

    async def _fabric_identity_binding(self, request: Request, source: Any) -> dict[str, Any]:
        from dataclasses import asdict

        services = getattr(request.app.state, "fabric_services", None)
        if services is None:
            raise DataSourceUnavailableError("Fabric authentication services are unavailable")
        current = await services.store.current_source(source.source_id)
        return asdict(current.context)

    def _cache_strategy_for(self, request: Request, source_id: str | None) -> Any | None:
        """The cache strategy the given source is configured to use.

        Falls back to the gateway-wide strategy when no resolver is wired,
        which keeps adapters constructed outside the full app lifespan - unit
        tests, mainly - behaving exactly as before.
        """
        state = getattr(getattr(request, "app", None), "state", None)
        if state is None:
            return None
        resolver = getattr(state, "cache_strategies", None)
        if resolver is None:
            return getattr(state, "cache_strategy", None)
        registry = self._resolve_registry(request)
        config = registry.get(source_id) if (registry is not None and source_id) else None
        return resolver.for_source(config)

    def _dialect_for_source(self, request: Request, source_id: str | None) -> str:
        """The SQL grammar this source speaks, for parsing only.

        Falls back to the default when the source is unknown, which keeps an
        unregistered or not-yet-loaded source behaving exactly as it did
        before dialects existed.
        """
        from interlock.core.normalizer import DEFAULT_DIALECT, dialect_for

        if not source_id:
            return DEFAULT_DIALECT
        try:
            registry = self._resolve_registry(request)
            config = registry.get(source_id) if registry is not None else None
        except Exception:  # noqa: BLE001 - parsing must not fail on registry trouble
            return DEFAULT_DIALECT
        if config is None:
            return DEFAULT_DIALECT
        return dialect_for(getattr(config, "connector_key", None) or config.source_type.value)

    async def _redact_rows(
        self, request: Request, rows: list[dict[str, Any]]
    ) -> tuple[list[dict[str, Any]], bool, list[str], dict[str, Any]]:
        """Run the PII scanner over any tool payload before it reaches a caller.

        Every content-returning MCP tool must go through this. Redaction used
        to live inline in the query handler only, which meant `interlock_query`
        redacted a value while `interlock_discover` returned the identical
        value verbatim - a real disclosure, since the discovery catalogue is
        populated from upstream documents and messages where free-text PII
        lives. The contract at docs-site/src/content/docs/reference/contracts/mcp-v1.md states that *tool*
        execution includes redaction, without scoping it to one tool.

        Fails closed per row: a scanner error replaces that row rather than
        letting it through, matching the behaviour the query path already had.

        Returns the redacted rows, whether anything was found, the entity
        types found, and countable evidence for `audit_log.redaction_stats`.
        That last value is what the operator guide points an auditor at, and
        it used to be written only by the HTTP `redact_columns` path - so on
        this path, the primary one agents use, the documented query returned
        nothing while redaction was in fact happening.
        """
        state = getattr(request.app, "state", None)
        scanner = getattr(state, "pii_scanner", None) if state else None
        if scanner is None or not rows:
            return rows, False, [], {}

        redacted: list[dict[str, Any]] = []
        detected = False
        types: list[str] = []
        counts: dict[str, int] = {}
        rows_redacted = 0
        failures = 0
        for row in rows:
            try:
                out, detections = await scanner.process_row(row)
            except Exception:
                logger.warning("PII scan failed for MCP row; redacting row", exc_info=True)
                redacted.append({"error": "row redacted after scanner failure"})
                detected = True
                failures += 1
                rows_redacted += 1
                types.append("PII_SCAN_FAILED")
                counts["PII_SCAN_FAILED"] = counts.get("PII_SCAN_FAILED", 0) + 1
                continue
            redacted.append(out)
            if detections:
                detected = True
                rows_redacted += 1
                for detection in detections:
                    entity = _detection_entity_type(detection)
                    if not entity:
                        continue
                    types.append(entity)
                    counts[entity] = counts.get(entity, 0) + 1

        stats: dict[str, Any] = {}
        if detected:
            stats = {
                "rows_scanned": len(rows),
                "rows_redacted": rows_redacted,
                "pii_redactions": counts,
                "scanner_failures": failures,
            }
        return redacted, detected, sorted(set(types)), stats

    async def _safe_audit(self, audit, **fields: Any) -> None:
        identity = fields.pop("identity", None)
        decision = fields.pop("decision", None)
        pipeline = GatewayPipeline(audit_logger=audit)
        await pipeline.audit(
            GatewayRequest(
                protocol="mcp",
                source_id=fields.get("source_id") or "__control__",
                operation=fields.get("operation", "read"),
                identity=identity,
                method=fields.get("method"),
                path=fields.get("path"),
                sql=fields.get("sql"),
                parameters=fields.get("parameters"),
                tables=fields.get("tables"),
                metadata={
                    "row_count": fields.get("row_count"),
                    "upstream_identity": fields.get("upstream_identity"),
                    "failure_category": fields.get("failure_category"),
                    "tool_name": fields.get("path"),
                    "redaction_stats": fields.get("redaction_stats") or None,
                    **(
                        {"correlation_id": correlation_id}
                        if (
                            correlation_id := fields.get("correlation_id")
                            or _CALL_CORRELATION_ID.get()
                        )
                        else {}
                    ),
                },
            ),
            decision=decision,
            fingerprint=fields.get("fingerprint"),
            cache_hit=fields.get("cache_hit", False),
            cache_tier=fields.get("cache_tier"),
            latency_ms=fields.get("latency_ms"),
            status=fields.get("status", "success"),
            error_message=fields.get("error_message"),
            pii_detected=fields.get("pii_detected", False),
            pii_types=fields.get("pii_types", []),
        )

    async def _catalog_naming(self, request: Request, source_id: str) -> Any | None:
        state = getattr(request.app, "state", None)
        resolver = getattr(state, "sql_naming_resolver", None) if state else None
        if resolver is None:
            return None
        naming = await resolver.naming_for_source(source_id)
        if naming is None or naming.columns is None:
            return None
        return naming

    async def _describable_tables(
        self, request: Request, source_id: str, identity: IdentityContext | None
    ) -> list[str]:
        """Catalogued tables this identity may describe; empty without a catalog.

        PostgreSQL only: other connectors answer with their own introspection,
        which is not filtered per table, so narrowing their request would let a
        table-scoped caller read the whole source's shape.
        """
        registry = self._resolve_registry(request)
        source = registry.get(source_id) if registry is not None else None
        if source is None or source.source_type.value != "postgresql":
            return []
        state = getattr(request.app, "state", None)
        evaluator = getattr(state, "source_role_evaluator", None) if state else None
        identity_id = getattr(identity, "identity_id", None)
        if evaluator is None or identity_id is None:
            return []
        try:
            naming = await self._catalog_naming(request, source_id)
        except Exception:
            logger.warning("Catalog naming unavailable for %s", source_id, exc_info=True)
            return []
        if naming is None:
            return []
        tables = sorted(f"{schema}.{name}" for schema, name in naming.known_tables or ())
        allowed = await evaluator.allowed_resources(
            identity_id,
            source_id,
            action="db.table.describe",
            resource_type="db.table",
            resources=[f"{table}.*" for table in tables],
        )
        return [table for table in tables if f"{table}.*" in allowed]

    async def _resources_view(
        self, request: Request, identity: IdentityContext | None, source_id: str
    ) -> dict[str, Any]:
        """What this caller may read on one source, from the catalog.

        Lists only tables and columns its roles allow and do not deny - never a
        name it could not read - and marks a table a policy would refuse.
        """
        state = getattr(request.app, "state", None)
        registry = self._resolve_registry(request)
        source = registry.get(source_id) if registry is not None else None
        connector_key = (
            connector_key_for(source.source_type.value, source.metadata)
            if source is not None
            else ""
        )
        if connector_key not in _CATALOG_ENFORCED_CONNECTORS:
            return {
                "enforced": False,
                "note": (
                    "Requests to this source are not checked against catalogued "
                    "resources yet; the actions above are what governs it."
                ),
            }
        naming = await self._catalog_naming(request, source_id)
        if naming is None:
            return {"enforced": True, "catalogued": False, "tables": []}
        evaluator = getattr(state, "source_role_evaluator", None)
        identity_id = getattr(identity, "identity_id", None)
        if evaluator is None or identity_id is None:
            return {"enforced": True, "catalogued": True, "tables": []}

        columns_by_table = {
            f"{schema}.{name}": list(cols) for (schema, name), cols in naming.columns.items()
        }
        tables = sorted(f"{schema}.{name}" for schema, name in naming.known_tables or ())
        if naming.connector_key == "fabric_sql":
            tables = [table for table in tables if not resolve_table(table, naming).refusal]
            if naming.identifier_case_sensitive is False:
                tables = [
                    table
                    for table in tables
                    if all(c.isascii() and c == c.strip() for c in columns_by_table.get(table, []))
                ]
        truncated = len(tables) > _RESOURCES_TABLE_LIMIT
        tables = tables[:_RESOURCES_TABLE_LIMIT]
        whole_resources = [f"{table}.*" for table in tables]
        column_resources = [
            f"{table}.{column}" for table in tables for column in columns_by_table.get(table, [])
        ]
        aliases = _legacy_aliases(naming, [*whole_resources, *column_resources])
        whole = await evaluator.allowed_resources(
            identity_id,
            source_id,
            action="db.table.select",
            resource_type="db.table",
            resources=whole_resources,
            aliases=aliases,
            case_sensitive=naming.identifier_case_sensitive is True,
            native_identifiers=naming.connector_key == "fabric_sql",
        )
        readable_columns = await evaluator.allowed_resources(
            identity_id,
            source_id,
            action="db.table.select",
            resource_type="db.column",
            resources=column_resources,
            aliases=aliases,
            case_sensitive=naming.identifier_case_sensitive is True,
            native_identifiers=naming.connector_key == "fabric_sql",
        )
        policy = getattr(state, "policy_engine", None)
        listed: list[dict[str, Any]] = []
        for table in tables:
            every = columns_by_table.get(table, [])
            readable = [c for c in every if f"{table}.{c}" in readable_columns]
            if not readable and f"{table}.*" not in whole:
                continue
            entry: dict[str, Any] = {
                "table": table,
                "columns": readable,
                "all_columns": f"{table}.*" in whole and len(readable) == len(every),
            }
            if policy is not None and identity is not None:
                decision = policy.evaluate(
                    identity=identity,
                    source_id=source_id,
                    operation="read",
                    tables=[table],
                    deny_table_spellings=table_spellings([resolve_table(table, naming)]),
                    identifier_case_sensitive=(
                        naming.identifier_case_sensitive
                        if naming.connector_key == "fabric_sql"
                        else None
                    ),
                )
                if not decision.allowed:
                    entry["policy"] = {
                        "refused": True,
                        "rule": decision.rule_name,
                        "reason": decision.reason,
                    }
            listed.append(entry)
        scan = await self._last_scan(request, source_id)
        return {
            "enforced": True,
            "catalogued": True,
            "scanned_at": scan.get("finished_at"),
            "catalog_truncated": bool(scan.get("truncated")),
            "tables": listed,
            "truncated": truncated,
        }

    async def _last_scan(self, request: Request, source_id: str) -> dict[str, Any]:
        pool = self._resolve_pool(request)
        if pool is None:
            return {}
        row = await pool.fetchrow(
            "SELECT finished_at, truncated FROM source_catalog_scans "
            "WHERE source_id = $1 AND status = 'succeeded' ORDER BY finished_at DESC LIMIT 1",
            source_id,
        )
        if row is None:
            return {}
        finished = row["finished_at"]
        return {
            "finished_at": finished.isoformat() if finished is not None else None,
            "truncated": row["truncated"],
        }

    async def _describe_access(self, request: Request, args: dict[str, Any]) -> JSONResponse:
        """Tell the caller what its own source roles permit, per granted source.

        Audited like `_list_sources`, against `__registry__`: it is a read of
        control-plane metadata rather than of any upstream, and an agent asking
        what it may do is worth a row in the trail.
        """
        t0 = time.monotonic()
        state = getattr(request.app, "state", None)
        identity = getattr(request.state, "identity", None)
        evaluator = getattr(state, "source_role_evaluator", None) if state else None
        identity_id = getattr(identity, "identity_id", None)

        summary: dict[str, Any] = {}
        error: str | None = None
        if evaluator is None or identity_id is None:
            # Without an evaluator or a resolved identity there is no authority to
            # describe. Saying so beats returning an empty object an agent would
            # read as "you may do nothing".
            error = "Source-role access description is unavailable for this caller"
        else:
            granted = _allowed_source_ids_for_identity(identity) or set()
            requested = str(args.get("source_id") or "").strip()
            if requested:
                granted = {requested} & granted
            for source_id in sorted(granted):
                summary[source_id] = await evaluator.describe_access(identity_id, source_id)
                try:
                    summary[source_id]["resources"] = await self._resources_view(
                        request, identity, source_id
                    )
                except Exception:
                    logger.warning(
                        "Could not describe catalogued resources for %s", source_id, exc_info=True
                    )
                    summary[source_id]["resources"] = {"available": False}

        audit = getattr(state, "audit_logger", None) if state else None
        if audit is not None:
            await self._safe_audit(
                audit,
                source_id="__registry__",
                operation="read",
                method="tools/call",
                path="interlock_describe_access",
                parameters=args,
                identity=identity,
                latency_ms=(time.monotonic() - t0) * 1000,
                row_count=len(summary),
                status="error" if error else "success",
                error_message=error,
            )
        if error:
            return JSONResponse(_text_content(error), status_code=403)
        return JSONResponse(_text_content(json.dumps(summary)))

    async def _list_sources(self, request: Request, args: dict[str, Any]) -> JSONResponse:
        """Return all registered data sources."""
        t0 = time.monotonic()
        registry = self._resolve_registry(request)

        if registry is None:
            audit = getattr(request.app.state, "audit_logger", None)
            if audit is not None:
                await self._safe_audit(
                    audit,
                    source_id="__registry__",
                    operation="read",
                    method="tools/call",
                    path="agentgate_list_sources",
                    parameters=args,
                    identity=getattr(request.state, "identity", None),
                    latency_ms=(time.monotonic() - t0) * 1000,
                    status="error",
                    error_message="No source registry available",
                )
            return JSONResponse(_text_content("{}"))

        identity = getattr(request.state, "identity", None)
        allowed_source_ids = _allowed_source_ids_for_identity(identity)

        sources = registry.get_all()
        summary = {
            k: {"name": v.name, "type": v.source_type.value}
            for k, v in sources.items()
            if allowed_source_ids is None or k in allowed_source_ids
        }
        audit = getattr(request.app.state, "audit_logger", None)
        if audit is not None:
            await self._safe_audit(
                audit,
                source_id="__registry__",
                operation="read",
                method="tools/call",
                path="agentgate_list_sources",
                parameters=args,
                identity=getattr(request.state, "identity", None),
                latency_ms=(time.monotonic() - t0) * 1000,
                row_count=len(summary),
            )
        return JSONResponse(_text_content(json.dumps(summary)))

    async def _discover(self, request: Request, args: dict[str, Any]) -> JSONResponse:
        """Search the discovery index for relevant data assets."""
        t0 = time.monotonic()
        query = args.get("query", "")
        source_id = args.get("source_id")
        limit = args.get("limit", 10)
        metadata_filters = {
            key: args[key]
            for key in ("source_types", "doc_types", "time_range", "audience", "entities")
            if key in args and args[key] not in (None, [], {})
        }

        search = self._resolve_discovery(request)
        if search is None:
            return JSONResponse(
                _text_content("Discovery search not available"),
                status_code=503,
            )

        try:
            search_kwargs: dict[str, Any] = {
                "query": query,
                "source_id": source_id,
                "limit": limit,
            }
            if args.get("category_path"):
                search_kwargs["category_path"] = args.get("category_path")
            if metadata_filters:
                search_kwargs["metadata_filters"] = metadata_filters
            results = await search.search(**search_kwargs)
            allowed_source_ids = _allowed_source_ids_for_identity(
                getattr(request.state, "identity", None)
            )
            payload = [
                {
                    "asset_id": r.asset_id,
                    "source_id": r.source_id,
                    "asset_type": r.asset_type,
                    "asset_path": r.asset_path,
                    "title": r.title,
                    "summary": r.summary,
                    "score": r.score,
                    "strategy": r.strategy,
                    "metadata": r.metadata,
                }
                for r in results
                if allowed_source_ids is None or r.source_id in allowed_source_ids
            ]
            payload, pii_detected, pii_types, redaction_stats = await self._redact_rows(
                request, payload
            )
            audit = getattr(request.app.state, "audit_logger", None)
            if audit is not None:
                await self._safe_audit(
                    audit,
                    source_id=source_id or "__discovery__",
                    operation="discovery",
                    method="tools/call",
                    path="agentgate_discover",
                    parameters=args,
                    identity=getattr(request.state, "identity", None),
                    decision=getattr(request.state, "gateway_decision", None),
                    latency_ms=(time.monotonic() - t0) * 1000,
                    row_count=len(payload),
                    pii_detected=pii_detected,
                    pii_types=pii_types,
                    redaction_stats=redaction_stats,
                )
            return JSONResponse(_text_content(json.dumps(payload, default=_default_serializer)))
        except Exception as exc:
            logger.warning("MCP discover error: %s", exc)
            audit = getattr(request.app.state, "audit_logger", None)
            if audit is not None:
                await self._safe_audit(
                    audit,
                    source_id=source_id or "__discovery__",
                    operation="discovery",
                    method="tools/call",
                    path="agentgate_discover",
                    parameters=args,
                    identity=getattr(request.state, "identity", None),
                    decision=getattr(request.state, "gateway_decision", None),
                    latency_ms=(time.monotonic() - t0) * 1000,
                    status="error",
                    error_message=str(exc),
                )
            return JSONResponse(_text_content("Error: tool execution failed"), status_code=400)

    async def _describe_source(self, request: Request, args: dict[str, Any]) -> JSONResponse:
        """Return schema metadata (information_schema.columns) for a source."""
        t0 = time.monotonic()
        pool = self._resolve_pool(request)
        source_id = args.get("source_id")

        if pool is None:
            audit = getattr(request.app.state, "audit_logger", None)
            if audit is not None:
                await self._safe_audit(
                    audit,
                    source_id=source_id or "__control__",
                    operation="read",
                    method="tools/call",
                    path="agentgate_describe_source",
                    parameters=args,
                    identity=getattr(request.state, "identity", None),
                    decision=getattr(request.state, "gateway_decision", None),
                    latency_ms=(time.monotonic() - t0) * 1000,
                    status="error",
                    error_message="No database pool available",
                )
            return JSONResponse(
                _text_content("No database pool available"),
                status_code=503,
            )

        try:
            registry = self._resolve_registry(request)
            source_config = registry.get(source_id) if registry is not None and source_id else None
            if source_config is not None and source_config.source_type.value != "postgresql":
                adapter = get_adapter(
                    source_config.connector_key,
                    source_config.metadata,
                    fabric_services=getattr(request.app.state, "fabric_services", None),
                    source_id=source_id,
                )
                introspection = await adapter.introspect(source_config.connection_config)
                # Introspection is schema shape rather than row content, so a
                # detection here is unusual - but a connector is free to
                # include sample values, and "unusual" is not a guarantee.
                #
                # `introspect` may return a mapping or a list of them, so the
                # shape is normalised to a list for redaction and restored
                # afterwards. Kept in separate names rather than reassigning
                # one: rebinding a dict-typed variable to a list is the sort
                # of thing that type-checks only because nobody looked.
                rows: list[dict[str, Any]] = (
                    list(introspection) if isinstance(introspection, list) else [introspection]
                )
                was_list = isinstance(introspection, list)
                redacted_rows, pii_detected, pii_types, redaction_stats = await self._redact_rows(
                    request, rows
                )
                introspection_result: Any = redacted_rows if was_list else redacted_rows[0]
                audit = getattr(request.app.state, "audit_logger", None)
                if audit is not None:
                    row_count = len(redacted_rows)
                    await self._safe_audit(
                        audit,
                        source_id=source_id or "__control__",
                        operation="read",
                        method="tools/call",
                        path="agentgate_describe_source",
                        parameters=args,
                        identity=getattr(request.state, "identity", None),
                        decision=getattr(request.state, "gateway_decision", None),
                        latency_ms=(time.monotonic() - t0) * 1000,
                        row_count=row_count,
                        pii_detected=pii_detected,
                        pii_types=pii_types,
                        redaction_stats=redaction_stats,
                    )
                return JSONResponse(_text_content(json.dumps(introspection_result, default=str)))

            describable = getattr(request.state, "describable_tables", None)
            if describable:
                # From the catalog: every schema, only what this caller may
                # describe, in the flat shape PostgreSQL callers already read.
                rows = await pool.fetch(
                    """
                    SELECT c.path[array_length(c.path, 1) - 2] AS table_schema,
                           c.path[array_length(c.path, 1) - 1] AS table_name,
                           c.name AS column_name, c.data_type
                    FROM source_catalog c
                    JOIN source_catalog t
                      ON t.source_id = c.source_id AND t.path = c.parent_path
                    WHERE c.source_id = $1 AND c.node_type = 'column'
                      AND c.removed_at IS NULL AND t.removed_at IS NULL
                      AND t.resource_key = ANY($2::text[])
                    ORDER BY t.resource_key, c.ordinal
                    """,
                    source_id,
                    list(describable),
                )
            else:
                conn_mgr = getattr(request.app.state, "conn_manager", None)
                if conn_mgr is not None and source_id:
                    source_pool = await conn_mgr.get_pool(source_id)
                else:
                    source_pool = pool
                rows = await source_pool.fetch(
                    "SELECT table_schema, table_name, column_name, data_type "
                    "FROM information_schema.columns "
                    "WHERE table_schema = 'public' "
                    "ORDER BY table_name, ordinal_position"
                )
            result = [dict(r) for r in rows]
            result, pii_detected, pii_types, redaction_stats = await self._redact_rows(
                request, result
            )
            audit = getattr(request.app.state, "audit_logger", None)
            if audit is not None:
                await self._safe_audit(
                    audit,
                    source_id=source_id or "__control__",
                    operation="read",
                    method="tools/call",
                    path="agentgate_describe_source",
                    parameters=args,
                    identity=getattr(request.state, "identity", None),
                    decision=getattr(request.state, "gateway_decision", None),
                    latency_ms=(time.monotonic() - t0) * 1000,
                    row_count=len(result),
                    pii_detected=pii_detected,
                    pii_types=pii_types,
                    redaction_stats=redaction_stats,
                )
            return JSONResponse(_text_content(json.dumps(result, default=str)))
        except Exception as exc:
            logger.warning("MCP describe_source error: %s", exc)
            audit = getattr(request.app.state, "audit_logger", None)
            if audit is not None:
                await self._safe_audit(
                    audit,
                    source_id=source_id or "__control__",
                    operation="read",
                    method="tools/call",
                    path="agentgate_describe_source",
                    parameters=args,
                    identity=getattr(request.state, "identity", None),
                    decision=getattr(request.state, "gateway_decision", None),
                    latency_ms=(time.monotonic() - t0) * 1000,
                    status="error",
                    error_message=str(exc),
                )
            return _tool_failure_response(exc)

    async def _related_documents(self, request: Request, args: dict[str, Any]) -> JSONResponse:
        """Return documents sharing prominent entities with an asset."""
        t0 = time.monotonic()
        pool = self._resolve_pool(request)
        asset_id = args.get("asset_id")
        limit = int(args.get("limit", 10))
        if pool is None:
            return JSONResponse(_text_content("No database pool available"), status_code=503)
        if asset_id is None:
            return JSONResponse(_text_content("asset_id is required"), status_code=400)
        try:
            seed = await pool.fetchrow(
                "SELECT source_id FROM discovery_assets WHERE id = $1",
                int(asset_id),
            )
            if seed is None:
                return JSONResponse(_text_content("Asset not found"), status_code=404)

            seed_source_id = str(seed["source_id"])
            allowed_source_ids = _allowed_source_ids_for_identity(
                getattr(request.state, "identity", None)
            )
            if allowed_source_ids is not None and seed_source_id not in allowed_source_ids:
                return JSONResponse(
                    _text_content("Related documents are not permitted for this source"),
                    status_code=403,
                )

            rows = await pool.fetch(
                """
                WITH seed_entities AS (
                    SELECT entity_text, entity_type
                    FROM entity_document_xref
                    WHERE document_id = $1
                )
                SELECT da.id AS asset_id,
                       da.source_id,
                       da.asset_type,
                       da.asset_path,
                       da.title,
                       da.summary,
                       COUNT(*) AS shared_entity_count
                FROM entity_document_xref ex
                JOIN seed_entities se
                  ON se.entity_text = ex.entity_text
                 AND se.entity_type = ex.entity_type
                JOIN discovery_assets da ON da.id = ex.document_id
                WHERE ex.document_id <> $1
                  AND da.source_id = $3
                GROUP BY da.id
                ORDER BY shared_entity_count DESC, da.updated_at DESC
                LIMIT $2
                """,
                int(asset_id),
                limit,
                seed_source_id,
            )
            payload = [dict(r) for r in rows]
            # Related documents are discovery assets reached by a second
            # route, so they need the same redaction as discovery itself.
            payload, pii_detected, pii_types, redaction_stats = await self._redact_rows(
                request, payload
            )
            audit = getattr(request.app.state, "audit_logger", None)
            if audit is not None:
                await self._safe_audit(
                    audit,
                    source_id=seed_source_id,
                    operation="discovery",
                    method="tools/call",
                    path="agentgate_related_documents",
                    parameters=args,
                    identity=getattr(request.state, "identity", None),
                    decision=getattr(request.state, "gateway_decision", None),
                    latency_ms=(time.monotonic() - t0) * 1000,
                    row_count=len(payload),
                    pii_detected=pii_detected,
                    pii_types=pii_types,
                    redaction_stats=redaction_stats,
                )
            return JSONResponse(_text_content(json.dumps(payload, default=str)))
        except Exception as exc:
            logger.warning("MCP related documents error: %s", exc)
            audit = getattr(request.app.state, "audit_logger", None)
            if audit is not None:
                await self._safe_audit(
                    audit,
                    source_id=str(args.get("source_id") or "__control__"),
                    operation="discovery",
                    method="tools/call",
                    path="agentgate_related_documents",
                    parameters=args,
                    identity=getattr(request.state, "identity", None),
                    decision=getattr(request.state, "gateway_decision", None),
                    latency_ms=(time.monotonic() - t0) * 1000,
                    status="error",
                    error_message=str(exc),
                )
            return JSONResponse(_text_content("Error: tool execution failed"), status_code=400)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _is_json_payload(data: bytes) -> bool:
    """True when a cached entry is the JSON text an MCP result is built from."""
    try:
        json.loads(data)
    except (UnicodeDecodeError, ValueError):
        return False
    return True


def _text_content(text: str) -> dict[str, Any]:
    """Wrap a string in the MCP content envelope."""
    return {"content": [{"type": "text", "text": text}]}


# Statuses that mean "the request was understood and governance refused it",
# as opposed to a malformed request or a server fault. Handshake-era clients
# render a JSON-RPC error as a transport failure ("Error POSTing to endpoint"),
# which buries the reason the operator needs to see, so these come back as tool
# results instead.
_GOVERNANCE_REFUSAL_STATUSES = {401: "unauthenticated", 403: "denied", 429: "rate_limited"}
# A source InterLock declined to use, as opposed to a request that failed while
# using one. Reported the same way and for the same reason: the agent needs the
# why, and a JSON-RPC error buries it.
_SOURCE_REFUSAL_STATUSES = {404: "not_found", 503: "unavailable"}
# A statement the database rejected: the agent wrote it and can fix it.
_QUERY_ERROR_STATUSES = {422: "query_error"}
_HANDSHAKE_TOOL_ERROR_STATUSES = {
    **_GOVERNANCE_REFUSAL_STATUSES,
    **_SOURCE_REFUSAL_STATUSES,
    **_QUERY_ERROR_STATUSES,
}


# SQLSTATE classes whose message describes the agent's own statement: syntax
# errors and unknown tables or columns and access rules (42), bad data values
# (22), integrity violations (23) and unsupported features (0A). Connection,
# authentication and server classes (08, 28, 53, 57, 58) stay opaque: their
# messages can carry hosts and addresses the error contract forbids returning.
_QUERY_ERROR_SQLSTATE_CLASSES = frozenset({"42", "22", "23", "0A"})
# The MySQL equivalents: unknown column, syntax, unknown table, access denied to
# a table or column, ambiguous column, duplicate key, bad values.
_QUERY_ERROR_MYSQL_CODES = frozenset({1052, 1054, 1062, 1064, 1142, 1143, 1146, 1292, 1366})
_QUERY_ERROR_MESSAGE_LIMIT = 500


def _query_error(exc: BaseException) -> tuple[str, str] | None:
    """(code, message) when `exc` is a database's complaint about the query itself.

    Only the primary message is used. A PostgreSQL DETAIL can quote row
    values and a HINT can name columns the agent is not granted, so neither is
    returned. The cause chain is followed because connector adapters wrap the
    driver's exception.
    """
    seen: set[int] = set()
    current: BaseException | None = exc
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        sqlstate = getattr(current, "sqlstate", None)
        if isinstance(sqlstate, str) and sqlstate[:2] in _QUERY_ERROR_SQLSTATE_CLASSES:
            message = getattr(current, "message", None) or str(current).splitlines()[0]
            return sqlstate, str(message)[:_QUERY_ERROR_MESSAGE_LIMIT]
        args: tuple[Any, ...] = tuple(getattr(current, "args", ()) or ())
        if len(args) >= 2 and isinstance(args[0], int) and args[0] in _QUERY_ERROR_MYSQL_CODES:
            return f"MySQL {args[0]}", str(args[1])[:_QUERY_ERROR_MESSAGE_LIMIT]
        current = current.__cause__ or current.__context__
    return None


def _call_correlation_id(request: Request) -> str:
    """Return the current tool call's correlation ID, choosing one outside a call."""
    return _CALL_CORRELATION_ID.get() or correlation_id_from_request(request)


def _tool_failure_response(exc: Exception, correlation_id: str | None = None) -> JSONResponse:
    """What an agent is told when a tool handler's origin work fails.

    An unknown or unavailable source says so: `ConnectionManager.get_pool`
    refuses with fixed text naming only the source - circuit open, disabled,
    upstream TLS refused, unknown id. A query the database rejected says why,
    with its SQLSTATE, so the agent can correct it; the rc.13 independent
    evaluation found an agent told only "tool execution failed" for a column
    that did not exist, while the reason sat in the audit log. Every other
    failure stays opaque, because a raw upstream exception can carry addresses
    the error contract forbids returning. Both carry the correlation ID an
    admin can find the full audit event by.
    """
    if isinstance(exc, DataSourceNotFoundError):
        return JSONResponse(_text_content(str(exc)), status_code=404)
    if isinstance(exc, DataSourceUnavailableError):
        return JSONResponse(_text_content(str(exc)), status_code=503)
    reference = f" (correlation ID {correlation_id})" if correlation_id else ""
    query_error = _query_error(exc)
    if query_error is not None:
        code, message = query_error
        body = _text_content(f"Query error {code}: {message}{reference}")
        body["query_error"] = {
            "category": "query_error",
            "code": code,
            "message": message,
            "correlation_id": correlation_id,
        }
        return JSONResponse(body, status_code=422)
    body = _text_content(f"Error: tool execution failed{reference}")
    body["correlation_id"] = correlation_id
    return JSONResponse(body, status_code=400)


def _queued_write_result(payload: dict[str, Any]) -> dict[str, Any]:
    """Shape a write held for approval as a tool result an agent can act on.

    This used to flow through as a JSON-RPC success whose body was
    `{"error": ...}` with no `content` array - not a valid tool result, so a
    strict client rejected it and the agent never learned an approval existed.

    `isError` is false on purpose. The write was refused, but this is the
    governed outcome rather than a failure, and clients retry failed tool
    calls: `ApprovalQueue.submit` has no dedupe, so a retry would enqueue a
    second approval for one intended write. The text says so explicitly
    because that sentence, not the flag, is what the model reads.
    """
    reason = str(payload.get("error", "Write queued for approval"))
    approval_id = payload.get("approval_id")
    approval_state = payload.get("approval_state") or "pending"
    return {
        "content": [
            {
                "type": "text",
                "text": (
                    f"{reason}. The statement was not executed. It is queued for "
                    f"operator approval (approval_id={approval_id}, "
                    f"approval_state={approval_state}) and will run only if approved. "
                    "Do not retry it; retrying creates a duplicate approval."
                ),
            }
        ],
        "structuredContent": {
            "status": "queued",
            "approval_id": approval_id,
            "approval_state": approval_state,
            "message": reason,
        },
        "isError": False,
    }


def _refusal_result(reason: str, status_code: int) -> dict[str, Any]:
    """Shape a refusal - governance, or an unusable source - as a tool error with the reason."""
    return {
        "content": [{"type": "text", "text": reason}],
        "structuredContent": {
            "status": _HANDSHAKE_TOOL_ERROR_STATUSES.get(status_code, "denied"),
            "code": status_code,
            "message": reason,
        },
        "isError": True,
    }


def _complete_mcp_result(payload: dict[str, Any]) -> dict[str, Any]:
    """Stamp the mandatory modern MCP result discriminator and server identity."""
    result = dict(payload)
    result["resultType"] = "complete"
    raw_meta = result.get("_meta")
    meta = dict(raw_meta) if isinstance(raw_meta, dict) else {}
    meta["io.modelcontextprotocol/serverInfo"] = dict(_MCP_SERVER_INFO)
    result["_meta"] = meta
    return result


def _validate_mcp_origin(request: Request) -> JSONResponse | None:
    """Reject browser-origin MCP requests outside the configured allowlist."""
    origin = request.headers.get("origin")
    if not origin:
        return None
    try:
        parsed = urlsplit(origin)
    except ValueError:
        return _jsonrpc_http_error(None, -32600, "Invalid Origin", 403)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return _jsonrpc_http_error(None, -32600, "Invalid Origin", 403)
    state = getattr(getattr(request, "app", None), "state", None)
    configured = getattr(state, "mcp_allowed_origins", ()) if state is not None else ()
    allowed = {str(item).rstrip("/") for item in configured or ()}
    # Never derive a trusted origin from the inbound Host header. Deployments
    # that permit browser-origin MCP calls must configure exact canonical origins.
    if origin.rstrip("/") not in allowed:
        return _jsonrpc_http_error(None, -32600, "Origin not allowed", 403)
    return None


def _jsonrpc_http_error(
    request_id: Any,
    code: int,
    message: str,
    status_code: int,
    *,
    data: dict[str, Any] | None = None,
) -> JSONResponse:
    error: dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        error["data"] = data
    return JSONResponse(
        {
            "jsonrpc": "2.0",
            "id": request_id,
            "error": error,
        },
        status_code=status_code,
    )


def _jsonrpc_sse_response(payload: dict[str, Any]) -> StreamingResponse:
    async def events() -> AsyncIterator[str]:
        yield f"event: message\ndata: {json.dumps(payload, default=_default_serializer)}\n\n"

    return StreamingResponse(
        events(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"},
    )


def _jsonrpc_sse_factory_response(
    request_id: Any,
    factory: Callable[[], Awaitable[dict[str, Any]]],
) -> StreamingResponse:
    """Run request work inside the SSE iterator so disconnect cancels it."""

    async def events() -> AsyncIterator[str]:
        try:
            result = await factory()
            payload = {"jsonrpc": "2.0", "id": request_id, "result": result}
        except _MCPIngressError as exc:
            payload = {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {
                    "code": -32602 if exc.status_code < 500 else -32603,
                    "message": exc.error,
                },
            }
        yield f"event: message\ndata: {json.dumps(payload, default=_default_serializer)}\n\n"

    return StreamingResponse(
        events(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"},
    )


@dataclass(frozen=True)
class _MCPDialect:
    """Which MCP dialect a request speaks, and the version it settled on."""

    version: str
    modern: bool


def _resolve_mcp_dialect(
    request: Request,
    *,
    request_id: Any,
    method: str,
    params: dict[str, Any],
) -> _MCPDialect | JSONResponse:
    """Decide which protocol dialect this request speaks.

    Two are served. `2026-07-28` is the modern dialect: it carries mirrored
    `Mcp-Method`/`Mcp-Name` headers and `_meta` fields, and those stay
    mandatory for it. The 2025 versions are the handshake dialect that every
    mainstream client implements; they negotiate through `initialize` and send
    no mirrors at all.

    A missing header is not an error. The python SDK clears it before
    `initialize` and Claude Code sets it only after a version is negotiated,
    so requiring it made the server unreachable to both. On `initialize` the
    version comes from the body; afterwards the 2025-06-18 spec says to assume
    `2025-03-26`.
    """
    header = request.headers.get("mcp-protocol-version", "")
    if header:
        if header in _MODERN_MCP_PROTOCOL_VERSIONS:
            return _MCPDialect(version=header, modern=True)
        if header in _SUPPORTED_MCP_PROTOCOL_VERSIONS:
            return _MCPDialect(version=header, modern=False)
        return _jsonrpc_http_error(
            request_id,
            -32022,
            "UnsupportedProtocolVersionError",
            400,
            data={
                "supported": sorted(_SUPPORTED_MCP_PROTOCOL_VERSIONS),
                "requested": header,
            },
        )

    if method == "initialize":
        negotiated = _negotiate_handshake_version(params)
        if negotiated is None:
            return _jsonrpc_http_error(request_id, -32602, "Invalid params", 400)
        return _MCPDialect(version=negotiated, modern=False)

    return _MCPDialect(version=_MCP_DEFAULT_HANDSHAKE_VERSION, modern=False)


def _negotiate_handshake_version(params: dict[str, Any]) -> str | None:
    """Pick the version to answer `initialize` with, or None if malformed.

    The spec asks a server that does not support the requested version to
    answer with one it does support, preferring its latest - the client then
    decides whether to continue.
    """
    requested = params.get("protocolVersion")
    if not isinstance(requested, str):
        return None
    if requested in MCP_HANDSHAKE_PROTOCOL_VERSIONS:
        return requested
    return MCP_LATEST_HANDSHAKE_PROTOCOL_VERSION


def _initialize_result(version: str) -> dict[str, Any]:
    """Build the `initialize` result for a handshake-era client.

    Deliberately not wrapped in the modern envelope: `resultType` and `_meta`
    are 2026 concepts, and only `tools` is advertised because a client that
    sees `resources` or `prompts` will call `resources/list`, which this
    server answers with -32601.
    """
    return {
        "protocolVersion": version,
        "capabilities": {"tools": {"listChanged": False}},
        "serverInfo": dict(_MCP_SERVER_INFO),
        "instructions": ("All tool execution is governed by InterLock source roles and policy."),
    }


def _validate_streamable_request_metadata(
    request: Request,
    *,
    request_id: Any,
    method: str,
    params: dict[str, Any],
    version: str,
) -> JSONResponse | None:
    """Validate the mirrored request metadata required by MCP 2026-07-28."""
    meta = params.get("_meta")
    body_version = (
        meta.get("io.modelcontextprotocol/protocolVersion") if isinstance(meta, dict) else None
    )
    client_capabilities = (
        meta.get("io.modelcontextprotocol/clientCapabilities") if isinstance(meta, dict) else None
    )
    if (
        body_version != version
        or request.headers.get("mcp-method", "") != method
        or not isinstance(client_capabilities, dict)
    ):
        return _jsonrpc_http_error(request_id, -32020, "HeaderMismatch", 400)

    expected_name = params.get("name") if method == "tools/call" else None
    if method in {"resources/read", "prompts/get"}:
        expected_name = params.get("uri") or params.get("name")
    supplied_name = request.headers.get("mcp-name")
    if expected_name is not None:
        try:
            decoded_name = _decode_mcp_header_value(supplied_name or "")
        except ValueError:
            return _jsonrpc_http_error(request_id, -32020, "HeaderMismatch", 400)
        if not isinstance(expected_name, str) or decoded_name != expected_name:
            return _jsonrpc_http_error(request_id, -32020, "HeaderMismatch", 400)
    elif supplied_name:
        return _jsonrpc_http_error(request_id, -32020, "HeaderMismatch", 400)
    return None


def _decode_mcp_header_value(value: str) -> str:
    if value.startswith("=?base64?") and value.endswith("?="):
        encoded = value[len("=?base64?") : -2]
        try:
            return base64.b64decode(encoded, validate=True).decode("utf-8")
        except (ValueError, UnicodeDecodeError) as exc:
            raise ValueError("invalid MCP header encoding") from exc
    if (
        not value
        or value != value.strip()
        or any(ord(char) < 0x20 or ord(char) > 0x7E for char in value)
    ):
        raise ValueError("invalid MCP header value")
    return value


def _prefers_sse(accept: str) -> bool:
    """Choose SSE when it is listed before JSON; compliant clients support both."""
    return accept.find("text/event-stream") < accept.find("application/json")


async def _read_mcp_json_body(request: Request, *, max_bytes: int) -> dict[str, Any]:
    raw = await _read_bounded_request_body(request, max_bytes=max_bytes)
    if not raw:
        raise _MCPIngressError(400, "invalid_json")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise _MCPIngressError(400, "invalid_json") from exc
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        raise _MCPIngressError(400, "invalid_json") from exc
    if not isinstance(payload, dict):
        raise _MCPIngressError(422, "invalid_request")
    return payload


async def _read_bounded_request_body(request: Request, *, max_bytes: int) -> bytes:
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            declared = int(content_length)
        except ValueError as exc:
            raise _MCPIngressError(400, "invalid_content_length") from exc
        if declared < 0:
            raise _MCPIngressError(400, "invalid_content_length")
        if declared > max_bytes:
            raise _MCPIngressError(413, "request_too_large")

    total = 0
    chunks: list[bytes] = []
    async for chunk in request.stream():
        if not chunk:
            continue
        total += len(chunk)
        if total > max_bytes:
            raise _MCPIngressError(413, "request_too_large")
        chunks.append(chunk)
    return b"".join(chunks)


def _parse_tool_name(body: dict[str, Any]) -> str:
    name = body.get("name")
    if not isinstance(name, str) or not name.strip():
        raise _MCPIngressError(422, "invalid_tool_name")
    return name


def _parse_tool_arguments(
    body: dict[str, Any],
    tool_name: str,
    max_tool_limit: int,
) -> dict[str, Any]:
    raw_args = body.get("arguments", {})
    if raw_args is None:
        args: dict[str, Any] = {}
    elif isinstance(raw_args, dict):
        args = dict(raw_args)
    else:
        raise _MCPIngressError(422, "invalid_arguments")

    canonical_name = _LEGACY_TOOL_ALIASES.get(tool_name, tool_name)
    if canonical_name in {"agentgate_discover", "agentgate_related_documents"}:
        args["limit"] = _coerce_clamped_limit(args.get("limit", 10), max_tool_limit)
    return args


def _coerce_clamped_limit(value: Any, maximum: int) -> int:
    try:
        limit = int(value)
    except (TypeError, ValueError) as exc:
        raise _MCPIngressError(422, "invalid_limit") from exc
    if limit < 1:
        raise _MCPIngressError(422, "invalid_limit")
    return min(limit, maximum)


def _clamp_int(value: int, *, default: int, minimum: int, maximum: int) -> int:
    try:
        candidate = int(value)
    except (TypeError, ValueError):
        candidate = default
    return max(minimum, min(candidate, maximum))


# Sources whose SQL governance reads the catalog, and how many tables
# interlock_describe_access lists for one before saying it stopped.

_RESOURCES_TABLE_LIMIT = 200


def _legacy_aliases(naming: Any, resources: list[str]) -> dict[str, list[str]]:
    """The legacy `public.` spelling of each resource a bare name would reach.

    Only where the source has the alias (MySQL, Snowflake) and only for tables
    in the default schema, since a bare name resolves there and nowhere else -
    the same rule `resolve_table` applies to queries.
    """
    if not getattr(naming, "legacy_alias", False) or naming.default_schema == "public":
        return {}
    prefix = f"{naming.default_schema}."
    return {
        resource: [f"public.{resource[len(prefix) :]}"]
        for resource in resources
        if resource.startswith(prefix)
    }


def _allowed_source_ids_for_identity(identity: IdentityContext | None) -> set[str] | None:
    """Return source ids granted to an identity, or None when auth is not enforced."""
    if identity is None:
        return None
    grants = getattr(identity, "source_roles", []) or []
    return {
        str(grant.get("source_id"))
        for grant in grants
        if grant.get("source_id") and _grant_allows_source_listing(grant)
    }


def _grant_allows_source_listing(grant: Any) -> bool:
    if not isinstance(grant, dict):
        return False
    role = str(grant.get("role") or grant.get("role_key") or "").lower()
    if role in {"blocked", "deny", "denied"}:
        return False
    permissions = grant.get("permissions")
    if isinstance(permissions, list) and permissions:
        has_allow = False
        for permission in permissions:
            if not isinstance(permission, dict):
                continue
            effect = str(permission.get("effect") or "allow").lower()
            action = str(permission.get("action") or "")
            if effect == "deny" and action in {"*", "source.list", "discovery.search"}:
                return False
            if effect == "allow":
                has_allow = True
        return has_allow
    return True


def _validate_fabric_result_columns(sql: str, columns: list[str], decision: Any) -> None:
    """One origin/cache delivery boundary for catalog-expanded wildcard shape.

    A wildcard authorized against an older catalog must never expose columns
    added since that scan. Explicit projections keep their normal lineage.
    """
    import sqlglot
    from sqlglot import exp

    parsed = sqlglot.parse_one(sql, read="tsql")
    if not any(
        projection.is_star
        for select in parsed.find_all(exp.Select)
        for projection in select.expressions
    ):
        return
    lineage = getattr(decision, "column_lineage", None) or {}
    normalize = str if getattr(decision, "identifier_case_sensitive", None) is True else str.lower
    expected = {normalize(name) for name in lineage}
    if not expected or any(normalize(name) not in expected for name in columns):
        raise ValueError(
            "Fabric result shape changed since catalog authorization; rescan and retry"
        )


def redact_policy_columns(
    rows: list[dict[str, Any]],
    fields: list[str],
    lineage: dict[str, set[str]],
    *,
    identifier_case_sensitive: bool | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Replace the values of every output column a policy says to redact.

    An output column is redacted when any base column it derives from matches a
    policy field - `ssn`, `customers.ssn` or `sales.customers.ssn` - so
    `SELECT ssn AS x` and `SELECT upper(ssn)` are redacted as `ssn`. With no
    lineage for a column, its own name is matched, as the HTTP proxy does.
    """
    normalize = str if identifier_case_sensitive is True else str.lower
    wanted = {normalize(field.strip()) for field in fields if field.strip()}

    def matches(base: str) -> bool:
        base = normalize(base)
        return any(base == f or base.endswith(f".{f}") for f in wanted)

    targets: set[str] = set()
    if rows:
        for name in rows[0]:
            sources = lineage.get(normalize(str(name)))
            if sources:
                if any(matches(source) for source in sources):
                    targets.add(name)
            elif normalize(str(name)) in {f.rsplit(".", 1)[-1] for f in wanted}:
                targets.add(name)
    count = 0
    redacted: list[dict[str, Any]] = []
    for row in rows:
        out = dict(row)
        for name in targets:
            if name in out:
                out[name] = "[REDACTED:POLICY]"
                count += 1
        redacted.append(out)
    return redacted, {
        "policy_fields": sorted(wanted),
        "redacted_fields": sorted(str(name) for name in targets),
        "count": count,
    }


def _sql_operation(sql: str, dialect: str = DEFAULT_DIALECT) -> str:
    """Read or write, judged in the source's own SQL grammar.

    The dialect matters here more than anywhere: SQL the classifier cannot
    parse is conservatively treated as an unknown high-risk write, which is
    correct for genuinely unreadable input and wrong for a statement that is
    perfectly valid in the source's dialect.
    """
    return "write" if WriteClassifier(dialect=dialect).classify(sql) is not None else "read"


def _grants_version(identity: IdentityContext | None) -> str | None:
    if identity is None:
        return None
    if identity.grants_version:
        return str(identity.grants_version)
    metadata = getattr(identity, "metadata", None)
    if isinstance(metadata, dict) and metadata.get("grants_version"):
        return str(metadata["grants_version"])
    return None


def _decision_scope_hash(decision: Any | None) -> str | None:
    if decision is None:
        return None
    payload: dict[str, object] = {}
    policy_decision = getattr(decision, "policy_decision", None)
    if policy_decision is not None:
        payload["policy_decision"] = policy_decision.model_dump()
    source_role_decision = getattr(decision, "source_role_decision", None)
    if source_role_decision is not None:
        payload["source_role_decision"] = (
            source_role_decision.model_dump()
            if hasattr(source_role_decision, "model_dump")
            else str(source_role_decision)
        )
    if getattr(decision, "redaction_required", False):
        payload["redaction_required"] = True
    if not payload:
        return None
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()
