"""Enterprise connector registry and lightweight adapter contracts."""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import os
import re
import ssl
import tempfile
import time
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol
from urllib.parse import quote, unquote, urlparse, urlsplit

import httpx

from interlock.connections.source_config import validate_source_config
from interlock.models import HealthStatus, PermissionRequest
from interlock.secrets.resolver import MissingSecretError, resolve, resolve_file_path
from interlock.security.egress import (
    build_safe_async_http_transport,
    join_and_validate_http_egress_url,
    validate_host_egress,
    validate_http_egress_url,
)

if TYPE_CHECKING:
    from interlock.connections.fabric.runtime import FabricServices

logger = logging.getLogger(__name__)

_SECRET_KEY_RE = re.compile(
    r"(password|passwd|pwd|token|secret|private[_-]?key|api[_-]?key|access[_-]?key|"
    r"credential|service[_-]?account|session|authorization|connection[_-]?string|dsn)",
    re.IGNORECASE,
)


@dataclass(frozen=True, slots=True)
class ConnectorCapabilities:
    supports_proxy: bool = False
    supports_query: bool = False
    supports_discovery: bool = False
    supports_ingestion: bool = False
    supports_incremental_sync: bool = False
    supports_write: bool = False
    supports_field_permissions: bool = False
    supports_cost_metadata: bool = False


@dataclass(frozen=True, slots=True)
class ConnectorDefinition:
    key: str
    name: str
    tier: int
    source_type: str
    family: str
    status: str
    description: str
    oss_libraries: tuple[str, ...] = ()
    credential_fields: tuple[str, ...] = ()
    secret_fields: tuple[str, ...] = ()
    capabilities: ConnectorCapabilities = field(default_factory=ConnectorCapabilities)
    default_cache_strategy: str = "semantic_first"
    role_templates: dict[str, list[dict[str, Any]]] = field(default_factory=dict)

    def model_dump(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "name": self.name,
            "tier": self.tier,
            "source_type": self.source_type,
            "family": self.family,
            "status": self.status,
            "description": self.description,
            "oss_libraries": list(self.oss_libraries),
            "credential_fields": list(self.credential_fields),
            "secret_fields": list(self.secret_fields),
            "capabilities": asdict(self.capabilities),
            "default_cache_strategy": self.default_cache_strategy,
            "role_templates": self.role_templates,
        }


class ConnectorAdapter(Protocol):
    definition: ConnectorDefinition

    async def probe(
        self,
        connection_config: dict[str, Any],
        *,
        timeout_seconds: float = 5.0,
    ) -> HealthStatus: ...

    async def introspect(self, connection_config: dict[str, Any]) -> dict[str, Any]: ...

    def build_permission_request(
        self,
        *,
        source_id: str,
        identity_id: int | None,
        operation: str,
        metadata: dict[str, Any] | None = None,
    ) -> PermissionRequest: ...

    async def execute_read(self, request: dict[str, Any]) -> Any: ...

    async def execute_write(self, request: dict[str, Any]) -> Any: ...

    async def list_assets(self, connection_config: dict[str, Any]) -> list[dict[str, Any]]: ...

    async def fetch_asset(self, connection_config: dict[str, Any], asset_ref: str) -> bytes: ...

    async def sync_incremental(
        self,
        connection_config: dict[str, Any],
        state: dict[str, Any],
    ) -> dict[str, Any]: ...

    def sanitize_config_for_admin(self, connection_config: dict[str, Any]) -> dict[str, Any]: ...


class BaseConnectorAdapter:
    definition: ConnectorDefinition

    def __init__(self, definition: ConnectorDefinition) -> None:
        self.definition = definition

    def _validate_config(
        self,
        connection_config: dict[str, Any],
        *,
        source_id: str | None = None,
    ) -> None:
        _validate_connector_config(self.definition, connection_config, source_id=source_id)

    async def probe(
        self,
        connection_config: dict[str, Any],
        *,
        timeout_seconds: float = 5.0,
    ) -> HealthStatus:
        return _health(
            self.definition.key,
            False,
            0,
            f"probe not implemented for connector={self.definition.key}",
        )

    async def introspect(self, connection_config: dict[str, Any]) -> dict[str, Any]:
        return {"connector": self.definition.key, "supported": False}

    def build_permission_request(
        self,
        *,
        source_id: str,
        identity_id: int | None,
        operation: str,
        metadata: dict[str, Any] | None = None,
    ) -> PermissionRequest:
        metadata = metadata or {}
        action = _generic_action(self.definition.family, operation)
        resource = str(
            metadata.get("resource") or metadata.get("path") or metadata.get("asset_ref") or "*"
        )
        return PermissionRequest(
            protocol=self.definition.family,
            source_id=source_id,
            identity_id=identity_id,
            action=action,
            resource_type=_resource_type_for_connector_action(action, metadata),
            resources=[resource],
            operation=operation,
            path=None if resource == "*" else resource,
            metadata=metadata,
        )

    async def execute_read(self, request: dict[str, Any]) -> Any:
        raise NotImplementedError(f"{self.definition.key} read execution is not implemented")

    async def execute_write(self, request: dict[str, Any]) -> Any:
        raise NotImplementedError(f"{self.definition.key} write execution is not implemented")

    async def list_assets(self, connection_config: dict[str, Any]) -> list[dict[str, Any]]:
        return []

    async def fetch_asset(self, connection_config: dict[str, Any], asset_ref: str) -> bytes:
        raise NotImplementedError(f"{self.definition.key} asset fetch is not implemented")

    async def sync_incremental(
        self,
        connection_config: dict[str, Any],
        state: dict[str, Any],
    ) -> dict[str, Any]:
        return {"state": state, "assets": []}

    def sanitize_config_for_admin(self, connection_config: dict[str, Any]) -> dict[str, Any]:
        return sanitize_config(connection_config, self.definition)


def _validate_connector_config(
    definition: ConnectorDefinition,
    connection_config: dict[str, Any],
    *,
    source_id: str | None = None,
) -> None:
    validate_source_config(
        connection_config,
        connector_key=definition.key,
        source_type=definition.source_type,
        source_id=source_id,
        allowed_fields=definition.credential_fields,
        secret_fields=definition.secret_fields,
    )


def _allow_private_egress(connection_config: dict[str, Any]) -> bool:
    return str(connection_config.get("allow_private_egress")).strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def _connector_http_client(
    connection_config: dict[str, Any],
    **kwargs: Any,
) -> httpx.AsyncClient:
    """Create a source connector client with DNS-pinned safe egress."""
    allow_private = _allow_private_egress(connection_config)
    kwargs.setdefault("follow_redirects", False)
    kwargs.setdefault("trust_env", False)
    kwargs.setdefault(
        "transport",
        build_safe_async_http_transport(allow_private=allow_private),
    )
    return httpx.AsyncClient(**kwargs)


def _guard_connector_url(
    definition: ConnectorDefinition,
    connection_config: dict[str, Any],
    base_url: str,
    path: str = "",
) -> str:
    _validate_connector_config(definition, connection_config)
    if not path:
        validate_http_egress_url(
            str(base_url),
            allow_private=_allow_private_egress(connection_config),
        )
        return str(base_url)
    return join_and_validate_http_egress_url(
        str(base_url),
        path,
        allow_private=_allow_private_egress(connection_config),
    )


def _guard_connector_host(
    definition: ConnectorDefinition,
    connection_config: dict[str, Any],
    host: str,
    *,
    port: int | None = None,
) -> None:
    _validate_connector_config(definition, connection_config)
    validate_host_egress(
        str(host),
        port=port,
        allow_private=_allow_private_egress(connection_config),
    )


def http_probe_url(connection_config: dict[str, Any]) -> str:
    """The URL Test Connection requests for an HTTP source.

    The base URL, unless `probe_path` names a route on it. An API's root often
    answers 404 while its data routes work, which made the connection test
    report a working source as failed. `probe_path` is a path on the base URL,
    never another host.
    """
    base_url = str(connection_config.get("base_url") or "")
    probe_path = str(connection_config.get("probe_path") or "").strip()
    if not probe_path:
        return base_url
    if "://" in probe_path or probe_path.startswith("//"):
        raise ValueError("connection_config.probe_path must be a path on base_url")
    return base_url.rstrip("/") + "/" + probe_path.lstrip("/")


def http_probe_error(status_code: int, probe_url: str, connection_config: dict[str, Any]) -> str:
    """Say what was probed, so a 404 from an API root is not read as 'unreachable'."""
    path = urlsplit(probe_url).path or "/"
    hint = (
        ""
        if connection_config.get("probe_path")
        else "; the test requests the base URL, so set probe_path to a route that answers"
    )
    return f"HTTP {status_code} from {path}{hint}"


class HTTPProbeAdapter(BaseConnectorAdapter):
    async def probe(
        self,
        connection_config: dict[str, Any],
        *,
        timeout_seconds: float = 5.0,
    ) -> HealthStatus:
        start = time.monotonic()
        base_url = connection_config.get("base_url")
        if not base_url:
            return _health(self.definition.key, False, 0, "connection_config.base_url is required")
        headers = _auth_headers(connection_config)
        try:
            self._validate_config(connection_config)
            probe_url = http_probe_url(connection_config)
            guarded_url = _guard_connector_url(self.definition, connection_config, probe_url)
            async with _connector_http_client(connection_config, timeout=timeout_seconds) as client:
                resp = await client.get(guarded_url, headers=headers)
            error = (
                http_probe_error(resp.status_code, probe_url, connection_config)
                if resp.status_code >= 400
                else None
            )
            return _health(
                self.definition.key,
                error is None,
                _elapsed_ms(start),
                error,
            )
        except Exception as exc:
            return _health(self.definition.key, False, _elapsed_ms(start), str(exc))


class MySQLAdapter(BaseConnectorAdapter):
    def build_permission_request(
        self,
        *,
        source_id: str,
        identity_id: int | None,
        operation: str,
        metadata: dict[str, Any] | None = None,
    ) -> PermissionRequest:
        metadata = metadata or {}
        query = str(metadata.get("query") or metadata.get("sql") or operation or "")
        return _sql_permission_request(
            source_id=source_id,
            identity_id=identity_id,
            query=query,
            dialect="mysql",
            protocol="mysql",
            metadata=metadata,
        )

    async def probe(
        self,
        connection_config: dict[str, Any],
        *,
        timeout_seconds: float = 5.0,
    ) -> HealthStatus:
        start = time.monotonic()
        host = connection_config.get("host")
        if not host:
            return _health(self.definition.key, False, 0, "connection_config.host is required")
        try:
            _guard_connector_host(
                self.definition,
                connection_config,
                str(host),
                port=int(connection_config.get("port") or 3306),
            )
        except Exception as exc:
            return _health(self.definition.key, False, _elapsed_ms(start), str(exc))
        try:
            import aiomysql  # type: ignore[import-not-found]
        except ImportError:
            return _health(self.definition.key, False, 0, "aiomysql is not installed")
        password = _secret_value(connection_config, "password", "password_ref")
        try:
            conn = await asyncio.wait_for(
                aiomysql.connect(
                    host=str(host),
                    port=int(connection_config.get("port") or 3306),
                    db=connection_config.get("database") or None,
                    user=connection_config.get("user") or connection_config.get("username"),
                    password=password,
                    ssl=_mysql_ssl_context(connection_config),
                ),
                timeout=timeout_seconds,
            )
            try:
                async with conn.cursor() as cur:
                    await cur.execute("SELECT 1")
            finally:
                conn.close()
            return _health(self.definition.key, True, _elapsed_ms(start), None)
        except Exception as exc:
            return _health(self.definition.key, False, _elapsed_ms(start), str(exc))

    async def introspect(self, connection_config: dict[str, Any]) -> dict[str, Any]:
        pool = await self._connect(connection_config)
        try:
            async with pool.cursor() as cur:
                await cur.execute(
                    """
                    SELECT table_schema, table_name, column_name, data_type
                    FROM information_schema.columns
                    WHERE table_schema = COALESCE(%s, DATABASE())
                      AND table_schema NOT IN ('information_schema', 'mysql', 'performance_schema', 'sys')
                    ORDER BY table_schema, table_name, ordinal_position
                    """,
                    (connection_config.get("database"),),
                )
                rows = await cur.fetchall()
        finally:
            pool.close()
        tables: dict[str, dict[str, Any]] = {}
        for schema, table, column, data_type in rows:
            key = f"{schema}.{table}"
            tables.setdefault(
                key,
                {"schema": schema, "table": table, "columns": []},
            )[
                "columns"
            ].append({"name": column, "type": data_type})
        return {
            "connector": self.definition.key,
            "dialect": "mysql",
            "tables": list(tables.values()),
        }

    async def execute_read(self, request: dict[str, Any]) -> dict[str, Any]:
        query = _request_query(request)
        if not query:
            raise ValueError("request.query is required")
        _ensure_single_read_sql(query, dialect="mysql")
        permission = self.build_permission_request(
            source_id=str(request.get("source_id") or ""),
            identity_id=request.get("identity_id"),
            operation=query,
            metadata={"query": query},
        )
        if (
            not permission.action.startswith("db.table.select")
            and permission.action != "db.schema.list"
        ):
            raise PermissionError("execute_read only accepts read SQL")
        conn = await self._connect(request["connection_config"])
        try:
            import aiomysql  # type: ignore[import-not-found]

            async with conn.cursor(aiomysql.DictCursor) as cur:
                parameters = request.get("parameters")
                if parameters is None:
                    await cur.execute(query)
                else:
                    await cur.execute(query, parameters)
                rows = await cur.fetchall()
                columns = [desc[0] for desc in (cur.description or [])]
            return {
                "rows": list(rows),
                "columns": columns,
                "row_count": len(rows),
                "permission_request": permission.model_dump(),
            }
        finally:
            conn.close()

    async def execute_write(self, request: dict[str, Any]) -> dict[str, Any]:
        query = _request_query(request)
        if not query:
            raise ValueError("request.query is required")
        permission = self.build_permission_request(
            source_id=str(request.get("source_id") or ""),
            identity_id=request.get("identity_id"),
            operation=query,
            metadata={"query": query},
        )
        if permission.action.startswith("db.table.select") or permission.action == "db.schema.list":
            raise PermissionError("execute_write only accepts write SQL")
        conn = await self._connect(request["connection_config"])
        try:
            async with conn.cursor() as cur:
                parameters = request.get("parameters")
                if parameters is None:
                    await cur.execute(query)
                else:
                    await cur.execute(query, parameters)
                affected = cur.rowcount
            await conn.commit()
            return {
                "affected_rows": affected,
                "permission_request": permission.model_dump(),
            }
        except Exception:
            await conn.rollback()
            raise
        finally:
            conn.close()

    async def _connect(self, connection_config: dict[str, Any]) -> Any:
        _guard_connector_host(
            self.definition,
            connection_config,
            str(connection_config.get("host") or "localhost"),
            port=int(connection_config.get("port") or 3306),
        )
        try:
            import aiomysql  # type: ignore[import-not-found]
        except ImportError as exc:
            raise RuntimeError("aiomysql is not installed") from exc
        return await aiomysql.connect(
            host=str(connection_config.get("host") or "localhost"),
            port=int(connection_config.get("port") or 3306),
            db=connection_config.get("database") or None,
            user=connection_config.get("user") or connection_config.get("username"),
            password=_secret_value(connection_config, "password", "password_ref"),
            ssl=_mysql_ssl_context(connection_config),
            autocommit=False,
        )


class S3ConnectorAdapter(BaseConnectorAdapter):
    def build_permission_request(
        self,
        *,
        source_id: str,
        identity_id: int | None,
        operation: str,
        metadata: dict[str, Any] | None = None,
    ) -> PermissionRequest:
        metadata = metadata or {}
        op = (operation or metadata.get("operation") or "read").lower()
        action = {
            "bucket.list": "storage.bucket.list",
            "bucket_list": "storage.bucket.list",
            "list": "storage.prefix.list",
            "browse": "storage.prefix.list",
            "prefix.list": "storage.prefix.list",
            "prefix_list": "storage.prefix.list",
            "read": "storage.object.read",
            "download": "storage.object.read",
            "write": "storage.object.write",
            "upload": "storage.object.write",
            "delete": "storage.object.delete",
        }.get(op, "storage.object.read")
        bucket = str(metadata.get("bucket") or metadata.get("s3_bucket") or "")
        prefix = str(metadata.get("prefix") or "")
        path = str(metadata.get("path") or metadata.get("asset_ref") or "")
        if not path:
            if action == "storage.bucket.list" and bucket:
                path = f"s3://{bucket}"
            elif bucket:
                path = f"s3://{bucket}/{prefix}".rstrip("/") + "/*"
            else:
                path = "*"
        extension = metadata.get("file_extension")
        if not extension and path not in {"*", "/"}:
            extension = Path(urlparse(path).path).suffix.lower()
        return PermissionRequest(
            protocol="object_storage",
            source_id=source_id,
            identity_id=identity_id,
            action=action,
            resources=[path],
            operation=op,
            path=path,
            metadata={**metadata, "file_extension": extension},
        )

    async def probe(
        self,
        connection_config: dict[str, Any],
        *,
        timeout_seconds: float = 5.0,
    ) -> HealthStatus:
        start = time.monotonic()
        bucket = connection_config.get("bucket")
        if not bucket:
            return _health(self.definition.key, False, 0, "connection_config.bucket is required")
        try:
            self._validate_config(connection_config)
            from interlock.connections.adapters.s3 import S3Adapter

            adapter = S3Adapter(
                bucket=str(bucket),
                prefix=str(connection_config.get("prefix") or ""),
                aws_access_key_id=_secret_value(
                    connection_config, "aws_access_key_id", "aws_access_key_id_ref"
                ),
                aws_secret_access_key=_secret_value(
                    connection_config, "aws_secret_access_key", "aws_secret_access_key_ref"
                ),
                region_name=str(connection_config.get("region_name") or "us-east-1"),
                endpoint_url=connection_config.get("endpoint_url"),
            )
            await adapter.initialize()
            if not adapter.available:
                return _health(self.definition.key, False, 0, "aiobotocore is not installed")
            await asyncio.wait_for(adapter.list_files(max_files=1), timeout=timeout_seconds)
            return _health(self.definition.key, True, _elapsed_ms(start), None)
        except Exception as exc:
            return _health(self.definition.key, False, _elapsed_ms(start), str(exc))

    async def list_assets(self, connection_config: dict[str, Any]) -> list[dict[str, Any]]:
        self._validate_config(connection_config)
        from interlock.connections.adapters.s3 import S3Adapter

        adapter = S3Adapter(
            bucket=str(connection_config["bucket"]),
            prefix=str(connection_config.get("prefix") or ""),
            aws_access_key_id=_secret_value(
                connection_config, "aws_access_key_id", "aws_access_key_id_ref"
            ),
            aws_secret_access_key=_secret_value(
                connection_config, "aws_secret_access_key", "aws_secret_access_key_ref"
            ),
            region_name=str(connection_config.get("region_name") or "us-east-1"),
            endpoint_url=connection_config.get("endpoint_url"),
        )
        await adapter.initialize()
        return [
            {
                "asset_path": f"s3://{connection_config['bucket']}/{item.key}",
                "asset_type": "file",
                "size": item.size,
                "last_modified": item.last_modified,
                "etag": item.etag,
                "metadata": {
                    "bucket": str(connection_config["bucket"]),
                    "key": item.key,
                    "prefix": str(connection_config.get("prefix") or ""),
                    "file_extension": Path(item.key).suffix.lower(),
                    "size": item.size,
                },
            }
            for item in await adapter.list_files()
        ]

    async def fetch_asset(self, connection_config: dict[str, Any], asset_ref: str) -> bytes:
        self._validate_config(connection_config)
        key = _s3_key_from_ref(asset_ref, default_bucket=str(connection_config["bucket"]))
        try:
            from aiobotocore.session import (
                get_session as get_aio_session,  # type: ignore[import-not-found]
            )
        except ImportError as exc:
            raise RuntimeError("aiobotocore is not installed") from exc
        session = get_aio_session()
        credentials = _aws_credentials(connection_config)
        async with session.create_client(
            "s3",
            region_name=str(connection_config.get("region_name") or "us-east-1"),
            endpoint_url=connection_config.get("endpoint_url"),
            **credentials,
        ) as client:
            resp = await client.get_object(Bucket=str(connection_config["bucket"]), Key=key)
            async with resp["Body"] as stream:
                return await stream.read()

    async def execute_read(self, request: dict[str, Any]) -> Any:
        op = str(request.get("operation") or "list").lower()
        config = request["connection_config"]
        if op in {"list", "browse", "discovery"}:
            return {"assets": await self.list_assets(config)}
        if op in {"read", "download"}:
            asset_ref = str(request.get("asset_ref") or request.get("path") or "")
            return await self.fetch_asset(config, asset_ref)
        raise ValueError(f"unsupported S3 read operation: {op}")

    async def execute_write(self, request: dict[str, Any]) -> dict[str, Any]:
        op = str(request.get("operation") or "").lower()
        if op not in {"write", "upload", "put", "delete", "remove"}:
            raise ValueError("S3 execute_write supports write/upload/put/delete/remove")
        config = request["connection_config"]
        self._validate_config(config)
        key = _s3_key_from_ref(
            str(request.get("asset_ref") or request.get("path") or ""),
            default_bucket=str(config["bucket"]),
        )
        try:
            from aiobotocore.session import (
                get_session as get_aio_session,  # type: ignore[import-not-found]
            )
        except ImportError as exc:
            raise RuntimeError("aiobotocore is not installed") from exc
        session = get_aio_session()
        async with session.create_client(
            "s3",
            region_name=str(config.get("region_name") or "us-east-1"),
            endpoint_url=config.get("endpoint_url"),
            **_aws_credentials(config),
        ) as client:
            if op in {"delete", "remove"}:
                resp = await client.delete_object(Bucket=str(config["bucket"]), Key=key)
                return {
                    "asset_ref": f"s3://{config['bucket']}/{key}",
                    "deleted": True,
                    "version_id": resp.get("VersionId"),
                }
            body = request.get("body")
            if isinstance(body, str):
                body = body.encode()
            if not isinstance(body, bytes):
                raise ValueError("request.body must be bytes or str")
            resp = await client.put_object(Bucket=str(config["bucket"]), Key=key, Body=body)
        return {"asset_ref": f"s3://{config['bucket']}/{key}", "etag": resp.get("ETag")}

    async def sync_incremental(
        self,
        connection_config: dict[str, Any],
        state: dict[str, Any],
    ) -> dict[str, Any]:
        assets = await self.list_assets(connection_config)
        since = state.get("last_modified")
        if since:
            assets = [
                asset for asset in assets if str(asset.get("last_modified") or "") > str(since)
            ]
        next_cursor = max(
            (str(asset.get("last_modified") or "") for asset in assets), default=since or ""
        )
        return {"state": {"last_modified": next_cursor}, "assets": assets}


class SnowflakeAdapter(BaseConnectorAdapter):
    def build_permission_request(
        self,
        *,
        source_id: str,
        identity_id: int | None,
        operation: str,
        metadata: dict[str, Any] | None = None,
    ) -> PermissionRequest:
        metadata = metadata or {}
        query = str(metadata.get("query") or metadata.get("sql") or operation or "")
        return _sql_permission_request(
            source_id=source_id,
            identity_id=identity_id,
            query=query,
            dialect="snowflake",
            protocol="snowflake",
            metadata=metadata,
        )

    async def probe(
        self,
        connection_config: dict[str, Any],
        *,
        timeout_seconds: float = 5.0,
    ) -> HealthStatus:
        start = time.monotonic()
        required = ("account", "user")
        missing = [key for key in required if not connection_config.get(key)]
        if missing:
            return _health(
                self.definition.key,
                False,
                0,
                f"connection_config.{', '.join(missing)} is required",
            )

        def _run_probe() -> None:
            conn = self._connect_sync(connection_config)
            try:
                with conn.cursor() as cur:
                    cur.execute("SELECT 1")
                    cur.fetchone()
            finally:
                conn.close()

        try:
            await asyncio.wait_for(asyncio.to_thread(_run_probe), timeout=timeout_seconds)
            return _health(self.definition.key, True, _elapsed_ms(start), None)
        except Exception as exc:
            return _health(self.definition.key, False, _elapsed_ms(start), str(exc))

    async def introspect(self, connection_config: dict[str, Any]) -> dict[str, Any]:
        def _run() -> dict[str, Any]:
            conn = self._connect_sync(connection_config)
            try:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        SELECT table_catalog, table_schema, table_name, column_name, data_type
                        FROM information_schema.columns
                        WHERE table_schema = COALESCE(%s, CURRENT_SCHEMA())
                        ORDER BY table_catalog, table_schema, table_name, ordinal_position
                        """,
                        (connection_config.get("schema"),),
                    )
                    rows = cur.fetchall()
            finally:
                conn.close()
            tables: dict[str, dict[str, Any]] = {}
            for catalog, schema, table, column, data_type in rows:
                key = f"{catalog}.{schema}.{table}"
                tables.setdefault(
                    key,
                    {"database": catalog, "schema": schema, "table": table, "columns": []},
                )["columns"].append({"name": column, "type": data_type})
            return {
                "connector": self.definition.key,
                "dialect": "snowflake",
                "tables": list(tables.values()),
            }

        return await asyncio.to_thread(_run)

    async def list_assets(self, connection_config: dict[str, Any]) -> list[dict[str, Any]]:
        introspection = await self.introspect(connection_config)
        assets: list[dict[str, Any]] = []
        for table in introspection.get("tables", []):
            database = table.get("database") or connection_config.get("database") or ""
            schema = table.get("schema") or connection_config.get("schema") or ""
            table_name = table.get("table") or ""
            assets.append(
                {
                    "asset_path": f"snowflake://{database}/{schema}/{table_name}",
                    "asset_type": "table",
                    "title": f"{schema}.{table_name}".strip("."),
                    "metadata": {
                        "database": database,
                        "schema": schema,
                        "table": table_name,
                        "columns": table.get("columns", []),
                        "warehouse": connection_config.get("warehouse"),
                        "role": connection_config.get("role"),
                    },
                }
            )
        return assets

    async def fetch_asset(self, connection_config: dict[str, Any], asset_ref: str) -> bytes:
        for asset in await self.list_assets(connection_config):
            if asset["asset_path"] == asset_ref:
                return json.dumps(asset, default=str).encode()
        raise FileNotFoundError(f"Snowflake asset not found: {asset_ref}")

    async def execute_read(self, request: dict[str, Any]) -> dict[str, Any]:
        query = _request_query(request)
        if not query:
            raise ValueError("request.query is required")
        _ensure_single_read_sql(query, dialect="snowflake")
        permission = self.build_permission_request(
            source_id=str(request.get("source_id") or ""),
            identity_id=request.get("identity_id"),
            operation=query,
            metadata={"query": query},
        )
        if (
            not permission.action.startswith("db.table.select")
            and permission.action != "db.schema.list"
        ):
            raise PermissionError("execute_read only accepts read SQL")

        def _run() -> dict[str, Any]:
            conn = self._connect_sync(request["connection_config"])
            try:
                with conn.cursor() as cur:
                    cur.execute(query, request.get("parameters") or None)
                    columns = [desc[0] for desc in (cur.description or [])]
                    rows = [dict(zip(columns, row, strict=False)) for row in cur.fetchall()]
                    query_id = getattr(cur, "sfqid", None)
                cost_metadata = self._cost_metadata(
                    conn,
                    request["connection_config"],
                    query_id=query_id,
                    row_count=len(rows),
                )
            finally:
                conn.close()
            return {
                "rows": rows,
                "columns": columns,
                "row_count": len(rows),
                "cost_metadata": cost_metadata,
                "permission_request": permission.model_dump(),
            }

        return await asyncio.to_thread(_run)

    async def execute_write(self, request: dict[str, Any]) -> dict[str, Any]:
        query = _request_query(request)
        if not query:
            raise ValueError("request.query is required")
        _ensure_single_write_sql(query, dialect="snowflake")
        permission = self.build_permission_request(
            source_id=str(request.get("source_id") or ""),
            identity_id=request.get("identity_id"),
            operation=query,
            metadata={"query": query},
        )
        if permission.action.startswith("db.table.select") or permission.action == "db.schema.list":
            raise PermissionError("execute_write only accepts write SQL")

        def _run() -> dict[str, Any]:
            conn = self._connect_sync(request["connection_config"])
            try:
                with conn.cursor() as cur:
                    cur.execute(query, request.get("parameters") or None)
                    affected = cur.rowcount
                    query_id = getattr(cur, "sfqid", None)
                cost_metadata = self._cost_metadata(
                    conn,
                    request["connection_config"],
                    query_id=query_id,
                    affected_rows=affected,
                )
                conn.commit()
            except Exception:
                conn.rollback()
                raise
            finally:
                conn.close()
            return {
                "affected_rows": affected,
                "cost_metadata": cost_metadata,
                "permission_request": permission.model_dump(),
            }

        return await asyncio.to_thread(_run)

    def _connect_sync(self, connection_config: dict[str, Any]) -> Any:
        self._validate_config(connection_config)
        try:
            import snowflake.connector  # type: ignore[import-not-found]
        except ImportError as exc:
            raise RuntimeError("snowflake-connector-python is not installed") from exc
        connect_kwargs = {
            "account": connection_config["account"],
            "user": connection_config["user"],
            "password": _secret_value(connection_config, "password", "password_ref"),
            "warehouse": connection_config.get("warehouse"),
            "database": connection_config.get("database"),
            "schema": connection_config.get("schema"),
            "role": connection_config.get("role"),
            "application": connection_config.get("application") or "InterLock",
        }
        if connection_config.get("authenticator"):
            connect_kwargs["authenticator"] = connection_config["authenticator"]
        if connection_config.get("private_key") or connection_config.get("private_key_ref"):
            connect_kwargs["private_key"] = _secret_value(
                connection_config, "private_key", "private_key_ref"
            )
            connect_kwargs["password"] = None
        return snowflake.connector.connect(
            **{key: value for key, value in connect_kwargs.items() if value is not None}
        )

    def _cost_metadata(
        self,
        conn: Any,
        connection_config: dict[str, Any],
        *,
        query_id: str | None,
        row_count: int | None = None,
        affected_rows: int | None = None,
    ) -> dict[str, Any]:
        metadata = {
            "query_id": query_id,
            "warehouse": connection_config.get("warehouse"),
            "database": connection_config.get("database"),
            "schema": connection_config.get("schema"),
            "role": connection_config.get("role"),
            "row_count": row_count,
            "affected_rows": affected_rows,
        }
        if query_id and connection_config.get("collect_query_history", True):
            metadata.update(self._query_history_metadata(conn, query_id))
        return {key: value for key, value in metadata.items() if value is not None}

    def _query_history_metadata(self, conn: Any, query_id: str) -> dict[str, Any]:
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT query_id, bytes_scanned, bytes_written,
                           rows_produced, credits_used_cloud_services
                    FROM TABLE(INFORMATION_SCHEMA.QUERY_HISTORY_BY_SESSION(RESULT_LIMIT => 50))
                    WHERE query_id = %s
                    """,
                    (query_id,),
                )
                row = cur.fetchone()
                if not row:
                    return {}
                columns = [str(desc[0]).lower() for desc in (cur.description or [])]
                return {
                    key: value
                    for key, value in zip(columns, row, strict=False)
                    if value is not None and key != "query_id"
                }
        except Exception:
            logger.debug("Snowflake query history lookup failed", exc_info=True)
            return {}


class ZendeskAdapter(BaseConnectorAdapter):
    """Read/discovery-first Zendesk adapter backed by the official REST API."""

    def build_permission_request(
        self,
        *,
        source_id: str,
        identity_id: int | None,
        operation: str,
        metadata: dict[str, Any] | None = None,
    ) -> PermissionRequest:
        metadata = metadata or {}
        object_type = str(metadata.get("object_type") or "ticket")
        object_id = str(metadata.get("object_id") or "*")
        op = (operation or "read").lower()
        if op in {"describe", "metadata"}:
            action = "saas.object.describe"
        elif op in {"search", "list_assets", "discovery"}:
            action = "saas.object.search"
        elif op in {"write", "update", "comment", "create"}:
            action = "saas.object.write"
        elif op in {"delete", "remove"}:
            action = "saas.object.delete"
        else:
            action = "saas.object.read"
        resource = f"zendesk:{object_type}/{object_id}"
        return PermissionRequest(
            protocol="saas",
            source_id=source_id,
            identity_id=identity_id,
            action=action,
            resources=[resource],
            operation=op,
            path=resource,
            metadata={"connector_key": "zendesk", **metadata, "object_type": object_type},
        )

    async def probe(
        self,
        connection_config: dict[str, Any],
        *,
        timeout_seconds: float = 5.0,
    ) -> HealthStatus:
        start = time.monotonic()
        if not _zendesk_base_url(connection_config):
            return _health(
                self.definition.key, False, 0, "connection_config.subdomain or base_url is required"
            )
        try:
            url = _guard_connector_url(
                self.definition,
                connection_config,
                _zendesk_base_url(connection_config),
                "/api/v2/users/me.json",
            )
            async with _connector_http_client(connection_config, timeout=timeout_seconds) as client:
                resp = await client.get(
                    url,
                    headers=_zendesk_headers(connection_config),
                )
            return _health_from_response(self.definition.key, resp.status_code, _elapsed_ms(start))
        except Exception as exc:
            return _health(self.definition.key, False, _elapsed_ms(start), str(exc))

    async def execute_read(self, request: dict[str, Any]) -> Any:
        op = str(request.get("operation") or "search").lower()
        if op in {"describe", "metadata"}:
            return await self.introspect(request["connection_config"])
        if op == "list_assets":
            return {"assets": await self.list_assets(request["connection_config"])}
        asset_ref = str(request.get("asset_ref") or request.get("path") or "")
        if asset_ref:
            return json.loads(
                (await self.fetch_asset(request["connection_config"], asset_ref)).decode()
            )
        query = request.get("query") or request.get("search")
        if query:
            return await self._get_json(
                request["connection_config"], f"/api/v2/search.json?query={quote(str(query))}"
            )
        return {"assets": await self.list_assets(request["connection_config"])}

    async def execute_write(self, request: dict[str, Any]) -> Any:
        raise NotImplementedError(
            "Zendesk writes are approval-gated and not enabled by the Tier 1 MVP adapter"
        )

    async def introspect(self, connection_config: dict[str, Any]) -> dict[str, Any]:
        return {
            "connector": self.definition.key,
            "objects": [
                {
                    "object_type": "ticket",
                    "id_field": "id",
                    "title_field": "subject",
                    "filter_fields": [
                        "brand_id",
                        "group_id",
                        "organization_id",
                        "status",
                        "tags",
                    ],
                    "read_asset": "zendesk://ticket/{id}",
                },
                {
                    "object_type": "article",
                    "id_field": "id",
                    "title_field": "title",
                    "filter_fields": ["section_id", "locale", "draft"],
                    "read_asset": "zendesk://article/{id}",
                },
                {
                    "object_type": "user",
                    "id_field": "id",
                    "title_field": "name",
                    "filter_fields": ["organization_id", "role", "tags"],
                    "read_asset": "zendesk://user/{id}",
                },
                {
                    "object_type": "organization",
                    "id_field": "id",
                    "title_field": "name",
                    "filter_fields": ["tags"],
                    "read_asset": "zendesk://organization/{id}",
                },
            ],
            "role_constraint_keys": [
                "object_types",
                "brand_ids",
                "group_ids",
                "organization_ids",
                "statuses",
                "tags",
                "allowed_fields",
            ],
        }

    async def list_assets(self, connection_config: dict[str, Any]) -> list[dict[str, Any]]:
        assets: list[dict[str, Any]] = []
        endpoints = [
            (
                _zendesk_endpoint(
                    "/api/v2/tickets.json",
                    per_page=_zendesk_limit(connection_config, "max_tickets", 25),
                    extra=_zendesk_ticket_filter_params(connection_config),
                ),
                "ticket",
                "tickets",
                "id",
                "subject",
            ),
            (
                _zendesk_endpoint(
                    "/api/v2/help_center/articles.json",
                    per_page=_zendesk_limit(connection_config, "max_articles", 25),
                ),
                "article",
                "articles",
                "id",
                "title",
            ),
        ]
        if _zendesk_bool(connection_config, "include_users", True):
            endpoints.append(
                (
                    _zendesk_endpoint(
                        "/api/v2/users.json",
                        per_page=_zendesk_limit(connection_config, "max_users", 25),
                    ),
                    "user",
                    "users",
                    "id",
                    "name",
                )
            )
        if _zendesk_bool(connection_config, "include_organizations", True):
            endpoints.append(
                (
                    _zendesk_endpoint(
                        "/api/v2/organizations.json",
                        per_page=_zendesk_limit(connection_config, "max_organizations", 25),
                    ),
                    "organization",
                    "organizations",
                    "id",
                    "name",
                )
            )
        for path, object_type, collection_key, id_key, title_key in endpoints:
            try:
                payload = await self._get_json(connection_config, path)
            except Exception:
                continue
            values = payload.get(collection_key) or []
            for item in values:
                item_id = item.get(id_key)
                if item_id is None:
                    continue
                assets.append(
                    {
                        "asset_path": f"zendesk://{object_type}/{item_id}",
                        "asset_type": object_type,
                        "title": item.get(title_key) or str(item_id),
                        "updated_at": item.get("updated_at"),
                        "metadata": _zendesk_asset_metadata(object_type, item),
                    }
                )
        return assets

    async def fetch_asset(self, connection_config: dict[str, Any], asset_ref: str) -> bytes:
        parsed = urlparse(asset_ref)
        object_type = parsed.netloc or parsed.path.strip("/").split("/")[0]
        object_id = parsed.path.strip("/").split("/")[-1]
        if object_type == "ticket":
            payload = await self._get_json(connection_config, f"/api/v2/tickets/{object_id}.json")
            if _zendesk_bool(connection_config, "include_ticket_comments", True):
                try:
                    comments = await self._get_json(
                        connection_config,
                        f"/api/v2/tickets/{object_id}/comments.json?include=users",
                    )
                    payload["comments"] = comments.get("comments", [])
                    if comments.get("users"):
                        payload["comment_users"] = comments.get("users", [])
                except Exception:
                    logger.debug("Zendesk ticket comments fetch failed", exc_info=True)
        elif object_type == "article":
            payload = await self._get_json(
                connection_config, f"/api/v2/help_center/articles/{object_id}.json"
            )
        elif object_type == "user":
            payload = await self._get_json(connection_config, f"/api/v2/users/{object_id}.json")
        elif object_type == "organization":
            payload = await self._get_json(
                connection_config, f"/api/v2/organizations/{object_id}.json"
            )
        else:
            raise ValueError(f"unsupported Zendesk asset_ref: {asset_ref}")
        return json.dumps(payload, default=str).encode()

    async def sync_incremental(
        self,
        connection_config: dict[str, Any],
        state: dict[str, Any],
    ) -> dict[str, Any]:
        start_time = int(state.get("start_time") or 0)
        payload = await self._get_json(
            connection_config,
            f"/api/v2/incremental/tickets/cursor.json?start_time={start_time}",
        )
        tickets = payload.get("tickets") or []
        assets = [
            {
                "asset_path": f"zendesk://ticket/{ticket.get('id')}",
                "asset_type": "ticket",
                "title": ticket.get("subject") or str(ticket.get("id")),
                "updated_at": ticket.get("updated_at"),
                "metadata": _zendesk_asset_metadata("ticket", ticket),
            }
            for ticket in tickets
        ]
        return {
            "state": {
                "start_time": payload.get("end_time", start_time),
                "cursor": payload.get("after_cursor"),
            },
            "assets": assets,
        }

    async def _get_json(self, connection_config: dict[str, Any], path: str) -> dict[str, Any]:
        url = _guard_connector_url(
            self.definition,
            connection_config,
            _zendesk_base_url(connection_config),
            path,
        )
        async with _connector_http_client(
            connection_config, timeout=float(connection_config.get("timeout_seconds") or 10)
        ) as client:
            resp = await client.get(
                url,
                headers=_zendesk_headers(connection_config),
            )
            resp.raise_for_status()
            return resp.json()


class SlackAdapter(BaseConnectorAdapter):
    """Slack discovery adapter using slack-sdk's async Web API client."""

    def build_permission_request(
        self,
        *,
        source_id: str,
        identity_id: int | None,
        operation: str,
        metadata: dict[str, Any] | None = None,
    ) -> PermissionRequest:
        metadata = metadata or {}
        asset_ref = str(metadata.get("asset_ref") or metadata.get("path") or "")
        parsed = _parse_slack_asset_ref(asset_ref)
        op = str(
            operation or metadata.get("operation") or parsed.get("object_type") or "message"
        ).lower()
        if parsed.get("object_type") == "channel" or op in {"channel", "channels", "list"}:
            action = "collab.channel.read"
        elif parsed.get("object_type") == "file" or op in {"file", "files"}:
            action = "collab.file.read"
        else:
            action = "collab.message.read"
        resource = asset_ref or str(metadata.get("resource") or "*")
        return PermissionRequest(
            protocol="collaboration",
            source_id=source_id,
            identity_id=identity_id,
            action=action,
            resources=[resource],
            operation=op,
            path=None if resource == "*" else resource,
            metadata={"connector_key": "slack", **metadata, **parsed},
        )

    async def probe(
        self,
        connection_config: dict[str, Any],
        *,
        timeout_seconds: float = 5.0,
    ) -> HealthStatus:
        start = time.monotonic()
        if not connection_config.get("workspace"):
            return _health(self.definition.key, False, 0, "connection_config.workspace is required")
        try:
            self._validate_config(connection_config)
            client = _slack_client(connection_config)
            await asyncio.wait_for(client.auth_test(), timeout=timeout_seconds)
            return _health(self.definition.key, True, _elapsed_ms(start), None)
        except Exception as exc:
            return _health(self.definition.key, False, _elapsed_ms(start), str(exc))

    async def execute_read(self, request: dict[str, Any]) -> Any:
        if str(request.get("operation") or "list_assets") == "list_assets":
            return {"assets": await self.list_assets(request["connection_config"])}
        asset_ref = str(request.get("asset_ref") or request.get("path") or "")
        if asset_ref:
            return json.loads(
                (await self.fetch_asset(request["connection_config"], asset_ref)).decode()
            )
        return {"assets": await self.list_assets(request["connection_config"])}

    async def execute_write(self, request: dict[str, Any]) -> Any:
        raise NotImplementedError(
            "Slack writes are intentionally disabled for the Tier 1 MVP adapter"
        )

    async def introspect(self, connection_config: dict[str, Any]) -> dict[str, Any]:
        return {
            "connector": self.definition.key,
            "objects": [
                {"object_type": "channel", "asset": "slack://channel/{channel_id}"},
                {"object_type": "message", "asset": "slack://channel/{channel_id}/message/{ts}"},
                {
                    "object_type": "thread_reply",
                    "asset": "slack://channel/{channel_id}/thread/{thread_ts}/message/{ts}",
                },
                {"object_type": "file", "asset": "slack://file/{file_id}"},
            ],
            "role_constraint_keys": [
                "workspaces",
                "channel_ids",
                "channel_names",
                "channel_types",
                "user_ids",
                "file_types",
            ],
        }

    async def list_assets(self, connection_config: dict[str, Any]) -> list[dict[str, Any]]:
        self._validate_config(connection_config)
        client = _slack_client(connection_config)
        channel_ids = _slack_id_list(
            connection_config.get("channel_ids") or connection_config.get("channels")
        )
        channel_limit = _slack_limit(connection_config, "max_channels", 25)
        message_limit = _slack_limit(connection_config, "max_messages_per_channel", 25)
        reply_limit = _slack_limit(connection_config, "max_replies_per_thread", 25)
        if channel_ids:
            channels: list[dict[str, Any]] = []
            for channel_id in channel_ids[:channel_limit]:
                try:
                    info = await client.conversations_info(channel=channel_id)
                    channel = dict(info.get("channel") or {})
                except Exception:
                    channel = {}
                channel.setdefault("id", channel_id)
                channels.append(channel)
        else:
            channels_resp = await client.conversations_list(
                limit=channel_limit,
                types=connection_config.get("channel_types") or "public_channel,private_channel",
            )
            channels = list(channels_resp.get("channels", []))
        assets: list[dict[str, Any]] = []
        for channel in channels:
            channel_id = channel.get("id")
            if not channel_id:
                continue
            channel_name = channel.get("name") or channel_id
            channel_type = _slack_channel_type(channel)
            assets.append(
                {
                    "asset_path": f"slack://channel/{channel_id}",
                    "asset_type": "channel",
                    "title": channel_name,
                    "metadata": _slack_asset_metadata(
                        "channel",
                        channel_id=channel_id,
                        channel_name=channel_name,
                        channel_type=channel_type,
                        is_private=channel.get("is_private"),
                        workspace=connection_config.get("workspace"),
                    ),
                }
            )
            if not _slack_bool(connection_config, "include_messages", True):
                continue
            try:
                history = await client.conversations_history(
                    channel=channel_id, limit=message_limit
                )
            except Exception:
                continue
            for message in history.get("messages", []):
                ts = message.get("ts")
                if not ts:
                    continue
                assets.append(
                    {
                        "asset_path": f"slack://channel/{channel_id}/message/{ts}",
                        "asset_type": "message",
                        "title": (message.get("text") or ts or "")[:120],
                        "updated_at": ts,
                        "metadata": _slack_asset_metadata(
                            "message",
                            channel_id=channel_id,
                            channel_name=channel_name,
                            channel_type=channel_type,
                            ts=ts,
                            thread_ts=message.get("thread_ts"),
                            user_id=message.get("user"),
                            workspace=connection_config.get("workspace"),
                        ),
                    }
                )
                for file_item in message.get("files") or []:
                    file_id = file_item.get("id")
                    if not file_id:
                        continue
                    assets.append(
                        _slack_file_asset(
                            file_item,
                            channel_id=channel_id,
                            channel_name=channel_name,
                            channel_type=channel_type,
                            workspace=connection_config.get("workspace"),
                        )
                    )
                if (
                    _slack_bool(connection_config, "include_threads", True)
                    and message.get("thread_ts")
                    and str(message.get("thread_ts")) == str(ts)
                    and int(message.get("reply_count") or 0) > 0
                ):
                    try:
                        replies = await client.conversations_replies(
                            channel=channel_id,
                            ts=ts,
                            limit=reply_limit,
                        )
                    except Exception:
                        continue
                    for reply in replies.get("messages", [])[1:]:
                        reply_ts = reply.get("ts")
                        if not reply_ts:
                            continue
                        assets.append(
                            {
                                "asset_path": f"slack://channel/{channel_id}/thread/{ts}/message/{reply_ts}",
                                "asset_type": "thread_reply",
                                "title": (reply.get("text") or reply_ts or "")[:120],
                                "updated_at": reply_ts,
                                "metadata": _slack_asset_metadata(
                                    "thread_reply",
                                    channel_id=channel_id,
                                    channel_name=channel_name,
                                    channel_type=channel_type,
                                    ts=reply_ts,
                                    thread_ts=ts,
                                    user_id=reply.get("user"),
                                    workspace=connection_config.get("workspace"),
                                ),
                            }
                        )
        if _slack_bool(connection_config, "include_files", True):
            try:
                files_resp = await client.files_list(
                    limit=_slack_limit(connection_config, "max_files", 25),
                )
            except Exception:
                files_resp = {}
            for file_item in files_resp.get("files", []):
                file_channels = {str(value) for value in file_item.get("channels") or []}
                if channel_ids and file_channels and file_channels.isdisjoint(channel_ids):
                    continue
                assets.append(
                    _slack_file_asset(
                        file_item,
                        workspace=connection_config.get("workspace"),
                    )
                )
        return assets

    async def fetch_asset(self, connection_config: dict[str, Any], asset_ref: str) -> bytes:
        self._validate_config(connection_config)
        parsed = urlparse(asset_ref)
        parts = parsed.path.strip("/").split("/")
        client = _slack_client(connection_config)
        if parsed.netloc == "channel" and len(parts) == 1:
            payload = await client.conversations_info(channel=parts[0])
        elif parsed.netloc == "channel" and len(parts) >= 3 and parts[1] == "message":
            payload = await client.conversations_history(
                channel=parts[0], latest=parts[2], inclusive=True, limit=1
            )
        elif (
            parsed.netloc == "channel"
            and len(parts) >= 5
            and parts[1] == "thread"
            and parts[3] == "message"
        ):
            payload = await client.conversations_replies(
                channel=parts[0],
                ts=parts[2],
                latest=parts[4],
                inclusive=True,
                limit=1,
            )
        elif parsed.netloc == "file" and parts:
            payload = await client.files_info(file=parts[0])
        else:
            raise ValueError(f"unsupported Slack asset_ref: {asset_ref}")
        return json.dumps(_slack_response_dict(payload), default=str).encode()

    async def sync_incremental(
        self,
        connection_config: dict[str, Any],
        state: dict[str, Any],
    ) -> dict[str, Any]:
        assets = await self.list_assets(connection_config)
        return {"state": {"synced_at": datetime.now(UTC).isoformat(), **state}, "assets": assets}


class GwsRunner:
    """Safe subprocess wrapper around the Google Workspace CLI.

    The CLI has a dynamic Discovery-driven command surface, so InterLock keeps
    its own static allowlist and always builds argv lists itself. User input can
    influence JSON params, never executable command tokens.
    """

    ALLOWED_COMMANDS: frozenset[tuple[str, ...]] = frozenset(
        {
            ("drive", "about", "get"),
            ("drive", "files", "list"),
            ("drive", "files", "get"),
            ("drive", "files", "export"),
            ("gmail", "users", "messages", "list"),
            ("gmail", "users", "messages", "get"),
            ("calendar", "calendarList", "list"),
            ("calendar", "events", "list"),
            ("calendar", "events", "get"),
            ("docs", "documents", "get"),
            ("sheets", "spreadsheets", "get"),
            ("slides", "presentations", "get"),
            ("chat", "spaces", "list"),
            ("chat", "spaces", "messages", "list"),
            ("admin", "reports", "activities", "list"),
        }
    )

    def __init__(self, binary: str = "gws") -> None:
        self.binary = binary

    async def run_json(
        self,
        connection_config: dict[str, Any],
        command: tuple[str, ...],
        *,
        params: dict[str, Any] | None = None,
        body: dict[str, Any] | None = None,
        timeout_seconds: float | None = None,
        page_all: bool = False,
    ) -> Any:
        if command not in self.ALLOWED_COMMANDS:
            raise PermissionError(f"gws command is not allowlisted: {' '.join(command)}")
        if connection_config.get("gws_binary"):
            raise PermissionError("connection_config.gws_binary is not allowed")
        argv = [self.binary, *command]
        if params is not None:
            argv.extend(["--params", json.dumps(params, separators=(",", ":"))])
        if body is not None:
            argv.extend(["--json", json.dumps(body, separators=(",", ":"))])
        if page_all:
            argv.append("--page-all")

        env, cleanup_paths = _gws_env(connection_config)
        try:
            proc = await asyncio.create_subprocess_exec(
                *argv,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env,
            )
            try:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(),
                    timeout=timeout_seconds
                    or float(connection_config.get("timeout_seconds") or 20),
                )
            except TimeoutError as exc:
                proc.kill()
                await proc.communicate()
                raise RuntimeError(f"gws command timed out: {' '.join(command)}") from exc
        finally:
            for path in cleanup_paths:
                try:
                    path.unlink()
                except FileNotFoundError:
                    pass

        if proc.returncode != 0:
            detail = _scrub_gws_text(
                stderr.decode(errors="replace").strip() or stdout.decode(errors="replace").strip(),
                connection_config,
            )
            raise RuntimeError(
                f"gws command failed ({proc.returncode}) for {' '.join(command)}: {detail}"
            )
        try:
            return _parse_gws_output(stdout)
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"gws returned invalid JSON: {exc.msg}") from exc


class GoogleWorkspaceAdapter(BaseConnectorAdapter):
    """Read/discovery-first Google Workspace adapter.

    Uses native Google API clients for delegated service-account credentials and
    keeps ``gws`` as the CLI execution backend for OAuth/config-directory based
    usage.
    """

    def __init__(
        self,
        definition: ConnectorDefinition,
        *,
        runner: GwsRunner | None = None,
    ) -> None:
        super().__init__(definition)
        self._runner = runner or GwsRunner()

    def build_permission_request(
        self,
        *,
        source_id: str,
        identity_id: int | None,
        operation: str,
        metadata: dict[str, Any] | None = None,
    ) -> PermissionRequest:
        metadata = metadata or {}
        asset_ref = str(metadata.get("asset_ref") or metadata.get("path") or "")
        parsed = _parse_workspace_asset_ref(asset_ref)
        op = str(operation or metadata.get("operation") or parsed.get("object_type") or "read")
        action = _workspace_action(op, parsed)
        resource = asset_ref or _workspace_resource_from_metadata(metadata, parsed)
        return PermissionRequest(
            protocol="workspace",
            source_id=source_id,
            identity_id=identity_id,
            action=action,
            resource_type=_workspace_resource_type(action),
            resources=[resource],
            operation=op.lower(),
            path=None if resource == "*" else resource,
            risk_level=(
                "low" if action.endswith(".read") or action.endswith(".download") else "high"
            ),
            metadata={"connector_key": "google_workspace", **metadata, **parsed},
        )

    async def probe(
        self,
        connection_config: dict[str, Any],
        *,
        timeout_seconds: float = 5.0,
    ) -> HealthStatus:
        start = time.monotonic()
        if not _gws_has_auth(connection_config):
            return _health(
                self.definition.key,
                False,
                0,
                "one of access_token_ref, credentials_file_ref, service_account_json_ref, or gws_config_dir is required",
            )
        try:
            self._validate_config(connection_config)
            if _gws_use_native_backend(connection_config):
                await asyncio.wait_for(
                    asyncio.to_thread(
                        _google_service(connection_config, "drive", "v3")
                        .about()
                        .get(fields="user")
                        .execute
                    ),
                    timeout=timeout_seconds,
                )
            else:
                await self._runner.run_json(
                    connection_config,
                    ("drive", "about", "get"),
                    params={"fields": "user"},
                    timeout_seconds=timeout_seconds,
                )
            return _health(self.definition.key, True, _elapsed_ms(start), None)
        except Exception as exc:
            return _health(self.definition.key, False, _elapsed_ms(start), str(exc))

    async def introspect(self, connection_config: dict[str, Any]) -> dict[str, Any]:
        return {
            "connector": self.definition.key,
            "execution_backend": (
                "google_api" if _gws_use_native_backend(connection_config) else "gws_cli"
            ),
            "services": _gws_enabled_services(connection_config),
            "objects": [
                {"object_type": "drive_file", "asset": "gdrive://file/{file_id}"},
                {"object_type": "drive_folder", "asset": "gdrive://folder/{folder_id}"},
                {"object_type": "gmail_message", "asset": "gmail://user/{email}/message/{id}"},
                {"object_type": "calendar_event", "asset": "gcal://calendar/{id}/event/{id}"},
                {"object_type": "doc", "asset": "gdocs://document/{document_id}"},
                {"object_type": "sheet", "asset": "gsheets://spreadsheet/{spreadsheet_id}"},
                {"object_type": "slide", "asset": "gslides://presentation/{presentation_id}"},
                {"object_type": "chat_message", "asset": "gchat://space/{space_id}/message/{id}"},
                {"object_type": "admin_report", "asset": "gadmin://reports/{application}/{event}"},
            ],
            # None of the Workspace-specific keys (drive_ids, mime_types, ...)
            # is read by the source-role evaluator, so none is advertised.
            "role_constraint_keys": [],
        }

    async def execute_read(self, request: dict[str, Any]) -> Any:
        if str(request.get("operation") or "").lower() in {"describe", "metadata"}:
            return await self.introspect(request["connection_config"])
        asset_ref = str(request.get("asset_ref") or request.get("path") or "")
        if asset_ref:
            return json.loads(
                (await self.fetch_asset(request["connection_config"], asset_ref)).decode()
            )
        return {"assets": await self.list_assets(request["connection_config"])}

    async def execute_write(self, request: dict[str, Any]) -> Any:
        raise NotImplementedError(
            "Google Workspace writes are approval-gated and disabled by default"
        )

    async def list_assets(self, connection_config: dict[str, Any]) -> list[dict[str, Any]]:
        self._validate_config(connection_config)
        assets: list[dict[str, Any]] = []
        services = set(_gws_enabled_services(connection_config))
        if "drive" in services:
            assets.extend(await self._list_drive_assets(connection_config))
        if "gmail" in services:
            assets.extend(await self._list_gmail_assets(connection_config))
        if "calendar" in services:
            assets.extend(await self._list_calendar_assets(connection_config))
        if "chat" in services:
            assets.extend(await self._list_chat_assets(connection_config))
        if "admin_reports" in services:
            assets.extend(await self._list_admin_report_assets(connection_config))
        return assets

    async def fetch_asset(self, connection_config: dict[str, Any], asset_ref: str) -> bytes:
        self._validate_config(connection_config)
        parsed = _parse_workspace_asset_ref(asset_ref)
        service = parsed.get("service")
        object_id = str(parsed.get("object_id") or "")
        if service == "drive":
            if _gws_use_native_backend(connection_config):
                payload = await asyncio.to_thread(
                    _google_service(connection_config, "drive", "v3")
                    .files()
                    .get(
                        fileId=object_id,
                        fields="id,name,mimeType,modifiedTime,webViewLink,owners,parents,driveId,size",
                        supportsAllDrives=True,
                    )
                    .execute
                )
            else:
                payload = await self._runner.run_json(
                    connection_config,
                    ("drive", "files", "get"),
                    params={
                        "fileId": object_id,
                        "fields": "id,name,mimeType,modifiedTime,webViewLink,owners,parents,driveId,size",
                    },
                )
        elif service == "docs":
            if _gws_use_native_backend(connection_config):
                payload = await asyncio.to_thread(
                    _google_service(connection_config, "docs", "v1")
                    .documents()
                    .get(documentId=object_id)
                    .execute
                )
            else:
                payload = await self._runner.run_json(
                    connection_config,
                    ("docs", "documents", "get"),
                    params={"documentId": object_id},
                )
        elif service == "sheets":
            if _gws_use_native_backend(connection_config):
                payload = await asyncio.to_thread(
                    _google_service(connection_config, "sheets", "v4")
                    .spreadsheets()
                    .get(spreadsheetId=object_id)
                    .execute
                )
            else:
                payload = await self._runner.run_json(
                    connection_config,
                    ("sheets", "spreadsheets", "get"),
                    params={"spreadsheetId": object_id},
                )
        elif service == "slides":
            if _gws_use_native_backend(connection_config):
                payload = await asyncio.to_thread(
                    _google_service(connection_config, "slides", "v1")
                    .presentations()
                    .get(presentationId=object_id)
                    .execute
                )
            else:
                payload = await self._runner.run_json(
                    connection_config,
                    ("slides", "presentations", "get"),
                    params={"presentationId": object_id},
                )
        elif service == "gmail":
            user_id = parsed.get("user") or connection_config.get("gmail_user") or "me"
            if _gws_use_native_backend(connection_config):
                payload = await asyncio.to_thread(
                    _google_service(connection_config, "gmail", "v1")
                    .users()
                    .messages()
                    .get(userId=user_id, id=object_id, format="full")
                    .execute
                )
            else:
                payload = await self._runner.run_json(
                    connection_config,
                    ("gmail", "users", "messages", "get"),
                    params={
                        "userId": user_id,
                        "id": object_id,
                        "format": "full",
                    },
                )
        elif service == "calendar":
            calendar_id = (
                parsed.get("calendar_id") or connection_config.get("calendar_ids") or "primary"
            )
            if _gws_use_native_backend(connection_config):
                payload = await asyncio.to_thread(
                    _google_service(connection_config, "calendar", "v3")
                    .events()
                    .get(calendarId=calendar_id, eventId=object_id)
                    .execute
                )
            else:
                payload = await self._runner.run_json(
                    connection_config,
                    ("calendar", "events", "get"),
                    params={
                        "calendarId": calendar_id,
                        "eventId": object_id,
                    },
                )
        elif service == "chat":
            payload = await self._runner.run_json(
                connection_config,
                ("chat", "spaces", "messages", "list"),
                params={"parent": parsed.get("space") or object_id, "pageSize": 1},
            )
        else:
            raise ValueError(f"unsupported Google Workspace asset_ref: {asset_ref}")
        return json.dumps(payload, default=str).encode()

    async def sync_incremental(
        self,
        connection_config: dict[str, Any],
        state: dict[str, Any],
    ) -> dict[str, Any]:
        return {
            "state": {"synced_at": datetime.now(UTC).isoformat(), **state},
            "assets": await self.list_assets(connection_config),
        }

    async def _list_drive_assets(self, config: dict[str, Any]) -> list[dict[str, Any]]:
        params: dict[str, Any] = {
            "pageSize": _int_config(config, "max_drive_files", 25, upper=200),
            "fields": "files(id,name,mimeType,modifiedTime,webViewLink,owners,parents,driveId,size),nextPageToken",
        }
        drive_query = str(config.get("drive_query") or "").strip()
        if drive_query:
            params["q"] = drive_query
        if config.get("drive_id"):
            params.update(
                {
                    "driveId": config["drive_id"],
                    "corpora": "drive",
                    "includeItemsFromAllDrives": True,
                    "supportsAllDrives": True,
                }
            )
        if _gws_use_native_backend(config):
            payloads = [
                await asyncio.to_thread(
                    _google_service(config, "drive", "v3").files().list(**params).execute
                )
            ]
        else:
            payloads = _gws_payloads(
                await self._runner.run_json(config, ("drive", "files", "list"), params=params)
            )
        assets: list[dict[str, Any]] = []
        for payload in payloads:
            for item in payload.get("files") or []:
                file_id = item.get("id")
                if not file_id:
                    continue
                mime_type = str(item.get("mimeType") or "")
                asset_path = _workspace_drive_asset_ref(str(file_id), mime_type)
                assets.append(
                    {
                        "asset_path": asset_path,
                        "asset_type": _workspace_drive_asset_type(mime_type),
                        "title": item.get("name") or str(file_id),
                        "updated_at": item.get("modifiedTime"),
                        "metadata": _workspace_metadata(
                            "drive",
                            object_id=str(file_id),
                            mime_type=mime_type,
                            name=item.get("name"),
                            drive_id=item.get("driveId"),
                            parents=item.get("parents"),
                            owners=item.get("owners"),
                            workspace_domain=config.get("workspace_domain"),
                            web_view_link=item.get("webViewLink"),
                            size=item.get("size"),
                        ),
                    }
                )
        return assets

    async def _list_gmail_assets(self, config: dict[str, Any]) -> list[dict[str, Any]]:
        users = _list_config(config.get("gmail_users") or config.get("gmail_user")) or ["me"]
        labels = _list_config(config.get("gmail_labels"))
        query = str(config.get("gmail_query") or "").strip()
        max_results = _int_config(config, "max_gmail_messages", 25, upper=100)
        assets: list[dict[str, Any]] = []
        for user in users:
            params: dict[str, Any] = {"userId": user, "maxResults": max_results}
            if query:
                params["q"] = query
            if labels:
                params["labelIds"] = labels
            if _gws_use_native_backend(config):
                payloads = [
                    await asyncio.to_thread(
                        _google_service(config, "gmail", "v1")
                        .users()
                        .messages()
                        .list(**params)
                        .execute
                    )
                ]
            else:
                payloads = _gws_payloads(
                    await self._runner.run_json(
                        config, ("gmail", "users", "messages", "list"), params=params
                    )
                )
            for payload in payloads:
                for item in payload.get("messages") or []:
                    message_id = item.get("id")
                    if not message_id:
                        continue
                    assets.append(
                        {
                            "asset_path": f"gmail://user/{quote(str(user), safe='')}/message/{quote(str(message_id), safe='')}",
                            "asset_type": "gmail_message",
                            "title": item.get("snippet") or str(message_id),
                            "metadata": _workspace_metadata(
                                "gmail",
                                object_id=str(message_id),
                                user=user,
                                thread_id=item.get("threadId"),
                                labels=labels,
                                workspace_domain=config.get("workspace_domain"),
                            ),
                        }
                    )
        return assets

    async def _list_calendar_assets(self, config: dict[str, Any]) -> list[dict[str, Any]]:
        calendars = _list_config(config.get("calendar_ids")) or ["primary"]
        max_results = _int_config(config, "max_calendar_events", 25, upper=100)
        assets: list[dict[str, Any]] = []
        for calendar_id in calendars:
            params: dict[str, Any] = {
                "calendarId": calendar_id,
                "maxResults": max_results,
                "singleEvents": True,
                "orderBy": "startTime",
            }
            if config.get("calendar_time_min"):
                params["timeMin"] = config["calendar_time_min"]
            if config.get("calendar_time_max"):
                params["timeMax"] = config["calendar_time_max"]
            if _gws_use_native_backend(config):
                payloads = [
                    await asyncio.to_thread(
                        _google_service(config, "calendar", "v3").events().list(**params).execute
                    )
                ]
            else:
                payloads = _gws_payloads(
                    await self._runner.run_json(
                        config, ("calendar", "events", "list"), params=params
                    )
                )
            for payload in payloads:
                for item in payload.get("items") or []:
                    event_id = item.get("id")
                    if not event_id:
                        continue
                    assets.append(
                        {
                            "asset_path": f"gcal://calendar/{quote(str(calendar_id), safe='')}/event/{quote(str(event_id), safe='')}",
                            "asset_type": "calendar_event",
                            "title": item.get("summary") or str(event_id),
                            "updated_at": item.get("updated"),
                            "metadata": _workspace_metadata(
                                "calendar",
                                object_id=str(event_id),
                                calendar_id=calendar_id,
                                start=item.get("start"),
                                end=item.get("end"),
                                workspace_domain=config.get("workspace_domain"),
                            ),
                        }
                    )
        return assets

    async def _list_chat_assets(self, config: dict[str, Any]) -> list[dict[str, Any]]:
        payloads = _gws_payloads(
            await self._runner.run_json(
                config,
                ("chat", "spaces", "list"),
                params={"pageSize": _int_config(config, "max_chat_spaces", 25, upper=100)},
            )
        )
        assets: list[dict[str, Any]] = []
        for payload in payloads:
            for space in payload.get("spaces") or []:
                name = str(space.get("name") or "")
                if not name:
                    continue
                assets.append(
                    {
                        "asset_path": f"gchat://space/{quote(name, safe='')}",
                        "asset_type": "chat_space",
                        "title": space.get("displayName") or name,
                        "metadata": _workspace_metadata(
                            "chat",
                            object_id=name,
                            space=name,
                            workspace_domain=config.get("workspace_domain"),
                        ),
                    }
                )
        return assets

    async def _list_admin_report_assets(self, config: dict[str, Any]) -> list[dict[str, Any]]:
        applications = _list_config(config.get("admin_report_applications")) or ["drive"]
        user_key = str(config.get("admin_report_user_key") or "all")
        max_results = _int_config(config, "max_admin_activities", 25, upper=100)
        assets: list[dict[str, Any]] = []
        for application in applications:
            payloads = _gws_payloads(
                await self._runner.run_json(
                    config,
                    ("admin", "reports", "activities", "list"),
                    params={
                        "userKey": user_key,
                        "applicationName": application,
                        "maxResults": max_results,
                    },
                )
            )
            for payload in payloads:
                for item in payload.get("items") or []:
                    item_id = str(
                        item.get("id", {}).get("uniqueQualifier") or item.get("etag") or ""
                    )
                    if not item_id:
                        continue
                    assets.append(
                        {
                            "asset_path": f"gadmin://reports/{quote(str(application), safe='')}/{quote(item_id, safe='')}",
                            "asset_type": "admin_report",
                            "title": item.get("name") or item_id,
                            "updated_at": item.get("id", {}).get("time"),
                            "metadata": _workspace_metadata(
                                "admin_reports",
                                object_id=item_id,
                                application=application,
                                user_key=user_key,
                                workspace_domain=config.get("workspace_domain"),
                            ),
                        }
                    )
        return assets


class GitHubAdapter(BaseConnectorAdapter):
    """GitHub/GitHub Enterprise discovery adapter using PyGithub."""

    def build_permission_request(
        self,
        *,
        source_id: str,
        identity_id: int | None,
        operation: str,
        metadata: dict[str, Any] | None = None,
    ) -> PermissionRequest:
        return _repo_permission_request(
            provider="github",
            source_id=source_id,
            identity_id=identity_id,
            operation=operation,
            metadata=metadata,
        )

    async def probe(
        self,
        connection_config: dict[str, Any],
        *,
        timeout_seconds: float = 5.0,
    ) -> HealthStatus:
        start = time.monotonic()
        try:
            await asyncio.wait_for(
                asyncio.to_thread(self._probe_sync, connection_config), timeout=timeout_seconds
            )
            return _health(self.definition.key, True, _elapsed_ms(start), None)
        except Exception as exc:
            return _health(self.definition.key, False, _elapsed_ms(start), str(exc))

    async def execute_read(self, request: dict[str, Any]) -> Any:
        asset_ref = str(request.get("asset_ref") or request.get("path") or "")
        if asset_ref:
            return json.loads(
                (await self.fetch_asset(request["connection_config"], asset_ref)).decode()
            )
        return {"assets": await self.list_assets(request["connection_config"])}

    async def execute_write(self, request: dict[str, Any]) -> Any:
        raise NotImplementedError(
            "GitHub writes are approval-gated and not enabled by the Tier 1 MVP adapter"
        )

    async def list_assets(self, connection_config: dict[str, Any]) -> list[dict[str, Any]]:
        return await asyncio.to_thread(self._list_assets_sync, connection_config)

    async def fetch_asset(self, connection_config: dict[str, Any], asset_ref: str) -> bytes:
        return await asyncio.to_thread(self._fetch_asset_sync, connection_config, asset_ref)

    async def sync_incremental(
        self,
        connection_config: dict[str, Any],
        state: dict[str, Any],
    ) -> dict[str, Any]:
        assets = await self.list_assets(connection_config)
        return {"state": {"synced_at": datetime.now(UTC).isoformat(), **state}, "assets": assets}

    async def introspect(self, connection_config: dict[str, Any]) -> dict[str, Any]:
        return {
            "connector": self.definition.key,
            "objects": [
                {"object_type": "repository", "asset": "github://repo/{org}/{repo}"},
                {"object_type": "issue", "asset": "github://issue/{org}/{repo}/{number}"},
                {"object_type": "pull_request", "asset": "github://pr/{org}/{repo}/{number}"},
                {"object_type": "release", "asset": "github://release/{org}/{repo}/{tag}"},
                {"object_type": "workflow", "asset": "github://workflow/{org}/{repo}/{name}"},
                {"object_type": "file", "asset": "github://file/{org}/{repo}/{path}"},
            ],
            "role_constraint_keys": [
                "orgs",
                "repos",
                "branches",
                "path_prefixes",
                "labels",
                "visibility",
                "workflows",
            ],
        }

    def _client(self, connection_config: dict[str, Any]) -> Any:
        self._validate_config(connection_config)
        try:
            from github import Auth, Github  # type: ignore[import-not-found]
        except ImportError as exc:
            raise RuntimeError("PyGithub is not installed") from exc
        token = _secret_value(connection_config, "token", "token_ref")
        auth = Auth.Token(token) if token else None
        base_url = connection_config.get("base_url")
        if base_url and "github.com" not in str(base_url):
            guarded_url = _guard_connector_url(self.definition, connection_config, str(base_url))
            return Github(auth=auth, base_url=guarded_url.rstrip("/"))
        return Github(auth=auth)

    def _probe_sync(self, connection_config: dict[str, Any]) -> None:
        self._client(connection_config).get_rate_limit()

    def _list_assets_sync(self, connection_config: dict[str, Any]) -> list[dict[str, Any]]:
        gh = self._client(connection_config)
        org_name = connection_config.get("org") or connection_config.get("owner")
        repo_names = _repo_path_list(
            connection_config.get("repo_names")
            or connection_config.get("repos")
            or connection_config.get("repositories")
        )
        if repo_names:
            repos = [
                gh.get_repo(name if "/" in name or not org_name else f"{org_name}/{name}")
                for name in repo_names
            ]
        else:
            repos = (
                gh.get_organization(org_name).get_repos() if org_name else gh.get_user().get_repos()
            )
        limit = _repo_limit(connection_config, "max_repos", 50)
        issue_limit = _repo_limit(connection_config, "max_issues_per_repo", 10)
        pr_limit = _repo_limit(connection_config, "max_prs_per_repo", 10)
        release_limit = _repo_limit(connection_config, "max_releases_per_repo", 5)
        workflow_limit = _repo_limit(connection_config, "max_workflows_per_repo", 10)
        code_paths = _repo_path_list(connection_config.get("include_code_paths"))
        assets: list[dict[str, Any]] = []
        for index, repo in enumerate(repos):
            if index >= limit:
                break
            full_name = repo.full_name
            default_branch = getattr(repo, "default_branch", None)
            assets.append(
                {
                    "asset_path": f"github://repo/{full_name}",
                    "asset_type": "repository",
                    "title": full_name,
                    "updated_at": repo.updated_at.isoformat() if repo.updated_at else None,
                    "metadata": _repo_metadata(
                        "github",
                        "repository",
                        full_name=full_name,
                        branch=default_branch,
                        private=getattr(repo, "private", None),
                        default_branch=default_branch,
                    ),
                }
            )
            for issue in _safe_iter(lambda repo=repo: repo.get_issues(state="open"), issue_limit):
                if getattr(issue, "pull_request", None):
                    continue
                assets.append(
                    {
                        "asset_path": f"github://issue/{full_name}/{issue.number}",
                        "asset_type": "issue",
                        "title": issue.title,
                        "updated_at": issue.updated_at.isoformat() if issue.updated_at else None,
                        "metadata": _repo_metadata(
                            "github",
                            "issue",
                            full_name=full_name,
                            number=issue.number,
                            labels=_github_labels(issue),
                        ),
                    }
                )
            for pr in _safe_iter(lambda repo=repo: repo.get_pulls(state="open"), pr_limit):
                assets.append(
                    {
                        "asset_path": f"github://pr/{full_name}/{pr.number}",
                        "asset_type": "pull_request",
                        "title": pr.title,
                        "updated_at": (
                            pr.updated_at.isoformat() if getattr(pr, "updated_at", None) else None
                        ),
                        "metadata": _repo_metadata(
                            "github",
                            "pull_request",
                            full_name=full_name,
                            number=pr.number,
                            branch=getattr(getattr(pr, "head", None), "ref", None),
                            labels=_github_labels(pr),
                        ),
                    }
                )
            for release in _safe_iter(lambda repo=repo: repo.get_releases(), release_limit):
                tag = getattr(release, "tag_name", None)
                assets.append(
                    {
                        "asset_path": f"github://release/{full_name}/{tag}",
                        "asset_type": "release",
                        "title": getattr(release, "title", None) or tag,
                        "updated_at": (
                            release.updated_at.isoformat()
                            if getattr(release, "updated_at", None)
                            else None
                        ),
                        "metadata": _repo_metadata(
                            "github", "release", full_name=full_name, tag=tag
                        ),
                    }
                )
            for workflow in _safe_iter(lambda repo=repo: repo.get_workflows(), workflow_limit):
                name = getattr(workflow, "name", None) or getattr(workflow, "path", None)
                assets.append(
                    {
                        "asset_path": f"github://workflow/{full_name}/{quote(str(name or 'workflow'), safe='')}",
                        "asset_type": "workflow",
                        "title": name or "workflow",
                        "metadata": _repo_metadata(
                            "github", "workflow", full_name=full_name, workflow=name
                        ),
                    }
                )
            for path in code_paths:
                assets.append(
                    {
                        "asset_path": f"github://file/{full_name}/{path}",
                        "asset_type": "file",
                        "title": path,
                        "metadata": _repo_metadata(
                            "github",
                            "file",
                            full_name=full_name,
                            branch=connection_config.get("ref") or default_branch,
                            path=path,
                        ),
                    }
                )
        return assets

    def _fetch_asset_sync(self, connection_config: dict[str, Any], asset_ref: str) -> bytes:
        gh = self._client(connection_config)
        parsed = urlparse(asset_ref)
        parts = parsed.path.strip("/").split("/")
        if parsed.netloc == "repo" and len(parts) >= 2:
            repo = gh.get_repo("/".join(parts[:2]))
            payload = {
                "full_name": repo.full_name,
                "description": repo.description,
                "default_branch": repo.default_branch,
            }
        elif parsed.netloc == "issue" and len(parts) >= 3:
            repo = gh.get_repo("/".join(parts[:2]))
            issue = repo.get_issue(int(parts[2]))
            payload = {
                "title": issue.title,
                "body": issue.body,
                "number": issue.number,
                "state": issue.state,
                "labels": _github_labels(issue),
            }
        elif parsed.netloc == "pr" and len(parts) >= 3:
            repo = gh.get_repo("/".join(parts[:2]))
            pr = repo.get_pull(int(parts[2]))
            payload = {
                "title": pr.title,
                "body": pr.body,
                "number": pr.number,
                "state": pr.state,
                "head": getattr(getattr(pr, "head", None), "ref", None),
            }
        elif parsed.netloc == "release" and len(parts) >= 3:
            repo = gh.get_repo("/".join(parts[:2]))
            tag = "/".join(parts[2:])
            release = repo.get_release(tag)
            payload = {"title": release.title, "body": release.body, "tag_name": release.tag_name}
        elif parsed.netloc == "workflow" and len(parts) >= 3:
            repo = gh.get_repo("/".join(parts[:2]))
            payload = {"repo": repo.full_name, "workflow": "/".join(parts[2:])}
        elif parsed.netloc == "file" and len(parts) >= 3:
            repo = gh.get_repo("/".join(parts[:2]))
            path = "/".join(parts[2:])
            # Omit `ref` rather than passing None: PyGithub 2.x validates it
            # with `is_optional`, which accepts a str or its NotSet sentinel
            # and rejects None, so the default configuration could never read
            # a file.
            ref = connection_config.get("ref")
            content = repo.get_contents(path, ref=str(ref)) if ref else repo.get_contents(path)
            payload = {
                "path": path,
                "branch": connection_config.get("ref") or getattr(repo, "default_branch", None),
                "content": content.decoded_content.decode(errors="replace"),
            }
        else:
            raise ValueError(f"unsupported GitHub asset_ref: {asset_ref}")
        return json.dumps(payload, default=str).encode()


class GitLabAdapter(BaseConnectorAdapter):
    """GitLab discovery adapter using python-gitlab."""

    def build_permission_request(
        self,
        *,
        source_id: str,
        identity_id: int | None,
        operation: str,
        metadata: dict[str, Any] | None = None,
    ) -> PermissionRequest:
        return _repo_permission_request(
            provider="gitlab",
            source_id=source_id,
            identity_id=identity_id,
            operation=operation,
            metadata=metadata,
        )

    async def probe(
        self,
        connection_config: dict[str, Any],
        *,
        timeout_seconds: float = 5.0,
    ) -> HealthStatus:
        start = time.monotonic()
        try:
            await asyncio.wait_for(
                asyncio.to_thread(self._probe_sync, connection_config), timeout=timeout_seconds
            )
            return _health(self.definition.key, True, _elapsed_ms(start), None)
        except Exception as exc:
            return _health(self.definition.key, False, _elapsed_ms(start), str(exc))

    async def execute_read(self, request: dict[str, Any]) -> Any:
        asset_ref = str(request.get("asset_ref") or request.get("path") or "")
        if asset_ref:
            return json.loads(
                (await self.fetch_asset(request["connection_config"], asset_ref)).decode()
            )
        return {"assets": await self.list_assets(request["connection_config"])}

    async def execute_write(self, request: dict[str, Any]) -> Any:
        raise NotImplementedError(
            "GitLab writes are approval-gated and not enabled by the Tier 1 MVP adapter"
        )

    async def list_assets(self, connection_config: dict[str, Any]) -> list[dict[str, Any]]:
        return await asyncio.to_thread(self._list_assets_sync, connection_config)

    async def fetch_asset(self, connection_config: dict[str, Any], asset_ref: str) -> bytes:
        return await asyncio.to_thread(self._fetch_asset_sync, connection_config, asset_ref)

    async def sync_incremental(
        self,
        connection_config: dict[str, Any],
        state: dict[str, Any],
    ) -> dict[str, Any]:
        assets = await self.list_assets(connection_config)
        return {"state": {"synced_at": datetime.now(UTC).isoformat(), **state}, "assets": assets}

    async def introspect(self, connection_config: dict[str, Any]) -> dict[str, Any]:
        return {
            "connector": self.definition.key,
            "objects": [
                {"object_type": "project", "asset": "gitlab://project/{project_id}"},
                {"object_type": "issue", "asset": "gitlab://issue/{project_id}/{iid}"},
                {
                    "object_type": "merge_request",
                    "asset": "gitlab://merge_request/{project_id}/{iid}",
                },
                {"object_type": "pipeline", "asset": "gitlab://pipeline/{project_id}/{id}"},
                {"object_type": "file", "asset": "gitlab://file/{project_id}/{path}"},
            ],
            "role_constraint_keys": [
                "projects",
                "branches",
                "path_prefixes",
                "labels",
                "visibility",
            ],
        }

    def _client(self, connection_config: dict[str, Any]) -> Any:
        self._validate_config(connection_config)
        try:
            import gitlab  # type: ignore[import-not-found]
        except ImportError as exc:
            raise RuntimeError("python-gitlab is not installed") from exc
        base_url = str(connection_config.get("base_url") or "https://gitlab.com")
        if connection_config.get("base_url"):
            base_url = _guard_connector_url(self.definition, connection_config, base_url)
        return gitlab.Gitlab(
            base_url,
            private_token=_secret_value(connection_config, "token", "token_ref"),
        )

    def _probe_sync(self, connection_config: dict[str, Any]) -> None:
        self._client(connection_config).auth()

    def _list_assets_sync(self, connection_config: dict[str, Any]) -> list[dict[str, Any]]:
        gl = self._client(connection_config)
        group = connection_config.get("group")
        project_filter = connection_config.get("project")
        if project_filter:
            projects = [gl.projects.get(project_filter)]
        elif group:
            projects = gl.groups.get(group).projects.list(
                all=False,
                per_page=int(connection_config.get("max_projects") or 50),
            )
        else:
            projects = gl.projects.list(
                membership=True,
                per_page=int(connection_config.get("max_projects") or 50),
            )
        issue_limit = _repo_limit(connection_config, "max_issues_per_project", 10)
        mr_limit = _repo_limit(connection_config, "max_mrs_per_project", 10)
        pipeline_limit = _repo_limit(connection_config, "max_pipelines_per_project", 5)
        code_paths = _repo_path_list(connection_config.get("include_code_paths"))
        assets: list[dict[str, Any]] = []
        for project_ref in projects:
            project = (
                project_ref
                if hasattr(project_ref, "path_with_namespace")
                else gl.projects.get(project_ref.id)
            )
            project_id = str(project.id)
            project_path = getattr(project, "path_with_namespace", project_id)
            default_branch = getattr(project, "default_branch", None)
            assets.append(
                {
                    "asset_path": f"gitlab://project/{project.id}",
                    "asset_type": "project",
                    "title": project_path,
                    "updated_at": getattr(project, "last_activity_at", None),
                    "metadata": _repo_metadata(
                        "gitlab",
                        "project",
                        full_name=project_path,
                        project_id=project_id,
                        branch=default_branch,
                        default_branch=default_branch,
                        visibility=getattr(project, "visibility", None),
                    ),
                }
            )
            for issue in project.issues.list(state="opened", per_page=issue_limit):
                assets.append(
                    {
                        "asset_path": f"gitlab://issue/{project.id}/{issue.iid}",
                        "asset_type": "issue",
                        "title": issue.title,
                        "updated_at": issue.updated_at,
                        "metadata": _repo_metadata(
                            "gitlab",
                            "issue",
                            full_name=project_path,
                            project_id=project_id,
                            number=issue.iid,
                            labels=getattr(issue, "labels", []),
                        ),
                    }
                )
            for mr in _safe_iter(
                lambda project=project: project.mergerequests.list(
                    state="opened",
                    per_page=mr_limit,
                ),
                mr_limit,
            ):
                assets.append(
                    {
                        "asset_path": f"gitlab://merge_request/{project.id}/{mr.iid}",
                        "asset_type": "merge_request",
                        "title": mr.title,
                        "updated_at": getattr(mr, "updated_at", None),
                        "metadata": _repo_metadata(
                            "gitlab",
                            "merge_request",
                            full_name=project_path,
                            project_id=project_id,
                            number=mr.iid,
                            branch=getattr(mr, "source_branch", None),
                            labels=getattr(mr, "labels", []),
                        ),
                    }
                )
            for pipeline in _safe_iter(
                lambda project=project: project.pipelines.list(per_page=pipeline_limit),
                pipeline_limit,
            ):
                pipeline_id = getattr(pipeline, "id", None)
                assets.append(
                    {
                        "asset_path": f"gitlab://pipeline/{project.id}/{pipeline_id}",
                        "asset_type": "pipeline",
                        "title": str(pipeline_id),
                        "updated_at": getattr(pipeline, "updated_at", None),
                        "metadata": _repo_metadata(
                            "gitlab",
                            "pipeline",
                            full_name=project_path,
                            project_id=project_id,
                            branch=getattr(pipeline, "ref", None),
                        ),
                    }
                )
            for path in code_paths:
                assets.append(
                    {
                        "asset_path": f"gitlab://file/{project.id}/{path}",
                        "asset_type": "file",
                        "title": path,
                        "metadata": _repo_metadata(
                            "gitlab",
                            "file",
                            full_name=project_path,
                            project_id=project_id,
                            branch=connection_config.get("ref") or default_branch,
                            path=path,
                        ),
                    }
                )
        return assets

    def _fetch_asset_sync(self, connection_config: dict[str, Any], asset_ref: str) -> bytes:
        gl = self._client(connection_config)
        parsed = urlparse(asset_ref)
        parts = parsed.path.strip("/").split("/")
        if parsed.netloc == "project" and parts:
            project = gl.projects.get(parts[0])
            payload = {
                "id": project.id,
                "path_with_namespace": project.path_with_namespace,
                "description": project.description,
            }
        elif parsed.netloc == "issue" and len(parts) >= 2:
            issue = gl.projects.get(parts[0]).issues.get(parts[1])
            payload = {
                "title": issue.title,
                "description": issue.description,
                "iid": issue.iid,
                "state": issue.state,
                "labels": getattr(issue, "labels", []),
            }
        elif parsed.netloc == "merge_request" and len(parts) >= 2:
            mr = gl.projects.get(parts[0]).mergerequests.get(parts[1])
            payload = {
                "title": mr.title,
                "description": mr.description,
                "iid": mr.iid,
                "state": mr.state,
                "source_branch": getattr(mr, "source_branch", None),
            }
        elif parsed.netloc == "pipeline" and len(parts) >= 2:
            pipeline = gl.projects.get(parts[0]).pipelines.get(parts[1])
            payload = {
                "id": pipeline.id,
                "status": getattr(pipeline, "status", None),
                "ref": getattr(pipeline, "ref", None),
            }
        elif parsed.netloc == "file" and len(parts) >= 2:
            project = gl.projects.get(parts[0])
            path = "/".join(parts[1:])
            raw = project.files.raw(file_path=path, ref=connection_config.get("ref") or "main")
            return raw if isinstance(raw, bytes) else str(raw).encode()
        else:
            raise ValueError(f"unsupported GitLab asset_ref: {asset_ref}")
        return json.dumps(payload, default=str).encode()


class DigitalOceanSpacesAdapter(S3ConnectorAdapter):
    """DigitalOcean Spaces adapter using the S3-compatible object API."""

    def build_permission_request(
        self,
        *,
        source_id: str,
        identity_id: int | None,
        operation: str,
        metadata: dict[str, Any] | None = None,
    ) -> PermissionRequest:
        request = super().build_permission_request(
            source_id=source_id,
            identity_id=identity_id,
            operation=operation,
            metadata=metadata,
        )
        request.metadata["connector_key"] = "digitalocean_spaces"
        request.metadata["provider"] = "digitalocean_spaces"
        return request


class OpenSearchAdapter(BaseConnectorAdapter):
    """OpenSearch/Elasticsearch discovery and query adapter."""

    def build_permission_request(
        self,
        *,
        source_id: str,
        identity_id: int | None,
        operation: str,
        metadata: dict[str, Any] | None = None,
    ) -> PermissionRequest:
        metadata = metadata or {}
        op = str(operation or metadata.get("operation") or "query").lower()
        asset_ref = str(metadata.get("asset_ref") or metadata.get("path") or "")
        parsed = _parse_search_asset_ref(self.definition.key, asset_ref)
        index = str(metadata.get("index") or parsed.get("index") or "*")
        if op in {"describe", "index", "indices", "list"}:
            action = "search.index.describe"
            resource_type = "search.index"
            resources = [index]
        elif op in {"document", "get", "read"}:
            action = "search.document.read"
            resource_type = "search.document"
            resources = [asset_ref or f"{self.definition.key}://{index}/*"]
        elif op in {"write", "index_document", "create", "update"}:
            action = "search.document.write"
            resource_type = "search.document"
            resources = [asset_ref or f"{self.definition.key}://{index}/*"]
        elif op in {"delete", "remove"}:
            action = "search.document.delete"
            resource_type = "search.document"
            resources = [asset_ref or f"{self.definition.key}://{index}/*"]
        else:
            action = "search.query"
            resource_type = "search.index"
            resources = [index]
        return PermissionRequest(
            protocol="search",
            source_id=source_id,
            identity_id=identity_id,
            action=action,
            resource_type=resource_type,
            resources=resources,
            operation=op,
            path=asset_ref or index,
            risk_level=(
                "low"
                if action in {"search.index.describe", "search.query", "search.document.read"}
                else "high"
            ),
            metadata={"connector_key": self.definition.key, **metadata, **parsed, "index": index},
        )

    async def probe(
        self,
        connection_config: dict[str, Any],
        *,
        timeout_seconds: float = 5.0,
    ) -> HealthStatus:
        start = time.monotonic()
        if not connection_config.get("base_url"):
            return _health(self.definition.key, False, 0, "connection_config.base_url is required")
        try:
            url = _join_url(
                str(connection_config["base_url"]),
                "/_cluster/health",
                connection_config,
                self.definition,
            )
            async with _connector_http_client(connection_config, timeout=timeout_seconds) as client:
                resp = await client.get(
                    url,
                    headers=_search_headers(connection_config),
                    auth=_basic_auth(connection_config),
                )
            return _health_from_response(self.definition.key, resp.status_code, _elapsed_ms(start))
        except Exception as exc:
            return _health(self.definition.key, False, _elapsed_ms(start), str(exc))

    async def introspect(self, connection_config: dict[str, Any]) -> dict[str, Any]:
        self._validate_config(connection_config)
        indices = await self._indices(connection_config)
        return {
            "connector": self.definition.key,
            "indices": indices,
            "role_constraint_keys": ["indices", "allowed_fields"],
            "objects": [
                {"object_type": "index", "asset": f"{self.definition.key}://{{index}}"},
                {"object_type": "document", "asset": f"{self.definition.key}://{{index}}/{{id}}"},
            ],
        }

    async def execute_read(self, request: dict[str, Any]) -> Any:
        self._validate_config(request["connection_config"])
        op = str(request.get("operation") or "query").lower()
        if op in {"describe", "indices", "list"}:
            return await self.introspect(request["connection_config"])
        asset_ref = str(request.get("asset_ref") or request.get("path") or "")
        if op in {"document", "get", "read"} and asset_ref:
            return json.loads(
                (await self.fetch_asset(request["connection_config"], asset_ref)).decode()
            )
        index = str(request.get("index") or request.get("metadata", {}).get("index") or "_all")
        body = request.get("body") or request.get("query") or {"query": {"match_all": {}}}
        url = _join_url(
            str(request["connection_config"]["base_url"]),
            f"/{quote(index, safe=',*')}/_search",
            request["connection_config"],
            self.definition,
        )
        async with _connector_http_client(
            request["connection_config"],
            timeout=float(request["connection_config"].get("timeout_seconds") or 10),
        ) as client:
            resp = await client.post(
                url,
                headers=_search_headers(request["connection_config"]),
                auth=_basic_auth(request["connection_config"]),
                json=(
                    body
                    if isinstance(body, dict)
                    else {"query": {"query_string": {"query": str(body)}}}
                ),
            )
            resp.raise_for_status()
            return resp.json()

    async def execute_write(self, request: dict[str, Any]) -> Any:
        raise NotImplementedError(
            f"{self.definition.name} writes are approval-gated and disabled by default"
        )

    async def list_assets(self, connection_config: dict[str, Any]) -> list[dict[str, Any]]:
        self._validate_config(connection_config)
        assets: list[dict[str, Any]] = []
        indices = await self._indices(connection_config)
        max_docs = _int_config(connection_config, "max_docs_per_index", 10, upper=100)
        for index in indices:
            index_name = str(index.get("index") or index.get("name") or "")
            if not index_name:
                continue
            assets.append(
                {
                    "asset_path": f"{self.definition.key}://{index_name}",
                    "asset_type": "index",
                    "title": index_name,
                    "metadata": {
                        "connector_key": self.definition.key,
                        "object_type": "index",
                        "index": index_name,
                        **index,
                    },
                }
            )
            for hit in await self._sample_hits(connection_config, index_name, max_docs):
                doc_id = str(hit.get("_id") or "")
                if not doc_id:
                    continue
                source = hit.get("_source") or {}
                title = source.get("title") if isinstance(source, dict) else None
                assets.append(
                    {
                        "asset_path": f"{self.definition.key}://{index_name}/{quote(doc_id, safe='')}",
                        "asset_type": "document",
                        "title": title or doc_id,
                        "updated_at": (
                            source.get("updated_at") if isinstance(source, dict) else None
                        ),
                        "metadata": {
                            "connector_key": self.definition.key,
                            "object_type": "document",
                            "index": index_name,
                            "document_id": doc_id,
                            "fields": sorted(source.keys()) if isinstance(source, dict) else [],
                        },
                    }
                )
        return assets

    async def fetch_asset(self, connection_config: dict[str, Any], asset_ref: str) -> bytes:
        self._validate_config(connection_config)
        parsed = _parse_search_asset_ref(self.definition.key, asset_ref)
        index = parsed.get("index")
        document_id = parsed.get("document_id")
        if not index:
            raise ValueError(f"unsupported {self.definition.key} asset_ref: {asset_ref}")
        if not document_id:
            for item in await self._indices(connection_config):
                if str(item.get("index") or item.get("name") or "") == index:
                    return json.dumps(item, default=str).encode()
            raise FileNotFoundError(f"{self.definition.key} index not found: {index}")
        url = _join_url(
            str(connection_config["base_url"]),
            f"/{quote(index, safe='')}/_doc/{quote(str(document_id), safe='')}",
            connection_config,
            self.definition,
        )
        async with _connector_http_client(
            connection_config, timeout=float(connection_config.get("timeout_seconds") or 10)
        ) as client:
            resp = await client.get(
                url,
                headers=_search_headers(connection_config),
                auth=_basic_auth(connection_config),
            )
            resp.raise_for_status()
            return json.dumps(resp.json(), default=str).encode()

    async def sync_incremental(
        self,
        connection_config: dict[str, Any],
        state: dict[str, Any],
    ) -> dict[str, Any]:
        return {
            "state": {"synced_at": datetime.now(UTC).isoformat(), **state},
            "assets": await self.list_assets(connection_config),
        }

    async def _indices(self, connection_config: dict[str, Any]) -> list[dict[str, Any]]:
        self._validate_config(connection_config)
        configured = _list_config(connection_config.get("indices"))
        if configured:
            return [{"index": index} for index in configured]
        url = _join_url(
            str(connection_config["base_url"]),
            "/_cat/indices",
            connection_config,
            self.definition,
        )
        async with _connector_http_client(
            connection_config, timeout=float(connection_config.get("timeout_seconds") or 10)
        ) as client:
            resp = await client.get(
                url,
                params={"format": "json"},
                headers=_search_headers(connection_config),
                auth=_basic_auth(connection_config),
            )
            resp.raise_for_status()
            payload = resp.json()
            return payload if isinstance(payload, list) else []

    async def _sample_hits(
        self,
        connection_config: dict[str, Any],
        index: str,
        size: int,
    ) -> list[dict[str, Any]]:
        if size <= 0:
            return []
        try:
            url = _join_url(
                str(connection_config["base_url"]),
                f"/{quote(index, safe='')}/_search",
                connection_config,
                self.definition,
            )
            async with _connector_http_client(
                connection_config, timeout=float(connection_config.get("timeout_seconds") or 10)
            ) as client:
                resp = await client.post(
                    url,
                    headers=_search_headers(connection_config),
                    auth=_basic_auth(connection_config),
                    json={"size": size, "query": {"match_all": {}}},
                )
                resp.raise_for_status()
                return list((resp.json().get("hits") or {}).get("hits") or [])
        except Exception:
            logger.debug("%s sample document listing failed", self.definition.key, exc_info=True)
            return []


class QdrantSourceAdapter(BaseConnectorAdapter):
    """Qdrant as a governed source connector, separate from semantic cache use."""

    def build_permission_request(
        self,
        *,
        source_id: str,
        identity_id: int | None,
        operation: str,
        metadata: dict[str, Any] | None = None,
    ) -> PermissionRequest:
        metadata = metadata or {}
        op = str(operation or metadata.get("operation") or "query").lower()
        asset_ref = str(metadata.get("asset_ref") or metadata.get("path") or "")
        parsed = _parse_qdrant_asset_ref(asset_ref)
        collection = str(metadata.get("collection") or parsed.get("collection") or "*")
        if op in {"describe", "collection", "collections", "list"}:
            action = "search.index.describe"
            resource_type = "search.collection"
            resources = [collection]
        elif op in {"point", "document", "get", "read"}:
            action = "search.document.read"
            resource_type = "search.document"
            resources = [asset_ref or f"qdrant://{collection}/point/*"]
        elif op in {"write", "upsert"}:
            action = "search.document.write"
            resource_type = "search.document"
            resources = [asset_ref or f"qdrant://{collection}/point/*"]
        elif op in {"delete", "remove"}:
            action = "search.document.delete"
            resource_type = "search.document"
            resources = [asset_ref or f"qdrant://{collection}/point/*"]
        else:
            action = "search.query"
            resource_type = "search.collection"
            resources = [collection]
        return PermissionRequest(
            protocol="search",
            source_id=source_id,
            identity_id=identity_id,
            action=action,
            resources=resources,
            operation=op,
            path=asset_ref or collection,
            # Set on the request itself: the evaluator never reads it from
            # metadata, so without this a collection-scoped template statement
            # was compared against `search.index` and never matched.
            resource_type=resource_type,
            risk_level=(
                "low"
                if action in {"search.index.describe", "search.query", "search.document.read"}
                else "high"
            ),
            metadata={
                "connector_key": "qdrant",
                "resource_type": resource_type,
                **metadata,
                **parsed,
                "collection": collection,
            },
        )

    async def probe(
        self,
        connection_config: dict[str, Any],
        *,
        timeout_seconds: float = 5.0,
    ) -> HealthStatus:
        start = time.monotonic()
        if not connection_config.get("base_url"):
            return _health(self.definition.key, False, 0, "connection_config.base_url is required")
        try:
            url = _join_url(
                str(connection_config["base_url"]),
                "/collections",
                connection_config,
                self.definition,
            )
            async with _connector_http_client(connection_config, timeout=timeout_seconds) as client:
                resp = await client.get(
                    url,
                    headers=_qdrant_headers(connection_config),
                )
            return _health_from_response(self.definition.key, resp.status_code, _elapsed_ms(start))
        except Exception as exc:
            return _health(self.definition.key, False, _elapsed_ms(start), str(exc))

    async def introspect(self, connection_config: dict[str, Any]) -> dict[str, Any]:
        self._validate_config(connection_config)
        collections = await self._collections(connection_config)
        details = []
        urls = {
            collection: _join_url(
                str(connection_config["base_url"]),
                f"/collections/{quote(collection, safe='')}",
                connection_config,
                self.definition,
            )
            for collection in collections
        }
        async with _connector_http_client(
            connection_config, timeout=float(connection_config.get("timeout_seconds") or 10)
        ) as client:
            for collection in collections:
                try:
                    resp = await client.get(
                        urls[collection],
                        headers=_qdrant_headers(connection_config),
                    )
                    resp.raise_for_status()
                    details.append({"collection": collection, **(resp.json().get("result") or {})})
                except Exception:
                    details.append({"collection": collection})
        return {
            "connector": self.definition.key,
            "collections": details,
            "role_constraint_keys": ["collections", "allowed_fields"],
            "objects": [
                {"object_type": "collection", "asset": "qdrant://{collection}"},
                {"object_type": "point", "asset": "qdrant://{collection}/point/{id}"},
            ],
        }

    async def execute_read(self, request: dict[str, Any]) -> Any:
        self._validate_config(request["connection_config"])
        op = str(request.get("operation") or "query").lower()
        if op in {"describe", "collections", "list"}:
            return await self.introspect(request["connection_config"])
        asset_ref = str(request.get("asset_ref") or request.get("path") or "")
        if op in {"point", "document", "get", "read"} and asset_ref:
            return json.loads(
                (await self.fetch_asset(request["connection_config"], asset_ref)).decode()
            )
        collection = str(
            request.get("collection") or request.get("metadata", {}).get("collection") or ""
        )
        if not collection:
            raise ValueError("request.collection is required for Qdrant query")
        payload: dict[str, Any] = {
            "limit": _int_config(request, "limit", 10, upper=100),
            "with_payload": True,
        }
        if request.get("vector") is not None:
            payload["vector"] = request["vector"]
            endpoint = f"/collections/{quote(collection, safe='')}/points/search"
        else:
            endpoint = f"/collections/{quote(collection, safe='')}/points/scroll"
        url = _join_url(
            str(request["connection_config"]["base_url"]),
            endpoint,
            request["connection_config"],
            self.definition,
        )
        async with _connector_http_client(
            request["connection_config"],
            timeout=float(request["connection_config"].get("timeout_seconds") or 10),
        ) as client:
            resp = await client.post(
                url,
                headers=_qdrant_headers(request["connection_config"]),
                json=payload,
            )
            resp.raise_for_status()
            return resp.json()

    async def execute_write(self, request: dict[str, Any]) -> Any:
        raise NotImplementedError("Qdrant source writes are approval-gated and disabled by default")

    async def list_assets(self, connection_config: dict[str, Any]) -> list[dict[str, Any]]:
        self._validate_config(connection_config)
        assets: list[dict[str, Any]] = []
        max_points = _int_config(connection_config, "max_points_per_collection", 25, upper=200)
        for collection in await self._collections(connection_config):
            assets.append(
                {
                    "asset_path": f"qdrant://{collection}",
                    "asset_type": "collection",
                    "title": collection,
                    "metadata": {
                        "connector_key": "qdrant",
                        "object_type": "collection",
                        "collection": collection,
                    },
                }
            )
            for point in await self._scroll_points(connection_config, collection, max_points):
                point_id = str(point.get("id") or "")
                payload = point.get("payload") or {}
                title = payload.get("title") if isinstance(payload, dict) else None
                assets.append(
                    {
                        "asset_path": f"qdrant://{collection}/point/{quote(point_id, safe='')}",
                        "asset_type": "point",
                        "title": title or point_id,
                        "metadata": {
                            "connector_key": "qdrant",
                            "object_type": "point",
                            "collection": collection,
                            "point_id": point_id,
                            "fields": sorted(payload.keys()) if isinstance(payload, dict) else [],
                        },
                    }
                )
        return assets

    async def fetch_asset(self, connection_config: dict[str, Any], asset_ref: str) -> bytes:
        self._validate_config(connection_config)
        parsed = _parse_qdrant_asset_ref(asset_ref)
        collection = parsed.get("collection")
        point_id = parsed.get("point_id")
        if not collection:
            raise ValueError(f"unsupported Qdrant asset_ref: {asset_ref}")
        if not point_id:
            return json.dumps({"collection": collection}, default=str).encode()
        url = _join_url(
            str(connection_config["base_url"]),
            f"/collections/{quote(str(collection), safe='')}/points",
            connection_config,
            self.definition,
        )
        async with _connector_http_client(
            connection_config, timeout=float(connection_config.get("timeout_seconds") or 10)
        ) as client:
            qdrant_id: str | int = int(point_id) if str(point_id).isdigit() else str(point_id)
            resp = await client.post(
                url,
                headers=_qdrant_headers(connection_config),
                json={"ids": [qdrant_id], "with_payload": True, "with_vector": False},
            )
            resp.raise_for_status()
            return json.dumps(resp.json(), default=str).encode()

    async def sync_incremental(
        self,
        connection_config: dict[str, Any],
        state: dict[str, Any],
    ) -> dict[str, Any]:
        return {
            "state": {"synced_at": datetime.now(UTC).isoformat(), **state},
            "assets": await self.list_assets(connection_config),
        }

    async def _collections(self, connection_config: dict[str, Any]) -> list[str]:
        self._validate_config(connection_config)
        configured = _list_config(connection_config.get("collections"))
        if configured:
            return configured
        url = _join_url(
            str(connection_config["base_url"]),
            "/collections",
            connection_config,
            self.definition,
        )
        async with _connector_http_client(
            connection_config, timeout=float(connection_config.get("timeout_seconds") or 10)
        ) as client:
            resp = await client.get(
                url,
                headers=_qdrant_headers(connection_config),
            )
            resp.raise_for_status()
            collections = (resp.json().get("result") or {}).get("collections") or []
            return [str(item.get("name")) for item in collections if item.get("name")]

    async def _scroll_points(
        self,
        connection_config: dict[str, Any],
        collection: str,
        limit: int,
    ) -> list[dict[str, Any]]:
        try:
            url = _join_url(
                str(connection_config["base_url"]),
                f"/collections/{quote(collection, safe='')}/points/scroll",
                connection_config,
                self.definition,
            )
            async with _connector_http_client(
                connection_config, timeout=float(connection_config.get("timeout_seconds") or 10)
            ) as client:
                resp = await client.post(
                    url,
                    headers=_qdrant_headers(connection_config),
                    json={"limit": limit, "with_payload": True, "with_vector": False},
                )
                resp.raise_for_status()
                return list((resp.json().get("result") or {}).get("points") or [])
        except Exception:
            logger.debug("Qdrant point scroll failed", exc_info=True)
            return []


class SalesforceAdapter(BaseConnectorAdapter):
    """Read/discovery-first Salesforce adapter using simple-salesforce."""

    def build_permission_request(
        self,
        *,
        source_id: str,
        identity_id: int | None,
        operation: str,
        metadata: dict[str, Any] | None = None,
    ) -> PermissionRequest:
        return _saas_permission_request(
            provider="salesforce",
            source_id=source_id,
            identity_id=identity_id,
            operation=operation,
            metadata=metadata,
            default_object_type="Account",
        )

    async def probe(
        self,
        connection_config: dict[str, Any],
        *,
        timeout_seconds: float = 5.0,
    ) -> HealthStatus:
        start = time.monotonic()
        try:
            if connection_config.get("base_url") and not connection_config.get("username"):
                url = _join_url(
                    _salesforce_base_url(connection_config),
                    "/services/data",
                    connection_config,
                    self.definition,
                )
                async with _connector_http_client(
                    connection_config, timeout=timeout_seconds
                ) as client:
                    resp = await client.get(
                        url,
                        headers=_salesforce_headers(connection_config),
                    )
                return _health_from_response(
                    self.definition.key, resp.status_code, _elapsed_ms(start)
                )
            await asyncio.wait_for(
                asyncio.to_thread(self._client, connection_config), timeout=timeout_seconds
            )
            return _health(self.definition.key, True, _elapsed_ms(start), None)
        except Exception as exc:
            return _health(self.definition.key, False, _elapsed_ms(start), str(exc))

    async def introspect(self, connection_config: dict[str, Any]) -> dict[str, Any]:
        self._validate_config(connection_config)
        if connection_config.get("base_url") and not connection_config.get("username"):
            return await self._introspect_rest(connection_config)
        return await asyncio.to_thread(self._introspect_sync, connection_config)

    async def execute_read(self, request: dict[str, Any]) -> Any:
        self._validate_config(request["connection_config"])
        if str(request.get("operation") or "list_assets").lower() in {"describe", "metadata"}:
            return await self.introspect(request["connection_config"])
        asset_ref = str(request.get("asset_ref") or request.get("path") or "")
        if asset_ref:
            return json.loads(
                (await self.fetch_asset(request["connection_config"], asset_ref)).decode()
            )
        query = request.get("query") or request.get("soql")
        if query:
            if request["connection_config"].get("base_url") and not request[
                "connection_config"
            ].get("username"):
                return await self._query_rest(request["connection_config"], str(query))
            return await asyncio.to_thread(
                self._client(request["connection_config"]).query_all, str(query)
            )
        return {"assets": await self.list_assets(request["connection_config"])}

    async def execute_write(self, request: dict[str, Any]) -> Any:
        raise NotImplementedError("Salesforce writes are approval-gated and disabled by default")

    async def list_assets(self, connection_config: dict[str, Any]) -> list[dict[str, Any]]:
        self._validate_config(connection_config)
        if connection_config.get("base_url") and not connection_config.get("username"):
            return await self._list_assets_rest(connection_config)
        return await asyncio.to_thread(self._list_assets_sync, connection_config)

    async def fetch_asset(self, connection_config: dict[str, Any], asset_ref: str) -> bytes:
        self._validate_config(connection_config)
        if connection_config.get("base_url") and not connection_config.get("username"):
            return await self._fetch_asset_rest(connection_config, asset_ref)
        return await asyncio.to_thread(self._fetch_asset_sync, connection_config, asset_ref)

    async def sync_incremental(
        self,
        connection_config: dict[str, Any],
        state: dict[str, Any],
    ) -> dict[str, Any]:
        return {
            "state": {"synced_at": datetime.now(UTC).isoformat(), **state},
            "assets": await self.list_assets(connection_config),
        }

    def _client(self, connection_config: dict[str, Any]) -> Any:
        self._validate_config(connection_config)
        try:
            from simple_salesforce import Salesforce  # type: ignore[import-not-found]
        except ImportError as exc:
            raise RuntimeError("simple-salesforce is not installed") from exc
        kwargs: dict[str, Any] = {}
        if connection_config.get("instance_url") and connection_config.get("session_id"):
            kwargs.update(
                {
                    "instance_url": str(connection_config["instance_url"]),
                    "session_id": _secret_value(connection_config, "session_id", "session_id_ref"),
                }
            )
        else:
            kwargs.update(
                {
                    "username": connection_config.get("username") or connection_config.get("user"),
                    "password": _secret_value(connection_config, "password", "password_ref"),
                    "security_token": _secret_value(
                        connection_config, "security_token", "security_token_ref"
                    ),
                    "domain": connection_config.get("domain") or "login",
                }
            )
            if connection_config.get("instance_url"):
                kwargs["instance_url"] = connection_config.get("instance_url")
            if connection_config.get("client_id"):
                kwargs["client_id"] = connection_config.get("client_id")
        return Salesforce(**{key: value for key, value in kwargs.items() if value})

    def _configured_objects(self, connection_config: dict[str, Any]) -> list[str]:
        return _list_config(connection_config.get("objects")) or [
            "Account",
            "Contact",
            "Opportunity",
            "Case",
            "Knowledge__kav",
        ]

    async def _introspect_rest(self, connection_config: dict[str, Any]) -> dict[str, Any]:
        objects: list[dict[str, Any]] = []
        urls = {
            object_name: _join_url(
                _salesforce_base_url(connection_config),
                f"/services/data/{_salesforce_api_version(connection_config)}/sobjects/{quote(object_name, safe='')}/describe",
                connection_config,
                self.definition,
            )
            for object_name in self._configured_objects(connection_config)
        }
        async with _connector_http_client(
            connection_config, timeout=float(connection_config.get("timeout_seconds") or 10)
        ) as client:
            for object_name in urls:
                try:
                    resp = await client.get(
                        urls[object_name],
                        headers=_salesforce_headers(connection_config),
                    )
                    resp.raise_for_status()
                    describe = resp.json()
                except Exception:
                    describe = {"name": object_name, "fields": []}
                objects.append(
                    {
                        "object_type": object_name,
                        "name": describe.get("name") or object_name,
                        "fields": [
                            {"name": field.get("name"), "type": field.get("type")}
                            for field in describe.get("fields", [])
                            if field.get("name")
                        ],
                        "asset": f"salesforce://{object_name}/{{id}}",
                    }
                )
        return {
            "connector": self.definition.key,
            "objects": objects,
            "role_constraint_keys": ["object_types", "allowed_fields"],
        }

    async def _query_rest(self, connection_config: dict[str, Any], query: str) -> dict[str, Any]:
        url = _join_url(
            _salesforce_base_url(connection_config),
            f"/services/data/{_salesforce_api_version(connection_config)}/query",
            connection_config,
            self.definition,
        )
        async with _connector_http_client(
            connection_config, timeout=float(connection_config.get("timeout_seconds") or 10)
        ) as client:
            resp = await client.get(
                url,
                params={"q": query},
                headers=_salesforce_headers(connection_config),
            )
            resp.raise_for_status()
            return resp.json()

    async def _list_assets_rest(self, connection_config: dict[str, Any]) -> list[dict[str, Any]]:
        limit = _int_config(connection_config, "max_records_per_object", 25, upper=200)
        assets: list[dict[str, Any]] = []
        for object_name in self._configured_objects(connection_config):
            fields = _salesforce_fields_for(object_name)
            try:
                payload = await self._query_rest(
                    connection_config,
                    f"SELECT {', '.join(fields)} FROM {object_name} LIMIT {limit}",
                )
            except Exception:
                continue
            for record in payload.get("records", []):
                record_id = record.get("Id")
                if not record_id:
                    continue
                assets.append(
                    {
                        "asset_path": f"salesforce://{object_name}/{record_id}",
                        "asset_type": object_name,
                        "title": record.get("Name") or record.get("Subject") or str(record_id),
                        "updated_at": record.get("LastModifiedDate")
                        or record.get("SystemModstamp"),
                        "metadata": {
                            "connector_key": "salesforce",
                            "object_type": object_name,
                            "object_id": record_id,
                            "fields": sorted(key for key in record if key != "attributes"),
                        },
                    }
                )
        return assets

    async def _fetch_asset_rest(self, connection_config: dict[str, Any], asset_ref: str) -> bytes:
        parsed = _parse_saas_asset_ref("salesforce", asset_ref)
        object_type = parsed.get("object_type")
        object_id = parsed.get("object_id")
        if not object_type or not object_id:
            raise ValueError(f"unsupported Salesforce asset_ref: {asset_ref}")
        url = _join_url(
            _salesforce_base_url(connection_config),
            f"/services/data/{_salesforce_api_version(connection_config)}/sobjects/{quote(str(object_type), safe='')}/{quote(str(object_id), safe='')}",
            connection_config,
            self.definition,
        )
        async with _connector_http_client(
            connection_config, timeout=float(connection_config.get("timeout_seconds") or 10)
        ) as client:
            resp = await client.get(
                url,
                headers=_salesforce_headers(connection_config),
            )
            resp.raise_for_status()
            return json.dumps(resp.json(), default=str).encode()

    def _introspect_sync(self, connection_config: dict[str, Any]) -> dict[str, Any]:
        sf = self._client(connection_config)
        objects: list[dict[str, Any]] = []
        for object_name in self._configured_objects(connection_config):
            try:
                describe = getattr(sf, object_name).describe()
            except Exception:
                describe = {"name": object_name, "fields": []}
            objects.append(
                {
                    "object_type": object_name,
                    "name": describe.get("name") or object_name,
                    "fields": [
                        {"name": field.get("name"), "type": field.get("type")}
                        for field in describe.get("fields", [])
                        if field.get("name")
                    ],
                    "asset": f"salesforce://{object_name}/{{id}}",
                }
            )
        return {
            "connector": self.definition.key,
            "objects": objects,
            "role_constraint_keys": ["object_types", "allowed_fields"],
        }

    def _list_assets_sync(self, connection_config: dict[str, Any]) -> list[dict[str, Any]]:
        sf = self._client(connection_config)
        limit = _int_config(connection_config, "max_records_per_object", 25, upper=200)
        assets: list[dict[str, Any]] = []
        for object_name in self._configured_objects(connection_config):
            fields = _salesforce_fields_for(object_name)
            try:
                payload = sf.query_all(
                    f"SELECT {', '.join(fields)} FROM {object_name} LIMIT {limit}"
                )
            except Exception:
                continue
            for record in payload.get("records", []):
                record_id = record.get("Id")
                if not record_id:
                    continue
                assets.append(
                    {
                        "asset_path": f"salesforce://{object_name}/{record_id}",
                        "asset_type": object_name,
                        "title": record.get("Name") or record.get("Subject") or str(record_id),
                        "updated_at": record.get("LastModifiedDate")
                        or record.get("SystemModstamp"),
                        "metadata": {
                            "connector_key": "salesforce",
                            "object_type": object_name,
                            "object_id": record_id,
                            "fields": sorted(key for key in record if key != "attributes"),
                        },
                    }
                )
        return assets

    def _fetch_asset_sync(self, connection_config: dict[str, Any], asset_ref: str) -> bytes:
        parsed = _parse_saas_asset_ref("salesforce", asset_ref)
        object_type = parsed.get("object_type")
        object_id = parsed.get("object_id")
        if not object_type or not object_id:
            raise ValueError(f"unsupported Salesforce asset_ref: {asset_ref}")
        payload = getattr(self._client(connection_config), str(object_type)).get(str(object_id))
        return json.dumps(payload, default=str).encode()


class NotionAdapter(BaseConnectorAdapter):
    """Read/discovery-first Notion adapter using the official REST API."""

    def build_permission_request(
        self,
        *,
        source_id: str,
        identity_id: int | None,
        operation: str,
        metadata: dict[str, Any] | None = None,
    ) -> PermissionRequest:
        return _saas_permission_request(
            provider="notion",
            source_id=source_id,
            identity_id=identity_id,
            operation=operation,
            metadata=metadata,
            default_object_type="page",
        )

    async def probe(
        self,
        connection_config: dict[str, Any],
        *,
        timeout_seconds: float = 5.0,
    ) -> HealthStatus:
        start = time.monotonic()
        try:
            url = _join_url(
                _notion_base_url(connection_config),
                "/v1/users/me",
                connection_config,
                self.definition,
            )
            async with _connector_http_client(connection_config, timeout=timeout_seconds) as client:
                resp = await client.get(
                    url,
                    headers=_notion_headers(connection_config),
                )
            return _health_from_response(self.definition.key, resp.status_code, _elapsed_ms(start))
        except Exception as exc:
            return _health(self.definition.key, False, _elapsed_ms(start), str(exc))

    async def introspect(self, connection_config: dict[str, Any]) -> dict[str, Any]:
        self._validate_config(connection_config)
        return {
            "connector": self.definition.key,
            "objects": [
                {"object_type": "page", "asset": "notion://page/{id}"},
                {"object_type": "database", "asset": "notion://database/{id}"},
                {"object_type": "block", "asset": "notion://block/{id}"},
            ],
            "role_constraint_keys": [
                "page_ids",
                "database_ids",
                "property_names",
                "workspace_ids",
            ],
        }

    async def execute_read(self, request: dict[str, Any]) -> Any:
        self._validate_config(request["connection_config"])
        if str(request.get("operation") or "search").lower() in {"describe", "metadata"}:
            return await self.introspect(request["connection_config"])
        asset_ref = str(request.get("asset_ref") or request.get("path") or "")
        if asset_ref:
            return json.loads(
                (await self.fetch_asset(request["connection_config"], asset_ref)).decode()
            )
        return {"assets": await self.list_assets(request["connection_config"])}

    async def execute_write(self, request: dict[str, Any]) -> Any:
        raise NotImplementedError("Notion writes are approval-gated and disabled by default")

    async def list_assets(self, connection_config: dict[str, Any]) -> list[dict[str, Any]]:
        self._validate_config(connection_config)
        payload = await self._post_json(
            connection_config,
            "/v1/search",
            {
                "page_size": _int_config(connection_config, "max_results", 25, upper=100),
                "filter": {"property": "object", "value": "page"},
            },
        )
        assets: list[dict[str, Any]] = []
        for item in payload.get("results") or []:
            object_type = str(item.get("object") or "page")
            item_id = str(item.get("id") or "")
            if not item_id:
                continue
            assets.append(
                {
                    "asset_path": f"notion://{object_type}/{item_id}",
                    "asset_type": object_type,
                    "title": _notion_title(item),
                    "updated_at": item.get("last_edited_time"),
                    "metadata": {
                        "connector_key": "notion",
                        "object_type": object_type,
                        "object_id": item_id,
                        "page_id": item_id if object_type == "page" else None,
                        "database_id": item_id if object_type == "database" else None,
                        "workspace": connection_config.get("workspace"),
                    },
                }
            )
        return assets

    async def fetch_asset(self, connection_config: dict[str, Any], asset_ref: str) -> bytes:
        self._validate_config(connection_config)
        parsed = _parse_saas_asset_ref("notion", asset_ref)
        object_type = str(parsed.get("object_type") or "")
        object_id = str(parsed.get("object_id") or "")
        if not object_type or not object_id:
            raise ValueError(f"unsupported Notion asset_ref: {asset_ref}")
        if object_type == "page":
            page = await self._get_json(connection_config, f"/v1/pages/{quote(object_id, safe='')}")
            blocks = await self._get_json(
                connection_config, f"/v1/blocks/{quote(object_id, safe='')}/children"
            )
            payload = {"page": page, "blocks": blocks.get("results") or []}
        elif object_type == "database":
            payload = await self._get_json(
                connection_config, f"/v1/databases/{quote(object_id, safe='')}"
            )
        elif object_type == "block":
            payload = await self._get_json(
                connection_config, f"/v1/blocks/{quote(object_id, safe='')}"
            )
        else:
            raise ValueError(f"unsupported Notion object type: {object_type}")
        return json.dumps(payload, default=str).encode()

    async def sync_incremental(
        self,
        connection_config: dict[str, Any],
        state: dict[str, Any],
    ) -> dict[str, Any]:
        return {
            "state": {"synced_at": datetime.now(UTC).isoformat(), **state},
            "assets": await self.list_assets(connection_config),
        }

    async def _get_json(self, connection_config: dict[str, Any], path: str) -> dict[str, Any]:
        url = _join_url(
            _notion_base_url(connection_config),
            path,
            connection_config,
            self.definition,
        )
        async with _connector_http_client(
            connection_config, timeout=float(connection_config.get("timeout_seconds") or 10)
        ) as client:
            resp = await client.get(
                url,
                headers=_notion_headers(connection_config),
            )
            resp.raise_for_status()
            return resp.json()

    async def _post_json(
        self,
        connection_config: dict[str, Any],
        path: str,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        url = _join_url(
            _notion_base_url(connection_config),
            path,
            connection_config,
            self.definition,
        )
        async with _connector_http_client(
            connection_config, timeout=float(connection_config.get("timeout_seconds") or 10)
        ) as client:
            resp = await client.post(
                url,
                headers=_notion_headers(connection_config),
                json=payload,
            )
            resp.raise_for_status()
            return resp.json()


class SDKPresenceAdapter(BaseConnectorAdapter):
    """Probe adapter for SaaS/search systems where credentials are not yet enough.

    These adapters intentionally do not perform broad live reads during source
    setup. They validate required config and whether the preferred OSS SDK is
    importable, then return a degraded-but-actionable probe message.
    """

    def __init__(
        self,
        definition: ConnectorDefinition,
        *,
        import_name: str | None = None,
        required_fields: tuple[str, ...] = (),
    ) -> None:
        super().__init__(definition)
        self._import_name = import_name
        self._required_fields = required_fields

    async def probe(
        self,
        connection_config: dict[str, Any],
        *,
        timeout_seconds: float = 5.0,
    ) -> HealthStatus:
        missing = [field for field in self._required_fields if not connection_config.get(field)]
        if missing:
            return _health(
                self.definition.key,
                False,
                0,
                f"connection_config.{', '.join(missing)} is required",
            )
        if not self._import_name:
            return _health(
                self.definition.key, True, 0, "configured; live probe uses HTTP mock/live adapter"
            )
        try:
            __import__(self._import_name)
        except ImportError:
            return _health(
                self.definition.key,
                False,
                0,
                f"{self.definition.oss_libraries[0]} is not installed",
            )
        return _health(self.definition.key, True, 0, None)


def sanitize_config(
    connection_config: dict[str, Any],
    definition: ConnectorDefinition | None = None,
) -> dict[str, Any]:
    secret_fields = set(definition.secret_fields if definition else ())
    return {
        str(key): _sanitize_config_value(str(key), value, secret_fields)
        for key, value in (connection_config or {}).items()
    }


def _sanitize_config_value(key: str, value: Any, secret_fields: set[str]) -> Any:
    key_text = str(key)
    if key_text.endswith("_ref"):
        return _defang_secret_ref(value)
    if key_text in secret_fields or _SECRET_KEY_RE.search(key_text):
        return "<configured>" if value not in (None, "") else ""
    if isinstance(value, dict):
        return {
            str(child_key): _sanitize_config_value(str(child_key), child_value, secret_fields)
            for child_key, child_value in value.items()
        }
    if isinstance(value, list):
        return [_sanitize_config_value(key_text, item, secret_fields) for item in value]
    if isinstance(value, tuple):
        return tuple(_sanitize_config_value(key_text, item, secret_fields) for item in value)
    if isinstance(value, str):
        return _redact_uri_userinfo(value)
    return value


def _defang_secret_ref(value: Any) -> str:
    if value in (None, ""):
        return ""
    return str(value).replace("://", ":")


def _redact_uri_userinfo(value: str) -> str:
    parsed = urlparse(value)
    if not parsed.scheme or "@" not in parsed.netloc:
        return value
    host = parsed.hostname or ""
    if parsed.port:
        host = f"{host}:{parsed.port}"
    return parsed._replace(netloc=f"<redacted>@{host}").geturl()


def _join_url(
    base_url: str,
    path: str,
    connection_config: dict[str, Any] | None = None,
    definition: ConnectorDefinition | None = None,
) -> str:
    if connection_config is not None and definition is not None:
        _validate_connector_config(definition, connection_config)
    return join_and_validate_http_egress_url(
        str(base_url),
        str(path),
        allow_private=_allow_private_egress(connection_config or {}),
    )


def _list_config(raw: Any) -> list[str]:
    if raw is None:
        return []
    if isinstance(raw, (list, tuple, set)):
        values = raw
    else:
        values = str(raw).replace("\n", ",").split(",")
    result: list[str] = []
    seen: set[str] = set()
    for value in values:
        item = str(value).strip()
        if not item or item in seen:
            continue
        seen.add(item)
        result.append(item)
    return result


def _int_config(
    config: dict[str, Any],
    key: str,
    default: int,
    *,
    upper: int | None = None,
) -> int:
    try:
        value = int(config.get(key) or default)
    except (TypeError, ValueError):
        value = default
    value = max(0, value)
    return min(value, upper) if upper is not None else value


def _basic_auth(config: dict[str, Any]) -> tuple[str, str] | None:
    username = config.get("username") or config.get("user")
    password = _secret_value(config, "password", "password_ref")
    if username and password:
        return (str(username), str(password))
    return None


def _search_headers(config: dict[str, Any]) -> dict[str, str]:
    headers = {"Accept": "application/json"}
    token = _secret_value(config, "token", "token_ref") or _secret_value(
        config, "api_key", "api_key_ref"
    )
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _qdrant_headers(config: dict[str, Any]) -> dict[str, str]:
    headers = {"Accept": "application/json"}
    api_key = _secret_value(config, "api_key", "api_key_ref")
    if api_key:
        headers["api-key"] = api_key
    return headers


def _notion_base_url(config: dict[str, Any]) -> str:
    return str(config.get("base_url") or "https://api.notion.com").rstrip("/")


def _notion_headers(config: dict[str, Any]) -> dict[str, str]:
    token = _secret_value(config, "token", "token_ref") or _secret_value(
        config, "integration_token", "integration_token_ref"
    )
    if not token:
        raise ValueError("connection_config.token or token_ref is required")
    return {
        "Authorization": f"Bearer {token}",
        "Notion-Version": str(config.get("notion_version") or "2022-06-28"),
        "Content-Type": "application/json",
    }


def _salesforce_base_url(config: dict[str, Any]) -> str:
    return str(config.get("base_url") or config.get("instance_url") or "").rstrip("/")


def _salesforce_api_version(config: dict[str, Any]) -> str:
    version = str(config.get("api_version") or "v60.0").strip()
    return version if version.startswith("v") else f"v{version}"


def _salesforce_headers(config: dict[str, Any]) -> dict[str, str]:
    headers = {"Accept": "application/json"}
    token = _secret_value(config, "token", "token_ref") or _secret_value(
        config, "session_id", "session_id_ref"
    )
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def connector_key_for(source_type: str, metadata: dict[str, Any] | None = None) -> str:
    metadata = metadata or {}
    key = metadata.get("connector_key") or metadata.get("provider")
    if key:
        return str(key).lower()
    kind = (source_type or "").lower()
    aliases = {
        "postgresql": "postgresql",
        "mysql": "mysql",
        "mariadb": "mariadb",
        "http": "generic_rest",
        "s3": "s3",
        "warehouse": "snowflake",
        "search": "opensearch",
    }
    return aliases.get(kind, kind or "generic_rest")


def get_connector(
    key_or_source_type: str, metadata: dict[str, Any] | None = None
) -> ConnectorDefinition:
    key = connector_key_for(key_or_source_type, metadata)
    return CONNECTOR_DEFINITIONS.get(key, CONNECTOR_DEFINITIONS["generic_rest"])


def get_adapter(
    key_or_source_type: str,
    metadata: dict[str, Any] | None = None,
    *,
    fabric_services: FabricServices | None = None,
    source_id: str | None = None,
) -> BaseConnectorAdapter:
    definition = get_connector(key_or_source_type, metadata)
    if definition.key == "fabric_sql":
        from interlock.connections.fabric.adapter import FabricSQLAdapter

        return FabricSQLAdapter(definition, fabric_services=fabric_services, source_id=source_id)
    factory = _ADAPTER_FACTORIES.get(definition.key, BaseConnectorAdapter)
    if isinstance(factory, tuple):
        cls, kwargs = factory
        return cls(definition, **kwargs)
    return factory(definition)


def tiered_connectors() -> dict[int, list[ConnectorDefinition]]:
    tiers: dict[int, list[ConnectorDefinition]] = {}
    for definition in CONNECTOR_DEFINITIONS.values():
        tiers.setdefault(definition.tier, []).append(definition)
    for values in tiers.values():
        values.sort(key=lambda item: item.name)
    return dict(sorted(tiers.items()))


def source_metadata_for_connector(connector_key: str) -> dict[str, Any]:
    definition = CONNECTOR_DEFINITIONS[connector_key]
    return {
        "connector_key": definition.key,
        "connector_family": definition.family,
        "connector_status": definition.status,
        "connector_capabilities": asdict(definition.capabilities),
        "source_roles_version": 2,
    }


def role_templates_for_connector(connector_key: str) -> dict[str, list[dict[str, Any]]]:
    return CONNECTOR_DEFINITIONS.get(
        connector_key, CONNECTOR_DEFINITIONS["generic_rest"]
    ).role_templates


def _health(source_id: str, healthy: bool, latency_ms: float, error: str | None) -> HealthStatus:
    return HealthStatus(
        source_id=source_id,
        healthy=healthy,
        latency_ms=latency_ms,
        error=error,
        checked_at=datetime.now(UTC),
    )


def _health_from_response(source_id: str, status_code: int, latency_ms: float) -> HealthStatus:
    healthy = 200 <= status_code < 400
    return _health(source_id, healthy, latency_ms, None if healthy else f"HTTP {status_code}")


def _elapsed_ms(start: float) -> float:
    return (time.monotonic() - start) * 1000


def _secret_value(config: dict[str, Any], literal_key: str, ref_key: str) -> str | None:
    try:
        if config.get(ref_key):
            return resolve(str(config[ref_key]))
        if config.get(literal_key):
            return resolve(str(config[literal_key]))
    except MissingSecretError as exc:
        raise RuntimeError(str(exc)) from exc
    return None


def _mysql_ssl_context(config: dict[str, Any]) -> ssl.SSLContext | bool | None:
    """Build an aiomysql SSL option from connector config.

    ``ssl=true`` enables TLS with normal certificate verification. Temporary
    test databases and private managed clusters can set ``ssl_verify=false``
    until their CA is provided through ``ssl_ca`` or ``ssl_ca_ref``.
    """
    ssl_setting = config.get("ssl")
    ssl_ca = _secret_value(config, "ssl_ca", "ssl_ca_ref")
    if not ssl_setting and not ssl_ca:
        return None
    if isinstance(ssl_setting, ssl.SSLContext):
        return ssl_setting
    if isinstance(ssl_setting, dict):
        ssl_ca = ssl_ca or _secret_value(ssl_setting, "ca", "ca_ref")
        verify = ssl_setting.get("verify", ssl_setting.get("ssl_verify", True))
    else:
        verify = config.get("ssl_verify", True)

    context = ssl.create_default_context(cafile=ssl_ca)
    if str(verify).lower() in {"0", "false", "no", "off"}:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    return context


def _auth_headers(config: dict[str, Any]) -> dict[str, str]:
    header = config.get("auth_header")
    token = _secret_value(config, "token", "token_ref")
    if header and token:
        return {str(header): str(token)}
    return {}


def _generic_action(family: str, operation: str) -> str:
    op = (operation or "read").lower()
    if family == "object_storage":
        return (
            "storage.object.read" if op in {"read", "list", "discovery"} else "storage.object.write"
        )
    if family == "saas":
        return "saas.object.read" if op in {"read", "search", "discovery"} else "saas.object.write"
    if family == "collaboration":
        if op in {"channel", "channels", "list"}:
            return "collab.channel.read"
        if op in {"file", "files"}:
            return "collab.file.read"
        return "collab.message.read"
    if family == "repo":
        if op in {"code", "file", "files"}:
            return "repo.code.read"
        if op in {"issue", "issues"}:
            return "repo.issue.read"
        if op in {"pr", "pull_request", "merge_request"}:
            return "repo.pr.read"
        if op in {"write", "execute", "comment", "label", "workflow"}:
            return "repo.action.execute"
        return "repo.read"
    if family == "search":
        return "search.query"
    if family in {"database", "warehouse"}:
        if op in {"read", "select", "query", "discovery", "describe", "list"}:
            return "db.table.select"
        if op in {"insert"}:
            return "db.table.insert"
        if op in {"update"}:
            return "db.table.update"
        if op in {"delete", "delete_rows"}:
            return "db.table.delete_rows"
        return "db.execute_raw"
    return "http.get" if op == "read" else "http.post"


def _repo_permission_request(
    *,
    provider: str,
    source_id: str,
    identity_id: int | None,
    operation: str,
    metadata: dict[str, Any] | None,
) -> PermissionRequest:
    metadata = metadata or {}
    asset_ref = str(metadata.get("asset_ref") or metadata.get("path") or "")
    parsed = _parse_repo_asset_ref(provider, asset_ref)
    op = str(operation or metadata.get("operation") or parsed.get("object_type") or "read").lower()
    action = _generic_action("repo", op)
    if action == "repo.action.execute":
        pass
    elif parsed.get("object_type") == "file":
        action = "repo.code.read"
    elif parsed.get("object_type") == "issue":
        action = "repo.issue.read"
    elif parsed.get("object_type") in {"pr", "merge_request"}:
        action = "repo.pr.read"
    elif parsed.get("object_type") in {"workflow", "pipeline"}:
        action = "repo.action.execute" if op in {"execute", "run", "trigger"} else "repo.read"
    elif parsed.get("object_type") in {"repo", "project", "release"}:
        action = "repo.read"
    resource = asset_ref or str(metadata.get("resource") or "*")
    merged_metadata = {
        "connector_key": provider,
        **metadata,
        **parsed,
    }
    return PermissionRequest(
        protocol="repo",
        source_id=source_id,
        identity_id=identity_id,
        action=action,
        resources=[resource],
        operation=op,
        path=None if resource == "*" else resource,
        metadata=merged_metadata,
    )


def _parse_repo_asset_ref(provider: str, asset_ref: str) -> dict[str, Any]:
    if not asset_ref:
        return {}
    parsed = urlparse(asset_ref)
    if parsed.scheme and parsed.scheme != provider:
        return {}
    parts = [part for part in parsed.path.strip("/").split("/") if part]
    object_type = parsed.netloc
    if provider == "github":
        if (
            object_type in {"repo", "issue", "pr", "release", "workflow", "file"}
            and len(parts) >= 2
        ):
            org, repo = parts[0], parts[1]
            metadata: dict[str, Any] = {
                "object_type": object_type,
                "org": org,
                "repo": repo,
                "full_name": f"{org}/{repo}",
            }
            if object_type in {"issue", "pr"} and len(parts) >= 3:
                metadata["number"] = parts[2]
            elif object_type == "file" and len(parts) >= 3:
                metadata["path"] = "/".join(parts[2:])
            elif object_type == "workflow" and len(parts) >= 3:
                metadata["workflow"] = "/".join(parts[2:])
            elif object_type == "release" and len(parts) >= 3:
                metadata["tag"] = "/".join(parts[2:])
            return metadata
    if provider == "gitlab":
        if object_type in {"project", "issue", "merge_request", "pipeline", "file"} and parts:
            metadata = {"object_type": object_type, "project_id": parts[0]}
            if object_type in {"issue", "merge_request", "pipeline"} and len(parts) >= 2:
                metadata["number"] = parts[1]
            elif object_type == "file" and len(parts) >= 2:
                metadata["path"] = "/".join(parts[1:])
            return metadata
    return {"object_type": object_type} if object_type else {}


def _parse_search_asset_ref(provider: str, asset_ref: str) -> dict[str, Any]:
    if not asset_ref:
        return {}
    parsed = urlparse(asset_ref)
    if parsed.scheme and parsed.scheme != provider:
        return {}
    parts = [part for part in parsed.path.strip("/").split("/") if part]
    index = unquote(parsed.netloc or "")
    metadata: dict[str, Any] = {"object_type": "index"} if index else {}
    if index:
        metadata["index"] = index
    if parts:
        metadata.update(
            {
                "object_type": "document",
                "document_id": unquote("/".join(parts)),
            }
        )
    return metadata


def _parse_qdrant_asset_ref(asset_ref: str) -> dict[str, Any]:
    if not asset_ref:
        return {}
    parsed = urlparse(asset_ref)
    if parsed.scheme and parsed.scheme != "qdrant":
        return {}
    collection = unquote(parsed.netloc or "")
    parts = [part for part in parsed.path.strip("/").split("/") if part]
    metadata: dict[str, Any] = {"object_type": "collection"} if collection else {}
    if collection:
        metadata["collection"] = collection
    if len(parts) >= 2 and parts[0] == "point":
        metadata.update(
            {
                "object_type": "point",
                "point_id": unquote("/".join(parts[1:])),
            }
        )
    return metadata


def _parse_saas_asset_ref(provider: str, asset_ref: str) -> dict[str, Any]:
    if not asset_ref:
        return {}
    parsed = urlparse(asset_ref)
    if parsed.scheme and parsed.scheme != provider:
        return {}
    object_type = parsed.netloc
    object_id = unquote(parsed.path.strip("/"))
    metadata: dict[str, Any] = {}
    if object_type:
        metadata["object_type"] = object_type
    if object_id:
        metadata["object_id"] = object_id
        if provider == "notion" and object_type == "page":
            metadata["page_id"] = object_id
        if provider == "notion" and object_type == "database":
            metadata["database_id"] = object_id
    return metadata


def _parse_workspace_asset_ref(asset_ref: str) -> dict[str, Any]:
    if not asset_ref:
        return {}
    parsed = urlparse(asset_ref)
    scheme = parsed.scheme
    parts = [unquote(part) for part in parsed.path.strip("/").split("/") if part]
    metadata: dict[str, Any] = {}
    if scheme == "gdrive":
        metadata["service"] = "drive"
        if parsed.netloc == "file" and parts:
            metadata.update(
                {"object_type": "drive_file", "object_id": parts[0], "file_id": parts[0]}
            )
        elif parsed.netloc == "folder" and parts:
            metadata.update(
                {"object_type": "drive_folder", "object_id": parts[0], "folder_id": parts[0]}
            )
        elif parsed.netloc == "drive" and len(parts) >= 3 and parts[1] == "file":
            metadata.update(
                {
                    "object_type": "drive_file",
                    "drive_id": parts[0],
                    "object_id": parts[2],
                    "file_id": parts[2],
                }
            )
    elif scheme == "gmail":
        metadata["service"] = "gmail"
        if parsed.netloc == "user" and len(parts) >= 3 and parts[1] == "message":
            metadata.update(
                {
                    "object_type": "gmail_message",
                    "user": parts[0],
                    "object_id": parts[2],
                    "message_id": parts[2],
                }
            )
    elif scheme == "gcal":
        metadata["service"] = "calendar"
        if parsed.netloc == "calendar" and len(parts) >= 3 and parts[1] == "event":
            metadata.update(
                {
                    "object_type": "calendar_event",
                    "calendar_id": parts[0],
                    "object_id": parts[2],
                    "event_id": parts[2],
                }
            )
    elif scheme == "gdocs" and parsed.netloc == "document" and parts:
        metadata.update(
            {
                "service": "docs",
                "object_type": "doc",
                "object_id": parts[0],
                "document_id": parts[0],
            }
        )
    elif scheme == "gsheets" and parsed.netloc == "spreadsheet" and parts:
        metadata.update(
            {
                "service": "sheets",
                "object_type": "sheet",
                "object_id": parts[0],
                "spreadsheet_id": parts[0],
            }
        )
    elif scheme == "gslides" and parsed.netloc == "presentation" and parts:
        metadata.update(
            {
                "service": "slides",
                "object_type": "slide",
                "object_id": parts[0],
                "presentation_id": parts[0],
            }
        )
    elif scheme == "gchat":
        metadata["service"] = "chat"
        if parsed.netloc == "space" and parts:
            metadata["space"] = parts[0]
            metadata["object_id"] = parts[-1]
            metadata["object_type"] = "chat_message" if "message" in parts else "chat_space"
    elif scheme == "gadmin" and parsed.netloc == "reports" and len(parts) >= 2:
        metadata.update(
            {
                "service": "admin_reports",
                "object_type": "admin_report",
                "application": parts[0],
                "object_id": parts[1],
            }
        )
    return metadata


def _workspace_action(operation: str, parsed: dict[str, Any]) -> str:
    op = str(operation or "").lower()
    service = str(parsed.get("service") or "")
    object_type = str(parsed.get("object_type") or "")
    if op in {"write", "update", "create", "append", "send"}:
        if service == "gmail":
            return "workspace.gmail.message.send"
        if service == "calendar":
            return "workspace.calendar.event.write"
        if service == "sheets":
            return "workspace.sheets.spreadsheet.write"
        if service == "docs":
            return "workspace.docs.document.write"
        if service == "chat":
            return "workspace.chat.message.send"
        return "workspace.drive.file.write"
    if op in {"delete", "remove"}:
        return "workspace.drive.file.delete"
    if op in {"download", "export"}:
        return "workspace.drive.file.download"
    if service == "gmail" or object_type == "gmail_message" or op.startswith("gmail"):
        return "workspace.gmail.message.read"
    if service == "calendar" or object_type == "calendar_event" or op.startswith("calendar"):
        return "workspace.calendar.event.read"
    if service == "docs" or object_type == "doc":
        return "workspace.docs.document.read"
    if service == "sheets" or object_type == "sheet":
        return "workspace.sheets.spreadsheet.read"
    if service == "slides" or object_type == "slide":
        return "workspace.slides.presentation.read"
    if service == "chat" or object_type.startswith("chat_"):
        return "workspace.chat.message.read"
    if service == "admin_reports" or object_type == "admin_report":
        return "workspace.admin.report.read"
    return "workspace.drive.file.read"


def _workspace_resource_type(action: str) -> str:
    if action.startswith("workspace.drive."):
        return "workspace.drive.file"
    if action.startswith("workspace.gmail."):
        return "workspace.gmail.message"
    if action.startswith("workspace.calendar."):
        return "workspace.calendar.event"
    if action.startswith("workspace.docs."):
        return "workspace.docs.document"
    if action.startswith("workspace.sheets."):
        return "workspace.sheets.spreadsheet"
    if action.startswith("workspace.slides."):
        return "workspace.slides.presentation"
    if action.startswith("workspace.chat."):
        return "workspace.chat.message"
    if action.startswith("workspace.admin."):
        return "workspace.admin.report"
    return "workspace.resource"


def _workspace_resource_from_metadata(metadata: dict[str, Any], parsed: dict[str, Any]) -> str:
    if metadata.get("resource"):
        return str(metadata["resource"])
    object_type = str(metadata.get("object_type") or parsed.get("object_type") or "")
    object_id = str(metadata.get("object_id") or parsed.get("object_id") or "*")
    if object_type == "gmail_message":
        user = quote(str(metadata.get("user") or parsed.get("user") or "*"), safe="")
        return f"gmail://user/{user}/message/{quote(object_id, safe='')}"
    if object_type == "calendar_event":
        calendar_id = quote(
            str(metadata.get("calendar_id") or parsed.get("calendar_id") or "*"), safe=""
        )
        return f"gcal://calendar/{calendar_id}/event/{quote(object_id, safe='')}"
    if object_type == "doc":
        return f"gdocs://document/{quote(object_id, safe='')}"
    if object_type == "sheet":
        return f"gsheets://spreadsheet/{quote(object_id, safe='')}"
    if object_type == "slide":
        return f"gslides://presentation/{quote(object_id, safe='')}"
    return f"gdrive://file/{quote(object_id, safe='')}"


def _workspace_drive_asset_ref(file_id: str, mime_type: str) -> str:
    if mime_type == "application/vnd.google-apps.document":
        return f"gdocs://document/{quote(file_id, safe='')}"
    if mime_type == "application/vnd.google-apps.spreadsheet":
        return f"gsheets://spreadsheet/{quote(file_id, safe='')}"
    if mime_type == "application/vnd.google-apps.presentation":
        return f"gslides://presentation/{quote(file_id, safe='')}"
    if mime_type == "application/vnd.google-apps.folder":
        return f"gdrive://folder/{quote(file_id, safe='')}"
    return f"gdrive://file/{quote(file_id, safe='')}"


def _workspace_drive_asset_type(mime_type: str) -> str:
    mapping = {
        "application/vnd.google-apps.document": "doc",
        "application/vnd.google-apps.spreadsheet": "sheet",
        "application/vnd.google-apps.presentation": "slide",
        "application/vnd.google-apps.folder": "drive_folder",
    }
    return mapping.get(mime_type, "drive_file")


def _workspace_metadata(service: str, **values: Any) -> dict[str, Any]:
    return {
        "connector_key": "google_workspace",
        "service": service,
        **{key: value for key, value in values.items() if value is not None},
    }


def _gws_enabled_services(config: dict[str, Any]) -> list[str]:
    requested = _list_config(config.get("enabled_services") or config.get("services"))
    if not requested:
        requested = ["drive"]
    aliases = {"admin": "admin_reports", "reports": "admin_reports"}
    result: list[str] = []
    for service in requested:
        normalized = aliases.get(service.lower(), service.lower())
        if (
            normalized
            in {
                "drive",
                "gmail",
                "calendar",
                "docs",
                "sheets",
                "slides",
                "chat",
                "admin_reports",
            }
            and normalized not in result
        ):
            result.append(normalized)
    return result or ["drive"]


def _gws_has_auth(config: dict[str, Any]) -> bool:
    return bool(
        config.get("access_token")
        or config.get("access_token_ref")
        or config.get("credentials_file")
        or config.get("credentials_file_ref")
        or config.get("service_account_json")
        or config.get("service_account_json_ref")
        or config.get("gws_config_dir")
    )


def _gws_use_native_backend(config: dict[str, Any]) -> bool:
    backend = str(config.get("execution_backend") or config.get("backend") or "").lower()
    if backend in {"google_api", "native"}:
        return True
    if backend in {"gws", "gws_cli"}:
        return False
    return bool(config.get("subject_user") or config.get("service_account_json_ref"))


def _google_service(config: dict[str, Any], service_name: str, version: str) -> Any:
    try:
        from google.oauth2 import service_account  # type: ignore[import-not-found]
        from googleapiclient.discovery import build  # type: ignore[import-not-found]
    except ImportError as exc:
        raise RuntimeError("google-api-python-client and google-auth are required") from exc

    credentials_file = _gws_credential_value(config, "credentials_file", "credentials_file_ref")
    service_account_json = _gws_credential_value(
        config, "service_account_json", "service_account_json_ref"
    )
    scopes = _google_workspace_scopes(config)
    if service_account_json and service_account_json.lstrip().startswith("{"):
        credentials = service_account.Credentials.from_service_account_info(
            json.loads(service_account_json),
            scopes=scopes,
        )
    elif credentials_file or service_account_json:
        credentials = service_account.Credentials.from_service_account_file(
            credentials_file or str(service_account_json),
            scopes=scopes,
        )
    else:
        raise ValueError("native Google Workspace backend requires service-account credentials")

    if config.get("subject_user"):
        credentials = credentials.with_subject(str(config["subject_user"]))
    return build(service_name, version, credentials=credentials, cache_discovery=False)


def _google_workspace_scopes(config: dict[str, Any]) -> list[str]:
    configured = _list_config(config.get("scopes"))
    if configured:
        return configured
    services = set(_gws_enabled_services(config))
    scopes = {
        "https://www.googleapis.com/auth/drive.readonly",
        "https://www.googleapis.com/auth/documents.readonly",
        "https://www.googleapis.com/auth/spreadsheets.readonly",
        "https://www.googleapis.com/auth/presentations.readonly",
    }
    if "gmail" in services:
        scopes.add("https://www.googleapis.com/auth/gmail.readonly")
    if "calendar" in services:
        scopes.add("https://www.googleapis.com/auth/calendar.readonly")
    if "chat" in services:
        scopes.add("https://www.googleapis.com/auth/chat.messages.readonly")
    if "admin_reports" in services:
        scopes.add("https://www.googleapis.com/auth/admin.reports.audit.readonly")
    return sorted(scopes)


def _gws_env(config: dict[str, Any]) -> tuple[dict[str, str], list[Path]]:
    env = _minimal_gws_subprocess_env()
    cleanup_paths: list[Path] = []
    token = _secret_value(config, "access_token", "access_token_ref")
    if token:
        env["GOOGLE_WORKSPACE_CLI_TOKEN"] = token
    credentials_file = _gws_credential_value(config, "credentials_file", "credentials_file_ref")
    service_account = _gws_credential_value(
        config, "service_account_json", "service_account_json_ref"
    )
    credentials_value = credentials_file or service_account
    if credentials_value:
        if credentials_value.lstrip().startswith("{"):
            handle = tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                prefix="interlock-gws-credentials-",
                suffix=".json",
                delete=False,
            )
            try:
                handle.write(credentials_value)
            finally:
                handle.close()
            path = Path(handle.name)
            path.chmod(0o600)
            cleanup_paths.append(path)
            env["GOOGLE_WORKSPACE_CLI_CREDENTIALS_FILE"] = str(path)
        else:
            env["GOOGLE_WORKSPACE_CLI_CREDENTIALS_FILE"] = credentials_value
    if config.get("gws_config_dir"):
        env["GOOGLE_WORKSPACE_CLI_CONFIG_DIR"] = str(config["gws_config_dir"])
    if config.get("project_id"):
        env["GOOGLE_WORKSPACE_PROJECT_ID"] = str(config["project_id"])
    return env, cleanup_paths


def _minimal_gws_subprocess_env() -> dict[str, str]:
    env: dict[str, str] = {"PATH": os.environ.get("PATH", os.defpath)}
    for key in ("HOME", "SSL_CERT_FILE", "SSL_CERT_DIR", "LANG", "LC_ALL"):
        value = os.environ.get(key)
        if value:
            env[key] = value
    return env


def _gws_credential_value(config: dict[str, Any], literal_key: str, ref_key: str) -> str | None:
    try:
        if config.get(ref_key):
            return resolve_file_path(str(config[ref_key]))
        if config.get(literal_key):
            return resolve_file_path(str(config[literal_key]))
    except MissingSecretError as exc:
        raise RuntimeError(str(exc)) from exc
    return None


def _scrub_gws_text(text: str, config: dict[str, Any]) -> str:
    redacted = text
    for marker in _gws_secret_markers(config):
        redacted = redacted.replace(marker, "[REDACTED]")
    redacted = re.sub(r"ya29\.[A-Za-z0-9._~+-]+", "[REDACTED]", redacted)
    redacted = re.sub(
        r"(?is)-----BEGIN [^-]*PRIVATE KEY-----.*?(?:-----END [^-]*PRIVATE KEY-----|$)",
        "[REDACTED]",
        redacted,
    )
    redacted = re.sub(
        r"(?i)(token|password|secret|client_secret|private_key|authorization)"
        r"([\"']?\s*[:=]\s*[\"']?)[^\"'\s,}]+",
        r"\1\2[REDACTED]",
        redacted,
    )
    return redacted


def _gws_secret_markers(config: dict[str, Any]) -> set[str]:
    markers: set[str] = set()
    for literal_key, ref_key in (
        ("access_token", "access_token_ref"),
        ("credentials_file", "credentials_file_ref"),
        ("service_account_json", "service_account_json_ref"),
    ):
        literal = config.get(literal_key)
        if isinstance(literal, str) and len(literal) >= 6 and not literal.startswith("file://"):
            markers.add(literal)
        ref = config.get(ref_key)
        if ref:
            try:
                resolved = resolve(str(ref))
            except MissingSecretError:
                resolved = None
            if resolved and len(resolved) >= 6:
                markers.add(resolved)
    for payload in list(markers):
        if payload.lstrip().startswith("{"):
            try:
                parsed = json.loads(payload)
            except json.JSONDecodeError:
                continue
            private_key = parsed.get("private_key") if isinstance(parsed, dict) else None
            if isinstance(private_key, str) and len(private_key) >= 6:
                markers.add(private_key)
    return markers


def _parse_gws_output(stdout: bytes) -> Any:
    text = stdout.decode(errors="replace").strip()
    if not text:
        return {}
    lines = [line for line in text.splitlines() if line.strip()]
    if len(lines) > 1:
        parsed_lines: list[Any] = []
        for line in lines:
            try:
                parsed_lines.append(json.loads(line))
            except json.JSONDecodeError:
                pass
        if parsed_lines:
            return parsed_lines
    return json.loads(text)


def _gws_payloads(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if isinstance(payload, dict):
        return [payload]
    return []


def _saas_permission_request(
    *,
    provider: str,
    source_id: str,
    identity_id: int | None,
    operation: str,
    metadata: dict[str, Any] | None,
    default_object_type: str,
) -> PermissionRequest:
    metadata = metadata or {}
    asset_ref = str(metadata.get("asset_ref") or metadata.get("path") or "")
    parsed = _parse_saas_asset_ref(provider, asset_ref)
    object_type = str(
        metadata.get("object_type") or parsed.get("object_type") or default_object_type
    )
    object_id = str(metadata.get("object_id") or parsed.get("object_id") or "*")
    op = str(operation or metadata.get("operation") or "read").lower()
    if op in {"describe", "metadata"}:
        action = "saas.object.describe"
    elif op in {"search", "query", "list", "discovery"}:
        action = "saas.object.search"
    elif op in {"write", "update", "create", "comment"}:
        action = "saas.object.write"
    elif op in {"delete", "remove"}:
        action = "saas.object.delete"
    else:
        action = "saas.object.read"
    resource = asset_ref or f"{provider}:{object_type}/{object_id}"
    if resource.startswith(f"{provider}://"):
        resource = _canonical_saas_resource(provider, object_type, object_id)
    return PermissionRequest(
        protocol="saas",
        source_id=source_id,
        identity_id=identity_id,
        action=action,
        resource_type="saas.object",
        resources=[resource],
        operation=op,
        path=resource,
        risk_level=(
            "low"
            if action in {"saas.object.describe", "saas.object.search", "saas.object.read"}
            else "high"
        ),
        metadata={
            "connector_key": provider,
            **metadata,
            **parsed,
            "object_type": object_type,
            "object_id": object_id,
        },
    )


def _canonical_saas_resource(provider: str, object_type: str, object_id: str) -> str:
    return f"{provider}:{object_type}/{object_id or '*'}"


def _resource_type_for_connector_action(action: str, metadata: dict[str, Any]) -> str | None:
    if action.startswith("storage.bucket."):
        return "storage.bucket"
    if action.startswith("storage.prefix."):
        return "storage.prefix"
    if action.startswith("storage.object."):
        return "storage.object"
    if action.startswith("saas."):
        return "saas.object"
    if action.startswith("search.document."):
        return "search.document"
    if action.startswith("search.index."):
        return "search.collection" if metadata.get("connector_key") == "qdrant" else "search.index"
    if action.startswith("search."):
        return "search.index"
    if action.startswith("db.schema."):
        return "db.schema"
    if action.startswith("db.table."):
        return "db.table"
    if action == "db.execute_raw":
        return "db.raw"
    if action.startswith("repo.issue."):
        return "repo.issue"
    if action.startswith("repo.pr."):
        return "repo.pull_request"
    if action.startswith("repo.code."):
        return "repo.path"
    if action == "repo.action.execute":
        object_type = str(metadata.get("object_type") or "")
        if object_type == "issue":
            return "repo.issue"
        if object_type in {"pr", "pull_request", "merge_request"}:
            return "repo.pull_request"
        if object_type in {"workflow", "pipeline"}:
            return "repo.workflow"
    if action.startswith("repo."):
        return "repo.repository"
    if action.startswith("workspace.drive."):
        return "workspace.drive.file"
    if action.startswith("workspace.gmail."):
        return "workspace.gmail.message"
    if action.startswith("workspace.calendar."):
        return "workspace.calendar.event"
    if action.startswith("workspace.docs."):
        return "workspace.docs.document"
    if action.startswith("workspace.sheets."):
        return "workspace.sheets.spreadsheet"
    if action.startswith("workspace.slides."):
        return "workspace.slides.presentation"
    if action.startswith("workspace.chat."):
        return "workspace.chat.message"
    if action.startswith("workspace.admin."):
        return "workspace.admin.report"
    return None


def _salesforce_fields_for(object_name: str) -> list[str]:
    title_field = "Subject" if object_name in {"Case", "Task", "Event"} else "Name"
    fields = ["Id", title_field, "LastModifiedDate", "SystemModstamp"]
    if object_name == "Contact":
        fields.extend(["Email", "AccountId"])
    if object_name == "Opportunity":
        fields.extend(["StageName", "Amount", "AccountId"])
    if object_name == "Case":
        fields.extend(["Status", "AccountId", "ContactId"])
    return list(dict.fromkeys(fields))


def _notion_title(item: dict[str, Any]) -> str:
    properties = item.get("properties") if isinstance(item.get("properties"), dict) else {}
    for value in properties.values():
        if not isinstance(value, dict):
            continue
        candidates = value.get("title") or value.get("rich_text") or []
        parts = [
            str(part.get("plain_text") or "")
            for part in candidates
            if isinstance(part, dict) and part.get("plain_text")
        ]
        if parts:
            return "".join(parts)[:160]
    return str(item.get("id") or item.get("object") or "Notion item")


def _request_query(request: dict[str, Any]) -> str:
    return str(request.get("query") or request.get("sql") or request.get("operation") or "").strip()


def _ensure_single_read_sql(query: str, *, dialect: str) -> None:
    """Reject write or multi-statement SQL before a read connector opens a DB connection."""
    try:
        import sqlglot  # type: ignore[import-not-found]
        from sqlglot import expressions as exp  # type: ignore[import-not-found]

        parsed = [statement for statement in sqlglot.parse(query, read=dialect) if statement]
        if len(parsed) != 1:
            raise PermissionError("execute_read only accepts a single read SQL statement")

        statement = parsed[0]
        write_types = tuple(
            getattr(exp, name)
            for name in (
                "Insert",
                "Update",
                "Delete",
                "Create",
                "Drop",
                "Alter",
                "Truncate",
                "Merge",
            )
            if hasattr(exp, name)
        )
        if write_types and (
            isinstance(statement, write_types) or any(statement.find_all(*write_types))
        ):
            raise PermissionError("execute_read only accepts read SQL")

        read_types = tuple(
            getattr(exp, name)
            for name in ("Select", "Show", "Describe", "Explain")
            if hasattr(exp, name)
        )
        if not read_types or not isinstance(statement, read_types):
            raise PermissionError("execute_read only accepts read SQL")
        return
    except PermissionError:
        raise
    except Exception:
        lowered = query.lower().lstrip()
        if _contains_unquoted_semicolon(query):
            raise PermissionError("execute_read only accepts a single read SQL statement") from None
        if not lowered.startswith(("select", "show", "describe", "desc", "explain")):
            raise PermissionError("execute_read only accepts read SQL") from None
        if re.search(
            r"\b(insert|update|delete|create|drop|alter|truncate|replace|merge)\b",
            lowered,
        ):
            raise PermissionError("execute_read only accepts read SQL") from None


def _ensure_single_write_sql(query: str, *, dialect: str) -> None:
    """Reject multi-statement or read-only SQL before a write connector executes."""
    try:
        import sqlglot  # type: ignore[import-not-found]
        from sqlglot import expressions as exp  # type: ignore[import-not-found]

        parsed = [statement for statement in sqlglot.parse(query, read=dialect) if statement]
        if len(parsed) != 1:
            raise PermissionError("execute_write only accepts a single write SQL statement")

        statement = parsed[0]
        read_types = tuple(
            getattr(exp, name)
            for name in ("Select", "Show", "Describe", "Explain")
            if hasattr(exp, name)
        )
        if read_types and isinstance(statement, read_types):
            raise PermissionError("execute_write only accepts write SQL")

        write_types = tuple(
            getattr(exp, name)
            for name in (
                "Insert",
                "Update",
                "Delete",
                "Create",
                "Drop",
                "Alter",
                "Truncate",
                "Merge",
                "Command",
            )
            if hasattr(exp, name)
        )
        if write_types and (
            isinstance(statement, write_types) or any(statement.find_all(*write_types))
        ):
            return
        raise PermissionError("execute_write only accepts recognized write SQL")
    except PermissionError:
        raise
    except Exception:
        lowered = query.lower().lstrip()
        if _contains_unquoted_semicolon(query):
            raise PermissionError(
                "execute_write only accepts a single write SQL statement"
            ) from None
        if not lowered.startswith(
            (
                "insert",
                "update",
                "delete",
                "create",
                "drop",
                "alter",
                "truncate",
                "merge",
                "copy",
                "grant",
                "revoke",
            )
        ):
            raise PermissionError("execute_write only accepts write SQL") from None


def _contains_unquoted_semicolon(query: str) -> bool:
    in_single = False
    in_double = False
    in_backtick = False
    escaped = False
    for index, char in enumerate(query):
        if escaped:
            escaped = False
            continue
        if char == "\\" and in_single:
            escaped = True
            continue
        if char == "'" and not in_double and not in_backtick:
            in_single = not in_single
            continue
        if char == '"' and not in_single and not in_backtick:
            in_double = not in_double
            continue
        if char == "`" and not in_single and not in_double:
            in_backtick = not in_backtick
            continue
        if char == ";" and not in_single and not in_double and not in_backtick:
            return bool(query[index + 1 :].strip())
    return False


def _sql_permission_request(
    *,
    source_id: str,
    identity_id: int | None,
    query: str,
    dialect: str,
    protocol: str,
    metadata: dict[str, Any],
) -> PermissionRequest:
    action = "db.execute_raw"
    schemas: set[str] = set()
    tables: set[str] = set()
    columns: set[str] = set()
    risk = "medium"

    try:
        import sqlglot  # type: ignore[import-not-found]
        from sqlglot import expressions as exp  # type: ignore[import-not-found]

        parsed = sqlglot.parse_one(query, read=dialect)
        if isinstance(parsed, exp.Select):
            action = "db.table.select"
            risk = "low"
        elif isinstance(parsed, exp.Insert):
            action = "db.table.insert"
            risk = "medium"
        elif isinstance(parsed, exp.Update):
            action = "db.table.update"
            risk = "medium"
        elif isinstance(parsed, exp.Delete):
            action = "db.table.delete_rows"
            risk = "high"
        elif isinstance(parsed, exp.Create):
            action = "db.schema.create_table"
            risk = "high"
        elif isinstance(parsed, exp.Drop):
            action = "db.schema.drop_table"
            risk = "high"
        elif isinstance(parsed, exp.Alter):
            action = "db.schema.alter_table"
            risk = "high"

        for table in parsed.find_all(exp.Table):
            table_name = table.name
            db = table.db
            catalog = getattr(table, "catalog", None)
            if catalog and db:
                schemas.add(f"{catalog}.{db}")
                tables.add(f"{catalog}.{db}.{table_name}")
            elif db:
                schemas.add(str(db))
                tables.add(f"{db}.{table_name}")
            elif table_name:
                tables.add(str(table_name))
        for column in parsed.find_all(exp.Column):
            if column.name:
                columns.add(str(column.name))
    except Exception:
        lowered = query.lower().lstrip()
        if lowered.startswith(("select", "show", "describe", "desc")):
            action = "db.table.select"
            risk = "low"
        elif lowered.startswith("insert"):
            action = "db.table.insert"
        elif lowered.startswith("update"):
            action = "db.table.update"
        elif lowered.startswith("delete"):
            action = "db.table.delete_rows"
            risk = "high"
        elif lowered.startswith(("create", "alter", "drop", "truncate")):
            action = "db.execute_raw"
            risk = "high"
        for table in _fallback_sql_tables(query):
            parts = table.split(".")
            if len(parts) > 1:
                schemas.add(".".join(parts[:-1]))
                tables.add(table)
            else:
                tables.add(f"*.{table}")

    resources = sorted(tables) or (["*.*"] if action.startswith("db.table.") else ["*"])
    operation = action.rsplit(".", 1)[-1]
    return PermissionRequest(
        protocol=protocol,
        source_id=source_id,
        identity_id=identity_id,
        action=action,
        resources=resources,
        operation=operation,
        schemas=sorted(schemas),
        tables=sorted(tables),
        columns=sorted(columns),
        risk_level=risk,
        metadata={**metadata, "dialect": dialect, "query": query},
    )


def _fallback_sql_tables(query: str) -> set[str]:
    cleaned = " ".join(query.replace("\n", " ").split())
    patterns = (
        r"\bfrom\s+([A-Za-z0-9_.$\"`]+)",
        r"\bjoin\s+([A-Za-z0-9_.$\"`]+)",
        r"\binsert\s+into\s+([A-Za-z0-9_.$\"`]+)",
        r"\bupdate\s+([A-Za-z0-9_.$\"`]+)",
        r"\bdelete\s+from\s+([A-Za-z0-9_.$\"`]+)",
        r"\btruncate\s+(?:table\s+)?([A-Za-z0-9_.$\"`]+)",
        r"\bcreate\s+table\s+([A-Za-z0-9_.$\"`]+)",
        r"\balter\s+table\s+([A-Za-z0-9_.$\"`]+)",
        r"\bdrop\s+table\s+([A-Za-z0-9_.$\"`]+)",
    )
    tables: set[str] = set()
    for pattern in patterns:
        for match in re.finditer(pattern, cleaned, flags=re.IGNORECASE):
            table = match.group(1).strip().strip(",;")
            table = table.replace('"', "").replace("`", "").replace("$", ".")
            if table:
                tables.add(table)
    return tables


def _aws_credentials(config: dict[str, Any]) -> dict[str, str]:
    credentials: dict[str, str] = {}
    access_key = _secret_value(config, "aws_access_key_id", "aws_access_key_id_ref")
    secret_key = _secret_value(config, "aws_secret_access_key", "aws_secret_access_key_ref")
    if access_key:
        credentials["aws_access_key_id"] = access_key
    if secret_key:
        credentials["aws_secret_access_key"] = secret_key
    return credentials


def _s3_key_from_ref(asset_ref: str, *, default_bucket: str) -> str:
    parsed = urlparse(asset_ref)
    if parsed.scheme == "s3":
        if parsed.netloc and parsed.netloc != default_bucket:
            raise ValueError(f"asset bucket {parsed.netloc!r} does not match configured bucket")
        return parsed.path.lstrip("/")
    return asset_ref.lstrip("/")


def _zendesk_base_url(config: dict[str, Any]) -> str:
    if config.get("base_url"):
        return str(config["base_url"]).rstrip("/")
    subdomain = config.get("subdomain")
    return f"https://{subdomain}.zendesk.com" if subdomain else ""


def _zendesk_headers(config: dict[str, Any]) -> dict[str, str]:
    token = _secret_value(config, "api_token", "api_token_ref")
    if not token:
        return {}
    email = config.get("email")
    if email:
        raw = f"{email}/token:{token}".encode()
        return {"Authorization": f"Basic {base64.b64encode(raw).decode()}"}
    return {"Authorization": f"Bearer {token}"}


def _zendesk_bool(config: dict[str, Any], key: str, default: bool) -> bool:
    value = config.get(key)
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() not in {"", "0", "false", "no", "off"}


def _zendesk_limit(config: dict[str, Any], key: str, default: int) -> int:
    try:
        return max(1, min(int(config.get(key) or default), 100))
    except (TypeError, ValueError):
        return default


def _zendesk_endpoint(
    path: str,
    *,
    per_page: int,
    extra: dict[str, Any] | None = None,
) -> str:
    params = {"per_page": per_page, **(extra or {})}
    query = "&".join(
        f"{quote(str(key))}={quote(str(value))}"
        for key, value in params.items()
        if value is not None and value != ""
    )
    return f"{path}?{query}" if query else path


def _zendesk_ticket_filter_params(config: dict[str, Any]) -> dict[str, Any]:
    params: dict[str, Any] = {}
    for cfg_key, api_key in (
        ("brand_id", "brand_id"),
        ("group_id", "group_id"),
        ("organization_id", "organization_id"),
        ("status", "status"),
    ):
        if config.get(cfg_key):
            params[api_key] = config[cfg_key]
    return params


def _zendesk_asset_metadata(object_type: str, item: dict[str, Any]) -> dict[str, Any]:
    fields = [
        "id",
        "brand_id",
        "group_id",
        "organization_id",
        "requester_id",
        "assignee_id",
        "status",
        "tags",
        "section_id",
        "locale",
        "draft",
        "role",
        "updated_at",
        "created_at",
    ]
    return {
        "connector_key": "zendesk",
        "object_type": object_type,
        **{key: item.get(key) for key in fields if key in item},
    }


def _repo_path_list(raw: Any) -> list[str]:
    if not raw:
        return []
    if isinstance(raw, (list, tuple, set)):
        values = raw
    else:
        values = str(raw).replace("\n", ",").split(",")
    paths: list[str] = []
    seen: set[str] = set()
    for value in values:
        path = str(value).strip().lstrip("/")
        if not path or path in seen:
            continue
        seen.add(path)
        paths.append(path)
    return paths


def _repo_metadata(
    provider: str,
    object_type: str,
    *,
    full_name: str | None = None,
    project_id: str | None = None,
    branch: str | None = None,
    path: str | None = None,
    labels: Any = None,
    **extra: Any,
) -> dict[str, Any]:
    metadata: dict[str, Any] = {
        "connector_key": provider,
        "object_type": object_type,
    }
    if full_name:
        metadata["full_name"] = full_name
        if "/" in full_name:
            org, repo = full_name.split("/", 1)
            metadata["org"] = org
            metadata["repo"] = repo
    if project_id:
        metadata["project_id"] = str(project_id)
    if branch:
        metadata["branch"] = branch
    if path:
        metadata["path"] = path
    if labels is not None:
        metadata["labels"] = [str(label) for label in labels]
    metadata.update({key: value for key, value in extra.items() if value is not None})
    return metadata


def _github_labels(item: Any) -> list[str]:
    labels = getattr(item, "labels", []) or []
    out: list[str] = []
    for label in labels:
        out.append(str(getattr(label, "name", label)))
    return out


def _safe_iter(factory: Any, limit: int) -> list[Any]:
    """Read up to `limit` items from an optional listing, never raising.

    The call and the iteration are guarded together on purpose. PyGithub and
    python-gitlab both return a lazy paginated object, so the HTTP request -
    and therefore any 403 from a least-privilege token - happens on the first
    iteration, not on the call that produced it. Guarding only the call left
    exactly the failure this helper exists to absorb free to abort the whole
    sync, so one unreadable listing discarded every other asset.

    Whatever was read before a mid-listing failure is kept: a page boundary
    the token cannot cross should cost that page, not the pages already read.
    """
    if limit <= 0:
        return []
    out: list[Any] = []
    try:
        for value in factory():
            if len(out) >= limit:
                break
            out.append(value)
    except Exception:
        # Warning, not debug: the caller silently returns fewer assets than
        # the upstream holds, and an operator needs to be able to see why.
        logger.warning(
            "Repository connector optional listing failed after %d item(s); "
            "continuing without the rest",
            len(out),
            exc_info=True,
        )
    return out


def _repo_limit(config: dict[str, Any], key: str, default: int) -> int:
    """A listing limit that honours an explicit zero.

    Read as `int(config.get(key) or default)`, a limit of 0 was falsy and so
    selected the default - meaning a listing could not be switched off, which
    is the obvious remedy when one of them is unreadable. It was also
    type-dependent: 0 took the default while the string "0" did not.
    """
    raw = config.get(key)
    if raw is None or raw == "":
        return default
    try:
        return max(0, int(raw))
    except (TypeError, ValueError):
        return default


def _parse_slack_asset_ref(asset_ref: str) -> dict[str, Any]:
    if not asset_ref:
        return {}
    parsed = urlparse(asset_ref)
    if parsed.scheme and parsed.scheme != "slack":
        return {}
    parts = [part for part in parsed.path.strip("/").split("/") if part]
    if parsed.netloc == "channel" and parts:
        metadata: dict[str, Any] = {
            "object_type": "channel",
            "channel_id": parts[0],
        }
        if len(parts) >= 3 and parts[1] == "message":
            metadata.update({"object_type": "message", "ts": parts[2]})
        elif len(parts) >= 5 and parts[1] == "thread" and parts[3] == "message":
            metadata.update(
                {
                    "object_type": "thread_reply",
                    "thread_ts": parts[2],
                    "ts": parts[4],
                }
            )
        return metadata
    if parsed.netloc == "file" and parts:
        return {"object_type": "file", "file_id": parts[0]}
    return {"object_type": parsed.netloc} if parsed.netloc else {}


def _slack_bool(config: dict[str, Any], key: str, default: bool) -> bool:
    value = config.get(key)
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() not in {"", "0", "false", "no", "off"}


def _slack_limit(config: dict[str, Any], key: str, default: int) -> int:
    try:
        return max(1, min(int(config.get(key) or default), 200))
    except (TypeError, ValueError):
        return default


def _slack_id_list(raw: Any) -> list[str]:
    if not raw:
        return []
    if isinstance(raw, (list, tuple, set)):
        values = raw
    else:
        values = str(raw).replace("\n", ",").split(",")
    ids: list[str] = []
    seen: set[str] = set()
    for value in values:
        item = str(value).strip()
        if not item or item in seen:
            continue
        seen.add(item)
        ids.append(item)
    return ids


def _slack_response_dict(response: Any) -> dict[str, Any]:
    if isinstance(response, dict):
        return dict(response)
    data = getattr(response, "data", None)
    if isinstance(data, dict):
        return dict(data)
    to_dict = getattr(response, "to_dict", None)
    if callable(to_dict):
        converted = to_dict()
        if isinstance(converted, dict):
            return converted
    return {"response": str(response)}


def _slack_channel_type(channel: dict[str, Any]) -> str:
    if channel.get("is_im"):
        return "im"
    if channel.get("is_mpim"):
        return "mpim"
    if channel.get("is_private"):
        return "private_channel"
    return "public_channel"


def _slack_asset_metadata(object_type: str, **values: Any) -> dict[str, Any]:
    return {
        "connector_key": "slack",
        "object_type": object_type,
        **{key: value for key, value in values.items() if value is not None},
    }


def _slack_file_asset(
    file_item: dict[str, Any],
    *,
    channel_id: str | None = None,
    channel_name: str | None = None,
    channel_type: str | None = None,
    workspace: Any = None,
) -> dict[str, Any]:
    file_id = str(file_item.get("id") or "")
    file_type = file_item.get("filetype") or file_item.get("mimetype")
    name = file_item.get("title") or file_item.get("name") or file_id
    return {
        "asset_path": f"slack://file/{file_id}",
        "asset_type": "file",
        "title": name,
        "updated_at": file_item.get("updated") or file_item.get("created"),
        "metadata": _slack_asset_metadata(
            "file",
            file_id=file_id,
            file_type=file_type,
            mimetype=file_item.get("mimetype"),
            size=file_item.get("size"),
            channel_id=channel_id or (file_item.get("channels") or [None])[0],
            channel_name=channel_name,
            channel_type=channel_type,
            user_id=file_item.get("user"),
            workspace=workspace,
        ),
    }


def _slack_client(config: dict[str, Any]) -> Any:
    try:
        from slack_sdk.web.async_client import AsyncWebClient  # type: ignore[import-not-found]
    except ImportError as exc:
        raise RuntimeError("slack-sdk is not installed") from exc
    token = _secret_value(config, "bot_token", "bot_token_ref") or _secret_value(
        config, "token", "token_ref"
    )
    if not token:
        raise ValueError("connection_config.bot_token or bot_token_ref is required")
    return AsyncWebClient(token=token)


DB_READ = [
    {
        "effect": "allow",
        "action": "db.schema.list",
        "resource_type": "db.schema",
        "resource_pattern": "*",
    },
    {
        "effect": "allow",
        "action": "db.table.describe",
        "resource_type": "db.table",
        "resource_pattern": "*.*",
    },
    {
        "effect": "allow",
        "action": "db.table.select",
        "resource_type": "db.table",
        "resource_pattern": "*.*",
    },
    {
        "effect": "allow",
        "action": "discovery.search",
        "resource_type": "discovery.asset",
        "resource_pattern": "*",
    },
    {
        "effect": "allow",
        "action": "discovery.asset.read",
        "resource_type": "discovery.asset",
        "resource_pattern": "*",
    },
]
DB_WRITE = [
    *DB_READ,
    {
        "effect": "allow",
        "action": "db.table.insert",
        "resource_type": "db.table",
        "resource_pattern": "*.*",
    },
    {
        "effect": "allow",
        "action": "db.table.update",
        "resource_type": "db.table",
        "resource_pattern": "*.*",
    },
]
OWNER = [{"effect": "allow", "action": "*", "resource_type": "*", "resource_pattern": "*"}]
BLOCKED = [{"effect": "deny", "action": "*", "resource_type": "*", "resource_pattern": "*"}]

STORAGE_BROWSER = [
    {
        "effect": "allow",
        "action": "storage.bucket.list",
        "resource_type": "storage.bucket",
        "resource_pattern": "*",
    },
    {
        "effect": "allow",
        "action": "storage.prefix.list",
        "resource_type": "storage.prefix",
        "resource_pattern": "*",
    },
]
STORAGE_READER = [
    *STORAGE_BROWSER,
    {
        "effect": "allow",
        "action": "storage.object.read",
        "resource_type": "storage.object",
        "resource_pattern": "*",
    },
    {
        "effect": "allow",
        "action": "storage.object.metadata.read",
        "resource_type": "storage.object",
        "resource_pattern": "*",
    },
    {
        "effect": "allow",
        "action": "discovery.search",
        "resource_type": "discovery.asset",
        "resource_pattern": "*",
    },
    {
        "effect": "allow",
        "action": "discovery.asset.read",
        "resource_type": "discovery.asset",
        "resource_pattern": "*",
    },
]

SAAS_READER = [
    {
        "effect": "allow",
        "action": "saas.object.describe",
        "resource_type": "saas.object",
        "resource_pattern": "*",
    },
    {
        "effect": "allow",
        "action": "saas.object.read",
        "resource_type": "saas.object",
        "resource_pattern": "*",
    },
    {
        "effect": "allow",
        "action": "saas.object.search",
        "resource_type": "saas.object",
        "resource_pattern": "*",
    },
    {
        "effect": "allow",
        "action": "discovery.search",
        "resource_type": "discovery.asset",
        "resource_pattern": "*",
    },
    {
        "effect": "allow",
        "action": "discovery.asset.read",
        "resource_type": "discovery.asset",
        "resource_pattern": "*",
    },
]

COLLAB_READER = [
    {
        "effect": "allow",
        "action": "collab.channel.read",
        "resource_type": "collab.channel",
        "resource_pattern": "*",
    },
    {
        "effect": "allow",
        "action": "collab.message.read",
        "resource_type": "collab.message",
        "resource_pattern": "*",
    },
    {
        "effect": "allow",
        "action": "collab.file.read",
        "resource_type": "collab.file",
        "resource_pattern": "*",
    },
    {
        "effect": "allow",
        "action": "discovery.search",
        "resource_type": "discovery.asset",
        "resource_pattern": "*",
    },
]

WORKSPACE_DISCOVERY = [
    {
        "effect": "allow",
        "action": "discovery.search",
        "resource_type": "discovery.asset",
        "resource_pattern": "*",
    },
    {
        "effect": "allow",
        "action": "discovery.asset.read",
        "resource_type": "discovery.asset",
        "resource_pattern": "*",
    },
]
WORKSPACE_DRIVE_READER = [
    {
        "effect": "allow",
        "action": "workspace.drive.file.read",
        "resource_type": "workspace.drive.file",
        "resource_pattern": "gdrive://*",
    },
    {
        "effect": "allow",
        "action": "workspace.drive.file.download",
        "resource_type": "workspace.drive.file",
        "resource_pattern": "gdrive://*",
    },
    {
        "effect": "allow",
        "action": "workspace.docs.document.read",
        "resource_type": "workspace.docs.document",
        "resource_pattern": "gdocs://document/*",
    },
    {
        "effect": "allow",
        "action": "workspace.sheets.spreadsheet.read",
        "resource_type": "workspace.sheets.spreadsheet",
        "resource_pattern": "gsheets://spreadsheet/*",
    },
    {
        "effect": "allow",
        "action": "workspace.slides.presentation.read",
        "resource_type": "workspace.slides.presentation",
        "resource_pattern": "gslides://presentation/*",
    },
    *WORKSPACE_DISCOVERY,
]
WORKSPACE_GMAIL_READER = [
    {
        "effect": "allow",
        "action": "workspace.gmail.message.read",
        "resource_type": "workspace.gmail.message",
        "resource_pattern": "gmail://user/*/message/*",
    },
    *WORKSPACE_DISCOVERY,
]
WORKSPACE_CALENDAR_READER = [
    {
        "effect": "allow",
        "action": "workspace.calendar.event.read",
        "resource_type": "workspace.calendar.event",
        "resource_pattern": "gcal://calendar/*/event/*",
    },
    *WORKSPACE_DISCOVERY,
]
WORKSPACE_ADMIN_AUDITOR = [
    {
        "effect": "allow",
        "action": "workspace.admin.report.read",
        "resource_type": "workspace.admin.report",
        "resource_pattern": "gadmin://reports/*/*",
    },
    *WORKSPACE_DISCOVERY,
]

REPO_READER = [
    {
        "effect": "allow",
        "action": "repo.read",
        "resource_type": "repo.repository",
        "resource_pattern": "*",
    },
    {
        "effect": "allow",
        "action": "repo.issue.read",
        "resource_type": "repo.issue",
        "resource_pattern": "*",
    },
    {
        "effect": "allow",
        "action": "repo.pr.read",
        "resource_type": "repo.pull_request",
        "resource_pattern": "*",
    },
]
CODE_READER = [
    *REPO_READER,
    {
        "effect": "allow",
        "action": "repo.code.read",
        "resource_type": "repo.path",
        "resource_pattern": "*",
    },
]

SEARCH_READER = [
    {
        "effect": "allow",
        "action": "search.index.describe",
        "resource_type": "search.index",
        "resource_pattern": "*",
    },
    {
        "effect": "allow",
        "action": "search.query",
        "resource_type": "search.index",
        "resource_pattern": "*",
    },
    {
        "effect": "allow",
        "action": "search.document.read",
        "resource_type": "search.document",
        "resource_pattern": "*",
    },
]
SEARCH_WRITER = [
    *SEARCH_READER,
    {
        "effect": "allow",
        "action": "search.document.write",
        "resource_type": "search.document",
        "resource_pattern": "*",
    },
]
SEARCH_ADMIN = [
    *SEARCH_WRITER,
    {
        "effect": "allow",
        "action": "search.document.delete",
        "resource_type": "search.document",
        "resource_pattern": "*",
    },
]
QDRANT_READER = [
    {
        "effect": "allow",
        "action": "search.index.describe",
        "resource_type": "search.collection",
        "resource_pattern": "*",
    },
    {
        "effect": "allow",
        "action": "search.query",
        "resource_type": "search.collection",
        "resource_pattern": "*",
    },
    {
        "effect": "allow",
        "action": "search.document.read",
        "resource_type": "search.document",
        "resource_pattern": "*",
    },
    {
        "effect": "allow",
        "action": "discovery.search",
        "resource_type": "discovery.asset",
        "resource_pattern": "*",
    },
    {
        "effect": "allow",
        "action": "discovery.asset.read",
        "resource_type": "discovery.asset",
        "resource_pattern": "*",
    },
]


CONNECTOR_DEFINITIONS: dict[str, ConnectorDefinition] = {
    "postgresql": ConnectorDefinition(
        key="postgresql",
        name="PostgreSQL",
        tier=0,
        source_type="postgresql",
        family="database",
        status="production",
        description="Existing governed PostgreSQL proxy and discovery connector.",
        # `database` is required, not optional: the proxy falls back to the
        # client's startup database (the source id) when it is absent, which
        # never names a real upstream database. `sslmode` and `verify_ssl` are
        # the PostgreSQL spellings of the common `ssl` / `ssl_verify` keys and
        # are read alongside them, so they must be declared too.
        credential_fields=(
            "host",
            "port",
            "database",
            "database_ref",
            "user",
            "password_ref",
            "sslmode",
            "verify_ssl",
        ),
        secret_fields=("password",),
        capabilities=ConnectorCapabilities(True, True, True, True, False, True, True, False),
        default_cache_strategy="deterministic_first",
        role_templates={
            "read": DB_READ,
            "analyst": DB_READ,
            "write": DB_WRITE,
            "owner": OWNER,
            "blocked": BLOCKED,
        },
    ),
    "mysql": ConnectorDefinition(
        key="mysql",
        name="MySQL / MariaDB",
        tier=1,
        source_type="mysql",
        family="database",
        status="native",
        description="Async MySQL/MariaDB connector using aiomysql and sqlglot.",
        oss_libraries=("aiomysql", "sqlglot"),
        credential_fields=("host", "port", "database", "user", "password_ref"),
        secret_fields=("password",),
        capabilities=ConnectorCapabilities(True, True, True, True, False, True, True, False),
        default_cache_strategy="deterministic_first",
        role_templates={
            "read": DB_READ,
            "writer": DB_WRITE,
            "maintainer": [
                *DB_WRITE,
                {
                    "effect": "allow",
                    "action": "db.table.delete_rows",
                    "resource_type": "db.table",
                    "resource_pattern": "*.*",
                },
            ],
            "schema_owner": OWNER,
            "blocked": BLOCKED,
        },
    ),
    "mariadb": ConnectorDefinition(
        key="mariadb",
        name="MariaDB",
        tier=1,
        source_type="mysql",
        family="database",
        status="native",
        description="MariaDB-compatible connector using the MySQL adapter.",
        oss_libraries=("aiomysql", "sqlglot"),
        credential_fields=("host", "port", "database", "user", "password_ref"),
        secret_fields=("password",),
        capabilities=ConnectorCapabilities(True, True, True, True, False, True, True, False),
        default_cache_strategy="deterministic_first",
        role_templates={},
    ),
    "s3": ConnectorDefinition(
        key="s3",
        name="Amazon S3",
        tier=1,
        source_type="s3",
        family="object_storage",
        status="native",
        description="S3 object discovery and ingestion connector using aiobotocore.",
        oss_libraries=("aiobotocore",),
        credential_fields=(
            "bucket",
            "prefix",
            "region_name",
            "endpoint_url",
            "aws_access_key_id_ref",
            "aws_secret_access_key_ref",
        ),
        secret_fields=("aws_access_key_id", "aws_secret_access_key"),
        capabilities=ConnectorCapabilities(False, False, True, True, True, True, False, False),
        role_templates={
            "browser": STORAGE_BROWSER,
            "reader": STORAGE_READER,
            "writer": [
                *STORAGE_READER,
                {
                    "effect": "allow",
                    "action": "storage.object.write",
                    "resource_type": "storage.object",
                    "resource_pattern": "*",
                },
            ],
            "maintainer": [
                *STORAGE_READER,
                {
                    "effect": "allow",
                    "action": "storage.object.delete",
                    "resource_type": "storage.object",
                    "resource_pattern": "*",
                },
            ],
            "blocked": BLOCKED,
        },
    ),
    "digitalocean_spaces": ConnectorDefinition(
        key="digitalocean_spaces",
        name="DigitalOcean Spaces",
        tier=1,
        source_type="object_storage",
        family="object_storage",
        status="native",
        description="DigitalOcean Spaces connector using the S3-compatible object API.",
        oss_libraries=("aiobotocore",),
        credential_fields=(
            "bucket",
            "prefix",
            "region_name",
            "endpoint_url",
            "aws_access_key_id_ref",
            "aws_secret_access_key_ref",
        ),
        secret_fields=("aws_access_key_id", "aws_secret_access_key"),
        capabilities=ConnectorCapabilities(False, False, True, True, True, True, False, False),
        role_templates={
            "browser": STORAGE_BROWSER,
            "reader": STORAGE_READER,
            "writer": [
                *STORAGE_READER,
                {
                    "effect": "allow",
                    "action": "storage.object.write",
                    "resource_type": "storage.object",
                    "resource_pattern": "*",
                },
            ],
            "maintainer": [
                *STORAGE_READER,
                {
                    "effect": "allow",
                    "action": "storage.object.delete",
                    "resource_type": "storage.object",
                    "resource_pattern": "*",
                },
            ],
            "blocked": BLOCKED,
        },
    ),
    "snowflake": ConnectorDefinition(
        key="snowflake",
        name="Snowflake",
        tier=1,
        source_type="warehouse",
        family="warehouse",
        status="native",
        description="Snowflake SQL connector using the official Python connector and sqlglot.",
        oss_libraries=("snowflake-connector-python", "sqlglot"),
        credential_fields=(
            "account",
            "user",
            "password",
            "password_ref",
            "private_key",
            "private_key_ref",
            "warehouse",
            "database",
            "schema",
            "role",
            "authenticator",
            "application",
            "collect_query_history",
        ),
        secret_fields=("password", "private_key"),
        capabilities=ConnectorCapabilities(False, True, True, True, False, True, True, True),
        default_cache_strategy="deterministic_first",
        role_templates={
            "analyst": DB_READ,
            "power_analyst": DB_READ,
            "writer": DB_WRITE,
            "warehouse_admin": OWNER,
            "blocked": BLOCKED,
        },
    ),
    "zendesk": ConnectorDefinition(
        key="zendesk",
        name="Zendesk",
        tier=1,
        source_type="saas",
        family="saas",
        status="native",
        description="Zendesk ticket/help-center connector using httpx for runtime and dlt for ingestion acceleration.",
        oss_libraries=("httpx", "dlt"),
        credential_fields=(
            "base_url",
            "subdomain",
            "email",
            "api_token",
            "api_token_ref",
            "brand_id",
            "group_id",
            "organization_id",
            "status",
            "include_users",
            "include_organizations",
            "include_ticket_comments",
            "max_tickets",
            "max_articles",
            "max_users",
            "max_organizations",
        ),
        secret_fields=("api_token",),
        capabilities=ConnectorCapabilities(False, False, True, True, True, False, True, False),
        role_templates={
            "support_reader": [
                {
                    "effect": "allow",
                    "action": "saas.object.describe",
                    "resource_type": "saas.object",
                    "resource_pattern": "*",
                },
                {
                    "effect": "allow",
                    "action": "saas.object.search",
                    "resource_type": "saas.object",
                    "resource_pattern": "zendesk:ticket/*",
                },
                {
                    "effect": "allow",
                    "action": "discovery.search",
                    "resource_type": "discovery.asset",
                    "resource_pattern": "*",
                },
                {
                    "effect": "allow",
                    "action": "discovery.asset.read",
                    "resource_type": "discovery.asset",
                    "resource_pattern": "*",
                },
                {
                    "effect": "allow",
                    "action": "saas.object.read",
                    "resource_type": "saas.object",
                    "resource_pattern": "zendesk:ticket/*",
                },
                {
                    "effect": "allow",
                    "action": "saas.object.read",
                    "resource_type": "saas.object",
                    "resource_pattern": "zendesk:article/*",
                },
            ],
            "support_analyst": [
                {
                    "effect": "allow",
                    "action": "saas.object.describe",
                    "resource_type": "saas.object",
                    "resource_pattern": "*",
                },
                {
                    "effect": "allow",
                    "action": "saas.object.search",
                    "resource_type": "saas.object",
                    "resource_pattern": "zendesk:*/*",
                },
                {
                    "effect": "allow",
                    "action": "discovery.search",
                    "resource_type": "discovery.asset",
                    "resource_pattern": "*",
                },
                {
                    "effect": "allow",
                    "action": "discovery.asset.read",
                    "resource_type": "discovery.asset",
                    "resource_pattern": "*",
                },
                {
                    "effect": "allow",
                    "action": "saas.object.read",
                    "resource_type": "saas.object",
                    "resource_pattern": "zendesk:*/*",
                },
            ],
            "blocked": BLOCKED,
        },
    ),
    "slack": ConnectorDefinition(
        key="slack",
        name="Slack",
        tier=1,
        source_type="saas",
        family="collaboration",
        status="native",
        description="Slack discovery connector using slack-sdk with read-only MVP scope.",
        oss_libraries=("slack-sdk", "dlt"),
        credential_fields=(
            "workspace",
            "bot_token",
            "bot_token_ref",
            "channel_types",
            "include_messages",
            "include_threads",
            "include_files",
            "max_channels",
            "max_messages_per_channel",
            "max_replies_per_thread",
            "max_files",
        ),
        secret_fields=("bot_token",),
        capabilities=ConnectorCapabilities(False, False, True, True, False, False, False, False),
        role_templates={
            "channel_reader": [
                {
                    "effect": "allow",
                    "action": "collab.channel.read",
                    "resource_type": "collab.channel",
                    "resource_pattern": "*",
                },
                {
                    "effect": "allow",
                    "action": "collab.message.read",
                    "resource_type": "collab.message",
                    "resource_pattern": "*",
                },
                {
                    "effect": "allow",
                    "action": "discovery.search",
                    "resource_type": "discovery.asset",
                    "resource_pattern": "*",
                },
                {
                    "effect": "allow",
                    "action": "discovery.asset.read",
                    "resource_type": "discovery.asset",
                    "resource_pattern": "*",
                },
            ],
            "knowledge_reader": COLLAB_READER,
            "compliance_reader": [
                *COLLAB_READER,
                {
                    "effect": "allow",
                    "action": "collab.file.read",
                    "resource_type": "collab.file",
                    "resource_pattern": "*",
                },
            ],
            "workspace_admin": [
                {
                    "effect": "allow",
                    "action": "collab.channel.read",
                    "resource_type": "collab.channel",
                    "resource_pattern": "*",
                },
            ],
            "blocked": BLOCKED,
        },
    ),
    "github": ConnectorDefinition(
        key="github",
        name="GitHub",
        tier=1,
        source_type="saas",
        family="repo",
        status="native",
        description="GitHub/GitHub Enterprise connector using PyGithub and httpx fallbacks.",
        oss_libraries=("PyGithub", "httpx", "dlt"),
        credential_fields=(
            "base_url",
            "org",
            "owner",
            "repo_names",
            "token",
            "token_ref",
            "ref",
            "include_code_paths",
            "max_repos",
            "max_issues_per_repo",
            "max_prs_per_repo",
            "max_releases_per_repo",
            "max_workflows_per_repo",
        ),
        secret_fields=("token",),
        capabilities=ConnectorCapabilities(False, False, True, True, False, False, True, False),
        role_templates={
            "repo_reader": [
                *REPO_READER,
                {
                    "effect": "allow",
                    "action": "discovery.search",
                    "resource_type": "discovery.asset",
                    "resource_pattern": "*",
                },
                {
                    "effect": "allow",
                    "action": "discovery.asset.read",
                    "resource_type": "discovery.asset",
                    "resource_pattern": "*",
                },
            ],
            "code_reader": [
                *CODE_READER,
                {
                    "effect": "allow",
                    "action": "discovery.search",
                    "resource_type": "discovery.asset",
                    "resource_pattern": "*",
                },
                {
                    "effect": "allow",
                    "action": "discovery.asset.read",
                    "resource_type": "discovery.asset",
                    "resource_pattern": "*",
                },
            ],
            "blocked": BLOCKED,
        },
    ),
    "gitlab": ConnectorDefinition(
        key="gitlab",
        name="GitLab",
        tier=1,
        source_type="saas",
        family="repo",
        status="native",
        description="GitLab connector using python-gitlab.",
        oss_libraries=("python-gitlab",),
        credential_fields=(
            "base_url",
            "group",
            "project",
            "token",
            "token_ref",
            "ref",
            "include_code_paths",
            "max_projects",
            "max_issues_per_project",
            "max_mrs_per_project",
            "max_pipelines_per_project",
        ),
        secret_fields=("token",),
        capabilities=ConnectorCapabilities(False, False, True, True, False, False, True, False),
        role_templates={
            "repo_reader": [
                *REPO_READER,
                {
                    "effect": "allow",
                    "action": "discovery.search",
                    "resource_type": "discovery.asset",
                    "resource_pattern": "*",
                },
                {
                    "effect": "allow",
                    "action": "discovery.asset.read",
                    "resource_type": "discovery.asset",
                    "resource_pattern": "*",
                },
            ],
            "code_reader": [
                *CODE_READER,
                {
                    "effect": "allow",
                    "action": "discovery.search",
                    "resource_type": "discovery.asset",
                    "resource_pattern": "*",
                },
                {
                    "effect": "allow",
                    "action": "discovery.asset.read",
                    "resource_type": "discovery.asset",
                    "resource_pattern": "*",
                },
            ],
            "blocked": BLOCKED,
        },
    ),
    "opensearch": ConnectorDefinition(
        key="opensearch",
        name="OpenSearch",
        tier=2,
        source_type="search",
        family="search",
        status="native",
        description="OpenSearch-first search connector.",
        oss_libraries=("opensearch-py",),
        credential_fields=(
            "base_url",
            "username",
            "password_ref",
            "token_ref",
            "indices",
            "max_docs_per_index",
        ),
        secret_fields=("password", "token"),
        capabilities=ConnectorCapabilities(False, True, True, True, False, False, True, False),
        role_templates={
            "query_reader": [
                *SEARCH_READER,
                {
                    "effect": "allow",
                    "action": "discovery.search",
                    "resource_type": "discovery.asset",
                    "resource_pattern": "*",
                },
                {
                    "effect": "allow",
                    "action": "discovery.asset.read",
                    "resource_type": "discovery.asset",
                    "resource_pattern": "*",
                },
            ],
            "blocked": BLOCKED,
        },
    ),
    "elasticsearch": ConnectorDefinition(
        key="elasticsearch",
        name="Elasticsearch",
        tier=2,
        source_type="search",
        family="search",
        status="native",
        description="Elasticsearch-compatible search connector using the OpenSearch REST contract.",
        oss_libraries=("httpx",),
        credential_fields=(
            "base_url",
            "username",
            "password_ref",
            "token_ref",
            "indices",
            "max_docs_per_index",
        ),
        secret_fields=("password", "token"),
        capabilities=ConnectorCapabilities(False, True, True, True, False, False, True, False),
        role_templates={
            "query_reader": [
                *SEARCH_READER,
                {
                    "effect": "allow",
                    "action": "discovery.search",
                    "resource_type": "discovery.asset",
                    "resource_pattern": "*",
                },
                {
                    "effect": "allow",
                    "action": "discovery.asset.read",
                    "resource_type": "discovery.asset",
                    "resource_pattern": "*",
                },
            ],
            "blocked": BLOCKED,
        },
    ),
    "qdrant": ConnectorDefinition(
        key="qdrant",
        name="Qdrant",
        tier=2,
        source_type="search",
        family="search",
        status="native",
        description="Qdrant source connector for collection and point discovery.",
        oss_libraries=("httpx",),
        credential_fields=("base_url", "api_key_ref", "collections", "max_points_per_collection"),
        secret_fields=("api_key",),
        capabilities=ConnectorCapabilities(False, True, True, True, False, False, True, False),
        role_templates={
            "collection_reader": QDRANT_READER,
            "blocked": BLOCKED,
        },
    ),
    "mongodb": ConnectorDefinition(
        key="mongodb",
        name="MongoDB",
        tier=2,
        source_type="database",
        family="database",
        status="planned",
        description="MongoDB connector using PyMongo async APIs.",
        oss_libraries=("pymongo",),
        credential_fields=("connection_string_ref", "database"),
        secret_fields=("connection_string",),
        capabilities=ConnectorCapabilities(False, True, True, True, False, False, True, False),
        role_templates={"read": SAAS_READER, "blocked": BLOCKED},
    ),
    "salesforce": ConnectorDefinition(
        key="salesforce",
        name="Salesforce",
        tier=2,
        source_type="saas",
        family="saas",
        status="native",
        description="Salesforce CRM connector using simple-salesforce.",
        oss_libraries=("simple-salesforce",),
        credential_fields=(
            "instance_url",
            "client_id",
            "client_secret_ref",
            "username",
            "password_ref",
            "security_token_ref",
            "session_id_ref",
            "domain",
            "objects",
            "max_records_per_object",
        ),
        secret_fields=("client_secret", "password", "security_token", "session_id"),
        capabilities=ConnectorCapabilities(False, True, True, True, False, False, True, False),
        role_templates={
            "object_reader": [
                {
                    "effect": "allow",
                    "action": "saas.object.describe",
                    "resource_type": "saas.object",
                    "resource_pattern": "salesforce:*/*",
                },
                {
                    "effect": "allow",
                    "action": "saas.object.read",
                    "resource_type": "saas.object",
                    "resource_pattern": "salesforce:*/*",
                },
                {
                    "effect": "allow",
                    "action": "saas.object.search",
                    "resource_type": "saas.object",
                    "resource_pattern": "salesforce:*/*",
                },
                {
                    "effect": "allow",
                    "action": "discovery.search",
                    "resource_type": "discovery.asset",
                    "resource_pattern": "*",
                },
                {
                    "effect": "allow",
                    "action": "discovery.asset.read",
                    "resource_type": "discovery.asset",
                    "resource_pattern": "*",
                },
            ],
            "analyst": SAAS_READER,
            "blocked": BLOCKED,
        },
    ),
    "notion": ConnectorDefinition(
        key="notion",
        name="Notion",
        tier=2,
        source_type="saas",
        family="saas",
        status="native",
        description="Notion workspace/page/database connector using the official REST API.",
        oss_libraries=("httpx",),
        credential_fields=(
            "base_url",
            "workspace",
            "token_ref",
            "integration_token_ref",
            "notion_version",
            "max_results",
        ),
        secret_fields=("token", "integration_token"),
        capabilities=ConnectorCapabilities(False, False, True, True, False, False, True, False),
        role_templates={
            "workspace_reader": [
                {
                    "effect": "allow",
                    "action": "saas.object.describe",
                    "resource_type": "saas.object",
                    "resource_pattern": "notion:*/*",
                },
                {
                    "effect": "allow",
                    "action": "saas.object.search",
                    "resource_type": "saas.object",
                    "resource_pattern": "notion:*/*",
                },
                {
                    "effect": "allow",
                    "action": "saas.object.read",
                    "resource_type": "saas.object",
                    "resource_pattern": "notion:*/*",
                },
                {
                    "effect": "allow",
                    "action": "discovery.search",
                    "resource_type": "discovery.asset",
                    "resource_pattern": "*",
                },
                {
                    "effect": "allow",
                    "action": "discovery.asset.read",
                    "resource_type": "discovery.asset",
                    "resource_pattern": "*",
                },
            ],
            "database_reader": [
                {
                    "effect": "allow",
                    "action": "saas.object.read",
                    "resource_type": "saas.object",
                    "resource_pattern": "notion:database/*",
                },
                {
                    "effect": "allow",
                    "action": "saas.object.search",
                    "resource_type": "saas.object",
                    "resource_pattern": "notion:database/*",
                },
                {
                    "effect": "allow",
                    "action": "discovery.search",
                    "resource_type": "discovery.asset",
                    "resource_pattern": "*",
                },
                {
                    "effect": "allow",
                    "action": "discovery.asset.read",
                    "resource_type": "discovery.asset",
                    "resource_pattern": "*",
                },
            ],
            "page_reader": [
                {
                    "effect": "allow",
                    "action": "saas.object.read",
                    "resource_type": "saas.object",
                    "resource_pattern": "notion:page/*",
                },
                {
                    "effect": "allow",
                    "action": "discovery.search",
                    "resource_type": "discovery.asset",
                    "resource_pattern": "*",
                },
                {
                    "effect": "allow",
                    "action": "discovery.asset.read",
                    "resource_type": "discovery.asset",
                    "resource_pattern": "*",
                },
            ],
            "blocked": BLOCKED,
        },
    ),
    "atlassian": ConnectorDefinition(
        key="atlassian",
        name="Atlassian Confluence / Jira",
        tier=2,
        source_type="saas",
        family="saas",
        status="planned",
        description="Confluence and Jira connector using atlassian-python-api.",
        oss_libraries=("atlassian-python-api",),
        credential_fields=("base_url", "email", "api_token_ref"),
        secret_fields=("api_token",),
        capabilities=ConnectorCapabilities(False, False, True, True, False, False, True, False),
        role_templates={
            "reader": SAAS_READER,
            "blocked": BLOCKED,
        },
    ),
    "google_workspace": ConnectorDefinition(
        key="google_workspace",
        name="Google Drive / Workspace",
        tier=2,
        source_type="saas",
        family="workspace",
        status="native",
        description="Google Workspace hybrid connector using the gws CLI for governed read/discovery paths.",
        oss_libraries=("@googleworkspace/cli", "google-api-python-client"),
        credential_fields=(
            "workspace_domain",
            "enabled_services",
            "access_token_ref",
            "credentials_file_ref",
            "service_account_json_ref",
            "gws_config_dir",
            "project_id",
            "subject_user",
            "drive_id",
            "drive_query",
            "gmail_users",
            "gmail_labels",
            "gmail_query",
            "calendar_ids",
            "calendar_time_min",
            "calendar_time_max",
            "admin_report_applications",
        ),
        secret_fields=("access_token", "credentials_file", "service_account_json"),
        capabilities=ConnectorCapabilities(False, False, True, True, False, False, True, False),
        role_templates={
            "workspace_reader": WORKSPACE_DRIVE_READER,
            "workspace_knowledge_reader": WORKSPACE_DRIVE_READER,
            "drive_reader": WORKSPACE_DRIVE_READER,
            "gmail_reader": WORKSPACE_GMAIL_READER,
            "calendar_reader": WORKSPACE_CALENDAR_READER,
            "admin_auditor": WORKSPACE_ADMIN_AUDITOR,
            "blocked": BLOCKED,
        },
    ),
    "bigquery": ConnectorDefinition(
        key="bigquery",
        name="Google BigQuery",
        tier=2,
        source_type="warehouse",
        family="warehouse",
        status="planned",
        description="BigQuery connector using google-cloud-bigquery and sqlglot.",
        oss_libraries=("google-cloud-bigquery", "sqlglot"),
        credential_fields=("project", "service_account_json_ref", "location"),
        secret_fields=("service_account_json",),
        capabilities=ConnectorCapabilities(False, True, True, True, False, False, True, True),
        role_templates={"analyst": DB_READ, "blocked": BLOCKED},
    ),
    "servicenow": ConnectorDefinition(
        key="servicenow",
        name="ServiceNow",
        tier=2,
        source_type="saas",
        family="saas",
        status="planned",
        description="ServiceNow Table/Knowledge API connector using httpx.",
        oss_libraries=("httpx",),
        credential_fields=("instance_url", "username", "password_ref"),
        secret_fields=("password",),
        capabilities=ConnectorCapabilities(False, False, True, True, False, False, True, False),
        role_templates={
            "reader": SAAS_READER,
            "blocked": BLOCKED,
        },
    ),
    "fabric_sql": ConnectorDefinition(
        key="fabric_sql",
        name="Microsoft Fabric SQL",
        tier=1,
        source_type="database",
        family="database",
        status="beta",
        description="Fabric Warehouse, Lakehouse SQL analytics, and SQL Database via saved Entra identity.",
        oss_libraries=("msal", "pyodbc", "sqlglot"),
        credential_fields=(
            "host",
            "database",
            "tenant_id",
            "client_id",
            "endpoint_type",
            "auth_mode",
            "client_secret_ref",
            "port",
            "connect_timeout_seconds",
            "statement_timeout_seconds",
            "max_rows",
            "max_bytes",
            "allow_private_egress",
        ),
        secret_fields=("client_secret_ref",),
        capabilities=ConnectorCapabilities(
            supports_query=True,
            supports_discovery=True,
            supports_write=True,
            supports_field_permissions=True,
        ),
        default_cache_strategy="deterministic_first",
        role_templates={"reader": DB_READ, "writer": DB_WRITE, "owner": OWNER, "blocked": BLOCKED},
    ),
    "mssql": ConnectorDefinition(
        key="mssql",
        name="Microsoft SQL Server",
        tier=2,
        source_type="database",
        family="database",
        status="planned",
        description="SQL Server connector using pyodbc and sqlglot TSQL parsing.",
        oss_libraries=("pyodbc", "sqlglot"),
        credential_fields=("host", "port", "database", "user", "password_ref", "driver"),
        secret_fields=("password",),
        capabilities=ConnectorCapabilities(False, True, True, True, False, False, True, False),
        default_cache_strategy="deterministic_first",
        role_templates={
            "read": DB_READ,
            "blocked": BLOCKED,
        },
    ),
    "generic_rest": ConnectorDefinition(
        key="generic_rest",
        name="HTTP / REST",
        tier=0,
        source_type="http",
        family="http",
        status="production",
        description="Generic governed REST proxy.",
        oss_libraries=("httpx",),
        credential_fields=("base_url", "auth_header", "token_ref", "probe_path"),
        secret_fields=("token",),
        capabilities=ConnectorCapabilities(True, False, False, False, False, True, False, False),
        role_templates={
            "read": [
                {
                    "effect": "allow",
                    "action": "http.get",
                    "resource_type": "http.path",
                    "resource_pattern": "/*",
                },
                {
                    "effect": "allow",
                    "action": "http.head",
                    "resource_type": "http.path",
                    "resource_pattern": "/*",
                },
            ],
            "write": [
                {
                    "effect": "allow",
                    "action": "http.post",
                    "resource_type": "http.path",
                    "resource_pattern": "/*",
                },
                {
                    "effect": "allow",
                    "action": "http.put",
                    "resource_type": "http.path",
                    "resource_pattern": "/*",
                },
                {
                    "effect": "allow",
                    "action": "http.patch",
                    "resource_type": "http.path",
                    "resource_pattern": "/*",
                },
            ],
            "owner": OWNER,
            "blocked": BLOCKED,
        },
    ),
}

CONNECTOR_DEFINITIONS["mariadb"] = ConnectorDefinition(
    **{
        **CONNECTOR_DEFINITIONS["mysql"].model_dump(),
        "key": "mariadb",
        "name": "MariaDB",
        "description": "MariaDB-compatible connector using the MySQL adapter.",
        "capabilities": CONNECTOR_DEFINITIONS["mysql"].capabilities,
        "oss_libraries": CONNECTOR_DEFINITIONS["mysql"].oss_libraries,
        "credential_fields": CONNECTOR_DEFINITIONS["mysql"].credential_fields,
        "secret_fields": CONNECTOR_DEFINITIONS["mysql"].secret_fields,
        "role_templates": CONNECTOR_DEFINITIONS["mysql"].role_templates,
    }
)

_ADAPTER_FACTORIES: dict[str, Any] = {
    "generic_rest": HTTPProbeAdapter,
    "mysql": MySQLAdapter,
    "mariadb": MySQLAdapter,
    "s3": S3ConnectorAdapter,
    "digitalocean_spaces": DigitalOceanSpacesAdapter,
    "snowflake": SnowflakeAdapter,
    "zendesk": ZendeskAdapter,
    "slack": SlackAdapter,
    "github": GitHubAdapter,
    "gitlab": GitLabAdapter,
    "opensearch": OpenSearchAdapter,
    "elasticsearch": OpenSearchAdapter,
    "qdrant": QdrantSourceAdapter,
    "mongodb": (SDKPresenceAdapter, {"import_name": "pymongo", "required_fields": ("database",)}),
    "salesforce": SalesforceAdapter,
    "notion": NotionAdapter,
    "atlassian": (SDKPresenceAdapter, {"required_fields": ("base_url",)}),
    "google_workspace": GoogleWorkspaceAdapter,
    "bigquery": (
        SDKPresenceAdapter,
        {"import_name": "google.cloud.bigquery", "required_fields": ("project",)},
    ),
    "servicenow": (SDKPresenceAdapter, {"required_fields": ("instance_url",)}),
    "mssql": (SDKPresenceAdapter, {"import_name": "pyodbc", "required_fields": ("host",)}),
}
