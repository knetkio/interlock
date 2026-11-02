"""Fabric's deliberately narrow, single-statement T-SQL execution boundary."""

from __future__ import annotations

import asyncio
import time
from typing import TYPE_CHECKING, Any

import sqlglot
from pydantic import ValidationError
from sqlglot import exp
from sqlglot.errors import SqlglotError

from interlock.connections.connectors import BaseConnectorAdapter, ConnectorDefinition, _health
from interlock.connections.fabric.config import FabricConfig
from interlock.core.source_roles import build_permission_request
from interlock.core.sql_governance import naming_for
from interlock.models import HealthStatus, PermissionRequest

if TYPE_CHECKING:
    from interlock.connections.fabric.runtime import FabricServices


class FabricSQLAdapter(BaseConnectorAdapter):
    def __init__(
        self,
        definition: ConnectorDefinition,
        *,
        fabric_services: FabricServices | None = None,
        source_id: str | None = None,
    ) -> None:
        super().__init__(definition)
        self.services = fabric_services
        self.source_id = source_id

    def _runtime(self) -> FabricServices:
        if not self.source_id:
            raise RuntimeError("Save the Fabric source before connecting or testing it")
        if self.services is None:
            raise RuntimeError("Fabric authentication services are unavailable")
        return self.services

    def validate_sql(self, query: str, *, database: str | None = None) -> exp.Expression:
        try:
            statements = [s for s in sqlglot.parse(query, read="tsql") if s is not None]
        except SqlglotError:
            raise ValueError("Unsupported Fabric SQL statement") from None
        if len(statements) != 1 or not isinstance(
            statements[0],
            (exp.Select, exp.Union, exp.Intersect, exp.Except, exp.Insert, exp.Update, exp.Delete),
        ):
            raise ValueError("Fabric supports one SELECT, INSERT, UPDATE, or DELETE statement")
        statement = statements[0]
        if statement.find(exp.Returning) is not None:
            raise ValueError(
                "Fabric OUTPUT is unsupported until returned columns have separate read authorization"
            )
        if any(
            statement.find_all(
                exp.Into,
                exp.Command,
                exp.Merge,
                exp.Create,
                exp.Drop,
                exp.Alter,
                exp.Lock,
                exp.NextValueFor,
            )
        ):
            raise ValueError("Unsupported Fabric SQL operation")
        if any(
            node is not statement for node in statement.find_all(exp.Insert, exp.Update, exp.Delete)
        ):
            raise ValueError("Nested Fabric DML is unsupported")
        for table in statement.find_all(exp.Table):
            # Do not stringify ambiguous identifiers into a permission resource.
            parts = table.parts
            if len(parts) > 3 or any(
                not isinstance(p, exp.Identifier)
                or not p.name
                or p.name != p.name.strip()
                or any(c in p.name for c in ".*?[]")
                for p in parts
            ):
                raise ValueError("Unsupported or ambiguous Fabric table scope")
            if table.catalog:
                if not table.db or database is None or table.catalog != database:
                    raise ValueError("Cross-database or unresolved Fabric table scope")
                table.set("catalog", None)
        # OPENROWSET/OPENQUERY/TVFs are not necessarily represented as ordinary
        # Tables; only named tables, joins, subqueries and CTEs are supported.
        for node in statement.walk():
            if isinstance(node, exp.Dot) and isinstance(node.expression, exp.Func):
                raise ValueError("Fabric user-defined functions have unsupported table scope")
            if isinstance(node, (exp.From, exp.Join)):
                relation = node.this
                if not isinstance(relation, (exp.Table, exp.Subquery)):
                    raise ValueError("Unsupported Fabric table function")
        return statement

    def _permission(
        self,
        statement: exp.Expression,
        *,
        source_id: str,
        identity_id: int | None,
        metadata: dict[str, Any],
    ) -> PermissionRequest:
        ctes = {c.alias for c in statement.find_all(exp.CTE)}
        tables = sorted(
            {
                ".".join(p.name for p in t.parts)
                for t in statement.find_all(exp.Table)
                if t.db or t.name not in ctes
            }
        )
        columns = sorted({c.name for c in statement.find_all(exp.Column) if c.name})
        return build_permission_request(
            protocol="fabric_sql",
            source_id=source_id,
            identity_id=identity_id,
            operation="SELECT" if isinstance(statement, exp.Query) else statement.key.upper(),
            tables=tables,
            columns=columns,
            metadata=metadata,
            naming=naming_for("fabric_sql"),
        )

    def build_permission_request(
        self,
        *,
        source_id: str,
        identity_id: int | None,
        operation: str,
        metadata: dict[str, Any] | None = None,
    ) -> PermissionRequest:
        metadata = metadata or {}
        query = str(metadata.get("query") or metadata.get("sql") or "")
        statement = self.validate_sql(query)
        return self._permission(
            statement, source_id=source_id, identity_id=identity_id, metadata=metadata
        )

    async def _execute(self, request: dict[str, Any], *, write: bool) -> dict[str, Any]:
        try:
            config = FabricConfig.from_mapping(request.get("connection_config") or {})
        except ValidationError:
            raise ValueError("invalid Fabric SQL connection configuration") from None
        query = str(request.get("query") or request.get("sql") or "")
        statement = self.validate_sql(query, database=config.database)
        is_write = isinstance(statement, (exp.Insert, exp.Update, exp.Delete))
        if is_write != write:
            raise ValueError("Fabric statement does not match the requested read/write operation")
        if write and config.endpoint_type == "lakehouse_sql":
            raise ValueError("Lakehouse SQL analytics endpoints do not support table DML")
        services = self._runtime()
        if request.get("source_id") not in (None, self.source_id):
            raise ValueError("Fabric request source does not match its saved identity")
        parameters = request.get("parameters") or ()
        if not isinstance(parameters, (tuple, list)):
            raise ValueError("Fabric SQL parameters must be an ordered sequence")
        permission = self._permission(
            statement,
            source_id=self.source_id or "",
            identity_id=request.get("identity_id"),
            metadata={},
        )
        token = await services.auth.acquire(self.source_id or "", config)
        # The SQL itself stays untouched. Normalized names are exclusively for
        # enforcement; the one transport owner measures the entire envelope.
        return await services.transport.execute(
            config,
            token,
            query,
            tuple(parameters),
            write=write,
            permission_request=permission.model_dump(),
        )

    async def execute_read(self, request: dict[str, Any]) -> dict[str, Any]:
        return await self._execute(request, write=False)

    async def execute_write(self, request: dict[str, Any]) -> dict[str, Any]:
        return await self._execute(request, write=True)

    async def probe(
        self, connection_config: dict[str, Any], *, timeout_seconds: float = 5.0
    ) -> HealthStatus:
        start = time.monotonic()
        try:
            self._runtime()
            async with asyncio.timeout(timeout_seconds):
                await self.execute_read(
                    {"connection_config": connection_config, "query": "SELECT 1"}
                )
            return _health(
                self.source_id or "<unsaved>", True, (time.monotonic() - start) * 1000, None
            )
        except Exception as exc:
            return _health(
                self.source_id or "<unsaved>", False, (time.monotonic() - start) * 1000, str(exc)
            )

    async def metadata_snapshot(self) -> dict[str, Any]:
        # Task 6 owns the system-catalog query and coherent snapshot contract.
        self._runtime()
        raise NotImplementedError("Fabric metadata collection is not available yet")

    async def introspect(self, connection_config: dict[str, Any]) -> dict[str, Any]:
        self._runtime()
        return await self.metadata_snapshot()
