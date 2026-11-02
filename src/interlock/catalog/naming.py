"""The catalog's answer to "which table does this name mean", for the hot path.

Governance resolves every SQL table reference per request, so this keeps each
source's naming - search path, default schema, known tables - in memory. An
entry lives `ttl_seconds` and is dropped early when a worker finishes a scan of
that source (`interlock_catalog_changed`). If the control database cannot be
read, a source falls back to naming from its configuration alone: governance
degrades to the pre-catalog behaviour rather than failing every query.
"""

from __future__ import annotations

import logging
import time
from typing import Any

from interlock.catalog.model import TABLE_LIKE_NODE_TYPES
from interlock.catalog.runner import CATALOG_CHANGED_CHANNEL
from interlock.core.sql_governance import SqlNaming, naming_for

logger = logging.getLogger(__name__)

SQL_CONNECTOR_KEYS = frozenset(
    {"postgresql", "postgres", "mysql", "mariadb", "snowflake", "fabric_sql"}
)

_ROOT_SQL = """
SELECT attributes FROM source_catalog
WHERE source_id = $1 AND node_type = 'source' AND removed_at IS NULL
"""

_COLUMNS_SQL = """
SELECT parent_path, name FROM source_catalog
WHERE source_id = $1 AND node_type = 'column' AND removed_at IS NULL
ORDER BY parent_path, ordinal NULLS LAST, name
"""

_TABLES_SQL = """
SELECT path FROM source_catalog
WHERE source_id = $1 AND node_type = ANY($2::text[]) AND removed_at IS NULL
"""


def _attributes(value: Any) -> dict[str, Any]:
    if isinstance(value, str):
        import json

        try:
            value = json.loads(value or "{}")
        except ValueError:
            return {}
    return value if isinstance(value, dict) else {}


class CatalogNamingResolver:
    """Per-source SQL naming, from the registry and the source catalog."""

    def __init__(self, pool: Any, registry: Any, *, ttl_seconds: float = 60.0) -> None:
        self._pool = pool
        self._registry = registry
        self._ttl = ttl_seconds
        self._cache: dict[str, tuple[float, SqlNaming]] = {}
        self._listener_conn: Any = None

    async def naming_for_source(self, source_id: str) -> SqlNaming | None:
        """The source's naming, or None for a source that does not speak SQL."""
        source = self._registry.get(source_id) if self._registry is not None else None
        if source is None:
            return None
        connector_key = str(getattr(source, "connector_key", "") or "").lower()
        if connector_key not in SQL_CONNECTOR_KEYS:
            return None
        cached = self._cache.get(source_id)
        now = time.monotonic()
        if cached is not None and now - cached[0] < self._ttl:
            return cached[1]
        config = dict(getattr(source, "connection_config", {}) or {})
        try:
            naming = await self._load(source_id, connector_key, config)
        except Exception:
            logger.warning(
                "Could not read the catalog for %s; resolving names from its configuration",
                source_id,
                exc_info=True,
            )
            # Not cached: the next request tries the catalog again.
            return naming_for(connector_key, config)
        self._cache[source_id] = (now, naming)
        return naming

    async def _load(self, source_id: str, connector_key: str, config: dict[str, Any]) -> SqlNaming:
        root = await self._pool.fetchval(_ROOT_SQL, source_id)
        if root is None:
            return naming_for(connector_key, config)
        rows = await self._pool.fetch(_TABLES_SQL, source_id, sorted(TABLE_LIKE_NODE_TYPES))
        normalize = str if connector_key == "fabric_sql" else lambda value: str(value).lower()
        known = frozenset(
            (normalize(row["path"][-2]), normalize(row["path"][-1]))
            for row in rows
            if len(row["path"]) >= 2
        )
        columns: dict[tuple[str, str], list[str]] = {}
        for row in await self._pool.fetch(_COLUMNS_SQL, source_id):
            parent = row["parent_path"]
            if len(parent) >= 2:
                key = (normalize(parent[-2]), normalize(parent[-1]))
                columns.setdefault(key, []).append(normalize(row["name"]))
        return naming_for(
            connector_key,
            config,
            _attributes(root),
            known,
            {key: tuple(names) for key, names in columns.items()},
        )

    def invalidate(self, source_id: str | None = None) -> None:
        if source_id is None:
            self._cache.clear()
        else:
            self._cache.pop(source_id, None)

    async def setup_listener(self) -> None:
        """Drop a source's entry as soon as a scan of it finishes."""
        self._listener_conn = await self._pool.acquire()
        await self._listener_conn.add_listener(CATALOG_CHANGED_CHANNEL, self._on_notify)

    def _on_notify(self, connection: Any, pid: int, channel: str, payload: str) -> None:
        self.invalidate(payload or None)

    async def close(self) -> None:
        if self._listener_conn is None:
            return
        try:
            await self._listener_conn.remove_listener(CATALOG_CHANGED_CHANNEL, self._on_notify)
        finally:
            await self._pool.release(self._listener_conn)
            self._listener_conn = None
