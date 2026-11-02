"""Collectors, one per connector, keyed by connector key.

A collector turns one source's live structure into a `CatalogSnapshot`. It
never reads row data, runs read-only, respects `ScanLimits`, and resolves
credentials and TLS through the same code the gateway uses - it never handles
a secret itself.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from interlock.catalog.model import CatalogSnapshot, ScanLimits
from interlock.connections.connectors import connector_key_for

if TYPE_CHECKING:
    from interlock.connections.fabric.runtime import FabricServices


@dataclass(frozen=True, slots=True)
class CollectContext:
    """What a collector gets to work with."""

    source_id: str
    connector_key: str
    connection_config: dict[str, Any]
    limits: ScanLimits
    conn_manager: Any = None
    fabric_services: FabricServices | None = None


Collector = Callable[[CollectContext], Awaitable[CatalogSnapshot]]


def _registry() -> dict[str, Collector]:
    # Imported lazily so that importing the catalog package does not pull in
    # every driver.
    from interlock.catalog.collectors.fabric import collect_fabric
    from interlock.catalog.collectors.mysql import collect_mysql
    from interlock.catalog.collectors.postgres import collect_postgres
    from interlock.catalog.collectors.services import (
        collect_github,
        collect_qdrant,
        collect_s3,
        collect_salesforce,
        collect_search,
        collect_slack,
    )
    from interlock.catalog.collectors.snowflake import collect_snowflake

    return {
        "fabric_sql": collect_fabric,
        "postgresql": collect_postgres,
        "mysql": collect_mysql,
        "mariadb": collect_mysql,
        "snowflake": collect_snowflake,
        "s3": collect_s3,
        "digitalocean_spaces": collect_s3,
        "slack": collect_slack,
        "github": collect_github,
        "salesforce": collect_salesforce,
        "opensearch": collect_search,
        "elasticsearch": collect_search,
        "qdrant": collect_qdrant,
    }


# Connectors whose catalogued structure the gateway enforces on agent paths.
# Everything else a collector records is inventory: visible to the admin and to
# role authors, but not yet a boundary an agent request is checked against.
ENFORCED_CONNECTOR_KEYS = frozenset({"postgresql", "mysql", "mariadb", "snowflake", "fabric_sql"})


def is_enforced(connector_key: str) -> bool:
    return connector_key_for(connector_key) in ENFORCED_CONNECTOR_KEYS


def collector_for(connector_key: str) -> Collector | None:
    return _registry().get(connector_key_for(connector_key))


def has_collector(connector_key: str) -> bool:
    return connector_key_for(connector_key) in _registry()


def collector_keys() -> frozenset[str]:
    return frozenset(_registry())
