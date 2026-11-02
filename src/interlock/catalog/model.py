"""Value types shared by collectors, the store and the scan runner."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from interlock.connections.fabric.credentials import FabricCurrentSource

# Node types a collector may emit. Kept in step with the CHECK constraint on
# `source_catalog.node_type` in migrations/016_source_catalog.sql.
NODE_TYPES = frozenset(
    {
        "source",
        "database",
        "schema",
        "table",
        "view",
        "materialized_view",
        "foreign_table",
        "column",
        "bucket",
        "prefix",
        "channel",
        "repository",
        "object",
        "field",
        "index",
        "collection",
    }
)

TABLE_LIKE_NODE_TYPES = frozenset({"table", "view", "materialized_view", "foreign_table"})


@dataclass(frozen=True, slots=True)
class CatalogNode:
    """One structural element of a source.

    `path` is the node's identity, in native case, from the source root - an
    array because identifiers and S3 keys can themselves contain dots.
    `resource_key` is the string enforcement matches patterns against, which
    for SQL is a dotted form such as `sales.customers.email`. Fabric preserves
    native spelling; other SQL collectors retain their lower-case convention.
    """

    node_type: str
    path: tuple[str, ...]
    name: str
    resource_key: str
    ordinal: int | None = None
    data_type: str | None = None
    heuristic_class: str | None = None
    attributes: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.node_type not in NODE_TYPES:
            raise ValueError(f"unknown catalog node type: {self.node_type}")

    @property
    def parent_path(self) -> tuple[str, ...]:
        return self.path[:-1]

    @property
    def depth(self) -> int:
        return len(self.path)

    @property
    def attributes_hash(self) -> str:
        """Digest of everything a rescan should call a change."""
        material = json.dumps(
            {
                "data_type": self.data_type,
                "ordinal": self.ordinal,
                "attributes": self.attributes,
            },
            sort_keys=True,
            default=str,
        )
        return hashlib.sha256(material.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class ScanLimits:
    """Hard caps that bound one scan. Hitting any of them sets `truncated`."""

    max_nodes: int = 250_000
    max_schemas: int = 500
    max_tables: int = 20_000
    max_columns_per_table: int = 2_000


@dataclass(slots=True)
class CatalogSnapshot:
    """Everything one scan saw.

    `complete_subtrees` lists the paths a collector enumerated without hitting
    a cap. The store only marks a node removed when it falls under one of them,
    so a truncated scan retains unseen nodes within the same upstream identity.
    An identity change makes old unseen inventory non-current even during a
    partial scan. A completed scan reports `[()]` - the whole source.
    """

    nodes: list[CatalogNode] = field(default_factory=list)
    source_attributes: dict[str, Any] = field(default_factory=dict)
    truncated: bool = False
    truncation: dict[str, Any] = field(default_factory=dict)
    complete_subtrees: list[tuple[str, ...]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    publication_context: FabricCurrentSource | None = field(default=None, repr=False)

    def is_complete_under(self, path: tuple[str, ...]) -> bool:
        return any(path[: len(subtree)] == subtree for subtree in self.complete_subtrees)


def sql_resource_key(*parts: str) -> str:
    """The dotted, lower-cased form SQL enforcement matches against."""
    return ".".join(part.lower() for part in parts)


# Column-name fragments that suggest personal data. A hint for review, never a
# classification: the wizard pre-ticks these, and the console marks them
# "likely PII" until an admin decides.
PII_NAME_HINTS: tuple[str, ...] = (
    "ssn",
    "social_security",
    "email",
    "phone",
    "mobile",
    "credit_card",
    "card_number",
    "cvv",
    "passport",
    "drivers_license",
    "dob",
    "date_of_birth",
    "first_name",
    "last_name",
    "full_name",
    "address",
    "street",
    "zip",
    "postcode",
    "mrn",
)


def looks_like_pii(name: str) -> bool:
    lowered = name.lower()
    return any(hint in lowered for hint in PII_NAME_HINTS)
