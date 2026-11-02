"""The connector support matrix agrees with the connector registry.

The matrix is hand-written because it carries judgement (what was certified,
how). What it may not do is drift from the registry: a stable connector listed
as beta, a planned one missing, or a connector whose governance is unexercised
presented without saying so. A GitHub row once claimed proof the test stacks
never provided; this is the mechanical guard against that class of claim.
"""

from __future__ import annotations

from interlock.connections.activation import STABLE_CONNECTOR_KEYS
from interlock.connections.connectors import CONNECTOR_DEFINITIONS
from interlock.feature_status import GOVERNANCE_UNVERIFIED_CONNECTORS
from tests.unit.docs_site import body

# How the matrix names each connector. A new connector must be added here, and
# to the matrix, before this test passes.
MATRIX_LABEL = {
    "fabric_sql": "Microsoft Fabric SQL",
    "postgresql": "PostgreSQL",
    "mysql": "MySQL/MariaDB",
    "mariadb": "MySQL/MariaDB",
    "generic_rest": "HTTP",
    "s3": "Amazon S3",
    "digitalocean_spaces": "DigitalOcean Spaces",
    "slack": "Slack",
    "github": "GitHub",
    "gitlab": "GitLab",
    "snowflake": "Snowflake",
    "zendesk": "Zendesk",
    "opensearch": "OpenSearch",
    "elasticsearch": "Elasticsearch",
    "qdrant": "Qdrant",
    "salesforce": "Salesforce",
    "notion": "Notion",
    "google_workspace": "Google Workspace",
}


def _section(text: str, heading: str) -> str:
    return text.split(heading, 1)[1].split("\n## ", 1)[0]


def _table_labels(section: str) -> set[str]:
    return {
        line.split("|")[1].strip()
        for line in section.splitlines()
        if line.startswith("| ") and not line.startswith("| Connector") and "---" not in line
    }


def test_every_available_connector_has_a_matrix_label() -> None:
    available = {k for k, d in CONNECTOR_DEFINITIONS.items() if d.status != "planned"}
    assert available == set(MATRIX_LABEL), sorted(available ^ set(MATRIX_LABEL))


def test_stable_and_beta_connectors_sit_in_the_right_table() -> None:
    text = body("/reference/connector-support-matrix/")
    stable = _table_labels(_section(text, "## Stable V1 Sources"))
    beta = _table_labels(_section(text, "## Beta V1 Connectors"))
    for key, label in MATRIX_LABEL.items():
        if key in STABLE_CONNECTOR_KEYS:
            assert label in stable, f"{key} is stable in code but not in the stable table"
        else:
            assert label in beta, f"{key} is beta in code but not in the beta table"


def test_planned_connectors_are_listed_as_deferred() -> None:
    deferred = _section(
        body("/reference/connector-support-matrix/"), "## Deferred Connector Features"
    )
    for key, definition in CONNECTOR_DEFINITIONS.items():
        if definition.status == "planned":
            assert f"`{key}`" in deferred, f"planned connector {key} is not listed as deferred"


def test_connectors_with_unexercised_governance_are_named_as_such() -> None:
    text = " ".join(body("/reference/connector-support-matrix/").split())
    paragraph = text.split("not yet held to that last requirement", 1)[1].split("**S3", 1)[0]
    for key in GOVERNANCE_UNVERIFIED_CONNECTORS:
        assert MATRIX_LABEL[key] in paragraph, f"{key} is not named as governance-unverified"
