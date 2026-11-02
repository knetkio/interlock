import pytest
from pydantic import ValidationError

from interlock.connections.fabric.config import FabricConfig
from interlock.connections.source_config import SourceConfigValidationError, validate_source_config

BASE = dict(
    host="example.datawarehouse.fabric.microsoft.com",
    database="sales",
    tenant_id="tenant",
    client_id="client",
    endpoint_type="warehouse",
    auth_mode="oauth",
)


def test_defaults_are_bounded_and_verified():
    cfg = FabricConfig.from_mapping(BASE)
    assert (cfg.port, cfg.connect_timeout_seconds, cfg.statement_timeout_seconds) == (1433, 15, 30)
    assert (cfg.max_rows, cfg.max_bytes) == (1000, 8388608)


@pytest.mark.parametrize(
    "field", ["host", "database", "tenant_id", "client_id", "endpoint_type", "auth_mode"]
)
def test_missing_required_field_is_rejected(field):
    with pytest.raises(ValidationError):
        FabricConfig.from_mapping({k: v for k, v in BASE.items() if k != field})


@pytest.mark.parametrize("endpoint", ["warehouse", "lakehouse_sql", "sql_database"])
@pytest.mark.parametrize("auth", ["oauth", "spn"])
def test_supported_endpoint_and_auth_combinations(endpoint, auth):
    cfg = FabricConfig.from_mapping(
        BASE | dict(endpoint_type=endpoint, auth_mode=auth, client_secret_ref="env://FABRIC_SPN")
    )
    assert cfg.endpoint_type == endpoint and cfg.auth_mode == auth


@pytest.mark.parametrize(
    "extra",
    [
        {"endpoint_type": "postgres"},
        {"auth_mode": "default"},
        {"auth_mode": "spn"},
        {"client_secret_ref": "literal-secret"},
        {"password": "secret"},
        {"token": "bearer"},
        {"dsn": "x"},
        {"connection_string": "x"},
        {"driver": "x"},
        {"authentication": "x"},
        {"ssl": False},
        {"ssl_verify": False},
        {"trust_server_certificate": True},
        {"encrypt": False},
        {"host": "host;UID=bad"},
        {"host": "https://host"},
        {"host": "host,1433"},
        {"host": "host\\instance"},
        {"host": "host\n"},
        {"database": "db;PWD=bad"},
        {"port": 0},
        {"connect_timeout_seconds": 0},
        {"statement_timeout_seconds": 0},
        {"max_rows": 0},
        {"max_bytes": 0},
        {"max_bytes": 268435457},
    ],
)
def test_unsafe_config_is_rejected_even_by_generic_validator(extra):
    with pytest.raises(ValidationError):
        FabricConfig.from_mapping(BASE | extra)
    with pytest.raises(SourceConfigValidationError):
        validate_source_config(BASE | extra, connector_key="fabric_sql")


@pytest.mark.parametrize("field", ["tenant_id", "client_id"])
@pytest.mark.parametrize("value", ["tenant?query", "tenant#fragment", "tenant%2Fpath"])
def test_auth_identifiers_cannot_change_authority_url(field, value):
    with pytest.raises(ValidationError):
        FabricConfig.from_mapping(BASE | {field: value})


def test_operator_key_settings_accept_only_secret_references():
    from interlock.config import FabricSettings

    with pytest.raises(ValidationError):
        FabricSettings(active_key_version="v1", key_refs={"v1": "literal"})
    with pytest.raises(ValidationError):
        FabricSettings(active_key_version="v2", key_refs={"v1": "env://FABRIC_KEY"})
    assert (
        FabricSettings(
            active_key_version="v1", key_refs={"v1": "env://FABRIC_KEY"}
        ).active_key_version
        == "v1"
    )


@pytest.mark.parametrize("tenant", ["common", "organizations", "consumers", "COMMON"])
def test_tenant_must_not_select_a_global_account_authority(tenant):
    with pytest.raises(ValidationError):
        FabricConfig.from_mapping(BASE | {"tenant_id": tenant})
