from pathlib import Path

from jinja2 import Environment, FileSystemLoader

ROOT = Path(__file__).resolve().parents[2] / "src/interlock/admin/templates"


def test_fabric_form_offers_all_endpoints_and_save_first_state():
    env = Environment(loader=FileSystemLoader(ROOT), autoescape=True)
    html = env.get_template("partials/fabric_connection_fields.html").render(form={})
    for value in [
        'value="warehouse"',
        'value="lakehouse_sql"',
        'value="sql_database"',
        'value="oauth"',
        'value="spn"',
        'name="client_secret_ref"',
        "Save the source",
    ]:
        assert value in html
    assert "password" not in html.lower()


def test_saved_oauth_actions_and_account_are_escaped():
    env = Environment(loader=FileSystemLoader(ROOT), autoescape=True)
    html = env.get_template("partials/fabric_auth_controls.html").render(
        ds={"source_id": "f", "enabled": True},
        fabric_auth={"auth_mode": "oauth", "status": "connected", "account_id": "<script>"},
        fabric_oauth_ready=True,
    )
    assert "Reconnect" in html and "Disconnect" in html
    assert "&lt;script&gt;" in html and "Rotate credentials" not in html


def test_fabric_wizard_uses_its_auth_fields_without_generic_db_passwords():
    env = Environment(loader=FileSystemLoader(ROOT), autoescape=True)
    html = env.get_template("partials/wizard/step2_connection.html").render(
        state={
            "connector_key": "fabric_sql",
            "source_type": "database",
            "name": "Fabric",
            "auth_mode": "spn",
        }
    )
    assert 'name="tenant_id"' in html and 'name="endpoint_type"' in html
    assert 'name="password"' not in html and 'name="user"' not in html
    assert 'disabled title="Save the source first"' in html


def test_spn_controls_rotate_without_oauth_connect():
    env = Environment(loader=FileSystemLoader(ROOT), autoescape=True)
    html = env.get_template("partials/fabric_auth_controls.html").render(
        ds={"source_id": "f", "enabled": True},
        fabric_auth={"auth_mode": "spn", "status": "connected"},
    )
    assert "Rotate credentials" in html and "/fabric/connect" not in html


def test_fabric_draft_preserves_its_auth_config_and_drops_oauth_spn_secret():
    from interlock.admin.routes.dashboard import _connector_config_from_form, _wizard_state

    values = {
        "connector_key": "fabric_sql",
        "source_type": "database",
        "host": "h",
        "database": "db",
        "tenant_id": "tenant",
        "client_id": "client",
        "endpoint_type": "warehouse",
        "auth_mode": "oauth",
        "client_secret_ref": "env://UNRELATED",
    }
    state = _wizard_state(values)
    config = _connector_config_from_form("fabric_sql", state)
    assert config == {
        "host": "h",
        "database": "db",
        "tenant_id": "tenant",
        "client_id": "client",
        "endpoint_type": "warehouse",
        "auth_mode": "oauth",
    }


def test_official_icon_renders_accessibly_in_picker_list_detail_and_mcp_help():
    from fastapi.templating import Jinja2Templates

    from interlock.admin.app import _install_template_filters

    templates = Jinja2Templates(directory=str(ROOT))
    _install_template_filters(templates)
    ds = dict(
        source_id="f",
        name="Fabric",
        source_type="database",
        connector_key="fabric_sql",
        connector_name="Microsoft Fabric SQL",
        enabled=True,
        masked_connection_config={},
        fabric_auth={"status": "disconnected", "auth_mode": "oauth"},
        fabric_oauth_ready=False,
    )
    rendered = [
        templates.env.get_template("partials/wizard/step1_type.html").render(
            state={"connector_key": "fabric_sql"}, connector_groups=[]
        ),
        templates.env.get_template("partials/data_sources_table.html").render(data_sources=[ds]),
        templates.env.get_template("pages/data_source_detail.html").render(
            ds=ds,
            content_only=True,
            stats={},
            policies=[],
            source_roles=[],
            recent=[],
            approvals=[],
        ),
    ]
    for html in rendered:
        assert (
            'src="/static/assets/connectors/fabric.svg"' in html
            and 'alt="Microsoft Fabric"' in html
        )
    assert "Agents reach Fabric through MCP" in rendered[2]
    assert "the PostgreSQL database name" not in rendered[2]
    assert "Connect</button>" in rendered[2] and "disabled" in rendered[2]


def test_official_svg_contains_only_local_passive_shapes_and_green_gradients():
    from xml.etree import ElementTree

    icon = ROOT.parent / "static/assets/connectors/fabric.svg"
    tree = ElementTree.parse(icon)
    assert {node.tag.split("}")[-1] for node in tree.iter()} <= {
        "svg",
        "path",
        "defs",
        "linearGradient",
        "stop",
    }
    for node in tree.iter():
        assert not any(key.lower().startswith("on") or key.endswith("href") for key in node.attrib)
    assert "#25FFD4" in {node.attrib.get("stop-color") for node in tree.iter()}
