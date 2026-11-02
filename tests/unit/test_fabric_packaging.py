"""Rendered deployment contracts: no ambient credentials or partial process setup."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

from interlock.config import FabricSettings

ROOT = Path(__file__).resolve().parents[2]


def helm(*args):
    if not shutil.which("helm"):
        pytest.skip("Helm CLI required for rendered deployment contracts")
    result = subprocess.run(
        ["helm", "template", "fabric-test", "deploy/helm/interlock", *args],
        cwd=ROOT,
        text=True,
        capture_output=True,
    )
    assert result.returncode == 0, result.stderr
    return [doc for doc in yaml.safe_load_all(result.stdout) if doc]


def workloads(documents):
    return [
        doc["spec"]["template"]["spec"]
        for doc in documents
        if doc["kind"] in {"Deployment", "StatefulSet"}
    ]


def test_no_fabric_helm_defaults_preserve_unrelated_startup():
    for pod in workloads(helm()):
        env = pod["containers"][0]["env"]
        assert not any(item["name"].startswith("INTERLOCK_FABRIC__") for item in env)
    assert FabricSettings().active_key_version is None


def test_enabled_helm_delivers_same_settings_and_readonly_keys_to_all_processes(tmp_path):
    values = tmp_path / "fabric.yaml"
    values.write_text(
        yaml.safe_dump(
            {
                "fabric": {
                    "enabled": True,
                    "existingSecret": "fabric-credentials",
                    "activeKeyVersion": "v2",
                    "keyVersions": ["v1", "v2"],
                    "oauthClientId": "test-app",
                    "oauthAllowedTenants": ["test-tenant"],
                    "oauthRedirectUri": "https://console.example/api/fabric/oauth/callback",
                    "oauthClientSecretKey": "oauth-client-secret",
                }
            }
        )
    )
    pods = workloads(helm("-f", str(values)))
    assert len(pods) == 3
    for pod in pods:
        container = pod["containers"][0]
        env = {item["name"]: item["value"] for item in container["env"] if "value" in item}
        assert env["INTERLOCK_FABRIC__ACTIVE_KEY_VERSION"] == "v2"
        refs = json.loads(env["INTERLOCK_FABRIC__KEY_REFS"])
        assert refs == {
            "v1": "file:///run/secrets/fabric/key-v1",
            "v2": "file:///run/secrets/fabric/key-v2",
        }
        settings = FabricSettings(
            active_key_version=env["INTERLOCK_FABRIC__ACTIVE_KEY_VERSION"],
            key_refs=refs,
            oauth_redirect_uri=env["INTERLOCK_FABRIC__OAUTH_REDIRECT_URI"],
            oauth_client_id=env["INTERLOCK_FABRIC__OAUTH_CLIENT_ID"],
            oauth_client_secret_ref=env["INTERLOCK_FABRIC__OAUTH_CLIENT_SECRET_REF"],
            oauth_allowed_tenants=json.loads(env["INTERLOCK_FABRIC__OAUTH_ALLOWED_TENANTS"]),
        )
        assert settings.oauth_allowed_tenants == ["test-tenant"]
        assert settings.oauth_redirect_uri == "https://console.example/api/fabric/oauth/callback"
        mount = next(m for m in container["volumeMounts"] if m["name"] == "fabric-secrets")
        assert mount["readOnly"] is True
        volume = next(v for v in pod["volumes"] if v["name"] == "fabric-secrets")
        assert volume["secret"]["secretName"] == "fabric-credentials"
        assert volume["secret"]["defaultMode"] == 0o440


@pytest.mark.skipif(not shutil.which("helm"), reason="Helm CLI required")
def test_helm_refuses_enabled_without_explicit_key_configuration():
    result = subprocess.run(
        ["helm", "template", "test", "deploy/helm/interlock", "--set", "fabric.enabled=true"],
        cwd=ROOT,
        text=True,
        capture_output=True,
    )
    assert result.returncode != 0
    assert "fabric." in result.stderr


def test_compose_inherits_unset_optional_references_without_empty_strings():
    result = subprocess.run(
        ["docker", "compose", "config", "--format", "json"],
        cwd=ROOT,
        text=True,
        capture_output=True,
        env={"PATH": __import__("os").environ["PATH"]},
    )
    assert result.returncode == 0, result.stderr
    services = json.loads(result.stdout)["services"]
    for name in ["admin", "gateway", "worker-1", "worker-2"]:
        env = services[name]["environment"]
        assert "INTERLOCK_FABRIC__KEY_REFS" in env
        assert env["INTERLOCK_FABRIC__OAUTH_CLIENT_SECRET_REF"] is None
        settings = FabricSettings(
            **{
                key.removeprefix("INTERLOCK_FABRIC__").lower(): (
                    json.loads(value) if key.endswith(("KEY_REFS", "ALLOWED_TENANTS")) else value
                )
                for key, value in env.items()
                if key.startswith("INTERLOCK_FABRIC__") and value is not None
            }
        )
        assert settings.active_key_version is None


def test_image_probe_is_executable_and_requires_expected_architecture():
    result = subprocess.run(
        ["uv", "run", "python", "tools/check_fabric_image.py", "--help"],
        cwd=ROOT,
        text=True,
        capture_output=True,
    )
    assert result.returncode == 0, result.stderr
    assert "--architecture" in result.stdout


@pytest.mark.skipif(not shutil.which("helm"), reason="Helm CLI required")
def test_enabled_helm_oauth_requires_registered_callback_secret_and_tenant(tmp_path):
    base = {
        "enabled": True,
        "existingSecret": "fabric-creds",
        "activeKeyVersion": "v1",
        "keyVersions": ["v1"],
        "oauthClientId": "application",
        "oauthRedirectUri": "https://console.example/api/fabric/oauth/callback",
        "oauthAllowedTenants": ["tenant"],
        "oauthClientSecretKey": "oauth-secret",
    }
    for missing in ["oauthRedirectUri", "oauthAllowedTenants", "oauthClientSecretKey"]:
        values = tmp_path / "incomplete.yaml"
        values.write_text(
            yaml.safe_dump({"fabric": {k: v for k, v in base.items() if k != missing}})
        )
        result = subprocess.run(
            ["helm", "template", "test", "deploy/helm/interlock", "-f", str(values)],
            cwd=ROOT,
            text=True,
            capture_output=True,
        )
        assert result.returncode != 0, f"Incomplete OAuth accepted without {missing}"


def test_optin_compose_mounts_identical_readonly_secret_directory(tmp_path):
    result = subprocess.run(
        [
            "docker",
            "compose",
            "-f",
            "docker-compose.yml",
            "-f",
            "docker-compose.fabric.yml",
            "config",
            "--format",
            "json",
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        env={**__import__("os").environ, "FABRIC_SECRET_DIRECTORY": str(tmp_path)},
    )
    assert result.returncode == 0, result.stderr
    services = json.loads(result.stdout)["services"]
    for service in ["admin", "gateway", "worker-1", "worker-2"]:
        mount = next(
            m for m in services[service]["volumes"] if m["target"] == "/run/secrets/fabric"
        )
        assert mount["read_only"] is True
        assert mount["source"] == str(tmp_path)


def test_generated_fabric_reference_preserves_existing_secret_reference_key():
    code = (
        "import runpy; from interlock.connections.connectors import get_connector; "
        "print(runpy.run_path('tools/docs/generate.py')['connector_page']"
        "(get_connector('fabric_sql')))"
    )
    result = subprocess.run(
        ["uv", "run", "python", "-c", code], cwd=ROOT, text=True, capture_output=True
    )
    assert result.returncode == 0, result.stderr
    assert "client_secret_ref_ref" not in result.stdout
    assert "| `client_secret_ref` | yes; reference required |" in result.stdout
