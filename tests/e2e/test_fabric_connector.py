"""HTTP/template packaging smoke against an isolated synthetic Compose stack.

No browser binaries, customer endpoint, token, or host model-provider key needed.
INTERLOCK_E2E=1 INTERLOCK_E2E_SKIP_SEED=1 FABRIC_PACKAGING_E2E=1 uv run pytest \\
  tests/e2e/test_fabric_connector.py -q
"""

from __future__ import annotations

import os

import httpx
import pytest

pytestmark = [
    pytest.mark.e2e,
    pytest.mark.skipif(
        os.environ.get("FABRIC_PACKAGING_E2E") != "1", reason="isolated Fabric smoke not enabled"
    ),
]


def test_nonfabric_default_startup_and_saved_source_auth_boundary():
    # Fixed disposable ports intentionally cannot fall back to the user's stack.
    assert httpx.get("http://127.0.0.1:23001/health").status_code == 200
    with httpx.Client(base_url="http://127.0.0.1:29090", follow_redirects=False) as client:
        assert client.get("/health").status_code == 200
        login = client.post(
            "/auth/login",
            data={"username": "admin", "password": "fabric-e2e-password"},
            headers={"Accept": "application/json"},
        )
        assert login.status_code == 200
        csrf = client.get("/auth/csrf").json()["csrf"]
        activation = client.post(
            "/dashboard/connectors/fabric_sql/activation",
            data={"active": "on"},
            headers={"X-CSRF-Token": csrf},
        )
        assert activation.status_code == 200
        picker = client.get("/dashboard/data-sources/new")
        assert picker.status_code == 200
        assert "Microsoft Fabric SQL" in picker.text
        assert "fabric_sql" in picker.text
        response = client.post(
            "/api/data-sources/no-such-source/fabric/connect", headers={"X-CSRF-Token": csrf}
        )
        # Fabric is disabled without an operator keyring. The response must not
        # redirect to Microsoft or attempt an ambient-account bootstrap.
        assert response.status_code in (404, 503)
        assert "login.microsoftonline.com" not in response.text
        with httpx.Client(base_url="http://127.0.0.1:29090") as anonymous:
            response = anonymous.post("/api/data-sources/no-such-source/fabric/connect")
            assert response.status_code in (401, 403)
