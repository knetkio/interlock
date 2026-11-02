"""Fabric lifecycle behavior with an external MSAL boundary and no provider access."""

from __future__ import annotations

import asyncio
import json
import threading
import time
from contextlib import asynccontextmanager
from dataclasses import replace
from datetime import UTC, datetime
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit

import pytest

from interlock.config import FabricSettings
from interlock.connections.fabric.auth import FabricAuth, FabricAuthError
from interlock.connections.fabric.config import FabricConfig
from interlock.connections.fabric.credentials import FabricCredentialContext, FabricCredentialError

BASE = dict(
    host="example.datawarehouse.fabric.microsoft.com",
    database="sales",
    tenant_id="tenant",
    client_id="client",
    endpoint_type="warehouse",
    auth_mode="spn",
    client_secret_ref="env://FABRIC_CLIENT_SECRET",
)
SCOPE = ["https://database.windows.net/.default"]
ACCOUNT = {"home_account_id": "uid.tenant", "local_account_id": "uid", "realm": "tenant"}


class MemoryStore:
    """Transactional test double at the store boundary; production SQL has integration tests."""

    def __init__(self, config):
        self.config = config
        self.context = FabricCredentialContext(
            "one",
            1,
            config.tenant_id,
            config.client_id,
            None,
            config.auth_mode,
            "connected" if config.auth_mode == "spn" else "disconnected",
        )
        self.cache = ""
        self.pending = {}
        self.mutex = asyncio.Lock()

    @asynccontextmanager
    async def locked(self, source_id):
        assert source_id == "one"
        async with self.mutex:
            locked = SimpleNamespace(
                config=self.config, context=self.context, revision=0, decrypted_cache=self.cache
            )
            yield locked
            self.context, self.cache = locked.context, locked.decrypted_cache

    async def get_context(self, source_id):
        async with self.locked(source_id) as locked:
            return locked.context

    async def save_cache(self, locked, serialized_cache):
        locked.decrypted_cache = serialized_cache
        if locked.context.auth_mode == "spn":
            locked.context = replace(locked.context, status="connected")

    async def save_identity(self, locked, *, account_id, status="connected"):
        locked.context = replace(
            locked.context,
            generation=locked.context.generation + 1,
            account_id=account_id,
            status=status,
        )
        locked.decrypted_cache = ""
        self.pending.clear()
        return locked.context

    async def invalidate_locked(self, locked, *, reason, delete_cache):
        locked.context = replace(
            locked.context,
            generation=locked.context.generation + 1,
            status="disconnected" if reason == "disconnect" else "reconnect_required",
            account_id=None if delete_cache else locked.context.account_id,
        )
        if delete_cache:
            locked.decrypted_cache = ""
        self.pending.clear()
        return locked.context

    async def invalidate(self, source_id, **kwargs):
        async with self.locked(source_id) as locked:
            return await self.invalidate_locked(locked, **kwargs)

    async def save_pending(
        self,
        source_id,
        session_binding,
        flow,
        expires_at,
        expected_generation,
        *,
        state=None,
        expected_incarnation=None,
    ):
        assert datetime.now(UTC) < expires_at
        async with self.locked(source_id) as locked:
            if locked.context.generation != expected_generation or (
                expected_incarnation is not None
                and locked.context.incarnation != expected_incarnation
            ):
                raise FabricCredentialError("generation changed")
            handle = state or f"opaque-{len(self.pending)}"
            self.pending[handle] = (
                session_binding,
                json.loads(json.dumps(flow)),
                expected_generation,
            )
            return handle

    async def consume_pending(self, state, session_binding):
        async with self.mutex:
            item = self.pending.get(state)
            if item is None or item[0] != session_binding:
                raise FabricCredentialError("invalid state")
            _, flow, generation = self.pending.pop(state)
            if generation != self.context.generation:
                raise FabricCredentialError("generation changed")
            return flow | {
                "_fabric_source_id": "one",
                "_fabric_generation": generation,
                "_fabric_incarnation": self.context.incarnation,
            }


@pytest.fixture
def setup_auth(monkeypatch):
    from interlock.connections.fabric import auth as module

    monkeypatch.setenv("FABRIC_CLIENT_SECRET", "client-private-secret")
    monkeypatch.setenv("FABRIC_OAUTH_SECRET", "oauth-private-secret")
    calls = []
    behavior = SimpleNamespace(
        result={"access_token": "access-private-token", "expires_in": 3600},
        account=ACCOUNT.copy(),
        canonical_tenant="tenant",
        entered=None,
        release=None,
    )

    class Client:
        def __init__(self, client_id, **kwargs):
            calls.append(("construct", client_id, kwargs))
            self.cache = kwargs["token_cache"]
            self.authority = SimpleNamespace(tenant=behavior.canonical_tenant)

        def get_accounts(self):
            return list(self.cache.search("Account"))

        def _token(self, scopes, *, account=None, force_refresh=False):
            assert scopes == SCOPE
            calls.append(("token", account, force_refresh))
            records = list(self.cache.search("AccessToken"))
            if records and not force_refresh:
                token = records[0]
                return {
                    "access_token": token["secret"],
                    "expires_in": int(token["expires_on"]) - int(time.time()),
                }
            calls.append(("network", account))
            if behavior.entered:
                behavior.entered.set()
                assert behavior.release.wait(5)
            if isinstance(behavior.result, Exception):
                raise behavior.result
            result = behavior.result.copy()
            if "access_token" in result:
                data = json.loads(self.cache.serialize())
                data["AccessToken"] = {
                    "key": {
                        "credential_type": "AccessToken",
                        "secret": result["access_token"],
                        "expires_on": str(int(time.time()) + int(result["expires_in"])),
                    }
                }
                self.cache.deserialize(json.dumps(data))
                self.cache.has_state_changed = True
            return result

        def acquire_token_for_client(self, scopes):
            return self._token(scopes)

        def remove_tokens_for_client(self):
            data = json.loads(self.cache.serialize())
            data.pop("AccessToken", None)
            self.cache.deserialize(json.dumps(data))

        def acquire_token_silent_with_error(self, scopes, account, force_refresh=False):
            return self._token(scopes, account=account, force_refresh=force_refresh)

        def initiate_auth_code_flow(self, scopes, **kwargs):
            assert scopes == SCOPE
            calls.append(("begin", kwargs))
            return {
                "auth_uri": f"https://login.microsoftonline.com/tenant/authorize?state={kwargs['state']}&code_challenge=challenge&code_challenge_method=S256",
                "state": kwargs["state"],
                "code_verifier": "pkce-private-verifier",
                "nonce": "nonce",
                "redirect_uri": kwargs["redirect_uri"],
                "scope": scopes,
            }

        def acquire_token_by_auth_code_flow(self, flow, query):
            assert not any(
                k in flow
                for k in (
                    "_fabric_source_id",
                    "_fabric_generation",
                    "_fabric_incarnation",
                    "_fabric_binding",
                )
            )
            assert flow["state"] == query["state"]
            assert flow["code_verifier"] == "pkce-private-verifier"
            calls.append(("complete", query))
            result = self._token(SCOPE)
            if "access_token" in result:
                result["id_token_claims"] = {
                    "tid": behavior.account["realm"],
                    "oid": behavior.account["local_account_id"],
                }
                data = json.loads(self.cache.serialize())
                data["Account"] = {"account": behavior.account}
                self.cache.deserialize(json.dumps(data))
                self.cache.has_state_changed = True
            return result

    monkeypatch.setattr(module.msal, "ConfidentialClientApplication", Client)
    settings = FabricSettings(
        oauth_client_id="client",
        oauth_client_secret_ref="env://FABRIC_OAUTH_SECRET",
        oauth_allowed_tenants=["tenant"],
        oauth_redirect_uri="https://admin.example/fabric/callback",
    )

    def create(*, oauth=False):
        config = FabricConfig(
            **(BASE | ({"auth_mode": "oauth", "client_secret_ref": None} if oauth else {}))
        )
        store = MemoryStore(config)
        return FabricAuth(store, settings), store, config

    return create, behavior, calls, settings


async def connect(auth, store):
    url = await auth.begin_oauth("one", "admin-session")
    state = parse_qs(urlsplit(url).query)["state"][0]
    context = await auth.complete_oauth(
        state, {"state": state, "code": "authorization-private-code"}, "admin-session"
    )
    return state, context


async def test_spn_uses_only_explicit_identity_sql_scope_and_hides_secrets(setup_auth):
    create, _, calls, _ = setup_auth
    auth, store, config = create()
    token = await auth.acquire("one", config)
    assert token.access_token == "access-private-token"
    assert token.context == store.context
    assert token.expires_at > time.time() + 3500
    assert "access-private-token" not in repr(token)
    _, client, args = calls[0]
    assert client == "client"
    assert args["authority"] == "https://login.microsoftonline.com/tenant"
    assert args["client_credential"] == "client-private-secret"
    assert calls[1] == ("token", None, False)


async def test_cached_token_survives_service_restart_without_refresh(setup_auth):
    create, behavior, calls, settings = setup_auth
    auth, store, config = create()
    first = await auth.acquire("one", config)
    behavior.result = RuntimeError("provider unavailable")
    token = await FabricAuth(store, settings).acquire("one", config)
    assert token.access_token == first.access_token
    assert len([c for c in calls if c[0] == "token"]) == 2


async def test_refreshes_inside_120_second_skew(setup_auth):
    create, behavior, calls, _ = setup_auth
    auth, store, config = create()
    await auth.acquire("one", config)
    envelope = json.loads(store.cache)
    cache = json.loads(envelope["msal"])
    cache["AccessToken"]["key"]["expires_on"] = str(int(time.time()) + 119)
    envelope["msal"] = json.dumps(cache)
    store.cache = json.dumps(envelope)
    behavior.result = {"access_token": "new-private-token", "expires_in": 3600}
    token = await auth.acquire("one", config)
    assert token.access_token == "new-private-token"
    assert len([c for c in calls if c[0] == "token"]) == 3


@pytest.mark.parametrize(
    "change", [{"host": "new.example.com"}, {"database": "other"}, {"max_rows": 20}]
)
async def test_stale_runtime_config_never_requests_a_token(setup_auth, change):
    create, _, calls, _ = setup_auth
    auth, store, config = create()
    store.config = FabricConfig(**(BASE | change))
    with pytest.raises(FabricAuthError) as error:
        await auth.acquire("one", config)
    assert error.value.code == "configuration_changed"
    assert not calls


@pytest.mark.parametrize(
    "result,code",
    [
        (
            {"error": "invalid_client", "error_description": "client-private-secret"},
            "authentication_denied",
        ),
        (
            {"error": "temporarily_unavailable", "error_description": "access-private-token"},
            "authentication_unavailable",
        ),
        (RuntimeError("oauth-private-secret"), "authentication_unavailable"),
    ],
)
async def test_provider_errors_are_stable_and_sanitized(setup_auth, result, code):
    create, behavior, _, _ = setup_auth
    auth, _, config = create()
    behavior.result = result
    with pytest.raises(FabricAuthError) as error:
        await auth.acquire("one", config)
    assert error.value.code == code
    assert "private" not in str(error.value) + repr(error.value)
    assert error.value.__suppress_context__


async def test_oauth_state_session_binding_replay_and_selected_identity(setup_auth):
    create, _, calls, _ = setup_auth
    auth, store, _ = create(oauth=True)
    url = await auth.begin_oauth("one", "admin-session")
    query = parse_qs(urlsplit(url).query)
    assert query["code_challenge_method"] == ["S256"]
    state = query["state"][0]
    assert state != "msal-state"
    with pytest.raises(FabricAuthError):
        await auth.complete_oauth(state, {"state": state, "code": "code"}, "wrong-session")
    context = await auth.complete_oauth(state, {"state": state, "code": "code"}, "admin-session")
    assert (context.account_id, context.status, context.generation) == (
        "uid.tenant",
        "connected",
        2,
    )
    assert json.loads(store.cache)["msal"]
    with pytest.raises(FabricAuthError):
        await auth.complete_oauth(state, {"state": state, "code": "code"}, "admin-session")
    assert len([c for c in calls if c[0] == "complete"]) == 1


@pytest.mark.parametrize("change", [{"oauth_client_id": "other"}, {"oauth_allowed_tenants": []}])
async def test_operator_registration_and_explicit_tenant_allowlist_are_required(setup_auth, change):
    create, _, calls, settings = setup_auth
    _, store, _ = create(oauth=True)
    changed = settings.model_copy(update=change)
    with pytest.raises(FabricAuthError):
        await FabricAuth(store, changed).begin_oauth("one", "admin-session")
    assert not calls


async def test_callback_rechecks_operator_binding_and_source_generation(setup_auth):
    create, _, calls, settings = setup_auth
    auth, store, _ = create(oauth=True)
    url = await auth.begin_oauth("one", "admin-session")
    state = parse_qs(urlsplit(url).query)["state"][0]
    changed = FabricAuth(
        store, settings.model_copy(update={"oauth_redirect_uri": "https://new.example/callback"})
    )
    with pytest.raises(FabricAuthError):
        await changed.complete_oauth(state, {"state": state, "code": "code"}, "admin-session")
    assert not [c for c in calls if c[0] == "complete"]
    assert store.context.status == "disconnected"


async def test_wrong_returned_tenant_is_rejected_without_saving_identity(setup_auth):
    create, behavior, _, _ = setup_auth
    auth, store, _ = create(oauth=True)
    behavior.account = ACCOUNT | {"realm": "other-tenant"}
    with pytest.raises(FabricAuthError) as error:
        await connect(auth, store)
    assert error.value.code == "authentication_denied"
    assert store.context.account_id is None and not store.cache


async def test_reconnect_to_different_account_replaces_old_identity_and_cache(setup_auth):
    create, behavior, _, _ = setup_auth
    auth, store, config = create(oauth=True)
    await connect(auth, store)
    behavior.account = {
        "home_account_id": "other.tenant",
        "local_account_id": "other",
        "realm": "tenant",
    }
    await connect(auth, store)
    assert store.context.account_id == "other.tenant" and store.context.generation == 3
    token = await auth.acquire("one", config)
    assert token.context.account_id == "other.tenant"
    assert "uid.tenant" not in store.cache


async def test_lost_consent_commits_reconnect_state_and_never_returns_rows(setup_auth):
    create, behavior, _, _ = setup_auth
    auth, store, config = create(oauth=True)
    await connect(auth, store)
    envelope = json.loads(store.cache)
    data = json.loads(envelope["msal"])
    data.pop("AccessToken")
    envelope["msal"] = json.dumps(data)
    store.cache = json.dumps(envelope)
    behavior.result = {
        "error": "interaction_required",
        "error_description": "refresh-private-token",
    }
    with pytest.raises(FabricAuthError) as error:
        await auth.acquire("one", config)
    assert error.value.code == "reconnect_required"
    assert store.context.status == "reconnect_required" and store.context.generation == 3
    assert "private" not in str(error.value)


async def test_spn_secret_rotation_reacquires_at_new_generation(setup_auth, monkeypatch):
    create, behavior, calls, _ = setup_auth
    auth, store, config = create()
    first = await auth.acquire("one", config)
    monkeypatch.setenv("FABRIC_CLIENT_SECRET", "rotated-private-secret")
    behavior.result = {"access_token": "rotated-access-token", "expires_in": 3600}
    second = await auth.acquire("one", config)
    assert second.access_token == "rotated-access-token"
    assert second.context.generation == first.context.generation + 1
    assert second.context.status == "connected"
    assert [c[2]["client_credential"] for c in calls if c[0] == "construct"][
        -1
    ] == "rotated-private-secret"


async def test_two_auth_instances_preserve_latest_cache(setup_auth):
    create, behavior, calls, settings = setup_auth
    auth, store, config = create()
    behavior.entered, behavior.release = threading.Event(), threading.Event()
    first = asyncio.create_task(auth.acquire("one", config))
    assert await asyncio.to_thread(behavior.entered.wait, 2)
    second = asyncio.create_task(FabricAuth(store, settings).acquire("one", config))
    await asyncio.sleep(0)
    behavior.release.set()
    tokens = await asyncio.gather(first, second)
    assert tokens[0].access_token == tokens[1].access_token
    assert len([c for c in calls if c[0] == "token"]) == 2


async def test_queued_invalidation_prevents_returning_refreshed_old_generation(setup_auth):
    create, behavior, _, _ = setup_auth
    auth, store, config = create()
    behavior.entered, behavior.release = threading.Event(), threading.Event()
    refresh = asyncio.create_task(auth.acquire("one", config))
    assert await asyncio.to_thread(behavior.entered.wait, 2)
    revoke = asyncio.create_task(store.invalidate("one", reason="disconnect", delete_cache=True))
    await asyncio.sleep(0)
    behavior.release.set()
    await revoke
    with pytest.raises(FabricAuthError) as error:
        await refresh
    assert error.value.code == "reconnect_required"
    assert not store.cache and store.context.generation == 2


def test_installed_msal_pkce_state_reserved_scopes_and_query_callback_without_network():
    """Characterize the MSAL assumptions our adapter relies on, at its HTTP boundary."""
    import base64
    import hashlib

    import msal

    posts = []

    class Http:
        def get(self, url, **kwargs):
            assert (
                url
                == "https://login.microsoftonline.com/tenant/v2.0/.well-known/openid-configuration"
            )
            return SimpleNamespace(
                status_code=200,
                text=json.dumps(
                    {
                        "authorization_endpoint": "https://login.microsoftonline.com/tenant/oauth2/v2.0/authorize",
                        "token_endpoint": "https://login.microsoftonline.com/tenant/oauth2/v2.0/token",
                        "issuer": "https://login.microsoftonline.com/tenant/v2.0",
                    }
                ),
            )

        def post(self, url, data, **kwargs):
            posts.append(data)
            assert url == "https://login.microsoftonline.com/tenant/oauth2/v2.0/token"
            return SimpleNamespace(
                status_code=200, headers={}, text=json.dumps({"error": "invalid_grant"})
            )

    app = msal.ConfidentialClientApplication(
        "client",
        authority="https://login.microsoftonline.com/tenant",
        client_credential="secret",
        http_client=Http(),
        instance_discovery=False,
    )
    flow = app.initiate_auth_code_flow(
        SCOPE,
        state="opaque-operator-state",
        redirect_uri="https://admin.example/callback",
        response_mode="query",
        prompt="select_account",
    )
    query = parse_qs(urlsplit(flow["auth_uri"]).query)
    digest = hashlib.sha256(flow["code_verifier"].encode()).digest()
    assert query["code_challenge"] == [base64.urlsafe_b64encode(digest).rstrip(b"=").decode()]
    assert query["code_challenge_method"] == ["S256"]
    assert query["state"] == ["opaque-operator-state"]
    assert query["response_mode"] == ["query"]
    assert set(query["scope"][0].split()) == {
        "https://database.windows.net/.default",
        "offline_access",
        "openid",
        "profile",
    }
    with pytest.raises(ValueError):
        app.acquire_token_by_auth_code_flow(flow.copy(), {"state": "stolen", "code": "code"})
    assert not posts
    result = app.acquire_token_by_auth_code_flow(
        flow.copy(), {"state": "opaque-operator-state", "code": "code"}
    )
    assert result["error"] == "invalid_grant"
    assert posts[0]["code_verifier"] == flow["code_verifier"]


async def test_oauth_uses_only_saved_account_even_when_another_account_has_tokens(setup_auth):
    create, _, calls, _ = setup_auth
    auth, store, config = create(oauth=True)
    await connect(auth, store)
    store.context = replace(store.context, account_id="missing.tenant")
    before = len([c for c in calls if c[0] == "token"])
    with pytest.raises(FabricAuthError) as error:
        await auth.acquire("one", config)
    assert error.value.code == "reconnect_required"
    assert len([c for c in calls if c[0] == "token"]) == before
    assert store.context.status == "reconnect_required"


@pytest.mark.parametrize("state", ["", "wrong-state"])
async def test_mismatched_callback_state_does_not_consume_legitimate_flow(setup_auth, state):
    create, _, _, _ = setup_auth
    auth, store, _ = create(oauth=True)
    url = await auth.begin_oauth("one", "admin-session")
    handle = parse_qs(urlsplit(url).query)["state"][0]
    with pytest.raises(FabricAuthError):
        await auth.complete_oauth(handle, {"state": state, "code": "code"}, "admin-session")
    assert handle in store.pending


async def test_cancellation_never_persists_or_delivers_late_thread_result(setup_auth):
    create, behavior, _, _ = setup_auth
    auth, store, config = create()
    behavior.entered, behavior.release = threading.Event(), threading.Event()
    refresh = asyncio.create_task(auth.acquire("one", config))
    assert await asyncio.to_thread(behavior.entered.wait, 2)
    refresh.cancel()
    with pytest.raises(asyncio.CancelledError):
        await refresh
    behavior.release.set()
    assert not store.cache


async def test_callback_refuses_token_that_cannot_survive_refresh_skew(setup_auth):
    create, behavior, _, _ = setup_auth
    auth, store, _ = create(oauth=True)
    behavior.result = {"access_token": "short-lived-token", "expires_in": 30}
    with pytest.raises(FabricAuthError) as error:
        await connect(auth, store)
    assert error.value.code == "authentication_unavailable"
    assert store.context.account_id is None and not store.cache


async def test_allowlisted_tenant_domain_uses_msals_canonical_tenant_for_saved_account(setup_auth):
    create, behavior, _, settings = setup_auth
    _, store, _ = create(oauth=True)
    config = FabricConfig(
        **(
            BASE
            | {
                "tenant_id": "contoso.onmicrosoft.com",
                "auth_mode": "oauth",
                "client_secret_ref": None,
            }
        )
    )
    store.config = config
    store.context = replace(store.context, tenant_id="contoso.onmicrosoft.com")
    behavior.canonical_tenant = "canonical-tenant-guid"
    behavior.account = {
        "home_account_id": "uid.canonical-tenant-guid",
        "local_account_id": "uid",
        "realm": "canonical-tenant-guid",
    }
    settings = settings.model_copy(update={"oauth_allowed_tenants": ["contoso.onmicrosoft.com"]})
    auth = FabricAuth(store, settings)
    await connect(auth, store)
    token = await auth.acquire("one", config)
    assert token.context.tenant_id == "contoso.onmicrosoft.com"
    assert token.context.account_id == "uid.canonical-tenant-guid"


@pytest.mark.parametrize("operation", ["malformed_response", "callback_cache", "refresh_error"])
async def test_real_msal_logs_redact_provider_payloads_without_affecting_concurrent_callers(
    monkeypatch, caplog, operation
):
    """Exercise real SDK ERROR, cache/code DEBUG, and refresh-error DEBUG logging."""
    import hashlib
    import logging

    from interlock.connections.fabric import auth as module

    secret = "fabric-log-test-client-secret"
    token = "fabric-log-test-access-token"
    code = "fabric-log-test-authorization-code"
    marker = "fabric-log-test-provider-payload"
    refresh = "fabric-log-test-refresh-token"
    entered, release = threading.Event(), threading.Event()
    real_client = module.msal.ConfidentialClientApplication
    posts = []
    oauth = operation != "malformed_response"
    config = FabricConfig(
        **(BASE | ({"auth_mode": "oauth", "client_secret_ref": None} if oauth else {}))
    )
    store = MemoryStore(config)
    settings = FabricSettings(
        oauth_client_id="client",
        oauth_client_secret_ref="env://FABRIC_LOG_TEST_SECRET",
        oauth_allowed_tenants=["tenant"],
        oauth_redirect_uri="https://admin.example/fabric/callback",
    )
    monkeypatch.setenv("FABRIC_LOG_TEST_SECRET", secret)
    monkeypatch.setenv("FABRIC_CLIENT_SECRET", secret)

    class Http:
        def get(self, url, **kwargs):
            assert (
                url
                == "https://login.microsoftonline.com/tenant/v2.0/.well-known/openid-configuration"
            )
            return SimpleNamespace(
                status_code=200,
                text=json.dumps(
                    {
                        "authorization_endpoint": "https://login.microsoftonline.com/tenant/oauth2/v2.0/authorize",
                        "token_endpoint": "https://login.microsoftonline.com/tenant/oauth2/v2.0/token",
                        "issuer": "https://login.microsoftonline.com/tenant/v2.0",
                    }
                ),
            )

        def post(self, url, data, **kwargs):
            assert url == "https://login.microsoftonline.com/tenant/oauth2/v2.0/token"
            assert data["client_secret"] == secret
            posts.append(data.copy())
            entered.set()
            assert release.wait(5)
            payload = f"{marker} {token} {code} {secret} {refresh}"
            if operation == "malformed_response":
                text = f"truncated provider body: {payload}"
            elif operation == "refresh_error":
                text = json.dumps({"error": "invalid_grant", "error_description": payload})
            else:
                text = json.dumps(
                    {
                        "access_token": token,
                        "expires_in": 3600,
                        "token_type": "Bearer",
                        "scope": "https://database.windows.net/.default",
                        "provider_diagnostic": payload,
                    }
                )
            return SimpleNamespace(status_code=200, headers={}, text=text)

    def construct(*args, **kwargs):
        return real_client(*args, http_client=Http(), **kwargs)

    monkeypatch.setattr(module.msal, "ConfidentialClientApplication", construct)
    auth = FabricAuth(store, settings)
    caplog.set_level(logging.DEBUG)
    if operation == "callback_cache":
        url = await auth.begin_oauth("one", "admin-session")
        state = parse_qs(urlsplit(url).query)["state"][0]
        task = asyncio.create_task(
            auth.complete_oauth(state, {"state": state, "code": code}, "admin-session")
        )
        expected = "authentication_denied"  # Token lacks a returned user identity.
    else:
        if operation == "refresh_error":
            account = ACCOUNT | {
                "environment": "login.microsoftonline.com",
                "authority_type": "MSSTS",
            }
            cache = {
                "Account": {"account": account},
                "RefreshToken": {
                    "refresh": {
                        "credential_type": "RefreshToken",
                        "secret": refresh,
                        "home_account_id": "uid.tenant",
                        "environment": "login.microsoftonline.com",
                        "client_id": "client",
                        "target": "https://database.windows.net/.default",
                    }
                },
            }
            store.context = replace(store.context, status="connected", account_id="uid.tenant")
            store.cache = json.dumps(
                {
                    "version": 1,
                    "msal": json.dumps(cache),
                    "secret_fingerprint": hashlib.sha256(secret.encode()).hexdigest(),
                }
            )
        task = asyncio.create_task(auth.acquire("one", config))
        expected = "reconnect_required" if oauth else "authentication_unavailable"
    try:
        assert await asyncio.to_thread(entered.wait, 2)
        # This is an unrelated caller on the same SDK logger during Fabric I/O.
        logging.getLogger("msal.oauth2cli.oauth2").debug("Unrelated MSAL caller remains visible")
    finally:
        release.set()
    with pytest.raises(FabricAuthError) as error:
        await task
    assert error.value.code == expected
    assert "Unrelated MSAL caller remains visible" in caplog.text
    assert len(posts) == 1
    if operation == "callback_cache":
        assert posts[0]["code"] == code
        assert store.context.status == "disconnected" and not store.cache
    elif operation == "refresh_error":
        assert posts[0]["refresh_token"] == refresh
        assert store.context.status == "reconnect_required"
    else:
        assert store.context.status == "connected" and not store.cache
    for sensitive in (marker, token, code, secret, refresh):
        assert sensitive not in caplog.text
    sdk_records = [record for record in caplog.records if record.name.startswith("msal.")]
    level = logging.ERROR if operation == "malformed_response" else logging.DEBUG
    assert any(record.levelno == level for record in sdk_records)
    assert all(record.exc_info is None and record.stack_info is None for record in sdk_records)
