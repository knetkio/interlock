"""Explicit Fabric identities and encrypted, generation-bound MSAL lifecycles."""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import math
import secrets
import time
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, Literal
from urllib.parse import parse_qs, urlsplit

import msal

from interlock.config import FabricSettings
from interlock.connections.fabric.config import FabricConfig
from interlock.connections.fabric.credentials import (
    FabricCredentialContext,
    FabricCredentialError,
    FabricCredentialStore,
)
from interlock.secrets.resolver import resolve

SQL_SCOPES = ["https://database.windows.net/.default"]
AuthErrorCode = Literal[
    "reconnect_required",
    "authentication_denied",
    "authentication_unavailable",
    "configuration_changed",
]
_MESSAGES: dict[AuthErrorCode, str] = {
    "reconnect_required": "Fabric authentication requires reconnecting this source",
    "authentication_denied": "Fabric authentication was denied",
    "authentication_unavailable": "Fabric authentication is temporarily unavailable",
    "configuration_changed": "Fabric source configuration changed; reload this source",
}

_FABRIC_MSAL_LOG_SCOPE: ContextVar[bool] = ContextVar("fabric_msal_log_scope", default=False)


class _FabricMsalLogFilter(logging.Filter):
    """Scrub SDK records before handlers, only inside this connector's calls.

    MSAL's PII setting does not cover malformed response exception logging or
    all cache/refresh DEBUG fields. Never format that untrusted payload here.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        if _FABRIC_MSAL_LOG_SCOPE.get():
            record.msg = "Fabric authentication provider diagnostic (sensitive details suppressed)"
            record.args = ()
            record.exc_info = None
            record.exc_text = None
            record.stack_info = None
        return True


# Install once, without request-time changes to global logging configuration.
# Logger filters are not inherited by descendants: cover each SDK logger used
# by confidential-client construction, OAuth, refresh and cache operations.
_MSAL_LOG_FILTER = _FabricMsalLogFilter()
for _logger_name in (
    "msal.application",
    "msal.authority",
    "msal.token_cache",
    "msal.telemetry",
    "msal.region",
    "msal.oauth2cli.oauth2",
    "msal.oauth2cli.oidc",
    "msal.oauth2cli.assertion",
):
    logging.getLogger(_logger_name).addFilter(_MSAL_LOG_FILTER)


@contextmanager
def _redacted_msal_logs() -> Iterator[None]:
    # The decorator enters inside the worker thread, including construction and
    # cache handling. Cancellation leaves late SDK logs scoped until it exits.
    scope = _FABRIC_MSAL_LOG_SCOPE.set(True)
    try:
        yield
    finally:
        _FABRIC_MSAL_LOG_SCOPE.reset(scope)


class FabricAuthError(RuntimeError):
    """Stable public errors; provider text, codes, claims and secrets never escape."""

    def __init__(self, code: AuthErrorCode) -> None:
        self.code = code
        super().__init__(_MESSAGES[code])


@dataclass(frozen=True, slots=True)
class FabricToken:
    access_token: str = field(repr=False)
    expires_at: float
    context: FabricCredentialContext


class _SecretChangedError(Exception):
    """Internal signal with no secret material attached."""


def _provider_error(result: dict[str, Any] | None) -> FabricAuthError:
    error = (result or {}).get("error")
    if not result or error in {
        "interaction_required",
        "login_required",
        "consent_required",
        "invalid_grant",
    }:
        return FabricAuthError("reconnect_required")
    if error in {"access_denied", "invalid_client", "unauthorized_client", "invalid_scope"}:
        return FabricAuthError("authentication_denied")
    return FabricAuthError("authentication_unavailable")


class FabricAuth:
    """MSAL is the only token authority; the store lock is the only refresh owner.

    No application/token cache lives on this service. Each operation reloads the
    current encrypted cache while holding the source and credential locks.
    """

    def __init__(self, store: FabricCredentialStore, settings: FabricSettings) -> None:
        self._store = store
        self._settings = settings

    def _validate_oauth(self, config: FabricConfig) -> None:
        if (
            config.auth_mode != "oauth"
            or config.client_id != self._settings.oauth_client_id
            or config.tenant_id.lower()
            not in {tenant.lower() for tenant in self._settings.oauth_allowed_tenants}
            or not self._settings.oauth_client_secret_ref
            or not self._settings.oauth_redirect_uri
        ):
            raise FabricAuthError("authentication_denied") from None

    def _binding(self, config: FabricConfig, fingerprint: str) -> dict[str, Any]:
        return {
            "config": config.model_dump(),
            "oauth_client_id": self._settings.oauth_client_id,
            "oauth_client_secret_ref": self._settings.oauth_client_secret_ref,
            "oauth_redirect_uri": self._settings.oauth_redirect_uri,
            "secret_fingerprint": fingerprint,
        }

    def _session(
        self, config: FabricConfig, serialized: str, *, binding: dict[str, Any] | None = None
    ) -> tuple[Any, Any, str]:
        """Called only in a worker thread; resolved secrets are operation-local."""
        try:
            ref = (
                config.client_secret_ref
                if config.auth_mode == "spn"
                else self._settings.oauth_client_secret_ref
            )
            secret = resolve(ref)
            if not secret:
                raise FabricAuthError("authentication_unavailable")
            fingerprint = hashlib.sha256(secret.encode()).hexdigest()
            cache = msal.SerializableTokenCache()
            if serialized:
                try:
                    envelope = json.loads(serialized)
                    if envelope["version"] != 1 or not isinstance(envelope["msal"], str):
                        raise ValueError("invalid cache format")
                    if not secrets.compare_digest(envelope["secret_fingerprint"], fingerprint):
                        raise _SecretChangedError
                    cache.deserialize(envelope["msal"])
                except _SecretChangedError:
                    raise
                except Exception:
                    raise FabricAuthError("reconnect_required") from None
            if binding is not None and binding != self._binding(config, fingerprint):
                raise FabricAuthError("authentication_denied")
            app = msal.ConfidentialClientApplication(
                config.client_id,
                authority=f"https://login.microsoftonline.com/{config.tenant_id}",
                client_credential=secret,
                token_cache=cache,
                instance_discovery=False,
                enable_pii_log=False,
                timeout=config.connect_timeout_seconds,
            )
            return app, cache, fingerprint
        except (_SecretChangedError, FabricAuthError):
            raise
        except Exception:
            raise FabricAuthError("authentication_unavailable") from None

    @staticmethod
    def _serialize(cache: Any, fingerprint: str) -> str:
        # The entire envelope is encrypted by the store, including its binding.
        return json.dumps(
            {"version": 1, "msal": cache.serialize(), "secret_fingerprint": fingerprint}
        )

    @staticmethod
    def _expires(result: dict[str, Any]) -> float:
        try:
            expires = (
                float(result["expires_on"])
                if "expires_on" in result
                else time.time() + float(result["expires_in"])
            )
            if not math.isfinite(expires):
                raise ValueError("invalid expiry")
            return expires
        except (KeyError, ValueError, TypeError, OverflowError):
            raise FabricAuthError("authentication_unavailable") from None

    @_redacted_msal_logs()
    def _acquire_sync(
        self, config: FabricConfig, serialized: str, account_id: str | None
    ) -> tuple[str, float, str]:
        app, cache, fingerprint = self._session(config, serialized)
        try:
            account = None
            if config.auth_mode == "oauth":
                # MSAL tenant discovery canonicalizes an allowlisted tenant domain
                # to its immutable tenant ID via the token endpoint metadata.
                tenant = str(app.authority.tenant).lower()
                accounts = [
                    item
                    for item in app.get_accounts()
                    if item.get("home_account_id") == account_id
                    and str(item.get("realm", "")).lower() == tenant
                ]
                if len(accounts) != 1:
                    raise FabricAuthError("reconnect_required")
                account = accounts[0]
                result = app.acquire_token_silent_with_error(SQL_SCOPES, account=account)
            else:
                result = app.acquire_token_for_client(scopes=SQL_SCOPES)
            if not isinstance(result, dict) or not result.get("access_token"):
                raise _provider_error(result)
            expires = self._expires(result)
            if expires <= time.time() + self._settings.refresh_skew_seconds:
                if config.auth_mode == "oauth":
                    result = app.acquire_token_silent_with_error(
                        SQL_SCOPES, account=account, force_refresh=True
                    )
                else:
                    # MSAL deliberately rejects force_refresh for client credentials.
                    app.remove_tokens_for_client()
                    result = app.acquire_token_for_client(scopes=SQL_SCOPES)
                if not isinstance(result, dict) or not result.get("access_token"):
                    raise _provider_error(result)
                expires = self._expires(result)
                if expires <= time.time() + self._settings.refresh_skew_seconds:
                    raise FabricAuthError("authentication_unavailable")
            token = result["access_token"]
            if not isinstance(token, str):
                raise FabricAuthError("authentication_unavailable")
            return token, expires, self._serialize(cache, fingerprint)
        except FabricAuthError:
            raise
        except Exception:
            raise FabricAuthError("authentication_unavailable") from None

    async def acquire(self, source_id: str, config: FabricConfig) -> FabricToken:
        failure: FabricAuthError | None = None
        token: FabricToken | None = None
        try:
            async with self._store.locked(source_id) as locked:
                if locked.config != config:
                    raise FabricAuthError("configuration_changed")
                if config.auth_mode == "oauth":
                    self._validate_oauth(config)
                if locked.context.status == "disconnected" or (
                    config.auth_mode == "oauth" and locked.context.status != "connected"
                ):
                    raise FabricAuthError("reconnect_required")
                try:
                    try:
                        access, expires, serialized = await asyncio.to_thread(
                            self._acquire_sync,
                            config,
                            locked.decrypted_cache,
                            locked.context.account_id,
                        )
                    except _SecretChangedError:
                        await self._store.invalidate_locked(
                            locked, reason="secret_rotation", delete_cache=config.auth_mode == "spn"
                        )
                        if config.auth_mode == "oauth":
                            raise FabricAuthError("reconnect_required") from None
                        access, expires, serialized = await asyncio.to_thread(
                            self._acquire_sync, config, "", None
                        )
                    if serialized != locked.decrypted_cache or locked.context.status != "connected":
                        await self._store.save_cache(locked, serialized)
                    token = FabricToken(access, expires, locked.context)
                except FabricAuthError as exc:
                    # Commit this transition, then raise outside the transaction.
                    if exc.code == "reconnect_required" and locked.context.status == "connected":
                        await self._store.invalidate_locked(
                            locked, reason="consent_lost", delete_cache=False
                        )
                    failure = exc
            if failure is not None:
                raise failure from None
            if token is None:
                raise FabricAuthError("authentication_unavailable")
            # A revocation queued behind the refresh lock wins before delivery.
            current = await self._store.get_context(source_id)
            if current != token.context:
                raise FabricAuthError("reconnect_required")
            return token
        except FabricAuthError as exc:
            raise exc from None
        except FabricCredentialError:
            raise FabricAuthError("reconnect_required") from None
        except Exception:
            raise FabricAuthError("authentication_unavailable") from None

    @_redacted_msal_logs()
    def _begin_sync(self, config: FabricConfig, state: str) -> dict[str, Any]:
        app, _, fingerprint = self._session(config, "")
        try:
            # MSAL adds offline_access/openid/profile and generates PKCE + nonce.
            flow: dict[str, Any] = app.initiate_auth_code_flow(
                SQL_SCOPES,
                redirect_uri=self._settings.oauth_redirect_uri,
                state=state,
                prompt="select_account",
                response_mode="query",
            )
            query = parse_qs(urlsplit(flow["auth_uri"]).query)
            if (
                flow.get("state") != state
                or query.get("state") != [state]
                or not flow.get("code_verifier")
                or query.get("code_challenge_method") != ["S256"]
            ):
                raise FabricAuthError("authentication_unavailable")
            flow["_fabric_binding"] = self._binding(config, fingerprint)
            return flow
        except FabricAuthError:
            raise
        except Exception:
            raise FabricAuthError("authentication_unavailable") from None

    async def begin_oauth(self, source_id: str, session_binding: str) -> str:
        try:
            if not session_binding:
                raise FabricAuthError("authentication_denied")
            state = secrets.token_urlsafe(32)
            async with self._store.locked(source_id) as locked:
                config = locked.config
                self._validate_oauth(config)
                generation = locked.context.generation
                incarnation = locked.context.incarnation
                flow = await asyncio.to_thread(self._begin_sync, config, state)
            handle = await self._store.save_pending(
                source_id,
                session_binding,
                flow,
                datetime.now(UTC) + timedelta(seconds=599),
                generation,
                state=state,
                expected_incarnation=incarnation,
            )
            if handle != state:
                raise FabricAuthError("authentication_unavailable")
            return str(flow["auth_uri"])
        except FabricAuthError as exc:
            raise exc from None
        except FabricCredentialError:
            raise FabricAuthError("reconnect_required") from None
        except Exception:
            raise FabricAuthError("authentication_unavailable") from None

    @_redacted_msal_logs()
    def _complete_sync(
        self, config: FabricConfig, flow: dict[str, Any], query: dict[str, str]
    ) -> tuple[str, str]:
        binding = flow.pop("_fabric_binding", None)
        if not isinstance(binding, dict):
            raise FabricAuthError("authentication_denied")
        app, cache, fingerprint = self._session(config, "", binding=binding)
        try:
            result = app.acquire_token_by_auth_code_flow(flow, query)
            if not isinstance(result, dict) or not result.get("access_token"):
                raise _provider_error(result)
            if (
                not isinstance(result["access_token"], str)
                or self._expires(result) <= time.time() + self._settings.refresh_skew_seconds
            ):
                raise FabricAuthError("authentication_unavailable")
            claims = result.get("id_token_claims", {})
            accounts = app.get_accounts()
            tenant = str(app.authority.tenant).lower()
            if (
                str(claims.get("tid", "")).lower() != tenant
                or not claims.get("oid")
                or len(accounts) != 1
                or accounts[0].get("local_account_id") != claims["oid"]
                or str(accounts[0].get("realm", "")).lower() != tenant
                or not isinstance(accounts[0].get("home_account_id"), str)
                or not accounts[0]["home_account_id"]
            ):
                raise FabricAuthError("authentication_denied")
            return str(accounts[0]["home_account_id"]), self._serialize(cache, fingerprint)
        except FabricAuthError:
            raise
        except ValueError:
            raise FabricAuthError("authentication_denied") from None
        except Exception:
            raise FabricAuthError("authentication_unavailable") from None

    async def complete_oauth(
        self, state: str, query: dict[str, str], session_binding: str
    ) -> FabricCredentialContext:
        try:
            if not state or not session_binding or query.get("state") != state:
                raise FabricAuthError("authentication_denied")
            flow = await self._store.consume_pending(state, session_binding)
            source_id = flow.pop("_fabric_source_id")
            generation = flow.pop("_fabric_generation")
            incarnation = flow.pop("_fabric_incarnation")
            if (
                not isinstance(source_id, str)
                or not isinstance(generation, int)
                or not isinstance(incarnation, str)
            ):
                raise FabricAuthError("authentication_denied")
            async with self._store.locked(source_id) as locked:
                self._validate_oauth(locked.config)
                if (
                    locked.context.generation != generation
                    or locked.context.incarnation != incarnation
                    or flow.get("state") != state
                ):
                    raise FabricAuthError("reconnect_required")
                account_id, serialized = await asyncio.to_thread(
                    self._complete_sync, locked.config, flow, query.copy()
                )
                await self._store.save_identity(locked, account_id=account_id)
                await self._store.save_cache(locked, serialized)
                context = locked.context
            if await self._store.get_context(source_id) != context:
                raise FabricAuthError("reconnect_required")
            return context
        except FabricAuthError as exc:
            raise exc from None
        except FabricCredentialError:
            raise FabricAuthError("reconnect_required") from None
        except Exception:
            raise FabricAuthError("authentication_unavailable") from None
