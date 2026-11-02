---
title: "Microsoft Fabric SQL"
description: "Configure saved-user OAuth or service-principal SQL access, deployment secrets, and opt-in acceptance."
sidebar:
  order: 12
---

The `fabric_sql` database connector supports Warehouse, Lakehouse SQL analytics
endpoints, and Fabric SQL Database. It uses MSAL and Microsoft ODBC Driver 18,
with encryption and certificate verification required. Native endpoint acceptance
is **unverified** in this increment; implemented/tested behavior is not six-cell
certification. Content ingestion and incremental sync are not capabilities.

## Register an identity and grant access

1. Copy the **exact server and database** from the intended Fabric item's SQL
   connection settings. Do not derive server names from endpoint type: published
   examples include multiple domains. Record the customer, tenant, workspace,
   database, and intended upstream principal before connecting. See Microsoft's
   [SQL Database connection guide](https://learn.microsoft.com/en-us/fabric/database/sql/connect).
2. For saved-user OAuth, register a confidential **Web** application in the intended
   Entra tenant. Register the exact console origin plus
   `/api/fabric/oauth/callback` as its redirect URI. `localhost` and `127.0.0.1`
   are different origins. Configure Azure SQL Database delegated permission and
   required tenant consent for `https://database.windows.net/.default`.
   Store the app client secret in the deployment secret store. See
   [MSAL authorization-code acquisition](https://learn.microsoft.com/en-us/entra/msal/python/getting-started/acquiring-tokens).
3. For SPN, designate the tenant/application and a client-secret **reference**;
   certificate authentication is deferred. An administrator must arrange Fabric
   item/workspace access and the SQL grants needed for the intended objects.
   Metadata visibility follows those grants. See
   [Fabric Warehouse service principals](https://learn.microsoft.com/en-us/fabric/data-warehouse/service-principals).
4. On the console **Connectors** page, activate the beta **Microsoft Fabric SQL**
   connector; it is intentionally absent from the six default quickstart choices.
   Then create/save the source and use **Connect** for OAuth. The administrator
   operates the login and verifies the account. This is the saved user's identity
   for subsequent execution, not the identity of each downstream caller. SPN uses
   only its designated secret reference. No global account, Azure CLI login,
   default identity, OBO, or automatic grant is used.

Fabric/SQL grants are administrator operations, separate from InterLock roles,
policies, redaction, and approval. Give the upstream principal least privilege;
trigger definitions and view bodies are not expanded by the connector.

## Supply deployment secrets

Fabric defaults to disabled (`active_key_version: null`, `key_refs: {}`). There
is no development encryption key or default credential. The production and worker
images include the SDKs and driver; optional Python installs use the `fabric-sql`
extra. The existing `python:3.12-slim` Debian base is retained. Installation uses
Microsoft's distro-specific signed package repository and explicit EULA acceptance,
following the [Linux installation guide](https://learn.microsoft.com/en-us/sql/connect/odbc/linux/installing-the-microsoft-odbc-driver-for-sql-server-on-linux).

Generate a Fernet key using `uv run python -c 'from cryptography.fernet import Fernet;
print(Fernet.generate_key().decode())'` in a private terminal. Store the result
outside the repository as `key-v1`; do not paste it into chat, logs, or YAML.
Back up the keyring alongside encrypted control-database backups with separate
access controls: losing an old key can make saved caches unreadable.

For Compose, set these **reference settings** in the operator environment and use
`docker compose -f docker-compose.yml -f docker-compose.fabric.yml up -d`:

```sh
export FABRIC_SECRET_DIRECTORY=/private/interlock-fabric-secrets
export INTERLOCK_FABRIC__ACTIVE_KEY_VERSION=v1
export INTERLOCK_FABRIC__KEY_REFS='{"v1":"file:///run/secrets/fabric/key-v1"}'
export INTERLOCK_FABRIC__OAUTH_CLIENT_ID=YOUR-APP-ID
export INTERLOCK_FABRIC__OAUTH_REDIRECT_URI=https://console.example/api/fabric/oauth/callback
export INTERLOCK_FABRIC__OAUTH_CLIENT_SECRET_REF=file:///run/secrets/fabric/oauth-client-secret
export INTERLOCK_FABRIC__OAUTH_ALLOWED_TENANTS='["YOUR-TENANT-ID"]'
```

Create the files privately and grant the container's uid/gid 1000 read access.
The opt-in overlay mounts the same directory read-only in admin, gateway, and
both workers. SPN source references may use `file:///run/secrets/fabric/spn-secret`.
Unset optional environment variables are omitted, rather than passed as invalid
empty references. Ordinary quickstart does not require these files.

For Helm, create an operator-managed Kubernetes Secret with `key-v1`, any retained
`key-v0`, `oauth-client-secret`, and needed SPN files. Do not put secret values in
Helm values. For example:

```yaml
fabric:
  enabled: true
  existingSecret: interlock-fabric-credentials
  activeKeyVersion: v1
  keyVersions: [v0, v1]
  oauthClientId: YOUR-APP-ID
  oauthRedirectUri: https://console.example/api/fabric/oauth/callback
  oauthAllowedTenants: [YOUR-TENANT-ID]
  oauthClientSecretKey: oauth-client-secret
```

The chart supplies identical references/settings to all three process types and
mounts the Secret read-only with group-readable `0440` permissions. Omit OAuth
settings for an SPN-only installation. All replicas must use the same control DB,
keyring and active version. Credential/token caches are encrypted in the control
DB; no token or plaintext cache belongs in source metadata or container images.

## Reconnect, rotate, and recover

- OAuth token renewal is silent when consent/cache remains usable. If status
  requires reconnect, use the source's **Connect** flow again with the designated
  account. Disconnect invalidates the source generation and encrypted cache;
  pending flows cannot be replayed. Reconnect after consent is restored.
- For SPN rotation, provision the new secret privately, update its reference/file,
  then use the source's **Rotate credentials** action. Updating file contents alone
  does not invalidate already prepared credentials. Verify the source under its
  new generation before retiring the old credential. Never grant permissions as
  part of rotation.
- For encryption-key rotation, retain old references, add `v2`, and change the
  active version consistently across all replicas. Restart processes to load the
  keyring. New cache/pending-flow writes use the active version. Reconnect/rotate
  each source so its cache is rewritten; verify stored encrypted records use the
  new version before removing old keys. Pending OAuth states expire after ten
  minutes. Keep historical keys needed by retained backups. There is no automatic
  bulk re-encryption command in this increment.
- Cancellation or timeout after submission can leave a write outcome unknown.
  Do not automatically retry. Native calls that remain blocked retain their
  bounded worker slots. Use an external container/process shutdown deadline;
  process termination is the final isolation boundary.

## SQL and endpoint limits

Read operations support ordinary projections/aliases, SELECT CTEs and joins
within registered scope. Catalog naming facts and supported catalog collations
must be available; missing/unsupported facts refuse scope. Visible tables and
views are discoverable; views are read-only. Native case/metadata behavior still
requires endpoint acceptance.

Initial Warehouse and SQL Database writes are limited to single-target
`INSERT VALUES`, `UPDATE`, and `DELETE` on catalog-confirmed tables, under existing
source roles/policies/approval. No `OUTPUT`, mixed read/write syntax (`SELECT`,
subqueries, CTEs, `FROM`, joins, `USING`, or a second data-bearing table), `MERGE`,
DDL, procedures, dynamic SQL, batches, or endpoint administration. Lakehouse table
mutations are rejected before authentication/driver submission. Generic transport
`OUTPUT` rollback tests do not enable it in the Fabric adapter. UPDATE assignments
accept only literal values (including NULL and negative numeric literals) or bound
parameters. Column-derived assignments and computed expressions are refused,
including previously queued approvals, until input reads can be authorized
separately from destination writes.

Structured `FOR XML`/`FOR JSON`, PIVOT/UNPIVOT/APPLY, table-valued functions,
cross-database three-part names, four-part names, SELECT INTO, and wildcard shapes
whose result lineage cannot be established are outside this subset. Exact same-database three-part
qualification (for example, `Demo.dbo.Users` when the saved database is `Demo`)
is supported; SQL sent to the driver keeps that qualification. Hidden wildcard
serialization cannot bypass column redaction. No TDS listener, PostgreSQL-to-TSQL translation,
VectorETL integration, or per-request delegated identity is provided.

Defaults are 15-second login, 30-second statement, 1,000 rows, 8 MiB serialized
result bytes, eight active operations and sixteen waiting submissions per process.
Source limits can be set to login 1–120 seconds, statement 1–3,600 seconds,
1–100,000 rows and 1 KiB–256 MiB, with no unbounded values. Duplicate result-column
names and exceeded limits are errors. Decimal is an exact string; dates/times,
UUIDs and binary use strings (binary base64); null remains null. Unknown affected
row counts are not reported as exact counts.

## Native acceptance and release gate

| Endpoint | Saved-user OAuth | SPN |
| --- | --- | --- |
| Warehouse | Unverified; no designated native credentials | Unverified; no designated native credentials |
| Lakehouse SQL analytics | Unverified; no designated native credentials | Unverified; no designated native credentials |
| Fabric SQL Database | Unverified; no designated native credentials | Unverified; no designated native credentials |

Build/loading checks are separate: run `tools/check_fabric_image.py` inside each
production/worker image on each architecture. It verifies uid/gid 1000, architecture,
MSAL/pyodbc imports, Driver 18 registration, and native shared-library loading.
It makes no database or egress claim. Current build evidence lives in the Task 8
implementation report; the six native cells above are not certified.

Live tests are opt-in. Before obtaining credentials, the harness runs
`~/.local/bin/fabric-customer status --project /absolute/designated/project`
and requires matching customer/tenant and an enabled SQL selection. Never use
another customer's connection or a global login. Create a private manifest using
this shape (no token, DSN, client secret, or policy seed is accepted):

```json
{
  "project": "/absolute/designated/project",
  "customer": "blendx",
  "cells": [{
    "endpoint_type": "warehouse", "auth_mode": "oauth", "source_id": "saved-source-id",
    "tenant_id": "designated-tenant", "workspace_id": "designated-workspace",
    "host": "exact-server-from-fabric", "database": "exact-database-from-fabric",
    "client_id": "designated-app", "expected_account_id": "saved-msal-home-account-id",
    "expected_sql_identity": "expected-SUSER_SNAME-result"
  }]
}
```

SPN cells explicitly use `"expected_account_id": null`. The manifest designates
workspace membership; this SQL-only harness does not independently query the
Fabric control plane. Operators must verify workspace/item ownership beforehand.
The saved source and credential context must match the manifest before token
acquisition. OAuth must already be connected through the console; do not paste
an access token into fixtures. Create a private application settings file containing the explicit control DB
and key references, then run:

```sh
FABRIC_LIVE=1 FABRIC_LIVE_MANIFEST=/private/fabric-manifest.json \
  FABRIC_LIVE_CONFIG_PATH=/private/fabric-test-config.yaml \
  uv run pytest tests/integration/test_fabric_live.py -m live -q -rA \
  --junitxml=/private/fabric-live-results.xml
```

Missing cells skip as **unverified**. Runnable probes verify connection/token
packing, a bounded read with DB/principal assertions, catalog visibility, and
Lakehouse adapter rejection without sending destructive SQL. The remaining dimensions use explicitly supplied operator scenarios described
below. All native results remain pending until those authorized fixtures are
supplied and actually executed. This harness never invents grants, policies,
credentials or disposable objects.

### Executable operator scenarios

Set `FABRIC_LIVE_SCENARIOS=/private/fabric-scenarios.json` alongside the manifest
and control settings. The file maps endpoint/auth cells to scenarios and pins
the exact allowed gateway origins; HTTP redirects are refused. For example:

```json
{
  "allowed_gateway_origins": ["https://gateway.test.example"],
  "cells": {
    "warehouse/spn": {
      "audit": {
        "probe": {
          "gateway_url": "https://gateway.test.example",
          "actor_key_ref": "file:///run/secrets/fabric-test-actor",
          "actor_id": 7,
          "sql": "SELECT Name FROM dbo.AcceptanceFixture",
          "expected_rows": [{"Name": "authorized-fixture"}]
        }
      }
    }
  }
}
```

Use an existing authorized downstream identity, role/policy and harmless fixture.
`probe.parameters` is an optional ordered array. General probes must be read-only.
Every governed observation checks a new audit event bound to source, actor and
its unique request correlation ID; old or unrelated traffic is insufficient.

| Scenario key | Required fixture/actions and independent assertions |
| --- | --- |
| `denial` | `probe` must receive 403 and a new correlated denied audit event. |
| `redaction` | `probe`, nonempty `masked_columns`; all designated returned columns must equal `[REDACTED:POLICY]`, with a new success audit. |
| `audit` | Exact expected fixture rows and new source/actor success audit. |
| `restart_refresh` | `probe`, `restart` and `refresh` hooks, `restart_observer_path`; fresh observed process identity change, unchanged credential identity/generation, later token expiry, successful governed read/audit. Arrange genuine renewal conditions beforehand; a hook exit alone cannot prove restart or renewal. |
| `oauth_reconnect_lost_consent` | `probe`, `lose_consent` and `reconnect` hooks; acquisition must require reconnect after loss, then a newer generation and correct SQL identity after user-operated reconnect. |
| `spn_rotation` | `probe`, `rotate` hook; newer generation, old prepared capability refused, correct new-generation read/audit. |
| `multi_instance_cache` | `probe`, distinct allowed `second_gateway_url`, `reset_cache`/`invalidate` hooks; first miss/second-instance hit before and after generation invalidation, with matching new identity audits. |
| `statement_cancellation` | An empty scenario object opts into the existing native worker/handle/server-request probe; also requires `FABRIC_SQL_OBSERVE_SESSION_AUTHORIZED=1`. |
| `login_cancellation` | `prepare`/`cleanup` hooks and `network` fixture; positive login-start event, actual cancellation, original native worker completion and observed login closure. |
| `tls_certificate_failure` | `prepare`/`cleanup` hooks and `network` fixture; actual driver rejection plus observed certificate rejection. No TLS verification override is available. |
| `driver_redirect_egress` | `prepare`/`cleanup` hooks and `network` fixture; actual driver rejection, positive allowed initial destination and blocked disallowed redirect; any allowed disallowed destination fails as a bypass. |
| `writes` | `probe`, `write.authorization: "disposable_objects_only"`, designated `write.table`, exactly three `write.steps` (INSERT VALUES, UPDATE, DELETE). Each step supplies SQL, optional ordered parameters, same-table `read_sql`, and exact `expected_rows`. Existing policy/role/approval remains enforced. A 202 requires an explicit `approve` hook and an executed queue record; new write audit and read-back must both match. Lakehouse writes are excluded. |

`hooks` maps the named action to an object with `argv` (absolute executable and
explicit nonsecret arguments), optional `timeout_seconds` (1–60), and optional
`secret_env` mapping variable names to secret references. Hooks run with
`shell=False`, suppressed stdout/stderr and no ambient credential environment.
The harness supplies `FABRIC_ACCEPTANCE_SOURCE_ID`, `FABRIC_ACCEPTANCE_NONCE`, and
for approval `FABRIC_ACCEPTANCE_APPROVAL_ID`. Sensitive values/references never
belong in argv. User-operated OAuth login must use the approved console flow;
prepare any longer interactive action before a bounded hook verifies completion.
Hooks must only operate the explicitly authorized fixtures, with no automatic
grants or policy creation. The harness provides no generic recorded-pass field.

The `network` object supplies absolute `observer_path`, exact
`allowed_destination` (for example `sql.example:1433`), a different
`blocked_destination` for redirect tests, and optional `cleanup_seconds` (1–60).
Prepare the observation fixture against the saved source's **exact host**; the
harness does not change its host, identity, TLS settings or permissions. A trusted
external observer appends JSONL events with `nonce`, `source_id`, `target_host`,
`destination`, `timestamp` (UTC epoch seconds), `action` (`allowed` or `blocked`)
and `event`. Only fresh records appended after the attempt began are accepted.
Required events include `login_started`/`login_closed`,
`tls_certificate_rejected`, or `redirect` as applicable. Restart observation uses
fresh JSONL `event: "process_restart"`, matching nonce/source/`gateway_origin`,
`timestamp`, and different nonempty `previous_instance`/`current_instance` IDs.

These observers must be trusted telemetry from actual fixture/process/network
controls, independent of hook exit status. An arbitrary file's authenticity cannot
be independently proven by this harness. Passing only establishes the observed
fixture behavior; release still requires trusted actual deployment egress evidence.
Missing cell/scenario/permission skips remain **unverified**, and failed assertions
are failures. Offline synthetic boundary tests never count as native certification.

The optional `test_sqlserver_transport.py` probes use the same manifest and saved
identity (`FABRIC_SQL_INTEGRATION=1`). Only explicit
`FABRIC_SQL_DISPOSABLE_WRITE_AUTHORIZED=1` plus a matching
`FABRIC_SQL_WRITE_SOURCE_ID` authorizes creation/drop of unique
`dbo.interlock_transport_test_*` fixtures. The transport's OUTPUT check is not
adapter write acceptance. Cancellation additionally requires
`FABRIC_SQL_OBSERVE_SESSION_AUTHORIZED=1` and authorized visibility into
`sys.dm_exec_requests`; it checks the original worker, successful native handle
close, and absence of the original server request. A short caller return or a
successful query on a spare worker is insufficient evidence.

ODBC can redirect after the initial connection. Deploy network-level egress
controls covering every destination/port and Entra HTTPS access, then capture
actual driver traffic and prove an unauthorized redirect is blocked. Initial
hostname validation is **not DNS pinning or complete redirect enforcement**.
See Microsoft's [Fabric network allowlist](https://github.com/MicrosoftDocs/fabric-docs/blob/main/docs/security/fabric-allow-list-urls.md)
and [Warehouse connectivity guidance](https://learn.microsoft.com/en-us/fabric/data-warehouse/connectivity).
A redirect policy bypass is a release blocker. TLS failure, login/statement
cancellation and redirect behavior remain unverified without native evidence;
do not release on mocked-driver results alone.

The synthetic HTTP packaging smoke uses `docker-compose.fabric-e2e.yml`, a separate
Compose project, fresh volumes, admin 29090, gateway 23001, PG 25433 and Redis
26380. It explicitly clears optional model-provider keys and never reuses the
running evaluation database. It proves packaged startup/auth boundaries, not
visual browser behavior or Microsoft connectivity.
