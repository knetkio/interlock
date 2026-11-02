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
`OUTPUT` rollback tests do not enable it in the Fabric adapter.

Structured `FOR XML`/`FOR JSON`, PIVOT/UNPIVOT/APPLY, table-valued functions,
three/four-part names, SELECT INTO, and wildcard shapes whose result lineage
cannot be established are outside this subset. Hidden wildcard serialization
cannot bypass column redaction. No TDS listener, PostgreSQL-to-TSQL translation,
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
Lakehouse adapter rejection without sending destructive SQL. Separate pending
cells list denial, redaction, audit, restart/refresh, reconnect/lost consent,
SPN rotation, multi-instance cache lifecycle, login/statement cancellation,
TLS certificate failures and redirect egress. They require designated authorized
actor/role/policy/object fixtures and operator scenarios; this harness does not
invent grants or mark those scenarios passed. Write acceptance remains pending
until disposable objects are explicitly authorized.

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
