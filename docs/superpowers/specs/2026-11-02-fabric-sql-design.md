# Fabric SQL connector design

Status: proposed for user approval. No implementation authorized by this document alone.

## Intent and agreed decisions

Add one dedicated `fabric_sql` connector to InterLock covering Fabric Warehouse,
Lakehouse SQL analytics endpoints, and Fabric SQL Database. Each source supplies
its server endpoint and database. All three share the same connector requirements:
OAuth user authentication and service principal (SPN) authentication, connection
validation, governed queries, catalog discovery, redaction, and audit.

OAuth represents the user saved when an administrator connects the source.
Requests do not impersonate each downstream agent's human user. SPN is another
authentication choice on that same source configuration. Existing InterLock agent
credentials and source roles continue to authorize access to the source.

The user selected a dedicated Fabric connector. The implementation choices below
are recommendations, not additional user-approved requirements.

## Approaches

1. Selected: dedicated Fabric connector backed by reusable SQL Server transport.
   Keeps Fabric endpoint/authentication configuration explicit while sharing driver
   and query code across the three endpoint types.
2. Extend the planned generic `mssql` connector. Less registry surface, but mixes
   general SQL Server authentication and Fabric setup. Not selected.

Do not turn the existing generic `mssql` placeholder into a supported connector
as part of this change. Share transport code without claiming generic coverage.

## Existing implementation

- `connections/connectors.py` defines adapters, capabilities, role templates,
  credential fields, configuration sanitization, and the adapter factory.
- Its `mssql` definition is planned and uses `SDKPresenceAdapter`; it has no
  functional SQL execution implementation.
- `core/normalizer.py` already maps `mssql` to sqlglot `tsql`.
- `gateway/mcp_adapter.py` dispatches non-PostgreSQL source queries to adapters,
  with existing policy, source-role, cache, redaction, and audit handling around it.
- Catalog collectors have an explicit registry and enforced-connector allowlist.
- The secret resolver reads references; it is not a writable OAuth token store.
- The Docker image does not currently install Microsoft's SQL ODBC driver.

## Proposed scope

Deliver connection setup, OAuth connect/reconnect/disconnect, SPN setup, health
probes, bounded SELECT queries, schema/table/view/column catalog discovery, and
existing governance integration through MCP. Support governed SQL writes where
the endpoint supports them, using InterLock's existing risk and approval flow.
Lakehouse SQL analytics endpoints do not support mutation of Lakehouse table data;
reject those operations clearly. Do not infer SQL Database or Warehouse write
permissions merely because their endpoint type permits writes.

Advertise each capability only when implemented and verified. Metadata-only
catalog discovery is distinct from document/content ingestion; do not advertise
content ingestion or incremental sync in this increment.

Non-goals: native TDS listener, translating the PostgreSQL wire protocol to T-SQL,
per-request user delegation/OBO, Fabric REST item provisioning, OneLake/Spark
access, automatic permission grants, or wiring VectorETL into InterLock.

## Configuration and administration

Connector key: `fabric_sql`; family/source type: database.

Persist explicit fields: host, port (default 1433), database, endpoint_type
(`warehouse`, `lakehouse_sql`, `sql_database`), auth_mode (`oauth`, `spn`), tenant_id,
client_id, applicable secret references, and bounded query/connect settings.
Require a database even where the service permits omission. Do not accept an
arbitrary connection string, authentication authority, driver name, or fallback
credential chain. Build connection strings from escaped validated fields.

Use one source form with endpoint type and authentication method selectors.
OAuth offers Connect, connected-account/tenant display, Reconnect, and Disconnect.
SPN accepts a tenant, application ID, and client-secret reference. Certificate-based
SPN credentials are deferred unless requested; secrets satisfy the initial SPN
requirement. OAuth app registration and its confidential client credential are
operator configuration, not secrets returned to the browser.

Test Connection verifies token acquisition and `SELECT 1` against the configured
database. Catalog scan is a separate operation. Report authentication-required,
permission-denied, network, driver, and query failures without exposing credentials.

## Authentication and stored identity

Use MSAL for both modes and the SQL resource scope
`https://database.windows.net/.default` in the public Azure cloud.

OAuth: tenant-specific authorization-code flow with PKCE and state protection,
registered callback URI, and offline token renewal. Bind pending authorization to
the authenticated admin session, source ID, tenant/client configuration, and a
short expiry. Callback is single-use; configuration edits invalidate old attempts.
Verify the returned tenant/account matches the connection being established.
Never treat an admin login session as an upstream SQL credential.

Store the MSAL cache encrypted in the control database in a separate credential
record. Use an operator-provided dedicated encryption key outside the database,
with key versioning for rotation. Persist neither raw tokens in connection_config
nor secrets in logs, audit payloads, HTML, or API responses. Use the existing secret
resolver for client credentials; add a writable encrypted credential/cache service
rather than pretending the resolver can save refresh tokens.

Use per-source, tenant, client, account, and credential-generation cache ownership.
Coordinate refresh across admin/gateway/worker processes with database locking or
optimistic revision control so concurrent cache updates do not lose refresh state.
Resolve a token silently before opening a new SQL connection, refreshing before
expiry. Interaction-required returns a reconnect-needed state and no data.

SPN: acquire application tokens using the configured tenant/client and resolved
secret, renewing as needed. No Azure CLI login, global account, or default identity
fallback. Rotation invalidates the previous credential generation.

Disconnect and auth/endpoint edits invalidate the local credential generation,
connection reuse, catalog state where relevant, and cached query responses before
another request can use them. Disconnect deletes locally stored OAuth credentials;
it does not promise tenant-wide token revocation. An explicit reconnect may replace
the saved account and must invalidate data cached under the previous identity.

## SQL transport and concurrency

Use pyodbc with Microsoft ODBC Driver 18, encrypted connections, and certificate
verification. Supply the acquired SQL access token through the driver's token
attribute; omit UID/PWD/Authentication when using that attribute.

Keep blocking driver work off the async event loop with bounded thread execution.
Initially use explicitly closed per-operation connections and disable implicit
ODBC pooling to avoid credential-generation reuse. Revisit pooling only with
identity-aware ownership and expiry tests.

Own login timeout, statement timeout, active cancellation, result row/byte limits,
parameter binding, and cleanup at the transport boundary. A timed-out coroutine
must not leave an unbounded SQL operation executing. Bind parameter values;
never interpolate them. Fetch incrementally to enforce result limits. Reuse the
existing result conventions and serializers for decimal/date/time/UUID/binary/null
values; define deterministic handling of duplicate column names and truncation.

Follow existing egress protections, including private-endpoint opt-in. Token
issuance and driver redirect destinations must not become an escape from host
validation; verify the actual ODBC redirect/egress behavior in deployment tests.
No arbitrary driver options or executable configuration are exposed to sources.

## Governance, catalog, and caching

Map `fabric_sql` to `tsql` everywhere SQL is parsed, normalized, classified, or
analyzed for table/column access. Use schema-qualified resource identifiers.
Verify three-part names and cross-database references; reject unsupported scope
rather than allowing access outside the registered database. Deny unsupported
procedural SQL, dynamic SQL, batches, and statements the enforcement path cannot
analyze safely. Normalization output is never executed as rewritten SQL.

Implement adapters for probe, introspect, permission requests, reads, and supported
writes. Preserve the existing pipeline's role and policy decisions, redaction,
write approval, and audit ordering. Add the connector to enforced catalog coverage
only together with a working collector and tests for missing/stale metadata.

Catalog uses SQL metadata queries through the same auth/transport; only names,
types, and supported structure are collected, not customer row values. Respect
existing scan limits and upstream visibility permissions.

Source cache identity must include upstream credential generation/account and
existing downstream role/policy scope. Inspect the existing cache path before
adding the new dimension; apply invalidation to every tier used by this connector.
Audit identifies the InterLock actor, source, configured upstream principal, and
outcome without tokens, secrets, or unnecessary personal claims.

Initial write support is limited to single-statement INSERT, UPDATE, and DELETE
on supported tables in Warehouse and SQL Database, subject to existing policy and
source-role authorization. MERGE, DDL, stored procedures, and endpoint-specific
administrative operations are deferred. This boundary is a proposed builder choice
for user approval.

Writes use the existing queue/approval execution path; approval must recheck current
source/auth/policy state. No automatic retry after a write may have reached SQL.
Endpoint type is a capability hint, not a substitute for SQL permission checks.

## Packaging and implementation boundaries

Add focused modules for Fabric auth/cache storage, SQL Server transport, and the
Fabric adapter rather than extending the already large connector registry with
all implementation bodies. Register those modules through existing factories.
Add a Fabric catalog collector and console routes/templates following existing
patterns. Add a forward migration for credential state and revisions.

Install MSAL and pyodbc via the project's uv-managed dependencies. Install ODBC 18
and its runtime libraries in supported container architectures; preserve non-root
runtime and explicit driver license acceptance in build tooling. Check support for
the current Debian base/architecture rather than assuming a package exists.
Update Compose/Helm/operator examples for callback URL and encryption-key secret
mounting. Use Bun only for any JavaScript tooling that this work actually needs.

## Verification and acceptance

Unit and dashboard tests: config branches, secret masking, callback authorization,
state/PKCE replay and expiry, tenant/account binding, concurrent refresh, restart,
revoked consent, credential rotation, disconnect, and key-rotation handling.

Transport and governance tests: T-SQL TOP/bracket identifiers/CTEs/joins, parameter
binding, denial of writes under read roles, unsafe SQL, out-of-database references,
redaction, audit sanitization, row/byte limits, cancellation/cleanup, and no stale
identity cache hits. Test supported writes and approval-state changes separately.

Live acceptance matrix: all three endpoint types crossed with OAuth and SPN.
Each cell proves connection, query, catalog, permission denial, and audit; refresh
and reconnect tests prove the shared auth lifecycle. Test write behavior on
Warehouse/SQL Database and rejection of Lakehouse table mutations. Only use
disposable, explicitly authorized test objects for writes.

Before any live customer access, check this project's fabric-customer selection
and the intended tenant/workspace/database/identity. BlendX is the selected customer;
no Stretch Zone SQL connection or global login fallback is permitted. Missing live
fixtures remain explicit verification gaps, not claimed certified coverage.

All synthetic fixtures and deployment checks live in tests/tooling. No deployment
self-tests or recurring verification are added to normal query execution.

## Delivery and approval

Proposed sequence: configuration/auth storage; token lifecycle; SQL transport and
adapter; catalog/governance; console onboarding; container and live acceptance.
Each implementation task must include its own meaningful verification.

Builder check completed: the reviewer identified the undefined write-statement
scope; this revision proposes INSERT/UPDATE/DELETE and explicitly defers other
mutations. No other important planning questions were identified.

User approval of this design is required before implementation. After approval,
write a separate file-by-file implementation plan with test commands and execution
boundaries. This proposal includes writes on capable endpoints and secret-based
SPN authentication; those are the principal scope choices for review.
