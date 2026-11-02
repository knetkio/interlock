# Fabric SQL Connector Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add one Fabric SQL connector for Warehouse, Lakehouse SQL analytics endpoints, and Fabric SQL Database, with saved-user OAuth and SPN authentication.

**Architecture:** A dedicated `fabric_sql` adapter delegates authentication to a process-injected Fabric service and SQL execution to reusable ODBC transport. Encrypted control-database credential state and a current credential generation coordinate admin, gateway, and workers. Existing InterLock governance remains the authority around execution.

**Tech Stack:** Python 3.12, MSAL Python, pyodbc, Microsoft ODBC Driver 18, asyncpg/PostgreSQL, existing FastAPI/Jinja/sqlglot/pytest stack; uv for Python dependencies and Bun for any JavaScript tooling.

**Spec:** `docs/superpowers/specs/2026-11-02-fabric-sql-design.md` (approved in chat; logo requirement included).

## Global Constraints

- Connector key: `fabric_sql`; family/source type: database.
- Endpoint types: `warehouse`, `lakehouse_sql`, `sql_database`; auth modes: `oauth`, `spn`.
- OAuth represents the user saved when an administrator connects the source.
- Use the green Microsoft Fabric “F” logo as the connector icon.
- Use MSAL for both modes and the SQL resource scope `https://database.windows.net/.default` in the public Azure cloud.
- Use pyodbc with Microsoft ODBC Driver 18, encrypted connections, and certificate verification.
- No Azure CLI login, global account, or default identity fallback.
- Initial write support is limited to single-statement INSERT, UPDATE, and DELETE on supported tables in Warehouse and SQL Database, subject to existing policy and source-role authorization.
- MERGE, DDL, stored procedures, and endpoint-specific administrative operations are deferred.
- SPN client-secret references are required initially; certificate support is deferred.
- No TDS listener, PostgreSQL-to-TSQL translation, per-request delegation/OBO, automatic permission grants, or VectorETL integration.
- Content ingestion and incremental sync are not connector capabilities in this increment.
- All synthetic fixtures and deployment checks live in tests/tooling.
- Before live customer access run `/Users/avouk/.local/bin/fabric-customer status --project /Users/avouk/Development/blend-contextdata-poc/interlock`; verify BlendX tenant/workspace/database/identity. No Stretch Zone SQL or global login fallback.
- Keep the running local evaluation stack unchanged until implementation verification and rollout are authorized. Do not install browser binaries or use another browser without the user's permission; use the in-app browser for manual UI review.

## Review Focus

- Credential edits racing with cache hits, refresh, and queued approvals: all subsequent uses require the current generation; test Tasks 2, 5, and 6.
- SQL that parses but escapes registered scope (three/four-part names, SELECT INTO, dynamic SQL, batches, TVFs): deny unsupported scope before driver invocation; test Task 4.
- A timeout/cancel after SQL submission: cancel and clean up, never automatically retry an uncertain write; test Task 3.
- OAuth state theft/replay, account changes, and lost concurrent refresh updates: session/tenant/source binding and revision protection; test Tasks 1, 2, and 7.
- Deployment behavior differs from mocked drivers (ODBC redirect, ARM64 packaging, token expiry, schema visibility): require opt-in live/container evidence, mark missing cells unverified; test Task 8.

## Files and responsibility map

New modules:
- `src/interlock/connections/fabric/{__init__,config,credentials,auth,runtime,adapter}.py`: Fabric configuration, encrypted state, MSAL lifecycle, per-process services, adapter respectively.
- `src/interlock/connections/sqlserver.py`: reusable ODBC execution; no MSAL, UI, policy decisions, or customer selection.
- `src/interlock/catalog/collectors/fabric.py`: metadata snapshot collector.
- `src/interlock/admin/routes/fabric_auth.py`: authenticated connect/callback/status/disconnect routes.
- `src/interlock/admin/templates/partials/fabric_connection_fields.html`: Fabric-specific form.
- `src/interlock/admin/static/assets/connectors/fabric.svg`: official green Fabric F asset.
- `migrations/020_fabric_credentials.sql`: encrypted credentials, pending OAuth state, credential revisions.

Existing integration points:
- `connections/connectors.py`, `connections/source_config.py`, `connections/manager.py`, `metadata/registry.py`: registry, validation, process service injection, source lifecycle.
- `core/normalizer.py`, `core/approval_queue.py`, `gateway/mcp_adapter.py`: dialect, approvals, execution/cache integration.
- `catalog/collectors/__init__.py`, `catalog/validation.py`: collector wiring and enforcement.
- `admin/app.py`, `gateway/app.py`, `worker/__main__.py`, `worker/loop.py`: process lifetime and shared-service creation.
- `admin/routes/data_sources.py`, `admin/routes/dashboard.py`, `admin/source_cache.py`: source edits, UI, invalidation.
- `config.py`, `pyproject.toml`, `uv.lock`, `requirements-production.txt`, `Dockerfile`, `docker-compose.yml`, `deploy/helm/interlock/{values.yaml,templates/*.yaml}`: settings/build/deployment.

Create test files named in tasks; follow existing fixture conventions. Add new modules to the hardened typecheck configuration if its file allowlist requires it. Retain existing APIs for other connectors; do not restructure their implementations.

## Builder decisions and shared contracts

Defaults proposed for this implementation: connect timeout 15 seconds; statement timeout 30 seconds; query result limit 1,000 rows and 8 MiB serialized bytes; maximum 8 concurrent ODBC operations per process with 16 waiting submissions. OAuth state TTL 10 minutes; refresh skew 120 seconds. Operator settings may vary connect timeout from 1–120 seconds, statement timeout from 1–3,600 seconds, row limit from 1–100,000, and byte limit from 1 KiB–256 MiB; no zero/unbounded values.

Result semantics: reject duplicate output column names explicitly instead of silently overwriting dictionary values; reject an oversized single value/result with a clear result-limit error rather than silently truncate. Decimal becomes an exact string; dates/times/UUID become strings; binary becomes base64; null stays null. Reads stop with a result-limit error after detecting row limit + 1. Writes with OUTPUT that exceed limits must roll back; do not commit a result the adapter cannot safely return. Preserve order and existing result envelope keys `rows`, `columns`, `row_count`, `permission_request`; do not claim affected row counts when ODBC reports unknown.

Public interfaces (new unless noted):
- `FabricConfig` in `fabric/config.py`: validated configuration model; `.from_mapping(config: dict[str, Any]) -> FabricConfig`.
- `FabricCredentialContext` in `fabric/credentials.py`: source_id, generation (integer), tenant_id, client_id, account_id, auth_mode, status. This is non-secret.
- `LockedFabricCredential` in `fabric/credentials.py`: context (`FabricCredentialContext`), revision (integer), decrypted_cache (string), and encrypted pending-flow lifecycle helpers; used only within the store lock context.
- `FabricCredentialStore.locked(source_id: str) -> AsyncContextManager[LockedFabricCredential]`; `save_cache(locked: LockedFabricCredential, serialized_cache: str) -> None`; `save_pending(source_id: str, session_binding: str, flow: dict[str, Any], expires_at: datetime, expected_generation: int) -> str`; and `consume_pending(state: str, session_binding: str) -> dict[str, Any]` are async except the context-manager factory. The state string returned by save_pending is an opaque handle; consume_pending atomically validates ownership/expiry/generation and deletes it before returning the decrypted MSAL flow.
- `FabricToken` in `fabric/auth.py`: access_token (repr disabled), expires_at (UTC epoch), context (`FabricCredentialContext`). Never serialize through admin APIs.
- `FabricCredentialStore(pool, keyring)` in `fabric/credentials.py`: encrypted credential reads/writes, pending state consumption, revision locking, lifecycle transaction ownership. `get_context(source_id: str) -> FabricCredentialContext` and `invalidate(source_id: str, *, reason: str, delete_cache: bool) -> FabricCredentialContext` are async.
- `FabricAuth(store, settings)` in `fabric/auth.py`: async `acquire(source_id: str, config: FabricConfig) -> FabricToken`; `begin_oauth(source_id: str, session_binding: str) -> str` returns authorization URL; `complete_oauth(state: str, query: dict[str, str], session_binding: str) -> FabricCredentialContext`.
- `SqlServerTransport` in `connections/sqlserver.py`: async `execute(config: FabricConfig, token: FabricToken, sql: str, parameters: tuple[Any, ...], *, write: bool) -> dict[str, Any]`; `close() -> None` async. The transport reads only endpoint/limit fields from config and token string; does not refresh credentials.
- `FabricServices(store, auth, transport)` in `fabric/runtime.py`: process-lifetime container with async close. No secrets or service objects live in source metadata.
- Extend `get_adapter(key_or_source_type, metadata=None, *, fabric_services: FabricServices | None = None, source_id: str | None = None)` compatibly. Fabric permission parsing works without services; methods needing I/O fail explicitly without services/source_id. Other adapters ignore these optional arguments.
- `FabricSQLAdapter` in `fabric/adapter.py`: existing ConnectorAdapter methods plus async `metadata_snapshot(*, limits: ScanLimits | None = None) -> dict[str, Any]` for public metadata introspection; it shares the bounded typed collector helper with `collect_fabric`.
- `collect_fabric(ctx: CollectContext) -> CatalogSnapshot` async; add an optional `fabric_services` member to `CollectContext` without changing existing collectors.

Each task's consumed/produced interfaces are these shared contracts. If an integration requires changing a signature, update this contract and every dependent test/caller in the same task before proceeding.

### Task 1: Configuration and encrypted credential state

**Files:** Create `fabric/__init__.py`, `fabric/config.py`, `fabric/credentials.py`, migration `020_fabric_credentials.sql`, `tests/unit/test_fabric_config.py`, `tests/unit/test_fabric_credentials.py`, `tests/integration/test_fabric_credentials_store.py`; modify `config.py`, `connections/source_config.py`.

**Interfaces:** Produces FabricConfig, FabricCredentialContext, FabricCredentialStore. Consumes the existing asyncpg pool and secret resolver; no provider requests.

- [ ] Write failing config tests: require host/database/tenant/client; default port 1433; accept exactly the three endpoint types/two auth modes; require SPN secret reference; reject literal tokens/passwords, DSN/auth/driver overrides, malformed host/ODBC injection, zero limits. Assert Fabric keys cannot weaken verified TLS.
- [ ] Write failing store tests: ciphertext does not contain token data; wrong/missing key fails closed; versioned-key rotation can read old records and write new; source deletion cascades credentials; invalidate increments generation; state expires after 600 seconds, matches session/source/config generation, and can be consumed only once. Model revisions and concurrent refresh with real PostgreSQL in integration tests.
- [ ] Run `uv run pytest tests/unit/test_fabric_config.py tests/unit/test_fabric_credentials.py -q`; confirm missing-interface failures before code.
- [ ] Implement configuration and the migration. Use encrypted MSAL cache/pending-flow blobs with an operator-provided versioned Fernet keyring resolved from secret references (existing cryptography dependency). Set token fields `repr=False`. Store source ownership/status/generation separately from encrypted bytes. Use explicit database transactions and row locks for lifecycle transitions; no raw secrets in source configuration.
- [ ] Add async encrypted load/save/pending-state helpers needed by FabricAuth, with expected-generation/revision checks. Implement the locked context manager and save_cache/save_pending/consume_pending methods from the shared contract; enforce a bounded lock/refresh deadline. A canceled refresh must release its transaction and lock without accepting an obsolete generation.
- [ ] Verify unit tests and `INTEGRATION_TEST=1 uv run pytest tests/integration/test_fabric_credentials_store.py -q` against an isolated disposable control database. Verify migration on clean schema and repeat-run behavior via existing migration tooling.
- [ ] Commit `feat: add Fabric configuration and encrypted credential state`.

### Task 2: OAuth and SPN token lifecycle

**Files:** Create `fabric/auth.py`, `tests/unit/test_fabric_auth.py`; modify `pyproject.toml`, `uv.lock`, `requirements-production.txt`.

**Interfaces:** Consumes Task 1 store/config; produces FabricToken and FabricAuth methods from the contract.

- [ ] Write failing MSAL-mocked tests: SPN uses configured tenant/client/secret and SQL scope only; never calls default credentials; token cache hit versus refresh with 120-second skew; secrets never appear in repr/errors. OAuth tests require the source client_id to match the configured operator OAuth registration and source tenant_id to match an explicit operator tenant allowlist; assert PKCE and state binding, one-time callback, wrong tenant rejection, reconnect to a different account, lost-consent state, and encrypted cache persistence after process restart.
- [ ] Add concurrency tests: two service instances refreshing the same source retain the latest cache; invalidate while refresh is in flight prevents saving/using the old generation. Rotation reads the current configured secret and requires a new generation; interaction-required emits a stable reconnect-needed error without rows.
- [ ] Run `uv run pytest tests/unit/test_fabric_auth.py -q`; confirm failures.
- [ ] Add MSAL as a Fabric runtime extra using `uv add --optional fabric-sql msal pyodbc`; retain existing pyodbc tier2 compatibility and resolve a consistent version. Include the extra in published production/worker extras; refresh the lock/export through existing Makefile export target.
- [ ] Implement FabricAuth with tenant-specific ConfidentialClientApplication. Keep MSAL blocking I/O off the event loop; use the Task 1 locked store path for cache synchronization. Request offline renewal through MSAL's supported defaults; do not manually add reserved scopes. Map provider responses to sanitized authentication-required/denied/unavailable states.
- [ ] On begin/complete, bind the OAuth registration/tenant/config generation, allow one selected returned account, and store only minimal account identifiers/display metadata. Persist all flow secrets encrypted; callback must recheck current admin/session ownership in Task 7.
- [ ] Run Task 1+2 tests and `uv run ruff check src/interlock/connections/fabric tests/unit/test_fabric*.py`. Verify resolved Python dependencies contain MSAL/pyodbc for both production extras.
- [ ] Commit `feat: implement Fabric OAuth and SPN authentication`.

### Task 3: Bounded token-authenticated SQL Server transport

**Files:** Create `connections/sqlserver.py`, `tests/unit/test_sqlserver_transport.py`, `tests/integration/test_sqlserver_transport.py`.

**Interfaces:** Consumes FabricConfig/FabricToken; produces SqlServerTransport.execute/close.

- [ ] Write failing fake-driver tests for ODBC 18, token packing (length-prefixed UTF-16LE), Encrypt=yes, TrustServerCertificate=no, and absence of UID/PWD/Authentication. Assert values bind through qmark parameters unchanged, handles always close, ODBC pooling is disabled before first connection, and no driver/DSN override is accepted.
- [ ] Add timeout/cancellation/queue tests proving 8-operation/16-waiter bounds, cancellation reaches cursor.cancel, connection cleanup completes, and a write is never retried after submission. Add fetchmany tests for 1,001 rows, 8 MiB + 1 byte, duplicate names, types from the contract, multiple result sets, commit/rollback, and unknown affected-row count.
- [ ] Run `uv run pytest tests/unit/test_sqlserver_transport.py -q`; confirm failures.
- [ ] Implement bounded worker execution with driver login/statement timeouts plus active cancellation and a bounded cleanup deadline. Do not use asyncio.wait_for as the sole cancellation mechanism. Validate endpoint egress once at the connection boundary and escape database identifiers/connection-string fields safely.
- [ ] Implement incremental fetch/serialization with the contract's explicit limits. Single DML execution owns a transaction: consume/validate OUTPUT before commit; rollback on result errors. Do not silently discard additional result sets; reject unsupported shapes and rollback writes.
- [ ] Verify unit tests; run isolated SQL Server integration tests for transaction/cancel behavior where a test driver/server is available. Mark those tests skipped explicitly when absent; mock passing does not certify driver cancellation.
- [ ] Commit `feat: add bounded Entra token SQL Server transport`.

### Task 4: Fabric adapter, registry, T-SQL enforcement, and service wiring

**Files:** Create `fabric/adapter.py`, `fabric/runtime.py`, `tests/unit/test_fabric_adapter.py`, `tests/unit/test_fabric_runtime.py`; modify `connections/connectors.py`, `core/normalizer.py`, `connections/manager.py`, `gateway/mcp_adapter.py`, `core/approval_queue.py`, `admin/app.py`, `gateway/app.py`, `worker/__main__.py`, `worker/loop.py`, `metadata/registry.py` as needed for lifecycle state.

**Interfaces:** Consumes Tasks 1–3; produces FabricServices, FabricSQLAdapter, optional get_adapter injection. Keeps existing adapter and manager interfaces backwards-compatible.

- [ ] Write failing adapter tests for probe SELECT 1, existing result envelope, permission extraction, and `fabric_sql -> tsql` across TOP/brackets/CTEs/joins. Deny SELECT INTO, batches, EXEC/dynamic SQL, MERGE, DDL, unsupported table functions, linked-server/four-part references, and cross-database three-part references before driver execution. Allow same-database qualification only after normalizing it into the schema/table enforcement scope; ambiguous qualification fails closed.
- [ ] Test INSERT/UPDATE/DELETE recognition independently; lakehouse_sql rejects table DML before token acquisition. Configuring warehouse/sql_database does not itself grant writes. Test services absent, source_id absent, and metadata trying to supply runtime objects fail safely.
- [ ] Run `uv run pytest tests/unit/test_fabric_adapter.py tests/unit/test_fabric_runtime.py -q`; confirm failures.
- [ ] Implement the adapter, register a dedicated definition with deterministic cache strategy, database role templates, and no ingestion/incremental/proxy claims. Keep generic mssql planned. Break the registry/adapter circular import using a lazy Fabric import in get_adapter. Add T-SQL mapping; reuse existing parser helpers while enforcing the narrower supported statement contract in one Fabric SQL validation owner.
- [ ] Create one FabricServices container per process from the existing control pool, settings, and key references. Pass it explicitly through ConnectionManager/ApprovalQueue constructors and CollectContext; supply source_id to adapter creation for probes, queries, introspection, approvals, and workers. Pure permission parsing in dashboard routes stays stateless. Add optional keyword args rather than leaking dependencies through source metadata or globals.
- [ ] Close auth clients/transport on shutdown and tolerate absent Fabric settings when no Fabric source is used. A configured Fabric source with missing auth settings reports unavailable; it does not disable unrelated connectors.
- [ ] Run targeted tests plus `uv run pytest tests/unit/test_connector_registry.py tests/unit/test_source_onboarding_routes.py tests/unit/test_approval_queue.py -q` and `make type-v1`.
- [ ] Commit `feat: register Fabric SQL adapter across runtime paths`.

### Task 5: Current-identity cache barriers and lifecycle edits

**Files:** Create `tests/unit/test_fabric_cache_scope.py`, `tests/integration/test_fabric_lifecycle.py`; modify `gateway/mcp_adapter.py`, `admin/routes/data_sources.py`, `admin/routes/dashboard.py`, `admin/source_cache.py`, Fabric credential/runtime modules; modify the actual cache-key helper only if extending its existing source-generation input cannot express the identity dimension.

**Interfaces:** Consumes current FabricCredentialContext and existing SourceGenerationBarrier. Produces an authenticated-source context required before cached data can be returned.

- [ ] Write failing tests for warmed-cache disconnect, account replacement, endpoint/database/auth edit, SPN secret rotation, expired credentials, stale gateway registry, invalidation failure, and an in-flight old-generation read finishing after a change. Assert old results are neither served under new credentials nor written into a current namespace.
- [ ] Run `uv run pytest tests/unit/test_fabric_cache_scope.py -q`; confirm failures.
- [ ] Resolve current Fabric state before cache lookup, using authoritative credential generation rather than asynchronously refreshed source metadata. Combine its stable non-secret identity/generation scope with existing source_generation/role/policy cache keying; preserve other connectors' key formats. Silent credential renewal must succeed before a result is served for a Fabric source needing renewal; unavailable identity state fails closed.
- [ ] Make lifecycle transitions invalidate generation in the same control-database transaction as endpoint/auth/source changes. OAuth disconnect also deletes cached credentials; ordinary token refresh does not bump generation. Enforce this through both API and dashboard mutation paths. Publish existing config/cache notifications after commit; generation checks remain authoritative when notifications fail or lag.
- [ ] Verify invalidation covers every enabled result tier and retained background fetches. Make cached audit provenance identify the current configured upstream principal without exposing refresh/access tokens.
- [ ] Run Task 5 tests plus `uv run pytest tests/unit/test_cache_key_format.py tests/unit/test_p0_c_cache_key_identity_scope.py tests/unit/test_cache_invalidation_wiring.py tests/unit/test_disabled_source_serves_nothing.py -q`. Run multi-instance lifecycle integration against isolated control PostgreSQL/Redis.
- [ ] Commit `feat: scope Fabric cached results to current credentials`.

### Task 6: Catalog and governed write acceptance

**Files:** Create `catalog/collectors/fabric.py`, `tests/unit/test_fabric_catalog.py`, `tests/unit/test_fabric_governance.py`; modify `catalog/collectors/__init__.py`, `catalog/validation.py`, `core/approval_queue.py`, `connections/role_vocabulary.py`, `gateway/mcp_adapter.py` where required by tested integration.

**Interfaces:** Consumes adapter.metadata_snapshot and existing CollectContext/CatalogSnapshot/ScanLimits; produces collect_fabric and enforced database resources. Consumes Task 5 current-generation checks in approval execution.

- [x] Write failing metadata tests for schemas/tables/views/columns, least-privilege visibility, multiple schemas, case/quoted names, limits, complete_subtrees, truncated scans that do not imply removals, empty catalogs, and permission errors. Assert only metadata SQL executes and no customer rows enter catalog state.
- [x] Write governance tests for table/column role restrictions, star projection, CTEs/joins, named-column redaction, audit success/error, and missing/stale catalog behavior consistent with existing enforced SQL connectors. Test read-role DML denial, approval required by existing classifier, current policy/role/source/auth recheck at approval, and generation/account changes invalidating pending approval execution.
- [x] Run `uv run pytest tests/unit/test_fabric_catalog.py tests/unit/test_fabric_governance.py -q`; confirm failures.
- [x] Implement metadata queries using the same auth/transport and registered database. Build typed CatalogSnapshots respecting existing scan completion semantics. Add Fabric to collector registry and ENFORCED_CONNECTOR_KEYS together, not before collector correctness passes.
- [x] Preserve InterLock's existing risk rules: low-risk writes may execute immediately if existing policy permits; queued writes execute only after current-state checks. Store the non-secret Fabric credential generation with queued Fabric writes; a changed generation requires resubmission, never execution using a replacement account. No retry after an uncertain write outcome.
- [x] Verify the factory uses connector_key rather than generic source_type='database' when executing approved Fabric writes. Add audit evidence for execution failure instead of reporting a successful approval with no write.
- [x] Run targeted tests plus `uv run pytest tests/unit/test_catalog_validation.py tests/unit/test_source_roles.py tests/unit/test_approval_structured_writes.py -q`; use isolated integration tests for commit/rollback and approval concurrency.
- [x] Commit `feat: enforce Fabric catalog permissions and governed writes`.

**Task 6 builder corrections:** Metadata uses bounded keyset system-view pages under one authenticated identity. CatalogSnapshot carries an internal FabricCurrentSource publication binding; the runner applies with the exact guard_current connection. Different-generation/incarnation partial snapshots tombstone unseen prior inventory; same-identity truncation preserves it. Fabric naming reads verify the root identity against current credentials. GatewayDecision carries the trusted original upstream_identity, required before Fabric cache/origin use; SQL parameters are included in cache identity and queue execution. Fresh approval acceptance reloads original actor/grants/policy/catalog after authentication, skips only the already-satisfied queue decision, and records sanitized execution success/error audit. Native relation_types are retained by the naming resolver; the shared Fabric governance owner permits writes only to catalog-verified table targets, never views or unknown types. Fabric-only lineage covers unions/scalar subqueries; structured FOR XML/JSON and wildcard projections inside set operations/scalar subqueries or beneath positional CTE/derived-column aliases are centrally unsupported because fixed output aliases can hide changed origins. No synthetic runtime fixtures, global authentication mode, business-record holds or live customer/provider access were introduced. See task-6-report.md in the SDD handoff directory for exact interfaces and test evidence.

### Task 7: Admin OAuth flow, source setup, and Fabric logo

**Files:** Create `admin/routes/fabric_auth.py`, `admin/templates/partials/fabric_connection_fields.html`, `admin/static/assets/connectors/fabric.svg`, `tests/unit/test_fabric_auth_routes.py`, `tests/dashboard/test_fabric_onboarding.py`; modify `admin/app.py`, `admin/routes/dashboard.py`, `admin/routes/data_sources.py`, `admin/templates/partials/source_wizard_modal.html`, `admin/templates/partials/data_source_form.html`, `admin/templates/partials/data_sources_table.html`, `admin/templates/pages/data_source_detail.html` and the existing connector-picker rendering partial identified there.

**Interfaces:** Consumes FabricAuth/Store services. Produces POST `/api/data-sources/{source_id}/fabric/connect`, GET `/api/fabric/oauth/callback`, GET `/api/data-sources/{source_id}/fabric/auth-status`, POST `/api/data-sources/{source_id}/fabric/disconnect`, POST `/api/data-sources/{source_id}/fabric/rotate` (SPN only).

- [ ] Write failing route tests for existing admin authentication/CSRF, source ownership/connector checks, safe return paths, callback session/state binding, replay, expiry, consent denied, account/tenant mismatch, and configuration edited while login is pending. Assert no raw provider errors/token values/secret references leak from status and responses.
- [ ] Write rendered-form tests for endpoint/auth selectors, conditional SPN fields plus Rotate credentials versus OAuth Connect/Reconnect/Disconnect, disabled actions for incomplete setup, minimal connected-account display, and the green Fabric logo in picker/list/detail with accessible text.
- [ ] Run `uv run pytest tests/unit/test_fabric_auth_routes.py tests/dashboard/test_fabric_onboarding.py -q`; confirm failures.
- [ ] Implement routes using existing admin authorization, CSRF, and audit patterns. Use an operator-registered fixed callback URI; do not derive it from arbitrary Host/Forwarded headers. Store pending MSAL flow server-side encrypted, bind it to an opaque admin session nonce, and redirect only to approved internal source pages. Allow saving an OAuth source before it has credentials, with an explicit needs-sign-in state.
- [ ] Implement one form for all endpoint types; keep technical token/driver internals out of normal user flows. Reuse safe source edit lifecycle code from Task 5. Test Connection uses source-bound services and does not create an implicit ingestion job. The SPN Rotate action increments the source credential generation even when its secret reference string is unchanged; re-resolve the secret on the next acquire and purge local application-token caches. Do not silently reuse a token acquired under the old secret.
- [ ] Obtain the official green Fabric F SVG from a Microsoft source during implementation, record provenance/usage terms alongside the asset, sanitize embedded SVG content, and serve it locally; do not invent a substitute F or hotlink runtime UI assets. Follow existing icon sizing/theme conventions.
- [ ] Verify rendered tests and the UI in the Codex in-app browser against a disposable/local preview. Do not log into a real customer tenant until the selector and intended identity are verified; interactive sign-in remains a user step.
- [ ] Commit `feat: add Fabric OAuth onboarding and connector branding`.

### Task 8: Container support, live matrix, and operator documentation

**Files:** Modify `Dockerfile`, `docker-compose.yml`, `deploy/helm/interlock/values.yaml`, `deploy/helm/interlock/templates/secret.yaml`, `deploy/helm/interlock/templates/admin-deployment.yaml`, `deploy/helm/interlock/templates/gateway-deployment.yaml`, `deploy/helm/interlock/templates/worker-deployment.yaml`, `config.example.yaml`, `docs-site/src/content/docs/reference/connector-support-matrix.md`; create `docs-site/src/content/docs/guides/fabric-sql.md`, `tests/integration/test_fabric_live.py`, `tests/e2e/test_fabric_connector.py`, `tools/check_fabric_image.py`.

**Interfaces:** Consumes all prior tasks. Produces operator settings for OAuth app/registered callback and versioned credential-encryption-key references, plus opt-in six-cell live acceptance tooling. No customer credentials are committed.

- [ ] Add failing tests/tool checks that the production and worker images load MSAL/pyodbc and ODBC Driver 18 while running as the existing non-root user; test settings/callback/key mounts are consistently supplied to all required processes and disabled-by-default configuration preserves unrelated quickstart behavior.
- [ ] Build with the actual supported Microsoft repository/package for the current Debian base and verify amd64/arm64 separately. Preserve license acceptance and existing least-privilege image setup. If the base is unsupported, document and implement an explicitly reviewed compatible-base change; do not silently change distro or architectures.
- [ ] Add `pytest.mark.live` tests parameterized over the three endpoint types and both auth modes. A live manifest must explicitly designate customer, tenant, workspace/database, and expected upstream identity; skip absent cells and report them unverified. Use the project selector check before obtaining credentials. OAuth login/bootstrap is user-operated through the approved flow, with no token pasted into fixtures.
- [ ] For each supplied cell verify connection, bounded SELECT, catalog visibility, denial, redaction, audit, restart/refresh; verify reconnect, lost consent, SPN rotation and multi-instance cache lifecycle across appropriate shared cases. Test writes only against disposable objects that the user has explicitly authorized; otherwise mark write acceptance pending. Verify Lakehouse table mutation rejection without sending destructive SQL.
- [ ] Exercise real token packing, login/statement cancellation, TLS certificate failure, and ODBC redirects under deployment egress controls. A policy bypass via driver redirects is a release blocker; do not present hostname validation alone as complete egress enforcement.
- [ ] Run `make lint`, `make type`, `make test-unit`, `make test-integration`, `make requirements-production-check`, and `make helm-render`; use separate disposable Compose project/ports for Fabric e2e tests. Do not reuse the current evaluation database as a test fixture. Run only the additional regression/e2e suites justified by changed paths.
- [ ] Document registration/consent, Fabric item and SQL grants, OAuth reconnect, SPN rotation, encryption-key backup/rotation, endpoint behavior, current known limitations, and exact verified matrix. Keep permission grants an administrator operation, never an automatic connector side effect. Regenerate generated reference pages with existing tooling when registry metadata changes.
- [ ] Commit `feat: package and certify Fabric SQL connector`.

## Self-review and handoff

All agreed requirements map to Tasks 1–8: auth/config/state (1–2), SQL transport (3), connector/process paths (4), identity-scoped cache/edit behavior (5), catalog/governance/writes (6), onboarding/green logo (7), deployment/live proof/docs (8). Each Review Focus condition has an owning test task. New module boundaries avoid extending the large registry with implementation bodies. The optional get_adapter arguments preserve existing connectors; runtime service ownership and source_id are explicit across every I/O caller.

Implementation must not claim six-cell certification without actual evidence. Missing credentials, endpoints, packaging support, or required user login must appear in the final verification report. Testing tools must not write customer objects without the disposable-object authorization described above.

This plan creates no application behavior. The fork/feature branch are already authorized. Before starting implementation, have the user review the plan and choose subagent-driven or native execution per the invoked writing-plans skill. Prefer subagent-driven execution for this change because authentication, concurrent credential state, cached results, and queued writes cross trust boundaries and benefit from independent task reviews.
