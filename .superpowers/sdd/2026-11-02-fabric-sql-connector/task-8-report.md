# Task 8 — package Fabric SQL connector

Status: **DONE_WITH_CONCERNS**. Packaging, operator configuration/docs, opt-in
acceptance tooling and local gates are implemented. **No six-cell native/live
certification is claimed.** No native customer credentials/endpoints were supplied.
No source objects/grants/policies were created in a customer system, and no global
login, external browser or browser installation was used.

Base: `cdb0631`, branch `work/fabric-sql-implementation`.
Commit subject: `feat: package Fabric SQL connector` (truthful replacement for the
plan's "package and certify" subject).

## Implemented

- Retained `python:3.12-slim`; actual builds use Debian 13 (trixie). Build stage
  installs unixODBC headers/C++ compiler for pyodbc fallback. Runtime installs
  Microsoft `msodbcsql18` from the matching Debian Microsoft package repository,
  with explicit `ACCEPT_EULA=Y`, CA roots and required Kerberos shared library.
  Unsupported distro/architecture fails rather than silently changing the base.
  Existing uid/gid 1000, non-root user, image entry point and multi-stage design
  are preserved. SDK dependencies were already present in locked production extras.
- `tools/check_fabric_image.py` runs under the image's default user and verifies
  expected architecture, uid/gid, imports, Driver 18 registration, and actual
  `ctypes.CDLL` native library load. It does not connect to any database.
- Disabled-by-default Compose environment forwarding uses inherited-null entries;
  absent secret references do not become invalid empty strings. The explicit
  `docker-compose.fabric.yml` overlay mounts the same private directory read-only
  in admin/gateway/both workers. No default encryption key or credential exists.
- Helm's opt-in Fabric values require an existing operator-managed Secret, a
  valid active key version, and complete OAuth app/callback/secret/tenant settings
  when OAuth is configured. All three process types receive the same settings
  and read-only versioned key files (`0440`, existing fsGroup). Secret values are
  never embedded in values/rendered manifests. Defaults retain unrelated startup.
- Private manifest accepts only explicit customer/project, endpoint/auth cell,
  source ID, tenant/workspace/database/server/application and expected saved SQL
  identity/account. Unknown fields/credentials, duplicate cells, unassigned
  customers and incomplete identity scope fail. Validation errors omit input
  values. A supplied cell must match its current saved source/credential context
  before token acquisition. The project selector must confirm the customer/tenant
  and enabled SQL selection before a control pool or credential is accessed.
  `FABRIC_LIVE_CONFIG_PATH` must explicitly designate the control database; it
  cannot silently use evaluation DB defaults. OAuth bootstrap remains user-operated
  through the console; pasted access tokens and ambient login are not accepted.
- Six-cell opt-in pytest inventory gives each acceptance dimension a separate
  result. Implemented native probes cover real token packing/connection, bounded
  DB/principal SELECT, visible catalog, and Lakehouse mutation rejection without
  SQL submission. Missing cells are unverified. Remaining dimensions are explicitly
  pending, never substituted with mocks or reported as certified.
- Existing optional native transport probes now consume the same saved-source
  manifest. Unique disposable SQL Database table creation/drop requires explicit
  source-specific write authorization. Generic transport OUTPUT tests do not
  enable OUTPUT in the Fabric adapter. Cancellation requires explicit server
  observation authorization and verifies positive visibility of the original
  active server request, completion of the original worker, successful native
  cursor/connection close, and disappearance of that request. Caller return
  latency or a successful query on a spare worker cannot satisfy this test.
- Added isolated HTTP/template packaging e2e with fresh Compose project/volumes,
  separate ports and explicitly cleared model-provider keys. It verifies default
  startup, admin login, connector activation -> New Source picker, and auth
  boundaries. Root additionally inspected the actual Docker UI in the in-app
  browser: login -> activate Fabric beta -> New Source/green F -> all three endpoint
  choices -> OAuth/SPN field toggles -> unsaved probe disabled. No source/login to
  Microsoft was attempted. This is not native SQL or exhaustive visual acceptance.
- Operator guide covers activation, registration/consent, item/SQL grants,
  reconnect, SPN rotation, key backup/rotation, endpoint behavior, limits, exact
  unverified native matrix and release blockers. Updated support matrix/setup
  guide/sidebar/config example; regenerated API/config/connector references.
  Corrected the reference generator's handling of already-suffixed secret refs so
  Fabric documents `client_secret_ref`, not an invalid doubled suffix.

## TDD and integration corrections

Evidence logs are durable under `build/fabric-task8-evidence/` (ignored build
artifacts, not committed). They include initial failures as well as final results.

1. `PATH=/Users/avouk/.local/share/mise/installs/helm/3.19.2/darwin-arm64:$PATH uv run pytest tests/unit/test_fabric_packaging.py -q`
   RED: 4 failed, 1 passed before implementation: enabled Helm omitted key/settings,
   incomplete enabled config rendered successfully, Compose omitted forwarding,
   image probe did not exist (`fabric-task8-red.log`). Initial execution without
   Helm on PATH also failed; reran with the installed Helm before implementation.
   GREEN initially 5 passed; subsequent OAuth completeness, Compose mount and
   generated-secret-reference checks expanded the suite.
2. `uv run pytest tests/unit/test_fabric_live_manifest.py -q`
   RED: 10 failed because manifest tooling was absent
   (`fabric-task8-manifest-red.log`); GREEN initially 10 passed.
   Additional explicit-control-settings guard RED failed before the helper existed
   (`control-config-red.log`), then passed after implementation.
3. OAuth Helm completeness RED: 1 failed, 6 passed: missing client-secret key was
   accepted (`fabric-task8-oauth-red.log`). Added validation; GREEN passes.
   Reference-generation RED: 1 failed, 7 passed because of doubled secret suffix
   (`fabric-task8-docs-red.log`). Corrected generator; GREEN passes.
4. First full gates exposed branch integration gaps: missing Fabric field
   descriptions/docs inventory/sidebar; stale migration inventories through 019;
   a production-worker extras snapshot missing fabric-sql; an obsolete Task 4
   approval test using `object()` for the control pool. Fixed descriptions/docs/
   inventories. With controller approval, removed the obsolete mock-pool unit
   test rather than bypassing fresh governance. The existing stronger real-PG
   `test_transport_failure_is_failed_once_and_audited_without_echoing_values`
   proves failed status, sanitized audit and exactly one transport invocation;
   explicit focused run: **1 passed** (`approval-regression-final.log`).
5. Full strict type RED: 9 new Fabric branch diagnostics in policy normalizer and
   sqlglot scope traversal (`type.log`, `type-current-focused-red.log`). Comparison
   against `44f2742` versions in the same environment passes
   (`type-base.log`); thus these were branch integration issues, not baseline.
   Added a typed local normalizer and explicit cast at sqlglot's documented
   untyped post-order iterator boundary; no behavior or authorization change.
   Full strict + V1 gate now passes (`type-final.log`).
6. A full integration run during image builds exposed a race in the test's
   `sleep(.03)` assumption: a pending revocation coroutine had not necessarily
   reached PostgreSQL's lock queue. Original failure preserved in
   `test-integration-final.log`: DID NOT RAISE in
   `test_invalidation_queued_during_refresh_prevents_delivery_of_old_generation`.
   With controller approval, used an explicitly borrowed revocation connection
   and positive `pg_blocking_pids` waiter barrier before releasing refresh. Kept
   the rejection/code/cache/status assertions. Focused GREEN: **1 passed**
   (`auth-waiter-green.log`); corrected full integration GREEN below. No production
   authentication semantics were changed.
7. Final portability adjustment lets rendered Helm unit checks skip when the CLI
   is absent (the explicit Helm gate remains mandatory). A missing pytest import
   briefly caused collection failure; corrected before final focused checks.
   No failing result is claimed as passing.

Final focused command:

```sh
PATH=/Users/avouk/.local/share/mise/installs/helm/3.19.2/darwin-arm64:$PATH \
  uv run pytest tests/unit/test_fabric_packaging.py tests/unit/test_fabric_live_manifest.py \
  tests/integration/test_fabric_live.py tests/integration/test_sqlserver_transport.py -q
```

Result: **19 passed, 106 skipped**, 1.04s
(`packaging-manifest-final.log`). All 106 native skips are unverified, not success.

## Full gates

The following shared environment was used; it targets only the designated
synthetic test PostgreSQL/Redis, never evaluation ports 5433/6380:

```sh
export PATH=/Users/avouk/.local/share/mise/installs/helm/3.19.2/darwin-arm64:$PATH
export TEST_PG_HOST=127.0.0.1 TEST_PG_PORT=15433 TEST_PG_USER=onyx
export TEST_PG_PASSWORD=onyx_dev TEST_PG_DATABASE=onyx
export TEST_REDIS_URL=redis://127.0.0.1:16380/0
export ANTHROPIC_API_KEY= MISTRAL_API_KEY=
```

| Command | Final result | Log |
| --- | --- | --- |
| `make lint` | exit 0; ruff + black, 478 files unchanged | `lint-corrected-final.log` |
| `make type` | exit 0; strict 60 files; V1 91 checked/57 strict-clean/126 pinned diagnostics | `type-final.log` |
| `make test-unit` | exit 0; 3,672 passed, 9 skipped, 7 warnings | `test-unit-final.log` |
| `make test-integration` | exit 0; 142 passed, 1 skipped, 112 deselected | `test-integration-corrected-final.log` |
| `make requirements-production-check` | exit 0; locked export unchanged | `requirements-production-check-final.log` |
| `make helm-render` | exit 0; default + certification values | `helm-render-final.log` |
| `uv run python tools/docs/generate.py --check` | exit 0 | `docs-check-final.log` |
| `git diff --check` | exit 0 | checked before commit |

Full suites were not blindly repeated: initial failures led to the narrow fixes
above, followed by corrected affected gates. The final isolated harness-only
control-settings addition/Helm portability adjustment was verified by the focused
19-pass run and final lint; it adds one test beyond the 3,672-pass full-unit run.

Warnings were not suppressed: Starlette/httpx and AnyIO deprecations, Authlib
jose deprecation, two expected legacy ONYX-prefix deprecations, and two MSAL
warnings recommending form_post rather than the existing GET callback flow.
No MSAL callback-mode architectural change was made in Task 8.

## Separate image architecture evidence

For each row, executed the actual build independently (no manifest-only claim):

```sh
docker buildx build --platform linux/ARCH --load \
  --build-arg INTERLOCK_EXTRA=EXTRA -t interlock-fabric-task8:ARCH-VARIANT .
docker run --rm --platform linux/ARCH --entrypoint python \
  -v "$PWD/tools/check_fabric_image.py:/tmp/check.py:ro" \
  interlock-fabric-task8:ARCH-VARIANT /tmp/check.py --architecture ARCH
```

`ARCH` is arm64 or amd64; `VARIANT/EXTRA` is production/production or
worker/production-worker. All four final-source builds and probes exited **0**.
Logs: `ARCH-VARIANT-build-final.log` and `ARCH-VARIANT-probe-final.log`.
AMD64 executes through Docker Desktop emulation on the ARM64 host, not physical
Intel hardware; this is packaging/load evidence, not native service certification.

Every row reports Debian GNU/Linux 13 (trixie), MSAL **1.39.0**, pyodbc **5.3.0**,
msodbcsql18 **18.7.1.1-1**, successful shared-library load, uid/gid **1000/1000**.

| Image tag suffix | Architecture | Final local image ID |
| --- | --- | --- |
| arm64-production | aarch64 | `sha256:a83ae3e1b4a3b92a18023a4d225d4a911fe9815a3b1ff9d52b5eeb41cdddf3a7` |
| amd64-production | x86_64 | `sha256:530458c24864e6dc6b99afbcd81548d46a3396790b765c2513979f039f8a364f` |
| arm64-worker | aarch64 | `sha256:5cf3914074d89e5527ed15a499338e1d9673de5964e9e01b33e3f975d8fe8e97` |
| amd64-worker | x86_64 | `sha256:5781709c48f7b8184f56592850e9101c1b26cdb1d719893ca352eb58f5e63e0e` |

Image IDs/user/architecture were independently inspected (`images-final.log`).

## Isolated e2e and preserved scope

```sh
docker compose -p interlock-fabric-task8 -f docker-compose.yml \
  -f docker-compose.fabric-e2e.yml up -d --no-build --wait \
  postgres redis migration admin gateway
INTERLOCK_E2E=1 INTERLOCK_E2E_SKIP_SEED=1 FABRIC_PACKAGING_E2E=1 \
  uv run pytest tests/e2e/test_fabric_connector.py -q
docker compose -p interlock-fabric-task8 -f docker-compose.yml \
  -f docker-compose.fabric-e2e.yml down -v
```

Final result: **1 passed**, 0.24s (`e2e-final.log`), final-source production image.
Fresh isolated volumes were removed; no original stack containers/volumes were
restarted or modified. Verified original admin9090/gateway3001/controlPG5433/
Redis6380 still running. Dedicated test PG15433/Redis16380 also remain available.
`.codex/` is untouched/untracked and excluded from this commit. Images remain
locally available for review; nothing was pushed, merged or deployed to the
original evaluation stack.

## Native matrix and remaining acceptance

| Endpoint | OAuth | SPN |
| --- | --- | --- |
| Warehouse | Unverified — no supplied native cell | Unverified — no supplied native cell |
| Lakehouse SQL analytics | Unverified — no supplied native cell | Unverified — no supplied native cell |
| SQL Database | Unverified — no supplied native cell | Unverified — no supplied native cell |

No native connection/token packing, expiry/refresh, catalog metadata/case/visibility,
real read or write acceptance is claimed. All cells lack actual Microsoft/ODBC
runtime evidence. The harness designates workspace but does not independently
query Fabric control-plane membership; operators verify ownership beforehand.

Denial/redaction/audit, restart/refresh, OAuth reconnect/lost consent, SPN rotation,
multi-instance cache lifecycle, login cancellation, statement cancellation, TLS
certificate failure and driver redirects need designated operator scenarios/
fixtures and remain pending. The harness records these dimensions separately; it
does not implement a new live governance framework or automatic policy/grant seed.
Writes require explicitly authorized disposable objects; write acceptance pending.
Native cancellation's stronger probe is implemented but unrun. Native shutdown
still requires an external process/container deadline for stuck calls.

**Redirect policy bypass is a release blocker.** Initial hostname validation does
not pin DNS or enforce subsequent driver destinations. Deployment egress controls
and actual traffic/blocked-redirect proof remain unverified. Do not release based
on this package/load evidence alone.

Preserved initial limits: table-only single-target INSERT VALUES/UPDATE/DELETE,
no OUTPUT/mixed-read DML, view writes, MERGE/DDL/procedures/admin commands; Lakehouse
read-only; structured XML/JSON/PIVOT/UNPIVOT/APPLY and unresolvable lineage shapes
refused; no ingestion, incremental sync, OBO, global/default identity, TDS listener,
PostgreSQL translation, certificates, automatic grants or VectorETL integration.

## Microsoft primary-source verification (2026-11-02)

- [Linux driver install/repository/EULA and Debian support](https://learn.microsoft.com/en-us/sql/connect/odbc/linux/installing-the-microsoft-odbc-driver-for-sql-server-on-linux)
- [Driver downloads/platform release information](https://learn.microsoft.com/en-us/sql/connect/odbc/download-odbc-driver-for-sql-server)
- [Fabric SQL endpoint discovery](https://learn.microsoft.com/en-us/fabric/database/sql/connect)
- [Warehouse SPN/item/data permissions](https://learn.microsoft.com/en-us/fabric/data-warehouse/service-principals)
- [MSAL token acquisition](https://learn.microsoft.com/en-us/entra/msal/python/getting-started/acquiring-tokens)
- [Fabric allowlist](https://github.com/MicrosoftDocs/fabric-docs/blob/main/docs/security/fabric-allow-list-urls.md)

Actual per-architecture package/load results above, rather than documentary
support alone, establish the limited packaging claim.

## Self-review and changed files

Reviewed runtime/build boundaries, default startup, shared settings/mounts,
reference-generation output, opt-in manifest/authorization gates, original-worker
and server-operation cancellation evidence, egress limitations, and scope wording.
No remaining known implementation failure; native acceptance gaps above are material.

Changed files are enumerated below.
- `Dockerfile`
- `config.example.yaml`
- `deploy/helm/interlock/templates/_helpers.tpl`
- `deploy/helm/interlock/templates/admin-deployment.yaml`
- `deploy/helm/interlock/templates/gateway-deployment.yaml`
- `deploy/helm/interlock/templates/secret.yaml`
- `deploy/helm/interlock/templates/worker-deployment.yaml`
- `deploy/helm/interlock/values.yaml`
- `docker-compose.fabric-e2e.yml`
- `docker-compose.fabric.yml`
- `docker-compose.yml`
- `docs-site/public/admin-api/openapi.json`
- `docs-site/sidebar.json`
- `docs-site/src/content/docs/get-started/setup-walkthrough.md`
- `docs-site/src/content/docs/guides/fabric-sql.md`
- `docs-site/src/content/docs/reference/admin-api.md`
- `docs-site/src/content/docs/reference/configuration.md`
- `docs-site/src/content/docs/reference/connector-support-matrix.md`
- `docs-site/src/content/docs/reference/connectors/fabric_sql.md`
- `docs-site/src/content/docs/reference/connectors/index.md`
- `src/interlock/config.py`
- `src/interlock/core/policy.py`
- `src/interlock/core/sql_columns.py`
- `tests/e2e/test_fabric_connector.py`
- `tests/integration/fabric_live_support.py`
- `tests/integration/test_fabric_auth.py`
- `tests/integration/test_fabric_live.py`
- `tests/integration/test_sqlserver_transport.py`
- `tests/unit/test_connector_matrix_reconciliation.py`
- `tests/unit/test_fabric_live_manifest.py`
- `tests/unit/test_fabric_packaging.py`
- `tests/unit/test_fabric_runtime.py`
- `tests/unit/test_migration_runner.py`
- `tests/unit/test_mvp_status_docs.py`
- `tools/check_fabric_image.py`
- `tools/docs/generate.py`
- `.superpowers/sdd/2026-11-02-fabric-sql-connector/task-8-report.md`
