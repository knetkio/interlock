---
title: "Setup walkthrough"
description: "Set InterLock up end to end: a source, roles, an agent identity and key, a connected agent, and proof it was governed."
sidebar:
  order: 4
---

This guide takes an InterLock install from empty to an AI agent running a
governed query: register a target system, authorize access to it, issue an
agent an API key, connect over each protocol, and confirm the request was
governed. Each step gives the Admin console path first and the equivalent API
call beside it.

Conceptual background is in
[Connect an agent](/guides/connect-an-agent/mcp-clients/); the per-area
review checklists are in [Day to day](/guides/day-to-day/review-approvals/).

## 1. Before You Start

Two starting points lead here.

**Evaluating.** Bring up the seeded stack and sign in:

```bash
make e2e-up
make e2e-seed
```

The Admin console is at `http://127.0.0.1:9090` with the seeded credentials in
[Evaluate with the seeded stack](/guides/evaluate-with-the-seeded-stack/). The seed already creates
sources, roles, grants, and identities, so use it to see a configured system
before building your own.

The seed writes directly to the control database. It bypasses source-config
validation, Admin RBAC, and the Admin audit trail, and it stores upstream
credentials inline. Read it as a fixture, never as a model for production
setup.

**First sign-in.** A fresh install creates one admin, `admin`, with the
password `admin`. Signing in with it opens only a change-password page; the
rest of the console and the admin API answer `password_change_required` until
a new password of at least 12 characters is set. Setting
`INTERLOCK_ADMIN__BOOTSTRAP_PASSWORD` (Helm: `admin.bootstrapPasswordExistingSecret`)
before the first start chooses the first password instead, and is not forced
to change. Every admin can change their own password from the sidebar.

**Deploying for real.** Install the chart with a values file derived from
`deploy/helm/values.cloud.example.yaml`, which lists the Secrets and storage
class to create first. Then follow this guide against your own Admin URL.
Section 7 covers what changes under production configuration.

Throughout, `ADMIN` means your Admin base URL and `GATEWAY` the gateway base
URL. On the local stack those are `http://127.0.0.1:9090` and
`http://127.0.0.1:3001`.

### Authenticating to the admin API

Every `/api/...` call in this guide needs a session cookie and a CSRF token.
Sign in once, keep the cookie jar, and read the token from `/auth/csrf`:

```bash
curl -sS -c cookies.txt -X POST "$ADMIN/auth/login" \
  --data-urlencode "username=$ADMIN_USER" \
  --data-urlencode "password=$ADMIN_PASSWORD"

CSRF="$(curl -sS -b cookies.txt "$ADMIN/auth/csrf" | python3 -c 'import json,sys; print(json.load(sys.stdin)["csrf"])')"
```

The token is required on every `POST`, `PUT`, `PATCH`, and `DELETE`; safe
methods need only the cookie. The admin account also needs the right role:
`source_admin` or `security_admin` for `/api/data-sources`, and
`security_admin` for `/api/identities`. A missing or wrong token returns 403
with `Invalid or missing CSRF token`.

## 2. Register A Target System

**Only active connectors can be used.** The **Connectors** page lists the
connectors new sources can be registered on and, under **Available to
activate**, the rest. A fresh deployment starts with PostgreSQL, MySQL, Amazon
S3, Slack, GitHub and HTTP/REST active: the connectors that have been run
against real systems. That is not the same as certified: GitHub's source
roles, policy and audit are not yet exercised by any test stack, as the
connector support matrix records. A source admin or security admin can activate or deactivate any other
non-planned connector there; each change is recorded in the admin audit log as
`connector.activate` or `connector.deactivate`. Deactivating a connector only
stops new registrations: sources already on it keep serving traffic, and their
page marks the connector inactive. Every registration path - the wizard, the
console form, `POST /api/data-sources` and both Test Connection routes -
refuses an inactive or unknown connector. `GET /api/connectors` returns the
list with `active` and the number of sources on each.

### 2.1 Through the console

Open **Data Sources**, choose **New Source**, and work through the wizard:

1. **Type.** Give the source a display name and pick a connector (only active
   connectors are listed). This decides which connection fields appear next.
   You do not choose the source id: it is generated from the display name -
   `Sales PostgreSQL` becomes `sales_postgresql`, with `_2`, `_3` added if
   taken - and shown on the review step. It is what agents use to reach the
   source (the PostgreSQL database name, the `/proxy/<source_id>/` path and the
   MCP `source_id`), it cannot be changed later, and the source's page shows it
   with a Copy button.
2. **Connection.** Fill in the fields for that type (section 2.3). A
   PostgreSQL source also takes a **TLS mode**, defaulting to `verify-full`,
   and a **CA certificate** path. Choose **Test Connection** before
   continuing: it probes the upstream with the values on screen and persists
   nothing. A failed probe reports the error without saving.
3. **Schema.** For PostgreSQL, InterLock reads `information_schema` and lists
   tables and columns, flagging likely PII by column name. Tick the columns to
   tag as PII. Other connectors skip this step.
4. **Cache policy.** Accept the default strategy for the type or override it.
5. **Review.** Confirm and save. Saving registers the source, optionally
   creates default source roles, records the PII classification tags, and
   reloads the gateway's registry.

Registered sources can be re-probed later from the source detail page with
**Test Connection**.

### 2.2 Through the API

The admin API is served under `/api/...`. There is no `/api/v1/` prefix.

```bash
# Probe a configuration without saving it.
curl -sS -X POST "$ADMIN/api/data-sources/test" \
  -H 'Content-Type: application/json' \
  -H "X-CSRF-Token: $CSRF" -b cookies.txt \
  -d '{"source_type": "postgresql",
       "connection_config": {"host": "db.internal", "port": 5432,
                             "database": "sales", "user": "interlock_ro",
                             "password_ref": "env://SALES_DB_PASSWORD",
                             "sslmode": "verify-full",
                             "ssl_ca": "/run/secrets/sales-ca/ca.crt"}}'

# Register it.
curl -sS -X POST "$ADMIN/api/data-sources" \
  -H 'Content-Type: application/json' \
  -H "X-CSRF-Token: $CSRF" -b cookies.txt \
  -d '{"source_id": "sales_pg", "name": "Sales PostgreSQL",
       "source_type": "postgresql",
       "connection_config": {"host": "db.internal", "port": 5432,
                             "database": "sales", "user": "interlock_ro",
                             "password_ref": "env://SALES_DB_PASSWORD",
                             "sslmode": "verify-full",
                             "ssl_ca": "/run/secrets/sales-ca/ca.crt"},
       "cache_strategy": "deterministic_first"}'
```

`source_id` is optional. Omit it and the id is generated from `name` the same
way the console does, and returned in the response; supply it and it must be
1-63 characters of lower-case letters, digits, `_` or `-`, starting with a
letter or digit.

`POST /api/data-sources/{source_id}/test` re-probes a registered source.
`PUT` updates one, `DELETE` removes it, and `GET` lists or fetches. Responses
mask secret-bearing keys, showing `<configured>` in place of a value.

Three limits are worth knowing before you choose a path.

**Private hosts are blocked unless you opt in.** Egress validation rejects
private and loopback addresses, so registering a database on an internal
network fails with `Private or local egress target is blocked` until you set
`"allow_private_egress": true` in the connection config. This is deliberate
SSRF protection; enabling it is logged.

**Structure is recorded in the source catalog.** After a source is saved, a
worker records its structure: schemas, tables and columns for PostgreSQL,
MySQL/MariaDB and Snowflake; buckets and prefixes for S3 and Spaces; channels
for Slack; repositories for GitHub; configured objects and their fields for
Salesforce; indices and fields for OpenSearch and Elasticsearch; collections
and payload fields for Qdrant. It is shown in the source's Catalog section and
on the Catalog page, and `POST /api/data-sources/{id}/catalog/scans` queues a
scan. Only SQL catalogs are enforced on agent paths; the others are inventory.
When a scan finds a new table or column, the drift list shows which roles can
already read it through their existing patterns, and **Access analytics** on
the Catalog page shows what agents actually read, from the audit trail.
The wizard's schema preview in step 3 remains PostgreSQL-only.

**Source roles have no API.** Section 3 is console-only; no
`/api/source-roles` router exists.

The wizard's save path does not run source-config validation and the API does,
so prefer the API for production registration wherever the connector allows it.

### Upstream PostgreSQL TLS in production

In production a PostgreSQL source must verify its upstream's certificate:
`sslmode` (or `ssl`) set to `verify-full` or `verify-ca`, with the CA supplied
through `ssl_ca`, `ssl_ca_ref`, or `sslrootcert`. Every other posture - no mode,
`disable`, `allow`, `prefer`, `require`, or `verify_ssl: false` - is refused on
every protocol. `require` is refused because it encrypts without checking the
certificate.

The refusal happens as early as possible. `POST` and `PUT /api/data-sources`
return 422 with the reason instead of storing the source, and Test Connection
reports the same reason without connecting. The console's new-source form,
wizard and edit page carry the same two fields - **TLS mode** and **CA
certificate** - and refuse to save an unverified posture with the same
message; the wizard's schema step applies the rule before it connects.
Development environments are not affected, so a local PostgreSQL without TLS
keeps working.

The CA path is read by the gateway and admin processes, so it must exist in
their containers: mount the CA as a Secret volume and give its path, or give a
secret reference that resolves to one.

### 2.3 Connection configuration by connector

Every connector accepts these common keys where they apply: `host`, `port`,
`user`, `username`, `password`, `base_url`, `url`, `endpoint_url`,
`instance_url`, `connection_string`, `dsn`, `token`, `api_key`, `auth_header`,
`ssl`, `ssl_ca`, `ssl_verify`, `timeout_seconds`, `allow_private_egress`, and
the `_ref` form of each secret-bearing key.

`allow_private_egress` deserves a note: it defaults to false, and with it
false any host that resolves to a private or loopback address is refused. Most
real databases are on private networks, so this is the first error most
operators hit. Set it to `true` deliberately, per source.

Any key ending in `_ref` holds a secret reference rather than a literal:

| Scheme | Example | Notes |
|---|---|---|
| `env://` | `env://SALES_DB_PASSWORD` | Reads a process environment variable. |
| `file://` | `file:///run/secrets/db-password` | Restricted to `/run/secrets`, `/var/run/secrets`, `/etc/interlock/secrets`, or the roots named by `INTERLOCK_SECRET_FILE_ROOTS`. |
| `vault://` | `vault://sales-db/password` | HashiCorp KV v2 at the default `secret` mount: the last segment is the key, the rest the secret path. Needs `VAULT_ADDR`, `VAULT_TOKEN` and the `hvac` package, which the published image does not include. |
| `aws-sm://` | `aws-sm://prod/sales-db#password` | AWS Secrets Manager, optional JSON key after `#`. |

A value with no scheme is used verbatim. An unresolvable reference fails
closed rather than leaking the URI.

The table below lists each connector's own keys. Secret-bearing keys are in
**bold**; supply each as a literal or as its `_ref` form.

| Connector | Source type | Connector-specific keys |
|---|---|---|
| `postgresql` | `postgresql` | `host`, `port`, `database`, `user`, **`password`**, `sslmode`, `ssl_ca` (or `sslrootcert`), `verify_ssl` |
| `mysql` | `mysql` | `host`, `port`, `database`, `user`, **`password`** |
| `mariadb` | `mysql` | `host`, `port`, `database`, `user`, **`password`** |
| `generic_rest` | `http` | `base_url`, `auth_header`, **`token`** |
| `s3` | `s3` | `bucket`, `prefix`, `region_name`, `endpoint_url`, **`aws_access_key_id`**, **`aws_secret_access_key`** |
| `digitalocean_spaces` | `object_storage` | `bucket`, `prefix`, `region_name`, `endpoint_url`, **`aws_access_key_id`**, **`aws_secret_access_key`** |
| `fabric_sql` | `database` | Exact Fabric `host`, `database`, `tenant_id`, `client_id`, `endpoint_type`, `auth_mode`; SPN requires **`client_secret_ref`**. Activate the beta connector first; [deployment, saved-user OAuth and acceptance limits](/guides/fabric-sql/). Native certification pending. |
| `snowflake` | `warehouse` | `account`, `user`, `warehouse`, `database`, `schema`, `role`, `authenticator`, `application`, `collect_query_history`, **`password`**, **`private_key`** |
| `slack` | `saas` | `workspace`, `channel_types`, `include_messages`, `include_threads`, `include_files`, `max_channels`, `max_messages_per_channel`, `max_replies_per_thread`, `max_files`, **`bot_token`** |
| `github` | `saas` | `base_url`, `org`, `owner`, `repo_names`, `ref`, `include_code_paths`, `max_repos`, `max_issues_per_repo`, `max_prs_per_repo`, `max_releases_per_repo`, `max_workflows_per_repo`, **`token`** |
| `gitlab` | `saas` | `base_url`, `group`, `project`, `ref`, `include_code_paths`, `max_projects`, `max_issues_per_project`, `max_mrs_per_project`, `max_pipelines_per_project`, **`token`** |
| `zendesk` | `saas` | `base_url`, `subdomain`, `email`, `brand_id`, `group_id`, `organization_id`, `status`, `include_users`, `include_organizations`, `include_ticket_comments`, `max_tickets`, `max_articles`, `max_users`, `max_organizations`, **`api_token`** |
| `notion` | `saas` | `base_url`, `workspace`, `notion_version`, `max_results`, **`token`**, **`integration_token`** |
| `salesforce` | `saas` | `instance_url`, `client_id`, `username`, `domain`, `objects`, `max_records_per_object`, **`client_secret`**, **`password`**, **`security_token`**, **`session_id`** |
| `google_workspace` | `saas` | `workspace_domain`, `enabled_services`, `gws_config_dir`, `project_id`, `subject_user`, `drive_id`, `drive_query`, `gmail_users`, `gmail_labels`, `gmail_query`, `calendar_ids`, `calendar_time_min`, `calendar_time_max`, `admin_report_applications`, **`access_token`**, **`credentials_file`**, **`service_account_json`** |
| `opensearch` | `search` | `base_url`, `username`, `indices`, `max_docs_per_index`, **`password`**, **`token`** |
| `elasticsearch` | `search` | `base_url`, `username`, `indices`, `max_docs_per_index`, **`password`**, **`token`** |
| `qdrant` | `search` | `base_url`, `collections`, `max_points_per_collection`, **`api_key`** |

`atlassian`, `bigquery`, `mongodb`, `mssql`, and `servicenow` are present in
the registry as planned connectors. They are not configurable capabilities;
see [feature-status.md](/reference/feature-status/).

Keys named `binary`, `executable`, `command`, `cmd`, or `shell` are rejected
in every connector configuration.

## 3. Authorize Access With Source Roles

Registering a source does not grant anyone access to it. Access comes from a
**source role** granted to an identity. Policy rules add governance on top and
never grant access on their own.

A source role is a named set of permission statements scoped to one source.
Each statement has five parts:

| Field | Meaning |
|---|---|
| `effect` | `allow` or `deny`. |
| `action` | What is being attempted, for example `db.table.select`, `db.table.insert`, `db.execute_raw`, `http.get`, `storage.object.read`, `saas.object.read`, `discovery.search`. |
| `resource_type` | The kind of thing addressed, for example `db.table`, `db.column`, `storage.object`. |
| `resource_pattern` | A glob over resource names, for example `public.*` or `customers`. |
| `constraints` | Optional JSON narrowing the statement, for example `{"methods": ["GET"]}`, `{"require_where": true}`, `{"classifications": ["pii"]}`. |

Evaluation is strict: an explicit `deny` wins immediately, and otherwise every
resource the request touches must be covered by some `allow`. A request that
matches nothing is denied.

**How SQL table names become resources.** A SQL resource is
`<schema>.<table>.*`, lower-cased. A table the query names without a schema is
resolved the way the source's database would resolve it, using the source
catalog:

| Source | An unqualified table resolves to |
|---|---|
| PostgreSQL | The first schema on the scanning login's search path that holds the table. Schemas earlier on the path are also checked against `deny` statements, so a table created there since the last scan cannot route around a deny. |
| MySQL, MariaDB | The configured database. |
| Snowflake | The configured schema. A reference into another database is refused. |

Before a source's first scan, and on PostgreSQL when the search path starts
with `public`, names resolve to `public` as they always did. Statements written
as `public.<table>` on MySQL and Snowflake - the only spelling that used to
match there - still match through a legacy alias; `GET
/api/catalog/naming-report` lists them, with the spelling to use instead, and
lists PostgreSQL `public.` statements that no longer cover bare names on a
source whose search path starts elsewhere.

**Column-level statements are enforced.** A SQL request carries one
resource per column it touches - `sales.customers.email` - resolved to its
table with the catalog: columns in the SELECT list, WHERE, JOIN, GROUP BY and
ORDER BY, those an UPDATE sets, and those an INSERT writes, with `SELECT *`
expanded. A table touched without naming a column, as in `COUNT(*)`, or one a
DELETE removes rows from, needs access to the whole table. Wildcard statements
such as `*.*`, `sales.*` or `sales.customers.*` cover every column, so roles
written at table level behave as before.

Where the columns cannot be determined - `to_jsonb(c)`, a column or table the
catalog does not have - the table is treated as read in full, and a request
that meets a column-level `deny` on that table is refused with a reason naming
it. Rescan the source after a schema change so the catalog knows new columns.

Policy `tables` conditions follow the same idea asymmetrically: a `deny` rule
matches every spelling of a table - bare, schema-qualified or `public.` - while
an `allow` rule still matches only the tables as the query wrote them, so a
broader allow can never pre-empt a lower-priority deny. A `deny` rule's
`columns` condition matches the columns a query was resolved to read, and a
query whose columns cannot be determined. A policy's `redact_columns` applies
to MCP query results as well as the HTTP proxy, following each output column
back to the columns it derives from, so `SELECT ssn AS tax_id` is redacted as
`ssn`. On the PostgreSQL wire only the PII scanner redacts.

**Create a role.** On the source detail page, open **Roles**, choose **New
Role**, give it a key and name, then add statements. Saving a role replaces
its whole statement set. For a catalogued SQL source, click into a statement's
resource pattern and choose **Use** on a schema, table or column in **Pick from
the catalog**; the pattern and resource type are filled in. Warnings below the
statements flag patterns that match nothing in the catalog, legacy `public.`
spellings, and column-level allows that make `SELECT *` fail. They never block
a save. Policies have the same picker for tables, columns and redact columns,
and `POST /api/policies/validate` returns the warnings for a rule.

**Delete a role.** On the source detail page, choose **Delete** on the role's
row. Deletion is refused while any identity holds an active grant of the role;
revoke those grants first (section 4). The role, its statements and its revoked
grant history are recorded in the admin audit log under `source_role.delete`
before the role is removed. Policies whose `roles` condition names the role are
listed in the confirmation, since they stop matching it. Default template roles
are not recreated. To withdraw a role temporarily, clear **Enabled** instead.

Most connectors ship default role templates the wizard can create for you, for
example `read`, `analyst`, `write`, `owner`, and `blocked` on PostgreSQL, or
`browser`, `reader`, `writer`, `maintainer`, and `blocked` on object storage.

**Grant it.** Grants are made on the identity, covered next. A grant names an
identity, a source, and a role, and can carry an expiry.

**Test before handing out a key.** The source detail page has a source-role
dry run, and **Policies** has a policy dry run that evaluates both layers and
reports the combined decision. Both derive the request exactly as the gateway
does - the same verb, every statement's tables, write classification and name
resolution - and show any other spellings a resource was matched under. Use
them to confirm a role behaves as intended before an agent depends on it.

## 4. Create An Agent Identity And Issue Its Key

### 4.1 Through the console

Open **Access Control**, choose **New Identity**, and set:

- **Name** - how the agent appears in the audit trail.
- **Agent type** - `claude_code`, `codex`, `copilot`, or `custom`.
- **Team** - optional grouping used in audit filters.
- **Mapped PG role** - the upstream PostgreSQL role this identity's queries run
  as, when the source is PostgreSQL.
- **Generate API key** - leave enabled to have InterLock mint one.
- **Grants** - the source and role pairs from section 3.

On save the raw API key is shown **once**. It is stored only as a hash and
cannot be recovered. Copy it straight into the agent's secret store.

### 4.2 Through the API

`POST /api/identities` requires you to supply the key; it does not mint one.
Generate it yourself with a cryptographically secure source:

```bash
API_KEY="$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"

curl -sS -X POST "$ADMIN/api/identities" \
  -H 'Content-Type: application/json' \
  -H "X-CSRF-Token: $CSRF" -b cookies.txt \
  -d "{\"name\": \"sales-analyst-agent\", \"agent_type\": \"claude_code\",
       \"team\": \"analytics\", \"mapped_pg_role\": \"interlock_ro\",
       \"api_key\": \"$API_KEY\"}"
```

A supplied key must be printable ASCII with no whitespace, must not contain
quotes, backticks, angle brackets, or a backslash, must use at least eight
distinct characters, and must be at least `auth.custom_api_key_min_length`
characters, which defaults to 32.

### 4.3 Rotate and revoke

**Rotate** from the identity detail page with **Rotate Key**. This issues a new
key, invalidates the cached session for the old one, and shows the new key
once. Rotation is console-only; there is no API endpoint.

**Revoke** by disabling the identity:

```bash
curl -sS -X PUT "$ADMIN/api/identities/$IDENTITY_ID" \
  -H 'Content-Type: application/json' \
  -H "X-CSRF-Token: $CSRF" -b cookies.txt \
  -d '{"enabled": false}'
```

Cached sessions are revalidated against the database on every request, so
disabling takes effect on the agent's next call. Removing a grant withdraws
access to one source while leaving the identity usable elsewhere.

### 4.4 Change what an identity can reach

Grants are separate from the credential. Adding or withdrawing one never
changes the agent's API key, so a running client keeps working across the
change, and a withdrawal takes effect on the agent's next request because
sessions are revalidated against the database every time.

On the identity's detail page, **Source-role grants** lists what the identity
holds, with a **Revoke** control on each and a form to add another.

The same operations over the API:

```bash
# what this agent can reach
curl -s "$ADMIN/api/identities/7/source-role-grants" -b cookies.txt

# grant a role on a source; role_key is resolved within that source
curl -s -X POST "$ADMIN/api/identities/7/source-role-grants" \
  -H 'Content-Type: application/json' \
  -H "X-CSRF-Token: $CSRF" -b cookies.txt \
  -d '{"source_id": "sales_pg", "role_key": "analyst"}'

# withdraw one grant, leaving the identity usable elsewhere
curl -s -X DELETE "$ADMIN/api/identities/7/source-role-grants/42" \
  -H "X-CSRF-Token: $CSRF" -b cookies.txt
```

`POST` is idempotent: granting a role the identity already holds restates its
terms and re-enables it if it had been withdrawn. An omitted `expires_at`
means no expiry, including when the previous grant had one.

A revoked grant is disabled rather than deleted, so the record of who held
what, and when it was taken away, survives. It stops appearing in the list
above; pass `?include_revoked=true` to see the history.

Two refusals worth recognising: granting a role that belongs to a different
source returns 422 rather than storing a grant that could never match, and an
unknown identity or grant returns 404.

## 5. Connect The Agent

All three protocols authenticate with the same API key.

### 5.1 PostgreSQL wire

The key goes in the **password** field, and the **database name selects the
source**. The username is not used to authenticate an API key, so any value
works.

```bash
psql "postgresql://agent:$API_KEY@127.0.0.1:5434/sales_pg?sslmode=require"
```

An identity may instead be given a dedicated PostgreSQL username and password,
in which case those are used in the usual way. Upstream credentials are never
supplied by the client; InterLock connects to the real database itself.

`sslmode=require` is mandatory wherever the listener requires client TLS,
which is the production default.

### 5.2 HTTP

```bash
curl -sS "$GATEWAY/proxy/orders_api/v2/orders?limit=10" \
  -H "Authorization: Bearer $API_KEY"
```

The path after the source id is forwarded upstream. `GET` and `HEAD` are
treated as reads; every other method is a write and is subject to write safety.
The `Authorization` header is stripped before the request reaches the upstream.

### 5.3 MCP

The canonical endpoint is `POST /mcp`, speaking JSON-RPC 2.0 over MCP
Streamable HTTP. It serves two dialects, and most operators need only the
first.

**Connecting a standard MCP client.** Claude Code, Claude Desktop and the
official SDKs negotiate through `initialize` and speak MCP `2025-03-26`,
`2025-06-18` or `2025-11-25`. They need no special handling:

```bash
claude mcp add --transport http interlock "$GATEWAY/mcp" \
  --header "Authorization: Bearer $API_KEY"
claude mcp list          # expect: interlock ... (HTTP) - Connected
```

By hand, the same dialect is two plain requests - note that `initialize`
carries no version header, because none has been agreed yet:

```bash
curl -sS -X POST "$GATEWAY/mcp" \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc": "2.0", "id": 1, "method": "initialize",
       "params": {"protocolVersion": "2025-11-25", "capabilities": {},
                  "clientInfo": {"name": "curl", "version": "0"}}}'

curl -sS -X POST "$GATEWAY/mcp" \
  -H "Authorization: Bearer $API_KEY" \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -H 'MCP-Protocol-Version: 2025-11-25' \
  -d '{"jsonrpc": "2.0", "id": 2, "method": "tools/call",
       "params": {"name": "interlock_query",
                  "arguments": {"source_id": "sales_pg",
                                "sql": "SELECT count(*) FROM customers"}}}'
```

**The `2026-07-28` dialect** additionally mirrors the method and tool name into
headers and repeats the version and client capabilities inside `params._meta`.
A request that declares `2026-07-28` and omits any of these is rejected with
JSON-RPC code `-32020` (`HeaderMismatch`) before it reaches the governance
pipeline.

```bash
curl -sS -X POST "$GATEWAY/mcp" \
  -H "Authorization: Bearer $API_KEY" \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -H 'MCP-Protocol-Version: 2026-07-28' \
  -H 'MCP-Method: tools/call' \
  -H 'MCP-Name: interlock_query' \
  -d '{"jsonrpc": "2.0", "id": 1, "method": "tools/call",
       "params": {"name": "interlock_query",
                  "arguments": {"source_id": "sales_pg",
                                "sql": "SELECT count(*) FROM customers"},
                  "_meta": {"io.modelcontextprotocol/protocolVersion": "2026-07-28",
                            "io.modelcontextprotocol/clientCapabilities": {}}}}'
```

`MCP-Method` must equal the JSON-RPC `method`, `MCP-Name` must equal
`params.name`, and `_meta`'s protocol version must equal the header. These
mirrors are required only when the request declares `2026-07-28`; a
handshake-era client sends none of them. A version outside the four supported
returns `-32022` (`UnsupportedProtocolVersionError`), whose `data.supported`
lists them.

A write that needs approval comes back as a normal tool result, not an error:
`isError` is false and `structuredContent` carries `approval_id` and
`approval_state`. Do not retry it - the approval queue does not deduplicate, so
a retry enqueues a second approval for the same intended write.

The V1 tools are `interlock_query`, `interlock_list_sources`,
`interlock_describe_access`, `interlock_describe_source`, `interlock_discover`,
and `interlock_related_documents`. The `agentgate_*` names are deprecated
aliases kept for compatibility; see
[contracts/compatibility-policy.md](/reference/contracts/compatibility-policy/).
`interlock_describe_access` has no alias because it is newer than that
deprecation.

### 5.4 What to tell the agent

The agent does not need the key explained to it, and it should never be able to
read it: the key belongs in the client's configuration beside the URL, as a
header, ideally through an environment variable so it never enters a process
argument list. Everything else the agent needs, it can ask for:

| The agent wants to know | It calls |
|---|---|
| Which sources can I reach? | `interlock_list_sources` - only granted sources are returned |
| What may I do on this source? | `interlock_describe_access` - the allow and deny statements of its own roles |
| What does this data look like? | `interlock_describe_source` |
| The data itself | `interlock_query`, `interlock_discover` |

Two lines in the agent's own system prompt are worth adding, because neither is
discoverable from the tool list:

- *"Call `interlock_describe_access` before planning work against a source."*
  Otherwise a capable model will plan optimistically and learn its limits by
  being refused, one wasted turn per boundary.
- *"A refusal from a source role or policy is a decision, not an error. Report
  it and stop; do not retry or look for another route."* Agents retry failures
  by default, and a governance denial is the one failure that will never
  succeed on retry.

## 6. Confirm It Was Governed

Open **Audit & Costs**. Every governed request produces a row with the
identity, source, operation, status, cache tier, latency, and whether PII was
detected. Filter by identity or source to find the agent's first call, and
open the row for the detail view: protocol, normalized operation, correlation
id, policy decision, cache decision, approval state, and any error.

**Export** produces CSV for a filtered range.

Redaction statistics are recorded in the `redaction_stats` column of
`audit_log` but are not yet displayed in the console. To confirm redaction ran,
query the control database:

```sql
SELECT created_at, identity_id, source_id, pii_detected, redaction_stats
FROM audit_log
WHERE source_id = 'sales_pg'
ORDER BY created_at DESC
LIMIT 5;
```

A healthy first run shows the audit row present, the policy decision recorded,
and redaction statistics populated for any field your policy redacts:

```json
{"count": 2, "policy_fields": ["email", "ssn"], "redacted_fields": ["email", "ssn"]}
```

`policy_fields` is what the policy targets and `redacted_fields` is what was
actually redacted in that response, so a `count` of 0 with a non-empty
`policy_fields` means the response simply contained none of those fields. The
agent sees the redacted values in place, for example
`{"email": "[REDACTED:POLICY]"}`.

## 7. What Changes In Production

Production configuration refuses to start unless these hold. They are enforced,
not advisory.

| Setting | Required value | Effect |
|---|---|---|
| `auth.api_key_pepper` | 32+ characters | API keys are stored as HMAC-SHA256 under this pepper. |
| `auth.allow_legacy_sha256_keys` | `false` | Plain SHA-256 key hashes are rejected. |
| `database.ssl_mode` | `verify-full` | The control database connection verifies the server certificate against a CA. |
| `gateway.pg_require_client_tls` | `true` | Agents must negotiate TLS on the PostgreSQL listener. |
| `audit.durability_mode` | `strict` | A request is not acknowledged until its audit event is durable. |
| `admin.cookie_secure` | `true` | Admin sessions require HTTPS. |

Two operational consequences follow.

**Use secret references, not literals.** Put upstream credentials in
`*_ref` keys backed by your secret manager so the control database never holds
them.

**Changing the pepper invalidates every API key.** Stored hashes are HMACs
computed under the pepper in force when the key was issued, and there is no
dual-pepper path. Rotating `auth.api_key_pepper` means every agent must be
re-keyed. Treat it as a fleet-wide credential rotation, not a config tweak.

## 8. Troubleshooting

These are the messages agents and operators actually see.

| Message | Cause |
|---|---|
| `Private or local egress target is blocked` | A source host resolves to a private or loopback address and `allow_private_egress` is not set on that source. |
| `unsupported connection_config field(s): <name>` | A key the connector does not declare. Check the connector's row in section 2.3; the admin API validates strictly, the probe endpoints do not. |
| `Invalid or missing CSRF token` | An admin API write without a valid `X-CSRF-Token` for the current session. |
| `Missing or invalid Authorization header` | No `Authorization: Bearer <key>` on an HTTP or MCP call. |
| `Invalid API key` (HTTP 401) | The key does not match any enabled identity: wrong key, disabled identity, deleted identity, a key hashed under a different pepper, or a legacy SHA-256 key once legacy hashes are disallowed. The same 401 covers all of these deliberately - the response does not distinguish them. |
| `Unknown or disabled API key` | The internal `IdentityNotFoundError` behind that 401 (`core/auth.py`). You see this in gateway logs, not in the agent's response. |
| `Source role denied: No source role grants matched this identity and source` | The identity has no grant on that source. Add one in **Access Control**. |
| `Source role denied: No source role permission allowed every requested resource` | A grant exists but no `allow` statement covers a table, column, or object the request touched. |
| `Source role denied: Explicit deny matched source role permission` | A `deny` statement matched. Explicit denies win. |
| `Policy denied: <reason>` | Source roles allowed it; a policy rule refused it. Use the policy dry run to find the matching rule. |
| `Invalid InterLock PostgreSQL credentials` (SQLSTATE 28P01) | The PostgreSQL-wire equivalent of the 401 above: wrong key, or an identity that has been disabled. Revocation surfaces here, not as a separate message. |
| `PostgreSQL client TLS is required` (SQLSTATE 28000) | The client connected without TLS. Add `sslmode=require`. |
| `Verified upstream PostgreSQL TLS is required` | A production PostgreSQL source has no verifying `sslmode`. Set `verify-full` or `verify-ca` and supply the CA. |
| `Unverified upstream PostgreSQL TLS is disabled` | A production PostgreSQL source sets `verify_ssl: false`. Remove it and supply the CA. |
| `Unknown data source: <name>` (SQLSTATE 3D000) | The database name in the connection string is not a registered source id. |
| `HeaderMismatch` (JSON-RPC `-32020`) | An MCP request declaring `2026-07-28` is missing `MCP-Method`, `MCP-Name`, or the matching `params._meta`. Handshake-era clients do not need them. See section 5.3. |
| `UnsupportedProtocolVersionError` (JSON-RPC `-32022`) | `MCP-Protocol-Version` is outside `2025-03-26`, `2025-06-18`, `2025-11-25` and `2026-07-28`. |
| `Accept must include application/json and text/event-stream` | The MCP request's `Accept` header is missing or too narrow. |
| `<tool> requires source_id` | An MCP tool call omitted `source_id`. |
| `Unknown tool: <name>` | The MCP tool name is wrong; the V1 names are listed in section 5.3. |

If a request is denied and the reason is not obvious, reproduce it with the
policy dry run: it evaluates the source-role and policy layers together and
reports which one refused and why, without needing the agent in the loop.
