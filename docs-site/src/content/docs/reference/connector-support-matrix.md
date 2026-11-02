---
title: "Connector support matrix"
description: "Which connectors are stable, beta or planned, and what each has been certified against."
normative: true
sidebar:
  order: 1
---

Last reviewed: 2026-11-02

This matrix is the public V1 support contract. Capability labels are
conservative: code presence or a mocked probe does not make a connector stable.

## Status Legend

- `Stable V1`: included in the V1 compatibility contract and required release
  certification.
- `Beta V1`: implemented and test-covered for read/discovery use, but source-
  specific behavior may evolve additively and live depth is limited.
- `Live-Gated`: requires temporary least-privilege credentials and is excluded
  from default CI.
- `Deferred`: modeled or partially implemented, but not an enabled V1 claim.

Separately from this support status, an operator chooses which connectors are
**active** for new sources on the Connectors page. A deployment starts with
PostgreSQL, MySQL, Amazon S3, Slack, GitHub and HTTP/REST active; planned
connectors can never be activated.

## Stable V1 Sources

| Connector | Runtime form | Capabilities | Mutation contract | Required V1 evidence |
| --- | --- | --- | --- | --- |
| PostgreSQL | Native governed PG wire subset | Source-aware auth, Simple/Extended Query subset, role/policy, redaction, cache, audit | Risky writes approval-gated; COPY/Cancel/GSS unsupported | Compose; live certified against managed PostgreSQL. Client compatibility is asyncpg only - see postgresql-v1.md |
| MySQL/MariaDB | Async connector, no MySQL wire listener | Probe, introspection, single-statement governed query, schema discovery | Distinct insert/update/delete/DDL permissions and approval | Compose; live certified against managed MySQL |
| HTTP | Governed reverse proxy | Method/path roles, policy, bounded bodies, egress guard, redaction, cache, audit | POST/PUT/PATCH/DELETE role-checked and approval-gated | Mock upstream, adversarial egress, memory bounds |
| Amazon S3 | Object-storage connector | Probe, prefix/object list/read, ingestion, discovery | None in V1: governed writes are unreachable (an approved write fails), so object mutations are not part of the contract | MinIO; live certified against a real bucket for read and discovery. Governed writes are unreachable - see below |
| DigitalOcean Spaces | S3-compatible object-storage connector | Spaces endpoint plus S3 read/discovery behavior | Same as S3 | MinIO compatibility; the live bucket certification covers the shared S3 path |

PostgreSQL protocol details are in
[`postgresql-v1.md`](/reference/contracts/postgresql-v1/). MySQL connector semantics are in
[`mysql-connector-v1.md`](/reference/contracts/mysql-connector-v1/).

## Beta V1 Connectors

| Connector | Family | V1 beta capability | Writes | Certification |
| --- | --- | --- | --- | --- |
| Microsoft Fabric SQL | Database | Warehouse, Lakehouse SQL analytics and SQL Database; saved-user OAuth/SPN, governed query and visible catalog | Lakehouse read-only; Warehouse/SQL Database restricted table DML, approval/policy enforced | Packaged/test-covered; all six native endpoint/auth cells unverified. [Setup and limits](/guides/fabric-sql/) |
| Slack | Collaboration | Scoped channels, messages, threads, files, discovery | Disabled | Mock/local; **live certified** for read, discovery, role denial, redaction, audit |
| GitHub | Repository | Scoped repository metadata, issues, pull requests, selected code paths, discovery | Disabled unless a separately certified action is enabled | Mock/local; live-gated |
| GitLab | Repository | Scoped groups/projects, issues, merge requests, selected code paths, discovery | Disabled unless a separately certified action is enabled | Mock/local; live-gated |
| Snowflake | Warehouse | Probe, introspection, single-statement query, SQL role boundaries, cost metadata where returned | Approval-gated only where explicitly enabled | Mock/local; live-gated |
| Zendesk | SaaS | Scoped ticket, user, organization, and help-center reads/discovery | Disabled | Mock/local; live-gated |
| OpenSearch | Search | Probe, index/alias discovery, search, document read, ingestion | Disabled | Local container |
| Elasticsearch | Search | Compatible search/read contract for supported APIs | Disabled | Mock/local; live-gated |
| Qdrant | Vector source | Collection introspection, point read/scroll/search, payload discovery | Disabled | Local container |
| Salesforce | SaaS | Object describe, SOQL read, configured-object discovery | Disabled | Mock/local; live-gated |
| Notion | SaaS | Workspace/page/database/block reads and discovery | Disabled | Mock/local; live-gated |
| Google Workspace | Workspace | Governed Drive, Gmail, Calendar, Chat, Docs, Sheets, Slides, and Reports read/discovery paths | Disabled | Mock/local; **live certified for Drive only** - domain-wide delegation was not granted for the other scopes |

Beta connectors must expose truthful capability flags, fail closed on
unsupported writes, sanitize configuration, use connector-native permission
requests, and pass source-role/policy/audit conformance tests.

**Five of them are not yet held to that last requirement in practice.**
Elasticsearch, GitHub, GitLab, Snowflake and Zendesk have adapter tests but no
source registered in any test stack, so nothing exercises source roles, policy,
redaction, write safety or audit against them. Adapter coverage is not
governance coverage, and `Beta V1` here should be read as "the adapter works",
never as "governance is proven". The list is one definition, held in
`src/interlock/feature_status.py` and pinned by
`tests/e2e/test_connector_governance_uniformity.py`.

Slack and Google Workspace were in that group until live certification covered
them; OpenSearch, Qdrant, Salesforce and Notion are exercised through the local
compose stack.

**S3 and Spaces writes are unreachable rather than merely uncertified.** The
connector declares `supports_query=False` and `supports_proxy=False`, so no
protocol surface can express an object write. There is nothing to approve and
nothing to gate; the error path is correct, and the capability is absent.

## Deferred Connector Features

- Native MySQL wire proxy.
- Broad SaaS mutations.
- Provider-admin operations not explicitly named in a certified role template.
- Generic external connector runners as a Gateway runtime dependency.
- Qdrant as the InterLock cache/vector backend; Qdrant-as-source is separate.
- Planned connectors, which are in the registry but have no working adapter and
  can never be activated: Atlassian (`atlassian`), BigQuery (`bigquery`),
  MongoDB (`mongodb`), Microsoft SQL Server (`mssql`) and ServiceNow
  (`servicenow`).

## Authorization Rules

- Source roles authorize source-scoped access first.
- Explicit deny wins; allowed permissions from active roles are unioned; no
  matching allow means deny.
- Policy may deny, redact, rate-limit, classify, cap write risk, or require
  approval. It cannot create source access.
- Unsupported writes must fail closed and must not appear as enabled Admin
  actions or role templates.
- Incremental sync is advertised only when stateful delta behavior is tested.
- Admin and audit display masked connector configuration only.

## Live Certification Rules

Use temporary least-privilege credentials and disposable resources. Live tests
run after local gates, are opt-in, and record only safe source labels or secret
references. Reports must never include raw credential values, private hostnames, account
identifiers, organization names, repository names, channel IDs, bucket names,
or production object IDs.
