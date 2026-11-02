from __future__ import annotations

import re
import subprocess
import tomllib
from pathlib import Path

import yaml

# Evaluator- and operator-facing documentation is the site under docs-site/.
# Certification evidence is generated into build/, never committed.
ROOT = Path(__file__).resolve().parents[2]
DOCS = ROOT / "docs-site" / "src" / "content" / "docs"
RELEASE_READINESS = DOCS / "project" / "release-process.md"
EVALUATOR_QUICKSTART = DOCS / "guides" / "evaluate-with-the-seeded-stack.md"
GOVERNANCE_CONCEPTS = tuple(
    DOCS / "concepts" / name for name in ("source-roles.md", "policies.md", "write-approval.md")
)
CONNECTOR_MATRIX = DOCS / "reference" / "connector-support-matrix.md"
AGENT_GUIDES = DOCS / "guides" / "connect-an-agent"
MVP_KNOWN_LIMITATIONS = DOCS / "reference" / "known-limitations.md"
PUBLIC_BETA_FEATURE_STATUS = DOCS / "reference" / "feature-status.md"
README = ROOT / "README.md"
MAKEFILE = ROOT / "Makefile"
CI_WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"


def test_tracked_markdown_links_resolve() -> None:
    """Every relative link in a shipped doc must resolve in a fresh clone.

    Docs get moved and renamed; without this guard a reader lands on a 404 and
    the repo looks abandoned. Only relative links are checked - external URLs
    are out of scope here.
    """
    tracked = subprocess.run(
        ["git", "ls-files", "*.md"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.split()

    link_pattern = re.compile(r"\[[^\]]*\]\(([^)]+)\)")
    broken: list[str] = []
    for name in tracked:
        # Site pages link by route (/reference/...), resolved and checked by
        # the site build's link validator, not as files.
        if name.startswith("docs-site/src/content/"):
            continue
        path = ROOT / name
        for match in link_pattern.finditer(path.read_text()):
            target = match.group(1).split("#")[0].strip()
            if not target or target.startswith(("http://", "https://", "mailto:")):
                continue
            if not (path.parent / target).resolve().exists():
                broken.append(f"{name} -> {target}")

    assert not broken, f"broken relative links: {broken}"


def test_release_readiness_doc_has_required_sections() -> None:
    body = RELEASE_READINESS.read_text()

    assert body.startswith('---\ntitle: "Release process"')
    assert "## Release gates" in body
    assert "## Launch rules" in body
    assert "## Feature honesty" in body


def test_release_readiness_records_open_gates_as_blocking() -> None:
    """The cloud gate is either open, or closed with its evidence cited.

    This is the guard that keeps the launch posture honest: marking the gate
    Done without naming the run, the date, the released version and both
    signed digests fails here, as does dropping the rule that an open gate
    blocks release.
    """
    body = RELEASE_READINESS.read_text()
    row = re.search(
        r"^\| (\*\*Open\*\*|Done) \| Automated DigitalOcean \(DOKS\) deployment and live "
        r"certification \|(.*)$",
        body,
        flags=re.MULTILINE,
    )
    assert row, "the DOKS gate row is missing"
    status, evidence = row.group(1), row.group(2)
    if status == "Done":
        assert re.search(r"\b20\d\d-\d\d-\d\d\b", evidence), "no certification date"
        assert re.search(r"`v1\.0\.0-rc\.\d+`", evidence), "no certified version"
        assert len(re.findall(r"sha256:[0-9a-f]{64}", evidence)) >= 2, "image and chart digests"
        assert re.search(r"actions/runs/\d+", evidence), "no workflow run cited"
    assert "Do not publish a public release" in body
    assert "while any gate above is open" in body


def test_release_readiness_keeps_credential_and_evidence_rules() -> None:
    body = RELEASE_READINESS.read_text()

    assert "temporary least-privilege credentials" in body
    assert "never commit raw credential values" in body
    assert "Certification evidence is generated into `build/`" in body


def test_evaluator_packaging_docs_exist() -> None:
    for path in (
        EVALUATOR_QUICKSTART,
        *GOVERNANCE_CONCEPTS,
        CONNECTOR_MATRIX,
        AGENT_GUIDES / "mcp-clients.md",
        MVP_KNOWN_LIMITATIONS,
        PUBLIC_BETA_FEATURE_STATUS,
    ):
        assert path.exists(), path


def test_evaluator_quickstart_has_safe_local_workflow() -> None:
    body = EVALUATOR_QUICKSTART.read_text()

    assert "make e2e-up" in body
    assert "make e2e-seed" in body
    assert "make test-e2e" in body
    assert "Live credentials are intentionally not required" in body


def test_governance_concepts_separate_roles_and_policies() -> None:
    body = " ".join(" ".join(path.read_text().split()) for path in GOVERNANCE_CONCEPTS)

    assert "Role permission does not bypass policy rules or write safety" in body
    assert "Policies must not grant source access on their own" in body
    assert "Approving executes exactly once" in body


def test_connector_support_matrix_tracks_certification_status() -> None:
    body = CONNECTOR_MATRIX.read_text()

    for connector in (
        "PostgreSQL",
        "MySQL/MariaDB",
        "HTTP",
        "DigitalOcean Spaces",
        "Slack",
        "OpenSearch",
        "Qdrant",
        "Salesforce",
        "Notion",
    ):
        assert connector in body
    assert "Unsupported writes must fail closed" in body
    assert "Reports must never include raw credential values" in body


def test_agent_guides_cover_every_protocol_and_the_origin_credential_rule() -> None:
    for page in ("mcp-clients.md", "postgresql-clients.md", "http.md"):
        assert (AGENT_GUIDES / page).exists(), page
    body = " ".join(
        " ".join(path.read_text().split()) for path in sorted(AGENT_GUIDES.glob("*.md"))
    )
    assert "Do not give agents direct origin credentials" in body
    pipeline = (DOCS / "concepts" / "request-pipeline.md").read_text()
    assert pipeline.index("**Source roles.**") < pipeline.index("**Policy.**")


def test_mvp_known_limitations_tracks_deferred_and_blocked_gates() -> None:
    """The live-certification section must separate what ran from what did not.

    It used to be headed "Deferred Until Final Boss Live Gates" and listed
    eleven connectors as uniformly pending. Five have since been certified
    live, so a single deferral list was no longer true in either direction:
    it understated what had been proven and, more importantly, hid that some
    connectors are not "awaiting live certification" but untested by anything.
    Phase 8 of the governance audit split it, and this pins the split so it
    cannot collapse back into one flattering list.
    """
    body = MVP_KNOWN_LIMITATIONS.read_text()

    assert "Certified live:" in body
    assert "Not certified live:" in body
    assert "Proven nowhere" in body
    assert "Unsupported writes must fail closed" in body
    # Contributor tooling notes live with the tests, not among product limits.
    assert "Helm CLI is missing" in (DOCS / "project" / "testing.md").read_text()


def test_release_readiness_tracks_cloud_deployment_gate() -> None:
    body = RELEASE_READINESS.read_text()

    assert "Automated DigitalOcean (DOKS) deployment and live certification" in body
    assert "EKS and DOKS" in body
    aws = re.search(
        r"^\| (Deferred|\*\*Open\*\*|Done) \| AWS \(EKS\) deployment certification \|(.*)$",
        body,
        flags=re.MULTILINE,
    )
    assert aws, "the AWS (EKS) gate row is missing"
    # Closed only with the same evidence the DOKS gate requires.
    if aws.group(1) == "Done":
        evidence = aws.group(2)
        assert re.search(r"\b20\d\d-\d\d-\d\d\b", evidence), "no certification date"
        assert re.search(r"`v1\.0\.0-rc\.\d+`", evidence), "no certified version"
        assert len(re.findall(r"sha256:[0-9a-f]{64}", evidence)) >= 2, "image and chart digests"
        assert re.search(r"actions/runs/\d+", evidence), "no workflow run cited"
    assert "disposable infrastructure" in body
    assert "tear down" in body


def test_current_docs_do_not_reference_legacy_sql_parser() -> None:
    """No shipped document may advertise the removed GPL SQL parser.

    `pglast` was dropped for licensing reasons; `sqlglot` replaced it. This
    sweeps every tracked markdown doc rather than a fixed list, so a new doc
    cannot reintroduce the stale claim.
    """
    assert "sqlglot" in README.read_text()

    for path in [README, *sorted(p for p in DOCS.rglob("*") if p.suffix in {".md", ".mdx"})]:
        assert "pglast" not in path.read_text(), path


def test_public_beta_feature_status_marks_facades_not_public_beta() -> None:
    """Pins the doc's shape: the states, and that it names its source of truth.

    The per-capability evidence text is deliberately no longer asserted here.
    These substring checks were half of a contract with no mechanism behind
    it - this file checked the markdown, tests/unit/test_feature_status.py
    checked the registry, and because neither compared the two, they drifted
    apart across six capabilities without either failing. The comparison now
    lives in tests/unit/test_feature_status_reconciliation.py, which derives
    it field by field instead of sampling strings, so duplicating the wording
    here would only re-create the maintenance burden that caused the drift.

    What is left is what that test cannot see: that the doc still points a
    reader at the module, and that facades stay marked Disabled or Planned.
    """
    body = PUBLIC_BETA_FEATURE_STATUS.read_text()

    assert "src/interlock/feature_status.py" in body
    assert "| Semantic cache serving | `Disabled` |" in body
    assert "| OpenTelemetry export | `Beta` |" in body
    assert "| Deep PII scanner | `Beta` |" in body
    assert "| Discovery reciprocal rank fusion | `Beta` |" in body
    assert "| Dependency-tracked cache invalidation | `Beta` |" in body
    assert "| Qdrant vector backend | `Planned` |" in body
    assert "| External alert notifications | `Planned` |" in body


def test_readme_points_to_mvp_evaluator_and_migration_runner() -> None:
    body = README.read_text()

    for page in (
        "get-started/quick-start.mdx",
        "reference/connector-support-matrix.md",
        "guides/connect-an-agent/mcp-clients.md",
        "reference/known-limitations.md",
        "reference/feature-status.md",
    ):
        assert f"docs-site/src/content/docs/{page}" in body, page
    upgrades = (DOCS / "operations" / "upgrades-and-migrations.md").read_text()
    assert "python -m interlock.db.migrate" in upgrades
    assert "schema_migrations" in upgrades
    assert "pglast" not in body


def test_makefile_final_boss_contains_local_release_gates() -> None:
    body = MAKEFILE.read_text()

    assert "final-boss-local:" in body
    assert "final-boss:" in body
    for gate in (
        "uv sync --locked",
        "black --check src tests",
        "ruff check src tests",
        "$(MAKE) type",
        "$(MAKE) test-unit",
        "$(MAKE) audit-cover",
        "$(MAKE) security",
        "$(MAKE) release-evidence",
        "secret-scan:",
        "requirements-production-check:",
        "uv export --locked --format requirements.txt --extra production --no-dev --no-emit-project --no-header",
        "sbom:",
        "uv export --locked --format cyclonedx1.5 --extra production --no-dev",
        "cve-scan:",
        "pip-audit -r requirements-production.txt --disable-pip --no-deps --format cyclonedx-json",
        "docker-build:",
        "docker build --build-arg PYTHON_BASE_IMAGE=$(PYTHON_BASE_IMAGE) -t $(IMAGE_NAME):$(IMAGE_TAG) .",
        "$(MAKE) helm-render",
        "$(MAKE) e2e-seed",
        "$(MAKE) test-e2e",
        "$(MAKE) load",
    ):
        assert gate in body
    assert "$(MAKE) e2e-seed\n\t$(MAKE) e2e-seed" in body
    assert "tests/e2e/test_seeded_admin_pages.py" in body
    assert body.index("$(MAKE) e2e-down\n\t$(MAKE) load") > body.index("$(MAKE) test-e2e")
    assert "LIVE_" not in body
    assert "security: secret-scan" in body
    assert "final-boss: final-boss-local" in body


def test_public_docs_claim_apache_license_after_license_exists() -> None:
    body = README.read_text()
    pyproject = (ROOT / "pyproject.toml").read_text()

    assert (ROOT / "LICENSE").exists()
    license_body = (ROOT / "LICENSE").read_text()
    assert "Apache License" in license_body
    assert "Version 2.0" in license_body
    assert "InterLock is licensed under the Apache License, Version 2.0" in body
    assert 'name = "interlock-runtime"' in pyproject
    assert 'name = "onyx"' not in pyproject
    assert 'license = "Apache-2.0"' in pyproject
    assert "## License\n\nMIT" not in body


def test_demo_guide_uses_tracked_commands_not_removed_scripts() -> None:
    body = EVALUATOR_QUICKSTART.read_text()

    assert "make e2e-up" in body
    assert "make e2e-seed" in body
    assert "make test-e2e" in body
    assert "demo/seed_demo.py" not in body
    assert "demo/run_demo.py" not in body
    assert "demo/reset_demo.py" not in body


def test_production_requirements_do_not_reintroduce_gpl_sql_parser() -> None:
    body = (ROOT / "requirements-production.txt").read_text()

    assert "pglast" not in body
    assert "--no-hashes" not in body
    assert "--hash=sha256:" in body
    assert "This file was autogenerated" not in body


def test_supply_chain_cve_remediation_is_documented_and_pinned() -> None:
    requirements = (ROOT / "requirements-production.txt").read_text()
    pyproject = (ROOT / "pyproject.toml").read_text()
    readiness = RELEASE_READINESS.read_text()
    changelog = (ROOT / "CHANGELOG.md").read_text()

    for pinned_package in (
        "aiohttp==3.14.5",
        "authlib==1.9.1",
        "cryptography==50.0.2",
        "dlt==1.29.0",
        "joserfc==1.7.7",
        "msgpack==1.2.3",
        "pydantic-settings==2.14.2",
        "pyjwt==2.15.1",
        "python-multipart==0.0.32",
        "setuptools==84.2.1",
        "starlette==1.3.1",
        "urllib3==2.8.0",
    ):
        assert pinned_package in requirements

    # Heavy extractor/ML dependencies belong to worker-specific profiles,
    # not the public Gateway/Admin runtime image.
    assert "pillow==" not in requirements
    assert "soupsieve==" not in requirements
    assert "torch==" not in requirements
    assert (
        "production-worker = "
        '["interlock-runtime[pii,vector,ingestion,otel,connectors-tier1,connectors-repo,'
        'connectors-published-saas,fabric-sql]"]' in pyproject
    )
    assert 'production-worker-ml = ["interlock-runtime[production-worker,ml]"]' in pyproject

    for constraint in (
        '"starlette>=1.3.1,<2.0"',
        '"pydantic-settings>=2.14.2,<3.0"',
        '"msgpack>=1.2.1,<2.0"',
        '"python-multipart>=0.0.31,<1.0"',
        '"cryptography>=50.0.0,<51.0"',
        '"torch>=2.13.0,<3.0"',
        # PYSEC-2026-3721 / CVE-2026-9856 / CVE-2026-15925. Each floor sits at
        # or above the advisory's fixed version, inside the existing ceiling.
        # snowflake is the only one of the three that reaches a shipped image;
        # transformers belongs to the ml extra and pip is dev tooling, neither
        # of which appears in requirements-production.txt.
        '"transformers>=5.10.0,<6.0"',
        '"snowflake-connector-python>=4.7.1,<5.0"',
        '"dlt>=1.27.2,<2.0"',
        '"aiohttp>=3.14.4"',
        '"httplib2>=0.32.0"',
        '"joserfc>=1.7.6"',
        '"oauthlib>=4.0.0"',
        '"sentence-transformers>=5.6.0,<6.0"',
        '"pip>=26.2"',
        '"pillow>=13.0.0"',
        # Ten PyJWT advisories published 2026-09-29 are fixed in 2.14.0.
        '"pyjwt>=2.14.0"',
        '"setuptools>=84.1.0"',
        '"soupsieve>=2.8.4"',
        '"urllib3>=2.8.0,<3.0"',
        '"zeep>=4.3.3"',
    ):
        assert constraint in pyproject

    # The durable policy must stay published: no silent CVE waivers, and any
    # future waiver has to carry attribution and an expiry.
    assert "No active production dependency CVE waivers are accepted" in readiness
    assert "reason, owner, and expiry" in readiness
    assert "hash-pinned export" in readiness
    assert "currently blocks release until known vulnerabilities" not in readiness
    assert "no active production dependency CVE waivers" in changelog


def test_docker_image_does_not_bake_tracked_config_yaml() -> None:
    body = (ROOT / "Dockerfile").read_text()

    assert "COPY config.yaml" not in body
    assert "config.yaml" not in body.split("FROM ${PYTHON_BASE_IMAGE}", 1)[-1]
    assert "COPY uv.lock ./" in body
    assert "ARG INTERLOCK_EXTRA=production" in body
    assert 'uv sync --locked --no-dev --extra "${INTERLOCK_EXTRA}"' in body
    assert "requirements-production.txt" not in body


def test_docker_image_creates_a_writable_default_audit_spool() -> None:
    """The image must own the spool directory its own default points at.

    /var/lib is root-owned and the runtime stage runs as uid 1000, so an image
    that does not pre-create the spool cannot create it either: the buffer's
    mkdir(parents=True) raises PermissionError. Under the strict durability
    that production requires, that is a hard startup failure, not a warning.
    The path is read from the config default so moving the default without
    updating the image fails here.
    """
    from interlock.config import AuditConfig

    spool = AuditConfig().spool_path
    runtime_stage = (ROOT / "Dockerfile").read_text().split("FROM ${PYTHON_BASE_IMAGE}", 1)[-1]

    assert spool.startswith("/"), "spool_path default must be absolute"
    mkdir_lines = [ln for ln in runtime_stage.splitlines() if "mkdir" in ln]
    chown_lines = [ln for ln in runtime_stage.splitlines() if "chown" in ln]

    assert any(
        spool in ln for ln in mkdir_lines
    ), f"Dockerfile runtime stage does not create the default audit spool {spool}"
    # chown may target the spool or a parent it lives under.
    owned = any(
        any(part.startswith("/") and spool.startswith(part) for part in ln.split())
        for ln in chown_lines
    )
    assert owned, f"Dockerfile runtime stage does not chown the audit spool {spool}"


def test_admin_entrypoint_honors_configured_host() -> None:
    body = (ROOT / "src" / "interlock" / "admin" / "__main__.py").read_text()

    assert 'host = os.environ.get("HOST", config.admin.host)' in body
    assert 'host="0.0.0.0"' not in body


def test_makefile_e2e_and_load_cleanup_on_failure() -> None:
    body = MAKEFILE.read_text()

    assert "$(MAKE) e2e-up || ($(MAKE) e2e-logs; $(MAKE) e2e-down; exit 1)" in body
    assert (
        'uv run pytest -m "load and not live" tests/load -q || ' "(docker compose down -v; exit 1)"
    ) in body


def test_makefile_helm_render_fails_clearly_without_helm() -> None:
    body = MAKEFILE.read_text()

    assert "helm-render:" in body
    assert "command -v helm" in body
    assert "helm CLI is required" in body
    assert "helm template interlock deploy/helm/interlock" in body


def test_ci_e2e_waits_for_static_type_and_unit_gates() -> None:
    workflow = yaml.safe_load(CI_WORKFLOW.read_text())
    e2e_job = workflow["jobs"]["e2e"]

    assert sorted(e2e_job["needs"]) == [
        "audit",
        "helm",
        "lint",
        "security",
        "supply-chain",
        "test",
        "typecheck",
    ]
    steps = e2e_job["steps"]
    install_steps = [step["run"] for step in steps if "run" in step and "uv sync" in step["run"]]
    assert install_steps == [
        "uv sync --locked --extra dev --extra pii --extra ml --extra ingestion --extra otel --extra connectors-tier1 --extra connectors-tier2 --extra connectors-repo"
    ]
    assert any(step.get("run") == "make e2e" for step in steps)


def test_ci_renders_helm_chart_before_e2e() -> None:
    workflow = yaml.safe_load(CI_WORKFLOW.read_text())
    helm_job = workflow["jobs"]["helm"]

    assert helm_job["needs"] == ["lint", "audit", "security"]
    assert any(step.get("uses", "").startswith("azure/setup-helm@") for step in helm_job["steps"])
    assert any(step.get("run") == "make helm-render" for step in helm_job["steps"])


def test_ci_has_supply_chain_security_and_audit_gates() -> None:
    workflow = yaml.safe_load(CI_WORKFLOW.read_text())
    jobs = workflow["jobs"]

    assert "audit" in jobs
    assert any(step.get("run") == "make audit-cover" for step in jobs["audit"]["steps"])

    assert "security" in jobs
    assert any(step.get("run") == "make security" for step in jobs["security"]["steps"])

    supply_chain_steps = jobs["supply-chain"]["steps"]
    assert any(
        step.get("run") == "make requirements-production-check" for step in supply_chain_steps
    )
    assert any(step.get("run") == "make release-evidence" for step in supply_chain_steps)
    assert any(
        step.get("uses", "").startswith("docker/build-push-action@") for step in supply_chain_steps
    )
    assert any(
        step.get("uses", "").startswith("aquasecurity/trivy-action@") for step in supply_chain_steps
    )

    dependency_review_steps = jobs["dependency-review"]["steps"]
    assert any(
        step.get("uses", "").startswith("actions/dependency-review-action@")
        for step in dependency_review_steps
    )


def test_makefile_has_offline_infrastructure_validation() -> None:
    """Terraform and workflow syntax must be checkable without cloud access.

    These are the only gates that catch a broken cloud-certification workflow
    or Terraform root before a paid run, so they belong in the local gate and
    must stay offline (`-backend=false`, no credentials, no network).
    """
    body = MAKEFILE.read_text()

    assert "terraform-validate:" in body
    assert "actionlint:" in body
    assert "check-infra:" in body

    # Same missing-tool convention as helm-render: explain and exit 127.
    assert "terraform CLI is required" in body
    assert "actionlint is required" in body

    assert body.count("init -backend=false") == 2, "validation must not touch remote state"
    assert "terraform fmt -check -recursive deploy/terraform" in body
    assert ".github/workflows/cloud-certification.yml" in body

    # Both run inside the full local gate, before its e2e block - the cheap
    # static checks should fail before Docker is started. Scope the ordering
    # check to that target: `$(MAKE) e2e-up` also appears in the standalone
    # `e2e` target earlier in the file.
    gate = body.split("final-boss-local:", 1)[1].split("\n\n", 1)[0]
    assert "$(MAKE) terraform-validate" in gate
    assert "$(MAKE) actionlint" in gate
    assert gate.index("$(MAKE) terraform-validate") < gate.index("$(MAKE) e2e-up")


def test_helm_render_covers_the_certification_values() -> None:
    """A broken certification values file must fail locally, not in the cloud."""
    body = MAKEFILE.read_text()

    assert "deploy/helm/values.certification.yaml" in body


OPERATOR_GUIDE = DOCS / "get-started" / "setup-walkthrough.md"


def test_operator_setup_guide_exists_and_covers_the_full_path() -> None:
    """The guide must actually walk setup end to end.

    Before it existed, generating a key, rotating one, introspecting a schema,
    and writing a policy rule had no written procedure anywhere.
    """
    body = OPERATOR_GUIDE.read_text()

    for heading in (
        "## 1. Before You Start",
        "## 2. Register A Target System",
        "## 3. Authorize Access With Source Roles",
        "## 4. Create An Agent Identity And Issue Its Key",
        "## 5. Connect The Agent",
        "## 6. Confirm It Was Governed",
        "## 7. What Changes In Production",
        "## 8. Troubleshooting",
    ):
        assert heading in body, heading

    # One worked example per protocol; these are what an agent operator copies.
    assert "psql " in body and "sslmode=require" in body
    assert "Authorization: Bearer" in body
    assert '"method": "tools/call"' in body and "interlock_query" in body


def test_operator_setup_guide_documents_every_available_connector() -> None:
    """Every connector an operator can actually configure must be documented.

    Read the registry rather than a hand-copied list so adding a connector
    without documenting it fails the build. Connectors marked `planned` are
    excluded: documenting them as configurable would breach the feature-status
    honesty contract.
    """
    from interlock.connections.connectors import CONNECTOR_DEFINITIONS

    body = OPERATOR_GUIDE.read_text()
    available = {key for key, spec in CONNECTOR_DEFINITIONS.items() if spec.status != "planned"}
    planned = {key for key, spec in CONNECTOR_DEFINITIONS.items() if spec.status == "planned"}

    missing = sorted(key for key in available if f"`{key}`" not in body)
    assert not missing, f"connectors missing from the operator guide: {missing}"

    # Planned connectors must be named as planned, not silently omitted.
    for key in sorted(planned):
        assert key in body, f"planned connector {key} is not mentioned"
    assert "planned connectors" in body.lower()


def test_operator_setup_guide_does_not_invent_an_api_version_prefix() -> None:
    """There is no /api/v1 router; the guide must not route a call through one.

    Saying the prefix does not exist is useful - operators assume versioning -
    so only reject an actual endpoint path under it.
    """
    body = OPERATOR_GUIDE.read_text()

    routed = re.findall(r"/api/v1/\w", body)
    assert not routed, f"guide routes calls through a nonexistent prefix: {routed}"
    assert "/api/data-sources" in body
    assert "/api/identities" in body


def test_the_license_posture_documented_matches_the_extra_that_is_shipped() -> None:
    """NOTICE must describe the image that is actually built.

    The copyleft position is the one claim in this repo that a reader may act
    on legally, and for a long time it was maintained by hand in six places at
    once. Phase 8 of the governance audit found the same pattern in the
    feature-status contract and the fix was the same: derive the claim instead
    of asserting a substring.

    So this resolves the `production` extra transitively, asks whether the
    LGPL-3.0 libraries are in the image the Dockerfile builds, and requires
    NOTICE to say so either way. If someone moves `connectors-repo` in or out
    of `production`, this test fails until NOTICE is rewritten to match.
    """
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text())
    extras = pyproject["project"]["optional-dependencies"]

    def resolve(name: str, seen: set[str] | None = None) -> set[str]:
        """Flatten `interlock-runtime[a,b]` self-references into leaf extras."""
        seen = seen if seen is not None else set()
        if name in seen:
            return set()
        seen.add(name)
        names = {name}
        for entry in extras.get(name, []):
            match = re.fullmatch(r"interlock-runtime\[([^\]]+)\]", entry.strip())
            if match:
                for nested in match.group(1).split(","):
                    names |= resolve(nested.strip(), seen)
        return names

    shipped = resolve("production")
    copyleft_is_shipped = "connectors-repo" in shipped
    notice = (ROOT / "NOTICE").read_text()

    # The Dockerfile builds this extra; if that changes, the whole premise of
    # this test moves and it should fail loudly rather than pass vacuously.
    assert "ARG INTERLOCK_EXTRA=production" in (ROOT / "Dockerfile").read_text()

    if copyleft_is_shipped:
        assert "NOT part of the default installation" not in notice, (
            "NOTICE still claims the LGPL-3.0 libraries are excluded, but "
            "`production` now resolves to them and the published image "
            "contains them"
        )
        assert (
            "published container image" in notice and "included" in notice
        ), "NOTICE must state that the copyleft libraries ship in the image"
        pinned = (ROOT / "requirements-production.txt").read_text().lower()
        assert "pygithub" in pinned, "production export does not match the extra"
    else:
        assert "NOT part of the default installation" in notice
        assert "pygithub" not in (ROOT / "requirements-production.txt").read_text().lower()


def test_the_dependency_review_policy_denies_what_the_image_does_not_ship() -> None:
    """The license denylist and the shipped extra must not contradict.

    Denying LGPL-3.0 in CI while shipping an LGPL-3.0 library would fail every
    pull request that touched a dependency; dropping the denial while shipping
    nothing copyleft would silently lower the bar. Either way the strongly
    reciprocal licenses stay denied - relaxing LGPL is a deliberate, narrow
    decision and must not become a general one.
    """
    workflow = yaml.safe_load(CI_WORKFLOW.read_text())
    review = next(
        step
        for job in workflow["jobs"].values()
        for step in job.get("steps", [])
        if "dependency-review-action" in step.get("uses", "")
    )
    denied = {item.strip() for item in review["with"]["deny-licenses"].split(",")}

    assert {"GPL-2.0", "GPL-3.0", "AGPL-3.0"} <= denied, (
        "strongly reciprocal licenses must stay denied regardless of the " "LGPL decision"
    )

    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text())
    production = pyproject["project"]["optional-dependencies"]["production"]
    ships_copyleft = any("connectors-repo" in entry for entry in production)
    assert (
        "LGPL-3.0" in denied
    ) is not ships_copyleft, "the deny-licenses policy contradicts what the production extra ships"


def test_runtime_image_applies_debian_security_updates_at_build() -> None:
    """The runtime stage upgrades its OS packages before installing anything.

    The python:3.12-slim tag is rebuilt upstream on its own schedule, so a
    Debian security fix can be published well before the base image carries
    it. The CI supply-chain gate (Trivy, CRITICAL/HIGH, fixed only) failed on
    exactly that gap - gzip, pcre2, sqlite and perl - with no change to the
    image definition, and release builds pin an older base digest still.
    """
    runtime_stage = (ROOT / "Dockerfile").read_text().rsplit("FROM ${PYTHON_BASE_IMAGE}", 1)[-1]
    assert "apt-get upgrade -y" in runtime_stage
    upgrade = runtime_stage.index("apt-get upgrade -y")
    assert runtime_stage.index("apt-get update") < upgrade
    assert upgrade < runtime_stage.index("rm -rf /var/lib/apt/lists/*")


def test_the_packaged_version_has_a_changelog_section() -> None:
    """The release workflow publishes this section as the release notes and
    fails when it is missing, so a version bump must add it."""
    from interlock import release_version

    changelog = (ROOT / "CHANGELOG.md").read_text()
    assert f"\n## {release_version()} - " in changelog
    assert "\n## Unreleased\n" not in changelog.split(f"\n## {release_version()} - ", 1)[1]
