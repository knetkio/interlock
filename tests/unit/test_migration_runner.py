from __future__ import annotations

import tomllib
from pathlib import Path
from typing import Any

import pytest

from interlock.db.migrations import apply_migrations, discover_migrations, verify_migration_head

ROOT = Path(__file__).resolve().parents[2]


class _Tx:
    async def __aenter__(self) -> None:
        return None

    async def __aexit__(self, *args: object) -> None:
        return None


class FakeMigrationConnection:
    def __init__(
        self,
        *,
        initialized: bool = False,
        legacy_version: str | None = None,
    ) -> None:
        self.initialized = initialized
        self.legacy_version = legacy_version
        self.rows: dict[str, str] = {}
        self.executed: list[str] = []
        self.locked = False

    def transaction(self) -> _Tx:
        return _Tx()

    async def execute(self, sql: str, *args: Any) -> str:
        self.executed.append(sql)
        if "pg_advisory_lock" in sql:
            self.locked = True
        if "pg_advisory_unlock" in sql:
            self.locked = False
        if "INSERT INTO schema_migrations" in sql and args:
            self.rows[str(args[0])] = str(args[2])
        return "OK"

    async def fetch(self, sql: str, *args: Any) -> list[dict[str, str]]:
        return [
            {"version": version, "checksum": checksum}
            for version, checksum in sorted(self.rows.items())
        ]

    async def fetchval(self, sql: str, *args: Any) -> bool:
        if "table_name = $1" in sql and args:
            table = str(args[0])
            if table == "audit_partition_maintenance":
                return (self.legacy_version or "") >= "010"
            if table == "source_roles":
                return (self.legacy_version or "") >= "007"
            if table == "cache_dependencies":
                return (self.legacy_version or "") >= "005"
            if table == "alert_rules":
                return (self.legacy_version or "") >= "004"
            if table == "admin_identities":
                return (self.legacy_version or "") >= "002"
        if "column_name = $2" in sql and args:
            table, column = str(args[0]), str(args[1])
            if table == "identities" and column == "api_key_hash_version":
                return (self.legacy_version or "") >= "012"
            if table == "audit_log" and column == "event_id":
                return (self.legacy_version or "") >= "011"
            if table == "identities" and column == "pg_username":
                return (self.legacy_version or "") >= "006"
            if table == "identities" and column == "last_used_at":
                return (self.legacy_version or "") >= "003"
        if "indexname = $1" in sql and args:
            index = str(args[0])
            if index == "idx_identity_source_role_grants_active":
                return (self.legacy_version or "") >= "008"
        return self.initialized


def _write_migration(root: Path, name: str, sql: str) -> None:
    (root / name).write_text(sql)


def test_discover_migrations_orders_and_hashes(tmp_path: Path) -> None:
    _write_migration(tmp_path, "002_second.sql", "SELECT 2;")
    _write_migration(tmp_path, "001_first.sql", "SELECT 1;")

    migrations = discover_migrations(tmp_path)

    assert [migration.name for migration in migrations] == [
        "001_first.sql",
        "002_second.sql",
    ]
    assert all(len(migration.checksum) == 64 for migration in migrations)


@pytest.mark.asyncio
async def test_migrations_apply_empty_db(tmp_path: Path) -> None:
    _write_migration(tmp_path, "001_first.sql", "CREATE TABLE example (id int);")
    _write_migration(tmp_path, "002_second.sql", "ALTER TABLE example ADD COLUMN name text;")
    conn = FakeMigrationConnection(initialized=False)

    result = await apply_migrations(conn, tmp_path)

    assert result.applied == ["001_first.sql", "002_second.sql"]
    assert result.skipped == []
    assert result.baselined == []
    assert conn.locked is False
    assert set(conn.rows) == {"001", "002"}


@pytest.mark.asyncio
async def test_migrations_apply_twice_idempotently(tmp_path: Path) -> None:
    _write_migration(tmp_path, "001_first.sql", "CREATE TABLE example (id int);")
    conn = FakeMigrationConnection(initialized=False)

    first = await apply_migrations(conn, tmp_path)
    second = await apply_migrations(conn, tmp_path)

    assert first.applied == ["001_first.sql"]
    assert second.applied == []
    assert second.skipped == ["001_first.sql"]


@pytest.mark.asyncio
async def test_readiness_verifies_exact_migration_head(tmp_path: Path) -> None:
    _write_migration(tmp_path, "001_first.sql", "CREATE TABLE example (id int);")
    conn = FakeMigrationConnection(initialized=False)
    await apply_migrations(conn, tmp_path)

    status = await verify_migration_head(conn, tmp_path)

    assert status == {"status": "ok", "head": "001", "applied": 1}


@pytest.mark.asyncio
async def test_readiness_rejects_missing_or_modified_migrations(tmp_path: Path) -> None:
    _write_migration(tmp_path, "001_first.sql", "SELECT 1;")
    conn = FakeMigrationConnection(initialized=False)

    with pytest.raises(RuntimeError, match="not applied"):
        await verify_migration_head(conn, tmp_path)

    await apply_migrations(conn, tmp_path)
    _write_migration(tmp_path, "001_first.sql", "SELECT 2;")
    with pytest.raises(RuntimeError, match="checksum"):
        await verify_migration_head(conn, tmp_path)


@pytest.mark.asyncio
async def test_migrations_upgrade_from_legacy_initialized_database(tmp_path: Path) -> None:
    _write_migration(tmp_path, "001_first.sql", "CREATE TABLE example (id int);")
    _write_migration(tmp_path, "002_second.sql", "ALTER TABLE example ADD COLUMN name text;")
    conn = FakeMigrationConnection(initialized=True)

    result = await apply_migrations(conn, tmp_path)

    assert result.applied == ["002_second.sql"]
    assert result.baselined == ["001_first.sql"]
    assert set(conn.rows) == {"001", "002"}


@pytest.mark.asyncio
async def test_migrations_upgrade_from_004_fixture_to_head() -> None:
    conn = FakeMigrationConnection(initialized=True, legacy_version="004")

    result = await apply_migrations(conn, ROOT / "migrations")

    assert result.baselined == [
        "001_initial_schema.sql",
        "002_admin_identities.sql",
        "003_identity_last_used.sql",
        "004_alerts.sql",
    ]
    assert result.applied == [
        "005_production_remediation_foundation.sql",
        "006_pg_production_governance.sql",
        "007_source_roles_permissions.sql",
        "008_role_policy_alignment.sql",
        "009_enterprise_connectors.sql",
        "010_audit_partition_durability.sql",
        "011_audit_delivery_durability.sql",
        "012_api_key_hash_versions.sql",
        "013_oidc_identity_mapping.sql",
        "014_admin_authorization_version.sql",
        "015_repair_double_encoded_jsonb.sql",
        "016_source_catalog.sql",
        "017_identity_tombstones.sql",
        "018_connector_activation.sql",
        "019_admin_password_change.sql",
        "020_fabric_credentials.sql",
        "021_fabric_source_lifecycle.sql",
        "022_fabric_connector_resolution.sql",
    ]
    assert result.skipped == []
    assert set(conn.rows) == {f"{version:03d}" for version in range(1, 23)}


@pytest.mark.asyncio
async def test_migrations_baseline_modern_legacy_database_to_head() -> None:
    conn = FakeMigrationConnection(initialized=True, legacy_version="010")

    result = await apply_migrations(conn, ROOT / "migrations")

    assert result.applied == [
        "011_audit_delivery_durability.sql",
        "012_api_key_hash_versions.sql",
        "013_oidc_identity_mapping.sql",
        "014_admin_authorization_version.sql",
        "015_repair_double_encoded_jsonb.sql",
        "016_source_catalog.sql",
        "017_identity_tombstones.sql",
        "018_connector_activation.sql",
        "019_admin_password_change.sql",
        "020_fabric_credentials.sql",
        "021_fabric_source_lifecycle.sql",
        "022_fabric_connector_resolution.sql",
    ]
    assert result.skipped == []
    assert result.baselined == [
        "001_initial_schema.sql",
        "002_admin_identities.sql",
        "003_identity_last_used.sql",
        "004_alerts.sql",
        "005_production_remediation_foundation.sql",
        "006_pg_production_governance.sql",
        "007_source_roles_permissions.sql",
        "008_role_policy_alignment.sql",
        "009_enterprise_connectors.sql",
        "010_audit_partition_durability.sql",
    ]
    assert set(conn.rows) == {f"{version:03d}" for version in range(1, 23)}


@pytest.mark.asyncio
async def test_migrations_do_not_replay_role_alignment_when_008_marker_exists() -> None:
    conn = FakeMigrationConnection(initialized=True, legacy_version="008")

    result = await apply_migrations(conn, ROOT / "migrations")

    assert "007_source_roles_permissions.sql" in result.baselined
    assert "008_role_policy_alignment.sql" in result.baselined
    assert "008_role_policy_alignment.sql" not in result.applied
    assert result.applied == [
        "009_enterprise_connectors.sql",
        "010_audit_partition_durability.sql",
        "011_audit_delivery_durability.sql",
        "012_api_key_hash_versions.sql",
        "013_oidc_identity_mapping.sql",
        "014_admin_authorization_version.sql",
        "015_repair_double_encoded_jsonb.sql",
        "016_source_catalog.sql",
        "017_identity_tombstones.sql",
        "018_connector_activation.sql",
        "019_admin_password_change.sql",
        "020_fabric_credentials.sql",
        "021_fabric_source_lifecycle.sql",
        "022_fabric_connector_resolution.sql",
    ]


def test_audit_partition_durability_migration_has_default_and_maintainer() -> None:
    body = (ROOT / "migrations" / "010_audit_partition_durability.sql").read_text()

    assert "PARTITION OF audit_log DEFAULT" in body
    assert "audit_partition_maintenance" in body
    assert "maintain_audit_partitions" in body


def test_audit_delivery_durability_migration_has_dedup_and_dead_letter() -> None:
    body = (ROOT / "migrations" / "011_audit_delivery_durability.sql").read_text()

    assert "ADD COLUMN IF NOT EXISTS event_id UUID" in body
    assert "CREATE TABLE IF NOT EXISTS audit_event_dedup" in body
    assert "CREATE TABLE IF NOT EXISTS audit_dead_letter" in body
    assert "CREATE UNIQUE INDEX" in body
    assert "consecutive_failures = consecutive_failures + 1" in body


def test_api_key_hash_version_migration_supports_legacy_upgrade() -> None:
    body = (ROOT / "migrations" / "012_api_key_hash_versions.sql").read_text()

    assert "api_key_hash_version" in body
    assert "sha256-v1" in body
    assert "hmac-sha256-v2" in body


def test_migrations_packaged_in_wheel() -> None:
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text())
    force_include = pyproject["tool"]["hatch"]["build"]["targets"]["wheel"]["force-include"]

    # Must match the package directory: interlock.db.migrate resolves the
    # packaged migrations as Path(__file__).parents[1] / "migrations".
    assert force_include["migrations"] == "interlock/migrations"


def test_docker_build_copies_migrations_before_package_install() -> None:
    body = (ROOT / "Dockerfile").read_text()

    assert body.index("COPY migrations/ ./migrations/") < body.rindex(
        'RUN uv sync --locked --no-dev --extra "${INTERLOCK_EXTRA}"'
    )


def test_applied_migration_files_are_immutable() -> None:
    """Migration files are content-addressed; editing one breaks live readiness.

    ``verify_migrations`` compares the checksum of each bundled file against
    the checksum recorded when it was applied, so a cosmetic edit - a renamed
    env var in a comment, a reworded note - makes every already-migrated
    database fail readiness. Historical migrations are immutable artifacts:
    change behavior by adding a new migration, never by editing an old one.

    This guard pins the checksums of the migrations that shipped before the
    Onyx to InterLock rename, which is exactly when a repo-wide sweep is
    tempted to rewrite them.
    """
    # Digests of every migration that has shipped. Editing a file below - even
    # a comment - changes its digest and breaks readiness on every database
    # that already applied it. Adding a NEW migration is fine and requires
    # adding its digest here deliberately.
    pinned = {
        "001": "b2df9892a8911c7aded8fd525996a2d1636face2e834842792c7b8ca395aaefb",
        "002": "25accd111bbc7ae6c9a447039b74f112334657a20a23202b2fb2d4bfdaa5fe11",
        "003": "3e1ddbccdeeb72b7cfb7b9bd2c898389146251e3cb676156f93d8be03a292dc5",
        "004": "ee30655a809c8ca87f5461a9e066bfb6bc11084e26eefb0a5cea65269b598a7f",
        "005": "082411e69f156536b39749c14984737d971a64fbed7e84dae5df99bacaa7fc99",
        "006": "946aedf0d2770d5167368a01b89524446efe50eb4867bbe720fb7501b3e809dc",
        "007": "dd1bece74d66c738b61955bebbc2814098be61de2154d19a0b2303f46f250098",
        "008": "1eff8ee7f4e45759f7e11b4f5caccf3cd19649a81dee6d30c3677044ee29c22b",
        "009": "dc9584009a28df9ce971d31bee5fe9ccd37ffd35643ba38a131db86171145a46",
        "010": "3bb2a9f106ce1c89cab1d5dcc7da21815d44fdb33cd6f3293e33f71fd3da8400",
        "011": "08a6e43201cd5a9532ca485edcb882770af3b80360eab126047f31c7a474cd0b",
        "012": "44fa07a04ab052525d3ef633ac3dea3a8fa0079b4636a56fbc167f7ecabdf339",
        "013": "e9bae449271ee5283fada65b1de70fe534e8a1ffbf6df18f2a11f24acb25fb89",
        "014": "e70c6f2ec886bf76c9e9b323201c9fa664f677969f3b97ac359cbe6e65fc9358",
    }
    migrations = {m.version: m for m in discover_migrations(ROOT / "migrations")}

    missing = set(pinned) - set(migrations)
    assert not missing, f"migrations removed or renumbered: {sorted(missing)}"

    drifted = [
        version for version, digest in pinned.items() if migrations[version].checksum != digest
    ]
    assert not drifted, (
        f"migration files edited after being applied: {sorted(drifted)}. "
        "Applied migrations are immutable - revert the edit and express the "
        "change as a new migration."
    )
