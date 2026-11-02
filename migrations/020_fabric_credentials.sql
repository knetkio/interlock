-- Secret bytes never enter source metadata. A credential row is the lock owner
-- for refresh, OAuth completion, source edits and disconnect transitions.
CREATE TABLE IF NOT EXISTS fabric_credentials (
    source_id TEXT PRIMARY KEY REFERENCES data_sources(source_id) ON DELETE CASCADE,
    generation BIGINT NOT NULL DEFAULT 1 CHECK (generation > 0),
    revision BIGINT NOT NULL DEFAULT 0 CHECK (revision >= 0),
    tenant_id TEXT NOT NULL,
    client_id TEXT NOT NULL,
    account_id TEXT,
    auth_mode TEXT NOT NULL CHECK (auth_mode IN ('oauth', 'spn')),
    status TEXT NOT NULL DEFAULT 'disconnected'
        CHECK (status IN ('disconnected', 'connected', 'reconnect_required')),
    encrypted_cache BYTEA,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS fabric_pending_oauth (
    state_hash TEXT PRIMARY KEY,
    source_id TEXT NOT NULL REFERENCES fabric_credentials(source_id) ON DELETE CASCADE,
    generation BIGINT NOT NULL,
    session_hash TEXT NOT NULL,
    encrypted_flow BYTEA NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (expires_at <= created_at + INTERVAL '600 seconds')
);
CREATE INDEX IF NOT EXISTS idx_fabric_pending_source ON fabric_pending_oauth(source_id);

CREATE OR REPLACE FUNCTION interlock_invalidate_fabric_credentials()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    UPDATE fabric_credentials SET
        generation = generation + 1,
        revision = revision + 1,
        tenant_id = COALESCE(NEW.connection_config->>'tenant_id', tenant_id),
        client_id = COALESCE(NEW.connection_config->>'client_id', client_id),
        auth_mode = COALESCE(NEW.connection_config->>'auth_mode', auth_mode),
        account_id = NULL, encrypted_cache = NULL,
        status = 'reconnect_required', updated_at = NOW()
    WHERE source_id = NEW.source_id;
    DELETE FROM fabric_pending_oauth WHERE source_id = NEW.source_id;
    RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS trg_fabric_config_generation ON data_sources;
CREATE TRIGGER trg_fabric_config_generation
AFTER UPDATE OF connection_config ON data_sources
FOR EACH ROW WHEN (OLD.connection_config IS DISTINCT FROM NEW.connection_config)
EXECUTE FUNCTION interlock_invalidate_fabric_credentials();
