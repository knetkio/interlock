-- A new row can start at generation 1 after delete/recreate. Incarnation keeps
-- retained results and queued work from ever matching that replacement row.
ALTER TABLE fabric_credentials
    ADD COLUMN IF NOT EXISTS incarnation UUID NOT NULL DEFAULT gen_random_uuid();

-- Source mutations and credential revocation commit together, independent of
-- best-effort config/cache notifications. Token refresh does not use this path.
CREATE OR REPLACE FUNCTION interlock_invalidate_fabric_credentials()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    UPDATE fabric_credentials SET
        generation = generation + 1,
        revision = revision + 1,
        tenant_id = COALESCE(NEW.connection_config->>'tenant_id', tenant_id),
        client_id = COALESCE(NEW.connection_config->>'client_id', client_id),
        auth_mode = CASE WHEN NEW.connection_config->>'auth_mode' IN ('oauth', 'spn')
            THEN NEW.connection_config->>'auth_mode' ELSE auth_mode END,
        account_id = NULL, encrypted_cache = NULL,
        status = 'reconnect_required', updated_at = NOW()
    WHERE source_id = NEW.source_id;
    DELETE FROM fabric_pending_oauth WHERE source_id = NEW.source_id;
    RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS trg_fabric_config_generation ON data_sources;
CREATE TRIGGER trg_fabric_config_generation
AFTER UPDATE OF connection_config, enabled, source_type, metadata ON data_sources
FOR EACH ROW WHEN (
    OLD.connection_config IS DISTINCT FROM NEW.connection_config OR
    OLD.enabled IS DISTINCT FROM NEW.enabled OR
    OLD.source_type IS DISTINCT FROM NEW.source_type OR
    OLD.metadata->>'connector_key' IS DISTINCT FROM NEW.metadata->>'connector_key'
)
EXECUTE FUNCTION interlock_invalidate_fabric_credentials();
