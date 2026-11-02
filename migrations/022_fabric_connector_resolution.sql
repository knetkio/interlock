-- Lifecycle counterpart of connector_key_for: explicit connector_key wins,
-- then provider, then source type. Python's false/empty JSON marker values
-- fall through; an ignored provider edit must not revoke an explicit identity.
CREATE OR REPLACE FUNCTION interlock_source_connector_key(kind TEXT, metadata JSONB)
RETURNS TEXT LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE
    marker JSONB;
    fallback TEXT;
BEGIN
    FOREACH marker IN ARRAY ARRAY[metadata->'connector_key', metadata->'provider']
    LOOP
        IF marker IS NOT NULL AND marker NOT IN (
            'null'::jsonb, 'false'::jsonb, '0'::jsonb,
            '""'::jsonb, '[]'::jsonb, '{}'::jsonb
        ) THEN
            RETURN LOWER(marker #>> '{}');
        END IF;
    END LOOP;
    fallback := LOWER(COALESCE(kind, ''));
    RETURN CASE fallback
        WHEN 'http' THEN 'generic_rest'
        WHEN 'warehouse' THEN 'snowflake'
        WHEN 'search' THEN 'opensearch'
        WHEN '' THEN 'generic_rest'
        ELSE fallback
    END;
END;
$$;

DROP TRIGGER IF EXISTS trg_fabric_config_generation ON data_sources;
CREATE TRIGGER trg_fabric_config_generation
AFTER UPDATE OF connection_config, enabled, source_type, metadata ON data_sources
FOR EACH ROW WHEN (
    OLD.connection_config IS DISTINCT FROM NEW.connection_config OR
    OLD.enabled IS DISTINCT FROM NEW.enabled OR
    OLD.source_type IS DISTINCT FROM NEW.source_type OR
    interlock_source_connector_key(OLD.source_type, OLD.metadata)
        IS DISTINCT FROM interlock_source_connector_key(NEW.source_type, NEW.metadata)
)
EXECUTE FUNCTION interlock_invalidate_fabric_credentials();
