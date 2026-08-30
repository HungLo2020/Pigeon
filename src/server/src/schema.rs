use super::*;

pub(crate) fn initialize(connection: &Connection) -> Result<()> {
    // A full canonical genesis is the primary key. Compact IDs are indexed
    // convenience values only and are intentionally not unique.
    connection.execute_batch("CREATE TABLE IF NOT EXISTS identities_v2 (genesis BLOB PRIMARY KEY, compact_id BLOB NOT NULL, card BLOB NOT NULL); CREATE INDEX IF NOT EXISTS identities_v2_compact_id ON identities_v2(compact_id); CREATE TABLE IF NOT EXISTS routes_v2 (genesis BLOB PRIMARY KEY, compact_id BLOB NOT NULL, route BLOB NOT NULL); CREATE INDEX IF NOT EXISTS routes_v2_compact_id ON routes_v2(compact_id); CREATE TABLE IF NOT EXISTS devices_v2 (genesis BLOB NOT NULL, device_id BLOB NOT NULL, record BLOB NOT NULL, revoked INTEGER NOT NULL DEFAULT 0, dormant INTEGER NOT NULL DEFAULT 0, last_seen INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(genesis, device_id)); CREATE TABLE IF NOT EXISTS revocations_v2 (genesis BLOB NOT NULL, device_id BLOB NOT NULL, revocation BLOB NOT NULL, PRIMARY KEY(genesis, device_id)); CREATE TABLE IF NOT EXISTS key_packages_v2 (genesis BLOB PRIMARY KEY, compact_id BLOB NOT NULL, key_package BLOB NOT NULL); CREATE TABLE IF NOT EXISTS mls_events_v2 (id INTEGER PRIMARY KEY, recipient_genesis BLOB NOT NULL, record BLOB NOT NULL, created_at INTEGER NOT NULL DEFAULT 0); CREATE TABLE IF NOT EXISTS event_deliveries_v2 (event_id INTEGER NOT NULL, recipient_genesis BLOB NOT NULL, device_id BLOB NOT NULL, acknowledged INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(event_id, recipient_genesis, device_id)); CREATE TABLE IF NOT EXISTS pairing_artifacts_v2 (genesis BLOB NOT NULL, compact_id BLOB NOT NULL, session BLOB NOT NULL, nonce BLOB NOT NULL, kind INTEGER NOT NULL, expiry INTEGER NOT NULL, commitment BLOB NOT NULL, payload BLOB NOT NULL, cancelled INTEGER NOT NULL DEFAULT 0, consumed INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(genesis, session, kind)); CREATE INDEX IF NOT EXISTS pairing_artifacts_v2_compact_id ON pairing_artifacts_v2(compact_id); CREATE TABLE IF NOT EXISTS relay_identity (id INTEGER PRIMARY KEY CHECK(id = 1), secret BLOB NOT NULL); CREATE TABLE IF NOT EXISTS outbound_forwards (id INTEGER PRIMARY KEY, forward BLOB NOT NULL); CREATE TABLE IF NOT EXISTS relay_tls (id INTEGER PRIMARY KEY CHECK(id = 1), spki BLOB NOT NULL); CREATE TABLE IF NOT EXISTS relay_config (name TEXT PRIMARY KEY, value BLOB NOT NULL);")?;
    // A populated prototype schema cannot faithfully represent a collision.
    // Fail explicitly rather than merging two canonical genesis records.
    for table in [
        "identities",
        "routes",
        "devices",
        "revocations",
        "key_packages",
        "mls_events",
        "event_deliveries",
        "pairing_artifacts",
    ] {
        let exists: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1)",
            [table],
            |row| row.get(0),
        )?;
        if exists
            && connection.query_row::<i64, _, _>(
                &format!("SELECT COUNT(*) FROM {table}"),
                [],
                |row| row.get(0),
            )? != 0
        {
            bail!("legacy compact-ID-only relay database detected in table {table}; use a fresh relay database and re-register accounts rather than risking identity collision merging");
        }
    }
    Ok(())
}
