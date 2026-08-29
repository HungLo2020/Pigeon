use super::*;

pub(crate) fn initialize(connection: &Connection) -> Result<()> {
    connection.execute_batch("CREATE TABLE IF NOT EXISTS identities (id BLOB PRIMARY KEY, card BLOB NOT NULL); CREATE TABLE IF NOT EXISTS routes (identity_id BLOB PRIMARY KEY, route BLOB NOT NULL); CREATE TABLE IF NOT EXISTS devices (device_id BLOB PRIMARY KEY, identity_id BLOB NOT NULL, record BLOB NOT NULL, revoked INTEGER NOT NULL DEFAULT 0, dormant INTEGER NOT NULL DEFAULT 0, last_seen INTEGER NOT NULL DEFAULT 0); CREATE TABLE IF NOT EXISTS revocations (device_id BLOB PRIMARY KEY, revocation BLOB NOT NULL); CREATE TABLE IF NOT EXISTS mls_events (id INTEGER PRIMARY KEY, record BLOB NOT NULL, created_at INTEGER NOT NULL DEFAULT 0); CREATE TABLE IF NOT EXISTS event_deliveries (event_id INTEGER NOT NULL, device_id BLOB NOT NULL, acknowledged INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(event_id, device_id)); CREATE TABLE IF NOT EXISTS key_packages (identity BLOB PRIMARY KEY, key_package BLOB NOT NULL);")?;
    connection.execute("CREATE TABLE IF NOT EXISTS relay_identity (id INTEGER PRIMARY KEY CHECK(id = 1), secret BLOB NOT NULL)", [])?;
    connection.execute("CREATE TABLE IF NOT EXISTS pairing_artifacts (identity BLOB NOT NULL, session BLOB NOT NULL, nonce BLOB NOT NULL, kind INTEGER NOT NULL, expiry INTEGER NOT NULL, commitment BLOB NOT NULL, payload BLOB NOT NULL, cancelled INTEGER NOT NULL DEFAULT 0, consumed INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(identity, session, kind))", [])?;
    connection.execute("CREATE TABLE IF NOT EXISTS outbound_forwards (id INTEGER PRIMARY KEY, forward BLOB NOT NULL)", [])?;
    connection.execute("CREATE TABLE IF NOT EXISTS relay_tls (id INTEGER PRIMARY KEY CHECK(id = 1), spki BLOB NOT NULL)", [])?;
    connection.execute(
        "CREATE TABLE IF NOT EXISTS relay_config (name TEXT PRIMARY KEY, value BLOB NOT NULL)",
        [],
    )?;
    // Upgrade relay databases created before operational device state existed.
    let _ = connection.execute(
        "ALTER TABLE devices ADD COLUMN dormant INTEGER NOT NULL DEFAULT 0",
        [],
    );
    let _ = connection.execute(
        "ALTER TABLE devices ADD COLUMN last_seen INTEGER NOT NULL DEFAULT 0",
        [],
    );
    let _ = connection.execute(
        "ALTER TABLE mls_events ADD COLUMN created_at INTEGER NOT NULL DEFAULT 0",
        [],
    );
    Ok(())
}
