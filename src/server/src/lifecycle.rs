use super::*;

pub(crate) fn remove_completed_events(connection: &Connection) -> Result<()> {
    connection.execute("DELETE FROM event_deliveries WHERE event_id IN (SELECT e.id FROM mls_events e WHERE NOT EXISTS (SELECT 1 FROM event_deliveries d WHERE d.event_id = e.id AND d.acknowledged = 0))", [])?;
    connection.execute("DELETE FROM mls_events WHERE id IN (SELECT e.id FROM mls_events e WHERE NOT EXISTS (SELECT 1 FROM event_deliveries d WHERE d.event_id = e.id AND d.acknowledged = 0))", [])?;
    Ok(())
}
pub(crate) fn maintain_lifecycle(connection: &Connection, now: i64) -> Result<()> {
    let dormant_before = now.saturating_sub(DORMANCY_SECONDS);
    connection.execute(
        "UPDATE devices SET dormant = 1 WHERE revoked = 0 AND last_seen < ?1",
        params![dormant_before],
    )?;
    connection.execute("DELETE FROM event_deliveries WHERE acknowledged = 0 AND device_id IN (SELECT device_id FROM devices WHERE dormant = 1 OR revoked = 1)", [])?;
    remove_completed_events(connection)?;
    let expires_at = now.saturating_sub(RETENTION_SECONDS);
    connection.execute("DELETE FROM event_deliveries WHERE event_id IN (SELECT id FROM mls_events WHERE created_at <= ?1)", params![expires_at])?;
    connection.execute(
        "DELETE FROM mls_events WHERE created_at <= ?1",
        params![expires_at],
    )?;
    Ok(())
}
pub(crate) fn touch_device(connection: &Connection, device_id: [u8; 32], now: i64) -> Result<bool> {
    Ok(connection.execute(
        "UPDATE devices SET last_seen = ?1, dormant = 0 WHERE device_id = ?2 AND revoked = 0",
        params![now, device_id.to_vec()],
    )? != 0)
}
pub(crate) fn system_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}
