use super::*;

pub(crate) fn remove_completed_events(connection: &Connection) -> Result<()> {
    connection.execute("DELETE FROM event_deliveries_v2 WHERE event_id IN (SELECT e.id FROM mls_events_v2 e WHERE NOT EXISTS (SELECT 1 FROM event_deliveries_v2 d WHERE d.event_id = e.id AND d.acknowledged = 0))", [])?;
    connection.execute("DELETE FROM mls_events_v2 WHERE id IN (SELECT e.id FROM mls_events_v2 e WHERE NOT EXISTS (SELECT 1 FROM event_deliveries_v2 d WHERE d.event_id = e.id AND d.acknowledged = 0))", [])?;
    Ok(())
}

pub(crate) fn remove_completed_attachments(connection: &Connection) -> Result<()> {
    connection.execute("DELETE FROM attachment_deliveries_v1 WHERE (recipient_genesis, attachment_id) IN (SELECT a.recipient_genesis, a.attachment_id FROM attachments_v1 a WHERE NOT EXISTS (SELECT 1 FROM attachment_deliveries_v1 d WHERE d.recipient_genesis = a.recipient_genesis AND d.attachment_id = a.attachment_id AND d.acknowledged = 0))", [])?;
    connection.execute("DELETE FROM attachments_v1 WHERE NOT EXISTS (SELECT 1 FROM attachment_deliveries_v1 d WHERE d.recipient_genesis = attachments_v1.recipient_genesis AND d.attachment_id = attachments_v1.attachment_id AND d.acknowledged = 0)", [])?;
    Ok(())
}
pub(crate) fn maintain_lifecycle(connection: &Connection, now: i64) -> Result<()> {
    let dormant_before = now.saturating_sub(DORMANCY_SECONDS);
    connection.execute(
        "UPDATE devices_v2 SET dormant = 1 WHERE revoked = 0 AND last_seen < ?1",
        params![dormant_before],
    )?;
    connection.execute("DELETE FROM event_deliveries_v2 WHERE acknowledged = 0 AND EXISTS (SELECT 1 FROM devices_v2 d WHERE d.genesis = event_deliveries_v2.recipient_genesis AND d.device_id = event_deliveries_v2.device_id AND (d.dormant = 1 OR d.revoked = 1))", [])?;
    remove_completed_events(connection)?;
    connection.execute("DELETE FROM attachment_deliveries_v1 WHERE acknowledged = 0 AND EXISTS (SELECT 1 FROM devices_v2 d WHERE d.genesis = attachment_deliveries_v1.recipient_genesis AND d.device_id = attachment_deliveries_v1.device_id AND (d.dormant = 1 OR d.revoked = 1))", [])?;
    remove_completed_attachments(connection)?;
    let expires_at = now.saturating_sub(RETENTION_SECONDS);
    connection.execute("DELETE FROM event_deliveries_v2 WHERE event_id IN (SELECT id FROM mls_events_v2 WHERE created_at <= ?1)", params![expires_at])?;
    connection.execute(
        "DELETE FROM mls_events_v2 WHERE created_at <= ?1",
        params![expires_at],
    )?;
    connection.execute("DELETE FROM attachment_deliveries_v1 WHERE (recipient_genesis, attachment_id) IN (SELECT recipient_genesis, attachment_id FROM attachments_v1 WHERE created_at <= ?1)", params![expires_at])?;
    connection.execute(
        "DELETE FROM attachments_v1 WHERE created_at <= ?1",
        params![expires_at],
    )?;
    Ok(())
}
pub(crate) fn touch_device(
    connection: &Connection,
    genesis: &[u8],
    device_id: [u8; 32],
    now: i64,
) -> Result<bool> {
    Ok(connection.execute(
        "UPDATE devices_v2 SET last_seen = ?1, dormant = 0 WHERE genesis = ?2 AND device_id = ?3 AND revoked = 0",
        params![now, genesis, device_id.to_vec()],
    )? != 0)
}
pub(crate) fn system_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}
