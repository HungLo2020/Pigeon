use std::time::{SystemTime, UNIX_EPOCH};

pub(super) fn message_time() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}
