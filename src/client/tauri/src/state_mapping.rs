//! Pure presentation-state helpers. They deliberately contain no Tauri or
//! client-core invocation code, making state mapping independently testable.

use super::{Conversation, Message};

pub(super) fn unread_count(
    messages: &[Message],
    identity: Option<&str>,
    conversation: &str,
    cursor: i64,
) -> usize {
    messages
        .iter()
        .filter(|message| {
            message.conversation == conversation
                && identity != Some(message.sender.as_str())
                && message.timestamp > cursor
        })
        .count()
}

pub(super) fn sort_conversations(conversations: &mut [Conversation]) {
    conversations.sort_by(|left, right| {
        right
            .timestamp
            .cmp(&left.timestamp)
            .then_with(|| left.id.cmp(&right.id))
    });
}

pub(super) fn hex_bytes(value: Option<&serde_json::Value>) -> String {
    value
        .and_then(serde_json::Value::as_array)
        .map(|bytes| {
            bytes
                .iter()
                .filter_map(|byte| byte.as_u64().map(|n| format!("{n:02x}")))
                .collect()
        })
        .unwrap_or_default()
}
