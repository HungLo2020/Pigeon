use serde::Serialize;
use std::{path::PathBuf, process::Command, thread, time::Duration};
use tauri::{Emitter, Manager};

#[derive(Serialize, Clone)]
struct Contact {
    id: String,
    server: String,
}
#[derive(Serialize, Clone)]
struct Group {
    id: String,
    members: usize,
}
#[derive(Serialize, Clone)]
struct Conversation {
    id: String,
    title: String,
    kind: String,
    preview: Option<String>,
    timestamp: Option<i64>,
    unread: usize,
}
#[derive(Serialize, Clone)]
struct Device {
    id: String,
    state: String,
    /// Last activity is relay-observed data and is intentionally absent until
    /// the server exposes a signed account-status query.
    last_activity: Option<i64>,
}
#[derive(Serialize, Clone)]
struct Route {
    server: String,
    revision: u64,
    relay_fingerprint: String,
    tls_spki_fingerprint: String,
}
#[derive(Serialize, Clone)]
struct Message {
    conversation: String,
    sender: String,
    text: String,
    timestamp: i64,
}
#[derive(Serialize, Clone)]
struct AccountStatus {
    state_exists: bool,
    identity: Option<String>,
    server: Option<String>,
    contacts: Vec<Contact>,
    groups: Vec<Group>,
    conversations: Vec<Conversation>,
    devices: Vec<Device>,
    route: Option<Route>,
    messages: Vec<Message>,
}

fn unread_count(
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

fn sort_conversations(conversations: &mut [Conversation]) {
    conversations.sort_by(|left, right| {
        right
            .timestamp
            .cmp(&left.timestamp)
            .then_with(|| left.id.cmp(&right.id))
    });
}

fn hex_bytes(value: Option<&serde_json::Value>) -> String {
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

fn state_path(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    app.path()
        .app_data_dir()
        .map_err(|e| e.to_string())
        .map(|path| path.join("identity.json"))
}
fn core(app: &tauri::AppHandle, arguments: &[String]) -> Result<String, String> {
    let state = state_path(app)?;
    if let Some(parent) = state.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let mut command =
        Command::new(std::env::var("PIGEON_CLIENT_BIN").unwrap_or_else(|_| "pigeon-client".into()));
    command.arg("--state").arg(state);
    if let Ok(certificate) = std::env::var("PIGEON_CERTIFICATE") {
        command.arg("--certificate").arg(certificate);
    }
    command.args(arguments);
    let output = command
        .output()
        .map_err(|e| format!("start client core: {e}"))?;
    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    } else {
        Err(String::from_utf8_lossy(&output.stderr).into_owned())
    }
}
#[tauri::command]
fn account_status(app: tauri::AppHandle) -> Result<AccountStatus, String> {
    let path = state_path(&app)?;
    if !path.exists() {
        return Ok(AccountStatus {
            state_exists: false,
            identity: None,
            server: None,
            contacts: vec![],
            groups: vec![],
            conversations: vec![],
            devices: vec![],
            route: None,
            messages: vec![],
        });
    }
    let value: serde_json::Value =
        serde_json::from_slice(&std::fs::read(path).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
    let identity = value
        .pointer("/card/signing_key")
        .map(|key| hex_bytes(Some(key)));
    let server = value
        .pointer("/card/server")
        .and_then(|v| v.as_str())
        .map(ToOwned::to_owned);
    let contacts: Vec<Contact> = value
        .get("contacts")
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
        .filter_map(|card| {
            Some(Contact {
                id: hex_bytes(card.get("signing_key")),
                server: card.get("server")?.as_str()?.to_owned(),
            })
        })
        .collect();
    let mut groups: Vec<_> = value
        .get("groups")
        .and_then(|v| v.as_object())
        .into_iter()
        .flatten()
        .filter(|(id, _)| id.len() == 32 && id.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .map(|(id, group)| Group {
            id: id.clone(),
            members: group
                .get("members")
                .and_then(|m| m.as_array())
                .map_or(0, Vec::len),
        })
        .collect();
    groups.sort_by(|left, right| left.id.cmp(&right.id));
    let revoked: std::collections::HashSet<_> = value
        .get("revocations")
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
        .map(|revocation| hex_bytes(revocation.get("device_id")))
        .collect();
    let mut devices: Vec<_> = value
        .pointer("/authorized_devices/devices")
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
        .map(|device| Device {
            id: hex_bytes(device.get("device_id")),
            state: "active".into(),
            last_activity: None,
        })
        .collect();
    for id in revoked {
        if !devices.iter().any(|device| device.id == id) {
            devices.push(Device {
                id,
                state: "revoked".into(),
                last_activity: None,
            });
        }
    }
    let messages: Vec<Message> = value
        .get("history")
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
        .filter_map(|message| {
            Some(Message {
                conversation: message.get("conversation")?.as_str()?.to_owned(),
                sender: message.get("sender")?.as_str()?.to_owned(),
                text: message.get("text")?.as_str()?.to_owned(),
                timestamp: message.get("timestamp")?.as_i64()?,
            })
        })
        .collect();
    let read_at = value
        .get("read_at")
        .and_then(|v| v.as_object())
        .cloned()
        .unwrap_or_default();
    let mut conversations: Vec<Conversation> = contacts
        .iter()
        .map(|contact| {
            (
                contact.id.clone(),
                contact.id[..12.min(contact.id.len())].to_owned(),
                "direct".to_owned(),
            )
        })
        .chain(groups.iter().map(|group| {
            (
                format!("group:{}", group.id),
                "Group chat".to_owned(),
                "group".to_owned(),
            )
        }))
        .map(|(id, title, kind)| {
            let latest = messages
                .iter()
                .filter(|message| message.conversation == id)
                .max_by_key(|message| message.timestamp);
            let cursor = read_at
                .get(&id)
                .and_then(serde_json::Value::as_i64)
                .unwrap_or_default();
            let unread = unread_count(&messages, identity.as_deref(), &id, cursor);
            Conversation {
                id,
                title,
                kind,
                preview: latest.map(|message| message.text.clone()),
                timestamp: latest.map(|message| message.timestamp),
                unread,
            }
        })
        .collect();
    sort_conversations(&mut conversations);
    let route = value.get("routing").and_then(|route| {
        Some(Route {
            server: route.get("server")?.as_str()?.to_owned(),
            revision: route.get("revision")?.as_u64()?,
            relay_fingerprint: hex_bytes(route.get("relay_identity")),
            tls_spki_fingerprint: hex_bytes(route.get("tls_spki_fingerprint")),
        })
    });
    Ok(AccountStatus {
        state_exists: true,
        identity,
        server,
        contacts,
        groups,
        conversations,
        devices,
        route,
        messages,
    })
}
#[tauri::command]
fn create_identity(app: tauri::AppHandle, server: String) -> Result<(), String> {
    core(&app, &["create".into(), "--server".into(), server]).map(|_| ())
}
#[tauri::command]
fn fetch_messages(app: tauri::AppHandle) -> Result<Vec<String>, String> {
    core(&app, &["fetch".into()]).map(|output| output.lines().map(ToOwned::to_owned).collect())
}
#[tauri::command]
fn send_direct(app: tauri::AppHandle, to: String, text: String) -> Result<(), String> {
    core(&app, &["send".into(), "--to".into(), to, text]).map(|_| ())
}
#[tauri::command]
fn send_group(app: tauri::AppHandle, group: String, text: String) -> Result<(), String> {
    core(&app, &["group-send".into(), "--group".into(), group, text]).map(|_| ())
}
#[tauri::command]
fn import_contact(app: tauri::AppHandle, card: String) -> Result<(), String> {
    core(&app, &["add-contact".into(), card]).map(|_| ())
}
#[tauri::command]
fn share_card(app: tauri::AppHandle) -> Result<String, String> {
    core(&app, &["card".into()]).map(|value| value.trim().to_owned())
}
#[tauri::command]
fn mark_read(app: tauri::AppHandle, conversation: String) -> Result<(), String> {
    core(
        &app,
        &["mark-read".into(), "--conversation".into(), conversation],
    )
    .map(|_| ())
}
fn main() {
    tauri::Builder::default()
        .setup(|app| {
            let handle = app.handle().clone();
            thread::spawn(move || loop {
                if account_status(handle.clone()).is_ok() {
                    let _ = fetch_messages(handle.clone());
                    if let Ok(status) = account_status(handle.clone()) {
                        let _ = handle.emit("pigeon://state", status);
                    }
                }
                thread::sleep(Duration::from_secs(8));
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            account_status,
            create_identity,
            fetch_messages,
            send_direct,
            send_group,
            import_contact,
            share_card,
            mark_read
        ])
        .run(tauri::generate_context!())
        .expect("run Pigeon");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unread_excludes_local_and_read_messages() {
        let messages = vec![
            Message {
                conversation: "bob".into(),
                sender: "bob".into(),
                text: "old".into(),
                timestamp: 10,
            },
            Message {
                conversation: "bob".into(),
                sender: "alice".into(),
                text: "sent".into(),
                timestamp: 20,
            },
            Message {
                conversation: "bob".into(),
                sender: "bob".into(),
                text: "new".into(),
                timestamp: 30,
            },
        ];
        assert_eq!(unread_count(&messages, Some("alice"), "bob", 10), 1);
    }

    #[test]
    fn conversation_order_is_latest_first_and_deterministic() {
        let mut conversations = vec![
            Conversation {
                id: "b".into(),
                title: "B".into(),
                kind: "direct".into(),
                preview: None,
                timestamp: Some(10),
                unread: 0,
            },
            Conversation {
                id: "a".into(),
                title: "A".into(),
                kind: "direct".into(),
                preview: None,
                timestamp: Some(10),
                unread: 0,
            },
            Conversation {
                id: "c".into(),
                title: "C".into(),
                kind: "direct".into(),
                preview: None,
                timestamp: Some(20),
                unread: 0,
            },
        ];
        sort_conversations(&mut conversations);
        assert_eq!(
            conversations
                .iter()
                .map(|conversation| conversation.id.as_str())
                .collect::<Vec<_>>(),
            ["c", "a", "b"]
        );
    }
}
