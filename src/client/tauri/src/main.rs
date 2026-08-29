use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fs, thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tauri::Emitter;

mod account_store;
mod state_mapping;
use account_store::{app_data, core, index, save_index, state_path};
use state_mapping::{hex_bytes, sort_conversations, unread_count};

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
    accounts: Vec<AccountEntry>,
    selected_account: Option<String>,
    needs_relay: bool,
}
#[derive(Serialize, Deserialize, Clone)]
struct AccountEntry {
    id: String,
    label: String,
    identity: String,
}
#[derive(Serialize, Deserialize, Default)]
struct AccountIndex {
    selected: Option<String>,
    accounts: Vec<AccountEntry>,
}

#[tauri::command]
fn account_status(app: tauri::AppHandle) -> Result<AccountStatus, String> {
    let account_index = index(&app)?;
    if account_index.selected.is_none() {
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
            accounts: account_index.accounts,
            selected_account: None,
            needs_relay: false,
        });
    }
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
            accounts: account_index.accounts,
            selected_account: account_index.selected,
            needs_relay: false,
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
        .filter(|(id, group)| {
            id.len() == 32
                && id.bytes().all(|byte| byte.is_ascii_hexdigit())
                // Older direct Welcome handling persisted a group entry for a
                // two-identity direct conversation. Never present that as a
                // group chat.
                && group
                    .get("members")
                    .and_then(|members| members.as_array())
                    .is_some_and(|members| members.len() > 2)
        })
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
    let mut messages: Vec<Message> = value
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
    // A direct chat is also an MLS group internally. Older persisted state
    // recorded its canonical MLS group ID in `groups`; map that two-identity
    // representation back to the verified contact conversation for UI/history
    // purposes without changing MLS state or ownerless-group membership.
    let direct_group_conversations: HashMap<String, String> = value
        .get("groups")
        .and_then(|groups| groups.as_object())
        .into_iter()
        .flatten()
        .filter_map(|(group_id, group)| {
            let members: Vec<String> = group
                .get("members")?
                .as_array()?
                .iter()
                .map(|member| hex_bytes(Some(member)))
                .collect();
            if members.len() != 2 {
                return None;
            }
            let other = members
                .iter()
                .find(|member| Some(member.as_str()) != identity.as_deref())?;
            contacts
                .iter()
                .any(|contact| contact.id == *other)
                .then(|| (format!("group:{group_id}"), other.clone()))
        })
        .collect();
    for message in &mut messages {
        if let Some(conversation) = direct_group_conversations.get(&message.conversation) {
            message.conversation = conversation.clone();
        }
    }
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
        accounts: account_index.accounts,
        selected_account: account_index.selected,
        needs_relay: value.get("routing").is_none(),
    })
}
#[tauri::command]
fn create_account(app: tauri::AppHandle) -> Result<(), String> {
    let id = format!(
        "account-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| e.to_string())?
            .as_nanos()
    );
    let path = app_data(&app)?.join("accounts").join(format!("{id}.json"));
    fs::create_dir_all(path.parent().ok_or("missing account parent")?)
        .map_err(|e| e.to_string())?;
    let mut account_index = index(&app)?;
    account_index.selected = Some(id.clone());
    save_index(&app, &account_index)?;
    core(&app, &["create-local".into()])?;
    let value: serde_json::Value =
        serde_json::from_slice(&fs::read(&path).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
    let identity = hex_bytes(value.pointer("/card/signing_key"));
    account_index.accounts.push(AccountEntry {
        id,
        label: format!("Account {}", &identity[..12]),
        identity,
    });
    save_index(&app, &account_index)
}
#[tauri::command]
fn select_account(app: tauri::AppHandle, id: String) -> Result<(), String> {
    let mut account_index = index(&app)?;
    if !account_index
        .accounts
        .iter()
        .any(|account| account.id == id)
    {
        return Err("unknown local account".into());
    };
    account_index.selected = Some(id);
    save_index(&app, &account_index)
}
#[tauri::command]
fn configure_relay(app: tauri::AppHandle, server: String) -> Result<(), String> {
    core(&app, &["configure-relay".into(), "--server".into(), server]).map(|_| ())
}
#[tauri::command]
fn migrate_relay(app: tauri::AppHandle, server: String) -> Result<(), String> {
    core(&app, &["migrate".into(), "--server".into(), server]).map(|_| ())
}
#[tauri::command]
fn import_account(app: tauri::AppHandle, backup: String) -> Result<(), String> {
    let id = format!(
        "account-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| e.to_string())?
            .as_nanos()
    );
    let path = app_data(&app)?.join("accounts").join(format!("{id}.json"));
    fs::create_dir_all(path.parent().ok_or("missing account parent")?)
        .map_err(|e| e.to_string())?;
    let mut account_index = index(&app)?;
    let previous_selected = account_index.selected.clone();
    account_index.selected = Some(id.clone());
    save_index(&app, &account_index)?;
    if let Err(error) = core(&app, &["import".into(), "--input".into(), backup]) {
        account_index.selected = previous_selected;
        save_index(&app, &account_index)?;
        let _ = fs::remove_file(&path);
        return Err(error);
    }
    let value: serde_json::Value =
        serde_json::from_slice(&fs::read(path).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
    let identity = hex_bytes(value.pointer("/card/signing_key"));
    account_index.accounts.push(AccountEntry {
        id,
        label: format!("Account {}", &identity[..12]),
        identity,
    });
    save_index(&app, &account_index)
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
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            let handle = app.handle().clone();
            thread::spawn(move || loop {
                if let Ok(before) = account_status(handle.clone()) {
                    if before.state_exists {
                        if let Err(error) = fetch_messages(handle.clone()) {
                            eprintln!("Pigeon background sync failed: {error}");
                            let _ = handle.emit("pigeon://sync-error", error);
                        }
                    }
                    if let Ok(status) = account_status(handle.clone()) {
                        // Avoid replacing the frontend DOM every polling cycle
                        // when sync did not change account-visible state.
                        if serde_json::to_string(&before).ok()
                            != serde_json::to_string(&status).ok()
                        {
                            let _ = handle.emit("pigeon://state", status);
                        }
                    }
                }
                thread::sleep(Duration::from_secs(8));
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            account_status,
            create_account,
            select_account,
            configure_relay,
            migrate_relay,
            import_account,
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
