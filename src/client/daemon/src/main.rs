//! Linux-only owner for live Pigeon desktop-client state.
//!
//! This process is deliberately a narrow broker around the platform-neutral
//! client core binary.  It is the only process which writes account-index or
//! account-state files and serializes all core invocations.  Tauri talks to it
//! over a same-UID Unix socket and receives snapshots/events; it never races
//! MLS or sync work by operating state files itself.

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    env, fs,
    io::{BufRead, BufReader, Write},
    os::unix::{
        fs::PermissionsExt,
        net::{UnixListener, UnixStream},
    },
    path::{Path, PathBuf},
    process::Command,
    sync::{
        mpsc::{self, Sender},
        Arc, Mutex,
    },
    thread,
    time::Duration,
};

const MAX_FRAME: usize = 1024 * 1024;
const SOCKET_NAME: &str = "pigeon-client.sock";

#[derive(Debug, Serialize, Deserialize, Clone)]
struct AccountIndex {
    selected: Option<String>,
    accounts: Vec<AccountEntry>,
    #[serde(default = "default_appearance")]
    appearance: String,
}
#[derive(Debug, Serialize, Deserialize, Clone)]
struct AccountEntry {
    id: String,
    label: String,
    identity: String,
}
fn default_appearance() -> String {
    "system".into()
}
impl Default for AccountIndex {
    fn default() -> Self {
        Self {
            selected: None,
            accounts: vec![],
            appearance: default_appearance(),
        }
    }
}

/// The IPC protocol is intentionally finite and typed.  In particular this
/// is not a shell endpoint: `Core` only accepts documented client-core verbs.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
enum Request {
    Ping,
    Snapshot,
    Core { arguments: Vec<String> },
    ReplaceIndex { index: AccountIndex },
    Subscribe,
}
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
enum Response {
    Pong,
    Snapshot(Snapshot),
    Output(String),
    Error(String),
}
#[derive(Debug, Serialize, Deserialize, Clone)]
struct Snapshot {
    index: AccountIndex,
    #[serde(skip_serializing_if = "Option::is_none")]
    state: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pairing: Option<Value>,
    revision: String,
}

struct Daemon {
    data_dir: PathBuf,
    core_bin: PathBuf,
    certificate: Option<PathBuf>,
    index: AccountIndex,
    subscribers: Vec<Sender<Snapshot>>,
    history_counts: HashMap<String, usize>,
}
type Shared = Arc<Mutex<Daemon>>;

fn data_dir_default() -> PathBuf {
    if let Some(value) = env::var_os("PIGEON_DATA_DIR") {
        return PathBuf::from(value);
    }
    env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            let home = env::var_os("HOME").unwrap_or_else(|| ".".into());
            PathBuf::from(home).join(".local/share")
        })
        .join("pigeon")
}
fn socket_default() -> Result<PathBuf> {
    if let Some(value) = env::var_os("PIGEON_DAEMON_SOCKET") {
        return Ok(PathBuf::from(value));
    }
    let runtime = env::var_os("XDG_RUNTIME_DIR")
        .ok_or_else(|| anyhow!("XDG_RUNTIME_DIR is required for pigeon-client-daemon"))?;
    Ok(PathBuf::from(runtime).join("pigeon").join(SOCKET_NAME))
}
fn index_path(data_dir: &Path) -> PathBuf {
    data_dir.join("accounts.json")
}
fn state_path(data_dir: &Path, id: &str) -> PathBuf {
    data_dir.join("accounts").join(format!("{id}.json"))
}
fn pairing_path(data_dir: &Path, id: &str) -> PathBuf {
    state_path(data_dir, id).with_extension("json.pairing")
}
fn load_index(data_dir: &Path) -> Result<AccountIndex> {
    let path = index_path(data_dir);
    if !path.exists() {
        return Ok(AccountIndex::default());
    }
    serde_json::from_slice(&fs::read(&path).with_context(|| format!("read {}", path.display()))?)
        .context("parse account index")
}
fn save_index(data_dir: &Path, index: &AccountIndex) -> Result<()> {
    fs::create_dir_all(data_dir)?;
    let path = index_path(data_dir);
    let temporary = path.with_extension("json.tmp");
    fs::write(&temporary, serde_json::to_vec_pretty(index)?)?;
    fs::set_permissions(&temporary, fs::Permissions::from_mode(0o600))?;
    fs::rename(temporary, path)?;
    Ok(())
}
fn revision(index: &AccountIndex, state: &Option<Value>) -> String {
    let bytes = serde_json::to_vec(&(index, state)).unwrap_or_default();
    hex(&Sha256::digest(bytes))
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn snapshot(daemon: &Daemon) -> Snapshot {
    let state = daemon
        .index
        .selected
        .as_deref()
        .and_then(|id| fs::read(state_path(&daemon.data_dir, id)).ok())
        .and_then(|raw| serde_json::from_slice(&raw).ok());
    let pairing = daemon
        .index
        .selected
        .as_deref()
        .and_then(|id| fs::read(pairing_path(&daemon.data_dir, id)).ok())
        .and_then(|raw| serde_json::from_slice(&raw).ok());
    Snapshot {
        index: daemon.index.clone(),
        revision: revision(&daemon.index, &state),
        state,
        pairing,
    }
}
fn publish(daemon: &mut Daemon) {
    let event = snapshot(daemon);
    daemon
        .subscribers
        .retain(|sender| sender.send(event.clone()).is_ok());
}
fn permitted_core_command(arguments: &[String]) -> bool {
    matches!(
        arguments.first().map(String::as_str),
        Some(
            "create-local"
                | "create"
                | "discover-relay"
                | "configure-relay"
                | "migrate"
                | "export"
                | "import"
                | "set-display-name"
                | "set-nickname"
                | "fetch"
                | "send"
                | "group-send"
                | "add-contact"
                | "card"
                | "mark-read"
                | "revoke-device"
                | "pair-request"
                | "pair-approve"
                | "pair-consume"
                | "pair-cancel"
                | "pair-status"
                | "change-password"
        )
    )
}
fn core_for_selected(daemon: &Daemon, arguments: &[String]) -> Result<String> {
    if !permitted_core_command(arguments) {
        bail!("unsupported daemon client-core operation");
    }
    let selected = daemon
        .index
        .selected
        .as_deref()
        .ok_or_else(|| anyhow!("no local account selected"))?;
    let state = state_path(&daemon.data_dir, selected);
    let parent = state.parent().expect("account state parent");
    fs::create_dir_all(parent)?;
    fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
    let mut command = Command::new(&daemon.core_bin);
    // `--state` and `--certificate` are global Clap options and therefore
    // must precede the subcommand. Keeping this ordering here prevents GUI
    // actions from behaving differently from the historical direct wrapper.
    command.arg("--state").arg(&state);
    if let Some(certificate) = &daemon.certificate {
        command.arg("--certificate").arg(certificate);
    }
    command.args(arguments);
    let output = command
        .output()
        .with_context(|| format!("start client core {}", daemon.core_bin.display()))?;
    if output.status.success() {
        // Core deliberately remains platform-neutral. The Linux owner applies
        // the desktop confidentiality policy after every write, including the
        // pending pairing record which contains local capabilities.
        if state.exists() {
            fs::set_permissions(&state, fs::Permissions::from_mode(0o600))?;
        }
        let pairing = pairing_path(&daemon.data_dir, selected);
        if pairing.exists() {
            fs::set_permissions(pairing, fs::Permissions::from_mode(0o600))?;
        }
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    } else {
        bail!("{}", String::from_utf8_lossy(&output.stderr).trim())
    }
}
fn history_count(value: &Option<Value>) -> usize {
    value
        .as_ref()
        .and_then(|state| state.get("history"))
        .and_then(Value::as_array)
        .map_or(0, Vec::len)
}
fn notify_background_message() {
    // `notify-send` is deliberately best-effort.  The daemon never includes a
    // message preview, so a locked screen does not disclose conversation text.
    let _ = Command::new("notify-send")
        .args(["Pigeon", "New encrypted message"])
        .status();
}
fn execute(shared: &Shared, request: Request) -> Response {
    match request {
        Request::Ping => Response::Pong,
        Request::Snapshot => Response::Snapshot(snapshot(&shared.lock().expect("daemon lock"))),
        Request::ReplaceIndex { index } => {
            if !matches!(index.appearance.as_str(), "system" | "light" | "dark") {
                return Response::Error("invalid appearance".into());
            }
            let mut daemon = shared.lock().expect("daemon lock");
            if let Err(error) = save_index(&daemon.data_dir, &index) {
                return Response::Error(error.to_string());
            }
            daemon.index = index;
            publish(&mut daemon);
            Response::Output(String::new())
        }
        Request::Core { arguments } => {
            let mut daemon = shared.lock().expect("daemon lock");
            match core_for_selected(&daemon, &arguments) {
                Ok(output) => {
                    publish(&mut daemon);
                    Response::Output(output)
                }
                Err(error) => Response::Error(error.to_string()),
            }
        }
        Request::Subscribe => Response::Error("subscribe is a streaming request".into()),
    }
}
fn write_response(stream: &mut UnixStream, response: &Response) -> Result<()> {
    let encoded = serde_json::to_vec(response)?;
    if encoded.len() > MAX_FRAME {
        bail!("IPC response too large");
    }
    stream.write_all(&encoded)?;
    stream.write_all(b"\n")?;
    stream.flush()?;
    Ok(())
}
fn same_user(stream: &UnixStream) -> Result<bool> {
    let mut credentials: libc::ucred = unsafe { std::mem::zeroed() };
    let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut credentials as *mut libc::ucred).cast(),
            &mut length,
        )
    };
    if result != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(peer_uid_authorized(credentials.uid, unsafe {
        libc::geteuid()
    }))
}
fn peer_uid_authorized(peer_uid: libc::uid_t, daemon_uid: libc::uid_t) -> bool {
    peer_uid == daemon_uid
}
use std::os::unix::io::AsRawFd;
fn handle_stream(mut stream: UnixStream, shared: Shared) -> Result<()> {
    if !same_user(&stream)? {
        bail!("rejected IPC peer from another Unix user");
    }
    let reader_stream = stream.try_clone()?;
    let mut reader = BufReader::new(reader_stream);
    let mut line = String::new();
    reader.read_line(&mut line)?;
    if line.len() > MAX_FRAME {
        bail!("IPC request too large");
    }
    let request: Request = serde_json::from_str(line.trim_end()).context("invalid IPC request")?;
    if matches!(request, Request::Subscribe) {
        let (sender, receiver) = mpsc::channel();
        {
            let mut daemon = shared.lock().expect("daemon lock");
            write_response(&mut stream, &Response::Snapshot(snapshot(&daemon)))?;
            daemon.subscribers.push(sender);
        }
        for event in receiver {
            if write_response(&mut stream, &Response::Snapshot(event)).is_err() {
                break;
            }
        }
        return Ok(());
    }
    write_response(&mut stream, &execute(&shared, request))
}
fn synchronize(shared: &Shared) {
    let mut daemon = shared.lock().expect("daemon lock");
    let accounts = daemon.index.accounts.clone();
    let selected = daemon.index.selected.clone();
    for account in accounts {
        let state = state_path(&daemon.data_dir, &account.id);
        if !state.exists() {
            // A joining device retains its own request/capabilities in a
            // daemon-owned pending file. Once an approval appears, consume is
            // safe to retry and the relay enforces its one-time semantics.
            if pairing_path(&daemon.data_dir, &account.id).exists() {
                let old = daemon.index.selected.clone();
                daemon.index.selected = Some(account.id.clone());
                let _ = core_for_selected(&daemon, &["pair-consume".into()]);
                daemon.index.selected = old;
            }
            continue;
        }
        let before: Option<Value> = fs::read(&state)
            .ok()
            .and_then(|raw| serde_json::from_slice(&raw).ok());
        // Fetch each account independently without ever changing the selected
        // account persisted for an open GUI.
        let old = daemon.index.selected.clone();
        daemon.index.selected = Some(account.id.clone());
        let _ = core_for_selected(&daemon, &["fetch".into()]);
        daemon.index.selected = old;
        let after: Option<Value> = fs::read(&state)
            .ok()
            .and_then(|raw| serde_json::from_slice(&raw).ok());
        let previous = daemon
            .history_counts
            .insert(account.id.clone(), history_count(&after))
            .unwrap_or_else(|| history_count(&before));
        if history_count(&after) > previous && daemon.subscribers.is_empty() {
            notify_background_message();
        }
    }
    daemon.index.selected = selected;
    publish(&mut daemon);
}
fn establish_socket(path: &Path) -> Result<UnixListener> {
    fs::create_dir_all(
        path.parent()
            .ok_or_else(|| anyhow!("socket has no parent"))?,
    )?;
    fs::set_permissions(path.parent().unwrap(), fs::Permissions::from_mode(0o700))?;
    if path.exists() {
        match UnixStream::connect(path) {
            Ok(_) => bail!(
                "another pigeon-client-daemon is already listening at {}",
                path.display()
            ),
            Err(_) => fs::remove_file(path)?,
        }
    }
    let listener = UnixListener::bind(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(listener)
}
fn main() -> Result<()> {
    let mut arguments = env::args_os().skip(1);
    let mut data_dir = None;
    let mut socket = None;
    while let Some(argument) = arguments.next() {
        match argument.to_string_lossy().as_ref() {
            "--data-dir" => data_dir = arguments.next().map(PathBuf::from),
            "--socket" => socket = arguments.next().map(PathBuf::from),
            "--help" | "-h" => {
                println!("pigeon-client-daemon [--data-dir PATH] [--socket PATH]");
                return Ok(());
            }
            other => bail!("unknown argument {other}"),
        }
    }
    let data_dir = data_dir.unwrap_or_else(data_dir_default);
    let socket = socket.unwrap_or(socket_default()?);
    fs::create_dir_all(&data_dir)?;
    fs::set_permissions(&data_dir, fs::Permissions::from_mode(0o700))?;
    let core_bin = env::var_os("PIGEON_CLIENT_BIN")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            let packaged = PathBuf::from("/usr/lib/pigeon/pigeon-client-core");
            if packaged.exists() {
                packaged
            } else {
                PathBuf::from("pigeon-client")
            }
        });
    let certificate = env::var_os("PIGEON_CERTIFICATE").map(PathBuf::from);
    let daemon = Arc::new(Mutex::new(Daemon {
        index: load_index(&data_dir)?,
        data_dir,
        core_bin,
        certificate,
        subscribers: vec![],
        history_counts: HashMap::new(),
    }));
    let listener = establish_socket(&socket)?;
    let sync_daemon = daemon.clone();
    thread::spawn(move || loop {
        thread::sleep(Duration::from_secs(5));
        synchronize(&sync_daemon);
    });
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let daemon = daemon.clone();
                thread::spawn(move || {
                    let _ = handle_stream(stream, daemon);
                });
            }
            Err(error) => eprintln!("pigeon-client-daemon socket error: {error}"),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};
    #[test]
    fn allowed_commands_are_closed() {
        assert!(permitted_core_command(&["fetch".into()]));
        assert!(!permitted_core_command(&["shell".into()]));
    }
    #[test]
    fn snapshot_revision_changes_with_state() {
        let index = AccountIndex::default();
        assert_ne!(
            revision(&index, &None),
            revision(&index, &Some(serde_json::json!({"history":[]})))
        );
    }
    #[test]
    fn pairing_paths_keep_accounts_isolated() {
        let root = PathBuf::from("/tmp/pigeon-daemon-test");
        assert_ne!(pairing_path(&root, "alice"), pairing_path(&root, "bob"));
    }

    #[test]
    fn ipc_authorization_rejects_another_local_user() {
        assert!(peer_uid_authorized(1000, 1000));
        assert!(!peer_uid_authorized(1001, 1000));
    }

    #[test]
    fn account_index_survives_daemon_restart_without_cross_account_merge() {
        let root = std::env::temp_dir().join(format!(
            "pigeon-daemon-index-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let first = AccountIndex {
            selected: Some("alice-device".into()),
            accounts: vec![
                AccountEntry {
                    id: "alice-device".into(),
                    label: "Alice".into(),
                    identity: "alice-genesis".into(),
                },
                AccountEntry {
                    id: "bob-device".into(),
                    label: "Bob".into(),
                    identity: "bob-genesis".into(),
                },
            ],
            appearance: "dark".into(),
        };
        save_index(&root, &first).unwrap();
        let after_restart = load_index(&root).unwrap();
        assert_eq!(after_restart.selected.as_deref(), Some("alice-device"));
        assert_eq!(after_restart.accounts.len(), 2);
        assert_ne!(
            state_path(&root, "alice-device"),
            state_path(&root, "bob-device")
        );
        assert_eq!(after_restart.appearance, "dark");
    }

    #[test]
    fn ipc_socket_and_parent_are_private() {
        let root = std::env::temp_dir().join(format!(
            "pigeon-daemon-socket-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let socket = root.join("runtime/pigeon.sock");
        let _listener = establish_socket(&socket).unwrap();
        assert_eq!(
            fs::metadata(&socket).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(socket.parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
    }
}
