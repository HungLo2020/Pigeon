//! Desktop daemon IPC. Tauri deliberately has no direct account-file or
//! client-core access: the daemon serializes every mutation and sync operation.
use super::AccountIndex;
use serde_json::{json, Value};
use std::{
    env,
    io::{BufRead, BufReader, Write},
    os::unix::net::UnixStream,
    path::PathBuf,
    process::Command,
    thread,
    time::Duration,
};

pub(super) fn app_data(_app: &tauri::AppHandle) -> Result<PathBuf, String> {
    if let Some(path) = env::var_os("PIGEON_DATA_DIR") {
        return Ok(PathBuf::from(path));
    }
    let base = env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(env::var_os("HOME").unwrap_or_else(|| ".".into())).join(".local/share")
        });
    Ok(base.join("pigeon"))
}
fn socket_path() -> Result<PathBuf, String> {
    if let Some(path) = env::var_os("PIGEON_DAEMON_SOCKET") {
        return Ok(PathBuf::from(path));
    }
    let runtime = env::var_os("XDG_RUNTIME_DIR")
        .ok_or("XDG_RUNTIME_DIR is unavailable; cannot connect to Pigeon daemon")?;
    Ok(PathBuf::from(runtime).join("pigeon/pigeon-client.sock"))
}
fn start_daemon(app: &tauri::AppHandle) -> Result<(), String> {
    let executable =
        env::var("PIGEON_CLIENT_DAEMON_BIN").unwrap_or_else(|_| "pigeon-client-daemon".into());
    let mut command = Command::new(executable);
    command.arg("--data-dir").arg(app_data(app)?);
    if let Ok(socket) = env::var("PIGEON_DAEMON_SOCKET") {
        command.arg("--socket").arg(socket);
    }
    command
        .spawn()
        .map_err(|error| format!("start pigeon-client-daemon: {error}"))?;
    Ok(())
}
fn connect(app: &tauri::AppHandle) -> Result<UnixStream, String> {
    let socket = socket_path()?;
    if let Ok(stream) = UnixStream::connect(&socket) {
        return Ok(stream);
    }
    start_daemon(app)?;
    for _ in 0..30 {
        thread::sleep(Duration::from_millis(100));
        if let Ok(stream) = UnixStream::connect(&socket) {
            return Ok(stream);
        }
    }
    Err(format!(
        "pigeon-client-daemon did not start at {}",
        socket.display()
    ))
}
fn request(app: &tauri::AppHandle, value: Value) -> Result<Value, String> {
    let mut stream = connect(app)?;
    serde_json::to_writer(&mut stream, &value).map_err(|error| error.to_string())?;
    stream.write_all(b"\n").map_err(|error| error.to_string())?;
    stream.flush().map_err(|error| error.to_string())?;
    let mut line = String::new();
    BufReader::new(stream)
        .read_line(&mut line)
        .map_err(|error| error.to_string())?;
    let response: Value =
        serde_json::from_str(&line).map_err(|error| format!("invalid daemon response: {error}"))?;
    if response.get("type").and_then(Value::as_str) == Some("error") {
        return Err(response
            .get("data")
            .and_then(Value::as_str)
            .unwrap_or("daemon operation failed")
            .into());
    }
    Ok(response)
}
pub(super) fn snapshot(app: &tauri::AppHandle) -> Result<Value, String> {
    let response = request(app, json!({"type":"snapshot"}))?;
    response
        .get("data")
        .cloned()
        .ok_or("daemon snapshot was missing data".into())
}
pub(super) fn index(app: &tauri::AppHandle) -> Result<AccountIndex, String> {
    serde_json::from_value(
        snapshot(app)?
            .get("index")
            .cloned()
            .ok_or("daemon snapshot lacks account index")?,
    )
    .map_err(|error| error.to_string())
}
pub(super) fn save_index(app: &tauri::AppHandle, index: &AccountIndex) -> Result<(), String> {
    request(app, json!({"type":"replace_index","data":{"index":index}})).map(|_| ())
}
pub(super) fn core(app: &tauri::AppHandle, arguments: &[String]) -> Result<String, String> {
    let response = request(app, json!({"type":"core","data":{"arguments":arguments}}))?;
    response
        .get("data")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or("daemon core response was missing output".into())
}
pub(super) fn subscribe(app: &tauri::AppHandle) -> Result<UnixStream, String> {
    let mut stream = connect(app)?;
    serde_json::to_writer(&mut stream, &json!({"type":"subscribe"}))
        .map_err(|error| error.to_string())?;
    stream.write_all(b"\n").map_err(|error| error.to_string())?;
    stream.flush().map_err(|error| error.to_string())?;
    Ok(stream)
}
