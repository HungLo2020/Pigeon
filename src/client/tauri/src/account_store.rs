//! Local account selection and isolated core-process invocation.
use super::AccountIndex;
use std::{fs, path::PathBuf, process::Command};
use tauri::Manager;

pub(super) fn app_data(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    app.path().app_data_dir().map_err(|e| e.to_string())
}
fn index_path(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    Ok(app_data(app)?.join("accounts.json"))
}
pub(super) fn index(app: &tauri::AppHandle) -> Result<AccountIndex, String> {
    let path = index_path(app)?;
    if path.exists() {
        serde_json::from_slice(&fs::read(path).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())
    } else {
        Ok(AccountIndex::default())
    }
}
pub(super) fn save_index(app: &tauri::AppHandle, index: &AccountIndex) -> Result<(), String> {
    let path = index_path(app)?;
    fs::create_dir_all(path.parent().ok_or("missing app data parent")?)
        .map_err(|e| e.to_string())?;
    fs::write(
        path,
        serde_json::to_vec_pretty(index).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())
}
pub(super) fn state_path(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    let account_index = index(app)?;
    let id = account_index.selected.ok_or("no local account selected")?;
    Ok(app_data(app)?.join("accounts").join(format!("{id}.json")))
}
pub(super) fn core(app: &tauri::AppHandle, arguments: &[String]) -> Result<String, String> {
    let state = state_path(app)?;
    if let Some(parent) = state.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
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
