//! Versioned account-state serialization; no network or UI dependency.
use super::{Context, Result, State};
use anyhow::bail;
use std::fs;

pub(super) fn load(path: &str) -> Result<State> {
    let state: State = serde_json::from_slice(
        &fs::read(path).with_context(|| format!("read identity state {path}"))?,
    )?;
    if state.state_version != super::ACCOUNT_STATE_VERSION {
        bail!("legacy root-only account state is incompatible with account-genesis security. Export a new encrypted recovery backup from a current client, then import it; legacy state is never silently upgraded")
    }
    pigeon_shared::verify_card(&state.card)?;
    pigeon_shared::verify_device_set(&state.authorized_devices)?;
    Ok(state)
}
pub(super) fn save(path: &str, state: &State) -> Result<()> {
    fs::write(path, serde_json::to_vec_pretty(state)?)?;
    Ok(())
}
