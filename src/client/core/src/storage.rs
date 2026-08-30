//! Versioned account-state serialization; no network or UI dependency.
use super::{Context, Result, State};
use anyhow::bail;
use std::fs;

pub(super) fn load(path: &str) -> Result<State> {
    let bytes = fs::read(path).with_context(|| format!("read identity state {path}"))?;
    let version = serde_json::from_slice::<serde_json::Value>(&bytes)?
        .get("state_version")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or_default() as u8;
    if version != super::ACCOUNT_STATE_VERSION {
        bail!("account state format {version} does not preserve canonical-genesis identity keys. Export a fresh encrypted recovery backup with a compatible client and import it; compact-ID-only state is never silently upgraded")
    }
    let state: State = serde_json::from_slice(&bytes)?;
    if state.state_version != super::ACCOUNT_STATE_VERSION {
        bail!("invalid account state version")
    }
    pigeon_shared::verify_card(&state.card)?;
    pigeon_shared::verify_device_set(&state.authorized_devices)?;
    Ok(state)
}
pub(super) fn save(path: &str, state: &State) -> Result<()> {
    fs::write(path, serde_json::to_vec_pretty(state)?)?;
    Ok(())
}
