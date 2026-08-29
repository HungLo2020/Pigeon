//! Versioned account-state serialization; no network or UI dependency.
use super::{Context, Result, State};
use anyhow::bail;
use std::fs;

pub(super) fn load(path: &str) -> Result<State> {
    let state: State = serde_json::from_slice(
        &fs::read(path).with_context(|| format!("read identity state {path}"))?,
    )?;
    if state.routing.is_none() && state.state_version == 0 {
        bail!("legacy identity state has no versioned relay-bound routing record; re-import from a current backup")
    }
    Ok(state)
}
pub(super) fn save(path: &str, state: &State) -> Result<()> {
    fs::write(path, serde_json::to_vec_pretty(state)?)?;
    Ok(())
}
