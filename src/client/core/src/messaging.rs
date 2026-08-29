//! MLS transport framing that remains opaque to relays.

use super::{ContactCard, Context, Result, RoutingRecord, State};
use anyhow::bail;
use serde::{Deserialize, Serialize};

const DISCOVERY_ENVELOPE_MAGIC: &[u8] = b"PIGEONMD";
const DISCOVERY_ENVELOPE_VERSION: u8 = 1;

#[derive(Serialize, Deserialize)]
struct DiscoveryEnvelope {
    version: u8,
    mls_payload: Vec<u8>,
    sender_card: ContactCard,
    sender_route: RoutingRecord,
}
type DiscoveryMetadata = (ContactCard, RoutingRecord);

pub(super) fn wrap_mls_payload(state: &State, mls_payload: Vec<u8>) -> Result<Vec<u8>> {
    let sender_route = state
        .routing
        .clone()
        .context("cannot send MLS data before this account has a signed route")?;
    let mut payload = DISCOVERY_ENVELOPE_MAGIC.to_vec();
    payload.extend(bincode::serialize(&DiscoveryEnvelope {
        version: DISCOVERY_ENVELOPE_VERSION,
        mls_payload,
        sender_card: state.card.clone(),
        sender_route,
    })?);
    Ok(payload)
}

pub(super) fn unwrap_mls_payload(payload: Vec<u8>) -> Result<(Vec<u8>, Option<DiscoveryMetadata>)> {
    if !payload.starts_with(DISCOVERY_ENVELOPE_MAGIC) {
        return Ok((payload, None));
    }
    let envelope: DiscoveryEnvelope =
        bincode::deserialize(&payload[DISCOVERY_ENVELOPE_MAGIC.len()..])?;
    if envelope.version != DISCOVERY_ENVELOPE_VERSION {
        bail!("unsupported MLS discovery envelope version")
    }
    Ok((
        envelope.mls_payload,
        Some((envelope.sender_card, envelope.sender_route)),
    ))
}
