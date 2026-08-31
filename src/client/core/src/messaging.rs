//! MLS transport framing that remains opaque to relays.

use super::{AttachmentDescriptor, ContactCard, Context, Result, RoutingRecord, State};
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

/// Versioned MLS application content. Older peers emitted UTF-8 text directly;
/// decoding deliberately retains that strictly local compatibility while all
/// new attachment metadata remains inside MLS encryption.
const APPLICATION_CONTENT_VERSION: u8 = 1;
#[derive(Serialize, Deserialize)]
pub(super) enum ApplicationContent {
    Text(String),
    Attachment(AttachmentDescriptor),
}

pub(super) fn encode_application(content: ApplicationContent) -> Result<Vec<u8>> {
    let mut bytes = b"PIGEONAPP".to_vec();
    bytes.push(APPLICATION_CONTENT_VERSION);
    bytes.extend(bincode::serialize(&content)?);
    Ok(bytes)
}

pub(super) fn decode_application(bytes: Vec<u8>) -> Result<ApplicationContent> {
    const MAGIC: &[u8] = b"PIGEONAPP";
    if !bytes.starts_with(MAGIC) {
        return Ok(ApplicationContent::Text(String::from_utf8(bytes)?));
    }
    if bytes.get(MAGIC.len()).copied() != Some(APPLICATION_CONTENT_VERSION) {
        bail!("unsupported MLS application content version")
    }
    Ok(bincode::deserialize(&bytes[MAGIC.len() + 1..])?)
}

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
