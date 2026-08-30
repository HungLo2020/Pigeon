use anyhow::Result;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hpke::{
    aead::AesGcm128, kdf::HkdfSha256, kem::X25519HkdfSha256, setup_receiver, setup_sender,
    Deserializable, OpModeR, OpModeS, Serializable,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};
use x509_parser::prelude::parse_x509_certificate;

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct DeviceRecord {
    pub identity: [u8; 32],
    pub device_id: [u8; 32],
    pub device_key: [u8; 32],
    pub mls_key_package: Vec<u8>,
    pub authorization_revision: u64,
    pub signature: Vec<u8>,
}
/// Public, root-authoritative device roster. This is distinct from a device's
/// local private credential and from the relay's observed delivery state.
#[derive(Clone, Serialize, Deserialize, Debug, Default)]
pub struct AuthorizedDeviceSet {
    pub identity: [u8; 32],
    pub revision: u64,
    pub devices: Vec<DeviceRecord>,
}
#[derive(Clone, Copy, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub enum DeviceState {
    Active,
    Dormant,
    Revoked,
}
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct DeviceRevocation {
    pub identity: [u8; 32],
    pub device_id: [u8; 32],
    pub revision: u64,
    pub signature: Vec<u8>,
}
/// Mutable, root-signed routing metadata.  It is deliberately separate from
/// the stable root identity and device authorization records.
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct RoutingRecord {
    pub version: u8,
    pub identity: [u8; 32],
    pub server: String,
    pub revision: u64,
    pub parent_revision: u64,
    pub relay_identity: [u8; 32],
    /// SHA-256 of the DER SubjectPublicKeyInfo in the relay TLS certificate.
    /// It is a signed pin, not a CA assertion or TOFU value.
    pub tls_spki_fingerprint: [u8; 32],
    pub signature: Vec<u8>,
}
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct RelayDescriptor {
    pub identity: [u8; 32],
    pub tls_spki_fingerprint: [u8; 32],
}
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct ContactCard {
    #[serde(default)]
    pub profile_version: u8,
    pub signing_key: [u8; 32],
    pub encryption_key: [u8; 32],
    pub server: String,
    pub revision: u64,
    pub devices: Vec<DeviceRecord>,
    #[serde(default)]
    pub display_name: String,
    pub signature: Vec<u8>,
}
/// Opaque MLS wire data. The relay validates routing metadata only; it never
/// parses MLS payloads or holds MLS private state.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct MlsRecord {
    pub recipient_identity: [u8; 32],
    pub sender_device: [u8; 32],
    pub target_devices: Vec<[u8; 32]>,
    pub payload: Vec<u8>,
}
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct RelayForward {
    pub version: u8,
    pub route: RoutingRecord,
    pub record: MlsRecord,
    pub sender_relay: [u8; 32],
    pub signature: Vec<u8>,
}
pub const PAIRING_VERSION: u8 = 1;
#[derive(Clone, Copy, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub enum PairingArtifactKind {
    PublicRequest,
    Approval,
    EncryptedBootstrap,
}
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct PairingRelayArtifact {
    pub version: u8,
    pub identity: [u8; 32],
    pub session_id: [u8; 16],
    pub nonce: [u8; 16],
    pub kind: PairingArtifactKind,
    pub expires_at: i64,
    pub capability_commitment: [u8; 32],
    pub payload: Vec<u8>,
}
pub fn capability_commitment(capability: &[u8; 32]) -> [u8; 32] {
    Sha256::digest(capability).into()
}
pub fn verify_pairing_artifact(a: &PairingRelayArtifact, now: i64) -> Result<()> {
    if a.version != PAIRING_VERSION || a.expires_at <= now {
        anyhow::bail!("invalid or expired pairing artifact")
    }
    Ok(())
}
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct PairingRequest {
    pub version: u8,
    pub identity: [u8; 32],
    pub session_id: [u8; 16],
    pub nonce: [u8; 16],
    pub expires_at: i64,
    pub device: DeviceRecord,
    pub hpke_public_key: [u8; 32],
    /// Commitments keep both relay capabilities out of QR/copyable request text.
    pub bootstrap_capability_commitment: [u8; 32],
    pub cancel_capability_commitment: [u8; 32],
}
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct PairingApproval {
    pub version: u8,
    pub identity: [u8; 32],
    pub session_id: [u8; 16],
    pub nonce: [u8; 16],
    pub device: DeviceRecord,
    pub roster_revision: u64,
    pub roster_digest: [u8; 32],
    pub expires_at: i64,
    pub bootstrap_hash: [u8; 32],
    pub bootstrap_capability_commitment: [u8; 32],
    pub signature: Vec<u8>,
}
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct PairingCancel {
    pub version: u8,
    pub identity: [u8; 32],
    pub session_id: [u8; 16],
    pub nonce: [u8; 16],
    pub expires_at: i64,
}
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct BootstrapPayload {
    pub version: u8,
    pub root_secret: [u8; 32],
    pub roster: AuthorizedDeviceSet,
    pub routing: Option<RoutingRecord>,
    pub contacts: Vec<ContactCard>,
    pub control_state: Vec<u8>,
    pub mls_bootstrap: Vec<Vec<u8>>,
}
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct EncryptedBootstrap {
    pub version: u8,
    pub encapsulated_key: Vec<u8>,
    pub ciphertext: Vec<u8>,
}
fn pairing_bytes<T: Serialize>(value: &T) -> Vec<u8> {
    bincode::serialize(value).expect("serializable pairing")
}
fn approval_bytes(a: &PairingApproval) -> Vec<u8> {
    pairing_bytes(&(
        a.version,
        a.identity,
        a.session_id,
        a.nonce,
        &a.device,
        a.roster_revision,
        a.roster_digest,
        a.expires_at,
        a.bootstrap_hash,
        a.bootstrap_capability_commitment,
    ))
}
pub fn verify_pairing_request(r: &PairingRequest, now: i64) -> Result<()> {
    if r.version != PAIRING_VERSION || r.expires_at <= now || r.device.identity != r.identity {
        anyhow::bail!("invalid or expired pairing request")
    }
    // A joining device does not yet possess the root key, so this is public
    // device material rather than an already-authorized DeviceRecord. The
    // approving device turns this exact material into a signed record.
    if r.device.device_id != r.device.device_key || r.device.mls_key_package.is_empty() {
        anyhow::bail!("invalid pairing device material")
    }
    Ok(())
}
pub fn authorize_pairing_device(
    root: &SigningKey,
    material: &DeviceRecord,
    authorization_revision: u64,
) -> DeviceRecord {
    let mut device = material.clone();
    device.identity = root.verifying_key().to_bytes();
    device.device_id = device.device_key;
    device.authorization_revision = authorization_revision;
    device.signature = root.sign(&device_bytes(&device)).to_bytes().to_vec();
    device
}
pub fn make_pairing_approval(
    root: &SigningKey,
    r: &PairingRequest,
    roster: &AuthorizedDeviceSet,
    bootstrap_hash: [u8; 32],
) -> Result<PairingApproval> {
    if roster.identity != r.identity
        || !roster
            .devices
            .iter()
            .any(|device| device.device_id == r.device.device_id)
    {
        anyhow::bail!("pairing approval roster does not contain requested device")
    }
    let device = roster
        .devices
        .iter()
        .find(|device| device.device_id == r.device.device_id)
        .expect("checked roster membership")
        .clone();
    let mut a = PairingApproval {
        version: PAIRING_VERSION,
        identity: r.identity,
        session_id: r.session_id,
        nonce: r.nonce,
        device: device.clone(),
        roster_revision: roster.revision,
        roster_digest: Sha256::digest(pairing_bytes(roster)).into(),
        expires_at: r.expires_at,
        bootstrap_hash,
        bootstrap_capability_commitment: r.bootstrap_capability_commitment,
        signature: vec![0; 64],
    };
    a.signature = root.sign(&approval_bytes(&a)).to_bytes().to_vec();
    Ok(a)
}
pub fn verify_pairing_approval(r: &PairingRequest, a: &PairingApproval, now: i64) -> Result<()> {
    verify_pairing_request(r, now)?;
    if a.version != PAIRING_VERSION
        || a.expires_at <= now
        || a.identity != r.identity
        || a.session_id != r.session_id
        || a.nonce != r.nonce
        || a.device.device_id != r.device.device_id
        || a.device.device_key != r.device.device_key
        || a.device.mls_key_package != r.device.mls_key_package
        || a.bootstrap_capability_commitment != r.bootstrap_capability_commitment
    {
        anyhow::bail!("pairing approval does not bind request")
    }
    verify_device(&a.device)?;
    VerifyingKey::from_bytes(&a.identity)?
        .verify(&approval_bytes(a), &signature(&a.signature)?)
        .map_err(Into::into)
}
pub fn seal_bootstrap(r: &PairingRequest, p: &BootstrapPayload) -> Result<EncryptedBootstrap> {
    let pk = <X25519HkdfSha256 as hpke::Kem>::PublicKey::from_bytes(&r.hpke_public_key)?;
    let (enc, mut ctx) = setup_sender::<AesGcm128, HkdfSha256, X25519HkdfSha256>(
        &OpModeS::Base,
        &pk,
        &pairing_bytes(r),
    )?;
    Ok(EncryptedBootstrap {
        version: PAIRING_VERSION,
        encapsulated_key: enc.to_bytes().to_vec(),
        ciphertext: ctx.seal(&pairing_bytes(p), &pairing_bytes(r))?,
    })
}
pub fn open_bootstrap(
    r: &PairingRequest,
    secret: [u8; 32],
    e: &EncryptedBootstrap,
) -> Result<BootstrapPayload> {
    if e.version != PAIRING_VERSION {
        anyhow::bail!("unsupported bootstrap version")
    }
    let sk = <X25519HkdfSha256 as hpke::Kem>::PrivateKey::from_bytes(&secret)?;
    let enc = <X25519HkdfSha256 as hpke::Kem>::EncappedKey::from_bytes(&e.encapsulated_key)?;
    let mut ctx = setup_receiver::<AesGcm128, HkdfSha256, X25519HkdfSha256>(
        &OpModeR::Base,
        &sk,
        &enc,
        &pairing_bytes(r),
    )?;
    let p: BootstrapPayload = bincode::deserialize(&ctx.open(&e.ciphertext, &pairing_bytes(r))?)?;
    if p.version != PAIRING_VERSION {
        anyhow::bail!("unsupported payload version")
    }
    Ok(p)
}
#[derive(Serialize, Deserialize, Debug)]
#[allow(clippy::large_enum_variant)]
pub enum Request {
    Register {
        card: ContactCard,
        device: DeviceRecord,
        device_signature: Vec<u8>,
    },
    RevokeDevice(DeviceRevocation),
    GetRevocations {
        identity: [u8; 32],
    },
    PublishRouting(RoutingRecord),
    GetRouting {
        identity: [u8; 32],
    },
    GetRelayDescriptor,
    QueueForward {
        record: MlsRecord,
        route: RoutingRecord,
    },
    ForwardMls(RelayForward),
    PublishKeyPackage {
        identity: [u8; 32],
        key_package: Vec<u8>,
    },
    GetKeyPackage {
        identity: [u8; 32],
    },
    SendMls(MlsRecord),
    Fetch {
        identity: [u8; 32],
        device_id: [u8; 32],
        known_routing_revision: u64,
    },
    Acknowledge {
        device_id: [u8; 32],
        record_ids: Vec<i64>,
        signature: Vec<u8>,
    },
    PublishPairingArtifact(PairingRelayArtifact),
    FetchPairingRequest {
        identity: [u8; 32],
        session_id: [u8; 16],
    },
    FetchConsumePairingBootstrap {
        identity: [u8; 32],
        session_id: [u8; 16],
        capability: [u8; 32],
    },
    CancelPairing {
        identity: [u8; 32],
        session_id: [u8; 16],
        capability: [u8; 32],
    },
}
#[derive(Serialize, Deserialize, Debug)]
pub enum Response {
    Ok,
    KeyPackage(Option<Vec<u8>>),
    MlsMessages(Vec<(i64, MlsRecord)>),
    Revocations(Vec<DeviceRevocation>),
    Routing(Option<RoutingRecord>),
    Moved(RoutingRecord),
    RelayDescriptor(RelayDescriptor),
    Error(String),
    PairingArtifact(PairingRelayArtifact),
    PairingNotFound,
    PairingConsumed,
    PairingCancelled,
    PairingExpired,
    PairingUnauthorized,
}

#[derive(Serialize, Deserialize)]
struct UnsignedCard {
    signing_key: [u8; 32],
    encryption_key: [u8; 32],
    server: String,
    revision: u64,
    devices: Vec<DeviceRecord>,
}
#[derive(Serialize)]
struct UnsignedProfileCard {
    profile_version: u8,
    signing_key: [u8; 32],
    encryption_key: [u8; 32],
    server: String,
    revision: u64,
    devices: Vec<DeviceRecord>,
    display_name: String,
}
fn card_bytes(card: &ContactCard) -> Vec<u8> {
    if card.profile_version >= 1 {
        return bincode::serialize(&UnsignedProfileCard {
            profile_version: card.profile_version,
            signing_key: card.signing_key,
            encryption_key: card.encryption_key,
            server: card.server.clone(),
            revision: card.revision,
            devices: card.devices.clone(),
            display_name: card.display_name.clone(),
        })
        .expect("serializable profile card");
    }
    bincode::serialize(&UnsignedCard {
        signing_key: card.signing_key,
        encryption_key: card.encryption_key,
        server: card.server.clone(),
        revision: card.revision,
        devices: card.devices.clone(),
    })
    .expect("serializable card")
}
fn signature(bytes: &[u8]) -> Result<Signature> {
    Ok(Signature::from_bytes(bytes.try_into()?))
}
pub fn identity_id(card: &ContactCard) -> [u8; 32] {
    card.signing_key
}
fn device_bytes(device: &DeviceRecord) -> Vec<u8> {
    bincode::serialize(&(
        device.identity,
        device.device_id,
        device.device_key,
        &device.mls_key_package,
        device.authorization_revision,
    ))
    .expect("serializable device")
}
pub fn make_device(root: &SigningKey, device: &SigningKey, package: Vec<u8>) -> DeviceRecord {
    let mut id = [0; 32];
    id.copy_from_slice(&device.verifying_key().to_bytes());
    let mut record = DeviceRecord {
        identity: root.verifying_key().to_bytes(),
        device_id: id,
        device_key: device.verifying_key().to_bytes(),
        mls_key_package: package,
        authorization_revision: 1,
        signature: vec![0; 64],
    };
    record.signature = root.sign(&device_bytes(&record)).to_bytes().to_vec();
    record
}
pub fn verify_device(record: &DeviceRecord) -> Result<()> {
    if record.device_id != record.device_key {
        anyhow::bail!("device id must be its stable device public key")
    }
    VerifyingKey::from_bytes(&record.identity)?
        .verify(&device_bytes(record), &signature(&record.signature)?)
        .map_err(Into::into)
}
pub fn verify_device_set(set: &AuthorizedDeviceSet) -> Result<()> {
    for device in &set.devices {
        if device.identity != set.identity {
            anyhow::bail!("device belongs to another identity")
        }
        verify_device(device)?;
    }
    Ok(())
}
fn revocation_bytes(revocation: &DeviceRevocation) -> Vec<u8> {
    bincode::serialize(&(
        revocation.identity,
        revocation.device_id,
        revocation.revision,
    ))
    .expect("serializable revocation")
}
fn routing_bytes(route: &RoutingRecord) -> Vec<u8> {
    bincode::serialize(&(
        route.identity,
        route.version,
        &route.server,
        route.revision,
        route.parent_revision,
        route.relay_identity,
        route.tls_spki_fingerprint,
    ))
    .expect("serializable routing record")
}
fn forward_bytes(forward: &RelayForward) -> Vec<u8> {
    bincode::serialize(&(
        forward.version,
        &forward.route,
        &forward.record,
        forward.sender_relay,
    ))
    .expect("serializable relay forward")
}
pub fn make_relay_forward(
    relay: &SigningKey,
    route: RoutingRecord,
    record: MlsRecord,
) -> RelayForward {
    let mut forward = RelayForward {
        version: 1,
        route,
        record,
        sender_relay: relay.verifying_key().to_bytes(),
        signature: vec![0; 64],
    };
    forward.signature = relay.sign(&forward_bytes(&forward)).to_bytes().to_vec();
    forward
}
pub fn verify_relay_forward(forward: &RelayForward) -> Result<()> {
    if forward.version != 1 {
        anyhow::bail!("unsupported relay forwarding version")
    }
    VerifyingKey::from_bytes(&forward.sender_relay)?
        .verify(&forward_bytes(forward), &signature(&forward.signature)?)
        .map_err(Into::into)
}
pub fn make_routing(
    root: &SigningKey,
    server: String,
    relay_identity: [u8; 32],
    tls_spki_fingerprint: [u8; 32],
    revision: u64,
    parent_revision: u64,
) -> RoutingRecord {
    let mut route = RoutingRecord {
        version: 2,
        identity: root.verifying_key().to_bytes(),
        server,
        revision,
        parent_revision,
        relay_identity,
        tls_spki_fingerprint,
        signature: vec![0; 64],
    };
    route.signature = root.sign(&routing_bytes(&route)).to_bytes().to_vec();
    route
}
pub fn verify_routing(route: &RoutingRecord) -> Result<()> {
    if route.version != 2
        || route.relay_identity == [0; 32]
        || route.tls_spki_fingerprint == [0; 32]
        || route.revision == 0
        || route.parent_revision >= route.revision
    {
        anyhow::bail!("invalid routing revision ancestry")
    }
    VerifyingKey::from_bytes(&route.identity)?
        .verify(&routing_bytes(route), &signature(&route.signature)?)
        .map_err(Into::into)
}
/// Return the SHA-256 pin of exactly the TLS SubjectPublicKeyInfo presented by
/// a relay. Parsing is strict: malformed/non-X.509 input is never pinned.
pub fn tls_spki_fingerprint(certificate_der: &[u8]) -> Result<[u8; 32]> {
    let (remaining, certificate) = parse_x509_certificate(certificate_der)
        .map_err(|error| anyhow::anyhow!("invalid relay TLS certificate: {error}"))?;
    if !remaining.is_empty() {
        anyhow::bail!("trailing data after relay TLS certificate")
    }
    Ok(Sha256::digest(certificate.tbs_certificate.subject_pki.raw).into())
}
/// A deterministic tie-breaker for valid conflicting records with the same
/// parent/revision.  It avoids server authority while guaranteeing convergence.
pub fn routing_precedes(left: &RoutingRecord, right: &RoutingRecord) -> bool {
    bincode::serialize(left).expect("serializable route")
        < bincode::serialize(right).expect("serializable route")
}
pub fn make_revocation(root: &SigningKey, device_id: [u8; 32], revision: u64) -> DeviceRevocation {
    let mut revocation = DeviceRevocation {
        identity: root.verifying_key().to_bytes(),
        device_id,
        revision,
        signature: vec![0; 64],
    };
    revocation.signature = root
        .sign(&revocation_bytes(&revocation))
        .to_bytes()
        .to_vec();
    revocation
}
pub fn verify_revocation(revocation: &DeviceRevocation) -> Result<()> {
    VerifyingKey::from_bytes(&revocation.identity)?
        .verify(
            &revocation_bytes(revocation),
            &signature(&revocation.signature)?,
        )
        .map_err(Into::into)
}
pub fn make_card(
    signing: &SigningKey,
    encryption: &StaticSecret,
    server: String,
    device: DeviceRecord,
) -> ContactCard {
    make_card_named(signing, encryption, server, device, "Unnamed".into())
}
pub fn make_card_named(
    signing: &SigningKey,
    encryption: &StaticSecret,
    server: String,
    device: DeviceRecord,
    display_name: String,
) -> ContactCard {
    let mut card = ContactCard {
        profile_version: 1,
        signing_key: signing.verifying_key().to_bytes(),
        encryption_key: PublicKey::from(encryption).to_bytes(),
        server,
        revision: 1,
        devices: vec![device],
        display_name,
        signature: vec![0; 64],
    };
    card.signature = signing.sign(&card_bytes(&card)).to_bytes().to_vec();
    card
}
/// Produce a new root-signed contact card after an authorized roster change.
pub fn make_card_with_devices(
    signing: &SigningKey,
    encryption: &StaticSecret,
    server: String,
    devices: Vec<DeviceRecord>,
    revision: u64,
) -> ContactCard {
    make_card_with_devices_named(
        signing,
        encryption,
        server,
        devices,
        revision,
        "Unnamed".into(),
    )
}
pub fn make_card_with_devices_named(
    signing: &SigningKey,
    encryption: &StaticSecret,
    server: String,
    devices: Vec<DeviceRecord>,
    revision: u64,
    display_name: String,
) -> ContactCard {
    let mut card = ContactCard {
        profile_version: 1,
        signing_key: signing.verifying_key().to_bytes(),
        encryption_key: PublicKey::from(encryption).to_bytes(),
        server,
        revision,
        devices,
        display_name,
        signature: vec![0; 64],
    };
    card.signature = signing.sign(&card_bytes(&card)).to_bytes().to_vec();
    card
}
pub fn verify_card(card: &ContactCard) -> Result<()> {
    if card.profile_version > 1
        || (card.profile_version == 1
            && (card.display_name.trim().is_empty() || card.display_name.chars().count() > 64))
    {
        anyhow::bail!("invalid contact profile display name")
    }
    VerifyingKey::from_bytes(&card.signing_key)?
        .verify(&card_bytes(card), &signature(&card.signature)?)?;
    for device in &card.devices {
        if device.identity != card.signing_key {
            anyhow::bail!("contact card contains a device from another identity")
        }
        verify_device(device)?;
    }
    Ok(())
}
pub fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    Ok(bincode::serialize(value)?)
}
pub fn decode<T: for<'a> Deserialize<'a>>(data: &[u8]) -> Result<T> {
    Ok(bincode::deserialize(data)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ::tls_codec::Deserialize as _;
    use openmls::prelude::*;
    use openmls_basic_credential::SignatureKeyPair;
    use openmls_rust_crypto::OpenMlsRustCrypto;

    #[test]
    fn openmls_two_member_application_message() {
        let provider_a = OpenMlsRustCrypto::default();
        let provider_b = OpenMlsRustCrypto::default();
        let suite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
        let signer_a = SignatureKeyPair::new(suite.signature_algorithm()).unwrap();
        let signer_b = SignatureKeyPair::new(suite.signature_algorithm()).unwrap();
        let credential_a = CredentialWithKey {
            credential: BasicCredential::new(b"alice".to_vec()).into(),
            signature_key: signer_a.to_public_vec().into(),
        };
        let credential_b = CredentialWithKey {
            credential: BasicCredential::new(b"bob".to_vec()).into(),
            signature_key: signer_b.to_public_vec().into(),
        };
        let package_b = KeyPackage::builder()
            .build(suite, &provider_b, &signer_b, credential_b)
            .unwrap();
        let config = MlsGroupCreateConfig::builder()
            .ciphersuite(suite)
            .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
            .use_ratchet_tree_extension(true)
            .build();
        let mut alice = MlsGroup::new(&provider_a, &signer_a, &config, credential_a).unwrap();
        let (_, welcome, _) = alice
            .add_members(
                &provider_a,
                &signer_a,
                core::slice::from_ref(package_b.key_package()),
            )
            .unwrap();
        alice.merge_pending_commit(&provider_a).unwrap();
        let welcome = MlsMessageIn::tls_deserialize_exact(welcome.to_bytes().unwrap()).unwrap();
        let MlsMessageBodyIn::Welcome(welcome) = welcome.extract() else {
            panic!("expected welcome")
        };
        let mut bob =
            StagedWelcome::new_from_welcome(&provider_b, config.join_config(), welcome, None)
                .unwrap()
                .into_group(&provider_b)
                .unwrap();
        let wire = alice
            .create_message(&provider_a, &signer_a, b"MLS works")
            .unwrap()
            .to_bytes()
            .unwrap();
        let incoming = MlsMessageIn::tls_deserialize_exact(wire)
            .unwrap()
            .try_into_protocol_message()
            .unwrap();
        let processed = bob.process_message(&provider_b, incoming).unwrap();
        let ProcessedMessageContent::ApplicationMessage(message) = processed.into_content() else {
            panic!("expected application message")
        };
        assert_eq!(message.into_bytes(), b"MLS works");
    }

    #[test]
    fn root_authorizes_two_distinct_devices_across_restart_serialization() {
        let root = SigningKey::generate(&mut rand_core::OsRng);
        let phone = SigningKey::generate(&mut rand_core::OsRng);
        let laptop = SigningKey::generate(&mut rand_core::OsRng);
        let phone_record = make_device(&root, &phone, vec![1, 2, 3]);
        let laptop_record = make_device(&root, &laptop, vec![4, 5, 6]);
        assert_ne!(phone_record.device_id, laptop_record.device_id);
        assert_ne!(phone_record.device_key, laptop_record.device_key);
        let roster = AuthorizedDeviceSet {
            identity: root.verifying_key().to_bytes(),
            revision: 2,
            devices: vec![phone_record, laptop_record],
        };
        verify_device_set(&roster).unwrap();
        let restored: AuthorizedDeviceSet = decode(&encode(&roster).unwrap()).unwrap();
        verify_device_set(&restored).unwrap();
        assert_eq!(restored.devices.len(), 2);
        assert_eq!(restored.devices[0].mls_key_package, vec![1, 2, 3]);
        assert_eq!(restored.devices[1].mls_key_package, vec![4, 5, 6]);
    }

    #[test]
    fn mls_removal_excludes_revoked_device_from_future_messages() {
        let suite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
        let config = MlsGroupCreateConfig::builder()
            .ciphersuite(suite)
            .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
            .use_ratchet_tree_extension(true)
            .build();
        let provider_a1 = OpenMlsRustCrypto::default();
        let provider_a2 = OpenMlsRustCrypto::default();
        let provider_b1 = OpenMlsRustCrypto::default();
        let signer_a1 = SignatureKeyPair::new(suite.signature_algorithm()).unwrap();
        let signer_a2 = SignatureKeyPair::new(suite.signature_algorithm()).unwrap();
        let signer_b1 = SignatureKeyPair::new(suite.signature_algorithm()).unwrap();
        let credential = |name: &[u8], signer: &SignatureKeyPair| CredentialWithKey {
            credential: BasicCredential::new(name.to_vec()).into(),
            signature_key: signer.to_public_vec().into(),
        };
        let package_a2 = KeyPackage::builder()
            .build(
                suite,
                &provider_a2,
                &signer_a2,
                credential(b"alice-a2", &signer_a2),
            )
            .unwrap();
        let package_b1 = KeyPackage::builder()
            .build(
                suite,
                &provider_b1,
                &signer_b1,
                credential(b"bob-b1", &signer_b1),
            )
            .unwrap();
        let mut a1 = MlsGroup::new(
            &provider_a1,
            &signer_a1,
            &config,
            credential(b"alice-a1", &signer_a1),
        )
        .unwrap();
        let (_, welcome, _) = a1
            .add_members(
                &provider_a1,
                &signer_a1,
                &[
                    package_a2.key_package().clone(),
                    package_b1.key_package().clone(),
                ],
            )
            .unwrap();
        a1.merge_pending_commit(&provider_a1).unwrap();
        let join = |provider: &OpenMlsRustCrypto| {
            let welcome = MlsMessageIn::tls_deserialize_exact(welcome.to_bytes().unwrap()).unwrap();
            let MlsMessageBodyIn::Welcome(welcome) = welcome.extract() else {
                panic!("expected welcome")
            };
            StagedWelcome::new_from_welcome(provider, config.join_config(), welcome, None)
                .unwrap()
                .into_group(provider)
                .unwrap()
        };
        let mut a2 = join(&provider_a2);
        let mut b1 = join(&provider_b1);
        let a2_leaf = a1
            .members()
            .find(|member| member.credential == BasicCredential::new(b"alice-a2".to_vec()).into())
            .unwrap()
            .index;
        let (remove_commit, _, _) = a1
            .remove_members(&provider_a1, &signer_a1, &[a2_leaf])
            .unwrap();
        a1.merge_pending_commit(&provider_a1).unwrap();
        let commit = MlsMessageIn::tls_deserialize_exact(remove_commit.to_bytes().unwrap())
            .unwrap()
            .try_into_protocol_message()
            .unwrap();
        let ProcessedMessageContent::StagedCommitMessage(staged) = b1
            .process_message(&provider_b1, commit)
            .unwrap()
            .into_content()
        else {
            panic!("expected staged removal")
        };
        b1.merge_staged_commit(&provider_b1, *staged).unwrap();
        assert_eq!(a1.members().count(), 2);
        assert_eq!(b1.members().count(), 2);
        // Simulate both surviving clients restarting from their persisted MLS
        // provider storage before creating the post-revocation application data.
        let restart = |provider: &OpenMlsRustCrypto| {
            let restored = OpenMlsRustCrypto::default();
            let values = provider.storage().values.read().unwrap().clone();
            restored.storage().values.write().unwrap().extend(values);
            restored
        };
        let provider_a1_restarted = restart(&provider_a1);
        let provider_b1_restarted = restart(&provider_b1);
        let group_id = a1.group_id().clone();
        let mut a1 = MlsGroup::load(provider_a1_restarted.storage(), &group_id)
            .unwrap()
            .unwrap();
        let mut b1 = MlsGroup::load(provider_b1_restarted.storage(), &group_id)
            .unwrap()
            .unwrap();
        let post_revocation = b1
            .create_message(&provider_b1_restarted, &signer_b1, b"new epoch")
            .unwrap()
            .to_bytes()
            .unwrap();
        let message = MlsMessageIn::tls_deserialize_exact(post_revocation.clone())
            .unwrap()
            .try_into_protocol_message()
            .unwrap();
        let ProcessedMessageContent::ApplicationMessage(message) = a1
            .process_message(&provider_a1_restarted, message)
            .unwrap()
            .into_content()
        else {
            panic!("A1 should decrypt post-removal message")
        };
        assert_eq!(message.into_bytes(), b"new epoch");
        let old_state_message = MlsMessageIn::tls_deserialize_exact(post_revocation)
            .unwrap()
            .try_into_protocol_message()
            .unwrap();
        assert!(a2.process_message(&provider_a2, old_state_message).is_err());
    }

    #[test]
    fn pairing_approval_and_hpke_bootstrap_reject_all_bound_tampering() {
        use hpke::Kem as _;
        let root = SigningKey::generate(&mut rand_core::OsRng);
        let device = SigningKey::generate(&mut rand_core::OsRng);
        let record = make_device(&root, &device, vec![1, 2, 3]);
        let (sk, pk) = X25519HkdfSha256::gen_keypair();
        let request = PairingRequest {
            version: PAIRING_VERSION,
            identity: root.verifying_key().to_bytes(),
            session_id: [1; 16],
            nonce: [2; 16],
            expires_at: 100,
            device: record.clone(),
            hpke_public_key: pk.to_bytes().into(),
            bootstrap_capability_commitment: capability_commitment(&[3; 32]),
            cancel_capability_commitment: capability_commitment(&[4; 32]),
        };
        verify_pairing_request(&request, 99).unwrap();
        let payload = BootstrapPayload {
            version: PAIRING_VERSION,
            root_secret: root.to_bytes(),
            roster: AuthorizedDeviceSet {
                identity: request.identity,
                revision: 2,
                devices: vec![record.clone()],
            },
            routing: None,
            contacts: vec![],
            control_state: vec![9],
            mls_bootstrap: vec![vec![8]],
        };
        let encrypted = seal_bootstrap(&request, &payload).unwrap();
        let approval = make_pairing_approval(
            &root,
            &request,
            &payload.roster,
            Sha256::digest(pairing_bytes(&encrypted)).into(),
        )
        .unwrap();
        verify_pairing_approval(&request, &approval, 99).unwrap();
        assert_eq!(
            open_bootstrap(&request, sk.to_bytes().into(), &encrypted)
                .unwrap()
                .root_secret,
            root.to_bytes()
        );

        let mut forged = approval.clone();
        forged.signature[0] ^= 1;
        assert!(verify_pairing_approval(&request, &forged, 99).is_err());
        for altered in [
            PairingRequest {
                identity: [3; 32],
                ..request.clone()
            },
            PairingRequest {
                session_id: [3; 16],
                ..request.clone()
            },
            PairingRequest {
                nonce: [3; 16],
                ..request.clone()
            },
            PairingRequest {
                expires_at: 98,
                ..request.clone()
            },
        ] {
            assert!(verify_pairing_approval(&altered, &approval, 99).is_err());
        }
        let mut wrong_device = request.clone();
        wrong_device.device =
            make_device(&root, &SigningKey::generate(&mut rand_core::OsRng), vec![4]);
        assert!(verify_pairing_approval(&wrong_device, &approval, 99).is_err());
        let mut changed = approval.clone();
        changed.roster_revision += 1;
        assert!(verify_pairing_approval(&request, &changed, 99).is_err());
        let mut corrupt = encrypted.clone();
        corrupt.ciphertext[0] ^= 1;
        assert!(open_bootstrap(&request, sk.to_bytes().into(), &corrupt).is_err());
        let (wrong_sk, _) = X25519HkdfSha256::gen_keypair();
        assert!(open_bootstrap(&request, wrong_sk.to_bytes().into(), &encrypted).is_err());
        let mut bad_version = request.clone();
        bad_version.version = 2;
        assert!(verify_pairing_request(&bad_version, 99).is_err());
        let mut bad_payload = encrypted.clone();
        bad_payload.ciphertext = vec![0];
        assert!(open_bootstrap(&request, sk.to_bytes().into(), &bad_payload).is_err());
    }
}
