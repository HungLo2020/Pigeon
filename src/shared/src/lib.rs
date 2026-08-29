use anyhow::Result;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
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
    pub signing_key: [u8; 32],
    pub encryption_key: [u8; 32],
    pub server: String,
    pub revision: u64,
    pub devices: Vec<DeviceRecord>,
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
}

#[derive(Serialize, Deserialize)]
struct UnsignedCard {
    signing_key: [u8; 32],
    encryption_key: [u8; 32],
    server: String,
    revision: u64,
    devices: Vec<DeviceRecord>,
}
fn card_bytes(card: &ContactCard) -> Vec<u8> {
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
    let mut card = ContactCard {
        signing_key: signing.verifying_key().to_bytes(),
        encryption_key: PublicKey::from(encryption).to_bytes(),
        server,
        revision: 1,
        devices: vec![device],
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
    let mut card = ContactCard {
        signing_key: signing.verifying_key().to_bytes(),
        encryption_key: PublicKey::from(encryption).to_bytes(),
        server,
        revision,
        devices,
        signature: vec![0; 64],
    };
    card.signature = signing.sign(&card_bytes(&card)).to_bytes().to_vec();
    card
}
pub fn verify_card(card: &ContactCard) -> Result<()> {
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
}
