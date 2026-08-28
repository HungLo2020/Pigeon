use anyhow::Result;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey, StaticSecret};

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct ContactCard {
    pub signing_key: [u8; 32],
    pub encryption_key: [u8; 32],
    pub server: String,
    pub revision: u64,
    pub mls_key_package: Vec<u8>,
    pub signature: Vec<u8>,
}
/// Opaque MLS wire data. The relay validates routing metadata only; it never
/// parses MLS payloads or holds MLS private state.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct MlsRecord {
    pub recipient: [u8; 32],
    pub sender: [u8; 32],
    pub payload: Vec<u8>,
}
#[derive(Serialize, Deserialize, Debug)]
pub enum Request {
    Register(ContactCard),
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
    },
}
#[derive(Serialize, Deserialize, Debug)]
pub enum Response {
    Ok,
    KeyPackage(Option<Vec<u8>>),
    MlsMessages(Vec<MlsRecord>),
    Error(String),
}

#[derive(Serialize, Deserialize)]
struct UnsignedCard {
    signing_key: [u8; 32],
    encryption_key: [u8; 32],
    server: String,
    revision: u64,
    mls_key_package: Vec<u8>,
}
fn card_bytes(card: &ContactCard) -> Vec<u8> {
    bincode::serialize(&UnsignedCard {
        signing_key: card.signing_key,
        encryption_key: card.encryption_key,
        server: card.server.clone(),
        revision: card.revision,
        mls_key_package: card.mls_key_package.clone(),
    })
    .expect("serializable card")
}
fn signature(bytes: &[u8]) -> Result<Signature> {
    Ok(Signature::from_bytes(bytes.try_into()?))
}
pub fn identity_id(card: &ContactCard) -> [u8; 32] {
    card.signing_key
}
pub fn make_card(
    signing: &SigningKey,
    encryption: &StaticSecret,
    server: String,
    mls_key_package: Vec<u8>,
) -> ContactCard {
    let mut card = ContactCard {
        signing_key: signing.verifying_key().to_bytes(),
        encryption_key: PublicKey::from(encryption).to_bytes(),
        server,
        revision: 1,
        mls_key_package,
        signature: vec![0; 64],
    };
    card.signature = signing.sign(&card_bytes(&card)).to_bytes().to_vec();
    card
}
pub fn verify_card(card: &ContactCard) -> Result<()> {
    VerifyingKey::from_bytes(&card.signing_key)?
        .verify(&card_bytes(card), &signature(&card.signature)?)
        .map_err(Into::into)
}
pub fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    Ok(bincode::serialize(value)?)
}
pub fn decode<T: for<'a> Deserialize<'a>>(data: &[u8]) -> Result<T> {
    Ok(bincode::deserialize(data)?)
}

#[cfg(test)]
mod tests {
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
}
