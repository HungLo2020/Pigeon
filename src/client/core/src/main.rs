use ::tls_codec::Deserialize as _;
use ::tls_codec::Serialize as _;
use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine};
use clap::{Parser, Subcommand};
use ed25519_dalek::SigningKey;
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use pigeon_shared::{
    decode, encode, identity_id, make_card, make_card_with_devices, make_device, make_revocation,
    make_routing, AuthorizedDeviceSet, ContactCard, DeviceRecord, DeviceRevocation,
    RelayDescriptor, Request, Response, RoutingRecord,
};
use rand_core::{OsRng, RngCore};
use rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, ServerName},
    ClientConfig, DigitallySignedStruct, Error as TlsError, RootCertStore, SignatureScheme,
};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, fs, sync::Arc};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use tokio_rustls::TlsConnector;
use x25519_dalek::StaticSecret;

mod history;
mod messaging;
mod routing;
mod storage;
use history::message_time;
use messaging::{unwrap_mls_payload, wrap_mls_payload};
use routing::should_replace_route;
use storage::{load, save};

type PersistedMlsIdentity = (Vec<u8>, Vec<u8>, HashMap<String, String>);

#[derive(Serialize, Deserialize)]
struct State {
    #[serde(default)]
    state_version: u8,
    signing_secret: [u8; 32],
    encryption_secret: [u8; 32],
    card: ContactCard,
    contacts: Vec<ContactCard>,
    /// Serialized OpenMLS provider storage and conversation metadata. This is
    /// account-local and is included in an identity export.
    mls_storage: HashMap<String, String>,
    mls_conversations: HashMap<String, Vec<u8>>,
    #[serde(default)]
    direct_groups: HashMap<String, String>,
    mls_signer: Vec<u8>,
    device: DeviceRecord,
    authorized_devices: AuthorizedDeviceSet,
    #[serde(default)]
    revocations: Vec<DeviceRevocation>,
    #[serde(default)]
    routing: Option<RoutingRecord>,
    #[serde(default)]
    pending_routing: Vec<RoutingRecord>,
    #[serde(default)]
    cached_routes: HashMap<String, RoutingRecord>,
    #[serde(default)]
    groups: HashMap<String, GroupState>,
    #[serde(default)]
    history: Vec<LocalMessage>,
    /// Per-device read cursors.  This belongs beside the device's MLS state,
    /// rather than in a frontend cache, so unread state survives restart and
    /// applies equally to CLI and GUI sync.
    #[serde(default)]
    read_at: HashMap<String, i64>,
}
#[derive(Clone, Serialize, Deserialize)]
struct LocalMessage {
    conversation: String,
    sender: String,
    text: String,
    timestamp: i64,
}
#[derive(Clone, Serialize, Deserialize)]
struct GroupState {
    group_id: Vec<u8>,
    members: Vec<[u8; 32]>,
}
#[derive(Parser)]
struct Args {
    #[arg(long, default_value = "pigeon-identity.json")]
    state: String,
    #[arg(long, default_value = "pigeon-server-cert.der")]
    certificate: String,
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand, Clone)]
enum Command {
    CreateLocal,
    Create {
        #[arg(long)]
        server: String,
    },
    ConfigureRelay {
        #[arg(long)]
        server: String,
    },
    Export {
        #[arg(long)]
        output: String,
    },
    Import {
        #[arg(long)]
        input: String,
    },
    Card,
    AddContact {
        card: String,
    },
    Send {
        #[arg(long)]
        to: String,
        text: String,
    },
    GroupCreate {
        #[arg(long)]
        group: String,
        #[arg(long, required = true)]
        members: Vec<String>,
    },
    GroupSend {
        #[arg(long)]
        group: String,
        text: String,
    },
    GroupAdd {
        #[arg(long)]
        group: String,
        #[arg(long)]
        member: String,
    },
    GroupRemove {
        #[arg(long)]
        group: String,
        #[arg(long)]
        member: String,
    },
    MarkRead {
        #[arg(long)]
        conversation: String,
    },
    Fetch,
    RevokeDevice {
        /// Hex-encoded stable device ID from the account's authorized roster.
        device_id: String,
    },
    Migrate {
        #[arg(long)]
        server: String,
        /// Certificate for the previous relay, used only to publish the
        /// already-signed MOVED route before switching local state.
        #[arg(long)]
        previous_certificate: Option<String>,
    },
}

fn create_mls_identity(device_id: &[u8]) -> Result<PersistedMlsIdentity> {
    let provider = OpenMlsRustCrypto::default();
    let suite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    let signer = SignatureKeyPair::new(suite.signature_algorithm())?;
    let credential = CredentialWithKey {
        credential: BasicCredential::new(device_id.to_vec()).into(),
        signature_key: signer.to_public_vec().into(),
    };
    let package = KeyPackage::builder().build(suite, &provider, &signer, credential)?;
    let storage = provider
        .storage()
        .values
        .read()
        .map_err(|_| anyhow::anyhow!("MLS storage lock poisoned"))?
        .iter()
        .map(|(key, value)| (STANDARD_NO_PAD.encode(key), STANDARD_NO_PAD.encode(value)))
        .collect();
    Ok((
        package.key_package().tls_serialize_detached()?,
        serde_json::to_vec(&signer)?,
        storage,
    ))
}
fn mls_runtime(state: &State) -> Result<(OpenMlsRustCrypto, SignatureKeyPair)> {
    let provider = OpenMlsRustCrypto::default();
    {
        let mut values = provider
            .storage()
            .values
            .write()
            .map_err(|_| anyhow::anyhow!("MLS storage lock poisoned"))?;
        for (key, value) in &state.mls_storage {
            values.insert(STANDARD_NO_PAD.decode(key)?, STANDARD_NO_PAD.decode(value)?);
        }
    }
    Ok((provider, serde_json::from_slice(&state.mls_signer)?))
}
fn persist_mls(state: &mut State, provider: &OpenMlsRustCrypto) -> Result<()> {
    state.mls_storage = provider
        .storage()
        .values
        .read()
        .map_err(|_| anyhow::anyhow!("MLS storage lock poisoned"))?
        .iter()
        .map(|(key, value)| (STANDARD_NO_PAD.encode(key), STANDARD_NO_PAD.encode(value)))
        .collect();
    Ok(())
}
async fn read_frame<S: AsyncReadExt + Unpin>(stream: &mut S) -> Result<Vec<u8>> {
    let length = stream.read_u32().await? as usize;
    if length > 16 * 1024 * 1024 {
        bail!("frame too large")
    };
    let mut bytes = vec![0; length];
    stream.read_exact(&mut bytes).await?;
    Ok(bytes)
}
async fn write_frame<S: AsyncWriteExt + Unpin>(stream: &mut S, bytes: &[u8]) -> Result<()> {
    stream.write_u32(bytes.len() as u32).await?;
    stream.write_all(bytes).await?;
    stream.flush().await?;
    Ok(())
}
async fn request(server: &str, certificate: &str, value: Request) -> Result<Response> {
    let certificate = CertificateDer::from(fs::read(certificate)?);
    let mut roots = RootCertStore::empty();
    roots.add(certificate)?;
    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(config));
    let stream = TcpStream::connect(server).await?;
    let name = ServerName::try_from("localhost")?.to_owned();
    let mut tls = connector.connect(name, stream).await?;
    write_frame(&mut tls, &encode(&value)?).await?;
    decode(&read_frame(&mut tls).await?)
}
#[derive(Debug)]
struct SpkiVerifier([u8; 32]);
impl ServerCertVerifier for SpkiVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: rustls::pki_types::UnixTime,
    ) -> std::result::Result<ServerCertVerified, TlsError> {
        match pigeon_shared::tls_spki_fingerprint(end_entity.as_ref()) {
            Ok(pin) if pin == self.0 => Ok(ServerCertVerified::assertion()),
            Ok(_) => Err(TlsError::General(
                "signed relay TLS SPKI pin mismatch".into(),
            )),
            Err(error) => Err(TlsError::General(format!(
                "invalid relay TLS certificate: {error}"
            ))),
        }
    }
    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::ED25519,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::RSA_PSS_SHA256,
        ]
    }
}
async fn pinned_request(route: &RoutingRecord, value: Request) -> Result<Response> {
    pigeon_shared::verify_routing(route)?;
    let config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SpkiVerifier(route.tls_spki_fingerprint)))
        .with_no_client_auth();
    let stream = TcpStream::connect(&route.server).await?;
    let mut tls = TlsConnector::from(Arc::new(config))
        .connect(ServerName::try_from("localhost")?.to_owned(), stream)
        .await?;
    write_frame(&mut tls, &encode(&value)?).await?;
    decode(&read_frame(&mut tls).await?)
}
fn card_text(card: &ContactCard) -> Result<String> {
    Ok(STANDARD_NO_PAD.encode(serde_json::to_vec(card)?))
}
fn parse_card(value: &str) -> Result<ContactCard> {
    let card: ContactCard = serde_json::from_slice(&STANDARD_NO_PAD.decode(value.trim())?)?;
    pigeon_shared::verify_card(&card)?;
    Ok(card)
}
fn response_ok(response: Response) -> Result<()> {
    match response {
        Response::Ok => Ok(()),
        Response::Error(error) => bail!("server rejected request: {error}"),
        _ => bail!("unexpected server response"),
    }
}
async fn relay_descriptor(server: &str, certificate: &str) -> Result<RelayDescriptor> {
    let Response::RelayDescriptor(descriptor) =
        request(server, certificate, Request::GetRelayDescriptor).await?
    else {
        bail!("relay did not provide an identity and TLS SPKI pin")
    };
    Ok(descriptor)
}
async fn pinned_relay_descriptor(route: &RoutingRecord) -> Result<RelayDescriptor> {
    let Response::RelayDescriptor(descriptor) =
        pinned_request(route, Request::GetRelayDescriptor).await?
    else {
        bail!("relay did not provide an identity and TLS SPKI pin")
    };
    Ok(descriptor)
}
fn validate_route_descriptor(route: &RoutingRecord, descriptor: &RelayDescriptor) -> Result<()> {
    pigeon_shared::verify_routing(route)?;
    if route.relay_identity != descriptor.identity
        || route.tls_spki_fingerprint != descriptor.tls_spki_fingerprint
    {
        bail!("routing record relay identity/TLS SPKI fingerprint mismatch")
    }
    Ok(())
}
fn delivery_request(
    state: &State,
    recipient: &ContactCard,
    record: pigeon_shared::MlsRecord,
) -> Result<Request> {
    let identity = identity_id(recipient);
    if recipient.server == state.card.server {
        return Ok(Request::SendMls(record));
    }
    let route = state
        .cached_routes
        .get(&hex::encode(identity))
        .context("cross-server contact has no verified relay-bound route")?
        .clone();
    pigeon_shared::verify_routing(&route)?;
    if route.identity != identity || route.server == state.card.server {
        bail!("invalid cross-server contact route")
    }
    Ok(Request::QueueForward { record, route })
}
fn parse_identity(value: &str) -> Result<[u8; 32]> {
    hex::decode(value)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("identity must be 32 bytes of hexadecimal"))
}
fn contact_for(state: &State, identity: [u8; 32]) -> Result<ContactCard> {
    state
        .contacts
        .iter()
        .find(|contact| identity_id(contact) == identity)
        .cloned()
        .context("group member is not a verified contact")
}
fn identities_in_mls_group(state: &State, group: &MlsGroup) -> Vec<[u8; 32]> {
    let mut identities = vec![identity_id(&state.card)];
    for contact in &state.contacts {
        if contact.devices.iter().any(|device| {
            group.members().any(|leaf| {
                leaf.credential == BasicCredential::new(device.device_id.to_vec()).into()
            })
        }) {
            identities.push(identity_id(contact));
        }
    }
    identities.sort();
    identities.dedup();
    identities
}
async fn deliver_group_payload(
    state: &State,
    certificate: &str,
    members: &[[u8; 32]],
    payload: Vec<u8>,
) -> Result<()> {
    let payload = wrap_mls_payload(state, payload)?;
    for identity in members {
        if *identity == identity_id(&state.card) {
            continue;
        }
        let contact = contact_for(state, *identity)?;
        response_ok(
            request(
                &state.card.server,
                certificate,
                delivery_request(
                    state,
                    &contact,
                    pigeon_shared::MlsRecord {
                        recipient_identity: *identity,
                        sender_device: state.device.device_id,
                        target_devices: contact
                            .devices
                            .iter()
                            .map(|device| device.device_id)
                            .collect(),
                        payload: payload.clone(),
                    },
                )?,
            )
            .await?,
        )?;
    }
    Ok(())
}
mod commands;

#[tokio::main]
async fn main() -> Result<()> {
    commands::dispatch(Args::parse()).await
}
