use ::tls_codec::Deserialize as _;
use ::tls_codec::Serialize as _;
use anyhow::{bail, Context, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305, XNonce,
};
use clap::{Parser, Subcommand};
use ed25519_dalek::SigningKey;
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use pigeon_shared::{
    account_id, account_identity, capability_commitment, decode, encode, identity_id,
    make_authorized_device_set, make_card_from_roster, make_device, make_pairing_approval,
    make_revocation, make_routing, open_bootstrap, roster_hash, seal_bootstrap, verify_device_set,
    verify_pairing_approval, verify_pairing_request, verify_roster_transition,
    AccountTransitionKind, AttachmentDescriptor, AuthorizedDeviceSet, BootstrapPayload,
    ContactCard, DeviceRecord, DeviceRevocation, EncryptedBootstrap, PairingApproval,
    PairingArtifactKind, PairingRelayArtifact, PairingRequest, PigeonAccountGenesis,
    RelayDescriptor, Request, Response, RoutingRecord,
};
use rand_core::{OsRng, RngCore};
use rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, ServerName},
    ClientConfig, DigitallySignedStruct, Error as TlsError, RootCertStore, SignatureScheme,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::HashMap, fs, sync::Arc};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use tokio_rustls::TlsConnector;
use url::Url;
use x25519_dalek::{PublicKey, StaticSecret};

mod history;
mod messaging;
mod routing;
mod storage;
use history::message_time;
use messaging::{
    decode_application, encode_application, unwrap_mls_payload, wrap_mls_payload,
    ApplicationContent,
};
use routing::should_replace_route;
use storage::{load, save};

type PersistedMlsIdentity = (Vec<u8>, Vec<u8>, HashMap<String, String>);

#[derive(Serialize, Deserialize)]
struct State {
    #[serde(default)]
    state_version: u8,
    signing_secret: [u8; 32],
    /// The current endpoint's distinct private device credential. It is never
    /// exported or copied through pairing/backup.
    device_secret: [u8; 32],
    recovery_wrap: PasswordWrappedRecovery,
    encryption_secret: [u8; 32],
    card: ContactCard,
    contacts: Vec<ContactCard>,
    #[serde(default)]
    nicknames: HashMap<String, String>,
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
    /// Metadata and private cache paths only. Portable account backups
    /// intentionally exclude this collection and never carry decrypted bytes.
    #[serde(default)]
    attachments: HashMap<String, LocalAttachment>,
}
const ACCOUNT_STATE_VERSION: u8 = 3;
const RECOVERY_WRAP_VERSION: u8 = 1;
#[derive(Clone, Serialize, Deserialize)]
struct PasswordWrappedRecovery {
    version: u8,
    salt: [u8; 16],
    nonce: [u8; 24],
    ciphertext: Vec<u8>,
}
const PORTABLE_BACKUP_VERSION: u8 = 2;
#[derive(Serialize, Deserialize)]
struct EncryptedPortableBackup {
    version: u8,
    salt: [u8; 16],
    nonce: [u8; 24],
    ciphertext: Vec<u8>,
}
#[derive(Serialize, Deserialize)]
struct PortableBackupPayload {
    version: u8,
    genesis: PigeonAccountGenesis,
    root_secret: [u8; 32],
    recovery_secret: [u8; 32],
    encryption_secret: [u8; 32],
    card: ContactCard,
    authorized_devices: AuthorizedDeviceSet,
    revocations: Vec<DeviceRevocation>,
    routing: Option<RoutingRecord>,
    pending_routing: Vec<RoutingRecord>,
    cached_routes: HashMap<String, RoutingRecord>,
    contacts: Vec<ContactCard>,
    nicknames: HashMap<String, String>,
    groups: HashMap<String, GroupState>,
}
fn backup_aad() -> &'static [u8] {
    b"pigeon-portable-account-backup-v1"
}
fn encrypt_backup(
    password: &str,
    payload: &PortableBackupPayload,
) -> Result<EncryptedPortableBackup> {
    let mut salt = [0; 16];
    let mut nonce = [0; 24];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce);
    let cipher = XChaCha20Poly1305::new((&password_key(password, &salt)?).into());
    Ok(EncryptedPortableBackup {
        version: PORTABLE_BACKUP_VERSION,
        salt,
        nonce,
        ciphertext: cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                chacha20poly1305::aead::Payload {
                    msg: &encode(payload)?,
                    aad: backup_aad(),
                },
            )
            .map_err(|_| anyhow::anyhow!("could not encrypt portable backup"))?,
    })
}
fn decrypt_backup(
    password: &str,
    backup: &EncryptedPortableBackup,
) -> Result<PortableBackupPayload> {
    if backup.version != PORTABLE_BACKUP_VERSION {
        bail!("unsupported portable backup format")
    }
    let cipher = XChaCha20Poly1305::new((&password_key(password, &backup.salt)?).into());
    let plaintext = cipher
        .decrypt(
            XNonce::from_slice(&backup.nonce),
            chacha20poly1305::aead::Payload {
                msg: &backup.ciphertext,
                aad: backup_aad(),
            },
        )
        .map_err(|_| anyhow::anyhow!("incorrect backup password or corrupt encrypted backup"))?;
    let payload: PortableBackupPayload = decode(&plaintext)?;
    if payload.version != PORTABLE_BACKUP_VERSION
        || account_id(&payload.genesis)? != identity_id(&payload.card)
        || payload.authorized_devices.genesis != payload.genesis
    {
        bail!("portable backup account state is malformed")
    }
    Ok(payload)
}
#[derive(Clone, Serialize, Deserialize)]
struct LocalMessage {
    conversation: String,
    sender: String,
    text: String,
    timestamp: i64,
    #[serde(default)]
    attachment: Option<AttachmentDescriptor>,
}

#[derive(Clone, Serialize, Deserialize)]
struct LocalAttachment {
    descriptor: AttachmentDescriptor,
    filename: String,
    mime_type: String,
    local_path: String,
    complete: bool,
}
#[derive(Clone, Serialize, Deserialize)]
struct GroupState {
    group_id: Vec<u8>,
    members: Vec<pigeon_shared::AccountIdentity>,
}
#[derive(Serialize, Deserialize)]
struct PendingPairing {
    request: PairingRequest,
    device_secret: [u8; 32],
    mls_signer: Vec<u8>,
    mls_storage: HashMap<String, String>,
    hpke_secret: [u8; 32],
    bootstrap_capability: [u8; 32],
    cancel_capability: [u8; 32],
    server: String,
    #[serde(default)]
    cancelled: bool,
}
#[derive(Serialize, Deserialize)]
struct BootstrapControl {
    encryption_secret: [u8; 32],
    card: ContactCard,
    recovery_wrap: PasswordWrappedRecovery,
}
fn password_key(password: &str, salt: &[u8; 16]) -> Result<[u8; 32]> {
    if password.chars().count() < 12 {
        bail!("account password must contain at least 12 characters")
    }
    let params = Params::new(19 * 1024, 2, 1, Some(32))
        .map_err(|error| anyhow::anyhow!("invalid Argon2id parameters: {error}"))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut output = [0; 32];
    argon
        .hash_password_into(password.as_bytes(), salt, &mut output)
        .map_err(|error| anyhow::anyhow!("Argon2id password derivation failed: {error}"))?;
    Ok(output)
}
fn wrap_recovery(password: &str, recovery_secret: [u8; 32]) -> Result<PasswordWrappedRecovery> {
    let mut salt = [0; 16];
    let mut nonce = [0; 24];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce);
    let cipher = XChaCha20Poly1305::new((&password_key(password, &salt)?).into());
    Ok(PasswordWrappedRecovery {
        version: RECOVERY_WRAP_VERSION,
        salt,
        nonce,
        ciphertext: cipher
            .encrypt(XNonce::from_slice(&nonce), recovery_secret.as_slice())
            .map_err(|_| anyhow::anyhow!("could not encrypt recovery material"))?,
    })
}
fn unwrap_recovery(password: &str, wrapped: &PasswordWrappedRecovery) -> Result<[u8; 32]> {
    if wrapped.version != RECOVERY_WRAP_VERSION {
        bail!("unsupported password-wrapped recovery format")
    }
    let cipher = XChaCha20Poly1305::new((&password_key(password, &wrapped.salt)?).into());
    let plaintext = cipher
        .decrypt(
            XNonce::from_slice(&wrapped.nonce),
            wrapped.ciphertext.as_ref(),
        )
        .map_err(|_| anyhow::anyhow!("incorrect account password or corrupt recovery material"))?;
    plaintext
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid recovery secret length"))
}
#[derive(Serialize)]
struct DiscoveredRelay {
    descriptor: RelayDescriptor,
    /// Direct host:port endpoints use explicit TOFU confirmation. HTTPS
    /// discovery documents authenticated by the platform trust store do not.
    requires_confirmation: bool,
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
    CreateLocal {
        #[arg(long)]
        display_name: String,
        #[arg(long)]
        password: String,
    },
    Create {
        #[arg(long)]
        server: String,
        #[arg(long)]
        display_name: String,
        #[arg(long)]
        password: String,
    },
    ConfigureRelay {
        #[arg(long)]
        server: String,
        /// Base64url JSON RelayDescriptor previously returned by
        /// `discover-relay`. Supplying it makes setup pin-only and avoids any
        /// certificate file dependency.
        #[arg(long)]
        descriptor: Option<String>,
    },
    DiscoverRelay {
        /// host:port (explicit TOFU), hostname (HTTPS well-known), or an
        /// explicit HTTPS discovery URL.
        #[arg(long)]
        input: String,
    },
    Export {
        #[arg(long)]
        output: String,
        #[arg(long)]
        password: String,
    },
    Import {
        #[arg(long)]
        input: String,
        #[arg(long)]
        password: String,
    },
    Card,
    SetDisplayName {
        #[arg(long)]
        display_name: String,
    },
    ChangePassword {
        #[arg(long)]
        old_password: String,
        #[arg(long)]
        new_password: String,
    },
    SetNickname {
        #[arg(long)]
        identity: String,
        #[arg(long)]
        nickname: Option<String>,
    },
    AddContact {
        card: String,
    },
    Send {
        #[arg(long)]
        to: String,
        text: String,
    },
    /// Encrypt and send a file through the current MLS conversation.
    SendAttachment {
        #[arg(long)]
        to: String,
        #[arg(long)]
        file: String,
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
    GroupAttachment {
        #[arg(long)]
        group: String,
        #[arg(long)]
        file: String,
    },
    /// Explicitly copy a verified attachment to a user-selected local path.
    SaveAttachment {
        #[arg(long)]
        attachment_id: String,
        #[arg(long)]
        output: String,
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
        #[arg(long)]
        password: String,
    },
    PairRequest {
        #[arg(long)]
        identity: String,
        /// Base64url canonical PigeonAccountGenesis for the target account.
        /// A compact identity hash alone is never enough to select an account.
        #[arg(long)]
        genesis: String,
        #[arg(long)]
        server: String,
    },
    PairApprove {
        /// Base64url pairing request emitted by `pair-request`.
        request: String,
        #[arg(long)]
        password: String,
    },
    PairConsume,
    PairCancel,
    Migrate {
        #[arg(long)]
        server: String,
        /// Confirmed discovery descriptor. When present, all destination
        /// traffic is pinned without reading an operator certificate file.
        #[arg(long)]
        descriptor: Option<String>,
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
/// Used only to read a public descriptor from an explicit `host:port` first
/// contact. Its result is displayed and requires user confirmation; it is
/// never persisted or used for normal protocol traffic until the subsequent
/// pinned connection proves the displayed SPKI again.
#[derive(Debug)]
struct DiscoveryVerifier;
impl ServerCertVerifier for DiscoveryVerifier {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: rustls::pki_types::UnixTime,
    ) -> std::result::Result<ServerCertVerified, TlsError> {
        Ok(ServerCertVerified::assertion())
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
        SpkiVerifier([0; 32]).supported_verify_schemes()
    }
}
async fn pinned_request(route: &RoutingRecord, value: Request) -> Result<Response> {
    pigeon_shared::verify_routing(route)?;
    spki_request(&route.server, route.tls_spki_fingerprint, value).await
}

async fn spki_request(server: &str, pin: [u8; 32], value: Request) -> Result<Response> {
    let config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SpkiVerifier(pin)))
        .with_no_client_auth();
    let stream = TcpStream::connect(server).await?;
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
    pigeon_shared::verify_relay_descriptor(&descriptor)?;
    Ok(descriptor)
}
async fn pinned_relay_descriptor(route: &RoutingRecord) -> Result<RelayDescriptor> {
    let Response::RelayDescriptor(descriptor) =
        pinned_request(route, Request::GetRelayDescriptor).await?
    else {
        bail!("relay did not provide an identity and TLS SPKI pin")
    };
    pigeon_shared::verify_relay_descriptor(&descriptor)?;
    Ok(descriptor)
}
fn validate_route_descriptor(route: &RoutingRecord, descriptor: &RelayDescriptor) -> Result<()> {
    pigeon_shared::verify_routing(route)?;
    pigeon_shared::verify_relay_descriptor(descriptor)?;
    if route.relay_identity != descriptor.identity
        || route.tls_spki_fingerprint != descriptor.tls_spki_fingerprint
        || route.server != descriptor.address
    {
        bail!("routing record relay address/identity/TLS SPKI fingerprint mismatch")
    }
    Ok(())
}

fn descriptor_text(descriptor: &RelayDescriptor) -> Result<String> {
    pigeon_shared::verify_relay_descriptor(descriptor)?;
    Ok(STANDARD_NO_PAD.encode(serde_json::to_vec(descriptor)?))
}

fn parse_descriptor_text(value: &str) -> Result<RelayDescriptor> {
    let descriptor: RelayDescriptor =
        serde_json::from_slice(&STANDARD_NO_PAD.decode(value.trim())?)?;
    pigeon_shared::verify_relay_descriptor(&descriptor)?;
    Ok(descriptor)
}

fn direct_endpoint(value: &str) -> Result<Option<String>> {
    let value = value.trim();
    if value.is_empty() || value.contains(['/', '@', '?', '#']) {
        return Ok(None);
    }
    let Some((host, port)) = value.rsplit_once(':') else {
        return Ok(None);
    };
    if host.trim().is_empty() || port.parse::<u16>().ok().filter(|port| *port != 0).is_none() {
        bail!("relay endpoint must be host:port with a port from 1 to 65535")
    }
    Ok(Some(value.to_owned()))
}

async fn direct_relay_descriptor(server: &str) -> Result<RelayDescriptor> {
    let config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(DiscoveryVerifier))
        .with_no_client_auth();
    let stream = TcpStream::connect(server).await?;
    let mut tls = TlsConnector::from(Arc::new(config))
        .connect(ServerName::try_from("localhost")?.to_owned(), stream)
        .await?;
    write_frame(&mut tls, &encode(&Request::GetRelayDescriptor)?).await?;
    let Response::RelayDescriptor(descriptor) = decode(&read_frame(&mut tls).await?)? else {
        bail!("relay did not provide a discovery descriptor")
    };
    pigeon_shared::verify_relay_descriptor(&descriptor)?;
    Ok(descriptor)
}

async fn https_relay_descriptor(input: &str) -> Result<RelayDescriptor> {
    let url = if input.starts_with("https://") {
        Url::parse(input)?
    } else {
        Url::parse(&format!("https://{input}/.well-known/pigeon-relay"))?
    };
    if url.scheme() != "https"
        || url.host_str().is_none()
        || url.username() != ""
        || url.password().is_some()
    {
        bail!("relay discovery URL must be an absolute HTTPS URL without credentials")
    }
    let host = url.host_str().expect("checked host");
    let port = url
        .port_or_known_default()
        .context("HTTPS URL has no port")?;
    let socket = if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let stream = TcpStream::connect(socket).await?;
    let name = ServerName::try_from(host.to_owned())?.to_owned();
    let mut tls = TlsConnector::from(Arc::new(config))
        .connect(name, stream)
        .await?;
    let mut path = url.path().to_owned();
    if path.is_empty() {
        path = "/".into();
    }
    if let Some(query) = url.query() {
        path.push('?');
        path.push_str(query);
    }
    let request = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nAccept: application/json\r\nConnection: close\r\n\r\n");
    tls.write_all(request.as_bytes()).await?;
    tls.flush().await?;
    let mut response = Vec::new();
    tls.read_to_end(&mut response).await?;
    parse_https_discovery_response(&response)
}

fn parse_https_discovery_response(response: &[u8]) -> Result<RelayDescriptor> {
    let Some(separator) = response.windows(4).position(|value| value == b"\r\n\r\n") else {
        bail!("malformed HTTPS relay discovery response")
    };
    let header = std::str::from_utf8(&response[..separator])?;
    if !header.starts_with("HTTP/1.1 200 ") && !header.starts_with("HTTP/1.0 200 ") {
        bail!(
            "HTTPS relay discovery returned {}",
            header.lines().next().unwrap_or("an invalid status")
        )
    }
    let descriptor: RelayDescriptor = serde_json::from_slice(&response[separator + 4..])?;
    pigeon_shared::verify_relay_descriptor(&descriptor)?;
    Ok(descriptor)
}

async fn discover_relay(input: &str) -> Result<DiscoveredRelay> {
    if let Some(endpoint) = direct_endpoint(input)? {
        let descriptor = direct_relay_descriptor(&endpoint).await?;
        validate_direct_descriptor(&endpoint, &descriptor)?;
        return Ok(DiscoveredRelay {
            descriptor,
            requires_confirmation: true,
        });
    }
    Ok(DiscoveredRelay {
        descriptor: https_relay_descriptor(input.trim()).await?,
        requires_confirmation: false,
    })
}

fn validate_direct_descriptor(endpoint: &str, descriptor: &RelayDescriptor) -> Result<()> {
    pigeon_shared::verify_relay_descriptor(descriptor)?;
    if descriptor.address != endpoint {
        bail!("direct relay descriptor address does not match the entered endpoint")
    }
    Ok(())
}

async fn verify_descriptor_endpoint(descriptor: &RelayDescriptor) -> Result<()> {
    pigeon_shared::verify_relay_descriptor(descriptor)?;
    let Response::RelayDescriptor(observed) = spki_request(
        &descriptor.address,
        descriptor.tls_spki_fingerprint,
        Request::GetRelayDescriptor,
    )
    .await?
    else {
        bail!("relay did not provide a descriptor after pinned connection")
    };
    pigeon_shared::verify_relay_descriptor(&observed)?;
    if &observed != descriptor {
        bail!("pinned relay descriptor differs from the confirmed discovery descriptor")
    }
    Ok(())
}

async fn configuration_descriptor(
    server: &str,
    encoded: Option<&str>,
    certificate: &str,
) -> Result<RelayDescriptor> {
    match encoded {
        Some(encoded) => {
            let descriptor = parse_descriptor_text(encoded)?;
            verify_descriptor_endpoint(&descriptor).await?;
            Ok(descriptor)
        }
        None => relay_descriptor(server, certificate).await,
    }
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
        .get(&contact_key(recipient)?)
        .context("cross-server contact has no verified relay-bound route")?
        .clone();
    pigeon_shared::verify_routing(&route)?;
    if route.identity != identity
        || route.genesis != recipient.genesis
        || route.server == state.card.server
    {
        bail!("invalid cross-server contact route")
    }
    Ok(Request::QueueForward { record, route })
}
fn attachment_delivery_request(
    state: &State,
    recipient: &ContactCard,
    record: pigeon_shared::AttachmentRecord,
) -> Result<Request> {
    if recipient.server == state.card.server {
        return Ok(Request::SendAttachment(record));
    }
    let route = state
        .cached_routes
        .get(&contact_key(recipient)?)
        .context("cross-server contact has no verified relay-bound route")?
        .clone();
    pigeon_shared::verify_routing(&route)?;
    if route.identity != identity_id(recipient)
        || route.genesis != recipient.genesis
        || route.server == state.card.server
    {
        bail!("invalid cross-server attachment route")
    }
    Ok(Request::QueueForwardAttachment { record, route })
}

async fn upload_attachment_to_contact(
    state: &State,
    certificate: &str,
    contact: &ContactCard,
    encrypted: &pigeon_shared::EncryptedAttachment,
) -> Result<()> {
    let request_value = attachment_delivery_request(
        state,
        contact,
        pigeon_shared::AttachmentRecord {
            version: pigeon_shared::ATTACHMENT_VERSION,
            recipient: account_identity(contact.genesis.clone())?,
            sender: account_identity(state.card.genesis.clone())?,
            sender_device: state.device.device_id,
            target_devices: contact
                .devices
                .iter()
                .map(|device| device.device_id)
                .collect(),
            attachment_id: encrypted.descriptor.attachment_id,
            conversation_id: encrypted.descriptor.conversation_id.clone(),
            plaintext_size: encrypted.descriptor.plaintext_size,
            ciphertext_hash: encrypted.descriptor.ciphertext_hash,
            nonce: encrypted.nonce,
            ciphertext: encrypted.ciphertext.clone(),
        },
    )?;
    response_ok(match state.routing.as_ref() {
        Some(route) => pinned_request(route, request_value).await?,
        None => request(&state.card.server, certificate, request_value).await?,
    })
}

async fn upload_attachment_to_group(
    state: &State,
    certificate: &str,
    members: &[pigeon_shared::AccountIdentity],
    encrypted: &pigeon_shared::EncryptedAttachment,
) -> Result<()> {
    for member in members {
        if member.genesis == state.card.genesis {
            continue;
        }
        let contact = state
            .contacts
            .iter()
            .find(|contact| contact.genesis == member.genesis)
            .cloned()
            .context("attachment recipient is not a verified canonical contact")?;
        upload_attachment_to_contact(state, certificate, &contact, encrypted).await?;
    }
    Ok(())
}
fn parse_identity(value: &str) -> Result<[u8; 32]> {
    hex::decode(value)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("identity must be 32 bytes of hexadecimal"))
}

fn parse_genesis(value: &str) -> Result<PigeonAccountGenesis> {
    let genesis: PigeonAccountGenesis = decode(&STANDARD_NO_PAD.decode(value.trim())?)?;
    pigeon_shared::verify_genesis(&genesis)?;
    Ok(genesis)
}

/// Stable local map key for an external account. It is the entire canonical
/// genesis encoding, not the compact SHA-256 display/index value.
fn canonical_account_key(genesis: &PigeonAccountGenesis) -> Result<String> {
    Ok(STANDARD_NO_PAD.encode(pigeon_shared::canonical_genesis_key(genesis)?))
}

fn contact_key(card: &ContactCard) -> Result<String> {
    canonical_account_key(&card.genesis)
}

fn device_mls_key(genesis: &PigeonAccountGenesis, device_id: [u8; 32]) -> Result<String> {
    Ok(format!(
        "{}:{}",
        canonical_account_key(genesis)?,
        hex::encode(device_id)
    ))
}

fn contact_for_selector(state: &State, selector: &str) -> Result<ContactCard> {
    if let Ok(bytes) = STANDARD_NO_PAD.decode(selector.trim()) {
        if let Ok(genesis) = decode::<PigeonAccountGenesis>(&bytes) {
            pigeon_shared::verify_genesis(&genesis)?;
            return state
                .contacts
                .iter()
                .find(|contact| contact.genesis == genesis)
                .cloned()
                .context("unknown canonical contact genesis");
        }
    }
    contact_for(state, parse_identity(selector)?)
}
fn contact_for(state: &State, identity: [u8; 32]) -> Result<ContactCard> {
    let matches: Vec<_> = state
        .contacts
        .iter()
        .filter(|contact| identity_id(contact) == identity)
        .cloned()
        .collect();
    if matches.len() != 1 {
        bail!("group member compact ID is unknown or collides")
    }
    Ok(matches[0].clone())
}
fn identities_in_mls_group(
    state: &State,
    group: &MlsGroup,
) -> Result<Vec<pigeon_shared::AccountIdentity>> {
    let mut identities = vec![account_identity(state.card.genesis.clone())?];
    for contact in &state.contacts {
        if contact.devices.iter().any(|device| {
            group.members().any(|leaf| {
                leaf.credential == BasicCredential::new(device.device_id.to_vec()).into()
            })
        }) {
            identities.push(account_identity(contact.genesis.clone())?);
        }
    }
    identities.sort_by_key(|identity| canonical_account_key(&identity.genesis).unwrap_or_default());
    identities.dedup_by(|left, right| left.genesis == right.genesis);
    Ok(identities)
}
async fn deliver_group_payload(
    state: &State,
    certificate: &str,
    members: &[pigeon_shared::AccountIdentity],
    payload: Vec<u8>,
) -> Result<()> {
    let payload = wrap_mls_payload(state, payload)?;
    for identity in members {
        if identity.genesis == state.card.genesis {
            continue;
        }
        let contact = state
            .contacts
            .iter()
            .find(|contact| contact.genesis == identity.genesis)
            .cloned()
            .context("group member is not a verified canonical contact")?;
        let request_value = delivery_request(
            state,
            &contact,
            pigeon_shared::MlsRecord {
                recipient: identity.clone(),
                sender: account_identity(state.card.genesis.clone())?,
                sender_device: state.device.device_id,
                target_devices: contact
                    .devices
                    .iter()
                    .map(|device| device.device_id)
                    .collect(),
                payload: payload.clone(),
            },
        )?;
        response_ok(match state.routing.as_ref() {
            Some(route) => pinned_request(route, request_value).await?,
            None => request(&state.card.server, certificate, request_value).await?,
        })?;
    }
    Ok(())
}
mod commands;

#[tokio::main]
async fn main() -> Result<()> {
    commands::dispatch(Args::parse()).await
}

#[cfg(test)]
mod discovery_tests {
    use super::*;

    fn descriptor(address: &str) -> RelayDescriptor {
        RelayDescriptor {
            version: pigeon_shared::RELAY_DESCRIPTOR_VERSION,
            address: address.into(),
            identity: [1; 32],
            tls_spki_fingerprint: [2; 32],
        }
    }

    #[test]
    fn direct_endpoint_requires_an_explicit_socket_port() {
        assert_eq!(
            direct_endpoint("100.72.33.98:8443").unwrap(),
            Some("100.72.33.98:8443".into())
        );
        assert_eq!(direct_endpoint("relay.example").unwrap(), None);
        assert_eq!(direct_endpoint("https://relay.example/path").unwrap(), None);
        assert!(direct_endpoint("relay.example:0").is_err());
    }

    #[test]
    fn direct_first_contact_rejects_descriptor_address_substitution() {
        validate_direct_descriptor("100.72.33.98:8443", &descriptor("100.72.33.98:8443")).unwrap();
        assert!(
            validate_direct_descriptor("100.72.33.98:8443", &descriptor("evil.example:8443"))
                .is_err()
        );
    }

    #[test]
    fn descriptor_text_is_version_checked_before_pinning() {
        let text = descriptor_text(&descriptor("relay.example:8443")).unwrap();
        assert_eq!(
            parse_descriptor_text(&text).unwrap().address,
            "relay.example:8443"
        );
        let invalid = RelayDescriptor {
            version: 99,
            ..descriptor("relay.example:8443")
        };
        let text = STANDARD_NO_PAD.encode(serde_json::to_vec(&invalid).unwrap());
        assert!(parse_descriptor_text(&text).is_err());
    }

    #[test]
    fn https_descriptor_response_parsing_rejects_bad_status_and_payloads() {
        let body = serde_json::to_vec(&descriptor("relay.example:8443")).unwrap();
        let response = [
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n".as_slice(),
            body.as_slice(),
        ]
        .concat();
        assert_eq!(
            parse_https_discovery_response(&response).unwrap().address,
            "relay.example:8443"
        );
        assert!(parse_https_discovery_response(b"HTTP/1.1 404 Nope\r\n\r\n{}").is_err());
        assert!(parse_https_discovery_response(b"not HTTP").is_err());
        assert!(parse_https_discovery_response(b"HTTP/1.1 200 OK\r\n\r\nnot-json").is_err());
    }

    #[test]
    fn route_descriptor_validation_rejects_fingerprint_substitution() {
        let root = SigningKey::generate(&mut OsRng);
        let recovery = SigningKey::generate(&mut OsRng);
        let genesis = PigeonAccountGenesis {
            version: pigeon_shared::ACCOUNT_GENESIS_VERSION,
            root_public_key: root.verifying_key().to_bytes(),
            initial_device_key: root.verifying_key().to_bytes(),
            recovery_public_key: recovery.verifying_key().to_bytes(),
            nonce: [9; 32],
            initial_display_name: "Test".into(),
        };
        let route = pigeon_shared::make_routing(
            &root,
            genesis,
            "relay.example:8443".into(),
            [1; 32],
            [2; 32],
            1,
            0,
        );
        validate_route_descriptor(&route, &descriptor("relay.example:8443")).unwrap();
        assert!(validate_route_descriptor(
            &route,
            &RelayDescriptor {
                identity: [3; 32],
                ..descriptor("relay.example:8443")
            },
        )
        .is_err());
        assert!(validate_route_descriptor(
            &route,
            &RelayDescriptor {
                tls_spki_fingerprint: [4; 32],
                ..descriptor("relay.example:8443")
            },
        )
        .is_err());
    }
}
