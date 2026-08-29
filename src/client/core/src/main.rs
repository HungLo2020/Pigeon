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

type PersistedMlsIdentity = (Vec<u8>, Vec<u8>, HashMap<String, String>);

#[derive(Serialize, Deserialize)]
struct State {
    signing_secret: [u8; 32],
    encryption_secret: [u8; 32],
    card: ContactCard,
    contacts: Vec<ContactCard>,
    /// Serialized OpenMLS provider storage and conversation metadata. This is
    /// account-local and is included in an identity export.
    mls_storage: HashMap<String, String>,
    mls_conversations: HashMap<String, Vec<u8>>,
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
#[derive(Subcommand)]
enum Command {
    Create {
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

fn load(path: &str) -> Result<State> {
    let state: State = serde_json::from_slice(
        &fs::read(path).with_context(|| format!("read identity state {path}"))?,
    )?;
    if state.routing.is_none() {
        bail!("legacy identity state has no versioned relay-bound routing record; re-import from a current backup")
    }
    Ok(state)
}
fn save(path: &str, state: &State) -> Result<()> {
    fs::write(path, serde_json::to_vec_pretty(state)?)?;
    Ok(())
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
#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    match args.command {
        Command::Create { server } => {
            if std::path::Path::new(&args.state).exists() {
                bail!("identity already exists: {}", args.state)
            };
            let mut signing_secret = [0; 32];
            let mut encryption_secret = [0; 32];
            OsRng.fill_bytes(&mut signing_secret);
            OsRng.fill_bytes(&mut encryption_secret);
            let signing = SigningKey::from_bytes(&signing_secret);
            let encryption = StaticSecret::from(encryption_secret);
            let device_signing = SigningKey::generate(&mut OsRng);
            let (mls_key_package, mls_signer, mls_storage) =
                create_mls_identity(&device_signing.verifying_key().to_bytes())?;
            let device = make_device(&signing, &device_signing, mls_key_package);
            let card = make_card(&signing, &encryption, server.clone(), device.clone());
            let authorized_devices = AuthorizedDeviceSet {
                identity: identity_id(&card),
                revision: 1,
                devices: vec![device.clone()],
            };
            let state = State {
                signing_secret,
                encryption_secret,
                card: card.clone(),
                contacts: vec![],
                mls_storage,
                mls_conversations: HashMap::new(),
                mls_signer,
                device: device.clone(),
                authorized_devices,
                revocations: vec![],
                routing: None,
                pending_routing: vec![],
                cached_routes: HashMap::new(),
                groups: HashMap::new(),
            };
            response_ok(
                request(
                    &server,
                    &args.certificate,
                    Request::Register {
                        card,
                        device,
                        device_signature: vec![],
                    },
                )
                .await?,
            )?;
            let descriptor = relay_descriptor(&server, &args.certificate).await?;
            let route = make_routing(
                &signing,
                server.clone(),
                descriptor.identity,
                descriptor.tls_spki_fingerprint,
                1,
                0,
            );
            response_ok(
                request(
                    &server,
                    &args.certificate,
                    Request::PublishRouting(route.clone()),
                )
                .await?,
            )?;
            let mut state = state;
            state.routing = Some(route);
            save(&args.state, &state)?;
            println!(
                "identity created: {}",
                hex::encode(identity_id(&state.card))
            );
            println!(
                "export it with: pigeon-client --state {} export --output backup.json",
                args.state
            );
        }
        Command::Export { output } => {
            let state = load(&args.state)?;
            save(&output, &state)?;
            eprintln!(
                "WARNING: this unencrypted identity backup authorizes a device. Store it securely."
            );
            println!("exported {output}");
        }
        Command::Import { input } => {
            let state = load(&input)?;
            response_ok(
                request(
                    &state.card.server,
                    &args.certificate,
                    Request::Register {
                        card: state.card.clone(),
                        device: state.device.clone(),
                        device_signature: vec![],
                    },
                )
                .await?,
            )?;
            save(&args.state, &state)?;
            println!(
                "imported identity: {}",
                hex::encode(identity_id(&state.card))
            );
        }
        Command::Card => println!("{}", card_text(&load(&args.state)?.card)?),
        Command::AddContact { card } => {
            let mut state = load(&args.state)?;
            let card = parse_card(&card)?;
            let contact_identity = identity_id(&card);
            if let Ok(Response::Routing(Some(route))) = request(
                &card.server,
                &args.certificate,
                Request::GetRouting {
                    identity: contact_identity,
                },
            )
            .await
            {
                validate_route_descriptor(&route, &pinned_relay_descriptor(&route).await?)?;
                // The signed route is independently verified.  A freshly
                // created card and its first route commonly share revision 1,
                // so equality is sufficient to cache the route needed for
                // cross-relay delivery.
                if route.identity == contact_identity && route.revision >= card.revision {
                    state
                        .cached_routes
                        .insert(hex::encode(contact_identity), route);
                }
            }
            if !state
                .contacts
                .iter()
                .any(|existing| identity_id(existing) == identity_id(&card))
            {
                state.contacts.push(card);
                save(&args.state, &state)?;
            }
            println!("contact added");
        }
        Command::Send { to, text } => {
            let state = load(&args.state)?;
            let recipient = state
                .contacts
                .iter()
                .find(|card| hex::encode(identity_id(card)) == to)
                .context("unknown contact; add their card first")?
                .clone();
            let mut state = state;
            let (provider, signer) = mls_runtime(&state)?;
            let conversation = hex::encode(identity_id(&recipient));
            let group_id = if let Some(group_id) = state.mls_conversations.get(&conversation) {
                GroupId::tls_deserialize_exact(group_id)?
            } else {
                let recipient_device = recipient
                    .devices
                    .first()
                    .context("contact has no authorized device")?;
                let package =
                    KeyPackageIn::tls_deserialize_exact(recipient_device.mls_key_package.clone())?
                        .validate(provider.crypto(), ProtocolVersion::Mls10)?;
                let config = MlsGroupCreateConfig::builder()
                    .ciphersuite(Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519)
                    .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
                    .use_ratchet_tree_extension(true)
                    .build();
                let credential = CredentialWithKey {
                    credential: BasicCredential::new(identity_id(&state.card).to_vec()).into(),
                    signature_key: signer.to_public_vec().into(),
                };
                let mut group = MlsGroup::new(&provider, &signer, &config, credential)?;
                let (_, welcome, _) = group.add_members(&provider, &signer, &[package])?;
                group.merge_pending_commit(&provider)?;
                let id = group.group_id().clone();
                response_ok(
                    request(
                        &state.card.server,
                        &args.certificate,
                        delivery_request(
                            &state,
                            &recipient,
                            pigeon_shared::MlsRecord {
                                recipient_identity: identity_id(&recipient),
                                sender_device: state.device.device_id,
                                target_devices: recipient
                                    .devices
                                    .iter()
                                    .map(|device| device.device_id)
                                    .collect(),
                                payload: welcome.to_bytes()?,
                            },
                        )?,
                    )
                    .await?,
                )?;
                state
                    .mls_conversations
                    .insert(conversation.clone(), id.tls_serialize_detached()?);
                for device in &recipient.devices {
                    state
                        .mls_conversations
                        .insert(hex::encode(device.device_id), id.tls_serialize_detached()?);
                }
                id
            };
            let mut group = MlsGroup::load(provider.storage(), &group_id)?
                .context("MLS conversation state missing")?;
            let message = group
                .create_message(&provider, &signer, text.as_bytes())?
                .to_bytes()?;
            response_ok(
                request(
                    &state.card.server,
                    &args.certificate,
                    delivery_request(
                        &state,
                        &recipient,
                        pigeon_shared::MlsRecord {
                            recipient_identity: identity_id(&recipient),
                            sender_device: state.device.device_id,
                            target_devices: recipient
                                .devices
                                .iter()
                                .map(|device| device.device_id)
                                .collect(),
                            payload: message,
                        },
                    )?,
                )
                .await?,
            )?;
            persist_mls(&mut state, &provider)?;
            save(&args.state, &state)?;
            println!("sent");
        }
        Command::GroupCreate { group, members } => {
            let mut state = load(&args.state)?;
            if state.groups.contains_key(&group) {
                bail!("group already exists")
            }
            let members: Vec<[u8; 32]> = members
                .iter()
                .map(|member| parse_identity(member))
                .collect::<Result<_>>()?;
            if members.is_empty()
                || members
                    .iter()
                    .any(|member| *member == identity_id(&state.card))
            {
                bail!("group members must be one or more contacts")
            }
            let contacts: Vec<ContactCard> = members
                .iter()
                .map(|member| contact_for(&state, *member))
                .collect::<Result<_>>()?;
            let (provider, signer) = mls_runtime(&state)?;
            let config = MlsGroupCreateConfig::builder()
                .ciphersuite(Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519)
                .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
                .use_ratchet_tree_extension(true)
                .build();
            let credential = CredentialWithKey {
                // MLS leaves are device endpoints.  Root identities are used
                // only for the local group membership projection.
                credential: BasicCredential::new(state.device.device_id.to_vec()).into(),
                signature_key: signer.to_public_vec().into(),
            };
            let mut mls_group = MlsGroup::new(&provider, &signer, &config, credential)?;
            let mut packages = Vec::new();
            for device in contacts.iter().flat_map(|contact| contact.devices.iter()) {
                let package = KeyPackageIn::tls_deserialize_exact(device.mls_key_package.clone())?
                    .validate(provider.crypto(), ProtocolVersion::Mls10)?;
                packages.push(package);
            }
            let (_, welcome, _) = mls_group.add_members(&provider, &signer, &packages)?;
            mls_group.merge_pending_commit(&provider)?;
            let mut identities = members;
            identities.push(identity_id(&state.card));
            let group_id = mls_group.group_id().tls_serialize_detached()?;
            deliver_group_payload(&state, &args.certificate, &identities, welcome.to_bytes()?)
                .await?;
            let canonical_group = hex::encode(mls_group.group_id().as_slice());
            state.groups.insert(
                group.clone(),
                GroupState {
                    group_id: group_id.clone(),
                    members: identities.clone(),
                },
            );
            state.groups.insert(
                canonical_group.clone(),
                GroupState {
                    group_id,
                    members: identities,
                },
            );
            persist_mls(&mut state, &provider)?;
            save(&args.state, &state)?;
            println!("group created: {group} {canonical_group}");
        }
        Command::GroupSend { group, text } => {
            let mut state = load(&args.state)?;
            let group_state = state.groups.get(&group).context("unknown group")?.clone();
            if !group_state.members.contains(&identity_id(&state.card)) {
                bail!("this identity is not a group member")
            }
            let (provider, signer) = mls_runtime(&state)?;
            let group_id = GroupId::tls_deserialize_exact(group_state.group_id)?;
            let mut mls_group = MlsGroup::load(provider.storage(), &group_id)?
                .context("MLS group state missing")?;
            let payload = mls_group
                .create_message(&provider, &signer, text.as_bytes())?
                .to_bytes()?;
            deliver_group_payload(&state, &args.certificate, &group_state.members, payload).await?;
            persist_mls(&mut state, &provider)?;
            save(&args.state, &state)?;
            println!("sent");
        }
        Command::GroupAdd { group, member } => {
            let mut state = load(&args.state)?;
            let mut group_state = state.groups.get(&group).context("unknown group")?.clone();
            let member = parse_identity(&member)?;
            if !group_state.members.contains(&identity_id(&state.card)) {
                bail!("only a current participant may change membership")
            }
            if group_state.members.contains(&member) {
                bail!("identity is already a member")
            }
            let contact = contact_for(&state, member)?;
            let (provider, signer) = mls_runtime(&state)?;
            let group_id = GroupId::tls_deserialize_exact(group_state.group_id.clone())?;
            let mut mls_group = MlsGroup::load(provider.storage(), &group_id)?
                .context("MLS group state missing")?;
            let mut packages = Vec::new();
            for device in &contact.devices {
                let package = KeyPackageIn::tls_deserialize_exact(device.mls_key_package.clone())?
                    .validate(provider.crypto(), ProtocolVersion::Mls10)?;
                packages.push(package);
            }
            let (commit, welcome, _) = mls_group.add_members(&provider, &signer, &packages)?;
            mls_group.merge_pending_commit(&provider)?;
            deliver_group_payload(&state, &args.certificate, &[member], welcome.to_bytes()?)
                .await?;
            deliver_group_payload(
                &state,
                &args.certificate,
                &group_state.members,
                commit.to_bytes()?,
            )
            .await?;
            group_state.members.push(member);
            for saved in state.groups.values_mut() {
                if saved.group_id == group_state.group_id {
                    saved.members = group_state.members.clone();
                }
            }
            state.groups.insert(group, group_state);
            persist_mls(&mut state, &provider)?;
            save(&args.state, &state)?;
            println!("member added");
        }
        Command::GroupRemove { group, member } => {
            let mut state = load(&args.state)?;
            let mut group_state = state.groups.get(&group).context("unknown group")?.clone();
            let member = parse_identity(&member)?;
            if !group_state.members.contains(&identity_id(&state.card)) {
                bail!("only a current participant may change membership")
            }
            if member == identity_id(&state.card) || !group_state.members.contains(&member) {
                bail!("identity is not a removable group member")
            }
            let (provider, signer) = mls_runtime(&state)?;
            let group_id = GroupId::tls_deserialize_exact(group_state.group_id.clone())?;
            let mut mls_group = MlsGroup::load(provider.storage(), &group_id)?
                .context("MLS group state missing")?;
            let contact = contact_for(&state, member)?;
            let device_ids: Vec<Vec<u8>> = contact
                .devices
                .iter()
                .map(|device| device.device_id.to_vec())
                .collect();
            let leaves: Vec<_> = mls_group
                .members()
                .filter(|leaf| {
                    device_ids.iter().any(|device_id| {
                        leaf.credential == BasicCredential::new(device_id.clone()).into()
                    })
                })
                .map(|leaf| leaf.index)
                .collect();
            if leaves.is_empty() {
                bail!("identity has no MLS device leaves")
            }
            let (commit, _, _) = mls_group.remove_members(&provider, &signer, &leaves)?;
            mls_group.merge_pending_commit(&provider)?;
            group_state.members = identities_in_mls_group(&state, &mls_group);
            deliver_group_payload(
                &state,
                &args.certificate,
                &group_state.members,
                commit.to_bytes()?,
            )
            .await?;
            for saved in state.groups.values_mut() {
                if saved.group_id == group_state.group_id {
                    saved.members = group_state.members.clone();
                }
            }
            state.groups.insert(group, group_state);
            persist_mls(&mut state, &provider)?;
            save(&args.state, &state)?;
            println!("member removed");
        }
        Command::RevokeDevice { device_id } => {
            let mut state = load(&args.state)?;
            let bytes = hex::decode(device_id)?;
            let device_id: [u8; 32] = bytes
                .try_into()
                .map_err(|_| anyhow::anyhow!("device ID must be 32 bytes of hexadecimal"))?;
            if device_id == state.device.device_id {
                bail!("cannot revoke the current device from itself")
            }
            if !state
                .authorized_devices
                .devices
                .iter()
                .any(|device| device.device_id == device_id)
            {
                bail!("device is not in this identity's authorized roster")
            }
            let root = SigningKey::from_bytes(&state.signing_secret);
            let revision = state
                .revocations
                .iter()
                .map(|revocation| revocation.revision)
                .max()
                .unwrap_or(0)
                + 1;
            let revocation = make_revocation(&root, device_id, revision);
            response_ok(
                request(
                    &state.card.server,
                    &args.certificate,
                    Request::RevokeDevice(revocation.clone()),
                )
                .await?,
            )?;
            let surviving_devices: Vec<[u8; 32]> = state
                .authorized_devices
                .devices
                .iter()
                .filter(|device| device.device_id != device_id)
                .map(|device| device.device_id)
                .collect();
            // A device credential is also the MLS BasicCredential.  Remove it
            // from every direct group held by this surviving device and relay
            // the resulting MLS Commit to the peer and any other surviving
            // local devices.  The relay sees only the opaque commit.
            let (provider, signer) = mls_runtime(&state)?;
            for group_bytes in state.mls_conversations.values() {
                let group_id = GroupId::tls_deserialize_exact(group_bytes)?;
                let mut group = MlsGroup::load(provider.storage(), &group_id)?
                    .context("persisted MLS group missing")?;
                let revoked_leaf = group
                    .members()
                    .find(|member| {
                        member.credential == BasicCredential::new(device_id.to_vec()).into()
                    })
                    .map(|member| member.index);
                let Some(revoked_leaf) = revoked_leaf else {
                    continue;
                };
                let (commit, _, _) = group.remove_members(&provider, &signer, &[revoked_leaf])?;
                group.merge_pending_commit(&provider)?;
                let payload = commit.to_bytes()?;
                for contact in &state.contacts {
                    if !contact.devices.iter().any(|device| {
                        group.members().any(|member| {
                            member.credential
                                == BasicCredential::new(device.device_id.to_vec()).into()
                        })
                    }) {
                        continue;
                    }
                    response_ok(
                        request(
                            &state.card.server,
                            &args.certificate,
                            Request::SendMls(pigeon_shared::MlsRecord {
                                recipient_identity: identity_id(contact),
                                sender_device: state.device.device_id,
                                target_devices: contact
                                    .devices
                                    .iter()
                                    .map(|device| device.device_id)
                                    .collect(),
                                payload: payload.clone(),
                            }),
                        )
                        .await?,
                    )?;
                }
                let local_targets: Vec<_> = surviving_devices
                    .iter()
                    .copied()
                    .filter(|target| *target != state.device.device_id)
                    .collect();
                if !local_targets.is_empty() {
                    response_ok(
                        request(
                            &state.card.server,
                            &args.certificate,
                            Request::SendMls(pigeon_shared::MlsRecord {
                                recipient_identity: identity_id(&state.card),
                                sender_device: state.device.device_id,
                                target_devices: local_targets,
                                payload,
                            }),
                        )
                        .await?,
                    )?;
                }
            }
            persist_mls(&mut state, &provider)?;
            state.revocations.push(revocation);
            state
                .authorized_devices
                .devices
                .retain(|device| device.device_id != device_id);
            state.authorized_devices.revision += 1;
            state.card = make_card_with_devices(
                &root,
                &StaticSecret::from(state.encryption_secret),
                state.card.server.clone(),
                state.authorized_devices.devices.clone(),
                state.card.revision + 1,
            );
            save(&args.state, &state)?;
            println!("device revoked");
        }
        Command::Migrate {
            server,
            previous_certificate,
        } => {
            let mut state = load(&args.state)?;
            if state.card.server == server {
                println!("already using {server}");
                return Ok(());
            }
            let root = SigningKey::from_bytes(&state.signing_secret);
            let current_revision = state
                .routing
                .as_ref()
                .map(|route| route.revision)
                .unwrap_or(state.card.revision);
            let card = make_card_with_devices(
                &root,
                &StaticSecret::from(state.encryption_secret),
                server.clone(),
                state.authorized_devices.devices.clone(),
                state.card.revision + 1,
            );
            // Register first: a route is never published to a destination that
            // has not accepted the identity/device records.
            response_ok(
                request(
                    &server,
                    &args.certificate,
                    Request::Register {
                        card: card.clone(),
                        device: state.device.clone(),
                        device_signature: vec![],
                    },
                )
                .await?,
            )?;
            let descriptor = relay_descriptor(&server, &args.certificate).await?;
            let route = make_routing(
                &root,
                server.clone(),
                descriptor.identity,
                descriptor.tls_spki_fingerprint,
                current_revision + 1,
                current_revision,
            );
            response_ok(
                request(
                    &server,
                    &args.certificate,
                    Request::PublishRouting(route.clone()),
                )
                .await?,
            )?;
            let previous_certificate = previous_certificate.as_deref().unwrap_or(&args.certificate);
            if request(
                &state.card.server,
                previous_certificate,
                Request::PublishRouting(route.clone()),
            )
            .await
            .and_then(response_ok)
            .is_err()
            {
                state.pending_routing.push(route.clone());
            }
            // Contact relays are non-authoritative caches of the same signed
            // record. This provides a reachable propagation path when the old
            // relay is offline without introducing a global directory.
            // Reachable contacts learn this via their cached signed route and
            // normal sync; guessing another relay's TLS certificate here
            // would weaken pinning.
            state.card = card;
            state.routing = Some(route);
            save(&args.state, &state)?;
            println!("migrated to {server}");
        }
        Command::Fetch => {
            let mut state = load(&args.state)?;
            for contact in state.contacts.clone() {
                let identity = identity_id(&contact);
                let known_route = state.cached_routes.get(&hex::encode(identity)).cloned();
                let route_response = match known_route {
                    Some(route) => pinned_request(&route, Request::GetRouting { identity }).await,
                    None => {
                        request(
                            &contact.server,
                            &args.certificate,
                            Request::GetRouting { identity },
                        )
                        .await
                    }
                };
                if let Ok(Response::Routing(Some(route))) = route_response {
                    validate_route_descriptor(&route, &pinned_relay_descriptor(&route).await?)?;
                    let key = hex::encode(identity);
                    let known = state
                        .cached_routes
                        .get(&key)
                        .map(|route| route.revision)
                        .unwrap_or(contact.revision);
                    if route.identity == identity && route.revision > known {
                        state.cached_routes.insert(key, route);
                    }
                }
            }
            let revocations = match request(
                &state.card.server,
                &args.certificate,
                Request::GetRevocations {
                    identity: identity_id(&state.card),
                },
            )
            .await?
            {
                Response::Revocations(revocations) => revocations,
                Response::Error(error) => bail!("server rejected request: {error}"),
                _ => bail!("unexpected revocation synchronization response"),
            };
            for revocation in revocations {
                pigeon_shared::verify_revocation(&revocation)?;
                if !state
                    .revocations
                    .iter()
                    .any(|known| known.device_id == revocation.device_id)
                {
                    state
                        .authorized_devices
                        .devices
                        .retain(|device| device.device_id != revocation.device_id);
                    state.revocations.push(revocation);
                }
            }
            if state
                .revocations
                .iter()
                .any(|revocation| revocation.device_id == state.device.device_id)
            {
                save(&args.state, &state)?;
                bail!("this device has been revoked and cannot synchronize")
            }
            match request(
                &state.card.server,
                &args.certificate,
                Request::Fetch {
                    identity: identity_id(&state.card),
                    device_id: state.device.device_id,
                    known_routing_revision: state.card.revision,
                },
            )
            .await?
            {
                Response::MlsMessages(records) => {
                    let (provider, _signer) = mls_runtime(&state)?;
                    let record_ids: Vec<i64> = records.iter().map(|(id, _)| *id).collect();
                    let config = MlsGroupCreateConfig::builder()
                        .ciphersuite(Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519)
                        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
                        .use_ratchet_tree_extension(true)
                        .build();
                    for (_record_id, record) in records {
                        let incoming = MlsMessageIn::tls_deserialize_exact(record.payload.clone())?;
                        match incoming.extract() {
                            MlsMessageBodyIn::Welcome(welcome) => {
                                let group = StagedWelcome::new_from_welcome(
                                    &provider,
                                    config.join_config(),
                                    welcome,
                                    None,
                                )?
                                .into_group(&provider)?;
                                let group_id = group.group_id().tls_serialize_detached()?;
                                state
                                    .mls_conversations
                                    .insert(hex::encode(record.sender_device), group_id.clone());
                                if let Some(contact) = state.contacts.iter().find(|contact| {
                                    contact
                                        .devices
                                        .iter()
                                        .any(|device| device.device_id == record.sender_device)
                                }) {
                                    // The sender device maps this Welcome to
                                    // the stable contact identity so a reply
                                    // reuses the established MLS group.
                                    state
                                        .mls_conversations
                                        .insert(hex::encode(identity_id(contact)), group_id);
                                }
                                let mut members = vec![identity_id(&state.card)];
                                for contact in &state.contacts {
                                    if contact.devices.iter().any(|device| {
                                        group.members().any(|leaf| {
                                            leaf.credential
                                                == BasicCredential::new(device.device_id.to_vec())
                                                    .into()
                                        })
                                    }) {
                                        members.push(identity_id(contact));
                                    }
                                }
                                members.sort();
                                members.dedup();
                                state
                                    .groups
                                    .entry(hex::encode(group.group_id().as_slice()))
                                    .or_insert(GroupState {
                                        group_id: group.group_id().tls_serialize_detached()?,
                                        members,
                                    });
                            }
                            MlsMessageBodyIn::PrivateMessage(_)
                            | MlsMessageBodyIn::PublicMessage(_) => {
                                let key = hex::encode(record.sender_device);
                                let protocol = MlsMessageIn::tls_deserialize_exact(record.payload)?
                                    .try_into_protocol_message()?;
                                let protocol_group = hex::encode(protocol.group_id().as_slice());
                                let group_bytes = state
                                    .groups
                                    .get(&protocol_group)
                                    .map(|group| group.group_id.clone())
                                    .or_else(|| state.mls_conversations.get(&key).cloned())
                                    .context("received MLS message before Welcome")?;
                                let group_id = GroupId::tls_deserialize_exact(group_bytes)?;
                                let mut group = MlsGroup::load(provider.storage(), &group_id)?
                                    .context("persisted MLS group missing")?;
                                let processed = group.process_message(&provider, protocol)?;
                                match processed.into_content() {
                                    ProcessedMessageContent::ApplicationMessage(message) => {
                                        println!(
                                            "{}: {}",
                                            key,
                                            String::from_utf8(message.into_bytes())?
                                        );
                                    }
                                    ProcessedMessageContent::StagedCommitMessage(staged) => {
                                        group.merge_staged_commit(&provider, *staged)?;
                                        let members = identities_in_mls_group(&state, &group);
                                        let group_id = group.group_id().tls_serialize_detached()?;
                                        for group_state in state.groups.values_mut() {
                                            if group_state.group_id == group_id {
                                                group_state.members = members.clone();
                                            }
                                        }
                                    }
                                    ProcessedMessageContent::OwnPendingCommit => {
                                        group.merge_pending_commit(&provider)?;
                                    }
                                    _ => {}
                                }
                            }
                            _ => bail!("unexpected MLS relay message"),
                        }
                    }
                    persist_mls(&mut state, &provider)?;
                    save(&args.state, &state)?;
                    if !record_ids.is_empty() {
                        response_ok(
                            request(
                                &state.card.server,
                                &args.certificate,
                                Request::Acknowledge {
                                    device_id: state.device.device_id,
                                    record_ids,
                                    signature: vec![],
                                },
                            )
                            .await?,
                        )?;
                    }
                }
                Response::Error(error) => bail!("server rejected request: {error}"),
                Response::Moved(route) => {
                    validate_route_descriptor(&route, &pinned_relay_descriptor(&route).await?)?;
                    if route.identity != identity_id(&state.card)
                        || route.revision
                            <= state
                                .routing
                                .as_ref()
                                .map(|route| route.revision)
                                .unwrap_or(0)
                    {
                        bail!("received stale or unrelated MOVED record")
                    }
                    let root = SigningKey::from_bytes(&state.signing_secret);
                    state.card = make_card_with_devices(
                        &root,
                        &StaticSecret::from(state.encryption_secret),
                        route.server.clone(),
                        state.authorized_devices.devices.clone(),
                        route.revision,
                    );
                    state.routing = Some(route);
                    save(&args.state, &state)?;
                    println!("switched to the newer server route; run fetch again");
                }
                _ => bail!("unexpected server response"),
            }
        }
    };
    Ok(())
}
