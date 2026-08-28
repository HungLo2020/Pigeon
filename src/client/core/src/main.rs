use ::tls_codec::Deserialize as _;
use ::tls_codec::Serialize as _;
use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine};
use clap::{Parser, Subcommand};
use ed25519_dalek::SigningKey;
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use pigeon_shared::{decode, encode, identity_id, make_card, ContactCard, Request, Response};
use rand_core::{OsRng, RngCore};
use rustls::{
    pki_types::{CertificateDer, ServerName},
    ClientConfig, RootCertStore,
};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, fs, sync::Arc};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use tokio_rustls::TlsConnector;
use x25519_dalek::StaticSecret;

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
    Fetch,
}

fn load(path: &str) -> Result<State> {
    Ok(serde_json::from_slice(
        &fs::read(path).with_context(|| format!("read identity state {path}"))?,
    )?)
}
fn save(path: &str, state: &State) -> Result<()> {
    fs::write(path, serde_json::to_vec_pretty(state)?)?;
    Ok(())
}
fn create_mls_identity(identity: &[u8]) -> Result<(Vec<u8>, Vec<u8>, HashMap<String, String>)> {
    let provider = OpenMlsRustCrypto::default();
    let suite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    let signer = SignatureKeyPair::new(suite.signature_algorithm())?;
    let credential = CredentialWithKey {
        credential: BasicCredential::new(identity.to_vec()).into(),
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
fn card_text(card: &ContactCard) -> Result<String> {
    Ok(STANDARD_NO_PAD.encode(serde_json::to_vec(card)?))
}
fn parse_card(value: &str) -> Result<ContactCard> {
    let card: ContactCard = serde_json::from_slice(&STANDARD_NO_PAD.decode(value)?)?;
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
            let (mls_key_package, mls_signer, mls_storage) =
                create_mls_identity(&signing.verifying_key().to_bytes())?;
            let card = make_card(&signing, &encryption, server.clone(), mls_key_package);
            let state = State {
                signing_secret,
                encryption_secret,
                card: card.clone(),
                contacts: vec![],
                mls_storage,
                mls_conversations: HashMap::new(),
                mls_signer,
            };
            response_ok(request(&server, &args.certificate, Request::Register(card)).await?)?;
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
                    Request::Register(state.card.clone()),
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
                let package =
                    KeyPackageIn::tls_deserialize_exact(recipient.mls_key_package.clone())?
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
                        Request::SendMls(pigeon_shared::MlsRecord {
                            recipient: identity_id(&recipient),
                            sender: identity_id(&state.card),
                            payload: welcome.to_bytes()?,
                        }),
                    )
                    .await?,
                )?;
                state
                    .mls_conversations
                    .insert(conversation.clone(), id.tls_serialize_detached()?);
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
                    Request::SendMls(pigeon_shared::MlsRecord {
                        recipient: identity_id(&recipient),
                        sender: identity_id(&state.card),
                        payload: message,
                    }),
                )
                .await?,
            )?;
            persist_mls(&mut state, &provider)?;
            save(&args.state, &state)?;
            println!("sent");
        }
        Command::Fetch => {
            let mut state = load(&args.state)?;
            match request(
                &state.card.server,
                &args.certificate,
                Request::Fetch {
                    identity: identity_id(&state.card),
                },
            )
            .await?
            {
                Response::MlsMessages(records) => {
                    let (provider, _signer) = mls_runtime(&state)?;
                    let config = MlsGroupCreateConfig::builder()
                        .ciphersuite(Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519)
                        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
                        .use_ratchet_tree_extension(true)
                        .build();
                    for record in records {
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
                                state.mls_conversations.insert(
                                    hex::encode(record.sender),
                                    group.group_id().tls_serialize_detached()?,
                                );
                            }
                            MlsMessageBodyIn::PrivateMessage(_)
                            | MlsMessageBodyIn::PublicMessage(_) => {
                                let key = hex::encode(record.sender);
                                let group_id = GroupId::tls_deserialize_exact(
                                    state
                                        .mls_conversations
                                        .get(&key)
                                        .context("received MLS message before Welcome")?,
                                )?;
                                let mut group = MlsGroup::load(provider.storage(), &group_id)?
                                    .context("persisted MLS group missing")?;
                                let protocol = MlsMessageIn::tls_deserialize_exact(record.payload)?
                                    .try_into_protocol_message()?;
                                let processed = group.process_message(&provider, protocol)?;
                                if let ProcessedMessageContent::ApplicationMessage(message) =
                                    processed.into_content()
                                {
                                    println!(
                                        "{}: {}",
                                        key,
                                        String::from_utf8(message.into_bytes())?
                                    );
                                }
                            }
                            _ => bail!("unexpected MLS relay message"),
                        }
                    }
                    persist_mls(&mut state, &provider)?;
                    save(&args.state, &state)?;
                }
                Response::Error(error) => bail!("server rejected request: {error}"),
                _ => bail!("unexpected server response"),
            }
        }
    };
    Ok(())
}
