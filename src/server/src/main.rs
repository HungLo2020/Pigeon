use anyhow::{bail, Context, Result};
use clap::Parser;
use pigeon_shared::{decode, encode, identity_id, verify_card, Request, Response};
use rcgen::generate_simple_self_signed;
use rusqlite::{params, Connection, OptionalExtension};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::ServerConfig;
use std::{
    fs,
    sync::{Arc, Mutex},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use tokio_rustls::TlsAcceptor;

#[derive(Parser)]
struct Args {
    #[arg(long, default_value = "127.0.0.1:8443")]
    listen: String,
    #[arg(long, default_value = "pigeon-server.sqlite3")]
    database: String,
    #[arg(long, default_value = "pigeon-server-cert.der")]
    certificate: String,
    #[arg(long, default_value = "pigeon-server-key.der")]
    private_key: String,
}

fn ensure_certificate(cert: &str, key: &str) -> Result<(Vec<u8>, Vec<u8>)> {
    if std::path::Path::new(cert).exists() && std::path::Path::new(key).exists() {
        return Ok((fs::read(cert)?, fs::read(key)?));
    }
    let generated = generate_simple_self_signed(vec!["localhost".into()])?;
    let certificate = generated.cert.der().to_vec();
    let private_key = generated.key_pair.serialize_der();
    fs::write(cert, &certificate)?;
    fs::write(key, &private_key)?;
    eprintln!("generated development TLS certificate at {cert}");
    Ok((certificate, private_key))
}

async fn read_frame<S: AsyncReadExt + Unpin>(stream: &mut S) -> Result<Vec<u8>> {
    let size = stream.read_u32().await? as usize;
    if size > 16 * 1024 * 1024 {
        bail!("frame too large");
    }
    let mut value = vec![0; size];
    stream.read_exact(&mut value).await?;
    Ok(value)
}
async fn write_frame<S: AsyncWriteExt + Unpin>(stream: &mut S, bytes: &[u8]) -> Result<()> {
    stream.write_u32(bytes.len() as u32).await?;
    stream.write_all(bytes).await?;
    stream.flush().await?;
    Ok(())
}

fn initialize(connection: &Connection) -> Result<()> {
    connection.execute_batch("CREATE TABLE IF NOT EXISTS identities (id BLOB PRIMARY KEY, card BLOB NOT NULL); CREATE TABLE IF NOT EXISTS key_packages (identity BLOB PRIMARY KEY, key_package BLOB NOT NULL); CREATE TABLE IF NOT EXISTS mls_records (id INTEGER PRIMARY KEY, recipient BLOB NOT NULL, record BLOB NOT NULL); CREATE TABLE IF NOT EXISTS envelopes (id INTEGER PRIMARY KEY, recipient BLOB NOT NULL, envelope BLOB NOT NULL);")?;
    Ok(())
}
fn process(connection: &Connection, request: Request) -> Response {
    let result: Result<Response> = (|| match request {
        Request::Register(card) => {
            verify_card(&card)?;
            connection.execute(
                "INSERT OR REPLACE INTO identities (id, card) VALUES (?1, ?2)",
                params![identity_id(&card).to_vec(), encode(&card)?],
            )?;
            Ok(Response::Ok)
        }
        Request::PublishKeyPackage {
            identity,
            key_package,
        } => {
            let found: bool = connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM identities WHERE id = ?1)",
                params![identity.to_vec()],
                |r| r.get(0),
            )?;
            if !found {
                bail!("identity has not registered this server")
            }
            connection.execute(
                "INSERT OR REPLACE INTO key_packages (identity, key_package) VALUES (?1, ?2)",
                params![identity.to_vec(), key_package],
            )?;
            Ok(Response::Ok)
        }
        Request::GetKeyPackage { identity } => {
            let package = connection
                .query_row(
                    "SELECT key_package FROM key_packages WHERE identity = ?1",
                    params![identity.to_vec()],
                    |r| r.get(0),
                )
                .optional()?;
            Ok(Response::KeyPackage(package))
        }
        Request::SendMls(record) => {
            let found: bool = connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM identities WHERE id = ?1)",
                params![record.recipient.to_vec()],
                |r| r.get(0),
            )?;
            if !found {
                bail!("recipient has not registered this server")
            }
            connection.execute(
                "INSERT INTO mls_records (recipient, record) VALUES (?1, ?2)",
                params![record.recipient.to_vec(), encode(&record)?],
            )?;
            Ok(Response::Ok)
        }
        Request::Fetch { identity } => {
            let mut statement = connection
                .prepare("SELECT id, record FROM mls_records WHERE recipient = ?1 ORDER BY id")?;
            let records: Vec<(i64, Vec<u8>)> = statement
                .query_map(params![identity.to_vec()], |r| Ok((r.get(0)?, r.get(1)?)))?
                .collect::<std::result::Result<_, _>>()?;
            let messages = records
                .iter()
                .map(|(_, value)| pigeon_shared::decode(value))
                .collect::<Result<Vec<_>>>()?;
            for (id, _) in records {
                connection.execute("DELETE FROM mls_records WHERE id = ?1", params![id])?;
            }
            Ok(Response::MlsMessages(messages))
        }
    })();
    result.unwrap_or_else(|error| Response::Error(error.to_string()))
}
async fn handle(
    stream: TcpStream,
    acceptor: TlsAcceptor,
    database: Arc<Mutex<Connection>>,
) -> Result<()> {
    let mut tls = acceptor.accept(stream).await?;
    let request = decode(&read_frame(&mut tls).await?)?;
    let response = {
        let connection = database
            .lock()
            .map_err(|_| anyhow::anyhow!("database lock poisoned"))?;
        process(&connection, request)
    };
    write_frame(&mut tls, &encode(&response)?).await
}
#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let (cert, key) = ensure_certificate(&args.certificate, &args.private_key)?;
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(cert)],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key)),
        )
        .context("invalid TLS certificate")?;
    let database = Connection::open(&args.database)?;
    initialize(&database)?;
    let database = Arc::new(Mutex::new(database));
    let listener = TcpListener::bind(&args.listen).await?;
    eprintln!("pigeon relay listening on {}", args.listen);
    let acceptor = TlsAcceptor::from(Arc::new(config));
    loop {
        let (stream, _) = listener.accept().await?;
        if let Err(error) = handle(stream, acceptor.clone(), database.clone()).await {
            eprintln!("connection rejected: {error:#}");
        }
    }
}
