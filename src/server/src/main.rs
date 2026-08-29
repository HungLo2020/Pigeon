use anyhow::{bail, Context, Result};
use clap::Parser;
use ed25519_dalek::SigningKey;
use pigeon_shared::{
    decode, encode, identity_id, make_relay_forward, routing_precedes, tls_spki_fingerprint,
    verify_card, verify_device, verify_relay_forward, verify_revocation, verify_routing,
    DeviceRevocation, RelayDescriptor, Request, Response, RoutingRecord,
};
use rand_core::OsRng;
use rusqlite::{params, Connection, OptionalExtension};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    ClientConfig, DigitallySignedStruct, Error as TlsError, ServerConfig, SignatureScheme,
};
use std::{
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::{
    net::{TcpListener, TcpStream},
    time::{self, Duration},
};
use tokio_rustls::{TlsAcceptor, TlsConnector};

mod tls;
mod transport;
use tls::ensure_certificate;
use transport::{read_frame, write_frame};

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

const DORMANCY_SECONDS: i64 = 90 * 24 * 60 * 60;
const RETENTION_SECONDS: i64 = 14 * 24 * 60 * 60;

mod runtime;
use runtime::{
    bind_relay_tls_spki, flush_network_outbound, handle, initialize, maintain_lifecycle,
    set_relay_address, system_now,
};

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let (cert, key) = ensure_certificate(&args.certificate, &args.private_key)?;
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(cert.clone())],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key)),
        )
        .context("invalid TLS certificate")?;
    let database = Connection::open(&args.database)?;
    initialize(&database)?;
    bind_relay_tls_spki(&database, tls_spki_fingerprint(&cert)?)?;
    set_relay_address(&database, &args.listen)?;
    let database = Arc::new(Mutex::new(database));
    let lifecycle_database = database.clone();
    tokio::spawn(async move {
        let mut interval = time::interval(Duration::from_secs(1));
        loop {
            interval.tick().await;
            match lifecycle_database.lock() {
                Ok(connection) => {
                    if let Err(error) = maintain_lifecycle(&connection, system_now()) {
                        eprintln!("relay lifecycle maintenance failed: {error:#}");
                    }
                }
                Err(_) => eprintln!("relay lifecycle maintenance failed: database lock poisoned"),
            }
        }
    });
    let forwarding_database = database.clone();
    tokio::spawn(async move {
        let mut interval = time::interval(Duration::from_millis(250));
        loop {
            interval.tick().await;
            if let Err(error) = flush_network_outbound(forwarding_database.clone()).await {
                // The row deliberately remains durable for retry after a peer
                // outage, restart, or corrected route/TLS endpoint.
                eprintln!("relay forwarding deferred: {error:#}");
            }
        }
    });
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
