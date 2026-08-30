use anyhow::{bail, Context, Result};
use clap::Parser;
use ed25519_dalek::SigningKey;
use pigeon_shared::{
    decode, encode, identity_id, make_relay_forward, routing_precedes, tls_spki_fingerprint,
    verify_card, verify_device, verify_relay_forward, verify_revocation, verify_routing,
    DeviceRevocation, PairingArtifactKind, RelayDescriptor, Request, Response, RoutingRecord,
};
use rand_core::OsRng;
use rusqlite::{params, Connection, OptionalExtension};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    ClientConfig, DigitallySignedStruct, Error as TlsError, ServerConfig, SignatureScheme,
};
use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::{
    net::{TcpListener, TcpStream},
    time::{self, Duration},
};
use tokio_rustls::{TlsAcceptor, TlsConnector};

mod config;
mod tls;
mod transport;
use config::ServerSettings;
use tls::ensure_certificate;
use transport::{read_frame, write_frame};

#[derive(Parser)]
struct Args {
    /// Persistent key=value relay configuration, normally /etc/pigeon/pigeon-server.conf.
    #[arg(long)]
    config: Option<PathBuf>,
    #[arg(long)]
    listen: Option<String>,
    #[arg(long)]
    public_address: Option<String>,
    #[arg(long)]
    database: Option<String>,
    #[arg(long)]
    certificate: Option<String>,
    #[arg(long)]
    private_key: Option<String>,
    /// Initialize persistent TLS/relay/database state and exit without binding a socket.
    #[arg(long)]
    initialize_only: bool,
    /// Print the public JSON discovery descriptor after initializing persistent state.
    #[arg(long)]
    print_descriptor: bool,
}

impl Args {
    fn settings(&self) -> Result<ServerSettings> {
        let uses_legacy_defaults = self.config.is_none();
        let mut settings = match &self.config {
            Some(path) => ServerSettings::from_config(path)?,
            None => ServerSettings::default(),
        };
        if let Some(value) = &self.listen {
            settings.listen = value.clone();
        }
        if let Some(value) = &self.public_address {
            settings.public_address = value.clone();
        } else if uses_legacy_defaults && self.listen.is_some() {
            // Before packaged config existed, --listen was also the published
            // route. Preserve that CLI behavior for development callers.
            settings.public_address = settings.listen.clone();
        }
        if let Some(value) = &self.database {
            settings.database = value.clone();
        }
        if let Some(value) = &self.certificate {
            settings.certificate = value.clone();
        }
        if let Some(value) = &self.private_key {
            settings.private_key = value.clone();
        }
        settings.validate()?;
        Ok(settings)
    }
}

const DORMANCY_SECONDS: i64 = 90 * 24 * 60 * 60;
const RETENTION_SECONDS: i64 = 14 * 24 * 60 * 60;

mod runtime;
use runtime::{
    bind_relay_tls_spki, descriptor, flush_network_outbound, handle, initialize,
    maintain_lifecycle, set_relay_address, system_now,
};

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let settings = args.settings()?;
    let (cert, key) = ensure_certificate(&settings.certificate, &settings.private_key)?;
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(cert.clone())],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key)),
        )
        .context("invalid TLS certificate")?;
    let database = Connection::open(&settings.database)?;
    initialize(&database)?;
    bind_relay_tls_spki(&database, tls_spki_fingerprint(&cert)?)?;
    set_relay_address(&database, &settings.public_address)?;
    if args.print_descriptor {
        println!("{}", serde_json::to_string(&descriptor(&database)?)?);
        return Ok(());
    }
    if args.initialize_only {
        eprintln!(
            "pigeon relay state initialized for {}",
            settings.public_address
        );
        return Ok(());
    }
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
    let listener = TcpListener::bind(&settings.listen).await?;
    eprintln!("pigeon relay listening on {}", settings.listen);
    let acceptor = TlsAcceptor::from(Arc::new(config));
    loop {
        let (stream, _) = listener.accept().await?;
        if let Err(error) = handle(stream, acceptor.clone(), database.clone()).await {
            eprintln!("connection rejected: {error:#}");
        }
    }
}

#[cfg(test)]
mod cli_tests {
    use super::Args;

    #[test]
    fn direct_cli_listen_remains_the_default_public_address() {
        let args = Args {
            config: None,
            listen: Some("127.0.0.1:9443".into()),
            public_address: None,
            database: None,
            certificate: None,
            private_key: None,
            initialize_only: false,
            print_descriptor: false,
        };
        let settings = args.settings().unwrap();
        assert_eq!(settings.listen, "127.0.0.1:9443");
        assert_eq!(settings.public_address, "127.0.0.1:9443");
    }
}
