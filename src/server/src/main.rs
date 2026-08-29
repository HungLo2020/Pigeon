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

fn initialize(connection: &Connection) -> Result<()> {
    connection.execute_batch("CREATE TABLE IF NOT EXISTS identities (id BLOB PRIMARY KEY, card BLOB NOT NULL); CREATE TABLE IF NOT EXISTS routes (identity_id BLOB PRIMARY KEY, route BLOB NOT NULL); CREATE TABLE IF NOT EXISTS devices (device_id BLOB PRIMARY KEY, identity_id BLOB NOT NULL, record BLOB NOT NULL, revoked INTEGER NOT NULL DEFAULT 0, dormant INTEGER NOT NULL DEFAULT 0, last_seen INTEGER NOT NULL DEFAULT 0); CREATE TABLE IF NOT EXISTS revocations (device_id BLOB PRIMARY KEY, revocation BLOB NOT NULL); CREATE TABLE IF NOT EXISTS mls_events (id INTEGER PRIMARY KEY, record BLOB NOT NULL, created_at INTEGER NOT NULL DEFAULT 0); CREATE TABLE IF NOT EXISTS event_deliveries (event_id INTEGER NOT NULL, device_id BLOB NOT NULL, acknowledged INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(event_id, device_id)); CREATE TABLE IF NOT EXISTS key_packages (identity BLOB PRIMARY KEY, key_package BLOB NOT NULL);")?;
    connection.execute("CREATE TABLE IF NOT EXISTS relay_identity (id INTEGER PRIMARY KEY CHECK(id = 1), secret BLOB NOT NULL)", [])?;
    connection.execute("CREATE TABLE IF NOT EXISTS outbound_forwards (id INTEGER PRIMARY KEY, forward BLOB NOT NULL)", [])?;
    connection.execute("CREATE TABLE IF NOT EXISTS relay_tls (id INTEGER PRIMARY KEY CHECK(id = 1), spki BLOB NOT NULL)", [])?;
    connection.execute(
        "CREATE TABLE IF NOT EXISTS relay_config (name TEXT PRIMARY KEY, value BLOB NOT NULL)",
        [],
    )?;
    // Upgrade relay databases created before operational device state existed.
    let _ = connection.execute(
        "ALTER TABLE devices ADD COLUMN dormant INTEGER NOT NULL DEFAULT 0",
        [],
    );
    let _ = connection.execute(
        "ALTER TABLE devices ADD COLUMN last_seen INTEGER NOT NULL DEFAULT 0",
        [],
    );
    let _ = connection.execute(
        "ALTER TABLE mls_events ADD COLUMN created_at INTEGER NOT NULL DEFAULT 0",
        [],
    );
    Ok(())
}
fn relay_tls_spki(connection: &Connection) -> Result<[u8; 32]> {
    let value: Vec<u8> = connection
        .query_row("SELECT spki FROM relay_tls WHERE id = 1", [], |r| r.get(0))
        .context("relay TLS SPKI is not initialized")?;
    value
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid persisted relay TLS SPKI"))
}
fn bind_relay_tls_spki(connection: &Connection, spki: [u8; 32]) -> Result<()> {
    let existing: Option<Vec<u8>> = connection
        .query_row("SELECT spki FROM relay_tls WHERE id = 1", [], |r| r.get(0))
        .optional()?;
    match existing {
        None => {
            connection.execute(
                "INSERT INTO relay_tls (id, spki) VALUES (1, ?1)",
                params![spki.to_vec()],
            )?;
        }
        Some(existing) if existing.as_slice() == spki => {}
        Some(_) => {
            // A certificate may change only after a root-signed v2 route that
            // names this relay and the new pin is already persisted.
            let routes = connection
                .prepare("SELECT route FROM routes")?
                .query_map([], |r| r.get::<_, Vec<u8>>(0))?
                .collect::<std::result::Result<Vec<_>, _>>()?;
            let identity = relay_identity(connection)?;
            let approved = routes
                .iter()
                .filter_map(|bytes| decode::<RoutingRecord>(bytes).ok())
                .any(|route| {
                    route.relay_identity == identity && route.tls_spki_fingerprint == spki
                });
            if !approved {
                bail!("relay TLS SPKI changed without a newer signed routing record")
            }
            connection.execute(
                "UPDATE relay_tls SET spki = ?1 WHERE id = 1",
                params![spki.to_vec()],
            )?;
        }
    }
    Ok(())
}
fn set_relay_address(connection: &Connection, address: &str) -> Result<()> {
    connection.execute("INSERT INTO relay_config (name, value) VALUES ('address', ?1) ON CONFLICT(name) DO UPDATE SET value = excluded.value", params![address.as_bytes()])?;
    Ok(())
}
fn relay_address(connection: &Connection) -> Result<String> {
    let bytes: Vec<u8> = connection
        .query_row(
            "SELECT value FROM relay_config WHERE name = 'address'",
            [],
            |r| r.get(0),
        )
        .context("relay network address is not initialized")?;
    String::from_utf8(bytes).map_err(Into::into)
}
fn relay_identity(connection: &Connection) -> Result<[u8; 32]> {
    let secret: Option<Vec<u8>> = connection
        .query_row("SELECT secret FROM relay_identity WHERE id = 1", [], |r| {
            r.get(0)
        })
        .optional()?;
    let key = match secret {
        Some(secret) => SigningKey::from_bytes(
            &secret
                .try_into()
                .map_err(|_| anyhow::anyhow!("invalid persisted relay identity"))?,
        ),
        None => {
            let key = SigningKey::generate(&mut OsRng);
            connection.execute(
                "INSERT INTO relay_identity (id, secret) VALUES (1, ?1)",
                params![key.to_bytes().to_vec()],
            )?;
            key
        }
    };
    Ok(key.verifying_key().to_bytes())
}
fn relay_signer(connection: &Connection) -> Result<SigningKey> {
    let _ = relay_identity(connection)?;
    let secret: Vec<u8> =
        connection.query_row("SELECT secret FROM relay_identity WHERE id = 1", [], |r| {
            r.get(0)
        })?;
    Ok(SigningKey::from_bytes(&secret.try_into().map_err(
        |_| anyhow::anyhow!("invalid persisted relay identity"),
    )?))
}
fn remove_completed_events(connection: &Connection) -> Result<()> {
    connection.execute("DELETE FROM event_deliveries WHERE event_id IN (SELECT e.id FROM mls_events e WHERE NOT EXISTS (SELECT 1 FROM event_deliveries d WHERE d.event_id = e.id AND d.acknowledged = 0))", [])?;
    connection.execute("DELETE FROM mls_events WHERE id IN (SELECT e.id FROM mls_events e WHERE NOT EXISTS (SELECT 1 FROM event_deliveries d WHERE d.event_id = e.id AND d.acknowledged = 0))", [])?;
    Ok(())
}
fn maintain_lifecycle(connection: &Connection, now: i64) -> Result<()> {
    let dormant_before = now.saturating_sub(DORMANCY_SECONDS);
    connection.execute(
        "UPDATE devices SET dormant = 1 WHERE revoked = 0 AND last_seen < ?1",
        params![dormant_before],
    )?;
    connection.execute("DELETE FROM event_deliveries WHERE acknowledged = 0 AND device_id IN (SELECT device_id FROM devices WHERE dormant = 1 OR revoked = 1)", [])?;
    remove_completed_events(connection)?;
    let expires_at = now.saturating_sub(RETENTION_SECONDS);
    connection.execute("DELETE FROM event_deliveries WHERE event_id IN (SELECT id FROM mls_events WHERE created_at <= ?1)", params![expires_at])?;
    connection.execute(
        "DELETE FROM mls_events WHERE created_at <= ?1",
        params![expires_at],
    )?;
    Ok(())
}
fn touch_device(connection: &Connection, device_id: [u8; 32], now: i64) -> Result<bool> {
    Ok(connection.execute(
        "UPDATE devices SET last_seen = ?1, dormant = 0 WHERE device_id = ?2 AND revoked = 0",
        params![now, device_id.to_vec()],
    )? != 0)
}
fn system_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}
fn process_at(connection: &Connection, request: Request, now: i64) -> Response {
    let result: Result<Response> = (|| {
        maintain_lifecycle(connection, now)?;
        match request {
            Request::Register { card, device, .. } => {
                verify_card(&card)?;
                verify_device(&device)?;
                if device.identity != identity_id(&card)
                    || !card
                        .devices
                        .iter()
                        .any(|candidate| candidate.device_id == device.device_id)
                {
                    bail!("registering device is not authorized by the contact card")
                }
                connection.execute(
                    "INSERT OR REPLACE INTO identities (id, card) VALUES (?1, ?2)",
                    params![identity_id(&card).to_vec(), encode(&card)?],
                )?;
                for authorized in &card.devices {
                    verify_device(authorized)?;
                    // A later registration may refresh an authorized device record, but
                    // can never resurrect a revoked credential.  Re-adding a physical
                    // device needs a new, explicitly root-authorized device credential.
                    connection.execute("INSERT INTO devices (device_id, identity_id, record, last_seen) VALUES (?1, ?2, ?3, ?4) ON CONFLICT(device_id) DO UPDATE SET record = excluded.record WHERE devices.revoked = 0 AND devices.identity_id = excluded.identity_id", params![authorized.device_id.to_vec(), identity_id(&card).to_vec(), encode(authorized)?, now])?;
                }
                if !touch_device(connection, device.device_id, now)? {
                    bail!("device is revoked")
                }
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
            Request::SendMls(mut record) => {
                maintain_lifecycle(connection, now)?;
                let _ = touch_device(connection, record.sender_device, now)?;
                let found: bool = connection.query_row(
                    "SELECT EXISTS(SELECT 1 FROM identities WHERE id = ?1)",
                    params![record.recipient_identity.to_vec()],
                    |r| r.get(0),
                )?;
                if !found {
                    bail!("recipient has not registered this server")
                }
                record.target_devices.retain(|device| connection.query_row("SELECT EXISTS(SELECT 1 FROM devices WHERE device_id = ?1 AND identity_id = ?2 AND revoked = 0 AND dormant = 0)", params![device.to_vec(), record.recipient_identity.to_vec()], |r| r.get::<_, bool>(0)).unwrap_or(false));
                if record.target_devices.is_empty() {
                    return Ok(Response::Ok);
                }
                let mut unique_targets = std::collections::HashSet::new();
                if !record
                    .target_devices
                    .iter()
                    .all(|device| unique_targets.insert(*device))
                {
                    bail!("MLS record has duplicate delivery targets")
                }
                let transaction = connection.unchecked_transaction()?;
                transaction.execute(
                    "INSERT INTO mls_events (record, created_at) VALUES (?1, ?2)",
                    params![encode(&record)?, now],
                )?;
                let event_id = transaction.last_insert_rowid();
                for device in &record.target_devices {
                    let authorized: bool = transaction.query_row("SELECT EXISTS(SELECT 1 FROM devices WHERE device_id = ?1 AND identity_id = ?2 AND revoked = 0 AND dormant = 0)", params![device.to_vec(), record.recipient_identity.to_vec()], |r| r.get(0))?;
                    if !authorized {
                        bail!("target device is not authorized for recipient identity")
                    }
                    transaction.execute(
                        "INSERT INTO event_deliveries (event_id, device_id) VALUES (?1, ?2)",
                        params![event_id, device.to_vec()],
                    )?;
                }
                transaction.commit()?;
                Ok(Response::Ok)
            }
            Request::Fetch {
                identity,
                device_id,
                known_routing_revision,
            } => {
                maintain_lifecycle(connection, now)?;
                let route = connection
                    .query_row(
                        "SELECT route FROM routes WHERE identity_id = ?1",
                        params![identity.to_vec()],
                        |r| r.get::<_, Vec<u8>>(0),
                    )
                    .optional()?;
                if let Some(route) = route {
                    let route: RoutingRecord = decode(&route)?;
                    if route.revision > known_routing_revision {
                        return Ok(Response::Moved(route));
                    }
                }
                let authorized: bool = connection.query_row("SELECT EXISTS(SELECT 1 FROM devices WHERE device_id = ?1 AND identity_id = ?2 AND revoked = 0)", params![device_id.to_vec(), identity.to_vec()], |r| r.get(0))?;
                if !authorized {
                    bail!("device is not authorized for identity")
                }
                touch_device(connection, device_id, now)?;
                let mut statement = connection
                .prepare("SELECT e.id, e.record FROM mls_events e JOIN event_deliveries d ON d.event_id=e.id WHERE d.device_id = ?1 AND d.acknowledged = 0 ORDER BY e.id")?;
                let records: Vec<(i64, Vec<u8>)> = statement
                    .query_map(params![device_id.to_vec()], |r| Ok((r.get(0)?, r.get(1)?)))?
                    .collect::<std::result::Result<_, _>>()?;
                let messages = records
                    .iter()
                    .map(|(id, value)| {
                        let record = pigeon_shared::decode(value)
                            .with_context(|| format!("decode MLS record {id}"))?;
                        Ok((*id, record))
                    })
                    .collect::<Result<Vec<_>>>()?;
                Ok(Response::MlsMessages(messages))
            }
            Request::Acknowledge {
                device_id,
                record_ids,
                ..
            } => {
                maintain_lifecycle(connection, now)?;
                let authorized: bool = connection.query_row(
                    "SELECT EXISTS(SELECT 1 FROM devices WHERE device_id = ?1 AND revoked = 0)",
                    params![device_id.to_vec()],
                    |r| r.get(0),
                )?;
                if !authorized {
                    bail!("device is not authorized")
                }
                touch_device(connection, device_id, now)?;
                for event_id in record_ids {
                    connection.execute("UPDATE event_deliveries SET acknowledged = 1 WHERE event_id = ?1 AND device_id = ?2", params![event_id, device_id.to_vec()])?;
                    let outstanding: bool = connection.query_row("SELECT EXISTS(SELECT 1 FROM event_deliveries WHERE event_id = ?1 AND acknowledged = 0)", params![event_id], |r| r.get(0))?;
                    if !outstanding {
                        connection.execute(
                            "DELETE FROM event_deliveries WHERE event_id = ?1",
                            params![event_id],
                        )?;
                        connection
                            .execute("DELETE FROM mls_events WHERE id = ?1", params![event_id])?;
                    }
                }
                Ok(Response::Ok)
            }
            Request::RevokeDevice(revocation) => {
                verify_revocation(&revocation)?;
                let transaction = connection.unchecked_transaction()?;
                let existing: Option<Vec<u8>> = transaction
                    .query_row(
                        "SELECT revocation FROM revocations WHERE device_id = ?1",
                        params![revocation.device_id.to_vec()],
                        |r| r.get(0),
                    )
                    .optional()?;
                if let Some(existing) = existing {
                    let existing: DeviceRevocation = decode(&existing)?;
                    if existing.identity == revocation.identity
                        && existing.revision == revocation.revision
                        && existing.signature == revocation.signature
                    {
                        return Ok(Response::Ok);
                    }
                    bail!("device has already been revoked")
                }
                let changed = transaction.execute("UPDATE devices SET revoked = 1 WHERE device_id = ?1 AND identity_id = ?2 AND revoked = 0", params![revocation.device_id.to_vec(), revocation.identity.to_vec()])?;
                if changed == 0 {
                    bail!("unknown device revocation")
                }
                transaction.execute(
                    "INSERT INTO revocations (device_id, revocation) VALUES (?1, ?2)",
                    params![revocation.device_id.to_vec(), encode(&revocation)?],
                )?;
                transaction.execute(
                    "DELETE FROM event_deliveries WHERE device_id = ?1 AND acknowledged = 0",
                    params![revocation.device_id.to_vec()],
                )?;
                transaction.execute("DELETE FROM event_deliveries WHERE event_id IN (SELECT e.id FROM mls_events e WHERE NOT EXISTS (SELECT 1 FROM event_deliveries d WHERE d.event_id = e.id AND d.acknowledged = 0))", [])?;
                transaction.execute("DELETE FROM mls_events WHERE id IN (SELECT e.id FROM mls_events e WHERE NOT EXISTS (SELECT 1 FROM event_deliveries d WHERE d.event_id = e.id AND d.acknowledged = 0))", [])?;
                transaction.commit()?;
                Ok(Response::Ok)
            }
            Request::GetRevocations { identity } => {
                let mut statement = connection.prepare("SELECT r.revocation FROM revocations r JOIN devices d ON d.device_id = r.device_id WHERE d.identity_id = ?1 ORDER BY r.rowid")?;
                let records = statement
                    .query_map(params![identity.to_vec()], |r| r.get::<_, Vec<u8>>(0))?
                    .collect::<std::result::Result<Vec<_>, _>>()?;
                Ok(Response::Revocations(
                    records
                        .iter()
                        .map(|record| decode(record))
                        .collect::<Result<_>>()?,
                ))
            }
            Request::PublishRouting(route) => {
                verify_routing(&route)?;
                // A relay may cache a self-authenticating route learned via a
                // contact path. The client still registers at a migration
                // destination before publication; this cache never grants the
                // relay authority to fabricate or rewrite routing metadata.
                let previous: Option<Vec<u8>> = connection
                    .query_row(
                        "SELECT route FROM routes WHERE identity_id = ?1",
                        params![route.identity.to_vec()],
                        |r| r.get(0),
                    )
                    .optional()?;
                let accept = match previous {
                    None => true,
                    Some(previous) => {
                        let previous: RoutingRecord = decode(&previous)?;
                        route.revision > previous.revision
                            || (route.revision == previous.revision
                                && route.parent_revision == previous.parent_revision
                                && routing_precedes(&route, &previous))
                    }
                };
                if !accept {
                    bail!("stale or losing routing revision")
                }
                connection.execute("INSERT INTO routes (identity_id, route) VALUES (?1, ?2) ON CONFLICT(identity_id) DO UPDATE SET route = excluded.route", params![route.identity.to_vec(), encode(&route)?])?;
                Ok(Response::Ok)
            }
            Request::GetRouting { identity } => {
                let route = connection
                    .query_row(
                        "SELECT route FROM routes WHERE identity_id = ?1",
                        params![identity.to_vec()],
                        |r| r.get::<_, Vec<u8>>(0),
                    )
                    .optional()?;
                Ok(Response::Routing(
                    route.map(|bytes| decode(&bytes)).transpose()?,
                ))
            }
            Request::GetRelayDescriptor => Ok(Response::RelayDescriptor(RelayDescriptor {
                identity: relay_identity(connection)?,
                tls_spki_fingerprint: relay_tls_spki(connection)?,
            })),
            Request::QueueForward { record, route } => {
                verify_routing(&route)?;
                if record.recipient_identity != route.identity {
                    bail!("forward route identity does not match recipient")
                }
                let forward = make_relay_forward(&relay_signer(connection)?, route, record);
                connection.execute(
                    "INSERT INTO outbound_forwards (forward) VALUES (?1)",
                    params![encode(&forward)?],
                )?;
                Ok(Response::Ok)
            }
            Request::ForwardMls(forward) => {
                verify_relay_forward(&forward)?;
                verify_routing(&forward.route)?;
                if forward.record.recipient_identity != forward.route.identity {
                    bail!("forward route identity does not match recipient")
                }
                if let Some(current) = connection
                    .query_row(
                        "SELECT route FROM routes WHERE identity_id = ?1",
                        params![forward.route.identity.to_vec()],
                        |r| r.get::<_, Vec<u8>>(0),
                    )
                    .optional()?
                {
                    let current: RoutingRecord = decode(&current)?;
                    if current.revision > forward.route.revision {
                        return Ok(Response::Moved(current));
                    }
                }
                if forward.route.relay_identity != relay_identity(connection)? {
                    bail!("routing record does not name this relay")
                }
                if forward.route.tls_spki_fingerprint != relay_tls_spki(connection)? {
                    bail!("routing record TLS SPKI pin does not name this relay")
                }
                if forward.route.server != relay_address(connection)? {
                    bail!("routing record address does not name this relay")
                }
                Ok(process_at(
                    connection,
                    Request::SendMls(forward.record),
                    now,
                ))
            }
        }
    })();
    result.unwrap_or_else(|error| Response::Error(format!("{error:#}")))
}
#[derive(Debug)]
struct SpkiVerifier([u8; 32]);
impl ServerCertVerifier for SpkiVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<ServerCertVerified, TlsError> {
        match tls_spki_fingerprint(end_entity.as_ref()) {
            Ok(actual) if actual == self.0 => Ok(ServerCertVerified::assertion()),
            Ok(_) => Err(TlsError::General(
                "relay TLS SPKI fingerprint mismatch".into(),
            )),
            Err(error) => Err(TlsError::General(format!(
                "invalid relay TLS certificate: {error}"
            ))),
        }
    }
    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
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
async fn relay_request(route: &RoutingRecord, value: Request) -> Result<Response> {
    verify_routing(route)?;
    let config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SpkiVerifier(route.tls_spki_fingerprint)))
        .with_no_client_auth();
    let stream = TcpStream::connect(&route.server).await?;
    let name = rustls::pki_types::ServerName::try_from("localhost")?.to_owned();
    let mut tls = TlsConnector::from(Arc::new(config))
        .connect(name, stream)
        .await?;
    write_frame(&mut tls, &encode(&value)?).await?;
    decode(&read_frame(&mut tls).await?)
}
async fn flush_network_outbound(database: Arc<Mutex<Connection>>) -> Result<()> {
    let candidate = {
        let connection = database
            .lock()
            .map_err(|_| anyhow::anyhow!("database lock poisoned"))?;
        connection
            .query_row(
                "SELECT id, forward FROM outbound_forwards ORDER BY id LIMIT 1",
                [],
                |r| Ok((r.get::<_, i64>(0)?, r.get::<_, Vec<u8>>(1)?)),
            )
            .optional()?
    };
    let Some((id, bytes)) = candidate else {
        return Ok(());
    };
    let mut forward = decode::<pigeon_shared::RelayForward>(&bytes)?;
    let response = relay_request(&forward.route, Request::ForwardMls(forward.clone())).await;
    let connection = database
        .lock()
        .map_err(|_| anyhow::anyhow!("database lock poisoned"))?;
    match response {
        Ok(Response::Ok) => {
            connection.execute("DELETE FROM outbound_forwards WHERE id = ?1", params![id])?;
        }
        Ok(Response::Moved(route)) => {
            verify_routing(&route)?;
            if route.identity != forward.record.recipient_identity {
                bail!("MOVED identity mismatch")
            }
            forward = make_relay_forward(&relay_signer(&connection)?, route, forward.record);
            connection.execute(
                "UPDATE outbound_forwards SET forward = ?1 WHERE id = ?2",
                params![encode(&forward)?, id],
            )?;
        }
        Ok(Response::Error(error)) => bail!("destination rejected forward: {error}"),
        Ok(_) => bail!("unexpected destination forwarding response"),
        Err(error) => return Err(error),
    }
    Ok(())
}
fn process(connection: &Connection, request: Request) -> Response {
    process_at(connection, request, system_now())
}
/// Deliver persisted opaque forwards to a reachable destination relay. The
/// production transport invokes the same `ForwardMls` request over TLS; this
/// helper keeps queue/retry semantics independently testable.
#[allow(dead_code)]
fn flush_outbound(sender: &Connection, destination: &Connection, now: i64) -> Result<()> {
    let rows = sender
        .prepare("SELECT id, forward FROM outbound_forwards ORDER BY id")?
        .query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, Vec<u8>>(1)?)))?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    for (id, bytes) in rows {
        let mut forward: pigeon_shared::RelayForward = decode(&bytes)?;
        match process_at(destination, Request::ForwardMls(forward.clone()), now) {
            Response::Ok => {
                sender.execute("DELETE FROM outbound_forwards WHERE id = ?1", params![id])?;
            }
            Response::Moved(route) => {
                verify_routing(&route)?;
                if route.identity != forward.record.recipient_identity {
                    bail!("MOVED identity mismatch")
                }
                forward = make_relay_forward(&relay_signer(sender)?, route, forward.record);
                sender.execute(
                    "UPDATE outbound_forwards SET forward = ?1 WHERE id = ?2",
                    params![encode(&forward)?, id],
                )?;
            }
            Response::Error(error) => bail!("destination rejected forward: {error}"),
            _ => bail!("unexpected destination forwarding response"),
        }
    }
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use pigeon_shared::{
        make_card, make_card_with_devices, make_device, make_relay_forward, make_revocation,
        make_routing, MlsRecord,
    };
    use rand_core::OsRng;
    use rcgen::generate_simple_self_signed;
    use x25519_dalek::StaticSecret;

    #[test]
    fn fetch_pairs_sql_id_with_decoded_mls_record() {
        let database = Connection::open_in_memory().unwrap();
        initialize(&database).unwrap();
        let root = SigningKey::generate(&mut OsRng);
        let device_key = SigningKey::generate(&mut OsRng);
        let encryption = StaticSecret::random_from_rng(OsRng);
        let device = make_device(&root, &device_key, vec![1, 2, 3]);
        let card = make_card(&root, &encryption, "server.test".into(), device.clone());
        assert!(matches!(
            process(
                &database,
                Request::Register {
                    card: card.clone(),
                    device,
                    device_signature: vec![]
                }
            ),
            Response::Ok
        ));
        let record = MlsRecord {
            recipient_identity: identity_id(&card),
            sender_device: [9; 32],
            target_devices: vec![device_key.verifying_key().to_bytes()],
            payload: vec![7, 8, 9],
        };
        assert!(matches!(
            process(&database, Request::SendMls(record.clone())),
            Response::Ok
        ));
        let Response::MlsMessages(records) = process(
            &database,
            Request::Fetch {
                identity: identity_id(&card),
                device_id: device_key.verifying_key().to_bytes(),
                known_routing_revision: 0,
            },
        ) else {
            panic!("expected MLS records")
        };
        assert_eq!(records.len(), 1);
        assert!(records[0].0 > 0);
        assert_eq!(records[0].1.payload, record.payload);
    }

    #[test]
    fn signed_revocation_removes_pending_delivery_and_survives_relay_restart() {
        let path =
            std::env::temp_dir().join(format!("pigeon-revocation-{}.sqlite", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let database = Connection::open(&path).unwrap();
        initialize(&database).unwrap();
        let root = SigningKey::generate(&mut OsRng);
        let a1 = SigningKey::generate(&mut OsRng);
        let a2 = SigningKey::generate(&mut OsRng);
        let encryption = StaticSecret::random_from_rng(OsRng);
        let a1_record = make_device(&root, &a1, vec![1]);
        let a2_record = make_device(&root, &a2, vec![2]);
        let card = make_card_with_devices(
            &root,
            &encryption,
            "server.test".into(),
            vec![a1_record.clone(), a2_record.clone()],
            2,
        );
        assert!(matches!(
            process(
                &database,
                Request::Register {
                    card: card.clone(),
                    device: a1_record.clone(),
                    device_signature: vec![]
                }
            ),
            Response::Ok
        ));
        let record = MlsRecord {
            recipient_identity: root.verifying_key().to_bytes(),
            sender_device: [7; 32],
            target_devices: vec![a1_record.device_id, a2_record.device_id],
            payload: vec![9],
        };
        assert!(matches!(
            process(&database, Request::SendMls(record)),
            Response::Ok
        ));
        let Response::MlsMessages(a1_events) = process(
            &database,
            Request::Fetch {
                identity: root.verifying_key().to_bytes(),
                device_id: a1_record.device_id,
                known_routing_revision: 0,
            },
        ) else {
            panic!("expected A1 event")
        };
        assert_eq!(a1_events.len(), 1);
        assert!(matches!(
            process(
                &database,
                Request::Acknowledge {
                    device_id: a1_record.device_id,
                    record_ids: vec![a1_events[0].0],
                    signature: vec![]
                }
            ),
            Response::Ok
        ));
        let revocation = make_revocation(&root, a2_record.device_id, 1);
        assert!(pigeon_shared::verify_revocation(&revocation).is_ok());
        assert!(matches!(
            process(&database, Request::RevokeDevice(revocation.clone())),
            Response::Ok
        ));
        assert!(matches!(
            process(
                &database,
                Request::SendMls(MlsRecord {
                    recipient_identity: root.verifying_key().to_bytes(),
                    sender_device: [8; 32],
                    target_devices: vec![a2_record.device_id],
                    payload: vec![10],
                })
            ),
            Response::Ok
        ));
        assert_eq!(
            database
                .query_row("SELECT COUNT(*) FROM mls_events", [], |r| r
                    .get::<_, i64>(0))
                .unwrap(),
            0
        );
        assert!(matches!(
            process(
                &database,
                Request::Fetch {
                    identity: root.verifying_key().to_bytes(),
                    device_id: a2_record.device_id,
                    known_routing_revision: 0,
                }
            ),
            Response::Error(_)
        ));
        drop(database);
        let database = Connection::open(&path).unwrap();
        let Response::Revocations(revocations) = process(
            &database,
            Request::GetRevocations {
                identity: root.verifying_key().to_bytes(),
            },
        ) else {
            panic!("expected revocation sync")
        };
        assert_eq!(revocations.len(), 1);
        assert_eq!(revocations[0].device_id, a2_record.device_id);
        // Reconnecting with the pre-revocation credential cannot clear revoked.
        assert!(matches!(
            process(
                &database,
                Request::Register {
                    card,
                    device: a2_record,
                    device_signature: vec![]
                }
            ),
            Response::Error(_)
        ));
        assert!(matches!(
            process(
                &database,
                Request::Fetch {
                    identity: root.verifying_key().to_bytes(),
                    device_id: a2.verifying_key().to_bytes(),
                    known_routing_revision: 0,
                }
            ),
            Response::Error(_)
        ));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn dormant_devices_stop_blocking_delivery_and_expiry_is_hard() {
        let path = std::env::temp_dir().join(format!(
            "pigeon-lifecycle-{}-{}.sqlite",
            std::process::id(),
            system_now()
        ));
        let _ = std::fs::remove_file(&path);
        let database = Connection::open(&path).unwrap();
        initialize(&database).unwrap();
        let start = 1_000_000_i64;
        let alice_root = SigningKey::generate(&mut OsRng);
        let bob_root = SigningKey::generate(&mut OsRng);
        let a1 = SigningKey::generate(&mut OsRng);
        let a2 = SigningKey::generate(&mut OsRng);
        let b1 = SigningKey::generate(&mut OsRng);
        let alice_encryption = StaticSecret::random_from_rng(OsRng);
        let bob_encryption = StaticSecret::random_from_rng(OsRng);
        let a1_record = make_device(&alice_root, &a1, vec![1]);
        let a2_record = make_device(&alice_root, &a2, vec![2]);
        let b1_record = make_device(&bob_root, &b1, vec![3]);
        let alice_card = make_card_with_devices(
            &alice_root,
            &alice_encryption,
            "server.test".into(),
            vec![a1_record.clone(), a2_record.clone()],
            1,
        );
        let bob_card = make_card(
            &bob_root,
            &bob_encryption,
            "server.test".into(),
            b1_record.clone(),
        );
        for (card, device) in [
            (alice_card.clone(), a1_record.clone()),
            (bob_card, b1_record.clone()),
        ] {
            assert!(matches!(
                process_at(
                    &database,
                    Request::Register {
                        card,
                        device,
                        device_signature: vec![]
                    },
                    start,
                ),
                Response::Ok
            ));
        }
        let just_before_dormancy = start + DORMANCY_SECONDS - 1;
        let send = |payload| {
            Request::SendMls(MlsRecord {
                recipient_identity: alice_root.verifying_key().to_bytes(),
                sender_device: b1_record.device_id,
                target_devices: vec![a1_record.device_id, a2_record.device_id],
                payload,
            })
        };
        assert!(matches!(
            process_at(&database, send(vec![1]), just_before_dormancy),
            Response::Ok
        ));
        let event_id: i64 = database
            .query_row("SELECT id FROM mls_events", [], |r| r.get(0))
            .unwrap();
        assert!(matches!(
            process_at(
                &database,
                Request::Acknowledge {
                    device_id: a1_record.device_id,
                    record_ids: vec![event_id],
                    signature: vec![]
                },
                just_before_dormancy,
            ),
            Response::Ok
        ));
        assert_eq!(
            database
                .query_row("SELECT COUNT(*) FROM mls_events", [], |r| r
                    .get::<_, i64>(0))
                .unwrap(),
            1
        );
        let dormant_at = start + DORMANCY_SECONDS + 1;
        // This ordinary interaction runs the server clock; A2 is now dormant,
        // while the event itself is only seconds old.
        assert!(matches!(
            process_at(
                &database,
                Request::GetRevocations {
                    identity: alice_root.verifying_key().to_bytes()
                },
                dormant_at,
            ),
            Response::Revocations(_)
        ));
        assert_eq!(
            database
                .query_row(
                    "SELECT dormant FROM devices WHERE device_id = ?1",
                    params![a2_record.device_id.to_vec()],
                    |r| r.get::<_, i64>(0)
                )
                .unwrap(),
            1
        );
        assert_eq!(
            database
                .query_row("SELECT COUNT(*) FROM mls_events", [], |r| r
                    .get::<_, i64>(0))
                .unwrap(),
            0
        );
        let dormant_send = process_at(&database, send(vec![2]), dormant_at);
        assert!(matches!(dormant_send, Response::Ok), "{dormant_send:?}");
        assert_eq!(
            database
                .query_row(
                    "SELECT COUNT(*) FROM event_deliveries WHERE device_id = ?1",
                    params![a2_record.device_id.to_vec()],
                    |r| r.get::<_, i64>(0)
                )
                .unwrap(),
            0
        );
        // A valid registration is activity, so a dormant (but authorized)
        // device automatically resumes without a new root authorization.
        assert!(matches!(
            process_at(
                &database,
                Request::Register {
                    card: alice_card.clone(),
                    device: a2_record.clone(),
                    device_signature: vec![]
                },
                dormant_at + 1,
            ),
            Response::Ok
        ));
        assert_eq!(
            database
                .query_row(
                    "SELECT dormant FROM devices WHERE device_id = ?1",
                    params![a2_record.device_id.to_vec()],
                    |r| r.get::<_, i64>(0)
                )
                .unwrap(),
            0
        );
        // Complete the A1-only event, then ensure a future event targets A2.
        let a1_only: i64 = database
            .query_row(
                "SELECT event_id FROM event_deliveries WHERE device_id = ?1",
                params![a1_record.device_id.to_vec()],
                |r| r.get(0),
            )
            .unwrap();
        assert!(matches!(
            process_at(
                &database,
                Request::Acknowledge {
                    device_id: a1_record.device_id,
                    record_ids: vec![a1_only],
                    signature: vec![]
                },
                dormant_at + 1
            ),
            Response::Ok
        ));
        assert!(matches!(
            process_at(&database, send(vec![3]), dormant_at + 1),
            Response::Ok
        ));
        assert_eq!(database.query_row("SELECT COUNT(*) FROM event_deliveries WHERE device_id = ?1 AND acknowledged = 0", params![a2_record.device_id.to_vec()], |r| r.get::<_, i64>(0)).unwrap(), 1);
        let unresponsive_event: i64 = database
            .query_row("SELECT MAX(id) FROM mls_events", [], |r| r.get(0))
            .unwrap();
        let revocation = make_revocation(&alice_root, a2_record.device_id, 9);
        assert!(matches!(
            process_at(&database, Request::RevokeDevice(revocation), dormant_at + 2),
            Response::Ok
        ));
        assert!(matches!(
            process_at(
                &database,
                Request::Register {
                    card: alice_card,
                    device: a2_record,
                    device_signature: vec![]
                },
                dormant_at + 3
            ),
            Response::Error(_)
        ));
        // The still-active A1 never ACKs this event.  Its content, unlike the
        // device/revocation control state, disappears at the hard retention bound.
        assert!(matches!(
            process_at(
                &database,
                Request::GetRevocations {
                    identity: alice_root.verifying_key().to_bytes()
                },
                dormant_at + 1 + RETENTION_SECONDS
            ),
            Response::Revocations(_)
        ));
        assert_eq!(
            database
                .query_row(
                    "SELECT COUNT(*) FROM mls_events WHERE id = ?1",
                    params![unresponsive_event],
                    |r| r.get::<_, i64>(0)
                )
                .unwrap(),
            0
        );
        drop(database);
        let database = Connection::open(&path).unwrap();
        assert_eq!(
            database
                .query_row("SELECT COUNT(*) FROM revocations", [], |r| r
                    .get::<_, i64>(0))
                .unwrap(),
            1
        );
        assert_eq!(
            database
                .query_row(
                    "SELECT dormant FROM devices WHERE device_id = ?1",
                    params![a1_record.device_id.to_vec()],
                    |r| r.get::<_, i64>(0)
                )
                .unwrap(),
            0
        );
        assert_eq!(
            database
                .query_row(
                    "SELECT last_seen FROM devices WHERE device_id = ?1",
                    params![a1_record.device_id.to_vec()],
                    |r| r.get::<_, i64>(0)
                )
                .unwrap(),
            dormant_at + 1
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn signed_routing_migration_moves_stale_devices_and_persists() {
        let old = Connection::open_in_memory().unwrap();
        let path = std::env::temp_dir().join(format!("pigeon-route-{}.sqlite", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let new = Connection::open(&path).unwrap();
        initialize(&old).unwrap();
        initialize(&new).unwrap();
        let root = SigningKey::generate(&mut OsRng);
        let a1 = SigningKey::generate(&mut OsRng);
        let a2 = SigningKey::generate(&mut OsRng);
        let encryption = StaticSecret::random_from_rng(OsRng);
        let a1_record = make_device(&root, &a1, vec![1]);
        let a2_record = make_device(&root, &a2, vec![2]);
        let old_card = make_card_with_devices(
            &root,
            &encryption,
            "old.test".into(),
            vec![a1_record.clone(), a2_record.clone()],
            1,
        );
        assert!(matches!(
            process(
                &old,
                Request::Register {
                    card: old_card.clone(),
                    device: a1_record.clone(),
                    device_signature: vec![]
                }
            ),
            Response::Ok
        ));
        let initial = make_routing(
            &root,
            "old.test".into(),
            relay_identity(&old).unwrap(),
            [1; 32],
            1,
            0,
        );
        assert!(matches!(
            process(&old, Request::PublishRouting(initial.clone())),
            Response::Ok
        ));
        let new_card = make_card_with_devices(
            &root,
            &encryption,
            "new.test".into(),
            vec![a1_record.clone(), a2_record.clone()],
            2,
        );
        // Destination registration precedes publication, preserving the
        // migration ordering even if the old relay becomes unreachable.
        assert!(matches!(
            process(
                &new,
                Request::Register {
                    card: new_card,
                    device: a1_record.clone(),
                    device_signature: vec![]
                }
            ),
            Response::Ok
        ));
        let moved = make_routing(
            &root,
            "new.test".into(),
            relay_identity(&new).unwrap(),
            [2; 32],
            2,
            1,
        );
        assert!(matches!(
            process(&new, Request::PublishRouting(moved.clone())),
            Response::Ok
        ));
        // Simulate an offline old relay: the destination retains the valid
        // route and can serve it when another reachable path learns it.
        assert!(
            matches!(process(&new, Request::GetRouting { identity: root.verifying_key().to_bytes() }), Response::Routing(Some(route)) if route == moved)
        );
        assert!(matches!(
            process(&old, Request::PublishRouting(moved.clone())),
            Response::Ok
        ));
        assert!(
            matches!(process(&old, Request::Fetch { identity: root.verifying_key().to_bytes(), device_id: a2_record.device_id, known_routing_revision: 1 }), Response::Moved(route) if route == moved)
        );
        assert_eq!(moved.identity, root.verifying_key().to_bytes());
        let mut forged = moved.clone();
        forged.server = "attacker.test".into();
        assert!(matches!(
            process(&old, Request::PublishRouting(forged)),
            Response::Error(_)
        ));
        let conflicting = make_routing(
            &root,
            "alternate.test".into(),
            relay_identity(&old).unwrap(),
            [1; 32],
            2,
            1,
        );
        assert!(matches!(
            process(&old, Request::PublishRouting(conflicting.clone())),
            Response::Ok | Response::Error(_)
        ));
        let Response::Routing(Some(chosen)) = process(
            &old,
            Request::GetRouting {
                identity: root.verifying_key().to_bytes(),
            },
        ) else {
            panic!("missing route")
        };
        assert_eq!(
            chosen,
            if routing_precedes(&conflicting, &moved) {
                conflicting
            } else {
                moved
            }
        );
        drop(new);
        let new = Connection::open(&path).unwrap();
        assert!(
            matches!(process(&new, Request::GetRouting { identity: root.verifying_key().to_bytes() }), Response::Routing(Some(route)) if route.revision == 2)
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn relay_identity_and_route_fingerprint_survive_restart() {
        let path =
            std::env::temp_dir().join(format!("pigeon-relay-id-{}.sqlite", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let database = Connection::open(&path).unwrap();
        initialize(&database).unwrap();
        let relay = relay_identity(&database).unwrap();
        drop(database);
        let database = Connection::open(&path).unwrap();
        initialize(&database).unwrap();
        assert_eq!(relay_identity(&database).unwrap(), relay);
        let root = SigningKey::generate(&mut OsRng);
        set_relay_address(&database, "relay.test").unwrap();
        bind_relay_tls_spki(&database, [1; 32]).unwrap();
        let route = make_routing(&root, "relay.test".into(), relay, [1; 32], 1, 0);
        pigeon_shared::verify_routing(&route).unwrap();
        let mut substituted = route.clone();
        substituted.relay_identity = [9; 32];
        assert!(pigeon_shared::verify_routing(&substituted).is_err());
        let mut wrong_tls = route.clone();
        wrong_tls.tls_spki_fingerprint = [9; 32];
        assert!(pigeon_shared::verify_routing(&wrong_tls).is_err());
        assert!(matches!(
            process(&database, Request::PublishRouting(route.clone())),
            Response::Ok
        ));
        // A relay cannot silently start with a replacement TLS key.
        assert!(bind_relay_tls_spki(&database, [2; 32]).is_err());
        let rotated = make_routing(&root, "relay.test".into(), relay, [2; 32], 2, 1);
        assert!(matches!(
            process(&database, Request::PublishRouting(rotated)),
            Response::Ok
        ));
        bind_relay_tls_spki(&database, [2; 32]).unwrap();
        assert_eq!(relay_tls_spki(&database).unwrap(), [2; 32]);
        assert!(serde_json::from_str::<RoutingRecord>(r#"{"identity":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"server":"legacy","revision":1,"parent_revision":0,"signature":[]}"#).is_err());
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn tls_pinning_rejects_a_relay_certificate_not_named_by_the_route() {
        let expected = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let impostor = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let expected_der = CertificateDer::from(expected.cert.der().to_vec());
        let impostor_der = CertificateDer::from(impostor.cert.der().to_vec());
        let verifier = SpkiVerifier(tls_spki_fingerprint(expected_der.as_ref()).unwrap());
        let name = rustls::pki_types::ServerName::try_from("localhost")
            .unwrap()
            .to_owned();
        let now = rustls::pki_types::UnixTime::since_unix_epoch(std::time::Duration::from_secs(1));
        assert!(verifier
            .verify_server_cert(&expected_der, &[], &name, &[], now)
            .is_ok());
        assert!(verifier
            .verify_server_cert(&impostor_der, &[], &name, &[], now)
            .is_err());
    }

    #[test]
    fn authenticated_opaque_forwarding_queues_retries_and_delivers() {
        let sender = Connection::open_in_memory().unwrap();
        let destination = Connection::open_in_memory().unwrap();
        initialize(&sender).unwrap();
        initialize(&destination).unwrap();
        bind_relay_tls_spki(&sender, [1; 32]).unwrap();
        bind_relay_tls_spki(&destination, [2; 32]).unwrap();
        set_relay_address(&sender, "relay-a").unwrap();
        set_relay_address(&destination, "relay-b").unwrap();
        let bob_root = SigningKey::generate(&mut OsRng);
        let bob_device_key = SigningKey::generate(&mut OsRng);
        let encryption = StaticSecret::random_from_rng(OsRng);
        let bob_device = make_device(&bob_root, &bob_device_key, vec![1]);
        let card = make_card(&bob_root, &encryption, "relay-b".into(), bob_device.clone());
        assert!(matches!(
            process(
                &destination,
                Request::Register {
                    card,
                    device: bob_device.clone(),
                    device_signature: vec![]
                }
            ),
            Response::Ok
        ));
        let route_b = make_routing(
            &bob_root,
            "relay-b".into(),
            relay_identity(&destination).unwrap(),
            [2; 32],
            1,
            0,
        );
        assert!(matches!(
            process(&destination, Request::PublishRouting(route_b.clone())),
            Response::Ok
        ));
        let record = MlsRecord {
            recipient_identity: bob_root.verifying_key().to_bytes(),
            sender_device: [7; 32],
            target_devices: vec![bob_device.device_id],
            payload: vec![8, 9],
        };
        assert!(matches!(
            process(
                &sender,
                Request::QueueForward {
                    record: record.clone(),
                    route: route_b.clone()
                }
            ),
            Response::Ok
        ));
        flush_outbound(&sender, &destination, system_now()).unwrap();
        assert_eq!(
            sender
                .query_row("SELECT COUNT(*) FROM outbound_forwards", [], |r| r
                    .get::<_, i64>(0))
                .unwrap(),
            0
        );
        let Response::MlsMessages(events) = process(
            &destination,
            Request::Fetch {
                identity: bob_root.verifying_key().to_bytes(),
                device_id: bob_device.device_id,
                known_routing_revision: 1,
            },
        ) else {
            panic!("expected forwarded opaque event")
        };
        assert_eq!(events[0].1.payload, record.payload);
        let mut forged = make_relay_forward(&relay_signer(&sender).unwrap(), route_b, record);
        forged.signature[0] ^= 1;
        assert!(matches!(
            process(&destination, Request::ForwardMls(forged)),
            Response::Error(_)
        ));
    }
}
