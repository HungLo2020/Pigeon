use super::*;
use sha2::Digest;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[path = "lifecycle.rs"]
mod lifecycle;
#[path = "relay.rs"]
mod relay;
#[path = "schema.rs"]
mod schema;
pub(crate) use lifecycle::maintain_lifecycle;
pub(crate) use lifecycle::system_now;
use lifecycle::{remove_completed_attachments, touch_device};
pub(crate) use relay::{bind_relay_tls_spki, set_relay_address};
use relay::{relay_address, relay_identity, relay_signer, relay_tls_spki};
pub(crate) use schema::initialize;

type PairingRequestRow = (i64, Vec<u8>, Vec<u8>, Vec<u8>);
type PairingBootstrapRow = (i64, i64, i64, Vec<u8>, Vec<u8>);

fn genesis_key(genesis: &pigeon_shared::PigeonAccountGenesis) -> Result<Vec<u8>> {
    canonical_genesis_key(genesis)
}

fn account_key(account: &pigeon_shared::AccountIdentity) -> Result<Vec<u8>> {
    pigeon_shared::verify_account_identity(account)?;
    genesis_key(&account.genesis)
}

pub(crate) fn descriptor(connection: &Connection) -> Result<RelayDescriptor> {
    Ok(RelayDescriptor {
        version: pigeon_shared::RELAY_DESCRIPTOR_VERSION,
        address: relay_address(connection)?,
        identity: relay_identity(connection)?,
        tls_spki_fingerprint: relay_tls_spki(connection)?,
    })
}

fn decode_indexed_pairing_artifact(
    bytes: &[u8],
    account: &pigeon_shared::AccountIdentity,
    session_id: [u8; 16],
    nonce: &[u8],
    kind: PairingArtifactKind,
    expiry: i64,
    commitment: &[u8],
) -> Result<pigeon_shared::PairingRelayArtifact> {
    let artifact: pigeon_shared::PairingRelayArtifact = decode(bytes)?;
    if artifact.identity != account.compact_id
        || artifact.genesis != account.genesis
        || artifact.session_id != session_id
        || artifact.nonce.as_slice() != nonce
        || artifact.kind != kind
        || artifact.expires_at != expiry
        || artifact.capability_commitment.as_slice() != commitment
    {
        bail!("stored pairing envelope does not match its indexed session metadata")
    }
    Ok(artifact)
}

fn process_at(connection: &Connection, request: Request, now: i64) -> Response {
    let result: Result<Response> = (|| {
        maintain_lifecycle(connection, now)?;
        match request {
            Request::Register { card, device, .. } => {
                verify_card(&card)?;
                let registered_device = card.devices.iter().find(|candidate| {
                    candidate.device_id == device.device_id
                        && candidate.device_key == device.device_key
                });
                if registered_device.is_none() {
                    bail!("registering device is not authorized by the contact card")
                }
                let device = registered_device.expect("checked card membership").clone();
                verify_device_with_genesis(&device, &card.genesis)?;
                let genesis = genesis_key(&card.genesis)?;
                let compact_id = identity_id(&card);
                let existing: Option<Vec<u8>> = connection
                    .query_row(
                        "SELECT card FROM identities_v2 WHERE genesis = ?1",
                        params![genesis.clone()],
                        |r| r.get(0),
                    )
                    .optional()?;
                if let Some(existing) = existing {
                    let existing: pigeon_shared::ContactCard = decode(&existing)?;
                    verify_card(&existing)?;
                    if existing.genesis != card.genesis {
                        bail!("conflicting immutable account genesis for registered identity")
                    }
                    if card.revision < existing.revision {
                        bail!("stale signed account profile registration")
                    }
                    if card.revision == existing.revision && encode(&card)? != encode(&existing)? {
                        bail!("conflicting signed account profile at the same revision")
                    }
                    if card.authorized_devices.revision > existing.authorized_devices.revision {
                        verify_roster_transition(
                            &existing.authorized_devices,
                            &card.authorized_devices,
                        )?;
                    } else if card.authorized_devices.revision
                        < existing.authorized_devices.revision
                    {
                        bail!("stale account roster registration")
                    } else if roster_hash(&card.authorized_devices)
                        != roster_hash(&existing.authorized_devices)
                    {
                        bail!("conflicting account roster at the same revision")
                    }
                }
                connection.execute(
                    "INSERT OR REPLACE INTO identities_v2 (genesis, compact_id, card) VALUES (?1, ?2, ?3)",
                    params![genesis.clone(), compact_id.to_vec(), encode(&card)?],
                )?;
                for authorized in &card.devices {
                    verify_device_with_genesis(authorized, &card.genesis)?;
                    // A later registration may refresh an authorized device record, but
                    // can never resurrect a revoked credential.  Re-adding a physical
                    // device needs a new, explicitly root-authorized device credential.
                    connection.execute("INSERT INTO devices_v2 (genesis, device_id, record, last_seen) VALUES (?1, ?2, ?3, ?4) ON CONFLICT(genesis, device_id) DO UPDATE SET record = excluded.record WHERE devices_v2.revoked = 0", params![genesis.clone(), authorized.device_id.to_vec(), encode(authorized)?, now])?;
                }
                if !touch_device(connection, &genesis, device.device_id, now)? {
                    bail!("device is revoked")
                }
                Ok(Response::Ok)
            }
            Request::PublishKeyPackage {
                account,
                key_package,
            } => {
                let genesis = account_key(&account)?;
                let found: bool = connection.query_row(
                    "SELECT EXISTS(SELECT 1 FROM identities_v2 WHERE genesis = ?1)",
                    params![genesis.clone()],
                    |r| r.get(0),
                )?;
                if !found {
                    bail!("identity has not registered this server")
                }
                connection.execute(
                    "INSERT OR REPLACE INTO key_packages_v2 (genesis, compact_id, key_package) VALUES (?1, ?2, ?3)",
                    params![genesis, account.compact_id.to_vec(), key_package],
                )?;
                Ok(Response::Ok)
            }
            Request::GetKeyPackage { account } => {
                let genesis = account_key(&account)?;
                let package = connection
                    .query_row(
                        "SELECT key_package FROM key_packages_v2 WHERE genesis = ?1",
                        params![genesis],
                        |r| r.get(0),
                    )
                    .optional()?;
                Ok(Response::KeyPackage(package))
            }
            Request::SendMls(mut record) => {
                maintain_lifecycle(connection, now)?;
                let sender_genesis = account_key(&record.sender)?;
                // The recipient relay usually does not host the sender
                // account; authenticated relay forwarding is the authority in
                // that case. If it does host the sender, scope lifecycle
                // activity to that exact canonical account, never merely a
                // colliding device or compact identity ID.
                let sender_registered: bool = connection.query_row(
                    "SELECT EXISTS(SELECT 1 FROM devices_v2 WHERE genesis = ?1 AND device_id = ?2 AND revoked = 0)",
                    params![sender_genesis.clone(), record.sender_device.to_vec()],
                    |row| row.get(0),
                )?;
                if sender_registered
                    && !touch_device(connection, &sender_genesis, record.sender_device, now)?
                {
                    bail!("sender device is not authorized for the canonical sender account")
                }
                let recipient_genesis = account_key(&record.recipient)?;
                let found: bool = connection.query_row(
                    "SELECT EXISTS(SELECT 1 FROM identities_v2 WHERE genesis = ?1)",
                    params![recipient_genesis.clone()],
                    |r| r.get(0),
                )?;
                if !found {
                    bail!("recipient has not registered this server")
                }
                record.target_devices.retain(|device| connection.query_row("SELECT EXISTS(SELECT 1 FROM devices_v2 WHERE device_id = ?1 AND genesis = ?2 AND revoked = 0 AND dormant = 0)", params![device.to_vec(), recipient_genesis.clone()], |r| r.get::<_, bool>(0)).unwrap_or(false));
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
                    "INSERT INTO mls_events_v2 (recipient_genesis, record, created_at) VALUES (?1, ?2, ?3)",
                    params![recipient_genesis.clone(), encode(&record)?, now],
                )?;
                let event_id = transaction.last_insert_rowid();
                for device in &record.target_devices {
                    let authorized: bool = transaction.query_row("SELECT EXISTS(SELECT 1 FROM devices_v2 WHERE device_id = ?1 AND genesis = ?2 AND revoked = 0 AND dormant = 0)", params![device.to_vec(), recipient_genesis.clone()], |r| r.get(0))?;
                    if !authorized {
                        bail!("target device is not authorized for recipient identity")
                    }
                    transaction.execute(
                        "INSERT INTO event_deliveries_v2 (event_id, recipient_genesis, device_id) VALUES (?1, ?2, ?3)",
                        params![event_id, recipient_genesis.clone(), device.to_vec()],
                    )?;
                }
                transaction.commit()?;
                Ok(Response::Ok)
            }
            Request::SendAttachment(mut record) => {
                if record.version != pigeon_shared::ATTACHMENT_VERSION
                    || record.attachment_id == [0; 32]
                    || record.conversation_id.is_empty()
                    || record.ciphertext.is_empty()
                    || record.ciphertext_hash
                        != <[u8; 32]>::from(sha2::Sha256::digest(&record.ciphertext))
                {
                    bail!("malformed opaque attachment record")
                }
                let sender_genesis = account_key(&record.sender)?;
                let sender_registered: bool = connection.query_row(
                    "SELECT EXISTS(SELECT 1 FROM devices_v2 WHERE genesis = ?1 AND device_id = ?2 AND revoked = 0)",
                    params![sender_genesis.clone(), record.sender_device.to_vec()],
                    |row| row.get(0),
                )?;
                if sender_registered
                    && !touch_device(connection, &sender_genesis, record.sender_device, now)?
                {
                    bail!("attachment sender device is not authorized")
                }
                let recipient_genesis = account_key(&record.recipient)?;
                let found: bool = connection.query_row(
                    "SELECT EXISTS(SELECT 1 FROM identities_v2 WHERE genesis = ?1)",
                    params![recipient_genesis.clone()],
                    |row| row.get(0),
                )?;
                if !found {
                    bail!("attachment recipient has not registered this server")
                }
                record.target_devices.retain(|device| connection.query_row(
                    "SELECT EXISTS(SELECT 1 FROM devices_v2 WHERE device_id = ?1 AND genesis = ?2 AND revoked = 0 AND dormant = 0)",
                    params![device.to_vec(), recipient_genesis.clone()],
                    |row| row.get::<_, bool>(0),
                ).unwrap_or(false));
                if record.target_devices.is_empty() {
                    return Ok(Response::Ok);
                }
                let mut targets = std::collections::HashSet::new();
                if !record
                    .target_devices
                    .iter()
                    .all(|device| targets.insert(*device))
                {
                    bail!("attachment record has duplicate delivery targets")
                }
                let transaction = connection.unchecked_transaction()?;
                let existing: Option<Vec<u8>> = transaction.query_row(
                    "SELECT record FROM attachments_v1 WHERE recipient_genesis=?1 AND attachment_id=?2",
                    params![recipient_genesis.clone(), record.attachment_id.to_vec()],
                    |row| row.get(0),
                ).optional()?;
                if let Some(existing) = existing {
                    if existing != encode(&record)? {
                        bail!("attachment id already exists with different ciphertext")
                    }
                    return Ok(Response::Ok);
                }
                transaction.execute(
                    "INSERT INTO attachments_v1 (recipient_genesis, attachment_id, record, created_at) VALUES (?1, ?2, ?3, ?4)",
                    params![recipient_genesis.clone(), record.attachment_id.to_vec(), encode(&record)?, now],
                )?;
                for device in &record.target_devices {
                    transaction.execute(
                        "INSERT INTO attachment_deliveries_v1 (recipient_genesis, attachment_id, device_id) VALUES (?1, ?2, ?3)",
                        params![recipient_genesis.clone(), record.attachment_id.to_vec(), device.to_vec()],
                    )?;
                }
                transaction.commit()?;
                Ok(Response::Ok)
            }
            Request::FetchAttachment {
                account,
                device_id,
                attachment_id,
            } => {
                let genesis = account_key(&account)?;
                let authorized: bool = connection.query_row(
                    "SELECT EXISTS(SELECT 1 FROM devices_v2 WHERE genesis=?1 AND device_id=?2 AND revoked=0)",
                    params![genesis.clone(), device_id.to_vec()],
                    |row| row.get(0),
                )?;
                if !authorized {
                    bail!("device is not authorized for attachment delivery")
                }
                touch_device(connection, &genesis, device_id, now)?;
                let bytes: Option<Vec<u8>> = connection.query_row(
                    "SELECT a.record FROM attachments_v1 a JOIN attachment_deliveries_v1 d ON d.recipient_genesis=a.recipient_genesis AND d.attachment_id=a.attachment_id WHERE a.recipient_genesis=?1 AND a.attachment_id=?2 AND d.device_id=?3 AND d.acknowledged=0",
                    params![genesis, attachment_id.to_vec(), device_id.to_vec()],
                    |row| row.get(0),
                ).optional()?;
                Ok(Response::Attachment(Box::new(
                    bytes.map(|bytes| decode(&bytes)).transpose()?,
                )))
            }
            Request::AcknowledgeAttachment {
                account,
                device_id,
                attachment_id,
            } => {
                let genesis = account_key(&account)?;
                let authorized: bool = connection.query_row(
                    "SELECT EXISTS(SELECT 1 FROM devices_v2 WHERE genesis=?1 AND device_id=?2 AND revoked=0)",
                    params![genesis.clone(), device_id.to_vec()],
                    |row| row.get(0),
                )?;
                if !authorized {
                    bail!("device is not authorized for attachment acknowledgement")
                }
                touch_device(connection, &genesis, device_id, now)?;
                connection.execute(
                    "UPDATE attachment_deliveries_v1 SET acknowledged=1 WHERE recipient_genesis=?1 AND attachment_id=?2 AND device_id=?3",
                    params![genesis, attachment_id.to_vec(), device_id.to_vec()],
                )?;
                remove_completed_attachments(connection)?;
                Ok(Response::Ok)
            }
            Request::Fetch {
                account,
                device_id,
                known_routing_revision,
            } => {
                maintain_lifecycle(connection, now)?;
                let genesis = account_key(&account)?;
                let route = connection
                    .query_row(
                        "SELECT route FROM routes_v2 WHERE genesis = ?1",
                        params![genesis.clone()],
                        |r| r.get::<_, Vec<u8>>(0),
                    )
                    .optional()?;
                if let Some(route) = route {
                    let route: RoutingRecord = decode(&route)?;
                    if route.revision > known_routing_revision {
                        return Ok(Response::Moved(route));
                    }
                }
                let authorized: bool = connection.query_row("SELECT EXISTS(SELECT 1 FROM devices_v2 WHERE device_id = ?1 AND genesis = ?2 AND revoked = 0)", params![device_id.to_vec(), genesis.clone()], |r| r.get(0))?;
                if !authorized {
                    bail!("device is not authorized for identity")
                }
                touch_device(connection, &genesis, device_id, now)?;
                let mut statement = connection
                .prepare("SELECT e.id, e.record FROM mls_events_v2 e JOIN event_deliveries_v2 d ON d.event_id=e.id AND d.recipient_genesis=e.recipient_genesis WHERE d.device_id = ?1 AND d.recipient_genesis = ?2 AND d.acknowledged = 0 ORDER BY e.id")?;
                let records: Vec<(i64, Vec<u8>)> = statement
                    .query_map(params![device_id.to_vec(), genesis], |r| {
                        Ok((r.get(0)?, r.get(1)?))
                    })?
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
                account,
                device_id,
                record_ids,
                ..
            } => {
                maintain_lifecycle(connection, now)?;
                let genesis = account_key(&account)?;
                let authorized: bool = connection.query_row(
                    "SELECT EXISTS(SELECT 1 FROM devices_v2 WHERE genesis = ?1 AND device_id = ?2 AND revoked = 0)",
                    params![genesis.clone(), device_id.to_vec()],
                    |r| r.get(0),
                )?;
                if !authorized {
                    bail!("device is not authorized")
                }
                touch_device(connection, &genesis, device_id, now)?;
                for event_id in record_ids {
                    connection.execute("UPDATE event_deliveries_v2 SET acknowledged = 1 WHERE event_id = ?1 AND recipient_genesis = ?2 AND device_id = ?3", params![event_id, genesis.clone(), device_id.to_vec()])?;
                    let outstanding: bool = connection.query_row("SELECT EXISTS(SELECT 1 FROM event_deliveries_v2 WHERE event_id = ?1 AND acknowledged = 0)", params![event_id], |r| r.get(0))?;
                    if !outstanding {
                        connection.execute(
                            "DELETE FROM event_deliveries_v2 WHERE event_id = ?1",
                            params![event_id],
                        )?;
                        connection.execute(
                            "DELETE FROM mls_events_v2 WHERE id = ?1",
                            params![event_id],
                        )?;
                    }
                }
                Ok(Response::Ok)
            }
            Request::RevokeDevice(revocation) => {
                verify_revocation(&revocation)?;
                let transaction = connection.unchecked_transaction()?;
                let existing: Option<Vec<u8>> = transaction
                    .query_row(
                        "SELECT revocation FROM revocations_v2 WHERE genesis = ?1 AND device_id = ?2",
                        params![genesis_key(&revocation.genesis)?, revocation.device_id.to_vec()],
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
                let genesis = genesis_key(&revocation.genesis)?;
                let changed = transaction.execute("UPDATE devices_v2 SET revoked = 1 WHERE device_id = ?1 AND genesis = ?2 AND revoked = 0", params![revocation.device_id.to_vec(), genesis.clone()])?;
                if changed == 0 {
                    bail!("unknown device revocation")
                }
                transaction.execute(
                    "INSERT INTO revocations_v2 (genesis, device_id, revocation) VALUES (?1, ?2, ?3)",
                    params![genesis.clone(), revocation.device_id.to_vec(), encode(&revocation)?],
                )?;
                transaction.execute(
                    "DELETE FROM event_deliveries_v2 WHERE recipient_genesis = ?1 AND device_id = ?2 AND acknowledged = 0",
                    params![genesis.clone(), revocation.device_id.to_vec()],
                )?;
                transaction.execute("DELETE FROM event_deliveries_v2 WHERE event_id IN (SELECT e.id FROM mls_events_v2 e WHERE NOT EXISTS (SELECT 1 FROM event_deliveries_v2 d WHERE d.event_id = e.id AND d.acknowledged = 0))", [])?;
                transaction.execute("DELETE FROM mls_events_v2 WHERE id IN (SELECT e.id FROM mls_events_v2 e WHERE NOT EXISTS (SELECT 1 FROM event_deliveries_v2 d WHERE d.event_id = e.id AND d.acknowledged = 0))", [])?;
                transaction.commit()?;
                Ok(Response::Ok)
            }
            Request::GetRevocations { account } => {
                let genesis = account_key(&account)?;
                let mut statement = connection.prepare(
                    "SELECT revocation FROM revocations_v2 WHERE genesis = ?1 ORDER BY rowid",
                )?;
                let records = statement
                    .query_map(params![genesis], |r| r.get::<_, Vec<u8>>(0))?
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
                let genesis = genesis_key(&route.genesis)?;
                let registered: Option<Vec<u8>> = connection
                    .query_row(
                        "SELECT card FROM identities_v2 WHERE genesis = ?1",
                        params![genesis.clone()],
                        |r| r.get(0),
                    )
                    .optional()?;
                if let Some(card) = registered {
                    let card: pigeon_shared::ContactCard = decode(&card)?;
                    if card.genesis != route.genesis {
                        bail!("routing record genesis does not match registered account")
                    }
                }
                // A relay may cache a self-authenticating route learned via a
                // contact path. The client still registers at a migration
                // destination before publication; this cache never grants the
                // relay authority to fabricate or rewrite routing metadata.
                let previous: Option<Vec<u8>> = connection
                    .query_row(
                        "SELECT route FROM routes_v2 WHERE genesis = ?1",
                        params![genesis.clone()],
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
                connection.execute("INSERT INTO routes_v2 (genesis, compact_id, route) VALUES (?1, ?2, ?3) ON CONFLICT(genesis) DO UPDATE SET route = excluded.route", params![genesis, route.identity.to_vec(), encode(&route)?])?;
                Ok(Response::Ok)
            }
            Request::GetRouting { account } => {
                let genesis = account_key(&account)?;
                let route = connection
                    .query_row(
                        "SELECT route FROM routes_v2 WHERE genesis = ?1",
                        params![genesis],
                        |r| r.get::<_, Vec<u8>>(0),
                    )
                    .optional()?;
                Ok(Response::Routing(
                    route.map(|bytes| decode(&bytes)).transpose()?,
                ))
            }
            Request::GetRelayDescriptor => Ok(Response::RelayDescriptor(descriptor(connection)?)),
            Request::PublishPairingArtifact(artifact) => {
                pigeon_shared::verify_pairing_artifact(&artifact, now)?;
                let genesis = genesis_key(&artifact.genesis)?;
                let kind = encode(&artifact.kind)?;
                let session_nonce: Option<Vec<u8>> = connection
                    .query_row(
                        "SELECT nonce FROM pairing_artifacts_v2 WHERE genesis=?1 AND session=?2 LIMIT 1",
                        params![genesis.clone(), artifact.session_id.to_vec()],
                        |r| r.get(0),
                    )
                    .optional()?;
                match session_nonce {
                    Some(nonce) if nonce != artifact.nonce => {
                        bail!("pairing session nonce conflict")
                    }
                    None if artifact.kind != PairingArtifactKind::PublicRequest => {
                        bail!("pairing request must be published before protected artifacts")
                    }
                    _ => {}
                }
                let existing: Option<(Vec<u8>, Vec<u8>)> = connection.query_row("SELECT nonce, commitment FROM pairing_artifacts_v2 WHERE genesis=?1 AND session=?2 AND kind=?3", params![genesis.clone(), artifact.session_id.to_vec(), kind.clone()], |r| Ok((r.get(0)?, r.get(1)?))).optional()?;
                if let Some((nonce, commitment)) = existing {
                    if nonce != artifact.nonce
                        || commitment != artifact.capability_commitment.to_vec()
                    {
                        bail!("pairing session binding conflict")
                    }
                    bail!("pairing artifact already published")
                }
                // The envelope is the opaque relay artifact.  Metadata is indexed separately
                // only to enforce lifecycle and capability checks; fetches must reconstruct the
                // exact envelope the publisher supplied.
                let encoded_artifact = encode(&artifact)?;
                connection.execute("INSERT INTO pairing_artifacts_v2 (genesis,compact_id,session,nonce,kind,expiry,commitment,payload) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)", params![genesis,artifact.identity.to_vec(),artifact.session_id.to_vec(),artifact.nonce.to_vec(),kind,artifact.expires_at,artifact.capability_commitment.to_vec(),encoded_artifact])?;
                Ok(Response::Ok)
            }
            Request::FetchPairingRequest {
                account,
                session_id,
            } => {
                let genesis = account_key(&account)?;
                let kind = encode(&PairingArtifactKind::PublicRequest)?;
                let row: Option<PairingRequestRow> = connection.query_row("SELECT expiry,payload,commitment,nonce FROM pairing_artifacts_v2 WHERE genesis=?1 AND session=?2 AND kind=?3 AND cancelled=0",params![genesis,session_id.to_vec(),kind],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).optional()?;
                match row {
                    Some((expiry, _, _, _)) if expiry <= now => Ok(Response::PairingExpired),
                    Some((expiry, bytes, commitment, nonce)) => {
                        Ok(Response::PairingArtifact(decode_indexed_pairing_artifact(
                            &bytes,
                            &account,
                            session_id,
                            &nonce,
                            PairingArtifactKind::PublicRequest,
                            expiry,
                            &commitment,
                        )?))
                    }
                    None => Ok(Response::PairingNotFound),
                }
            }
            Request::FetchConsumePairingBootstrap {
                account,
                session_id,
                capability,
            } => {
                let genesis = account_key(&account)?;
                let kind = encode(&PairingArtifactKind::EncryptedBootstrap)?;
                let commitment = pigeon_shared::capability_commitment(&capability).to_vec();
                let tx = connection.unchecked_transaction()?;
                let row:Option<PairingBootstrapRow>=tx.query_row("SELECT expiry,cancelled,consumed,payload,nonce FROM pairing_artifacts_v2 WHERE genesis=?1 AND session=?2 AND kind=?3 AND commitment=?4",params![genesis.clone(),session_id.to_vec(),kind,commitment.clone()],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?))).optional()?;
                let response = match row {
                    None => Response::PairingUnauthorized,
                    Some((expiry, _, _, _, _)) if expiry <= now => Response::PairingExpired,
                    Some((_, 1, _, _, _)) => Response::PairingCancelled,
                    Some((_, _, 1, _, _)) => Response::PairingConsumed,
                    Some((expiry, _, _, bytes, nonce)) => {
                        let artifact = decode_indexed_pairing_artifact(
                            &bytes,
                            &account,
                            session_id,
                            &nonce,
                            PairingArtifactKind::EncryptedBootstrap,
                            expiry,
                            &commitment,
                        )?;
                        tx.execute("UPDATE pairing_artifacts_v2 SET consumed=1 WHERE genesis=?1 AND session=?2 AND kind=?3 AND commitment=?4",params![genesis,session_id.to_vec(),kind, commitment])?;
                        Response::PairingArtifact(artifact)
                    }
                };
                tx.commit()?;
                Ok(response)
            }
            Request::CancelPairing {
                account,
                session_id,
                capability,
            } => {
                let genesis = account_key(&account)?;
                let commitment = pigeon_shared::capability_commitment(&capability).to_vec();
                // Cancellation is authorized by the commitment published on
                // the public request. Once proved, it cancels every opaque
                // artifact in that session without revealing any of them.
                let request_kind = encode(&PairingArtifactKind::PublicRequest)?;
                let authorized: bool = connection.query_row("SELECT EXISTS(SELECT 1 FROM pairing_artifacts_v2 WHERE genesis=?1 AND session=?2 AND kind=?3 AND commitment=?4 AND consumed=0)", params![genesis.clone(),session_id.to_vec(),request_kind,commitment], |r| r.get(0))?;
                let changed = if authorized {
                    connection.execute("UPDATE pairing_artifacts_v2 SET cancelled=1 WHERE genesis=?1 AND session=?2 AND consumed=0",params![genesis,session_id.to_vec()])?
                } else {
                    0
                };
                Ok(if changed == 0 {
                    Response::PairingUnauthorized
                } else {
                    Response::PairingCancelled
                })
            }
            Request::QueueForward { record, route } => {
                verify_routing(&route)?;
                if record.recipient.compact_id != route.identity
                    || record.recipient.genesis != route.genesis
                {
                    bail!("forward route identity does not match recipient")
                }
                let forward = make_relay_forward(&relay_signer(connection)?, route, record);
                connection.execute(
                    "INSERT INTO outbound_forwards (forward) VALUES (?1)",
                    params![encode(&forward)?],
                )?;
                Ok(Response::Ok)
            }
            Request::QueueForwardAttachment { record, route } => {
                verify_routing(&route)?;
                if record.recipient.compact_id != route.identity
                    || record.recipient.genesis != route.genesis
                {
                    bail!("attachment forward route identity does not match recipient")
                }
                let forward = pigeon_shared::make_relay_attachment_forward(
                    &relay_signer(connection)?,
                    route,
                    record,
                );
                connection.execute(
                    "INSERT INTO outbound_attachment_forwards (forward) VALUES (?1)",
                    params![encode(&forward)?],
                )?;
                Ok(Response::Ok)
            }
            Request::ForwardMls(forward) => {
                verify_relay_forward(&forward)?;
                verify_routing(&forward.route)?;
                if forward.record.recipient.compact_id != forward.route.identity
                    || forward.record.recipient.genesis != forward.route.genesis
                {
                    bail!("forward route identity does not match recipient")
                }
                if let Some(current) = connection
                    .query_row(
                        "SELECT route FROM routes_v2 WHERE genesis = ?1",
                        params![genesis_key(&forward.route.genesis)?],
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
            Request::ForwardAttachment(forward) => {
                pigeon_shared::verify_relay_attachment_forward(&forward)?;
                verify_routing(&forward.route)?;
                if forward.record.recipient.compact_id != forward.route.identity
                    || forward.record.recipient.genesis != forward.route.genesis
                {
                    bail!("attachment forward route identity does not match recipient")
                }
                if let Some(current) = connection
                    .query_row(
                        "SELECT route FROM routes_v2 WHERE genesis = ?1",
                        params![genesis_key(&forward.route.genesis)?],
                        |r| r.get::<_, Vec<u8>>(0),
                    )
                    .optional()?
                {
                    let current: RoutingRecord = decode(&current)?;
                    if current.revision > forward.route.revision {
                        return Ok(Response::Moved(current));
                    }
                }
                if forward.route.relay_identity != relay_identity(connection)?
                    || forward.route.tls_spki_fingerprint != relay_tls_spki(connection)?
                    || forward.route.server != relay_address(connection)?
                {
                    bail!("attachment route does not name this relay")
                }
                Ok(process_at(
                    connection,
                    Request::SendAttachment(forward.record),
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
pub(super) async fn flush_network_outbound(database: Arc<Mutex<Connection>>) -> Result<()> {
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
            if route.identity != forward.record.recipient.compact_id
                || route.genesis != forward.record.recipient.genesis
            {
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

pub(super) async fn flush_network_attachment_outbound(
    database: Arc<Mutex<Connection>>,
) -> Result<()> {
    let candidate = {
        let connection = database
            .lock()
            .map_err(|_| anyhow::anyhow!("database lock poisoned"))?;
        connection
            .query_row(
                "SELECT id, forward FROM outbound_attachment_forwards ORDER BY id LIMIT 1",
                [],
                |r| Ok((r.get::<_, i64>(0)?, r.get::<_, Vec<u8>>(1)?)),
            )
            .optional()?
    };
    let Some((id, bytes)) = candidate else {
        return Ok(());
    };
    let mut forward: pigeon_shared::RelayAttachmentForward = decode(&bytes)?;
    let response = relay_request(&forward.route, Request::ForwardAttachment(forward.clone())).await;
    let connection = database
        .lock()
        .map_err(|_| anyhow::anyhow!("database lock poisoned"))?;
    match response {
        Ok(Response::Ok) => {
            connection.execute(
                "DELETE FROM outbound_attachment_forwards WHERE id=?1",
                params![id],
            )?;
        }
        Ok(Response::Moved(route)) => {
            verify_routing(&route)?;
            if route.identity != forward.record.recipient.compact_id
                || route.genesis != forward.record.recipient.genesis
            {
                bail!("attachment MOVED identity mismatch")
            }
            forward = pigeon_shared::make_relay_attachment_forward(
                &relay_signer(&connection)?,
                route,
                forward.record,
            );
            connection.execute(
                "UPDATE outbound_attachment_forwards SET forward=?1 WHERE id=?2",
                params![encode(&forward)?, id],
            )?;
        }
        Ok(Response::Error(error)) => bail!("destination rejected attachment forward: {error}"),
        Ok(_) => bail!("unexpected attachment forwarding response"),
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
                if route.identity != forward.record.recipient.compact_id
                    || route.genesis != forward.record.recipient.genesis
                {
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
pub(super) async fn handle(
    stream: TcpStream,
    acceptor: TlsAcceptor,
    database: Arc<Mutex<Connection>>,
) -> Result<()> {
    let mut tls = acceptor.accept(stream).await?;
    let first = tls.read_u8().await?;
    if first == b'G' {
        return handle_discovery_http(&mut tls, database).await;
    }
    let request = decode(&read_prefixed_frame(&mut tls, first).await?)?;
    let response = {
        let connection = database
            .lock()
            .map_err(|_| anyhow::anyhow!("database lock poisoned"))?;
        process(&connection, request)
    };
    write_frame(&mut tls, &encode(&response)?).await
}

/// The relay protocol remains length-delimited TLS.  Discovery deliberately
/// shares that TLS listener so a simple self-hosted relay does not need a
/// second public port; the first plaintext byte after TLS selects either a
/// public HTTP GET or the existing binary protocol frame.
async fn read_prefixed_frame<S: AsyncReadExt + Unpin>(
    stream: &mut S,
    first: u8,
) -> Result<Vec<u8>> {
    let mut length = [first, 0, 0, 0];
    stream.read_exact(&mut length[1..]).await?;
    let length = u32::from_be_bytes(length) as usize;
    if length > 16 * 1024 * 1024 {
        bail!("frame too large")
    }
    let mut bytes = vec![0; length];
    stream.read_exact(&mut bytes).await?;
    Ok(bytes)
}

async fn handle_discovery_http<S: AsyncReadExt + AsyncWriteExt + Unpin>(
    stream: &mut S,
    database: Arc<Mutex<Connection>>,
) -> Result<()> {
    let mut request = vec![b'G'];
    while !request.ends_with(b"\r\n\r\n") {
        if request.len() >= 16 * 1024 {
            bail!("discovery HTTP request too large")
        }
        request.push(stream.read_u8().await?);
    }
    let request = std::str::from_utf8(&request).context("invalid discovery HTTP request")?;
    let mut words = request
        .lines()
        .next()
        .unwrap_or_default()
        .split_ascii_whitespace();
    let method = words.next();
    let path = words.next();
    let valid_get = method == Some("GET") && path.is_some_and(|path| path.starts_with('/'));
    let (status, body) = if valid_get {
        let descriptor = {
            let connection = database
                .lock()
                .map_err(|_| anyhow::anyhow!("database lock poisoned"))?;
            descriptor(&connection)?
        };
        ("200 OK", serde_json::to_vec(&descriptor)?)
    } else {
        ("404 Not Found", b"not found\n".to_vec())
    };
    let header = format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(header.as_bytes()).await?;
    stream.write_all(&body).await?;
    stream.flush().await?;
    Ok(())
}

#[cfg(test)]
#[path = "runtime_tests.rs"]
mod tests;
