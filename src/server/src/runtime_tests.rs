use super::*;
use ed25519_dalek::{Signer, SigningKey};
use pigeon_shared::{
    account_id, account_identity, make_authorized_device_set, make_card_from_roster,
    make_relay_forward, AccountTransitionKind, AttachmentRecord, DeviceRecord, MlsRecord,
    PairingArtifactKind, PairingRelayArtifact, PigeonAccountGenesis,
};
use rand_core::OsRng;
use rcgen::generate_simple_self_signed;
use sha2::{Digest, Sha256};
use x25519_dalek::StaticSecret;

// Existing relay tests exercise delivery rather than account creation. These
// fixtures construct a valid recovery-authorized public account state without
// reintroducing a production root-only constructor.
fn fixture_recovery(root: &SigningKey) -> SigningKey {
    SigningKey::from_bytes(
        &Sha256::digest(
            [
                b"pigeon-test-recovery".as_slice(),
                root.to_bytes().as_slice(),
            ]
            .concat(),
        )
        .into(),
    )
}
fn fixture_genesis(root: &SigningKey) -> PigeonAccountGenesis {
    let recovery = fixture_recovery(root);
    PigeonAccountGenesis {
        version: pigeon_shared::ACCOUNT_GENESIS_VERSION,
        root_public_key: root.verifying_key().to_bytes(),
        initial_device_key: root.verifying_key().to_bytes(),
        recovery_public_key: recovery.verifying_key().to_bytes(),
        nonce: Sha256::digest(
            [
                b"pigeon-test-genesis".as_slice(),
                root.to_bytes().as_slice(),
            ]
            .concat(),
        )
        .into(),
        initial_display_name: "Fixture".into(),
    }
}
fn make_device(root: &SigningKey, device: &SigningKey, package: Vec<u8>) -> DeviceRecord {
    let key = device.verifying_key().to_bytes();
    let mut record = DeviceRecord {
        identity: root.verifying_key().to_bytes(),
        device_id: key,
        device_key: key,
        mls_key_package: package,
        authorization_revision: 1,
        signature: vec![0; 64],
    };
    record.signature = root
        .sign(
            &bincode::serialize(&(
                record.identity,
                record.device_id,
                record.device_key,
                &record.mls_key_package,
                record.authorization_revision,
            ))
            .unwrap(),
        )
        .to_bytes()
        .to_vec();
    record
}
fn fixture_card(
    root: &SigningKey,
    encryption: &StaticSecret,
    server: String,
    devices: Vec<DeviceRecord>,
    revision: u64,
) -> pigeon_shared::ContactCard {
    let genesis = fixture_genesis(root);
    let identity = account_id(&genesis).unwrap();
    let recovery = fixture_recovery(root);
    let devices: Vec<_> = devices
        .into_iter()
        .map(|mut device| {
            device.identity = identity;
            device.signature = root
                .sign(
                    &bincode::serialize(&(
                        device.identity,
                        device.device_id,
                        device.device_key,
                        &device.mls_key_package,
                        device.authorization_revision,
                    ))
                    .unwrap(),
                )
                .to_bytes()
                .to_vec();
            device
        })
        .collect();
    let roster = make_authorized_device_set(
        genesis.clone(),
        root,
        &recovery,
        devices,
        1,
        None,
        None,
        AccountTransitionKind::Recovery,
    )
    .unwrap();
    make_card_from_roster(
        root,
        genesis,
        encryption,
        server,
        roster,
        revision,
        "Fixture".into(),
    )
    .unwrap()
}
fn make_card(
    root: &SigningKey,
    encryption: &StaticSecret,
    server: String,
    device: DeviceRecord,
) -> pigeon_shared::ContactCard {
    fixture_card(root, encryption, server, vec![device], 1)
}
fn make_card_with_devices(
    root: &SigningKey,
    encryption: &StaticSecret,
    server: String,
    devices: Vec<DeviceRecord>,
    revision: u64,
) -> pigeon_shared::ContactCard {
    fixture_card(root, encryption, server, devices, revision)
}
fn make_routing(
    root: &SigningKey,
    server: String,
    relay: [u8; 32],
    tls: [u8; 32],
    revision: u64,
    parent: u64,
) -> RoutingRecord {
    pigeon_shared::make_routing(
        root,
        fixture_genesis(root),
        server,
        relay,
        tls,
        revision,
        parent,
    )
}
fn make_revocation(root: &SigningKey, device: [u8; 32], revision: u64) -> DeviceRevocation {
    pigeon_shared::make_revocation(root, fixture_genesis(root), device, revision)
}

fn pairing_artifact(
    kind: PairingArtifactKind,
    session: u8,
    capability: u8,
    payload: Vec<u8>,
) -> PairingRelayArtifact {
    let account = pairing_account();
    PairingRelayArtifact {
        version: 1,
        identity: account.compact_id,
        genesis: account.genesis,
        session_id: [session; 16],
        nonce: [9; 16],
        kind,
        expires_at: 100,
        capability_commitment: pigeon_shared::capability_commitment(&[capability; 32]),
        payload,
    }
}

fn pairing_account() -> pigeon_shared::AccountIdentity {
    let root = SigningKey::from_bytes(&[7; 32]);
    let recovery = SigningKey::from_bytes(&[8; 32]);
    let device = SigningKey::from_bytes(&[9; 32]);
    account_identity(PigeonAccountGenesis {
        version: pigeon_shared::ACCOUNT_GENESIS_VERSION,
        root_public_key: root.verifying_key().to_bytes(),
        initial_device_key: device.verifying_key().to_bytes(),
        recovery_public_key: recovery.verifying_key().to_bytes(),
        nonce: [7; 32],
        initial_display_name: "Pairing fixture".into(),
    })
    .unwrap()
}

fn account_for(card: &pigeon_shared::ContactCard) -> pigeon_shared::AccountIdentity {
    account_identity(card.genesis.clone()).unwrap()
}

#[test]
fn forced_compact_id_collision_keeps_canonical_accounts_and_relay_state_isolated() {
    let database = Connection::open_in_memory().unwrap();
    initialize(&database).unwrap();
    let root_a = SigningKey::generate(&mut OsRng);
    let root_b = SigningKey::generate(&mut OsRng);
    let genesis_a = fixture_genesis(&root_a);
    let genesis_b = fixture_genesis(&root_b);
    assert_ne!(genesis_a, genesis_b);
    pigeon_shared::force_compact_id_for_test(&genesis_a, [42; 32]).unwrap();
    pigeon_shared::force_compact_id_for_test(&genesis_b, [42; 32]).unwrap();
    let device_a_key = SigningKey::generate(&mut OsRng);
    let device_b_key = SigningKey::generate(&mut OsRng);
    let encryption_a = StaticSecret::random_from_rng(OsRng);
    let encryption_b = StaticSecret::random_from_rng(OsRng);
    let card_a = make_card(
        &root_a,
        &encryption_a,
        "relay.test:8443".into(),
        make_device(&root_a, &device_a_key, vec![1]),
    );
    let card_b = make_card(
        &root_b,
        &encryption_b,
        "relay.test:8443".into(),
        make_device(&root_b, &device_b_key, vec![2]),
    );
    assert_eq!(identity_id(&card_a), identity_id(&card_b));
    assert_ne!(card_a.genesis, card_b.genesis);
    for card in [&card_a, &card_b] {
        assert!(matches!(
            process(
                &database,
                Request::Register {
                    card: card.clone(),
                    device: card.devices[0].clone(),
                    device_signature: vec![],
                }
            ),
            Response::Ok
        ));
    }
    assert_eq!(
        database
            .query_row(
                "SELECT COUNT(*) FROM identities_v2 WHERE compact_id = ?1",
                params![[42u8; 32].to_vec()],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
        2
    );
    let route_a = make_routing(&root_a, "relay-a.test:8443".into(), [1; 32], [2; 32], 1, 0);
    let route_b = make_routing(&root_b, "relay-b.test:8443".into(), [3; 32], [4; 32], 1, 0);
    assert!(matches!(
        process(&database, Request::PublishRouting(route_a.clone())),
        Response::Ok
    ));
    assert!(matches!(
        process(&database, Request::PublishRouting(route_b.clone())),
        Response::Ok
    ));
    assert!(matches!(
        process(&database, Request::GetRouting { account: account_for(&card_a) }),
        Response::Routing(Some(route)) if route == route_a
    ));
    assert!(matches!(
        process(&database, Request::GetRouting { account: account_for(&card_b) }),
        Response::Routing(Some(route)) if route == route_b
    ));
    let record = MlsRecord {
        recipient: account_for(&card_a),
        sender: account_for(&card_a),
        sender_device: card_a.devices[0].device_id,
        target_devices: vec![card_a.devices[0].device_id],
        payload: vec![9, 9],
    };
    assert!(matches!(
        process(&database, Request::SendMls(record)),
        Response::Ok
    ));
    assert!(matches!(
        process(
            &database,
            Request::Fetch {
                account: account_for(&card_b),
                device_id: card_b.devices[0].device_id,
                known_routing_revision: 1,
            }
        ),
        Response::MlsMessages(messages) if messages.is_empty()
    ));
    let artifact = |card: &pigeon_shared::ContactCard, payload: Vec<u8>| PairingRelayArtifact {
        version: pigeon_shared::PAIRING_VERSION,
        identity: identity_id(card),
        genesis: card.genesis.clone(),
        session_id: [3; 16],
        nonce: [4; 16],
        kind: PairingArtifactKind::PublicRequest,
        expires_at: 100,
        capability_commitment: [5; 32],
        payload,
    };
    assert!(matches!(
        process_at(
            &database,
            Request::PublishPairingArtifact(artifact(&card_a, vec![1])),
            1
        ),
        Response::Ok
    ));
    assert!(matches!(
        process_at(
            &database,
            Request::PublishPairingArtifact(artifact(&card_b, vec![2])),
            1
        ),
        Response::Ok
    ));
    assert!(matches!(
        process_at(&database, Request::FetchPairingRequest { account: account_for(&card_b), session_id: [3; 16] }, 1),
        Response::PairingArtifact(value) if value.payload == vec![2]
    ));
    let revocation = make_revocation(&root_a, card_a.devices[0].device_id, 2);
    assert!(matches!(
        process(&database, Request::RevokeDevice(revocation)),
        Response::Ok
    ));
    assert!(matches!(
        process(
            &database,
            Request::Fetch {
                account: account_for(&card_b),
                device_id: card_b.devices[0].device_id,
                known_routing_revision: 1,
            }
        ),
        Response::MlsMessages(_)
    ));
}

#[test]
fn pairing_artifacts_are_opaque_capability_gated_and_single_use() {
    let db = Connection::open_in_memory().unwrap();
    initialize(&db).unwrap();
    let request = pairing_artifact(PairingArtifactKind::PublicRequest, 1, 0, vec![1, 2]);
    assert!(matches!(
        process_at(&db, Request::PublishPairingArtifact(request.clone()), 1),
        Response::Ok
    ));
    assert!(
        matches!(process_at(&db, Request::FetchPairingRequest { account: pairing_account(), session_id:[1;16] }, 1), Response::PairingArtifact(a) if a.payload == vec![1,2])
    );
    let stored: Vec<u8> = db
        .query_row(
            "SELECT payload FROM pairing_artifacts_v2 WHERE genesis=?1 AND session=?2 AND kind=?3",
            params![
                canonical_genesis_key(&pairing_account().genesis).unwrap(),
                [1u8; 16].to_vec(),
                encode(&PairingArtifactKind::PublicRequest).unwrap()
            ],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(stored, encode(&request).unwrap());
    let bootstrap = pairing_artifact(PairingArtifactKind::EncryptedBootstrap, 1, 4, vec![9, 8, 7]);
    assert!(matches!(
        process_at(&db, Request::PublishPairingArtifact(bootstrap.clone()), 1),
        Response::Ok
    ));
    assert!(matches!(
        process_at(
            &db,
            Request::FetchConsumePairingBootstrap {
                account: pairing_account(),
                session_id: [1; 16],
                capability: [3; 32]
            },
            1
        ),
        Response::PairingUnauthorized
    ));
    assert!(
        matches!(process_at(&db, Request::FetchConsumePairingBootstrap { account: pairing_account(), session_id:[1;16], capability:[4;32] }, 1), Response::PairingArtifact(a) if a.payload == bootstrap.payload)
    );
    assert!(matches!(
        process_at(
            &db,
            Request::FetchConsumePairingBootstrap {
                account: pairing_account(),
                session_id: [1; 16],
                capability: [4; 32]
            },
            1
        ),
        Response::PairingConsumed
    ));
    assert!(matches!(
        process_at(
            &db,
            Request::FetchPairingRequest {
                account: pairing_account(),
                session_id: [2; 16]
            },
            1
        ),
        Response::PairingNotFound
    ));
}

#[test]
fn relay_descriptor_is_versioned_and_bound_to_persistent_relay_state() {
    let db = Connection::open_in_memory().unwrap();
    initialize(&db).unwrap();
    set_relay_address(&db, "relay.example:8443").unwrap();
    bind_relay_tls_spki(&db, [9; 32]).unwrap();
    let Response::RelayDescriptor(first) = process(&db, Request::GetRelayDescriptor) else {
        panic!("expected relay descriptor")
    };
    pigeon_shared::verify_relay_descriptor(&first).unwrap();
    assert_eq!(first.address, "relay.example:8443");
    assert_eq!(first.version, pigeon_shared::RELAY_DESCRIPTOR_VERSION);
    let Response::RelayDescriptor(after_restart) = process(&db, Request::GetRelayDescriptor) else {
        panic!("expected relay descriptor after restart")
    };
    assert_eq!(first, after_restart);
}

#[test]
fn pairing_cancellation_expiry_and_restart_preserve_lifecycle_state() {
    let path = std::env::temp_dir().join(format!(
        "pigeon-pairing-{}-{}.sqlite",
        std::process::id(),
        system_now()
    ));
    let _ = std::fs::remove_file(&path);
    let bootstrap = pairing_artifact(PairingArtifactKind::EncryptedBootstrap, 3, 6, vec![5, 4, 3]);
    {
        let db = Connection::open(&path).unwrap();
        initialize(&db).unwrap();
        let request = pairing_artifact(PairingArtifactKind::PublicRequest, 3, 6, vec![1]);
        assert!(matches!(
            process_at(&db, Request::PublishPairingArtifact(request), 1),
            Response::Ok
        ));
        assert!(matches!(
            process_at(&db, Request::PublishPairingArtifact(bootstrap.clone()), 1),
            Response::Ok
        ));
        assert!(matches!(
            process_at(
                &db,
                Request::PublishPairingArtifact(pairing_artifact(
                    PairingArtifactKind::PublicRequest,
                    7,
                    0,
                    vec![2]
                )),
                1
            ),
            Response::Ok
        ));
        assert!(matches!(
            process_at(
                &db,
                Request::CancelPairing {
                    account: pairing_account(),
                    session_id: [3; 16],
                    capability: [8; 32]
                },
                1
            ),
            Response::PairingUnauthorized
        ));
        assert!(matches!(
            process_at(
                &db,
                Request::CancelPairing {
                    account: pairing_account(),
                    session_id: [3; 16],
                    capability: [6; 32]
                },
                1
            ),
            Response::PairingCancelled
        ));
    }
    {
        let db = Connection::open(&path).unwrap();
        initialize(&db).unwrap();
        assert!(matches!(
            process_at(
                &db,
                Request::FetchConsumePairingBootstrap {
                    account: pairing_account(),
                    session_id: [3; 16],
                    capability: [6; 32]
                },
                1
            ),
            Response::PairingCancelled
        ));
        let mut expired = pairing_artifact(PairingArtifactKind::PublicRequest, 4, 0, vec![1]);
        expired.expires_at = 2;
        assert!(matches!(
            process_at(&db, Request::PublishPairingArtifact(expired), 1),
            Response::Ok
        ));
        assert!(matches!(
            process_at(
                &db,
                Request::FetchPairingRequest {
                    account: pairing_account(),
                    session_id: [4; 16]
                },
                2
            ),
            Response::PairingExpired
        ));
    }
    let _ = std::fs::remove_file(path);
}

#[test]
fn pairing_publish_rejects_mismatched_bindings_without_affecting_other_sessions() {
    let db = Connection::open_in_memory().unwrap();
    initialize(&db).unwrap();
    let request = pairing_artifact(PairingArtifactKind::PublicRequest, 5, 0, vec![1]);
    assert!(matches!(
        process_at(&db, Request::PublishPairingArtifact(request.clone()), 1),
        Response::Ok
    ));
    let mut nonce_mismatch =
        pairing_artifact(PairingArtifactKind::EncryptedBootstrap, 5, 4, vec![2]);
    nonce_mismatch.nonce = [8; 16];
    assert!(matches!(
        process_at(&db, Request::PublishPairingArtifact(nonce_mismatch), 1),
        Response::Error(_)
    ));
    let mut identity_mismatch = pairing_artifact(PairingArtifactKind::PublicRequest, 5, 0, vec![3]);
    identity_mismatch.identity = [6; 32];
    assert!(matches!(
        process_at(&db, Request::PublishPairingArtifact(identity_mismatch), 1),
        Response::Error(_)
    ));
    let mut commitment_mismatch = request.clone();
    commitment_mismatch.capability_commitment = pigeon_shared::capability_commitment(&[9; 32]);
    assert!(matches!(
        process_at(&db, Request::PublishPairingArtifact(commitment_mismatch), 1),
        Response::Error(_)
    ));
    assert!(matches!(
        process_at(&db, Request::FetchPairingRequest { account: pairing_account(), session_id:[5;16] }, 1),
        Response::PairingArtifact(a) if a.payload == request.payload
    ));
    // A compact-ID substitution cannot create or replace another canonical
    // genesis session; the original public artifact remains visible.
    assert!(matches!(
        process_at(&db, Request::FetchPairingRequest { account: pairing_account(), session_id:[5;16] }, 1),
        Response::PairingArtifact(a) if a.payload == request.payload
    ));
    assert!(matches!(
        process_at(
            &db,
            Request::FetchConsumePairingBootstrap {
                account: pairing_account(),
                session_id: [5; 16],
                capability: [4; 32]
            },
            1
        ),
        Response::PairingUnauthorized
    ));
}

#[test]
fn pairing_consume_and_metadata_validation_are_atomic_across_restart() {
    let path = std::env::temp_dir().join(format!(
        "pigeon-pairing-consume-{}-{}.sqlite",
        std::process::id(),
        system_now()
    ));
    let _ = std::fs::remove_file(&path);
    let bootstrap = pairing_artifact(PairingArtifactKind::EncryptedBootstrap, 6, 4, vec![7, 7]);
    {
        let db = Connection::open(&path).unwrap();
        initialize(&db).unwrap();
        assert!(matches!(
            process_at(
                &db,
                Request::PublishPairingArtifact(pairing_artifact(
                    PairingArtifactKind::PublicRequest,
                    6,
                    0,
                    vec![1]
                )),
                1
            ),
            Response::Ok
        ));
        assert!(matches!(
            process_at(&db, Request::PublishPairingArtifact(bootstrap.clone()), 1),
            Response::Ok
        ));

        assert!(matches!(
            process_at(
                &db,
                Request::PublishPairingArtifact(pairing_artifact(
                    PairingArtifactKind::PublicRequest,
                    7,
                    0,
                    vec![2]
                )),
                1
            ),
            Response::Ok
        ));

        // A malformed or metadata-substituted stored envelope is rejected before the
        // row is marked consumed. This also protects independent sessions.
        let mut wrong_identity = bootstrap.clone();
        wrong_identity.identity = [3; 32];
        let mut wrong_session = bootstrap.clone();
        wrong_session.session_id = [3; 16];
        let mut wrong_nonce = bootstrap.clone();
        wrong_nonce.nonce = [3; 16];
        let mut wrong_kind = bootstrap.clone();
        wrong_kind.kind = PairingArtifactKind::Approval;
        let mut wrong_commitment = bootstrap.clone();
        wrong_commitment.capability_commitment = pigeon_shared::capability_commitment(&[3; 32]);
        for substituted in [
            wrong_identity,
            wrong_session,
            wrong_nonce,
            wrong_kind,
            wrong_commitment,
        ] {
            db.execute(
                "UPDATE pairing_artifacts_v2 SET payload=?1 WHERE genesis=?2 AND session=?3 AND kind=?4",
                params![
                    encode(&substituted).unwrap(),
                    canonical_genesis_key(&pairing_account().genesis).unwrap(),
                    [6u8; 16].to_vec(),
                    encode(&PairingArtifactKind::EncryptedBootstrap).unwrap()
                ],
            )
            .unwrap();
            assert!(matches!(
                process_at(
                    &db,
                    Request::FetchConsumePairingBootstrap {
                        account: pairing_account(),
                        session_id: [6; 16],
                        capability: [4; 32]
                    },
                    1
                ),
                Response::Error(_)
            ));
        }
        let consumed: i64 = db
            .query_row(
                "SELECT consumed FROM pairing_artifacts_v2 WHERE genesis=?1 AND session=?2 AND kind=?3",
                params![
                    canonical_genesis_key(&pairing_account().genesis).unwrap(),
                    [6u8; 16].to_vec(),
                    encode(&PairingArtifactKind::EncryptedBootstrap).unwrap()
                ],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(consumed, 0);
        assert!(matches!(
            process_at(
                &db,
                Request::FetchPairingRequest {
                    account: pairing_account(),
                    session_id: [7; 16]
                },
                1
            ),
            Response::PairingArtifact(a) if a.payload == vec![2]
        ));
        db.execute(
            "UPDATE pairing_artifacts_v2 SET payload=?1 WHERE genesis=?2 AND session=?3 AND kind=?4",
            params![
                encode(&bootstrap).unwrap(),
                canonical_genesis_key(&pairing_account().genesis).unwrap(),
                [6u8; 16].to_vec(),
                encode(&PairingArtifactKind::EncryptedBootstrap).unwrap()
            ],
        )
        .unwrap();
        assert!(matches!(
            process_at(&db, Request::FetchConsumePairingBootstrap { account: pairing_account(), session_id:[6;16], capability:[4;32] }, 1),
            Response::PairingArtifact(a) if a.payload == bootstrap.payload
        ));
    }
    {
        let db = Connection::open(&path).unwrap();
        initialize(&db).unwrap();
        assert!(matches!(
            process_at(
                &db,
                Request::FetchConsumePairingBootstrap {
                    account: pairing_account(),
                    session_id: [6; 16],
                    capability: [4; 32]
                },
                1
            ),
            Response::PairingConsumed
        ));
    }
    let _ = std::fs::remove_file(path);
}

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
        recipient: account_for(&card),
        sender: account_for(&card),
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
            account: account_for(&card),
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
fn opaque_attachment_delivery_requires_per_device_ack_and_preserves_bytes() {
    let database = Connection::open_in_memory().unwrap();
    initialize(&database).unwrap();
    let root = SigningKey::generate(&mut OsRng);
    let device_key = SigningKey::generate(&mut OsRng);
    let encryption = StaticSecret::random_from_rng(OsRng);
    let device = make_device(&root, &device_key, vec![1]);
    let card = make_card(&root, &encryption, "server.test".into(), device.clone());
    assert!(matches!(
        process(
            &database,
            Request::Register {
                card: card.clone(),
                device: device.clone(),
                device_signature: vec![]
            }
        ),
        Response::Ok
    ));
    let record = AttachmentRecord {
        version: pigeon_shared::ATTACHMENT_VERSION,
        recipient: account_for(&card),
        sender: account_for(&card),
        sender_device: device.device_id,
        target_devices: vec![device.device_id],
        attachment_id: [4; 32],
        conversation_id: b"group".to_vec(),
        plaintext_size: 3,
        ciphertext_hash: Sha256::digest([7, 8, 9]).into(),
        nonce: [5; 24],
        ciphertext: vec![7, 8, 9],
    };
    assert!(matches!(
        process(&database, Request::SendAttachment(record.clone())),
        Response::Ok
    ));
    // A retry is idempotent, but an attacker cannot reuse the identifier to
    // replace opaque bytes after another target has seen the MLS descriptor.
    assert!(matches!(
        process(&database, Request::SendAttachment(record.clone())),
        Response::Ok
    ));
    let mut substituted = record.clone();
    substituted.ciphertext = vec![1, 2, 3];
    substituted.ciphertext_hash = Sha256::digest(&substituted.ciphertext).into();
    assert!(matches!(
        process(&database, Request::SendAttachment(substituted)),
        Response::Error(_)
    ));
    let Response::Attachment(fetched) = process(
        &database,
        Request::FetchAttachment {
            account: account_for(&card),
            device_id: device.device_id,
            attachment_id: [4; 32],
        },
    ) else {
        panic!("expected attachment")
    };
    let Some(fetched) = *fetched else {
        panic!("expected attachment")
    };
    assert_eq!(fetched.ciphertext, record.ciphertext);
    assert!(matches!(
        process(
            &database,
            Request::AcknowledgeAttachment {
                account: account_for(&card),
                device_id: device.device_id,
                attachment_id: [4; 32]
            }
        ),
        Response::Ok
    ));
    assert!(matches!(
        process(
            &database,
            Request::FetchAttachment {
                account: account_for(&card),
                device_id: device.device_id,
                attachment_id: [4; 32]
            },
        ),
        Response::Attachment(value) if value.is_none()
    ));
}

#[test]
fn opaque_attachment_expires_at_the_hard_retention_bound() {
    let database = Connection::open_in_memory().unwrap();
    initialize(&database).unwrap();
    let root = SigningKey::generate(&mut OsRng);
    let device_key = SigningKey::generate(&mut OsRng);
    let encryption = StaticSecret::random_from_rng(OsRng);
    let device = make_device(&root, &device_key, vec![1]);
    let card = make_card(&root, &encryption, "server.test".into(), device.clone());
    let start = 50_000_i64;
    assert!(matches!(
        process_at(
            &database,
            Request::Register {
                card: card.clone(),
                device: device.clone(),
                device_signature: vec![]
            },
            start,
        ),
        Response::Ok
    ));
    let record = AttachmentRecord {
        version: pigeon_shared::ATTACHMENT_VERSION,
        recipient: account_for(&card),
        sender: account_for(&card),
        sender_device: device.device_id,
        target_devices: vec![device.device_id],
        attachment_id: [9; 32],
        conversation_id: b"retention-group".to_vec(),
        plaintext_size: 4,
        ciphertext_hash: Sha256::digest([1, 2, 3, 4]).into(),
        nonce: [7; 24],
        ciphertext: vec![1, 2, 3, 4],
    };
    assert!(matches!(
        process_at(&database, Request::SendAttachment(record), start),
        Response::Ok
    ));
    assert_eq!(
        database
            .query_row("SELECT COUNT(*) FROM attachments_v1", [], |row| row
                .get::<_, i64>(0))
            .unwrap(),
        1
    );
    // Lifecycle cleanup is driven by ordinary relay requests; it must not
    // retain unacknowledged opaque bytes past the documented 14-day bound.
    assert!(matches!(
        process_at(
            &database,
            Request::GetRevocations {
                account: account_for(&card)
            },
            start + RETENTION_SECONDS,
        ),
        Response::Revocations(_)
    ));
    assert_eq!(
        database
            .query_row("SELECT COUNT(*) FROM attachments_v1", [], |row| row
                .get::<_, i64>(0))
            .unwrap(),
        0
    );
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
        recipient: account_for(&card),
        sender: account_for(&card),
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
            account: account_for(&card),
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
                account: account_for(&card),
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
                recipient: account_for(&card),
                sender: account_for(&card),
                sender_device: [8; 32],
                target_devices: vec![a2_record.device_id],
                payload: vec![10],
            })
        ),
        Response::Ok
    ));
    assert_eq!(
        database
            .query_row("SELECT COUNT(*) FROM mls_events_v2", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        0
    );
    assert!(matches!(
        process(
            &database,
            Request::Fetch {
                account: account_for(&card),
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
            account: account_for(&card),
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
                card: card.clone(),
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
                account: account_for(&card),
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
            recipient: account_for(&alice_card),
            sender: account_for(&alice_card),
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
        .query_row("SELECT id FROM mls_events_v2", [], |r| r.get(0))
        .unwrap();
    assert!(matches!(
        process_at(
            &database,
            Request::Acknowledge {
                account: account_for(&alice_card),
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
            .query_row("SELECT COUNT(*) FROM mls_events_v2", [], |r| r
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
                account: account_for(&alice_card)
            },
            dormant_at,
        ),
        Response::Revocations(_)
    ));
    assert_eq!(
        database
            .query_row(
                "SELECT dormant FROM devices_v2 WHERE genesis = ?1 AND device_id = ?2",
                params![
                    canonical_genesis_key(&alice_card.genesis).unwrap(),
                    a2_record.device_id.to_vec()
                ],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
        1
    );
    assert_eq!(
        database
            .query_row("SELECT COUNT(*) FROM mls_events_v2", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        0
    );
    let dormant_send = process_at(&database, send(vec![2]), dormant_at);
    assert!(matches!(dormant_send, Response::Ok), "{dormant_send:?}");
    assert_eq!(
        database
            .query_row(
                "SELECT COUNT(*) FROM event_deliveries_v2 WHERE recipient_genesis = ?1 AND device_id = ?2",
                params![canonical_genesis_key(&alice_card.genesis).unwrap(), a2_record.device_id.to_vec()],
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
                "SELECT dormant FROM devices_v2 WHERE genesis = ?1 AND device_id = ?2",
                params![
                    canonical_genesis_key(&alice_card.genesis).unwrap(),
                    a2_record.device_id.to_vec()
                ],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
        0
    );
    // Complete the A1-only event, then ensure a future event targets A2.
    let a1_only: i64 = database
        .query_row(
            "SELECT event_id FROM event_deliveries_v2 WHERE recipient_genesis = ?1 AND device_id = ?2",
            params![canonical_genesis_key(&alice_card.genesis).unwrap(), a1_record.device_id.to_vec()],
            |r| r.get(0),
        )
        .unwrap();
    assert!(matches!(
        process_at(
            &database,
            Request::Acknowledge {
                account: account_for(&alice_card),
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
    assert_eq!(
        database
            .query_row(
                "SELECT COUNT(*) FROM event_deliveries_v2 WHERE recipient_genesis = ?1 AND device_id = ?2 AND acknowledged = 0",
                params![canonical_genesis_key(&alice_card.genesis).unwrap(), a2_record.device_id.to_vec()],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
        1
    );
    let unresponsive_event: i64 = database
        .query_row("SELECT MAX(id) FROM mls_events_v2", [], |r| r.get(0))
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
                card: alice_card.clone(),
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
                account: account_for(&alice_card)
            },
            dormant_at + 1 + RETENTION_SECONDS
        ),
        Response::Revocations(_)
    ));
    assert_eq!(
        database
            .query_row(
                "SELECT COUNT(*) FROM mls_events_v2 WHERE id = ?1",
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
            .query_row("SELECT COUNT(*) FROM revocations_v2", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        1
    );
    assert_eq!(
        database
            .query_row(
                "SELECT dormant FROM devices_v2 WHERE genesis = ?1 AND device_id = ?2",
                params![
                    canonical_genesis_key(&alice_card.genesis).unwrap(),
                    a1_record.device_id.to_vec()
                ],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
        0
    );
    assert_eq!(
        database
            .query_row(
                "SELECT last_seen FROM devices_v2 WHERE genesis = ?1 AND device_id = ?2",
                params![
                    canonical_genesis_key(&alice_card.genesis).unwrap(),
                    a1_record.device_id.to_vec()
                ],
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
        matches!(process(&new, Request::GetRouting { account: account_for(&old_card) }), Response::Routing(Some(route)) if route == moved)
    );
    assert!(matches!(
        process(&old, Request::PublishRouting(moved.clone())),
        Response::Ok
    ));
    assert!(
        matches!(process(&old, Request::Fetch { account: account_for(&old_card), device_id: a2_record.device_id, known_routing_revision: 1 }), Response::Moved(route) if route == moved)
    );
    assert_eq!(moved.identity, identity_id(&old_card));
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
            account: account_for(&old_card),
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
        matches!(process(&new, Request::GetRouting { account: account_for(&old_card) }), Response::Routing(Some(route)) if route.revision == 2)
    );
    let _ = std::fs::remove_file(path);
}

#[test]
fn relay_identity_and_route_fingerprint_survive_restart() {
    let path = std::env::temp_dir().join(format!("pigeon-relay-id-{}.sqlite", std::process::id()));
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
                card: card.clone(),
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
        recipient: account_for(&card),
        sender: account_for(&card),
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
            account: account_for(&card),
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
