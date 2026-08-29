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
    assert_eq!(
        database
            .query_row(
                "SELECT COUNT(*) FROM event_deliveries WHERE device_id = ?1 AND acknowledged = 0",
                params![a2_record.device_id.to_vec()],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
        1
    );
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
