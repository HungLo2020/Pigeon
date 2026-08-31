use std::{
    fs,
    net::{SocketAddr, TcpStream},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{Mutex, OnceLock},
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

fn relay_test_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        // A prior assertion must not turn independent relay tests into
        // misleading poison failures; the guard still serializes all relay
        // processes and each test reports its own concrete failure.
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn run(binary: &Path, arguments: &[String]) -> String {
    let output = Command::new(binary)
        .args(arguments)
        .output()
        .expect("run client");
    assert!(
        output.status.success(),
        "client failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("client output UTF-8")
}

fn server(binary: &Path, address: &str, directory: &Path, name: &str) -> Child {
    Command::new(binary)
        .args([
            "--listen",
            address,
            "--database",
            directory.join(format!("{name}.sqlite")).to_str().unwrap(),
            "--certificate",
            directory.join(format!("{name}.der")).to_str().unwrap(),
            "--private-key",
            directory.join(format!("{name}.key")).to_str().unwrap(),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("start relay")
}

fn wait_for(path: &Path) {
    // Fresh bundled-SQLite relay startup can exceed 2.5 seconds on a loaded
    // hosted CI runner. Keep the test deterministic without masking an exited
    // process (checked on every iteration).
    for _ in 0..400 {
        if path.exists() {
            return;
        }
        thread::sleep(Duration::from_millis(25));
    }
    panic!("relay did not create {}", path.display());
}

fn wait_for_relay(relay: &mut Child, address: &str, certificate: &Path) {
    wait_for(certificate);
    let address: SocketAddr = address.parse().expect("test relay socket address");
    for _ in 0..100 {
        if let Some(status) = relay.try_wait().expect("inspect relay process") {
            panic!("relay exited before accepting connections: {status}");
        }
        if TcpStream::connect_timeout(&address, Duration::from_millis(25)).is_ok() {
            return;
        }
        thread::sleep(Duration::from_millis(25));
    }
    panic!("relay did not accept connections at {address}");
}

fn id(output: &str) -> String {
    output
        .lines()
        .find_map(|line| line.strip_prefix("identity created: "))
        .expect("identity output")
        .to_owned()
}

fn genesis(output: &str) -> String {
    output
        .lines()
        .find_map(|line| line.strip_prefix("account genesis: "))
        .expect("account genesis output")
        .to_owned()
}

fn client_args(state: &Path, certificate: &Path, command: Vec<String>) -> Vec<String> {
    let mut arguments = vec![
        "--state".into(),
        state.display().to_string(),
        "--certificate".into(),
        certificate.display().to_string(),
    ];
    arguments.extend(command);
    arguments
}

#[test]
fn encrypted_backup_recovers_a_fresh_device_without_history_or_mls_epoch_state() {
    let client = PathBuf::from(env!("CARGO_BIN_EXE_pigeon-client"));
    let directory = std::env::temp_dir().join(format!(
        "pigeon-backup-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir(&directory).unwrap();
    let original = directory.join("original.json");
    let recovered = directory.join("recovered.json");
    let backup = directory.join("account.pigeon-backup.json");
    let password = "correct horse battery staple";
    run(
        &client,
        &[
            "--state".into(),
            original.display().to_string(),
            "create-local".into(),
            "--display-name".into(),
            "Alice".into(),
            "--password".into(),
            password.into(),
        ],
    );
    run(
        &client,
        &[
            "--state".into(),
            original.display().to_string(),
            "export".into(),
            "--output".into(),
            backup.display().to_string(),
            "--password".into(),
            password.into(),
        ],
    );
    let wrong = Command::new(&client)
        .args([
            "--state",
            recovered.to_str().unwrap(),
            "import",
            "--input",
            backup.to_str().unwrap(),
            "--password",
            "wrong password never works",
        ])
        .output()
        .unwrap();
    assert!(!wrong.status.success());
    run(
        &client,
        &[
            "--state".into(),
            recovered.display().to_string(),
            "import".into(),
            "--input".into(),
            backup.display().to_string(),
            "--password".into(),
            password.into(),
        ],
    );
    let original: serde_json::Value = serde_json::from_slice(&fs::read(original).unwrap()).unwrap();
    let recovered: serde_json::Value =
        serde_json::from_slice(&fs::read(recovered).unwrap()).unwrap();
    assert_eq!(
        original["authorized_devices"]["identity"],
        recovered["authorized_devices"]["identity"]
    );
    assert_ne!(
        original["device"]["device_id"],
        recovered["device"]["device_id"]
    );
    assert_eq!(recovered["history"].as_array().unwrap().len(), 0);
    assert_eq!(recovered["mls_conversations"].as_object().unwrap().len(), 0);
    assert!(!fs::read_to_string(backup)
        .unwrap()
        .contains("signing_secret"));
    let _ = fs::remove_dir_all(directory);
}

#[test]
fn pairing_creates_a_distinct_device_with_the_same_root_identity() {
    let _guard = relay_test_lock();
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..");
    let server_bin = root.join("target/debug/pigeon-server");
    if !server_bin.exists() {
        assert!(Command::new("cargo")
            .current_dir(&root)
            .args([
                "build",
                "--quiet",
                "-p",
                "pigeon-server",
                "--bin",
                "pigeon-server"
            ])
            .status()
            .expect("build relay")
            .success());
    }
    let client_bin = PathBuf::from(env!("CARGO_BIN_EXE_pigeon-client"));
    let directory = std::env::temp_dir().join(format!(
        "pigeon-pairing-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir(&directory).unwrap();
    let address = "127.0.0.1:39420";
    let mut relay = server(&server_bin, address, &directory, "pairing");
    let certificate = directory.join("pairing.der");
    wait_for_relay(&mut relay, address, &certificate);
    let existing = directory.join("existing.json");
    let joining = directory.join("joining.json");
    let created = run(
        &client_bin,
        &client_args(
            &existing,
            &certificate,
            vec![
                "create".into(),
                "--server".into(),
                address.into(),
                "--display-name".into(),
                "Existing".into(),
                "--password".into(),
                "correct horse battery staple".into(),
            ],
        ),
    );
    let root_id = id(&created);
    let root_genesis = genesis(&created);
    let pairing_request = run(
        &client_bin,
        &client_args(
            &joining,
            &certificate,
            vec![
                "pair-request".into(),
                "--identity".into(),
                root_id.clone(),
                "--genesis".into(),
                root_genesis,
                "--server".into(),
                address.into(),
            ],
        ),
    );
    // The pending request is local durable state and the relay session is
    // SQLite-backed, so an interruption between request and approval is safe.
    let _ = relay.kill();
    let _ = relay.wait();
    relay = server(&server_bin, address, &directory, "pairing");
    wait_for_relay(&mut relay, address, &certificate);
    run(
        &client_bin,
        &client_args(
            &existing,
            &certificate,
            vec![
                "pair-approve".into(),
                pairing_request.trim().into(),
                "--password".into(),
                "correct horse battery staple".into(),
            ],
        ),
    );
    run(
        &client_bin,
        &client_args(&joining, &certificate, vec!["pair-consume".into()]),
    );
    let existing_state: serde_json::Value =
        serde_json::from_slice(&fs::read(&existing).unwrap()).unwrap();
    let joining_state: serde_json::Value =
        serde_json::from_slice(&fs::read(&joining).unwrap()).unwrap();
    assert_eq!(
        existing_state["card"]["signing_key"],
        joining_state["card"]["signing_key"]
    );
    assert_ne!(
        existing_state["device"]["device_id"],
        joining_state["device"]["device_id"]
    );
    assert_eq!(
        existing_state["authorized_devices"]["devices"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert_eq!(
        joining_state["authorized_devices"]["devices"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    let _ = relay.kill();
    let _ = relay.wait();
    let _ = fs::remove_dir_all(directory);
}

#[test]
fn clients_exchange_mls_through_pinned_relays_and_follow_moved_after_restart() {
    let _guard = relay_test_lock();
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..");
    let server_bin = root.join("target/debug/pigeon-server");
    if !server_bin.exists() {
        assert!(Command::new("cargo")
            .current_dir(&root)
            .args([
                "build",
                "--quiet",
                "-p",
                "pigeon-server",
                "--bin",
                "pigeon-server"
            ])
            .status()
            .expect("build relay")
            .success());
    }
    let client_bin = PathBuf::from(env!("CARGO_BIN_EXE_pigeon-client"));
    let directory = std::env::temp_dir().join(format!(
        "pigeon-cross-server-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir(&directory).unwrap();
    let a = "127.0.0.1:39401";
    let b = "127.0.0.1:39402";
    let c = "127.0.0.1:39403";
    let mut relay_a = server(&server_bin, a, &directory, "a");
    let mut relay_b = server(&server_bin, b, &directory, "b");
    wait_for_relay(&mut relay_a, a, &directory.join("a.der"));
    wait_for_relay(&mut relay_b, b, &directory.join("b.der"));
    let alice = directory.join("alice.json");
    let bob = directory.join("bob.json");
    let alice_id = id(&run(
        &client_bin,
        &[
            "--state".into(),
            alice.display().to_string(),
            "--certificate".into(),
            directory.join("a.der").display().to_string(),
            "create".into(),
            "--server".into(),
            a.into(),
            "--display-name".into(),
            "Alice".into(),
            "--password".into(),
            "correct horse battery staple".into(),
        ],
    ));
    let bob_id = id(&run(
        &client_bin,
        &[
            "--state".into(),
            bob.display().to_string(),
            "--certificate".into(),
            directory.join("b.der").display().to_string(),
            "create".into(),
            "--server".into(),
            b.into(),
            "--display-name".into(),
            "Bob".into(),
            "--password".into(),
            "correct horse battery staple".into(),
        ],
    ));
    let bob_card = run(
        &client_bin,
        &["--state".into(), bob.display().to_string(), "card".into()],
    );
    run(
        &client_bin,
        &[
            "--state".into(),
            alice.display().to_string(),
            "--certificate".into(),
            directory.join("b.der").display().to_string(),
            "add-contact".into(),
            bob_card,
        ],
    );
    run(
        &client_bin,
        &[
            "--state".into(),
            alice.display().to_string(),
            "--certificate".into(),
            directory.join("a.der").display().to_string(),
            "send".into(),
            "--to".into(),
            bob_id.clone(),
            "before restart".into(),
        ],
    );
    thread::sleep(Duration::from_millis(700));
    assert!(run(
        &client_bin,
        &[
            "--state".into(),
            bob.display().to_string(),
            "--certificate".into(),
            directory.join("b.der").display().to_string(),
            "fetch".into()
        ]
    )
    .contains("before restart"));

    // The opaque file is queued from Alice's own relay to Bob's relay, while
    // the only usable content key travels in the MLS application event.
    let attachment = directory.join("notes.txt");
    fs::write(&attachment, b"opaque relay attachment test\n").unwrap();
    run(
        &client_bin,
        &[
            "--state".into(),
            alice.display().to_string(),
            "--certificate".into(),
            directory.join("a.der").display().to_string(),
            "send-attachment".into(),
            "--to".into(),
            bob_id.clone(),
            "--file".into(),
            attachment.display().to_string(),
        ],
    );
    thread::sleep(Duration::from_millis(700));
    run(
        &client_bin,
        &[
            "--state".into(),
            bob.display().to_string(),
            "--certificate".into(),
            directory.join("b.der").display().to_string(),
            "fetch".into(),
        ],
    );
    let bob_state: serde_json::Value = serde_json::from_slice(&fs::read(&bob).unwrap()).unwrap();
    let local = bob_state["attachments"]
        .as_object()
        .unwrap()
        .values()
        .next()
        .unwrap();
    assert_eq!(local["filename"], "notes.txt");
    assert_eq!(
        fs::read(local["local_path"].as_str().unwrap()).unwrap(),
        b"opaque relay attachment test\n"
    );

    // State and relay identities are file-backed; restarting both sides must
    // preserve the established MLS group and recipient ACK state.
    relay_a.kill().unwrap();
    relay_a.wait().unwrap();
    relay_b.kill().unwrap();
    relay_b.wait().unwrap();
    relay_a = server(&server_bin, a, &directory, "a");
    relay_b = server(&server_bin, b, &directory, "b");
    wait_for_relay(&mut relay_a, a, &directory.join("a.der"));
    wait_for_relay(&mut relay_b, b, &directory.join("b.der"));
    run(
        &client_bin,
        &[
            "--state".into(),
            bob.display().to_string(),
            "--certificate".into(),
            directory.join("b.der").display().to_string(),
            "send".into(),
            "--to".into(),
            alice_id,
            "after restart".into(),
        ],
    );
    thread::sleep(Duration::from_millis(700));
    assert!(run(
        &client_bin,
        &[
            "--state".into(),
            alice.display().to_string(),
            "--certificate".into(),
            directory.join("a.der").display().to_string(),
            "fetch".into()
        ]
    )
    .contains("after restart"));

    let mut relay_c = server(&server_bin, c, &directory, "c");
    wait_for_relay(&mut relay_c, c, &directory.join("c.der"));
    // Bob signs and publishes B -> C before C becomes its local route. Alice
    // retains B until normal pinned sync learns the signed newer revision.
    run(
        &client_bin,
        &[
            "--state".into(),
            bob.display().to_string(),
            "--certificate".into(),
            directory.join("c.der").display().to_string(),
            "migrate".into(),
            "--server".into(),
            c.into(),
            "--previous-certificate".into(),
            directory.join("b.der").display().to_string(),
        ],
    );
    run(
        &client_bin,
        &[
            "--state".into(),
            alice.display().to_string(),
            "--certificate".into(),
            directory.join("a.der").display().to_string(),
            "fetch".into(),
        ],
    );
    run(
        &client_bin,
        &[
            "--state".into(),
            alice.display().to_string(),
            "--certificate".into(),
            directory.join("a.der").display().to_string(),
            "send".into(),
            "--to".into(),
            bob_id,
            "after moved".into(),
        ],
    );
    thread::sleep(Duration::from_millis(700));
    assert!(run(
        &client_bin,
        &[
            "--state".into(),
            bob.display().to_string(),
            "--certificate".into(),
            directory.join("c.der").display().to_string(),
            "fetch".into()
        ]
    )
    .contains("after moved"));
    relay_a.kill().unwrap();
    relay_b.kill().unwrap();
    relay_c.kill().unwrap();
    relay_a.wait().unwrap();
    relay_b.wait().unwrap();
    relay_c.wait().unwrap();
}

#[test]
fn ownerless_group_membership_and_messages_cross_three_relays() {
    let _guard = relay_test_lock();
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..");
    let server_bin = root.join("target/debug/pigeon-server");
    if !server_bin.exists() {
        assert!(Command::new("cargo")
            .current_dir(&root)
            .args([
                "build",
                "--quiet",
                "-p",
                "pigeon-server",
                "--bin",
                "pigeon-server"
            ])
            .status()
            .unwrap()
            .success());
    }
    let client_bin = PathBuf::from(env!("CARGO_BIN_EXE_pigeon-client"));
    let directory = std::env::temp_dir().join(format!(
        "pigeon-group-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir(&directory).unwrap();
    let (a, b, c) = ("127.0.0.1:39601", "127.0.0.1:39602", "127.0.0.1:39603");
    let mut relay_a = server(&server_bin, a, &directory, "a");
    let mut relay_b = server(&server_bin, b, &directory, "b");
    let mut relay_c = server(&server_bin, c, &directory, "c");
    wait_for_relay(&mut relay_a, a, &directory.join("a.der"));
    wait_for_relay(&mut relay_b, b, &directory.join("b.der"));
    wait_for_relay(&mut relay_c, c, &directory.join("c.der"));
    let alice = directory.join("alice.json");
    let bob = directory.join("bob.json");
    let carol = directory.join("carol.json");
    let alice_id = id(&run(
        &client_bin,
        &client_args(
            &alice,
            &directory.join("a.der"),
            vec![
                "create".into(),
                "--server".into(),
                a.into(),
                "--display-name".into(),
                "Alice".into(),
                "--password".into(),
                "correct horse battery staple".into(),
            ],
        ),
    ));
    let bob_id = id(&run(
        &client_bin,
        &client_args(
            &bob,
            &directory.join("b.der"),
            vec![
                "create".into(),
                "--server".into(),
                b.into(),
                "--display-name".into(),
                "Bob".into(),
                "--password".into(),
                "correct horse battery staple".into(),
            ],
        ),
    ));
    let carol_id = id(&run(
        &client_bin,
        &client_args(
            &carol,
            &directory.join("c.der"),
            vec![
                "create".into(),
                "--server".into(),
                c.into(),
                "--display-name".into(),
                "Carol".into(),
                "--password".into(),
                "correct horse battery staple".into(),
            ],
        ),
    ));
    let alice_card = run(
        &client_bin,
        &client_args(&alice, &directory.join("a.der"), vec!["card".into()]),
    );
    let bob_card = run(
        &client_bin,
        &client_args(&bob, &directory.join("b.der"), vec!["card".into()]),
    );
    let carol_card = run(
        &client_bin,
        &client_args(&carol, &directory.join("c.der"), vec!["card".into()]),
    );
    for (state, cert, card) in [
        (&alice, "b.der", bob_card.as_str()),
        (&alice, "c.der", carol_card.as_str()),
        (&bob, "a.der", alice_card.as_str()),
        (&bob, "c.der", carol_card.as_str()),
        (&carol, "a.der", alice_card.as_str()),
        (&carol, "b.der", bob_card.as_str()),
    ] {
        run(
            &client_bin,
            &client_args(
                state,
                &directory.join(cert),
                vec!["add-contact".into(), card.into()],
            ),
        );
    }
    let created = run(
        &client_bin,
        &client_args(
            &alice,
            &directory.join("a.der"),
            vec![
                "group-create".into(),
                "--group".into(),
                "alpha".into(),
                "--members".into(),
                bob_id.clone(),
            ],
        ),
    );
    let group = created.split_whitespace().last().unwrap().to_owned();
    thread::sleep(Duration::from_millis(700));
    run(
        &client_bin,
        &client_args(&bob, &directory.join("b.der"), vec!["fetch".into()]),
    );
    run(
        &client_bin,
        &client_args(
            &alice,
            &directory.join("a.der"),
            vec![
                "group-send".into(),
                "--group".into(),
                "alpha".into(),
                "alice-to-bob".into(),
            ],
        ),
    );
    thread::sleep(Duration::from_millis(700));
    assert!(run(
        &client_bin,
        &client_args(&bob, &directory.join("b.der"), vec!["fetch".into()])
    )
    .contains("alice-to-bob"));
    // Bob is an ordinary MLS participant. He can add Carol; there is no
    // creator/admin credential in either the client or relay protocol.
    run(
        &client_bin,
        &client_args(
            &bob,
            &directory.join("b.der"),
            vec![
                "group-add".into(),
                "--group".into(),
                group.clone(),
                "--member".into(),
                carol_id,
            ],
        ),
    );
    thread::sleep(Duration::from_millis(700));
    run(
        &client_bin,
        &client_args(&carol, &directory.join("c.der"), vec!["fetch".into()]),
    );
    run(
        &client_bin,
        &client_args(&alice, &directory.join("a.der"), vec!["fetch".into()]),
    );
    run(
        &client_bin,
        &client_args(
            &carol,
            &directory.join("c.der"),
            vec![
                "group-send".into(),
                "--group".into(),
                group.clone(),
                "carol-to-all".into(),
            ],
        ),
    );
    thread::sleep(Duration::from_millis(700));
    let alice_after_carol = run(
        &client_bin,
        &client_args(&alice, &directory.join("a.der"), vec!["fetch".into()]),
    );
    assert!(
        alice_after_carol.contains("carol-to-all"),
        "{alice_after_carol}"
    );
    assert!(run(
        &client_bin,
        &client_args(&bob, &directory.join("b.der"), vec!["fetch".into()])
    )
    .contains("carol-to-all"));
    // An image-shaped byte stream uses the exact same encrypted attachment
    // protocol in a three-relay ownerless group; image presentation is purely
    // a local GUI concern after decryption.
    let image = directory.join("sample.png");
    fs::write(
        &image,
        b"\x89PNG\r\n\x1a\nnot-a-real-image-but-opaque-bytes",
    )
    .unwrap();
    run(
        &client_bin,
        &client_args(
            &carol,
            &directory.join("c.der"),
            vec![
                "group-attachment".into(),
                "--group".into(),
                group.clone(),
                "--file".into(),
                image.display().to_string(),
            ],
        ),
    );
    thread::sleep(Duration::from_millis(700));
    for (state, certificate) in [(&alice, "a.der"), (&bob, "b.der")] {
        run(
            &client_bin,
            &client_args(state, &directory.join(certificate), vec!["fetch".into()]),
        );
        let state: serde_json::Value = serde_json::from_slice(&fs::read(state).unwrap()).unwrap();
        assert!(state["attachments"]
            .as_object()
            .unwrap()
            .values()
            .any(|entry| entry["filename"] == "sample.png"));
    }
    // Restart a current participant and its relay, then remove Bob as another
    // ordinary participant. The removal commit targets survivors only.
    relay_a.kill().unwrap();
    relay_a.wait().unwrap();
    relay_a = server(&server_bin, a, &directory, "a");
    wait_for_relay(&mut relay_a, a, &directory.join("a.der"));
    run(
        &client_bin,
        &client_args(
            &alice,
            &directory.join("a.der"),
            vec![
                "group-remove".into(),
                "--group".into(),
                "alpha".into(),
                "--member".into(),
                bob_id,
            ],
        ),
    );
    thread::sleep(Duration::from_millis(700));
    run(
        &client_bin,
        &client_args(&carol, &directory.join("c.der"), vec!["fetch".into()]),
    );
    // Every client invocation is a fresh process using persisted local MLS
    // state. Restart Carol's relay after it accepted Alice's removal commit
    // and before she sends, proving the surviving group resumes intact.
    relay_c.kill().unwrap();
    relay_c.wait().unwrap();
    relay_c = server(&server_bin, c, &directory, "c");
    wait_for_relay(&mut relay_c, c, &directory.join("c.der"));
    run(
        &client_bin,
        &client_args(
            &carol,
            &directory.join("c.der"),
            vec![
                "group-send".into(),
                "--group".into(),
                group,
                "after-bob-removed".into(),
            ],
        ),
    );
    thread::sleep(Duration::from_millis(700));
    assert!(run(
        &client_bin,
        &client_args(&alice, &directory.join("a.der"), vec!["fetch".into()])
    )
    .contains("after-bob-removed"));
    assert!(!run(
        &client_bin,
        &client_args(&bob, &directory.join("b.der"), vec!["fetch".into()])
    )
    .contains("after-bob-removed"));
    for relay in [&mut relay_a, &mut relay_b, &mut relay_c] {
        relay.kill().unwrap();
        relay.wait().unwrap();
    }
    let _ = alice_id;
}
