use std::{
    fs,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

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
    for _ in 0..100 {
        if path.exists() {
            return;
        }
        thread::sleep(Duration::from_millis(25));
    }
    panic!("relay did not create {}", path.display());
}

fn id(output: &str) -> String {
    output
        .lines()
        .find_map(|line| line.strip_prefix("identity created: "))
        .expect("identity output")
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
fn clients_exchange_mls_through_pinned_relays_and_follow_moved_after_restart() {
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
    wait_for(&directory.join("a.der"));
    wait_for(&directory.join("b.der"));
    // Certificate persistence precedes listener bind by a small amount.
    thread::sleep(Duration::from_millis(150));
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

    // State and relay identities are file-backed; restarting both sides must
    // preserve the established MLS group and recipient ACK state.
    relay_a.kill().unwrap();
    relay_a.wait().unwrap();
    relay_b.kill().unwrap();
    relay_b.wait().unwrap();
    relay_a = server(&server_bin, a, &directory, "a");
    relay_b = server(&server_bin, b, &directory, "b");
    thread::sleep(Duration::from_millis(300));
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
    wait_for(&directory.join("c.der"));
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
    for name in ["a.der", "b.der", "c.der"] {
        wait_for(&directory.join(name));
    }
    thread::sleep(Duration::from_millis(150));
    let alice = directory.join("alice.json");
    let bob = directory.join("bob.json");
    let carol = directory.join("carol.json");
    let alice_id = id(&run(
        &client_bin,
        &client_args(
            &alice,
            &directory.join("a.der"),
            vec!["create".into(), "--server".into(), a.into()],
        ),
    ));
    let bob_id = id(&run(
        &client_bin,
        &client_args(
            &bob,
            &directory.join("b.der"),
            vec!["create".into(), "--server".into(), b.into()],
        ),
    ));
    let carol_id = id(&run(
        &client_bin,
        &client_args(
            &carol,
            &directory.join("c.der"),
            vec!["create".into(), "--server".into(), c.into()],
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
    // Restart a current participant and its relay, then remove Bob as another
    // ordinary participant. The removal commit targets survivors only.
    relay_a.kill().unwrap();
    relay_a.wait().unwrap();
    relay_a = server(&server_bin, a, &directory, "a");
    thread::sleep(Duration::from_millis(200));
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
    thread::sleep(Duration::from_millis(200));
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
