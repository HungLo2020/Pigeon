use super::*;

pub(super) async fn dispatch(args: Args) -> Result<()> {
    let requested_create_server = match &args.command {
        Command::Create { server, .. } => Some(server.clone()),
        _ => None,
    };
    match args.command {
        Command::CreateLocal { display_name } | Command::Create { display_name, .. } => {
            if std::path::Path::new(&args.state).exists() {
                bail!("identity already exists: {}", args.state)
            };
            let mut signing_secret = [0; 32];
            let mut encryption_secret = [0; 32];
            OsRng.fill_bytes(&mut signing_secret);
            OsRng.fill_bytes(&mut encryption_secret);
            let signing = SigningKey::from_bytes(&signing_secret);
            let encryption = StaticSecret::from(encryption_secret);
            let device_signing = SigningKey::generate(&mut OsRng);
            let (mls_key_package, mls_signer, mls_storage) =
                create_mls_identity(&device_signing.verifying_key().to_bytes())?;
            let device = make_device(&signing, &device_signing, mls_key_package);
            let server = requested_create_server.unwrap_or_default();
            if display_name.trim().is_empty() {
                bail!("display name is required")
            }
            let card = make_card_named(
                &signing,
                &encryption,
                server.clone(),
                device.clone(),
                display_name.trim().into(),
            );
            let authorized_devices = AuthorizedDeviceSet {
                identity: identity_id(&card),
                revision: 1,
                devices: vec![device.clone()],
            };
            let state = State {
                state_version: 1,
                signing_secret,
                encryption_secret,
                card: card.clone(),
                contacts: vec![],
                nicknames: HashMap::new(),
                mls_storage,
                mls_conversations: HashMap::new(),
                direct_groups: HashMap::new(),
                mls_signer,
                device: device.clone(),
                authorized_devices,
                revocations: vec![],
                routing: None,
                pending_routing: vec![],
                cached_routes: HashMap::new(),
                groups: HashMap::new(),
                history: vec![],
                read_at: HashMap::new(),
            };
            if server.is_empty() {
                save(&args.state, &state)?;
                println!(
                    "identity created: {}",
                    hex::encode(identity_id(&state.card))
                );
                return Ok(());
            }
            response_ok(
                request(
                    &server,
                    &args.certificate,
                    Request::Register {
                        card,
                        device,
                        device_signature: vec![],
                    },
                )
                .await?,
            )?;
            let descriptor = relay_descriptor(&server, &args.certificate).await?;
            let route = make_routing(
                &signing,
                server.clone(),
                descriptor.identity,
                descriptor.tls_spki_fingerprint,
                1,
                0,
            );
            response_ok(
                request(
                    &server,
                    &args.certificate,
                    Request::PublishRouting(route.clone()),
                )
                .await?,
            )?;
            let mut state = state;
            state.routing = Some(route);
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
        Command::ConfigureRelay { server } => {
            let mut state = load(&args.state)?;
            if state.routing.is_some() {
                bail!("identity already has a configured relay")
            }
            let signing = SigningKey::from_bytes(&state.signing_secret);
            let encryption = StaticSecret::from(state.encryption_secret);
            let card = make_card(&signing, &encryption, server.clone(), state.device.clone());
            response_ok(
                request(
                    &server,
                    &args.certificate,
                    Request::Register {
                        card: card.clone(),
                        device: state.device.clone(),
                        device_signature: vec![],
                    },
                )
                .await?,
            )?;
            let descriptor = relay_descriptor(&server, &args.certificate).await?;
            let route = make_routing(
                &signing,
                server,
                descriptor.identity,
                descriptor.tls_spki_fingerprint,
                1,
                0,
            );
            response_ok(
                request(
                    &route.server,
                    &args.certificate,
                    Request::PublishRouting(route.clone()),
                )
                .await?,
            )?;
            state.card = card;
            state.routing = Some(route);
            save(&args.state, &state)?;
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
                    Request::Register {
                        card: state.card.clone(),
                        device: state.device.clone(),
                        device_signature: vec![],
                    },
                )
                .await?,
            )?;
            save(&args.state, &state)?;
            println!(
                "imported identity: {}",
                hex::encode(identity_id(&state.card))
            );
        }
        Command::PairRequest { identity, server } => {
            let identity = parse_identity(&identity)?;
            let pending_path = pairing_state_path(&args.state);
            if std::path::Path::new(&pending_path).exists() {
                bail!("a pairing request is already pending for this state path")
            }
            let device_signing = SigningKey::generate(&mut OsRng);
            let (mls_key_package, mls_signer, mls_storage) =
                create_mls_identity(&device_signing.verifying_key().to_bytes())?;
            let mut hpke_secret = [0; 32];
            let mut bootstrap_capability = [0; 32];
            let mut cancel_capability = [0; 32];
            OsRng.fill_bytes(&mut hpke_secret);
            OsRng.fill_bytes(&mut bootstrap_capability);
            OsRng.fill_bytes(&mut cancel_capability);
            let hpke_public = PublicKey::from(&StaticSecret::from(hpke_secret));
            let mut session_id = [0; 16];
            let mut nonce = [0; 16];
            OsRng.fill_bytes(&mut session_id);
            OsRng.fill_bytes(&mut nonce);
            let now = pairing_now();
            let request_value = PairingRequest {
                version: pigeon_shared::PAIRING_VERSION,
                identity,
                session_id,
                nonce,
                expires_at: now + 10 * 60,
                device: DeviceRecord {
                    identity,
                    device_id: device_signing.verifying_key().to_bytes(),
                    device_key: device_signing.verifying_key().to_bytes(),
                    mls_key_package,
                    authorization_revision: 0,
                    signature: vec![],
                },
                hpke_public_key: hpke_public.to_bytes(),
                bootstrap_capability_commitment: capability_commitment(&bootstrap_capability),
                cancel_capability_commitment: capability_commitment(&cancel_capability),
            };
            verify_pairing_request(&request_value, now)?;
            let artifact = PairingRelayArtifact {
                version: pigeon_shared::PAIRING_VERSION,
                identity,
                session_id,
                nonce,
                kind: PairingArtifactKind::PublicRequest,
                expires_at: request_value.expires_at,
                capability_commitment: request_value.cancel_capability_commitment,
                payload: encode(&request_value)?,
            };
            response_ok(
                request(
                    &server,
                    &args.certificate,
                    Request::PublishPairingArtifact(artifact),
                )
                .await?,
            )?;
            save_pairing(
                &pending_path,
                &PendingPairing {
                    request: request_value.clone(),
                    device_secret: device_signing.to_bytes(),
                    mls_signer,
                    mls_storage,
                    hpke_secret,
                    bootstrap_capability,
                    cancel_capability,
                    server,
                    cancelled: false,
                },
            )?;
            println!(
                "{}",
                STANDARD_NO_PAD.encode(serde_json::to_vec(&request_value)?)
            );
        }
        Command::PairApprove {
            request: request_text,
        } => {
            let mut state = load(&args.state)?;
            let pairing_request: PairingRequest =
                serde_json::from_slice(&STANDARD_NO_PAD.decode(request_text.trim())?)?;
            let now = pairing_now();
            verify_pairing_request(&pairing_request, now)?;
            if pairing_request.identity != identity_id(&state.card) {
                bail!("pairing request is for a different identity")
            }
            let root = SigningKey::from_bytes(&state.signing_secret);
            let revision = state.authorized_devices.revision + 1;
            let provisional =
                pigeon_shared::authorize_pairing_device(&root, &pairing_request.device, revision);
            if state
                .authorized_devices
                .devices
                .iter()
                .any(|device| device.device_id == provisional.device_id)
            {
                bail!("pairing device is already authorized")
            }
            let mut roster = state.authorized_devices.clone();
            roster.revision = revision;
            roster.devices.push(provisional);
            verify_device_set(&roster)?;
            let card = make_card_with_devices_named(
                &root,
                &StaticSecret::from(state.encryption_secret),
                state.card.server.clone(),
                roster.devices.clone(),
                state.card.revision + 1,
                state.card.display_name.clone(),
            );
            let bootstrap = BootstrapPayload {
                version: pigeon_shared::PAIRING_VERSION,
                root_secret: state.signing_secret,
                roster: roster.clone(),
                routing: state.routing.clone(),
                contacts: state.contacts.clone(),
                control_state: encode(&BootstrapControl {
                    encryption_secret: state.encryption_secret,
                    card: card.clone(),
                })?,
                // Existing device MLS private state and history are deliberately excluded.
                mls_bootstrap: vec![],
            };
            let encrypted = seal_bootstrap(&pairing_request, &bootstrap)?;
            let approval = make_pairing_approval(
                &root,
                &pairing_request,
                &roster,
                Sha256::digest(encode(&encrypted)?).into(),
            )?;
            verify_pairing_approval(&pairing_request, &approval, now)?;
            response_ok(
                request(
                    &state.card.server,
                    &args.certificate,
                    Request::Register {
                        card: card.clone(),
                        device: state.device.clone(),
                        device_signature: vec![],
                    },
                )
                .await?,
            )?;
            state.authorized_devices = roster.clone();
            state.card = card.clone();
            add_paired_device_to_mls_groups(&mut state, &args.certificate, &pairing_request.device)
                .await?;
            let approval_artifact = PairingRelayArtifact {
                version: pigeon_shared::PAIRING_VERSION,
                identity: pairing_request.identity,
                session_id: pairing_request.session_id,
                nonce: pairing_request.nonce,
                kind: PairingArtifactKind::Approval,
                expires_at: pairing_request.expires_at,
                capability_commitment: pairing_request.bootstrap_capability_commitment,
                payload: encode(&approval)?,
            };
            response_ok(
                request(
                    &state.card.server,
                    &args.certificate,
                    Request::PublishPairingArtifact(approval_artifact),
                )
                .await?,
            )?;
            let bootstrap_artifact = PairingRelayArtifact {
                version: pigeon_shared::PAIRING_VERSION,
                identity: pairing_request.identity,
                session_id: pairing_request.session_id,
                nonce: pairing_request.nonce,
                kind: PairingArtifactKind::EncryptedBootstrap,
                expires_at: pairing_request.expires_at,
                capability_commitment: pairing_request.bootstrap_capability_commitment,
                payload: encode(&(approval, encrypted))?,
            };
            response_ok(
                request(
                    &state.card.server,
                    &args.certificate,
                    Request::PublishPairingArtifact(bootstrap_artifact),
                )
                .await?,
            )?;
            save(&args.state, &state)?;
            println!("pairing approved");
        }
        Command::PairConsume => {
            let pending_path = pairing_state_path(&args.state);
            let pending = load_pairing(&pending_path)?;
            if pending.cancelled {
                bail!("pairing session is cancelled")
            }
            let now = pairing_now();
            verify_pairing_request(&pending.request, now)?;
            let response = request(
                &pending.server,
                &args.certificate,
                Request::FetchConsumePairingBootstrap {
                    identity: pending.request.identity,
                    session_id: pending.request.session_id,
                    capability: pending.bootstrap_capability,
                },
            )
            .await?;
            let Response::PairingArtifact(artifact) = response else {
                bail!("pairing bootstrap is not available: {response:?}")
            };
            if artifact.identity != pending.request.identity
                || artifact.session_id != pending.request.session_id
                || artifact.nonce != pending.request.nonce
                || artifact.kind != PairingArtifactKind::EncryptedBootstrap
                || artifact.capability_commitment != pending.request.bootstrap_capability_commitment
            {
                bail!("relay returned a mismatched pairing bootstrap envelope")
            }
            let (approval, encrypted): (PairingApproval, EncryptedBootstrap) =
                decode(&artifact.payload)?;
            verify_pairing_approval(&pending.request, &approval, now)?;
            if Sha256::digest(encode(&encrypted)?).as_slice() != approval.bootstrap_hash {
                bail!("pairing bootstrap does not match its signed approval")
            }
            let bootstrap = open_bootstrap(&pending.request, pending.hpke_secret, &encrypted)?;
            verify_device_set(&bootstrap.roster)?;
            if bootstrap.roster.identity != pending.request.identity
                || bootstrap.roster.revision != approval.roster_revision
                || Sha256::digest(encode(&bootstrap.roster)?).as_slice() != approval.roster_digest
                || !bootstrap
                    .roster
                    .devices
                    .iter()
                    .any(|device| device.device_id == pending.request.device.device_id)
            {
                bail!("bootstrap roster does not authorize this device")
            }
            let control: BootstrapControl = decode(&bootstrap.control_state)?;
            if identity_id(&control.card) != pending.request.identity {
                bail!("bootstrap card identity mismatch")
            }
            let state = State {
                state_version: 1,
                signing_secret: bootstrap.root_secret,
                encryption_secret: control.encryption_secret,
                card: control.card,
                contacts: bootstrap.contacts,
                nicknames: HashMap::new(),
                mls_storage: pending.mls_storage,
                mls_conversations: HashMap::new(),
                direct_groups: HashMap::new(),
                mls_signer: pending.mls_signer,
                device: approval.device,
                authorized_devices: bootstrap.roster,
                revocations: vec![],
                routing: bootstrap.routing,
                pending_routing: vec![],
                cached_routes: HashMap::new(),
                groups: HashMap::new(),
                history: vec![],
                read_at: HashMap::new(),
            };
            response_ok(
                request(
                    &state.card.server,
                    &args.certificate,
                    Request::Register {
                        card: state.card.clone(),
                        device: state.device.clone(),
                        device_signature: vec![],
                    },
                )
                .await?,
            )?;
            save(&args.state, &state)?;
            fs::remove_file(pending_path)?;
            println!("pairing complete");
        }
        Command::PairCancel => {
            let pending_path = pairing_state_path(&args.state);
            let mut pending = load_pairing(&pending_path)?;
            let response = request(
                &pending.server,
                &args.certificate,
                Request::CancelPairing {
                    identity: pending.request.identity,
                    session_id: pending.request.session_id,
                    capability: pending.cancel_capability,
                },
            )
            .await?;
            if !matches!(response, Response::PairingCancelled) {
                bail!("pairing cancellation was rejected: {response:?}")
            }
            pending.cancelled = true;
            save_pairing(&pending_path, &pending)?;
            println!("pairing cancelled");
        }
        Command::SetDisplayName { display_name } => {
            if display_name.trim().is_empty() {
                bail!("display name is required")
            }
            let mut state = load(&args.state)?;
            let root = SigningKey::from_bytes(&state.signing_secret);
            state.card = make_card_with_devices_named(
                &root,
                &StaticSecret::from(state.encryption_secret),
                state.card.server.clone(),
                state.authorized_devices.devices.clone(),
                state.card.revision + 1,
                display_name.trim().into(),
            );
            response_ok(
                request(
                    &state.card.server,
                    &args.certificate,
                    Request::Register {
                        card: state.card.clone(),
                        device: state.device.clone(),
                        device_signature: vec![],
                    },
                )
                .await?,
            )?;
            save(&args.state, &state)?;
        }
        Command::SetNickname { identity, nickname } => {
            let mut state = load(&args.state)?;
            let identity = parse_identity(&identity)?;
            if !state
                .contacts
                .iter()
                .any(|card| identity_id(card) == identity)
            {
                bail!("unknown contact")
            }
            let key = hex::encode(identity);
            match nickname.filter(|name| !name.trim().is_empty()) {
                Some(name) => {
                    state.nicknames.insert(key, name.trim().into());
                }
                None => {
                    state.nicknames.remove(&key);
                }
            }
            save(&args.state, &state)?;
        }
        Command::Card => println!("{}", card_text(&load(&args.state)?.card)?),
        Command::AddContact { card } => {
            let mut state = load(&args.state)?;
            let card = parse_card(&card)?;
            let contact_identity = identity_id(&card);
            if let Ok(Response::Routing(Some(route))) = request(
                &card.server,
                &args.certificate,
                Request::GetRouting {
                    identity: contact_identity,
                },
            )
            .await
            {
                validate_route_descriptor(&route, &pinned_relay_descriptor(&route).await?)?;
                // The signed route is independently verified.  A freshly
                // created card and its first route commonly share revision 1,
                // so equality is sufficient to cache the route needed for
                // cross-relay delivery.
                if route.identity == contact_identity && route.revision >= card.revision {
                    state
                        .cached_routes
                        .insert(hex::encode(contact_identity), route);
                }
            }
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
                let recipient_device = recipient
                    .devices
                    .first()
                    .context("contact has no authorized device")?;
                let package =
                    KeyPackageIn::tls_deserialize_exact(recipient_device.mls_key_package.clone())?
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
                        delivery_request(
                            &state,
                            &recipient,
                            pigeon_shared::MlsRecord {
                                recipient_identity: identity_id(&recipient),
                                sender_device: state.device.device_id,
                                target_devices: recipient
                                    .devices
                                    .iter()
                                    .map(|device| device.device_id)
                                    .collect(),
                                payload: wrap_mls_payload(&state, welcome.to_bytes()?)?,
                            },
                        )?,
                    )
                    .await?,
                )?;
                state
                    .mls_conversations
                    .insert(conversation.clone(), id.tls_serialize_detached()?);
                state
                    .direct_groups
                    .insert(hex::encode(id.as_slice()), conversation.clone());
                for device in &recipient.devices {
                    state
                        .mls_conversations
                        .insert(hex::encode(device.device_id), id.tls_serialize_detached()?);
                }
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
                    delivery_request(
                        &state,
                        &recipient,
                        pigeon_shared::MlsRecord {
                            recipient_identity: identity_id(&recipient),
                            sender_device: state.device.device_id,
                            target_devices: recipient
                                .devices
                                .iter()
                                .map(|device| device.device_id)
                                .collect(),
                            payload: wrap_mls_payload(&state, message)?,
                        },
                    )?,
                )
                .await?,
            )?;
            persist_mls(&mut state, &provider)?;
            state.history.push(LocalMessage {
                conversation: conversation.clone(),
                sender: hex::encode(identity_id(&state.card)),
                text,
                timestamp: message_time(),
            });
            save(&args.state, &state)?;
            println!("sent");
        }
        Command::GroupCreate { group, members } => {
            let mut state = load(&args.state)?;
            if state.groups.contains_key(&group) {
                bail!("group already exists")
            }
            let members: Vec<[u8; 32]> = members
                .iter()
                .map(|member| parse_identity(member))
                .collect::<Result<_>>()?;
            if members.is_empty()
                || members
                    .iter()
                    .any(|member| *member == identity_id(&state.card))
            {
                bail!("group members must be one or more contacts")
            }
            let contacts: Vec<ContactCard> = members
                .iter()
                .map(|member| contact_for(&state, *member))
                .collect::<Result<_>>()?;
            let (provider, signer) = mls_runtime(&state)?;
            let config = MlsGroupCreateConfig::builder()
                .ciphersuite(Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519)
                .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
                .use_ratchet_tree_extension(true)
                .build();
            let credential = CredentialWithKey {
                // MLS leaves are device endpoints.  Root identities are used
                // only for the local group membership projection.
                credential: BasicCredential::new(state.device.device_id.to_vec()).into(),
                signature_key: signer.to_public_vec().into(),
            };
            let mut mls_group = MlsGroup::new(&provider, &signer, &config, credential)?;
            let mut packages = Vec::new();
            for device in contacts.iter().flat_map(|contact| contact.devices.iter()) {
                let package = KeyPackageIn::tls_deserialize_exact(device.mls_key_package.clone())?
                    .validate(provider.crypto(), ProtocolVersion::Mls10)?;
                packages.push(package);
            }
            let (_, welcome, _) = mls_group.add_members(&provider, &signer, &packages)?;
            mls_group.merge_pending_commit(&provider)?;
            let mut identities = members;
            identities.push(identity_id(&state.card));
            let group_id = mls_group.group_id().tls_serialize_detached()?;
            deliver_group_payload(&state, &args.certificate, &identities, welcome.to_bytes()?)
                .await?;
            let canonical_group = hex::encode(mls_group.group_id().as_slice());
            state.groups.insert(
                group.clone(),
                GroupState {
                    group_id: group_id.clone(),
                    members: identities.clone(),
                },
            );
            state.groups.insert(
                canonical_group.clone(),
                GroupState {
                    group_id,
                    members: identities,
                },
            );
            persist_mls(&mut state, &provider)?;
            save(&args.state, &state)?;
            println!("group created: {group} {canonical_group}");
        }
        Command::GroupSend { group, text } => {
            let mut state = load(&args.state)?;
            let group_state = state.groups.get(&group).context("unknown group")?.clone();
            if !group_state.members.contains(&identity_id(&state.card)) {
                bail!("this identity is not a group member")
            }
            let (provider, signer) = mls_runtime(&state)?;
            let group_id = GroupId::tls_deserialize_exact(group_state.group_id)?;
            let mut mls_group = MlsGroup::load(provider.storage(), &group_id)?
                .context("MLS group state missing")?;
            let payload = mls_group
                .create_message(&provider, &signer, text.as_bytes())?
                .to_bytes()?;
            deliver_group_payload(&state, &args.certificate, &group_state.members, payload).await?;
            persist_mls(&mut state, &provider)?;
            state.history.push(LocalMessage {
                // Store the protocol group ID, not a user supplied alias.
                // Incoming group messages use this same stable identifier.
                conversation: format!("group:{}", hex::encode(mls_group.group_id().as_slice())),
                sender: hex::encode(identity_id(&state.card)),
                text,
                timestamp: message_time(),
            });
            save(&args.state, &state)?;
            println!("sent");
        }
        Command::GroupAdd { group, member } => {
            let mut state = load(&args.state)?;
            let mut group_state = state.groups.get(&group).context("unknown group")?.clone();
            let member = parse_identity(&member)?;
            if !group_state.members.contains(&identity_id(&state.card)) {
                bail!("only a current participant may change membership")
            }
            if group_state.members.contains(&member) {
                bail!("identity is already a member")
            }
            let contact = contact_for(&state, member)?;
            let (provider, signer) = mls_runtime(&state)?;
            let group_id = GroupId::tls_deserialize_exact(group_state.group_id.clone())?;
            let mut mls_group = MlsGroup::load(provider.storage(), &group_id)?
                .context("MLS group state missing")?;
            let mut packages = Vec::new();
            for device in &contact.devices {
                let package = KeyPackageIn::tls_deserialize_exact(device.mls_key_package.clone())?
                    .validate(provider.crypto(), ProtocolVersion::Mls10)?;
                packages.push(package);
            }
            let (commit, welcome, _) = mls_group.add_members(&provider, &signer, &packages)?;
            mls_group.merge_pending_commit(&provider)?;
            deliver_group_payload(&state, &args.certificate, &[member], welcome.to_bytes()?)
                .await?;
            deliver_group_payload(
                &state,
                &args.certificate,
                &group_state.members,
                commit.to_bytes()?,
            )
            .await?;
            group_state.members.push(member);
            for saved in state.groups.values_mut() {
                if saved.group_id == group_state.group_id {
                    saved.members = group_state.members.clone();
                }
            }
            state.groups.insert(group, group_state);
            persist_mls(&mut state, &provider)?;
            save(&args.state, &state)?;
            println!("member added");
        }
        Command::GroupRemove { group, member } => {
            let mut state = load(&args.state)?;
            let mut group_state = state.groups.get(&group).context("unknown group")?.clone();
            let member = parse_identity(&member)?;
            if !group_state.members.contains(&identity_id(&state.card)) {
                bail!("only a current participant may change membership")
            }
            if member == identity_id(&state.card) || !group_state.members.contains(&member) {
                bail!("identity is not a removable group member")
            }
            let (provider, signer) = mls_runtime(&state)?;
            let group_id = GroupId::tls_deserialize_exact(group_state.group_id.clone())?;
            let mut mls_group = MlsGroup::load(provider.storage(), &group_id)?
                .context("MLS group state missing")?;
            let contact = contact_for(&state, member)?;
            let device_ids: Vec<Vec<u8>> = contact
                .devices
                .iter()
                .map(|device| device.device_id.to_vec())
                .collect();
            let leaves: Vec<_> = mls_group
                .members()
                .filter(|leaf| {
                    device_ids.iter().any(|device_id| {
                        leaf.credential == BasicCredential::new(device_id.clone()).into()
                    })
                })
                .map(|leaf| leaf.index)
                .collect();
            if leaves.is_empty() {
                bail!("identity has no MLS device leaves")
            }
            let (commit, _, _) = mls_group.remove_members(&provider, &signer, &leaves)?;
            mls_group.merge_pending_commit(&provider)?;
            group_state.members = identities_in_mls_group(&state, &mls_group);
            deliver_group_payload(
                &state,
                &args.certificate,
                &group_state.members,
                commit.to_bytes()?,
            )
            .await?;
            for saved in state.groups.values_mut() {
                if saved.group_id == group_state.group_id {
                    saved.members = group_state.members.clone();
                }
            }
            state.groups.insert(group, group_state);
            persist_mls(&mut state, &provider)?;
            save(&args.state, &state)?;
            println!("member removed");
        }
        Command::RevokeDevice { device_id } => {
            let mut state = load(&args.state)?;
            let bytes = hex::decode(device_id)?;
            let device_id: [u8; 32] = bytes
                .try_into()
                .map_err(|_| anyhow::anyhow!("device ID must be 32 bytes of hexadecimal"))?;
            if device_id == state.device.device_id {
                bail!("cannot revoke the current device from itself")
            }
            if !state
                .authorized_devices
                .devices
                .iter()
                .any(|device| device.device_id == device_id)
            {
                bail!("device is not in this identity's authorized roster")
            }
            let root = SigningKey::from_bytes(&state.signing_secret);
            let revision = state
                .revocations
                .iter()
                .map(|revocation| revocation.revision)
                .max()
                .unwrap_or(0)
                + 1;
            let revocation = make_revocation(&root, device_id, revision);
            response_ok(
                request(
                    &state.card.server,
                    &args.certificate,
                    Request::RevokeDevice(revocation.clone()),
                )
                .await?,
            )?;
            let surviving_devices: Vec<[u8; 32]> = state
                .authorized_devices
                .devices
                .iter()
                .filter(|device| device.device_id != device_id)
                .map(|device| device.device_id)
                .collect();
            // A device credential is also the MLS BasicCredential.  Remove it
            // from every direct group held by this surviving device and relay
            // the resulting MLS Commit to the peer and any other surviving
            // local devices.  The relay sees only the opaque commit.
            let (provider, signer) = mls_runtime(&state)?;
            for group_bytes in state.mls_conversations.values() {
                let group_id = GroupId::tls_deserialize_exact(group_bytes)?;
                let mut group = MlsGroup::load(provider.storage(), &group_id)?
                    .context("persisted MLS group missing")?;
                let revoked_leaf = group
                    .members()
                    .find(|member| {
                        member.credential == BasicCredential::new(device_id.to_vec()).into()
                    })
                    .map(|member| member.index);
                let Some(revoked_leaf) = revoked_leaf else {
                    continue;
                };
                let (commit, _, _) = group.remove_members(&provider, &signer, &[revoked_leaf])?;
                group.merge_pending_commit(&provider)?;
                let payload = commit.to_bytes()?;
                for contact in &state.contacts {
                    if !contact.devices.iter().any(|device| {
                        group.members().any(|member| {
                            member.credential
                                == BasicCredential::new(device.device_id.to_vec()).into()
                        })
                    }) {
                        continue;
                    }
                    response_ok(
                        request(
                            &state.card.server,
                            &args.certificate,
                            Request::SendMls(pigeon_shared::MlsRecord {
                                recipient_identity: identity_id(contact),
                                sender_device: state.device.device_id,
                                target_devices: contact
                                    .devices
                                    .iter()
                                    .map(|device| device.device_id)
                                    .collect(),
                                payload: wrap_mls_payload(&state, payload.clone())?,
                            }),
                        )
                        .await?,
                    )?;
                }
                let local_targets: Vec<_> = surviving_devices
                    .iter()
                    .copied()
                    .filter(|target| *target != state.device.device_id)
                    .collect();
                if !local_targets.is_empty() {
                    response_ok(
                        request(
                            &state.card.server,
                            &args.certificate,
                            Request::SendMls(pigeon_shared::MlsRecord {
                                recipient_identity: identity_id(&state.card),
                                sender_device: state.device.device_id,
                                target_devices: local_targets,
                                payload: wrap_mls_payload(&state, payload)?,
                            }),
                        )
                        .await?,
                    )?;
                }
            }
            persist_mls(&mut state, &provider)?;
            state.revocations.push(revocation);
            state
                .authorized_devices
                .devices
                .retain(|device| device.device_id != device_id);
            state.authorized_devices.revision += 1;
            state.card = make_card_with_devices_named(
                &root,
                &StaticSecret::from(state.encryption_secret),
                state.card.server.clone(),
                state.authorized_devices.devices.clone(),
                state.card.revision + 1,
                state.card.display_name.clone(),
            );
            save(&args.state, &state)?;
            println!("device revoked");
        }
        Command::Migrate {
            server,
            previous_certificate,
        } => {
            let mut state = load(&args.state)?;
            if state.card.server == server {
                println!("already using {server}");
                return Ok(());
            }
            let root = SigningKey::from_bytes(&state.signing_secret);
            let current_revision = state
                .routing
                .as_ref()
                .map(|route| route.revision)
                .unwrap_or(state.card.revision);
            let card = make_card_with_devices_named(
                &root,
                &StaticSecret::from(state.encryption_secret),
                server.clone(),
                state.authorized_devices.devices.clone(),
                state.card.revision + 1,
                state.card.display_name.clone(),
            );
            // Register first: a route is never published to a destination that
            // has not accepted the identity/device records.
            response_ok(
                request(
                    &server,
                    &args.certificate,
                    Request::Register {
                        card: card.clone(),
                        device: state.device.clone(),
                        device_signature: vec![],
                    },
                )
                .await?,
            )?;
            let descriptor = relay_descriptor(&server, &args.certificate).await?;
            let route = make_routing(
                &root,
                server.clone(),
                descriptor.identity,
                descriptor.tls_spki_fingerprint,
                current_revision + 1,
                current_revision,
            );
            response_ok(
                request(
                    &server,
                    &args.certificate,
                    Request::PublishRouting(route.clone()),
                )
                .await?,
            )?;
            let previous_certificate = previous_certificate.as_deref().unwrap_or(&args.certificate);
            if request(
                &state.card.server,
                previous_certificate,
                Request::PublishRouting(route.clone()),
            )
            .await
            .and_then(response_ok)
            .is_err()
            {
                state.pending_routing.push(route.clone());
            }
            // Contact relays are non-authoritative caches of the same signed
            // record. This provides a reachable propagation path when the old
            // relay is offline without introducing a global directory.
            // Reachable contacts learn this via their cached signed route and
            // normal sync; guessing another relay's TLS certificate here
            // would weaken pinning.
            state.card = card;
            state.routing = Some(route);
            save(&args.state, &state)?;
            println!("migrated to {server}");
        }
        Command::MarkRead { conversation } => {
            let mut state = load(&args.state)?;
            state.read_at.insert(conversation, message_time());
            save(&args.state, &state)?;
        }
        Command::Fetch => {
            let mut state = load(&args.state)?;
            for contact in state.contacts.clone() {
                let identity = identity_id(&contact);
                let known_route = state.cached_routes.get(&hex::encode(identity)).cloned();
                let route_response = match known_route {
                    Some(route) => pinned_request(&route, Request::GetRouting { identity }).await,
                    None => {
                        request(
                            &contact.server,
                            &args.certificate,
                            Request::GetRouting { identity },
                        )
                        .await
                    }
                };
                if let Ok(Response::Routing(Some(route))) = route_response {
                    validate_route_descriptor(&route, &pinned_relay_descriptor(&route).await?)?;
                    let key = hex::encode(identity);
                    if route.identity == identity
                        && should_replace_route(state.cached_routes.get(&key), &route)
                    {
                        state.cached_routes.insert(key, route);
                    }
                }
            }
            let revocations = match request(
                &state.card.server,
                &args.certificate,
                Request::GetRevocations {
                    identity: identity_id(&state.card),
                },
            )
            .await?
            {
                Response::Revocations(revocations) => revocations,
                Response::Error(error) => bail!("server rejected request: {error}"),
                _ => bail!("unexpected revocation synchronization response"),
            };
            for revocation in revocations {
                pigeon_shared::verify_revocation(&revocation)?;
                if !state
                    .revocations
                    .iter()
                    .any(|known| known.device_id == revocation.device_id)
                {
                    state
                        .authorized_devices
                        .devices
                        .retain(|device| device.device_id != revocation.device_id);
                    state.revocations.push(revocation);
                }
            }
            if state
                .revocations
                .iter()
                .any(|revocation| revocation.device_id == state.device.device_id)
            {
                save(&args.state, &state)?;
                bail!("this device has been revoked and cannot synchronize")
            }
            match request(
                &state.card.server,
                &args.certificate,
                Request::Fetch {
                    identity: identity_id(&state.card),
                    device_id: state.device.device_id,
                    known_routing_revision: state.card.revision,
                },
            )
            .await?
            {
                Response::MlsMessages(records) => {
                    let (provider, _signer) = mls_runtime(&state)?;
                    let record_ids: Vec<i64> = records.iter().map(|(id, _)| *id).collect();
                    let config = MlsGroupCreateConfig::builder()
                        .ciphersuite(Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519)
                        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
                        .use_ratchet_tree_extension(true)
                        .build();
                    for (_record_id, record) in records {
                        let (mls_payload, discovery) = unwrap_mls_payload(record.payload)?;
                        if let Some((card, route)) = discovery {
                            pigeon_shared::verify_card(&card)?;
                            if !card
                                .devices
                                .iter()
                                .any(|device| device.device_id == record.sender_device)
                            {
                                bail!("sender contact card does not authorize MLS sender device")
                            }
                            let sender_identity = identity_id(&card);
                            if sender_identity == identity_id(&state.card) {
                                bail!("received MLS record claims this account as sender")
                            }
                            match state
                                .contacts
                                .iter()
                                .position(|contact| identity_id(contact) == sender_identity)
                            {
                                Some(index) if card.revision > state.contacts[index].revision => {
                                    state.contacts[index] = card.clone();
                                }
                                None => state.contacts.push(card.clone()),
                                _ => {}
                            }
                            if route.identity != sender_identity || route.server != card.server {
                                bail!("sender routing record does not match sender contact card")
                            }
                            validate_route_descriptor(
                                &route,
                                &pinned_relay_descriptor(&route).await?,
                            )?;
                            let route_key = hex::encode(sender_identity);
                            if should_replace_route(state.cached_routes.get(&route_key), &route) {
                                state.cached_routes.insert(route_key, route);
                            }
                        }
                        let incoming = MlsMessageIn::tls_deserialize_exact(mls_payload.clone())?;
                        match incoming.extract() {
                            MlsMessageBodyIn::Welcome(welcome) => {
                                let group = StagedWelcome::new_from_welcome(
                                    &provider,
                                    config.join_config(),
                                    welcome,
                                    None,
                                )?
                                .into_group(&provider)?;
                                let group_id = group.group_id().tls_serialize_detached()?;
                                state
                                    .mls_conversations
                                    .insert(hex::encode(record.sender_device), group_id.clone());
                                if let Some(contact) = state.contacts.iter().find(|contact| {
                                    contact
                                        .devices
                                        .iter()
                                        .any(|device| device.device_id == record.sender_device)
                                }) {
                                    // The sender device maps this Welcome to
                                    // the stable contact identity so a reply
                                    // reuses the established MLS group.
                                    state
                                        .mls_conversations
                                        .insert(hex::encode(identity_id(contact)), group_id);
                                    state.direct_groups.insert(
                                        hex::encode(group.group_id().as_slice()),
                                        hex::encode(identity_id(contact)),
                                    );
                                }
                                let mut members = vec![identity_id(&state.card)];
                                for contact in &state.contacts {
                                    if contact.devices.iter().any(|device| {
                                        group.members().any(|leaf| {
                                            leaf.credential
                                                == BasicCredential::new(device.device_id.to_vec())
                                                    .into()
                                        })
                                    }) {
                                        members.push(identity_id(contact));
                                    }
                                }
                                members.sort();
                                members.dedup();
                                state
                                    .groups
                                    .entry(hex::encode(group.group_id().as_slice()))
                                    .or_insert(GroupState {
                                        group_id: group.group_id().tls_serialize_detached()?,
                                        members,
                                    });
                            }
                            MlsMessageBodyIn::PrivateMessage(_)
                            | MlsMessageBodyIn::PublicMessage(_) => {
                                let key = hex::encode(record.sender_device);
                                let protocol = MlsMessageIn::tls_deserialize_exact(mls_payload)?
                                    .try_into_protocol_message()?;
                                let protocol_group = hex::encode(protocol.group_id().as_slice());
                                let group_bytes = state
                                    .groups
                                    .get(&protocol_group)
                                    .map(|group| group.group_id.clone())
                                    .or_else(|| state.mls_conversations.get(&key).cloned())
                                    .context("received MLS message before Welcome")?;
                                let group_id = GroupId::tls_deserialize_exact(group_bytes)?;
                                let mut group = MlsGroup::load(provider.storage(), &group_id)?
                                    .context("persisted MLS group missing")?;
                                let processed = group.process_message(&provider, protocol)?;
                                match processed.into_content() {
                                    ProcessedMessageContent::ApplicationMessage(message) => {
                                        let conversation = if let Some(contact) =
                                            state.direct_groups.get(&protocol_group).cloned()
                                        {
                                            contact
                                        } else if state.groups.contains_key(&protocol_group) {
                                            format!("group:{protocol_group}")
                                        } else {
                                            state
                                                .contacts
                                                .iter()
                                                .find(|contact| {
                                                    contact.devices.iter().any(|device| {
                                                        device.device_id == record.sender_device
                                                    })
                                                })
                                                .map(|contact| hex::encode(identity_id(contact)))
                                                .unwrap_or(key.clone())
                                        };
                                        let text = String::from_utf8(message.into_bytes())?;
                                        println!("{}: {}", key, text);
                                        state.history.push(LocalMessage {
                                            conversation,
                                            sender: key,
                                            text,
                                            timestamp: message_time(),
                                        });
                                    }
                                    ProcessedMessageContent::StagedCommitMessage(staged) => {
                                        group.merge_staged_commit(&provider, *staged)?;
                                        let members = identities_in_mls_group(&state, &group);
                                        let group_id = group.group_id().tls_serialize_detached()?;
                                        for group_state in state.groups.values_mut() {
                                            if group_state.group_id == group_id {
                                                group_state.members = members.clone();
                                            }
                                        }
                                    }
                                    ProcessedMessageContent::OwnPendingCommit => {
                                        group.merge_pending_commit(&provider)?;
                                    }
                                    _ => {}
                                }
                            }
                            _ => bail!("unexpected MLS relay message"),
                        }
                    }
                    persist_mls(&mut state, &provider)?;
                    save(&args.state, &state)?;
                    if !record_ids.is_empty() {
                        response_ok(
                            request(
                                &state.card.server,
                                &args.certificate,
                                Request::Acknowledge {
                                    device_id: state.device.device_id,
                                    record_ids,
                                    signature: vec![],
                                },
                            )
                            .await?,
                        )?;
                    }
                }
                Response::Error(error) => bail!("server rejected request: {error}"),
                Response::Moved(route) => {
                    validate_route_descriptor(&route, &pinned_relay_descriptor(&route).await?)?;
                    if route.identity != identity_id(&state.card)
                        || route.revision
                            <= state
                                .routing
                                .as_ref()
                                .map(|route| route.revision)
                                .unwrap_or(0)
                    {
                        bail!("received stale or unrelated MOVED record")
                    }
                    let root = SigningKey::from_bytes(&state.signing_secret);
                    state.card = make_card_with_devices_named(
                        &root,
                        &StaticSecret::from(state.encryption_secret),
                        route.server.clone(),
                        state.authorized_devices.devices.clone(),
                        route.revision,
                        state.card.display_name.clone(),
                    );
                    state.routing = Some(route);
                    save(&args.state, &state)?;
                    println!("switched to the newer server route; run fetch again");
                }
                _ => bail!("unexpected server response"),
            }
        }
    };
    Ok(())
}

fn pairing_state_path(state: &str) -> String {
    format!("{state}.pairing")
}

fn load_pairing(path: &str) -> Result<PendingPairing> {
    serde_json::from_slice(&fs::read(path).with_context(|| format!("read pairing state {path}"))?)
        .with_context(|| format!("decode pairing state {path}"))
}

fn save_pairing(path: &str, pending: &PendingPairing) -> Result<()> {
    fs::write(path, serde_json::to_vec_pretty(pending)?)
        .with_context(|| format!("write pairing state {path}"))?;
    Ok(())
}

fn pairing_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}

async fn add_paired_device_to_mls_groups(
    state: &mut State,
    certificate: &str,
    device: &DeviceRecord,
) -> Result<()> {
    let (provider, signer) = mls_runtime(state)?;
    let mut group_ids: Vec<Vec<u8>> = state
        .mls_conversations
        .values()
        .cloned()
        .chain(state.groups.values().map(|group| group.group_id.clone()))
        .collect();
    group_ids.sort();
    group_ids.dedup();
    for group_bytes in group_ids {
        let group_id = GroupId::tls_deserialize_exact(group_bytes)?;
        let mut group = MlsGroup::load(provider.storage(), &group_id)?
            .context("persisted MLS group missing while adding paired device")?;
        if group.members().any(|member| {
            member.credential == BasicCredential::new(device.device_id.to_vec()).into()
        }) {
            continue;
        }
        let package = KeyPackageIn::tls_deserialize_exact(device.mls_key_package.clone())?
            .validate(provider.crypto(), ProtocolVersion::Mls10)?;
        let (commit, welcome, _) = group.add_members(&provider, &signer, &[package])?;
        group.merge_pending_commit(&provider)?;
        response_ok(
            request(
                &state.card.server,
                certificate,
                Request::SendMls(pigeon_shared::MlsRecord {
                    recipient_identity: identity_id(&state.card),
                    sender_device: state.device.device_id,
                    target_devices: vec![device.device_id],
                    payload: wrap_mls_payload(state, welcome.to_bytes()?)?,
                }),
            )
            .await?,
        )?;
        let members = identities_in_mls_group(state, &group);
        deliver_group_payload(state, certificate, &members, commit.to_bytes()?).await?;
    }
    persist_mls(state, &provider)
}
