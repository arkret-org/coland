fn retained_actor_devices(store: &arkret_bridge_runtime::FileAuthoringStore, actor: &ActorId) -> std::collections::BTreeMap<String, String> {
    use arkret_bridge_runtime::AuthoringStore as _;
    use chacha20poly1305::aead::{Aead as _, KeyInit as _, Payload};
    use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
    let cipher = XChaCha20Poly1305::new(&Key::from([0x53; 32]));
    store.entries_with_prefix("managed-device/v1/").unwrap().into_iter().filter_map(|(key, raw)| {
        let parts: Vec<_> = raw.split('.').collect();
        let nonce = arkret::base64url_decode(parts[1]).unwrap();
        let ciphertext = arkret::base64url_decode(parts[2]).unwrap();
        let plain = cipher.decrypt(&XNonce::try_from(nonce.as_slice()).unwrap(), Payload { msg: &ciphertext, aad: key.as_bytes() }).unwrap();
        let value: Value = serde_json::from_slice(&plain).unwrap();
        (value["plan"]["actor_id"] == json!(actor)).then(|| (key, arkret_canonical::canonical_digest(raw.as_bytes())))
    }).collect()
}

async fn query_managed_actor(
    fixture: &Fixture,
    service: &NativeService,
    actor: &ActorId,
) -> arkret_http_client::Result<arkret_models_integration::AppletActorView> {
    let client = arkret_http_client::Client::builder(service.package.base_url.parse().unwrap())
        .http_client(native_http_client(std::time::Duration::from_secs(30)))
        .retry(arkret_http_client::RetryConfig::disabled())
        .http_message_signer(arkret_http_client::HttpMessageSigner::new(
            fixture.state.service_verification_method("notary-key").unwrap().to_string(),
            fixture.state.notary_signing_key().as_ref().clone(),
        ))
        .build().unwrap();
    client.applet_actor(&fixture.state.service_core_id(), &service.package.service_id, actor).await
}

// Simulate a crash after the real preview and durable request save, before any effect.
async fn freeze_manager_revoke_request(
    fixture: &Fixture,
    package: &AppletPackage,
    candidate: &RealmActorCreatePayload,
) -> (
    AppletRevokeRequestBody,
    arkret_wire::EventAdmissionSubmission,
) {
    let mode = arkret_wire::AppletRevokeMode::RevokeRuntimeOnly;
    let reason = arkret_wire::ReasonCode::from_wire("applet_revoked");
    let preview_request = AppletRevokePreviewRequestBody {
        service_id: package.service_id.clone(),
        effective_scope: candidate.creation_scope.clone(),
        reason_code: reason.clone(),
        revoke_mode: mode,
    };
    let (status, body) = fixture
        .admin_post(
            &format!("/_arkret/self/applets/{}/revoke/preview", package.applet_id),
            arkret_wire::ServiceOperationId::SELF_APPLET_REVOKE_COMMAND_PREVIEW_V1,
            &json!(preview_request),
            None,
        )
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "pre-transfer revoke preview: {body}"
    );
    let preview: AppletRevokePreviewOutcome = serde_json::from_value(body).unwrap();
    let request = AppletRevokeRequestBody {
        service_id: package.service_id.clone(),
        revoke_plan_digest: arkret_wire::Hash::new(arkret_canonical::canonical_sha256(&preview.revoke_plan).unwrap()).unwrap(),
        effective_scope: candidate.creation_scope.clone(), reason_code: reason, revoke_mode: mode,
        capability_revoke_events: preview.revoke_plan.capability_revocations.iter().map(|intent| {
            arkret_wire::EventAdmissionSubmission::new(fixture.admin_event(EventKind::CapabilityRevoke,
                candidate.creation_scope.clone(), json!({"grant_id":intent.grant_id,"expected_revision":intent.expected_revision,"reason":intent.reason_code})))
        }).collect(),
        membership_state_events: preview.revoke_plan.membership_removals.iter().map(|intent| {
            arkret_wire::EventAdmissionSubmission::new(fixture.admin_event(EventKind::MemberState,
                candidate.creation_scope.clone(), json!({"member_id":intent.member_id,"membership":intent.membership,"reason":intent.reason_code})))
        }).collect(),
    };
    let effect = request
        .membership_state_events
        .iter()
        .find(|submission| {
            submission.event.payload.get("member_id") == Some(&json!(candidate.actor_id))
        })
        .unwrap()
        .clone();
    let store = PgAppletStore {
        pool: fixture.pool.clone(),
    };
    let scope_key = coland_storage::applet_effective_scope_key(&candidate.creation_scope).unwrap();
    let expected = store
        .get(
            package.applet_id.as_str(),
            package.service_id.as_str(),
            &scope_key,
        )
        .await
        .unwrap()
        .unwrap();
    let mut replacement = expected.clone();
    let mut steps: Vec<_> = request.capability_revoke_events.iter().map(|submission| ("capability_revoke_event", submission))
        .chain(request.membership_state_events.iter().map(|submission| ("membership_state_event", submission)))
        .map(|(effect_kind, submission)| json!({"effect_kind":effect_kind,"submitted_event_id":submission.event.event_id,"status":"pending"})).collect();
    steps.push(json!({"effect_kind":"local_applet_fence","effect_ref":package.applet_id,"status":"pending"}));
    replacement["revoke_execution"] = json!({
        "principal_id":fixture.state.service_id(),"admin_actor_id":effect.event.actor_id.to_string(),
        "idempotency_key":"manager-race-frozen-revoke","request_digest":arkret_canonical::canonical_sha256(&request).unwrap(),
        "request":request,"revoke_plan":preview.revoke_plan,
        "outcome":{"operation_id":format!("ak:operation:{}",uuid::Uuid::now_v7()),"revoke_plan_digest":request.revoke_plan_digest,"status":"in_progress","steps":steps,"revoked_refs":[],"rejections":[]},
    });
    let _: arkret_models_integration::AppletRevokeOutcome =
        serde_json::from_value(replacement["revoke_execution"]["outcome"].clone()).unwrap();
    assert!(
        store
            .compare_and_swap(
                package.applet_id.as_str(),
                package.service_id.as_str(),
                &scope_key,
                &expected,
                replacement
            )
            .await
            .unwrap()
    );
    (request, effect)
}

// Same Applet, two Services, complete durable custody retained in a shared backend.
#[allow(clippy::too_many_arguments, reason = "The fixture keeps independent signed originals, accepted references and source-time coordinates explicit.")]
async fn run_manager_runtime_transfer(
    factory: &AppletAuthoringFactory,
    previous: &NativeService,
    candidate: &RealmActorCreatePayload,
    previous_config: &arkret_bridge_runtime::Config,
    client: &arkret::http_client::Client,
    previous_runtime: &arkret_bridge_runtime::managed_device::ManagedDeviceRuntime,
    previous_device: &arkret_bridge_runtime::managed_device::ManagedDevice,
    retained_path: &std::path::Path,
    previous_edge: &Arc<arkret_bridge_runtime::ArkretEdge>,
) {
    use arkret_bridge_runtime::managed_device::{ManagedDeviceRuntime, ManagementTransferPlan};
    use arkret_bridge_runtime::{ArkretEdge, AuthoringJournal, AuthoringStore, FileAuthoringStore};
    use arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequest;
    struct LostManagerReceipt {
        inner: FileAuthoringStore,
        armed: Arc<std::sync::atomic::AtomicBool>,
    }
    impl AuthoringStore for LostManagerReceipt {
        fn load(&self, key: &str) -> arkret_bridge_runtime::Result<Option<String>> {
            self.inner.load(key)
        }
        fn entries_with_prefix(
            &self,
            prefix: &str,
        ) -> arkret_bridge_runtime::Result<Vec<(String, String)>> {
            self.inner.entries_with_prefix(prefix)
        }
        fn compare_exchange_batch(
            &self,
            expected: &[(String, Option<String>)],
            writes: &[(String, Option<String>)],
        ) -> arkret_bridge_runtime::Result<bool> {
            if writes
                .iter()
                .any(|(key, _)| key.starts_with("managed-manager-origin/v1/"))
                && self.armed.swap(false, std::sync::atomic::Ordering::SeqCst)
            {
                return Err(arkret_bridge_runtime::BridgeError::App(
                    "injected lost manager receipt".into(),
                ));
            }
            self.inner.compare_exchange_batch(expected, writes)
        }
    }
    let fixture = &factory.fixture;
    let actor = &candidate.actor_id;
    let view = boxed_step(|| query_managed_actor(fixture, previous, actor)).await.unwrap();
    assert_eq!(view.actor_id.as_ref(), Some(actor));
    // A second subject stays on the original Service throughout the batch.
    let author = arkret_bridge_runtime::managed_actor_authoring::ManagedActorAuthoringService::new(previous_edge.clone()).unwrap();
    let external = arkret::GhostExternalTuple {
        protocol: "fixture".into(), instance_id: "bridge-native".into(), external_id: "stays-on-previous-service".into(),
    };
    let prepared = boxed_step(|| author.prepare_ghost_in_scope(&candidate.applet_id, &candidate.creation_scope, &external, None)).await.unwrap();
    let arkret_bridge_runtime::PreparedGhost::Create(other_command) = prepared else { panic!("new companion Ghost required"); };
    let other_candidate: RealmActorCreatePayload = serde_json::from_value(serde_json::to_value(&other_command.create_event.payload).unwrap()).unwrap();
    let result = boxed_step(|| previous_edge.submit_managed_creation(&other_command)).await.unwrap();
    assert!(matches!(result, arkret::AuthoritySubmitOutcome::Accepted { .. }));
    boxed_step(|| realm_actor_mls_fixture::business_parent(fixture, &previous.package, &other_candidate.actor_id, &candidate.creation_scope)).await;
    let other_device = boxed_step(|| previous_runtime.device_for_actor(&other_candidate.actor_id)).await.unwrap();
    boxed_step(|| previous_runtime.ensure_realm_membership(&other_device)).await.unwrap();
    let other_before = snapshot(fixture, &other_candidate.actor_id).await;

    let human_group = boxed_step(|| realm_actor_mls_fixture::human_admits_runtime(fixture, previous_device)).await;
    let old_reader = boxed_step(|| previous_runtime.open_reader(previous_device)).await.unwrap();
    let welcome = boxed_step(|| previous_runtime.poll_welcome_queue(previous_device, &old_reader)).await.unwrap();
    assert_eq!(welcome.durable_welcomes, 1);
    assert!(welcome.acknowledged);
    assert_eq!(previous_runtime.installed_mls_epoch(previous_device).await.unwrap(), Some(1));
    boxed_step(|| previous_runtime.maintain_mls_key_packages(&other_device, 2)).await.unwrap();
    let mut human_group = boxed_step(|| realm_actor_mls_fixture::human_adds_runtime_to_group(fixture, &other_device, human_group)).await;
    let other_reader = boxed_step(|| previous_runtime.open_reader(&other_device)).await.unwrap();
    let other_welcome = boxed_step(|| previous_runtime.poll_welcome_queue(&other_device, &other_reader)).await.unwrap();
    assert_eq!(other_welcome.durable_welcomes, 1);
    assert!(other_welcome.acknowledged);
    assert_eq!(previous_runtime.installed_mls_epoch(&other_device).await.unwrap(), Some(2));
    let (frozen_revoke_request, frozen_revoke) = boxed_step(|| freeze_manager_revoke_request(fixture, &previous.package, candidate)).await;
    eprintln!("manager runtime: explicit pause and independent receiving installation");
    boxed_step(|| {
        previous_runtime.set_owner_status(
            actor,
            "manager-transfer-pause",
            RealmActorStatusSetPayloadState::Paused,
        )
    })
    .await
    .unwrap();
    let mut receiving = NativeService::new(&candidate.applet_id, &fixture.state.service_core_id());

    realm_actor_mls_fixture::enable(&mut receiving.package);
    let controller_method = receiving
        .package
        .proof
        .as_ref()
        .unwrap()
        .verification_method
        .clone();
    let epoch = applet_registration_epoch_evidence(&receiving.package);
    receiving.package.stamp_registration_epoch(&epoch).unwrap();
    receiving.package.stamp_package_digest().unwrap();
    receiving
        .package
        .sign(
            &Ed25519PayloadSigner::from_did_key_seed(
                [13; 32],
                arkret_identity::verification_method_did(controller_method.as_str()).unwrap(),
                controller_method.clone(),
            ),
            &controller_method,
        )
        .unwrap();
    factory
        .packages
        .lock()
        .await
        .insert(candidate.applet_id.to_string(), receiving.package.clone());
    let install =
        boxed_step(|| factory.prepare_install(&candidate.applet_id, "bridge-native-runtime")).await;
    let applets = PgAppletStore {
        pool: fixture.pool.clone(),
    };
    let receiving_installation = commit_install_http(fixture, &install).await;
    let record = applets
        .get(
            candidate.applet_id.as_str(),
            receiving.package.service_id.as_str(),
            &coland_storage::applet_effective_scope_key(&install.effective_scope).unwrap(),
        )
        .await
        .unwrap()
        .unwrap();
    let registration: Event = serde_json::from_value(record["registration_event"].clone()).unwrap();
    let grant = fixture.admin_event(EventKind::CapabilityGrant, ScopeRef::Realm { realm_id: fixture.realm.clone() },
        json!({"grant":{"schema":"ak.schema.capability.v1","realm_id":fixture.realm,
            "issuer_id":ActorId::account(fixture.pcr.history.account.clone()),
            "subject":ActorId::service(receiving.package.service_id.clone()),"actions":["ak.realm.actor.manager.change"],
            "resources":[{"kind":"realm_actor","actor_id":actor}],"constraints":[],
            "issuer_authority_refs":[{"kind":"realm_root","realm_id":fixture.realm,"authority_event_ref":fixture.authority_event_ref,"authority_generation":0}],
            "issued_at":arkret_canonical::format_timestamp_canonical(chrono::Utc::now())}}));
    let (status, body) = fixture
        .admin_post_network(
            "/_arkret/self/events",
            arkret_wire::ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT_V1,
            &json!(SelfAuthoritySubmitRequest::Event(
                arkret_wire::EventAdmissionSubmission::new(grant.clone())
            )),
            "receiving-manager-permission",
        )
        .await;
    assert_eq!(status, StatusCode::OK, "manager permission: {body}");
    let plan = ManagementTransferPlan {
        operation_id: "independent-manager".into(),
        actor_id: actor.clone(),
        new_service_id: receiving.package.service_id.clone(),
        new_registration_ref: registration.event_id,
        management_authorization_ref: arkret_wire::GrantId::from_event_id(&grant.event_id),
    };
    let mut config = previous_config.clone();
    config.arkret.applet_base_url = receiving.package.base_url.clone();
    config.arkret.service_did = applet_service_did(&receiving.package);
    config.arkret.service_resolution = Some(fixture_applet_service_history(&receiving.package));
    config.arkret.applet_namespaces = receiving.package.namespaces.clone();
    // The principal's stable host is retained; only its public resource backend
    // changes. The new Service itself has a distinct native DID and HTTPS host.
    let path = retained_path.to_owned();
    let retained_store = FileAuthoringStore::new(path.clone()).unwrap();
    let retained_devices = retained_actor_devices(&retained_store, actor);
    assert!(!retained_devices.is_empty());
    let armed = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let make_edge = || {
        Arc::new(
            ArkretEdge::new_outbound(
                Arc::new(config.clone()),
                client.clone(),
                Ed25519PayloadSigner::new(
                    SigningKey::from_bytes(&[42; 32]),
                    applet_service_did(&receiving.package),
                    receiving.package.webhook_auth.key_ref.clone(),
                ),
                AuthoringJournal::new(Arc::new(LostManagerReceipt {
                    inner: FileAuthoringStore::new(path.clone()).unwrap(),
                    armed: armed.clone(),
                })),
            )
            .unwrap(),
        )
    };
    let edge = make_edge();
    *receiving.managed_router.lock().unwrap() = Some(Arc::new(salvo::Service::new(
        arkret_bridge_runtime::web::managed_applet_host_router(edge.clone()).unwrap(),
    )));
    let runtime = ManagedDeviceRuntime::new(edge.clone()).unwrap();
    boxed_step(|| runtime.remember_installation_outcome(&install.effective_scope, &receiving_installation)).await.unwrap();
    assert!(
        boxed_step(|| runtime.local_actor_for_realm(&fixture.realm))
            .await
            .unwrap()
            .is_none()
    );
    let receiving_author = arkret_bridge_runtime::managed_actor_authoring::ManagedActorAuthoringService::new(edge.clone()).unwrap();
    let receiving_external = arkret::GhostExternalTuple {
        protocol: "fixture".into(), instance_id: "bridge-native".into(), external_id: "already-on-receiving-service".into(),
    };
    let prepared = boxed_step(|| receiving_author.prepare_ghost_in_scope(&candidate.applet_id, &candidate.creation_scope, &receiving_external, None)).await.unwrap();
    let arkret_bridge_runtime::PreparedGhost::Create(receiving_command) = prepared else { panic!("new receiving companion required"); };
    let receiving_candidate: RealmActorCreatePayload = serde_json::from_value(serde_json::to_value(&receiving_command.create_event.payload).unwrap()).unwrap();
    assert!(matches!(boxed_step(|| edge.submit_managed_creation(&receiving_command)).await.unwrap(), arkret::AuthoritySubmitOutcome::Accepted { .. }));
    boxed_step(|| realm_actor_mls_fixture::business_parent(fixture, &receiving.package, &receiving_candidate.actor_id, &candidate.creation_scope)).await;
    let receiving_device = boxed_step(|| runtime.device_for_actor(&receiving_candidate.actor_id)).await.unwrap();
    boxed_step(|| runtime.ensure_realm_membership(&receiving_device)).await.unwrap();
    let receiving_before = snapshot(fixture, &receiving_candidate.actor_id).await;
    let retained_originals = retained_store.entries_with_prefix("managed-authoring/original/").unwrap();
    assert_eq!(retained_originals.len(), 3, "two old subjects and one receiving subject precede transfer");
    eprintln!("manager runtime: retained custody and per-actor Service acceptance");
    let offer =
        boxed_step(|| runtime.management_transfer_offer(&plan, &candidate.initial_resolution.did))
            .await
            .unwrap();
    let offer =
        serde_json::from_slice(&arkret_canonical::canonical_json_bytes(&offer).unwrap()).unwrap();
    let proposal = boxed_step(|| previous_runtime.management_control_transcript(&offer))
        .await
        .unwrap();
    let proposal =
        serde_json::from_slice(&arkret_canonical::canonical_json_bytes(&proposal).unwrap())
            .unwrap();
    let cold_receiver = ManagedDeviceRuntime::new(make_edge()).unwrap();
    let signature =
        boxed_step(|| cold_receiver.sign_management_control_transcript(&plan, &proposal))
            .await
            .unwrap();
    let accepted_control =
        boxed_step(|| previous_runtime.submit_management_control(&plan, &signature))
            .await
            .unwrap();
    let release =
        boxed_step(|| previous_runtime.release_management_native(&plan, &accepted_control))
            .await
            .unwrap();
    let control_ref = CommittedEventRef {
        event_id: accepted_control.event_ref,
        commit_id: accepted_control.commit_id,
        stream_ref: accepted_control.stream_ref,
        stream_position: accepted_control.stream_position,
    };
    let creation_ref = actor_current_ref(
        fixture,
        actor,
        json!({"kind":"realm_actor_identity","actor_id":actor}),
    )
    .await;
    boxed_step(|| {
        cold_receiver.prepare_management_acceptance(&plan, &release, &control_ref, &creation_ref)
    })
    .await
    .unwrap();
    drop(cold_receiver);
    boxed_step(|| previous_runtime.prepare_management_transfer_to(&runtime, &plan))
        .await
        .unwrap();
    let before = snapshot(fixture, actor).await;
    assert_eq!(
        before["realm_actor_manager"]["service_id"],
        json!(previous.package.service_id)
    );
    assert_eq!(boxed_step(|| runtime.local_actor_for_realm(&fixture.realm)).await.unwrap(), Some(receiving_candidate.actor_id.clone()));
    *previous.principal_router.lock().unwrap() = Some(Arc::new(salvo::Service::new(
        Arc::new(
            arkret_bridge_runtime::managed_actor_authoring::ManagedActorAuthoringService::new(
                edge.clone(),
            )
            .unwrap(),
        )
        .router(),
    )));
    let failed = boxed_step(|| runtime.complete_management_transfer(&plan))
        .await
        .unwrap_err();
    assert!(
        failed.to_string().contains("injected lost manager receipt"),
        "{failed}"
    );
    let accepted = snapshot(fixture, actor).await;
    assert_eq!(
        accepted["realm_actor_manager"]["service_id"],
        json!(receiving.package.service_id)
    );
    assert_eq!(
        accepted["realm_actor_device_generation"]["current_device_generation_ref"]
            .as_u64()
            .unwrap(),
        before["realm_actor_device_generation"]["current_device_generation_ref"]
            .as_u64()
            .unwrap()
            + 1
    );
    assert_eq!(accepted["realm_actor_statusowner"], "paused");
    let (status, body) = fixture.admin_post_network(
        "/_arkret/self/events", arkret_wire::ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT_V1,
        &json!(SelfAuthoritySubmitRequest::Event(frozen_revoke.clone())), "manager-race-old-revoke-effect",
    ).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "old Service revoke cannot remove the transferred subject: {body}");
    assert!(fixture.state.test_persistence().authority_commits().committed_event(&frozen_revoke.event.event_id).await.unwrap().is_none());
    assert_eq!(snapshot(fixture, actor).await, accepted, "stale revoke has no control side effects");
    // Cover the retired leaf before remaining members publish new content.
    boxed_step(|| realm_actor_mls_fixture::human_rotates_out_runtime(fixture, previous_device, &mut human_group)).await;
    boxed_step(|| runtime.maintain_mls_key_packages(&receiving_device, 2)).await.unwrap();
    human_group = boxed_step(|| realm_actor_mls_fixture::human_adds_runtime_to_group(fixture, &receiving_device, human_group)).await;
    let receiving_reader = boxed_step(|| runtime.open_reader(&receiving_device)).await.unwrap();
    let receiving_welcome = boxed_step(|| runtime.poll_welcome_queue(&receiving_device, &receiving_reader)).await.unwrap();
    assert_eq!(receiving_welcome.durable_welcomes, 1);
    assert!(receiving_welcome.acknowledged);
    assert_eq!(runtime.installed_mls_epoch(&receiving_device).await.unwrap(), Some(4));

    assert_eq!(snapshot(fixture, &other_candidate.actor_id).await, other_before,
        "one actor's Service change must not alter another actor's manager, control or generation");
    assert!(boxed_step(|| query_managed_actor(fixture, previous, actor)).await.is_err(),
        "the previous manager must not disclose a transferred actor");
    assert_eq!(boxed_step(|| query_managed_actor(fixture, &receiving, actor)).await.unwrap().actor_id.as_ref(), Some(actor));
    assert_eq!(boxed_step(|| query_managed_actor(fixture, previous, &other_candidate.actor_id)).await.unwrap().actor_id.as_ref(), Some(&other_candidate.actor_id));
    let other_reader = boxed_step(|| previous_runtime.open_reader(&other_device)).await.unwrap();
    boxed_step(|| other_reader.client().snapshot_head(&fixture.realm)).await.unwrap();
    let location = json!({"protocol":"fixture","network_id":"bridge-native","location_id":"other-service-continues"});
    boxed_step(|| previous_runtime.submit_portal_strand(&other_candidate.actor_id, &candidate.creation_scope, "Still managed by the original Service", &location)).await.unwrap();

    let old_reader = boxed_step(|| previous_runtime.open_reader(previous_device))
        .await
        .unwrap();
    assert!(
        boxed_step(|| old_reader.client().snapshot_head(&fixture.realm))
            .await
            .is_err()
    );
    assert!(
        boxed_step(|| previous_runtime.recover_control(actor, "old-service-recovery"))
            .await
            .is_err()
    );
    drop(runtime);
    drop(edge);
    let edge = make_edge();
    let runtime = ManagedDeviceRuntime::new(edge.clone()).unwrap();
    // Retained-custody setup spends the real API bucket on accepted originals
    // and refusal probes. Pace the recovery phase by its configured window;
    // keep the production limiter and every authority check enabled.
    tokio::time::sleep(fixture.state.config().rate_limiter.window).await;
    eprintln!("manager runtime: cold exact receipt recovery and fresh custody operations");
    let receipt = boxed_step(|| runtime.complete_management_transfer(&plan))
        .await
        .unwrap();
    assert_eq!(
        boxed_step(|| runtime.complete_management_transfer(&plan))
            .await
            .unwrap(),
        receipt
    );
    assert_eq!(
        snapshot(fixture, actor).await,
        accepted,
        "exact retry changes no accepted state"
    );
    assert_eq!(boxed_step(|| query_managed_actor(fixture, &receiving, actor)).await.unwrap().actor_id.as_ref(), Some(actor));
    assert_eq!(boxed_step(|| query_managed_actor(fixture, &receiving, &receiving_candidate.actor_id)).await.unwrap().actor_id.as_ref(), Some(&receiving_candidate.actor_id));
    assert_eq!(snapshot(fixture, &receiving_candidate.actor_id).await, receiving_before);
    let receiving_reader = boxed_step(|| runtime.open_reader(&receiving_device)).await.unwrap();
    boxed_step(|| receiving_reader.client().snapshot_head(&fixture.realm)).await.unwrap();
    let receiving_location = json!({"protocol":"fixture","network_id":"bridge-native","location_id":"receiving-companion"});
    boxed_step(|| runtime.submit_portal_strand(&receiving_candidate.actor_id, &candidate.creation_scope, "Already managed by the receiving Service", &receiving_location)).await.unwrap();
    let store = FileAuthoringStore::new(path.clone()).unwrap();
    assert_eq!(store.entries_with_prefix("managed-authoring/original/").unwrap(), retained_originals,
        "historical creation custody is preserved byte-for-byte");
    assert_eq!(retained_actor_devices(&store, actor), retained_devices,
        "old Device and MLS private state remain retained despite generation fencing");
    boxed_step(|| runtime.rotate_control(actor, "receiving-control-rotation"))
        .await
        .unwrap();
    let old_did = candidate.initial_resolution.did.clone();
    let locator = applet_service_did(&receiving.package).as_str().splitn(4, ':').nth(3).unwrap().to_owned();
    let target_did: arkret::Did = format!("did:webvh:{}:{}",
        old_did.as_str().split(':').nth(2).unwrap(),
        locator.replace(":webvh:service", ":webvh:relocated-actor")).parse().unwrap();
    let mut moved_config = config.clone();
    moved_config.arkret.managed_actor_authoring.principal_endpoint = receiving.package.base_url.clone();
    let moved_edge = Arc::new(ArkretEdge::new_outbound(Arc::new(moved_config), client.clone(),
        Ed25519PayloadSigner::new(SigningKey::from_bytes(&[42; 32]),
            applet_service_did(&receiving.package), receiving.package.webhook_auth.key_ref.clone()),
        AuthoringJournal::new(Arc::new(FileAuthoringStore::new(path.clone()).unwrap()))).unwrap());
    *receiving.managed_router.lock().unwrap() = Some(Arc::new(salvo::Service::new(
        arkret_bridge_runtime::web::managed_applet_host_router(moved_edge.clone()).unwrap())));
    let runtime = ManagedDeviceRuntime::new(moved_edge.clone()).unwrap();
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    let relocation = boxed_step(|| runtime.relocate_control(actor, "retained-data-host-move", &target_did)).await.unwrap();
    drop(runtime);
    let runtime = ManagedDeviceRuntime::new(moved_edge.clone()).unwrap();
    assert_eq!(boxed_step(|| runtime.relocate_control(actor, "retained-data-host-move", &target_did)).await.unwrap(), relocation);
    let old_url: url::Url = arkret_identity::DidWebvhResolver::document_url(&old_did).unwrap().parse().unwrap();
    let prefix = old_url.path().strip_suffix("did.json").unwrap().to_owned();
    previous.unavailable_principals.lock().unwrap().insert(prefix);
    let network = native_http_client(std::time::Duration::from_secs(30));
    assert_eq!(network.get(old_url).send().await.unwrap().status(), StatusCode::NOT_FOUND);
    let new_url = arkret_identity::DidWebvhResolver::document_url(&target_did).unwrap();
    let new_document: Value = network.get(new_url).send().await.unwrap().error_for_status().unwrap().json().await.unwrap();
    assert_eq!(new_document["id"], json!(target_did));
    assert_eq!(snapshot(fixture, actor).await["realm_actor_control"]["resolution"]["did"], json!(target_did));
    let edge = moved_edge;
    boxed_step(|| {
        runtime.set_owner_status(
            actor,
            "receiving-explicit-resume",
            RealmActorStatusSetPayloadState::Active,
        )
    })
    .await
    .unwrap();
    boxed_step(|| {
        realm_actor_mls_fixture::business_parent(
            fixture,
            &receiving.package,
            actor,
            &candidate.creation_scope,
        )
    })
    .await;
    if let Some(external) = &candidate.external_ref {
        let author =
            arkret_bridge_runtime::managed_actor_authoring::ManagedActorAuthoringService::new(
                edge.clone(),
            )
            .unwrap();
        let external = arkret::GhostExternalTuple {
            protocol: external.protocol.clone(),
            instance_id: external.instance_id.clone(),
            external_id: external.external_id.clone(),
        };
        let reused = boxed_step(|| {
            author.prepare_ghost_in_scope(
                &candidate.applet_id,
                &candidate.creation_scope,
                &external,
                None,
            )
        })
        .await
        .unwrap();
        let arkret_bridge_runtime::PreparedGhost::Reuse {
            authoring_request,
            existing,
        } = reused
        else {
            panic!("transferred Ghost must retain the same external identity");
        };
        assert_eq!(&existing.ghost_actor_id, actor);
        assert_eq!(
            boxed_step(|| author.reused_ghost_did(&authoring_request, &existing))
                .await
                .unwrap(),
            candidate.initial_resolution.did
        );
    }
    let old_reader = boxed_step(|| previous_runtime.open_reader(previous_device))
        .await
        .unwrap();
    assert!(
        boxed_step(|| old_reader.client().snapshot_head(&fixture.realm))
            .await
            .is_err(),
        "old Device remains invalid after owner resume"
    );
    let device = boxed_step(|| runtime.device_for_actor(actor))
        .await
        .unwrap();
    assert_eq!(runtime.installed_mls_epoch(previous_device).await.unwrap(), Some(1),
        "retired Device MLS private history remains readable in retained local custody");
    assert_ne!(device.device_id, previous_device.device_id);
    assert_eq!(device.actor_id, previous_device.actor_id);
    assert!(
        runtime
            .installed_mls_epoch(&device)
            .await
            .unwrap()
            .is_none()
    );
    boxed_step(|| runtime.ensure_realm_membership(&device))
        .await
        .unwrap();
    boxed_step(|| runtime.open_reader(&device)).await.unwrap();
    eprintln!("manager runtime: ordinary member admits the replacement Device, then native business resumes");

    boxed_step(|| runtime.maintain_mls_key_packages(&device, 2)).await.unwrap();
    let _human_group = boxed_step(|| realm_actor_mls_fixture::human_adds_runtime_to_group(fixture, &device, human_group)).await;
    let reader = boxed_step(|| runtime.open_reader(&device)).await.unwrap();
    let welcome = boxed_step(|| runtime.poll_welcome_queue(&device, &reader)).await.unwrap();
    assert_eq!(welcome.durable_welcomes, 1);
    assert!(welcome.acknowledged);
    assert_eq!(runtime.installed_mls_epoch(&device).await.unwrap(), Some(5));
    assert_eq!(runtime.installed_mls_epoch(previous_device).await.unwrap(), Some(1));
    let location = json!({"protocol":"fixture","network_id":"bridge-native","location_id":"receiving-service-resumes"});
    boxed_step(|| runtime.submit_portal_strand(actor, &candidate.creation_scope, "Resumed on the receiving Service", &location)).await.unwrap();
    assert_eq!(
        snapshot(fixture, actor).await["realm_actor_recovery"]["enabled"],
        true,
        "manager transfer preserves the accepted recovery permission"
    );
    eprintln!("manager runtime: remove all receiving daily keys, preserve native recovery custody");
    {
        use chacha20poly1305::aead::{Aead as _, KeyInit as _, Payload};
        use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
        let cipher = XChaCha20Poly1305::new(&Key::from([0x53; 32]));
        for (storage_key, raw) in store.entries_with_prefix("managed-").unwrap() {
            if !storage_key.starts_with("managed-control/v1/")
                && !storage_key.starts_with("managed-manager-transfer/v1/incoming/")
            {
                continue;
            }
            let parts: Vec<_> = raw.split('.').collect();
            let nonce = arkret::base64url_decode(parts[1]).unwrap();
            let ciphertext = arkret::base64url_decode(parts[2]).unwrap();
            let plain = cipher
                .decrypt(
                    &XNonce::try_from(nonce.as_slice()).unwrap(),
                    Payload {
                        msg: &ciphertext,
                        aad: storage_key.as_bytes(),
                    },
                )
                .unwrap();
            let mut value: Value = serde_json::from_slice(&plain).unwrap();
            let stored_actor = if storage_key.starts_with("managed-manager-transfer/") {
                &value["offer"]["plan"]["actor_id"]
            } else {
                &value["actor_id"]
            };
            if *stored_actor != serde_json::to_value(actor).unwrap() {
                continue;
            }
            if storage_key.starts_with("managed-manager-transfer/") {
                assert_eq!(value["controller_seed"], "");
                assert_eq!(value["update_seed"], "");
                assert_eq!(value["next_update_seed"], "");
                continue;
            }
            value["controllers"] = json!({});
            let nonce = XNonce::from(rand::random::<[u8; 24]>());
            let plain = arkret_canonical::canonical_json_bytes(&value).unwrap();
            let encrypted = cipher
                .encrypt(
                    &nonce,
                    Payload {
                        msg: &plain,
                        aad: storage_key.as_bytes(),
                    },
                )
                .unwrap();
            let encoded = format!(
                "v1.{}.{}",
                arkret::base64url_encode(nonce),
                arkret::base64url_encode(encrypted)
            );
            assert!(
                store
                    .compare_exchange_batch(
                        &[(storage_key.clone(), Some(raw))],
                        &[(storage_key, Some(encoded))]
                    )
                    .unwrap()
            );
        }
    }
    assert!(
        boxed_step(|| runtime.rotate_control(actor, "lost-receiving-daily-key"))
            .await
            .is_err()
    );
    boxed_step(|| runtime.recover_control(actor, "receiving-native-recovery"))
        .await
        .unwrap();
    assert_eq!(
        snapshot(fixture, actor).await["realm_actor_manager"]["service_id"],
        json!(receiving.package.service_id)
    );
    let obsolete_reader = boxed_step(|| runtime.open_reader(&device)).await.unwrap();
    assert!(
        boxed_step(|| obsolete_reader.client().snapshot_head(&fixture.realm))
            .await
            .is_err()
    );
    let (status, body) = fixture.admin_post_network(
        &format!("/_arkret/self/applets/{}/revoke", candidate.applet_id),
        arkret_wire::ServiceOperationId::SELF_APPLET_COMMAND_REVOKE_V1,
        &json!(frozen_revoke_request), "manager-race-frozen-revoke",
    ).await;
    assert_eq!(status, StatusCode::OK, "resume the exact saved uninstall request: {body}");
    let outcome: arkret_models_integration::AppletRevokeOutcome = serde_json::from_value(body).unwrap();
    assert_eq!(outcome.status, arkret_models_integration::AppletRevokeSagaStatus::PartiallyCompleted);
    assert!(outcome.steps.iter().any(|step| matches!(step,
        arkret_models_integration::AppletRevokeStep::SubmittedEvent(step)
        if step.submitted_event_id == frozen_revoke.event.event_id
            && step.status == arkret_models_integration::AppletRevokeSubmittedEventStatus::Rejected)));
    assert!(fixture.state.test_persistence().authority_commits().committed_event(&frozen_revoke.event.event_id).await.unwrap().is_none());
    let independent_leave = fixture.admin_event(EventKind::MemberState, candidate.creation_scope.clone(),
        json!({"member_id":actor,"membership":"leave","reason":"independent admin decision after transfer"}));
    let (status, body) = fixture.admin_post_network(
        "/_arkret/self/events", arkret_wire::ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT_V1,
        &json!(SelfAuthoritySubmitRequest::Event(arkret_wire::EventAdmissionSubmission::new(independent_leave))),
        "manager-race-independent-admin-leave",
    ).await;
    assert_eq!(status, StatusCode::OK, "independent admin member authority remains valid: {body}");
}
