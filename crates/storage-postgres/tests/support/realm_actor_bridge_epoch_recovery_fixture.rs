// Real ArkretEdge publication over the existing Gov TLS fixture. The injected
// fault is an accepted ACK batch refused by the host store, not wire loss or
// an OS-process kill. Service A bytes are recovered after a cold journal reopen
// using the same native Service's authenticated B history and current key.
use arkret_bridge_runtime::AuthoringStore as _;

#[derive(Clone)]
struct BridgeAcceptedAckWrite {
    key: String,
    previous: Option<String>,
    proposed: String,
}

#[derive(Default)]
struct BridgeAcceptedAckFault {
    armed: std::sync::atomic::AtomicBool,
    hit: std::sync::Mutex<Option<BridgeAcceptedAckWrite>>,
}

struct LostBridgeAcceptedAck {
    inner: arkret_bridge_runtime::FileAuthoringStore,
    fault: Arc<BridgeAcceptedAckFault>,
}

impl arkret_bridge_runtime::AuthoringStore for LostBridgeAcceptedAck {
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
        let accepted = writes.iter().find_map(|(key, value)| {
            if !key.starts_with("result/") {
                return None;
            }
            let raw = value.as_ref()?;
            let record: Value = serde_json::from_str(raw).unwrap();
            record.get("committed").filter(|c| !c.is_null())?;
            Some((key, raw))
        });
        if let Some((key, proposed)) = accepted
            && self
                .fault
                .armed
                .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            let previous = expected.iter().find(|(k, _)| k == key).unwrap().1.clone();
            assert_eq!(self.inner.load(key)?, previous);
            assert_ne!(previous.as_ref(), Some(proposed));
            assert!(
                writes
                    .iter()
                    .any(|(k, v)| k.starts_with("pending/") && v.is_none())
            );
            assert!(
                writes
                    .iter()
                    .any(|(k, v)| k.starts_with("observation/") && v.is_some())
            );
            assert!(
                self.fault
                    .hit
                    .lock()
                    .unwrap()
                    .replace(BridgeAcceptedAckWrite {
                        key: key.clone(),
                        previous,
                        proposed: proposed.clone(),
                    })
                    .is_none()
            );
            return Err(arkret_bridge_runtime::BridgeError::Database(
                "injected local publication accepted ACK write failure".into(),
            ));
        }
        self.inner.compare_exchange_batch(expected, writes)
    }
}

fn bridge_epoch_config(
    fixture: &Fixture,
    package: &AppletPackage,
    resolution: &arkret_models_identity::AuthenticatedServiceResolution,
    seed: u8,
) -> arkret_bridge_runtime::Config {
    let method = &package.webhook_signature_policy.key_ref;
    let (_, fragment) = method.as_str().rsplit_once('#').unwrap();
    serde_json::from_value(json!({
        "bridge":{"bridge_id":"native-epoch-ack"},
        "arkret":{
            "server_url":fixture.state.config().public_base_url,
            "applet_base_url":package.base_url,
            "service_resolution":resolution,
            "service_did":applet_service_did(package),
            "trust_domain":fixture.state.config().trust_domain,
            "applet_id":package.applet_id,
            "signing_key_seed_hex":format!("{seed:02x}").repeat(32),
            "verification_method_fragment":format!("#{fragment}"),
            "trusted_server_did":fixture.state.service_did(),
            "applet_namespaces":package.namespaces,
            "managed_actor_authoring":{
                "principal_endpoint":package.base_url,
                "key_encryption_key_hex":"53".repeat(32),
                "device":{"actions":["ak.message.create"],"lifetime_seconds":3600,"mls":false,
                    "key_package_inventory_target":0}
            }
        }
    }))
    .unwrap()
}

async fn bridge_epoch_deliveries(fixture: &Fixture, package: &AppletPackage) -> Vec<Value> {
    use diesel::sql_types::{Jsonb, Text};
    use diesel_async::RunQueryDsl as _;
    #[derive(diesel::QueryableByName)]
    struct Row {
        #[diesel(sql_type=Jsonb)]
        value: Value,
    }
    let mut conn = fixture.pool.get().await.unwrap();
    diesel::sql_query("SELECT to_jsonb(t) AS value FROM applet_transactions t WHERE applet_id=$1 AND source_id=$2 ORDER BY idempotency_key")
        .bind::<Text,_>(package.applet_id.as_str())
        .bind::<Text,_>(package.service_id.as_str())
        .load::<Row>(&mut conn).await.unwrap().into_iter().map(|r|r.value).collect()
}

pub(super) async fn bridge_epoch_ack_loss_recovers_original(pool: PgPool) {
    use arkret_models_collaboration::events_payloads::CapabilityRevokePayload;
    use arkret_models_collaboration::governance::grant_constraint::{
        GrantConstraintKind, GrantConstraintSubkind,
    };
    let (fixture, _governor) = boxed_step(|| network_fixture(pool.clone())).await;
    let factory = AppletAuthoringFactory {
        fixture,
        packages: Default::default(),
        scopes: Default::default(),
    };
    let applet = AppletId::new(format!("ak:applet:{}", uuid::Uuid::now_v7())).unwrap();
    let mut native = NativeService::new(&applet, &factory.fixture.state.service_core_id());
    realm_actor_mls_fixture::enable(&mut native.package);
    factory
        .packages
        .lock()
        .await
        .insert(applet.to_string(), native.package.clone());
    let install = boxed_step(|| factory.prepare_install(&applet, "bridge-ack-epoch")).await;
    let fixture = &factory.fixture;
    let coland_storage::AppletAdmissionRequest::Install(a_body) = &install.input.candidate.request;
    let (status, value) = boxed_step(|| async {
        fixture
            .admin_post_network(
                "/_arkret/self/applets/install",
                arkret_wire::ServiceOperationId::SELF_APPLET_COMMAND_INSTALL_V1,
                &json!(a_body),
                "bridge-ack-initial-install",
            )
            .await
    })
    .await;
    assert_eq!(status, StatusCode::CREATED, "real A install: {value}");
    let a_install: AppletInstallResponseBody = serde_json::from_value(value).unwrap();
    let provision = a_body
        .authoring_request_basis
        .capability_grant_events
        .iter()
        .find(|event| {
            event.payload["grant"]["actions"]
                .as_array()
                .unwrap()
                .iter()
                .any(|action| action == "ak.applet.bot.provision")
        })
        .unwrap();
    let provision = arkret_wire::GrantId::from_event_id(&provision.event_id);
    let (actor, actor_signer) = authority_admission_candidate(
        &native.package,
        fixture,
        &a_install.registration_event_ref,
        &provision,
        true,
        &native.archive,
    );
    let create = authority_admission_create(&actor, &actor_signer);
    let (status, value) =
        boxed_step(|| authority_admission_send(fixture, &native.package, &create)).await;
    assert_eq!(status, StatusCode::OK, "genuine A Bot: {value}");
    let scope = install.effective_scope.clone();
    let parent = boxed_step(|| {
        realm_actor_mls_fixture::business_parent(fixture, &native.package, &actor.actor_id, &scope)
    })
    .await;
    let original = fixture
        .state
        .test_persistence()
        .authority_commits()
        .committed_event(&EventId::from_token_bytes(parent.token_bytes()).unwrap())
        .await
        .unwrap()
        .unwrap();
    let mut child: CapabilityGrantCreateBody =
        serde_json::from_value(original.event.payload["grant"].clone()).unwrap();
    let service = ActorId::service(native.package.service_id.clone());
    child.issuer_id = service.clone();
    child.subject = CapabilitySubject::Actor(actor.actor_id.clone());
    child.issuer_authority_refs = vec![IssuerAuthorityRef::Grant {
        grant_id: parent.clone(),
    }];
    child.issued_at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    for c in &mut child.constraints {
        if c.constraint_subkind == Some(GrantConstraintSubkind::AppletAuthority) {
            c.executed_by = Some(actor.actor_id.clone());
        } else if c.constraint_kind == GrantConstraintKind::AuthorityControl
            && c.constraint_subkind.is_none()
        {
            c.allowed_managed_actor_roles.clear();
            c.max_authority_depth = Some(0);
            c.authority_regrant_allowed = Some(false);
        }
    }
    use arkret_bridge_runtime::{ArkretEdge, AuthoringJournal, FileAuthoringStore};
    let station_url: Url = fixture.state.config().public_base_url.parse().unwrap();
    let client = arkret::ClientBuilder::new(station_url.clone())
        .loopback_service_discovery(station_url.host_str().unwrap(), station_url.port().unwrap())
        .unwrap()
        .http_client(native_http_client(std::time::Duration::from_secs(90)))
        .build()
        .unwrap();
    let path = std::env::temp_dir().join(format!("bridge-epoch-ack-{}.redb", uuid::Uuid::now_v7()));
    let fault = Arc::new(BridgeAcceptedAckFault::default());
    let journal_a = AuthoringJournal::new(Arc::new(LostBridgeAcceptedAck {
        inner: FileAuthoringStore::new(path.clone()).unwrap(),
        fault: fault.clone(),
    }));
    let edge_a = ArkretEdge::new_outbound(
        Arc::new(bridge_epoch_config(
            fixture,
            &native.package,
            &native.service_resolution.lock().unwrap(),
            42,
        )),
        client.clone(),
        Ed25519PayloadSigner::new(
            applet_service_signing_key(&native.package.webhook_signature_policy.key_ref),
            applet_service_did(&native.package),
            native.package.webhook_signature_policy.key_ref.clone(),
        ),
        journal_a.clone(),
    )
    .unwrap();
    let intent = edge_a
        .service_intent::<arkret::event_spec::CapabilityGrant>(
            &fixture.realm,
            CapabilityGrantPayload { grant: child },
        )
        .unwrap()
        .with_authorization_ref(arkret_wire::AuthorizationRef::new(parent.as_str()).unwrap());
    let publication = "native-epoch-ack-original";
    let authored = boxed_step(|| edge_a.author_and_sign(&fixture.realm, publication, intent))
        .await
        .unwrap();
    let event_a = authored.event().clone();
    assert_eq!(event_a.scope_ref, ScopeRef::realm(fixture.realm.clone()));
    assert_eq!(event_a.kind, EventKind::CapabilityGrant);
    assert_eq!(event_a.actor_id, service);
    let frozen_bytes = arkret_canonical::canonical_json_bytes(&event_a).unwrap();
    let wire_body = AppletTransactionRequestBody::Events(AppletEventTransactionRequestBody {
        applet_id: applet.clone(),
        source_id: native.package.service_id.clone(),
        events: vec![event_a.clone()],
        committed_events: vec![],
        signals: vec![],
    });
    let body_bytes = arkret_canonical::canonical_json_bytes(&wire_body).unwrap();
    assert_eq!(
        journal_a.pending_events().await.unwrap(),
        vec![authored.clone()]
    );
    let baseline = boxed_step(|| bridge_epoch_deliveries(fixture, &native.package)).await;
    let baseline_ids = baseline
        .iter()
        .map(|r| r["idempotency_key"].as_str().unwrap().to_owned())
        .collect::<std::collections::BTreeSet<_>>();
    fault.armed.store(true, std::sync::atomic::Ordering::SeqCst);
    let error = boxed_step(|| edge_a.submit_event(&authored))
        .await
        .expect_err("local accepted ACK must fail after true HTTPS acceptance");
    assert!(
        error
            .to_string()
            .contains("injected local publication accepted ACK"),
        "{error}"
    );
    assert!(!fault.armed.load(std::sync::atomic::Ordering::SeqCst));
    let hit = fault
        .hit
        .lock()
        .unwrap()
        .clone()
        .expect("actual accepted ACK batch observed");
    let proposed: Value = serde_json::from_str(&hit.proposed).unwrap();
    let c: arkret_wire::CommittedEventRef =
        serde_json::from_value(proposed["committed"].clone()).unwrap();
    let lost_outcome: AppletTransactionResponseBody =
        serde_json::from_value(proposed["outcome"]["result"].clone()).unwrap();
    assert_eq!(proposed["outcome"]["kind"], "applet");
    assert_eq!(c.event_id, event_a.event_id);
    let checked_outcome = boxed_step(|| {
        realm_actor_mls_fixture::grant_boundary_assert_accepted(
            fixture,
            &event_a,
            json!(lost_outcome),
        )
    })
    .await;
    assert_eq!(checked_outcome, lost_outcome);
    let a_record = fixture
        .state
        .test_persistence()
        .authority_commits()
        .committed_event(&event_a.event_id)
        .await
        .unwrap()
        .unwrap();
    let a_full = arkret_wire::CommittedEventFullView {
        event: a_record.event,
        commit: a_record.commit,
    };
    assert_eq!(a_full.event, event_a);
    assert_eq!(
        c,
        arkret_wire::CommittedEventRef {
            event_id: a_full.commit.event_ref.clone(),
            commit_id: a_full.commit.commit_id.clone(),
            stream_ref: a_full.commit.stream_ref.clone(),
            stream_position: a_full.commit.stream_position,
        }
    );
    let a_fact = fixture
        .state
        .test_persistence()
        .authority_commits()
        .producer_signer_fact(&event_a, &a_full.commit)
        .await
        .unwrap()
        .unwrap();
    let suite = event_a.realm_id.digest_suite_code().digest_suite();
    a_fact.validate_commit_binding(&a_full, suite).unwrap();
    arkret_identity::account_device_signer_evidence::verify_historical_producer_event_signature(
        &event_a, &a_fact, suite,
    )
    .unwrap();
    let after_a = boxed_step(|| bridge_epoch_deliveries(fixture, &native.package)).await;
    let added_a = after_a
        .iter()
        .filter(|r| !baseline_ids.contains(r["idempotency_key"].as_str().unwrap()))
        .collect::<Vec<_>>();
    let [receipt_a] = added_a.as_slice() else {
        panic!("one actual A delivery must be accepted");
    };
    assert_eq!(receipt_a["outcome"], json!(lost_outcome));
    let auth_a: AppletDeliveryAuthenticationRecord =
        serde_json::from_value(receipt_a["delivery_authentication_record"].clone()).unwrap();
    assert_eq!(
        auth_a.verification_method,
        native.package.webhook_signature_policy.key_ref
    );
    assert_eq!(auth_a.registration_epoch, native.package.registration_epoch);
    assert_eq!(
        auth_a.verification_key_digest,
        Hash::new(arkret_canonical::sha256_digest(
            applet_service_signing_key(&native.package.webhook_signature_policy.key_ref)
                .verifying_key()
                .to_bytes()
        ))
        .unwrap()
    );
    assert_eq!(
        auth_a.direction,
        AppletDeliveryDirection::AppletToArkretInbound
    );
    assert_eq!(
        auth_a.signature_algorithm,
        HttpMessageSignatureAlgorithm::Ed25519
    );
    assert_eq!(auth_a.source_id, native.package.service_id);
    assert_eq!(auth_a.destination_id, fixture.state.service_core_id());
    assert_eq!(
        auth_a.operation_id.as_str(),
        arkret_wire::ServiceOperationId::EDGE_APPLET_COMMAND_TRANSACTION_V1
    );
    assert_eq!(auth_a.content_digest, content_digest_header(&body_bytes));
    assert_eq!(
        receipt_a["request_digest"],
        arkret_canonical::sha256_digest(&body_bytes)
    );
    assert_eq!(
        auth_a.idempotency_key,
        receipt_a["idempotency_key"].as_str().unwrap()
    );
    assert_eq!(
        receipt_a["delivery_authentication_record_digest"],
        json!(auth_a.stable_digest().unwrap())
    );
    let receipt_a = (**receipt_a).clone();
    // Closing every A owner is essential: the next FileAuthoringStore must run
    // its own immediate reopen barrier, not merely reuse a cached live engine.
    drop(edge_a);
    drop(journal_a);
    let pending_store = FileAuthoringStore::new(path.clone()).unwrap();
    assert_eq!(pending_store.load(&hit.key).unwrap(), hit.previous);
    assert!(
        !pending_store
            .entries_with_prefix("pending/")
            .unwrap()
            .is_empty()
    );
    assert!(
        pending_store
            .entries_with_prefix("observation/")
            .unwrap()
            .is_empty()
    );
    drop(pending_store);
    let rows = fixture
        .state
        .test_persistence()
        .capability_grant_current_states()
        .snapshot_for_realm(&fixture.realm)
        .await
        .unwrap();
    let parent_row = rows.iter().find(|row| row.grant_id == parent).unwrap();
    let close = fixture.admin_event(
        EventKind::CapabilityRevoke,
        scope.clone(),
        json!(CapabilityRevokePayload {
            grant_id: parent.clone(),
            expected_commit_id: parent_row.revision.commit_id.clone(),
            reason: Some("business parent closed before key rotation".into()),
        }),
    );
    let close =
        arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequestBody::Event(
            arkret_wire::EventAdmissionSubmission::new(close),
        );
    let (status, value) = boxed_step(|| async {
        fixture
            .admin_post_network(
                "/_arkret/self/events",
                arkret_wire::ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT_V1,
                &json!(close),
                "bridge-ack-close-A-parent",
            )
            .await
    })
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "real A business-parent revocation: {value}"
    );
    let closed: arkret_models_collaboration::authority_commit::SelfAuthoritySubmitResponseBody =
        serde_json::from_value(value).unwrap();
    closed.validate_for_request(&close).unwrap();

    // Prepare a legitimate A template now. Calling the generic factory after
    // rotation would reconstruct/cache inception A, so B is derived below only
    // from the actually served native B resolution and typed closed models.
    let template = boxed_step(|| factory.prepare_install(&applet, "bridge-ack-epoch")).await;
    let coland_storage::AppletAdmissionRequest::Install(template) =
        &template.input.candidate.request;
    let mut b_body = (**template).clone();
    let previous: AppletRegistrationPayload = serde_json::from_value(json!(
        b_body.authoring_request_basis.registration_event.payload
    ))
    .unwrap();
    let (package_b, epoch_b) =
        boxed_step(|| epoch_b_package(fixture, &native, a_full.commit.committed_at)).await;
    b_body.applet_package = package_b.clone();
    b_body.authoring_request_basis.package_digest = package_b.package_digest.clone().unwrap();
    b_body.authoring_request_basis.registration_event = fixture.admin_event(
        EventKind::AppletRegistration,
        ScopeRef::realm(fixture.realm.clone()),
        json!(
            package_b
                .to_registration(&epoch_b, previous.expected_commit_id)
                .unwrap()
        ),
    );
    for event in &mut b_body.authoring_request_basis.capability_grant_events {
        let mut payload: CapabilityGrantPayload =
            serde_json::from_value(json!(event.payload)).unwrap();
        for c in &mut payload.grant.constraints {
            if c.constraint_subkind == Some(GrantConstraintSubkind::AppletAuthority) {
                c.registration_epoch = Some(package_b.registration_epoch.clone());
            }
        }
        *event = fixture.admin_event(
            EventKind::CapabilityGrant,
            ScopeRef::realm(fixture.realm.clone()),
            json!(payload),
        );
    }
    boxed_step(|| install_admission_repreview(fixture, &mut b_body)).await;
    let (status, value) = boxed_step(|| async {
        fixture
            .admin_post_network(
                "/_arkret/self/applets/install",
                arkret_wire::ServiceOperationId::SELF_APPLET_COMMAND_INSTALL_V1,
                &json!(b_body),
                "bridge-ack-real-B-install",
            )
            .await
    })
    .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "actual B registration/installation: {value}"
    );
    let b_install: AppletInstallResponseBody = serde_json::from_value(value).unwrap();
    assert_eq!(b_install.service_id, a_install.service_id);
    assert_ne!(b_install.registration_epoch, a_install.registration_epoch);
    assert_ne!(b_install.install_id, a_install.install_id);

    // Preserve the actual served A+B method-native history, never synthesize a
    // current-only document or save A's historical private signing material.
    let config_b = bridge_epoch_config(
        fixture,
        &package_b,
        &native.service_resolution.lock().unwrap(),
        44,
    );
    let journal_b = AuthoringJournal::new(Arc::new(FileAuthoringStore::new(path.clone()).unwrap()));
    let edge_b = ArkretEdge::new_outbound(
        Arc::new(config_b),
        client,
        Ed25519PayloadSigner::new(
            applet_service_signing_key(&package_b.webhook_signature_policy.key_ref),
            applet_service_did(&package_b),
            package_b.webhook_signature_policy.key_ref.clone(),
        ),
        journal_b.clone(),
    )
    .unwrap();
    let retained = edge_b
        .retained_publication(&fixture.realm, &service, publication)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        arkret_canonical::canonical_json_bytes(retained.event()).unwrap(),
        frozen_bytes
    );
    assert_eq!(retained.producer_proof, authored.producer_proof);
    assert_eq!(
        journal_b.pending_events().await.unwrap(),
        vec![retained.clone()]
    );
    let before_replay = boxed_step(|| native_business_footprint(fixture)).await;
    let child_id = arkret_wire::GrantId::from_event_id(&event_a.event_id);
    let before_current = fixture
        .state
        .test_persistence()
        .capability_grant_current_states()
        .snapshot_for_realm(&fixture.realm)
        .await
        .unwrap();
    assert_eq!(
        before_current
            .iter()
            .find(|g| g.grant_id == parent)
            .unwrap()
            .status,
        coland_storage::CapabilityGrantCurrentStatus::Revoked
    );
    let before_current = before_current
        .iter()
        .find(|g| g.grant_id == child_id)
        .unwrap();
    let before_current = (*before_current).clone();
    assert_eq!(
        boxed_step(|| edge_b.submit_event(&retained)).await.unwrap(),
        event_a.event_id.to_string()
    );
    assert_eq!(
        boxed_step(|| native_business_footprint(fixture)).await,
        before_replay
    );
    assert!(journal_b.pending_events().await.unwrap().is_empty());
    let after_b = boxed_step(|| bridge_epoch_deliveries(fixture, &package_b)).await;
    let added_b = after_b
        .iter()
        .filter(|r| !baseline_ids.contains(r["idempotency_key"].as_str().unwrap()))
        .collect::<Vec<_>>();
    assert_eq!(
        added_b.len(),
        2,
        "exactly two actual single-event Bridge attempts reach Gov"
    );
    let observed_a = added_b
        .iter()
        .find(|r| r["idempotency_key"] == receipt_a["idempotency_key"])
        .unwrap();
    assert_eq!(
        **observed_a, receipt_a,
        "the first accepted receipt is immutable"
    );
    let receipt_b = added_b
        .iter()
        .find(|r| r["idempotency_key"] != receipt_a["idempotency_key"])
        .unwrap();
    let auth_b: AppletDeliveryAuthenticationRecord =
        serde_json::from_value(receipt_b["delivery_authentication_record"].clone()).unwrap();
    assert_ne!(auth_a.idempotency_key, auth_b.idempotency_key);
    arkret_wire::RequestId::new(auth_a.idempotency_key.clone()).unwrap();
    arkret_wire::RequestId::new(auth_b.idempotency_key.clone()).unwrap();
    assert_eq!(
        auth_b.verification_method,
        package_b.webhook_signature_policy.key_ref
    );
    assert_eq!(auth_b.registration_epoch, package_b.registration_epoch);
    assert_eq!(
        auth_b.verification_key_digest,
        Hash::new(arkret_canonical::sha256_digest(
            applet_service_signing_key(&package_b.webhook_signature_policy.key_ref)
                .verifying_key()
                .to_bytes()
        ))
        .unwrap()
    );
    assert_ne!(
        auth_a.verification_key_digest,
        auth_b.verification_key_digest
    );
    assert_eq!(
        auth_b.direction,
        AppletDeliveryDirection::AppletToArkretInbound
    );
    assert_eq!(
        auth_b.signature_algorithm,
        HttpMessageSignatureAlgorithm::Ed25519
    );
    assert_ne!(auth_a.verification_method, auth_b.verification_method);
    assert_ne!(auth_a.registration_epoch, auth_b.registration_epoch);
    assert_eq!(auth_a.source_id, auth_b.source_id);
    assert_eq!(auth_a.destination_id, auth_b.destination_id);
    assert_eq!(auth_a.content_digest, auth_b.content_digest);
    assert_eq!(receipt_a["request_digest"], receipt_b["request_digest"]);
    assert_eq!(receipt_b["outcome"], receipt_a["outcome"]);
    assert_eq!(
        receipt_b["delivery_authentication_record_digest"],
        json!(auth_b.stable_digest().unwrap())
    );
    let recovered = fixture
        .state
        .test_persistence()
        .authority_commits()
        .committed_event(&event_a.event_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(recovered.event, event_a);
    assert_eq!(recovered.commit, a_full.commit);
    let recovered_fact = fixture
        .state
        .test_persistence()
        .authority_commits()
        .producer_signer_fact(&event_a, &recovered.commit)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        arkret_canonical::canonical_json_bytes(&recovered_fact).unwrap(),
        arkret_canonical::canonical_json_bytes(&a_fact).unwrap()
    );
    let after_current = fixture
        .state
        .test_persistence()
        .capability_grant_current_states()
        .snapshot_for_realm(&fixture.realm)
        .await
        .unwrap();
    let after_current = after_current
        .iter()
        .find(|g| g.grant_id == child_id)
        .unwrap();
    assert_eq!(after_current.status, before_current.status);
    assert_eq!(after_current.revision, before_current.revision);
    assert_eq!(after_current.source, before_current.source);
    assert_eq!(
        arkret_canonical::canonical_json_bytes(&after_current.value).unwrap(),
        arkret_canonical::canonical_json_bytes(&before_current.value).unwrap()
    );
    let completed_store = FileAuthoringStore::new(path.clone()).unwrap();
    let completed_raw = completed_store.load(&hit.key).unwrap().unwrap();
    let completed: Value = serde_json::from_str(&completed_raw).unwrap();
    assert_eq!(completed["committed"], json!(c));
    assert_eq!(completed["outcome"]["result"], json!(lost_outcome));
    assert_eq!(completed["observation_count"], 1);
    assert_eq!(
        completed_store
            .entries_with_prefix("observation/")
            .unwrap()
            .len(),
        1
    );
    // A further call consumes durable acceptance; recorded deliveries, counters
    // and the accepted result must remain unchanged.
    assert_eq!(
        boxed_step(|| edge_b.submit_event(&retained)).await.unwrap(),
        event_a.event_id.to_string()
    );
    assert_eq!(
        boxed_step(|| bridge_epoch_deliveries(fixture, &package_b)).await,
        after_b
    );
    assert_eq!(
        boxed_step(|| native_business_footprint(fixture)).await,
        before_replay
    );
    assert_eq!(
        completed_store.load(&hit.key).unwrap().as_deref(),
        Some(completed_raw.as_str())
    );
    drop(completed_store);
    drop(edge_b);
    drop(journal_b);
    std::fs::remove_file(path).unwrap();
}
