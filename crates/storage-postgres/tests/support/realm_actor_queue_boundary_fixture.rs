// Imported by realm_native_fixture; every receiver is a real accepted
// RealmActor Device. Human accounts only produce the MLS Add/Remove.
#[derive(Default)]
struct NativeRecipientStoreFault {
    remaining: std::sync::atomic::AtomicUsize,
    phase: std::sync::atomic::AtomicUsize,
    hits: std::sync::Mutex<Vec<Value>>,
}

impl NativeRecipientStoreFault {
    fn arm(&self, phase: usize, nth_device_write: usize) {
        use std::sync::atomic::Ordering::SeqCst;
        assert!(nth_device_write > 0);
        assert_eq!(
            self.remaining.load(SeqCst),
            0,
            "previous fault must have fired"
        );
        self.phase.store(phase, SeqCst);
        self.remaining.store(nth_device_write, SeqCst);
    }

    fn before_compare_exchange(
        &self,
        expected: &[(String, Option<String>)],
        writes: &[(String, Option<String>)],
        inner: &arkret_bridge_runtime::FileAuthoringStore,
    ) -> arkret_bridge_runtime::Result<()> {
        use std::sync::atomic::Ordering::SeqCst;

        use arkret_bridge_runtime::AuthoringStore as _;
        let Some((key, Some(previous))) = expected
            .iter()
            .find(|(key, value)| key.starts_with("managed-device/v1/") && value.is_some())
        else {
            return Ok(());
        };
        let n = self.remaining.load(SeqCst);
        if n == 0 || self.remaining.fetch_sub(1, SeqCst) != 1 {
            return Ok(());
        }
        let phase = self.phase.load(SeqCst);
        let next = writes
            .iter()
            .find(|(candidate, _)| candidate == key)
            .and_then(|(_, value)| value.as_ref())
            .expect("Device CAS must write custody");
        assert_eq!(
            inner.load(key)?.as_ref(),
            Some(previous),
            "fault before durable mutation"
        );
        let hit = json!({"phase":phase,"key":key,
            "expected_sha256":arkret_canonical::sha256_digest(previous.as_bytes()),
            "proposed_sha256":arkret_canonical::sha256_digest(next.as_bytes())});
        assert_ne!(hit["expected_sha256"], hit["proposed_sha256"]);
        self.hits.lock().unwrap().push(hit);
        Err(arkret_bridge_runtime::BridgeError::App(format!(
            "injected recipient write phase={phase}"
        )))
    }

    fn prove_failed_postimage(&self, phase: usize, path: &std::path::Path) {
        use arkret_bridge_runtime::AuthoringStore as _;
        let hits = self.hits.lock().unwrap();
        let exact = hits
            .iter()
            .filter(|hit| hit["phase"] == phase)
            .collect::<Vec<_>>();
        assert_eq!(exact.len(), 1, "each boundary must fail exactly once");
        let hit = exact[0];
        let store = arkret_bridge_runtime::FileAuthoringStore::new(path.to_owned()).unwrap();
        let raw = store.load(hit["key"].as_str().unwrap()).unwrap().unwrap();
        assert_eq!(
            json!(arkret_canonical::sha256_digest(raw.as_bytes())),
            hit["expected_sha256"],
            "failed encrypted custody write must leave its exact previous bytes"
        );
    }
}

fn strict_empty_native_page(
    page: &arkret_models_collaboration::device_messages::DeviceMessagesGetResponseBody,
) {
    assert!(page.deliveries.is_empty());
    assert!(!page.has_more);
    assert!(page.acknowledgement_token.is_none());
    assert!(page.next_cursor.is_none());
    assert_eq!(page.limited, Some(false));
    assert_eq!(page.lost, Some(false));
}

fn welcome_ids(
    page: &arkret_models_collaboration::device_messages::DeviceMessagesGetResponseBody,
    scope: &ScopeRef,
    actor: &ActorId,
    device: &arkret_wire::DeviceId,
) -> Vec<arkret_wire::MlsWelcomeDeliveryId> {
    page.deliveries
        .iter()
        .map(|item| {
            let arkret_models_collaboration::device_messages::RecipientDelivery::MlsWelcome {
                mls_welcome,
            } = item
            else {
                panic!("native recipient page must contain actual MLS Welcome originals");
            };
            assert_eq!(&mls_welcome.effective_scope, scope);
            assert_eq!(&mls_welcome.recipient_actor_id, actor);
            assert!(matches!(&mls_welcome.recipient_endpoint,
            arkret_wire::MlsWelcomeRecipientEndpoint::Device { device_id } if device_id == device));
            mls_welcome.welcome_id.clone()
        })
        .collect()
}

async fn same_device_cross_circle_queue(
    factory: &AppletAuthoringFactory,
    package: &AppletPackage,
    devices: &arkret_bridge_runtime::managed_device::ManagedDeviceRuntime,
    actor: &ActorId,
    scope_a: &ScopeRef,
) {
    use arkret_bridge_runtime::managed_device::InitialManagedDevicePlan;
    use arkret_models_collaboration::device_messages::DeviceMessagesAcknowledgementRequestBody;
    assert!(matches!(scope_a, ScopeRef::Circle { .. }));
    let install_b =
        boxed_step(|| factory.prepare_install(&package.applet_id, "native-queue:scope-conflict"))
            .await;
    let scope_b = install_b.effective_scope.clone();
    assert_ne!(scope_a, &scope_b);
    let outcome_b = boxed_step(|| commit_install_http(&factory.fixture, &install_b)).await;
    boxed_step(|| devices.remember_installation_outcome(&scope_b, &outcome_b))
        .await
        .unwrap();
    let realm_scope = ScopeRef::Realm {
        realm_id: factory.fixture.realm.clone(),
    };
    for scope in [&realm_scope, scope_a, &scope_b] {
        boxed_step(|| {
            realm_actor_mls_fixture::business_parent(&factory.fixture, package, actor, scope)
        })
        .await;
    }
    let mut actions = vec![
        "ak.applet.join",
        "ak.circle.member.add",
        "ak.event.read",
        "ak.message.create",
        "ak.message.redact",
        "ak.mls.commit",
        "ak.object.read_content",
        "ak.self.blob.resource.get.v1",
        "ak.self.blob.command.presign.v1",
        "ak.self.blob.upload.create.v1",
        "ak.strand.create",
    ];
    actions.sort_unstable();
    let mut scopes = vec![
        json!({"effective_scope":realm_scope,"actions":actions}),
        json!({"effective_scope":scope_a,"actions":actions}),
        json!({"effective_scope":scope_b,"actions":actions}),
    ];
    scopes.sort_by_key(|entry| {
        arkret_canonical::canonical_json_bytes(&entry["effective_scope"]).unwrap()
    });
    let plan = InitialManagedDevicePlan {
        operation_id: "one-device-three-authorized-scopes".into(),
        actor_id: actor.clone(),
        scopes: serde_json::from_value(json!(scopes)).unwrap(),
        not_before: chrono::Utc::now(),
        expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
    };
    let parent = boxed_step(|| devices.authorize_initial_device(plan.clone(), &realm_scope))
        .await
        .unwrap();
    let a = boxed_step(|| devices.authorize_initial_device(plan.clone(), scope_a))
        .await
        .unwrap();
    let b = boxed_step(|| devices.authorize_initial_device(plan.clone(), &scope_b))
        .await
        .unwrap();
    for other in [&a, &b] {
        assert_eq!(other.actor_id, parent.actor_id);
        assert_eq!(
            other.device_id, parent.device_id,
            "same physical Device, not two receiver fixtures"
        );
        assert_eq!(other.authorization_event_id, parent.authorization_event_id);
        assert_eq!(other.authorization_commit, parent.authorization_commit);
    }
    boxed_step(|| devices.ensure_realm_membership(&parent))
        .await
        .unwrap();
    boxed_step(|| devices.join_circle_after_realm_join(&a, &parent))
        .await
        .unwrap();
    boxed_step(|| devices.join_circle_after_realm_join(&b, &parent))
        .await
        .unwrap();
    for endpoint in [&a, &b] {
        boxed_step(|| devices.maintain_mls_key_packages(endpoint, 3))
            .await
            .unwrap();
    }
    // Durable queue positions are genuinely interleaved A1, B1, A2.
    let mut group_a =
        boxed_step(|| realm_actor_mls_fixture::human_admits_runtime(&factory.fixture, &a)).await;
    let _group_b =
        boxed_step(|| realm_actor_mls_fixture::human_admits_runtime(&factory.fixture, &b)).await;
    boxed_step(|| {
        realm_actor_mls_fixture::human_rotates_out_runtime(&factory.fixture, &a, &mut group_a)
    })
    .await;
    let _group_a = boxed_step(|| {
        realm_actor_mls_fixture::human_adds_runtime_to_group(&factory.fixture, &a, group_a)
    })
    .await;
    let first = a
        .client()
        .receive_device_messages(None, Some(1))
        .await
        .unwrap();
    assert_eq!(first.deliveries.len(), 1);
    assert!(
        first.has_more,
        "limit=1 must actually paginate two legitimate A originals"
    );
    let second = a
        .client()
        .receive_device_messages(first.next_cursor.as_deref(), Some(1))
        .await
        .unwrap();
    assert_eq!(second.deliveries.len(), 1);
    assert!(!second.has_more);
    let first_ids = welcome_ids(&first, scope_a, actor, &a.device_id);
    let second_ids = welcome_ids(&second, scope_a, actor, &a.device_id);
    assert_ne!(first_ids, second_ids);
    let b_before = b
        .client()
        .receive_device_messages(None, Some(1))
        .await
        .unwrap();
    let b_ids = welcome_ids(&b_before, &scope_b, actor, &b.device_id);
    assert_eq!(b_ids.len(), 1);
    assert!(!first_ids.contains(&b_ids[0]) && !second_ids.contains(&b_ids[0]));
    let ack = DeviceMessagesAcknowledgementRequestBody {
        acknowledgement_token: second.acknowledgement_token.clone().unwrap(),
    };
    let before_wrong_ack = boxed_step(|| native_queue_handoff_footprint(&factory.fixture)).await;
    let denied = b.client().ack_device_messages(&ack).await.unwrap_err();
    assert_eq!(
        denied.error_code(),
        Some(arkret_wire::ErrorCode::ParamInvalid),
        "same Device still cannot use the other Circle's token: {denied}"
    );
    let arkret::http_client::Error::Api { status, error } = &denied else {
        panic!("the real queue endpoint must reject the cross-binding token: {denied}");
    };
    assert_eq!(*status, StatusCode::BAD_REQUEST.as_u16());
    assert_eq!(error.status, StatusCode::BAD_REQUEST.as_u16());
    assert_eq!(
        error.problem_type,
        "https://arkret.org/problems/param_invalid"
    );
    assert_eq!(error.detail, "invalid ack token");
    assert_eq!(
        error.extensions.get("reason_code"),
        Some(&json!(arkret_wire::ReasonCode::INVALID_ACK_TOKEN))
    );
    assert_eq!(
        boxed_step(|| native_queue_handoff_footprint(&factory.fixture)).await,
        before_wrong_ack,
        "a cross-Circle token must not alter either queue, ACK frontier or cursor state"
    );
    let a_still = a
        .client()
        .receive_device_messages(None, Some(100))
        .await
        .unwrap();
    let mut all_a = welcome_ids(&a_still, scope_a, actor, &a.device_id);
    let mut expected_a = [first_ids, second_ids].concat();
    all_a.sort();
    expected_a.sort();
    assert_eq!(all_a, expected_a);
    assert_eq!(
        welcome_ids(
            &b.client()
                .receive_device_messages(None, Some(100))
                .await
                .unwrap(),
            &scope_b,
            actor,
            &b.device_id
        ),
        b_ids
    );
    let done = a.client().ack_device_messages(&ack).await.unwrap();
    assert_eq!(
        done.pruned_count, 2,
        "later page ACK covers exactly A's disclosed cumulative prefix"
    );
    let replay = a.client().ack_device_messages(&ack).await.unwrap();
    assert_eq!(replay.pruned_count, 0, "same original ACK is idempotent");
    strict_empty_native_page(
        &a.client()
            .receive_device_messages(None, Some(1))
            .await
            .unwrap(),
    );
    strict_empty_native_page(
        &a.client()
            .receive_device_messages(second.next_cursor.as_deref(), Some(1))
            .await
            .unwrap(),
    );
    let b_after = b
        .client()
        .receive_device_messages(None, Some(100))
        .await
        .unwrap();
    assert_eq!(
        welcome_ids(&b_after, &scope_b, actor, &b.device_id),
        b_ids,
        "A's cumulative ACK must preserve interleaved B original"
    );
    let done = b
        .client()
        .ack_device_messages(&DeviceMessagesAcknowledgementRequestBody {
            acknowledgement_token: b_after.acknowledgement_token.unwrap(),
        })
        .await
        .unwrap();
    assert_eq!(done.pruned_count, 1);
    strict_empty_native_page(
        &b.client()
            .receive_device_messages(None, Some(1))
            .await
            .unwrap(),
    );
}

async fn welcome_checkpoint_consume_and_ack_recovery<F>(
    fixture: &Fixture,
    actor: &ActorId,
    make_edge: &F,
    path: &std::path::Path,
    fault: &NativeRecipientStoreFault,
) where
    F: Fn() -> Arc<arkret_bridge_runtime::ArkretEdge>,
{
    use arkret_bridge_runtime::managed_device::ManagedDeviceRuntime;
    let original = boxed_step(|| native_business_footprint(fixture)).await;
    let edge = make_edge();
    let runtime = ManagedDeviceRuntime::new(edge.clone()).unwrap();
    let device = boxed_step(|| runtime.device_for_actor(actor))
        .await
        .unwrap();
    let id = device.device_id.clone();
    let auth = device.authorization_event_id.clone();
    let reader = boxed_step(|| runtime.open_reader(&device)).await.unwrap();
    let observed = reader
        .client()
        .receive_device_messages(None, Some(100))
        .await
        .unwrap();
    let page = observed.value().unwrap().clone();
    drop(observed);
    assert_eq!(
        page.deliveries.len(),
        1,
        "real positive Add must precede fault injection"
    );
    let arkret_models_collaboration::device_messages::RecipientDelivery::MlsWelcome {
        mls_welcome: welcome,
    } = &page.deliveries[0]
    else {
        panic!("real Realm Device Welcome required");
    };
    assert_eq!(welcome.recipient_actor_id, *actor);
    assert_eq!(welcome.effective_scope, *device.effective_scope());
    assert!(
        matches!(&welcome.recipient_endpoint, arkret_wire::MlsWelcomeRecipientEndpoint::Device { device_id } if device_id == &id)
    );
    let ledger = fixture
        .state
        .test_persistence()
        .mls_key_packages()
        .get_peer_claim_by_claim_id(welcome.keypackage_claim_ref.as_str())
        .await
        .unwrap()
        .unwrap();
    assert_ne!(ledger.state, "consumed");
    assert!(ledger.consume_receipt.is_none());
    // Phase 1: first CAS saves the authenticated page; second would atomically
    // install the group plus frozen signed consume. Refuse it before writing.
    fault.arm(1, 2);
    let error = boxed_step(|| runtime.poll_welcome_queue(&device, &reader))
        .await
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("injected recipient write phase=1"),
        "{error}"
    );
    fault.prove_failed_postimage(1, path);
    assert_eq!(runtime.installed_mls_epoch(&device).await.unwrap(), None);
    assert!(
        fixture
            .state
            .test_persistence()
            .mls_key_packages()
            .get_peer_claim_by_claim_id(welcome.keypackage_claim_ref.as_str())
            .await
            .unwrap()
            .unwrap()
            .consume_receipt
            .is_none()
    );
    assert_eq!(
        welcome_ids(
            &device
                .client()
                .receive_device_messages(None, Some(100))
                .await
                .unwrap(),
            device.effective_scope(),
            actor,
            &id
        ),
        vec![welcome.welcome_id.clone()]
    );
    drop(reader);
    drop(device);
    drop(runtime);
    drop(edge);
    // Phase 2: cold resume installs the group/consume (CAS 1), then actual
    // authenticated HTTP consume succeeds. Lose only its durable local receipt
    // at CAS 2. This is receipt-persistence failure, not an OS kill claim.
    let edge = make_edge();
    let runtime = ManagedDeviceRuntime::new(edge.clone()).unwrap();
    let device = boxed_step(|| runtime.device_for_actor(actor))
        .await
        .unwrap();
    assert_eq!(device.device_id, id);
    assert_eq!(device.authorization_event_id, auth);
    let reader = boxed_step(|| runtime.open_reader(&device)).await.unwrap();
    fault.arm(2, 2);
    let error = boxed_step(|| runtime.poll_welcome_queue(&device, &reader))
        .await
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("injected recipient write phase=2"),
        "{error}"
    );
    fault.prove_failed_postimage(2, path);
    assert_eq!(runtime.installed_mls_epoch(&device).await.unwrap(), Some(1));
    let ledger = fixture
        .state
        .test_persistence()
        .mls_key_packages()
        .get_peer_claim_by_claim_id(welcome.keypackage_claim_ref.as_str())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(ledger.state, "consumed");
    let terminal = ledger.consume_receipt.unwrap();
    assert_eq!(
        welcome_ids(
            &device
                .client()
                .receive_device_messages(None, Some(100))
                .await
                .unwrap(),
            device.effective_scope(),
            actor,
            &id
        ),
        vec![welcome.welcome_id.clone()]
    );
    drop(reader);
    drop(device);
    drop(runtime);
    drop(edge);
    // Phase 3: frozen consume exact-replays and stores the original receipt
    // (CAS 1); actual HTTP ACK prunes the queue, then cursor cleanup CAS 2 fails.
    let edge = make_edge();
    let runtime = ManagedDeviceRuntime::new(edge.clone()).unwrap();
    let device = boxed_step(|| runtime.device_for_actor(actor))
        .await
        .unwrap();
    let reader = boxed_step(|| runtime.open_reader(&device)).await.unwrap();
    fault.arm(3, 2);
    let error = boxed_step(|| runtime.poll_welcome_queue(&device, &reader))
        .await
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("injected recipient write phase=3"),
        "{error}"
    );
    fault.prove_failed_postimage(3, path);
    strict_empty_native_page(
        &device
            .client()
            .receive_device_messages(None, Some(100))
            .await
            .unwrap(),
    );
    drop(reader);
    drop(device);
    drop(runtime);
    drop(edge);
    // Final cold worker can finish only the stored ACK/page. It does not mint
    // another identity, Device, Add or consume result to recover its cursor.
    let edge = make_edge();
    let runtime = ManagedDeviceRuntime::new(edge.clone()).unwrap();
    let device = boxed_step(|| runtime.device_for_actor(actor))
        .await
        .unwrap();
    assert_eq!(device.device_id, id);
    assert_eq!(device.authorization_event_id, auth);
    assert!(
        boxed_step(|| runtime.complete_durable_recipient_page(&device))
            .await
            .unwrap()
    );
    assert!(
        !boxed_step(|| runtime.complete_durable_recipient_page(&device))
            .await
            .unwrap()
    );
    assert_eq!(runtime.installed_mls_epoch(&device).await.unwrap(), Some(1));
    strict_empty_native_page(
        &device
            .client()
            .receive_device_messages(None, Some(100))
            .await
            .unwrap(),
    );
    let after = boxed_step(|| native_business_footprint(fixture)).await;
    for table in [
        "canonical_events",
        "realm_commits",
        "realm_actor_creations",
        "realm_actor_current_states",
        "realm_actor_private_signer_facts",
    ] {
        assert_eq!(
            after[table], original[table],
            "cold recovery must preserve accepted originals: {table}"
        );
    }
    let ledger = fixture
        .state
        .test_persistence()
        .mls_key_packages()
        .get_peer_claim_by_claim_id(welcome.keypackage_claim_ref.as_str())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(ledger.state, "consumed");
    assert_eq!(ledger.consume_receipt, Some(terminal));
    assert_eq!(
        fault.hits.lock().unwrap().len(),
        3,
        "all three exact boundaries reached"
    );
}

pub(super) async fn native_boundary_response(
    fixture: &Fixture,
    authority: &coland_storage::AppletManagedDeviceAuthority,
    scope: &ScopeRef,
    seed: &[u8; 32],
    path: &str,
    operation: arkret_wire::ServiceOperationId,
    body: Option<Value>,
) -> salvo::Response {
    let state = &fixture.state;
    let metadata = AppletManagedDeviceMetadata {
        actor_id: authority.actor_id.clone(),
        device_id: authority.device_id.clone(),
        authorization_event_id: authority.authorization_ref.event_id.clone(),
        applet_id: authority.applet_id.clone(),
        effective_scope: scope.clone(),
        nonce: arkret_canonical::base64url_encode(rand::random::<[u8; 32]>()),
    };
    let uri = format!(
        "{}{path}",
        state.config().public_base_url.trim_end_matches('/')
    );
    let url = url::Url::parse(&uri).unwrap();
    let mut headers = vec![
        ("arkret-operation".into(), operation.to_string()),
        (
            "destination-service-id".into(),
            state.service_core_id().to_string(),
        ),
        (
            "arkret-managed-device".into(),
            metadata.to_header_value().unwrap(),
        ),
    ];
    let bytes = body
        .as_ref()
        .map(|value| arkret_canonical::canonical_json_bytes(value).unwrap());
    let digest = bytes.as_ref().map(|value| content_digest_header(value));
    let mut covered = vec![];
    if let Some(value) = &body {
        headers.push(("content-type".into(), "application/json".into()));
        headers.push(("content-digest".into(), digest.clone().unwrap()));
        let id = value
            .get("claim_request_id")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .unwrap_or_else(|| uuid::Uuid::now_v7().to_string());
        headers.push(("idempotency-key".into(), id));
        covered.extend(["content-digest", "idempotency-key"]);
    }
    let parts = SignedRequestParts {
        method: if body.is_some() { "POST" } else { "GET" }.into(),
        target_uri: uri.clone(),
        authority: url[url::Position::BeforeHost..url::Position::AfterPort].into(),
        path: path.into(),
        headers,
        body_digest: digest,
    };
    let fingerprint = arkret_canonical::ed25519_pubkey_to_did_key_multibase(&authority.public_key);
    let method = format!("did:key:{fingerprint}#{fingerprint}");
    let signed = sign_http_message_for_scenario(
        &parts,
        HttpSignatureScenario::AppletManagedDeviceV1,
        &covered,
        "sig1",
        &method,
        chrono::Utc::now().timestamp(),
        &SigningKey::from_bytes(seed),
    )
    .unwrap();
    let mut request = if body.is_some() {
        TestClient::post(uri)
    } else {
        TestClient::get(uri)
    };
    for (name, value) in parts.headers {
        request = request.add_header(
            salvo::http::header::HeaderName::from_bytes(name.as_bytes()).unwrap(),
            value,
            true,
        );
    }
    if let Some(bytes) = bytes {
        request = request.body(bytes);
    }
    request
        .add_header("signature-input", signed.signature_input_header, true)
        .add_header("signature", signed.signature_header, true)
        .send(&service(state.clone()))
        .await
}

async fn native_queue_handoff_footprint(fixture: &Fixture) -> Value {
    use diesel_async::RunQueryDsl as _;
    #[derive(diesel::QueryableByName)]
    struct Row {
        #[diesel(sql_type=diesel::sql_types::Jsonb)]
        value: Value,
    }
    let mut value = boxed_step(|| native_business_footprint(fixture)).await;
    let mut connection = fixture.pool.get().await.unwrap();
    for table in [
        "mls_welcome_deliveries",
        "mls_key_packages",
        "device_message_ack_tokens",
        "sync_cursor_handles",
        "sync_cursor_revocations",
        "mls_group_current_states",
        "device_messages",
    ] {
        let row=diesel::sql_query(format!("SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text),'[]'::jsonb) AS value FROM {table} r"))
            .get_result::<Row>(&mut connection).await.unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert(table.into(), row.value);
    }
    value
}

async fn native_queue_cut_released(fixture: &Fixture) {
    use diesel_async::RunQueryDsl as _;
    let mut connection = fixture.pool.get().await.unwrap();
    let until = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        if diesel::sql_query(
            "SELECT realm_id FROM realm_authorities WHERE realm_id=$1 FOR UPDATE NOWAIT",
        )
        .bind::<diesel::sql_types::Text, _>(fixture.realm.as_str())
        .execute(&mut connection)
        .await
        .is_ok()
        {
            return;
        }
        assert!(
            std::time::Instant::now() < until,
            "canceled native queue cut must release its actual Realm writer lock"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
}

pub(super) async fn native_prepared_queue_handoff_boundaries(
    fixture: &Fixture,
    authority: &coland_storage::AppletManagedDeviceAuthority,
    seed: &[u8; 32],
    welcome: &arkret_wire::MlsWelcomeDelivery,
    deadline: chrono::DateTime<chrono::Utc>,
) {
    use diesel_async::RunQueryDsl as _;
    use futures_util::StreamExt as _;
    #[derive(diesel::QueryableByName)]
    struct Backend {
        #[diesel(sql_type=diesel::sql_types::Integer)]
        pid: i32,
    }
    #[derive(diesel::QueryableByName)]
    struct Stopped {
        #[diesel(sql_type=diesel::sql_types::Bool)]
        stopped: bool,
    }
    let path = "/_arkret/self/device_messages?limit=1";
    let scope = &welcome.effective_scope;
    let operation = arkret_wire::ServiceOperationId::SelfDeviceMessagesReadListV1;
    // First prove the retained original is really reachable through this route.
    let mut initial = boxed_step(|| {
        native_boundary_response(fixture, authority, scope, seed, path, operation, None)
    })
    .await;
    assert_eq!(initial.status_code, Some(StatusCode::OK));
    let page: arkret_models_collaboration::device_messages::DeviceMessagesGetResponseBody =
        initial.take_json().await.unwrap();
    assert_eq!(
        welcome_ids(&page, scope, &authority.actor_id, &authority.device_id),
        vec![welcome.welcome_id.clone()]
    );
    assert!(page.acknowledgement_token.is_some());
    assert!(page.next_cursor.is_some());
    let before = boxed_step(|| native_queue_handoff_footprint(fixture)).await;
    let mut observer = fixture.pool.get().await.unwrap();
    let query = "SELECT pid FROM pg_stat_activity WHERE datname=current_database() AND pid<>pg_backend_pid() AND state='idle in transaction' AND query LIKE 'INSERT INTO sync_cursor_handles%'";
    let old = diesel::sql_query(query)
        .load::<Backend>(&mut observer)
        .await
        .unwrap();
    let mut response = boxed_step(|| {
        native_boundary_response(fixture, authority, scope, seed, path, operation, None)
    })
    .await;
    assert_eq!(response.status_code, Some(StatusCode::OK));
    let new = diesel::sql_query(query)
        .load::<Backend>(&mut observer)
        .await
        .unwrap();
    let owned = new
        .iter()
        .filter(|row| !old.iter().any(|p| p.pid == row.pid))
        .collect::<Vec<_>>();
    let exactly_one = owned.len() == 1;
    let stopped = if exactly_one {
        diesel::sql_query("SELECT pg_terminate_backend($1) AS stopped")
            .bind::<diesel::sql_types::Integer, _>(owned[0].pid)
            .get_result::<Stopped>(&mut observer)
            .await
            .unwrap()
            .stopped
    } else {
        false
    };
    drop(observer);
    let mut body = response.take_body();
    let first = tokio::time::timeout(std::time::Duration::from_secs(5), body.next()).await;
    drop(body);
    drop(response);
    boxed_step(|| native_queue_cut_released(fixture)).await;
    let after = boxed_step(|| native_queue_handoff_footprint(fixture)).await;
    assert!(
        exactly_one,
        "must identify only this actual prepared native page backend"
    );
    assert!(
        stopped,
        "terminate only the held native queue cut owned by this test"
    );
    assert!(
        matches!(first, Ok(Some(Err(_)))),
        "a lost real DB authorization cut must fail before the first complete frame"
    );
    assert_eq!(
        after, before,
        "lost current cut must roll back all new ACK/cursor allocations"
    );
    // The same signed Welcome remains reachable; no ACK consumed its original.
    let mut recovered = boxed_step(|| {
        native_boundary_response(fixture, authority, scope, seed, path, operation, None)
    })
    .await;
    assert_eq!(recovered.status_code, Some(StatusCode::OK));
    let page: arkret_models_collaboration::device_messages::DeviceMessagesGetResponseBody =
        recovered.take_json().await.unwrap();
    assert_eq!(
        welcome_ids(&page, scope, &authority.actor_id, &authority.device_id),
        vec![welcome.welcome_id.clone()]
    );
    let before = boxed_step(|| native_queue_handoff_footprint(fixture)).await;
    let mut prepared = boxed_step(|| {
        native_boundary_response(fixture, authority, scope, seed, path, operation, None)
    })
    .await;
    assert_eq!(prepared.status_code, Some(StatusCode::OK));
    assert!(
        chrono::Utc::now() < deadline,
        "genuine claim must still be live when queued original response is prepared"
    );
    assert_eq!(
        boxed_step(|| native_queue_handoff_footprint(fixture)).await,
        before,
        "private response allocations stay uncommitted"
    );
    tokio::time::sleep(
        (deadline - chrono::Utc::now()).to_std().unwrap() + std::time::Duration::from_millis(80),
    )
    .await;
    let mut body = prepared.take_body();
    let first = tokio::time::timeout(std::time::Duration::from_secs(5), body.next()).await;
    drop(body);
    drop(prepared);
    boxed_step(|| native_queue_cut_released(fixture)).await;
    assert!(
        matches!(first, Ok(Some(Err(_)))),
        "physical claim expiry must deny the first actual Welcome response frame"
    );
    assert_eq!(
        boxed_step(|| native_queue_handoff_footprint(fixture)).await,
        before,
        "expired queue handoff must leave neither ACK nor cursor allocation"
    );
    let mut refused = boxed_step(|| {
        native_boundary_response(fixture, authority, scope, seed, path, operation, None)
    })
    .await;
    assert_eq!(refused.status_code, Some(StatusCode::NOT_FOUND));
    let problem: Value = refused.take_json().await.unwrap();
    assert_eq!(problem["type"], "https://arkret.org/problems/not_found");
    assert_eq!(problem["detail"], "native recipient queue is unavailable");
    assert_eq!(
        boxed_step(|| native_queue_handoff_footprint(fixture)).await,
        before
    );
}
