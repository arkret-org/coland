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
    page: &arkret_models_collaboration::device_messages::DeviceMessagesGetOutcome,
) {
    assert!(page.deliveries.is_empty());
    assert!(!page.has_more);
    assert!(page.ack_token.is_none());
    assert!(page.next_cursor.is_none());
    assert_eq!(page.limited, Some(false));
    assert_eq!(page.lost, Some(false));
}

fn welcome_ids(
    page: &arkret_models_collaboration::device_messages::DeviceMessagesGetOutcome,
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
    use arkret_models_collaboration::device_messages::DeviceMessagesAckRequestBody;
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
    let ack = DeviceMessagesAckRequestBody {
        ack_token: second.ack_token.clone().unwrap(),
    };
    let denied = b.client().ack_device_messages(&ack).await.unwrap_err();
    assert_eq!(
        denied.error_code(),
        Some(arkret_wire::ErrorCode::CapabilityDenied),
        "same Device still cannot use the other Circle's token: {denied}"
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
        .ack_device_messages(&DeviceMessagesAckRequestBody {
            ack_token: b_after.ack_token.unwrap(),
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
        "realm_actor_current_results",
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
