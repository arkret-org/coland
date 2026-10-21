// Included inside realm_native_fixture; failures occur only after the real
// HTTP acceptance and before the corresponding encrypted local outcome CAS.
#[derive(Clone)]
struct NativeRuntimeRecoveryWrite {
    phase: usize,
    key: String,
    previous: String,
    proposed: String,
}

#[derive(Default)]
struct NativeRuntimeRecoveryFault {
    armed: std::sync::atomic::AtomicUsize,
    hits: std::sync::Mutex<Vec<NativeRuntimeRecoveryWrite>>,
}

impl NativeRuntimeRecoveryFault {
    fn arm(&self, phase: usize) {
        assert!(phase > 0);
        assert_eq!(
            self.armed.swap(phase, std::sync::atomic::Ordering::SeqCst),
            0,
            "previous runtime outcome failure must have fired"
        );
    }

    fn before_compare_exchange(
        &self,
        expected: &[(String, Option<String>)],
        writes: &[(String, Option<String>)],
        inner: &arkret_bridge_runtime::FileAuthoringStore,
    ) -> arkret_bridge_runtime::Result<()> {
        use arkret_bridge_runtime::AuthoringStore as _;
        let Some((key, Some(previous))) = expected
            .iter()
            .find(|(key, value)| key.starts_with("managed-device/v1/") && value.is_some())
        else {
            return Ok(());
        };
        let phase = self.armed.swap(0, std::sync::atomic::Ordering::SeqCst);
        if phase == 0 {
            return Ok(());
        }
        let proposed = writes
            .iter()
            .find(|(candidate, _)| candidate == key)
            .and_then(|(_, value)| value.as_ref())
            .expect("Device outcome must update its original encrypted custody");
        assert_eq!(inner.load(key)?.as_ref(), Some(previous));
        assert_ne!(previous, proposed);
        self.hits.lock().unwrap().push(NativeRuntimeRecoveryWrite {
            phase,
            key: key.clone(),
            previous: previous.clone(),
            proposed: proposed.clone(),
        });
        Err(arkret_bridge_runtime::BridgeError::App(format!(
            "injected native runtime outcome phase={phase}"
        )))
    }

    fn unchanged_pending(
        &self,
        phase: usize,
        path: &std::path::Path,
    ) -> NativeRuntimeRecoveryWrite {
        use arkret_bridge_runtime::AuthoringStore as _;
        let hits = self.hits.lock().unwrap();
        let exact = hits
            .iter()
            .filter(|hit| hit.phase == phase)
            .collect::<Vec<_>>();
        assert_eq!(exact.len(), 1, "each actual outcome CAS must fail once");
        let hit = exact[0].clone();
        let store = arkret_bridge_runtime::FileAuthoringStore::new(path.to_owned()).unwrap();
        assert_eq!(store.load(&hit.key).unwrap(), Some(hit.previous.clone()));
        assert_ne!(store.load(&hit.key).unwrap(), Some(hit.proposed.clone()));
        hit
    }
}

async fn runtime_recovery_authorizations(
    fixture: &Fixture,
    actor: &ActorId,
) -> Vec<coland_storage::CommittedEventRecord> {
    let mut result = Vec::new();
    for row in fixture
        .state
        .test_persistence()
        .events()
        .snapshot_all()
        .await
        .unwrap()
    {
        if row.kind != "ak.device.authorize" || row.envelope["actor_id"] != json!(actor) {
            continue;
        }
        let event: Event = serde_json::from_value(row.envelope).unwrap();
        let original = fixture
            .state
            .test_persistence()
            .authority_commits()
            .committed_event(&event.event_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(original.event, event);
        result.push(original);
    }
    result.sort_by(|a, b| a.event.event_id.cmp(&b.event.event_id));
    result
}

async fn run_native_runtime_recovery<F>(
    fixture: &Fixture,
    package: &AppletPackage,
    actor: &ActorId,
    scope: &ScopeRef,
    make_edge: &F,
    path: &std::path::Path,
    fault: &NativeRuntimeRecoveryFault,
) where
    F: Fn() -> Arc<arkret_bridge_runtime::ArkretEdge>,
{
    use arkret_bridge_runtime::AuthoringStore as _;
    use arkret_bridge_runtime::managed_device::ManagedDeviceRuntime;

    assert!(
        boxed_step(|| runtime_recovery_authorizations(fixture, actor))
            .await
            .is_empty()
    );
    let before = boxed_step(|| native_business_footprint(fixture)).await;
    let edge = make_edge();
    let runtime = ManagedDeviceRuntime::new(edge.clone()).unwrap();
    // Initial preparation uses an absent expected value. The next Device CAS
    // can only be the verified real HTTP outcome, after its acceptance.
    fault.arm(1);
    let error = boxed_step(|| runtime.device_for_actor(actor))
        .await
        .err()
        .expect("accepted Device outcome persistence must fail");
    assert!(
        error
            .to_string()
            .contains("injected native runtime outcome phase=1"),
        "{error}"
    );
    let pending_device = fault.unchanged_pending(1, path);
    let originals = boxed_step(|| runtime_recovery_authorizations(fixture, actor)).await;
    assert_eq!(originals.len(), 1, "the actual Station accepted one Device");
    let original = originals.into_iter().next().unwrap();
    let payload: arkret_models_collaboration::events_payloads::DeviceAuthorizePayload =
        serde_json::from_value(json!(original.event.payload)).unwrap();
    assert_eq!(original.event.actor_id, *actor);
    let accepted = boxed_step(|| native_business_footprint(fixture)).await;
    for table in [
        "canonical_events",
        "realm_commits",
        "realm_actor_private_signer_facts",
    ] {
        assert_eq!(
            accepted[table].as_array().unwrap().len(),
            before[table].as_array().unwrap().len() + 1,
            "real initial Device footprint: {table}"
        );
    }
    drop(runtime);
    drop(edge);

    // Every owner is closed before a fresh FileAuthoringStore/runtime reopens.
    // The ordinary product entry must recover its frozen plan, never author a
    // second Device, change its expiry or replace the accepted original Commit.
    let edge = make_edge();
    let runtime = ManagedDeviceRuntime::new(edge.clone()).unwrap();
    assert_eq!(
        arkret_bridge_runtime::FileAuthoringStore::new(path.to_owned())
            .unwrap()
            .load(&pending_device.key)
            .unwrap(),
        Some(pending_device.previous)
    );
    let device = boxed_step(|| runtime.device_for_actor(actor))
        .await
        .unwrap();
    assert_eq!(device.actor_id, *actor);
    assert_eq!(device.effective_scope(), scope);
    assert_eq!(device.device_id, payload.device_id);
    assert_eq!(device.authorization_event_id, original.event.event_id);
    assert_eq!(device.authorization_commit, original.commit);
    assert_eq!(
        boxed_step(|| runtime_recovery_authorizations(fixture, actor)).await,
        vec![original.clone()]
    );
    assert_eq!(
        boxed_step(|| native_business_footprint(fixture)).await,
        accepted
    );

    boxed_step(|| realm_actor_mls_fixture::business_parent(fixture, package, actor, scope)).await;
    boxed_step(|| runtime.ensure_realm_membership(&device))
        .await
        .unwrap();
    let packages_before = fixture
        .state
        .test_persistence()
        .mls_key_packages()
        .snapshot_all()
        .await
        .unwrap();
    assert!(
        packages_before
            .iter()
            .all(|row| &row.owner_actor_id != actor)
    );
    // This public production method fsyncs the private identity/bundles and
    // exact signed request before permitting the first publication attempt.
    let request = boxed_step(|| runtime.prepare_mls_key_packages(&device, 2))
        .await
        .unwrap()
        .unwrap();
    let request_bytes = arkret_canonical::canonical_json_bytes(&request).unwrap();
    assert_eq!(request.actor_id, *actor);
    assert_eq!(request.device_id.as_ref(), Some(&device.device_id));
    assert_eq!(request.keypackages.len(), 2);
    assert!(
        runtime
            .mls_key_package_inventory(&device)
            .await
            .unwrap()
            .entries
            .is_empty()
    );
    let store = arkret_bridge_runtime::FileAuthoringStore::new(path.to_owned()).unwrap();
    let pending_package = store.load(&pending_device.key).unwrap().unwrap();
    drop(store);
    fault.arm(2);
    let error = boxed_step(|| runtime.maintain_mls_key_packages(&device, 2))
        .await
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("injected native runtime outcome phase=2"),
        "{error}"
    );
    let failed_publication = fault.unchanged_pending(2, path);
    assert_eq!(failed_publication.key, pending_device.key);
    assert_eq!(failed_publication.previous, pending_package);
    assert!(
        runtime
            .mls_key_package_inventory(&device)
            .await
            .unwrap()
            .entries
            .is_empty(),
        "unknown remote outcome must not count as durable local published inventory"
    );
    let published = fixture
        .state
        .test_persistence()
        .mls_key_packages()
        .snapshot_all()
        .await
        .unwrap();
    assert_eq!(
        published.len(),
        packages_before.len() + request.keypackages.len()
    );
    for entry in &request.keypackages {
        let rows = published
            .iter()
            .filter(|row| row.id == entry.keypackage_id)
            .collect::<Vec<_>>();
        assert_eq!(rows.len(), 1);
        let row = rows[0];
        assert_eq!(&row.owner_actor_id, actor);
        assert_eq!(row.effective_scope.as_ref(), Some(scope));
        assert_eq!(row.device_id.as_deref(), Some(device.device_id.as_str()));
        assert_eq!(
            row.device_authorize_event_id.as_deref(),
            Some(device.authorization_event_id.as_str())
        );
        assert_eq!(row.keypackage_ref, entry.keypackage_ref);
        assert_eq!(
            row.key_package_bytes,
            arkret_canonical::base64url_decode(entry.keypackage.as_str()).unwrap()
        );
        assert!(row.claimed_at.is_none());
        assert!(row.consumed_at.is_none());
    }
    let accepted_packages = boxed_step(|| native_business_footprint(fixture)).await;
    drop(device);
    drop(runtime);
    drop(edge);

    let edge = make_edge();
    let runtime = ManagedDeviceRuntime::new(edge.clone()).unwrap();
    assert_eq!(
        arkret_bridge_runtime::FileAuthoringStore::new(path.to_owned())
            .unwrap()
            .load(&failed_publication.key)
            .unwrap(),
        Some(pending_package)
    );
    let device = boxed_step(|| runtime.device_for_actor(actor))
        .await
        .unwrap();
    assert_eq!(device.authorization_event_id, original.event.event_id);
    assert_eq!(device.authorization_commit, original.commit);
    let replay = boxed_step(|| runtime.prepare_mls_key_packages(&device, 2))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        arkret_canonical::canonical_json_bytes(&replay).unwrap(),
        request_bytes,
        "cold publication must recover the original complete signed request"
    );
    boxed_step(|| runtime.maintain_mls_key_packages(&device, 2))
        .await
        .unwrap();
    let inventory = runtime.mls_key_package_inventory(&device).await.unwrap();
    assert_eq!(inventory.entries.len(), request.keypackages.len());
    assert_eq!(
        inventory.usable_single_use_count(chrono::Utc::now()),
        request.keypackages.len()
    );
    for entry in &request.keypackages {
        let retained = inventory.entries.get(&entry.keypackage_id).unwrap();
        assert_eq!(retained.keypackage_ref.as_str(), entry.keypackage_ref);
        assert!(
            retained.has_private_state,
            "the original private bundle must survive the cold reopen"
        );
    }
    assert!(
        boxed_step(|| runtime.prepare_mls_key_packages(&device, 2))
            .await
            .unwrap()
            .is_none()
    );
    let mut final_packages = fixture
        .state
        .test_persistence()
        .mls_key_packages()
        .snapshot_all()
        .await
        .unwrap();
    let mut published = published;
    final_packages.sort_by(|a, b| a.id.cmp(&b.id));
    published.sort_by(|a, b| a.id.cmp(&b.id));
    assert_eq!(
        final_packages, published,
        "retry must preserve exact accepted public package rows"
    );
    assert_eq!(
        boxed_step(|| native_business_footprint(fixture)).await,
        accepted_packages
    );
    assert_eq!(
        boxed_step(|| runtime_recovery_authorizations(fixture, actor)).await,
        vec![original]
    );
    assert_eq!(fault.hits.lock().unwrap().len(), 2);
    eprintln!(
        "native runtime recovery: initial authorization and KeyPackage publication preserved exact pending custody, original Device/Commit and private package bundles across two cold reopens"
    );
}
