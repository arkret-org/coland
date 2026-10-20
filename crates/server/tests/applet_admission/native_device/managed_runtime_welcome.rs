//! Real host custody, independent RFC MLS join and cold recipient retries.
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use arkret_bridge_runtime::managed_actor_authoring::ManagedActorAuthoringService;
use arkret_bridge_runtime::managed_device::ManagedDeviceRuntime;
use arkret_bridge_runtime::{AuthoringStore, BridgeError, FileAuthoringStore};
use coland_storage::{DeviceRevocationStore as _, MlsKeyPackageStore as _};

use super::*;

struct CheckpointStore {
    inner: Arc<dyn AuthoringStore>,
    writes: AtomicUsize,
    fail_checkpoint: bool,
    lose_consume: Arc<crate::managed_runtime::LostNativeReply>,
    armed: AtomicBool,
}
impl AuthoringStore for CheckpointStore {
    fn load(&self, key: &str) -> arkret_bridge_runtime::Result<Option<String>> {
        AuthoringStore::load(self.inner.as_ref(), key)
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
        let checkpoint = expected
            .iter()
            .any(|(key, value)| key.starts_with("managed-device/v1/") && value.is_some())
            && self.writes.fetch_add(1, Ordering::SeqCst) == 1
            && self.armed.swap(false, Ordering::SeqCst);
        if checkpoint && self.fail_checkpoint {
            return Err(BridgeError::Database(
                "injected Welcome checkpoint durability failure".into(),
            ));
        }
        let written = self.inner.compare_exchange_batch(expected, writes)?;
        if checkpoint && written {
            self.lose_consume.armed.store(true, Ordering::SeqCst);
        }
        Ok(written)
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_runtime_welcome_survives_checkpoint_failure_lost_consume_and_cold_ack() {
    for ghost in [false, true] {
        tokio::spawn(exercise(ghost)).await.unwrap();
    }
}

fn exercise(ghost: bool) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> {
    Box::pin(async move {
        let context = Box::new(crate::managed_runtime::setup_with_mls(true).await);
        let context = crate::managed_runtime::recover(context).await;
        let scope = ScopeRef::Realm {
            realm_id: context.fixture.realm.clone(),
        };
        let mut genesis =
            native_phase(|| activate_mls_with_private_state(&context.fixture, scope.clone())).await;
        let _read = native_phase(|| {
            native_package_business_parent_in_scope(
                &context.fixture,
                &context.native.package,
                vec![],
                vec!["ak.event.read".into()],
                None,
                scope.clone(),
            )
        })
        .await;
        let (account, original, _) = &context.accepted[usize::from(ghost)];
        let operation = format!(
            "initial-device/{}",
            original
                .authoring_context
                .principal_control_commit
                .event_ref
        );
        let store = FileAuthoringStore::shared(context.store_path.clone()).unwrap();
        let edge = crate::managed_runtime::host_with_retry(
            context.config.clone(),
            store.clone(),
            arkret_http_client::RetryConfig::standard(0),
        );
        *context.native.managed_author.lock().unwrap() = Some(Arc::new(
            ManagedActorAuthoringService::new(edge.clone()).unwrap(),
        ));
        let runtime = ManagedDeviceRuntime::new(edge.clone()).unwrap();
        let device = runtime
            .recover_initial_device(account, &operation, &scope)
            .await
            .unwrap()
            .unwrap();
        runtime.maintain_mls_key_packages(&device, 2).await.unwrap();
        let packages = coland_storage_postgres::PgMlsKeyPackageStore {
            pool: context.fixture.pool.clone(),
        };
        let rows = native_phase(|| packages.snapshot_all()).await.unwrap();
        let package = rows
            .iter()
            .find(|row| row.owner_actor_id == device.account_id)
            .unwrap();
        let device_store = coland_storage_postgres::PgDeviceRevocationStore {
            pool: context.fixture.pool.clone(),
        };
        let authority = native_phase(|| {
            device_store.applet_managed_device_authority(
                &device.account_id,
                &device.device_id,
                chrono::Utc::now(),
            )
        })
        .await
        .unwrap()
        .unwrap();
        let human_key =
            SigningKey::from_bytes(&context.fixture.pcr.history.founding_device_signing_seed);
        let mut command = request(&authority, &human_key, &scope, &package.keypackage_ref);
        command.requester_account_id = Some(context.fixture.pcr.history.account.clone());
        if let arkret_models_crypto::PeerKeyPackageRequesterAuthorization::Device {
            verification_method,
            requester_device_id,
            device_authorize_event_id,
            ..
        } = &mut command.requester_authorization
        {
            *verification_method = context
                .fixture
                .pcr
                .history
                .device_verification_method
                .clone();
            *requester_device_id = context.fixture.pcr.history.founding_device_id.clone();
            *device_authorize_event_id = context.fixture.pcr.history.events[1].event_id.clone();
        } else {
            unreachable!();
        }
        resign(&mut command, &human_key);
        let body = serde_json::to_value(&command).unwrap();
        let (status, value) = native_phase(|| {
            context.fixture.admin_post(
                "/_arkret/self/keys/keypackages/claim",
                ServiceOperationId::SelfKeysKeypackagesCommandClaimV1.as_str(),
                &body,
                Some(command.claim_request_id.as_str()),
            )
        })
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "real Human claim of independently generated Device package: {value}"
        );
        let claim: arkret_models_crypto::KeyPackagesClaimOutcome =
            serde_json::from_value(value).unwrap();
        let guard = coland_storage::AppletManagedDeviceScopeGuard {
            authority: authority.clone(),
            effective_scope: scope.clone(),
            service_did_document: applet_service_id_document(&context.native.package),
        };
        let (welcome, accepted, _) = native_phase(|| {
            accepted_add(
                &context.fixture,
                &authority,
                &scope,
                &mut genesis,
                &claim.claims[0],
                &guard,
            )
        })
        .await;
        assert_eq!(accepted.event.event_id, welcome.commit_event_ref);
        context.lost.attempts.lock().unwrap().clear();
        drop(device);
        drop(runtime);
        drop(edge);
        *context.native.managed_author.lock().unwrap() = None;
        // The first CAS stores the exact queue page; the second must be the
        // joined group, private identity and original signed consume together.
        for fail_checkpoint in [true, false] {
            let injected: Arc<dyn AuthoringStore> = Arc::new(CheckpointStore {
                inner: store.clone(),
                writes: AtomicUsize::new(if fail_checkpoint { 0 } else { 1 }),
                fail_checkpoint,
                lose_consume: context.lost.clone(),
                armed: AtomicBool::new(true),
            });
            let edge = crate::managed_runtime::host_with_retry(
                context.config.clone(),
                injected,
                arkret_http_client::RetryConfig::standard(0),
            );
            let runtime = ManagedDeviceRuntime::new(edge.clone()).unwrap();
            let device = runtime
                .recover_initial_device(account, &operation, &scope)
                .await
                .unwrap()
                .unwrap();
            let reader = runtime.open_reader(&device).await.unwrap();
            let old = reader.client().clone();
            let error = runtime
                .poll_welcome_queue(&device, &reader)
                .await
                .unwrap_err();
            if fail_checkpoint {
                assert!(
                    error.to_string().contains("checkpoint durability failure"),
                    "{error}"
                );
                assert_eq!(runtime.installed_mls_epoch(&device).await.unwrap(), None);
                assert!(
                    !context
                        .lost
                        .attempts
                        .lock()
                        .unwrap()
                        .iter()
                        .any(|(_, body, _)| {
                            serde_json::from_slice::<Value>(body)
                                .ok()
                                .is_some_and(|body| body.get("recipient_durable_receipt").is_some())
                        }),
                    "consume must never precede durable checkpoint"
                );
            } else {
                assert!(error.to_string().contains("503"), "{error}");
                assert_eq!(runtime.installed_mls_epoch(&device).await.unwrap(), Some(1));
            }
            drop(reader);
            assert!(
                old.check_context().is_err(),
                "cold replacement cannot revive the retired reader"
            );
        }
        let edge = crate::managed_runtime::host_with_retry(
            context.config.clone(),
            store.clone(),
            arkret_http_client::RetryConfig::standard(0),
        );
        let runtime = ManagedDeviceRuntime::new(edge.clone()).unwrap();
        let device = runtime
            .recover_initial_device(account, &operation, &scope)
            .await
            .unwrap()
            .unwrap();
        let reader = runtime.open_reader(&device).await.unwrap();
        let progress = runtime.poll_welcome_queue(&device, &reader).await.unwrap();
        assert!(progress.acknowledged);
        assert_eq!(progress.durable_welcomes, 1);
        assert_eq!(runtime.installed_mls_epoch(&device).await.unwrap(), Some(1));
        assert!(
            device
                .client()
                .receive_device_messages(None, Some(10))
                .await
                .unwrap()
                .deliveries
                .is_empty()
        );
        let attempts = context
            .lost
            .attempts
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, body, _)| {
                serde_json::from_slice::<Value>(body)
                    .ok()
                    .is_some_and(|body| body.get("recipient_durable_receipt").is_some())
            })
            .cloned()
            .collect::<Vec<_>>();
        assert_eq!(attempts.len(), 2);
        assert_eq!(
            attempts[0].1, attempts[1].1,
            "cold consume retry preserves the full original signed body"
        );
        assert_ne!(attempts[0].0.nonce, attempts[1].0.nonce);
        let scans = context
            .lost
            .attempts
            .lock()
            .unwrap()
            .iter()
            .filter_map(|(metadata, bytes, _)| {
                serde_json::from_slice::<arkret_wire::StreamScanRequest>(bytes)
                    .ok()
                    .map(|request| (metadata.clone(), request))
            })
            .collect::<Vec<_>>();
        assert_eq!(
            scans.len(),
            2,
            "each fresh join must obtain its actual historical stream source"
        );
        for (metadata, scan) in scans {
            assert_eq!(metadata.account_id, device.account_id);
            assert_eq!(metadata.device_id, device.device_id);
            assert_eq!(metadata.effective_scope, scope);
            assert_eq!(scan.realm_id, accepted.commit.realm_id);
            assert_eq!(scan.stream_ref, accepted.commit.stream_ref);
            assert_eq!(
                scan.direction,
                arkret_wire::StreamScanDirection::Before(Some(
                    accepted.commit.stream_position.checked_add(1).unwrap()
                ))
            );
            assert_eq!(
                scan.limit, 1,
                "historical resolution must not broaden into a Realm scan"
            );
        }
        let mut replica =
            garth::own_station_results::OwnStationDeviceReplica::new(scope.clone()).unwrap();
        let current = reader
            .client()
            .snapshot_head(scope.realm_id())
            .await
            .unwrap();
        let snapshot = garth::own_station_results::consume_own_station_device_snapshot(&current)
            .unwrap()
            .clone();
        let original = reader
            .client()
            .snapshot_by_ref(scope.realm_id(), &snapshot.snapshot_id)
            .await
            .unwrap();
        assert_eq!(
            garth::own_station_results::consume_own_station_device_snapshot(&original).unwrap(),
            &snapshot
        );
        replica.install_current(current).unwrap();
        assert!(
            replica.head().unwrap().is_none(),
            "current coverage is not downloaded history"
        );
        replica
            .bootstrap_current_head(reader.client())
            .await
            .unwrap();
        assert_eq!(
            replica.head().unwrap(),
            Some(&snapshot.visible_stream_heads[0])
        );
        let scan_request = arkret_wire::StreamScanRequest {
            realm_id: scope.realm_id().clone(),
            stream_ref: snapshot.visible_stream_heads[0].stream_ref.clone(),
            direction: arkret_wire::StreamScanDirection::After(Some(
                snapshot.visible_stream_heads[0].stream_position,
            )),
            limit: 1,
        };
        let scan = reader
            .client()
            .scan_commit_stream(&scan_request)
            .await
            .unwrap();
        let page = replica
            .apply_bound_scan(reader.client(), scan)
            .await
            .unwrap();
        assert!(page.rows().unwrap().is_empty());
        native_phase(|| {
            exercise_stream(
                &context,
                &operation,
                &device,
                &runtime,
                &reader,
                &mut genesis,
                &accepted,
            )
        })
        .await;
        // A stale opaque cursor is a transport continuation failure, not an
        // MLS reset. Revocation/integrity refusals must never take this path.
        for code in [
            arkret_wire::ErrorCode::CursorRevoked,
            arkret_wire::ErrorCode::CursorIntegrityInvalid,
        ] {
            context.lost.queue_reads.lock().unwrap().clear();
            *context.lost.cursor_error_once.lock().unwrap() = Some(code);
            let error = runtime
                .poll_welcome_queue(&device, &reader)
                .await
                .unwrap_err();
            assert!(error.to_string().contains(code.as_str()), "{error}");
            {
                let reads = context.lost.queue_reads.lock().unwrap();
                assert_eq!(
                    reads.len(),
                    1,
                    "an authority/integrity refusal cannot restart the queue"
                );
                assert!(reads[0].1.is_some());
            }
            assert_eq!(runtime.installed_mls_epoch(&device).await.unwrap(), Some(2));
        }
        context.lost.queue_reads.lock().unwrap().clear();
        *context.lost.cursor_error_once.lock().unwrap() =
            Some(arkret_wire::ErrorCode::CursorExpired);
        let resumed = runtime.poll_welcome_queue(&device, &reader).await.unwrap();
        assert!(!resumed.acknowledged);
        let reads = context.lost.queue_reads.lock().unwrap().clone();
        assert_eq!(reads.len(), 2);
        assert!(reads[0].1.is_some());
        assert!(
            reads[1].1.is_none(),
            "expiry requires a fresh current-authorized read"
        );
        for (metadata, _) in &reads {
            assert_eq!(metadata.account_id, device.account_id);
            assert_eq!(metadata.device_id, device.device_id);
            assert_eq!(metadata.effective_scope, scope);
        }
        assert_ne!(reads[0].0.nonce, reads[1].0.nonce);
        assert_eq!(runtime.installed_mls_epoch(&device).await.unwrap(), Some(2));
        // The actual persistent worker entry used by both production hosts
        // performs a real native queue read; its shutdown retires and joins
        // every per-Device task before the test removes private custody.
        let mut configured = context.config.clone();
        configured.arkret.managed_actor_authoring.device =
            Some(arkret_bridge_runtime::ManagedDeviceBootstrapConfig {
                actions: vec![
                    arkret_wire::CapabilityActionId::from_wire("ak.applet.join").unwrap(),
                    arkret_wire::CapabilityActionId::EventRead,
                ],
                lifetime_seconds: 3600,
                mls: true,
                key_package_inventory_target: 2,
            });
        let worker_edge = crate::managed_runtime::host_with_retry(
            configured,
            store.clone(),
            arkret_http_client::RetryConfig::standard(0),
        );
        let mut workers =
            arkret_bridge_runtime::managed_device::ManagedDeviceWorkers::new(worker_edge).unwrap();
        context.lost.responses.lock().unwrap().clear();
        workers.tick().await.unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(30), async {
            loop {
                if context
                    .lost
                    .responses
                    .lock()
                    .unwrap()
                    .iter()
                    .any(|(metadata, path, status)| {
                        metadata.account_id == device.account_id
                            && metadata.device_id == device.device_id
                            && path == "/_arkret/self/device_messages"
                            && *status == Some(StatusCode::OK)
                    })
                {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the real native worker must receive an authorized queue response");
        workers.shutdown().await;
        // Replenishing a joined group's inventory must update that same
        // checkpoint provider rather than lose the newly generated bundles.
        runtime.maintain_mls_key_packages(&device, 2).await.unwrap();
        drop(reader);
        assert!(replica.snapshot().is_err());
        assert!(replica.head().is_err());
        assert!(page.rows().is_err());
        assert!(original.value().is_err());
        drop(device);
        drop(runtime);
        drop(edge);
        let edge = crate::managed_runtime::host_with_retry(
            context.config.clone(),
            store.clone(),
            arkret_http_client::RetryConfig::standard(0),
        );
        let runtime = ManagedDeviceRuntime::new(edge.clone()).unwrap();
        let device = runtime
            .recover_initial_device(account, &operation, &scope)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(runtime.installed_mls_epoch(&device).await.unwrap(), Some(2));
        assert_eq!(
            runtime
                .mls_key_package_inventory(&device)
                .await
                .unwrap()
                .usable_single_use_count(chrono::Utc::now()),
            2
        );
        assert!(
            store
                .entries_with_prefix("managed-device/v1/")
                .unwrap()
                .iter()
                .all(|(_, bytes)| bytes.starts_with("v1.")
                    && !bytes.contains("serialized_state")
                    && !bytes.contains("recipient_durable_receipt"))
        );
        drop(device);
        drop(runtime);
        drop(edge);
        drop(store);
        crate::managed_runtime::retained(context).await;
    })
}

struct StreamCheckpointStore {
    inner: Arc<dyn AuthoringStore>,
    fail_next: AtomicBool,
}
impl AuthoringStore for StreamCheckpointStore {
    fn load(&self, key: &str) -> arkret_bridge_runtime::Result<Option<String>> {
        AuthoringStore::load(self.inner.as_ref(), key)
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
        if expected
            .iter()
            .any(|(key, value)| key.starts_with("managed-device/v1/") && value.is_some())
            && self.fail_next.swap(false, Ordering::SeqCst)
        {
            return Err(BridgeError::Database(
                "injected stream checkpoint failure".into(),
            ));
        }
        self.inner.compare_exchange_batch(expected, writes)
    }
}

async fn remote_update(
    fixture: &Fixture,
    scope: &ScopeRef,
    genesis: &mut MlsGenesisRuntime,
    accepted_add: &arkret_wire::CommittedEventFullView,
) -> arkret_wire::CommittedEventFullView {
    genesis
        .group
        .install_recovered_own_commit(accepted_add, &genesis.accepted.event.event_id)
        .unwrap();
    let current = coland_storage_postgres::PgMlsGroupCurrentStore {
        pool: fixture.pool.clone(),
    }
    .current(scope)
    .await
    .unwrap()
    .unwrap();
    let binding = arkret_models_crypto::MlsGovernanceBindingPayload::new(
        scope.clone(),
        Some(accepted_add.event.event_id.clone()),
        1,
        2,
        current.value.current_key_access_revision,
    )
    .unwrap();
    let envelope = genesis
        .group
        .self_update_commit_with_governance_binding(&binding)
        .unwrap();
    let payload = arkret_models_crypto::MlsCommitPayload::new(
        accepted_add.event.event_id.clone(),
        current.value.current_key_access_revision,
        &envelope,
        binding,
    )
    .unwrap();
    let event = fixture.admin_event(
        EventKind::MlsCommit,
        scope.clone(),
        serde_json::to_value(payload).unwrap(),
    );
    let event_id = event.event_id.clone();
    let token = uuid::Uuid::now_v7();
    let request =
        arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequest::MlsCommit(
            arkret_wire::MlsCommitSubmission {
                commit_event: event,
                welcomes: vec![],
                idempotency_key: arkret_wire::UuidV7::new(token).unwrap(),
            },
        );
    let body = serde_json::to_value(request).unwrap();
    let (status, outcome) = fixture
        .admin_post(
            "/_arkret/self/events",
            ServiceOperationId::SelfEventsCommandSubmitV1.as_str(),
            &body,
            Some(&token.to_string()),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "real next remote MLS Commit: {outcome}"
    );
    let original = PgAuthorityCommitStore {
        pool: fixture.pool.clone(),
    }
    .committed_event(&event_id)
    .await
    .unwrap()
    .unwrap();
    arkret_wire::CommittedEventFullView {
        event: original.event,
        commit: original.commit,
    }
}

async fn exercise_stream(
    context: &crate::managed_runtime::RuntimeContext,
    operation: &str,
    device: &arkret_bridge_runtime::managed_device::ManagedDevice,
    runtime: &ManagedDeviceRuntime,
    reader: &arkret_bridge_runtime::managed_device::ManagedDeviceReader,
    genesis: &mut MlsGenesisRuntime,
    accepted_add: &arkret_wire::CommittedEventFullView,
) {
    let scope = ScopeRef::Realm {
        realm_id: context.fixture.realm.clone(),
    };
    let old_current = reader
        .client()
        .snapshot_head(scope.realm_id())
        .await
        .unwrap()
        .value()
        .unwrap()
        .clone();
    let update =
        native_phase(|| remote_update(&context.fixture, &scope, genesis, accepted_add)).await;
    assert!(update.commit.stream_position > accepted_add.commit.stream_position);
    // Both originals predate the first stream checkpoint. A snapshot-head
    // seed would silently skip the next epoch and the following state row.
    native_phase(|| {
        let event = context.fixture.admin_event(
            EventKind::RealmJoinRule,
            scope.clone(),
            json!({"value":"invite"}),
        );
        accepted_admin_domain_event(&context.fixture, event)
    })
    .await;
    let expected_head = reader
        .client()
        .snapshot_head(scope.realm_id())
        .await
        .unwrap()
        .value()
        .unwrap()
        .visible_stream_heads[0]
        .clone();
    let store = FileAuthoringStore::shared(context.store_path.clone()).unwrap();
    let failed = Arc::new(StreamCheckpointStore {
        inner: store.clone(),
        fail_next: AtomicBool::new(false),
    });
    let edge = crate::managed_runtime::host_with_retry(
        context.config.clone(),
        failed.clone(),
        arkret_http_client::RetryConfig::standard(0),
    );
    let candidate = ManagedDeviceRuntime::new(edge).unwrap();
    let mut candidate_device = candidate
        .recover_initial_device(&device.account_id, operation, &scope)
        .await
        .unwrap()
        .unwrap();
    let candidate_reader = candidate.open_reader(&candidate_device).await.unwrap();
    let before = store.entries_with_prefix("managed-device/v1/").unwrap();
    let original_device = candidate_device.device_id.clone();
    candidate_device.device_id =
        arkret_wire::DeviceId::new_v7_at(chrono::Utc::now().timestamp_millis().try_into().unwrap());
    let attempts = context.lost.attempts.lock().unwrap().len();
    let mismatch = candidate
        .poll_content_stream(&candidate_device, &candidate_reader)
        .await
        .unwrap_err();
    assert!(
        mismatch.to_string().contains("another original Device"),
        "{mismatch}"
    );
    assert_eq!(
        context.lost.attempts.lock().unwrap().len(),
        attempts,
        "reader confusion must fail before HTTP"
    );
    candidate_device.device_id = original_device;
    failed.fail_next.store(true, Ordering::SeqCst);
    let error = candidate
        .poll_content_stream(&candidate_device, &candidate_reader)
        .await
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("injected stream checkpoint failure"),
        "{error}"
    );
    assert_eq!(
        store.entries_with_prefix("managed-device/v1/").unwrap(),
        before,
        "head and merged private state must share one failed write"
    );
    assert_eq!(runtime.installed_mls_epoch(device).await.unwrap(), Some(1));
    assert_eq!(
        runtime
            .durable_stream_progress(device)
            .await
            .unwrap()
            .last_position,
        None
    );
    drop(candidate_reader);
    drop(candidate_device);
    drop(candidate);
    let progress = runtime.poll_content_stream(device, reader).await.unwrap();
    assert!(progress.durable_events > 0);
    assert_eq!(progress.epoch, Some(2));
    assert_eq!(progress.last_position, Some(expected_head.stream_position));
    assert_eq!(progress.pending_events, 1);
    assert_eq!(runtime.installed_mls_epoch(device).await.unwrap(), Some(2));
    let before = store.entries_with_prefix("managed-device/v1/").unwrap();
    *context.lost.snapshot_once.lock().unwrap() = Some(old_current);
    let stale = runtime
        .poll_content_stream(device, reader)
        .await
        .unwrap_err();
    assert!(stale.to_string().contains("current is behind"), "{stale}");
    assert_eq!(
        store.entries_with_prefix("managed-device/v1/").unwrap(),
        before,
        "a replayed valid old current must not bless a newer durable head"
    );
    let head = progress.last_position;
    let cold_edge = crate::managed_runtime::host_with_retry(
        context.config.clone(),
        store.clone(),
        arkret_http_client::RetryConfig::standard(0),
    );
    let cold = ManagedDeviceRuntime::new(cold_edge).unwrap();
    let cold_device = cold
        .recover_initial_device(&device.account_id, operation, &scope)
        .await
        .unwrap()
        .unwrap();
    let cold_reader = cold.open_reader(&cold_device).await.unwrap();
    let before = store.entries_with_prefix("managed-device/v1/").unwrap();
    let progress = cold
        .poll_content_stream(&cold_device, &cold_reader)
        .await
        .unwrap();
    assert_eq!(progress.durable_events, 0);
    assert_eq!(progress.pending_events, 1);
    assert_eq!(progress.last_position, head);
    assert_eq!(progress.epoch, Some(2));
    assert_eq!(
        store.entries_with_prefix("managed-device/v1/").unwrap(),
        before,
        "an unchanged idle read must not rewrite encrypted custody"
    );
    cold_reader.retire();
    assert!(
        cold.poll_content_stream(&cold_device, &cold_reader)
            .await
            .is_err()
    );
    assert_eq!(
        store.entries_with_prefix("managed-device/v1/").unwrap(),
        before
    );
}
