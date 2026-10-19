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
            .find(|row| row.owner_account_id == device.account_id)
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
        assert_eq!(runtime.installed_mls_epoch(&device).await.unwrap(), Some(1));
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
