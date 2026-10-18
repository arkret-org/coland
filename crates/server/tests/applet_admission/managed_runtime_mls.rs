//! Real native MLS publication, encrypted custody and cold exact recovery.
use coland_storage::MlsKeyPackageStore as _;

use super::*;

fn operation(original: &AppletAuthoringTransactionRequestBody) -> String {
    format!(
        "initial-device/{}",
        original
            .authoring_context
            .principal_control_commit
            .event_ref
    )
}

async fn packages(
    context: &RuntimeContext,
    account: &arkret::AccountId,
) -> Vec<coland_storage::MlsKeyPackageRow> {
    let store = coland_storage_postgres::PgMlsKeyPackageStore {
        pool: context.fixture.pool.clone(),
    };
    let mut rows: Vec<_> = store
        .snapshot_all()
        .await
        .unwrap()
        .into_iter()
        .filter(|row| &row.owner_account_id == account)
        .collect();
    rows.sort_by(|a, b| a.id.cmp(&b.id));
    rows
}

fn publish(
    context: Box<RuntimeContext>,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Box<RuntimeContext>> + Send>> {
    Box::pin(async move {
        let scope = ScopeRef::Realm {
            realm_id: context.fixture.realm.clone(),
        };
        for (account, original, _) in &context.accepted {
            let id = operation(original);
            let original_request;
            {
                let store = FileAuthoringStore::shared(context.store_path.clone()).unwrap();
                let edge = host_with_retry(
                    context.config.clone(),
                    store.clone(),
                    arkret_http_client::RetryConfig::standard(0),
                );
                let author = Arc::new(ManagedActorAuthoringService::new(edge.clone()).unwrap());
                *context.native.managed_author.lock().unwrap() = Some(author);
                let runtime = ManagedDeviceRuntime::new(edge.clone()).unwrap();
                let device = runtime
                    .recover_initial_device(account, &id, &scope)
                    .await
                    .unwrap()
                    .unwrap();
                let other = ManagedDeviceRuntime::new(edge.clone()).unwrap();
                let (first, second) = tokio::join!(
                    runtime.prepare_mls_key_packages(&device, 2),
                    other.prepare_mls_key_packages(&device, 2),
                );
                let prepared = first.unwrap().unwrap();
                assert_eq!(
                    arkret_canonical::canonical_json_bytes(&prepared).unwrap(),
                    arkret_canonical::canonical_json_bytes(&second.unwrap().unwrap()).unwrap(),
                    "independent writers must return the committed original"
                );
                original_request = arkret_canonical::canonical_json_bytes(&prepared).unwrap();
                let before = store.entries_with_prefix("managed-device/v1/").unwrap();
                let again = runtime
                    .prepare_mls_key_packages(&device, 2)
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(
                    original_request,
                    arkret_canonical::canonical_json_bytes(&again).unwrap()
                );
                assert_eq!(
                    before,
                    store.entries_with_prefix("managed-device/v1/").unwrap()
                );
                assert!(before.iter().all(|(_, value)| value.starts_with("v1.")
                    && !value.contains("serialized_state")
                    && !value.contains("keypackages")));
                assert!(
                    runtime
                        .mls_key_package_inventory(&device)
                        .await
                        .unwrap()
                        .entries
                        .is_empty()
                );
                assert!(
                    packages(&context, account).await.is_empty(),
                    "private preparation must not publish before its CAS"
                );
                context.lost.attempts.lock().unwrap().clear();
                context
                    .lost
                    .armed
                    .store(true, std::sync::atomic::Ordering::SeqCst);
                assert!(
                    runtime.maintain_mls_key_packages(&device, 2).await.is_err(),
                    "actual accepted reply is lost and automatic retry is disabled"
                );
                assert!(!std::sync::atomic::AtomicBool::load(
                    &context.lost.armed,
                    std::sync::atomic::Ordering::SeqCst,
                ));
                assert_eq!(packages(&context, account).await.len(), 2);
                assert!(
                    runtime
                        .mls_key_package_inventory(&device)
                        .await
                        .unwrap()
                        .entries
                        .is_empty()
                );
                let attempts = context.lost.attempts.lock().unwrap();
                assert_eq!(attempts.len(), 1);
                assert_eq!(attempts[0].1, original_request);
                assert!(
                    attempts[0].2.is_empty(),
                    "upload retains its registered no-header contract"
                );
                drop(attempts);
                *context.native.managed_author.lock().unwrap() = None;
            }
            let second_request;
            {
                let inner = FileAuthoringStore::shared(context.store_path.clone()).unwrap();
                let store = Arc::new(FailOutcomeStore {
                    inner,
                    armed: std::sync::atomic::AtomicBool::new(false),
                });
                let edge = host_with_retry(
                    context.config.clone(),
                    store.clone(),
                    arkret_http_client::RetryConfig::standard(0),
                );
                let author = Arc::new(ManagedActorAuthoringService::new(edge.clone()).unwrap());
                *context.native.managed_author.lock().unwrap() = Some(author);
                let runtime = ManagedDeviceRuntime::new(edge.clone()).unwrap();
                let device = runtime
                    .recover_initial_device(account, &id, &scope)
                    .await
                    .unwrap()
                    .unwrap();
                let prepared = runtime
                    .prepare_mls_key_packages(&device, 2)
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(
                    original_request,
                    arkret_canonical::canonical_json_bytes(&prepared).unwrap()
                );
                context.lost.attempts.lock().unwrap().clear();
                runtime.maintain_mls_key_packages(&device, 2).await.unwrap();
                assert_eq!(context.lost.attempts.lock().unwrap()[0].1, original_request);
                assert_eq!(packages(&context, account).await.len(), 2);
                let inventory = runtime.mls_key_package_inventory(&device).await.unwrap();
                assert_eq!(inventory.usable_single_use_count(chrono::Utc::now()), 2);
                let rows = packages(&context, account).await;
                for entry in inventory.entries.values() {
                    let row = rows
                        .iter()
                        .find(|row| row.keypackage_ref == entry.keypackage_ref.as_str())
                        .unwrap();
                    assert_eq!(row.effective_scope.as_ref(), Some(&scope));
                    assert_eq!(row.device_id.as_deref(), Some(device.device_id.as_str()));
                    assert_eq!(
                        row.device_authorize_event_id.as_deref(),
                        Some(device.authorization_event_id.as_str())
                    );
                }
                let prepared = runtime
                    .prepare_mls_key_packages(&device, 3)
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(prepared.keypackages.len(), 1);
                second_request = arkret_canonical::canonical_json_bytes(&prepared).unwrap();
                store.armed.store(true, std::sync::atomic::Ordering::SeqCst);
                let error = runtime
                    .maintain_mls_key_packages(&device, 3)
                    .await
                    .unwrap_err();
                assert!(
                    error.to_string().contains("injected post-acceptance"),
                    "{error}"
                );
                assert_eq!(packages(&context, account).await.len(), 3);
                assert_eq!(
                    runtime
                        .mls_key_package_inventory(&device)
                        .await
                        .unwrap()
                        .usable_single_use_count(chrono::Utc::now()),
                    2
                );
                *context.native.managed_author.lock().unwrap() = None;
            }
            {
                let store = FileAuthoringStore::shared(context.store_path.clone()).unwrap();
                let edge = host_with_retry(
                    context.config.clone(),
                    store.clone(),
                    arkret_http_client::RetryConfig::standard(0),
                );
                let author = Arc::new(ManagedActorAuthoringService::new(edge.clone()).unwrap());
                *context.native.managed_author.lock().unwrap() = Some(author);
                let runtime = ManagedDeviceRuntime::new(edge.clone()).unwrap();
                let device = runtime
                    .recover_initial_device(account, &id, &scope)
                    .await
                    .unwrap()
                    .unwrap();
                let prepared = runtime
                    .prepare_mls_key_packages(&device, 3)
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(
                    second_request,
                    arkret_canonical::canonical_json_bytes(&prepared).unwrap()
                );
                runtime.maintain_mls_key_packages(&device, 3).await.unwrap();
                let inventory = runtime.mls_key_package_inventory(&device).await.unwrap();
                assert_eq!(inventory.usable_single_use_count(chrono::Utc::now()), 3);
                let before = store.entries_with_prefix("managed-device/v1/").unwrap();
                let published = packages(&context, account).await;
                context.lost.attempts.lock().unwrap().clear();
                runtime.maintain_mls_key_packages(&device, 3).await.unwrap();
                assert_eq!(
                    before,
                    store.entries_with_prefix("managed-device/v1/").unwrap()
                );
                assert_eq!(published, packages(&context, account).await);
                assert!(
                    context.lost.attempts.lock().unwrap().is_empty(),
                    "sufficient inventory makes no HTTP probe"
                );
                *context.native.managed_author.lock().unwrap() = None;
            }
        }
        // This is the same configured entry used by both production host loops.
        let mut config = context.config.clone();
        config.arkret.managed_actor_authoring.device =
            Some(arkret_bridge_runtime::ManagedDeviceBootstrapConfig {
                actions: vec![
                    arkret_wire::CapabilityActionId::from_wire("ak.applet.join").unwrap(),
                    arkret_wire::CapabilityActionId::EventRead,
                ],
                lifetime_seconds: 3600,
                mls: true,
                key_package_inventory_target: 4,
            });
        {
            let store = FileAuthoringStore::shared(context.store_path.clone()).unwrap();
            let edge = host(config, store);
            let author = Arc::new(ManagedActorAuthoringService::new(edge.clone()).unwrap());
            *context.native.managed_author.lock().unwrap() = Some(author);
            let devices = ManagedDeviceRuntime::bootstrap_if_configured(edge.clone())
                .await
                .unwrap();
            assert_eq!(devices.len(), 2);
            let runtime = ManagedDeviceRuntime::new(edge).unwrap();
            for device in &devices {
                assert_eq!(
                    runtime
                        .mls_key_package_inventory(device)
                        .await
                        .unwrap()
                        .usable_single_use_count(chrono::Utc::now()),
                    4
                );
                assert_eq!(packages(&context, &device.account_id).await.len(), 4);
            }
            *context.native.managed_author.lock().unwrap() = None;
        }
        context
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn independent_native_mls_inventory_survives_lost_reply_and_failed_outcome_persistence() {
    let context = Box::new(setup_with_mls(true).await);
    let context = recover(context).await;
    let context = publish(context).await;
    retained(context).await;
}
