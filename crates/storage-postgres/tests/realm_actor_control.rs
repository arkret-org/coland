//! Real HTTP lifecycle backed by accepted identity, installation and private control.
#[path = "support/applet_authoring.rs"]
#[allow(dead_code)]
mod applet_authoring;
#[path = "support/ordinary_realm.rs"]
#[allow(dead_code)]
mod ordinary_realm;
#[tokio::test]
async fn realm_device_claims_remote_ordinary_device_and_commits_mls_add() {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::WARN)
        .with_test_writer()
        .try_init();
    let database = coland_storage_postgres::test_database::TestDatabase::lease().await;
    Box::pin(applet_authoring::realm_native_mls(database.pool())).await;
}
#[tokio::test]
async fn realm_actor_control_lifecycle_and_account_audit_preserve_identity() {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::WARN)
        .with_test_writer()
        .try_init();
    let database = coland_storage_postgres::test_database::TestDatabase::lease().await;
    Box::pin(applet_authoring::realm_native_creation(database.pool())).await;
}

#[tokio::test]
async fn bridge_runtime_authors_realm_identity_and_device_over_real_https() {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::WARN)
        .with_test_writer()
        .try_init();
    let database = coland_storage_postgres::test_database::TestDatabase::lease().await;
    Box::pin(applet_authoring::realm_bridge_runtime(database.pool())).await;
}

#[tokio::test]
async fn bridge_runtime_circle_only_device_preserves_blob_scope_over_real_https() {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::WARN)
        .with_test_writer()
        .try_init();
    let database = coland_storage_postgres::test_database::TestDatabase::lease().await;
    Box::pin(applet_authoring::realm_bridge_circle_runtime(
        database.pool(),
    ))
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn applet_configuration_preserves_original_intent_and_candidate_over_real_https() {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::WARN)
        .with_test_writer()
        .try_init();
    let database = coland_storage_postgres::test_database::TestDatabase::lease().await;
    Box::pin(applet_authoring::realm_applet_configuration(
        database.pool(),
    ))
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bridge_completion_receiver_preserves_original_over_signed_retries_cold_recovery_and_expiry()
 {
    let database = coland_storage_postgres::test_database::TestDatabase::lease().await;
    Box::pin(applet_authoring::realm_bridge_completion_receiver(
        database.pool(),
    ))
    .await;
}
