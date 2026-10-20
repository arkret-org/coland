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
    eprintln!(
        "private delivery sizes: input={}, material={}",
        std::mem::size_of::<coland_storage::AccountContentDeliveryInput>(),
        std::mem::size_of::<arkret_models_integration::RealmActorMaterialOutcome>()
    );
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
