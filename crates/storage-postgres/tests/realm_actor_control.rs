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

#[tokio::test]
async fn realm_bot_consumes_native_mentions_and_publishes_own_reply() {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::WARN)
        .with_test_writer()
        .try_init();
    let database = coland_storage_postgres::test_database::TestDatabase::lease().await;
    Box::pin(applet_authoring::realm_bot_runtime(database.pool(), false)).await;
}

#[tokio::test]
async fn realm_bot_retains_output_across_mls_update_and_worker_restart() {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::WARN)
        .with_test_writer()
        .try_init();
    let database = coland_storage_postgres::test_database::TestDatabase::lease().await;
    Box::pin(applet_authoring::realm_bot_runtime(database.pool(), true)).await;
}

#[tokio::test]
async fn bridge_bot_recovers_same_identity_after_admin_reenable_and_daily_key_loss() {
    let database = coland_storage_postgres::test_database::TestDatabase::lease().await;
    Box::pin(applet_authoring::realm_runtime_key_loss_recovery(
        database.pool(),
        true,
    ))
    .await;
}

#[tokio::test]
async fn bridge_ghost_recovers_same_identity_after_admin_reenable_and_daily_key_loss() {
    let database = coland_storage_postgres::test_database::TestDatabase::lease().await;
    Box::pin(applet_authoring::realm_runtime_key_loss_recovery(
        database.pool(),
        false,
    ))
    .await;
}

#[tokio::test]
async fn bridge_recovery_cancelled_before_publication_requires_a_new_intent() {
    let database = coland_storage_postgres::test_database::TestDatabase::lease().await;
    Box::pin(applet_authoring::realm_runtime_cancelled_recovery(
        database.pool(),
    ))
    .await;
}

#[tokio::test]
async fn bridge_recovery_replacement_requires_the_exact_pending_original() {
    let database = coland_storage_postgres::test_database::TestDatabase::lease().await;
    Box::pin(applet_authoring::realm_runtime_replaced_recovery(
        database.pool(),
    ))
    .await;
}

#[tokio::test]
async fn bridge_closes_an_unaccepted_recovery_only_after_a_proven_cas_fence() {
    let database = coland_storage_postgres::test_database::TestDatabase::lease().await;
    Box::pin(applet_authoring::realm_runtime_unaccepted_recovery(
        database.pool(),
    ))
    .await;
}

#[tokio::test]
async fn bridge_recovers_lost_daily_keys_with_an_unaccepted_control_rotation() {
    let database = coland_storage_postgres::test_database::TestDatabase::lease().await;
    Box::pin(
        applet_authoring::realm_runtime_recovery_with_unresolved_control(database.pool(), false),
    )
    .await;
}

#[tokio::test]
async fn bridge_recovery_retains_the_original_accepted_control_rotation_receipt() {
    let database = coland_storage_postgres::test_database::TestDatabase::lease().await;
    Box::pin(
        applet_authoring::realm_runtime_recovery_with_unresolved_control(database.pool(), true),
    )
    .await;
}

#[tokio::test]
async fn bridge_keeps_original_claim_across_real_governance_handoff_and_cold_welcome() {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::WARN)
        .with_test_writer()
        .try_init();
    let database = coland_storage_postgres::test_database::TestDatabase::lease().await;
    Box::pin(applet_authoring::realm_runtime_mls_handoff(database.pool())).await;
}
