//! Applet and Realm actor admission through the shared production-HTTP fixtures.
//! Bot/Ghost creation has one realm_control original, no Account/PCR aggregate.

#[path = "../../storage-postgres/tests/support/applet_authoring.rs"]
#[allow(dead_code)]
mod applet_authoring;
#[path = "../../storage-postgres/tests/support/ordinary_realm.rs"]
#[allow(dead_code)]
mod ordinary_realm;

#[tokio::test]
async fn service_install_is_atomic_and_cannot_inject_bot_account_or_actor_inventory() {
    use coland_storage::contract_tests::{
        AppletFormalCommitContractStores, assert_applet_formal_commit_transaction_contract,
    };
    use coland_storage_postgres::{
        PgAppletStore, PgAuthorityCommitStore, PgEventCommitUnitOfWork, PgEventStore,
    };
    let database = coland_storage_postgres::test_database::TestDatabase::lease().await;
    let pool = database.pool();
    let unit_of_work = PgEventCommitUnitOfWork::new(pool.clone());
    let authority = PgAuthorityCommitStore { pool: pool.clone() };
    let events = PgEventStore { pool: pool.clone() };
    let factory = Box::pin(applet_authoring::AppletAuthoringFactory::new(pool.clone())).await;
    let applets = PgAppletStore { pool };
    Box::pin(assert_applet_formal_commit_transaction_contract(
        AppletFormalCommitContractStores {
            unit_of_work: &unit_of_work,
            authority: &authority,
            events: &events,
            applets: &applets,
            factory: &factory,
        },
        &format!("server-formal-applet-{}", uuid::Uuid::now_v7()),
    ))
    .await;
}

#[tokio::test]
async fn ghost_creation_quota_rolls_back_with_the_unit_and_counts_exact_retry_once() {
    let database = coland_storage_postgres::test_database::TestDatabase::lease().await;
    Box::pin(applet_authoring::realm_native_creation(database.pool())).await;
}

#[tokio::test]
async fn realm_device_mls_remote_account_claim_welcome_and_consume_keep_originals() {
    let database = coland_storage_postgres::test_database::TestDatabase::lease().await;
    Box::pin(applet_authoring::realm_native_mls(database.pool())).await;
}

#[tokio::test]
async fn realm_runtime_cold_recovery_and_native_messages_use_real_https() {
    let database = coland_storage_postgres::test_database::TestDatabase::lease().await;
    Box::pin(applet_authoring::realm_bridge_runtime(database.pool())).await;
}

#[tokio::test]
async fn realm_runtime_circle_scope_never_becomes_an_account_or_foreign_realm() {
    let database = coland_storage_postgres::test_database::TestDatabase::lease().await;
    Box::pin(applet_authoring::realm_bridge_circle_runtime(
        database.pool(),
    ))
    .await;
}

#[tokio::test]
async fn configuration_review_and_lost_creation_response_recover_the_exact_original() {
    let database = coland_storage_postgres::test_database::TestDatabase::lease().await;
    Box::pin(applet_authoring::realm_applet_configuration(
        database.pool(),
    ))
    .await;
}

#[tokio::test]
async fn widget_native_inventory_preserves_consent_scope_and_all_three_revoke_modes() {
    Box::pin(applet_authoring::widget_inventory_native_install_and_revoke()).await;
}

#[tokio::test]
async fn same_realm_device_cross_circle_pages_ack_only_the_disclosed_prefix() {
    let database = coland_storage_postgres::test_database::TestDatabase::lease().await;
    Box::pin(applet_authoring::realm_bridge_cross_circle_queue_boundaries(database.pool())).await;
}

#[tokio::test]
async fn realm_device_welcome_checkpoint_lost_consume_and_cold_ack_preserve_originals() {
    let database = coland_storage_postgres::test_database::TestDatabase::lease().await;
    Box::pin(applet_authoring::realm_bridge_welcome_recovery_boundaries(
        database.pool(),
    ))
    .await;
}

#[tokio::test]
async fn native_install_admission_rechecks_each_e2ee_choice_and_policy() {
    let database = coland_storage_postgres::test_database::TestDatabase::lease().await;
    Box::pin(applet_authoring::realm_native_install_admission(
        database.pool(),
    ))
    .await;
}

#[tokio::test]
async fn native_authority_admission_preserves_identity_sources_and_exact_retries() {
    let database = coland_storage_postgres::test_database::TestDatabase::lease().await;
    Box::pin(applet_authoring::realm_native_authority_admission(
        database.pool(),
    ))
    .await;
}

#[tokio::test]
async fn native_keypackage_admission_rejects_opaque_identity_and_preserves_exact_consumption() {
    let database = coland_storage_postgres::test_database::TestDatabase::lease().await;
    Box::pin(applet_authoring::realm_native_mls_admission(
        database.pool(),
    ))
    .await;
}

#[tokio::test]
async fn native_reviews_keep_candidate_grant_and_postimage_approvals_independent() {
    let database = coland_storage_postgres::test_database::TestDatabase::lease().await;
    Box::pin(applet_authoring::realm_native_review_admission(
        database.pool(),
    ))
    .await;
}

#[tokio::test]
async fn native_workers_share_claim_budget_and_observe_later_publication() {
    let database = coland_storage_postgres::test_database::TestDatabase::lease().await;
    Box::pin(applet_authoring::realm_native_worker_publication_budget(
        database.pool(),
    ))
    .await;
}

#[tokio::test]
async fn native_claim_handoff_holds_the_real_human_counterpart_pcr() {
    let database = coland_storage_postgres::test_database::TestDatabase::lease().await;
    Box::pin(applet_authoring::realm_native_human_pcr_handoff(
        database.pool(),
    ))
    .await;
}

#[tokio::test]
async fn native_claim_handoff_rechecks_original_e2ee_install_expiry() {
    let database = coland_storage_postgres::test_database::TestDatabase::lease().await;
    Box::pin(applet_authoring::realm_native_claim_e2ee_expiry(
        database.pool(),
    ))
    .await;
}

#[tokio::test]
async fn native_query_handoff_rechecks_original_e2ee_install_expiry() {
    let database = coland_storage_postgres::test_database::TestDatabase::lease().await;
    Box::pin(applet_authoring::realm_native_query_e2ee_expiry(
        database.pool(),
    ))
    .await;
}

#[tokio::test]
async fn native_encrypted_read_handoff_rechecks_original_e2ee_install_expiry() {
    let database = coland_storage_postgres::test_database::TestDatabase::lease().await;
    Box::pin(applet_authoring::realm_native_encrypted_read_e2ee_expiry(
        database.pool(),
    ))
    .await;
}

#[tokio::test]
async fn native_exact_current_below_history_floor_requires_its_live_read_source() {
    let database = coland_storage_postgres::test_database::TestDatabase::lease().await;
    Box::pin(applet_authoring::realm_native_exact_current_floor(
        database.pool(),
    ))
    .await;
}

#[tokio::test]
async fn native_authorization_and_keypackage_upload_recover_exact_originals_after_local_outcome_failure()
 {
    let database = coland_storage_postgres::test_database::TestDatabase::lease().await;
    Box::pin(applet_authoring::realm_native_runtime_recovery(
        database.pool(),
    ))
    .await;
}
