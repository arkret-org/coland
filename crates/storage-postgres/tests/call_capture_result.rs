//! Capture production uses the real registered Service producer and PostgreSQL.
#[path = "support/applet_authoring/mod.rs"]
#[allow(dead_code)]
mod applet_authoring;
#[path = "support/ordinary_realm.rs"]
#[allow(dead_code)]
mod ordinary_realm;

use applet_authoring::call_capture_fixture::{
    registered_call_capture_key_source_and_geometry, registered_call_capture_result,
    registered_call_capture_result_rejects_deactivated_account,
};

#[tokio::test]
async fn registered_recording_start_stop_ready_keeps_original_budget_and_service_provenance() {
    let database = coland_storage_postgres::test_database::TestDatabase::lease().await;
    Box::pin(registered_call_capture_result(database.pool())).await;
}

#[tokio::test]
async fn native_recording_pins_start_mls_source_and_rejects_changed_key_or_stream_geometry() {
    let database = coland_storage_postgres::test_database::TestDatabase::lease().await;
    Box::pin(registered_call_capture_key_source_and_geometry(
        database.pool(),
    ))
    .await;
}

#[tokio::test]
async fn delegated_call_ready_after_account_deactivation_rejects_without_new_effects() {
    let database = coland_storage_postgres::test_database::TestDatabase::lease().await;
    Box::pin(registered_call_capture_result_rejects_deactivated_account(
        database.pool(),
    ))
    .await;
}
