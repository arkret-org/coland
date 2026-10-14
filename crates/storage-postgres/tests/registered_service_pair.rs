//! Service delegation passes real signed peer HTTP and accepted PG state.
#[path = "support/applet_authoring.rs"]
#[allow(dead_code)]
mod applet_authoring;
#[path = "support/ordinary_realm.rs"]
#[allow(dead_code)]
mod ordinary_realm;

#[tokio::test]
async fn registered_service_pair_has_real_peer_producer_facts() {
    let database = coland_storage_postgres::test_database::TestDatabase::lease().await;
    Box::pin(applet_authoring::registered_service_pair(database.pool())).await;
}
