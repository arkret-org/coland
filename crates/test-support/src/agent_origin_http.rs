use coland_storage_postgres::PgPersistenceStore;

use crate::agent_origin::OriginFixture;

impl OriginFixture {
    /// Install the same original service document and history read by production.
    pub async fn app_state(
        &self,
        config: coland_http::config::AppConfig,
    ) -> coland_http::state::AppState {
        use coland_storage::DeliveryPolicyStoreRegistry as _;
        let version = self.inception_log["versionId"].as_str().unwrap().to_owned();
        let identity = super::fixture_service_identity_for_did_and_version(
            &config,
            self.station_did.clone(),
            version,
        );
        let seed = self.issuer.to_bytes();
        let mut stored = super::fixture_stored_service_identity(&config, &identity, seed);
        stored.did_document = serde_json::from_value(self.inception_log["state"].clone()).unwrap();
        stored.registration_receipt.log_head_digest =
            arkret_canonical::canonical_sha256(&self.inception_log).unwrap();
        stored.registration_receipt.registration_receipt_id = stored
            .registration_receipt
            .expected_registration_receipt_id()
            .unwrap();
        stored.registration_receipt.proof.payload_digest = stored
            .registration_receipt
            .expected_payload_digest()
            .unwrap();
        let persistence = std::sync::Arc::new(PgPersistenceStore::new(self.pool.clone()));
        persistence.service_identity().put(stored).await.unwrap();
        persistence
            .webvh()
            .append_log_event(coland_storage::WebvhLogRecord {
                event_digest: arkret_canonical::canonical_sha256(&self.inception_log).unwrap(),
                did: self.station_did.to_string(),
                sequence: 1,
                operation: self.inception_log.clone(),
                created_at: self.genesis.commit.committed_at,
            })
            .await
            .unwrap();
        super::app_state_with_identity(config, persistence, identity, seed)
    }
}
