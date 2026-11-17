//! Process-local inputs for the Organization's one-create native transaction.
//! Public protocol carriers and method evidence remain SDK-owned.

#[derive(Clone, Debug)]
pub struct OrganizationPcrGenesisAdmissionWrite {
    pub transaction: crate::AuthorityCommitTransaction,
    pub request:
        arkret_models_collaboration::authority_commit::PeerAuthorityForwardEventRequestBody,
    /// Independently authenticated peer source, never read from the wire body.
    pub source_service_id: arkret_wire::DidCoreId,
    pub organization_log_entries: Vec<serde_json::Value>,
    pub organization_witness_records: Vec<serde_json::Value>,
    pub producer_service_resolution: Option<arkret_models_identity::AuthenticatedServiceResolution>,
    pub queued_at: chrono::DateTime<chrono::Utc>,
}
