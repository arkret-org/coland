use super::{
    PersistenceError, PersistenceResult, Value, WebvhDocumentRecord, WebvhLogRecord, async_trait,
};
/// DID documents + their key-log events. The two are coupled: every accepted
/// `submit_did_operation` writes a document and appends a log entry.
#[async_trait]
pub trait WebvhStore: Send + Sync {
    async fn get_document(&self, did: &str) -> PersistenceResult<Option<WebvhDocumentRecord>>;
    async fn get_embedded_webvh_document_by_local_id(
        &self,
        local_id: &str,
    ) -> PersistenceResult<Option<WebvhDocumentRecord>>;
    async fn put_document(&self, record: WebvhDocumentRecord) -> PersistenceResult<()>;
    async fn append_log_event(&self, event: WebvhLogRecord) -> PersistenceResult<()>;
    /// Atomically retain a freshly resolved, complete native history and its
    /// current document. The expected head prevents concurrent rollback.
    async fn ingest_verified_history(
        &self,
        expected_current_head: Option<String>,
        document: WebvhDocumentRecord,
    ) -> PersistenceResult<WebvhLogCommitOutcome>;
    async fn list_log_events(&self, did: &str) -> PersistenceResult<Vec<WebvhLogRecord>>;
    async fn commit_log_operation(
        &self,
        expected_current_head: Option<String>,
        document: WebvhDocumentRecord,
        event: WebvhLogRecord,
        service_identity: Option<ServiceIdentitySuccessor>,
    ) -> PersistenceResult<WebvhLogCommitOutcome>;
    async fn get_service_registration(
        &self,
        key: &arkret_models_identity::service_identity::ServiceRegistrationKey,
    ) -> PersistenceResult<
        Option<arkret_models_identity::service_identity::ServiceRegistrationOutcome>,
    >;
    async fn commit_service_registration(
        &self,
        key: arkret_models_identity::service_identity::ServiceRegistrationKey,
        outcome: arkret_models_identity::service_identity::ServiceRegistrationOutcome,
        document: WebvhDocumentRecord,
        event: WebvhLogRecord,
    ) -> PersistenceResult<ServiceRegistrationCommitOutcome>;
}

/// The deployment's own service DID successor, committed with its public
/// WebVH log and document. Secrets remain in KeyStore under these opaque refs.
#[derive(Clone, Debug)]
pub struct ServiceIdentitySuccessor {
    pub expected: arkret_identity::service_identity::StoredDidCoreIdentity,
    pub next: arkret_identity::service_identity::StoredDidCoreIdentity,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WebvhLogCommitOutcome {
    Accepted,
    Duplicate,
    Conflict,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ServiceRegistrationCommitOutcome {
    Created(arkret_models_identity::service_identity::ServiceRegistrationOutcome),
    Existing(arkret_models_identity::service_identity::ServiceRegistrationOutcome),
    Conflict,
}
#[doc(hidden)]
pub fn decode_registration_outcome(
    value: Value,
) -> PersistenceResult<arkret_models_identity::service_identity::ServiceRegistrationOutcome> {
    serde_json::from_value(value).map_err(|error| {
        PersistenceError::Internal(format!(
            "stored service registration outcome is invalid: {error}"
        ))
    })
}
#[doc(hidden)]
pub fn registration_as_existing(
    mut outcome: arkret_models_identity::service_identity::ServiceRegistrationOutcome,
) -> arkret_models_identity::service_identity::ServiceRegistrationOutcome {
    outcome.created = false;
    outcome
}
#[doc(hidden)]
pub fn registrations_match(
    left: &arkret_models_identity::service_identity::ServiceRegistrationOutcome,
    right: &arkret_models_identity::service_identity::ServiceRegistrationOutcome,
) -> bool {
    left.registration_receipt.service_id == right.registration_receipt.service_id
        && left.registration_receipt.version_id == right.registration_receipt.version_id
        && left.registration_receipt.log_head_digest == right.registration_receipt.log_head_digest
        && left.registration_receipt.control_key_digest
            == right.registration_receipt.control_key_digest
}
#[doc(hidden)]
pub fn valid_new_service_registration_records(
    outcome: &arkret_models_identity::service_identity::ServiceRegistrationOutcome,
    document: &WebvhDocumentRecord,
    event: &WebvhLogRecord,
) -> bool {
    document.did == outcome.registration_receipt.did.as_str()
        && event.did == outcome.registration_receipt.did.as_str()
        && document.seq == 1
        && event.seq == 1
        && document.key_log_head.as_deref() == Some(event.event_digest.as_str())
        && outcome.registration_receipt.log_head_digest == event.event_digest
}
