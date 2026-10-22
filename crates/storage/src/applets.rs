use super::{PersistenceResult, Value, async_trait};
#[async_trait]
#[allow(
    clippy::too_many_arguments,
    reason = "Storage operations bind the complete protocol authoring and authority context."
)]
pub trait AppletStore: Send + Sync {
    /// Internal exact-candidate lookup for current Account lock planning.
    async fn configuration_review_account(
        &self,
        _request: &arkret_models_integration::ManagementReviewRequestBody,
    ) -> PersistenceResult<Option<arkret_wire::AccountId>> {
        if _request.configuration_ref.is_none() {
            return Ok(None);
        }
        Err(super::PersistenceError::Internal(
            "configuration ledger unavailable".into(),
        ))
    }

    async fn configuration_candidate_account(
        &self,
        _event: &arkret_wire::Event,
    ) -> PersistenceResult<Option<arkret_wire::AccountId>> {
        Err(super::PersistenceError::Internal(
            "configuration ledger unavailable".into(),
        ))
    }
    async fn configuration_intent(
        &self,
        _governor: &arkret_wire::DidCoreId,
        _applet: &arkret_wire::AppletId,
        _actor: &arkret_wire::ActorId,
        _intent: &arkret_models_integration::AppletConfigurationIntent,
        _current: &crate::ManagementReviewCurrent,
    ) -> PersistenceResult<Option<arkret_models_integration::AppletConfigurationExecutionIntent>>
    {
        Err(super::PersistenceError::Internal(
            "configuration ledger unavailable".into(),
        ))
    }
    /// Private configuration ledger owned by the current Realm governor.
    async fn configuration(
        &self,
        _governor: &arkret_wire::DidCoreId,
        _intent: &arkret_models_integration::AppletConfigurationExecutionIntent,
        _command: arkret_models_integration::AppletConfigurationCommand,
        _current: &crate::ManagementReviewCurrent,
        _ingress: &crate::AppletConfigurationIngress,
    ) -> PersistenceResult<arkret_models_integration::AppletConfigurationOutcome> {
        Err(super::PersistenceError::Internal(
            "configuration ledger unavailable".into(),
        ))
    }
    async fn retain_configuration_source(
        &self,
        _governor: &arkret_wire::DidCoreId,
        _intent: &arkret_models_integration::AppletConfigurationExecutionIntent,
        _source: &arkret_models_integration::AppletConfigurationExecutionOutcome,
        _producer: &crate::AppletEventProducerGuard,
        _current: &crate::ManagementReviewCurrent,
    ) -> PersistenceResult<arkret_models_integration::AppletConfigurationOutcome> {
        Err(super::PersistenceError::Internal(
            "configuration ledger unavailable".into(),
        ))
    }
    async fn authority_material(
        &self,
        _applet: &arkret_wire::AppletId,
        _service: &arkret_wire::DidCoreId,
        _station: &arkret_wire::DidCoreId,
        _request: &arkret_models_collaboration::applet_installation_authority::AppletAuthorityMaterialRequestBody,
    ) -> PersistenceResult<
        arkret_models_collaboration::applet_installation_authority::AppletAuthorityMaterialOutcome,
    > {
        Err(super::PersistenceError::Conflict(
            "failed_precondition: Applet authority material is unavailable".into(),
        ))
    }
    /// Host-local issuance; adapters validate the accepted approval and declared
    /// scope while holding the exact install row lock.
    async fn issue_widget_token(
        &self,
        _record: crate::AppletWidgetTokenRecord,
    ) -> PersistenceResult<bool> {
        Err(super::PersistenceError::Internal(
            "widget token inventory is unavailable".into(),
        ))
    }
    async fn widget_tokens(
        &self,
        _install: &crate::AppletWidgetInstallSelector,
        _at: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<Vec<crate::AppletWidgetTokenRecord>> {
        Err(super::PersistenceError::Internal(
            "widget token inventory is unavailable".into(),
        ))
    }
    async fn check_widget_token(
        &self,
        _gate: &crate::AppletWidgetTokenGateSelector,
        _at: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<crate::AppletWidgetTokenRecord> {
        Err(super::PersistenceError::Internal(
            "widget token inventory is unavailable".into(),
        ))
    }
    async fn invalidate_widget_token(
        &self,
        _install: &crate::AppletWidgetInstallSelector,
        _token_ref: &str,
        _at: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<crate::AppletWidgetTokenInvalidation> {
        Err(super::PersistenceError::Internal(
            "widget token inventory is unavailable".into(),
        ))
    }
    /// Admit only the registered local Applet installation/Ghost fixed set.
    /// Both callbacks run inside its transaction, after each actual authority
    /// head has been locked; finalization never receives fabricated refs.
    async fn admit_authoring_unit(
        &self,
        _input: AppletAuthoringUnitWrite,
        _author: AppletCommitAuthor,
        _attester: AppletResolutionAttester,
        _finalize: AppletUnitFinalizer,
    ) -> PersistenceResult<AppletAuthoringUnitOutcome> {
        Err(super::PersistenceError::Conflict(
            "unsupported_feature: Applet authoring aggregate is unavailable".to_owned(),
        ))
    }
    async fn get_identity(
        &self,
        applet_id: &str,
        target_station_id: &str,
    ) -> PersistenceResult<Option<Value>>;
    async fn get(
        &self,
        applet_id: &str,
        service_id: &str,
        effective_scope_key: &str,
    ) -> PersistenceResult<Option<Value>>;
    async fn compare_and_swap(
        &self,
        applet_id: &str,
        service_id: &str,
        effective_scope_key: &str,
        expected: &Value,
        replacement: Value,
    ) -> PersistenceResult<bool>;
    /// Atomically fences one exact installation and, iff it was the final
    /// active scope, stamps the independent managed-identity winner.
    async fn fence_installation(
        &self,
        applet_id: &str,
        service_id: &str,
        effective_scope_key: &str,
        target_station_id: &str,
        expected: &Value,
        replacement: Value,
        fenced_at: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<AppletInstallationFenceOutcome>;
    async fn list(&self) -> PersistenceResult<Vec<Value>>;
    async fn begin_transaction_replay(
        &self,
        record: AppletTransactionReplayRecord,
    ) -> PersistenceResult<AppletTransactionReplayBegin>;
    async fn complete_transaction_replay(
        &self,
        applet_id: &str,
        source_id: &str,
        idempotency_key: &str,
        outcome: Value,
    ) -> PersistenceResult<()>;
    async fn issue_authoring_preview(
        &self,
        candidate: AppletAuthoringPreviewRecord,
    ) -> PersistenceResult<AppletAuthoringPreviewRecord>;
    async fn current_authoring_preview(
        &self,
        subject_key: &str,
    ) -> PersistenceResult<Option<AppletAuthoringPreviewRecord>>;
    async fn pending_authoring_completions(
        &self,
        _limit: u32,
    ) -> PersistenceResult<Vec<AppletAuthoringCompletion>> {
        Err(super::PersistenceError::Internal(
            "durable Applet completion delivery is unavailable".to_owned(),
        ))
    }
    async fn acknowledge_authoring_completion(
        &self,
        _applet_id: &arkret_wire::AppletId,
        _request_digest: &arkret_wire::Hash,
        _idempotency_key: &str,
        _at: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<()> {
        Err(super::PersistenceError::Internal(
            "durable Applet completion acknowledgement is unavailable".to_owned(),
        ))
    }
}

/// Internal immutable delivery record written with its accepted authoring unit.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct AppletAuthoringCompletion {
    pub applet_id: arkret_wire::AppletId,
    pub realm_id: arkret_wire::RealmId,
    pub actor_id: arkret_wire::ActorId,
    pub creation_ref: arkret_wire::CommittedEventRef,
    pub request_digest: arkret_wire::Hash,
    pub source_id: arkret_wire::DidCoreId,
    pub destination_id: arkret_wire::DidCoreId,
    pub endpoint: String,
    pub idempotency_key: String,
    pub context: Option<arkret_models_integration::AppletManagedActorAuthoringContext>,
    pub delivery_key_digest: Option<arkret_wire::Hash>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AppletInstallationFenceOutcome {
    pub updated: bool,
    pub globally_fenced: bool,
}

#[derive(Clone, Debug)]
pub struct AppletAuthoringPreviewRecord {
    pub subject_key: String,
    pub basis_digest: String,
    pub request_digest: String,
    pub signed_request: Value,
    pub issued_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
}
#[derive(Clone, Debug)]
pub struct AppletTransactionReplayRecord {
    pub applet_id: arkret_wire::AppletId,
    pub source_id: String,
    pub idempotency_key: String,
    pub delivery_authentication_record: Value,
    pub delivery_authentication_record_digest: String,
    pub request_digest: String,
    pub outcome: Option<Value>,
    pub received_at: chrono::DateTime<chrono::Utc>,
    pub completed_at: Option<chrono::DateTime<chrono::Utc>>,
}
#[derive(Clone, Debug)]
pub enum AppletTransactionReplayBegin {
    Fresh,
    Existing(Box<AppletTransactionReplayRecord>),
}
#[doc(hidden)]
pub fn applet_registration_select_sql(suffix: &str) -> String {
    format!("SELECT record FROM applet_installations {suffix}")
}
#[doc(hidden)]
pub fn applet_transaction_replay_select_sql() -> &'static str {
    "SELECT applet_id, source_id, idempotency_key, delivery_authentication_record, \
     delivery_authentication_record_digest, request_digest, \
     outcome, received_at, completed_at \
     FROM applet_transactions \
     WHERE applet_id = $1 AND source_id = $2 AND idempotency_key = $3"
}

/// Internal transaction input; all protocol values use their SDK contracts.
#[derive(Clone, Debug, serde::Serialize)]
#[serde(untagged)]
pub enum AppletAdmissionRequest {
    Install(Box<arkret_models_integration::AppletInstallRequestBody>),
}

/// Original candidate and receiver-derived verification material. Pure
/// validation can inspect this without constructing a write or consuming any
/// quota, approval, idempotency identity or business outcome.
#[derive(Clone, Debug)]
pub struct AppletAuthoringCandidate {
    pub request: AppletAdmissionRequest,
    pub package: arkret_models_integration::AppletPackage,
    pub recomputed_install_plan: Option<arkret_models_integration::AppletInstallPlan>,
    pub service_did_document: arkret_identity::DidDocument,
    pub controller_did_document: arkret_identity::DidDocument,
    pub station_verification_method: arkret_wire::DidUrl,
    pub station_public_key: [u8; 32],
    pub admin_actor_id: arkret_wire::ActorId,
    pub admin_producer_guards: Vec<super::SelfProducerCommitGuard>,
    pub request_digest: arkret_wire::Hash,
    pub canonical_request_hash: arkret_wire::Hash,
    pub prior_managed_refs: Vec<arkret_wire::CommittedEventRef>,
    pub prior_service_signer_evidence:
        Option<arkret_models_integration::AppletServiceSignerEvidence>,
    pub accepted_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Debug)]
pub struct AppletAuthoringUnitWrite {
    pub candidate: AppletAuthoringCandidate,
    /// Original method-native Service history, retained only for a fresh
    /// managed creation. Installation and Ghost reuse create no new source.
    pub creation_service_resolution: Option<arkret_models_identity::AuthenticatedServiceResolution>,
    pub expected_identity: Option<Value>,
    pub expected_installation: Option<Value>,
    pub preview_subject_key: String,
    pub operation_id: String,
    pub idempotency_key: String,
    pub operation_approvals: Option<crate::OperationApprovalCommit>,
}

impl std::ops::Deref for AppletAuthoringUnitWrite {
    type Target = AppletAuthoringCandidate;
    fn deref(&self) -> &Self::Target {
        &self.candidate
    }
}

impl std::ops::DerefMut for AppletAuthoringUnitWrite {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.candidate
    }
}

pub type AppletCommitAuthor = std::sync::Arc<
    dyn Fn(
            &arkret_wire::Event,
            &super::CurrentRealmAuthority,
            Option<&arkret_wire::CommitStreamHead>,
            chrono::DateTime<chrono::Utc>,
            Option<&arkret_models_collaboration::authority_commit::HistoricalProducerSignerFact>,
            Option<&arkret_models_crypto::DeviceProjectionAttestationCore>,
        ) -> PersistenceResult<(
            arkret_wire::RealmCommit,
            Option<arkret_models_identity::AccountDeviceSignerEvidence>,
        )> + Send
        + Sync,
>;

pub type AppletUnitFinalizer = std::sync::Arc<
    dyn Fn(&[arkret_wire::CommittedEventRef]) -> PersistenceResult<AppletUnitFinalization>
        + Send
        + Sync,
>;

#[derive(Clone, Debug)]
pub struct AppletUnitFinalization {
    pub applet_record: super::AppletRecordCommit,
    pub idempotency_record: super::IdempotencyRecord,
    pub response_body: Value,
}

#[derive(Clone, Debug)]
pub struct AppletAuthoringUnitOutcome {
    pub committed_event_refs: Vec<arkret_wire::CommittedEventRef>,
    pub response_body: Value,
    pub replayed: bool,
}

pub type AppletResolutionAttester = std::sync::Arc<
    dyn Fn(
            arkret_models_identity::PrincipalResolutionProjectionAttestationCore,
        )
            -> PersistenceResult<arkret_models_identity::PrincipalResolutionProjectionAttestation>
        + Send
        + Sync,
>;

/// Private receiver audit material. Only the authenticated HTTP ingress builds
/// this record; it is never accepted as a client-supplied protocol carrier.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct AppletConfigurationIngress {
    pub requester_account_id: arkret_wire::AccountId,
    pub request: arkret_models_integration::AppletConfigurationRequest,
    pub source: AppletConfigurationIngressSource,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AppletConfigurationIngressSource {
    LocalSession,
    Peer(Box<AppletConfigurationPeerSource>),
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct AppletConfigurationPeerSource {
    pub source_service_id: arkret_wire::DidCoreId,
    pub signature_input: String,
    pub signature: String,
    pub content_digest: String,
    pub verified_key_digest: [u8; 32],
    pub method: String,
    pub target_uri: String,
    pub authority: String,
    pub signed_headers: std::collections::BTreeMap<String, String>,
}

#[cfg(test)]
mod ingress_serialization_tests {
    use super::AppletConfigurationIngressSource;

    #[test]
    fn peer_ingress_preserves_the_flat_metadata_carrier() {
        let original = serde_json::json!({
            "kind": "peer",
            "source_service_id": "ak:did_core:web:peer.example",
            "signature_input": "signature-input",
            "signature": "signature",
            "content_digest": "digest",
            "verified_key_digest": vec![0; 32],
            "method": "POST",
            "target_uri": "https://station.example/_arkret/",
            "authority": "station.example",
            "signed_headers": {"arkret-operation": "operation"}
        });
        let source: AppletConfigurationIngressSource =
            serde_json::from_value(original.clone()).unwrap();
        assert!(matches!(source, AppletConfigurationIngressSource::Peer(_)));
        assert_eq!(serde_json::to_value(source).unwrap(), original);
    }
}
