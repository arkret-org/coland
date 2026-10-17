use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use arkret_identifiers::{DidCoreId, RealmId};
use arkret_models_collaboration::events_payloads::ContentBlock;
use arkret_wire::ScopeRef;
use chrono::{DateTime, Utc};
pub use coland_storage::PublicationEvidenceRecord;
use coland_storage::RealmEventStats;
use serde_json::Value;

use crate::ServiceResult;

#[derive(Clone, Debug, Default)]
pub struct RealmDirectoryQuery {
    pub text: Option<String>,
    pub tags: BTreeSet<String>,
    pub members: BTreeSet<DidCoreId>,
    pub public_only: bool,
    pub limit: Option<usize>,
}

pub use coland_storage::{
    CircleMemberProjectionRecord, CircleProjectionRecord, RealmOrganizationStatementRecord,
};

#[derive(Clone, Debug, PartialEq)]
pub struct MorphProjectionRecord {
    pub morph_id: String,
    pub realm_id: String,
    pub scope_circle_id: Option<String>,
    pub morph_kind: String,
    pub title: Option<String>,
    pub fields: BTreeMap<String, Value>,
    pub schema_refs: Vec<String>,
    pub facets: BTreeMap<String, BTreeMap<String, Value>>,
    pub versions: Vec<coland_domain::reducer::DocumentVersionProjection>,
    /// Canonical content slot; exactly one of the two is present on an active
    /// object and both are absent once `state=redacted` (common-fields.md 5.2).
    /// Typed as the SDK [`ContentBlock`], matching
    /// `arkret_models_collaboration::objects::profiles::Morph`.
    pub content: Option<ContentBlock>,
    pub encrypted_content: Option<serde_json::Value>,
    pub state: String,
    pub state_changed_at: Option<DateTime<Utc>>,
    /// Wire spelling of the business-progression stage (`common-fields.md`
    /// §5.3), absent when the Morph carries no stage.
    pub stage: Option<String>,
    /// Reducer-derived timestamp of the last real stage transition.
    pub stage_changed_at: Option<DateTime<Utc>>,
    pub created_by: String,
    pub created_at: DateTime<Utc>,
    pub updated_by: Option<String>,
    pub updated_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RealmDirectoryEntry {
    pub realm_id: RealmId,
    pub title: String,
    pub description: Option<String>,
    pub tags: BTreeSet<String>,
    pub members: BTreeSet<DidCoreId>,
    pub public: bool,
    pub category: Option<String>,
    pub realm_class: Option<String>,
    pub default_join_rule: Option<String>,
    pub as_of: DateTime<Utc>,
    pub source_refs: Vec<String>,
    pub policy_revision: String,
    /// Caller-visible Directory data exists only after a verified direct
    /// publication from the current governance Station. Realm reducer state,
    /// membership, source references, and join policy never populate it.
    pub public_metadata: Option<PublicRealmMetadataRecord>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicRealmMetadataRecord {
    pub display_name: String,
    pub summary: Option<String>,
    pub public_locator: Option<String>,
    pub avatar_blob_ref: Option<arkret_wire::BlobRef>,
    pub indexed_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

/// Where a directory entry's `source_refs` comes from.
///
/// `source_refs` exists so a consumer can go back to the truth source and verify
/// the entry itself (`discovery-directory.md` §7.3 invariant 3). The constructor
/// used to default it to a freshly minted `ak:event:` uuid, which made that
/// impossible in the exact way the field was meant to prevent: the id resolves to
/// nothing, and it *looks* verifiable, so a consumer spends a lookup finding out.
/// Worse, every caller that had a real Event id available inherited the forged one
/// unless it remembered to overwrite the field — and only one of eleven did.
///
/// Two constructors would have let a caller pick the convenient one. An enum makes
/// "this entry has no Event behind it" a thing you have to say out loud.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DirectoryProvenance {
    /// Derived from an accepted Event; carries that Event's id.
    AcceptedEvent(String),
    /// Server-local synthesis with no Event behind it. `source_refs` is omitted
    /// on the wire; `policy_revision = "local"` marks the entry.
    LocalOnly,
}

impl DirectoryProvenance {
    fn source_refs(self) -> Vec<String> {
        match self {
            Self::AcceptedEvent(event_id) => vec![event_id],
            Self::LocalOnly => Vec::new(),
        }
    }
}

impl RealmDirectoryEntry {
    pub fn new(
        realm_id: RealmId,
        title: impl Into<String>,
        provenance: DirectoryProvenance,
    ) -> Self {
        Self {
            realm_id,
            title: title.into(),
            description: None,
            tags: BTreeSet::new(),
            members: BTreeSet::new(),
            public: false,
            category: None,
            realm_class: None,
            default_join_rule: None,
            as_of: DateTime::from_timestamp_millis(Utc::now().timestamp_millis())
                .expect("current time is representable at millisecond precision"),
            source_refs: provenance.source_refs(),
            policy_revision: "local".to_owned(),
            public_metadata: None,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct RealmDirectoryIndex {
    entries: BTreeMap<RealmId, RealmDirectoryEntry>,
}

impl RealmDirectoryIndex {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn upsert(&mut self, entry: RealmDirectoryEntry) {
        self.entries.insert(entry.realm_id.clone(), entry);
    }

    pub fn get(&self, realm_id: &RealmId) -> Option<&RealmDirectoryEntry> {
        self.entries.get(realm_id)
    }

    pub fn get_mut(&mut self, realm_id: &RealmId) -> Option<&mut RealmDirectoryEntry> {
        self.entries.get_mut(realm_id)
    }

    pub fn entries_iter(&self) -> impl Iterator<Item = (&RealmId, &RealmDirectoryEntry)> {
        self.entries.iter()
    }

    pub fn search(&self, query: RealmDirectoryQuery) -> Vec<&RealmDirectoryEntry> {
        let mut scored =
            self.entries
                .values()
                .filter(|entry| !query.public_only || entry.public)
                .filter(|entry| {
                    query.text.as_ref().is_none_or(|text| {
                        realm_directory_text(entry).contains(&text.to_lowercase())
                    })
                })
                .filter(|entry| query.tags.iter().all(|tag| entry.tags.contains(tag)))
                .filter(|entry| {
                    query
                        .members
                        .iter()
                        .all(|member| entry.members.contains(member))
                })
                .map(|entry| (realm_directory_score(entry, &query), entry))
                .collect::<Vec<_>>();
        scored.sort_by(|(left_score, left), (right_score, right)| {
            right_score
                .cmp(left_score)
                .then_with(|| left.title.cmp(&right.title))
        });
        let mut results = scored
            .into_iter()
            .map(|(_, entry)| entry)
            .collect::<Vec<_>>();
        if let Some(limit) = query.limit {
            results.truncate(limit);
        }
        results
    }
}

#[derive(Clone)]
pub struct RealmDirectoryService {
    index: Arc<parking_lot::Mutex<RealmDirectoryIndex>>,
}

impl RealmDirectoryService {
    pub fn new(index: RealmDirectoryIndex) -> Self {
        Self {
            index: Arc::new(parking_lot::Mutex::new(index)),
        }
    }

    pub fn snapshot(&self) -> RealmDirectoryIndex {
        self.index.lock().clone()
    }

    pub fn entry(&self, realm_id: &RealmId) -> Option<RealmDirectoryEntry> {
        self.index.lock().get(realm_id).cloned()
    }

    pub fn upsert(&self, entry: RealmDirectoryEntry) {
        self.index.lock().upsert(entry);
    }

    pub fn update_entry<R>(
        &self,
        realm_id: &RealmId,
        update: impl FnOnce(&mut RealmDirectoryEntry) -> R,
    ) -> Option<R> {
        self.index.lock().get_mut(realm_id).map(update)
    }

    pub fn add_member(&self, realm_id: &RealmId, member: DidCoreId) -> bool {
        self.update_entry(realm_id, |entry| entry.members.insert(member))
            .unwrap_or(false)
    }

    pub fn remove_member_from_all(&self, member: &DidCoreId) -> usize {
        let mut index = self.index.lock();
        let mut removed = 0;
        for entry in index.entries.values_mut() {
            if entry.members.remove(member) {
                removed += 1;
            }
        }
        removed
    }

    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn test_index(&self) -> &Arc<parking_lot::Mutex<RealmDirectoryIndex>> {
        &self.index
    }
}

fn realm_directory_text(entry: &RealmDirectoryEntry) -> String {
    format!(
        "{} {} {}",
        entry.title,
        entry.description.as_deref().unwrap_or_default(),
        entry.tags.iter().cloned().collect::<Vec<_>>().join(" ")
    )
    .to_lowercase()
}

fn realm_directory_score(entry: &RealmDirectoryEntry, query: &RealmDirectoryQuery) -> usize {
    let mut score = 0;
    if let Some(text) = &query.text {
        let text = text.to_lowercase();
        if entry.title.to_lowercase().contains(&text) {
            score += 10;
        }
        if entry
            .description
            .as_deref()
            .unwrap_or_default()
            .to_lowercase()
            .contains(&text)
        {
            score += 4;
        }
    }
    score += query
        .tags
        .iter()
        .filter(|tag| entry.tags.contains(*tag))
        .count()
        * 3;
    score += query
        .members
        .iter()
        .filter(|member| entry.members.contains(*member))
        .count()
        * 2;
    score
}

pub use coland_storage::CanonicalEventRecord as AcceptedEvent;

/// Recompute the replacement authorize payload commitment in a re-anchor.
///
/// The digest suite comes from the authorize envelope digest so the payload
/// commitment and the envelope commitment always speak the same Realm live
/// suite; inferring it from the payload would let the producer choose it.
pub fn replacement_authorize_payload_digest(
    authorize_envelope: &Value,
    authorize_envelope_digest: &str,
) -> Result<arkret_identifiers::Hash, String> {
    let suite = authorize_envelope_digest
        .split_once(':')
        .map(|(suite, _)| suite)
        .ok_or_else(|| "authorize envelope digest carries no suite prefix".to_owned())?;
    let suite = arkret_canonical::digest_suite(suite)
        .map_err(|_| format!("authorize envelope digest suite {suite} is not supported"))?;
    let payload = authorize_envelope
        .get("payload")
        .ok_or_else(|| "authorize envelope carries no payload".to_owned())?;
    arkret_models_collaboration::events_payloads::device_identity::device_authorize_payload_digest(
        payload, suite,
    )
    .map_err(|error| format!("replacement authorize payload digest failed: {error}"))
}

#[derive(Clone, Debug)]
pub struct ProjectedEvent {
    pub event_id: String,
    pub realm_id: String,
    pub event_kind: arkret_wire::EventKind,
    pub operation_kind: String,
    pub operation_id: Option<String>,
    pub sender: Option<String>,
    pub payload: Value,
    pub created_at: DateTime<Utc>,
    pub received_at: DateTime<Utc>,
}

pub use coland_storage::MessageRecord as MessageState;

#[async_trait::async_trait]
pub trait MessagePort: Send + Sync {
    async fn message(&self, event_id: &str) -> ServiceResult<Option<MessageState>>;
    async fn store_message(&self, message: MessageState) -> ServiceResult<()>;
    async fn messages_for_realm(
        &self,
        realm_id: &str,
        limit: usize,
    ) -> ServiceResult<Vec<MessageState>>;
}

pub use coland_storage::{
    AppletAuthoringPreviewRecord as AppletAuthoringPreviewState,
    AppletTransactionReplayBegin as AppletTransactionReplayResult,
    AppletTransactionReplayRecord as AppletTransactionReplayState,
};

#[async_trait::async_trait]
pub trait AppletPort: Send + Sync {
    async fn issue_widget_token(
        &self,
        _record: coland_storage::AppletWidgetTokenRecord,
    ) -> ServiceResult<bool> {
        Err(coland_storage::PersistenceError::Internal(
            "widget token inventory is unavailable".into(),
        )
        .into())
    }

    async fn widget_tokens(
        &self,
        _install: &coland_storage::AppletWidgetInstallSelector,
        _at: chrono::DateTime<chrono::Utc>,
    ) -> ServiceResult<Vec<coland_storage::AppletWidgetTokenRecord>> {
        Err(coland_storage::PersistenceError::Internal(
            "widget token inventory is unavailable".into(),
        )
        .into())
    }

    async fn check_widget_token(
        &self,
        _gate: &coland_storage::AppletWidgetTokenGateSelector,
        _at: chrono::DateTime<chrono::Utc>,
    ) -> ServiceResult<coland_storage::AppletWidgetTokenRecord> {
        Err(coland_storage::PersistenceError::Internal(
            "widget token inventory is unavailable".into(),
        )
        .into())
    }

    async fn invalidate_widget_token(
        &self,
        _install: &coland_storage::AppletWidgetInstallSelector,
        _token_ref: &str,
        _at: chrono::DateTime<chrono::Utc>,
    ) -> ServiceResult<coland_storage::AppletWidgetTokenInvalidation> {
        Err(coland_storage::PersistenceError::Internal(
            "widget token inventory is unavailable".into(),
        )
        .into())
    }

    async fn admit_applet_authoring_unit(
        &self,
        input: coland_storage::AppletAuthoringUnitWrite,
        author: coland_storage::AppletCommitAuthor,
        attester: coland_storage::AppletResolutionAttester,
        finalize: coland_storage::AppletUnitFinalizer,
    ) -> ServiceResult<coland_storage::AppletAuthoringUnitOutcome>;
    async fn applet_identity(
        &self,
        applet_id: &str,
        target_station_id: &str,
    ) -> ServiceResult<Option<Value>>;
    async fn applet(
        &self,
        applet_id: &str,
        effective_scope_key: &str,
    ) -> ServiceResult<Option<Value>>;
    async fn applets(&self) -> ServiceResult<Vec<Value>>;
    async fn compare_and_swap_applet(
        &self,
        applet_id: &str,
        effective_scope_key: &str,
        expected: &Value,
        replacement: Value,
    ) -> ServiceResult<bool>;
    async fn fence_applet_installation(
        &self,
        applet_id: &str,
        effective_scope_key: &str,
        target_station_id: &str,
        expected: &Value,
        replacement: Value,
        fenced_at: DateTime<Utc>,
    ) -> ServiceResult<coland_storage::AppletInstallationFenceOutcome>;
    async fn begin_applet_transaction(
        &self,
        replay: AppletTransactionReplayState,
    ) -> ServiceResult<AppletTransactionReplayResult>;
    async fn complete_applet_transaction(
        &self,
        applet_id: &str,
        source_id: &str,
        idempotency_key: &str,
        outcome: Value,
    ) -> ServiceResult<()>;
    async fn issue_applet_authoring_preview(
        &self,
        candidate: AppletAuthoringPreviewState,
    ) -> ServiceResult<AppletAuthoringPreviewState>;
    async fn current_applet_authoring_preview(
        &self,
        subject_key: &str,
    ) -> ServiceResult<Option<AppletAuthoringPreviewState>>;
    async fn pending_applet_authoring_completions(
        &self,
        _limit: u32,
    ) -> ServiceResult<Vec<coland_storage::AppletAuthoringCompletion>> {
        Err(coland_storage::PersistenceError::Internal(
            "durable Applet completion delivery is unavailable".to_owned(),
        )
        .into())
    }
    async fn acknowledge_applet_authoring_completion(
        &self,
        _applet_id: &arkret_wire::AppletId,
        _request_digest: &arkret_wire::Hash,
        _at: DateTime<Utc>,
    ) -> ServiceResult<()> {
        Err(coland_storage::PersistenceError::Internal(
            "durable Applet completion acknowledgement is unavailable".to_owned(),
        )
        .into())
    }
}

pub use coland_storage::ProjectionEventAppendOutcome as ProjectedEventAppendResult;

#[derive(Clone, Debug)]
pub struct IdempotentResponse {
    pub authenticated_actor: arkret_wire::ActorId,
    pub operation_id: String,
    pub key: String,
    pub request_hash: String,
    pub status: i32,
    pub body: Value,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

/// One outbound delivery intent committed together with its Event. Same type
/// the federation service enqueues and the dispatcher claims — there is exactly
/// one shape for "a request this service owes a peer".
use crate::federation::FederationDeliveryRecord;

#[derive(Clone, Debug)]
pub struct CommitAcceptedEventCommand {
    pub verified_media_participant: Option<arkret_signatures::media::VerifiedCallParticipant>,
    /// Current-authority transaction that orders this Event on its Realm,
    /// Circle or Sidecar stream. One `RealmCommit` accepts exactly one Event,
    /// so the signed commit travels with the Event it admits.
    pub authority_commit: coland_storage::AuthorityCommitTransaction,
    pub self_producer_guard: Option<coland_storage::SelfProducerCommitGuard>,
    pub applet_producer_guard: Option<coland_storage::AppletEventProducerGuard>,
    pub widget_token_gate: Option<coland_storage::AppletWidgetTokenGateSelector>,
    /// Verifier-private subject evidence, rechecked inside the grant transaction.
    pub agent_grant_scope_evidence: Option<coland_storage::VerifiedAgentScopeEvidence>,
    /// Verified `producer_device_evidence` of a cross-Station human-device
    /// producer, retained for audit with the Event's first Commit.
    pub forwarded_producer_evidence: Option<coland_storage::ForwardedProducerDeviceEvidence>,
    pub forwarded_agent_producer:
        Option<arkret_identity::agent_authority_evidence::VerifiedAgentProducer>,
    pub agent_deployment_ceiling:
        arkret_models_collaboration::governance::agent_participation::ParticipationBits,
    pub event: AcceptedEvent,
    pub parent_membership_admission: Option<coland_storage::ParentMembershipAdmissionCheck>,
    pub contact_projection: Option<CommitContactProjection>,
    pub device_revocation_transition: Option<coland_storage::DeviceRevocationTransition>,
    pub device_revocation_gate: Option<coland_storage::DeviceRevocationGateSelector>,
    pub projections: Vec<ProjectedEvent>,
    pub idempotency: Option<IdempotentResponse>,
    pub deliveries: Vec<FederationDeliveryRecord>,
    /// The exact admission submission of a Realm-stream Event; its
    /// committed-replication fanout is planned inside the commit transaction.
    pub realm_fanout_source: Option<arkret_wire::EventAdmissionSubmission>,
}

/// One account-data cell replaced by revision CAS inside an Event commit.
#[derive(Clone, Debug)]
pub struct CommitAccountDataCas {
    pub record: crate::identity::AccountDataState,
    pub expected_revision: u64,
    pub conflict_code: String,
}

pub use coland_storage::{
    AppletAuthoringPreviewCommit as CommitAppletAuthoringPreview,
    AppletIdentityCommit as CommitAppletIdentity, AppletRecordCommit as CommitAppletRecord,
    ContactProjectionCommit as CommitContactProjection,
};

#[derive(Clone, Debug)]
pub struct CommitAcceptedEventBatchCommand {
    pub audit_unit: Option<coland_storage::RegisteredAuditCommit>,
    pub events: Vec<CommitAcceptedEventCommand>,
    pub franking_replay_nonce: Option<coland_storage::FrankingReplayNonceCommit>,
    pub realm_organization_proof: Option<coland_storage::RealmOrganizationProofCommit>,
    pub invite_claim_proof: Option<coland_storage::InviteClaimProofCommit>,
    pub event_approvals: Option<coland_storage::EventApprovalCommit>,
    pub applet_record: Option<CommitAppletRecord>,
    pub applet_authoring_preview: Option<CommitAppletAuthoringPreview>,
    pub agent_membership_cascade: Option<coland_storage::AgentMembershipCascadeCommit>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommitAcceptedEventResult {
    pub audit_outcome: Option<coland_storage::RegisteredAuditOutcome>,
    pub projections_inserted: usize,
    pub deliveries_inserted: usize,
}

#[async_trait::async_trait]
pub trait EventReadPort: Send + Sync {
    async fn direct_conversation_founding_slot(
        &self,
        founder_id: &str,
        trust_domain_id: &str,
        pair_key: &str,
    ) -> ServiceResult<Option<coland_storage::DirectConversationFoundingSlotRecord>>;
    async fn direct_conversation_durable_state(
        &self,
        trust_domain_id: &str,
        pair_key: &str,
    ) -> ServiceResult<Option<coland_storage::DirectConversationDurableState>>;
    async fn direct_conversation_durable_state_for_realm(
        &self,
        realm_id: &str,
    ) -> ServiceResult<Option<coland_storage::DirectConversationDurableState>>;
    async fn foreign_direct_mls_input(
        &self,
        _realm: &arkret_wire::RealmId,
        _caller: &arkret_wire::ActorId,
    ) -> ServiceResult<Option<coland_storage::ForeignDirectMlsInput>> {
        Ok(None)
    }
    async fn install_foreign_direct_mls_public_state(
        &self,
        _input: &coland_storage::ForeignDirectMlsInput,
        _result: &coland_storage::ForeignDirectMlsBase,
        _exact: bool,
    ) -> ServiceResult<bool> {
        Ok(false)
    }
    async fn canonical_event(&self, event_id: &str) -> ServiceResult<Option<AcceptedEvent>>;
    async fn has_canonical_event(&self, event_id: &str) -> ServiceResult<bool>;
    async fn canonical_events(&self) -> ServiceResult<Vec<AcceptedEvent>>;
    async fn canonical_events_for_actor(&self, actor_id: &str)
    -> ServiceResult<Vec<AcceptedEvent>>;
    async fn franking_proofs_for_target(
        &self,
        realm_id: &str,
        received_by: &arkret_identifiers::DidCoreId,
        target_event_id: &str,
    ) -> ServiceResult<Vec<AcceptedEvent>>;
    async fn identity_anchor_account_slot(
        &self,
        account_id: &arkret_wire::AccountId,
    ) -> ServiceResult<Option<coland_storage::IdentityAnchorAccountSlot>>;
    async fn realm_event_stats(&self, realm_id: &str) -> ServiceResult<RealmEventStats>;
    async fn realm_events_newest_first(&self, realm_id: &str) -> ServiceResult<Vec<AcceptedEvent>>;
    async fn accepted_event(&self, event_id: &str) -> ServiceResult<Option<AcceptedEvent>>;
    async fn accepted_events(&self) -> ServiceResult<Vec<AcceptedEvent>>;
    async fn projected_event(&self, event_id: &str) -> ServiceResult<Option<ProjectedEvent>>;
    async fn projected_event_by_operation_id(
        &self,
        operation_id: &str,
    ) -> ServiceResult<Option<ProjectedEvent>>;
    async fn projected_events_for_realm(
        &self,
        realm_id: &str,
    ) -> ServiceResult<Vec<ProjectedEvent>>;
    async fn projected_events_for_actor(
        &self,
        actor_id: &str,
    ) -> ServiceResult<Vec<ProjectedEvent>>;
    async fn projected_events_for_kind(
        &self,
        event_kind: arkret_wire::EventKind,
    ) -> ServiceResult<Vec<ProjectedEvent>>;
    async fn append_projected_event(
        &self,
        event: ProjectedEvent,
    ) -> ServiceResult<ProjectedEventAppendResult>;
    async fn accepted_events_for_actor(&self, actor_id: &str) -> ServiceResult<Vec<AcceptedEvent>>;
}

#[async_trait::async_trait]
pub trait ProjectionWritePort: Send + Sync {
    /// Persist one Circle row together with its complete membership set.
    async fn store_circle_projection(
        &self,
        record: &CircleProjectionRecord,
        members: &[CircleMemberProjectionRecord],
    ) -> ServiceResult<()>;
    async fn store_morph_projection(&self, record: &MorphProjectionRecord) -> ServiceResult<()>;
    async fn store_realm_organization_statement(
        &self,
        record: &RealmOrganizationStatementRecord,
    ) -> ServiceResult<()>;
}

/// Publication evidence per accepted Event canonical digest
/// (`authz/offline-publication.md` §2.1).
#[async_trait::async_trait]
pub trait PublicationEvidencePort: Send + Sync {
    /// Store the evidence for an Event not seen before and return whatever is
    /// stored afterwards. An Event that is already present wins, so the
    /// original `accepted_at` survives an idempotent retry verbatim.
    async fn store_publication_evidence(
        &self,
        record: PublicationEvidenceRecord,
    ) -> ServiceResult<PublicationEvidenceRecord>;
    async fn publication_evidence(
        &self,
        event_id: &arkret_wire::EventId,
    ) -> ServiceResult<Option<PublicationEvidenceRecord>>;
    async fn publication_evidence_for_events(
        &self,
        event_ids: &[arkret_wire::EventId],
    ) -> ServiceResult<Vec<PublicationEvidenceRecord>>;
}

#[derive(Clone)]
pub struct EventQueryService {
    events: Arc<dyn EventReadPort>,
    messages: Arc<dyn MessagePort>,
    applets: Arc<dyn AppletPort>,
    projections: Arc<dyn ProjectionWritePort>,
    publication_evidence: Arc<dyn PublicationEvidencePort>,
}

impl EventQueryService {
    pub async fn direct_conversation_founding_slot(
        &self,
        founder_id: &str,
        trust_domain_id: &str,
        pair_key: &str,
    ) -> ServiceResult<Option<coland_storage::DirectConversationFoundingSlotRecord>> {
        self.events
            .direct_conversation_founding_slot(founder_id, trust_domain_id, pair_key)
            .await
    }
    pub async fn direct_conversation_durable_state(
        &self,
        trust_domain_id: &str,
        pair_key: &str,
    ) -> ServiceResult<Option<coland_storage::DirectConversationDurableState>> {
        self.events
            .direct_conversation_durable_state(trust_domain_id, pair_key)
            .await
    }
    pub async fn direct_conversation_durable_state_for_realm(
        &self,
        realm_id: &str,
    ) -> ServiceResult<Option<coland_storage::DirectConversationDurableState>> {
        self.events
            .direct_conversation_durable_state_for_realm(realm_id)
            .await
    }
    pub async fn foreign_direct_mls_input(
        &self,
        realm: &arkret_wire::RealmId,
        caller: &arkret_wire::ActorId,
    ) -> ServiceResult<Option<coland_storage::ForeignDirectMlsInput>> {
        self.events.foreign_direct_mls_input(realm, caller).await
    }
    pub async fn install_foreign_direct_mls_public_state(
        &self,
        input: &coland_storage::ForeignDirectMlsInput,
        result: &coland_storage::ForeignDirectMlsBase,
        exact: bool,
    ) -> ServiceResult<bool> {
        self.events
            .install_foreign_direct_mls_public_state(input, result, exact)
            .await
    }
    pub async fn canonical_event(&self, event_id: &str) -> ServiceResult<Option<AcceptedEvent>> {
        self.events.canonical_event(event_id).await
    }
    pub async fn has_canonical_event(&self, event_id: &str) -> ServiceResult<bool> {
        self.events.has_canonical_event(event_id).await
    }
    pub async fn canonical_events(&self) -> ServiceResult<Vec<AcceptedEvent>> {
        self.events.canonical_events().await
    }
    pub async fn canonical_events_for_actor(
        &self,
        actor_id: &str,
    ) -> ServiceResult<Vec<AcceptedEvent>> {
        self.events.canonical_events_for_actor(actor_id).await
    }
    pub async fn franking_proofs_for_target(
        &self,
        realm_id: &str,
        received_by: &arkret_identifiers::DidCoreId,
        target_event_id: &str,
    ) -> ServiceResult<Vec<AcceptedEvent>> {
        self.events
            .franking_proofs_for_target(realm_id, received_by, target_event_id)
            .await
    }
    pub async fn identity_anchor_account_slot(
        &self,
        account_id: &arkret_wire::AccountId,
    ) -> ServiceResult<Option<coland_storage::IdentityAnchorAccountSlot>> {
        self.events.identity_anchor_account_slot(account_id).await
    }
    pub async fn realm_event_stats(&self, realm_id: &str) -> ServiceResult<RealmEventStats> {
        self.events.realm_event_stats(realm_id).await
    }
    pub async fn realm_events_newest_first(
        &self,
        realm_id: &str,
    ) -> ServiceResult<Vec<AcceptedEvent>> {
        self.events.realm_events_newest_first(realm_id).await
    }

    pub fn new(
        events: Arc<dyn EventReadPort>,
        messages: Arc<dyn MessagePort>,
        applets: Arc<dyn AppletPort>,
        projections: Arc<dyn ProjectionWritePort>,
        publication_evidence: Arc<dyn PublicationEvidencePort>,
    ) -> Self {
        Self {
            events,
            messages,
            applets,
            projections,
            publication_evidence,
        }
    }

    /// Persist the authority acceptance evidence for one Event, or return the
    /// evidence already stored for it.
    pub async fn store_publication_evidence(
        &self,
        record: PublicationEvidenceRecord,
    ) -> ServiceResult<PublicationEvidenceRecord> {
        self.publication_evidence
            .store_publication_evidence(record)
            .await
    }

    pub async fn publication_evidence(
        &self,
        event_id: &arkret_wire::EventId,
    ) -> ServiceResult<Option<PublicationEvidenceRecord>> {
        self.publication_evidence
            .publication_evidence(event_id)
            .await
    }

    pub async fn publication_evidence_for_events(
        &self,
        event_ids: &[arkret_wire::EventId],
    ) -> ServiceResult<Vec<PublicationEvidenceRecord>> {
        self.publication_evidence
            .publication_evidence_for_events(event_ids)
            .await
    }

    pub async fn accepted_event(&self, event_id: &str) -> ServiceResult<Option<AcceptedEvent>> {
        self.events.accepted_event(event_id).await
    }

    pub async fn accepted_events(&self) -> ServiceResult<Vec<AcceptedEvent>> {
        self.events.accepted_events().await
    }

    pub async fn projected_event(&self, event_id: &str) -> ServiceResult<Option<ProjectedEvent>> {
        self.events.projected_event(event_id).await
    }

    pub async fn projected_event_by_operation_id(
        &self,
        operation_id: &str,
    ) -> ServiceResult<Option<ProjectedEvent>> {
        self.events
            .projected_event_by_operation_id(operation_id)
            .await
    }

    pub async fn projected_events_for_realm(
        &self,
        realm_id: &str,
    ) -> ServiceResult<Vec<ProjectedEvent>> {
        self.events.projected_events_for_realm(realm_id).await
    }

    pub async fn projected_events_for_actor(
        &self,
        actor_id: &str,
    ) -> ServiceResult<Vec<ProjectedEvent>> {
        self.events.projected_events_for_actor(actor_id).await
    }

    pub async fn projected_events_for_kind(
        &self,
        event_kind: arkret_wire::EventKind,
    ) -> ServiceResult<Vec<ProjectedEvent>> {
        self.events.projected_events_for_kind(event_kind).await
    }

    pub async fn append_projected_event(
        &self,
        event: ProjectedEvent,
    ) -> ServiceResult<ProjectedEventAppendResult> {
        self.events.append_projected_event(event).await
    }

    pub async fn accepted_events_for_actor(
        &self,
        actor_id: &str,
    ) -> ServiceResult<Vec<AcceptedEvent>> {
        self.events.accepted_events_for_actor(actor_id).await
    }

    pub async fn message(&self, event_id: &str) -> ServiceResult<Option<MessageState>> {
        self.messages.message(event_id).await
    }

    pub async fn store_message(&self, message: MessageState) -> ServiceResult<()> {
        self.messages.store_message(message).await
    }

    pub async fn messages_for_realm(
        &self,
        realm_id: &str,
        limit: usize,
    ) -> ServiceResult<Vec<MessageState>> {
        self.messages.messages_for_realm(realm_id, limit).await
    }

    pub async fn applet(
        &self,
        applet_id: &str,
        effective_scope_key: &str,
    ) -> ServiceResult<Option<Value>> {
        self.applets.applet(applet_id, effective_scope_key).await
    }
    pub async fn applet_identity(
        &self,
        applet_id: &str,
        target_station_id: &str,
    ) -> ServiceResult<Option<Value>> {
        self.applets
            .applet_identity(applet_id, target_station_id)
            .await
    }
    pub async fn admit_applet_authoring_unit(
        &self,
        input: coland_storage::AppletAuthoringUnitWrite,
        author: coland_storage::AppletCommitAuthor,
        attester: coland_storage::AppletResolutionAttester,
        finalize: coland_storage::AppletUnitFinalizer,
    ) -> ServiceResult<coland_storage::AppletAuthoringUnitOutcome> {
        self.applets
            .admit_applet_authoring_unit(input, author, attester, finalize)
            .await
    }

    pub async fn applets(&self) -> ServiceResult<Vec<Value>> {
        self.applets.applets().await
    }
    pub async fn compare_and_swap_applet(
        &self,
        applet_id: &str,
        effective_scope_key: &str,
        expected: &Value,
        replacement: Value,
    ) -> ServiceResult<bool> {
        self.applets
            .compare_and_swap_applet(applet_id, effective_scope_key, expected, replacement)
            .await
    }
    pub async fn fence_applet_installation(
        &self,
        applet_id: &str,
        effective_scope_key: &str,
        target_station_id: &str,
        expected: &Value,
        replacement: Value,
        fenced_at: DateTime<Utc>,
    ) -> ServiceResult<coland_storage::AppletInstallationFenceOutcome> {
        self.applets
            .fence_applet_installation(
                applet_id,
                effective_scope_key,
                target_station_id,
                expected,
                replacement,
                fenced_at,
            )
            .await
    }
    pub async fn begin_applet_transaction(
        &self,
        replay: AppletTransactionReplayState,
    ) -> ServiceResult<AppletTransactionReplayResult> {
        self.applets.begin_applet_transaction(replay).await
    }
    pub async fn complete_applet_transaction(
        &self,
        applet_id: &str,
        source_id: &str,
        idempotency_key: &str,
        outcome: Value,
    ) -> ServiceResult<()> {
        self.applets
            .complete_applet_transaction(applet_id, source_id, idempotency_key, outcome)
            .await
    }

    pub async fn issue_applet_authoring_preview(
        &self,
        candidate: AppletAuthoringPreviewState,
    ) -> ServiceResult<AppletAuthoringPreviewState> {
        self.applets.issue_applet_authoring_preview(candidate).await
    }

    pub async fn current_applet_authoring_preview(
        &self,
        subject_key: &str,
    ) -> ServiceResult<Option<AppletAuthoringPreviewState>> {
        self.applets
            .current_applet_authoring_preview(subject_key)
            .await
    }
    /// Local host issuer. Return the opaque secret once; durable state contains only its digest.
    pub async fn issue_widget_credential(
        &self,
        mut record: coland_storage::AppletWidgetTokenRecord,
    ) -> ServiceResult<(String, coland_storage::AppletWidgetTokenRecord)> {
        let mut entropy = [0u8; 32];
        getrandom::fill(&mut entropy).map_err(|error| {
            crate::ServiceError::Internal(format!("widget credential entropy failed: {error}"))
        })?;
        let secret = hex::encode(entropy);
        record.token_digest =
            arkret_wire::Hash::new(arkret_canonical::sha256_digest(secret.as_bytes()))
                .map_err(|error| crate::ServiceError::Internal(error.to_string()))?;
        record.token_ref = format!("ak:widget_token:{}", uuid::Uuid::now_v7());
        record.invalidated_at = None;
        record.issued_at = Utc::now();
        if !self.applets.issue_widget_token(record.clone()).await? {
            return Err(crate::ServiceError::Conflict(
                "widget issuance collided".into(),
            ));
        }
        Ok((secret, record))
    }
    pub async fn issue_widget_token(
        &self,
        record: coland_storage::AppletWidgetTokenRecord,
    ) -> ServiceResult<bool> {
        self.applets.issue_widget_token(record).await
    }
    pub async fn widget_tokens(
        &self,
        install: &coland_storage::AppletWidgetInstallSelector,
        at: chrono::DateTime<chrono::Utc>,
    ) -> ServiceResult<Vec<coland_storage::AppletWidgetTokenRecord>> {
        self.applets.widget_tokens(install, at).await
    }
    pub async fn check_widget_token(
        &self,
        gate: &coland_storage::AppletWidgetTokenGateSelector,
        at: chrono::DateTime<chrono::Utc>,
    ) -> ServiceResult<coland_storage::AppletWidgetTokenRecord> {
        self.applets.check_widget_token(gate, at).await
    }
    pub async fn invalidate_widget_token(
        &self,
        install: &coland_storage::AppletWidgetInstallSelector,
        token_ref: &str,
        at: chrono::DateTime<chrono::Utc>,
    ) -> ServiceResult<coland_storage::AppletWidgetTokenInvalidation> {
        self.applets
            .invalidate_widget_token(install, token_ref, at)
            .await
    }
    pub async fn pending_applet_authoring_completions(
        &self,
        limit: u32,
    ) -> ServiceResult<Vec<coland_storage::AppletAuthoringCompletion>> {
        self.applets
            .pending_applet_authoring_completions(limit)
            .await
    }
    pub async fn acknowledge_applet_authoring_completion(
        &self,
        applet_id: &arkret_wire::AppletId,
        request_digest: &arkret_wire::Hash,
        at: DateTime<Utc>,
    ) -> ServiceResult<()> {
        self.applets
            .acknowledge_applet_authoring_completion(applet_id, request_digest, at)
            .await
    }

    pub async fn store_morph_projection(
        &self,
        record: &MorphProjectionRecord,
    ) -> ServiceResult<()> {
        self.projections.store_morph_projection(record).await
    }

    pub async fn store_circle_projection(
        &self,
        record: &CircleProjectionRecord,
        members: &[CircleMemberProjectionRecord],
    ) -> ServiceResult<()> {
        self.projections
            .store_circle_projection(record, members)
            .await
    }

    pub async fn store_realm_organization_statement(
        &self,
        record: &RealmOrganizationStatementRecord,
    ) -> ServiceResult<()> {
        self.projections
            .store_realm_organization_statement(record)
            .await
    }
}

/// Read port of the `mls_group` typed current (encryption-and-audit.md
/// §2.5). Only the accepting transactions of MLS Events and of membership
/// changes write it.
#[async_trait::async_trait]
pub trait MlsGroupReadPort: Send + Sync {
    async fn current(
        &self,
        effective_scope: &ScopeRef,
    ) -> ServiceResult<Option<coland_storage::MlsGroupCurrentRecord>>;
    async fn realm_currents(
        &self,
        realm_id: &arkret_wire::RealmId,
    ) -> ServiceResult<Vec<coland_storage::MlsGroupCurrentRecord>>;
    #[cfg(any(test, feature = "test-support"))]
    async fn seed_test_current(
        &self,
        record: &coland_storage::MlsGroupCurrentRecord,
    ) -> ServiceResult<()>;
}

#[derive(Clone)]
pub struct MlsGroupQueryService {
    groups: Arc<dyn MlsGroupReadPort>,
}

impl MlsGroupQueryService {
    pub fn new(groups: Arc<dyn MlsGroupReadPort>) -> Self {
        Self { groups }
    }

    /// The accepted current group of `effective_scope`, if its Genesis is
    /// accepted.
    pub async fn current(
        &self,
        effective_scope: &ScopeRef,
    ) -> ServiceResult<Option<coland_storage::MlsGroupCurrentRecord>> {
        self.groups.current(effective_scope).await
    }

    /// Every accepted current group of one Realm, Realm scope first.
    pub async fn realm_currents(
        &self,
        realm_id: &arkret_wire::RealmId,
    ) -> ServiceResult<Vec<coland_storage::MlsGroupCurrentRecord>> {
        self.groups.realm_currents(realm_id).await
    }

    /// Install one current group row for a reader fixture.
    #[cfg(any(test, feature = "test-support"))]
    pub async fn seed_test_current(
        &self,
        record: &coland_storage::MlsGroupCurrentRecord,
    ) -> ServiceResult<()> {
        self.groups.seed_test_current(record).await
    }
}

pub struct ClaimMlsKeyPackageCommand<'a> {
    pub id: &'a str,
    pub target: ClaimMlsKeyPackageTarget<'a>,
    pub intended_realm_id: Option<&'a str>,
    pub device_authorize_event_id: Option<&'a str>,
    pub agent_key_authorize_event_id: Option<&'a str>,
    pub device_revocation_gate: Option<&'a coland_storage::DeviceRevocationGateSelector>,
    pub claimed_at: i64,
    pub claim_expires_at_unix_ms: Option<i64>,
    pub applet_device_scope_guard: Option<&'a coland_storage::AppletManagedDeviceScopeGuard>,
}

pub enum ClaimMlsKeyPackageTarget<'a> {
    Group(&'a str),
    Retire,
    Revoke,
}

pub use coland_storage::{
    MlsKeyPackageRow as MlsKeyPackageState,
    PeerKeyPackageClaimLedgerRecord as PeerKeyPackageClaimLedgerState,
    PersistedKeyPackageClaimState, PersistedKeyPackageReusePolicy,
};

pub struct PeerKeyPackageClaimCommand<'a> {
    pub admission: Option<&'a coland_storage::MlsKeyPackageClaimAdmission>,
    pub keypackage_id: &'a str,
    pub mls_group_id: &'a str,
    pub device_authorize_event_id: Option<&'a str>,
    pub agent_key_authorize_event_id: Option<&'a str>,
    pub device_revocation_gate: Option<&'a coland_storage::DeviceRevocationGateSelector>,
    pub claimed_at_unix_ms: i64,
    pub claim_expires_at_unix_ms: i64,
    pub ledger: &'a PeerKeyPackageClaimLedgerState,
    pub applet_device_scope_guard: Option<&'a coland_storage::AppletManagedDeviceScopeGuard>,
}

pub struct PeerClaimTerminalTransitionCommand<'a> {
    pub source_id: &'a str,
    pub claim_request_id: &'a str,
    pub request_digest: &'a str,
    pub expected_outcome: &'a Value,
    pub terminal_state: &'a str,
    pub terminal_receipt: &'a Value,
    pub now_unix_ms: i64,
}

pub use coland_storage::{
    PeerKeyPackageClaimAttemptResult as PeerKeyPackageClaimResult,
    PeerKeyPackageClaimLedgerWriteResult,
};

#[async_trait::async_trait]
pub trait MlsKeyPackageMaintenancePort: Send + Sync {
    async fn store_key_package(&self, record: &MlsKeyPackageState) -> ServiceResult<bool>;
    async fn store_key_package_for_applet_device(
        &self,
        record: &MlsKeyPackageState,
        guard: &coland_storage::AppletManagedDeviceScopeGuard,
        expires_at: chrono::DateTime<chrono::Utc>,
        body: &arkret_models_crypto::KeyPackagesUploadRequestBody,
    ) -> ServiceResult<bool>;

    async fn revoke_for_applet_device(
        &self,
        body: &arkret_models_crypto::KeyPackagesRevokeRequestBody,
        authority: &coland_storage::AppletManagedDeviceAuthority,
        scope: &arkret_wire::ScopeRef,
        expires_at: chrono::DateTime<chrono::Utc>,
    ) -> ServiceResult<coland_storage::MlsKeyPackageRevocation>;
    async fn key_package(&self, id: &str) -> ServiceResult<Option<MlsKeyPackageState>>;
    async fn key_package_by_ref(
        &self,
        keypackage_ref: &str,
    ) -> ServiceResult<Option<MlsKeyPackageState>>;
    async fn claim_key_package(
        &self,
        command: ClaimMlsKeyPackageCommand<'_>,
    ) -> ServiceResult<Option<MlsKeyPackageState>>;
    async fn consume_key_package_claim(
        &self,
        id: &str,
        mls_group_id: &str,
        now_unix_ms: i64,
        peer_consume_receipt: Option<&Value>,
    ) -> ServiceResult<Option<MlsKeyPackageState>>;
    async fn record_peer_claim_attempt(
        &self,
        body: &arkret_models_crypto::PeerKeyPackagesClaimRequestBody,
    ) -> ServiceResult<coland_storage::PeerKeyPackageClaimRateDecision>;
    async fn prune_peer_claim_attempts(&self) -> ServiceResult<usize>;
    async fn peer_claim(
        &self,
        source_id: &str,
        claim_request_id: &str,
    ) -> ServiceResult<Option<PeerKeyPackageClaimLedgerState>>;
    async fn peer_claim_by_claim_id(
        &self,
        claim_id: &str,
    ) -> ServiceResult<Option<PeerKeyPackageClaimLedgerState>>;
    async fn peer_claim_by_keypackage_id(
        &self,
        keypackage_id: &str,
    ) -> ServiceResult<Option<PeerKeyPackageClaimLedgerState>>;
    async fn claim_welcome_binding(
        &self,
        claim_id: &str,
    ) -> ServiceResult<Option<coland_storage::MlsWelcomeClaimBinding>>;
    async fn claim_peer_key_package(
        &self,
        attempt: PeerKeyPackageClaimCommand<'_>,
    ) -> ServiceResult<PeerKeyPackageClaimResult>;
    async fn store_peer_claim_terminal(
        &self,
        record: &PeerKeyPackageClaimLedgerState,
    ) -> ServiceResult<PeerKeyPackageClaimLedgerWriteResult>;
    async fn attach_peer_claim_terminal_receipt(
        &self,
        source_id: &str,
        claim_request_id: &str,
        request_digest: &str,
        terminal_receipt: &Value,
        updated_at: i64,
    ) -> ServiceResult<Option<PeerKeyPackageClaimLedgerState>>;
    async fn attach_peer_claim_consume_receipt(
        &self,
        source_id: &str,
        claim_request_id: &str,
        request_digest: &str,
        consume_receipt: &Value,
        now_unix_ms: i64,
    ) -> ServiceResult<Option<PeerKeyPackageClaimLedgerState>>;
    async fn transition_peer_claim_consumed(
        &self,
        source_id: &str,
        claim_request_id: &str,
        request_digest: &str,
        expected_outcome: &Value,
        consume_receipt: &Value,
        consumed_at_unix_ms: i64,
    ) -> ServiceResult<Option<PeerKeyPackageClaimLedgerState>>;
    async fn transition_peer_claim_terminal(
        &self,
        transition: PeerClaimTerminalTransitionCommand<'_>,
    ) -> ServiceResult<Option<PeerKeyPackageClaimLedgerState>>;
    async fn revoke_expired_peer_claims(&self, now_unix_ms: i64) -> ServiceResult<Vec<String>>;
    async fn key_packages(&self) -> ServiceResult<Vec<MlsKeyPackageState>>;
    async fn key_packages_claimed_by_group(
        &self,
        mls_group_id: &str,
    ) -> ServiceResult<Vec<MlsKeyPackageState>>;
    async fn retire_owner_account_keypackages(
        &self,
        owner_account_id: arkret_wire::AccountId,
        retired_at: i64,
    ) -> ServiceResult<usize>;
}

#[derive(Clone)]
pub struct MlsKeyPackageService {
    key_packages: Arc<dyn MlsKeyPackageMaintenancePort>,
}

impl MlsKeyPackageService {
    pub fn new(key_packages: Arc<dyn MlsKeyPackageMaintenancePort>) -> Self {
        Self { key_packages }
    }

    pub async fn retire_owner_account_keypackages(
        &self,
        owner_account_id: arkret_wire::AccountId,
        retired_at: i64,
    ) -> ServiceResult<usize> {
        self.key_packages
            .retire_owner_account_keypackages(owner_account_id, retired_at)
            .await
    }

    pub async fn store_key_package(&self, record: &MlsKeyPackageState) -> ServiceResult<bool> {
        self.key_packages.store_key_package(record).await
    }
    pub async fn store_key_package_for_applet_device(
        &self,
        record: &MlsKeyPackageState,
        guard: &coland_storage::AppletManagedDeviceScopeGuard,
        expires_at: chrono::DateTime<chrono::Utc>,
        body: &arkret_models_crypto::KeyPackagesUploadRequestBody,
    ) -> ServiceResult<bool> {
        self.key_packages
            .store_key_package_for_applet_device(record, guard, expires_at, body)
            .await
    }
    pub async fn revoke_for_applet_device(
        &self,
        body: &arkret_models_crypto::KeyPackagesRevokeRequestBody,
        authority: &coland_storage::AppletManagedDeviceAuthority,
        scope: &arkret_wire::ScopeRef,
        expires_at: chrono::DateTime<chrono::Utc>,
    ) -> ServiceResult<coland_storage::MlsKeyPackageRevocation> {
        self.key_packages
            .revoke_for_applet_device(body, authority, scope, expires_at)
            .await
    }
    pub async fn key_package(&self, id: &str) -> ServiceResult<Option<MlsKeyPackageState>> {
        self.key_packages.key_package(id).await
    }
    pub async fn key_package_by_ref(
        &self,
        keypackage_ref: &str,
    ) -> ServiceResult<Option<MlsKeyPackageState>> {
        self.key_packages.key_package_by_ref(keypackage_ref).await
    }
    pub async fn claim_key_package(
        &self,
        command: ClaimMlsKeyPackageCommand<'_>,
    ) -> ServiceResult<Option<MlsKeyPackageState>> {
        self.key_packages.claim_key_package(command).await
    }
    pub async fn consume_key_package_claim(
        &self,
        id: &str,
        mls_group_id: &str,
        now_unix_ms: i64,
        peer_consume_receipt: Option<&Value>,
    ) -> ServiceResult<Option<MlsKeyPackageState>> {
        self.key_packages
            .consume_key_package_claim(id, mls_group_id, now_unix_ms, peer_consume_receipt)
            .await
    }
    pub async fn record_peer_claim_attempt(
        &self,
        body: &arkret_models_crypto::PeerKeyPackagesClaimRequestBody,
    ) -> ServiceResult<coland_storage::PeerKeyPackageClaimRateDecision> {
        self.key_packages.record_peer_claim_attempt(body).await
    }
    pub async fn prune_peer_claim_attempts(&self) -> ServiceResult<usize> {
        self.key_packages.prune_peer_claim_attempts().await
    }
    pub async fn peer_claim(
        &self,
        source_id: &str,
        claim_request_id: &str,
    ) -> ServiceResult<Option<PeerKeyPackageClaimLedgerState>> {
        self.key_packages
            .peer_claim(source_id, claim_request_id)
            .await
    }
    /// The ledger row that issued the exact `KeypackageClaimId` a Welcome
    /// names.
    pub async fn peer_claim_by_claim_id(
        &self,
        claim_id: &str,
    ) -> ServiceResult<Option<PeerKeyPackageClaimLedgerState>> {
        self.key_packages.peer_claim_by_claim_id(claim_id).await
    }
    /// The Welcome binding the claim destination recorded for `claim_id`
    /// when it queued that claim's Welcome (decision 0121).
    pub async fn claim_welcome_binding(
        &self,
        claim_id: &str,
    ) -> ServiceResult<Option<coland_storage::MlsWelcomeClaimBinding>> {
        self.key_packages.claim_welcome_binding(claim_id).await
    }
    pub async fn peer_claim_by_keypackage_id(
        &self,
        keypackage_id: &str,
    ) -> ServiceResult<Option<PeerKeyPackageClaimLedgerState>> {
        self.key_packages
            .peer_claim_by_keypackage_id(keypackage_id)
            .await
    }
    pub async fn claim_peer_key_package(
        &self,
        attempt: PeerKeyPackageClaimCommand<'_>,
    ) -> ServiceResult<PeerKeyPackageClaimResult> {
        self.key_packages.claim_peer_key_package(attempt).await
    }
    pub async fn store_peer_claim_terminal(
        &self,
        record: &PeerKeyPackageClaimLedgerState,
    ) -> ServiceResult<PeerKeyPackageClaimLedgerWriteResult> {
        self.key_packages.store_peer_claim_terminal(record).await
    }
    pub async fn attach_peer_claim_terminal_receipt(
        &self,
        source_id: &str,
        claim_request_id: &str,
        request_digest: &str,
        terminal_receipt: &Value,
        updated_at: i64,
    ) -> ServiceResult<Option<PeerKeyPackageClaimLedgerState>> {
        self.key_packages
            .attach_peer_claim_terminal_receipt(
                source_id,
                claim_request_id,
                request_digest,
                terminal_receipt,
                updated_at,
            )
            .await
    }
    pub async fn attach_peer_claim_consume_receipt(
        &self,
        source_id: &str,
        claim_request_id: &str,
        request_digest: &str,
        consume_receipt: &Value,
        now_unix_ms: i64,
    ) -> ServiceResult<Option<PeerKeyPackageClaimLedgerState>> {
        self.key_packages
            .attach_peer_claim_consume_receipt(
                source_id,
                claim_request_id,
                request_digest,
                consume_receipt,
                now_unix_ms,
            )
            .await
    }
    pub async fn transition_peer_claim_terminal(
        &self,
        transition: PeerClaimTerminalTransitionCommand<'_>,
    ) -> ServiceResult<Option<PeerKeyPackageClaimLedgerState>> {
        self.key_packages
            .transition_peer_claim_terminal(transition)
            .await
    }
    pub async fn transition_peer_claim_consumed(
        &self,
        source_id: &str,
        claim_request_id: &str,
        request_digest: &str,
        expected_outcome: &Value,
        consume_receipt: &Value,
        consumed_at_unix_ms: i64,
    ) -> ServiceResult<Option<PeerKeyPackageClaimLedgerState>> {
        self.key_packages
            .transition_peer_claim_consumed(
                source_id,
                claim_request_id,
                request_digest,
                expected_outcome,
                consume_receipt,
                consumed_at_unix_ms,
            )
            .await
    }
    pub async fn revoke_expired_peer_claims(&self, now_unix_ms: i64) -> ServiceResult<Vec<String>> {
        self.key_packages
            .revoke_expired_peer_claims(now_unix_ms)
            .await
    }
    pub async fn key_packages(&self) -> ServiceResult<Vec<MlsKeyPackageState>> {
        self.key_packages.key_packages().await
    }
    pub async fn key_packages_claimed_by_group(
        &self,
        mls_group_id: &str,
    ) -> ServiceResult<Vec<MlsKeyPackageState>> {
        self.key_packages
            .key_packages_claimed_by_group(mls_group_id)
            .await
    }
}

pub use coland_storage::RealmMetaRecord as RealmMetadata;

#[async_trait::async_trait]
pub trait RealmMetadataPort: Send + Sync {
    async fn realm_metadata(&self, realm_id: &str) -> ServiceResult<Option<RealmMetadata>>;
    async fn realm_metadata_list(&self) -> ServiceResult<Vec<(String, RealmMetadata)>>;
    async fn store_realm_metadata(
        &self,
        realm_id: &str,
        metadata: RealmMetadata,
    ) -> ServiceResult<()>;
    async fn delete_realm_metadata(&self, realm_id: &str) -> ServiceResult<()>;
}

#[derive(Clone)]
pub struct RealmQueryService {
    realms: Arc<dyn RealmMetadataPort>,
}

impl RealmQueryService {
    pub fn new(realms: Arc<dyn RealmMetadataPort>) -> Self {
        Self { realms }
    }

    pub async fn realm_metadata(&self, realm_id: &str) -> ServiceResult<Option<RealmMetadata>> {
        self.realms.realm_metadata(realm_id).await
    }

    pub async fn realm_metadata_list(&self) -> ServiceResult<Vec<(String, RealmMetadata)>> {
        self.realms.realm_metadata_list().await
    }

    pub async fn store_realm_metadata(
        &self,
        realm_id: &str,
        metadata: RealmMetadata,
    ) -> ServiceResult<()> {
        self.realms.store_realm_metadata(realm_id, metadata).await
    }
    pub async fn delete_realm_metadata(&self, realm_id: &str) -> ServiceResult<()> {
        self.realms.delete_realm_metadata(realm_id).await
    }
}

pub use coland_storage::{
    InviteLocatorInsertOutcome as InviteLocatorInsertResult,
    InviteLocatorRecord as InviteLocatorState,
    InviteLocatorRotateMutation as InviteLocatorRotateCommand,
};

#[async_trait::async_trait]
pub trait InviteLocatorPort: Send + Sync {
    async fn insert(
        &self,
        record: &InviteLocatorState,
        active_limit: usize,
        now: DateTime<Utc>,
    ) -> ServiceResult<InviteLocatorInsertResult>;
    async fn resolve_and_consume(
        &self,
        token_digest: &str,
        now: DateTime<Utc>,
    ) -> ServiceResult<Option<InviteLocatorState>>;
    async fn rotate(
        &self,
        subject_id: &str,
        old_locator_id: &str,
        mutation: &InviteLocatorRotateCommand,
        now: DateTime<Utc>,
    ) -> ServiceResult<Option<InviteLocatorState>>;
    async fn revoke(
        &self,
        subject_id: &str,
        locator_id: &str,
        now: DateTime<Utc>,
    ) -> ServiceResult<Option<InviteLocatorState>>;
}

/// Principal invite locators (`invite_locators`), independent of any Realm
/// Invite.
#[derive(Clone)]
pub struct InviteLocatorService {
    locators: Arc<dyn InviteLocatorPort>,
}

impl InviteLocatorService {
    pub fn new(locators: Arc<dyn InviteLocatorPort>) -> Self {
        Self { locators }
    }

    pub async fn insert_locator(
        &self,
        record: &InviteLocatorState,
        active_limit: usize,
        now: DateTime<Utc>,
    ) -> ServiceResult<InviteLocatorInsertResult> {
        self.locators.insert(record, active_limit, now).await
    }

    pub async fn resolve_and_consume_locator(
        &self,
        token_digest: &str,
        now: DateTime<Utc>,
    ) -> ServiceResult<Option<InviteLocatorState>> {
        self.locators.resolve_and_consume(token_digest, now).await
    }

    pub async fn rotate_locator(
        &self,
        subject_id: &str,
        old_locator_id: &str,
        mutation: &InviteLocatorRotateCommand,
        now: DateTime<Utc>,
    ) -> ServiceResult<Option<InviteLocatorState>> {
        self.locators
            .rotate(subject_id, old_locator_id, mutation, now)
            .await
    }

    pub async fn revoke_locator(
        &self,
        subject_id: &str,
        locator_id: &str,
        now: DateTime<Utc>,
    ) -> ServiceResult<Option<InviteLocatorState>> {
        self.locators.revoke(subject_id, locator_id, now).await
    }
}

#[derive(Clone)]
pub struct EventService {
    commits: Arc<dyn EventCommitPort>,
}

#[async_trait::async_trait]
pub trait EventCommitPort: Send + Sync {
    async fn commit_accepted_event(
        &self,
        command: CommitAcceptedEventCommand,
    ) -> ServiceResult<CommitAcceptedEventResult>;

    async fn commit_accepted_event_batch(
        &self,
        command: CommitAcceptedEventBatchCommand,
    ) -> ServiceResult<CommitAcceptedEventResult>;
}

impl EventService {
    pub fn new(commits: Arc<dyn EventCommitPort>) -> Self {
        Self { commits }
    }

    pub fn commit_accepted_event(
        &self,
        command: CommitAcceptedEventCommand,
    ) -> impl std::future::Future<Output = ServiceResult<CommitAcceptedEventResult>> + Send + '_
    {
        self.commits.commit_accepted_event(command)
    }

    pub fn commit_accepted_event_batch(
        &self,
        command: CommitAcceptedEventBatchCommand,
    ) -> impl std::future::Future<Output = ServiceResult<CommitAcceptedEventResult>> + Send + '_
    {
        self.commits.commit_accepted_event_batch(command)
    }
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;

    use super::*;

    struct RecordingCommitter;

    #[async_trait]
    impl EventCommitPort for RecordingCommitter {
        async fn commit_accepted_event(
            &self,
            command: CommitAcceptedEventCommand,
        ) -> ServiceResult<CommitAcceptedEventResult> {
            assert_eq!(command.event.kind, "ak.message.create");
            assert_eq!(command.projections.len(), 1);
            assert_eq!(command.deliveries.len(), 1);
            Ok(CommitAcceptedEventResult {
                audit_outcome: None,
                projections_inserted: 1,
                deliveries_inserted: 1,
            })
        }

        async fn commit_accepted_event_batch(
            &self,
            command: CommitAcceptedEventBatchCommand,
        ) -> ServiceResult<CommitAcceptedEventResult> {
            assert_eq!(command.events.len(), 2);
            assert!(command.applet_record.is_some());
            Ok(CommitAcceptedEventResult {
                audit_outcome: None,
                projections_inserted: 2,
                deliveries_inserted: 0,
            })
        }
    }

    /// One accepted Event plus the signed commit that ordered it.
    ///
    /// A commit accepts exactly one Event, so the fixture builds the pair
    /// together and keeps the same Realm, stream and Event id on both sides.
    fn authority_commit_fixture(
        event_id: &arkret_identifiers::EventId,
        realm_id: &arkret_identifiers::RealmId,
        now: DateTime<Utc>,
    ) -> coland_storage::AuthorityCommitTransaction {
        let stream_ref = arkret_wire::CommitStreamRef::Realm {
            realm_id: realm_id.clone(),
        };
        let authority_ref =
            arkret_wire::RealmCommitAuthorityRef::GenesisOrChangeEvent(event_id.clone());
        coland_storage::AuthorityCommitTransaction {
            expected_authority: coland_storage::CurrentRealmAuthority {
                realm_id: realm_id.clone(),
                generation: 0,
                service_id: DidCoreId::new("ak:did_core:web:station.example").unwrap(),
                authority_ref: authority_ref.clone(),
                last_handoff_ref: None,
            },
            event: arkret_wire::Event {
                event_id: event_id.clone(),
                kind: arkret_wire::EventKind::MessageCreate,
                realm_id: realm_id.clone(),
                scope_ref: arkret_wire::ScopeRef::Realm {
                    realm_id: realm_id.clone(),
                },
                actor_id: arkret_wire::ActorId::account(arkret_wire::AccountId::new(
                    DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
                    DidCoreId::new("ak:did_core:web:station.example").unwrap(),
                )),
                executed_by: None,
                authorization_ref: None,
                applet_id: None,
                external_ref: None,
                created_at: now,
                semantic_refs: Vec::new(),
                payload: BTreeMap::new(),
                producer_proof: None,
            },
            commit: arkret_wire::RealmCommit {
                producer_signer_fact_digest: None,
                commit_id: arkret_wire::RealmCommitId::from_digest([0x32; 32]),
                realm_id: realm_id.clone(),
                stream_ref,
                stream_position: 0,
                previous_commit_ref: None,
                event_ref: event_id.clone(),
                governance_generation: 0,
                authority_ref,
                committed_at: now,
                signature: arkret_wire::DetachedObjectSignature {
                    context: arkret_wire::DetachedSignatureContext::RealmCommit,
                    signature_algorithm: arkret_wire::DetachedSignatureAlgorithm::Ed25519,
                    verification_method: arkret_wire::DidUrl::new(
                        "did:web:station.example#authority",
                    )
                    .unwrap(),
                    signed_digest: arkret_wire::Hash::new(format!("sha256:{}", "3".repeat(64)))
                        .unwrap(),
                    created_at: now,
                    sig: arkret_wire::Base64UrlString::new("c2lnbmF0dXJl".to_owned()).unwrap(),
                },
            },
            producer_signer_fact: None,
            mls_state: None,
            welcomes: Vec::new(),
            recipient_queue_capacity: 0,
        }
    }

    #[tokio::test]
    async fn accepted_event_command_is_committed_through_one_port() {
        let now = Utc::now();
        let event_id = arkret_identifiers::EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            [0x31; 32],
        );
        let realm_id = arkret_identifiers::RealmId::from_event_id(&event_id);
        let authority_commit = authority_commit_fixture(&event_id, &realm_id, now);
        let event_id = event_id.to_string();
        let realm_id = realm_id.to_string();
        let service = EventService::new(Arc::new(RecordingCommitter));
        let result = service
            .commit_accepted_event(CommitAcceptedEventCommand {
                verified_media_participant: None,
                authority_commit,
                self_producer_guard: None,
                applet_producer_guard: None,
                widget_token_gate: None,
                agent_grant_scope_evidence: None,
                forwarded_producer_evidence: None,
                forwarded_agent_producer: None,
                agent_deployment_ceiling: arkret_models_collaboration::governance::agent_participation::ParticipationBits::ALL,
                parent_membership_admission: None,
                contact_projection: None,

                event: AcceptedEvent {
                    event_id: event_id.clone(),
                    actor_id: "ak:did_core:web:alice.example".to_owned(),
                    realm_id: Some(realm_id.clone()),
                    kind: "ak.message.create".to_owned(),
                    schema_id: "arkret://events/message/create/v1".to_owned(),
                    digest_suite: arkret_canonical::DigestSuite::Sha256,
                    canonical_digest: "sha256:test".to_owned(),
                    canonical_bytes: vec![1],
                    envelope: serde_json::json!({}),
                    received_at: now,
                },
                device_revocation_transition: None,
                device_revocation_gate: None,
                projections: vec![ProjectedEvent {
                    event_id,
                    realm_id,
                    event_kind: arkret_wire::EventKind::MessageCreate,
                    operation_kind: "create".to_owned(),
                    operation_id: None,
                    sender: Some("did:web:alice.example".to_owned()),
                    payload: serde_json::json!({}),
                    created_at: now,
                    received_at: now,
                }],
                idempotency: None,
                deliveries: vec![FederationDeliveryRecord {
                    id: "delivery:test".to_owned(),
                    peer_id: arkret_wire::DidCoreId::new("ak:did_core:web:peer.example")
                        .expect("peer service id"),
                    peer_url: Some("https://peer.example".to_owned()),
                    endpoint: "/_arkret/peer/events".to_owned(),
                    idempotency_key: "event:test".to_owned(),
                    payload_json: "{}".to_owned(),
                    coalescing_key: None,
                    coalescing_position: None,
                    realm_fanout: None,
                    created_at: now.timestamp(),
                }],
                realm_fanout_source: None,
            })
            .await
            .expect("commit accepted event");
        assert_eq!(result.projections_inserted, 1);
        assert_eq!(result.deliveries_inserted, 1);
    }
}
