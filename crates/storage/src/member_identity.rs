use super::{PersistenceResult, Value, async_trait};

/// Cell subject key for the member-identity registry. Mirrors the composite
/// `(payload.realm_id, payload.member_id, payload.segment)` cell subject from
/// `event-kind-registry.json`.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct MemberIdentitySubjectKey {
    pub realm_id: String,
    pub actor_id: String,
    pub segment: String,
}

/// One replacement edge resolved from `payload.replaces[]`.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MemberIdentityReplacementEdge {
    pub event_id: String,
    pub payload_digest: String,
}

/// One stored `ak.member.identity.update` event.
#[derive(Clone, Debug, PartialEq)]
pub struct MemberIdentityEventRecord {
    pub event_id: String,
    pub subject: MemberIdentitySubjectKey,
    /// SHA-256 over RFC 8785 JCS canonical JSON of the full
    /// `payload.identity_payload` carrier object (the value goes into
    /// any subsequent event's `payload.replaces[].payload_digest`).
    pub payload_digest: String,
    /// `payload.replaces[]` references as observed on the wire. The
    /// effective-set filter matches each edge's `payload_digest` against the
    /// referenced event's stored `payload_digest` at projection time
    /// (mismatched / cross-subject references are dropped as no-op edges per
    /// MID-2).
    pub replaces: Vec<MemberIdentityReplacementEdge>,
    /// Original Event envelope as received. MID-5: coland MUST store the
    /// envelope verbatim; no query-time re-encryption, no projection
    /// rewrite.
    pub raw_event: Value,
}

/// Local handle-claim evidence record, keyed by claim `subject`. Sources are
/// deliberately local-only: directory-issued signed claims and handle-claim
/// envelopes carried by accepted identity events.
#[derive(Clone, Debug, PartialEq)]
pub struct HandleClaimEvidenceRecord {
    pub digest: String,
    pub subject_id: arkret_wire::DidCoreId,
    pub issuer_id: arkret_wire::DidCoreId,
    pub audience: Option<String>,
    pub status: String,
    pub revocation_digest: Option<String>,
    pub fresh_until: chrono::DateTime<chrono::Utc>,
    pub visibility: Option<String>,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub envelope: Value,
}

/// Accepted identity Event/Commit hydration plus local handle-claim evidence.
/// Identity assertions are written only by the accepting Event unit of work.
#[async_trait]
pub trait MemberIdentityStore: Send + Sync {
    /// Full event snapshot for startup hydration.
    async fn snapshot_events(&self) -> PersistenceResult<Vec<MemberIdentityEventRecord>>;
    /// Idempotent upsert keyed by `(subject_id, digest)`.
    async fn put_handle_claim(&self, record: &HandleClaimEvidenceRecord) -> PersistenceResult<()>;
    /// Drop every cached claim for one subject; returns the number removed.
    async fn delete_handle_claims_for_subject(
        &self,
        subject_id: &arkret_wire::DidCoreId,
    ) -> PersistenceResult<usize>;
    /// Full handle-claim snapshot for startup hydration.
    async fn snapshot_handle_claims(&self) -> PersistenceResult<Vec<HandleClaimEvidenceRecord>>;
}
