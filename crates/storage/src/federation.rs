use arkret_wire::DidCoreId;

use super::{
    FederationOutboxDeadLetterRecord, FederationOutboxRecord, FederationOutboxState,
    PersistenceError, PersistenceResult, ProjectedEventOperation, async_trait,
};

/// One atomic "read due rows and take ownership of them" operation.
///
/// Claiming and reading are deliberately one storage call: a bare `SELECT`
/// lets two replicas send the same row concurrently, which the receiver's
/// idempotency absorbs but which inflates traffic, attempt counters and
/// diagnostic noise (`sync/federation.md` §8.5).
#[derive(Clone, Debug)]
pub struct FederationOutboxClaim {
    pub now_unix_secs: i64,
    pub limit: usize,
    /// Stable worker identity, e.g. `<service_id>#<process uuid>`.
    pub lease_owner: String,
    /// Random per-claim token. A row re-claimed later carries a different
    /// token, which is what invalidates the previous holder's writes.
    pub lease_token: String,
    pub lease_duration_secs: i64,
}

/// The terminal or retry decision one delivery attempt produced.
#[derive(Clone, Debug)]
pub enum FederationOutboxOutcome {
    /// Keep the same transport identity (same canonical body, same
    /// `Idempotency-Key`) and try again at `next_attempt_at`.
    Retry { next_attempt_at: i64 },
    /// No verified route currently exists for the frozen target service.
    /// Realm fanout keeps the exact intent durable and retries indefinitely.
    RouteUnavailable { next_attempt_at: i64 },
    /// Peer accepted or confirmed the batch as a duplicate.
    Delivered,
    /// Every frozen authority witness ceased to be current before send.
    /// This is terminal and the old intent is never revived by later joins.
    CancelledAuthorityLost,
    /// Local egress policy denied the target before any socket was opened.
    /// Not a network failure and not a delivery — it stays recoverable
    /// through revalidation when the policy version changes.
    PolicySuppressed { policy_version: String },
    /// Terminal failure. The dead-letter row is written in the same
    /// transaction as the state change, so "stopped delivering" and "has a
    /// failure ledger entry" can never disagree.
    // Boxed for the same reason as `FederationDeliveryOutcome::DeadLettered`.
    DeadLettered(Box<FederationOutboxDeadLetterRecord>),
    /// A response was received that requires re-evaluation. The old transport
    /// identity is finished and a fresh pending row (new body, new
    /// `Idempotency-Key`, `supersedes_outbox_id` back-reference) replaces it in
    /// the same transaction (`sync/federation.md` §8.5).
    Superseded(Box<FederationOutboxRecord>),
}

/// The full result of one delivery attempt, applied atomically.
#[derive(Clone, Debug)]
pub struct FederationOutboxTransition {
    pub id: String,
    /// Lease token the caller holds. The write only lands when it matches the
    /// row's current `lease_token`.
    pub lease_token: String,
    pub attempts: i32,
    pub semantic_attempts: i32,
    pub last_http_status: Option<i32>,
    pub last_error_code: Option<String>,
    pub last_response_excerpt: Option<String>,
    pub observed_at: i64,
    pub outcome: FederationOutboxOutcome,
}

/// Storage-neutral projection of an outbox delivery outcome.
///
/// The memory and PostgreSQL adapters deliberately share this classifier so
/// lifecycle admission and field projection cannot drift between backends.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FederationOutboxCompletion {
    pub state: FederationOutboxState,
    pub next_attempt_at: i64,
    pub completed_at: Option<i64>,
    pub policy_version: Option<String>,
}

#[doc(hidden)]
pub fn classify_federation_outbox_completion(
    realm_fanout: bool,
    transition: &FederationOutboxTransition,
) -> PersistenceResult<FederationOutboxCompletion> {
    if (realm_fanout
        && matches!(
            &transition.outcome,
            FederationOutboxOutcome::PolicySuppressed { .. }
                | FederationOutboxOutcome::DeadLettered(_)
                | FederationOutboxOutcome::Superseded(_)
        ))
        || (!realm_fanout
            && matches!(
                &transition.outcome,
                FederationOutboxOutcome::RouteUnavailable { .. }
                    | FederationOutboxOutcome::CancelledAuthorityLost
            ))
    {
        return Err(PersistenceError::Conflict(
            "schema_violation: federation transition does not match the row lifecycle".to_owned(),
        ));
    }

    let (state, next_attempt_at, completed_at, policy_version) = match &transition.outcome {
        FederationOutboxOutcome::Retry { next_attempt_at } => {
            (FederationOutboxState::Pending, *next_attempt_at, None, None)
        }
        FederationOutboxOutcome::RouteUnavailable { next_attempt_at } => (
            FederationOutboxState::PendingRoute,
            *next_attempt_at,
            None,
            None,
        ),
        FederationOutboxOutcome::Delivered => (
            FederationOutboxState::Delivered,
            transition.observed_at,
            Some(transition.observed_at),
            None,
        ),
        FederationOutboxOutcome::CancelledAuthorityLost => (
            FederationOutboxState::CancelledAuthorityLost,
            transition.observed_at,
            Some(transition.observed_at),
            None,
        ),
        FederationOutboxOutcome::PolicySuppressed { policy_version } => (
            FederationOutboxState::PolicySuppressed,
            transition.observed_at,
            Some(transition.observed_at),
            Some(policy_version.clone()),
        ),
        FederationOutboxOutcome::DeadLettered(_) => (
            FederationOutboxState::DeadLettered,
            transition.observed_at,
            Some(transition.observed_at),
            None,
        ),
        FederationOutboxOutcome::Superseded(_) => (
            FederationOutboxState::Superseded,
            transition.observed_at,
            Some(transition.observed_at),
            None,
        ),
    };

    Ok(FederationOutboxCompletion {
        state,
        next_attempt_at,
        completed_at,
        policy_version,
    })
}

/// Verdict of one `policy_suppressed` revalidation.
#[derive(Clone, Debug)]
pub enum FederationOutboxPolicyResolution {
    /// Revalidation passed under the new policy — return the row to `pending`.
    Release { next_attempt_at: i64 },
    /// Still denied. Pin the current policy version so the sweep stops
    /// re-checking this row until the policy changes again.
    Repin { policy_version: String },
}

/// Operator replay of one dead letter (`sync/federation.md` §8.5: a response
/// was received, so re-evaluation MUST use a new key).
#[derive(Clone, Debug)]
pub struct FederationOutboxRequeue {
    pub dead_letter_id: String,
    /// Fresh pending row with a new id, a new `Idempotency-Key` and
    /// `supersedes_outbox_id` pointing at the dead-lettered row.
    pub record: FederationOutboxRecord,
    pub operator: String,
    pub reason: String,
    pub request_digest: String,
    pub requeued_at: i64,
}

/// G3.S0 — durable outbound federation HTTP delivery queue.
///
/// Rows are inserted inside the same transaction that accepts the Event; the
/// `FederationDispatcher` background worker
/// (`routing::federation::outbox::FederationDispatcher`) claims due rows under
/// a lease and posts them to peers.
///
/// Idempotency: `(peer_id, idempotency_key)` is UNIQUE. Callers that
/// re-enqueue the same logical request MUST see `enqueue` return `Ok(false)`
/// rather than a duplicate-row error; the worker treats the existing row as
/// the authoritative delivery state.
#[async_trait]
pub trait FederationOutboxStore: Send + Sync {
    /// Historical content destinations, including transport-uncertain sends.
    /// Membership loss and later terminal Events do not revoke receipt duties.
    async fn historical_content_holders(
        &self,
        realm_ids: &[arkret_wire::RealmId],
    ) -> PersistenceResult<Vec<DidCoreId>>;
    async fn historical_content_holders_for_actor(
        &self,
        actor: &arkret_wire::ActorId,
    ) -> PersistenceResult<Vec<DidCoreId>>;
    async fn erasure_receipt_deliveries(
        &self,
        receipt_id: &str,
    ) -> PersistenceResult<Vec<FederationOutboxRecord>>;
    async fn erasure_receipt_feedback(
        &self,
        receipt: &arkret_models_collaboration::governance::erasure::ErasureReceipt,
    ) -> PersistenceResult<
        Vec<(
            arkret_models_collaboration::governance::erasure::ErasureReceiptPackage,
            chrono::DateTime<chrono::Utc>,
        )>,
    >;
    /// Insert a new outbox row. Returns `Ok(true)` if a fresh row was
    /// stored, `Ok(false)` if `(peer_id, idempotency_key)` already
    /// exists (callers MUST treat that as "already enqueued" rather
    /// than an error — see trait-doc idempotency note).
    async fn enqueue(&self, record: &FederationOutboxRecord) -> PersistenceResult<bool>;
    /// Atomically claim up to `limit` rows in `pending` or `pending_route`
    /// state whose
    /// `next_attempt_at <= now`, plus rows whose `leased` state has an expired
    /// lease, ordered by `next_attempt_at` ascending. Implementations MUST
    /// stamp `lease_owner` / `lease_token` / `lease_expires_at` and move the
    /// rows to `leased` in the same statement that selects them, so two
    /// replicas never claim the same row.
    async fn claim_due(
        &self,
        claim: &FederationOutboxClaim,
    ) -> PersistenceResult<Vec<FederationOutboxRecord>>;
    /// Apply one delivery attempt's result. Returns `Ok(false)` when the lease
    /// token no longer matches, i.e. the caller is a stale holder whose write
    /// MUST be dropped. Terminal transitions and their dead-letter or successor
    /// rows commit together or not at all.
    async fn complete(&self, transition: &FederationOutboxTransition) -> PersistenceResult<bool>;
    /// Rows currently parked in `policy_suppressed` whose recorded
    /// `policy_version` differs from `current_policy_version`. Those are the
    /// only candidates for revalidation; a bare restart never re-opens a row
    /// the still-current policy denied.
    async fn policy_suppressed_stale(
        &self,
        current_policy_version: &str,
        limit: usize,
    ) -> PersistenceResult<Vec<FederationOutboxRecord>>;
    /// Apply the revalidation verdict to one `policy_suppressed` row. Returns
    /// `Ok(false)` when the row left `policy_suppressed` meanwhile.
    async fn resolve_policy_suppressed(
        &self,
        id: &str,
        resolution: &FederationOutboxPolicyResolution,
    ) -> PersistenceResult<bool>;
    /// Fetch a single row by primary key.
    async fn get(&self, id: &str) -> PersistenceResult<Option<FederationOutboxRecord>>;
    /// Snapshot the full table — diagnostics + the integration test
    /// rely on it. Production deployments SHOULD NOT call this on a
    /// large outbox; use `claim_due` instead.
    async fn snapshot_all(&self) -> PersistenceResult<Vec<FederationOutboxRecord>>;
    /// Rows in one lifecycle state, newest first, for the operator surfaces.
    async fn list_by_state(
        &self,
        state: FederationOutboxState,
        limit: usize,
    ) -> PersistenceResult<Vec<FederationOutboxRecord>>;
    /// Aggregate depth per `(state, peer_id)` for the gauge exporter.
    async fn state_depth(&self) -> PersistenceResult<Vec<FederationOutboxStateDepth>>;
    async fn dead_letter(
        &self,
        id: &str,
    ) -> PersistenceResult<Option<FederationOutboxDeadLetterRecord>>;
    async fn dead_letters_snapshot(
        &self,
    ) -> PersistenceResult<Vec<FederationOutboxDeadLetterRecord>>;
    /// Insert the replay row and stamp the operator audit onto the dead letter
    /// in one transaction. Returns `Ok(false)` when the dead letter is missing
    /// or was already requeued.
    async fn requeue_dead_letter(
        &self,
        command: &FederationOutboxRequeue,
    ) -> PersistenceResult<bool>;
}

/// One `(state, peer_id)` bucket of the outbox depth gauge.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FederationOutboxStateDepth {
    pub state: FederationOutboxState,
    pub peer_id: DidCoreId,
    pub depth: i64,
    /// Unix seconds of the oldest row in this bucket, for the pending-age
    /// alert. `None` when the bucket is empty.
    pub oldest_created_at: Option<i64>,
}
#[cfg(test)]
#[path = "federation/tests.rs"]
mod tests;

/// Replay log of federation operations the local service has accepted from
/// peers (and emitted itself). Currently in-memory but the trait shape is
/// what the durable Pg implementation will follow.
#[async_trait]
pub trait FederationOperationsStore: Send + Sync {
    async fn append(&self, operation: ProjectedEventOperation) -> PersistenceResult<()>;
    async fn contains(&self, operation_id: &str) -> PersistenceResult<bool>;
    async fn list_for_realm(
        &self,
        realm_id: &str,
    ) -> PersistenceResult<Vec<ProjectedEventOperation>>;
    async fn snapshot_all(&self) -> PersistenceResult<Vec<ProjectedEventOperation>>;
}
