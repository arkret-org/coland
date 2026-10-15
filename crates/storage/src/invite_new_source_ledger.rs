use arkret_wire::AccountId;
use arkret_wire::receive_policy::EffectiveNewSourceQuota;

use super::{PersistenceResult, Utc, async_trait};

/// Outcome of one admission evaluation at the quarantine chokepoint
/// (`identity/consent-model.md` section 6.1.1.3).
///
/// The three arms are the whole decision space: a source already on the ledger
/// is not charged again, a source under both ceilings is charged once, and a
/// source over either ceiling is dropped without touching the ledger. The
/// caller never sees the counts, so it cannot reconstruct a distinguishable
/// outcome for the requester.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NewSourceAdmission {
    /// Already admitted inside the retention window. Proceed to the cell write
    /// without a ledger write, and without refreshing `first_admitted_at`.
    Seen,
    /// First contact inside both ceilings. `(source, now)` was appended.
    Admitted,
    /// Over the sliding rate window or over the retention-window total. The
    /// caller MUST silently drop: no ledger write, no cell write, and the same
    /// opaque `deferred` outcome as every other member of the equivalence class.
    Denied,
}

/// Durable server-internal seen-source ledger backing the per-holder new-source
/// quota (`identity/consent-model.md` section 6.1.1.4).
///
/// This state deliberately has no wire carrier: it is not an account-data cell,
/// no DTO projects it, and no operation reads it. The holder's only observable
/// surface stays the quarantine cell itself, which is what keeps the five-way
/// indistinguishable equivalence class of section 6.1.1 intact.
///
/// `source_digest` is a keyed digest of the peer principal, not the principal
/// itself: membership testing only needs equality, so the ledger never has to
/// store a readable list of every stranger who contacted a holder.
#[async_trait]
pub trait InviteNewSourceLedgerStore: Send + Sync {
    /// Read the immutable holder key and derive a tag without creating state.
    /// No signing-key rotation or authority handoff may replace this key.
    async fn source_digest(
        &self,
        _holder: &AccountId,
        _source: &arkret_wire::DidCoreId,
    ) -> PersistenceResult<String> {
        Err(crate::PersistenceError::Conflict(
            "temporarily_unavailable: holder quota key unavailable".into(),
        ))
    }

    /// Prune expired rows, test membership, count both sliding windows and
    /// append on admission -- linearized per holder, as one step.
    ///
    /// Splitting this into separate read and write calls would let two
    /// concurrent first contacts both observe an under-quota ledger and both be
    /// admitted, so the whole decision belongs to the store.
    async fn admit_new_source(
        &self,
        holder: &AccountId,
        source_digest: &str,
        now: chrono::DateTime<Utc>,
        quota: &EffectiveNewSourceQuota,
    ) -> PersistenceResult<NewSourceAdmission>;

    /// Drop the holder's entire ledger. Account erasure MUST call this;
    /// consent revoke and source allow/deny list edits MUST NOT, because
    /// anti-abuse admission state is separate from consent state.
    async fn delete_for_holder(&self, holder: &AccountId) -> PersistenceResult<()>;

    /// Rows currently retained for one holder. Test-only observability for the
    /// erasure and retention contracts; it is not reachable from any wire path.
    async fn retained_source_count(&self, holder: &AccountId) -> PersistenceResult<usize>;
}
