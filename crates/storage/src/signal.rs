use super::{PersistenceResult, SignalRelayRecord, async_trait};

/// Live relay for admitted `SignalEnvelope`s (`sync/signal.md` §4).
///
/// A Signal is not durable: records are held only until `expires_at`, produce
/// no Event id and advance no authority Commit. `position` is an internal
/// per-Realm dedupe watermark, never a wire cursor. Each live subscription
/// starts after its admitted relay head; reconnects do not recover a gap.
#[async_trait]
pub trait SignalRelayStore: Send + Sync {
    /// Atomically suppress exact replay before allocating relay progress.
    /// Only the winning insertion returns true and may wake or relay.
    async fn append(&self, record: SignalRelayRecord) -> PersistenceResult<bool>;
    /// Every non-expired Signal of the Realm, ascending by `position`.
    /// Scope eligibility is decided by the caller, which holds the accepted
    /// membership projection.
    async fn list_for_realm(&self, realm_id: &str) -> PersistenceResult<Vec<SignalRelayRecord>>;
    async fn prune_expired(&self) -> PersistenceResult<usize>;
    /// Highest per-Realm `position` already delivered to `(actor, device,
    /// realm)`. Returns `0` when nothing has been delivered yet.
    async fn delivered_through(
        &self,
        actor: &str,
        device: &str,
        realm_id: &str,
    ) -> PersistenceResult<u64>;
    /// Advance the `(actor, device, realm)` watermark to `position` (monotonic;
    /// a lower value is ignored).
    async fn advance(
        &self,
        account: &arkret_wire::AccountId,
        device: &str,
        realm_id: &str,
        position: u64,
    ) -> PersistenceResult<()>;
}

/// Per-Realm cap on retained Signals, bounding memory under a burst. Signals
/// are short-lived (≤120 s TTL) so the bound only matters transiently; the
/// oldest entries are dropped first.
pub const SIGNAL_RELAY_MAX_PER_REALM: usize = 512;
