use arkret_models_collaboration::objects::read_receipts::{ReadCursor, ReadMarkerResponseBody};
use arkret_wire::{AccountId, DidCoreId, Event, RealmId};
use async_trait::async_trait;
use chrono::{DateTime, Utc};

use crate::{PersistenceResult, SelfProducerCommitGuard};

/// One producer-verified `ak.read_cursor.advance` ready for the
/// `ak.private.read_cursor.v1` actor-private effect
/// (actor-private-effects.md §3.4).
///
/// The effect is owned by `payload.actor_id.account_id` at its Station and is
/// never a Realm current result: nothing here takes or reads a RealmCommit as
/// the cursor's own head. The position Event's accepted Commit is read only to
/// decide causal dominance and caller visibility.
#[derive(Clone, Debug)]
pub struct ReadCursorAdvance {
    /// The verified advance Event, kept for the in-transaction producer guard.
    pub event: Event,
    /// SHA-256 of the complete canonical Event bytes, the exact retry identity
    /// together with `event.event_id`.
    pub canonical_event_digest: Vec<u8>,
    /// The decoded payload; its actor, device and Realm are already bound to
    /// the envelope and the authenticated session.
    pub cursor: ReadCursor,
    /// The owning Account, `payload.actor_id.account_id`.
    pub owner: AccountId,
    /// The producer authorization pinned by the preflight and rechecked in the
    /// winner transaction. The self operation always pins one; only a storage
    /// fixture without a PCR device omits it.
    pub producer_guard: Option<SelfProducerCommitGuard>,
    /// This Station; only a Realm it currently governs holds a provable
    /// committed history to classify the position against.
    pub station_id: DidCoreId,
    pub accepted_at: DateTime<Utc>,
}

/// The first saved outcome of an advance, or why it was refused.
#[derive(Clone, Debug)]
pub enum ReadCursorAdvanceOutcome {
    /// A new candidate was classified. `candidate_won` is false for an
    /// accepted loser, which leaves the durable winner untouched.
    Accepted {
        marker: ReadMarkerResponseBody,
        candidate_won: bool,
    },
    /// The byte-identical Event was already accepted; its first outcome is
    /// returned without another write or device fanout.
    Replayed(ReadMarkerResponseBody),
    /// A write-before condition failed; nothing was written.
    Refused(ReadCursorAdvanceRefusal),
}

/// The `rejection.conditions` of the `ak.read_cursor.advance` contract, as
/// this Station can decide them.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReadCursorAdvanceRefusal {
    /// The same Event identity was accepted with different canonical bytes.
    DuplicateConflict,
    /// The owner is not a joined member of the Realm at this cut.
    NotMember,
    /// The position names no committed Event of the Realm.
    PositionNotInRealm,
    /// The position is a committed Event of the Realm before the owner's
    /// current join Commit, outside the owner's readable interval.
    PositionNotReadable,
    /// This Station cannot prove the position's visibility to the owner or
    /// its causal relation to the current winner; the candidate stays
    /// provisional and must not change the durable winner.
    Unproved(&'static str),
}

/// Account-private read cursor winners and the exact-retry ledger.
#[async_trait]
pub trait ReadCursorStore: Send + Sync {
    /// Classify and, when it wins, store one candidate in a single private
    /// transaction. A producer guard failure is an error with its device code.
    async fn advance(
        &self,
        advance: &ReadCursorAdvance,
    ) -> PersistenceResult<ReadCursorAdvanceOutcome>;

    /// The owner's current winners, ordered by Realm then canonical scope.
    async fn list(
        &self,
        owner: &AccountId,
        realm_id: Option<&RealmId>,
    ) -> PersistenceResult<Vec<ReadMarkerResponseBody>>;
}
