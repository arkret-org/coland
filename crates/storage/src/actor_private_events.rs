//! `ak.self.actor_private_events.command.submit.v1` storage
//! (actor-private-effects.md §2.1): the four caller-signed actor-private
//! kinds without a dedicated operation are admitted into their owner's
//! account-private store in one private transaction. No RealmCommit covers
//! them and nothing here reads or writes a Realm stream.

use arkret_models_collaboration::events_payloads::agent::{
    AgentActionRejectPayload, AgentActionRequestPayload,
};
use arkret_models_identity::device_push_route::DevicePushRoutePayload;
use arkret_wire::{AccountId, ActorPrivateEventSubmitResponseBody, Event};
use async_trait::async_trait;
use chrono::{DateTime, Utc};

use crate::{AgentDraftPendingIntentCommit, PersistenceResult, SelfProducerCommitGuard};

/// The registered private effect of one submitted Event, already decoded
/// from its signed payload and bound to the owner selected by the kind's
/// `storage_owner.account_id_source`.
#[derive(Clone, Debug)]
pub enum ActorPrivateEventEffect {
    /// `ak.private.device.push_route.v1`: `server_revision_cas` whole value.
    DevicePushRoute(DevicePushRoutePayload),
    /// `ak.private.agent.action_request.v1`: create-once pending request.
    AgentActionRequest(AgentActionRequestPayload),
    /// `ak.private.agent.rejection.v1`: create-once rejection that terminates
    /// the one named action request of the same controller and Agent.
    AgentActionReject {
        payload: AgentActionRejectPayload,
        request_id: String,
    },
    /// `ak.private.agent.draft_pending_intent.v1`: create-once available
    /// pending intent.
    AgentDraftPropose(AgentDraftPendingIntentCommit),
}

/// One producer-verified actor-private Event ready for its private
/// transaction.
#[derive(Clone, Debug)]
pub struct ActorPrivateEventSubmission {
    /// The exact signed Event, stored in the actor-private ledger.
    pub event: Event,
    /// SHA-256 of the complete canonical Event bytes; with the Event id, the
    /// exact-retry identity.
    pub canonical_event_digest: Vec<u8>,
    /// The Account selected by the kind's `storage_owner.account_id_source`,
    /// already proved to belong to this Station.
    pub owner: AccountId,
    pub effect: ActorPrivateEventEffect,
    /// The producer authorization pinned by the preflight and rechecked in the
    /// private transaction. Only a storage fixture without a PCR device omits
    /// it.
    pub producer_guard: Option<SelfProducerCommitGuard>,
    /// Station protocol time of this admission; expiry is judged against it.
    pub accepted_at: DateTime<Utc>,
}

/// The first saved outcome of a submission, or why it wrote nothing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ActorPrivateEventSubmitResult {
    Accepted(ActorPrivateEventSubmitResponseBody),
    /// The byte-identical Event was already accepted; its first outcome is
    /// returned without another write.
    Replayed(ActorPrivateEventSubmitResponseBody),
    Refused(ActorPrivateEventRefusal),
}

/// The write-before `rejection.conditions` decided inside the transaction.
/// Every refusal writes nothing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActorPrivateEventRefusal {
    /// The Event identity or an occupied create-once key carries other bytes.
    DuplicateConflict(&'static str),
    /// `expected_server_revision` differs from the stored route revision.
    CasConflict,
    /// A rejection target is missing, terminal or not rejectable, or a
    /// proposal or request is already expired.
    FailedPrecondition(&'static str),
}

/// Account-private effects of the generic actor-private submit operation and
/// their exact-retry ledger.
#[async_trait]
pub trait ActorPrivateEventStore: Send + Sync {
    async fn submit(
        &self,
        submission: &ActorPrivateEventSubmission,
    ) -> PersistenceResult<ActorPrivateEventSubmitResult>;
}
