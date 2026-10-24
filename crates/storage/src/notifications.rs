use std::collections::{BTreeMap, BTreeSet};

use arkret_models_collaboration::objects::read_receipts::Notification;
use arkret_models_collaboration::sync_frames::account_subscribe::NotificationDelta;
use arkret_wire::events::EventKind;
use arkret_wire::{ActorId, CircleId, DidCoreId, RealmId, StrandId};

use super::{AccountPk, PersistenceResult, async_trait};

#[derive(Clone, Debug, PartialEq)]
pub struct RecipientNotificationRecord {
    pub notification: Notification,
    pub event_kind: EventKind,
    pub source_actor_id: Option<ActorId>,
}

#[derive(Clone, Debug)]
pub struct AccountNotificationDeltaWrite {
    pub delta: NotificationDelta,
    pub recipient_actor_id: ActorId,
    pub controller_account_pk: AccountPk,
    pub recipient_id: DidCoreId,
    pub source_account_artifact_id: String,
}

#[derive(Clone, Debug)]
pub struct StoredAccountNotificationDelta {
    pub record: AccountNotificationDeltaWrite,
    pub projection_position: i64,
}

/// The accepted current facts an ordinary source-Event notification fanout
/// is decided from (private-objects.md sections 3.3-3.6,
/// push-notifications.md section 4.3.2).
///
/// Every field is read from the registered typed current results after the
/// source Event's Commit, never from a process-local reducer projection.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NotificationFanoutBasis {
    /// Effectively joined Realm members. An Agent member counts only while
    /// its controller binding names the controller's current join.
    pub joined_members: BTreeSet<ActorId>,
    /// The Strand's current scope, absent when it has no current value.
    pub strand: Option<NotificationStrandScope>,
    /// Explicit watch levels on the Strand in this Realm; a cleared watch is
    /// absent.
    pub watch_levels: BTreeMap<ActorId, String>,
    /// The `to_ref` actors of the Strand's active `assigned_to` Relations.
    pub active_assignees: BTreeSet<ActorId>,
}

/// The current scope of the Strand a notification source Event names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NotificationStrandScope {
    pub realm_id: RealmId,
    /// Whether the Strand's current lifecycle state is `active`.
    pub active: bool,
    pub scope_circle_id: Option<CircleId>,
    /// Joined members of the scope Circle while that Circle is active; empty
    /// for a Realm-scope Strand.
    pub circle_members: BTreeSet<ActorId>,
}

/// AKP-0016 §9.4.5 — per-recipient notification projection (mention
/// fanout output). Agents are gated by their effective
/// third_party_mention_delivery_allowed bit before a row is written here.
#[async_trait]
pub trait NotificationStore: Send + Sync {
    async fn put(&self, record: RecipientNotificationRecord) -> PersistenceResult<()>;
    async fn put_account_delta(
        &self,
        record: AccountNotificationDeltaWrite,
    ) -> PersistenceResult<()>;
    async fn list_for_recipient(
        &self,
        recipient_id: &str,
    ) -> PersistenceResult<Vec<RecipientNotificationRecord>>;
    async fn list_for_account(
        &self,
        controller_account_pk: &AccountPk,
        recipient_id: &str,
        after_position: Option<i64>,
    ) -> PersistenceResult<Vec<StoredAccountNotificationDelta>>;
    /// Read one consistent current cut of the facts a committed source
    /// Event's notification fanout needs.
    async fn fanout_basis(
        &self,
        realm_id: &RealmId,
        strand_id: Option<&StrandId>,
    ) -> PersistenceResult<NotificationFanoutBasis>;
}
