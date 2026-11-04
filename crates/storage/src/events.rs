use super::{
    CanonicalEventRecord, DirectConversationFoundingSlotRecord, FederationOutboxRecord,
    MessageRecord, PersistenceResult, async_trait,
};

/// Trait for message storage operations.
#[async_trait]
pub trait MessageStore: Send + Sync {
    async fn get(&self, event_id: &str) -> PersistenceResult<Option<MessageRecord>>;
    async fn put(&self, record: &MessageRecord) -> PersistenceResult<()>;
    async fn list_for_realm(
        &self,
        realm_id: &str,
        limit: usize,
    ) -> PersistenceResult<Vec<MessageRecord>>;
    async fn list_for_thread(
        &self,
        thread_id: &str,
        limit: usize,
    ) -> PersistenceResult<Vec<MessageRecord>>;
    async fn delete(&self, event_id: &str) -> PersistenceResult<()>;
}
/// Canonical Event log keyed by the 33-byte Event id, which losslessly encodes
/// the full `(digest_suite, digest)` identity. Implementations must never
/// overwrite a row when identical digest bytes bind different digest-preimage
/// canonical bytes. Envelope-only proof/unsigned differences are not hash
/// collisions and must be handled by producer proof validation.
#[async_trait]
pub trait EventStore: Send + Sync {
    /// Durable fanout intents atomically associated with one accepted Event.
    /// The join is authoritative for batch rows that cover multiple Events.
    async fn federation_outbox_for_event(
        &self,
        event_id: &str,
    ) -> PersistenceResult<Vec<FederationOutboxRecord>>;
    async fn direct_conversation_founding_slot(
        &self,
        founder_id: &str,
        trust_domain_id: &str,
        pair_key: &str,
    ) -> PersistenceResult<Option<DirectConversationFoundingSlotRecord>>;
    async fn direct_conversation_durable_state(
        &self,
        trust_domain_id: &str,
        pair_key: &str,
    ) -> PersistenceResult<Option<crate::DirectConversationDurableState>>;
    async fn direct_conversation_durable_state_for_realm(
        &self,
        realm_id: &str,
    ) -> PersistenceResult<Option<crate::DirectConversationDurableState>>;
    async fn foreign_direct_mls_input(
        &self,
        _realm: &arkret_wire::RealmId,
        _caller: &arkret_wire::ActorId,
    ) -> PersistenceResult<Option<crate::ForeignDirectMlsInput>> {
        Ok(None)
    }
    /// Publish public replay facts only if the same verified cut is still current.
    async fn install_foreign_direct_mls_public_state(
        &self,
        _input: &crate::ForeignDirectMlsInput,
        _result: &crate::ForeignDirectMlsBase,
        _exact_pair: bool,
    ) -> PersistenceResult<bool> {
        Ok(false)
    }
    /// Accepted identity-anchor binding for one exact protocol Account.
    /// This is service-internal authority evidence and is never projected to
    /// holder sync as AccountData.
    async fn identity_anchor_account_slot(
        &self,
        account_id: &arkret_wire::AccountId,
    ) -> PersistenceResult<Option<IdentityAnchorAccountSlot>>;
    async fn get(&self, event_id: &str) -> PersistenceResult<Option<CanonicalEventRecord>>;
    async fn contains(&self, event_id: &str) -> PersistenceResult<bool>;
    async fn list_for_actor(&self, actor_id: &str) -> PersistenceResult<Vec<CanonicalEventRecord>>;
    async fn snapshot_all(&self) -> PersistenceResult<Vec<CanonicalEventRecord>>;
    /// Cheap Realm-local cardinality/byte preflight for bounded proof
    /// materialization. Implementations must not load Event envelopes.
    async fn realm_event_stats(&self, realm_id: &str) -> PersistenceResult<RealmEventStats>;
    /// Events for a single Realm, newest first. Pushes the `realm_id` filter
    /// and `received_at DESC` ordering into the query so hot-path latest-policy
    /// lookups do not full-scan the whole `canonical_events` table.
    async fn realm_events_newest_first(
        &self,
        realm_id: &str,
    ) -> PersistenceResult<Vec<CanonicalEventRecord>>;
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RealmEventStats {
    pub count: u64,
    pub canonical_bytes: u64,
}
/// Durable account-scoped create-once slot for a principal-control Realm.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdentityAnchorAccountSlot {
    pub account_authority_id: String,
    pub account_subject: String,
    pub account_id: arkret_wire::AccountId,
    pub realm_id: String,
    pub create_event_id: String,
}
