use arkret_wire::AccountId;

use super::{
    AccountDataCasResult, AccountDataChangeRecord, AccountDataRecord, AccountLifecycleRecord,
    AccountLocalpartRecord, AccountPk, AccountRecord, PersistenceResult, async_trait,
};
/// Trait for account storage operations.
#[async_trait]
pub trait AccountStore: Send + Sync {
    async fn get(&self, account_id: &AccountId) -> PersistenceResult<Option<AccountRecord>>;
    async fn get_by_pk(&self, account_pk: AccountPk) -> PersistenceResult<Option<AccountRecord>>;
    async fn put(&self, record: &AccountRecord) -> PersistenceResult<AccountPk>;
    async fn list(&self) -> PersistenceResult<Vec<AccountRecord>>;
    async fn delete(&self, account_id: &AccountId) -> PersistenceResult<()>;
}
#[async_trait]
pub trait AccountLocalpartStore: Send + Sync {
    async fn list_for_account(
        &self,
        account_pk: AccountPk,
    ) -> PersistenceResult<Vec<AccountLocalpartRecord>>;
    async fn owner_of(&self, localpart: &str) -> PersistenceResult<Option<AccountLocalpartRecord>>;
    async fn add(
        &self,
        account_pk: AccountPk,
        localpart: &str,
        primary: bool,
    ) -> PersistenceResult<AccountLocalpartRecord>;
    /// Removes the exact `(account_pk, localpart)` association. Absence is
    /// idempotent, while a localpart assigned to another Account is a conflict.
    async fn remove(&self, account_pk: AccountPk, localpart: &str) -> PersistenceResult<()>;
    async fn clear_for_account(&self, account_pk: AccountPk) -> PersistenceResult<()>;
}
#[async_trait]
pub trait AccountLifecycleStore: Send + Sync {
    async fn put(
        &self,
        account_pk: AccountPk,
        record: &AccountLifecycleRecord,
    ) -> PersistenceResult<()>;
    async fn delete(&self, account_pk: AccountPk) -> PersistenceResult<()>;
    async fn snapshot_all(&self) -> PersistenceResult<Vec<(AccountId, AccountLifecycleRecord)>>;
}
/// One producer-verified actor-private account-data Event and the holder CAS
/// it asks for.
#[derive(Clone, Debug)]
pub struct ActorPrivateAccountDataAdmission {
    pub event: arkret_wire::Event,
    /// SHA-256 of the complete canonical Event bytes.
    pub canonical_event_digest: Vec<u8>,
    pub cas: crate::AccountDataCasCommit,
    /// The producer authorization pinned by the preflight; only a storage
    /// fixture without a PCR device omits it.
    pub producer_guard: Option<crate::SelfProducerCommitGuard>,
    pub accepted_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActorPrivateAccountDataOutcome {
    /// The CAS succeeded and the value was published to the holder.
    Applied,
    /// The byte-identical Event was already accepted; nothing was written.
    Replayed,
}

/// Trait for actor-private account data storage.
///
/// `account_data_key` is the canonical wire key (e.g. `ak.contacts.actor.<did>`,
/// `ak.contacts.realm.<realm_id>`, `ak.read_receipt.preferences`). The
/// payload is opaque to the server — no schema validation runs here; the
/// client owns canonical encoding and (where applicable) encryption.
///
/// Spec: `discovery/client-preferences.md` §2 (storage model), §3.6
/// (actor remarks), §3.7 (Realm remarks).
#[async_trait]
pub trait AccountDataStore: Send + Sync {
    async fn get(
        &self,
        actor: &str,
        account_data_key: &str,
    ) -> PersistenceResult<Option<AccountDataRecord>>;
    /// Atomically replace the whole value when the stored revision equals
    /// `expected_revision`. An absent key has revision 0.
    async fn compare_and_set(
        &self,
        record: &AccountDataRecord,
        expected_revision: u64,
    ) -> PersistenceResult<AccountDataCasResult>;
    /// Admit one producer-verified actor-private `ak.account_data.set` Event
    /// (actor-private-effects.md section 3.1) in one private transaction: an
    /// exact retry of the same Event bytes returns `Replayed` before any other
    /// check, the same Event identity with
    /// other bytes is `duplicate_conflict`, the producer guard is rechecked,
    /// and the Event is recorded in the actor-private ledger together with the
    /// holder CAS and its account sync publication. A CAS mismatch is
    /// `cas_conflict`. No RealmCommit is involved and every refusal writes
    /// nothing.
    async fn admit_actor_private_event(
        &self,
        admission: &ActorPrivateAccountDataAdmission,
    ) -> PersistenceResult<ActorPrivateAccountDataOutcome>;
    async fn list_for_actor(&self, actor: &str) -> PersistenceResult<Vec<AccountDataRecord>>;
    async fn changes_after(
        &self,
        actor: &str,
        position: u64,
    ) -> PersistenceResult<Vec<AccountDataChangeRecord>>;
    async fn snapshot_for_actor(
        &self,
        actor: &str,
    ) -> PersistenceResult<(Vec<AccountDataRecord>, u64)>;
    async fn latest_change_position(&self, actor: &str) -> PersistenceResult<u64>;
    /// Returns whether every Account Data change after `position` is still replayable.
    ///
    /// A false result requires an initial resync; advancing a cursor across the
    /// retained boundary would silently omit holder-private state.
    async fn change_position_is_replayable(
        &self,
        actor: &str,
        position: u64,
    ) -> PersistenceResult<bool>;
    /// Removes change records older than `cutoff` while durably preserving the
    /// per-actor replay boundary and current projection high-water mark.
    async fn prune_changes_before(
        &self,
        cutoff: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<u64>;
}
#[doc(hidden)]
pub fn account_with_primary_localpart_select(where_clause: &str) -> String {
    format!(
        "SELECT a.pk, a.principal_id, a.station_id, COALESCE(lp.localpart, '') AS localpart, \
         a.display_name, a.payload, a.created_at \
         FROM accounts a \
         LEFT JOIN LATERAL ( \
             SELECT localpart FROM account_localparts \
             WHERE account_pk = a.pk \
             ORDER BY is_primary DESC, created_at ASC, localpart ASC \
             LIMIT 1 \
         ) lp ON true \
         {where_clause}"
    )
}
