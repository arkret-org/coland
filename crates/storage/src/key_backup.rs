/// Storage key for an ordered backup metadata page; never exposed in cursor wire bytes.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyBackupListPosition {
    pub backup_kind: String,
    pub series_id: String,
    pub series_sequence: i64,
    pub backup_id: String,
}

#[derive(Clone, Debug)]
pub struct KeyBackupListQuery {
    pub actor_id: String,
    pub backup_kind: Option<String>,
    pub series_id: Option<String>,
    pub after: Option<KeyBackupListPosition>,
    pub limit: u32,
}

#[derive(Clone, Debug)]
pub struct KeyBackupListPage {
    pub revision: i64,
    pub byte_limited: bool,
    pub payloads: Vec<serde_json::Value>,
}

#[derive(Clone, Debug)]
pub struct ConfirmedKeyBackupListPage {
    pub active_series: arkret_models_crypto::BackupActiveSeriesState,
    pub page: KeyBackupListPage,
}

/// One self-authored `ak.key_backup.active_series` Event together with the
/// RealmCommit the governance Station signed for it on the PCR stream. The
/// storage unit rechecks the signing device, generation, source checkpoint,
/// record signature and pointer CAS at the locked PCR cut before any write.
#[derive(Clone, Debug)]
pub struct KeyBackupActiveSeriesCommitWrite {
    pub commit: crate::AuthorityCommitTransaction,
    pub queued_at: chrono::DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum KeyBackupActiveSeriesCommitOutcome {
    Committed(arkret_wire::RealmCommit),
    /// The exact same Event and Commit were already accepted by this unit.
    Duplicate(arkret_wire::RealmCommit),
}

use super::{PersistenceResult, Utc, Value, async_trait};

/// A server-issued key-backup delete challenge
/// (`key-management.md` §7.8.1,
/// `keys-operations.schema.json#/$defs/keys_backups_delete_challenge`).
///
/// `challenge` holds the whole serialized challenge so the wire shape keeps one
/// definition (the SDK type) instead of a column per member; the columns beside
/// it are exactly the ones the two lookups need — by `challenge_id` to verify a
/// DELETE, and by `(account_id, backup_id, request_id)` to re-issue the same
/// challenge while it is still valid.
///
/// `consumed_at` is what makes the challenge single-use. It is set in the same
/// transaction as the delete it authorizes, so a replay finds it consumed.
#[derive(Clone, Debug, PartialEq)]
pub struct KeyBackupDeleteChallengeRecord {
    pub challenge_id: String,
    pub account_id: arkret_wire::AccountId,
    pub backup_id: String,
    pub request_id: String,
    pub challenge: Value,
    pub issued_at: chrono::DateTime<Utc>,
    pub expires_at: chrono::DateTime<Utc>,
    pub consumed_at: Option<chrono::DateTime<Utc>>,
}

/// The confirmed `secret_storage` pointer a current-device unlock or a delete
/// was authorized against (key-management.md §7.6). The consuming
/// transaction rereads the pointer and every named device at its own PCR cut:
/// a changed pointer or a device that is no longer active refuses, while a
/// later unrelated PCR Commit does not by itself stale the request.
#[derive(Clone, Debug, PartialEq)]
pub struct KeyBackupPointerBasis {
    pub account_id: arkret_wire::AccountId,
    pub secret_storage: arkret_models_crypto::BackupActiveSeriesPointer,
}

/// Internal same-cut authority basis for a confirmed active-series read.
/// `state` is the public projection while `committed_ref` is the exact PCR
/// head Event/Commit/stream tuple against which a destructive manifest was
/// frozen.
#[derive(Clone, Debug, PartialEq)]
pub struct ConfirmedKeyBackupAuthorityBasis {
    pub state: arkret_models_crypto::BackupActiveSeriesState,
    pub committed_ref: arkret_wire::CommittedEventRef,
}

/// The authority a backup unlock consumes, rechecked in the consuming
/// transaction.
#[derive(Clone, Debug, PartialEq)]
pub enum KeyBackupUnlockBasis {
    /// An ordinary unlock by the requesting device: the pointer must be
    /// unchanged, the device active, and the envelope in the active series
    /// under the current generation.
    CurrentDevice {
        basis: KeyBackupPointerBasis,
        device_id: arkret_wire::DeviceId,
    },
    /// A verified recovery session: the manifest frozen at verification is
    /// the basis, and the session and its policy are rechecked.
    RecoverySession,
}

/// Frozen unlock inputs consumed together under the original transaction guards.
#[derive(Debug)]
pub struct KeyBackupUnlockCommand<'a> {
    pub basis: &'a KeyBackupUnlockBasis,
    pub authority_id: &'a str,
    pub backup: Value,
    pub request_digest: &'a str,
    pub holder: &'a str,
    pub ip: &'a str,
    pub now: chrono::DateTime<Utc>,
    pub daily_limit: u32,
}

/// Frozen authorization inputs rechecked inside the destructive transaction.
#[derive(Clone, Debug)]
pub struct KeyBackupDeleteGate {
    pub basis: KeyBackupPointerBasis,
    pub quorum_devices: Vec<arkret_wire::DeviceId>,
    pub expected_policy: Option<Value>,
    pub replay: crate::IdempotencyRecord,
}

/// Encrypted key-backup envelopes (one row per `backup_id`), plus the durable
/// delete-challenge ledger the high-risk DELETE path consumes.
#[async_trait]
pub trait KeyBackupStore: Send + Sync {
    /// Resolve the PCR Realm head and the secret-storage pointer from one
    /// confirmed database cut. `None` means the PCR/current authority could
    /// not be established; it must never be mapped to `Absent` by a caller.
    async fn confirmed_active_series(
        &self,
        account_id: &arkret_wire::AccountId,
    ) -> PersistenceResult<Option<arkret_models_crypto::BackupActiveSeriesState>>;
    async fn confirmed_active_series_basis(
        &self,
        _account_id: &arkret_wire::AccountId,
    ) -> PersistenceResult<Option<ConfirmedKeyBackupAuthorityBasis>> {
        Err(crate::PersistenceError::SchemaViolation(
            "same-cut KeyBackup authority provenance is unavailable".to_owned(),
        ))
    }
    /// Resolve the human device lifecycle and pointer from one PCR snapshot.
    async fn confirmed_active_series_for_device(
        &self,
        _account_id: &arkret_wire::AccountId,
        _device_id: &arkret_wire::DeviceId,
        _now: chrono::DateTime<Utc>,
    ) -> PersistenceResult<Option<arkret_models_crypto::BackupActiveSeriesState>> {
        Err(crate::PersistenceError::SchemaViolation(
            "same-cut KeyBackup device authority is unavailable".to_owned(),
        ))
    }
    /// Account-level metadata cut for a verified recovery authorization.
    /// The HTTP boundary validates the recovery grant; this read preserves
    /// the pointer and page in one database snapshot without requiring the
    /// replacement device to have already been authorized.
    async fn confirmed_list_page_for_account(
        &self,
        _account_id: &arkret_wire::AccountId,
        _query: &KeyBackupListQuery,
    ) -> PersistenceResult<ConfirmedKeyBackupListPage> {
        Err(crate::PersistenceError::SchemaViolation(
            "same-cut KeyBackup account listing is unavailable".to_owned(),
        ))
    }
    async fn confirmed_list_page_for_device(
        &self,
        _account_id: &arkret_wire::AccountId,
        _device_id: &arkret_wire::DeviceId,
        _now: chrono::DateTime<Utc>,
        _query: &KeyBackupListQuery,
    ) -> PersistenceResult<ConfirmedKeyBackupListPage> {
        Err(crate::PersistenceError::SchemaViolation(
            "same-cut KeyBackup listing is unavailable".to_owned(),
        ))
    }
    /// Accept one active-series pointer Event, its PCR RealmCommit and the
    /// typed current pointer atomically.
    async fn commit_active_series_pointer(
        &self,
        _write: KeyBackupActiveSeriesCommitWrite,
    ) -> PersistenceResult<KeyBackupActiveSeriesCommitOutcome> {
        Err(crate::PersistenceError::Conflict(
            "key_backup_active_series_current_device_authority_unavailable".to_owned(),
        ))
    }
    async fn issue_unlock_challenge(
        &self,
        challenge: Value,
        now: chrono::DateTime<Utc>,
    ) -> PersistenceResult<Value>;
    async fn reserve_recovery_unlock_attempt(
        &self,
        authority_id: &str,
        holder: &str,
        request_digest: &str,
        now: chrono::DateTime<Utc>,
    ) -> PersistenceResult<bool>;
    async fn unlock_challenge(&self, authority_id: &str) -> PersistenceResult<Option<Value>>;
    async fn consume_unlock(&self, command: KeyBackupUnlockCommand<'_>)
    -> PersistenceResult<Value>;
    async fn put(&self, backup_id: String, payload: Value) -> PersistenceResult<()>;
    async fn get(&self, backup_id: &str) -> PersistenceResult<Option<Value>>;
    async fn delete(&self, backup_id: &str) -> PersistenceResult<bool>;
    async fn snapshot_all(&self) -> PersistenceResult<Vec<Value>>;
    async fn list_for_actor(&self, actor_id: &str) -> PersistenceResult<Vec<Value>>;
    async fn list_page(&self, query: &KeyBackupListQuery) -> PersistenceResult<KeyBackupListPage>;

    /// Issue `record`, or return the still-valid challenge already issued for
    /// the same `(account_id, backup_id, request_id)`.
    ///
    /// §7.8.1 requires re-issuing the *same* challenge while it is valid, so a
    /// client retrying the issue call does not invalidate the challenge it is
    /// already signing. "Still valid" is unconsumed and unexpired; a consumed or
    /// expired row is replaced.
    async fn issue_delete_challenge(
        &self,
        record: KeyBackupDeleteChallengeRecord,
        now: chrono::DateTime<Utc>,
    ) -> PersistenceResult<KeyBackupDeleteChallengeRecord>;

    /// Read a challenge by id, consumed or not. The caller distinguishes
    /// "expired", "already consumed" and "belongs to another principal or
    /// backup" so each is reported as its own failure.
    async fn delete_challenge(
        &self,
        challenge_id: &str,
    ) -> PersistenceResult<Option<KeyBackupDeleteChallengeRecord>>;

    /// Recheck current authority, delete the exact backup snapshot and consume
    /// its challenge in one transaction. Returns `false` for an unavailable
    /// challenge; a changed backup rolls back without consuming authorization.
    async fn consume_delete_challenge(
        &self,
        gate: &KeyBackupDeleteGate,
        challenge_id: &str,
        backup: Value,
        recovery_session_id: Option<&str>,
        now: chrono::DateTime<Utc>,
    ) -> PersistenceResult<bool>;

    /// TTL sweep for challenges at or past `now`.
    async fn prune_expired_delete_challenges(
        &self,
        now: chrono::DateTime<Utc>,
    ) -> PersistenceResult<usize>;
}
