use arkret_models_collaboration::governance::invite_addressing::PrincipalLocatorDisplayHint;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::{PersistenceResult, async_trait};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct InviteLocatorRecord {
    pub locator_id: String,
    pub token_digest: String,
    pub subject_id: String,
    pub recipient_id: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub one_time_use: bool,
    pub display_hint: Option<PrincipalLocatorDisplayHint>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub consumed_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct InviteLocatorRotateMutation {
    pub locator_id: String,
    pub token_digest: String,
    pub issued_at: DateTime<Utc>,
    pub ttl_seconds: Option<u32>,
    pub one_time_use: Option<bool>,
    pub display_hint: Option<Option<PrincipalLocatorDisplayHint>>,
}

impl InviteLocatorRotateMutation {
    pub fn apply_to(&self, old: &InviteLocatorRecord) -> InviteLocatorRecord {
        let granted_lifetime = old.expires_at - old.issued_at;
        let lifetime = self
            .ttl_seconds
            .map(|seconds| chrono::Duration::seconds(i64::from(seconds)))
            .unwrap_or(granted_lifetime);
        InviteLocatorRecord {
            locator_id: self.locator_id.clone(),
            token_digest: self.token_digest.clone(),
            subject_id: old.subject_id.clone(),
            recipient_id: old.recipient_id.clone(),
            issued_at: self.issued_at,
            expires_at: self.issued_at + lifetime,
            one_time_use: self.one_time_use.unwrap_or(old.one_time_use),
            display_hint: self
                .display_hint
                .clone()
                .unwrap_or_else(|| old.display_hint.clone()),
            revoked_at: None,
            consumed_at: None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InviteLocatorInsertOutcome {
    Inserted,
    ActiveLimitReached,
}

#[async_trait]
pub trait InviteLocatorStore: Send + Sync {
    async fn insert(
        &self,
        record: &InviteLocatorRecord,
        active_limit: usize,
        now: DateTime<Utc>,
    ) -> PersistenceResult<InviteLocatorInsertOutcome>;
    async fn resolve_and_consume(
        &self,
        token_digest: &str,
        now: DateTime<Utc>,
    ) -> PersistenceResult<Option<InviteLocatorRecord>>;
    async fn rotate(
        &self,
        account_id: &arkret_wire::AccountId,
        old_locator_id: &str,
        mutation: &InviteLocatorRotateMutation,
        now: DateTime<Utc>,
    ) -> PersistenceResult<Option<InviteLocatorRecord>>;
    async fn revoke(
        &self,
        account_id: &arkret_wire::AccountId,
        locator_id: &str,
        now: DateTime<Utc>,
    ) -> PersistenceResult<Option<InviteLocatorRecord>>;
}
