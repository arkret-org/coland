use std::collections::BTreeMap;
use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
pub use coland_storage::{
    CursorRevocation as CursorRevocationState, SyncCursorRecord as CursorState,
};
use parking_lot::Mutex;

use crate::ServiceResult;

#[async_trait]
pub trait CursorStorePort: Send + Sync {
    async fn account_sync_watermarks(&self) -> ServiceResult<(i64, i64)>;
    async fn account_global_watermark(&self) -> ServiceResult<i64>;
    async fn account_global_channel_position(
        &self,
        actor_key: &str,
        channel: &str,
        watermark: i64,
    ) -> ServiceResult<i64>;
    async fn account_global_page(
        &self,
        actor_key: &str,
        channel: &str,
        watermark: i64,
        after_key: &str,
        after_revision: Option<i64>,
        limit: usize,
    ) -> ServiceResult<Vec<coland_storage::AccountGlobalVersion>>;
    async fn account_summary_watermark(&self) -> ServiceResult<i64>;
    async fn account_summary_page(
        &self,
        actor_key: &str,
        watermark: i64,
        after: Option<&coland_storage::AccountSummaryKey>,
        limit: usize,
    ) -> ServiceResult<Vec<coland_storage::AccountSummaryVersion>>;
    async fn account_summary_changes(
        &self,
        actor_key: &str,
        after_revision: i64,
        limit: usize,
    ) -> ServiceResult<Vec<coland_storage::AccountSummaryVersion>>;
    async fn get(&self, handle: &str) -> ServiceResult<Option<CursorState>>;
    async fn upsert(&self, record: &CursorState) -> ServiceResult<()>;
    async fn upsert_with_inputs(
        &self,
        record: &CursorState,
        inputs: &[CursorState],
    ) -> ServiceResult<()> {
        if inputs.is_empty() {
            return self.upsert(record).await;
        }
        Err(crate::ServiceError::Internal(
            "atomic cursor input validation is unavailable".to_owned(),
        ))
    }

    async fn delete(&self, handle: &str) -> ServiceResult<bool>;

    async fn prune_expired(&self, now_ms: i64) -> ServiceResult<usize>;
    async fn record_revocation(&self, record: &CursorRevocationState) -> ServiceResult<()>;
    async fn active_revocations(
        &self,
        now: DateTime<Utc>,
    ) -> ServiceResult<Vec<CursorRevocationState>>;
}

pub use coland_storage::{
    WebsocketAuthChallengeRecord as WebsocketChallengeState,
    WebsocketAuthReplayRecord as WebsocketReplayState, WebsocketConnectionLease,
};

/// Durable, cross-instance challenge + replay state for the WebSocket binding.
#[async_trait]
pub trait WebsocketAuthPort: Send + Sync {
    async fn reserve_connection(&self, _lease: &WebsocketConnectionLease) -> ServiceResult<bool> {
        Err(crate::ServiceError::Internal(
            "shared socket connection quotas are unavailable".to_owned(),
        ))
    }
    async fn release_connection(&self, _connection_id: &str) -> ServiceResult<()> {
        Err(crate::ServiceError::Internal(
            "shared socket connection quotas are unavailable".to_owned(),
        ))
    }
    async fn prepare_challenge(&self, record: &WebsocketChallengeState) -> ServiceResult<()>;
    async fn challenge(
        &self,
        connection_id: &str,
        nonce: &str,
    ) -> ServiceResult<Option<WebsocketChallengeState>>;
    async fn replay_ledger_contains(
        &self,
        cnf_jkt: &str,
        jti: &str,
        proof_context: &str,
    ) -> ServiceResult<bool>;
    async fn consume_challenge(
        &self,
        connection_id: &str,
        nonce: &str,
        replay: &WebsocketReplayState,
    ) -> ServiceResult<bool>;
    async fn prune_expired(&self, now: DateTime<Utc>) -> ServiceResult<usize>;
}

#[derive(Clone)]
pub struct SyncService {
    cursors: Arc<dyn CursorStorePort>,
    websocket_auth: Arc<dyn WebsocketAuthPort>,
    reconnect_deadlines: Arc<Mutex<BTreeMap<String, DateTime<Utc>>>>,
}

impl SyncService {
    pub fn new(
        cursors: Arc<dyn CursorStorePort>,
        websocket_auth: Arc<dyn WebsocketAuthPort>,
    ) -> Self {
        Self {
            cursors,
            websocket_auth,
            reconnect_deadlines: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }

    /// The durable WebSocket challenge / replay ledger (§3.1).
    pub async fn account_sync_watermarks(&self) -> ServiceResult<(i64, i64)> {
        self.cursors.account_sync_watermarks().await
    }
    pub async fn account_global_watermark(&self) -> ServiceResult<i64> {
        self.cursors.account_global_watermark().await
    }
    pub async fn account_global_channel_position(
        &self,
        actor_key: &str,
        channel: &str,
        watermark: i64,
    ) -> ServiceResult<i64> {
        self.cursors
            .account_global_channel_position(actor_key, channel, watermark)
            .await
    }
    pub async fn account_global_page(
        &self,
        actor_key: &str,
        channel: &str,
        watermark: i64,
        after_key: &str,
        after_revision: Option<i64>,
        limit: usize,
    ) -> ServiceResult<Vec<coland_storage::AccountGlobalVersion>> {
        self.cursors
            .account_global_page(
                actor_key,
                channel,
                watermark,
                after_key,
                after_revision,
                limit,
            )
            .await
    }
    pub async fn account_summary_watermark(&self) -> ServiceResult<i64> {
        self.cursors.account_summary_watermark().await
    }

    pub async fn account_summary_page(
        &self,
        actor_key: &str,
        watermark: i64,
        after: Option<&coland_storage::AccountSummaryKey>,
        limit: usize,
    ) -> ServiceResult<Vec<coland_storage::AccountSummaryVersion>> {
        self.cursors
            .account_summary_page(actor_key, watermark, after, limit)
            .await
    }

    pub async fn account_summary_changes(
        &self,
        actor_key: &str,
        after_revision: i64,
        limit: usize,
    ) -> ServiceResult<Vec<coland_storage::AccountSummaryVersion>> {
        self.cursors
            .account_summary_changes(actor_key, after_revision, limit)
            .await
    }

    pub fn websocket_auth(&self) -> &dyn WebsocketAuthPort {
        self.websocket_auth.as_ref()
    }

    pub fn subscribe_retry_after_ms(&self, key: &str, now: DateTime<Utc>) -> Option<u64> {
        let mut deadlines = self.reconnect_deadlines.lock();
        deadlines.retain(|_, deadline| *deadline > now);
        let deadline = deadlines.get(key)?;
        Some((*deadline - now).num_milliseconds().max(1) as u64)
    }

    pub fn arm_subscribe_reconnect(&self, key: String, now: DateTime<Utc>, delay_ms: u64) {
        const MAX_RECONNECT_WINDOW_MS: u64 = 86_400_000;
        if delay_ms == 0 {
            return;
        }
        let clamped_ms = delay_ms.min(MAX_RECONNECT_WINDOW_MS) as i64;
        let mut deadlines = self.reconnect_deadlines.lock();
        deadlines.insert(key, now + chrono::Duration::milliseconds(clamped_ms));
        deadlines.retain(|_, deadline| *deadline > now);
    }

    pub fn revoked_in(
        revocations: &[CursorRevocationState],
        cursor_digest: &str,
        account_id: Option<&arkret_wire::AccountId>,
        device_id: Option<&str>,
        session_id: Option<&str>,
        now: DateTime<Utc>,
    ) -> bool {
        revocations
            .iter()
            .filter(|entry| entry.expires_at > now)
            .any(|entry| match entry.scope.as_str() {
                "this_cursor" => {
                    entry.cursor_digest == cursor_digest
                        && account_id.is_some_and(|account| &entry.account_id == account)
                }
                "same_device" => account_id.is_some_and(|account| {
                    &entry.account_id == account && entry.device_id.as_deref() == device_id
                }),
                "same_session" => account_id.is_some_and(|account| {
                    &entry.account_id == account
                        && entry.device_id.as_deref() == device_id
                        && session_id.is_some()
                        && entry.session_id.as_deref() == session_id
                }),
                _ => false,
            })
    }

    pub async fn cursor(&self, handle: &str) -> ServiceResult<Option<CursorState>> {
        self.cursors.get(handle).await
    }

    pub async fn upsert_cursor(&self, record: &CursorState) -> ServiceResult<()> {
        self.cursors.upsert(record).await
    }

    pub async fn upsert_cursor_with_inputs(
        &self,
        record: &CursorState,
        inputs: &[CursorState],
    ) -> ServiceResult<()> {
        self.cursors.upsert_with_inputs(record, inputs).await
    }

    pub async fn delete_cursor(&self, handle: &str) -> ServiceResult<bool> {
        self.cursors.delete(handle).await
    }

    pub async fn prune_expired_cursors(&self, now_ms: i64) -> ServiceResult<usize> {
        self.cursors.prune_expired(now_ms).await
    }

    pub async fn record_cursor_revocation(
        &self,
        record: &CursorRevocationState,
    ) -> ServiceResult<()> {
        self.cursors.record_revocation(record).await
    }

    pub async fn active_cursor_revocations(
        &self,
        now: DateTime<Utc>,
    ) -> ServiceResult<Vec<CursorRevocationState>> {
        self.cursors.active_revocations(now).await
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    #[derive(Default)]
    struct RecordingCursors(Mutex<Vec<CursorState>>);

    #[async_trait]
    impl CursorStorePort for RecordingCursors {
        async fn account_sync_watermarks(&self) -> ServiceResult<(i64, i64)> {
            Ok((0, 0))
        }
        async fn account_global_watermark(&self) -> ServiceResult<i64> {
            Ok(0)
        }
        async fn account_global_channel_position(
            &self,
            _: &str,
            _: &str,
            _: i64,
        ) -> ServiceResult<i64> {
            Ok(0)
        }
        async fn account_global_page(
            &self,
            _: &str,
            _: &str,
            _: i64,
            _: &str,
            _: Option<i64>,
            _: usize,
        ) -> ServiceResult<Vec<coland_storage::AccountGlobalVersion>> {
            Ok(Vec::new())
        }
        async fn account_summary_watermark(&self) -> ServiceResult<i64> {
            Ok(0)
        }
        async fn account_summary_page(
            &self,
            _: &str,
            _: i64,
            _: Option<&coland_storage::AccountSummaryKey>,
            _: usize,
        ) -> ServiceResult<Vec<coland_storage::AccountSummaryVersion>> {
            Ok(Vec::new())
        }
        async fn account_summary_changes(
            &self,
            _: &str,
            _: i64,
            _: usize,
        ) -> ServiceResult<Vec<coland_storage::AccountSummaryVersion>> {
            Ok(Vec::new())
        }
        async fn get(&self, handle: &str) -> ServiceResult<Option<CursorState>> {
            Ok(self
                .0
                .lock()
                .expect("cursor lock")
                .iter()
                .find(|record| record.handle == handle)
                .cloned())
        }

        async fn upsert(&self, record: &CursorState) -> ServiceResult<()> {
            self.0.lock().expect("cursor lock").push(record.clone());
            Ok(())
        }

        async fn delete(&self, handle: &str) -> ServiceResult<bool> {
            let mut records = self.0.lock().expect("cursor lock");
            let before = records.len();
            records.retain(|record| record.handle != handle);
            Ok(records.len() != before)
        }

        async fn prune_expired(&self, _now_ms: i64) -> ServiceResult<usize> {
            Ok(0)
        }

        async fn record_revocation(&self, _record: &CursorRevocationState) -> ServiceResult<()> {
            Ok(())
        }

        async fn active_revocations(
            &self,
            _now: DateTime<Utc>,
        ) -> ServiceResult<Vec<CursorRevocationState>> {
            Ok(Vec::new())
        }
    }

    /// Challenge / replay stub: the cursor tests never touch the WebSocket
    /// binding, and a `SyncService` needs both ports.
    #[derive(Default)]
    struct UnusedWebsocketAuth;

    #[async_trait]
    impl WebsocketAuthPort for UnusedWebsocketAuth {
        async fn prepare_challenge(&self, _record: &WebsocketChallengeState) -> ServiceResult<()> {
            unreachable!("the cursor tests never mint a WebSocket challenge")
        }

        async fn challenge(
            &self,
            _connection_id: &str,
            _nonce: &str,
        ) -> ServiceResult<Option<WebsocketChallengeState>> {
            unreachable!("the cursor tests never read a WebSocket challenge")
        }

        async fn replay_ledger_contains(
            &self,
            _cnf_jkt: &str,
            _jti: &str,
            _proof_context: &str,
        ) -> ServiceResult<bool> {
            unreachable!("the cursor tests never read the replay ledger")
        }

        async fn consume_challenge(
            &self,
            _connection_id: &str,
            _nonce: &str,
            _replay: &WebsocketReplayState,
        ) -> ServiceResult<bool> {
            unreachable!("the cursor tests never consume a WebSocket challenge")
        }

        async fn prune_expired(&self, _now: DateTime<Utc>) -> ServiceResult<usize> {
            unreachable!("the cursor tests never sweep the WebSocket challenge store")
        }
    }

    #[tokio::test]
    async fn cursor_lifecycle_uses_only_the_cursor_port() {
        let port = Arc::new(RecordingCursors::default());
        let service = SyncService::new(port, Arc::new(UnusedWebsocketAuth));
        let record = CursorState {
            handle: "cursor-handle".to_owned(),
            binding_subject: None,
            device_id: None,
            session_id: None,
            service_id: arkret_identifiers::DidCoreId::new(
                "ak:did_core:web:service.example".to_owned(),
            )
            .unwrap(),
            filter_digest: None,
            purpose: "stream".to_owned(),
            positions: None,
            target: None,
            issued_at_ms: 1,
            expires_at_ms: 2,
        };
        service.upsert_cursor(&record).await.expect("upsert cursor");
        assert_eq!(service.cursor("cursor-handle").await.unwrap(), Some(record));
    }

    #[test]
    fn subscribe_reconnect_window_expires() {
        let service = SyncService::new(
            Arc::new(RecordingCursors::default()),
            Arc::new(UnusedWebsocketAuth),
        );
        let now = Utc::now();
        let key = "ak.self.committed_event.stream.subscribe.v1|alice|realm-a";
        service.arm_subscribe_reconnect(key.to_owned(), now, 10_000);
        let retry_after = service
            .subscribe_retry_after_ms(key, now + chrono::Duration::milliseconds(2_500))
            .expect("cooldown active");
        assert!((7_400..=7_500).contains(&retry_after));
        assert!(
            service
                .subscribe_retry_after_ms(key, now + chrono::Duration::milliseconds(10_000))
                .is_none()
        );
    }
}
