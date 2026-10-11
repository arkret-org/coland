use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
pub use coland_storage::{
    AccountNotificationDeltaWrite, NotificationFanoutBasis, NotificationStrandScope,
    RecipientDeliveryRecord, RecipientNotificationRecord, RecipientQueueSelector,
    StoredAccountNotificationDelta,
};
use coland_storage::{AccountPk, SignalRelayRecord};
use futures_util::stream::BoxStream;
use serde_json::Value;

use crate::ServiceResult;

#[async_trait]
pub trait ObjectStoragePort: Send + Sync {
    fn backend_name(&self) -> String;
    fn object_key_for_sha256(&self, sha256: &str) -> String;
    async fn put(&self, key: &str, bytes: Vec<u8>) -> Result<(), String>;
    async fn put_file(&self, key: &str, file_path: &std::path::Path) -> Result<(), String>;
    async fn get(&self, key: &str) -> Result<Vec<u8>, String>;
    async fn get_range_stream(
        &self,
        key: &str,
        range: std::ops::Range<u64>,
    ) -> Result<BoxStream<'static, Result<Bytes, String>>, String>;
    async fn delete(&self, key: &str) -> Result<(), String>;
}

#[derive(Clone, Debug)]
pub struct StoreNotificationCommand {
    pub record: RecipientNotificationRecord,
}

#[derive(Clone, Debug)]
pub struct StoreAccountNotificationDeltaCommand {
    pub record: AccountNotificationDeltaWrite,
}

#[derive(Clone, Debug)]
pub struct ListAccountNotificationDeltasQuery {
    pub controller_account_pk: AccountPk,
    pub recipient_id: String,
    pub after_position: Option<i64>,
}

#[derive(Clone, Debug)]
pub struct ListRecipientNotificationsQuery {
    pub recipient_id: String,
}

#[async_trait]
pub trait NotificationWritePort: Send + Sync {
    async fn store_notification(&self, record: RecipientNotificationRecord) -> ServiceResult<()>;
    async fn store_account_delta(&self, record: AccountNotificationDeltaWrite)
    -> ServiceResult<()>;
    async fn list_for_account(
        &self,
        controller_account_pk: &AccountPk,
        recipient_id: &str,
        after_position: Option<i64>,
    ) -> ServiceResult<Vec<StoredAccountNotificationDelta>>;
    async fn list_for_recipient(
        &self,
        recipient_id: &str,
    ) -> ServiceResult<Vec<RecipientNotificationRecord>>;
    async fn fanout_basis(
        &self,
        realm_id: &arkret_wire::RealmId,
        strand_id: Option<&arkret_wire::StrandId>,
    ) -> ServiceResult<NotificationFanoutBasis>;
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DeviceDeliveryPurgeResult {
    pub to_device_messages_dropped: usize,
    pub push_registrations_removed: usize,
}

#[async_trait]
pub trait DeviceDeliveryPort: Send + Sync {
    async fn purge_device_delivery(
        &self,
        actor_id: &str,
        device_id: &str,
    ) -> ServiceResult<DeviceDeliveryPurgeResult>;
    async fn register_push_device(
        &self,
        authorization: &coland_storage::DeviceRevocationGateSelector,
        registration: Value,
    ) -> ServiceResult<()>;
    async fn unregister_push_device(
        &self,
        actor_id: &arkret_wire::AccountId,
        device_id: &str,
        push_key: Option<&str>,
        app_id: Option<&str>,
    ) -> ServiceResult<usize>;
}

/// One admitted `SignalEnvelope` held for its TTL (`sync/signal.md` §4).
///
/// Presence, typing, call signalling and read receipts are all Signals in v1:
/// they share this one opaque relay record instead of four plaintext shapes,
/// and the server sees only the AAD-bound envelope header.
pub use coland_storage::BlobRecord as BlobState;
pub use coland_storage::{
    DeviceMessageBatchCommitOutcome, DeviceMessageBatchInspection, DeviceMessageBatchItemRecord,
    DeviceMessageBatchRecord, DeviceMessageIntentRecord, DeviceMessageRecord as DeviceMessageState,
    DeviceMessageTargetSnapshotGuard,
};

#[async_trait]
pub trait BlobPort: Send + Sync {
    async fn blob(&self, blob_ref: &str) -> ServiceResult<Option<BlobState>>;
    async fn store_blob(&self, blob_ref: &str, blob: BlobState) -> ServiceResult<()>;
    async fn store_blob_if_absent(&self, blob_ref: &str, blob: BlobState) -> ServiceResult<bool>;
    async fn blobs(&self) -> ServiceResult<Vec<BlobState>>;
}

/// Live Signal relay (`sync/signal.md` §4).
///
/// A Signal is not durable: it produces no Event id, advances no `actor_seq`
/// and enters no Seal coverage, so this port only holds admitted envelopes
/// until `expires_at` and tracks a per-subscriber-device deliver-once
/// watermark.
#[async_trait]
pub trait SignalRelayPort: Send + Sync {
    async fn append_signal(&self, record: SignalRelayRecord) -> ServiceResult<bool>;
    async fn signals_for_realm(&self, realm_id: &str) -> ServiceResult<Vec<SignalRelayRecord>>;
    /// Short-lived replay suppression: whether this exact envelope digest was
    /// already admitted inside the retention window (`signal.md` §2).
    async fn prune_expired_signals(&self) -> ServiceResult<usize>;
    async fn signal_watermark(
        &self,
        actor_id: &str,
        device_id: &str,
        realm_id: &str,
    ) -> ServiceResult<u64>;
    async fn advance_signal_watermark(
        &self,
        actor_id: &str,
        device_id: &str,
        realm_id: &str,
        position: u64,
    ) -> ServiceResult<()>;
}

#[async_trait]
pub trait DeviceMessagePort: Send + Sync {
    async fn append(
        &self,
        device_revocation_gate: Option<&coland_storage::DeviceRevocationGateSelector>,
        message: DeviceMessageState,
        per_device_queue_capacity: usize,
    ) -> ServiceResult<()>;
    async fn inspect_batch(
        &self,
        request_key: &str,
        request_digest: &str,
        items: &[DeviceMessageIntentRecord],
    ) -> ServiceResult<DeviceMessageBatchInspection>;
    async fn commit_batch(
        &self,
        batch: DeviceMessageBatchRecord,
    ) -> ServiceResult<DeviceMessageBatchCommitOutcome>;
    async fn issue_ack_token(
        &self,
        recipient: &str,
        device_id: &str,
        queue_position: i64,
    ) -> ServiceResult<Option<String>>;
    async fn acknowledge(
        &self,
        recipient: &str,
        device_id: &str,
        ack_token: &str,
    ) -> ServiceResult<Option<usize>>;
    async fn messages_after(
        &self,
        recipient: &str,
        device_id: &str,
        queue_position: i64,
        limit: usize,
    ) -> ServiceResult<Vec<DeviceMessageState>>;
    async fn recipient_deliveries_after(
        &self,
        selector: &RecipientQueueSelector,
        queue_position: i64,
        limit: usize,
    ) -> ServiceResult<Vec<RecipientDeliveryRecord>>;
    async fn issue_recipient_ack_token(
        &self,
        selector: &RecipientQueueSelector,
        queue_position: i64,
    ) -> ServiceResult<Option<String>>;
    async fn acknowledge_recipient_deliveries(
        &self,
        selector: &RecipientQueueSelector,
        ack_token: &str,
    ) -> ServiceResult<Option<usize>>;
    async fn lost_watermark(&self, recipient: &str, device_id: &str) -> ServiceResult<Option<i64>>;
}

#[derive(Clone)]
pub struct DeliveryService {
    notifications: Arc<dyn NotificationWritePort>,
    device_delivery: Arc<dyn DeviceDeliveryPort>,
    device_messages: Arc<dyn DeviceMessagePort>,
    signals: Arc<dyn SignalRelayPort>,
    blobs: Arc<dyn BlobPort>,
    object_storage: Arc<dyn ObjectStoragePort>,
    push_target_hmac_key: [u8; 32],
}

pub struct DeliveryServiceRuntime {
    pub notifications: Arc<dyn NotificationWritePort>,
    pub device_delivery: Arc<dyn DeviceDeliveryPort>,
    pub device_messages: Arc<dyn DeviceMessagePort>,
    pub signals: Arc<dyn SignalRelayPort>,
    pub blobs: Arc<dyn BlobPort>,
    pub object_storage: Arc<dyn ObjectStoragePort>,
    pub push_target_hmac_key: [u8; 32],
}

impl DeliveryService {
    pub fn new(runtime: DeliveryServiceRuntime) -> Self {
        let DeliveryServiceRuntime {
            notifications,
            device_delivery,
            device_messages,
            signals,
            blobs,
            object_storage,
            push_target_hmac_key,
        } = runtime;
        Self {
            notifications,
            device_delivery,
            device_messages,
            signals,
            blobs,
            object_storage,
            push_target_hmac_key,
        }
    }

    pub fn object_storage_backend_name(&self) -> String {
        self.object_storage.backend_name()
    }

    pub fn object_key_for_sha256(&self, sha256: &str) -> String {
        self.object_storage.object_key_for_sha256(sha256)
    }

    pub async fn put_object(&self, key: &str, bytes: Vec<u8>) -> Result<(), String> {
        self.object_storage.put(key, bytes).await
    }

    pub async fn put_object_file(
        &self,
        key: &str,
        file_path: &std::path::Path,
    ) -> Result<(), String> {
        self.object_storage.put_file(key, file_path).await
    }

    pub async fn get_object(&self, key: &str) -> Result<Vec<u8>, String> {
        self.object_storage.get(key).await
    }

    pub async fn get_object_range_stream(
        &self,
        key: &str,
        range: std::ops::Range<u64>,
    ) -> Result<BoxStream<'static, Result<Bytes, String>>, String> {
        self.object_storage.get_range_stream(key, range).await
    }

    pub async fn delete_object(&self, key: &str) -> Result<(), String> {
        self.object_storage.delete(key).await
    }

    pub fn push_target_hmac_key(&self) -> &[u8; 32] {
        &self.push_target_hmac_key
    }

    pub async fn store_notification(&self, command: StoreNotificationCommand) -> ServiceResult<()> {
        self.notifications.store_notification(command.record).await
    }

    pub async fn store_account_delta(
        &self,
        command: StoreAccountNotificationDeltaCommand,
    ) -> ServiceResult<()> {
        self.notifications.store_account_delta(command.record).await
    }

    pub async fn list_account_deltas(
        &self,
        query: ListAccountNotificationDeltasQuery,
    ) -> ServiceResult<Vec<StoredAccountNotificationDelta>> {
        self.notifications
            .list_for_account(
                &query.controller_account_pk,
                &query.recipient_id,
                query.after_position,
            )
            .await
    }

    pub async fn list_recipient_notifications(
        &self,
        query: ListRecipientNotificationsQuery,
    ) -> ServiceResult<Vec<RecipientNotificationRecord>> {
        self.notifications
            .list_for_recipient(&query.recipient_id)
            .await
    }

    pub async fn notification_fanout_basis(
        &self,
        realm_id: &arkret_wire::RealmId,
        strand_id: Option<&arkret_wire::StrandId>,
    ) -> ServiceResult<NotificationFanoutBasis> {
        self.notifications.fanout_basis(realm_id, strand_id).await
    }

    pub async fn purge_device_delivery(
        &self,
        actor_id: &str,
        device_id: &str,
    ) -> ServiceResult<DeviceDeliveryPurgeResult> {
        self.device_delivery
            .purge_device_delivery(actor_id, device_id)
            .await
    }

    pub async fn register_push_device(
        &self,
        authorization: &coland_storage::DeviceRevocationGateSelector,
        registration: Value,
    ) -> ServiceResult<()> {
        self.device_delivery
            .register_push_device(authorization, registration)
            .await
    }
    pub async fn unregister_push_device(
        &self,
        actor_id: &arkret_wire::AccountId,
        device_id: &str,
        push_key: Option<&str>,
        app_id: Option<&str>,
    ) -> ServiceResult<usize> {
        self.device_delivery
            .unregister_push_device(actor_id, device_id, push_key, app_id)
            .await
    }
    pub async fn append_device_message(
        &self,
        device_revocation_gate: Option<&coland_storage::DeviceRevocationGateSelector>,
        message: DeviceMessageState,
        per_device_queue_capacity: usize,
    ) -> ServiceResult<()> {
        self.device_messages
            .append(device_revocation_gate, message, per_device_queue_capacity)
            .await
    }

    pub async fn commit_device_message_batch(
        &self,
        batch: DeviceMessageBatchRecord,
    ) -> ServiceResult<DeviceMessageBatchCommitOutcome> {
        self.device_messages.commit_batch(batch).await
    }

    pub async fn inspect_device_message_batch(
        &self,
        request_key: &str,
        request_digest: &str,
        items: &[DeviceMessageIntentRecord],
    ) -> ServiceResult<DeviceMessageBatchInspection> {
        self.device_messages
            .inspect_batch(request_key, request_digest, items)
            .await
    }

    pub async fn issue_device_message_ack_token(
        &self,
        recipient: &str,
        device_id: &str,
        queue_position: i64,
    ) -> ServiceResult<Option<String>> {
        self.device_messages
            .issue_ack_token(recipient, device_id, queue_position)
            .await
    }

    pub async fn acknowledge_device_messages(
        &self,
        recipient: &str,
        device_id: &str,
        ack_token: &str,
    ) -> ServiceResult<Option<usize>> {
        self.device_messages
            .acknowledge(recipient, device_id, ack_token)
            .await
    }

    pub async fn device_messages_after(
        &self,
        recipient: &str,
        device_id: &str,
        queue_position: i64,
        limit: usize,
    ) -> ServiceResult<Vec<DeviceMessageState>> {
        self.device_messages
            .messages_after(recipient, device_id, queue_position, limit)
            .await
    }

    pub async fn recipient_deliveries_after(
        &self,
        selector: &RecipientQueueSelector,
        queue_position: i64,
        limit: usize,
    ) -> ServiceResult<Vec<RecipientDeliveryRecord>> {
        self.device_messages
            .recipient_deliveries_after(selector, queue_position, limit)
            .await
    }

    pub async fn issue_recipient_ack_token(
        &self,
        selector: &RecipientQueueSelector,
        queue_position: i64,
    ) -> ServiceResult<Option<String>> {
        self.device_messages
            .issue_recipient_ack_token(selector, queue_position)
            .await
    }

    pub async fn acknowledge_recipient_deliveries(
        &self,
        selector: &RecipientQueueSelector,
        ack_token: &str,
    ) -> ServiceResult<Option<usize>> {
        self.device_messages
            .acknowledge_recipient_deliveries(selector, ack_token)
            .await
    }

    pub async fn device_message_lost_watermark(
        &self,
        recipient: &str,
        device_id: &str,
    ) -> ServiceResult<Option<i64>> {
        self.device_messages
            .lost_watermark(recipient, device_id)
            .await
    }

    pub async fn append_signal(&self, record: SignalRelayRecord) -> ServiceResult<bool> {
        self.signals.append_signal(record).await
    }

    pub async fn signals_for_realm(&self, realm_id: &str) -> ServiceResult<Vec<SignalRelayRecord>> {
        self.signals.signals_for_realm(realm_id).await
    }

    pub async fn prune_expired_signals(&self) -> ServiceResult<usize> {
        self.signals.prune_expired_signals().await
    }

    pub async fn signal_watermark(
        &self,
        actor_id: &str,
        device_id: &str,
        realm_id: &str,
    ) -> ServiceResult<u64> {
        self.signals
            .signal_watermark(actor_id, device_id, realm_id)
            .await
    }

    pub async fn advance_signal_watermark(
        &self,
        actor_id: &str,
        device_id: &str,
        realm_id: &str,
        position: u64,
    ) -> ServiceResult<()> {
        self.signals
            .advance_signal_watermark(actor_id, device_id, realm_id, position)
            .await
    }

    pub async fn blob(&self, blob_ref: &str) -> ServiceResult<Option<BlobState>> {
        self.blobs.blob(blob_ref).await
    }
    pub async fn store_blob(&self, blob_ref: &str, blob: BlobState) -> ServiceResult<()> {
        self.blobs.store_blob(blob_ref, blob).await
    }
    pub async fn store_blob_if_absent(
        &self,
        blob_ref: &str,
        blob: BlobState,
    ) -> ServiceResult<bool> {
        self.blobs.store_blob_if_absent(blob_ref, blob).await
    }
    pub async fn blobs(&self) -> ServiceResult<Vec<BlobState>> {
        self.blobs.blobs().await
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    #[derive(Default)]
    struct RecordingNotifications(Mutex<usize>);

    struct NoDeviceDelivery;

    struct NoDeviceMessages;
    struct NoSignalRelay;
    struct NoBlobs;
    struct NoObjectStorage;

    #[async_trait]
    impl ObjectStoragePort for NoObjectStorage {
        fn backend_name(&self) -> String {
            "memory".to_owned()
        }

        fn object_key_for_sha256(&self, sha256: &str) -> String {
            format!("sha256/{sha256}")
        }

        async fn put(&self, _key: &str, _bytes: Vec<u8>) -> Result<(), String> {
            Ok(())
        }

        async fn put_file(&self, _key: &str, _file_path: &std::path::Path) -> Result<(), String> {
            Ok(())
        }

        async fn get(&self, _key: &str) -> Result<Vec<u8>, String> {
            Ok(Vec::new())
        }

        async fn get_range_stream(
            &self,
            _key: &str,
            _range: std::ops::Range<u64>,
        ) -> Result<BoxStream<'static, Result<Bytes, String>>, String> {
            Ok(Box::pin(futures_util::stream::empty()))
        }

        async fn delete(&self, _key: &str) -> Result<(), String> {
            Ok(())
        }
    }

    #[async_trait]
    impl BlobPort for NoBlobs {
        async fn blob(&self, _blob_ref: &str) -> ServiceResult<Option<BlobState>> {
            Ok(None)
        }
        async fn store_blob(&self, _blob_ref: &str, _blob: BlobState) -> ServiceResult<()> {
            Ok(())
        }
        async fn store_blob_if_absent(
            &self,
            _blob_ref: &str,
            _blob: BlobState,
        ) -> ServiceResult<bool> {
            Ok(false)
        }
        async fn blobs(&self) -> ServiceResult<Vec<BlobState>> {
            Ok(Vec::new())
        }
    }

    #[async_trait]
    impl SignalRelayPort for NoSignalRelay {
        async fn append_signal(&self, _record: SignalRelayRecord) -> ServiceResult<bool> {
            Ok(true)
        }
        async fn signals_for_realm(
            &self,
            _realm_id: &str,
        ) -> ServiceResult<Vec<SignalRelayRecord>> {
            Ok(Vec::new())
        }
        async fn prune_expired_signals(&self) -> ServiceResult<usize> {
            Ok(0)
        }
        async fn signal_watermark(
            &self,
            _actor_id: &str,
            _device_id: &str,
            _realm_id: &str,
        ) -> ServiceResult<u64> {
            Ok(0)
        }
        async fn advance_signal_watermark(
            &self,
            _actor_id: &str,
            _device_id: &str,
            _realm_id: &str,
            _position: u64,
        ) -> ServiceResult<()> {
            Ok(())
        }
    }

    #[async_trait]
    impl DeviceMessagePort for NoDeviceMessages {
        async fn append(
            &self,
            _device_revocation_gate: Option<&coland_storage::DeviceRevocationGateSelector>,
            _message: DeviceMessageState,
            _per_device_queue_capacity: usize,
        ) -> ServiceResult<()> {
            Ok(())
        }
        async fn inspect_batch(
            &self,
            _request_key: &str,
            _request_digest: &str,
            _items: &[DeviceMessageIntentRecord],
        ) -> ServiceResult<DeviceMessageBatchInspection> {
            Ok(DeviceMessageBatchInspection::Fresh {
                existing_message_outcomes: Default::default(),
            })
        }
        async fn commit_batch(
            &self,
            _batch: DeviceMessageBatchRecord,
        ) -> ServiceResult<DeviceMessageBatchCommitOutcome> {
            Ok(DeviceMessageBatchCommitOutcome::Stored(Default::default()))
        }
        async fn issue_ack_token(
            &self,
            _recipient: &str,
            _device_id: &str,
            _queue_position: i64,
        ) -> ServiceResult<Option<String>> {
            Ok(None)
        }
        async fn acknowledge(
            &self,
            _recipient: &str,
            _device_id: &str,
            _ack_token: &str,
        ) -> ServiceResult<Option<usize>> {
            Ok(None)
        }
        async fn messages_after(
            &self,
            _recipient: &str,
            _device_id: &str,
            _queue_position: i64,
            _limit: usize,
        ) -> ServiceResult<Vec<DeviceMessageState>> {
            Ok(Vec::new())
        }
        async fn recipient_deliveries_after(
            &self,
            _selector: &RecipientQueueSelector,
            _queue_position: i64,
            _limit: usize,
        ) -> ServiceResult<Vec<RecipientDeliveryRecord>> {
            Ok(Vec::new())
        }
        async fn issue_recipient_ack_token(
            &self,
            _selector: &RecipientQueueSelector,
            _queue_position: i64,
        ) -> ServiceResult<Option<String>> {
            Ok(None)
        }
        async fn acknowledge_recipient_deliveries(
            &self,
            _selector: &RecipientQueueSelector,
            _ack_token: &str,
        ) -> ServiceResult<Option<usize>> {
            Ok(None)
        }
        async fn lost_watermark(
            &self,
            _recipient: &str,
            _device_id: &str,
        ) -> ServiceResult<Option<i64>> {
            Ok(None)
        }
    }

    #[async_trait]
    impl DeviceDeliveryPort for NoDeviceDelivery {
        async fn purge_device_delivery(
            &self,
            _actor_id: &str,
            _device_id: &str,
        ) -> ServiceResult<DeviceDeliveryPurgeResult> {
            Ok(DeviceDeliveryPurgeResult::default())
        }

        async fn register_push_device(
            &self,
            _authorization: &coland_storage::DeviceRevocationGateSelector,
            _registration: Value,
        ) -> ServiceResult<()> {
            Ok(())
        }
        async fn unregister_push_device(
            &self,
            _actor_id: &arkret_wire::AccountId,
            _device_id: &str,
            _push_key: Option<&str>,
            _app_id: Option<&str>,
        ) -> ServiceResult<usize> {
            Ok(0)
        }
    }

    #[async_trait]
    impl NotificationWritePort for RecordingNotifications {
        async fn store_notification(
            &self,
            _record: RecipientNotificationRecord,
        ) -> ServiceResult<()> {
            *self.0.lock().expect("notification lock") += 1;
            Ok(())
        }

        async fn store_account_delta(
            &self,
            _record: AccountNotificationDeltaWrite,
        ) -> ServiceResult<()> {
            *self.0.lock().expect("notification lock") += 1;
            Ok(())
        }

        async fn list_for_account(
            &self,
            _controller_account_pk: &AccountPk,
            _recipient_id: &str,
            _after_position: Option<i64>,
        ) -> ServiceResult<Vec<StoredAccountNotificationDelta>> {
            Ok(Vec::new())
        }

        async fn list_for_recipient(
            &self,
            _recipient_id: &str,
        ) -> ServiceResult<Vec<RecipientNotificationRecord>> {
            Ok(Vec::new())
        }

        async fn fanout_basis(
            &self,
            _realm_id: &arkret_wire::RealmId,
            _strand_id: Option<&arkret_wire::StrandId>,
        ) -> ServiceResult<NotificationFanoutBasis> {
            Ok(NotificationFanoutBasis::default())
        }
    }

    #[tokio::test]
    async fn notification_write_uses_only_the_narrow_port() {
        let port = Arc::new(RecordingNotifications::default());
        let service = DeliveryService::new(DeliveryServiceRuntime {
            notifications: port.clone(),
            device_delivery: Arc::new(NoDeviceDelivery),
            device_messages: Arc::new(NoDeviceMessages),
            signals: Arc::new(NoSignalRelay),
            blobs: Arc::new(NoBlobs),
            object_storage: Arc::new(NoObjectStorage),
            push_target_hmac_key: [0; 32],
        });
        service
            .store_notification(StoreNotificationCommand {
                record: RecipientNotificationRecord {
                    notification: arkret_models_collaboration::objects::read_receipts::Notification {
                        id: arkret_models_collaboration::objects::read_receipts::derive_notification_projection_id(
                            &arkret_wire::AccountId::new(
                                arkret_wire::DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
                                arkret_wire::DidCoreId::new("ak:did_core:web:principal.example").unwrap(),
                            ),
                            &arkret_wire::RealmId::new("ak:realm:AdF_8ICakbYdEH0Cnl-w5o1WFlnh5rXGWqY_-_G6yM7N").unwrap(),
                            &arkret_wire::EventId::new("ak:event:AT33EWBTXdTx5CjY-ogbIIF2T4vh-v7jCMCQ80Fss2Rq").unwrap(),
                            arkret_wire::OrdinaryNotificationKind::Message,
                        ).expect("notification id").into(),
                        schema: arkret_models_collaboration::objects::read_receipts::NotificationSchema::V1,
                        actor_id: arkret_wire::ActorId::account(arkret_wire::AccountId::new(
                            arkret_wire::DidCoreId::new(
                                "ak:did_core:web:alice.example".to_owned(),
                            )
                            .expect("actor DID"),
                            arkret_wire::DidCoreId::new(
                                "ak:did_core:web:principal.example".to_owned(),
                            )
                            .expect("hosting Station DID"),
                        )),
                        source: arkret_models_collaboration::objects::read_receipts::NotificationSource::Event(
                            arkret_models_collaboration::objects::read_receipts::NotificationEventSource {
                                source_event_id: arkret_wire::EventId::new(
                                    "ak:event:AT33EWBTXdTx5CjY-ogbIIF2T4vh-v7jCMCQ80Fss2Rq"
                                        .to_owned(),
                                )
                                .expect("event id"),
                                realm_id: Some(arkret_wire::RealmId::new("ak:realm:AdF_8ICakbYdEH0Cnl-w5o1WFlnh5rXGWqY_-_G6yM7N").unwrap()),
                                source_ref: None,
                                strand_id: None,
                                track_name: None,
                            },
                        ),
                        notification_kind: arkret_wire::NotificationKind::Message,
                        priority: arkret_wire::NotificationPriority::Normal,
                        state: arkret_wire::NotificationState::Unread,
                        preview: None,
                        created_at: chrono::Utc::now(),
                        updated_at: None,
                    },
                    event_kind: arkret_wire::EventKind::MessageCreate,
                    source_actor_id: None,
                },
            })
            .await
            .expect("store notification");
        assert_eq!(*port.0.lock().expect("notification lock"), 1);
    }
}
