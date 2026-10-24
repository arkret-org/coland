use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use super::{
    DeviceInventoryRecord, DeviceMessageBatchCommitOutcome, DeviceMessageBatchInspection,
    DeviceMessageBatchRecord, DeviceMessageIntentRecord, DeviceMessageRecord,
    DeviceRevocationGateSelector, PersistenceResult, RecipientDeliveryRecord,
    RecipientQueueSelector, Utc, Uuid, Value, async_trait,
};
/// Local presentation/activity fields. Protocol authorization is deliberately
/// absent: only authenticated history may install it.
#[derive(Clone, Debug)]
pub struct DeviceInventoryMetadata {
    pub actor: String,
    pub device_id: String,
    pub display_name: Option<String>,
    pub last_seen_at: Option<chrono::DateTime<Utc>>,
    pub last_key_upload_at: Option<chrono::DateTime<Utc>>,
    pub updated_at: chrono::DateTime<Utc>,
}

/// Trait for durable device inventory operations.
#[async_trait]
pub trait DeviceInventoryStore: Send + Sync {
    async fn get(
        &self,
        actor: &str,
        device_id: &str,
    ) -> PersistenceResult<Option<DeviceInventoryRecord>>;
    async fn put_metadata(&self, record: &DeviceInventoryMetadata) -> PersistenceResult<()>;
    async fn revoke_actor(
        &self,
        actor: &str,
        revoked_at: chrono::DateTime<Utc>,
    ) -> PersistenceResult<usize>;
    /// Insert a placeholder only when the actor/device row does not exist.
    ///
    /// Account registration is idempotent and may be replayed after an
    /// `ak.device.authorize` projection has already verified the device.  A
    /// placeholder write must never overwrite that authoritative projection.
    async fn put_if_absent(&self, record: &DeviceInventoryRecord) -> PersistenceResult<bool>;
    async fn list_for_actor(&self, actor: &str) -> PersistenceResult<Vec<DeviceInventoryRecord>>;
    async fn list_for_actor_including_revoked(
        &self,
        actor: &str,
    ) -> PersistenceResult<Vec<DeviceInventoryRecord>>;
    async fn list(&self) -> PersistenceResult<Vec<DeviceInventoryRecord>>;
}
/// Private native queue request, authenticated by the real accepted Device.
pub struct AppletDeviceQueueRead<'a> {
    pub endpoint: &'a crate::AppletManagedDeviceScopeGuard,
    pub after: Option<&'a str>,
    pub limit: usize,
    pub transport_expires_at: chrono::DateTime<Utc>,
}

/// Pending private allocations and the current cut survive until publication.
pub struct AppletDeviceQueuePage {
    pub outcome: arkret_models_collaboration::device_messages::DeviceMessagesGetResponseBody,
    pub guard: Box<dyn crate::AccountContentDeliveryGuard>,
}

/// ACK is a narrow completion of an original legally delivered exact page.
pub struct AppletDeviceQueueAck<'a> {
    pub authority: &'a crate::AppletManagedDeviceAuthority,
    pub effective_scope: &'a arkret_wire::ScopeRef,
    pub body:
        &'a arkret_models_collaboration::device_messages::DeviceMessagesAcknowledgementRequestBody,
    pub transport_expires_at: chrono::DateTime<Utc>,
}

/// To-device message queue + idempotency-key set.
#[async_trait]
pub trait DeviceMessageStore: Send + Sync {
    async fn applet_device_queue(
        &self,
        _input: AppletDeviceQueueRead<'_>,
    ) -> PersistenceResult<AppletDeviceQueuePage> {
        Err(crate::PersistenceError::Internal(
            "native recipient queue is unavailable".into(),
        ))
    }
    async fn ack_applet_device_queue(
        &self,
        _input: AppletDeviceQueueAck<'_>,
    ) -> PersistenceResult<Option<usize>> {
        Err(crate::PersistenceError::Internal(
            "native recipient ACK is unavailable".into(),
        ))
    }

    async fn append(
        &self,
        device_revocation_gate: Option<&DeviceRevocationGateSelector>,
        message: DeviceMessageRecord,
        per_device_queue_capacity: usize,
    ) -> PersistenceResult<()>;
    /// Read current request/message idempotency state before dynamic device-policy checks. The
    /// subsequent commit rechecks the same records atomically to close inspection races.
    async fn inspect_batch(
        &self,
        request_key: &str,
        request_digest: &str,
        items: &[DeviceMessageIntentRecord],
    ) -> PersistenceResult<DeviceMessageBatchInspection>;
    /// Atomically bind request- and message-level idempotency records and enqueue only fresh
    /// logical messages.
    async fn commit_batch(
        &self,
        batch: DeviceMessageBatchRecord,
    ) -> PersistenceResult<DeviceMessageBatchCommitOutcome>;
    /// Issue a bearer ack token for the delivered high-water queue position.
    async fn issue_ack_token(
        &self,
        recipient: &str,
        device_id: &str,
        queue_position: i64,
    ) -> PersistenceResult<Option<String>>;
    /// Consume a bearer ack token and prune the messages it covers. Returns
    /// `None` when the token is unknown, expired, or not bound to this device.
    async fn ack_with_token(
        &self,
        recipient: &str,
        device_id: &str,
        acknowledgement_token: &str,
    ) -> PersistenceResult<Option<usize>>;
    /// List queued messages for a device strictly after `queue_position`.
    async fn list_after(
        &self,
        recipient: &str,
        device_id: &str,
        queue_position: i64,
        limit: usize,
    ) -> PersistenceResult<Vec<DeviceMessageRecord>>;
    async fn list_recipient_deliveries(
        &self,
        selector: &RecipientQueueSelector,
        queue_position: i64,
        limit: usize,
    ) -> PersistenceResult<Vec<RecipientDeliveryRecord>>;
    async fn issue_recipient_ack_token(
        &self,
        selector: &RecipientQueueSelector,
        queue_position: i64,
    ) -> PersistenceResult<Option<String>>;
    async fn ack_recipient_with_token(
        &self,
        selector: &RecipientQueueSelector,
        acknowledgement_token: &str,
    ) -> PersistenceResult<Option<usize>>;
    /// Historical verified loss watermark, if any. Current v1 writers retain
    /// unacknowledged deliveries until explicit ACK.
    async fn lost_watermark(
        &self,
        recipient: &str,
        device_id: &str,
    ) -> PersistenceResult<Option<i64>>;
}
/// Long-term device key bundles (one per `(actor, device_id)`).
#[async_trait]
pub trait DeviceKeyStore: Send + Sync {
    async fn put(
        &self,
        authorization: &DeviceRevocationGateSelector,
        payload: Value,
    ) -> PersistenceResult<()>;
    async fn get(&self, actor: &str, device_id: &str) -> PersistenceResult<Option<Value>>;
}
/// One-time prekey pool. Calls to `claim` pop a single key.
#[async_trait]
pub trait OneTimeKeyStore: Send + Sync {
    async fn put(
        &self,
        authorization: &DeviceRevocationGateSelector,
        keys: Vec<Value>,
    ) -> PersistenceResult<()>;
    async fn claim(&self, actor: &str, device_id: &str) -> PersistenceResult<Option<Value>>;
}
#[derive(Clone)]
#[doc(hidden)]
pub struct DeviceMessageAckTokenRecord {
    pub recipient: String,
    pub device_id: String,
    pub queue_position: i64,
    pub expires_at: chrono::DateTime<Utc>,
    pub consumed_at: Option<chrono::DateTime<Utc>>,
}
#[doc(hidden)]
pub fn fresh_device_message_ack_token() -> String {
    let mut bytes = Vec::with_capacity(32);
    bytes.extend_from_slice(Uuid::new_v4().as_bytes());
    bytes.extend_from_slice(Uuid::new_v4().as_bytes());
    URL_SAFE_NO_PAD.encode(bytes)
}
