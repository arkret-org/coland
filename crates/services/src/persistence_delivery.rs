use std::sync::Arc;

use coland_storage::*;
use serde_json::Value;

use crate::delivery::*;

struct PersistenceNotificationWriter(Arc<dyn PersistenceStore>);
struct PersistenceDeviceDelivery(Arc<dyn PersistenceStore>);
struct PersistenceDeviceMessages(Arc<dyn PersistenceStore>);
struct PersistenceSignalRelay(Arc<dyn PersistenceStore>);
struct PersistenceBlobs(Arc<dyn PersistenceStore>);
#[async_trait::async_trait]
impl crate::delivery::NotificationWritePort for PersistenceNotificationWriter {
    async fn store_notification(
        &self,
        record: RecipientNotificationRecord,
    ) -> crate::ServiceResult<()> {
        self.0.notifications().put(record).await?;
        Ok(())
    }

    async fn store_account_delta(
        &self,
        record: AccountNotificationDeltaWrite,
    ) -> crate::ServiceResult<()> {
        self.0.notifications().put_account_delta(record).await?;
        Ok(())
    }

    async fn list_for_account(
        &self,
        controller_account_pk: &AccountPk,
        recipient_id: &str,
        after_position: Option<i64>,
    ) -> crate::ServiceResult<Vec<StoredAccountNotificationDelta>> {
        Ok(self
            .0
            .notifications()
            .list_for_account(controller_account_pk, recipient_id, after_position)
            .await?)
    }

    async fn list_for_recipient(
        &self,
        recipient_id: &str,
    ) -> crate::ServiceResult<Vec<RecipientNotificationRecord>> {
        Ok(self
            .0
            .notifications()
            .list_for_recipient(recipient_id)
            .await?)
    }

    async fn fanout_basis(
        &self,
        realm_id: &arkret_wire::RealmId,
        strand_id: Option<&arkret_wire::StrandId>,
    ) -> crate::ServiceResult<NotificationFanoutBasis> {
        Ok(self
            .0
            .notifications()
            .fanout_basis(realm_id, strand_id)
            .await?)
    }
}

#[async_trait::async_trait]
impl crate::delivery::DeviceDeliveryPort for PersistenceDeviceDelivery {
    async fn purge_device_delivery(
        &self,
        actor_id: &str,
        device_id: &str,
    ) -> crate::ServiceResult<crate::delivery::DeviceDeliveryPurgeResult> {
        // Queue entries remain durable until their endpoint acknowledges them.
        // Logout and account lifecycle may revoke push routes, but neither is
        // evidence of a queue ACK.
        let to_device_messages_dropped = 0;
        let push_registrations_removed = self
            .0
            .push_devices()
            .purge_principal_device(actor_id, device_id)
            .await?;
        Ok(crate::delivery::DeviceDeliveryPurgeResult {
            to_device_messages_dropped,
            push_registrations_removed,
        })
    }

    async fn register_push_device(
        &self,
        authorization: &coland_storage::DeviceRevocationGateSelector,
        registration: Value,
    ) -> crate::ServiceResult<()> {
        self.0
            .push_devices()
            .register(authorization, registration)
            .await?;
        Ok(())
    }

    async fn unregister_push_device(
        &self,
        actor_id: &arkret_wire::AccountId,
        device_id: &str,
        push_key: Option<&str>,
        app_id: Option<&str>,
    ) -> crate::ServiceResult<usize> {
        Ok(self
            .0
            .push_devices()
            .unregister(actor_id, device_id, push_key, app_id)
            .await?)
    }
}

#[async_trait::async_trait]
impl crate::delivery::SignalRelayPort for PersistenceSignalRelay {
    async fn append_signal(&self, record: SignalRelayRecord) -> crate::ServiceResult<bool> {
        Ok(self.0.signal_relay().append(record).await?)
    }

    async fn signals_for_realm(
        &self,
        realm_id: &str,
    ) -> crate::ServiceResult<Vec<SignalRelayRecord>> {
        Ok(self.0.signal_relay().list_for_realm(realm_id).await?)
    }

    async fn prune_expired_signals(&self) -> crate::ServiceResult<usize> {
        Ok(self.0.signal_relay().prune_expired().await?)
    }

    async fn signal_watermark(
        &self,
        actor_id: &str,
        device_id: &str,
        realm_id: &str,
    ) -> crate::ServiceResult<u64> {
        Ok(self
            .0
            .signal_relay()
            .delivered_through(actor_id, device_id, realm_id)
            .await?)
    }

    async fn advance_signal_watermark(
        &self,
        actor_id: &str,
        device_id: &str,
        realm_id: &str,
        position: u64,
    ) -> crate::ServiceResult<()> {
        self.0
            .signal_relay()
            .advance(actor_id, device_id, realm_id, position)
            .await?;
        Ok(())
    }
}

#[async_trait::async_trait]
impl crate::delivery::BlobPort for PersistenceBlobs {
    async fn blob(
        &self,
        blob_ref: &str,
    ) -> crate::ServiceResult<Option<crate::delivery::BlobState>> {
        Ok(self.0.blobs().get(blob_ref).await?)
    }
    async fn store_blob(
        &self,
        blob_ref: &str,
        blob: crate::delivery::BlobState,
    ) -> crate::ServiceResult<()> {
        self.0.blobs().put(blob_ref, &blob).await?;
        Ok(())
    }
    async fn store_blob_if_absent(
        &self,
        blob_ref: &str,
        blob: crate::delivery::BlobState,
    ) -> crate::ServiceResult<bool> {
        Ok(self.0.blobs().put_if_absent(blob_ref, &blob).await?)
    }
    async fn blobs(&self) -> crate::ServiceResult<Vec<crate::delivery::BlobState>> {
        Ok(self.0.blobs().snapshot_all().await?)
    }
}

#[async_trait::async_trait]
impl crate::delivery::DeviceMessagePort for PersistenceDeviceMessages {
    async fn append(
        &self,
        device_revocation_gate: Option<&coland_storage::DeviceRevocationGateSelector>,
        message: crate::delivery::DeviceMessageState,
        per_device_queue_capacity: usize,
    ) -> crate::ServiceResult<()> {
        self.0
            .device_messages()
            .append(device_revocation_gate, message, per_device_queue_capacity)
            .await?;
        Ok(())
    }

    async fn commit_batch(
        &self,
        batch: crate::delivery::DeviceMessageBatchRecord,
    ) -> crate::ServiceResult<crate::delivery::DeviceMessageBatchCommitOutcome> {
        Ok(self.0.device_messages().commit_batch(batch).await?)
    }

    async fn inspect_batch(
        &self,
        request_key: &str,
        request_digest: &str,
        items: &[crate::delivery::DeviceMessageIntentRecord],
    ) -> crate::ServiceResult<crate::delivery::DeviceMessageBatchInspection> {
        Ok(self
            .0
            .device_messages()
            .inspect_batch(request_key, request_digest, items)
            .await?)
    }

    async fn issue_ack_token(
        &self,
        recipient: &str,
        device_id: &str,
        queue_position: i64,
    ) -> crate::ServiceResult<Option<String>> {
        Ok(self
            .0
            .device_messages()
            .issue_ack_token(recipient, device_id, queue_position)
            .await?)
    }

    async fn acknowledge(
        &self,
        recipient: &str,
        device_id: &str,
        acknowledgement_token: &str,
    ) -> crate::ServiceResult<Option<usize>> {
        Ok(self
            .0
            .device_messages()
            .ack_with_token(recipient, device_id, acknowledgement_token)
            .await?)
    }

    async fn messages_after(
        &self,
        recipient: &str,
        device_id: &str,
        queue_position: i64,
        limit: usize,
    ) -> crate::ServiceResult<Vec<crate::delivery::DeviceMessageState>> {
        Ok(self
            .0
            .device_messages()
            .list_after(recipient, device_id, queue_position, limit)
            .await?)
    }

    async fn applet_device_queue(
        &self,
        input: coland_storage::AppletDeviceQueueRead<'_>,
    ) -> crate::ServiceResult<coland_storage::AppletDeviceQueuePage> {
        Ok(self.0.device_messages().applet_device_queue(input).await?)
    }
    async fn ack_applet_device_queue(
        &self,
        input: coland_storage::AppletDeviceQueueAck<'_>,
    ) -> crate::ServiceResult<Option<usize>> {
        Ok(self
            .0
            .device_messages()
            .ack_applet_device_queue(input)
            .await?)
    }

    async fn recipient_deliveries_after(
        &self,
        selector: &crate::delivery::RecipientQueueSelector,
        queue_position: i64,
        limit: usize,
    ) -> crate::ServiceResult<Vec<crate::delivery::RecipientDeliveryRecord>> {
        Ok(self
            .0
            .device_messages()
            .list_recipient_deliveries(selector, queue_position, limit)
            .await?)
    }

    async fn issue_recipient_ack_token(
        &self,
        selector: &crate::delivery::RecipientQueueSelector,
        queue_position: i64,
    ) -> crate::ServiceResult<Option<String>> {
        Ok(self
            .0
            .device_messages()
            .issue_recipient_ack_token(selector, queue_position)
            .await?)
    }

    async fn acknowledge_recipient_deliveries(
        &self,
        selector: &crate::delivery::RecipientQueueSelector,
        acknowledgement_token: &str,
    ) -> crate::ServiceResult<Option<usize>> {
        Ok(self
            .0
            .device_messages()
            .ack_recipient_with_token(selector, acknowledgement_token)
            .await?)
    }

    async fn lost_watermark(
        &self,
        recipient: &str,
        device_id: &str,
    ) -> crate::ServiceResult<Option<i64>> {
        Ok(self
            .0
            .device_messages()
            .lost_watermark(recipient, device_id)
            .await?)
    }
}

pub fn build_persistence_delivery_service(
    persistence: Arc<dyn PersistenceStore>,
    object_storage: Arc<dyn ObjectStoragePort>,
    push_target_hmac_key: [u8; 32],
) -> DeliveryService {
    DeliveryService::new(crate::delivery::DeliveryServiceRuntime {
        notifications: Arc::new(PersistenceNotificationWriter(persistence.clone())),
        device_delivery: Arc::new(PersistenceDeviceDelivery(persistence.clone())),
        device_messages: Arc::new(PersistenceDeviceMessages(persistence.clone())),
        signals: Arc::new(PersistenceSignalRelay(persistence.clone())),
        blobs: Arc::new(PersistenceBlobs(persistence.clone())),
        object_storage,
        push_target_hmac_key,
    })
}
