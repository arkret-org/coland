use std::sync::Arc;

use coland_storage::*;
use serde_json::Value;

use crate::federation::FederationService;
use crate::governance::{GovernanceService, RuntimeSettingsPort};
use crate::jobs::{JobsService, RuntimeHealthPort};
use crate::sync::SyncService;

struct PersistenceFederationOutbox(Arc<dyn PersistenceStore>);
struct PersistenceAuditLog(Arc<dyn PersistenceStore>);
struct PersistenceModeration(Arc<dyn PersistenceStore>);
struct PersistenceGovernanceRecords(Arc<dyn PersistenceStore>);
struct PersistenceCursorStore(Arc<dyn PersistenceStore>);
struct PersistenceWebsocketAuth(Arc<dyn PersistenceStore>);
struct PersistenceMaintenance(Arc<dyn PersistenceStore>);

fn federation_delivery_record(
    record: crate::federation::FederationDeliveryRecord,
) -> FederationOutboxRecord {
    let coalescing_key = record.coalescing_key.clone();
    let coalescing_position = record.coalescing_position;
    let mut persisted = match record.realm_fanout {
        Some(binding) => FederationOutboxRecord::realm_fanout(RealmFanoutOutboxInput {
            id: record.id,
            peer_id: record.peer_id,
            peer_url: record.peer_url,
            endpoint: record.endpoint,
            idempotency_key: record.idempotency_key,
            payload_json: record.payload_json,
            binding,
            created_at: record.created_at,
        }),
        None => match record.peer_url {
            Some(peer_url) => FederationOutboxRecord::pending(
                record.id,
                record.peer_id,
                peer_url,
                record.endpoint,
                record.idempotency_key,
                record.payload_json,
                record.created_at,
            ),
            None => FederationOutboxRecord::pending_without_locator(
                record.id,
                record.peer_id,
                record.endpoint,
                record.idempotency_key,
                record.payload_json,
                record.created_at,
            ),
        },
    };
    persisted.coalescing_key = coalescing_key;
    persisted.coalescing_position = coalescing_position;
    persisted
}

fn application_delivery_record(
    record: &FederationOutboxRecord,
) -> crate::federation::FederationDeliveryRecord {
    crate::federation::FederationDeliveryRecord {
        id: record.id.clone(),
        peer_id: record.peer_id.clone(),
        peer_url: record.peer_url.clone(),
        endpoint: record.endpoint.clone(),
        idempotency_key: record.idempotency_key.clone(),
        payload_json: record.payload_json.clone(),
        coalescing_key: record.coalescing_key.clone(),
        coalescing_position: record.coalescing_position,
        realm_fanout: record.realm_fanout.clone(),
        created_at: record.created_at,
    }
}

fn application_pending_delivery(
    record: FederationOutboxRecord,
) -> crate::federation::PendingFederationDelivery {
    crate::federation::PendingFederationDelivery {
        delivery: application_delivery_record(&record),
        state: record.state,
        leased_from_state: record.leased_from_state,
        attempts: record.attempts,
        semantic_attempts: record.semantic_attempts,
        next_attempt_at: record.next_attempt_at,
        last_http_status: record.last_http_status,
        last_error_code: record.last_error_code,
        last_response_excerpt: record.last_response_excerpt,
        lease_owner: record.lease_owner,
        lease_token: record.lease_token,
        lease_expires_at: record.lease_expires_at,
        policy_version: record.policy_version,
        supersedes_outbox_id: record.supersedes_outbox_id,
        completed_at: record.completed_at,
    }
}

#[async_trait::async_trait]
impl crate::federation::FederationOutboxPort for PersistenceFederationOutbox {
    async fn enqueue(
        &self,
        delivery: &crate::federation::FederationDeliveryRecord,
    ) -> crate::ServiceResult<bool> {
        Ok(self
            .0
            .federation_outbox()
            .enqueue(&federation_delivery_record(delivery.clone()))
            .await?)
    }

    async fn find(
        &self,
        peer_id: &arkret_identifiers::DidCoreId,
        idempotency_key: &str,
    ) -> crate::ServiceResult<Option<crate::federation::FederationDeliveryRecord>> {
        Ok(self
            .0
            .federation_outbox()
            .snapshot_all()
            .await?
            .into_iter()
            .find(|row| &row.peer_id == peer_id && row.idempotency_key == idempotency_key)
            .map(|row| application_delivery_record(&row)))
    }

    async fn claim_due(
        &self,
        command: &crate::federation::ClaimFederationDeliveriesCommand,
    ) -> crate::ServiceResult<Vec<crate::federation::PendingFederationDelivery>> {
        Ok(self
            .0
            .federation_outbox()
            .claim_due(&FederationOutboxClaim {
                now_unix_secs: command.now,
                limit: command.limit,
                lease_owner: command.lease_owner.clone(),
                lease_token: command.lease_token.clone(),
                lease_duration_secs: command.lease_duration_secs,
            })
            .await?
            .into_iter()
            .map(application_pending_delivery)
            .collect())
    }

    async fn record_attempt(
        &self,
        command: &crate::federation::RecordFederationAttemptCommand,
    ) -> crate::ServiceResult<bool> {
        let outcome = match &command.outcome {
            crate::federation::FederationDeliveryOutcome::Retry { next_attempt_at } => {
                FederationOutboxOutcome::Retry {
                    next_attempt_at: *next_attempt_at,
                }
            }
            crate::federation::FederationDeliveryOutcome::RouteUnavailable { next_attempt_at } => {
                FederationOutboxOutcome::RouteUnavailable {
                    next_attempt_at: *next_attempt_at,
                }
            }
            crate::federation::FederationDeliveryOutcome::Delivered => {
                FederationOutboxOutcome::Delivered
            }
            crate::federation::FederationDeliveryOutcome::CancelledAuthorityLost => {
                FederationOutboxOutcome::CancelledAuthorityLost
            }
            crate::federation::FederationDeliveryOutcome::PolicySuppressed { policy_version } => {
                FederationOutboxOutcome::PolicySuppressed {
                    policy_version: policy_version.clone(),
                }
            }
            crate::federation::FederationDeliveryOutcome::DeadLettered(record) => {
                FederationOutboxOutcome::DeadLettered(record.clone())
            }
            crate::federation::FederationDeliveryOutcome::Superseded {
                delivery,
                next_attempt_at,
            } => {
                let mut successor = federation_delivery_record((**delivery).clone());
                successor.semantic_attempts = command.semantic_attempts;
                successor.supersedes_outbox_id = Some(command.id.clone());
                successor.next_attempt_at = *next_attempt_at;
                FederationOutboxOutcome::Superseded(Box::new(successor))
            }
        };
        Ok(self
            .0
            .federation_outbox()
            .complete(&FederationOutboxTransition {
                id: command.id.clone(),
                lease_token: command.lease_token.clone(),
                attempts: command.attempts,
                semantic_attempts: command.semantic_attempts,
                last_http_status: command.last_http_status,
                last_error_code: command.last_error_code.clone(),
                last_response_excerpt: command.last_response_excerpt.clone(),
                observed_at: command.observed_at,
                outcome,
            })
            .await?)
    }

    async fn policy_suppressed_stale(
        &self,
        current_policy_version: &str,
        limit: usize,
    ) -> crate::ServiceResult<Vec<crate::federation::PendingFederationDelivery>> {
        Ok(self
            .0
            .federation_outbox()
            .policy_suppressed_stale(current_policy_version, limit)
            .await?
            .into_iter()
            .map(application_pending_delivery)
            .collect())
    }

    async fn resolve_policy_suppressed(
        &self,
        id: &str,
        resolution: &coland_storage::FederationOutboxPolicyResolution,
    ) -> crate::ServiceResult<bool> {
        Ok(self
            .0
            .federation_outbox()
            .resolve_policy_suppressed(id, resolution)
            .await?)
    }

    async fn delivery(
        &self,
        id: &str,
    ) -> crate::ServiceResult<Option<crate::federation::PendingFederationDelivery>> {
        Ok(self
            .0
            .federation_outbox()
            .get(id)
            .await?
            .map(application_pending_delivery))
    }

    async fn deliveries_for_event(
        &self,
        event_id: &str,
    ) -> crate::ServiceResult<Vec<crate::federation::PendingFederationDelivery>> {
        Ok(self
            .0
            .events()
            .federation_outbox_for_event(event_id)
            .await?
            .into_iter()
            .map(application_pending_delivery)
            .collect())
    }

    async fn deliveries_by_state(
        &self,
        state: coland_storage::FederationOutboxState,
        limit: usize,
    ) -> crate::ServiceResult<Vec<crate::federation::PendingFederationDelivery>> {
        Ok(self
            .0
            .federation_outbox()
            .list_by_state(state, limit)
            .await?
            .into_iter()
            .map(application_pending_delivery)
            .collect())
    }

    async fn state_depth(
        &self,
    ) -> crate::ServiceResult<Vec<coland_storage::FederationOutboxStateDepth>> {
        Ok(self.0.federation_outbox().state_depth().await?)
    }

    async fn dead_letter(
        &self,
        id: &str,
    ) -> crate::ServiceResult<Option<crate::federation::FederationDeadLetter>> {
        Ok(self.0.federation_outbox().dead_letter(id).await?)
    }

    async fn dead_letters(
        &self,
    ) -> crate::ServiceResult<Vec<crate::federation::FederationDeadLetter>> {
        Ok(self.0.federation_outbox().dead_letters_snapshot().await?)
    }

    async fn requeue_dead_letter(
        &self,
        command: &crate::federation::RequeueFederationDeadLetterCommand,
    ) -> crate::ServiceResult<bool> {
        let mut record = federation_delivery_record(command.delivery.clone());
        record.supersedes_outbox_id = Some(command.supersedes_outbox_id.clone());
        Ok(self
            .0
            .federation_outbox()
            .requeue_dead_letter(&FederationOutboxRequeue {
                dead_letter_id: command.dead_letter_id.clone(),
                record,
                operator: command.operator.clone(),
                reason: command.reason.clone(),
                request_digest: command.request_digest.clone(),
                requeued_at: command.requeued_at,
            })
            .await?)
    }

    async fn deliveries(
        &self,
    ) -> crate::ServiceResult<Vec<crate::federation::PendingFederationDelivery>> {
        Ok(self
            .0
            .federation_outbox()
            .snapshot_all()
            .await?
            .into_iter()
            .map(application_pending_delivery)
            .collect())
    }
}

#[async_trait::async_trait]
impl crate::federation::FederationStatePort for PersistenceFederationOutbox {
    async fn append_operation(
        &self,
        operation: arkret_event_draft::ProjectedEventOperation,
    ) -> crate::ServiceResult<()> {
        self.0.federation_operations().append(operation).await?;
        Ok(())
    }
    async fn has_operation(&self, operation_id: &str) -> crate::ServiceResult<bool> {
        Ok(self
            .0
            .federation_operations()
            .contains(operation_id)
            .await?)
    }
    async fn operations_for_realm(
        &self,
        realm_id: &str,
    ) -> crate::ServiceResult<Vec<arkret_event_draft::ProjectedEventOperation>> {
        Ok(self
            .0
            .federation_operations()
            .list_for_realm(realm_id)
            .await?)
    }
    async fn operations(
        &self,
    ) -> crate::ServiceResult<Vec<arkret_event_draft::ProjectedEventOperation>> {
        Ok(self.0.federation_operations().snapshot_all().await?)
    }
}

#[async_trait::async_trait]
impl crate::governance::AuditLogPort for PersistenceAuditLog {
    async fn append(&self, entry: Value) -> crate::ServiceResult<()> {
        self.0.audit().append(entry).await?;
        Ok(())
    }

    async fn entries(&self) -> crate::ServiceResult<Vec<Value>> {
        Ok(self.0.audit().snapshot_all().await?)
    }

    async fn entries_for_actor(&self, actor_id: &str) -> crate::ServiceResult<Vec<Value>> {
        Ok(self.0.audit().list_for_actor(actor_id).await?)
    }
}

#[async_trait::async_trait]
impl crate::governance::ModerationPort for PersistenceModeration {
    async fn queue_view_for_actor(
        &self,
        actor: &arkret_wire::ActorId,
        realm_id: Option<&arkret_wire::RealmId>,
    ) -> crate::ServiceResult<
        Vec<arkret_models_collaboration::governance::moderation_queue::ModerationQueueItem>,
    > {
        Ok(self
            .0
            .moderation()
            .queue_view_for_actor(actor, realm_id)
            .await?)
    }
    async fn management_view_for_actor(
        &self,
        actor: &arkret_wire::ActorId,
        realm_id: Option<&arkret_wire::RealmId>,
    ) -> crate::ServiceResult<coland_storage::ModerationManagementView> {
        Ok(self
            .0
            .moderation()
            .management_view_for_actor(actor, realm_id)
            .await?)
    }
    async fn report_count(&self) -> crate::ServiceResult<u64> {
        Ok(self.0.moderation().report_count().await?)
    }
}

#[async_trait::async_trait]
impl crate::governance::GovernanceRecordsPort for PersistenceGovernanceRecords {
    async fn organization(
        &self,
        organization_id: &str,
    ) -> crate::ServiceResult<Option<crate::governance::OrganizationRecord>> {
        Ok(self.0.organizations().get(organization_id).await?)
    }

    async fn store_organization(
        &self,
        record: &crate::governance::OrganizationRecord,
    ) -> crate::ServiceResult<()> {
        self.0.organizations().put(record).await?;
        Ok(())
    }

    async fn organizations(
        &self,
    ) -> crate::ServiceResult<Vec<crate::governance::OrganizationRecord>> {
        Ok(self.0.organizations().list().await?)
    }

    async fn link_realm_organization(
        &self,
        realm_id: &str,
        organization_id: &arkret_wire::DidCoreId,
    ) -> crate::ServiceResult<()> {
        self.0
            .realm_organizations()
            .link(realm_id, organization_id)
            .await?;
        Ok(())
    }

    async fn realm_organization_links(
        &self,
    ) -> crate::ServiceResult<Vec<(String, std::collections::BTreeSet<arkret_wire::DidCoreId>)>>
    {
        Ok(self.0.realm_organizations().snapshot_all().await?)
    }

    async fn policy_document(
        &self,
        policy_id: &str,
    ) -> crate::ServiceResult<Option<crate::governance::PolicyDocumentRecord>> {
        Ok(self.0.policy_documents().get(policy_id).await?)
    }

    async fn store_policy_document(
        &self,
        record: crate::governance::PolicyDocumentRecord,
    ) -> crate::ServiceResult<()> {
        self.0.policy_documents().put(record).await?;
        Ok(())
    }

    async fn delete_policy_document(&self, policy_id: &str) -> crate::ServiceResult<bool> {
        Ok(self.0.policy_documents().delete(policy_id).await?)
    }

    async fn policy_documents_for_owner(
        &self,
        owner: &str,
    ) -> crate::ServiceResult<Vec<crate::governance::PolicyDocumentRecord>> {
        Ok(self.0.policy_documents().list_for_owner(owner).await?)
    }

    async fn policy_documents(
        &self,
    ) -> crate::ServiceResult<Vec<crate::governance::PolicyDocumentRecord>> {
        Ok(self.0.policy_documents().snapshot_all().await?)
    }

    async fn retention_policy(
        &self,
        realm_id: &str,
    ) -> crate::ServiceResult<Option<crate::governance::RetentionPolicyRecord>> {
        Ok(self.0.retention_policies().get(realm_id).await?)
    }

    async fn store_retention_policy(
        &self,
        record: &crate::governance::RetentionPolicyRecord,
    ) -> crate::ServiceResult<()> {
        self.0.retention_policies().put(record).await?;
        Ok(())
    }

    async fn retention_tombstone(
        &self,
        event_id: &str,
    ) -> crate::ServiceResult<Option<crate::governance::RetentionTombstoneRecord>> {
        Ok(self.0.retention_tombstones().get(event_id).await?)
    }

    async fn retention_tombstones(
        &self,
    ) -> crate::ServiceResult<Vec<crate::governance::RetentionTombstoneRecord>> {
        Ok(self.0.retention_tombstones().snapshot_all().await?)
    }

    async fn store_retention_tombstone(
        &self,
        record: &crate::governance::RetentionTombstoneRecord,
    ) -> crate::ServiceResult<()> {
        self.0.retention_tombstones().put(record).await?;
        Ok(())
    }
}

#[async_trait::async_trait]
impl crate::jobs::MaintenancePort for PersistenceMaintenance {
    async fn prune_expired_idempotency(
        &self,
        now: chrono::DateTime<chrono::Utc>,
    ) -> crate::ServiceResult<usize> {
        Ok(self.0.idempotency_keys().prune_expired(now).await?)
    }

    async fn idempotency_record(
        &self,
        principal_id: &arkret_identifiers::DidCoreId,
        key: &str,
    ) -> crate::ServiceResult<Option<crate::jobs::IdempotencyState>> {
        Ok(self
            .0
            .idempotency_keys()
            .get(
                &arkret_wire::ActorId::service(principal_id.clone()),
                crate::jobs::INTERNAL_IDEMPOTENCY_OPERATION,
                key,
            )
            .await?)
    }

    async fn idempotency_record_scoped(
        &self,
        authenticated_actor: &arkret_wire::ActorId,
        operation_id: &str,
        key: &str,
    ) -> crate::ServiceResult<Option<crate::jobs::IdempotencyState>> {
        Ok(self
            .0
            .idempotency_keys()
            .get(authenticated_actor, operation_id, key)
            .await?)
    }

    async fn store_idempotency_record(
        &self,
        record: crate::jobs::IdempotencyState,
    ) -> crate::ServiceResult<()> {
        self.0.idempotency_keys().record(&record).await?;
        Ok(())
    }
}

#[async_trait::async_trait]
impl crate::sync::CursorStorePort for PersistenceCursorStore {
    async fn account_sync_watermarks(&self) -> crate::ServiceResult<(i64, i64)> {
        Ok(self.0.sync_cursors().account_sync_watermarks().await?)
    }
    async fn account_global_watermark(&self) -> crate::ServiceResult<i64> {
        Ok(self.0.sync_cursors().account_global_watermark().await?)
    }
    async fn account_global_channel_position(
        &self,
        actor_key: &str,
        channel: &str,
        watermark: i64,
    ) -> crate::ServiceResult<i64> {
        Ok(self
            .0
            .sync_cursors()
            .account_global_channel_position(actor_key, channel, watermark)
            .await?)
    }
    async fn account_global_page(
        &self,
        actor_key: &str,
        channel: &str,
        watermark: i64,
        after_key: &str,
        after_revision: Option<i64>,
        limit: usize,
    ) -> crate::ServiceResult<Vec<coland_storage::AccountGlobalVersion>> {
        Ok(self
            .0
            .sync_cursors()
            .account_global_page(
                actor_key,
                channel,
                watermark,
                after_key,
                after_revision,
                limit,
            )
            .await?)
    }
    async fn account_summary_watermark(&self) -> crate::ServiceResult<i64> {
        Ok(self.0.sync_cursors().account_summary_watermark().await?)
    }
    async fn account_summary_page(
        &self,
        actor_key: &str,
        watermark: i64,
        after: Option<&coland_storage::AccountSummaryKey>,
        limit: usize,
    ) -> crate::ServiceResult<Vec<coland_storage::AccountSummaryVersion>> {
        Ok(self
            .0
            .sync_cursors()
            .account_summary_page(actor_key, watermark, after, limit)
            .await?)
    }
    async fn account_summary_changes(
        &self,
        actor_key: &str,
        after: i64,
        limit: usize,
    ) -> crate::ServiceResult<Vec<coland_storage::AccountSummaryVersion>> {
        Ok(self
            .0
            .sync_cursors()
            .account_summary_changes(actor_key, after, limit)
            .await?)
    }
    async fn get(&self, handle: &str) -> crate::ServiceResult<Option<crate::sync::CursorState>> {
        Ok(self.0.sync_cursors().get(handle).await?)
    }

    async fn upsert(&self, record: &crate::sync::CursorState) -> crate::ServiceResult<()> {
        self.0.sync_cursors().upsert(record).await?;
        Ok(())
    }

    async fn upsert_with_inputs(
        &self,
        record: &crate::sync::CursorState,
        inputs: &[crate::sync::CursorState],
    ) -> crate::ServiceResult<()> {
        self.0
            .sync_cursors()
            .upsert_with_inputs(record, inputs)
            .await?;
        Ok(())
    }

    async fn delete(&self, handle: &str) -> crate::ServiceResult<bool> {
        Ok(self.0.sync_cursors().delete(handle).await?)
    }

    async fn prune_expired(&self, now_ms: i64) -> crate::ServiceResult<usize> {
        Ok(self.0.sync_cursors().prune_expired(now_ms).await?)
    }

    async fn record_revocation(
        &self,
        record: &crate::sync::CursorRevocationState,
    ) -> crate::ServiceResult<()> {
        self.0.sync_cursors().record_revocation(record).await?;
        Ok(())
    }

    async fn active_revocations(
        &self,
        now: chrono::DateTime<chrono::Utc>,
    ) -> crate::ServiceResult<Vec<crate::sync::CursorRevocationState>> {
        Ok(self.0.sync_cursors().active_revocations(now).await?)
    }
}

#[derive(Clone)]
pub struct PersistenceOperationalServices {
    pub federation: FederationService,
    pub governance: GovernanceService,
    pub sync: SyncService,
    pub jobs: JobsService,
}

#[async_trait::async_trait]
impl crate::sync::WebsocketAuthPort for PersistenceWebsocketAuth {
    async fn reserve_connection(
        &self,
        lease: &crate::sync::WebsocketConnectionLease,
    ) -> crate::ServiceResult<bool> {
        Ok(self.0.websocket_auth().reserve_connection(lease).await?)
    }
    async fn release_connection(&self, connection_id: &str) -> crate::ServiceResult<()> {
        Ok(self
            .0
            .websocket_auth()
            .release_connection(connection_id)
            .await?)
    }
    async fn prepare_challenge(
        &self,
        record: &crate::sync::WebsocketChallengeState,
    ) -> crate::ServiceResult<()> {
        Ok(self.0.websocket_auth().prepare_challenge(record).await?)
    }

    async fn challenge(
        &self,
        connection_id: &str,
        nonce: &str,
    ) -> crate::ServiceResult<Option<crate::sync::WebsocketChallengeState>> {
        Ok(self
            .0
            .websocket_auth()
            .get_challenge(connection_id, nonce)
            .await?)
    }

    async fn replay_ledger_contains(
        &self,
        cnf_jkt: &str,
        jti: &str,
        proof_context: &str,
    ) -> crate::ServiceResult<bool> {
        Ok(self
            .0
            .websocket_auth()
            .replay_ledger_contains(cnf_jkt, jti, proof_context)
            .await?)
    }

    async fn consume_challenge(
        &self,
        connection_id: &str,
        nonce: &str,
        replay: &crate::sync::WebsocketReplayState,
    ) -> crate::ServiceResult<bool> {
        Ok(self
            .0
            .websocket_auth()
            .consume_challenge(connection_id, nonce, replay)
            .await?)
    }

    async fn prune_expired(
        &self,
        now: chrono::DateTime<chrono::Utc>,
    ) -> crate::ServiceResult<usize> {
        Ok(self.0.websocket_auth().prune_expired(now).await?)
    }
}

pub fn build_persistence_operational_services(
    persistence: Arc<dyn PersistenceStore>,
    runtime_settings: Arc<dyn RuntimeSettingsPort>,
    runtime_health: Arc<dyn RuntimeHealthPort>,
) -> PersistenceOperationalServices {
    PersistenceOperationalServices {
        federation: FederationService::new(
            Arc::new(PersistenceFederationOutbox(persistence.clone())),
            Arc::new(PersistenceFederationOutbox(persistence.clone())),
        ),
        governance: GovernanceService::new(
            Arc::new(PersistenceAuditLog(persistence.clone())),
            Arc::new(PersistenceModeration(persistence.clone())),
            Arc::new(PersistenceGovernanceRecords(persistence.clone())),
            runtime_settings,
        ),
        sync: SyncService::new(
            Arc::new(PersistenceCursorStore(persistence.clone())),
            Arc::new(PersistenceWebsocketAuth(persistence.clone())),
        ),
        jobs: JobsService::new(
            Arc::new(PersistenceMaintenance(persistence)),
            runtime_health,
        ),
    }
}
