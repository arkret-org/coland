//! Durable SecurityRotation coordinator worker.
//!
//! `revoke`, `upload_new_material`, `switch_authoritative_pointer` and
//! `erase_old_material` are coordinator-owned steps (security-transactions.md
//! §1.1, §3): the Station advances them, never a client request. Every transition is a
//! registered storage unit, so a sweep that finds a transaction mid-way only
//! resumes it; the process holds no rotation state of its own.

use std::sync::Arc;

use crate::state::AppState;

#[cfg(feature = "test-support")]
#[doc(hidden)]
pub async fn execute_erase_for_test(
    state: &AppState,
    transaction: coland_storage::SecurityTransactionRecord,
    request: &coland_storage::BackupSeriesEraseWorkerRequest,
) -> Result<(), crate::error::AppError> {
    crate::routing::identity::recovery::execute_rotation_erase_for_test(state, transaction, request)
        .await
}

#[async_trait::async_trait]
impl coland_storage::RecoveryInventoryPublicMaterial for AppState {
    async fn governor_head(
        &self,
        realm: &arkret_wire::RealmId,
        service: &arkret_wire::DidCoreId,
    ) -> coland_storage::PersistenceResult<arkret_wire::RealmAuthorityCurrentAssertion> {
        let located =
            crate::routing::realm_join::resolve_verified_authority_of_service(self, realm, service)
                .await
                .map_err(|error| {
                    coland_storage::PersistenceError::Conflict(format!(
                        "revision_unavailable: recovery governor {}",
                        error.wire_code()
                    ))
                })?;
        Ok(located.bundle.current_assertion)
    }

    async fn publication(
        &self,
        blob: &coland_storage::BlobRecord,
    ) -> coland_storage::PersistenceResult<Option<Vec<u8>>> {
        if blob.storage_backend != self.deliveries().object_storage_backend_name() {
            return Ok(None);
        }
        let bytes = self
            .deliveries()
            .get_object(&blob.storage_key)
            .await
            .map_err(coland_storage::PersistenceError::database)?;
        if bytes.len() as i64 != blob.size_bytes
            || arkret_canonical::sha256_hex(&bytes) != blob.sha256
        {
            return Err(coland_storage::PersistenceError::Conflict(
                "revision_unavailable: MLS publication differs from its registered Blob".into(),
            ));
        }
        Ok(Some(bytes))
    }
}

pub fn spawn(state: AppState) -> Arc<tokio::task::JoinHandle<()>> {
    let interval =
        std::time::Duration::from_secs(state.config().security_rotation_worker_interval_seconds);
    Arc::new(tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        loop {
            ticker.tick().await;
            crate::routing::identity::recovery::sweep_rotation_worker(&state).await;
            if let Err(error) = state
                .security_transactions()
                .prepare_content_recoveries(&state.service_core_id(), Some(&state))
                .await
            {
                tracing::warn!(%error, "content recovery inventory worker deferred");
            }
            if let Err(error) = sweep_realm_device_revocations(&state).await {
                tracing::warn!(%error, "Realm Device revoke worker deferred");
            }
        }
    }))
}

pub async fn sweep_realm_device_revocations(
    state: &AppState,
) -> coland_services::ServiceResult<usize> {
    state
        .authority_commits()
        .sweep_realm_actor_device_revocations(&state.service_core_id())
        .await
}
