//! Durable physical-erasure execution derived from accepted immutable
//! account-status records. The record is the command; this worker owns no
//! parallel peer API.

use std::sync::Arc;

use arkret_models_collaboration::governance::erasure::ErasureStorageBoundary;
use arkret_wire::AccountStatusRecordId;
use chrono::{Duration, Utc};
use coland_storage::{AccountErasureExecution, AccountErasureExecutionState as ExecutionState};

use crate::error::AppError;
use crate::state::AppState;

const POLL_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5);

fn execution_principal_id(state: &AppState) -> arkret_wire::DidCoreId {
    state.service_core_id()
}

fn execution_key(record_id: &AccountStatusRecordId, state: ExecutionState) -> String {
    AccountErasureExecution::key_for(record_id, state)
}

fn execution_hash(execution: &AccountErasureExecution) -> Result<String, AppError> {
    execution
        .request_hash()
        .map_err(|error| AppError::internal(error.to_string()))
}

/// Verify the original execution intent atomically retained by terminal
/// replica admission before the receiver acknowledges. This path never creates
/// a second intent or repairs a hand-seeded, incomplete admission.
pub async fn ensure_intent(
    state: &AppState,
    account_authority_id: &str,
    account_id: &arkret_wire::AccountId,
    principal_id: &arkret_wire::DidCoreId,
    record_id: &AccountStatusRecordId,
) -> Result<(), AppError> {
    let principal_idempotency_id = execution_principal_id(state);
    let key = execution_key(record_id, ExecutionState::Pending);
    let execution = AccountErasureExecution {
        receiver_id: arkret_wire::DidCoreId::new(state.service_id().to_owned())
            .map_err(|error| AppError::internal(format!("service DID invalid: {error}")))?,
        account_authority_id: arkret_wire::DidCoreId::new(account_authority_id.to_owned())
            .map_err(|error| {
                AppError::internal(format!("Account Authority DID invalid: {error}"))
            })?,
        account_id: account_id.clone(),
        principal_id: principal_id.clone(),
        triggering_status_record_id: record_id.clone(),
        storage_boundary: ErasureStorageBoundary::AccountPrivateStore,
        state: ExecutionState::Pending,
        package: None,
    };
    let request_hash = execution_hash(&execution)?;
    if let Some(existing) = state
        .jobs()
        .idempotency_record(&principal_idempotency_id, &key)
        .await
        .map_err(|error| AppError::internal(format!("erasure intent lookup: {error}")))?
    {
        let original: AccountErasureExecution = serde_json::from_value(existing.response_body)
            .map_err(|error| AppError::internal(format!("erasure intent decode: {error}")))?;
        if existing.request_hash != request_hash
            || original != execution
            || existing.response_status != 202
        {
            return Err(AppError::conflict(
                "erasure execution key is bound to different coordinates",
            ));
        }
        return Ok(());
    }
    Err(AppError::internal(
        "accepted terminal record has no atomic erasure intent",
    ))
}

async fn store_execution(
    state: &AppState,
    execution: &AccountErasureExecution,
    created_at: chrono::DateTime<Utc>,
) -> Result<(), AppError> {
    state
        .jobs()
        .store_idempotency_record(coland_services::jobs::IdempotencyState {
            authenticated_actor: arkret_wire::ActorId::service(execution_principal_id(state)),
            operation_id: coland_services::jobs::INTERNAL_IDEMPOTENCY_OPERATION.to_owned(),
            idempotency_key: execution_key(&execution.triggering_status_record_id, execution.state),
            request_hash: execution_hash(execution)?,
            response_status: if execution.state == ExecutionState::Pending {
                202
            } else {
                200
            },
            response_body: serde_json::to_value(execution).map_err(|error| {
                AppError::internal(format!("erasure execution encode: {error}"))
            })?,
            created_at,
            expires_at: created_at + Duration::days(36_500),
        })
        .await
        .map_err(|error| AppError::internal(format!("erasure execution store: {error}")))
}

async fn run_execution(
    state: &AppState,
    account_id: &arkret_wire::AccountId,
    principal_id: &arkret_wire::DidCoreId,
    record_id: &AccountStatusRecordId,
    account_authority_id: &arkret_wire::DidCoreId,
) -> Result<(), AppError> {
    ensure_intent(
        state,
        account_authority_id.as_str(),
        account_id,
        principal_id,
        record_id,
    )
    .await?;
    let principal_idempotency_id = execution_principal_id(state);
    let mut stored = None;
    for phase in [
        ExecutionState::FanoutEnqueued,
        ExecutionState::Completed,
        ExecutionState::Pending,
    ] {
        if let Some(record) = state
            .jobs()
            .idempotency_record(&principal_idempotency_id, &execution_key(record_id, phase))
            .await
            .map_err(|error| AppError::internal(format!("erasure execution lookup: {error}")))?
        {
            stored = Some(record);
            break;
        }
    }
    let stored = stored
        .ok_or_else(|| AppError::internal("erasure execution disappeared after intent store"))?;
    let mut execution: AccountErasureExecution = serde_json::from_value(stored.response_body)
        .map_err(|error| AppError::internal(format!("erasure execution decode: {error}")))?;
    if execution_hash(&execution)? != stored.request_hash {
        return Err(AppError::conflict(
            "stored erasure execution coordinates do not match their digest",
        ));
    }
    if execution.state == ExecutionState::Pending {
        crate::routing::identity::account::lifecycle::prepare_account_status_erasure(
            state,
            &execution.account_id,
        )
        .await?;
        let sign = |completed_at| {
            crate::routing::identity::account::lifecycle::account_status_erasure_package(
                state,
                &execution.account_id,
                &execution.triggering_status_record_id,
                completed_at,
            )
            .map_err(|error| coland_storage::PersistenceError::Internal(error.to_string()))
        };
        execution = state
            .persistence()
            .complete_account_erasure(&execution, &sign)
            .await
            .map_err(|error| AppError::internal(format!("atomic erasure completion: {error}")))?;
    }
    if execution.state == ExecutionState::Completed {
        let package = execution
            .package
            .as_ref()
            .ok_or_else(|| AppError::internal("completed erasure execution has no receipt"))?;
        crate::routing::federation::erasure_receipts::persist_issued_package(
            state,
            package,
            &execution.account_authority_id,
        )
        .await?;
        crate::routing::identity::account::lifecycle::fanout_erasure_receipt(
            state,
            package,
            Some(&execution.account_id),
        )
        .await?;
        execution.state = ExecutionState::FanoutEnqueued;
        store_execution(state, &execution, stored.created_at).await?;
    }
    Ok(())
}

/// Reconcile every accepted terminal record using the intent retained in its
/// same admission transaction. No second command carrier or repair ledger exists.
pub async fn run_once(state: &AppState) -> Result<usize, AppError> {
    let mut processed = 0_usize;
    for record in state
        .persistence()
        .erasure_pending_account_status_records(256)
        .await
        .map_err(|error| AppError::internal(format!("erasure record scan: {error}")))?
    {
        run_execution(
            state,
            &record.account_id,
            &record.account_id.principal_id,
            &record.account_status_record_id,
            &record.account_authority_id,
        )
        .await?;
        processed += 1;
    }
    Ok(processed)
}

pub fn spawn(state: AppState) -> Arc<tokio::task::JoinHandle<()>> {
    Arc::new(tokio::spawn(async move {
        let mut ticker = tokio::time::interval(POLL_INTERVAL);
        loop {
            ticker.tick().await;
            if let Err(error) = run_once(&state).await {
                tracing::error!(%error, worker = "account_erasure", "erasure reconciliation failed");
            }
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn execution(state: ExecutionState) -> AccountErasureExecution {
        AccountErasureExecution {
            receiver_id: arkret_wire::DidCoreId::new(
                "ak:did_core:web:principal.example".to_owned(),
            )
            .unwrap(),
            account_authority_id: arkret_wire::DidCoreId::new(
                "ak:did_core:web:authority.example".to_owned(),
            )
            .unwrap(),
            account_id: arkret_wire::AccountId::new(
                arkret_wire::DidCoreId::new("ak:did_core:web:alice.example".to_owned()).unwrap(),
                arkret_wire::DidCoreId::new("ak:did_core:web:principal.example".to_owned())
                    .unwrap(),
            ),
            principal_id: arkret_wire::DidCoreId::new("ak:did_core:web:alice.example".to_owned())
                .unwrap(),
            triggering_status_record_id: AccountStatusRecordId::new(
                "ak:account_status_record:AY9h1b8J8DX3jG8mPz1mLzWwPrZ_leEIRy9ANidKfcQa".to_owned(),
            )
            .unwrap(),
            storage_boundary: ErasureStorageBoundary::AccountPrivateStore,
            state,
            package: None,
        }
    }

    #[test]
    fn append_only_phases_keep_one_coordinate_digest() {
        let pending = execution(ExecutionState::Pending);
        let completed = execution(ExecutionState::Completed);

        assert_eq!(
            execution_hash(&pending).unwrap(),
            execution_hash(&completed).unwrap()
        );
        assert_ne!(
            execution_key(
                &pending.triggering_status_record_id,
                ExecutionState::Pending
            ),
            execution_key(
                &pending.triggering_status_record_id,
                ExecutionState::Completed
            )
        );
        assert_ne!(
            execution_key(
                &pending.triggering_status_record_id,
                ExecutionState::Completed
            ),
            execution_key(
                &pending.triggering_status_record_id,
                ExecutionState::FanoutEnqueued
            )
        );
    }

    #[test]
    fn authority_source_is_part_of_execution_coordinates() {
        let original = execution(ExecutionState::Pending);
        let mut different_authority = original.clone();
        different_authority.account_authority_id =
            arkret_wire::DidCoreId::new("ak:did_core:web:other-authority.example".to_owned())
                .unwrap();

        assert_ne!(
            execution_hash(&original).unwrap(),
            execution_hash(&different_authority).unwrap()
        );
    }
}
