//! Durable physical-erasure execution derived from accepted immutable
//! account-status records. The record is the command; this worker owns no
//! parallel peer API.

use std::sync::Arc;

use arkret_models_collaboration::governance::erasure::{
    ErasureReceiptPackage, ErasureStorageBoundary,
};
use arkret_wire::AccountStatusRecordId;
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};

use crate::error::AppError;
use crate::state::AppState;

const POLL_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ExecutionState {
    Pending,
    Completed,
    FanoutEnqueued,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AccountErasureExecution {
    receiver_id: arkret_wire::DidCoreId,
    account_authority_id: arkret_wire::DidCoreId,
    account_id: arkret_wire::AccountId,
    principal_id: arkret_wire::DidCoreId,
    triggering_status_record_id: AccountStatusRecordId,
    storage_boundary: ErasureStorageBoundary,
    state: ExecutionState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    package: Option<ErasureReceiptPackage>,
}

fn execution_principal_id(state: &AppState) -> arkret_wire::DidCoreId {
    state.service_core_id()
}

fn execution_key(record_id: &AccountStatusRecordId, state: ExecutionState) -> String {
    let phase = match state {
        ExecutionState::Pending => "intent",
        ExecutionState::Completed => "completed",
        ExecutionState::FanoutEnqueued => "fanout_enqueued",
    };
    format!("{}:account_private_store:{phase}", record_id.as_str())
}

fn execution_hash(execution: &AccountErasureExecution) -> Result<String, AppError> {
    #[derive(Serialize)]
    struct Coordinates<'a> {
        receiver_id: &'a arkret_wire::DidCoreId,
        account_authority_id: &'a arkret_wire::DidCoreId,
        account_id: &'a arkret_wire::AccountId,
        principal_id: &'a arkret_wire::DidCoreId,
        triggering_status_record_id: &'a AccountStatusRecordId,
        storage_boundary: ErasureStorageBoundary,
    }
    arkret_canonical::canonical_sha256(&Coordinates {
        receiver_id: &execution.receiver_id,
        account_authority_id: &execution.account_authority_id,
        account_id: &execution.account_id,
        principal_id: &execution.principal_id,
        triggering_status_record_id: &execution.triggering_status_record_id,
        storage_boundary: execution.storage_boundary,
    })
    .map_err(|error| AppError::internal(format!("erasure execution digest: {error}")))
}

/// Persist the execution intent before the account-status receiver acknowledges
/// an erasure_pending record. Exact replay is a no-op; any coordinate change is
/// a permanent duplicate conflict.
pub async fn ensure_intent(
    state: &AppState,
    account_authority_id: &str,
    account_id: &arkret_wire::AccountId,
    principal_id: &arkret_wire::DidCoreId,
    record_id: &AccountStatusRecordId,
) -> Result<(), AppError> {
    if state
        .identities()
        .account(account_id)
        .await
        .map_err(|error| AppError::internal(format!("erasure boundary applicability: {error}")))?
        .is_none()
    {
        // Foreign canonical content is another storage boundary. It does not
        // create an Account-private execution owned by this deployment.
        return Ok(());
    }
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
        if existing.request_hash != request_hash {
            return Err(AppError::conflict(
                "erasure execution key is bound to different coordinates",
            ));
        }
        return Ok(());
    }
    let created_at = Utc::now();
    state
        .jobs()
        .store_idempotency_record(coland_services::jobs::IdempotencyState {
            authenticated_actor: arkret_wire::ActorId::service(principal_idempotency_id),
            operation_id: coland_services::jobs::INTERNAL_IDEMPOTENCY_OPERATION.to_owned(),
            idempotency_key: key,
            request_hash,
            response_status: 202,
            response_body: serde_json::to_value(&execution)
                .map_err(|error| AppError::internal(format!("erasure intent encode: {error}")))?,
            created_at,
            expires_at: created_at + Duration::days(36_500),
        })
        .await
        .map_err(|error| AppError::internal(format!("erasure intent store: {error}")))
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
) -> Result<(), AppError> {
    let account_authority_id =
        crate::routing::events::peer::trusted_account_authority_id(state).await?;
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
        let package = crate::routing::identity::account::lifecycle::execute_account_status_erasure(
            state,
            &execution.account_id,
            &execution.triggering_status_record_id,
        )
        .await?;
        execution.package = Some(package);
        execution.state = ExecutionState::Completed;
        store_execution(state, &execution, stored.created_at).await?;
        let completed = state
            .jobs()
            .idempotency_record(
                &principal_idempotency_id,
                &execution_key(record_id, ExecutionState::Completed),
            )
            .await
            .map_err(|error| AppError::internal(format!("erasure completion lookup: {error}")))?
            .ok_or_else(|| AppError::internal("erasure completion was not persisted"))?;
        execution = serde_json::from_value(completed.response_body)
            .map_err(|error| AppError::internal(format!("erasure completion decode: {error}")))?;
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

/// Reconcile every accepted erasure_pending record. This makes a crash between
/// replica commit and intent persistence recoverable without introducing a
/// second command carrier.
pub async fn run_once(state: &AppState) -> Result<usize, AppError> {
    let mut processed = 0_usize;
    let mut failed = 0_usize;
    for record in state
        .persistence()
        .erasure_pending_account_status_records(256)
        .await
        .map_err(|error| AppError::internal(format!("erasure record scan: {error}")))?
    {
        if state
            .identities()
            .account(&record.account_id)
            .await
            .map_err(|error| {
                AppError::internal(format!("erasure boundary applicability: {error}"))
            })?
            .is_none()
        {
            continue;
        }
        let execution = run_execution(
            state,
            &record.account_id,
            &record.account_id.principal_id,
            &record.account_status_record_id,
        )
        .await;
        match execution {
            Ok(()) => processed += 1,
            Err(error) => {
                failed += 1;
                tracing::error!(%error,account_id=%record.account_id,record_id=%record.account_status_record_id,"Account-private erasure remains incomplete");
            }
        }
    }
    if failed > 0 {
        return Err(AppError::internal(format!(
            "{failed} Account-private erasure executions remain incomplete; {processed} others processed"
        )));
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
