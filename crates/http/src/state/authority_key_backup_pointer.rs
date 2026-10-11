//! Self admission of `ak.key_backup.active_series`.
//!
//! The serving layer only verifies the producer proof against the
//! authenticated session and signs the successor PCR Commit. Whether the
//! pointer may be accepted is decided entirely by the registered storage unit
//! at the locked PCR cut: device status, current authorization Event and
//! generation, source checkpoint, record signature and pointer CAS.

use arkret_wire::{AuthorityCommitStatus, AuthoritySubmitOutcome, EventAdmissionSubmission};
use chrono::Utc;
use coland_services::{ServiceError, ServiceResult};
use coland_storage::{KeyBackupActiveSeriesCommitOutcome, KeyBackupActiveSeriesCommitWrite};

use super::AppState;

pub(super) async fn submit_self_key_backup_pointer(
    state: &AppState,
    request: &EventAdmissionSubmission,
) -> ServiceResult<AuthoritySubmitOutcome> {
    let event = &request.event;
    if event.kind != arkret_wire::EventKind::KeyBackupActiveSeries {
        return Err(ServiceError::Internal(
            "KeyBackup pointer admission received another Event kind".to_owned(),
        ));
    }
    if request.approval_signatures.is_some() {
        return Err(ServiceError::Conflict(
            "self Event approval signatures are not verified".to_owned(),
        ));
    }
    if let Some(existing) = state
        .authority_commits()
        .committed_event(&event.event_id)
        .await?
    {
        if existing.event != *event {
            return Err(ServiceError::Conflict(
                "event_id is already committed with different canonical content".to_owned(),
            ));
        }
        return Ok(AuthoritySubmitOutcome::Accepted {
            status: AuthorityCommitStatus::Duplicate,
            commit: existing.commit,
        });
    }
    let committed_at = Utc::now();
    let method = arkret_wire::DidUrl::new(
        crate::routing::federation::federation_service_signature_key_id(
            state.service_did().as_str(),
        ),
    )
    .map_err(|error| ServiceError::Internal(error.to_string()))?;
    let transaction = state
        .authority_commits()
        .prepare_self_event_transaction(
            event,
            &state.service_core_id(),
            method,
            state.notary_signing_key().as_ref(),
            committed_at,
        )
        .await?;
    let outcome = state
        .key_backups()
        .commit_active_series_pointer(KeyBackupActiveSeriesCommitWrite {
            commit: transaction,
            queued_at: committed_at,
        })
        .await?;
    Ok(match outcome {
        KeyBackupActiveSeriesCommitOutcome::Committed(commit) => AuthoritySubmitOutcome::Accepted {
            status: AuthorityCommitStatus::Committed,
            commit,
        },
        KeyBackupActiveSeriesCommitOutcome::Duplicate(commit) => AuthoritySubmitOutcome::Accepted {
            status: AuthorityCommitStatus::Duplicate,
            commit,
        },
    })
}
