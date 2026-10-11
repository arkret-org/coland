//! Self admission of `ak.identity.accountability_grant`.
//!
//! The serving layer verifies the producer proof against the authenticated
//! session and signs the successor PCR Commit. Whether the endorsement may be
//! accepted -- the issuer is the Event actor, the issuer's signing device is
//! active at the locked PCR cut and both the inner issuer proof and the Event
//! proof verify against its accepted key -- is decided by the registered
//! storage unit, which writes the `identity_accountability` row with the
//! Commit (`zh/models/actor.md` section 3.3.1).

use arkret_wire::{AuthorityCommitStatus, AuthoritySubmitOutcome, EventAdmissionSubmission};
use chrono::Utc;
use coland_services::{ServiceError, ServiceResult};
use coland_storage::{AccountabilityGrantAdmissionOutcome, AccountabilityGrantAdmissionWrite};

use super::AppState;

pub(super) async fn submit_self_accountability_grant(
    state: &AppState,
    request: &EventAdmissionSubmission,
) -> ServiceResult<AuthoritySubmitOutcome> {
    let event = &request.event;
    if event.kind != arkret_wire::EventKind::IdentityAccountabilityGrant {
        return Err(ServiceError::Internal(
            "accountability grant admission received another Event kind".to_owned(),
        ));
    }
    if request.approval_signatures.is_some() {
        return Err(ServiceError::Conflict(
            "self Event approval signatures are not verified".to_owned(),
        ));
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
        .persistence()
        .admit_accountability_grant(AccountabilityGrantAdmissionWrite {
            commit: transaction,
            queued_at: committed_at,
        })
        .await?;
    Ok(match outcome {
        AccountabilityGrantAdmissionOutcome::Committed(record) => {
            AuthoritySubmitOutcome::Accepted {
                status: AuthorityCommitStatus::Committed,
                commit: record.commit,
            }
        }
        AccountabilityGrantAdmissionOutcome::Duplicate(record) => {
            AuthoritySubmitOutcome::Accepted {
                status: AuthorityCommitStatus::Duplicate,
                commit: record.commit,
            }
        }
    })
}
