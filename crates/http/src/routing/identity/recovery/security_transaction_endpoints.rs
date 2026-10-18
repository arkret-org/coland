use arkret_event_draft::EventPayloadExt as _;
use arkret_models_crypto::{
    AcceptedSecurityTransactionStep as AcceptedStep, PcrPolicyRecoveryBinding,
    PcrPolicyRecoveryPlan, RecoveryIdentityModel, RecoveryTransactionCreateRequest,
    SecurityTransactionAcceptor, SecurityTransactionPreparedPlan, SecurityTransactionStep,
    SecurityTransactionTerminalOutcome,
};
use arkret_wire::{ActorId, DidCoreId, SchemaId};
use coland_services::identity::{
    BackupSeriesEraseProgressState, SecurityTransactionStepAttemptState,
    SecurityTransactionStepOutcomeState,
};
use ed25519_dalek::Signer as _;

use super::*;

fn transaction_account(request: &SecurityTransactionCreateRequest) -> &arkret_wire::AccountId {
    match request {
        SecurityTransactionCreateRequest::Recovery(request) => &request.account_id,
        SecurityTransactionCreateRequest::SecurityRotation(request) => &request.account_id,
    }
}

fn recovery_transaction_session_id(
    request: &SecurityTransactionCreateRequest,
) -> Option<&arkret_identifiers::RecoverySessionId> {
    match request {
        SecurityTransactionCreateRequest::Recovery(request) => {
            Some(&request.recovery_intent.recovery_session_id)
        }
        SecurityTransactionCreateRequest::SecurityRotation(_) => None,
    }
}

async fn enforce_recovery_grant_transaction_binding(
    state: &AppState,
    session: &SessionRecord,
    recovery_session_id: Option<&arkret_identifiers::RecoverySessionId>,
) -> Result<(), AppError> {
    let Some(grant) = session.session_grant.as_ref().filter(|grant| {
        grant.credential_class
            == arkret_models_identity::SessionGrantCredentialClass::RecoverySession
    }) else {
        return Ok(());
    };
    let recovery_session_id = recovery_session_id.ok_or_else(|| {
        AppError::capability_denied(
            "recovery session grant cannot authorize a security-rotation transaction",
        )
    })?;
    let recovery = state
        .recovery_sessions()
        .session(recovery_session_id.as_str())
        .await
        .map_err(recovery_service_error)?
        .ok_or_else(|| AppError::not_found("recovery session not found"))?;
    if recovery.principal_id.as_str() != session.actor
        || recovery.station_id.as_str() != session.audience
        || recovery.requesting_device_id.as_str() != session.require_human_device_id()
        || recovery.session_grant_id != grant.grant_id.as_str()
        || recovery.session_grant_cnf_jkt != grant.cnf_jkt
    {
        return Err(AppError::capability_denied(
            "security transaction recovery session does not match the presented recovery grant",
        ));
    }
    Ok(())
}

async fn load_owned_security_transaction(
    state: &AppState,
    session: &SessionRecord,
    transaction_id: &str,
) -> Result<SecurityTransactionRecord, AppError> {
    TransactionId::new(transaction_id.to_owned())
        .map_err(|error| AppError::param_invalid(error.to_string()))?;
    let record = state
        .security_transactions()
        .transaction(transaction_id)
        .await
        .map_err(recovery_service_error)?
        .ok_or_else(|| AppError::not_found("security transaction not found"))?;
    let transaction_actor =
        transaction_account_actor(&record.resource.account_id, &state.service_core_id())?;
    let session_actor =
        crate::routing::identity::session_actor::session_actor_from_credential(state, session)?;
    if transaction_actor != session_actor {
        // The standard read contract deliberately makes an invisible
        // transaction indistinguishable from a missing one.
        return Err(AppError::not_found("security transaction not found"));
    }
    let recovery_session_id = record
        .resource
        .recovery_plan()
        .map(|plan| &plan.binding.recovery_session_id);
    enforce_recovery_grant_transaction_binding(state, session, recovery_session_id).await?;
    Ok(record)
}

/// The authorizing device's lifecycle at the confirmed PCR cut. The legacy
/// device inventory is not an authority for rotation (§4).
async fn authorizing_device_active(
    state: &AppState,
    account_id: &AccountId,
    device_id: &DeviceId,
) -> Result<bool, AppError> {
    state
        .persistence()
        .pcr_device_admission(account_id, device_id, chrono::Utc::now())
        .await
        .map(|admission| admission == arkret_wire::DeviceRevocationAdmissionDecision::Allow)
        .map_err(|error| {
            tracing::warn!(%error, "PCR device status unavailable for security rotation");
            crate::app_error!(
                TemporarilyUnavailable,
                "PCR device status is unavailable; retry the same request",
            )
        })
}

fn transaction_account_actor(
    account_id: &AccountId,
    local_station_id: &DidCoreId,
) -> Result<ActorId, AppError> {
    // The coordinator of a Station-local transaction is `account_id.station_id`
    // and nothing else. Never substitute the current Station for a foreign one.
    if &account_id.station_id != local_station_id {
        return Err(AppError::not_found("security transaction not found"));
    }
    Ok(ActorId::account(account_id.clone()))
}

#[salvo::oapi::endpoint(
    operation_id = "ak.self.security_transaction.command.create",
    tags("identity")
)]
#[tracing::instrument(
    skip_all,
    fields(op = "ak.self.security_transaction.command.create.v1")
)]
pub(super) async fn security_transaction_create(
    aa: AuthArgs,
    body: JsonBody<SecurityTransactionCreateRequest>,
    depot: &mut Depot,
    res: &mut Response,
    req: &mut Request,
) -> JsonResult<SecurityTransaction> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let request = body.into_inner();
    let session_actor =
        crate::routing::identity::session_actor::session_actor_from_credential(state, &session)?;
    if ActorId::account(transaction_account(&request).clone()) != session_actor {
        return Err(crate::app_error!(
            CapabilityDenied,
            "security transaction account_id does not match the authenticated account",
        )
        .with_internal_reason("security_transaction_principal_isolation"));
    }
    enforce_recovery_grant_transaction_binding(
        state,
        &session,
        recovery_transaction_session_id(&request),
    )
    .await?;
    if let SecurityTransactionCreateRequest::SecurityRotation(rotation) = &request
        && (rotation.authorizing_device_id.as_str() != session.require_human_device_id()
            || state.account_lifecycle_state(session.actor.as_str()) != "active"
            || !authorizing_device_active(
                state,
                &rotation.account_id,
                &rotation.authorizing_device_id,
            )
            .await?)
    {
        return Err(crate::app_error!(
            Unauthenticated,
            "security rotation requires fresh high-risk authentication by the authorizing device",
        )
        .with_wire_code("reauthentication_required"));
    }
    // §2.1 — a recovery create request never carries a finished plan. The
    // Station derives it here, in the same durable prepare that freezes the
    // canonical request bytes, and that prepare produces no recovery effect:
    // no accepted Event, no committed Seal, no generation advance, no activated
    // device, no consumed session, no terminal result.
    let prepared_plan = match &request {
        SecurityTransactionCreateRequest::Recovery(recovery) => {
            SecurityTransactionPreparedPlan::Recovery(
                prepare_recovery_plan(state, &session, recovery).await?,
            )
        }
        SecurityTransactionCreateRequest::SecurityRotation(rotation) => {
            SecurityTransactionPreparedPlan::SecurityRotation(rotation.prepared_plan.clone())
        }
    };
    let (resource, canonical_request) = request
        .into_initial_resource(prepared_plan, chrono::Utc::now())
        .map_err(|error| AppError::schema_violation(error.to_string()))?;
    if transaction_account_actor(&resource.account_id, &state.service_core_id())?
        != crate::routing::identity::session_actor::session_actor_from_credential(state, &session)?
    {
        return Err(AppError::capability_denied(
            "security transaction does not match the authenticated account",
        )
        .with_internal_reason("security_transaction_principal_isolation"));
    }
    let stored = state
        .security_transactions()
        .create(SecurityTransactionRecord {
            canonical_request,
            resource,
        })
        .await
        .map_err(security_transaction_service_error)?;
    let resource = if stored.resource.security_rotation_plan().is_some() {
        // The durable worker owns `revoke`, `upload_new_material`,
        // `switch_authoritative_pointer` and `erase_old_material`; drive them
        // now rather than waiting for the next sweep, then answer with the
        // durable resource.
        advance_rotation(state, stored.resource.transaction_id.as_str()).await;
        state
            .security_transactions()
            .transaction(stored.resource.transaction_id.as_str())
            .await
            .map_err(recovery_service_error)?
            .map_or(stored.resource, |record| record.resource)
    } else {
        stored.resource
    };
    res.status_code(StatusCode::OK);
    json_ok(resource)
}

#[salvo::oapi::endpoint(
    operation_id = "ak.self.security_transaction.resource.get",
    tags("identity")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.security_transaction.resource.get.v1"))]
pub(super) async fn security_transaction_get(
    aa: AuthArgs,
    transaction_id: PathParam<String>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<SecurityTransaction> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let record = load_owned_security_transaction(
        state,
        &aa.authenticated_session(state, req).await?,
        transaction_id.into_inner().as_str(),
    )
    .await?;
    json_ok(record.resource)
}

#[salvo::oapi::endpoint(
    operation_id = "ak.self.security_transaction.command.continue",
    tags("identity")
)]
#[tracing::instrument(
    skip_all,
    fields(op = "ak.self.security_transaction.command.continue.v1")
)]
pub(super) async fn security_transaction_continue(
    aa: AuthArgs,
    transaction_id: PathParam<String>,
    body: JsonBody<SecurityTransactionContinueRequest>,
    depot: &mut Depot,
    res: &mut Response,
    req: &mut Request,
) -> JsonResult<SecurityTransaction> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let transaction_id = transaction_id.into_inner();
    let request = body.into_inner();
    let canonical_request = arkret_canonical::canonical_json_bytes(&request)
        .map_err(|error| AppError::param_invalid(error.to_string()))?;
    let session = aa.authenticated_session(state, req).await?;
    let transaction = load_owned_security_transaction(state, &session, &transaction_id).await?;
    let expected_count = usize::try_from(request.expected_accepted_step_count).map_err(|_| {
        crate::app_error!(FailedPrecondition, "accepted step count is out of range")
    })?;
    if transaction.resource.accepted_steps.len() != expected_count {
        // A lost response is retried with the same bytes after the step was
        // accepted; it reads the first stored result instead of failing.
        let accepted_step = transaction
            .resource
            .step_order()
            .ok()
            .and_then(|order| order.get(expected_count).copied())
            .filter(|_| expected_count < transaction.resource.accepted_steps.len());
        if let Some(step) = accepted_step
            && let Some(stored) = state
                .security_transactions()
                .step_outcome(&transaction_id, step)
                .await
                .map_err(recovery_service_error)?
            && stored.canonical_request == canonical_request
        {
            let resource = serde_json::from_value(stored.response).map_err(|error| {
                AppError::internal(format!(
                    "stored security transaction response invalid: {error}"
                ))
            })?;
            res.status_code(StatusCode::OK);
            return json_ok(resource);
        }
        return Err(crate::app_error!(
            FailedPrecondition,
            "security transaction accepted step count changed",
        ));
    }
    let requested_step = transaction
        .resource
        .next_required_step()
        .map_err(|error| crate::app_error!(FailedPrecondition, error.to_string()))?
        .ok_or_else(|| {
            crate::app_error!(
                FailedPrecondition,
                "security transaction has no remaining step",
            )
        })?;

    if let Some(stored) = state
        .security_transactions()
        .step_outcome(&transaction_id, requested_step)
        .await
        .map_err(recovery_service_error)?
    {
        if stored.canonical_request != canonical_request {
            return Err(AppError::conflict(
                "security transaction step already accepted different canonical request bytes",
            )
            .with_wire_code("duplicate_conflict"));
        }
        let resource = serde_json::from_value(stored.response).map_err(|error| {
            AppError::internal(format!(
                "stored security transaction response invalid: {error}"
            ))
        })?;
        res.status_code(StatusCode::OK);
        return json_ok(resource);
    }

    request
        .validate_for_transaction(&transaction.resource)
        .map_err(|error| crate::app_error!(FailedPrecondition, error.to_string()))?;
    if transaction.resource.expires_at <= chrono::Utc::now() {
        return Err(
            crate::app_error!(FailedPrecondition, "security transaction has expired")
                .with_internal_reason("security_transaction_expired"),
        );
    }

    match requested_step {
        SecurityTransactionStep::CommitRecoveryUnit => {
            continue_commit_recovery_unit(
                state,
                &session,
                transaction,
                request,
                canonical_request,
                res,
            )
            .await
        }
        SecurityTransactionStep::Revoke
        | SecurityTransactionStep::UploadNewMaterial
        | SecurityTransactionStep::SwitchAuthoritativePointer
        | SecurityTransactionStep::EraseOldMaterial => Err(crate::app_error!(
            FailedPrecondition,
            "coordinator-owned rotation steps are advanced only by the Station's durable worker",
        )),
        SecurityTransactionStep::LocalCommit => {
            continue_rotation_local_commit(
                state,
                &session,
                transaction,
                request,
                canonical_request,
                res,
            )
            .await
        }
    }
}

fn rotation_plan(
    transaction: &SecurityTransactionRecord,
) -> Result<arkret_models_crypto::SecurityRotationPlan, AppError> {
    match &transaction.resource.prepared_plan {
        SecurityTransactionPreparedPlan::SecurityRotation(plan) => Ok(plan.clone()),
        _ => Err(crate::app_error!(
            FailedPrecondition,
            "rotation step requires a SecurityRotationTransaction"
        )),
    }
}

async fn begin_rotation_step(
    state: &AppState,
    transaction_id: &str,
    step: SecurityTransactionStep,
    canonical_request: &[u8],
) -> Result<(), AppError> {
    state
        .security_transactions()
        .begin_step(SecurityTransactionStepAttemptState {
            transaction_id: transaction_id.to_owned(),
            step,
            canonical_request: canonical_request.to_vec(),
        })
        .await
        .map_err(security_transaction_service_error)?;
    Ok(())
}

/// Upper bound of transactions one worker sweep drives.
const ROTATION_WORKER_SWEEP_LIMIT: u32 = 32;

/// One pass of the durable SecurityRotation worker over every live rotation
/// whose next step is coordinator-owned.
pub(crate) async fn sweep_rotation_worker(state: &AppState) {
    let pending = match state
        .security_transactions()
        .rotations_awaiting_worker(ROTATION_WORKER_SWEEP_LIMIT)
        .await
    {
        Ok(pending) => pending,
        Err(error) => {
            tracing::warn!(%error, "rotation worker sweep could not list pending transactions");
            return;
        }
    };
    for transaction_id in pending {
        advance_rotation(state, &transaction_id).await;
    }
}

/// Drive every coordinator-owned step of one SecurityRotation that is ready
/// (security-transactions.md §1.1, §3): `revoke`, then `upload_new_material`,
/// then `switch_authoritative_pointer`, then `erase_old_material`. Each
/// transition is durable on its own, so the loop stops at the first step that
/// makes no durable progress and the next sweep resumes exactly there. The
/// client-attested `local_commit` is left to `continue`.
pub(crate) async fn advance_rotation(state: &AppState, transaction_id: &str) {
    for _ in 0..4 {
        match try_advance_rotation_step(state, transaction_id).await {
            Ok(true) => {}
            Ok(false) => return,
            Err(error) => {
                tracing::warn!(
                    %error,
                    transaction_id,
                    "rotation step deferred to the next worker sweep"
                );
                return;
            }
        }
    }
}

/// Run the one step the durable resource names next. `Ok(true)` means the
/// resource changed (a step, a proposal or a terminal outcome was stored).
async fn try_advance_rotation_step(
    state: &AppState,
    transaction_id: &str,
) -> Result<bool, coland_services::ServiceError> {
    // Partial erase progress is durable but does not change the resource;
    // the loop then stops and the next sweep resumes the remaining objects.
    let progress = |record: &SecurityTransactionRecord| {
        (
            record.resource.accepted_steps.len(),
            record.resource.revoke_proposal.is_some(),
            record.resource.terminal_outcome.is_some(),
        )
    };
    let Some(before) = state
        .security_transactions()
        .transaction(transaction_id)
        .await?
    else {
        return Ok(false);
    };
    let next = before
        .resource
        .next_required_step()
        .map_err(|error| coland_services::ServiceError::Internal(error.to_string()))?;
    match next {
        Some(SecurityTransactionStep::Revoke) => {
            try_advance_rotation_revoke(state, transaction_id).await?;
        }
        Some(SecurityTransactionStep::UploadNewMaterial) => {
            try_advance_rotation_upload(state, before.clone()).await?;
        }
        Some(SecurityTransactionStep::SwitchAuthoritativePointer) => {
            try_advance_rotation_switch(state, before.clone()).await?;
        }
        Some(SecurityTransactionStep::EraseOldMaterial) => {
            try_advance_rotation_erase(state, before.clone()).await?;
        }
        _ => return Ok(false),
    }
    let after = state
        .security_transactions()
        .transaction(transaction_id)
        .await?;
    Ok(after.is_some_and(|after| progress(&after) != progress(&before)))
}

/// Drive the coordinator-owned `revoke` step of one SecurityRotation
/// (security-transactions.md §3; decision 0102).
///
/// The prepared `ak.device.revoke` first enters the PCR as an immutable
/// pending proposal: the registered storage unit rechecks, under the PCR
/// authority lock, that the authorizing device is active and signed the Event
/// with its current key, and commits Event, covering RealmCommit, proposal
/// dot and `revoke_proposal` in one PostgreSQL
/// transaction. The terminal unit then commits `revoke_command_outcome`
/// together with `accepted_steps[0]`. Between the two the target device is
/// pending and fails closed; a crash there is resumed by the next sweep,
/// which finds the stored proposal and only decides it.
///
/// A refusal that retrying cannot change aborts a transaction that has no
/// proposal; expiry writes `expired`, with the rejected result exactly when a
/// proposal exists. Anything else is left for the next sweep.
async fn try_advance_rotation_revoke(
    state: &AppState,
    transaction_id: &str,
) -> Result<(), coland_services::ServiceError> {
    use arkret_models_crypto::{
        SecurityRotationRevokeCommandDecision, SecurityRotationRevokeCommandOutcome,
        SecurityRotationRevokeProposal,
    };
    use coland_services::ServiceError;
    use coland_services::identity::{RevokeCommandTerminalWrite, RevokeProposalCommitWrite};

    let internal = |error: &dyn std::fmt::Display| ServiceError::Internal(error.to_string());
    let Some(transaction) = state
        .security_transactions()
        .transaction(transaction_id)
        .await?
    else {
        return Ok(());
    };
    let resource = &transaction.resource;
    if resource.next_required_step().map_err(|e| internal(&e))?
        != Some(SecurityTransactionStep::Revoke)
        || resource.revoke_command_outcome.is_some()
    {
        return Ok(());
    }
    let Some(plan) = resource.security_rotation_plan().cloned() else {
        return Ok(());
    };
    let now = chrono::Utc::now();
    if resource.expires_at <= now {
        return expire_rotation_revoke(state, transaction).await;
    }
    let [submission] = plan.revoke_unit.request.events.as_slice() else {
        return abort_rotation_revoke(state, transaction, None).await;
    };
    let event = &submission.event;

    let proposed = match &resource.revoke_proposal {
        Some(_) => transaction,
        None => {
            let method = DidUrl::new(
                crate::routing::federation::federation_service_signature_key_id(
                    state.service_did().as_str(),
                ),
            )
            .map_err(|e| internal(&e))?;
            let commit = state
                .authority_commits()
                .prepare_self_event_transaction(
                    event,
                    &state.service_core_id(),
                    method,
                    state.notary_signing_key().as_ref(),
                    now,
                )
                .await?;
            let mut proposed = transaction.clone();
            proposed.resource.revoke_proposal = Some(SecurityRotationRevokeProposal {
                proposal_event_id: event.event_id.clone(),
                covering_commit_id: commit.commit.commit_id.clone(),
            });
            let admitted = state
                .security_transactions()
                .commit_revoke_proposal(RevokeProposalCommitWrite {
                    transaction: proposed.clone(),
                    commit,
                    queued_at: now,
                })
                .await;
            match admitted {
                Ok(_) => proposed,
                Err(error) => {
                    return match permanent_revoke_refusal(&error) {
                        Some(reason_code) => {
                            tracing::warn!(
                                %error,
                                transaction_id,
                                "rotation revoke proposal refused; aborting the transaction"
                            );
                            abort_rotation_revoke(state, transaction, reason_code).await
                        }
                        None => Err(error),
                    };
                }
            }
        }
    };

    // Crash-consistency fault injection between the proposal and its
    // decision. Empty outside development mode.
    if state
        .config()
        .failpoints
        .scope(
            crate::failpoints::FailpointId::SecurityRotationRevokeTerminal,
            true,
        )
        .trips_before_next_step()
    {
        return Err(ServiceError::Conflict(
            "temporarily_unavailable: revoke decision deferred by a development failpoint"
                .to_owned(),
        ));
    }
    let proposal = proposed
        .resource
        .revoke_proposal
        .clone()
        .expect("proposal present on this branch");
    let decided_at = chrono::Utc::now();
    let outcome = SecurityRotationRevokeCommandOutcome {
        proposal_event_id: proposal.proposal_event_id,
        covering_commit_id: proposal.covering_commit_id.clone(),
        result: SecurityRotationRevokeCommandDecision::Accepted,
        decided_at,
    };
    let mut decided = proposed;
    decided.resource.revoke_command_outcome = Some(outcome);
    decided.resource.accepted_steps.push(AcceptedStep {
        acceptor: SecurityTransactionAcceptor::Principal {
            principal_id: state.service_core_id(),
        },
        accepted_at: decided_at,
    });
    decided
        .resource
        .validate_structural()
        .map_err(|e| internal(&e))?;
    let response = serde_json::to_value(&decided.resource).map_err(|e| internal(&e))?;
    // The worker's step request is the transaction's own canonical request:
    // the coordinator-owned step takes no client bytes.
    let canonical_request = decided.canonical_request.clone();
    state
        .security_transactions()
        .commit_revoke_command_terminal(RevokeCommandTerminalWrite {
            step_outcome: Some(SecurityTransactionStepOutcomeState {
                transaction_id: decided.resource.transaction_id.as_str().to_owned(),
                step: SecurityTransactionStep::Revoke,
                canonical_request,
                response,
                participant_outcome: None,
            }),
            transaction: decided,
        })
        .await?;
    Ok(())
}

/// Refusals of the proposal unit that no retry can change, mapped to the
/// registered reason code the aborted terminal carries (if any).
fn permanent_revoke_refusal(error: &coland_services::ServiceError) -> Option<Option<String>> {
    use coland_storage::ConflictCode;

    if matches!(
        error.kind(),
        coland_services::ServiceErrorKind::SchemaViolation
    ) {
        return Some(None);
    }
    match error.conflict_code()? {
        ConflictCode::SignatureInvalid => Some(Some("proof_invalid".to_owned())),
        ConflictCode::DuplicateConflict => Some(Some("duplicate_conflict".to_owned())),
        ConflictCode::SchemaViolation
        | ConflictCode::FailedPrecondition
        | ConflictCode::DeviceRevoked => Some(None),
        _ => None,
    }
}

/// A rotation that never admitted its proposal terminates without a command
/// result (§3: an admission failure has no proposal and no result).
async fn abort_rotation_revoke(
    state: &AppState,
    mut transaction: SecurityTransactionRecord,
    reason_code: Option<String>,
) -> Result<(), coland_services::ServiceError> {
    debug_assert!(transaction.resource.revoke_proposal.is_none());
    transaction.resource.terminal_outcome = Some(SecurityTransactionTerminalOutcome::Aborted {
        completed_at: chrono::Utc::now(),
        reason_code,
    });
    state.security_transactions().save(transaction).await
}

/// Expiry: with an accepted proposal the rejected result and the `expired`
/// terminal commit together; without one the transaction simply expires.
async fn expire_rotation_revoke(
    state: &AppState,
    mut transaction: SecurityTransactionRecord,
) -> Result<(), coland_services::ServiceError> {
    use arkret_models_crypto::{
        SecurityRotationRevokeCommandDecision, SecurityRotationRevokeCommandOutcome,
    };
    use coland_services::identity::RevokeCommandTerminalWrite;

    let expires_at = transaction.resource.expires_at;
    transaction.resource.terminal_outcome = Some(SecurityTransactionTerminalOutcome::Expired {
        completed_at: expires_at,
        reason_code: None,
    });
    let Some(proposal) = transaction.resource.revoke_proposal.clone() else {
        return state.security_transactions().save(transaction).await;
    };
    transaction.resource.revoke_command_outcome = Some(SecurityRotationRevokeCommandOutcome {
        proposal_event_id: proposal.proposal_event_id,
        covering_commit_id: proposal.covering_commit_id,
        result: SecurityRotationRevokeCommandDecision::Rejected,
        decided_at: expires_at,
    });
    state
        .security_transactions()
        .commit_revoke_command_terminal(RevokeCommandTerminalWrite {
            transaction,
            step_outcome: None,
        })
        .await
        .map(|_| ())
}

/// The worker's step request is the transaction's own canonical request: a
/// coordinator-owned step takes no client bytes.
fn worker_step_outcome(
    transaction: &SecurityTransactionRecord,
    step: SecurityTransactionStep,
) -> Result<SecurityTransactionStepOutcomeState, coland_services::ServiceError> {
    Ok(SecurityTransactionStepOutcomeState {
        transaction_id: transaction.resource.transaction_id.as_str().to_owned(),
        step,
        canonical_request: transaction.canonical_request.clone(),
        response: serde_json::to_value(&transaction.resource)
            .map_err(|error| coland_services::ServiceError::Internal(error.to_string()))?,
        participant_outcome: None,
    })
}

/// Append one Station-accepted worker step for its atomic storage unit.
fn with_worker_step(
    state: &AppState,
    transaction: &SecurityTransactionRecord,
    accepted_at: chrono::DateTime<chrono::Utc>,
) -> Result<SecurityTransactionRecord, coland_services::ServiceError> {
    let mut next = transaction.clone();
    next.resource.accepted_steps.push(AcceptedStep {
        acceptor: SecurityTransactionAcceptor::Principal {
            principal_id: state.service_core_id(),
        },
        accepted_at,
    });
    next.resource
        .validate_structural()
        .map_err(|error| coland_services::ServiceError::Internal(error.to_string()))?;
    Ok(next)
}

/// A refusal of a worker unit that no retry can change, with the reason code
/// the aborted terminal carries. Only a registered-code conflict is final; a
/// retryable code, an unavailable dependency or an infrastructure failure is
/// left for the next sweep (and, at worst, for expiry).
fn permanent_worker_refusal(error: &coland_services::ServiceError) -> Option<Option<String>> {
    use coland_storage::ConflictCode;

    if error.kind() != coland_services::ServiceErrorKind::Conflict {
        return None;
    }
    match error.conflict_code() {
        Some(ConflictCode::TemporarilyUnavailable) => None,
        Some(ConflictCode::SignatureInvalid) => Some(Some("proof_invalid".to_owned())),
        Some(code) => Some(Some(code.as_str().to_owned())),
        None => {
            let detail = error.detail();
            let token = detail.split_once(": ").map_or(detail, |(head, _)| head);
            let is_code = !token.is_empty()
                && token
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_');
            Some(is_code.then(|| token.to_owned()))
        }
    }
}

/// Stop a rotation whose accepted prefix cannot advance: expired at its
/// deadline, or aborted on a final refusal. Accepted facts stay accepted.
async fn stop_rotation(
    state: &AppState,
    mut transaction: SecurityTransactionRecord,
    reason_code: Option<Option<String>>,
) -> Result<(), coland_services::ServiceError> {
    transaction.resource.terminal_outcome = Some(match reason_code {
        None => SecurityTransactionTerminalOutcome::Expired {
            completed_at: transaction.resource.expires_at,
            reason_code: None,
        },
        Some(reason_code) => SecurityTransactionTerminalOutcome::Aborted {
            completed_at: chrono::Utc::now(),
            reason_code,
        },
    });
    state.security_transactions().save(transaction).await
}

/// `upload_new_material`: store every planned replacement envelope of the
/// frozen material and accept the step, atomically. The serving-layer
/// envelope checks run first; the storage unit rechecks the authorizing
/// device, its current authorization, each signature, the fresh series chain
/// and the reserved ids at the locked PCR cut.
async fn try_advance_rotation_upload(
    state: &AppState,
    transaction: SecurityTransactionRecord,
) -> Result<(), coland_services::ServiceError> {
    let internal =
        |error: &dyn std::fmt::Display| coland_services::ServiceError::Internal(error.to_string());
    let now = chrono::Utc::now();
    if transaction.resource.expires_at <= now {
        return stop_rotation(state, transaction, None).await;
    }
    let Some(plan) = transaction.resource.security_rotation_plan().cloned() else {
        return Ok(());
    };
    for rotation in &plan.backup_rotations {
        for backup in &rotation.new_backup_envelopes {
            let value = serde_json::to_value(backup).map_err(|error| internal(&error))?;
            if let Err(error) =
                crate::routing::identity::key_backup::validate_rotation_replacement_backup(
                    state, &value,
                )
                .await
            {
                if error.http_status().is_server_error() {
                    return Err(internal(&error));
                }
                let reason = error.wire_code().to_owned();
                return stop_rotation(state, transaction, Some(Some(reason))).await;
            }
        }
    }
    let next = with_worker_step(state, &transaction, now)?;
    let step_outcome = worker_step_outcome(&next, SecurityTransactionStep::UploadNewMaterial)?;
    match state
        .security_transactions()
        .commit_rotation_upload(coland_storage::RotationUploadCommitWrite {
            transaction: next,
            step_outcome,
        })
        .await
    {
        Ok(_) => Ok(()),
        Err(error) => match permanent_worker_refusal(&error) {
            Some(reason_code) => {
                tracing::warn!(%error, "rotation upload refused; aborting the transaction");
                stop_rotation(state, transaction, Some(reason_code)).await
            }
            None => Err(error),
        },
    }
}

/// `switch_authoritative_pointer`: the Station signs the successor PCR Commit
/// for the prepared `ak.key_backup.active_series` Event, and the storage unit
/// admits it through the registered same-cut pointer unit (active signer,
/// current authorization and generation, exactly one version up from the
/// planned previous series) together with the accepted step.
async fn try_advance_rotation_switch(
    state: &AppState,
    transaction: SecurityTransactionRecord,
) -> Result<(), coland_services::ServiceError> {
    let internal =
        |error: &dyn std::fmt::Display| coland_services::ServiceError::Internal(error.to_string());
    let now = chrono::Utc::now();
    if transaction.resource.expires_at <= now {
        return stop_rotation(state, transaction, None).await;
    }
    let Some(plan) = transaction.resource.security_rotation_plan().cloned() else {
        return Ok(());
    };
    let [rotation] = plan.backup_rotations.as_slice() else {
        return stop_rotation(
            state,
            transaction,
            Some(Some("schema_violation".to_owned())),
        )
        .await;
    };
    let [submission] = rotation.active_series_unit.request.events.as_slice() else {
        return stop_rotation(
            state,
            transaction,
            Some(Some("schema_violation".to_owned())),
        )
        .await;
    };
    let event = &submission.event;
    let method = DidUrl::new(
        crate::routing::federation::federation_service_signature_key_id(
            state.service_did().as_str(),
        ),
    )
    .map_err(|e| internal(&e))?;
    let commit = state
        .authority_commits()
        .prepare_self_event_transaction(
            event,
            &state.service_core_id(),
            method,
            state.notary_signing_key().as_ref(),
            now,
        )
        .await?;
    let next = with_worker_step(state, &transaction, now)?;
    let step_outcome =
        worker_step_outcome(&next, SecurityTransactionStep::SwitchAuthoritativePointer)?;
    match state
        .security_transactions()
        .commit_rotation_pointer_switch(coland_storage::RotationPointerSwitchWrite {
            transaction: next,
            step_outcome,
            commit,
            queued_at: now,
        })
        .await
    {
        Ok(_) => Ok(()),
        Err(error) => match permanent_worker_refusal(&error) {
            Some(reason_code) => {
                tracing::warn!(%error, "rotation pointer switch refused; aborting the transaction");
                stop_rotation(state, transaction, Some(reason_code)).await
            }
            None => Err(error),
        },
    }
}

/// `erase_old_material`: the worker builds the one internal erase request
/// from the saved plan (security-transactions.md §3) and executes it. A
/// request whose progress is already durable is resumed with its exact first
/// bytes; otherwise the authority basis is the confirmed PCR cut of the still
/// active authorizing device. A refusal of an execution-time precondition
/// stops the rotation before any further deletion; partial storage progress
/// stays durable and is resumed by the next sweep.
async fn try_advance_rotation_erase(
    state: &AppState,
    transaction: SecurityTransactionRecord,
) -> Result<(), coland_services::ServiceError> {
    use coland_storage::BackupSeriesEraseWorkerRequest;

    let internal =
        |error: &dyn std::fmt::Display| coland_services::ServiceError::Internal(error.to_string());
    let now = chrono::Utc::now();
    if transaction.resource.expires_at <= now {
        return stop_rotation(state, transaction, None).await;
    }
    let Some(plan) = transaction.resource.security_rotation_plan().cloned() else {
        return Ok(());
    };
    let resource = &transaction.resource;
    let transaction_id = resource.transaction_id.as_str().to_owned();
    let (request, canonical_request) = match state
        .security_transactions()
        .backup_erase_progress(&transaction_id)
        .await?
    {
        Some(progress) => (
            serde_json::from_slice::<BackupSeriesEraseWorkerRequest>(&progress.canonical_request)
                .map_err(|e| internal(&e))?,
            progress.canonical_request,
        ),
        None => {
            let Some(authorizer) = resource.authorizing_device_id.clone() else {
                return stop_rotation(
                    state,
                    transaction,
                    Some(Some("schema_violation".to_owned())),
                )
                .await;
            };
            if state
                .persistence()
                .pcr_device_admission(&resource.account_id, &authorizer, now)
                .await?
                != arkret_wire::DeviceRevocationAdmissionDecision::Allow
            {
                return stop_rotation(
                    state,
                    transaction,
                    Some(Some("failed_precondition".to_owned())),
                )
                .await;
            }
            let confirmed = state
                .key_backups()
                .confirmed_active_series_for_device(&resource.account_id, &authorizer, now)
                .await?
                .ok_or_else(|| {
                    coland_services::ServiceError::Conflict(
                        "temporarily_unavailable: the confirmed backup pointer is absent"
                            .to_owned(),
                    )
                })?;
            let request = BackupSeriesEraseWorkerRequest {
                transaction_id: resource.transaction_id.clone(),
                transaction_request_digest: resource.request_digest.clone(),
                prepared_plan_digest: resource.prepared_plan_digest.clone(),
                erase_confirmation_digest: plan.erase_confirmation_digest.clone(),
                series: plan
                    .backup_rotations
                    .iter()
                    .map(|rotation| rotation.binding.clone())
                    .collect(),
                authority_commit_id: confirmed.authority_commit_id,
            };
            request.validate_structural().map_err(|e| internal(&e))?;
            let canonical_request =
                arkret_canonical::canonical_json_bytes(&request).map_err(|e| internal(&e))?;
            (request, canonical_request)
        }
    };
    match execute_rotation_erase(state, transaction.clone(), &request, canonical_request).await {
        Ok(_) => Ok(()),
        Err(error) if error.http_status().is_server_error() => Err(internal(&error)),
        Err(error) => {
            tracing::warn!(
                error = %error,
                transaction_id,
                "rotation erase refused before deletion; stopping the transaction"
            );
            let reason = error.wire_code().to_owned();
            stop_rotation(state, transaction, Some(Some(reason))).await
        }
    }
}

fn backup_rotation_kind_name(kind: arkret_models_crypto::BackupRotationKind) -> &'static str {
    match kind {
        arkret_models_crypto::BackupRotationKind::SecretStorage => "secret_storage",
    }
}

fn initial_backup_erase_outcome(
    request: &coland_storage::BackupSeriesEraseWorkerRequest,
) -> Result<coland_storage::BackupSeriesEraseOutcome, AppError> {
    use coland_storage::{
        BackupSeriesEraseOutcome, BackupSeriesEraseRow, BackupSeriesEraseRowStatus,
        BackupSeriesEraseStatus,
    };

    let request_digest = Hash::new(
        arkret_canonical::canonical_sha256(request)
            .map_err(|error| AppError::internal(format!("erase request digest failed: {error}")))?,
    )
    .map_err(|error| AppError::internal(error.to_string()))?;
    let series_records = request
        .series
        .iter()
        .map(|rotation| {
            let mut remaining_backups = rotation.old_backups.clone();
            remaining_backups
                .sort_by(|left, right| left.backup_id.as_str().cmp(right.backup_id.as_str()));
            BackupSeriesEraseRow {
                backup_kind: rotation.backup_kind,
                previous_series_id: rotation.previous_series_id.clone(),
                new_series_id: rotation.new_series_id.clone(),
                status: BackupSeriesEraseRowStatus::Pending,
                erased_backups: Vec::new(),
                remaining_backups,
                reason_code: None,
            }
        })
        .collect();
    let outcome = BackupSeriesEraseOutcome {
        transaction_id: request.transaction_id.clone(),
        request_digest,
        status: BackupSeriesEraseStatus::Partial,
        series_records,
        confirmation: None,
    };
    outcome.validate_for_request(request).map_err(|error| {
        AppError::internal(format!("initial backup erase progress is invalid: {error}"))
    })?;
    Ok(outcome)
}

fn backup_value_matches_rotation(
    value: &Value,
    actor_id: &ActorId,
    series_id: &arkret_wire::BackupSeriesId,
    backup_kind: arkret_models_crypto::BackupRotationKind,
    expected: &arkret_models_crypto::BackupObjectRef,
) -> bool {
    value.get("backup_id").and_then(Value::as_str) == Some(expected.backup_id.as_str())
        && value.get("ciphertext_digest").and_then(Value::as_str)
            == Some(expected.ciphertext_digest.as_str())
        && value.get("actor_id").is_some_and(|value| {
            serde_json::from_value::<ActorId>(value.clone()).is_ok_and(|actor| &actor == actor_id)
        })
        && value.get("series_id").and_then(Value::as_str) == Some(series_id.as_str())
        && value.get("backup_kind").and_then(Value::as_str)
            == Some(backup_rotation_kind_name(backup_kind))
}

fn refresh_backup_erase_completion(
    outcome: &mut coland_storage::BackupSeriesEraseOutcome,
    request: &coland_storage::BackupSeriesEraseWorkerRequest,
) -> bool {
    use arkret_models_crypto::BackupSeriesEraseConfirmation;
    use coland_storage::BackupSeriesEraseStatus;

    let complete = outcome
        .series_records
        .iter()
        .all(|result| result.remaining_backups.is_empty());
    outcome.status = if complete {
        BackupSeriesEraseStatus::Complete
    } else {
        BackupSeriesEraseStatus::Partial
    };
    outcome.confirmation = complete.then(|| BackupSeriesEraseConfirmation {
        schema: SchemaId::BackupSeriesEraseConfirmationV1,
        transaction_id: request.transaction_id.clone(),
        transaction_request_digest: request.transaction_request_digest.clone(),
        prepared_plan_digest: request.prepared_plan_digest.clone(),
        series: request.series.clone(),
    });
    complete
}

/// Execute `erase_old_material` for the durable rotation worker
/// (security-transactions.md §3). `request` is the internal erase request the
/// worker built from the saved plan; immediately before any deletion every
/// execution-time precondition is rechecked (live transaction, active
/// Account, active authorizing device, current authority basis, authoritative
/// new series). Progress persists per object and is monotonic; the step is
/// accepted only with the complete outcome and its canonical confirmation.
async fn execute_rotation_erase(
    state: &AppState,
    mut transaction: SecurityTransactionRecord,
    request: &coland_storage::BackupSeriesEraseWorkerRequest,
    canonical_request: Vec<u8>,
) -> Result<coland_storage::BackupSeriesEraseOutcome, AppError> {
    use coland_storage::BackupSeriesEraseRowStatus;

    let request = request.clone();
    let transaction_id = transaction.resource.transaction_id.as_str().to_owned();
    let plan = rotation_plan(&transaction)?;
    let transaction_actor =
        transaction_account_actor(&transaction.resource.account_id, &state.service_core_id())?;
    let planned_series_match = plan.backup_rotations.len() == request.series.len()
        && plan
            .backup_rotations
            .iter()
            .zip(&request.series)
            .all(|(prepared, requested)| prepared.binding == *requested);
    let now = chrono::Utc::now();
    let authorizing_device_id = transaction
        .resource
        .authorizing_device_id
        .as_ref()
        .ok_or_else(|| {
            crate::app_error!(
                FailedPrecondition,
                "security rotation is missing its authorizing device",
            )
        })?;
    if transaction
        .resource
        .next_required_step()
        .map_err(|error| AppError::internal(error.to_string()))?
        != Some(SecurityTransactionStep::EraseOldMaterial)
        || transaction.resource.request_digest != request.transaction_request_digest
        || transaction.resource.prepared_plan_digest != request.prepared_plan_digest
        || plan.erase_confirmation_digest != request.erase_confirmation_digest
        || !planned_series_match
        || transaction.resource.expires_at <= now
        || state.account_lifecycle_state(transaction.resource.account_id.principal_id.as_str())
            != "active"
    {
        return Err(crate::app_error!(
            FailedPrecondition,
            "backup-series erase request is not authorized for this transaction",
        ));
    }
    let existing_progress = state
        .security_transactions()
        .backup_erase_progress(&transaction_id)
        .await
        .map_err(security_transaction_service_error)?;
    // One PCR snapshot answers whether the authorizing device is still active
    // and what the authoritative secret_storage pointer is (§3 step 4). On the
    // first attempt, its covering Commit must be the exact basis frozen into
    // the request. Once durable progress exists, an unrelated later PCR Commit
    // does not stale the frozen bytes; pointer and generation checks below are
    // the normative retry guards.
    let confirmed = state
        .key_backups()
        .confirmed_active_series_for_device(
            &transaction.resource.account_id,
            authorizing_device_id,
            now,
        )
        .await
        .ok()
        .flatten()
        .ok_or_else(|| {
            crate::app_error!(
                FailedPrecondition,
                "authorizing device or confirmed backup pointer is not current",
            )
        })?;
    if existing_progress.is_none() && confirmed.authority_commit_id != request.authority_commit_id {
        return Err(crate::app_error!(
            FailedPrecondition,
            "backup-series erase authority Commit does not match the current pointer",
        ));
    }
    for prepared in &plan.backup_rotations {
        let rotation = &prepared.binding;
        for expected in &rotation.new_backups {
            let Some(stored) = state
                .key_backups()
                .backup(expected.backup_id.as_str())
                .await
                .map_err(recovery_service_error)?
            else {
                return Err(crate::app_error!(
                    FailedPrecondition,
                    "replacement backup is missing before old-series erasure",
                ));
            };
            if !backup_value_matches_rotation(
                &stored,
                &transaction_actor,
                &rotation.new_series_id,
                rotation.backup_kind,
                expected,
            ) {
                return Err(crate::app_error!(
                    FailedPrecondition,
                    "replacement backup identity, series, kind, or digest changed before erasure",
                ));
            }
        }
        let active = state
            .event_queries()
            .accepted_event(rotation.active_series_event_id.as_str())
            .await
            .map_err(recovery_service_error)?
            .filter(|event| event.kind == arkret_wire::EventKind::KeyBackupActiveSeries.as_str())
            .and_then(|event| {
                serde_json::from_value::<
                    arkret_models_collaboration::events_payloads::KeyBackupActiveSeries,
                >(event.envelope.get("payload")?.clone())
                .ok()
            })
            .ok_or_else(|| {
                crate::app_error!(
                    FailedPrecondition,
                    "replacement active-series Event is not accepted"
                )
            })?;
        // The frozen basis is the pointer this rotation switched to: its new
        // series and `series_pointer_version` must still be the authoritative
        // pointer, verbatim.
        if !matches!(
            &confirmed.secret_storage,
            arkret_models_crypto::BackupActiveSeriesPointer::Active {
                active_series_id,
                series_pointer_version,
            } if active_series_id == &rotation.new_series_id
                && *series_pointer_version == active.series_pointer_version
        ) || active.active_series_id != rotation.new_series_id
            || !active
                .previous_series_ids
                .contains(&rotation.previous_series_id)
        {
            return Err(crate::app_error!(
                FailedPrecondition,
                "replacement backup series pointer changed before old-series erasure",
            ));
        }
        let generation = crate::routing::identity::device_generation::current_device_generation(
            state,
            transaction.resource.account_id.principal_id.as_str(),
        )
        .await
        .map_err(recovery_service_error)?;
        if generation.map(|generation| generation.current_ref)
            != Some(active.source_commit_ref.device_generation_ref)
        {
            return Err(crate::app_error!(
                FailedPrecondition,
                "the PCR device generation changed before old-series erasure",
            ));
        }
    }

    // Crash-consistency fault injection. Only the first attempt of a
    // transaction is armed, so the retry that must prove resumability runs the
    // real storage path. Empty outside development mode.
    let mut erase_failpoint = state.config().failpoints.scope(
        crate::failpoints::FailpointId::BackupSeriesEraseDurableStep,
        existing_progress.is_none(),
    );
    if existing_progress.is_none() {
        for prepared in &plan.backup_rotations {
            let rotation = &prepared.binding;
            for old in &rotation.old_backups {
                let existing = state
                    .key_backups()
                    .backup(old.backup_id.as_str())
                    .await
                    .map_err(recovery_service_error)?
                    .ok_or_else(|| {
                        crate::app_error!(
                            FailedPrecondition,
                            "planned old backup is missing before erasure begins"
                        )
                    })?;
                if !backup_value_matches_rotation(
                    &existing,
                    &transaction_actor,
                    &rotation.previous_series_id,
                    rotation.backup_kind,
                    old,
                ) {
                    return Err(crate::app_error!(
                        FailedPrecondition,
                        "planned old backup identity, series, kind, or digest changed before erasure",
                    ));
                }
            }
        }
    }
    begin_rotation_step(
        state,
        &transaction_id,
        SecurityTransactionStep::EraseOldMaterial,
        &canonical_request,
    )
    .await?;

    let mut progress = match existing_progress {
        Some(progress) => {
            if progress.canonical_request != canonical_request {
                return Err(AppError::conflict(
                    "backup-series erase already began with different canonical bytes",
                )
                .with_wire_code("duplicate_conflict"));
            }
            progress
                .outcome
                .validate_for_request(&request)
                .map_err(|error| AppError::internal(error.to_string()))?;
            progress
        }
        None => state
            .security_transactions()
            .begin_backup_erase(BackupSeriesEraseProgressState {
                transaction_id: transaction_id.clone(),
                canonical_request: canonical_request.clone(),
                outcome: initial_backup_erase_outcome(&request)?,
            })
            .await
            .map_err(security_transaction_service_error)?,
    };

    for result_index in 0..progress.outcome.series_records.len() {
        let remaining = progress.outcome.series_records[result_index]
            .remaining_backups
            .clone();
        let mut storage_failed = false;
        for old in remaining {
            if erase_failpoint.trips_before_next_step() {
                storage_failed = true;
                continue;
            }
            if let Some(existing) = state
                .key_backups()
                .backup(old.backup_id.as_str())
                .await
                .map_err(recovery_service_error)?
                && !backup_value_matches_rotation(
                    &existing,
                    &transaction_actor,
                    &request.series[result_index].previous_series_id,
                    request.series[result_index].backup_kind,
                    &old,
                )
            {
                return Err(crate::app_error!(
                    FailedPrecondition,
                    "planned old backup changed while erasure was in progress",
                ));
            }
            if state
                .key_backups()
                .delete_backup(old.backup_id.as_str())
                .await
                .is_err()
            {
                storage_failed = true;
                continue;
            }
            erase_failpoint.record_durable_step();
            let result = &mut progress.outcome.series_records[result_index];
            result
                .remaining_backups
                .retain(|reference| reference.backup_id != old.backup_id);
            if !result
                .erased_backups
                .iter()
                .any(|reference| reference.backup_id == old.backup_id)
            {
                result.erased_backups.push(old);
                result
                    .erased_backups
                    .sort_by(|left, right| left.backup_id.as_str().cmp(right.backup_id.as_str()));
            }
            result.status = if result.remaining_backups.is_empty() {
                BackupSeriesEraseRowStatus::Erased
            } else {
                BackupSeriesEraseRowStatus::Pending
            };
            result.reason_code = None;
            refresh_backup_erase_completion(&mut progress.outcome, &request);
            progress = state
                .security_transactions()
                .update_backup_erase(progress)
                .await
                .map_err(security_transaction_service_error)?;
        }
        let result = &mut progress.outcome.series_records[result_index];
        if storage_failed && !result.remaining_backups.is_empty() {
            result.status = BackupSeriesEraseRowStatus::FailedRetryable;
            result.reason_code = Some(arkret_wire::ReasonCode::from_wire(
                "storage_temporarily_unavailable",
            ));
            progress = state
                .security_transactions()
                .update_backup_erase(progress)
                .await
                .map_err(security_transaction_service_error)?;
        }
    }
    let complete = refresh_backup_erase_completion(&mut progress.outcome, &request);
    progress = state
        .security_transactions()
        .update_backup_erase(progress)
        .await
        .map_err(security_transaction_service_error)?;
    let outcome = progress.outcome;
    outcome.validate_for_request(&request).map_err(|error| {
        AppError::internal(format!("backup-series erase outcome is invalid: {error}"))
    })?;
    if !complete {
        return Ok(outcome);
    }

    transaction.resource.accepted_steps.push(AcceptedStep {
        acceptor: SecurityTransactionAcceptor::Principal {
            principal_id: state.service_core_id(),
        },
        accepted_at: chrono::Utc::now(),
    });
    transaction
        .resource
        .validate_structural()
        .map_err(|error| AppError::internal(error.to_string()))?;
    let response = serde_json::to_value(&transaction.resource)
        .map_err(|error| AppError::internal(error.to_string()))?;
    let participant_outcome =
        serde_json::to_value(&outcome).map_err(|error| AppError::internal(error.to_string()))?;
    state
        .security_transactions()
        .accept_step(
            transaction,
            SecurityTransactionStepOutcomeState {
                transaction_id,
                step: SecurityTransactionStep::EraseOldMaterial,
                canonical_request,
                response,
                participant_outcome: Some(participant_outcome),
            },
        )
        .await
        .map_err(security_transaction_service_error)?;
    Ok(outcome)
}

/// `local_commit`, the client-attested terminal step of a SecurityRotation.
/// The artifact must copy the durable transaction and plan references, name
/// the session's own device, and its outer attestation must be signed with
/// that device's key. The key, the verification method binding and the
/// device's `active` status are all decided by the registered storage unit
/// at the locked PCR cut from the device's current accepted authorization;
/// no device mirror or session record supplies key material.
#[cfg(feature = "test-support")]
pub(crate) async fn execute_rotation_erase_for_test(
    state: &AppState,
    transaction: SecurityTransactionRecord,
    request: &coland_storage::BackupSeriesEraseWorkerRequest,
) -> Result<(), AppError> {
    let canonical_request = arkret_canonical::canonical_json_bytes(request)
        .map_err(|error| AppError::internal(error.to_string()))?;
    execute_rotation_erase(state, transaction, request, canonical_request)
        .await
        .map(|_| ())
}

async fn continue_rotation_local_commit(
    state: &AppState,
    session: &SessionRecord,
    mut transaction: SecurityTransactionRecord,
    request: SecurityTransactionContinueRequest,
    canonical_request: Vec<u8>,
    res: &mut Response,
) -> JsonResult<SecurityTransaction> {
    let plan = rotation_plan(&transaction)?;
    let attestation = request.client_attestation;
    let arkret_models_crypto::ClientStepAttestationArtifact::SecurityRotation(commit) =
        &attestation.artifact
    else {
        return Err(AppError::schema_violation(
            "local commit requires SecurityRotationLocalCommit",
        ));
    };
    if commit.transaction_id != transaction.resource.transaction_id
        || commit.transaction_request_digest != transaction.resource.request_digest
        || commit.prepared_plan_digest != transaction.resource.prepared_plan_digest
        || commit.local_commit_digest != plan.local_commit_digest
        || commit.device_id.as_str() != session.require_human_device_id()
    {
        return Err(crate::app_error!(
            FailedPrecondition,
            "local commit artifact changed the durable rotation plan"
        ));
    }
    let participant_outcome =
        serde_json::to_value(commit).map_err(|error| AppError::internal(error.to_string()))?;
    let accepted_at = chrono::Utc::now();
    transaction.resource.accepted_steps.push(AcceptedStep {
        acceptor: SecurityTransactionAcceptor::Principal {
            principal_id: state.service_core_id(),
        },
        accepted_at,
    });
    transaction.resource.terminal_outcome = Some(SecurityTransactionTerminalOutcome::Completed {
        completed_at: accepted_at,
        receipt_id: None,
        completion_attestation: None,
    });
    transaction
        .resource
        .validate_structural()
        .map_err(|error| AppError::internal(error.to_string()))?;
    let response = serde_json::to_value(&transaction.resource)
        .map_err(|error| AppError::internal(error.to_string()))?;
    let step_outcome = SecurityTransactionStepOutcomeState {
        transaction_id: transaction.resource.transaction_id.as_str().to_owned(),
        step: SecurityTransactionStep::LocalCommit,
        canonical_request,
        response,
        participant_outcome: Some(participant_outcome),
    };
    let stored = state
        .security_transactions()
        .commit_rotation_local_commit(coland_services::identity::RotationLocalCommitWrite {
            transaction,
            step_outcome,
            attestation,
        })
        .await
        .map_err(local_commit_refusal)?;
    res.status_code(StatusCode::OK);
    json_ok(stored.resource)
}

/// The local-commit unit refuses in registered conflict codes. Only an exact
/// canonical-bytes conflict and an unavailable PCR cut keep their own code;
/// every other refusal (inactive device, foreign verification method, bad
/// signature, drifted resource) is the operation's `failed_precondition`.
fn local_commit_refusal(error: coland_services::ServiceError) -> AppError {
    use coland_storage::ConflictCode;

    match error.conflict_code() {
        Some(ConflictCode::DuplicateConflict) => {
            AppError::conflict(error.detail()).with_wire_code("duplicate_conflict")
        }
        Some(ConflictCode::TemporarilyUnavailable) => {
            crate::app_error!(TemporarilyUnavailable, "{}", error.detail())
        }
        Some(_) => crate::app_error!(FailedPrecondition, "{}", error.detail()),
        None if error.kind() == coland_services::ServiceErrorKind::Conflict => {
            crate::app_error!(FailedPrecondition, "{}", error.detail())
        }
        None => security_transaction_service_error(error),
    }
}

/// The replacement device submits the signed recovery receipt. The Station
/// signs consecutive PCR RealmCommits for the prepared Events, then stores
/// both Commits, session consumption and terminal result in one transaction.
async fn continue_commit_recovery_unit(
    state: &AppState,
    session: &SessionRecord,
    mut transaction: SecurityTransactionRecord,
    request: SecurityTransactionContinueRequest,
    canonical_request: Vec<u8>,
    res: &mut Response,
) -> JsonResult<SecurityTransaction> {
    let attestation = &request.client_attestation;
    attestation
        .validate()
        .map_err(|error| AppError::schema_violation(error.to_string()))?;
    let arkret_models_crypto::ClientStepAttestationArtifact::Recovery(terminal_commit) =
        &attestation.artifact
    else {
        return Err(AppError::schema_violation(
            "terminal recovery requires RecoveryTerminalCommit",
        ));
    };
    terminal_commit
        .validate()
        .map_err(|error| AppError::schema_violation(error.to_string()))?;
    let receipt = &terminal_commit.recovery_receipt;
    let (binding, plan) = pcr_policy_parts(&transaction.resource)?;
    let binding = binding.clone();
    let plan = plan.clone();
    let [reanchor_submission, authorize_submission] = plan.reanchor_unit.request.events.as_slice()
    else {
        return Err(AppError::internal(
            "prepared recovery Event pair is malformed",
        ));
    };
    let (reanchor_event, authorize_event) =
        (&reanchor_submission.event, &authorize_submission.event);
    if session.require_human_device_id() != binding.replacement_device_id.as_str()
        || receipt.receipt_id != binding.terminal_receipt_id
        || receipt.transaction_id != transaction.resource.transaction_id
        || receipt.transaction_request_digest != transaction.resource.request_digest
        || receipt.prepared_plan_digest != transaction.resource.prepared_plan_digest
        || receipt.account_id != transaction.resource.account_id
        || receipt.recovery_session_id != binding.recovery_session_id
        || receipt.new_device_id != binding.replacement_device_id
        || receipt.identity_model != RecoveryIdentityModel::PcrPolicy
        || receipt.recovery_authority_kind != arkret_models_crypto::RecoveryAuthorityKind::PcrPolicy
        || receipt.previous_model_generation_ref != plan.previous_model_generation_ref
        || receipt.result_model_generation_ref != plan.result_model_generation_ref
        || receipt.authorization_event_id != binding.authorize_event_id
        || receipt.reanchor_event_id != binding.reanchor_event_id
        || receipt.proof_summary.proof_digest != plan.proof_digest
        || receipt.outcome != arkret_models_crypto::RecoveryReceiptOutcome::Completed
        || attestation.step != SecurityTransactionStep::CommitRecoveryUnit
        || attestation.output_ref != receipt.receipt_id.as_str()
        || attestation.transaction_id != transaction.resource.transaction_id
        || attestation.transaction_request_digest != transaction.resource.request_digest
        || attestation.prepared_plan_digest != transaction.resource.prepared_plan_digest
    {
        return Err(crate::app_error!(
            FailedPrecondition,
            "terminal recovery receipt changed the durable prepared binding"
        ));
    }
    let recovery_session = state
        .recovery_sessions()
        .session(binding.recovery_session_id.as_str())
        .await
        .map_err(recovery_service_error)?
        .ok_or_else(|| {
            crate::app_error!(FailedPrecondition, "bound recovery session unavailable")
        })?;
    let proof_summary = recovery_proof_summary(&recovery_session).ok_or_else(|| {
        crate::app_error!(
            FailedPrecondition,
            "verified recovery proof summary unavailable"
        )
    })?;
    if recovery_session.state != SessionState::Verified
        || recovery_session.transaction_id.as_deref()
            != Some(transaction.resource.transaction_id.as_str())
        || recovery_session.principal_id != transaction.resource.account_id.principal_id
        || recovery_session.station_id != transaction.resource.account_id.station_id
        || recovery_session.station_id.as_str() != state.service_id()
        || recovery_session.requesting_device_id != binding.replacement_device_id.as_str()
        || recovery_session.created_at != receipt.started_at
        || recovery_session.policy_id != receipt.policy_id.as_str()
        || u64::from(recovery_session.policy_version) != receipt.policy_version
        || recovery_session.trust_domain != receipt.trust_domain.as_str()
        || proof_summary.kind != receipt.proof_summary.kind
        || proof_summary.proof_digest != receipt.proof_summary.proof_digest
    {
        return Err(crate::app_error!(
            FailedPrecondition,
            "terminal recovery receipt does not match the verified session"
        ));
    }
    validate_frozen_session_policy(
        state,
        &recovery_session,
        recovery_session.proof_payload.as_ref(),
    )
    .await?;
    let payload = authorize_event
        .typed_payload::<arkret_wire::event_spec::DeviceAuthorize>()
        .map_err(|error| AppError::internal(format!("prepared authorize payload: {error}")))?;
    if payload.device_public_key_did.as_str() != recovery_session.requesting_device_public_key_did
        || payload.device_id != binding.replacement_device_id
        || payload.recovery_session_id.as_ref() != Some(&binding.recovery_session_id)
    {
        return Err(crate::app_error!(
            FailedPrecondition,
            "prepared authorize Event changed the recovery session binding"
        ));
    }
    let expected_method = &authorize_event
        .producer_proof
        .as_ref()
        .ok_or_else(|| AppError::internal("authorize Event has no producer proof"))?
        .verification_method;
    if &attestation.auth_data.verification_method != expected_method
        || &receipt.auth_data.verification_method != expected_method
    {
        return Err(crate::app_error!(
            FailedPrecondition,
            "terminal signatures are not identified by the replacement device"
        ));
    }
    let key = crate::routing::identity::device_signing::decode_ed25519_key(
        payload.device_public_key_did.as_str(),
        "multibase",
    )
    .map_err(|error| AppError::internal(format!("replacement device key: {error}")))?;
    verify_recovery_device_signature(
        &key,
        &attestation.auth_data.signature,
        &attestation
            .signing_bytes()
            .map_err(|error| AppError::param_invalid(error.to_string()))?,
    )?;
    verify_recovery_device_signature(
        &key,
        &receipt.auth_data.signature,
        &receipt
            .signature_transcript_bytes()
            .map_err(|error| AppError::param_invalid(error.to_string()))?,
    )?;
    let committed_at = chrono::Utc::now();
    super::validation::validate_recovery_receipt_completed_at(receipt.completed_at, committed_at)?;
    let authority = state
        .authority_commits()
        .current_authority(&plan.reanchor_commit_intent.realm_id)
        .await
        .map_err(|error| AppError::internal(format!("PCR authority: {error}")))?
        .ok_or_else(|| AppError::conflict("PCR Realm has no current authority"))?;
    if authority.service_id != state.service_core_id()
        || authority.generation != recovery_session.authority_context.authority_generation
        || authority.authority_ref != recovery_session.authority_context.authority_ref
    {
        return Err(AppError::conflict("PCR authority changed after prepare"));
    }
    let predecessor = state
        .authority_commits()
        .stream_head(&arkret_wire::CommitStreamRef::Realm {
            realm_id: plan.reanchor_commit_intent.realm_id.clone(),
        })
        .await
        .map_err(|error| AppError::internal(format!("PCR stream head: {error}")))?
        .ok_or_else(|| AppError::conflict("PCR Realm has no accepted Commit head"))?;
    if predecessor != recovery_session.authority_context.realm_stream_head
        || predecessor.commit_id != plan.reanchor_commit_intent.predecessor_ref
    {
        return Err(crate::app_error!(
            FailedPrecondition,
            "PCR stream head changed after prepare"
        ));
    }
    let method = arkret_wire::DidUrl::new(
        crate::routing::federation::federation_service_signature_key_id(
            state.service_did().as_str(),
        ),
    )
    .map_err(|error| AppError::internal(error.to_string()))?;
    let commits = state
        .authority_commits()
        .prepare_recovery_unit_commits(
            &[reanchor_event.clone(), authorize_event.clone()],
            &authority,
            &predecessor,
            method.clone(),
            state.notary_signing_key().as_ref(),
            committed_at,
        )
        .map_err(|error| AppError::internal(format!("recovery Commit signing: {error}")))?;
    let committed_ref =
        |item: &coland_storage::AuthorityCommitTransaction| arkret_wire::CommittedEventRef {
            event_id: item.event.event_id.clone(),
            commit_id: item.commit.commit_id.clone(),
            stream_ref: item.commit.stream_ref.clone(),
            stream_position: item.commit.stream_position,
        };
    let receipt_digest = canonical_digest(receipt)?;
    let unsigned = arkret_wire::UnsignedRecoveryCompletionAttestation::new(
        arkret_wire::UnsignedRecoveryCompletionAttestationBody {
            transaction_id: transaction.resource.transaction_id.clone(),
            transaction_request_digest: transaction.resource.request_digest.clone(),
            prepared_plan_digest: transaction.resource.prepared_plan_digest.clone(),
            account_id: transaction.resource.account_id.clone(),
            recovery_session_id: binding.recovery_session_id.clone(),
            terminal_receipt_id: receipt.receipt_id.clone(),
            terminal_receipt_digest: receipt_digest.clone(),
            replacement_device_id: binding.replacement_device_id.clone(),
            result_model_generation_ref: plan.result_model_generation_ref,
            completed_at: committed_at,
            reanchor_event_ref: committed_ref(&commits[0]),
            device_authorization_event_ref: committed_ref(&commits[1]),
        },
        method,
    )
    .map_err(|error| AppError::internal(error.to_string()))?;
    let signature = state.notary_signing_key().sign(
        &unsigned
            .signing_bytes()
            .map_err(|error| AppError::internal(error.to_string()))?,
    );
    let completion = unsigned
        .attach_signature(
            arkret_wire::Base64UrlString::new(URL_SAFE_NO_PAD.encode(signature.to_bytes()))
                .map_err(|error| AppError::internal(error.to_string()))?,
        )
        .map_err(|error| AppError::internal(error.to_string()))?;
    transaction.resource.accepted_steps.push(AcceptedStep {
        acceptor: SecurityTransactionAcceptor::Principal {
            principal_id: state.service_core_id(),
        },
        accepted_at: committed_at,
    });
    transaction.resource.terminal_outcome = Some(SecurityTransactionTerminalOutcome::Completed {
        completed_at: committed_at,
        receipt_id: Some(receipt.receipt_id.clone()),
        completion_attestation: Some(completion),
    });
    transaction
        .resource
        .validate_structural()
        .map_err(|error| AppError::internal(format!("completed transaction: {error}")))?;
    let outcome = SecurityTransactionStepOutcomeState {
        transaction_id: transaction.resource.transaction_id.as_str().to_owned(),
        step: SecurityTransactionStep::CommitRecoveryUnit,
        canonical_request,
        response: serde_json::to_value(&transaction.resource)
            .map_err(|error| AppError::internal(error.to_string()))?,
        participant_outcome: Some(
            serde_json::to_value(terminal_commit)
                .map_err(|error| AppError::internal(error.to_string()))?,
        ),
    };
    let lock = crate::routing::identity::device_generation::device_generation_admission_lock(
        transaction.resource.account_id.principal_id.as_str(),
    );
    let _guard = lock.lock().await;
    let accepted = state
        .security_transactions()
        .commit_recovery_unit(coland_services::identity::RecoveryUnitCommitWrite {
            transaction,
            step_outcome: outcome,
            predecessor,
            commits,
            queued_at: committed_at,
        })
        .await
        .map_err(recovery_service_error)?;
    let resource = serde_json::from_value(accepted.response)
        .map_err(|error| AppError::internal(format!("stored recovery response: {error}")))?;
    res.status_code(StatusCode::OK);
    json_ok(resource)
}

/// Validate and freeze the replacement device's two producer Events and the
/// current PCR RealmCommit predecessor. Prepare has no accepted-event effect:
/// authority Commit bodies are issued only by terminal admission.
async fn prepare_recovery_plan(
    state: &AppState,
    session: &SessionRecord,
    request: &RecoveryTransactionCreateRequest,
) -> Result<PcrPolicyRecoveryPlan, AppError> {
    let intent = &request.recovery_intent;
    intent
        .validate(&request.account_id)
        .map_err(|error| AppError::schema_violation(error.to_string()))?;
    if session.require_human_device_id() != intent.replacement_device_id.as_str() {
        return Err(crate::app_error!(
            CapabilityDenied,
            "recovery transaction must be created by the replacement device session",
        ));
    }
    let recovery_session = state
        .recovery_sessions()
        .session(intent.recovery_session_id.as_str())
        .await
        .map_err(recovery_service_error)?
        .ok_or_else(|| AppError::not_found("recovery session not found"))?;
    if recovery_session.state != coland_storage::RecoverySessionLifecycle::Verified
        || recovery_session.principal_id != request.account_id.principal_id
        || recovery_session.station_id != request.account_id.station_id
        || recovery_session.station_id.as_str() != state.service_id()
        || recovery_session.requesting_device_id != intent.replacement_device_id.as_str()
    {
        return Err(AppError::conflict(
            "recovery session is not verified for this account and replacement device",
        ));
    }
    validate_frozen_session_policy(
        state,
        &recovery_session,
        recovery_session.proof_payload.as_ref(),
    )
    .await?;
    let proof_summary = recovery_proof_summary(&recovery_session).ok_or_else(|| {
        AppError::capability_denied("recovery session has no verified proof summary")
    })?;
    let commit_intent = &intent.reanchor_commit_intent;
    let realm_id = &commit_intent.realm_id;
    if recovery_session.authority_context.realm_id != *realm_id {
        return Err(AppError::conflict(
            "recovery commit intent does not name the session-frozen PCR Realm",
        ));
    }
    let current_authority = state
        .authority_commits()
        .current_authority(realm_id)
        .await
        .map_err(|error| AppError::internal(format!("PCR authority lookup failed: {error}")))?
        .ok_or_else(|| AppError::conflict("PCR Realm has no current authority"))?;
    if current_authority.service_id != state.service_core_id()
        || current_authority.generation != recovery_session.authority_context.authority_generation
        || current_authority.authority_ref != recovery_session.authority_context.authority_ref
    {
        return Err(AppError::conflict(
            "PCR authority changed after the recovery session was frozen",
        ));
    }
    let stream_head = state
        .authority_commits()
        .stream_head(&arkret_wire::CommitStreamRef::Realm {
            realm_id: realm_id.clone(),
        })
        .await
        .map_err(|error| AppError::internal(format!("PCR stream head lookup failed: {error}")))?
        .ok_or_else(|| AppError::conflict("PCR Realm has no accepted Commit head"))?;
    if stream_head != recovery_session.authority_context.realm_stream_head
        || stream_head.commit_id != commit_intent.predecessor_ref
    {
        return Err(crate::app_error!(
            FailedPrecondition,
            "recovery commit intent predecessor_ref is not the session-frozen PCR stream head",
        ));
    }
    let [reanchor_submission, authorize_submission] =
        intent.reanchor_unit.request.events.as_slice()
    else {
        return Err(AppError::schema_violation(
            "recovery unit must contain exactly the ordered re-anchor and authorize Events",
        ));
    };
    let (reanchor_event, authorize_event) =
        (&reanchor_submission.event, &authorize_submission.event);
    let reanchor_event_id = reanchor_event.event_id.clone();
    let authorize_event_id = authorize_event.event_id.clone();
    let digest_suite = arkret_canonical::DigestSuite::Sha256;
    let reanchor_payload: arkret_models_collaboration::events_payloads::device_identity::DeviceReanchorPayload =
        serde_json::from_value(
            serde_json::to_value(&reanchor_event.payload)
                .map_err(|error| AppError::internal(error.to_string()))?,
        )
        .map_err(|error| {
            AppError::schema_violation(format!("device re-anchor payload is invalid: {error}"))
        })?;
    let authorization_payload = authorize_event
        .typed_payload::<arkret_wire::event_spec::DeviceAuthorize>()
        .map_err(|error| {
            AppError::param_invalid(format!(
                "recovery device authorization payload is invalid: {error}"
            ))
        })?;
    if authorization_payload.device_id != intent.replacement_device_id
        || authorization_payload.device_public_key_did.as_str()
            != recovery_session.requesting_device_public_key_did
        || authorization_payload.recovery_session_id.as_ref() != Some(&intent.recovery_session_id)
    {
        return Err(AppError::conflict(
            "replacement authorization Event changed the session-frozen device identity",
        ));
    }
    let authorize_envelope = serde_json::to_value(authorize_event)
        .map_err(|error| AppError::internal(error.to_string()))?;
    let authorize_envelope_digest = authorize_event
        .event_digest_with_digest_suite(digest_suite)
        .map_err(|error| AppError::internal(error.to_string()))?;
    let replacement_payload_digest = coland_services::events::replacement_authorize_payload_digest(
        &authorize_envelope,
        &authorize_envelope_digest,
    )
    .map_err(AppError::internal)?;
    if reanchor_payload.account_id != request.account_id
        || reanchor_payload.replacement_authorize_payload_digest != replacement_payload_digest
    {
        return Err(crate::app_error!(
            FailedPrecondition,
            "recovery Events do not form the fixed re-anchor/authorize binding",
        ));
    }
    let key = crate::routing::identity::device_signing::decode_ed25519_key(
        &recovery_session.requesting_device_public_key_did,
        "multibase",
    )
    .map_err(|error| {
        AppError::internal(format!(
            "session-frozen replacement device public key is invalid: {error}"
        ))
    })?;
    let principal_resolution = state
        .persistence()
        .principal_resolution_by_account_id(&request.account_id)
        .await
        .map_err(|error| AppError::internal(format!("principal authority lookup failed: {error}")))?
        .ok_or_else(|| AppError::conflict("accepted recovery principal resolution missing"))?;
    let verification_method = recovery_device_verification_method(
        &principal_resolution.projection.did,
        &request.account_id,
        &intent.replacement_device_id,
    )?;
    for event in [reanchor_event, authorize_event] {
        verify_recovery_event_proof(event, &request.account_id, &verification_method, &key)?;
    }
    let recovery_session_snapshot_digest = Hash::new(
        arkret_canonical::canonical_sha256(
            &super::session_endpoints::typed_recovery_session_state(&recovery_session)?,
        )
        .map_err(|error| AppError::internal(error.to_string()))?,
    )
    .map_err(|error| AppError::internal(error.to_string()))?;
    Ok(PcrPolicyRecoveryPlan {
        binding: PcrPolicyRecoveryBinding {
            identity_model: RecoveryIdentityModel::PcrPolicy,
            recovery_session_id: intent.recovery_session_id.clone(),
            replacement_device_id: intent.replacement_device_id.clone(),
            reanchor_event_id,
            authorize_event_id,
            terminal_receipt_id: intent.terminal_receipt_id.clone(),
        },
        recovery_session_snapshot_digest,
        proof_digest: proof_summary.proof_digest.clone(),
        previous_model_generation_ref: intent.previous_model_generation_ref,
        result_model_generation_ref: intent.result_model_generation_ref,
        reanchor_unit: intent.reanchor_unit.clone(),
        reanchor_commit_intent: commit_intent.clone(),
    })
}

/// The accepted Account DID identifies the candidate method; the session's
/// frozen replacement key supplies its unit-local verification material.
fn recovery_device_verification_method(
    accepted_did: &arkret_wire::Did,
    account: &AccountId,
    device_id: &DeviceId,
) -> Result<DidUrl, AppError> {
    if arkret_wire::project_did_to_core_id(accepted_did)
        .map_err(|error| AppError::internal(error.to_string()))?
        != account.principal_id
    {
        return Err(AppError::conflict(
            "accepted recovery DID differs from the Account principal",
        ));
    }
    DidUrl::new(format!("{accepted_did}#{device_id}"))
        .map_err(|error| AppError::internal(error.to_string()))
}

fn verify_recovery_event_proof(
    event: &arkret_wire::Event,
    account: &AccountId,
    verification_method: &DidUrl,
    frozen_key: &ed25519_dalek::VerifyingKey,
) -> Result<(), AppError> {
    if event.actor_id != ActorId::account(account.clone()) || event.executed_by.is_some() {
        return Err(AppError::conflict(
            "recovery Event is not authored by the exact Account",
        ));
    }
    let digest_suite = arkret_canonical::DigestSuite::Sha256;
    event
        .verify_event_id_matches_content_with_digest_suite(digest_suite)
        .map_err(|error| AppError::param_invalid(error.to_string()))?;
    let proof = event
        .producer_proof
        .as_ref()
        .ok_or_else(|| AppError::param_invalid("recovery Event has no producer proof"))?;
    proof
        .validate_production()
        .map_err(|error| AppError::param_invalid(error.to_string()))?;
    if &proof.verification_method != verification_method {
        return Err(AppError::conflict(
            "recovery Event signer differs from the accepted Account device method",
        ));
    }
    let envelope = arkret_signatures::EventProofBuilder::new()
        .envelope_bytes(event)
        .map_err(|error| AppError::param_invalid(error.to_string()))?;
    arkret_signatures::verify_ed25519_detached_jws_proof_with_digest_suite(
        proof,
        &envelope,
        &event.actor_id,
        &arkret_signatures::PublicKeyMaterial::Ed25519Raw {
            bytes: frozen_key.to_bytes().to_vec(),
        },
        digest_suite,
    )
    .map_err(|error| {
        AppError::conflict(format!(
            "replacement device Event proof is invalid: {error}"
        ))
    })
}

fn verify_recovery_device_signature(
    key: &ed25519_dalek::VerifyingKey,
    signature: &str,
    signing_bytes: &[u8],
) -> Result<(), AppError> {
    let raw = URL_SAFE_NO_PAD
        .decode(signature.as_bytes())
        .or_else(|_| STANDARD.decode(signature.as_bytes()))
        .map_err(|_| {
            AppError::param_invalid("recovery device signature is not base64/base64url")
        })?;
    let signature = Signature::from_slice(&raw)
        .map_err(|_| AppError::param_invalid("recovery device signature must be 64 bytes"))?;
    key.verify(signing_bytes, &signature).map_err(|_| {
        crate::app_error!(
            FailedPrecondition,
            "recovery device signature verification failed"
        )
    })
}

fn pcr_policy_parts(
    transaction: &SecurityTransaction,
) -> Result<(&PcrPolicyRecoveryBinding, &PcrPolicyRecoveryPlan), AppError> {
    match &transaction.prepared_plan {
        SecurityTransactionPreparedPlan::Recovery(plan) => Ok((&plan.binding, plan)),
        _ => Err(crate::app_error!(
            FailedPrecondition,
            "operation requires a PCR-policy recovery transaction"
        )),
    }
}

fn canonical_digest(value: &impl Serialize) -> Result<Hash, AppError> {
    let digest = crate::util::canonical_digest(value)?;
    Hash::new(digest).map_err(|error| AppError::internal(error.to_string()))
}

fn security_transaction_service_error(error: coland_services::ServiceError) -> AppError {
    if error.kind() == coland_services::ServiceErrorKind::Conflict
        && error.detail().contains("different canonical bytes")
    {
        AppError::conflict(error.detail()).with_wire_code("duplicate_conflict")
    } else {
        recovery_service_error(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn core(name: &str) -> DidCoreId {
        DidCoreId::new(format!("ak:did_core:web:{name}.example")).unwrap()
    }

    #[test]
    fn recovery_event_method_is_bound_to_the_accepted_account_and_frozen_key() {
        let account = AccountId::new(core("alice"), core("station-a"));
        let accepted_did = arkret_wire::Did::new("did:web:alice.example").unwrap();
        let device = DeviceId::new("ak:device:01964137-0000-7000-8000-000000000001").unwrap();
        let expected =
            recovery_device_verification_method(&accepted_did, &account, &device).unwrap();
        let seed = [73; 32];
        let key = ed25519_dalek::SigningKey::from_bytes(&seed).verifying_key();
        let realm = arkret_wire::RealmId::from_event_id(&arkret_wire::EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            [0x52; 32],
        ));
        let signed = |method: DidUrl, author: &AccountId, signing_seed| {
            coland_test_support::device_authorization_history::sign_event(
                arkret_wire::test_support::raw_event(
                    arkret_wire::EventKind::MessageCreate.as_str(),
                    arkret_wire::ScopeRef::Realm {
                        realm_id: realm.clone(),
                    },
                    author.principal_id.clone(),
                    author.station_id.clone(),
                    json!({}),
                )
                .unwrap(),
                method,
                signing_seed,
            )
        };
        let event = signed(expected.clone(), &account, seed);
        verify_recovery_event_proof(&event, &account, &expected, &key).unwrap();
        let another_key = ed25519_dalek::SigningKey::from_bytes(&[74; 32]).verifying_key();
        assert!(verify_recovery_event_proof(&event, &account, &expected, &another_key).is_err());
        for method in [
            "did:web:alice.example#ak:device:01964137-0000-7000-8000-000000000003",
            "did:web:bob.example#ak:device:01964137-0000-7000-8000-000000000001",
            "did:key:z6MkrJVnaZkeFzdQyMZuW7Lh1UmCXySXy3yw8DabJVmVZdtv#z6MkrJVnaZkeFzdQyMZuW7Lh1UmCXySXy3yw8DabJVmVZdtv",
        ] {
            let event = signed(DidUrl::new(method).unwrap(), &account, seed);
            assert!(verify_recovery_event_proof(&event, &account, &expected, &key).is_err());
        }
        let other_station = AccountId::new(account.principal_id.clone(), core("station-b"));
        let event = signed(expected.clone(), &other_station, seed);
        assert!(verify_recovery_event_proof(&event, &account, &expected, &key).is_err());
        assert!(
            recovery_device_verification_method(
                &arkret_wire::Did::new("did:web:bob.example").unwrap(),
                &account,
                &device,
            )
            .is_err()
        );
    }

    #[test]
    fn transaction_account_binding_rejects_a_foreign_coordinator() {
        let principal = core("alice");
        let local = core("station-a");
        let foreign = core("station-b");
        let local_account = AccountId::new(principal.clone(), local.clone());
        let actor = transaction_account_actor(&local_account, &local).unwrap();
        assert_eq!(
            actor,
            ActorId::account(AccountId::new(principal.clone(), local.clone()))
        );
        // The coordinator is `account_id.station_id` and nothing else, so an
        // account at another Station is invisible here rather than adopted.
        let foreign_account = AccountId::new(principal.clone(), foreign.clone());
        assert!(transaction_account_actor(&foreign_account, &local).is_err());
        assert_ne!(
            actor,
            transaction_account_actor(&foreign_account, &foreign).unwrap()
        );
    }

    #[test]
    fn backup_rotation_match_requires_the_exact_account_actor() {
        let principal = core("alice");
        let station = core("station-a");
        let account = AccountId::new(principal.clone(), station.clone());
        let actor = transaction_account_actor(&account, &station).unwrap();
        let expected = arkret_models_crypto::BackupObjectRef {
            backup_id: arkret_wire::BackupId::new(
                "ak:backup:01964137-0000-7000-8000-000000000001".to_owned(),
            )
            .unwrap(),
            ciphertext_digest: Hash::new(format!("sha256:{}", "a".repeat(64))).unwrap(),
        };
        let series_id = arkret_wire::BackupSeriesId::new(
            "ak:backup_series:01964137-0000-7000-8000-000000000001".to_owned(),
        )
        .unwrap();
        // The matcher's identity/digest fragment; envelope validation remains
        // the SDK's responsibility at the publication boundary.
        let value = json!({
            "backup_id": expected.backup_id,
            "ciphertext_digest": expected.ciphertext_digest,
            "actor_id": actor,
            "series_id": series_id,
            "backup_kind": "secret_storage"
        });
        let matches = |value: &Value| {
            backup_value_matches_rotation(
                value,
                &actor,
                &series_id,
                arkret_models_crypto::BackupRotationKind::SecretStorage,
                &expected,
            )
        };
        assert!(matches(&value));
        for wrong_actor in [
            json!(ActorId::account(AccountId::new(
                principal.clone(),
                core("station-b")
            ))),
            json!(ActorId::service(principal.clone())),
            json!(principal),
            json!(actor.to_string()),
        ] {
            let mut changed = value.clone();
            changed["actor_id"] = wrong_actor;
            assert!(!matches(&changed));
        }
        let mut changed = value;
        changed["ciphertext_digest"] = json!(format!("sha256:{}", "b".repeat(64)));
        assert!(!matches(&changed));
    }
}
