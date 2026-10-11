use std::collections::BTreeMap;

use arkret_identifiers::DidCoreId;
use arkret_models_collaboration::account_lifecycle::{
    AccountStatusPropagationState, AccountStatusPublication, AccountStatusPublicationOutcome,
    AccountStatusPublicationRequestBody, AccountStatusPublicationStatus,
    AccountStatusReceiptedPublication, AccountStatusResolveOutcome,
    AccountStatusResolveRequestBody,
};
use arkret_models_collaboration::account_status::UnsignedAccountStatusReceipt;
use arkret_models_collaboration::authority_commit::{
    DirectConversationFoundingMissingDependency, DirectConversationFoundingMissingDependencyList,
    PeerAuthoritySubmitRequest, PeerRegisteredAtomicUnit,
};
use arkret_models_collaboration::objects::direct_conversation::DirectConversationFoundingAuthorityEvidence;
use arkret_models_collaboration::principal_operations::{
    PcrGenesisAdmissionInput, PcrGenesisAdmissionOutcome,
};
use arkret_models_identity::service_identity::CanonicalServiceUrl;
use arkret_wire::{SignalRelayOutcome, SignalRelayRequest};
#[cfg(test)]
use chrono::DateTime;
use chrono::{Duration, Utc};
use coland_http::error::AppError;
use coland_http::result::{JsonResult, json_ok};
#[cfg(test)]
use coland_services::events::AcceptedEvent;
#[cfg(test)]
use coland_services::events::RealmMetadata as RealmMetaRecord;
use salvo::http::StatusCode;
use salvo::prelude::*;
use serde_json::{Value, json};

use super::{render_error, validate_did};
use crate::state::AppState;

const HEADER_SOURCE_SERVICE_ID: &str = "source-service-id";
const HEADER_DESTINATION_SERVICE_ID: &str = "destination-service-id";
const ACCOUNT_STATUS_IDEMPOTENCY_RESERVED_STATUS: i32 = 102;
const ACCOUNT_STATUS_IDEMPOTENCY_RESERVED_STATE: &str = "account_status_submission_pending";

pub(super) fn router() -> Router {
    Router::new()
        .push(Router::with_path("events").post(peer_events_submit))
        .push(Router::with_path("account-status").post(peer_account_status_submit))
        .push(Router::with_path("account-status/resolve").post(peer_account_status_resolve))
        .push(Router::with_path("signal").post(peer_signal_relay))
}

#[handler]
pub(super) async fn admit_private_principal_genesis(
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<PcrGenesisAdmissionOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    authenticate_account_authority_private_request(state, req)?;
    let header_idempotency_key = required_header(req, "idempotency-key")?;
    // Preserve the authenticated HTTP bytes for the PCR genesis UoW's exact
    // replay comparison. Re-encoding the typed DTO would merge distinct
    // requests under one idempotency key.
    let exact_request_body = req
        .payload()
        .await
        .map_err(|error| {
            AppError::json_invalid(format!("unable to read principal genesis body: {error}"))
        })?
        .to_vec();
    let request = parse_json_body::<PcrGenesisAdmissionInput>(
        req,
        "invalid private principal genesis admission body",
    )
    .await?;
    request
        .validate()
        .map_err(|error| schema_violation(error.to_string()))?;
    if header_idempotency_key != request.idempotency_key.as_str() {
        return Err(cross_domain_replay(
            "principal genesis private adapter idempotency binding mismatch",
        ));
    }
    let configured_authority = trusted_account_authority_id(state).await?;
    if configured_authority != request.account_authority_id {
        return Err(AppError::capability_denied(
            "principal genesis caller is not the configured Account Authority",
        ));
    }
    if let Some(authority_url) = state.config().account_authority_url.as_deref()
        && request
            .identity_creation_control_proof
            .origin
            .as_str()
            .trim_end_matches('/')
            != authority_url.trim_end_matches('/')
    {
        return Err(cross_domain_replay(
            "principal genesis creation-proof origin does not match the configured Account Authority",
        ));
    }
    super::event_log::submit_peer_pcr_genesis(state, &request, exact_request_body)
        .await
        .map_err(|error| {
            error.rejection().cloned().unwrap_or_else(|| {
                crate::app_error!(Quarantine, error.message()).with_internal_reason(error.code())
            })
        })
        .and_then(json_ok)
}

async fn trusted_account_authority_binding(
    state: &AppState,
) -> Result<(DidCoreId, CanonicalServiceUrl), AppError> {
    let authority_url = state
        .config()
        .account_authority_url
        .as_deref()
        .ok_or_else(|| AppError::capability_denied("Account Authority is not configured"))?;
    // A split Account Authority uses this Station's authorized assertion key.
    // Its endpoint location never establishes a second service identity.
    let authority_id = state.service_core_id();
    let authority_url = CanonicalServiceUrl::canonicalize(authority_url).map_err(|error| {
        AppError::internal(format!(
            "configured Account Authority URL is invalid: {error}"
        ))
    })?;
    Ok((authority_id, authority_url))
}

pub(crate) async fn trusted_account_authority_id(state: &AppState) -> Result<DidCoreId, AppError> {
    trusted_account_authority_binding(state)
        .await
        .map(|(service_id, _)| service_id)
}

/// One resolved registered deployment-internal authenticated channel.
///
/// Built only from explicit deployment configuration plus this Station's own
/// verified identity. Nothing in it comes from the request.
pub(crate) struct RegisteredInternalChannel {
    credential: String,
}

impl RegisteredInternalChannel {}

fn registered_internal_authority_channel_from_config(
    config: &crate::config::AppConfig,
) -> Result<RegisteredInternalChannel, AppError> {
    let authority_url = config
        .account_authority_url
        .as_deref()
        .ok_or_else(|| AppError::capability_denied("Account Authority is not configured"))?;
    CanonicalServiceUrl::canonicalize(authority_url).map_err(|error| {
        AppError::internal(format!(
            "configured Account Authority URL is invalid: {error}"
        ))
    })?;
    let channel_config = config.internal_authority_channel.as_ref().ok_or_else(|| {
        AppError::capability_denied(
            "no deployment-internal authenticated channel is registered for this Account Authority",
        )
    })?;
    Ok(RegisteredInternalChannel {
        credential: channel_config.credential().to_owned(),
    })
}

fn constant_time_credential_eq(expected: &str, presented: &str) -> bool {
    use subtle::ConstantTimeEq as _;

    expected.len() == presented.len() && bool::from(expected.as_bytes().ct_eq(presented.as_bytes()))
}

/// Authenticate a product-private Account Authority adapter call.
///
/// Unlike the retired canonical self-call operations this edge is not keyed by
/// an Arkret operation id and is never advertised in protocol discovery. The
/// deployment's fixed shared-secret channel is the whole caller identity.
pub(in crate::routing) fn authenticate_account_authority_private_request(
    state: &AppState,
    req: &Request,
) -> Result<RegisteredInternalChannel, AppError> {
    let channel = registered_internal_authority_channel_from_config(state.config())?;
    if !internal_channel_request_is_authentic(&channel, req.headers()) {
        return Err(AppError::unauthenticated(
            "caller is not authenticated on the Account Authority private channel",
        ));
    }
    Ok(channel)
}

/// The credential and transport-input half of the private-channel check, separated from
/// configuration resolution so both halves are directly testable.
fn internal_channel_request_is_authentic(
    channel: &RegisteredInternalChannel,
    headers: &salvo::http::HeaderMap,
) -> bool {
    let presented = headers
        .get(salvo::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| {
            value
                .strip_prefix("Bearer ")
                .or_else(|| value.strip_prefix("bearer "))
        })
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let Some(presented) = presented else {
        return false;
    };
    if !constant_time_credential_eq(&channel.credential, presented) {
        return false;
    }
    // §2.5.1: with no signature covering the transport shell, the request MUST
    // NOT carry a `Content-Digest` that exists only for an HTTP signature, and
    // the receiver MUST NOT treat shell digests or whole-body byte equality as
    // an authentication means. Reject rather than silently ignore, so there is
    // never a second, weaker-looking acceptance path beside the channel.
    if headers.contains_key("content-digest") {
        return false;
    }
    true
}

#[salvo::oapi::endpoint(operation_id = "ak.peer.account_status.command.submit", tags("events"))]
async fn peer_account_status_submit(
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AccountStatusPublicationOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    validate_peer_request(state, req, true).await?;
    let source_id = source_id_from_request(req)?;
    let idempotency_key = required_header(req, "idempotency-key")?;
    let request = parse_json_body::<AccountStatusPublicationRequestBody>(
        req,
        "invalid ak.peer.account_status.command.submit.v1 request body",
    )
    .await?;
    request
        .validate_shape()
        .map_err(|error| schema_violation(error.to_string()))?;
    let record = request.publication.record();
    validate_account_status_publication(state, &source_id, &request).await?;
    let request_hash = arkret_canonical::canonical_sha256(&request).map_err(|error| {
        AppError::internal(format!("account-status request digest failed: {error}"))
    })?;
    let idempotency_principal_id = arkret_wire::DidCoreId::new(source_id.clone())
        .map_err(|error| AppError::param_invalid(format!("Source-Service-ID invalid: {error}")))?;
    let idempotency_actor = arkret_wire::ActorId::service(idempotency_principal_id);
    let stored_at = Utc::now();
    let reservation = coland_services::jobs::IdempotencyState {
        authenticated_actor: idempotency_actor.clone(),
        operation_id: arkret_wire::ServiceOperationId::PEER_ACCOUNT_STATUS_COMMAND_SUBMIT_V1
            .to_owned(),
        idempotency_key: idempotency_key.clone(),
        request_hash: request_hash.clone(),
        response_status: ACCOUNT_STATUS_IDEMPOTENCY_RESERVED_STATUS,
        response_body: json!({"state": ACCOUNT_STATUS_IDEMPOTENCY_RESERVED_STATE}),
        created_at: stored_at,
        expires_at: stored_at + Duration::days(3650),
    };
    state
        .persistence()
        .record_idempotency(&reservation)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    let reservation = state
        .persistence()
        .scoped_idempotency_record(
            &idempotency_actor,
            arkret_wire::ServiceOperationId::PEER_ACCOUNT_STATUS_COMMAND_SUBMIT_V1,
            &idempotency_key,
        )
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
        .ok_or_else(|| AppError::internal("account-status idempotency reservation disappeared"))?;
    if reservation.request_hash != request_hash {
        return Err(AppError::conflict(
            "Idempotency-Key reused with another account-status publication",
        )
        .with_wire_code("duplicate_conflict"));
    }
    if !account_status_idempotency_is_pending(&reservation) {
        let outcome = serde_json::from_value(reservation.response_body).map_err(|error| {
            AppError::internal(format!("stored account-status outcome invalid: {error}"))
        })?;
        return json_ok(outcome);
    }

    let candidate_receipt = sign_account_status_receipt(state, record)?;
    let append = state
        .persistence()
        .append_account_status_record(record, &candidate_receipt)
        .await
        .map_err(|error| {
            AppError::internal(format!("account-status replica unavailable: {error}"))
        })?;
    let (status, current, required_status_seq, receipt) = match append {
        coland_storage::AccountStatusReplicaAppend::Accepted(receipt) => (
            AccountStatusPublicationStatus::Accepted,
            Some(record.clone()),
            None,
            receipt,
        ),
        coland_storage::AccountStatusReplicaAppend::Duplicate(receipt) => (
            AccountStatusPublicationStatus::Duplicate,
            Some(record.clone()),
            None,
            receipt,
        ),
        coland_storage::AccountStatusReplicaAppend::DependencyMissing {
            current_record,
            required_status_seq,
        } => {
            let outcome = publication_outcome(
                record,
                AccountStatusPublicationStatus::DependencyMissing,
                current_record.as_ref(),
                Some(required_status_seq),
                None,
            );
            return json_ok(outcome);
        }
        coland_storage::AccountStatusReplicaAppend::Stale { current_record } => {
            return Err(crate::app_error!(
                FailedPrecondition,
                format!(
                    "account-status record is stale; current status_seq is {}",
                    current_record.status_seq
                ),
            )
            .with_reason_code(arkret_wire::ReasonCode::ACCOUNT_STATUS_RECORD_STALE));
        }
        coland_storage::AccountStatusReplicaAppend::Conflict { kind, .. } => {
            use coland_storage::AccountStatusReplicaConflictKind;
            return Err(match kind {
                AccountStatusReplicaConflictKind::Fork => {
                    crate::app_error!(FailedPrecondition, "account-status ledger fork",)
                        .with_reason_code(arkret_wire::ReasonCode::ACCOUNT_STATUS_RECORD_FORK)
                }
                AccountStatusReplicaConflictKind::BindingRollback => crate::app_error!(
                    FailedPrecondition,
                    "account-status binding version rollback",
                )
                .with_reason_code(arkret_wire::ReasonCode::ACCOUNT_STATUS_BINDING_ROLLBACK),
                AccountStatusReplicaConflictKind::TransitionInvalid => {
                    crate::app_error!(FailedPrecondition, "account-status transition is invalid",)
                        .with_reason_code(
                            arkret_wire::ReasonCode::ACCOUNT_STATUS_TRANSITION_INVALID,
                        )
                }
                AccountStatusReplicaConflictKind::ErasurePendingTerminal => crate::app_error!(
                    FailedPrecondition,
                    "account-status erasure_pending state is terminal",
                )
                .with_reason_code(arkret_wire::ReasonCode::ERASURE_PENDING_IS_TERMINAL),
            });
        }
    };
    if status == AccountStatusPublicationStatus::Accepted
        && record.status
            == arkret_models_collaboration::objects::account_status::AccountStatus::ErasurePending
    {
        crate::account_erasure_worker::ensure_intent(
            state,
            record.account_authority_id.as_str(),
            &record.account_id,
            &record.account_id.principal_id,
            &record.account_status_record_id,
        )
        .await?;
    }
    let (propagation_state, pending_destination_count) =
        enqueue_account_status_fanout(state, record, &receipt).await?;
    let outcome = AccountStatusPublicationOutcome {
        status,
        account_status_record_id: record.account_status_record_id.clone(),
        status_seq: record.status_seq,
        account_id: record.account_id.clone(),
        current_account_status_record_id: current
            .as_ref()
            .map(|record| record.account_status_record_id.clone()),
        current_status_seq: current.as_ref().map(|record| record.status_seq),
        required_status_seq,
        barrier_cursor: None,
        propagation_state,
        pending_destination_count,
        receipt: Some(receipt),
    };
    let completed = coland_services::jobs::IdempotencyState {
        response_status: StatusCode::OK.as_u16() as i32,
        response_body: serde_json::to_value(&outcome)
            .map_err(|error| AppError::internal(error.to_string()))?,
        ..reservation.clone()
    };
    let completed_here = state
        .persistence()
        .complete_idempotency_reservation(&reservation, &completed)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    if completed_here {
        return json_ok(outcome);
    }
    let landed = state
        .persistence()
        .scoped_idempotency_record(
            &idempotency_actor,
            arkret_wire::ServiceOperationId::PEER_ACCOUNT_STATUS_COMMAND_SUBMIT_V1,
            &idempotency_key,
        )
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
        .ok_or_else(|| AppError::internal("account-status idempotency completion disappeared"))?;
    if landed.request_hash != request_hash || account_status_idempotency_is_pending(&landed) {
        return Err(AppError::internal(
            "account-status idempotency completion did not converge",
        ));
    }
    serde_json::from_value(landed.response_body)
        .map_err(|error| {
            AppError::internal(format!("stored account-status outcome invalid: {error}"))
        })
        .and_then(json_ok)
}

fn account_status_idempotency_is_pending(record: &coland_services::jobs::IdempotencyState) -> bool {
    record.response_status == ACCOUNT_STATUS_IDEMPOTENCY_RESERVED_STATUS
        && record.response_body.get("state").and_then(Value::as_str)
            == Some(ACCOUNT_STATUS_IDEMPOTENCY_RESERVED_STATE)
}

#[salvo::oapi::endpoint(operation_id = "ak.peer.account_status.read.resolve", tags("events"))]
async fn peer_account_status_resolve(
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AccountStatusResolveOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    validate_peer_request(state, req, true).await?;
    let source_id = source_id_from_request(req)?;
    let request = parse_json_body::<AccountStatusResolveRequestBody>(
        req,
        "invalid ak.peer.account_status.read.resolve.v1 request body",
    )
    .await?;
    request
        .validate()
        .map_err(|error| schema_violation(error.to_string()))?;

    // All relationship checks precede ledger access so unknown accounts and
    // unrelated callers collapse into the same non-enumerating response.
    let local_authority = trusted_account_authority_id(state).await?;
    let affected_services = crate::routing::identity::account::lifecycle::
        durable_deactivation_peer_service_targets_for_account(state, &request.account_id)
        .await?;
    if request.account_authority_id != local_authority
        || !account_status_resolve_source_authorized(
            &source_id,
            &request.account_authority_id,
            &request.account_id,
            &affected_services,
        )
    {
        return Err(account_status_resolve_not_found());
    }

    let current_exists = state
        .persistence()
        .current_account_status_record(request.account_authority_id.as_str(), &request.account_id)
        .await
        .map_err(|error| {
            AppError::internal(format!("account-status resolve unavailable: {error}"))
        })?
        .is_some();
    if !current_exists {
        return Err(account_status_resolve_not_found());
    }
    let fetch_limit = request.limit.saturating_add(1);
    let mut records = state
        .persistence()
        .resolve_account_status_records(
            request.account_authority_id.as_str(),
            &request.account_id,
            request.from_status_seq,
            fetch_limit,
        )
        .await
        .map_err(|error| {
            AppError::internal(format!("account-status resolve unavailable: {error}"))
        })?;
    let has_more = records.len() > usize::from(request.limit);
    records.truncate(usize::from(request.limit));
    let next_status_seq = if has_more {
        Some(
            records
                .last()
                .expect("positive resolve limit retains one row when has_more")
                .status_seq
                .checked_add(1)
                .ok_or_else(|| AppError::internal("account-status sequence overflow"))?,
        )
    } else {
        None
    };
    // A current head can legitimately precede from_status_seq; that is an
    // authorized empty freshness observation, not an unknown-account signal.
    let outcome = AccountStatusResolveOutcome {
        account_authority_id: request.account_authority_id.clone(),
        account_id: request.account_id.clone(),
        records,
        has_more,
        next_status_seq,
    };
    outcome.validate_for_request(&request).map_err(|error| {
        AppError::internal(format!("account-status resolve invariant: {error}"))
    })?;
    json_ok(outcome)
}

fn account_status_resolve_not_found() -> AppError {
    AppError::not_found("account-status records not found")
}

fn account_status_resolve_source_authorized(
    source_id: &str,
    account_authority_id: &DidCoreId,
    account_id: &arkret_wire::AccountId,
    affected_services: &[Value],
) -> bool {
    source_id == account_authority_id.as_str()
        || source_id == account_id.station_id.as_str()
        || affected_services
            .iter()
            .any(|target| target.get("service_id").and_then(Value::as_str) == Some(source_id))
}

async fn enqueue_account_status_fanout(
    state: &AppState,
    record: &arkret_models_collaboration::account_status::AccountStatusRecord,
    receipt: &arkret_models_collaboration::account_status::AccountStatusReceipt,
) -> Result<(AccountStatusPropagationState, Option<u64>), AppError> {
    if record.account_id.station_id.as_str() != state.service_id() {
        return Ok((AccountStatusPropagationState::NotRequired, None));
    }
    let targets = crate::routing::identity::account::lifecycle::
        durable_deactivation_peer_service_targets_for_account(state, &record.account_id)
        .await?;
    if targets.len() > 256 {
        return Err(AppError::internal(
            "account-status affected Station set exceeds 256",
        ));
    }
    let target_ids = targets
        .iter()
        .map(|target| {
            target
                .get("service_id")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    AppError::internal(
                        "account-status affected-service projection has no service_id",
                    )
                })
                .and_then(|service_id| {
                    arkret_wire::DidCoreId::new(service_id.to_owned()).map_err(|error| {
                        AppError::internal(format!("affected service id is invalid: {error}"))
                    })
                })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let now = Utc::now();
    let window_ms = i64::try_from(state.config().deactivation_propagation_window_ms)
        .map_err(|_| AppError::internal("deactivation propagation window exceeds i64"))?;
    let projection = state
        .persistence()
        .begin_account_status_propagation(
            record,
            &target_ids,
            now + Duration::milliseconds(window_ms),
            now,
        )
        .await
        .map_err(|error| {
            AppError::internal(format!(
                "account-status propagation initialization: {error}"
            ))
        })?;
    if target_ids.is_empty() {
        return Ok((
            account_status_propagation_state(projection.state),
            Some(projection.pending_destination_count),
        ));
    }
    let configured = crate::routing::federation::configured_peer_targets(state)
        .into_iter()
        .map(|peer| (peer.service_id.clone(), peer))
        .collect::<BTreeMap<_, _>>();
    let body = AccountStatusPublicationRequestBody {
        publication: AccountStatusPublication::Receipted(AccountStatusReceiptedPublication {
            record: record.clone(),
            account_status_receipts: vec![receipt.clone()],
        }),
    };
    let payload = arkret_canonical::canonical_json_string(&body)
        .map_err(|error| AppError::internal(format!("account-status fanout encode: {error}")))?;
    for service_id in &target_ids {
        // The worker resolves the current verified Service route from the
        // stable service id before every send. `peer_url` is historical
        // diagnostics only; an absent configured locator must not suppress
        // the durable intent.
        let peer_url = configured.get(service_id).map(|peer| peer.url.as_str());
        crate::routing::federation::outbox::enqueue_coalesced_outbound(
            state,
            peer_url,
            service_id.as_str(),
            "/_arkret/peer/account-status",
            &format!(
                "account-status:{}:{}:{}:{}",
                record.account_authority_id,
                record.account_id,
                service_id,
                record.account_status_record_id,
            ),
            &payload,
            &format!(
                "account-status:{}:{}",
                record.account_authority_id, record.account_id,
            ),
            i64::try_from(record.status_seq).map_err(|_| {
                AppError::internal("account-status sequence exceeds outbox lane range")
            })?,
        )
        .await
        .map_err(|error| AppError::internal(format!("account-status fanout enqueue: {error}")))?;
    }
    Ok((
        account_status_propagation_state(projection.state),
        Some(projection.pending_destination_count),
    ))
}

fn account_status_propagation_state(
    state: coland_storage::AccountStatusPropagationProjectionState,
) -> AccountStatusPropagationState {
    match state {
        coland_storage::AccountStatusPropagationProjectionState::Scheduled => {
            AccountStatusPropagationState::Scheduled
        }
        coland_storage::AccountStatusPropagationProjectionState::Complete => {
            AccountStatusPropagationState::Complete
        }
        coland_storage::AccountStatusPropagationProjectionState::Incomplete => {
            AccountStatusPropagationState::Incomplete
        }
    }
}

fn publication_outcome(
    record: &arkret_models_collaboration::account_status::AccountStatusRecord,
    status: AccountStatusPublicationStatus,
    current: Option<&arkret_models_collaboration::account_status::AccountStatusRecord>,
    required_status_seq: Option<u64>,
    receipt: Option<arkret_models_collaboration::account_status::AccountStatusReceipt>,
) -> AccountStatusPublicationOutcome {
    AccountStatusPublicationOutcome {
        status,
        account_status_record_id: record.account_status_record_id.clone(),
        status_seq: record.status_seq,
        account_id: record.account_id.clone(),
        current_account_status_record_id: current
            .map(|record| record.account_status_record_id.clone()),
        current_status_seq: current.map(|record| record.status_seq),
        required_status_seq,
        barrier_cursor: None,
        propagation_state: AccountStatusPropagationState::NotRequired,
        pending_destination_count: None,
        receipt,
    }
}

fn sign_account_status_receipt(
    state: &AppState,
    record: &arkret_models_collaboration::account_status::AccountStatusRecord,
) -> Result<arkret_models_collaboration::account_status::AccountStatusReceipt, AppError> {
    let accepted_at = Utc::now();
    let unsigned = UnsignedAccountStatusReceipt {
        receipt_id: arkret_wire::ReceiptId::new(crate::ids::generate("receipt"))
            .map_err(|error| AppError::internal(error.to_string()))?,
        account_status_record_id: record.account_status_record_id.clone(),
        record_digest: record
            .payload_digest()
            .map_err(|error| AppError::internal(error.to_string()))?,
        account_authority_id: record.account_authority_id.clone(),
        account_id: record.account_id.clone(),
        status_seq: record.status_seq,
        receiver_id: DidCoreId::new(state.service_id().clone())
            .map_err(|error| AppError::internal(error.to_string()))?,
        accepted_at,
        verification_method: state
            .service_verification_method("notary-key")
            .map_err(AppError::internal)?,
    };
    arkret_signatures::account_status::sign_account_status_receipt(
        unsigned,
        state.notary_signing_key().as_ref(),
    )
    .map_err(|error| AppError::internal(format!("account-status receipt signing failed: {error}")))
}

async fn historical_account_status_service_key(
    state: &AppState,
    service_id: &DidCoreId,
    pinned_base_url: Option<&CanonicalServiceUrl>,
    verification_method: &str,
    at: chrono::DateTime<chrono::Utc>,
    label: &str,
) -> Result<ed25519_dalek::VerifyingKey, AppError> {
    crate::jws_verify::validate_verification_method_controller(
        service_id.as_str(),
        verification_method,
    )
    .map_err(|error| {
        AppError::capability_denied(format!(
            "account-status {label} method controller mismatch: {error}"
        ))
    })?;
    arkret_wire::DidUrl::new(verification_method.to_owned()).map_err(|error| {
        schema_violation(format!(
            "account-status {label} verification method invalid: {error}"
        ))
    })?;
    if let Some(pinned_base_url) = pinned_base_url {
        let (configured_id, configured_base_url) = trusted_account_authority_binding(state).await?;
        if configured_id != *service_id || configured_base_url != *pinned_base_url {
            return Err(AppError::capability_denied(format!(
                "account-status {label} identity does not match the deployment-private Account Authority pin"
            )));
        }
    }
    let resolution = crate::routing::identity::agents::evidence::fetch_service_resolution(
        state, service_id, None,
    )
    .await
    .map_err(|error| {
        AppError::capability_denied(format!(
            "account-status {label} historical signer evidence unavailable: {error:?}"
        ))
    })?;
    let document = arkret_identity::authenticated_service_document_at(&resolution, service_id, at)
        .map_err(|error| {
            AppError::capability_denied(format!(
                "account-status {label} historical service document invalid: {error}"
            ))
        })?;
    arkret_identity::jws::resolve_ed25519_pubkey_from_document(&document, verification_method)
        .map_err(|error| {
            AppError::capability_denied(format!(
                "account-status {label} historical key unavailable: {error}"
            ))
        })
}

async fn validate_account_status_publication(
    state: &AppState,
    source_id: &str,
    request: &AccountStatusPublicationRequestBody,
) -> Result<(), AppError> {
    let record = request.publication.record();
    record
        .validate_shape()
        .map_err(|error| schema_violation(error.to_string()))?;
    let configured = trusted_account_authority_id(state).await?;
    if configured != record.account_authority_id {
        return Err(AppError::capability_denied(
            "account-status record Account Authority mismatch",
        ));
    }
    let local_server = DidCoreId::new(state.service_id().clone())
        .map_err(|error| AppError::internal(error.to_string()))?;
    let method = record.proof.verification_method.as_str();
    let (_, authority_url) = trusted_account_authority_binding(state).await?;
    let public_key = historical_account_status_service_key(
        state,
        &record.account_authority_id,
        Some(&authority_url),
        method,
        record.proof.created_at,
        "Account Authority",
    )
    .await?;
    arkret_signatures::account_status::verify_account_status_record(
        record,
        &arkret_signatures::PublicKeyMaterial::Ed25519Raw {
            bytes: public_key.to_bytes().to_vec(),
        },
    )
    .map_err(|error| {
        AppError::capability_denied(format!("account-status authority proof invalid: {error}"))
    })?;

    if source_id != record.account_authority_id.as_str() {
        if source_id != record.account_id.station_id.as_str() {
            return Err(AppError::capability_denied(
                "account-status fanout source is not the origin Station",
            ));
        }
        let source_receipt = request
            .publication
            .receipts()
            .iter()
            .find(|receipt| receipt.receiver_id.as_str() == source_id)
            .ok_or_else(|| {
                AppError::capability_denied(
                    "account-status fanout omits the origin Station receipt",
                )
            })?;
        let receipt_method = source_receipt.proof.verification_method.as_str();
        let receipt_key = historical_account_status_service_key(
            state,
            &source_receipt.receiver_id,
            None,
            receipt_method,
            source_receipt.accepted_at,
            "receipt issuer",
        )
        .await?;
        arkret_signatures::account_status::verify_account_status_receipt(
            source_receipt,
            &arkret_signatures::PublicKeyMaterial::Ed25519Raw {
                bytes: receipt_key.to_bytes().to_vec(),
            },
        )
        .map_err(|error| {
            AppError::capability_denied(format!("account-status receipt proof invalid: {error}"))
        })?;
        return Ok(());
    }

    if record.account_id.station_id != local_server {
        return Err(AppError::capability_denied(
            "initial account-status record is addressed to another Station",
        ));
    }

    let authority =
        arkret_wire::AccountId::new(record.account_id.principal_id.clone(), local_server);
    let resolution = state
        .persistence()
        .principal_resolution_by_account_id(&authority)
        .await
        .map_err(|error| {
            AppError::internal(format!("account-status PCR binding unavailable: {error}"))
        })?
        .ok_or_else(|| AppError::capability_denied("account-status PCR binding is not accepted"))?;
    // `account_id` is the Account Authority's own deployment-local service
    // account id (account-lifecycle.md §3.1); a Station never mints or
    // stores it, so it can only be bound to the Event payload and to the
    // monotonic authority floor below. The local `AccountRecord.id` is an
    // unrelated coland-local identifier and comparing the two rejects every
    // lawful publication.
    if resolution.pcr_realm_id != record.principal_control_realm_id {
        return Err(AppError::capability_denied(
            "account-status principal/PCR binding mismatch",
        ));
    }
    Ok(())
}

#[salvo::oapi::endpoint(operation_id = "ak.peer.signal.command.relay", tags("events"))]
#[tracing::instrument(skip_all, fields(op = "ak.peer.signal.command.relay.v1"))]
async fn peer_signal_relay(depot: &mut Depot, req: &mut Request) -> JsonResult<SignalRelayOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    if req.headers().contains_key("idempotency-key") {
        return Err(schema_violation(
            "ak.peer.signal.command.relay.v1 forbids Idempotency-Key",
        ));
    }
    // Preserve the Signal byte-ceiling code before the shared canonical JSON
    // verifier can classify its generic ingress budget as a schema failure.
    let maximum_body_bytes =
        arkret_wire::MAX_SIGNAL_RELAY_CANONICAL_BODY_BYTES.min(req.secure_max_size());
    let payload = req
        .payload_with_max_size(maximum_body_bytes)
        .await
        .map_err(|error| match error {
            salvo::http::ParseError::PayloadTooLarge => crate::app_error!(
                PayloadTooLarge,
                "Signal relay request exceeds the body byte ceiling",
            ),
            _ => AppError::json_invalid("unable to read the Signal relay request body"),
        })?;
    if payload.len() > maximum_body_bytes {
        return Err(crate::app_error!(
            PayloadTooLarge,
            "Signal relay request exceeds the body byte ceiling",
        ));
    }
    validate_peer_request(state, req, true).await?;
    validate_signal_signature_window(req)?;
    let request = parse_json_body::<SignalRelayRequest>(
        req,
        "invalid ak.peer.signal.command.relay.v1 request body",
    )
    .await?;
    request.validate().map_err(|error| {
        if error.error_code() == Some(arkret_wire::ErrorCode::PayloadTooLarge) {
            crate::app_error!(PayloadTooLarge, error.to_string(),)
        } else {
            schema_violation(error.to_string())
        }
    })?;
    let source_id = source_id_from_request(req)?;
    for envelope in request.signals {
        if let Err(error) =
            super::sync::signal::accept_peer_signal(state, &source_id, &envelope).await
        {
            tracing::debug!(
                %error,
                realm_id = %request.realm_id,
                "peer signal item silently dropped"
            );
        }
    }
    json_ok(SignalRelayOutcome::ACCEPTED)
}

fn validate_signal_signature_window(req: &Request) -> Result<(), AppError> {
    let signature_input =
        coland_http::http_signature::parse_signature_input_header(req).map_err(|error| {
            schema_violation(format!("invalid Signal relay Signature-Input: {error}"))
        })?;
    if signature_input.expires < signature_input.created
        || signature_input.expires - signature_input.created > 5
    {
        return Err(AppError::capability_denied(
            "Signal relay signature validity window must be at most 5 seconds",
        ));
    }
    Ok(())
}

#[salvo::oapi::endpoint(operation_id = "ak.peer.events.command.submit", tags("events"))]
#[tracing::instrument(skip_all, fields(op = "ak.peer.events.command.submit.v1"))]
async fn peer_events_submit(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let peer = match authenticated_peer_context(state, req, true).await {
        Ok(peer) => peer,
        Err(error) => {
            render_app_error(res, error);
            return;
        }
    };
    let submission = match req.parse_json::<PeerAuthoritySubmitRequest>().await {
        Ok(body) => body,
        Err(_) => {
            render_error(
                res,
                StatusCode::BAD_REQUEST,
                "json_invalid",
                "invalid ak.peer.events.command.submit.v1 request body",
            );
            return;
        }
    };
    // The authority port validates each closed branch in its own order and
    // checks the outcome it returns: an `authority_forward` answers an exact
    // duplicate Event before its evidence rule (device-lifecycle §8.2.2).
    let founding_missing_dependency =
        match &submission {
            PeerAuthoritySubmitRequest::RegisteredAtomicUnit(request) => {
                match &request.unit {
                    PeerRegisteredAtomicUnit::DirectConversationFounding(unit) => {
                        match &unit.founding_authority_evidence {
                    DirectConversationFoundingAuthorityEvidence::Human {
                        contact_round_evidence,
                        ..
                    } => contact_round_evidence.request_receipts.first().map(|receipt| {
                        DirectConversationFoundingMissingDependency::ContactRoundEvidence {
                            source_event_ref: receipt.core.request_event_ref.clone(),
                        }
                    }),
                    DirectConversationFoundingAuthorityEvidence::ControllerAgent {
                        agent_provision_ref,
                        ..
                    } => Some(DirectConversationFoundingMissingDependency::AgentProvisionRef {
                        source_event_ref: agent_provision_ref.clone(),
                    }),
                }
                    }
                    _ => None,
                }
            }
            _ => None,
        };
    match state.authority().submit_peer(&peer, submission).await {
        Ok(outcome) => res.render(Json(outcome)),
        Err(error) => {
            if error.conflict_code() == Some(coland_storage::ConflictCode::DependencyMissing)
                && let Some(dependency) = founding_missing_dependency
            {
                let details = DirectConversationFoundingMissingDependencyList {
                    missing_dependencies: vec![dependency],
                };
                crate::error::render_problem_envelope(
                    res,
                    StatusCode::CONFLICT,
                    arkret_wire::problem_details::Problem::new(
                        "dependency_missing",
                        409,
                        "the peer Station lacks a founding authority dependency",
                    )
                    .with_extension(
                        "details",
                        serde_json::to_value(details).expect("typed dependency list serializes"),
                    ),
                );
                return;
            }
            if matches!(
                error,
                coland_services::ServiceError::Internal(_)
                    | coland_services::ServiceError::Database(_)
            ) {
                tracing::warn!(?error, "peer authority submission unavailable");
            }
            crate::routing::authority_commit::render_service_error(res, error);
        }
    }
}

#[cfg(test)]
#[derive(Clone, Debug)]
#[expect(
    dead_code,
    reason = "The test fixture retains its complete envelope while each unit case inspects only its relevant fields."
)]
struct PeerReadAuthz {
    source_id: String,
    realm_meta: BTreeMap<String, RealmMetaRecord>,
    realm_members: BTreeMap<String, BTreeMap<String, PeerMembership>>,
    pending_realm_invites: BTreeMap<(String, String), PendingPeerInvite>,
    circles: BTreeMap<String, PeerCircleState>,
    circle_members: BTreeMap<String, BTreeMap<String, PeerMembership>>,
}

#[cfg(test)]
#[derive(Clone, Debug)]
struct PeerMembership {
    joined_at: DateTime<Utc>,
    invited_at: Option<DateTime<Utc>>,
}

#[cfg(test)]
#[derive(Clone, Debug)]
struct PendingPeerInvite {
    invitee_account_id: arkret_wire::AccountId,
    invited_at: DateTime<Utc>,
}

#[cfg(test)]
#[derive(Clone, Debug)]
#[expect(
    dead_code,
    reason = "The test fixture retains its complete envelope while each unit case inspects only its relevant fields."
)]
struct PeerCircleState {
    realm_id: String,
    history_access: String,
    active: bool,
}

#[cfg(test)]
impl PeerReadAuthz {
    fn apply_invite_record(&mut self, record: &AcceptedEvent) {
        let Some(realm_id) = super::event_log::canonical_realm_id_for_record(record) else {
            return;
        };
        let Some(payload) = record_payload(record) else {
            return;
        };
        match arkret_wire::EventKind::from_wire(&record.kind) {
            arkret_wire::EventKind::InviteCreate => {
                let Some(invite_id) = payload.get("invite_id").and_then(Value::as_str) else {
                    return;
                };
                let Some(invitee_account) = payload.get("invitee_account_id").and_then(|value| {
                    serde_json::from_value::<arkret_wire::AccountId>(value.clone()).ok()
                }) else {
                    return;
                };
                let source_matches = invitee_account.station_id.as_str() == self.source_id;
                if source_matches {
                    self.pending_realm_invites.insert(
                        (realm_id, invite_id.to_owned()),
                        PendingPeerInvite {
                            invitee_account_id: invitee_account,
                            invited_at: record_event_time(record),
                        },
                    );
                }
            }
            arkret_wire::EventKind::InviteAccept => {
                let Some(invite_id) = payload
                    .get("invite_id")
                    .or_else(|| payload.get("invite_ref"))
                    .and_then(Value::as_str)
                else {
                    return;
                };
                let Some(invite) = self
                    .pending_realm_invites
                    .remove(&(realm_id.clone(), invite_id.to_owned()))
                else {
                    return;
                };
                let invitee = arkret_wire::ActorId::account(invite.invitee_account_id).to_string();
                if record.actor_id != invitee {
                    return;
                }
                self.realm_members.entry(realm_id).or_default().insert(
                    invitee,
                    PeerMembership {
                        joined_at: record_event_time(record),
                        invited_at: Some(invite.invited_at),
                    },
                );
            }
            _ => {}
        }
    }

    fn apply_member_record(&mut self, record: &AcceptedEvent) {
        if record.kind != arkret_wire::EventKind::MemberState.as_str() {
            return;
        }
        let Some(realm_id) = super::event_log::canonical_realm_id_for_record(record) else {
            return;
        };
        let Some(payload) = record_payload(record) else {
            return;
        };
        let Some(actor_id) = payload
            .get("member_id")
            .and_then(|value| serde_json::from_value::<arkret_wire::ActorId>(value.clone()).ok())
        else {
            return;
        };
        let actor = actor_id.to_string();
        let membership = payload
            .get("membership")
            .and_then(Value::as_str)
            .unwrap_or_default();
        match membership {
            "join" | "active" => {
                if actor_id.route_service_id().as_str() != self.source_id {
                    self.remove_realm_member(&realm_id, &actor);
                    return;
                }
                let previous = self
                    .realm_members
                    .get(&realm_id)
                    .and_then(|members| members.get(&actor));
                let membership = PeerMembership {
                    joined_at: previous
                        .map(|member| member.joined_at)
                        .unwrap_or_else(|| record_event_time(record)),
                    invited_at: previous.and_then(|member| member.invited_at),
                };
                self.realm_members
                    .entry(realm_id)
                    .or_default()
                    .insert(actor, membership);
            }
            "invite" | "invited" => {
                if let Some(member) = self
                    .realm_members
                    .entry(realm_id)
                    .or_default()
                    .get_mut(&actor)
                {
                    member
                        .invited_at
                        .get_or_insert_with(|| record_event_time(record));
                }
            }
            "leave" | "ban" | "removed" | "banned" | "left" => {
                self.remove_realm_member(&realm_id, &actor);
            }
            _ => {}
        }
    }

    fn remove_realm_member(&mut self, realm_id: &str, actor: &str) {
        if let Some(members) = self.realm_members.get_mut(realm_id) {
            members.remove(actor);
            if members.is_empty() {
                self.realm_members.remove(realm_id);
            }
        }
    }

    fn apply_circle_member_record(&mut self, record: &AcceptedEvent) {
        if record.kind != arkret_wire::EventKind::CircleMemberState.as_str() {
            return;
        }
        let Some(payload) = record_payload(record) else {
            return;
        };
        let Some(circle_id) = payload.get("circle_id").and_then(Value::as_str) else {
            return;
        };
        let Some(actor_id) = payload
            .get("member_id")
            .and_then(|value| serde_json::from_value::<arkret_wire::ActorId>(value.clone()).ok())
        else {
            return;
        };
        let actor = actor_id.to_string();
        let state = payload
            .get("membership")
            .and_then(Value::as_str)
            .unwrap_or_default();
        match state {
            "join" | "active" => {
                let previous = self
                    .circle_members
                    .get(circle_id)
                    .and_then(|members| members.get(&actor));
                let membership = PeerMembership {
                    joined_at: previous
                        .map(|member| member.joined_at)
                        .unwrap_or_else(|| record_event_time(record)),
                    invited_at: previous.and_then(|member| member.invited_at),
                };
                self.circle_members
                    .entry(circle_id.to_owned())
                    .or_default()
                    .insert(actor.to_owned(), membership);
            }
            "invite" | "invited" => {
                if let Some(member) = self
                    .circle_members
                    .entry(circle_id.to_owned())
                    .or_default()
                    .get_mut(&actor)
                {
                    member
                        .invited_at
                        .get_or_insert_with(|| record_event_time(record));
                }
            }
            "leave" | "ban" | "removed" | "banned" | "left" => {
                if let Some(members) = self.circle_members.get_mut(circle_id) {
                    members.remove(&actor);
                    if members.is_empty() {
                        self.circle_members.remove(circle_id);
                    }
                }
            }
            _ => {}
        }
    }
}

#[cfg(test)]
fn record_requires_private_plaintext_visibility(record: &AcceptedEvent) -> bool {
    if serde_json::from_value::<arkret_wire::Event>(record.envelope.clone())
        .ok()
        .is_some_and(|event| {
            matches!(
                event.kind,
                arkret_wire::EventKind::MemberState | arkret_wire::EventKind::CircleMemberState
            )
        })
    {
        // Membership changes are the accepted routing control facts used to
        // decide which peer hosts a joined member. Other plaintext payloads
        // stay behind the stricter visibility check.
        return false;
    }
    let Some(payload) = record_payload(record) else {
        return true;
    };
    !(payload.get("encrypted_content").is_some() || payload.get("encrypted_payload").is_some())
}

#[cfg(test)]
fn record_payload(record: &AcceptedEvent) -> Option<&serde_json::Map<String, Value>> {
    record.envelope.get("payload").and_then(Value::as_object)
}

#[cfg(test)]
fn record_event_time(record: &AcceptedEvent) -> DateTime<Utc> {
    record
        .envelope
        .get("created_at")
        .and_then(Value::as_str)
        .and_then(parse_rfc3339)
        .unwrap_or(record.received_at)
}

#[cfg(test)]
fn parse_rfc3339(value: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|dt| dt.with_timezone(&Utc))
}

async fn parse_json_body<T>(req: &mut Request, message: &'static str) -> Result<T, AppError>
where
    T: serde::de::DeserializeOwned,
{
    req.parse_json::<T>()
        .await
        .map_err(|_| AppError::json_invalid(message))
}

pub(in crate::routing) async fn validate_peer_request(
    state: &AppState,
    req: &mut Request,
    has_body: bool,
) -> Result<(), AppError> {
    let expected_destination = state.config().trust_domain.clone();
    if has_body {
        let trust_headers =
            crate::routing::federation::FederationTrustHeaders::from_salvo_request(req)
                .map_err(|violation| schema_violation(violation.message()))?;
        trust_headers
            .verify_destination(&expected_destination)
            .map_err(|_| {
                cross_domain_replay("Destination-Trust-Domain header does not match this service")
            })?;
    } else {
        if req.headers().contains_key("content-digest") {
            return Err(schema_violation(
                "GET peer read requests must not carry body digest headers",
            ));
        }
        if let Some(signature_input) = req
            .headers()
            .get("signature-input")
            .and_then(|value| value.to_str().ok())
        {
            let signature_input = signature_input.to_ascii_lowercase();
            if signature_input.contains("\"content-digest\"") {
                return Err(schema_violation(
                    "GET peer read Signature-Input must not bind body digest components",
                ));
            }
        }
        let destination_trust_domain = required_header(req, "destination-trust-domain")?;
        let destination_trust_domain =
            arkret_identifiers::TrustDomainId::new(destination_trust_domain)
                .map_err(|_| schema_violation("destination-trust-domain must be a trust domain"))?;
        if destination_trust_domain != expected_destination {
            return Err(cross_domain_replay(
                "Destination-Trust-Domain header does not match this service",
            ));
        }
        let source_trust_domain = required_header(req, "source-trust-domain")?;
        arkret_identifiers::TrustDomainId::new(source_trust_domain)
            .map_err(|_| schema_violation("source-trust-domain must be a trust domain"))?;
    }
    let source_id = required_header(req, HEADER_SOURCE_SERVICE_ID)?;
    if validate_did(&source_id).is_err() && arkret_wire::DidCoreId::new(source_id.clone()).is_err()
    {
        return Err(schema_violation(
            "source-service-id must be a service core_id",
        ));
    }
    let destination_id = required_header(req, HEADER_DESTINATION_SERVICE_ID)?;
    if validate_did(&destination_id).is_err()
        && arkret_wire::DidCoreId::new(destination_id.clone()).is_err()
    {
        return Err(schema_violation(
            "destination-service-id must be a service core_id",
        ));
    }
    let local_core =
        arkret_wire::project_did_to_core_id(&state.service_resolution_commitment().did)
            .map(|core| core.into_string())
            .map_err(|_| AppError::internal("local service did cannot be projected"))?;
    if destination_id != *state.service_id() && destination_id != local_core {
        return Err(cross_domain_replay(
            "destination-service-id header does not match this service",
        ));
    }
    // federation.md §3.2/§6: all `/_arkret/peer/*` requests MUST be authenticated
    // with an RFC 9421 HTTP Message Signature verified against the sender's
    // service DID key, and the local peer deny policy MUST be enforced inbound.
    // The bare trust-header checks above are necessary but not sufficient; the
    // signature verification (which also re-binds POST body digests and runs
    // the deny policy) is the authoritative gate.
    crate::routing::federation::verify_inbound_peer_http_signature(state, req, has_body).await?;
    Ok(())
}

/// Preserve the authenticated peer identity through service admission. The
/// signature verifier above binds this header to the request body and applies
/// the inbound deny policy before the context is constructed.
pub(in crate::routing) async fn authenticated_peer_context(
    state: &AppState,
    req: &mut Request,
    has_body: bool,
) -> Result<coland_services::authority_commit::AuthenticatedPeerContext, AppError> {
    validate_peer_request(state, req, has_body).await?;
    let source_service_id =
        arkret_wire::DidCoreId::new(required_header(req, HEADER_SOURCE_SERVICE_ID)?)
            .map_err(|_| schema_violation("source-service-id must be a service core_id"))?;
    Ok(coland_services::authority_commit::AuthenticatedPeerContext { source_service_id })
}

pub(in crate::routing) fn source_id_from_request(req: &Request) -> Result<String, AppError> {
    required_header(req, HEADER_SOURCE_SERVICE_ID)
}

fn required_header(req: &Request, name: &'static str) -> Result<String, AppError> {
    req.headers()
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .ok_or_else(|| schema_violation(format!("required federation header {name} missing")))
}

pub(in crate::routing) fn schema_violation(message: impl Into<String>) -> AppError {
    AppError::schema_violation(message)
}

pub(in crate::routing) fn cross_domain_replay(message: impl Into<String>) -> AppError {
    AppError::conflict(message).with_reason_code("cross_domain_replay_rejected")
}

fn render_app_error(res: &mut Response, error: AppError) {
    render_error(res, error.http_status(), error.wire_code(), &error.message);
}

#[cfg(test)]
mod internal_channel_tests {
    use std::collections::BTreeMap;

    use salvo::http::{HeaderMap, HeaderName, HeaderValue};

    use super::*;

    const TRUST_DOMAIN: &str = "ak:trust_domain:coland.example";
    const AUTHORITY_TRUST_DOMAIN: &str = "ak:trust_domain:auth.coland.example";
    const CREDENTIAL: &str = "shared-internal-channel-credential";

    fn configured_values() -> BTreeMap<String, String> {
        BTreeMap::from([
            ("COLAND_TRUST_DOMAIN".to_owned(), TRUST_DOMAIN.to_owned()),
            ("COLAND_DEVELOPMENT_MODE".to_owned(), "true".to_owned()),
            (
                "COLAND_ACCOUNT_AUTHORITY_URL".to_owned(),
                "https://auth.coland.example".to_owned(),
            ),
            (
                "COLAND_INTERNAL_AUTHORITY_SHARED_SECRET".to_owned(),
                CREDENTIAL.to_owned(),
            ),
            (
                "COLAND_ACCOUNT_AUTHORITY_TRUST_DOMAIN".to_owned(),
                AUTHORITY_TRUST_DOMAIN.to_owned(),
            ),
        ])
    }

    fn channel() -> RegisteredInternalChannel {
        RegisteredInternalChannel {
            credential: CREDENTIAL.to_owned(),
        }
    }

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for (name, value) in pairs {
            headers.insert(
                HeaderName::from_bytes(name.as_bytes()).unwrap(),
                HeaderValue::from_str(value).unwrap(),
            );
        }
        headers
    }

    fn authentic_pairs() -> Vec<(&'static str, &'static str)> {
        vec![("authorization", "Bearer shared-internal-channel-credential")]
    }

    fn authentic(pairs: &[(&str, &str)]) -> bool {
        internal_channel_request_is_authentic(&channel(), &headers(pairs))
    }

    #[test]
    fn channel_admits_only_the_configured_credential() {
        assert!(authentic(&authentic_pairs()));

        // No credential at all, a blank one, the wrong scheme and a wrong
        // secret are all the same rejection: the credential is the whole
        // authentication contract, so there is nothing else to fall back to.
        let mut without = authentic_pairs();
        without.retain(|(name, _)| *name != "authorization");
        assert!(!authentic(&without));

        for bad in [
            "Bearer ",
            "Bearer not-the-configured-credential",
            "Basic shared-internal-channel-credential",
            "shared-internal-channel-credential",
        ] {
            let mut pairs = authentic_pairs();
            pairs[0] = ("authorization", bad);
            assert!(!authentic(&pairs), "`{bad}` must not authenticate");
        }
    }

    /// Self-reported identity fields are not part of the minimal pair binding.
    /// The configured credential decides the peer; these headers neither grant
    /// nor reduce that authority.
    #[test]
    fn self_reported_identity_headers_are_ignored() {
        let mut pairs = authentic_pairs();
        for (header, conflicting) in [
            ("source-service-id", "ak:did_core:web:attacker.example"),
            ("destination-service-id", "ak:did_core:web:other.example"),
            ("source-trust-domain", "ak:trust_domain:attacker.example"),
            ("destination-trust-domain", "ak:trust_domain:other.example"),
        ] {
            pairs.push((header, conflicting));
        }
        assert!(authentic(&pairs));
    }

    /// `service-http-binding.md` §2.5.1 — no signature covers this shell, so
    /// the request must not carry the digest that exists only for one, and the
    /// receiver must not accept it as an authentication means.
    #[test]
    fn shell_content_digest_is_rejected_not_verified() {
        let mut pairs = authentic_pairs();
        pairs.push(("content-digest", "sha-256=:UjNhZGU=:"));
        assert!(!authentic(&pairs));
    }

    #[test]
    fn channel_without_explicit_authority_trust_domain_is_not_registered() {
        let mut values = configured_values();
        values.remove("COLAND_ACCOUNT_AUTHORITY_TRUST_DOMAIN");
        let config = crate::config::AppConfig::from_values(
            &values,
            crate::config::StartupOverrides::default(),
        )
        .unwrap();
        assert!(config.internal_authority_channel.is_none());
    }
}

#[cfg(test)]
mod membership_identity_tests {
    use super::*;

    fn account(station: &str) -> arkret_wire::AccountId {
        arkret_wire::AccountId::new(
            DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
            DidCoreId::new(station).unwrap(),
        )
    }

    fn record(kind: &str, actor: &arkret_wire::ActorId, payload: Value) -> AcceptedEvent {
        AcceptedEvent {
            event_id: "ak:event:AYqyX_pkT3hbwKscye0o3wq75G7axNkEMZADE88iy_gD".into(),
            actor_id: actor.to_string(),
            realm_id: Some("ak:realm:AYqyX_pkT3hbwKscye0o3wq75G7axNkEMZADE88iy_gD".into()),
            kind: kind.into(),
            schema_id: String::new(),
            digest_suite: arkret_canonical::DigestSuite::Sha256,
            canonical_digest: String::new(),
            canonical_bytes: Vec::new(),
            envelope: json!({"payload": payload}),
            received_at: Utc::now(),
        }
    }

    #[test]
    fn accepted_membership_rebuild_keeps_station_accounts_and_circle_keys_exact() {
        let source = "ak:did_core:web:source.example";
        let local = arkret_wire::ActorId::account(account(source));
        let foreign = arkret_wire::ActorId::account(account("ak:did_core:web:other.example"));
        let mut authz = PeerReadAuthz {
            source_id: source.into(),
            realm_meta: BTreeMap::new(),
            realm_members: BTreeMap::new(),
            pending_realm_invites: BTreeMap::new(),
            circles: BTreeMap::new(),
            circle_members: BTreeMap::new(),
        };
        let mut member = record(
            "ak.member.state",
            &local,
            json!({"member_id": foreign, "membership": "join"}),
        );
        let realm = member.realm_id.clone().unwrap();
        authz.apply_member_record(&member);
        assert!(authz.realm_members.is_empty());
        member.envelope["payload"] = json!({"actor_id": local, "membership": "join"});
        authz.apply_member_record(&member);
        assert!(
            authz.realm_members.is_empty(),
            "retired member carrier must not grant access"
        );
        member.envelope["payload"] = json!({"member_id": local, "membership": "join"});
        authz.apply_member_record(&member);
        assert!(authz.realm_members[&realm].contains_key(&local.to_string()));
        assert!(!authz.realm_members[&realm].contains_key(&foreign.to_string()));

        let state_only = record(
            "ak.member.state",
            &local,
            json!({"member_id": foreign, "state": "join"}),
        );
        authz.apply_member_record(&state_only);
        assert!(
            !authz.realm_members[&realm].contains_key(&foreign.to_string()),
            "retired state alias must not grant peer visibility"
        );

        let circle = "ak:circle:ATOTi3sw4NO_6LjlHGedSYTeT3Leu2J3Tb49M1gn9cFN";
        for actor in [&local, &foreign] {
            authz.apply_circle_member_record(&record(
                "ak.circle.member.state",
                actor,
                json!({"circle_id": circle, "member_id": actor, "membership": "join"}),
            ));
        }
        assert_eq!(authz.circle_members[circle].len(), 2);
        authz.apply_circle_member_record(&record(
            "ak.circle.member.state",
            &foreign,
            json!({"circle_id": circle, "member_id": foreign, "state": "leave"}),
        ));
        assert!(
            authz.circle_members[circle].contains_key(&foreign.to_string()),
            "retired state alias must not revoke canonical circle membership"
        );
        authz.apply_circle_member_record(&record(
            "ak.circle.member.state",
            &foreign,
            json!({"circle_id": circle, "member_id": foreign, "membership": "leave"}),
        ));
        assert!(authz.circle_members[circle].contains_key(&local.to_string()));
        assert!(!authz.circle_members[circle].contains_key(&foreign.to_string()));

        authz.apply_invite_record(&record(
            "ak.invite.create",
            &local,
            json!({"invite_id": "invite", "invitee_account_id": account(source)}),
        ));
        authz.apply_invite_record(&record(
            "ak.invite.accept",
            &local,
            json!({"invite_id": "invite"}),
        ));
        assert!(
            authz.realm_members[&realm][&local.to_string()]
                .invited_at
                .is_some()
        );
        assert_eq!(authz.realm_members[&realm].len(), 1);
    }

    #[test]
    fn control_plane_visibility_is_not_treated_as_private_content_processing() {
        let source = "ak:did_core:web:source.example";
        let actor = arkret_wire::ActorId::account(account(source));
        let mut control = record(
            arkret_wire::EventKind::MemberState.as_str(),
            &actor,
            json!({"member_id": actor, "membership": "leave"}),
        );
        // Only a complete accepted Event envelope proves its kind; a partial
        // envelope falls back to fail-closed payload inspection.
        control.envelope = serde_json::to_value(
            arkret_wire::test_support::raw_event_for_actor_at(
                arkret_wire::EventKind::MemberState.as_str(),
                arkret_wire::ScopeRef::Realm {
                    realm_id: arkret_wire::RealmId::new(control.realm_id.as_deref().unwrap())
                        .unwrap(),
                },
                actor.clone(),
                json!({"member_id": actor, "membership": "leave"}),
                Utc::now(),
            )
            .unwrap(),
        )
        .unwrap();
        assert!(!record_requires_private_plaintext_visibility(&control));

        let data = record(
            arkret_wire::EventKind::MessageCreate.as_str(),
            &actor,
            json!({"body": "private plaintext"}),
        );
        assert!(record_requires_private_plaintext_visibility(&data));
    }
}

#[cfg(test)]
mod account_authority_identity_tests {
    use coland_storage_postgres::Db;

    use super::*;

    fn state_with(endpoint: &str) -> AppState {
        let config = crate::config::AppConfig {
            account_authority_url: Some(endpoint.to_owned()),
            ..crate::config::AppConfig::test_default()
        };
        AppState::new(config, Db { pool: None })
    }

    #[tokio::test]
    async fn account_authority_endpoint_does_not_change_its_station_identity() {
        for endpoint in ["https://auth.example", "https://another-process.example"] {
            let state = state_with(endpoint);
            assert_eq!(
                trusted_account_authority_id(&state).await.unwrap(),
                state.service_core_id()
            );
        }
    }
}

#[cfg(test)]
mod account_status_resolution_tests {
    use super::*;

    fn account_id() -> arkret_wire::AccountId {
        arkret_wire::AccountId::new(
            DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
            DidCoreId::new("ak:did_core:web:origin.example").unwrap(),
        )
    }

    #[test]
    fn resolve_admits_only_authority_origin_or_indexed_affected_service() {
        let authority = DidCoreId::new("ak:did_core:web:authority.example").unwrap();
        let account_id = account_id();
        let affected = vec![json!({
            "service_id": "ak:did_core:web:affected.example",
            "realm_ids": [],
            "membership_frontier": []
        })];

        for authorized in [
            authority.as_str(),
            account_id.station_id.as_str(),
            "ak:did_core:web:affected.example",
        ] {
            assert!(account_status_resolve_source_authorized(
                authorized,
                &authority,
                &account_id,
                &affected,
            ));
        }
        assert!(!account_status_resolve_source_authorized(
            "ak:did_core:web:unrelated.example",
            &authority,
            &account_id,
            &affected,
        ));
    }

    #[test]
    fn account_status_reservation_is_operation_scoped_and_explicit() {
        let now = Utc::now();
        let authority = DidCoreId::new("ak:did_core:web:authority.example").unwrap();
        let mut record = coland_services::jobs::IdempotencyState {
            authenticated_actor: arkret_wire::ActorId::service(authority),
            operation_id: arkret_wire::ServiceOperationId::PEER_ACCOUNT_STATUS_COMMAND_SUBMIT_V1
                .to_owned(),
            idempotency_key: "status-7".to_owned(),
            request_hash: "sha256:fixture".to_owned(),
            response_status: ACCOUNT_STATUS_IDEMPOTENCY_RESERVED_STATUS,
            response_body: json!({"state": ACCOUNT_STATUS_IDEMPOTENCY_RESERVED_STATE}),
            created_at: now,
            expires_at: now + Duration::days(1),
        };
        assert!(account_status_idempotency_is_pending(&record));
        assert_eq!(
            record.operation_id,
            "ak.peer.account_status.command.submit.v1"
        );
        record.response_status = StatusCode::OK.as_u16() as i32;
        assert!(!account_status_idempotency_is_pending(&record));
    }
}
