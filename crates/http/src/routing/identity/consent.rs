//! Holder-private Consent routes.
//!
//! Caller-signed Events are admitted by the PCR current unit. Holder reads
//! and introduction evidence use that same durable current, without caches.

use arkret_models_collaboration::consent_operations::{
    ConsentGrantRequestBody, ConsentList, ConsentRequestOutcome, ConsentRequestRequestBody,
    ConsentRevokeRequestBody, ConsentView,
};
use arkret_wire::AccountDataKey;
use chrono::{DateTime, Utc};
use coland_storage::{ConsentRequestQuarantineInput, ConsentRequestQuarantineOutcome};
use salvo::oapi::extract::JsonBody;
use salvo::prelude::*;

use super::AuthArgs;
use super::device_messages::{
    ActorPrivateAccountDataOperation, ActorPrivateAccountDataUpdate, ActorPrivateDeviceUpdate,
    fanout_actor_private_update, station_device_message_sender,
};
use crate::error::AppError;
use crate::state::AppState;
use crate::{JsonResult, json_ok};

pub(super) fn router() -> Router {
    Router::with_path("consent")
        .push(Router::with_path("results").get(list_consents))
        .push(Router::with_path("result").get(get_consent))
        .push(Router::with_path("results/grant").post(grant_consent))
        .push(Router::with_path("results/revoke").post(revoke_consent))
        .push(Router::with_path("request").post(request_consent))
        .push(Router::with_path("current").post(read_full_current))
}

#[salvo::handler]
async fn read_full_current(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<arkret_models_collaboration::consent_operations::ConsentCurrentReadRequestBody>,
) -> JsonResult<arkret_models_collaboration::consent_operations::ConsentCurrentReadOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    crate::routing::events::require_agent_session_scope(
        &session,
        arkret_wire::ServiceOperationId::SELF_CONSENT_READ_CURRENT_V1,
    )?;
    let holder = super::auth_grant_dpop::authenticated_session_account_id(state, &session).await?;
    let body = body.into_inner();
    if body.holder_account_id != holder {
        return Err(AppError::capability_denied(
            "Consent current read belongs to another holder",
        ));
    }
    json_ok(crate::state::authority_consent::read_current(state, &body).await?)
}

#[salvo::handler]
#[tracing::instrument(skip_all, fields(op = "ak.self.consent.read.list.v1"))]
async fn list_consents(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<ConsentList> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let holder = super::auth_grant_dpop::authenticated_session_account_id(state, &session).await?;
    let records = state
        .persistence()
        .consent_current(&holder)
        .await
        .map_err(|error| consent_error(error.into()))?;
    json_ok(ConsentList {
        consents: records.iter().map(|record| record.view()).collect(),
    })
}

#[salvo::handler]
#[tracing::instrument(skip_all, fields(op = "ak.self.consent.resource.get.v1"))]
async fn get_consent(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<ConsentView> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let holder = super::auth_grant_dpop::authenticated_session_account_id(state, &session).await?;
    let peer_raw = req
        .query::<String>("peer")
        .ok_or_else(|| AppError::param_invalid("peer is required"))?;
    let peer: arkret_models_collaboration::events_payloads::consent::ConsentPeer =
        serde_json::from_str(&peer_raw).map_err(|e| AppError::param_invalid(e.to_string()))?;
    let scope = req
        .query::<String>("consent_scope")
        .map(|value| {
            serde_json::from_value::<arkret_wire::ConsentScope>(serde_json::Value::String(value))
        })
        .transpose()
        .map_err(|e| AppError::param_invalid(e.to_string()))?;
    let mut records = state
        .persistence()
        .consent_current(&holder)
        .await
        .map_err(|error| consent_error(error.into()))?
        .into_iter()
        .filter(|record| {
            record.value.peer == peer
                && scope.is_none_or(|scope| record.value.consent_scope == scope)
        });
    let record = records
        .next()
        .ok_or_else(|| crate::app_error!(NotFound, "Consent does not exist"))?;
    if records.next().is_some() {
        return Err(crate::app_error!(
            FailedPrecondition,
            "Consent peer and scope match multiple IDs"
        ));
    }
    json_ok(record.view())
}

#[salvo::handler]
#[tracing::instrument(skip_all, fields(op = "ak.self.consent.command.grant.v1"))]
async fn grant_consent(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<ConsentGrantRequestBody>,
) -> JsonResult<ConsentView> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let body = body.into_inner();
    body.validate()
        .map_err(|error| AppError::param_invalid(format!("grant_event: {error}")))?;
    let outcome = crate::state::authority_consent::submit(state, &session, &body.grant_event)
        .await
        .map_err(consent_error)?;
    let record = match outcome {
        coland_storage::ConsentAdmissionOutcome::Committed(record)
        | coland_storage::ConsentAdmissionOutcome::Duplicate(record) => record,
    };
    json_ok(record.view())
}

#[salvo::handler]
#[tracing::instrument(skip_all, fields(op = "ak.self.consent.command.revoke.v1"))]
async fn revoke_consent(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<ConsentRevokeRequestBody>,
) -> JsonResult<ConsentView> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let body = body.into_inner();
    body.validate()
        .map_err(|error| AppError::param_invalid(format!("revoke_event: {error}")))?;
    let outcome = crate::state::authority_consent::submit(state, &session, &body.revoke_event)
        .await
        .map_err(consent_error)?;
    let record = match outcome {
        coland_storage::ConsentAdmissionOutcome::Committed(record)
        | coland_storage::ConsentAdmissionOutcome::Duplicate(record) => record,
    };
    json_ok(record.view())
}

#[salvo::handler]
#[tracing::instrument(skip_all, fields(op = "ak.self.consent.command.request.v1"))]
async fn request_consent(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<ConsentRequestRequestBody>,
) -> JsonResult<ConsentRequestOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let body = body.into_inner();
    body.validate()
        .map_err(|error| AppError::param_invalid(format!("consent request: {error}")))?;
    let requester =
        super::auth_grant_dpop::authenticated_session_account_id(state, &session).await?;
    let actor = super::session_actor::validated_session_actor(state, &session).await?;
    if actor.as_account_id() != Some(&requester) {
        return Err(AppError::unauthenticated(
            "Consent requester differs from its authenticated Account",
        ));
    }
    // The self route is Station-local. Remote or unknown holders receive the
    // same opaque result as quota, policy and successful queue admission.
    if body.holder_account_id.station_id != state.service_core_id() {
        return json_ok(ConsentRequestOutcome::accepted());
    }
    let quota_constraints = state
        .config()
        .receive_policy_constraints
        .as_ref()
        .and_then(|constraints| constraints.new_source_quota.clone())
        .unwrap_or_default();
    let received_at = arkret_canonical::normalize_timestamp_canonical(Utc::now());
    let source_digest = crate::routing::invites::new_source_ledger_digest(
        state,
        &body.holder_account_id,
        requester.principal_id.as_str(),
    );
    let admitted = state
        .persistence()
        .admit_consent_request_quarantine(ConsentRequestQuarantineInput {
            holder: body.holder_account_id.clone(),
            requester,
            consent_scope: body.consent_scope,
            source_digest,
            received_at,
            quota_constraints,
        })
        .await;
    if let Ok(ConsentRequestQuarantineOutcome::Queued(record)) = admitted {
        // Only the committed CAS winner is delivered, and its complete row is
        // the content every active holder device can read independently.
        fanout_actor_private_update(
            state,
            body.holder_account_id.principal_id.as_str(),
            ActorPrivateDeviceUpdate::AccountData {
                sender: station_device_message_sender(state),
                content: ActorPrivateAccountDataUpdate {
                    operation: ActorPrivateAccountDataOperation::Put,
                    account_data_key: AccountDataKey::ACCOUNT_HOLDER_QUARANTINE.to_owned(),
                    revision: record.revision,
                    content: Some(record.payload),
                    updated_at: record.updated_at,
                },
                created_at: record.updated_at,
            },
        )
        .await;
    } else if let Err(error) = admitted {
        // A storage refusal must not reveal holder presence or policy through
        // the requester's response. The transaction has already rolled back.
        tracing::warn!(%error, "Consent request quarantine admission failed closed");
    }
    json_ok(ConsentRequestOutcome::accepted())
}

pub(crate) fn consent_error(error: coland_services::ServiceError) -> AppError {
    use arkret_wire::ErrorCode;
    use coland_services::ServiceError;
    let code = match &error {
        ServiceError::NotFound(_) => ErrorCode::NotFound,
        ServiceError::SchemaViolation(_) => ErrorCode::SchemaViolation,
        ServiceError::UnsupportedEventKind(_) => ErrorCode::UnsupportedEventKind,
        ServiceError::Conflict(_) => error
            .conflict_code()
            .and_then(|code| ErrorCode::from_wire(code.as_str()))
            .unwrap_or(ErrorCode::CapabilityDenied),
        ServiceError::Database(_) | ServiceError::Internal(_) => ErrorCode::InternalError,
    };
    AppError::from_rejection(code, error.to_string())
}

/// Introduction evidence must be checked against the holder's current
/// authority. A local legacy grant-dot cache is never proof of freshness.
pub(crate) async fn has_active_consent_grant_evidence(
    state: &AppState,
    subject: &str,
    holder_station_id: &str,
    inviter_actor_id: &arkret_wire::ActorId,
    consent_grant_ref: &str,
    consent_id: Option<&str>,
    at: DateTime<Utc>,
) -> bool {
    let Ok(principal) = arkret_wire::DidCoreId::new(subject.to_owned()) else {
        return false;
    };
    let Ok(station) = arkret_wire::DidCoreId::new(holder_station_id.to_owned()) else {
        return false;
    };
    if station != state.service_core_id() {
        return false;
    }
    let holder = arkret_wire::AccountId::new(principal, station);
    let Ok(records) = state.persistence().consent_current(&holder).await else {
        return false;
    };
    records.iter().any(|record| {
        record.event.event_id.as_str() == consent_grant_ref
            && consent_id.is_none_or(|id| record.value.consent_id.as_str() == id)
            && record.permits(inviter_actor_id, arkret_wire::ConsentScope::Invite, at)
    })
}
