//! Holder-private Consent routes.
//!
//! Caller-signed Events are admitted by the PCR current unit. Holder reads
//! and introduction evidence use that same durable current, without caches.

use arkret_models_collaboration::consent_operations::{
    ConsentGrantRequestBody, ConsentList, ConsentRequestOutcome, ConsentRequestRequestBody,
    ConsentRevokeRequestBody, ConsentView,
};
use salvo::oapi::extract::JsonBody;
use salvo::prelude::*;

use super::AuthArgs;
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
    super::auth_grant_dpop::authenticated_session_account_id(state, &session).await?;
    json_ok(crate::routing::consent_private::list(state, &session).await?)
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
    super::auth_grant_dpop::authenticated_session_account_id(state, &session).await?;
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
    let mut records = crate::routing::consent_private::list(state, &session)
        .await?
        .consents
        .into_iter()
        .filter(|record| {
            record.peer == peer && scope.is_none_or(|scope| record.consent_scope == scope)
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
    json_ok(record)
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
    json_ok(
        crate::routing::consent_private::submit_consent(state, &session, &body.grant_event).await?,
    )
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
    json_ok(
        crate::routing::consent_private::submit_consent(state, &session, &body.revoke_event)
            .await?,
    )
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
    use arkret_models_collaboration::consent_private::*;
    let result = crate::routing::consent_private::execute(
        state,
        &body.holder_account_id,
        ConsentPrivateContext::Station(ConsentPrivateStationContext {
            kind: ConsentPrivateStationContextKind::Station,
            actor_id: arkret_wire::ActorId::service(state.service_core_id()),
        }),
        ConsentPrivateCommand::Request(ConsentPrivateRequestCommand {
            kind: ConsentPrivateRequestCommandKind::Request,
            body: ConsentPrivateRequestBody {
                requester_actor_id: actor,
                request: body.clone(),
            },
        }),
    )
    .await;
    if result.is_err() {
        tracing::debug!("Consent request admission deferred without disclosure");
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
        ServiceError::Conflict(detail) => detail
            .split_once(':')
            .and_then(|(code, _)| ErrorCode::from_wire(code.trim()))
            .or_else(|| {
                error
                    .conflict_code()
                    .and_then(|code| ErrorCode::from_wire(code.as_str()))
            })
            .unwrap_or(ErrorCode::CapabilityDenied),
        ServiceError::Database(_) | ServiceError::Internal(_) => ErrorCode::InternalError,
    };
    AppError::from_rejection(code, error.to_string())
}
