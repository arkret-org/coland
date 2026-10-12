//! Authenticated, non-enumerating self reads answered from one governing
//! read cut:
//!
//! - `GET  /_arkret/self/realms/{realm_id}/streams` (`ak.self.realm.read.streams.v1`)
//! - `POST /_arkret/self/current-results/exact` (`ak.self.current_results.read.exact.v1`)
//! - `POST /_arkret/self/strands/watch/current` (`ak.self.strand.watch.read.current.v1`)
//! - `POST /_arkret/self/media-service-bindings/query`
//!   (`ak.self.media_service_binding.read.resolve.v1`)
//!
//! Invisible, foreign, unknown and unauthorized selectors share the universal
//! `not_found`. A visible selector whose current basis this Station cannot
//! confirm fails closed with the registered unresolved code; absence is never
//! inferred from a missing row, a snapshot omission or local Event order.

use arkret_models_collaboration::exact_current_results::ExactCurrentResultsReadRequestBody;
use arkret_models_collaboration::strand_watch_operations::StrandWatchCurrentRequestBody;
use arkret_models_identity::service_binding_results::MediaServiceBindingRequestBody;
use arkret_wire::{AccountId, ErrorCode, ServiceOperationId};
use coland_storage::{MediaServiceAnchorRead, SelfExactCurrentRead};
use salvo::prelude::*;

use super::authority_commit::{no_store, parse_closed_body, render_service_error};
use crate::state::AppState;

mod stream_listing;

pub(super) fn router() -> Router {
    Router::new()
        .push(Router::with_path("realms/{realm_id}/streams").get(stream_listing::realm_streams))
        .push(Router::with_path("current-results/exact").post(exact_current_results))
        .push(Router::with_path("strands/watch/current").post(strand_watch_current))
        .push(Router::with_path("media-service-bindings/query").post(media_service_binding))
}

fn not_found(res: &mut Response) {
    crate::error::render_error_code(ErrorCode::NotFound, res, "not found");
}

fn app_state<'a>(depot: &'a Depot, res: &mut Response) -> Option<&'a AppState> {
    match depot.get_typed::<AppState>() {
        Ok(state) => Some(state),
        Err(_) => {
            crate::error::render_error_code(
                ErrorCode::InternalError,
                res,
                "service state is unavailable",
            );
            None
        }
    }
}

/// Authenticate the session, bind any Agent session to `operation`, and
/// return its Account. Every exact current read is decided for an Account
/// member; any other actor has no visible selector.
async fn authenticated_account(
    state: &AppState,
    req: &mut Request,
    res: &mut Response,
    operation: &'static str,
) -> Option<AccountId> {
    authenticated_reader(state, req, res, operation)
        .await
        .map(|(_, account)| account)
}

async fn authenticated_reader(
    state: &AppState,
    req: &mut Request,
    res: &mut Response,
    operation: &'static str,
) -> Option<(coland_services::identity::SessionIdentityState, AccountId)> {
    let session = crate::routing::auth_or_render(state, req, res).await?;
    let actor =
        match crate::routing::identity::session_actor::validated_session_actor(state, &session)
            .await
        {
            Ok(actor) => actor,
            Err(error) => {
                crate::routing::render_error(
                    res,
                    error.http_status(),
                    error.wire_code(),
                    &error.message,
                );
                return None;
            }
        };
    if let Err(error) = crate::routing::events::require_agent_session_scope(&session, operation) {
        crate::routing::render_error(res, error.http_status(), error.wire_code(), &error.message);
        return None;
    }
    let Some(account) = actor.as_account_id() else {
        not_found(res);
        return None;
    };
    Some((session, account.clone()))
}

fn render_unresolved(res: &mut Response, code: ErrorCode, operation: &str, reason: &str) {
    tracing::info!(
        operation,
        reason,
        "self current read is not provable at this cut"
    );
    crate::error::render_error_code(
        code,
        res,
        "the current governing basis cannot be confirmed at this cut",
    );
}

/// `ak.self.current_results.read.exact.v1`.
#[handler]
async fn exact_current_results(req: &mut Request, depot: &Depot, res: &mut Response) {
    let Some(state) = app_state(depot, res) else {
        return;
    };
    let Some((session, account)) = authenticated_reader(
        state,
        req,
        res,
        ServiceOperationId::SELF_CURRENT_RESULTS_READ_EXACT_V1,
    )
    .await
    else {
        return;
    };
    let Some(request) = parse_closed_body::<ExactCurrentResultsReadRequestBody>(req, res).await
    else {
        return;
    };
    if let Err(error) = request.validate() {
        return crate::error::render_error_code(
            ErrorCode::SchemaViolation,
            res,
            &format!("invalid exact current-result selector: {error}"),
        );
    }
    let result = state
        .authority_commits()
        .exact_current_result_for_account(&request, &account, &state.service_core_id())
        .await;
    match result {
        Ok(SelfExactCurrentRead::Answer(outcome)) => {
            let input = coland_storage::AccountContentDeliveryInput {
                realms: vec![request.realm_id.clone()],
                exact_reads: vec![(request.clone(), outcome.clone())],
                ..Default::default()
            };
            let guard =
                match crate::routing::events::sync::content_delivery_guard(state, &session, &input)
                    .await
                {
                    Ok(guard) => guard,
                    Err(_) => return not_found(res),
                };
            no_store(res);
            let Ok(response) = coland_http::result::guarded_json_ok(outcome, guard) else {
                return;
            };
            salvo::Scribe::render(response, res);
        }
        Ok(SelfExactCurrentRead::NotFound) => not_found(res),
        Ok(SelfExactCurrentRead::Unresolved(reason)) => render_unresolved(
            res,
            ErrorCode::RevisionUnavailable,
            ServiceOperationId::SELF_CURRENT_RESULTS_READ_EXACT_V1,
            reason,
        ),
        Err(error) => render_service_error(res, error),
    }
}

/// `ak.self.strand.watch.read.current.v1`. Only the watcher itself may read
/// its cell; another actor's selector is `not_found`.
#[handler]
async fn strand_watch_current(req: &mut Request, depot: &Depot, res: &mut Response) {
    let Some(state) = app_state(depot, res) else {
        return;
    };
    let Some((session, account)) = authenticated_reader(
        state,
        req,
        res,
        ServiceOperationId::SELF_STRAND_WATCH_READ_CURRENT_V1,
    )
    .await
    else {
        return;
    };
    let Some(request) = parse_closed_body::<StrandWatchCurrentRequestBody>(req, res).await else {
        return;
    };
    let result = state
        .authority_commits()
        .strand_watch_current_for_account(&request, &account, &state.service_core_id())
        .await;
    match result {
        Ok(SelfExactCurrentRead::Answer(outcome)) => {
            let input = coland_storage::AccountContentDeliveryInput {
                realms: vec![request.realm_id.clone()],
                watch_reads: vec![(request.clone(), outcome.clone())],
                ..Default::default()
            };
            let guard =
                match crate::routing::events::sync::content_delivery_guard(state, &session, &input)
                    .await
                {
                    Ok(guard) => guard,
                    Err(_) => return not_found(res),
                };
            no_store(res);
            let Ok(response) = coland_http::result::guarded_json_ok(outcome, guard) else {
                return;
            };
            salvo::Scribe::render(response, res);
        }
        Ok(SelfExactCurrentRead::NotFound) => not_found(res),
        Ok(SelfExactCurrentRead::Unresolved(reason)) => render_unresolved(
            res,
            ErrorCode::RevisionUnavailable,
            ServiceOperationId::SELF_STRAND_WATCH_READ_CURRENT_V1,
            reason,
        ),
        Err(error) => render_service_error(res, error),
    }
}

/// `ak.self.media_service_binding.read.resolve.v1`. The request's Account
/// must be the session's own Account on this Station. A visible Realm with an
/// accepted assignment is answered only from a resolved route and method
/// state; until that resolution is available it is unresolved, never a
/// guessed route.
#[handler]
async fn media_service_binding(req: &mut Request, depot: &Depot, res: &mut Response) {
    let Some(state) = app_state(depot, res) else {
        return;
    };
    let Some(account) = authenticated_account(
        state,
        req,
        res,
        ServiceOperationId::SELF_MEDIA_SERVICE_BINDING_READ_RESOLVE_V1,
    )
    .await
    else {
        return;
    };
    let Some(request) = parse_closed_body::<MediaServiceBindingRequestBody>(req, res).await else {
        return;
    };
    if let Err(error) = request.validate() {
        return crate::error::render_error_code(
            ErrorCode::SchemaViolation,
            res,
            &format!("invalid media service binding request: {error}"),
        );
    }
    if request.account_id != account || account.station_id != state.service_core_id() {
        return not_found(res);
    }
    let result = state
        .authority_commits()
        .media_service_anchor_for_account(&request.realm_id, &account, &state.service_core_id())
        .await;
    match result {
        Ok(MediaServiceAnchorRead::NotFound) => not_found(res),
        Ok(MediaServiceAnchorRead::Anchored) => render_unresolved(
            res,
            ErrorCode::TemporarilyUnavailable,
            ServiceOperationId::SELF_MEDIA_SERVICE_BINDING_READ_RESOLVE_V1,
            "the accepted media service route and method state are not resolved",
        ),
        Err(error) => render_service_error(res, error),
    }
}
