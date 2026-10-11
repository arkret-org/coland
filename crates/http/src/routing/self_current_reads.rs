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
use arkret_wire::{AccountId, ErrorCode, RealmId, RealmStreamList, ServiceOperationId};
use coland_storage::{AccountRealmStreamList, MediaServiceAnchorRead, SelfExactCurrentRead};
use salvo::prelude::*;

use super::authority_commit::{no_store, parse_closed_body, render_service_error};
use crate::state::AppState;

pub(super) fn router() -> Router {
    Router::new()
        .push(Router::with_path("realms/{realm_id}/streams").get(realm_streams))
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
    Some(account.clone())
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

/// `ak.self.realm.read.streams.v1`. Pages come from one fixed server-side
/// generation; this Station serves every provable listing as a single page,
/// so it never issues a continuation cursor and rejects any presented one.
#[handler]
async fn realm_streams(req: &mut Request, depot: &Depot, res: &mut Response) {
    let Some(state) = app_state(depot, res) else {
        return;
    };
    let Some(account) = authenticated_account(
        state,
        req,
        res,
        ServiceOperationId::SELF_REALM_READ_STREAMS_V1,
    )
    .await
    else {
        return;
    };
    let Some(realm_id) = req
        .param::<String>("realm_id")
        .and_then(|value| RealmId::new(value).ok())
    else {
        return crate::error::render_error_code(
            ErrorCode::SchemaViolation,
            res,
            "realm_id is not a Realm id",
        );
    };
    if let Some(limit) = req.query::<String>("limit")
        && !limit
            .parse::<u16>()
            .is_ok_and(|parsed| (1..=500).contains(&parsed) && parsed.to_string() == limit)
    {
        return crate::error::render_error_code(
            ErrorCode::SchemaViolation,
            res,
            "limit must be an integer in 1..=500",
        );
    }
    if let Some(token) = req.query::<String>("cursor") {
        if let Err(error) = arkret_server::CursorAuthority::decode_stream(&token) {
            match error {
                arkret_server::CursorAuthorityError::ParamInvalid(message) => {
                    crate::error::render_error_with_reason_code(
                        res,
                        crate::error::error_http_status(ErrorCode::ParamInvalid),
                        ErrorCode::ParamInvalid.as_str(),
                        &message,
                        arkret_wire::ReasonCode::INVALID_CURSOR,
                        None,
                    )
                }
                arkret_server::CursorAuthorityError::Expired => crate::error::render_error_code(
                    ErrorCode::CursorExpired,
                    res,
                    "cursor has expired",
                ),
                arkret_server::CursorAuthorityError::IntegrityInvalid => {
                    crate::error::render_error_code(
                        ErrorCode::CursorIntegrityInvalid,
                        res,
                        "cursor issuance cannot be proved",
                    )
                }
            }
            return;
        }
        return crate::error::render_error_code(
            ErrorCode::CursorIntegrityInvalid,
            res,
            "the cursor was not issued for this enumeration; restart it",
        );
    }
    let result = state
        .authority_commits()
        .list_realm_streams_for_account(&realm_id, &account, &state.service_core_id())
        .await;
    match result {
        Ok(AccountRealmStreamList::Listed(streams)) => {
            no_store(res);
            res.render(Json(RealmStreamList {
                realm_id,
                streams,
                next_cursor: None,
                has_more: false,
            }));
        }
        Ok(AccountRealmStreamList::NotVisible) => not_found(res),
        Ok(AccountRealmStreamList::Unproved(reason)) => render_unresolved(
            res,
            ErrorCode::TemporarilyUnavailable,
            ServiceOperationId::SELF_REALM_READ_STREAMS_V1,
            reason,
        ),
        Err(error) => render_service_error(res, error),
    }
}

/// `ak.self.current_results.read.exact.v1`.
#[handler]
async fn exact_current_results(req: &mut Request, depot: &Depot, res: &mut Response) {
    let Some(state) = app_state(depot, res) else {
        return;
    };
    let Some(account) = authenticated_account(
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
            no_store(res);
            res.render(Json(outcome));
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
    let Some(account) = authenticated_account(
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
            no_store(res);
            res.render(Json(outcome));
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
