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
        .push(Router::with_path("strands/watch/audit-read").post(strand_watch_audit_read))
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
    if let Err(error) = request.validate() {
        return crate::error::render_error_code(
            ErrorCode::PayloadTooLarge,
            res,
            &error.to_string(),
        );
    }
    if request.watcher_actor_id.as_account_id() != Some(&account)
        || account.station_id != state.service_core_id()
    {
        return not_found(res);
    }
    let delivery_device = if let Some(device) = session.human_device_id() {
        match crate::routing::identity::device_generation::active_device_revocation_gate_selector(
            state,
            &session.actor,
            device,
        )
        .await
        {
            Ok(selector) => Some(selector),
            Err(error) => return render_service_error(res, error),
        }
    } else {
        None
    };
    let current_authority = match state
        .authority_commits()
        .current_authority(&request.realm_id)
        .await
    {
        Ok(Some(authority)) => authority,
        Ok(None) => return not_found(res),
        Err(error) => return render_service_error(res, error),
    };
    let remote = if current_authority.service_id != state.service_core_id() {
        use arkret_models_collaboration::governance::realm_join_intake::{
            AuthorityLocatorSource, RealmJoinCandidate, RealmJoinCandidateServiceKind,
        };
        let nonce =
            arkret_wire::Base64UrlString::new(arkret_canonical::base64url_encode(rand::random::<
                [u8; 32],
            >()))
            .expect("random nonce has a valid base64url encoding");
        let hint = RealmJoinCandidate {
            service_kind: RealmJoinCandidateServiceKind::Station,
            service_id: current_authority.service_id.clone(),
            endpoint_url: None,
            source: AuthorityLocatorSource::Cache,
        };
        let located = match crate::routing::realm_join::resolve_verified_authority(
            state,
            &request.realm_id,
            &[hint],
            &nonce,
        )
        .await
        {
            Ok(located) => located,
            Err(_) => {
                return render_unresolved(
                    res,
                    ErrorCode::RevisionUnavailable,
                    ServiceOperationId::SELF_STRAND_WATCH_READ_CURRENT_V1,
                    "fresh current governor cannot be verified",
                );
            }
        };
        let verified = located.current_authority();
        if verified.generation < current_authority.generation
            || (verified.generation == current_authority.generation
                && verified != current_authority)
        {
            return render_unresolved(
                res,
                ErrorCode::RevisionUnavailable,
                ServiceOperationId::SELF_STRAND_WATCH_READ_CURRENT_V1,
                "observed authority conflicts with the peer chain",
            );
        }
        if verified.service_id != state.service_core_id()
            && state
                .authority_commits()
                .record_remote_authority(&verified, &state.service_core_id())
                .await
                .is_err()
        {
            return render_unresolved(
                res,
                ErrorCode::RevisionUnavailable,
                ServiceOperationId::SELF_STRAND_WATCH_READ_CURRENT_V1,
                "the verified governing observation could not be retained",
            );
        }
        Some(verified)
    } else {
        None
    };
    let result = if let Some(authority) = remote.as_ref() {
        let bytes = match arkret_canonical::canonical_json_bytes(&request) {
            Ok(bytes) => bytes,
            Err(_) => {
                return render_unresolved(
                    res,
                    ErrorCode::RevisionUnavailable,
                    ServiceOperationId::SELF_STRAND_WATCH_READ_CURRENT_V1,
                    "Watch request cannot be encoded",
                );
            }
        };
        use arkret_models_collaboration::strand_watch_operations::{
            PEER_STRAND_WATCH_CURRENT_PATH, STRAND_WATCH_CURRENT_MAX_BYTES,
            StrandWatchCurrentOutcome,
        };
        let response = match crate::routing::federation::outbox::signed_peer_request(
            state,
            authority.service_id.as_str(),
            PEER_STRAND_WATCH_CURRENT_PATH,
            &bytes,
            STRAND_WATCH_CURRENT_MAX_BYTES,
        )
        .await
        {
            Ok(response) => response,
            Err(_) => {
                return render_unresolved(
                    res,
                    ErrorCode::RevisionUnavailable,
                    ServiceOperationId::SELF_STRAND_WATCH_READ_CURRENT_V1,
                    "governing Watch read is unreachable",
                );
            }
        };
        if response.status == 404 {
            return not_found(res);
        }
        if response.status != 200 {
            return render_unresolved(
                res,
                ErrorCode::RevisionUnavailable,
                ServiceOperationId::SELF_STRAND_WATCH_READ_CURRENT_V1,
                "governing Watch read is unresolved",
            );
        }
        let outcome = match serde_json::from_slice::<StrandWatchCurrentOutcome>(&response.body) {
            Ok(outcome)
                if outcome
                    .validate_for_generation(&request, authority.generation)
                    .is_ok() =>
            {
                outcome
            }
            _ => {
                return render_unresolved(
                    res,
                    ErrorCode::RevisionUnavailable,
                    ServiceOperationId::SELF_STRAND_WATCH_READ_CURRENT_V1,
                    "governing Watch answer does not bind the verified request and authority",
                );
            }
        };
        Ok(SelfExactCurrentRead::Answer(outcome))
    } else {
        state
            .authority_commits()
            .strand_watch_current_for_account(&request, &account, &state.service_core_id())
            .await
    };
    match result {
        Ok(SelfExactCurrentRead::Answer(outcome)) => {
            let grant = coland_http::util::dpop_token(req);
            if let Err((status, code, message)) =
                crate::routing::identity::auth::revalidate_current_read_session(
                    state, &session, grant,
                )
                .await
            {
                return crate::routing::render_error(res, status, code, message);
            }
            let input = coland_storage::AccountContentDeliveryInput {
                realms: if remote.is_none() {
                    vec![request.realm_id.clone()]
                } else {
                    Vec::new()
                },
                watch_reads: if remote.is_none() {
                    vec![(request.clone(), outcome.clone())]
                } else {
                    Vec::new()
                },
                remote_watch_read: remote
                    .map(|authority| (request.clone(), outcome.clone(), authority)),
                watch_delivery_device: delivery_device,
                watch_local_session: if session.session_grant.is_none() {
                    session
                        .account_pk
                        .map(|pk| (session.token_hash.clone(), pk))
                } else {
                    None
                },
                ..Default::default()
            };
            let guard =
                match crate::routing::events::sync::content_delivery_guard(state, &session, &input)
                    .await
                {
                    Ok(guard) => guard,
                    Err(error) if error.code == ErrorCode::RevisionUnavailable => {
                        return render_unresolved(
                            res,
                            ErrorCode::RevisionUnavailable,
                            ServiceOperationId::SELF_STRAND_WATCH_READ_CURRENT_V1,
                            "the final remote Watch delivery cut is unproved",
                        );
                    }
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
    let Some((session, account)) = authenticated_reader(
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
    if account.station_id != state.service_core_id() {
        return not_found(res);
    }
    match resolve_media_binding(state, &account, &request).await {
        Ok(Some(outcome)) => {
            let input = coland_storage::AccountContentDeliveryInput {
                realms: vec![request.realm_id.clone()],
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
            if let Ok(response) = coland_http::result::guarded_json_ok(outcome, guard) {
                salvo::Scribe::render(response, res);
            }
        }
        Ok(None) => not_found(res),
        Err(error) => render_service_error(res, error),
    }
}

/// S2S authentication establishes the source Station, never another Account's
/// private selector. Governing scope and current are read in one durable cut.
#[handler]
pub(super) async fn peer_strand_watch_current(
    req: &mut Request,
    depot: &Depot,
    res: &mut Response,
) {
    let Some(state) = app_state(depot, res) else {
        return;
    };
    if let Err(error) = crate::routing::events::peer::validate_peer_request(state, req, true).await
    {
        return crate::routing::render_error(
            res,
            error.http_status(),
            error.wire_code(),
            &error.message,
        );
    }
    let Some(request) = parse_closed_body::<StrandWatchCurrentRequestBody>(req, res).await else {
        return;
    };
    if let Err(error) = request.validate() {
        return crate::error::render_error_code(
            ErrorCode::PayloadTooLarge,
            res,
            &error.to_string(),
        );
    }
    let source = match crate::routing::events::peer::source_id_from_request(req) {
        Ok(source) => source,
        Err(error) => {
            return crate::routing::render_error(
                res,
                error.http_status(),
                error.wire_code(),
                &error.message,
            );
        }
    };
    let Some(account) = request.watcher_actor_id.as_account_id() else {
        return not_found(res);
    };
    if account.station_id.as_str() != source {
        return not_found(res);
    }
    let result = state
        .authority_commits()
        .strand_watch_current_for_account(&request, account, &state.service_core_id())
        .await;
    match result {
        Ok(SelfExactCurrentRead::Answer(outcome)) => {
            if outcome.validate_for_request(&request).is_err() {
                return render_unresolved(
                    res,
                    ErrorCode::RevisionUnavailable,
                    ServiceOperationId::PEER_STRAND_WATCH_READ_CURRENT_V1,
                    "stored Watch result is invalid",
                );
            }
            no_store(res);
            res.render(Json(outcome));
        }
        Ok(SelfExactCurrentRead::NotFound) => not_found(res),
        Ok(SelfExactCurrentRead::Unresolved(reason)) => render_unresolved(
            res,
            ErrorCode::RevisionUnavailable,
            ServiceOperationId::PEER_STRAND_WATCH_READ_CURRENT_V1,
            reason,
        ),
        Err(error) => render_service_error(res, error),
    }
}

#[handler]
async fn strand_watch_audit_read(req: &mut Request, depot: &Depot, res: &mut Response) {
    no_store(res);
    let Some(state) = app_state(depot, res) else {
        return;
    };
    let Some((session, account)) = authenticated_reader(
        state,
        req,
        res,
        ServiceOperationId::SELF_STRAND_WATCH_COMMAND_AUDIT_READ_V1,
    )
    .await
    else {
        return;
    };
    let Some(request) = parse_closed_body::<
        arkret_models_collaboration::strand_watch_operations::WatchAuditReadRequest,
    >(req, res)
    .await
    else {
        return;
    };
    let delivery_device = if let Some(device) = session.human_device_id() {
        match crate::routing::identity::device_generation::active_device_revocation_gate_selector(
            state,
            &session.actor,
            device,
        )
        .await
        {
            Ok(gate) => Some(gate),
            Err(error) => return render_service_error(res, error),
        }
    } else {
        None
    };
    let (outcome, authority) =
        match crate::state::authority_audit_unit::submit_self_read(state, &session, &request).await
        {
            Ok(result) => result,
            Err(error) => return render_service_error(res, error),
        };
    if request.audit_submission.event.actor_id.as_account_id() != Some(&account) {
        return not_found(res);
    }
    if let Err((status, code, message)) =
        crate::routing::identity::auth::revalidate_current_read_session(
            state,
            &session,
            coland_http::util::dpop_token(req),
        )
        .await
    {
        return crate::routing::render_error(res, status, code, message);
    }
    let input = coland_storage::AccountContentDeliveryInput {
        audited_watch_read: Some((request, outcome.clone(), authority)),
        watch_delivery_device: delivery_device,
        watch_local_session: if session.session_grant.is_none() {
            session
                .account_pk
                .map(|pk| (session.token_hash.clone(), pk))
        } else {
            None
        },
        ..Default::default()
    };
    let guard =
        match crate::routing::events::sync::content_delivery_guard(state, &session, &input).await {
            Ok(guard) => guard,
            Err(error) if error.code == ErrorCode::RevisionUnavailable => {
                return render_unresolved(
                    res,
                    ErrorCode::RevisionUnavailable,
                    ServiceOperationId::SELF_STRAND_WATCH_COMMAND_AUDIT_READ_V1,
                    "audit delivery cut unavailable",
                );
            }
            Err(_) => return not_found(res),
        };
    if let Ok(response) = coland_http::result::guarded_json_ok(outcome, guard) {
        salvo::Scribe::render(response, res);
    }
}

#[handler]
pub(super) async fn peer_strand_watch_audit_read(
    req: &mut Request,
    depot: &Depot,
    res: &mut Response,
) {
    no_store(res);
    let Some(state) = app_state(depot, res) else {
        return;
    };
    let peer = match super::events::peer::authenticated_peer_context(state, req, true).await {
        Ok(peer) => peer,
        Err(error) => {
            return crate::routing::render_error(
                res,
                error.http_status(),
                error.wire_code(),
                &error.message,
            );
        }
    };
    let Some(request) = parse_closed_body::<
        arkret_models_collaboration::strand_watch_operations::PeerWatchAuditReadRequest,
    >(req, res)
    .await
    else {
        return;
    };
    if let Err(error) = request.validate_carrier_shape() {
        return crate::error::render_error_code(
            ErrorCode::SchemaViolation,
            res,
            &error.to_string(),
        );
    }
    let outcome =
        match crate::state::authority_audit_unit::submit_peer_read(state, &peer, &request).await {
            Ok(outcome) => outcome,
            Err(error) => return render_service_error(res, error),
        };
    let signature = match coland_http::http_signature::parse_signature_input_header(req) {
        Ok(signature) => signature,
        Err(error) => {
            return crate::error::render_error_code(
                ErrorCode::SignatureInvalid,
                res,
                &error.to_string(),
            );
        }
    };
    let Some(expires_at) = chrono::DateTime::from_timestamp(signature.expires as i64, 0) else {
        return crate::error::render_error_code(
            ErrorCode::SignatureWindowInvalid,
            res,
            "peer signature expiry invalid",
        );
    };
    let guard = match state
        .authority_commits()
        .watch_audit_read_delivery_guard(
            &request.logical_request(),
            &outcome,
            &state.service_core_id(),
            expires_at,
        )
        .await
    {
        Ok(guard) => guard,
        Err(error) => return render_service_error(res, error.into()),
    };
    if let Ok(response) = coland_http::result::guarded_json_ok(outcome, Some(guard)) {
        salvo::Scribe::render(response, res);
    }
}

async fn resolve_media_binding(
    state: &AppState,
    account: &AccountId,
    request: &MediaServiceBindingRequestBody,
) -> coland_services::ServiceResult<Option<arkret_models_identity::MediaServiceBindingOutcome>> {
    use arkret_models_identity::MediaServiceBindingOutcome;
    use coland_services::ServiceError;
    let unavailable =
        |detail: &str| ServiceError::Conflict(format!("temporarily_unavailable: {detail}"));
    let anchor = state
        .authority_commits()
        .media_service_anchor_for_account(&request.realm_id, account, &state.service_core_id())
        .await?;
    let MediaServiceAnchorRead::Anchored { value, .. } = &anchor else {
        return Ok(None);
    };
    let (route, signing_keys) = super::media_service_binding::resolve_issuer(state, value).await?;
    let now = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    let outcome = MediaServiceBindingOutcome {
        request_id: request.request_id.clone(),
        realm_id: request.realm_id.clone(),
        route,
        signing_keys,
        observed_at: now,
        expires_at: now + chrono::Duration::seconds(300),
    };
    outcome
        .validate_for_request(request, &value.service_id)
        .map_err(|e| unavailable(&e.to_string()))?;
    let current = state
        .authority_commits()
        .media_service_anchor_for_account(&request.realm_id, account, &state.service_core_id())
        .await?;
    if matches!(current, MediaServiceAnchorRead::NotFound) {
        return Ok(None);
    }
    if current != anchor {
        return Err(unavailable(
            "accepted media assignment changed during resolution",
        ));
    }
    Ok(Some(outcome))
}
