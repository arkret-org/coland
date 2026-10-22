//! Realm join preparation and post-admission bootstrap on the current v1 carriers.

use arkret_models_collaboration::governance::membership_invite::{
    MembershipPayload, MembershipPayloadState,
};
use arkret_models_collaboration::governance::realm_join_intake::{
    PeerRealmJoinBootstrapOutcome, PeerRealmJoinBootstrapRequestBody, SelfRealmJoinPrepareOutcome,
    SelfRealmJoinPrepareRequestBody,
};
use arkret_wire::{ActorId, AuthorityBundleRequest, Base64UrlString, CommitStreamRef, EventKind};
use coland_http::error::AppError;
use coland_http::result::{JsonResult, json_ok};
use salvo::prelude::*;
use serde_json::Value;

use crate::routing::system::extract::AuthArgs;
use crate::state::AppState;
mod authority;
mod preview;

pub(crate) use authority::{
    LocatedRealmAuthority, fetch_authority_bundle_of_service, insert_historical_method_key,
    resolve_verified_authority, resolve_verified_authority_of_service,
    verified_keys as verified_bundle_keys, verify_served_bundle,
};

pub(super) fn self_router() -> Router {
    Router::new()
        .push(Router::with_path("realm-joins/preview").post(preview::self_preview))
        .push(Router::with_path("realm-joins/prepare").post(prepare))
}

pub(super) fn peer_router() -> Router {
    Router::new()
        .push(Router::with_path("realm-joins/preview").post(preview::peer_preview))
        .push(Router::with_path("realm-joins/bootstrap").post(peer_bootstrap))
}

fn invalid_request(error: impl std::fmt::Display) -> AppError {
    AppError::param_invalid(error.to_string())
}

fn unavailable(error: impl std::fmt::Display) -> AppError {
    AppError::internal(format!("Realm authority evidence unavailable: {error}"))
}

pub(crate) fn nonce_for_request(
    request_id: &arkret_wire::RequestId,
) -> Result<Base64UrlString, AppError> {
    Base64UrlString::new(request_id.as_str().trim_start_matches("ak:request:"))
        .map_err(invalid_request)
}

/// This Station's own nonce-bound bundle for a Realm it currently governs.
/// A Realm governed elsewhere fails here, so the result is never a claim of
/// authority this Station does not hold.
pub(crate) async fn local_authority_bundle(
    state: &AppState,
    realm_id: &arkret_wire::RealmId,
    nonce: &Base64UrlString,
) -> Result<arkret_wire::RealmAuthorityBundle, AppError> {
    if let Some(current) = state
        .authority_commits()
        .current_authority(realm_id)
        .await
        .map_err(unavailable)?
        && current.service_id != state.service_core_id()
    {
        // A known former governor remains a locator after a planned handoff.
        // Relay the new governor's nonce-bound original; never sign a cached
        // assertion or treat the old Station's route as current authority.
        let bundle = authority::fetch_authority_bundle_of_service(
            state,
            realm_id,
            &current.service_id,
            nonce,
        )
        .await?;
        let located = authority::verify_served_bundle(state, bundle, nonce).await?;
        let verified = located.current_authority();
        if verified.realm_id != *realm_id
            || verified.generation < current.generation
            || (verified.generation == current.generation && verified != current)
        {
            return Err(unavailable(
                "relayed authority conflicts with the observed governing cut",
            ));
        }
        return Ok(located.bundle);
    }
    let route =
        crate::routing::system::service_resolution::current_authenticated_service_resolution(state)
            .await?;
    let route = serde_json::to_value(route).map_err(unavailable)?;
    let verification_method = state
        .service_verification_method("notary-key")
        .map_err(unavailable)?;
    state
        .authority_commits()
        .authority_bundle(
            &AuthorityBundleRequest {
                realm_id: realm_id.clone(),
                nonce: nonce.clone(),
            },
            &state.service_core_id(),
            route,
            verification_method,
            state.notary_signing_key().as_ref(),
            crate::wire::now(),
        )
        .await
        .map_err(|error| match error {
            coland_services::ServiceError::NotFound(_) => {
                AppError::not_found("Realm authority not found")
            }
            other => unavailable(other),
        })
}

#[handler]
#[tracing::instrument(skip_all, fields(op = "ak.self.realm_join.command.prepare.v1"))]
async fn prepare(depot: &mut Depot, req: &mut Request) -> JsonResult<SelfRealmJoinPrepareOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = AuthArgs.authenticated_session(state, req).await?;
    let account_id = crate::routing::identity::auth_grant_dpop::authenticated_session_account_id(
        state, &session,
    )
    .await?;
    if account_id.station_id != state.service_core_id() {
        return Err(AppError::not_found("Realm join preparation not found"));
    }
    let body = req
        .parse_json::<SelfRealmJoinPrepareRequestBody>()
        .await
        .map_err(invalid_request)?;
    body.validate().map_err(invalid_request)?;
    let located =
        authority::resolve_join_target_authority(state, &body.target, &body.request_id).await?;
    // The verified current authority is the join intake state this Station
    // keeps: the applicant's exact signed Event is then forwarded to that
    // Station and nowhere else (join-policy.md §6).
    if located.authority.current_service_id() != &state.service_core_id() {
        state
            .authority_commits()
            .record_remote_authority(&located.current_authority(), &state.service_core_id())
            .await
            .map_err(unavailable)?;
    }
    let bundle = located.bundle;
    let outcome = SelfRealmJoinPrepareOutcome {
        request_id: body.request_id,
        realm_stream_head: bundle.realm_stream_head.clone(),
        authority_bundle: bundle,
    };
    json_ok(outcome)
}

#[handler]
#[tracing::instrument(skip_all, fields(op = "ak.peer.realm_join.read.bootstrap.v1"))]
async fn peer_bootstrap(
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<PeerRealmJoinBootstrapOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    crate::routing::events::peer::validate_peer_request(state, req, true).await?;
    let source_id = crate::routing::events::peer::source_id_from_request(req)?;
    let body = req
        .parse_json::<PeerRealmJoinBootstrapRequestBody>()
        .await
        .map_err(invalid_request)?;
    if body.member_account_id.station_id.as_str() != source_id {
        return Err(AppError::not_found("Realm join bootstrap not found"));
    }
    let accepted = state
        .authority_commits()
        .committed_event_by_commit_id(&body.membership_commit_id)
        .await
        .map_err(unavailable)?
        .ok_or_else(|| AppError::not_found("Realm join bootstrap not found"))?;
    let event = &accepted.event;
    let expected_stream =
        CommitStreamRef::from_scope(&event.scope_ref, None).map_err(invalid_request)?;
    if event.realm_id != body.realm_id || accepted.commit.stream_ref != expected_stream {
        return Err(AppError::not_found("Realm join bootstrap not found"));
    }
    let member = ActorId::account(body.member_account_id.clone());
    // The membership Commit is the member's own join: its `ak.member.state{join}`
    // or, for a directed Invite, its `ak.invite.accept`.
    let joins_member = match event.kind {
        EventKind::MemberState => serde_json::to_value(&event.payload)
            .ok()
            .and_then(|payload| serde_json::from_value::<MembershipPayload>(payload).ok())
            .is_some_and(|payload| {
                payload.member_id == member && payload.membership == MembershipPayloadState::Join
            }),
        EventKind::CircleMemberState => {
            let arkret_wire::ScopeRef::Circle {
                realm_id,
                circle_id,
            } = &event.scope_ref
            else {
                return Err(AppError::not_found("Realm join bootstrap not found"));
            };
            realm_id == &body.realm_id
                && event.actor_id == member
                && event.payload.get("circle_id").and_then(Value::as_str)
                    == Some(circle_id.as_str())
                && event.payload.get("membership").and_then(Value::as_str) == Some("join")
                && event
                    .payload
                    .get("member_id")
                    .and_then(|value| serde_json::from_value::<ActorId>(value.clone()).ok())
                    .as_ref()
                    == Some(&member)
        }
        EventKind::InviteAccept => event.actor_id == member,
        _ => false,
    };
    if !joins_member {
        return Err(AppError::not_found("Realm join bootstrap not found"));
    }
    let bundle =
        local_authority_bundle(state, &body.realm_id, &nonce_for_request(&body.request_id)?)
            .await?;
    if let Some(stream) = &body.history_stream_ref {
        let snapshot = state
            .authority_commits()
            .issue_stream_history_snapshot_for_account(
                &body.realm_id,
                &body.member_account_id,
                &state.service_core_id(),
                stream,
                Some(&body.membership_commit_id),
                &state
                    .service_verification_method("notary-key")
                    .map_err(unavailable)?,
                state.notary_signing_key().as_ref(),
                crate::wire::now(),
            )
            .await
            .map_err(unavailable)?
            .ok_or_else(|| AppError::not_found("history basis unavailable"))?;
        return json_ok(PeerRealmJoinBootstrapOutcome {
            request_id: body.request_id,
            authority_bundle: bundle,
            visible_stream_heads: snapshot.visible_stream_heads.clone(),
            snapshot,
        });
    }
    // The member Station anchors its held stream on this snapshot: the
    // member's complete disclosure with the Realm stream floor at its own
    // join, which must still be its current membership (`federation.md`
    // §4.1.1, member Station bootstrap).
    let material = state
        .authority_commits()
        .member_station_bootstrap_material(
            &body.realm_id,
            &body.member_account_id,
            &body.membership_commit_id,
        )
        .await
        .map_err(unavailable)?
        .ok_or_else(|| AppError::not_found("Realm join bootstrap not found"))?;
    if material.visible_stream_heads.is_empty() {
        return Err(unavailable("Realm stream head is unavailable"));
    }
    let snapshot = coland_services::authority_commit::build_signed_realm_state_snapshot(
        &material,
        state
            .service_verification_method("notary-key")
            .map_err(unavailable)?,
        state.notary_signing_key().as_ref(),
        crate::wire::now(),
    )
    .map_err(unavailable)?;
    json_ok(PeerRealmJoinBootstrapOutcome {
        request_id: body.request_id,
        authority_bundle: bundle,
        snapshot,
        visible_stream_heads: material.visible_stream_heads,
    })
}
