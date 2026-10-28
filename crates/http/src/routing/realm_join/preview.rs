//! Pre-join Realm preview (`invite-addressing.md` section 7.1).
//!
//! The preview has one source, the same as join preparation: the Realm's
//! current governance Station. The caller's own Station verifies that Station
//! through the locator hints with a nonce it generates itself, then asks it
//! for the preview over service-to-service authentication, or answers on the
//! equivalent local path when it is that Station. Inviter Stations, Directory
//! entries and member Stations are never a preview source.

use std::time::Duration;

use arkret_models_collaboration::events_payloads::preview::PreviewPolicyPayloadValue;
use arkret_models_collaboration::events_payloads::realm::RealmProfile;
use arkret_models_collaboration::governance::realm_join_intake::{
    PUBLIC_PREVIEW_DISPLAY_NAME_MAX_CHARS, PeerRealmJoinPreviewRequestBody,
    PeerRealmJoinPreviewResponseBody, RealmPublicPreview, SelfRealmJoinPreviewRequestBody,
    SelfRealmJoinPreviewResponseBody,
};
use arkret_wire::{
    AccountId, ActorId, Base64UrlString, CurrentSelector, CurrentState, DidCoreId, HistoryAccess,
    InviteId, JoinRule, RealmId,
};
use base64::Engine as _;
use coland_http::error::AppError;
use coland_http::result::{JsonResult, json_ok};
use salvo::prelude::*;

use super::{AuthArgs, invalid_request};
use crate::state::AppState;

/// Every peer preview answer, disclosed or not, is held to at least this
/// duration so that unknown, hidden, non-governed and mismatched targets fall
/// into one timing bucket with the successful path.
const PEER_PREVIEW_TIMING_FLOOR: Duration = Duration::from_millis(150);

/// Registered `max_canonical_body_bytes` of the peer preview operation, also
/// the bound applied to its response.
const PEER_PREVIEW_MAX_BYTES: usize = 64 * 1024;

const PEER_PREVIEW_PATH: &str = "/_arkret/peer/realm-joins/preview";

/// The single non-enumerating failure for every target the governance
/// Station does not disclose.
fn preview_not_found() -> AppError {
    AppError::not_found("Realm preview not found")
}

/// The current governance Station could not be reached or answered outside
/// the closed outcome. The caller may retry; no other source is substituted.
fn governance_unavailable(error: impl std::fmt::Display) -> AppError {
    crate::app_error!(
        ServiceUnavailable,
        "Realm governance Station preview unavailable: {error}",
    )
}

pub(super) fn fresh_nonce() -> Result<Base64UrlString, AppError> {
    Base64UrlString::new(
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>()),
    )
    .map_err(|error| AppError::internal(error.to_string()))
}

#[handler]
#[tracing::instrument(skip_all, fields(op = "ak.self.realm_join.read.preview.v1"))]
pub(super) async fn self_preview(
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<SelfRealmJoinPreviewResponseBody> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = AuthArgs.authenticated_session(state, req).await?;
    let account_id = crate::routing::identity::auth_grant_dpop::authenticated_session_account_id(
        state, &session,
    )
    .await?;
    if account_id.station_id != state.service_core_id() {
        return Err(preview_not_found());
    }
    let body = req
        .parse_json::<SelfRealmJoinPreviewRequestBody>()
        .await
        .map_err(invalid_request)?;
    body.validate().map_err(invalid_request)?;
    let started = tokio::time::Instant::now();
    let answer = Box::pin(resolve_self_preview(state, account_id, body)).await;
    tokio::time::sleep_until(started + PEER_PREVIEW_TIMING_FLOOR).await;
    answer
}

/// Hold every target-dependent self answer to the same floor, including
/// locator refusals and the equivalent local governance path.
async fn resolve_self_preview(
    state: &AppState,
    account_id: AccountId,
    body: SelfRealmJoinPreviewRequestBody,
) -> JsonResult<SelfRealmJoinPreviewResponseBody> {
    // Undisclosed or invalid evidence remains non-enumerating. Transport
    // failure and divergent verified chains require a retry without changing source.
    let located = super::resolve_verified_authority(
        state,
        &body.target.realm_id,
        &body.target.authority_locator_hints,
        &fresh_nonce()?,
    )
    .await
    .map_err(|error| {
        if error.code == crate::error::ErrorCode::TemporarilyUnavailable {
            error
        } else {
            preview_not_found()
        }
    })?;
    let peer_request = PeerRealmJoinPreviewRequestBody {
        request_id: body.request_id.clone(),
        realm_id: body.target.realm_id.clone(),
        requester_account_id: account_id,
        invite_id: body.target.invite_id.clone(),

        realm_invite_link_id: body.target.realm_invite_link_id.clone(),
        link_proof: body.link_proof.clone(),
    };
    let governance = located.authority.current_service_id();
    let preview = if *governance == state.service_core_id() {
        governance_preview(state, &peer_request).await?
    } else {
        request_peer_preview(state, governance, &peer_request)
            .await?
            .preview
    };
    let outcome = SelfRealmJoinPreviewResponseBody {
        request_id: body.request_id.clone(),
        authority_bundle: located.bundle,
        preview,
    };
    // A preview answered under a different governance tenure than the bundle
    // this Station verified raced a handoff; the caller retries.
    outcome
        .validate_for_request(&body)
        .map_err(governance_unavailable)?;
    json_ok(outcome)
}

#[handler]
#[tracing::instrument(skip_all, fields(op = "ak.peer.realm_join.read.preview.v1"))]
pub(super) async fn peer_preview(
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<PeerRealmJoinPreviewResponseBody> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    crate::routing::events::peer::validate_peer_request(state, req, true).await?;
    let source_id = crate::routing::events::peer::source_id_from_request(req)?;
    let body = req
        .parse_json::<PeerRealmJoinPreviewRequestBody>()
        .await
        .map_err(invalid_request)?;
    body.validate().map_err(invalid_request)?;
    json_ok(answer_peer_preview(state, &source_id, body).await?)
}

/// Answer one authenticated peer preview. The requester Account must belong
/// to the calling Station; every answer, disclosed or not, is held to the
/// same timing floor.
async fn answer_peer_preview(
    state: &AppState,
    source_id: &str,
    body: PeerRealmJoinPreviewRequestBody,
) -> Result<PeerRealmJoinPreviewResponseBody, AppError> {
    let started = tokio::time::Instant::now();
    let answer = if body.requester_account_id.station_id.as_str() == source_id {
        governance_preview(state, &body).await
    } else {
        Err(preview_not_found())
    };
    tokio::time::sleep_until(started + PEER_PREVIEW_TIMING_FLOOR).await;
    Ok(PeerRealmJoinPreviewResponseBody {
        request_id: body.request_id,
        preview: answer?,
    })
}

/// The governance Station's own answer. Every non-disclosing branch returns
/// the same `not_found`; only a storage fault surfaces as an internal error.
pub(super) async fn governance_preview(
    state: &AppState,
    request: &PeerRealmJoinPreviewRequestBody,
) -> Result<RealmPublicPreview, AppError> {
    let authorities = state.authority_commits();
    let Some(authority) = authorities
        .current_authority(&request.realm_id)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
    else {
        return Err(preview_not_found());
    };
    if authority.service_id != state.service_core_id() {
        return Err(preview_not_found());
    }
    let link_holder = if request.realm_invite_link_id.is_some() {
        state
            .persistence()
            .check_realm_invite_link_preview(request, crate::wire::now())
            .await
            .map_err(|error| match error {
                coland_storage::PersistenceError::NotFound(_)
                | coland_storage::PersistenceError::Conflict(_) => preview_not_found(),
                other => AppError::internal(other.to_string()),
            })?;
        true
    } else {
        false
    };
    let invited = match &request.invite_id {
        Some(invite_id) => {
            if !invite_binds_requester(
                state,
                &request.realm_id,
                invite_id,
                &request.requester_account_id,
            )
            .await?
            {
                return Err(preview_not_found());
            }
            true
        }
        None => false,
    };
    let member = authorities
        .local_current_member_joined(
            &request.realm_id,
            &ActorId::account(request.requester_account_id.clone()),
            &authority.service_id,
        )
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    let Some(material) = authorities
        .realm_state_snapshot_material(&request.realm_id)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
    else {
        return Err(preview_not_found());
    };
    if material.governance_generation != authority.generation {
        return Err(governance_unavailable(
            "the governing tenure changed while the preview was read",
        ));
    }
    let Some(policy) = singleton_value(
        &material.current_state_entries,
        &CurrentSelector::RealmPreviewPolicy,
    )
    .and_then(|value| serde_json::from_value::<PreviewPolicyPayloadValue>(value.clone()).ok()) else {
        return Err(preview_not_found());
    };
    disclose(
        &policy,
        PreviewAudience {
            invited,
            member,
            link_holder,
        },
        &request.realm_id,
        material.governance_generation,
        &material.current_state_entries,
    )
    .ok_or_else(preview_not_found)
}

/// One read-only cut joins the directed Invite typed current results with its
/// accepted create Event. A holder-private delivery or a stale InviteId cannot
/// turn into a preview entitlement.
async fn invite_binds_requester(
    state: &AppState,
    realm_id: &RealmId,
    invite_id: &InviteId,
    requester: &AccountId,
) -> Result<bool, AppError> {
    let candidates = state
        .persistence()
        .open_directed_invites_for_invitee(requester, Some(realm_id))
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    let at = crate::wire::now();
    Ok(candidates.into_iter().any(|invite| {
        invite.invite_id == *invite_id
            && invite.state == arkret_wire::InviteState::Pending
            && invite.expires_at > at
    }))
}

#[derive(Clone, Copy, Debug)]
struct PreviewAudience {
    invited: bool,
    member: bool,
    link_holder: bool,
}

impl PreviewAudience {
    /// A peer requester is always an authenticated Account; the invited and
    /// member classes are added only from this Station's accepted state.
    /// Knock applicant, restricted claim and link-token audiences have no
    /// accepted source on this path and are never assumed.
    fn admitted_by(self, audiences: &[String]) -> bool {
        audiences.iter().any(|audience| match audience.as_str() {
            "anonymous" | "authenticated" => true,
            "invited" => self.invited,
            "link_token_holder" => self.link_holder,
            "realm_member" => self.member,
            _ => false,
        })
    }
}

fn singleton_value<'a>(
    entries: &'a [CurrentState],
    wanted: &CurrentSelector,
) -> Option<&'a serde_json::Value> {
    entries.iter().find_map(|entry| match entry {
        CurrentState::Value {
            selector, value, ..
        } if selector == wanted => Some(value),
        _ => None,
    })
}

/// Build the disclosed preview from one governing cut. The required members
/// always come from the committed `realm_join_rule` and `realm_history_access`
/// results; `display_name` is disclosed only when the policy lists `title` and
/// the committed profile carries a valid one. `None` means nothing may be
/// disclosed to this audience.
fn disclose(
    policy: &PreviewPolicyPayloadValue,
    audience: PreviewAudience,
    realm_id: &RealmId,
    governance_generation: u64,
    entries: &[CurrentState],
) -> Option<RealmPublicPreview> {
    if policy.mode == "none" || !audience.admitted_by(&policy.audiences) {
        return None;
    }
    let join_rule = singleton_value(entries, &CurrentSelector::RealmJoinRule)
        .and_then(|value| serde_json::from_value::<JoinRule>(value.clone()).ok())?;
    let history_access = singleton_value(entries, &CurrentSelector::RealmHistoryAccess)
        .and_then(|value| serde_json::from_value::<HistoryAccess>(value.clone()).ok())?;
    let display_name = policy
        .fields
        .iter()
        .any(|field| field == "title")
        .then(|| singleton_value(entries, &CurrentSelector::RealmProfile))
        .flatten()
        .and_then(|value| serde_json::from_value::<RealmProfile>(value.clone()).ok())
        .map(|profile| profile.title)
        .filter(|title| {
            !title.is_empty() && title.chars().count() <= PUBLIC_PREVIEW_DISPLAY_NAME_MAX_CHARS
        });
    let preview = RealmPublicPreview {
        realm_id: realm_id.clone(),
        join_rule,
        history_access,
        governance_generation,
        display_name,
    };
    preview.validate().ok()?;
    Some(preview)
}

/// Ask the verified current governance Station over service-to-service
/// authentication. The requester's own bearer or session credential is never
/// forwarded: the request names the complete requester Account, which the
/// governance Station binds to this Station's `Source-Service-ID`.
async fn request_peer_preview(
    state: &AppState,
    governance: &DidCoreId,
    request: &PeerRealmJoinPreviewRequestBody,
) -> Result<PeerRealmJoinPreviewResponseBody, AppError> {
    use crate::routing::federation::outbox::{
        content_digest_header_value, insert_header_if_valid, rfc9421_sign,
    };

    let peer_target = crate::routing::federation::resolved_peer_target(
        state,
        governance.as_str(),
        "station",
        false,
    )
    .await
    .map_err(governance_unavailable)?;
    let target = format!("{}{PEER_PREVIEW_PATH}", peer_target.base_url);
    let (url, client) = crate::security::validate_http_url_for_egress_with_pinned_client(
        &target,
        "Realm join preview",
        state.config().development_mode,
        crate::routing::federation::outbox::REQUEST_TIMEOUT,
    )
    .map_err(governance_unavailable)?;
    let body = arkret_canonical::canonical_json_bytes(request)
        .map_err(|error| AppError::internal(error.to_string()))?;
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        reqwest::header::CONTENT_TYPE,
        reqwest::header::HeaderValue::from_static("application/json"),
    );
    insert_header_if_valid(
        &mut headers,
        "content-digest",
        &content_digest_header_value(&body),
    );
    insert_header_if_valid(&mut headers, "source-service-id", state.service_id());
    insert_header_if_valid(&mut headers, "destination-service-id", governance.as_str());
    insert_header_if_valid(
        &mut headers,
        "source-trust-domain",
        state.config().trust_domain.as_str(),
    );
    insert_header_if_valid(
        &mut headers,
        "destination-trust-domain",
        &peer_target.trust_domain,
    );
    let headers = rfc9421_sign(state, headers, "POST", &target);
    let mut response = client
        .post(url)
        .headers(headers)
        .body(body)
        .send()
        .await
        .map_err(governance_unavailable)?;
    if response.status() == reqwest::StatusCode::NOT_FOUND {
        return Err(preview_not_found());
    }
    if !response.status().is_success() {
        return Err(governance_unavailable(format!(
            "HTTP {}",
            response.status()
        )));
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(governance_unavailable)? {
        if bytes.len() + chunk.len() > PEER_PREVIEW_MAX_BYTES {
            return Err(governance_unavailable(
                "response exceeds the operation limit",
            ));
        }
        bytes.extend_from_slice(&chunk);
    }
    let outcome = serde_json::from_slice::<PeerRealmJoinPreviewResponseBody>(&bytes)
        .map_err(governance_unavailable)?;
    outcome
        .validate_for_request(request)
        .map_err(governance_unavailable)?;
    Ok(outcome)
}

#[cfg(test)]
#[path = "preview_tests.rs"]
mod tests;
