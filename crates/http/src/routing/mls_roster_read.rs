//! Member-authorized signed MLS roster reads through Account and governance Stations.

use arkret_models_collaboration::mls_roster_authority::{
    MlsMemberRosterAuthorityReadRequestBody, MlsRosterAuthorityReadOutcome,
    MlsRosterAuthorityReadRequestBody,
};
use arkret_wire::DidCoreId;
use coland_services::authority_commit::{
    MlsRosterAuthorityApplicationRead as Read, MlsRosterAuthorityPreflight as Preflight,
};

use super::*;

const MAX_PEER_PAGE_BYTES: usize = 2 * 1024 * 1024;

fn not_found() -> AppError {
    AppError::not_found("MLS roster authority not found")
}

fn unavailable() -> AppError {
    crate::app_error!(
        RevisionUnavailable,
        "authorized MLS roster history is unavailable",
    )
}

fn cursor_invalid() -> AppError {
    crate::app_error!(CursorInvalid, "invalid MLS roster cursor")
}

fn validate_request(request: &MlsRosterAuthorityReadRequestBody) -> Result<(), AppError> {
    request.validate().map_err(|_| {
        if request.cursor.is_some() {
            cursor_invalid()
        } else {
            crate::app_error!(SchemaViolation, "invalid MLS roster selector")
        }
    })
}

fn internal_read_error(_: coland_services::ServiceError) -> AppError {
    AppError::internal("MLS roster authority read unavailable")
}

fn read_page(outcome: Read) -> Result<MlsRosterAuthorityReadOutcome, AppError> {
    match outcome {
        Read::NotFound => Err(not_found()),
        Read::CursorInvalid => Err(cursor_invalid()),
        Read::RevisionUnavailable | Read::ForwardRequired => Err(unavailable()),
        Read::Page(page) => Ok(page),
    }
}

async fn governance_page(
    state: &AppState,
    request: &MlsRosterAuthorityReadRequestBody,
    source_peer: Option<&DidCoreId>,
) -> Result<MlsRosterAuthorityReadOutcome, AppError> {
    let issuer = state.service_core_id();
    let head = match state
        .authority_commits()
        .mls_roster_authority_attestors(request, &issuer, source_peer)
        .await
        .map_err(internal_read_error)?
    {
        Preflight::NotFound => return Err(not_found()),
        Preflight::RevisionUnavailable | Preflight::ForwardRequired => return Err(unavailable()),
        Preflight::Authorized {
            authority_head_commit_event_ref,
        } => authority_head_commit_event_ref,
    };
    let verification_method = state
        .service_verification_method("notary-key")
        .map_err(|_| unavailable())?;
    let key = state.notary_signing_key();
    let outcome = state
        .authority_commits()
        .mls_roster_authority_read(
            request,
            &issuer,
            source_peer,
            &head,
            &verification_method,
            key.as_ref(),
            chrono::Utc::now(),
        )
        .await
        .map_err(internal_read_error)?;
    read_page(outcome)
}

fn json_page(page: MlsRosterAuthorityReadOutcome) -> JsonResult<serde_json::Value> {
    let value = serde_json::to_value(page)
        .map_err(|_| AppError::internal("MLS roster page serialization unavailable"))?;
    json_ok(value)
}

fn self_json_page(
    page: MlsRosterAuthorityReadOutcome,
    request: &MlsRosterAuthorityReadRequestBody,
    authority: &DidCoreId,
    resolution: &arkret_models_identity::AuthenticatedServiceResolution,
) -> JsonResult<serde_json::Value> {
    for record in &page.records {
        if let arkret_models_collaboration::mls_roster_authority::MlsRosterRecord::Add {
            proposal_wire_b64u,
            attestation,
            ..
        } = record
        {
            let proposal = arkret_mls::verify_add_proposal_leaf(
                &arkret_canonical::base64url_decode(proposal_wire_b64u.as_str())
                    .map_err(|_| unavailable())?,
            )
            .map_err(|_| unavailable())?;
            if proposal.actor_id != attestation.actor_id
                || proposal.leaf_signature_key != attestation.leaf_signature_key_b64u
            {
                return Err(unavailable());
            }
        }
    }
    let head = page.manifest.authority_head_commit_event_ref.clone();
    let projected =
        arkret::project_mls_self_roster_authority_page(page, request, authority, &head, resolution)
            .map_err(|_| unavailable())?;
    json_ok(serde_json::to_value(projected).map_err(|_| unavailable())?)
}

async fn recheck_self_cut(
    state: &AppState,
    member: &MlsMemberRosterAuthorityReadRequestBody,
    selected: &MlsRosterAuthorityReadRequestBody,
    authority: &coland_storage::CurrentRealmAuthority,
) -> Result<(), AppError> {
    let cut = state
        .authority_commits()
        .mls_member_roster_selector(member, &state.service_core_id())
        .await
        .map_err(internal_read_error)?;
    match cut {
        coland_storage::MlsMemberRosterSelectorRead::NotFound => return Err(not_found()),
        coland_storage::MlsMemberRosterSelectorRead::Authorized {
            request,
            governance_station_id,
        } if request.as_ref() == selected && governance_station_id == authority.service_id => {}
        _ => return Err(unavailable()),
    }
    if state
        .authority_commits()
        .current_authority(&member.realm_id)
        .await
        .map_err(internal_read_error)?
        .as_ref()
        != Some(authority)
    {
        return Err(unavailable());
    }
    Ok(())
}

#[salvo::oapi::endpoint(
    operation_id = "ak.self.mls.read.roster_authority",
    request_body = serde_json::Value,
    tags("mls.rs")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.mls.read.roster_authority.v1"))]
pub(super) async fn resolve_self_mls_roster_authority(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<serde_json::Value> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let caller =
        crate::routing::identity::session_actor::validated_session_actor(state, &session).await?;
    let member_request = req
        .parse_json::<MlsMemberRosterAuthorityReadRequestBody>()
        .await
        .map_err(|_| crate::app_error!(SchemaViolation, "invalid MLS roster request"))?;
    member_request
        .validate()
        .map_err(|_| crate::app_error!(SchemaViolation, "invalid MLS member roster selector",))?;
    if member_request.caller_actor_id != caller
        || caller.route_service_id() != &state.service_core_id()
    {
        return Err(not_found());
    }
    let local = state.service_core_id();
    let (request, selected_governance) = match state
        .authority_commits()
        .mls_member_roster_selector(&member_request, &local)
        .await
        .map_err(internal_read_error)?
    {
        coland_storage::MlsMemberRosterSelectorRead::NotFound => return Err(not_found()),
        coland_storage::MlsMemberRosterSelectorRead::RevisionUnavailable => {
            return Err(unavailable());
        }
        coland_storage::MlsMemberRosterSelectorRead::Authorized {
            request,
            governance_station_id,
        } => (request, governance_station_id),
    };
    let authorized = state
        .authority_commits()
        .mls_roster_authority_attestors(&request, &local, None)
        .await
        .map_err(internal_read_error)?;
    match authorized {
        Preflight::NotFound => return Err(not_found()),
        Preflight::RevisionUnavailable => return Err(unavailable()),
        Preflight::Authorized { .. } | Preflight::ForwardRequired => {}
    }
    let authority = state
        .authority_commits()
        .current_authority(&request.realm_id)
        .await
        .map_err(internal_read_error)?
        .ok_or_else(not_found)?;
    if authority.service_id != selected_governance {
        return Err(unavailable());
    }
    if authority.service_id == local {
        let page = governance_page(state, &request, None).await?;
        let resolution =
            crate::routing::system::service_resolution::current_authenticated_service_resolution(
                state,
            )
            .await
            .map_err(|_| unavailable())?;
        recheck_self_cut(state, &member_request, &request, &authority).await?;
        return self_json_page(page, &request, &authority.service_id, &resolution);
    }
    if !matches!(authorized, Preflight::ForwardRequired) {
        return Err(unavailable());
    }
    crate::routing::realm_join::resolve_verified_authority_of_service(
        state,
        &request.realm_id,
        &authority.service_id,
    )
    .await
    .map_err(|_| unavailable())?;
    let body = arkret_canonical::canonical_json_bytes(&request).map_err(|_| unavailable())?;
    let response = crate::routing::federation::outbox::signed_peer_request(
        state,
        authority.service_id.as_str(),
        arkret_wire::PATH_PEER_MLS_ROSTER_AUTHORITY,
        &body,
        MAX_PEER_PAGE_BYTES,
    )
    .await
    .map_err(|_| unavailable())?;
    match response.status {
        404 => return Err(not_found()),
        400 => return Err(cursor_invalid()),
        503 => return Err(unavailable()),
        200 => {}
        _ => return Err(unavailable()),
    }
    let page: MlsRosterAuthorityReadOutcome =
        serde_json::from_slice(&response.body).map_err(|_| unavailable())?;
    let resolution = crate::routing::identity::agents::evidence::fetch_service_resolution(
        state,
        &authority.service_id,
        None,
    )
    .await
    .map_err(|_| unavailable())?;
    arkret::verify_mls_roster_authority_manifest_signature(
        &page.manifest,
        &request,
        &authority.service_id,
        &page.manifest.authority_head_commit_event_ref,
        &resolution,
    )
    .map_err(|_| unavailable())?;
    if page.records.is_empty()
        || page.records.len() > 8
        || page.page_index >= page.manifest.page_count
        || page.next_cursor.is_some() != (page.page_index + 1 < page.manifest.page_count)
    {
        return Err(unavailable());
    }
    recheck_self_cut(state, &member_request, &request, &authority).await?;
    self_json_page(page, &request, &authority.service_id, &resolution)
}

#[salvo::oapi::endpoint(
    operation_id = "ak.peer.mls.read.roster_authority",
    request_body = serde_json::Value,
    tags("governance")
)]
#[tracing::instrument(skip_all, fields(op = "ak.peer.mls.read.roster_authority.v1"))]
pub(super) async fn resolve_peer_mls_roster_authority(
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<serde_json::Value> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let peer = crate::routing::events::peer::authenticated_peer_context(state, req, true).await?;
    let request = req
        .parse_json::<MlsRosterAuthorityReadRequestBody>()
        .await
        .map_err(|_| crate::app_error!(SchemaViolation, "invalid MLS roster request"))?;
    validate_request(&request)?;
    if request.caller_actor_id.route_service_id() != &peer.source_service_id {
        return Err(not_found());
    }
    json_page(governance_page(state, &request, Some(&peer.source_service_id)).await?)
}
