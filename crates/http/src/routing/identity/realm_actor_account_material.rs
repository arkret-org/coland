//! Account-originated private audit reads, with a separate final delivery cut.
use arkret_models_integration::{
    PeerRealmActorMaterialRequestBody, RealmActorMaterialRequestBody,
    RealmActorMaterialResponseBody,
};
use arkret_wire::{ActorId, ServiceOperationId};
use coland_http::error::AppError;
use salvo::prelude::*;

use crate::state::AppState;

const MAX_BYTES: usize = 4_194_304;

fn hidden() -> AppError {
    AppError::not_found("Realm actor material not found")
}
fn unavailable() -> AppError {
    crate::app_error!(
        TemporarilyUnavailable,
        "Realm actor material is unavailable"
    )
}

async fn body<T: serde::de::DeserializeOwned>(
    req: &mut Request,
    operation: ServiceOperationId,
) -> Result<T, AppError> {
    if req.headers().get_all("arkret-operation").iter().count() != 1
        || req
            .headers()
            .get("arkret-operation")
            .and_then(|v| v.to_str().ok())
            != Some(operation.as_str())
    {
        return Err(hidden());
    }
    let bytes = req.payload().await.map_err(|_| hidden())?;
    if bytes.len() > MAX_BYTES {
        return Err(AppError::schema_violation("material exceeds 4 MiB"));
    }
    arkret_canonical::canonical::validate_canonical_bytes(bytes)
        .map_err(|_| AppError::json_invalid("material request is not canonical"))?;
    serde_json::from_slice(bytes)
        .map_err(|_| AppError::schema_violation("invalid private material request"))
}

#[handler]
pub(crate) async fn peer_read(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let result = peer_material(state, req).await;
    match result {
        Ok(outcome) => {
            super::super::authority_commit::no_store(res);
            res.render(Json(outcome));
        }
        Err(error) => error.write(req, depot, res).await,
    }
}

async fn peer_material(
    state: &AppState,
    req: &mut Request,
) -> Result<RealmActorMaterialResponseBody, AppError> {
    crate::routing::events::peer::validate_peer_request(state, req, true).await?;
    let request: PeerRealmActorMaterialRequestBody =
        body(req, ServiceOperationId::PeerRealmActorReadMaterialV1).await?;
    let source = crate::routing::events::peer::source_id_from_request(req)?;
    let source = source.parse().map_err(|_| hidden())?;
    request.validate_source(&source).map_err(|_| hidden())?;
    let caller = coland_storage::RealmActorMaterialCaller::Account {
        account_id: request.requester_account_id,
        expires_at: chrono::Utc::now() + chrono::Duration::seconds(60),
    };
    super::realm_actor_material::supply(state, &request.request, &caller).await
}

pub(super) async fn read_account(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let Some((session, account)) = crate::routing::self_current_reads::authenticated_reader(
        state,
        req,
        res,
        ServiceOperationId::SELF_REALM_ACTOR_READ_MATERIAL_V1,
    )
    .await
    else {
        return;
    };
    let result = Box::pin(async {
        if account.station_id != state.service_core_id() {
            return Err(hidden());
        }
        let request: RealmActorMaterialRequestBody =
            body(req, ServiceOperationId::SelfRealmActorReadMaterialV1).await?;
        request.validate().map_err(|_| hidden())?;
        let realm = &request
            .actor_id()
            .as_realm_actor_id()
            .ok_or_else(hidden)?
            .realm_id;
        let observed = state
            .authority_commits()
            .current_authority(realm)
            .await
            .map_err(|_| unavailable())?
            .ok_or_else(hidden)?;
        let actor = ActorId::account(account.clone());
        let (outcome, authority) = if observed.service_id == state.service_core_id() {
            let caller = coland_storage::RealmActorMaterialCaller::Account {
                account_id: account.clone(),
                expires_at: session.expires_at,
            };
            (
                super::realm_actor_material::supply(state, &request, &caller).await?,
                observed,
            )
        } else {
            use arkret_models_collaboration::governance::realm_join_intake::{
                AuthorityLocatorSource, RealmJoinCandidate, RealmJoinCandidateServiceKind,
            };
            let hint = RealmJoinCandidate {
                service_kind: RealmJoinCandidateServiceKind::Station,
                service_id: observed.service_id.clone(),
                endpoint_url: None,
                source: AuthorityLocatorSource::Cache,
            };
            let nonce = arkret_wire::Base64UrlString::new(request.request_nonce().to_owned())
                .map_err(|_| hidden())?;
            let located = crate::routing::realm_join::resolve_verified_authority(
                state,
                realm,
                &[hint],
                &nonce,
            )
            .await
            .map_err(|error| {
                tracing::warn!(%error, "Realm audit governance resolution failed");
                unavailable()
            })?;
            let authority = located.current_authority();
            if authority.generation < observed.generation
                || (authority.generation == observed.generation && authority != observed)
            {
                return Err(unavailable());
            }
            state
                .authority_commits()
                .record_remote_authority(&authority, &state.service_core_id())
                .await
                .map_err(|_| unavailable())?;
            let peer = PeerRealmActorMaterialRequestBody {
                requester_account_id: account.clone(),
                request: request.clone(),
            };
            let bytes = arkret_canonical::canonical_json_bytes(&peer).map_err(|_| unavailable())?;
            if bytes.len() > MAX_BYTES {
                return Err(AppError::schema_violation("material exceeds 4 MiB"));
            }
            let response = crate::routing::federation::outbox::signed_peer_request(
                state,
                authority.service_id.as_str(),
                "/_arkret/peer/realm-actors/material",
                &bytes,
                MAX_BYTES,
            )
            .await
            .map_err(|error| {
                tracing::warn!(%error, "Realm audit peer material transport failed");
                unavailable()
            })?;
            if response.status == 404 {
                return Err(hidden());
            }
            if response.status != 200 {
                return Err(unavailable());
            }
            let outcome: RealmActorMaterialResponseBody =
                serde_json::from_slice(&response.body).map_err(|_| unavailable())?;
            let resolution = super::agents::evidence::fetch_service_resolution(
                state,
                &authority.service_id,
                None,
            )
            .await
            .map_err(|error| {
                tracing::warn!(?error, "Realm audit issuer resolution failed");
                unavailable()
            })?;
            let verified = arkret_identity::realm_actor_material::verify_realm_actor_material(
                outcome,
                &request,
                &actor,
                &located.authority,
                &resolution,
                &located.keys,
                chrono::Utc::now(),
            )
            .map_err(|error| {
                tracing::warn!(%error, "Realm audit signed material validation failed");
                unavailable()
            })?;
            (verified.into_material(), authority)
        };
        outcome
            .validate_for_request(&request, &actor, chrono::Utc::now())
            .map_err(|_| unavailable())?;
        let token = coland_http::util::dpop_token(req);
        if crate::routing::identity::auth::revalidate_current_read_session(state, &session, token)
            .await
            .is_err()
        {
            return Err(hidden());
        }
        let device = if let Some(device) = session.human_device_id() {
            Some(
                super::device_generation::active_device_revocation_gate_selector(
                    state,
                    &session.actor,
                    device,
                )
                .await
                .map_err(|_| hidden())?,
            )
        } else {
            None
        };
        let input = coland_storage::AccountContentDeliveryInput {
            realm_actor_material: Some(Box::new((request, outcome.clone(), authority))),
            watch_delivery_device: device,
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
            crate::routing::events::sync::content_delivery_guard(state, &session, &input).await?;
        coland_http::result::guarded_json_ok(outcome, guard).map_err(|_| unavailable())
    })
    .await;
    match result {
        Ok(response) => {
            crate::routing::authority_commit::no_store(res);
            salvo::Scribe::render(response, res);
        }
        Err(error) => error.write(req, depot, res).await,
    }
}
