//! Realm governance HTTP surface.
//!
//! Surfaces:
//! - `GET /_arkret/self/realms/{realm_id}/links?direction=outbound|inbound|both&
//!   allowed_link_kinds=... ` — list the typed cross-Realm links projected from `ak.realm.link`
//!   events. Powered by the exact durable accepted current rows and their original Events/Commits.
use arkret_identifiers::RealmId;
use arkret_models_collaboration::governance::realm_governance::{
    RealmLinkList, RealmLinkListQuery,
};
use coland_http::error::AppError;
use coland_http::result::{GuardedJsonResult, guarded_json_ok};
use salvo::oapi::endpoint;
use salvo::oapi::extract::{PathParam, QueryParam};
use salvo::prelude::*;

use super::AuthArgs;
use crate::state::AppState;

/// Protocol-surface realm governance routes, mounted under
/// `/_arkret/self/realms/...`. Only spec-registered `ak.self.realm_link.*`
/// operations live here — every URL has an `operation-registry.json` entry.
pub(crate) fn router() -> Router {
    Router::with_path("realms").push(Router::with_path("{realm_id}/links").get(list_realm_links))
}

#[endpoint(
    operation_id = "ak.self.realm_link.read.list",
    summary = "List typed cross-Realm links",
    tags("realm_links")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.realm_link.read.list.v1"))]
pub(crate) async fn list_realm_links(
    aa: AuthArgs,
    realm_id: PathParam<String>,
    direction: QueryParam<String, false>,
    allowed_link_kinds: QueryParam<String, false>,
    depot: &mut Depot,
    req: &mut Request,
) -> GuardedJsonResult<RealmLinkList> {
    let session = {
        let state = depot.get_typed::<AppState>().expect("state injected");
        aa.authenticated_session(state, req).await?
    };
    // Extractors describe the HTTP parameters; validation retains all raw pairs.
    let _ = (direction, allowed_link_kinds);
    let query = realm_link_query(req)?;
    list_realm_links_impl(session, realm_id, query, depot).await
}

#[endpoint(
    operation_id = "org.arkret.coland.admin.realm_link.query.list",
    summary = "List typed cross-Realm links for administration",
    tags("admin", "realm_links")
)]
#[tracing::instrument(skip_all, fields(op = "org.arkret.coland.admin.realm_link.query.list"))]
pub(crate) async fn admin_list_realm_links(
    admin: super::admin::AdminAuth,
    realm_id: PathParam<String>,
    direction: QueryParam<String, false>,
    allowed_link_kinds: QueryParam<String, false>,
    depot: &mut Depot,
    req: &mut Request,
) -> GuardedJsonResult<RealmLinkList> {
    let session = admin.session()?;
    let _ = (direction, allowed_link_kinds);
    let query = realm_link_query(req)?;
    list_realm_links_impl(session, realm_id, query, depot).await
}

fn realm_link_query(req: &Request) -> Result<RealmLinkListQuery, AppError> {
    RealmLinkListQuery::from_query_pairs(url::form_urlencoded::parse(
        req.uri().query().unwrap_or_default().as_bytes(),
    ))
    .map_err(|error| crate::app_error!(QueryInvalid, error.to_string()))
}

/// Administrative role does not grant access to private Realm contents.
async fn list_realm_links_impl(
    session: coland_services::identity::SessionIdentityState,
    realm_id: PathParam<String>,
    query: RealmLinkListQuery,
    depot: &mut Depot,
) -> GuardedJsonResult<RealmLinkList> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let actor =
        crate::routing::identity::session_actor::validated_session_actor(state, &session).await?;
    let realm_id = RealmId::new(realm_id.into_inner())
        .map_err(|e| AppError::param_invalid(format!("realm_id: {e}")))?;
    let allow: Option<Vec<String>> = query
        .allowed_link_kinds
        .as_ref()
        .map(|kinds| kinds.iter().map(|kind| kind.as_str().to_owned()).collect());

    let list = state
        .persistence()
        .accepted_realm_links(
            &realm_id,
            &actor,
            &state.service_core_id(),
            query.direction,
            allow.as_deref(),
        )
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
        .ok_or_else(|| AppError::not_found("not found"))?;
    let input = coland_storage::AccountContentDeliveryInput {
        realms: std::iter::once(realm_id)
            .chain(list.links.iter().map(|link| link.realm_id.clone()))
            .collect(),
        realm_link_reads: vec![(list.clone(), allow)],
        ..Default::default()
    };
    let guard =
        crate::routing::events::sync::content_delivery_guard(state, &session, &input).await?;
    guarded_json_ok(list, guard)
}

#[cfg(test)]
mod tests {
    use arkret_models_collaboration::governance::realm_governance::{
        RealmLinkDirection, RealmLinkKind,
    };
    use coland_http::result::{JsonResult, json_ok};
    use salvo::test::{ResponseExt, TestClient};

    use super::*;

    #[handler]
    async fn query_boundary(req: &mut Request) -> JsonResult<RealmLinkListQuery> {
        json_ok(realm_link_query(req)?)
    }

    #[tokio::test]
    async fn realm_link_query_keeps_the_typed_filter_and_rejects_dropped_pairs() {
        let service = salvo::Service::new(Router::with_path("links").get(query_boundary));
        let mut response = TestClient::get(
            "http://server/links?direction=outbound&allowed_link_kinds=governed_by%2Cmirror_of",
        )
        .send(&service)
        .await;
        assert_eq!(response.status_code, Some(StatusCode::OK));
        let query: RealmLinkListQuery = response.take_json().await.unwrap();
        assert_eq!(query.direction, RealmLinkDirection::Outbound);
        assert_eq!(
            query.allowed_link_kinds,
            Some(vec![RealmLinkKind::GovernedBy, RealmLinkKind::MirrorOf])
        );

        for query in [
            "link_kind_allow=governed_by",
            "allowed_link_kinds=governed_by&link_kind_allow=mirror_of",
            "allowed_link_kinds=governed_by&allowed_link_kinds=mirror_of",
            "direction=outbound&direction=inbound",
            "allowed_link_kinds=",
            "allowed_link_kinds=governed_by,",
            "allowed_link_kinds=unknown",
            "direction=unknown",
            "unregistered_filter=governed_by",
        ] {
            let mut response = TestClient::get(format!("http://server/links?{query}"))
                .send(&service)
                .await;
            assert_eq!(
                response.status_code,
                Some(StatusCode::BAD_REQUEST),
                "{query}"
            );
            let problem: arkret_wire::Problem = response.take_json().await.unwrap();
            assert_eq!(problem.status, 400, "{query}: {problem:?}");
            assert_eq!(
                problem.problem_type,
                arkret_wire::ErrorCode::QueryInvalid.type_uri(),
                "{query}: {problem:?}"
            );
        }
    }
}
