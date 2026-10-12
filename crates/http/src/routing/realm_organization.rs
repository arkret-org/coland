//! SOL-ORG-06 — Realm organization-relationship read surface.
//!
//! `GET /_arkret/self/realms/{realm_id}/organizations`
//! (`ak.self.realm_organization.read.list.v1`) projects the accepted
//! `ak.realm.organization` relationship statements (active / revoked / expired,
//! latest-per-`(organization_id, relationship)`) plus the declared
//! `owning_organization_ids` hints (SOL-ORG-05) that carry no verified statement.
//!
//! A relationship is only verified when `lifecycle_phase=verified_active`;
//! `declared_organization_hint_ids` are unverified claims. This is the protocol
//! read path referenced by `realm-and-space.md` §2.3.0 — coland never invents a
//! private endpoint for it.
//!
//! Spec: `arkret-spec/spec/v1/zh/models/realm-and-space.md` §2.3.0; response
//! schema `realm-organization-operations.schema.json`.

use arkret_identifiers::RealmId;
use arkret_models_collaboration::governance::realm_governance::RealmOrganizationRelationshipList;
use coland_http::error::AppError;
use coland_http::result::{JsonResult, json_ok};
use salvo::oapi::endpoint;
use salvo::oapi::extract::PathParam;
use salvo::prelude::*;
use serde::de::DeserializeOwned;
use serde_json::json;

use super::AuthArgs;
use crate::state::AppState;

pub(crate) fn router() -> Router {
    Router::with_path("realms")
        .push(Router::with_path("{realm_id}/organizations").get(list_realm_organizations))
}

/// Deserialize a validated projection string into a wire newtype / enum. The
/// projection only stores values the reducer already accepted, so a parse
/// failure is an internal invariant violation.
fn de_str<T: DeserializeOwned>(field: &str, value: &str) -> Result<T, AppError> {
    serde_json::from_value(json!(value))
        .map_err(|e| AppError::internal(format!("invalid projected {field} '{value}': {e}")))
}

#[endpoint(
    operation_id = "ak.self.realm_organization.read.list",
    summary = "List a realm's organization relationships",
    tags("realm_organizations")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.realm_organization.read.list.v1"))]
pub(crate) async fn list_realm_organizations(
    aa: AuthArgs,
    realm_id: PathParam<String>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<RealmOrganizationRelationshipList> {
    let session = {
        let state = depot.get_typed::<AppState>().expect("state injected");
        aa.authenticated_session(state, req).await?
    };
    list_realm_organizations_impl(session, realm_id, depot).await
}

#[endpoint(
    operation_id = "org.arkret.coland.admin.realm_organization.query.list",
    summary = "List a realm's organization relationships for administration",
    tags("admin", "realm_organizations")
)]
#[tracing::instrument(
    skip_all,
    fields(op = "org.arkret.coland.admin.realm_organization.query.list")
)]
pub(crate) async fn admin_list_realm_organizations(
    admin: super::admin::AdminAuth,
    realm_id: PathParam<String>,
    depot: &mut Depot,
) -> JsonResult<RealmOrganizationRelationshipList> {
    let session = admin.session()?;
    list_realm_organizations_impl(session, realm_id, depot).await
}

/// `session` is the caller already authenticated by the wrapping endpoint
/// (the self bearer path or the `RequireAdmin` gate).
async fn list_realm_organizations_impl(
    session: coland_services::identity::SessionIdentityState,
    realm_id: PathParam<String>,
    depot: &mut Depot,
) -> JsonResult<RealmOrganizationRelationshipList> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let realm_id = de_str::<RealmId>("realm_id", &realm_id.into_inner())?;
    let actor =
        crate::routing::identity::session_actor::session_actor_from_credential(state, &session)?;
    let outcome = state
        .persistence()
        .accepted_realm_organization_read(&realm_id, &actor, chrono::Utc::now())
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
        .ok_or_else(|| AppError::not_found("realm not found"))?;
    json_ok(outcome)
}
