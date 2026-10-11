//! Organization discovery and historical organization-side consent.
//!
//! Display declarations never authorize or deny membership or federation.
//! Sensitive actions read accepted organization relationships at the PostgreSQL
//! admission cut; cross-Realm moderation policy authority remains fail-closed.

use std::collections::BTreeSet;

use arkret_wire::DidCoreId;
use chrono::Utc;
use coland_http::error::AppError;
use coland_services::governance::OrganizationRecord;
use salvo::oapi::endpoint;
use salvo::oapi::extract::JsonBody;
use salvo::prelude::*;
use serde::{Deserialize, Serialize};

use crate::routing::system::extract::AuthArgs;
use crate::state::AppState;
use crate::{JsonResult, json_ok};

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
struct UpsertOrganizationRequestBody {
    organization_id: DidCoreId,
    #[serde(default)]
    handle: Option<String>,
    #[serde(default)]
    display_name: Option<String>,
    #[serde(default)]
    verified: Option<bool>,
    #[serde(default)]
    members: Vec<String>,
    #[serde(default)]
    member_count: Option<usize>,
}

#[derive(Clone, Debug, Serialize, salvo::oapi::ToSchema)]
pub(crate) struct OrganizationView {
    organization_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    handle: Option<String>,
    display_name: String,
    #[serde(default)]
    source_refs: Vec<String>,
    policy_revision: String,
    verified: bool,
    verified_badge: bool,
    #[serde(default)]
    members: Vec<String>,
    member_count: usize,
    #[serde(default)]
    realms: Vec<String>,
    realm_count: usize,
    created_by: DidCoreId,
    created_at: String,
    updated_at: String,
}

#[derive(Clone, Debug, Serialize, salvo::oapi::ToSchema)]
struct OrganizationListOutcome {
    organizations: Vec<OrganizationView>,
    total: usize,
}

pub(crate) fn router() -> Router {
    Router::with_path("organizations")
        .get(list_organizations)
        .post(upsert_organization)
}

fn ensure_organization_registry_admin(state: &AppState, actor: &str) -> Result<(), AppError> {
    if state.is_admin_principal(actor) {
        return Ok(());
    }
    Err(AppError::capability_denied(
        "organization registry write requires a server administrator",
    ))
}

pub(crate) async fn refresh_organization_projection(
    state: &AppState,
) -> coland_services::ServiceResult<()> {
    let organizations = state.governance().organizations().await?;
    let links = state.governance().realm_organization_links().await?;
    state
        .governance()
        .replace_organization_projection(organizations, links);

    Ok(())
}

#[endpoint(
    operation_id = "org.arkret.coland.organization.query.list",
    summary = "List organizations",
    tags("organizations")
)]
#[tracing::instrument(skip_all, fields(op = "org.arkret.coland.organization.query.list"))]
async fn list_organizations(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<OrganizationListOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let _session = aa.authenticated_session(state, req).await?;
    refresh_organization_projection(state)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    let mut rows = state
        .governance()
        .cached_organizations()
        .iter()
        .map(|record| organization_record_view(state, record))
        .collect::<Vec<_>>();
    rows.sort_by(|left, right| left.display_name.cmp(&right.display_name));
    let total = rows.len();
    json_ok(OrganizationListOutcome {
        organizations: rows,
        total,
    })
}

#[endpoint(
    operation_id = "org.arkret.coland.organization.command.upsert",
    summary = "Create or update an organization",
    tags("organizations")
)]
#[tracing::instrument(skip_all, fields(op = "org.arkret.coland.organization.command.upsert"))]
async fn upsert_organization(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<UpsertOrganizationRequestBody>,
) -> JsonResult<OrganizationView> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    // Registering an organization (a verified, listable org-principal record) is
    // a deployment-governance act, gated to the server's configured admin
    // principals — not every authenticated user may mint organizations.
    ensure_organization_registry_admin(state, &session.actor)?;
    let body = body.into_inner();
    let now = Utc::now();
    let organization_id = normalized_organization_id(body.organization_id.as_str())?;
    let display_name = body
        .display_name
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| display_name_from_organization_id(&organization_id));
    let members = body
        .members
        .into_iter()
        .filter(|value| !value.trim().is_empty())
        .collect::<BTreeSet<_>>();
    let member_count = body.member_count.unwrap_or(members.len());
    let record = OrganizationRecord {
        organization_id: organization_id.clone(),
        handle: body.handle,
        display_name,
        // No source Event stands behind a locally registered organization.
        source_refs: Vec::new(),
        policy_revision: "local".to_owned(),
        verified: body.verified.unwrap_or(true),
        members,
        member_count,
        created_by: DidCoreId::new(session.actor.clone()).map_err(|error| {
            AppError::param_invalid(format!("authenticated principal_id: {error}"))
        })?,
        created_at: now,
        updated_at: now,
    };
    state
        .governance()
        .store_organization(&record)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    json_ok(organization_record_view(state, &record))
}

/// SOL-ORG-05 — declared `owning_organization_ids` hints for a Realm. Display /
/// discovery surface ONLY; never use this to drive policy inheritance.
pub(crate) fn realm_organization_ids(state: &AppState, realm_id: &str) -> Vec<DidCoreId> {
    state.governance().cached_realm_organizations(realm_id)
}

/// Resolve organization consent at its signed historical DID state before the
/// authority transaction. PostgreSQL binds and verifies this internal evidence
/// again against the exact accepted Event; it is never a caller-side sidecar.
pub(crate) async fn prepare_realm_organization_proof(
    state: &AppState,
    event: &arkret_wire::Event,
) -> Result<Option<coland_storage::RealmOrganizationProofCommit>, &'static str> {
    if event.kind != arkret_wire::EventKind::RealmOrganization {
        return Ok(None);
    }
    let payload: arkret_models_collaboration::RealmOrganizationPayload = serde_json::from_value(
        serde_json::to_value(&event.payload)
            .map_err(|_| arkret_wire::ErrorCode::SCHEMA_VIOLATION)?,
    )
    .map_err(|_| arkret_wire::ErrorCode::SCHEMA_VIOLATION)?;
    arkret_policy::verify_realm_organization_statement(
        &payload,
        &event.realm_id,
        event.created_at,
        &arkret_policy::NoDelegationResolver,
    )
    .map_err(|_| "organization_statement_unverified")?;
    if payload.authorization.issuer_role
        != arkret_models_collaboration::RealmOrganizationIssuerRole::Organization
        || payload.authorization.issuer_id != payload.organization_id
        || payload.authorization.signed_at > event.created_at
    {
        return Err("organization_statement_unverified");
    }
    let did = arkret_identity::verification_method_did(
        payload.authorization.verification_method.as_str(),
    )
    .map_err(|_| "organization_statement_unverified")?;
    if arkret_wire::project_did_to_core_id(&did).map_err(|_| "organization_statement_unverified")?
        != payload.organization_id
    {
        return Err("organization_statement_unverified");
    }
    let key = crate::jws_verify::resolve_ed25519_pubkey_at(
        state,
        payload.authorization.verification_method.as_str(),
        payload.authorization.signed_at,
    )
    .await
    .map_err(|_| "organization_statement_unverified")?;
    use base64::Engine as _;
    let arkret_models_collaboration::SignatureMaterial::NonEmptyString(encoded) =
        &payload.authorization.proof
    else {
        return Err("organization_statement_unverified");
    };
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded.as_str())
        .map_err(|_| "organization_statement_unverified")?;
    let signature = ed25519_dalek::Signature::from_slice(&bytes)
        .map_err(|_| "organization_statement_unverified")?;
    let transcript =
        arkret_models_collaboration::realm_organization_statement_signing_bytes(&payload)
            .map_err(|_| "organization_statement_unverified")?;
    key.verify_strict(&transcript, &signature)
        .map_err(|_| "organization_statement_unverified")?;
    Ok(Some(coland_storage::RealmOrganizationProofCommit {
        event_id: event.event_id.clone(),
        verification_method: payload.authorization.verification_method,
        signed_at: payload.authorization.signed_at,
        public_key: key.to_bytes(),
    }))
}

pub(crate) async fn organization_policy_blocks_federation(
    state: &AppState,
    realm_id: &str,
    _peer_service_id: &DidCoreId,
) -> bool {
    let Ok(realm_id) = arkret_wire::RealmId::new(realm_id.to_owned()) else {
        return true;
    };
    state
        .persistence()
        .require_organization_moderation_authority(&realm_id, Utc::now())
        .await
        .is_err()
}

fn organization_record_view(state: &AppState, record: &OrganizationRecord) -> OrganizationView {
    let organization_id = DidCoreId::new(record.organization_id.clone())
        .expect("stored organization id remains a DID core id");
    let realms = state
        .governance()
        .cached_organization_realms(&organization_id);
    let realm_count = realms.len();
    OrganizationView {
        organization_id: record.organization_id.clone(),
        handle: record.handle.clone(),
        display_name: record.display_name.clone(),
        source_refs: record.source_refs.clone(),
        policy_revision: record.policy_revision.clone(),
        verified: record.verified,
        verified_badge: record.verified,
        members: record.members.iter().cloned().collect::<Vec<_>>(),
        member_count: record.member_count.max(record.members.len()),
        realms,
        realm_count,
        created_by: record.created_by.clone(),
        created_at: arkret_canonical::format_timestamp_canonical(record.created_at),
        updated_at: arkret_canonical::format_timestamp_canonical(record.updated_at),
    }
}

fn normalized_organization_id(raw: &str) -> Result<String, AppError> {
    let value = raw.trim();
    if value.is_empty() {
        return Err(AppError::param_invalid("organization_id is required"));
    }
    arkret_identifiers::DidCoreId::new(value.to_owned())
        .map(|id| id.to_string())
        .map_err(|_| AppError::param_invalid("organization_id must be a DID core identifier"))
}

fn display_name_from_organization_id(organization_id: &str) -> String {
    organization_id
        .trim_start_matches("ak:did_core:")
        .replace(['.', '-'], " ")
}
