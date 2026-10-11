//! Owner-scoped policy document CRUD on the Coland product surface.
//!
//! `/_coland/self/...` stores deployment-local policy documents
//! CRUD is deployment-local document management, not a v1 protocol operation.
//! These documents do not participate in protocol authorization decisions.
//! This product surface is served off the protocol root and
//! uses reverse-domain `org.arkret.coland.policy_document.*` operation ids
//! rather than the `ak.*` protocol namespace:
//! - `GET    /_coland/self/policies`            list owner-scoped policies
//! - `POST   /_coland/self/policies`            upsert one policy document
//! - `GET    /_coland/self/policies/{id}`       read one policy document
//! - `DELETE /_coland/self/policies/{id}`       remove one policy document
//!
//! `policy_document_to_response`, `is_valid_generated_or_custom_id`, and the
//! supported-effect/scope/type validators are `pub` so product handlers
//! can reuse them via the `crate::routing::*` re-exports.
use arkret_identifiers::{Did, DidCoreId, RealmId, project_did_to_core_id};
use coland_http::error::AppError;
use coland_http::result::{JsonResult, json_ok};
use coland_services::governance::PolicyDocumentRecord;
use salvo::oapi::extract::{JsonBody, PathParam, QueryParam};
use salvo::prelude::*;

use super::{now, validate_canonical_json_value};
use crate::ids;
use crate::routing::system::extract::AuthArgs;
use crate::state::AppState;
use crate::wire::{
    AdminPolicyDocument, AdminPolicyDocumentPage, AdminPolicyPayload, OkOutcome,
    UpsertPolicyDocumentRequestBody,
};

/// Product surface (`/_coland/self/...`): owner-scoped policy document storage
/// CRUD, kept outside the protocol root.
pub(super) fn product_router() -> Router {
    Router::new()
        .push(
            Router::with_path("policies")
                .get(list_policy_documents)
                .post(upsert_policy_document),
        )
        .push(
            Router::with_path("policies/{policy_id}")
                .get(get_policy_document)
                .delete(delete_policy_document),
        )
}

#[salvo::oapi::endpoint(
    operation_id = "org.arkret.coland.policy_document.query.list",
    tags("access")
)]
#[tracing::instrument(skip_all, fields(op = "org.arkret.coland.policy_document.query.list"))]
async fn list_policy_documents(
    aa: AuthArgs,
    scope: QueryParam<String, false>,
    subject_ref: QueryParam<String, false>,
    include_inactive: QueryParam<bool, false>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AdminPolicyDocumentPage> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let scope = scope.into_inner();
    let subject_ref = subject_ref.into_inner();
    let include_inactive = include_inactive.into_inner().unwrap_or(false);
    let policies = state
        .governance()
        .policy_documents_for_owner(&session.actor)
        .await
        .unwrap_or_default()
        .into_iter()
        .filter(|policy| include_inactive || policy.active)
        .filter(|policy| scope.as_deref().is_none_or(|scope| policy.scope == scope))
        .filter(|policy| {
            subject_ref
                .as_deref()
                .is_none_or(|subject_ref| policy.subject_ref == subject_ref)
        })
        .map(|policy| policy_document_to_response(&policy))
        .collect::<Result<Vec<_>, _>>()?;
    json_ok(AdminPolicyDocumentPage {
        policies,
        next_cursor: None,
    })
}

#[salvo::oapi::endpoint(
    operation_id = "org.arkret.coland.policy_document.resource.get",
    tags("access")
)]
#[tracing::instrument(
    skip_all,
    fields(op = "org.arkret.coland.policy_document.resource.get")
)]
async fn get_policy_document(
    aa: AuthArgs,
    policy_id: PathParam<String>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AdminPolicyDocument> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let policy_id = policy_id.into_inner();
    state
        .governance()
        .policy_document(&policy_id)
        .await
        .ok()
        .flatten()
        .filter(|policy| policy.owner == session.actor)
        .map(|policy| policy_document_to_response(&policy).and_then(json_ok))
        .unwrap_or_else(|| Err(AppError::not_found("policy not found")))
}

#[salvo::oapi::endpoint(
    operation_id = "org.arkret.coland.policy_document.command.upsert",
    tags("access")
)]
#[tracing::instrument(
    skip_all,
    fields(op = "org.arkret.coland.policy_document.command.upsert")
)]
async fn upsert_policy_document(
    aa: AuthArgs,
    body: JsonBody<UpsertPolicyDocumentRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AdminPolicyDocument> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let body = body.into_inner();
    if !is_valid_policy_scope(&body.scope) {
        return Err(AppError::param_invalid("invalid policy scope"));
    }
    let subject_ref = canonical_policy_subject_ref(&body.subject_ref)
        .ok_or_else(|| AppError::param_invalid("invalid policy subject_ref"))?;
    if !is_valid_policy_kind(&body.policy_kind) {
        return Err(AppError::param_invalid("invalid policy type"));
    }
    if let Err(message) = validate_canonical_json_value(&body.resource) {
        return Err(AppError::param_invalid(message));
    }
    for obligation in &body.obligations {
        if let Err(message) = validate_canonical_json_value(obligation) {
            return Err(AppError::param_invalid(message));
        }
    }
    let actions = if body.actions.is_empty() {
        vec!["*".to_owned()]
    } else {
        body.actions
    };
    if actions
        .iter()
        .any(|action| action.trim().is_empty() || action.len() > 128)
    {
        return Err(AppError::param_invalid("invalid policy action"));
    }
    let policy_id = body.policy_id.unwrap_or_else(|| ids::generate("policy"));
    if !is_valid_generated_or_custom_id(&policy_id, "policy") {
        return Err(AppError::param_invalid("invalid policy_id"));
    }
    let service = state.governance();
    if let Ok(Some(existing)) = service.policy_document(&policy_id).await
        && existing.owner != session.actor
    {
        return Err(AppError::capability_denied(
            "policy is owned by another actor",
        ));
    }
    let payload = AdminPolicyPayload {
        effect: body.effect,
        actions,
        resource: body.resource,
        obligations: body.obligations,
    };
    let record = PolicyDocumentRecord {
        policy_id: policy_id.clone(),
        owner: session.actor,
        scope: body.scope,
        subject_ref,
        policy_kind: body.policy_kind,
        payload: serde_json::to_value(&payload)
            .map_err(|error| AppError::internal(error.to_string()))?,
        active: body.active,
        updated_at: now(),
    };
    service
        .store_policy_document(record.clone())
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    json_ok(policy_document_to_response(&record)?)
}

#[salvo::oapi::endpoint(
    operation_id = "org.arkret.coland.policy_document.resource.delete",
    tags("access")
)]
#[tracing::instrument(
    skip_all,
    fields(op = "org.arkret.coland.policy_document.resource.delete")
)]
async fn delete_policy_document(
    aa: AuthArgs,
    policy_id: PathParam<String>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<OkOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let policy_id = policy_id.into_inner();
    let service = state.governance();
    let Ok(Some(policy)) = service.policy_document(&policy_id).await else {
        return Err(AppError::not_found("policy not found"));
    };
    if policy.owner != session.actor {
        return Err(AppError::capability_denied(
            "policy is owned by another actor",
        ));
    }
    service
        .delete_policy_document(&policy_id)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    json_ok(OkOutcome { ok: true })
}

/// Decode a stored local policy document into its public response shape.
///
/// The stored payload is written by [`upsert_policy_document`] through the
/// same type, so a decode failure is storage corruption rather than an older
/// shape and is surfaced as an internal error.
pub fn policy_document_to_response(
    policy: &PolicyDocumentRecord,
) -> Result<AdminPolicyDocument, AppError> {
    let payload: AdminPolicyPayload =
        serde_json::from_value(policy.payload.clone()).map_err(|error| {
            AppError::internal(format!(
                "policy document {} has an undecodable payload: {error}",
                policy.policy_id
            ))
        })?;
    Ok(AdminPolicyDocument {
        policy_id: policy.policy_id.clone(),
        owner: policy.owner.clone(),
        scope: policy.scope.clone(),
        subject_ref: policy.subject_ref.clone(),
        policy_kind: policy.policy_kind.clone(),
        payload,
        active: policy.active,
        updated_at: policy.updated_at,
    })
}

fn canonical_policy_subject_ref(subject_ref: &str) -> Option<String> {
    if subject_ref == "*" {
        return Some(subject_ref.to_owned());
    }
    DidCoreId::new(subject_ref.to_owned())
        .or_else(|_| Did::new(subject_ref.to_owned()).and_then(|did| project_did_to_core_id(&did)))
        .ok()
        .map(|core_id| core_id.to_string())
}

pub fn is_valid_policy_scope(value: &str) -> bool {
    value == "*" || RealmId::new(value.to_owned()).is_ok()
}

pub fn is_valid_policy_kind(value: &str) -> bool {
    let value = value.trim();
    !value.is_empty()
        && value.len() <= 128
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-' | '*'))
}

pub fn is_valid_generated_or_custom_id(value: &str, kind: &str) -> bool {
    let prefix = format!("ak:{kind}:");
    value.starts_with(&prefix)
        && value[prefix.len()..]
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | ':' | '.'))
}
