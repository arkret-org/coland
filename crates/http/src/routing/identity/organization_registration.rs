use arkret_identifiers::DidCoreId;
use arkret_models_identity::{
    OrganizationRegistrationChallenge, OrganizationRegistrationChallengeRequestBody,
    OrganizationRegistrationEnsureRequestBody, OrganizationRegistrationRefreshRequestBody,
    OrganizationRegistrationResponseBody, OrganizationRegistrationRevokeRequestBody,
    OrganizationRegistrationScope,
};
use arkret_signatures::Ed25519DetachedJwsSigner;
use coland_http::error::AppError;
use coland_http::result::{JsonResult, json_ok};
use coland_services::organization_registration::{
    OrganizationRegistrationError, OrganizationRegistrationErrorCode,
    OrganizationRegistrationReceiptSigner,
};
use salvo::oapi::endpoint;
use salvo::oapi::extract::{JsonBody, QueryParam};
use salvo::prelude::*;
use serde::de::DeserializeOwned;
use serde_json::Value;

use super::AuthArgs;
use crate::state::AppState;

struct CurrentReceiptSigner {
    issuer_id: DidCoreId,
    verification_method: arkret_wire::DidUrl,
    signer: Ed25519DetachedJwsSigner,
}

impl CurrentReceiptSigner {
    fn from_state(state: &AppState) -> Result<Self, AppError> {
        let issuer_id = DidCoreId::new(state.service_id().clone())
            .map_err(|error| AppError::internal(format!("service core id is invalid: {error}")))?;
        let issuer_did = state.service_resolution_commitment().did.clone();
        let verification_method = arkret_wire::DidUrl::new(format!("{issuer_did}#notary-key"))
            .map_err(|error| {
                AppError::internal(format!(
                    "service notary verification method is invalid: {error}"
                ))
            })?;
        let signer = Ed25519DetachedJwsSigner::new(
            state.notary_signing_key().as_ref().clone(),
            verification_method.as_str().to_owned(),
        );
        Ok(Self {
            issuer_id,
            verification_method,
            signer,
        })
    }
}

impl OrganizationRegistrationReceiptSigner for CurrentReceiptSigner {
    fn issuer_id(&self) -> &DidCoreId {
        &self.issuer_id
    }

    fn verification_method(&self) -> &arkret_wire::DidUrl {
        &self.verification_method
    }

    fn sign_detached_jws(&self, signing_bytes: &[u8]) -> Result<String, String> {
        Ok(self.signer.sign_detached_jws(signing_bytes))
    }
}

#[endpoint(
    operation_id = "ak.root.identity.organization_registration.command.prepare",
    request_body = OrganizationRegistrationChallengeRequestBody,
    summary = "Prepare an external organization DID registration",
    tags("organization_registration")
)]
pub(crate) async fn prepare(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<OrganizationRegistrationChallenge> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    require_registry_admin(state, &aa.authenticated_session(state, req).await?.actor)?;
    let body = parse_registration_body(req).await?;
    let issuer = DidCoreId::new(state.service_id().clone())
        .map_err(|error| AppError::internal(format!("service core id is invalid: {error}")))?;
    let origin = state
        .config()
        .public_base_url
        .trim_end_matches('/')
        .to_owned();
    let challenge = state
        .organization_registrations()
        .prepare(
            body,
            &origin,
            state.config().trust_domain.as_str(),
            &issuer,
            chrono::Utc::now(),
        )
        .await
        .map_err(map_error)?;
    json_ok(challenge)
}

#[endpoint(
    operation_id = "ak.root.identity.organization_registration.command.ensure",
    request_body = OrganizationRegistrationEnsureRequestBody,
    summary = "Ensure an external organization DID registration",
    tags("organization_registration")
)]
pub(crate) async fn ensure(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<OrganizationRegistrationResponseBody> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    require_registry_admin(state, &aa.authenticated_session(state, req).await?.actor)?;
    let body = parse_registration_body(req).await?;
    let signer = CurrentReceiptSigner::from_state(state)?;
    let outcome = state
        .organization_registrations()
        .ensure(body, &signer, chrono::Utc::now())
        .await
        .map_err(map_error)?;
    json_ok(outcome)
}

#[endpoint(
    operation_id = "ak.root.identity.organization_registration.resource.get",
    summary = "Get an external organization DID registration",
    tags("organization_registration")
)]
pub(crate) async fn get(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    organization_id: QueryParam<String, true>,
) -> JsonResult<OrganizationRegistrationResponseBody> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let actor = aa.authenticated_session(state, req).await?.actor;
    let organization_id = DidCoreId::new(organization_id.into_inner())
        .map_err(|error| AppError::param_invalid(format!("invalid organization_id: {error}")))?;
    let current = state
        .organization_registrations()
        .current(&organization_id)
        .await
        .map_err(map_error)?;
    let actor_core_id = authenticated_actor_core_id(&actor);
    let authorized = current.as_ref().is_some_and(|current| {
        state.is_admin_principal(&actor)
            || actor_core_id.as_ref() == Some(&current.generation.local_admin_subject_id)
    });
    if !authorized {
        return Err(indistinguishable_not_found());
    }
    let mut outcome = current.expect("authorized current registration").outcome;
    outcome.created = false;
    json_ok(outcome)
}

#[endpoint(
    operation_id = "ak.root.identity.organization_registration.command.refresh",
    summary = "Refresh an external organization DID registration",
    tags("organization_registration")
)]
pub(crate) async fn refresh(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<OrganizationRegistrationRefreshRequestBody>,
) -> JsonResult<OrganizationRegistrationResponseBody> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let request = body.into_inner();
    let current = require_registration_manager(state, &aa, req, &request.organization_id).await?;
    let signer = CurrentReceiptSigner::from_state(state)?;
    let outcome = state
        .organization_registrations()
        .refresh(request, &current, &signer, chrono::Utc::now())
        .await
        .map_err(map_error)?;
    json_ok(outcome)
}

#[endpoint(
    operation_id = "ak.root.identity.organization_registration.command.revoke",
    summary = "Revoke an external organization DID registration",
    tags("organization_registration")
)]
pub(crate) async fn revoke(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<OrganizationRegistrationRevokeRequestBody>,
) -> JsonResult<OrganizationRegistrationResponseBody> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let request = body.into_inner();
    let current = require_registration_manager(state, &aa, req, &request.organization_id).await?;
    let signer = CurrentReceiptSigner::from_state(state)?;
    let outcome = state
        .organization_registrations()
        .revoke(request, &current, &signer, chrono::Utc::now())
        .await
        .map_err(map_error)?;
    json_ok(outcome)
}

async fn require_registration_manager(
    state: &AppState,
    aa: &AuthArgs,
    req: &mut Request,
    organization_id: &DidCoreId,
) -> Result<coland_storage::OrganizationRegistrationCurrent, AppError> {
    let actor = aa.authenticated_session(state, req).await?.actor;
    let current = state
        .organization_registrations()
        .current(organization_id)
        .await
        .map_err(map_error)?;
    let actor_core_id = authenticated_actor_core_id(&actor);
    if current.as_ref().is_some_and(|current| {
        state.is_admin_principal(&actor)
            || actor_core_id.as_ref() == Some(&current.generation.local_admin_subject_id)
    }) {
        return Ok(current.expect("authorized current registration"));
    }
    Err(indistinguishable_not_found())
}

fn authenticated_actor_core_id(actor: &str) -> Option<DidCoreId> {
    DidCoreId::new(actor.to_owned()).ok()
}

fn require_registry_admin(state: &AppState, actor: &str) -> Result<(), AppError> {
    if state.is_admin_principal(actor) {
        return Ok(());
    }
    Err(AppError::capability_denied(
        "organization registration requires a trusted deployment administrator",
    ))
}

async fn parse_registration_body<T: DeserializeOwned>(req: &mut Request) -> Result<T, AppError> {
    let body = req
        .parse_json::<Value>()
        .await
        .map_err(|error| crate::app_error!(SchemaViolation, error.to_string()))?;
    if let Some(scopes) = body.get("requested_scopes").and_then(Value::as_array) {
        for scope in scopes {
            if scope.is_string()
                && serde_json::from_value::<OrganizationRegistrationScope>(scope.clone()).is_err()
            {
                return Err(crate::app_error!(
                    UnsupportedOrganizationRegistrationScope,
                    "organization registration scope is unsupported",
                ));
            }
        }
    }
    serde_json::from_value(body)
        .map_err(|error| crate::app_error!(SchemaViolation, error.to_string()))
}

fn indistinguishable_not_found() -> AppError {
    crate::app_error!(DidNotFound, "organization registration was not found",)
}

fn map_error(error: OrganizationRegistrationError) -> AppError {
    let detail = error.detail;
    match error.code {
        OrganizationRegistrationErrorCode::SchemaViolation => {
            crate::app_error!(SchemaViolation, detail)
        }
        OrganizationRegistrationErrorCode::DidNotFound => indistinguishable_not_found(),
        OrganizationRegistrationErrorCode::ChallengeInvalid => {
            crate::app_error!(OrganizationRegistrationChallengeInvalid, detail)
        }
        OrganizationRegistrationErrorCode::ControlProofInvalid => {
            crate::app_error!(OrganizationRegistrationControlProofInvalid, detail,)
        }
        OrganizationRegistrationErrorCode::QuorumNotMet => {
            crate::app_error!(OrganizationRegistrationQuorumNotMet, detail)
        }
        OrganizationRegistrationErrorCode::ScopeUnsupported => {
            crate::app_error!(UnsupportedOrganizationRegistrationScope, detail)
        }
        OrganizationRegistrationErrorCode::Revoked => {
            crate::app_error!(OrganizationRegistrationRevoked, detail)
        }
        OrganizationRegistrationErrorCode::Stale => {
            crate::app_error!(OrganizationRegistrationStale, detail)
        }
        OrganizationRegistrationErrorCode::Internal => AppError::internal(detail),
    }
}

#[cfg(test)]
mod tests {
    use super::authenticated_actor_core_id;

    #[test]
    fn authenticated_actor_uses_the_session_principal_core() {
        let core = authenticated_actor_core_id("ak:did_core:webvh:z6mkactor")
            .expect("authenticated principal core");
        assert_eq!(core.as_str(), "ak:did_core:webvh:z6mkactor");
        assert!(authenticated_actor_core_id("did:webvh:z6mkactor:alice.example").is_none());
    }
}
