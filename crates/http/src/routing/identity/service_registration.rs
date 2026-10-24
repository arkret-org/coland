//! Standard Service Identity Provider operations.

use arkret_models_identity::service_identity::{
    CanonicalServiceUrl, ServiceRegistrationEnsureRequestBody, ServiceRegistrationKey,
    ServiceRegistrationReceipt, ServiceRegistrationResponseBody,
};
use arkret_wire::{DidCoreId, PayloadProof, ServiceKind, project_did_to_core_id, proof_kind};
use coland_http::error::AppError;
use coland_http::result::{JsonResult, json_ok};
use coland_services::identity::{DidDocumentState, DidLogEvent, ServiceRegistrationCommitResult};
use salvo::oapi::endpoint;
use salvo::oapi::extract::{JsonBody, QueryParam};
use salvo::prelude::*;
use serde_json::{Value, json};

use super::did::require_embedded_webvh_registration_bearer;
use super::webvh_validation::{
    WebvhLogEntry, validate_log_chain, validate_rotation_authorization_for_log,
    validate_witness_policy_for_log, verify_log_subject, verify_scid_against_did,
    verify_webvh_log_proof,
};
use crate::state::AppState;

#[endpoint(
    summary = "Ensure a service registration",
    tags("service_registration")
)]
pub(crate) async fn ensure(
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<ServiceRegistrationEnsureRequestBody>,
) -> JsonResult<ServiceRegistrationResponseBody> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    require_embedded_webvh_registration_bearer(state, req)?;
    let request = body.into_inner();
    request.validate().map_err(registration_rejected)?;
    let key = request.registration_key().map_err(registration_rejected)?;
    let operation = serde_json::to_value(&request.inception_operation)
        .map_err(|error| AppError::internal(error.to_string()))?;
    validate_signed_inception(&request, &operation)?;

    let issued_at = chrono::Utc::now();
    let receipt = sign_registration_receipt(state, &key, &request, issued_at).await?;
    let outcome = ServiceRegistrationResponseBody {
        did_document: request.inception_operation.state.clone(),
        registration_receipt: receipt,
        created: true,
    };
    outcome
        .validate_ensure_response(&request)
        .map_err(registration_rejected)?;

    let event_digest = outcome.registration_receipt.log_head_digest.clone();
    let service_did = outcome.did_document.id.to_string();
    let document_value = serde_json::to_value(&outcome.did_document)
        .map_err(|error| AppError::internal(error.to_string()))?;
    let document = DidDocumentState {
        did: service_did.clone(),
        did_document: document_value,
        key_log_head: Some(event_digest.clone()),
        sequence: 1,
        method_evidence: json!({
            "mode": "service_registration_provider",
            "operation": arkret_wire::ServiceOperationId::ROOT_IDENTITY_SERVICE_REGISTRATION_COMMAND_ENSURE_V1,
            "service_kind": key.service_kind().as_str(),
            "public_base_url": key.public_base_url().as_str(),
            "version_id": outcome.version_id(),
        }),
        fetched_at: issued_at,
        expires_at: issued_at,
        updated_at: issued_at,
    };
    let admitted_document: arkret_identity::DidDocument =
        serde_json::from_value(document.did_document.clone()).map_err(|error| {
            crate::app_error!(
                SchemaViolation,
                format!("service DID document is invalid: {error}"),
            )
        })?;
    crate::test_material_admission::enforce_did_document_admission(
        &admitted_document,
        Some(&state.config().trust_domain),
    )
    .map_err(|error| crate::app_error!(SignatureInvalid, error))?;
    let event = DidLogEvent {
        event_digest,
        did: service_did,
        sequence: 1,
        operation,
        created_at: issued_at,
    };

    match state
        .dids()
        .commit_formal_service_registration(
            &state.config().trust_domain,
            key,
            outcome,
            document.clone(),
            event,
        )
        .await
        .map_err(provider_unavailable)?
    {
        ServiceRegistrationCommitResult::Created(outcome) => {
            if let Err(error) = state.cache_resolved_did_document(document) {
                tracing::warn!(%error, "failed to cache newly registered service DID document");
            }
            json_ok(outcome)
        }
        ServiceRegistrationCommitResult::Existing(outcome) => json_ok(outcome),
        ServiceRegistrationCommitResult::Conflict => Err(crate::app_error!(
            ServiceIdentityConflict,
            "service registration key, DID, or control root is already bound differently",
        )),
    }
}

#[endpoint(summary = "Get a service registration", tags("service_registration"))]
pub(crate) async fn get(
    depot: &mut Depot,
    req: &mut Request,
    service_kind: QueryParam<String, true>,
    public_base_url: QueryParam<String, true>,
) -> JsonResult<ServiceRegistrationResponseBody> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    require_embedded_webvh_registration_bearer(state, req)?;
    let service_kind =
        serde_json::from_value::<ServiceKind>(Value::String(service_kind.into_inner()))
            .map_err(|error| AppError::param_invalid(format!("invalid service_kind: {error}")))?;
    let public_base_url = CanonicalServiceUrl::new(public_base_url.into_inner())
        .map_err(|error| AppError::param_invalid(error.to_string()))?;
    let key = ServiceRegistrationKey::new(service_kind, public_base_url)
        .map_err(|error| AppError::param_invalid(error.to_string()))?;
    let outcome = state
        .dids()
        .service_registration(&key)
        .await
        .map_err(provider_unavailable)?
        .ok_or_else(|| {
            crate::app_error!(
                DidNotFound,
                "service registration does not exist for the requested key",
            )
        })?;
    outcome.validate_for(&key).map_err(|error| {
        AppError::internal(format!("stored service registration invalid: {error}"))
    })?;
    json_ok(outcome)
}

fn validate_signed_inception(
    request: &ServiceRegistrationEnsureRequestBody,
    operation: &Value,
) -> Result<(), AppError> {
    verify_webvh_log_proof(operation).map_err(registration_rejected)?;
    let log = [WebvhLogEntry::new(operation.clone())];
    validate_log_chain(&log).map_err(registration_rejected)?;
    let did = request.inception_operation.state.id.as_str();
    verify_scid_against_did(did, &log[0]).map_err(registration_rejected)?;
    verify_log_subject(did, &log).map_err(registration_rejected)?;
    validate_witness_policy_for_log(&log).map_err(registration_rejected)?;
    validate_rotation_authorization_for_log(&log).map_err(registration_rejected)
}

async fn sign_registration_receipt(
    state: &AppState,
    key: &ServiceRegistrationKey,
    request: &ServiceRegistrationEnsureRequestBody,
    issued_at: chrono::DateTime<chrono::Utc>,
) -> Result<ServiceRegistrationReceipt, AppError> {
    let issued_at = arkret_canonical::normalize_timestamp_canonical(issued_at);
    let provider_id = DidCoreId::new(state.service_id().clone())
        .map_err(|error| AppError::internal(format!("provider service id invalid: {error}")))?;
    let log_head_digest = request
        .inception_operation
        .log_head_digest()
        .map_err(|error| AppError::internal(error.to_string()))?;
    let control_key_digest = request
        .inception_operation
        .control_key_digest()
        .map_err(|error| AppError::internal(error.to_string()))?;
    let did = request.inception_operation.state.id.clone();
    let service_id =
        project_did_to_core_id(&did).map_err(|error| AppError::internal(error.to_string()))?;
    let (_, verification_method) = state
        .current_service_receipt_binding()
        .await
        .map_err(AppError::internal)?;
    let mut receipt = ServiceRegistrationReceipt {
        registration_receipt_id: arkret_wire::ServiceRegistrationReceiptId::new(format!(
            "ak:service_registration_receipt:{}",
            "0".repeat(64)
        ))
        .map_err(|error| AppError::internal(error.to_string()))?,
        registration_key: key.clone(),
        service_id,
        did,
        version_id: request.inception_operation.version_id.clone(),
        log_head_digest,
        control_key_digest,
        issued_at,
        provider_id,
        proof: PayloadProof {
            kind: proof_kind::DETACHED_JWS.to_owned(),
            verification_method,
            payload_digest: arkret_wire::Hash::new(format!("sha256:{}", "0".repeat(64)))
                .map_err(|error| AppError::internal(error.to_string()))?,
            created_at: issued_at,
            domain: None,
            audience: None,
            proof_purpose: None,
            jws: "placeholder".to_owned(),
        },
    };
    receipt.registration_receipt_id = receipt
        .expected_registration_receipt_id()
        .map_err(|error| AppError::internal(error.to_string()))?;
    receipt.proof.payload_digest = receipt
        .expected_payload_digest()
        .map_err(|error| AppError::internal(error.to_string()))?;
    receipt.proof = arkret_signatures::service_identity::sign_registration_receipt_proof(
        &receipt,
        state.notary_signing_key().as_ref(),
    )
    .map_err(|error| AppError::internal(error.to_string()))?;
    receipt
        .validate_for(key, &receipt.service_id, &receipt.did)
        .map_err(|error| AppError::internal(error.to_string()))?;
    Ok(receipt)
}

fn registration_rejected(error: impl std::fmt::Display) -> AppError {
    crate::app_error!(
        ServiceRegistrationDenied,
        format!("service registration rejected: {error}"),
    )
}

fn provider_unavailable(error: impl std::fmt::Display) -> AppError {
    crate::app_error!(
        ServiceIdentityProviderUnavailable,
        format!("service identity provider unavailable: {error}"),
    )
}
