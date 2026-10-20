//! Session-free RFC 9421 proof by the exact accepted Realm control method.
use arkret_models_integration::RealmActorControlHttpMetadata;
use arkret_signatures::http_signature::{HttpSignatureScenario, SignatureVerificationPolicy};
use arkret_wire::ServiceOperationId;
use coland_http::error::AppError;
use coland_http::http_signature;
use salvo::prelude::Request;

use crate::state::AppState;

#[derive(Clone, Debug)]
pub(crate) struct VerifiedRealmActorControl {
    pub carrier: coland_storage::AppletControlCarrier,
    pub operation: ServiceOperationId,
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

fn refused(detail: impl std::fmt::Display) -> AppError {
    AppError::unauthenticated(format!("Realm control authentication failed: {detail}"))
}
fn authority_error(error: coland_services::ServiceError) -> AppError {
    match error {
        coland_services::ServiceError::Conflict(_) => refused("control identity or nonce refused"),
        _ => crate::app_error!(
            TemporarilyUnavailable,
            "Realm control authority is unavailable"
        ),
    }
}
fn header<'a>(req: &'a Request, name: &str) -> Result<&'a str, AppError> {
    let values = req.headers().get_all(name);
    let mut values = values.iter();
    let value = values
        .next()
        .ok_or_else(|| refused(format!("missing {name}")))?;
    if values.next().is_some() {
        return Err(refused(format!("ambiguous {name}")));
    }
    value.to_str().map_err(refused)
}

pub(crate) async fn verify(
    state: &AppState,
    req: &mut Request,
) -> Result<VerifiedRealmActorControl, AppError> {
    for name in [
        "authorization",
        "dpop",
        "source-service-id",
        "arkret-managed-device",
    ] {
        if req.headers().contains_key(name) {
            return Err(refused("mixed authentication credentials"));
        }
    }
    for name in [
        "signature-input",
        "signature",
        "content-digest",
        "idempotency-key",
        "content-type",
    ] {
        if req.headers().contains_key(name) {
            header(req, name)?;
        }
    }
    let operation = ServiceOperationId::from_wire(header(req, "arkret-operation")?)
        .filter(|operation| {
            matches!(
                operation,
                ServiceOperationId::SelfEventsCommandSubmitV1
                    | ServiceOperationId::SelfRealmActorReadMaterialV1
            )
        })
        .ok_or_else(|| refused("operation is outside the Realm control surface"))?;
    if !super::session_pop::request_matches_operation(req, operation)
        || header(req, "destination-service-id")? != state.service_id()
    {
        return Err(refused("method, path or destination differs"));
    }
    let metadata = RealmActorControlHttpMetadata::from_header_value(header(
        req,
        "arkret-realm-actor-control",
    )?)
    .map_err(refused)?;
    http_signature::reject_content_encoding(req, || refused("Content-Encoding is not permitted"))?;
    let bytes = req.payload().await.map_err(refused)?.to_vec();
    if !bytes.is_empty() {
        arkret_canonical::canonical::validate_canonical_bytes(&bytes).map_err(refused)?;
    }
    let carrier = state
        .authority_commits()
        .realm_actor_control_carrier(&metadata, &state.service_core_id())
        .await
        .map_err(authority_error)?;
    let input = http_signature::parse_signature_input_header(req).map_err(refused)?;
    if input.label != "sig1" || input.key_id != carrier.verification_method.as_str() {
        return Err(refused("keyid is not the exact accepted control method"));
    }
    let mut conditional = Vec::new();
    if !bytes.is_empty() {
        conditional.push("content-digest");
    }
    if req.headers().contains_key("idempotency-key") {
        conditional.push("idempotency-key");
    }
    let policy = SignatureVerificationPolicy::for_scenario(
        HttpSignatureScenario::RealmActorControlV1,
        &conditional,
    )
    .map_err(refused)?;
    let key = ed25519_dalek::VerifyingKey::from_bytes(&carrier.public_key).map_err(refused)?;
    let verified = http_signature::verify_signed_http_request(
        req,
        &crate::routing::federation::signature_target_uri(req, state),
        &crate::routing::federation::signature_authority(req, state),
        &bytes,
        &key,
        &policy,
    )
    .map_err(refused)?;
    let expires_at = chrono::DateTime::from_timestamp(verified.signature_input.expires, 0)
        .ok_or_else(|| refused("invalid signature expiry"))?;
    state
        .authority_commits()
        .consume_realm_actor_control_nonce(&carrier, &metadata, expires_at)
        .await
        .map_err(authority_error)?;
    Ok(VerifiedRealmActorControl {
        carrier,
        operation,
        expires_at,
    })
}
