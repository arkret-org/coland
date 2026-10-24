//! Server-mediated device-pairing short-link surface (mirrors the agent-pairing
//! `open` template). Mounted UNAUTHENTICATED under `/_arkret/open`:
//!
//! - `POST /_arkret/open/device-pairing/requests`         —
//!   `ak.open.device_pairing.command.stage.v1`
//! - `POST /_arkret/open/device-pairing/resolve`          —
//!   `ak.open.device_pairing.read.resolve.v1`
//! - `POST /_arkret/open/device-pairing/requests/status`  — `ak.open.device_pairing.read.status.v1`
//!
//! Security: these handlers take NO `AuthArgs` and never call
//! `authenticated_session`. They retain the public rate bucket and body-shape
//! checks, then forward the exact public DTO through the typed Account
//! Authority port. They never save, read, cache, or derive pairing business
//! state locally. Until an RFC 9421 service-to-service transport is installed,
//! that port fails closed as `temporarily_unavailable`; the older deployment
//! bearer is not a fallback. The resolve token is accepted only in the JSON
//! body, never the URL.

use arkret_identifiers::DeviceId;
use arkret_models_collaboration::device_pairing::{
    DevicePairingBootstrap, DevicePairingResolveRequestBody, DevicePairingStageRequestBody,
    DevicePairingStageResponseBody, DevicePairingStatusRequestBody,
    DevicePairingStatusResponseBody,
};
use arkret_models_collaboration::governance::agent_artifacts::PublicKey;
use coland_http::error::AppError;
use coland_http::result::{JsonResult, json_ok};
use salvo::oapi::endpoint;
use salvo::oapi::extract::JsonBody;
use salvo::prelude::*;

use crate::state::AppState;

/// Mounted under `/_arkret/open`.
pub(crate) fn open_router() -> Router {
    Router::with_path("device-pairing")
        .push(Router::with_path("requests").post(stage_device_pairing))
        .push(Router::with_path("resolve").post(resolve_device_pairing))
        .push(Router::with_path("requests/status").post(device_pairing_status))
}

#[endpoint(
    operation_id = "ak.open.device_pairing.command.stage",
    summary = "Stage a device pairing short-link request",
    tags("device_pairing")
)]
#[tracing::instrument(skip_all, fields(op = "ak.open.device_pairing.command.stage.v1"))]
pub(super) async fn stage_device_pairing(
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<DevicePairingStageRequestBody>,
) -> JsonResult<DevicePairingStageResponseBody> {
    reject_device_pairing_query(req)?;
    let state = depot.get_typed::<AppState>().expect("state injected");
    let body = body.into_inner();
    validate_new_device_pubkey(&body.new_device_public_key)?;
    // This key belongs to exactly this accepted public ingress. The port owns
    // transport retry and receives the key once, so every retry is forced to
    // reuse it while the next public invocation receives a fresh value.
    let idempotency_key = new_internal_stage_idempotency_key();
    let outcome = state
        .account_authority_device_pairing()
        .stage(state, &body, &idempotency_key)
        .await?;
    json_ok(outcome)
}

#[endpoint(
    operation_id = "ak.open.device_pairing.read.resolve",
    summary = "Resolve a device pairing bootstrap",
    tags("device_pairing")
)]
#[tracing::instrument(skip_all, fields(op = "ak.open.device_pairing.read.resolve.v1"))]
pub(super) async fn resolve_device_pairing(
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<DevicePairingBootstrap> {
    reject_device_pairing_query(req)?;
    let state = depot.get_typed::<AppState>().expect("state injected");
    let body = req
        .parse_json::<DevicePairingResolveRequestBody>()
        .await
        .map_err(|_| AppError::json_invalid("invalid device pairing resolve request body"))?;
    let pairing_token = body.pairing_token.trim();
    if !is_device_pairing_token_shape(pairing_token) {
        return Err(device_pairing_not_found());
    }
    let outcome = state
        .account_authority_device_pairing()
        .resolve(state, &body)
        .await?;
    json_ok(outcome)
}

#[endpoint(
    operation_id = "ak.open.device_pairing.read.status",
    summary = "Poll a device pairing request status",
    tags("device_pairing")
)]
#[tracing::instrument(skip_all, fields(op = "ak.open.device_pairing.read.status.v1"))]
pub(super) async fn device_pairing_status(
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<DevicePairingStatusResponseBody> {
    reject_device_pairing_query(req)?;
    let state = depot.get_typed::<AppState>().expect("state injected");
    let body = req
        .parse_json::<DevicePairingStatusRequestBody>()
        .await
        .map_err(|_| AppError::json_invalid("invalid device pairing status request body"))?;
    let outcome = state
        .account_authority_device_pairing()
        .status(state, &body)
        .await?;
    outcome.validate().map_err(|error| {
        crate::app_error!(
            TemporarilyUnavailable,
            "invalid device pairing status from Account Authority: {error}"
        )
    })?;
    json_ok(outcome)
}

fn new_internal_stage_idempotency_key() -> String {
    format!("device-pairing-stage:{}", uuid::Uuid::now_v7())
}

fn reject_device_pairing_query(req: &Request) -> Result<(), AppError> {
    if req.uri().query().is_none() {
        return Ok(());
    }
    Err(AppError::schema_violation(
        "device pairing inputs must be sent in the JSON body, never in URL path or query",
    ))
}

fn is_device_pairing_token_shape(value: &str) -> bool {
    (22..=512).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn device_pairing_not_found() -> AppError {
    AppError::not_found("device pairing token not found")
}

/// Validate the staged device key the same way `auth::device_pair` does before
/// authorizing: `kid` must be an `ak:device` id and `key` must be an Ed25519
/// raw 32-byte base64url key. Directory multibase is a distinct representation
/// and accepting it here would stage a request the proof verifier cannot use.
fn validate_new_device_pubkey(new_device_public_key: &PublicKey) -> Result<(), AppError> {
    let public_key = new_device_public_key.key.as_str().trim();
    let bytes = arkret_canonical::base64url_decode(public_key).map_err(|error| {
        AppError::param_invalid(format!(
            "new_device_public_key.key must be a base64url Ed25519 key: {error}"
        ))
    })?;
    let _: [u8; 32] = bytes.try_into().map_err(|bytes: Vec<u8>| {
        AppError::param_invalid(format!(
            "new_device_public_key.key decoded to {} bytes, expected 32",
            bytes.len()
        ))
    })?;
    DeviceId::new(new_device_public_key.kid.as_str().to_owned())
        .map(|_| ())
        .map_err(|_| AppError::param_invalid("new_device_public_key.kid must be a ak:device id"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_public_stage_ingress_gets_a_fresh_internal_key() {
        let first = new_internal_stage_idempotency_key();
        let second = new_internal_stage_idempotency_key();
        assert_ne!(first, second);
        for key in [first, second] {
            assert!(key.starts_with("device-pairing-stage:"));
            assert!(key.len() <= 128);
            assert!(key.bytes().all(|byte| byte.is_ascii_alphanumeric()
                || matches!(byte, b'.' | b'_' | b'~' | b':' | b'-')));
        }
    }

    #[test]
    fn staged_pairing_key_rejects_directory_multibase() {
        let raw = arkret_canonical::base64url_encode([7_u8; 32]);
        let canonical: PublicKey = serde_json::from_value(serde_json::json!({
            "kty": "OKP",
            "kid": "ak:device:01964137-0000-7000-8000-0000000000c1",
            "algorithm": "Ed25519",
            "key": raw
        }))
        .unwrap();
        assert!(validate_new_device_pubkey(&canonical).is_ok());

        let multibase = arkret_canonical::ed25519_pubkey_to_did_key_multibase(&[7_u8; 32]);
        let noncanonical: PublicKey = serde_json::from_value(serde_json::json!({
            "kty": "OKP",
            "kid": "ak:device:01964137-0000-7000-8000-0000000000c1",
            "algorithm": "Ed25519",
            "key": multibase
        }))
        .unwrap();
        assert!(validate_new_device_pubkey(&noncanonical).is_err());
    }

    #[test]
    fn public_handoff_handlers_have_no_local_pairing_store_access() {
        let source = include_str!("device_pairing_open.rs");
        let production = source
            .split("#[cfg(test)]")
            .next()
            .expect("production source precedes tests");
        assert!(production.contains(".stage(state, &body, &idempotency_key)"));
        assert!(production.contains(".resolve(state, &body)"));
        assert!(production.contains(".status(state, &body)"));
        assert!(!production.contains(".device_pairings()"));
        assert!(!production.contains("DevicePairingState"));
        assert!(!production.contains("DevicePairingRecord"));
    }
}
