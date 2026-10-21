//! Embedded did:webvh crypto / derivation helpers.

use super::*;

pub(super) fn identity_trust_roots(state: &AppState) -> Vec<Value> {
    let mut trust_roots = vec![json!({
        "id": "coland.local_identity_store",
        "kind": "local_identity_store",
        "profile": arkret_wire::ProfileId::IDENTITY_REGISTRY_V1,
        "service_id": state.service_id(),
        "trust_domain": state.config().trust_domain,
        "proof_verification": {
            "controller_proof": "eddsa-jcs-2022",
            "webvh_log_chain": "required",
            "webvh_scid": "required",
            // Fail-closed today: coland cannot verify witness evidence, so a
            // log declaring a witness policy is always rejected with
            // WitnessQuorumNotMet (`webvh_validation::validate_witness_policy_for_log`).
            "webvh_witness_quorum": "unsupported"
        }
    })];
    if let Some(url) = state.config().external_webvh_provider_url.as_deref() {
        trust_roots.push(json!({
            "id": "external.webvh",
            "kind": "external",
            "adapter_version": arkret_models_identity::DID_WEBVH_V1_METHOD,
            "base_url": url,
            "expected_trust_domain": state.config().trust_domain
        }));
    }
    trust_roots
}

pub(in crate::routing::identity) fn require_embedded_webvh_registration_bearer(
    state: &AppState,
    req: &Request,
) -> Result<(), AppError> {
    let Some(expected) = state
        .config()
        .embedded_webvh_registration_bearer
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return Err(crate::app_error!(
            TemporarilyUnavailable,
            "embedded did:webvh registration requires COLAND_EMBEDDED_WEBVH_REGISTRATION_BEARER",
        ));
    };
    let Some(provided) = bearer_token(req)
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return Err(AppError::unauthenticated(
            "embedded did:webvh registration requires Authorization: Bearer <token>",
        ));
    };
    if sha256_hex(provided.as_bytes()) != sha256_hex(expected.as_bytes()) {
        return Err(AppError::unauthenticated(
            "invalid embedded did:webvh registration bearer",
        ));
    }
    Ok(())
}

pub(super) async fn embedded_webvh_record_for_request(
    state: &AppState,
    req: &mut Request,
    res: &mut Response,
) -> Option<WebvhDocumentRecord> {
    if !state.config().embedded_webvh_provider_enabled {
        render_error(
            res,
            StatusCode::NOT_FOUND,
            "not_found",
            "embedded did:webvh provider is disabled",
        );
        return None;
    }
    let Some(raw_local_id) = req.param::<String>("local_id") else {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "param_missing",
            "local_id is required",
        );
        return None;
    };
    let Some(local_id) = normalize_webvh_local_id(&raw_local_id) else {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "param_invalid",
            "invalid local_id",
        );
        return None;
    };
    let expected_log_url = format!(
        "{}/webvh/{local_id}/did.jsonl",
        state.config().public_base_url.trim_end_matches('/')
    );
    match state
        .dids()
        .embedded_document(&local_id, &expected_log_url)
        .await
    {
        Ok(Some(record)) => Some(record),
        Ok(None) => {
            render_error(
                res,
                StatusCode::NOT_FOUND,
                "not_found",
                "did document not found",
            );
            None
        }
        Err(error) => {
            tracing::error!(%error, "failed to read embedded webvh document");
            render_error(
                res,
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "failed to read did document",
            );
            None
        }
    }
}

pub(super) fn normalize_webvh_local_id(value: &str) -> Option<String> {
    let normalized = value.trim().trim_start_matches('@').to_ascii_lowercase();
    let valid = !normalized.is_empty()
        && normalized.len() <= 64
        && !normalized.contains("..")
        && normalized
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'));
    valid.then_some(normalized)
}
