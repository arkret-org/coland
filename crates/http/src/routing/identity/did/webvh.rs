//! Embedded did:webvh crypto / derivation helpers.

use super::*;

#[derive(Clone, Debug)]
pub(super) struct EmbeddedWebvhLocation {
    pub(super) did: String,
    pub(super) scid: String,
    pub(super) document_url: String,
    pub(super) log_url: String,
}

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

pub(super) fn did_webvh_descriptor(state: &AppState) -> Value {
    let embedded_id = "coland.embedded";
    let external_id = "external.webvh";
    let embedded_enabled = state.config().embedded_webvh_provider_enabled;
    let embedded_registration_auth_configured = state
        .config()
        .embedded_webvh_registration_bearer
        .as_deref()
        .is_some_and(|value| !value.trim().is_empty());
    let embedded_authority = embedded_webvh_authority(&state.config().public_base_url);
    let external_enabled = state.config().external_webvh_provider_url.is_some();
    let default_provider_id = state
        .config()
        .default_webvh_provider_id
        .as_deref()
        .filter(|id| {
            (*id == embedded_id && embedded_enabled) || (*id == external_id && external_enabled)
        })
        .map(ToOwned::to_owned)
        .or_else(|| embedded_enabled.then(|| embedded_id.to_owned()))
        .or_else(|| external_enabled.then(|| external_id.to_owned()));

    let mut providers = Vec::new();
    if embedded_enabled {
        let (active, probe, document_url_template, log_url_template) = match &embedded_authority {
            Ok((_, https_authority)) => {
                let document_url_template = Some(format!(
                    "https://{https_authority}/webvh/{{local_id}}/did.json"
                ));
                let log_url_template = Some(format!(
                    "https://{https_authority}/webvh/{{local_id}}/did.jsonl"
                ));
                if embedded_registration_auth_configured {
                    (
                        true,
                        "ok".to_owned(),
                        document_url_template,
                        log_url_template,
                    )
                } else {
                    (
                        false,
                        "missing_registration_bearer".to_owned(),
                        document_url_template,
                        log_url_template,
                    )
                }
            }
            Err(message) => (false, message.clone(), None, None),
        };
        providers.push(json!({
            "id": embedded_id,
            "kind": "embedded",
            "label": "Coland embedded did:webvh",
            "method": "did:webvh",
            "adapter_version": arkret_models_identity::DID_WEBVH_V1_METHOD,
            "default": default_provider_id.as_deref() == Some(embedded_id),
            "active": active,
            // The embedded webvh provider is a coland *deployment* facility, so
            // its registration entrypoint intentionally lives on the product
            // face (`/_coland/...`), not the protocol face — webvh registration
            // is not a `ak.*` protocol operation (only resolution is). Flag it
            // as deployment-local so clients can distinguish the product-face
            // registration URL from the protocol-face `resolver_url` below.
            "provider_local": true,
            "registration_url": format!("{}/_coland/root/identity/webvh/register", state.config().public_base_url.trim_end_matches('/')),
            "resolver_url": format!("{}/_arkret/root/identity", state.config().public_base_url.trim_end_matches('/')),
            "document_url_template": document_url_template,
            "log_url_template": log_url_template,
            "registration_auth": {
                "required": true,
                "mode": "bearer",
                "header": "Authorization",
                "scheme": "Bearer",
                "configured": embedded_registration_auth_configured,
            },
            "health": {
                "active": active,
                "probe": probe,
            },
        }));
    }
    if let Some(url) = &state.config().external_webvh_provider_url {
        providers.push(json!({
            "id": external_id,
            "kind": "external",
            "label": "External did:webvh provider",
            "method": "did:webvh",
            "adapter_version": arkret_models_identity::DID_WEBVH_V1_METHOD,
            "default": default_provider_id.as_deref() == Some(external_id),
            "active": state.config().external_webvh_provider_active,
            "base_url": url,
            // STA-07-002 — advertise the canonical generic server-describe
            // endpoint (operation_id ak.server.read.describe.v1) the resolver
            // freshness probe targets. Provider-specific `<URL>/describe`
            // shapes are not probed.
            "describe_url": format!(
                "{}{}",
                url.trim_end_matches('/'),
                crate::state::did_resolver_chain::CANONICAL_DESCRIBE_PATH
            ),
            "freshness_probe": crate::state::did_resolver_chain::CANONICAL_DESCRIBE_PATH,
            "health": {
                "active": state.config().external_webvh_provider_active,
                "probe": if state.config().external_webvh_provider_active {
                    "ok"
                } else {
                    "probe_failed_at_boot"
                },
            },
        }));
    }

    let enabled = !providers.is_empty();
    let provider_count = providers.len();
    let default_missing = default_provider_id.is_none();
    json!({
        "method": "did:webvh",
        "adapter_version": arkret_models_identity::DID_WEBVH_V1_METHOD,
        "enabled": enabled,
        "default_provider_id": default_provider_id,
        "providers": providers,
        "selection": {
            "coauth_prompt": provider_count > 1,
            "required_when_default_missing": default_missing,
        },
    })
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
    match state.dids().embedded_document(&local_id).await {
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

pub(super) fn embedded_webvh_location_with_scid(
    method_authority: &str,
    https_authority: &str,
    local_id: &str,
    scid: &str,
) -> EmbeddedWebvhLocation {
    let path_url = format!("webvh/{local_id}");
    EmbeddedWebvhLocation {
        did: arkret_signatures::webvh::format_webvh_did(method_authority, scid, local_id),
        scid: scid.to_owned(),
        document_url: format!("https://{https_authority}/{path_url}/did.json"),
        log_url: format!("https://{https_authority}/{path_url}/did.jsonl"),
    }
}

pub(super) fn embedded_webvh_did(method_authority: &str, scid: &str, local_id: &str) -> String {
    arkret_signatures::webvh::format_webvh_did(method_authority, scid, local_id)
}

pub(super) fn embedded_webvh_authority(public_base_url: &str) -> Result<(String, String), String> {
    let parsed = reqwest::Url::parse(public_base_url)
        .map_err(|e| format!("COLAND_PUBLIC_BASE_URL is not a valid URL: {e}"))?;
    let host = parsed
        .host_str()
        .ok_or_else(|| "COLAND_PUBLIC_BASE_URL must include a host".to_owned())?;
    if !host.contains('.') {
        return Err("COLAND_PUBLIC_BASE_URL host must contain a dot for did:webvh".to_owned());
    }
    Ok(arkret_signatures::webvh::webvh_authority_pair(
        host,
        parsed.port(),
    ))
}

pub(super) fn embedded_webvh_document_value(
    did: &str,
    did_key_id: &str,
    did_public_key_multibase: &str,
    also_known_as: &[String],
    service_endpoint: &str,
) -> Value {
    // The service array order + entry shape MUST match the registering client's
    // document byte-for-byte (canonical JSON does not sort array elements), or
    // the SCID / entry hash / log proof recomputed here will not verify. coauth's
    // embedded_webvh provider (coauth services/coland_webvh.rs) emits the same
    // station service entry; mirror that exactly.
    let service = vec![json!({
        "id": format!("{did}#coland"),
        "type": "ArkretStation",
        "serviceEndpoint": service_endpoint,
    })];
    json!({
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": did,
        "verificationMethod": [{
            "id": did_key_id,
            "type": "Multikey",
            "controller": did,
            "publicKeyMultibase": did_public_key_multibase,
        }],
        "authentication": [did_key_id],
        "assertionMethod": [did_key_id],
        "alsoKnownAs": also_known_as,
        "service": service,
    })
}

pub(super) fn valid_multibase_key(value: &str) -> bool {
    value.starts_with('z') && value.len() >= 2
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

pub(super) fn normalize_webvh_key_fragment(value: &str) -> Option<String> {
    let normalized = value.trim().trim_start_matches('#').to_owned();
    let valid = !normalized.is_empty()
        && normalized.len() <= 64
        && normalized
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'));
    valid.then_some(normalized)
}
