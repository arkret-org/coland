//! Resolve an accepted assignment without promoting a locator to authority.

use arkret_models_collaboration::events_payloads::RealmMediaServiceValue;
use arkret_models_identity::{
    MediaServiceBindingOutcome, MediaServiceBindingRequestBody, ServiceResolutionCarrier,
    ServiceSigningKey,
};
use arkret_wire::{AccountId, BindingKind, ServiceKind, ServiceOperationId};
use coland_storage::MediaServiceAnchorRead;

use super::AppState;

pub(super) async fn resolve(
    state: &AppState,
    account: &AccountId,
    request: &MediaServiceBindingRequestBody,
    cut: &MediaServiceAnchorRead,
) -> Result<MediaServiceBindingOutcome, String> {
    let MediaServiceAnchorRead::Anchored { value, .. } = cut else {
        return Err("the current media assignment is unavailable".into());
    };
    let first = value
        .foci
        .first()
        .ok_or("the media assignment has no focus")?;
    // The accepted descriptor supplies a locator only. Native DID authority,
    // the durable anti-rollback floor and Describe establish the route.
    let candidate = url::Url::parse(&first.token_endpoint).map_err(|e| e.to_string())?;
    let candidate_base = format!("{}/", candidate.origin().ascii_serialization());
    let carrier = ServiceResolutionCarrier::ResolutionUrl {
        resolution_url: format!(
            "{}{}",
            candidate_base,
            arkret_models_identity::canonical_service_resolution_path(&value.service_id)
                .trim_start_matches('/')
        ),
    };
    let policy = if state.config().development_mode {
        arkret_egress_policy::OutboundPolicy::local_development()
    } else {
        arkret_egress_policy::OutboundPolicy::public_https()
    };
    let transport = arkret_http_client::ServiceResolutionFetcher::with_egress_policy(policy);
    let material = transport
        .materialize(&carrier, &value.service_id)
        .await
        .map_err(|e| e.to_string())?;
    let evidence = material.authenticated_resolution();
    let kind = match evidence.service_kind.as_str() {
        "station" => ServiceKind::Station,
        "media_service" if ServiceKind::MediaService.valid_in("service_registration_key") => {
            ServiceKind::MediaService
        }
        _ => return Err("the assigned service does not have a media issuer role".into()),
    };
    let now = chrono::Utc::now();
    let resolver = state.service_route_resolver().map_err(str::to_owned)?;
    let route = resolver
        .resolve_carrier(&carrier, &value.service_id, kind.as_str(), now)
        .await
        .map_err(|e| e.to_string())?;
    let resolved = resolver
        .resolve_route(&value.service_id, kind.as_str(), now, false)
        .await
        .map_err(|e| e.to_string())?;
    // Bind the document used for signing keys to the independently verified
    // current route; a concurrent key rotation cannot mix two method states.
    if evidence.projection().map_err(|e| e.to_string())? != route.projection
        || resolved.route.projection != route.projection
    {
        return Err("media method state changed during resolution".into());
    }
    let description = transport
        .fetch_describe(route.base_url(), kind)
        .await
        .map_err(|e| e.to_string())?;
    description
        .validate_route_projection(&route.projection)
        .map_err(|e| e.to_string())?;
    if description.service_kind != kind
        || !description
            .supported_profiles
            .iter()
            .any(|p| p == "ak.profile.media_service_binding.v1")
    {
        return Err("the assigned service does not advertise the media binding profile".into());
    }
    use arkret_models_collaboration::objects::media::MediaBackendKind;
    for focus in &value.foci {
        let backend = match focus.focus_kind {
            MediaBackendKind::Livekit => "livekit",
            MediaBackendKind::Mediasoup => "mediasoup",
            MediaBackendKind::Janus => "janus",
            MediaBackendKind::ArkretNative => "arkret_native",
            MediaBackendKind::MoqRelay => {
                return Err("the reserved MoQ backend is not active".into());
            }
        };
        let profile = format!("ak.profile.media_service_binding.{backend}.v1");
        if !description.supported_profiles.contains(&profile) {
            return Err(
                "the assigned service does not advertise the selected backend profile".into(),
            );
        }
    }
    let operation = ServiceOperationId::SelfCallMediaExchangeIssueTokenV1;
    if !arkret_wire::operation_bundles_for_service_kind(kind).any(|bundle| {
        bundle.contains(operation, BindingKind::HttpJson)
            && description
                .supported_operation_bundles
                .iter()
                .any(|id| id == bundle.operation_bundle_id)
    }) {
        return Err("the assigned issuer does not advertise the token HTTP operation".into());
    }
    check_origins(value, route.base_url())?;
    let document = &evidence.normalized_did_document;
    let normalized =
        arkret_models_identity::normalized_did_document(document).map_err(|e| e.to_string())?;
    let assertions = normalized["assertion_methods"]
        .as_array()
        .ok_or("media issuer has no assertion methods")?;
    let mut signing_keys = Vec::new();
    for assertion in assertions {
        let method = assertion
            .get("verification_method")
            .and_then(serde_json::Value::as_str)
            .ok_or("invalid normalized media assertion method")?;
        let method = if method.starts_with('#') {
            format!("{}{method}", document.id)
        } else {
            method.to_owned()
        };
        // Non-Ed25519 methods are not keys for the registered media signatures.
        if let Ok(key) =
            arkret_identity::jws::resolve_ed25519_pubkey_from_document(document, &method)
        {
            let key = ServiceSigningKey {
                verification_method: arkret_wire::DidUrl::new(method).map_err(|e| e.to_string())?,
                public_key_b64u: arkret_canonical::base64url_encode(key.as_bytes()),
            };
            key.validate().map_err(|e| e.to_string())?;
            if key.controller().map_err(|e| e.to_string())? != *route.did() {
                return Err("media assertion method is controlled by a different DID".into());
            }
            signing_keys.push(key);
        }
    }
    let after = state
        .authority_commits()
        .media_service_anchor_for_account(&request.realm_id, account, &state.service_core_id())
        .await
        .map_err(|e| e.to_string())?;
    if &after != cut {
        return Err("the accepted media authorization cut changed".into());
    }
    let observed_at =
        chrono::DateTime::from_timestamp_millis(chrono::Utc::now().timestamp_millis())
            .ok_or("invalid current timestamp")?;
    let expires_at = std::cmp::min(
        observed_at + chrono::Duration::seconds(300),
        std::cmp::min(route.cache_expires_at, resolved.describe_cache_expires_at),
    );
    let outcome = MediaServiceBindingOutcome {
        request_id: request.request_id.clone(),
        realm_id: request.realm_id.clone(),
        route: route.projection,
        signing_keys,
        observed_at,
        expires_at,
    };
    outcome
        .validate_for_request(request, &value.service_id)
        .map_err(|e| e.to_string())?;
    Ok(outcome)
}

fn check_origins(value: &RealmMediaServiceValue, base: &str) -> Result<(), String> {
    let base = url::Url::parse(base).map_err(|e| e.to_string())?;
    for endpoint in value
        .ice_config_endpoint
        .iter()
        .map(String::as_str)
        .chain(value.foci.iter().map(|focus| focus.token_endpoint.as_str()))
    {
        let endpoint = url::Url::parse(endpoint).map_err(|e| e.to_string())?;
        if endpoint.origin() != base.origin()
            || !endpoint.username().is_empty()
            || endpoint.password().is_some()
        {
            return Err("a credential endpoint is outside the verified issuer origin".into());
        }
    }
    Ok(())
}
