//! One authenticated issuer boundary for own-Station results and accepted roster joins.
use arkret_models_collaboration::events_payloads::RealmMediaServiceValue;
use arkret_models_identity::{
    AuthenticatedServiceResolution, ServiceResolutionProjection, ServiceSigningKey,
};
use arkret_wire::ServiceOperationId;
use coland_services::{ServiceError, ServiceResult};

use crate::state::AppState;

pub(crate) async fn resolve_issuer(
    state: &AppState,
    value: &RealmMediaServiceValue,
) -> ServiceResult<(
    ServiceResolutionProjection,
    Vec<ServiceSigningKey>,
    AuthenticatedServiceResolution,
)> {
    let unavailable =
        |detail: &str| ServiceError::Conflict(format!("temporarily_unavailable: {detail}"));
    let (route, description_profiles, bundles, evidence) =
        if value.service_id == state.service_core_id() {
            let evidence =
                super::system::service_resolution::current_authenticated_service_resolution(state)
                    .await
                    .map_err(|e| unavailable(&e.message))?;
            let route = evidence
                .projection()
                .map_err(|e| unavailable(&e.to_string()))?;
            let describe = super::system::describe::build_server_description(state);
            describe
                .validate_route_projection(&route)
                .map_err(|e| unavailable(&e.to_string()))?;
            (
                route,
                describe.supported_profiles,
                describe.supported_operation_bundles,
                evidence,
            )
        } else {
            let route = match super::federation::resolved_peer_route(
                state,
                value.service_id.as_str(),
                "station",
                true,
            )
            .await
            {
                Ok(route) => route,
                Err(station_error) => super::federation::resolved_peer_route(
                    state,
                    value.service_id.as_str(),
                    "media_service",
                    true,
                )
                .await
                .map_err(|media_error| {
                    unavailable(&format!(
                        "station issuer: {station_error}; media issuer: {media_error}"
                    ))
                })?,
            };
            let evidence = route
                .authenticated_resolution
                .as_ref()
                .ok_or_else(|| unavailable("verified issuer method evidence is unavailable"))?
                .clone();
            (
                route.route.projection,
                route.supported_profiles,
                route.supported_operation_bundles,
                evidence,
            )
        };
    if !description_profiles
        .iter()
        .any(|p| p == "ak.profile.media_service_binding.v1")
    {
        return Err(unavailable(
            "issuer does not advertise the media binding profile",
        ));
    }
    let role = arkret_wire::ServiceKind::ALL
        .iter()
        .copied()
        .find(|kind| kind.as_str() == route.service_kind)
        .ok_or_else(|| unavailable("issuer role is not registered"))?;
    let bundle = arkret_wire::operation_bundles_for_service_kind(role)
        .find(|b| {
            b.contains(
                ServiceOperationId::SelfCallMediaExchangeIssueTokenV1,
                arkret_wire::BindingKind::HttpJson,
            )
        })
        .ok_or_else(|| unavailable("issuer role has no token HTTP bundle"))?;
    if !bundles.iter().any(|b| b == bundle.operation_bundle_id) {
        return Err(unavailable(
            "issuer Describe lacks the registered token HTTP bundle",
        ));
    }
    let base =
        url::Url::parse(&route.base_url).map_err(|_| unavailable("issuer route is invalid"))?;
    let credential_origin = |endpoint: &str| -> bool {
        base.join(endpoint).is_ok_and(|endpoint| {
            endpoint.origin() == base.origin()
                && endpoint.username().is_empty()
                && endpoint.password().is_none()
        })
    };
    for focus in &value.foci {
        let backend =
            serde_json::to_value(focus.focus_kind).map_err(|e| unavailable(&e.to_string()))?;
        let profile = format!(
            "ak.profile.media_service_binding.{}.v1",
            backend
                .as_str()
                .ok_or_else(|| unavailable("backend is not a registered kind"))?
        );
        if !description_profiles.contains(&profile) || !credential_origin(&focus.token_endpoint) {
            return Err(unavailable(
                "focus backend or credential origin does not match the verified issuer",
            ));
        }
    }
    if value
        .ice_config_endpoint
        .as_ref()
        .is_some_and(|endpoint| !credential_origin(endpoint))
    {
        return Err(unavailable(
            "ICE credential origin differs from the verified issuer",
        ));
    }
    let document = &evidence.normalized_did_document;
    let mut signing_keys = Vec::new();
    for method in document.verification_methods.keys() {
        let method = arkret_wire::DidUrl::new(method.clone()).map_err(&unavailable)?;
        if arkret_identity::validate_verification_method_relationship(
            document,
            &method,
            &document.id,
            arkret_identity::DidVerificationRelationship::AssertionMethod,
        )
        .is_err()
        {
            continue;
        }
        let key = arkret_identity::resolve_verification_method_key_from_document(
            document,
            method.as_str(),
        )
        .map_err(|e| unavailable(&e.to_string()))?;
        let Ok(bytes) = key.public_key.ed25519_bytes() else {
            continue;
        };
        signing_keys.push(ServiceSigningKey {
            verification_method: method,
            public_key_b64u: arkret_canonical::base64url_encode(bytes),
        });
    }
    signing_keys.sort_by(|a, b| a.verification_method.cmp(&b.verification_method));
    if signing_keys.is_empty() || signing_keys.len() > 16 {
        return Err(unavailable(
            "issuer current assertion key set is outside the closed bound",
        ));
    }
    Ok((route, signing_keys, evidence))
}
