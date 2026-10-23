use crate::state::AppState;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct FederationPeerTarget {
    pub(crate) url: String,
    pub(crate) service_id: arkret_wire::DidCoreId,
    pub(crate) trust_domain: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ResolvedFederationPeerTarget {
    pub(crate) base_url: String,
    pub(crate) trust_domain: String,
}

pub(crate) fn configured_peer_targets(state: &AppState) -> Vec<FederationPeerTarget> {
    use crate::config::FederationFanoutTopology;
    let settings = state.settings();
    let entries: Vec<String> = match settings.federation_fanout_topology {
        FederationFanoutTopology::Mesh => settings.federation_peers.clone(),
        FederationFanoutTopology::Hub => settings
            .federation_peers
            .first()
            .cloned()
            .into_iter()
            .collect(),
    };
    entries
        .into_iter()
        .filter_map(|entry| parse_peer_target(&entry))
        .filter(|peer| {
            let denied =
                crate::security::federation_peer_denied(&peer.url, peer.service_id.as_str());
            if denied {
                tracing::warn!(
                    peer_url = %peer.url,
                    peer_id = %peer.service_id,
                    "configured federation peer denied by deployment peer policy"
                );
                return false;
            }
            // `sovereign-deployment.md` §8 — a sovereign deployment MUST check
            // the target service_id's trust_domain against the local
            // federation_allowlist before the request, and MUST NOT rely on
            // the receiver to refuse. The denylist above cannot express this:
            // it fails open on anything it was not told about.
            if let Some(reason) = crate::security::federation_outbound_trust_domain_denial(
                peer.service_id.as_str(),
                peer.trust_domain.as_deref(),
            ) {
                tracing::warn!(
                    peer_url = %peer.url,
                    peer_id = %peer.service_id,
                    %reason,
                    "configured federation peer denied by sovereign outbound trust_domain policy"
                );
                return false;
            }
            true
        })
        .collect()
}

pub(crate) fn peer_url_for_service_id(state: &AppState, service_id: &str) -> Option<String> {
    configured_peer_targets(state)
        .into_iter()
        .find(|peer| peer.service_id.as_str() == service_id)
        .map(|peer| peer.url)
}

/// Resolve a service destination through the shared verified resolver.
pub(crate) async fn resolved_peer_base_url(
    state: &AppState,
    service_id: &str,
    service_kind: &str,
    force_refresh: bool,
) -> Result<String, String> {
    Ok(
        resolved_peer_target(state, service_id, service_kind, force_refresh)
            .await?
            .base_url,
    )
}

/// Resolve the exact routable URL and destination trust domain from the same
/// independently verified record→ServiceDescribe chain. A configured trust
/// domain, when present, is only an additional accepted-binding constraint and
/// must agree with the fetched description.
pub(crate) async fn resolved_peer_target(
    state: &AppState,
    service_id: &str,
    service_kind: &str,
    force_refresh: bool,
) -> Result<ResolvedFederationPeerTarget, String> {
    let route = resolved_peer_route(state, service_id, service_kind, force_refresh).await?;
    Ok(ResolvedFederationPeerTarget {
        base_url: route.base_url().trim_end_matches('/').to_owned(),
        trust_domain: route.trust_domain.to_string(),
    })
}

/// Resolve a core service id to the complete independently verified
/// record→ServiceDescribe result. Callers that sign protocol requests should
/// retain this value so the endpoint and trust domain come from one snapshot.
pub(crate) async fn resolved_peer_route(
    state: &AppState,
    service_id: &str,
    service_kind: &str,
    force_refresh: bool,
) -> Result<coland_services::service_route::ResolvedServiceRoute, String> {
    let core = arkret_wire::DidCoreId::new(service_id.to_owned())
        .map_err(|error| format!("federation destination is not a service core id: {error}"))?;
    let resolver = state.service_route_resolver().map_err(str::to_owned)?;
    let now = chrono::Utc::now();
    let route = match resolver
        .resolve_route(&core, service_kind, now, force_refresh)
        .await
    {
        Ok(route) => route,
        Err(initial_error) => {
            if !state
                .persistence()
                .stored_service_route_quarantine(&core, service_kind, 1)
                .await
                .map_err(|error| error.to_string())?
                .is_empty()
            {
                return Err(initial_error.to_string());
            }
            // An accepted DID's former host may be offline after relocation.
            // A newly configured locator is still only a candidate: the same
            // resolver verifies native history, current state, the durable
            // anti-rollback/quarantine floor and Describe before publishing it.
            let endpoint = peer_url_for_service_id(state, service_id)
                .ok_or_else(|| initial_error.to_string())?;
            let carrier = configured_peer_resolution_carrier(&endpoint, &core)?;
            if let Err(candidate_error) = resolver
                .resolve_carrier(&carrier, &core, service_kind, now)
                .await
            {
                return Err(match initial_error {
                    coland_services::ServiceError::NotFound(_) => candidate_error,
                    original => original,
                }
                .to_string());
            }
            resolver
                .resolve_route(&core, service_kind, now, false)
                .await
                .map_err(|error| error.to_string())?
        }
    };
    route
        .require_trust_domain(peer_trust_domain_for_service_id(state, service_id).as_deref())
        .map_err(|error| error.to_string())?;
    Ok(route)
}

fn configured_peer_resolution_carrier(
    endpoint: &str,
    service_id: &arkret_wire::DidCoreId,
) -> Result<arkret_models_identity::ServiceResolutionCarrier, String> {
    let base =
        arkret_models_identity::service_identity::CanonicalServiceUrl::canonicalize(endpoint)
            .map_err(|error| error.to_string())?;
    let carrier = arkret_models_identity::ServiceResolutionCarrier::ResolutionUrl {
        resolution_url: format!(
            "{}{}",
            base,
            arkret_models_identity::canonical_service_resolution_path(service_id)
                .trim_start_matches('/')
        ),
    };
    carrier
        .validate_shape(service_id)
        .map_err(|error| error.to_string())?;
    Ok(carrier)
}

pub(crate) fn peer_trust_domain_for_service_id(
    state: &AppState,
    service_id: &str,
) -> Option<String> {
    state
        .settings()
        .federation_peers
        .iter()
        .filter_map(|entry| parse_peer_target(entry))
        .find(|peer| peer.service_id.as_str() == service_id)
        .and_then(|peer| peer.trust_domain)
}

pub(super) fn parse_peer_target(entry: &str) -> Option<FederationPeerTarget> {
    let entry = entry.trim();
    if entry.is_empty() {
        return None;
    }
    let parts = entry.split('|').map(str::trim).collect::<Vec<_>>();
    if parts.iter().any(|part| part.is_empty()) || !(2..=3).contains(&parts.len()) {
        return None;
    }
    let url = parts
        .iter()
        .copied()
        .find(|part| part.starts_with("https://") || part.starts_with("http://"))?;
    let service_id = parts
        .iter()
        .copied()
        .find_map(|part| arkret_wire::DidCoreId::new(part.to_owned()).ok())?;
    let trust_domain = parts
        .iter()
        .copied()
        .find(|part| part.starts_with("ak:trust_domain:"));
    if parts.len() == 3 && trust_domain.is_none() {
        return None;
    }
    if let Some(trust_domain) = trust_domain {
        arkret_identifiers::TrustDomainId::new(trust_domain.to_owned()).ok()?;
    }
    Some(FederationPeerTarget {
        url: url.trim_end_matches('/').to_owned(),
        service_id,
        trust_domain: trust_domain.map(ToOwned::to_owned),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configured_candidate_pins_the_exact_target_without_becoming_a_verified_route() {
        let first = arkret_wire::DidCoreId::new("ak:did_core:web:first.example").unwrap();
        let second = arkret_wire::DidCoreId::new("ak:did_core:web:second.example").unwrap();
        let carrier =
            configured_peer_resolution_carrier("https://candidate.example/", &first).unwrap();
        let other =
            configured_peer_resolution_carrier("https://candidate.example/", &second).unwrap();
        assert_ne!(
            serde_json::to_value(&carrier).unwrap(),
            serde_json::to_value(&other).unwrap()
        );
        assert!(carrier.validate_shape(&first).is_ok());
        assert!(carrier.validate_shape(&second).is_err());
        assert!(
            configured_peer_resolution_carrier("https://user:password@candidate.example/", &first)
                .is_err()
        );
    }

    #[test]
    fn peer_target_preserves_verified_trust_domain_binding() {
        let target = parse_peer_target(
            "https://peer.example|ak:did_core:web:peer.example|ak:trust_domain:partner.example",
        )
        .expect("three-part peer target");
        assert_eq!(target.service_id.as_str(), "ak:did_core:web:peer.example");
        assert_eq!(
            target.trust_domain.as_deref(),
            Some("ak:trust_domain:partner.example")
        );
        assert!(
            parse_peer_target(
                "https://peer.example|ak:did_core:web:peer.example|not-a-trust-domain"
            )
            .is_none()
        );
        let core = parse_peer_target(
            "https://peer.example|ak:did_core:webvh:z6mkpeer|ak:trust_domain:partner.example",
        )
        .expect("core service target");
        assert_eq!(core.service_id.as_str(), "ak:did_core:webvh:z6mkpeer");
    }
}
