use std::sync::Arc;

use arkret_models_identity::ServiceResolutionCarrier;
use arkret_wire::{DidCoreId, ServiceKind};
use async_trait::async_trait;
use chrono::Utc;
use coland_services::identity::DidService;
use coland_services::service_route::{
    ServiceRouteFetcher, VerifiedRouteCandidate, VerifiedServiceDescribeMetadata,
};
use coland_services::{ServiceError, ServiceResult};
use coland_storage::ServiceRouteStore;
pub(crate) struct VerifiedBindingRouteFetcher {
    dids: DidService,
    route_store: Arc<dyn ServiceRouteStore>,
    transport: arkret_http_client::ServiceResolutionFetcher,
}
impl VerifiedBindingRouteFetcher {
    pub(crate) fn new(
        dids: DidService,
        route_store: Arc<dyn ServiceRouteStore>,
        development_mode: bool,
    ) -> Self {
        let egress = if development_mode {
            arkret_egress_policy::OutboundPolicy::local_development()
        } else {
            arkret_egress_policy::OutboundPolicy::public_https()
        };
        Self {
            dids,
            route_store,
            transport: arkret_http_client::ServiceResolutionFetcher::with_egress_policy(egress),
        }
    }
    async fn verify_carrier(
        &self,
        carrier: &ServiceResolutionCarrier,
        service_id: &DidCoreId,
        service_kind: &str,
    ) -> ServiceResult<VerifiedRouteCandidate> {
        let materialized = self
            .transport
            .materialize(carrier, service_id)
            .await
            .map_err(|e| ServiceError::SchemaViolation(e.to_string()))?;
        let evidence = materialized.authenticated_resolution().clone();
        let route = evidence
            .projection()
            .map_err(|e| ServiceError::SchemaViolation(e.to_string()))?;
        let current = self
            .dids
            .resolve_current_service_did(&route.did)
            .await
            .map_err(ServiceError::SchemaViolation)?;
        let route = arkret_identity::verify_current_service_resolution(
            &evidence,
            service_id,
            service_kind,
            &current,
            Utc::now(),
        )
        .map_err(|e| ServiceError::SchemaViolation(e.to_string()))?;
        let kind = ServiceKind::ALL
            .iter()
            .copied()
            .find(|k| k.as_str() == service_kind && k.valid_in("service_describe"))
            .ok_or_else(|| ServiceError::SchemaViolation("unsupported service kind".into()))?;
        let describe = self
            .transport
            .fetch_describe(&route.base_url, kind)
            .await
            .map_err(|e| ServiceError::SchemaViolation(e.to_string()))?;
        let description = validate_service_describe(&route, describe, kind)?;
        Ok(VerifiedRouteCandidate {
            evidence,
            description,
        })
    }
}
fn validate_service_describe(
    route: &arkret_models_identity::ServiceResolutionProjection,
    description: arkret_models_discovery::ServiceDescribe,
    expected_kind: ServiceKind,
) -> ServiceResult<VerifiedServiceDescribeMetadata> {
    if description.service_kind != expected_kind {
        return Err(ServiceError::SchemaViolation(
            "describe kind mismatch".into(),
        ));
    }
    description
        .validate_route_projection(route)
        .map_err(|e| ServiceError::SchemaViolation(e.to_string()))?;
    Ok(VerifiedServiceDescribeMetadata {
        service_id: description.service_id,
        service_kind: description.service_kind.as_str().to_owned(),
        service_resolution: description.service_resolution,
        http_json_base_url: route.base_url.clone(),
        trust_domain: description.trust_domain,
        protocol_version: description.protocol_version.to_string(),
        supported_operation_bundles: description.supported_operation_bundles,
    })
}

#[async_trait]
impl ServiceRouteFetcher for VerifiedBindingRouteFetcher {
    async fn fetch_carrier(
        &self,
        carrier: &ServiceResolutionCarrier,
        service_id: &DidCoreId,
        service_kind: &str,
    ) -> ServiceResult<Option<VerifiedRouteCandidate>> {
        self.verify_carrier(carrier, service_id, service_kind)
            .await
            .map(Some)
    }
    async fn fetch_current(
        &self,
        service_id: &DidCoreId,
        service_kind: &str,
    ) -> ServiceResult<Option<VerifiedRouteCandidate>> {
        let Some(accepted) = self
            .route_store
            .method_state(service_id, service_kind)
            .await?
        else {
            return Ok(None);
        };
        // The previous HTTP endpoint may already be offline. Discover the current
        // endpoint from the method resolver before fetching its public evidence.
        // This URL remains a hint until verify_carrier checks the complete material.
        let current = self
            .dids
            .resolve_current_service_did(&accepted.did)
            .await
            .map_err(ServiceError::SchemaViolation)?;
        if arkret_wire::project_did_to_core_id(&current.document.id)
            .map_err(|e| ServiceError::SchemaViolation(e.to_string()))?
            != *service_id
        {
            return Err(ServiceError::SchemaViolation(
                "current DID changed service identity".into(),
            ));
        }
        let services = current
            .document
            .raw_properties
            .get("service")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| {
                ServiceError::SchemaViolation("current DID omits service endpoints".into())
            })?;
        let entries: Vec<_> = services
            .iter()
            .filter(|e| e["type"] == "ArkretService" && e["serviceKind"] == service_kind)
            .collect();
        if entries.len() != 1 {
            return Err(ServiceError::SchemaViolation(
                "current DID service endpoint is ambiguous".into(),
            ));
        }
        let base = entries[0]["serviceEndpoint"].as_str().ok_or_else(|| {
            ServiceError::SchemaViolation("current DID service endpoint is not a URL".into())
        })?;
        let base = arkret_models_identity::service_identity::CanonicalServiceUrl::new(base)
            .map_err(|e| ServiceError::SchemaViolation(e.to_string()))?;
        base.require_https()
            .map_err(|e| ServiceError::SchemaViolation(e.to_string()))?;
        let resolution_url = format!(
            "{}{}",
            base,
            arkret_models_identity::canonical_service_resolution_path(service_id)
                .trim_start_matches('/')
        );
        self.verify_carrier(
            &ServiceResolutionCarrier::ResolutionUrl { resolution_url },
            service_id,
            service_kind,
        )
        .await
        .map(Some)
    }
}
