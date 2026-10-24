use std::collections::BTreeMap;
use std::sync::Arc;

use arkret_models_identity::{
    AuthenticatedServiceResolution, ServiceResolutionCarrier, VerifiedServiceRoute,
};
use arkret_wire::{
    BindingKind, DidCoreId, Hash, ServiceKind, ServiceOperationId, TrustDomainId,
    operation_bundles_for_service_kind,
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use coland_storage::{MonotonicRouteWrite, ServiceResolutionForkEvidence, ServiceRouteStore};

use crate::{ServiceError, ServiceResult};
#[derive(Clone, Debug)]
pub struct VerifiedRouteCandidate {
    pub evidence: AuthenticatedServiceResolution,
    pub description: VerifiedServiceDescribeMetadata,
}
#[derive(Clone, Debug)]
pub struct VerifiedServiceDescribeMetadata {
    pub service_id: DidCoreId,
    pub service_kind: String,
    pub service_resolution: arkret_models_identity::ResolutionCommitment,
    pub http_json_base_url: String,
    pub trust_domain: TrustDomainId,
    pub protocol_version: String,
    pub supported_operation_bundles: Vec<String>,
    pub supported_profiles: Vec<String>,
}
#[derive(Clone, Debug)]
pub struct ResolvedServiceRoute {
    pub authenticated_resolution: Option<AuthenticatedServiceResolution>,
    pub route: VerifiedServiceRoute,
    pub trust_domain: TrustDomainId,
    pub protocol_version: String,
    pub supported_operation_bundles: Vec<String>,
    pub supported_profiles: Vec<String>,
    pub describe_verified_at: DateTime<Utc>,
    pub describe_cache_expires_at: DateTime<Utc>,
}
impl ResolvedServiceRoute {
    pub fn is_routable_at(&self, now: DateTime<Utc>) -> bool {
        self.route.is_routable_at(now) && now < self.describe_cache_expires_at
    }
    #[must_use]
    pub const fn service_id(&self) -> &DidCoreId {
        self.route.service_id()
    }
    #[must_use]
    pub const fn did(&self) -> &arkret_wire::Did {
        self.route.did()
    }
    #[must_use]
    pub fn base_url(&self) -> &str {
        self.route.base_url()
    }
    #[must_use]
    pub fn method_history_head(&self) -> &str {
        self.route.method_history_head()
    }
    pub fn require_trust_domain(&self, expected: Option<&str>) -> ServiceResult<()> {
        if expected.is_some_and(|v| v != self.trust_domain.as_str()) {
            return Err(ServiceError::Conflict(
                "verified describe trust domain conflicts with binding".into(),
            ));
        }
        Ok(())
    }

    /// Require the exact generated capability bundles for a public Push
    /// Gateway registration handoff. A verified URL or DID is not sufficient:
    /// the same role-scoped Describe must advertise both notification ingest
    /// and durable registration handoff.
    pub fn require_push_gateway_registration_handoff(&self) -> ServiceResult<()> {
        if self.route.service_kind() != ServiceKind::PushGateway.as_str() {
            return Err(ServiceError::Conflict(
                "verified service route is not a Push Gateway".into(),
            ));
        }
        for operation_id in [
            ServiceOperationId::EdgePushCommandNotifyV1,
            ServiceOperationId::EdgePushCommandApplyRegistrationV1,
        ] {
            let required_bundle = operation_bundles_for_service_kind(ServiceKind::PushGateway)
                .find(|bundle| bundle.contains(operation_id, BindingKind::HttpJson))
                .ok_or_else(|| {
                    ServiceError::Internal(format!(
                        "generated Push Gateway registry omits {operation_id} HTTP binding"
                    ))
                })?;
            if !self
                .supported_operation_bundles
                .iter()
                .any(|actual| actual == required_bundle.operation_bundle_id)
            {
                return Err(ServiceError::Conflict(format!(
                    "verified Push Gateway Describe omits required bundle {}",
                    required_bundle.operation_bundle_id
                )));
            }
        }
        Ok(())
    }
}
#[async_trait]
pub trait ServiceRouteFetcher: Send + Sync {
    async fn fetch_carrier(
        &self,
        _carrier: &ServiceResolutionCarrier,
        _service_id: &DidCoreId,
        _service_kind: &str,
    ) -> ServiceResult<Option<VerifiedRouteCandidate>> {
        Ok(None)
    }
    async fn fetch_current(
        &self,
        service_id: &DidCoreId,
        service_kind: &str,
    ) -> ServiceResult<Option<VerifiedRouteCandidate>>;
}
pub struct ServiceRouteResolver {
    store: Arc<dyn ServiceRouteStore>,
    fetcher: Arc<dyn ServiceRouteFetcher>,
    resolved_routes: parking_lot::Mutex<BTreeMap<(String, String), ResolvedServiceRoute>>,
}
impl ServiceRouteResolver {
    pub fn new(store: Arc<dyn ServiceRouteStore>, fetcher: Arc<dyn ServiceRouteFetcher>) -> Self {
        Self {
            store,
            fetcher,
            resolved_routes: parking_lot::Mutex::new(BTreeMap::new()),
        }
    }
    pub async fn resolve_route(
        &self,
        service_id: &DidCoreId,
        service_kind: &str,
        now: DateTime<Utc>,
        force_refresh: bool,
    ) -> ServiceResult<ResolvedServiceRoute> {
        let key = (service_id.to_string(), service_kind.to_owned());
        if self.store.is_quarantined(service_id, service_kind).await? {
            return Err(ServiceError::Conflict(
                "service DID is fork-quarantined".into(),
            ));
        }
        let cached = if force_refresh {
            None
        } else {
            self.resolved_routes.lock().get(&key).cloned()
        };
        if let Some(route) = cached
            && route.is_routable_at(now)
            && self
                .store
                .route_cache(service_id, service_kind)
                .await?
                .is_some_and(|c| {
                    c.method_history_head() == route.method_history_head() && c.is_routable_at(now)
                })
        {
            return Ok(route);
        }
        self.resolve(service_id, service_kind, now, true).await?;
        self.resolved_routes
            .lock()
            .get(&key)
            .cloned()
            .ok_or_else(|| ServiceError::Internal("verified describe missing".into()))
    }
    pub async fn resolve(
        &self,
        service_id: &DidCoreId,
        service_kind: &str,
        now: DateTime<Utc>,
        force_refresh: bool,
    ) -> ServiceResult<VerifiedServiceRoute> {
        if self.store.is_quarantined(service_id, service_kind).await? {
            return Err(ServiceError::Conflict(
                "service DID is fork-quarantined".into(),
            ));
        }
        if !force_refresh
            && let Some(c) = self.store.route_cache(service_id, service_kind).await?
            && c.is_routable_at(now)
        {
            return Ok(c);
        }
        let candidate = self
            .fetcher
            .fetch_current(service_id, service_kind)
            .await?
            .ok_or_else(|| ServiceError::NotFound("verified service route unavailable".into()))?;
        self.accept(service_id, service_kind, candidate, now).await
    }
    pub async fn resolve_carrier(
        &self,
        carrier: &ServiceResolutionCarrier,
        service_id: &DidCoreId,
        service_kind: &str,
        now: DateTime<Utc>,
    ) -> ServiceResult<VerifiedServiceRoute> {
        let candidate = self
            .fetcher
            .fetch_carrier(carrier, service_id, service_kind)
            .await?
            .ok_or_else(|| ServiceError::NotFound("verified service carrier unavailable".into()))?;
        self.accept(service_id, service_kind, candidate, now).await
    }
    async fn accept(
        &self,
        service_id: &DidCoreId,
        service_kind: &str,
        candidate: VerifiedRouteCandidate,
        now: DateTime<Utc>,
    ) -> ServiceResult<VerifiedServiceRoute> {
        if self.store.is_quarantined(service_id, service_kind).await? {
            return Err(ServiceError::Conflict(
                "service DID is fork-quarantined".into(),
            ));
        }
        let p = candidate
            .evidence
            .projection()
            .map_err(|e| ServiceError::SchemaViolation(e.to_string()))?;
        let d = candidate.description;
        arkret_identity::test_material::enforce_formal_test_material_policy(
            None,
            Some(&p.did),
            None,
            Some(&d.trust_domain),
        )
        .map_err(|error| ServiceError::SchemaViolation(error.to_string()))?;
        if p.service_id != *service_id
            || p.service_kind != service_kind
            || d.service_id != *service_id
            || d.service_kind != service_kind
            || d.service_resolution.did != p.did
            || d.service_resolution.method_history_head != p.method_history_head
            || d.service_resolution.version_id != p.version_id
            || d.http_json_base_url != p.base_url
        {
            return Err(ServiceError::SchemaViolation(
                "describe disagrees with verified DID route".into(),
            ));
        }
        let entry = VerifiedServiceRoute::new(p, now);
        match self
            .store
            .publish_route_cache(candidate.evidence.clone(), entry.clone())
            .await?
        {
            MonotonicRouteWrite::Applied | MonotonicRouteWrite::Replay => {}
            MonotonicRouteWrite::Stale => {
                return Err(ServiceError::Conflict(
                    "service DID rollback or missing native history".into(),
                ));
            }
            MonotonicRouteWrite::Conflict { accepted_digest } => {
                self.store
                    .quarantine_fork(ServiceResolutionForkEvidence {
                        service_id: service_id.clone(),
                        service_kind: service_kind.to_owned(),
                        version_id: entry.version_id().to_owned(),
                        accepted_digest,
                        conflicting_digest: Hash::new(entry.method_history_head().to_owned())
                            .map_err(|e| ServiceError::Internal(e.to_string()))?,
                        evidence: serde_json::to_value(candidate.evidence)
                            .map_err(|e| ServiceError::Internal(e.to_string()))?,
                        quarantined_at: now,
                    })
                    .await?;
                return Err(ServiceError::Conflict("service DID fork".into()));
            }
        }
        self.resolved_routes.lock().insert(
            (service_id.to_string(), service_kind.to_owned()),
            ResolvedServiceRoute {
                authenticated_resolution: Some(candidate.evidence.clone()),
                supported_profiles: d.supported_profiles,
                route: entry.clone(),
                trust_domain: d.trust_domain,
                protocol_version: d.protocol_version,
                supported_operation_bundles: d.supported_operation_bundles,
                describe_verified_at: now,
                describe_cache_expires_at: entry.cache_expires_at,
            },
        );
        Ok(entry)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use arkret_models_identity::{
        AuthenticatedServiceResolution, DidBindingEvidenceKind, DidBindingEvidenceReceipt,
        DidDocument, ResolutionMethodEvidenceBoundary, ResolutionMethodHistoryEvidence,
        ServiceMethodState,
    };
    use async_trait::async_trait;
    use coland_storage::{PersistenceResult, ServiceRouteStoredKey};

    use super::*;

    #[derive(Default)]
    struct RecordingRouteStore {
        publish_writes: AtomicUsize,
        quarantine_writes: AtomicUsize,
    }

    #[async_trait]
    impl ServiceRouteStore for RecordingRouteStore {
        async fn list_stored_route_keys(
            &self,
            _after: Option<&ServiceRouteStoredKey>,
            _limit: usize,
        ) -> PersistenceResult<Vec<ServiceRouteStoredKey>> {
            Ok(Vec::new())
        }

        async fn quarantine_evidence(
            &self,
            _service_id: &DidCoreId,
            _service_kind: &str,
            _limit: usize,
        ) -> PersistenceResult<Vec<ServiceResolutionForkEvidence>> {
            Ok(Vec::new())
        }

        async fn method_state(
            &self,
            _service_id: &DidCoreId,
            _service_kind: &str,
        ) -> PersistenceResult<Option<ServiceMethodState>> {
            Ok(None)
        }

        async fn publish_route_cache(
            &self,
            _evidence: AuthenticatedServiceResolution,
            _route: VerifiedServiceRoute,
        ) -> PersistenceResult<MonotonicRouteWrite> {
            self.publish_writes.fetch_add(1, Ordering::SeqCst);
            Ok(MonotonicRouteWrite::Applied)
        }

        async fn quarantine_fork(
            &self,
            _evidence: ServiceResolutionForkEvidence,
        ) -> PersistenceResult<()> {
            self.quarantine_writes.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        async fn is_quarantined(
            &self,
            _service_id: &DidCoreId,
            _service_kind: &str,
        ) -> PersistenceResult<bool> {
            Ok(false)
        }

        async fn route_cache(
            &self,
            _service_id: &DidCoreId,
            _service_kind: &str,
        ) -> PersistenceResult<Option<VerifiedServiceRoute>> {
            Ok(None)
        }

        async fn evict_route_cache(
            &self,
            _service_id: &DidCoreId,
            _service_kind: &str,
        ) -> PersistenceResult<()> {
            Ok(())
        }
    }

    struct StaticFetcher(VerifiedRouteCandidate);

    #[async_trait]
    impl ServiceRouteFetcher for StaticFetcher {
        async fn fetch_current(
            &self,
            _service_id: &DidCoreId,
            _service_kind: &str,
        ) -> ServiceResult<Option<VerifiedRouteCandidate>> {
            Ok(Some(self.0.clone()))
        }
    }

    fn route_candidate(trust_domain: &str) -> (DidCoreId, VerifiedRouteCandidate) {
        let did = arkret_wire::Did::new("did:web:peer.production.example".to_owned()).unwrap();
        let service_id = arkret_wire::project_did_to_core_id(&did).unwrap();
        let base_url = "https://peer.production.example/";
        let document: DidDocument = serde_json::from_value(serde_json::json!({
            "id": did,
            "service": [{
                "id": format!("{did}#station"),
                "type": "ArkretService",
                "serviceKind": "station",
                "serviceEndpoint": base_url,
            }],
        }))
        .unwrap();
        let digest = arkret_identity::document_canonical_digest(&document).unwrap();
        let head = digest.to_string();
        let version = format!(
            "synthetic-jcs-sha256:{}",
            head.trim_start_matches("sha256:")
        );
        let evidence = AuthenticatedServiceResolution {
            service_id: service_id.clone(),
            service_kind: "station".to_owned(),
            normalized_did_document: document,
            method_history_evidence: ResolutionMethodHistoryEvidence::DidWebDocument {
                boundary: ResolutionMethodEvidenceBoundary {
                    from_method_history_head: head.clone(),
                    to_method_history_head: head.clone(),
                    from_version_id: version.clone(),
                    to_version_id: version.clone(),
                },
                evidence: DidBindingEvidenceReceipt {
                    kind: DidBindingEvidenceKind::AkDidBindingEvidenceV1,
                    method: "web".to_owned(),
                    document_digest: digest,
                    method_proofs: Vec::new(),
                },
            },
        };
        (
            service_id.clone(),
            VerifiedRouteCandidate {
                evidence,
                description: VerifiedServiceDescribeMetadata {
                    supported_profiles: Vec::new(),
                    service_id,
                    service_kind: "station".to_owned(),
                    service_resolution: arkret_models_identity::ResolutionCommitment {
                        did,
                        method_history_head: head,
                        version_id: version,
                    },
                    http_json_base_url: base_url.to_owned(),
                    trust_domain: TrustDomainId::new(trust_domain.to_owned()).unwrap(),
                    protocol_version: arkret_wire::PROTOCOL_VERSION.to_owned(),
                    supported_operation_bundles: vec![
                        arkret_wire::role_describe_bundle_descriptor(ServiceKind::Station)
                            .unwrap()
                            .operation_bundle_id
                            .to_owned(),
                    ],
                },
            },
        )
    }

    #[tokio::test]
    async fn reserved_trust_domain_is_rejected_before_durable_or_runtime_route_cache_write() {
        let (service_id, candidate) = route_candidate("ak:trust_domain:fixture.example");
        let store = Arc::new(RecordingRouteStore::default());
        let resolver = ServiceRouteResolver::new(store.clone(), Arc::new(StaticFetcher(candidate)));

        let error = resolver
            .resolve(&service_id, "station", Utc::now(), true)
            .await
            .expect_err("a formal route may not admit a reserved trust domain");

        assert!(error.to_string().contains("test_signing_material_denied"));
        assert_eq!(store.publish_writes.load(Ordering::SeqCst), 0);
        assert_eq!(store.quarantine_writes.load(Ordering::SeqCst), 0);
        assert!(resolver.resolved_routes.lock().is_empty());
    }

    fn push_bundle_id(operation_id: ServiceOperationId) -> String {
        operation_bundles_for_service_kind(ServiceKind::PushGateway)
            .find(|bundle| bundle.contains(operation_id, BindingKind::HttpJson))
            .expect("generated Push Gateway operation bundle")
            .operation_bundle_id
            .to_owned()
    }

    fn resolved_route_with_capabilities(
        service_kind: ServiceKind,
        supported_operation_bundles: Vec<String>,
    ) -> ResolvedServiceRoute {
        let (_, candidate) = route_candidate("ak:trust_domain:peer.production.example");
        let mut projection = candidate.evidence.projection().unwrap();
        projection.service_kind = service_kind.as_str().to_owned();
        let now = Utc::now();
        let route = VerifiedServiceRoute::new(projection, now);
        ResolvedServiceRoute {
            authenticated_resolution: None,
            supported_profiles: Vec::new(),
            describe_cache_expires_at: route.cache_expires_at,
            route,
            trust_domain: candidate.description.trust_domain,
            protocol_version: candidate.description.protocol_version,
            supported_operation_bundles,
            describe_verified_at: now,
        }
    }

    #[test]
    fn push_gateway_handoff_requires_both_generated_role_bundles() {
        let notify = push_bundle_id(ServiceOperationId::EdgePushCommandNotifyV1);
        let handoff = push_bundle_id(ServiceOperationId::EdgePushCommandApplyRegistrationV1);
        resolved_route_with_capabilities(
            ServiceKind::PushGateway,
            vec![notify.clone(), handoff.clone()],
        )
        .require_push_gateway_registration_handoff()
        .unwrap();

        for (missing, remaining) in [
            (notify.clone(), vec![handoff.clone()]),
            (handoff.clone(), vec![notify.clone()]),
        ] {
            let error = resolved_route_with_capabilities(ServiceKind::PushGateway, remaining)
                .require_push_gateway_registration_handoff()
                .expect_err("a missing Push Gateway bundle must fail closed");
            assert!(error.to_string().contains(&missing));
        }
    }

    #[test]
    fn push_gateway_handoff_rejects_a_verified_route_with_the_wrong_role() {
        let bundles = vec![
            push_bundle_id(ServiceOperationId::EdgePushCommandNotifyV1),
            push_bundle_id(ServiceOperationId::EdgePushCommandApplyRegistrationV1),
        ];
        let error = resolved_route_with_capabilities(ServiceKind::Station, bundles)
            .require_push_gateway_registration_handoff()
            .expect_err("a Station route cannot stand in for a Push Gateway");
        assert!(error.to_string().contains("not a Push Gateway"));
    }
}
