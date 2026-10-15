//! Deployment trust roots for independently operated public Push Gateways.
//!
//! A user-supplied `push_gateway_url` is only a locator.  This registry is the
//! explicit onboarding boundary that turns its canonical origin into the one
//! Gateway DID and receipt assertion key the deployment has approved.  Route
//! discovery remains responsible for current DID history and role-scoped
//! Describe capabilities; [`TrustedPushGatewayRegistry::authorize_route`]
//! joins those two independently verified facts without weakening either one.

use std::collections::{BTreeMap, BTreeSet};

use arkret_wire::{Did, DidCoreId, DidUrl, WebOrigin};
use chrono::{DateTime, Utc};
use coland_services::service_route::ResolvedServiceRoute;
use ed25519_dalek::VerifyingKey;
use serde::Deserialize;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TrustedPushGatewayError {
    #[error("trusted Push Gateway registry is not valid JSON: {0}")]
    InvalidJson(String),
    #[error("trusted Push Gateway origin must use https: {0}")]
    InsecureOrigin(String),
    #[error("trusted Push Gateway DID cannot identify a service: {0}")]
    InvalidServiceDid(String),
    #[error("trusted Push Gateway receipt verification method is not controlled by its DID")]
    ReceiptMethodControllerMismatch,
    #[error("trusted Push Gateway receipt public key is not canonical Ed25519 multibase: {0}")]
    InvalidReceiptKey(String),
    #[error("trusted Push Gateway registry repeats canonical origin {0}")]
    DuplicateOrigin(String),
    #[error("trusted Push Gateway registry repeats service DID {0}")]
    DuplicateServiceDid(String),
    #[error("trusted Push Gateway registry repeats projected service id {0}")]
    DuplicateServiceId(String),
    #[error("trusted Push Gateway registry repeats receipt verification method {0}")]
    DuplicateReceiptMethod(String),
    #[error("trusted Push Gateway registry reuses a receipt Ed25519 key")]
    DuplicateReceiptKey,
    #[error("Push Gateway origin is not onboarded: {0}")]
    UnknownOrigin(String),
    #[error("verified Push Gateway route is stale")]
    StaleRoute,
    #[error("verified Push Gateway route does not match the onboarded service identity")]
    RouteIdentityMismatch,
    #[error("verified Push Gateway route does not match the onboarded canonical origin")]
    RouteOriginMismatch,
    #[error("verified Push Gateway route lacks its required role-scoped bundles: {0}")]
    MissingRoleCapability(String),
}

#[derive(Clone, Debug)]
pub struct TrustedPushGateway {
    canonical_origin: WebOrigin,
    service_did: Did,
    service_id: DidCoreId,
    receipt_verification_method: DidUrl,
    receipt_verifying_key: VerifyingKey,
}

impl TrustedPushGateway {
    #[must_use]
    pub const fn canonical_origin(&self) -> &WebOrigin {
        &self.canonical_origin
    }

    #[must_use]
    pub const fn service_did(&self) -> &Did {
        &self.service_did
    }

    #[must_use]
    pub const fn service_id(&self) -> &DidCoreId {
        &self.service_id
    }

    #[must_use]
    pub const fn receipt_verification_method(&self) -> &DidUrl {
        &self.receipt_verification_method
    }

    #[must_use]
    pub const fn receipt_verifying_key(&self) -> &VerifyingKey {
        &self.receipt_verifying_key
    }
}

/// Immutable deployment snapshot of explicitly onboarded public Gateways.
#[derive(Clone, Debug, Default)]
pub struct TrustedPushGatewayRegistry {
    by_origin: BTreeMap<WebOrigin, TrustedPushGateway>,
    by_service_id: BTreeMap<DidCoreId, WebOrigin>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfiguredGateway {
    canonical_origin: WebOrigin,
    service_did: Did,
    receipt_verification_method: DidUrl,
    receipt_public_key_multibase: String,
}

impl TrustedPushGatewayRegistry {
    /// Parse the complete registry from one closed JSON array.  The public key
    /// is intentionally configuration, not a secret; no bearer or private key
    /// is accepted by this shape.
    pub fn from_json(value: &str) -> Result<Self, TrustedPushGatewayError> {
        let configured: Vec<ConfiguredGateway> = serde_json::from_str(value)
            .map_err(|error| TrustedPushGatewayError::InvalidJson(error.to_string()))?;
        Self::from_configured(configured)
    }

    fn from_configured(
        configured: Vec<ConfiguredGateway>,
    ) -> Result<Self, TrustedPushGatewayError> {
        let mut by_origin = BTreeMap::new();
        let mut by_service_id = BTreeMap::new();
        let mut service_dids = BTreeSet::new();
        let mut receipt_methods = BTreeSet::new();
        let mut receipt_keys = BTreeSet::new();

        for configured in configured {
            if !configured.canonical_origin.as_str().starts_with("https://") {
                return Err(TrustedPushGatewayError::InsecureOrigin(
                    configured.canonical_origin.to_string(),
                ));
            }
            let service_id =
                arkret_wire::project_did_to_core_id(&configured.service_did).map_err(|_| {
                    TrustedPushGatewayError::InvalidServiceDid(configured.service_did.to_string())
                })?;
            let method_controller = arkret_identity::verification_method_did(
                configured.receipt_verification_method.as_str(),
            )
            .map_err(|_| TrustedPushGatewayError::ReceiptMethodControllerMismatch)?;
            if method_controller != configured.service_did {
                return Err(TrustedPushGatewayError::ReceiptMethodControllerMismatch);
            }
            let receipt_key_bytes = arkret_canonical::decode_ed25519_multibase(
                &configured.receipt_public_key_multibase,
            )
            .map_err(|error| TrustedPushGatewayError::InvalidReceiptKey(error.to_string()))?;
            let receipt_verifying_key = VerifyingKey::from_bytes(&receipt_key_bytes)
                .map_err(|error| TrustedPushGatewayError::InvalidReceiptKey(error.to_string()))?;

            if by_origin.contains_key(&configured.canonical_origin) {
                return Err(TrustedPushGatewayError::DuplicateOrigin(
                    configured.canonical_origin.to_string(),
                ));
            }
            if !service_dids.insert(configured.service_did.clone()) {
                return Err(TrustedPushGatewayError::DuplicateServiceDid(
                    configured.service_did.to_string(),
                ));
            }
            if by_service_id
                .insert(service_id.clone(), configured.canonical_origin.clone())
                .is_some()
            {
                return Err(TrustedPushGatewayError::DuplicateServiceId(
                    service_id.to_string(),
                ));
            }
            if !receipt_methods.insert(configured.receipt_verification_method.clone()) {
                return Err(TrustedPushGatewayError::DuplicateReceiptMethod(
                    configured.receipt_verification_method.to_string(),
                ));
            }
            if !receipt_keys.insert(receipt_verifying_key.to_bytes()) {
                return Err(TrustedPushGatewayError::DuplicateReceiptKey);
            }

            by_origin.insert(
                configured.canonical_origin.clone(),
                TrustedPushGateway {
                    canonical_origin: configured.canonical_origin,
                    service_did: configured.service_did,
                    service_id,
                    receipt_verification_method: configured.receipt_verification_method,
                    receipt_verifying_key,
                },
            );
        }

        Ok(Self {
            by_origin,
            by_service_id,
        })
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_origin.is_empty()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.by_origin.len()
    }

    #[must_use]
    pub fn get(&self, origin: &WebOrigin) -> Option<&TrustedPushGateway> {
        self.by_origin.get(origin)
    }

    #[must_use]
    pub fn get_by_service_id(&self, service_id: &DidCoreId) -> Option<&TrustedPushGateway> {
        self.by_service_id
            .get(service_id)
            .and_then(|origin| self.by_origin.get(origin))
    }

    /// Bind a current resolver result to the static onboarding trust root.
    /// This is intentionally an adapter, not another resolver: the route must
    /// already have passed DID-history and Describe verification.
    pub fn authorize_route<'a>(
        &'a self,
        origin: &WebOrigin,
        route: &ResolvedServiceRoute,
        now: DateTime<Utc>,
    ) -> Result<&'a TrustedPushGateway, TrustedPushGatewayError> {
        let gateway = self
            .get(origin)
            .ok_or_else(|| TrustedPushGatewayError::UnknownOrigin(origin.to_string()))?;
        if !route.is_routable_at(now) {
            return Err(TrustedPushGatewayError::StaleRoute);
        }
        if route.service_id() != gateway.service_id() || route.did() != gateway.service_did() {
            return Err(TrustedPushGatewayError::RouteIdentityMismatch);
        }
        let route_url = url::Url::parse(route.base_url())
            .map_err(|_| TrustedPushGatewayError::RouteOriginMismatch)?;
        let route_origin = WebOrigin::new(route_url.origin().ascii_serialization())
            .map_err(|_| TrustedPushGatewayError::RouteOriginMismatch)?;
        if &route_origin != origin {
            return Err(TrustedPushGatewayError::RouteOriginMismatch);
        }
        route
            .require_push_gateway_registration_handoff()
            .map_err(|error| TrustedPushGatewayError::MissingRoleCapability(error.to_string()))?;
        Ok(gateway)
    }
}

#[cfg(test)]
mod tests {
    use arkret_models_identity::{ServiceResolutionProjection, VerifiedServiceRoute};
    use arkret_wire::TrustDomainId;

    use super::*;

    const ORIGIN: &str = "https://push.example";
    const DID: &str = "did:web:push.example";

    fn public_key_multibase(seed: u8) -> String {
        let key = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]).verifying_key();
        let mut multicodec = vec![0xed, 0x01];
        multicodec.extend_from_slice(key.as_bytes());
        format!("z{}", bs58::encode(multicodec).into_string())
    }

    fn registry_json(entries: serde_json::Value) -> String {
        serde_json::to_string(&entries).unwrap()
    }

    fn entry(origin: &str, did: &str, method: &str, seed: u8) -> serde_json::Value {
        serde_json::json!({
            "canonical_origin": origin,
            "service_did": did,
            "receipt_verification_method": method,
            "receipt_public_key_multibase": public_key_multibase(seed),
        })
    }

    fn resolved_route(now: DateTime<Utc>) -> ResolvedServiceRoute {
        let did = Did::new(DID).unwrap();
        let projection = ServiceResolutionProjection {
            service_id: arkret_wire::project_did_to_core_id(&did).unwrap(),
            service_kind: arkret_wire::ServiceKind::PushGateway.as_str().to_owned(),
            did,
            method_history_head: format!("sha256:{}", "1".repeat(64)),
            version_id: "1-fixture".to_owned(),
            resolution_event_ref: format!("did-web-document-sha256:{}", "1".repeat(64)),
            base_url: format!("{ORIGIN}/"),
        };
        let route = VerifiedServiceRoute::new(projection, now);
        ResolvedServiceRoute {
            authenticated_resolution: None,
            supported_profiles: Vec::new(),
            route: route.clone(),
            trust_domain: TrustDomainId::new("ak:trust_domain:push.example").unwrap(),
            protocol_version: "1".to_owned(),
            supported_operation_bundles: vec![
                "ak.operation_bundle.push_gateway.http_notify.v1".to_owned(),
                "ak.operation_bundle.push_gateway.registration_handoff.v1".to_owned(),
            ],
            describe_verified_at: now,
            describe_cache_expires_at: route.cache_expires_at,
        }
    }

    #[test]
    fn resolves_exact_origin_to_did_and_receipt_key_then_binds_verified_route() {
        let registry =
            TrustedPushGatewayRegistry::from_json(&registry_json(serde_json::json!([entry(
                ORIGIN,
                DID,
                &format!("{DID}#receipt"),
                7
            )])))
            .unwrap();
        let origin = WebOrigin::new(ORIGIN).unwrap();
        let gateway = registry.get(&origin).unwrap();
        assert_eq!(gateway.service_did().as_str(), DID);
        assert_eq!(
            registry
                .get_by_service_id(gateway.service_id())
                .unwrap()
                .canonical_origin(),
            &origin
        );
        assert_eq!(
            gateway.receipt_verification_method().as_str(),
            format!("{DID}#receipt")
        );
        assert_eq!(
            gateway.receipt_verifying_key(),
            &ed25519_dalek::SigningKey::from_bytes(&[7; 32]).verifying_key()
        );

        let now = Utc::now();
        assert!(
            registry
                .authorize_route(&origin, &resolved_route(now), now)
                .is_ok()
        );
    }

    #[test]
    fn startup_rejects_noncanonical_or_insecure_origins_and_unbound_keys() {
        for invalid in [
            entry("https://push.example/", DID, &format!("{DID}#receipt"), 1),
            entry("http://push.example", DID, &format!("{DID}#receipt"), 1),
            entry(ORIGIN, DID, "did:web:other.example#receipt", 1),
            serde_json::json!({
                "canonical_origin": ORIGIN,
                "service_did": DID,
                "receipt_verification_method": format!("{DID}#receipt"),
                "receipt_public_key_multibase": "zbad",
            }),
        ] {
            assert!(
                TrustedPushGatewayRegistry::from_json(&registry_json(serde_json::json!([invalid])))
                    .is_err()
            );
        }
    }

    #[test]
    fn startup_rejects_duplicate_origin_did_method_or_key() {
        let base = entry(ORIGIN, DID, &format!("{DID}#receipt"), 1);
        let conflicts = [
            entry(
                ORIGIN,
                "did:web:push-2.example",
                "did:web:push-2.example#receipt",
                2,
            ),
            entry(
                "https://push-2.example",
                DID,
                &format!("{DID}#receipt-2"),
                2,
            ),
            entry("https://push-2.example", DID, &format!("{DID}#receipt"), 2),
            entry(
                "https://push-2.example",
                "did:web:push-2.example",
                "did:web:push-2.example#receipt",
                1,
            ),
        ];
        for conflict in conflicts {
            assert!(
                TrustedPushGatewayRegistry::from_json(&registry_json(serde_json::json!([
                    base.clone(),
                    conflict
                ])))
                .is_err()
            );
        }
    }

    #[test]
    fn reverse_lookup_keeps_each_gateway_on_its_unique_canonical_origin() {
        let registry = TrustedPushGatewayRegistry::from_json(&registry_json(serde_json::json!([
            entry(ORIGIN, DID, &format!("{DID}#receipt"), 7),
            entry(
                "https://push-2.example",
                "did:web:push-2.example",
                "did:web:push-2.example#receipt",
                8
            )
        ])))
        .unwrap();
        for (did, expected_origin) in [
            (DID, ORIGIN),
            ("did:web:push-2.example", "https://push-2.example"),
        ] {
            let service_id = arkret_wire::project_did_to_core_id(&Did::new(did).unwrap()).unwrap();
            assert_eq!(
                registry
                    .get_by_service_id(&service_id)
                    .unwrap()
                    .canonical_origin()
                    .as_str(),
                expected_origin
            );
        }
        assert!(
            registry
                .get_by_service_id(&DidCoreId::new("ak:did_core:web:unknown.example").unwrap())
                .is_none()
        );
    }

    #[test]
    fn verified_route_still_requires_exact_identity_origin_and_bundles() {
        let registry =
            TrustedPushGatewayRegistry::from_json(&registry_json(serde_json::json!([entry(
                ORIGIN,
                DID,
                &format!("{DID}#receipt"),
                7
            )])))
            .unwrap();
        let origin = WebOrigin::new(ORIGIN).unwrap();
        let now = Utc::now();

        let mut missing_bundle = resolved_route(now);
        missing_bundle.supported_operation_bundles.pop();
        assert!(matches!(
            registry.authorize_route(&origin, &missing_bundle, now),
            Err(TrustedPushGatewayError::MissingRoleCapability(_))
        ));

        let mut wrong_origin = resolved_route(now);
        wrong_origin.route.projection.base_url = "https://other.example/".to_owned();
        assert!(matches!(
            registry.authorize_route(&origin, &wrong_origin, now),
            Err(TrustedPushGatewayError::RouteOriginMismatch)
        ));

        let mut wrong_did = resolved_route(now);
        let did = Did::new("did:web:other.example").unwrap();
        wrong_did.route.projection.service_id = arkret_wire::project_did_to_core_id(&did).unwrap();
        wrong_did.route.projection.did = did;
        assert!(matches!(
            registry.authorize_route(&origin, &wrong_did, now),
            Err(TrustedPushGatewayError::RouteIdentityMismatch)
        ));
    }
}
