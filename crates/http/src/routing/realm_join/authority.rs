use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use arkret_identity::{
    RealmAuthorityFreshness, RealmAuthorityKeyMap, VerifiedRealmAuthority,
    converge_verified_realm_authorities, verify_realm_authority_bundle,
};
use arkret_models_collaboration::governance::realm_join_intake::{
    RealmJoinCandidate, RealmJoinTarget, validate_authority_locator_hints,
};
use arkret_signatures::PublicKeyMaterial;
use arkret_wire::{
    Base64UrlString, Did, DidUrl, RealmAuthorityBundle, RealmAuthorityBundleRequestBody, RealmId,
    RequestId,
};
use chrono::{DateTime, Utc};

use super::{AppError, AppState, invalid_request, local_authority_bundle, unavailable};

const MAX_BUNDLE_BYTES: usize = 8 * 1024 * 1024;

async fn method_key(state: &AppState, method: &DidUrl) -> Result<PublicKeyMaterial, AppError> {
    let did_text = method.as_str().split('#').next().unwrap_or_default();
    let did = Did::new(did_text.to_owned()).map_err(unavailable)?;
    let document = state.dids().resolve_did(&did).await.map_err(unavailable)?;
    let multibase = document
        .verification_methods
        .get(method.as_str())
        .ok_or_else(|| unavailable("authority signature method is absent from resolved DID"))?;
    Ok(PublicKeyMaterial::Ed25519Multibase {
        value: multibase.clone(),
    })
}

async fn historical_method_key(
    state: &AppState,
    method: &DidUrl,
    signed_at: DateTime<Utc>,
    bundle: &RealmAuthorityBundle,
) -> Result<PublicKeyMaterial, AppError> {
    let did_text = method.as_str().split('#').next().unwrap_or_default();
    let did = Did::new(did_text.to_owned()).map_err(unavailable)?;
    if did.method() == "key" {
        return method_key(state, method).await;
    }
    if did.method() != "webvh" {
        return Err(unavailable(
            "mutable DID method has no authenticated historical authority key",
        ));
    }
    let service = arkret_wire::project_did_to_core_id(&did).map_err(unavailable)?;
    let document: arkret_identity::DidDocument = if service == bundle.current_service_id {
        // The nonce-bound bundle already carries complete portable native
        // evidence. Reverify it and select the original method at signed_at;
        // an old DID URL must not become a new network dependency after moving.
        let resolution: arkret_models_identity::AuthenticatedServiceResolution =
            serde_json::from_value(bundle.current_route_record.clone()).map_err(unavailable)?;
        arkret_identity::authenticated_service_document_at(&resolution, &service, signed_at)
            .map_err(unavailable)?
    } else {
        // Other historical governors keep their independent native verifier.
        let resolver = crate::state::did_resolver_chain::build_coland_did_resolver(state.config());
        let history = resolver
            .fetch_verified_webvh_history(&did)
            .await
            .map_err(unavailable)?;
        let point = arkret_signatures::webvh::validate_webvh_history_at(
            &did,
            &history.raw_entries,
            signed_at,
        )
        .map_err(unavailable)?;
        serde_json::from_value(point.document).map_err(unavailable)?
    };
    if document.id != did {
        return Err(unavailable("historical authority DID document id mismatch"));
    }
    arkret_identity::validate_verification_method_relationship(
        &document,
        method,
        &did,
        arkret_identity::DidVerificationRelationship::AssertionMethod,
    )
    .map_err(unavailable)?;
    let multibase = document
        .verification_methods
        .get(method.as_str())
        .ok_or_else(|| unavailable("historical authority signature method is absent"))?;
    Ok(PublicKeyMaterial::Ed25519Multibase {
        value: multibase.clone(),
    })
}

pub(crate) async fn insert_historical_method_key(
    state: &AppState,
    keys: &mut RealmAuthorityKeyMap,
    method: &DidUrl,
    signed_at: DateTime<Utc>,
    bundle: &RealmAuthorityBundle,
) -> Result<(), AppError> {
    keys.insert_at(
        method,
        signed_at,
        historical_method_key(state, method, signed_at, bundle).await?,
    );
    Ok(())
}

pub(crate) async fn verified_keys(
    state: &AppState,
    bundle: &RealmAuthorityBundle,
) -> Result<RealmAuthorityKeyMap, AppError> {
    let mut methods: BTreeMap<DidUrl, BTreeSet<DateTime<Utc>>> = BTreeMap::new();
    let mut add_signature = |signature: &arkret_wire::DetachedObjectSignature| {
        methods
            .entry(signature.verification_method.clone())
            .or_default()
            .insert(signature.created_at);
    };
    add_signature(&bundle.genesis_commit.signature);
    for transition in &bundle.authority_transitions {
        add_signature(&transition.change_commit.signature);
        add_signature(&transition.handoff.old_authority_signature);
        add_signature(&transition.handoff.new_authority_acceptance_signature);
    }
    let mut keys = RealmAuthorityKeyMap::new();
    for (method, times) in methods {
        for signed_at in times {
            insert_historical_method_key(state, &mut keys, &method, signed_at, bundle).await?;
        }
    }
    Ok(keys)
}

async fn fetch_candidate(
    state: &AppState,
    endpoint: &str,
    request: &RealmAuthorityBundleRequestBody,
) -> Result<RealmAuthorityBundle, AppError> {
    let target = format!(
        "{}/_arkret/open/realm-authority/bundle",
        endpoint.trim_end_matches('/'),
    );
    let (url, client) = crate::security::validate_http_url_for_egress_with_pinned_client(
        &target,
        "Realm authority bundle",
        state.config().development_mode,
        Duration::from_secs(30),
    )
    .map_err(unavailable)?;
    let body = arkret_canonical::canonical_json_bytes(request).map_err(unavailable)?;
    let mut response = crate::routing::with_arkret_operation(
        client.post(url),
        arkret_wire::ServiceOperationId::OPEN_REALM_AUTHORITY_READ_BUNDLE_V1,
    )
    .header(reqwest::header::CONTENT_TYPE, "application/json")
    .body(body)
    .send()
    .await
    .map_err(unavailable)?;
    if !response.status().is_success() {
        if matches!(response.status().as_u16(), 403 | 404) {
            return Err(AppError::not_found("Realm authority not disclosed"));
        }
        return Err(unavailable(
            "Realm authority candidate did not return a bundle",
        ));
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(unavailable)? {
        if bytes.len() + chunk.len() > MAX_BUNDLE_BYTES {
            return Err(unavailable(
                "Realm authority bundle exceeds the response limit",
            ));
        }
        bytes.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&bytes).map_err(unavailable)
}

/// One Realm authority verified through untrusted locator hints: every hint
/// is asked for a bundle bound to `nonce`, each bundle is verified end to end
/// under keys resolved from its own DIDs, and the verified results must
/// converge. A locator never establishes authority by itself.
pub(crate) struct LocatedRealmAuthority {
    pub bundle: RealmAuthorityBundle,
    pub authority: VerifiedRealmAuthority,
    pub keys: RealmAuthorityKeyMap,
}

impl LocatedRealmAuthority {
    /// The durable current-authority record this verified chain names.
    pub(crate) fn current_authority(&self) -> coland_storage::CurrentRealmAuthority {
        let (authority_ref, last_handoff_ref) = match self.bundle.authority_transitions.last() {
            Some(transition) => (
                arkret_wire::RealmCommitAuthorityRef::Handoff(
                    transition.handoff.handoff_id.clone(),
                ),
                Some(transition.handoff.handoff_id.clone()),
            ),
            None => (
                arkret_wire::RealmCommitAuthorityRef::GenesisOrChangeEvent(
                    self.bundle.genesis_event.event_id.clone(),
                ),
                None,
            ),
        };
        coland_storage::CurrentRealmAuthority {
            realm_id: self.authority.realm_id().clone(),
            generation: self.authority.current_generation(),
            service_id: self.authority.current_service_id().clone(),
            authority_ref,
            last_handoff_ref,
        }
    }
}

/// Verify one fetched candidate bundle end to end, bound to `request.nonce`,
/// under keys resolved from the bundle's own DIDs. Every refusal is logged
/// with its reason; the caller only learns that the candidate did not verify.
async fn verify_candidate(
    state: &AppState,
    locator: &str,
    request: &RealmAuthorityBundleRequestBody,
    fetched: Result<RealmAuthorityBundle, AppError>,
) -> Option<LocatedRealmAuthority> {
    let verified = async {
        let bundle = fetched.map_err(|error| format!("bundle fetch: {}", error.message))?;
        if bundle.realm_id != request.realm_id {
            return Err("bundle names another Realm".to_owned());
        }
        let keys = verified_keys(state, &bundle)
            .await
            .map_err(|error| format!("authority keys: {}", error.message))?;
        let freshness = RealmAuthorityFreshness::new(crate::wire::now(), request.nonce.clone());
        let authority = verify_realm_authority_bundle(&bundle, &freshness, &keys)
            .map_err(|error| format!("bundle verification: {error}"))?;
        Ok(LocatedRealmAuthority {
            bundle,
            authority,
            keys,
        })
    }
    .await;
    match verified {
        Ok(located) => Some(located),
        Err(reason) => {
            tracing::warn!(%locator, realm_id = %request.realm_id, %reason,
                "Realm authority candidate was not verified");
            None
        }
    }
}

/// Verify a bundle a peer Station served bound to `nonce`, end to end under
/// keys resolved from the bundle's own DIDs.
pub(crate) async fn verify_served_bundle(
    state: &AppState,
    bundle: RealmAuthorityBundle,
    nonce: &Base64UrlString,
) -> Result<LocatedRealmAuthority, AppError> {
    let keys = verified_keys(state, &bundle).await?;
    let freshness = RealmAuthorityFreshness::new(crate::wire::now(), nonce.clone());
    let authority =
        verify_realm_authority_bundle(&bundle, &freshness, &keys).map_err(unavailable)?;
    Ok(LocatedRealmAuthority {
        bundle,
        authority,
        keys,
    })
}

/// Verify the Realm authority an authenticated peer Station serves: its
/// verified route is the only locator, and the verified chain must name that
/// Station as the current governance Station.
pub(crate) async fn fetch_authority_bundle_of_service(
    state: &AppState,
    realm_id: &RealmId,
    service_id: &arkret_wire::DidCoreId,
    nonce: &Base64UrlString,
) -> Result<RealmAuthorityBundle, AppError> {
    let endpoint = crate::routing::federation::resolved_peer_route(
        state,
        service_id.as_str(),
        "station",
        false,
    )
    .await
    .map_err(unavailable)?
    .base_url()
    .to_owned();
    fetch_candidate(
        state,
        &endpoint,
        &RealmAuthorityBundleRequestBody {
            realm_id: realm_id.clone(),
            nonce: nonce.clone(),
        },
    )
    .await
}

pub(crate) async fn resolve_verified_authority_of_service(
    state: &AppState,
    realm_id: &RealmId,
    service_id: &arkret_wire::DidCoreId,
) -> Result<LocatedRealmAuthority, AppError> {
    let nonce = Base64UrlString::new(arkret_canonical::base64url_encode(
        rand::random::<[u8; 32]>(),
    ))
    .map_err(unavailable)?;
    let request = RealmAuthorityBundleRequestBody {
        realm_id: realm_id.clone(),
        nonce,
    };
    if service_id == &state.service_core_id() {
        let bundle = local_authority_bundle(state, realm_id, &request.nonce).await?;
        let located = verify_served_bundle(state, bundle, &request.nonce).await?;
        if located.authority.current_service_id() != service_id {
            return Err(unavailable(
                "this Station no longer governs the requested Realm",
            ));
        }
        return Ok(located);
    }
    let endpoint = crate::routing::federation::resolved_peer_route(
        state,
        service_id.as_str(),
        "station",
        false,
    )
    .await
    .map_err(unavailable)?
    .base_url()
    .to_owned();
    let fetched = fetch_candidate(state, &endpoint, &request).await;
    let located = verify_candidate(state, &endpoint, &request, fetched)
        .await
        .ok_or_else(|| unavailable("the peer Station served no verifiable Realm authority"))?;
    if located.authority.current_service_id() != service_id {
        return Err(unavailable(
            "the peer Station is not the Realm's current governance Station",
        ));
    }
    Ok(located)
}

pub(crate) async fn resolve_verified_authority(
    state: &AppState,
    realm_id: &RealmId,
    hints: &[RealmJoinCandidate],
    nonce: &Base64UrlString,
) -> Result<LocatedRealmAuthority, AppError> {
    // Every carrier validated its array on decode; the set is re-checked here
    // because a locator is used only after the consumer itself proved the
    // whole array is bounded, ordered and free of repeated service ids.
    validate_authority_locator_hints(hints).map_err(invalid_request)?;
    let request = RealmAuthorityBundleRequestBody {
        realm_id: realm_id.clone(),
        nonce: nonce.clone(),
    };
    let mut verified: Vec<LocatedRealmAuthority> = Vec::new();
    let mut fetch_unavailable = false;
    for candidate in hints {
        // A locator naming this Station is answered on the equivalent local
        // path: the bundle is still verified like any other candidate, but no
        // request is sent to this Station's own public endpoint.
        let fetched = if candidate.service_id == state.service_core_id() {
            local_authority_bundle(state, realm_id, nonce).await
        } else {
            fetch_remote_candidate(state, candidate, &request).await
        };
        fetch_unavailable |= fetched
            .as_ref()
            .is_err_and(|error| error.code != crate::error::ErrorCode::NotFound);
        if let Some(located) =
            verify_candidate(state, candidate.service_id.as_str(), &request, fetched).await
        {
            verified.push(located);
        }
    }
    let authorities: Vec<_> = verified
        .iter()
        .map(|located| located.authority.clone())
        .collect();
    if verified.is_empty() && !fetch_unavailable {
        return Err(AppError::not_found("Realm authority not disclosed"));
    }
    // No locator led to a verified current governance Station, or the verified
    // ones disagree. Either way the Realm's current authority cannot be reached
    // now: a retryable upstream failure, never an internal error and never a
    // substituted source (`invite-addressing.md` section 7.1).
    let converged = converge_verified_realm_authorities(&authorities)
        .map_err(|error| {
            AppError::from_rejection(
                crate::error::ErrorCode::TemporarilyUnavailable,
                format!("Realm authority evidence unavailable: {error}"),
            )
        })?
        .clone();
    verified
        .into_iter()
        .find(|located| located.authority == converged)
        .ok_or_else(|| invalid_request("verified Realm authority did not converge"))
}

async fn fetch_remote_candidate(
    state: &AppState,
    candidate: &RealmJoinCandidate,
    request: &RealmAuthorityBundleRequestBody,
) -> Result<RealmAuthorityBundle, AppError> {
    let endpoint = match &candidate.endpoint_url {
        Some(url) => url.clone(),
        None => crate::routing::federation::resolved_peer_route(
            state,
            candidate.service_id.as_str(),
            "station",
            false,
        )
        .await
        .map_err(unavailable)?
        .base_url()
        .to_owned(),
    };
    fetch_candidate(state, &endpoint, request).await
}

pub(super) async fn resolve_join_target_authority(
    state: &AppState,
    target: &RealmJoinTarget,
    _request_id: &RequestId,
) -> Result<LocatedRealmAuthority, AppError> {
    resolve_verified_authority(
        state,
        &target.realm_id,
        &target.authority_locator_hints,
        &super::preview::fresh_nonce()?,
    )
    .await
}
