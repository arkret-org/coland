//! Coland thin adapter over the canonical detached-JWS verifier in the SDK.
//!
//! All JWS verification semantics (RFC 7515 detached shape, Ed25519
//! signature check and authority binding) live in the SDK so inkson, floria,
//! cotest, flagon and coland share one wire-compatible implementation. This
//! module selects a document or accepted key from [`AppState`], then hands
//! pinned material to the resolver-free SDK verifier.
//!
//! Every mode, including development mode, runs the same verifier: the
//! selected document, issuer and verification-method DID root must agree
//! before the SDK performs Ed25519 verification. There is no shape-only path.

use std::collections::BTreeMap;

use arkret_identifiers::{Did, Hash};
use arkret_identity::{DidDocument, DidResolver as _};
use coland_services::identity::{
    DID_DOCUMENT_HIGH_RISK_TTL_SECS, DidDocumentFreshness, evaluate_did_document_freshness,
};
use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
use serde_json::Value;

use crate::routing::identity::webvh_validation::{
    WebvhLogEntry, validate_log_chain, validate_witness_policy_for_log, verify_scid_against_did,
};
use crate::state::AppState;

/// DID document freshness threshold for high-risk verification paths. Equal
/// to the persistence-layer baseline TTL (15min). Records older than this,
/// or records without freshness evidence, fail closed because coland does not
/// perform on-demand network refreshes.
pub const HIGH_RISK_DID_FRESHNESS_MAX_SECS: i64 = DID_DOCUMENT_HIGH_RISK_TTL_SECS;

/// Resolved Ed25519 verification key with the document metadata that
/// endpoints need to report or bind into audit records.
#[derive(Clone, Debug)]
pub struct ResolvedVerificationKey {
    pub verification_method: String,
    pub algorithm: &'static str,
    pub public_key: VerifyingKey,
    pub did_document_ref: String,
    pub key_log_head: Hash,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedPrincipalDeviceSignatureBinding {
    pub authorization_event_id: arkret_wire::EventId,
    pub generation_ref: u64,
}

/// Production detached-JWS verifier for a DID-controlled method.
///
/// This synchronous form uses only deployment-local snapshots and configured
/// keys. Signature verification is delegated to the SDK after the document is
/// pinned; `issuer` is compared with both document id and the method's DID root.
pub fn verify_did_controlled_jws(
    canonical_bytes: &[u8],
    jws: &str,
    verification_method: &str,
    issuer: &str,
    state: &AppState,
) -> Result<(), String> {
    let did = arkret_identity::verification_method_did(verification_method)
        .map_err(|error| error.to_string())?;
    validate_verification_method_controller(issuer, verification_method)?;
    let document = document_for_verification_sync(state, &did, verification_method)?;
    enforce_selected_document_admission(
        &document,
        verification_method,
        Some(&state.config().trust_domain),
    )?;
    verify_jws_with_pinned_document(canonical_bytes, jws, verification_method, issuer, &document)
}

/// Async-native production Ed25519 detached-JWS verifier.
///
/// This resolves the DID document through coland's async resolver service
/// before delegating shape and signature verification to the SDK verifier.
pub async fn verify_did_controlled_jws_async(
    canonical_bytes: &[u8],
    jws: &str,
    verification_method: &str,
    issuer: &str,
    state: &AppState,
) -> Result<(), String> {
    let did = arkret_identity::verification_method_did(verification_method)
        .map_err(|error| error.to_string())?;
    validate_verification_method_controller(issuer, verification_method)?;
    let document = document_for_verification(state, &did, verification_method).await?;
    enforce_selected_document_admission(
        &document,
        verification_method,
        Some(&state.config().trust_domain),
    )?;
    verify_jws_with_pinned_document(canonical_bytes, jws, verification_method, issuer, &document)
}

pub fn verify_ed25519_signature_with_public_key(
    payload: &[u8],
    signature_b64url: &str,
    public_key: &[u8; 32],
) -> Result<(), String> {
    if payload.is_empty() {
        return Err("empty signed payload".to_owned());
    }
    let signature_bytes = arkret_canonical::base64url_decode(signature_b64url)
        .map_err(|error| format!("signature is not unpadded base64url: {error}"))?;
    let signature = Signature::from_slice(&signature_bytes)
        .map_err(|_| "Ed25519 signature must be 64 bytes".to_owned())?;
    let verifying_key = VerifyingKey::from_bytes(public_key)
        .map_err(|_| "Ed25519 public key is invalid".to_owned())?;
    verifying_key
        .verify(payload, &signature)
        .map_err(|_| "Ed25519 signature verification failed".to_owned())
}

fn document_for_verification_sync(
    state: &AppState,
    did: &Did,
    verification_method: &str,
) -> Result<DidDocument, String> {
    if did.method() == "key" {
        return arkret_identity::DidKeyResolver::new()
            .resolve_did_document(did)
            .map_err(|error| error.to_string());
    }
    if is_local_service_notary_method(state, did, verification_method) {
        return Ok(DidDocument {
            id: did.clone(),
            verification_methods: BTreeMap::from([(
                verification_method.to_owned(),
                arkret_canonical::ed25519_pubkey_to_did_key_multibase(
                    state.notary_verifying_key().as_bytes(),
                ),
            )]),
            also_known_as: Vec::new(),
            updated_at: Some(chrono::Utc::now()),
            raw_properties: BTreeMap::new(),
        });
    }
    if let Some(key) = state.federation_peer_verification_method_key(verification_method) {
        return Ok(DidDocument {
            id: did.clone(),
            verification_methods: BTreeMap::from([(
                verification_method.to_owned(),
                arkret_canonical::ed25519_pubkey_to_did_key_multibase(key.as_bytes()),
            )]),
            also_known_as: Vec::new(),
            updated_at: Some(chrono::Utc::now()),
            raw_properties: BTreeMap::new(),
        });
    }
    resolve_did_document(state, did)
}

/// Produce the DID document a JWS should be verified against.
///
/// Two deployment-local sources short-circuit any resolution: this service's
/// own notary key and an already-accepted federation peer key. Everything else
/// goes through [`resolve_did_document_async`], which prefers the durable local
/// DID store and only then the resolver chain.
async fn document_for_verification(
    state: &AppState,
    did: &Did,
    verification_method: &str,
) -> Result<DidDocument, String> {
    if did.method() == "key" {
        return arkret_identity::DidKeyResolver::new()
            .resolve_did_document(did)
            .map_err(|error| error.to_string());
    }
    if is_local_service_notary_method(state, did, verification_method) {
        return Ok(DidDocument {
            id: did.clone(),
            verification_methods: BTreeMap::from([(
                verification_method.to_owned(),
                arkret_canonical::ed25519_pubkey_to_did_key_multibase(
                    state.notary_verifying_key().as_bytes(),
                ),
            )]),
            also_known_as: Vec::new(),
            updated_at: Some(chrono::Utc::now()),
            raw_properties: BTreeMap::new(),
        });
    }
    if let Some(key) = state.federation_peer_verification_method_key(verification_method) {
        return Ok(DidDocument {
            id: did.clone(),
            verification_methods: BTreeMap::from([(
                verification_method.to_owned(),
                arkret_canonical::ed25519_pubkey_to_did_key_multibase(key.as_bytes()),
            )]),
            also_known_as: Vec::new(),
            updated_at: Some(chrono::Utc::now()),
            raw_properties: BTreeMap::new(),
        });
    }
    resolve_did_document_async(state, did).await
}

/// Decode a pinned/historical DID document that a caller already selected by
/// version, log head or `accepted_at`, so it can be handed to the SDK's
/// zero-resolver verifier [`arkret_identity::verify_jws_with_document`].
///
/// This is a serde adapter, not a verifier: coland deliberately keeps **no**
/// private JWS-with-document implementation
/// (`did-usage-and-verification.md` §6 — one shared verifier layer).
pub fn decode_pinned_did_document(
    document_value: &serde_json::Value,
) -> Result<DidDocument, String> {
    serde_json::from_value::<DidDocument>(document_value.clone())
        .map_err(|error| format!("historical DID document decode failed: {error}"))
}

/// Verify a detached JWS against an already-pinned historical DID document.
///
/// Thin typed adapter over [`arkret_identity::verify_jws_with_document`]:
/// it parses the wire strings into `DidUrl` / `Did`, records the signature
/// verification in metrics, and delegates every semantic check to the SDK.
/// **Zero resolver calls by construction** — the SDK entry point has no
/// resolver parameter.
pub fn verify_jws_with_pinned_document(
    canonical_bytes: &[u8],
    jws: &str,
    verification_method: &str,
    issuer: &str,
    document: &DidDocument,
) -> Result<(), String> {
    let verification_method = arkret_wire::DidUrl::new(verification_method.to_owned())
        .map_err(|error| format!("verification_method is not a DID URL: {error}"))?;
    // `issuer` may be the protocol's Core principal/service id while the
    // resolved DID document and verification method necessarily retain the
    // versioned DID. Validate that pair first, then hand the Full
    // verification-method controller to the SDK verifier. Parsing `issuer`
    // directly as `Did` made every legitimate Core issuer fail before
    // cryptographic verification.
    validate_verification_method_controller(issuer, verification_method.as_str())?;
    let issuer_did = arkret_identity::verification_method_did(verification_method.as_str())
        .map_err(|error| error.to_string())?;
    enforce_selected_document_admission(document, verification_method.as_str(), None)?;
    let outcome = arkret_identity::verify_jws_with_document(
        canonical_bytes,
        jws,
        &verification_method,
        &issuer_did,
        document,
    )
    .map_err(|error| error.to_string());
    crate::metrics::record_signature_verify(
        crate::metrics::SIGNATURE_SCHEME_PINNED_DOCUMENT,
        outcome.is_ok(),
    );
    outcome
}

/// Principal-authorization verification error.
///
/// Principal authorization has no core-only entry point: every verifier below
/// takes an exact `(principal_id, station_id)` account authority
/// context plus accepted local device evidence. The sole current-DID path is
/// restricted to registered identity-resolution updates.
#[derive(Debug)]
pub enum PrincipalAuthorizedJwsError {
    HighRiskDidFreshness(String),
    Verification(String),
}

impl std::fmt::Display for PrincipalAuthorizedJwsError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::HighRiskDidFreshness(reason) | Self::Verification(reason) => {
                formatter.write_str(reason)
            }
        }
    }
}

/// Key source used only by registered identity-resolution updates.
///
/// This path requires the current DID authority document. It deliberately does
/// not consult the PCR device directory, accepted-binding cache, service
/// routes, or development fixture keys.
enum PrincipalVerificationSource {
    AuthorityDocument(Box<DidDocument>),
}

async fn principal_verification_source(
    verification_method: &str,
    principal_id: &str,
    state: &AppState,
) -> Result<(Did, PrincipalVerificationSource), PrincipalAuthorizedJwsError> {
    let method_did = arkret_identity::verification_method_did(verification_method)
        .map_err(|error| PrincipalAuthorizedJwsError::Verification(error.to_string()))?;
    let method_principal_id = arkret_wire::project_did_to_core_id(&method_did)
        .map_err(|error| PrincipalAuthorizedJwsError::Verification(error.to_string()))?;
    if method_principal_id.as_str() != principal_id {
        return Err(PrincipalAuthorizedJwsError::Verification(
            "verification method controller does not match principal".to_owned(),
        ));
    }
    if verification_method
        .strip_prefix(method_did.as_str())
        .and_then(|fragment| fragment.strip_prefix('#'))
        .is_some_and(|fragment| arkret_identifiers::DeviceId::new(fragment.to_owned()).is_ok())
    {
        return Err(PrincipalAuthorizedJwsError::Verification(
            "identity resolution updates require a current DID authority method, not a PCR device key"
                .to_owned(),
        ));
    }
    if method_did.method() != "key"
        && !is_local_service_notary_method(state, &method_did, verification_method)
    {
        enforce_high_risk_did_freshness(state, &method_did)
            .await
            .map_err(PrincipalAuthorizedJwsError::HighRiskDidFreshness)?;
    }
    let document = document_for_verification(state, &method_did, verification_method)
        .await
        .map_err(PrincipalAuthorizedJwsError::Verification)?;
    Ok((
        method_did,
        PrincipalVerificationSource::AuthorityDocument(Box::new(document)),
    ))
}

/// Verify a principal-device detached JWS against an explicit local account
/// authority coordinate and the accepted device authorization in that PCR.
async fn principal_authorized_device_binding_with_account_authority_async(
    verification_method: &str,
    authority: &arkret_wire::AccountId,
    expected_device_id: &arkret_identifiers::DeviceId,
    state: &AppState,
) -> Result<
    (
        arkret_wire::DidUrl,
        DidDocument,
        arkret_identity::AcceptedDidBinding,
        VerifiedPrincipalDeviceSignatureBinding,
    ),
    PrincipalAuthorizedJwsError,
> {
    let fail = |reason: String| PrincipalAuthorizedJwsError::Verification(reason);
    if authority.station_id.as_str() != state.service_id() {
        return Err(fail(
            "principal authorization is addressed to a different Station".to_owned(),
        ));
    }
    let (method_did, fragment) = verification_method
        .rsplit_once('#')
        .ok_or_else(|| fail("principal verification method has no device fragment".to_owned()))?;
    let method_did = arkret_wire::Did::new(method_did.to_owned()).map_err(|error| {
        fail(format!(
            "principal verification method DID is invalid: {error}"
        ))
    })?;
    let method_principal_id =
        arkret_wire::project_did_to_core_id(&method_did).map_err(|error| {
            fail(format!(
                "principal verification method DID cannot be projected: {error}"
            ))
        })?;
    if method_principal_id != authority.principal_id || fragment != expected_device_id.as_str() {
        return Err(fail(
            "principal verification method does not bind the session authority and device"
                .to_owned(),
        ));
    }

    let durable = state
        .persistence()
        .principal_resolution_by_account_id(authority)
        .await
        .map_err(|error| {
            fail(format!(
                "principal account authority lookup failed: {error}"
            ))
        })?
        .ok_or_else(|| fail("principal account authority is not durably accepted".to_owned()))?;
    let device = state
        .identities()
        .find_device(coland_services::identity::FindDeviceQuery {
            actor_id: authority.principal_id.to_string(),
            device_id: expected_device_id.to_string(),
        })
        .await
        .map_err(|error| fail(format!("principal device state unavailable: {error}")))?
        .ok_or_else(|| fail("principal signer device is unavailable".to_owned()))?;
    if device.revoked_at.is_some() || device.verification_state != "verified" {
        return Err(fail("principal signer device is not active".to_owned()));
    }
    let payload = serde_json::from_value::<
        crate::routing::identity::device_signing::ProjectedDevicePayload,
    >(device.payload)
    .map_err(|error| fail(format!("principal device evidence is invalid: {error}")))?;
    let signing_key = payload
        .device_public_key_did
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| fail("principal signer key is unavailable".to_owned()))?;
    crate::routing::identity::device_signing::decode_ed25519_key(signing_key, "multibase")
        .map_err(|error| fail(format!("principal signer key is invalid: {error}")))?;
    let generation_ref = payload
        .authorized_generation_ref
        .ok_or_else(|| fail("principal signer has no active device generation".to_owned()))?;
    let generation = crate::routing::identity::device_generation::current_device_generation(
        state,
        authority.principal_id.as_str(),
    )
    .await
    .map_err(|error| fail(format!("principal device generation unavailable: {error}")))?
    .ok_or_else(|| fail("principal device generation is unavailable".to_owned()))?;
    if generation.current_ref != generation_ref {
        return Err(fail(
            "principal signer is outside the active device generation".to_owned(),
        ));
    }
    let authorize_event_id = payload
        .device_authorize_event_id
        .ok_or_else(|| fail("principal signer has no accepted authorization Event".to_owned()))?;
    let authorize_event = state
        .event_queries()
        .canonical_event(authorize_event_id.as_str())
        .await
        .map_err(|error| {
            fail(format!(
                "principal device authorization lookup failed: {error}"
            ))
        })?
        .ok_or_else(|| fail("principal device authorization Event is unavailable".to_owned()))?;
    let expected_actor = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        authority.principal_id.clone(),
        authority.station_id.clone(),
    ));
    if authorize_event.actor_id != expected_actor.to_string()
        || authorize_event.kind != arkret_wire::event_kind_str::DEVICE_AUTHORIZE
        || authorize_event.realm_id.as_deref() != Some(durable.pcr_realm_id.as_str())
    {
        return Err(fail(
            "principal device authorization is outside the selected PCR authority".to_owned(),
        ));
    }

    let document = DidDocument {
        id: method_did.clone(),
        verification_methods: BTreeMap::from([(
            verification_method.to_owned(),
            signing_key
                .strip_prefix("did:key:")
                .unwrap_or(signing_key)
                .to_owned(),
        )]),
        also_known_as: Vec::new(),
        updated_at: None,
        raw_properties: BTreeMap::new(),
    };
    let accepted = principal_binding_acceptance(state, &method_did, verification_method, &document)
        .map_err(fail)?;
    let verification_method_id = arkret_wire::DidUrl::new(verification_method.to_owned())
        .map_err(|error| fail(format!("principal verification method is invalid: {error}")))?;
    let authorization_event_id = arkret_wire::EventId::new(authorize_event_id)
        .map_err(|error| fail(format!("device authorization Event id is invalid: {error}")))?;
    Ok((
        verification_method_id,
        document,
        accepted,
        VerifiedPrincipalDeviceSignatureBinding {
            authorization_event_id,
            generation_ref,
        },
    ))
}

/// Resolve the current Ed25519 key for a principal device only after binding it
/// to an exact local Account authority and its accepted PCR authorization.
pub(crate) async fn resolve_principal_authorized_device_key_with_account_authority_async(
    verification_method: &str,
    authority: &arkret_wire::AccountId,
    expected_device_id: &arkret_identifiers::DeviceId,
    state: &AppState,
) -> Result<VerifyingKey, PrincipalAuthorizedJwsError> {
    let (verification_method, document, ..) =
        principal_authorized_device_binding_with_account_authority_async(
            verification_method,
            authority,
            expected_device_id,
            state,
        )
        .await?;
    let public_key_multibase = document
        .verification_methods
        .get(verification_method.as_str())
        .ok_or_else(|| {
            PrincipalAuthorizedJwsError::Verification(
                "principal verification method is absent from the accepted device binding"
                    .to_owned(),
            )
        })?;
    let public_key =
        arkret_canonical::decode_ed25519_multibase(public_key_multibase).map_err(|error| {
            PrincipalAuthorizedJwsError::Verification(format!(
                "principal verification method key is invalid: {error}"
            ))
        })?;
    VerifyingKey::from_bytes(&public_key).map_err(|error| {
        PrincipalAuthorizedJwsError::Verification(format!(
            "principal verification method key is invalid: {error}"
        ))
    })
}

pub async fn verify_principal_authorized_jws_with_account_authority_async(
    canonical_bytes: &[u8],
    jws: &str,
    verification_method: &str,
    authority: &arkret_wire::AccountId,
    expected_device_id: &arkret_identifiers::DeviceId,
    state: &AppState,
) -> Result<(), PrincipalAuthorizedJwsError> {
    let (verification_method, _, accepted, _) =
        principal_authorized_device_binding_with_account_authority_async(
            verification_method,
            authority,
            expected_device_id,
            state,
        )
        .await?;
    let outcome = arkret_identity::verify_jws_with_binding(
        canonical_bytes,
        jws,
        &verification_method,
        &accepted,
    )
    .map_err(|error| PrincipalAuthorizedJwsError::Verification(error.to_string()));
    crate::metrics::record_signature_verify(
        crate::metrics::SIGNATURE_SCHEME_PINNED_DOCUMENT,
        outcome.is_ok(),
    );
    outcome
}

/// Verify the accepted-device proof's raw Ed25519 signature against the same
/// durable PCR authority and current device authorization used for detached
/// principal JWS verification.
pub async fn verify_principal_authorized_ed25519_signature_with_account_authority_async(
    canonical_bytes: &[u8],
    signature_b64url: &str,
    verification_method: &str,
    authority: &arkret_wire::AccountId,
    expected_device_id: &arkret_identifiers::DeviceId,
    state: &AppState,
) -> Result<VerifiedPrincipalDeviceSignatureBinding, PrincipalAuthorizedJwsError> {
    let (verification_method, document, _, binding) =
        principal_authorized_device_binding_with_account_authority_async(
            verification_method,
            authority,
            expected_device_id,
            state,
        )
        .await?;
    let public_key_multibase = document
        .verification_methods
        .get(verification_method.as_str())
        .ok_or_else(|| {
            PrincipalAuthorizedJwsError::Verification(
                "principal verification method is absent from the accepted device binding"
                    .to_owned(),
            )
        })?;
    let public_key =
        arkret_canonical::decode_ed25519_multibase(public_key_multibase).map_err(|error| {
            PrincipalAuthorizedJwsError::Verification(format!(
                "principal verification method key is invalid: {error}"
            ))
        })?;
    let outcome =
        verify_ed25519_signature_with_public_key(canonical_bytes, signature_b64url, &public_key)
            .map_err(PrincipalAuthorizedJwsError::Verification);
    crate::metrics::record_signature_verify(
        crate::metrics::SIGNATURE_SCHEME_PINNED_DOCUMENT,
        outcome.is_ok(),
    );
    outcome?;
    Ok(binding)
}

/// Event-proof verifier for principal-authorized Events.
///
/// # Why Event proofs may not use a generic detached-JWS entry point
///
/// An Event proof's JWS does not sign the bytes handed to a generic detached-JWS
/// verifier: per `encoding.md` §6 it signs the canonical **proof binding
/// object**, and the Event profile's protected header
/// (`arkret_signatures`' `DetachedJwsProtectedHeader`, `deny_unknown_fields`)
/// is strictly narrower than the generic one:
///
/// | check | Event profile (here) | generic profile |
/// | --- | --- | --- |
/// | `kid` header member | rejected | accepted and ignored |
/// | `header.alg` | must be `Ed25519` | must be `Ed25519` |
///
/// Reconstructing the binding bytes by hand and feeding them to the generic
/// verifier — which is what this call site used to do — therefore relaxed the
/// header checks on every DID-rooted Event proof. Every branch below routes
/// through an SDK Event-profile verifier instead, so the transcript, the digest
/// comparison and the header hygiene all come from one implementation.
///
/// `envelope_bytes` are the Event's canonical bytes with `proofs` / `unsigned`
/// stripped (`arkret_signatures::EventProofBuilder::envelope_bytes`); the SDK
/// re-derives `event_digest` from them and constant-time compares it to
/// `proof.event_digest`. `actor_id` is the Event envelope's `actor_id` — the
/// record subject folded into the signed transcript — which for delegated
/// execution differs from `principal_id`, the DID that owns the signing key.
pub fn verify_principal_authorized_event_proof_async<'a>(
    proof: &'a arkret_wire::ProducerEventProof,
    envelope_bytes: &'a [u8],
    actor_id: &'a arkret_wire::ActorId,
    verification_method: &'a str,
    principal_id: &'a str,
    state: &'a AppState,
) -> std::pin::Pin<
    Box<
        dyn std::future::Future<Output = Result<arkret_wire::DidKey, PrincipalAuthorizedJwsError>>
            + Send
            + 'a,
    >,
> {
    Box::pin(async move {
        let fail = |reason: String| PrincipalAuthorizedJwsError::Verification(reason);
        let (method_did, device_id) = verification_method.rsplit_once('#').ok_or_else(|| {
            fail("principal Event verification method has no device fragment".to_owned())
        })?;
        let method_did = arkret_wire::Did::new(method_did.to_owned()).map_err(|error| {
            fail(format!(
                "principal Event verification method DID is invalid: {error}"
            ))
        })?;
        let method_principal_id =
            arkret_wire::project_did_to_core_id(&method_did).map_err(|error| {
                fail(format!(
                    "principal Event verification method DID cannot be projected: {error}"
                ))
            })?;
        let expected_principal_id = arkret_wire::DidCoreId::new(principal_id.to_owned())
            .or_else(|_| {
                arkret_wire::Did::new(principal_id.to_owned())
                    .and_then(|did| arkret_wire::project_did_to_core_id(&did))
            })
            .map_err(|error| {
                fail(format!(
                    "principal Event signer identity is invalid: {error}"
                ))
            })?;
        if method_principal_id != expected_principal_id {
            return Err(fail(
                "principal Event verification method does not belong to the proof signer"
                    .to_owned(),
            ));
        }
        let device_id =
            arkret_identifiers::DeviceId::new(device_id.to_owned()).map_err(|error| {
                fail(format!(
                    "principal Event device fragment is invalid: {error}"
                ))
            })?;
        let envelope: Value = serde_json::from_slice(envelope_bytes)
            .map_err(|error| fail(format!("principal Event envelope is invalid: {error}")))?;

        let station_id = actor_id.route_service_id();
        if station_id.as_str() != state.service_id() {
            return Err(fail(
                "principal Event is not addressed to this Station".to_owned(),
            ));
        }
        if actor_id.signing_principal_id() != &expected_principal_id {
            let agent = state
                .agent_pairings()
                .agent(actor_id.signing_principal_id().as_str())
                .await
                .map_err(|error| fail(format!("Agent authority lookup failed: {error}")))?
                .ok_or_else(|| fail("delegated Event actor is not a local Agent".to_owned()))?;
            let agent_controller_principal_id =
                arkret_wire::DidCoreId::new(agent.controller_principal_id.clone())
                    .or_else(|_| {
                        arkret_wire::Did::new(agent.controller_principal_id.clone())
                            .and_then(|did| arkret_wire::project_did_to_core_id(&did))
                    })
                    .map_err(|error| fail(format!("Agent controller is invalid: {error}")))?;
            if agent_controller_principal_id != expected_principal_id {
                return Err(fail(
                    "delegated Event signer is not the Agent controller".to_owned(),
                ));
            }
            let authorization_ref = envelope
                .get("authorization_ref")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    fail("delegated Event has no controller authorization_ref".to_owned())
                })?;
            if authorization_ref != agent.controller_authorization_ref.as_str() {
                return Err(fail(
                    "delegated Event does not use the Agent authorization_ref".to_owned(),
                ));
            }
        }
        let authority_key =
            arkret_wire::AccountId::new(expected_principal_id.clone(), station_id.clone());
        let durable = state
            .persistence()
            .principal_resolution_by_account_id(&authority_key)
            .await
            .map_err(|error| {
                fail(format!(
                    "principal account authority lookup failed: {error}"
                ))
            })?
            .ok_or_else(|| {
                fail("principal account authority is not durably accepted".to_owned())
            })?;

        let device = state
            .identities()
            .find_device(coland_services::identity::FindDeviceQuery {
                actor_id: expected_principal_id.to_string(),
                device_id: device_id.to_string(),
            })
            .await
            .map_err(|error| {
                fail(format!(
                    "principal device signing state unavailable: {error}"
                ))
            })?
            .ok_or_else(|| fail("principal Event signer device is unavailable".to_owned()))?;
        if device.revoked_at.is_some() || device.verification_state != "verified" {
            return Err(fail(
                "principal Event signer device is not active".to_owned(),
            ));
        }
        let device_payload = serde_json::from_value::<
            crate::routing::identity::device_signing::ProjectedDevicePayload,
        >(device.payload)
        .map_err(|error| {
            fail(format!(
                "principal device signing evidence is invalid: {error}"
            ))
        })?;
        let signing_key = device_payload
            .device_public_key_did
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| fail("principal Event signer key is unavailable".to_owned()))?;
        crate::routing::identity::device_signing::decode_ed25519_key(signing_key, "multibase")
            .map_err(|error| fail(format!("principal Event signer key is invalid: {error}")))?;
        // DidDocument's verification-method convenience index stores the
        // publicKeyMultibase value, not a did:key URL wrapper.
        let signing_key = signing_key
            .strip_prefix("did:key:")
            .unwrap_or(signing_key)
            .to_owned();
        let generation_ref = device_payload.authorized_generation_ref.ok_or_else(|| {
            fail("principal Event signer has no active device generation".to_owned())
        })?;
        let generation = crate::routing::identity::device_generation::current_device_generation(
            state,
            expected_principal_id.as_str(),
        )
        .await
        .map_err(|error| fail(format!("principal device generation unavailable: {error}")))?
        .ok_or_else(|| fail("principal device generation is unavailable".to_owned()))?;
        if generation.current_ref != generation_ref {
            return Err(fail(
                "principal Event signer is outside the active device generation".to_owned(),
            ));
        }
        let authorize_event_id = device_payload.device_authorize_event_id.ok_or_else(|| {
            fail("principal Event signer has no accepted authorization Event".to_owned())
        })?;
        let authorize_event = state
            .event_queries()
            .canonical_event(authorize_event_id.as_str())
            .await
            .map_err(|error| {
                fail(format!(
                    "principal device authorization lookup failed: {error}"
                ))
            })?
            .ok_or_else(|| {
                fail("principal device authorization Event is unavailable".to_owned())
            })?;
        let expected_actor = arkret_wire::ActorId::account(authority_key.clone());
        if authorize_event.actor_id != expected_actor.to_string()
            || authorize_event.kind != arkret_wire::event_kind_str::DEVICE_AUTHORIZE
            || authorize_event.realm_id.as_deref() != Some(durable.pcr_realm_id.as_str())
        {
            return Err(fail(
                "principal device authorization Event is outside the selected PCR authority"
                    .to_owned(),
            ));
        }

        let document = DidDocument {
            id: method_did.clone(),
            verification_methods: BTreeMap::from([(
                verification_method.to_owned(),
                signing_key.clone(),
            )]),
            also_known_as: Vec::new(),
            updated_at: None,
            raw_properties: BTreeMap::new(),
        };
        let accepted =
            principal_binding_acceptance(state, &method_did, verification_method, &document)
                .map_err(fail)?;
        let outcome = arkret_identity::verify_event_proof_with_binding(
            proof,
            envelope_bytes,
            actor_id,
            &accepted,
        )
        .map_err(|error| fail(error.to_string()));
        crate::metrics::record_signature_verify(
            crate::metrics::SIGNATURE_SCHEME_PINNED_DOCUMENT,
            outcome.is_ok(),
        );
        outcome?;
        arkret_wire::DidKey::new(format!("did:key:{signing_key}"))
            .map_err(|error| fail(format!("principal Event signer key is invalid: {error}")))
    })
}

pub async fn verify_registered_identity_resolution_event_proof_async(
    proof: &arkret_wire::ProducerEventProof,
    envelope_bytes: &[u8],
    actor_id: &arkret_wire::ActorId,
    verification_method: &str,
    principal_id: &str,
    state: &AppState,
) -> Result<arkret_wire::DidKey, PrincipalAuthorizedJwsError> {
    let (method_did, source) =
        principal_verification_source(verification_method, principal_id, state).await?;
    let PrincipalVerificationSource::AuthorityDocument(document) = source;
    // Build a one-shot binding only to use the SDK's strict Event-proof
    // verifier. It is not stored: every registered resolution update must
    // re-establish current DID authority and freshness.
    let accepted = principal_binding_acceptance(state, &method_did, verification_method, &document)
        .map_err(PrincipalAuthorizedJwsError::Verification)?;
    let outcome = arkret_identity::verify_event_proof_with_binding(
        proof,
        envelope_bytes,
        actor_id,
        &accepted,
    )
    .map_err(|error| PrincipalAuthorizedJwsError::Verification(error.to_string()));
    crate::metrics::record_signature_verify(
        crate::metrics::SIGNATURE_SCHEME_PINNED_DOCUMENT,
        outcome.is_ok(),
    );
    outcome?;
    let public_key =
        arkret_identity::jws::resolve_ed25519_pubkey_from_document(&document, verification_method)
            .map_err(|error| PrincipalAuthorizedJwsError::Verification(error.to_string()))?;
    let multibase = arkret_canonical::ed25519_pubkey_to_did_key_multibase(public_key.as_bytes());
    arkret_wire::DidKey::new(format!("did:key:{multibase}"))
        .map_err(|error| PrincipalAuthorizedJwsError::Verification(error.to_owned()))
}

/// Build the §5 binding key this deployment uses for principal-control
/// verification methods.
fn principal_binding_key(
    state: &AppState,
    did: &Did,
    verification_method: &str,
) -> Option<arkret_identity::VerifiedDidBindingKey> {
    Some(arkret_identity::VerifiedDidBindingKey {
        did: did.clone(),
        trust_domain: state.did_binding_trust_domain().ok()?,
        purpose: arkret_identity::DidBindingPurpose::Principal,
        policy_digest: state.did_binding_policy_digest().ok()?,
        verification_method: Some(arkret_wire::DidUrl::new(verification_method.to_owned()).ok()?),
    })
}

/// Build the acceptance a successful authority verification represents, without
/// deciding whether it may be cached.
///
/// The pairing is itself a check: `AcceptedDidBinding::new` refuses a document
/// whose `id` is not the bound DID or whose canonical digest is not the one the
/// binding pins, so a caller can verify an Event proof against the result and
/// get the document-issuer check for free.
fn principal_binding_acceptance(
    state: &AppState,
    did: &Did,
    verification_method: &str,
    document: &DidDocument,
) -> Result<arkret_identity::AcceptedDidBinding, String> {
    if let Err(error) = enforce_selected_document_admission(
        document,
        verification_method,
        Some(&state.config().trust_domain),
    ) {
        state.dids().discard_cached_document(did);
        state.invalidate_did_bindings(did);
        return Err(error);
    }
    let key = principal_binding_key(state, did, verification_method)
        .ok_or_else(|| "principal device key cannot form an accepted binding".to_owned())?;
    let document_digest =
        arkret_identity::document_canonical_digest(document).map_err(|error| error.to_string())?;
    let verified_at = chrono::Utc::now();
    // The acceptance inherits the high-risk freshness window that gated it, so
    // a binding can never outlive the evidence it rests on.
    let expires_at = verified_at + chrono::Duration::seconds(HIGH_RISK_DID_FRESHNESS_MAX_SECS);
    // §5.2 — the evidence digest is the digest of the canonical evidence
    // receipt, and the receipt is retained so an auditor can recompute it.
    // coland's resolver boundary surfaces no method proof set on this path, so
    // `method_proofs` is empty: that is the normative degenerate form for a
    // proofless resolution, not a placeholder standing in for evidence. It is
    // still strictly stronger than the `evidence_digest = document_digest` this
    // replaced, because the receipt also commits to the resolved method.
    let receipt = arkret_identity::EvidenceReceipt::new(
        did.method(),
        document_digest.clone(),
        &arkret_identity::MethodEvidence::none(),
    );
    let input = arkret_identity::VerifiedDidBindingInput {
        did: did.clone(),
        trust_domain: key.trust_domain.clone(),
        purpose: key.purpose,
        method: did.method().to_owned(),
        verification_method: key.verification_method.clone(),
        document_digest,
        history_head: None,
        version_id: None,
        // §5.5 — neither pin is available here, and this path cannot tell a
        // method that has no history from one whose history the resolver did not
        // surface, so both states are recorded rather than omitted.
        limited_trust: arkret_identity::LimitedTrust::for_proofless_method(None, None).record_for(),
        evidence_digest: receipt.digest().map_err(|error| error.to_string())?,
        evidence_dependencies: receipt
            .evidence_dependencies()
            .map_err(|error| error.to_string())?,
        policy_digest: key.policy_digest.clone(),
        verified_at,
        refresh_after: None,
        expires_at: Some(expires_at),
        status: arkret_identity::DidBindingStatus::Active,
    };
    let binding =
        arkret_identity::VerifiedDidBinding::new(input).map_err(|error| error.to_string())?;
    arkret_identity::AcceptedDidBinding::new(binding, document.clone(), receipt)
        .map_err(|error| error.to_string())
}

pub fn is_local_service_notary_method(
    state: &AppState,
    did: &Did,
    verification_method: &str,
) -> bool {
    let service_did = state.service_did();
    did == &service_did
        && state
            .service_verification_method("notary-key")
            .is_ok_and(|method| method.as_str() == verification_method)
}

/// Resolve a DID URL to its Ed25519 [`VerifyingKey`] via the AppState
/// resolver chain. Adapter over
/// [`arkret_identity::jws::resolve_ed25519_pubkey`].
pub fn resolve_ed25519_pubkey(
    state: &AppState,
    verification_method: &str,
) -> Result<VerifyingKey, String> {
    let did = arkret_identity::verification_method_did(verification_method)
        .map_err(|error| error.to_string())?;
    let document = document_for_verification_sync(state, &did, verification_method)?;
    let public_key =
        arkret_identity::jws::resolve_ed25519_pubkey_from_document(&document, verification_method)
            .map_err(|error| error.to_string())?;
    enforce_selected_key_admission(
        &did,
        verification_method,
        &public_key,
        Some(&state.config().trust_domain),
    )?;
    Ok(public_key)
}

pub async fn resolve_ed25519_pubkey_async(
    state: &AppState,
    verification_method: &str,
) -> Result<VerifyingKey, String> {
    let did = arkret_identity::verification_method_did(verification_method)
        .map_err(|error| error.to_string())?;
    let document = document_for_verification(state, &did, verification_method).await?;
    let public_key =
        arkret_identity::jws::resolve_ed25519_pubkey_from_document(&document, verification_method)
            .map_err(|error| error.to_string())?;
    enforce_selected_key_admission(
        &did,
        verification_method,
        &public_key,
        Some(&state.config().trust_domain),
    )?;
    Ok(public_key)
}

/// Resolve the Ed25519 key that was effective at a signed historical instant.
///
/// `did:key` is intrinsically immutable. `did:webvh` is selected from a fully
/// verified method history. Other DID methods fail closed because the current
/// resolver cannot prove which key controlled them at an earlier instant.
pub async fn resolve_ed25519_pubkey_at(
    state: &AppState,
    verification_method: &str,
    at: chrono::DateTime<chrono::Utc>,
) -> Result<VerifyingKey, String> {
    let did = arkret_identity::verification_method_did(verification_method)
        .map_err(|error| error.to_string())?;
    let document = match did.method() {
        "key" => arkret_identity::DidKeyResolver::new()
            .resolve_did_document(&did)
            .map_err(|error| error.to_string())?,
        "webvh" => {
            let pinned = state
                .dids()
                .resolve_webvh_state_at(&did, at)
                .await
                .map_err(|error| error.to_string())?;
            decode_pinned_did_document(&pinned.document)?
        }
        method => {
            return Err(format!(
                "historical verification is unavailable for did:{method}"
            ));
        }
    };
    let public_key =
        arkret_identity::jws::resolve_ed25519_pubkey_from_document(&document, verification_method)
            .map_err(|error| error.to_string())?;
    enforce_selected_key_admission(
        &did,
        verification_method,
        &public_key,
        Some(&state.config().trust_domain),
    )?;
    Ok(public_key)
}

/// Resolve and validate a DID-scoped Ed25519 verification method.
///
/// This is the shared verifier boundary used by federation, recovery and
/// other control-plane endpoints that sign canonical JSON transcripts outside
/// the detached-JWS wrapper. It enforces the same controller and DID-document
/// membership checks before returning the public key.
pub async fn resolve_ed25519_verification_key_for_did(
    state: &AppState,
    did: &Did,
    verification_method: &str,
) -> Result<ResolvedVerificationKey, String> {
    validate_verification_method_controller(did.as_str(), verification_method)?;
    let document = resolve_did_document_async(state, did).await?;
    require_verification_method_in_document(&document, verification_method)?;
    let public_key =
        arkret_identity::jws::resolve_ed25519_pubkey_from_document(&document, verification_method)
            .map_err(|error| error.to_string())?;
    enforce_selected_key_admission(
        did,
        verification_method,
        &public_key,
        Some(&state.config().trust_domain),
    )?;
    let key_log_head = did_document_key_log_head(state, did, &document).await?;
    Ok(ResolvedVerificationKey {
        verification_method: verification_method.to_owned(),
        algorithm: "Ed25519",
        public_key,
        did_document_ref: format!("{}#document", did),
        key_log_head,
    })
}

fn enforce_selected_document_admission(
    document: &DidDocument,
    verification_method: &str,
    trust_domain: Option<&arkret_wire::TrustDomainId>,
) -> Result<(), String> {
    let public_key =
        arkret_identity::jws::resolve_ed25519_pubkey_from_document(document, verification_method)
            .map_err(|error| error.to_string())?;
    enforce_selected_key_admission(&document.id, verification_method, &public_key, trust_domain)
}

fn enforce_selected_key_admission(
    did: &Did,
    verification_method: &str,
    public_key: &VerifyingKey,
    trust_domain: Option<&arkret_wire::TrustDomainId>,
) -> Result<(), String> {
    let verification_method = arkret_wire::DidUrl::new(verification_method.to_owned())
        .map_err(|error| format!("verification_method is not a DID URL: {error}"))?;
    crate::test_material_admission::enforce_ed25519_admission(
        public_key,
        did,
        &verification_method,
        trust_domain,
    )
}

pub fn validate_verification_method_controller(
    controller_principal_id: &str,
    verification_method: &str,
) -> Result<(), String> {
    let method_controller = arkret_identity::verification_method_did(verification_method)
        .map_err(|error| format!("verification method is not a DID URL: {error}"))?;
    let controller_matches = if let Ok(controller_core) =
        arkret_wire::DidCoreId::new(controller_principal_id.to_owned())
    {
        arkret_wire::project_did_to_core_id(&method_controller)
            .is_ok_and(|method_core| method_core == controller_core)
    } else {
        Did::new(controller_principal_id.to_owned())
            .is_ok_and(|controller_did| method_controller == controller_did)
    };
    if !controller_matches {
        return Err("verification method controller does not match DID".to_owned());
    }
    let fragment = verification_method
        .split_once('#')
        .map(|(_, fragment)| fragment)
        .expect("verification_method_did accepted a DID URL with a fragment");
    if fragment.trim().is_empty() {
        return Err("verification method fragment is empty".to_owned());
    }
    Ok(())
}

pub fn resolve_did_document(state: &AppState, did: &Did) -> Result<DidDocument, String> {
    let document = state
        .dids()
        .resolver()
        .resolve_did_document(did)
        .map_err(|error| format!("DID resolution failed: {error}"))?;
    if document.id != *did {
        return Err("resolved DID document id does not match requested DID".to_owned());
    }
    Ok(document)
}

pub async fn resolve_did_document_async(
    state: &AppState,
    did: &Did,
) -> Result<DidDocument, String> {
    let document = state
        .dids()
        .resolve_did(did)
        .await
        .map_err(|error| format!("DID resolution failed: {error}"))?;
    if document.id != *did {
        return Err("resolved DID document id does not match requested DID".to_owned());
    }
    Ok(document)
}

/// DID document freshness gate for high-risk paths (fail-closed-on-stale).
///
/// Fetches the DID's persisted [`WebvhDocumentRecord`] (the ingested
/// document) and evaluates it with [`verify_did_document_freshness`]:
///
/// * [`WebvhFreshness::Fresh`] returns `Ok(())`.
/// * [`WebvhFreshness::Stale`] returns `Err`; the cached public key exceeded the high-risk TTL and
///   must fail closed.
///
/// If persistence has no record for the DID (`get_document` returns `None`),
/// there is no trusted ingestion evidence for high-risk verification and the
/// path also fails closed. Local immediate documents such as dev / extension
/// actors are not persisted here and are handled directly by the SDK resolver
/// inside the SDK resolver chain; this gate only covers cached remote/submitted
/// documents.
///
/// Because coland does not perform on-demand network fetches, "stale" means
/// "unavailable" for high-risk writes; degraded read-only relaxation does not
/// apply here.
pub async fn enforce_high_risk_did_freshness(state: &AppState, did: &Did) -> Result<(), String> {
    // `did:key` is locally resolvable but has neither a version id nor a
    // history head. `did-usage-and-verification.md` section 5.5 requires high
    // risk authority paths to reject every non-pinned binding, including the
    // otherwise legitimate `method_unsupported` terminal state. Persisting a
    // synthetic document must not turn a bootstrap/test DID into a rotatable,
    // history-pinned authority.
    if did.method() == "key" {
        return Err(format!(
            "DID method did:key cannot satisfy high-risk history and version pinning: {did}"
        ));
    }
    let max_age = chrono::Duration::seconds(HIGH_RISK_DID_FRESHNESS_MAX_SECS);
    let record = state
        .dids()
        .document(did.as_str())
        .await
        .map_err(|error| format!("DID freshness lookup failed: {error}"))?;
    let Some(record) = record else {
        // No ingested record means no trusted freshness evidence for a
        // high-risk path, so fail closed.
        return Err(format!(
            "DID document freshness unavailable for high-risk verification: no ingested record for {did}"
        ));
    };
    match evaluate_did_document_freshness(&record, chrono::Utc::now(), max_age) {
        DidDocumentFreshness::Fresh => {
            state
                .cache_resolved_did_document(record)
                .map_err(|error| format!("DID freshness cache failed: {error}"))?;
            Ok(())
        }
        DidDocumentFreshness::Stale => {
            let stale_error = format!(
                "DID document is stale for high-risk verification (exceeded {HIGH_RISK_DID_FRESHNESS_MAX_SECS}s freshness window): {did}"
            );
            if !is_embedded_webvh_document(did, &record) {
                return Err(stale_error);
            }
            if let Err(error) =
                refresh_embedded_webvh_document_for_high_risk(state, did, &record).await
            {
                return Err(format!(
                    "{stale_error}; embedded refresh unavailable: {error}"
                ));
            }
            Ok(())
        }
    }
}

fn is_embedded_webvh_document(
    did: &Did,
    record: &coland_services::identity::DidDocumentState,
) -> bool {
    did.as_str().starts_with("did:webvh:")
        && record
            .method_evidence
            .get("mode")
            .and_then(serde_json::Value::as_str)
            == Some("embedded_webvh_provider")
}

async fn refresh_embedded_webvh_document_for_high_risk(
    state: &AppState,
    did: &Did,
    record: &coland_services::identity::DidDocumentState,
) -> Result<(), String> {
    if !is_embedded_webvh_document(did, record) {
        return Err("document is not a local embedded did:webvh record".to_owned());
    }

    let events = state
        .dids()
        .log_events(did.as_str())
        .await
        .map_err(|error| format!("DID log lookup failed: {error}"))?;
    let Some(last_event) = events.last() else {
        return Err("embedded did:webvh log is empty".to_owned());
    };
    if record.seq != last_event.seq {
        return Err(format!(
            "embedded did:webvh document seq {} does not match log tail seq {}",
            record.seq, last_event.seq
        ));
    }
    if record.key_log_head.as_deref() != Some(last_event.event_digest.as_str()) {
        return Err("embedded did:webvh document head does not match log tail".to_owned());
    }

    let log: Vec<WebvhLogEntry> = events
        .iter()
        .map(|event| WebvhLogEntry::new(event.operation.clone()))
        .collect();
    validate_log_chain(&log).map_err(|error| error.to_string())?;
    verify_scid_against_did(did.as_str(), &log[0]).map_err(|error| error.to_string())?;
    validate_witness_policy_for_log(&log).map_err(|error| error.to_string())?;

    state
        .dids()
        .store_document(record.clone())
        .await
        .map_err(|error| format!("DID document refresh write failed: {error}"))?;
    state
        .cache_resolved_did_document(record.clone())
        .map_err(|error| format!("DID document refresh cache failed: {error}"))?;
    Ok(())
}

pub fn require_verification_method_in_document(
    document: &DidDocument,
    verification_method: &str,
) -> Result<(), String> {
    if document
        .verification_methods
        .contains_key(verification_method)
    {
        return Ok(());
    }
    let fragment = verification_method
        .split_once('#')
        .map(|(_, fragment)| fragment)
        .unwrap_or(verification_method);
    if document.verification_methods.contains_key(fragment) {
        return Ok(());
    }
    Err("verification method is not present in DID document".to_owned())
}

async fn did_document_key_log_head(
    state: &AppState,
    did: &Did,
    document: &DidDocument,
) -> Result<Hash, String> {
    let cached_head = if did.method() == "webvh" {
        state
            .dids()
            .document(did.as_str())
            .await
            .map_err(|error| format!("did:webvh document lookup failed: {error}"))?
            .and_then(|record| record.key_log_head)
    } else {
        None
    };
    key_log_head_for_method(did, document, cached_head)
}

fn key_log_head_for_method(
    did: &Did,
    document: &DidDocument,
    cached_head: Option<String>,
) -> Result<Hash, String> {
    match did.method() {
        "webvh" => {
            let head =
                cached_head.ok_or_else(|| "did:webvh key-log head is unavailable".to_owned())?;
            return Hash::new(head)
                .map_err(|error| format!("did:webvh key-log head is invalid: {error}"));
        }
        "web" => {}
        method => return Err(format!("key-log head is unavailable for did:{method}")),
    }
    let value = serde_json::to_value(document)
        .map_err(|error| format!("DID document serialization failed: {error}"))?;
    let digest = arkret_canonical::canonical_sha256(&value)
        .map_err(|error| format!("DID document canonical digest failed: {error}"))?;
    Hash::new(digest).map_err(|error| format!("DID document digest invalid: {error}"))
}

#[cfg(test)]
mod did_binding_tests {
    use coland_storage_postgres::Db;
    use ed25519_dalek::SigningKey;

    use super::*;

    const PRINCIPAL: &str = "did:web:principal.example";

    /// A state whose resolver chain has no document for [`PRINCIPAL`]. The
    /// `web` method remains registered so the resolver-policy digest is valid
    /// and an accepted binding can be keyed by that policy. Any verification
    /// that succeeds after seeding the binding therefore used the binding; an
    /// authority-path lookup still fails because no document was ingested.
    fn state_without_any_resolver() -> AppState {
        AppState::new(
            crate::config::AppConfig {
                object_storage: crate::config::ObjectStorageConfig::local(
                    std::env::temp_dir().join("coland-did-binding-test"),
                ),
                did_resolver_allow_methods: vec!["web".to_owned()],
                ..crate::config::AppConfig::test_default()
            },
            Db { pool: None },
        )
    }

    #[tokio::test]
    async fn async_ed25519_resolver_uses_the_local_service_notary_document() {
        let state = state_without_any_resolver();
        let method = state.service_verification_method("notary-key").unwrap();
        let resolved = resolve_ed25519_pubkey_async(&state, method.as_str())
            .await
            .expect("the local service notary must not depend on the external DID allowlist");
        assert_eq!(resolved, state.notary_verifying_key());
    }

    #[test]
    fn did_webvh_never_falls_back_to_a_did_web_document_digest() {
        let did = Did::new("did:webvh:z6mkfixture:principal.example".to_owned()).unwrap();
        let key = SigningKey::from_bytes(&[8u8; 32]);
        let document = document_for(&did, &format!("{did}#control-1"), &key);

        let error = key_log_head_for_method(&did, &document, None)
            .expect_err("did:webvh requires its method-native accepted log head");
        assert_eq!(error, "did:webvh key-log head is unavailable");
    }

    #[test]
    fn did_web_uses_the_canonical_document_digest() {
        let did = Did::new(PRINCIPAL.to_owned()).unwrap();
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let document = document_for(&did, &format!("{did}#control-1"), &key);
        let expected = Hash::new(
            arkret_canonical::canonical_sha256(&serde_json::to_value(&document).unwrap()).unwrap(),
        )
        .unwrap();

        assert_eq!(
            key_log_head_for_method(&did, &document, None).unwrap(),
            expected
        );
    }

    fn document_for(did: &Did, verification_method: &str, key: &SigningKey) -> DidDocument {
        DidDocument {
            id: did.clone(),
            verification_methods: BTreeMap::from([(
                verification_method.to_owned(),
                arkret_canonical::ed25519_pubkey_to_did_key_multibase(
                    key.verifying_key().as_bytes(),
                ),
            )]),
            also_known_as: Vec::new(),
            updated_at: Some(chrono::Utc::now()),
            raw_properties: BTreeMap::new(),
        }
    }

    fn did_key_authority(key: &SigningKey) -> (Did, String) {
        let multibase =
            arkret_canonical::ed25519_pubkey_to_did_key_multibase(key.verifying_key().as_bytes());
        let did = Did::new(format!("did:key:{multibase}")).unwrap();
        let verification_method = format!("{did}#{multibase}");
        (did, verification_method)
    }

    #[tokio::test]
    async fn did_key_wrong_fragment_cannot_verify_or_install_an_authority_binding() {
        let state = state_without_any_resolver();
        let key = SigningKey::from_bytes(&[31; 32]);
        let (did, method) = did_key_authority(&key);
        let payload = br#"{"purpose":"did-key-method-binding"}"#;
        let proof = signed(&key, payload);
        let document = arkret_identity::DidKeyResolver::new()
            .resolve_did_document(&did)
            .unwrap();
        verify_jws_with_pinned_document(payload, &proof, &method, did.as_str(), &document).unwrap();
        assert!(state.did_bindings().snapshot().is_empty());
        let wrong = format!("{did}#wrong");
        assert!(
            verify_jws_with_pinned_document(payload, &proof, &wrong, did.as_str(), &document)
                .is_err()
        );
        assert!(resolve_ed25519_pubkey_async(&state, &wrong).await.is_err());
        assert!(principal_binding_acceptance(&state, &did, &wrong, &document).is_err());
        assert!(state.did_bindings().snapshot().is_empty());
    }

    fn signed(key: &SigningKey, payload: &[u8]) -> String {
        arkret_signatures::sign_ed25519_detached_jws(key, payload).expect("detached JWS")
    }

    // §3 / §4 row 4 — historical replay: an Event accepted under the old
    // version still verifies against the document pinned at that time, while the
    // current document refuses the same signature.
    #[test]
    fn historical_replay_uses_the_pinned_document_not_the_current_one() {
        let did = Did::new(PRINCIPAL.to_owned()).unwrap();
        let verification_method = format!("{did}#control-1");
        let old_key = SigningKey::from_bytes(&[9u8; 32]);
        let new_key = SigningKey::from_bytes(&[10u8; 32]);
        let pinned = document_for(&did, &verification_method, &old_key);
        let current = document_for(&did, &verification_method, &new_key);

        let payload = b"historical-event";
        let jws = signed(&old_key, payload);
        verify_jws_with_pinned_document(payload, &jws, &verification_method, did.as_str(), &pinned)
            .expect("the pinned historical document still authenticates the old Event");
        verify_jws_with_pinned_document(
            payload,
            &jws,
            &verification_method,
            did.as_str(),
            &current,
        )
        .expect_err("the rotated current document must not accept the old key");
    }

    #[test]
    fn pinned_document_rejects_issuer_and_method_controller_mismatch() {
        let issuer = Did::new(PRINCIPAL.to_owned()).unwrap();
        let other = Did::new("did:web:other.example".to_owned()).unwrap();
        let verification_method = format!("{issuer}#control-1");
        let key = SigningKey::from_bytes(&[11u8; 32]);
        let document = document_for(&issuer, &verification_method, &key);
        let payload = b"issuer-bound-object";
        let jws = signed(&key, payload);

        verify_jws_with_pinned_document(
            payload,
            &jws,
            &verification_method,
            other.as_str(),
            &document,
        )
        .expect_err("a valid signature cannot substitute a different issuer");

        let other_method = format!("{other}#control-1");
        let other_document = document_for(&issuer, &other_method, &key);
        verify_jws_with_pinned_document(
            payload,
            &signed(&key, payload),
            &other_method,
            issuer.as_str(),
            &other_document,
        )
        .expect_err("a method rooted in another DID cannot control the issuer");
    }

    #[test]
    fn pinned_document_accepts_exact_core_controller_but_rejects_another_core_controller() {
        let issuer = Did::new(PRINCIPAL.to_owned()).unwrap();
        let issuer_core = arkret_wire::project_did_to_core_id(&issuer).unwrap();
        let other_core =
            arkret_wire::DidCoreId::new("ak:did_core:web:other.example".to_owned()).unwrap();
        let verification_method = format!("{issuer}#control-1");
        let key = SigningKey::from_bytes(&[12u8; 32]);
        let document = document_for(&issuer, &verification_method, &key);
        let payload = b"core-controller-bound-object";
        let jws = signed(&key, payload);

        verify_jws_with_pinned_document(
            payload,
            &jws,
            &verification_method,
            issuer_core.as_str(),
            &document,
        )
        .expect("the exact Core controller selects the DID method document");
        verify_jws_with_pinned_document(
            payload,
            &jws,
            &verification_method,
            other_core.as_str(),
            &document,
        )
        .expect_err("a different Core controller cannot borrow the pinned method");
    }

    #[test]
    fn valid_signature_from_published_material_is_denied_without_a_binding() {
        let state = state_without_any_resolver();
        let seed: [u8; 32] = std::array::from_fn(|index| index as u8);
        let published_key = SigningKey::from_bytes(&seed);
        let did = Did::new("did:web:real-deployment.company".to_owned()).unwrap();
        let verification_method = format!("{did}#renamed-production-key");
        let document = document_for(&did, &verification_method, &published_key);
        let previously_safe = document_for(
            &did,
            &verification_method,
            &SigningKey::from_bytes(&[91; 32]),
        );
        let accepted =
            principal_binding_acceptance(&state, &did, &verification_method, &previously_safe)
                .expect("unlisted material can form the previous accepted binding");
        state.did_bindings().accept(accepted).unwrap();
        assert_eq!(state.did_bindings().snapshot().len(), 1);
        let payload = b"otherwise-valid-formal-trust-admission";
        let jws = signed(&published_key, payload);
        let typed_method = arkret_wire::DidUrl::new(verification_method.clone()).unwrap();

        // The SDK formal verifier refuses published fixture material before
        // any signature work, so no layer can treat it as a valid signer.
        assert!(matches!(
            arkret_identity::verify_jws_with_document(
                payload,
                &jws,
                &typed_method,
                &did,
                &document
            ),
            Err(arkret_identity::BindingVerifyError::TestMaterial(
                arkret_identity::test_material::FormalTestMaterialPolicyError::Denied(_)
            ))
        ));
        let binding_error =
            principal_binding_acceptance(&state, &did, &verification_method, &document)
                .expect_err("published material must not form an accepted binding");
        assert_eq!(binding_error, "test_signing_material_denied");
        assert!(state.did_bindings().snapshot().is_empty());
        let error = verify_jws_with_pinned_document(
            payload,
            &jws,
            &verification_method,
            did.as_str(),
            &document,
        )
        .expect_err("formal Coland verification must refuse the published key");

        assert_eq!(error, "test_signing_material_denied");
        assert!(state.did_bindings().snapshot().is_empty());
    }

    // ========================================================================
    // Event proof protected-header hygiene (`encoding.md` §6)
    //
    // These are the regression tests for routing Event proofs through the
    // generic detached-JWS verifier. Each one pairs the Event-profile rejection
    // with a control showing the **generic** profile accepts the very same JWS,
    // so a failure can only mean the Event path degraded back to the generic
    // one — not that the fixture signature happens to be broken.
    // ========================================================================

    /// Sign `payload` as a detached JWS whose protected header is exactly
    /// `header`, including members the Event profile forbids.
    fn detached_jws_with_header(
        key: &SigningKey,
        header: &serde_json::Value,
        payload: &[u8],
    ) -> String {
        use base64::Engine as _;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use ed25519_dalek::Signer as _;

        let header_b64 = URL_SAFE_NO_PAD
            .encode(arkret_canonical::canonical_json_bytes(header).expect("canonical header"));
        let signing_input = format!("{header_b64}.{}", URL_SAFE_NO_PAD.encode(payload));
        let signature = key.sign(signing_input.as_bytes());
        format!(
            "{header_b64}..{}",
            URL_SAFE_NO_PAD.encode(signature.to_bytes())
        )
    }

    /// A minimal but genuine Event proof: real envelope bytes, an
    /// `event_digest` actually derived from them, and the canonical
    /// proof-binding transcript the JWS has to sign.
    fn event_proof_fixture(
        verification_method: &str,
    ) -> (Vec<u8>, arkret_wire::ProducerEventProof) {
        let envelope_bytes =
            br#"{"actor_id":"ak:did_core:web:principal.example","kind":"ak.test.event"}"#.to_vec();
        let event_digest =
            Hash::new(arkret_canonical::sha256_digest(&envelope_bytes)).expect("event digest");
        let proof = arkret_signatures::build_proof_envelope(
            "detached_jws",
            arkret_wire::DidUrl::new(verification_method.to_owned()).expect("DID URL"),
            event_digest,
            None,
            None,
            "",
        );
        (envelope_bytes, proof)
    }

    #[tokio::test]
    async fn identity_resolution_update_rejects_pcr_device_method() {
        let state = state_without_any_resolver();
        let did = Did::new(PRINCIPAL.to_owned()).unwrap();
        let device_id = "ak:device:01904100-0000-7000-8000-000000000002";
        let verification_method = format!("{did}#{device_id}");
        let (envelope_bytes, proof) = event_proof_fixture(&verification_method);
        let actor_id = crate::test_actor_id(&did);
        let actor = arkret_wire::ActorId::service(actor_id.clone());

        let error = verify_registered_identity_resolution_event_proof_async(
            &proof,
            &envelope_bytes,
            &actor,
            &verification_method,
            actor_id.as_str(),
            &state,
        )
        .await
        .expect_err("PCR device keys must not replace current DID authority");
        assert!(error.to_string().contains("current DID authority method"));
    }

    /// The Event protected header is `deny_unknown_fields` and knows no `kid`.
    /// The generic header type accepts `kid` and merely reports it, so a proof
    /// carrying one used to sail through this call site.
    #[tokio::test]
    async fn an_event_proof_with_a_kid_protected_header_is_rejected() {
        let state = state_without_any_resolver();
        let key = SigningKey::from_bytes(&[9u8; 32]);
        let (did, verification_method) = did_key_authority(&key);

        let (envelope_bytes, mut proof) = event_proof_fixture(&verification_method);
        let actor_id = crate::test_actor_id(&did);
        let actor = arkret_wire::ActorId::service(actor_id.clone());
        let binding_bytes = proof
            .canonical_binding_bytes(&actor)
            .expect("binding bytes");
        let jws = detached_jws_with_header(
            &key,
            &serde_json::json!({"alg": "Ed25519", "kid": verification_method}),
            &binding_bytes,
        );
        proof.jws = jws.clone();

        // The Event profile must not.
        verify_registered_identity_resolution_event_proof_async(
            &proof,
            &envelope_bytes,
            &actor,
            &verification_method,
            actor_id.as_str(),
            &state,
        )
        .await
        .expect_err("an Event proof protected header may not carry `kid`");
    }

    /// The Event Ed25519 profile rejects a protected header that selects a
    /// different algorithm.
    #[tokio::test]
    async fn an_event_proof_with_an_unsupported_protected_algorithm_is_rejected() {
        let state = state_without_any_resolver();
        let key = SigningKey::from_bytes(&[9u8; 32]);
        let (did, verification_method) = did_key_authority(&key);

        let (envelope_bytes, mut proof) = event_proof_fixture(&verification_method);
        let actor_id = crate::test_actor_id(&did);
        let actor = arkret_wire::ActorId::service(actor_id.clone());
        let binding_bytes = proof
            .canonical_binding_bytes(&actor)
            .expect("binding bytes");
        proof.jws =
            detached_jws_with_header(&key, &serde_json::json!({"alg": "ES256"}), &binding_bytes);

        verify_registered_identity_resolution_event_proof_async(
            &proof,
            &envelope_bytes,
            &actor,
            &verification_method,
            actor_id.as_str(),
            &state,
        )
        .await
        .expect_err("the Event Ed25519 profile must reject ES256");
    }

    /// Positive control for the two rejections above: a clean current
    /// self-certifying DID authority verifies without any cached binding.
    #[tokio::test]
    async fn a_well_formed_resolution_event_proof_verifies_current_did_authority() {
        let state = state_without_any_resolver();
        let key = SigningKey::from_bytes(&[9u8; 32]);
        let (did, verification_method) = did_key_authority(&key);

        let (envelope_bytes, mut proof) = event_proof_fixture(&verification_method);
        let actor_id = crate::test_actor_id(&did);
        let actor = arkret_wire::ActorId::service(actor_id.clone());
        let binding_bytes = proof
            .canonical_binding_bytes(&actor)
            .expect("binding bytes");
        proof.jws =
            detached_jws_with_header(&key, &serde_json::json!({"alg": "Ed25519"}), &binding_bytes);

        verify_registered_identity_resolution_event_proof_async(
            &proof,
            &envelope_bytes,
            &actor,
            &verification_method,
            actor_id.as_str(),
            &state,
        )
        .await
        .expect("a well-formed Event proof verifies through current DID authority");
    }

    /// The Event verifier re-derives `event_digest` from the envelope bytes it
    /// is handed, so a proof whose transcript names a different Event cannot be
    /// replayed onto this one even with a valid signature.
    #[tokio::test]
    async fn an_event_proof_bound_to_other_envelope_bytes_is_rejected() {
        let state = state_without_any_resolver();
        let key = SigningKey::from_bytes(&[9u8; 32]);
        let (did, verification_method) = did_key_authority(&key);

        let (_, mut proof) = event_proof_fixture(&verification_method);
        let actor_id = crate::test_actor_id(&did);
        let actor = arkret_wire::ActorId::service(actor_id.clone());
        let binding_bytes = proof
            .canonical_binding_bytes(&actor)
            .expect("binding bytes");
        proof.jws =
            detached_jws_with_header(&key, &serde_json::json!({"alg": "Ed25519"}), &binding_bytes);

        verify_registered_identity_resolution_event_proof_async(
            &proof,
            br#"{"actor_id":"ak:did_core:web:principal.example","kind":"ak.other.event"}"#,
            &actor,
            &verification_method,
            actor_id.as_str(),
            &state,
        )
        .await
        .expect_err("the proof transcript is bound to the Event it was signed over");
    }
}
