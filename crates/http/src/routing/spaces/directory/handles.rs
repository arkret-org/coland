use arkret_identifiers::DidCoreId;
use arkret_models_identity::{
    Handle as SdkHandle, HandleClaim as SdkHandleClaim, HandleClaimCore, HandleClaimStatus,
    HandleClaimVariant, HandleVisibility, handle_claim_proof_signing_bytes,
};
use arkret_wire::{
    AccountId, Audience, Hash, PayloadProof, PayloadProofPurpose, SchemaId, proof_kind,
};
use chrono::{DateTime, Utc};
use coland_http::error::AppError;
use serde_json::{Value, json};

use crate::routing::now;
use crate::state::AppState;

pub(crate) async fn signed_handle_claim_value(
    state: &AppState,
    handle: &str,
    principal_id: &str,
    audience: &str,
) -> Result<Value, AppError> {
    let claim = signed_handle_claim(state, handle, principal_id, audience).await?;
    claim
        .validate()
        .map_err(|error| AppError::internal(format!("handle claim validation failed: {error}")))?;
    serde_json::to_value(claim)
        .map_err(|error| AppError::internal(format!("handle claim serialization failed: {error}")))
}

async fn signed_handle_claim(
    state: &AppState,
    handle: &str,
    principal_id: &str,
    audience: &str,
) -> Result<SdkHandleClaim, AppError> {
    if let Err(rejection) = coland_http::wire_validators::handle_claim_subject::validate_subject(
        &json!({ "subject_id": principal_id }),
    ) {
        return Err(crate::app_error!(SchemaViolation, rejection.message));
    }

    let default_domain = service_handle_domain(state);
    let parsed = if handle.starts_with("acct:") {
        SdkHandle::from_acct(handle)
    } else {
        let without_sigil = handle.strip_prefix('@').unwrap_or(handle);
        if without_sigil.contains(':') || without_sigil.contains('@') {
            SdkHandle::prepare(handle)
        } else {
            SdkHandle::prepare(&format!("{without_sigil}:{default_domain}"))
        }
    }
    .map_err(|_| AppError::param_invalid("handle must be canonicalizable"))?;
    if parsed.domain() != default_domain {
        return Err(handle_unverified_error(parsed.canonical()));
    }
    require_local_handle_binding(state, principal_id, parsed.canonical(), parsed.localpart())
        .await?;

    let subject = DidCoreId::new(principal_id.to_owned())
        .map_err(|error| AppError::internal(format!("invalid handle subject: {error}")))?;
    let signer_id = DidCoreId::new(state.service_id().clone())
        .map_err(|error| AppError::internal(format!("invalid handle issuer: {error}")))?;
    let issued_at = now();
    let placeholder = handle_claim_proof(
        state,
        Hash::new(format!("sha256:{}", "0".repeat(64)))
            .map_err(|error| AppError::internal(format!("placeholder digest: {error}")))?,
        PayloadProofPurpose::IssuerAttestation,
        issued_at,
        None,
    )?;
    let mut core = HandleClaimCore {
        schema: HandleClaimCore::SCHEMA.to_owned(),
        handle_aliases: vec![parsed.to_acct()],
        handle: parsed,
        subject_account_id: AccountId::new(subject, state.service_core_id().clone()),
        issuer_id: signer_id.clone(),
        claim: HandleClaimVariant::HandleBinding,
        visibility: HandleVisibility::Public,
        audience: None,
        issued_at,
        expires_at: Some(issued_at + chrono::Duration::hours(24)),
        source_refs: Vec::new(),
        proofs: [placeholder.clone(), placeholder],
    };
    let claim_digest = core
        .claim_digest()
        .map_err(|error| AppError::internal(format!("handle claim digest failed: {error}")))?;
    core.proofs = [
        handle_claim_proof(
            state,
            claim_digest.clone(),
            PayloadProofPurpose::IssuerAttestation,
            issued_at,
            None,
        )?,
        handle_claim_proof(
            state,
            claim_digest.clone(),
            PayloadProofPurpose::HolderAcceptance,
            issued_at,
            None,
        )?,
    ];
    let mut claim = SdkHandleClaim {
        schema: SchemaId::HANDLE_CLAIM_V1.to_owned(),
        claim: core,
        status: HandleClaimStatus::Verified,
        evaluated_at: issued_at,
        verifier_id: signer_id,
        verified_at: Some(issued_at),
        revocation: None,
        cache_expires_at: issued_at + chrono::Duration::minutes(5),
        status_proof: handle_claim_proof(
            state,
            claim_digest,
            PayloadProofPurpose::StatusAttestation,
            issued_at,
            Some(audience),
        )?,
    };
    claim.status_proof = handle_claim_proof(
        state,
        claim
            .status_digest()
            .map_err(|error| AppError::internal(format!("handle status digest failed: {error}")))?,
        PayloadProofPurpose::StatusAttestation,
        issued_at,
        Some(audience),
    )?;
    Ok(claim)
}

fn service_handle_domain(state: &AppState) -> String {
    reqwest::Url::parse(&state.config().public_base_url)
        .ok()
        .and_then(|url| url.host_str().map(ToOwned::to_owned))
        .and_then(|host| arkret_wire::string_profiles::prepare_idna_domain(&host).ok())
        .unwrap_or_else(|| "coland.local".to_owned())
}

async fn require_local_handle_binding(
    state: &AppState,
    principal_id: &str,
    canonical_handle: &str,
    localpart: &str,
) -> Result<(), AppError> {
    let owner = state
        .identities()
        .localpart_owner(localpart)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    let Some(owner) = owner else {
        return Err(handle_unverified_error(canonical_handle));
    };
    let profile = state
        .identities()
        .account_by_id(owner.account_pk)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    if profile.is_some_and(|record| record.principal_id.as_str() == principal_id) {
        Ok(())
    } else {
        Err(handle_unverified_error(canonical_handle))
    }
}

fn handle_unverified_error(canonical_handle: &str) -> AppError {
    AppError::capability_denied(format!(
        "handle `{canonical_handle}` is not bound to the subject account"
    ))
    .with_internal_reason("handle_unverified")
}

fn handle_claim_proof(
    state: &AppState,
    payload_digest: Hash,
    proof_purpose: PayloadProofPurpose,
    created_at: DateTime<Utc>,
    audience: Option<&str>,
) -> Result<PayloadProof, AppError> {
    let verification_method = arkret_wire::DidUrl::new(format!(
        "{}#directory-handle-claim",
        state.service_resolution_commitment().did
    ))
    .map_err(|error| AppError::internal(format!("handle claim method: {error}")))?;
    let domain = match proof_purpose {
        PayloadProofPurpose::IssuerAttestation | PayloadProofPurpose::HolderAcceptance => {
            arkret_models_identity::HANDLE_CLAIM_PROOF_DOMAIN
        }
        PayloadProofPurpose::StatusAttestation => {
            arkret_models_identity::HANDLE_CLAIM_STATUS_DOMAIN
        }
        _ => return Err(AppError::internal("invalid HandleClaim proof purpose")),
    };
    let mut proof = PayloadProof {
        kind: proof_kind::DETACHED_JWS.to_owned(),
        verification_method,
        payload_digest,
        created_at,
        domain: Some(domain.to_owned()),
        audience: audience.map(|value| Audience::Single(value.to_owned())),
        proof_purpose: Some(proof_purpose),
        jws: String::new(),
    };
    let signing_bytes = handle_claim_proof_signing_bytes(&proof)
        .map_err(|error| AppError::internal(format!("handle claim transcript: {error}")))?;
    proof.jws = arkret_signatures::jws::sign_jws_ed25519(
        &signing_bytes,
        state.notary_signing_key().as_ref(),
    )
    .map_err(|error| AppError::internal(format!("handle claim sign: {error}")))?;
    Ok(proof)
}
