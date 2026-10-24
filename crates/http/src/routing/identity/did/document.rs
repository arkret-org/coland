//! DID document rendering, validation, and operation-application helpers.

use super::*;

pub(super) fn render_json_bytes(res: &mut Response, content_type: &str, value: &Value) {
    let body = serde_json::to_vec(value).unwrap_or_else(|_| b"{}".to_vec());
    res.headers_mut()
        .insert(header::CONTENT_TYPE, content_type.parse().unwrap());
    res.headers_mut().insert(
        header::CONTENT_LENGTH,
        body.len().to_string().parse().unwrap(),
    );
    res.write_body(body).ok();
}

/// Run G3.S3 webvh validation gates (prev_hash chain + SCID mismatch +
/// witness quorum/degraded-window validation) over a DID's locally-cached
/// log before trusting the resolved document. Spec: identity-did.md
/// §3.4 / §4.2.1 / §3 ("DNS hijack protection") / §3.4 "controller
/// proof".
pub(super) async fn run_webvh_resolution_checks(
    state: &AppState,
    did: &str,
    document: &WebvhDocumentRecord,
) -> Result<Option<IdentityMethodEvidence>, AppError> {
    let events = state.dids().log_events(did).await.map_err(|error| {
        tracing::error!(%error, %did, "failed to read webvh log during resolution checks");
        AppError::internal("failed to read did:webvh log")
    })?;
    if events.is_empty() {
        // No local log to validate — the resolver falls through to the
        // SDK resolver path higher up. We do not fail closed
        // here because the cached document may legitimately come from
        // an external resolver.
        return Ok(None);
    }
    let log: Vec<WebvhLogEntry> = events
        .iter()
        .map(|event| WebvhLogEntry::new(event.operation.clone()))
        .collect();
    validate_log_chain(&log)?;
    let genesis = &log[0];
    verify_scid_against_did(did, genesis)?;
    verify_log_subject(&document.did, &log)?;
    validate_witness_policy_for_log(&log)?;
    // Rotation control authorisation (identity-did.md §7 controller proof,
    // §8.1–§8.2 governance quorum, key-management.md §3.3 recovery key). Kept
    // distinct from witness quorum above: witnesses prove history visibility,
    // these proofs prove who is allowed to change the DID.
    validate_rotation_authorization_for_log(&log)?;
    let head = log.last().ok_or_else(|| {
        crate::app_error!(
            CurrentDidAuthorityUnavailable,
            "verified did:webvh history has no current head",
        )
    })?;
    let version_id = NonEmptyString::new(
        head.version_id()
            .ok_or_else(|| {
                crate::app_error!(
                    CurrentDidAuthorityUnavailable,
                    "verified did:webvh head has no versionId",
                )
            })?
            .to_owned(),
    )
    .map_err(|error| {
        crate::app_error!(
            CurrentDidAuthorityUnavailable,
            format!("verified did:webvh head has invalid versionId: {error}"),
        )
    })?;
    let log_head_digest = Hash::new(
        arkret_canonical::canonical_sha256(&head.payload)
            .map_err(|error| AppError::internal(format!("failed to digest WebVH head: {error}")))?,
    )
    .map_err(|error| AppError::internal(format!("invalid WebVH head digest: {error}")))?;
    let persisted_head = events.last().ok_or_else(|| {
        crate::app_error!(
            CurrentDidAuthorityUnavailable,
            "verified did:webvh history has no durable head",
        )
    })?;
    if persisted_head.event_digest != log_head_digest.as_str() {
        return Err(crate::app_error!(
            CurrentDidAuthorityUnavailable,
            "durable did:webvh head digest does not match the verified log entry",
        ));
    }
    let did = Did::new(did.to_owned()).map_err(|error| {
        crate::app_error!(
            CurrentDidAuthorityUnavailable,
            format!("verified did:webvh subject is invalid: {error}"),
        )
    })?;
    // A valid history can end in deactivation, or its newest signed version
    // can be later than this resolution. Neither is current control authority.
    // Take updateKeys from the selected, fully verified native entry.
    let current = state
        .dids()
        .resolve_webvh_state_at(&did, chrono::Utc::now())
        .await
        .map_err(|error| {
            crate::app_error!(
                CurrentDidAuthorityUnavailable,
                format!("current did:webvh control state is unavailable: {error}"),
            )
        })?;
    if current.status != coland_services::identity::PinnedDidVersionStatus::Current
        || current.version_id != version_id.as_str()
        || current.log_head_digest != log_head_digest
        || document.key_log_head.as_deref() != Some(log_head_digest.as_str())
        || document.sequence != persisted_head.sequence
        || document.did_document != current.document
    {
        return Err(crate::app_error!(
            CurrentDidAuthorityUnavailable,
            "did:webvh control state is not the same active verified head",
        ));
    }
    let update_key = current.update_keys.first().ok_or_else(|| {
        crate::app_error!(
            CurrentDidAuthorityUnavailable,
            "verified did:webvh control state has no active updateKeys[0]",
        )
    })?;
    let update_key = update_key.strip_prefix("did:key:").unwrap_or(update_key);
    let control_key_bytes =
        arkret_canonical::decode_ed25519_multibase(update_key).map_err(|error| {
            crate::app_error!(
                CurrentDidAuthorityUnavailable,
                format!("verified did:webvh active update key is invalid: {error}"),
            )
        })?;
    let control_key_digest = Hash::new(format!(
        "sha256:{}",
        arkret_canonical::sha256_hex(control_key_bytes)
    ))
    .map_err(|error| AppError::internal(format!("invalid WebVH control-key digest: {error}")))?;
    Ok(Some(IdentityMethodEvidence::DidWebvh {
        version_id,
        control_key_digest,
    }))
}

pub(super) fn federation_peer_id_document(state: &AppState, did: &str) -> Option<Value> {
    let verification_method = format!("{did}#notary-key");
    let key = state.federation_peer_verification_method_key(&verification_method)?;
    let public_key = arkret_canonical::ed25519_pubkey_to_did_key_multibase(key.as_bytes());
    Some(json!({
        "id": did,
        "verificationMethod": [{
            "id": verification_method,
            "type": "Multikey",
            "controller": did,
            "publicKeyMultibase": public_key,
        }],
        "authentication": [verification_method],
        "assertionMethod": [verification_method],
    }))
}
