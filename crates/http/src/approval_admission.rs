//! Historical method authority for detached Event admission approvals.
use coland_services::{ServiceError, ServiceResult};
use coland_storage::{ApprovalHistoricalMethod, EventApprovalCommit};

use crate::state::AppState;

pub(crate) async fn prepare_event_approvals(
    state: &AppState,
    submission: &arkret_wire::EventAdmissionSubmission,
    at: chrono::DateTime<chrono::Utc>,
) -> ServiceResult<Option<EventApprovalCommit>> {
    let Some(signatures) = &submission.approval_signatures else {
        return Ok(None);
    };
    submission
        .validate()
        .map_err(|e| ServiceError::SchemaViolation(e.to_string()))?;
    let mut methods = Vec::with_capacity(signatures.len());
    for signature in signatures {
        let crypt_code = if matches!(
            signature.input.approval_context,
            arkret_wire::ApprovalContext::ListWip { .. }
        ) {
            "approval_required"
        } else {
            "signature_invalid"
        };
        signature
            .validate()
            .map_err(|e| ServiceError::SchemaViolation(e.to_string()))?;
        signature
            .input
            .validate_approved_at(at)
            .map_err(|error| ServiceError::Conflict(format!("{crypt_code}: {error}")))?;
        let method = signature.proof.verification_method.as_str();
        let did = arkret_identity::verification_method_did(method)
            .map_err(|error| ServiceError::SchemaViolation(error.to_string()))?;
        // Accepted-at evidence uses the signing-time authenticated DID history,
        // never current PCR devices or the target Event producer proof.
        let (public_key, native_control, control_history) = if signature.input.approver_did.method()
            == "webvh"
            && did.method() == "key"
        {
            let principal = arkret_wire::project_did_to_core_id(&signature.input.approver_did)
                .map_err(|e| ServiceError::SchemaViolation(e.to_string()))?;
            let (key, selected) = crate::principal_control::resolve_native_identity_control(
                state,
                &signature.input.approver_did,
                &principal,
                &signature.proof.verification_method,
                signature.input.approved_at,
                arkret_identity::principal_control::DirectIdentityControlPurpose::ApprovalSignature,
            )
            .await
            .map_err(|_| {
                ServiceError::Conflict(format!(
                    "{crypt_code}: native approval control is unavailable"
                ))
            })?;
            let history = serde_json::json!({"did":selected.did,"version_id":selected.version_id,
                "log_head_digest":selected.log_head_digest,"update_keys":selected.update_keys,
                "verified_at":arkret_canonical::format_timestamp_canonical(signature.input.approved_at)});
            (*key.public_key(), Some(key), Some(history))
        } else {
            if did != signature.input.approver_did {
                return Err(ServiceError::Conflict(format!(
                    "{crypt_code}: approval method controller differs"
                )));
            }
            let public_key = crate::jws_verify::resolve_ed25519_pubkey_at(
                state,
                method,
                signature.input.approved_at,
            )
            .await
            .map_err(|_| {
                ServiceError::Conflict(format!(
                    "{crypt_code}: historical approval method is unavailable"
                ))
            })?
            .to_bytes();
            (public_key, None, None)
        };
        methods.push(ApprovalHistoricalMethod {
            signature: signature.clone(),
            public_key,
            native_control,
            control_history,
        });
    }
    Ok(Some(EventApprovalCommit {
        event_id: submission.event.event_id.clone(),
        event_digest: arkret_canonical::canonical_sha256(&submission.event)
            .map_err(|error| ServiceError::SchemaViolation(error.to_string()))?,
        committed_at: at,
        methods,
    }))
}
