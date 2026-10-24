use super::*;

/// Validate the published policy document and return the account it binds.
pub(super) fn validate_recovery_policy(
    payload: &Value,
) -> Result<arkret_wire::AccountId, AppError> {
    let typed: RecoveryPolicy = serde_json::from_value(payload.clone()).map_err(|error| {
        AppError::schema_violation(format!("recovery policy violates SDK shape: {error}"))
    })?;
    reject_unexecutable_recovery_policy(&typed)?;
    typed.validate_shape().map_err(|error| {
        AppError::schema_violation(format!(
            "recovery policy violates protocol invariants: {error}"
        ))
    })?;
    require_const_string(payload, "schema", arkret_wire::SchemaId::RECOVERY_POLICY_V1)?;
    let policy_id = require_string(payload, "policy_id")?;
    require_policy_id_pattern(&policy_id)?;
    let account_id = typed.account_id.clone();
    let version = require_u32_min(payload, "version", 1)?;
    let supersedes_id = match payload.get("supersedes_id") {
        Some(Value::Null) | None => None,
        Some(Value::String(s)) => {
            require_policy_id_pattern(s)?;
            Some(s.clone())
        }
        _ => {
            return Err(AppError::param_invalid(
                "supersedes_id must be null or a ak:policy:<uuidv7> string",
            ));
        }
    };
    if version == 1 && supersedes_id.is_some() {
        return Err(AppError::param_invalid(
            "genesis policy (version=1) MUST have supersedes_id=null",
        ));
    }
    if version > 1 && supersedes_id.is_none() {
        return Err(AppError::param_invalid(
            "non-genesis policy MUST name a predecessor in supersedes_id",
        ));
    }
    let issued_at = require_rfc3339(payload, "issued_at")?;
    let expires_at = match payload.get("expires_at") {
        Some(Value::Null) | None => None,
        Some(Value::String(s)) => {
            let parsed = chrono::DateTime::parse_from_rfc3339(s)
                .map_err(|_| AppError::param_invalid("expires_at must be rfc3339"))?;
            Some(parsed.with_timezone(&chrono::Utc))
        }
        _ => {
            return Err(AppError::param_invalid(
                "expires_at must be null or rfc3339",
            ));
        }
    };
    if let Some(exp) = expires_at
        && exp <= issued_at
    {
        return Err(AppError::param_invalid(
            "expires_at MUST be strictly after issued_at",
        ));
    }
    let signature_proof = payload
        .get("signature_proof")
        .and_then(Value::as_object)
        .ok_or_else(|| AppError::param_invalid("signature_proof is required"))?;
    signature_proof
        .get("verification_method")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            AppError::param_invalid("signature_proof.verification_method is required")
        })?;
    let signature_algorithm = signature_proof
        .get("signature_algorithm")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            AppError::param_invalid("signature_proof.signature_algorithm is required")
        })?;
    if signature_algorithm != "Ed25519" {
        return Err(AppError::param_invalid(format!(
            "signature_proof.signature_algorithm `{signature_algorithm}` not in {{Ed25519, Ed25519}}",
        )));
    }
    signature_proof
        .get("signature")
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::param_invalid("signature_proof.signature is required"))?;
    Ok(account_id)
}

/// key-management.md §8.1 — publish / rotate MUST reject a policy the receiving
/// deployment cannot execute, instead of accepting it and only failing when a
/// real recovery is attempted. Every rejection here is `failed_precondition`.
fn recovery_policy_unexecutable(message: impl Into<String>) -> AppError {
    crate::app_error!(FailedPrecondition, message.into())
}

fn reject_unexecutable_recovery_policy(policy: &RecoveryPolicy) -> Result<(), AppError> {
    for method in &policy.methods {
        match method {
            arkret_models_crypto::RecoveryMethod::DidRoot => {}
            arkret_models_crypto::RecoveryMethod::RecoveryUnlock { keys } => {
                for key in keys {
                    if key.not_before >= key.expires_at
                        || key
                            .revoked_at
                            .is_some_and(|revoked_at| revoked_at < key.not_before)
                    {
                        return Err(recovery_policy_unexecutable(
                            "recovery_unlock key validity interval is empty or self-contradictory",
                        ));
                    }
                    let hpke = &key.backup_hpke;
                    if hpke.not_before >= hpke.expires_at
                        || hpke
                            .revoked_at
                            .is_some_and(|revoked_at| revoked_at < hpke.not_before)
                        || hpke.key_agreement_ref.as_str() == key.verification_method.as_str()
                    {
                        return Err(recovery_policy_unexecutable(
                            "recovery_unlock backup_hpke entry is unusable for this signing key",
                        ));
                    }
                }
            }
            arkret_models_crypto::RecoveryMethod::DeviceQuorum { k, member_ids } => {
                let distinct = member_ids.iter().collect::<BTreeSet<_>>().len();
                if usize::try_from(*k).unwrap_or(usize::MAX) > distinct {
                    return Err(recovery_policy_unexecutable(format!(
                        "device_quorum k={k} exceeds {distinct} distinct member devices"
                    )));
                }
            }
            arkret_models_crypto::RecoveryMethod::TrustedRecoveryService { services } => {
                for service in services {
                    let controller = arkret_identity::verification_method_did(
                        service.authorization_verification_method.as_str(),
                    )
                    .map_err(|error| {
                        recovery_policy_unexecutable(format!(
                            "trusted_recovery_service authorization_verification_method is not a DID URL: {error}"
                        ))
                    })?;
                    let controller_core = arkret_wire::project_did_to_core_id(&controller)
                        .map_err(|error| {
                            recovery_policy_unexecutable(format!(
                                "trusted_recovery_service controller DID is not projectable: {error}"
                            ))
                        })?;
                    if controller_core != service.service_id {
                        return Err(recovery_policy_unexecutable(
                            "trusted_recovery_service authorization_verification_method controller does not equal service_id",
                        ));
                    }
                }
            }
        }
    }
    Ok(())
}

pub(super) fn recovery_signature_error(message: impl Into<String>) -> AppError {
    crate::app_error!(SignatureInvalid, message.into())
        .with_reason_code(arkret_wire::ReasonCode::PROOF_INVALID)
}

/// A recovery proof is not bound to the expected (recovery policy, session,
/// recovery key entry) tuple. Registry-canonical `recovery_evidence_unbound`.
pub(super) fn recovery_evidence_unbound_error(message: impl Into<String>) -> AppError {
    crate::app_error!(SignatureInvalid, message.into())
        .with_reason_code("recovery_evidence_unbound")
}

/// `security-transactions.md` §2.2 — the receipt `completed_at` is the
/// replacement device authoring "completed if every check passes". That moment
/// can never be later than the commit that would make it true, so a later
/// timestamp is a deterministic rejection of the whole submission, with zero
/// authoritative writes. v1 defines no skew allowance in either direction: the
/// Station neither waits for the client clock nor signs a future-dated
/// attestation.
pub(super) fn validate_recovery_receipt_completed_at(
    receipt_completed_at: chrono::DateTime<chrono::Utc>,
    linearized_commit_at: chrono::DateTime<chrono::Utc>,
) -> Result<(), AppError> {
    if receipt_completed_at > linearized_commit_at {
        return Err(crate::app_error!(
            FailedPrecondition,
            "recovery receipt completed_at is later than the linearized commit time",
        )
        .with_reason_code(arkret_wire::ReasonCode::RECOVERY_RECEIPT_COMPLETED_AT_AFTER_COMMIT));
    }
    Ok(())
}

// ── Small helpers ─────────────────────────────────────────────────────

pub(super) fn require_const_string(
    payload: &Value,
    key: &str,
    expected: &str,
) -> Result<(), AppError> {
    let value = payload
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::param_invalid(format!("{key} is required")))?;
    if value != expected {
        return Err(AppError::param_invalid(format!(
            "{key} must be `{expected}` (got `{value}`)"
        )));
    }
    Ok(())
}

pub(super) fn require_string(payload: &Value, key: &str) -> Result<String, AppError> {
    payload
        .get(key)
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .ok_or_else(|| AppError::param_invalid(format!("{key} is required")))
}

pub(super) fn require_u32_min(payload: &Value, key: &str, min: u64) -> Result<u32, AppError> {
    let value = payload
        .get(key)
        .and_then(Value::as_u64)
        .ok_or_else(|| AppError::param_invalid(format!("{key} is required (integer)")))?;
    if value < min {
        return Err(AppError::param_invalid(format!(
            "{key} must be >= {min} (got {value})",
        )));
    }
    if value > u32::MAX as u64 {
        return Err(AppError::param_invalid(format!(
            "{key} must fit in u32 (got {value})",
        )));
    }
    Ok(value as u32)
}

pub(super) fn require_rfc3339(
    payload: &Value,
    key: &str,
) -> Result<chrono::DateTime<chrono::Utc>, AppError> {
    let value = require_string(payload, key)?;
    let parsed = chrono::DateTime::parse_from_rfc3339(&value)
        .map_err(|_| AppError::param_invalid(format!("{key} must be rfc3339")))?;
    Ok(parsed.with_timezone(&chrono::Utc))
}

pub(super) fn require_policy_id_pattern(value: &str) -> Result<(), AppError> {
    if !value.starts_with("ak:policy:") {
        return Err(AppError::param_invalid(format!(
            "policy_id `{value}` must start with ak:policy:",
        )));
    }
    let uuid_part = value.trim_start_matches("ak:policy:");
    let parsed = uuid::Uuid::parse_str(uuid_part)
        .map_err(|_| AppError::param_invalid("policy_id MUST be ak:policy:<uuidv7>"))?;
    if parsed.get_version_num() != 7 {
        return Err(AppError::param_invalid(
            "policy_id MUST be uuidv7 (version 7)",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_receipt_authored_after_the_commit_is_refused_with_its_registered_reason() {
        let commit = chrono::Utc::now();
        // Authored at or before the commit: "completed if every check passes"
        // is still true at the moment the commit makes it true.
        validate_recovery_receipt_completed_at(commit, commit).unwrap();
        validate_recovery_receipt_completed_at(commit - chrono::Duration::hours(1), commit)
            .unwrap();
        // v1 defines no skew allowance, so a single millisecond later is the
        // deterministic refusal, not a tolerated clock difference.
        let error = validate_recovery_receipt_completed_at(
            commit + chrono::Duration::milliseconds(1),
            commit,
        )
        .expect_err("a future-dated receipt is refused");
        assert_eq!(
            error.reason_code.as_deref(),
            Some(arkret_wire::ReasonCode::RECOVERY_RECEIPT_COMPLETED_AT_AFTER_COMMIT)
        );
    }
}
