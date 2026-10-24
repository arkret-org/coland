use super::*;

pub(super) fn schema_error(message: impl Into<String>) -> AppError {
    crate::app_error!(SchemaViolation, message)
}

fn failed_precondition(message: impl Into<String>, reason: &str) -> AppError {
    crate::app_error!(FailedPrecondition, message).with_internal_reason(reason)
}

pub(super) fn is_base64url_token(value: &str) -> bool {
    !value.is_empty()
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_')
}

pub(super) fn is_sha_digest(value: &str) -> bool {
    // Key-backup ciphertext digests and key commitments are restricted
    // to sha256 per key-management.md: exactly the `sha256:` prefix followed by 64
    // lowercase hex characters. The SDK `Hash` type intentionally accepts the wider
    // multi-algorithm digest vocabulary (blake3 / sha3_256 / sha512), so this gate
    // must enforce the sha256-only shape itself rather than delegate to `Hash::new`.
    let Some(hex) = value.strip_prefix("sha256:") else {
        return false;
    };
    hex.len() == 64
        && hex
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub(super) fn key_backup_to_value(backup: &KeyBackup) -> Result<Value, AppError> {
    serde_json::to_value(backup)
        .map_err(|error| AppError::internal(format!("key backup body re-encode failed: {error}")))
}

pub(super) fn validate_key_backup_body_typed(
    backup_id: &BackupId,
    actor_id: &arkret_wire::ActorId,
    backup: &KeyBackup,
) -> Result<(), AppError> {
    backup
        .validate()
        .map_err(|error| schema_error(format!("invalid key backup: {error}")))?;
    if backup.backup_id.as_str() != backup_id.as_str() {
        return Err(crate::app_error!(
            SchemaViolation,
            "path backup_id must match body backup_id",
        ));
    }
    if &backup.actor_id != actor_id {
        return Err(AppError::capability_denied(
            "backup actor_id must match authenticated actor",
        ));
    }
    validate_key_backup_encryption_typed(backup)?;
    validate_key_backup_domain_separation_typed(backup)?;
    validate_recovery_policy_ref_shape_typed(backup)?;
    validate_key_backup_auth_data_typed(backup)?;
    validate_key_backup_ciphertext_digest_typed(backup)?;
    if backup.contents.is_empty() {
        return Err(schema_error("key backup contents must not be empty"));
    }
    // KeyBackup::validate checks every closed secret_storage content entry.
    Ok(())
}

pub(super) fn validate_key_backup_ciphertext_digest_typed(
    backup: &KeyBackup,
) -> Result<(), AppError> {
    let ciphertext = arkret_canonical::base64url_decode(backup.ciphertext.as_str())
        .map_err(|_| schema_error("key backup ciphertext must be canonical base64url"))?;
    arkret_canonical::verify_digest(&ciphertext, backup.ciphertext_digest.as_str())
        .map_err(|_| schema_error("key backup ciphertext_digest does not match ciphertext"))
}

pub(super) fn validate_key_backup_session_device(
    backup: &KeyBackup,
    session_device_id: &str,
) -> Result<(), AppError> {
    if backup.signature_proof.device_id.as_str() != session_device_id {
        return Err(AppError::capability_denied(
            "key backup signer device must match the authenticated session device",
        ));
    }
    Ok(())
}

pub(super) fn validate_key_backup_encryption_typed(backup: &KeyBackup) -> Result<(), AppError> {
    // key-management.md 7.9: an unknown, reserved (`ak.aead.hybrid_kem.*`) or
    // name-contradicting `aead_profile` fails closed under its own registered
    // reason code. It is checked ahead of the per-method field sets because a
    // profile the receiver cannot resolve makes every derived parameter
    // unverifiable.
    backup
        .encryption
        .aead
        .validate_aead_profile()
        .map_err(|reason| {
            schema_error(format!(
                "key backup encryption.aead.aead_profile `{}` is not an active registered profile",
                backup.encryption.aead.aead_profile.as_deref().unwrap_or("")
            ))
            .with_reason_code(reason)
        })?;
    match backup.encryption.recipient_method {
        KeyBackupRecipientMethod::PassphraseKdf => {
            validate_key_backup_kdf_typed(backup)?;
            let nonce_salt = backup
                .encryption
                .aead
                .nonce_salt
                .as_deref()
                .unwrap_or_default();
            if !is_base64url_token(nonce_salt) {
                return Err(schema_error(
                    "passphrase_kdf key backup requires base64url encryption.aead.nonce_salt",
                ));
            }
            let key_commitment = backup
                .encryption
                .key_commitment
                .as_ref()
                .map(arkret_wire::Hash::as_str)
                .unwrap_or_default();
            if !is_sha_digest(key_commitment) {
                return Err(schema_error(
                    "passphrase_kdf key backup requires a sha-digest encryption.key_commitment",
                ));
            }
            Ok(())
        }
        KeyBackupRecipientMethod::SecretStorageKey => {
            if backup.encryption.kdf.is_some() {
                return Err(schema_error(
                    "secret_storage_key key backups must not carry encryption.kdf",
                ));
            }
            if backup
                .encryption
                .recipient_key_ref
                .as_deref()
                .is_none_or(|recipient| recipient.trim().is_empty())
            {
                return Err(schema_error(
                    "secret_storage_key key backup requires a non-empty recipient_key_ref",
                ));
            }
            Ok(())
        }
        KeyBackupRecipientMethod::RecoveryPublicKey => {
            if backup
                .encryption
                .recipient_key_ref
                .as_deref()
                .is_none_or(|recipient| recipient.trim().is_empty())
            {
                return Err(schema_error(
                    "recovery_public_key key backup requires a non-empty recipient_key_ref",
                ));
            }
            let enc = backup.encryption.aead.enc.as_deref().unwrap_or_default();
            if !is_base64url_token(enc) {
                return Err(schema_error(
                    "recovery_public_key key backup requires base64url encryption.aead.enc",
                ));
            }
            if backup.encryption.kdf.is_some() {
                return Err(schema_error(
                    "recovery_public_key key backups must not carry encryption.kdf",
                ));
            }
            Ok(())
        }
    }
}

pub(super) fn valid_key_backup_subdomain(value: &str) -> bool {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    first.is_ascii_lowercase()
        && value.len() <= 64
        && chars.all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '_')
}

pub(super) fn validate_key_backup_domain_separation_typed(
    backup: &KeyBackup,
) -> Result<(), AppError> {
    let domain = &backup.domain_separation;
    if !valid_key_backup_subdomain(&domain.subdomain) {
        return Err(schema_error(
            "domain_separation.subdomain must match [a-z][a-z0-9_]{0,63}",
        ));
    }
    Ok(())
}

pub(super) fn validate_key_backup_kdf_typed(backup: &KeyBackup) -> Result<(), AppError> {
    let kdf = backup
        .encryption
        .kdf
        .as_ref()
        .ok_or_else(|| schema_error("passphrase_kdf key backup requires encryption.kdf"))?;
    match kdf.name {
        KeyBackupKdfName::Argon2id => {
            let memory_floor = if backup.mixed_secret_storage {
                262_144
            } else {
                65_536
            };
            let iteration_floor = if memory_floor == 262_144 { 4 } else { 3 };
            if kdf
                .parameters
                .memory_kib
                .is_none_or(|value| value < memory_floor)
            {
                return Err(schema_error(format!(
                    "argon2id parameters.memory_kib must be >= {memory_floor}"
                )));
            }
            if kdf
                .parameters
                .iterations
                .is_none_or(|value| value < iteration_floor)
            {
                return Err(schema_error(format!(
                    "argon2id parameters.iterations must be >= {iteration_floor}"
                )));
            }
            if kdf.parameters.parallelism.is_none_or(|value| value < 1) {
                return Err(schema_error("argon2id parameters.parallelism must be >= 1"));
            }
        }
        KeyBackupKdfName::Pbkdf2 => {
            if kdf
                .parameters
                .iterations
                .is_none_or(|value| value < 600_000)
            {
                return Err(schema_error(
                    "pbkdf2 parameters.iterations must be >= 600000",
                ));
            }
            if kdf.parameters.digest_algorithm.is_none() {
                return Err(schema_error(
                    "pbkdf2 parameters.digest_algorithm must be sha256, sha384, or sha512",
                ));
            }
            if kdf
                .degraded_profile_reason
                .as_deref()
                .is_none_or(str::is_empty)
            {
                return Err(schema_error(
                    "pbkdf2 key backup requires degraded_profile_reason",
                ));
            }
        }
    }
    Ok(())
}

pub(super) fn typed_recovery_policy_ref(backup: &KeyBackup) -> Option<(&str, u64)> {
    let policy_ref = backup.recovery_policy_ref.as_ref()?;
    Some((policy_ref.policy_id.as_str(), policy_ref.policy_version))
}

pub(super) fn validate_recovery_policy_ref_shape_typed(backup: &KeyBackup) -> Result<(), AppError> {
    let present = backup.recovery_policy_ref.is_some();

    if !present {
        return Ok(());
    }

    let (policy_id, version) = typed_recovery_policy_ref(backup)
        .ok_or_else(|| schema_error("recovery_policy_ref must be an object"))?;
    if !policy_id.starts_with("ak:policy:") {
        return Err(schema_error(format!(
            "recovery_policy_ref.policy_id `{policy_id}` must start with ak:policy:"
        )));
    }
    if version < 1 {
        return Err(schema_error(
            "recovery_policy_ref.policy_version must be >= 1",
        ));
    }

    Ok(())
}

pub(super) fn validate_key_backup_auth_data_typed(backup: &KeyBackup) -> Result<(), AppError> {
    if backup.signature_proof.signature.as_str().is_empty() {
        return Err(schema_error("key backup signature is required"));
    }
    Ok(())
}

pub(super) fn validate_series_genesis_shape_typed(backup: &KeyBackup) -> Result<(), AppError> {
    if backup.supersedes_id.is_some() {
        return Err(crate::app_error!(
            Conflict,
            "series_chain_broken: genesis envelope (series_sequence=0) must not carry `supersedes_id`",
        )
        .with_reason_code(arkret_wire::ReasonCode::SERIES_CHAIN_BROKEN));
    }
    if backup.supersedes_digest.is_some() {
        return Err(crate::app_error!(
            Conflict,
            "series_chain_broken: genesis envelope (series_sequence=0) must not carry `supersedes_digest`",
        )
        .with_reason_code(arkret_wire::ReasonCode::SERIES_CHAIN_BROKEN));
    }
    Ok(())
}

/// `key-backup.schema.json` `encryption.recipient_key_ref`: for
/// `recipient_method=recovery_public_key` it MUST resolve to a non-revoked
/// `methods[].keys[].backup_hpke.key_agreement_ref` of the accepted recovery
/// policy, and the selected `hpke_suite` MUST appear in that entry's
/// `hpke_suites`. A DID-Document-only agreement or a `methods[].keys[]`
/// signing method is not an authorization source.
pub(super) async fn validate_current_recovery_recipient(
    state: &AppState,
    backup: &KeyBackup,
    evaluated_at: DateTime<Utc>,
) -> Result<(), AppError> {
    let account_id = backup.actor_id.as_account_id().ok_or_else(|| {
        failed_precondition(
            "recovery_public_key backup requires an account actor",
            "recovery_policy_mismatch",
        )
    })?;
    let policy = state
        .recovery_policies()
        .active_policy(account_id)
        .await
        .map_err(|error| AppError::internal(format!("recovery policy lookup failed: {error}")))?
        .ok_or_else(|| {
            failed_precondition(
                "a recovery_public_key key backup requires an accepted recovery policy",
                "recovery_policy_mismatch",
            )
        })?;
    let policy: RecoveryPolicy = serde_json::from_value(policy.raw_payload).map_err(|error| {
        AppError::internal(format!(
            "accepted recovery policy failed strong decoding: {error}"
        ))
    })?;
    policy.validate_shape().map_err(|error| {
        AppError::internal(format!(
            "accepted recovery policy failed validation: {error}"
        ))
    })?;
    let recipient = backup
        .encryption
        .recipient_key_ref
        .as_deref()
        .unwrap_or_default();
    let suite_id = backup
        .encryption
        .hpke_suite
        .as_deref()
        .unwrap_or(arkret_wire::HPKE_SUITE_X25519_CHACHA20POLY1305_V1);
    let suite: arkret_models_crypto::recovery_policy::RecoveryBackupHpkeSuite =
        serde_json::from_value(Value::String(suite_id.to_owned())).map_err(|_| {
            crate::app_error!(
                UnsupportedHpkeSuite,
                format!("key backup HPKE suite is unsupported: {suite_id}"),
            )
        })?;
    let policy_ref = backup.recovery_policy_ref.as_ref().ok_or_else(|| {
        failed_precondition(
            "recovery_public_key backup has no recovery policy ref",
            "recovery_policy_mismatch",
        )
    })?;
    if policy.account_id != *account_id
        || policy.policy_id != policy_ref.policy_id
        || policy.version != policy_ref.policy_version
    {
        return Err(failed_precondition(
            "backup recovery_policy_ref does not identify the accepted policy",
            "recovery_policy_mismatch",
        ));
    }
    let matching_recipient = policy.methods.iter().find_map(|method| {
        let arkret_models_crypto::recovery_policy::RecoveryMethod::RecoveryUnlock { keys } = method
        else {
            return None;
        };
        keys.iter()
            .map(|key| &key.backup_hpke)
            .find(|entry| current_backup_hpke_agreement(entry, recipient, evaluated_at))
    });
    let Some(agreement) = matching_recipient else {
        return Err(failed_precondition(
            "recipient_key_ref is not a current non-revoked backup HPKE key agreement in the accepted recovery policy",
            "recovery_policy_mismatch",
        ));
    };
    if !agreement.hpke_suites.contains(&suite) {
        return Err(crate::app_error!(
            UnsupportedHpkeSuite,
            format!(
                "key backup HPKE suite {suite_id} is not allowed by recovery key agreement {recipient}"
            ),
        ));
    }
    Ok(())
}

fn current_backup_hpke_agreement(
    entry: &RecoveryKeyAgreementEntry,
    recipient: &str,
    evaluated_at: DateTime<Utc>,
) -> bool {
    entry.key_agreement_ref.as_str() == recipient
        && entry.r#use == RecoveryKeyAgreementUse::BackupHpke
        && entry.revoked_at.is_none()
        && entry.not_before <= evaluated_at
        && entry.expires_at > evaluated_at
}

#[cfg(test)]
mod tests {
    use chrono::{DateTime, Utc};

    use super::*;

    const RECOVERY_CONTROLLER_DID: &str = "did:webvh:z6mkcontroller:controller.example";
    #[test]
    fn a_recovery_signing_key_is_not_a_backup_hpke_recipient() {
        let now: DateTime<Utc> = "2026-07-15T00:00:00.000Z".parse().unwrap();
        let agreement = RecoveryKeyAgreementEntry {
            key_agreement_ref: arkret_wire::DidUrl::new(format!(
                "{RECOVERY_CONTROLLER_DID}#backup-hpke-1"
            ))
            .unwrap(),
            key_agreement_algorithm:
                arkret_models_crypto::recovery_policy::RecoveryKeyAgreementAlgorithm::X25519,
            public_key_multibase: "z6LSriWhVBzW9Vz2PvqbieSz7Aa2hPLzTKJuDwXTMKFeomeW".to_owned(),
            hpke_suites: vec![arkret_models_crypto::recovery_policy::RecoveryBackupHpkeSuite::X25519AeadChacha20Poly1305V1],
            r#use: RecoveryKeyAgreementUse::BackupHpke,
            not_before: now - chrono::TimeDelta::minutes(1),
            expires_at: now + chrono::TimeDelta::days(1),
            revoked_at: None,
        };

        assert!(current_backup_hpke_agreement(
            &agreement,
            agreement.key_agreement_ref.as_str(),
            now
        ));
        assert!(!current_backup_hpke_agreement(
            &agreement,
            &format!("{RECOVERY_CONTROLLER_DID}#recovery-proof-1"),
            now
        ));
    }

    fn secret_storage_encryption(
        name: arkret_models_crypto::key_backup::KeyBackupAeadName,
        aead_profile: Option<&str>,
    ) -> arkret_models_crypto::key_backup::KeyBackupEncryption {
        arkret_models_crypto::key_backup::KeyBackupEncryption {
            recipient_method:
                arkret_models_crypto::key_backup::KeyBackupRecipientMethod::SecretStorageKey,
            recipient_key_ref: Some("ak.secret_storage.default".to_owned()),
            kdf: None,
            aead: arkret_models_crypto::key_backup::KeyBackupAead {
                name,
                aead_profile: aead_profile.map(str::to_owned),
                nonce_salt: None,
                // `secret_storage_key` requires an AEAD nonce; the fixture is a
                // complete envelope so `validate()` exercises the profile rule
                // rather than tripping on a missing sibling field.
                nonce: Some(
                    arkret_wire::Base64UrlString::new("AAECAwQFBgcICQoL".to_owned()).unwrap(),
                ),
                enc: None,
                extra: Default::default(),
            },
            key_commitment: None,
            hpke_suite: None,
            extra: Default::default(),
        }
    }

    /// key-management.md 7.9: the receiver fails closed on a profile it cannot
    /// resolve, under the registered `unsupported_aead_profile` reason code.
    #[test]
    fn an_unresolvable_aead_profile_fails_closed_with_its_reason_code() {
        for profile in [
            "ak.aead.hybrid_kem.x25519_mlkem768.v1",
            "ak.aead.unpublished_future.v1",
        ] {
            let encryption = secret_storage_encryption(
                arkret_models_crypto::key_backup::KeyBackupAeadName::Xchacha20Poly1305,
                Some(profile),
            );
            let error = encryption
                .aead
                .validate_aead_profile()
                .expect_err("profile must fail closed");
            assert_eq!(error, arkret_wire::ReasonCode::UNSUPPORTED_AEAD_PROFILE);
        }
    }

    #[test]
    fn an_active_profile_matching_its_algorithm_is_accepted() {
        let encryption = secret_storage_encryption(
            arkret_models_crypto::key_backup::KeyBackupAeadName::Xchacha20Poly1305,
            Some("ak.aead.xchacha20_poly1305.v1"),
        );
        assert!(encryption.aead.validate_aead_profile().is_ok());
        assert!(encryption.validate().is_ok());
    }

    #[test]
    fn critical_digest_shape_is_sha256_only() {
        let digest64 = "0".repeat(64);
        let digest128 = "0".repeat(128);

        assert!(is_sha_digest(&format!("sha256:{digest64}")));
        assert!(!is_sha_digest(&format!("blake3:{digest64}")));
        assert!(!is_sha_digest(&format!("sha3_256:{digest64}")));
        assert!(!is_sha_digest(&format!("sha512:{digest128}")));
        assert!(!is_sha_digest(&format!("sha256:{}", "A".repeat(64))));
    }
}
