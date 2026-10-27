//! Encrypted key-backup CRUD.

use arkret_identifiers::{BackupId, EventId};
use arkret_models_crypto::{
    BackupKind, KeyBackup, KeyBackupKdfName, KeyBackupRecipientMethod, KeyBackupUnlockProof,
    KeysBackupsDeleteRequestBody, KeysBackupsUnlockRequestBody, RecoveryKeyAgreementEntry,
    RecoveryKeyAgreementUse, RecoveryPolicy,
};
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use coland_http::error::AppError;
use coland_http::result::{JsonResult, json_ok};
use ed25519_dalek::{Signature, Verifier as _};
use salvo::oapi::extract::{JsonBody, PathParam, QueryParam};
use salvo::prelude::*;
use serde_json::{Value, json};

use super::append_audit_log;
use crate::routing::system::extract::AuthArgs;
use crate::state::AppState;
use crate::wire::{KeyBackupPutStatus, KeysBackupsPage, KeysBackupsReplaceResponseBody};

mod delete;
mod handlers;
mod listing;
mod unlock;
mod validation;

use delete::*;
use handlers::*;
use listing::*;
use unlock::*;
use validation::*;

pub(super) fn protocol_router() -> Router {
    Router::new()
        .push(
            Router::with_path("keys/backups/{backup_id}")
                .put(put_key_backup)
                .delete(delete_key_backup),
        )
        .push(
            // key-management.md §7.8.1 step 1: the server mints every freshness
            // value for a high-risk delete. Without this endpoint the DELETE
            // below has nothing valid to consume.
            Router::with_path("keys/backups/{backup_id}/delete-challenge")
                .post(issue_key_backup_delete_challenge),
        )
        .push(Router::with_path("keys/backups/{backup_id}/unlock").post(unlock_key_backup))
        .push(
            Router::with_path("keys/backups/{backup_id}/unlock-challenge")
                .post(issue_key_backup_unlock_challenge),
        )
        .push(Router::with_path("keys/backups").get(list_key_backups))
}

pub(crate) fn admin_router() -> Router {
    Router::with_path("key-backups").get(list_key_backups_admin)
}

fn local_backup_actor(
    state: &AppState,
    principal_id: &str,
) -> Result<arkret_wire::ActorId, AppError> {
    Ok(arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        arkret_wire::DidCoreId::new(principal_id.to_owned()).map_err(|error| {
            AppError::capability_denied(format!("invalid account principal: {error}"))
        })?,
        state.service_core_id(),
    )))
}

/// Serving-layer checks of one planned SecurityRotation replacement envelope:
/// the closed body, encryption, KDF, domain separation and ciphertext digest,
/// the recovery-policy reference and a recovery-public-key recipient, as the
/// self PUT applies them. Identity, signer, current authorization, signature
/// and series chain are rechecked by the upload storage unit at the locked
/// PCR cut.
pub(in crate::routing) async fn validate_rotation_replacement_backup(
    state: &AppState,
    value: &Value,
) -> Result<(), AppError> {
    let backup: KeyBackup = serde_json::from_value(value.clone())
        .map_err(|error| schema_error(format!("invalid replacement backup envelope: {error}")))?;
    validate_key_backup_body_typed(&backup.backup_id, &backup.actor_id, &backup)?;
    enforce_recovery_policy_ref_typed(state, "", &backup).await?;
    if backup.encryption.recipient_method == KeyBackupRecipientMethod::RecoveryPublicKey {
        validate_current_recovery_recipient(state, &backup, Utc::now()).await?;
    }
    Ok(())
}

fn backup_actor_matches(backup: &Value, actor_id: &arkret_wire::ActorId) -> bool {
    backup
        .get("actor_id")
        .cloned()
        .and_then(|value| serde_json::from_value::<arkret_wire::ActorId>(value).ok())
        .is_some_and(|owner| &owner == actor_id)
}
#[cfg(test)]
mod tests {
    use arkret_identifiers::DidCoreId;
    use coland_http::error::ErrorCode;
    use serde_json::json;

    use super::*;

    const ACTOR: &str = "ak:did_core:web:alice.example";
    const BACKUP_ID: &str = "ak:backup:01964137-0000-7000-8000-000000000001";
    const DEVICE_ID: &str = "ak:device:01964137-0000-7000-8000-000000000001";

    fn backup_account_actor(principal_id: &str) -> arkret_wire::ActorId {
        arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            DidCoreId::new(principal_id.to_owned()).unwrap(),
            crate::test_event::station_id(),
        ))
    }

    fn validate_key_backup_body(
        backup_id: &str,
        actor_id: &str,
        body: &Value,
    ) -> Result<(), AppError> {
        let typed_backup_id = BackupId::new(backup_id.to_owned()).map_err(|error| {
            AppError::param_invalid(format!(
                "backup_id must be a ak:backup:<uuidv7> typed id: {error}"
            ))
        })?;
        let backup = typed_key_backup_body(body)?;
        validate_key_backup_body_typed(&typed_backup_id, &backup_account_actor(actor_id), &backup)
    }

    fn typed_key_backup_body(body: &Value) -> Result<KeyBackup, AppError> {
        serde_json::from_value(body.clone()).map_err(|error| {
            schema_error(format!(
                "key backup payload failed SDK type validation: {error}"
            ))
        })
    }

    #[test]
    fn key_backup_ciphertext_digest_uses_decoded_bytes() {
        let mut body = key_backup_body("secret_storage", passphrase_encryption());
        let backup = typed_key_backup_body(&body).unwrap();
        validate_key_backup_ciphertext_digest_typed(&backup).unwrap();
        body["ciphertext"] = json!("AAAB");
        let backup = typed_key_backup_body(&body).unwrap();
        assert!(validate_key_backup_ciphertext_digest_typed(&backup).is_err());
        body["ciphertext_digest"] = json!(arkret_canonical::blake3_digest([0, 0, 1]));
        let backup = typed_key_backup_body(&body).unwrap();
        validate_key_backup_ciphertext_digest_typed(&backup).unwrap();
    }

    #[test]
    fn key_backup_signer_must_be_the_session_device() {
        let body = key_backup_body("secret_storage", passphrase_encryption());
        let backup = typed_key_backup_body(&body).unwrap();
        validate_key_backup_session_device(&backup, DEVICE_ID).unwrap();
        assert!(
            validate_key_backup_session_device(
                &backup,
                "ak:device:01964137-0000-7000-8000-000000000002"
            )
            .is_err()
        );
    }

    fn key_backup_body(backup_kind: &str, encryption: Value) -> Value {
        let mut body = json!({
            "backup_id": BACKUP_ID,
            "actor_id": backup_account_actor(ACTOR),
            "device_id": DEVICE_ID,
            "backup_kind": backup_kind,
            "backup_version": "kb_1",
            "created_at": "2026-05-30T00:00:00.000Z",
            "series_id": "ak:backup_series:01964137-0000-7000-8000-000000000001",
            "series_sequence": 0,
            "encryption": encryption,
            "contents": [{
                "item_kind": "recovery_key_share",
                "secret_id": "test-secret"
            }],
            "ciphertext": "AAAA",
            "ciphertext_digest": "sha256:709e80c88487a2411e1ee4dfb9f22a861492d20c4765150c0c794abd70f8147c",
            "domain_separation": {
                "subdomain": "test"
            },
            "signature_proof": {
                "device_id": DEVICE_ID,
                "verification_method": "did:web:alice.example#device",
                "signature_algorithm": "Ed25519",
                "signature": "c2lnbmF0dXJl",
                "device_authorize_event_id": "ak:event:AcIMom-0qqAXx_hmDJfxxaUJb_oJ64S3ARW1-WKFDCoD"
            }
        });
        if body["encryption"]["recipient_method"].as_str() == Some("passphrase_kdf") {
            body["encryption"]["key_commitment"] =
                json!("sha256:2222222222222222222222222222222222222222222222222222222222222222");
        }
        if body["encryption"]["recipient_method"].as_str() == Some("recovery_public_key") {
            body["recovery_policy_ref"] = json!({
                "policy_id": "ak:policy:01964137-0000-7000-8000-000000000001",
                "policy_version": 1
            });
        }
        body
    }

    fn passphrase_encryption() -> Value {
        json!({
            "recipient_method": "passphrase_kdf",
            "kdf": {
                "name": "argon2id",
                "salt": "MDAwMDAwMDAwMDAwMDAwMA",
                "parameters": {
                    "memory_kib": 65_536,
                    "iterations": 3,
                    "parallelism": 1
                }
            },
            "aead": {
                "name": "xchacha20_poly1305",
                "aead_profile": "ak.aead.xchacha20_poly1305.v1",
                "nonce": "MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAw",
                "nonce_salt": "MDAwMDAwMDAwMDAwMDAwMA"
            }
        })
    }

    fn secret_storage_key_encryption() -> Value {
        json!({
            "recipient_method": "secret_storage_key",
            "recipient_key_ref": "mls_group_secrets_backup_key",
            "aead": {
                "name": "xchacha20_poly1305",
                "aead_profile": "ak.aead.xchacha20_poly1305.v1",
                "nonce": "nonce"
            }
        })
    }

    fn recovery_public_key_encryption() -> Value {
        json!({
            "recipient_method": "recovery_public_key",
            "recipient_key_ref": "did:web:alice.example#recovery",
            "aead": {
                // Absent hpke_suite selector denotes the v1 default-MUST HPKE suite
                // ak.hpke_x25519_aead_chacha20poly1305.v1, whose AEAD is chacha20_poly1305.
                "name": "chacha20_poly1305",
                "aead_profile": "ak.aead.chacha20_poly1305.v1",
                "enc": "ZW5jYXBzdWxhdGVka2V5"
            }
        })
    }

    #[test]
    fn recovery_public_key_requires_enc() {
        let mut enc = recovery_public_key_encryption();
        enc["aead"].as_object_mut().unwrap().remove("enc");
        let body = key_backup_body("secret_storage", enc);
        let err = validate_key_backup_body(BACKUP_ID, ACTOR, &body)
            .expect_err("recovery_public_key without aead.enc must be rejected");
        assert!(err.message.contains("enc"));
    }

    #[test]
    fn auth_data_rejects_missing_device_trust_anchor() {
        let mut body = key_backup_body("secret_storage", passphrase_encryption());
        body["signature_proof"]
            .as_object_mut()
            .unwrap()
            .remove("device_authorize_event_id");

        let err = validate_key_backup_body(BACKUP_ID, ACTOR, &body)
            .expect_err("key backup signature_proof must have a device trust anchor");
        assert_eq!(err.code, ErrorCode::SchemaViolation);
        assert!(err.message.contains("device_authorize_event_id"));
    }

    #[test]
    fn passphrase_kdf_requires_nonce_salt_and_key_commitment() {
        // Drop nonce_salt -> reject.
        let mut enc = passphrase_encryption();
        enc["aead"].as_object_mut().unwrap().remove("nonce_salt");
        let body = key_backup_body("secret_storage", enc);
        let err = validate_key_backup_body(BACKUP_ID, ACTOR, &body)
            .expect_err("passphrase_kdf without nonce_salt must be rejected");
        assert!(err.message.contains("inconsistent encryption fields"));

        // Drop key_commitment -> reject.
        let mut body2 = key_backup_body("secret_storage", passphrase_encryption());
        body2["encryption"]
            .as_object_mut()
            .unwrap()
            .remove("key_commitment");
        let err2 = validate_key_backup_body(BACKUP_ID, ACTOR, &body2)
            .expect_err("passphrase_kdf without key_commitment must be rejected");
        assert!(err2.message.contains("inconsistent encryption fields"));
    }

    #[test]
    fn unsupported_recipient_method_is_rejected() {
        let mut encryption = passphrase_encryption();
        encryption["recipient_method"] = json!("unknown_magic_key");
        let body = key_backup_body("secret_storage", encryption);

        let err = validate_key_backup_body(BACKUP_ID, ACTOR, &body)
            .expect_err("unknown recipient methods must not pass schema validation");
        assert_eq!(err.code, ErrorCode::SchemaViolation);
        assert!(err.message.contains("unknown_magic_key"));
    }

    #[test]
    fn passphrase_kdf_still_requires_kdf_metadata() {
        let mut encryption = passphrase_encryption();
        encryption.as_object_mut().unwrap().remove("kdf");
        let body = key_backup_body("secret_storage", encryption);

        let err = validate_key_backup_body(BACKUP_ID, ACTOR, &body)
            .expect_err("passphrase_kdf without kdf metadata is invalid");
        assert_eq!(err.code, ErrorCode::SchemaViolation);
        // The SDK encryption type validation gate fires first and rejects the
        // missing kdf ("passphrase_kdf requires `kdf`") before coland's domain check.
        assert!(err.message.contains("kdf"));
    }

    #[test]
    fn secret_storage_rejects_plaintext_fields() {
        let mut body = key_backup_body("secret_storage", secret_storage_key_encryption());
        body["plaintext"] = json!("raw group state");

        let err = validate_key_backup_body(BACKUP_ID, ACTOR, &body)
            .expect_err("coland must store only opaque backup ciphertext");
        assert_eq!(err.code, ErrorCode::SchemaViolation);
    }

    #[test]
    fn duplicate_backup_id_rejects_cross_actor_overwrite() {
        let existing = json!({
            "backup_id": BACKUP_ID,
            "actor_id": backup_account_actor("ak:did_core:web:bob.example")
        });

        let err =
            key_backup_idempotent_retry(Some(&existing), &backup_account_actor(ACTOR), &existing)
                .expect_err("other actor must not overwrite backup_id");

        assert_eq!(err.code, ErrorCode::CapabilityDenied);
        assert_eq!(
            err.http_status(),
            coland_http::error::error_http_status(err.code)
        );
    }

    #[test]
    fn duplicate_backup_id_accepts_same_actor_retry() {
        let existing = json!({
            "backup_id": BACKUP_ID,
            "actor_id": backup_account_actor(ACTOR)
        });

        let duplicate =
            key_backup_idempotent_retry(Some(&existing), &backup_account_actor(ACTOR), &existing)
                .expect("same actor idempotent retry is allowed");

        assert!(duplicate);
    }

    #[test]
    fn duplicate_backup_id_rejects_same_principal_at_another_station() {
        let owner = backup_account_actor(ACTOR);
        let other_account = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            DidCoreId::new(ACTOR.to_owned()).unwrap(),
            DidCoreId::new("ak:did_core:web:other-station.example".to_owned()).unwrap(),
        ));
        let existing = json!({"backup_id": BACKUP_ID, "actor_id": owner});
        assert!(!backup_actor_matches(&existing, &other_account));
        let error = key_backup_idempotent_retry(Some(&existing), &other_account, &existing)
            .expect_err("Station change creates a distinct account, not an overwrite authority");
        assert_eq!(error.code, ErrorCode::CapabilityDenied);
    }

    #[test]
    fn duplicate_backup_id_rejects_different_content() {
        let existing = json!({
            "backup_id": BACKUP_ID,
            "actor_id": backup_account_actor(ACTOR),
            "ciphertext": "first"
        });
        let incoming = json!({
            "backup_id": BACKUP_ID,
            "actor_id": backup_account_actor(ACTOR),
            "ciphertext": "second"
        });

        let err =
            key_backup_idempotent_retry(Some(&existing), &backup_account_actor(ACTOR), &incoming)
                .expect_err("same id with different content must conflict");

        assert_eq!(err.code, ErrorCode::DuplicateConflict);
        assert_eq!(err.http_status(), StatusCode::CONFLICT);
    }

    fn delete_challenge_fixture() -> arkret_models_crypto::KeysBackupsDeleteChallenge {
        arkret_models_crypto::KeysBackupsDeleteChallenge {
            challenge_id: arkret_wire::Base64UrlString::new("Y2hhbGxlbmdlLWlk").unwrap(),
            challenge: arkret_wire::Base64UrlString::new("Y2hhbGxlbmdlLWJ5dGVz").unwrap(),
            nonce: arkret_wire::Base64UrlString::new("bm9uY2UtYnl0ZXM").unwrap(),
            operation: "ak.self.keys.backups.resource.delete.v1".to_owned(),
            account_id: arkret_wire::AccountId::new(
                DidCoreId::new(ACTOR.to_owned()).unwrap(),
                DidCoreId::new("ak:did_core:web:coland.test".to_owned()).unwrap(),
            ),
            backup_id: BackupId::new(BACKUP_ID.to_owned()).unwrap(),
            audience: arkret_wire::NonEmptyString::new("https://coland.test").unwrap(),
            service_id: DidCoreId::new("ak:did_core:web:coland.test".to_owned()).unwrap(),
            request_id: arkret_wire::Base64UrlString::new("cmVxdWVzdC1pZA").unwrap(),
            issued_at: "2026-08-01T00:00:00.000Z".parse().unwrap(),
            expires_at: "2026-08-01T00:05:00.000Z".parse().unwrap(),
        }
    }

    /// §7.8.1 step 2: the transcript's key set is fixed, and an absent `reason`
    /// is encoded as JSON `null` rather than omitted.
    ///
    /// Omitting the key would make "no reason given" and "reason tampered away"
    /// produce different bytes on different implementations — which is exactly
    /// the kind of divergence the canonical form exists to prevent.
    #[test]
    fn delete_intent_transcript_has_the_fixed_key_set_and_null_reason() {
        let transcript = delete_challenge_fixture().delete_intent_transcript(None);
        let object = transcript.as_object().expect("transcript is an object");
        let mut keys: Vec<&str> = object.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "account_id",
                "audience",
                "backup_id",
                "challenge",
                "challenge_id",
                "context",
                "expires_at",
                "issued_at",
                "nonce",
                "operation",
                "reason",
                "request_id",
                "service_id",
            ]
        );
        assert_eq!(
            object["context"],
            arkret_wire::ProofContextId::KEY_BACKUP_DELETE_PROOF_V1
        );
        assert_eq!(
            object["operation"],
            "ak.self.keys.backups.resource.delete.v1"
        );
        assert!(
            object["reason"].is_null(),
            "an absent reason MUST be encoded as JSON null, not omitted"
        );
    }

    /// §7.8.1 step 5: tampering with any transcript field MUST make signature
    /// verification fail. The digest is what the signature covers, so this
    /// states that property at the digest.
    #[test]
    fn tampering_any_transcript_field_changes_the_delete_intent_digest() {
        let base = delete_challenge_fixture();
        let baseline = base.delete_intent_digest(None).expect("digest");

        // `reason` is signed, so adding one moves the digest.
        assert_ne!(
            baseline,
            base.delete_intent_digest(Some("device lost"))
                .expect("digest")
        );

        let mut tampered_backup = base.clone();
        tampered_backup.backup_id =
            BackupId::new("ak:backup:01964137-0000-7000-8000-000000000099".to_owned()).unwrap();
        assert_ne!(
            baseline,
            tampered_backup.delete_intent_digest(None).unwrap()
        );

        let mut tampered_audience = base.clone();
        tampered_audience.audience = arkret_wire::NonEmptyString::new("https://evil.test").unwrap();
        assert_ne!(
            baseline,
            tampered_audience.delete_intent_digest(None).unwrap()
        );

        let mut tampered_nonce = base.clone();
        tampered_nonce.nonce = arkret_wire::Base64UrlString::new("b3RoZXItbm9uY2U").unwrap();
        assert_ne!(baseline, tampered_nonce.delete_intent_digest(None).unwrap());

        let mut tampered_service = base.clone();
        tampered_service.service_id =
            DidCoreId::new("ak:did_core:web:other.test".to_owned()).unwrap();
        assert_ne!(
            baseline,
            tampered_service.delete_intent_digest(None).unwrap()
        );

        // The freshness window is signed too, so a replayed challenge cannot be
        // re-dated into a fresh one.
        let mut tampered_window = base;
        tampered_window.expires_at = "2026-08-01T01:00:00.000Z".parse().unwrap();
        assert_ne!(
            baseline,
            tampered_window.delete_intent_digest(None).unwrap()
        );
    }

    // ── §7.6 genesis-envelope shape ──────────────────────────────────────

    #[test]
    fn genesis_envelope_rejects_supersedes() {
        let mut body = key_backup_body("secret_storage", passphrase_encryption());
        body["supersedes_id"] = json!("ak:backup:01964137-0000-7000-8000-0000000000ff");

        let backup = typed_key_backup_body(&body).expect("typed key backup");
        let err = validate_series_genesis_shape_typed(&backup)
            .expect_err("genesis envelope carrying `supersedes_id` must be series_chain_broken");
        assert_eq!(err.code, ErrorCode::Conflict);
        assert_eq!(err.http_status(), StatusCode::CONFLICT);
        assert_eq!(
            err.reason_code.as_deref(),
            Some(arkret_wire::ReasonCode::SERIES_CHAIN_BROKEN)
        );
        assert!(err.message.contains("`supersedes_id`"));
    }

    #[test]
    fn genesis_envelope_rejects_supersedes_digest() {
        // Spec key-management.md §7.6 — genesis MUST NOT carry
        // `supersedes_digest` even when `supersedes` itself is absent.
        let mut body = key_backup_body("secret_storage", passphrase_encryption());
        body["supersedes_digest"] =
            json!("sha256:3333333333333333333333333333333333333333333333333333333333333333");

        let backup = typed_key_backup_body(&body).expect("typed key backup");
        let err = validate_series_genesis_shape_typed(&backup).expect_err(
            "genesis envelope carrying `supersedes_digest` must be series_chain_broken",
        );
        assert_eq!(err.code, ErrorCode::Conflict);
        assert_eq!(err.http_status(), StatusCode::CONFLICT);
        assert_eq!(
            err.reason_code.as_deref(),
            Some(arkret_wire::ReasonCode::SERIES_CHAIN_BROKEN)
        );
        assert!(err.message.contains("supersedes_digest"));
    }

    #[test]
    fn genesis_envelope_tolerates_null_predecessor_fields() {
        // Spec §7.6 phrases genesis as `supersedes == null`; an explicit
        // JSON null is equivalent to absence, not a chain claim.
        let mut body = key_backup_body("secret_storage", passphrase_encryption());
        body["supersedes_id"] = Value::Null;
        body["supersedes_digest"] = Value::Null;

        let backup = typed_key_backup_body(&body).expect("typed key backup");
        validate_series_genesis_shape_typed(&backup)
            .expect("explicit null predecessor fields are equivalent to absence");
    }

    // ── §7.8 download-quota clamp ────────────────────────────────────────

    #[test]
    fn download_limit_defaults_and_clamps_to_spec_range() {
        use coland_services::runtime_guards::{
            KEY_BACKUP_DAILY_DOWNLOAD_LIMIT_DEFAULT, KEY_BACKUP_DAILY_DOWNLOAD_LIMIT_MAX,
            KEY_BACKUP_DAILY_DOWNLOAD_LIMIT_MIN,
        };

        // Unset → spec default (64).
        assert_eq!(
            coland_services::runtime_guards::clamp_key_backup_daily_download_limit(None),
            KEY_BACKUP_DAILY_DOWNLOAD_LIMIT_DEFAULT
        );
        // In-range values are honored as-is.
        assert_eq!(
            coland_services::runtime_guards::clamp_key_backup_daily_download_limit(Some(100)),
            100
        );
        // Outside the spec-allowed [16, 256] range the value is clamped —
        // §7.8 forbids relaxing past the ceiling, and a sub-floor value
        // would break a single legitimate long-series restore.
        assert_eq!(
            coland_services::runtime_guards::clamp_key_backup_daily_download_limit(Some(1)),
            KEY_BACKUP_DAILY_DOWNLOAD_LIMIT_MIN
        );
        assert_eq!(
            coland_services::runtime_guards::clamp_key_backup_daily_download_limit(Some(100_000)),
            KEY_BACKUP_DAILY_DOWNLOAD_LIMIT_MAX
        );
    }
}

pub(crate) async fn recovery_unlock_manifest(
    state: &AppState,
    account: &arkret_wire::AccountId,
) -> Result<Value, AppError> {
    let basis = state
        .key_backups()
        .confirmed_active_series_basis(account)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
        .ok_or_else(|| AppError::internal("confirmed PCR pointer basis is absent"))?;
    let pointers = basis.state;
    let actor = arkret_wire::ActorId::account(account.clone()).to_string();
    let query = coland_services::identity::KeyBackupListQuery {
        actor_id: actor.clone(),
        backup_kind: None,
        series_id: None,
        after: None,
        limit: 1,
    };
    let revision = state
        .key_backups()
        .list_page(&query)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
        .revision;
    let backups = state
        .key_backups()
        .backups_for_actor(&actor)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    let mut manifest = Vec::new();
    for backup in backups {
        let typed: KeyBackup = serde_json::from_value(backup.clone())
            .map_err(|error| AppError::internal(error.to_string()))?;
        let pointer = match typed.backup_kind {
            BackupKind::SecretStorage => &pointers.secret_storage,
        };
        if pointer.series_id() == Some(&typed.series_id)
            && backup
                .get("expires_at")
                .and_then(Value::as_str)
                .is_none_or(|time| {
                    chrono::DateTime::parse_from_rfc3339(time).is_ok_and(|time| time > Utc::now())
                })
        {
            manifest.push(backup);
        }
    }
    if revision
        != state
            .key_backups()
            .list_page(&query)
            .await
            .map_err(|error| AppError::internal(error.to_string()))?
            .revision
    {
        return Err(AppError::conflict(
            "backup manifest changed during verification",
        ));
    }
    // Freeze the confirmed Account Authority basis from the current active-series
    // projection. This is the response DTO's authority_commit_id, separate from
    // the signed active-series payload's source_commit_ref (§7.6.1).
    // The revision below detects changes to the backup set itself.
    let frozen = json!({
        "backups": manifest,
        "revision": revision,
        "actor_id": actor,
        "realm_id": pointers.control_realm_id,
        "authority_commit_id": pointers.authority_commit_id,
        "committed_ref": basis.committed_ref,
    });
    Ok(frozen)
}
