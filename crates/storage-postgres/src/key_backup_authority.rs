//! Native writer and recipient checks at the locked backup admission cut.

use arkret_models_crypto::{KeyBackup, KeyBackupRecipientMethod, RecoveryPolicy};
use arkret_wire::{AccountId, DeviceId};
use coland_storage::{ConflictCode, PersistenceError};
use diesel::sql_types::{BigInt, Nullable, Text};
use diesel::{QueryableByName, sql_query};
use horme::{OptionalExtension, RunQueryDsl};
use serde::{Deserialize, Serialize};

use crate::key_backup_current_states::verification_method_device;
use crate::pcr_device_status_reader::ConfirmedPcrDeviceStatusCut;
use crate::{AsyncPgConnection, PgTransactionError};

/// Internal first-admission provenance, retained independently of current
/// device state. It is not a wire authorization or a reusable admission lease.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DeviceBackupAdmission {
    envelope_digest: String,
    signer_actor: arkret_wire::ActorId,
    signer_device: DeviceId,
    authorization_event_ref: arkret_wire::EventId,
    source_head: arkret_wire::RealmCommitId,
    generation: u64,
    public_key_did: String,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    accepted_at: chrono::DateTime<chrono::Utc>,
}

impl DeviceBackupAdmission {
    pub(crate) fn matches_envelope(&self, digest: &str) -> bool {
        self.envelope_digest == digest
    }

    pub(crate) fn authenticates_metadata(
        &self,
        actor: &arkret_wire::ActorId,
        digest: &str,
    ) -> bool {
        &self.signer_actor == actor && self.matches_envelope(digest)
    }

    /// Verify the exact retained original using its first accepted key. Current
    /// writer revocation/generation is deliberately not a historical read gate.
    pub(crate) fn verify_retained_envelope(
        &self,
        backup: &KeyBackup,
    ) -> crate::PersistenceResult<()> {
        let invalid = || {
            PersistenceError::SchemaViolation(
                "backup differs from its first native admission".into(),
            )
        };
        if !self.matches_envelope(
            &arkret_canonical::canonical_sha256(backup).map_err(PersistenceError::database)?,
        ) || backup.actor_id != self.signer_actor
            || backup.signature_proof.device_id.as_ref() != Some(&self.signer_device)
            || backup.signature_proof.device_authorize_event_id.as_ref()
                != Some(&self.authorization_event_ref)
        {
            return Err(invalid());
        }
        let key = self
            .public_key_did
            .strip_prefix("did:key:")
            .ok_or_else(invalid)?;
        let key =
            arkret_canonical::multibase::decode_ed25519_multibase(key).map_err(|_| invalid())?;
        let signed = backup.signing_payload_bytes().map_err(|_| invalid())?;
        if !arkret_signatures::verify_detached_ed25519_signature(
            &arkret_signatures::PublicKeyMaterial::Ed25519Raw {
                bytes: key.to_vec(),
            },
            &signed,
            backup.signature_proof.signature.as_str(),
        ) {
            return Err(invalid());
        }
        Ok(())
    }
}

/// Verify a real Realm-native writer without constructing an Account or PCR
/// trust anchor. The caller has re-read this exact live authorization at the
/// locked accepting cut and separately applies the resource/business gates.
pub(crate) fn verify_realm_device_backup_signature(
    backup: &KeyBackup,
    authority: &coland_storage::AppletManagedDeviceAuthority,
    accepted_at: chrono::DateTime<chrono::Utc>,
) -> crate::PersistenceResult<DeviceBackupAdmission> {
    let invalid = || {
        PersistenceError::Conflict(
            "signature_invalid: native backup differs from its original Device".into(),
        )
    };
    backup.validate().map_err(PersistenceError::database)?;
    backup
        .validate_ciphertext_digest()
        .map_err(PersistenceError::database)?;
    let binding = backup.auth_binding.as_ref().ok_or_else(invalid)?;
    let fingerprint = arkret_canonical::ed25519_pubkey_to_did_key_multibase(&authority.public_key);
    if backup.actor_id != authority.actor_id
        || backup.actor_id.as_realm_actor_id().is_none()
        || backup.device_id.as_ref() != Some(&authority.device_id)
        || backup.signature_proof.device_id.as_ref() != Some(&authority.device_id)
        || backup.signature_proof.device_authorize_event_id.as_ref()
            != Some(&authority.authorization_ref.event_id)
        || backup.signature_proof.verification_method.as_str()
            != format!("did:key:{fingerprint}#{fingerprint}")
        || binding.device_generation != authority.current_device_generation_ref
        || backup.created_at < authority.not_before
        || backup.created_at >= authority.expires_at
        || accepted_at < authority.not_before
        || accepted_at >= authority.expires_at
    {
        return Err(invalid());
    }
    if !arkret_signatures::verify_detached_ed25519_signature(
        &arkret_signatures::PublicKeyMaterial::Ed25519Raw {
            bytes: authority.public_key.to_vec(),
        },
        &backup
            .signing_payload_bytes()
            .map_err(PersistenceError::database)?,
        backup.signature_proof.signature.as_str(),
    ) {
        return Err(invalid());
    }
    Ok(DeviceBackupAdmission {
        envelope_digest: arkret_canonical::canonical_sha256(backup)
            .map_err(PersistenceError::database)?,
        signer_actor: authority.actor_id.clone(),
        signer_device: authority.device_id.clone(),
        authorization_event_ref: authority.authorization_ref.event_id.clone(),
        source_head: authority.authorization_ref.commit_id.clone(),
        generation: authority.current_device_generation_ref,
        public_key_did: format!("did:key:{fingerprint}"),
        accepted_at,
    })
}

fn rejected(code: impl std::fmt::Display, reason: &str) -> PgTransactionError {
    PersistenceError::Conflict(format!("{code}: {reason}")).into()
}

#[derive(QueryableByName)]
struct SourceCheckpointRow {
    #[diesel(sql_type = Nullable<BigInt>)]
    source_position: Option<i64>,
    #[diesel(sql_type = Nullable<BigInt>)]
    generation_position: Option<i64>,
    #[diesel(sql_type = Nullable<BigInt>)]
    authorization_position: Option<i64>,
}

/// Verify one planned replacement envelope against the authorizing device's
/// current accepted authorization at the locked cut.
pub(crate) async fn verify_human_backup_signature(
    conn: &mut AsyncPgConnection,
    backup: &KeyBackup,
    cut: &ConfirmedPcrDeviceStatusCut,
    account: &AccountId,
    authorizer: &DeviceId,
) -> Result<DeviceBackupAdmission, PgTransactionError> {
    let authorization = cut.authority.authorization.as_ref().ok_or_else(|| {
        rejected(
            ConflictCode::FailedPrecondition,
            "backup authorizing device has no authorization",
        )
    })?;
    let generation = cut.authority.current_generation.ok_or_else(|| {
        rejected(
            ConflictCode::TemporarilyUnavailable,
            "backup PCR has no current generation",
        )
    })?;
    if backup.signature_proof.device_id.as_ref() != Some(authorizer)
        || backup
            .signature_proof
            .agent_authorization_event_ref
            .is_some()
        || backup
            .device_id
            .as_ref()
            .is_some_and(|device| device != authorizer)
        || verification_method_device(&backup.signature_proof.verification_method, account).as_ref()
            != Some(authorizer)
    {
        return Err(rejected(
            ConflictCode::SignatureInvalid,
            "backup is not signed by the backup's authorizing device",
        ));
    }
    if backup.signature_proof.device_authorize_event_id.as_ref() != Some(&authorization.event_id) {
        return Err(rejected(
            ConflictCode::SignatureInvalid,
            "backup names a device authorization that is not current",
        ));
    }
    if let Some(source) = &backup.source_commit_ref {
        if source.device_generation_ref != generation {
            return Err(rejected(
                "backup_revision_stale",
                "backup generation is not current",
            ));
        }
        let checkpoint = sql_query(
            "SELECT \
               (SELECT c.stream_position FROM realm_commits c WHERE c.commit_id=$2 AND c.realm_id=$1 \
                  AND c.stream_ref=jsonb_build_object('kind','realm','realm_id',$1::text)) AS source_position, \
               (SELECT g.current_stream_position FROM pcr_device_generation_current_states g \
                  WHERE g.realm_id=$1) AS generation_position, \
               (SELECT c.stream_position FROM realm_commits c WHERE c.commit_id=$3 AND c.realm_id=$1) \
                  AS authorization_position",
        )
        .bind::<Text, _>(cut.authority.realm_id.as_str())
        .bind::<Text, _>(source.realm_commit_id.as_str())
        .bind::<Text, _>(authorization.source_commit_id.as_str())
        .get_result::<SourceCheckpointRow>(&mut *conn)
        .await?;
        match (
            checkpoint.source_position,
            checkpoint.generation_position,
            checkpoint.authorization_position,
        ) {
            (Some(source), Some(generation_at), Some(authorized_at))
                if source >= generation_at && source >= authorized_at => {}
            _ => {
                return Err(rejected(
                    "backup_revision_stale",
                    "backup source is not an accepted PCR Commit under the current generation and device",
                ));
            }
        }
    }
    let did_key = authorization
        .payload
        .device_public_key_did
        .as_str()
        .strip_prefix("did:key:")
        .ok_or_else(|| {
            rejected(
                ConflictCode::FailedPrecondition,
                "current device authorization has no did:key key",
            )
        })?;
    let public_key =
        arkret_canonical::multibase::decode_ed25519_multibase(did_key).map_err(|_| {
            rejected(
                ConflictCode::FailedPrecondition,
                "current device authorization key is invalid",
            )
        })?;
    let signed = backup
        .signing_payload_bytes()
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    if !arkret_signatures::verify_detached_ed25519_signature(
        &arkret_signatures::PublicKeyMaterial::Ed25519Raw {
            bytes: public_key.to_vec(),
        },
        &signed,
        backup.signature_proof.signature.as_str(),
    ) {
        return Err(rejected(
            ConflictCode::SignatureInvalid,
            "backup signature does not match the authorizing device key",
        ));
    }
    let accepted_at = chrono::Utc::now();
    if authorization.payload.not_before > accepted_at
        || authorization
            .payload
            .expires_at
            .flatten()
            .is_some_and(|expires| expires <= accepted_at)
    {
        return Err(rejected(
            ConflictCode::DeviceUnauthorized,
            "backup writer authorization expired before admission",
        ));
    }
    Ok(DeviceBackupAdmission {
        envelope_digest: arkret_canonical::canonical_sha256(backup)
            .map_err(PersistenceError::database)?,
        signer_actor: arkret_wire::ActorId::account(account.clone()),
        signer_device: authorizer.clone(),
        authorization_event_ref: authorization.event_id.clone(),
        source_head: cut.authority.authority_commit_id.clone(),
        generation,
        public_key_did: authorization
            .payload
            .device_public_key_did
            .as_str()
            .to_owned(),
        accepted_at,
    })
}

pub(crate) async fn verify_current_backup_recipient(
    conn: &mut AsyncPgConnection,
    backup: &KeyBackup,
    at: chrono::DateTime<chrono::Utc>,
) -> Result<(), PgTransactionError> {
    let at = at.max(chrono::Utc::now());
    if backup.encryption.recipient_method != KeyBackupRecipientMethod::RecoveryPublicKey {
        return Ok(());
    }
    backup
        .validate()
        .map_err(|error| rejected(ConflictCode::RecoveryPolicyMismatch, &error.to_string()))?;
    let subject = backup
        .custodian_actor_id
        .as_ref()
        .unwrap_or(&backup.actor_id);
    let reference = backup.recovery_policy_ref.as_ref().ok_or_else(|| {
        rejected(
            ConflictCode::RecoveryPolicyMismatch,
            "backup has no recipient policy reference",
        )
    })?;
    verify_current_recipient_view(
        conn,
        arkret_models_crypto::key_backup::BackupRecoveryRecipient {
            subject,
            policy_ref: reference,
            key_agreement_ref: backup
                .encryption
                .recipient_key_ref
                .as_deref()
                .unwrap_or_default(),
            hpke_suite: backup.encryption.hpke_suite.as_deref(),
        },
        at,
    )
    .await
}

pub(crate) async fn verify_current_recipient_view(
    conn: &mut AsyncPgConnection,
    recipient: arkret_models_crypto::key_backup::BackupRecoveryRecipient<'_>,
    at: chrono::DateTime<chrono::Utc>,
) -> Result<(), PgTransactionError> {
    let at = at.max(chrono::Utc::now());
    let account = recipient.subject.as_account_id().ok_or_else(|| {
        rejected(
            ConflictCode::RecoveryPolicyMismatch,
            "backup recipient has no Account policy",
        )
    })?;
    // This is the same policy publication lock, after the PCR authority row.
    let accepted = crate::pcr_recovery_policy_unit::current_policy(conn, account)
        .await?
        .ok_or_else(|| {
            rejected(
                ConflictCode::RecoveryPolicyMismatch,
                "accepted recipient policy is absent",
            )
        })?;
    let policy: RecoveryPolicy =
        serde_json::from_value(accepted.raw_payload).map_err(PersistenceError::database)?;
    recipient.validate(&policy, at).map_err(|error| {
        let code = if error.error_code() == Some(arkret_wire::ErrorCode::UnsupportedHpkeSuite) {
            ConflictCode::UnsupportedHpkeSuite
        } else {
            ConflictCode::RecoveryPolicyMismatch
        };
        rejected(code, &error.to_string())
    })
}

pub(crate) async fn verify_backup_writer(
    conn: &mut AsyncPgConnection,
    backup: &KeyBackup,
) -> Result<DeviceBackupAdmission, PgTransactionError> {
    backup
        .validate()
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    // Agent custody uses its own native provision/runtime gate. Until that
    // gate is connected, never reinterpret it as a Human Device writer.
    if backup.custodian_actor_id.is_some()
        || backup
            .signature_proof
            .agent_authorization_event_ref
            .is_some()
    {
        return Err(rejected(
            ConflictCode::DeviceUnauthorized,
            "Agent custody admission is unavailable",
        ));
    }
    let account = backup.actor_id.as_account_id().ok_or_else(|| {
        rejected(
            ConflictCode::DeviceUnauthorized,
            "backup writer is not an Account",
        )
    })?;
    let device = backup.signature_proof.device_id.as_ref().ok_or_else(|| {
        rejected(
            ConflictCode::DeviceUnauthorized,
            "backup writer has no Device",
        )
    })?;
    #[derive(QueryableByName)]
    struct Realm {
        #[diesel(sql_type = Text)]
        realm_id: String,
    }
    let realm = sql_query("SELECT a.realm_id FROM pcr_genesis_units p JOIN realm_authorities a ON a.realm_id=p.realm_id WHERE p.principal_id=$1 AND p.station_id=$2 AND p.result_json<>'{}'::jsonb FOR SHARE OF a")
        .bind::<Text,_>(account.principal_id.as_str()).bind::<Text,_>(account.station_id.as_str())
        .get_result::<Realm>(&mut *conn).await.optional()?
        .ok_or_else(|| rejected(ConflictCode::DeviceUnauthorized, "backup writer has no accepted PCR"))?;
    let now = chrono::Utc::now();
    let cut = crate::pcr_device_status_reader::confirmed_pcr_device_status_cut_in_connection(
        conn, account, device, now,
    )
    .await?
    .ok_or_else(|| {
        rejected(
            ConflictCode::DeviceUnauthorized,
            "backup writer has no confirmed authority",
        )
    })?;
    if cut.authority.realm_id.as_str() != realm.realm_id {
        return Err(rejected(
            ConflictCode::DeviceUnauthorized,
            "backup writer PCR differs",
        ));
    }
    use crate::pcr_device_status_fold::PcrDeviceLifecycle;
    if cut.lifecycle != PcrDeviceLifecycle::Active {
        let code = match cut.lifecycle {
            PcrDeviceLifecycle::Revoked => ConflictCode::DeviceRevoked,
            PcrDeviceLifecycle::RevocationPending => ConflictCode::DeviceRevocationPending,
            PcrDeviceLifecycle::GenerationFenced => ConflictCode::DeviceGenerationFenced,
            _ => ConflictCode::DeviceUnauthorized,
        };
        return Err(rejected(code, "backup writer is not currently active"));
    }
    let admission = verify_human_backup_signature(conn, backup, &cut, account, device).await?;
    verify_current_backup_recipient(conn, backup, admission.accepted_at).await?;
    Ok(admission)
}
