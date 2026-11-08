//! Native writer and recipient checks at the locked backup admission cut.

use arkret_models_crypto::{KeyBackup, KeyBackupRecipientMethod, RecoveryPolicy};
use arkret_wire::{AccountId, DeviceId};
use coland_storage::{ConflictCode, PersistenceError};
use diesel::sql_types::{BigInt, Nullable, Text};
use diesel::{QueryableByName, sql_query};
use horme::{OptionalExtension, RunQueryDsl};

use crate::key_backup_current_states::verification_method_device;
use crate::pcr_device_status_reader::ConfirmedPcrDeviceStatusCut;
use crate::{AsyncPgConnection, PgTransactionError};

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
) -> Result<(), PgTransactionError> {
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
    Ok(())
}

pub(crate) async fn verify_current_backup_recipient(
    conn: &mut AsyncPgConnection,
    backup: &KeyBackup,
    at: chrono::DateTime<chrono::Utc>,
) -> Result<(), PgTransactionError> {
    if backup.encryption.recipient_method != KeyBackupRecipientMethod::RecoveryPublicKey {
        return Ok(());
    }
    let subject = backup
        .custodian_actor_id
        .as_ref()
        .unwrap_or(&backup.actor_id);
    let account = subject.as_account_id().ok_or_else(|| {
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
    backup
        .validate_recovery_recipient(&policy, at)
        .map_err(|error| {
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
) -> Result<(), PgTransactionError> {
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
    verify_human_backup_signature(conn, backup, &cut, account, device).await?;
    verify_current_backup_recipient(conn, backup, now).await
}
