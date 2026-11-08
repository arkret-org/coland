//! Read immutable first-admitted root metadata without loading ciphertexts.
//! Native PUT already checked the complete original, its digest and signature.
//! The live body cannot be updated; ordinary deletion retains its admission.

use arkret_models_crypto::{ContentRootContext, RecoveryPolicyRef};
use arkret_wire::{ActorId, BackupId, Hash};
use diesel::sql_types::{Array, Jsonb, Nullable, Text, Timestamptz};
use diesel::{QueryableByName, sql_query};
use horme::{OptionalExtension, RunQueryDsl};
use serde_json::Value;

use crate::{AsyncPgConnection, PersistenceError, PgTransactionError};

pub(crate) struct RootPacket {
    pub actor: ActorId,
    pub recipient_subject: ActorId,
    pub policy_ref: RecoveryPolicyRef,
    pub recipient_key_ref: String,
    pub hpke_suite: Option<String>,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub roots: Vec<(Hash, ContentRootContext)>,
}

impl RootPacket {
    pub(crate) async fn require_current_recipient(
        &self,
        conn: &mut AsyncPgConnection,
    ) -> Result<(), PgTransactionError> {
        crate::key_backup_authority::verify_current_recipient_view(
            conn,
            arkret_models_crypto::key_backup::BackupRecoveryRecipient {
                subject: &self.recipient_subject,
                policy_ref: &self.policy_ref,
                key_agreement_ref: &self.recipient_key_ref,
                hpke_suite: self.hpke_suite.as_deref(),
            },
            chrono::Utc::now(),
        )
        .await
    }
}

#[derive(QueryableByName)]
struct PacketRow {
    #[diesel(sql_type=Text)]
    actor_id: String,
    #[diesel(sql_type=Nullable<Jsonb>)]
    custodian_actor: Option<Value>,
    #[diesel(sql_type=Jsonb)]
    policy_ref: Value,
    #[diesel(sql_type=Text)]
    recipient_key_ref: String,
    #[diesel(sql_type=Nullable<Text>)]
    hpke_suite: Option<String>,
    #[diesel(sql_type=Nullable<Timestamptz>)]
    expires_at: Option<chrono::DateTime<chrono::Utc>>,
    #[diesel(sql_type=Text)]
    envelope_digest: String,
    #[diesel(sql_type=Jsonb)]
    writer_admission: Value,
    #[diesel(sql_type=Jsonb)]
    roots: Value,
}

pub(crate) async fn read_in_connection(
    conn: &mut AsyncPgConnection,
    id: &BackupId,
    wanted: &[String],
) -> Result<RootPacket, PgTransactionError> {
    let invalid = || {
        PersistenceError::Conflict(
            "failed_precondition: root package has no immutable native admission".into(),
        )
    };
    let row = sql_query("SELECT b.actor_id,b.payload->'custodian_actor_id' AS custodian_actor,b.payload->'recovery_policy_ref' AS policy_ref,b.payload->'encryption'->>'recipient_key_ref' AS recipient_key_ref,b.payload->'encryption'->>'hpke_suite' AS hpke_suite,(b.payload->>'expires_at')::timestamptz AS expires_at,i.envelope_digest,i.writer_admission, COALESCE((SELECT jsonb_agg(DISTINCT jsonb_build_object('root_ref',entry->'root_ref','root_context',entry->'root_context')) FROM jsonb_array_elements(i.content_index) entry WHERE entry->>'item_kind'='content_epoch_root' AND entry->>'root_ref'=ANY($2)), '[]'::jsonb) AS roots FROM key_backups b JOIN key_backup_identities i ON i.id=b.id WHERE b.id=$1 AND b.actor_id=i.actor_id AND i.deleted_at IS NULL AND b.payload->'encryption'->>'recipient_method'='recovery_public_key' FOR SHARE OF b,i")
        .bind::<diesel::sql_types::Uuid,_>(crate::ids::typed_uuid_part_expect_internal(id.as_str()))
        .bind::<Array<Text>,_>(wanted).get_result::<PacketRow>(&mut *conn).await.optional()?.ok_or_else(invalid)?;
    let actor: ActorId = serde_json::from_str(&row.actor_id).map_err(PersistenceError::database)?;
    let admission: crate::key_backup_authority::DeviceBackupAdmission =
        serde_json::from_value(row.writer_admission).map_err(|_| invalid())?;
    if !admission.authenticates_metadata(&actor, &row.envelope_digest) {
        return Err(invalid().into());
    }
    let recipient_subject = row
        .custodian_actor
        .map(serde_json::from_value::<ActorId>)
        .transpose()
        .map_err(PersistenceError::database)?
        .unwrap_or_else(|| actor.clone());
    let roots = row
        .roots
        .as_array()
        .ok_or_else(invalid)?
        .iter()
        .map(|entry| {
            let reference: Hash = serde_json::from_value(entry["root_ref"].clone())
                .map_err(PersistenceError::database)?;
            let context: ContentRootContext = serde_json::from_value(entry["root_context"].clone())
                .map_err(PersistenceError::database)?;
            Ok((reference, context))
        })
        .collect::<Result<Vec<_>, PersistenceError>>()?;
    Ok(RootPacket {
        actor,
        recipient_subject,
        policy_ref: serde_json::from_value(row.policy_ref).map_err(PersistenceError::database)?,
        recipient_key_ref: row.recipient_key_ref,
        hpke_suite: row.hpke_suite,
        expires_at: row.expires_at,
        roots,
    })
}

/// Verify the retained signed body and the immutable index together. Historical
/// callers do not require the original writer to remain a current endpoint.
pub(crate) async fn read_retained_envelope(
    conn: &mut AsyncPgConnection,
    id: &BackupId,
) -> crate::PersistenceResult<arkret_models_crypto::KeyBackup> {
    let invalid = || {
        PersistenceError::Conflict("failed_precondition: retained root package unavailable".into())
    };
    let row = sql_query("SELECT jsonb_build_object('body',b.payload,'index',i.content_index,'admission',i.writer_admission) AS payload FROM key_backups b JOIN key_backup_identities i USING(id) WHERE b.id=$1 AND b.actor_id=i.actor_id AND i.deleted_at IS NULL FOR SHARE OF b,i")
        .bind::<diesel::sql_types::Uuid,_>(crate::ids::typed_uuid_part_expect_internal(id.as_str()))
        .get_result::<crate::JsonPayloadRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?
        .ok_or_else(invalid)?.payload;
    let backup: arkret_models_crypto::KeyBackup =
        serde_json::from_value(row["body"].clone()).map_err(PersistenceError::database)?;
    let admission: crate::key_backup_authority::DeviceBackupAdmission =
        serde_json::from_value(row["admission"].clone()).map_err(PersistenceError::database)?;
    backup.validate().map_err(PersistenceError::database)?;
    backup
        .validate_ciphertext_digest()
        .map_err(PersistenceError::database)?;
    admission.verify_retained_envelope(&backup)?;
    if backup.backup_id != *id
        || serde_json::to_value(&backup.contents).map_err(PersistenceError::database)?
            != row["index"]
    {
        return Err(invalid());
    }
    Ok(backup)
}

/// The original signed backup ref still anchors its first-admitted root index
/// after its live body was replaced and deleted. A matching new signed package
/// is only a mapping for this exact Actor/root/context, never another scope.
pub(crate) async fn require_original_binding(
    conn: &mut AsyncPgConnection,
    ids: &[BackupId],
    actor: &ActorId,
    root: &Hash,
    context: &ContentRootContext,
) -> crate::PersistenceResult<()> {
    let selector = serde_json::json!([{"item_kind":"content_epoch_root","root_ref":root,"root_context":context}]);
    let ids = ids
        .iter()
        .map(|id| crate::ids::typed_uuid_part_expect_internal(id.as_str()))
        .collect::<Vec<_>>();
    let rows = sql_query("SELECT jsonb_build_object('digest',envelope_digest,'admission',writer_admission) AS payload FROM key_backup_identities WHERE id=ANY($1) AND actor_id=$2 AND content_index @> $3 FOR SHARE")
        .bind::<Array<diesel::sql_types::Uuid>,_>(&ids).bind::<Text,_>(actor.to_string()).bind::<Jsonb,_>(&selector)
        .get_results::<crate::JsonPayloadRow>(&mut *conn).await.map_err(PersistenceError::database)?;
    for row in rows {
        let admission: crate::key_backup_authority::DeviceBackupAdmission =
            serde_json::from_value(row.payload["admission"].clone())
                .map_err(PersistenceError::database)?;
        if row.payload["digest"]
            .as_str()
            .is_some_and(|digest| admission.authenticates_metadata(actor, digest))
        {
            return Ok(());
        }
    }
    Err(PersistenceError::Conflict(
        "failed_precondition: root replacement has no original signed native binding".into(),
    ))
}
