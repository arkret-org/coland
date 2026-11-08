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
