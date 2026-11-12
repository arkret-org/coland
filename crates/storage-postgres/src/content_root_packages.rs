//! Resolve immutable first-admitted root references to verified retained packages.
//! Native PUT already checked the complete original, its digest and signature.
//! The live body cannot be updated; ordinary deletion retains its admission.

use arkret_models_crypto::ContentRootContext;
use arkret_wire::{ActorId, BackupId, Hash};
use diesel::sql_types::{Array, Jsonb, Text};
use diesel::{QueryableByName, sql_query};
use horme::{OptionalExtension, RunQueryDsl};

use crate::{AsyncPgConnection, PersistenceError, PgTransactionError};

pub(crate) struct RootPacket {
    pub actor: ActorId,
    pub recipient_subject: ActorId,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub roots: Vec<(Hash, ContentRootContext)>,
    backup: arkret_models_crypto::KeyBackup,
}

impl RootPacket {
    pub(crate) async fn require_current_recipient(
        &self,
        conn: &mut AsyncPgConnection,
    ) -> crate::PersistenceResult<()> {
        // Historical policy acceptance and the continuing current agreement
        // are distinct checks. A retained original need not claim a new PUT.
        self.current_recipient_valid_until(conn).await?;
        Ok(())
    }

    pub(crate) async fn current_recipient_valid_until(
        &self,
        conn: &mut AsyncPgConnection,
    ) -> crate::PersistenceResult<chrono::DateTime<chrono::Utc>> {
        if self.backup.actor_id.as_realm_actor_id().is_some() {
            return crate::realm_actor_content_backup::current_root_recipient(conn, &self.backup)
                .await;
        }
        let until = crate::key_backup_history::recipient(conn, &self.backup).await?;
        Ok(self.expires_at.map_or(until, |expiry| expiry.min(until)))
    }
}

pub(crate) async fn read_in_connection(
    conn: &mut AsyncPgConnection,
    id: &BackupId,
    wanted: &[String],
) -> Result<RootPacket, PgTransactionError> {
    let backup = read_retained_envelope(conn, id).await?;
    if !matches!(
        backup.encryption.recipient_method,
        arkret_models_crypto::KeyBackupRecipientMethod::RecoveryPublicKey
            | arkret_models_crypto::KeyBackupRecipientMethod::RealmActorRecovery
    ) {
        return Err(PersistenceError::Conflict(
            "failed_precondition: root package has no recovery recipient".into(),
        )
        .into());
    }
    let roots = backup
        .contents
        .iter()
        .filter_map(|entry| match (&entry.root_ref, &entry.root_context) {
            (Some(root), Some(context)) if wanted.iter().any(|wanted| wanted == root.as_str()) => {
                Some((root.clone(), context.clone()))
            }
            _ => None,
        })
        .collect();
    Ok(RootPacket {
        actor: backup.actor_id.clone(),
        recipient_subject: backup
            .custodian_actor_id
            .clone()
            .unwrap_or_else(|| backup.actor_id.clone()),
        expires_at: backup.expires_at.flatten(),
        roots,
        backup,
    })
}

pub(crate) struct OriginalRootIndex {
    pub actor: ActorId,
    pub roots: Vec<(Hash, ContentRootContext)>,
}

/// Recheck the immutable original index after policy and Actor-series locks.
/// A current replacement can cover only this first-admitted Actor/R/context.
pub(crate) async fn original_index_in_connection(
    conn: &mut AsyncPgConnection,
    id: &BackupId,
) -> crate::PersistenceResult<OriginalRootIndex> {
    let row = sql_query("SELECT jsonb_build_object('actor',actor_id,'digest',envelope_digest,'index',content_index,'admission',writer_admission) AS payload FROM key_backup_identities WHERE id=$1 FOR SHARE")
        .bind::<diesel::sql_types::Uuid,_>(crate::ids::typed_uuid_part_expect_internal(id.as_str()))
        .get_result::<crate::JsonPayloadRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?
        .ok_or_else(|| PersistenceError::Conflict("failed_precondition: original references a missing durable root package first-admission index".into()))?.payload;
    let invalid = || {
        PersistenceError::SchemaViolation(
            "root index differs from its first native admission".into(),
        )
    };
    let actor: ActorId = serde_json::from_str(row["actor"].as_str().ok_or_else(invalid)?)
        .map_err(PersistenceError::database)?;
    let admission: crate::key_backup_authority::DeviceBackupAdmission =
        serde_json::from_value(row["admission"].clone()).map_err(PersistenceError::database)?;
    if !row["digest"]
        .as_str()
        .is_some_and(|digest| admission.authenticates_metadata(&actor, digest))
    {
        return Err(invalid());
    }
    let index: Vec<arkret_models_crypto::SecretStorageContentIndex> =
        serde_json::from_value(row["index"].clone()).map_err(PersistenceError::database)?;
    let mut roots = Vec::new();
    for entry in index {
        entry.validate().map_err(PersistenceError::database)?;
        if entry.item_kind != arkret_models_crypto::SecretStorageItemKind::ContentEpochRoot {
            return Err(invalid());
        }
        roots.push((
            entry.root_ref.ok_or_else(invalid)?,
            entry.root_context.ok_or_else(invalid)?,
        ));
    }
    if roots.is_empty() {
        return Err(invalid());
    }
    Ok(OriginalRootIndex { actor, roots })
}

/// Find a currently sufficient signed package after the Actor-series lock.
/// The caller has separately bound the original signed backup reference.
pub(crate) async fn current_root_in_connection(
    conn: &mut AsyncPgConnection,
    actor: &ActorId,
    root: &Hash,
    context: &ContentRootContext,
) -> Result<(RootPacket, chrono::DateTime<chrono::Utc>), PgTransactionError> {
    #[derive(QueryableByName)]
    struct Candidate {
        #[diesel(sql_type=diesel::sql_types::Uuid)]
        id: uuid::Uuid,
    }
    let selector = serde_json::json!([{"item_kind":"content_epoch_root","root_ref":root,"root_context":context}]);
    let mut after = uuid::Uuid::nil();
    loop {
        let page = sql_query("SELECT b.id FROM key_backups b JOIN key_backup_identities i USING(id) WHERE b.actor_id=$1 AND i.actor_id=b.actor_id AND i.deleted_at IS NULL AND b.id>$2 AND i.content_index @> $3 ORDER BY b.id LIMIT 64 FOR SHARE OF b,i")
            .bind::<Text,_>(actor.to_string()).bind::<diesel::sql_types::Uuid,_>(after)
            .bind::<Jsonb,_>(&selector).get_results::<Candidate>(&mut *conn).await?;
        let last = page.len() < 64;
        for candidate in page {
            after = candidate.id;
            let id = BackupId::new(format!("ak:backup:{}", candidate.id))
                .map_err(PersistenceError::database)?;
            let packet = read_in_connection(conn, &id, &[root.to_string()]).await?;
            if packet.actor != *actor
                || !packet.roots.iter().any(|(r, c)| r == root && c == context)
            {
                return Err(PersistenceError::SchemaViolation(
                    "replacement differs from original Actor/root/context".into(),
                )
                .into());
            }
            if packet
                .expires_at
                .is_some_and(|expires| expires <= chrono::Utc::now())
            {
                continue;
            }
            match packet.current_recipient_valid_until(conn).await {
                Ok(until) => return Ok((packet, until)),
                Err(PersistenceError::Conflict(_)) => {}
                Err(error) => return Err(error.into()),
            }
        }
        if last {
            break;
        }
    }
    Err(PersistenceError::Conflict("failed_precondition: original references a missing durable root package or sufficient current-recipient substitute".into()).into())
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
