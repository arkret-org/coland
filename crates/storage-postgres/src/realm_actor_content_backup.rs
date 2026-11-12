//! Native root custody shares one full-actor lock across its private ledgers.

use arkret_models_integration::{
    RealmActorArchiveRecipientEntry, RealmActorArchiveRecipientEntryKind,
    RealmActorBackupEventMaterial, RealmActorRecoveryValue,
};
use arkret_wire::{ActorId, RealmId};
use coland_storage::{PersistenceError, PersistenceResult};
use diesel::sql_types::{BigInt, Jsonb, Text};
use diesel::{QueryableByName, sql_query};
use horme::{OptionalExtension, RunQueryDsl};
use serde_json::{Value, json};

use crate::AsyncPgConnection;

mod inventory;
mod material;
mod publication;
mod series;
mod unlock;
pub(crate) use unlock::{consume_native_unlock, issue_native_unlock};
mod reading;
pub(crate) use inventory::{inventory_in_connection, validate_archived_namespaces};
pub(crate) use material::prepare_input_in_connection;
pub(crate) use publication::{put_native, recover_put};
pub(crate) use reading::{native_head, native_inventory, native_inventory_delivery};
pub(crate) use series::admit_series;

/// Business use of a retained native root still requires its accepted public
/// recipient to be the live agreement. This is not a fresh PUT or archive read.
pub(crate) async fn current_root_recipient(
    conn: &mut AsyncPgConnection,
    backup: &arkret_models_crypto::KeyBackup,
) -> PersistenceResult<chrono::DateTime<chrono::Utc>> {
    backup.validate().map_err(unavailable)?;
    let actor = &backup.actor_id;
    let binding = backup
        .auth_binding
        .as_ref()
        .ok_or_else(|| unavailable("native root has no original binding"))?;
    let (recovery, _) = crate::realm_actor_control::current_source(
        conn,
        actor,
        json!(arkret_wire::CurrentSelector::RealmActorRecovery {
            actor_id: actor.clone()
        }),
    )
    .await?;
    let recovery: RealmActorRecoveryValue =
        serde_json::from_value(recovery).map_err(unavailable)?;
    let (manager, manager_ref) = crate::realm_actor_control::current_source(
        conn,
        actor,
        json!(arkret_wire::CurrentSelector::RealmActorManager {
            actor_id: actor.clone()
        }),
    )
    .await?;
    let manager: arkret_models_integration::RealmActorManagerValue =
        serde_json::from_value(manager).map_err(unavailable)?;
    if recovery.pending.is_some()
        || manager.binding_ref != manager_ref
        || binding.manager_ref != manager_ref
        || binding.recipient_ref != recovery.content_backup_recipient_ref
        || backup.encryption.recipient_key_ref.as_deref()
            != Some(recovery.content_backup_recipient.key_agreement_ref.as_str())
    {
        return Err(unavailable(
            "native root has no continuing current manager/recipient agreement",
        ));
    }
    require_recipient_original(
        conn,
        actor,
        &binding.recipient_ref,
        &recovery.content_backup_recipient,
    )
    .await?;
    let declaration = original_material(conn, &binding.recipient_ref).await?;
    let row=sql_query("SELECT source AS value FROM realm_actor_backup_recipients WHERE realm_id=$1 AND actor_id=$2 AND recipient_ref=$3 AND content_backup_recipient=$4 FOR SHARE")
        .bind::<Text,_>(actor.as_realm_actor_id().ok_or_else(||unavailable("native root actor absent"))?.realm_id.as_str())
        .bind::<Jsonb,_>(json!(actor)).bind::<Jsonb,_>(json!(binding.recipient_ref))
        .bind::<Jsonb,_>(json!(recovery.content_backup_recipient)).get_result::<JsonRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?
        .ok_or_else(||unavailable("native root recipient original is not retained"))?;
    if row.value != json!(declaration) {
        return Err(unavailable(
            "native root recipient declaration differs from its immutable original",
        ));
    }
    Ok(chrono::DateTime::<chrono::Utc>::MAX_UTC)
}

#[derive(QueryableByName)]
struct Revision {
    #[diesel(sql_type = BigInt)]
    archive_revision: i64,
}

#[derive(QueryableByName)]
struct ActorRow {
    #[diesel(sql_type = Jsonb)]
    actor_id: Value,
}

#[derive(QueryableByName)]
struct JsonRow {
    #[diesel(sql_type = Jsonb)]
    value: Value,
}

fn unavailable(detail: impl std::fmt::Display) -> PersistenceError {
    PersistenceError::Conflict(format!("temporarily_unavailable: {detail}"))
}

/// Compare the continuing public agreement to its exact immutable declaration;
/// current DID discovery never substitutes for a missing accepted original.
pub(crate) async fn require_recipient_original(
    conn: &mut AsyncPgConnection,
    actor: &ActorId,
    reference: &arkret_wire::CommittedEventRef,
    descriptor: &arkret_models_crypto::RealmActorContentBackupRecipient,
) -> PersistenceResult<()> {
    let original = original_material(conn, reference).await?;
    match original.event.kind {
        arkret_wire::EventKind::RealmActorCreate => {
            let payload: arkret_models_integration::RealmActorCreatePayload =
                serde_json::from_value(json!(original.event.payload)).map_err(unavailable)?;
            if payload.actor_id != *actor
                || payload.recovery.content_backup_recipient != *descriptor
            {
                return Err(unavailable(
                    "recipient differs from accepted creation declaration",
                ));
            }
            arkret_identity::verify_realm_actor_initial_resolution(
                &payload,
                original.commit.committed_at,
            )
            .map_err(unavailable)?;
        }
        arkret_wire::EventKind::RealmActorManagerChange => {
            let payload: arkret_models_integration::RealmActorManagerChangePayload =
                serde_json::from_value(json!(original.event.payload)).map_err(unavailable)?;
            if original.event.actor_id != *actor
                || payload.next_content_backup_recipient != *descriptor
            {
                return Err(unavailable(
                    "recipient differs from accepted manager declaration",
                ));
            }
        }
        arkret_wire::EventKind::RealmActorControlReset => {
            let payload: arkret_models_integration::RealmActorControlResetPayload =
                serde_json::from_value(json!(original.event.payload)).map_err(unavailable)?;
            let begin = original_material(conn, &payload.recovery_begin_ref).await?;
            let plan: arkret_models_integration::RealmActorRecoveryBeginPayload =
                serde_json::from_value(json!(begin.event.payload)).map_err(unavailable)?;
            if begin.event.kind != arkret_wire::EventKind::RealmActorRecoveryBegin
                || begin.event.actor_id != original.event.actor_id
                || plan.target_actor_id != *actor
                || plan.next_content_backup_recipient.as_ref() != Some(descriptor)
            {
                return Err(unavailable(
                    "reset recipient is not the exact frozen accepted begin replacement",
                ));
            }
            arkret_identity::verify_realm_actor_recovery_publication(
                &plan,
                &payload.published_method_history_evidence,
                original.commit.committed_at,
            )
            .map_err(unavailable)?;
        }
        _ => {
            return Err(unavailable(
                "recipient declaration writer is not registered",
            ));
        }
    }
    Ok(())
}

/// A changed manager cannot resume daily work on pointers selected by the old
/// manager. No Device PUT is required while paused: that still needs active
/// business authority and is performed only after the explicit resume.
pub(crate) async fn require_manager_resume_ready(
    conn: &mut AsyncPgConnection,
    actor: &ActorId,
) -> PersistenceResult<()> {
    let (manager, manager_ref) = crate::realm_actor_control::current_source(
        conn,
        actor,
        json!(arkret_wire::CurrentSelector::RealmActorManager {
            actor_id: actor.clone()
        }),
    )
    .await?;
    let manager: arkret_models_integration::RealmActorManagerValue =
        serde_json::from_value(manager).map_err(unavailable)?;
    let original = original_material(conn, &manager_ref).await?;
    if original.event.kind != arkret_wire::EventKind::RealmActorManagerChange {
        return Ok(());
    }
    lock_namespace(conn, actor).await?;
    let (recovery, _) = crate::realm_actor_control::current_source(
        conn,
        actor,
        json!(arkret_wire::CurrentSelector::RealmActorRecovery {
            actor_id: actor.clone()
        }),
    )
    .await?;
    let recovery: RealmActorRecoveryValue =
        serde_json::from_value(recovery).map_err(unavailable)?;
    let creation = crate::realm_actor_control::creation_source(conn, actor).await?;
    let manifest = inventory_in_connection(conn, actor).await?;
    let mut scopes = std::collections::BTreeMap::new();
    scopes.insert(
        arkret_canonical::canonical_json_bytes(&creation.creation_scope).map_err(unavailable)?,
        creation.creation_scope,
    );
    for entry in &manifest.entries {
        let scope = match entry {
            arkret_models_integration::RealmActorArchiveInventoryEntry::Series(entry) => {
                Some(&entry.effective_scope)
            }
            arkret_models_integration::RealmActorArchiveInventoryEntry::Backup(entry) => {
                Some(&entry.native_source.admission.effective_scope)
            }
            _ => None,
        };
        if let Some(scope) = scope {
            scopes.insert(
                arkret_canonical::canonical_json_bytes(scope).map_err(unavailable)?,
                scope.clone(),
            );
        }
    }
    for scope in scopes.values() {
        let selector = arkret_wire::CurrentSelector::RealmActorKeyBackupActiveSeries {
            actor_id: actor.clone(),
            effective_scope: scope.clone(),
            backup_kind: arkret_wire::RealmActorBackupKind::SecretStorage,
        };
        let (value, _) =
            crate::realm_actor_control::optional_current_source(conn, actor, json!(selector))
                .await?
                .ok_or_else(|| {
                    PersistenceError::Conflict(
                "failed_precondition: new manager has not selected every necessary scoped series"
                    .into(),
            )
                })?;
        let value: arkret_models_collaboration::RealmActorKeyBackupActiveSeriesValue =
            serde_json::from_value(value).map_err(unavailable)?;
        if manager.binding_ref != manager_ref
            || value.manager_ref != manager_ref
            || value.recipient_ref != recovery.content_backup_recipient_ref
        {
            return Err(PersistenceError::Conflict("failed_precondition: new manager scoped series or recipient is not ready for resume".into()));
        }
    }
    Ok(())
}

/// Called only with the parent Realm authorization lock already held. This is
/// the same advisory lock used by immutable packet identity reservation.
pub(crate) async fn lock_namespace(
    conn: &mut AsyncPgConnection,
    actor: &ActorId,
) -> PersistenceResult<u64> {
    let subject = actor
        .as_realm_actor_id()
        .ok_or_else(|| unavailable("native backup namespace requires a full Realm actor"))?;
    crate::key_backup::lock_backup_series_in_connection(conn, actor).await?;
    let row = sql_query("SELECT archive_revision FROM realm_actor_backup_namespaces WHERE realm_id=$1 AND actor_id=$2 FOR UPDATE")
        .bind::<Text, _>(subject.realm_id.as_str())
        .bind::<Jsonb, _>(json!(actor))
        .get_result::<Revision>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?
        .ok_or_else(|| unavailable("accepted native backup namespace is absent"))?;
    u64::try_from(row.archive_revision).map_err(unavailable)
}

pub(crate) async fn initialize_namespace(
    conn: &mut AsyncPgConnection,
    actor: &ActorId,
) -> PersistenceResult<()> {
    let subject = actor
        .as_realm_actor_id()
        .ok_or_else(|| unavailable("native backup namespace requires a full Realm actor"))?;
    crate::key_backup::lock_backup_series_in_connection(conn, actor).await?;
    sql_query("INSERT INTO realm_actor_backup_namespaces(realm_id,actor_id,archive_revision) VALUES($1,$2,0) ON CONFLICT(realm_id,actor_id) DO NOTHING")
        .bind::<Text, _>(subject.realm_id.as_str())
        .bind::<Jsonb, _>(json!(actor))
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
    Ok(())
}

/// Lock in deterministic actor order before exporting/importing the complete
/// governing Realm private state. No business reference or current scope limits
/// which native namespace participates in the frozen commitment.
pub(crate) async fn lock_realm_namespaces(
    conn: &mut AsyncPgConnection,
    realm: &RealmId,
) -> PersistenceResult<()> {
    let actors = sql_query(
        "SELECT actor_id FROM realm_actor_backup_namespaces WHERE realm_id=$1 ORDER BY actor_id",
    )
    .bind::<Text, _>(realm.as_str())
    .get_results::<ActorRow>(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    for actor in actors {
        let actor: ActorId = serde_json::from_value(actor.actor_id).map_err(unavailable)?;
        lock_namespace(conn, &actor).await?;
    }
    Ok(())
}

/// Exact replay and reads do not call this. Every actual custody mutation calls
/// it in its own transaction while holding the parent and namespace locks.
pub(crate) async fn advance_revision(
    conn: &mut AsyncPgConnection,
    actor: &ActorId,
    expected: u64,
) -> PersistenceResult<u64> {
    let subject = actor
        .as_realm_actor_id()
        .ok_or_else(|| unavailable("native backup namespace requires a full Realm actor"))?;
    let expected = i64::try_from(expected).map_err(unavailable)?;
    let row = sql_query("UPDATE realm_actor_backup_namespaces SET archive_revision=archive_revision+1 WHERE realm_id=$1 AND actor_id=$2 AND archive_revision=$3 AND archive_revision<9223372036854775807 RETURNING archive_revision")
        .bind::<Text, _>(subject.realm_id.as_str())
        .bind::<Jsonb, _>(json!(actor))
        .bind::<BigInt, _>(expected)
        .get_result::<Revision>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?
        .ok_or_else(|| unavailable("native backup archive revision changed or overflowed"))?;
    u64::try_from(row.archive_revision).map_err(unavailable)
}

pub(crate) async fn original_material(
    conn: &mut AsyncPgConnection,
    reference: &arkret_wire::CommittedEventRef,
) -> PersistenceResult<RealmActorBackupEventMaterial> {
    let (event, commit) = crate::realm_actor_control_source::original(conn, reference).await?;
    let producer_signer_fact =
        crate::agent_producer_signer_keys::producer_source_for_commit_in_connection(
            conn, &event, &commit,
        )
        .await?
        .ok_or_else(|| unavailable("native archive original producer source is absent"))?;
    Ok(RealmActorBackupEventMaterial {
        event,
        commit,
        producer_signer_fact,
    })
}

/// Retain the original declaration exactly once. A reset without a replacement,
/// an enable toggle and an unrelated current writer keep the old reference and
/// therefore cannot invent a new declaration or advance the archive revision.
pub(crate) async fn retain_current_recipient(
    conn: &mut AsyncPgConnection,
    actor: &ActorId,
) -> PersistenceResult<()> {
    let subject = actor
        .as_realm_actor_id()
        .ok_or_else(|| unavailable("native archive recipient requires a Realm actor"))?;
    let revision = lock_namespace(conn, actor).await?;
    let (value, _) = crate::realm_actor_control::current_source(
        conn,
        actor,
        json!(arkret_wire::CurrentSelector::RealmActorRecovery {
            actor_id: actor.clone()
        }),
    )
    .await?;
    let recovery: RealmActorRecoveryValue = serde_json::from_value(value).map_err(unavailable)?;
    let reference = recovery.content_backup_recipient_ref;
    let declaration = original_material(conn, &reference).await?;
    let recovery_begin = if declaration.event.kind == arkret_wire::EventKind::RealmActorControlReset
    {
        let payload: arkret_models_integration::RealmActorControlResetPayload =
            serde_json::from_value(json!(declaration.event.payload)).map_err(unavailable)?;
        Some(original_material(conn, &payload.recovery_begin_ref).await?)
    } else {
        None
    };
    let entry = RealmActorArchiveRecipientEntry {
        kind: RealmActorArchiveRecipientEntryKind::Value,
        recipient_ref: reference.clone(),
        content_backup_recipient: recovery.content_backup_recipient,
        declaration,
        recovery_begin,
    };
    let previous = sql_query("SELECT jsonb_build_object('kind','recipient','recipient_ref',recipient_ref,'content_backup_recipient',content_backup_recipient,'declaration',source) || CASE WHEN recovery_begin IS NULL THEN '{}'::jsonb ELSE jsonb_build_object('recovery_begin',recovery_begin) END AS value FROM realm_actor_backup_recipients WHERE realm_id=$1 AND actor_id=$2 AND recipient_ref=$3")
        .bind::<Text,_>(subject.realm_id.as_str()).bind::<Jsonb,_>(json!(actor))
        .bind::<Jsonb,_>(json!(reference)).get_result::<JsonRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
    if let Some(previous) = previous {
        if previous.value != serde_json::to_value(&entry).map_err(unavailable)? {
            return Err(unavailable(
                "native recipient original conflicts with retained custody",
            ));
        }
        return Ok(());
    }
    sql_query("INSERT INTO realm_actor_backup_recipients(realm_id,actor_id,recipient_ref,content_backup_recipient,source,recovery_begin) VALUES($1,$2,$3,$4,$5,$6)")
        .bind::<Text,_>(subject.realm_id.as_str()).bind::<Jsonb,_>(json!(actor))
        .bind::<Jsonb,_>(json!(entry.recipient_ref)).bind::<Jsonb,_>(json!(entry.content_backup_recipient))
        .bind::<Jsonb,_>(json!(entry.declaration))
        .bind::<diesel::sql_types::Nullable<Jsonb>,_>(entry.recovery_begin.as_ref().map(|value|json!(value)))
        .execute(&mut *conn).await.map_err(PersistenceError::database)?;
    advance_revision(conn, actor, revision).await?;
    Ok(())
}
