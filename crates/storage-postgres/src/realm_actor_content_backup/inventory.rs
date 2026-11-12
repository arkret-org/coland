//! Reconstruct the complete native archive from durable first-PUT records.

use arkret_models_integration::{
    RealmActorArchiveBackupEntry, RealmActorArchiveBackupEntryKind,
    RealmActorArchiveInventoryEntry, RealmActorArchiveInventoryManifest,
    RealmActorArchiveRecipientEntry, RealmActorArchiveRecipientEntryKind,
    RealmActorArchiveSeriesEntry, RealmActorArchiveSeriesEntryKind, RealmActorContentBackupSource,
    RealmActorManagerValue,
};
use arkret_wire::ActorId;
use diesel::sql_types::{Jsonb, Nullable, Text, Uuid};
use diesel::{QueryableByName, sql_query};
use horme::RunQueryDsl;
use serde_json::{Value, json};

use super::{AsyncPgConnection, PersistenceError, PersistenceResult, lock_namespace, unavailable};

#[derive(QueryableByName)]
struct PacketRow {
    #[diesel(sql_type = Uuid)]
    id: uuid::Uuid,
    #[diesel(sql_type = Jsonb)]
    source: Value,
}

#[derive(QueryableByName)]
struct SeriesRow {
    #[diesel(sql_type = Jsonb)]
    effective_scope: Value,
    #[diesel(sql_type = Jsonb)]
    record: Value,
    #[diesel(sql_type = Jsonb)]
    source: Value,
}

#[derive(QueryableByName)]
struct RecipientRow {
    #[diesel(sql_type = Jsonb)]
    recipient_ref: Value,
    #[diesel(sql_type = Jsonb)]
    content_backup_recipient: Value,
    #[diesel(sql_type = Jsonb)]
    source: Value,
    #[diesel(sql_type = Nullable<Jsonb>)]
    recovery_begin: Option<Value>,
}

/// The caller holds the Realm lock and has independently authenticated current
/// manager archive authority. It must keep that authority through delivery;
/// the returned manifest is a custody inventory, never a bearer capability.
pub(crate) async fn inventory_in_connection(
    conn: &mut AsyncPgConnection,
    actor: &ActorId,
) -> PersistenceResult<RealmActorArchiveInventoryManifest> {
    let subject = actor
        .as_realm_actor_id()
        .ok_or_else(|| unavailable("native archive requires a full Realm actor"))?;
    let archive_revision = lock_namespace(conn, actor).await?;
    let (manager, manager_ref) = crate::realm_actor_control::current_source(
        conn,
        actor,
        json!(arkret_wire::CurrentSelector::RealmActorManager {
            actor_id: actor.clone()
        }),
    )
    .await?;
    let manager: RealmActorManagerValue = serde_json::from_value(manager).map_err(unavailable)?;
    if manager.binding_ref != manager_ref {
        return Err(unavailable(
            "current manager binding differs from its original",
        ));
    }
    let mut entries = Vec::new();
    let packets = sql_query("SELECT i.id,a.source FROM key_backup_identities i LEFT JOIN key_backups b ON b.id=i.id LEFT JOIN realm_actor_backup_admissions a ON a.backup_id=i.id WHERE i.actor_id=$1 ORDER BY i.id")
        .bind::<Text,_>(actor.to_string()).get_results::<PacketRow>(&mut *conn)
        .await.map_err(PersistenceError::database)?;
    for packet in packets {
        let id =
            arkret_wire::BackupId::new(format!("ak:backup:{}", packet.id)).map_err(unavailable)?;
        let backup = crate::content_root_packages::read_retained_envelope(conn, &id).await?;
        let native_source: RealmActorContentBackupSource =
            serde_json::from_value(packet.source).map_err(unavailable)?;
        arkret_signatures::realm_actor_content_backup::verify_realm_actor_backup_packet(
            &backup,
            &native_source.admission,
        )
        .map_err(unavailable)?;
        let receipt = &native_source.admission;
        if backup.actor_id != *actor
            || receipt.realm_actor_id != *subject
            || receipt.backup_id != id
            || receipt.envelope_digest.as_str()
                != arkret_canonical::canonical_sha256(&backup).map_err(unavailable)?
            || receipt.ciphertext_digest != backup.ciphertext_digest
            || receipt.device_id
                != native_source
                    .device_authorization
                    .event
                    .payload
                    .get("device_id")
                    .and_then(Value::as_str)
                    .and_then(|value| arkret_wire::DeviceId::new(value.to_owned()).ok())
                    .ok_or_else(|| unavailable("native original Device coordinate is absent"))?
        {
            return Err(unavailable(
                "native packet differs from its immutable first-PUT source",
            ));
        }
        let original = super::original_material(conn, &receipt.device_authorize_ref).await?;
        if arkret_canonical::canonical_json_bytes(&original).map_err(unavailable)?
            != arkret_canonical::canonical_json_bytes(&native_source.device_authorization)
                .map_err(unavailable)?
        {
            return Err(unavailable(
                "native admission has another original Device authority",
            ));
        }
        entries.push(RealmActorArchiveInventoryEntry::Backup(
            RealmActorArchiveBackupEntry {
                kind: RealmActorArchiveBackupEntryKind::Value,
                backup,
                native_source,
            },
        ));
    }
    let series = sql_query("SELECT effective_scope,record,source FROM realm_actor_backup_series WHERE realm_id=$1 AND actor_id=$2")
        .bind::<Text,_>(subject.realm_id.as_str()).bind::<Jsonb,_>(json!(actor))
        .get_results::<SeriesRow>(&mut *conn).await.map_err(PersistenceError::database)?;
    for row in series {
        let source: arkret_models_integration::RealmActorBackupEventMaterial =
            serde_json::from_value(row.source).map_err(unavailable)?;
        let source_ref = arkret_wire::CommittedEventRef {
            event_id: source.event.event_id.clone(),
            commit_id: source.commit.commit_id.clone(),
            stream_ref: source.commit.stream_ref.clone(),
            stream_position: source.commit.stream_position,
        };
        let record: arkret_models_collaboration::events_payloads::KeyBackupActiveSeries =
            serde_json::from_value(row.record).map_err(unavailable)?;
        arkret_models_collaboration::events_payloads::validate_key_backup_active_series_record(
            &record,
        )
        .map_err(unavailable)?;
        if record.actor_id != *actor
            || json!(source.event.payload) != json!(record)
            || json!(record.effective_scope) != row.effective_scope
        {
            return Err(unavailable(
                "native scoped series original differs from retained record",
            ));
        }
        if json!(super::original_material(conn, &source_ref).await?) != json!(source) {
            return Err(unavailable(
                "native series authority differs from its retained immutable original",
            ));
        }
        entries.push(RealmActorArchiveInventoryEntry::Series(
            RealmActorArchiveSeriesEntry {
                kind: RealmActorArchiveSeriesEntryKind::Value,
                effective_scope: serde_json::from_value(row.effective_scope)
                    .map_err(unavailable)?,
                record,
                source_ref,
                source,
            },
        ));
    }
    let recipients = sql_query("SELECT recipient_ref,content_backup_recipient,source,recovery_begin FROM realm_actor_backup_recipients WHERE realm_id=$1 AND actor_id=$2")
        .bind::<Text,_>(subject.realm_id.as_str()).bind::<Jsonb,_>(json!(actor))
        .get_results::<RecipientRow>(&mut *conn).await.map_err(PersistenceError::database)?;
    for row in recipients {
        let reference: arkret_wire::CommittedEventRef =
            serde_json::from_value(row.recipient_ref).map_err(unavailable)?;
        let declaration: arkret_models_integration::RealmActorBackupEventMaterial =
            serde_json::from_value(row.source).map_err(unavailable)?;
        if json!(super::original_material(conn, &reference).await?) != json!(declaration) {
            return Err(unavailable(
                "native recipient authority differs from its retained immutable original",
            ));
        }
        let recovery_begin: Option<arkret_models_integration::RealmActorBackupEventMaterial> = row
            .recovery_begin
            .map(serde_json::from_value)
            .transpose()
            .map_err(unavailable)?;
        if let Some(begin) = &recovery_begin {
            let reference = arkret_wire::CommittedEventRef {
                event_id: begin.event.event_id.clone(),
                commit_id: begin.commit.commit_id.clone(),
                stream_ref: begin.commit.stream_ref.clone(),
                stream_position: begin.commit.stream_position,
            };
            if json!(super::original_material(conn, &reference).await?) != json!(begin) {
                return Err(unavailable(
                    "native reset begin authority differs from original",
                ));
            }
        }
        entries.push(RealmActorArchiveInventoryEntry::Recipient(
            RealmActorArchiveRecipientEntry {
                kind: RealmActorArchiveRecipientEntryKind::Value,
                recipient_ref: reference,
                content_backup_recipient: serde_json::from_value(row.content_backup_recipient)
                    .map_err(unavailable)?,
                declaration,
                recovery_begin,
            },
        ));
    }
    let mut manifest = RealmActorArchiveInventoryManifest {
        realm_actor_id: subject.clone(),
        manager_ref,
        archive_revision,
        entries,
    };
    manifest.sort_entries().map_err(unavailable)?;
    manifest.validate_order().map_err(unavailable)?;
    for entry in &manifest.entries {
        let recipient = match entry {
            RealmActorArchiveInventoryEntry::Backup(entry) => {
                Some(&entry.native_source.admission.recipient_ref)
            }
            RealmActorArchiveInventoryEntry::Series(entry) => entry.record.recipient_ref.as_ref(),
            RealmActorArchiveInventoryEntry::Recipient(_) => None,
        };
        if let Some(recipient) = recipient {
            if !manifest.entries.iter().any(|entry|matches!(entry,RealmActorArchiveInventoryEntry::Recipient(entry) if &entry.recipient_ref==recipient)) {
                return Err(unavailable("native inventory omits a retained packet or series recipient declaration"));
            }
        }
    }
    Ok(manifest)
}

/// Run on the frozen private-state export/import cut. This checks the real
/// retained relations rather than accepting a canonical hash of disconnected
/// rows. Historical cryptographic source validation also runs at every archive
/// delivery; this function never derives an authority from a claimed receipt.
pub(crate) async fn validate_archived_namespaces(
    conn: &mut AsyncPgConnection,
    realm: &arkret_wire::RealmId,
) -> PersistenceResult<()> {
    #[derive(QueryableByName)]
    struct Namespace {
        #[diesel(sql_type=Jsonb)]
        actor_id: Value,
    }
    let missing=sql_query("SELECT c.actor_id FROM realm_actor_creations c LEFT JOIN realm_actor_backup_namespaces n ON n.realm_id=c.realm_id AND n.actor_id=c.actor_id WHERE c.realm_id=$1 AND n.actor_id IS NULL")
        .bind::<Text,_>(realm.as_str()).get_results::<Namespace>(&mut *conn).await.map_err(PersistenceError::database)?;
    if !missing.is_empty() {
        return Err(unavailable(
            "accepted native actor has no immutable backup namespace",
        ));
    }
    let actors=sql_query("SELECT actor_id FROM realm_actor_backup_namespaces WHERE realm_id=$1 ORDER BY actor_id::text")
        .bind::<Text,_>(realm.as_str()).get_results::<Namespace>(&mut *conn).await.map_err(PersistenceError::database)?;
    for row in actors {
        let actor: ActorId = serde_json::from_value(row.actor_id).map_err(unavailable)?;
        let inventory = inventory_in_connection(conn, &actor).await?;
        for entry in &inventory.entries {
            match entry {
                RealmActorArchiveInventoryEntry::Backup(entry) => {
                    #[derive(QueryableByName)]
                    struct Outcome {
                        #[diesel(sql_type=Jsonb)]
                        fixed_reply: Value,
                        #[diesel(sql_type=Text)]
                        idempotency_key: String,
                    }
                    let retained=sql_query("SELECT fixed_reply,idempotency_key FROM realm_actor_backup_admissions WHERE realm_id=$1 AND actor_id=$2 AND backup_id=$3")
                        .bind::<Text,_>(realm.as_str()).bind::<Jsonb,_>(json!(actor))
                        .bind::<Uuid,_>(crate::ids::typed_uuid_part_expect_internal(entry.backup.backup_id.as_str()))
                        .get_result::<Outcome>(&mut *conn).await.map_err(PersistenceError::database)?;
                    let reply: arkret_models_crypto::RealmActorBackupPutResponseBody =
                        serde_json::from_value(retained.fixed_reply).map_err(unavailable)?;
                    if retained.idempotency_key.is_empty()
                        || retained.idempotency_key.len() > 128
                        || reply.status != arkret_models_crypto::KeyBackupPutStatus::Accepted
                        || reply.backup_id != entry.backup.backup_id
                        || reply.ciphertext_digest != entry.backup.ciphertext_digest
                        || json!(reply.admission) != json!(entry.native_source.admission)
                    {
                        return Err(unavailable(
                            "native archive fixed PUT outcome differs from its retained original source",
                        ));
                    }
                }
                RealmActorArchiveInventoryEntry::Recipient(entry) => {
                    super::require_recipient_original(
                        conn,
                        &actor,
                        &entry.recipient_ref,
                        &entry.content_backup_recipient,
                    )
                    .await?;
                }
                RealmActorArchiveInventoryEntry::Series(_) => {}
            }
        }
    }
    Ok(())
}
