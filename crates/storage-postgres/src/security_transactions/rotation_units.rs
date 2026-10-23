//! The SecurityRotation steps after `revoke` that carry a durable effect
//! (security-transactions.md §3): the coordinator-owned
//! `upload_new_material` and `switch_authoritative_pointer`, and the
//! client-attested terminal `local_commit`. Each is one PostgreSQL
//! transaction that rechecks its durable dependencies at the locked PCR cut
//! and appends its accepted step together with the effect, so a refusal
//! leaves no backup, Event, Commit, pointer or step behind and a replay reads
//! the first result.

use arkret_models_collaboration::events_payloads::KeyBackupActiveSeries;
use arkret_models_crypto::{BackupKind, KeyBackup, SecurityTransactionStep};
use arkret_wire::{AccountId, ActorId, DeviceId, RealmId};
use coland_storage::{
    ConflictCode, KeyBackupActiveSeriesCommitOutcome, KeyBackupActiveSeriesCommitWrite,
    PersistenceError, RotationLocalCommitWrite, RotationPointerSwitchWrite,
    RotationUploadCommitWrite, SecurityTransactionRecord,
};
use diesel::sql_types::{BigInt, Jsonb, Nullable, Text};
use diesel::{QueryableByName, sql_query};
use horme::{OptionalExtension, RunQueryDsl};
use serde_json::Value;

use super::{
    AsyncPgConnection, PgTransactionError, StepAttemptSource, accept_step_in_transaction, load_one,
    load_step_outcome,
};
use crate::key_backup_current_results::{
    commit_key_backup_pointer_unit_in_connection, verification_method_device,
};
use crate::pcr_device_status_fold::PcrDeviceLifecycle;
use crate::pcr_device_status_reader::{
    ConfirmedPcrDeviceStatusCut, confirmed_pcr_device_status_cut_in_connection,
};

/// Every refusal carries a registered [`ConflictCode`] or wire reason prefix
/// so the worker decides between retry and abort without reading prose.
fn rejected(code: impl std::fmt::Display, reason: &str) -> PgTransactionError {
    PersistenceError::Conflict(format!("{code}: {reason}")).into()
}

#[derive(QueryableByName)]
struct PcrRealmRow {
    #[diesel(sql_type = Text)]
    pcr_realm_id: String,
}

#[derive(QueryableByName)]
struct CurrentAccountDidRow {
    #[diesel(sql_type = Text)]
    did: String,
}

#[derive(QueryableByName)]
struct HeadRow {
    #[diesel(sql_type = Text)]
    commit_id: String,
}

#[derive(QueryableByName)]
struct StoredBackupRow {
    #[diesel(sql_type = Text)]
    id: String,
    #[diesel(sql_type = Jsonb)]
    payload: Value,
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

#[derive(QueryableByName)]
struct PointerValueRow {
    #[diesel(sql_type = Jsonb)]
    value: Value,
}

/// Lock the transaction row and decide replay versus first write. `Ok(Some)`
/// is the stored result of an exact replay; `Ok(None)` means `step` is the
/// next step and `write` appends exactly it to the durable resource.
async fn begin_worker_step(
    conn: &mut AsyncPgConnection,
    transaction: &SecurityTransactionRecord,
    canonical_request: &[u8],
    step: SecurityTransactionStep,
) -> Result<Option<SecurityTransactionRecord>, PgTransactionError> {
    let transaction_id = transaction.resource.transaction_id.as_str();
    let existing = load_one(conn, transaction_id, true)
        .await?
        .ok_or_else(|| rejected(ConflictCode::FailedPrecondition, "rotation is absent"))?;
    if existing.canonical_request != transaction.canonical_request {
        return Err(rejected(
            ConflictCode::DuplicateConflict,
            "rotation step changed its original canonical request",
        ));
    }
    if let Some(stored) = load_step_outcome(conn, transaction_id, step).await? {
        if stored.canonical_request != canonical_request {
            return Err(rejected(
                ConflictCode::DuplicateConflict,
                "rotation step was accepted for different canonical bytes",
            ));
        }
        return Ok(Some(existing));
    }
    let next = existing
        .resource
        .next_required_step()
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    if next != Some(step) {
        return Err(rejected(
            ConflictCode::FailedPrecondition,
            "rotation is not at this coordinator-owned step",
        ));
    }
    let mut prior = transaction.resource.clone();
    prior.accepted_steps.pop();
    if existing.resource != prior {
        return Err(rejected(
            ConflictCode::DuplicateConflict,
            "rotation step does not extend the durable resource by exactly one step",
        ));
    }
    Ok(None)
}

async fn pcr_realm(
    conn: &mut AsyncPgConnection,
    account: &AccountId,
) -> Result<RealmId, PgTransactionError> {
    let row = sql_query(
        "SELECT pcr_realm_id FROM principal_resolutions WHERE principal_id=$1 AND station_id=$2",
    )
    .bind::<Text, _>(account.principal_id.as_str())
    .bind::<Text, _>(account.station_id.as_str())
    .get_result::<PcrRealmRow>(&mut *conn)
    .await
    .optional()?
    .ok_or_else(|| {
        rejected(
            ConflictCode::TemporarilyUnavailable,
            "rotation Account has no PCR",
        )
    })?;
    RealmId::new(row.pcr_realm_id)
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()).into())
}

/// Serialize with every PCR head writer (they take this row `FOR UPDATE`).
async fn lock_pcr(
    conn: &mut AsyncPgConnection,
    realm_id: &RealmId,
    exclusive: bool,
) -> Result<(), PgTransactionError> {
    let mode = if exclusive { "UPDATE" } else { "SHARE" };
    sql_query(format!(
        "SELECT realm_id AS pcr_realm_id FROM realm_authorities WHERE realm_id=$1 FOR {mode}"
    ))
    .bind::<Text, _>(realm_id.as_str())
    .get_result::<PcrRealmRow>(&mut *conn)
    .await
    .optional()?
    .ok_or_else(|| {
        rejected(
            ConflictCode::TemporarilyUnavailable,
            "rotation PCR authority is absent",
        )
    })?;
    Ok(())
}

/// The rotation's signing device (the authorizing device for the worker
/// steps, the attesting device for `local_commit`) must still be `active` at
/// the locked cut.
async fn active_authorizer_cut(
    conn: &mut AsyncPgConnection,
    account: &AccountId,
    device_id: &DeviceId,
    realm_id: &RealmId,
    at: chrono::DateTime<chrono::Utc>,
) -> Result<ConfirmedPcrDeviceStatusCut, PgTransactionError> {
    let cut = confirmed_pcr_device_status_cut_in_connection(conn, account, device_id, at)
        .await?
        .ok_or_else(|| {
            rejected(
                ConflictCode::TemporarilyUnavailable,
                "rotation signing device has no confirmed PCR cut",
            )
        })?;
    if &cut.authority.realm_id != realm_id {
        return Err(rejected(
            ConflictCode::FailedPrecondition,
            "rotation signing device belongs to another PCR",
        ));
    }
    if cut.lifecycle != PcrDeviceLifecycle::Active {
        let code = match cut.lifecycle {
            PcrDeviceLifecycle::Revoked => ConflictCode::DeviceRevoked,
            PcrDeviceLifecycle::RevocationPending => ConflictCode::DeviceRevocationPending,
            _ => ConflictCode::FailedPrecondition,
        };
        return Err(rejected(
            code,
            "rotation signing device is not active at the PCR cut",
        ));
    }
    Ok(cut)
}

/// Verify one planned replacement envelope against the authorizing device's
/// current accepted authorization at the locked cut.
async fn verify_replacement_envelope(
    conn: &mut AsyncPgConnection,
    backup: &KeyBackup,
    cut: &ConfirmedPcrDeviceStatusCut,
    account: &AccountId,
    authorizer: &DeviceId,
) -> Result<(), PgTransactionError> {
    let authorization = cut.authority.authorization.as_ref().ok_or_else(|| {
        rejected(
            ConflictCode::FailedPrecondition,
            "rotation authorizing device has no authorization",
        )
    })?;
    let generation = cut.authority.current_generation.ok_or_else(|| {
        rejected(
            ConflictCode::TemporarilyUnavailable,
            "rotation PCR has no current generation",
        )
    })?;
    if &backup.auth_data.device_id != authorizer
        || backup
            .device_id
            .as_ref()
            .is_some_and(|device| device != authorizer)
        || verification_method_device(&backup.auth_data.verification_method, account).as_ref()
            != Some(authorizer)
    {
        return Err(rejected(
            ConflictCode::SignatureInvalid,
            "replacement backup is not signed by the rotation's authorizing device",
        ));
    }
    if backup.auth_data.device_authorize_event_id != authorization.event_id {
        return Err(rejected(
            ConflictCode::SignatureInvalid,
            "replacement backup names a device authorization that is not current",
        ));
    }
    if let Some(source) = &backup.source_commit_ref {
        if source.device_generation_ref != generation {
            return Err(rejected(
                "backup_revision_stale",
                "replacement backup generation is not current",
            ));
        }
        let checkpoint = sql_query(
            "SELECT \
               (SELECT c.stream_position FROM realm_commits c WHERE c.commit_id=$2 AND c.realm_id=$1 \
                  AND c.stream_ref=jsonb_build_object('kind','realm','realm_id',$1::text)) AS source_position, \
               (SELECT g.current_stream_position FROM pcr_device_generation_current_results g \
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
                    "replacement backup source is not an accepted PCR Commit under the current generation and device",
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
        backup.auth_data.signature.as_str(),
    ) {
        return Err(rejected(
            ConflictCode::SignatureInvalid,
            "replacement backup signature does not match the authorizing device key",
        ));
    }
    Ok(())
}

/// The planned envelopes, typed, bound to their reserved refs and ordered as
/// one complete fresh series chain.
fn planned_replacement_chain(
    transaction: &SecurityTransactionRecord,
) -> Result<Vec<(KeyBackup, Value)>, PgTransactionError> {
    let resource = &transaction.resource;
    let plan = resource
        .security_rotation_plan()
        .ok_or_else(|| rejected(ConflictCode::SchemaViolation, "not a SecurityRotation"))?;
    let [rotation] = plan.backup_rotations.as_slice() else {
        return Err(rejected(
            ConflictCode::SchemaViolation,
            "rotation plan must carry exactly one secret_storage rotation",
        ));
    };
    let binding = &rotation.binding;
    let envelopes = &rotation.new_backup_envelopes;
    if envelopes.len() != binding.new_backups.len() {
        return Err(rejected(
            ConflictCode::SchemaViolation,
            "prepared backup envelopes differ from the reserved replacement set",
        ));
    }
    let actor = ActorId::account(resource.account_id.clone());
    let mut chain = Vec::with_capacity(envelopes.len());
    let mut previous_id: Option<&str> = None;
    for (backup, reserved) in envelopes.iter().zip(&binding.new_backups) {
        backup.validate().map_err(|error| {
            rejected(
                ConflictCode::SchemaViolation,
                &format!("prepared replacement backup is invalid: {error}"),
            )
        })?;
        let value = serde_json::to_value(backup).map_err(PersistenceError::database)?;
        if previous_id.is_some_and(|previous| previous >= backup.backup_id.as_str()) {
            return Err(rejected(
                ConflictCode::SchemaViolation,
                "prepared replacement backups are not in distinct canonical backup_id order",
            ));
        }
        previous_id = Some(backup.backup_id.as_str());
        if reserved.backup_id != backup.backup_id
            || reserved.ciphertext_digest != backup.ciphertext_digest
            || backup.actor_id != actor
            || backup.backup_kind != BackupKind::SecretStorage
            || backup.series_id != binding.new_series_id
        {
            return Err(rejected(
                ConflictCode::SchemaViolation,
                "prepared replacement backup differs from its reserved identity, series, class or digest",
            ));
        }
        chain.push((backup.clone(), value));
    }
    chain.sort_by_key(|(backup, _)| backup.series_seq);
    let mut predecessor: Option<&KeyBackup> = None;
    for (index, (backup, _)) in chain.iter().enumerate() {
        let linked = match predecessor {
            None => {
                backup.series_seq == 0
                    && backup.supersedes_id.is_none()
                    && backup.supersedes_digest.is_none()
            }
            Some(previous) => {
                let digest = arkret_canonical::sha256_digest(
                    previous
                        .signing_payload_bytes()
                        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?,
                );
                u64::try_from(index).ok() == Some(backup.series_seq)
                    && backup.supersedes_id.as_ref() == Some(&previous.backup_id)
                    && backup
                        .supersedes_digest
                        .as_ref()
                        .is_some_and(|value| value.as_str() == digest)
            }
        };
        if !linked {
            return Err(rejected(
                "series_chain_broken",
                "prepared replacement backups are not one fresh series chain",
            ));
        }
        predecessor = Some(backup);
    }
    Ok(chain)
}

pub(super) async fn commit_rotation_upload_in_connection(
    conn: &mut AsyncPgConnection,
    write: RotationUploadCommitWrite,
) -> Result<SecurityTransactionRecord, PgTransactionError> {
    write.validate()?;
    if let Some(stored) = begin_worker_step(
        conn,
        &write.transaction,
        &write.step_outcome.canonical_request,
        SecurityTransactionStep::UploadNewMaterial,
    )
    .await?
    {
        return Ok(stored);
    }
    let resource = &write.transaction.resource;
    let account = &resource.account_id;
    let authorizer = resource.authorizing_device_id.clone().ok_or_else(|| {
        rejected(
            ConflictCode::FailedPrecondition,
            "rotation authorizing device is absent",
        )
    })?;
    let accepted_at = resource
        .accepted_steps
        .last()
        .expect("validated worker step")
        .accepted_at;
    let chain = planned_replacement_chain(&write.transaction)?;
    let realm_id = pcr_realm(conn, account).await?;
    lock_pcr(conn, &realm_id, false).await?;
    let cut = active_authorizer_cut(conn, account, &authorizer, &realm_id, accepted_at).await?;

    let series_id = chain[0].0.series_id.clone();
    let existing =
        sql_query("SELECT id::text AS id, payload FROM key_backups WHERE series_id=$1 FOR UPDATE")
            .bind::<Text, _>(series_id.as_str())
            .load::<StoredBackupRow>(&mut *conn)
            .await?;
    for row in &existing {
        let planned = chain.iter().find(|(backup, _)| {
            crate::ids::typed_uuid_part_expect_internal(backup.backup_id.as_str()).to_string()
                == row.id
        });
        if planned.is_none_or(|(_, value)| *value != row.payload) {
            return Err(rejected(
                ConflictCode::DuplicateConflict,
                "the reserved replacement series already holds other bytes",
            ));
        }
    }
    for (backup, value) in &chain {
        verify_replacement_envelope(conn, backup, &cut, account, &authorizer).await?;
        let uuid = crate::ids::typed_uuid_part_expect_internal(backup.backup_id.as_str());
        let stored =
            sql_query("SELECT id::text AS id, payload FROM key_backups WHERE id=$1 FOR UPDATE")
                .bind::<diesel::sql_types::Uuid, _>(uuid)
                .get_result::<StoredBackupRow>(&mut *conn)
                .await
                .optional()?;
        match stored {
            Some(row) if row.payload == *value => {}
            Some(_) => {
                return Err(rejected(
                    ConflictCode::DuplicateConflict,
                    "a reserved replacement backup id already stores different bytes",
                ));
            }
            None => {
                crate::key_backup::put_key_backup_in_connection(
                    conn,
                    backup.backup_id.as_str(),
                    value,
                )
                .await?;
            }
        }
    }
    accept_step_in_transaction(
        conn,
        write.transaction.clone(),
        write.step_outcome,
        StepAttemptSource::CoCommittedWithOutcome,
    )
    .await?;
    load_one(conn, resource.transaction_id.as_str(), false)
        .await?
        .ok_or_else(|| {
            rejected(
                ConflictCode::FailedPrecondition,
                "rotation vanished after upload",
            )
        })
}

pub(super) async fn commit_rotation_pointer_switch_in_connection(
    conn: &mut AsyncPgConnection,
    write: RotationPointerSwitchWrite,
) -> Result<SecurityTransactionRecord, PgTransactionError> {
    write.validate()?;
    if let Some(stored) = begin_worker_step(
        conn,
        &write.transaction,
        &write.step_outcome.canonical_request,
        SecurityTransactionStep::SwitchAuthoritativePointer,
    )
    .await?
    {
        return Ok(stored);
    }
    let resource = &write.transaction.resource;
    let plan = resource.security_rotation_plan().expect("validated");
    let binding = &plan.backup_rotations[0].binding;
    let event = &write.commit.event;
    let record: KeyBackupActiveSeries = serde_json::from_value(
        serde_json::to_value(&event.payload).map_err(PersistenceError::database)?,
    )
    .map_err(|error| {
        rejected(
            ConflictCode::SchemaViolation,
            &format!("prepared active-series payload is invalid: {error}"),
        )
    })?;
    if record.active_series_id != binding.new_series_id
        || !record
            .previous_series_ids
            .contains(&binding.previous_series_id)
        || record.backup_kind != BackupKind::SecretStorage
    {
        return Err(rejected(
            ConflictCode::SchemaViolation,
            "prepared active-series record does not switch the planned series",
        ));
    }
    let realm_id = pcr_realm(conn, &resource.account_id).await?;
    if event.realm_id != realm_id {
        return Err(rejected(
            ConflictCode::SchemaViolation,
            "prepared active-series Event targets another Realm than the Account PCR",
        ));
    }
    lock_pcr(conn, &realm_id, true).await?;
    let head = sql_query(
        "SELECT commit_id FROM realm_commits WHERE realm_id=$1 \
         AND stream_ref=jsonb_build_object('kind','realm','realm_id',$1::text) \
         ORDER BY stream_position DESC LIMIT 1",
    )
    .bind::<Text, _>(realm_id.as_str())
    .get_result::<HeadRow>(&mut *conn)
    .await
    .optional()?;
    if head.as_ref().map(|head| head.commit_id.as_str())
        != write
            .commit
            .commit
            .previous_commit_ref
            .as_ref()
            .map(|id| id.as_str())
    {
        // The Station signs the covering Commit before this transaction; a
        // head that moved meanwhile is re-signed on the next worker pass.
        return Err(rejected(
            ConflictCode::TemporarilyUnavailable,
            "PCR head moved before the rotation pointer switch",
        ));
    }
    // The planned previous series must still be the authoritative pointer:
    // this is the switch's own CAS, stricter than the version CAS below.
    let current_key = arkret_models_crypto::derive_key_backup_active_series_current_key(
        &ActorId::account(resource.account_id.clone()),
        BackupKind::SecretStorage,
    )
    .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    let current = sql_query(
        "SELECT value FROM key_backup_active_series_current_results \
         WHERE realm_id=$1 AND current_key=$2",
    )
    .bind::<Text, _>(realm_id.as_str())
    .bind::<Text, _>(&current_key)
    .get_result::<PointerValueRow>(&mut *conn)
    .await
    .optional()?
    .map(|row| serde_json::from_value::<KeyBackupActiveSeries>(row.value))
    .transpose()
    .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    if current.is_none_or(|current| current.active_series_id != binding.previous_series_id) {
        return Err(rejected(
            "key_backup_active_series_pointer_version_fork",
            "the rotation's previous series is no longer the authoritative pointer",
        ));
    }
    match commit_key_backup_pointer_unit_in_connection(
        conn,
        &KeyBackupActiveSeriesCommitWrite {
            commit: write.commit.clone(),
            queued_at: write.queued_at,
        },
    )
    .await
    {
        Ok(KeyBackupActiveSeriesCommitOutcome::Committed(_)) => {}
        Ok(KeyBackupActiveSeriesCommitOutcome::Duplicate(_)) => {
            return Err(rejected(
                ConflictCode::DuplicateConflict,
                "the reserved active-series Event was accepted outside its rotation",
            ));
        }
        Err(error) => return Err(pointer_refusal(error)),
    }
    accept_step_in_transaction(
        conn,
        write.transaction.clone(),
        write.step_outcome,
        StepAttemptSource::CoCommittedWithOutcome,
    )
    .await?;
    load_one(conn, resource.transaction_id.as_str(), false)
        .await?
        .ok_or_else(|| {
            rejected(
                ConflictCode::FailedPrecondition,
                "rotation vanished after pointer switch",
            )
        })
}

/// The Ed25519 public key of `cut`'s device, taken only from its current
/// accepted PCR authorization (`device_public_key_did`, a `did:key`).
fn authorized_device_key(
    cut: &ConfirmedPcrDeviceStatusCut,
) -> Result<[u8; 32], PgTransactionError> {
    let authorization = cut.authority.authorization.as_ref().ok_or_else(|| {
        rejected(
            ConflictCode::FailedPrecondition,
            "rotation signing device has no accepted authorization",
        )
    })?;
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
    arkret_canonical::multibase::decode_ed25519_multibase(did_key).map_err(|_| {
        rejected(
            ConflictCode::FailedPrecondition,
            "current device authorization key is invalid",
        )
    })
}

/// `local_commit`: the client-attested terminal step. Under the PCR share
/// lock the attesting device must be `active` at the confirmed cut, the
/// attestation's verification method must be the DID URL of the Account's
/// principal DID with the exact `device_id` fragment, and the outer
/// signature must verify against that device's current accepted
/// authorization key. The step, the `completed` terminal outcome and the
/// first response then commit together.
pub(super) async fn commit_rotation_local_commit_in_connection(
    conn: &mut AsyncPgConnection,
    write: RotationLocalCommitWrite,
) -> Result<SecurityTransactionRecord, PgTransactionError> {
    use arkret_models_crypto::ClientStepAttestationArtifact;

    write.validate()?;
    let resource = &write.transaction.resource;
    let transaction_id = resource.transaction_id.as_str();
    let existing = load_one(conn, transaction_id, true)
        .await?
        .ok_or_else(|| rejected(ConflictCode::FailedPrecondition, "rotation is absent"))?;
    if existing.canonical_request != write.transaction.canonical_request {
        return Err(rejected(
            ConflictCode::DuplicateConflict,
            "local commit changed the rotation's original canonical request",
        ));
    }
    if let Some(stored) =
        load_step_outcome(conn, transaction_id, SecurityTransactionStep::LocalCommit).await?
    {
        if stored.canonical_request != write.step_outcome.canonical_request {
            return Err(rejected(
                ConflictCode::DuplicateConflict,
                "local commit was accepted for different canonical bytes",
            ));
        }
        return Ok(existing);
    }
    let next = existing
        .resource
        .next_required_step()
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    if next != Some(SecurityTransactionStep::LocalCommit) {
        return Err(rejected(
            ConflictCode::FailedPrecondition,
            "rotation is not ready for its local commit",
        ));
    }
    let mut prior = resource.clone();
    prior.accepted_steps.pop();
    prior.terminal_outcome = None;
    if existing.resource != prior {
        return Err(rejected(
            ConflictCode::DuplicateConflict,
            "local commit does not extend the durable resource by exactly its terminal step",
        ));
    }
    let ClientStepAttestationArtifact::SecurityRotation(artifact) = &write.attestation.artifact
    else {
        return Err(rejected(
            ConflictCode::SchemaViolation,
            "local commit requires SecurityRotationLocalCommit",
        ));
    };
    let account = &resource.account_id;
    let accepted_at = resource
        .accepted_steps
        .last()
        .expect("validated local commit step")
        .accepted_at;
    let realm_id = pcr_realm(conn, account).await?;
    lock_pcr(conn, &realm_id, false).await?;
    let cut =
        active_authorizer_cut(conn, account, &artifact.device_id, &realm_id, accepted_at).await?;
    let account_did = sql_query(
        "SELECT value->>'did' AS did FROM principal_resolution_current_results \
         WHERE principal_id=$1 AND station_id=$2 AND pcr_realm_id=$3",
    )
    .bind::<Text, _>(account.principal_id.as_str())
    .bind::<Text, _>(account.station_id.as_str())
    .bind::<Text, _>(realm_id.as_str())
    .get_result::<CurrentAccountDidRow>(&mut *conn)
    .await
    .optional()?
    .ok_or_else(|| {
        rejected(
            ConflictCode::TemporarilyUnavailable,
            "current Account DID is absent",
        )
    })?;
    let expected_method = format!("{}#{}", account_did.did, artifact.device_id.as_str());
    if write.attestation.auth_data.verification_method.as_str() != expected_method
        || verification_method_device(&write.attestation.auth_data.verification_method, account)
            .as_ref()
            != Some(&artifact.device_id)
    {
        return Err(rejected(
            ConflictCode::SignatureInvalid,
            "local commit verification method is not the attesting device of this Account",
        ));
    }
    let public_key = authorized_device_key(&cut)?;
    let signed = write
        .attestation
        .signing_bytes()
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    if !arkret_signatures::verify_detached_ed25519_signature(
        &arkret_signatures::PublicKeyMaterial::Ed25519Raw {
            bytes: public_key.to_vec(),
        },
        &signed,
        write.attestation.auth_data.signature.as_str(),
    ) {
        return Err(rejected(
            ConflictCode::SignatureInvalid,
            "local commit signature does not match the attesting device's authorized key",
        ));
    }
    accept_step_in_transaction(
        conn,
        write.transaction.clone(),
        write.step_outcome,
        StepAttemptSource::CoCommittedWithOutcome,
    )
    .await?;
    load_one(conn, transaction_id, false).await?.ok_or_else(|| {
        rejected(
            ConflictCode::FailedPrecondition,
            "rotation vanished after its local commit",
        )
    })
}

/// The pointer unit speaks in reason codes (`backup_revision_stale`, the
/// pointer transition codes) or prose. Keep a bare reason code as the prefix;
/// give prose a registered precondition prefix so it can never route as a
/// retryable condition.
fn pointer_refusal(error: PgTransactionError) -> PgTransactionError {
    match error.into_persistence() {
        PersistenceError::Conflict(detail) => {
            let token = detail
                .split_once(": ")
                .map_or(detail.as_str(), |(head, _)| head);
            let is_code = !token.is_empty()
                && token
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_');
            if is_code {
                PersistenceError::Conflict(detail).into()
            } else {
                rejected(ConflictCode::FailedPrecondition, &detail)
            }
        }
        other => other.into(),
    }
}

/// Refuse a self-authored active-series Event that any SecurityRotation plan
/// reserved: it may move the pointer only through that rotation's switch.
pub(crate) async fn refuse_rotation_reserved_pointer_in_connection(
    conn: &mut AsyncPgConnection,
    event_id: &arkret_wire::EventId,
) -> Result<(), PgTransactionError> {
    #[derive(QueryableByName)]
    struct ReservedRow {
        #[diesel(sql_type = BigInt)]
        count: i64,
    }
    let reserved = sql_query(
        "SELECT count(*) AS count FROM security_transactions WHERE kind='security_rotation' \
         AND prepared_plan->'backup_rotations'->0->'binding'->>'active_series_event_id'=$1",
    )
    .bind::<Text, _>(event_id.as_str())
    .get_result::<ReservedRow>(&mut *conn)
    .await?;
    if reserved.count > 0 {
        return Err(rejected(
            ConflictCode::FailedPrecondition,
            "the active-series Event is reserved by a SecurityRotation and switches only through it",
        ));
    }
    Ok(())
}
