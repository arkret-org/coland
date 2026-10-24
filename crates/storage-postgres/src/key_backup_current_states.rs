//! Accepted KeyBackup pointer projection and same-snapshot PCR head read.

use arkret_models_collaboration::events_payloads::{
    KeyBackupActiveSeries, validate_key_backup_active_series_record,
    validate_key_backup_active_series_transition,
};
use arkret_models_crypto::{
    BackupActiveSeriesPointer, BackupActiveSeriesState, BackupKind,
    derive_key_backup_active_series_current_key,
};
use arkret_wire::{AccountId, ActorId, CommitStreamRef, DeviceId, Event, RealmCommit};
use diesel::sql_types::{BigInt, Jsonb, Nullable, Text, Timestamptz};
use diesel::{QueryableByName, sql_query};
use diesel_async::AsyncConnection;
use horme::{OptionalExtension, RunQueryDsl};
use serde_json::Value;

use crate::{
    AsyncPgConnection, PersistenceError, PersistenceResult, PgPool, PgTransactionError, pg_conn,
};

#[derive(QueryableByName)]
struct CurrentRow {
    #[diesel(sql_type = Jsonb)]
    value: Value,
}

#[derive(QueryableByName)]
struct ConfirmedPointerRow {
    #[diesel(sql_type = Text)]
    pcr_realm_id: String,
    #[diesel(sql_type = Text)]
    head_commit_id: String,
    #[diesel(sql_type = BigInt)]
    head_position: i64,
    #[diesel(sql_type = Jsonb)]
    head_commit_json: Value,
    #[diesel(sql_type = Nullable<Text>)]
    latest_pointer_commit_id: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    pointer_commit_id: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    pointer_event_id: Option<String>,
    #[diesel(sql_type = Nullable<BigInt>)]
    pointer_position: Option<i64>,
    #[diesel(sql_type = Nullable<Jsonb>)]
    pointer_value: Option<Value>,
    #[diesel(sql_type = Nullable<Jsonb>)]
    pointer_commit_json: Option<Value>,
}

fn invalid(message: impl Into<String>) -> PersistenceError {
    PersistenceError::SchemaViolation(message.into())
}

/// Project the exact signed payload in the same transaction as its accepting
/// RealmCommit. The caller must have already verified producer authority and
/// the device-generation source anchor; this function enforces the durable
/// pointer CAS against concurrent accepts.
pub(crate) async fn commit_key_backup_pointer_in_connection(
    conn: &mut AsyncPgConnection,
    event: &Event,
    commit: &RealmCommit,
) -> PersistenceResult<()> {
    if event.kind != arkret_wire::EventKind::KeyBackupActiveSeries {
        return Ok(());
    }
    let record: KeyBackupActiveSeries = serde_json::from_value(
        serde_json::to_value(&event.payload).map_err(PersistenceError::database)?,
    )
    .map_err(|error| invalid(format!("KeyBackup pointer payload is invalid: {error}")))?;
    if record.actor_id != event.actor_id
        || commit.event_ref != event.event_id
        || commit.realm_id != event.realm_id
        || commit.stream_ref
            != (CommitStreamRef::Realm {
                realm_id: event.realm_id.clone(),
            })
    {
        return Err(invalid("KeyBackup pointer Event and RealmCommit differ"));
    }
    let account = record
        .actor_id
        .as_account_id()
        .ok_or_else(|| invalid("KeyBackup pointer actor is not an account"))?;
    let current_key =
        derive_key_backup_active_series_current_key(&record.actor_id, record.backup_kind)
            .map_err(|error| invalid(error.to_string()))?;
    let pcr = sql_query(
        "SELECT pcr_realm_id FROM principal_resolutions \
         WHERE principal_id=$1 AND station_id=$2 FOR SHARE",
    )
    .bind::<Text, _>(account.principal_id.as_str())
    .bind::<Text, _>(account.station_id.as_str())
    .get_result::<PcrRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?
    .ok_or_else(|| invalid("KeyBackup pointer PCR is unavailable"))?;
    if pcr.pcr_realm_id != event.realm_id.as_str() {
        return Err(invalid("KeyBackup pointer targets a different PCR"));
    }
    let prior = sql_query(
        "SELECT value FROM key_backup_active_series_current_states \
         WHERE realm_id=$1 AND current_key=$2 FOR UPDATE",
    )
    .bind::<Text, _>(event.realm_id.as_str())
    .bind::<Text, _>(&current_key)
    .get_result::<CurrentRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?;
    let prior = prior
        .map(|row| {
            serde_json::from_value::<KeyBackupActiveSeries>(row.value)
                .map_err(|error| invalid(format!("stored KeyBackup pointer is invalid: {error}")))
        })
        .transpose()?;
    let prior_head = prior
        .as_ref()
        .map(arkret_models_collaboration::events_payloads::key_backup_active_series_head)
        .transpose()
        .map_err(|error| invalid(error.to_string()))?;
    validate_key_backup_active_series_transition(prior_head.as_ref(), &record)
        .map_err(|error| PersistenceError::Conflict(error.reason_code().to_owned()))?;
    if prior
        .as_ref()
        .is_some_and(|prior| record.series_pointer_version <= prior.series_pointer_version)
    {
        return Err(PersistenceError::Conflict(
            "key_backup_active_series_pointer_version_not_advanced".to_owned(),
        ));
    }
    let position = i64::try_from(commit.stream_position)
        .map_err(|_| invalid("KeyBackup pointer stream position overflow"))?;
    let value = serde_json::to_value(&record).map_err(PersistenceError::database)?;
    sql_query(
        "INSERT INTO key_backup_active_series_current_states \
         (realm_id,current_key,actor_id,backup_kind,current_event_id,current_commit_id, \
          current_stream_position,value,updated_at) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) \
         ON CONFLICT (realm_id,current_key) DO UPDATE SET \
           current_event_id=EXCLUDED.current_event_id, \
           current_commit_id=EXCLUDED.current_commit_id, \
           current_stream_position=EXCLUDED.current_stream_position, \
           value=EXCLUDED.value,updated_at=EXCLUDED.updated_at",
    )
    .bind::<Text, _>(event.realm_id.as_str())
    .bind::<Text, _>(&current_key)
    .bind::<Jsonb, _>(serde_json::to_value(&record.actor_id).map_err(PersistenceError::database)?)
    .bind::<Text, _>(record.backup_kind.as_str())
    .bind::<Text, _>(event.event_id.as_str())
    .bind::<Text, _>(commit.commit_id.as_str())
    .bind::<BigInt, _>(position)
    .bind::<Jsonb, _>(value)
    .bind::<Timestamptz, _>(commit.committed_at)
    .execute(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    Ok(())
}

#[derive(QueryableByName)]
struct PcrRow {
    #[diesel(sql_type = Text)]
    pcr_realm_id: String,
}

#[derive(QueryableByName)]
struct RealmLockRow {
    #[diesel(sql_type = Text)]
    realm_id: String,
}

#[derive(QueryableByName)]
struct AcceptedPointerEventRow {
    #[diesel(sql_type = Jsonb)]
    envelope: Value,
    #[diesel(sql_type = Nullable<Jsonb>)]
    commit_json: Option<Value>,
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

fn pointer_rejected(reason: impl Into<String>) -> PgTransactionError {
    PersistenceError::Conflict(reason.into()).into()
}

pub(crate) fn verification_method_device(
    method: &arkret_wire::DidUrl,
    account: &AccountId,
) -> Option<DeviceId> {
    let (controller, fragment) = method.as_str().rsplit_once('#')?;
    let did = arkret_wire::Did::new(controller.to_owned()).ok()?;
    if arkret_wire::project_did_to_core_id(&did).ok()? != account.principal_id {
        return None;
    }
    DeviceId::new(fragment.to_owned()).ok()
}

/// The registered `ak.key_backup.active_series` unit. The caller supplies the
/// Station-signed RealmCommit it prepared at the PCR head; everything that
/// depends on durable state is decided here under the PCR authority lock:
/// the signing device is `active` at the same status cut, the record names
/// that device's current authorization Event and the current generation, the
/// source checkpoint is an accepted Commit of this PCR at or after the
/// generation and authorization it relies on, both the record signature and
/// the Event producer proof verify against the accepted device key, and the
/// pointer version advances by exactly one. The Event, Commit and typed
/// pointer become visible together or not at all.
pub(crate) async fn commit_key_backup_pointer_unit_in_connection(
    conn: &mut AsyncPgConnection,
    write: &coland_storage::KeyBackupActiveSeriesCommitWrite,
) -> Result<coland_storage::KeyBackupActiveSeriesCommitOutcome, PgTransactionError> {
    use coland_storage::KeyBackupActiveSeriesCommitOutcome as Outcome;

    let event = &write.commit.event;
    let commit = &write.commit.commit;
    if event.kind != arkret_wire::EventKind::KeyBackupActiveSeries
        || event.executed_by.is_some()
        || commit.event_ref != event.event_id
        || commit.realm_id != event.realm_id
        || event.scope_ref
            != (arkret_wire::ScopeRef::Realm {
                realm_id: event.realm_id.clone(),
            })
        || commit.stream_ref
            != (CommitStreamRef::Realm {
                realm_id: event.realm_id.clone(),
            })
    {
        return Err(invalid("KeyBackup pointer unit Event and Commit differ").into());
    }
    let suite =
        arkret_canonical::canonical::digest_suite(event.event_id.digest_suite_code().as_str())
            .map_err(|error| invalid(error.to_string()))?;
    event
        .verify_event_id_matches_content_with_digest_suite(suite)
        .map_err(|error| invalid(error.to_string()))?;
    let record: KeyBackupActiveSeries = serde_json::from_value(
        serde_json::to_value(&event.payload).map_err(PersistenceError::database)?,
    )
    .map_err(|error| invalid(format!("KeyBackup pointer payload is invalid: {error}")))?;
    validate_key_backup_active_series_record(&record)
        .map_err(|error| PersistenceError::Conflict(error.reason_code().to_owned()))?;
    let account = event
        .actor_id
        .as_account_id()
        .ok_or_else(|| invalid("KeyBackup pointer actor is not an account"))?;
    if record.actor_id != event.actor_id || record.backup_kind != BackupKind::SecretStorage {
        return Err(pointer_rejected(
            "key_backup_active_series_actor_or_class_mismatch",
        ));
    }
    let proof = event
        .producer_proof
        .as_ref()
        .ok_or_else(|| pointer_rejected("KeyBackup pointer producer proof is absent"))?;
    if proof.verification_method != record.signature_proof.verification_method {
        return Err(pointer_rejected(
            "KeyBackup pointer record and Event are signed by different methods",
        ));
    }
    let device_id =
        verification_method_device(&record.signature_proof.verification_method, account)
            .ok_or_else(|| {
                pointer_rejected("KeyBackup pointer method is not an Account device method")
            })?;

    // Every accepted PCR writer takes this row lock before changing its head,
    // so the status cut read below cannot move before this unit commits.
    let lock = sql_query("SELECT realm_id FROM realm_authorities WHERE realm_id=$1 FOR UPDATE")
        .bind::<Text, _>(event.realm_id.as_str())
        .get_result::<RealmLockRow>(&mut *conn)
        .await
        .optional()?
        .ok_or_else(|| pointer_rejected("KeyBackup pointer PCR authority is absent"))?;
    if lock.realm_id != event.realm_id.as_str() {
        return Err(pointer_rejected("KeyBackup pointer PCR lock differs"));
    }
    let token = crate::ids::parse_event_id(event.event_id.as_str())
        .ok_or_else(|| invalid("KeyBackup pointer Event id is not canonical"))?;
    let existing = sql_query(
        "SELECT e.envelope,c.commit_json FROM canonical_events e \
         LEFT JOIN realm_commits c ON c.event_pk=e.pk WHERE e.id=$1",
    )
    .bind::<diesel::sql_types::Binary, _>(token.to_vec())
    .get_result::<AcceptedPointerEventRow>(&mut *conn)
    .await
    .optional()?;
    if let Some(existing) = existing {
        let envelope = serde_json::to_value(event).map_err(PersistenceError::database)?;
        let presented = serde_json::to_value(commit).map_err(PersistenceError::database)?;
        return match existing.commit_json {
            Some(stored) if existing.envelope == envelope && stored == presented => {
                Ok(Outcome::Duplicate(commit.clone()))
            }
            _ => Err(pointer_rejected(
                "KeyBackup pointer Event is already known with different content or Commit",
            )),
        };
    }

    let status = crate::pcr_device_status_reader::confirmed_pcr_device_status_cut_in_connection(
        conn,
        account,
        &device_id,
        commit.committed_at,
    )
    .await?
    .ok_or_else(|| pointer_rejected("KeyBackup pointer device has no confirmed PCR cut"))?;
    if status.authority.realm_id != event.realm_id
        || status.lifecycle != crate::pcr_device_status_fold::PcrDeviceLifecycle::Active
    {
        return Err(pointer_rejected(
            "KeyBackup pointer device is not active at the PCR cut",
        ));
    }
    if commit.previous_commit_ref.as_ref() != Some(&status.authority.authority_commit_id) {
        return Err(pointer_rejected(
            "KeyBackup pointer Commit does not extend the confirmed PCR head",
        ));
    }
    let authorization = status
        .authority
        .authorization
        .as_ref()
        .ok_or_else(|| pointer_rejected("KeyBackup pointer device has no authorization"))?;
    let generation = status
        .authority
        .current_generation
        .ok_or_else(|| pointer_rejected("KeyBackup pointer PCR has no current generation"))?;
    if record.signature_proof.device_authorize_event_id != authorization.event_id {
        return Err(pointer_rejected(
            "KeyBackup pointer names a device authorization that is not current",
        ));
    }
    if record.source_commit_ref.device_generation_ref != generation {
        return Err(pointer_rejected("backup_revision_stale"));
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
    .bind::<Text, _>(event.realm_id.as_str())
    .bind::<Text, _>(record.source_commit_ref.realm_commit_id.as_str())
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
            return Err(pointer_rejected(
                "KeyBackup pointer source checkpoint is not an accepted PCR Commit under the current generation and device",
            ));
        }
    }

    let did_key = authorization
        .payload
        .device_public_key_did
        .as_str()
        .strip_prefix("did:key:")
        .ok_or_else(|| pointer_rejected("current device authorization has no did:key key"))?;
    let public_key = arkret_canonical::multibase::decode_ed25519_multibase(did_key)
        .map_err(|_| pointer_rejected("current device authorization key is invalid"))?;
    let device_key = arkret_signatures::PublicKeyMaterial::Ed25519Raw {
        bytes: public_key.to_vec(),
    };
    let signed = record
        .signing_payload_bytes()
        .map_err(|error| invalid(error.to_string()))?;
    if !arkret_signatures::verify_detached_ed25519_signature(
        &device_key,
        &signed,
        record.signature_proof.signature.as_str(),
    ) {
        return Err(pointer_rejected(
            "KeyBackup pointer signature does not match the device key",
        ));
    }
    let envelope_bytes = arkret_signatures::EventProofBuilder::new()
        .envelope_bytes(event)
        .map_err(|error| invalid(format!("KeyBackup pointer envelope is invalid: {error}")))?;
    arkret_signatures::verify_ed25519_detached_jws_proof_with_digest_suite(
        proof,
        &envelope_bytes,
        &event.actor_id,
        &device_key,
        suite,
    )
    .map_err(|_| {
        pointer_rejected("KeyBackup pointer producer proof does not match the device key")
    })?;

    let historical =
        crate::agent_producer_signer_keys::prepare_confirmed_human_outcome_in_connection(
            conn, event, commit, &status, account, &device_id,
        )
        .await?;
    crate::authority_commit::queue_event_in_connection(conn, event, write.queued_at).await?;
    match crate::authority_commit::commit_verified_key_backup_pointer_in_connection(
        conn,
        &write.commit,
    )
    .await?
    {
        coland_storage::AuthorityCommitWriteOutcome::Committed => {}
        coland_storage::AuthorityCommitWriteOutcome::Duplicate => {
            return Err(pointer_rejected(
                "KeyBackup pointer Event was committed outside this unit",
            ));
        }
        coland_storage::AuthorityCommitWriteOutcome::StaleAuthority(_) => {
            return Err(pointer_rejected(
                "PCR authority changed before KeyBackup pointer commit",
            ));
        }
    }
    crate::agent_producer_signer_keys::retain_self_outcome_in_connection(
        conn, event, commit, historical,
    )
    .await?;
    commit_key_backup_pointer_in_connection(conn, event, commit).await?;
    Ok(Outcome::Committed(commit.clone()))
}

/// Returns `None` when the PCR or confirmed Realm head is unavailable. A
/// confirmed head with no pointer row yields the explicit `Absent` branch.
/// One SQL statement gives all inputs the same PostgreSQL MVCC snapshot.
pub(crate) async fn confirmed_key_backup_pointer(
    pool: &PgPool,
    account_id: &AccountId,
) -> PersistenceResult<Option<BackupActiveSeriesState>> {
    let mut conn = pg_conn(pool).await?;
    confirmed_key_backup_pointer_in_connection(&mut conn, account_id).await
}

pub(crate) async fn confirmed_key_backup_pointer_basis(
    pool: &PgPool,
    account_id: &AccountId,
) -> PersistenceResult<Option<coland_storage::ConfirmedKeyBackupAuthorityBasis>> {
    let mut conn = pg_conn(pool).await?;
    confirmed_key_backup_pointer_basis_in_connection(&mut conn, account_id).await
}

/// The caller owns a repeatable-read snapshot. Device status and the pointer
/// must name the same accepted PCR head before a self-service read is served.
pub(crate) async fn confirmed_key_backup_pointer_for_active_device(
    pool: &PgPool,
    account_id: &AccountId,
    device_id: &DeviceId,
    now: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<Option<BackupActiveSeriesState>> {
    let mut conn = pg_conn(pool).await?;
    conn.transaction::<Option<BackupActiveSeriesState>, PgTransactionError, _>(async |conn| {
        sql_query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
            .execute(&mut *conn)
            .await?;
        confirmed_key_backup_pointer_for_active_device_in_connection(
            conn, account_id, device_id, now,
        )
        .await
    })
    .await
    .map_err(PgTransactionError::into_persistence)
}

pub(crate) async fn confirmed_key_backup_pointer_for_active_device_in_connection(
    conn: &mut AsyncPgConnection,
    account_id: &AccountId,
    device_id: &DeviceId,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<Option<BackupActiveSeriesState>, PgTransactionError> {
    let cut = crate::pcr_device_status_reader::confirmed_pcr_device_status_cut_in_connection(
        conn, account_id, device_id, now,
    )
    .await?
    .ok_or_else(|| invalid("KeyBackup device has no confirmed PCR status"))?;
    if cut.lifecycle != crate::pcr_device_status_fold::PcrDeviceLifecycle::Active {
        return Err(invalid("KeyBackup device is not active at the PCR cut").into());
    }
    let pointer = confirmed_key_backup_pointer_in_connection(conn, account_id)
        .await?
        .ok_or_else(|| invalid("KeyBackup pointer has no confirmed PCR head"))?;
    if pointer.authority_commit_id != cut.authority.authority_commit_id
        || pointer.control_realm_id != cut.authority.realm_id
    {
        return Err(invalid("KeyBackup pointer and device status name different PCR cuts").into());
    }
    Ok(Some(pointer))
}

pub(crate) async fn confirmed_key_backup_pointer_in_connection(
    conn: &mut AsyncPgConnection,
    account_id: &AccountId,
) -> PersistenceResult<Option<BackupActiveSeriesState>> {
    Ok(
        confirmed_key_backup_pointer_basis_in_connection(conn, account_id)
            .await?
            .map(|basis| basis.state),
    )
}

pub(crate) async fn confirmed_key_backup_pointer_basis_in_connection(
    conn: &mut AsyncPgConnection,
    account_id: &AccountId,
) -> PersistenceResult<Option<coland_storage::ConfirmedKeyBackupAuthorityBasis>> {
    let actor = ActorId::account(account_id.clone());
    let current_key =
        derive_key_backup_active_series_current_key(&actor, BackupKind::SecretStorage)
            .map_err(|error| invalid(error.to_string()))?;
    let row = sql_query(
        "SELECT p.pcr_realm_id, h.commit_id AS head_commit_id, \
                h.stream_position AS head_position, h.commit_json AS head_commit_json, \
                latest_pointer.commit_id AS latest_pointer_commit_id, \
                b.current_commit_id AS pointer_commit_id, \
                b.current_event_id AS pointer_event_id, \
                b.current_stream_position AS pointer_position, \
                b.value AS pointer_value, c.commit_json AS pointer_commit_json \
         FROM principal_resolutions p \
         JOIN realm_authorities a ON a.realm_id=p.pcr_realm_id \
                                  AND a.service_id=p.station_id \
         JOIN LATERAL (SELECT commit_id,stream_position,commit_json FROM realm_commits \
                       WHERE realm_id=p.pcr_realm_id \
                         AND stream_ref=jsonb_build_object('kind','realm','realm_id',p.pcr_realm_id) \
                       ORDER BY stream_position DESC LIMIT 1) h ON TRUE \
         LEFT JOIN LATERAL (SELECT c.commit_id FROM realm_commits c \
                            JOIN canonical_events e ON e.pk=c.event_pk \
                            WHERE c.realm_id=p.pcr_realm_id \
                              AND c.stream_ref=jsonb_build_object('kind','realm','realm_id',p.pcr_realm_id) \
                              AND e.kind='ak.key_backup.active_series' \
                            ORDER BY c.stream_position DESC LIMIT 1) latest_pointer ON TRUE \
         LEFT JOIN key_backup_active_series_current_states b \
           ON b.realm_id=p.pcr_realm_id AND b.current_key=$3 \
         LEFT JOIN realm_commits c ON c.commit_id=b.current_commit_id \
         WHERE p.principal_id=$1 AND p.station_id=$2",
    )
    .bind::<Text, _>(account_id.principal_id.as_str())
    .bind::<Text, _>(account_id.station_id.as_str())
    .bind::<Text, _>(&current_key)
    .get_result::<ConfirmedPointerRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?;
    let Some(row) = row else { return Ok(None) };
    let control_realm_id =
        arkret_wire::RealmId::new(row.pcr_realm_id).map_err(|error| invalid(error.to_string()))?;
    let authority_commit_id = arkret_wire::RealmCommitId::new(row.head_commit_id)
        .map_err(|error| invalid(error.to_string()))?;
    let head_commit: RealmCommit = serde_json::from_value(row.head_commit_json)
        .map_err(|error| invalid(format!("stored PCR head Commit is invalid: {error}")))?;
    if head_commit.commit_id != authority_commit_id
        || head_commit.realm_id != control_realm_id
        || head_commit.stream_ref
            != (CommitStreamRef::Realm {
                realm_id: control_realm_id.clone(),
            })
        || head_commit.stream_position
            != u64::try_from(row.head_position)
                .map_err(|_| invalid("stored head position is negative"))?
    {
        return Err(invalid("stored PCR head provenance is inconsistent"));
    }
    let pointer = match (
        row.pointer_commit_id,
        row.pointer_event_id,
        row.pointer_position,
        row.pointer_value,
        row.pointer_commit_json,
    ) {
        (None, None, None, None, None) if row.latest_pointer_commit_id.is_none() => {
            BackupActiveSeriesPointer::Absent {}
        }
        (Some(commit_id), Some(event_id), Some(position), Some(value), Some(commit_json)) => {
            let record: KeyBackupActiveSeries = serde_json::from_value(value).map_err(|error| {
                invalid(format!("stored KeyBackup pointer is invalid: {error}"))
            })?;
            let commit: RealmCommit = serde_json::from_value(commit_json)
                .map_err(|error| invalid(format!("stored pointer Commit is invalid: {error}")))?;
            if record.actor_id != actor
                || record.backup_kind != BackupKind::SecretStorage
                || commit.commit_id.as_str() != commit_id
                || row.latest_pointer_commit_id.as_deref() != Some(commit_id.as_str())
                || commit.event_ref.as_str() != event_id
                || commit.realm_id != control_realm_id
                || commit.stream_ref
                    != (CommitStreamRef::Realm {
                        realm_id: control_realm_id.clone(),
                    })
                || commit.stream_position
                    != u64::try_from(position)
                        .map_err(|_| invalid("stored pointer position is negative"))?
                || commit.stream_position
                    > u64::try_from(row.head_position)
                        .map_err(|_| invalid("stored head position is negative"))?
            {
                return Err(invalid(
                    "KeyBackup pointer is not bound to the confirmed PCR cut",
                ));
            }
            validate_key_backup_active_series_record(&record)
                .map_err(|error| invalid(error.to_string()))?;
            if record.series_pointer_version == 0 {
                return Err(invalid("stored KeyBackup pointer version is zero"));
            }
            BackupActiveSeriesPointer::Active {
                active_series_id: record.active_series_id,
                series_pointer_version: record.series_pointer_version,
            }
        }
        _ => return Err(invalid("KeyBackup pointer provenance is incomplete")),
    };
    Ok(Some(coland_storage::ConfirmedKeyBackupAuthorityBasis {
        committed_ref: arkret_wire::CommittedEventRef {
            event_id: head_commit.event_ref,
            commit_id: head_commit.commit_id,
            stream_ref: head_commit.stream_ref,
            stream_position: head_commit.stream_position,
        },
        state: BackupActiveSeriesState {
            account_id: account_id.clone(),
            control_realm_id,
            authority_commit_id,
            secret_storage: pointer,
        },
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AsyncConnection, Binary, PgTransactionError};

    #[derive(QueryableByName)]
    struct CountRow {
        #[diesel(sql_type = BigInt)]
        count: i64,
    }

    fn account() -> AccountId {
        AccountId::new(
            arkret_wire::DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
            arkret_wire::DidCoreId::new("ak:did_core:web:station.example").unwrap(),
        )
    }

    fn commit(
        event_id: arkret_wire::EventId,
        realm_id: arkret_wire::RealmId,
        position: u64,
        previous: Option<arkret_wire::RealmCommitId>,
    ) -> RealmCommit {
        let now = chrono::DateTime::parse_from_rfc3339("2026-09-24T00:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        RealmCommit {
            producer_signer_fact_digest: None,
            commit_id: arkret_wire::RealmCommitId::from_digest([position as u8 + 10; 32]),
            realm_id: realm_id.clone(),
            stream_ref: CommitStreamRef::Realm { realm_id },
            stream_position: position,
            previous_commit_ref: previous,
            event_ref: event_id.clone(),
            governance_generation: 0,
            authority_ref: arkret_wire::RealmCommitAuthorityRef::GenesisOrChangeEvent(event_id),
            committed_at: now,
            signature: arkret_wire::DetachedObjectSignature {
                context: arkret_wire::DetachedSignatureContext::RealmCommit,
                signature_algorithm: arkret_wire::DetachedSignatureAlgorithm::Ed25519,
                verification_method: arkret_wire::DidUrl::new("did:web:station.example#authority")
                    .unwrap(),
                signed_digest: arkret_wire::Hash::new(format!("sha256:{}", "aa".repeat(32)))
                    .unwrap(),
                created_at: now,
                signature: arkret_wire::Base64UrlString::new("c2lnbmF0dXJl").unwrap(),
            },
        }
    }

    async fn insert_commit(conn: &mut AsyncPgConnection, commit: &RealmCommit, event: &Event) {
        let token = crate::ids::event_token_part_expect_internal(event.event_id.as_str(), "event");
        sql_query(
            "INSERT INTO canonical_events \
             (id,digest_suite,digest,actor_id,realm_id,scope_ref,kind,canonical_bytes,envelope,state,received_at,committed_at) \
             VALUES($1,1,$2,$3,$4,$5,$6,'\\x00'::bytea,$7,'committed',$8,$8)",
        )
        .bind::<Binary, _>(token.to_vec())
        .bind::<Binary, _>(token[1..].to_vec())
        .bind::<Text, _>(event.actor_id.to_string())
        .bind::<Text, _>(event.realm_id.as_str())
        .bind::<Jsonb, _>(serde_json::to_value(&event.scope_ref).unwrap())
        .bind::<Text, _>(event.kind.as_str())
        .bind::<Jsonb, _>(serde_json::to_value(event).unwrap())
        .bind::<Timestamptz, _>(commit.committed_at)
        .execute(&mut *conn)
        .await
        .unwrap();
        sql_query(
            "INSERT INTO realm_commits \
             (commit_id,realm_id,stream_key,stream_ref,stream_position,previous_commit_ref,event_pk,governance_generation,commit_json,committed_at) \
             SELECT $1,$2,$3,$4,$5,$6,pk,0,$7,$8 FROM canonical_events WHERE id=$9",
        )
        .bind::<Text, _>(commit.commit_id.as_str())
        .bind::<Text, _>(commit.realm_id.as_str())
        .bind::<Text, _>(arkret_canonical::canonical_json_string(&commit.stream_ref).unwrap())
        .bind::<Jsonb, _>(serde_json::to_value(&commit.stream_ref).unwrap())
        .bind::<BigInt, _>(commit.stream_position as i64)
        .bind::<Nullable<Text>, _>(commit.previous_commit_ref.as_ref().map(|id| id.as_str()))
        .bind::<Jsonb, _>(serde_json::to_value(commit).unwrap())
        .bind::<Timestamptz, _>(commit.committed_at)
        .bind::<Binary, _>(token.to_vec())
        .execute(&mut *conn)
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn pointer_is_visible_only_with_accepted_commit_and_survives_rollback() {
        let database = crate::test_database::TestDatabase::lease().await;
        let pool = database.pool();
        let account = account();
        let realm_id = arkret_wire::RealmId::from_event_id(&arkret_wire::EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            [1; 32],
        ));
        let genesis = arkret_wire::test_support::raw_event(
            arkret_wire::EventKind::RealmCreate.as_str(),
            arkret_wire::ScopeRef::Realm {
                realm_id: realm_id.clone(),
            },
            account.principal_id.clone(),
            account.station_id.clone(),
            serde_json::json!({"genesis":true}),
        )
        .unwrap();
        let genesis_commit = commit(genesis.event_id.clone(), realm_id.clone(), 0, None);
        let mut conn = pg_conn(&pool).await.unwrap();
        sql_query(
            "INSERT INTO realm_authorities(realm_id,generation,service_id,authority_ref) VALUES($1,0,$2,$3)",
        )
        .bind::<Text, _>(realm_id.as_str())
        .bind::<Text, _>(account.station_id.as_str())
        .bind::<Jsonb, _>(serde_json::to_value(&genesis_commit.authority_ref).unwrap())
        .execute(&mut conn)
        .await
        .unwrap();
        sql_query(
            "INSERT INTO principal_resolutions \
             (principal_id,station_id,pcr_realm_id,genesis_event_id,current_event_id,projection,updated_at) \
             VALUES($1,$2,$3,$4,$4,'{}'::jsonb,now())",
        )
        .bind::<Text, _>(account.principal_id.as_str())
        .bind::<Text, _>(account.station_id.as_str())
        .bind::<Text, _>(realm_id.as_str())
        .bind::<Text, _>(genesis.event_id.as_str())
        .execute(&mut conn)
        .await
        .unwrap();
        insert_commit(&mut conn, &genesis_commit, &genesis).await;
        let absent = confirmed_key_backup_pointer(&pool, &account)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(absent.authority_commit_id, genesis_commit.commit_id);
        assert_eq!(absent.secret_storage, BackupActiveSeriesPointer::Absent {});
        let absent_basis = confirmed_key_backup_pointer_basis(&pool, &account)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(absent_basis.state, absent);
        assert_eq!(absent_basis.committed_ref.event_id, genesis.event_id);
        assert_eq!(
            absent_basis.committed_ref.commit_id,
            genesis_commit.commit_id
        );
        assert_eq!(
            absent_basis.committed_ref.stream_ref,
            genesis_commit.stream_ref
        );
        assert_eq!(
            absent_basis.committed_ref.stream_position,
            genesis_commit.stream_position
        );

        let payload = serde_json::json!({
            "schema":"ak.schema.key_backup_active_series.v1",
            "actor_id":ActorId::account(account.clone()),
            "backup_kind":"secret_storage",
            "active_series_id":"ak:backup_series:01964137-1000-7000-8000-000000000000",
            "series_pointer_version":1,
            "previous_series_ids":[],
            "source_commit_ref":{"realm_commit_id":genesis_commit.commit_id,"device_generation_ref":1},
            "issued_at":"2026-09-24T00:00:00.000Z",
            "signature_proof":{
                "verification_method":"did:web:alice.example#ak_device_01964137",
                "signature_algorithm":"Ed25519",
                "signature":"c2lnbmF0dXJl",
                "device_authorize_event_id":genesis.event_id
            }
        });
        let event = arkret_wire::test_support::raw_event(
            arkret_wire::EventKind::KeyBackupActiveSeries.as_str(),
            arkret_wire::ScopeRef::Realm {
                realm_id: realm_id.clone(),
            },
            account.principal_id.clone(),
            account.station_id.clone(),
            payload,
        )
        .unwrap();
        let successor = commit(
            event.event_id.clone(),
            realm_id,
            1,
            Some(genesis_commit.commit_id.clone()),
        );
        let generic = crate::authority_commit::commit_transaction_in_connection(
            &mut conn,
            &coland_storage::AuthorityCommitTransaction {
                expected_authority: coland_storage::CurrentRealmAuthority {
                    realm_id: successor.realm_id.clone(),
                    generation: 0,
                    service_id: account.station_id.clone(),
                    authority_ref: successor.authority_ref.clone(),
                    last_handoff_ref: None,
                },
                event: event.clone(),
                commit: successor.clone(),
                producer_signer_fact: None,
                mls_state: None,
                welcomes: Vec::new(),
                recipient_queue_capacity: 0,
            },
        )
        .await;
        let generic_error = generic
            .err()
            .expect("unchecked pointer must be rejected")
            .into_persistence();
        assert!(
            matches!(&generic_error, PersistenceError::Conflict(reason)
                if reason == "key_backup_active_series_current_device_authority_unavailable"),
            "unexpected generic admission failure: {generic_error}"
        );
        let event_token =
            crate::ids::event_token_part_expect_internal(event.event_id.as_str(), "event");
        let row = sql_query(
            "SELECT (SELECT count(*) FROM canonical_events WHERE id=$1) + \
                    (SELECT count(*) FROM realm_commits WHERE commit_id=$2) + \
                    (SELECT count(*) FROM key_backup_active_series_current_states WHERE realm_id=$3) AS count",
        )
        .bind::<Binary, _>(event_token.to_vec())
        .bind::<Text, _>(successor.commit_id.as_str())
        .bind::<Text, _>(successor.realm_id.as_str())
        .get_result::<CountRow>(&mut conn)
        .await
        .unwrap();
        assert_eq!(
            row.count, 0,
            "unchecked pointer admission made durable writes"
        );
        let rollback = conn
            .transaction::<(), PgTransactionError, _>(async |conn| {
                insert_commit(conn, &successor, &event).await;
                commit_key_backup_pointer_in_connection(conn, &event, &successor).await?;
                Err(PersistenceError::Conflict("abort fixture transaction".to_owned()).into())
            })
            .await;
        assert!(rollback.is_err());
        assert_eq!(
            confirmed_key_backup_pointer(&pool, &account)
                .await
                .unwrap()
                .unwrap()
                .secret_storage,
            BackupActiveSeriesPointer::Absent {}
        );
        conn.transaction::<(), PgTransactionError, _>(async |conn| {
            insert_commit(conn, &successor, &event).await;
            commit_key_backup_pointer_in_connection(conn, &event, &successor).await?;
            Ok(())
        })
        .await
        .map_err(PgTransactionError::into_persistence)
        .unwrap();
        let active = confirmed_key_backup_pointer(&pool, &account)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(active.authority_commit_id, successor.commit_id);
        assert!(matches!(
            active.secret_storage,
            BackupActiveSeriesPointer::Active {
                series_pointer_version: 1,
                ..
            }
        ));
        let active_basis = confirmed_key_backup_pointer_basis(&pool, &account)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(active_basis.state, active);
        assert_eq!(active_basis.committed_ref.event_id, event.event_id);
        assert_eq!(active_basis.committed_ref.commit_id, successor.commit_id);
        assert_eq!(active_basis.committed_ref.stream_ref, successor.stream_ref);
        assert_eq!(
            active_basis.committed_ref.stream_position,
            successor.stream_position
        );

        // An accepted successor without its typed current projection makes
        // the read unavailable; it must not return the earlier pointer.
        let mut later_payload = serde_json::to_value(&event.payload).unwrap();
        later_payload["series_pointer_version"] = serde_json::json!(2);
        later_payload["source_commit_ref"]["realm_commit_id"] =
            serde_json::to_value(&successor.commit_id).unwrap();
        let later_event = arkret_wire::test_support::raw_event(
            arkret_wire::EventKind::KeyBackupActiveSeries.as_str(),
            arkret_wire::ScopeRef::Realm {
                realm_id: successor.realm_id.clone(),
            },
            account.principal_id.clone(),
            account.station_id.clone(),
            later_payload,
        )
        .unwrap();
        let later_commit = commit(
            later_event.event_id.clone(),
            successor.realm_id.clone(),
            2,
            Some(successor.commit_id),
        );
        insert_commit(&mut conn, &later_commit, &later_event).await;
        assert!(
            confirmed_key_backup_pointer(&pool, &account).await.is_err(),
            "a missing accepted pointer projection must not return a stale pointer"
        );
    }
}
