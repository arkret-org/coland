//! Standing-manager scoped series maintenance on the private Realm control stream.

use arkret_models_collaboration::RealmActorKeyBackupActiveSeriesValue;
use arkret_models_collaboration::events_payloads::{
    KeyBackupActiveSeries, key_backup_active_series_head, validate_key_backup_active_series_record,
    validate_key_backup_active_series_transition,
};
use arkret_models_integration::{RealmActorManagerValue, RealmActorRecoveryValue};
use arkret_wire::{ActorId, CommitStreamRef, CurrentSelector, EventKind, ScopeRef};
use coland_storage::{
    AppletEventProducerGuard, AuthorityCommitWriteOutcome, KeyBackupActiveSeriesCommitOutcome,
    KeyBackupActiveSeriesCommitWrite, PersistenceError, PersistenceResult,
};
use diesel::sql_types::{BigInt, Jsonb, Text};
use diesel::{QueryableByName, sql_query};
use diesel_async::AsyncConnection;
use horme::{OptionalExtension, RunQueryDsl};
use serde_json::{Value, json};

use crate::{AsyncPgConnection, PgPool, PgTransactionError, pg_conn};

#[derive(QueryableByName)]
struct JsonRow {
    #[diesel(sql_type = Jsonb)]
    value: Value,
}

fn refused(detail: impl std::fmt::Display) -> PersistenceError {
    PersistenceError::Conflict(format!("failed_precondition: {detail}"))
}

pub(crate) async fn admit_series(
    pool: &PgPool,
    write: &KeyBackupActiveSeriesCommitWrite,
    producer: &AppletEventProducerGuard,
) -> PersistenceResult<KeyBackupActiveSeriesCommitOutcome> {
    let mut conn = pg_conn(pool).await?;
    conn.transaction::<_, PgTransactionError, _>(async |conn| {
        admit_in_connection(conn, write, producer).await
    })
    .await
    .map_err(PgTransactionError::into_persistence)
}

async fn admit_in_connection(
    conn: &mut AsyncPgConnection,
    write: &KeyBackupActiveSeriesCommitWrite,
    producer: &AppletEventProducerGuard,
) -> Result<KeyBackupActiveSeriesCommitOutcome, PgTransactionError> {
    let event = &write.commit.event;
    let commit = &write.commit.commit;
    let record: KeyBackupActiveSeries =
        serde_json::from_value(json!(event.payload)).map_err(refused)?;
    validate_key_backup_active_series_record(&record).map_err(refused)?;
    let subject = record
        .actor_id
        .as_realm_actor_id()
        .ok_or_else(|| refused("native series requires a Realm actor"))?;
    let scope = record
        .effective_scope
        .as_ref()
        .ok_or_else(|| refused("native series exact scope is absent"))?;
    if event.kind != EventKind::KeyBackupActiveSeries
        || event.realm_id != subject.realm_id
        || event.scope_ref
            != (ScopeRef::RealmControl {
                realm_id: subject.realm_id.clone(),
            })
        || commit.stream_ref
            != (CommitStreamRef::RealmControl {
                realm_id: subject.realm_id.clone(),
            })
        || event.executed_by.is_some()
        || event.authorization_ref.is_some()
        || !matches!(event.actor_id, ActorId::Service { .. })
    {
        return Err(
            refused("native series requires its registered manager-only control branch").into(),
        );
    }
    crate::realm_authorization_cut::lock_realm_authorization_cut(conn, &event.realm_id).await?;
    crate::realm_actor_control::require_current_governor(
        conn,
        &event.realm_id,
        &write.commit.expected_authority.service_id,
    )
    .await?;
    crate::realm_management_archive::require_unfrozen(conn, &event.realm_id).await?;
    let revision = super::lock_namespace(conn, &record.actor_id).await?;
    let fact = crate::realm_actor_control::recovery_service_fact(
        conn,
        event,
        producer,
        commit.committed_at,
    )
    .await?;
    crate::agent_producer_signer_keys::validate_producer_fact_binding(event, commit, Some(&fact))?;
    let (manager, manager_ref) = crate::realm_actor_control::current_source(
        conn,
        &record.actor_id,
        json!(CurrentSelector::RealmActorManager {
            actor_id: record.actor_id.clone()
        }),
    )
    .await?;
    let manager: RealmActorManagerValue = serde_json::from_value(manager).map_err(refused)?;
    let (recovery, recovery_ref) = crate::realm_actor_control::current_source(
        conn,
        &record.actor_id,
        json!(CurrentSelector::RealmActorRecovery {
            actor_id: record.actor_id.clone()
        }),
    )
    .await?;
    let recovery: RealmActorRecoveryValue = serde_json::from_value(recovery).map_err(refused)?;
    if event.actor_id != ActorId::service(manager.service_id)
        || record.manager_ref.as_ref() != Some(&manager_ref)
        || record.recovery_ref.as_ref() != Some(&recovery_ref)
        || record.recipient_ref.as_ref() != Some(&recovery.content_backup_recipient_ref)
        || recovery.pending.is_some()
    {
        return Err(
            refused("native selection manager, recovery or recipient source changed").into(),
        );
    }
    for gate in [
        arkret_wire::RealmActorStatusGate::Owner,
        arkret_wire::RealmActorStatusGate::Governance,
    ] {
        let (status, _) = crate::realm_actor_control::current_source(
            conn,
            &record.actor_id,
            json!(CurrentSelector::RealmActorStatus {
                actor_id: record.actor_id.clone(),
                gate
            }),
        )
        .await?;
        if status == "retired" {
            return Err(refused("retired native actor cannot maintain a series").into());
        }
    }
    // Realm lifecycle remains an independent terminal boundary. Pausing an
    // actor or disabling identity reset is not a business-install dependency.
    let lifecycle = crate::realm_authorization_cut::RealmAuthorizationCut::read(
        conn,
        &event.realm_id,
        &event.actor_id,
    )
    .await?;
    lifecycle.require_open_lifecycle(event)?;
    require_known_scope(conn, &record.actor_id, scope).await?;
    let key = arkret_identity::public_key_material_from_document(
        &producer.service_did_document,
        &record.signature_proof.verification_method,
    )
    .map_err(refused)?;
    if event
        .producer_proof
        .as_ref()
        .is_none_or(|proof| proof.verification_method != record.signature_proof.verification_method)
        || !arkret_signatures::verify_detached_ed25519_signature(
            &key,
            &record.signing_payload_bytes().map_err(refused)?,
            record.signature_proof.signature.as_str(),
        )
    {
        return Err(refused("native series record lacks its actual manager Ed signature").into());
    }
    if let Some(original) =
        crate::committed_disclosure::accepted_full_event_in_connection(conn, &event.event_id)
            .await?
    {
        if original.event != *event {
            return Err(refused("duplicate_conflict: native series original differs").into());
        }
        return Ok(KeyBackupActiveSeriesCommitOutcome::Duplicate(
            original.commit,
        ));
    }
    let previous=sql_query("SELECT record AS value FROM realm_actor_backup_series WHERE realm_id=$1 AND actor_id=$2 AND effective_scope=$3 ORDER BY series_pointer_version DESC LIMIT 1 FOR UPDATE")
        .bind::<Text,_>(event.realm_id.as_str()).bind::<Jsonb,_>(json!(record.actor_id)).bind::<Jsonb,_>(json!(scope))
        .get_result::<JsonRow>(&mut *conn).await.optional()?;
    let previous = previous
        .map(|row| serde_json::from_value::<KeyBackupActiveSeries>(row.value))
        .transpose()
        .map_err(refused)?;
    let reused=sql_query("SELECT effective_scope AS value FROM realm_actor_backup_series WHERE realm_id=$1 AND actor_id=$2 AND active_series_id=$3 LIMIT 1 FOR SHARE")
        .bind::<Text,_>(event.realm_id.as_str()).bind::<Jsonb,_>(json!(record.actor_id)).bind::<Text,_>(record.active_series_id.as_str())
        .get_result::<JsonRow>(&mut *conn).await.optional()?;
    if let Some(reused) = reused {
        if reused.value != json!(scope)
            || previous.as_ref().map(|current| &current.active_series_id)
                != Some(&record.active_series_id)
        {
            return Err(refused("native series identity cannot cross scopes or resurrect an earlier replaced series").into());
        }
    }
    let head = previous
        .as_ref()
        .map(key_backup_active_series_head)
        .transpose()
        .map_err(refused)?;
    validate_key_backup_active_series_transition(head.as_ref(), &record).map_err(refused)?;
    if previous
        .as_ref()
        .is_some_and(|previous| record.series_pointer_version <= previous.series_pointer_version)
    {
        return Err(refused("native pointer must advance its exact scoped version").into());
    }
    for old in &record.previous_series_ids {
        let old=sql_query("SELECT record AS value FROM realm_actor_backup_series WHERE realm_id=$1 AND actor_id=$2 AND effective_scope=$3 AND active_series_id=$4 FOR SHARE")
            .bind::<Text,_>(event.realm_id.as_str()).bind::<Jsonb,_>(json!(record.actor_id))
            .bind::<Jsonb,_>(json!(scope)).bind::<Text,_>(old.as_str())
            .get_result::<JsonRow>(&mut *conn).await.optional()?;
        if old.is_none() {
            return Err(
                refused("previous series is not an accepted original in this exact scope").into(),
            );
        }
    }
    crate::authority_commit::queue_event_in_connection(conn, event, commit.committed_at).await?;
    if !matches!(
        crate::authority_commit::commit_verified_key_backup_pointer_in_connection(
            conn,
            &write.commit
        )
        .await?,
        AuthorityCommitWriteOutcome::Committed
    ) {
        return Err(refused("native series governance or control head changed").into());
    }
    crate::agent_producer_signer_keys::retain_prepared_applet_in_connection(
        conn, event, commit, &fact,
    )
    .await?;
    let reference = arkret_wire::CommittedEventRef {
        event_id: event.event_id.clone(),
        commit_id: commit.commit_id.clone(),
        stream_ref: commit.stream_ref.clone(),
        stream_position: commit.stream_position,
    };
    let source = super::original_material(conn, &reference).await?;
    sql_query("INSERT INTO realm_actor_backup_series(realm_id,actor_id,effective_scope,active_series_id,series_pointer_version,record,source) VALUES($1,$2,$3,$4,$5,$6,$7)")
        .bind::<Text,_>(event.realm_id.as_str()).bind::<Jsonb,_>(json!(record.actor_id)).bind::<Jsonb,_>(json!(scope))
        .bind::<Text,_>(record.active_series_id.as_str()).bind::<BigInt,_>(i64::try_from(record.series_pointer_version).map_err(refused)?)
        .bind::<Jsonb,_>(json!(record)).bind::<Jsonb,_>(json!(source)).execute(&mut *conn).await?;
    let selector = CurrentSelector::RealmActorKeyBackupActiveSeries {
        actor_id: record.actor_id.clone(),
        effective_scope: scope.clone(),
        backup_kind: arkret_wire::RealmActorBackupKind::SecretStorage,
    };
    let value = RealmActorKeyBackupActiveSeriesValue {
        active_series_id: record.active_series_id,
        series_pointer_version: record.series_pointer_version,
        manager_ref: record
            .manager_ref
            .ok_or_else(|| refused("native manager ref absent"))?,
        recovery_ref: record
            .recovery_ref
            .ok_or_else(|| refused("native recovery ref absent"))?,
        recipient_ref: record
            .recipient_ref
            .ok_or_else(|| refused("native recipient ref absent"))?,
    };
    crate::realm_actor_control::write_current(
        conn,
        &record.actor_id,
        json!(selector),
        json!(value),
        commit,
    )
    .await?;
    super::advance_revision(conn, &record.actor_id, revision).await?;
    Ok(KeyBackupActiveSeriesCommitOutcome::Committed(
        commit.clone(),
    ))
}

async fn require_known_scope(
    conn: &mut AsyncPgConnection,
    actor: &ActorId,
    scope: &ScopeRef,
) -> PersistenceResult<()> {
    let subject = actor
        .as_realm_actor_id()
        .ok_or_else(|| refused("native actor absent"))?;
    arkret_models_crypto::validate_realm_actor_backup_scope(subject, scope).map_err(refused)?;
    if let ScopeRef::Circle { circle_id, .. } = scope {
        let row=sql_query("SELECT to_jsonb(EXISTS(SELECT 1 FROM projection_circles c WHERE c.realm_id=$1 AND c.id=$2) AND (EXISTS(SELECT 1 FROM realm_actor_backup_series s WHERE s.realm_id=$1 AND s.actor_id=$3 AND s.effective_scope=$4) OR EXISTS(SELECT 1 FROM realm_actor_current_states a CROSS JOIN LATERAL jsonb_array_elements(a.value->'scopes') e WHERE a.realm_id=$1 AND a.actor_id=$3 AND a.selector->>'kind'='realm_actor_device_authorization' AND e->'effective_scope'=$4))) AS value")
            .bind::<Text,_>(subject.realm_id.as_str()).bind::<diesel::sql_types::Binary,_>(circle_id.token_bytes().to_vec())
            .bind::<Jsonb,_>(json!(actor)).bind::<Jsonb,_>(json!(scope)).get_result::<JsonRow>(&mut *conn).await.map_err(PersistenceError::database)?;
        if row.value != json!(true) {
            return Err(refused(
                "native Circle scope is not an existing known actor scope",
            ));
        }
    }
    Ok(())
}
