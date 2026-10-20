//! Atomic Realm Device proposal and terminal effects, independent of Account PCRs.
use arkret_models_collaboration::events_payloads::{DeviceOrPrincipalRef, DeviceRevokePayload};
use arkret_models_integration::{
    RealmActorDeviceAuthorizationValue, RealmActorDeviceRevokeOutcomeStatus,
    RealmActorDeviceRevokeState, RealmActorOperationOutcome,
};
use arkret_wire::{ActorId, CommittedEventRef, Event, EventKind, Hash};
use coland_storage::{
    AuthorityCommitTransaction, CurrentRealmAuthority, PersistenceError, PersistenceResult,
};
use diesel::sql_types::{Jsonb, Text, Timestamptz};
use diesel::{OptionalExtension, QueryableByName, sql_query};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use serde_json::{Value, json};

use crate::PgTransactionError;
use crate::realm_actor_control::{current_source, write_current};

#[derive(QueryableByName)]
struct Row {
    #[diesel(sql_type = Jsonb)]
    value: Value,
}
fn invalid(error: impl std::fmt::Display) -> PersistenceError {
    PersistenceError::Conflict(format!("temporarily_unavailable: {error}"))
}
fn decode<T: serde::de::DeserializeOwned>(value: Value) -> PersistenceResult<T> {
    serde_json::from_value(value).map_err(invalid)
}

async fn cleanup_digest(
    conn: &mut AsyncPgConnection,
    proposal: &CommittedEventRef,
) -> PersistenceResult<String> {
    let rows = sql_query("SELECT to_jsonb(c)-'completion_ref' AS value FROM realm_actor_device_revoke_cleanup c WHERE proposal_commit_id=$1 ORDER BY mls_group_id COLLATE \"C\",leaf_index")
        .bind::<Text,_>(proposal.commit_id.as_str()).load::<Row>(&mut *conn).await.map_err(PersistenceError::database)?;
    arkret_canonical::canonical_sha256(&rows.into_iter().map(|row| row.value).collect::<Vec<_>>())
        .map_err(invalid)
}

pub(crate) async fn prepare(
    conn: &mut AsyncPgConnection,
    event: &Event,
    proposal: &CommittedEventRef,
) -> Result<RealmActorOperationOutcome, PgTransactionError> {
    let payload: DeviceRevokePayload = decode(json!(event.payload))?;
    payload.validate().map_err(invalid)?;
    let subject = event
        .actor_id
        .as_realm_actor_id()
        .ok_or_else(|| invalid("Realm actor required"))?;
    if event.kind != EventKind::DeviceRevoke
        || !matches!(&payload.revoked_by, DeviceOrPrincipalRef::Principal(id) if id == &subject.principal_id)
    {
        return Err(invalid("revoke requires the subject's current control authority").into());
    }
    let (value, authorization_ref) = current_source(conn, &event.actor_id,
        json!({"kind":"realm_actor_device_authorization","actor_id":event.actor_id,"device_id":payload.device_id})).await?;
    let value: RealmActorDeviceAuthorizationValue = decode(value)?;
    let (original, _) =
        crate::realm_actor_control_source::original(conn, &authorization_ref).await?;
    if original.actor_id != event.actor_id
        || original.payload.get("device_id") != Some(&json!(payload.device_id))
        || RealmActorDeviceAuthorizationValue::from_event(&original).map_err(invalid)? != value
        || authorization_ref.stream_ref != proposal.stream_ref
        || authorization_ref.stream_position >= proposal.stream_position
    {
        return Err(invalid("revoke authorization original differs").into());
    }
    Ok(RealmActorOperationOutcome::DeviceRevoke {
        status: RealmActorDeviceRevokeOutcomeStatus::DeviceRevoke,
        proposal_ref: proposal.clone(),
        device_id: payload.device_id,
        authorization_ref,
        authorized_generation_ref: value.authorized_generation_ref,
        state: RealmActorDeviceRevokeState::Pending,
        decided_at: None,
    })
}

pub(crate) async fn retain(
    conn: &mut AsyncPgConnection,
    transaction: &AuthorityCommitTransaction,
    digest: &Hash,
    outcome: RealmActorOperationOutcome,
) -> Result<(), PgTransactionError> {
    let RealmActorOperationOutcome::DeviceRevoke {
        proposal_ref,
        device_id,
        authorized_generation_ref,
        ..
    } = &outcome
    else {
        return Err(invalid("revoke outcome required").into());
    };
    let event = &transaction.event;
    sql_query("INSERT INTO realm_actor_device_revoke_results(proposal_commit_id,realm_id,actor_id,request_digest,command_result,accepted_at,result_json,cleanup_digest) VALUES($1,$2,$3,$4,'pending',$5,$6,$7)")
        .bind::<Text,_>(proposal_ref.commit_id.as_str()).bind::<Text,_>(event.realm_id.as_str())
        .bind::<Jsonb,_>(json!(event.actor_id)).bind::<Text,_>(digest.as_str())
        .bind::<Timestamptz,_>(transaction.commit.committed_at).bind::<Jsonb,_>(json!(outcome))
        .bind::<Text,_>(arkret_canonical::canonical_sha256(&Vec::<Value>::new()).map_err(invalid)?)
        .execute(&mut *conn).await?;
    crate::realm_actor_recovery::inventory_selected(
        conn,
        &event.actor_id,
        *authorized_generation_ref,
        proposal_ref,
        Some(device_id),
    )
    .await?;
    let inventory_digest = cleanup_digest(conn, proposal_ref).await?;
    sql_query("UPDATE realm_actor_device_revoke_results SET cleanup_digest=$1 WHERE proposal_commit_id=$2")
        .bind::<Text,_>(inventory_digest).bind::<Text,_>(proposal_ref.commit_id.as_str()).execute(&mut *conn).await?;
    let proposals = sql_query("SELECT jsonb_build_object('tag_id',(e.envelope->>'event_id')||':1','value',e.envelope->'payload') AS value FROM canonical_events e JOIN realm_commits c ON c.event_pk=e.pk WHERE c.realm_id=$1 AND c.stream_ref=$2 AND e.state='committed' AND e.kind='ak.device.revoke' AND e.envelope->'actor_id'=$3 AND e.envelope#>>'{payload,device_id}'=$4 ORDER BY (e.envelope->>'event_id') COLLATE \"C\"")
        .bind::<Text,_>(event.realm_id.as_str()).bind::<Jsonb,_>(json!(proposal_ref.stream_ref))
        .bind::<Jsonb,_>(json!(event.actor_id)).bind::<Text,_>(device_id.as_str())
        .load::<Row>(&mut *conn).await?;
    write_current(conn, &event.actor_id,
        json!({"kind":"realm_actor_device_revocation_proposals","actor_id":event.actor_id,"device_id":device_id}),
        json!({"proposals":proposals.into_iter().map(|row| row.value).collect::<Vec<_>>()}),
        &transaction.commit).await?;
    Ok(())
}

/// Validate the complete immutable sources before disclosing or executing a command.
pub(crate) async fn read(
    conn: &mut AsyncPgConnection,
    actor: &ActorId,
    proposal: &CommittedEventRef,
) -> PersistenceResult<RealmActorOperationOutcome> {
    let row = sql_query("SELECT to_jsonb(r) AS value FROM realm_actor_device_revoke_results r WHERE proposal_commit_id=$1 FOR UPDATE")
        .bind::<Text,_>(proposal.commit_id.as_str()).get_result::<Row>(&mut *conn).await
        .optional().map_err(PersistenceError::database)?
        .ok_or_else(|| invalid("accepted revoke lost its command ledger"))?;
    let outcome: RealmActorOperationOutcome = decode(row.value["result_json"].clone())?;
    if row.value["cleanup_digest"] != json!(cleanup_digest(conn, proposal).await?) {
        return Err(invalid("revoke cleanup inventory incomplete"));
    }
    let RealmActorOperationOutcome::DeviceRevoke {
        proposal_ref,
        device_id,
        authorization_ref,
        authorized_generation_ref,
        state,
        decided_at,
        ..
    } = &outcome
    else {
        return Err(invalid("invalid revoke ledger result"));
    };
    let subject = actor
        .as_realm_actor_id()
        .ok_or_else(|| invalid("Realm actor required"))?;
    if proposal_ref != proposal
        || row.value["actor_id"] != json!(actor)
        || row.value["realm_id"] != json!(subject.realm_id)
        || row.value["command_result"] != json!(state)
        || (*state == RealmActorDeviceRevokeState::Pending) != decided_at.is_none()
        || *authorized_generation_ref == 0
        || authorization_ref.stream_ref != proposal.stream_ref
        || authorization_ref.stream_position >= proposal.stream_position
    {
        return Err(invalid("revoke ledger binding differs"));
    }
    let (event, commit) = crate::realm_actor_control_source::original(conn, proposal).await?;
    let (authorization, _) =
        crate::realm_actor_control_source::original(conn, authorization_ref).await?;
    let value = RealmActorDeviceAuthorizationValue::from_event(&authorization).map_err(invalid)?;
    let payload: DeviceRevokePayload = decode(json!(event.payload))?;
    if event.kind != EventKind::DeviceRevoke
        || event.actor_id != *actor
        || authorization.actor_id != *actor
        || payload.device_id != *device_id
        || authorization.payload.get("device_id") != Some(&json!(device_id))
        || value.authorized_generation_ref != *authorized_generation_ref
        || decode::<chrono::DateTime<chrono::Utc>>(row.value["accepted_at"].clone())?
            != commit.committed_at
        || decided_at.is_some_and(|at| at < commit.committed_at)
    {
        return Err(invalid("revoke ledger original differs"));
    }
    crate::agent_producer_signer_keys::producer_source_for_commit_in_connection(
        conn, &event, &commit,
    )
    .await?
    .ok_or_else(|| invalid("revoke signer fact absent"))?;
    let operation = sql_query("SELECT to_jsonb(o) AS value FROM realm_actor_operation_outcomes o WHERE realm_id=$1 AND actor_id=$2 AND request_digest=$3")
        .bind::<Text,_>(subject.realm_id.as_str()).bind::<Jsonb,_>(json!(actor))
        .bind::<Text,_>(row.value["request_digest"].as_str().ok_or_else(|| invalid("revoke digest absent"))?)
        .get_result::<Row>(&mut *conn).await.optional().map_err(PersistenceError::database)?
        .ok_or_else(|| invalid("revoke operation original absent"))?;
    if operation.value["event_id"] != json!(event.event_id)
        || operation.value["outcome"]["commit"] != json!(commit)
    {
        return Err(invalid("revoke operation original differs"));
    }
    Ok(outcome)
}

/// The caller holds the Realm authorization lock. No Applet can supply a result.
pub(crate) async fn finish(
    conn: &mut AsyncPgConnection,
    actor: &ActorId,
    authority: &CurrentRealmAuthority,
    terminal: &RealmActorOperationOutcome,
) -> Result<(), PgTransactionError> {
    let subject = actor
        .as_realm_actor_id()
        .ok_or_else(|| invalid("Realm actor required"))?;
    let current = sql_query(
        "SELECT to_jsonb(a) AS value FROM realm_authorities a WHERE realm_id=$1 FOR UPDATE",
    )
    .bind::<Text, _>(subject.realm_id.as_str())
    .get_result::<Row>(&mut *conn)
    .await?;
    if authority.realm_id != subject.realm_id
        || current.value["service_id"] != json!(authority.service_id)
        || current.value["generation"] != json!(authority.generation)
        || current.value["authority_ref"] != json!(authority.authority_ref)
        || current.value["last_handoff_ref"] != json!(authority.last_handoff_ref)
    {
        return Err(invalid("stale_realm_authority: revoke worker no longer governs").into());
    }
    let RealmActorOperationOutcome::DeviceRevoke {
        proposal_ref,
        state,
        decided_at,
        ..
    } = terminal
    else {
        return Err(invalid("revoke terminal required").into());
    };
    if *state == RealmActorDeviceRevokeState::Pending
        || decided_at.is_none()
        || decided_at.is_some_and(|at| at > chrono::Utc::now())
    {
        return Err(invalid("real terminal decision time required").into());
    }
    let original = read(conn, actor, proposal_ref).await?;
    if json!(original) == json!(terminal) {
        return Ok(());
    }
    let mut expected = original;
    let RealmActorOperationOutcome::DeviceRevoke {
        state: old_state,
        decided_at: old_time,
        ..
    } = &mut expected
    else {
        return Err(invalid("invalid revoke ledger").into());
    };
    if *old_state != RealmActorDeviceRevokeState::Pending {
        return Err(PersistenceError::Conflict(
            "duplicate_conflict: revoke terminal differs".into(),
        )
        .into());
    }
    *old_state = *state;
    *old_time = *decided_at;
    if json!(expected) != json!(terminal) {
        return Err(PersistenceError::Conflict(
            "duplicate_conflict: revoke coordinates differ".into(),
        )
        .into());
    }
    let (proposal_event, proposal_commit) =
        crate::realm_actor_control_source::original(conn, proposal_ref).await?;
    crate::authority_commit::require_planned_handoff_write_in_connection(
        conn,
        &proposal_event,
        authority,
    )
    .await?;
    if decided_at.is_some_and(|at| at < proposal_commit.committed_at) {
        return Err(invalid("terminal predates proposal").into());
    }
    if *state == RealmActorDeviceRevokeState::Accepted {
        sql_query("INSERT INTO realm_actor_mls_cleanup(realm_id,actor_id,fenced_generation,device_id,mls_group_id,leaf_index,signature_key,authorization_ref,begin_ref,group_state_ref,completion_ref,queue_state) SELECT realm_id,actor_id,fenced_generation,device_id,mls_group_id,leaf_index,signature_key,authorization_ref,begin_ref,group_state_ref,completion_ref,CASE WHEN completion_ref IS NULL THEN 'pending' ELSE 'completed' END FROM realm_actor_device_revoke_cleanup WHERE proposal_commit_id=$1 ON CONFLICT DO NOTHING")
            .bind::<Text,_>(proposal_ref.commit_id.as_str()).execute(&mut *conn).await?;
    }
    sql_query("UPDATE realm_actor_device_revoke_results SET command_result=$1,result_json=$2 WHERE proposal_commit_id=$3 AND command_result='pending'")
        .bind::<Text,_>(if *state == RealmActorDeviceRevokeState::Accepted {"accepted"} else {"rejected"})
        .bind::<Jsonb,_>(json!(terminal)).bind::<Text,_>(proposal_ref.commit_id.as_str())
        .execute(&mut *conn).await?;
    Ok(())
}

pub(crate) async fn sweep(
    conn: &mut AsyncPgConnection,
    governor: &arkret_wire::DidCoreId,
) -> Result<usize, PgTransactionError> {
    let pending = sql_query("SELECT jsonb_build_object('actor',r.actor_id,'outcome',r.result_json,'authority',to_jsonb(a)) AS value FROM realm_actor_device_revoke_results r JOIN realm_authorities a ON a.realm_id=r.realm_id WHERE r.command_result='pending' AND a.service_id=$1 ORDER BY r.realm_id,r.accepted_at,r.proposal_commit_id LIMIT 64")
        .bind::<Text,_>(governor.as_str()).load::<Row>(&mut *conn).await?;
    let mut count = 0;
    for row in pending {
        let actor: ActorId = decode(row.value["actor"].clone())?;
        let selected_authority = &row.value["authority"];
        let authority = CurrentRealmAuthority {
            realm_id: decode(selected_authority["realm_id"].clone())?,
            service_id: decode(selected_authority["service_id"].clone())?,
            generation: decode(selected_authority["generation"].clone())?,
            authority_ref: decode(selected_authority["authority_ref"].clone())?,
            last_handoff_ref: decode(selected_authority["last_handoff_ref"].clone())?,
        };
        let selected: RealmActorOperationOutcome = decode(row.value["outcome"].clone())?;
        crate::realm_authorization_cut::lock_realm_authorization_cut(
            conn,
            &actor
                .as_realm_actor_id()
                .ok_or_else(|| invalid("Realm actor absent"))?
                .realm_id,
        )
        .await?;
        let RealmActorOperationOutcome::DeviceRevoke { proposal_ref, .. } = selected else {
            return Err(invalid("revoke ledger malformed").into());
        };
        let mut terminal = read(conn, &actor, &proposal_ref).await?;
        let RealmActorOperationOutcome::DeviceRevoke {
            state, decided_at, ..
        } = &mut terminal
        else {
            return Err(invalid("revoke ledger malformed").into());
        };
        if *state != RealmActorDeviceRevokeState::Pending {
            continue;
        }
        *state = RealmActorDeviceRevokeState::Accepted;
        *decided_at = Some(arkret_canonical::normalize_timestamp_canonical(
            chrono::Utc::now(),
        ));
        finish(conn, &actor, &authority, &terminal).await?;
        count += 1;
    }
    Ok(count)
}
