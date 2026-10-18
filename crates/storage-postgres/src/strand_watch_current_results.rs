//! Self watch preferences: canonical whole-value CAS at the accepting Commit cut.
use arkret_models_collaboration::events_payloads::strand::StrandWatchSetPayload;
use arkret_wire::{
    ActorId, CommitStreamHead, CommitStreamRef, CurrentRevision, Event, EventKind, RealmCommit,
    RealmId, ScopeRef, StrandId,
};
use coland_storage::{PersistenceError, PersistenceResult};
use diesel::sql_types::{BigInt, Jsonb, Text, Timestamptz};
use diesel::{OptionalExtension, sql_query};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use serde_json::{Value, json};

pub(crate) const WATCH_HISTORY_SQL: &str = "SELECT EXISTS(SELECT 1 FROM canonical_events WHERE realm_id=$1 AND kind='ak.strand.watch.set' AND state='committed' AND envelope->'payload'->>'strand_id'=$2 AND envelope->'payload'->'watcher_actor_id'=$3::jsonb AND envelope->>'event_id'<>$4) AS present";

#[derive(diesel::QueryableByName)]
struct PresentRow {
    #[diesel(sql_type=diesel::sql_types::Bool)]
    present: bool,
}

#[derive(diesel::QueryableByName)]
struct CurrentRow {
    #[diesel(sql_type = Jsonb)]
    value: Value,
}

fn refusal(detail: &str) -> PersistenceError {
    PersistenceError::Conflict(format!("failed_precondition: {detail}"))
}

pub(crate) fn event_value(event: &Event) -> PersistenceResult<Value> {
    let payload: StrandWatchSetPayload = serde_json::from_value(json!(&event.payload))
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    let Some(level) = payload.level else {
        return Ok(Value::Null);
    };
    let mut value = json!({"level":level});
    if let Some(public) = payload.level_public {
        value["level_public"] = json!(public);
    }
    Ok(value)
}

pub(crate) async fn commit_with_audit_in_connection(
    conn: &mut AsyncPgConnection,
    event: &Event,
    commit: &RealmCommit,
    audit_unit: Option<&coland_storage::RegisteredAuditCommit>,
    prepared: Option<&coland_storage::EventApprovalCommit>,
) -> PersistenceResult<()> {
    if event.kind != EventKind::StrandWatchSet {
        return Ok(());
    }
    arkret_schema::validate_event_for_submit(event)
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    let payload: StrandWatchSetPayload =
        serde_json::from_value(json!(&event.payload)).map_err(PersistenceError::database)?;
    if payload.watcher_actor_id != event.actor_id
        && !audit_unit.is_some_and(|unit| unit.pair_for(event))
    {
        return Err(refusal(
            "other-actor watch has no registered same-batch audit admission",
        ));
    }
    if !audit_unit.is_some_and(|unit| unit.pair_for(event)) {
        crate::realm_authorization_cut::authorize_capability_gated_event_with_approvals(
            conn, event, commit, prepared,
        )
        .await?;
    }
    let strand = sql_query("SELECT s.value FROM strand_current_results s JOIN realm_commits c ON c.commit_id=s.current_commit_id WHERE s.realm_id=$1 AND s.strand_id=$2 AND c.realm_id=s.realm_id AND c.stream_position=s.current_stream_position AND c.stream_ref=$3 FOR SHARE OF s")
        .bind::<Text,_>(event.realm_id.as_str()).bind::<Text,_>(payload.strand_id.as_str())
        .bind::<Jsonb,_>(serde_json::to_value(&commit.stream_ref).map_err(PersistenceError::database)?)
        .get_result::<CurrentRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?
        .ok_or_else(|| refusal("watch target Strand has no confirmed current value in its effective stream"))?;
    if strand.value.get("state").and_then(Value::as_str) != Some("active") {
        return Err(refusal("watch target is not an active Strand"));
    }
    let scope = match strand.value.get("scope_circle_id").and_then(Value::as_str) {
        Some(circle) => ScopeRef::Circle {
            realm_id: event.realm_id.clone(),
            circle_id: circle.parse().map_err(PersistenceError::database)?,
        },
        None => ScopeRef::Realm {
            realm_id: event.realm_id.clone(),
        },
    };
    if event.scope_ref != scope
        || commit.stream_ref
            != CommitStreamRef::from_scope(&scope, None).map_err(PersistenceError::database)?
    {
        return Err(refusal(
            "watch source differs from the Strand effective namespace",
        ));
    }
    if matches!(scope, ScopeRef::Circle { .. }) {
        crate::circle_current_results::require_active_author_in_connection(conn, event, commit)
            .await?;
    }
    require_current_basis_in_connection(
        conn,
        &event.realm_id,
        &CommitStreamHead {
            stream_ref: commit.stream_ref.clone(),
            commit_id: commit.commit_id.clone(),
            stream_position: commit.stream_position,
        },
        &payload.strand_id,
        &payload.watcher_actor_id,
        event.event_id.as_str(),
    )
    .await?;
    let current = sql_query("SELECT value FROM strand_watch_current_results WHERE realm_id=$1 AND strand_id=$2 AND watcher_actor_id=$3 FOR UPDATE")
        .bind::<Text,_>(event.realm_id.as_str()).bind::<Text,_>(payload.strand_id.as_str()).bind::<Text,_>(payload.watcher_actor_id.to_string())
        .get_result::<CurrentRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
    // Omission asserts never-written. Explicit JSON null asserts a written,
    // cleared value and is never confused with the missing row.
    let expected = event.payload.get("expected_value");
    if match (&current, expected) {
        (None, None) => false,
        (Some(current), Some(expected)) => current.value != *expected,
        _ => true,
    } {
        return Err(refusal(
            "watch expected_value differs from the complete current value",
        ));
    }
    install_in_connection(
        conn,
        &event.realm_id,
        &payload.strand_id,
        &payload.watcher_actor_id,
        &CurrentRevision {
            commit_id: commit.commit_id.clone(),
            stream_position: commit.stream_position,
        },
        &event_value(event)?,
        commit.committed_at,
    )
    .await
}

/// Prove the exact effective namespace is a complete accepted chain, then
/// compare the last original selector write with its durable reducer row.
/// Neither generation zero nor a missing row is an absence proof.
pub(crate) async fn require_current_basis_in_connection(
    conn: &mut AsyncPgConnection,
    realm: &RealmId,
    head: &CommitStreamHead,
    strand: &StrandId,
    actor: &ActorId,
    exclude: &str,
) -> PersistenceResult<()> {
    let imported = sql_query("SELECT EXISTS(SELECT 1 FROM realm_authorities a WHERE a.realm_id=$1 AND (a.generation=0 OR EXISTS(SELECT 1 FROM realm_authority_handoffs h WHERE h.realm_id=a.realm_id AND h.to_generation=a.generation AND h.to_service_id=a.service_id AND h.handoff_id=a.last_handoff_ref))) AS present")
        .bind::<Text,_>(realm.as_str()).get_result::<PresentRow>(&mut *conn).await.map_err(PersistenceError::database)?.present;
    if !imported {
        return Err(PersistenceError::Conflict(
            "revision_unavailable: watch never-written state has no confirmed tenure import"
                .to_owned(),
        ));
    }
    let stream = serde_json::to_value(&head.stream_ref).map_err(PersistenceError::database)?;
    let complete = sql_query("SELECT (count(*)=$3+1 AND count(e.pk)=count(*) AND count(*) FILTER (WHERE c.stream_position=0 AND c.commit_json->'previous_commit_ref' IS NULL OR c.stream_position=0 AND c.commit_json->'previous_commit_ref'='null'::jsonb)=1 AND count(*) FILTER (WHERE c.stream_position=$3 AND c.commit_id=$4)=1 AND bool_and(c.stream_position=0 OR EXISTS(SELECT 1 FROM realm_commits p WHERE p.realm_id=c.realm_id AND p.stream_ref=c.stream_ref AND p.stream_position=c.stream_position-1 AND p.commit_id=c.commit_json->>'previous_commit_ref'))) AS present FROM realm_commits c LEFT JOIN canonical_events e ON e.pk=c.event_pk AND e.state='committed' AND e.realm_id=c.realm_id AND e.envelope->>'event_id'=c.commit_json->>'event_ref' WHERE c.realm_id=$1 AND c.stream_ref=$2 AND c.stream_position<=$3")
        .bind::<Text,_>(realm.as_str()).bind::<Jsonb,_>(&stream)
        .bind::<BigInt,_>(i64::try_from(head.stream_position).map_err(PersistenceError::database)?).bind::<Text,_>(head.commit_id.as_str())
        .get_result::<PresentRow>(&mut *conn).await.map_err(PersistenceError::database)?.present;
    if !complete {
        return Err(PersistenceError::Conflict(
            "revision_unavailable: watch accepted namespace is incomplete".to_owned(),
        ));
    }
    let uncovered = sql_query("SELECT EXISTS(SELECT 1 FROM canonical_events e LEFT JOIN realm_commits c ON c.event_pk=e.pk AND c.realm_id=e.realm_id AND c.commit_json->>'event_ref'=e.envelope->>'event_id' WHERE e.realm_id=$1 AND e.kind='ak.strand.watch.set' AND e.state='committed' AND e.envelope->'payload'->>'strand_id'=$2 AND e.envelope->'payload'->'watcher_actor_id'=$3::jsonb AND e.envelope->>'event_id'<>$4 AND (c.commit_id IS NULL OR c.stream_ref<>$5 OR c.stream_position>$6)) AS present")
        .bind::<Text,_>(realm.as_str()).bind::<Text,_>(strand.as_str()).bind::<Text,_>(actor.to_string()).bind::<Text,_>(exclude)
        .bind::<Jsonb,_>(&stream).bind::<BigInt,_>(i64::try_from(head.stream_position).map_err(PersistenceError::database)?)
        .get_result::<PresentRow>(&mut *conn).await.map_err(PersistenceError::database)?.present;
    if uncovered {
        return Err(PersistenceError::Conflict(
            "revision_unavailable: accepted Watch source has no covering namespace Commit"
                .to_owned(),
        ));
    }
    #[derive(diesel::QueryableByName)]
    struct Source {
        #[diesel(sql_type=Jsonb)]
        envelope: Value,
        #[diesel(sql_type=Text)]
        commit_id: String,
        #[diesel(sql_type=BigInt)]
        stream_position: i64,
        #[diesel(sql_type=Jsonb)]
        stream_ref: Value,
    }
    let source = sql_query("SELECT e.envelope,c.commit_id,c.stream_position,c.stream_ref FROM canonical_events e JOIN realm_commits c ON c.event_pk=e.pk AND c.realm_id=e.realm_id WHERE e.realm_id=$1 AND e.kind='ak.strand.watch.set' AND e.state='committed' AND e.envelope->'payload'->>'strand_id'=$2 AND e.envelope->'payload'->'watcher_actor_id'=$3::jsonb AND e.envelope->>'event_id'<>$4 ORDER BY c.governance_generation DESC,c.stream_position DESC LIMIT 1")
        .bind::<Text,_>(realm.as_str()).bind::<Text,_>(strand.as_str()).bind::<Text,_>(actor.to_string()).bind::<Text,_>(exclude)
        .get_result::<Source>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
    #[derive(diesel::QueryableByName)]
    struct Materialized {
        #[diesel(sql_type=Jsonb)]
        value: Value,
        #[diesel(sql_type=Text)]
        current_commit_id: String,
        #[diesel(sql_type=BigInt)]
        current_stream_position: i64,
    }
    let current = sql_query("SELECT value,current_commit_id,current_stream_position FROM strand_watch_current_results WHERE realm_id=$1 AND strand_id=$2 AND watcher_actor_id=$3")
        .bind::<Text,_>(realm.as_str()).bind::<Text,_>(strand.as_str()).bind::<Text,_>(actor.to_string())
        .get_result::<Materialized>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
    let valid = match (source, current) {
        (None, None) => true,
        (Some(source), Some(current)) => {
            let event: Event =
                serde_json::from_value(source.envelope).map_err(PersistenceError::database)?;
            source.stream_ref == stream
                && source.stream_position
                    <= i64::try_from(head.stream_position).map_err(PersistenceError::database)?
                && source.commit_id == current.current_commit_id
                && source.stream_position == current.current_stream_position
                && event_value(&event)? == current.value
        }
        _ => false,
    };
    if !valid {
        return Err(PersistenceError::Conflict(
            "revision_unavailable: watch originals and durable current disagree".to_owned(),
        ));
    }
    Ok(())
}

pub(crate) async fn install_in_connection(
    conn: &mut AsyncPgConnection,
    realm: &RealmId,
    strand: &StrandId,
    actor: &ActorId,
    revision: &CurrentRevision,
    value: &Value,
    at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<()> {
    let _: arkret_models_collaboration::strand_watch_operations::StrandWatchCurrentValue =
        serde_json::from_value(value.clone()).map_err(PersistenceError::database)?;
    let changed = sql_query("INSERT INTO strand_watch_current_results (realm_id,strand_id,watcher_actor_id,current_commit_id,current_stream_position,value,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(strand_id,watcher_actor_id) DO UPDATE SET current_commit_id=EXCLUDED.current_commit_id,current_stream_position=EXCLUDED.current_stream_position,value=EXCLUDED.value,updated_at=EXCLUDED.updated_at WHERE strand_watch_current_results.realm_id=EXCLUDED.realm_id AND (strand_watch_current_results.current_stream_position<EXCLUDED.current_stream_position OR (strand_watch_current_results.current_stream_position=EXCLUDED.current_stream_position AND strand_watch_current_results.current_commit_id=EXCLUDED.current_commit_id AND strand_watch_current_results.value=EXCLUDED.value))")
        .bind::<Text,_>(realm.as_str()).bind::<Text,_>(strand.as_str()).bind::<Text,_>(actor.to_string()).bind::<Text,_>(revision.commit_id.as_str())
        .bind::<BigInt,_>(i64::try_from(revision.stream_position).map_err(PersistenceError::database)?).bind::<Jsonb,_>(value).bind::<Timestamptz,_>(at)
        .execute(conn).await.map_err(PersistenceError::database)?;
    if changed != 1 {
        return Err(refusal(
            "watch current revision regressed or conflicts at this Commit",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn watch_same_revision_requires_identical_value() {
        let database = crate::test_database::TestDatabase::lease().await;
        let pool = database.pool();
        let realm = RealmId::new("ak:realm:ARQRpvtCGBgQfVQzTK4_Hgbg0D0HSnc3gPCvXOQUICir").unwrap();
        let strand =
            StrandId::new("ak:strand:AT3ARBdH1FM6GjXK9ulTx-YMvQOXys39dlUzZV6KyID9").unwrap();
        let revision = CurrentRevision {
            commit_id: arkret_wire::RealmCommitId::from_digest([3; 32]),
            stream_position: 0,
        };
        let actor = ActorId::account(arkret_wire::AccountId::new(
            arkret_wire::DidCoreId::new("ak:did_core:web:watcher.example").unwrap(),
            arkret_wire::DidCoreId::new("ak:did_core:web:station.example").unwrap(),
        ));
        let mut conn = pool.get().await.unwrap();
        // The storage fold accepts an already verified Commit reference; a
        // chain node is enough to test its independent revision invariant.
        sql_query("INSERT INTO realm_commits(commit_id,realm_id,stream_key,stream_ref,stream_position,governance_generation,commit_json,committed_at) VALUES($1,$2,$3,$4,0,0,'{}',now())")
            .bind::<Text,_>(revision.commit_id.as_str()).bind::<Text,_>(realm.as_str()).bind::<Text,_>(realm.as_str()).bind::<Jsonb,_>(json!({"kind":"realm","realm_id":realm})).execute(&mut *conn).await.unwrap();
        install_in_connection(
            &mut conn,
            &realm,
            &strand,
            &actor,
            &revision,
            &json!({"level":"all"}),
            chrono::Utc::now(),
        )
        .await
        .unwrap();
        install_in_connection(
            &mut conn,
            &realm,
            &strand,
            &actor,
            &revision,
            &json!({"level":"all"}),
            chrono::Utc::now(),
        )
        .await
        .unwrap();
        assert!(
            install_in_connection(
                &mut conn,
                &realm,
                &strand,
                &actor,
                &revision,
                &json!({"level":"muted"}),
                chrono::Utc::now()
            )
            .await
            .is_err()
        );
    }
}
