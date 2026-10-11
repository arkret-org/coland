//! Self watch preferences: canonical whole-value CAS at the accepting Commit cut.
use arkret_models_collaboration::events_payloads::strand::StrandWatchSetPayload;
use arkret_wire::{
    ActorId, CommitStreamRef, CurrentRevision, Event, EventKind, RealmCommit, RealmId, ScopeRef,
    StrandId,
};
use coland_storage::{PersistenceError, PersistenceResult};
use diesel::sql_types::{BigInt, Jsonb, Text, Timestamptz};
use diesel::{OptionalExtension, sql_query};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use serde_json::{Value, json};

pub(crate) const WATCH_HISTORY_SQL: &str = "SELECT EXISTS(SELECT 1 FROM canonical_events WHERE realm_id=$1 AND kind='ak.strand.watch.set' AND state='committed' AND envelope->'payload'->>'strand_id'=$2 AND actor_id=$3 AND envelope->>'event_id'<>$4) AS present";

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

pub(crate) async fn commit_in_connection(
    conn: &mut AsyncPgConnection,
    event: &Event,
    commit: &RealmCommit,
) -> PersistenceResult<()> {
    if event.kind != EventKind::StrandWatchSet {
        return Ok(());
    }
    arkret_schema::validate_event_for_submit(event)
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    let payload: StrandWatchSetPayload =
        serde_json::from_value(json!(&event.payload)).map_err(PersistenceError::database)?;
    if payload.watcher_actor_id != event.actor_id {
        return Err(PersistenceError::Conflict(
            "unsupported_feature: other-actor watch requires its registered audit batch admission"
                .to_owned(),
        ));
    }
    if event.scope_ref
        != (ScopeRef::Realm {
            realm_id: event.realm_id.clone(),
        })
        || commit.stream_ref
            != (CommitStreamRef::Realm {
                realm_id: event.realm_id.clone(),
            })
    {
        return Err(PersistenceError::Conflict("unsupported_feature: Circle watch requires a complete scoped authorization and disclosure cut".to_owned()));
    }
    crate::realm_authorization_cut::authorize_capability_gated_event_in_connection(
        conn,
        event,
        commit.committed_at,
    )
    .await?;
    let strand = sql_query("SELECT s.value FROM strand_current_results s JOIN realm_commits c ON c.commit_id=s.current_commit_id WHERE s.realm_id=$1 AND s.strand_id=$2 AND c.realm_id=s.realm_id AND c.stream_position=s.current_stream_position AND c.stream_ref->>'kind'='realm' AND c.stream_ref->>'realm_id'=s.realm_id FOR SHARE OF s")
        .bind::<Text,_>(event.realm_id.as_str()).bind::<Text,_>(payload.strand_id.as_str()).get_result::<CurrentRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?
        .ok_or_else(|| refusal("watch target Strand has no confirmed current value"))?;
    if strand
        .value
        .get("scope_circle_id")
        .is_some_and(|scope| !scope.is_null())
        || strand.value.get("state").and_then(Value::as_str) != Some("active")
    {
        return Err(refusal("watch target is not an active Realm-scope Strand"));
    }
    let current = sql_query("SELECT value FROM strand_watch_current_results WHERE realm_id=$1 AND strand_id=$2 AND watcher_actor_id=$3 FOR UPDATE")
        .bind::<Text,_>(event.realm_id.as_str()).bind::<Text,_>(payload.strand_id.as_str()).bind::<Text,_>(payload.watcher_actor_id.to_string())
        .get_result::<CurrentRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
    // Omission asserts never-written. Explicit JSON null asserts a written,
    // cleared value and is never confused with the missing row.
    let expected = event.payload.get("expected_value");
    if current.is_none() {
        if commit.governance_generation != 0 {
            return Err(PersistenceError::Conflict(
                "revision_unavailable: watch never-written state has no confirmed tenure import"
                    .to_owned(),
            ));
        }
        let written = sql_query(WATCH_HISTORY_SQL)
            .bind::<Text, _>(event.realm_id.as_str())
            .bind::<Text, _>(payload.strand_id.as_str())
            .bind::<Text, _>(payload.watcher_actor_id.to_string())
            .bind::<Text, _>(event.event_id.as_str())
            .get_result::<PresentRow>(&mut *conn)
            .await
            .map_err(PersistenceError::database)?
            .present;
        if written {
            return Err(PersistenceError::Conflict(
                "revision_unavailable: accepted watch history has no materialized current value"
                    .to_owned(),
            ));
        }
    }
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
