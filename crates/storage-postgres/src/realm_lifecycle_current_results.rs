//! Registered Realm lifecycle results at the accepting Commit.

use coland_storage::{PersistenceError, PersistenceResult};
use diesel::sql_types::{BigInt, Bool, Jsonb, Text, Timestamptz};
use diesel_async::{AsyncPgConnection, RunQueryDsl};

#[derive(diesel::QueryableByName)]
struct ReplicaLifecycle {
    #[diesel(sql_type = Bool)]
    terminal: bool,
    #[diesel(sql_type = Bool)]
    archived: bool,
    #[diesel(sql_type = Bool)]
    frozen: bool,
}

/// A fresh successor may project only while its anchored scope is live.
/// Historical rows at or below the installed anchor do not call this gate.
pub(crate) async fn require_replica_live_in_connection(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
) -> PersistenceResult<()> {
    let gates = diesel::sql_query(
        "SELECT EXISTS(SELECT 1 FROM realm_bootstrap_current_results \
         WHERE realm_id=$1 AND result_family='realm_tombstone') AS terminal, \
         EXISTS(SELECT 1 FROM realm_bootstrap_current_results \
         WHERE realm_id=$1 AND result_family='realm_archive' AND value->>'archived'='true') AS archived, \
         EXISTS(SELECT 1 FROM realm_bootstrap_current_results \
         WHERE realm_id=$1 AND result_family='realm_freeze' AND value->>'frozen'='true') AS frozen",
    )
    .bind::<Text, _>(event.realm_id.as_str())
    .get_result::<ReplicaLifecycle>(conn)
    .await
    .map_err(PersistenceError::database)?;
    if event.kind == arkret_wire::EventKind::RealmDestroy {
        return Err(PersistenceError::Conflict(
            "failed_precondition: v1 has no registered destructive confirmation carrier".to_owned(),
        ));
    }
    if gates.terminal && !arkret_wire::events::kinds::is_audit_kind(&event.kind) {
        return Err(PersistenceError::Conflict(
            "failed_precondition: replica cannot create live effects in a terminal Realm"
                .to_owned(),
        ));
    }
    let payload = serde_json::Value::Object(event.payload.clone().into_iter().collect());
    if event.kind == arkret_wire::EventKind::RealmTombstone {
        let typed: arkret_models_collaboration::governance::realm_lifecycle::RealmTombstonePayload =
            serde_json::from_value(payload.clone())
                .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
        if typed.successor_realm_id == event.realm_id {
            return Err(PersistenceError::Conflict(
                "failed_precondition: successor must differ from the terminating Realm".to_owned(),
            ));
        }
    }
    if (gates.archived || gates.frozen)
        && !arkret_wire::events::kinds::realm_write_gate_exempt(&event.kind, &payload)
    {
        return Err(PersistenceError::Conflict(
            "realm_frozen: replica cannot create live effects in an archived or frozen Realm"
                .to_owned(),
        ));
    }
    Ok(())
}

pub(crate) async fn commit_in_connection(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    commit: &arkret_wire::RealmCommit,
) -> PersistenceResult<()> {
    use arkret_wire::EventKind;
    let (family, value) = match event.kind {
        EventKind::RealmTombstone => (
            "realm_tombstone",
            serde_json::to_value(&event.payload).map_err(PersistenceError::database)?,
        ),
        EventKind::RealmArchive => ("realm_archive", serde_json::json!({"archived": true})),
        EventKind::RealmRestore => ("realm_archive", serde_json::json!({"archived": false})),
        EventKind::RealmFreeze => ("realm_freeze", serde_json::json!({"frozen": true})),
        EventKind::RealmUnfreeze => ("realm_freeze", serde_json::json!({"frozen": false})),
        _ => return Ok(()),
    };
    let position = i64::try_from(commit.stream_position)
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    let changed = diesel::sql_query(
        "INSERT INTO realm_bootstrap_current_results \
         (realm_id,result_family,current_commit_id,current_stream_position,value,updated_at) \
         VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(realm_id,result_family) DO UPDATE SET \
         current_commit_id=EXCLUDED.current_commit_id, \
         current_stream_position=EXCLUDED.current_stream_position, \
         value=EXCLUDED.value,updated_at=EXCLUDED.updated_at \
         WHERE realm_bootstrap_current_results.current_stream_position < EXCLUDED.current_stream_position \
           AND EXCLUDED.result_family <> 'realm_tombstone'",
    )
    .bind::<Text, _>(event.realm_id.as_str())
    .bind::<Text, _>(family)
    .bind::<Text, _>(commit.commit_id.as_str())
    .bind::<BigInt, _>(position)
    .bind::<Jsonb, _>(&value)
    .bind::<Timestamptz, _>(commit.committed_at)
    .execute(conn).await.map_err(PersistenceError::database)?;
    if changed != 1 {
        return Err(PersistenceError::Conflict(
            "failed_precondition: lifecycle current cannot advance".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn replica_terminal_gate_refuses_destroy_and_live_effects_but_preserves_audit() {
        let database = crate::TestDatabase::lease().await;
        let pool = database.pool();
        let mut conn = pool.get().await.unwrap();
        let realm =
            arkret_wire::RealmId::new("ak:realm:AY6DJbBwavsGTQuBZZiqqw9MVcqPZ8QX8invQ3i2kpi7")
                .unwrap();
        let actor = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            arkret_wire::DidCoreId::new("ak:did_core:web:holder.example").unwrap(),
            arkret_wire::DidCoreId::new("ak:did_core:web:station.example").unwrap(),
        ));
        let at = chrono::Utc::now();
        let event = |kind: &str| {
            arkret_wire::test_support::raw_event_for_actor_at(
                kind,
                arkret_wire::ScopeRef::Realm {
                    realm_id: realm.clone(),
                },
                actor.clone(),
                serde_json::json!({}),
                at,
            )
            .unwrap()
        };
        let destroy = event("ak.realm.destroy");
        let error = require_replica_live_in_connection(&mut conn, &destroy)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("failed_precondition"), "{error}");
        assert!(
            !error.to_string().contains("realm_terminal_state"),
            "{error}"
        );
        // The gate itself never installs the forbidden registered destroy result.
        #[derive(diesel::QueryableByName)]
        struct CountRow {
            #[diesel(sql_type = BigInt)]
            count: i64,
        }
        let count = diesel::sql_query(
            "SELECT COUNT(*) AS count FROM realm_bootstrap_current_results WHERE realm_id=$1",
        )
        .bind::<Text, _>(realm.as_str())
        .get_result::<CountRow>(&mut *conn)
        .await
        .unwrap();
        assert_eq!(count.count, 0);
        let terminal = serde_json::json!({"successor_realm_id": "ak:realm:ASR8x2N1qyfyy6I-eob3l-FNhx4FPBTyMJrIfifkksgW"});
        diesel::sql_query("INSERT INTO realm_bootstrap_current_results (realm_id,result_family,current_commit_id,current_stream_position,value,updated_at) VALUES($1,'realm_tombstone',$2,9,$3,$4)")
            .bind::<Text, _>(realm.as_str())
            .bind::<Text, _>(arkret_wire::RealmCommitId::from_digest([73; 32]).as_str())
            .bind::<Jsonb, _>(&terminal).bind::<Timestamptz, _>(at)
            .execute(&mut *conn).await.unwrap();
        for kind in [
            "ak.space.update",
            "ak.realm.restore",
            "ak.realm.tombstone",
            "ak.realm.destroy",
        ] {
            let error = require_replica_live_in_connection(&mut conn, &event(kind))
                .await
                .unwrap_err();
            assert!(
                error.to_string().contains("failed_precondition"),
                "{kind}: {error}"
            );
            assert!(
                !error.to_string().contains("realm_terminal_state"),
                "{kind}: {error}"
            );
        }
        for kind in ["ak.audit.accessed", "ak.audit.erasure_receipt"] {
            require_replica_live_in_connection(&mut conn, &event(kind))
                .await
                .unwrap();
        }
        #[derive(diesel::QueryableByName)]
        struct ValueRow {
            #[diesel(sql_type = Jsonb)]
            value: serde_json::Value,
        }
        let retained = diesel::sql_query("SELECT value FROM realm_bootstrap_current_results WHERE realm_id=$1 AND result_family='realm_tombstone'")
            .bind::<Text, _>(realm.as_str()).get_result::<ValueRow>(&mut *conn).await.unwrap();
        assert_eq!(retained.value, terminal);
    }
}
