//! Real PostgreSQL snapshot replacement and competing current-row writes.
use arkret_wire::{
    CommitStreamHead, CommitStreamRef, CurrentRevision, CurrentSelector, CurrentState,
};

use super::*;
use crate::test_database::TestDatabase;

async fn footprint(conn: &mut AsyncPgConnection, realm: &arkret_wire::RealmId) -> Value {
    #[derive(diesel::QueryableByName)]
    struct Row {
        #[diesel(sql_type = Jsonb)]
        value: Value,
    }
    diesel::sql_query(
        "SELECT jsonb_build_object( \
         'evidence',(SELECT jsonb_agg(to_jsonb(r) ORDER BY selector::text) FROM replica_authorization_rows r WHERE realm_id=$1), \
         'current',(SELECT jsonb_agg(to_jsonb(r) ORDER BY state_family) FROM realm_bootstrap_current_states r WHERE realm_id=$1), \
         'heads',(SELECT jsonb_agg(to_jsonb(r) ORDER BY source_stream_ref::text) FROM replica_authorization_cuts r WHERE realm_id=$1)) AS value",
    )
    .bind::<Text, _>(realm.as_str())
    .get_result::<Row>(conn)
    .await
    .unwrap()
    .value
}

fn entry(realm: &arkret_wire::RealmId, selector: CurrentSelector, value: Value) -> CurrentState {
    CurrentState::Value {
        selector,
        source_stream_ref: CommitStreamRef::Realm {
            realm_id: realm.clone(),
        },
        revision: CurrentRevision {
            commit_id: arkret_wire::RealmCommitId::from_digest([31; 32]),
            stream_position: 0,
        },
        value,
    }
}

#[tokio::test]
async fn snapshot_same_revision_conflicts_preserve_the_whole_installed_cut() {
    let database = TestDatabase::lease().await;
    let mut conn = database.pool().get().await.unwrap();
    let realm = arkret_wire::RealmId::from_event_id(&arkret_wire::EventId::from_digest(
        arkret_canonical::DigestSuite::Sha256,
        [30; 32],
    ));
    let at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    let rows = vec![
        entry(
            &realm,
            CurrentSelector::RealmJoinRule,
            serde_json::json!("open"),
        ),
        entry(
            &realm,
            CurrentSelector::RealmHistoryAccess,
            serde_json::json!("since_join"),
        ),
    ];
    let CurrentState::Value {
        source_stream_ref,
        revision,
        ..
    } = &rows[0];
    let head = CommitStreamHead {
        stream_ref: source_stream_ref.clone(),
        commit_id: revision.commit_id.clone(),
        stream_position: revision.stream_position,
    };
    install_snapshot_in_connection(&mut conn, &realm, &head, &rows, at)
        .await
        .unwrap();
    let before = footprint(&mut conn, &realm).await;
    for source_conflict in [false, true] {
        let mut candidates = rows.clone();
        // An earlier valid successor must also be rolled back with a bad sibling.
        let CurrentState::Value {
            revision, value, ..
        } = &mut candidates[0];
        revision.commit_id = arkret_wire::RealmCommitId::from_digest([32; 32]);
        revision.stream_position = 1;
        *value = serde_json::json!("closed");
        let new_head = CommitStreamHead {
            commit_id: revision.commit_id.clone(),
            stream_position: 1,
            ..head.clone()
        };
        let CurrentState::Value {
            source_stream_ref,
            value,
            ..
        } = &mut candidates[1];
        if source_conflict {
            *source_stream_ref = CommitStreamRef::Circle {
                realm_id: realm.clone(),
                circle_id: arkret_wire::CircleId::from_event_id(
                    &arkret_wire::EventId::from_digest(
                        arkret_canonical::DigestSuite::Sha256,
                        [33; 32],
                    ),
                ),
            };
        } else {
            *value = serde_json::json!("all_history_for_current_members");
        }
        diesel::sql_query("BEGIN")
            .execute(&mut *conn)
            .await
            .unwrap();
        let error = install_snapshot_in_connection(&mut conn, &realm, &new_head, &candidates, at)
            .await
            .unwrap_err();
        assert!(matches!(error, PersistenceError::Conflict(_)));
        assert_eq!(footprint(&mut conn, &realm).await, before);
        diesel::sql_query("ROLLBACK")
            .execute(&mut *conn)
            .await
            .unwrap();
        assert_eq!(footprint(&mut conn, &realm).await, before);
    }
    // Exact replay keeps canonical bytes; a genuine successor can replace them.
    install_snapshot_in_connection(&mut conn, &realm, &head, &rows, at)
        .await
        .unwrap();
    assert_eq!(footprint(&mut conn, &realm).await, before);
    let mut successor = rows.clone();
    for row in &mut successor {
        let CurrentState::Value { revision, .. } = row;
        revision.commit_id = arkret_wire::RealmCommitId::from_digest([32; 32]);
        revision.stream_position = 1;
    }
    let CurrentState::Value { value, .. } = &mut successor[1];
    *value = serde_json::json!("all_history_for_current_members");
    let next = CommitStreamHead {
        commit_id: arkret_wire::RealmCommitId::from_digest([32; 32]),
        stream_position: 1,
        ..head
    };
    install_snapshot_in_connection(&mut conn, &realm, &next, &successor, at)
        .await
        .unwrap();
    assert_ne!(footprint(&mut conn, &realm).await, before);
}

#[tokio::test]
async fn concurrent_same_revision_values_have_one_winner_and_exact_replay() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let mut first = pool.get().await.unwrap();
    let mut second = pool.get().await.unwrap();
    let realm = arkret_wire::RealmId::from_event_id(&arkret_wire::EventId::from_digest(
        arkret_canonical::DigestSuite::Sha256,
        [34; 32],
    ));
    let at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    let a = entry(
        &realm,
        CurrentSelector::RealmJoinRule,
        serde_json::json!("open"),
    );
    let b = entry(
        &realm,
        CurrentSelector::RealmJoinRule,
        serde_json::json!("closed"),
    );
    let (left, right) = tokio::join!(
        crate::replica_authorization::save_row(&mut first, &realm, &a, at),
        crate::replica_authorization::save_row(&mut second, &realm, &b, at),
    );
    assert_ne!(left.is_ok(), right.is_ok());
    let (winner, loser, failure) = if left.is_ok() {
        (&a, &b, right)
    } else {
        (&b, &a, left)
    };
    assert!(matches!(failure, Err(PersistenceError::Conflict(_))));
    let before = footprint(&mut first, &realm).await;
    crate::replica_authorization::save_row(&mut first, &realm, winner, at)
        .await
        .unwrap();
    assert_eq!(footprint(&mut first, &realm).await, before);
    assert!(
        crate::replica_authorization::save_row(&mut first, &realm, loser, at)
            .await
            .is_err()
    );
    let mut source_conflict = winner.clone();
    let CurrentState::Value {
        source_stream_ref, ..
    } = &mut source_conflict;
    *source_stream_ref = CommitStreamRef::Sidecar {
        realm_id: realm.clone(),
        sidecar_id: arkret_wire::SidecarId::from_event_id(&arkret_wire::EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            [35; 32],
        )),
    };
    assert!(
        crate::replica_authorization::save_row(&mut first, &realm, &source_conflict, at)
            .await
            .is_err()
    );
    assert_eq!(footprint(&mut first, &realm).await, before);
}

#[tokio::test]
async fn revision_integrity_guard_stays_bounded_with_unrelated_realms_and_hot_current() {
    use diesel_async::SimpleAsyncConnection as _;
    let database = TestDatabase::lease().await;
    let mut conn = database.pool().get().await.unwrap();
    let realm = arkret_wire::RealmId::from_event_id(&arkret_wire::EventId::from_digest(
        arkret_canonical::DigestSuite::Sha256,
        [36; 32],
    ));
    let at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    let current = entry(
        &realm,
        CurrentSelector::RealmJoinRule,
        serde_json::json!("open"),
    );
    crate::replica_authorization::save_row(&mut conn, &realm, &current, at)
        .await
        .unwrap();
    #[derive(diesel::QueryableByName)]
    struct Plan {
        #[diesel(column_name = "QUERY PLAN", sql_type = diesel::sql_types::Json)]
        value: Value,
    }
    fn visited(node: &Value) -> f64 {
        let own = if node["Relation Name"] == "replica_authorization_rows" {
            [
                "Actual Rows",
                "Rows Removed by Filter",
                "Rows Removed by Index Recheck",
            ]
            .iter()
            .filter_map(|key| node[key].as_f64())
            .sum::<f64>()
                * node["Actual Loops"].as_f64().unwrap_or(1.0)
        } else {
            0.0
        };
        own + node["Plans"]
            .as_array()
            .into_iter()
            .flatten()
            .map(visited)
            .sum::<f64>()
    }
    // Selector probes must not scan the rest of a hot Realm or other Realms.
    for (realms, hot_width) in [(1, 1000), (100, 2000), (1000, 10000)] {
        conn.batch_execute(&format!(
            "INSERT INTO replica_authorization_rows(realm_id,selector,source_stream_ref,current_commit_id,current_stream_position,value,updated_at) \
             SELECT CASE WHEN r=1 THEN '{}' ELSE 'unrelated-realm-'||r END, \
               jsonb_build_object('unrelated_selector',n), \
               jsonb_build_object('kind','realm','realm_id','unrelated-realm-'||r),'unrelated',0,'null',now() \
             FROM generate_series(1,{realms}) r, generate_series(1,20) n ON CONFLICT DO NOTHING; \
             INSERT INTO replica_authorization_rows(realm_id,selector,source_stream_ref,current_commit_id,current_stream_position,value,updated_at) \
             SELECT '{}',jsonb_build_object('hot_selector',n),jsonb_build_object('kind','realm','realm_id','{}'),'unrelated',0,'null',now() \
             FROM generate_series(1,{hot_width}) n ON CONFLICT DO NOTHING; ANALYZE replica_authorization_rows;",
            realm.as_str(), realm.as_str(), realm.as_str(),
        )).await.unwrap();
        let plan = diesel::sql_query(format!(
            "EXPLAIN (ANALYZE, FORMAT JSON) {}",
            crate::replica_authorization::CURRENT_REVISION_GUARD_SQL
        ))
        .bind::<Text, _>(realm.as_str())
        .bind::<Jsonb, _>(serde_json::to_value([&current]).unwrap())
        .get_result::<Plan>(&mut *conn)
        .await
        .unwrap()
        .value;
        let rows = visited(&plan[0]["Plan"]);
        assert!(rows <= 8.0, "integrity guard scanned {rows} rows: {plan}");
        println!(
            "current integrity realms={realms} hot_width={hot_width} visited={rows} plan={plan}"
        );
        crate::replica_authorization::guard_current_rows(
            &mut conn,
            &realm,
            std::slice::from_ref(&current),
        )
        .await
        .unwrap();
    }
}
