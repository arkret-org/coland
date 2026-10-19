//! Real durable Snapshot replacement, using the normative Call transcripts.
use diesel_async::SimpleAsyncConnection;

use super::*;
use crate::test_database::TestDatabase;

fn fixture() -> Value {
    arkret_schema_conformance::spec_json_artifact("fixtures/call-current-fixture.json")
        .expect("the pinned Call fixture must be available")
}
fn checkpoint(
    fixture: &Value,
    index: usize,
    axes: &[&str],
) -> (
    arkret_wire::RealmId,
    arkret_wire::CommitStreamHead,
    Vec<arkret_wire::TypedCurrentRow>,
) {
    let snapshot = &fixture["checkpoints"][index];
    let rows = snapshot["current_state_entries"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|row| axes.contains(&row["selector"]["kind"].as_str().unwrap()))
        .cloned()
        .map(|row| serde_json::from_value(row).unwrap())
        .collect();
    (
        serde_json::from_value(snapshot["realm_id"].clone()).unwrap(),
        serde_json::from_value(snapshot["visible_stream_heads"][0].clone()).unwrap(),
        rows,
    )
}
#[derive(diesel::QueryableByName)]
struct Footprint {
    #[diesel(sql_type=Jsonb)]
    value: Value,
}
async fn footprint(conn: &mut AsyncPgConnection) -> Value {
    diesel::sql_query("SELECT jsonb_build_object('axes',(SELECT COALESCE(jsonb_agg(to_jsonb(c) ORDER BY realm_id,call_id,selector),'[]') FROM call_component_current_results c),'cuts',(SELECT COALESCE(jsonb_agg(to_jsonb(c) ORDER BY realm_id),'[]') FROM replica_authorization_cuts c),'rows',(SELECT COALESCE(jsonb_agg(to_jsonb(c) ORDER BY realm_id,selector),'[]') FROM replica_authorization_rows c),'keys',(SELECT COALESCE(jsonb_agg(to_jsonb(c) ORDER BY realm_id,call_id,source_commit_id),'[]') FROM call_participant_issuer_sources c)) AS value")
        .get_result::<Footprint>(&mut *conn).await.unwrap().value
}

#[tokio::test]
async fn empty_call_axes_recover_exact_last_sources_and_refuse_partial_forked_replacement() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let mut conn = pool.get().await.unwrap();
    let fixture = fixture();
    let at = chrono::Utc::now();
    let (realm, head, rows) = checkpoint(&fixture, 5, &["call_state", "call_moderation"]);
    install_snapshot_in_connection(&mut conn, &realm, &head, &rows, at)
        .await
        .unwrap();
    let (realm, head, rows) = checkpoint(
        &fixture,
        9,
        &["call_state", "call_roster", "call_moderation"],
    );
    for _ in 0..2 {
        install_snapshot_in_connection(&mut conn, &realm, &head, &rows, at)
            .await
            .unwrap();
    }
    let before = footprint(&mut conn).await;
    let mut cases = Vec::new();
    cases.push(
        rows.iter()
            .filter(|row| {
                !matches!(
                    row,
                    arkret_wire::TypedCurrentRow::Value {
                        selector: arkret_wire::CurrentSelector::CallRoster { .. },
                        ..
                    }
                )
            })
            .cloned()
            .collect::<Vec<_>>(),
    );
    for mutation in [
        "wrong_dot",
        "omitted_kick",
        "changed_source",
        "legacy_assertions",
    ] {
        let mut changed = rows.clone();
        let arkret_wire::TypedCurrentRow::Value { value, .. } = changed
            .iter_mut()
            .find(|row| {
                matches!(
                    row,
                    arkret_wire::TypedCurrentRow::Value {
                        selector: arkret_wire::CurrentSelector::CallModeration { .. },
                        ..
                    }
                )
            })
            .unwrap();
        match mutation {
            "wrong_dot" => value["last_source"]["tag_id"] = serde_json::json!("wrong:6"),
            "omitted_kick" => value["entries"] = serde_json::json!([]),
            "changed_source" => {
                value["last_source"]["source_commit"]["stream_position"] = serde_json::json!(99)
            }
            _ => *value = serde_json::json!({"assertions":[]}),
        }
        cases.push(changed);
    }
    for changed in cases {
        conn.batch_execute("BEGIN").await.unwrap();
        assert!(
            install_snapshot_in_connection(&mut conn, &realm, &head, &changed, at)
                .await
                .is_err()
        );
        conn.batch_execute("ROLLBACK").await.unwrap();
        assert_eq!(footprint(&mut conn).await, before);
    }
    drop(conn);
    let mut reopened = pool.get().await.unwrap();
    assert_eq!(footprint(&mut reopened).await, before);
    let roster = diesel::sql_query(
        "SELECT value FROM call_component_current_results WHERE selector->>'kind'='call_roster'",
    )
    .get_result::<Footprint>(&mut reopened)
    .await
    .unwrap()
    .value;
    assert_eq!(roster["entries"], serde_json::json!([]));
    assert_eq!(
        roster["last_source"]["source_commit"],
        fixture["original_rows"][9]["commit"]
    );
}

#[tokio::test]
async fn snapshot_binding_key_without_independent_native_authority_is_unavailable_and_atomic() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let mut conn = pool.get().await.unwrap();
    let fixture = fixture();
    let (realm, head, rows) = checkpoint(
        &fixture,
        10,
        &["call_state", "call_roster", "call_moderation"],
    );
    let before = footprint(&mut conn).await;
    conn.batch_execute("BEGIN").await.unwrap();
    let error = install_snapshot_in_connection(&mut conn, &realm, &head, &rows, chrono::Utc::now())
        .await
        .unwrap_err();
    assert!(error.to_string().contains("native history"), "{error}");
    conn.batch_execute("ROLLBACK").await.unwrap();
    assert_eq!(footprint(&mut conn).await, before);
}
