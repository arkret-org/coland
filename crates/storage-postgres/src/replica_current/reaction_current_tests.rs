//! Durable Reaction baseline and tail tests against real PostgreSQL rows.
//! Native signature/target admission is an input to this storage boundary;
//! these tests do not claim that installing a fixture verifies its signers.

use super::*;
use crate::test_database::TestDatabase;

fn fixture() -> Value {
    arkret_schema_conformance::spec_json_artifact("fixtures/reaction-authority-order-fixture.json")
        .expect("the pinned Reaction fixture must be available")
}

fn source(fixture: &Value, index: usize) -> (arkret_wire::Event, arkret_wire::RealmCommit) {
    let row = &fixture["original_rows"][index];
    (
        serde_json::from_value(row["event"].clone()).unwrap(),
        serde_json::from_value(row["commit"].clone()).unwrap(),
    )
}

fn checkpoint(
    fixture: &Value,
    index: usize,
) -> (
    arkret_wire::RealmId,
    arkret_wire::CommitStreamHead,
    Vec<arkret_wire::CurrentState>,
) {
    let cut = &fixture["checkpoints"][index];
    let realm = serde_json::from_value(cut["realm_id"].clone()).unwrap();
    let head: arkret_wire::CommitStreamHead =
        serde_json::from_value(cut["visible_stream_heads"][0].clone()).unwrap();
    let mut rows: Vec<arkret_wire::CurrentState> =
        serde_json::from_value(cut["current_state_entries"].clone()).unwrap();
    // The fixture explicitly supplies target existence as a trusted native
    // fact. Represent its visible current baseline without adding a local
    // original Event or pretending this row is a complete signed Snapshot.
    rows.push(arkret_wire::CurrentState::Value {
        selector: arkret_wire::CurrentSelector::MessageRevision {
            message_id: serde_json::from_value(fixture["trusted_basis"]["target_ref"].clone()).unwrap(),
        },
        source_stream_ref: head.stream_ref.clone(),
        revision: arkret_wire::CurrentRevision {
            commit_id: serde_json::from_value(fixture["trusted_basis"]["commit_id"].clone()).unwrap(),
            stream_position: 0,
        },
        value: serde_json::json!({"strand_id": arkret_wire::StrandId::from_event_id(&arkret_wire::EventId::from_digest(arkret_canonical::DigestSuite::Sha256,[91;32]))}),
    });
    (realm, head, rows)
}

#[derive(diesel::QueryableByName)]
struct ValueRow {
    #[diesel(sql_type = Jsonb)]
    value: Value,
}

async fn footprint(conn: &mut AsyncPgConnection, realm: &arkret_wire::RealmId) -> Value {
    diesel::sql_query("SELECT jsonb_build_object('reactions',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY target_ref),'[]') FROM message_reactions_current_states r WHERE realm_id=$1),'messages',(SELECT coalesce(jsonb_agg(to_jsonb(m) ORDER BY message_id),'[]') FROM message_revision_current_states m WHERE realm_id=$1),'cuts',(SELECT coalesce(jsonb_agg(to_jsonb(c) ORDER BY source_stream_ref::text),'[]') FROM replica_authorization_cuts c WHERE realm_id=$1),'rows',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY selector::text),'[]') FROM replica_authorization_rows r WHERE realm_id=$1)) AS value")
        .bind::<Text,_>(realm.as_str()).get_result::<ValueRow>(conn).await.unwrap().value
}

async fn reaction(conn: &mut AsyncPgConnection, realm: &arkret_wire::RealmId) -> Value {
    diesel::sql_query("SELECT jsonb_build_object('revision',jsonb_build_object('commit_id',current_commit_id,'stream_position',current_stream_position),'value',value,'source_stream_ref',source_stream_ref) AS value FROM message_reactions_current_states WHERE realm_id=$1")
        .bind::<Text,_>(realm.as_str()).get_result::<ValueRow>(conn).await.unwrap().value
}

async fn rejected_tail(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    commit: &arkret_wire::RealmCommit,
) -> String {
    let before = footprint(conn, &event.realm_id).await;
    diesel::sql_query("BEGIN")
        .execute(&mut *conn)
        .await
        .unwrap();
    let error = advance_in_connection(conn, event, commit)
        .await
        .unwrap_err()
        .to_string();
    diesel::sql_query("ROLLBACK")
        .execute(&mut *conn)
        .await
        .unwrap();
    assert_eq!(footprint(conn, &event.realm_id).await, before);
    error
}

#[tokio::test]
async fn reaction_snapshot_needs_no_old_original_and_contiguous_tail_deletes_without_tombstones() {
    let database = TestDatabase::lease().await;
    let mut conn = database.pool().get().await.unwrap();
    let fixture = fixture();
    let (add, add_commit) = source(&fixture, 0);
    let (remove, remove_commit) = source(&fixture, 1);
    let (again, again_commit) = source(&fixture, 2);
    let (_, gap) = source(&fixture, 3);
    assert!(
        rejected_tail(&mut conn, &add, &add_commit)
            .await
            .contains("dependency_missing")
    );
    let (realm, head, rows) = checkpoint(&fixture, 0);
    install_snapshot_in_connection(&mut conn, &realm, &head, &rows, head_time(&fixture))
        .await
        .unwrap();
    let before = reaction(&mut conn, &realm).await;
    assert_eq!(before["value"]["entries"].as_array().unwrap().len(), 1);
    // No canonical_events or realm_commits were inserted: the active source
    // can predate the readable floor and is consumed as authenticated metadata.
    advance_in_connection(&mut conn, &remove, &remove_commit)
        .await
        .unwrap();
    let empty = reaction(&mut conn, &realm).await;
    assert_eq!(empty["value"], serde_json::json!({"entries":[]}));
    assert_eq!(
        empty["revision"]["commit_id"],
        serde_json::json!(remove_commit.commit_id)
    );
    assert!(
        rejected_tail(&mut conn, &add, &add_commit)
            .await
            .contains("next installed Commit")
    );
    let (gap_event, _) = source(&fixture, 3);
    assert!(
        rejected_tail(&mut conn, &gap_event, &gap)
            .await
            .contains("next installed Commit")
    );
    advance_in_connection(&mut conn, &again, &again_commit)
        .await
        .unwrap();
    let active = reaction(&mut conn, &realm).await;
    assert_eq!(active["value"]["entries"].as_array().unwrap().len(), 1);
    assert_eq!(
        active["value"]["entries"][0]["source"]["event_id"],
        serde_json::json!(again.event_id)
    );
    assert_eq!(
        active["source_stream_ref"],
        serde_json::json!(again_commit.stream_ref)
    );
}

fn head_time(fixture: &Value) -> chrono::DateTime<chrono::Utc> {
    serde_json::from_value(fixture["original_rows"][0]["commit"]["committed_at"].clone()).unwrap()
}

#[tokio::test]
async fn reaction_snapshot_guards_old_rows_under_new_heads_and_exact_value_equivocation() {
    let database = TestDatabase::lease().await;
    let mut conn = database.pool().get().await.unwrap();
    let fixture = fixture();
    let (realm, head, rows) = checkpoint(&fixture, 2);
    install_snapshot_in_connection(&mut conn, &realm, &head, &rows, head_time(&fixture))
        .await
        .unwrap();
    let before = footprint(&mut conn, &realm).await;
    let (_, newer, _) = checkpoint(&fixture, 3);
    let (_, _, older) = checkpoint(&fixture, 0);
    let mut cases = vec![older];
    let mut equivocation = rows.clone();
    let arkret_wire::CurrentState::Value { value, .. } = &mut equivocation[0];
    value["entries"][0]["key"] = serde_json::json!("changed");
    cases.push(equivocation);
    let mut partial = rows.clone();
    partial.pop();
    cases.push(partial);
    let mut future_source = rows.clone();
    let arkret_wire::CurrentState::Value { value, .. } = &mut future_source[0];
    value["entries"][0]["source"]["stream_position"] = serde_json::json!(newer.stream_position + 1);
    cases.push(future_source);
    for candidate in cases {
        diesel::sql_query("BEGIN")
            .execute(&mut *conn)
            .await
            .unwrap();
        assert!(
            install_snapshot_in_connection(
                &mut conn,
                &realm,
                &newer,
                &candidate,
                head_time(&fixture)
            )
            .await
            .is_err()
        );
        diesel::sql_query("ROLLBACK")
            .execute(&mut *conn)
            .await
            .unwrap();
        assert_eq!(footprint(&mut conn, &realm).await, before);
    }
}

#[tokio::test]
async fn undisclosed_old_targets_require_a_new_visible_baseline_instead_of_assuming_empty() {
    let database = TestDatabase::lease().await;
    let mut conn = database.pool().get().await.unwrap();
    let fixture = fixture();
    let (realm, head, rows) = checkpoint(&fixture, 1);
    install_snapshot_in_connection(&mut conn, &realm, &head, &[], head_time(&fixture))
        .await
        .unwrap();
    let (event, commit) = source(&fixture, 2);
    assert!(
        rejected_tail(&mut conn, &event, &commit)
            .await
            .contains("complete visible current Snapshot baseline")
    );
    // Once the authority supplies the full, visible target/current baseline,
    // no pre-floor add Event is requested and the same successor can proceed.
    install_snapshot_in_connection(&mut conn, &realm, &head, &rows, head_time(&fixture))
        .await
        .unwrap();
    advance_in_connection(&mut conn, &event, &commit)
        .await
        .unwrap();
    assert_eq!(
        reaction(&mut conn, &realm).await["value"]["entries"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
}
