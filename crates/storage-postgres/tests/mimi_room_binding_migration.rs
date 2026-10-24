//! MIMI binding lineage is decided by the real PostgreSQL authority unit.
#[path = "support/ordinary_realm.rs"]
#[allow(dead_code)]
mod ordinary_realm;
use arkret_wire::EventKind;
use coland_storage::{AuthorityCommitStore, EventCommitRequest, EventCommitUnitOfWork};
use coland_storage_postgres::PgEventCommitUnitOfWork;
use coland_storage_postgres::test_database::TestDatabase;
use diesel::sql_types::{BigInt, Text};
use diesel_async::RunQueryDsl;
use serde_json::{Value, json};

#[derive(diesel::QueryableByName, Debug, PartialEq)]
struct Counts {
    #[diesel(sql_type=BigInt)]
    events: i64,
    #[diesel(sql_type=BigInt)]
    commits: i64,
    #[diesel(sql_type=BigInt)]
    bindings: i64,
    #[diesel(sql_type=BigInt)]
    outbox: i64,
}
async fn counts(pool: &coland_storage_postgres::PgPool, realm: &str) -> Counts {
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query("SELECT (SELECT count(*) FROM canonical_events WHERE realm_id=$1) AS events,(SELECT count(*) FROM realm_commits WHERE realm_id=$1) AS commits,(SELECT count(*) FROM mimi_room_binding_current_states WHERE realm_id=$1) AS bindings,(SELECT count(*) FROM federation_outbox) AS outbox")
        .bind::<Text,_>(realm).get_result(&mut conn).await.unwrap()
}
async fn next(
    pool: &coland_storage_postgres::PgPool,
    previous: &EventCommitRequest,
    payload: Value,
) -> EventCommitRequest {
    let request = ordinary_realm::next_request_for_actor(
        &previous.authority_commit,
        EventKind::MimiRoomBinding,
        previous.authority_commit.event.actor_id.clone(),
        payload,
        previous.authority_commit.commit.committed_at,
    );
    ordinary_realm::source_request(pool, request).await
}

#[tokio::test]
async fn completed_and_rolled_back_use_exact_lineage_and_topology_at_cut() {
    for outcome in ["completed", "rolled_back"] {
        let database = TestDatabase::lease().await;
        let pool = database.pool();
        let discussion =
            ordinary_realm::open_discussion(&pool, &format!("mimi-migration-{outcome}")).await;
        let realm = discussion.realm_id();
        let uow = PgEventCommitUnitOfWork::new(pool.clone());
        let original = json!({"profile":"ak.profile.mimi_interop.v1",
            "mimi_room_uri":format!("mimi://ordinary-station.example/rooms/{outcome}"),
            "binding_scope":{"realm_id":realm,"strand_id":discussion.strand_id},
            "hub_provider_id":"ak:did_core:web:first-hub.example","local_provider_role":"hub","status":"accepted"});
        let accepted = next(&pool, &discussion.head, original.clone()).await;
        uow.commit_event(accepted.clone()).await.unwrap();
        let mut candidate = original.clone();
        candidate["status"] = json!("migrating");
        candidate["hub_provider_id"] = json!("ak:did_core:web:next-hub.example");
        let migrating = next(&pool, &accepted, candidate.clone()).await;
        uow.commit_event(migrating.clone()).await.unwrap();
        let mut resolved = if outcome == "completed" {
            candidate
        } else {
            original
        };
        resolved["status"] = json!("accepted");
        resolved["migration_outcome"] = json!(outcome);
        resolved["migration_proof"] = json!({
            "previous_accepted_event_id":accepted.authority_commit.event.event_id,
            "previous_accepted_commit_id":accepted.authority_commit.commit.commit_id,
            "migrating_event_id":migrating.authority_commit.event.event_id,
            "migrating_commit_id":migrating.authority_commit.commit.commit_id});
        for mutation in [
            "stale_migrating_commit",
            "wrong_selected_topology",
            "unaccepted_group_info",
        ] {
            let mut invalid = resolved.clone();
            match mutation {
                "stale_migrating_commit" => {
                    invalid["migration_proof"]["migrating_commit_id"] =
                        json!(accepted.authority_commit.commit.commit_id)
                }
                "wrong_selected_topology" => {
                    invalid["hub_provider_id"] = json!("ak:did_core:web:unrelated-hub.example")
                }
                _ => {
                    invalid["mls_group_id"] = json!(
                        arkret_wire::ScopeRef::Realm {
                            realm_id: realm.clone()
                        }
                        .canonical_mls_group_id()
                        .unwrap()
                    )
                }
            }
            let before = counts(&pool, realm.as_str()).await;
            assert!(
                uow.commit_event(next(&pool, &migrating, invalid).await)
                    .await
                    .is_err(),
                "{mutation}"
            );
            assert_eq!(
                counts(&pool, realm.as_str()).await,
                before,
                "{mutation} must roll back all effects"
            );
        }
        uow.commit_event(next(&pool, &migrating, resolved).await)
            .await
            .unwrap();
        let mut conn = pool.get().await.unwrap();
        #[derive(diesel::QueryableByName)]
        struct Current {
            #[diesel(sql_type=diesel::sql_types::Jsonb)]
            value: Value,
        }
        let row: Current = diesel::sql_query(
            "SELECT value FROM mimi_room_binding_current_states WHERE realm_id=$1",
        )
        .bind::<Text, _>(realm.as_str())
        .get_result(&mut conn)
        .await
        .unwrap();
        assert_eq!(row.value["status"], "accepted");
        assert_eq!(row.value["migration_outcome"], outcome);
        drop(conn);
        let store = coland_storage_postgres::PgAuthorityCommitStore { pool: pool.clone() };
        let uri = arkret_wire::MimiRoomUri::new(format!(
            "mimi://ordinary-station.example/rooms/{outcome}"
        ))
        .unwrap();
        let record = store
            .current_mimi_room_binding(&uri)
            .await
            .unwrap()
            .unwrap();
        record.current.validate().unwrap();
        assert_eq!(
            record.current.source_stream_ref,
            accepted.authority_commit.commit.stream_ref
        );
        assert_eq!(record.current.source_stream_ref.realm_id(), &realm);
        assert_eq!(record.current.selector.mimi_room_uri, uri);
        let mut conn = pool.get().await.unwrap();
        diesel::sql_query("UPDATE mimi_room_binding_current_states SET current_stream_position=current_stream_position+1 WHERE mimi_room_uri=$1")
            .bind::<Text, _>(uri.as_str()).execute(&mut conn).await.unwrap();
        drop(conn);
        assert!(
            store.current_mimi_room_binding(&uri).await.is_err(),
            "a missing exact covering Commit must fail instead of manufacturing a stream ref"
        );
    }
}
