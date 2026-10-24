//! Production Poll admission and projection atomicity on real PostgreSQL.
#[path = "support/ordinary_realm.rs"]
#[allow(dead_code)]
mod ordinary_realm;

use coland_storage::{EventCommitRequest, EventCommitUnitOfWork};
use coland_storage_postgres::test_database::TestDatabase;
use coland_storage_postgres::{PgEventCommitUnitOfWork, PgPool};
use diesel::sql_types::{BigInt, Jsonb, Text};
use diesel_async::{RunQueryDsl, SimpleAsyncConnection};
use serde_json::{Value, json};

#[derive(diesel::QueryableByName)]
struct Footprint {
    #[diesel(sql_type = Jsonb)]
    value: Value,
}

async fn footprint(pool: &PgPool) -> Value {
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query("SELECT jsonb_build_object('events',(SELECT count(*) FROM canonical_events), 'commits',(SELECT count(*) FROM realm_commits), 'messages',(SELECT count(*) FROM message_revision_current_states), 'votes',(SELECT count(*) FROM poll_response_inputs), 'outbox',(SELECT count(*) FROM federation_outbox)) AS value")
        .get_result::<Footprint>(&mut *conn).await.unwrap().value
}

fn definition(discussion: &ordinary_realm::Discussion) -> Value {
    json!({"strand_id":discussion.strand_id,"track_name":"discussion","content":{
        "kind":"ak.content.poll","body":"Choose","poll":{"kind":"disclosed","max_selection_count":1,
        "answers":[{"id":"a","text":{"kind":"ak.content.text","body":"A"}},
        {"id":"b","text":{"kind":"ak.content.text","body":"B"}}]}}})
}

fn response(
    discussion: &ordinary_realm::Discussion,
    poll: &EventCommitRequest,
    selections: Value,
) -> Value {
    json!({"strand_id":discussion.strand_id,"track_name":"discussion","content":{
        "kind":"ak.content.poll.response","body":"Vote","poll_response":{
        "poll_ref":arkret_wire::MessageId::from_event_id(&poll.authority_commit.event.event_id),"selections":selections}}})
}

#[derive(diesel::QueryableByName)]
struct CurrentVote {
    #[diesel(sql_type = Text)]
    response_event_id: String,
    #[diesel(sql_type = BigInt)]
    stream_position: i64,
    #[diesel(sql_type = Jsonb)]
    selections: Value,
}

#[tokio::test]
async fn votes_keep_canonical_history_without_message_rows_and_commit_position_wins() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let discussion = ordinary_realm::open_human_discussion(&pool, "poll-current").await;
    let actor = discussion
        .head
        .authority_commit
        .event
        .actor_id
        .signing_principal_id()
        .clone();
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let at = discussion.committed_at() + chrono::Duration::seconds(30);
    let poll = ordinary_realm::next_request(
        &discussion.head.authority_commit,
        arkret_wire::EventKind::MessageCreate,
        &actor,
        definition(&discussion),
        at,
    );
    let poll = ordinary_realm::source_request(&pool, poll).await;
    uow.commit_event(poll.clone()).await.unwrap();
    let first = ordinary_realm::next_request(
        &poll.authority_commit,
        arkret_wire::EventKind::MessageCreate,
        &actor,
        response(&discussion, &poll, json!(["a"])),
        at + chrono::Duration::seconds(2),
    );
    let first = ordinary_realm::source_request(&pool, first).await;
    uow.commit_event(first.clone()).await.unwrap();
    let mut payload = response(&discussion, &poll, json!(["b"]));
    payload["poll_response_heads"] = json!([{"poll_event_ref":poll.authority_commit.event.event_id,
        "response_event_ref":first.authority_commit.event.event_id}]);
    let mut second_event = ordinary_realm::event(
        arkret_wire::EventKind::MessageCreate,
        poll.authority_commit.event.scope_ref.clone(),
        &actor,
        &ordinary_realm::station(),
        payload,
        at - chrono::Duration::seconds(1),
    );
    ordinary_realm::reseal(&mut second_event);
    let second = ordinary_realm::request_for_event(
        &first.authority_commit,
        second_event,
        at + chrono::Duration::seconds(3),
    );
    // `reseal` updates the content address using a structural proof. Restore
    // the accepted device signature only after the final signed body is set.
    let second = ordinary_realm::source_request(&pool, second).await;
    uow.commit_event(second.clone()).await.unwrap();
    let before = footprint(&pool).await;
    uow.commit_event(first.clone()).await.unwrap();
    uow.commit_event(second.clone()).await.unwrap();
    assert_eq!(
        footprint(&pool).await,
        before,
        "exact replay writes no second vote input"
    );
    assert_eq!(before["votes"], 2);
    assert_eq!(
        before["messages"], 1,
        "only the poll definition is a MessageState"
    );
    let mut conn = pool.get().await.unwrap();
    let vote = diesel::sql_query("SELECT response_event_id,stream_position,selections FROM poll_state_current_votes WHERE realm_id=$1")
        .bind::<Text,_>(discussion.realm_id().as_str()).get_result::<CurrentVote>(&mut *conn).await.unwrap();
    assert_eq!(
        vote.response_event_id,
        second.authority_commit.event.event_id.as_str()
    );
    assert_eq!(
        vote.stream_position as u64,
        second.authority_commit.commit.stream_position
    );
    assert_eq!(vote.selections, json!(["b"]));
}

#[tokio::test]
async fn semantic_refusals_and_poll_projection_fault_roll_back_the_whole_commit() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let discussion = ordinary_realm::open_human_discussion(&pool, "poll-atomic").await;
    let actor = discussion
        .head
        .authority_commit
        .event
        .actor_id
        .signing_principal_id()
        .clone();
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let at = discussion.committed_at() + chrono::Duration::seconds(30);
    let poll = ordinary_realm::next_request(
        &discussion.head.authority_commit,
        arkret_wire::EventKind::MessageCreate,
        &actor,
        definition(&discussion),
        at,
    );
    let poll = ordinary_realm::source_request(&pool, poll).await;
    uow.commit_event(poll.clone()).await.unwrap();
    let before = footprint(&pool).await;
    let mut wrong_head = response(&discussion, &poll, json!(["a"]));
    wrong_head["poll_response_heads"] = json!([{"poll_event_ref":poll.authority_commit.event.event_id,
        "response_event_ref":poll.authority_commit.event.event_id}]);
    let mut wrong_poll = response(&discussion, &poll, json!(["a"]));
    wrong_poll["content"]["poll_response"]["poll_ref"] = json!(
        arkret_wire::MessageId::from_event_id(&discussion.head.authority_commit.event.event_id)
    );
    for payload in [
        response(&discussion, &poll, json!(["unknown"])),
        response(&discussion, &poll, json!(["a", "b"])),
        wrong_head,
        wrong_poll,
    ] {
        let request = ordinary_realm::next_request(
            &poll.authority_commit,
            arkret_wire::EventKind::MessageCreate,
            &actor,
            payload,
            at + chrono::Duration::seconds(1),
        );
        let request = ordinary_realm::source_request(&pool, request).await;
        let error = uow.commit_event(request).await.unwrap_err();
        assert!(
            matches!(error, coland_storage::PersistenceError::Conflict(_)),
            "{error}"
        );
        assert_eq!(
            footprint(&pool).await,
            before,
            "semantic refusal has zero durable side effects"
        );
    }
    let mut conn = pool.get().await.unwrap();
    conn.batch_execute("CREATE FUNCTION poll_projection_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'poll projection fault'; END $$; CREATE TRIGGER poll_projection_fault BEFORE INSERT ON poll_response_inputs FOR EACH ROW EXECUTE FUNCTION poll_projection_fault();").await.unwrap();
    drop(conn);
    let request = ordinary_realm::next_request(
        &poll.authority_commit,
        arkret_wire::EventKind::MessageCreate,
        &actor,
        response(&discussion, &poll, json!(["a"])),
        at + chrono::Duration::seconds(2),
    );
    let request = ordinary_realm::source_request(&pool, request).await;
    let result = uow.commit_event(request.clone()).await;
    let mut conn = pool.get().await.unwrap();
    conn.batch_execute("DROP TRIGGER poll_projection_fault ON poll_response_inputs; DROP FUNCTION poll_projection_fault();").await.unwrap();
    drop(conn);
    assert!(
        result.is_err(),
        "a projection fault cannot publish its canonical Event/Commit"
    );
    assert_eq!(footprint(&pool).await, before);
    uow.commit_event(request).await.unwrap();
    assert_eq!(
        footprint(&pool).await["votes"],
        1,
        "the rollback released the same stream position"
    );
}
