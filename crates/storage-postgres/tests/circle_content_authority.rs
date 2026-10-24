//! Circle-scoped Strand and plaintext Poll use the signed Circle source and
//! confirmed membership at the accepting PostgreSQL transaction cut.
#[path = "support/ordinary_realm.rs"]
#[allow(dead_code)]
mod ordinary_realm;

use arkret_wire::{
    CircleId, CommitStreamRef, CurrentSelector, CurrentState, EventKind, MessageId, ScopeRef,
    StrandId,
};
use coland_storage::{
    AuthorityCommitStore, AuthorityCommitTransaction, EventCommitRequest, EventCommitUnitOfWork,
    EventProjectionStoreRegistry,
};
use coland_storage_postgres::test_database::TestDatabase;
use coland_storage_postgres::{PgAuthorityCommitStore, PgEventCommitUnitOfWork, PgPool};
use diesel::sql_types::BigInt;
use diesel_async::RunQueryDsl;
use serde_json::{Value, json};

#[derive(diesel::QueryableByName)]
struct Counts {
    #[diesel(sql_type = BigInt)]
    events: i64,
    #[diesel(sql_type = BigInt)]
    commits: i64,
    #[diesel(sql_type = BigInt)]
    strands: i64,
    #[diesel(sql_type = BigInt)]
    messages: i64,
    #[diesel(sql_type = BigInt)]
    votes: i64,
}

async fn counts(pool: &PgPool) -> (i64, i64, i64, i64, i64) {
    let mut conn = pool.get().await.unwrap();
    let row = diesel::sql_query(
        "SELECT (SELECT count(*) FROM canonical_events) AS events, \
        (SELECT count(*) FROM realm_commits) AS commits, \
        (SELECT count(*) FROM strand_current_states) AS strands, \
        (SELECT count(*) FROM message_revision_current_states) AS messages, \
        (SELECT count(*) FROM poll_response_inputs) AS votes",
    )
    .get_result::<Counts>(&mut *conn)
    .await
    .unwrap();
    (
        row.events,
        row.commits,
        row.strands,
        row.messages,
        row.votes,
    )
}

fn circle_request(
    previous: &AuthorityCommitTransaction,
    circle: &CircleId,
    kind: EventKind,
    payload: Value,
) -> EventCommitRequest {
    let mut event = ordinary_realm::event_for_actor(
        kind,
        ScopeRef::Circle {
            realm_id: previous.event.realm_id.clone(),
            circle_id: circle.clone(),
        },
        previous.event.actor_id.clone(),
        payload,
        previous.commit.committed_at,
    );
    ordinary_realm::bind_structural_human_device(&mut event);
    let mut request =
        ordinary_realm::request_for_event(previous, event, previous.commit.committed_at);
    let stream = CommitStreamRef::Circle {
        realm_id: previous.event.realm_id.clone(),
        circle_id: circle.clone(),
    };
    if previous.commit.stream_ref != stream {
        request.authority_commit.commit.stream_position = 0;
        request.authority_commit.commit.previous_commit_ref = None;
    }
    request.authority_commit.commit.stream_ref = stream;
    ordinary_realm::seal_final_commit(&mut request.authority_commit.commit);
    request.realm_fanout_source = Some(arkret_wire::EventAdmissionSubmission::new(
        request.authority_commit.event.clone(),
    ));
    request
}

#[tokio::test]
async fn circle_strand_and_plaintext_poll_require_exact_scope_and_current_membership() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let discussion =
        ordinary_realm::open_discussion(&pool, &uuid::Uuid::now_v7().to_string()).await;
    let root = &discussion.head.authority_commit;
    let realm = root.event.realm_id.clone();
    let actor = root.event.actor_id.clone();
    let at = root.commit.committed_at;
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    let uow = PgEventCommitUnitOfWork::new(pool.clone());

    let absent = CircleId::from_event_id(&arkret_wire::EventId::from_digest(
        arkret_canonical::DigestSuite::Sha256,
        [42; 32],
    ));
    let unknown = circle_request(
        root,
        &absent,
        EventKind::StrandCreate,
        json!({"object":{"schema":"ak.schema.strand.v1","realm_id":realm,
            "scope_circle_id":absent,"tracks":{"discussion":{"is_primary":true,"profile":"discussion"}},
            "metadata":{"title":"Unknown Circle"},"state":"active","created_by":actor,
            "created_at":arkret_canonical::format_timestamp_canonical(at)}}),
    );
    let baseline = counts(&pool).await;
    let refused = uow.commit_event(unknown.clone()).await.unwrap_err();
    assert!(
        matches!(refused, coland_storage::PersistenceError::Conflict(ref detail)
        if detail == "failed_precondition: circle_not_active"),
        "{refused:?}"
    );
    assert_eq!(counts(&pool).await, baseline);
    assert!(
        store
            .committed_event(&unknown.authority_commit.event.event_id)
            .await
            .unwrap()
            .is_none()
    );

    let create = ordinary_realm::next_request_for_actor(
        root,
        EventKind::CircleCreate,
        actor.clone(),
        json!({"object":{"schema":"ak.schema.circle.v1","realm_id":realm,
            "title":"Poll Circle","display":{"short_name":"Poll","color_token":"blue","symbol":{"glyph":"lock"}},
            "directory_visibility":"members","join_rule":"public","history_access":"since_join",
            "state":"active","created_by":actor,"created_at":arkret_canonical::format_timestamp_canonical(at)}}),
        at,
    );
    uow.commit_event(create.clone()).await.unwrap();
    let circle = CircleId::from_event_id(&create.authority_commit.event.event_id);
    let strand_body = json!({"object":{"schema":"ak.schema.strand.v1","realm_id":realm,
        "scope_circle_id":circle,"tracks":{"discussion":{"is_primary":true,"profile":"discussion"}},
        "metadata":{"title":"Private poll"},"state":"active","created_by":actor,
        "created_at":arkret_canonical::format_timestamp_canonical(at)}});
    let not_member = circle_request(
        &create.authority_commit,
        &circle,
        EventKind::StrandCreate,
        strand_body.clone(),
    );
    let baseline = counts(&pool).await;
    assert!(uow.commit_event(not_member.clone()).await.is_err());
    assert_eq!(counts(&pool).await, baseline);
    assert!(
        store
            .committed_event(&not_member.authority_commit.event.event_id)
            .await
            .unwrap()
            .is_none()
    );

    let join = circle_request(
        &create.authority_commit,
        &circle,
        EventKind::CircleMemberState,
        json!({"circle_id":circle,"member_id":actor,"membership":"join",
            "parent_membership_revision":ordinary_realm::parent_membership_revision(&pool,&realm,&actor).await,
            "expected_membership":null}),
    );
    uow.commit_event(join.clone()).await.unwrap();
    // Realm-signed source cannot create an object that declares Circle scope.
    let wrong_scope = ordinary_realm::next_request_for_actor(
        &create.authority_commit,
        EventKind::StrandCreate,
        actor.clone(),
        strand_body.clone(),
        at,
    );
    let baseline = counts(&pool).await;
    assert!(uow.commit_event(wrong_scope.clone()).await.is_err());
    assert_eq!(counts(&pool).await, baseline);
    let strand = circle_request(
        &join.authority_commit,
        &circle,
        EventKind::StrandCreate,
        strand_body,
    );
    uow.commit_event(strand.clone()).await.unwrap();
    let strand_id = StrandId::from_event_id(&strand.authority_commit.event.event_id);
    let projection = coland_storage_postgres::PgPersistenceStore::new(pool.clone());
    let restored = projection
        .object_current_snapshot()
        .snapshot()
        .await
        .unwrap();
    assert!(restored.strands.iter().any(|current| {
        current.id.as_ref() == Some(&strand_id) && current.scope_circle_id.as_ref() == Some(&circle)
    }));
    // A Realm-stream Commit with a valid id and position still cannot cover
    // a Circle-scoped Strand current during process restart.
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query(
        "UPDATE strand_current_states SET current_commit_id=$2,current_stream_position=$3 WHERE strand_id=$1",
    )
    .bind::<diesel::sql_types::Text, _>(strand_id.as_str())
    .bind::<diesel::sql_types::Text, _>(create.authority_commit.commit.commit_id.as_str())
    .bind::<BigInt, _>(i64::try_from(create.authority_commit.commit.stream_position).unwrap())
    .execute(&mut conn)
    .await
    .unwrap();
    assert!(
        projection
            .object_current_snapshot()
            .snapshot()
            .await
            .is_err()
    );
    diesel::sql_query(
        "UPDATE strand_current_states SET current_commit_id=$2,current_stream_position=$3 WHERE strand_id=$1",
    )
    .bind::<diesel::sql_types::Text, _>(strand_id.as_str())
    .bind::<diesel::sql_types::Text, _>(strand.authority_commit.commit.commit_id.as_str())
    .bind::<BigInt, _>(i64::try_from(strand.authority_commit.commit.stream_position).unwrap())
    .execute(&mut conn)
    .await
    .unwrap();
    let account = actor.as_account_id().unwrap();
    let circle_stream = CommitStreamRef::Circle {
        realm_id: realm.clone(),
        circle_id: circle.clone(),
    };
    let joined_snapshot = store
        .realm_state_snapshot_material_for_account(&realm, account)
        .await
        .unwrap()
        .unwrap();
    assert!(
        joined_snapshot
            .visible_stream_heads
            .iter()
            .any(|head| head.stream_ref == circle_stream)
    );
    assert!(
        joined_snapshot
            .current_state_entries
            .iter()
            .any(|row| matches!(row,
                CurrentState::Value {
                    selector: CurrentSelector::Strand { strand_id: subject },
                    source_stream_ref,
                    ..
                } if subject == &strand_id && source_stream_ref == &circle_stream
            ))
    );
    let poll = circle_request(
        &strand.authority_commit,
        &circle,
        EventKind::MessageCreate,
        json!({"strand_id":strand_id,"track_name":"discussion","content":{
            "kind":"ak.content.poll","body":"Choose","poll":{"kind":"disclosed","max_selection_count":1,
            "answers":[{"id":"a","text":{"kind":"ak.content.text","body":"A"}}]}}}),
    );
    uow.commit_event(poll.clone()).await.unwrap();
    let vote = circle_request(
        &poll.authority_commit,
        &circle,
        EventKind::MessageCreate,
        json!({"strand_id":strand_id,"track_name":"discussion","content":{
            "kind":"ak.content.poll.response","body":"Vote","poll_response":{
            "poll_ref":MessageId::from_event_id(&poll.authority_commit.event.event_id),"selections":["a"]}}}),
    );
    uow.commit_event(vote.clone()).await.unwrap();
    assert_eq!(counts(&pool).await.4, 1);

    // A second Circle has a distinct stream even inside the same Realm.
    // A response there cannot consume the first Circle's Poll.
    let second_create = ordinary_realm::next_request_for_actor(
        &create.authority_commit,
        EventKind::CircleCreate,
        actor.clone(),
        json!({"object":{"schema":"ak.schema.circle.v1","realm_id":realm,
            "title":"Other Circle","display":{"short_name":"Other","color_token":"blue","symbol":{"glyph":"lock"}},
            "directory_visibility":"members","join_rule":"public","history_access":"since_join",
            "state":"active","created_by":actor,"created_at":arkret_canonical::format_timestamp_canonical(at)}}),
        at,
    );
    uow.commit_event(second_create.clone()).await.unwrap();
    let second_circle = CircleId::from_event_id(&second_create.authority_commit.event.event_id);
    let second_join = circle_request(
        &second_create.authority_commit,
        &second_circle,
        EventKind::CircleMemberState,
        json!({"circle_id":second_circle,"member_id":actor,"membership":"join",
            "parent_membership_revision":ordinary_realm::parent_membership_revision(&pool,&realm,&actor).await,
            "expected_membership":null}),
    );
    uow.commit_event(second_join.clone()).await.unwrap();
    let second_strand = circle_request(
        &second_join.authority_commit,
        &second_circle,
        EventKind::StrandCreate,
        json!({"object":{"schema":"ak.schema.strand.v1","realm_id":realm,
            "scope_circle_id":second_circle,"tracks":{"discussion":{"is_primary":true,"profile":"discussion"}},
            "metadata":{"title":"Other private poll"},"state":"active","created_by":actor,
            "created_at":arkret_canonical::format_timestamp_canonical(at)}}),
    );
    uow.commit_event(second_strand.clone()).await.unwrap();
    let second_strand_id = StrandId::from_event_id(&second_strand.authority_commit.event.event_id);
    let cross_circle_vote = circle_request(
        &second_strand.authority_commit,
        &second_circle,
        EventKind::MessageCreate,
        json!({"strand_id":second_strand_id,"track_name":"discussion","content":{
            "kind":"ak.content.poll.response","body":"Vote","poll_response":{
            "poll_ref":MessageId::from_event_id(&poll.authority_commit.event.event_id),"selections":["a"]}}}),
    );
    let baseline = counts(&pool).await;
    let error = uow
        .commit_event(cross_circle_vote.clone())
        .await
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("Message reference differs from its effective stream"),
        "{error}"
    );
    assert_eq!(counts(&pool).await, baseline);
    assert!(
        store
            .committed_event(&cross_circle_vote.authority_commit.event.event_id)
            .await
            .unwrap()
            .is_none()
    );

    let leave = circle_request(
        &vote.authority_commit,
        &circle,
        EventKind::CircleMemberState,
        json!({"circle_id":circle,"member_id":actor,"membership":"leave","expected_membership":"join"}),
    );
    uow.commit_event(leave.clone()).await.unwrap();
    let left_snapshot = store
        .realm_state_snapshot_material_for_account(&realm, account)
        .await
        .unwrap()
        .unwrap();
    assert!(
        !left_snapshot
            .visible_stream_heads
            .iter()
            .any(|head| head.stream_ref == circle_stream)
    );
    assert!(
        !left_snapshot
            .current_state_entries
            .iter()
            .any(|row| matches!(row,
                CurrentState::Value {
                    selector: CurrentSelector::Strand { strand_id: subject },
                    ..
                } if subject == &strand_id
            ))
    );
    let after_leave = circle_request(
        &leave.authority_commit,
        &circle,
        EventKind::MessageCreate,
        ordinary_realm::message_payload(&strand_id, "after leave"),
    );
    let baseline = counts(&pool).await;
    assert!(uow.commit_event(after_leave.clone()).await.is_err());
    assert_eq!(counts(&pool).await, baseline);
    assert!(
        store
            .committed_event(&after_leave.authority_commit.event.event_id)
            .await
            .unwrap()
            .is_none()
    );
}
