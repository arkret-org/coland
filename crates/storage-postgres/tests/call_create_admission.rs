//! Real PostgreSQL Call genesis and capability admission. These UoW fixtures
//! are structural TCB inputs; HTTP tests separately prove producer signatures.
#[path = "support/human_profile.rs"]
#[allow(dead_code)]
mod human_profile;
#[path = "support/ordinary_realm.rs"]
#[allow(dead_code)]
mod ordinary_realm;

use arkret_wire::{ActorId, EventKind};
use coland_storage::{AuthorityCommitStore, EventCommitRequest, EventCommitUnitOfWork};
use coland_storage_postgres::test_database::TestDatabase;
use coland_storage_postgres::{PgAuthorityCommitStore, PgEventCommitUnitOfWork, PgPool};
use diesel::sql_types::{Jsonb, Text};
use diesel_async::RunQueryDsl;
use serde_json::{Value, json};

#[derive(diesel::QueryableByName)]
struct ValueRow {
    #[diesel(sql_type = Jsonb)]
    value: Value,
}

async fn footprint(pool: &PgPool) -> Value {
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query("SELECT jsonb_build_object('events',(SELECT count(*) FROM canonical_events),'commits',(SELECT count(*) FROM realm_commits),'calls',(SELECT count(*) FROM call_state_current_results)) AS value")
        .get_result::<ValueRow>(&mut *conn).await.unwrap().value
}

#[tokio::test]
async fn three_initial_states_derive_call_ids_and_exact_replay_preserves_current() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let discussion = ordinary_realm::open_human_discussion(&pool, "call-initial").await;
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let mut head = discussion.head.clone();
    for state in ["scheduled", "ringing", "connecting"] {
        let request = ordinary_realm::next_request(
            &head.authority_commit,
            EventKind::CallCreate,
            head.authority_commit.event.actor_id.signing_principal_id(),
            json!({"initial_state":state}),
            head.authority_commit.commit.committed_at + chrono::Duration::seconds(1),
        );
        uow.commit_event(request.clone()).await.unwrap();
        let before = footprint(&pool).await;
        uow.commit_event(request.clone()).await.unwrap();
        assert_eq!(footprint(&pool).await, before);
        let mut conn = pool.get().await.unwrap();
        let record = diesel::sql_query("SELECT jsonb_build_object('value',value,'source',source_stream_ref,'commit',current_commit_id,'position',current_stream_position,'create',create_event_id) AS value FROM call_state_current_results WHERE realm_id=$1 AND call_id=$2")
            .bind::<Text,_>(discussion.realm_id().as_str())
            .bind::<Text,_>(arkret_wire::CallId::from_event_id(&request.authority_commit.event.event_id).as_str())
            .get_result::<ValueRow>(&mut *conn).await.unwrap().value;
        assert_eq!(record["value"], json!({"from":null,"to":state}));
        assert_eq!(
            record["source"],
            json!(request.authority_commit.commit.stream_ref)
        );
        assert_eq!(
            record["commit"],
            json!(request.authority_commit.commit.commit_id)
        );
        assert_eq!(
            record["create"],
            json!(request.authority_commit.event.event_id)
        );
        assert_eq!(
            record["position"],
            json!(request.authority_commit.commit.stream_position)
        );
        drop(conn);
        let snapshot = PgAuthorityCommitStore { pool: pool.clone() }
            .realm_state_snapshot_material_for_account(
                &discussion.realm_id(),
                request
                    .authority_commit
                    .event
                    .actor_id
                    .as_account_id()
                    .unwrap(),
            )
            .await
            .unwrap()
            .expect("joined caller sees the accepted Call current");
        assert!(snapshot.current_state_entries.iter().any(|entry| matches!(entry,
            arkret_wire::TypedCurrentRow::Value { selector: arkret_wire::CurrentSelector::CallState {call_id}, value, .. }
            if call_id == &arkret_wire::CallId::from_event_id(&request.authority_commit.event.event_id)
                && value == &json!({"from":null,"to":state}))));
        head = request;
    }
}

async fn refused(uow: &PgEventCommitUnitOfWork, pool: &PgPool, request: EventCommitRequest) {
    let before = footprint(pool).await;
    uow.commit_event(request).await.unwrap_err();
    assert_eq!(
        footprint(pool).await,
        before,
        "refusal leaves no Event, Commit or Call current"
    );
}

#[tokio::test]
async fn terminal_states_supplied_call_ids_and_wrong_scope_have_no_writes() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let discussion = ordinary_realm::open_human_discussion(&pool, "call-refusal").await;
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let head = &discussion.head.authority_commit;
    for state in ["active", "ended", "missed", "failed", "cancelled"] {
        let before = footprint(&pool).await;
        let request = ordinary_realm::next_request(
            head,
            EventKind::CallCreate,
            head.event.actor_id.signing_principal_id(),
            json!({"initial_state":state}),
            head.commit.committed_at,
        );
        let error = uow.commit_event(request).await.unwrap_err();
        assert_eq!(
            error.conflict_code(),
            Some(coland_storage::ConflictCode::CallStateTransitionInvalid),
            "{state}: {error}"
        );
        assert_eq!(footprint(&pool).await, before);
    }
    for payload in [
        json!({"initial_state":"unknown"}),
        json!({"initial_state":false}),
        json!({}),
        json!({"initial_state":"ringing","call_id":arkret_wire::CallId::from_event_id(&head.event.event_id)}),
    ] {
        let before = footprint(&pool).await;
        let request = ordinary_realm::next_request(
            head,
            EventKind::CallCreate,
            head.event.actor_id.signing_principal_id(),
            payload,
            head.commit.committed_at,
        );
        let error = uow.commit_event(request).await.unwrap_err();
        assert!(
            matches!(error, coland_storage::PersistenceError::SchemaViolation(_)),
            "{error}"
        );
        assert_eq!(footprint(&pool).await, before);
    }
    let mut event = ordinary_realm::event(
        EventKind::CallCreate,
        arkret_wire::ScopeRef::Circle {
            realm_id: discussion.realm_id(),
            circle_id: arkret_wire::CircleId::from_event_id(&head.event.event_id),
        },
        head.event.actor_id.signing_principal_id(),
        &ordinary_realm::station(),
        json!({"initial_state":"ringing"}),
        head.commit.committed_at,
    );
    ordinary_realm::reseal(&mut event);
    refused(
        &uow,
        &pool,
        ordinary_realm::request_for_event(head, event, head.commit.committed_at),
    )
    .await;
}

#[tokio::test]
async fn joined_account_needs_call_join_grant_and_other_station_cannot_borrow_it() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let discussion = ordinary_realm::open_human_discussion(&pool, "call-capability").await;
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let founder = discussion.head.authority_commit.event.actor_id.clone();
    let member = human_profile::admit(&pool, &ordinary_realm::station(), "call-member").await;
    let mut head = discussion.head;
    let at = head.authority_commit.commit.committed_at;
    let invite = ordinary_realm::next_request_for_actor(
        &head.authority_commit,
        EventKind::InviteCreate,
        founder.clone(),
        json!({
        "invitee_account_id":member,"introduction_evidence_digest":format!("sha256:{}","a".repeat(64)),
        "expires_at":arkret_canonical::format_timestamp_canonical(at+chrono::Duration::days(7))}),
        at,
    );
    uow.commit_event(invite.clone()).await.unwrap();
    let join = ordinary_realm::next_request_for_actor(
        &invite.authority_commit,
        EventKind::InviteAccept,
        ActorId::account(member.clone()),
        json!({
        "invite_id":arkret_wire::InviteId::from_event_id(&invite.authority_commit.event.event_id),"previous_state":"pending","invitee_account_id":member}),
        at,
    );
    uow.commit_event(join.clone()).await.unwrap();
    head = join;
    let no_grant = ordinary_realm::next_request_for_actor(
        &head.authority_commit,
        EventKind::CallCreate,
        ActorId::account(member.clone()),
        json!({"initial_state":"ringing"}),
        at,
    );
    let before = footprint(&pool).await;
    let error = uow.commit_event(no_grant).await.unwrap_err();
    assert_eq!(
        error.conflict_code(),
        Some(coland_storage::ConflictCode::CapabilityDenied)
    );
    assert_eq!(footprint(&pool).await, before);
    let realm = head.authority_commit.event.realm_id.clone();
    #[derive(diesel::QueryableByName)]
    struct RootRow {
        #[diesel(sql_type = Text)]
        authority_event_ref: String,
    }
    let mut conn = pool.get().await.unwrap();
    let root = diesel::sql_query(
        "SELECT authority_event_ref FROM realm_authority_root_current_results WHERE realm_id=$1",
    )
    .bind::<Text, _>(realm.as_str())
    .get_result::<RootRow>(&mut *conn)
    .await
    .unwrap()
    .authority_event_ref;
    drop(conn);
    let grant = ordinary_realm::next_request_for_actor(
        &head.authority_commit,
        EventKind::CapabilityGrant,
        founder,
        json!({"grant":{
        "schema":"ak.schema.capability.v1","realm_id":realm,"issuer_id":discussion.unit.transactions[0].event.actor_id,
        "subject":ActorId::account(member.clone()),"actions":["ak.call.join"],"resources":[{"kind":"realm","realm_id":realm}],
        "issuer_authority_refs":[{"kind":"realm_root","realm_id":realm,"authority_event_ref":root,"authority_generation":0}],
        "issued_at":arkret_canonical::format_timestamp_canonical(at)}}),
        at,
    );
    uow.commit_event(grant.clone()).await.unwrap();
    let call = ordinary_realm::next_request_for_actor(
        &grant.authority_commit,
        EventKind::CallCreate,
        ActorId::account(member.clone()),
        json!({"initial_state":"ringing"}),
        at,
    );
    uow.commit_event(call.clone()).await.unwrap();
    let other = arkret_wire::AccountId::new(
        member.principal_id,
        arkret_wire::DidCoreId::new("ak:did_core:web:other-call-station.example").unwrap(),
    );
    refused(
        &uow,
        &pool,
        ordinary_realm::next_request_for_actor(
            &call.authority_commit,
            EventKind::CallCreate,
            ActorId::account(other),
            json!({"initial_state":"ringing"}),
            at,
        ),
    )
    .await;
}
