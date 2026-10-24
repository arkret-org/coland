#[path = "support/historical_human.rs"]
mod historical_human;

use arkret_wire::{ActorId, CommitStreamRef, EventKind};
use coland_storage::{AuthorityCommitStore, AuthorityCommitTransaction, EventCommitUnitOfWork};
use coland_storage_postgres::test_database::TestDatabase;
use coland_storage_postgres::{PgAuthorityCommitStore, PgEventCommitUnitOfWork};
use historical_human::ordinary_realm;

fn membership(
    previous: &AuthorityCommitTransaction,
    circle: &arkret_wire::CircleId,
    actor: &ActorId,
    state: &str,
    expected: Option<&str>,
    parent: Option<serde_json::Value>,
) -> coland_storage::EventCommitRequest {
    let scope = arkret_wire::ScopeRef::Circle {
        realm_id: previous.event.realm_id.clone(),
        circle_id: circle.clone(),
    };
    let event = ordinary_realm::event_for_actor(
        EventKind::CircleMemberState,
        scope,
        actor.clone(),
        {
            let mut payload = serde_json::json!({"circle_id":circle,"member_id":actor,"membership":state,"expected_membership":expected});
            if let Some(parent) = parent {
                payload["parent_membership_revision"] = parent;
            }
            payload
        },
        previous.commit.committed_at,
    );
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
    request.realm_fanout_source = Some(arkret_wire::EventAdmissionSubmission::new(
        request.authority_commit.event.clone(),
    ));
    request
}

#[tokio::test]
async fn durable_circle_directory_and_member_details_follow_accepted_current() {
    Box::pin(check_circle_convenience("realm_members")).await;
    Box::pin(check_circle_convenience("members")).await;
}

async fn check_circle_convenience(visibility: &str) {
    use arkret_models_collaboration::governance::circle::{CircleMembership, CircleReadView};
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let did = ordinary_realm::human_profile::station_did(&ordinary_realm::station());
    let fixture = historical_human::HumanFixture::new(&pool, did).await;
    ordinary_realm::human_profile::register_fixture_signer(
        &fixture.pcr.history.account,
        fixture.pcr.history.device_verification_method.clone(),
        fixture.pcr.history.founding_device_signing_seed,
    );
    let actor = ActorId::account(fixture.pcr.history.account.clone());
    fixture.admit(&pool).await;
    let unit = fixture.unit;
    let head = unit.transactions.last().unwrap();
    let realm = head.event.realm_id.clone();
    let at = head.commit.committed_at;
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let short = "Durable";
    let create = ordinary_realm::next_request_for_actor(
        head,
        EventKind::CircleCreate,
        actor.clone(),
        serde_json::json!({"object":{"schema":"ak.schema.circle.v1","realm_id":realm,"title":short,
            "display":{"short_name":short,"color_token":"blue","symbol":{"glyph":"lock"}},
            "directory_visibility":visibility,"join_rule":"public","history_access":"since_join","state":"active",
            "created_by":actor,"created_at":arkret_canonical::format_timestamp_canonical(at)}}),
        at,
    );
    let create = Box::pin(ordinary_realm::source_request(&pool, create)).await;
    uow.commit_event(create.clone()).await.unwrap();
    let id = arkret_wire::CircleId::from_event_id(&create.authority_commit.event.event_id);
    let before = store.circle_view_for_actor(&id, &actor).await.unwrap();
    let listed = store.circle_views_for_actor(&realm, &actor).await.unwrap();
    assert!(
        before.is_none(),
        "Realm membership and Circle creation confer no full CircleView access ({visibility})"
    );
    assert!(
        listed.is_empty(),
        "the full-view list must not leak title or creator to non-members ({visibility})"
    );
    let before_read = store.circle_read_for_actor(&id, &actor).await.unwrap();
    let before_list = store.circle_reads_for_actor(&realm, &actor).await.unwrap();
    if visibility == "realm_members" {
        let CircleReadView::Preview(preview) = before_read.unwrap() else {
            panic!("Realm member must see closed preview before joining");
        };
        assert_eq!(before_list.len(), 1);
        assert_eq!(
            serde_json::to_value(&preview)
                .unwrap()
                .as_object()
                .unwrap()
                .len(),
            7
        );
        assert_eq!(
            serde_json::to_value(&preview.display)
                .unwrap()
                .as_object()
                .unwrap()
                .len(),
            2
        );
        assert_eq!(
            serde_json::to_value(preview.member_count_bucket).unwrap(),
            "0"
        );
        assert_eq!(preview.opaque_commitment.len(), 64);
        assert!(
            preview
                .opaque_commitment
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        );
    } else {
        assert!(before_read.is_none());
        assert!(before_list.is_empty());
    }
    let parent = ordinary_realm::parent_membership_revision(&database.pool(), &realm, &actor).await;
    let join = membership(
        &create.authority_commit,
        &id,
        &actor,
        "join",
        None,
        Some(parent),
    );
    let join = Box::pin(ordinary_realm::source_request(&pool, join)).await;
    uow.commit_event(join.clone()).await.unwrap();
    let joined = store
        .circle_view_for_actor(&id, &actor)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(joined.viewer_membership, Some(CircleMembership::Join));
    assert_eq!(joined.member_ids, vec![actor.clone()]);
    check_snapshot_current_without_create_history(&pool, &store, &id, &actor).await;
    assert!(matches!(
        store.circle_read_for_actor(&id, &actor).await.unwrap(),
        Some(CircleReadView::Full(_))
    ));
    assert_eq!(
        store
            .circle_views_for_actor(&realm, &actor)
            .await
            .unwrap()
            .len(),
        1,
        "a joined member can list the full CircleView ({visibility})"
    );
    let leave = membership(
        &join.authority_commit,
        &id,
        &actor,
        "leave",
        Some("join"),
        None,
    );
    let leave = Box::pin(ordinary_realm::source_request(&pool, leave)).await;
    uow.commit_event(leave).await.unwrap();
    let ended = store.circle_view_for_actor(&id, &actor).await.unwrap();
    assert!(
        ended.is_none(),
        "leaving closes the full-view read ({visibility})"
    );
    assert_eq!(
        store
            .circle_read_for_actor(&id, &actor)
            .await
            .unwrap()
            .is_some(),
        visibility == "realm_members"
    );
    assert!(
        store
            .circle_views_for_actor(&realm, &actor)
            .await
            .unwrap()
            .is_empty()
    );
}

async fn check_snapshot_current_without_create_history(
    pool: &coland_storage_postgres::PgPool,
    store: &PgAuthorityCommitStore,
    id: &arkret_wire::CircleId,
    actor: &ActorId,
) {
    use diesel::sql_types::{BigInt, Text};
    use diesel_async::RunQueryDsl;

    let mut conn = pool.get().await.unwrap();
    #[derive(diesel::QueryableByName)]
    struct CoveringEvent {
        #[diesel(sql_type=BigInt)]
        event_pk: i64,
    }
    let covering = diesel::sql_query("SELECT c.event_pk FROM realm_commits c JOIN circle_current_states r ON r.current_commit_id=c.commit_id WHERE r.circle_id=$1")
        .bind::<Text,_>(id.as_str()).get_result::<CoveringEvent>(&mut *conn).await.unwrap();
    // A retained continuity Commit carries no readable producer Event.
    diesel::sql_query("UPDATE realm_commits SET event_pk=NULL WHERE commit_id=(SELECT current_commit_id FROM circle_current_states WHERE circle_id=$1)")
        .bind::<Text,_>(id.as_str()).execute(&mut *conn).await.unwrap();
    assert!(store.circle_view_for_actor(id, actor).await.is_err());
    diesel::sql_query("INSERT INTO replica_authorization_rows(realm_id,selector,source_stream_ref,current_commit_id,current_stream_position,value,updated_at) SELECT realm_id,jsonb_build_object('kind','circle','circle_id',circle_id),source_stream_ref,current_commit_id,current_stream_position,value,updated_at FROM circle_current_states WHERE circle_id=$1")
        .bind::<Text,_>(id.as_str()).execute(&mut *conn).await.unwrap();
    diesel::sql_query("INSERT INTO replica_authorization_cuts(realm_id,source_stream_ref,head_commit_id,head_stream_position,verified_at) SELECT realm_id,source_stream_ref,current_commit_id,current_stream_position,updated_at FROM circle_current_states WHERE circle_id=$1")
        .bind::<Text,_>(id.as_str()).execute(&mut *conn).await.unwrap();
    assert!(
        store
            .circle_view_for_actor(id, actor)
            .await
            .unwrap()
            .is_some()
    );
    // Cached value divergence must not supply Snapshot provenance.
    diesel::sql_query("UPDATE replica_authorization_rows SET value=jsonb_set(value,'{title}','\"different current\"') WHERE selector=jsonb_build_object('kind','circle','circle_id',$1::text)")
        .bind::<Text,_>(id.as_str()).execute(&mut *conn).await.unwrap();
    assert!(store.circle_view_for_actor(id, actor).await.is_err());
    diesel::sql_query("UPDATE replica_authorization_rows v SET value=r.value FROM circle_current_states r WHERE r.circle_id=$1 AND v.selector=jsonb_build_object('kind','circle','circle_id',r.circle_id)")
        .bind::<Text,_>(id.as_str()).execute(&mut *conn).await.unwrap();
    // Equal positions from a different Commit are not the same verified cut.
    diesel::sql_query("UPDATE replica_authorization_cuts h SET head_commit_id='different-commit' FROM circle_current_states r WHERE r.circle_id=$1 AND h.realm_id=r.realm_id AND h.source_stream_ref=r.source_stream_ref")
        .bind::<Text,_>(id.as_str()).execute(&mut *conn).await.unwrap();
    assert!(store.circle_view_for_actor(id, actor).await.is_err());
    diesel::sql_query("UPDATE realm_commits c SET event_pk=$2 FROM circle_current_states r WHERE r.circle_id=$1 AND c.commit_id=r.current_commit_id")
        .bind::<Text,_>(id.as_str()).bind::<BigInt,_>(covering.event_pk).execute(&mut *conn).await.unwrap();
    diesel::sql_query("DELETE FROM replica_authorization_rows WHERE selector=jsonb_build_object('kind','circle','circle_id',$1::text)")
        .bind::<Text,_>(id.as_str()).execute(&mut *conn).await.unwrap();
    diesel::sql_query("DELETE FROM replica_authorization_cuts h USING circle_current_states r WHERE r.circle_id=$1 AND h.realm_id=r.realm_id AND h.source_stream_ref=r.source_stream_ref")
        .bind::<Text,_>(id.as_str()).execute(&mut *conn).await.unwrap();
}
