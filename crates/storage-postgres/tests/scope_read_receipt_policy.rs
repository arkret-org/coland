//! Scope policy admission, independent replacements and zero-write refusals.
#[path = "support/ordinary_realm.rs"]
#[allow(dead_code)]
mod ordinary_realm;
use arkret_wire::{CircleId, CommitStreamRef, CurrentSelector, CurrentState, EventKind, ScopeRef};
use coland_storage::{
    AuthorityCommitStore, AuthorityCommitTransaction, EventCommitRequest, EventCommitUnitOfWork,
};
use coland_storage_postgres::test_database::TestDatabase;
use coland_storage_postgres::{PgAuthorityCommitStore, PgEventCommitUnitOfWork};
use diesel::sql_types::BigInt;
use diesel_async::RunQueryDsl;
use serde_json::{Value, json};
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

#[derive(diesel::QueryableByName, PartialEq, Debug)]
struct Counts {
    #[diesel(sql_type=BigInt)]
    events: i64,
    #[diesel(sql_type=BigInt)]
    commits: i64,
    #[diesel(sql_type=BigInt)]
    policies: i64,
}
async fn counts(pool: &coland_storage_postgres::PgPool) -> Counts {
    diesel::sql_query("SELECT (SELECT count(*) FROM canonical_events) AS events,(SELECT count(*) FROM realm_commits) AS commits,(SELECT count(*) FROM scope_read_receipt_policy_current_states) AS policies")
        .get_result(&mut *pool.get().await.unwrap()).await.unwrap()
}
#[tokio::test]
async fn scope_read_receipt_policy_independent_streams_and_atomic_refusals() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let discussion =
        ordinary_realm::open_discussion(&pool, &uuid::Uuid::now_v7().to_string()).await;
    let mut root = discussion.head.authority_commit;
    let realm = root.event.realm_id.clone();
    let actor = root.event.actor_id.clone();
    let at = root.commit.committed_at;
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    let mut circles = Vec::new();
    for title in ["First", "Second"] {
        let create = ordinary_realm::next_request_for_actor(
            &root,
            EventKind::CircleCreate,
            actor.clone(),
            json!({"object":{"schema":"ak.schema.circle.v1","realm_id":realm,"title":title,"display":{"short_name":title,"color_token":"blue","symbol":{"glyph":"lock"}},"directory_visibility":"members","join_rule":"public","history_access":"since_join","state":"active","created_by":actor,"created_at":arkret_canonical::format_timestamp_canonical(at)}}),
            at,
        );
        uow.commit_event(create.clone()).await.unwrap();
        root = create.authority_commit;
        let circle = CircleId::from_event_id(&root.event.event_id);
        let unauthorized = circle_request(
            &root,
            &circle,
            EventKind::ScopeReadReceiptPolicy,
            json!({"disclosure":"required"}),
        );
        let before = counts(&pool).await;
        assert!(uow.commit_event(unauthorized).await.is_err());
        assert_eq!(counts(&pool).await, before);
        let join = circle_request(
            &root,
            &circle,
            EventKind::CircleMemberState,
            json!({"circle_id":circle,"member_id":actor,"membership":"join","parent_membership_revision":ordinary_realm::parent_membership_revision(&pool,&realm,&actor).await,"expected_membership":null}),
        );
        uow.commit_event(join.clone()).await.unwrap();
        circles.push((circle, join.authority_commit));
    }
    let realm_scope = ScopeRef::Realm {
        realm_id: realm.clone(),
    };
    let mut expected = Vec::new();
    for (scope, value) in [
        (
            realm_scope.clone(),
            json!({"disclosure":"disabled","visibility":"private"}),
        ),
        (
            ScopeRef::Circle {
                realm_id: realm.clone(),
                circle_id: circles[0].0.clone(),
            },
            json!({"disclosure":"required","visibility":"public"}),
        ),
        (
            ScopeRef::Circle {
                realm_id: realm.clone(),
                circle_id: circles[1].0.clone(),
            },
            json!({"disclosure":"optional","visibility":"members"}),
        ),
        (realm_scope.clone(), json!({"disclosure":"required"})),
        (
            ScopeRef::Circle {
                realm_id: realm.clone(),
                circle_id: circles[1].0.clone(),
            },
            json!({"visibility":"private"}),
        ),
    ] {
        let request = if let ScopeRef::Circle { circle_id, .. } = &scope {
            let previous = &circles.iter().find(|(id, _)| id == circle_id).unwrap().1;
            circle_request(
                previous,
                circle_id,
                EventKind::ScopeReadReceiptPolicy,
                value.clone(),
            )
        } else {
            ordinary_realm::next_request_for_actor(
                &root,
                EventKind::ScopeReadReceiptPolicy,
                actor.clone(),
                value.clone(),
                at,
            )
        };
        uow.commit_event(request.clone()).await.unwrap();
        if let ScopeRef::Circle { circle_id, .. } = &scope {
            circles
                .iter_mut()
                .find(|(id, _)| id == circle_id)
                .unwrap()
                .1 = request.authority_commit.clone();
        } else {
            root = request.authority_commit.clone();
        }
        let selector = CurrentSelector::ScopeReadReceiptPolicy {
            scope_ref: scope.clone(),
        };
        expected.retain(
            |row| !matches!(row,CurrentState::Value {selector:found,..} if found==&selector),
        );
        expected.push(CurrentState::Value {
            selector,
            source_stream_ref: request.authority_commit.commit.stream_ref.clone(),
            revision: arkret_wire::CurrentRevision {
                commit_id: request.authority_commit.commit.commit_id.clone(),
                stream_position: request.authority_commit.commit.stream_position,
            },
            value,
        });
        let snapshot = store
            .realm_state_snapshot_material_for_account(&realm, actor.as_account_id().unwrap())
            .await
            .unwrap()
            .unwrap();
        let found: Vec<_> = snapshot
            .current_state_entries
            .into_iter()
            .filter(|row| {
                matches!(
                    row,
                    CurrentState::Value {
                        selector: CurrentSelector::ScopeReadReceiptPolicy { .. },
                        ..
                    }
                )
            })
            .collect();
        assert_eq!(found.len(), expected.len());
        for row in &expected {
            assert!(found.contains(row), "missing {row:?}");
        }
    }
    let mut wrong = circle_request(
        &circles[0].1,
        &circles[0].0,
        EventKind::ScopeReadReceiptPolicy,
        json!({"disclosure":"disabled"}),
    );
    wrong.authority_commit.commit.stream_ref = CommitStreamRef::Realm { realm_id: realm };
    ordinary_realm::seal_final_commit(&mut wrong.authority_commit.commit);
    let before = counts(&pool).await;
    assert!(uow.commit_event(wrong).await.is_err());
    assert_eq!(counts(&pool).await, before);
    for payload in [
        json!({}),
        json!({"disclosure":null}),
        json!({"disclosure":"optional","scope_overrides":{}}),
    ] {
        let invalid = circle_request(
            &circles[1].1,
            &circles[1].0,
            EventKind::ScopeReadReceiptPolicy,
            payload,
        );
        let before = counts(&pool).await;
        assert!(uow.commit_event(invalid).await.is_err());
        assert_eq!(counts(&pool).await, before);
    }
}
