#[path = "support/accepted_pcr_account.rs"]
mod accepted_pcr_account;
#[path = "../../test-support/src/device_authorization_history.rs"]
#[allow(dead_code)]
mod device_authorization_history;
#[path = "support/ordinary_realm.rs"]
#[expect(
    dead_code,
    reason = "This integration binary uses only its subset of the shared Realm fixture."
)]
mod ordinary_realm;
#[path = "../../test-support/src/pcr_genesis.rs"]
#[allow(dead_code)]
mod pcr_genesis;

use coland_storage::{AuthorityCommitStore, EventCommitUnitOfWork, ModerationStore};
use coland_storage_postgres::test_database::TestDatabase;
use coland_storage_postgres::{PgAuthorityCommitStore, PgEventCommitUnitOfWork, PgModerationStore};

async fn bootstrap(
    pool: &coland_storage_postgres::PgPool,
) -> coland_storage::OrdinaryRealmBootstrapCommitUnit {
    let did = ordinary_realm::human_profile::station_did(&ordinary_realm::station());
    let account = ordinary_realm::human_profile::admit_for_station_did(
        pool,
        did.clone(),
        "moderation-founder",
    )
    .await;
    ordinary_realm::source_bootstrap(
        pool,
        ordinary_realm::bootstrap_unit_with_history_for_account(
            &uuid::Uuid::now_v7().to_string(),
            "invite",
            "since_join",
            &account,
            &did,
        ),
    )
    .await
}

#[tokio::test]
async fn pending_review_without_report_is_exact_accepted_event_and_lift_removes_it() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let unit = bootstrap(&pool).await;
    let at = unit.transactions[0].commit.committed_at;
    let authority = PgAuthorityCommitStore { pool: pool.clone() };
    authority
        .admit_ordinary_realm_bootstrap_unit(&unit, at)
        .await
        .unwrap();
    let head = unit.transactions.last().unwrap();
    let realm = head.event.realm_id.clone();
    let actor = head.event.actor_id.clone();
    let principal = actor.signing_principal_id();
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let queue = PgModerationStore { pool: pool.clone() };
    let review = ordinary_realm::next_request_for_actor(
        head,
        arkret_wire::EventKind::ModerationDecision,
        actor.clone(),
        serde_json::json!({"target_ref":realm,"decision":"require_review",
            "issuer_id":principal,"request_canonical_digest":format!("sha256:{}", "01".repeat(32))}),
        at,
    );
    let review = ordinary_realm::source_request(&pool, review).await;
    uow.commit_event(review.clone()).await.unwrap();
    let view = queue.management_view_for_actor(&actor, None).await.unwrap();
    assert!(
        view.items.is_empty(),
        "a policy decision must not fabricate a report"
    );
    assert_eq!(
        view.pending_review_events,
        vec![review.authority_commit.event.clone()]
    );
    let stranger = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        "ak:did_core:web:review-stranger.example".parse().unwrap(),
        ordinary_realm::station(),
    ));
    let hidden = queue
        .management_view_for_actor(&stranger, Some(&realm))
        .await
        .unwrap();
    assert!(hidden.items.is_empty());
    assert!(hidden.pending_review_events.is_empty());
    let lift_payload = serde_json::json!({"target_ref":realm,
        "decision_ref":review.authority_commit.event.event_id,
        "expected_revision":{"commit_id":review.authority_commit.commit.commit_id,
            "stream_position":review.authority_commit.commit.stream_position}});
    let mut stale_payload = lift_payload.clone();
    stale_payload["expected_revision"]["stream_position"] = serde_json::json!(0);
    let stale = ordinary_realm::next_request_for_actor(
        &review.authority_commit,
        arkret_wire::EventKind::ModerationDecisionLift,
        actor.clone(),
        stale_payload,
        at,
    );
    assert_eq!(
        uow.commit_event(ordinary_realm::source_request(&pool, stale).await)
            .await
            .unwrap_err()
            .conflict_code(),
        Some(coland_storage::ConflictCode::CasConflict)
    );
    assert_eq!(
        queue
            .management_view_for_actor(&actor, Some(&realm))
            .await
            .unwrap()
            .pending_review_events,
        vec![review.authority_commit.event.clone()]
    );
    let lift = ordinary_realm::next_request_for_actor(
        &review.authority_commit,
        arkret_wire::EventKind::ModerationDecisionLift,
        actor.clone(),
        lift_payload,
        at,
    );
    uow.commit_event(ordinary_realm::source_request(&pool, lift).await)
        .await
        .unwrap();
    let lifted = queue
        .management_view_for_actor(&actor, Some(&realm))
        .await
        .unwrap();
    assert!(lifted.items.is_empty());
    assert!(lifted.pending_review_events.is_empty());
}

async fn circle_request(
    pool: &coland_storage_postgres::PgPool,
    previous: &coland_storage::AuthorityCommitTransaction,
    kind: arkret_wire::EventKind,
    actor: arkret_wire::ActorId,
    circle: &arkret_wire::CircleId,
    payload: serde_json::Value,
) -> coland_storage::EventCommitRequest {
    let scope = arkret_wire::ScopeRef::Circle {
        realm_id: previous.event.realm_id.clone(),
        circle_id: circle.clone(),
    };
    let event =
        ordinary_realm::event_for_actor(kind, scope, actor, payload, previous.commit.committed_at);
    let mut request =
        ordinary_realm::request_for_event(previous, event, previous.commit.committed_at);
    let stream = arkret_wire::CommitStreamRef::Circle {
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
    ordinary_realm::source_request(pool, request).await
}

#[tokio::test]
async fn circle_report_decision_lift_require_exact_circle_grant_and_source_cut() {
    circle_review_scenario().await;
}

#[inline(never)]
fn scenario_future<F, Fut>(make: F) -> std::pin::Pin<Box<Fut>>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future,
{
    Box::pin(make())
}

#[inline(never)]
fn circle_review_scenario() -> std::pin::Pin<Box<impl std::future::Future<Output = ()>>> {
    Box::pin(async {
        use diesel_async::RunQueryDsl;
        let database = TestDatabase::lease().await;
        let pool = database.pool();
        let governing_did =
            device_authorization_history::did_web_station(&ordinary_realm::station());
        let human = scenario_future(|| {
            accepted_pcr_account::accepted_pcr_account(&pool, governing_did.clone())
        })
        .await;
        let unit = ordinary_realm::bootstrap_unit_for_account(
            &uuid::Uuid::now_v7().to_string(),
            human.as_account_id().unwrap(),
            &governing_did,
        );
        let unit = scenario_future(|| ordinary_realm::source_bootstrap(&pool, unit)).await;
        let head = unit.transactions.last().unwrap();
        let at = head.commit.committed_at;
        let actor = head.event.actor_id.clone();
        let principal = actor.signing_principal_id().clone();
        let realm = head.event.realm_id.clone();
        let store = PgAuthorityCommitStore { pool: pool.clone() };
        store
            .admit_ordinary_realm_bootstrap_unit(&unit, at)
            .await
            .unwrap();
        let uow = PgEventCommitUnitOfWork::new(pool.clone());
        let queue = PgModerationStore { pool: pool.clone() };
        let create = ordinary_realm::next_request_for_actor(
            head,
            arkret_wire::EventKind::CircleCreate,
            actor.clone(),
            serde_json::json!({"object":{"schema":"ak.schema.circle.v1","realm_id":realm,
        "title":"Review Circle","display":{"short_name":"Review","color_token":"blue","symbol":{"glyph":"lock"}},
        "directory_visibility":"members","join_rule":"public","history_access":"since_join",
        "state":"active","created_by":actor,"created_at":arkret_canonical::format_timestamp_canonical(at)}}),
            at,
        );
        let create = scenario_future(|| ordinary_realm::source_request(&pool, create)).await;
        uow.commit_event(create.clone()).await.unwrap();
        let circle = arkret_wire::CircleId::from_event_id(&create.authority_commit.event.event_id);
        let scope = arkret_wire::ScopeRef::Circle {
            realm_id: realm.clone(),
            circle_id: circle.clone(),
        };
        let parent_membership_revision =
            ordinary_realm::parent_membership_revision(&pool, &realm, &actor).await;
        let join = scenario_future(|| {
            circle_request(
                &pool,
                &create.authority_commit,
                arkret_wire::EventKind::CircleMemberState,
                actor.clone(),
                &circle,
                serde_json::json!({"circle_id":circle,"member_id":actor,"membership":"join",
            "parent_membership_revision":parent_membership_revision,
            "expected_membership":null}),
            )
        })
        .await;
        uow.commit_event(join.clone()).await.unwrap();
        let report_payload = serde_json::json!({"realm_id":realm,"effective_scope":scope,
        "target_ref":circle,"report_reason_code":"spam","reporter_id":principal});
        let report = scenario_future(|| {
            circle_request(
                &pool,
                &join.authority_commit,
                arkret_wire::EventKind::SelfModerationReport,
                actor.clone(),
                &circle,
                report_payload.clone(),
            )
        })
        .await;
        uow.commit_event(report.clone()).await.unwrap();
        assert!(
            queue
                .management_view_for_actor(&actor, None)
                .await
                .unwrap()
                .items
                .is_empty(),
            "Realm root alone must not disclose Circle reports"
        );
        let review_payload = serde_json::json!({"target_ref":circle,"decision":"require_review","issuer_id":principal,
        "request_canonical_digest":format!("sha256:{}","02".repeat(32))});
        let denied = scenario_future(|| {
            circle_request(
                &pool,
                &report.authority_commit,
                arkret_wire::EventKind::ModerationDecision,
                actor.clone(),
                &circle,
                review_payload.clone(),
            )
        })
        .await;
        assert!(uow.commit_event(denied.clone()).await.is_err());
        assert!(
            store
                .committed_event(&denied.authority_commit.event.event_id)
                .await
                .unwrap()
                .is_none()
        );
        #[derive(diesel::QueryableByName)]
        struct Root {
            #[diesel(sql_type=diesel::sql_types::Text)]
            authority_event_ref: String,
        }
        let mut conn = pool.get().await.unwrap();
        let root = diesel::sql_query(
        "SELECT authority_event_ref FROM realm_authority_root_current_results WHERE realm_id=$1",
    )
    .bind::<diesel::sql_types::Text, _>(realm.as_str())
    .get_result::<Root>(&mut *conn)
    .await
    .unwrap();
        drop(conn);
        let grant = ordinary_realm::next_request_for_actor(
            &create.authority_commit,
            arkret_wire::EventKind::CapabilityGrant,
            actor.clone(),
            serde_json::json!({"grant":{"schema":"ak.schema.capability.v1","realm_id":realm,"issuer_id":actor,"subject":actor,
            "actions":["ak.moderation.decision","ak.moderation.decision.lift"],
            "resources":[{"kind":"circle","realm_id":realm,"circle_id":circle}],
            "issuer_authority_refs":[{"kind":"realm_root","realm_id":realm,"authority_event_ref":root.authority_event_ref,"authority_generation":0}],
            "issued_at":arkret_canonical::format_timestamp_canonical(at)}}),
            at,
        );
        uow.commit_event(scenario_future(|| ordinary_realm::source_request(&pool, grant)).await)
            .await
            .unwrap();
        let view = queue.management_view_for_actor(&actor, None).await.unwrap();
        assert_eq!(view.items.len(), 1);
        assert_eq!(
            serde_json::to_value(&view.items[0].status).unwrap(),
            serde_json::json!("submitted")
        );
        let wrong_target = scenario_future(|| {
            circle_request(
                &pool,
                &report.authority_commit,
                arkret_wire::EventKind::SelfModerationReport,
                actor.clone(),
                &circle,
                {
                    let mut p = report_payload;
                    p["target_ref"] = serde_json::json!(realm);
                    p
                },
            )
        })
        .await;
        assert!(uow.commit_event(wrong_target.clone()).await.is_err());
        assert!(
            store
                .committed_event(&wrong_target.authority_commit.event.event_id)
                .await
                .unwrap()
                .is_none()
        );
        uow.commit_event(denied.clone()).await.unwrap();
        let view = queue.management_view_for_actor(&actor, None).await.unwrap();
        assert_eq!(
            view.pending_review_events,
            vec![denied.authority_commit.event.clone()]
        );
        assert_eq!(
            serde_json::to_value(&view.items[0].status).unwrap(),
            serde_json::json!("resolved")
        );
        let lift_payload = serde_json::json!({"target_ref":circle,"decision_ref":denied.authority_commit.event.event_id,
        "expected_revision":{"commit_id":denied.authority_commit.commit.commit_id,"stream_position":denied.authority_commit.commit.stream_position}});
        let stale = scenario_future(|| {
            circle_request(
                &pool,
                &denied.authority_commit,
                arkret_wire::EventKind::ModerationDecisionLift,
                actor.clone(),
                &circle,
                {
                    let mut p = lift_payload.clone();
                    p["expected_revision"]["stream_position"] = serde_json::json!(0);
                    p
                },
            )
        })
        .await;
        assert_eq!(
            uow.commit_event(stale).await.unwrap_err().conflict_code(),
            Some(coland_storage::ConflictCode::CasConflict)
        );
        let lift = scenario_future(|| {
            circle_request(
                &pool,
                &denied.authority_commit,
                arkret_wire::EventKind::ModerationDecisionLift,
                actor.clone(),
                &circle,
                lift_payload,
            )
        })
        .await;
        uow.commit_event(lift).await.unwrap();
        let view = queue.management_view_for_actor(&actor, None).await.unwrap();
        assert!(view.pending_review_events.is_empty());
        assert_eq!(
            serde_json::to_value(&view.items[0].status).unwrap(),
            serde_json::json!("resolved")
        );
    })
}
