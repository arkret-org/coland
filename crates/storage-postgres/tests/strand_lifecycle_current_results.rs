//! Strand progress and lifecycle transitions through the accepting PostgreSQL UOW.
//! Signatures use the ordinary structural fixture; these are storage-cut tests.
#[path = "support/ordinary_realm.rs"]
#[allow(dead_code)]
mod ordinary_realm;

use arkret_wire::{ActorId, EventKind, StrandId};
use coland_storage::{
    AuthorityCommitStore, AuthorityCommitTransaction, EventCommitRequest, EventCommitUnitOfWork,
};
use coland_storage_postgres::test_database::TestDatabase;
use coland_storage_postgres::{PgEventCommitUnitOfWork, PgPool};
use diesel::sql_types::{BigInt, Jsonb, Text};
use diesel_async::{RunQueryDsl, SimpleAsyncConnection};
use ordinary_realm::{next_request, open_discussion};
use serde_json::{Value, json};

#[derive(diesel::QueryableByName, Debug, PartialEq)]
struct Current {
    #[diesel(sql_type = Text)]
    current_commit_id: String,
    #[diesel(sql_type = BigInt)]
    current_stream_position: i64,
    #[diesel(sql_type = Jsonb)]
    value: Value,
}
#[derive(diesel::QueryableByName)]
struct Footprint {
    #[diesel(sql_type = Jsonb)]
    value: Value,
}
async fn current(pool: &PgPool, strand: &StrandId) -> Current {
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query("SELECT current_commit_id,current_stream_position,value FROM strand_current_results WHERE strand_id=$1")
        .bind::<Text,_>(strand.as_str()).get_result(&mut *conn).await.unwrap()
}
async fn footprint(pool: &PgPool) -> Value {
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query("SELECT jsonb_build_object('events',(SELECT count(*) FROM canonical_events),'commits',(SELECT count(*) FROM realm_commits),'currents',(SELECT count(*) FROM strand_current_results),'outbox',(SELECT count(*) FROM federation_outbox)) AS value")
        .get_result::<Footprint>(&mut *conn).await.unwrap().value
}

async fn full_write_footprint(pool: &PgPool) -> Value {
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query("SELECT jsonb_build_object( \
        'events',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text),'[]'::jsonb) FROM canonical_events r), \
        'commits',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text),'[]'::jsonb) FROM realm_commits r), \
        'current',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text),'[]'::jsonb) FROM strand_current_results r), \
        'authority',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text),'[]'::jsonb) FROM realm_authorities r), \
        'producer_keys',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text),'[]'::jsonb) FROM agent_producer_signer_keys r), \
        'outbox',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text),'[]'::jsonb) FROM federation_outbox r), \
        'event_outbox',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text),'[]'::jsonb) FROM event_federation_outbox r)) AS value")
        .get_result::<Footprint>(&mut *conn).await.unwrap().value
}

async fn assert_capability_denied_without_writes(pool: &PgPool, request: EventCommitRequest) {
    let before = full_write_footprint(pool).await;
    let id = request.authority_commit.event.event_id.clone();
    let error = PgEventCommitUnitOfWork::new(pool.clone())
        .commit_event(request)
        .await
        .unwrap_err();
    assert_eq!(
        error.conflict_code(),
        Some(coland_storage::ConflictCode::CapabilityDenied)
    );
    assert_eq!(full_write_footprint(pool).await, before);
    assert!(
        coland_storage_postgres::PgAuthorityCommitStore { pool: pool.clone() }
            .committed_event(&id)
            .await
            .unwrap()
            .is_none()
    );
}

async fn accept_and_assert_exact_replay(pool: &PgPool, request: EventCommitRequest) {
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    assert!(
        uow.commit_event(request.clone())
            .await
            .unwrap()
            .event_inserted
    );
    let accepted = full_write_footprint(pool).await;
    let replay = uow.commit_event(request.clone()).await.unwrap();
    assert!(!replay.event_inserted);
    assert_eq!(replay.projections_inserted, 0);
    assert_eq!(replay.outbox_inserted, 0);
    assert_eq!(full_write_footprint(pool).await, accepted);
    let held = coland_storage_postgres::PgAuthorityCommitStore { pool: pool.clone() }
        .committed_event(&request.authority_commit.event.event_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(held.event, request.authority_commit.event);
    assert_eq!(held.commit, request.authority_commit.commit);
}

async fn create_for_actor(
    pool: &PgPool,
    previous: &AuthorityCommitTransaction,
    actor: ActorId,
    title: &str,
) -> EventCommitRequest {
    let at = previous.commit.committed_at + chrono::Duration::seconds(1);
    let request = ordinary_realm::next_human_request_for_actor(
        previous,
        EventKind::StrandCreate,
        actor.clone(),
        json!({"object":{"schema":"ak.schema.strand.v1","realm_id":previous.event.realm_id,
            "tracks":{"discussion":{"is_primary":true,"profile":"discussion"}},
            "metadata":{"title":title},"state":"active","created_by":actor,
            "created_at":arkret_canonical::format_timestamp_canonical(at)}}),
        at,
    );
    Box::pin(ordinary_realm::source_request(pool, request)).await
}

async fn lifecycle_for_actor(
    pool: &PgPool,
    previous: &AuthorityCommitTransaction,
    strand: &StrandId,
    actor: ActorId,
    kind: EventKind,
) -> EventCommitRequest {
    let request = ordinary_realm::next_human_request_for_actor(
        previous,
        kind,
        actor,
        json!({"target_ref":strand}),
        previous.commit.committed_at + chrono::Duration::seconds(1),
    );
    Box::pin(ordinary_realm::source_request(pool, request)).await
}

#[tokio::test]
async fn strand_create_checks_capability_and_exact_replay_preserves_all_rows() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let opened = Box::pin(open_discussion(&pool, "create-capability-replay")).await;
    let intruder = Box::pin(ordinary_realm::human_profile::admit(
        &pool,
        &ordinary_realm::station(),
        "create-intruder",
    ))
    .await;
    let denied = Box::pin(create_for_actor(
        &pool,
        &opened.head.authority_commit,
        ActorId::account(intruder),
        "Denied create",
    ))
    .await;
    Box::pin(assert_capability_denied_without_writes(&pool, denied)).await;
    let accepted = Box::pin(create_for_actor(
        &pool,
        &opened.head.authority_commit,
        opened.head.authority_commit.event.actor_id.clone(),
        "Accepted create",
    ))
    .await;
    Box::pin(accept_and_assert_exact_replay(&pool, accepted)).await;
}

#[tokio::test]
async fn strand_archive_checks_capability_and_exact_replay_preserves_all_rows() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let opened = Box::pin(open_discussion(&pool, "archive-capability-replay")).await;
    let intruder = Box::pin(ordinary_realm::human_profile::admit(
        &pool,
        &ordinary_realm::station(),
        "archive-intruder",
    ))
    .await;
    let denied = Box::pin(lifecycle_for_actor(
        &pool,
        &opened.head.authority_commit,
        &opened.strand_id,
        ActorId::account(intruder),
        EventKind::StrandArchive,
    ))
    .await;
    Box::pin(assert_capability_denied_without_writes(&pool, denied)).await;
    let accepted = Box::pin(lifecycle_for_actor(
        &pool,
        &opened.head.authority_commit,
        &opened.strand_id,
        opened.head.authority_commit.event.actor_id.clone(),
        EventKind::StrandArchive,
    ))
    .await;
    Box::pin(accept_and_assert_exact_replay(&pool, accepted)).await;
}

#[tokio::test]
async fn strand_restore_checks_capability_and_exact_replay_preserves_all_rows() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let opened = Box::pin(open_discussion(&pool, "restore-capability-replay")).await;
    let intruder = Box::pin(ordinary_realm::human_profile::admit(
        &pool,
        &ordinary_realm::station(),
        "restore-intruder",
    ))
    .await;
    let archived = Box::pin(lifecycle_for_actor(
        &pool,
        &opened.head.authority_commit,
        &opened.strand_id,
        opened.head.authority_commit.event.actor_id.clone(),
        EventKind::StrandArchive,
    ))
    .await;
    Box::pin(accept_and_assert_exact_replay(&pool, archived.clone())).await;
    let denied = Box::pin(lifecycle_for_actor(
        &pool,
        &archived.authority_commit,
        &opened.strand_id,
        ActorId::account(intruder),
        EventKind::StrandRestore,
    ))
    .await;
    Box::pin(assert_capability_denied_without_writes(&pool, denied)).await;
    let accepted = Box::pin(lifecycle_for_actor(
        &pool,
        &archived.authority_commit,
        &opened.strand_id,
        opened.head.authority_commit.event.actor_id.clone(),
        EventKind::StrandRestore,
    ))
    .await;
    Box::pin(accept_and_assert_exact_replay(&pool, accepted)).await;
}
fn stage(
    previous: &AuthorityCommitTransaction,
    strand: &StrandId,
    value: &str,
    expected: Option<&str>,
    seconds: i64,
) -> EventCommitRequest {
    let mut payload = json!({"strand_id":strand,"stage":value});
    if let Some(expected) = expected {
        payload["expected_stage"] = json!(expected);
    }
    next_request(
        previous,
        EventKind::StrandStageSet,
        previous.event.actor_id.signing_principal_id(),
        payload,
        previous.commit.committed_at + chrono::Duration::seconds(seconds),
    )
}
fn lifecycle(
    previous: &AuthorityCommitTransaction,
    strand: &StrandId,
    kind: EventKind,
    seconds: i64,
) -> EventCommitRequest {
    next_request(
        previous,
        kind,
        previous.event.actor_id.signing_principal_id(),
        json!({"target_ref":strand}),
        previous.commit.committed_at + chrono::Duration::seconds(seconds),
    )
}
async fn assert_refused(
    pool: &PgPool,
    strand: &StrandId,
    request: EventCommitRequest,
    reason: &str,
) {
    let before = current(pool, strand).await;
    let counts = footprint(pool).await;
    let error = PgEventCommitUnitOfWork::new(pool.clone())
        .commit_event(request)
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains(reason), "wanted {reason}, got {error}");
    assert_eq!(current(pool, strand).await, before);
    assert_eq!(footprint(pool).await, counts);
}

#[tokio::test]
async fn stage_initial_cas_concurrent_winner_and_noop_revision_are_durable() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let discussion = Box::pin(open_discussion(&pool, "strand-stage-cas")).await;
    let initial = current(&pool, &discussion.strand_id).await;
    assert!(initial.value.get("stage").is_none());
    assert!(initial.value.get("stage_changed_at").is_none());
    let first = Box::pin(ordinary_realm::source_request(
        &pool,
        stage(
            &discussion.head.authority_commit,
            &discussion.strand_id,
            "planned",
            None,
            1,
        ),
    ))
    .await;
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    uow.commit_event(first.clone()).await.unwrap();
    let planned = current(&pool, &discussion.strand_id).await;
    assert_eq!(planned.value["stage"], "planned");
    assert_eq!(
        planned.value["stage_changed_at"],
        arkret_canonical::format_timestamp_canonical(first.authority_commit.event.created_at)
    );
    assert_eq!(
        planned.current_commit_id,
        first.authority_commit.commit.commit_id.as_str()
    );
    for expected in [None, Some("draft")] {
        assert_refused(
            &pool,
            &discussion.strand_id,
            Box::pin(ordinary_realm::source_request(
                &pool,
                stage(
                    &first.authority_commit,
                    &discussion.strand_id,
                    "in_progress",
                    expected,
                    2,
                ),
            ))
            .await,
            "expected_stage",
        )
        .await;
    }
    let left = Box::pin(ordinary_realm::source_request(
        &pool,
        stage(
            &first.authority_commit,
            &discussion.strand_id,
            "in_progress",
            Some("planned"),
            3,
        ),
    ))
    .await;
    let right = Box::pin(ordinary_realm::source_request(
        &pool,
        stage(
            &first.authority_commit,
            &discussion.strand_id,
            "blocked",
            Some("planned"),
            3,
        ),
    ))
    .await;
    let second_uow = PgEventCommitUnitOfWork::new(pool.clone());
    let baseline = footprint(&pool).await;
    let (left_result, right_result) = tokio::join!(
        uow.commit_event(left.clone()),
        second_uow.commit_event(right.clone())
    );
    assert_ne!(
        left_result.is_ok(),
        right_result.is_ok(),
        "exactly one competing Commit may advance the shared basis"
    );
    let winner = if left_result.is_ok() { left } else { right };
    let won = current(&pool, &discussion.strand_id).await;
    assert_eq!(
        won.current_commit_id,
        winner.authority_commit.commit.commit_id.as_str()
    );
    let after = footprint(&pool).await;
    assert_eq!(
        after["events"].as_i64(),
        baseline["events"].as_i64().map(|n| n + 1)
    );
    assert_eq!(
        after["commits"].as_i64(),
        baseline["commits"].as_i64().map(|n| n + 1)
    );
    assert_eq!(after["outbox"], baseline["outbox"]);
    let value = won.value["stage"].as_str().unwrap();
    let noop = Box::pin(ordinary_realm::source_request(
        &pool,
        stage(
            &winner.authority_commit,
            &discussion.strand_id,
            value,
            Some(value),
            4,
        ),
    ))
    .await;
    uow.commit_event(noop.clone()).await.unwrap();
    let settled = current(&pool, &discussion.strand_id).await;
    assert_eq!(
        settled.value, won.value,
        "same stage preserves all semantic and audit timestamps"
    );
    assert_eq!(
        settled.current_stream_position,
        won.current_stream_position + 1
    );
    assert_eq!(
        settled.current_commit_id,
        noop.authority_commit.commit.commit_id.as_str()
    );
    let counts = footprint(&pool).await;
    let reopened = PgEventCommitUnitOfWork::new(pool.clone());
    assert!(
        !reopened
            .commit_event(noop.clone())
            .await
            .unwrap()
            .event_inserted
    );
    assert!(
        !reopened
            .commit_event(first.clone())
            .await
            .unwrap()
            .event_inserted
    );
    let reader = coland_storage_postgres::PgAuthorityCommitStore { pool: pool.clone() };
    for request in [&first, &noop] {
        assert_eq!(
            reader
                .committed_event(&request.authority_commit.event.event_id)
                .await
                .unwrap()
                .unwrap()
                .commit,
            request.authority_commit.commit
        );
    }
    assert_eq!(current(&pool, &discussion.strand_id).await, settled);
    assert_eq!(footprint(&pool).await, counts);
    let account = arkret_wire::AccountId::new(
        discussion
            .head
            .authority_commit
            .event
            .actor_id
            .signing_principal_id()
            .clone(),
        ordinary_realm::station(),
    );
    let snapshot =
        coland_storage_postgres::account_snapshot_material(&pool, &discussion.realm_id(), &account)
            .await
            .unwrap()
            .unwrap();
    assert!(snapshot.current_state_entries.iter().any(|entry| matches!(entry, arkret_wire::TypedCurrentRow::Value {selector:arkret_wire::CurrentSelector::Strand {strand_id}, revision, value,..} if strand_id == &discussion.strand_id && revision.commit_id == noop.authority_commit.commit.commit_id && value == &settled.value)));
}

#[tokio::test]
async fn archive_restore_fsm_and_accepting_time_replay_do_not_diverge() {
    archive_restore_scenario().await;
}

#[inline(never)]
fn archive_restore_scenario() -> std::pin::Pin<Box<impl std::future::Future<Output = ()>>> {
    Box::pin(async move {
        let database = TestDatabase::lease().await;
        let pool = database.pool();
        let discussion = scenario_future(|| open_discussion(&pool, "strand-lifecycle-fsm")).await;
        assert_refused(
            &pool,
            &discussion.strand_id,
            scenario_future(|| {
                ordinary_realm::source_request(
                    &pool,
                    lifecycle(
                        &discussion.head.authority_commit,
                        &discussion.strand_id,
                        EventKind::StrandRestore,
                        1,
                    ),
                )
            })
            .await,
            "strand_not_archived",
        )
        .await;
        let mut archive = lifecycle(
            &discussion.head.authority_commit,
            &discussion.strand_id,
            EventKind::StrandArchive,
            2,
        );
        let accepted_at = archive.authority_commit.event.created_at + chrono::Duration::seconds(7);
        archive.authority_commit.commit.committed_at = accepted_at;
        archive.authority_commit.commit.signature =
            ordinary_realm::signature(&ordinary_realm::station(), accepted_at);
        archive.event.received_at = accepted_at;
        for projection in &mut archive.projections {
            projection.received_at = accepted_at;
        }
        let archive = scenario_future(|| ordinary_realm::source_request(&pool, archive)).await;
        let uow = PgEventCommitUnitOfWork::new(pool.clone());
        uow.commit_event(archive.clone()).await.unwrap();
        let archived = current(&pool, &discussion.strand_id).await;
        assert_eq!(archived.value["state"], "archived");
        assert_eq!(
            archived.value["state_changed_at"],
            arkret_canonical::format_timestamp_canonical(accepted_at)
        );
        assert_eq!(
            archived.value["updated_at"],
            archived.value["state_changed_at"]
        );
        assert_refused(
            &pool,
            &discussion.strand_id,
            scenario_future(|| {
                ordinary_realm::source_request(
                    &pool,
                    lifecycle(
                        &archive.authority_commit,
                        &discussion.strand_id,
                        EventKind::StrandArchive,
                        1,
                    ),
                )
            })
            .await,
            "strand_not_active",
        )
        .await;
        assert_refused(
            &pool,
            &discussion.strand_id,
            scenario_future(|| {
                ordinary_realm::source_request(
                    &pool,
                    stage(
                        &archive.authority_commit,
                        &discussion.strand_id,
                        "done",
                        None,
                        1,
                    ),
                )
            })
            .await,
            "strand_not_active",
        )
        .await;
        let restore = scenario_future(|| {
            ordinary_realm::source_request(
                &pool,
                lifecycle(
                    &archive.authority_commit,
                    &discussion.strand_id,
                    EventKind::StrandRestore,
                    2,
                ),
            )
        })
        .await;
        uow.commit_event(restore.clone()).await.unwrap();
        let restored = current(&pool, &discussion.strand_id).await;
        assert_eq!(restored.value["state"], "active");
        assert_eq!(
            restored.current_commit_id,
            restore.authority_commit.commit.commit_id.as_str()
        );
        let baseline = footprint(&pool).await;
        let reopened = PgEventCommitUnitOfWork::new(pool.clone());
        let reader = coland_storage_postgres::PgAuthorityCommitStore { pool: pool.clone() };
        for request in [archive, restore] {
            assert!(
                !reopened
                    .commit_event(request.clone())
                    .await
                    .unwrap()
                    .event_inserted
            );
            assert_eq!(
                reader
                    .committed_event(&request.authority_commit.event.event_id)
                    .await
                    .unwrap()
                    .unwrap()
                    .commit,
                request.authority_commit.commit
            );
        }
        assert_eq!(current(&pool, &discussion.strand_id).await, restored);
        assert_eq!(footprint(&pool).await, baseline);
    })
}

#[tokio::test]
async fn transition_actor_realm_and_scope_refusals_leave_no_durable_footprint() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let discussion = Box::pin(open_discussion(&pool, "strand-transition-gates")).await;
    let other = Box::pin(open_discussion(&pool, "strand-transition-other-realm")).await;
    let previous = &discussion.head.authority_commit;
    let outsider = Box::pin(ordinary_realm::human_profile::admit(
        &pool,
        &ordinary_realm::station(),
        "transition-outsider",
    ))
    .await;
    for actor in [ActorId::account(outsider)] {
        let request = ordinary_realm::next_human_request_for_actor(
            previous,
            EventKind::StrandStageSet,
            actor,
            json!({"strand_id":discussion.strand_id,"stage":"done"}),
            previous.commit.committed_at + chrono::Duration::seconds(1),
        );
        let request = Box::pin(ordinary_realm::source_request(&pool, request)).await;
        assert_refused(&pool, &discussion.strand_id, request, "capability_denied").await;
    }
    let (foreign_request, _origin_state) = Box::pin(foreign_station_stage_request(
        previous,
        &discussion.strand_id,
    ))
    .await;
    assert_refused(
        &pool,
        &discussion.strand_id,
        foreign_request,
        "capability_denied",
    )
    .await;
    assert_refused(
        &pool,
        &discussion.strand_id,
        Box::pin(ordinary_realm::source_request(
            &pool,
            stage(previous, &other.strand_id, "done", None, 2),
        ))
        .await,
        "target",
    )
    .await;
    let event = ordinary_realm::event(
        EventKind::StrandStageSet,
        arkret_wire::ScopeRef::Circle {
            realm_id: discussion.realm_id(),
            circle_id: arkret_wire::CircleId::from_event_id(&previous.event.event_id),
        },
        previous.event.actor_id.signing_principal_id(),
        &ordinary_realm::station(),
        json!({"strand_id":discussion.strand_id,"stage":"done"}),
        previous.commit.committed_at + chrono::Duration::seconds(3),
    );
    let request = ordinary_realm::request_for_event(
        previous,
        event,
        previous.commit.committed_at + chrono::Duration::seconds(3),
    );
    let request = Box::pin(ordinary_realm::source_request(&pool, request)).await;
    // The malformed request's Event scope does not match its Realm Commit;
    // either transaction validation or the writer must reject it before writes.
    Box::pin(assert_independent_scope_schema_refused(&pool, request)).await;
}

async fn assert_independent_scope_schema_refused(pool: &PgPool, request: EventCommitRequest) {
    let before = full_write_footprint(pool).await;
    let error = PgEventCommitUnitOfWork::new(pool.clone())
        .commit_event(request)
        .await
        .unwrap_err();
    let coland_storage::PersistenceError::SchemaViolation(detail) = error else {
        panic!("expected independent-scope schema violation, got {error:?}");
    };
    assert_eq!(
        detail,
        "wire validation failed: committed Event view must bind the exact Event and its independent scope stream"
    );
    assert_eq!(full_write_footprint(pool).await, before);
}

async fn foreign_station_stage_request(
    previous: &AuthorityCommitTransaction,
    strand: &StrandId,
) -> (EventCommitRequest, coland_http::state::AppState) {
    let mut config = coland_test_support::app_config();
    config.public_base_url = "https://other-transition-station.example".into();
    let (origin, origin_pool) = coland_test_support::app_state_with_pool(config);
    let account = Box::pin(ordinary_realm::human_profile::admit_for_station_did(
        &origin_pool,
        origin.service_did(),
        "ordinary-founder",
    ))
    .await;
    assert_eq!(
        &account.principal_id,
        previous.event.actor_id.signing_principal_id()
    );
    assert_ne!(account.station_id, ordinary_realm::station());
    let request = ordinary_realm::next_human_request_for_actor(
        previous,
        EventKind::StrandStageSet,
        ActorId::account(account.clone()),
        json!({"strand_id":strand,"stage":"done"}),
        previous.commit.committed_at + chrono::Duration::seconds(1),
    );
    let mut request = Box::pin(ordinary_realm::source_request(&origin_pool, request)).await;
    let evidence = Box::pin(coland_http::test_fresh_producer_device_evidence(
        &origin,
        &request.authority_commit.event,
        &previous.expected_authority.service_id,
    ))
    .await
    .unwrap()
    .unwrap();
    let core = &evidence.device_projection_attestation.attestation;
    let fact = arkret_identity::account_device_signer_evidence::verify_forwarded_human_signer_fact(
        &evidence,
        &request.authority_commit.event,
        &account.station_id,
        &previous.expected_authority.service_id,
        &core.event_authorization.forward_body_digest,
        arkret_canonical::DigestSuite::Sha256,
        core.attested_at,
    )
    .unwrap()
    .into_fact();
    request.authority_commit.producer_signer_fact = Some(fact.clone().into());
    request.authority_commit.commit.producer_signer_fact_digest = Some(fact.digest().unwrap());
    request.authority_commit.commit.committed_at = core.attested_at;
    request.self_producer_guard = None;
    request.forwarded_producer_evidence =
        Some(coland_storage::ForwardedProducerDeviceEvidence::new(evidence, fact).unwrap());
    request.realm_fanout_source = Some(arkret_wire::EventAdmissionSubmission::new(
        request.authority_commit.event.clone(),
    ));
    ordinary_realm::seal_final_commit(&mut request.authority_commit.commit);
    (request, origin)
}

#[tokio::test]
async fn transition_update_fault_rolls_back_event_commit_and_current_together() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let discussion = Box::pin(open_discussion(&pool, "strand-transition-fault")).await;
    let mut previous = discussion.head.authority_commit.clone();
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    for kind in [EventKind::StrandStageSet, EventKind::StrandArchive] {
        let request = if kind == EventKind::StrandStageSet {
            Box::pin(ordinary_realm::source_request(
                &pool,
                stage(&previous, &discussion.strand_id, "done", None, 1),
            ))
            .await
        } else {
            Box::pin(ordinary_realm::source_request(
                &pool,
                lifecycle(&previous, &discussion.strand_id, kind, 1),
            ))
            .await
        };
        let before = current(&pool, &discussion.strand_id).await;
        let baseline = footprint(&pool).await;
        let mut conn = pool.get().await.unwrap();
        conn.batch_execute("CREATE FUNCTION strand_transition_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'strand transition fault'; END $$; CREATE TRIGGER strand_transition_fault BEFORE UPDATE ON strand_current_results FOR EACH ROW EXECUTE FUNCTION strand_transition_fault();").await.unwrap();
        drop(conn);
        let result = uow.commit_event(request.clone()).await;
        let mut conn = pool.get().await.unwrap();
        conn.batch_execute("DROP TRIGGER strand_transition_fault ON strand_current_results; DROP FUNCTION strand_transition_fault();").await.unwrap();
        drop(conn);
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("strand transition fault")
        );
        assert_eq!(current(&pool, &discussion.strand_id).await, before);
        assert_eq!(footprint(&pool).await, baseline);
        assert!(
            uow.commit_event(request.clone())
                .await
                .unwrap()
                .event_inserted
        );
        assert_eq!(
            current(&pool, &discussion.strand_id)
                .await
                .current_commit_id,
            request.authority_commit.commit.commit_id.as_str()
        );
        previous = request.authority_commit;
    }
}

#[inline(never)]
fn scenario_future<F, Fut>(make: F) -> std::pin::Pin<Box<Fut>>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future,
{
    Box::pin(make())
}
