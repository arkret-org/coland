//! A real ordinary Realm cut drives Board/List placement; rejected writes
//! leave both the Realm stream and the typed-pair current result unchanged.

#[path = "support/ordinary_realm.rs"]
#[allow(dead_code)]
mod ordinary_realm;

use coland_storage::{AuthorityCommitStore, ConflictCode, EventCommitUnitOfWork};
use coland_storage_postgres::test_database::TestDatabase;
use coland_storage_postgres::{PgAuthorityCommitStore, PgEventCommitUnitOfWork, PgPool};
use diesel::sql_types::{BigInt, Jsonb, Text};
use diesel_async::RunQueryDsl;
use ordinary_realm::{next_request, open_discussion};
use serde_json::{Value, json};

fn founder() -> arkret_wire::DidCoreId {
    ordinary_realm::human_profile::account(&ordinary_realm::station(), "ordinary-founder")
        .principal_id
}

fn approval_account_label(seed: u8) -> String {
    format!("position-approver-{seed}")
}

fn native_approval_method(
    signature: arkret_wire::ApprovalSignature,
    seed: u8,
    station: &arkret_wire::DidCoreId,
) -> coland_storage::ApprovalHistoricalMethod {
    let fixture = ordinary_realm::human_profile::fixture(station, &approval_account_label(seed));
    let arkret_models_identity::principal_registration_anchor::PrincipalRegistrationAnchor::WebvhRegistration { log_entries, .. } =
        &fixture.history.registration_anchor;
    let log_entries = log_entries
        .iter()
        .map(|entry| serde_json::to_value(entry).unwrap())
        .collect::<Vec<_>>();
    let history =
        arkret_identity::verify_did_webvh_v1_chain(&fixture.history.did, &log_entries).unwrap();
    let selected = coland_services::identity::select_did_webvh_state_at(
        &fixture.history.did,
        &history,
        signature.input.approved_at,
    )
    .unwrap();
    let control =
        arkret_identity::principal_control::native_identity_control_key_from_verified_selection(
            &selected.did,
            &fixture.history.account.principal_id,
            &selected.update_keys,
            &signature.proof.verification_method,
            arkret_identity::principal_control::DirectIdentityControlPurpose::ApprovalSignature,
        )
        .unwrap();
    coland_storage::ApprovalHistoricalMethod {
        public_key: *control.public_key(),
        control_history: Some(json!({
            "did":selected.did,"version_id":selected.version_id,"log_head_digest":selected.log_head_digest,
            "update_keys":selected.update_keys,
            "verified_at":arkret_canonical::format_timestamp_canonical(signature.input.approved_at),
        })),
        signature,
        native_control: Some(control),
    }
}

#[derive(diesel::QueryableByName)]
struct Count {
    #[diesel(sql_type = BigInt)]
    count: i64,
}

#[derive(diesel::QueryableByName)]
struct Position {
    #[diesel(sql_type = Jsonb)]
    value: Value,
    #[diesel(sql_type = BigInt)]
    current_stream_position: i64,
}

async fn count(pool: &PgPool, realm: &arkret_wire::RealmId, table: &str) -> i64 {
    let mut conn = pool.get().await.unwrap();
    let row: Count = diesel::sql_query(format!(
        "SELECT COUNT(*) AS count FROM {table} WHERE realm_id=$1"
    ))
    .bind::<Text, _>(realm.as_str())
    .get_result(&mut conn)
    .await
    .unwrap();
    row.count
}

async fn position(
    pool: &PgPool,
    board: &arkret_wire::SpaceId,
    strand: &arkret_wire::StrandId,
) -> Position {
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query("SELECT value,current_stream_position FROM strand_position_current_states WHERE board_space_id=$1 AND strand_id=$2")
        .bind::<Text, _>(board.as_str()).bind::<Text, _>(strand.as_str())
        .get_result(&mut conn).await.unwrap()
}

fn space_payload(
    realm: &arkret_wire::RealmId,
    actor: &arkret_wire::ActorId,
    at: chrono::DateTime<chrono::Utc>,
    kind: &str,
    title: &str,
    parent: Option<&arkret_wire::SpaceId>,
    fields: Value,
) -> Value {
    let mut object = json!({"schema":"ak.schema.space.v1","realm_id":realm,
        "kind":kind,"title":title,"fields":fields,"created_by":actor,"created_at":at});
    if let Some(parent) = parent {
        object["parent_space_id"] = json!(parent);
    }
    json!({"object":object})
}

struct PlacementSetup {
    opened: ordinary_realm::Discussion,
    board_id: arkret_wire::SpaceId,
    list_a_id: arkret_wire::SpaceId,
    list_b_id: arkret_wire::SpaceId,
    list_b: coland_storage::EventCommitRequest,
}

async fn prepare_placement_setup(pool: &PgPool) -> PlacementSetup {
    let opened = Box::pin(open_discussion(&pool, "strand-position-authority")).await;
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let realm = opened.head.authority_commit.event.realm_id.clone();
    let actor = opened.head.authority_commit.event.actor_id.clone();
    let at = opened.head.authority_commit.commit.committed_at;
    let board = Box::pin(ordinary_realm::source_request(
        &pool,
        next_request(
            &opened.head.authority_commit,
            arkret_wire::EventKind::SpaceCreate,
            opened
                .head
                .authority_commit
                .event
                .actor_id
                .signing_principal_id(),
            space_payload(&realm, &actor, at, "board", "Board", None, json!({})),
            at,
        ),
    ))
    .await;
    let board_id = arkret_wire::SpaceId::from_event_id(&board.authority_commit.event.event_id);
    uow.commit_event(board.clone()).await.unwrap();
    let list_a = Box::pin(ordinary_realm::source_request(
        &pool,
        next_request(
            &board.authority_commit,
            arkret_wire::EventKind::SpaceCreate,
            opened
                .head
                .authority_commit
                .event
                .actor_id
                .signing_principal_id(),
            space_payload(
                &realm,
                &actor,
                at,
                "list",
                "A",
                Some(&board_id),
                json!({"wip_limit":1,"wip_limit_enforcement":"reject"}),
            ),
            at,
        ),
    ))
    .await;
    let list_a_id = arkret_wire::SpaceId::from_event_id(&list_a.authority_commit.event.event_id);
    uow.commit_event(list_a.clone()).await.unwrap();
    let list_b = Box::pin(ordinary_realm::source_request(
        &pool,
        next_request(
            &list_a.authority_commit,
            arkret_wire::EventKind::SpaceCreate,
            opened
                .head
                .authority_commit
                .event
                .actor_id
                .signing_principal_id(),
            space_payload(&realm, &actor, at, "list", "B", Some(&board_id), json!({})),
            at,
        ),
    ))
    .await;
    let list_b_id = arkret_wire::SpaceId::from_event_id(&list_b.authority_commit.event.event_id);
    uow.commit_event(list_b.clone()).await.unwrap();

    PlacementSetup {
        opened,
        board_id,
        list_a_id,
        list_b_id,
        list_b,
    }
}

async fn exercise_placement_cas_and_reorder(
    pool: &PgPool,
    setup: &PlacementSetup,
) -> coland_storage::EventCommitRequest {
    let opened = &setup.opened;
    let board_id = setup.board_id.clone();
    let list_a_id = setup.list_a_id.clone();
    let list_b_id = setup.list_b_id.clone();
    let list_b = &setup.list_b;
    let realm = opened.head.authority_commit.event.realm_id.clone();
    let at = opened.head.authority_commit.commit.committed_at;
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let first = Box::pin(ordinary_realm::source_request(
        &pool,
        next_request(
            &list_b.authority_commit,
            arkret_wire::EventKind::StrandMove,
            opened
                .head
                .authority_commit
                .event
                .actor_id
                .signing_principal_id(),
            json!({"board_space_id":board_id,"strand_id":opened.strand_id,
            "target_space_id":list_a_id,"rank":"a"}),
            at,
        ),
    ))
    .await;
    uow.commit_event(first.clone()).await.unwrap();
    let initial = position(&pool, &board_id, &opened.strand_id).await;
    assert_eq!(initial.value, json!({"list_space_id":list_a_id,"rank":"a"}));
    assert_eq!(
        initial.current_stream_position,
        first.authority_commit.commit.stream_position as i64
    );
    let first_counts = (
        count(&pool, &realm, "canonical_events").await,
        count(&pool, &realm, "realm_commits").await,
    );
    assert!(
        !uow.commit_event(first.clone())
            .await
            .unwrap()
            .event_inserted
    );
    assert_eq!(
        first_counts,
        (
            count(&pool, &realm, "canonical_events").await,
            count(&pool, &realm, "realm_commits").await,
        )
    );
    let replayed = position(&pool, &board_id, &opened.strand_id).await;
    assert_eq!(replayed.value, initial.value);
    assert_eq!(
        replayed.current_stream_position,
        initial.current_stream_position
    );

    let bad = Box::pin(ordinary_realm::source_request(
        &pool,
        next_request(
            &first.authority_commit,
            arkret_wire::EventKind::StrandReorder,
            opened
                .head
                .authority_commit
                .event
                .actor_id
                .signing_principal_id(),
            json!({"board_space_id":board_id,"strand_id":opened.strand_id,
            "space_id":list_a_id,"rank":"b",
            "expected_position":{"list_space_id":list_a_id,"rank":"stale"}}),
            at,
        ),
    ))
    .await;
    let events_before = count(&pool, &realm, "canonical_events").await;
    let commits_before = count(&pool, &realm, "realm_commits").await;
    assert_eq!(
        uow.commit_event(bad).await.unwrap_err().conflict_code(),
        Some(ConflictCode::FailedPrecondition)
    );
    assert_eq!(
        count(&pool, &realm, "canonical_events").await,
        events_before
    );
    assert_eq!(count(&pool, &realm, "realm_commits").await, commits_before);

    let stranger = Box::pin(ordinary_realm::human_profile::admit(
        &pool,
        &ordinary_realm::station(),
        "placement-stranger",
    ))
    .await;
    let unauthorized_move = Box::pin(ordinary_realm::source_request(
        &pool,
        next_request(
            &first.authority_commit,
            arkret_wire::EventKind::StrandMove,
            &stranger.principal_id,
            json!({"board_space_id":board_id,"strand_id":opened.strand_id,
            "from_space_id":list_a_id,"target_space_id":list_b_id,"rank":"a",
            "expected_position":{"list_space_id":list_a_id,"rank":"a"}}),
            at,
        ),
    ))
    .await;
    assert_eq!(
        uow.commit_event(unauthorized_move)
            .await
            .unwrap_err()
            .conflict_code(),
        Some(ConflictCode::CapabilityDenied)
    );
    assert_eq!(
        count(&pool, &realm, "canonical_events").await,
        events_before
    );
    assert_eq!(count(&pool, &realm, "realm_commits").await, commits_before);
    let refused = position(&pool, &board_id, &opened.strand_id).await;
    assert_eq!(refused.value, initial.value);
    assert_eq!(
        refused.current_stream_position,
        initial.current_stream_position
    );
    assert_eq!(
        position(&pool, &board_id, &opened.strand_id).await.value,
        initial.value
    );

    let unauthorized = Box::pin(ordinary_realm::source_request(
        &pool,
        next_request(
            &first.authority_commit,
            arkret_wire::EventKind::StrandReorder,
            &stranger.principal_id,
            json!({"board_space_id":board_id,"strand_id":opened.strand_id,
            "space_id":list_a_id,"rank":"unauthorized",
            "expected_position":{"list_space_id":list_a_id,"rank":"a"}}),
            at,
        ),
    ))
    .await;
    assert_eq!(
        uow.commit_event(unauthorized)
            .await
            .unwrap_err()
            .conflict_code(),
        Some(ConflictCode::CapabilityDenied)
    );
    assert_eq!(
        count(&pool, &realm, "canonical_events").await,
        events_before
    );
    assert_eq!(count(&pool, &realm, "realm_commits").await, commits_before);

    let reordered = Box::pin(ordinary_realm::source_request(
        &pool,
        next_request(
            &first.authority_commit,
            arkret_wire::EventKind::StrandReorder,
            opened
                .head
                .authority_commit
                .event
                .actor_id
                .signing_principal_id(),
            json!({"board_space_id":board_id,"strand_id":opened.strand_id,
            "space_id":list_a_id,"rank":"b",
            "expected_position":{"list_space_id":list_a_id,"rank":"a"}}),
            at,
        ),
    ))
    .await;
    uow.commit_event(reordered.clone()).await.unwrap();
    assert_eq!(
        position(&pool, &board_id, &opened.strand_id).await.value,
        json!({"list_space_id":list_a_id,"rank":"b"})
    );
    let reordered_counts = (
        count(&pool, &realm, "canonical_events").await,
        count(&pool, &realm, "realm_commits").await,
    );
    assert!(
        !uow.commit_event(reordered.clone())
            .await
            .unwrap()
            .event_inserted
    );
    assert_eq!(
        reordered_counts,
        (
            count(&pool, &realm, "canonical_events").await,
            count(&pool, &realm, "realm_commits").await,
        )
    );
    let replayed = position(&pool, &board_id, &opened.strand_id).await;
    assert_eq!(
        replayed.value,
        json!({"list_space_id":list_a_id,"rank":"b"})
    );
    assert_eq!(
        replayed.current_stream_position,
        reordered.authority_commit.commit.stream_position as i64
    );

    reordered
}

async fn exercise_placement_wip_postimage(
    pool: &PgPool,
    setup: &PlacementSetup,
    reordered: coland_storage::EventCommitRequest,
) {
    let opened = &setup.opened;
    let board_id = setup.board_id.clone();
    let list_a_id = setup.list_a_id.clone();
    let list_b_id = setup.list_b_id.clone();
    let realm = opened.head.authority_commit.event.realm_id.clone();
    let actor = opened.head.authority_commit.event.actor_id.clone();
    let at = opened.head.authority_commit.commit.committed_at;
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let second_strand = Box::pin(ordinary_realm::source_request(
        &pool,
        next_request(
            &reordered.authority_commit,
            arkret_wire::EventKind::StrandCreate,
            opened
                .head
                .authority_commit
                .event
                .actor_id
                .signing_principal_id(),
            json!({"object":{"schema":"ak.schema.strand.v1","realm_id":realm,
            "tracks":{"discussion":{"is_primary":true,"profile":"discussion"}},
            "metadata":{"title":"Second"},"state":"active","created_by":actor,
            "created_at":arkret_canonical::format_timestamp_canonical(at)}}),
            at,
        ),
    ))
    .await;
    let second_id =
        arkret_wire::StrandId::from_event_id(&second_strand.authority_commit.event.event_id);
    uow.commit_event(second_strand.clone()).await.unwrap();
    let over_wip = Box::pin(ordinary_realm::source_request(
        &pool,
        next_request(
            &second_strand.authority_commit,
            arkret_wire::EventKind::StrandMove,
            opened
                .head
                .authority_commit
                .event
                .actor_id
                .signing_principal_id(),
            json!({"board_space_id":board_id,"strand_id":second_id,
            "target_space_id":list_a_id,"rank":"c"}),
            at,
        ),
    ))
    .await;
    let before = (
        count(&pool, &realm, "canonical_events").await,
        count(&pool, &realm, "realm_commits").await,
    );
    assert_eq!(
        uow.commit_event(over_wip)
            .await
            .unwrap_err()
            .conflict_code(),
        Some(ConflictCode::FailedPrecondition)
    );
    assert_eq!(
        before,
        (
            count(&pool, &realm, "canonical_events").await,
            count(&pool, &realm, "realm_commits").await
        )
    );

    let move_out = Box::pin(ordinary_realm::source_request(
        &pool,
        next_request(
            &second_strand.authority_commit,
            arkret_wire::EventKind::StrandMove,
            opened
                .head
                .authority_commit
                .event
                .actor_id
                .signing_principal_id(),
            json!({"board_space_id":board_id,"strand_id":opened.strand_id,
            "from_space_id":list_a_id,"target_space_id":list_b_id,"rank":"a",
            "expected_position":{"list_space_id":list_a_id,"rank":"b"}}),
            at,
        ),
    ))
    .await;
    uow.commit_event(move_out.clone()).await.unwrap();
    let now_fits = Box::pin(ordinary_realm::source_request(
        &pool,
        next_request(
            &move_out.authority_commit,
            arkret_wire::EventKind::StrandMove,
            opened
                .head
                .authority_commit
                .event
                .actor_id
                .signing_principal_id(),
            json!({"board_space_id":board_id,"strand_id":second_id,
            "target_space_id":list_a_id,"rank":"a"}),
            at,
        ),
    ))
    .await;
    uow.commit_event(now_fits.clone()).await.unwrap();
    assert_eq!(
        position(&pool, &board_id, &second_id).await.value,
        json!({"list_space_id":list_a_id,"rank":"a"})
    );
}

#[tokio::test]
async fn placement_has_whole_position_cas_reorder_and_postimage_wip_at_accepting_cut() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let setup = Box::pin(prepare_placement_setup(&pool)).await;
    let reordered = Box::pin(exercise_placement_cas_and_reorder(&pool, &setup)).await;
    Box::pin(exercise_placement_wip_postimage(&pool, &setup, reordered)).await;
}

struct WipWarnSetup {
    opened: ordinary_realm::Discussion,
    board_id: arkret_wire::SpaceId,
    warn_id: arkret_wire::SpaceId,
    review_id: arkret_wire::SpaceId,
    second_id: arkret_wire::StrandId,
    second_strand: coland_storage::EventCommitRequest,
}

async fn prepare_wip_warn_setup(pool: &PgPool) -> WipWarnSetup {
    let opened = Box::pin(open_discussion(&pool, "strand-position-wip-enforcement")).await;
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let realm = opened.head.authority_commit.event.realm_id.clone();
    let actor = opened.head.authority_commit.event.actor_id.clone();
    let at = opened.head.authority_commit.commit.committed_at;
    let board = Box::pin(ordinary_realm::source_request(
        &pool,
        next_request(
            &opened.head.authority_commit,
            arkret_wire::EventKind::SpaceCreate,
            opened
                .head
                .authority_commit
                .event
                .actor_id
                .signing_principal_id(),
            space_payload(&realm, &actor, at, "board", "Board", None, json!({})),
            at,
        ),
    ))
    .await;
    let board_id = arkret_wire::SpaceId::from_event_id(&board.authority_commit.event.event_id);
    uow.commit_event(board.clone()).await.unwrap();
    let warn_list = Box::pin(ordinary_realm::source_request(
        &pool,
        next_request(
            &board.authority_commit,
            arkret_wire::EventKind::SpaceCreate,
            opened
                .head
                .authority_commit
                .event
                .actor_id
                .signing_principal_id(),
            space_payload(
                &realm,
                &actor,
                at,
                "list",
                "Warn",
                Some(&board_id),
                json!({"wip_limit":1,"wip_limit_enforcement":"warn"}),
            ),
            at,
        ),
    ))
    .await;
    let warn_id = arkret_wire::SpaceId::from_event_id(&warn_list.authority_commit.event.event_id);
    uow.commit_event(warn_list.clone()).await.unwrap();
    let review_list = Box::pin(ordinary_realm::source_request(
        &pool,
        next_request(
            &warn_list.authority_commit,
            arkret_wire::EventKind::SpaceCreate,
            opened
                .head
                .authority_commit
                .event
                .actor_id
                .signing_principal_id(),
            space_payload(
                &realm,
                &actor,
                at,
                "list",
                "Review",
                Some(&board_id),
                json!({"wip_limit":1,"wip_limit_enforcement":"require_review"}),
            ),
            at,
        ),
    ))
    .await;
    let review_id =
        arkret_wire::SpaceId::from_event_id(&review_list.authority_commit.event.event_id);
    uow.commit_event(review_list.clone()).await.unwrap();
    let second_strand = Box::pin(ordinary_realm::source_request(
        &pool,
        next_request(
            &review_list.authority_commit,
            arkret_wire::EventKind::StrandCreate,
            opened
                .head
                .authority_commit
                .event
                .actor_id
                .signing_principal_id(),
            json!({"object":{"schema":"ak.schema.strand.v1","realm_id":realm,
            "tracks":{"discussion":{"is_primary":true,"profile":"discussion"}},
            "metadata":{"title":"Second"},"state":"active","created_by":actor,
            "created_at":arkret_canonical::format_timestamp_canonical(at)}}),
            at,
        ),
    ))
    .await;
    let second_id =
        arkret_wire::StrandId::from_event_id(&second_strand.authority_commit.event.event_id);
    uow.commit_event(second_strand.clone()).await.unwrap();

    WipWarnSetup {
        opened,
        board_id,
        warn_id,
        review_id,
        second_id,
        second_strand,
    }
}

async fn exercise_wip_warn_and_review(pool: &PgPool, setup: &WipWarnSetup) {
    let opened = &setup.opened;
    let board_id = setup.board_id.clone();
    let warn_id = setup.warn_id.clone();
    let review_id = setup.review_id.clone();
    let second_id = setup.second_id.clone();
    let second_strand = &setup.second_strand;
    let realm = opened.head.authority_commit.event.realm_id.clone();
    let at = opened.head.authority_commit.commit.committed_at;
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let warn_first = Box::pin(ordinary_realm::source_request(
        &pool,
        next_request(
            &second_strand.authority_commit,
            arkret_wire::EventKind::StrandMove,
            opened
                .head
                .authority_commit
                .event
                .actor_id
                .signing_principal_id(),
            json!({"board_space_id":board_id,"strand_id":opened.strand_id,
            "target_space_id":warn_id,"rank":"a"}),
            at,
        ),
    ))
    .await;
    uow.commit_event(warn_first.clone()).await.unwrap();
    let warn_over_limit = Box::pin(ordinary_realm::source_request(
        &pool,
        next_request(
            &warn_first.authority_commit,
            arkret_wire::EventKind::StrandMove,
            opened
                .head
                .authority_commit
                .event
                .actor_id
                .signing_principal_id(),
            json!({"board_space_id":board_id,"strand_id":second_id,
            "target_space_id":warn_id,"rank":"b"}),
            at,
        ),
    ))
    .await;
    uow.commit_event(warn_over_limit.clone()).await.unwrap();
    assert_eq!(
        position(&pool, &board_id, &second_id).await.value,
        json!({"list_space_id":warn_id,"rank":"b"})
    );

    let review_first = Box::pin(ordinary_realm::source_request(
        &pool,
        next_request(
            &warn_over_limit.authority_commit,
            arkret_wire::EventKind::StrandMove,
            opened
                .head
                .authority_commit
                .event
                .actor_id
                .signing_principal_id(),
            json!({"board_space_id":board_id,"strand_id":opened.strand_id,
            "from_space_id":warn_id,"target_space_id":review_id,"rank":"a",
            "expected_position":{"list_space_id":warn_id,"rank":"a"}}),
            at,
        ),
    ))
    .await;
    uow.commit_event(review_first.clone()).await.unwrap();
    let review_over_limit = Box::pin(ordinary_realm::source_request(
        &pool,
        next_request(
            &review_first.authority_commit,
            arkret_wire::EventKind::StrandMove,
            opened
                .head
                .authority_commit
                .event
                .actor_id
                .signing_principal_id(),
            json!({"board_space_id":board_id,"strand_id":second_id,
            "from_space_id":warn_id,"target_space_id":review_id,"rank":"b",
            "expected_position":{"list_space_id":warn_id,"rank":"b"}}),
            at,
        ),
    ))
    .await;
    let before = (
        count(&pool, &realm, "canonical_events").await,
        count(&pool, &realm, "realm_commits").await,
    );
    assert_eq!(
        uow.commit_event(review_over_limit)
            .await
            .unwrap_err()
            .conflict_code(),
        Some(ConflictCode::ApprovalRequired)
    );
    assert_eq!(
        before,
        (
            count(&pool, &realm, "canonical_events").await,
            count(&pool, &realm, "realm_commits").await
        )
    );
    assert_eq!(
        position(&pool, &board_id, &second_id).await.value,
        json!({"list_space_id":warn_id,"rank":"b"})
    );
}

#[tokio::test]
async fn wip_warn_accepts_but_require_review_without_proof_refuses_without_writes() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let setup = Box::pin(prepare_wip_warn_setup(&pool)).await;
    Box::pin(exercise_wip_warn_and_review(&pool, &setup)).await;
}

struct WipOverrideSetup {
    opened: ordinary_realm::Discussion,
    board_id: arkret_wire::SpaceId,
    list_a_id: arkret_wire::SpaceId,
    list_b_id: arkret_wire::SpaceId,
    second_id: arkret_wire::StrandId,
    second_placed: coland_storage::EventCommitRequest,
}

async fn prepare_wip_override_setup(pool: &PgPool) -> WipOverrideSetup {
    let opened = Box::pin(open_discussion(&pool, "strand-position-wip-override")).await;
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let realm = opened.head.authority_commit.event.realm_id.clone();
    let actor = opened.head.authority_commit.event.actor_id.clone();
    let at = opened.head.authority_commit.commit.committed_at;
    let board = Box::pin(ordinary_realm::source_request(
        &pool,
        next_request(
            &opened.head.authority_commit,
            arkret_wire::EventKind::SpaceCreate,
            opened
                .head
                .authority_commit
                .event
                .actor_id
                .signing_principal_id(),
            space_payload(&realm, &actor, at, "board", "Board", None, json!({})),
            at,
        ),
    ))
    .await;
    let board_id = arkret_wire::SpaceId::from_event_id(&board.authority_commit.event.event_id);
    uow.commit_event(board.clone()).await.unwrap();
    let list_a = Box::pin(ordinary_realm::source_request(
        &pool,
        next_request(
            &board.authority_commit,
            arkret_wire::EventKind::SpaceCreate,
            opened
                .head
                .authority_commit
                .event
                .actor_id
                .signing_principal_id(),
            space_payload(
                &realm,
                &actor,
                at,
                "list",
                "A",
                Some(&board_id),
                json!({"wip_limit":1,"wip_limit_enforcement":"reject"}),
            ),
            at,
        ),
    ))
    .await;
    let list_a_id = arkret_wire::SpaceId::from_event_id(&list_a.authority_commit.event.event_id);
    uow.commit_event(list_a.clone()).await.unwrap();
    let list_b = Box::pin(ordinary_realm::source_request(
        &pool,
        next_request(
            &list_a.authority_commit,
            arkret_wire::EventKind::SpaceCreate,
            opened
                .head
                .authority_commit
                .event
                .actor_id
                .signing_principal_id(),
            space_payload(
                &realm,
                &actor,
                at,
                "list",
                "B",
                Some(&board_id),
                json!({"wip_limit":1,"wip_limit_enforcement":"reject"}),
            ),
            at,
        ),
    ))
    .await;
    let list_b_id = arkret_wire::SpaceId::from_event_id(&list_b.authority_commit.event.event_id);
    uow.commit_event(list_b.clone()).await.unwrap();
    let second_strand = Box::pin(ordinary_realm::source_request(
        &pool,
        next_request(
            &list_b.authority_commit,
            arkret_wire::EventKind::StrandCreate,
            opened
                .head
                .authority_commit
                .event
                .actor_id
                .signing_principal_id(),
            json!({"object":{"schema":"ak.schema.strand.v1","realm_id":realm,
            "tracks":{"discussion":{"is_primary":true,"profile":"discussion"}},
            "metadata":{"title":"Second"},"state":"active","created_by":actor,
            "created_at":arkret_canonical::format_timestamp_canonical(at)}}),
            at,
        ),
    ))
    .await;
    let second_id =
        arkret_wire::StrandId::from_event_id(&second_strand.authority_commit.event.event_id);
    uow.commit_event(second_strand.clone()).await.unwrap();
    let first_placed = Box::pin(ordinary_realm::source_request(
        &pool,
        next_request(
            &second_strand.authority_commit,
            arkret_wire::EventKind::StrandMove,
            opened
                .head
                .authority_commit
                .event
                .actor_id
                .signing_principal_id(),
            json!({"board_space_id":board_id,"strand_id":opened.strand_id,
            "target_space_id":list_a_id,"rank":"a"}),
            at,
        ),
    ))
    .await;
    uow.commit_event(first_placed.clone()).await.unwrap();
    let second_placed = Box::pin(ordinary_realm::source_request(
        &pool,
        next_request(
            &first_placed.authority_commit,
            arkret_wire::EventKind::StrandMove,
            opened
                .head
                .authority_commit
                .event
                .actor_id
                .signing_principal_id(),
            json!({"board_space_id":board_id,"strand_id":second_id,
            "target_space_id":list_b_id,"rank":"a"}),
            at,
        ),
    ))
    .await;
    uow.commit_event(second_placed.clone()).await.unwrap();

    WipOverrideSetup {
        opened,
        board_id,
        list_a_id,
        list_b_id,
        second_id,
        second_placed,
    }
}

async fn exercise_wip_override_resource_grants(
    pool: &PgPool,
    setup: &WipOverrideSetup,
) -> coland_storage::EventCommitRequest {
    let opened = &setup.opened;
    let board_id = setup.board_id.clone();
    let list_a_id = setup.list_a_id.clone();
    let list_b_id = setup.list_b_id.clone();
    let second_id = setup.second_id.clone();
    let realm = opened.head.authority_commit.event.realm_id.clone();
    let at = opened.head.authority_commit.commit.committed_at;
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let actor = opened.head.authority_commit.event.actor_id.clone();
    let second_placed = &setup.second_placed;
    let grant_payload = json!({"grant":{
        "schema":"ak.schema.capability.v1",
        "realm_id":realm,
        "issuer_id":actor,
        "subject":actor,
        "actions":["ak.strand.move"],
        "resources":[arkret_wire::WireResourceSelector::strand(realm.clone(), second_id.clone())],
        "constraints":[{
            "constraint_kind":"scope_limitation","effect":"allow",
            "allowed_to_container_refs":[list_a_id],
            "wip_limit_override_allowed":true
        }],
        "issuer_authority_refs":[{
            "kind":"realm_root","realm_id":realm,
            "authority_event_ref":opened.unit.transactions[0].event.event_id,
            "authority_generation":"0"
        }],
        "issued_at":arkret_canonical::format_timestamp_canonical(at)
    }});
    let mut conflicting_payload = grant_payload.clone();
    conflicting_payload["grant"]["constraints"]
        .as_array_mut()
        .unwrap()
        .push(
            json!({"constraint_kind":"scope_limitation","effect":"allow",
            "wip_limit_override_allowed":false}),
        );
    let conflicting_grant = Box::pin(ordinary_realm::source_request(
        &pool,
        next_request(
            &second_placed.authority_commit,
            arkret_wire::EventKind::CapabilityGrant,
            opened
                .head
                .authority_commit
                .event
                .actor_id
                .signing_principal_id(),
            conflicting_payload,
            at,
        ),
    ))
    .await;
    uow.commit_event(conflicting_grant.clone()).await.unwrap();
    let conflicting_move = Box::pin(ordinary_realm::source_request(
        &pool,
        next_request(
            &conflicting_grant.authority_commit,
            arkret_wire::EventKind::StrandMove,
            opened
                .head
                .authority_commit
                .event
                .actor_id
                .signing_principal_id(),
            json!({"board_space_id":board_id,"strand_id":second_id,
            "from_space_id":list_b_id,"target_space_id":list_a_id,"rank":"b",
            "expected_position":{"list_space_id":list_b_id,"rank":"a"}}),
            at,
        ),
    ))
    .await;
    let before = (
        count(&pool, &realm, "canonical_events").await,
        count(&pool, &realm, "realm_commits").await,
    );
    assert_eq!(
        uow.commit_event(conflicting_move)
            .await
            .unwrap_err()
            .conflict_code(),
        Some(ConflictCode::FailedPrecondition)
    );
    assert_eq!(
        before,
        (
            count(&pool, &realm, "canonical_events").await,
            count(&pool, &realm, "realm_commits").await
        )
    );
    let override_grant = Box::pin(ordinary_realm::source_request(
        &pool,
        next_request(
            &conflicting_grant.authority_commit,
            arkret_wire::EventKind::CapabilityGrant,
            opened
                .head
                .authority_commit
                .event
                .actor_id
                .signing_principal_id(),
            grant_payload.clone(),
            at,
        ),
    ))
    .await;
    uow.commit_event(override_grant.clone()).await.unwrap();

    // Root ownership admits ordinary moves, but the narrow grant cannot
    // override WIP for another Strand or destination List.
    let wrong_target = Box::pin(ordinary_realm::source_request(
        &pool,
        next_request(
            &override_grant.authority_commit,
            arkret_wire::EventKind::StrandMove,
            opened
                .head
                .authority_commit
                .event
                .actor_id
                .signing_principal_id(),
            json!({"board_space_id":board_id,"strand_id":opened.strand_id,
            "from_space_id":list_a_id,"target_space_id":list_b_id,"rank":"b",
            "expected_position":{"list_space_id":list_a_id,"rank":"a"}}),
            at,
        ),
    ))
    .await;
    let before = (
        count(&pool, &realm, "canonical_events").await,
        count(&pool, &realm, "realm_commits").await,
    );
    assert_eq!(
        uow.commit_event(wrong_target)
            .await
            .unwrap_err()
            .conflict_code(),
        Some(ConflictCode::FailedPrecondition)
    );
    assert_eq!(
        before,
        (
            count(&pool, &realm, "canonical_events").await,
            count(&pool, &realm, "realm_commits").await
        )
    );

    override_grant
}

async fn exercise_wip_override_global_deny(
    pool: &PgPool,
    setup: &WipOverrideSetup,
    override_grant: &coland_storage::EventCommitRequest,
) -> coland_storage::EventCommitRequest {
    let opened = &setup.opened;
    let board_id = setup.board_id.clone();
    let list_a_id = setup.list_a_id.clone();
    let list_b_id = setup.list_b_id.clone();
    let second_id = setup.second_id.clone();
    let realm = opened.head.authority_commit.event.realm_id.clone();
    let at = opened.head.authority_commit.commit.committed_at;
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let actor = opened.head.authority_commit.event.actor_id.clone();
    let grant_payload = json!({"grant":{
        "schema":"ak.schema.capability.v1",
        "realm_id":realm,
        "issuer_id":actor,
        "subject":actor,
        "actions":["ak.strand.move"],
        "resources":[arkret_wire::WireResourceSelector::strand(realm.clone(), second_id.clone())],
        "constraints":[{
            "constraint_kind":"scope_limitation","effect":"allow",
            "allowed_to_container_refs":[list_a_id],
            "wip_limit_override_allowed":true
        }],
        "issuer_authority_refs":[{
            "kind":"realm_root","realm_id":realm,
            "authority_event_ref":opened.unit.transactions[0].event.event_id,
            "authority_generation":"0"
        }],
        "issued_at":arkret_canonical::format_timestamp_canonical(at)
    }});
    // A different matching grant's deny is global and wins over the
    // satisfying override grant.
    let mut denial_payload = grant_payload;
    denial_payload["grant"]["constraints"] = json!([{
        "constraint_kind":"scope_limitation","effect":"deny",
        "denied_space_ids":[list_a_id]
    }]);
    let denial_grant = Box::pin(ordinary_realm::source_request(
        &pool,
        next_request(
            &override_grant.authority_commit,
            arkret_wire::EventKind::CapabilityGrant,
            opened
                .head
                .authority_commit
                .event
                .actor_id
                .signing_principal_id(),
            denial_payload,
            at,
        ),
    ))
    .await;
    uow.commit_event(denial_grant.clone()).await.unwrap();
    let denied_by_other_grant = Box::pin(ordinary_realm::source_request(
        &pool,
        next_request(
            &denial_grant.authority_commit,
            arkret_wire::EventKind::StrandMove,
            opened
                .head
                .authority_commit
                .event
                .actor_id
                .signing_principal_id(),
            json!({"board_space_id":board_id,"strand_id":second_id,
            "from_space_id":list_b_id,"target_space_id":list_a_id,"rank":"b",
            "expected_position":{"list_space_id":list_b_id,"rank":"a"}}),
            at,
        ),
    ))
    .await;
    let before = (
        count(&pool, &realm, "canonical_events").await,
        count(&pool, &realm, "realm_commits").await,
    );
    assert_eq!(
        uow.commit_event(denied_by_other_grant)
            .await
            .unwrap_err()
            .conflict_code(),
        Some(ConflictCode::CapabilityDenied)
    );
    assert_eq!(
        before,
        (
            count(&pool, &realm, "canonical_events").await,
            count(&pool, &realm, "realm_commits").await
        )
    );
    let denial_revoked = Box::pin(ordinary_realm::source_request(
        &pool,
        next_request(
            &denial_grant.authority_commit,
            arkret_wire::EventKind::CapabilityRevoke,
            opened
                .head
                .authority_commit
                .event
                .actor_id
                .signing_principal_id(),
            json!({"grant_id":arkret_wire::GrantId::from_event_id(
            &denial_grant.authority_commit.event.event_id),
            "expected_revision":{
                "commit_id":denial_grant.authority_commit.commit.commit_id,
                "stream_position":denial_grant.authority_commit.commit.stream_position
            }}),
            at,
        ),
    ))
    .await;
    uow.commit_event(denial_revoked.clone()).await.unwrap();

    let override_move = Box::pin(ordinary_realm::source_request(
        &pool,
        next_request(
            &denial_revoked.authority_commit,
            arkret_wire::EventKind::StrandMove,
            opened
                .head
                .authority_commit
                .event
                .actor_id
                .signing_principal_id(),
            json!({"board_space_id":board_id,"strand_id":second_id,
            "from_space_id":list_b_id,"target_space_id":list_a_id,"rank":"b",
            "expected_position":{"list_space_id":list_b_id,"rank":"a"}}),
            at,
        ),
    ))
    .await;
    uow.commit_event(override_move.clone()).await.unwrap();
    assert_eq!(
        position(&pool, &board_id, &second_id).await.value,
        json!({"list_space_id":list_a_id,"rank":"b"})
    );

    override_move
}

async fn exercise_wip_after_override_revocation(
    pool: &PgPool,
    setup: &WipOverrideSetup,
    override_grant: &coland_storage::EventCommitRequest,
    override_move: &coland_storage::EventCommitRequest,
) {
    let opened = &setup.opened;
    let board_id = setup.board_id.clone();
    let list_a_id = setup.list_a_id.clone();
    let list_b_id = setup.list_b_id.clone();
    let second_id = setup.second_id.clone();
    let realm = opened.head.authority_commit.event.realm_id.clone();
    let at = opened.head.authority_commit.commit.committed_at;
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let revoked = Box::pin(ordinary_realm::source_request(
        &pool,
        next_request(
            &override_move.authority_commit,
            arkret_wire::EventKind::CapabilityRevoke,
            opened
                .head
                .authority_commit
                .event
                .actor_id
                .signing_principal_id(),
            json!({"grant_id":arkret_wire::GrantId::from_event_id(
                &override_grant.authority_commit.event.event_id),
            "expected_revision":{
                "commit_id":override_grant.authority_commit.commit.commit_id,
                "stream_position":override_grant.authority_commit.commit.stream_position
            }}),
            at,
        ),
    ))
    .await;
    uow.commit_event(revoked.clone()).await.unwrap();
    let move_out = Box::pin(ordinary_realm::source_request(
        &pool,
        next_request(
            &revoked.authority_commit,
            arkret_wire::EventKind::StrandMove,
            opened
                .head
                .authority_commit
                .event
                .actor_id
                .signing_principal_id(),
            json!({"board_space_id":board_id,"strand_id":second_id,
            "from_space_id":list_a_id,"target_space_id":list_b_id,"rank":"a",
            "expected_position":{"list_space_id":list_a_id,"rank":"b"}}),
            at,
        ),
    ))
    .await;
    uow.commit_event(move_out.clone()).await.unwrap();
    let after_revocation = Box::pin(ordinary_realm::source_request(
        &pool,
        next_request(
            &move_out.authority_commit,
            arkret_wire::EventKind::StrandMove,
            opened
                .head
                .authority_commit
                .event
                .actor_id
                .signing_principal_id(),
            json!({"board_space_id":board_id,"strand_id":second_id,
            "from_space_id":list_b_id,"target_space_id":list_a_id,"rank":"c",
            "expected_position":{"list_space_id":list_b_id,"rank":"a"}}),
            at,
        ),
    ))
    .await;
    let before = (
        count(&pool, &realm, "canonical_events").await,
        count(&pool, &realm, "realm_commits").await,
    );
    assert_eq!(
        uow.commit_event(after_revocation)
            .await
            .unwrap_err()
            .conflict_code(),
        Some(ConflictCode::FailedPrecondition)
    );
    assert_eq!(
        before,
        (
            count(&pool, &realm, "canonical_events").await,
            count(&pool, &realm, "realm_commits").await
        )
    );
    assert_eq!(
        position(&pool, &board_id, &second_id).await.value,
        json!({"list_space_id":list_b_id,"rank":"a"})
    );
}

#[tokio::test]
async fn wip_override_requires_a_current_grant_matching_the_strand_and_destination() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let fixture_pool = pool.clone();
    let setup =
        tokio::spawn(
            async move { Box::new(Box::pin(prepare_wip_override_setup(&fixture_pool)).await) },
        )
        .await
        .unwrap();
    let grant = Box::pin(exercise_wip_override_resource_grants(&pool, &setup)).await;
    let moved = Box::pin(exercise_wip_override_global_deny(&pool, &setup, &grant)).await;
    Box::pin(exercise_wip_after_override_revocation(
        &pool, &setup, &grant, &moved,
    ))
    .await;
}

#[path = "support/approval_wip_cases.rs"]
mod approval_wip_cases;
#[path = "support/grant_approval_cases.rs"]
mod grant_approval_cases;

#[tokio::test]
async fn terminal_target_keeps_canonical_position_without_breaking_the_joined_read() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let opened = Box::pin(open_discussion(&pool, "strand-position-joined-view")).await;
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let realm = opened.head.authority_commit.event.realm_id.clone();
    let actor = opened.head.authority_commit.event.actor_id.clone();
    let at = opened.head.authority_commit.commit.committed_at;
    let board = Box::pin(ordinary_realm::source_request(
        &pool,
        next_request(
            &opened.head.authority_commit,
            arkret_wire::EventKind::SpaceCreate,
            opened
                .head
                .authority_commit
                .event
                .actor_id
                .signing_principal_id(),
            space_payload(&realm, &actor, at, "board", "Board", None, json!({})),
            at,
        ),
    ))
    .await;
    let board_id = arkret_wire::SpaceId::from_event_id(&board.authority_commit.event.event_id);
    uow.commit_event(board.clone()).await.unwrap();
    let list_a = Box::pin(ordinary_realm::source_request(
        &pool,
        next_request(
            &board.authority_commit,
            arkret_wire::EventKind::SpaceCreate,
            opened
                .head
                .authority_commit
                .event
                .actor_id
                .signing_principal_id(),
            space_payload(
                &realm,
                &actor,
                at,
                "list",
                "A",
                Some(&board_id),
                json!({"wip_limit":1,"wip_limit_enforcement":"reject"}),
            ),
            at,
        ),
    ))
    .await;
    let list_a_id = arkret_wire::SpaceId::from_event_id(&list_a.authority_commit.event.event_id);
    uow.commit_event(list_a.clone()).await.unwrap();
    let list_b = Box::pin(ordinary_realm::source_request(
        &pool,
        next_request(
            &list_a.authority_commit,
            arkret_wire::EventKind::SpaceCreate,
            opened
                .head
                .authority_commit
                .event
                .actor_id
                .signing_principal_id(),
            space_payload(&realm, &actor, at, "list", "B", Some(&board_id), json!({})),
            at,
        ),
    ))
    .await;
    uow.commit_event(list_b.clone()).await.unwrap();

    let first = Box::pin(ordinary_realm::source_request(
        &pool,
        next_request(
            &list_b.authority_commit,
            arkret_wire::EventKind::StrandMove,
            opened
                .head
                .authority_commit
                .event
                .actor_id
                .signing_principal_id(),
            json!({"board_space_id":board_id,"strand_id":opened.strand_id,
            "target_space_id":list_a_id,"rank":"a"}),
            at,
        ),
    ))
    .await;
    uow.commit_event(first.clone()).await.unwrap();
    let initial = position(&pool, &board_id, &opened.strand_id).await;
    assert_eq!(initial.value, json!({"list_space_id":list_a_id,"rank":"a"}));
    assert_eq!(
        initial.current_stream_position,
        first.authority_commit.commit.stream_position as i64
    );

    let store = PgAuthorityCommitStore { pool: pool.clone() };
    let caller = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        opened
            .head
            .authority_commit
            .event
            .actor_id
            .signing_principal_id()
            .clone(),
        ordinary_realm::station(),
    ));
    let events_before = count(&pool, &realm, "canonical_events").await;
    let commits_before = count(&pool, &realm, "realm_commits").await;
    for target in [&list_a_id, &board_id] {
        // Assemble a joined-current read fixture; this does not claim that a
        // latest-cut tombstone with observed dependents is admissible.
        let mut conn = pool.get().await.unwrap();
        let metadata: Position = diesel::sql_query(
            "SELECT value,current_stream_position FROM space_current_states WHERE space_id=$1",
        )
        .bind::<Text, _>(target.as_str())
        .get_result(&mut conn)
        .await
        .unwrap();
        let mut terminal = metadata.value.clone();
        terminal["state"] = json!("tombstoned");
        terminal["state_changed_at"] = json!(arkret_canonical::format_timestamp_canonical(at));
        diesel::sql_query("UPDATE space_current_states SET value=$2 WHERE space_id=$1")
            .bind::<Text, _>(target.as_str())
            .bind::<Jsonb, _>(&terminal)
            .execute(&mut conn)
            .await
            .unwrap();
        drop(conn);
        for include_terminal in [false, true] {
            let (_, strands) = store
                .object_projection_lists_for_actor(&realm, &caller, include_terminal)
                .await
                .expect("terminal placement targets leave the remaining joined read available")
                .unwrap();
            let strand = strands
                .strands
                .iter()
                .find(|row| row.strand_id == opened.strand_id)
                .unwrap();
            assert!(strand.board_space_id.is_none());
            assert!(strand.list_space_id.is_none());
            assert!(strand.rank.is_none());
        }
        let unchanged = position(&pool, &board_id, &opened.strand_id).await;
        assert_eq!(unchanged.value, initial.value);
        assert_eq!(
            unchanged.current_stream_position,
            initial.current_stream_position
        );
        assert_eq!(
            count(&pool, &realm, "canonical_events").await,
            events_before
        );
        assert_eq!(count(&pool, &realm, "realm_commits").await, commits_before);
        let mut conn = pool.get().await.unwrap();
        diesel::sql_query("UPDATE space_current_states SET value=$2 WHERE space_id=$1")
            .bind::<Text, _>(target.as_str())
            .bind::<Jsonb, _>(&metadata.value)
            .execute(&mut conn)
            .await
            .unwrap();
    }
    let (_, strands) = store
        .object_projection_lists_for_actor(&realm, &caller, false)
        .await
        .unwrap()
        .unwrap();
    let strand = strands
        .strands
        .iter()
        .find(|row| row.strand_id == opened.strand_id)
        .unwrap();
    assert_eq!(strand.board_space_id.as_ref(), Some(&board_id));
    assert_eq!(strand.list_space_id.as_ref(), Some(&list_a_id));
}
