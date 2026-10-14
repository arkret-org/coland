//! `ak.private.read_cursor.v1` over PostgreSQL (actor-private-effects.md
//! §3.4, read-receipts.md §6.5): causal-first merge against committed
//! positions, exact retry, and zero-write refusals.

#[path = "support/ordinary_realm.rs"]
#[expect(
    dead_code,
    reason = "Each integration binary uses only its subset of the shared Realm fixture."
)]
mod ordinary_realm;

use coland_storage::{
    EventCommitUnitOfWork, ReadCursorAdvance, ReadCursorAdvanceOutcome, ReadCursorAdvanceRefusal,
    ReadCursorStore,
};
use coland_storage_postgres::test_database::TestDatabase;
use coland_storage_postgres::{PgEventCommitUnitOfWork, PgPool, PgReadCursorStore};
use ordinary_realm::{Discussion, event_for_actor, open_human_discussion, station};

const DEVICE_A: &str = "ak:device:01964137-0000-7000-8000-00000000000a";
const DEVICE_B: &str = "ak:device:01964137-0000-7000-8000-00000000000b";
const DEVICE_C: &str = "ak:device:01964137-0000-7000-8000-00000000000c";

fn owner(principal: &arkret_wire::DidCoreId) -> arkret_wire::AccountId {
    arkret_wire::AccountId::new(principal.clone(), station())
}

fn advance(
    discussion: &Discussion,
    principal: &arkret_wire::DidCoreId,
    device: &str,
    position: &arkret_wire::EventId,
    hlc: &str,
    offset_ms: i64,
) -> ReadCursorAdvance {
    let owner = owner(principal);
    let actor = arkret_wire::ActorId::account(owner.clone());
    let realm_id = discussion.realm_id();
    let at = discussion.committed_at() + chrono::Duration::milliseconds(offset_ms);
    let event = event_for_actor(
        arkret_wire::EventKind::ReadCursorAdvance,
        arkret_wire::ScopeRef::Realm {
            realm_id: realm_id.clone(),
        },
        actor.clone(),
        serde_json::json!({
            "schema": "ak.schema.read_cursor.v1",
            "actor_id": actor,
            "device_id": device,
            "realm_id": realm_id,
            "read_scope": {"kind": "realm"},
            "position": {"event_id": position, "hlc": hlc},
        }),
        at,
    );
    with_event(event, owner, station())
}

fn with_event(
    event: arkret_wire::Event,
    owner: arkret_wire::AccountId,
    station_id: arkret_wire::DidCoreId,
) -> ReadCursorAdvance {
    let cursor = serde_json::from_value(serde_json::to_value(&event.payload).unwrap()).unwrap();
    ReadCursorAdvance {
        canonical_event_digest: arkret_canonical::sha256_bytes(
            &arkret_canonical::canonical_json_bytes(&event).unwrap(),
        )
        .to_vec(),
        accepted_at: event.created_at,
        event,
        cursor,
        owner,
        producer_guard: None,
        station_id,
    }
}

fn accepted(outcome: ReadCursorAdvanceOutcome) -> (arkret_wire::EventId, String, bool) {
    match outcome {
        ReadCursorAdvanceOutcome::Accepted {
            marker,
            candidate_won,
        } => (
            marker.position.event_id,
            marker.device_id.to_string(),
            candidate_won,
        ),
        other => panic!("expected an accepted advance, got {other:?}"),
    }
}

fn refused(outcome: ReadCursorAdvanceOutcome) -> ReadCursorAdvanceRefusal {
    match outcome {
        ReadCursorAdvanceOutcome::Refused(refusal) => refusal,
        other => panic!("expected a refusal, got {other:?}"),
    }
}

async fn count(pool: &PgPool, table: &str) -> i64 {
    use diesel_async::RunQueryDsl as _;
    #[derive(diesel::QueryableByName)]
    struct Count {
        #[diesel(sql_type = diesel::sql_types::BigInt)]
        count: i64,
    }
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query(format!("SELECT count(*) AS count FROM {table}"))
        .get_result::<Count>(&mut *conn)
        .await
        .unwrap()
        .count
}

/// Two Messages committed after the default Strand: `first` precedes
/// `second` on the Realm stream.
async fn two_messages(
    pool: &PgPool,
    discussion: &Discussion,
) -> (arkret_wire::EventId, arkret_wire::EventId) {
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let at = discussion.committed_at();
    let first = discussion.message_after(&discussion.head.authority_commit, "first", at);
    uow.commit_event(first.clone()).await.unwrap();
    let second = discussion.message_after(&first.authority_commit, "second", at);
    uow.commit_event(second.clone()).await.unwrap();
    (
        first.authority_commit.event.event_id,
        second.authority_commit.event.event_id,
    )
}

#[tokio::test]
async fn causal_position_wins_over_hlc_and_exact_retry_returns_the_first_outcome() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let discussion = open_human_discussion(&pool, "read-cursor-causal").await;
    let principal = discussion
        .head
        .authority_commit
        .event
        .actor_id
        .signing_principal_id();
    let (first, second) = two_messages(&pool, &discussion).await;
    let store = PgReadCursorStore::new(pool.clone());
    let owner_id = owner(principal);

    // The first candidate for a key always wins.
    let low_hlc_later = advance(
        &discussion,
        principal,
        DEVICE_A,
        &second,
        "019641370000-0000-00000001",
        1,
    );
    let (position, device, won) = accepted(store.advance(&low_hlc_later).await.unwrap());
    assert_eq!(
        (position, device.as_str(), won),
        (second.clone(), DEVICE_A, true)
    );

    // A causally earlier position loses even with a greater HLC; the loser
    // is an accepted no-op that reports the kept winner.
    let high_hlc_earlier = advance(
        &discussion,
        principal,
        DEVICE_B,
        &first,
        "0196413700ff-0000-00000001",
        2,
    );
    let (position, device, won) = accepted(store.advance(&high_hlc_earlier).await.unwrap());
    assert_eq!(
        (position, device.as_str(), won),
        (second.clone(), DEVICE_A, false)
    );
    let ledger = count(&pool, "actor_private_events").await;

    // The byte-identical retry returns the first saved outcome and writes
    // nothing more.
    match store.advance(&high_hlc_earlier).await.unwrap() {
        ReadCursorAdvanceOutcome::Replayed(marker) => {
            assert_eq!(marker.position.event_id, second);
            assert_eq!(marker.device_id.as_str(), DEVICE_A);
        }
        other => panic!("expected the first outcome, got {other:?}"),
    }
    assert_eq!(count(&pool, "actor_private_events").await, ledger);

    // The same Event identity with other canonical bytes is a duplicate
    // conflict with zero writes.
    let mut divergent = high_hlc_earlier.clone();
    divergent.canonical_event_digest = vec![7; 32];
    assert_eq!(
        refused(store.advance(&divergent).await.unwrap()),
        ReadCursorAdvanceRefusal::DuplicateConflict
    );
    assert_eq!(count(&pool, "actor_private_events").await, ledger);

    // Positions that are causally equal are concurrent: the greater HLC
    // wins, and an equal HLC falls to the greater device id.
    let concurrent = advance(
        &discussion,
        principal,
        DEVICE_B,
        &second,
        "019641370001-0000-00000001",
        3,
    );
    let (_, device, won) = accepted(store.advance(&concurrent).await.unwrap());
    assert_eq!((device.as_str(), won), (DEVICE_B, true));
    let tie = advance(
        &discussion,
        principal,
        DEVICE_C,
        &second,
        "019641370001-0000-00000001",
        4,
    );
    let (_, device, won) = accepted(store.advance(&tie).await.unwrap());
    assert_eq!((device.as_str(), won), (DEVICE_C, true));
    let lower_device_tie = advance(
        &discussion,
        principal,
        DEVICE_A,
        &second,
        "019641370001-0000-00000001",
        5,
    );
    let (_, device, won) = accepted(store.advance(&lower_device_tie).await.unwrap());
    assert_eq!((device.as_str(), won), (DEVICE_C, false));

    // The winner is durable account-private state: a fresh store over the
    // same database reads it back, with `updated_at` from the winning
    // advance's envelope.
    let restarted = PgReadCursorStore::new(pool.clone());
    let markers = restarted.list(&owner_id, None).await.unwrap();
    assert_eq!(markers.len(), 1);
    assert_eq!(markers[0].device_id.as_str(), DEVICE_C);
    assert_eq!(markers[0].position.event_id, second);
    assert_eq!(markers[0].updated_at, tie.event.created_at);
    assert_eq!(
        restarted
            .list(&owner_id, Some(&discussion.realm_id()))
            .await
            .unwrap()
            .len(),
        1
    );
    assert_eq!(count(&pool, "read_cursor_winners").await, 1);
}

#[tokio::test]
async fn unprovable_or_foreign_positions_are_refused_with_zero_writes() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let discussion = open_human_discussion(&pool, "read-cursor-refusals").await;
    let principal = discussion
        .head
        .authority_commit
        .event
        .actor_id
        .signing_principal_id();
    let (_, second) = two_messages(&pool, &discussion).await;
    let store = PgReadCursorStore::new(pool.clone());
    let hlc = "019641370000-0000-00000001";

    // A position that names no committed Event of the Realm.
    let unknown = arkret_wire::EventId::from_digest(
        arkret_canonical::DigestSuite::Sha256,
        arkret_canonical::sha256_bytes(b"not an Event of this Realm"),
    );
    let missing = advance(&discussion, principal, DEVICE_A, &unknown, hlc, 1);
    assert_eq!(
        refused(store.advance(&missing).await.unwrap()),
        ReadCursorAdvanceRefusal::PositionNotInRealm
    );

    // An Account that is not a joined member owns no cursor here.
    let stranger = arkret_wire::DidCoreId::new("ak:did_core:web:stranger.example").unwrap();
    let outsider = advance(&discussion, &stranger, DEVICE_A, &second, hlc, 2);
    assert_eq!(
        refused(store.advance(&outsider).await.unwrap()),
        ReadCursorAdvanceRefusal::NotMember
    );

    // A Station that does not govern the Realm cannot classify the position.
    let elsewhere = advance(&discussion, principal, DEVICE_A, &second, hlc, 4);
    let elsewhere = with_event(
        elsewhere.event,
        owner(principal),
        arkret_wire::DidCoreId::new("ak:did_core:web:other-station.example").unwrap(),
    );
    assert!(matches!(
        refused(store.advance(&elsewhere).await.unwrap()),
        ReadCursorAdvanceRefusal::Unproved(_)
    ));

    assert_eq!(count(&pool, "actor_private_events").await, 0);
    assert_eq!(count(&pool, "read_cursor_winners").await, 0);

    // An owner that is not the payload actor never reaches the transaction.
    let mut unbound = advance(&discussion, principal, DEVICE_A, &second, hlc, 5);
    unbound.owner = owner(&stranger);
    assert!(store.advance(&unbound).await.is_err());
    assert_eq!(count(&pool, "actor_private_events").await, 0);
}

#[tokio::test]
async fn read_cursor_uses_the_same_readable_floor_as_stream_scans() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let discussion = open_human_discussion(&pool, "read-cursor-history-floor").await;
    let founder = discussion
        .head
        .authority_commit
        .event
        .actor_id
        .signing_principal_id();
    let genesis = &discussion.unit.transactions[0].event.event_id;
    let store = PgReadCursorStore::new(pool.clone());
    let hlc = "019641370000-0000-00000001";
    // The founder's join and position zero belong to one accepted atomic unit;
    // since_join therefore starts at stream position zero, not its join slot.
    let (position, _, won) = accepted(
        store
            .advance(&advance(&discussion, founder, DEVICE_A, genesis, hlc, 1))
            .await
            .unwrap(),
    );
    assert_eq!(&position, genesis);
    assert!(won);

    let member = Box::pin(ordinary_realm::human_profile::admit(
        &pool,
        &station(),
        "read-cursor-late-member",
    ))
    .await;
    let joined_at = chrono::Utc::now();
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let joined = Box::pin(ordinary_realm::source_request(&pool,ordinary_realm::next_request(
        &discussion.head.authority_commit,arkret_wire::EventKind::MemberState,&member.principal_id,
        serde_json::json!({"member_id":arkret_wire::ActorId::account(member.clone()),"membership":"join"}),
        joined_at,
    ))).await;
    uow.commit_event(joined.clone()).await.unwrap();
    let before = (
        count(&pool, "actor_private_events").await,
        count(&pool, "read_cursor_winners").await,
    );
    assert_eq!(
        refused(
            store
                .advance(&advance(
                    &discussion,
                    &member.principal_id,
                    DEVICE_B,
                    genesis,
                    hlc,
                    3
                ))
                .await
                .unwrap()
        ),
        ReadCursorAdvanceRefusal::PositionNotReadable
    );
    assert_eq!(
        (
            count(&pool, "actor_private_events").await,
            count(&pool, "read_cursor_winners").await
        ),
        before
    );
    let joined_id = &joined.authority_commit.event.event_id;
    assert_eq!(
        accepted(
            store
                .advance(&advance(
                    &discussion,
                    &member.principal_id,
                    DEVICE_B,
                    joined_id,
                    hlc,
                    4
                ))
                .await
                .unwrap()
        )
        .0,
        *joined_id
    );
}

#[tokio::test]
async fn all_history_positions_are_admitted_until_policy_tightens_without_rewriting_winners() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let discussion = ordinary_realm::open_discussion_with_history(
        &pool,
        "read-cursor-all-history",
        "all_history_for_current_members",
    )
    .await;
    let founder = discussion
        .head
        .authority_commit
        .event
        .actor_id
        .signing_principal_id();
    let member = Box::pin(ordinary_realm::human_profile::admit(
        &pool,
        &station(),
        "read-cursor-history-member",
    ))
    .await;
    let at = chrono::Utc::now();
    let joined = Box::pin(ordinary_realm::source_request(&pool,ordinary_realm::next_request(
        &discussion.head.authority_commit,arkret_wire::EventKind::MemberState,&member.principal_id,
        serde_json::json!({"member_id":arkret_wire::ActorId::account(member.clone()),"membership":"join"}),at,
    ))).await;
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    uow.commit_event(joined.clone()).await.unwrap();
    let genesis = &discussion.unit.transactions[0].event.event_id;
    let store = PgReadCursorStore::new(pool.clone());
    let hlc = "019641370000-0000-00000001";
    assert_eq!(
        accepted(
            store
                .advance(&advance(
                    &discussion,
                    &member.principal_id,
                    DEVICE_B,
                    genesis,
                    hlc,
                    1
                ))
                .await
                .unwrap()
        )
        .0,
        *genesis
    );
    let history = Box::pin(ordinary_realm::source_request(
        &pool,
        ordinary_realm::next_request(
            &joined.authority_commit,
            arkret_wire::EventKind::RealmHistoryAccess,
            founder,
            serde_json::json!({"from":"all_history_for_current_members","to":"since_join"}),
            at + chrono::Duration::milliseconds(1),
        ),
    ))
    .await;
    uow.commit_event(history).await.unwrap();
    let before = (
        count(&pool, "actor_private_events").await,
        count(&pool, "read_cursor_winners").await,
    );
    assert_eq!(
        refused(
            store
                .advance(&advance(
                    &discussion,
                    &member.principal_id,
                    DEVICE_B,
                    genesis,
                    hlc,
                    2
                ))
                .await
                .unwrap()
        ),
        ReadCursorAdvanceRefusal::PositionNotReadable
    );
    assert_eq!(
        (
            count(&pool, "actor_private_events").await,
            count(&pool, "read_cursor_winners").await
        ),
        before
    );
    assert_eq!(
        store
            .list(&member, Some(&discussion.realm_id()))
            .await
            .unwrap()[0]
            .position
            .event_id,
        *genesis
    );
}
