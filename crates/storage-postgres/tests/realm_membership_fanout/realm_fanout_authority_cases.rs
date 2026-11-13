//! Frozen witnesses retain tuple identity and complete canonical disclosure.
use coland_storage::{RetentionTombstoneRecord, RetentionTombstoneStore};
use coland_storage_postgres::PgRetentionTombstoneStore;

use super::*;

async fn join(
    pool: &PgPool,
    uow: &PgEventCommitUnitOfWork,
    previous: &AuthorityCommitTransaction,
    member: &arkret_wire::ActorId,
    state: &str,
) -> EventCommitRequest {
    let candidate = membership_request(previous, member.clone(), member, state);
    let request = heap_future(|| ordinary_realm::source_request(pool, candidate)).await;
    uow.commit_event(request.clone()).await.unwrap();
    request
}

fn witness(join: &EventCommitRequest) -> RealmFanoutAuthorityWitness {
    RealmFanoutAuthorityWitness {
        member_id: join.authority_commit.event.actor_id.clone(),
        membership_event_ref: join.authority_commit.event.event_id.to_string(),
        circle_membership_event_ref: None,
    }
}

#[tokio::test]
async fn withdrawn_terminal_bytes_invalidate_every_frozen_witness() {
    heap_future(withdrawn_terminal_case).await;
}

async fn withdrawn_terminal_case() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let unit = heap_future(|| admit(&pool, "terminal-byte-withdrawal", "public")).await;
    let member = remote_member("terminal-byte-reader");
    let joined = join(
        &pool,
        &uow,
        unit.transactions.last().unwrap(),
        &member,
        "join",
    )
    .await;
    let candidate = sourced(next_request(
        &joined.authority_commit,
        arkret_wire::EventKind::RealmTombstone,
        &founder(),
        arkret_models_collaboration::governance::realm_lifecycle::RealmTombstonePayload::new(
            "ak:realm:ASR8x2N1qyfyy6I-eob3l-FNhx4FPBTyMJrIfifkksgW"
                .parse()
                .unwrap(),
            "migration",
        )
        .to_value()
        .unwrap(),
        joined.authority_commit.commit.committed_at,
    ));
    let terminal = heap_future(|| ordinary_realm::source_request(&pool, candidate)).await;
    uow.commit_event(terminal.clone()).await.unwrap();
    let basis = vec![witness(&joined)];
    let local = arkret_wire::DidCoreId::new(STATION).unwrap();
    let event = &terminal.authority_commit.event;
    let at = chrono::Utc::now();
    assert!(
        store
            .realm_fanout_still_owed(event, &local, &member_station(), &basis, at)
            .await
            .unwrap()
    );
    let tombstones = PgRetentionTombstoneStore { pool: pool.clone() };
    tombstones
        .put(&RetentionTombstoneRecord {
            event_id: event.event_id.to_string(),
            realm_id: event.realm_id.to_string(),
            reason: "expired".into(),
            policy_ttl_seconds: 1,
            expired_at: at,
            tombstoned_at: at,
            sealed: true,
        })
        .await
        .unwrap();
    let before = fanout_rows(&pool, &terminal).await;
    assert!(
        !store
            .realm_fanout_still_owed(event, &local, &member_station(), &basis, at)
            .await
            .unwrap()
    );
    assert_eq!(
        member_state(&pool, &event.realm_id, &member)
            .await
            .as_deref(),
        Some("join")
    );
    let held = store
        .committed_event(&event.event_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(held.event, *event);
    assert_eq!(held.commit, terminal.authority_commit.commit);
    let after = fanout_rows(&pool, &terminal).await;
    assert_eq!(before[0].payload_json, after[0].payload_json);
    assert_eq!(before[0].realm_fanout, after[0].realm_fanout);
    assert_eq!(before[0].state, after[0].state);
}

#[tokio::test]
async fn complete_witness_or_survives_leave_but_new_join_never_revives_old_basis() {
    heap_future(witness_or_case).await;
}

async fn witness_or_case() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let unit = heap_future(|| admit(&pool, "complete-witness-or", "public")).await;
    let bob = remote_member("complete-bob");
    let carol = remote_member("complete-carol");
    let bob_join = join(&pool, &uow, unit.transactions.last().unwrap(), &bob, "join").await;
    let carol_join = join(&pool, &uow, &bob_join.authority_commit, &carol, "join").await;
    let at = carol_join.authority_commit.commit.committed_at;
    let candidate = sourced(next_request(
        &carol_join.authority_commit,
        arkret_wire::EventKind::StrandCreate,
        &founder(),
        serde_json::json!({"object": {"schema":"ak.schema.strand.v1",
            "realm_id":carol_join.authority_commit.event.realm_id,
            "tracks":{"discussion":{"is_primary":true,"profile":"discussion"}},
            "metadata":{"title":"Frozen witness read"},"state":"active",
            "created_by":founder_actor(),"created_at":arkret_canonical::format_timestamp_canonical(at)}}),
        at,
    ));
    let shared = heap_future(|| ordinary_realm::source_request(&pool, candidate)).await;
    uow.commit_event(shared.clone()).await.unwrap();
    let event = &shared.authority_commit.event;
    let local = arkret_wire::DidCoreId::new(STATION).unwrap();
    let basis = vec![witness(&bob_join), witness(&carol_join)];
    assert!(
        store
            .realm_fanout_still_owed(event, &local, &member_station(), &basis, at)
            .await
            .unwrap()
    );
    let bob_left = join(&pool, &uow, &shared.authority_commit, &bob, "leave").await;
    assert!(
        store
            .realm_fanout_still_owed(event, &local, &member_station(), &basis, at)
            .await
            .unwrap()
    );
    let mixed = vec![
        RealmFanoutAuthorityWitness {
            member_id: carol.clone(),
            membership_event_ref: basis[0].membership_event_ref.clone(),
            circle_membership_event_ref: None,
        },
        RealmFanoutAuthorityWitness {
            member_id: bob.clone(),
            membership_event_ref: basis[1].membership_event_ref.clone(),
            circle_membership_event_ref: None,
        },
    ];
    assert!(
        !store
            .realm_fanout_still_owed(event, &local, &member_station(), &mixed, at)
            .await
            .unwrap()
    );
    let carol_left = join(&pool, &uow, &bob_left.authority_commit, &carol, "leave").await;
    assert!(
        !store
            .realm_fanout_still_owed(event, &local, &member_station(), &basis, at)
            .await
            .unwrap()
    );
    let rejoin = join(&pool, &uow, &carol_left.authority_commit, &carol, "join").await;
    assert!(
        !store
            .realm_fanout_still_owed(event, &local, &member_station(), &basis, at)
            .await
            .unwrap()
    );
    assert!(
        store
            .realm_fanout_still_owed(
                &rejoin.authority_commit.event,
                &local,
                &member_station(),
                &[witness(&rejoin)],
                at
            )
            .await
            .unwrap()
    );
}
