//! Native successor consent, immutable accepted W1 and the participant lock set.

#[path = "support/realm_owner_transfer.rs"]
mod native_owner;

#[path = "support/ordinary_realm.rs"]
#[allow(dead_code)]
mod ordinary_realm;
#[path = "realm_owner_transfer/private_handoff.rs"]
mod private_handoff;

#[path = "realm_owner_transfer/lifecycle.rs"]
mod lifecycle;

#[path = "realm_owner_transfer/mixed_locks.rs"]
mod mixed_locks;

use std::time::Duration;

use arkret_models_identity::AccountDeviceSignerEvidence;
use arkret_wire::{AccountId, RealmId};
use coland_storage::{EventCommitUnitOfWork, OwnerTransferSuccessorSource};
use coland_storage_postgres::test_database::TestDatabase;
use coland_storage_postgres::{PgEventCommitUnitOfWork, PgPool};
use diesel::sql_types::{BigInt, Integer, Jsonb, Text};
use diesel_async::{RunQueryDsl as _, SimpleAsyncConnection as _};
use serde_json::Value;

#[derive(diesel::QueryableByName)]
struct JsonRow {
    #[diesel(sql_type=Jsonb)]
    value: Value,
}

#[derive(diesel::QueryableByName)]
struct Original {
    #[diesel(sql_type=Jsonb)]
    envelope: Value,
    #[diesel(sql_type=Jsonb)]
    commit_json: Value,
}

#[tokio::test]
async fn reset_refuses_the_numeric_preimage_of_the_actual_canonical_root() {
    ordinary_realm::case_future(|| async {
        let database = TestDatabase::lease().await;
        let pool = database.pool();
        let fixture = native_owner::prepared(&pool, "owner-root-canonical-preimage").await;
        let before = native_owner::root_value(&pool, &fixture.realm).await;
        assert_eq!(before["authority_generation"], serde_json::json!("0"));
        let mut numeric = before.clone();
        numeric["authority_generation"] = serde_json::json!(0);
        let wrong_digest = arkret_canonical::canonical_sha256(&numeric).unwrap();
        assert_ne!(wrong_digest, arkret_canonical::canonical_sha256(&before).unwrap());

        // Take the actual accepted predecessor, not the unaccepted Owner
        // candidate. Thus a head/CAS mismatch cannot masquerade as this gate.
        let mut conn = pool.get().await.unwrap();
        let row = diesel::sql_query("SELECT e.envelope,c.commit_json FROM realm_commits c JOIN canonical_events e ON e.pk=c.event_pk WHERE c.commit_id=$1 AND e.state='committed'")
            .bind::<Text, _>(fixture.commit().previous_commit_ref.as_ref().unwrap().as_str())
            .get_result::<Original>(&mut conn).await.unwrap();
        drop(conn);
        let mut predecessor = fixture.request.authority_commit.clone();
        predecessor.event = serde_json::from_value(row.envelope).unwrap();
        predecessor.commit = serde_json::from_value(row.commit_json).unwrap();
        predecessor.commit.verify_commit_id_matches_content().unwrap();
        predecessor.producer_signer_fact = None;
        let reset = ordinary_realm::next_human_request_for_actor(
            &predecessor,
            arkret_wire::EventKind::RealmAuthorityReset,
            arkret_wire::ActorId::account(fixture.author.clone()),
            serde_json::json!({"realm_id":fixture.realm,"expected_state_digest":wrong_digest}),
            native_owner::now(),
        );
        let reset = ordinary_realm::case_future(|| ordinary_realm::source_request(&pool, reset)).await;
        let reset_id = reset.authority_commit.event.event_id.clone();
        assert!(PgEventCommitUnitOfWork::new(pool.clone()).commit_event(reset).await.is_err());
        assert_eq!(native_owner::root_value(&pool, &fixture.realm).await, before);
        let mut conn = pool.get().await.unwrap();
        let count = diesel::sql_query("SELECT COUNT(*) AS count FROM canonical_events WHERE envelope->>'event_id'=$1")
            .bind::<Text, _>(reset_id.as_str()).get_result::<Count>(&mut conn).await.unwrap();
        assert_eq!(count.count, 0);
    }).await;
}

async fn accepted_witness(
    fixture: &native_owner::NativeOwnerTransfer,
) -> AccountDeviceSignerEvidence {
    let mut conn = fixture.pool.get().await.unwrap();
    let row = diesel::sql_query("SELECT successor_device_evidence_json AS value FROM canonical_events WHERE envelope->>'event_id'=$1 AND state='committed'")
        .bind::<Text, _>(fixture.event().event_id.as_str())
        .get_result::<JsonRow>(&mut conn)
        .await
        .unwrap();
    serde_json::from_value(row.value).unwrap()
}

#[tokio::test]
async fn native_consent_is_required_and_exact_replay_keeps_the_first_witness() {
    ordinary_realm::case_future(|| async {
        let database = TestDatabase::lease().await;
        let fixture = native_owner::prepared(&database.pool(), "owner-first-witness").await;
        let before = native_owner::root_value(&fixture.pool, &fixture.realm).await;
        let uow = PgEventCommitUnitOfWork::new(fixture.pool.clone());

        let mut missing = fixture.request.clone();
        missing.owner_transfer_successor = None;
        assert!(uow.commit_event(missing).await.is_err());
        assert_eq!(
            native_owner::root_value(&fixture.pool, &fixture.realm).await,
            before
        );

        // A genuinely signs this other Event, but it contains no valid B
        // mathematical signature. A's authority cannot substitute for consent.
        let mut invalid = fixture.request.clone();
        let mut payload = serde_json::to_value(&invalid.authority_commit.event.payload).unwrap();
        payload["successor_acceptance"]["signature"] =
            Value::String(arkret_canonical::base64url_encode([0_u8; 64]));
        invalid.authority_commit.event.payload = serde_json::from_value(payload).unwrap();
        for projection in &mut invalid.projections {
            projection.payload =
                serde_json::to_value(&invalid.authority_commit.event.payload).unwrap();
        }
        let mut invalid =
            ordinary_realm::case_future(|| ordinary_realm::source_request(&fixture.pool, invalid))
                .await;
        invalid.owner_transfer_successor = Some(
            OwnerTransferSuccessorSource::for_event(
                &invalid.authority_commit.event,
                fixture.w1.clone(),
            )
            .unwrap(),
        );
        assert!(uow.commit_event(invalid).await.is_err());
        assert_eq!(
            native_owner::root_value(&fixture.pool, &fixture.realm).await,
            before
        );

        fixture.accept().await;
        let accepted = native_owner::root_value(&fixture.pool, &fixture.realm).await;
        assert_eq!(
            accepted["controller_actor_id"],
            serde_json::json!(arkret_wire::ActorId::account(fixture.successor.clone()))
        );
        assert_eq!(
            accepted["authority_generation"],
            before["authority_generation"]
        );
        assert_eq!(accepted_witness(&fixture).await, fixture.w1);

        let w2 = fixture.fresh_witness().await;
        assert_ne!(
            w2.signer_evidence_ref().unwrap(),
            fixture.w1.signer_evidence_ref().unwrap()
        );
        let mut retry = fixture.request.clone();
        retry.owner_transfer_successor =
            Some(OwnerTransferSuccessorSource::for_event(fixture.event(), w2).unwrap());
        uow.commit_event(retry)
            .await
            .expect("accepted exact Event returns its immutable result");
        assert_eq!(
            native_owner::root_value(&fixture.pool, &fixture.realm).await,
            accepted
        );
        assert_eq!(accepted_witness(&fixture).await, fixture.w1);
        arkret_identity::account_device_signer_evidence::verify_owner_transfer_successor_evidence(
            &fixture.w1,
            &fixture.component.intent,
            &fixture.component.acceptance,
            fixture.commit().committed_at,
        )
        .unwrap();
    })
    .await;
}

#[derive(diesel::QueryableByName)]
struct Pcr {
    #[diesel(sql_type=Text)]
    realm_id: String,
}
async fn pcr(pool: &PgPool, account: &AccountId) -> RealmId {
    let mut conn = pool.get().await.unwrap();
    let row = diesel::sql_query(
        "SELECT realm_id FROM pcr_genesis_units WHERE principal_id=$1 AND station_id=$2",
    )
    .bind::<Text, _>(account.principal_id.as_str())
    .bind::<Text, _>(account.station_id.as_str())
    .get_result::<Pcr>(&mut conn)
    .await
    .unwrap();
    RealmId::new(row.realm_id).unwrap()
}
#[derive(diesel::QueryableByName)]
struct Backend {
    #[diesel(sql_type=Integer)]
    pid: i32,
}
#[derive(diesel::QueryableByName)]
struct Count {
    #[diesel(sql_type=BigInt)]
    count: i64,
}

/// Observe actual server lock dependencies, including a queued tuple waiter.
/// Yielding or a fixed delay is not evidence that either UoW reached the lock.
async fn wait_for_blocked(pool: &PgPool, blocker: i32, wanted: i64) {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let mut conn = pool.get().await.unwrap();
            let row = diesel::sql_query("WITH RECURSIVE waiting(pid) AS (SELECT pid FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid)) UNION SELECT a.pid FROM pg_stat_activity a JOIN waiting w ON w.pid=ANY(pg_blocking_pids(a.pid))) SELECT COUNT(DISTINCT pid) AS count FROM waiting")
                .bind::<Integer, _>(blocker)
                .get_result::<Count>(&mut conn).await.unwrap();
            if row.count >= wanted { break; }
            drop(conn);
            tokio::task::yield_now().await;
        }
    }).await.expect("native UoWs must actually wait on the held PCR row");
}

#[tokio::test]
async fn reciprocal_transfers_lock_both_native_participant_pcrs_in_the_same_order() {
    ordinary_realm::case_future(|| async {
        let database = TestDatabase::lease().await;
        let pool = database.pool();
        let first = native_owner::prepared(&pool, "owner-reciprocal-first").await;
        let second = first.reciprocal_realm("owner-reciprocal-second").await;
        let pcr_a = pcr(&pool, &first.author).await;
        let pcr_b = pcr(&pool, &first.successor).await;
        let (earlier, later, held) = if pcr_a < pcr_b {
            (second.request.clone(), first.request.clone(), pcr_a)
        } else {
            (first.request.clone(), second.request.clone(), pcr_b)
        };
        let mut barrier = pool.get().await.unwrap();
        barrier.batch_execute("BEGIN").await.unwrap();
        let blocker = diesel::sql_query("SELECT pg_backend_pid() AS pid")
            .get_result::<Backend>(&mut barrier)
            .await
            .unwrap()
            .pid;
        diesel::sql_query("SELECT realm_id FROM realm_authorities WHERE realm_id=$1 FOR UPDATE")
            .bind::<Text, _>(held.as_str())
            .get_result::<Pcr>(&mut barrier)
            .await
            .unwrap();

        // Queue the transfer whose successor is the smaller PCR first. In the
        // faulty partial plan, the other transfer holds the larger PCR before
        // it joins this queue, producing the real A/B cycle after release.
        let earlier_pool = pool.clone();
        let earlier = tokio::spawn(async move {
            PgEventCommitUnitOfWork::new(earlier_pool)
                .commit_event(earlier)
                .await
        });
        wait_for_blocked(&pool, blocker, 1).await;
        let later_pool = pool.clone();
        let later = tokio::spawn(async move {
            PgEventCommitUnitOfWork::new(later_pool)
                .commit_event(later)
                .await
        });
        wait_for_blocked(&pool, blocker, 2).await;
        barrier.batch_execute("COMMIT").await.unwrap();
        tokio::time::timeout(Duration::from_secs(10), async {
            earlier
                .await
                .unwrap()
                .expect("first native transfer commits without lock inversion");
            later
                .await
                .unwrap()
                .expect("reciprocal native transfer commits without lock inversion");
        })
        .await
        .expect("both real transactions terminate after the blocker releases");
        assert_eq!(accepted_witness(&first).await, first.w1);
        assert_eq!(accepted_witness(&second).await, second.w1);
    })
    .await;
}
