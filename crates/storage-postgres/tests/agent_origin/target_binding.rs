//! Wrong native targets are rejected before either controller/PCR Realm lock.

use std::time::Duration as Wait;

use arkret_wire::{ActorId, ActorProfileId, CommitStreamRef, RealmAuthorityRootValue};
use coland_storage::{AgentControlAdmissionOutcome, ConflictCode, PersistenceError};
use diesel::sql_types::{Integer, Jsonb};
use diesel_async::SimpleAsyncConnection as _;
use serde_json::{Value, json};

use super::*;

#[derive(diesel::QueryableByName)]
struct JsonRow {
    #[diesel(sql_type=Jsonb)]
    value: Value,
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

async fn fixture_with_business_realm_before_controller_pcr() -> BootstrapReaderFixture {
    for _ in 0..32 {
        let fixture = Box::pin(BootstrapReaderFixture::new()).await;
        if fixture.head.event.realm_id < fixture.origin.controller.history.events[0].realm_id {
            return fixture;
        }
    }
    panic!("the regression requires a real business R ordered before controller PCR H");
}

async fn observe_waiter(pool: &coland_storage_postgres::PgPool, blocker: i32) -> bool {
    tokio::time::timeout(Wait::from_secs(5), async {
        loop {
            let mut conn = pool.get().await.unwrap();
            let count = diesel::sql_query("SELECT COUNT(*) AS count FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid))")
                .bind::<Integer, _>(blocker)
                .get_result::<Count>(&mut conn).await.unwrap();
            if count.count > 0 { break; }
            drop(conn);
            tokio::task::yield_now().await;
        }
    }).await.is_ok()
}

#[tokio::test]
async fn wrong_realm_agent_profile_update_refuses_before_native_locks_while_ordinary_writer_waits()
{
    ordinary_realm::case_future(|| async {
        let fixture = fixture_with_business_realm_before_controller_pcr().await;
        let origin = &fixture.origin;
        let pool = origin.pool.clone();
        let profiles = PgActorProfileStore { pool: pool.clone() };

        // First accept a genuine Agent Profile in J using the same controller
        // key/delegation. The later malformed request changes only its target.
        let at = origin.genesis.commit.committed_at + Duration::seconds(1);
        let profile_create = agent_control_event(
            &origin.controller.history, &origin.agent, &origin.genesis.event.realm_id,
            &format!("{}#managed-controller", origin.agent_did), EventKind::ProfileCreate,
            json!({"object": {
                "principal_id":origin.agent.principal_id, "actor_kind":"agent",
                "display_name":"Actual accepted Agent profile",
                "accountable_principal_ids":[origin.controller.history.account.principal_id],
            }}), at,
        );
        let mut profile_commit = station_successor(&origin.genesis.commit, &profile_create, &origin.station_did, 1);
        origin_seal(&mut profile_commit, &origin.method, &origin.issuer);
        let profile = origin_tx(profile_create, profile_commit, &origin.station);
        origin.stage(&profile).await;
        let accepted_profile = profiles.admit_agent_control_event(AgentControlAdmissionWrite {
            commit: profile.clone(), queued_at: profile.commit.committed_at,
        }).await.expect("the correct native H-to-J path must remain usable");
        assert!(matches!(accepted_profile, AgentControlAdmissionOutcome::Committed(_)));

        let realm = &fixture.head.event.realm_id;
        let mut conn = pool.get().await.unwrap();
        let before = diesel::sql_query("SELECT jsonb_build_object('controller_actor_id',controller_actor_id,'controller_epoch',controller_epoch,'authority_generation',authority_generation::text,'authority_event_ref',authority_event_ref) AS value FROM realm_authority_root_current_states WHERE realm_id=$1")
            .bind::<Text, _>(realm.as_str()).get_result::<JsonRow>(&mut conn).await.unwrap();
        drop(conn);
        let root: RealmAuthorityRootValue = serde_json::from_value(before.value).unwrap();
        root.validate().unwrap();
        let ordinary = ordinary_realm::next_human_request_for_actor(
            &fixture.head, EventKind::RealmAuthorityReset,
            ActorId::account(origin.controller.history.account.clone()),
            json!({"realm_id":realm,"expected_state_digest":arkret_canonical::canonical_sha256(&root).unwrap()}),
            arkret_canonical::normalize_timestamp_canonical(Utc::now()),
        );
        let ordinary = ordinary_realm::case_future(|| ordinary_realm::source_request(&pool, ordinary)).await;
        let wrong_at = arkret_canonical::normalize_timestamp_canonical(Utc::now());
        let wrong = agent_control_event(
            &origin.controller.history, &origin.agent, realm,
            &format!("{}#managed-controller", origin.agent_did), EventKind::ProfileUpdate,
            json!({"actor_profile_id":ActorProfileId::from_event_id(&profile.event.event_id),
                "patch":{"display_name":"Must never reach this ordinary Realm"}}),
            wrong_at,
        );
        arkret_schema::validate_event_for_submit(&wrong).unwrap();
        let mut wrong_commit = station_successor(&fixture.head.commit, &wrong, &origin.station_did, 1);
        wrong_commit.committed_at = wrong_at.max(fixture.head.commit.committed_at);
        origin_seal(&mut wrong_commit, &origin.method, &origin.issuer);
        let wrong = origin_tx(wrong, wrong_commit, &origin.station);
        wrong.validate().unwrap();
        let wrong_id = wrong.event.event_id.clone();

        let mut barrier = pool.get().await.unwrap();
        barrier.batch_execute("BEGIN").await.unwrap();
        let blocker = diesel::sql_query("SELECT pg_backend_pid() AS pid")
            .get_result::<Backend>(&mut barrier).await.unwrap().pid;
        #[derive(diesel::QueryableByName)]
        struct Locked { #[diesel(sql_type=Text)] realm_id: String }
        let held = diesel::sql_query("SELECT realm_id FROM realm_authorities WHERE realm_id=$1 FOR UPDATE")
            .bind::<Text, _>(realm.as_str()).get_result::<Locked>(&mut barrier).await.unwrap();
        assert_eq!(held.realm_id, realm.as_str());
        let ordinary_pool = pool.clone();
        let ordinary = tokio::spawn(async move {
            PgEventCommitUnitOfWork::new(ordinary_pool).commit_event(ordinary).await
        });
        let ordinary_waited = observe_waiter(&pool, blocker).await;
        let first_wrong = wrong.clone();
        let mut native = tokio::spawn(async move {
            profiles.admit_agent_control_event(AgentControlAdmissionWrite {
                queued_at: first_wrong.commit.committed_at, commit: first_wrong,
            }).await
        });
        // The wrong request must complete while R is still held. Old code
        // instead holds H and queues at R, forming the real reverse edge.
        let immediate = tokio::time::timeout(Wait::from_secs(5), &mut native).await;
        let refused_before_release = immediate.is_ok();
        let retry = if refused_before_release {
            // Also hold H while R remains held. This second identical rejected
            // request proves binding precedes the first controller lock too.
            let held = diesel::sql_query("SELECT realm_id FROM realm_authorities WHERE realm_id=$1 FOR UPDATE")
                .bind::<Text, _>(origin.controller.history.events[0].realm_id.as_str())
                .get_result::<Locked>(&mut barrier).await.unwrap();
            assert_eq!(held.realm_id, origin.controller.history.events[0].realm_id.as_str());
            let retry_pool = pool.clone();
            let mut task = tokio::spawn(async move {
                PgActorProfileStore { pool: retry_pool }
                    .admit_agent_control_event(AgentControlAdmissionWrite {
                        queued_at: wrong.commit.committed_at, commit: wrong,
                    }).await
            });
            let result = tokio::time::timeout(Wait::from_secs(5), &mut task).await;
            Some((result, task))
        } else { None };
        barrier.batch_execute("COMMIT").await.unwrap();
        let native = match immediate {
            Ok(result) => result.unwrap(),
            Err(_) => tokio::time::timeout(Wait::from_secs(10), native).await.unwrap().unwrap(),
        };
        let ordinary = tokio::time::timeout(Wait::from_secs(10), ordinary).await.unwrap().unwrap();
        if let Some((result, task)) = retry {
            let immediate = result.is_ok();
            let result = match result {
                Ok(result) => result.unwrap(),
                Err(_) => tokio::time::timeout(Wait::from_secs(10), task).await.unwrap().unwrap(),
            };
            assert!(immediate, "wrong target must refuse while both H and R remain locked");
            assert!(result.is_err());
        }
        assert!(ordinary_waited, "the ordinary production transaction must actually queue at R");
        assert!(refused_before_release, "wrong native target must not wait for R or own H while R is held");
        let error = native.expect_err("wrong Agent target cannot be accepted");
        assert!(matches!(error, PersistenceError::Conflict(ref detail)
            if ConflictCode::from_detail(detail)==Some(ConflictCode::FailedPrecondition)),
            "database deadlock is not a target-binding refusal: {error:?}");
        ordinary.expect("the real ordinary writer must commit after releasing R");
        assert_eq!(PgAuthorityCommitStore { pool: pool.clone() }
            .held_stream_head_commit(&CommitStreamRef::Realm {realm_id:origin.genesis.event.realm_id.clone()})
            .await.unwrap().unwrap(), profile.commit);
        let mut conn = pool.get().await.unwrap();
        let wrong_rows = diesel::sql_query("SELECT COUNT(*) AS count FROM canonical_events WHERE envelope->>'event_id'=$1")
            .bind::<Text, _>(wrong_id.as_str()).get_result::<Count>(&mut conn).await.unwrap();
        assert_eq!(wrong_rows.count, 0, "native refusal must leave no Event or projection");
    }).await;
}
