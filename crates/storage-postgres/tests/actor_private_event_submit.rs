//! `ak.self.actor_private_events.command.submit.v1` over PostgreSQL
//! (actor-private-effects.md §2.1, §3.2, §3.3): each branch writes its private
//! value projection and the exact-retry ledger in one transaction, an exact
//! retry returns the first outcome, and every refusal writes nothing.

#[path = "support/ordinary_realm.rs"]
#[expect(
    dead_code,
    reason = "Each integration binary uses only its subset of the shared Realm fixture."
)]
mod ordinary_realm;

use arkret_wire::{
    AccountId, ActorId, ActorPrivateEventSubmitOutcome, DidCoreId, Event, EventKind,
};
use coland_storage::{
    ActorPrivateEventEffect, ActorPrivateEventRefusal, ActorPrivateEventStore,
    ActorPrivateEventSubmission, ActorPrivateEventSubmitResult, AgentDraftPendingIntentCommit,
    AgentDraftPendingIntentRecord, AgentDraftPendingIntentState,
};
use coland_storage_postgres::test_database::TestDatabase;
use coland_storage_postgres::{PgActorPrivateEventStore, PgPool};
use ordinary_realm::{event_for_actor, station};
use serde_json::json;

const DEVICE: &str = "ak:device:01964137-0000-7000-8000-00000000000a";
const ROUTE: &str = "apns_main";
const TARGET: &str = "ak:pseudonym:push:kosc9iQ4gVct1OB-b6X364WIFIsJFVbVzn7BMBs1sm8";
const GATEWAY: &str = "ak:did_core:web:gateway.example";
const AGENT: &str = "ak:did_core:web:agent.example";

fn account(principal: &str) -> AccountId {
    AccountId::new(DidCoreId::new(principal).unwrap(), station())
}

fn holder() -> AccountId {
    account("ak:did_core:web:holder.example")
}

fn agent() -> AccountId {
    account(AGENT)
}

fn base_time() -> chrono::DateTime<chrono::Utc> {
    "2026-09-26T00:00:00.000Z".parse().unwrap()
}

fn signed(kind: EventKind, actor: &AccountId, payload: serde_json::Value, offset_ms: i64) -> Event {
    let realm_id = arkret_wire::RealmId::from_event_id(&arkret_wire::EventId::from_digest(
        arkret_canonical::DigestSuite::Sha256,
        [0x5a; 32],
    ));
    event_for_actor(
        kind,
        arkret_wire::ScopeRef::Realm { realm_id },
        ActorId::account(actor.clone()),
        payload,
        base_time() + chrono::Duration::milliseconds(offset_ms),
    )
}

fn digest(event: &Event) -> Vec<u8> {
    arkret_canonical::sha256_bytes(&arkret_canonical::canonical_json_bytes(event).unwrap()).to_vec()
}

fn submission(
    event: Event,
    owner: AccountId,
    effect: ActorPrivateEventEffect,
) -> ActorPrivateEventSubmission {
    ActorPrivateEventSubmission {
        canonical_event_digest: digest(&event),
        accepted_at: event.created_at,
        event,
        owner,
        effect,
        producer_guard: None,
    }
}

fn push_route_payload(expected: u64, revoked: bool) -> serde_json::Value {
    if revoked {
        json!({
            "account_id": holder(),
            "device_id": DEVICE,
            "push_route": ROUTE,
            "revoked": true,
            "expected_server_revision": expected,
        })
    } else {
        json!({
            "account_id": holder(),
            "device_id": DEVICE,
            "push_route": ROUTE,
            "push_target_id": TARGET,
            "push_gateway_id": GATEWAY,
            "encryption_key": "base64url-public-key",
            "capabilities": ["chat"],
            "expected_server_revision": expected,
        })
    }
}

fn push_route(expected: u64, revoked: bool, offset_ms: i64) -> ActorPrivateEventSubmission {
    let payload = push_route_payload(expected, revoked);
    let event = signed(
        EventKind::DevicePushRoute,
        &holder(),
        payload.clone(),
        offset_ms,
    );
    submission(
        event,
        holder(),
        ActorPrivateEventEffect::DevicePushRoute(serde_json::from_value(payload).unwrap()),
    )
}

fn action_request(
    request_id: &str,
    expires_in_ms: i64,
    offset_ms: i64,
) -> ActorPrivateEventSubmission {
    let created_at = base_time() + chrono::Duration::milliseconds(offset_ms);
    let payload = json!({
        "request_id": request_id,
        "agent_id": AGENT,
        "controller_account_id": holder(),
        "proposed_action": "ak.message.create",
        "target": {"kind": "realm", "realm_id": "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb"},
        "request_canonical_digest": format!("sha256:{}", "1".repeat(64)),
        "expires_at": arkret_canonical::format_timestamp_canonical(
            created_at + chrono::Duration::milliseconds(expires_in_ms)
        ),
        "created_at": arkret_canonical::format_timestamp_canonical(created_at),
    });
    let event = signed(
        EventKind::AgentActionRequest,
        &agent(),
        payload.clone(),
        offset_ms,
    );
    submission(
        event,
        holder(),
        ActorPrivateEventEffect::AgentActionRequest(serde_json::from_value(payload).unwrap()),
    )
}

fn reject(rejection_id: &str, request_id: &str, offset_ms: i64) -> ActorPrivateEventSubmission {
    let payload = json!({
        "rejection_id": rejection_id,
        "request_id": request_id,
        "agent_id": AGENT,
        "rejected_at": arkret_canonical::format_timestamp_canonical(
            base_time() + chrono::Duration::milliseconds(offset_ms)
        ),
    });
    let event = signed(
        EventKind::AgentActionReject,
        &holder(),
        payload.clone(),
        offset_ms,
    );
    submission(
        event,
        holder(),
        ActorPrivateEventEffect::AgentActionReject {
            payload: serde_json::from_value(payload).unwrap(),
            request_id: request_id.to_owned(),
        },
    )
}

fn draft_propose(
    draft_id: &str,
    expires_in_ms: i64,
    offset_ms: i64,
) -> ActorPrivateEventSubmission {
    let created_at = base_time() + chrono::Duration::milliseconds(offset_ms);
    let expires_at = created_at + chrono::Duration::milliseconds(expires_in_ms);
    let handoff = json!({
        "scheme": "ak.hpke_x25519_aead_chacha20poly1305.v1",
        "recipients": [{
            "recipient_device_id": DEVICE,
            "recipient_hpke_key_digest": format!("sha256:{}", "2".repeat(64)),
            "enc": "A".repeat(43),
            "ciphertext": "B".repeat(22),
            "ciphertext_digest": format!("sha256:{}", "3".repeat(64)),
        }],
    });
    let target = json!({"kind": "realm", "realm_id": "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb"});
    let payload = json!({
        "draft_id": draft_id,
        "agent_id": AGENT,
        "controller_account_id": holder(),
        "proposed_action": "ak.message.create",
        "target": target,
        "content_digest": format!("sha256:{}", "4".repeat(64)),
        "content_handoff": handoff,
        "expires_at": arkret_canonical::format_timestamp_canonical(expires_at),
        "created_at": arkret_canonical::format_timestamp_canonical(created_at),
    });
    let event = signed(EventKind::AgentDraftPropose, &agent(), payload, offset_ms);
    let canonical = digest(&event);
    let record = AgentDraftPendingIntentRecord {
        controller_account_id: holder(),
        agent_id: DidCoreId::new(AGENT).unwrap(),
        draft_id: draft_id.to_owned(),
        proposed_action: "ak.message.create".to_owned(),
        target,
        content_digest: arkret_wire::Hash::new(format!("sha256:{}", "4".repeat(64))).unwrap(),
        content_handoff: Some(handoff),
        canonical_event_digest: arkret_wire::Hash::new(format!(
            "sha256:{}",
            canonical
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        ))
        .unwrap(),
        accepted_event_id: event.event_id.clone(),
        expires_at,
        created_at,
        state: AgentDraftPendingIntentState::Available,
        consumption: None,
        expired_at: None,
    };
    submission(
        event,
        holder(),
        ActorPrivateEventEffect::AgentDraftPropose(AgentDraftPendingIntentCommit { record }),
    )
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

async fn text(pool: &PgPool, query: &str) -> String {
    use diesel_async::RunQueryDsl as _;
    #[derive(diesel::QueryableByName)]
    struct Value {
        #[diesel(sql_type = diesel::sql_types::Text)]
        value: String,
    }
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query(query)
        .get_result::<Value>(&mut *conn)
        .await
        .unwrap()
        .value
}

fn accepted(result: ActorPrivateEventSubmitResult) -> ActorPrivateEventSubmitOutcome {
    match result {
        ActorPrivateEventSubmitResult::Accepted(outcome) => outcome,
        other => panic!("expected an accepted submission, got {other:?}"),
    }
}

fn refused(result: ActorPrivateEventSubmitResult) -> ActorPrivateEventRefusal {
    match result {
        ActorPrivateEventSubmitResult::Refused(refusal) => refusal,
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[tokio::test]
async fn push_route_revision_cas_replays_exactly_and_refuses_stale_writes_with_zero_writes() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let store = PgActorPrivateEventStore::new(pool.clone());

    let create = push_route(0, false, 1);
    let first = accepted(store.submit(&create).await.unwrap());
    assert_eq!(
        first,
        ActorPrivateEventSubmitOutcome::DevicePushRoute {
            accepted_event_id: create.event.event_id.clone(),
            revision: 1,
        }
    );
    // The byte-identical retry returns the first outcome and writes nothing.
    assert_eq!(
        store.submit(&create).await.unwrap(),
        ActorPrivateEventSubmitResult::Replayed(first)
    );
    assert_eq!(count(&pool, "actor_private_events").await, 1);

    // The same Event identity with other canonical bytes is a duplicate.
    let mut divergent = create.clone();
    divergent.canonical_event_digest = vec![7; 32];
    assert!(matches!(
        refused(store.submit(&divergent).await.unwrap()),
        ActorPrivateEventRefusal::DuplicateConflict(_)
    ));

    // A second Event naming the occupied revision 0 is a CAS conflict.
    let stale = push_route(0, false, 2);
    assert_eq!(
        refused(store.submit(&stale).await.unwrap()),
        ActorPrivateEventRefusal::CasConflict
    );
    let skipped = push_route(5, false, 3);
    assert_eq!(
        refused(store.submit(&skipped).await.unwrap()),
        ActorPrivateEventRefusal::CasConflict
    );
    assert_eq!(count(&pool, "actor_private_events").await, 1);
    assert_eq!(
        text(
            &pool,
            "SELECT revision::text AS value FROM device_push_routes"
        )
        .await,
        "1"
    );

    // The revoked tombstone keeps the revision high-water and drops every
    // route secret.
    let revoke = push_route(1, true, 4);
    assert_eq!(
        accepted(store.submit(&revoke).await.unwrap()),
        ActorPrivateEventSubmitOutcome::DevicePushRoute {
            accepted_event_id: revoke.event.event_id.clone(),
            revision: 2,
        }
    );
    assert_eq!(
        text(
            &pool,
            "SELECT (revoked AND NOT route_value ? 'push_target_id' \
             AND NOT route_value ? 'encryption_key')::text AS value FROM device_push_routes"
        )
        .await,
        "true"
    );
    assert_eq!(count(&pool, "device_push_routes").await, 1);
    assert_eq!(count(&pool, "actor_private_events").await, 2);

    // An effect whose owner is not the named owner never reaches storage.
    let mut unbound = push_route(2, false, 5);
    unbound.owner = agent();
    assert!(store.submit(&unbound).await.is_err());
    assert_eq!(count(&pool, "actor_private_events").await, 2);
}

#[tokio::test]
async fn action_request_and_rejection_are_create_once_and_the_target_state_is_terminal() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let store = PgActorPrivateEventStore::new(pool.clone());

    // A rejection of a request that does not exist writes nothing.
    let orphan = reject("rejection-0", "request-1", 1);
    assert!(matches!(
        refused(store.submit(&orphan).await.unwrap()),
        ActorPrivateEventRefusal::FailedPrecondition(_)
    ));

    let request = action_request("request-1", 60_000, 2);
    assert_eq!(
        accepted(store.submit(&request).await.unwrap()),
        ActorPrivateEventSubmitOutcome::AgentActionRequest {
            accepted_event_id: request.event.event_id.clone(),
        }
    );
    assert!(matches!(
        store.submit(&request).await.unwrap(),
        ActorPrivateEventSubmitResult::Replayed(_)
    ));
    // Another Event at the occupied request key is a duplicate.
    let occupied = action_request("request-1", 60_000, 3);
    assert!(matches!(
        refused(store.submit(&occupied).await.unwrap()),
        ActorPrivateEventRefusal::DuplicateConflict(_)
    ));
    // An expired request is refused before any write.
    let expired = action_request("request-2", 1, 4);
    let mut expired = expired;
    expired.accepted_at = expired.accepted_at + chrono::Duration::seconds(1);
    assert!(matches!(
        refused(store.submit(&expired).await.unwrap()),
        ActorPrivateEventRefusal::FailedPrecondition(_)
    ));
    assert_eq!(count(&pool, "agent_action_requests").await, 1);
    assert_eq!(count(&pool, "actor_private_events").await, 1);

    let rejection = reject("rejection-1", "request-1", 5);
    assert_eq!(
        accepted(store.submit(&rejection).await.unwrap()),
        ActorPrivateEventSubmitOutcome::AgentActionReject {
            accepted_event_id: rejection.event.event_id.clone(),
        }
    );
    assert_eq!(
        text(
            &pool,
            "SELECT workflow_state||':'||rejection_id AS value FROM agent_action_requests"
        )
        .await,
        "rejected:rejection-1"
    );
    // The exact retry returns the first outcome without a second transition.
    assert!(matches!(
        store.submit(&rejection).await.unwrap(),
        ActorPrivateEventSubmitResult::Replayed(_)
    ));
    // A reused rejection id is a duplicate; a new rejection of the terminal
    // target is a failed precondition. Neither writes.
    let reused = reject("rejection-1", "request-1", 6);
    assert!(matches!(
        refused(store.submit(&reused).await.unwrap()),
        ActorPrivateEventRefusal::DuplicateConflict(_)
    ));
    let terminal = reject("rejection-2", "request-1", 7);
    assert!(matches!(
        refused(store.submit(&terminal).await.unwrap()),
        ActorPrivateEventRefusal::FailedPrecondition(_)
    ));
    assert_eq!(count(&pool, "agent_action_rejections").await, 1);
    assert_eq!(count(&pool, "actor_private_events").await, 2);
}

#[tokio::test]
async fn draft_proposal_creates_one_available_pending_intent_without_a_realm_commit() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let store = PgActorPrivateEventStore::new(pool.clone());

    let proposal = draft_propose("draft-1", 60_000, 1);
    assert_eq!(
        accepted(store.submit(&proposal).await.unwrap()),
        ActorPrivateEventSubmitOutcome::AgentDraftPropose {
            accepted_event_id: proposal.event.event_id.clone(),
        }
    );
    assert!(matches!(
        store.submit(&proposal).await.unwrap(),
        ActorPrivateEventSubmitResult::Replayed(_)
    ));
    let occupied = draft_propose("draft-1", 60_000, 2);
    assert!(matches!(
        refused(store.submit(&occupied).await.unwrap()),
        ActorPrivateEventRefusal::DuplicateConflict(_)
    ));
    let mut expired = draft_propose("draft-2", 1, 3);
    expired.accepted_at = expired.accepted_at + chrono::Duration::seconds(1);
    assert!(matches!(
        refused(store.submit(&expired).await.unwrap()),
        ActorPrivateEventRefusal::FailedPrecondition(_)
    ));
    assert_eq!(
        text(
            &pool,
            "SELECT state||':'||accepted_event_id AS value FROM agent_draft_pending_intents"
        )
        .await,
        format!("available:{}", proposal.event.event_id)
    );
    assert_eq!(count(&pool, "actor_private_events").await, 1);
    // The proposal is Station-private: no Realm Event or RealmCommit exists.
    assert_eq!(count(&pool, "realm_commits").await, 0);
    assert_eq!(count(&pool, "canonical_events").await, 0);
}
