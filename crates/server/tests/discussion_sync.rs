//! Retired discussion sync coverage uses committed stream positions and the
//! current membership/history policy. Equal Event timestamps deliberately
//! prove that the join Commit, rather than arrival time, defines the floor.

#[path = "../../storage-postgres/tests/support/ordinary_realm.rs"]
#[allow(dead_code)]
mod ordinary_realm;

use arkret_wire::{
    CommitStreamRef, CommittedEventView, EventKind, StrandId, StreamScanDirection,
    StreamScanOutcome, StreamScanRequest,
};
use coland_http::config::AppConfig;
use coland_http::service;
use coland_test_support::AppStateTestExt as _;
use salvo::http::StatusCode;
use salvo::test::{ResponseExt, TestClient};
use serde_json::{Value, json};

const SCAN_PATH: &str = "/_arkret/self/streams/scan";

async fn persisted_read_session(
    state: &coland_http::state::AppState,
    actor: &arkret_wire::DidCoreId,
) -> String {
    use base64::Engine as _;
    use sha2::{Digest, Sha256};

    let store = state.test_persistence();
    let now = chrono::Utc::now();
    let account_pk = store
        .accounts()
        .put(&coland_storage::AccountRecord {
            pk: coland_storage::AccountPk(0),
            principal_id: actor.clone(),
            station_id: state.service_core_id(),
            localpart: format!("history-{}", uuid::Uuid::now_v7().simple()),
            display_name: None,
            bio: None,
            avatar_blob_ref: None,
            created_at: now,
        })
        .await
        .unwrap();
    let token = format!("history-reader-{}", uuid::Uuid::now_v7());
    let mut hash = Sha256::new();
    hash.update(state.service_id().as_bytes());
    hash.update(b":");
    hash.update(token.as_bytes());
    let token_hash = format!(
        "sha256:{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hash.finalize())
    );
    let device_id = format!("ak:device:{}", uuid::Uuid::now_v7());
    store
        .devices()
        .put_if_absent(&coland_storage::DeviceInventoryRecord {
            actor: actor.to_string(),
            device_id: device_id.clone(),
            display_name: None,
            verification_state: "unverified".to_owned(),
            payload: json!({}),
            created_at: now,
            updated_at: now,
            revoked_at: None,
        })
        .await
        .unwrap();
    store
        .sessions()
        .put(&coland_storage::SessionRecord {
            token_hash,
            account_pk,
            actor: actor.to_string(),
            device_id,
            audience: state.service_id().clone(),
            session_public_key: None,
            agent_session: None,
            expires_at: now + chrono::Duration::hours(1),
            created_at: now,
            revoked_at: None,
        })
        .await
        .unwrap();
    token
}
async fn scan(
    state: &coland_http::state::AppState,
    token: &str,
    request: &StreamScanRequest,
) -> (StatusCode, Value) {
    let canonical_body = String::from_utf8(
        arkret_canonical::canonical_json_bytes(request).expect("canonical scan request"),
    )
    .expect("canonical JSON is UTF-8");
    let mut response = TestClient::post(format!("http://server{SCAN_PATH}"))
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header(
            "Arkret-Operation",
            arkret_wire::ServiceOperationId::SELF_COMMITTED_EVENT_READ_SCAN_V1,
            true,
        )
        .raw_json(canonical_body)
        .send(&service(state.clone()))
        .await;
    (
        response.status_code.expect("scan status"),
        response.take_json().await.expect("scan JSON"),
    )
}

fn seal_commit(state: &coland_http::state::AppState, commit: &mut arkret_wire::RealmCommit) {
    let identity = coland_test_support::fixture_service_identity(state.config());
    let key = ed25519_dalek::SigningKey::from_bytes(&coland_test_support::fixture_signing_seed(
        state.config(),
        &identity,
    ));
    commit.signature = arkret_signatures::detached_object::sign_detached_object(
        &arkret_canonical::canonical::unsigned_value(commit, &["signature"]).unwrap(),
        arkret_wire::DetachedSignatureContext::RealmCommit,
        arkret_wire::DidUrl::new(format!("{}#notary-key", state.service_did())).unwrap(),
        commit.committed_at,
        &key,
    )
    .unwrap();
    commit.verify_commit_id_matches_content().unwrap();
}

async fn next(
    state: &coland_http::state::AppState,
    pool: &coland_storage_postgres::PgPool,
    previous: &coland_storage::AuthorityCommitTransaction,
    kind: EventKind,
    payload: Value,
    actor: &arkret_wire::AccountId,
) -> coland_storage::EventCommitRequest {
    let mut request = ordinary_realm::next_request_for_actor(
        previous,
        kind,
        arkret_wire::ActorId::account(actor.clone()),
        payload,
        previous.commit.committed_at,
    );
    request.authority_commit.commit.signature =
        ordinary_realm::signature_for_did(&state.service_did(), previous.commit.committed_at);
    let mut request = Box::pin(ordinary_realm::source_request(pool, request)).await;
    seal_commit(state, &mut request.authority_commit.commit);
    request
}

async fn history_scenario(history: &str, via_invite: bool) {
    let (state, pool) = coland_test_support::app_state_with_pool(AppConfig {
        development_mode: true,
        ..coland_test_support::app_config()
    });
    let human = ordinary_realm::human_profile::admit_for_station_did(
        &pool,
        state.service_did(),
        "ordinary-founder",
    )
    .await;
    let persistence = state.test_persistence();
    let unit = ordinary_realm::bootstrap_unit_with_history_for_account(
        &format!("discussion-{history}-{}", uuid::Uuid::now_v7()),
        if via_invite { "invite" } else { "public" },
        history,
        &human,
        &state.service_did(),
    );
    let mut unit = Box::pin(ordinary_realm::source_bootstrap(&pool, unit)).await;
    for transaction in &mut unit.transactions {
        seal_commit(&state, &mut transaction.commit);
    }
    unit.validate().unwrap();
    persistence
        .authority_commits()
        .admit_ordinary_realm_bootstrap_unit(&unit, unit.transactions[0].commit.committed_at)
        .await
        .unwrap();
    let initial = unit.transactions.last().unwrap();
    let realm_id = initial.event.realm_id.clone();
    let strand = next(
        &state,
        &pool,
        initial,
        EventKind::StrandCreate,
        json!({"object": {
            "schema":"ak.schema.strand.v1", "realm_id":realm_id,
            "tracks":{"discussion":{"is_primary":true,"profile":"discussion"}},
            "metadata":{"title":"History floor"}, "state":"active",
            "created_by":initial.event.actor_id, "created_at":initial.commit.committed_at,
        }}),
        &human,
    )
    .await;
    persistence.commit_event(strand.clone()).await.unwrap();
    let strand_id = StrandId::from_event_id(&strand.authority_commit.event.event_id);
    let default = next(
        &state,
        &pool,
        &strand.authority_commit,
        EventKind::RealmSetDefaultStrand,
        json!({
            "realm_id":realm_id, "strand_id":strand_id, "expected_default_strand_id":null,
        }),
        &human,
    )
    .await;
    persistence.commit_event(default.clone()).await.unwrap();
    let before = next(
        &state,
        &pool,
        &default.authority_commit,
        EventKind::MessageCreate,
        ordinary_realm::message_payload(&strand_id, "before join"),
        &human,
    )
    .await;
    persistence.commit_event(before.clone()).await.unwrap();
    let bob_account = Box::pin(ordinary_realm::human_profile::admit_for_station_did(
        &pool,
        state.service_did(),
        "discussion-reader",
    ))
    .await;
    let bob = bob_account.principal_id.clone();
    let bob_actor = arkret_wire::ActorId::account(bob_account);
    let token = persisted_read_session(&state, &bob).await;
    let (previous, kind, payload) = if via_invite {
        let invite = next(
            &state, &pool,
            &before.authority_commit,
            EventKind::InviteCreate,
            json!({
                "invitee_account_id": bob_actor.as_account_id().unwrap(),
                "introduction_evidence_digest": format!("sha256:{}", "a".repeat(64)),
                "expires_at": arkret_canonical::format_timestamp_canonical(initial.commit.committed_at + chrono::Duration::days(7)),
            }),
            &human,
        ).await;
        persistence.commit_event(invite.clone()).await.unwrap();
        let payload = json!({
            "invite_id": arkret_wire::InviteId::from_event_id(&invite.authority_commit.event.event_id),
            "previous_state": "pending",
            "invitee_account_id": bob_actor.as_account_id().unwrap(),
        });
        (invite.authority_commit, EventKind::InviteAccept, payload)
    } else {
        (
            before.authority_commit.clone(),
            EventKind::MemberState,
            json!({"member_id":bob_actor,"membership":"join"}),
        )
    };
    let mut join =
        ordinary_realm::next_request(&previous, kind, &bob, payload, initial.commit.committed_at);
    join.authority_commit.commit.signature =
        ordinary_realm::signature_for_did(&state.service_did(), initial.commit.committed_at);
    let mut join = Box::pin(ordinary_realm::source_request(&pool, join)).await;
    seal_commit(&state, &mut join.authority_commit.commit);
    persistence.commit_event(join.clone()).await.unwrap();
    let after = next(
        &state,
        &pool,
        &join.authority_commit,
        EventKind::MessageCreate,
        ordinary_realm::message_payload(&strand_id, "after join"),
        &human,
    )
    .await;
    persistence.commit_event(after.clone()).await.unwrap();
    assert_eq!(
        before.authority_commit.event.created_at,
        after.authority_commit.event.created_at
    );
    let request = StreamScanRequest {
        realm_id: realm_id.clone(),
        stream_ref: CommitStreamRef::Realm { realm_id },
        direction: StreamScanDirection::After(None),
        limit: 100,
    };
    let (status, body) = scan(&state, &token, &request).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let page: StreamScanOutcome = serde_json::from_value(body).unwrap();
    page.validate_for_request(&request).unwrap();
    let event_ids = page
        .committed_events
        .iter()
        .filter_map(|view| {
            if let CommittedEventView::Full(full) = view {
                Some(full.event.event_id.clone())
            } else {
                None
            }
        })
        .collect::<Vec<_>>();
    assert!(event_ids.contains(&after.authority_commit.event.event_id));
    let floor = page.readable_floor.as_ref().unwrap();
    if history == "since_join" {
        assert!(!event_ids.contains(&before.authority_commit.event.event_id));
        assert_eq!(
            floor.oldest_position,
            join.authority_commit.commit.stream_position
        );
        assert_eq!(
            floor.floor_commit_id,
            join.authority_commit.commit.commit_id
        );
        assert_eq!(
            floor.floor_reason,
            arkret_wire::ReadableFloorReason::MembershipJoin
        );
    } else {
        assert!(event_ids.contains(&before.authority_commit.event.event_id));
        assert_eq!(floor.oldest_position, 0);
        assert_eq!(
            floor.floor_reason,
            arkret_wire::ReadableFloorReason::StreamStart
        );
    }
    let continuation = StreamScanRequest {
        direction: StreamScanDirection::After(Some(join.authority_commit.commit.stream_position)),
        ..request
    };
    let (status, body) = scan(&state, &token, &continuation).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let tail: StreamScanOutcome = serde_json::from_value(body).unwrap();
    tail.validate_for_request(&continuation).unwrap();
    assert_eq!(tail.committed_events.len(), 1);
    assert_eq!(
        tail.committed_events[0].commit(),
        &after.authority_commit.commit
    );
    assert_eq!(tail.readable_floor, page.readable_floor);
}

#[tokio::test]
async fn since_join_hides_prior_messages_and_continues_from_join_commit() {
    history_scenario("since_join", false).await;
}

#[tokio::test]
async fn shared_history_backfills_prior_messages_for_a_current_member() {
    history_scenario("all_history_for_current_members", false).await;
}

#[tokio::test]
async fn invite_accept_sets_the_since_join_floor_and_continuation() {
    history_scenario("since_join", true).await;
}
