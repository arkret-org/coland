//! The canonical self stream scan discloses an accepted Message until an
//! accepted redaction withholds its bytes. Both reads retain the exact Commit
//! chain; an outsider learns no readable interval.

#[path = "../../storage-postgres/tests/support/ordinary_realm.rs"]
#[allow(dead_code)]
mod ordinary_realm;

use arkret_wire::{
    CommitStreamRef, CommittedEventView, EventKind, MessageId, StrandId, StreamScanDirection,
    StreamScanRequestBody, StreamScanResponseBody,
};
use coland_http::config::AppConfig;
use coland_http::service;
use coland_test_support::AppStateTestExt as _;
use salvo::http::StatusCode;
use salvo::test::{ResponseExt, TestClient};
use serde_json::{Value, json};

const SCAN_PATH: &str = "/_arkret/self/streams/scan";

#[tokio::test]
async fn authority_bundle_unknown_refuses_and_unavailable_remote_locator_fails_closed() {
    let mut config = AppConfig {
        development_mode: true,
        ..coland_test_support::app_config()
    };
    config.did_resolver_allow_methods.push("webvh".into());
    let (state, _pool) = coland_test_support::app_state_with_pool(config);
    let foreign =
        ordinary_realm::bootstrap_unit(&format!("non-governing-bundle-{}", uuid::Uuid::now_v7()));
    // A replica records remote governance without importing foreign devices
    // into its own Station inventory or executing a foreign bootstrap locally.
    state
        .test_persistence()
        .authority_commits()
        .record_remote_authority(
            &foreign.transactions[0].expected_authority,
            &state.service_core_id(),
        )
        .await
        .expect("durable remote Realm authority");
    let unknown =
        ordinary_realm::bootstrap_unit(&format!("unknown-bundle-{}", uuid::Uuid::now_v7()));
    // A known remote governor is a locator: only its verified nonce-bound
    // original can succeed. An unavailable dependency is the registered 503,
    // while an unknown Realm has the registered non-enumerating not_found.
    for (realm_id, status, code) in [
        (
            foreign.transactions[0].event.realm_id.clone(),
            StatusCode::SERVICE_UNAVAILABLE,
            "temporarily_unavailable",
        ),
        (
            unknown.transactions[0].event.realm_id.clone(),
            StatusCode::NOT_FOUND,
            "not_found",
        ),
    ] {
        let request = arkret_wire::RealmAuthorityBundleRequestBody {
            realm_id,
            nonce: arkret_wire::Base64UrlString::new(arkret_canonical::base64url_encode([7u8; 32]))
                .unwrap(),
        };
        let before = state
            .test_persistence()
            .authority_commits()
            .current_authority(&request.realm_id)
            .await
            .unwrap();
        let body =
            String::from_utf8(arkret_canonical::canonical_json_bytes(&request).unwrap()).unwrap();
        let mut response = TestClient::post("http://server/_arkret/open/realm-authority/bundle")
            .add_header(
                "Arkret-Operation",
                arkret_wire::ServiceOperationId::OPEN_REALM_AUTHORITY_READ_BUNDLE_V1,
                true,
            )
            .raw_json(body)
            .send(&service(state.clone()))
            .await;
        let received_status = response.status_code;
        let problem: Value = response.take_json().await.unwrap();
        assert_eq!(received_status, Some(status), "{problem}");
        assert_eq!(
            problem["type"],
            format!("https://arkret.org/problems/{code}")
        );
        assert!(problem["instance"].as_str().is_some());
        assert_eq!(
            state
                .test_persistence()
                .authority_commits()
                .current_authority(&request.realm_id)
                .await
                .unwrap(),
            before
        );
        assert!(
            state
                .test_persistence()
                .authority_commits()
                .held_stream_head_commit(&CommitStreamRef::Realm {
                    realm_id: request.realm_id
                })
                .await
                .unwrap()
                .is_none(),
            "a failed locator read must not mint a local Realm head"
        );
    }
}

async fn dev_session(
    state: &coland_http::state::AppState,
    actor: &arkret_wire::DidCoreId,
) -> String {
    let mut response = TestClient::post("http://server/_coland/gate/auth/dev-login")
        .json(&json!({
            "actor": actor,
            "device_id": format!("ak:device:{}", uuid::Uuid::now_v7()),
            "display_name": "Stream scan fixture",
        }))
        .send(&service(state.clone()))
        .await;
    assert_eq!(response.status_code, Some(StatusCode::OK));
    let body: Value = response.take_json().await.expect("dev session JSON");
    body["session_credential"]
        .as_str()
        .expect("dev session credential")
        .to_owned()
}

async fn scan(
    state: &coland_http::state::AppState,
    token: &str,
    request: &StreamScanRequestBody,
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
    station_did: &arkret_wire::Did,
) -> coland_storage::EventCommitRequest {
    let mut request = ordinary_realm::next_request_for_actor(
        previous,
        kind,
        arkret_wire::ActorId::account(actor.clone()),
        payload,
        previous.commit.committed_at,
    );
    request.authority_commit.commit.signature =
        ordinary_realm::signature_for_did(station_did, previous.commit.committed_at);
    let mut request = ordinary_realm::source_request(pool, request).await;
    seal_commit(state, &mut request.authority_commit.commit);
    request
}

#[tokio::test]
async fn canonical_scan_withholds_redacted_message_without_skipping_commit() {
    let config = AppConfig {
        development_mode: true,
        ..coland_test_support::app_config()
    };
    let (state, pool) = coland_test_support::app_state_with_pool(config);
    let human = ordinary_realm::human_profile::admit_for_station_did(
        &pool,
        state.service_did(),
        "ordinary-founder",
    )
    .await;
    let persistence = state.test_persistence();
    let unit = ordinary_realm::bootstrap_unit_for_account(
        &format!("http-redaction-{}", uuid::Uuid::now_v7()),
        &human,
        &state.service_did(),
    );
    let mut unit = ordinary_realm::source_bootstrap(&pool, unit).await;
    for transaction in &mut unit.transactions {
        seal_commit(&state, &mut transaction.commit);
    }
    unit.validate()
        .expect("formal ordinary Realm bootstrap unit");
    persistence
        .authority_commits()
        .admit_ordinary_realm_bootstrap_unit(&unit, unit.transactions[0].commit.committed_at)
        .await
        .expect("accepted Realm bootstrap Events and Commits");

    let initial = unit.transactions.last().expect("bootstrap head");
    let realm_id = initial.event.realm_id.clone();
    let founder = human.principal_id.clone();
    let token = dev_session(&state, &founder).await;
    let outsider = dev_session(
        &state,
        &arkret_wire::DidCoreId::new("ak:did_core:web:scan-outsider.example").unwrap(),
    )
    .await;
    let request = StreamScanRequestBody {
        realm_id: realm_id.clone(),
        stream_ref: CommitStreamRef::Realm {
            realm_id: realm_id.clone(),
        },
        direction: StreamScanDirection::After(None),
        limit: 100,
    };

    let strand = next(
        &state,
        &pool,
        initial,
        EventKind::StrandCreate,
        json!({"object": {
            "schema": "ak.schema.strand.v1",
            "realm_id": realm_id,
            "tracks": {"discussion": {"is_primary": true, "profile": "discussion"}},
            "metadata": {"title": "Redaction scan"},
            "state": "active",
            "created_by": initial.event.actor_id,
            "created_at": initial.commit.committed_at,
        }}),
        &human,
        &state.service_did(),
    )
    .await;
    persistence
        .commit_event(strand.clone())
        .await
        .expect("accepted Strand Event and Commit");
    let strand_id = StrandId::from_event_id(&strand.authority_commit.event.event_id);
    let default = next(
        &state,
        &pool,
        &strand.authority_commit,
        EventKind::RealmSetDefaultStrand,
        json!({
            "realm_id": realm_id,
            "strand_id": strand_id,
            "expected_default_strand_id": null,
        }),
        &human,
        &state.service_did(),
    )
    .await;
    persistence
        .commit_event(default.clone())
        .await
        .expect("accepted default Strand Event and Commit");
    let message = next(
        &state,
        &pool,
        &default.authority_commit,
        EventKind::MessageCreate,
        ordinary_realm::message_payload(&strand_id, "redacted content"),
        &human,
        &state.service_did(),
    )
    .await;
    persistence
        .commit_event(message.clone())
        .await
        .expect("accepted Message Event and Commit");

    let (status, before_body) = scan(&state, &token, &request).await;
    assert_eq!(status, StatusCode::OK, "{before_body}");
    let before: StreamScanResponseBody =
        serde_json::from_value(before_body).expect("typed pre-redaction scan");
    before
        .validate_for_request(&request)
        .expect("valid scan page");
    let message_commit = &message.authority_commit.commit;
    assert!(before.committed_events.iter().any(|row| {
        matches!(row, CommittedEventView::Full(full)
            if full.commit == *message_commit
                && full.event == message.authority_commit.event)
    }));

    let message_id = MessageId::from_event_id(&message.authority_commit.event.event_id);
    let redaction = next(
        &state,
        &pool,
        &message.authority_commit,
        EventKind::MessageRedact,
        json!({"message_id": message_id, "reason": "retracted by author"}),
        &human,
        &state.service_did(),
    )
    .await;
    persistence
        .commit_event(redaction.clone())
        .await
        .expect("accepted redaction Event and Commit");

    let (status, after_body) = scan(&state, &token, &request).await;
    assert_eq!(status, StatusCode::OK, "{after_body}");
    let after: StreamScanResponseBody =
        serde_json::from_value(after_body).expect("typed post-redaction scan");
    after
        .validate_for_request(&request)
        .expect("contiguous scan page");
    assert_eq!(
        after.committed_events.len(),
        before.committed_events.len() + 1
    );
    assert_eq!(
        after
            .committed_events
            .iter()
            .map(|row| row.commit().stream_position)
            .collect::<Vec<_>>(),
        (0..=redaction.authority_commit.commit.stream_position).collect::<Vec<_>>()
    );
    assert!(after.committed_events.iter().any(|row| {
        matches!(row, CommittedEventView::Withheld(withheld)
            if withheld.commit == *message_commit)
    }));
    assert!(after.committed_events.iter().any(|row| {
        matches!(row, CommittedEventView::Full(full)
            if full.commit == redaction.authority_commit.commit
                && full.event == redaction.authority_commit.event)
    }));
    let (status, denied) = scan(&state, &outsider, &request).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{denied}");
    assert_eq!(
        denied["type"],
        "https://arkret.org/problems/capability_denied"
    );
}
