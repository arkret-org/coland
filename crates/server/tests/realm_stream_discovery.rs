//! Real HTTP stream enumeration across the 500-row boundary, frozen heads,
//! current membership loss, and cursor binding. No domain rows are fabricated.
#[path = "../../storage-postgres/tests/support/ordinary_realm.rs"]
#[allow(dead_code)]
mod ordinary_realm;

use arkret_wire::{ActorId, CommitStreamRef, EventKind, RealmId, RealmStreamList};
use coland_http::config::AppConfig;
use coland_http::service;
use coland_storage::AuthorityCommitTransaction;
use coland_test_support::AppStateTestExt as _;
use salvo::http::StatusCode;
use salvo::test::{ResponseExt, TestClient};
use serde_json::{Value, json};

async fn session(
    state: &coland_http::state::AppState,
    account: &arkret_wire::AccountId,
    label: &str,
) -> String {
    let now = chrono::Utc::now();
    let persistence = state.test_persistence();
    let account_pk = persistence
        .accounts()
        .put(&coland_storage::AccountRecord {
            pk: coland_storage::AccountPk(0),
            principal_id: account.principal_id.clone(),
            station_id: account.station_id.clone(),
            localpart: label.to_owned(),
            display_name: None,
            bio: None,
            avatar_blob_ref: None,
            created_at: now,
        })
        .await
        .unwrap();
    let identity = arkret_canonical::canonical_json_bytes(&(&state.service_did(), label)).unwrap();
    let device_id = format!(
        "ak:device:01904100-0000-7000-8000-{}",
        arkret_canonical::sha256_bytes(identity)[..6]
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    );
    let token = uuid::Uuid::now_v7().to_string();
    persistence
        .sessions()
        .put(&coland_storage::SessionRecord {
            token_hash: format!(
                "sha256:{}",
                arkret_wire::base64url::base64url_encode(&arkret_canonical::sha256_bytes(
                    format!("{}:{token}", state.service_id()).as_bytes()
                ))
            ),
            account_pk,
            actor: account.principal_id.to_string(),
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

async fn listing(
    state: &coland_http::state::AppState,
    token: &str,
    realm: &RealmId,
    limit: usize,
    cursor: Option<&str>,
) -> (StatusCode, Value) {
    let mut url = url::Url::parse(&format!(
        "http://server/_arkret/self/realms/{realm}/streams"
    ))
    .unwrap();
    url.query_pairs_mut()
        .append_pair("limit", &limit.to_string());
    if let Some(cursor) = cursor {
        url.query_pairs_mut().append_pair("cursor", cursor);
    }
    let mut response = TestClient::get(url.as_str())
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header(
            "Arkret-Operation",
            arkret_wire::ServiceOperationId::SELF_REALM_READ_STREAMS_V1,
            true,
        )
        .send(&service(state.clone()))
        .await;
    (
        response.status_code.unwrap(),
        response.take_json().await.unwrap(),
    )
}

async fn snapshot(
    state: &coland_http::state::AppState,
    token: &str,
    realm: &RealmId,
    id: Option<&arkret_wire::RealmSnapshotId>,
) -> (StatusCode, Value) {
    let suffix = id.map_or_else(|| "head".to_owned(), ToString::to_string);
    let mut url = url::Url::parse(&format!(
        "http://server/_arkret/self/realm-state-snapshot/{suffix}"
    ))
    .unwrap();
    url.query_pairs_mut()
        .append_pair("realm_id", realm.as_str());
    let operation = if id.is_some() {
        arkret_wire::ServiceOperationId::SELF_REALM_STATE_SNAPSHOT_READ_BY_REF_V1
    } else {
        arkret_wire::ServiceOperationId::SELF_REALM_STATE_SNAPSHOT_READ_MANIFEST_HEAD_V1
    };
    let mut response = TestClient::get(url.as_str())
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("Arkret-Operation", operation, true)
        .send(&service(state.clone()))
        .await;
    (
        response.status_code.unwrap(),
        response.take_json().await.unwrap(),
    )
}

fn verify_snapshot(
    state: &coland_http::state::AppState,
    snapshot: &arkret_wire::RealmStateSnapshot,
) {
    let identity = coland_test_support::fixture_service_identity(state.config());
    let key = ed25519_dalek::SigningKey::from_bytes(&coland_test_support::fixture_signing_seed(
        state.config(),
        &identity,
    ));
    let unsigned = arkret_canonical::unsigned_value(snapshot, &["signature"]).unwrap();
    arkret_signatures::detached_object::verify_detached_object_signature(
        &snapshot.signature,
        &unsigned,
        arkret_wire::DetachedSignatureContext::RealmSnapshot,
        &arkret_signatures::PublicKeyMaterial::Ed25519Raw {
            bytes: key.verifying_key().to_bytes().to_vec(),
        },
    )
    .unwrap();
    let identity =
        arkret_canonical::unsigned_value(snapshot, &["signature", "snapshot_id"]).unwrap();
    assert_eq!(
        snapshot.snapshot_id,
        arkret_wire::RealmSnapshotId::from_digest(arkret_canonical::sha256_bytes(
            arkret_canonical::canonical_json_bytes(&identity).unwrap()
        ))
    );
    assert_eq!(snapshot.governance_generation, 0);
    for row in &snapshot.current_state_entries {
        let arkret_wire::TypedCurrentRow::Value {
            source_stream_ref,
            revision,
            ..
        } = row;
        let head = snapshot
            .visible_stream_heads
            .iter()
            .find(|head| &head.stream_ref == source_stream_ref)
            .unwrap();
        assert!(revision.stream_position <= head.stream_position);
        if revision.stream_position == head.stream_position {
            assert_eq!(revision.commit_id, head.commit_id);
        }
    }
}

async fn create_circle(
    state: &coland_http::state::AppState,
    pool: &coland_storage_postgres::PgPool,
    previous: &AuthorityCommitTransaction,
    actor: &ActorId,
    parent: &Value,
    index: usize,
) -> (
    AuthorityCommitTransaction,
    coland_storage::EventCommitRequest,
) {
    let at = previous.commit.committed_at;
    let mut create = ordinary_realm::next_request_for_actor(
        previous,
        EventKind::CircleCreate,
        actor.clone(),
        json!({"object":{"schema":"ak.schema.circle.v1","realm_id":previous.event.realm_id,
            "title":format!("Discovery {index}"),"display":{"short_name":format!("C{index}"),"color_token":"blue","symbol":{"glyph":"lock"}},
            "directory_visibility":"members","join_rule":"public","history_access":"since_join","state":"active",
            "created_by":actor,"created_at":arkret_canonical::format_timestamp_canonical(at)}}),
        at,
    );
    create.authority_commit.commit.signature =
        ordinary_realm::signature_for_did(&state.service_did(), at);
    let mut create = ordinary_realm::source_request(pool, create).await;
    seal_commit(state, &mut create.authority_commit.commit);
    state
        .test_persistence()
        .commit_event(create.clone())
        .await
        .unwrap();
    let circle = arkret_wire::CircleId::from_event_id(&create.authority_commit.event.event_id);
    let mut join = membership(
        &create.authority_commit,
        &circle,
        actor,
        "join",
        None,
        Some(parent.clone()),
    );
    join.authority_commit.commit.signature =
        ordinary_realm::signature_for_did(&state.service_did(), at);
    let mut join = ordinary_realm::source_request(pool, join).await;
    seal_commit(state, &mut join.authority_commit.commit);
    state
        .test_persistence()
        .commit_event(join.clone())
        .await
        .unwrap();
    (create.authority_commit, join)
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

fn membership(
    previous: &AuthorityCommitTransaction,
    circle: &arkret_wire::CircleId,
    actor: &ActorId,
    state: &str,
    expected: Option<&str>,
    parent: Option<serde_json::Value>,
) -> coland_storage::EventCommitRequest {
    let scope = arkret_wire::ScopeRef::Circle {
        realm_id: previous.event.realm_id.clone(),
        circle_id: circle.clone(),
    };
    let event = ordinary_realm::event_for_actor(
        EventKind::CircleMemberState,
        scope,
        actor.clone(),
        {
            let mut payload = serde_json::json!({"circle_id":circle,"member_id":actor,"membership":state,"expected_membership":expected});
            if let Some(parent) = parent {
                payload["parent_membership_revision"] = parent;
            }
            payload
        },
        previous.commit.committed_at,
    );
    let mut request =
        ordinary_realm::request_for_event(previous, event, previous.commit.committed_at);
    let stream = CommitStreamRef::Circle {
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
    request
}

fn run_http_scenario<F: std::future::Future<Output = ()> + 'static>(make: fn() -> F) {
    // Salvo's full service plus native admission creates large debug futures.
    std::thread::Builder::new()
        .stack_size(16 * 1024 * 1024)
        .spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(Box::pin(make()));
        })
        .unwrap()
        .join()
        .unwrap();
}

#[test]
fn frozen_http_enumeration_crosses_500_and_rechecks_current_membership() {
    run_http_scenario(frozen_enumeration_scenario);
}

async fn frozen_enumeration_scenario() {
    let config = AppConfig {
        development_mode: true,
        ..coland_test_support::app_config()
    };
    let (state, pool) = coland_test_support::app_state_with_pool(config);
    let human = ordinary_realm::human_profile::admit_for_station_did(
        &pool,
        state.service_did(),
        "discovery-founder",
    )
    .await;
    let unit = ordinary_realm::bootstrap_unit_for_account(
        &uuid::Uuid::now_v7().to_string(),
        &human,
        &state.service_did(),
    );
    let mut unit = ordinary_realm::source_bootstrap(&pool, unit).await;
    for transaction in &mut unit.transactions {
        seal_commit(&state, &mut transaction.commit);
    }
    unit.validate().unwrap();
    state
        .test_persistence()
        .authority_commits()
        .admit_ordinary_realm_bootstrap_unit(&unit, unit.transactions[0].commit.committed_at)
        .await
        .unwrap();
    let mut head = unit.transactions.last().unwrap().clone();
    let realm = head.event.realm_id.clone();
    let actor = ActorId::account(human.clone());
    let token = session(&state, &human, "discovery-founder").await;
    let other_account = ordinary_realm::human_profile::admit_for_station_did(
        &pool,
        state.service_did(),
        "discovery-outsider",
    )
    .await;
    let outsider = session(&state, &other_account, "discovery-outsider").await;
    let parent = ordinary_realm::parent_membership_revision(&pool, &realm, &actor).await;
    let mut joins = std::collections::BTreeMap::new();
    for index in 0..501 {
        let (next, join) = create_circle(&state, &pool, &head, &actor, &parent, index).await;
        joins.insert(join.authority_commit.commit.stream_ref.clone(), join);
        head = next;
    }
    let cut = state
        .test_persistence()
        .authority_commits()
        .list_realm_streams_for_account(&realm, &human, &state.service_core_id())
        .await
        .unwrap();
    assert!(
        matches!(&cut, coland_storage::AccountRealmStreamList::Listed(rows) if rows.len() == 502),
        "{cut:?}"
    );
    let (status, value) = listing(&state, &token, &realm, 500, None).await;
    assert_eq!(status, StatusCode::OK, "{value}");
    let first: RealmStreamList = serde_json::from_value(value).unwrap();
    first.validate().unwrap();
    assert_eq!(first.streams.len(), 500);
    assert!(first.has_more);
    let cursor = first.next_cursor.as_deref().unwrap();
    let decoded = arkret_wire::cursor::Cursor::decode(cursor).unwrap();
    let mut tampered = decoded.clone();
    tampered.expires_at += chrono::Duration::milliseconds(1);
    assert_eq!(
        listing(
            &state,
            &token,
            &realm,
            500,
            Some(&tampered.encode().unwrap())
        )
        .await
        .1["type"],
        "https://arkret.org/problems/cursor_integrity_invalid"
    );
    tampered = decoded.clone();
    tampered.h = arkret_wire::cursor::generate_cursor_handle().unwrap();
    assert_eq!(
        listing(
            &state,
            &token,
            &realm,
            500,
            Some(&tampered.encode().unwrap())
        )
        .await
        .1["type"],
        "https://arkret.org/problems/cursor_integrity_invalid"
    );
    tampered = decoded.clone().with_barrier();
    let (status, refusal) = listing(
        &state,
        &token,
        &realm,
        500,
        Some(&tampered.encode().unwrap()),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(refusal["reason_code"], "invalid_cursor");
    let (status, value) = listing(&state, &token, &realm, 500, Some(cursor)).await;
    assert_eq!(status, StatusCode::OK, "{value}");
    let last: RealmStreamList = serde_json::from_value(value).unwrap();
    last.validate().unwrap();
    assert_eq!(last.streams.len(), 2);
    assert!(!last.has_more);
    let frozen = first
        .streams
        .iter()
        .chain(&last.streams)
        .cloned()
        .collect::<Vec<_>>();
    assert_eq!(
        listing(&state, &outsider, &realm, 500, Some(cursor))
            .await
            .0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        listing(&state, &token, &realm, 499, Some(cursor)).await.0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        listing(&state, &token, &realm, 501, None).await.0,
        StatusCode::UNPROCESSABLE_ENTITY
    );
    let other: RealmId = "ak:realm:AUGIFvQctz4TjQTmvvO4Wdy-xdc5XP2ZnJ5Qpbh4s8Ru"
        .parse()
        .unwrap();
    assert_eq!(
        listing(&state, &token, &other, 500, Some(cursor)).await.0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        listing(&state, &token, &realm, 500, Some("garbage"))
            .await
            .0,
        StatusCode::BAD_REQUEST
    );

    let (status, value) = snapshot(&state, &token, &realm, None).await;
    assert_eq!(status, StatusCode::OK, "{value}");
    let signed: arkret_wire::RealmStateSnapshot = serde_json::from_value(value).unwrap();
    verify_snapshot(&state, &signed);
    assert_eq!(signed.visible_stream_heads.len(), 502);
    assert_eq!(signed.retention_and_history_floor.stream_floors.len(), 502);
    let (status, value) = snapshot(&state, &token, &realm, Some(&signed.snapshot_id)).await;
    assert_eq!(status, StatusCode::OK, "{value}");
    assert_eq!(
        serde_json::from_value::<arkret_wire::RealmStateSnapshot>(value).unwrap(),
        signed
    );
    assert_eq!(
        snapshot(&state, &outsider, &realm, None).await.0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        snapshot(&state, &outsider, &realm, Some(&signed.snapshot_id))
            .await
            .0,
        StatusCode::FORBIDDEN
    );

    let revoke = last
        .streams
        .iter()
        .find(|row| matches!(row.stream_ref, CommitStreamRef::Circle { .. }))
        .unwrap()
        .clone();
    let joined = &joins[&revoke.stream_ref];
    let CommitStreamRef::Circle { circle_id, .. } = &revoke.stream_ref else {
        unreachable!()
    };
    let mut leave = membership(
        &joined.authority_commit,
        circle_id,
        &actor,
        "leave",
        Some("join"),
        None,
    );
    leave.authority_commit.commit.signature =
        ordinary_realm::signature_for_did(&state.service_did(), head.commit.committed_at);
    let mut leave = ordinary_realm::source_request(&pool, leave).await;
    seal_commit(&state, &mut leave.authority_commit.commit);
    state.test_persistence().commit_event(leave).await.unwrap();
    let (_, new_join) = create_circle(&state, &pool, &head, &actor, &parent, 502).await;
    let (status, value) = listing(&state, &token, &realm, 500, Some(cursor)).await;
    assert_eq!(status, StatusCode::OK, "{value}");
    let narrowed: RealmStreamList = serde_json::from_value(value).unwrap();
    assert_eq!(
        narrowed.streams,
        last.streams
            .into_iter()
            .filter(|row| row.stream_ref != revoke.stream_ref)
            .collect::<Vec<_>>()
    );
    assert!(
        narrowed
            .streams
            .iter()
            .all(|row| row.stream_ref != new_join.authority_commit.commit.stream_ref)
    );
    assert!(!narrowed.has_more);

    let (status, refusal) = snapshot(&state, &token, &realm, Some(&signed.snapshot_id)).await;
    assert_ne!(status, StatusCode::OK);
    assert_eq!(
        refusal["type"],
        "https://arkret.org/problems/realm_state_snapshot_unavailable"
    );
    let (status, value) = snapshot(&state, &token, &realm, None).await;
    assert_eq!(status, StatusCode::OK, "{value}");
    let fresh: arkret_wire::RealmStateSnapshot = serde_json::from_value(value).unwrap();
    verify_snapshot(&state, &fresh);
    assert!(
        fresh
            .visible_stream_heads
            .iter()
            .all(|head| head.stream_ref != revoke.stream_ref)
    );
    assert!(
        fresh
            .retention_and_history_floor
            .stream_floors
            .iter()
            .all(|floor| floor.stream_ref != revoke.stream_ref)
    );
    assert!(fresh.current_state_entries.iter().all(|row| {
        let arkret_wire::TypedCurrentRow::Value {
            source_stream_ref, ..
        } = row;
        source_stream_ref != &revoke.stream_ref
    }));

    let refreshed = session(&state, &human, "discovery-founder").await;
    let revoke_cursor = cursor.to_owned();
    let mut cursor = None;
    let mut expiry = None;
    let mut enumerated = Vec::new();
    loop {
        let (status, value) = listing(
            &state,
            if cursor.is_some() { &refreshed } else { &token },
            &realm,
            37,
            cursor.as_deref(),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{value}");
        let page: RealmStreamList = serde_json::from_value(value).unwrap();
        page.validate().unwrap();
        assert!(page.streams.len() <= 37);
        enumerated.extend(page.streams);
        cursor = page.next_cursor;
        if let Some(token) = &cursor {
            let decoded = arkret_wire::cursor::Cursor::decode(token).unwrap();
            assert_eq!(
                *expiry.get_or_insert(decoded.expires_at),
                decoded.expires_at
            );
        }
        if cursor.is_none() {
            break;
        }
    }
    assert_eq!(enumerated.len(), 502);
    assert!(
        enumerated
            .iter()
            .any(|row| row.stream_ref == new_join.authority_commit.commit.stream_ref)
    );
    assert!(
        !enumerated
            .iter()
            .any(|row| row.stream_ref == revoke.stream_ref)
    );
    assert_eq!(
        enumerated
            .iter()
            .map(|row| &row.stream_ref)
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        502
    );
    assert!(frozen.windows(2).all(|pair| {
        arkret_canonical::canonical_json_bytes(&pair[0].stream_ref).unwrap()
            < arkret_canonical::canonical_json_bytes(&pair[1].stream_ref).unwrap()
    }));
    let body = arkret_models_identity::account::AccountCursorRevokeRequestBody {
        cursor: revoke_cursor.clone(),
        reason_code: arkret_wire::ReasonCode::from_wire(arkret_wire::ReasonCode::INVALID_CURSOR),
        revoke_scope: arkret_models_identity::account::CursorRevokeScope::ThisCursor,
    };
    let mut response = TestClient::post("http://server/_arkret/self/account/cursor/revoke")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header(
            "Arkret-Operation",
            arkret_wire::ServiceOperationId::SELF_ACCOUNT_COMMAND_REVOKE_CURSOR_V1,
            true,
        )
        .raw_json(
            String::from_utf8(arkret_canonical::canonical_json_bytes(&body).unwrap()).unwrap(),
        )
        .send(&service(state.clone()))
        .await;
    let status = response.status_code.unwrap();
    let value: Value = response.take_json().await.unwrap();
    assert_eq!(status, StatusCode::OK, "{value}");
    let (_, refusal) = listing(&state, &token, &realm, 500, Some(&revoke_cursor)).await;
    assert_eq!(
        refusal["type"],
        "https://arkret.org/problems/cursor_revoked"
    );
}

#[test]
fn stream_enumeration_new_handles_bind_the_actual_issuing_session() {
    run_http_scenario(issuing_session_scenario);
}

async fn issuing_session_scenario() {
    use diesel_async::RunQueryDsl as _;
    #[derive(diesel::QueryableByName)]
    struct Count {
        #[diesel(sql_type = diesel::sql_types::BigInt)]
        value: i64,
    }
    let (state, pool) = coland_test_support::app_state_with_pool(AppConfig {
        development_mode: true,
        ..coland_test_support::app_config()
    });
    let human = ordinary_realm::human_profile::admit_for_station_did(
        &pool,
        state.service_did(),
        "issuing-session-founder",
    )
    .await;
    let unit = ordinary_realm::bootstrap_unit_for_account(
        &uuid::Uuid::now_v7().to_string(),
        &human,
        &state.service_did(),
    );
    let mut unit = ordinary_realm::source_bootstrap(&pool, unit).await;
    for transaction in &mut unit.transactions {
        seal_commit(&state, &mut transaction.commit);
    }
    unit.validate().unwrap();
    state
        .test_persistence()
        .authority_commits()
        .admit_ordinary_realm_bootstrap_unit(&unit, unit.transactions[0].commit.committed_at)
        .await
        .unwrap();
    let mut head = unit.transactions.last().unwrap().clone();
    let realm = head.event.realm_id.clone();
    let actor = ActorId::account(human.clone());
    let parent = ordinary_realm::parent_membership_revision(&pool, &realm, &actor).await;
    for index in 0..2 {
        head = create_circle(&state, &pool, &head, &actor, &parent, index)
            .await
            .0;
    }
    let original = session(&state, &human, "issuing-session-founder").await;
    let refreshed = session(&state, &human, "issuing-session-founder").await;
    let (status, first) = listing(&state, &original, &realm, 1, None).await;
    assert_eq!(status, StatusCode::OK, "{first}");
    let first: RealmStreamList = serde_json::from_value(first).unwrap();
    let root = first.next_cursor.unwrap();
    let (status, second) = listing(&state, &refreshed, &realm, 1, Some(&root)).await;
    assert_eq!(status, StatusCode::OK, "{second}");
    let second: RealmStreamList = serde_json::from_value(second).unwrap();
    let child = second.next_cursor.unwrap();
    let body = arkret_models_identity::account::AccountCursorRevokeRequestBody {
        cursor: child.clone(),
        reason_code: arkret_wire::ReasonCode::from_wire(arkret_wire::ReasonCode::INVALID_CURSOR),
        revoke_scope: arkret_models_identity::account::CursorRevokeScope::SameSession,
    };
    let mut response = TestClient::post("http://server/_arkret/self/account/cursor/revoke")
        .add_header("authorization", format!("Bearer {refreshed}"), true)
        .add_header(
            "Arkret-Operation",
            arkret_wire::ServiceOperationId::SELF_ACCOUNT_COMMAND_REVOKE_CURSOR_V1,
            true,
        )
        .raw_json(
            String::from_utf8(arkret_canonical::canonical_json_bytes(&body).unwrap()).unwrap(),
        )
        .send(&service(state.clone()))
        .await;
    let status = response.status_code.unwrap();
    let value: Value = response.take_json().await.unwrap();
    assert_eq!(status, StatusCode::OK, "{value}");
    let (_, refusal) = listing(&state, &refreshed, &realm, 1, Some(&child)).await;
    assert_eq!(
        refusal["type"],
        "https://arkret.org/problems/cursor_revoked"
    );
    let mut conn = pool.get().await.unwrap();
    let count = diesel::sql_query("SELECT COUNT(*) AS value FROM sync_cursor_handles")
        .get_result::<Count>(&mut *conn)
        .await
        .unwrap()
        .value;
    let (_, refusal) = listing(&state, &refreshed, &realm, 1, None).await;
    assert_eq!(
        refusal["type"],
        "https://arkret.org/problems/cursor_revoked"
    );
    assert_eq!(
        diesel::sql_query("SELECT COUNT(*) AS value FROM sync_cursor_handles")
            .get_result::<Count>(&mut *conn)
            .await
            .unwrap()
            .value,
        count
    );
    let (status, value) = listing(&state, &original, &realm, 1, Some(&root)).await;
    assert_eq!(status, StatusCode::OK, "{value}");
}

async fn admit(
    state: &coland_http::state::AppState,
    pool: &coland_storage_postgres::PgPool,
    mut request: coland_storage::EventCommitRequest,
) -> coland_storage::EventCommitRequest {
    request.authority_commit.commit.signature = ordinary_realm::signature_for_did(
        &state.service_did(),
        request.authority_commit.commit.committed_at,
    );
    let mut request = ordinary_realm::source_request(pool, request).await;
    seal_commit(state, &mut request.authority_commit.commit);
    state
        .test_persistence()
        .commit_event(request.clone())
        .await
        .unwrap();
    request
}

#[test]
fn snapshot_http_retention_preserves_state_and_rejects_oversized_cut_atomically() {
    run_http_scenario(snapshot_retention_http_scenario);
}

async fn snapshot_retention_http_scenario() {
    use diesel_async::RunQueryDsl;
    let (state, pool) = coland_test_support::app_state_with_pool(AppConfig {
        development_mode: true,
        ..coland_test_support::app_config()
    });
    let account = ordinary_realm::human_profile::admit_for_station_did(
        &pool,
        state.service_did(),
        "snapshot-retention-http",
    )
    .await;
    let unit = ordinary_realm::bootstrap_unit_for_account(
        &uuid::Uuid::now_v7().to_string(),
        &account,
        &state.service_did(),
    );
    let mut unit = ordinary_realm::source_bootstrap(&pool, unit).await;
    for transaction in &mut unit.transactions {
        seal_commit(&state, &mut transaction.commit);
    }
    state
        .test_persistence()
        .authority_commits()
        .admit_ordinary_realm_bootstrap_unit(&unit, unit.transactions[0].commit.committed_at)
        .await
        .unwrap();
    let parent = unit.transactions.last().unwrap();
    let realm = parent.event.realm_id.clone();
    let at = parent.commit.committed_at;
    let actor = ActorId::account(account.clone());
    let token = session(&state, &account, "snapshot-retention-http").await;
    let strand = admit(&state, &pool, ordinary_realm::next_request_for_actor(parent,
        EventKind::StrandCreate, actor.clone(), json!({"object":{"schema":"ak.schema.strand.v1","realm_id":realm,
        "tracks":{"discussion":{"is_primary":true,"profile":"discussion"}},"metadata":{"title":"Retention source"},"state":"active","created_by":actor,"created_at":arkret_canonical::format_timestamp_canonical(at)}}), at)).await;
    let strand_id = arkret_wire::StrandId::from_event_id(&strand.authority_commit.event.event_id);
    let (status, safe) = snapshot(&state, &token, &realm, None).await;
    assert_eq!(status, StatusCode::OK, "{safe}");
    let safe: arkret_wire::RealmStateSnapshot = serde_json::from_value(safe).unwrap();
    let message = admit(&state, &pool, ordinary_realm::next_request_for_actor(
        &strand.authority_commit, EventKind::MessageCreate, actor.clone(),
        json!({"strand_id":strand_id,"track_name":"discussion","content":{"kind":"ak.content.text","body":"expired HTTP content","format":"plain"}}), at)).await;
    let (status, unsafe_old) = snapshot(&state, &token, &realm, None).await;
    assert_eq!(status, StatusCode::OK, "{unsafe_old}");
    let unsafe_old: arkret_wire::RealmStateSnapshot = serde_json::from_value(unsafe_old).unwrap();
    state
        .test_persistence()
        .retention_tombstones()
        .put(&coland_storage::RetentionTombstoneRecord {
            event_id: message.authority_commit.event.event_id.to_string(),
            realm_id: realm.to_string(),
            reason: "retention_policy.ttl".into(),
            policy_ttl_seconds: 60,
            expired_at: chrono::Utc::now(),
            tombstoned_at: chrono::Utc::now(),
            sealed: false,
        })
        .await
        .unwrap();
    let (status, value) = snapshot(&state, &token, &realm, None).await;
    assert_eq!(status, StatusCode::OK, "{value}");
    let current: arkret_wire::RealmStateSnapshot = serde_json::from_value(value).unwrap();
    verify_snapshot(&state, &current);
    assert_eq!(
        current.visible_stream_heads,
        unsafe_old.visible_stream_heads
    );
    assert_eq!(
        current.retention_and_history_floor,
        unsafe_old.retention_and_history_floor
    );
    assert!(!current.current_state_entries.iter().any(|row| matches!(
        row,
        arkret_wire::TypedCurrentRow::Value {
            selector: arkret_wire::CurrentSelector::MessageRevision { .. },
            ..
        }
    )));
    assert_eq!(
        current.current_state_entries.len() + 1,
        unsafe_old.current_state_entries.len()
    );
    for old in [&safe, &current] {
        let (status, value) = snapshot(&state, &token, &realm, Some(&old.snapshot_id)).await;
        assert_eq!(status, StatusCode::OK, "{value}");
        assert_eq!(
            serde_json::from_value::<arkret_wire::RealmStateSnapshot>(value).unwrap(),
            *old
        );
    }
    let (status, refusal) = snapshot(&state, &token, &realm, Some(&unsafe_old.snapshot_id)).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{refusal}");
    assert_eq!(
        refusal["type"],
        "https://arkret.org/problems/realm_state_snapshot_unavailable"
    );

    // Corrupt/legacy data can exceed a budget that normal admission rejects.
    // The read must fail whole before persisting any signed object or issuance.
    #[derive(diesel::QueryableByName)]
    struct Count {
        #[diesel(sql_type = diesel::sql_types::BigInt)]
        value: i64,
    }
    let mut conn = pool.get().await.unwrap();
    let count_sql = "SELECT (SELECT COUNT(*) FROM realm_state_snapshots) + (SELECT COUNT(*) FROM realm_state_snapshot_issuances) AS value";
    let count = diesel::sql_query(count_sql)
        .get_result::<Count>(&mut conn)
        .await
        .unwrap()
        .value;
    diesel::sql_query("UPDATE realm_bootstrap_current_results SET value=jsonb_set(value,'{title}',to_jsonb($2::text)) WHERE realm_id=$1 AND result_family='realm_profile'")
        .bind::<diesel::sql_types::Text, _>(realm.as_str())
        .bind::<diesel::sql_types::Text, _>("x".repeat(8 * 1024 * 1024))
        .execute(&mut conn).await.unwrap();
    drop(conn);
    let (status, refusal) = snapshot(&state, &token, &realm, None).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE, "{refusal}");
    assert_eq!(
        refusal["type"],
        "https://arkret.org/problems/payload_too_large"
    );
    assert!(refusal.get("current_state_entries").is_none());
    let mut conn = pool.get().await.unwrap();
    assert_eq!(
        diesel::sql_query(count_sql)
            .get_result::<Count>(&mut conn)
            .await
            .unwrap()
            .value,
        count
    );
}

#[test]
fn sidecar_http_snapshot_discovery_and_bidirectional_scan_keep_private_coordinates() {
    run_http_scenario(sidecar_http_scenario);
}

async fn sidecar_http_scenario() {
    use arkret_wire::{StreamScanDirection, StreamScanOutcome, StreamScanRequest};
    let (state, pool) = coland_test_support::app_state_with_pool(AppConfig {
        development_mode: true,
        ..coland_test_support::app_config()
    });
    let controller = ordinary_realm::human_profile::admit_for_station_did(
        &pool,
        state.service_did(),
        "sidecar-http-controller",
    )
    .await;
    let member = ordinary_realm::human_profile::admit_for_station_did(
        &pool,
        state.service_did(),
        "sidecar-http-member",
    )
    .await;
    let unit = ordinary_realm::bootstrap_unit_for_account(
        &uuid::Uuid::now_v7().to_string(),
        &controller,
        &state.service_did(),
    );
    let mut unit = ordinary_realm::source_bootstrap(&pool, unit).await;
    for transaction in &mut unit.transactions {
        seal_commit(&state, &mut transaction.commit);
    }
    unit.validate().unwrap();
    state
        .test_persistence()
        .authority_commits()
        .admit_ordinary_realm_bootstrap_unit(&unit, unit.transactions[0].commit.committed_at)
        .await
        .unwrap();
    let parent = unit.transactions.last().unwrap();
    let at = parent.commit.committed_at;
    let realm = parent.event.realm_id.clone();
    let actor = ActorId::account(controller.clone());
    let token = session(&state, &controller, "sidecar-http-controller").await;
    let outsider = session(&state, &member, "sidecar-http-member").await;
    let strand = admit(&state, &pool, ordinary_realm::next_request_for_actor(parent, EventKind::StrandCreate, actor.clone(), json!({"object":{"schema":"ak.schema.strand.v1","realm_id":realm,
        "tracks":{"discussion":{"is_primary":true,"profile":"discussion"}},"metadata":{"title":"Sidecar HTTP source"},"state":"active","created_by":actor,"created_at":arkret_canonical::format_timestamp_canonical(at)}}), at)).await;
    let source = arkret_wire::StrandId::from_event_id(&strand.authority_commit.event.event_id);
    let create = admit(
        &state,
        &pool,
        ordinary_realm::next_request_for_actor(
            &strand.authority_commit,
            EventKind::SidecarCreate,
            actor.clone(),
            json!({}),
            at,
        ),
    )
    .await;
    let sidecar = arkret_wire::SidecarId::from_event_id(&create.authority_commit.event.event_id);
    let stream = CommitStreamRef::Sidecar {
        realm_id: realm.clone(),
        sidecar_id: sidecar.clone(),
    };
    let mut attach_event = ordinary_realm::event_for_actor(
        EventKind::SidecarContextAttach,
        arkret_wire::ScopeRef::Sidecar {
            realm_id: realm.clone(),
            sidecar_id: sidecar.clone(),
        },
        actor.clone(),
        json!({"sidecar_id":sidecar,"source_context_ref":{"kind":"strand","strand_id":source},"version":1}),
        at,
    );
    attach_event.semantic_refs = vec![arkret_wire::SemanticRef::new(
        create.authority_commit.event.event_id.to_string(),
        "after",
    )];
    ordinary_realm::reseal(&mut attach_event);
    let mut attach = ordinary_realm::request_for_event(&create.authority_commit, attach_event, at);
    attach.authority_commit.commit.stream_ref = stream.clone();
    attach.authority_commit.commit.stream_position = 0;
    attach.authority_commit.commit.previous_commit_ref = None;
    let attach = admit(&state, &pool, attach).await;
    admit(
        &state,
        &pool,
        ordinary_realm::next_request_for_actor(
            &create.authority_commit,
            EventKind::MemberState,
            ActorId::account(member.clone()),
            json!({"member_id":ActorId::account(member),"membership":"join"}),
            at,
        ),
    )
    .await;
    for (credential, expected) in [(&token, true), (&outsider, false)] {
        let (status, value) = listing(&state, credential, &realm, 500, None).await;
        assert_eq!(status, StatusCode::OK, "{value}");
        let page: RealmStreamList = serde_json::from_value(value).unwrap();
        page.validate().unwrap();
        assert_eq!(
            page.streams.iter().any(|row| row.stream_ref == stream),
            expected
        );
        let (status, value) = snapshot(&state, credential, &realm, None).await;
        assert_eq!(status, StatusCode::OK, "{value}");
        let signed: arkret_wire::RealmStateSnapshot = serde_json::from_value(value).unwrap();
        verify_snapshot(&state, &signed);
        assert_eq!(
            signed
                .visible_stream_heads
                .iter()
                .any(|head| head.stream_ref == stream),
            expected
        );
        assert_eq!(
            signed
                .retention_and_history_floor
                .stream_floors
                .iter()
                .any(|floor| floor.stream_ref == stream),
            expected
        );
        assert_eq!(signed.current_state_entries.iter().any(|row| matches!(row, arkret_wire::TypedCurrentRow::Value {source_stream_ref, ..} if source_stream_ref == &stream)), expected);
        let (status, value) = snapshot(&state, credential, &realm, Some(&signed.snapshot_id)).await;
        assert_eq!(status, StatusCode::OK, "{value}");
        assert_eq!(
            serde_json::from_value::<arkret_wire::RealmStateSnapshot>(value).unwrap(),
            signed
        );
        if expected {
            let (status, _) = snapshot(&state, &outsider, &realm, Some(&signed.snapshot_id)).await;
            assert_ne!(status, StatusCode::OK);
        }
        for direction in [
            StreamScanDirection::After(None),
            StreamScanDirection::Before(None),
        ] {
            let request = StreamScanRequest {
                realm_id: realm.clone(),
                stream_ref: stream.clone(),
                direction,
                limit: 1,
            };
            let mut response = TestClient::post("http://server/_arkret/self/streams/scan")
                .add_header("authorization", format!("Bearer {credential}"), true)
                .add_header(
                    "Arkret-Operation",
                    arkret_wire::ServiceOperationId::SELF_COMMITTED_EVENT_READ_SCAN_V1,
                    true,
                )
                .raw_json(
                    String::from_utf8(arkret_canonical::canonical_json_bytes(&request).unwrap())
                        .unwrap(),
                )
                .send(&service(state.clone()))
                .await;
            let status = response.status_code.unwrap();
            let value: Value = response.take_json().await.unwrap();
            if expected {
                assert_eq!(status, StatusCode::OK, "{value}");
                let scan: StreamScanOutcome = serde_json::from_value(value).unwrap();
                scan.validate_for_request(&request).unwrap();
                assert_eq!(scan.committed_events.len(), 1);
                assert_eq!(
                    scan.committed_events[0].commit(),
                    &attach.authority_commit.commit
                );
                assert_eq!(scan.readable_floor.as_ref().unwrap().oldest_position, 0);
                assert!(!scan.truncated);
            } else {
                assert_ne!(status, StatusCode::OK);
                assert!(value.get("committed_events").is_none());
                assert!(value.get("readable_floor").is_none());
            }
        }
    }
}
