//! `ak.self.signer_keys.read.resolve.v1` rejection matrix over the real HTTP
//! surface (`POST /_arkret/self/signer-keys/query`).
//!
//! The contract is `signer-key-operations.schema.json#/$defs/query_request_body`
//! plus its `operations-error-mapping.json` entry:
//!
//! * a recipient Account that is not the authenticated session's own Account at this Station
//!   answers one indistinguishable `404 not_found`;
//! * schema and count violations (closed selector union, missing or extra members, duplicates, `0`
//!   or `> 64` selectors, a historical coordinate from another Realm) answer `422
//!   schema_violation`;
//! * canonical request bytes above 64 KiB answer `413 payload_too_large`;
//! * hidden, unknown or unverified targets, including an unknown Realm, keep the same per-selector
//!   `unavailable` shape rather than a Realm-level error.
//!
//! Selectors are serialized from the SDK request model and only then mutated,
//! so every negative case differs from an accepted body by exactly the member
//! under test. The rejection matrix has no frozen producer rows. The final
//! positive case admits a real PCR and genuinely signed ordinary bootstrap;
//! its historical result comes from the production admission transaction.

use arkret_canonical::DigestSuite;
use arkret_models_identity::{
    CurrentSignerKeyQuerySender, HistoricalSignerKeyQuerySender, SignerKeyQuerySelector,
    SignerKeysQueryRequestBody,
};
use arkret_wire::{
    AccountId, ActorId, CommitStreamRef, CommittedEventRef, DeviceId, DidUrl, EventId,
    RealmCommitId, RequestId,
};

use super::common::*;

const PATH: &str = "http://server/_arkret/self/signer-keys/query";
const REQUEST_ID: &str = "ak:request:019b0000-0000-7000-8000-000000000301";
const DEVICE_ID: &str = "ak:device:01904100-0000-7000-8000-a11ce0000001";
const CALLER: &str = "did:web:alice.example";
const REQUEST_CANONICAL_LIMIT: usize = 64 * 1024;

// Construct large scenario Futures outside the test harness poll frame.
fn boxed_scenario<F: std::future::Future>(body: impl FnOnce() -> F) -> std::pin::Pin<Box<F>> {
    Box::pin(body())
}

fn problem_type(code: &str) -> String {
    format!("https://arkret.org/problems/{code}")
}

fn signer_actor(state: &AppState, index: usize) -> ActorId {
    fixture_account_actor(state, &format!("did:web:signer-{index}.example"))
}

fn signer_method(index: usize, fragment: &str) -> DidUrl {
    DidUrl::new(format!("did:web:signer-{index}.example#{fragment}")).unwrap()
}

fn committed_event_ref(realm_id: &RealmId, seed: u8) -> CommittedEventRef {
    CommittedEventRef {
        event_id: EventId::from_digest(DigestSuite::Sha256, [seed; 32]),
        commit_id: RealmCommitId::from_digest([seed.wrapping_add(1); 32]),
        stream_ref: CommitStreamRef::Realm {
            realm_id: realm_id.clone(),
        },
        stream_position: 7,
    }
}

fn current_agent(state: &AppState, index: usize, fragment: &str) -> SignerKeyQuerySelector {
    SignerKeyQuerySelector::CurrentAdmission {
        sender: CurrentSignerKeyQuerySender::Agent {
            actor: signer_actor(state, index),
            verification_method: signer_method(index, fragment),
        },
    }
}

/// One accepted selector per closed branch, in schema order.
fn four_branches(state: &AppState, realm_id: &RealmId) -> [SignerKeyQuerySelector; 4] {
    let device_id = DeviceId::new(DEVICE_ID).unwrap();
    [
        SignerKeyQuerySelector::CurrentAdmission {
            sender: CurrentSignerKeyQuerySender::AccountDevice {
                actor: signer_actor(state, 1),
                device_id: device_id.clone(),
                verification_method: signer_method(1, "device-key"),
            },
        },
        current_agent(state, 2, "agent-key"),
        SignerKeyQuerySelector::HistoricalEvent {
            sender: HistoricalSignerKeyQuerySender::AccountDevice {
                actor: signer_actor(state, 3),
                device_id,
                verification_method: signer_method(3, "device-key"),
                committed_event_ref: committed_event_ref(realm_id, 3),
            },
        },
        SignerKeyQuerySelector::HistoricalEvent {
            sender: HistoricalSignerKeyQuerySender::Agent {
                actor: signer_actor(state, 4),
                verification_method: signer_method(4, "agent-key"),
                committed_event_ref: committed_event_ref(realm_id, 4),
            },
        },
    ]
}

fn request(
    recipient_account_id: AccountId,
    realm_id: &RealmId,
    queries: Vec<SignerKeyQuerySelector>,
) -> Value {
    serde_json::to_value(SignerKeysQueryRequestBody {
        request_id: RequestId::new(REQUEST_ID).unwrap(),
        realm_id: realm_id.clone(),
        recipient_account_id: Some(recipient_account_id),
        recipient_actor_id: None,
        queries,
    })
    .unwrap()
}

fn canonical_len(body: &Value) -> usize {
    arkret_canonical::canonical_json_bytes(body).unwrap().len()
}

async fn send(app: &salvo::Service, token: Option<&str>, body: &Value) -> (StatusCode, Value) {
    let mut builder = TestClient::post(PATH);
    if let Some(token) = token {
        builder = builder.add_header("authorization", format!("Bearer {token}"), true);
    }
    let mut response = builder.json(body).send(app).await;
    let status = response.status_code.expect("response status");
    let body = response.take_json().await.expect("JSON response body");
    (status, body)
}

async fn assert_problem(
    app: &salvo::Service,
    token: &str,
    body: &Value,
    status: StatusCode,
    code: &str,
    case: &str,
) -> Value {
    let (actual, problem) = send(app, Some(token), body).await;
    assert_eq!(actual, status, "{case}: {problem}");
    assert_eq!(problem["type"], problem_type(code), "{case}: {problem}");
    assert_eq!(problem["status"], status.as_u16(), "{case}: {problem}");
    problem
}

/// Every selector answers once, in the exact closed `unavailable_signer_key_resolution`
/// shape: the complete request selector plus `status`, nothing else.
async fn assert_all_unavailable(app: &salvo::Service, token: &str, body: &Value, case: &str) {
    let (status, outcome) = send(app, Some(token), body).await;
    assert_eq!(status, StatusCode::OK, "{case}: {outcome}");
    let keys: Vec<&str> = outcome
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        keys.len(),
        4,
        "{case}: closed outcome members only: {outcome}"
    );
    for member in ["request_id", "realm_id", "recipient_account_id"] {
        assert_eq!(outcome[member], body[member], "{case}: echoed {member}");
    }
    let queries = body["queries"].as_array().unwrap();
    let results = outcome["resolutions"].as_array().unwrap();
    assert_eq!(
        results.len(),
        queries.len(),
        "{case}: one result per selector"
    );
    for (query, result) in queries.iter().zip(results) {
        assert_eq!(
            result,
            &serde_json::json!({ "selector": query, "status": "unavailable" }),
            "{case}: unavailable result must carry only the exact selector"
        );
    }
}

#[tokio::test]
async fn signer_keys_query_rejects_foreign_recipients_with_one_not_found_shape() {
    boxed_scenario(recipient_body).await;
}

async fn recipient_body() {
    let state = coland_test_support::app_state(test_config());
    let token = dev_token(state.clone()).await;
    let app = app_from_state(state.clone());
    let realm_id = RealmId::new(demo_realm_id().to_owned()).unwrap();
    let queries = four_branches(&state, &realm_id).to_vec();
    let own = fixture_account_id(&state, CALLER);

    let accepted = request(own.clone(), &realm_id, queries.clone());
    let (status, _) = send(&app, None, &accepted).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "session is required");
    assert_all_unavailable(&app, &token, &accepted, "own recipient Account").await;

    let other_station = DidCoreId::new("ak:did_core:web:other-station.example".to_owned()).unwrap();
    let same_principal_other_station = AccountId::new(own.principal_id.clone(), other_station);
    let other_principal_same_station = fixture_account_id(&state, "did:web:bob.example");
    let other_principal_other_station = AccountId::new(
        fixture_actor_core_id("did:web:bob.example"),
        DidCoreId::new("ak:did_core:web:other-station.example".to_owned()).unwrap(),
    );
    let mut problems = Vec::new();
    for (case, recipient) in [
        (
            "same Principal at another Station",
            same_principal_other_station,
        ),
        (
            "another Principal at this Station",
            other_principal_same_station,
        ),
        (
            "another Principal at another Station",
            other_principal_other_station,
        ),
    ] {
        let body = request(recipient, &realm_id, queries.clone());
        let mut problem = assert_problem(
            &app,
            &token,
            &body,
            StatusCode::NOT_FOUND,
            "not_found",
            case,
        )
        .await;
        // `instance` names this HTTP exchange, not the recipient.
        assert!(
            problem
                .as_object_mut()
                .unwrap()
                .remove("instance")
                .is_some()
        );
        problems.push(problem);
    }
    assert!(
        problems.windows(2).all(|pair| pair[0] == pair[1]),
        "foreign recipients must not be distinguishable: {problems:?}"
    );
}

#[tokio::test]
async fn signer_keys_query_scopes_selectors_to_the_request_realm() {
    boxed_scenario(realm_body).await;
}

async fn realm_body() {
    let state = coland_test_support::app_state(test_config());
    let token = dev_token(state.clone()).await;
    let app = app_from_state(state.clone());
    let own = fixture_account_id(&state, CALLER);
    let demo_realm = RealmId::new(demo_realm_id().to_owned()).unwrap();
    let unknown_realm =
        RealmId::from_event_id(&EventId::from_digest(DigestSuite::Sha256, [0x5a; 32]));

    // An existing Realm and a Realm this Station has never seen answer the
    // same per-selector shape; the Realm itself is never a distinct error.
    for (case, realm_id) in [
        ("existing ordinary Realm", &demo_realm),
        ("unknown Realm", &unknown_realm),
    ] {
        let body = request(
            own.clone(),
            realm_id,
            four_branches(&state, realm_id).to_vec(),
        );
        assert_all_unavailable(&app, &token, &body, case).await;
    }

    // A historical coordinate MUST name the request Realm. Both historical
    // branches are checked with every other member left valid.
    for (index, case) in [
        (2, "historical account-device coordinate from another Realm"),
        (3, "historical Agent coordinate from another Realm"),
    ] {
        let mut body = request(
            own.clone(),
            &demo_realm,
            four_branches(&state, &demo_realm).to_vec(),
        );
        body["queries"][index]["committed_event_ref"]["stream_ref"]["realm_id"] =
            serde_json::to_value(&unknown_realm).unwrap();
        assert_problem(
            &app,
            &token,
            &body,
            StatusCode::UNPROCESSABLE_ENTITY,
            "schema_violation",
            case,
        )
        .await;
    }
}

#[tokio::test]
async fn signer_keys_query_enforces_the_closed_selector_union() {
    boxed_scenario(selector_union_body).await;
}

async fn selector_union_body() {
    let state = coland_test_support::app_state(test_config());
    let token = dev_token(state.clone()).await;
    let app = app_from_state(state.clone());
    let own = fixture_account_id(&state, CALLER);
    let realm_id = RealmId::new(demo_realm_id().to_owned()).unwrap();
    let branches = four_branches(&state, &realm_id);
    let base = |index: usize| request(own.clone(), &realm_id, vec![branches[index].clone()]);

    for (index, branch) in [
        "current account_device",
        "current agent",
        "historical account_device",
        "historical agent",
    ]
    .into_iter()
    .enumerate()
    {
        let accepted = base(index);
        assert_all_unavailable(&app, &token, &accepted, branch).await;

        // Every required member of this closed branch is load-bearing.
        let required: Vec<String> = accepted["queries"][0]
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect();
        for member in &required {
            let mut body = accepted.clone();
            body["queries"][0].as_object_mut().unwrap().remove(member);
            assert_problem(
                &app,
                &token,
                &body,
                StatusCode::UNPROCESSABLE_ENTITY,
                "schema_violation",
                &format!("{branch} without {member}"),
            )
            .await;
        }

        // A member of another branch, the retired bare historical `event_id`,
        // or a caller-selected receiver never widens a closed branch.
        let mut extras = vec![
            (
                "receiver_station_id",
                serde_json::json!(state.service_core_id()),
            ),
            (
                "event_id",
                serde_json::to_value(EventId::from_digest(DigestSuite::Sha256, [9; 32])).unwrap(),
            ),
        ];
        if !required.iter().any(|member| member == "device_id") {
            extras.push(("device_id", serde_json::json!(DEVICE_ID)));
        }
        if !required
            .iter()
            .any(|member| member == "committed_event_ref")
        {
            extras.push((
                "committed_event_ref",
                serde_json::to_value(committed_event_ref(&realm_id, 9)).unwrap(),
            ));
        }
        for (member, value) in extras {
            let mut body = accepted.clone();
            body["queries"][0][member] = value;
            assert_problem(
                &app,
                &token,
                &body,
                StatusCode::UNPROCESSABLE_ENTITY,
                "schema_violation",
                &format!("{branch} with extra {member}"),
            )
            .await;
        }

        // The signer must be a complete account ActorId.
        let mut body = accepted.clone();
        body["queries"][0]["actor"] = serde_json::to_value(ActorId::service(
            DidCoreId::new("ak:did_core:web:signer.example".to_owned()).unwrap(),
        ))
        .unwrap();
        assert_problem(
            &app,
            &token,
            &body,
            StatusCode::UNPROCESSABLE_ENTITY,
            "schema_violation",
            &format!("{branch} with a service actor"),
        )
        .await;
    }

    // Swapping one tag cannot move a selector into a sibling branch.
    for (index, tag, value, case) in [
        (
            0,
            "verification_mode",
            "historical_event",
            "current device relabelled historical",
        ),
        (
            2,
            "verification_mode",
            "current_admission",
            "historical device relabelled current",
        ),
        (0, "sender_kind", "agent", "current device relabelled Agent"),
        (
            1,
            "sender_kind",
            "account_device",
            "current Agent relabelled device",
        ),
        (
            3,
            "sender_kind",
            "account_device",
            "historical Agent relabelled device",
        ),
        (
            1,
            "verification_mode",
            "current",
            "unknown verification_mode",
        ),
        (1, "sender_kind", "service", "unknown sender_kind"),
    ] {
        let mut body = base(index);
        body["queries"][0][tag] = serde_json::json!(value);
        assert_problem(
            &app,
            &token,
            &body,
            StatusCode::UNPROCESSABLE_ENTITY,
            "schema_violation",
            case,
        )
        .await;
    }

    // The historical coordinate is itself closed and complete.
    for member in ["event_id", "commit_id", "stream_ref", "stream_position"] {
        let mut body = base(3);
        body["queries"][0]["committed_event_ref"]
            .as_object_mut()
            .unwrap()
            .remove(member);
        assert_problem(
            &app,
            &token,
            &body,
            StatusCode::UNPROCESSABLE_ENTITY,
            "schema_violation",
            &format!("historical coordinate without {member}"),
        )
        .await;
    }
    let mut body = base(3);
    body["queries"][0]["committed_event_ref"]["accepted_at"] = serde_json::json!(
        canonical_timestamp(chrono::DateTime::<chrono::Utc>::from_timestamp_millis(0).unwrap())
    );
    assert_problem(
        &app,
        &token,
        &body,
        StatusCode::UNPROCESSABLE_ENTITY,
        "schema_violation",
        "historical coordinate with an extra member",
    )
    .await;
}

#[tokio::test]
async fn signer_keys_query_enforces_selector_count_uniqueness_and_byte_budget() {
    boxed_scenario(budget_body).await;
}

async fn budget_body() {
    let state = coland_test_support::app_state(test_config());
    let token = dev_token(state.clone()).await;
    let app = app_from_state(state.clone());
    let own = fixture_account_id(&state, CALLER);
    let realm_id = RealmId::new(demo_realm_id().to_owned()).unwrap();
    let branches = four_branches(&state, &realm_id);

    // Request envelope members are closed and all required.
    let accepted = request(own.clone(), &realm_id, branches.to_vec());
    for member in ["request_id", "realm_id", "recipient_account_id", "queries"] {
        let mut body = accepted.clone();
        body.as_object_mut().unwrap().remove(member);
        assert_problem(
            &app,
            &token,
            &body,
            StatusCode::UNPROCESSABLE_ENTITY,
            "schema_violation",
            &format!("request without {member}"),
        )
        .await;
    }
    let mut body = accepted.clone();
    body["receiver_station_id"] = serde_json::json!(state.service_core_id());
    assert_problem(
        &app,
        &token,
        &body,
        StatusCode::UNPROCESSABLE_ENTITY,
        "schema_violation",
        "request with a caller-selected receiver",
    )
    .await;

    let empty = request(own.clone(), &realm_id, Vec::new());
    assert_problem(
        &app,
        &token,
        &empty,
        StatusCode::UNPROCESSABLE_ENTITY,
        "schema_violation",
        "no selectors",
    )
    .await;

    // Uniqueness is per complete selector, for every branch.
    for (index, branch) in branches.iter().enumerate() {
        let mut queries = branches.to_vec();
        queries.push(branch.clone());
        let body = request(own.clone(), &realm_id, queries);
        assert_problem(
            &app,
            &token,
            &body,
            StatusCode::UNPROCESSABLE_ENTITY,
            "schema_violation",
            &format!("duplicate selector for branch {index}"),
        )
        .await;
    }

    let selectors = |count: usize| -> Vec<SignerKeyQuerySelector> {
        (0..count)
            .map(|index| current_agent(&state, index, "agent-key"))
            .collect()
    };
    let at_limit = request(own.clone(), &realm_id, selectors(64));
    assert!(canonical_len(&at_limit) < REQUEST_CANONICAL_LIMIT);
    assert_all_unavailable(&app, &token, &at_limit, "64 selectors").await;
    let over_limit = request(own.clone(), &realm_id, selectors(65));
    assert!(
        canonical_len(&over_limit) < REQUEST_CANONICAL_LIMIT,
        "count violation must be exercised independently of the byte budget"
    );
    assert_problem(
        &app,
        &token,
        &over_limit,
        StatusCode::UNPROCESSABLE_ENTITY,
        "schema_violation",
        "65 selectors",
    )
    .await;

    // The 64 KiB canonical request budget is independent of the selector
    // count: 64 selectors padded to exactly the limit are accepted, and one
    // more canonical byte is `payload_too_large`.
    let padded = |extra: usize| -> Value {
        let base = canonical_len(&request(own.clone(), &realm_id, selectors(64)));
        let total = REQUEST_CANONICAL_LIMIT + extra - base;
        let queries = (0..64)
            .map(|index| {
                let padding = total / 64 + usize::from(index < total % 64);
                current_agent(&state, index, &format!("agent-key{}", "x".repeat(padding)))
            })
            .collect();
        request(own.clone(), &realm_id, queries)
    };
    let exact = padded(0);
    assert_eq!(canonical_len(&exact), REQUEST_CANONICAL_LIMIT);
    assert_all_unavailable(&app, &token, &exact, "exactly 64 KiB").await;
    let oversized = padded(1);
    assert_eq!(canonical_len(&oversized), REQUEST_CANONICAL_LIMIT + 1);
    assert_problem(
        &app,
        &token,
        &oversized,
        StatusCode::PAYLOAD_TOO_LARGE,
        "payload_too_large",
        "64 KiB plus one canonical byte",
    )
    .await;
}

#[path = "../../../storage-postgres/tests/support/historical_human.rs"]
mod historical_human;

#[tokio::test]
async fn signer_keys_query_resolves_frozen_human_and_rejects_unproven_foreign_coordinates() {
    boxed_scenario(human_frozen_body).await;
}

async fn human_frozen_body() {
    use coland_storage::AuthorityCommitStore as _;
    let (state, pool) = coland_test_support::app_state_with_pool(test_config());
    let fixture = historical_human::HumanFixture::new(&pool, state.service_did()).await;
    fixture.admit(&pool).await;
    let token = dev_token_for_device(
        state.clone(),
        fixture.pcr.history.did.as_str(),
        fixture.pcr.history.founding_device_id.as_str(),
        "Historical producer",
    )
    .await;
    let app = app_from_state(state);
    let target = fixture.unit.transactions.last().unwrap();
    let selector = fixture.selector(target);
    let durable = coland_storage_postgres::PgAuthorityCommitStore { pool: pool.clone() }
        .historical_producer_signer_key(&target.event.realm_id, &selector)
        .await
        .unwrap()
        .unwrap();
    let mut foreign = selector.clone();
    if let SignerKeyQuerySelector::HistoricalEvent {
        sender: HistoricalSignerKeyQuerySender::AccountDevice { actor, .. },
    } = &mut foreign
    {
        let mut account = actor.as_account_id().unwrap().clone();
        account.station_id = DidCoreId::new("ak:did_core:web:foreign-history.example").unwrap();
        *actor = ActorId::account(account);
    }
    let queries = vec![selector.clone(), foreign.clone()];
    let body = request(
        fixture.pcr.history.account.clone(),
        &target.event.realm_id,
        queries,
    );
    let (status, response) = send(&app, Some(&token), &body).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "real accepted Human query must use ordinary HTTP resolution"
    );
    assert_eq!(
        response["resolutions"][0],
        serde_json::to_value(durable).unwrap()
    );
    assert_eq!(
        response["resolutions"][1],
        serde_json::json!({"status":"unavailable","selector":foreign})
    );
}
