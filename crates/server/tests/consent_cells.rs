use arkret_identifiers::Did;
use arkret_models_collaboration::governance::invite_addressing::InviteReceivePolicy;
use arkret_wire::{AccountId, DidCoreId, InviteReceiveAction, UnknownInviteAction};
use coland_http::config::AppConfig;
use coland_http::service;
use coland_test_support::AppStateTestExt as _;
use salvo::http::StatusCode;
use salvo::test::{ResponseExt, TestClient};
use serde_json::Value;

const ACCOUNT_REGISTER_BEARER: &str = "coland-test-account-register-bearer";

fn fixture_account_actor(
    state: &coland_http::state::AppState,
    principal_did: &str,
) -> arkret_wire::ActorId {
    let principal_id = arkret_wire::project_did_to_core_id(
        &Did::new(principal_did.to_owned()).expect("fixture account DID"),
    )
    .expect("fixture account core id");
    arkret_wire::ActorId::account(AccountId::new(principal_id, state.service_core_id()))
}

fn test_config() -> AppConfig {
    AppConfig {
        development_mode: true,
        embedded_webvh_registration_bearer: Some(ACCOUNT_REGISTER_BEARER.to_owned()),
        did_resolver_allow_methods: vec!["web".to_owned(), "key".to_owned(), "peer".to_owned()],
        ..coland_test_support::app_config()
    }
}

async fn ensure_account(app: &salvo::Service, actor: &str) {
    let did = Did::new(actor.to_owned()).expect("fixture account DID");
    let principal_id = arkret_wire::project_did_to_core_id(&did).expect("fixture account core id");
    let mut response = TestClient::post("http://server/_coland/gate/account/project")
        .add_header(
            "authorization",
            format!("Bearer {ACCOUNT_REGISTER_BEARER}"),
            true,
        )
        .json(&serde_json::json!({
            "principal_id": principal_id,
            "did": did,
            "display_name": actor,
        }))
        .send(app)
        .await;
    let status = response.status_code.expect("register status");
    let body: Value = response.take_json().await.unwrap();
    assert!(
        matches!(status, StatusCode::OK | StatusCode::CONFLICT),
        "account register failed: {body}"
    );
}

async fn dev_token(
    state: &coland_http::state::AppState,
    app: &salvo::Service,
    fixture: &coland_test_support::pcr_genesis::PcrGenesisFixture,
) -> String {
    let actor = fixture.history.did.as_str();
    fixture.admit(state).await.expect("accepted PCR genesis");
    ensure_account(app, actor).await;
    let actor_core = arkret_wire::project_did_to_core_id(
        &Did::new(actor.to_owned()).expect("fixture actor DID"),
    )
    .expect("fixture actor core id");
    let device_id = fixture.history.founding_device_id.to_string();
    let login: Value = TestClient::post("http://server/_coland/gate/auth/dev-login")
        .json(&serde_json::json!({
            "actor": actor_core,
            "device_id": device_id,
            "display_name": actor,
        }))
        .send(app)
        .await
        .take_json()
        .await
        .unwrap();

    login["session_credential"].as_str().unwrap().to_owned()
}

#[tokio::test]
async fn opaque_consent_request_does_not_create_a_pending_cell() {
    let state = coland_test_support::app_state(test_config());
    let app = service(state.clone());
    let alice_fixture =
        coland_test_support::pcr_genesis::PcrGenesisFixture::new(state.service_did());
    let bob_fixture = coland_test_support::pcr_genesis::PcrGenesisFixture::new(state.service_did());
    let alice_did = alice_fixture.history.did.as_str();
    let bob_did = bob_fixture.history.did.as_str();
    let alice_token = dev_token(&state, &app, &alice_fixture).await;
    let bob_token = dev_token(&state, &app, &bob_fixture).await;

    let mut requested = TestClient::post("http://server/_arkret/self/consent/request")
        .add_header("Authorization", format!("Bearer {alice_token}"), true)
        .add_header(
            "Arkret-Operation",
            arkret_wire::ServiceOperationId::SELF_CONSENT_COMMAND_REQUEST_V1,
            true,
        )
        .json(&serde_json::json!({
            "holder_account_id": fixture_account_actor(&state, bob_did)
                .as_account_id()
                .expect("fixture account actor"),
            "consent_scope": "voice_call",
        }))
        .send(&app)
        .await;
    assert_eq!(requested.status_code.unwrap(), StatusCode::OK);
    assert_eq!(
        requested.take_json::<Value>().await.unwrap(),
        serde_json::json!({
            "accepted_for_processing": true,
        })
    );

    let peer = serde_json::json!({
        "kind": "actor",
        "actor_id": fixture_account_actor(&state, alice_did),
    });
    let mut cell_url = url::Url::parse("http://server/_arkret/self/consent/result").unwrap();
    cell_url
        .query_pairs_mut()
        .append_pair("peer", &serde_json::to_string(&peer).unwrap());
    let response = TestClient::get(cell_url.as_str())
        .add_header("Authorization", format!("Bearer {bob_token}"), true)
        .add_header(
            "Arkret-Operation",
            arkret_wire::ServiceOperationId::SELF_CONSENT_RESOURCE_GET_V1,
            true,
        )
        .send(&app)
        .await;
    assert_eq!(response.status_code.unwrap(), StatusCode::NOT_FOUND);
}

fn signed_consent_event(
    fixture: &coland_test_support::pcr_genesis::PcrGenesisFixture,
    kind: arkret_wire::EventKind,
    payload: Value,
) -> arkret_wire::Event {
    let mut event = arkret_wire::test_support::raw_event_at(
        kind.as_str(),
        arkret_wire::ScopeRef::Realm {
            realm_id: fixture.unit.transactions[1].event.realm_id.clone(),
        },
        fixture.history.account.principal_id.clone(),
        fixture.history.account.station_id.clone(),
        payload,
        chrono::Utc::now(),
    )
    .unwrap();
    event.authorization_ref = Some(fixture.unit.transactions[0].event.event_id.clone().into());
    coland_test_support::device_authorization_history::sign_event(
        event,
        fixture.history.device_verification_method.clone(),
        fixture.history.founding_device_signing_seed,
    )
}

async fn consent_command(
    app: &salvo::Service,
    token: &str,
    event: arkret_wire::Event,
) -> (StatusCode, Value) {
    use arkret_models_collaboration::consent_operations::ConsentReplaceRequestBody;
    let path = "replace";
    let operation = "ak.self.consent.command.replace.v1";
    let body = arkret_canonical::canonical_json_bytes(&ConsentReplaceRequestBody {
        consent_event: arkret_wire::EventAdmissionSubmission::new(event),
    })
    .unwrap();
    let mut response =
        TestClient::post(format!("http://server/_arkret/self/consent/results/{path}"))
            .add_header("Authorization", format!("Bearer {token}"), true)
            .add_header("Arkret-Operation", operation, true)
            .add_header("Content-Type", "application/json", true)
            .body(body)
            .send(app)
            .await;
    let status = response.status_code.unwrap();
    (status, response.take_json().await.unwrap())
}

/// Seed accepted state through the production PCR transaction, never raw SQL.
/// Positive HTTP writes with Standard SessionGrant run in Cotest.
async fn admit_consent_fixture(
    state: &coland_http::state::AppState,
    event: arkret_wire::Event,
) -> Value {
    let store = state.test_persistence();
    let application = coland_services::authority_commit::AuthorityCommitApplication::new(
        coland_services::persistence::PersistenceHandle::from_shared(store.clone()),
        0,
    );
    let transaction = application
        .prepare_self_event_transaction(
            &event,
            &state.service_core_id(),
            arkret_wire::DidUrl::new(format!("{}#federation-fanout-key", state.service_did()))
                .unwrap(),
            state.notary_signing_key().as_ref(),
            chrono::Utc::now(),
        )
        .await
        .unwrap();
    let outcome = store
        .consent_current()
        .admit(coland_storage::ConsentAdmissionWrite { transaction })
        .await
        .unwrap();
    let record = match outcome {
        coland_storage::ConsentAdmissionOutcome::Committed(record)
        | coland_storage::ConsentAdmissionOutcome::Duplicate(record) => record,
    };
    serde_json::to_value(record.view()).unwrap()
}

async fn consent_wire_footprint(pool: &coland_storage_postgres::PgPool) -> Value {
    use diesel_async::RunQueryDsl;
    #[derive(diesel::QueryableByName)]
    struct Row {
        #[diesel(sql_type = diesel::sql_types::Jsonb)]
        value: Value,
    }
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query("SELECT jsonb_build_array((SELECT count(*) FROM canonical_events),(SELECT count(*) FROM realm_commits),(SELECT jsonb_agg(to_jsonb(r) ORDER BY peer_id) FROM consent_current_results r),(SELECT count(*) FROM consent_result_versions),(SELECT count(*) FROM account_data_changes),(SELECT count(*) FROM mimi_consent_correlations),(SELECT count(*) FROM mimi_consent_decision_attempts),(SELECT count(*) FROM federation_outbox),(SELECT count(*) FROM event_federation_outbox)) AS value")
        .get_result::<Row>(&mut conn).await.unwrap().value
}

fn signed_mimi_consent_wire_request(
    state: &coland_http::state::AppState,
    body: &Value,
) -> salvo::test::RequestBuilder {
    use arkret_signatures::http_signature::{
        HttpSignatureScenario, SignedRequestParts, sign_http_message_for_scenario,
    };
    use base64::Engine as _;
    use sha2::Digest as _;
    let path = "/_arkret/open/mimi/consent/request";
    let bytes = arkret_canonical::canonical_json_bytes(body).unwrap();
    let digest = format!(
        "sha-256=:{}:",
        base64::engine::general_purpose::STANDARD.encode(sha2::Sha256::digest(&bytes))
    );
    let headers = vec![
        (
            "arkret-operation".to_owned(),
            arkret_wire::ServiceOperationId::OPEN_MIMI_COMMAND_REQUEST_CONSENT_V1.to_owned(),
        ),
        ("content-digest".to_owned(), digest.clone()),
        (
            "source-service-id".to_owned(),
            state.service_id().to_string(),
        ),
        (
            "destination-service-id".to_owned(),
            state.service_id().to_string(),
        ),
        (
            "provider-id".to_owned(),
            "mimi://wire-scope.provider.invalid".to_owned(),
        ),
    ];
    let signature = sign_http_message_for_scenario(
        &SignedRequestParts {
            method: "POST".to_owned(),
            target_uri: format!("http://server{path}"),
            authority: "server".to_owned(),
            path: path.to_owned(),
            headers: headers.clone(),
            body_digest: Some(digest),
        },
        HttpSignatureScenario::MimiProviderV1,
        &[],
        "sig1",
        state
            .service_verification_method("notary-key")
            .unwrap()
            .as_str(),
        chrono::Utc::now().timestamp(),
        &state.notary_signing_key(),
    )
    .unwrap();
    let mut request = TestClient::post(format!("http://server{path}")).add_header(
        "Content-Type",
        "application/json",
        true,
    );
    for (name, value) in headers {
        request = request.add_header(
            name.parse::<salvo::http::header::HeaderName>().unwrap(),
            value,
            true,
        );
    }
    request
        .add_header("Signature-Input", signature.signature_input_header, true)
        .add_header("Signature", signature.signature_header, true)
        .body(bytes)
}

#[tokio::test]
async fn explicit_four_scope_current_rejects_any_and_future_native_and_mimi_wire_requests() {
    let (state, pool) = coland_test_support::app_state_with_pool(test_config());
    let app = service(state.clone());
    let holder = coland_test_support::pcr_genesis::PcrGenesisFixture::new(state.service_did());
    let token = dev_token(&state, &app, &holder).await;
    let peer_actor = fixture_account_actor(&state, "did:web:wire-scope-peer.invalid");
    let peer = serde_json::json!({"kind":"actor","actor_id":peer_actor});
    let full = signed_consent_event(
        &holder,
        arkret_wire::EventKind::ConsentReplace,
        serde_json::json!({"peer":peer,"expected_current":{"state":"never_written"},"permissions":[
            {"consent_scope":"invite"},{"consent_scope":"voice_call"},{"consent_scope":"video_call"},{"consent_scope":"presence"}]}),
    );
    let accepted = admit_consent_fixture(&state, full).await;
    assert_eq!(accepted["permission_scopes"].as_array().unwrap().len(), 4);
    let before = consent_wire_footprint(&pool).await;
    for rejected_scope in ["any", "future_scope"] {
        let invalid = signed_consent_event(
            &holder,
            arkret_wire::EventKind::ConsentReplace,
            serde_json::json!({"peer":peer,"expected_current":{"state":"present","revision":accepted["revision"]},
                "permissions":[{"consent_scope":rejected_scope}]}),
        );
        let (status, body) = consent_command(&app, &token, invalid).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert!(
            body.to_string().contains(rejected_scope),
            "replacement must fail its scope decoder: {body}"
        );
        let mut native = TestClient::post("http://server/_arkret/self/consent/request")
            .add_header("Authorization",format!("Bearer {token}"),true)
            .add_header("Arkret-Operation",arkret_wire::ServiceOperationId::SELF_CONSENT_COMMAND_REQUEST_V1,true)
            .json(&serde_json::json!({"holder_account_id":holder.history.account,"consent_scope":rejected_scope}))
            .send(&app).await;
        assert_eq!(
            native.status_code.unwrap(),
            StatusCode::UNPROCESSABLE_ENTITY
        );
        let native_body = native.take_string().await.unwrap();
        assert!(
            native_body.contains(rejected_scope),
            "native request must fail its scope decoder: {native_body}"
        );
        let mut mimi = signed_mimi_consent_wire_request(&state,
            &serde_json::json!({"requester_actor_id":arkret_wire::ActorId::account(holder.history.account.clone()),
                "holder_account_id":holder.history.account,"purpose":rejected_scope,"proofs":[]}))
            .send(&app).await;
        let mimi_status = mimi.status_code.unwrap();
        let mimi_body = mimi.take_string().await.unwrap();
        assert_eq!(mimi_status, StatusCode::UNPROCESSABLE_ENTITY, "{mimi_body}");
        assert!(
            mimi_body.contains(rejected_scope),
            "MIMI request must fail its purpose decoder: {mimi_body}"
        );
        assert_eq!(consent_wire_footprint(&pool).await, before);
    }
}

#[tokio::test]
async fn consent_holder_reads_one_peer_current_preserves_empty_and_rejects_local_bearer_writes() {
    let state = coland_test_support::app_state(test_config());
    let app = service(state.clone());
    let holder = coland_test_support::pcr_genesis::PcrGenesisFixture::new(state.service_did());
    let other = coland_test_support::pcr_genesis::PcrGenesisFixture::new(state.service_did());
    let token = dev_token(&state, &app, &holder).await;
    let other_token = dev_token(&state, &app, &other).await;
    let peer = serde_json::json!({"kind":"actor","actor_id":arkret_wire::ActorId::account(other.history.account.clone())});
    let initial = signed_consent_event(
        &holder,
        arkret_wire::EventKind::ConsentReplace,
        serde_json::json!({"peer":peer,"expected_current":{"state":"never_written"},"permissions":[{"consent_scope":"invite"}]}),
    );
    let (status, body) = consent_command(&app, &token, initial.clone()).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert!(body["detail"].as_str().unwrap().contains("standard grant"));
    let first = admit_consent_fixture(&state, initial.clone()).await;
    assert_eq!(first["permission_scopes"], serde_json::json!(["invite"]));
    assert_eq!(admit_consent_fixture(&state, initial.clone()).await, first);
    let (status, _) = consent_command(&app, &other_token, initial.clone()).await;
    assert_ne!(status, StatusCode::OK);
    let mut query = url::Url::parse("http://server/_arkret/self/consent/result").unwrap();
    query
        .query_pairs_mut()
        .append_pair("peer", &serde_json::to_string(&peer).unwrap());
    let mut get = TestClient::get(query.as_str())
        .add_header("Authorization", format!("Bearer {token}"), true)
        .add_header(
            "Arkret-Operation",
            arkret_wire::ServiceOperationId::SELF_CONSENT_RESOURCE_GET_V1,
            true,
        )
        .send(&app)
        .await;
    assert_eq!(get.status_code.unwrap(), StatusCode::OK);
    assert_eq!(get.take_json::<Value>().await.unwrap(), first);
    let replacement = signed_consent_event(
        &holder,
        arkret_wire::EventKind::ConsentReplace,
        serde_json::json!({"peer":peer,"expected_current":{"state":"present","revision":first["revision"]},"permissions":[{"consent_scope":"voice_call"}]}),
    );
    let next = admit_consent_fixture(&state, replacement).await;
    assert_eq!(next["permission_scopes"], serde_json::json!(["voice_call"]));
    let empty = signed_consent_event(
        &holder,
        arkret_wire::EventKind::ConsentReplace,
        serde_json::json!({"peer":peer,"expected_current":{"state":"present","revision":next["revision"]},"permissions":[]}),
    );
    let (status, body) = consent_command(&app, &token, empty.clone()).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert!(body["detail"].as_str().unwrap().contains("standard grant"));
    let closed = admit_consent_fixture(&state, empty).await;
    assert_eq!(closed["permission_scopes"], serde_json::json!([]));
    assert_eq!(admit_consent_fixture(&state, initial).await, first);
    let mut listed = TestClient::get("http://server/_arkret/self/consent/results")
        .add_header("Authorization", format!("Bearer {token}"), true)
        .add_header(
            "Arkret-Operation",
            arkret_wire::ServiceOperationId::SELF_CONSENT_READ_LIST_V1,
            true,
        )
        .send(&app)
        .await;
    let list: arkret_models_collaboration::consent_operations::ConsentList =
        listed.take_json().await.unwrap();
    assert_eq!(list.consents.len(), 1);
    assert!(list.consents[0].permission_scopes.is_empty());
    let mut private = TestClient::get("http://server/_arkret/self/consent/results")
        .add_header("Authorization", format!("Bearer {other_token}"), true)
        .add_header(
            "Arkret-Operation",
            arkret_wire::ServiceOperationId::SELF_CONSENT_READ_LIST_V1,
            true,
        )
        .send(&app)
        .await;
    assert!(
        private
            .take_json::<arkret_models_collaboration::consent_operations::ConsentList>()
            .await
            .unwrap()
            .consents
            .is_empty()
    );
}

#[tokio::test]
async fn invite_receive_policy_get_set_round_trips() {
    let state = coland_test_support::app_state(test_config());
    let app = service(state.clone());
    let alice_fixture =
        coland_test_support::pcr_genesis::PcrGenesisFixture::new(state.service_did());
    let alice = alice_fixture.history.account.clone();
    let mallory = DidCoreId::new("ak:did_core:web:irp-mallory.example").unwrap();
    let alice_token = dev_token(&state, &app, &alice_fixture).await;

    let default_policy: InviteReceivePolicy =
        TestClient::get("http://server/_arkret/self/invite-receive-policy")
            .add_header("Authorization", format!("Bearer {alice_token}"), true)
            .add_header(
                "Arkret-Operation",
                arkret_wire::ServiceOperationId::SELF_INVITE_RECEIVE_POLICY_RESOURCE_GET_V1,
                true,
            )
            .send(&app)
            .await
            .take_json()
            .await
            .unwrap();
    assert_eq!(default_policy.account_id, alice);
    assert!(
        default_policy
            .holder_allowed_introduction_kinds
            .iter()
            .any(|kind| kind == "consent_grant")
    );

    let mut custom = default_policy.clone();
    custom.holder_allowed_introduction_kinds = vec!["consent_grant".to_owned()];
    custom.explicit_address_behavior = InviteReceiveAction::Drop;
    custom.unknown_invites = UnknownInviteAction::Drop;
    custom.denied_actor_ids = vec![arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        mallory.clone(),
        arkret_wire::DidCoreId::new("ak:did_core:web:remote.example").unwrap(),
    ))];
    let mut stored_response = TestClient::put("http://server/_arkret/self/invite-receive-policy")
        .add_header("Authorization", format!("Bearer {alice_token}"), true)
        .add_header(
            "Arkret-Operation",
            arkret_wire::ServiceOperationId::SELF_INVITE_RECEIVE_POLICY_RESOURCE_REPLACE_V1,
            true,
        )
        .add_header("content-type", "application/json", true)
        .body(arkret_canonical::canonical_json_bytes(&custom).unwrap())
        .send(&app)
        .await;
    let stored_status = stored_response.status_code.unwrap();
    let stored_value: Value = stored_response.take_json().await.unwrap();
    assert_eq!(stored_status, StatusCode::OK, "{stored_value}");
    let stored: InviteReceivePolicy = serde_json::from_value(stored_value).unwrap();
    assert_eq!(stored, custom);

    let reread: InviteReceivePolicy =
        TestClient::get("http://server/_arkret/self/invite-receive-policy")
            .add_header("Authorization", format!("Bearer {alice_token}"), true)
            .add_header(
                "Arkret-Operation",
                arkret_wire::ServiceOperationId::SELF_INVITE_RECEIVE_POLICY_RESOURCE_GET_V1,
                true,
            )
            .send(&app)
            .await
            .take_json()
            .await
            .unwrap();
    assert_eq!(reread, custom);

    for mismatched_account in [
        AccountId::new(mallory, alice.station_id.clone()),
        AccountId::new(
            alice.principal_id.clone(),
            DidCoreId::new("ak:did_core:web:foreign-station.example").unwrap(),
        ),
    ] {
        let mismatched = InviteReceivePolicy::spec_default(mismatched_account.clone());
        let rejected = TestClient::put("http://server/_arkret/self/invite-receive-policy")
            .add_header("Authorization", format!("Bearer {alice_token}"), true)
            .add_header(
                "Arkret-Operation",
                arkret_wire::ServiceOperationId::SELF_INVITE_RECEIVE_POLICY_RESOURCE_REPLACE_V1,
                true,
            )
            .add_header("content-type", "application/json", true)
            .body(arkret_canonical::canonical_json_bytes(&mismatched).unwrap())
            .send(&app)
            .await;
        assert_eq!(
            rejected.status_code.unwrap(),
            StatusCode::FORBIDDEN,
            "cannot replace another account's policy: {mismatched_account}"
        );
    }

    let unchanged: InviteReceivePolicy =
        TestClient::get("http://server/_arkret/self/invite-receive-policy")
            .add_header("Authorization", format!("Bearer {alice_token}"), true)
            .add_header(
                "Arkret-Operation",
                arkret_wire::ServiceOperationId::SELF_INVITE_RECEIVE_POLICY_RESOURCE_GET_V1,
                true,
            )
            .send(&app)
            .await
            .take_json()
            .await
            .unwrap();
    assert_eq!(unchanged, custom);
}
