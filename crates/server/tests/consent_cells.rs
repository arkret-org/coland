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
        .append_pair("peer", &serde_json::to_string(&peer).unwrap())
        .append_pair("consent_scope", "voice_call");
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
    let path = "replace";
    let operation = "ak.self.consent.command.replace.v1";
    let body = arkret_canonical::canonical_json_bytes(
        &arkret_models_collaboration::consent_operations::ConsentReplaceRequestBody {
            consent_event: arkret_wire::EventAdmissionSubmission::new(event),
        },
    )
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

#[tokio::test]
async fn consent_holder_reads_one_complete_peer_summary_and_denies_foreign_sessions() {
    let state = coland_test_support::app_state(test_config());
    let app = service(state.clone());
    let holder = coland_test_support::pcr_genesis::PcrGenesisFixture::new(state.service_did());
    let other = coland_test_support::pcr_genesis::PcrGenesisFixture::new(state.service_did());
    let token = dev_token(&state, &app, &holder).await;
    let other_token = dev_token(&state, &app, &other).await;
    let peer = serde_json::json!({"kind":"actor","actor_id":arkret_wire::ActorId::account(other.history.account.clone())});
    let grant = signed_consent_event(
        &holder,
        arkret_wire::EventKind::ConsentReplace,
        serde_json::json!({"peer":peer,"expected_current":{"state":"never_written"},"permissions":[{"consent_scope":"invite"}]}),
    );
    let (status, value) = consent_command(&app, &token, grant.clone()).await;
    assert_eq!(status, StatusCode::OK, "{value}");
    let mut unsigned = grant.clone();
    unsigned.producer_proof = None;
    let (status, _) = consent_command(&app, &token, unsigned).await;
    assert!(
        status.is_client_error(),
        "a holder session replaced a missing producer proof"
    );
    let value = admit_consent_fixture(&state, grant.clone()).await;
    let granted: arkret_models_collaboration::consent_operations::ConsentView =
        serde_json::from_value(value).unwrap();
    assert_eq!(
        granted.permission_scopes,
        vec![arkret_wire::ConsentScope::Invite]
    );
    let duplicate = admit_consent_fixture(&state, grant.clone()).await;
    assert_eq!(
        serde_json::from_value::<arkret_models_collaboration::consent_operations::ConsentView>(
            duplicate
        )
        .unwrap(),
        granted
    );
    let (wrong_status, _) = consent_command(&app, &other_token, grant.clone()).await;
    assert_ne!(wrong_status, StatusCode::OK);
    let mut query = url::Url::parse("http://server/_arkret/self/consent/result").unwrap();
    query
        .query_pairs_mut()
        .append_pair("peer", &serde_json::to_string(&peer).unwrap());
    let mut get = TestClient::get(query.as_str())
        .add_header("Authorization", format!("Bearer {token}"), true)
        .add_header("Arkret-Operation", "ak.self.consent.resource.get.v1", true)
        .send(&app)
        .await;
    assert_eq!(get.status_code.unwrap(), StatusCode::OK);
    assert_eq!(
        get.take_json::<arkret_models_collaboration::consent_operations::ConsentView>()
            .await
            .unwrap(),
        granted
    );
    let revoke = signed_consent_event(
        &holder,
        arkret_wire::EventKind::ConsentReplace,
        serde_json::json!({"peer":peer,"expected_current":{"state":"present","revision":granted.revision},"permissions":[]}),
    );
    let (status, value) = consent_command(&app, &token, revoke.clone()).await;
    assert_eq!(status, StatusCode::OK, "{value}");
    let value = admit_consent_fixture(&state, revoke).await;
    assert_eq!(value["permission_scopes"], serde_json::json!([]));
    let value = admit_consent_fixture(&state, grant).await;
    assert_eq!(value["permission_scopes"], serde_json::json!(["invite"]));
    let mut listed = TestClient::get("http://server/_arkret/self/consent/results")
        .add_header("Authorization", format!("Bearer {token}"), true)
        .add_header("Arkret-Operation", "ak.self.consent.read.list.v1", true)
        .send(&app)
        .await;
    let list = listed
        .take_json::<arkret_models_collaboration::consent_operations::ConsentList>()
        .await
        .unwrap();
    assert_eq!(list.consents.len(), 1);
    assert!(list.consents[0].permission_scopes.is_empty());
    let mut private = TestClient::get("http://server/_arkret/self/consent/results")
        .add_header("Authorization", format!("Bearer {other_token}"), true)
        .add_header("Arkret-Operation", "ak.self.consent.read.list.v1", true)
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
