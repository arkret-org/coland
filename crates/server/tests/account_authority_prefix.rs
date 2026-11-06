//! Exercise discovery through the production router with a prefixed authority.
use coland_test_support::AppStateTestExt as _;
use salvo::test::{ResponseExt, TestClient};

#[test]
fn describe_keeps_authority_paths_and_advertises_a_valid_origin() {
    std::thread::Builder::new()
        .stack_size(16 * 1024 * 1024)
        .spawn(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async {
                    let mut config = coland_test_support::app_config();
                    config.account_authority_url = Some("https://station.example/auth/".to_owned());
                    let app = coland_http::service(coland_test_support::app_state(config));
                    let mut response =
                        TestClient::get("http://server/_arkret/describe?service_kind=station")
                            .add_header("Arkret-Operation", "ak.server.read.describe.v1", true)
                            .send(&app)
                            .await;
                    assert_eq!(response.status_code, Some(salvo::http::StatusCode::OK));
                    let description: serde_json::Value = response.take_json().await.unwrap();
                    let auth = &description["authentication_metadata"];
                    assert_eq!(
                        auth["account_authority"]["origin"],
                        "https://station.example"
                    );
                    assert_eq!(
                        auth["account_authority"]["gate_account_base_url"],
                        "https://station.example/auth/_arkret/gate/account"
                    );
                    assert_eq!(
                        auth["methods"][0]["issuer_uri"],
                        "https://station.example/auth/"
                    );
                });
        })
        .unwrap()
        .join()
        .unwrap();
}

#[test]
fn prefixed_authority_genesis_admits_its_origin_and_rejects_substituted_origins() {
    std::thread::Builder::new()
        .stack_size(16 * 1024 * 1024)
        .spawn(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async {
                    let mut config = coland_test_support::app_config();
                    config.account_authority_url = Some("https://principal.example/auth/".to_owned());
                    config.register_test_internal_authority_channel("prefix-test-credential");
                    let state = coland_test_support::app_state(config);
                    let now = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
                    let fixture = coland_test_support::pcr_genesis::PcrGenesisFixture::new_with(
                        state.service_did(),
                        coland_test_support::device_authorization_history::DeviceHistoryFixtureOptions {
                            local_id: format!("prefix-{}", uuid::Uuid::now_v7().simple()),
                            created_at: now,
                            founding_not_before: now,
                            ..Default::default()
                        },
                    );
                    let persistence = state.test_persistence();
                    let request = &fixture.unit.submission;
                    let app = coland_http::service(state.clone());
                    let endpoint = "http://server/_coland/account-authority/principal-genesis/admit";

                    for origin in ["http://principal.example", "https://other.example", "https://principal.example:8443"] {
                        let mut substituted = request.clone();
                        substituted.identity_creation_control_proof.origin = arkret_wire::WebOrigin::new(origin).unwrap();
                        let body = arkret_canonical::canonical_json_bytes(&substituted).unwrap();
                        let mut response = TestClient::post(endpoint)
                            .add_header("Authorization", "Bearer prefix-test-credential", true)
                            .add_header("Idempotency-Key", request.idempotency_key.as_str(), true)
                            .add_header("Content-Type", "application/json", true)
                            .body(body.clone())
                            .send(&app)
                            .await;
                        let status = response.status_code;
                        let problem = response.take_string().await.unwrap();
                        assert_eq!(status, Some(salvo::http::StatusCode::CONFLICT), "{problem}");
                        assert!(problem.contains("creation-proof origin does not match"), "{problem}");
                        assert!(persistence.authority_commits().pcr_genesis_replay(&substituted, &body).await.unwrap().is_none());
                    }

                    let operation = serde_json::to_value(&fixture.history.inception.operation).unwrap();
                    persistence.webvh().append_log_event(coland_storage::WebvhLogRecord {
                        event_digest: arkret_canonical::canonical_sha256(&operation).unwrap(),
                        did: fixture.history.did.to_string(),
                        sequence: fixture.history.inception.sequence.unwrap_or(1),
                        operation,
                        created_at: fixture.history.events[0].created_at,
                    }).await.unwrap();
                    let mut response = TestClient::post(endpoint)
                        .add_header("Authorization", "Bearer prefix-test-credential", true)
                        .add_header("Idempotency-Key", request.idempotency_key.as_str(), true)
                        .add_header("Content-Type", "application/json", true)
                        .body(arkret_canonical::canonical_json_bytes(request).unwrap())
                        .send(&app)
                        .await;
                    let status = response.status_code;
                    let body = response.take_string().await.unwrap();
                    assert_eq!(status, Some(salvo::http::StatusCode::OK), "{body}");
                    let outcome: arkret_models_collaboration::principal_operations::PcrGenesisAdmissionResponseBody = serde_json::from_str(&body).unwrap();
                    outcome.validate_against(request).unwrap();
                });
        })
        .unwrap()
        .join()
        .unwrap();
}
