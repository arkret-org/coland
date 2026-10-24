//! Exercise the normal library artifact, not its cfg(test) compilation.

use coland_http::config::AppConfig;
use salvo::http::StatusCode;
use salvo::prelude::Service;
use salvo::test::{ResponseExt, TestClient};

#[tokio::test]
async fn development_network_config_does_not_relax_formal_verification() {
    for development_mode in [false, true] {
        let config = AppConfig {
            development_mode,
            ..coland_test_support::app_config()
        };
        assert_eq!(config.proof_verifier_mode(), "production");
        assert_eq!(
            config.development_harness_enabled(),
            cfg!(feature = "conformance-harness") && development_mode,
        );
        assert_eq!(
            config.admin_auth_mode(),
            if cfg!(feature = "conformance-harness") && development_mode {
                "development"
            } else {
                "closed"
            },
        );
        let state = coland_test_support::app_state(config);
        let service = Service::new(coland_http::router(state));
        let mut describe = TestClient::get("http://server/_coland/gate/auth/bridge/describe")
            .send(&service)
            .await;
        assert_eq!(describe.status_code, Some(StatusCode::OK));
        let body: serde_json::Value = describe.take_json().await.expect("bridge describe");
        assert_eq!(
            body["auth"].get("dev_login_path").is_some(),
            cfg!(feature = "conformance-harness")
        );
        // This syntactically invalid fixture credential must reach validation
        // only in the explicit harness; the normal artifact has no issuer route.
        let login = TestClient::post("http://server/_coland/gate/auth/dev-login")
            .json(&serde_json::json!({"actor": "invalid", "device_id": "invalid"}))
            .send(&service)
            .await;
        if cfg!(feature = "conformance-harness") && development_mode {
            assert_eq!(login.status_code, Some(StatusCode::BAD_REQUEST));
        } else {
            assert_eq!(login.status_code, Some(StatusCode::NOT_FOUND));
        }
        let mut admin = TestClient::get("http://server/_coland/admin/settings")
            .send(&service)
            .await;
        assert_eq!(admin.status_code, Some(StatusCode::UNAUTHORIZED));
        let error: arkret_wire::problem_details::Problem =
            admin.take_json().await.expect("admin problem");
        assert_eq!(error.status, 401);
        assert_eq!(
            error.problem_type,
            "https://arkret.org/problems/unauthenticated"
        );
    }
}

/// A real accepted founding device and stored local bearer reaches the admin
/// scope gate in both builds. Only the explicit harness synthesizes scopes;
/// development network configuration in a normal artifact must deny it.
#[tokio::test]
async fn stored_local_session_cannot_gain_synthetic_admin_scopes_in_a_normal_artifact() {
    use coland_test_support::AppStateTestExt as _;
    use coland_test_support::pcr_genesis::PcrGenesisFixture;

    let config = AppConfig {
        development_mode: true,
        ..coland_test_support::app_config()
    };
    let state = coland_test_support::app_state(config);
    let fixture = PcrGenesisFixture::new(state.service_did());
    fixture
        .admit(&state)
        .await
        .expect("accepted real PCR founding device");
    let store = state.test_persistence();
    let now = chrono::Utc::now();
    let account_pk = store
        .accounts()
        .put(&coland_storage::AccountRecord {
            pk: coland_storage::AccountPk(0),
            principal_id: fixture.history.account.principal_id.clone(),
            station_id: state.service_core_id(),
            localpart: "development-boundary".to_owned(),
            display_name: None,
            biography: None,
            avatar_blob_ref: None,
            created_at: now,
        })
        .await
        .expect("persist exact Account");
    let token = "stored-development-boundary-credential";
    // The credential store key is audience-bound; constructing its fixture
    // value does not mint a SessionGrant or bypass any request admission gate.
    use base64::Engine as _;
    use sha2::{Digest, Sha256};
    let mut credential = Sha256::new();
    credential.update(state.service_id().as_bytes());
    credential.update(b":");
    credential.update(token.as_bytes());
    let token_hash = format!(
        "sha256:{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(credential.finalize())
    );
    store
        .sessions()
        .put(&coland_storage::SessionRecord {
            token_hash: token_hash.clone(),
            account_pk,
            actor: fixture.history.account.principal_id.to_string(),
            device_id: fixture.history.founding_device_id.to_string(),
            audience: state.service_id().clone(),
            session_public_key: None,
            agent_session: None,
            expires_at: now + chrono::Duration::hours(1),
            created_at: now,
            revoked_at: None,
        })
        .await
        .expect("persist real immutable founding-device binding");
    assert!(
        store
            .sessions()
            .device_authorization(&token_hash)
            .await
            .unwrap()
            .is_some()
    );
    let service = Service::new(coland_http::router(state));
    let mut response = TestClient::get("http://server/_coland/admin/settings")
        .add_header("Authorization", format!("Bearer {token}"), true)
        .send(&service)
        .await;
    if cfg!(feature = "conformance-harness") {
        assert_eq!(response.status_code, Some(StatusCode::OK));
        let _: serde_json::Value = response.take_json().await.expect("harness settings");
    } else {
        assert_eq!(response.status_code, Some(StatusCode::FORBIDDEN));
        let error: arkret_wire::problem_details::Problem =
            response.take_json().await.expect("scope denied problem");
        assert_eq!(error.status, 403);
        assert_eq!(
            error.problem_type,
            "https://arkret.org/problems/capability_denied"
        );
    }
}
