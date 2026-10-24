//! Restore browser transport coverage against the complete production service.
//! API conventions section 10 requires explicit origin admission and keeps
//! authentication mandatory after a successful preflight.

use std::collections::BTreeMap;
use std::future::Future;

use coland_http::config::{AppConfig, StartupOverrides};
use coland_http::service;
use salvo::http::{HeaderMap, StatusCode};
use salvo::test::{ResponseExt, TestClient};
use serde_json::Value;

const ALLOWED: &str = "https://app.example.com";
const SECOND_ALLOWED: &str = "https://admin.example.com";
const DENIED: &str = "https://app.example.com.attacker.example";
const VIEWER: &str = "http://server/_arkret/self/account/viewer";

fn app(origin: Option<&str>) -> salvo::Service {
    service(coland_test_support::app_state(AppConfig {
        cors_allow_origin: origin.map(str::to_owned),
        ..coland_test_support::app_config()
    }))
}

fn run<F: Future<Output = ()>>(body: impl FnOnce() -> F + Send + 'static) {
    let result = std::thread::Builder::new()
        .stack_size(16 * 1024 * 1024)
        .spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(body());
        })
        .unwrap()
        .join();
    if let Err(payload) = result {
        std::panic::resume_unwind(payload);
    }
}

fn header_tokens(headers: &HeaderMap, name: &str) -> Vec<String> {
    headers
        .get_all(name)
        .iter()
        .flat_map(|value| value.to_str().unwrap().split(','))
        .map(|value| value.trim().to_ascii_lowercase())
        .collect()
}

#[test]
fn allowlist_preflight_admits_protocol_headers_and_rejects_other_origins() {
    run(|| async {
        let app = app(Some(" https://app.example.com, https://admin.example.com "));
        for origin in [ALLOWED, SECOND_ALLOWED] {
            let response = TestClient::options(VIEWER)
                .add_header("Origin", origin, true)
                .add_header("Access-Control-Request-Method", "GET", true)
                .add_header(
                    "Access-Control-Request-Headers",
                    "authorization,arkret-operation,dpop,signature,signature-input,content-digest",
                    true,
                )
                .send(&app)
                .await;
            assert!(response.status_code.unwrap().is_success());
            assert_eq!(response.headers()["access-control-allow-origin"], origin);
            assert_eq!(
                response.headers()["access-control-allow-credentials"],
                "true"
            );
            let headers = header_tokens(response.headers(), "access-control-allow-headers");
            for required in [
                "authorization",
                "arkret-operation",
                "dpop",
                "signature",
                "signature-input",
                "content-digest",
            ] {
                assert!(
                    headers.iter().any(|header| header == required),
                    "missing {required}"
                );
            }
            let methods = header_tokens(response.headers(), "access-control-allow-methods");
            for method in [
                "get", "head", "query", "post", "put", "patch", "delete", "options",
            ] {
                assert!(
                    methods.iter().any(|allowed| allowed == method),
                    "missing {method}"
                );
            }
            for method in ["connect", "trace"] {
                assert!(!methods.iter().any(|allowed| allowed == method));
            }
            assert!(
                header_tokens(response.headers(), "vary")
                    .iter()
                    .any(|name| name == "origin")
            );
        }
        let response = TestClient::options(VIEWER)
            .add_header("Origin", DENIED, true)
            .add_header("Access-Control-Request-Method", "GET", true)
            .send(&app)
            .await;
        assert!(
            response
                .headers()
                .get("access-control-allow-origin")
                .is_none()
        );
    });
}

#[test]
fn allowlisted_browser_metadata_does_not_bypass_self_authentication() {
    run(|| async {
        let app = app(Some(ALLOWED));
        for origin in [ALLOWED, DENIED] {
            let mut response = TestClient::get("http://server/_arkret/describe")
                .add_header("Arkret-Operation", "ak.server.read.describe.v1", true)
                .add_header("Origin", origin, true)
                .send(&app)
                .await;
            assert_eq!(response.status_code, Some(StatusCode::OK));
            if origin == ALLOWED {
                assert_eq!(response.headers()["access-control-allow-origin"], ALLOWED);
                assert!(
                    header_tokens(response.headers(), "access-control-expose-headers")
                        .iter()
                        .any(|header| header == "arkret-operation")
                );
            } else {
                assert!(
                    response
                        .headers()
                        .get("access-control-allow-origin")
                        .is_none()
                );
            }
            let description: Value = response.take_json().await.unwrap();
            let _: arkret_models_discovery::ServiceDescribe =
                serde_json::from_value(description).expect("formal metadata remains typed");
        }
        let mut response = TestClient::get(VIEWER)
            .add_header("Arkret-Operation", "ak.self.account.read.viewer.v1", true)
            .add_header("Origin", ALLOWED, true)
            .add_header("Cookie", "principal=alice; session=browser-cookie", true)
            .send(&app)
            .await;
        assert_eq!(response.status_code, Some(StatusCode::UNAUTHORIZED));
        assert_eq!(response.headers()["access-control-allow-origin"], ALLOWED);
        let problem: Value = response.take_json().await.unwrap();
        assert_eq!(problem["status"], 401);
        assert!(problem.get("account_id").is_none());
        assert!(problem.get("devices").is_none());
    });
}

#[test]
fn absent_cors_configuration_does_not_admit_browser_origins() {
    run(|| async {
        let app = app(None);
        let response = TestClient::get("http://server/_arkret/describe")
            .add_header("Arkret-Operation", "ak.server.read.describe.v1", true)
            .add_header("Origin", ALLOWED, true)
            .send(&app)
            .await;
        assert_eq!(response.status_code, Some(StatusCode::OK));
        assert!(
            response
                .headers()
                .get("access-control-allow-origin")
                .is_none()
        );
        assert!(
            response
                .headers()
                .get("access-control-allow-credentials")
                .is_none()
        );
    });
}

#[test]
fn browser_metadata_advertises_configured_account_authority_and_oidc() {
    run(|| async {
        let app = service(coland_test_support::app_state(AppConfig {
            cors_allow_origin: Some(ALLOWED.to_owned()),
            account_authority_url: Some("https://auth.example.com/".to_owned()),
            oidc_client_id: Some("browser-client".to_owned()),
            ..coland_test_support::app_config()
        }));
        let mut response = TestClient::get("http://server/_arkret/describe")
            .add_header("Arkret-Operation", "ak.server.read.describe.v1", true)
            .add_header("Origin", ALLOWED, true)
            .send(&app)
            .await;
        assert_eq!(response.status_code, Some(StatusCode::OK));
        assert_eq!(response.headers()["access-control-allow-origin"], ALLOWED);
        let description: Value = response.take_json().await.unwrap();
        let _: arkret_models_discovery::ServiceDescribe =
            serde_json::from_value(description.clone()).unwrap();
        assert_eq!(
            description["authentication_metadata"]["account_authority"]["gate_account_base_url"],
            "https://auth.example.com/_arkret/gate/account"
        );
        let methods = description["authentication_metadata"]["methods"]
            .as_array()
            .unwrap();
        let oidc = methods
            .iter()
            .find(|method| method["method"] == "oidc")
            .expect("configured browser sign-in method");
        assert_eq!(oidc["issuer_uri"], "https://auth.example.com/");
        assert_eq!(
            oidc["openid_configuration_url"],
            "https://auth.example.com/.well-known/openid-configuration"
        );
        assert_eq!(oidc["client_id"], "browser-client");
    });
}

#[test]
fn wildcard_browser_configuration_is_rejected_even_in_development() {
    let mut values = BTreeMap::from([
        ("COLAND_DEVELOPMENT_MODE".to_owned(), "true".to_owned()),
        (
            "COLAND_TRUST_DOMAIN".to_owned(),
            "ak:trust_domain:server.test".to_owned(),
        ),
    ]);
    let config = AppConfig::from_values(&values, StartupOverrides::default()).unwrap();
    assert!(config.cors_allow_origin.is_none());
    for raw in ["*", "https://app.example.com, *"] {
        values.insert("COLAND_CORS_ALLOW_ORIGIN".to_owned(), raw.to_owned());
        let error = AppConfig::from_values(&values, StartupOverrides::default())
            .expect_err("authenticated service cannot accept wildcard origins");
        assert!(error.to_string().contains("COLAND_CORS_ALLOW_ORIGIN"));
    }
    values.insert("COLAND_CORS_ALLOW_ORIGIN".to_owned(), ALLOWED.to_owned());
    assert_eq!(
        AppConfig::from_values(&values, StartupOverrides::default())
            .unwrap()
            .cors_allow_origin
            .as_deref(),
        Some(ALLOWED)
    );
}

#[test]
fn directly_constructed_wildcard_config_cannot_admit_private_browser_requests() {
    run(|| async {
        for raw in ["*", "https://app.example.com, *"] {
            let app = app(Some(raw));
            let response = TestClient::options(VIEWER)
                .add_header("Origin", ALLOWED, true)
                .add_header("Access-Control-Request-Method", "GET", true)
                .add_header("Access-Control-Request-Headers", "authorization,dpop", true)
                .send(&app)
                .await;
            assert!(
                response
                    .headers()
                    .get("access-control-allow-origin")
                    .is_none()
            );
            assert!(
                response
                    .headers()
                    .get("access-control-allow-credentials")
                    .is_none()
            );
            let response = TestClient::get(VIEWER)
                .add_header("Origin", ALLOWED, true)
                .add_header("Arkret-Operation", "ak.self.account.read.viewer.v1", true)
                .send(&app)
                .await;
            assert_eq!(response.status_code, Some(StatusCode::UNAUTHORIZED));
            assert!(
                response
                    .headers()
                    .get("access-control-allow-origin")
                    .is_none()
            );
        }
    });
}
