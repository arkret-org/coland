// Current HTTP integration helpers. Legacy Seal/Cell fixtures remain in common.rs for migration
// reference.
//! Shared helpers, fixtures, and imports for the coland HTTP-API integration test binary.
//!
//! Originally lived inline at the top of the monolithic `http_api` test before the
//! file was split into per-domain submodules. All items are reachable
//! to siblings via `super::common::*` from the `main.rs` integration-test root.

// Each test binary uses a subset of these shared helpers and re-exports.
#![allow(dead_code, unused_imports)]

pub(crate) use std::sync::LazyLock;
use std::sync::OnceLock;
pub(crate) use std::sync::atomic::{AtomicU64, Ordering};
pub(crate) use std::time::Duration;

pub(crate) use arkret_identifiers::{Did, DidCoreId, RealmId, new_prefixed_uuid7};
pub(crate) use base64::Engine;
pub(crate) use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
pub(crate) use coland_domain::artifacts;
pub(crate) use coland_http::config::{AppConfig, IceServersConfig};
pub(crate) use coland_http::ratelimit::RateLimiterConfig;
pub(crate) use coland_http::state::{AppState, RealmDirectoryEntry};
pub(crate) use coland_http::{
    service, service_with_rate_limiter_config, service_with_request_size_limit,
};
pub(crate) use coland_storage::{RealmMetaRecord, WebvhDocumentRecord};
pub(crate) use coland_storage_postgres::Db;
pub(crate) use coland_test_support::AppStateTestExt;
pub(crate) use ed25519_dalek::{Signature, Signer, SigningKey, Verifier};
pub(crate) use futures_util::StreamExt;
pub(crate) use salvo::http::StatusCode;
pub(crate) use salvo::test::ResponseExt;
pub(crate) use serde_json::Value;
pub(crate) use sha2::{Digest, Sha256};

/// Protocol-aware test request factory. Production clients choose an exact
/// operation before sending; the integration harness derives that same exact
/// selector from the canonical registry so unrelated handler tests do not
/// duplicate 260 static header literals. Selector-negative tests must use
/// `salvo::test::TestClient` directly.
pub(crate) struct TestClient;

impl TestClient {
    fn select(
        method: salvo::http::Method,
        url: impl AsRef<str>,
        builder: salvo::test::RequestBuilder,
    ) -> salvo::test::RequestBuilder {
        let path = url::Url::parse(url.as_ref())
            .expect("test request URL is absolute")
            .path()
            .to_owned();
        let operation = if matches!(
            method,
            salvo::http::Method::POST
                | salvo::http::Method::PATCH
                | salvo::http::Method::HEAD
                | salvo::http::Method::DELETE
        ) && (path == "/_arkret/self/blob/resumable"
            || path.starts_with("/_arkret/self/blob/resumable/"))
        {
            Some(arkret_wire::ServiceOperationId::SelfBlobUploadCreateV1)
        } else {
            arkret_wire::ServiceOperationId::from_http_request(method.as_str(), &path)
        };
        match operation {
            Some(operation) => builder.add_header("Arkret-Operation", operation.as_str(), true),
            None => builder,
        }
    }

    pub(crate) fn get(url: impl AsRef<str>) -> salvo::test::RequestBuilder {
        Self::select(
            salvo::http::Method::GET,
            url.as_ref(),
            salvo::test::TestClient::get(url.as_ref()),
        )
    }

    pub(crate) fn post(url: impl AsRef<str>) -> salvo::test::RequestBuilder {
        Self::select(
            salvo::http::Method::POST,
            url.as_ref(),
            salvo::test::TestClient::post(url.as_ref()),
        )
    }

    pub(crate) fn put(url: impl AsRef<str>) -> salvo::test::RequestBuilder {
        Self::select(
            salvo::http::Method::PUT,
            url.as_ref(),
            salvo::test::TestClient::put(url.as_ref()),
        )
    }

    pub(crate) fn query(url: impl AsRef<str>) -> salvo::test::RequestBuilder {
        Self::select(
            salvo::http::Method::QUERY,
            url.as_ref(),
            salvo::test::TestClient::query(url.as_ref()),
        )
    }

    pub(crate) fn delete(url: impl AsRef<str>) -> salvo::test::RequestBuilder {
        Self::select(
            salvo::http::Method::DELETE,
            url.as_ref(),
            salvo::test::TestClient::delete(url.as_ref()),
        )
    }

    pub(crate) fn head(url: impl AsRef<str>) -> salvo::test::RequestBuilder {
        Self::select(
            salvo::http::Method::HEAD,
            url.as_ref(),
            salvo::test::TestClient::head(url.as_ref()),
        )
    }

    pub(crate) fn options(url: impl AsRef<str>) -> salvo::test::RequestBuilder {
        salvo::test::TestClient::options(url)
    }

    pub(crate) fn patch(url: impl AsRef<str>) -> salvo::test::RequestBuilder {
        Self::select(
            salvo::http::Method::PATCH,
            url.as_ref(),
            salvo::test::TestClient::patch(url.as_ref()),
        )
    }
}

/// Derived, never copied: the demo Realm id is `retype(genesis.event_id)` and
/// moves with any `arkret-spec` change that touches the genesis payload.
pub(crate) fn demo_realm_id() -> &'static str {
    static ID: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
        coland_test_support::app_state(test_config())
            .development_demo_realm_id()
            .to_string()
    });
    &ID
}
/// Fixed REST-style TURN shared secret installed by `test_config()` so the
/// derived TURN credential is deterministic in assertions. Mirrors
/// `COLAND_TURN_SHARED_SECRET`.
pub(crate) const COLAND_TEST_TURN_SHARED_SECRET: &str = "coland-test-turn-shared-secret-0123456789";
pub(crate) const ACCOUNT_REGISTER_BEARER: &str = "coland-test-account-register-bearer";

/// Project a fixture's DID onto its signing principal. Account-scoped payloads
/// and projection keys use the complete Account/Actor helpers below.
pub(crate) fn fixture_actor_core_id(actor: &str) -> DidCoreId {
    arkret_wire::project_did_to_core_id(&Did::new(actor.to_owned()).expect("fixture actor DID"))
        .expect("fixture actor DID projects to a core id")
}

/// Exact local Account used by a fixture whose Station is the supplied app.
pub(crate) fn fixture_account_id(state: &AppState, principal_did: &str) -> arkret_wire::AccountId {
    arkret_wire::AccountId::new(
        fixture_actor_core_id(principal_did),
        state.service_core_id(),
    )
}

pub(crate) fn fixture_account_actor(state: &AppState, principal_did: &str) -> arkret_wire::ActorId {
    arkret_wire::ActorId::account(fixture_account_id(state, principal_did))
}
/// Render a timestamp exactly as the SDK's canonical wire serializer does
/// (fixed milliseconds, `Z` suffix). The canonical deserializer rejects every
/// other RFC 3339 spelling, so hand-built fixture JSON must use this.
pub(crate) fn canonical_timestamp(at: chrono::DateTime<chrono::Utc>) -> String {
    at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

pub(crate) fn test_config() -> AppConfig {
    AppConfig {
        ice: IceServersConfig {
            // `webrtc-signaling.md` §4.1 — fix the REST-style TURN shared secret
            // so the derived credential is deterministic for assertions.
            turn_shared_secret: Some(COLAND_TEST_TURN_SHARED_SECRET.to_owned()),
            ..IceServersConfig::default()
        },
        development_mode: true,
        embedded_webvh_registration_bearer: Some(ACCOUNT_REGISTER_BEARER.to_owned()),
        // Tests use fixed-time HLC fixtures; window=0 disables replay-window
        // enforcement so they keep passing.
        resumable_upload_dir: std::env::temp_dir().join("coland-test-resumable-uploads"),
        seed_demo_data: true,
        ..coland_test_support::app_config()
    }
}

pub(crate) fn app() -> salvo::Service {
    service(coland_test_support::app_state(test_config()))
}

pub(crate) fn app_from_state(state: AppState) -> salvo::Service {
    service(state)
}

pub(crate) fn advertises_operation(describe: &Value, operation_id: &str) -> bool {
    describe["supported_operation_bundles"]
        .as_array()
        .is_some_and(|bundles| {
            bundles
                .iter()
                .filter_map(Value::as_str)
                .filter_map(arkret_wire::operation_bundle_descriptor)
                .flat_map(|bundle| bundle.members)
                .any(|binding| binding.operation_id.as_str() == operation_id)
        })
}

/// Return the canonical RFC 9457 Arkret problem code encoded by the problem
/// type URI. Error responses are closed problem-detail objects.
pub(crate) fn problem_code(body: &Value) -> &str {
    body["type"]
        .as_str()
        .and_then(|problem_type| problem_type.rsplit('/').next())
        .filter(|code| !code.is_empty())
        .expect("response must contain a canonical Arkret problem type URI")
}
pub(crate) async fn dev_token(state: AppState) -> String {
    dev_token_for_device(
        state,
        "did:web:alice.example",
        "ak:device:01904100-0000-7000-8000-a11ce0000001",
        "Alice Desktop",
    )
    .await
}
pub(crate) async fn dev_token_for_device(
    state: AppState,
    actor: &str,
    device_id: &str,
    display_name: &str,
) -> String {
    let actor_core = arkret_wire::project_did_to_core_id(
        &Did::new(actor.to_owned()).expect("fixture actor DID"),
    )
    .expect("fixture actor core id");
    let login: Value = TestClient::post("http://server/_coland/gate/auth/dev-login")
        .json(&serde_json::json!({
            "actor": actor_core,
            "device_id": device_id,
            "display_name": display_name
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    login["session_credential"].as_str().unwrap().to_owned()
}
pub(crate) fn multipart_blob_upload_body(
    content: impl AsRef<[u8]>,
    media_type: &str,
) -> (String, Vec<u8>) {
    let content = content.as_ref();
    let boundary = format!(
        "arkret-test-{}",
        hex::encode(Sha256::digest(content))
            .chars()
            .take(16)
            .collect::<String>()
    );
    let mut body = Vec::new();
    body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
    body.extend_from_slice(b"Content-Disposition: form-data; name=\"size_bytes\"\r\n\r\n");
    body.extend_from_slice(content.len().to_string().as_bytes());
    body.extend_from_slice(format!("\r\n--{boundary}\r\n").as_bytes());
    body.extend_from_slice(b"Content-Disposition: form-data; name=\"encryption\"\r\nContent-Type: application/json\r\n\r\nnull");
    body.extend_from_slice(format!("\r\n--{boundary}\r\n").as_bytes());
    body.extend_from_slice(
        b"Content-Disposition: form-data; name=\"content\"; filename=\"blob\"\r\n",
    );
    body.extend_from_slice(format!("Content-Type: {media_type}\r\n\r\n").as_bytes());
    body.extend_from_slice(content);
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    (format!("multipart/form-data; boundary={boundary}"), body)
}
pub(crate) async fn register_account(
    state: AppState,
    did: &str,
    handle: &str,
    device_id: &str,
) -> String {
    let did = Did::new(did.to_owned()).expect("fixture account DID");
    let principal_id = fixture_actor_core_id(did.as_str());
    let registered: Value = TestClient::post("http://server/_coland/gate/account/project")
        .json(&serde_json::json!({
            "principal_id": principal_id,
            "did": did,
            "display_name": handle.trim_start_matches('@'),
            "device_id": device_id
        }))
        .add_header(
            "authorization",
            format!("Bearer {ACCOUNT_REGISTER_BEARER}"),
            true,
        )
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(
        registered["principal_id"],
        principal_id.as_str(),
        "register response: {registered}"
    );

    let login: Value = TestClient::post("http://server/_coland/gate/auth/dev-login")
        .json(&serde_json::json!({
            "actor": principal_id,
            "device_id": device_id,
            "display_name": handle.trim_start_matches('@')
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    login["session_credential"].as_str().unwrap().to_owned()
}
/// Run one async test body with the standard thread stack and a
/// current-thread Tokio runtime.
pub(crate) fn run_on_test_runtime<F>(name: &'static str, body: impl FnOnce() -> F + Send + 'static)
where
    F: Future<Output = ()>,
{
    let joined = std::thread::Builder::new()
        .spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap_or_else(|error| panic!("build the {name} test runtime: {error}"))
                .block_on(body());
        })
        .unwrap_or_else(|error| panic!("spawn the {name} test thread: {error}"))
        .join();
    // Re-raise the original payload so the assertion message libtest reports is
    // the one the test body produced, not a generic "thread panicked".
    if let Err(payload) = joined {
        std::panic::resume_unwind(payload);
    }
}
