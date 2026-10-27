//! Admin routes behind the `RequireAdmin` gate authenticate a DPoP
//! SessionGrant exactly once per request.
//!
//! The gate verifies the request's DPoP proof (consuming its single-use
//! `jti`) and hands the authenticated principal to the handler through the
//! request depot. The handler must not verify the proof a second time: that
//! second verification is what used to turn every DPoP admin request into a
//! `jti` replay 401. The single-use rule itself stays intact — presenting the
//! same proof on a second request is still rejected.

use std::sync::{Arc, Mutex};

use coland_http::config::AppConfig;
use coland_http::service;
use coland_http::state::AppState;
use coland_test_support::AppStateTestExt as _;
use coland_test_support::pcr_genesis::PcrGenesisFixture;
use ed25519_dalek::SigningKey;
use salvo::http::StatusCode;
use salvo::test::{ResponseExt, TestClient};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const QUEUE_PATH: &str = "/_coland/admin/moderation/queue";
const VIEWER_PATH: &str = "/_arkret/self/account/viewer";
struct GrantSession {
    state: AppState,
    principal_id: arkret_identifiers::DidCoreId,
    grant_jwt: String,
    holder_key: SigningKey,
}

/// A founding-device DPoP SessionGrant for an accepted PCR, vouched for by a
/// component-only injected Account Authority double.
async fn grant_session(slug: &str, configure: impl FnOnce(&mut AppConfig)) -> GrantSession {
    let holder_key = SigningKey::from_bytes(&Sha256::digest(slug.as_bytes()).into());
    let grant_jwt = format!("admin-dpop-grant.{slug}.{}", uuid::Uuid::now_v7().simple());

    let slot = Arc::new(Mutex::new(Value::Null));
    let mut config = AppConfig {
        development_mode: true,
        account_authority_url: Some("https://component-aa.example".to_owned()),
        ..coland_test_support::app_config()
    };
    config.register_test_internal_authority_channel(format!("admin-dpop-{slug}"));
    configure(&mut config);
    let state = coland_test_support::app_state(config);
    let authority =
        coland_test_support::account_authority::ComponentAccountAuthority::from_json_slot(
            state.service_core_id(),
            slot.clone(),
        );
    let state = state.with_local_account_authority(authority).unwrap();
    let fixture = PcrGenesisFixture::new(state.service_did());
    fixture.admit(&state).await.expect("durable PCR genesis");
    // The Account row the grant's account binding resolves to at this Station.
    state
        .test_persistence()
        .accounts()
        .put(&coland_storage::AccountRecord {
            pk: coland_storage::AccountPk(0),
            principal_id: fixture.history.account.principal_id.clone(),
            station_id: state.service_core_id(),
            localpart: format!("admin-dpop-{slug}"),
            display_name: None,
            biography: None,
            avatar_blob_ref: None,
            created_at: chrono::Utc::now(),
        })
        .await
        .expect("seed the grant's Account");

    let device_id = fixture.history.founding_device_id.clone();
    let authorization_event_id = fixture.history.events[1].event_id.clone();
    let holder_jwk =
        arkret_signatures::JsonWebKey::from_ed25519_verifying_key(&holder_key.verifying_key());
    let cnf_jkt = arkret_signatures::dpop::dpop_jwk_thumbprint(&holder_jwk).expect("holder jkt");
    *slot.lock().unwrap() = json!({
        "active": true,
        "status": "active",
        "proof_required": false,
        "one_time_use_consumed": false,
        "grant": {
            "id": arkret_identifiers::SessionGrantId::from_issuance_digest(
                Sha256::digest(grant_jwt.as_bytes()).into(),
            ),
            "issuer_id": state.service_id(),
            "account_id": {
                "principal_id": fixture.history.account.principal_id,
                "station_id": state.service_id(),
            },
            "device_id": device_id,
            "audience_id": state.service_id(),
            "scopes": [
                arkret_models_identity::admin_grant::admin_scopes::ADMIN_READ,
                "ak.self.account.read.viewer.v1",
            ],
            "expires_at": arkret_canonical::format_timestamp_canonical(
                chrono::Utc::now() + chrono::Duration::minutes(5),
            ),
            "revocation_ref": format!("ak:session:{}", uuid::Uuid::now_v7().simple()),
            "session_public_key": format!(
                "{{\"crv\":\"Ed25519\",\"kty\":\"OKP\",\"x\":\"{}\"}}",
                arkret_canonical::base64url_encode(holder_key.verifying_key().to_bytes()),
            ),
            "cnf_jkt": cnf_jkt,
            "credential_class": "standard",
            "holder_binding": {"kind": "human_device", "device_binding": device_id},
            "device_binding": {
                "device_id": device_id,
                "authorization_event_id": authorization_event_id,
                "model_generation_ref": 1,
            },
        }
    });
    GrantSession {
        state,
        principal_id: fixture.history.account.principal_id.clone(),
        grant_jwt,
        holder_key,
    }
}

impl GrantSession {
    /// A fresh `Authorization`/`DPoP` header pair for one request.
    fn headers(&self, method: &str, path: &str) -> (String, String) {
        let htu = format!(
            "{}{}",
            self.state.config().public_base_url.trim_end_matches('/'),
            path
        );
        let proof = arkret_signatures::dpop::build_dpop_proof(
            &arkret_signatures::dpop::DpopProofRequest::new(method, htu)
                .access_token(self.grant_jwt.clone()),
            &self.holder_key,
        )
        .expect("DPoP proof builds");
        (format!("DPoP {}", self.grant_jwt), proof.header_value)
    }

    async fn get(&self, path: &str, headers: Option<&(String, String)>) -> (StatusCode, Value) {
        let mut request = TestClient::get(format!("http://server{path}"));
        if path.starts_with(VIEWER_PATH) {
            request =
                request.add_header("Arkret-Operation", "ak.self.account.read.viewer.v1", true);
        }
        if let Some((authorization, dpop)) = headers {
            request = request
                .add_header("authorization", authorization.clone(), true)
                .add_header("dpop", dpop.clone(), true);
        }
        let mut response = request.send(&service(self.state.clone())).await;
        let status = response.status_code.expect("status");
        let body = response.take_json().await.unwrap_or(Value::Null);
        (status, body)
    }
}

fn problem_code(body: &Value) -> &str {
    body["type"]
        .as_str()
        .and_then(|problem_type| problem_type.rsplit('/').next())
        .unwrap_or_default()
}

/// Restores the retired auth HTTP cases on the canonical self operation and
/// a committed founding-device fixture. Each negative uses a fresh proof so
/// a replay rejection cannot hide an authentication-shape regression.
#[tokio::test]
async fn canonical_viewer_rejects_missing_dpop_and_query_credentials() {
    let session = grant_session("viewer-auth-shape", |_| {}).await;

    let valid = session.headers("GET", VIEWER_PATH);
    let (status, body) = session.get(VIEWER_PATH, Some(&valid)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["principal_id"], session.principal_id.as_str());

    let mut missing_proof = TestClient::get(format!("http://server{VIEWER_PATH}"))
        .add_header("Arkret-Operation", "ak.self.account.read.viewer.v1", true)
        .add_header("authorization", format!("DPoP {}", session.grant_jwt), true)
        .send(&service(session.state.clone()))
        .await;
    assert_eq!(missing_proof.status_code, Some(StatusCode::UNAUTHORIZED));
    let body: Value = missing_proof
        .take_json()
        .await
        .expect("missing-proof problem");
    assert_eq!(problem_code(&body), "unauthenticated", "{body}");

    let (_, proof) = session.headers("GET", VIEWER_PATH);
    let mut bearer_with_proof = TestClient::get(format!("http://server{VIEWER_PATH}"))
        .add_header("Arkret-Operation", "ak.self.account.read.viewer.v1", true)
        .add_header(
            "authorization",
            format!("Bearer {}", session.grant_jwt),
            true,
        )
        .add_header("dpop", proof, true)
        .send(&service(session.state.clone()))
        .await;
    assert_eq!(
        bearer_with_proof.status_code,
        Some(StatusCode::UNAUTHORIZED)
    );
    let body: Value = bearer_with_proof.take_json().await.expect("Bearer problem");
    assert_eq!(problem_code(&body), "unauthenticated", "{body}");

    for query in ["access_token=leaked", "sign%61ture=leaked"] {
        let headers = session.headers("GET", VIEWER_PATH);
        let path = format!("{VIEWER_PATH}?page=1&{query}");
        let (status, body) = session.get(&path, Some(&headers)).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{query}: {body}");
        assert_eq!(problem_code(&body), "unauthenticated", "{query}: {body}");
    }

    let headers = session.headers("GET", VIEWER_PATH);
    let (status, body) = session
        .get(&format!("{VIEWER_PATH}?page=1"), Some(&headers))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

#[tokio::test]
async fn dpop_session_reaches_admin_route_once_and_replay_is_rejected() {
    let session = grant_session("dev", |_| {}).await;

    // One proof, one authentication: the gate consumes the proof and the
    // handler reads the authenticated principal instead of re-verifying it.
    let headers = session.headers("GET", QUEUE_PATH);
    let (status, body) = session.get(QUEUE_PATH, Some(&headers)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body["items"].is_array(), "{body}");

    // The exact same proof on a second request is a replay.
    let (status, body) = session.get(QUEUE_PATH, Some(&headers)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(problem_code(&body), "unauthenticated", "{body}");

    // A fresh proof for the same grant is admitted again.
    let fresh = session.headers("GET", QUEUE_PATH);
    let (status, body) = session.get(QUEUE_PATH, Some(&fresh)).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // No credential at all never reaches the handler.
    let (status, body) = session.get(QUEUE_PATH, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(problem_code(&body), "unauthenticated", "{body}");
}

#[tokio::test]
async fn dpop_session_reaches_every_admin_router_once() {
    let session = grant_session("routers", |_| {}).await;
    // Routes from each gated admin router: server ops, the operator surface
    // (including a handler that shares its body with a self-path endpoint),
    // and the collection/retention/settings branch.
    for path in [
        "/_coland/admin/server/status",
        "/_coland/admin/actors",
        "/_coland/admin/capabilities",
        "/_coland/admin/key-backups",
        "/_coland/admin/realms",
        "/_coland/admin/settings",
    ] {
        let headers = session.headers("GET", path);
        let (status, body) = session.get(path, Some(&headers)).await;
        assert_eq!(status, StatusCode::OK, "{path}: {body}");
        let (status, body) = session.get(path, Some(&headers)).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{path} replay: {body}");
    }
}

/// Production admin scopes come from the same freshly authenticated grant.
/// The DPoP proof is consumed exactly once by request authentication.
#[tokio::test]
async fn production_dpop_session_is_scope_checked_and_authenticated_once() {
    let session = grant_session("production", |config| {
        config.development_mode = false;
    })
    .await;

    // Not yet an admin principal: authenticated, then denied by the gate.
    let headers = session.headers("GET", QUEUE_PATH);
    let (status, body) = session.get(QUEUE_PATH, Some(&headers)).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");

    let mut settings = (*session.state.settings()).clone();
    settings.admin_principal_ids = vec![session.principal_id.clone()];
    session.state.replace_settings(settings);

    let headers = session.headers("GET", QUEUE_PATH);
    let (status, body) = session.get(QUEUE_PATH, Some(&headers)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = session.get(QUEUE_PATH, Some(&headers)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(problem_code(&body), "unauthenticated", "{body}");
}

/// The canonical self gate binds a real grant proof to method, complete URL,
/// credential bytes and holder key. Every mismatch carries a fresh signed jti.
#[tokio::test]
async fn canonical_viewer_binds_dpop_to_method_url_token_and_holder_key() {
    let session = grant_session("viewer-dpop-binding", |_| {}).await;
    let correct = session.headers("GET", VIEWER_PATH);
    let (status, body) = session.get(VIEWER_PATH, Some(&correct)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let viewer: arkret_models_collaboration::account_operations::AccountView =
        serde_json::from_value(body).expect("SDK AccountView");
    assert_eq!(viewer.principal_id, session.principal_id);

    let url = format!(
        "{}{}",
        session.state.config().public_base_url.trim_end_matches('/'),
        VIEWER_PATH
    );
    let other_key = SigningKey::from_bytes(&Sha256::digest(b"unbound-viewer-holder").into());
    for (label, method, target, token, key) in [
        (
            "method",
            "POST",
            url.clone(),
            session.grant_jwt.clone(),
            &session.holder_key,
        ),
        (
            "URL authority",
            "GET",
            format!("https://untrusted-origin.example{VIEWER_PATH}"),
            session.grant_jwt.clone(),
            &session.holder_key,
        ),
        (
            "token hash",
            "GET",
            url.clone(),
            "another-exact-credential".to_owned(),
            &session.holder_key,
        ),
        (
            "holder key",
            "GET",
            url,
            session.grant_jwt.clone(),
            &other_key,
        ),
    ] {
        let proof = arkret_signatures::dpop::build_dpop_proof(
            &arkret_signatures::dpop::DpopProofRequest::new(method, target).access_token(token),
            key,
        )
        .expect("fresh signed DPoP mismatch");
        let headers = (format!("DPoP {}", session.grant_jwt), proof.header_value);
        let (status, body) = session.get(VIEWER_PATH, Some(&headers)).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{label}: {body}");
        let problem: arkret_wire::Problem =
            serde_json::from_value(body.clone()).expect("SDK Problem");
        assert_eq!(problem.status, 401, "{label}: {body}");
        assert_eq!(problem.code(), "unauthenticated", "{label}: {body}");
        assert!(
            !problem.extensions.contains_key("principal_id"),
            "{label}: {body}"
        );
        assert!(
            !problem.extensions.contains_key("account_id"),
            "{label}: {body}"
        );
        assert!(
            !serde_json::to_string(&body)
                .unwrap()
                .contains(session.principal_id.as_str()),
            "{label}: viewer identity leaked"
        );
    }

    // Rejections cannot turn a previously consumed valid proof into a retry.
    let (status, body) = session.get(VIEWER_PATH, Some(&correct)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "replay: {body}");
    let problem: arkret_wire::Problem = serde_json::from_value(body).expect("SDK replay Problem");
    assert_eq!(problem.status, 401);
    assert_eq!(problem.code(), "unauthenticated");

    // The grant remains usable with a new correctly bound proof.
    let fresh = session.headers("GET", VIEWER_PATH);
    let (status, body) = session.get(VIEWER_PATH, Some(&fresh)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let viewer: arkret_models_collaboration::account_operations::AccountView =
        serde_json::from_value(body).expect("SDK AccountView after mismatches");
    assert_eq!(viewer.principal_id, session.principal_id);
}
