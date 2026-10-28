//! Integration tests — `health` domain.
//!
//! Helpers live in [`super::common`]; pull them in via `use`.

use super::common::*;

#[test]
fn health_and_describe_work() {
    run_on_test_runtime("health_and_describe_work", health_and_describe_work_body);
}

async fn health_and_describe_work_body() {
    let mut home = TestClient::get("http://server/").send(&app()).await;
    assert_eq!(home.status_code.unwrap(), StatusCode::OK);
    let home_body = home.take_string().await.unwrap();
    assert!(home_body.contains("<h1>it works</h1>"));

    let health: Value = TestClient::get("http://server/health")
        .send(&app())
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(health["ok"], true);
    assert_eq!(health["checks"]["database"]["ok"], true);
    assert_eq!(health["checks"]["events"]["ok"], true);

    let readyz: Value = TestClient::get("http://server/readyz")
        .send(&app())
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(readyz["ok"], true);
    assert_eq!(readyz["checks"]["database"]["ok"], true);
    assert_eq!(readyz["checks"]["pq_hybrid_tls"]["ok"], true);

    let mut missing_selector = salvo::test::TestClient::get("http://server/_arkret/describe")
        .send(&app())
        .await;
    assert_eq!(missing_selector.status_code, Some(StatusCode::BAD_REQUEST));
    let missing_selector: Value = missing_selector.take_json().await.unwrap();
    assert_eq!(
        missing_selector["type"],
        "https://arkret.org/problems/operation_selector_required"
    );
    assert_eq!(missing_selector["status"], 400);

    let mut wrong_selector = salvo::test::TestClient::get("http://server/_arkret/describe")
        .add_header("Arkret-Operation", "not-a-registered-operation", true)
        .send(&app())
        .await;
    assert_eq!(
        wrong_selector.status_code,
        Some(StatusCode::UNPROCESSABLE_ENTITY)
    );
    let wrong_selector: Value = wrong_selector.take_json().await.unwrap();
    assert_eq!(
        wrong_selector["type"],
        "https://arkret.org/problems/unsupported_operation_version"
    );
    assert_eq!(wrong_selector["status"], 422);

    let mut describe_response = TestClient::get("http://server/_arkret/describe")
        .send(&app())
        .await;
    assert_eq!(describe_response.status_code, Some(StatusCode::OK));
    assert_eq!(
        describe_response
            .headers()
            .get("Arkret-Operation")
            .and_then(|value| value.to_str().ok()),
        Some("ak.server.read.describe.v1")
    );
    let describe: Value = describe_response.take_json().await.unwrap();
    assert_eq!(describe["protocol_version"], "1.0");
    assert_eq!(describe["service_kind"], "station");
    assert!(
        !describe["supported_profiles"]
            .as_array()
            .unwrap()
            .iter()
            .any(|profile| profile == "org.arkret.coland.profile.limited_server.v1")
    );

    let operator_describe: Value = TestClient::get("http://server/_coland/describe")
        .send(&app())
        .await
        .take_json()
        .await
        .unwrap();
    assert!(
        operator_describe["unsupported_profiles"]
            .as_array()
            .unwrap()
            .iter()
            .any(
                |profile| profile["profile"] == "org.arkret.coland.profile.limited_server.v1"
                    && profile["status"] == "unsupported"
            )
    );
    assert!(
        !describe["supported_profiles"]
            .as_array()
            .unwrap()
            .iter()
            .any(|profile| profile == "ak.reducer.core.v1")
    );
    assert!(describe.get("supported_reducer_profiles").is_none());
    assert_eq!(
        describe["limits"]["profile_status"]["conformance"],
        "limited_reference"
    );
    assert_eq!(
        describe["limits"]["registries"]["source"],
        "arkret-spec generated Rust descriptors"
    );
    assert_eq!(
        describe["limits"]["plaintext_visible_service_capability"]["supported"],
        true
    );
    assert!(
        describe["supported_profiles"]
            .as_array()
            .unwrap()
            .iter()
            .any(|profile| profile == "ak.profile.mimi_interop.v1")
    );
    assert!(
        describe["supported_profiles"]
            .as_array()
            .unwrap()
            .iter()
            .any(|profile| profile == "ak.profile.file_transfer.v1")
    );
    assert!(
        describe["supported_profiles"]
            .as_array()
            .unwrap()
            .iter()
            .any(|profile| profile == "ak.profile.webrtc_media.v1")
    );
    assert!(
        describe["supported_profiles"]
            .as_array()
            .unwrap()
            .iter()
            .any(|profile| profile == "ak.profile.media_service_binding.v1")
    );
    assert!(advertises_operation(
        &describe,
        "ak.open.mimi.command.submit_message.v1"
    ));
    assert!(advertises_operation(
        &describe,
        "ak.self.events.command.submit.v1"
    ));
    assert!(advertises_operation(
        &describe,
        "ak.self.blob.upload.create.v1"
    ));
    assert!(advertises_operation(
        &describe,
        "ak.self.keys.backups.resource.replace.v1"
    ));
    assert!(advertises_operation(
        &describe,
        "ak.self.circle.command.create.v1"
    ));
    for operation_id in [
        "ak.self.authz.read.check.v1",
        "ak.self.authz.grants.read.effective.v1",
        "ak.self.authz.invites.read.list.v1",
    ] {
        assert!(
            advertises_operation(&describe, operation_id),
            "describe must advertise authz_policy operation {operation_id}"
        );
    }
    assert_eq!(
        describe["limits"]["authz_policy"]["self_surface_status"],
        "standard_self_supported"
    );
    assert_eq!(
        describe["limits"]["authz_policy"]["authz_check"]["path"],
        "/_arkret/self/authz/check"
    );
    assert_eq!(
        describe["limits"]["authz_policy"]["authz_check"]["operation_specific_error_codes"],
        serde_json::json!([])
    );
    assert_eq!(
        describe["limits"]["authz_policy"]["effective_grants"]["path"],
        "/_arkret/self/authz/effective-grants"
    );
    assert_eq!(
        describe["limits"]["authz_policy"]["invites"]["response_schema_ref"],
        "schemas/authorization-operations.schema.json#/$defs/authorization_invite_page"
    );
    for bundle in describe["supported_operation_bundles"].as_array().unwrap() {
        let bundle = bundle.as_str().expect("bundle id string");
        assert!(
            arkret_wire::operation_bundle_descriptor(bundle).is_some(),
            "supported_operation_bundles must only advertise registered ids, got {bundle}"
        );
    }
    assert_eq!(
        describe["limits"]["profile_status"]["local_extension_operation_source"],
        "transport_registry+live_openapi"
    );
    assert!(
        describe["limits"]["profile_status"]["local_extension_operations"]
            .as_array()
            .unwrap()
            .iter()
            .any(|operation| operation == "org.arkret.coland.admin.actors.get")
    );
    assert!(
        describe["limits"]["profile_status"]["implemented_surfaces"]
            .as_array()
            .unwrap()
            .iter()
            .any(|surface| surface == "authz_policy")
    );
    assert!(
        describe["limits"]["profile_status"]["implemented_surfaces"]
            .as_array()
            .unwrap()
            .iter()
            .any(|surface| surface == "circle_management")
    );
    assert!(
        !describe["limits"]["profile_status"]["full_profiles_not_claimed"]
            .as_array()
            .unwrap()
            .iter()
            .any(|profile| profile == "ak.profile.index_node.v1")
    );
    assert!(
        describe["limits"]["profile_status"]["full_profiles_not_claimed"]
            .as_array()
            .unwrap()
            .iter()
            .any(|profile| profile == "ak.profile.directory_service.v1")
    );
    let limitation_areas = describe["limits"]["profile_status"]["limitations"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|limitation| limitation["area"].as_str())
        .collect::<Vec<_>>();
    assert!(!limitation_areas.contains(&"authz.describe"));
    assert!(limitation_areas.contains(&"authz.capability_engine_depth"));
    assert!(limitation_areas.contains(&"policies.describe"));
    assert!(limitation_areas.contains(&"admin.bottom.manual_repair"));
    assert!(limitation_areas.contains(&"index.query"));
    assert!(limitation_areas.contains(&"federation.outbound_push"));
    let federation_limitation = describe["limits"]["profile_status"]["limitations"]
        .as_array()
        .unwrap()
        .iter()
        .find(|limitation| limitation["area"] == "federation.outbound_push")
        .expect("federation outbound limitation should remain described");
    assert_eq!(federation_limitation["status"], "partial");
    assert!(
        federation_limitation["remaining"]
            .as_array()
            .unwrap()
            .iter()
            .any(|gap| gap == "RFC 9421 HTTP Message Signatures header emission")
    );
    let full_gap = describe["limits"]["profile_status"]["station_full_profile_gaps"]
        .as_array()
        .unwrap()
        .iter()
        .find(|gap| gap["profile"] == "ak.profile.station.v1")
        .expect("Station full-profile gap summary should be visible");
    assert_eq!(full_gap["status"], "not_claimed");
}

#[test]
fn server_describe_accepts_only_its_selected_role() {
    run_on_test_runtime(
        "server_describe_accepts_only_its_selected_role",
        server_describe_accepts_only_its_selected_role_body,
    );
}

async fn server_describe_accepts_only_its_selected_role_body() {
    let service = app_from_state(coland_test_support::app_state(test_config()));

    let selected: Value = TestClient::get("http://server/_arkret/describe?service_kind=station")
        .send(&service)
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(selected["service_kind"], "station");

    let mut rejected =
        TestClient::get("http://server/_arkret/describe?service_kind=identity_registry")
            .send(&service)
            .await;
    assert_eq!(rejected.status_code.unwrap().as_u16(), 400);
    let rejected: Value = rejected.take_json().await.unwrap();
    assert_eq!(problem_code(&rejected), "param_invalid");
}

#[test]
fn open_service_resolution_serves_byte_canonical_evidence() {
    run_on_test_runtime(
        "open_service_resolution_serves_byte_canonical_evidence",
        open_service_resolution_serves_byte_canonical_evidence_body,
    );
}

async fn open_service_resolution_serves_byte_canonical_evidence_body() {
    let state = coland_test_support::app_state(test_config());
    let service = app_from_state(state.clone());
    let service_id = arkret_identifiers::DidCoreId::new(state.service_id().to_owned()).unwrap();
    let path = arkret_models_identity::canonical_service_resolution_path(&service_id);

    let mut response = TestClient::get(format!("http://server{path}"))
        .send(&service)
        .await;
    assert_eq!(response.status_code, Some(StatusCode::OK));
    let body = response.take_string().await.unwrap();
    // Trust preflights pin and hash the exact wire bytes (service-surface.md),
    // so the body must already be byte-for-byte canonical — a declaration-order
    // `Json` rendering of the record is not a valid encoding here.
    let resolution: arkret_models_identity::AuthenticatedServiceResolution =
        arkret_canonical::canonical::from_canonical_json_slice(body.as_bytes())
            .expect("resolution response body must be byte-for-byte canonical JSON");
    assert_eq!(resolution.service_id.as_str(), state.service_id().as_str());
    let projection = resolution.projection().unwrap();
    let store = state.test_persistence();
    let now = chrono::Utc::now();
    for offset in [0, 601, 1801] {
        let verified_at = now + chrono::Duration::seconds(offset);
        let entry =
            arkret_models_identity::VerifiedServiceRoute::new(projection.clone(), verified_at);
        assert!(matches!(
            store
                .service_routes()
                .publish_route_cache(resolution.clone(), entry)
                .await
                .unwrap(),
            coland_storage::MonotonicRouteWrite::Applied
                | coland_storage::MonotonicRouteWrite::Replay
        ));
    }
    store
        .service_routes()
        .evict_route_cache(&service_id, "station")
        .await
        .unwrap();
    let durable = store
        .service_routes()
        .method_state(&service_id, "station")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(durable.method_history_head, projection.method_history_head);
    assert_eq!(durable.version_id, projection.version_id);
    let mut again = TestClient::get(format!("http://server{path}"))
        .send(&service)
        .await;
    assert_eq!(
        again.take_string().await.unwrap(),
        body,
        "refreshing an unchanged DID must not produce a new artifact"
    );
}

#[test]
fn readyz_returns_503_until_session_grant_internal_channel_is_complete() {
    run_on_test_runtime(
        "readyz_returns_503_until_session_grant_internal_channel_is_complete",
        readyz_returns_503_until_session_grant_internal_channel_is_complete_body,
    );
}

async fn readyz_returns_503_until_session_grant_internal_channel_is_complete_body() {
    let mut config = test_config();
    config.development_mode = false;
    config.session_grant_introspection_url =
        Some("https://coauth.example/_coauth/internal/session-grants/introspect".to_owned());
    // URL + bearer alone must not make the process ready: the unsigned
    // introspection path is unavailable until trust-domain and integrity
    // registration have also produced `internal_authority_channel`.
    config.internal_authority_shared_secret = Some("configured-but-insufficient".to_owned());
    config.internal_authority_channel = None;
    let service = app_from_state(coland_test_support::app_state(config));

    let mut response = TestClient::get("http://server/readyz").send(&service).await;
    assert_eq!(
        response.status_code.unwrap(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    let body: Value = response.take_json().await.unwrap();
    assert_eq!(body["ok"], false);
    assert_eq!(body["checks"]["session_grant_introspection"]["ok"], false);
}

#[test]
fn describe_separates_claim_levels() {
    run_on_test_runtime(
        "describe_separates_claim_levels",
        describe_separates_claim_levels_body,
    );
}

async fn describe_separates_claim_levels_body() {
    let describe: Value = TestClient::get("http://server/_arkret/describe")
        .send(&app())
        .await
        .take_json()
        .await
        .unwrap();

    assert_eq!(describe["development_mode"], true);

    let verified = describe["verified_profiles"]
        .as_array()
        .expect("verified_profiles array present");
    assert!(
        verified.is_empty(),
        "dev mode must not advertise any conformance_verified profile, got {verified:?}"
    );

    assert!(describe.get("claimed_profiles").is_none());
    assert!(
        !describe["supported_profiles"]
            .as_array()
            .unwrap()
            .is_empty()
    );

    let features = describe["supported_features"]
        .as_array()
        .expect("supported_features array present");
    assert!(!features.is_empty());
    assert!(features.iter().all(|feature| {
        feature
            .as_str()
            .is_some_and(|feature| arkret_wire::feature_descriptor(feature).is_some())
    }));

    let interop = describe["interop_surfaces"]
        .as_array()
        .expect("interop_surfaces array present");
    assert!(
        interop.is_empty(),
        "Coland product-private routes are not interop surfaces"
    );
    let _: arkret_models_discovery::ServiceDescribe = serde_json::from_value(describe)
        .expect("server describe must deserialize with the SDK client model");
}

#[test]
fn describe_returns_development_mode_field() {
    run_on_test_runtime(
        "describe_returns_development_mode_field",
        describe_returns_development_mode_field_body,
    );
}

async fn describe_returns_development_mode_field_body() {
    // Default test config — `development_mode = true`, no admin allowlist.
    let dev_app = app();

    let health: Value = TestClient::get("http://server/health")
        .send(&dev_app)
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(health["development_mode"], true);
    assert_eq!(health["proof_verifier_mode"], "production");
    assert_eq!(health["admin_auth_mode"], "development");

    let describe: Value = TestClient::get("http://server/_arkret/describe")
        .send(&dev_app)
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(describe["development_mode"], true);
    assert!(describe.get("proof_verifier_mode").is_none());
    assert!(describe.get("admin_auth_mode").is_none());

    let operator_describe: Value = TestClient::get("http://server/_coland/describe")
        .send(&dev_app)
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(operator_describe["proof_verifier_mode"], "production");
    assert_eq!(operator_describe["admin_auth_mode"], "development");

    // Now flip to production posture with an explicit admin allowlist to
    // make sure the derivation tracks the config — this is the production
    // shape codmin must NOT render a red banner for.
    let prod_config = AppConfig {
        development_mode: false,
        public_base_url: "https://server.example.com".to_owned(),
        admin_principal_ids: vec![
            arkret_identifiers::DidCoreId::new("ak:did_core:web:ops.example").unwrap(),
        ],
        to_device_queue_capacity: 10_000,
        ..test_config()
    };
    let prod_state = coland_test_support::app_state(prod_config);
    let prod_app = app_from_state(prod_state);

    let prod_health: Value = TestClient::get("http://server/health")
        .send(&prod_app)
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(prod_health["development_mode"], false);
    assert_eq!(prod_health["proof_verifier_mode"], "production");
    assert_eq!(prod_health["admin_auth_mode"], "principal_id_allowlist");

    let prod_describe: Value = TestClient::get("http://server/_arkret/describe")
        .send(&prod_app)
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(
        prod_describe["development_mode"], false,
        "production describe: {prod_describe}"
    );
    assert!(prod_describe.get("proof_verifier_mode").is_none());
    assert!(prod_describe.get("admin_auth_mode").is_none());

    let prod_operator_describe: Value = TestClient::get("http://server/_coland/describe")
        .send(&prod_app)
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(prod_operator_describe["proof_verifier_mode"], "production");
    assert_eq!(
        prod_operator_describe["admin_auth_mode"],
        "principal_id_allowlist"
    );
}

#[test]
fn healthz_exposes_hardening_status() {
    run_on_test_runtime(
        "healthz_exposes_hardening_status",
        healthz_exposes_hardening_status_body,
    );
}

async fn healthz_exposes_hardening_status_body() {
    let dev_app = app();

    let health: Value = TestClient::get("http://server/health")
        .send(&dev_app)
        .await
        .take_json()
        .await
        .unwrap();
    let hardening = &health["hardening"];
    assert!(hardening.is_object(), "hardening block must be present");
    assert_eq!(hardening["development_mode"], true);
    assert_eq!(hardening["rate_limit_enabled"], true);
    assert_eq!(hardening["admin_auth_mode"], "development");
    assert_eq!(hardening["pq_hybrid_tls_required_group"], "X25519MLKEM768");
    assert_eq!(
        hardening["pq_hybrid_tls_probe_artifact"],
        "deployment-probes.json#/probes/0"
    );
    assert!(hardening["pq_hybrid_tls_probe_verified"].is_boolean());
    let score = hardening["checklist_score"].as_u64().unwrap();
    let max = hardening["checklist_max"].as_u64().unwrap();
    assert!(max >= 8, "checklist_max should cover at least 8 fields");
    assert!(
        score < max,
        "dev test config must fail at least one check (got {score}/{max})"
    );
    let warnings = hardening["warnings"].as_array().unwrap();
    assert!(
        warnings
            .iter()
            .any(|w| w.as_str() == Some("development_mode_disabled")),
        "warnings must flag development_mode (got {warnings:?})"
    );

    // Production posture: flip dev mode off, configure an admin
    // allowlist + TLS + a CORS origin + an notary key. The score
    // should rise materially.
    let prod_config = AppConfig {
        development_mode: false,
        public_base_url: "https://server.example.com".to_owned(),
        admin_principal_ids: vec![
            arkret_identifiers::DidCoreId::new("ak:did_core:web:ops.example").unwrap(),
        ],
        to_device_queue_capacity: 10_000,
        tls_cert_path: Some(std::path::PathBuf::from("/etc/coland/tls.crt")),
        tls_key_path: Some(std::path::PathBuf::from("/etc/coland/tls.key")),
        cors_allow_origin: Some("https://app.example.com".to_owned()),
        notary_signing_key_seed: Some([7u8; 32]),
        seed_demo_data: false,
        ..test_config()
    };
    let prod_state = coland_test_support::app_state(prod_config);
    let prod_app = app_from_state(prod_state);

    let prod_health: Value = TestClient::get("http://server/health")
        .send(&prod_app)
        .await
        .take_json()
        .await
        .unwrap();
    let prod_hardening = &prod_health["hardening"];
    assert_eq!(prod_hardening["development_mode"], false);
    assert_eq!(prod_hardening["tls_enabled"], true);
    assert_eq!(prod_hardening["admin_auth_mode"], "principal_id_allowlist");
    assert_eq!(prod_hardening["csp_header_configured"], true);
    assert_eq!(prod_hardening["cors_strict"], true);
    assert_eq!(prod_hardening["secret_manager_in_use"], true);
    let prod_score = prod_hardening["checklist_score"].as_u64().unwrap();
    assert!(
        prod_score >= score + 4,
        "prod posture should clear several extra checks (dev={score} prod={prod_score})"
    );

    // /_coland/describe keeps the coland-local operator posture fields.
    let describe: Value = TestClient::get("http://server/_coland/describe")
        .send(&prod_app)
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(
        describe["hardening"]["development_mode"], false,
        "operator describe: {describe}"
    );
}
