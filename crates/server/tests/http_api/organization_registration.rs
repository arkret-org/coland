use std::sync::Arc;

use arkret_models_identity::{
    OrganizationRegistrationChallenge, OrganizationRegistrationEnsureRequestBody,
    OrganizationRegistrationRefreshRequestBody, OrganizationRegistrationResponseBody,
    OrganizationRegistrationRevokeRequestBody, OrganizationRegistrationScope,
    OrganizationRegistrationStatus,
};
use coland_services::organization_registration::OrganizationRegistrationService;
use parking_lot::RwLock;
use salvo::test::ResponseExt;

use super::common::*;
#[path = "../support/organization_registration.rs"]
mod registration_fixture;
use registration_fixture::*;

#[test]
fn organization_registration_http_round_trip_and_get_are_non_enumerable() {
    run_on_test_runtime(
        "organization_registration_http_round_trip_and_get_are_non_enumerable",
        organization_registration_http_round_trip_and_get_are_non_enumerable_body,
    );
}

async fn organization_registration_http_round_trip_and_get_are_non_enumerable_body() {
    let mut config = test_config();
    config.admin_principal_ids = vec![fixture_actor_core_id("did:web:alice.example")];
    let mut state = coland_test_support::app_state(config);
    let persistence = state.test_persistence();
    let (organization_id, did, admin_id, pinned, control_signer) = organization_fixture();
    state.test_set_organization_registration_service(
        OrganizationRegistrationService::with_resolver(
            persistence,
            Arc::new(StaticOrganizationResolver {
                state: RwLock::new(pinned.clone()),
            }),
        ),
    );
    let alice_token = dev_token(state.clone()).await;
    let bob_token = dev_token_for_device(
        state.clone(),
        "did:web:bob.example",
        "ak:device:01904100-0000-7000-8000-b0b000000001",
        "Bob Desktop",
    )
    .await;
    let app = app_from_state(state);

    let openapi: serde_json::Value =
        TestClient::get("http://server/.well-known/arkret/openapi.json")
            .send(&app)
            .await
            .take_json()
            .await
            .unwrap();
    for (path, method, operation_id) in [
        (
            "/_arkret/root/identity/organization-registrations:prepare",
            "post",
            "ak.root.identity.organization_registration.command.prepare",
        ),
        (
            "/_arkret/root/identity/organization-registrations:ensure",
            "post",
            "ak.root.identity.organization_registration.command.ensure",
        ),
        (
            "/_arkret/root/identity/organization-registrations",
            "get",
            "ak.root.identity.organization_registration.resource.get",
        ),
        (
            "/_arkret/root/identity/organization-registrations:refresh",
            "post",
            "ak.root.identity.organization_registration.command.refresh",
        ),
        (
            "/_arkret/root/identity/organization-registrations:revoke",
            "post",
            "ak.root.identity.organization_registration.command.revoke",
        ),
    ] {
        assert_eq!(
            openapi["paths"][path][method]["operationId"],
            serde_json::Value::String(operation_id.to_owned())
        );
    }

    let mut unsupported_scope =
        TestClient::post("http://server/_arkret/root/identity/organization-registrations:prepare")
            .add_header("authorization", format!("Bearer {alice_token}"), true)
            .add_header("content-type", "application/json", true)
            .body(canonical_body(&serde_json::json!({
                "organization_id": organization_id,
                "organization_did": did,
                "local_admin_subject_id": admin_id,
                "requested_scopes": ["organization_unregistered_scope"],
            })))
            .send(&app)
            .await;
    let unsupported_scope_body: serde_json::Value = unsupported_scope.take_json().await.unwrap();
    assert_eq!(
        unsupported_scope_body["status"], 422,
        "{unsupported_scope_body}"
    );
    assert_eq!(
        unsupported_scope_body["type"],
        "https://arkret.org/problems/unsupported_organization_registration_scope"
    );

    let mut challenge_response =
        TestClient::post("http://server/_arkret/root/identity/organization-registrations:prepare")
            .add_header("authorization", format!("Bearer {alice_token}"), true)
            .add_header("content-type", "application/json", true)
            .body(canonical_body(&serde_json::json!({
                "organization_id": organization_id,
                "organization_did": did,
                "local_admin_subject_id": admin_id,
                "requested_scopes": ["organization_profile_manage"],
            })))
            .send(&app)
            .await;
    let challenge_status = challenge_response.status_code;
    let challenge_body: serde_json::Value = challenge_response.take_json().await.unwrap();
    let challenge: OrganizationRegistrationChallenge =
        serde_json::from_value(challenge_body.clone()).unwrap_or_else(|error| {
            panic!("challenge status {challenge_status:?}: {challenge_body}: {error}")
        });
    let ensure = OrganizationRegistrationEnsureRequestBody {
        organization_id: organization_id.clone(),
        organization_did: did.clone(),
        challenge_id: challenge.challenge_id.clone(),
        version_id: pinned.version_id.clone(),
        log_head_digest: pinned.log_head_digest.clone(),
        control_proof: signed_control_proof(&challenge, &pinned, &control_signer),
        local_admin_subject_id: admin_id.clone(),
        requested_scopes: vec![OrganizationRegistrationScope::OrganizationProfileManage],
        handle_attestation: None,
    };
    let outcome: OrganizationRegistrationResponseBody =
        TestClient::post("http://server/_arkret/root/identity/organization-registrations:ensure")
            .add_header("authorization", format!("Bearer {alice_token}"), true)
            .add_header("content-type", "application/json", true)
            .body(canonical_body(&ensure))
            .send(&app)
            .await
            .take_json()
            .await
            .unwrap();
    assert!(outcome.created);
    assert_eq!(outcome.registration_generation(), 1);
    outcome.validate().unwrap();

    let visible: OrganizationRegistrationResponseBody = TestClient::get(format!(
        "http://server/_arkret/root/identity/organization-registrations?organization_id={organization_id}"
    ))
    .add_header(
        "authorization",
        format!("Bearer {alice_token}"),
        true,
    )
    .send(&app)
    .await
    .take_json()
    .await
    .unwrap();
    assert!(!visible.created);

    let refresh_challenge: OrganizationRegistrationChallenge =
        TestClient::post("http://server/_arkret/root/identity/organization-registrations:prepare")
            .add_header("authorization", format!("Bearer {alice_token}"), true)
            .add_header("content-type", "application/json", true)
            .body(canonical_body(&serde_json::json!({
                "organization_id": organization_id,
                "organization_did": did,
                "local_admin_subject_id": admin_id,
                "requested_scopes": ["organization_profile_manage"],
            })))
            .send(&app)
            .await
            .take_json()
            .await
            .unwrap();
    let refreshed: OrganizationRegistrationResponseBody =
        TestClient::post("http://server/_arkret/root/identity/organization-registrations:refresh")
            .add_header("authorization", format!("Bearer {alice_token}"), true)
            .add_header("content-type", "application/json", true)
            .body(canonical_body(
                &OrganizationRegistrationRefreshRequestBody {
                    organization_id: organization_id.clone(),
                    organization_did: did.clone(),
                    challenge_id: refresh_challenge.challenge_id.clone(),
                    version_id: pinned.version_id.clone(),
                    log_head_digest: pinned.log_head_digest.clone(),
                    control_proof: signed_control_proof(
                        &refresh_challenge,
                        &pinned,
                        &control_signer,
                    ),
                },
            ))
            .send(&app)
            .await
            .take_json()
            .await
            .unwrap();
    assert_eq!(refreshed.registration_generation(), 1);
    assert_eq!(
        refreshed.registration_receipt.status,
        OrganizationRegistrationStatus::Active
    );

    let revoked: OrganizationRegistrationResponseBody =
        TestClient::post("http://server/_arkret/root/identity/organization-registrations:revoke")
            .add_header("authorization", format!("Bearer {alice_token}"), true)
            .add_header("content-type", "application/json", true)
            .body(canonical_body(&OrganizationRegistrationRevokeRequestBody {
                organization_id: organization_id.clone(),
                reason_code: None,
            }))
            .send(&app)
            .await
            .take_json()
            .await
            .unwrap();
    assert_eq!(revoked.registration_generation(), 1);
    assert_eq!(
        revoked.registration_receipt.status,
        OrganizationRegistrationStatus::Revoked
    );

    let mut unauthorized = TestClient::get(format!(
        "http://server/_arkret/root/identity/organization-registrations?organization_id={organization_id}"
    ))
    .add_header("authorization", format!("Bearer {bob_token}"), true)
    .send(&app)
    .await;
    assert_eq!(unauthorized.status_code.unwrap(), StatusCode::NOT_FOUND);
    let unauthorized_body: serde_json::Value = unauthorized.take_json().await.unwrap();

    let mut absent = TestClient::get(
        "http://server/_arkret/root/identity/organization-registrations?organization_id=ak:did_core:webvh:z6mkfixtureabsentexample",
    )
    .add_header("authorization", format!("Bearer {bob_token}"), true)
    .send(&app)
    .await;
    assert_eq!(absent.status_code.unwrap(), StatusCode::NOT_FOUND);
    let absent_body: serde_json::Value = absent.take_json().await.unwrap();
    assert_eq!(
        unauthorized_body["type"],
        "https://arkret.org/problems/did_not_found"
    );
    assert_eq!(unauthorized_body["type"], absent_body["type"]);
    assert_eq!(unauthorized_body["detail"], absent_body["detail"]);
}

fn canonical_body(value: &impl serde::Serialize) -> Vec<u8> {
    arkret_canonical::canonical_json_bytes(value).unwrap()
}
