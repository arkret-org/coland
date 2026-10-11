use coland_http::error::AppError;

use super::*;

const FEDERATION_AUTH_FAILURE_MESSAGE_FOR_TEST: &str = "federation request authentication failed";

fn trust_domain(value: &str) -> arkret_identifiers::TrustDomainId {
    arkret_identifiers::TrustDomainId::new(value.to_owned()).unwrap()
}

fn federation_headers() -> FederationTrustHeaders {
    FederationTrustHeaders {
        source_trust_domain: trust_domain("ak:trust_domain:peer.example"),
        destination_trust_domain: trust_domain("ak:trust_domain:coland.local"),
    }
}

#[test]
fn federation_headers_accept_destination_match() {
    validate_federation_headers(
        &federation_headers(),
        &trust_domain("ak:trust_domain:coland.local"),
    )
    .expect("matching destination accepted");
}

#[test]
fn verify_actor_headers_reject_destination_mismatch() {
    let error = validate_federation_headers(
        &federation_headers(),
        &trust_domain("ak:trust_domain:other.example"),
    )
    .expect_err("wrong destination rejected");

    assert_auth_rejection_is_minimal(error);
}

const SIG_TEST_DID: &str = "did:webvh:z6mkfixture:test.local";
const SIG_TEST_CORE_ID: &str = "ak:did_core:webvh:z6mkfixture";

fn signature_input(
    service_did: &str,
    fragment: &str,
) -> arkret_signatures::http_signature::SignatureInput {
    let now = chrono::Utc::now().timestamp();
    let header = format!(
        "sig1=(\"@method\");created={now};expires={};keyid=\"{service_did}#{fragment}\";alg=\"ed25519\"",
        now + 120
    );
    arkret_signatures::http_signature::parse_signature_input(&header).unwrap()
}

#[test]
fn signature_input_accepts_expected_federation_key() {
    validate_signature_input(
        &signature_input(SIG_TEST_DID, "federation-fanout-key"),
        SIG_TEST_CORE_ID,
        "test",
    )
    .expect("matching federation key must pass deployment binding");
}

#[test]
fn signature_input_accepts_other_controller_owned_service_key() {
    validate_signature_input(
        &signature_input(SIG_TEST_DID, "service-key"),
        SIG_TEST_CORE_ID,
        "test",
    )
    .expect("a controller-owned service verification method must be accepted");
}

#[test]
fn signature_input_rejects_mismatched_federation_key() {
    let error = validate_signature_input(
        &signature_input("did:webvh:z6mkother:other.local", "service-key"),
        SIG_TEST_CORE_ID,
        "test",
    )
    .expect_err("mismatched federation key must fail closed");
    assert_auth_rejection_is_minimal(error);
}

fn assert_auth_rejection_is_minimal(error: AppError) {
    assert_eq!(error.code, coland_http::error::ErrorCode::Unauthenticated);
    assert_eq!(error.wire_code(), "unauthenticated");
    assert_eq!(error.http_status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        error.message.as_ref(),
        FEDERATION_AUTH_FAILURE_MESSAGE_FOR_TEST
    );
}
