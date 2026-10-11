use serde_json::json;

#[tokio::test]
async fn bot_and_ghost_routes_refuse_unsigned_and_bearer_only_requests() {
    use salvo::test::ResponseExt as _;

    // No state is injected: authentication must reject before any storage access.
    let service = salvo::Service::new(super::protocol_router());
    let applet = "ak:applet:01904100-0000-7000-8000-000000000001";
    for operation in [
        "bots/provision/preview",
        "bots/provision",
        "ghosts/provision/preview",
        "ghosts/provision",
    ] {
        for bearer in [false, true] {
            let request = salvo::test::TestClient::post(format!(
                "http://server/self/applets/{applet}/{operation}"
            ))
            .json(&json!({}));
            let request = if bearer {
                request.add_header("authorization", "Bearer not-service-authority", true)
            } else {
                request
            };
            let mut response = request.send(&service).await;
            assert_eq!(
                response.status_code,
                Some(salvo::http::StatusCode::UNAUTHORIZED),
                "{operation}, bearer={bearer}"
            );
            let body = response.take_string().await.unwrap();
            assert!(
                body.contains("http_signature_required"),
                "{operation}: {body}"
            );
        }
    }
}

use super::signature::{
    applet_delivery_authentication_record_digest, applet_validate_signature_input,
};

fn params(created: i64, expires: i64) -> String {
    format!(
        "(\"@method\" \"@target-uri\" \"@authority\" \"content-digest\" \
         \"source-service-id\" \"destination-service-id\" \"idempotency-key\");\
         created={created};expires={expires};keyid=\"did:web:app#applet-service-key\";\
         alg=\"ed25519\""
    )
}

/// COT-03-001: the §7.3.1 content-digest helper MUST emit the RFC 9421
/// `sha-256=:<base64>:` structured form, not the `sha256:<hex>` digest.
#[test]
fn content_digest_header_is_rfc9421_structured() {
    let header = crate::routing::federation::rfc9530_content_digest(b"{}");
    assert!(header.starts_with("sha-256=:"));
    assert!(header.ends_with(':'));
    assert!(!header.contains("sha256:"));
}

/// keyid mismatch is `http_signature_invalid` (not a window error).
#[test]
fn keyid_mismatch_is_invalid_signature() {
    let now = chrono::Utc::now().timestamp();
    let input = arkret_signatures::http_signature::parse_signature_input(&format!(
        "sig1={}",
        params(now, now + 60)
    ))
    .unwrap();
    let err = applet_validate_signature_input(&input, "did:web:other#applet-service-key")
        .expect_err("keyid mismatch must fail");
    assert_eq!(
        err.code,
        coland_http::error::ErrorCode::HttpSignatureInvalid
    );
}

#[test]
fn delivery_authentication_record_digest_binds_closed_verified_material() {
    let key = ed25519_dalek::SigningKey::from_bytes(&[7; 32]).verifying_key();
    let rotated_key = ed25519_dalek::SigningKey::from_bytes(&[8; 32]).verifying_key();
    let input = arkret_signatures::http_signature::parse_signature_input(&format!(
        "sig1={}",
        params(1, 60)
    ))
    .unwrap();
    let digest = |epoch: &str, key: &ed25519_dalek::VerifyingKey| {
        applet_delivery_authentication_record_digest(
            "ak:did_core:web:app",
            "ak:did_core:web:edge",
            "idem-1",
            "sha-256=:abc=:",
            "did:web:app#applet-service-key",
            epoch,
            key,
            &input,
        )
        .unwrap()
    };
    let epoch = "sha256:2222222222222222222222222222222222222222222222222222222222222222";
    let (actual_record, base) = digest(epoch, &key);
    let epoch_rotated = digest(
        "sha256:3333333333333333333333333333333333333333333333333333333333333333",
        &key,
    );
    let key_rotated = digest(epoch, &rotated_key);
    assert_ne!(base, epoch_rotated.1);
    assert_ne!(base, key_rotated.1);

    let record = json!({
        "operation_id": "ak.edge.applet.command.transaction.v1",
        "direction": "applet_to_arkret_inbound",
        "source_id": "ak:did_core:web:app",
        "destination_id": "ak:did_core:web:edge",
        "signature_label": "sig1",
        "verification_method": "did:web:app#applet-service-key",
        "verification_key_digest": arkret_canonical::sha256_digest(key.to_bytes()),
        "signature_algorithm": "ed25519",
        "registration_epoch": epoch,
        "idempotency_key": "idem-1",
        "content_digest": "sha-256=:abc=:",
        "covered_components": input.covered_components.iter().map(|component| component.canonical_name()).collect::<Vec<_>>(),
        "created": 1,
        "expires": 60,
    });
    assert_eq!(actual_record, record);
    let mut stable = record.clone();
    stable.as_object_mut().unwrap().remove("created");
    stable.as_object_mut().unwrap().remove("expires");
    let bytes = arkret_canonical::canonical_json_bytes(&stable).unwrap();
    assert_eq!(
        base,
        arkret_canonical::sha256_digest_from_slices(&[
            b"ak.applet.delivery_authentication_record.v1\n",
            &bytes,
        ])
    );
}

#[test]
fn refreshed_delivery_time_keeps_stable_binding_after_independent_authentication() {
    let key = ed25519_dalek::SigningKey::from_bytes(&[7; 32]).verifying_key();
    let epoch = format!("sha256:{}", "a".repeat(64));
    let binding = |created, expires| {
        let input = arkret_signatures::http_signature::parse_signature_input(&format!(
            "sig1={}",
            params(created, expires)
        ))
        .unwrap();
        applet_delivery_authentication_record_digest(
            "ak:did_core:web:app",
            "ak:did_core:web:edge",
            "retry-1",
            "sha-256=:abc=:",
            "did:web:app#applet-service-key",
            &epoch,
            &key,
            &input,
        )
        .unwrap()
    };
    let first = binding(1, 60);
    let retry = binding(61, 120);
    assert_ne!(first.0, retry.0);
    assert_eq!(first.1, retry.1);
}
