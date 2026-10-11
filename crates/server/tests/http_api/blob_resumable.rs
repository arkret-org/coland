//! Integration tests — resumable (tus 1.0.0) blob upload binding.
//!
//! Spec: crypto-media/media-and-blob.md §2.1. Covers the OPTIONS probe,
//! the chunked create → PATCH → HEAD → finalize strand (asserting the
//! content-addressing invariant against the canonical single-shot
//! upload), offset conflicts, incomplete finalize, version negotiation
//! and cross-actor isolation.

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use serde_json::json;

use super::common::*;

fn b64(value: &str) -> String {
    BASE64_STANDARD.encode(value.as_bytes())
}

#[test]
fn tus_requires_and_freezes_storage_encryption_until_finalize() {
    run_on_test_runtime(
        "tus_requires_and_freezes_storage_encryption_until_finalize",
        tus_requires_and_freezes_storage_encryption_until_finalize_body,
    );
}

async fn tus_requires_and_freezes_storage_encryption_until_finalize_body() {
    let state = coland_test_support::app_state(test_config());
    let token = dev_token(state.clone()).await;
    for metadata in [
        None,
        Some(format!("purpose {}", b64("file_transfer"))),
        Some(format!("encryption {}", b64("{}"))),
        Some(format!("encryption {}", b64(r#"{"scheme":"unknown"}"#))),
        Some(format!(
            "encryption {}",
            b64(r#"{"scheme":"ak.blob.stream_aead.v1","key_ref":"secret"}"#)
        )),
        Some(format!(
            "encryption {},filename {}",
            b64("null"),
            b64("private.txt")
        )),
    ] {
        let mut request = TestClient::post("http://server/_arkret/self/blob/resumable")
            .add_header("authorization", format!("Bearer {token}"), true)
            .add_header("tus-resumable", "1.0.0", true)
            .add_header("upload-length", "15", true);
        if let Some(metadata) = metadata {
            request = request.add_header("upload-metadata", metadata, true);
        }
        let response = request.send(&app_from_state(state.clone())).await;
        assert_eq!(response.status_code.unwrap().as_u16(), 422);
    }
    let scheme = r#"{"scheme":"ak.blob.stream_aead.v1"}"#;
    let create = TestClient::post("http://server/_arkret/self/blob/resumable")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("tus-resumable", "1.0.0", true)
        .add_header("upload-length", "15", true)
        .add_header(
            "upload-metadata",
            format!("encryption {}", b64(scheme)),
            true,
        )
        .add_header("content-type", "application/offset+octet-stream", true)
        .body(b"encrypted bytes".to_vec())
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(create.status_code.unwrap().as_u16(), 201);
    let location = create.headers.get("location").unwrap().to_str().unwrap();
    let url = format!("http://server{location}");
    let override_attempt = TestClient::patch(&url)
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("tus-resumable", "1.0.0", true)
        .add_header("upload-offset", "15", true)
        .add_header("content-type", "application/offset+octet-stream", true)
        .add_header(
            "upload-metadata",
            format!("encryption {}", b64("null")),
            true,
        )
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(override_attempt.status_code.unwrap().as_u16(), 422);
    let mut finalized = TestClient::post(format!("{url}/finalize"))
        .add_header("authorization", format!("Bearer {token}"), true)
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(finalized.status_code.unwrap().as_u16(), 200);
    let outcome: Value = finalized.take_json().await.unwrap();
    let blob = state
        .test_persistence()
        .blobs()
        .get(outcome["blob_ref"].as_str().unwrap())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        serde_json::to_value(blob.encryption).unwrap(),
        serde_json::from_str::<Value>(scheme).unwrap()
    );
    let retry = TestClient::post("http://server/_arkret/self/blob/resumable")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("tus-resumable", "1.0.0", true)
        .add_header("upload-length", "15", true)
        .add_header(
            "upload-metadata",
            format!("encryption {}", b64("null")),
            true,
        )
        .add_header("content-type", "application/offset+octet-stream", true)
        .body(b"encrypted bytes".to_vec())
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(retry.status_code.unwrap().as_u16(), 201);
    let retry_location = retry.headers.get("location").unwrap().to_str().unwrap();
    let mut rejected = TestClient::post(format!("http://server{retry_location}/finalize"))
        .add_header("authorization", format!("Bearer {token}"), true)
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(rejected.status_code.unwrap().as_u16(), 409);
    let rejected: Value = rejected.take_json().await.unwrap();
    assert_eq!(problem_code(&rejected), "failed_precondition");
    assert_eq!(
        state
            .test_persistence()
            .blobs()
            .get(outcome["blob_ref"].as_str().unwrap())
            .await
            .unwrap()
            .unwrap()
            .encryption,
        blob.encryption
    );
    let mut presign = TestClient::post("http://server/_arkret/self/blob/presign")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("content-type", "application/json", true)
        .body(json!({"blob_ref":outcome["blob_ref"],"purpose":"media_inline"}).to_string())
        .send(&app_from_state(state))
        .await;
    assert_eq!(presign.status_code.unwrap().as_u16(), 403);
    let denied: Value = presign.take_json().await.unwrap();
    assert_eq!(problem_code(&denied), "capability_denied");
}

#[test]
fn tus_options_probe_advertises_capabilities_without_auth() {
    run_on_test_runtime(
        "tus_options_probe_advertises_capabilities_without_auth",
        tus_options_probe_advertises_capabilities_without_auth_body,
    );
}

async fn tus_options_probe_advertises_capabilities_without_auth_body() {
    let state = coland_test_support::app_state(test_config());
    let response = TestClient::options("http://server/_arkret/self/blob/resumable")
        .send(&app_from_state(state))
        .await;
    assert_eq!(response.status_code.unwrap().as_u16(), 204);
    let headers = &response.headers;
    assert_eq!(headers.get("tus-resumable").unwrap(), "1.0.0");
    assert_eq!(headers.get("tus-version").unwrap(), "1.0.0");
    let extensions = headers.get("tus-extension").unwrap().to_str().unwrap();
    assert!(extensions.contains("creation"));
    assert!(extensions.contains("creation-with-upload"));
    assert!(extensions.contains("termination"));
    assert!(extensions.contains("expiration"));
    assert_eq!(
        headers.get("tus-max-size").unwrap().to_str().unwrap(),
        (10 * 1024 * 1024).to_string()
    );
}

#[test]
fn tus_create_requires_supported_version_and_auth() {
    run_on_test_runtime(
        "tus_create_requires_supported_version_and_auth",
        tus_create_requires_supported_version_and_auth_body,
    );
}

async fn tus_create_requires_supported_version_and_auth_body() {
    let state = coland_test_support::app_state(test_config());
    let token = dev_token(state.clone()).await;

    // No bearer — 401 before any tus processing.
    let unauthenticated = TestClient::post("http://server/_arkret/self/blob/resumable")
        .add_header("tus-resumable", "1.0.0", true)
        .add_header("upload-length", "4", true)
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(unauthenticated.status_code.unwrap().as_u16(), 401);

    // Wrong protocol version — 412 + Tus-Version per tus core.
    let wrong_version = TestClient::post("http://server/_arkret/self/blob/resumable")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("tus-resumable", "0.2.2", true)
        .add_header("upload-length", "4", true)
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(wrong_version.status_code.unwrap().as_u16(), 412);
    assert_eq!(wrong_version.headers.get("tus-version").unwrap(), "1.0.0");
}

#[test]
fn resumable_chunked_upload_matches_canonical_blob_ref() {
    run_on_test_runtime(
        "resumable_chunked_upload_matches_canonical_blob_ref",
        resumable_chunked_upload_matches_canonical_blob_ref_body,
    );
}

async fn resumable_chunked_upload_matches_canonical_blob_ref_body() {
    let state = coland_test_support::app_state(test_config());
    let token = dev_token(state.clone()).await;

    let payload = b"resumable-file-transfer-ciphertext-bytes".to_vec();
    let expected_digest = format!("sha256:{}", hex::encode(Sha256::digest(&payload)));
    let (head, tail) = payload.split_at(16);

    // Create the upload resource with `blob_upload_request_body` metadata.
    let metadata = format!(
        "encryption {},content_digest {}",
        b64("null"),
        b64(&expected_digest)
    );
    let create = TestClient::post("http://server/_arkret/self/blob/resumable")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("tus-resumable", "1.0.0", true)
        .add_header("upload-length", payload.len().to_string(), true)
        .add_header("upload-metadata", metadata, true)
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(create.status_code.unwrap().as_u16(), 201);
    assert_eq!(create.headers.get("tus-resumable").unwrap(), "1.0.0");
    assert!(create.headers.get("upload-expires").is_some());
    let location = create
        .headers
        .get("location")
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    assert!(location.starts_with("/_arkret/self/blob/resumable/"));
    let upload_url = format!("http://server{location}");

    // First chunk at offset 0.
    let patch1 = TestClient::patch(&upload_url)
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("tus-resumable", "1.0.0", true)
        .add_header("content-type", "application/offset+octet-stream", true)
        .add_header("upload-offset", "0", true)
        .body(head.to_vec())
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(patch1.status_code.unwrap().as_u16(), 204);
    assert_eq!(
        patch1
            .headers
            .get("upload-offset")
            .unwrap()
            .to_str()
            .unwrap(),
        head.len().to_string()
    );

    // Interrupted-client resume: HEAD reports the committed offset.
    let probe = TestClient::head(&upload_url)
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("tus-resumable", "1.0.0", true)
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(probe.status_code.unwrap().as_u16(), 200);
    assert_eq!(
        probe
            .headers
            .get("upload-offset")
            .unwrap()
            .to_str()
            .unwrap(),
        head.len().to_string()
    );
    assert_eq!(
        probe
            .headers
            .get("upload-length")
            .unwrap()
            .to_str()
            .unwrap(),
        payload.len().to_string()
    );
    assert_eq!(probe.headers.get("cache-control").unwrap(), "no-store");

    // Stale offset answers 409 so the client re-syncs.
    let stale = TestClient::patch(&upload_url)
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("tus-resumable", "1.0.0", true)
        .add_header("content-type", "application/offset+octet-stream", true)
        .add_header("upload-offset", "0", true)
        .body(tail.to_vec())
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(stale.status_code.unwrap().as_u16(), 409);

    // Finalize before completion answers 409.
    let premature = TestClient::post(format!("{upload_url}/finalize"))
        .add_header("authorization", format!("Bearer {token}"), true)
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(premature.status_code.unwrap().as_u16(), 409);

    // Remaining chunk at the committed offset.
    let patch2 = TestClient::patch(&upload_url)
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("tus-resumable", "1.0.0", true)
        .add_header("content-type", "application/offset+octet-stream", true)
        .add_header("upload-offset", head.len().to_string(), true)
        .body(tail.to_vec())
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(patch2.status_code.unwrap().as_u16(), 204);

    // Finalize → canonical blob outcome.
    let outcome: Value = TestClient::post(format!("{upload_url}/finalize"))
        .add_header("authorization", format!("Bearer {token}"), true)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(outcome["blob_ref"], format!("ak:blob:{expected_digest}"));
    assert_eq!(outcome["media_type"], "application/octet-stream");
    assert_eq!(outcome["size_bytes"], payload.len());
    assert_eq!(outcome["upload_receipt"]["blob_ref"], outcome["blob_ref"]);
    assert!(outcome["upload_receipt"].get("purpose").is_none());
    assert!(outcome["upload_receipt"].get("upload_binding").is_none());
    assert!(
        outcome["upload_receipt"]
            .get("encrypted_attachment")
            .is_none()
    );
    let stored_resumable_blob = state
        .test_persistence()
        .blobs()
        .get(outcome["blob_ref"].as_str().unwrap())
        .await
        .unwrap()
        .expect("finalized resumable blob metadata is stored");
    // The creation-time null classification is retained through finalize.
    assert!(stored_resumable_blob.encryption.is_none());
    assert!(stored_resumable_blob.filename.is_none());

    // Content-addressing invariant (spec §2.1): the resumable path MUST
    // produce the same blob_ref the canonical single-shot upload yields
    // for the same bytes.
    let (canonical_content_type, canonical_body) =
        multipart_blob_upload_body(&payload, "application/octet-stream");
    let canonical: Value = TestClient::post("http://server/_arkret/self/blob/upload")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("content-type", canonical_content_type, true)
        .body(canonical_body)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(outcome["blob_ref"], canonical["blob_ref"]);
    assert_eq!(outcome["content_digest"], canonical["content_digest"]);

    // Staged part is consumed — the resource answers 404 afterwards.
    let after = TestClient::head(&upload_url)
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("tus-resumable", "1.0.0", true)
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(after.status_code.unwrap().as_u16(), 404);
}

#[test]
fn resumable_upload_is_actor_scoped_and_terminable() {
    run_on_test_runtime(
        "resumable_upload_is_actor_scoped_and_terminable",
        resumable_upload_is_actor_scoped_and_terminable_body,
    );
}

async fn resumable_upload_is_actor_scoped_and_terminable_body() {
    let state = coland_test_support::app_state(test_config());
    let alice = dev_token(state.clone()).await;
    let bob = dev_token_for_device(
        state.clone(),
        "did:web:bob.example",
        "ak:device:01904100-0000-7000-8000-b0b000000001",
        "Bob Laptop",
    )
    .await;

    let create = TestClient::post("http://server/_arkret/self/blob/resumable")
        .add_header("authorization", format!("Bearer {alice}"), true)
        .add_header("tus-resumable", "1.0.0", true)
        .add_header("upload-length", "8", true)
        .add_header(
            "upload-metadata",
            format!("encryption {}", b64("null")),
            true,
        )
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(create.status_code.unwrap().as_u16(), 201);
    let location = create
        .headers
        .get("location")
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    let upload_url = format!("http://server{location}");

    // Foreign actor sees 404 — indistinguishable from a missing resource.
    let foreign = TestClient::head(&upload_url)
        .add_header("authorization", format!("Bearer {bob}"), true)
        .add_header("tus-resumable", "1.0.0", true)
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(foreign.status_code.unwrap().as_u16(), 404);

    // Owner terminates; the resource is gone afterwards.
    let terminate = TestClient::delete(&upload_url)
        .add_header("authorization", format!("Bearer {alice}"), true)
        .add_header("tus-resumable", "1.0.0", true)
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(terminate.status_code.unwrap().as_u16(), 204);
    let after = TestClient::head(&upload_url)
        .add_header("authorization", format!("Bearer {alice}"), true)
        .add_header("tus-resumable", "1.0.0", true)
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(after.status_code.unwrap().as_u16(), 404);
}

#[test]
fn describe_advertises_tus_binding_and_limits() {
    run_on_test_runtime(
        "describe_advertises_tus_binding_and_limits",
        describe_advertises_tus_binding_and_limits_body,
    );
}

async fn describe_advertises_tus_binding_and_limits_body() {
    let state = coland_test_support::app_state(test_config());
    let describe: Value = TestClient::get("http://server/_arkret/describe")
        .send(&app_from_state(state))
        .await
        .take_json()
        .await
        .unwrap();
    assert!(
        describe["supported_features"]
            .as_array()
            .unwrap()
            .contains(&Value::String(
                "ak.feature.blob.resumable_upload.tus.v1".to_owned()
            ))
    );
    let tus_binding = describe["transport_bindings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|binding| binding["kind"] == "tus")
        .expect("tus binding advertised");
    assert_eq!(
        tus_binding["base_url"],
        "https://server.test/_arkret/self/blob/resumable"
    );
    assert!(tus_binding.get("operations").is_none());
    assert!(tus_binding["extension_profile_required"].is_null());
    assert_eq!(tus_binding["tus_version"], serde_json::json!(["1.0.0"]));
    assert_eq!(
        describe["limits"]["resumable_upload_incomplete_ttl_seconds"],
        86_400
    );
    assert_eq!(
        describe["limits"]["resumable_upload_max_bytes"],
        10 * 1024 * 1024
    );
}
