//! Blob upload + download handlers.
//!
//! Surfaces:
//! - `POST /_arkret/self/blob/upload`         — `ak.self.blob.upload.create.v1`: the closed
//!   `blob-operations.schema.json#/$defs/blob_upload_request_body` carried as `multipart/form-data`
//!   parts (and nowhere else), normalises MIME / filename, enforces per-actor / per-Realm /
//!   per-upload quotas.
//! - `HEAD /_arkret/self/blob/get`            — metadata + size for range planning
//! - `GET  /_arkret/self/blob/get`            — content (supports `Range` and the `?purpose=`
//!   discriminator)
//!
//! Blob metadata carries the spec `realm_id` association. Storing bytes on the
//! uploader's own Station forwards nothing to a third-party service, so the
//! upload is not a `plaintext_visible_services` decision (`sync/service-surface.md`
//! §5.4, `conformance/conformance-profiles.md`).

use arkret_canonical as canonical;
use arkret_identifiers::{BlobRef, DidCoreId, RealmId};
use arkret_models_collaboration::objects::blob::{
    BlobPresignAccessScope, BlobPresignDetachedJwsProof, BlobPresignEnvelope, BlobPresignOutcome,
    BlobPresignPayload, BlobPresignRequestBody, BlobStorageEncryption, BlobUploadOutcome,
    BlobVisibility, SignatureValue, UploadReceipt,
};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use coland_http::error::AppError;
use coland_http::result::{JsonResult, json_ok};
use coland_services::delivery::BlobState as BlobRecord;
use coland_services::identity::SessionIdentityState as SessionRecord;
use ed25519_dalek::Signer;
use futures_util::StreamExt as _;
use salvo::http::{Method, ParseError, StatusCode};
use salvo::oapi::extract::JsonBody;
use salvo::prelude::*;
use serde_json::{Value, json};
use subtle::ConstantTimeEq as _;

use super::{
    append_audit_log, auth_or_render, authenticated_session, is_valid_sha256_hex, now, query_param,
    render_error, sha256_hex,
};
use crate::state::AppState;

pub(super) fn router() -> Router {
    Router::new()
        .hoop(native_blob_credentials)
        .push(Router::with_path("blob/upload").post(blob_upload))
        .push(Router::with_path("blob/presign").post(blob_presign))
        .push(Router::with_path("blob/get").get(blob_get).head(blob_get))
}

#[handler]
async fn native_blob_credentials(
    req: &mut Request,
    depot: &mut Depot,
    res: &mut Response,
    ctrl: &mut FlowCtrl,
) {
    if req.headers().contains_key("arkret-managed-device")
        || req.headers().contains_key("arkret-realm-actor-control")
    {
        if req.method() == Method::POST && req.uri().path().ends_with("/blob/upload") {
            // The signature verifier reads and caches the exact multipart
            // body before the upload parser runs.
            req.set_secure_max_size(MAX_BLOB_UPLOAD_FORM_BYTES);
        }
        crate::routing::identity::session_pop::verify_session_pop
            .handle(req, depot, res, ctrl)
            .await;
    } else {
        ctrl.call_next(req, depot, res).await;
    }
}

pub(super) async fn blob_session_has_realm_membership(
    state: &AppState,
    realm_id: &str,
    session: &SessionRecord,
) -> Result<bool, AppError> {
    let actor =
        crate::routing::identity::session_actor::validated_session_actor(state, session).await?;
    let Ok(realm_id) = RealmId::new(realm_id.to_owned()) else {
        return Ok(false);
    };
    state
        .authority_commits()
        .accepted_realm_reader(&realm_id, &actor)
        .await
        .map_err(|error| AppError::internal(format!("Realm membership lookup failed: {error}")))
}

pub(super) fn blob_upload_outcome(
    state: &AppState,
    blob_ref: String,
    size_bytes: u64,
    media_type: String,
    received_at: chrono::DateTime<chrono::Utc>,
) -> Result<BlobUploadOutcome, AppError> {
    let blob_ref = BlobRef::new(blob_ref)
        .map_err(|error| AppError::internal(format!("blob_ref construction failed: {error}")))?;
    let issuer_id = arkret_identifiers::DidCoreId::new(state.service_id().clone())
        .map_err(|error| AppError::internal(format!("service DID is invalid: {error}")))?;
    let signing_payload = json!({
        "blob_ref": blob_ref.as_str(),
        "size_bytes": size_bytes,
        "received_at": canonical::format_timestamp_canonical(received_at),
        "issuer_id": issuer_id.as_str(),
    });
    let canonical_bytes = canonical::canonical_json_bytes(&signing_payload).map_err(|error| {
        AppError::internal(format!("upload receipt canonicalization failed: {error}"))
    })?;
    let signature = state.notary_signing_key().sign(&canonical_bytes);
    let signature_kid = arkret_wire::DidUrl::new(format!("{}#notary-key", state.service_did()))
        .map_err(|error| AppError::internal(format!("notary key DID URL is invalid: {error}")))?;
    let upload_receipt = UploadReceipt {
        blob_ref: blob_ref.clone(),
        size_bytes,
        received_at,
        issuer_id,
        signature: SignatureValue {
            kid: signature_kid,
            signature_algorithm: "Ed25519".to_owned(),
            sig: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
        },
    };
    Ok(BlobUploadOutcome {
        blob_ref,
        size_bytes,
        media_type: Some(media_type),
        upload_receipt: Some(upload_receipt),
    })
}

#[handler]
#[tracing::instrument(skip_all, fields(op = "org.arkret.coland.blob.upload"))]
async fn blob_upload(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let native = depot
        .get_typed::<crate::routing::identity::applet_managed_device::VerifiedAppletManagedDevice>()
        .ok();
    let session = if native.is_some() {
        None
    } else {
        let Some(session) = auth_or_render(state, req, res).await else {
            return;
        };
        Some(session)
    };
    let upload = match read_blob_upload_request(req).await {
        Ok(upload) => upload,
        Err(error) => {
            render_error(res, error.status, error.code, error.message.as_str());
            return;
        }
    };
    let bytes = upload.content;
    let size = bytes.len();
    if u64::try_from(size).ok() != Some(upload.size_bytes) {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "param_invalid",
            "size_bytes must match the content part length",
        );
        return;
    }
    if size > MAX_BLOB_UPLOAD_BYTES {
        render_error(
            res,
            StatusCode::PAYLOAD_TOO_LARGE,
            "payload_too_large",
            "blob exceeds maximum size",
        );
        return;
    }
    let realm_id = match upload.realm_id {
        Some(realm_id) => {
            let realm_id = realm_id.as_str().to_owned();
            let is_member = if let Some(session) = session.as_ref() {
                match blob_session_has_realm_membership(state, &realm_id, session).await {
                    Ok(is_member) => is_member,
                    Err(error) => {
                        render_error(res, error.http_status(), error.wire_code(), &error.message);
                        return;
                    }
                }
            } else {
                true
            };
            if !is_member {
                render_error(
                    res,
                    StatusCode::FORBIDDEN,
                    "capability_denied",
                    "uploader is not a joined member of the blob Realm",
                );
                return;
            }
            Some(realm_id)
        }
        None => None,
    };
    let mut native_guard = if let Some(native) = native {
        let Some(realm) = realm_id
            .as_deref()
            .and_then(|realm| RealmId::new(realm).ok())
        else {
            render_error(
                res,
                StatusCode::NOT_FOUND,
                "not_found",
                "native upload needs an exact Realm",
            );
            return;
        };
        let input = coland_storage::AccountContentDeliveryInput {
            realms: vec![realm.clone()],
            native_blob_upload: Some(realm),
            ..Default::default()
        };
        match crate::routing::identity::applet_managed_device::content_delivery_guard_for_input(
            state, native, input,
        )
        .await
        {
            Ok(guard) => Some(guard),
            Err(error) => {
                render_error(res, error.http_status(), error.wire_code(), &error.message);
                return;
            }
        }
    } else {
        None
    };
    let actor = native
        .map(|native| native.authority.actor_id.to_string())
        .or_else(|| session.as_ref().map(|session| session.actor.clone()))
        .expect("authenticated uploader");
    if native.is_none()
        && let Err(message) = enforce_blob_quota(state, &actor, realm_id.as_deref(), size).await
    {
        render_error(res, StatusCode::FORBIDDEN, "blob_quota_exceeded", message);
        return;
    }
    if let Some(declared) = upload.content_digest.as_deref()
        && !blob_content_digest_matches(declared, &bytes)
    {
        crate::metrics::record_digest_mismatch("blob_upload_content_digest");
        render_error(
            res,
            StatusCode::UNPROCESSABLE_ENTITY,
            "blob_digest_mismatch",
            "provided content_digest does not match blob content",
        );
        return;
    }
    // `crypto-media/media-and-blob.md` §2: the declared MIME and filename are
    // untrusted metadata. The parser checks any two declarations agree.
    let media_type = upload
        .media_type
        .or(upload.content_part_media_type)
        .unwrap_or_else(|| "application/octet-stream".to_owned());
    let filename = upload
        .filename
        .as_deref()
        .and_then(|filename| sanitize_blob_filename_value(filename).ok());
    let sha256 = sha256_hex(&bytes);
    let blob_ref = format!("ak:blob:sha256:{sha256}");
    if !validate_existing_blob_classification(state, &blob_ref, upload.encryption, res).await {
        return;
    }
    let storage_key = state.deliveries().object_key_for_sha256(&sha256);
    if let Some(guard) = native_guard.as_mut()
        && !guard.prepare_handoff().await
    {
        render_error(
            res,
            StatusCode::NOT_FOUND,
            "not_found",
            "native upload authority expired",
        );
        return;
    }
    if let Err(error) = state.deliveries().put_object(&storage_key, bytes).await {
        render_error(
            res,
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            &error.to_string(),
        );
        return;
    }
    let received_at = now();
    let record = BlobRecord {
        sha256: sha256.clone(),
        size_bytes: size as i64,
        storage_backend: state.deliveries().object_storage_backend_name(),
        storage_key: storage_key.clone(),
        media_type: media_type.clone(),
        filename: filename.clone(),
        realm_id: realm_id.clone(),
        encryption: upload.encryption,
        legal_hold: false,
        redacted: false,
        visibility: if realm_id.is_some() {
            BlobVisibility::RealmBound
        } else {
            BlobVisibility::Public
        },
        uploaded_by: actor,
        created_at: received_at,
    };
    if let Some(guard) = native_guard {
        let reference = BlobRef::new(blob_ref.clone()).expect("computed BlobRef");
        let retained = match guard
            .commit_native_blob_upload(
                &reference,
                &record,
                MAX_BLOB_ACCOUNT_BYTES as u64,
                MAX_BLOB_REALM_BYTES as u64,
            )
            .await
        {
            Ok(retained) => retained,
            Err(coland_storage::PersistenceError::Conflict(reason))
                if reason == "blob_quota_exceeded" =>
            {
                render_error(
                    res,
                    StatusCode::FORBIDDEN,
                    "blob_quota_exceeded",
                    "Blob quota exceeded",
                );
                return;
            }
            Err(coland_storage::PersistenceError::Conflict(_)) => {
                render_error(
                    res,
                    StatusCode::NOT_FOUND,
                    "not_found",
                    "native Blob binding is unavailable",
                );
                return;
            }
            Err(error) => {
                tracing::warn!(%error, "native Blob metadata commit failed");
                render_error(
                    res,
                    StatusCode::SERVICE_UNAVAILABLE,
                    "temporarily_unavailable",
                    "native Blob admission is unavailable",
                );
                return;
            }
        };
        match blob_upload_outcome(
            state,
            blob_ref,
            retained.size_bytes as u64,
            retained.media_type,
            retained.created_at,
        ) {
            Ok(outcome) => res.render(Json(outcome)),
            Err(error) => render_error(res, error.http_status(), error.wire_code(), &error.message),
        }
        return;
    }
    let stored = state.deliveries().store_blob(&blob_ref, record).await;
    if let Err(error) = stored {
        tracing::error!(%error, "failed to persist blob");
        if matches!(state.deliveries().blob(&blob_ref).await, Ok(None))
            && let Err(delete_error) = state.deliveries().delete_object(&storage_key).await
        {
            tracing::warn!(%delete_error, %storage_key, "failed to clean up blob after metadata write failure");
        }
        if !validate_existing_blob_classification(state, &blob_ref, upload.encryption, res).await {
            return;
        }
        render_error(
            res,
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            &error.to_string(),
        );
        return;
    }
    let outcome = match blob_upload_outcome(state, blob_ref, size as u64, media_type, received_at) {
        Ok(outcome) => outcome,
        Err(error) => {
            render_error(
                res,
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                &error.to_string(),
            );
            return;
        }
    };
    res.render(Json(outcome));
}

#[handler]
#[tracing::instrument(skip_all, fields(op = "org.arkret.coland.blob.get"))]
async fn blob_get(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let native = depot
        .get_typed::<crate::routing::identity::applet_managed_device::VerifiedAppletManagedDevice>()
        .ok();
    let Some(blob_ref) = query_param(req, "blob_ref") else {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "param_missing",
            "blob_ref is required",
        );
        return;
    };
    // `purpose` is authorization-bearing on the presign path and nowhere else:
    // `validate_presign_query` compares it against the signed payload, so a
    // presign URL without one cannot be checked and is refused here rather than
    // silently mismatching. On the session path nothing reads it for the access
    // decision — `blob_visible_to_session` does that — and requiring it made
    // every registered caller that follows the binding contract fail, including
    // the SDK's own realm-state-snapshot restore, which downloads its chunks
    // with `blob_download(chunk_ref, None)`. `service-http-binding.md` §3 lists
    // `purpose` as optional on this surface. Absent, it defaults the way the
    // presign issuer already defaults it, and "download" keeps
    // `Content-Disposition: attachment` — the safe direction.
    let purpose = match query_param(req, "purpose") {
        Some(purpose) => purpose,
        None if query_param(req, "presign").is_some() => {
            render_error(
                res,
                StatusCode::BAD_REQUEST,
                "param_missing",
                "purpose is required with presign",
            );
            return;
        }
        None => DEFAULT_BLOB_PURPOSE.to_owned(),
    };
    if !is_valid_blob_purpose(&purpose) {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "param_invalid",
            "invalid blob purpose",
        );
        return;
    }
    let presign_present = query_param(req, "presign").is_some();
    if presign_present && native.is_some() {
        render_error(
            res,
            StatusCode::NOT_FOUND,
            "not_found",
            "mixed Blob credentials",
        );
        return;
    }
    if presign_present
        && req
            .headers()
            .contains_key(salvo::http::header::AUTHORIZATION)
    {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "param_invalid",
            "Authorization and presign are mutually exclusive",
        );
        return;
    }
    let presign_payload = if presign_present {
        match validate_presign_query(state, req, &blob_ref, &purpose) {
            Ok(payload) => Some(payload),
            Err(()) => {
                render_error(res, StatusCode::NOT_FOUND, "not_found", "not found");
                return;
            }
        }
    } else {
        None
    };
    let session = if presign_payload.is_some() || native.is_some() {
        None
    } else {
        match authenticated_session(state, req).await {
            Ok(session) => Some(session),
            Err((_, code, message)) => {
                // api-conventions §3.3: expired or invalid presented grants
                // are unauthenticated, but authority outages and the Account
                // lifecycle's specific refusal remain their original class.
                let code = match crate::error::ErrorCode::from_wire(code) {
                    Some(crate::error::ErrorCode::AuthExpired) => {
                        crate::error::ErrorCode::Unauthenticated
                    }
                    Some(code) => code,
                    None => crate::error::ErrorCode::InternalError,
                };
                if code == crate::error::ErrorCode::TemporarilyUnavailable {
                    res.headers_mut()
                        .insert(salvo::http::header::RETRY_AFTER, "1".parse().unwrap());
                }
                AppError::from_rejection(code, message)
                    .with_status_context(arkret_wire::ErrorStatusContext::ProtectedResource)
                    .write(req, depot, res)
                    .await;
                return;
            }
        }
    };
    if let Ok(wait) = depot.get_typed::<crate::openapi_routes::WaitForSyncToken>() {
        let Some(session) = session.as_ref() else {
            render_error(
                res,
                StatusCode::UNAUTHORIZED,
                "unauthenticated",
                "wait-for requires the bound authenticated subject",
            );
            return;
        };
        let mut notifications = state.subscribe_event_notifications();
        let event_id = match crate::routing::events::sync::parse_and_validate_barrier_cursor(
            &wait.0,
            state,
            session,
            chrono::Utc::now().timestamp_millis(),
        )
        .await
        {
            Ok(event_id) => event_id,
            Err(error) => {
                crate::routing::events::sync::render_account_cursor_error(res, error, true);
                return;
            }
        };
        let barrier_result = crate::routing::events::sync::wait_for_account_projection_barrier(
            state,
            &mut notifications,
            &event_id,
        )
        .await;
        if let Err(error) = crate::routing::events::sync::parse_and_validate_barrier_cursor(
            &wait.0,
            state,
            session,
            chrono::Utc::now().timestamp_millis(),
        )
        .await
        {
            crate::routing::events::sync::render_account_cursor_error(res, error, true);
            return;
        }
        if !matches!(barrier_result, Ok(true)) {
            render_error(
                res,
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily_unavailable",
                "blob authorization projection coverage unavailable",
            );
            return;
        }
    }
    let mut blob = state.deliveries().blob(&blob_ref).await.ok().flatten();
    if blob.is_none()
        && purpose == "profile_avatar"
        && let Some(session) = session.as_ref()
    {
        blob = try_recover_profile_avatar_blob(state, &blob_ref, &session.actor).await;
    }
    match blob.as_ref() {
        Some(blob) => {
            if let Some(payload) = presign_payload.as_ref()
                && !presign_payload_matches_blob(blob, payload)
            {
                render_error(res, StatusCode::NOT_FOUND, "not_found", "not found");
                return;
            }
            let denied = if let Some(session) = session.as_ref() {
                !blob_visible_to_session(
                    state,
                    blob,
                    session,
                    query_param(req, "realm_id").as_deref(),
                )
                .await
            } else {
                false
            };
            if denied {
                render_error(res, StatusCode::NOT_FOUND, "not_found", "not found");
                return;
            }
            let delivery_guard = if let Some(native) = native {
                let input = coland_storage::AccountContentDeliveryInput {
                    realms: vec![native.metadata.effective_scope.realm_id().clone()],
                    blobs: vec![(
                        match BlobRef::new(blob_ref.clone()) {
                            Ok(reference) => reference,
                            Err(_) => {
                                render_error(res, StatusCode::NOT_FOUND, "not_found", "not found");
                                return;
                            }
                        },
                        blob.clone(),
                        if req.method() == Method::HEAD {
                            arkret_wire::CapabilityActionId::SelfBlobResourceHeadV1
                        } else {
                            arkret_wire::CapabilityActionId::SelfBlobResourceGetV1
                        },
                    )],
                    ..Default::default()
                };
                match crate::routing::identity::applet_managed_device::content_delivery_guard_for_input(state, native, input).await {
                    Ok(guard) => Some(guard),
                    Err(_) => { render_error(res, StatusCode::NOT_FOUND, "not_found", "not found"); return; }
                }
            } else if let Some(session) = session.as_ref() {
                let Some(realm) = blob.realm_id.as_deref().map(RealmId::new).transpose().ok()
                else {
                    render_error(res, StatusCode::NOT_FOUND, "not_found", "not found");
                    return;
                };
                let input = coland_storage::AccountContentDeliveryInput {
                    realms: realm.into_iter().collect(),
                    blobs: vec![(
                        match BlobRef::new(blob_ref.clone()) {
                            Ok(reference) => reference,
                            Err(_) => {
                                render_error(res, StatusCode::NOT_FOUND, "not_found", "not found");
                                return;
                            }
                        },
                        blob.clone(),
                        if req.method() == Method::HEAD {
                            arkret_wire::CapabilityActionId::ObjectReadMetadata
                        } else {
                            arkret_wire::CapabilityActionId::ObjectReadContent
                        },
                    )],
                    ..Default::default()
                };
                match crate::routing::events::sync::content_delivery_guard(state, session, &input)
                    .await
                {
                    Ok(guard) => guard,
                    Err(_) => {
                        render_error(res, StatusCode::NOT_FOUND, "not_found", "not found");
                        return;
                    }
                }
            } else {
                None
            };
            // Round R2/R3 (T11) — fail-closed gates for E2EE / legal_hold /
            // redacted / actor_private. `/blob/presign` issues a short-lived
            // local direct-serve URL that re-enters this handler without a
            // bearer session; the same gates + response headers apply here.
            let blob_value = presign_blob_policy_value(blob);
            let native_actor = native.map(|native| native.metadata.actor_id.to_string());
            let actor = native_actor
                .as_deref()
                .or_else(|| session.as_ref().map(|session| session.actor.as_str()))
                .unwrap_or("presigned");
            if let Some(block) = classify_presign_blob_block(&blob_value, actor) {
                let direct_member_e2ee_download = (session.is_some() || native.is_some())
                    && matches!(block, PresignBlobBlock::E2ee);
                if !direct_member_e2ee_download {
                    let error = block.as_error();
                    render_error(
                        res,
                        error.http_status(),
                        error.wire_code(),
                        error.message.as_ref(),
                    );
                    return;
                }
            }
            if presign_payload.is_some()
                && let Some(reason) =
                    realm_presign_policy_block(state, blob.realm_id.as_deref()).await
            {
                append_audit_log(
                    state,
                    None,
                    reason,
                    json!({
                        "blob_ref": blob_ref,
                        "realm_id": blob.realm_id.clone(),
                    }),
                    "rejected",
                )
                .await;
                render_error(res, StatusCode::NOT_FOUND, "not_found", "not found");
                return;
            }
            // Response headers per T11.
            res.headers_mut().insert(
                salvo::http::header::CACHE_CONTROL,
                PRESIGN_CACHE_CONTROL.parse().unwrap(),
            );
            res.headers_mut().insert(
                salvo::http::header::REFERRER_POLICY,
                PRESIGN_REFERRER_POLICY.parse().unwrap(),
            );
            let total_len = match usize::try_from(blob.size_bytes) {
                Ok(total_len) => total_len,
                Err(_) => {
                    render_error(
                        res,
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "internal_error",
                        "invalid blob size metadata",
                    );
                    return;
                }
            };
            let range = match parse_range(req, total_len).transpose() {
                Ok(range) => range,
                Err(message) => {
                    render_error(res, StatusCode::BAD_REQUEST, "param_invalid", message);
                    return;
                }
            };
            let (status, content_length, content_range) = match range {
                Some((start, end)) => (
                    StatusCode::PARTIAL_CONTENT,
                    end.saturating_sub(start) + 1,
                    Some(format!("bytes {start}-{end}/{total_len}")),
                ),
                None => (StatusCode::OK, total_len, None),
            };
            res.status_code(status);
            res.headers_mut().insert(
                salvo::http::header::CONTENT_TYPE,
                blob.media_type.parse().unwrap(),
            );
            res.headers_mut().insert(
                salvo::http::header::CONTENT_LENGTH,
                content_length.to_string().parse().unwrap(),
            );
            res.headers_mut().insert(
                salvo::http::header::HeaderName::from_static("digest"),
                format!("sha-256={}", blob_ref.trim_start_matches("ak:blob:sha256:"))
                    .parse()
                    .unwrap(),
            );
            res.headers_mut().insert(
                salvo::http::header::HeaderName::from_static("accept-ranges"),
                "bytes".parse().unwrap(),
            );
            if let Some(disposition) = blob_content_disposition(blob, &purpose) {
                res.headers_mut().insert(
                    salvo::http::header::CONTENT_DISPOSITION,
                    disposition.parse().unwrap(),
                );
            }
            if let Some(content_range) = content_range {
                res.headers_mut().insert(
                    salvo::http::header::CONTENT_RANGE,
                    content_range.parse().unwrap(),
                );
            }
            append_audit_log(
                state,
                Some(actor),
                "blob.get",
                json!({
                    "blob_ref": blob_ref.clone(),
                    "device_id": native.map(|native| native.metadata.device_id.to_string())
                        .or_else(|| session.as_ref().and_then(|session| session.human_device_id().cloned())),
                    "purpose": purpose,
                    "realm_id": blob.realm_id.clone(),
                    "presigned": presign_payload.is_some(),
                    "status": status.as_u16()
                }),
                "accepted",
            )
            .await;
            if delivery_guard
                .as_ref()
                .is_some_and(|guard| !guard.permits_handoff())
            {
                clear_blob_content_headers(res);
                render_error(res, StatusCode::NOT_FOUND, "not_found", "not found");
                return;
            }
            if req.method() != Method::HEAD {
                let object_range = match range {
                    Some((start, end)) => start as u64..(end as u64 + 1),
                    None => 0..total_len as u64,
                };
                let stream = match state
                    .deliveries()
                    .get_object_range_stream(&blob.storage_key, object_range)
                    .await
                {
                    Ok(stream) => stream,
                    Err(error) => {
                        tracing::error!(%error, storage_key = %blob.storage_key, "failed to read blob object");
                        render_error(
                            res,
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "internal_error",
                            "blob object unavailable",
                        );
                        return;
                    }
                };
                if let Some(guard) = delivery_guard {
                    if !guard.permits_handoff() {
                        clear_blob_content_headers(res);
                        render_error(res, StatusCode::NOT_FOUND, "not_found", "not found");
                        return;
                    }
                    res.stream(async_stream::stream! {
                        let mut stream = stream;
                        while let Some(chunk) = stream.next().await {
                            if !guard.permits_handoff() {
                                yield Err(std::io::Error::other("attachment delivery time authority changed"));
                                return;
                            }
                            yield chunk.map_err(std::io::Error::other);
                        }
                        if guard.finish().await.is_err() {
                            yield Err(std::io::Error::other("attachment delivery cut could not be released"));
                        }
                    });
                } else {
                    res.stream(stream);
                }
            } else if let Some(guard) = delivery_guard {
                // A HEAD response publishes the same protected metadata.
                res.stream(async_stream::stream! {
                    if !guard.permits_handoff() {
                        yield Err(std::io::Error::other("attachment metadata time authority changed"));
                        return;
                    }
                    yield Ok::<bytes::Bytes,std::io::Error>(bytes::Bytes::new());
                    if guard.finish().await.is_err() {
                        yield Err(std::io::Error::other("attachment metadata cut could not be released"));
                    }
                });
            }
        }
        None => render_error(res, StatusCode::NOT_FOUND, "not_found", "not found"),
    }
}

fn clear_blob_content_headers(res: &mut Response) {
    for name in [
        "content-type",
        "content-length",
        "content-range",
        "content-disposition",
        "digest",
        "accept-ranges",
    ] {
        res.headers_mut().remove(name);
    }
}

async fn try_recover_profile_avatar_blob(
    state: &AppState,
    blob_ref: &str,
    uploaded_by: &str,
) -> Option<BlobRecord> {
    let sha256 = blob_ref.strip_prefix("ak:blob:sha256:")?;
    if !is_valid_sha256_hex(sha256) {
        return None;
    }
    let storage_key = state.deliveries().object_key_for_sha256(sha256);
    let bytes = match state.deliveries().get_object(&storage_key).await {
        Ok(bytes) => bytes,
        Err(error) => {
            tracing::debug!(%error, %blob_ref, %storage_key, "profile avatar blob metadata missing and object is unavailable");
            return None;
        }
    };
    if bytes.len() > MAX_BLOB_UPLOAD_BYTES {
        tracing::warn!(%blob_ref, size = bytes.len(), "refusing to recover oversized profile avatar blob");
        return None;
    }
    let actual_sha256 = sha256_hex(&bytes);
    if actual_sha256 != sha256 {
        tracing::warn!(%blob_ref, %actual_sha256, "refusing to recover profile avatar blob with mismatched digest");
        return None;
    }
    let media_type = infer_profile_avatar_media_type(&bytes)?;
    let record = BlobRecord {
        sha256: sha256.to_owned(),
        size_bytes: bytes.len() as i64,
        storage_backend: state.deliveries().object_storage_backend_name(),
        storage_key,
        media_type,
        filename: None,
        realm_id: None,
        encryption: None,
        legal_hold: false,
        redacted: false,
        visibility: BlobVisibility::Public,
        uploaded_by: uploaded_by.to_owned(),
        created_at: now(),
    };
    if let Err(error) = state
        .deliveries()
        .store_blob(blob_ref, record.clone())
        .await
    {
        tracing::warn!(%error, %blob_ref, "failed to persist recovered profile avatar blob metadata");
        return None;
    }
    Some(record)
}

#[endpoint(operation_id = "ak.self.blob.command.presign")]
#[tracing::instrument(skip_all, fields(op = "ak.self.blob.command.presign.v1"))]
async fn blob_presign(
    aa: crate::routing::system::extract::AuthArgs,
    body: JsonBody<BlobPresignRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<BlobPresignOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let native = depot
        .get_typed::<crate::routing::identity::applet_managed_device::VerifiedAppletManagedDevice>()
        .ok();
    let session = if native.is_some() {
        None
    } else {
        Some(aa.authenticated_session(state, req).await?)
    };
    let body = body.into_inner();
    let blob_ref = body.blob_ref.as_str();
    let purpose = body.purpose.as_deref().unwrap_or(DEFAULT_BLOB_PURPOSE);
    if !is_valid_blob_purpose(purpose) {
        return Err(AppError::param_invalid("invalid blob purpose"));
    }
    let blob = state
        .deliveries()
        .blob(blob_ref)
        .await
        .ok()
        .flatten()
        .ok_or_else(|| AppError::not_found("blob not found"))?;
    if let Some(session) = session.as_ref()
        && !blob_visible_to_session(
            state,
            &blob,
            session,
            body.realm_id.as_ref().map(|realm_id| realm_id.as_str()),
        )
        .await
    {
        return Err(AppError::not_found("blob not found"));
    }
    let native_guard = if let Some(native) = native {
        if body
            .realm_id
            .as_ref()
            .is_some_and(|realm| realm != native.metadata.effective_scope.realm_id())
        {
            return Err(AppError::not_found("blob not found"));
        }
        let input = coland_storage::AccountContentDeliveryInput {
            realms: vec![native.metadata.effective_scope.realm_id().clone()],
            blobs: vec![(
                body.blob_ref.clone(),
                blob.clone(),
                arkret_wire::CapabilityActionId::SelfBlobCommandPresignV1,
            )],
            ..Default::default()
        };
        Some(
            crate::routing::identity::applet_managed_device::content_delivery_guard_for_input(
                state, native, input,
            )
            .await
            .map_err(|_| AppError::not_found("blob not found"))?,
        )
    } else {
        None
    };
    if let Some(session) = session
        .as_ref()
        .filter(|session| session.agent_session().is_some())
    {
        let realm = blob
            .realm_id
            .as_deref()
            .map(RealmId::new)
            .transpose()
            .map_err(|_| AppError::not_found("blob not found"))?;
        let input = coland_storage::AccountContentDeliveryInput {
            realms: realm.into_iter().collect(),
            blobs: vec![(
                body.blob_ref.clone(),
                blob.clone(),
                arkret_wire::CapabilityActionId::ObjectReadContent,
            )],
            ..Default::default()
        };
        let guard = crate::routing::events::sync::content_delivery_guard(state, session, &input)
            .await
            .map_err(|_| AppError::not_found("blob not found"))?;
        if guard.is_some() {
            return Err(AppError::capability_denied(
                "Owned Agent attachments require current authenticated delivery",
            ));
        }
    }
    let blob_value = presign_blob_policy_value(&blob);
    if let Some(block) = classify_presign_blob_block(&blob_value, "presigned") {
        return Err(block.as_error());
    }
    let native_actor = native.map(|native| native.metadata.actor_id.to_string());
    let actor = native_actor
        .as_deref()
        .or_else(|| session.as_ref().map(|session| session.actor.as_str()))
        .ok_or_else(|| AppError::not_found("blob not found"))?;
    if let Some(reason) = realm_presign_policy_block(state, blob.realm_id.as_deref()).await {
        append_audit_log(
            state,
            Some(actor),
            reason,
            json!({
                "blob_ref": blob_ref,
                "realm_id": blob.realm_id.clone(),
            }),
            "rejected",
        )
        .await;
        return Err(AppError::not_found("blob not found").with_rejection_code(reason));
    }
    let ttl_seconds = u64::from(body.max_age_seconds.unwrap_or(300)).clamp(1, 300);
    let issued_at = now();
    let expires_at = issued_at + chrono::Duration::seconds(ttl_seconds as i64);
    let presign = issue_presign_envelope(
        state,
        blob_ref,
        blob.realm_id.as_deref(),
        purpose,
        actor,
        issued_at,
        expires_at,
    )?;
    let base = state.config().public_base_url.trim_end_matches('/');
    let url = format!(
        "{base}/_arkret/self/blob/get?blob_ref={}&purpose={}&presign={}",
        query_escape(blob_ref),
        query_escape(purpose),
        query_escape(&presign.token),
    );
    if let Some(guard) = native_guard {
        if !guard.permits_handoff() {
            return Err(AppError::not_found("blob not found"));
        }
        guard
            .finish()
            .await
            .map_err(|_| AppError::not_found("blob not found"))?;
    }
    json_ok(BlobPresignOutcome {
        url,
        expires_at,
        purpose: Some(purpose.to_owned()),
        realm_id: presign.payload.realm_id,
        nonce: presign.payload.nonce,
        access_scope: presign.payload.access_scope,
    })
}

const BLOB_PRESIGN_SCHEME: &str = "ak.blob.presign.v1";
const BLOB_PRESIGN_PROOF_KIND: &str = "detached_jws";
const BLOB_PRESIGN_KID_FRAGMENT: &str = "notary-key";
const BLOB_PRESIGN_MAX_TTL_SECONDS: i64 = 300;
const BLOB_PRESIGN_CLOCK_SKEW_SECONDS: i64 = 30;

struct IssuedBlobPresign {
    token: String,
    payload: BlobPresignPayload,
}

fn issue_presign_envelope(
    state: &AppState,
    blob_ref: &str,
    realm_id: Option<&str>,
    purpose: &str,
    actor: &str,
    issued_at: chrono::DateTime<chrono::Utc>,
    expires_at: chrono::DateTime<chrono::Utc>,
) -> Result<IssuedBlobPresign, AppError> {
    let blob_ref = BlobRef::new(blob_ref.to_owned())
        .map_err(|error| AppError::internal(format!("blob_ref is invalid: {error}")))?;
    let issuer_id = arkret_identifiers::DidCoreId::new(state.service_id().clone())
        .map_err(|error| AppError::internal(format!("service DID is invalid: {error}")))?;
    let realm_id = realm_id
        .map(|value| {
            RealmId::new(value.to_owned())
                .map_err(|error| AppError::internal(format!("blob realm_id is invalid: {error}")))
        })
        .transpose()?;
    let audience_hint = DidCoreId::new(actor.to_owned()).ok();
    let mut nonce_bytes = [0u8; 16];
    {
        use rand::RngExt;

        rand::rng().fill(&mut nonce_bytes[..]);
    }
    let payload = BlobPresignPayload {
        scheme: BLOB_PRESIGN_SCHEME.to_owned(),
        blob_ref,
        realm_id,
        issuer_id: issuer_id.clone(),
        issued_at,
        expires_at,
        purpose: purpose.to_owned(),
        nonce: URL_SAFE_NO_PAD.encode(nonce_bytes),
        access_scope: BlobPresignAccessScope {
            method: vec!["GET".to_owned(), "HEAD".to_owned()],
            byte_range: None,
        },
        audience_hint,
    };
    let canonical_payload = canonical::canonical_json_bytes(&payload).map_err(|error| {
        AppError::internal(format!(
            "blob presign payload canonicalization failed: {error}"
        ))
    })?;
    let jws = arkret_signatures::jws::sign_jws_ed25519(
        &canonical_payload,
        state.notary_signing_key().as_ref(),
    )
    .map_err(|error| AppError::internal(format!("blob presign signing failed: {error}")))?;
    let envelope = BlobPresignEnvelope {
        payload: payload.clone(),
        proof: BlobPresignDetachedJwsProof {
            kind: BLOB_PRESIGN_PROOF_KIND.to_owned(),
            kid: blob_presign_kid(state),
            jws,
        },
    };
    let envelope_bytes = canonical::canonical_json_bytes(&envelope).map_err(|error| {
        AppError::internal(format!(
            "blob presign envelope canonicalization failed: {error}"
        ))
    })?;
    Ok(IssuedBlobPresign {
        token: URL_SAFE_NO_PAD.encode(envelope_bytes),
        payload,
    })
}

fn validate_presign_query(
    state: &AppState,
    req: &Request,
    blob_ref: &str,
    purpose: &str,
) -> Result<BlobPresignPayload, ()> {
    let encoded = query_param(req, "presign").ok_or(())?;
    let bytes = URL_SAFE_NO_PAD.decode(encoded.as_bytes()).map_err(|_| ())?;
    let envelope: BlobPresignEnvelope = serde_json::from_slice(&bytes).map_err(|_| ())?;
    let expected_kid = blob_presign_kid(state);
    if envelope.proof.kind != BLOB_PRESIGN_PROOF_KIND
        || envelope.proof.kid != expected_kid
        || envelope.proof.jws.trim().is_empty()
    {
        return Err(());
    }
    let payload = envelope.payload;
    if payload.scheme != BLOB_PRESIGN_SCHEME
        || payload.blob_ref.as_str() != blob_ref
        || payload.purpose != purpose
        || payload.issuer_id.as_str() != state.service_id().as_str()
        || payload.nonce.len() < 16
    {
        return Err(());
    }
    let method = req.method().as_str();
    if payload.access_scope.method.is_empty()
        || payload
            .access_scope
            .method
            .iter()
            .any(|method| method.as_str() != "GET" && method.as_str() != "HEAD")
        || !payload
            .access_scope
            .method
            .iter()
            .any(|allowed| allowed.as_str() == method)
    {
        return Err(());
    }
    let now = now();
    let skew = chrono::Duration::seconds(BLOB_PRESIGN_CLOCK_SKEW_SECONDS);
    if payload.expires_at <= payload.issued_at
        || payload.issued_at - skew > now
        || payload.expires_at + skew < now
        || (payload.expires_at - payload.issued_at).num_seconds() > BLOB_PRESIGN_MAX_TTL_SECONDS
    {
        return Err(());
    }
    let canonical_payload = canonical::canonical_json_bytes(&payload).map_err(|_| ())?;
    let expected_jws = arkret_signatures::jws::sign_jws_ed25519(
        &canonical_payload,
        state.notary_signing_key().as_ref(),
    )
    .map_err(|_| ())?;
    let expected = expected_jws.as_bytes();
    let actual = envelope.proof.jws.as_bytes();
    if expected.len() != actual.len() || !bool::from(expected.ct_eq(actual)) {
        return Err(());
    }
    Ok(payload)
}

fn blob_presign_kid(state: &AppState) -> String {
    format!("{}#{BLOB_PRESIGN_KID_FRAGMENT}", state.service_id())
}

fn presign_payload_matches_blob(blob: &BlobRecord, payload: &BlobPresignPayload) -> bool {
    match blob.realm_id.as_deref() {
        Some(realm_id) => payload.realm_id.as_ref().map(|value| value.as_str()) == Some(realm_id),
        None => payload.realm_id.is_none() && blob.visibility == BlobVisibility::Public,
    }
}

fn presign_blob_policy_value(blob: &BlobRecord) -> Value {
    json!({
        "encryption": blob.encryption.clone(),
        "uploaded_by": blob.uploaded_by.clone(),
        "legal_hold": blob.legal_hold,
        "redacted": blob.redacted,
        "visibility": blob.visibility.as_str(),
    })
}

fn query_escape(value: &str) -> String {
    value
        .replace('%', "%25")
        .replace(':', "%3A")
        .replace('/', "%2F")
        .replace(' ', "%20")
        .replace('&', "%26")
        .replace('=', "%3D")
}

fn blob_content_disposition(blob: &BlobRecord, purpose: &str) -> Option<String> {
    let dangerous_types = ["text/html", "application/javascript", "image/svg+xml"];
    let force_attachment =
        dangerous_types.contains(&blob.media_type.as_str()) || purpose != "profile_avatar";
    let disposition = if force_attachment {
        "attachment"
    } else {
        "inline"
    };
    match blob
        .filename
        .as_deref()
        .and_then(|filename| sanitize_blob_filename_value(filename).ok())
    {
        Some(filename) => Some(format!("{disposition}; filename=\"{filename}\"")),
        None if force_attachment => Some("attachment".to_owned()),
        None => None,
    }
}

/// The parsed `blob-operations.schema.json#/$defs/blob_upload_request_body`.
///
/// Every member arrives as a `multipart/form-data` part named after it;
/// no header, query parameter or `Content-Disposition` filename stands in
/// for any of them.
struct BlobUploadRequest {
    content: Vec<u8>,
    /// The content part's own `Content-Type`, the multipart default for
    /// `media_type` (`media-and-blob.md` §2).
    content_part_media_type: Option<String>,
    size_bytes: u64,
    realm_id: Option<RealmId>,
    content_digest: Option<String>,
    media_type: Option<String>,
    filename: Option<String>,
    encryption: Option<BlobStorageEncryption>,
}

struct BlobUploadBodyError {
    status: StatusCode,
    code: &'static str,
    message: String,
}

impl BlobUploadBodyError {
    /// `service-http-binding.md` §6: a closed schema or canonical encoding
    /// failure is `schema_violation`.
    fn schema_violation(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::UNPROCESSABLE_ENTITY,
            code: "schema_violation",
            message: message.into(),
        }
    }

    fn too_large(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::PAYLOAD_TOO_LARGE,
            code: "payload_too_large",
            message: message.into(),
        }
    }
}

/// The text members of `blob_upload_request_body`; `content` is the only
/// binary part.
const BLOB_UPLOAD_TEXT_FIELDS: [&str; 6] = [
    "size_bytes",
    "realm_id",
    "content_digest",
    "media_type",
    "filename",
    "encryption",
];

async fn read_blob_upload_request(
    req: &mut Request,
) -> Result<BlobUploadRequest, BlobUploadBodyError> {
    let boundary =
        req.headers()
            .get(salvo::http::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .filter(|value| {
                value.split(';').next().is_some_and(|essence| {
                    essence.trim().eq_ignore_ascii_case("multipart/form-data")
                })
            })
            .and_then(|value| multra::parse_boundary(value).ok())
            .ok_or_else(|| {
                BlobUploadBodyError::schema_violation("blob uploads require multipart/form-data")
            })?;
    let payload = req
        .payload_with_max_size(MAX_BLOB_UPLOAD_FORM_BYTES)
        .await
        .map_err(|error| match error {
            ParseError::PayloadTooLarge => {
                BlobUploadBodyError::too_large("blob exceeds maximum size")
            }
            _ => BlobUploadBodyError::schema_violation("unreadable multipart blob upload body"),
        })?
        .clone();
    let stream =
        futures_util::stream::once(
            async move { Ok::<bytes::Bytes, std::convert::Infallible>(payload) },
        );
    let mut multipart = multra::Multipart::new(stream, boundary);

    let malformed =
        |_| BlobUploadBodyError::schema_violation("malformed multipart blob upload body");
    let mut content: Option<(Vec<u8>, Option<String>)> = None;
    let mut text = std::collections::BTreeMap::<&'static str, String>::new();
    while let Some(field) = multipart.next_field().await.map_err(malformed)? {
        let Some(name) = field.name().map(str::to_owned) else {
            return Err(BlobUploadBodyError::schema_violation(
                "multipart part carries no field name",
            ));
        };
        if name == "content" {
            if content.is_some() {
                return Err(BlobUploadBodyError::schema_violation(
                    "multipart content part must appear exactly once",
                ));
            }
            let part_media_type = field
                .headers()
                .get(salvo::http::header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                .and_then(sanitize_media_type);
            let bytes = field.bytes().await.map_err(malformed)?;
            content = Some((bytes.to_vec(), part_media_type));
            continue;
        }
        let Some(key) = BLOB_UPLOAD_TEXT_FIELDS
            .iter()
            .copied()
            .find(|key| *key == name)
        else {
            return Err(BlobUploadBodyError::schema_violation(format!(
                "multipart field `{name}` is not a blob_upload_request_body member"
            )));
        };
        if text.contains_key(key) {
            return Err(BlobUploadBodyError::schema_violation(format!(
                "multipart field `{key}` must appear at most once"
            )));
        }
        let bytes = field.bytes().await.map_err(malformed)?;
        let value = String::from_utf8(bytes.to_vec()).map_err(|_| {
            BlobUploadBodyError::schema_violation(format!("multipart field `{key}` must be UTF-8"))
        })?;
        text.insert(key, value);
    }

    let (content, content_part_media_type) = content.ok_or_else(|| {
        BlobUploadBodyError::schema_violation("multipart content part is required")
    })?;
    let size_bytes = text
        .remove("size_bytes")
        .ok_or_else(|| BlobUploadBodyError::schema_violation("multipart size_bytes is required"))?;
    let size_bytes = (!size_bytes.is_empty()
        && size_bytes.bytes().all(|byte| byte.is_ascii_digit()))
    .then(|| size_bytes.parse::<u64>().ok())
    .flatten()
    .ok_or_else(|| {
        BlobUploadBodyError::schema_violation("size_bytes must be a non-negative integer")
    })?;
    let realm_id = text
        .remove("realm_id")
        .map(|value| {
            RealmId::new(value)
                .map_err(|_| BlobUploadBodyError::schema_violation("realm_id is not a Realm id"))
        })
        .transpose()?;
    let content_digest = text
        .remove("content_digest")
        .map(|value| {
            if is_valid_blob_upload_content_digest(&value) {
                Ok(value)
            } else {
                Err(BlobUploadBodyError::schema_violation(
                    "content_digest must be <sha256|blake3>:<64 lowercase hex>",
                ))
            }
        })
        .transpose()?;
    let media_type = text
        .remove("media_type")
        .map(|value| {
            if is_valid_blob_upload_media_type(&value) {
                Ok(value)
            } else {
                Err(BlobUploadBodyError::schema_violation(
                    "media_type must be <type>/<subtype>",
                ))
            }
        })
        .transpose()?;
    let filename = text
        .remove("filename")
        .map(|value| {
            if (1..=255).contains(&value.chars().count()) {
                Ok(value)
            } else {
                Err(BlobUploadBodyError::schema_violation(
                    "filename must be 1 to 255 characters",
                ))
            }
        })
        .transpose()?;
    let encryption_json = text
        .remove("encryption")
        .ok_or_else(|| BlobUploadBodyError::schema_violation("multipart encryption is required"))?;
    let encryption = parse_blob_storage_encryption(&encryption_json)
        .map_err(BlobUploadBodyError::schema_violation)?;
    if media_type
        .as_ref()
        .zip(content_part_media_type.as_ref())
        .is_some_and(|(form, part)| form != part)
    {
        return Err(BlobUploadBodyError::schema_violation(
            "media_type conflicts with content part Content-Type",
        ));
    }
    let effective_mime = media_type
        .as_deref()
        .or(content_part_media_type.as_deref())
        .unwrap_or("application/octet-stream");
    if encryption.is_some() && effective_mime != "application/octet-stream" {
        return Err(BlobUploadBodyError::schema_violation(
            "ciphertext media_type must be application/octet-stream",
        ));
    }
    Ok(BlobUploadRequest {
        content,
        content_part_media_type,
        size_bytes,
        realm_id,
        content_digest,
        media_type,
        filename,
        encryption,
    })
}

pub(super) fn parse_blob_storage_encryption(
    value: &str,
) -> Result<Option<BlobStorageEncryption>, &'static str> {
    serde_json::from_str(value)
        .map_err(|_| "encryption must be null or a closed registered scheme classification")
}

pub(super) async fn validate_existing_blob_classification(
    state: &AppState,
    blob_ref: &str,
    encryption: Option<BlobStorageEncryption>,
    res: &mut Response,
) -> bool {
    match state.deliveries().blob(blob_ref).await {
        Ok(Some(existing)) if existing.encryption != encryption => {
            render_error(
                res,
                StatusCode::CONFLICT,
                "failed_precondition",
                "blob encryption classification is immutable for this content reference",
            );
            false
        }
        Ok(_) => true,
        Err(error) => {
            render_error(
                res,
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                &error.to_string(),
            );
            false
        }
    }
}

/// `blob_upload_request_body.media_type`: `^[a-z0-9.+-]+/[a-z0-9.+-]+$`.
fn is_valid_blob_upload_media_type(value: &str) -> bool {
    let token = |part: &str| {
        !part.is_empty()
            && part.bytes().all(|byte| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || matches!(byte, b'.' | b'+' | b'-')
            })
    };
    value
        .split_once('/')
        .is_some_and(|(top, sub)| token(top) && token(sub))
}

/// `blob_upload_request_body.content_digest`: the SDK `Hash` digest form,
/// `^(sha256|blake3):[0-9a-f]{64}$`.
pub(super) fn is_valid_blob_upload_content_digest(value: &str) -> bool {
    arkret_identifiers::Hash::new(value.to_owned()).is_ok()
}

/// Whether a declared `content_digest` commits to `bytes` under its own
/// suite; the stored `blob_ref` stays on this Station's suite either way.
pub(super) fn blob_content_digest_matches(declared: &str, bytes: &[u8]) -> bool {
    declared
        .split_once(':')
        .and_then(|(suite, _)| canonical::digest_with_suite(suite, bytes).ok())
        .is_some_and(|computed| computed == declared)
}

fn parse_range(req: &Request, total_len: usize) -> Option<Result<(usize, usize), &'static str>> {
    let header = req
        .headers()
        .get(salvo::http::header::RANGE)?
        .to_str()
        .ok()?;
    let Some(range) = header.strip_prefix("bytes=") else {
        return Some(Err("only bytes ranges are supported"));
    };
    let Some((start, end)) = range.split_once('-') else {
        return Some(Err("invalid range"));
    };
    let start = match start.parse::<usize>() {
        Ok(value) => value,
        Err(_) => return Some(Err("invalid range start")),
    };
    let end = if end.is_empty() {
        total_len.saturating_sub(1)
    } else {
        match end.parse::<usize>() {
            Ok(value) => value,
            Err(_) => return Some(Err("invalid range end")),
        }
    };
    if total_len == 0 || start > end || end >= total_len {
        return Some(Err("range is outside blob bounds"));
    }
    Some(Ok((start, end)))
}

pub(crate) const MAX_BLOB_UPLOAD_BYTES: usize = 10 * 1024 * 1024;
const MAX_BLOB_UPLOAD_FORM_BYTES: usize = MAX_BLOB_UPLOAD_BYTES + 64 * 1024;
const MAX_BLOB_ACCOUNT_BYTES: usize = 50 * 1024 * 1024;
const MAX_BLOB_REALM_BYTES: usize = 100 * 1024 * 1024;

fn sanitize_media_type(raw: &str) -> Option<String> {
    let media_type = raw.split(';').next()?.trim().to_ascii_lowercase();
    let (top, sub) = media_type.split_once('/')?;
    (is_valid_mime_token(top) && is_valid_mime_token(sub)).then_some(media_type)
}

fn infer_profile_avatar_media_type(bytes: &[u8]) -> Option<String> {
    if bytes.starts_with(&[0xff, 0xd8, 0xff]) {
        return Some("image/jpeg".to_owned());
    }
    if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
        return Some("image/png".to_owned());
    }
    if bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a") {
        return Some("image/gif".to_owned());
    }
    if bytes.len() >= 12 && bytes.starts_with(b"RIFF") && &bytes[8..12] == b"WEBP" {
        return Some("image/webp".to_owned());
    }
    None
}

fn is_valid_mime_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.chars().all(|ch| {
            ch.is_ascii_alphanumeric()
                || matches!(ch, '!' | '#' | '$' | '&' | '-' | '^' | '_' | '.' | '+')
        })
}

fn sanitize_blob_filename_value(value: &str) -> Result<String, &'static str> {
    let basename = value
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or_default()
        .trim()
        .trim_matches('"');
    let mut sanitized = String::new();
    for ch in basename.chars() {
        if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_') {
            sanitized.push(ch);
        } else if ch.is_ascii_whitespace() || ch.is_ascii_punctuation() {
            sanitized.push('_');
        }
        if sanitized.len() >= 128 {
            break;
        }
    }
    let sanitized = sanitized
        .trim_matches(|ch| matches!(ch, '.' | '_' | '-' | ' '))
        .to_owned();
    if sanitized.is_empty() {
        return Err("filename must contain at least one safe character");
    }
    Ok(sanitized)
}

pub(super) async fn enforce_blob_quota(
    state: &AppState,
    actor: &str,
    realm_id: Option<&str>,
    size: usize,
) -> Result<(), &'static str> {
    let blobs = state
        .deliveries()
        .blobs()
        .await
        .map_err(|_| "blob store unavailable")?;
    let actor_bytes: usize = blobs
        .iter()
        .filter(|blob| blob.uploaded_by == actor)
        .map(|blob| blob.size_bytes.max(0) as usize)
        .sum();
    if actor_bytes.saturating_add(size) > MAX_BLOB_ACCOUNT_BYTES {
        return Err("account blob quota exceeded");
    }
    if let Some(realm_id) = realm_id {
        let realm_bytes: usize = blobs
            .iter()
            .filter(|blob| blob.realm_id.as_deref() == Some(realm_id))
            .map(|blob| blob.size_bytes.max(0) as usize)
            .sum();
        if realm_bytes.saturating_add(size) > MAX_BLOB_REALM_BYTES {
            return Err("realm blob quota exceeded");
        }
    }
    Ok(())
}

/// What a download declares when it declares nothing.
///
/// The presign issuer has always defaulted this way; the download surface now
/// does too, so the two halves of one contract agree.
pub(super) const DEFAULT_BLOB_PURPOSE: &str = "download";

pub(super) fn is_valid_blob_purpose(value: &str) -> bool {
    let value = value.trim();
    !value.is_empty()
        && value.len() <= 64
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.' | ':'))
}

async fn blob_visible_to_session(
    state: &AppState,
    blob: &BlobRecord,
    session: &SessionRecord,
    requested_realm_id: Option<&str>,
) -> bool {
    let Ok(actor) =
        crate::routing::identity::session_actor::validated_session_actor(state, session).await
    else {
        return false;
    };
    // Upload ownership does not exempt an Agent's Realm content from its
    // current controller and management ceiling. Unscoped private uploads
    // retain the uploader's ordinary access contract.
    if blob.uploaded_by == session.actor
        && (session.agent_session().is_none() || blob.realm_id.is_none())
    {
        return blob.realm_id.as_deref().is_none_or(|realm_id| {
            requested_realm_id.is_none_or(|requested| requested == realm_id)
        });
    }

    let Some(realm_id) = blob.realm_id.as_deref() else {
        return false;
    };
    if requested_realm_id.is_some_and(|requested| requested != realm_id) {
        return false;
    }
    let Ok(realm_id) = RealmId::new(realm_id.to_owned()) else {
        return false;
    };
    state
        .authority_commits()
        .accepted_realm_reader(&realm_id, &actor)
        .await
        .unwrap_or(false)
}

async fn realm_presign_policy_block(
    state: &AppState,
    realm_id: Option<&str>,
) -> Option<&'static str> {
    let realm_id = realm_id?;
    let Some(meta) = state.realms().realm_metadata(realm_id).await.ok().flatten() else {
        return Some("direct_download_disallowed_presign_forbidden");
    };
    if meta.minimal_metadata_realm {
        return Some("minimal_metadata_presign_forbidden");
    }
    if !asset_privacy_policy_allows_direct_download(meta.asset_privacy_policy.as_ref()) {
        return Some("direct_download_disallowed_presign_forbidden");
    }
    None
}

fn asset_privacy_policy_allows_direct_download(policy: Option<&Value>) -> bool {
    policy
        .and_then(|value| value.get("direct_download_allowed"))
        .and_then(Value::as_bool)
        == Some(true)
}

// ────────────────────────────────────────────────────────────────────────
// Presign blob fail-closed gating (spec T11).
// ────────────────────────────────────────────────────────────────────────

/// Blob preflight classifier for presign endpoints. Spec T11.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PresignBlobBlock {
    /// Blob payload is end-to-end encrypted; presign would expose key
    /// material — refuse fail-closed.
    E2ee,
    /// Blob is currently subject to a legal hold.
    LegalHold,
    /// Blob has been redacted.
    Redacted,
    /// Blob is actor_private and the requester_id is not the owner.
    ActorPrivate,
    /// Blob is device_bound and this path has no bound-device verifier.
    DeviceBound,
}

impl PresignBlobBlock {
    pub fn as_error(self) -> AppError {
        match self {
            Self::E2ee => crate::app_error!(
                CapabilityDenied,
                "blob is end-to-end encrypted; presign is refused fail-closed",
            ),
            Self::LegalHold => crate::app_error!(
                FailedPrecondition,
                "blob is currently subject to a legal hold; presign refused",
            )
            .with_reason_code(arkret_wire::ReasonCode::LEGAL_HOLD_ACTIVE),
            Self::Redacted => crate::app_error!(
                FailedPrecondition,
                "blob has been redacted; presign refused",
            )
            .with_reason_code(arkret_wire::ReasonCode::BLOB_REDACTED),
            Self::ActorPrivate => crate::app_error!(
                CapabilityDenied,
                "blob is actor_private; only the owner may request a presign URL",
            ),
            Self::DeviceBound => crate::app_error!(
                CapabilityDenied,
                "blob is device_bound; direct download is refused fail-closed",
            ),
        }
    }
}

/// Inspect a blob record for any of the four fail-closed classes. Spec T11.
/// Returns the matching block reason or `None`.
///
/// The blob record is taken as a JSON value so this fn stays decoupled
/// from the application blob state; presign callers pass
/// `serde_json::to_value(&record)` (cheap — BlobRecord is small).
pub fn classify_presign_blob_block(
    blob: &Value,
    requester_actor: &str,
) -> Option<PresignBlobBlock> {
    // E2EE: any encryption metadata present.
    if blob.get("encryption").is_some_and(|v| !v.is_null()) {
        return Some(PresignBlobBlock::E2ee);
    }
    // Legal hold flag.
    if blob.get("legal_hold").and_then(Value::as_bool) == Some(true) {
        return Some(PresignBlobBlock::LegalHold);
    }
    // Redaction.
    if blob.get("redacted").and_then(Value::as_bool) == Some(true) {
        return Some(PresignBlobBlock::Redacted);
    }
    match blob.get("visibility").and_then(Value::as_str) {
        Some("actor_private") => {
            let owner = blob
                .get("uploaded_by")
                .and_then(Value::as_str)
                .unwrap_or("");
            if owner != requester_actor {
                return Some(PresignBlobBlock::ActorPrivate);
            }
        }
        Some("device_bound") => return Some(PresignBlobBlock::DeviceBound),
        _ => {}
    }
    None
}

/// Response headers that MUST be set on presign responses. Spec T11.
///
/// Per spec: presign URLs are short-lived bearer tokens; intermediaries
/// MUST NOT cache them and the referring page MUST NOT leak the URL.
pub const PRESIGN_CACHE_CONTROL: &str = "private, no-store";
pub const PRESIGN_REFERRER_POLICY: &str = "no-referrer";

#[cfg(test)]
mod presign_block_tests {
    use super::*;

    #[test]
    fn presign_blob_e2ee_blocked() {
        let blob = json!({"encryption": {"scheme": "ak.blob.whole_file_aead.v1"}, "uploaded_by": "ak:did_core:web:alice.example"});
        assert_eq!(
            classify_presign_blob_block(&blob, "ak:did_core:web:alice.example"),
            Some(PresignBlobBlock::E2ee)
        );
    }

    #[test]
    fn presign_blob_legal_hold_blocked() {
        let blob = json!({"legal_hold": true, "uploaded_by": "ak:did_core:web:alice.example"});
        assert_eq!(
            classify_presign_blob_block(&blob, "ak:did_core:web:alice.example"),
            Some(PresignBlobBlock::LegalHold)
        );
    }

    #[test]
    fn presign_blob_redacted_blocked() {
        let blob = json!({"redacted": true, "uploaded_by": "ak:did_core:web:alice.example"});
        assert_eq!(
            classify_presign_blob_block(&blob, "ak:did_core:web:alice.example"),
            Some(PresignBlobBlock::Redacted)
        );
    }

    #[test]
    fn presign_blob_actor_private_blocked_for_non_owner() {
        let blob =
            json!({"visibility": "actor_private", "uploaded_by": "ak:did_core:web:alice.example"});
        assert_eq!(
            classify_presign_blob_block(&blob, "ak:did_core:web:bob.example"),
            Some(PresignBlobBlock::ActorPrivate)
        );
        assert_eq!(
            classify_presign_blob_block(&blob, "ak:did_core:web:alice.example"),
            None
        );
    }

    #[test]
    fn presign_blob_device_bound_blocked() {
        let blob =
            json!({"visibility": "device_bound", "uploaded_by": "ak:did_core:web:alice.example"});
        assert_eq!(
            classify_presign_blob_block(&blob, "ak:did_core:web:alice.example"),
            Some(PresignBlobBlock::DeviceBound)
        );
    }

    #[test]
    fn asset_privacy_policy_direct_download_is_explicit_opt_in() {
        assert!(super::asset_privacy_policy_allows_direct_download(Some(
            &json!({"direct_download_allowed": true})
        )));
        assert!(!super::asset_privacy_policy_allows_direct_download(Some(
            &json!({"direct_download_allowed": false})
        )));
        assert!(!super::asset_privacy_policy_allows_direct_download(Some(
            &json!({"value": {"direct_download_allowed": true}})
        )));
        assert!(!super::asset_privacy_policy_allows_direct_download(Some(
            &json!({"future_policy_field": true})
        )));
        assert!(!super::asset_privacy_policy_allows_direct_download(None));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn agent_uploaded_realm_blob_cannot_bypass_unavailable_current_reader() {
        let state = AppState::new(
            crate::config::AppConfig::test_default(),
            coland_storage_postgres::Db { pool: None },
        );
        let session = SessionRecord {
            token_hash: "blob-agent-current-fixture".into(),
            account_pk: None,
            actor: "ak:did_core:web:blob-agent.example".into(),
            endpoint: coland_services::identity::SessionEndpointState::AgentRuntime {
                state: coland_services::identity::AgentSessionState {
                    granted_scope: Vec::new(),
                    scope_details: json!({}),
                    freshness_state: arkret_wire::FreshnessState::Fresh,
                },
            },
            audience: state.service_id().clone(),
            session_public_key: None,
            session_grant: None,
            expires_at: now() + chrono::Duration::minutes(5),
            created_at: now(),
            revoked_at: None,
        };
        let mut blob = blob_record("application/octet-stream", None);
        blob.uploaded_by = session.actor.clone();
        assert!(!blob_visible_to_session(&state, &blob, &session, blob.realm_id.as_deref()).await);
        // A private upload is not a substitute for Realm or group content.
        blob.realm_id = None;
        assert!(blob_visible_to_session(&state, &blob, &session, None).await);
    }

    /// Realm membership itself is the durable accepted reader of the Realm
    /// (PostgreSQL `accepted_realm_reader`); a session bound to another
    /// Station never reaches it.
    #[tokio::test]
    async fn blob_membership_needs_a_session_of_this_station() {
        let state = AppState::new(
            crate::config::AppConfig::test_default(),
            coland_storage_postgres::Db { pool: None },
        );
        let principal = DidCoreId::new("ak:did_core:web:blob-owner.example").unwrap();
        let session = SessionRecord {
            token_hash: "blob-membership-fixture".to_owned(),
            account_pk: None,
            actor: principal.to_string(),
            endpoint: coland_services::identity::SessionEndpointState::HumanDevice {
                device_id: "ak:device:01904100-0000-7000-8000-000000000071".to_owned(),
            },
            audience: "ak:did_core:web:other-station.example".to_owned(),
            session_public_key: None,
            session_grant: None,
            expires_at: now() + chrono::Duration::minutes(5),
            created_at: now(),
            revoked_at: None,
        };
        let realm_id = "ak:realm:AZAySZA7XRDeJ9cO4MqaDWrJD-rqPk6Cudk7CCzsDQz1";
        let mut blob = blob_record("text/plain", None);
        assert!(!blob_visible_to_session(&state, &blob, &session, Some(realm_id)).await);
        blob.uploaded_by = session.actor.clone();
        assert!(!blob_visible_to_session(&state, &blob, &session, Some(realm_id)).await);
        assert!(
            blob_session_has_realm_membership(&state, realm_id, &session)
                .await
                .is_err()
        );
    }

    /// Original local development bearer path: lifecycle refusal is checked
    /// before device/current lookup. This is not normal Agent OAuth evidence.
    #[tokio::test]
    async fn blob_existing_session_lifecycle_refusal_preserves_registered_code() {
        use salvo::test::{ResponseExt as _, TestClient};
        let mut config = crate::config::AppConfig::test_default();
        config.development_mode = true;
        let state = AppState::new(config, coland_storage_postgres::Db { pool: None });
        let actor = DidCoreId::new("ak:did_core:web:blob-lifecycle.example").unwrap();
        let identity = state
            .identities()
            .register_account(coland_services::identity::RegisterAccountCommand {
                account_id: arkret_wire::AccountId::new(actor.clone(), state.service_core_id()),
                localpart: "blob_lifecycle".to_owned(),
                display_name: None,
                created_at: now(),
            })
            .await
            .unwrap();
        let token = "original-local-blob-session";
        let token_hash =
            crate::routing::identity::auth::session_credential_hash(token, state.service_id());
        let session = SessionRecord {
            token_hash: token_hash.clone(),
            account_pk: Some(identity.account_pk),
            actor: actor.to_string(),
            endpoint: coland_services::identity::SessionEndpointState::HumanDevice {
                device_id: "ak:device:01904100-0000-7000-8000-000000000071".to_owned(),
            },
            audience: state.service_id().to_string(),
            session_public_key: None,
            session_grant: None,
            expires_at: now() + chrono::Duration::minutes(5),
            created_at: now(),
            revoked_at: None,
        };
        state.sessions().create_session(session).await.unwrap();
        let service = crate::service(state.clone());
        for (status, code) in [
            ("soft_logged_out", crate::error::ErrorCode::SoftLoggedOut),
            ("locked", crate::error::ErrorCode::AccountLocked),
            ("deactivated", crate::error::ErrorCode::AccountDeactivated),
            ("erasure_pending", crate::error::ErrorCode::AccountErased),
        ] {
            let lifecycle = coland_services::identity::AccountLifecycleState {
                state: status.to_owned(),
                reason: None,
                changed_by: None,
                changed_at: now(),
            };
            state
                .identities()
                .save_account_lifecycle(identity.account_pk, actor.as_str(), lifecycle)
                .await
                .unwrap();
            let before = state.identities().account_lifecycles_snapshot();
            let mut response = TestClient::get("http://server/_arkret/self/blob/get?blob_ref=sha256:0000000000000000000000000000000000000000000000000000000000000000")
                .add_header("Authorization", format!("Bearer {token}"), true)
                .add_header("Arkret-Operation", arkret_wire::ServiceOperationId::SELF_BLOB_RESOURCE_GET_V1, true)
                .send(&service).await;
            assert_eq!(response.status_code, Some(StatusCode::UNAUTHORIZED));
            for protected in [
                "digest",
                "content-range",
                "content-disposition",
                "accept-ranges",
            ] {
                assert!(!response.headers().contains_key(protected));
            }
            let problem: arkret_wire::Problem = response.take_json().await.unwrap();
            assert_eq!(problem.error_code(), Some(code));
            assert!(problem.extensions.is_empty());
            let after = state.identities().account_lifecycles_snapshot();
            assert_eq!(before.len(), after.len());
            for ((before_actor, before), (after_actor, after)) in before.iter().zip(&after) {
                assert_eq!(before_actor, after_actor);
                assert_eq!(before.state, after.state);
                assert_eq!(before.reason, after.reason);
                assert_eq!(before.changed_by, after.changed_by);
                assert_eq!(before.changed_at, after.changed_at);
            }
            assert!(
                state
                    .sessions()
                    .session(&token_hash)
                    .await
                    .unwrap()
                    .is_some()
            );
        }
    }

    fn blob_record(media_type: &str, filename: Option<&str>) -> BlobRecord {
        BlobRecord {
            sha256: "0".repeat(64),
            size_bytes: 1,
            storage_backend: "memory".to_owned(),
            storage_key: "sha256/test".to_owned(),
            media_type: media_type.to_owned(),
            filename: filename.map(ToOwned::to_owned),
            realm_id: Some("ak:realm:AZAySZA7XRDeJ9cO4MqaDWrJD-rqPk6Cudk7CCzsDQz1".to_owned()),
            encryption: None,
            legal_hold: false,
            redacted: false,
            visibility: BlobVisibility::RealmBound,
            uploaded_by: "ak:did_core:web:alice.example".to_owned(),
            created_at: now(),
        }
    }

    #[test]
    fn content_disposition_for_message_attachment_sanitizes_filename() {
        let blob = blob_record("text/plain", Some("..\\report final.txt"));
        assert_eq!(
            blob_content_disposition(&blob, "message_attachment").as_deref(),
            Some("attachment; filename=\"report_final.txt\"")
        );
    }

    #[test]
    fn content_disposition_for_safe_profile_avatar_can_inline() {
        let blob = blob_record("image/png", Some("avatar.png"));
        assert_eq!(
            blob_content_disposition(&blob, "profile_avatar").as_deref(),
            Some("inline; filename=\"avatar.png\"")
        );
    }

    #[test]
    fn content_disposition_for_dangerous_profile_avatar_forces_attachment() {
        let blob = blob_record("image/svg+xml", Some("avatar.svg"));
        assert_eq!(
            blob_content_disposition(&blob, "profile_avatar").as_deref(),
            Some("attachment; filename=\"avatar.svg\"")
        );
    }

    #[test]
    fn upload_encryption_is_a_closed_registered_classification() {
        assert!(parse_blob_storage_encryption("null").unwrap().is_none());
        assert!(
            parse_blob_storage_encryption(r#"{"scheme":"ak.blob.whole_file_aead.v1"}"#)
                .unwrap()
                .is_some()
        );
        assert!(
            parse_blob_storage_encryption(r#"{"scheme":"ak.blob.stream_aead.v1"}"#)
                .unwrap()
                .is_some()
        );
        for invalid in [
            "",
            "{}",
            "true",
            r#"{"scheme":"unknown"}"#,
            r#"{"scheme":"ak.blob.stream_aead.v1","key_ref":"secret"}"#,
        ] {
            assert!(parse_blob_storage_encryption(invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn upload_media_type_follows_the_request_body_pattern() {
        assert!(is_valid_blob_upload_media_type("application/octet-stream"));
        assert!(is_valid_blob_upload_media_type("image/svg+xml"));
        assert!(!is_valid_blob_upload_media_type(
            "text/plain; charset=utf-8"
        ));
        assert!(!is_valid_blob_upload_media_type("Text/Plain"));
        assert!(!is_valid_blob_upload_media_type("text/"));
        assert!(!is_valid_blob_upload_media_type("text"));
    }

    #[test]
    fn declared_content_digest_is_checked_under_its_own_suite() {
        let bytes = b"public group info";
        let sha256 = canonical::digest_with_suite("sha256", bytes).unwrap();
        let blake3 = canonical::digest_with_suite("blake3", bytes).unwrap();
        assert!(is_valid_blob_upload_content_digest(&sha256));
        assert!(is_valid_blob_upload_content_digest(&blake3));
        assert!(blob_content_digest_matches(&sha256, bytes));
        assert!(blob_content_digest_matches(&blake3, bytes));
        assert!(!blob_content_digest_matches(&sha256, b"other bytes"));
        assert!(!is_valid_blob_upload_content_digest(&format!(
            "sha512:{}",
            "0".repeat(64)
        )));
        assert!(!is_valid_blob_upload_content_digest(&format!(
            "sha256:{}",
            "A".repeat(64)
        )));
    }

    #[test]
    fn profile_avatar_media_type_inference_accepts_only_safe_image_types() {
        assert_eq!(
            infer_profile_avatar_media_type(&[0xff, 0xd8, 0xff, 0xdb]).as_deref(),
            Some("image/jpeg")
        );
        assert_eq!(
            infer_profile_avatar_media_type(b"\x89PNG\r\n\x1a\nrest").as_deref(),
            Some("image/png")
        );
        assert_eq!(
            infer_profile_avatar_media_type(b"GIF89arest").as_deref(),
            Some("image/gif")
        );
        assert_eq!(
            infer_profile_avatar_media_type(b"RIFF\x00\x00\x00\x00WEBPrest").as_deref(),
            Some("image/webp")
        );
        assert_eq!(infer_profile_avatar_media_type(b"<svg></svg>"), None);
    }
}
