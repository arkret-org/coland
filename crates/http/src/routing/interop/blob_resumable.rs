//! Resumable (tus 1.0.0) blob upload binding.
//!
//! Spec: crypto-media/media-and-blob.md §2.1 — a per-operation HTTP
//! companion binding of `ak.self.blob.upload.create.v1`. tus carries the bytes
//! (create / PATCH / HEAD / DELETE with offset resume); a completed upload is
//! finalized into a canonical blob with the same `blob_ref` /
//! `content_digest` / `upload_receipt` the multipart path produces.
//!
//! The tus wire protocol is implemented locally instead of via the
//! `salvo-tus` crate: salvo-tus 0.93.0 keeps its `stores` module private,
//! so neither the staging directory nor the upload state needed by
//! completion is reachable from outside the crate. The subset below is
//! wire-compatible with tus 1.0.0 core plus the `creation`,
//! `creation-with-upload`, `termination` and `expiration` extensions.
//!
//! Surfaces (all under `/_arkret/self/blob/resumable`):
//! - `OPTIONS /`              — tus capability probe (no auth; endpoint-level confirmation only,
//!   discovery is `/_arkret/describe`)
//! - `POST    /`              — create an upload resource (`Upload-Length` required; optional
//!   `application/offset+octet-stream` body for creation-with-upload)
//! - `HEAD    /{id}`          — query `Upload-Offset` to resume
//! - `PATCH   /{id}`          — append a chunk at `Upload-Offset`
//! - `POST    /{id}/finalize` — complete an upload whose offset reached `Upload-Length`
//! - `DELETE  /{id}`          — terminate an in-progress upload
//!
//! Upload-Metadata keys understood at completion time are the
//! `blob_upload_request_body` members `encryption`, `realm_id` and
//! `content_digest`, validated exactly as on the canonical upload. Per spec
//! §2.1 privacy rules, plaintext filenames and MIME types of private/E2EE
//! blobs MUST NOT appear in `Upload-Metadata`, so the completion path stores
//! every resumable blob as `application/octet-stream` with no filename.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use coland_services::delivery::BlobState as BlobRecord;
use salvo::http::{HeaderValue, StatusCode};
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use tokio::io::AsyncReadExt as _;

use super::blob::{
    MAX_BLOB_UPLOAD_BYTES, blob_content_digest_matches, blob_session_has_realm_membership,
    blob_upload_response_body, enforce_blob_quota, is_valid_blob_upload_content_digest,
    parse_blob_storage_encryption, validate_existing_blob_classification,
};
use super::{auth_or_render, now, render_error};
use crate::state::AppState;

mod staged_owner;
use staged_owner::{OwnerGuard, io as owner_io};

pub const TUS_VERSION: &str = "1.0.0";
/// Protocol versions / extensions advertised both on the `OPTIONS` probe
/// and in `/_arkret/describe` `transport_bindings[kind="tus"]` — the
/// describe claim and the wire probe MUST agree.
pub const TUS_VERSIONS: &[&str] = &["1.0.0"];
pub const TUS_EXTENSIONS: &[&str] = &[
    "creation",
    "creation-with-upload",
    "termination",
    "expiration",
];

const H_TUS_RESUMABLE: &str = "tus-resumable";
const H_TUS_VERSION: &str = "tus-version";
const H_TUS_EXTENSION: &str = "tus-extension";
const H_TUS_MAX_SIZE: &str = "tus-max-size";
const H_UPLOAD_LENGTH: &str = "upload-length";
const H_UPLOAD_OFFSET: &str = "upload-offset";
const H_UPLOAD_METADATA: &str = "upload-metadata";
const H_UPLOAD_EXPIRES: &str = "upload-expires";
const H_UPLOAD_DEFER_LENGTH: &str = "upload-defer-length";
const CT_OFFSET_OCTET_STREAM: &str = "application/offset+octet-stream";

pub(super) fn router() -> Router {
    Router::new()
        .push(
            Router::with_path("blob/resumable")
                .options(tus_options)
                .post(tus_create),
        )
        .push(
            Router::with_path("blob/resumable/{id}")
                .options(tus_options)
                .head(tus_head)
                .patch(tus_patch)
                .delete(tus_delete),
        )
        .push(Router::with_path("blob/resumable/{id}/finalize").post(tus_finalize))
}

/// Staging-file metadata for one in-progress upload. Internal to this
/// node (never wire-visible); written atomically (`.tmp` + rename) next
/// to the byte file as `{id}.json` / `{id}.bin`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StagedUpload {
    upload_id: String,
    declared_size_bytes: u64,
    offset_bytes: u64,
    /// Decoded `Upload-Metadata` key/value pairs from creation time.
    upload_metadata: HashMap<String, Option<String>>,
    /// The authenticated complete creator; principal equality alone never
    /// selects another hosting Account or an Agent controller.
    created_by: arkret_wire::ActorId,
    created_at: String,
    expires_at: String,
}

fn data_path(dir: &Path, id: &str) -> PathBuf {
    dir.join(format!("{id}.bin"))
}

fn meta_path(dir: &Path, id: &str) -> PathBuf {
    dir.join(format!("{id}.json"))
}

fn is_safe_upload_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_'))
}

fn read_meta(dir: &Path, id: &str) -> std::io::Result<Option<StagedUpload>> {
    let raw = match std::fs::read(meta_path(dir, id)) {
        Ok(raw) => raw,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    serde_json::from_slice(&raw)
        .map(Some)
        .map_err(std::io::Error::other)
}

fn write_meta_atomic(dir: &Path, meta: &StagedUpload) -> std::io::Result<()> {
    use std::io::Write as _;
    let tmp = dir.join(format!("{}.json.tmp", meta.upload_id));
    let bytes = arkret_canonical::canonical_json_bytes(meta)
        .map_err(|error| std::io::Error::other(error.to_string()))?;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&tmp)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    std::fs::rename(tmp, meta_path(dir, &meta.upload_id))
}

fn remove_staged(dir: &Path, id: &str) -> std::io::Result<()> {
    for path in [
        data_path(dir, id),
        meta_path(dir, id),
        dir.join(format!("{id}.json.tmp")),
    ] {
        match std::fs::remove_file(path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn create_staged(dir: &Path, meta: &StagedUpload, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(data_path(dir, &meta.upload_id))?;
    file.write_all(bytes)?;
    file.sync_all()?;
    write_meta_atomic(dir, meta)
}

fn append_staged(dir: &Path, meta: &mut StagedUpload, chunk: &[u8]) -> std::io::Result<()> {
    use std::io::{Seek as _, Write as _};
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .open(data_path(dir, &meta.upload_id))?;
    if file.metadata()?.len() < meta.offset_bytes {
        return Err(std::io::Error::other(
            "staged body is shorter than its committed offset",
        ));
    }
    // An interrupted previous append may have no metadata acknowledgment.
    // Recover only the unaccepted tail, under the same actual native owner.
    file.set_len(meta.offset_bytes)?;
    file.seek(std::io::SeekFrom::Start(meta.offset_bytes))?;
    let old_offset = meta.offset_bytes;
    file.write_all(chunk)?;
    file.sync_all()?;
    meta.offset_bytes = old_offset + chunk.len() as u64;
    if let Err(error) = write_meta_atomic(dir, meta) {
        file.set_len(old_offset)?;
        file.sync_all()?;
        return Err(error);
    }
    Ok(())
}

fn render_owner_io(res: &mut Response, error: std::io::Error) {
    let busy = error.kind() == std::io::ErrorKind::WouldBlock;
    render_error(
        res,
        if busy {
            StatusCode::SERVICE_UNAVAILABLE
        } else {
            StatusCode::INTERNAL_SERVER_ERROR
        },
        if busy {
            "temporarily_unavailable"
        } else {
            "internal_error"
        },
        &error.to_string(),
    );
}

async fn request_owner(
    state: &AppState,
    session: &coland_services::identity::SessionIdentityState,
    req: &Request,
    res: &mut Response,
) -> Option<(arkret_wire::ActorId, Option<OwnerGuard>)> {
    let actor = match crate::routing::identity::session_actor::validated_session_actor(
        state, session,
    )
    .await
    {
        Ok(actor) => actor,
        Err(error) => {
            render_error(res, error.http_status(), error.wire_code(), &error.message);
            return None;
        }
    };
    // This actual router accepts Station sessions. It has no native
    // RealmDevice credential hoop and does not invent one from a principal.
    let Some(account) = actor.as_account_id() else {
        render_error(
            res,
            StatusCode::NOT_FOUND,
            "not_found",
            "native upload owner is unavailable",
        );
        return None;
    };
    let guard = match OwnerGuard::acquire(
        state.config().resumable_upload_dir.clone(),
        actor.clone(),
        true,
        true,
    )
    .await
    {
        Ok(Some(guard)) => guard,
        Ok(None) => {
            render_error(
                res,
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily_unavailable",
                "native upload owner is unavailable",
            );
            return None;
        }
        Err(error) => {
            render_owner_io(res, error);
            return None;
        }
    };
    // Keep no PG lock through external IO. The actual OS owner below covers
    // disconnect/cancellation; E first commits its native negative projection
    // and then drains this owner without any PG lock held.
    if let Err(error) = state
        .persistence()
        .require_private_account_owner(account)
        .await
    {
        let code = error
            .conflict_code()
            .and_then(|code| arkret_wire::ErrorCode::from_wire(code.as_str()))
            .unwrap_or(arkret_wire::ErrorCode::InternalError);
        let mut refusal = crate::error::AppError::from_rejection(code, error.to_string());
        if matches!(
            code,
            arkret_wire::ErrorCode::AccountErased | arkret_wire::ErrorCode::AccountDeactivated
        ) {
            refusal =
                refusal.with_status_context(arkret_wire::ErrorStatusContext::ProtectedResource);
        }
        render_error(
            res,
            refusal.http_status(),
            refusal.wire_code(),
            &refusal.message,
        );
        return None;
    }
    // This reuses the existing original-credential/current-native verifier.
    // It cannot replace an old holder, scope, Account or expiry, and it does
    // not consume/replay the already verified DPoP presentation a second time.
    let grant_secret = coland_http::util::dpop_token(req);
    if let Err((status, code, message)) =
        crate::routing::identity::auth::revalidate_current_read_session(
            state,
            session,
            grant_secret,
        )
        .await
    {
        render_error(res, status, code, message);
        return None;
    }
    Some((actor, Some(guard)))
}

fn is_expired(meta: &StagedUpload) -> bool {
    arkret_canonical::parse_timestamp_canonical(&meta.expires_at)
        .map(|expires| expires < chrono::Utc::now())
        .unwrap_or(true)
}

fn http_date(rfc3339: &str) -> Option<String> {
    arkret_canonical::parse_timestamp_canonical(rfc3339)
        .ok()
        .map(|t| t.format("%a, %d %b %Y %H:%M:%S GMT").to_string())
}

fn set_tus_header(res: &mut Response) {
    res.headers_mut()
        .insert(H_TUS_RESUMABLE, HeaderValue::from_static(TUS_VERSION));
}

/// Every non-OPTIONS tus request MUST carry `Tus-Resumable: 1.0.0`;
/// other versions get `412` plus the supported version list.
fn check_tus_version(req: &Request, res: &mut Response) -> bool {
    match req
        .headers()
        .get(H_TUS_RESUMABLE)
        .and_then(|value| value.to_str().ok())
    {
        Some(TUS_VERSION) => true,
        _ => {
            res.headers_mut()
                .insert(H_TUS_VERSION, HeaderValue::from_static(TUS_VERSION));
            set_tus_header(res);
            res.status_code(StatusCode::PRECONDITION_FAILED);
            false
        }
    }
}

/// Parse a tus `Upload-Metadata` header: comma-separated entries of
/// `key` or `key <base64 value>`; keys must be unique ASCII without
/// spaces/commas.
fn parse_upload_metadata(raw: &str) -> Result<HashMap<String, Option<String>>, &'static str> {
    let mut map = HashMap::new();
    for item in raw.split(',') {
        let item = item.trim();
        if item.is_empty() {
            return Err("empty Upload-Metadata entry");
        }
        let mut tokens = item.splitn(2, ' ');
        let key = tokens.next().unwrap_or_default();
        if key.is_empty()
            || key.len() > 64
            || !key
                .chars()
                .all(|ch| ch.is_ascii_graphic() && ch != ',' && ch != ';')
        {
            return Err("invalid Upload-Metadata key");
        }
        if map.contains_key(key) {
            return Err("duplicate Upload-Metadata key");
        }
        match tokens.next() {
            None => {
                map.insert(key.to_owned(), None);
            }
            Some(value) => {
                let decoded = BASE64_STANDARD
                    .decode(value.trim())
                    .map_err(|_| "Upload-Metadata value must be base64")?;
                if BASE64_STANDARD.encode(&decoded) != value.trim() {
                    return Err("Upload-Metadata value must use standard base64");
                }
                let decoded = String::from_utf8(decoded)
                    .map_err(|_| "Upload-Metadata value must be UTF-8")?;
                if decoded.len() > 512 {
                    return Err("Upload-Metadata value too long");
                }
                map.insert(key.to_owned(), Some(decoded));
            }
        }
    }
    Ok(map)
}

#[handler]
#[tracing::instrument(skip_all, fields(op = "org.arkret.coland.blob.resumable.options"))]
async fn tus_options(res: &mut Response) {
    set_tus_header(res);
    let headers = res.headers_mut();
    headers.insert(
        H_TUS_VERSION,
        HeaderValue::from_str(&TUS_VERSIONS.join(",")).expect("static version list"),
    );
    headers.insert(
        H_TUS_EXTENSION,
        HeaderValue::from_str(&TUS_EXTENSIONS.join(",")).expect("static extension list"),
    );
    headers.insert(
        H_TUS_MAX_SIZE,
        HeaderValue::from_str(&MAX_BLOB_UPLOAD_BYTES.to_string()).expect("numeric header"),
    );
    res.status_code(StatusCode::NO_CONTENT);
}

fn validate_upload_metadata(
    metadata: &HashMap<String, Option<String>>,
) -> Result<(), &'static str> {
    if metadata.keys().any(|key| {
        !matches!(
            key.as_str(),
            "encryption" | "realm_id" | "content_digest" | "size_bytes"
        )
    }) {
        return Err("unknown or private Upload-Metadata member");
    }
    let encryption = metadata
        .get("encryption")
        .and_then(Option::as_deref)
        .ok_or("Upload-Metadata encryption is required")?;
    let classification = parse_blob_storage_encryption(encryption)?;
    let canonical = arkret_canonical::canonical_json_bytes(&classification)
        .map_err(|_| "invalid encryption classification")?;
    if canonical != encryption.as_bytes() {
        return Err("Upload-Metadata encryption must be canonical JSON");
    }
    for (key, value) in metadata {
        let value = value
            .as_deref()
            .ok_or("Upload-Metadata fields require a value")?;
        match key.as_str() {
            "realm_id" if arkret_identifiers::RealmId::new(value.to_owned()).is_err() => {
                return Err("invalid Upload-Metadata realm_id");
            }
            "content_digest" if !is_valid_blob_upload_content_digest(value) => {
                return Err("invalid Upload-Metadata content_digest");
            }
            "size_bytes"
                if value
                    .parse::<u64>()
                    .ok()
                    .is_none_or(|size| size.to_string() != value) =>
            {
                return Err("invalid Upload-Metadata size_bytes");
            }
            _ => (),
        }
    }
    Ok(())
}

#[handler]
#[tracing::instrument(skip_all, fields(op = "org.arkret.coland.blob.resumable.create"))]
async fn tus_create(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let Some(session) = auth_or_render(state, req, res).await else {
        return;
    };
    if !check_tus_version(req, res) {
        return;
    }
    set_tus_header(res);
    if req.headers().get(H_UPLOAD_DEFER_LENGTH).is_some() {
        // creation-defer-length is not advertised in TUS_EXTENSIONS.
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "param_invalid",
            "Upload-Defer-Length is not supported; declare Upload-Length",
        );
        return;
    }
    let Some(declared_size) = req
        .headers()
        .get(H_UPLOAD_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.trim().parse::<u64>().ok())
    else {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "param_missing",
            "Upload-Length is required",
        );
        return;
    };
    if declared_size as usize > MAX_BLOB_UPLOAD_BYTES {
        res.headers_mut().insert(
            H_TUS_MAX_SIZE,
            HeaderValue::from_str(&MAX_BLOB_UPLOAD_BYTES.to_string()).expect("numeric header"),
        );
        render_error(
            res,
            StatusCode::PAYLOAD_TOO_LARGE,
            "payload_too_large",
            "blob exceeds maximum size",
        );
        return;
    }
    let upload_metadata = match req
        .headers()
        .get(H_UPLOAD_METADATA)
        .and_then(|value| value.to_str().ok())
    {
        Some(raw) => match parse_upload_metadata(raw) {
            Ok(metadata) => metadata,
            Err(message) => {
                render_error(
                    res,
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "schema_violation",
                    message,
                );
                return;
            }
        },
        None => HashMap::new(),
    };

    if let Err(message) = validate_upload_metadata(&upload_metadata) {
        render_error(
            res,
            StatusCode::UNPROCESSABLE_ENTITY,
            "schema_violation",
            message,
        );
        return;
    }
    if upload_metadata
        .get("size_bytes")
        .and_then(Option::as_deref)
        .is_some_and(|value| value.parse::<u64>().ok() != Some(declared_size))
    {
        render_error(
            res,
            StatusCode::UNPROCESSABLE_ENTITY,
            "schema_violation",
            "Upload-Metadata size_bytes disagrees with Upload-Length",
        );
        return;
    }
    let upload_id = uuid::Uuid::new_v4().simple().to_string();
    let created_at = arkret_canonical::format_timestamp_canonical(now());
    let expires_at = arkret_canonical::format_timestamp_canonical(
        chrono::Utc::now()
            + chrono::Duration::seconds(
                state.config().resumable_upload_incomplete_ttl_seconds as i64,
            ),
    );
    // creation-with-upload: an offset+octet-stream body on POST carries
    // the first chunk in the same request.
    let mut initial_bytes: Vec<u8> = Vec::new();
    let has_creation_body = req
        .headers()
        .get("content-type")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|ct| ct.starts_with(CT_OFFSET_OCTET_STREAM));
    if has_creation_body {
        req.set_secure_max_size(MAX_BLOB_UPLOAD_BYTES + 64 * 1024);
        match req.payload().await {
            Ok(bytes) => initial_bytes = bytes.to_vec(),
            Err(_) => {
                render_error(
                    res,
                    StatusCode::BAD_REQUEST,
                    "json_invalid",
                    "invalid creation-with-upload body",
                );
                return;
            }
        }
        if initial_bytes.len() as u64 > declared_size {
            render_error(
                res,
                StatusCode::PAYLOAD_TOO_LARGE,
                "payload_too_large",
                "creation-with-upload body exceeds Upload-Length",
            );
            return;
        }
    }
    let Some((creator, mut owner)) = request_owner(state, &session, req, res).await else {
        return;
    };
    let mut meta = StagedUpload {
        upload_id: upload_id.clone(),
        declared_size_bytes: declared_size,
        offset_bytes: 0,
        upload_metadata,
        created_by: creator.clone(),
        created_at,
        expires_at: expires_at.clone(),
    };

    meta.offset_bytes = initial_bytes.len() as u64;
    let stored = meta.clone();
    if let Err(error) = owner_io(&mut owner, move |dir| {
        create_staged(dir, &stored, &initial_bytes)
    })
    .await
    {
        render_owner_io(res, error);
        return;
    }

    // Relative Location — clients resolve it against the request URL. The
    // absolute base is already known from
    // `describe.transport_bindings[kind="tus"].base_url`.
    let location = format!("/_arkret/self/blob/resumable/{upload_id}");
    let headers = res.headers_mut();
    headers.insert(
        "location",
        HeaderValue::from_str(&location).expect("safe upload id path"),
    );
    if has_creation_body {
        headers.insert(
            H_UPLOAD_OFFSET,
            HeaderValue::from_str(&meta.offset_bytes.to_string()).expect("numeric header"),
        );
    }
    if let Some(expires) = http_date(&expires_at) {
        headers.insert(
            H_UPLOAD_EXPIRES,
            HeaderValue::from_str(&expires).expect("formatted date"),
        );
    }
    res.status_code(StatusCode::CREATED);
}

/// Load + gate one staged upload for the authenticated session. Expired
/// and foreign-actor resources answer `404` exactly like missing ones so
/// upload ids cannot be probed across accounts.
async fn load_gated(
    res: &mut Response,
    id: &str,
    actor: &arkret_wire::ActorId,
    owner: &mut Option<OwnerGuard>,
) -> Option<StagedUpload> {
    let not_found = |res: &mut Response| {
        render_error(
            res,
            StatusCode::NOT_FOUND,
            "not_found",
            "resumable upload not found or expired",
        )
    };
    if !is_safe_upload_id(id) {
        not_found(res);
        return None;
    }
    let selected = id.to_owned();
    let meta = match owner_io(owner, move |dir| read_meta(dir, &selected)).await {
        Ok(Some(meta)) => meta,
        Ok(None) => {
            not_found(res);
            return None;
        }
        Err(error) => {
            render_owner_io(res, error);
            return None;
        }
    };
    if &meta.created_by != actor || meta.upload_id != id {
        not_found(res);
        return None;
    }
    if is_expired(&meta) {
        let selected = id.to_owned();
        if let Err(error) = owner_io(owner, move |dir| remove_staged(dir, &selected)).await {
            render_owner_io(res, error);
            return None;
        }
        not_found(res);
        return None;
    }
    Some(meta)
}

#[handler]
#[tracing::instrument(skip_all, fields(op = "org.arkret.coland.blob.resumable.head"))]
async fn tus_head(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let Some(session) = auth_or_render(state, req, res).await else {
        return;
    };
    if !check_tus_version(req, res) {
        return;
    }
    set_tus_header(res);
    let id = req.param::<String>("id").unwrap_or_default();
    let Some((creator, mut owner)) = request_owner(state, &session, req, res).await else {
        return;
    };
    let Some(meta) = load_gated(res, &id, &creator, &mut owner).await else {
        return;
    };
    let headers = res.headers_mut();
    headers.insert(
        H_UPLOAD_OFFSET,
        HeaderValue::from_str(&meta.offset_bytes.to_string()).expect("numeric header"),
    );
    headers.insert(
        H_UPLOAD_LENGTH,
        HeaderValue::from_str(&meta.declared_size_bytes.to_string()).expect("numeric header"),
    );
    if let Some(expires) = http_date(&meta.expires_at) {
        headers.insert(
            H_UPLOAD_EXPIRES,
            HeaderValue::from_str(&expires).expect("formatted date"),
        );
    }
    headers.insert("cache-control", HeaderValue::from_static("no-store"));
    res.status_code(StatusCode::OK);
}

#[handler]
#[tracing::instrument(skip_all, fields(op = "org.arkret.coland.blob.resumable.patch"))]
async fn tus_patch(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let Some(session) = auth_or_render(state, req, res).await else {
        return;
    };
    if !check_tus_version(req, res) {
        return;
    }
    set_tus_header(res);
    if req.headers().contains_key(H_UPLOAD_METADATA) {
        render_error(
            res,
            StatusCode::UNPROCESSABLE_ENTITY,
            "schema_violation",
            "Upload-Metadata is frozen at creation and cannot be supplied on PATCH",
        );
        return;
    }
    let content_type_ok = req
        .headers()
        .get("content-type")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|ct| ct.starts_with(CT_OFFSET_OCTET_STREAM));
    if !content_type_ok {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "param_invalid",
            "PATCH requires content-type application/offset+octet-stream",
        );
        return;
    }
    let Some(request_offset) = req
        .headers()
        .get(H_UPLOAD_OFFSET)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.trim().parse::<u64>().ok())
    else {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "param_missing",
            "Upload-Offset is required",
        );
        return;
    };
    let id = req.param::<String>("id").unwrap_or_default();
    req.set_secure_max_size(MAX_BLOB_UPLOAD_BYTES + 64 * 1024);
    let chunk = match req.payload().await {
        Ok(bytes) => bytes.to_vec(),
        Err(_) => {
            render_error(
                res,
                StatusCode::BAD_REQUEST,
                "json_invalid",
                "invalid chunk body",
            );
            return;
        }
    };
    let Some((creator, mut owner)) = request_owner(state, &session, req, res).await else {
        return;
    };
    let Some(mut meta) = load_gated(res, &id, &creator, &mut owner).await else {
        return;
    };
    if request_offset != meta.offset_bytes {
        // tus: offset mismatch answers 409 Conflict; the client re-syncs
        // via HEAD.
        render_error(
            res,
            StatusCode::CONFLICT,
            "failed_precondition",
            "Upload-Offset does not match current offset",
        );
        return;
    }
    let new_offset = meta.offset_bytes.saturating_add(chunk.len() as u64);
    if new_offset > meta.declared_size_bytes {
        render_error(
            res,
            StatusCode::PAYLOAD_TOO_LARGE,
            "payload_too_large",
            "chunk exceeds declared Upload-Length",
        );
        return;
    }
    let mut updated = meta.clone();
    let appended = owner_io(&mut owner, move |dir| {
        append_staged(dir, &mut updated, &chunk)?;
        Ok(updated)
    })
    .await;
    meta = match appended {
        Ok(meta) => meta,
        Err(error) => {
            render_owner_io(res, error);
            return;
        }
    };
    let headers = res.headers_mut();
    headers.insert(
        H_UPLOAD_OFFSET,
        HeaderValue::from_str(&new_offset.to_string()).expect("numeric header"),
    );
    if new_offset == meta.declared_size_bytes {
        res.status_code(StatusCode::NO_CONTENT);
        return;
    }
    if let Some(expires) = http_date(&meta.expires_at) {
        headers.insert(
            H_UPLOAD_EXPIRES,
            HeaderValue::from_str(&expires).expect("formatted date"),
        );
    }
    res.status_code(StatusCode::NO_CONTENT);
}

#[handler]
#[tracing::instrument(skip_all, fields(op = "org.arkret.coland.blob.resumable.finalize"))]
async fn tus_finalize(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let Some(session) = auth_or_render(state, req, res).await else {
        return;
    };
    let id = req.param::<String>("id").unwrap_or_default();
    let Some((creator, mut owner)) = request_owner(state, &session, req, res).await else {
        return;
    };
    let Some(meta) = load_gated(res, &id, &creator, &mut owner).await else {
        return;
    };
    complete_resumable_upload(state, &session, &id, &meta, &mut owner, res).await;
}

#[handler]
#[tracing::instrument(skip_all, fields(op = "org.arkret.coland.blob.resumable.delete"))]
async fn tus_delete(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let Some(session) = auth_or_render(state, req, res).await else {
        return;
    };
    if !check_tus_version(req, res) {
        return;
    }
    set_tus_header(res);
    let id = req.param::<String>("id").unwrap_or_default();
    let Some((creator, mut owner)) = request_owner(state, &session, req, res).await else {
        return;
    };
    let Some(_meta) = load_gated(res, &id, &creator, &mut owner).await else {
        return;
    };
    let selected = id.clone();
    if let Err(error) = owner_io(&mut owner, move |dir| remove_staged(dir, &selected)).await {
        render_owner_io(res, error);
        return;
    }
    res.status_code(StatusCode::NO_CONTENT);
}

async fn complete_resumable_upload(
    state: &AppState,
    session: &coland_services::identity::SessionIdentityState,
    id: &str,
    meta: &StagedUpload,
    owner: &mut Option<OwnerGuard>,
    res: &mut Response,
) {
    let actor = session.actor.as_str();
    if meta.offset_bytes != meta.declared_size_bytes {
        render_error(
            res,
            StatusCode::CONFLICT,
            "failed_precondition",
            "resumable upload is incomplete",
        );
        return;
    }

    let meta_value = |key: &str| -> Option<String> {
        meta.upload_metadata
            .get(key)
            .cloned()
            .flatten()
            .map(|v| v.trim().to_owned())
            .filter(|v| !v.is_empty())
    };
    if let Err(message) = validate_upload_metadata(&meta.upload_metadata) {
        render_error(
            res,
            StatusCode::UNPROCESSABLE_ENTITY,
            "schema_violation",
            message,
        );
        return;
    }
    let encryption = parse_blob_storage_encryption(
        &meta_value("encryption").expect("validated encryption metadata"),
    )
    .expect("validated encryption classification");
    let realm_id = match meta_value("realm_id") {
        Some(realm_id) => {
            if arkret_identifiers::RealmId::new(realm_id.clone()).is_err() {
                render_error(
                    res,
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "schema_violation",
                    "realm_id is not a Realm id",
                );
                return;
            }
            let is_member = match blob_session_has_realm_membership(state, &realm_id, session).await
            {
                Ok(is_member) => is_member,
                Err(error) => {
                    render_error(res, error.http_status(), error.wire_code(), &error.message);
                    return;
                }
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
    let expected_digest = match meta_value("content_digest") {
        Some(digest) => {
            if !is_valid_blob_upload_content_digest(&digest) {
                render_error(
                    res,
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "schema_violation",
                    "content_digest must be <sha256|blake3>:<64 lowercase hex>",
                );
                return;
            }
            Some(digest)
        }
        None => None,
    };

    let Some(native) = owner.as_ref() else {
        render_error(
            res,
            StatusCode::SERVICE_UNAVAILABLE,
            "temporarily_unavailable",
            "native upload owner is unavailable",
        );
        return;
    };
    let staged_data_path = data_path(native.directory(), id);
    let metadata = match tokio::fs::metadata(&staged_data_path).await {
        Ok(metadata) => metadata,
        Err(error) => {
            tracing::error!(%error, upload_id = %id, "resumable upload data file unreadable");
            render_error(
                res,
                StatusCode::NOT_FOUND,
                "not_found",
                "resumable upload not found or expired",
            );
            return;
        }
    };
    if metadata.len() != meta.declared_size_bytes {
        render_error(
            res,
            StatusCode::CONFLICT,
            "failed_precondition",
            "resumable upload bytes do not match declared length",
        );
        return;
    }
    let size_bytes = match usize::try_from(metadata.len()) {
        Ok(size_bytes) => size_bytes,
        Err(_) => {
            render_error(
                res,
                StatusCode::PAYLOAD_TOO_LARGE,
                "payload_too_large",
                "blob exceeds maximum size",
            );
            return;
        }
    };
    if size_bytes > MAX_BLOB_UPLOAD_BYTES {
        render_error(
            res,
            StatusCode::PAYLOAD_TOO_LARGE,
            "payload_too_large",
            "blob exceeds maximum size",
        );
        return;
    }
    if let Err(message) = enforce_blob_quota(state, actor, realm_id.as_deref(), size_bytes).await {
        render_error(res, StatusCode::FORBIDDEN, "blob_quota_exceeded", message);
        return;
    }
    let sha256 = match sha256_file_hex(&staged_data_path).await {
        Ok(sha256) => sha256,
        Err(error) => {
            tracing::error!(%error, upload_id = %id, "resumable upload data file hash failed");
            render_error(
                res,
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "resumable upload data unavailable",
            );
            return;
        }
    };
    let content_digest = format!("sha256:{sha256}");
    let digest_matches = match expected_digest.as_deref() {
        None => true,
        Some(expected) if expected.starts_with("sha256:") => expected == content_digest,
        Some(expected) => match tokio::fs::read(&staged_data_path).await {
            Ok(bytes) => blob_content_digest_matches(expected, &bytes),
            Err(error) => {
                tracing::error!(%error, upload_id = %id, "resumable upload data file unreadable");
                render_error(
                    res,
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    "resumable upload data unavailable",
                );
                return;
            }
        },
    };
    if !digest_matches {
        crate::metrics::record_digest_mismatch("blob_resumable_patch");
        render_error(
            res,
            StatusCode::UNPROCESSABLE_ENTITY,
            "blob_digest_mismatch",
            "provided content_digest does not match blob content",
        );
        return;
    }

    // Identical ingest path to the canonical multipart upload: the final
    // blob_ref / content_digest MUST equal what a single-shot upload of
    // the same bytes would produce (spec §2.1 content-addressing
    // invariant).
    let media_type = "application/octet-stream".to_owned();
    let blob_ref = format!("ak:blob:sha256:{sha256}");
    if !validate_existing_blob_classification(state, &blob_ref, encryption, res).await {
        return;
    }
    let storage_key = state.deliveries().object_key_for_sha256(&sha256);
    if let Err(error) = state
        .deliveries()
        .put_object_file(&storage_key, &staged_data_path)
        .await
    {
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
        size_bytes: size_bytes as i64,
        storage_backend: state.deliveries().object_storage_backend_name(),
        storage_key: storage_key.clone(),
        media_type: media_type.clone(),
        filename: None,
        realm_id: realm_id.clone(),
        encryption,
        legal_hold: false,
        redacted: false,
        visibility: if realm_id.is_some() {
            arkret_models_collaboration::objects::blob::BlobVisibility::RealmBound
        } else {
            arkret_models_collaboration::objects::blob::BlobVisibility::Public
        },
        uploaded_by: actor.to_owned(),
        created_at: received_at,
    };
    if let Err(error) = state.deliveries().store_blob(&blob_ref, record).await {
        tracing::error!(%error, "failed to persist blob");
        // A concurrent admission may own this shared content-addressed key.
        // A failed metadata write cannot authorize deletion of its object.
        if !validate_existing_blob_classification(state, &blob_ref, encryption, res).await {
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
    // Staging part is consumed; drop it so it can never be replayed or
    // completed twice. Removal failure is non-fatal (the TTL sweeper
    // collects leftovers).
    let selected = id.to_owned();
    if let Err(error) = owner_io(owner, move |dir| remove_staged(dir, &selected)).await {
        render_owner_io(res, error);
        return;
    }
    let outcome = match blob_upload_response_body(
        state,
        blob_ref,
        size_bytes as u64,
        media_type,
        received_at,
    ) {
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

async fn sha256_file_hex(path: &Path) -> std::io::Result<String> {
    let mut file = tokio::fs::File::open(path).await?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 1024 * 1024];
    loop {
        let read = file.read(&mut buffer).await?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex::encode(hasher.finalize()))
}

/// Background sweeper for expired incomplete resumable upload parts.
/// Honors `describe.limits.resumable_upload_incomplete_ttl_seconds`:
/// staging files whose mtime is older than the TTL are removed and never
/// produce a referencable `blob_ref` (spec §2.1 expiration/GC rule).
pub fn spawn_resumable_upload_ttl_sweeper(
    state: AppState,
) -> std::sync::Arc<tokio::task::JoinHandle<()>> {
    let ttl =
        std::time::Duration::from_secs(state.config().resumable_upload_incomplete_ttl_seconds);
    let dir = state.config().resumable_upload_dir.clone();
    let interval = ttl.checked_div(4).unwrap_or(ttl).clamp(
        std::time::Duration::from_secs(60),
        std::time::Duration::from_secs(3600),
    );
    let task = tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        // Skip the immediate first tick so we don't fire mid-boot.
        ticker.tick().await;
        loop {
            ticker.tick().await;
            match sweep_expired_parts(&dir, ttl).await {
                Ok(0) => {}
                Ok(removed) => tracing::debug!(
                    removed,
                    "resumable upload TTL sweep removed expired staging files"
                ),
                Err(error) => {
                    tracing::warn!(%error, "resumable upload TTL sweep failed");
                }
            }
        }
    });
    std::sync::Arc::new(task)
}

fn staged_names(dir: &Path) -> std::io::Result<Vec<String>> {
    let mut names = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| std::io::Error::other("invalid staged filename"))?;
        if staged_owner::is_lock_file(&name) {
            continue;
        }
        let id = name
            .strip_suffix(".json.tmp")
            .or_else(|| name.strip_suffix(".json"))
            .or_else(|| name.strip_suffix(".bin"));
        if id.is_none_or(|id| !is_safe_upload_id(id)) || !entry.file_type()?.is_file() {
            return Err(std::io::Error::other("unknown source in native tus owner"));
        }
        names.push(name);
    }
    names.sort();
    Ok(names)
}

fn erase_owner_directory(dir: &Path, actor: &arkret_wire::ActorId) -> std::io::Result<()> {
    let names = staged_names(dir)?;
    for name in &names {
        if let Some(id) = name.strip_suffix(".json") {
            let meta = read_meta(dir, id)?
                .ok_or_else(|| std::io::Error::other("staged source disappeared"))?;
            if &meta.created_by != actor || meta.upload_id != id {
                return Err(std::io::Error::other(
                    "staged original names another full creator",
                ));
            }
        }
    }
    for name in names {
        std::fs::remove_file(dir.join(name))?;
    }
    Ok(())
}

/// Called only after the worker has verified its original accepted E intent.
/// No Account/PCR/Realm PG lock is held while this actual native owner drains.
/// A disconnected HTTP/PG future cannot release an in-flight file task's lock.
pub(crate) async fn erase_account_parts(
    state: &AppState,
    account: &arkret_wire::AccountId,
) -> Result<(), crate::error::AppError> {
    let actor = arkret_wire::ActorId::account(account.clone());
    let guard = OwnerGuard::acquire(
        state.config().resumable_upload_dir.clone(),
        actor.clone(),
        false,
        false,
    )
    .await;
    let guard = match guard {
        Ok(Some(guard)) => guard,
        Ok(None) => {
            // A genuine empty catalog is safe. Unknown old/foreign files are
            // not evidence that this Account has no unfinished private work.
            staged_owner::directories(state.config().resumable_upload_dir.clone())
                .await
                .map_err(|error| crate::error::AppError::internal(error.to_string()))?;
            return Ok(());
        }
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
            return Err(crate::app_error!(
                TemporarilyUnavailable,
                "native tus writer has not terminated"
            ));
        }
        Err(error) => return Err(crate::error::AppError::internal(error.to_string())),
    };
    guard
        .run(move |dir| erase_owner_directory(dir, &actor))
        .await
        .map_err(|error| crate::error::AppError::internal(error.to_string()))?;
    Ok(())
}

async fn sweep_expired_parts(dir: &Path, ttl: std::time::Duration) -> std::io::Result<u32> {
    let mut removed = 0;
    for key in staged_owner::directories(dir.to_owned()).await? {
        let guard = match OwnerGuard::acquire_key(dir.to_owned(), key.clone(), false, false).await {
            Ok(Some(guard)) => guard,
            Ok(None) => continue,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(error) => return Err(error),
        };
        let (_, count) = guard
            .run(move |directory| {
                let mut count = 0;
                let now = std::time::SystemTime::now();
                for name in staged_names(directory)? {
                    let path = directory.join(name);
                    let modified = std::fs::metadata(&path)?.modified()?;
                    if now.duration_since(modified).unwrap_or_default() > ttl {
                        std::fs::remove_file(path)?;
                        count += 1;
                    }
                }
                Ok(count)
            })
            .await?;
        removed += count;
    }
    Ok(removed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upload_metadata_parses_tus_pairs() {
        let parsed =
            parse_upload_metadata("encryption bnVsbA==,size_bytes NA==").expect("valid metadata");
        assert_eq!(parsed.get("encryption"), Some(&Some("null".to_owned())));
        assert_eq!(parsed.get("size_bytes"), Some(&Some("4".to_owned())));
        validate_upload_metadata(&parsed).expect("public metadata is valid");
    }

    #[test]
    fn upload_metadata_rejects_duplicates_and_bad_base64() {
        assert!(parse_upload_metadata("a Zg==,a Zg==").is_err());
        assert!(parse_upload_metadata("key not-base64!!").is_err());
        assert!(parse_upload_metadata("").is_err());
    }

    #[test]
    fn upload_metadata_requires_closed_canonical_public_encryption() {
        for raw in [
            "encryption bnVsbA==",
            "encryption eyJzY2hlbWUiOiJhay5ibG9iLnN0cmVhbV9hZWFkLnYxIn0=",
        ] {
            validate_upload_metadata(&parse_upload_metadata(raw).unwrap()).unwrap();
        }
        for value in [
            " null ",
            "{}",
            r#"{"scheme":"unknown"}"#,
            r#"{"scheme":"ak.blob.whole_file_aead.v1","key_ref":"secret"}"#,
        ] {
            let raw = format!("encryption {}", BASE64_STANDARD.encode(value));
            assert!(validate_upload_metadata(&parse_upload_metadata(&raw).unwrap()).is_err());
        }
        assert!(validate_upload_metadata(&HashMap::new()).is_err());
        let retired =
            parse_upload_metadata("encryption bnVsbA==,purpose ZmlsZV90cmFuc2Zlcg==").unwrap();
        assert!(validate_upload_metadata(&retired).is_err());
    }

    #[test]
    fn safe_upload_ids_reject_path_tricks() {
        assert!(is_safe_upload_id("0196deadbeef"));
        assert!(is_safe_upload_id("a-b_c"));
        assert!(!is_safe_upload_id(""));
        assert!(!is_safe_upload_id("../escape"));
        assert!(!is_safe_upload_id("a/b"));
        assert!(!is_safe_upload_id("a.b"));
        assert!(!is_safe_upload_id(&"x".repeat(65)));
    }
}
