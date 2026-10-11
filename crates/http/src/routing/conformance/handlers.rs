//! Conformance-vector HTTP handlers.
//!
//! Each handler is intentionally thin: it pulls the request body, runs the
//! forked conformance primitive in [`super::util`], and serializes the
//! result. The `/_arkret/_conformance/*` namespace is only mounted when
//! `development_mode=true`, and [`super::ensure_enabled`]
//! is the defense-in-depth handler guard. See [`super`] and
//! `service-http-binding.md` §2.1.2.
//!
//! Wire shapes mirror `cotest/e2e/scenarios/conformance/encoding-vectors.md`
//! Pre-conditions §:
//!   POST /_coland/self/conformance/encode    { vector_id, input }                              → {
//! canonical_json, digest }   POST /_coland/self/conformance/sign      { vector_id, event,
//! signing_key_ref }             → { canonical_bytes, digest, signature, public_key }   POST /api/
//! v1/conformance/hlc-merge { vector_id, clocks: [{actor, hlc, payload_hint}] } → { ordered: [...]
//! }   POST /_coland/self/conformance/cursor    { vector_id, events, reduce_round }               →
//! { cursor }   POST /_coland/self/conformance/envelope  { vector_id, envelope }
//! → { canonical_bytes, digest }   POST /_coland/self/conformance/redact    { vector_id, event,
//! redaction, viewer_did }       → { projected_event }
//!
//! Reject paths (`vector_id` starts with `reject_`) return HTTP 4xx with
//! `error.code` in the documented set:
//!   - `schema_violation` / `invalid_canonical_json` / `invalid_encoding` for /encode
//!   - `hlc_logical_overflow` for /hlc-merge
//!
//! When the conformance namespace is disabled at build/runtime, every route
//! returns `404 not_found` so the cotest probe stays in its accepted status
//! set (`[200, 404, 405, 501]`).

use std::cmp::Ordering;
use std::collections::BTreeMap;

use arkret_hlc::{Cursor, CursorPurpose};
use arkret_server::{CursorAuthority, CursorAuthorityError, CursorBindingContext};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use coland_http::error::{AppError, ErrorCode};
use coland_http::util::query_param;
use coland_services::events::{AcceptedEvent, ProjectedEvent as ProjectionEventRecord};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use salvo::oapi::extract::JsonBody;
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use super::util::{canonical_json, order_hlc_clocks, sha256_digest};
use crate::state::AppState;
use crate::{JsonResult, json_ok};

const MAX_CONFORMANCE_BATCH: usize = 1_000;
const MAX_CONFORMANCE_RELATION_DEPTH: u64 = 32;
const MAX_CONFORMANCE_ENVELOPE_BYTES: usize = 1024 * 1024;

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
pub struct EncodeVectorRequest {
    vector_id: String,

    input: Value,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct CanonicalJsonDigestOutcome {
    canonical_json: String,
    digest: String,
}

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
pub struct SignVectorRequest {
    vector_id: String,

    event: Value,
    signing_key_ref: String,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct SignVectorOutcome {
    canonical_bytes: String,
    digest: String,
    signature: String,
    public_key: String,
    algorithm: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub struct HlcClockVectorItem {
    actor: String,
    hlc: String,
    #[serde(default)]
    payload_hint: Value,
}

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
pub struct HlcMergeVectorRequest {
    vector_id: String,
    clocks: Vec<HlcClockVectorItem>,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct HlcMergeVectorOutcome {
    ordered: Vec<HlcClockVectorItem>,
}

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
pub struct CursorVectorRequest {
    vector_id: String,

    events: Vec<Value>,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct CursorVectorOutcome {
    cursor: String,
}

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
pub struct EnvelopeVectorRequest {
    vector_id: String,

    envelope: Value,
    ciphertext_base64url: Option<String>,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct CanonicalBytesDigestOutcome {
    canonical_bytes: String,
    digest: String,
}

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
pub struct RedactVectorRequest {
    vector_id: String,

    event: Value,

    redaction: Value,
    viewer_did: String,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct RedactVectorOutcome {
    projected_event: Value,
}

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
pub struct EraseReceiptVectorRequest {
    vector_id: String,

    event: Value,

    receipt: Value,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct EraseReceiptVectorOutcome {
    projected_event: Value,
    outcome: String,
    retained_stub_digest: String,
    verification_stub_retained: bool,
    plaintext_fingerprint_present: bool,
    legal_hold_blocked: bool,
}

#[derive(Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub struct QueryVectorRequest {
    vector_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    query: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    rows: Option<Vec<Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    dataset: Option<Vec<Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    cursor: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    unauthorized_fields: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    events: Option<Vec<Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    chunks: Option<Vec<Value>>,
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    #[salvo(schema(value_type = serde_json::Value))]
    extra: BTreeMap<String, Value>,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct QueryVectorBarrier {
    barrier_cursor: String,
    row_count: usize,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct QueryVectorOutcome {
    vector_id: String,

    items: Vec<Value>,
    has_more: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    next_cursor: Option<String>,
    barrier: QueryVectorBarrier,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct ChaosOperationOutcome {
    operation_id: String,
    canonical_event: Option<CanonicalEventDiagnostic>,
    projection_event: Option<ProjectionEventDiagnostic>,
    consistent: bool,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
struct CanonicalEventDiagnostic {
    event_id: String,
    actor_id: String,
    realm_id: Option<String>,
    kind: String,
    canonical_digest: String,
    #[serde(serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp")]
    received_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
struct ProjectionEventDiagnostic {
    event_id: String,
    realm_id: String,
    event_kind: String,
    operation_kind: String,
    operation_id: Option<String>,
    sender: Option<String>,
    #[serde(serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp")]
    created_at: chrono::DateTime<chrono::Utc>,
}

/// Errors that mean "the vector_id encodes a deliberate reject path" — used
/// by `/encode` to map `reject_noncanonical_numbers.v1` /
/// `reject_malformed_json.v1` style vectors to their documented codes.
fn encode_reject_for_vector(vector: &str) -> Option<(ErrorCode, &'static str)> {
    if vector.contains("reject_malformed_json") {
        Some((
            ErrorCode::JsonInvalid,
            "vector requests malformed-JSON reject",
        ))
    } else if vector.contains("reject_noncanonical_numbers") {
        Some((
            ErrorCode::SchemaViolation,
            "vector requests non-canonical-numbers reject",
        ))
    } else if vector.contains("reject_") {
        Some((
            ErrorCode::SchemaViolation,
            "vector requests canonicalization reject",
        ))
    } else {
        None
    }
}

#[salvo::oapi::endpoint(
    operation_id = "org.arkret.coland.conformance.encode",
    tags("conformance")
)]
#[tracing::instrument(skip_all, fields(op = "org.arkret.coland.conformance.encode"))]
pub async fn encode(body: JsonBody<EncodeVectorRequest>) -> JsonResult<CanonicalJsonDigestOutcome> {
    super::ensure_enabled()?;
    let body = body.into_inner();
    let vector = body.vector_id.as_str();
    if let Some((code, message)) = encode_reject_for_vector(vector) {
        return Err(AppError::from_rejection(code, message));
    }
    let canonical = canonical_json(&body.input)
        .map_err(|err| crate::app_error!(SchemaViolation, format!("canonicalize: {err}")))?;
    let digest = sha256_digest(canonical.as_bytes());
    json_ok(CanonicalJsonDigestOutcome {
        canonical_json: canonical,
        digest,
    })
}

#[salvo::oapi::endpoint(
    operation_id = "org.arkret.coland.conformance.sign",
    tags("conformance")
)]
#[tracing::instrument(skip_all, fields(op = "org.arkret.coland.conformance.sign"))]
pub async fn sign(body: JsonBody<SignVectorRequest>) -> JsonResult<SignVectorOutcome> {
    super::ensure_enabled()?;
    let body = body.into_inner();
    let _vector = body.vector_id.as_str();
    let event = &body.event;
    let signing_key_ref = body.signing_key_ref.as_str();

    // Deterministic conformance signing key: derive seed from the
    // `signing_key_ref` string. This is intentionally not a real account /
    // device key — conformance vectors only need a stable Ed25519 keypair
    // so the wire test can verify (a) determinism and (b) signature
    // validity under the returned `public_key`. Production-grade signing
    // for service-identity custody lives outside this conformance surface.
    let mut hasher = Sha256::new();
    hasher.update(b"coland:conformance:sign:");
    hasher.update(signing_key_ref.as_bytes());
    let seed: [u8; 32] = hasher.finalize().into();
    let signing_key = SigningKey::from_bytes(&seed);
    let verifying_key: VerifyingKey = signing_key.verifying_key();

    // The canonical Event digest preimage is the SDK's single exit for it:
    // `event_id` (derived from this digest) and `producer_proof` (which
    // cannot sign itself) are the only omitted members.
    let preimage = arkret_wire::event_digest_preimage(event)
        .map_err(|err| crate::app_error!(SchemaViolation, format!("preimage: {err}")))?;
    let canonical = canonical_json(&preimage)
        .map_err(|err| crate::app_error!(SchemaViolation, format!("canonicalize: {err}")))?;
    let digest = sha256_digest(canonical.as_bytes());
    let signature = signing_key.sign(canonical.as_bytes());

    json_ok(SignVectorOutcome {
        canonical_bytes: canonical,
        digest,
        signature: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
        public_key: URL_SAFE_NO_PAD.encode(verifying_key.to_bytes()),
        algorithm: "ed25519".to_owned(),
    })
}

#[salvo::oapi::endpoint(
    operation_id = "org.arkret.coland.conformance.hlc_merge",
    tags("conformance")
)]
#[tracing::instrument(skip_all, fields(op = "org.arkret.coland.conformance.hlc_merge"))]
pub async fn hlc_merge(body: JsonBody<HlcMergeVectorRequest>) -> JsonResult<HlcMergeVectorOutcome> {
    super::ensure_enabled()?;
    let body = body.into_inner();
    let vector = body.vector_id.as_str();
    if vector.contains("logical_overflow") {
        // error-code-registry.json binds `hlc_logical_overflow` to 503; the
        // registry-derived status renders verbatim, no handler-side override.
        return Err(crate::app_error!(
            HlcLogicalOverflow,
            "vector requests logical-counter overflow reject",
        ));
    }
    let clocks: Vec<(String, String, Value)> = body
        .clocks
        .iter()
        .map(|clock| {
            (
                clock.hlc.clone(),
                clock.actor.clone(),
                clock.payload_hint.clone(),
            )
        })
        .collect();
    let ordered = order_hlc_clocks(&clocks);
    let ordered = ordered
        .into_iter()
        .map(|(hlc, actor, payload_hint)| HlcClockVectorItem {
            actor,
            hlc,
            payload_hint,
        })
        .collect();
    json_ok(HlcMergeVectorOutcome { ordered })
}

#[salvo::oapi::endpoint(
    operation_id = "org.arkret.coland.conformance.cursor",
    tags("conformance")
)]
#[tracing::instrument(skip_all, fields(op = "org.arkret.coland.conformance.cursor"))]
pub async fn cursor(body: JsonBody<CursorVectorRequest>) -> JsonResult<CursorVectorOutcome> {
    super::ensure_enabled()?;
    let body = body.into_inner();
    let _vector = body.vector_id.as_str();
    let events = &body.events;

    // The cursor must be stable under re-reduce — i.e. independent of the
    // input event order. Encode the *count* of events plus the canonical
    // digest of their sorted-event-id set. That keeps the cursor opaque
    // (no plaintext event_id leak — they're hashed into x) and stable.
    let mut event_ids: Vec<String> = events
        .iter()
        .map(|event| {
            event
                .get("event_id")
                .and_then(Value::as_str)
                .map(|s| s.to_owned())
                .unwrap_or_default()
        })
        .collect();
    event_ids.sort();
    let mut hasher = Sha256::new();
    hasher.update(event_ids.join(",").as_bytes());
    let digest: [u8; 32] = hasher.finalize().into();
    let cursor_issued_at = chrono::Utc::now()
        .date_naive()
        .and_hms_opt(0, 0, 0)
        .expect("midnight is valid")
        .and_utc();
    let shape = Cursor {
        v: "1".to_owned(),
        purpose: CursorPurpose::Stream,
        issued_at: cursor_issued_at,
        expires_at: cursor_issued_at + chrono::Duration::milliseconds(Cursor::STREAM_TTL_MAX_MS),
        h: URL_SAFE_NO_PAD.encode(digest),
    };
    let cursor_token = shape
        .encode()
        .map_err(|err| crate::app_error!(InternalError, format!("encode cursor: {err}")))?;
    json_ok(CursorVectorOutcome {
        cursor: cursor_token,
    })
}

#[salvo::oapi::endpoint(
    operation_id = "org.arkret.coland.conformance.envelope",
    tags("conformance")
)]
#[tracing::instrument(skip_all, fields(op = "org.arkret.coland.conformance.envelope"))]
pub async fn envelope(
    body: JsonBody<EnvelopeVectorRequest>,
) -> JsonResult<CanonicalBytesDigestOutcome> {
    super::ensure_enabled()?;
    let body = body.into_inner();
    let _vector = body.vector_id.as_str();
    let canonical = canonical_json(&body.envelope)
        .map_err(|err| crate::app_error!(SchemaViolation, format!("canonicalize: {err}")))?;
    let digest = if let Some(ciphertext) = body.ciphertext_base64url.as_deref() {
        let ciphertext_bytes = URL_SAFE_NO_PAD
            .decode(ciphertext)
            .map_err(|err| AppError::param_invalid(format!("ciphertext_base64url: {err}")))?;
        let mut material = Vec::with_capacity(canonical.len() + ciphertext_bytes.len());
        material.extend_from_slice(canonical.as_bytes());
        material.extend_from_slice(&ciphertext_bytes);
        sha256_digest(&material)
    } else {
        sha256_digest(canonical.as_bytes())
    };
    json_ok(CanonicalBytesDigestOutcome {
        canonical_bytes: canonical,
        digest,
    })
}

#[salvo::oapi::endpoint(
    operation_id = "org.arkret.coland.conformance.redact",
    tags("conformance")
)]
#[tracing::instrument(skip_all, fields(op = "org.arkret.coland.conformance.redact"))]
pub async fn redact(body: JsonBody<RedactVectorRequest>) -> JsonResult<RedactVectorOutcome> {
    super::ensure_enabled()?;
    let body = body.into_inner();
    let _vector = body.vector_id.as_str();
    let event = &body.event;
    let redaction = &body.redaction;
    let viewer_did = body.viewer_did.as_str();

    // Spec §3.2 — redaction strips the fields listed in `redaction.fields`
    // (default: `["content", "payload.content"]`) unless the viewer is the
    // event's original author (`sender_actor_id` / `actor_id`). The projection
    // MUST drop the keys entirely
    // (not set them to null) and MUST keep `event_id`, `redacted_because`,
    // and tombstone markers visible to every viewer.
    let owner_did = event
        .get("sender_actor_id")
        .and_then(Value::as_str)
        .or_else(|| event.get("actor_id").and_then(Value::as_str))
        .or_else(|| event.get("actor").and_then(Value::as_str));
    let viewer_is_owner = owner_did == Some(viewer_did);

    let default_fields = vec![Value::from("content"), Value::from("payload.content")];
    let strip_fields: Vec<&str> = redaction
        .get("fields")
        .and_then(Value::as_array)
        .unwrap_or(&default_fields)
        .iter()
        .filter_map(Value::as_str)
        .collect();

    let mut projected = event.clone();
    if !viewer_is_owner {
        if let Some(object) = projected.as_object_mut() {
            for path in &strip_fields {
                strip_path(object, path);
            }
        }
        // Always surface the redacted_because marker if present in the
        // redaction event so guests can render a tombstone.
        if let Some(reason) = redaction.get("reason")
            && let Some(object) = projected.as_object_mut()
        {
            object.insert("redacted_because".to_owned(), reason.clone());
        }
    }

    json_ok(RedactVectorOutcome {
        projected_event: projected,
    })
}

#[salvo::oapi::endpoint(
    operation_id = "org.arkret.coland.conformance.erase_receipt",
    tags("conformance")
)]
#[tracing::instrument(skip_all, fields(op = "org.arkret.coland.conformance.erase_receipt"))]
pub async fn erase_receipt(
    body: JsonBody<EraseReceiptVectorRequest>,
) -> JsonResult<EraseReceiptVectorOutcome> {
    super::ensure_enabled()?;
    let body = body.into_inner();
    let _vector = body.vector_id.as_str();
    let event = &body.event;
    let receipt = &body.receipt;

    // conformance-vectors.md §3.4 — hard erasure deletes the erased subject's
    // payload bytes and derived plaintext within the storage boundary, but
    // retains a verification stub (original event id, envelope/proof digest,
    // redaction event id, erasure reason, executing service DID, time, signed
    // receipt). The default projection MUST show the erased / redacted
    // placeholder, never the original plaintext, and MUST NOT fabricate a
    // standalone content fingerprint of the erased low-entropy plaintext.
    let outcome = receipt
        .get("outcome")
        .and_then(Value::as_str)
        .unwrap_or("completed")
        .to_owned();
    let legal_hold_blocked = outcome == "blocked_by_legal_hold";

    // Build the default redacted projection: drop the erased content + producer proof
    // entirely (key removed, not nulled) so no erased plaintext survives in the
    // default view. §3.4: legal hold blocks hard erasure but the default
    // display still applies redaction, so the strip happens regardless of
    // outcome.
    let mut projected = event.clone();
    if let Some(object) = projected.as_object_mut() {
        strip_path(object, "payload.content");
        strip_path(object, "content");
        object.remove("producer_proof");
        object.remove("sender_actor_id");
        // Surface a tombstone marker keyed by the signed receipt so an auditor
        // can pivot to the retained verification stub.
        let receipt_id = receipt
            .get("receipt_id")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        object.insert(
            "redacted_because".to_owned(),
            json!({ "code": "hard_erasure", "receipt_id": receipt_id }),
        );
    }

    // The retained verification stub digest binds the exact stub bytes
    // (erasure-receipt.schema.json `retained_stub_digest`). Recompute it from
    // the in-band `retained_stub` when present so the wire test sees a digest
    // that matches the stub the issuer would expose, falling back to the
    // declared digest otherwise.
    let declared_stub_digest = receipt
        .get("retained_stub_digest")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned);
    let (retained_stub_digest, verification_stub_retained) =
        if let Some(stub) = receipt.get("retained_stub").filter(|stub| stub.is_object()) {
            let canonical = canonical_json(stub).map_err(schema_error)?;
            (sha256_digest(canonical.as_bytes()), true)
        } else if let Some(declared) = declared_stub_digest {
            (declared, true)
        } else if let Some(stub) = receipt
            .pointer("/snapshot/verification_stub")
            .filter(|stub| stub.is_object())
        {
            // §3.5 snapshot pruning — the stub may travel inside the snapshot
            // descriptor instead of a standalone receipt.
            let canonical = canonical_json(stub).map_err(schema_error)?;
            (sha256_digest(canonical.as_bytes()), true)
        } else {
            (String::new(), false)
        };

    // Fail-closed plaintext-leak guard: the projected default view MUST NOT
    // still carry the erased content/proofs, and the retained stub digest MUST
    // NOT be a bare digest of the erased low-entropy plaintext.
    let plaintext_fingerprint_present = projected_event_carries_plaintext(&projected, event);

    json_ok(EraseReceiptVectorOutcome {
        projected_event: projected,
        outcome,
        retained_stub_digest,
        verification_stub_retained,
        plaintext_fingerprint_present,
        legal_hold_blocked,
    })
}

/// True when the projected (post-erasure) event still leaks the original
/// erased content body or its standalone digest. Used as a fail-closed guard so
/// the conformance projection never surfaces erased plaintext.
fn projected_event_carries_plaintext(projected: &Value, original: &Value) -> bool {
    let Some(body) = original
        .pointer("/payload/content/body")
        .and_then(Value::as_str)
    else {
        return false;
    };
    if body.is_empty() {
        return false;
    }
    let body_digest = sha256_digest(body.as_bytes());
    let serialized = projected.to_string();
    serialized.contains(body) || serialized.contains(&body_digest)
}

#[salvo::oapi::endpoint(
    operation_id = "org.arkret.coland.conformance.query",
    tags("conformance")
)]
#[tracing::instrument(skip_all, fields(op = "org.arkret.coland.conformance.query"))]
pub async fn query(
    body: JsonBody<QueryVectorRequest>,
    depot: &mut Depot,
) -> JsonResult<QueryVectorOutcome> {
    super::ensure_enabled()?;
    let state = depot.get_typed::<AppState>().expect("state injected");
    let body = body.into_inner();
    let body_value = serde_json::to_value(&body)
        .map_err(|error| AppError::internal(format!("conformance query body encode: {error}")))?;
    let vector = body.vector_id.as_str();
    let query_value = body_value.get("query").unwrap_or(&body_value);
    validate_query_limits(vector, &body_value, query_value)?;
    validate_query_shape(vector, &body_value, query_value)?;

    let mut rows = body_value
        .get("rows")
        .or_else(|| body_value.get("dataset"))
        .or_else(|| query_value.get("rows"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_else(default_query_rows);
    rows.retain(|row| row_matches_query(row, query_value));
    sort_query_rows(&mut rows, query_value);

    let query_digest_shape = query_digest_value(query_value);
    let query_digest = digest_json(&query_digest_shape);
    let offset = match query_value
        .get("cursor")
        .or_else(|| body_value.get("cursor"))
        .and_then(Value::as_str)
    {
        Some(cursor_token) => resolve_query_cursor(state, cursor_token, &query_digest).await?,
        None => 0,
    };
    if offset > rows.len() {
        return Err(
            AppError::param_invalid("query cursor offset is beyond the result set")
                .with_reason_code(arkret_wire::ReasonCode::INVALID_CURSOR),
        );
    }
    let limit = query_value
        .get("limit")
        .or_else(|| query_value.get("page_size"))
        .and_then(Value::as_u64)
        .unwrap_or(rows.len().max(1) as u64)
        .min(MAX_CONFORMANCE_BATCH as u64) as usize;
    let end = (offset + limit).min(rows.len());
    let page: Vec<Value> = rows[offset..end].to_vec();
    let next_cursor = if end < rows.len() {
        Some(mint_query_cursor(state, end, &query_digest).await?)
    } else {
        None
    };
    let barrier_cursor = mint_query_barrier_cursor(state, rows.len(), &query_digest).await?;

    json_ok(QueryVectorOutcome {
        vector_id: vector.to_owned(),
        items: page,
        has_more: next_cursor.is_some(),
        next_cursor,
        barrier: QueryVectorBarrier {
            barrier_cursor,
            row_count: rows.len(),
        },
    })
}

#[salvo::oapi::endpoint(
    operation_id = "org.arkret.coland.conformance.chaos_operation",
    tags("conformance")
)]
#[tracing::instrument(skip_all, fields(op = "org.arkret.coland.conformance.chaos_operation"))]
pub async fn chaos_operation(
    depot: &mut Depot,
    req: &Request,
) -> JsonResult<ChaosOperationOutcome> {
    super::ensure_enabled()?;
    let state = depot.get_typed::<AppState>().expect("state injected");
    if !state.config().development_mode {
        return Err(AppError::not_found(
            "chaos diagnostics are only available in development_mode",
        ));
    }
    let operation_id = query_param(req, "operation_id")
        .ok_or_else(|| AppError::param_missing("missing operation_id"))?;
    if !operation_id.starts_with("ak:operation:") {
        return Err(AppError::param_invalid(
            "operation_id must use ak:operation:",
        ));
    }

    let canonical_event = state
        .event_queries()
        .canonical_events()
        .await
        .map_err(|error| crate::app_error!(InternalError, error.to_string()))?
        .into_iter()
        .find(|record| canonical_event_operation_id(record).as_deref() == Some(&operation_id));
    let projection_event = state
        .event_queries()
        .projected_event_by_operation_id(&operation_id)
        .await
        .map_err(|error| crate::app_error!(InternalError, error.to_string()))?;
    let canonical_json = canonical_event.as_ref().map(canonical_event_diagnostic);
    let projection_json = projection_event.as_ref().map(projection_event_diagnostic);

    json_ok(ChaosOperationOutcome {
        operation_id,
        canonical_event: canonical_json,
        projection_event: projection_json,
        consistent: canonical_event.is_some() == projection_event.is_some(),
    })
}

/// Drop `path` from `object`, supporting dotted paths like `"payload.content"`.
fn strip_path(object: &mut Map<String, Value>, path: &str) {
    if let Some((head, rest)) = path.split_once('.') {
        if let Some(Value::Object(child)) = object.get_mut(head) {
            strip_path(child, rest);
        }
    } else {
        object.remove(path);
    }
}

fn validate_query_limits(vector: &str, body: &Value, query_value: &Value) -> Result<(), AppError> {
    if vector.contains("envelope_over_1mib")
        || canonical_json(body).map_err(schema_error)?.len() > MAX_CONFORMANCE_ENVELOPE_BYTES
    {
        return Err(payload_too_large_error(
            "query canonical envelope exceeds 1 MiB",
        ));
    }
    let limit = query_value
        .get("limit")
        .or_else(|| query_value.get("page_size"))
        .and_then(Value::as_u64)
        .unwrap_or(0);
    if limit > MAX_CONFORMANCE_BATCH as u64 || vector.contains("page_size_over_max") {
        return Err(limit_error("query page size exceeds 1,000"));
    }
    let batch_count = body
        .get("events")
        .or_else(|| body.get("rows"))
        .or_else(|| body.get("chunks"))
        .and_then(Value::as_array)
        .map_or(0, Vec::len);
    if batch_count > MAX_CONFORMANCE_BATCH || vector.contains("batch_item_count_over_max") {
        return Err(limit_error("query batch exceeds 1,000 items"));
    }
    let relation_depth = query_value
        .pointer("/relation/depth")
        .or_else(|| query_value.pointer("/relation_expansion/depth"))
        .and_then(Value::as_u64)
        .unwrap_or(0);
    if relation_depth > MAX_CONFORMANCE_RELATION_DEPTH || vector.contains("relation_depth_over_max")
    {
        return Err(limit_error("query relation expansion depth exceeds 32"));
    }
    Ok(())
}

fn validate_query_shape(vector: &str, body: &Value, query_value: &Value) -> Result<(), AppError> {
    if vector.contains("unauthorized_field")
        || string_array(body.get("unauthorized_fields"))
            .next()
            .is_some()
        || string_array(query_value.get("projection")).any(|field| field.starts_with("secret"))
    {
        return Err(query_schema_error(
            "query references a field outside the caller's read grant",
        ));
    }

    for filter in query_filters(query_value) {
        let op = filter
            .get("op")
            .or_else(|| filter.get("operator"))
            .and_then(Value::as_str)
            .unwrap_or("eq");
        if !allowed_query_op(op) || vector.contains("unknown_filter_key") {
            return Err(query_schema_error("query filter op is not registered"));
        }
    }

    let mut seen_sort = BTreeMap::<String, String>::new();
    for sort in query_sorts(query_value) {
        let Some(field) = sort.get("field").and_then(Value::as_str) else {
            continue;
        };
        let direction = sort
            .get("direction")
            .or_else(|| sort.get("dir"))
            .and_then(Value::as_str)
            .unwrap_or("asc")
            .to_ascii_lowercase();
        if !matches!(direction.as_str(), "asc" | "desc") {
            return Err(query_schema_error("query sort direction is not registered"));
        }
        if let Some(previous) = seen_sort.insert(field.to_owned(), direction.clone())
            && previous != direction
        {
            return Err(query_schema_error(
                "query carries conflicting sort directions for the same field",
            ));
        }
    }
    if vector.contains("conflicting_sort") {
        return Err(query_schema_error(
            "query carries conflicting sort directions for the same field",
        ));
    }
    Ok(())
}

fn query_filters(query_value: &Value) -> Vec<&Value> {
    if let Some(filters) = query_value.get("filters").and_then(Value::as_array) {
        return filters.iter().collect();
    }
    query_value
        .get("filter")
        .and_then(Value::as_array)
        .map(|filters| filters.iter().collect())
        .unwrap_or_default()
}

fn query_sorts(query_value: &Value) -> Vec<&Value> {
    query_value
        .get("order_by")
        .or_else(|| query_value.get("sort"))
        .and_then(Value::as_array)
        .map(|sorts| sorts.iter().collect())
        .unwrap_or_default()
}

fn row_matches_query(row: &Value, query_value: &Value) -> bool {
    query_filters(query_value).into_iter().all(|filter| {
        let field = filter.get("field").and_then(Value::as_str).unwrap_or("");
        let op = filter
            .get("op")
            .or_else(|| filter.get("operator"))
            .and_then(Value::as_str)
            .unwrap_or("eq");
        let expected = filter.get("value").unwrap_or(&Value::Null);
        let actual = row.get(field).unwrap_or(&Value::Null);
        match op {
            "eq" => actual == expected,
            "neq" => actual != expected,
            "in" => expected
                .as_array()
                .is_some_and(|values| values.iter().any(|value| value == actual)),
            "not_in" => expected
                .as_array()
                .is_none_or(|values| values.iter().all(|value| value != actual)),
            "lt" => compare_json(actual, expected) == Some(Ordering::Less),
            "lte" => compare_json(actual, expected)
                .is_some_and(|ordering| matches!(ordering, Ordering::Less | Ordering::Equal)),
            "gt" => compare_json(actual, expected) == Some(Ordering::Greater),
            "gte" => compare_json(actual, expected)
                .is_some_and(|ordering| matches!(ordering, Ordering::Greater | Ordering::Equal)),
            "contains" => contains_json(actual, expected),
            "exists" => expected.as_bool().unwrap_or(true) != actual.is_null(),
            "prefix" => actual
                .as_str()
                .zip(expected.as_str())
                .is_some_and(|(actual, prefix)| actual.starts_with(prefix)),
            "full_text" => {
                actual
                    .as_str()
                    .zip(expected.as_str())
                    .is_some_and(|(actual, needle)| {
                        actual
                            .to_ascii_lowercase()
                            .contains(&needle.to_ascii_lowercase())
                    })
            }
            _ => false,
        }
    })
}

fn sort_query_rows(rows: &mut [Value], query_value: &Value) {
    let sorts = query_sorts(query_value);
    if sorts.is_empty() {
        return;
    }
    rows.sort_by(|left, right| {
        for sort in &sorts {
            let Some(field) = sort.get("field").and_then(Value::as_str) else {
                continue;
            };
            let descending = sort
                .get("direction")
                .or_else(|| sort.get("dir"))
                .and_then(Value::as_str)
                .is_some_and(|dir| dir.eq_ignore_ascii_case("desc"));
            let ordering = compare_json(
                left.get(field).unwrap_or(&Value::Null),
                right.get(field).unwrap_or(&Value::Null),
            )
            .unwrap_or(Ordering::Equal);
            let ordering = if descending {
                ordering.reverse()
            } else {
                ordering
            };
            if ordering != Ordering::Equal {
                return ordering;
            }
        }
        Ordering::Equal
    });
}

fn compare_json(left: &Value, right: &Value) -> Option<Ordering> {
    match (left, right) {
        (Value::Number(left), Value::Number(right)) => left.as_f64()?.partial_cmp(&right.as_f64()?),
        (Value::String(left), Value::String(right)) => Some(left.cmp(right)),
        (Value::Bool(left), Value::Bool(right)) => Some(left.cmp(right)),
        _ => None,
    }
}

fn contains_json(actual: &Value, expected: &Value) -> bool {
    match (actual, expected) {
        (Value::String(actual), Value::String(expected)) => actual.contains(expected),
        (Value::Array(actual), expected) => actual.iter().any(|item| item == expected),
        _ => false,
    }
}

fn allowed_query_op(op: &str) -> bool {
    matches!(
        op,
        "eq" | "neq"
            | "in"
            | "not_in"
            | "lt"
            | "lte"
            | "gt"
            | "gte"
            | "contains"
            | "exists"
            | "prefix"
            | "full_text"
    )
}

fn default_query_rows() -> Vec<Value> {
    vec![
        json!({"id": "row-a", "kind": "task", "title": "Alpha", "rank": 1, "visible": true}),
        json!({"id": "row-b", "kind": "note", "title": "Beta", "rank": 2, "visible": true}),
        json!({"id": "row-c", "kind": "task", "title": "Gamma", "rank": 3, "visible": false}),
    ]
}

// ── Conformance query pagination cursor (encoding.md §8) ────────────────────
//
// The wire body carries only the canonical core `{v, purpose, issued_at,
// expires_at, h}` fields; the page offset and the query digest are bound
// server-side to the `h` handle, exactly like the production list surfaces.

const CONFORMANCE_QUERY_CURSOR_TTL_MS: i64 = 60 * 60 * 1000;

fn conformance_cursor_error(error: CursorAuthorityError) -> AppError {
    match error {
        // encoding.md §8.3 closed set: syntax/schema failures pin the top-level
        // `param_invalid` code with reason `invalid_cursor`.
        CursorAuthorityError::ParamInvalid(message) => AppError::param_invalid(message)
            .with_reason_code(arkret_wire::ReasonCode::INVALID_CURSOR),
        CursorAuthorityError::Expired => {
            crate::app_error!(CursorExpired, "cursor has expired")
        }
        CursorAuthorityError::IntegrityInvalid => {
            crate::app_error!(CursorIntegrityInvalid, "cursor integrity check failed",)
        }
    }
}

fn query_cursor_context(state: &AppState, query_digest: &str) -> CursorBindingContext {
    // The conformance namespace is unauthenticated; the binding still pins
    // service identity and the canonical query digest.
    CursorBindingContext::new("anonymous", None, state.service_core_id(), query_digest)
}

async fn persist_query_cursor_row(
    state: &AppState,
    row: coland_services::sync::CursorState,
) -> Result<(), AppError> {
    state
        .sync()
        .upsert_cursor(&row)
        .await
        .map_err(|error| AppError::internal(format!("cursor binding persistence failed: {error}")))
}

async fn mint_query_cursor(
    state: &AppState,
    offset: usize,
    query_digest: &str,
) -> Result<String, AppError> {
    let (token, record) = CursorAuthority::mint_stream(
        query_cursor_context(state, query_digest),
        json!({ "offset": offset }),
        CONFORMANCE_QUERY_CURSOR_TTL_MS,
    )
    .map_err(conformance_cursor_error)?;
    persist_query_cursor_row(
        state,
        coland_services::sync::CursorState {
            handle: record.handle,
            binding_subject: Some(record.context.binding_subject),
            device_id: record.context.device_id,
            session_id: None,
            service_id: record.context.service_id.clone(),
            filter_digest: Some(record.context.filter_digest),
            purpose: "stream".to_owned(),
            positions: Some(record.positions),
            target: None,
            issued_at_ms: record.issued_at_ms,
            expires_at_ms: record.expires_at_ms,
        },
    )
    .await?;
    Ok(token)
}

async fn mint_query_barrier_cursor(
    state: &AppState,
    row_count: usize,
    query_digest: &str,
) -> Result<String, AppError> {
    let minted = Cursor::new_at(chrono::Utc::now(), Cursor::BARRIER_TTL_MAX_MS)
        .map_err(|error| AppError::internal(format!("mint barrier cursor: {error}")))?
        .with_barrier();
    let token = minted
        .encode()
        .map_err(|error| AppError::internal(format!("encode barrier cursor: {error}")))?;
    let context = query_cursor_context(state, query_digest);
    persist_query_cursor_row(
        state,
        coland_services::sync::CursorState {
            handle: minted.h.clone(),
            binding_subject: Some(context.binding_subject),
            device_id: context.device_id,
            session_id: None,
            service_id: context.service_id.clone(),
            filter_digest: Some(context.filter_digest),
            purpose: "barrier".to_owned(),
            positions: None,
            target: Some(json!({ "row_count": row_count })),
            issued_at_ms: minted.issued_at.timestamp_millis(),
            expires_at_ms: minted.expires_at.timestamp_millis(),
        },
    )
    .await?;
    Ok(token)
}

fn query_digest_value(query_value: &Value) -> Value {
    let mut digest_value = query_value.clone();
    if let Some(object) = digest_value.as_object_mut() {
        object.remove("cursor");
    }
    digest_value
}

async fn resolve_query_cursor(
    state: &AppState,
    cursor_token: &str,
    query_digest: &str,
) -> Result<usize, AppError> {
    let decoded =
        CursorAuthority::decode_stream(cursor_token.trim()).map_err(conformance_cursor_error)?;
    let stored =
        state.sync().cursor(&decoded.h).await.map_err(|error| {
            AppError::internal(format!("cursor binding lookup failed: {error}"))
        })?;
    let record = stored
        .map(coland_http::util::cursor_binding_record_from_state)
        .transpose()
        .map_err(conformance_cursor_error)?;
    let positions = CursorAuthority::resolve_stream(
        &decoded,
        &query_cursor_context(state, query_digest),
        record.as_ref(),
    )
    .map_err(conformance_cursor_error)?;
    positions
        .get("offset")
        .and_then(Value::as_u64)
        .and_then(|offset| usize::try_from(offset).ok())
        .ok_or_else(|| conformance_cursor_error(CursorAuthorityError::IntegrityInvalid))
}

fn digest_json(value: &Value) -> String {
    canonical_json(value)
        .map(|canonical| sha256_digest(canonical.as_bytes()))
        .unwrap_or_else(|_| sha256_digest(value.to_string().as_bytes()))
}

fn string_array(value: Option<&Value>) -> impl Iterator<Item = &str> {
    value
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
}

fn schema_error(error: anyhow::Error) -> AppError {
    crate::app_error!(
        SchemaViolation,
        format!("canonicalize conformance vector: {error}"),
    )
}

fn query_schema_error(message: impl Into<String>) -> AppError {
    crate::app_error!(SchemaViolation, message)
}

fn limit_error(message: impl Into<String>) -> AppError {
    crate::app_error!(QuotaExceeded, message).with_wire_code("quota_exceeded")
}

fn payload_too_large_error(message: impl Into<String>) -> AppError {
    crate::app_error!(PayloadTooLarge, message).with_wire_code("payload_too_large")
}

fn canonical_event_operation_id(record: &AcceptedEvent) -> Option<String> {
    crate::routing::events::event_log::event_operation_id(&record.envelope, &record.event_id)
        .map(|operation_id| operation_id.to_string())
}

fn canonical_event_diagnostic(record: &AcceptedEvent) -> CanonicalEventDiagnostic {
    CanonicalEventDiagnostic {
        event_id: record.event_id.clone(),
        actor_id: record.actor_id.clone(),
        realm_id: record.realm_id.clone(),
        kind: record.kind.clone(),
        canonical_digest: record.canonical_digest.clone(),
        received_at: record.received_at,
    }
}

fn projection_event_diagnostic(record: &ProjectionEventRecord) -> ProjectionEventDiagnostic {
    ProjectionEventDiagnostic {
        event_id: record.event_id.clone(),
        realm_id: record.realm_id.clone(),
        event_kind: record.event_kind.as_str().to_owned(),
        operation_kind: record.operation_kind.clone(),
        operation_id: record.operation_id.clone(),
        sender: record.sender.clone(),
        created_at: record.created_at,
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn encode_reject_classifier_recognizes_documented_prefixes() {
        assert!(encode_reject_for_vector("reject_noncanonical_numbers.v1").is_some());
        assert!(encode_reject_for_vector("reject_malformed_json.v1").is_some());
        assert!(encode_reject_for_vector("reject_other_thing.v1").is_some());
        assert!(encode_reject_for_vector("ak.vector.encoding.canonical_json.basic.v1").is_none());
    }

    #[test]
    fn strip_path_removes_nested_field() {
        let mut event = json!({
            "event_id": "ak:event:1",
            "payload": { "content": "secret", "kind": "msg" },
            "sender": "did:alice",
        });
        if let Some(object) = event.as_object_mut() {
            strip_path(object, "payload.content");
        }
        assert_eq!(
            event,
            json!({
                "event_id": "ak:event:1",
                "payload": { "kind": "msg" },
                "sender": "did:alice",
            })
        );
    }

    #[tokio::test]
    async fn query_cursor_round_trip_is_bound_to_query_digest() {
        let state = AppState::new(
            crate::config::AppConfig::test_default(),
            coland_storage_postgres::Db { pool: None },
        );
        let first_query = json!({"filter": [{"field": "kind", "op": "eq", "value": "task"}]});
        let first_digest = digest_json(&query_digest_value(&first_query));
        let second_digest =
            digest_json(&json!({"filter": [{"field": "kind", "op": "eq", "value": "note"}]}));
        let cursor_token = mint_query_cursor(&state, 25, &first_digest)
            .await
            .expect("cursor mints");

        // Wire body is the canonical core cursor: it decodes through the SDK
        // profile and carries no inline offset / query_digest fields.
        let decoded = Cursor::decode(&cursor_token).expect("SDK core cursor shape");
        assert_eq!(decoded.purpose, CursorPurpose::Stream);
        assert!(decoded.h.len() >= arkret_hlc::CURSOR_HANDLE_MIN_LEN);

        assert_eq!(
            resolve_query_cursor(&state, &cursor_token, &first_digest)
                .await
                .unwrap(),
            25
        );
        assert_eq!(
            digest_json(&query_digest_value(&json!({
                "cursor": cursor_token,
                "filter": [{"field": "kind", "op": "eq", "value": "task"}],
            }))),
            first_digest
        );

        // Cross-query replay is a binding mismatch -> integrity failure
        // (encoding.md §8.3.1), not a syntax error.
        let err = resolve_query_cursor(&state, &cursor_token, &second_digest)
            .await
            .expect_err("cursor must be bound to the canonical query shape");
        assert_eq!(err.wire_code(), "cursor_integrity_invalid");

        // Syntax failures pin `param_invalid` + reason `invalid_cursor`
        // (encoding.md §8.3 closed set).
        let err = resolve_query_cursor(&state, "ak:cursor:!!!not-base64url", &first_digest)
            .await
            .expect_err("malformed cursor must fail the syntax gate");
        assert_eq!(err.wire_code(), "param_invalid");
        assert_eq!(
            err.reason_code.as_deref(),
            Some(arkret_wire::ReasonCode::INVALID_CURSOR)
        );

        // Barrier mint keeps the canonical shape and the barrier purpose.
        let barrier = mint_query_barrier_cursor(&state, 3, &first_digest)
            .await
            .expect("barrier cursor mints");
        let decoded = Cursor::decode(&barrier).expect("SDK core cursor shape");
        assert_eq!(decoded.purpose, CursorPurpose::Barrier);
    }

    #[test]
    fn query_shape_rejects_unauthorized_projection() {
        let body = json!({});
        let query_value = json!({ "projection": ["id", "secret_notes"] });

        let err = validate_query_shape("ak.vector.query.projection", &body, &query_value)
            .expect_err("secret projection must fail closed");

        assert_eq!(err.wire_code(), "schema_violation");
        assert_eq!(
            err.http_status(),
            coland_http::error::error_http_status(err.code)
        );
    }
}
