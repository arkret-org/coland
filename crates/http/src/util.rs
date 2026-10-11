//! Shared mechanical helpers used across every handler module.
//!
//! Anything in here MUST be:
//! - free of `AppState` access (no locks, no persistence reads),
//! - free of business logic (no decision-making about events / authz / sync),
//! - and reusable across at least two domains.
//!
//! Domain-specific helpers (`auth_or_render`, `append_audit_log`,
//! `realm_has_member`, the blob/MIME helpers, the proof verifiers, etc.) stay
//! in their owning module so they can carry their own invariants. They will
//! land here only if they outgrow that scope.

use arkret_hlc::{Cursor, CursorPurpose};
use arkret_identifiers::{DeviceId, Did, SpaceId};
use salvo::http::header;
use salvo::prelude::*;

pub use crate::error::render_error;

/// Pull a single query-string value, decoding `+` to space and any
/// `%XX` percent-escapes back to their raw byte form. Required for
/// typed-id query args like `?space_id=ak:space:...` where browsers
/// (and `encodeURIComponent`) emit `ck%3Aspace%3A...` — without
/// decoding the downstream typed-id validator rejects the literal.
pub fn query_param(req: &Request, key: &str) -> Option<String> {
    req.uri().query().and_then(|query| {
        query.split('&').find_map(|pair| {
            let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
            (name == key).then(|| percent_decode_query_value(value))
        })
    })
}

fn percent_decode_query_value(value: &str) -> String {
    // Replace `+` → space, then percent-decode bytes. Fall back to the
    // raw value if decoding produces invalid UTF-8 — caller-side
    // validators surface the typed-id error in that case.
    let with_spaces = value.replace('+', " ");
    let bytes = with_spaces.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hi = hex_digit(bytes[i + 1]);
            let lo = hex_digit(bytes[i + 2]);
            if let (Some(hi), Some(lo)) = (hi, lo) {
                out.push((hi << 4) | lo);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8(out).unwrap_or(with_spaces)
}

fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

// The repeated-arg form (`?realms=A&realms=B`) is what every selector
// path uses; comma-separated values are not standardized.

/// Pull **every** occurrence of `key` from the query string as repeated args
/// (e.g. `?realms=A&realms=B&realms=C`) — required for spec C17
/// `ak.self.committed_event.read.scan.v1` / `ak.self.committed_event.stream.subscribe.v1` selectors
/// which accept `realms[]` ∪ `actors[]`. `+` decoded to space; empty values dropped.
pub fn query_param_all(req: &Request, key: &str) -> Vec<String> {
    let Some(query) = req.uri().query() else {
        return Vec::new();
    };
    query
        .split('&')
        .filter_map(|pair| {
            let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
            if name == key && !value.is_empty() {
                Some(percent_decode_query_value(value))
            } else {
                None
            }
        })
        .collect()
}

/// Extract the `Bearer ...` token from the `Authorization` header.
pub fn bearer_token(req: &Request) -> Option<&str> {
    req.headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| {
            arkret_server::authorization_credential(
                value,
                arkret_server::AuthorizationScheme::Bearer,
            )
        })
}

/// Extract an RFC 9449 DPoP-bound access token from `Authorization`.
/// Bearer and DPoP are deliberately separate parsers so a caller cannot
/// silently reinterpret a token presented with the wrong scheme.
pub fn dpop_token(req: &Request) -> Option<&str> {
    req.headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| {
            arkret_server::authorization_credential(value, arkret_server::AuthorizationScheme::Dpop)
        })
}

#[cfg(test)]
mod authorization_scheme_tests {
    use super::*;

    #[test]
    fn bearer_and_dpop_schemes_are_not_interchangeable() {
        let mut bearer = Request::new();
        bearer
            .headers_mut()
            .insert(header::AUTHORIZATION, "Bearer local-token".parse().unwrap());
        assert_eq!(bearer_token(&bearer), Some("local-token"));
        assert_eq!(dpop_token(&bearer), None);

        let mut dpop = Request::new();
        dpop.headers_mut()
            .insert(header::AUTHORIZATION, "DPoP session-grant".parse().unwrap());
        assert_eq!(dpop_token(&dpop), Some("session-grant"));
        assert_eq!(bearer_token(&dpop), None);
    }
}

// ── Crypto helpers ──────────────────────────────────────────────────────────

/// Hex-encoded SHA-256 of `bytes` (lowercase, 64 chars).
///
/// Thin re-export of the SDK [`arkret_canonical::sha256_hex`] so coland
/// shares the single canonical hash primitive instead of a local
/// reimplementation.
pub fn sha256_hex(bytes: &[u8]) -> String {
    arkret_canonical::sha256_hex(bytes)
}

/// Canonical JSON SHA-256 digest (`sha256:<hex>`) of any serializable value.
///
/// Single home for the canonicalize-then-digest step every handler module
/// used to reimplement locally. Callers that need a typed `Hash` wrap the
/// returned string themselves.
pub fn canonical_digest(value: &impl serde::Serialize) -> Result<String, crate::error::AppError> {
    arkret_canonical::canonical_sha256(value).map_err(|error| {
        crate::error::AppError::internal(format!("canonical digest failed: {error}"))
    })
}

// ── Token / digest validators ───────────────────────────────────────────────

/// Validate a `ak:cursor:<base64url>` token.
///
/// Delegate the issuing-service wire validation to the SDK cursor model so
/// this transport gate cannot drift from the canonical timestamp field names
/// or purpose-specific TTL rules.
pub fn is_valid_sync_token(token: &str) -> bool {
    Cursor::decode(token).is_ok_and(|cursor| {
        matches!(
            cursor.purpose,
            CursorPurpose::Stream | CursorPurpose::Barrier
        )
    })
}

#[cfg(test)]
mod sync_token_tests {
    use super::*;

    #[test]
    fn accepts_sdk_stream_and_barrier_cursor_wire_shapes() {
        let stream = Cursor::new_at(chrono::Utc::now(), 60_000)
            .expect("stream cursor")
            .with_stateful_handle("a".repeat(22));
        assert!(is_valid_sync_token(
            &stream.encode().expect("encoded stream cursor")
        ));

        let barrier = stream.with_barrier();
        assert!(is_valid_sync_token(
            &barrier.encode().expect("encoded barrier cursor")
        ));
    }
}

/// Convert a persisted [`coland_services::sync::CursorState`] row into the
/// SDK [`arkret_server::CursorBindingRecord`] consumed by
/// [`arkret_server::CursorAuthority::resolve_stream`].
///
/// Rows missing required binding fields map to
/// [`arkret_server::CursorAuthorityError::IntegrityInvalid`] (encoding.md
/// §8.3.1: incomplete/foreign binding rows are integrity failures, never a
/// panic or a silent accept).
pub fn cursor_binding_record_from_state(
    record: coland_services::sync::CursorState,
) -> Result<arkret_server::CursorBindingRecord, arkret_server::CursorAuthorityError> {
    use arkret_server::CursorAuthorityError;
    let purpose = match record.purpose.as_str() {
        "stream" => CursorPurpose::Stream,
        "barrier" => CursorPurpose::Barrier,
        _ => return Err(CursorAuthorityError::IntegrityInvalid),
    };
    Ok(arkret_server::CursorBindingRecord {
        handle: record.handle,
        context: arkret_server::CursorBindingContext::new(
            record
                .binding_subject
                .ok_or(CursorAuthorityError::IntegrityInvalid)?,
            record.device_id,
            record.service_id,
            record
                .filter_digest
                .ok_or(CursorAuthorityError::IntegrityInvalid)?,
        ),
        purpose,
        positions: record
            .positions
            .ok_or(CursorAuthorityError::IntegrityInvalid)?,
        issued_at_ms: record.issued_at_ms,
        expires_at_ms: record.expires_at_ms,
    })
}

/// Active `<digest-suite>:<64 lowercase hex>` hash shape.
pub fn is_valid_hash_digest(value: &str) -> bool {
    arkret_identifiers::Hash::new(value.to_owned()).is_ok()
}

/// 64 lowercase hex characters.
pub fn is_valid_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .chars()
            .all(|c| c.is_ascii_digit() || matches!(c, 'a'..='f'))
}

// ── Identifier / handle validators ──────────────────────────────────────────

/// Validate and parse a DID.
pub fn validate_did(value: &str) -> arkret_identifiers::Result<Did> {
    Did::new(value.to_owned())
}

pub fn validate_device_id(value: &str) -> arkret_identifiers::Result<DeviceId> {
    DeviceId::new(value.to_owned())
}

pub fn validate_space_id(value: &str) -> arkret_identifiers::Result<SpaceId> {
    SpaceId::new(value.to_owned())
}

/// Lowercase + ensure leading `@`.
pub fn normalize_handle(handle: &str) -> String {
    let trimmed = handle.trim().to_ascii_lowercase();
    if trimmed.starts_with('@') {
        trimmed
    } else {
        format!("@{trimmed}")
    }
}

/// Bare localpart form: trimmed, lowercase, no leading `@`.
pub fn normalize_localpart(handle: &str) -> String {
    normalize_handle(handle).trim_start_matches('@').to_owned()
}

/// Best-effort `@<tail>` derived from the last DID label, with `.` → `-`.
pub fn handle_for_did(did: &str) -> String {
    did.rsplit(':')
        .next()
        .map(|tail| format!("@{}", tail.replace('.', "-")))
        .unwrap_or_else(|| "@user".to_owned())
}

// ── Discoverability validator ───────────────────────────────────────────────
//
// (The `entity` abstraction never landed in `arkret-spec/v1`; typed
// objects in the protocol are `ak:space:` / `ak:strand:` / `ak:morph:` /
// `ak:relation:` / `ak:view:`, each driven by its own dedicated event
// kind.)

/// Allow-list of space-discoverability values.
pub fn is_valid_discoverability(value: &str) -> bool {
    matches!(
        value,
        "public" | "listed" | "restricted" | "unlisted" | "invite_only" | "secret"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// AKP-0008 / AKP-0009 (B-D, P2-G) — coland's inbound DID validator
    /// MUST route through the SDK `Did::new` parser. Regression guard so
    /// the wire ingress points (event_log envelope, agents.rs handlers,
    /// account.register, etc.) stay aligned with the spec DID format.
    #[test]
    fn validate_did_routes_through_sdk_parser() {
        assert!(validate_did("did:web:alice.example").is_ok());
        assert!(validate_did("did:key:z6Mki7v1mC9ATsB4VxAfqgZTLZbDpKpUjk78aWxNqQuqQqQu").is_ok());
        // Empty / scheme-less / wrong scheme MUST fail. The SDK validator
        // is the source of truth — we just assert the wrapper bubbles the
        // error.
        assert!(validate_did("").is_err());
        assert!(validate_did("not-a-did").is_err());
        assert!(validate_did("http://example.com").is_err());
        assert!(validate_did("did:").is_err());
    }
}
