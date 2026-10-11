//! Conformance primitives exposed over the HTTP resonance surface.
//!
//! Wire encoding must be the SDK production implementation, not a local fork:
//! these handlers are used to prove coland and the shared SDK agree on the
//! canonical protocol surface.

use anyhow::Result;
/// SHA-256 digest of `bytes`, lowercase hex, prefixed with `sha256:`.
///
/// Re-exported from the SDK canonical helper instead of carrying a third fork
/// alongside the conformance harness.
pub use arkret_canonical::sha256_digest;
use serde_json::Value;

pub fn canonical_json(value: &Value) -> Result<String> {
    arkret_canonical::canonical_json_string(value).map_err(Into::into)
}

/// Order a slice of HLC strings lexicographically with `actor_id` tiebreak.
///
/// Each entry is `(hlc, actor)`; the conformance spec breaks ties on equal HLC
/// values by the lexicographically smaller `actor`.
pub fn order_hlc_clocks<T: Clone>(clocks: &[(String, String, T)]) -> Vec<(String, String, T)> {
    let mut sorted = clocks.to_vec();
    sorted.sort_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(&right.1)));
    sorted
}

/// True when `value` matches the canonical `sha256:<64-lowercase-hex>` shape.
#[cfg(test)]
pub fn looks_like_sha256_digest(value: &str) -> bool {
    value.starts_with("sha256:")
        && value.len() == "sha256:".len() + 64
        && value["sha256:".len()..]
            .chars()
            .all(|ch| ch.is_ascii_hexdigit() && !ch.is_ascii_uppercase())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn canonical_json_sorts_object_keys() {
        let value = json!({ "b": 2, "a": 1 });
        assert_eq!(canonical_json(&value).unwrap(), r#"{"a":1,"b":2}"#);
    }

    #[test]
    fn canonical_json_basic_vector_matches_smoke_test() {
        let value = json!({ "b": 2, "a": 1 });
        let canonical = canonical_json(&value).unwrap();
        assert_eq!(canonical, r#"{"a":1,"b":2}"#);
        assert_eq!(
            sha256_digest(canonical.as_bytes()),
            "sha256:43258cff783fe7036d8a43033f830adfc60ec037382473548ac742b888292777"
        );
    }

    #[test]
    fn canonical_json_nested_objects_recurse() {
        let value = json!({ "z": { "b": 2, "a": 1 }, "a": [3, { "y": 1, "x": 2 }] });
        assert_eq!(
            canonical_json(&value).unwrap(),
            r#"{"a":[3,{"x":2,"y":1}],"z":{"a":1,"b":2}}"#
        );
    }

    #[test]
    fn canonical_json_uses_sdk_utf16_key_order() {
        let supplementary = char::from_u32(0x10000).unwrap().to_string();
        let private_use = char::from_u32(0xE000).unwrap().to_string();
        let value = json!({ private_use.clone(): 2, supplementary.clone(): 1 });
        let canonical = canonical_json(&value).unwrap();

        assert!(
            canonical.find(&format!("\"{supplementary}\"")).unwrap()
                < canonical.find(&format!("\"{private_use}\"")).unwrap()
        );
    }

    #[test]
    fn cursor_round_trip_uses_sdk_shape() {
        let issued_at = chrono::Utc::now()
            .date_naive()
            .and_hms_opt(0, 0, 0)
            .expect("midnight is valid")
            .and_utc();
        let cursor = arkret_hlc::Cursor {
            v: "1".to_owned(),
            purpose: arkret_hlc::CursorPurpose::Stream,
            issued_at,
            expires_at: chrono::DateTime::from_timestamp_millis(
                issued_at.timestamp_millis() + arkret_hlc::Cursor::STREAM_TTL_MAX_MS,
            )
            .unwrap(),
            h: "abcdefghijklmnopqrstuv".to_owned(),
        };
        let encoded = cursor.encode().unwrap();
        assert!(encoded.starts_with("ak:cursor:"));
        let decoded = arkret_hlc::Cursor::decode(&encoded).unwrap();
        assert_eq!(decoded.v, cursor.v);
        assert_eq!(decoded.purpose, cursor.purpose);
        assert_eq!(decoded.issued_at, cursor.issued_at);
        assert_eq!(decoded.expires_at, cursor.expires_at);
        assert_eq!(decoded.h, cursor.h);
    }

    #[test]
    fn order_hlc_clocks_breaks_ties_by_actor() {
        let clocks = vec![
            ("100".to_owned(), "did:bob".to_owned(), ()),
            ("100".to_owned(), "did:alice".to_owned(), ()),
            ("050".to_owned(), "did:carol".to_owned(), ()),
        ];
        let ordered = order_hlc_clocks(&clocks);
        assert_eq!(ordered[0].1, "did:carol");
        assert_eq!(ordered[1].1, "did:alice");
        assert_eq!(ordered[2].1, "did:bob");
    }

    #[test]
    fn sha256_digest_is_lowercase_prefixed_hex() {
        assert!(looks_like_sha256_digest(&sha256_digest(b"hello")));
        assert!(!looks_like_sha256_digest("SHA256:abc"));
        assert!(!looks_like_sha256_digest("sha256:short"));
    }
}
