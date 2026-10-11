//! Arkret v1 protocol-compliant ID generation.
//!
//! Producer-allocated typed IDs use RFC 9562 UUIDv7 tokens. Event-derived IDs
//! (`event`, `realm`, `space`, `circle`, `strand`, and peers) instead retain
//! the complete 264-bit, 44-character Event token and must never pass through
//! the UUID persistence helpers in this module.
//!
//! See `arkret-spec/spec/v1/zh/conformance/encoding.md` §4.

/// Typed wire identifiers are owned by the SDK `arkret` (identifiers) crate.
/// coland re-exports them so the whole server shares one validated newtype per
/// id-kind instead of maintaining parallel local copies.
///
/// - [`RealmId`] is the SDK security-boundary id and validates `ak:realm:`.
/// - [`SpaceId`] is the SDK Space container id and validates `ak:space:`.
pub use arkret_identifiers::{RealmId, SpaceId};
use uuid::Uuid;

/// Generate a new typed wire ID with the given kind prefix.
///
/// Format: `ak:<kind>:<uuid-v7-36-char-lowercase-hex>`. Delegates to the SDK
/// [`arkret_identifiers::new_prefixed_uuid7`] so the canonical lowercase UUIDv7 wire
/// form is produced by the single shared primitive.
/// Generators exist only for producer-allocated kinds. The event-derived kinds
/// (`realm`, `space`, `event`, `relation`, `circle`, `strand`, `message`,
/// `morph`, `view`, `actor_profile`) have no generator at all: their ids come
/// from the create Event, so a server that minted one would be naming an object
/// no receiver can agree with (spec `zh/models/common-fields.md` section 6.0).
pub fn generate(kind: &str) -> String {
    arkret_identifiers::new_prefixed_uuid7(&format!("ak:{kind}:"))
}

pub fn generate_operation_id() -> String {
    generate("operation")
}

pub fn generate_install_id() -> String {
    generate("install")
}

pub fn generate_realm_state_snapshot_id() -> String {
    generate("realm_state_snapshot")
}

pub fn generate_request_id() -> String {
    generate("request")
}

/// Convert a wire-form `ak:<kind>:<uuid>` typed ID to its raw `Uuid` for
/// PostgreSQL `uuid` column storage. Returns `None` if the input is not a
/// well-formed typed ID with a parseable UUID segment. The kind segment is
/// not validated here; callers that care MUST check it separately (the kind
/// is canonical bytes of the wire value, see encoding.md §4).
pub fn parse_typed_uuid(typed: &str, expected_kind: &str) -> Option<Uuid> {
    let prefix = format!("ak:{}:", expected_kind);
    let rest = typed.strip_prefix(&prefix)?;
    Uuid::parse_str(rest).ok()
}

/// Kind-agnostic typed-ID → `Uuid` helpers. Canonical home is
/// `coland_storage::ids` (the lower-level crate); re-exported here so existing
/// `crate::ids::*` call sites are unchanged. SOL-COR-02: the `expect_internal`
/// variant is reserved for IDs the server itself generated or that arrived
/// through an SDK strong-typed producer-allocated newtype — see the storage
/// copies' docs for the full contract.
pub use coland_storage::ids::{typed_uuid_part, typed_uuid_part_expect_internal};

/// Format a raw `Uuid` back to a typed wire ID `ak:<kind>:<uuid>`.
pub fn format_typed_uuid(kind: &str, uuid: &Uuid) -> String {
    format!("ak:{}:{}", kind, uuid)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_realm_id() -> String {
        let digest = arkret_identifiers::Hash::new(arkret_canonical::sha256_digest(
            b"coland-http-id-fixture",
        ))
        .unwrap();
        RealmId::from_event_id(&arkret_identifiers::EventId::from_event_digest(&digest).unwrap())
            .to_string()
    }

    #[test]
    fn parse_typed_uuid_roundtrip() {
        let id = generate_operation_id();
        let raw = parse_typed_uuid(&id, "operation").expect("parse");
        let back = format_typed_uuid("operation", &raw);
        assert_eq!(id, back);
    }

    #[test]
    fn parse_typed_uuid_rejects_wrong_kind() {
        let id = generate_operation_id();
        assert!(parse_typed_uuid(&id, "space").is_none());
    }

    #[test]
    fn realm_id_accepts_wire_form() {
        let wire = fixture_realm_id();
        let id = RealmId::new(wire.clone()).expect("realm id parse");
        assert_eq!(id.as_str(), wire);
        assert_eq!(id.to_string(), wire);
        assert_eq!(<RealmId as AsRef<str>>::as_ref(&id), wire.as_str());
    }

    #[test]
    fn realm_id_round_trips_through_serde() {
        let id = RealmId::new(fixture_realm_id()).expect("realm id");
        let json = serde_json::to_string(&id).expect("serialize");
        let parsed: RealmId = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed, id);
    }

    #[test]
    fn realm_id_fromstr_matches_new() {
        let wire = fixture_realm_id();
        let via_fromstr: RealmId = wire.parse().expect("FromStr");
        let via_new = RealmId::new(wire.clone()).expect("new");
        assert_eq!(via_fromstr, via_new);
    }

    #[test]
    fn space_container_id_rejects_bad_kind() {
        assert!(SpaceId::new(fixture_realm_id()).is_err());
        assert!(SpaceId::new("ak:space:01914b2e-7a6d-7cc2-98eb-07c7c9ff4b55").is_err());
        assert!(SpaceId::new("").is_err());
    }
}
