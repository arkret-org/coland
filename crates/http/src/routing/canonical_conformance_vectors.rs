use serde_json::json;

use super::*;

// ── Validate_canonical_json_value vectors ────────────────────────────

#[test]
fn validator_accepts_sorted_snake_case_keys() {
    let value = json!({"actor_id": "x", "kind": "y"});
    assert!(validate_canonical_json_value(&value).is_ok());
}

#[test]
fn validator_accepts_sdk_canonical_encoding() {
    let value = json!({"a": 1, "b": 2});
    assert!(validate_canonical_json_value(&value).is_ok());
    let canonical = arkret_canonical::canonical_json_string(&value).unwrap();
    assert_eq!(canonical, r#"{"a":1,"b":2}"#);
}

#[test]
fn validator_preserves_raw_external_field_names() {
    let value = json!({
        "versionId": "1",
        "didDocument": {
            "@context": ["https://www.w3.org/ns/did/v1"],
            "verificationMethod": [{"publicKeyMultibase": "z6Mktest"}],
        },
    });
    assert!(validate_canonical_json_value(&value).is_ok());
}

#[test]
fn validator_accepts_dollar_prefixed_json_schema_keys() {
    let value = json!({"$id": "schema-1", "$schema": "https://json-schema.org/draft/2020-12/schema", "type": "object"});
    assert!(validate_canonical_json_value(&value).is_ok());
}

#[test]
fn validator_accepts_rfc3339_utc_z_timestamp() {
    let value = json!({"created_at": "2026-04-29T12:00:00.000Z"});
    assert!(validate_canonical_json_value(&value).is_ok());
}

#[test]
fn validator_accepts_event_bound_fixed_millisecond_timestamp() {
    let value = json!({"object": {"created_at": "2026-04-29T12:00:00.123Z"}});
    assert!(validate_canonical_json_value(&value).is_ok());
}

#[test]
fn validator_rejects_noncanonical_timestamp_precision() {
    let value = json!({"created_at": "2026-04-29T12:00:00.123456Z"});
    assert!(validate_canonical_json_value(&value).is_err());
}

#[test]
fn validator_rejects_non_utc_timestamp() {
    let value = json!({"created_at": "2026-04-29T12:00:00+05:00"});
    assert!(validate_canonical_json_value(&value).is_err());
}

#[test]
fn validator_rejects_date_only_in_at_field() {
    let value = json!({"created_at": "2026-04-29"});
    assert!(validate_canonical_json_value(&value).is_err());
}

#[test]
fn validator_ignores_non_at_timestamp_fields() {
    // Fields not ending in _at should not be validated as timestamps.
    let value = json!({"description": "not a timestamp"});
    assert!(validate_canonical_json_value(&value).is_ok());
}

#[test]
fn validator_accepts_dotted_patch_path_keys() {
    // event-and-patch.md §4.2.1: `patch` map keys are dotted snake_case
    // patch *paths*, not canonical JSON field names.
    let value = json!({
        "morph_id": "ak:morph:AQ-DRvjAp7PmXKkjoqk8vbmRDFZoSMbThbqNN0j6guzb",
        "patch": {"metadata.title": "Backfill v2"},
    });
    assert!(validate_canonical_json_value(&value).is_ok());
}

#[test]
fn event_schema_rejects_unknown_arkret_camel_case_property() {
    let catalog = arkret_schema_conformance::event_payload_validator_catalog().unwrap();
    let payload = json!({
        "realm_id": "ak:realm:ARLbXJMwpJkX1X9nXmxj2Yv0DAzpbSmEiyQvmERDGGOt",
        "strand_id": "ak:strand:AdkuCk9s9aVgrLhlJ7RStI9OuRZNs0l_4p5_NBH_a-SY",
        "unknownField": true,
    });
    assert!(
        catalog
            .validate_payload("ak.realm.set_default_strand", &payload)
            .is_err()
    );
}
