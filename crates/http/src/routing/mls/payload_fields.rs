//! Canonical MLS governance binding reader.

use serde_json::Value;

/// The `mls_governance_binding` object all three MLS payloads require under
/// the name `governance_binding`.
pub(crate) fn governance_binding(value: &Value) -> Option<&Value> {
    value.get("governance_binding")
}
