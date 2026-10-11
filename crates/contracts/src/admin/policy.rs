//! Deployment-local policy document contract
//! (`GET`/`POST`/`DELETE /_coland/self/policies`).
//!
//! Both sides of this endpoint used to hand-write their own shape. The
//! producer emitted `owner` and a required canonical `updated_at`; the
//! operator console dropped `owner` entirely and declared `updated_at` an
//! optional string, so a producer rename would have blanked the column at
//! runtime with nothing failing to compile. One definition removes that
//! whole class of drift.
//!
//! `effect` is a closed set on the wire — spec `governance-objects.md`
//! (`Policy.default_effect` / `PolicyRule.effect`) and
//! `policy.schema.json#/$defs/policy_effect` register exactly four rule
//! effects (`allow`, `deny`, `quarantine`, `require_review`), and that type
//! lives in the SDK (`arkret_wire::PolicyEffect`). The five-value set with
//! `soft_deny` / `hard_deny` instead of `deny` is an authorization-decision
//! enum, not a valid stored rule effect — the two closed sets must not be conflated.
//!
//! `AdminPolicyPayload::resource` is permanently opaque operator data.  It is
//! not an extension point for approval evidence, audit records, or policy
//! decisions, and consumers must neither parse nor display its substructure.
//! Those concerns use their existing typed audit and policy-decision APIs.

pub use arkret_wire::PolicyEffect;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// The stored policy payload. The shape does not vary with `policy_kind` —
/// every document carries these four members — so it is a struct, not a
/// `policy_kind`-keyed `Value`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AdminPolicyPayload {
    /// Spec four-value `policy_effect` closed set; the SDK type carries no
    /// OpenAPI schema, so the field documents as a string here.
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = String)))]
    pub effect: PolicyEffect,
    #[serde(default)]
    pub actions: Vec<String>,
    /// Permanently opaque operator-authored data.
    ///
    /// Consumers must not infer, parse, or display subfields. In particular,
    /// evidence and audit data belong to their typed APIs, never here.
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    /// Permanently opaque operator data; see [`AdminPolicyPayload::resource`].
    #[serde(default)]
    pub resource: Value,
    /// Stored operator-authored obligations; not evaluated by authorization.
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    #[serde(default)]
    pub obligations: Vec<Value>,
}

/// One stored policy document as served to the operator console.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AdminPolicyDocument {
    pub policy_id: String,
    /// Actor that owns the document. Dropped by the previous console mirror,
    /// which is why the policy list could not say who authored a rule.
    pub owner: String,
    pub scope: String,
    pub subject_ref: String,
    pub policy_kind: String,
    pub payload: AdminPolicyPayload,
    pub active: bool,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub updated_at: DateTime<Utc>,
}

/// Cursor page of policy documents.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AdminPolicyDocumentPage {
    pub policies: Vec<AdminPolicyDocument>,
    pub next_cursor: Option<String>,
}

/// Create-or-replace request body. Shared so the console cannot send a shape
/// the server does not accept.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct UpsertPolicyDocumentRequestBody {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_id: Option<String>,
    pub scope: String,
    pub subject_ref: String,
    pub policy_kind: String,
    /// Spec four-value `policy_effect` closed set; see [`AdminPolicyPayload`]
    /// for why the OpenAPI schema degrades to a plain string.
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = String)))]
    pub effect: PolicyEffect,
    #[serde(default)]
    pub actions: Vec<String>,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    #[serde(default)]
    pub resource: Value,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    #[serde(default)]
    pub obligations: Vec<Value>,
    #[serde(default = "default_active")]
    pub active: bool,
}

fn default_active() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn resource_round_trips_as_opaque_json_without_a_typed_evidence_shape() {
        let payload = AdminPolicyPayload {
            effect: PolicyEffect::RequireReview,
            actions: vec!["ak.realm.policy.update".to_owned()],
            resource: json!({
                "approval_evidence": {"operator_key": "opaque"},
                "audit_trail": [{"actor": "opaque"}]
            }),
            obligations: Vec::new(),
        };

        let encoded = serde_json::to_value(&payload).expect("serialize payload");
        let decoded: AdminPolicyPayload =
            serde_json::from_value(encoded.clone()).expect("deserialize payload");

        assert_eq!(decoded.resource, encoded["resource"]);
        assert!(encoded.get("approval_evidence").is_none());
        assert!(encoded.get("audit_trail").is_none());
    }
}
