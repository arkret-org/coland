use super::*;

/// Allowed `proof_kind` enum per the spec
/// `recovery-policy.schema.json`.
pub(super) const ALLOWED_PROOF_KINDS: &[&str] = &[
    "did_root",
    "recovery_unlock",
    "device_quorum",
    "trusted_recovery_service",
];

#[derive(salvo::oapi::ToSchema, Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ColandRecoveryPoliciesOutcome {
    pub(super) policies: Vec<RecoveryPolicySummary>,
}
