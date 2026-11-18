use super::*;

#[derive(salvo::oapi::ToSchema, Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ColandRecoveryPoliciesOutcome {
    pub(super) policies: Vec<RecoveryPolicySummary>,
}
