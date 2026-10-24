//! Deployment-local source supply; never an Arkret operation or evidence carrier.

use arkret_identifiers::{EventId, Hash, RealmId, StrandId};
use arkret_models_collaboration::session_grants::RequestedAgentSessionGrantScope;
use arkret_wire::{AccountId, DidUrl};
use serde::{Deserialize, Serialize};

pub const AGENT_SESSION_AUTHORITY_PATH: &str =
    "/_coland/account-authority/agent-session-authority/read";

/// Called only after this deployment's Account Authority authenticates the
/// holder and canonical issue/refresh intent. The Station owns source facts;
/// the Authority owns proof verification and the issuer ledger transaction.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentSessionAuthorityRequest {
    pub agent_account_id: AccountId,
    pub controller_account_id: AccountId,
    pub agent_key_authorization_ref: EventId,
    pub verification_method: DidUrl,
    pub intent_digest: Hash,
    pub requested_scope: Vec<String>,
    pub resource_scope: RequestedAgentSessionGrantScope,
    pub approval_evidence_refs: Vec<EventId>,
}

/// A bounded projection from one current source snapshot. It cannot authorize
/// a later content operation, bypass a profile gate or expand a predecessor.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentSessionAuthorityView {
    pub binding: AgentSessionAuthorityRequest,
    pub granted_scope: Vec<String>,
    pub approval_required: bool,
    pub realm_ids: Vec<RealmId>,
    pub strand_ids: Vec<StrandId>,
    pub allowed_tracks: Vec<String>,
    pub allowed_data_labels: Vec<String>,
    pub allowed_endpoints: Vec<String>,
    pub capability_grant_refs: Vec<arkret_identifiers::GrantId>,
    pub policy_refs: Vec<String>,
}

impl AgentSessionAuthorityView {
    /// Exact internal binding is additional to authenticated channel ownership.
    pub fn matches_request(&self, request: &AgentSessionAuthorityRequest) -> bool {
        match (
            arkret_canonical::canonical_json_bytes(&self.binding),
            arkret_canonical::canonical_json_bytes(request),
        ) {
            (Ok(actual), Ok(expected)) => actual == expected,
            _ => false,
        }
    }
}
