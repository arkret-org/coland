use arkret_models_collaboration::agent_operations::AgentLifecycleState;
use arkret_models_collaboration::agent_scope::AgentRuntimeApprovalRequestBody;
use arkret_wire::{DidUrl, EventId, Hash, OpaqueLocalId};
use chrono::{DateTime, Utc};
use serde_json::Value;
use uuid::Uuid;

use crate::AccountPk;

#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct PendingAgentPairingCommitIntent {
    pub request_digest: String,
    pub authorize_event_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_authorization_event: Option<arkret_wire::Event>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope_custody_ref: Option<crate::AgentScopeCustodyRef>,
}

/// Durable projection of a Agent principal.
///
/// The controller, PCR, and controller-authorization fields form the immutable
/// identity binding. Adapters preserve those immutable fields during updates.
#[derive(Clone, Debug, PartialEq)]
pub struct AgentPrincipalRecord {
    pub id: String,
    pub controller_principal_id: String,
    pub principal_control_realm_id: String,
    pub controller_authorization_ref: DidUrl,
    pub display_name: Option<String>,
    pub agent_slug: Option<String>,
    pub avatar_blob_ref: Option<String>,
    pub state: AgentLifecycleState,
    pub requested_scope: Option<Value>,
    pub accountability: Option<Value>,
    pub provision_event_refs: Option<Value>,
    pub pairing_request_id: Option<OpaqueLocalId>,
    pub paired_pairing_request_id: Option<OpaqueLocalId>,
    pub paired_request_digest: Option<String>,
    pub pending_pairing_commit_intent: Option<PendingAgentPairingCommitIntent>,
    pub pairing_code: Option<String>,
    pub pairing_expires_at: Option<DateTime<Utc>>,
    pub approval_request_id: Option<OpaqueLocalId>,
    pub controller_account_pk: Option<AccountPk>,
    pub recipient_id: Option<String>,
    pub runtime_key_binding_digest: Option<String>,
    pub runtime_public_key_digest: Option<String>,
    pub runtime_attestation_digest: Option<String>,
    pub runtime_proof_verified_at: Option<DateTime<Utc>>,
    pub approval_notification_id: Option<Uuid>,
    pub runtime_key_request: Option<AgentRuntimeApprovalRequestBody>,
    pub approval_requested_at: Option<DateTime<Utc>>,
    pub authorized_event_ref: Option<String>,
    pub authorized_verification_method: Option<String>,
    pub authorized_public_key_digest: Option<String>,
    pub authorized_key_event: Option<arkret_wire::Event>,
    pub signer_resolution_evidence_ref: Option<arkret_wire::SignerEvidenceRef>,
    /// Station-local signer-resolution snapshot retained for audit/debugging.
    /// Protocol authorization is bound by `signer_resolution_evidence_ref`.
    pub current_signer_evidence: Option<
        arkret_models_identity::authenticated_signer_resolution_evidence::AuthenticatedSignerResolutionEvidence,
    >,
    pub state_changed_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl AgentPrincipalRecord {
    pub fn new(
        id: String,
        controller_principal_id: String,
        principal_control_realm_id: String,
        controller_authorization_ref: DidUrl,
        state: AgentLifecycleState,
        created_at: DateTime<Utc>,
    ) -> Self {
        Self {
            id,
            controller_principal_id,
            principal_control_realm_id,
            controller_authorization_ref,
            display_name: None,
            agent_slug: None,
            avatar_blob_ref: None,
            state,
            requested_scope: None,
            accountability: None,
            provision_event_refs: None,
            pairing_request_id: None,
            paired_pairing_request_id: None,
            paired_request_digest: None,
            pending_pairing_commit_intent: None,
            pairing_code: None,
            pairing_expires_at: None,
            approval_request_id: None,
            controller_account_pk: None,
            recipient_id: None,
            runtime_key_binding_digest: None,
            runtime_public_key_digest: None,
            runtime_attestation_digest: None,
            runtime_proof_verified_at: None,
            approval_notification_id: None,
            runtime_key_request: None,
            approval_requested_at: None,
            authorized_event_ref: None,
            authorized_verification_method: None,
            authorized_public_key_digest: None,
            authorized_key_event: None,
            signer_resolution_evidence_ref: None,
            current_signer_evidence: None,
            state_changed_at: Some(created_at),
            created_at,
            updated_at: created_at,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct OpenAgentPairingHandle {
    pub pairing_request_id: OpaqueLocalId,
    pub pairing_code: String,
    pub expires_at: DateTime<Utc>,
    pub pending_runtime_key_request:
        Option<arkret_models_collaboration::agent_scope::AgentRuntimeApprovalRequestBody>,
}

impl OpenAgentPairingHandle {
    pub fn is_live_at(&self, now: DateTime<Utc>) -> bool {
        self.expires_at > now
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct ActiveAgentRuntimeBinding {
    pub completed_pairing_request_id: OpaqueLocalId,
    pub authorized_event_ref: EventId,
    pub verification_method: DidUrl,
    pub public_key_digest: Hash,
    pub key_authorization_event: arkret_wire::Event,
    pub signer_resolution_evidence_ref: arkret_wire::SignerEvidenceRef,
    pub current_signer_evidence:
        arkret_models_identity::authenticated_signer_resolution_evidence::AuthenticatedSignerResolutionEvidence,
}

#[derive(Clone, Debug, PartialEq)]
pub struct AgentRuntimeBindings {
    pub open_handle: Option<OpenAgentPairingHandle>,
    pub active_binding: Option<ActiveAgentRuntimeBinding>,
}

impl AgentPrincipalRecord {
    /// Reconstruct the two protocol states hidden behind the flat persistence
    /// columns. Partial tuples are rejected instead of being interpreted as a
    /// weaker state.
    pub fn runtime_bindings(&self) -> Result<AgentRuntimeBindings, String> {
        let active_binding = match self.authorized_event_ref.as_ref() {
            Some(authorized_event_ref) => {
                let completed_pairing_request_id =
                    self.paired_pairing_request_id.clone().ok_or_else(|| {
                        "active Agent runtime binding is missing paired_pairing_request_id"
                            .to_owned()
                    })?;
                let authorized_event_ref =
                    EventId::new(authorized_event_ref.clone()).map_err(|error| {
                        format!("active Agent runtime authorized_event_ref is invalid: {error}")
                    })?;
                let verification_method = self
                    .authorized_verification_method
                    .clone()
                    .ok_or_else(|| {
                        "active Agent runtime binding is missing verification_method".to_owned()
                    })
                    .and_then(|value| {
                        DidUrl::new(value).map_err(|error| {
                            format!("active Agent runtime verification_method is invalid: {error}")
                        })
                    })?;
                let public_key_digest = self
                    .authorized_public_key_digest
                    .clone()
                    .ok_or_else(|| {
                        "active Agent runtime binding is missing public_key_digest".to_owned()
                    })
                    .and_then(|value| {
                        Hash::new(value).map_err(|error| {
                            format!("active Agent runtime public_key_digest is invalid: {error}")
                        })
                    })?;
                let key_authorization_event =
                    self.authorized_key_event.clone().ok_or_else(|| {
                        "active Agent runtime binding is missing key_authorization_event".to_owned()
                    })?;
                let signer_resolution_evidence_ref =
                    self.signer_resolution_evidence_ref.clone().ok_or_else(|| {
                        "active Agent runtime binding is missing signer evidence reference"
                            .to_owned()
                    })?;
                let current_signer_evidence =
                    self.current_signer_evidence.clone().ok_or_else(|| {
                        "active Agent runtime binding is missing current signer evidence".to_owned()
                    })?;
                // The evidence is content-addressed: recompute the address from
                // the carried bytes instead of trusting the stored sibling.
                if !current_signer_evidence
                    .matches_ref(&signer_resolution_evidence_ref)
                    .map_err(|error| error.to_string())?
                {
                    return Err(
                        "active Agent runtime signer evidence reference does not address its evidence"
                            .to_owned(),
                    );
                }
                let key = arkret_models_identity::agent_signer_evidence::AgentAuthorizedSigningKey::from_event(&key_authorization_event).map_err(|error| error.to_string())?;
                if key.agent_id.as_str() != self.id
                    || key.agent_key_authorize_event_id != authorized_event_ref
                    || key.verification_method != verification_method
                    || key.public_key_digest != public_key_digest
                {
                    return Err(
                        "active Agent authorization Event does not match its indexed key"
                            .to_owned(),
                    );
                }
                Some(ActiveAgentRuntimeBinding {
                    completed_pairing_request_id,
                    authorized_event_ref,
                    verification_method,
                    public_key_digest,
                    key_authorization_event,
                    signer_resolution_evidence_ref,
                    current_signer_evidence,
                })
            }
            None => {
                if self.paired_pairing_request_id.is_some()
                    || self.authorized_verification_method.is_some()
                    || self.authorized_public_key_digest.is_some()
                    || self.authorized_key_event.is_some()
                    || self.signer_resolution_evidence_ref.is_some()
                    || self.current_signer_evidence.is_some()
                {
                    return Err(
                        "Agent runtime authorization columns contain a partial active binding"
                            .to_owned(),
                    );
                }
                None
            }
        };

        let open_handle = match self.pairing_request_id.as_ref() {
            Some(pairing_request_id)
                if self.paired_pairing_request_id.as_deref()
                    != Some(pairing_request_id.as_str()) =>
            {
                let pairing_code = self.pairing_code.clone().ok_or_else(|| {
                    "open Agent pairing handle is missing pairing_code".to_owned()
                })?;
                let expires_at = self.pairing_expires_at.ok_or_else(|| {
                    "open Agent pairing handle is missing pairing_expires_at".to_owned()
                })?;
                if self.runtime_key_request.as_ref().is_some_and(|request| {
                    request.pairing_request_id.as_str() != pairing_request_id.as_str()
                        || request.agent_id.as_str() != self.id
                }) {
                    return Err(
                        "pending Agent runtime key request does not match its open handle"
                            .to_owned(),
                    );
                }
                Some(OpenAgentPairingHandle {
                    pairing_request_id: pairing_request_id.clone(),
                    pairing_code,
                    expires_at,
                    pending_runtime_key_request: self.runtime_key_request.clone(),
                })
            }
            _ => {
                if self.runtime_key_request.is_some() {
                    return Err(
                        "pending Agent runtime key request has no unconsumed pairing handle"
                            .to_owned(),
                    );
                }
                None
            }
        };

        Ok(AgentRuntimeBindings {
            open_handle,
            active_binding,
        })
    }
}
