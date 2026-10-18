//! Internal historical approval authority; the wire evidence is SDK-owned.
use arkret_wire::{ApprovalSignature, EventId};
use chrono::{DateTime, Utc};

/// Method-native history resolved by the service at the evidence signing time.
#[derive(Clone, Debug)]
pub struct ApprovalHistoricalMethod {
    pub signature: ApprovalSignature,
    pub public_key: [u8; 32],
    pub native_control: Option<arkret_identity::principal_control::NativeIdentityControlKey>,
    pub control_history: Option<serde_json::Value>,
}

/// Service-prepared history is bound to one candidate transaction and cannot
/// be deserialized from a caller-supplied wire object.
#[derive(Clone, Debug)]
pub struct EventApprovalCommit {
    /// Process-local binding selected only by the registered command executor.
    pub carrier_binding: Option<ApprovalCarrierBinding>,
    pub event_id: EventId,
    pub event_digest: String,
    pub committed_at: DateTime<Utc>,
    pub methods: Vec<ApprovalHistoricalMethod>,
    /// Only management reviews require these process-local current AA observations.
    /// They are not approval signatures or reusable lifecycle credentials.
    pub management_current: Option<crate::ManagementReviewCurrent>,
}

/// Closed registered carriers; never populated by deserializing peer input.
#[derive(Clone, Debug)]
pub enum ApprovalCarrierBinding {
    AuditPair { request_digest: String },
    WatchAuditRead { request_digest: String },
}

impl ApprovalCarrierBinding {
    pub fn operation(&self) -> &'static str {
        match self {
            Self::AuditPair { .. } => {
                arkret_wire::ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT_V1
            }
            Self::WatchAuditRead { .. } => {
                arkret_wire::ServiceOperationId::SELF_STRAND_WATCH_COMMAND_AUDIT_READ_V1
            }
        }
    }
    pub fn request_digest(&self) -> &str {
        match self {
            Self::AuditPair { request_digest } | Self::WatchAuditRead { request_digest } => {
                request_digest
            }
        }
    }
}

/// Historical votes for a real operation target, with no synthetic Event.
#[derive(Clone, Debug)]
pub struct OperationApprovalCommit {
    pub target_digest: arkret_wire::Hash,
    pub operation: arkret_wire::ServiceOperationId,
    pub methods: Vec<ApprovalHistoricalMethod>,
    pub current: crate::ManagementReviewCurrent,
}
