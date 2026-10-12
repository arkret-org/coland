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
    pub event_id: EventId,
    pub event_digest: String,
    pub committed_at: DateTime<Utc>,
    pub methods: Vec<ApprovalHistoricalMethod>,
    /// Only management reviews require these process-local current AA observations.
    /// They are not approval signatures or reusable lifecycle credentials.
    pub management_current: Option<crate::ManagementReviewCurrent>,
}
