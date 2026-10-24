//! Internal transaction context for the two registered audit operations.

use arkret_models_collaboration::authority_commit::{
    AuditPairedEventAcceptanceOutcome, AuditPairedEventUnitSubmission,
};
use arkret_models_collaboration::strand_watch_operations::{
    WatchAuditReadRequestBody, WatchAuditReadResponseBody,
};
use arkret_wire::Event;

#[derive(Clone, Debug)]
pub enum RegisteredAuditCommit {
    Pair {
        request: Box<AuditPairedEventUnitSubmission>,
        approvals: Box<[Option<crate::EventApprovalCommit>; 2]>,
    },
    WatchRead {
        request: Box<WatchAuditReadRequestBody>,
    },
}

impl RegisteredAuditCommit {
    pub fn pair_for(&self, event: &Event) -> bool {
        matches!(self, Self::Pair { request, .. } if request.events.iter().any(|slot| slot.event == *event))
    }
    pub fn read_for(&self, event: &Event) -> bool {
        matches!(self, Self::WatchRead { request } if request.audit_submission.event == *event)
    }
    pub fn canonical_request(&self) -> crate::PersistenceResult<Vec<u8>> {
        match self {
            Self::Pair { request, .. } => arkret_canonical::canonical_json_bytes(request),
            Self::WatchRead { request } => arkret_canonical::canonical_json_bytes(request),
        }
        .map_err(crate::PersistenceError::database)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RegisteredAuditOutcome {
    Pair(AuditPairedEventAcceptanceOutcome),
    WatchRead(WatchAuditReadResponseBody),
}

#[derive(Clone, Debug)]
pub struct RegisteredAuditResult {
    pub canonical_request: Vec<u8>,
    pub outcome: RegisteredAuditOutcome,
}
