use arkret_models_collaboration::account_status::{AccountStatusReceipt, AccountStatusRecord};
use arkret_models_collaboration::objects::account_status::AccountStatus;

use crate::{PersistenceResult, async_trait};

/// Durable evidence classes that can prove another Station already holds, or
/// is about to hold, state for one exact AccountId. The set is closed by
/// account-lifecycle.md §3.1; callers must not invent a generic peer source.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccountStatusAffectedServiceSource {
    Session,
    Device,
    KeyPackage,
    ToDevice,
    PushRoute,
    PrincipalLocator,
    RealmMembership,
}

impl AccountStatusAffectedServiceSource {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Session => "session",
            Self::Device => "device",
            Self::KeyPackage => "key_package",
            Self::ToDevice => "to_device",
            Self::PushRoute => "push_route",
            Self::PrincipalLocator => "principal_locator",
            Self::RealmMembership => "realm_membership",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccountStatusAffectedServiceObservation {
    pub service_id: arkret_wire::DidCoreId,
    pub source: AccountStatusAffectedServiceSource,
    pub observed_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccountStatusPropagationProjectionState {
    Scheduled,
    Complete,
    Incomplete,
}

impl AccountStatusPropagationProjectionState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Scheduled => "scheduled",
            Self::Complete => "complete",
            Self::Incomplete => "incomplete",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccountStatusPropagationProjection {
    pub account_authority_id: arkret_wire::DidCoreId,
    pub account_id: arkret_wire::AccountId,
    pub account_status_record_id: arkret_wire::AccountStatusRecordId,
    pub status_sequence: u64,
    pub state: AccountStatusPropagationProjectionState,
    pub pending_destination_count: u64,
    pub deadline_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccountStatusPropagationProjectionTransition {
    pub projection: AccountStatusPropagationProjection,
    pub became_incomplete: bool,
    pub became_complete: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccountStatusReplicaConflictKind {
    Fork,
    BindingRollback,
    TransitionInvalid,
    ErasurePendingTerminal,
}

#[derive(Clone, Debug, PartialEq)]
pub enum AccountStatusReplicaAppend {
    Accepted(AccountStatusReceipt),
    Duplicate(AccountStatusReceipt),
    DependencyMissing {
        current_material: Option<AccountStatusRecord>,
        required_status_sequence: u64,
    },
    Stale {
        current_material: AccountStatusRecord,
    },
    Conflict {
        current_material: Option<AccountStatusRecord>,
        kind: AccountStatusReplicaConflictKind,
    },
}

#[async_trait]
pub trait AccountStatusReplicaStore: Send + Sync {
    async fn append(
        &self,
        record: &AccountStatusRecord,
        receipt: &AccountStatusReceipt,
    ) -> PersistenceResult<AccountStatusReplicaAppend>;

    async fn current(
        &self,
        account_authority_id: &str,
        account_id: &arkret_wire::AccountId,
    ) -> PersistenceResult<Option<AccountStatusRecord>>;

    async fn resolve(
        &self,
        account_authority_id: &str,
        account_id: &arkret_wire::AccountId,
        from_status_sequence: u64,
        limit: u16,
    ) -> PersistenceResult<Vec<AccountStatusRecord>>;

    async fn erasure_pending(&self, limit: u16) -> PersistenceResult<Vec<AccountStatusRecord>>;

    async fn receipt(
        &self,
        account_authority_id: &str,
        account_id: &arkret_wire::AccountId,
        status_sequence: u64,
    ) -> PersistenceResult<Option<AccountStatusReceipt>>;

    /// Merge newly observed holders into the durable affected-service index
    /// and return the complete distinct target set. The ceiling is enforced
    /// under the same per-account lock as the inserts, so an over-limit batch
    /// has zero index writes even under concurrent discovery.
    async fn merge_affected_services(
        &self,
        account_id: &arkret_wire::AccountId,
        observations: &[AccountStatusAffectedServiceObservation],
        max_services: usize,
    ) -> PersistenceResult<Vec<arkret_wire::DidCoreId>>;

    /// Rebuild observations from the closed set of locally persisted state
    /// families. Implementations must match the complete AccountId and may
    /// only derive peer services from typed service/Actor identities already
    /// carried by those rows.
    async fn discover_affected_services(
        &self,
        account_id: &arkret_wire::AccountId,
        holder_service_id: &arkret_wire::DidCoreId,
        observed_at: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<Vec<AccountStatusAffectedServiceObservation>>;

    async fn affected_services(
        &self,
        account_id: &arkret_wire::AccountId,
        limit: usize,
    ) -> PersistenceResult<Vec<arkret_wire::DidCoreId>>;

    /// Freeze the destination ack-window for one immutable record. Exact
    /// replay returns the same projection; a different target/deadline set for
    /// the same record is a conflict.
    async fn begin_propagation(
        &self,
        record: &AccountStatusRecord,
        destinations: &[arkret_wire::DidCoreId],
        deadline_at: chrono::DateTime<chrono::Utc>,
        now: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<AccountStatusPropagationProjection>;

    /// Apply one receiver `accepted | duplicate` ack and recompute the
    /// aggregate. A late final ack clears an already-incomplete projection.
    async fn acknowledge_propagation_destination(
        &self,
        account_status_record_id: &arkret_wire::AccountStatusRecordId,
        destination_id: &arkret_wire::DidCoreId,
        acknowledged_at: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<Option<AccountStatusPropagationProjectionTransition>>;

    /// Read the latest record projection for this exact account while
    /// atomically promoting an overdue scheduled row to incomplete.
    async fn current_propagation_projection(
        &self,
        account_id: &arkret_wire::AccountId,
        now: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<Option<AccountStatusPropagationProjectionTransition>>;
}

/// Classifies an already transport- and proof-verified submission against the
/// durable replica head, which the account-status replica decision table
/// declares to be the only comparison baseline. Rows are evaluated top to
/// bottom and the first match wins. `None` means the submission is admitted and
/// the caller must perform the advancing write; every other outcome classifies
/// the submission with zero replica, receipt and outbox writes.
pub fn classify_account_status_replica_append(
    record: &AccountStatusRecord,
    head: Option<&(AccountStatusRecord, AccountStatusReceipt)>,
) -> Option<AccountStatusReplicaAppend> {
    let Some((head_record, head_receipt)) = head else {
        // genesis_gap: an absent head requires the genesis record first.
        if record.status_sequence > 1 {
            return Some(AccountStatusReplicaAppend::DependencyMissing {
                current_material: None,
                required_status_sequence: 1,
            });
        }
        // genesis_admission.
        return None;
    };
    // binding_version_rollback is evaluated before every sequence row so a
    // rolled-back binding can never be written by the advance branch.
    if record.binding_version < head_record.binding_version {
        return Some(conflict(
            head_record,
            AccountStatusReplicaConflictKind::BindingRollback,
        ));
    }
    if record.status_sequence == head_record.status_sequence + 1 {
        // fork_predecessor_mismatch, otherwise advance.
        if record.previous_account_status_record_id.as_ref()
            != Some(&head_record.account_status_record_id)
        {
            return Some(conflict(
                head_record,
                AccountStatusReplicaConflictKind::Fork,
            ));
        }
        return admission_conflict(record, head_record).map(|kind| conflict(head_record, kind));
    }
    if record.status_sequence == head_record.status_sequence {
        // duplicate is the terminal ack only when the head already is the
        // submitted record; a different record at the head sequence forks.
        return Some(
            if record.account_status_record_id == head_record.account_status_record_id {
                AccountStatusReplicaAppend::Duplicate(head_receipt.clone())
            } else {
                conflict(head_record, AccountStatusReplicaConflictKind::Fork)
            },
        );
    }
    if record.status_sequence < head_record.status_sequence {
        // stale is unconditional. How much history this receiver still retains
        // for the submitted sequence is a local retention decision and must not
        // turn a below-head submission into a duplicate.
        return Some(AccountStatusReplicaAppend::Stale {
            current_material: head_record.clone(),
        });
    }
    // sequence_gap.
    Some(AccountStatusReplicaAppend::DependencyMissing {
        current_material: Some(head_record.clone()),
        required_status_sequence: head_record.status_sequence + 1,
    })
}

fn conflict(
    head: &AccountStatusRecord,
    kind: AccountStatusReplicaConflictKind,
) -> AccountStatusReplicaAppend {
    AccountStatusReplicaAppend::Conflict {
        current_material: Some(head.clone()),
        kind,
    }
}

/// Admission guards that refine the `advance` row: the submission is the exact
/// successor of the head, and these checks reject a successor whose binding or
/// status transition the receiver must not durably record.
fn admission_conflict(
    record: &AccountStatusRecord,
    head: &AccountStatusRecord,
) -> Option<AccountStatusReplicaConflictKind> {
    if record.binding_version == head.binding_version
        && (record.account_id != head.account_id
            || record.principal_control_realm_id != head.principal_control_realm_id)
    {
        return Some(AccountStatusReplicaConflictKind::Fork);
    }
    if head.status == AccountStatus::ErasurePending {
        return Some(AccountStatusReplicaConflictKind::ErasurePendingTerminal);
    }
    (!head.status.can_transition_to(record.status))
        .then_some(AccountStatusReplicaConflictKind::TransitionInvalid)
}
