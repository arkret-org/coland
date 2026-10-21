//! Grant-local detached approvals; no governance configuration grants authority.
use arkret_models_collaboration::governance::grant_constraint::{
    CapabilityGrant, GrantConstraint, GrantConstraintKind, GrantConstraintSubkind,
};
use arkret_wire::{
    ApprovalContext, CapabilityActionId, Event, GrantId, RealmCommit, WireResourceSelector,
};
use coland_storage::{EventApprovalCommit, OperationFacts, PersistenceError, PersistenceResult};
use diesel_async::AsyncPgConnection;

use crate::approval_admission::{QualifiedApproval, validate_candidate};

#[derive(Clone, Debug)]
pub(crate) struct SatisfiedGrantApproval {
    pub grant_id: GrantId,
    pub constraint_digest: String,
    pub accepted: Vec<QualifiedApproval>,
}

fn missing(action: CapabilityActionId, quorum: u64, count: usize) -> PersistenceError {
    PersistenceError::Conflict(format!(
        "approval_required: action={} effective_approval_quorum={} counted_approvals={}",
        action.as_str(),
        quorum,
        count
    ))
}

pub(crate) fn is_approval_constraint(constraint: &GrantConstraint) -> bool {
    constraint.constraint_kind == GrantConstraintKind::ClaimBased
        && matches!(
            constraint.constraint_subkind,
            Some(GrantConstraintSubkind::Approval | GrantConstraintSubkind::Accountability)
        )
}

fn approval_deadline(
    approved_at: chrono::DateTime<chrono::Utc>,
    committed_at: chrono::DateTime<chrono::Utc>,
    timeout: Option<chrono::TimeDelta>,
) -> bool {
    // The shared signature verifier owns the independent future-only guard.
    // Timeout has only an upper age boundary, with no additional lower bound.
    timeout.is_none_or(|age| {
        approved_at
            .checked_add_signed(age)
            .is_some_and(|deadline| committed_at <= deadline)
    })
}

fn approval_not_before(grant: &CapabilityGrant) -> chrono::DateTime<chrono::Utc> {
    grant
        .constraints
        .iter()
        .filter(|constraint| constraint.constraint_kind == GrantConstraintKind::Temporal)
        .filter_map(|constraint| constraint.not_before)
        .fold(grant.issued_at, std::cmp::max)
}

/// A grant-context vote retains its declared time limits when reused by the
/// independent governance layer. Another fresh vote cannot revive its nonce.
pub(crate) fn grant_vote_is_current(
    grant: &CapabilityGrant,
    action: CapabilityActionId,
    signature: &arkret_wire::ApprovalSignature,
    at: chrono::DateTime<chrono::Utc>,
) -> bool {
    if signature.input.approved_at < approval_not_before(grant) {
        return false;
    }
    grant
        .constraints
        .iter()
        .filter(|constraint| {
            is_approval_constraint(constraint)
                && (constraint.approval_required == Some(true)
                    || constraint.guardian_approval_required == Some(true)
                    || constraint.controller_approval_required == Some(true))
                && (constraint.applies_to_actions.is_empty()
                    || constraint
                        .applies_to_actions
                        .iter()
                        .any(|entry| entry.as_str() == action.as_str()))
        })
        .all(|constraint| match constraint.timeout.as_deref() {
            Some(value) => coland_storage::fixed_duration(value)
                .filter(|age| *age > chrono::TimeDelta::zero())
                .is_some_and(|age| approval_deadline(signature.input.approved_at, at, Some(age))),
            None => true,
        })
}

/// Return only exact constraints proved at this cut. The shared evaluator must
/// preserve every deny/quarantine and all other unproved review constraints.
#[expect(
    clippy::too_many_arguments,
    reason = "Grant approval admission binds target, issuer, grants and proofs at the locked cut."
)]
pub(crate) async fn require_grant_approvals(
    conn: &mut AsyncPgConnection,
    event: &Event,
    commit: &RealmCommit,
    prepared: Option<&EventApprovalCommit>,
    grant: &CapabilityGrant,
    action: CapabilityActionId,
    target: &WireResourceSelector,
    facts: &OperationFacts,
) -> PersistenceResult<Vec<SatisfiedGrantApproval>> {
    let methods = validate_candidate(event, commit, prepared)?;
    let source = GrantApprovalSource::Event {
        event,
        at: commit.committed_at,
        registered_pair: prepared.is_some_and(|prepared| {
            matches!(
                prepared.carrier_binding,
                Some(coland_storage::ApprovalCarrierBinding::AuditPair { .. })
            )
        }),
    };
    require_with_source(conn, &source, methods, grant, action, target, facts).await
}

enum GrantApprovalSource<'a> {
    Event {
        event: &'a Event,
        at: chrono::DateTime<chrono::Utc>,
        registered_pair: bool,
    },
}
impl GrantApprovalSource<'_> {
    fn at(&self) -> chrono::DateTime<chrono::Utc> {
        match self {
            Self::Event { at, .. } => *at,
        }
    }
    fn initiator(&self) -> &arkret_wire::ActorId {
        match self {
            Self::Event { event, .. } => &event.actor_id,
        }
    }
    async fn qualify(
        &self,
        conn: &mut AsyncPgConnection,
        principal: &arkret_wire::DidCoreId,
        action: CapabilityActionId,
        target: &WireResourceSelector,
        facts: &OperationFacts,
    ) -> PersistenceResult<Option<serde_json::Value>> {
        match self {
            Self::Event {
                event,
                at,
                registered_pair,
            } => {
                crate::approval_admission::qualify_principal(
                    conn,
                    event,
                    principal,
                    action,
                    target,
                    facts,
                    *at,
                    false,
                    *registered_pair,
                )
                .await
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn require_with_source(
    conn: &mut AsyncPgConnection,
    source: &GrantApprovalSource<'_>,
    methods: &[coland_storage::ApprovalHistoricalMethod],
    grant: &CapabilityGrant,
    action: CapabilityActionId,
    target: &WireResourceSelector,
    facts: &OperationFacts,
) -> PersistenceResult<Vec<SatisfiedGrantApproval>> {
    let mut requirements = Vec::new();
    for constraint in grant
        .constraints
        .iter()
        .filter(|constraint| is_approval_constraint(constraint))
    {
        if !constraint.applies_to_actions.is_empty()
            && !constraint
                .applies_to_actions
                .iter()
                .any(|named| named.as_str() == action.as_str())
        {
            continue;
        }
        let required = constraint.approval_required == Some(true)
            || constraint.guardian_approval_required == Some(true)
            || constraint.controller_approval_required == Some(true);
        if !required {
            continue;
        }
        // Unregistered profile predicates cannot be discharged by a signature.
        if !constraint.extensions.is_empty() || constraint.condition.is_some() {
            return Err(missing(action, 0, 0));
        }
        let timeout = match constraint.timeout.as_deref() {
            Some(value) => Some(
                coland_storage::fixed_duration(value)
                    .filter(|age| *age > chrono::TimeDelta::zero())
                    .ok_or_else(|| missing(action, 0, 0))?,
            ),
            None => None,
        };
        let roster = constraint
            .approval_actor_ids
            .iter()
            .cloned()
            .collect::<std::collections::BTreeSet<_>>();
        let mut qualified = std::collections::BTreeMap::new();
        for principal in roster {
            if &principal == source.initiator().signing_principal_id() {
                continue;
            }
            if let Some(basis) =
                crate::boxed_future(|| source.qualify(conn, &principal, action, target, facts))
                    .await?
            {
                qualified.insert(principal, basis);
            }
        }
        let threshold = constraint.approval_threshold.unwrap_or_default();
        let Some(quorum) = threshold.required_votes(qualified.len() as u64) else {
            return Err(missing(action, 0, 0));
        };
        let constraint_digest = arkret_canonical::canonical_sha256(constraint)
            .map_err(|e| PersistenceError::SchemaViolation(e.to_string()))?;
        let roster_basis=qualified.iter().map(|(principal,basis)|serde_json::json!({"principal":principal,"qualification":basis})).collect::<Vec<_>>();
        let mut accepted = Vec::new();
        let mut counted = std::collections::BTreeSet::new();
        for method in methods {
            let vote = &method.signature;
            if vote.input.action != action
                || !matches!(&vote.input.approval_context,ApprovalContext::Grant {grant_id} if grant_id==&grant.id)
            {
                continue;
            }
            if vote.input.approved_at < approval_not_before(grant)
                || !approval_deadline(vote.input.approved_at, source.at(), timeout)
            {
                continue;
            }
            let principal = arkret_wire::project_did_to_core_id(&vote.input.approver_did)
                .map_err(|e| PersistenceError::SchemaViolation(e.to_string()))?;
            if let Some(basis) = qualified.get(&principal)
                && counted.insert(principal.clone())
            {
                accepted.push(QualifiedApproval {
                        method: method.clone(),
                        qualification_basis: serde_json::json!({"voter":basis,"grant_requirement":{
                            "grant_id":grant.id,"constraint_digest":constraint_digest,"constraint":constraint,
                            "eligible_roster":roster_basis,"effective_approval_quorum":quorum}}),
                    });
            }
        }
        if (accepted.len() as u64) < quorum {
            return Err(missing(action, quorum, accepted.len()));
        }
        requirements.push(SatisfiedGrantApproval {
            grant_id: grant.id.clone(),
            constraint_digest,
            accepted,
        });
    }
    Ok(requirements)
}

#[cfg(test)]
mod tests {
    use super::approval_deadline;
    #[test]
    fn approval_timeout_uses_signed_time_and_includes_the_exact_deadline() {
        let signed = chrono::DateTime::parse_from_rfc3339("2026-09-30T00:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let age = chrono::TimeDelta::seconds(60);
        assert!(approval_deadline(signed, signed + age, Some(age)));
        assert!(!approval_deadline(
            signed,
            signed + age + chrono::TimeDelta::milliseconds(1),
            Some(age)
        ));
        assert!(approval_deadline(
            signed,
            signed - chrono::TimeDelta::milliseconds(1),
            Some(age)
        ));
        assert!(approval_deadline(
            signed,
            signed + chrono::TimeDelta::days(365),
            None
        ));
        assert!(!approval_deadline(
            chrono::DateTime::<chrono::Utc>::MAX_UTC,
            chrono::DateTime::<chrono::Utc>::MAX_UTC,
            Some(age)
        ));
    }
}
