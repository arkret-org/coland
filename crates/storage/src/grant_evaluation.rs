//! Constraint evaluation of Capability Grants (`authz/constraint-schema.md`
//! §15 and §16, `authz/capabilities.md` §6).
//!
//! [`evaluate_grants`] is the single decision over the effective grants of one
//! actor for one operation. It first selects every grant that names one of the
//! requested actions on a resource covering the target, then folds their
//! constraints across grants (§15.4): any matching `deny`, `quarantine` or
//! `require_review` constraint of any selected grant decides the operation in
//! that order, and otherwise the operation is allowed exactly when at least one
//! selected grant satisfies every one of its own `allow` constraints (§15.2).
//!
//! Each constraint is judged by the matcher of its family (§16). A matcher
//! whose input the operation does not carry, a family or subkind whose
//! profile this Station does not declare, and an unregistered or extension
//! field all fail closed: such an `allow` constraint is not satisfied and such
//! a `deny` / `quarantine` / `require_review` constraint matches. A hard
//! `quota` (subkind `rate`) is `external`: the evaluator cannot decide it from
//! the grant alone, so a grant it would otherwise allow carries the exact
//! reservation it owes, and only a caller that performs that reservation on the
//! quota authority inside its own atomic write may count the grant.
//!
//! The `required_constraints` of the exercised action's registry row are
//! enforced regardless of the grant author's declarations: a required
//! shorthand the grant does not declare leaves the grant unsatisfied, except
//! the self-service windows whose absence means unbounded (§14.2) and a Circle
//! or Strand scope shorthand whose narrowing the covering resource selector
//! already expresses (`authz/resource-selector-grammar.md` §2.2).

use arkret_models_collaboration::governance::grant_constraint::{
    CapabilityGrant, GrantConstraint, GrantConstraintConditionKind, GrantConstraintEffect,
    GrantConstraintKind, GrantConstraintRecurrence, GrantConstraintRecurrenceDay,
    GrantConstraintRecurrenceFrequency, GrantConstraintScope, GrantConstraintSubkind,
};
use arkret_wire::{
    ActorId, CapabilityActionId, EvaluationClass, Facet, GrantId, ResourceSelectorKind,
    WireResourceSelector,
};
use chrono::{DateTime, Datelike, NaiveDate, NaiveTime, TimeDelta, TimeZone, Utc};

/// The facts of one operation that constraint matchers read beyond its
/// action and target selector. Every fact is optional; a matcher that needs
/// an absent fact fails closed. Identifiers a typed target selector already
/// names are read from the selector when the fact is absent.
#[derive(Clone, Debug, Default)]
pub struct OperationFacts {
    /// Applet identity and signer epoch independently resolved at the write cut.
    pub applet_id: Option<String>,
    pub executed_by: Option<ActorId>,
    pub registration_epoch: Option<String>,
    pub strand_id: Option<String>,
    pub space_id: Option<String>,
    /// Frozen source and destination List Spaces for a placement operation.
    pub from_container_id: Option<String>,
    pub to_container_id: Option<String>,
    pub circle_id: Option<String>,
    pub view_id: Option<String>,
    /// The Strand track the operation targets (`discussion` for Messages).
    pub track: Option<String>,
    /// The object type the operation acts on (`strand`, `message`, ...).
    pub object_kind: Option<String>,
    pub space_kind: Option<String>,
    pub morph_kind: Option<String>,
    pub facets: Option<Vec<Facet>>,
    pub view_kind: Option<String>,
    pub view_renderer: Option<String>,
    /// Field paths a write touches.
    pub write_fields: Option<Vec<String>>,
    /// Field paths a read returns. Present only for a read operation.
    pub read_fields: Option<Vec<String>>,
    /// The verified `created_at` of the target object (§16.1 windows).
    pub target_created_at: Option<DateTime<Utc>>,
    /// The verified author of the target object.
    pub target_owner: Option<ActorId>,
}

/// One operation an actor asks to perform.
#[derive(Clone, Copy, Debug)]
pub struct AuthorizationOperation<'a> {
    pub actor: &'a ActorId,
    /// Actions any one of which authorizes the operation.
    pub actions: &'a [&'a str],
    pub target: &'a WireResourceSelector,
    /// The verification time, fixed once for the whole evaluation.
    pub at: DateTime<Utc>,
    pub facts: &'a OperationFacts,
}

/// One reservation a hard rate quota (`constraint-schema.md` §8.1) requires
/// on its logical quota authority before the operation may take effect.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuotaReservation {
    pub grant_id: GrantId,
    /// `constraint_id`, or the canonical hash of the constraint.
    pub constraint_key: String,
    /// The canonical counter key selected by `constraint_scope`.
    pub counter_key: String,
    /// `floor(verification_time_ms / period_ms)`.
    pub window_id: i64,
    pub max_operations: u64,
    pub period_ms: i64,
    pub burst: Option<u64>,
    pub verification_ms: i64,
}

/// A grant that allows the operation, with the quota reservations it still
/// owes.
#[derive(Clone, Debug)]
pub struct SatisfiedGrant<'g> {
    pub grant: &'g CapabilityGrant,
    pub reservations: Vec<QuotaReservation>,
}

/// The cross-grant verdict of `constraint-schema.md` §15.4.
#[derive(Clone, Debug)]
pub enum GrantEvaluation<'g> {
    /// Satisfied grants: those owing no reservation first, then by grant id.
    Allowed(Vec<SatisfiedGrant<'g>>),
    Denied,
    Quarantined,
    RequiresReview,
    /// A grant names the request but none satisfies its `allow` constraints.
    Unsatisfied,
    /// No effective grant names one of the actions on a covering resource.
    Unnamed,
}

impl<'g> GrantEvaluation<'g> {
    /// The satisfied grants that owe no quota reservation: the only grants a
    /// caller without a quota authority may count.
    pub fn unreserved(&self) -> Vec<&'g CapabilityGrant> {
        match self {
            Self::Allowed(grants) => grants
                .iter()
                .filter(|satisfied| satisfied.reservations.is_empty())
                .map(|satisfied| satisfied.grant)
                .collect(),
            _ => Vec::new(),
        }
    }

    /// Whether a `deny`, `quarantine` or `require_review` constraint decided
    /// the operation.
    pub fn is_refusal(&self) -> bool {
        matches!(
            self,
            Self::Denied | Self::Quarantined | Self::RequiresReview
        )
    }
}

/// Whether `grant` names one of `actions` on a resource selector covering
/// `target`, ignoring its constraints.
pub fn grant_names_target(
    grant: &CapabilityGrant,
    actions: &[&str],
    target: &WireResourceSelector,
) -> bool {
    grant
        .actions
        .iter()
        .any(|action| actions.contains(&action.as_str()))
        && grant
            .resources
            .iter()
            .any(|resource| crate::resource_selector_covers(resource, target))
}

/// `constraint-schema.md` §15.4 over `grants` for `operation`.
pub fn evaluate_grants<'g>(
    operation: &AuthorizationOperation<'_>,
    grants: impl IntoIterator<Item = &'g CapabilityGrant>,
) -> GrantEvaluation<'g> {
    evaluate_grants_with_verified_approvals(operation, grants, &[])
}

/// Evaluate a mandatory ceiling without inventing a Capability Grant.
/// Every actual action must satisfy every allow constraint. Refusals retain
/// global deny/quarantine/review priority. Unknown or external authority cannot
/// be discharged by this stateless evaluator, including hard quota and claims.
/// Only `Allowed` means success; its empty candidate list grants no authority
/// and must never be passed to quota reservation or interpreted via `is_refusal`.
pub fn evaluate_constraint_ceiling(
    operation: &AuthorizationOperation<'_>,
    constraints: &[GrantConstraint],
) -> GrantEvaluation<'static> {
    if operation.actions.is_empty()
        || operation.target.kind == ResourceSelectorKind::All
        || operation.target.validate().is_err()
        || operation.actions.iter().any(|action| {
            arkret_schema::capability_action(action).is_none()
                && arkret_wire::ServiceOperationId::from_wire(action).is_none()
        })
    {
        return GrantEvaluation::Unsatisfied;
    }
    for effect in [
        GrantConstraintEffect::Deny,
        GrantConstraintEffect::Quarantine,
        GrantConstraintEffect::RequireReview,
    ] {
        if constraints
            .iter()
            .filter(|constraint| constraint.effect == effect)
            .any(|constraint| {
                operation
                    .actions
                    .iter()
                    .any(|action| constraint_matches(operation, action, constraint))
            })
        {
            return match effect {
                GrantConstraintEffect::Deny => GrantEvaluation::Denied,
                GrantConstraintEffect::Quarantine => GrantEvaluation::Quarantined,
                _ => GrantEvaluation::RequiresReview,
            };
        }
    }
    for constraint in constraints
        .iter()
        .filter(|constraint| constraint.effect == GrantConstraintEffect::Allow)
    {
        if !constraint_is_evaluable(constraint)
            || operation
                .actions
                .iter()
                .any(|action| admits(operation, action, constraint) != Tri::Yes)
        {
            return GrantEvaluation::Unsatisfied;
        }
    }
    GrantEvaluation::Allowed(Vec::new())
}

/// Add an explicit resource ceiling to the same mandatory-constraint decision.
/// Resources are alternatives within this ceiling, but every additional scope
/// layer must be checked independently against the unchanged actual target.
/// Empty resources are not a wildcard. A caller that has proved a scope has no
/// additional content selectors uses `evaluate_constraint_ceiling` directly.
pub fn evaluate_resource_constraint_ceiling(
    operation: &AuthorizationOperation<'_>,
    resources: &[WireResourceSelector],
    constraints: &[GrantConstraint],
) -> GrantEvaluation<'static> {
    if !resources
        .iter()
        .any(|ceiling| crate::resource_selector_covers(ceiling, operation.target))
    {
        return GrantEvaluation::Unsatisfied;
    }
    evaluate_constraint_ceiling(operation, constraints)
}

/// Intersect an Agent's complete paths with its controller's current paths.
/// Parent quota keys retain the controller actor and original grant identity.
/// The returned candidates are parent-first in canonical GrantId order; callers
/// must reserve each candidate's entire reservation set atomically.
pub fn evaluate_controller_bounded_grants<'g>(
    operation: &AuthorizationOperation<'_>,
    agent_grants: &[&'g CapabilityGrant],
    controller: &ActorId,
    controller_grants: &[&CapabilityGrant],
    approvals: &[VerifiedGrantApproval],
    controller_owner: bool,
) -> GrantEvaluation<'g> {
    let actions = operation
        .actions
        .iter()
        .copied()
        .filter(|action| {
            !arkret_schema::capability_action(action).is_some_and(|descriptor| {
                descriptor
                    .required_evaluator_checks
                    .contains(&"actor_eq_target_author")
            }) || operation.facts.target_owner.as_ref() == Some(operation.actor)
        })
        .collect::<Vec<_>>();
    if actions.is_empty() {
        return GrantEvaluation::Denied;
    }
    let operation = &AuthorizationOperation {
        actions: &actions,
        ..*operation
    };
    let agent_verdict =
        evaluate_grants_with_verified_approvals(operation, agent_grants.iter().copied(), approvals);
    let mut controller_facts = operation.facts.clone();
    controller_facts.applet_id = None;
    controller_facts.executed_by = None;
    controller_facts.registration_epoch = None;
    let controller_operation = AuthorizationOperation {
        actor: controller,
        facts: &controller_facts,
        ..*operation
    };
    let controller_verdict =
        evaluate_grants(&controller_operation, controller_grants.iter().copied());
    // Refusals apply across all matching grants before selecting either path.
    for effect in [0, 1, 2] {
        for verdict in [&agent_verdict, &controller_verdict] {
            match (effect, verdict) {
                (0, GrantEvaluation::Denied) => return GrantEvaluation::Denied,
                (1, GrantEvaluation::Quarantined) => return GrantEvaluation::Quarantined,
                (2, GrantEvaluation::RequiresReview) => return GrantEvaluation::RequiresReview,
                _ => {}
            }
        }
    }
    let controller_sources = operation
        .actions
        .iter()
        .map(|action| controller_grants_for_owned_action(operation, action, controller_grants))
        .collect::<Vec<_>>();
    for effect in [0, 1, 2] {
        for (action, sources) in operation.actions.iter().zip(&controller_sources) {
            let actions = [*action];
            let current = AuthorizationOperation {
                actions: &actions,
                ..controller_operation
            };
            match (effect, evaluate_grants(&current, sources.iter())) {
                (0, GrantEvaluation::Denied) => return GrantEvaluation::Denied,
                (1, GrantEvaluation::Quarantined) => return GrantEvaluation::Quarantined,
                (2, GrantEvaluation::RequiresReview) => return GrantEvaluation::RequiresReview,
                _ => {}
            }
        }
    }
    if !matches!(agent_verdict, GrantEvaluation::Allowed(_)) {
        return agent_verdict;
    }
    let mut candidates = Vec::new();
    for (action, sources) in operation.actions.iter().zip(&controller_sources) {
        let actions = [*action];
        let agent_operation = AuthorizationOperation {
            actions: &actions,
            ..*operation
        };
        let GrantEvaluation::Allowed(agent_paths) = evaluate_grants_with_verified_approvals(
            &agent_operation,
            agent_grants.iter().copied(),
            approvals,
        ) else {
            continue;
        };
        let controller_operation = AuthorizationOperation {
            actor: controller,
            facts: &controller_facts,
            ..agent_operation
        };
        let parent_paths = match evaluate_grants(&controller_operation, sources.iter()) {
            GrantEvaluation::Allowed(paths) => paths,
            _ => Vec::new(),
        };
        for agent in agent_paths {
            if controller_owner {
                candidates.push((None, agent.clone()));
            }
            for parent in &parent_paths {
                let mut bounded = agent.clone();
                bounded
                    .reservations
                    .extend(parent.reservations.iter().cloned());
                candidates.push((Some(parent.grant.id.clone()), bounded));
            }
        }
    }
    if candidates.is_empty() {
        return GrantEvaluation::Unsatisfied;
    }
    candidates.sort_by(|(left_parent, left), (right_parent, right)| {
        left_parent
            .cmp(right_parent)
            .then_with(|| left.grant.id.cmp(&right.grant.id))
    });
    GrantEvaluation::Allowed(candidates.into_iter().map(|(_, path)| path).collect())
}

fn controller_grants_for_owned_action(
    operation: &AuthorizationOperation<'_>,
    action: &str,
    grants: &[&CapabilityGrant],
) -> Vec<CapabilityGrant> {
    let own = arkret_schema::capability_action(action).is_some_and(|descriptor| {
        descriptor.required_evaluator_checks == ["actor_eq_target_author"].as_slice()
    }) && operation.facts.target_owner.as_ref() == Some(operation.actor);
    grants
        .iter()
        .map(|grant| {
            let mut grant = (**grant).clone();
            if own {
                for constraint in &mut grant.constraints {
                    if let Some(condition) = &mut constraint.condition {
                        if condition.kind == GrantConstraintConditionKind::ObjectIsOwnedByActor
                            && condition.extra.is_empty()
                        {
                            // Only the registered own-author predicate is mapped.
                            // Actual author, Device, claim and approver facts stay unchanged.
                            condition.kind = GrantConstraintConditionKind::Always;
                        }
                    }
                }
            }
            grant
        })
        .collect()
}

/// Internal admission evidence for one immutable constraint of one grant. This
/// is never deserialized from a request; the accepting transaction earns it by
/// verifying exact detached evidence and the eligible roster at its cut.
#[derive(Clone, Debug)]
pub struct VerifiedGrantApproval {
    pub grant_id: arkret_wire::GrantId,
    pub constraint_digest: String,
    pub action: arkret_wire::CapabilityActionId,
}

pub fn evaluate_grants_with_verified_approvals<'g>(
    operation: &AuthorizationOperation<'_>,
    grants: impl IntoIterator<Item = &'g CapabilityGrant>,
    approvals: &[VerifiedGrantApproval],
) -> GrantEvaluation<'g> {
    let mut named = Vec::new();
    for grant in grants {
        for action in operation.actions {
            if grant.actions.iter().any(|named| named.as_str() == *action)
                && grant
                    .resources
                    .iter()
                    .any(|resource| crate::resource_selector_covers(resource, operation.target))
            {
                named.push((grant, *action));
            }
        }
    }
    if named.is_empty() {
        return GrantEvaluation::Unnamed;
    }
    for effect in [
        GrantConstraintEffect::Deny,
        GrantConstraintEffect::Quarantine,
        GrantConstraintEffect::RequireReview,
    ] {
        let hit = named.iter().any(|(grant, action)| {
            grant
                .constraints
                .iter()
                .filter(|constraint| constraint.effect == effect)
                .any(|constraint| {
                    !(effect == GrantConstraintEffect::RequireReview
                        && approval_discharged(grant, constraint, action, approvals))
                        && constraint_matches(operation, action, constraint)
                })
        });
        if hit {
            return match effect {
                GrantConstraintEffect::Deny => GrantEvaluation::Denied,
                GrantConstraintEffect::Quarantine => GrantEvaluation::Quarantined,
                _ => GrantEvaluation::RequiresReview,
            };
        }
    }
    let mut satisfied: Vec<SatisfiedGrant<'g>> = Vec::new();
    for (grant, action) in named {
        let Some(reservations) = grant_allows(operation, action, grant, approvals) else {
            continue;
        };
        if let Some(existing) = satisfied
            .iter_mut()
            .find(|existing| existing.grant.id == grant.id)
        {
            if reservations.len() < existing.reservations.len() {
                existing.reservations = reservations;
            }
            continue;
        }
        satisfied.push(SatisfiedGrant {
            grant,
            reservations,
        });
    }
    if satisfied.is_empty() {
        return GrantEvaluation::Unsatisfied;
    }
    satisfied.sort_by(|left, right| {
        left.reservations
            .is_empty()
            .cmp(&right.reservations.is_empty())
            .reverse()
            .then_with(|| left.grant.id.cmp(&right.grant.id))
    });
    GrantEvaluation::Allowed(satisfied)
}

fn approval_discharged(
    grant: &CapabilityGrant,
    constraint: &GrantConstraint,
    action: &str,
    approvals: &[VerifiedGrantApproval],
) -> bool {
    if constraint.constraint_kind != GrantConstraintKind::ClaimBased
        || !matches!(
            constraint.constraint_subkind,
            Some(GrantConstraintSubkind::Approval | GrantConstraintSubkind::Accountability)
        )
        || !constraint.extensions.is_empty()
        || constraint.condition.is_some()
        || !approval_only_constraint(constraint)
        || constraint
            .evaluation_class
            .is_some_and(|class| Some(class) != canonical_evaluation_class(constraint))
    {
        return false;
    }
    if !constraint.applies_to_actions.is_empty()
        && !constraint
            .applies_to_actions
            .iter()
            .any(|named| named.as_str() == action)
    {
        return true;
    }
    let required = constraint.approval_required == Some(true)
        || constraint.guardian_approval_required == Some(true)
        || constraint.controller_approval_required == Some(true);
    if !required && constraint.accountability_required != Some(true) {
        return true;
    }
    let Ok(digest) = arkret_canonical::canonical_sha256(constraint) else {
        return false;
    };
    approvals.iter().any(|proof| {
        proof.grant_id == grant.id
            && proof.action.as_str() == action
            && proof.constraint_digest == digest
    })
}

/// A verified vote discharges only the registered approval obligation. Mixed
/// constraints retain their original fail-closed evaluation; a signature does
/// not establish temporal, resource, claim, or accountability predicates.
fn approval_only_constraint(constraint: &GrantConstraint) -> bool {
    if constraint.accountability_required == Some(true) {
        return false;
    }
    let Ok(serde_json::Value::Object(fields)) = serde_json::to_value(constraint) else {
        return false;
    };
    fields.keys().all(|field| {
        matches!(
            field.as_str(),
            "constraint_id"
                | "constraint_kind"
                | "constraint_subkind"
                | "effect"
                | "evaluation_class"
                | "applies_to_actions"
                | "approval_required"
                | "guardian_approval_required"
                | "controller_approval_required"
                | "approval_mode"
                | "approval_actor_ids"
                | "approval_relation"
                | "approval_threshold"
                | "timeout"
                | "accountability_required"
        )
    })
}

/// The reservations `grant` owes when it alone allows `operation` under
/// `action`, or `None` when it does not.
fn grant_allows(
    operation: &AuthorizationOperation<'_>,
    action: &str,
    grant: &CapabilityGrant,
    approvals: &[VerifiedGrantApproval],
) -> Option<Vec<QuotaReservation>> {
    if !required_constraints_declared(operation, action, grant) {
        return None;
    }
    let mut reservations = Vec::new();
    for constraint in grant
        .constraints
        .iter()
        .filter(|constraint| constraint.effect == GrantConstraintEffect::Allow)
    {
        if approval_discharged(grant, constraint, action, approvals) {
            continue;
        }
        match judge_allow(operation, action, grant, constraint) {
            Allow::Holds => {}
            Allow::Fails => return None,
            Allow::Owes(reservation) => reservations.push(reservation),
        }
    }
    Some(reservations)
}

enum Allow {
    Holds,
    Fails,
    Owes(QuotaReservation),
}

/// A matcher result: the operation is inside what the constraint describes,
/// outside it, or the operation does not carry what the matcher needs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Tri {
    Yes,
    No,
    Unknown,
}

impl Tri {
    fn and(self, other: Self) -> Self {
        match (self, other) {
            (Self::No, _) | (_, Self::No) => Self::No,
            (Self::Unknown, _) | (_, Self::Unknown) => Self::Unknown,
            _ => Self::Yes,
        }
    }

    fn or(self, other: Self) -> Self {
        match (self, other) {
            (Self::Yes, _) | (_, Self::Yes) => Self::Yes,
            (Self::Unknown, _) | (_, Self::Unknown) => Self::Unknown,
            _ => Self::No,
        }
    }

    fn from_bool(value: bool) -> Self {
        if value { Self::Yes } else { Self::No }
    }
}

fn judge_allow(
    operation: &AuthorizationOperation<'_>,
    action: &str,
    grant: &CapabilityGrant,
    constraint: &GrantConstraint,
) -> Allow {
    if !constraint_is_evaluable(constraint) {
        return Allow::Fails;
    }
    if constraint.constraint_kind == GrantConstraintKind::Quota
        && constraint.constraint_subkind == Some(GrantConstraintSubkind::Rate)
    {
        return match quota_reservation(operation, grant, constraint) {
            Some(reservation) => Allow::Owes(reservation),
            None => Allow::Fails,
        };
    }
    match admits(operation, action, constraint) {
        Tri::Yes => Allow::Holds,
        Tri::No | Tri::Unknown => Allow::Fails,
    }
}

/// `matches(operation, c)` of `constraint-schema.md` §15.3 for a `deny`,
/// `quarantine` or `require_review` constraint. What cannot be decided
/// matches.
fn constraint_matches(
    operation: &AuthorizationOperation<'_>,
    action: &str,
    constraint: &GrantConstraint,
) -> bool {
    if !constraint_is_evaluable(constraint) {
        return true;
    }
    let result = match constraint.constraint_kind {
        GrantConstraintKind::Temporal => temporal_matches(operation, action, constraint),
        GrantConstraintKind::FieldAccess => field_access_matches(operation, constraint),
        GrantConstraintKind::KindRestriction | GrantConstraintKind::ScopeLimitation => {
            if constraint.effect == GrantConstraintEffect::Deny {
                denied_lists_touched(operation, constraint)
            } else {
                admits(operation, action, constraint)
            }
        }
        // Re-grant control, rate quotas, claims, approvals and
        // confidentiality register no refusal-effect meaning this Station
        // can decide: a refusal constraint of those families always applies.
        GrantConstraintKind::AuthorityControl
        | GrantConstraintKind::Quota
        | GrantConstraintKind::ClaimBased
        | GrantConstraintKind::Confidentiality => Tri::Unknown,
    };
    result != Tri::No
}

/// Whether the operation is inside what an `allow`-shaped constraint admits.
fn admits(
    operation: &AuthorizationOperation<'_>,
    action: &str,
    constraint: &GrantConstraint,
) -> Tri {
    match constraint.constraint_kind {
        GrantConstraintKind::Temporal => temporal_matches(operation, action, constraint),
        GrantConstraintKind::FieldAccess => field_access_matches(operation, constraint),
        GrantConstraintKind::KindRestriction => kind_restriction_admits(operation, constraint),
        GrantConstraintKind::ScopeLimitation => scope_limitation_admits(operation, constraint),
        // Ordinary re-grant control governs issuing child grants
        // (`constraint-schema.md` §7.4); exercising the grant's own actions
        // is not restricted by it.
        GrantConstraintKind::AuthorityControl
            if constraint.constraint_subkind == Some(GrantConstraintSubkind::AppletAuthority) =>
        {
            match (
                &operation.facts.applet_id,
                &operation.facts.executed_by,
                &operation.facts.registration_epoch,
            ) {
                (Some(applet), Some(executor), Some(epoch)) => Tri::from_bool(
                    constraint
                        .applet_id
                        .as_ref()
                        .is_some_and(|id| id.as_str() == applet)
                        && constraint.executed_by.as_ref() == Some(executor)
                        && constraint
                            .registration_epoch
                            .as_ref()
                            .is_some_and(|id| id.as_str() == epoch),
                ),
                _ => Tri::Unknown,
            }
        }
        GrantConstraintKind::AuthorityControl => Tri::Yes,
        GrantConstraintKind::Quota
        | GrantConstraintKind::ClaimBased
        | GrantConstraintKind::Confidentiality => Tri::Unknown,
    }
}

/// Families and fields this Station evaluates. Extension families whose
/// profile it does not declare (`constraint-schema.md` §2.2, §19), a declared
/// `evaluation_class` other than the canonical one (§2.3) and `x_` extension
/// members fail closed.
fn constraint_is_evaluable(constraint: &GrantConstraint) -> bool {
    if !constraint.extensions.is_empty() {
        return false;
    }
    let canonical = canonical_evaluation_class(constraint);
    if let Some(declared) = constraint.evaluation_class
        && Some(declared) != canonical
    {
        return false;
    }
    match (constraint.constraint_kind, constraint.constraint_subkind) {
        (GrantConstraintKind::Temporal, None | Some(GrantConstraintSubkind::Window))
        | (
            GrantConstraintKind::Temporal,
            Some(GrantConstraintSubkind::EditWindow | GrantConstraintSubkind::RedactWindow),
        )
        | (GrantConstraintKind::Temporal, Some(GrantConstraintSubkind::Session)) => true,
        (GrantConstraintKind::FieldAccess, None)
        | (GrantConstraintKind::KindRestriction, None)
        | (GrantConstraintKind::AuthorityControl, None)
        | (GrantConstraintKind::AuthorityControl, Some(GrantConstraintSubkind::AppletAuthority))
        | (GrantConstraintKind::Quota, Some(GrantConstraintSubkind::Rate)) => true,
        (GrantConstraintKind::ScopeLimitation, None) => {
            // Placement resolves the source from durable current and the
            // destination from the signed payload at the accepting cut.
            // The position authority separately counts only a satisfied,
            // quota-free matching grant carrying override=true as WIP proof.
            constraint.allowed_relation_kinds.is_empty()
        }
        _ => false,
    }
}

/// The canonical `evaluation_class` of `constraint-schema.md` §2.3.
fn canonical_evaluation_class(constraint: &GrantConstraint) -> Option<EvaluationClass> {
    use GrantConstraintKind as Kind;
    use GrantConstraintSubkind as Subkind;
    Some(
        match (constraint.constraint_kind, constraint.constraint_subkind) {
            (Kind::Temporal, _) => EvaluationClass::Stateless,
            (Kind::FieldAccess, _) if constraint.condition.is_some() => EvaluationClass::RealmState,
            (Kind::FieldAccess, _) | (Kind::KindRestriction, _) => EvaluationClass::Stateless,
            (Kind::ScopeLimitation, _)
                if !constraint.allowed_from_container_refs.is_empty()
                    || !constraint.allowed_to_container_refs.is_empty()
                    || constraint.wip_limit_override.is_some() =>
            {
                EvaluationClass::RealmState
            }
            (Kind::ScopeLimitation, _) => EvaluationClass::Stateless,
            (Kind::AuthorityControl, _) => EvaluationClass::GrantLocal,
            (Kind::Quota, Some(Subkind::Rate)) => EvaluationClass::External,
            (Kind::Quota, Some(Subkind::Resource))
                if constraint.max_resources.is_some()
                    || constraint.max_total_blob_bytes.is_some() =>
            {
                EvaluationClass::External
            }
            (Kind::Quota, Some(Subkind::Resource)) => EvaluationClass::Stateless,
            (Kind::ClaimBased, Some(Subkind::Accountability)) => EvaluationClass::GrantLocal,
            (Kind::ClaimBased, Some(Subkind::Claim | Subkind::Approval)) => {
                EvaluationClass::External
            }
            (Kind::Confidentiality, Some(Subkind::Visibility)) => EvaluationClass::RealmState,
            // §12.2: the static and the scope-state parts of an encryption
            // constraint classify differently; either declaration is canonical.
            (Kind::Confidentiality, Some(Subkind::Encryption)) => {
                return constraint
                    .evaluation_class
                    .or(Some(EvaluationClass::Stateless));
            }
            _ => return None,
        },
    )
}

// ── temporal (§16.1) ────────────────────────────────────────────────────

fn temporal_skew() -> TimeDelta {
    let descriptor = arkret_identifiers::protocol_time_tolerance_scenario_descriptor(
        arkret_identifiers::ProtocolTimeToleranceScenario::TemporalConstraint,
    );
    TimeDelta::milliseconds(descriptor.tolerance_ms())
}

fn temporal_matches(
    operation: &AuthorizationOperation<'_>,
    action: &str,
    constraint: &GrantConstraint,
) -> Tri {
    let now = operation.at;
    let skew = temporal_skew();
    if !constraint.applies_to_actions.is_empty()
        && !constraint
            .applies_to_actions
            .iter()
            .any(|governed| governed == action)
    {
        return Tri::from_bool(constraint.effect == GrantConstraintEffect::Allow);
    }
    let window_subkind = matches!(
        constraint.constraint_subkind,
        Some(GrantConstraintSubkind::EditWindow | GrantConstraintSubkind::RedactWindow)
    );
    if window_subkind && constraint.applies_to_actions.is_empty() {
        return Tri::No;
    }
    // Session budgets need the presenting session, which no operation
    // carries; an approval-workflow expiry belongs to the claim family.
    if constraint.max_duration.is_some()
        || constraint.max_session_duration.is_some()
        || constraint.inactivity_timeout.is_some()
        || constraint.expires_after.is_some()
    {
        return Tri::Unknown;
    }
    let mut result = Tri::Yes;
    if constraint
        .not_before
        .is_some_and(|not_before| now + skew < not_before)
    {
        return Tri::No;
    }
    if constraint
        .expires_at
        .is_some_and(|expires_at| now - skew > expires_at)
    {
        return Tri::No;
    }
    if let Some(recurrence) = constraint.recurrence.as_ref() {
        result = result.and(recurrence_matches(now, skew, recurrence));
    }
    let edit = constraint.message_edit_window.as_deref();
    let redact = constraint.message_redact_window.as_deref();
    let window = match action {
        CapabilityActionId::MESSAGE_REVISE_OWN => edit,
        CapabilityActionId::MESSAGE_REDACT_OWN => match (redact, edit) {
            (Some(window), _) => Some(window),
            (None, Some(window)) if constraint.redact_after_window_allowed != Some(true) => {
                Some(window)
            }
            _ => None,
        },
        _ => None,
    };
    if let Some(window) = window {
        let within = match operation.facts.target_created_at {
            Some(created_at) => {
                Tri::from_bool(object_window_contains(created_at, window, now, skew))
            }
            None => Tri::Unknown,
        };
        result = result.and(within);
    }
    result
}

/// §16.1 `matches_object_window`: `now - skew` is not past
/// `created_at + window`. A window without a fixed length contains nothing.
pub fn object_window_contains(
    created_at: DateTime<Utc>,
    window: &str,
    now: DateTime<Utc>,
    skew: TimeDelta,
) -> bool {
    fixed_duration(window)
        .and_then(|window| created_at.checked_add_signed(window))
        .is_some_and(|deadline| now - skew <= deadline)
}

/// A duration `P[nW][nD][T[nH][nM][nS]]` of fixed length. Year and month
/// designators have no fixed length.
pub fn fixed_duration(value: &str) -> Option<TimeDelta> {
    let rest = value.strip_prefix('P').filter(|rest| !rest.is_empty())?;
    let (date, time) = match rest.split_once('T') {
        Some((_, "")) => return None,
        Some((date, time)) => (date, time),
        None => (rest, ""),
    };
    let seconds = designator_seconds(date, &[('W', 7 * 86_400), ('D', 86_400)])?.checked_add(
        designator_seconds(time, &[('H', 3_600), ('M', 60), ('S', 1)])?,
    )?;
    TimeDelta::try_seconds(seconds)
}

/// Seconds of one designator run such as `2W3D` or `1H30M`; each designator
/// appears at most once and in the order of `units`.
fn designator_seconds(part: &str, units: &[(char, i64)]) -> Option<i64> {
    let mut total = 0_i64;
    let mut digits = String::new();
    let mut remaining = units;
    for character in part.chars() {
        if character.is_ascii_digit() {
            digits.push(character);
            continue;
        }
        let offset = remaining.iter().position(|(unit, _)| *unit == character)?;
        let amount = digits.parse::<i64>().ok()?;
        total = total.checked_add(amount.checked_mul(remaining[offset].1)?)?;
        digits.clear();
        remaining = &remaining[offset + 1..];
    }
    digits.is_empty().then_some(total)
}

fn parse_local_time(value: &str) -> Option<NaiveTime> {
    let bytes = value.as_bytes();
    let format = match bytes.len() {
        5 => "%H:%M",
        8 => "%H:%M:%S",
        _ => return None,
    };
    NaiveTime::parse_from_str(value, format).ok()
}

fn weekday_token(day: chrono::Weekday) -> GrantConstraintRecurrenceDay {
    match day {
        chrono::Weekday::Mon => GrantConstraintRecurrenceDay::Mon,
        chrono::Weekday::Tue => GrantConstraintRecurrenceDay::Tue,
        chrono::Weekday::Wed => GrantConstraintRecurrenceDay::Wed,
        chrono::Weekday::Thu => GrantConstraintRecurrenceDay::Thu,
        chrono::Weekday::Fri => GrantConstraintRecurrenceDay::Fri,
        chrono::Weekday::Sat => GrantConstraintRecurrenceDay::Sat,
        chrono::Weekday::Sun => GrantConstraintRecurrenceDay::Sun,
    }
}

/// `matches_recurrence` of §16.1: the tolerance interval
/// `[now - skew, now + skew]` overlaps one window instance. An instance
/// starts on a listed local day; a window crossing midnight ends on the next
/// local day. An unregistered frequency, an unknown timezone, a lone window
/// boundary, or a boundary that falls in a DST gap or overlap fails closed.
fn recurrence_matches(
    now: DateTime<Utc>,
    skew: TimeDelta,
    recurrence: &GrantConstraintRecurrence,
) -> Tri {
    if !recurrence.extra.is_empty() {
        return Tri::No;
    }
    let frequency = recurrence
        .frequency
        .unwrap_or(GrantConstraintRecurrenceFrequency::Daily);
    match frequency {
        GrantConstraintRecurrenceFrequency::Daily => {}
        GrantConstraintRecurrenceFrequency::Weekly if !recurrence.days.is_empty() => {}
        _ => return Tri::No,
    }
    let timezone: chrono_tz::Tz = match recurrence.timezone.as_deref() {
        None => chrono_tz::Tz::UTC,
        Some(name) => match name.parse() {
            Ok(timezone) => timezone,
            Err(_) => return Tri::No,
        },
    };
    // `None` is the whole local day.
    let window = match (
        recurrence.window_start.as_deref(),
        recurrence.window_end.as_deref(),
    ) {
        (None, None) => None,
        (Some(start), Some(end)) => match (parse_local_time(start), parse_local_time(end)) {
            (Some(start), Some(end)) => Some((start, end)),
            _ => return Tri::No,
        },
        _ => return Tri::No,
    };
    let earliest = now - skew;
    let latest = now + skew;
    let first_day = earliest.with_timezone(&timezone).date_naive() - TimeDelta::days(1);
    let last_day = latest.with_timezone(&timezone).date_naive();
    let mut day = first_day;
    while day <= last_day {
        let Some(next_day) = day.succ_opt() else {
            return Tri::No;
        };
        let listed =
            recurrence.days.is_empty() || recurrence.days.contains(&weekday_token(day.weekday()));
        if listed {
            let (start, end, end_day) = match window {
                None => (NaiveTime::MIN, NaiveTime::MIN, next_day),
                Some((start, end)) if start <= end => (start, end, day),
                Some((start, end)) => (start, end, next_day),
            };
            let (Some(instance_start), Some(instance_end)) = (
                local_instant(&timezone, day, start),
                local_instant(&timezone, end_day, end),
            ) else {
                return Tri::No;
            };
            if instance_start <= latest && earliest < instance_end {
                return Tri::Yes;
            }
        }
        day = next_day;
    }
    Tri::No
}

fn local_instant(
    timezone: &chrono_tz::Tz,
    day: NaiveDate,
    time: NaiveTime,
) -> Option<DateTime<Utc>> {
    match timezone.from_local_datetime(&day.and_time(time)) {
        chrono::LocalResult::Single(instant) => Some(instant.with_timezone(&Utc)),
        _ => None,
    }
}

// ── field_access (§16.2) ────────────────────────────────────────────────

fn field_access_matches(
    operation: &AuthorizationOperation<'_>,
    constraint: &GrantConstraint,
) -> Tri {
    let (allow, deny, fields) = match operation.facts.read_fields.as_ref() {
        Some(fields) => (
            &constraint.allowed_read_fields,
            &constraint.denied_read_fields,
            Some(fields),
        ),
        None => (
            &constraint.allowed_write_fields,
            &constraint.denied_write_fields,
            operation.facts.write_fields.as_ref(),
        ),
    };
    if let Some(condition) = constraint.condition.as_ref() {
        if !condition.extra.is_empty() {
            return Tri::Unknown;
        }
        match condition_holds(operation, condition.kind) {
            Tri::Unknown => return Tri::Unknown,
            Tri::No => {
                return Tri::from_bool(constraint.effect == GrantConstraintEffect::Allow);
            }
            Tri::Yes => {}
        }
    }
    if constraint.effect == GrantConstraintEffect::Deny {
        if deny.is_empty() {
            return Tri::No;
        }
        return match fields {
            Some(fields) => Tri::from_bool(fields.iter().any(|field| path_listed(deny, field))),
            None => Tri::Unknown,
        };
    }
    if allow.is_empty() && deny.is_empty() {
        return Tri::Yes;
    }
    let Some(fields) = fields else {
        return Tri::Unknown;
    };
    Tri::from_bool(
        fields.iter().all(|field| {
            !path_listed(deny, field) && (allow.is_empty() || path_listed(allow, field))
        }),
    )
}

/// A field path is listed when an entry equals it or is one of its dotted
/// ancestors.
fn path_listed(entries: &[String], field: &str) -> bool {
    entries.iter().any(|entry| {
        field == entry
            || field
                .strip_prefix(entry.as_str())
                .is_some_and(|rest| rest.starts_with('.'))
    })
}

fn condition_holds(
    operation: &AuthorizationOperation<'_>,
    kind: GrantConstraintConditionKind,
) -> Tri {
    match kind {
        GrantConstraintConditionKind::Always => Tri::Yes,
        GrantConstraintConditionKind::Never => Tri::No,
        GrantConstraintConditionKind::ObjectIsOwnedByActor => match &operation.facts.target_owner {
            Some(owner) => Tri::from_bool(owner == operation.actor),
            None => Tri::Unknown,
        },
        _ => Tri::Unknown,
    }
}

// ── kind_restriction (§5) and scope_limitation (§6) ─────────────────────

impl OperationFacts {
    fn selector_kind_name(target: &WireResourceSelector) -> Option<&'static str> {
        Some(match target.kind {
            ResourceSelectorKind::Space => "space",
            ResourceSelectorKind::Circle => "circle",
            ResourceSelectorKind::Strand => "strand",
            ResourceSelectorKind::Message => "message",
            ResourceSelectorKind::Morph => "morph",
            ResourceSelectorKind::Relation => "relation",
            ResourceSelectorKind::View => "view",
            ResourceSelectorKind::Event => "event",
            ResourceSelectorKind::Invite => "invite",
            ResourceSelectorKind::Blob => "blob",
            _ => return None,
        })
    }
}

fn object_kind(operation: &AuthorizationOperation<'_>) -> Option<String> {
    operation
        .facts
        .object_kind
        .clone()
        .or_else(|| {
            (operation.target.kind == ResourceSelectorKind::Object)
                .then(|| operation.target.object_kind.clone())
                .flatten()
        })
        .or_else(|| OperationFacts::selector_kind_name(operation.target).map(str::to_owned))
}

fn strand_id(operation: &AuthorizationOperation<'_>) -> Option<String> {
    operation
        .facts
        .strand_id
        .clone()
        .or_else(|| operation.target.strand_id.as_ref().map(ToString::to_string))
}

fn space_id(operation: &AuthorizationOperation<'_>) -> Option<String> {
    operation
        .facts
        .space_id
        .clone()
        .or_else(|| operation.target.space_id.as_ref().map(ToString::to_string))
}

fn circle_id(operation: &AuthorizationOperation<'_>) -> Option<String> {
    operation
        .facts
        .circle_id
        .clone()
        .or_else(|| operation.target.circle_id.as_ref().map(ToString::to_string))
}

fn view_id(operation: &AuthorizationOperation<'_>) -> Option<String> {
    operation
        .facts
        .view_id
        .clone()
        .or_else(|| operation.target.view_id.as_ref().map(ToString::to_string))
}

fn morph_kind(operation: &AuthorizationOperation<'_>) -> Option<String> {
    operation
        .facts
        .morph_kind
        .clone()
        .or_else(|| operation.target.morph_kind.clone())
}

/// An allow list restricts the operation's value: listed passes, unlisted or
/// unknown does not. An empty list does not restrict.
fn allow_list<T: AsRef<str>>(list: &[T], value: Option<&str>) -> Tri {
    if list.is_empty() {
        return Tri::Yes;
    }
    match value {
        Some(value) => Tri::from_bool(list.iter().any(|entry| entry.as_ref() == value)),
        None => Tri::Unknown,
    }
}

/// A deny list refuses a listed value; an unknown value may be listed.
fn deny_list<T: AsRef<str>>(list: &[T], value: Option<&str>) -> Tri {
    if list.is_empty() {
        return Tri::No;
    }
    match value {
        Some(value) => Tri::from_bool(list.iter().any(|entry| entry.as_ref() == value)),
        None => Tri::Unknown,
    }
}

/// A list that only restricts objects of one type: an operation on another
/// object type is outside its reach.
fn typed_allow_list<T: AsRef<str>>(list: &[T], applies: Option<bool>, value: Option<&str>) -> Tri {
    if list.is_empty() {
        return Tri::Yes;
    }
    match applies {
        Some(false) => Tri::Yes,
        Some(true) => allow_list(list, value),
        None => Tri::Unknown,
    }
}

fn typed_deny_list<T: AsRef<str>>(list: &[T], applies: Option<bool>, value: Option<&str>) -> Tri {
    if list.is_empty() {
        return Tri::No;
    }
    match applies {
        Some(false) => Tri::No,
        Some(true) => deny_list(list, value),
        None => Tri::Unknown,
    }
}

fn is_kind(operation: &AuthorizationOperation<'_>, kind: &str) -> Option<bool> {
    object_kind(operation).map(|object| object == kind)
}

fn facet_names(operation: &AuthorizationOperation<'_>) -> Option<Vec<String>> {
    operation.facts.facets.as_ref().map(|facets| {
        facets
            .iter()
            .filter_map(|facet| serde_json::to_value(facet).ok())
            .filter_map(|value| value.as_str().map(str::to_owned))
            .collect()
    })
}

fn facet_tokens(facets: &[Facet]) -> Vec<String> {
    facets
        .iter()
        .filter_map(|facet| serde_json::to_value(facet).ok())
        .filter_map(|value| value.as_str().map(str::to_owned))
        .collect()
}

/// `allowed_facets` admits a target declaring at least one listed facet;
/// `denied_facets` refuses a target declaring any listed facet
/// (`capabilities.md` §6.2).
fn facets_admitted(allowed: &[Facet], operation: &AuthorizationOperation<'_>) -> Tri {
    if allowed.is_empty() {
        return Tri::Yes;
    }
    let allowed = facet_tokens(allowed);
    match facet_names(operation) {
        Some(declared) => Tri::from_bool(declared.iter().any(|facet| allowed.contains(facet))),
        None => Tri::Unknown,
    }
}

fn facets_denied(denied: &[Facet], operation: &AuthorizationOperation<'_>) -> Tri {
    if denied.is_empty() {
        return Tri::No;
    }
    let denied = facet_tokens(denied);
    match facet_names(operation) {
        Some(declared) => Tri::from_bool(declared.iter().any(|facet| denied.contains(facet))),
        None => Tri::Unknown,
    }
}

fn kind_restriction_admits(
    operation: &AuthorizationOperation<'_>,
    constraint: &GrantConstraint,
) -> Tri {
    let object = object_kind(operation);
    let space = operation.facts.space_kind.clone();
    let morph = morph_kind(operation);
    allow_list(&constraint.allowed_object_kinds, object.as_deref())
        .and(typed_allow_list(
            &constraint.allowed_space_kinds,
            is_kind(operation, "space"),
            space.as_deref(),
        ))
        .and(typed_allow_list(
            &constraint.allowed_morph_kinds,
            is_kind(operation, "morph"),
            morph.as_deref(),
        ))
        .and(facets_admitted(&constraint.allowed_facets, operation))
        .and(negate(kind_restriction_denied(operation, constraint)))
}

fn kind_restriction_denied(
    operation: &AuthorizationOperation<'_>,
    constraint: &GrantConstraint,
) -> Tri {
    let object = object_kind(operation);
    let space = operation.facts.space_kind.clone();
    let morph = morph_kind(operation);
    deny_list(&constraint.denied_object_kinds, object.as_deref())
        .or(typed_deny_list(
            &constraint.denied_space_kinds,
            is_kind(operation, "space"),
            space.as_deref(),
        ))
        .or(typed_deny_list(
            &constraint.denied_morph_kinds,
            is_kind(operation, "morph"),
            morph.as_deref(),
        ))
        .or(facets_denied(&constraint.denied_facets, operation))
}

fn negate(value: Tri) -> Tri {
    match value {
        Tri::Yes => Tri::No,
        Tri::No => Tri::Yes,
        Tri::Unknown => Tri::Unknown,
    }
}

/// The fields this Station has no operation input for: an operation never
/// carries a presign purpose, an egress endpoint, a data label or an Applet
/// interop session, so a constraint naming them cannot be decided.
fn scope_limitation_undecidable(constraint: &GrantConstraint) -> bool {
    constraint.blob_presign_scope.is_some()
        || !constraint.allowed_endpoints.is_empty()
        || !constraint.allowed_data_labels.is_empty()
        || !constraint.allowed_session_ids.is_empty()
}

fn scope_limitation_admits(
    operation: &AuthorizationOperation<'_>,
    constraint: &GrantConstraint,
) -> Tri {
    if scope_limitation_undecidable(constraint) {
        return Tri::Unknown;
    }
    let circles = constraint
        .allowed_circle_ids
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    allow_list(
        &constraint.allowed_strand_ids,
        strand_id(operation).as_deref(),
    )
    .and(allow_list(
        &constraint.allowed_space_ids,
        space_id(operation).as_deref(),
    ))
    .and(allow_list(&circles, circle_id(operation).as_deref()))
    .and(allow_list(
        &constraint.allowed_view_ids,
        view_id(operation).as_deref(),
    ))
    .and(allow_list(
        &constraint.allowed_from_container_refs,
        operation.facts.from_container_id.as_deref(),
    ))
    .and(allow_list(
        &constraint.allowed_to_container_refs,
        operation.facts.to_container_id.as_deref(),
    ))
    .and(allow_list(
        &constraint.allowed_tracks,
        operation.facts.track.as_deref(),
    ))
    .and(allow_list(
        &constraint.allowed_view_kinds,
        operation.facts.view_kind.as_deref(),
    ))
    .and(allow_list(
        &constraint.allowed_view_renderers,
        operation.facts.view_renderer.as_deref(),
    ))
    .and(negate(scope_limitation_denied(operation, constraint)))
}

fn scope_limitation_denied(
    operation: &AuthorizationOperation<'_>,
    constraint: &GrantConstraint,
) -> Tri {
    deny_list(
        &constraint.denied_strand_ids,
        strand_id(operation).as_deref(),
    )
    .or(deny_list(
        &constraint.denied_space_ids,
        space_id(operation).as_deref(),
    ))
    .or(deny_list(
        &constraint.denied_tracks,
        operation.facts.track.as_deref(),
    ))
    .or(deny_list(
        &constraint.denied_view_kinds,
        operation.facts.view_kind.as_deref(),
    ))
    .or(deny_list(
        &constraint.denied_view_renderers,
        operation.facts.view_renderer.as_deref(),
    ))
}

/// A `deny` constraint of `kind_restriction` or `scope_limitation` matches
/// exactly when the operation falls in one of its `denied_*` lists; its
/// `allowed_*` lists carry no refusal meaning (§16.2 by analogy: an empty
/// deny set matches nothing).
fn denied_lists_touched(
    operation: &AuthorizationOperation<'_>,
    constraint: &GrantConstraint,
) -> Tri {
    match constraint.constraint_kind {
        GrantConstraintKind::KindRestriction => kind_restriction_denied(operation, constraint),
        GrantConstraintKind::ScopeLimitation => {
            if scope_limitation_undecidable(constraint) {
                Tri::Unknown
            } else {
                scope_limitation_denied(operation, constraint)
            }
        }
        _ => Tri::Unknown,
    }
}

// ── quota (§8.1) ────────────────────────────────────────────────────────

/// The canonical key of one constraint inside its grant: its
/// `constraint_id`, or the SHA-256 of its canonical JSON.
pub fn constraint_key(constraint: &GrantConstraint) -> Option<String> {
    if let Some(id) = constraint.constraint_id.as_ref() {
        return Some(format!("id:{id}"));
    }
    let bytes = arkret_canonical::canonical_json_bytes(constraint).ok()?;
    Some(format!("sha256:{}", arkret_canonical::sha256_digest(bytes)))
}

fn quota_reservation(
    operation: &AuthorizationOperation<'_>,
    grant: &CapabilityGrant,
    constraint: &GrantConstraint,
) -> Option<QuotaReservation> {
    let max_operations = constraint.max_operations?;
    let period_ms = fixed_duration(constraint.period.as_deref()?)?
        .num_milliseconds()
        .max(0);
    if period_ms == 0 {
        return None;
    }
    if constraint.burst.is_some_and(|burst| burst == 0) {
        return None;
    }
    let actor = operation.actor.to_string();
    let realm = || operation.target.realm_id.as_ref().map(ToString::to_string);
    let key = match constraint.constraint_scope? {
        GrantConstraintScope::PerActor => vec!["per_actor".to_owned(), actor],
        GrantConstraintScope::PerRealm => vec!["per_realm".to_owned(), actor, realm()?],
        GrantConstraintScope::PerSpace => {
            vec![
                "per_space".to_owned(),
                actor,
                realm()?,
                space_id(operation)?,
            ]
        }
        GrantConstraintScope::Global => vec!["global".to_owned(), actor],
    };
    let counter_key = serde_json::to_string(&key).ok()?;
    let verification_ms = operation.at.timestamp_millis();
    Some(QuotaReservation {
        grant_id: grant.id.clone(),
        constraint_key: constraint_key(constraint)?,
        counter_key,
        window_id: verification_ms.div_euclid(period_ms),
        max_operations,
        period_ms,
        burst: constraint.burst,
        verification_ms,
    })
}

// ── registry required_constraints ───────────────────────────────────────

/// Whether `grant` declares every `required_constraints` shorthand of
/// `action`'s registry row (`capability-action-registry.json`
/// `registry_rules`). An action missing from the registry has no row to
/// satisfy and fails closed.
fn required_constraints_declared(
    operation: &AuthorizationOperation<'_>,
    action: &str,
    grant: &CapabilityGrant,
) -> bool {
    let Some(descriptor) = arkret_schema::capability_action(action) else {
        return false;
    };
    descriptor
        .required_constraints
        .iter()
        .all(|shorthand| match *shorthand {
            // §14.2: no declared window is an unbounded window.
            "message_edit_window" | "message_redact_window" => true,
            "expires_at" => crate::capability_grant_expires_at(grant).is_some(),
            "allowed_circle_ids" => {
                grant_declares(grant, shorthand)
                    || covered_by_narrowed_selector(grant, operation.target, |resource| {
                        resource.kind == ResourceSelectorKind::Circle
                            && resource.circle_id.is_some()
                    })
            }
            "allowed_strand_ids" => {
                grant_declares(grant, shorthand)
                    || covered_by_narrowed_selector(grant, operation.target, |resource| {
                        resource.kind == ResourceSelectorKind::Strand
                            && resource.strand_id.is_some()
                    })
            }
            other => grant_declares(grant, other),
        })
}

/// Whether an `allow` constraint of `grant` carries the member `shorthand`.
fn grant_declares(grant: &CapabilityGrant, shorthand: &str) -> bool {
    grant
        .constraints
        .iter()
        .filter(|constraint| constraint.effect == GrantConstraintEffect::Allow)
        .filter_map(|constraint| serde_json::to_value(constraint).ok())
        .any(|value| value.get(shorthand).is_some_and(|member| !member.is_null()))
}

/// Whether every resource of `grant` covering `target` is narrowed as
/// `narrowed` describes.
fn covered_by_narrowed_selector(
    grant: &CapabilityGrant,
    target: &WireResourceSelector,
    narrowed: impl Fn(&WireResourceSelector) -> bool,
) -> bool {
    let mut covering = grant
        .resources
        .iter()
        .filter(|resource| crate::resource_selector_covers(resource, target))
        .peekable();
    covering.peek().is_some() && covering.all(narrowed)
}

#[cfg(test)]
#[path = "grant_evaluation_tests.rs"]
mod tests;

#[cfg(test)]
mod constraint_ceiling_tests {
    use super::*;

    const REALM: &str = "ak:realm:AUGIFvQctz4TjQTmvvO4Wdy-xdc5XP2ZnJ5Qpbh4s8Ru";
    const OTHER_REALM: &str = "ak:realm:Ac1aCK8aQdnkYImvdH3DFjq4jDCP198pXYWCGzGuVyj5";
    const STRAND: &str = "ak:strand:AZ6GqZWWvnQ2KFwbBD-MenomzWNz-31MUAuKzBXIP0zv";

    fn actor() -> ActorId {
        ActorId::account(arkret_wire::AccountId::new(
            "ak:did_core:web:agent.example".parse().unwrap(),
            "ak:did_core:web:station.example".parse().unwrap(),
        ))
    }

    fn at() -> DateTime<Utc> {
        "2026-10-12T12:00:00.000Z".parse().unwrap()
    }

    fn target(realm: &str) -> WireResourceSelector {
        WireResourceSelector::strand(realm.parse().unwrap(), STRAND.parse().unwrap())
    }

    fn operation<'a>(
        actor: &'a ActorId,
        target: &'a WireResourceSelector,
        facts: &'a OperationFacts,
    ) -> AuthorizationOperation<'a> {
        AuthorizationOperation {
            actor,
            actions: &[CapabilityActionId::MESSAGE_CREATE],
            target,
            at: at(),
            facts,
        }
    }

    fn accepts(verdict: &GrantEvaluation<'_>) -> bool {
        matches!(verdict, GrantEvaluation::Allowed(candidates) if candidates.is_empty())
    }

    #[test]
    fn explicit_resource_ceiling_rejects_other_realm_and_empty_set() {
        let actor = actor();
        let target = target(REALM);
        let facts = OperationFacts::default();
        let op = operation(&actor, &target, &facts);
        let correct = WireResourceSelector::realm(REALM.parse().unwrap());
        let wrong = WireResourceSelector::realm(OTHER_REALM.parse().unwrap());
        assert!(accepts(&evaluate_resource_constraint_ceiling(
            &op,
            &[correct],
            &[]
        )));
        assert!(!accepts(&evaluate_resource_constraint_ceiling(
            &op,
            &[wrong],
            &[]
        )));
        assert!(!accepts(&evaluate_resource_constraint_ceiling(
            &op,
            &[],
            &[]
        )));
    }

    #[test]
    fn all_allow_constraints_intersect_actual_track_and_target() {
        let actor = actor();
        let target = target(REALM);
        let mut facts = OperationFacts {
            track: Some("discussion".into()),
            ..Default::default()
        };
        let mut track = GrantConstraint::new(
            GrantConstraintKind::ScopeLimitation,
            GrantConstraintEffect::Allow,
        );
        track.allowed_tracks = vec!["discussion".into()];
        let mut strand = GrantConstraint::new(
            GrantConstraintKind::ScopeLimitation,
            GrantConstraintEffect::Allow,
        );
        strand.allowed_strand_ids = vec![STRAND.into()];
        assert!(accepts(&evaluate_constraint_ceiling(
            &operation(&actor, &target, &facts),
            &[track.clone(), strand.clone()]
        )));
        facts.track = Some("synthesis".into());
        assert!(!accepts(&evaluate_constraint_ceiling(
            &operation(&actor, &target, &facts),
            &[track, strand]
        )));
    }

    #[test]
    fn temporal_ceiling_uses_actual_evaluation_time() {
        let actor = actor();
        let target = target(REALM);
        let facts = OperationFacts::default();
        let op = operation(&actor, &target, &facts);
        let mut temporal =
            GrantConstraint::new(GrantConstraintKind::Temporal, GrantConstraintEffect::Allow);
        temporal.expires_at = Some(at() + TimeDelta::hours(1));
        assert!(accepts(&evaluate_constraint_ceiling(
            &op,
            &[temporal.clone()]
        )));
        let mut own_window =
            GrantConstraint::new(GrantConstraintKind::Temporal, GrantConstraintEffect::Allow);
        own_window.constraint_subkind = Some(GrantConstraintSubkind::EditWindow);
        own_window.applies_to_actions = vec![CapabilityActionId::MESSAGE_REVISE_OWN.into()];
        own_window.message_edit_window = Some("PT1M".into());
        assert!(accepts(&evaluate_constraint_ceiling(
            &op,
            &[own_window.clone()]
        )));
        let all_actions = AuthorizationOperation {
            actions: &[
                CapabilityActionId::MESSAGE_CREATE,
                CapabilityActionId::MESSAGE_REVISE_OWN,
            ],
            ..op
        };
        assert!(
            matches!(
                evaluate_constraint_ceiling(&all_actions, &[own_window]),
                GrantEvaluation::Unsatisfied
            ),
            "an unrelated neutral action cannot replace a required unknown own-window fact"
        );
        temporal.expires_at = Some(at() - TimeDelta::hours(1));
        assert!(matches!(
            evaluate_constraint_ceiling(&op, &[temporal]),
            GrantEvaluation::Unsatisfied
        ));
    }

    #[test]
    fn global_refusals_keep_deny_quarantine_review_priority() {
        let actor = actor();
        let target = target(REALM);
        let facts = OperationFacts {
            track: Some("discussion".into()),
            ..Default::default()
        };
        let op = operation(&actor, &target, &facts);
        let mut deny = GrantConstraint::new(
            GrantConstraintKind::ScopeLimitation,
            GrantConstraintEffect::Deny,
        );
        deny.denied_tracks = vec!["discussion".into()];
        let quarantine = GrantConstraint::new(
            GrantConstraintKind::Temporal,
            GrantConstraintEffect::Quarantine,
        );
        let review = GrantConstraint::new(
            GrantConstraintKind::Temporal,
            GrantConstraintEffect::RequireReview,
        );
        assert!(matches!(
            evaluate_constraint_ceiling(&op, &[review.clone(), quarantine.clone(), deny]),
            GrantEvaluation::Denied
        ));
        assert!(matches!(
            evaluate_constraint_ceiling(&op, &[review.clone(), quarantine]),
            GrantEvaluation::Quarantined
        ));
        assert!(matches!(
            evaluate_constraint_ceiling(&op, &[review]),
            GrantEvaluation::RequiresReview
        ));
    }

    #[test]
    fn unknown_identity_or_track_facts_cannot_discharge_constraints() {
        let actor = actor();
        let target = target(REALM);
        let facts = OperationFacts::default();
        let op = operation(&actor, &target, &facts);
        let mut track = GrantConstraint::new(
            GrantConstraintKind::ScopeLimitation,
            GrantConstraintEffect::Allow,
        );
        track.allowed_tracks = vec!["discussion".into()];
        assert!(matches!(
            evaluate_constraint_ceiling(&op, &[track]),
            GrantEvaluation::Unsatisfied
        ));
        let mut identity = GrantConstraint::new(
            GrantConstraintKind::AuthorityControl,
            GrantConstraintEffect::Allow,
        );
        identity.constraint_subkind = Some(GrantConstraintSubkind::AppletAuthority);
        assert!(matches!(
            evaluate_constraint_ceiling(&op, &[identity]),
            GrantEvaluation::Unsatisfied
        ));
    }

    #[test]
    fn external_quota_never_gets_a_synthetic_grant_reservation() {
        let actor = actor();
        let target = target(REALM);
        let facts = OperationFacts::default();
        let op = operation(&actor, &target, &facts);
        let mut quota =
            GrantConstraint::new(GrantConstraintKind::Quota, GrantConstraintEffect::Allow);
        quota.constraint_subkind = Some(GrantConstraintSubkind::Rate);
        quota.constraint_scope = Some(GrantConstraintScope::PerActor);
        quota.max_operations = Some(3);
        quota.period = Some("PT1H".into());
        assert!(matches!(
            evaluate_constraint_ceiling(&op, &[quota]),
            GrantEvaluation::Unsatisfied
        ));
        let missing = AuthorizationOperation { actions: &[], ..op };
        assert!(matches!(
            evaluate_constraint_ceiling(&missing, &[]),
            GrantEvaluation::Unsatisfied
        ));
    }
}
