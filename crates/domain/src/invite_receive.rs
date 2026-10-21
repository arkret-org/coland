//! One deterministic Invite receive policy for every native accepting cut.

use arkret_identifiers::DidCoreId;
use arkret_models_collaboration::governance::invite_addressing::{
    DisclosedOutcome, DisclosureLevel, IntroductionEvidence, InviteReceivePolicy,
};
use arkret_models_identity::handle::Handle;
use arkret_models_identity::{HandleClaim, HandleClaimStatus};
use arkret_wire::{InviteReceiveAction, ReceivePolicyConstraints, UnknownInviteAction};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrustTier {
    High,
    Discovery,
    Low,
}

impl TrustTier {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::High => "high",
            Self::Discovery => "discovery",
            Self::Low => "low",
        }
    }
}

pub fn trust_tier_for_kind(kind: &str) -> TrustTier {
    match kind {
        "locator_ref" | "consent_grant" | "shared_realm" => TrustTier::High,
        "handle_claim" => TrustTier::Discovery,
        // same_station / explicit_address / unknown → low
        _ => TrustTier::Low,
    }
}

/// Outcome of applying the subject's `invite_receive_policy` to one
/// delivery: the receive action, the effective (post-downgrade) evidence
/// kind, its trust tier, and the graded-disclosure value to echo back.
pub struct ReceiveDecision {
    pub action: InviteReceiveAction,
    pub effective_kind: &'static str,
    pub trust_tier: TrustTier,
    pub disclosed_outcome: Option<DisclosedOutcome>,
}

pub fn evaluate_resolved(
    constraints: Option<&ReceivePolicyConstraints>,
    locator_verified: bool,
    at: chrono::DateTime<chrono::Utc>,
    policy: &InviteReceivePolicy,
    evidence: &IntroductionEvidence,
    inviter_actor_id: &arkret_wire::ActorId,
    subject: &str,
    recipient_id: &str,
    source_id: &str,
    same_station: bool,
    verified_consent: bool,
) -> ReceiveDecision {
    let now = at;

    // §5 — exact `denied_actor_ids` hit: MUST drop and force opaque disclosure so
    // the blocklist cannot leak through the response side channel.
    if policy
        .denied_actor_ids
        .iter()
        .any(|actor| actor == inviter_actor_id)
    {
        return ReceiveDecision {
            action: InviteReceiveAction::Drop,
            effective_kind: if same_station && evidence.kind() == "explicit_address" {
                "same_station"
            } else {
                evidence.kind()
            },
            trust_tier: TrustTier::Low,
            disclosed_outcome: None,
        };
    }

    // §2 — `consent_grant` evidence: verify the referenced grant is an
    // active `invite` permission in the exact-peer current the subject signed for that inviter
    // ActorId. On failure
    // MUST downgrade to low-trust `explicit_address`.
    if principal_service_blocked(policy, constraints, source_id)
        || !principal_service_trusted(policy, constraints, source_id)
        || !subject_did_method_accepted(constraints, subject)
    {
        return opaque_drop(evidence.kind());
    }

    let verified_kind: &'static str = match evidence {
        IntroductionEvidence::LocatorRef { principal_locator } => {
            if locator_verified
                && principal_locator.account_id.principal_id.as_str() == subject
                && principal_locator.account_id.station_id.as_str() == recipient_id
                && principal_locator.issued_at <= now
                && now < principal_locator.expires_at
            {
                "locator_ref"
            } else {
                "explicit_address"
            }
        }
        IntroductionEvidence::ConsentGrant { .. } => {
            if verified_consent {
                "consent_grant"
            } else {
                "explicit_address"
            }
        }
        IntroductionEvidence::SharedRealm { realm_id, .. } => {
            if policy.trusted_realm_ids.is_empty()
                || policy
                    .trusted_realm_ids
                    .iter()
                    .any(|trusted| trusted == realm_id)
            {
                "shared_realm"
            } else {
                "explicit_address"
            }
        }
        IntroductionEvidence::HandleClaim {
            handle,
            handle_claim,
            resolved_by,
            ..
        } => {
            if handle_claim_evidence_valid(
                policy,
                constraints,
                handle,
                handle_claim,
                resolved_by.as_ref(),
                subject,
                recipient_id,
                now,
            ) {
                "handle_claim"
            } else {
                "explicit_address"
            }
        }
        IntroductionEvidence::ExplicitAddress => "explicit_address",
    };
    let effective_kind = if verified_kind == "explicit_address" && same_station {
        "same_station"
    } else {
        verified_kind
    };

    if kind_forbidden_by_constraints(constraints, effective_kind)
        || !kind_permitted_by_constraints(constraints, effective_kind)
    {
        return opaque_drop(effective_kind);
    }

    // consent-model.md §6.1 step 2 — `require_explicit_consent` profile: only
    // verified `consent_grant` evidence may notify. Everything else is silently
    // dropped on the holder Station inside the opaque `deferred` class: no
    // quarantine, no quota charge, no holder-private write, and graded
    // disclosure is forced opaque so the profile itself is not observable.
    if policy.consent_profile.requires_explicit_consent() && effective_kind != "consent_grant" {
        return opaque_drop(effective_kind);
    }

    let trust_tier = trust_tier_for_kind(effective_kind);
    let action = receive_action_for_kind(policy, constraints, effective_kind);

    // §5.1 — graded disclosure. High-trust + `outcome` echoes the real
    // result; everything else stays opaque (`disclosed_outcome = None`).
    let disclosure_level = match trust_tier {
        TrustTier::High => policy
            .disclosure
            .as_ref()
            .and_then(|d| d.high_trust.clone())
            .unwrap_or(DisclosureLevel::Outcome),
        TrustTier::Discovery => policy
            .disclosure
            .as_ref()
            .and_then(|d| d.discovery_trust.clone())
            .unwrap_or(DisclosureLevel::Opaque),
        TrustTier::Low => policy
            .disclosure
            .as_ref()
            .and_then(|d| d.low_trust.clone())
            .unwrap_or(DisclosureLevel::Opaque),
    };
    let disclosed_outcome = disclosed_outcome_for_action(disclosure_level, &action);

    ReceiveDecision {
        action,
        effective_kind,
        trust_tier,
        disclosed_outcome,
    }
}

pub fn opaque_drop(effective_kind: &'static str) -> ReceiveDecision {
    ReceiveDecision {
        action: InviteReceiveAction::Drop,
        effective_kind,
        trust_tier: TrustTier::Low,
        disclosed_outcome: None,
    }
}

pub fn disclosed_outcome_for_action(
    disclosure_level: DisclosureLevel,
    action: &InviteReceiveAction,
) -> Option<DisclosedOutcome> {
    match (disclosure_level, action) {
        (DisclosureLevel::Outcome, InviteReceiveAction::Notify) => {
            Some(DisclosedOutcome::Delivered)
        }
        (DisclosureLevel::Outcome, InviteReceiveAction::Drop) => Some(DisclosedOutcome::Blocked),
        // Quarantine is holder-private consent state. It is always represented
        // externally by status=deferred without a disclosed_outcome, including
        // on high-trust/outcome routes.
        (DisclosureLevel::Outcome, InviteReceiveAction::Quarantine)
        | (DisclosureLevel::Opaque, _) => None,
    }
}

pub fn unknown_action_to_receive(action: &UnknownInviteAction) -> InviteReceiveAction {
    match action {
        UnknownInviteAction::Drop => InviteReceiveAction::Drop,
        UnknownInviteAction::Quarantine => InviteReceiveAction::Quarantine,
    }
}

pub fn receive_action_rank(action: &InviteReceiveAction) -> u8 {
    match action {
        InviteReceiveAction::Drop => 0,
        InviteReceiveAction::Quarantine => 1,
        InviteReceiveAction::Notify => 2,
    }
}

pub fn cap_receive_action(
    action: InviteReceiveAction,
    cap: Option<&InviteReceiveAction>,
) -> InviteReceiveAction {
    let Some(cap) = cap else {
        return action;
    };
    if receive_action_rank(&action) <= receive_action_rank(cap) {
        action
    } else {
        cap.clone()
    }
}

/// `invite-addressing.md` §5 / §5.2 — the holder's effective receive action for
/// one already-verified evidence kind.
///
/// The per-kind behavior fields do not carry two of the section's constraints
/// on their own:
///
/// - `holder_allowed_introduction_kinds` is an allowlist, and §5 states that an evidence kind
///   outside it MUST NOT reach a user notification. A holder who sets `handle_claim_behavior` /
///   `explicit_address_behavior` to `notify` without also allowlisting the kind therefore lands on
///   the next strictest behavior instead of notifying.
/// - `unknown_invites` governs deliveries with no evidence or non-conforming evidence.
///   `same_station` is receiver-derived but conforming, so it stays on the low-trust
///   `explicit_address_behavior` even when it is not allowlisted.
pub fn receive_action_for_kind(
    policy: &InviteReceivePolicy,
    constraints: Option<&ReceivePolicyConstraints>,
    effective_kind: &str,
) -> InviteReceiveAction {
    let allowlisted = policy
        .holder_allowed_introduction_kinds
        .iter()
        .any(|kind| kind == effective_kind);
    let unknown_path = !allowlisted
        && !matches!(
            effective_kind,
            "handle_claim" | "same_station" | "explicit_address"
        );
    let mut action = match effective_kind {
        "handle_claim" => policy
            .handle_claim_behavior
            .clone()
            .unwrap_or(InviteReceiveAction::Quarantine),
        "same_station" | "explicit_address" => policy.explicit_address_behavior.clone(),
        _ if allowlisted => InviteReceiveAction::Notify,
        _ => unknown_action_to_receive(&policy.unknown_invites),
    };
    if !allowlisted {
        action = cap_receive_action(action, Some(&InviteReceiveAction::Quarantine));
    }
    apply_behavior_caps(constraints, effective_kind, unknown_path, action)
}

pub fn apply_behavior_caps(
    constraints: Option<&ReceivePolicyConstraints>,
    effective_kind: &str,
    unknown_path: bool,
    action: InviteReceiveAction,
) -> InviteReceiveAction {
    let Some(constraints) = constraints else {
        return action;
    };
    let capped = match effective_kind {
        "handle_claim" => {
            cap_receive_action(action, constraints.handle_claim_max_behavior.as_ref())
        }
        // §2 puts `same_station` in the same low-trust tier as
        // `explicit_address`, and `receive_policy_constraints` carries no
        // separate `same_station_max_behavior`, so the two share one deployment
        // ceiling. Matching it by kind name alone let an allowlisted
        // `same_station` escape `explicit_address_max_behavior`, which §5.2
        // forbids: a deployment constraint may only make the subject harder to
        // reach, never easier.
        "same_station" | "explicit_address" => {
            cap_receive_action(action, constraints.explicit_address_max_behavior.as_ref())
        }
        _ => action,
    };
    if unknown_path {
        match constraints.unknown_invites_max_behavior.as_ref() {
            Some(UnknownInviteAction::Drop) => InviteReceiveAction::Drop,
            Some(UnknownInviteAction::Quarantine) => {
                cap_receive_action(capped, Some(&InviteReceiveAction::Quarantine))
            }
            None => capped,
        }
    } else {
        capped
    }
}

pub fn kind_forbidden_by_constraints(
    constraints: Option<&ReceivePolicyConstraints>,
    effective_kind: &str,
) -> bool {
    constraints.is_some_and(|constraints| {
        constraints
            .deployment_denied_introduction_kinds
            .iter()
            .any(|kind| kind == effective_kind)
    })
}

pub fn kind_permitted_by_constraints(
    constraints: Option<&ReceivePolicyConstraints>,
    effective_kind: &str,
) -> bool {
    constraints
        .and_then(|constraints| constraints.deployment_allowed_introduction_kinds.as_ref())
        .is_none_or(|kinds| kinds.iter().any(|kind| kind == effective_kind))
}

pub fn did_in_list(value: &str, list: &[DidCoreId]) -> bool {
    list.iter().any(|did| did.as_str() == value)
}

pub fn principal_service_blocked(
    policy: &InviteReceivePolicy,
    constraints: Option<&ReceivePolicyConstraints>,
    source_id: &str,
) -> bool {
    policy
        .denied_source_ids
        .iter()
        .any(|did| did.as_str() == source_id)
        || constraints
            .and_then(|constraints| constraints.denied_source_ids.as_ref())
            .is_some_and(|blocked| did_in_list(source_id, blocked))
}

pub fn principal_service_trusted(
    policy: &InviteReceivePolicy,
    constraints: Option<&ReceivePolicyConstraints>,
    source_id: &str,
) -> bool {
    if !policy.trusted_source_ids.is_empty() && !did_in_list(source_id, &policy.trusted_source_ids)
    {
        return false;
    }
    constraints
        .and_then(|constraints| constraints.trusted_source_ids.as_ref())
        .is_none_or(|trusted| did_in_list(source_id, trusted))
}

pub fn subject_did_method_accepted(
    constraints: Option<&ReceivePolicyConstraints>,
    subject: &str,
) -> bool {
    let Some(methods) =
        constraints.and_then(|constraints| constraints.accepted_subject_did_methods.as_ref())
    else {
        return true;
    };
    let Some(method) = did_method(subject) else {
        return false;
    };
    methods.iter().any(|accepted| accepted == &method)
}

pub fn did_method(did: &str) -> Option<String> {
    let mut parts = did.splitn(3, ':');
    match (parts.next(), parts.next()) {
        (Some("did"), Some(method)) if !method.is_empty() => Some(format!("did:{method}")),
        _ => None,
    }
}

#[allow(clippy::too_many_arguments)]
pub fn handle_claim_evidence_valid(
    policy: &InviteReceivePolicy,
    constraints: Option<&ReceivePolicyConstraints>,
    handle: &Handle,
    handle_claim: &HandleClaim,
    resolved_by: Option<&DidCoreId>,
    subject: &str,
    recipient_id: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> bool {
    if handle_claim.validate().is_err() {
        return false;
    }
    if &handle_claim.claim.handle != handle {
        return false;
    }
    if handle_claim.claim.subject_account_id.principal_id.as_str() != subject
        || handle_claim.claim.subject_account_id.station_id.as_str() != recipient_id
    {
        return false;
    }
    if handle_claim.status != HandleClaimStatus::Verified
        || now < handle_claim.as_of
        || now >= handle_claim.fresh_until
        || resolved_by.is_some_and(|resolver| resolver != &handle_claim.verifier_id)
    {
        return false;
    }
    if handle_claim
        .claim
        .expires_at
        .is_none_or(|expires_at| expires_at <= now)
    {
        return false;
    }
    if !handle_domain_allowed(policy, constraints, handle.domain()) {
        return false;
    }
    if !handle_claim_issuer_allowed(policy, constraints, handle_claim) {
        return false;
    }
    if !resolved_by_allowed(policy, constraints, resolved_by) {
        return false;
    }
    true
}

pub fn handle_domain_allowed(
    policy: &InviteReceivePolicy,
    constraints: Option<&ReceivePolicyConstraints>,
    domain: &str,
) -> bool {
    let domain = domain.to_ascii_lowercase();
    if policy
        .denied_handle_domains
        .iter()
        .any(|blocked| blocked.eq_ignore_ascii_case(&domain))
    {
        return false;
    }
    if !policy.allowed_handle_domains.is_empty()
        && !policy
            .allowed_handle_domains
            .iter()
            .any(|allowed| allowed.eq_ignore_ascii_case(&domain))
    {
        return false;
    }
    constraints
        .and_then(|constraints| constraints.allowed_handle_domains.as_ref())
        .is_none_or(|allowed| {
            allowed
                .iter()
                .any(|candidate| candidate.eq_ignore_ascii_case(&domain))
        })
}

pub fn handle_claim_issuer_allowed(
    policy: &InviteReceivePolicy,
    constraints: Option<&ReceivePolicyConstraints>,
    handle_claim: &HandleClaim,
) -> bool {
    if !policy.trusted_handle_issuer_ids.is_empty()
        && !handle_claim_matches_did_list(handle_claim, &policy.trusted_handle_issuer_ids)
    {
        return false;
    }
    constraints
        .and_then(|constraints| constraints.trusted_handle_issuer_ids.as_ref())
        .is_none_or(|trusted| handle_claim_matches_did_list(handle_claim, trusted))
}

pub fn handle_claim_matches_did_list(handle_claim: &HandleClaim, trusted: &[DidCoreId]) -> bool {
    if trusted.is_empty() {
        return false;
    }
    trusted
        .iter()
        .any(|did| did == &handle_claim.claim.issuer_id)
}

pub fn resolved_by_allowed(
    policy: &InviteReceivePolicy,
    constraints: Option<&ReceivePolicyConstraints>,
    resolved_by: Option<&DidCoreId>,
) -> bool {
    if !policy.trusted_directory_ids.is_empty()
        && !resolved_by.is_some_and(|did| policy.trusted_directory_ids.iter().any(|v| v == did))
    {
        return false;
    }
    constraints
        .and_then(|constraints| constraints.trusted_directory_ids.as_ref())
        .is_none_or(|trusted| {
            !trusted.is_empty()
                && resolved_by.is_some_and(|did| trusted.iter().any(|candidate| candidate == did))
        })
}

use arkret_models_collaboration::governance::invite_addressing::{
    InviteDelivery, InviteDeliveryEntry,
};
pub fn merge_invite_delivery_cell(
    existing: Option<InviteDelivery>,
    new_entry: InviteDeliveryEntry,
    received_at: chrono::DateTime<chrono::Utc>,
) -> Result<InviteDelivery, String> {
    let mut cell = existing.unwrap_or_else(|| InviteDelivery::new(received_at, Vec::new()));
    cell.delivery_entries.retain(|candidate| {
        invite_delivery_entry_active(candidate, received_at)
            && candidate.invite_id != new_entry.invite_id
    });
    cell.delivery_entries.push(new_entry);
    if cell.delivery_entries.len() > InviteDelivery::MAX_ENTRIES {
        let excess = cell.delivery_entries.len() - InviteDelivery::MAX_ENTRIES;
        cell.delivery_entries.drain(0..excess);
    }
    cell.updated_at = received_at;
    cell.validate()
        .map_err(|error| format!("invite delivery cell is invalid: {error}"))?;
    Ok(cell)
}

pub fn invite_delivery_entry_active(
    entry: &InviteDeliveryEntry,
    at: chrono::DateTime<chrono::Utc>,
) -> bool {
    entry.expires_at > at
}
