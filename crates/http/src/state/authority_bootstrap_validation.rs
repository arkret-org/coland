//! Preflight for the closed ordinary Realm bootstrap authority unit.

use arkret_models_collaboration::authority_commit::OrdinaryRealmBootstrapUnitSubmission;
use arkret_models_collaboration::events_payloads::join_policy::JoinPolicyGate;
use arkret_models_collaboration::events_payloads::realm::{
    RealmCreatePayload, RealmPolicyBundlePayload, RealmPurpose,
};
use arkret_wire::{EventKind, OperationKind};
use coland_services::identity::SessionIdentityState;
use coland_services::projection::StagedRealmBootstrap;
use coland_services::{ServiceError, ServiceResult};
use coland_storage::SelfProducerCommitGuard;

use super::AppState;

pub(super) async fn verify_ordinary_realm_bootstrap(
    state: &AppState,
    session: &SessionIdentityState,
    submission: &OrdinaryRealmBootstrapUnitSubmission,
    fresh_realm: bool,
) -> ServiceResult<(Vec<SelfProducerCommitGuard>, Option<StagedRealmBootstrap>)> {
    submission
        .validate()
        .map_err(|error| ServiceError::SchemaViolation(error.to_string()))?;
    let first = &submission.events[0].event;
    let account = first.actor_id.as_account_id().ok_or_else(|| {
        ServiceError::SchemaViolation(
            "ordinary Realm bootstrap creator must be an Account".to_owned(),
        )
    })?;
    if account.station_id != state.service_core_id() {
        return Err(ServiceError::Conflict(
            "ordinary Realm bootstrap creator is not local to the governing Station".to_owned(),
        ));
    }
    let create: RealmCreatePayload = serde_json::from_value(
        serde_json::to_value(&first.payload)
            .map_err(|error| ServiceError::SchemaViolation(error.to_string()))?,
    )
    .map_err(|error| ServiceError::SchemaViolation(error.to_string()))?;
    if create.object.purpose != RealmPurpose::Collaboration {
        return Err(ServiceError::SchemaViolation(
            "ordinary Realm bootstrap must create a collaboration Realm".to_owned(),
        ));
    }
    let last = &submission
        .events
        .last()
        .expect("validated non-empty unit")
        .event;
    if last.kind != EventKind::MemberState
        || last
            .payload
            .get("membership")
            .and_then(serde_json::Value::as_str)
            != Some("join")
        || last.payload.get("member_id")
            != Some(
                &serde_json::to_value(&first.actor_id)
                    .map_err(|error| ServiceError::SchemaViolation(error.to_string()))?,
            )
    {
        return Err(ServiceError::SchemaViolation(
            "ordinary Realm bootstrap must end with the creator's explicit join".to_owned(),
        ));
    }
    let policy_event = submission
        .events
        .iter()
        .find(|submitted| submitted.event.kind == EventKind::RealmPolicyBundle)
        .expect("validated required policy slot");
    let policy: RealmPolicyBundlePayload = serde_json::from_value(
        serde_json::to_value(&policy_event.event.payload)
            .map_err(|error| ServiceError::SchemaViolation(error.to_string()))?,
    )
    .map_err(|error| ServiceError::SchemaViolation(error.to_string()))?;
    policy
        .validate()
        .map_err(|error| ServiceError::SchemaViolation(error.to_string()))?;
    if policy.policy_revision != 1 {
        return Err(ServiceError::Conflict(
            "ordinary Realm bootstrap policy_revision must begin at 1".to_owned(),
        ));
    }
    // join-policy.md §3.1: a parent_membership source needs a current active
    // `join_gate_from` Realm link from this Realm, and a Realm being created
    // has none, so such a policy cannot be written by its bootstrap.
    let gates = policy
        .join_policy
        .as_ref()
        .map_or(&[][..], |join_policy| join_policy.gates.as_slice());
    if gates
        .iter()
        .any(|gate| matches!(gate, JoinPolicyGate::ParentMembership { .. }))
    {
        return Err(ServiceError::protocol(
            arkret_wire::ErrorCode::FailedPrecondition,
            "a parent_membership gate needs join_gate_from links the new Realm cannot have",
        ));
    }
    let join_rule_event = submission
        .events
        .iter()
        .find(|submitted| submitted.event.kind == EventKind::RealmJoinRule)
        .expect("validated required join-rule slot");
    // join-policy.md §2: `restricted` and `knock_restricted` need at least one
    // automatic gate; with only hard gates they would admit the `public` set.
    if matches!(
        join_rule_event
            .event
            .payload
            .get("value")
            .and_then(serde_json::Value::as_str),
        Some("restricted" | "knock_restricted")
    ) && !gates.iter().any(|gate| {
        matches!(
            gate,
            JoinPolicyGate::ClaimRequired { .. } | JoinPolicyGate::ChallengeResponse { .. }
        )
    }) {
        return Err(ServiceError::Conflict(format!(
            "{}: a restricted bootstrap declares no automatic join gate",
            coland_storage::ConflictCode::JoinRulePolicyMismatch
        )));
    }
    let mut guards = Vec::with_capacity(submission.events.len());
    let mut operations = Vec::with_capacity(submission.events.len());
    for submitted in &submission.events {
        let event = &submitted.event;
        guards.push(
            super::authority_producer_validation::verify_self_event_producer(state, session, event)
                .await?,
        );
        if fresh_realm {
            let envelope = serde_json::to_value(event)
                .map_err(|error| ServiceError::SchemaViolation(error.to_string()))?;
            let operation_id = crate::routing::events::event_log::event_operation_id(
                &envelope,
                event.event_id.as_str(),
            )
            .ok_or_else(|| {
                ServiceError::SchemaViolation(
                    "ordinary Realm bootstrap Event has no reproducible projection id".to_owned(),
                )
            })?;
            let operation = arkret_event_draft::ProjectedEventOperation::from_accepted_event(
                operation_id,
                OperationKind::Create,
                None,
                event,
                arkret_canonical::DigestSuite::Sha256,
            )
            .map_err(|error| ServiceError::SchemaViolation(error.to_string()))?;
            operations.push(operation);
        }
    }
    let staged = if fresh_realm {
        Some(
            state
                .projections()
                .stage_realm_bootstrap(&operations, false)
                .map_err(|error| {
                    ServiceError::Conflict(format!(
                        "ordinary Realm bootstrap reducer rejected slot {}: {}",
                        error.operation_index, error.reason
                    ))
                })?,
        )
    } else {
        None
    };
    Ok((guards, staged))
}
