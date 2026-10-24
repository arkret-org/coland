//! Capability verdicts over one durable authorization cut.
//!
//! Every input is the [`ActorRealmAuthorization`] the governing Station reads
//! from the Realm-stream typed current results (`realm_authority_root` and
//! every `capability_grant`) in one snapshot, the same evaluator that admits
//! capability-gated Events (`authz/capabilities.md` §18). No process-local
//! grant index exists: a grant is effective exactly when its durable current
//! result is.

use arkret_wire::{CapabilityActionId, WireResourceSelector};
use coland_storage::{
    ActorRealmAuthorization, EffectiveActorGrant, GrantEvaluation, OperationFacts,
};

/// The outcome of asking whether an actor may exercise one of a set of
/// actions on one resource.
#[derive(Clone, Debug)]
pub enum CapabilityVerdict {
    /// Effective grants that each allow the request without owing a quota
    /// reservation.
    Granted(Vec<EffectiveActorGrant>),
    /// The actor holds the effective `ak.realm.owner` aggregate and that
    /// aggregate covers one of the requested actions.
    RealmOwner,
    /// A `quarantine` constraint of a named grant matches the request.
    Quarantined,
    /// A `require_review` constraint of a named grant matches the request.
    RequiresReview,
    /// A grant names the request, but a `deny` constraint matches it or no
    /// named grant's `allow` constraints admit it without a quota reservation
    /// this read-only decision cannot take.
    ConstraintsNotSatisfied,
    /// Nothing authorizes the request.
    Denied,
}

impl CapabilityVerdict {
    #[must_use]
    pub fn allowed(&self) -> bool {
        matches!(self, Self::Granted(_) | Self::RealmOwner)
    }
}

/// Whether the effective `ak.realm.owner` aggregate covers `action`: the
/// aggregate itself, or an action whose durable Events the compiled owner role
/// may author. Root-control-only, subject-only, personal and `ak.self.*`
/// actions are never covered.
#[must_use]
pub fn realm_owner_covers(action: &str) -> bool {
    action == CapabilityActionId::REALM_OWNER
        || arkret_policy::owner_may_author_action(action).unwrap_or(false)
}

/// Decide whether the actor of `authorization` may exercise one of `actions`
/// on `target` with `facts` (`authz/constraint-schema.md` §15.4). A refusal
/// constraint of any named grant wins over every grant and the owner
/// aggregate; otherwise a satisfying grant wins over the owner aggregate so
/// the verdict names the grants that authorized it.
#[must_use]
pub fn evaluate(
    authorization: &ActorRealmAuthorization,
    actions: &[&str],
    target: &WireResourceSelector,
    facts: &OperationFacts,
) -> CapabilityVerdict {
    let evaluation = authorization.evaluate(actions, target, facts);
    let owner = || {
        target.realm_id.as_ref() == Some(&authorization.realm_id)
            && authorization.holds_realm_owner()
            && actions.iter().any(|action| realm_owner_covers(action))
    };
    match &evaluation {
        GrantEvaluation::Denied => CapabilityVerdict::ConstraintsNotSatisfied,
        GrantEvaluation::Quarantined => CapabilityVerdict::Quarantined,
        GrantEvaluation::RequiresReview => CapabilityVerdict::RequiresReview,
        GrantEvaluation::Allowed(_) => {
            let granted = evaluation
                .unreserved()
                .into_iter()
                .filter_map(|grant| authorization.effective(grant).cloned())
                .collect::<Vec<_>>();
            if !granted.is_empty() {
                CapabilityVerdict::Granted(granted)
            } else if owner() {
                CapabilityVerdict::RealmOwner
            } else {
                CapabilityVerdict::ConstraintsNotSatisfied
            }
        }
        GrantEvaluation::Unsatisfied if owner() => CapabilityVerdict::RealmOwner,
        GrantEvaluation::Unsatisfied => CapabilityVerdict::ConstraintsNotSatisfied,
        GrantEvaluation::Unnamed if owner() => CapabilityVerdict::RealmOwner,
        GrantEvaluation::Unnamed => CapabilityVerdict::Denied,
    }
}

#[cfg(test)]
mod tests {
    use arkret_models_collaboration::governance::grant_constraint::CapabilityGrant;

    use super::*;

    const REALM_ID: &str = "ak:realm:AUGIFvQctz4TjQTmvvO4Wdy-xdc5XP2ZnJ5Qpbh4s8Ru";
    const GRANT_ID: &str = "ak:grant:AcFfzgdHkT6eFkto1gjLaKniVuMXx9sD0GKQwk8BXykz";

    fn actor() -> arkret_wire::ActorId {
        arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            arkret_wire::DidCoreId::new("ak:did_core:web:reader.example").unwrap(),
            arkret_wire::DidCoreId::new("ak:did_core:web:station.example").unwrap(),
        ))
    }

    fn root_ref() -> serde_json::Value {
        serde_json::json!({
            "kind":"realm_root",
            "realm_id":REALM_ID,
            "authority_event_ref":arkret_wire::EventId::from_digest(
                arkret_canonical::DigestSuite::Sha256,
                [0x55; 32],
            ),
            "authority_generation":"0"
        })
    }

    fn grant(actions: &[&str]) -> CapabilityGrant {
        serde_json::from_value(serde_json::json!({
            "id": GRANT_ID,
            "schema": "ak.schema.capability.v1",
            "realm_id": REALM_ID,
            "issuer_id": actor(),
            "subject": actor(),
            "actions": actions,
            "resources": [{"kind":"realm", "realm_id":REALM_ID}],
            "issuer_authority_refs": [root_ref()],
            "authority_depth": 1,
            "authority_root_refs": [root_ref()],
            "issued_at": "2026-09-21T00:00:00.000Z",
            "status": "active"
        }))
        .unwrap()
    }

    fn authorization(
        root_controller: bool,
        grants: Vec<CapabilityGrant>,
    ) -> ActorRealmAuthorization {
        ActorRealmAuthorization {
            realm_id: REALM_ID.parse().unwrap(),
            actor: actor(),
            evaluated_at: chrono::Utc::now(),
            root_controller,
            agent_ceiling: None,
            grants: grants
                .into_iter()
                .map(|grant| EffectiveActorGrant {
                    grant,
                    revision: arkret_wire::CurrentRevision {
                        commit_id: "ak:realm_commit:ARNRmzDi2r78zveOLmoHOb6AephFMwVuGE1fwXmCoeo4"
                            .parse()
                            .unwrap(),
                        stream_position: 3,
                    },
                })
                .collect(),
        }
    }

    fn realm() -> WireResourceSelector {
        WireResourceSelector::realm(REALM_ID.parse().unwrap())
    }

    #[test]
    fn a_covering_grant_is_named_by_the_verdict() {
        let verdict = evaluate(
            &authorization(false, vec![grant(&[CapabilityActionId::REALM_ADMIN])]),
            &[CapabilityActionId::REALM_ADMIN],
            &realm(),
            &OperationFacts::default(),
        );
        let CapabilityVerdict::Granted(grants) = verdict else {
            panic!("expected a granted verdict");
        };
        assert_eq!(grants[0].grant.id.as_str(), GRANT_ID);
    }

    #[test]
    fn the_owner_aggregate_covers_event_actions_but_not_self_actions() {
        let root = authorization(true, Vec::new());
        assert!(matches!(
            evaluate(
                &root,
                &[CapabilityActionId::MESSAGE_CREATE],
                &realm(),
                &OperationFacts::default()
            ),
            CapabilityVerdict::RealmOwner
        ));
        assert!(matches!(
            evaluate(
                &root,
                &[CapabilityActionId::SELF_AGENT_SIDECAR_COMMAND_ENSURE_V1],
                &realm(),
                &OperationFacts::default()
            ),
            CapabilityVerdict::Denied
        ));
        let co_owner = authorization(false, vec![grant(&[CapabilityActionId::REALM_OWNER])]);
        assert!(
            evaluate(
                &co_owner,
                &[CapabilityActionId::REALM_ADMIN],
                &realm(),
                &OperationFacts::default()
            )
            .allowed()
        );
    }

    #[test]
    fn nothing_authorizes_an_actor_without_root_or_grant() {
        assert!(matches!(
            evaluate(
                &authorization(false, Vec::new()),
                &[CapabilityActionId::REALM_ADMIN],
                &realm(),
                &OperationFacts::default()
            ),
            CapabilityVerdict::Denied
        ));
    }

    #[test]
    fn service_verdict_does_not_restore_an_agent_owner_after_controller_rights_disappear() {
        let mut agent = authorization(true, vec![grant(&[CapabilityActionId::MESSAGE_CREATE])]);
        let mut controller = authorization(false, Vec::new());
        controller.actor = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            "ak:did_core:web:controller.example".parse().unwrap(),
            "ak:did_core:web:station.example".parse().unwrap(),
        ));
        agent.agent_ceiling = Some(coland_storage::AgentControllerCeiling {
            controller: Box::new(controller),
            management_policies: Vec::new(),
        });
        let actions = [CapabilityActionId::MESSAGE_CREATE];
        assert!(!evaluate(&agent, &actions, &realm(), &OperationFacts::default()).allowed());
        agent
            .agent_ceiling
            .as_mut()
            .unwrap()
            .controller
            .root_controller = true;
        assert!(matches!(
            evaluate(&agent, &actions, &realm(), &OperationFacts::default()),
            CapabilityVerdict::Granted(_)
        ));
    }
}
