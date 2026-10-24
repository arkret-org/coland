use arkret_wire::{ActorId, WireResourceSelector};
use coland_storage::OperationFacts;
use serde_json::json;

use super::*;

#[test]
fn publish_uses_exact_controller_exceptions_and_is_independent_of_serve() {
    let publish = |policies: &[Policy], controller: &AccountId, agent: &AccountId| {
        require_realm_intent(
            policies,
            &realm(),
            controller,
            agent,
            chrono::Utc::now(),
            AgentPolicyOperation::Publish,
        )
    };
    assert!(publish(&[], &account("controller"), &account("agent")).is_ok());
    let restriction = policy(None, vec!["publish"], "deny");
    assert!(
        publish(
            &[restriction.clone()],
            &account("controller"),
            &account("agent")
        )
        .is_err()
    );
    assert!(publish(&[restriction], &account("other"), &account("agent")).is_ok());
    let mut exception = policy(None, vec!["publish"], "allow");
    exception.default_effect = PolicyEffect::Deny;
    assert!(
        publish(
            &[exception.clone()],
            &account("controller"),
            &account("agent")
        )
        .is_ok()
    );
    let mut foreign = account("controller");
    foreign.station_id = "ak:did_core:web:other-station.example".parse().unwrap();
    assert!(publish(&[exception], &foreign, &account("agent")).is_err());
    assert!(
        publish(
            &[policy(None, vec!["serve", "join"], "deny")],
            &account("controller"),
            &account("agent")
        )
        .is_ok()
    );
    for effect in ["require_review", "quarantine"] {
        let mut restriction = policy(None, vec!["publish"], effect);
        if effect == "require_review" {
            restriction.rules[0].review_requirement = Some(arkret_models_collaboration::governance::operation_wire::ManagementReviewRequirement {
                approver_actor_ids: vec![ActorId::account(account("controller"))],
                threshold: 1,
                max_age_seconds: 60,
            });
        }
        restriction.validate().unwrap();
        assert!(publish(&[restriction], &account("controller"), &account("agent")).is_err());
    }
}

fn account(name: &str) -> AccountId {
    AccountId::new(
        format!("ak:did_core:web:{name}.example").parse().unwrap(),
        "ak:did_core:web:station.example".parse().unwrap(),
    )
}

fn realm() -> RealmId {
    "ak:realm:AT47eNekH0_aKZyIMsXq_s1FAWdYXC71_CUxQ5O478t-"
        .parse()
        .unwrap()
}

fn policy(actions: Option<Vec<&str>>, operations: Vec<&str>, effect: &str) -> Policy {
    let mut rule = json!({"rule_id":"restriction","kind":"agent","agent_target":{"kind":"controller","controller_account_id":account("controller")},"agent_operations":operations,"effect":effect});
    if let Some(actions) = actions {
        rule["actions"] = json!(actions);
    }
    serde_json::from_value(json!({"schema":"ak.schema.policy.v1","id":"ak:policy:0198ff00-0000-7000-8000-000000000001","realm_id":realm(),"policy_kind":"agent","rules":[rule],"default_effect":"allow","created_by":ActorId::account(account("controller")),"created_at":"2026-10-05T12:00:00.000Z"})).unwrap()
}

fn check(
    policies: &[Policy],
    actions: &[&str],
    facts: &OperationFacts,
) -> PersistenceResult<Vec<String>> {
    let realm = realm();
    let actor = ActorId::account(account("agent"));
    let target = WireResourceSelector::realm(realm.clone());
    let operation = AuthorizationOperation {
        actor: &actor,
        actions,
        target: &target,
        at: chrono::Utc::now(),
        facts,
    };
    executable_actions(
        policies,
        &realm,
        &account("controller"),
        &account("agent"),
        &operation,
        &execution_event(arkret_wire::ScopeRef::Realm {
            realm_id: realm.clone(),
        }),
    )
    .map(|actions| actions.into_iter().map(str::to_owned).collect())
}

#[test]
fn denied_action_is_removed_before_alternative_grant_evaluation() {
    let policies = [policy(
        Some(vec!["ak.message.create"]),
        vec!["execute"],
        "deny",
    )];
    assert_eq!(
        check(
            &policies,
            &["ak.message.create", "ak.reaction.add", "ak.realm.owner"],
            &OperationFacts::default()
        )
        .unwrap(),
        ["ak.reaction.add"]
    );
    assert!(
        check(
            &policies,
            &["ak.message.create", "ak.realm.owner"],
            &OperationFacts::default()
        )
        .unwrap()
        .is_empty()
    );
}

#[test]
fn join_only_ban_does_not_stop_existing_execution() {
    let policies = [policy(None, vec!["join", "authorize"], "deny")];
    assert_eq!(
        check(
            &policies,
            &["ak.message.create"],
            &OperationFacts::default()
        )
        .unwrap(),
        ["ak.message.create"]
    );
    assert_eq!(
        check(
            &[],
            &["ak.message.create", "ak.realm.owner"],
            &OperationFacts::default()
        )
        .unwrap(),
        ["ak.message.create", "ak.realm.owner"]
    );
    assert!(check(&[], &["ak.realm.owner"], &OperationFacts::default()).is_err());
}

#[test]
fn scoped_ban_matches_actual_strand_but_not_navigation_ancestry() {
    let strand = "ak:strand:AT47eNekH0_aKZyIMsXq_s1FAWdYXC71_CUxQ5O478t-";
    let mut policy = policy(None, vec!["execute"], "deny");
    policy.rules[0].resources = Some(vec![PolicyResourceSelector {
        kind: PolicyResourceKind::Strand,
        realm_id: Some(realm()),
        resource_ref: Some(strand.to_owned()),
    }]);
    assert!(
        check(
            &[policy.clone()],
            &["ak.message.create"],
            &OperationFacts {
                strand_id: Some(strand.to_owned()),
                ..OperationFacts::default()
            }
        )
        .unwrap()
        .is_empty()
    );
    let other = arkret_wire::StrandId::from_event_id(&arkret_wire::EventId::from_digest(
        arkret_canonical::DigestSuite::Sha256,
        [74; 32],
    ));
    assert!(
        check(
            &[policy],
            &["ak.message.create"],
            &OperationFacts {
                strand_id: Some(other.to_string()),
                ..OperationFacts::default()
            }
        )
        .is_ok()
    );
}

#[test]
fn unresolved_object_review_and_unknown_action_fail_closed() {
    for effect in ["quarantine", "require_review"] {
        assert!(
            check(
                &[policy(None, vec!["execute"], effect)],
                &["ak.message.create"],
                &OperationFacts::default()
            )
            .is_err()
        );
    }
    assert!(
        check(
            &[],
            &["not-a-registered-action"],
            &OperationFacts::default()
        )
        .is_err()
    );
    let mut policy = policy(None, vec!["execute"], "deny");
    policy.rules[0].resources = Some(vec![PolicyResourceSelector {
        kind: PolicyResourceKind::Object,
        realm_id: Some(realm()),
        resource_ref: Some("object".to_owned()),
    }]);
    assert!(
        check(
            &[policy],
            &["ak.message.create"],
            &OperationFacts::default()
        )
        .is_err()
    );
}

#[test]
fn denied_ordinary_action_does_not_preempt_a_separately_allowed_own_path() {
    let policies = [policy(
        Some(vec!["ak.message.revise"]),
        vec!["execute"],
        "deny",
    )];
    assert!(
        check(
            &policies,
            &["ak.message.revise"],
            &OperationFacts::default()
        )
        .unwrap()
        .is_empty()
    );
    assert_eq!(
        check(
            &policies,
            &["ak.message.revise.own"],
            &OperationFacts::default()
        )
        .unwrap(),
        ["ak.message.revise.own"]
    );
}

#[test]
fn wrong_account_or_realm_and_conflicting_facts_are_rejected() {
    let realm = realm();
    let actor = ActorId::account(account("agent"));
    let target = WireResourceSelector::strand(
        realm.clone(),
        "ak:strand:AT47eNekH0_aKZyIMsXq_s1FAWdYXC71_CUxQ5O478t-"
            .parse()
            .unwrap(),
    );
    let facts = OperationFacts {
        strand_id: Some(
            arkret_wire::StrandId::from_event_id(&arkret_wire::EventId::from_digest(
                arkret_canonical::DigestSuite::Sha256,
                [74; 32],
            ))
            .to_string(),
        ),
        ..OperationFacts::default()
    };
    let operation = AuthorizationOperation {
        actor: &actor,
        actions: &["ak.message.create"],
        target: &target,
        at: chrono::Utc::now(),
        facts: &facts,
    };
    assert!(
        executable_actions(
            &[],
            &realm,
            &account("controller"),
            &account("agent"),
            &operation,
            &execution_event(arkret_wire::ScopeRef::Realm {
                realm_id: realm.clone()
            })
        )
        .is_err()
    );
    assert!(
        executable_actions(
            &[],
            &realm,
            &account("controller"),
            &account("other-agent"),
            &operation,
            &execution_event(arkret_wire::ScopeRef::Realm {
                realm_id: realm.clone()
            })
        )
        .is_err()
    );
    assert!(
        check(
            &[],
            &["ak.message.create"],
            &OperationFacts {
                space_id: Some("invalid".to_owned()),
                ..OperationFacts::default()
            }
        )
        .is_err()
    );
}

fn authorize(policies: &[Policy], actions: &[&str]) -> PersistenceResult<()> {
    require_authorization(
        policies,
        &realm(),
        &account("controller"),
        &account("agent"),
        &actions
            .iter()
            .map(|action| (*action).to_owned())
            .collect::<Vec<_>>(),
        &[WireResourceSelector::realm(realm())],
        chrono::Utc::now(),
    )
}

#[test]
fn authorization_requires_every_requested_action_not_one_alternative() {
    let policies = [policy(
        Some(vec!["ak.message.create"]),
        vec!["authorize"],
        "deny",
    )];
    assert!(authorize(&policies, &["ak.reaction.add"]).is_ok());
    assert!(authorize(&policies, &["ak.reaction.add", "ak.message.create"]).is_err());
    assert!(authorize(&policies, &["ak.realm.owner"]).is_err());
    assert!(authorize(&[], &["ak.realm.owner"]).is_ok());
}

#[test]
fn authorize_ban_is_independent_of_issuer_and_execute_or_join_bans() {
    assert!(
        authorize(
            &[policy(None, vec!["authorize"], "deny")],
            &["ak.message.create"]
        )
        .is_err()
    );
    assert!(
        authorize(
            &[policy(None, vec!["execute", "join"], "deny")],
            &["ak.message.create"]
        )
        .is_ok()
    );
    let mut sibling = policy(None, vec!["authorize"], "deny");
    sibling.rules[0].agent_target = Some(
        serde_json::from_value(json!({"kind":"agent","agent_account_id":account("sibling")}))
            .unwrap(),
    );
    assert!(authorize(&[sibling], &["ak.message.create"]).is_ok());
    for effect in ["require_review", "quarantine"] {
        assert!(
            authorize(
                &[policy(None, vec!["authorize"], effect)],
                &["ak.message.create"]
            )
            .is_err()
        );
    }
}

#[test]
fn broad_authorization_cannot_hide_a_narrow_management_restriction() {
    let mut scoped = policy(None, vec!["authorize"], "deny");
    scoped.rules[0].resources = Some(vec![PolicyResourceSelector {
        kind: PolicyResourceKind::Strand,
        realm_id: Some(realm()),
        resource_ref: Some("ak:strand:AT47eNekH0_aKZyIMsXq_s1FAWdYXC71_CUxQ5O478t-".to_owned()),
    }]);
    assert!(authorize(&[scoped], &["ak.message.create"]).is_err());
    assert!(authorize(&[], &[]).is_err());
    assert!(authorize(&[], &["not-a-registered-action"]).is_err());
}

#[test]
fn join_only_policy_keeps_existing_scoped_and_aggregate_authorization_open() {
    let policies = [policy(None, vec!["join"], "deny")];
    let mut subtree = WireResourceSelector::realm(realm());
    subtree.match_scope = Some(arkret_wire::ResourceMatchScope::Subtree);
    for resource in [
        WireResourceSelector::strand(
            realm(),
            "ak:strand:AT47eNekH0_aKZyIMsXq_s1FAWdYXC71_CUxQ5O478t-"
                .parse()
                .unwrap(),
        ),
        WireResourceSelector::space(
            realm(),
            "ak:space:AT47eNekH0_aKZyIMsXq_s1FAWdYXC71_CUxQ5O478t-"
                .parse()
                .unwrap(),
        ),
        subtree,
    ] {
        for actions in [
            vec!["ak.message.create".to_owned()],
            vec!["ak.realm.owner".to_owned()],
        ] {
            assert!(
                require_authorization(
                    &policies,
                    &realm(),
                    &account("controller"),
                    &account("agent"),
                    &actions,
                    std::slice::from_ref(&resource),
                    chrono::Utc::now(),
                )
                .is_ok()
            );
            let restriction = [policy(None, vec!["authorize"], "deny")];
            assert!(
                require_authorization(
                    &restriction,
                    &realm(),
                    &account("controller"),
                    &account("agent"),
                    &actions,
                    std::slice::from_ref(&resource),
                    chrono::Utc::now(),
                )
                .is_err()
            );
        }
    }
}

#[test]
fn unrestricted_authorization_still_validates_complete_policy_and_identity() {
    let valid = policy(None, vec!["join"], "deny");
    let resource = WireResourceSelector::strand(
        realm(),
        "ak:strand:AT47eNekH0_aKZyIMsXq_s1FAWdYXC71_CUxQ5O478t-"
            .parse()
            .unwrap(),
    );
    let actions = ["ak.message.create".to_owned()];
    let mut invalid = valid.clone();
    invalid.policy_kind = arkret_wire::PolicyKind::Access;
    for policies in [vec![invalid], vec![valid.clone(), valid.clone()]] {
        assert!(
            require_authorization(
                &policies,
                &realm(),
                &account("controller"),
                &account("agent"),
                &actions,
                std::slice::from_ref(&resource),
                chrono::Utc::now(),
            )
            .is_err()
        );
    }
    assert!(
        require_authorization(
            &[valid],
            &realm(),
            &account("agent"),
            &account("agent"),
            &actions,
            &[resource],
            chrono::Utc::now(),
        )
        .is_err()
    );
}

#[test]
fn join_default_requires_distinct_accounts_and_join_ban_does_not_stop_execute() {
    let at = chrono::Utc::now();
    assert!(require_join(&[], &realm(), &account("controller"), &account("agent"), at).is_ok());
    assert!(require_join(&[], &realm(), &account("agent"), &account("agent"), at).is_err());
    let policies = [policy(None, vec!["join"], "deny")];
    assert!(
        require_join(
            &policies,
            &realm(),
            &account("controller"),
            &account("agent"),
            at
        )
        .is_err()
    );
    assert_eq!(
        check(
            &policies,
            &["ak.message.create"],
            &OperationFacts::default()
        )
        .unwrap(),
        ["ak.message.create"]
    );
    assert!(
        require_join(
            &[policy(None, vec!["execute", "authorize"], "deny")],
            &realm(),
            &account("controller"),
            &account("agent"),
            at
        )
        .is_ok()
    );
}

#[test]
fn controller_join_ban_matches_future_agents_and_exact_station_not_sibling_owners() {
    let policies = [policy(None, vec!["join"], "deny")];
    let at = chrono::Utc::now();
    for agent in [account("agent"), account("future-agent")] {
        assert!(require_join(&policies, &realm(), &account("controller"), &agent, at).is_err());
    }
    assert!(
        require_join(
            &policies,
            &realm(),
            &account("other-controller"),
            &account("agent"),
            at
        )
        .is_ok()
    );
    let mut foreign = account("controller");
    foreign.station_id = "ak:did_core:web:other-station.example".parse().unwrap();
    assert!(require_join(&policies, &realm(), &foreign, &account("agent"), at).is_ok());
    let mut specific = policy(None, vec!["join"], "deny");
    specific.rules[0].agent_target = Some(
        serde_json::from_value(json!({"kind":"agent","agent_account_id":account("agent")}))
            .unwrap(),
    );
    assert!(
        require_join(
            &[specific.clone()],
            &realm(),
            &account("controller"),
            &account("agent"),
            at
        )
        .is_err()
    );
    assert!(
        require_join(
            &[specific],
            &realm(),
            &account("controller"),
            &account("sibling"),
            at
        )
        .is_ok()
    );
}

#[test]
fn join_refuses_unmapped_content_scopes_and_unresolved_approval() {
    let at = chrono::Utc::now();
    for effect in ["quarantine", "require_review"] {
        assert!(
            require_join(
                &[policy(None, vec!["join"], effect)],
                &realm(),
                &account("controller"),
                &account("agent"),
                at
            )
            .is_err()
        );
    }
    assert!(
        require_join(
            &[policy(
                Some(vec!["ak.message.create"]),
                vec!["join"],
                "deny"
            )],
            &realm(),
            &account("controller"),
            &account("agent"),
            at
        )
        .is_err()
    );
    let mut scoped = policy(None, vec!["join"], "deny");
    scoped.rules[0].resources = Some(vec![PolicyResourceSelector {
        kind: PolicyResourceKind::Strand,
        realm_id: Some(realm()),
        resource_ref: Some("ak:strand:AT47eNekH0_aKZyIMsXq_s1FAWdYXC71_CUxQ5O478t-".to_owned()),
    }]);
    assert!(
        require_join(
            &[scoped],
            &realm(),
            &account("controller"),
            &account("agent"),
            at
        )
        .is_err()
    );
}

#[test]
fn member_event_read_obeys_read_ban_without_turning_join_or_execute_into_read_bans() {
    let read = |policies: &[Policy]| {
        require_member_event_read(
            policies,
            &realm(),
            &account("controller"),
            &account("agent"),
            chrono::Utc::now(),
        )
    };
    assert!(read(&[]).is_ok());
    assert!(read(&[policy(None, vec!["read"], "deny")]).is_err());
    assert!(
        read(&[policy(
            None,
            vec!["join", "authorize", "execute", "deliver"],
            "deny"
        )])
        .is_ok()
    );
    assert!(read(&[policy(Some(vec!["ak.event.read"]), vec!["read"], "deny")]).is_err());
    assert!(
        read(&[policy(
            Some(vec!["ak.message.create"]),
            vec!["read"],
            "deny"
        )])
        .is_ok()
    );
    for effect in ["quarantine", "require_review"] {
        assert!(read(&[policy(None, vec!["read"], effect)]).is_err());
    }
}

#[test]
fn member_event_read_preserves_full_controller_identity_and_refuses_unresolved_scopes() {
    let at = chrono::Utc::now();
    let policies = [policy(None, vec!["read"], "deny")];
    let mut foreign = account("controller");
    foreign.station_id = "ak:did_core:web:other-station.example".parse().unwrap();
    assert!(
        require_member_event_read(&policies, &realm(), &foreign, &account("agent"), at).is_ok()
    );
    assert!(
        require_member_event_read(&[], &realm(), &account("agent"), &account("agent"), at).is_err()
    );
    let mut scoped = policy(None, vec!["read"], "deny");
    scoped.rules[0].resources = Some(vec![PolicyResourceSelector {
        kind: PolicyResourceKind::Strand,
        realm_id: Some(realm()),
        resource_ref: Some("ak:strand:AT47eNekH0_aKZyIMsXq_s1FAWdYXC71_CUxQ5O478t-".to_owned()),
    }]);
    assert!(
        require_member_event_read(
            &[scoped],
            &realm(),
            &account("controller"),
            &account("agent"),
            at
        )
        .is_err()
    );
}

fn execution_event(scope: arkret_wire::ScopeRef) -> arkret_wire::Event {
    arkret_wire::test_support::raw_event_for_actor_at(
        arkret_wire::EventKind::MessageCreate.as_str(),
        scope,
        ActorId::account(account("agent")),
        json!({}),
        arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now()),
    )
    .unwrap()
}

fn check_signed_execution(
    policies: &[Policy],
    actions: &[&str],
    target: &WireResourceSelector,
    facts: &OperationFacts,
    event: &arkret_wire::Event,
) -> PersistenceResult<Vec<String>> {
    executable_actions(
        policies,
        &realm(),
        &account("controller"),
        &account("agent"),
        &AuthorizationOperation {
            actor: &ActorId::account(account("agent")),
            actions,
            target,
            at: event.created_at,
            facts,
        },
        event,
    )
    .map(|actions| actions.into_iter().map(str::to_owned).collect())
}

#[test]
fn serve_restricts_public_action_paths_and_preserves_private_sidecar_execution() {
    let realm = realm();
    let target = WireResourceSelector::realm(realm.clone());
    let shared = execution_event(arkret_wire::ScopeRef::Realm {
        realm_id: realm.clone(),
    });
    let sidecar = execution_event(arkret_wire::ScopeRef::Sidecar {
        realm_id: realm,
        sidecar_id: arkret_wire::SidecarId::from_event_id(&arkret_wire::EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            [75; 32],
        )),
    });
    let restriction = policy(Some(vec!["ak.message.create"]), vec!["serve"], "deny");
    let actions = ["ak.message.create", "ak.reaction.add", "ak.realm.owner"];
    assert_eq!(
        check_signed_execution(
            &[restriction.clone()],
            &actions,
            &target,
            &OperationFacts::default(),
            &shared
        )
        .unwrap(),
        ["ak.reaction.add"]
    );
    assert_eq!(
        check_signed_execution(
            &[restriction],
            &actions,
            &target,
            &OperationFacts::default(),
            &sidecar
        )
        .unwrap(),
        actions
    );
    let execute = policy(None, vec!["execute"], "deny");
    assert!(
        check_signed_execution(
            &[execute],
            &actions,
            &target,
            &OperationFacts::default(),
            &sidecar
        )
        .unwrap()
        .is_empty()
    );
}

#[test]
fn public_serve_and_execute_are_independent_intersecting_gates() {
    let target = WireResourceSelector::realm(realm());
    let event = execution_event(arkret_wire::ScopeRef::Realm { realm_id: realm() });
    for gates in [vec!["serve"], vec!["execute"]] {
        let restrict = policy(None, gates, "deny");
        assert!(
            check_signed_execution(
                &[restrict],
                &["ak.message.create"],
                &target,
                &OperationFacts::default(),
                &event
            )
            .unwrap()
            .is_empty()
        );
    }
    assert_eq!(
        check_signed_execution(
            &[],
            &["ak.message.create"],
            &target,
            &OperationFacts::default(),
            &event
        )
        .unwrap(),
        ["ak.message.create"]
    );
}

#[test]
fn public_serve_keeps_a_separately_legal_own_action_path() {
    let target = WireResourceSelector::realm(realm());
    let event = execution_event(arkret_wire::ScopeRef::Realm { realm_id: realm() });
    let restrict = policy(Some(vec!["ak.message.revise"]), vec!["serve"], "deny");
    assert_eq!(
        check_signed_execution(
            &[restrict],
            &[
                "ak.message.revise",
                "ak.message.revise.own",
                "ak.realm.owner"
            ],
            &target,
            &OperationFacts::default(),
            &event
        )
        .unwrap(),
        ["ak.message.revise.own"]
    );
}

#[test]
fn public_circle_serve_matches_exact_strand_resource_and_requires_signed_scope_facts() {
    let circle = arkret_wire::CircleId::from_event_id(&arkret_wire::EventId::from_digest(
        arkret_canonical::DigestSuite::Sha256,
        [76; 32],
    ));
    let target = WireResourceSelector::strand(
        realm(),
        arkret_wire::StrandId::from_event_id(&arkret_wire::EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            [77; 32],
        )),
    );
    let event = execution_event(arkret_wire::ScopeRef::Circle {
        realm_id: realm(),
        circle_id: circle.clone(),
    });
    let facts = OperationFacts {
        circle_id: Some(circle.to_string()),
        strand_id: target.strand_id.as_ref().map(ToString::to_string),
        ..OperationFacts::default()
    };
    let mut restrict = policy(None, vec!["serve"], "deny");
    restrict.rules[0].resources = Some(vec![PolicyResourceSelector {
        kind: PolicyResourceKind::Strand,
        realm_id: Some(realm()),
        resource_ref: target.strand_id.as_ref().map(ToString::to_string),
    }]);
    restrict.validate().unwrap();
    assert!(
        check_signed_execution(&[restrict], &["ak.message.create"], &target, &facts, &event)
            .unwrap()
            .is_empty()
    );
    assert!(
        check_signed_execution(
            &[],
            &["ak.message.create"],
            &target,
            &OperationFacts::default(),
            &event
        )
        .is_err()
    );
    let mut wrong = facts;
    wrong.circle_id = Some(
        arkret_wire::CircleId::from_event_id(&arkret_wire::EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            [78; 32],
        ))
        .to_string(),
    );
    assert!(check_signed_execution(&[], &["ak.message.create"], &target, &wrong, &event).is_err());
}

#[test]
fn public_output_classification_preserves_original_private_self_exceptions() {
    let mut event = execution_event(arkret_wire::ScopeRef::Realm { realm_id: realm() });
    for kind in [
        arkret_wire::EventKind::StrandWatchSet,
        arkret_wire::EventKind::ReadCursorAdvance,
        arkret_wire::EventKind::MlsGenesis,
        arkret_wire::EventKind::MlsCommit,
    ] {
        event.kind = kind;
        assert!(!crate::agent_interaction_current_states::requires_shared_public_mode(&event));
    }
    event.kind = arkret_wire::EventKind::MemberState;
    event.payload =
        serde_json::from_value(json!({"member_id":event.actor_id,"membership":"leave"})).unwrap();
    assert!(!crate::agent_interaction_current_states::requires_shared_public_mode(&event));
    event.executed_by = Some(ActorId::account(account("other")));
    assert!(crate::agent_interaction_current_states::requires_shared_public_mode(&event));
}

#[test]
fn unrelated_object_rule_does_not_deny_join_or_publish() {
    let mut unrelated = policy(None, vec!["execute"], "deny");
    unrelated.rules[0].resources = Some(vec![PolicyResourceSelector {
        kind: PolicyResourceKind::Object,
        realm_id: Some(realm()),
        resource_ref: Some("ak:strand:AT47eNekH0_aKZyIMsXq_s1FAWdYXC71_CUxQ5O478t-".into()),
    }]);
    unrelated.validate().unwrap();
    for operation in [AgentPolicyOperation::Join, AgentPolicyOperation::Publish] {
        assert!(
            require_realm_intent(
                &[unrelated.clone()],
                &realm(),
                &account("controller"),
                &account("agent"),
                chrono::Utc::now(),
                operation
            )
            .is_ok()
        );
    }
    unrelated.rules[0].agent_operations = Some(vec![AgentPolicyOperation::Join]);
    assert!(
        require_realm_intent(
            &[unrelated.clone()],
            &realm(),
            &account("controller"),
            &account("agent"),
            chrono::Utc::now(),
            AgentPolicyOperation::Join
        )
        .is_err()
    );
    unrelated.rules[0].agent_target = Some(
        arkret_models_collaboration::governance::operation_wire::AgentPolicyTarget::Agent {
            agent_account_id: account("different-agent"),
        },
    );
    assert!(
        require_realm_intent(
            &[unrelated.clone()],
            &realm(),
            &account("controller"),
            &account("agent"),
            chrono::Utc::now(),
            AgentPolicyOperation::Join
        )
        .is_ok()
    );
    // Filtering never makes malformed whole Policy into valid authority.
    assert!(
        require_realm_intent(
            &[unrelated.clone(), unrelated],
            &realm(),
            &account("controller"),
            &account("agent"),
            chrono::Utc::now(),
            AgentPolicyOperation::Join
        )
        .is_err()
    );
}

#[test]
fn authorization_exact_selectors_and_every_action_preserve_priority_intersection() {
    let exact = WireResourceSelector::strand(
        realm(),
        "ak:strand:AT47eNekH0_aKZyIMsXq_s1FAWdYXC71_CUxQ5O478t-"
            .parse()
            .unwrap(),
    );
    let other = WireResourceSelector::strand(
        realm(),
        arkret_wire::StrandId::from_event_id(&arkret_wire::EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            [74; 32],
        )),
    );
    let mut restriction = policy(Some(vec!["ak.message.create"]), vec!["authorize"], "deny");
    restriction.rules[0].resources = Some(vec![PolicyResourceSelector {
        kind: PolicyResourceKind::Strand,
        realm_id: Some(realm()),
        resource_ref: exact.strand_id.as_ref().map(ToString::to_string),
    }]);
    let run = |policies: &[Policy], actions: &[String], resources: &[WireResourceSelector]| {
        require_authorization(
            policies,
            &realm(),
            &account("controller"),
            &account("agent"),
            actions,
            resources,
            chrono::Utc::now(),
        )
    };
    assert!(
        run(
            &[restriction.clone()],
            &["ak.message.create".into()],
            &[other.clone()]
        )
        .is_ok()
    );
    assert!(
        run(
            &[restriction.clone()],
            &["ak.reaction.add".into()],
            &[exact.clone()]
        )
        .is_ok()
    );
    assert!(
        run(
            &[restriction.clone()],
            &["ak.reaction.add".into(), "ak.message.create".into()],
            &[other.clone(), exact.clone()]
        )
        .is_err()
    );
    let mut allow = restriction.rules[0].clone();
    allow.rule_id = "whole_allow".into();
    allow.effect = PolicyEffect::Allow;
    allow.resources = None;
    allow.priority = restriction.rules[0].priority + 1;
    restriction.rules.push(allow);
    assert!(
        run(
            &[restriction.clone()],
            &["ak.message.create".into()],
            &[WireResourceSelector::realm(realm())]
        )
        .is_ok()
    );
    restriction.rules[1].priority = restriction.rules[0].priority;
    assert!(
        run(
            &[restriction.clone()],
            &["ak.message.create".into()],
            &[WireResourceSelector::realm(realm())]
        )
        .is_err()
    );
    restriction.rules[1].priority += 1;
    let mut parent = policy(None, vec!["authorize"], "deny");
    parent.id = "ak:policy:0198ff00-0000-7000-8000-000000000002"
        .parse()
        .unwrap();
    assert!(
        run(
            &[restriction, parent],
            &["ak.message.create".into()],
            &[exact]
        )
        .is_err()
    );
}

#[test]
fn authorization_default_deny_needs_whole_domain_allow_and_never_current_object_enumeration() {
    let mut p = policy(None, vec!["authorize"], "allow");
    p.default_effect = PolicyEffect::Deny;
    let target = WireResourceSelector::strand(
        realm(),
        "ak:strand:AT47eNekH0_aKZyIMsXq_s1FAWdYXC71_CUxQ5O478t-"
            .parse()
            .unwrap(),
    );
    p.rules[0].resources = Some(vec![PolicyResourceSelector {
        kind: PolicyResourceKind::Strand,
        realm_id: Some(realm()),
        resource_ref: target.strand_id.as_ref().map(ToString::to_string),
    }]);
    let run = |p: &Policy, target: &WireResourceSelector| {
        require_authorization(
            std::slice::from_ref(p),
            &realm(),
            &account("controller"),
            &account("agent"),
            &["ak.message.create".into()],
            std::slice::from_ref(target),
            chrono::Utc::now(),
        )
    };
    assert!(run(&p, &target).is_ok());
    assert!(run(&p, &WireResourceSelector::realm(realm())).is_err());
    p.rules[0].resources.as_mut().unwrap()[0].resource_ref = None;
    let mut all_strands = target.clone();
    all_strands.strand_id = None;
    assert!(run(&p, &all_strands).is_ok());
    assert!(run(&p, &WireResourceSelector::realm(realm())).is_err());
    p.rules[0].resources = None;
    assert!(run(&p, &WireResourceSelector::realm(realm())).is_ok());
    let mut foreign = target;
    foreign.realm_id = Some(arkret_wire::RealmId::from_event_id(
        &arkret_wire::EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [75; 32]),
    ));
    assert!(run(&p, &foreign).is_err());
}

#[test]
fn execution_uses_exact_object_identity_and_does_not_preempt_unrelated_content_action() {
    let raw=arkret_wire::test_support::raw_event_for_actor_at(
        arkret_wire::EventKind::MessageCreate.as_str(), arkret_wire::ScopeRef::Realm {realm_id:realm()},
        ActorId::account(account("agent")), json!({"strand_id":"ak:strand:AT47eNekH0_aKZyIMsXq_s1FAWdYXC71_CUxQ5O478t-","track_name":"main"}),
        arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now())).unwrap();
    let mut restriction = policy(Some(vec!["ak.message.create"]), vec!["execute"], "deny");
    restriction.rules[0].resources = Some(vec![PolicyResourceSelector {
        kind: PolicyResourceKind::Object,
        realm_id: Some(realm()),
        resource_ref: Some(raw.event_id.to_string()),
    }]);
    assert!(
        check_signed_execution(
            &[restriction.clone()],
            &["ak.message.create"],
            &WireResourceSelector::realm(realm()),
            &OperationFacts::default(),
            &raw
        )
        .unwrap()
        .is_empty()
    );
    restriction.rules[0].actions = Some(vec!["ak.reaction.add".into()]);
    assert_eq!(
        check_signed_execution(
            &[restriction],
            &["ak.message.create"],
            &WireResourceSelector::realm(realm()),
            &OperationFacts::default(),
            &raw
        )
        .unwrap(),
        ["ak.message.create"]
    );
}

#[test]
fn authorization_object_effects_unknown_service_and_disabled_policy_remain_closed_or_neutral() {
    let target = WireResourceSelector::strand(
        realm(),
        "ak:strand:AT47eNekH0_aKZyIMsXq_s1FAWdYXC71_CUxQ5O478t-"
            .parse()
            .unwrap(),
    );
    let mut p = policy(Some(vec!["ak.message.create"]), vec!["authorize"], "deny");
    p.rules[0].resources = Some(vec![PolicyResourceSelector {
        kind: PolicyResourceKind::Object,
        realm_id: Some(realm()),
        resource_ref: Some(
            arkret_wire::EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [90; 32])
                .to_string(),
        ),
    }]);
    let run = |p: &Policy| {
        require_authorization(
            std::slice::from_ref(p),
            &realm(),
            &account("controller"),
            &account("agent"),
            &["ak.message.create".into()],
            std::slice::from_ref(&target),
            chrono::Utc::now(),
        )
    };
    assert!(run(&p).is_err()); // A future authored Event may be that exact Object.
    p.expires_at = Some(chrono::Utc::now() - chrono::TimeDelta::seconds(1));
    assert!(run(&p).is_ok());
    p.expires_at = None;
    p.rules[0].resources.as_mut().unwrap()[0].kind = PolicyResourceKind::Service;
    assert!(run(&p).is_err());
    p.rules[0].actions = Some(vec!["ak.reaction.add".into()]);
    assert!(run(&p).is_ok()); // A verified distinct action has no Service rule.
}
