use arkret_wire::{ActorId, WireResourceSelector};
use coland_storage::OperationFacts;
use serde_json::json;

use super::*;

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
            &operation
        )
        .is_err()
    );
    assert!(
        executable_actions(
            &[],
            &realm,
            &account("controller"),
            &account("other-agent"),
            &operation
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
