//! Pure host-cut integration; no native PostgreSQL/HTTP verification is claimed.
use std::sync::Arc;

use arkret_models_collaboration::governance::grant_constraint::{
    AuthorityRootRef, CapabilityGrant, GrantConstraint, GrantConstraintEffect, GrantConstraintKind,
    GrantConstraintScope, GrantConstraintSubkind, IssuerAuthorityRef,
};
use arkret_wire::{
    ActorId, CapabilityActionId, CurrentRevision, EventId, GrantId, RealmId, WireResourceSelector,
};
use chrono::{DateTime, TimeDelta, Utc};

use super::*;

const A: &str = CapabilityActionId::MESSAGE_CREATE;
const B: &str = CapabilityActionId::TYPING_BROADCAST;

fn at(minute: i64) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339("2026-11-01T00:00:00.000Z")
        .unwrap()
        .with_timezone(&Utc)
        + TimeDelta::minutes(minute)
}
fn actor(name: &str) -> ActorId {
    ActorId::account(arkret_wire::AccountId::new(
        format!("ak:did_core:web:{name}.example").parse().unwrap(),
        "ak:did_core:web:station.example".parse().unwrap(),
    ))
}
fn event(seed: u8) -> EventId {
    EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [seed; 32])
}
fn realm() -> RealmId {
    RealmId::from_event_id(&event(180))
}
fn root_source() -> IssuerAuthorityRef {
    IssuerAuthorityRef::RealmRoot {
        realm_id: realm(),
        authority_event_ref: event(181),
        authority_generation: 0,
    }
}
fn temporal(
    effect: GrantConstraintEffect,
    action: Option<&str>,
    from: Option<i64>,
    until: Option<i64>,
) -> GrantConstraint {
    let mut constraint = GrantConstraint::new(GrantConstraintKind::Temporal, effect);
    constraint.applies_to_actions = action.into_iter().map(str::to_owned).collect();
    constraint.not_before = from.map(at);
    constraint.expires_at = until.map(at);
    constraint
}
fn global() -> GrantConstraint {
    temporal(GrantConstraintEffect::Allow, None, None, Some(120))
}
fn grant(
    seed: u8,
    subject: ActorId,
    actions: &[&str],
    constraints: Vec<GrantConstraint>,
) -> CapabilityGrant {
    serde_json::from_value(serde_json::json!({
        "id":GrantId::from_event_id(&event(seed)),"schema":"ak.schema.capability.v1","realm_id":realm(),
        "issuer_id":actor("governor"),"subject":subject,"actions":actions,
        "resources":[WireResourceSelector::realm(realm())],"constraints":constraints,
        "issuer_authority_refs":[root_source()],"authority_depth":1,
        "authority_root_ref":AuthorityRootRef::RealmRoot{realm_id:realm(),authority_event_ref:event(181),authority_generation:0},
        "issued_at":arkret_canonical::format_timestamp_canonical(at(0)),"status":"active"
    })).unwrap()
}
fn cut(rows: Vec<CapabilityGrant>, controller: ActorId) -> Arc<GrantAuthorityCut> {
    let revisions = rows
        .iter()
        .enumerate()
        .map(|(index, grant)| {
            (
                grant.id.clone(),
                CurrentRevision {
                    commit_id: arkret_wire::RealmCommitId::from_digest(
                        arkret_canonical::sha256_bytes(grant.id.as_str().as_bytes()),
                    ),
                    stream_position: index as u64 + 2,
                },
            )
        })
        .collect();
    Arc::new(
        GrantAuthorityCut::new(
            realm(),
            arkret_wire::RealmAuthorityRootValue {
                controller_actor_id: controller,
                controller_epoch: 0,
                authority_generation: 0,
                authority_event_ref: event(181),
            },
            rows.into_iter()
                .map(|grant| (grant.id.clone(), grant))
                .collect(),
            revisions,
        )
        .unwrap(),
    )
}
fn auth(
    subject: ActorId,
    cut: Arc<GrantAuthorityCut>,
    views: Vec<GrantId>,
) -> ActorRealmAuthorization {
    ActorRealmAuthorization::from_source_cut(subject, at(30), cut, views, None).unwrap()
}
fn evaluate<'a>(
    auth: &'a ActorRealmAuthorization,
    actions: &'a [&'a str],
    target: &'a WireResourceSelector,
    facts: &'a crate::OperationFacts,
) -> crate::GrantEvaluation<'a> {
    auth.evaluate(actions, target, facts)
}

#[test]
fn realm_actor_audit_target_binds_the_complete_identity_without_extra_realm_field() {
    let target_actor = ActorId::realm(arkret_wire::RealmActorId::new(
        realm(),
        "ak:did_core:webvh:z6mkghost:ghost.example".parse().unwrap(),
    ));
    let target = WireResourceSelector::realm_actor(target_actor.clone()).unwrap();
    assert!(target.realm_id.is_none());
    let actions = [CapabilityActionId::REALM_ACTOR_AUDIT];
    let facts = crate::OperationFacts::default();
    let mut allowed = grant(230, actor("holder"), &actions, vec![global()]);
    allowed.resources = vec![target.clone()];
    let authorization = auth(
        actor("holder"),
        cut(vec![allowed.clone()], actor("governor")),
        vec![allowed.id.clone()],
    );
    assert!(
        !evaluate(&authorization, &actions, &target, &facts)
            .unreserved()
            .is_empty()
    );

    let other_actor = ActorId::realm(arkret_wire::RealmActorId::new(
        realm(),
        "ak:did_core:webvh:z6mkother:other.example".parse().unwrap(),
    ));
    let other = WireResourceSelector::realm_actor(other_actor).unwrap();
    assert!(
        evaluate(&authorization, &actions, &other, &facts)
            .unreserved()
            .is_empty()
    );
    let mut foreign_actor = target_actor;
    let ActorId::Realm { realm_actor_id } = &mut foreign_actor else {
        unreachable!()
    };
    realm_actor_id.realm_id = RealmId::from_event_id(&event(231));
    let foreign = WireResourceSelector::realm_actor(foreign_actor).unwrap();
    assert!(
        authorization
            .evaluate_with_approvals_checked(&actions, &foreign, &facts, &[])
            .is_err()
    );

    let mut extra_realm = target.clone();
    extra_realm.realm_id = Some(realm());
    let mut wrong_kind = target.clone();
    wrong_kind.kind = arkret_wire::ResourceSelectorKind::Realm;
    let mut account_target = target.clone();
    account_target.actor_id = Some(arkret_wire::ResourceActorId::Realm(actor("holder")));
    for malformed in [extra_realm, wrong_kind, account_target] {
        assert!(malformed.validate().is_err());
        assert!(
            authorization
                .evaluate_with_approvals_checked(&actions, &malformed, &facts, &[])
                .is_err()
        );
    }

    let empty = auth(
        actor("holder"),
        cut(Vec::new(), actor("governor")),
        Vec::new(),
    );
    assert!(
        evaluate(&empty, &actions, &target, &facts)
            .unreserved()
            .is_empty()
    );
    let mut manage = allowed;
    manage.actions = vec![CapabilityActionId::REALM_ACTOR_MANAGE.to_owned()];
    let manage = auth(
        actor("holder"),
        cut(vec![manage.clone()], actor("governor")),
        vec![manage.id],
    );
    assert!(
        evaluate(&manage, &actions, &target, &facts)
            .unreserved()
            .is_empty()
    );
    let mut positive = grant(232, actor("holder"), &actions, vec![global()]);
    positive.resources = vec![target.clone()];
    let mut refusal = grant(
        233,
        actor("holder"),
        &actions,
        vec![temporal(
            GrantConstraintEffect::Deny,
            Some(CapabilityActionId::REALM_ACTOR_AUDIT),
            Some(0),
            None,
        )],
    );
    refusal.resources = vec![target.clone()];
    let denied = auth(
        actor("holder"),
        cut(vec![positive.clone(), refusal], actor("governor")),
        vec![positive.id],
    );
    assert!(matches!(
        evaluate(&denied, &actions, &target, &facts),
        crate::GrantEvaluation::Denied
    ));
}

#[test]
fn display_selection_and_terminal_allow_failure_never_delete_current_refusals() {
    let target = WireResourceSelector::realm(realm());
    let facts = crate::OperationFacts::default();
    for (effect, expected) in [
        (GrantConstraintEffect::Deny, 0),
        (GrantConstraintEffect::Quarantine, 1),
        (GrantConstraintEffect::RequireReview, 2),
    ] {
        let positive = grant(182, actor("holder"), &[A], vec![global()]);
        let refusal = grant(
            183,
            actor("holder"),
            &[A],
            vec![
                global(),
                temporal(effect, Some(A), Some(0), None),
                temporal(GrantConstraintEffect::Allow, Some(A), Some(60), None),
            ],
        );
        let context = auth(
            actor("holder"),
            cut(vec![positive.clone(), refusal], actor("governor")),
            vec![positive.id],
        );
        assert_eq!(
            context.grants.len(),
            1,
            "the omitted row is disclosure selection only"
        );
        match (expected, evaluate(&context, &[A], &target, &facts)) {
            (0, crate::GrantEvaluation::Denied)
            | (1, crate::GrantEvaluation::Quarantined)
            | (2, crate::GrantEvaluation::RequiresReview) => {}
            (_, other) => panic!("terminal allow or hidden view row erased {effect:?}: {other:?}"),
        }
    }
}

#[test]
fn an_expired_real_parent_closes_child_refusals_but_not_its_own_terminal_refusal() {
    let parent = grant(
        184,
        actor("delegate"),
        &[A],
        vec![
            global(),
            temporal(GrantConstraintEffect::Allow, Some(A), None, Some(20)),
            temporal(GrantConstraintEffect::Deny, Some(A), Some(0), None),
            GrantConstraint::authority_control(1, true),
        ],
    );
    let mut child = grant(
        185,
        actor("holder"),
        &[A],
        vec![
            global(),
            parent.constraints[1].clone(),
            parent.constraints[2].clone(),
            GrantConstraint::authority_control(0, false),
        ],
    );
    child.issuer_id = actor("delegate");
    child.authority_depth = 2;
    child.issuer_authority_refs = vec![IssuerAuthorityRef::Grant {
        grant_id: parent.id.clone(),
    }];
    let positive = grant(182, actor("holder"), &[A], vec![global()]);
    let source = cut(
        vec![parent.clone(), child.clone(), positive.clone()],
        actor("governor"),
    );
    let holder = auth(
        actor("holder"),
        Arc::clone(&source),
        vec![child.id, positive.id],
    );
    let delegate = auth(actor("delegate"), source, vec![parent.id]);
    let target = WireResourceSelector::realm(realm());
    let facts = crate::OperationFacts::default();
    assert!(matches!(
        evaluate(&holder, &[A], &target, &facts),
        crate::GrantEvaluation::Allowed(_)
    ));
    assert!(matches!(
        evaluate(&delegate, &[A], &target, &facts),
        crate::GrantEvaluation::Denied
    ));
}

#[test]
fn alternative_actions_never_recombine_an_inactive_axis_from_a_candidate_union() {
    let parent_a = grant(
        184,
        actor("delegate"),
        &[A],
        vec![global(), GrantConstraint::authority_control(1, true)],
    );
    let parent_b = grant(
        186,
        actor("delegate"),
        &[B],
        vec![
            global(),
            temporal(GrantConstraintEffect::Allow, Some(B), None, Some(20)),
            temporal(GrantConstraintEffect::Deny, Some(B), Some(0), None),
            GrantConstraint::authority_control(1, true),
        ],
    );
    let mut child = grant(
        185,
        actor("holder"),
        &[A, B],
        vec![
            global(),
            parent_b.constraints[1].clone(),
            parent_b.constraints[2].clone(),
            GrantConstraint::authority_control(0, false),
        ],
    );
    child.issuer_id = actor("delegate");
    child.authority_depth = 2;
    child.issuer_authority_refs = vec![
        IssuerAuthorityRef::Grant {
            grant_id: parent_a.id.clone(),
        },
        IssuerAuthorityRef::Grant {
            grant_id: parent_b.id.clone(),
        },
    ];
    let source = cut(vec![parent_a, parent_b, child.clone()], actor("governor"));
    let context = auth(actor("holder"), source, vec![child.id]);
    let target = WireResourceSelector::realm(realm());
    let facts = crate::OperationFacts::default();
    let both = [A, B];
    let reverse = [B, A];
    for actions in [&both[..], &reverse[..]] {
        assert!(matches!(
            evaluate(&context, actions, &target, &facts),
            crate::GrantEvaluation::Allowed(_)
        ));
    }
}

#[test]
fn one_source_budget_is_not_duplicated_or_anded_across_authorization_alternatives() {
    let mut quota = GrantConstraint::new(GrantConstraintKind::Quota, GrantConstraintEffect::Allow);
    quota.constraint_subkind = Some(GrantConstraintSubkind::Rate);
    quota.constraint_id = Some("shared-budget".into());
    quota.max_operation_count = Some(1);
    quota.period = Some("PT1M".into());
    quota.constraint_scope = Some(GrantConstraintScope::PerActor);
    let source = grant(
        182,
        actor("holder"),
        &[A, B],
        vec![
            global(),
            quota,
            temporal(GrantConstraintEffect::Allow, Some(B), Some(60), None),
        ],
    );
    let context = auth(
        actor("holder"),
        cut(vec![source.clone()], actor("governor")),
        vec![source.id.clone()],
    );
    let target = WireResourceSelector::realm(realm());
    let facts = crate::OperationFacts::default();
    let single = [A];
    let both = [A, B];
    let crate::GrantEvaluation::Allowed(one) = evaluate(&context, &single, &target, &facts) else {
        panic!("one actual source owes one quota")
    };
    let crate::GrantEvaluation::Allowed(many) = evaluate(&context, &both, &target, &facts) else {
        panic!("an unavailable alternative cannot become an AND requirement")
    };
    assert_eq!(many.len(), 1);
    assert_eq!(many[0].reservations.len(), 1);
    assert_eq!(one[0].reservations.len(), 1);
    let identity = |reservation: &crate::QuotaReservation| {
        (
            reservation.grant_id.clone(),
            reservation.constraint_key.clone(),
            reservation.counter_key.clone(),
            reservation.window_id,
        )
    };
    assert_eq!(
        identity(&one[0].reservations[0]),
        identity(&many[0].reservations[0])
    );
    assert_eq!(many[0].grant.id, source.id);
    // With both alternatives available, the same original source/counter is
    // still chosen once, with the SDK's original alternative choice.
    let context = ActorRealmAuthorization::from_source_cut(
        actor("holder"),
        at(70),
        Arc::clone(context.source_cut()),
        vec![source.id.clone()],
        None,
    )
    .unwrap();
    let crate::GrantEvaluation::Allowed(one) = evaluate(&context, &single, &target, &facts) else {
        panic!("the source budget is still required")
    };
    let crate::GrantEvaluation::Allowed(many) = evaluate(&context, &both, &target, &facts) else {
        panic!("the source remains usable")
    };
    assert_eq!(many.len(), 1);
    assert_eq!(many[0].reservations.len(), 1);
    assert_eq!(
        identity(&one[0].reservations[0]),
        identity(&many[0].reservations[0])
    );
}

#[test]
fn positive_path_order_and_controller_alternatives_match_the_original_sdk() {
    let quota = |name: &str| {
        let mut constraint =
            GrantConstraint::new(GrantConstraintKind::Quota, GrantConstraintEffect::Allow);
        constraint.constraint_subkind = Some(GrantConstraintSubkind::Rate);
        constraint.constraint_id = Some(name.into());
        constraint.max_operation_count = Some(1);
        constraint.period = Some("PT1M".into());
        constraint.constraint_scope = Some(GrantConstraintScope::PerActor);
        constraint
    };
    let mut rows = [
        grant(182, actor("holder"), &[A, B], vec![global()]),
        grant(183, actor("holder"), &[A, B], vec![global()]),
    ];
    rows.sort_by(|left, right| left.id.cmp(&right.id));
    rows[0]
        .constraints
        .extend([quota("first"), quota("second")]);
    rows[1].constraints.push(quota("only"));
    let context = auth(
        actor("holder"),
        cut(rows.to_vec(), actor("governor")),
        Vec::new(),
    );
    let target = WireResourceSelector::realm(realm());
    let facts = crate::OperationFacts::default();
    let actions = [A, B];
    let operation = crate::AuthorizationOperation {
        actor: &context.actor,
        actions: &actions,
        target: &target,
        at: context.evaluated_at,
        facts: &facts,
    };
    let crate::GrantEvaluation::Allowed(expected) = crate::evaluate_grants_with_verified_approvals(
        &operation,
        context.source_cut.grants.values(),
        &[],
    ) else {
        panic!("both ordinary alternatives allow")
    };
    let crate::GrantEvaluation::Allowed(actual) = evaluate(&context, &actions, &target, &facts)
    else {
        panic!("both ordinary alternatives allow")
    };
    let identity =
        |path: &crate::SatisfiedGrant<'_>| (path.grant.id.clone(), path.reservations.clone());
    assert_eq!(
        actual.iter().map(identity).collect::<Vec<_>>(),
        expected.iter().map(identity).collect::<Vec<_>>()
    );
    assert_eq!(
        actual[0].reservations.len(),
        2,
        "nonempty quota count is not a new preference"
    );

    let agent_grant = grant(184, actor("agent"), &[A, B], vec![global()]);
    let first = grant(
        185,
        actor("controller"),
        &[A, B],
        vec![global(), quota("parent-one")],
    );
    let second = grant(
        186,
        actor("controller"),
        &[A, B],
        vec![global(), quota("parent-two")],
    );
    let source = cut(
        vec![agent_grant.clone(), first.clone(), second.clone()],
        actor("governor"),
    );
    let controller = auth(actor("controller"), Arc::clone(&source), Vec::new());
    let mut agent = auth(actor("agent"), source, Vec::new());
    let operation = crate::AuthorizationOperation {
        actor: &agent.actor,
        actions: &actions,
        target: &target,
        at: agent.evaluated_at,
        facts: &facts,
    };
    let crate::GrantEvaluation::Allowed(expected) = crate::evaluate_controller_bounded_grants(
        &operation,
        &[&agent_grant],
        &controller.actor,
        &[&first, &second],
        &[],
        false,
    ) else {
        panic!("both original controller sources allow")
    };
    let mut unique = Vec::new();
    for path in expected {
        let key = identity(&path);
        if !unique.contains(&key) {
            unique.push(key);
        }
    }
    agent.agent_ceiling = Some(AgentControllerCeiling {
        controller: Box::new(controller),
        management_policies: Vec::new(),
    });
    let crate::GrantEvaluation::Allowed(actual) = evaluate(&agent, &actions, &target, &facts)
    else {
        panic!("both current controller sources allow")
    };
    assert_eq!(
        actual.len(),
        2,
        "different parent counters remain OR alternatives"
    );
    assert_eq!(actual.iter().map(identity).collect::<Vec<_>>(), unique);
}

#[test]
fn controller_bound_cut_is_shared_and_unknown_sources_cannot_restore_implicit_owner() {
    let agent_grant = grant(182, actor("agent"), &[A], vec![global()]);
    let mut controller_grant = grant(
        185,
        actor("controller"),
        &[A],
        vec![global(), GrantConstraint::authority_control(0, false)],
    );
    controller_grant.issuer_id = actor("delegate");
    controller_grant.authority_depth = 2;
    controller_grant.issuer_authority_refs = vec![IssuerAuthorityRef::Grant {
        grant_id: GrantId::from_event_id(&event(199)),
    }];
    let source = cut(
        vec![agent_grant.clone(), controller_grant.clone()],
        actor("controller"),
    );
    let controller = auth(
        actor("controller"),
        Arc::clone(&source),
        vec![controller_grant.id],
    );
    let mut agent = auth(actor("agent"), source, vec![agent_grant.id.clone()]);
    assert!(controller.root_controller());
    agent.agent_ceiling = Some(AgentControllerCeiling {
        controller: Box::new(controller),
        management_policies: Vec::new(),
    });
    let target = WireResourceSelector::realm(realm());
    let facts = crate::OperationFacts::default();
    assert!(matches!(
        evaluate(&agent, &[A], &target, &facts),
        crate::GrantEvaluation::Denied
    ));
    assert!(
        matches!(agent.evaluate_with_approvals_checked(&[A],&target,&facts,&[]),
        Err(PersistenceError::Conflict(detail)) if detail.starts_with("revision_unavailable:"))
    );
    let first = cut(vec![agent_grant.clone()], actor("controller"));
    let second = cut(vec![agent_grant.clone()], actor("controller"));
    let controller = auth(actor("controller"), second, Vec::new());
    let mut agent = auth(actor("agent"), first, vec![agent_grant.id]);
    agent.agent_ceiling = Some(AgentControllerCeiling {
        controller: Box::new(controller),
        management_policies: Vec::new(),
    });
    assert!(matches!(
        evaluate(&agent, &[A], &target, &facts),
        crate::GrantEvaluation::Denied
    ));
}

#[test]
fn an_inapplicable_own_alternative_is_not_an_extra_and_or_global_denial() {
    let agent_grant = grant(182, actor("agent"), &[A], vec![global()]);
    let source = cut(vec![agent_grant.clone()], actor("controller"));
    let controller = auth(actor("controller"), Arc::clone(&source), Vec::new());
    let mut agent = auth(actor("agent"), source, vec![agent_grant.id]);
    agent.agent_ceiling = Some(AgentControllerCeiling {
        controller: Box::new(controller),
        management_policies: Vec::new(),
    });
    let target = WireResourceSelector::realm(realm());
    let facts = crate::OperationFacts::default();
    let alternatives = [CapabilityActionId::MESSAGE_REDACT_OWN, A];
    assert!(matches!(
        evaluate(&agent, &alternatives, &target, &facts),
        crate::GrantEvaluation::Allowed(_)
    ));
}

#[test]
fn refusal_priority_spans_every_actual_axis_before_any_positive_path() {
    let target = WireResourceSelector::realm(realm());
    let facts = crate::OperationFacts::default();
    for (left, right, expected) in [
        (
            GrantConstraintEffect::RequireReview,
            GrantConstraintEffect::Deny,
            0,
        ),
        (
            GrantConstraintEffect::Quarantine,
            GrantConstraintEffect::RequireReview,
            1,
        ),
        (
            GrantConstraintEffect::Deny,
            GrantConstraintEffect::Quarantine,
            0,
        ),
    ] {
        let positive = grant(182, actor("holder"), &[A, B], vec![global()]);
        let first = grant(
            183,
            actor("holder"),
            &[A],
            vec![global(), temporal(left, Some(A), Some(0), None)],
        );
        let second = grant(
            184,
            actor("holder"),
            &[B],
            vec![global(), temporal(right, Some(B), Some(0), None)],
        );
        let context = auth(
            actor("holder"),
            cut(vec![positive.clone(), first, second], actor("governor")),
            vec![positive.id],
        );
        let forward = [A, B];
        let backward = [B, A];
        for actions in [&forward[..], &backward[..]] {
            match (expected, evaluate(&context, actions, &target, &facts)) {
                (0, crate::GrantEvaluation::Denied) | (1, crate::GrantEvaluation::Quarantined) => {}
                (_, other) => panic!(
                    "an authorization alternative changed global refusal priority: {other:?}"
                ),
            }
        }
    }
}

#[test]
fn native_source_layer_does_not_pretend_to_discharge_real_management_policy() {
    let agent_grant = grant(182, actor("agent"), &[A], vec![global()]);
    let source = cut(vec![agent_grant.clone()], actor("controller"));
    let controller = auth(actor("controller"), Arc::clone(&source), Vec::new());
    let mut agent = auth(actor("agent"), source, vec![agent_grant.id]);
    let policy=serde_json::from_value(serde_json::json!({
        "id":"ak:policy:0198ff00-0000-7000-8000-000000000001","schema":"ak.schema.policy.v1",
        "realm_id":realm(),"policy_kind":"agent","rules":[{"rule_id":"no_execute","kind":"agent","effect":"deny",
        "priority":1,"agent_target":{"kind":"all"},"agent_operations":["execute"]}],
        "default_effect":"allow","created_by":actor("controller"),"created_at":arkret_canonical::format_timestamp_canonical(at(0))
    })).unwrap();
    agent.agent_ceiling = Some(AgentControllerCeiling {
        controller: Box::new(controller),
        management_policies: vec![policy],
    });
    let target = WireResourceSelector::realm(realm());
    let facts = crate::OperationFacts::default();
    let actions = [A];
    assert!(!matches!(
        agent
            .evaluate_with_approvals_checked(&actions, &target, &facts, &[])
            .unwrap(),
        crate::GrantEvaluation::Allowed(_)
    ));
    assert!(matches!(
        agent
            .evaluate_grant_sources_with_approvals_checked(&actions, &target, &facts, &[])
            .unwrap(),
        crate::GrantEvaluation::Allowed(_)
    ));
    assert_eq!(
        agent
            .agent_ceiling
            .as_ref()
            .unwrap()
            .management_policies
            .len(),
        1
    );
}

#[test]
fn ordinary_and_owned_current_windows_match_the_real_sdk_local_temporal_boundaries() {
    let skew = TimeDelta::milliseconds(
        arkret_identifiers::protocol_time_tolerance_scenario_descriptor(
            arkret_identifiers::ProtocolTimeToleranceScenario::TemporalConstraint,
        )
        .tolerance_ms(),
    );
    let subject = actor("agent");
    let controller = actor("controller");
    let target = WireResourceSelector::realm(realm());
    let facts = crate::OperationFacts::default();
    for owned in [false, true] {
        for (from, until, time, expected) in [
            (Some(60), None, at(60) - skew, true),
            (
                Some(60),
                None,
                at(60) - skew - TimeDelta::milliseconds(1),
                false,
            ),
            (None, Some(60), at(60) + skew, true),
            (
                None,
                Some(60),
                at(60) + skew + TimeDelta::milliseconds(1),
                false,
            ),
        ] {
            let mut source = grant(
                190,
                subject.clone(),
                &[A],
                vec![
                    global(),
                    temporal(GrantConstraintEffect::Allow, Some(A), from, until),
                    GrantConstraint::authority_control(0, false),
                ],
            );
            let owned_source = if owned {
                let controller_account_id = controller.as_account_id().unwrap().clone();
                let reference = IssuerAuthorityRef::OwnedAgent {
                    realm_id: realm(),
                    controller_account_id: controller_account_id.clone(),
                    controller_join_event_id: event(191),
                    agent_join_event_id: event(192),
                };
                source.issuer_id = controller.clone();
                source.issuer_authority_refs = vec![reference.clone()];
                source.authority_root_ref = AuthorityRootRef::OwnedAgent {
                    realm_id: realm(),
                    controller_account_id,
                    controller_join_event_id: event(191),
                    agent_join_event_id: event(192),
                };
                Some(reference)
            } else {
                None
            };
            let source_cut = cut(vec![source.clone()], controller.clone());
            let mut authorization = ActorRealmAuthorization::from_source_cut(
                subject.clone(),
                time,
                Arc::clone(&source_cut),
                vec![source.id.clone()],
                owned_source,
            )
            .unwrap();
            let actions = [A];
            let operation = crate::AuthorizationOperation {
                actor: &subject,
                actions: &actions,
                target: &target,
                at: time,
                facts: &facts,
            };
            let sdk = if owned {
                authorization.agent_ceiling = Some(AgentControllerCeiling {
                    controller: Box::new(
                        ActorRealmAuthorization::from_source_cut(
                            controller.clone(),
                            time,
                            source_cut,
                            Vec::new(),
                            None,
                        )
                        .unwrap(),
                    ),
                    management_policies: Vec::new(),
                });
                crate::evaluate_controller_bounded_grants(
                    &operation,
                    &[&source],
                    &controller,
                    &[],
                    &[],
                    true,
                )
            } else {
                crate::evaluate_grants_with_verified_approvals(&operation, [&source], &[])
            };
            assert_eq!(matches!(sdk, crate::GrantEvaluation::Allowed(_)), expected);
            assert_eq!(
                matches!(
                    evaluate(&authorization, &actions, &target, &facts),
                    crate::GrantEvaluation::Allowed(_),
                ),
                expected,
            );
            assert_eq!(
                !authorization
                    .current_positive_grant_records(A, &target)
                    .unwrap()
                    .is_empty(),
                expected,
            );
            let mut expired = authorization.clone();
            expired.evaluated_at = at(120);
            if let Some(ceiling) = expired.agent_ceiling.as_mut() {
                ceiling.controller.evaluated_at = at(120);
            }
            assert!(
                expired
                    .current_positive_grant_records(A, &target)
                    .unwrap()
                    .is_empty()
            );
        }
    }
}

#[test]
fn realm_actor_target_uses_its_embedded_realm_and_actual_named_audit_grant() {
    let holder = actor("auditor");
    let managed = ActorId::realm(arkret_wire::RealmActorId::new(
        realm(),
        "ak:did_core:webvh:z6mkfixtureaudit".parse().unwrap(),
    ));
    let target = WireResourceSelector::realm_actor(managed.clone()).unwrap();
    assert_eq!(
        serde_json::to_value(&target).unwrap(),
        serde_json::json!({"kind":"realm_actor","actor_id":managed})
    );
    assert!(target.realm_id.is_none());
    let mut audit = grant(
        210,
        holder.clone(),
        &[CapabilityActionId::REALM_ACTOR_AUDIT],
        vec![global()],
    );
    audit.resources = vec![target.clone()];
    let id = audit.id.clone();
    let context = auth(
        holder.clone(),
        cut(vec![audit], actor("governor")),
        Vec::new(),
    );
    let facts = crate::OperationFacts::default();
    let evaluated = context
        .evaluate_with_approvals_checked(
            &[CapabilityActionId::REALM_ACTOR_AUDIT],
            &target,
            &facts,
            &[],
        )
        .unwrap();
    let crate::GrantEvaluation::Allowed(paths) = evaluated else {
        panic!("same-Realm exact audit grant must be a real named allow");
    };
    assert_eq!(paths.len(), 1);
    assert_eq!(paths[0].grant.id, id);
    assert!(paths[0].reservations.is_empty());
    let absent = auth(holder, cut(Vec::new(), actor("governor")), Vec::new());
    assert!(
        absent
            .evaluate(&[CapabilityActionId::REALM_ACTOR_AUDIT], &target, &facts)
            .unreserved()
            .is_empty()
    );
}

#[test]
fn realm_actor_target_rejects_foreign_realm_and_noncanonical_or_all_selectors() {
    let holder = actor("auditor");
    let managed = |owner| {
        ActorId::realm(arkret_wire::RealmActorId::new(
            owner,
            "ak:did_core:webvh:z6mkfixtureaudit".parse().unwrap(),
        ))
    };
    let target = WireResourceSelector::realm_actor(managed(realm())).unwrap();
    let mut audit = grant(
        211,
        holder.clone(),
        &[CapabilityActionId::REALM_ACTOR_AUDIT],
        vec![global()],
    );
    audit.resources = vec![target.clone()];
    let context = auth(holder, cut(vec![audit], actor("governor")), Vec::new());
    let foreign =
        WireResourceSelector::realm_actor(managed(RealmId::from_event_id(&event(212)))).unwrap();
    let mut missing_actor = target.clone();
    missing_actor.actor_id = None;
    let mut surplus_realm = target.clone();
    surplus_realm.realm_id = Some(realm());
    let mut all = WireResourceSelector::realm(realm());
    all.kind = arkret_wire::ResourceSelectorKind::All;
    for invalid in [foreign, missing_actor, surplus_realm, all] {
        assert!(
            context
                .evaluate_with_approvals_checked(
                    &[CapabilityActionId::REALM_ACTOR_AUDIT],
                    &invalid,
                    &crate::OperationFacts::default(),
                    &[],
                )
                .is_err()
        );
    }
}
