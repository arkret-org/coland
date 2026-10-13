use arkret_models_collaboration::governance::grant_constraint::{
    CapabilityGrant, GrantConstraint, GrantConstraintEffect, GrantConstraintKind,
    GrantConstraintRecurrence, GrantConstraintRecurrenceDay, GrantConstraintRecurrenceFrequency,
    GrantConstraintScope, GrantConstraintSubkind,
};
use arkret_wire::{ActorId, CapabilityActionId, EvaluationClass, WireResourceSelector};
use chrono::{DateTime, TimeDelta, Utc};

use super::*;

const REALM: &str = "ak:realm:AUGIFvQctz4TjQTmvvO4Wdy-xdc5XP2ZnJ5Qpbh4s8Ru";
const CIRCLE_A: &str = "ak:circle:AcsXlJSItqSzy43Swu0nFz2ijj4Yaf0RgjmoTeivRt8M";
const CIRCLE_B: &str = "ak:circle:AT2LoQ65P6bU2ZDxq9XbubTSMDrqzlK8EFJNmM_pxt62";
const STRAND_A: &str = "ak:strand:AZ6GqZWWvnQ2KFwbBD-MenomzWNz-31MUAuKzBXIP0zv";
const STRAND_B: &str = "ak:strand:Aa-h0nYxlvhQk1U9H0yQTY4hZEVTz0be75pj6U70n7qy";
const LIST_A: &str = "ak:space:AY6DJbBwavsGTQuBZZiqqw9MVcqPZ8QX8invQ3i2kpi7";
const LIST_B: &str = "ak:space:AZ6GqZWWvnQ2KFwbBD-MenomzWNz-31MUAuKzBXIP0zv";

#[test]
fn applet_authority_requires_exact_service_and_registration_epoch() {
    let applet = arkret_wire::AppletId::new_v7_at(1_790_876_000_000);
    let executor = ActorId::service("ak:did_core:web:bridge.example".parse().unwrap());
    let epoch: arkret_wire::Hash = format!("sha256:{}", "1".repeat(64)).parse().unwrap();
    let grants = [grant(
        1,
        &["ak.message.create"],
        realm_wide(),
        vec![GrantConstraint::applet_authority(
            applet.clone(),
            executor.clone(),
            epoch.clone(),
        )],
    )];
    let mut facts = OperationFacts {
        applet_id: Some(applet.to_string()),
        executed_by: Some(executor),
        registration_epoch: Some(epoch.to_string()),
        ..Default::default()
    };
    let now = at("2026-10-01T18:41:32.000Z");
    assert!(allowed(&evaluate(
        &grants,
        "ak.message.create",
        &realm(),
        &facts,
        now
    )));
    facts.registration_epoch = Some(format!("sha256:{}", "2".repeat(64)));
    assert!(!allowed(&evaluate(
        &grants,
        "ak.message.create",
        &realm(),
        &facts,
        now
    )));
    facts.registration_epoch = Some(epoch.to_string());
    facts.executed_by = None;
    assert!(!allowed(&evaluate(
        &grants,
        "ak.message.create",
        &realm(),
        &facts,
        now
    )));
}

fn actor() -> ActorId {
    ActorId::account(arkret_wire::AccountId::new(
        arkret_wire::DidCoreId::new("ak:did_core:web:reader.example").unwrap(),
        arkret_wire::DidCoreId::new("ak:did_core:web:station.example").unwrap(),
    ))
}

fn root_ref() -> serde_json::Value {
    serde_json::json!({
        "kind": "realm_root",
        "realm_id": REALM,
        "authority_event_ref": arkret_wire::EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            [0x55; 32],
        ),
        "authority_generation": 0
    })
}

fn grant(
    seed: u8,
    actions: &[&str],
    resources: serde_json::Value,
    constraints: Vec<GrantConstraint>,
) -> CapabilityGrant {
    let id = arkret_wire::GrantId::from_event_id(&arkret_wire::EventId::from_digest(
        arkret_canonical::DigestSuite::Sha256,
        [seed; 32],
    ));
    let mut grant: CapabilityGrant = serde_json::from_value(serde_json::json!({
        "id": id,
        "schema": "ak.schema.capability.v1",
        "realm_id": REALM,
        "issuer_id": actor(),
        "subject": actor(),
        "actions": actions,
        "resources": resources,
        "issuer_authority_refs": [root_ref()],
        "authority_depth": 1,
        "authority_root_refs": [root_ref()],
        "issued_at": "2026-09-21T00:00:00.000Z",
        "status": "active"
    }))
    .unwrap();
    grant.constraints = constraints;
    grant
}

fn realm_wide() -> serde_json::Value {
    serde_json::json!([{"kind": "realm", "realm_id": REALM}])
}

fn selector(value: serde_json::Value) -> WireResourceSelector {
    serde_json::from_value(value).unwrap()
}

fn realm() -> WireResourceSelector {
    selector(serde_json::json!({"kind": "realm", "realm_id": REALM}))
}

fn circle(id: &str) -> WireResourceSelector {
    selector(serde_json::json!({"kind": "circle", "realm_id": REALM, "circle_id": id}))
}

fn strand(id: &str) -> WireResourceSelector {
    selector(serde_json::json!({"kind": "strand", "realm_id": REALM, "strand_id": id}))
}

fn at(value: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(value)
        .unwrap()
        .with_timezone(&Utc)
}

fn evaluate<'g>(
    grants: &'g [CapabilityGrant],
    action: &str,
    target: &WireResourceSelector,
    facts: &OperationFacts,
    now: DateTime<Utc>,
) -> GrantEvaluation<'g> {
    let actor = actor();
    evaluate_grants(
        &AuthorizationOperation {
            actor: &actor,
            actions: &[action],
            target,
            at: now,
            facts,
        },
        grants.iter(),
    )
}

fn allowed(evaluation: &GrantEvaluation<'_>) -> bool {
    !evaluation.unreserved().is_empty()
}

fn constraint(kind: GrantConstraintKind, effect: GrantConstraintEffect) -> GrantConstraint {
    GrantConstraint::new(kind, effect)
}

fn circles(ids: &[&str]) -> GrantConstraint {
    let mut constraint = constraint(
        GrantConstraintKind::ScopeLimitation,
        GrantConstraintEffect::Allow,
    );
    constraint.allowed_circle_ids = ids.iter().map(|id| id.parse().unwrap()).collect();
    constraint
}

fn now() -> DateTime<Utc> {
    at("2026-09-21T12:00:00Z")
}

#[test]
fn placement_grant_checks_both_resolved_containers() {
    let mut scope = constraint(
        GrantConstraintKind::ScopeLimitation,
        GrantConstraintEffect::Allow,
    );
    scope.allowed_from_container_refs = vec![LIST_A.to_owned()];
    scope.allowed_to_container_refs = vec![LIST_B.to_owned()];
    let grants = [grant(
        19,
        &[CapabilityActionId::STRAND_MOVE],
        realm_wide(),
        vec![scope],
    )];
    let mut facts = OperationFacts {
        strand_id: Some(STRAND_A.to_owned()),
        from_container_id: Some(LIST_A.to_owned()),
        to_container_id: Some(LIST_B.to_owned()),
        ..OperationFacts::default()
    };
    assert!(allowed(&evaluate(
        &grants,
        CapabilityActionId::STRAND_MOVE,
        &strand(STRAND_A),
        &facts,
        now()
    )));
    facts.from_container_id = None;
    assert!(!allowed(&evaluate(
        &grants,
        CapabilityActionId::STRAND_MOVE,
        &strand(STRAND_A),
        &facts,
        now()
    )));
    facts.from_container_id = Some(LIST_B.to_owned());
    assert!(!allowed(&evaluate(
        &grants,
        CapabilityActionId::STRAND_MOVE,
        &strand(STRAND_A),
        &facts,
        now()
    )));
    facts.from_container_id = Some(LIST_A.to_owned());
    facts.to_container_id = Some(LIST_A.to_owned());
    assert!(!allowed(&evaluate(
        &grants,
        CapabilityActionId::STRAND_MOVE,
        &strand(STRAND_A),
        &facts,
        now()
    )));
}

#[test]
fn circle_management_is_narrowed_by_allowed_circle_ids_or_a_circle_selector() {
    let facts = OperationFacts::default();
    let listed = [grant(
        1,
        &[CapabilityActionId::CIRCLE_MANAGE],
        realm_wide(),
        vec![circles(&[CIRCLE_A])],
    )];
    assert!(allowed(&evaluate(
        &listed,
        CapabilityActionId::CIRCLE_MANAGE,
        &circle(CIRCLE_A),
        &facts,
        now()
    )));
    assert!(matches!(
        evaluate(
            &listed,
            CapabilityActionId::CIRCLE_MANAGE,
            &circle(CIRCLE_B),
            &facts,
            now()
        ),
        GrantEvaluation::Unsatisfied
    ));
    // A Realm target names no Circle, so the Circle list cannot admit it.
    assert!(!allowed(&evaluate(
        &listed,
        CapabilityActionId::CIRCLE_MANAGE,
        &realm(),
        &facts,
        now()
    )));

    // The registry requires the narrowing: a Realm-wide grant without it is
    // not a normal authorization shape.
    let unnarrowed = [grant(
        2,
        &[CapabilityActionId::CIRCLE_MEMBER_MANAGE],
        realm_wide(),
        Vec::new(),
    )];
    assert!(matches!(
        evaluate(
            &unnarrowed,
            CapabilityActionId::CIRCLE_MEMBER_MANAGE,
            &circle(CIRCLE_A),
            &facts,
            now()
        ),
        GrantEvaluation::Unsatisfied
    ));
    let selector_narrowed = [grant(
        3,
        &[CapabilityActionId::CIRCLE_MEMBER_MANAGE],
        serde_json::json!([{"kind": "circle", "realm_id": REALM, "circle_id": CIRCLE_A}]),
        Vec::new(),
    )];
    assert!(allowed(&evaluate(
        &selector_narrowed,
        CapabilityActionId::CIRCLE_MEMBER_MANAGE,
        &circle(CIRCLE_A),
        &facts,
        now()
    )));
}

#[test]
fn a_refusal_of_any_named_grant_cannot_be_bleached_by_another_grant() {
    let facts = OperationFacts::default();
    let mut deny = constraint(
        GrantConstraintKind::ScopeLimitation,
        GrantConstraintEffect::Deny,
    );
    deny.denied_strand_ids = vec![STRAND_A.to_owned()];
    let grants = [
        grant(
            1,
            &[CapabilityActionId::MESSAGE_CREATE],
            realm_wide(),
            Vec::new(),
        ),
        grant(
            2,
            &[CapabilityActionId::MESSAGE_CREATE],
            realm_wide(),
            vec![deny],
        ),
    ];
    assert!(matches!(
        evaluate(
            &grants,
            CapabilityActionId::MESSAGE_CREATE,
            &strand(STRAND_A),
            &facts,
            now()
        ),
        GrantEvaluation::Denied
    ));
    assert!(allowed(&evaluate(
        &grants,
        CapabilityActionId::MESSAGE_CREATE,
        &strand(STRAND_B),
        &facts,
        now()
    )));
    // A Realm-wide target may be the denied Strand: undecidable matches.
    assert!(matches!(
        evaluate(
            &grants,
            CapabilityActionId::MESSAGE_CREATE,
            &realm(),
            &facts,
            now()
        ),
        GrantEvaluation::Denied
    ));
}

#[test]
fn refusal_effects_short_circuit_in_registered_order() {
    let facts = OperationFacts::default();
    let mut quarantine = constraint(
        GrantConstraintKind::ScopeLimitation,
        GrantConstraintEffect::Quarantine,
    );
    quarantine.allowed_strand_ids = vec![STRAND_A.to_owned()];
    let mut review = constraint(
        GrantConstraintKind::ScopeLimitation,
        GrantConstraintEffect::RequireReview,
    );
    review.allowed_strand_ids = vec![STRAND_A.to_owned(), STRAND_B.to_owned()];
    let grants = [grant(
        1,
        &[CapabilityActionId::MESSAGE_CREATE],
        realm_wide(),
        vec![review, quarantine],
    )];
    assert!(matches!(
        evaluate(
            &grants,
            CapabilityActionId::MESSAGE_CREATE,
            &strand(STRAND_A),
            &facts,
            now()
        ),
        GrantEvaluation::Quarantined
    ));
    assert!(matches!(
        evaluate(
            &grants,
            CapabilityActionId::MESSAGE_CREATE,
            &strand(STRAND_B),
            &facts,
            now()
        ),
        GrantEvaluation::RequiresReview
    ));
}

#[test]
fn allow_constraints_of_one_grant_do_not_restrict_another() {
    let facts = OperationFacts {
        track: Some("discussion".to_owned()),
        ..OperationFacts::default()
    };
    let mut synthesis_only = constraint(
        GrantConstraintKind::ScopeLimitation,
        GrantConstraintEffect::Allow,
    );
    synthesis_only.allowed_tracks = vec!["synthesis".to_owned()];
    let narrow = [grant(
        1,
        &[CapabilityActionId::MESSAGE_CREATE],
        realm_wide(),
        vec![synthesis_only],
    )];
    assert!(matches!(
        evaluate(
            &narrow,
            CapabilityActionId::MESSAGE_CREATE,
            &strand(STRAND_A),
            &facts,
            now()
        ),
        GrantEvaluation::Unsatisfied
    ));
    let mut both = narrow.to_vec();
    both.push(grant(
        2,
        &[CapabilityActionId::MESSAGE_CREATE],
        realm_wide(),
        Vec::new(),
    ));
    let evaluation = evaluate(
        &both,
        CapabilityActionId::MESSAGE_CREATE,
        &strand(STRAND_A),
        &facts,
        now(),
    );
    assert_eq!(evaluation.unreserved().len(), 1);
    assert_eq!(evaluation.unreserved()[0].id, both[1].id);
}

fn window(not_before: Option<&str>, expires_at: Option<&str>) -> GrantConstraint {
    let mut constraint = constraint(GrantConstraintKind::Temporal, GrantConstraintEffect::Allow);
    constraint.not_before = not_before.map(at);
    constraint.expires_at = expires_at.map(at);
    constraint
}

#[test]
fn validity_window_boundaries_follow_the_registered_tolerance() {
    let facts = OperationFacts::default();
    let skew = TimeDelta::milliseconds(
        arkret_identifiers::protocol_time_tolerance_scenario_descriptor(
            arkret_identifiers::ProtocolTimeToleranceScenario::TemporalConstraint,
        )
        .tolerance_ms(),
    );
    let expires = at("2026-09-21T12:00:00Z");
    let grants = [grant(
        1,
        &[CapabilityActionId::REALM_ADMIN],
        realm_wide(),
        vec![window(None, Some("2026-09-21T12:00:00Z"))],
    )];
    let check = |instant| {
        allowed(&evaluate(
            &grants,
            CapabilityActionId::REALM_ADMIN,
            &realm(),
            &facts,
            instant,
        ))
    };
    assert!(check(expires + skew));
    assert!(!check(expires + skew + TimeDelta::milliseconds(1)));
    let starts = [grant(
        2,
        &[CapabilityActionId::REALM_ADMIN],
        realm_wide(),
        vec![window(Some("2026-09-21T12:00:00Z"), None)],
    )];
    let check = |instant| {
        allowed(&evaluate(
            &starts,
            CapabilityActionId::REALM_ADMIN,
            &realm(),
            &facts,
            instant,
        ))
    };
    assert!(check(expires - skew));
    assert!(!check(expires - skew - TimeDelta::milliseconds(1)));
}

fn recurring(recurrence: GrantConstraintRecurrence) -> [CapabilityGrant; 1] {
    let mut constraint = window(None, None);
    constraint.constraint_subkind = Some(GrantConstraintSubkind::Window);
    constraint.recurrence = Some(recurrence);
    [grant(
        1,
        &[CapabilityActionId::REALM_ADMIN],
        realm_wide(),
        vec![constraint],
    )]
}

fn recurrence_allows(grants: &[CapabilityGrant], instant: &str) -> bool {
    allowed(&evaluate(
        grants,
        CapabilityActionId::REALM_ADMIN,
        &realm(),
        &OperationFacts::default(),
        at(instant),
    ))
}

#[test]
fn weekly_windows_match_local_days_hours_and_midnight_crossings() {
    // 2026-09-21 is a Monday.
    let office = recurring(GrantConstraintRecurrence {
        frequency: Some(GrantConstraintRecurrenceFrequency::Weekly),
        days: vec![GrantConstraintRecurrenceDay::Mon],
        window_start: Some("09:00".to_owned()),
        window_end: Some("17:00:00".to_owned()),
        timezone: Some("Asia/Shanghai".to_owned()),
        ..GrantConstraintRecurrence::default()
    });
    assert!(recurrence_allows(&office, "2026-09-21T01:00:00Z"));
    assert!(!recurrence_allows(&office, "2026-09-21T09:30:00Z"));
    // Within the tolerance before the start and before the end.
    assert!(recurrence_allows(&office, "2026-09-21T00:56:00Z"));
    assert!(!recurrence_allows(&office, "2026-09-21T00:54:59Z"));
    assert!(recurrence_allows(&office, "2026-09-21T08:59:00Z"));
    assert!(!recurrence_allows(&office, "2026-09-21T09:05:00Z"));
    // Tuesday is not listed.
    assert!(!recurrence_allows(&office, "2026-09-22T01:00:00Z"));

    let night = recurring(GrantConstraintRecurrence {
        days: vec![GrantConstraintRecurrenceDay::Mon],
        window_start: Some("22:00".to_owned()),
        window_end: Some("02:00".to_owned()),
        ..GrantConstraintRecurrence::default()
    });
    assert!(recurrence_allows(&night, "2026-09-21T23:00:00Z"));
    assert!(recurrence_allows(&night, "2026-09-22T01:00:00Z"));
    assert!(!recurrence_allows(&night, "2026-09-21T01:00:00Z"));

    let daily = recurring(GrantConstraintRecurrence::default());
    assert!(recurrence_allows(&daily, "2026-09-24T03:00:00Z"));
}

#[test]
fn unregistered_recurrence_forms_fail_closed() {
    for recurrence in [
        GrantConstraintRecurrence {
            frequency: Some(GrantConstraintRecurrenceFrequency::Monthly),
            ..GrantConstraintRecurrence::default()
        },
        GrantConstraintRecurrence {
            frequency: Some(GrantConstraintRecurrenceFrequency::Weekly),
            ..GrantConstraintRecurrence::default()
        },
        GrantConstraintRecurrence {
            timezone: Some("Mars/Olympus".to_owned()),
            ..GrantConstraintRecurrence::default()
        },
        GrantConstraintRecurrence {
            window_start: Some("09:00".to_owned()),
            ..GrantConstraintRecurrence::default()
        },
        // 02:30 does not exist in New York on 2026-03-08.
        GrantConstraintRecurrence {
            window_start: Some("02:30".to_owned()),
            window_end: Some("03:30".to_owned()),
            timezone: Some("America/New_York".to_owned()),
            ..GrantConstraintRecurrence::default()
        },
    ] {
        let grants = recurring(recurrence.clone());
        assert!(
            !recurrence_allows(&grants, "2026-03-08T07:45:00Z"),
            "{recurrence:?}"
        );
    }
}

fn edit_window(actions: &[&str], edit: Option<&str>, redact: Option<&str>) -> GrantConstraint {
    let mut constraint = window(None, None);
    constraint.constraint_subkind = Some(GrantConstraintSubkind::EditWindow);
    constraint.applies_to_actions = actions.iter().map(|action| (*action).to_owned()).collect();
    constraint.message_edit_window = edit.map(str::to_owned);
    constraint.message_redact_window = redact.map(str::to_owned);
    constraint
}

fn own(grants: &[CapabilityGrant], action: &str, created: &str, instant: &str) -> bool {
    let facts = OperationFacts {
        target_created_at: Some(at(created)),
        ..OperationFacts::default()
    };
    allowed(&evaluate(grants, action, &realm(), &facts, at(instant)))
}

#[test]
fn self_service_windows_follow_their_own_action() {
    let revise = CapabilityActionId::MESSAGE_REVISE_OWN;
    let redact = CapabilityActionId::MESSAGE_REDACT_OWN;
    let grants = [grant(
        1,
        &[revise, redact],
        realm_wide(),
        vec![edit_window(&[revise], Some("PT15M"), None)],
    )];
    assert!(own(
        &grants,
        revise,
        "2026-09-21T12:00:00Z",
        "2026-09-21T12:20:00Z"
    ));
    assert!(!own(
        &grants,
        revise,
        "2026-09-21T12:00:00Z",
        "2026-09-21T12:20:01Z"
    ));
    // A window gated to another action is neutral.
    assert!(own(
        &grants,
        redact,
        "2026-09-21T12:00:00Z",
        "2026-09-23T12:00:00Z"
    ));

    // Redact shares a window that gates it unless it opts out.
    let mut shared = edit_window(&[revise, redact], Some("PT15M"), None);
    let grants = [grant(2, &[redact], realm_wide(), vec![shared.clone()])];
    assert!(!own(
        &grants,
        redact,
        "2026-09-21T12:00:00Z",
        "2026-09-21T13:00:00Z"
    ));
    shared.redact_after_window_allowed = Some(true);
    let grants = [grant(3, &[redact], realm_wide(), vec![shared.clone()])];
    assert!(own(
        &grants,
        redact,
        "2026-09-21T12:00:00Z",
        "2026-09-22T12:00:00Z"
    ));
    shared.message_redact_window = Some("PT1H".to_owned());
    let grants = [grant(4, &[redact], realm_wide(), vec![shared])];
    assert!(!own(
        &grants,
        redact,
        "2026-09-21T12:00:00Z",
        "2026-09-21T13:06:00Z"
    ));

    // No verified target time, or a window without its action gate, fails.
    let grants = [grant(
        5,
        &[revise],
        realm_wide(),
        vec![edit_window(&[revise], Some("PT15M"), None)],
    )];
    assert!(!allowed(&evaluate(
        &grants,
        revise,
        &realm(),
        &OperationFacts::default(),
        now()
    )));
    let grants = [grant(
        6,
        &[revise],
        realm_wide(),
        vec![edit_window(&[], Some("PT15M"), None)],
    )];
    assert!(!own(
        &grants,
        revise,
        "2026-09-21T12:00:00Z",
        "2026-09-21T12:01:00Z"
    ));
}

#[test]
fn registered_windows_have_fixed_lengths_only() {
    for (value, seconds) in [
        ("PT15M", 900),
        ("PT24H", 86_400),
        ("P1W2DT3H4M5S", 9 * 86_400 + 3 * 3_600 + 4 * 60 + 5),
        ("P0D", 0),
    ] {
        assert_eq!(
            fixed_duration(value),
            TimeDelta::try_seconds(seconds),
            "{value}"
        );
    }
    for value in [
        "P", "PT", "P1Y", "P1M", "PT1H1H", "PT1M1H", "15M", "P1DT", "PT-1S",
    ] {
        assert_eq!(fixed_duration(value), None, "{value}");
    }
}

fn rate(scope: GrantConstraintScope) -> GrantConstraint {
    let mut constraint = constraint(GrantConstraintKind::Quota, GrantConstraintEffect::Allow);
    constraint.constraint_subkind = Some(GrantConstraintSubkind::Rate);
    constraint.max_operations = Some(3);
    constraint.period = Some("PT1H".to_owned());
    constraint.constraint_scope = Some(scope);
    constraint
}

fn bounded<'g>(
    agents: &'g [CapabilityGrant],
    parents: &[CapabilityGrant],
    actions: &[&str],
    facts: &OperationFacts,
) -> GrantEvaluation<'g> {
    let agent = actor();
    let controller = ActorId::account(arkret_wire::AccountId::new(
        "ak:did_core:web:controller.example".parse().unwrap(),
        "ak:did_core:web:station.example".parse().unwrap(),
    ));
    evaluate_controller_bounded_grants(
        &AuthorizationOperation {
            actor: &agent,
            actions,
            target: &strand(STRAND_A),
            at: now(),
            facts,
        },
        &agents.iter().collect::<Vec<_>>(),
        &controller,
        &parents.iter().collect::<Vec<_>>(),
        &[],
        false,
    )
}

#[test]
fn controller_bound_execution_loses_authority_without_revoking_agent_grant() {
    let agents = [grant(1, &["ak.message.create"], realm_wide(), vec![])];
    let parents = [grant(2, &["ak.message.create"], realm_wide(), vec![])];
    let facts = OperationFacts::default();
    assert!(allowed(&bounded(
        &agents,
        &parents,
        &["ak.message.create"],
        &facts
    )));
    assert!(matches!(
        bounded(&agents, &[], &["ak.message.create"], &facts),
        GrantEvaluation::Unsatisfied
    ));
    assert!(allowed(&bounded(
        &agents,
        &parents,
        &["ak.message.create"],
        &facts
    )));
}

#[test]
fn controller_own_mapping_keeps_actual_author_and_global_refusals() {
    use arkret_models_collaboration::governance::grant_constraint::{
        GrantConstraintCondition, GrantConstraintConditionKind,
    };
    let mut own = constraint(
        GrantConstraintKind::FieldAccess,
        GrantConstraintEffect::Allow,
    );
    own.allowed_write_fields = vec!["body".to_owned()];
    own.condition = Some(GrantConstraintCondition {
        kind: GrantConstraintConditionKind::ObjectIsOwnedByActor,
        extra: Default::default(),
    });
    let mut agents = [grant(
        1,
        &["ak.message.revise.own"],
        realm_wide(),
        vec![own.clone()],
    )];
    let mut parents = vec![grant(
        2,
        &["ak.message.revise.own"],
        realm_wide(),
        vec![own.clone()],
    )];
    let mut facts = OperationFacts {
        target_owner: Some(actor()),
        target_created_at: Some(now()),
        write_fields: Some(vec!["body".to_owned()]),
        ..Default::default()
    };
    assert!(allowed(&bounded(
        &agents,
        &parents,
        &["ak.message.revise.own"],
        &facts
    )));
    let author = facts.target_owner.clone();
    own.effect = GrantConstraintEffect::Deny;
    own.allowed_write_fields.clear();
    own.denied_write_fields = vec!["body".to_owned()];
    parents.push(grant(
        3,
        &["ak.message.revise.own"],
        realm_wide(),
        vec![own],
    ));
    assert!(matches!(
        bounded(&agents, &parents, &["ak.message.revise.own"], &facts),
        GrantEvaluation::Denied
    ));
    assert_eq!(facts.target_owner, author);
    parents.pop();
    facts.target_owner = Some(ActorId::account(arkret_wire::AccountId::new(
        "ak:did_core:web:controller.example".parse().unwrap(),
        "ak:did_core:web:station.example".parse().unwrap(),
    )));
    assert!(!allowed(&bounded(
        &agents,
        &parents,
        &["ak.message.revise.own"],
        &facts
    )));
    agents[0].actions.push("ak.message.revise".to_owned());
    parents[0].actions.push("ak.message.revise".to_owned());
    assert!(allowed(&bounded(
        &agents,
        &parents,
        &["ak.message.revise.own", "ak.message.revise"],
        &facts
    )));
    facts.target_owner = None;
    assert!(!allowed(&bounded(
        &agents,
        &parents,
        &["ak.message.revise.own"],
        &facts
    )));
}

#[test]
fn controller_bound_execution_never_splices_action_and_resource_paths() {
    let agents = [grant(1, &["ak.message.create"], realm_wide(), vec![])];
    let parents = [
        grant(2, &["ak.reaction.add"], realm_wide(), vec![]),
        grant(
            3,
            &["ak.message.create"],
            serde_json::json!([{"kind":"strand","realm_id":REALM,"strand_id":STRAND_B}]),
            vec![],
        ),
    ];
    assert!(matches!(
        bounded(
            &agents,
            &parents,
            &["ak.message.create", "ak.reaction.add"],
            &OperationFacts::default()
        ),
        GrantEvaluation::Unsatisfied
    ));
}

#[test]
fn controller_bound_execution_preserves_global_refusals() {
    let agents = [grant(1, &["ak.message.create"], realm_wide(), vec![])];
    for effect in [
        GrantConstraintEffect::Deny,
        GrantConstraintEffect::Quarantine,
        GrantConstraintEffect::RequireReview,
    ] {
        let mut refusal = window(None, Some("2026-10-21T00:00:00Z"));
        refusal.effect = effect;
        let parents = [
            grant(2, &["ak.message.create"], realm_wide(), vec![]),
            grant(3, &["ak.message.create"], realm_wide(), vec![refusal]),
        ];
        assert!(
            bounded(
                &agents,
                &parents,
                &["ak.message.create"],
                &OperationFacts::default()
            )
            .is_refusal()
        );
    }
}

#[test]
fn controller_bound_quotas_keep_original_parent_keys_and_agent_limits() {
    let agents = [grant(
        1,
        &["ak.message.create"],
        realm_wide(),
        vec![rate(GrantConstraintScope::PerActor)],
    )];
    let parents = [grant(
        2,
        &["ak.message.create"],
        realm_wide(),
        vec![rate(GrantConstraintScope::PerActor)],
    )];
    let facts = OperationFacts::default();
    let GrantEvaluation::Allowed(paths) =
        bounded(&agents, &parents, &["ak.message.create"], &facts)
    else {
        panic!("both paths satisfy")
    };
    assert_eq!(paths[0].reservations.len(), 2);
    let parent_counter = paths[0]
        .reservations
        .iter()
        .find(|row| row.grant_id == parents[0].id)
        .unwrap();
    assert!(parent_counter.counter_key.contains("controller.example"));
    assert!(!parent_counter.counter_key.contains("reader.example"));
    let controller = ActorId::account(arkret_wire::AccountId::new(
        "ak:did_core:web:controller.example".parse().unwrap(),
        "ak:did_core:web:station.example".parse().unwrap(),
    ));
    let GrantEvaluation::Allowed(owner_paths) = evaluate_grants(
        &AuthorizationOperation {
            actor: &controller,
            actions: &["ak.message.create"],
            target: &strand(STRAND_A),
            at: now(),
            facts: &facts,
        },
        parents.iter(),
    ) else {
        panic!("controller path satisfies")
    };
    assert_eq!(*parent_counter, owner_paths[0].reservations[0]);
}

#[test]
fn controller_bound_parent_selection_is_canonical_not_quota_free_first() {
    let agents = [grant(1, &["ak.message.create"], realm_wide(), vec![])];
    let mut parents = [
        grant(
            2,
            &["ak.message.create"],
            realm_wide(),
            vec![rate(GrantConstraintScope::PerActor)],
        ),
        grant(3, &["ak.message.create"], realm_wide(), vec![]),
    ];
    parents.sort_by(|a, b| a.id.cmp(&b.id));
    parents[0].constraints = vec![rate(GrantConstraintScope::PerActor)];
    parents[1].constraints.clear();
    let GrantEvaluation::Allowed(paths) = bounded(
        &agents,
        &parents,
        &["ak.message.create"],
        &OperationFacts::default(),
    ) else {
        panic!("two parent paths")
    };
    assert_eq!(paths.len(), 2);
    assert_eq!(paths[0].reservations[0].grant_id, parents[0].id);
    assert!(paths[1].reservations.is_empty());
}

#[test]
fn controller_bound_execution_cannot_borrow_agent_runtime_evidence() {
    let applet = arkret_wire::AppletId::new_v7_at(1_790_876_000_000);
    let executor = ActorId::service("ak:did_core:web:bridge.example".parse().unwrap());
    let epoch: arkret_wire::Hash = format!("sha256:{}", "1".repeat(64)).parse().unwrap();
    let agents = [grant(1, &["ak.message.create"], realm_wide(), vec![])];
    let parents = [grant(
        2,
        &["ak.message.create"],
        realm_wide(),
        vec![GrantConstraint::applet_authority(
            applet.clone(),
            executor.clone(),
            epoch.clone(),
        )],
    )];
    let facts = OperationFacts {
        applet_id: Some(applet.to_string()),
        executed_by: Some(executor),
        registration_epoch: Some(epoch.to_string()),
        ..Default::default()
    };
    assert!(matches!(
        bounded(&agents, &parents, &["ak.message.create"], &facts),
        GrantEvaluation::Unsatisfied
    ));
}

#[test]
fn a_rate_quota_is_owed_as_a_reservation_and_is_required_for_broadcast() {
    let broadcast = CapabilityActionId::MESSAGE_MENTION_BROADCAST;
    let facts = OperationFacts::default();
    let quota = rate(GrantConstraintScope::PerRealm);
    let grants = [grant(
        1,
        &[broadcast],
        realm_wide(),
        vec![window(None, Some("2026-10-21T00:00:00Z")), quota.clone()],
    )];
    let evaluation = evaluate(&grants, broadcast, &strand(STRAND_A), &facts, now());
    let GrantEvaluation::Allowed(satisfied) = &evaluation else {
        panic!("a quota grant is allowed subject to its reservation");
    };
    assert!(evaluation.unreserved().is_empty());
    let reservation = &satisfied[0].reservations[0];
    assert_eq!(reservation.grant_id, grants[0].id);
    assert_eq!(reservation.max_operations, 3);
    assert_eq!(reservation.period_ms, 3_600_000);
    assert_eq!(reservation.window_id, now().timestamp_millis() / 3_600_000);
    assert_eq!(
        reservation.counter_key,
        serde_json::to_string(&["per_realm", actor().to_string().as_str(), REALM]).unwrap()
    );
    assert_eq!(reservation.constraint_key, constraint_key(&quota).unwrap());

    // The broadcast grant without its registered quota is never sufficient.
    let unquoted = [grant(
        2,
        &[broadcast],
        realm_wide(),
        vec![window(None, Some("2026-10-21T00:00:00Z"))],
    )];
    assert!(matches!(
        evaluate(&unquoted, broadcast, &strand(STRAND_A), &facts, now()),
        GrantEvaluation::Unsatisfied
    ));

    // A per-Space quota needs the operation's Space.
    let per_space = [grant(
        3,
        &[CapabilityActionId::MESSAGE_CREATE],
        realm_wide(),
        vec![rate(GrantConstraintScope::PerSpace)],
    )];
    assert!(matches!(
        evaluate(
            &per_space,
            CapabilityActionId::MESSAGE_CREATE,
            &strand(STRAND_A),
            &facts,
            now()
        ),
        GrantEvaluation::Unsatisfied
    ));
}

#[test]
fn field_access_admits_listed_paths_and_denies_touched_ones() {
    let mut allow = constraint(
        GrantConstraintKind::FieldAccess,
        GrantConstraintEffect::Allow,
    );
    allow.allowed_write_fields = vec!["metadata.fields".to_owned()];
    let mut deny = constraint(
        GrantConstraintKind::FieldAccess,
        GrantConstraintEffect::Deny,
    );
    deny.denied_write_fields = vec!["metadata.fields.secret".to_owned()];
    let grants = [grant(
        1,
        &[CapabilityActionId::STRAND_UPDATE],
        realm_wide(),
        vec![allow, deny],
    )];
    let write = |fields: Option<Vec<&str>>| OperationFacts {
        write_fields: fields.map(|fields| fields.into_iter().map(str::to_owned).collect()),
        ..OperationFacts::default()
    };
    let target = strand(STRAND_A);
    let action = CapabilityActionId::STRAND_UPDATE;
    assert!(allowed(&evaluate(
        &grants,
        action,
        &target,
        &write(Some(vec!["metadata.fields.calendar"])),
        now()
    )));
    assert!(matches!(
        evaluate(
            &grants,
            action,
            &target,
            &write(Some(vec!["metadata.title"])),
            now()
        ),
        GrantEvaluation::Unsatisfied
    ));
    assert!(matches!(
        evaluate(
            &grants,
            action,
            &target,
            &write(Some(vec!["metadata.fields.secret.value"])),
            now()
        ),
        GrantEvaluation::Denied
    ));
    // Unknown written fields may touch the denied one.
    assert!(matches!(
        evaluate(&grants, action, &target, &write(None), now()),
        GrantEvaluation::Denied
    ));
    // `ak.strand.update` requires `allowed_write_fields`.
    let bare = [grant(2, &[action], realm_wide(), Vec::new())];
    assert!(matches!(
        evaluate(
            &bare,
            action,
            &target,
            &write(Some(vec!["metadata.title"])),
            now()
        ),
        GrantEvaluation::Unsatisfied
    ));
}

#[test]
fn kind_restriction_reads_the_target_object_kind() {
    let mut kinds = constraint(
        GrantConstraintKind::KindRestriction,
        GrantConstraintEffect::Allow,
    );
    kinds.allowed_object_kinds = vec!["strand".to_owned()];
    let grants = [grant(
        1,
        &[CapabilityActionId::MESSAGE_CREATE],
        realm_wide(),
        vec![kinds],
    )];
    let facts = OperationFacts::default();
    assert!(allowed(&evaluate(
        &grants,
        CapabilityActionId::MESSAGE_CREATE,
        &strand(STRAND_A),
        &facts,
        now()
    )));
    assert!(!allowed(&evaluate(
        &grants,
        CapabilityActionId::MESSAGE_CREATE,
        &realm(),
        &facts,
        now()
    )));
}

#[test]
fn undeclared_families_and_mismatched_classes_fail_closed() {
    let facts = OperationFacts::default();
    let target = strand(STRAND_A);
    let action = CapabilityActionId::MESSAGE_CREATE;
    let mut claim = constraint(
        GrantConstraintKind::ClaimBased,
        GrantConstraintEffect::Allow,
    );
    claim.constraint_subkind = Some(GrantConstraintSubkind::Claim);
    let mut kanban = constraint(
        GrantConstraintKind::ScopeLimitation,
        GrantConstraintEffect::Allow,
    );
    kanban.allowed_relation_kinds = vec!["contains".to_owned()];
    let mut lying = window(None, None);
    lying.evaluation_class = Some(EvaluationClass::External);
    let mut regrant = GrantConstraint::authority_control(1, true);
    regrant.evaluation_class = Some(EvaluationClass::GrantLocal);
    for (seed, constraints, admitted) in [
        (1, vec![claim.clone()], false),
        (2, vec![kanban], false),
        (3, vec![lying], false),
        (4, vec![regrant], true),
    ] {
        let grants = [grant(seed, &[action], realm_wide(), constraints)];
        assert_eq!(
            allowed(&evaluate(&grants, action, &target, &facts, now())),
            admitted,
            "{seed}"
        );
    }
    // An approval gate with no approval evidence carrier requires review.
    let mut approval = constraint(
        GrantConstraintKind::ClaimBased,
        GrantConstraintEffect::RequireReview,
    );
    approval.constraint_subkind = Some(GrantConstraintSubkind::Approval);
    approval.approval_required = Some(true);
    let grants = [grant(5, &[action], realm_wide(), vec![approval])];
    assert!(matches!(
        evaluate(&grants, action, &target, &facts, now()),
        GrantEvaluation::RequiresReview
    ));
}

#[test]
fn verified_approvals_discharge_only_the_exact_grant_constraint_and_action() {
    let action = CapabilityActionId::STRAND_MOVE;
    let subject = actor();
    let target = strand(STRAND_A);
    let facts = OperationFacts::default();
    let operation = AuthorizationOperation {
        actor: &subject,
        actions: &[action],
        target: &target,
        at: now(),
        facts: &facts,
    };
    let mut approval = constraint(
        GrantConstraintKind::ClaimBased,
        GrantConstraintEffect::RequireReview,
    );
    approval.constraint_subkind = Some(GrantConstraintSubkind::Approval);
    approval.approval_required = Some(true);
    let mut grants = vec![grant(91, &[action], realm_wide(), vec![approval.clone()])];
    let proof = VerifiedGrantApproval {
        grant_id: grants[0].id.clone(),
        constraint_digest: arkret_canonical::canonical_sha256(&approval).unwrap(),
        action: CapabilityActionId::StrandMove,
    };
    assert!(allowed(&evaluate_grants_with_verified_approvals(
        &operation,
        &grants,
        std::slice::from_ref(&proof)
    )));
    let mut wrong = proof.clone();
    wrong.constraint_digest.push('0');
    assert!(matches!(
        evaluate_grants_with_verified_approvals(&operation, &grants, &[wrong]),
        GrantEvaluation::RequiresReview
    ));
    let mut wrong = proof.clone();
    wrong.action = CapabilityActionId::StrandReorder;
    assert!(matches!(
        evaluate_grants_with_verified_approvals(&operation, &grants, &[wrong]),
        GrantEvaluation::RequiresReview
    ));
    grants.push(grant(92, &[action], realm_wide(), vec![approval]));
    assert!(matches!(
        evaluate_grants_with_verified_approvals(&operation, &grants, std::slice::from_ref(&proof)),
        GrantEvaluation::RequiresReview
    ));
    let mut deny = constraint(
        GrantConstraintKind::ScopeLimitation,
        GrantConstraintEffect::Deny,
    );
    deny.denied_strand_ids = vec![STRAND_A.to_owned()];
    grants[1].constraints = vec![deny];
    assert!(matches!(
        evaluate_grants_with_verified_approvals(&operation, &grants, &[proof]),
        GrantEvaluation::Denied
    ));
}

#[test]
fn false_grant_approval_requirement_withdraws_only_its_own_review() {
    let subject = actor();
    let target = strand(STRAND_A);
    let facts = OperationFacts::default();
    let operation = AuthorizationOperation {
        actor: &subject,
        actions: &[CapabilityActionId::STRAND_MOVE],
        target: &target,
        at: now(),
        facts: &facts,
    };
    let mut approval = constraint(
        GrantConstraintKind::ClaimBased,
        GrantConstraintEffect::RequireReview,
    );
    approval.constraint_subkind = Some(GrantConstraintSubkind::Approval);
    approval.approval_required = Some(false);
    let mut grants = vec![grant(
        93,
        &[CapabilityActionId::STRAND_MOVE],
        realm_wide(),
        vec![approval],
    )];
    assert!(allowed(&evaluate_grants_with_verified_approvals(
        &operation,
        &grants,
        &[]
    )));
    grants[0].constraints.push(constraint(
        GrantConstraintKind::Confidentiality,
        GrantConstraintEffect::RequireReview,
    ));
    assert!(matches!(
        evaluate_grants_with_verified_approvals(&operation, &grants, &[]),
        GrantEvaluation::RequiresReview
    ));
}

#[test]
fn approval_proof_never_discharges_mixed_predicates() {
    let subject = actor();
    let target = strand(STRAND_A);
    let facts = OperationFacts::default();
    let operation = AuthorizationOperation {
        actor: &subject,
        actions: &[CapabilityActionId::STRAND_MOVE],
        target: &target,
        at: now(),
        facts: &facts,
    };
    for (field, value) in [
        (
            "not_before",
            serde_json::json!(
                (now() + TimeDelta::days(1)).to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
            ),
        ),
        (
            "expires_at",
            serde_json::json!(
                (now() - TimeDelta::days(1)).to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
            ),
        ),
        ("max_resources", serde_json::json!(0)),
        ("allowed_space_ids", serde_json::json!([LIST_B])),
        ("accountability_required", serde_json::json!(true)),
        ("condition", serde_json::json!({"kind":"always"})),
        ("x_unregistered_predicate", serde_json::json!(true)),
    ] {
        for effect in [
            GrantConstraintEffect::Allow,
            GrantConstraintEffect::RequireReview,
        ] {
            for required in [true, false] {
                let mut raw =
                    serde_json::to_value(constraint(GrantConstraintKind::ClaimBased, effect))
                        .unwrap();
                raw["constraint_subkind"] = serde_json::json!("approval");
                raw["approval_required"] = serde_json::json!(required);
                raw[field] = value.clone();
                let mixed: GrantConstraint = serde_json::from_value(raw).unwrap();
                let grants = [grant(
                    94,
                    &[CapabilityActionId::STRAND_MOVE],
                    realm_wide(),
                    vec![mixed.clone()],
                )];
                let proof = VerifiedGrantApproval {
                    grant_id: grants[0].id.clone(),
                    constraint_digest: arkret_canonical::canonical_sha256(&mixed).unwrap(),
                    action: CapabilityActionId::StrandMove,
                };
                let result = evaluate_grants_with_verified_approvals(&operation, &grants, &[proof]);
                assert!(
                    !allowed(&result),
                    "{field}: {effect:?}, required={required}"
                );
            }
        }
    }
}
