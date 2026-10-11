use arkret_identifiers::{OperationId, RealmId};
use coland_domain::reducer::{FacetRef, ProjectionEffect, ProjectionState, ServerHlc, facet};
use serde_json::Value;

const REALM: &str = "ak:realm:AW2XhEBfjbMHqDBzRGwBXCaBZtSGUQTBe5CkC4pjU8O2";
const POLICY: &str = "ak:policy:0198ff00-0000-7000-8000-000000000001";

fn operation(kind: &str, payload: Value) -> arkret_event_draft::ProjectedEventOperation {
    arkret_event_draft::test_support::raw_projected_operation(
        OperationId::new(format!("ak:operation:{}", uuid::Uuid::now_v7())).unwrap(),
        RealmId::new(REALM).unwrap(),
        kind,
        payload,
    )
}

fn policy_payload() -> Value {
    serde_json::json!({
        "policy_id": POLICY,
        "value": {
            "schema": "ak.schema.policy.v1",
            "id": POLICY,
            "policy_kind": "access",
            "rules": [{
                "rule_id": "allow_members",
                "kind": "action",
                "effect": "allow",
                "actions": ["ak.message.create"]
            }],
            "default_effect": "deny",
            "created_by": {
                "kind": "account",
                "account_id": {
                    "principal_id": "ak:did_core:web:owner.example",
                    "station_id": "ak:did_core:web:station.example"
                }
            },
            "created_at": "2026-09-21T00:00:00.000Z"
        }
    })
}

fn policy_action_payload(policy_id: Option<&str>, action_id: Option<&str>) -> Value {
    let mut payload = serde_json::json!({
        "value": {
            "action": "ak.message.create",
            "approval_required": true,
            "approval_quorum": 2,
            "policy_scope": REALM
        }
    });
    if let Some(policy_id) = policy_id {
        payload["policy_id"] = Value::String(policy_id.to_owned());
    }
    if let Some(action_id) = action_id {
        payload["action_id"] = Value::String(action_id.to_owned());
    }
    payload
}

#[test]
fn policy_set_replaces_the_complete_document_under_its_policy_id() {
    let mut state = ProjectionState::default();
    let hlc = ServerHlc::new("policy-current");
    let effect = state.apply_projected(&operation("ak.policy.set", policy_payload()), &hlc);
    assert!(matches!(
        effect,
        ProjectionEffect::PolicyProjected { ref policy_id, ref realm_id }
            if policy_id == POLICY && realm_id == REALM
    ));

    let target = FacetRef::new(facet::POLICY, POLICY);
    assert_eq!(state.facet_revision(REALM, &target), 1);
    assert_eq!(state.facet_value(REALM, &target).unwrap()["id"], POLICY);

    let mut replacement = policy_payload();
    replacement["value"]["priority"] = serde_json::json!(7);
    assert!(matches!(
        state.apply_projected(&operation("ak.policy.set", replacement), &hlc),
        ProjectionEffect::PolicyProjected { .. }
    ));
    assert_eq!(state.facet_revision(REALM, &target), 2);
    assert_eq!(state.facet_value(REALM, &target).unwrap()["priority"], 7);
}

#[test]
fn policy_action_keeps_policy_and_realm_action_namespaces_disjoint() {
    let mut state = ProjectionState::default();
    let hlc = ServerHlc::new("policy-action-namespaces");
    state.apply_projected(&operation("ak.policy.set", policy_payload()), &hlc);

    let policy_effect = state.apply_projected(
        &operation(
            "ak.policy.action",
            policy_action_payload(Some(POLICY), None),
        ),
        &hlc,
    );
    assert!(matches!(
        policy_effect,
        ProjectionEffect::PolicyActionProjected {
            selector_kind: "policy_ref",
            ..
        }
    ));
    let realm_effect = state.apply_projected(
        &operation(
            "ak.policy.action",
            policy_action_payload(None, Some("moderated-message-create")),
        ),
        &hlc,
    );
    assert!(matches!(
        realm_effect,
        ProjectionEffect::PolicyActionProjected {
            selector_kind: "realm_action",
            ..
        }
    ));

    let policy_target = FacetRef::composite(
        facet::POLICY_ACTION_POLICY_REF,
        &[POLICY, "ak.message.create"],
    );
    let realm_target = FacetRef::new(
        facet::POLICY_ACTION_REALM_ACTION,
        "moderated-message-create",
    );
    assert!(state.facet_value(REALM, &policy_target).is_some());
    assert!(state.facet_value(REALM, &realm_target).is_some());
}

#[test]
fn policy_action_rejects_missing_policy_xor_and_rebinding_without_mutation() {
    let mut state = ProjectionState::default();
    let hlc = ServerHlc::new("policy-action-guards");

    let missing_policy = state.apply_projected(
        &operation(
            "ak.policy.action",
            policy_action_payload(Some(POLICY), None),
        ),
        &hlc,
    );
    assert!(matches!(
        missing_policy,
        ProjectionEffect::Rejected { ref reason }
            if reason == "policy_action_policy_unavailable"
    ));

    let both = state.apply_projected(
        &operation(
            "ak.policy.action",
            policy_action_payload(Some(POLICY), Some("slot")),
        ),
        &hlc,
    );
    assert!(matches!(both, ProjectionEffect::Rejected { .. }));

    let initial = policy_action_payload(None, Some("slot"));
    assert!(matches!(
        state.apply_projected(&operation("ak.policy.action", initial.clone()), &hlc),
        ProjectionEffect::PolicyActionProjected { .. }
    ));
    let target = FacetRef::new(facet::POLICY_ACTION_REALM_ACTION, "slot");
    let before = state.facet_value(REALM, &target).cloned().unwrap();

    let mut rebound = initial;
    rebound["value"]["action"] = Value::String("ak.message.revise".to_owned());
    assert!(matches!(
        state.apply_projected(&operation("ak.policy.action", rebound), &hlc),
        ProjectionEffect::Rejected { ref reason }
            if reason == arkret_wire::ErrorCode::CAS_CONFLICT
    ));
    assert_eq!(state.facet_value(REALM, &target), Some(&before));
    assert_eq!(state.facet_revision(REALM, &target), 1);
}

#[test]
fn policy_action_rejects_unknown_action_and_zero_quorum() {
    let mut state = ProjectionState::default();
    let hlc = ServerHlc::new("policy-action-shape");

    for (field, value) in [
        ("action", serde_json::json!("ak.future.unknown")),
        ("approval_quorum", serde_json::json!(0)),
    ] {
        let mut payload = policy_action_payload(None, Some("slot"));
        payload["value"][field] = value;
        assert!(matches!(
            state.apply_projected(&operation("ak.policy.action", payload), &hlc),
            ProjectionEffect::Rejected { .. }
        ));
    }
    assert!(
        state
            .facet_value(
                REALM,
                &FacetRef::new(facet::POLICY_ACTION_REALM_ACTION, "slot")
            )
            .is_none()
    );
}
