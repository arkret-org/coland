//! `security_class=high_assurance` federation-policy enforcement.

use arkret_event_draft::ProjectedEventOperation as Operation;
use coland_domain::hlc::ServerHlc;
use coland_domain::reducer::{ProjectionEffect, ProjectionState};
use serde_json::json;

const REALM: &str = "ak:realm:ATYL-87CDhaLQem29G2JQCXbZ_8zuu7khej2MbrsGLK6";

fn policy_operation(policy_revision: u64, federation_policy: &str) -> Operation {
    arkret_event_draft::test_support::raw_projected_operation(
        arkret_identifiers::OperationId::new(format!("ak:operation:{}", uuid::Uuid::now_v7()))
            .unwrap(),
        arkret_identifiers::RealmId::new(REALM).unwrap(),
        arkret_wire::EventKind::RealmPolicyBundle.as_str(),
        json!({
            "policy_revision": policy_revision,
            "federation_policy": federation_policy,
        }),
    )
}

fn state_with_security_class(security_class: &str) -> ProjectionState {
    let mut state = ProjectionState::new();
    state.set_realm_facet(
        REALM,
        coland_domain::reducer::facet::REALM_GENESIS,
        json!({"security_class": security_class}),
    );
    state
}

#[test]
fn high_assurance_rejects_open_or_omitted_federation_policy() {
    let mut state = state_with_security_class("high_assurance");
    let effect = state.apply(&policy_operation(1, "open"), &ServerHlc::new("test"));
    assert!(matches!(
        effect,
        ProjectionEffect::Rejected { reason }
            if reason == "high_assurance_federation_policy_invalid"
    ));

    let omitted = arkret_event_draft::test_support::raw_projected_operation(
        arkret_identifiers::OperationId::new(format!("ak:operation:{}", uuid::Uuid::now_v7()))
            .unwrap(),
        arkret_identifiers::RealmId::new(REALM).unwrap(),
        arkret_wire::EventKind::RealmPolicyBundle.as_str(),
        json!({"policy_revision": 1, "content_encryption_floor": "e2ee_required"}),
    );
    let effect = state.apply(&omitted, &ServerHlc::new("test"));
    assert!(matches!(
        effect,
        ProjectionEffect::Rejected { reason }
            if reason == "schema_violation"
    ));
}

#[test]
fn high_assurance_accepts_closed_restricted_and_quarantine() {
    for policy in ["closed", "restricted", "quarantine"] {
        let mut state = state_with_security_class("high_assurance");
        let effect = state.apply(&policy_operation(1, policy), &ServerHlc::new("test"));
        assert!(matches!(
            effect,
            ProjectionEffect::RealmPolicyBundleProjected { .. }
        ));
        assert_eq!(
            state.realm_federation_policy(REALM).as_deref(),
            Some(policy)
        );
    }
}

#[test]
fn standard_realm_accepts_open_federation_policy() {
    let mut state = state_with_security_class("standard");
    let effect = state.apply(&policy_operation(1, "open"), &ServerHlc::new("test"));
    assert!(matches!(
        effect,
        ProjectionEffect::RealmPolicyBundleProjected { .. }
    ));
}
