use super::*;

const REALM_ID: &str = "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb";
const CIRCLE_ID: &str = "ak:circle:AbdQDXGeR-uKf6HZP1Mt7cCkg1aM2OhVqu7lVR0WpgiI";
const STRAND_ID: &str = "ak:strand:AUAf2-oZl31wupPqnQLO-zloaqgMoX5xk2tpVSbi8zjD";
const MESSAGE_EVENT_ID: &str = "ak:event:AYqEzQ3jW02EHkMjxFQTlyeowxPQXJE4fI6JGOnzi23t";

fn seed_scoped_message(state: &mut ProjectionState, hlc: &ServerHlc) {
    let now = chrono::Utc::now();
    state.realm_states.insert(
        REALM_ID.to_owned(),
        ColandRealmState {
            realm_id: REALM_ID.to_owned(),
            owner: Some("ak:did_core:web:alice.example".to_owned()),
            title: Some("Product".to_owned()),
            deleted: false,

            created_at: now,
            updated_at: now,
            trust_domain: None,
            terminal_state: None,
            successor_realm_id: None,
            default_strand_id: None,
        },
    );
    state.members.insert(
        (
            REALM_ID.to_owned(),
            account_actor_string("ak:did_core:web:alice.example"),
        ),
        ColandMembershipState {
            member: account_actor_string("ak:did_core:web:alice.example"),
            realm_id: REALM_ID.to_owned(),
            state: "join".to_owned(),
            role: "member".to_owned(),
            membership_event_ref: None,
            invited_at: None,
            joined_at: now,
            updated_at: now,
            reason: None,
        },
    );
    let circle = state.apply(
        &make_operation(
            arkret_wire::EventKind::CircleCreate,
            REALM_ID,
            serde_json::json!({
                "object": {
                    "id": CIRCLE_ID,
                    "realm_id": REALM_ID,
                    "title": "Private",
                    "created_by": "ak:did_core:web:alice.example",
                    "join_rule": "public",
                    "encryption_profile": "mls_rfc9420",
                    "content_scheme": "mls_rfc9420"
                }
            }),
        ),
        hlc,
    );
    assert!(
        !matches!(circle, ProjectionEffect::Rejected { .. }),
        "circle fixture failed: {circle:?}"
    );
    let member = state.apply(
        &make_operation(
            arkret_wire::EventKind::CircleMemberState,
            REALM_ID,
            serde_json::json!({
                "circle_id": CIRCLE_ID,
                "member_id": account_actor("ak:did_core:web:alice.example"),
                "membership": "join",
                "sender": "ak:did_core:web:alice.example"
            }),
        ),
        hlc,
    );
    assert!(
        !matches!(member, ProjectionEffect::Rejected { .. }),
        "circle member fixture failed: {member:?}"
    );
    let strand = state.apply(
        &make_operation(
            arkret_wire::EventKind::StrandCreate,
            REALM_ID,
            serde_json::json!({
                "object": {
                    "id": STRAND_ID,
                    "realm_id": REALM_ID,
                    "scope_circle_id": CIRCLE_ID,
                    "metadata": {"title": "Private discussion"},
                    "created_by": "ak:did_core:web:alice.example"
                }
            }),
        ),
        hlc,
    );
    assert!(
        !matches!(strand, ProjectionEffect::Rejected { .. }),
        "strand fixture failed: {strand:?}"
    );
    let message = state.apply(
        &make_operation(
            arkret_wire::EventKind::MessageCreate,
            REALM_ID,
            serde_json::json!({
                "event_id": MESSAGE_EVENT_ID,
                "strand_id": STRAND_ID,
                "sender": "ak:did_core:web:alice.example",
                "content": {"kind": "ak.content.text", "body": "private"}
            }),
        ),
        hlc,
    );
    assert!(
        !matches!(message, ProjectionEffect::Rejected { .. }),
        "message fixture failed: {message:?}"
    );
}

fn pin_add(pin_scope: serde_json::Value) -> Operation {
    make_operation(
        arkret_wire::EventKind::PinAdd,
        REALM_ID,
        serde_json::json!({
            "pin_scope": pin_scope,
            "target_ref": MESSAGE_EVENT_ID,
            "rank": "a0",
            "sender": "ak:did_core:web:alice.example"
        }),
    )
}

#[test]
fn realm_pin_rejects_circle_scoped_message_target() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    seed_scoped_message(&mut state, &hlc);

    let operation = pin_add(serde_json::json!({"kind": "realm", "id": REALM_ID}));
    assert_eq!(state.check_pin_scope_safety(&operation), Err("not_found"));

    let effect = state.apply(&operation, &hlc);
    assert!(matches!(
        effect,
        ProjectionEffect::Rejected { ref reason } if reason == "not_found"
    ));
    assert!(state.pins.is_empty());
}

#[test]
fn circle_pin_accepts_same_circle_message_target() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    seed_scoped_message(&mut state, &hlc);

    let operation = pin_add(serde_json::json!({"kind": "circle", "id": CIRCLE_ID}));
    assert_eq!(state.check_pin_scope_safety(&operation), Ok(()));

    let effect = state.apply(&operation, &hlc);
    assert!(matches!(
        effect,
        ProjectionEffect::PinProjected { active: true, .. }
    ));
    assert_eq!(state.pins.len(), 1);
}

#[test]
fn pin_rejects_redacted_message_target() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    seed_scoped_message(&mut state, &hlc);

    state.apply(
        &make_operation(
            arkret_wire::EventKind::MessageRedact,
            REALM_ID,
            serde_json::json!({
                "message_id": MESSAGE_EVENT_ID.replace("ak:event:", "ak:message:"),
                "sender": "ak:did_core:web:alice.example"
            }),
        ),
        &hlc,
    );

    let operation = pin_add(serde_json::json!({"kind": "circle", "id": CIRCLE_ID}));
    assert_eq!(state.check_pin_scope_safety(&operation), Err("not_found"));
    assert!(!state.pin_target_is_visible_for_projection(MESSAGE_EVENT_ID));
}

#[test]
fn pin_rejects_quarantined_message_target() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    seed_scoped_message(&mut state, &hlc);
    // The decision is deliberately filed under a facet subject that is NOT the
    // message: an active decision must be found by the `target_ref` it carries,
    // not by the coordinate it happens to be stored at.
    state.set_facet(
        REALM_ID,
        FacetRef::new(facet::MODERATION_STATE, "decision-pin-quarantine"),
        serde_json::json!([{
            "tag": "decision-pin-quarantine",
            "value": {
                "decision_id": "decision-pin-quarantine",
                "target_ref": MESSAGE_EVENT_ID,
                "decision": "quarantine",
                "realm_id": REALM_ID
            }
        }]),
    );

    let operation = pin_add(serde_json::json!({"kind": "circle", "id": CIRCLE_ID}));
    assert_eq!(state.check_pin_scope_safety(&operation), Err("not_found"));
    assert!(!state.pin_target_is_visible_for_projection(MESSAGE_EVENT_ID));
}

#[test]
fn pin_rejects_active_moderation_decision_head() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    seed_scoped_message(&mut state, &hlc);
    state.set_facet(
        REALM_ID,
        FacetRef::new(facet::MODERATION_STATE, MESSAGE_EVENT_ID),
        serde_json::json!([{
            "tag": "ak:did_core:web:mod.example/sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "value": {
                "decision_id": "ak:event:AaCSkmkJGCJsdlTB9SXNQ9Ohes5_op9NMMetO0Trkf0q",
                "target_ref": MESSAGE_EVENT_ID,
                "decision": "hard_deny",
                "issuer_id": "ak:did_core:web:mod.example",
                "request_canonical_digest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "realm_id": REALM_ID
            }
        }, {
            "tag": "ak:did_core:web:other.example/sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            "value": {
                "decision_id": "ak:event:AcOfKRN6NaqA5lqbkGhhOD5HiIfpgFRFDsl7ay0xainV",
                "target_ref": MESSAGE_EVENT_ID,
                "decision": "require_review",
                "issuer_id": "ak:did_core:web:other.example",
                "request_canonical_digest": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                "realm_id": REALM_ID
            }
        }]),
    );

    let operation = pin_add(serde_json::json!({"kind": "circle", "id": CIRCLE_ID}));
    assert_eq!(state.check_pin_scope_safety(&operation), Err("not_found"));
    assert!(!state.pin_target_is_visible_for_projection(MESSAGE_EVENT_ID));
}
