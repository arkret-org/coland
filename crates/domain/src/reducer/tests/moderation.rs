use super::*;

// ── P2 moderation control-plane projection (apply_moderation.rs) ──────
//
// decision -> moderation-state facet entry; lift -> removal of exactly the
// entry the named `decision_ref` wrote.

const MOD_REALM: &str = "ak:realm:AUFiO2if_pcrsCPNPTKGbSLg0Q25_sBaNHxyQyo5pn7z";
const MOD_DECISION_ID: &str = "ak:event:AaE8e4n3nA8AyIlk8Sh9_DhbS-5fInpC8DrDoA81pxI-";
const OTHER_DECISION_ID: &str = "ak:event:AaE8e4n3nA8AyIlk8Sh9_DhbS-5fInpC8DrDoA81pxJ-";
const MOD_TARGET_REF: &str = "ak:message:AUDcGyskAu9_TgDdHy4-tLmIbJp1s_rpjKSw3apHadK8";
const MOD_REQUEST_DIGEST: &str =
    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const OTHER_REQUEST_DIGEST: &str =
    "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

/// The facet a decision on `MOD_TARGET_REF` settles on.
fn mod_decision_facet() -> FacetRef {
    FacetRef::new(facet::MODERATION_STATE, MOD_TARGET_REF)
}

/// The element tag of a decision: the accepting Event's canonical
/// `<event_id>:0` dot, never a payload composite.
fn entry_tag(decision_id: &str) -> String {
    format!("{decision_id}:0")
}

fn moderation_decision_operation(
    decision_id: &str,
    issuer: &str,
    request_digest: &str,
) -> Operation {
    let mut operation = make_operation(
        arkret_wire::EventKind::ModerationDecision,
        MOD_REALM,
        serde_json::json!({
            "issuer_id": issuer,
            "target_ref": MOD_TARGET_REF,
            "decision": "quarantine",
            "action": "quarantine_message",
            "request_canonical_digest": request_digest,
        }),
    );
    let event_id = arkret_identifiers::EventId::new(decision_id).unwrap();
    operation.context.event_id = event_id.clone();
    operation.context.accepted_event_id = event_id;
    operation
}

fn seed_decision(state: &mut ProjectionState, hlc: &ServerHlc, issuer: &str) {
    let op = moderation_decision_operation(MOD_DECISION_ID, issuer, MOD_REQUEST_DIGEST);
    let effect = state.apply(&op, hlc);
    assert!(
        matches!(effect, ProjectionEffect::ModerationDecisionProjected { .. }),
        "decision should project, got {effect:?}"
    );
}

fn lift_operation(decision_id: &str, expected_revision: Value) -> Operation {
    make_operation(
        arkret_wire::EventKind::ModerationDecisionLift,
        MOD_REALM,
        serde_json::json!({
            "decision_ref": decision_id,
            "expected_revision": expected_revision,
            "target_ref": MOD_TARGET_REF,
            "realm_id": MOD_REALM,
        }),
    )
}

/// The typed `{commit_id, stream_position}` revision a lift names.
fn typed_revision() -> Value {
    serde_json::json!({
        "commit_id": "ak:realm_commit:AaE8e4n3nA8AyIlk8Sh9_DhbS-5fInpC8DrDoA81pxI-",
        "stream_position": 7,
    })
}

#[test]
fn moderation_decision_identity_uses_accepted_event_context() {
    let operation = moderation_decision_operation(
        MOD_DECISION_ID,
        "ak:did_core:web:mod.example",
        MOD_REQUEST_DIGEST,
    );
    assert!(operation.payload.get("decision_id").is_none());
    assert!(operation.payload.get("event_id").is_none());
    let mut replay = operation.clone();
    replay.operation_id =
        arkret_identifiers::OperationId::new(format!("ak:operation:{}", uuid::Uuid::now_v7()))
            .unwrap();
    assert_ne!(operation.operation_id, replay.operation_id);
    let hlc = ServerHlc::new("ak:did_core:web:test.coland");
    let mut original_state = ProjectionState::new();
    let mut replay_state = ProjectionState::new();
    for (state, input) in [
        (&mut original_state, &operation),
        (&mut replay_state, &replay),
    ] {
        assert!(matches!(
            state.apply(input, &hlc),
            ProjectionEffect::ModerationDecisionProjected { decision_id, .. }
                if decision_id == MOD_DECISION_ID
        ));
        assert!(state.moderation_decision_is_live(MOD_DECISION_ID));
    }
    assert_eq!(
        original_state.facet_value(MOD_REALM, &mod_decision_facet()),
        replay_state.facet_value(MOD_REALM, &mod_decision_facet())
    );
}

#[test]
fn moderation_decision_then_lift_converges_on_the_target_facet() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("ak:did_core:web:test.coland");
    seed_decision(&mut state, &hlc, "ak:did_core:web:mod.example");
    assert!(state.moderation_decision_is_live(MOD_DECISION_ID));
    assert!(!state.moderation_decision_is_lifted(MOD_DECISION_ID));
    assert_eq!(
        state.moderation_decision_issuer(MOD_DECISION_ID).as_deref(),
        Some("ak:did_core:web:mod.example")
    );
    let items = match state.facet_value(MOD_REALM, &mod_decision_facet()) {
        Some(Value::Array(items)) => items.clone(),
        other => panic!("moderation target facet should hold a keyed set, got {other:?}"),
    };
    // The element tag is the accepting Event's dot, not an issuer/digest
    // composite (`current-state.schema.json` canonical_event_dot).
    assert_eq!(
        items[0].get("tag_id").and_then(Value::as_str),
        Some(entry_tag(MOD_DECISION_ID).as_str())
    );

    // A lift carries the typed revision of the durable result it observed;
    // an untyped counter is not a revision and is rejected.
    let untyped = lift_operation(MOD_DECISION_ID, serde_json::json!(1));
    assert!(matches!(
        state.apply(&untyped, &hlc),
        ProjectionEffect::Rejected { ref reason }
            if reason.as_str() == "moderation_lift_expected_revision_missing"
    ));
    assert!(state.moderation_decision_is_live(MOD_DECISION_ID));

    let lift = lift_operation(MOD_DECISION_ID, typed_revision());
    let effect = state.apply(&lift, &hlc);
    assert!(matches!(
        effect,
        ProjectionEffect::ModerationDecisionLifted { .. }
    ));
    assert!(state.moderation_decision_is_lifted(MOD_DECISION_ID));
    assert!(!state.moderation_decision_is_live(MOD_DECISION_ID));
}

#[test]
fn lifting_one_review_never_lifts_another_issuers_decision() {
    // `content-moderation.md` section 2.6 -- lifting one review must not
    // implicitly lift another issuer's decision. Two issuers hold decisions on
    // the same target; the lift removes exactly the entry its `decision_ref`
    // wrote.
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("ak:did_core:web:test.coland");
    seed_decision(&mut state, &hlc, "ak:did_core:web:mod.example");
    let other = moderation_decision_operation(
        OTHER_DECISION_ID,
        "ak:did_core:web:other-mod.example",
        OTHER_REQUEST_DIGEST,
    );
    assert!(matches!(
        state.apply(&other, &hlc),
        ProjectionEffect::ModerationDecisionProjected { .. }
    ));
    assert!(state.moderation_decision_is_live(MOD_DECISION_ID));
    assert!(state.moderation_decision_is_live(OTHER_DECISION_ID));

    let lift = lift_operation(MOD_DECISION_ID, typed_revision());
    assert!(matches!(
        state.apply(&lift, &hlc),
        ProjectionEffect::ModerationDecisionLifted { .. }
    ));
    assert!(state.moderation_decision_is_lifted(MOD_DECISION_ID));
    assert!(state.moderation_decision_is_live(OTHER_DECISION_ID));
    // The surviving decision still drives the effective verdict.
    assert_eq!(
        state.effective_moderation_verdict(MOD_TARGET_REF),
        "quarantine"
    );
    let items = match state.facet_value(MOD_REALM, &mod_decision_facet()) {
        Some(Value::Array(items)) => items.clone(),
        other => panic!("moderation target facet should hold a keyed set, got {other:?}"),
    };
    assert_eq!(items.len(), 1);
    assert_eq!(
        items[0].get("tag_id").and_then(Value::as_str),
        Some(entry_tag(OTHER_DECISION_ID).as_str())
    );
}
