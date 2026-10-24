use super::*;

/// One reducer input: the projection Operation plus the content-bound Event id
/// the Station accepted it under.
///
/// The reducer derives every facet write from `kind + payload` itself, so a
/// test hands it the Operation and reads the settled facets back.
struct CallInput {
    /// The Event id this Operation was accepted under. It is derived from the
    /// Event's own content, so tests read it here instead of pinning a literal.
    event_id: arkret_identifiers::EventId,
    operation: Operation,
}

fn call_input(kind: &str, realm: &str, payload: Value) -> CallInput {
    call_input_at_seq(kind, realm, 0, payload)
}

/// Same, with an explicit distinguishing sequence. Two Events with identical
/// kind, Realm, payload and timestamp *are* the same Event and share one id; a
/// test that needs two distinct Events separates them here.
fn call_input_at_seq(kind: &str, realm: &str, distinct_seq: u64, payload: Value) -> CallInput {
    let event_id = derived_event_id_at_seq(kind, realm, distinct_seq, &payload);
    let mut operation_payload = payload;
    operation_payload
        .as_object_mut()
        .expect("call payload object")
        .insert("event_id".to_owned(), Value::String(event_id.to_string()));
    CallInput {
        event_id,
        operation: make_operation(kind, realm, operation_payload),
    }
}

fn apply_call(state: &mut ProjectionState, input: &CallInput, hlc: &ServerHlc) -> ProjectionEffect {
    state.apply_projected(&input.operation, hlc)
}

const TEST_REALM: &str = "ak:realm:ASReu6ls3Ao5vTK0TGXBCAvLLQChFejCEmN9KaSceZOt";

/// Assert the Event was rejected for exactly `expected`, printing the real
/// effect otherwise. A bare `matches!` hides the reason that makes a reducer
/// failure diagnosable.
#[track_caller]
fn expect_rejected(effect: ProjectionEffect, expected: &str) {
    match effect {
        ProjectionEffect::Rejected { reason } => assert_eq!(reason, expected),
        other => panic!("expected Rejected({expected}), got {other:?}"),
    }
}

/// Assert the Event projected call state, returning the CallId it projected.
#[track_caller]
fn expect_call_state_projected(effect: ProjectionEffect) -> String {
    match effect {
        ProjectionEffect::CallStateProjected { call_id } => call_id,
        other => panic!("expected CallStateProjected, got {other:?}"),
    }
}

/// Open a call through its own `ak.call.create` and return the Event-derived
/// CallId.
///
/// `call_state_payload.state_transition.from` is a required non-null lifecycle
/// state, so there is no "null predecessor" edge: the head a first
/// `ak.call.state` transitions off is the one the accepted create established.
#[track_caller]
fn create_call(
    state: &mut ProjectionState,
    hlc: &ServerHlc,
    realm: &str,
    initial_state: &str,
) -> String {
    let input = call_input(
        arkret_wire::EventKind::CallCreate.as_str(),
        realm,
        serde_json::json!({ "initial_state": initial_state }),
    );
    let expected = arkret_identifiers::CallId::from_event_id(&input.event_id).to_string();
    let call_id = expect_call_state_projected(apply_call(state, &input, hlc));
    assert_eq!(call_id, expected);
    call_id
}

/// The tagged wire form of a participant identity. `common-ids.schema.json`
/// `actor_id` is a closed discriminated union, never a bare principal id.
fn call_actor(principal_id: &str) -> Value {
    serde_json::to_value(account_actor(principal_id)).expect("actor id serializes")
}

fn call_facet_value<'a>(
    state: &'a ProjectionState,
    realm: &str,
    facet_name: &str,
    subject: &str,
) -> Option<&'a Value> {
    state.facet_value(realm, &FacetRef::new(facet_name, subject))
}

#[test]
fn call_create_derives_call_id_and_establishes_initial_state() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let realm = TEST_REALM;
    let input = call_input(
        arkret_wire::EventKind::CallCreate.as_str(),
        realm,
        serde_json::json!({"initial_state": "ringing"}),
    );
    // `call` is Event-derived: the id is the create Event token retyped, which
    // is exactly what this test is named for.
    let call_id = arkret_identifiers::CallId::from_event_id(&input.event_id).to_string();

    assert_eq!(
        expect_call_state_projected(apply_call(&mut state, &input, &hlc)),
        call_id
    );
    assert_eq!(
        call_facet_value(&state, realm, facet::CALL_STATE, &call_id).unwrap(),
        &serde_json::json!("ringing")
    );

    // `call_create_payload` is closed on `initial_state` alone: focus is an
    // `ak.call.state` axis and a create Event has no slot to carry it in.
    let with_focus = call_input(
        arkret_wire::EventKind::CallCreate.as_str(),
        realm,
        serde_json::json!({
            "initial_state": "ringing",
            "focus": {"mode": "sfu", "session_focus": "fra-1"}
        }),
    );
    expect_rejected(
        apply_call(&mut state, &with_focus, &hlc),
        arkret_wire::ReasonCode::CALL_STATE_TRANSITION_INVALID,
    );
}

#[test]
fn call_create_without_optional_focus_establishes_initial_state() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let realm = TEST_REALM;
    let input = call_input(
        arkret_wire::EventKind::CallCreate.as_str(),
        realm,
        serde_json::json!({"initial_state": "connecting"}),
    );
    let call_id = arkret_identifiers::CallId::from_event_id(&input.event_id).to_string();

    assert!(matches!(
        apply_call(&mut state, &input, &hlc),
        ProjectionEffect::CallStateProjected { call_id: id } if id == call_id
    ));
    assert_eq!(
        call_facet_value(&state, realm, facet::CALL_STATE, &call_id).unwrap(),
        &serde_json::json!("connecting")
    );
}

#[test]
fn call_create_is_idempotent_against_an_identical_settled_facet() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let realm = TEST_REALM;
    let input = call_input(
        arkret_wire::EventKind::CallCreate.as_str(),
        realm,
        serde_json::json!({"initial_state": "ringing"}),
    );
    let call_id = arkret_identifiers::CallId::from_event_id(&input.event_id).to_string();
    state.set_facet(
        realm,
        FacetRef::new(facet::CALL_STATE, &call_id),
        serde_json::json!("ringing"),
    );

    assert!(matches!(
        apply_call(&mut state, &input, &hlc),
        ProjectionEffect::CallStateProjected { call_id: id } if id == call_id
    ));
}

#[test]
fn call_state_projects_independent_state_focus_and_roster_facets() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let realm = TEST_REALM;
    let call_id = create_call(&mut state, &hlc, realm, "scheduled");
    let participant = serde_json::json!({
        "actor_id": call_actor("ak:did_core:web:bob.example"),
        "device_id": "ak:device:01904100-0000-7000-8000-d00000000001"
    });
    let input = call_input(
        arkret_wire::EventKind::CallState.as_str(),
        realm,
        serde_json::json!({
            "call_id": call_id,
            "state_transition": {"from": "scheduled", "to": "ringing"},
            "focus": {"mode": "sfu", "session_focus": "fra-1"},
            "roster_delta": {"op": "join", "participant": participant}
        }),
    );

    assert_eq!(
        expect_call_state_projected(apply_call(&mut state, &input, &hlc)),
        call_id
    );
    assert_eq!(
        call_facet_value(&state, realm, facet::CALL_STATE, &call_id).unwrap(),
        &serde_json::json!("ringing")
    );
    assert_eq!(
        call_facet_value(&state, realm, facet::CALL_FOCUS, &call_id).unwrap()["session_focus"],
        "fra-1"
    );
    // A list-valued call facet tags each entry with the accepted Event id that
    // produced it, which is the coordinate a later delta names.
    assert_eq!(
        call_facet_value(&state, realm, facet::CALL_ROSTER, &call_id).unwrap()[0]["tag_id"],
        Value::String(input.event_id.to_string())
    );
}

#[test]
fn focus_update_cannot_omit_or_replace_committed_session_focus() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let realm = TEST_REALM;
    let call_id = create_call(&mut state, &hlc, realm, "ringing");
    let first = call_input(
        arkret_wire::EventKind::CallState.as_str(),
        realm,
        serde_json::json!({
            "call_id": call_id,
            "focus": {"mode": "sfu", "session_focus": "fra-1"}
        }),
    );
    assert_eq!(
        expect_call_state_projected(apply_call(&mut state, &first, &hlc)),
        call_id
    );

    for value in [
        serde_json::json!({"mode": "mcu"}),
        serde_json::json!({"mode": "sfu", "session_focus": "iad-1"}),
    ] {
        let update = call_input(
            arkret_wire::EventKind::CallState.as_str(),
            realm,
            serde_json::json!({"call_id": call_id, "focus": value}),
        );
        expect_rejected(
            apply_call(&mut state, &update, &hlc),
            arkret_wire::ReasonCode::SESSION_FOCUS_ALREADY_COMMITTED,
        );
    }
    assert_eq!(
        call_facet_value(&state, realm, facet::CALL_FOCUS, &call_id).unwrap()["session_focus"],
        "fra-1"
    );
}

#[test]
fn moderation_removal_is_tagged_with_the_accepted_event_id() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let realm = TEST_REALM;
    let call_id = create_call(&mut state, &hlc, realm, "ringing");
    // `action: "ban"` is the whole-actor branch and therefore MUST NOT name a
    // device; only `kick` does.
    let removal = serde_json::json!({
        "actor_id": call_actor("ak:did_core:web:bob.example"),
        "action": "ban",
        "removed_by": "ak:did_core:web:mod.example",
        "removed_at": "2026-07-26T00:00:00.000Z"
    });
    let add = call_input(
        arkret_wire::EventKind::CallState.as_str(),
        realm,
        serde_json::json!({
            "call_id": call_id,
            "moderation_delta": {"op": "remove_participant", "removal": removal}
        }),
    );
    assert_eq!(
        expect_call_state_projected(apply_call(&mut state, &add, &hlc)),
        call_id
    );
    assert_eq!(
        call_facet_value(&state, realm, facet::CALL_MODERATION, &call_id).unwrap(),
        &serde_json::json!([{
            "tag_id": add.event_id.to_string(),
            "value": removal
        }])
    );

    // A second removal naming the same `(actor_id, action)` replaces the entry
    // rather than accumulating a duplicate, and carries the newer Event id.
    let replay = call_input_at_seq(
        arkret_wire::EventKind::CallState.as_str(),
        realm,
        1,
        serde_json::json!({
            "call_id": call_id,
            "moderation_delta": {"op": "remove_participant", "removal": removal}
        }),
    );
    assert_eq!(
        expect_call_state_projected(apply_call(&mut state, &replay, &hlc)),
        call_id
    );
    let entries = call_facet_value(&state, realm, facet::CALL_MODERATION, &call_id).unwrap();
    assert_eq!(entries.as_array().unwrap().len(), 1);
    assert_eq!(
        entries[0]["tag_id"],
        Value::String(replay.event_id.to_string())
    );
}

#[test]
fn recording_start_requires_consent_before_both_facets_are_written() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let realm = TEST_REALM;
    let call_id = create_call(&mut state, &hlc, realm, "ringing");
    let recording_id = "capture-1";
    let capture = FacetRef::composite(facet::CALL_RECORDING, &[call_id.as_str(), recording_id]);
    let capture_result = FacetRef::composite(
        facet::CALL_RECORDING_RESULT,
        &[call_id.as_str(), recording_id],
    );

    // `call-state.md` §5 / `call_recording_start_payload` close the consent gate
    // at the payload boundary: `capture_metadata.retention.consent_confirmed` is pinned to
    // `true`, so a start Event that never collected consent is not a well-formed
    // payload at all and cannot reach the capture facets.
    let start_payload = |consent_confirmed: bool| {
        serde_json::json!({
            "call_id": call_id,
            "recording_id": recording_id,
            "recording_agent_id": "ak:did_core:web:capture.example",
            "capture_kind": "recording",
            "mode": "audio_video",
            "visible_notice": true,
            "capture_metadata": {"retention": {"consent_confirmed": consent_confirmed}}
        })
    };
    let unconsented = call_input(
        arkret_wire::EventKind::CallRecordingStart.as_str(),
        realm,
        start_payload(false),
    );
    expect_rejected(
        apply_call(&mut state, &unconsented, &hlc),
        arkret_wire::ErrorCode::SCHEMA_VIOLATION,
    );
    assert!(state.facet_value(realm, &capture).is_none());
    assert!(state.facet_value(realm, &capture_result).is_none());

    // With consent confirmed the same start writes both capture facets. The
    // wire payload MUST NOT carry `recording_start_event_id`: this Event's id
    // depends on its own payload digest, so there is no fixed point for it.
    let consented = call_input(
        arkret_wire::EventKind::CallRecordingStart.as_str(),
        realm,
        start_payload(true),
    );
    assert_eq!(
        expect_call_state_projected(apply_call(&mut state, &consented, &hlc)),
        call_id
    );
    assert_eq!(
        state.facet_value(realm, &capture).unwrap(),
        &serde_json::json!("recording")
    );
    assert_eq!(
        state.facet_value(realm, &capture_result).unwrap()["retention"]["consent_confirmed"],
        Value::Bool(true)
    );
}

#[test]
fn call_transition_rejects_wrong_predecessor_and_terminal_exit() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let realm = TEST_REALM;
    let call_id = create_call(&mut state, &hlc, realm, "ringing");

    let wrong_predecessor = call_input(
        arkret_wire::EventKind::CallState.as_str(),
        realm,
        serde_json::json!({
            "call_id": call_id,
            "state_transition": {"from": "scheduled", "to": "connecting"}
        }),
    );
    expect_rejected(
        apply_call(&mut state, &wrong_predecessor, &hlc),
        arkret_wire::ReasonCode::CALL_STATE_TRANSITION_INVALID,
    );

    let missed = call_input(
        arkret_wire::EventKind::CallState.as_str(),
        realm,
        serde_json::json!({
            "call_id": call_id,
            "state_transition": {"from": "ringing", "to": "missed"}
        }),
    );
    assert_eq!(
        expect_call_state_projected(apply_call(&mut state, &missed, &hlc)),
        call_id
    );
    let revive = call_input(
        arkret_wire::EventKind::CallState.as_str(),
        realm,
        serde_json::json!({
            "call_id": call_id,
            "state_transition": {"from": "missed", "to": "active"}
        }),
    );
    expect_rejected(
        apply_call(&mut state, &revive, &hlc),
        arkret_wire::ReasonCode::CALL_STATE_TERMINAL,
    );
}

#[test]
fn unrecognized_payload_labels_do_not_bypass_the_lifecycle_edge() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let realm = TEST_REALM;
    let call_id = create_call(&mut state, &hlc, realm, "ringing");

    let transition = |to: &str| {
        call_input(
            arkret_wire::EventKind::CallState.as_str(),
            realm,
            serde_json::json!({
                "call_id": call_id,
                "state_transition": {"from": "ringing", "to": to}
            }),
        )
    };
    let labelled = |to: &str| {
        let mut input = transition(to);
        input.operation.payload.as_object_mut().unwrap().insert(
            "conflict_basis".to_owned(),
            Value::String("unstructured-label".to_owned()),
        );
        input
    };

    // `call_state_payload` is a closed object and carries no concurrency label:
    // `conflict_basis` is not a registered field, so an Event that smuggles one
    // is not admissible in the first place.
    expect_rejected(
        apply_call(&mut state, &labelled("active"), &hlc),
        arkret_wire::ErrorCode::SCHEMA_VIOLATION,
    );
    assert_eq!(
        call_facet_value(&state, realm, facet::CALL_STATE, &call_id).unwrap(),
        &Value::String("ringing".to_owned())
    );

    assert_eq!(
        expect_call_state_projected(apply_call(&mut state, &transition("active"), &hlc)),
        call_id
    );
    // The stream is totally ordered, so the second Event is simply a later
    // transition off a head that has already moved: no label in the payload
    // buys it a concurrent lane, with or without one.
    expect_rejected(
        apply_call(&mut state, &transition("missed"), &hlc),
        arkret_wire::ReasonCode::CALL_STATE_TRANSITION_INVALID,
    );
    expect_rejected(
        apply_call(&mut state, &labelled("missed"), &hlc),
        arkret_wire::ErrorCode::SCHEMA_VIOLATION,
    );
    assert_eq!(
        call_facet_value(&state, realm, facet::CALL_STATE, &call_id).unwrap(),
        &Value::String("active".to_owned())
    );
}
