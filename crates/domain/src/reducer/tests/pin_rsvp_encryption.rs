use super::*;

const REALM_ID: &str = "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb";
const STRAND_ID: &str = "ak:strand:AWZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZm";

fn encrypted_payload() -> Value {
    serde_json::json!({
        "version": "1.0",
        "content_type": "application/json",
        "encryption_context": {
            "epoch": 7u64,
            "group_state_ref": "ak:event:AZEvldDJcWI9IRHqP2BMibDDfc59Ax_LwrbsrQmeD6Ml"
        },
        "ciphertext": "Y2lwaGVydGV4dA",
    })
}

fn seed_pin_target(state: &mut ProjectionState, hlc: &ServerHlc) {
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
    state.set_realm_facet(
        REALM_ID,
        facet::REALM_GENESIS,
        serde_json::json!({"encryption_profile": "mls_rfc9420"}),
    );
    let mut create = make_operation(
        arkret_wire::EventKind::StrandCreate,
        REALM_ID,
        serde_json::json!({
            "object": {
                "id": STRAND_ID,
                "realm_id": REALM_ID,
                "schema_refs": ["ak.schema.calendar_event.v1"],
                "metadata": {
                    "title": "Planning",
                    "fields": {
                        "calendar": {
                            "start": "2026-06-22T09:00:00",
                            "end": "2026-06-22T10:00:00",
                            "timezone": "America/Los_Angeles",
                            "tzdb_version": "2025a",
                            "all_day": false,
                            "status": "confirmed",
                            "recurrence": {"frequency": "weekly"}
                        }
                    }
                },
                "created_by": "ak:did_core:web:alice.example"
            }
        }),
    );
    // The schedule revision the RSVP entry names is this exact Event ID.
    set_event_identity(&mut create, SCHEDULE_BASIS_DIGEST);
    let strand = state.apply(&create, hlc);
    assert!(
        !matches!(strand, ProjectionEffect::Rejected { .. }),
        "strand fixture failed: {strand:?}"
    );
}

fn pin_payload(note: Value) -> Value {
    serde_json::json!({
        "pin_scope": {"kind": "realm", "id": REALM_ID},
        "target_ref": STRAND_ID,
        "rank": "a0",
        "sender": "ak:did_core:web:alice.example",
        "note": note
    })
}

const SCHEDULE_BASIS_DIGEST: &str =
    "sha256:6666666666666666666666666666666666666666666666666666666666666666";
const RSVP_EVENT_DIGEST: &str =
    "sha256:1111111111111111111111111111111111111111111111111111111111111111";

/// The exact Event ID of the calendar revision the responder observed.
/// This is the same Event identity `seed_pin_target` stamps on Strand create.
fn schedule_basis_ref() -> Value {
    let digest = arkret_identifiers::Hash::new(SCHEDULE_BASIS_DIGEST).expect("basis digest parses");
    let event_id = arkret_identifiers::EventId::from_event_digest(&digest)
        .expect("basis digest is an EventId");
    serde_json::to_value(event_id).expect("event id serializes")
}

fn rsvp_payload(encrypted_response: Value) -> Value {
    rsvp_payload_for("accepted", Value::Null, encrypted_response)
}

/// `entry` is the whole state model value, so the basis and the response travel
/// together and every head can be interpreted on its own.
fn rsvp_payload_for(status: &str, occurrence: Value, _unused: Value) -> Value {
    serde_json::json!({
        "event_ref": STRAND_ID,
        "occurrence": occurrence,
        "sender": "ak:did_core:web:alice.example",
        "entry": {
            "schedule_basis_refs": [schedule_basis_ref()],
            "response": {"status": status}
        }
    })
}

fn set_event_identity(operation: &mut arkret_event_draft::ProjectedEventOperation, digest: &str) {
    let digest = arkret_identifiers::Hash::new(digest).expect("event digest parses");
    let event_id = arkret_identifiers::EventId::from_event_digest(&digest)
        .expect("event digest forms an EventId");
    operation.context.canonical_event_digest = digest;
    operation.context.event_id = event_id.clone();
    operation.context.accepted_event_id = event_id;
}

/// An accepted RSVP Operation.
///
/// `apply_rsvp_set` re-derives the Event identity from the canonical Event
/// digest and refuses the pair when they disagree, so a fixture has to carry a
/// consistent `(digest, event_id)` the way an accepted envelope does.
fn rsvp_operation(payload: Value) -> arkret_event_draft::ProjectedEventOperation {
    let mut operation = make_operation(arkret_wire::EventKind::RsvpSet, REALM_ID, payload);
    set_event_identity(&mut operation, RSVP_EVENT_DIGEST);
    operation
}

#[test]
fn pin_note_rejects_plaintext_projection_payload() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    seed_pin_target(&mut state, &hlc);

    let effect = state.apply(
        &make_operation(
            arkret_wire::EventKind::PinAdd,
            REALM_ID,
            pin_payload(serde_json::json!("visible note")),
        ),
        &hlc,
    );

    assert!(matches!(
        effect,
        ProjectionEffect::Rejected { ref reason }
            if reason == "pin_note_encrypted_payload_required"
    ));
    assert!(state.pins.is_empty());
}

#[test]
fn pin_note_accepts_encrypted_projection_payload() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    seed_pin_target(&mut state, &hlc);
    let note = encrypted_payload();

    let effect = state.apply(
        &make_operation(
            arkret_wire::EventKind::PinAdd,
            REALM_ID,
            pin_payload(note.clone()),
        ),
        &hlc,
    );

    assert!(matches!(
        effect,
        ProjectionEffect::PinProjected { active: true, .. }
    ));
    let pin = state.pins.values().next().expect("pin should project");
    assert_eq!(pin.note.as_ref(), Some(&note));
}

#[test]
fn pin_note_rejects_envelope_committed_to_another_scope() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    seed_pin_target(&mut state, &hlc);
    let mut note = encrypted_payload();
    note["aad"]["scope_digest"] = serde_json::json!(format!("sha256:{}", "f".repeat(64)));

    let effect = state.apply(
        &make_operation(arkret_wire::EventKind::PinAdd, REALM_ID, pin_payload(note)),
        &hlc,
    );

    assert!(matches!(
        effect,
        ProjectionEffect::Rejected { ref reason }
            if reason == "pin_note_encrypted_payload_required"
    ));
    assert!(state.pins.is_empty());
}

#[test]
fn pin_note_rejects_unregistered_encryption_context_counter() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    seed_pin_target(&mut state, &hlc);
    let mut note = encrypted_payload();
    note["encryption_context"]["counter"] = Value::from(4u64);

    let effect = state.apply(
        &make_operation(
            arkret_wire::EventKind::PinAdd,
            REALM_ID,
            pin_payload(note.clone()),
        ),
        &hlc,
    );

    assert!(matches!(
        effect,
        ProjectionEffect::Rejected { ref reason }
            if reason == "pin_note_encrypted_payload_required"
    ));
    assert!(state.pins.is_empty());
}

#[test]
fn rsvp_target_must_be_an_active_calendar_in_the_same_realm() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    seed_pin_target(&mut state, &hlc);
    let operation = rsvp_operation(rsvp_payload(Value::Null));

    state
        .strands
        .get_mut(STRAND_ID)
        .expect("strand")
        .schema_refs
        .clear();
    let effect = state.apply(&operation, &hlc);
    assert!(
        matches!(
            effect,
            ProjectionEffect::Rejected { ref reason } if reason == "rsvp_event_not_calendar"
        ),
        "a Strand without the calendar schema ref cannot take an RSVP: {effect:?}"
    );

    state
        .strands
        .get_mut(STRAND_ID)
        .expect("strand")
        .schema_refs
        .push("ak.schema.calendar_event.v1".to_owned());
    state.strands.get_mut(STRAND_ID).expect("strand").realm_id =
        "ak:realm:Ab-zkG-9qydcyuk0bIAwMd1Op6VQjpOjQ1PbK_fCMMmz".to_owned();
    let effect = state.apply(&operation, &hlc);
    assert!(
        matches!(
            effect,
            ProjectionEffect::Rejected { ref reason } if reason == "rsvp_event_cross_realm"
        ),
        "an RSVP must not cross into another Realm's calendar: {effect:?}"
    );
}

#[test]
fn calendar_schedule_source_tracks_only_calendar_writes() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    seed_pin_target(&mut state, &hlc);
    assert_eq!(
        state.strands[STRAND_ID].schedule_revision_source.as_deref(),
        Some(SCHEDULE_BASIS_DIGEST)
    );

    let title_update = make_operation(
        arkret_wire::EventKind::StrandUpdate,
        REALM_ID,
        serde_json::json!({
            "target_ref": STRAND_ID,
            "patch": {"metadata.title": {"$op": "set", "value": "Renamed"}}
        }),
    );
    assert!(matches!(
        state.apply(&title_update, &hlc),
        ProjectionEffect::StrandLifecycle { .. }
    ));
    assert_eq!(
        state.strands[STRAND_ID].schedule_revision_source.as_deref(),
        Some(SCHEDULE_BASIS_DIGEST)
    );

    let next_digest = "sha256:7777777777777777777777777777777777777777777777777777777777777777";
    let mut schedule_update = make_operation(
        arkret_wire::EventKind::StrandUpdate,
        REALM_ID,
        serde_json::json!({
            "target_ref": STRAND_ID,
            "patch": {"metadata.fields.calendar": {"$op": "unset"}}
        }),
    );
    set_event_identity(&mut schedule_update, next_digest);
    assert!(matches!(
        state.apply(&schedule_update, &hlc),
        ProjectionEffect::StrandLifecycle { .. }
    ));
    assert_eq!(
        state.strands[STRAND_ID].schedule_revision_source.as_deref(),
        Some(next_digest)
    );
}

#[test]
fn rsvp_projects_the_complete_entry_as_the_settled_value() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    seed_pin_target(&mut state, &hlc);

    let effect = state.apply(&rsvp_operation(rsvp_payload(Value::Null)), &hlc);
    assert!(
        matches!(effect, ProjectionEffect::RsvpProjected { .. }),
        "series rsvp should project: {effect:?}"
    );
    assert_eq!(state.rsvps.len(), 1);
    let rsvp = state.rsvps.values().next().expect("rsvp should project");
    // The whole signed entry is the state model value: the response and the
    // basis it was given against travel together.
    assert_eq!(rsvp.entry["response"]["status"], "accepted");
    assert!(rsvp.entry.get("schedule_basis_refs").is_some());
    // Series RSVP keeps the signed JSON null rather than a sentinel string.
    assert_eq!(rsvp.occurrence, None);
}

#[test]
fn rsvp_schedule_basis_requires_one_exact_event_id() {
    for invalid_basis in [
        serde_json::json!([]),
        serde_json::json!([schedule_basis_ref(), schedule_basis_ref()]),
        serde_json::json!([SCHEDULE_BASIS_DIGEST]),
        serde_json::json!(["ak:event:not-an-event-id"]),
    ] {
        let mut state = ProjectionState::new();
        let hlc = ServerHlc::new("test");
        seed_pin_target(&mut state, &hlc);
        let mut payload = rsvp_payload(Value::Null);
        payload["entry"]["schedule_basis_refs"] = invalid_basis.clone();

        let effect = state.apply(&rsvp_operation(payload), &hlc);
        assert!(
            matches!(
                effect,
                ProjectionEffect::Rejected { ref reason } if reason == "rsvp_entry_invalid"
            ),
            "invalid schedule basis must fail closed: {invalid_basis}: {effect:?}"
        );
        assert!(state.rsvps.is_empty());
    }
}

#[test]
fn rsvp_occurrence_must_be_canonical_and_is_never_rewritten() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    seed_pin_target(&mut state, &hlc);

    // A UTC instant is not a canonical instance key. The cell subject derives
    // from the signed value, so the receiver rejects instead of repairing it.
    let effect = state.apply(
        &rsvp_operation(rsvp_payload_for(
            "accepted",
            serde_json::json!("2026-06-22T16:00:00.000Z"),
            Value::Null,
        )),
        &hlc,
    );
    assert!(
        matches!(
            effect,
            ProjectionEffect::Rejected { ref reason } if reason == "rsvp_occurrence_not_canonical"
        ),
        "a UTC instant is not a canonical instance key: {effect:?}"
    );

    let effect = state.apply(
        &rsvp_operation(rsvp_payload_for(
            "accepted",
            serde_json::json!("2026-06-22T09:00:00[America/Los_Angeles]"),
            Value::Null,
        )),
        &hlc,
    );
    assert!(
        matches!(effect, ProjectionEffect::RsvpProjected { .. }),
        "a canonical instance key should project: {effect:?}"
    );
    let rsvp = state
        .rsvps
        .values()
        .find(|cell| cell.occurrence.is_some())
        .expect("instance rsvp should project");
    assert_eq!(
        rsvp.occurrence.as_deref(),
        Some("2026-06-22T09:00:00[America/Los_Angeles]")
    );
}

#[test]
fn replaying_the_same_rsvp_event_changes_nothing() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    seed_pin_target(&mut state, &hlc);

    let operation = rsvp_operation(rsvp_payload(Value::Null));
    let first = state.apply(&operation, &hlc);
    assert!(
        matches!(first, ProjectionEffect::RsvpProjected { .. }),
        "the first rsvp should project: {first:?}"
    );
    let before = state
        .rsvps
        .values()
        .next()
        .map(|rsvp| (rsvp.entry.clone(), rsvp.source_event_id.clone()))
        .expect("rsvp should project");

    state.apply(&operation, &hlc);
    // One Event identity addresses one subject, so a replay settles the same
    // value on the same key instead of accumulating a second entry.
    assert_eq!(state.rsvps.len(), 1);
    let after = state
        .rsvps
        .values()
        .next()
        .map(|rsvp| (rsvp.entry.clone(), rsvp.source_event_id.clone()))
        .expect("rsvp should still project");
    assert_eq!(after, before);
}
