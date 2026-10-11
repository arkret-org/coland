use super::*;

// ── Business-progression stage axis (`common-fields.md` §5.3) ──
//
// v1 registers no per-Realm workflow-profile carrier (§5.3.4), so the core
// reducer enforces exactly six hard invariants and imposes no direction
// between the eight stage values. These tests pin all of that down.

const REALM: &str = "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb";

fn strand_create(strand_id: &str, stage: Option<&str>) -> Operation {
    let mut object = serde_json::json!({
        "id": strand_id,
        "realm_id": REALM,
        "metadata": { "title": "Implement login" },
        "created_by": account_actor("ak:did_core:web:alice.example"),
    });
    if let Some(stage) = stage {
        object
            .as_object_mut()
            .expect("create object")
            .insert("stage".to_owned(), serde_json::json!(stage));
    }
    make_operation(
        arkret_wire::EventKind::StrandCreate,
        REALM,
        serde_json::json!({ "object": object }),
    )
}

fn strand_stage_set(strand_id: &str, stage: &str) -> Operation {
    make_operation(
        arkret_wire::EventKind::StrandStageSet,
        REALM,
        serde_json::json!({ "strand_id": strand_id, "stage": stage }),
    )
}

fn morph_create(morph_id: &str, stage: Option<&str>) -> Operation {
    let mut object = serde_json::json!({
        "id": morph_id,
        "realm_id": REALM,
        "morph_kind": "task",
        "metadata": { "title": "Backfill" },
        "created_by": account_actor("ak:did_core:web:alice.example"),
    });
    if let Some(stage) = stage {
        object
            .as_object_mut()
            .expect("create object")
            .insert("stage".to_owned(), serde_json::json!(stage));
    }
    make_operation(
        arkret_wire::EventKind::MorphCreate,
        REALM,
        serde_json::json!({ "object": object }),
    )
}

fn morph_stage_set(morph_id: &str, stage: &str) -> Operation {
    make_operation(
        arkret_wire::EventKind::MorphStageSet,
        REALM,
        serde_json::json!({ "morph_id": morph_id, "stage": stage }),
    )
}

/// `ak.strand.create` projects an optional wire `stage`, and the first
/// `ak.strand.stage.set` writes both `stage` and the reducer-derived
/// `stage_changed_at` (`common-fields.md` §5.3.3 rule 3: the triggering
/// event's `created_at` is the only source).
#[test]
fn strand_stage_set_writes_stage_and_reducer_derived_timestamp() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let strand_id = "ak:strand:ARkwFWDTPrObvpqVAL9kBsWkK8GrMr5FDO--3PcMFEwU";

    state.apply(&strand_create(strand_id, Some("planned")), &hlc);
    assert_eq!(
        state.strands[strand_id].stage,
        Some(arkret_wire::ObjectStage::Planned)
    );
    // Create initializes the axis; it is not a transition, so the timestamp
    // stays absent.
    assert_eq!(state.strands[strand_id].stage_changed_at, None);

    let advance = strand_stage_set(strand_id, "done");
    let event_created_at = advance.created_at;
    let effect = state.apply(&advance, &hlc);
    assert!(matches!(
        effect,
        ProjectionEffect::StrandLifecycle {
            new_state: ObjectLifecycleState::Active,
            ..
        }
    ));
    assert_eq!(
        state.strands[strand_id].stage,
        Some(arkret_wire::ObjectStage::Done)
    );
    assert_eq!(
        state.strands[strand_id].stage_changed_at,
        Some(event_created_at)
    );
    // Stage is orthogonal to the physical lifecycle: `done` does not archive.
    assert_eq!(state.strands[strand_id].state, ObjectLifecycleState::Active);
}

/// A Strand created without `stage` takes its first value from
/// `ak.strand.stage.set` as an initialization, and the wire object's
/// `stage_changed_at` is ignored on create (§5.3.3 rule 3).
#[test]
fn strand_create_ignores_wire_supplied_stage_changed_at() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let strand_id = "ak:strand:AUzgWk6FQOO5CNGEhXKtRw7FKYOAXGqzSVCLuwh5qmkk";

    let create = make_operation(
        arkret_wire::EventKind::StrandCreate,
        REALM,
        serde_json::json!({
            "object": {
                "id": strand_id,
                "realm_id": REALM,
                "metadata": { "title": "Refactor" },
                "created_by": account_actor("ak:did_core:web:alice.example"),
                "stage": "draft",
                "stage_changed_at": "2020-01-01T00:00:00.000Z",
            }
        }),
    );
    state.apply(&create, &hlc);
    assert_eq!(
        state.strands[strand_id].stage,
        Some(arkret_wire::ObjectStage::Draft)
    );
    assert_eq!(state.strands[strand_id].stage_changed_at, None);
}

/// §5.3.3: v1 has no transition matrix carrier, so the core reducer accepts
/// every direction — including the two the deleted private transition used to reject.
#[test]
fn strand_stage_set_imposes_no_direction_rule() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let strand_id = "ak:strand:AeC6BSRzEkVPtZvqxpxC9cZzx8LzgKlSdyzxddWkHy9a";

    state.apply(&strand_create(strand_id, Some("planned")), &hlc);
    for (stage, expected) in [
        // Skips `in_progress` entirely.
        ("done", arkret_wire::ObjectStage::Done),
        // Reopens a closed item.
        ("in_progress", arkret_wire::ObjectStage::InProgress),
        ("cancelled", arkret_wire::ObjectStage::Cancelled),
        // Revives a cancelled item.
        ("planned", arkret_wire::ObjectStage::Planned),
        ("superseded", arkret_wire::ObjectStage::Superseded),
        ("blocked", arkret_wire::ObjectStage::Blocked),
        ("proposed", arkret_wire::ObjectStage::Proposed),
        ("draft", arkret_wire::ObjectStage::Draft),
    ] {
        let effect = state.apply(&strand_stage_set(strand_id, stage), &hlc);
        assert!(
            matches!(effect, ProjectionEffect::StrandLifecycle { .. }),
            "core reducer must accept {stage} from any predecessor"
        );
        assert_eq!(state.strands[strand_id].stage, Some(expected));
    }
}

/// §5.3.3 rule 4: a same-value self-transition is accepted but is not a
/// change — `stage_changed_at` and the audit columns MUST NOT move.
#[test]
fn strand_stage_set_same_value_leaves_stage_changed_at_untouched() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let strand_id = "ak:strand:AVn2mHTCEEyoAj8Wj-8IWs0zGDuqCoUwT1WrDMOa5MSt";

    state.apply(&strand_create(strand_id, Some("draft")), &hlc);
    state.apply(&strand_stage_set(strand_id, "in_progress"), &hlc);
    let changed_at = state.strands[strand_id].stage_changed_at;
    let updated_at = state.strands[strand_id].updated_at;
    assert!(changed_at.is_some());

    let effect = state.apply(&strand_stage_set(strand_id, "in_progress"), &hlc);
    assert!(matches!(effect, ProjectionEffect::StrandLifecycle { .. }));
    assert_eq!(
        state.strands[strand_id].stage,
        Some(arkret_wire::ObjectStage::InProgress)
    );
    assert_eq!(state.strands[strand_id].stage_changed_at, changed_at);
    assert_eq!(state.strands[strand_id].updated_at, updated_at);
}

/// §5.3.3 rules 1-2, enforced both in the read-only admission preflight and
/// again in the reducer so an event that bypasses admission cannot land.
#[test]
fn strand_stage_set_is_refused_on_archived_and_terminal_objects() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let strand_id = "ak:strand:AWk3Cy1sxOaFJhOF5oy5vQb7ULTYr3bJyEA1sxRB1w9L";

    state.apply(&strand_create(strand_id, Some("planned")), &hlc);
    state.apply(
        &make_operation(
            arkret_wire::EventKind::StrandArchive,
            REALM,
            serde_json::json!({ "target_ref": strand_id }),
        ),
        &hlc,
    );

    let archived = strand_stage_set(strand_id, "done");
    assert!(matches!(
        state.apply(&archived, &hlc),
        ProjectionEffect::Rejected { ref reason } if reason == "strand_not_active"
    ));
    assert_eq!(
        state.strands[strand_id].stage,
        Some(arkret_wire::ObjectStage::Planned)
    );

    state.strands.get_mut(strand_id).expect("strand").state = ObjectLifecycleState::Redacted;
    let terminal = strand_stage_set(strand_id, "done");
    assert!(matches!(
        state.apply(&terminal, &hlc),
        ProjectionEffect::Rejected { ref reason } if reason == "strand_already_terminal"
    ));
}

/// An unknown target is causal / backfill, not an error: the stage event is
/// queued for replay like every other Strand mutation.
#[test]
fn strand_stage_set_on_unknown_strand_queues_pending_replay() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let strand_id = "ak:strand:AYRc8fL0uJ6bQeqf3XvXwLyRLROGvBjZL5mCq6Uu3Kdi";

    let op = strand_stage_set(strand_id, "blocked");
    assert!(matches!(
        state.apply(&op, &hlc),
        ProjectionEffect::PendingReplayQueued { ref reason, .. } if reason == "strand_unknown"
    ));
}

/// §5.3.3 rule 6 — `stage` / `stage_changed_at` are single-sourced on
/// `ak.<kind>.stage.set`; an `ak.strand.update` patch on either path is
/// refused and leaves the projected axis alone.
#[test]
fn strand_update_patch_on_the_stage_axis_is_refused() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let strand_id = "ak:strand:AZAoOSCcHrDG3pmMYFTAOZ6xVFhGeCEXP6WFXeaAy0Ta";

    state.apply(&strand_create(strand_id, Some("planned")), &hlc);
    for patch in [
        serde_json::json!({ "stage": "done" }),
        serde_json::json!({ "stage_changed_at": "2030-01-01T00:00:00.000Z" }),
    ] {
        let error = arkret_event_draft::validate_event_payload(
            &arkret_wire::EventKind::StrandUpdate,
            &serde_json::json!({ "target_ref": strand_id, "patch": patch }),
        )
        .expect_err("stage-axis patches must be rejected before operation projection");
        assert!(error.to_string().contains("forbidden wire field patch:"));
    }
    assert_eq!(
        state.strands[strand_id].stage,
        Some(arkret_wire::ObjectStage::Planned)
    );
    assert_eq!(state.strands[strand_id].stage_changed_at, None);
}

/// `ak.morph.stage.set` is the same contract on the Morph axis: optional at
/// create, no direction rule, reducer-derived timestamp, same-value no-op and
/// the same two physical-lifecycle guards.
#[test]
fn morph_stage_set_matches_the_strand_contract() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let morph_id = "ak:morph:AS1d_Z6XKI-1kUKHJzhW03e-rwaqgz8YKTgrTuK1QHRX";

    // A generic data Morph omits stage; the first stage event initializes it.
    state.apply(&morph_create(morph_id, None), &hlc);
    assert_eq!(state.morphs[morph_id].stage, None);
    assert_eq!(state.morphs[morph_id].stage_changed_at, None);

    let initialize = morph_stage_set(morph_id, "done");
    let event_created_at = initialize.created_at;
    assert!(matches!(
        state.apply(&initialize, &hlc),
        ProjectionEffect::MorphLifecycle { .. }
    ));
    assert_eq!(
        state.morphs[morph_id].stage,
        Some(arkret_wire::ObjectStage::Done)
    );
    assert_eq!(
        state.morphs[morph_id].stage_changed_at,
        Some(event_created_at)
    );

    // Backwards is legal.
    state.apply(&morph_stage_set(morph_id, "in_progress"), &hlc);
    assert_eq!(
        state.morphs[morph_id].stage,
        Some(arkret_wire::ObjectStage::InProgress)
    );

    // Same-value self-transition does not move the timestamp.
    let changed_at = state.morphs[morph_id].stage_changed_at;
    state.apply(&morph_stage_set(morph_id, "in_progress"), &hlc);
    assert_eq!(state.morphs[morph_id].stage_changed_at, changed_at);

    // Archived Morph refuses the write in the preflight and in the reducer.
    state.apply(
        &make_operation(
            arkret_wire::EventKind::MorphArchive,
            REALM,
            serde_json::json!({ "target_ref": morph_id }),
        ),
        &hlc,
    );
    let archived = morph_stage_set(morph_id, "done");
    assert_eq!(
        state.check_morph_lifecycle_transition(&archived),
        Err("morph_not_active")
    );
    assert!(matches!(
        state.apply(&archived, &hlc),
        ProjectionEffect::Rejected { ref reason } if reason == "morph_not_active"
    ));

    state.morphs.get_mut(morph_id).expect("morph").state = ObjectLifecycleState::Redacted;
    let terminal = morph_stage_set(morph_id, "done");
    assert_eq!(
        state.check_morph_lifecycle_transition(&terminal),
        Err("morph_already_terminal")
    );
    assert!(matches!(
        state.apply(&terminal, &hlc),
        ProjectionEffect::Rejected { ref reason } if reason == "morph_already_terminal"
    ));
}

/// The projected stage round-trips through the SDK enum's own serde mapping;
/// coland never re-declares the protocol enumeration and rejects any spelling
/// outside it.
#[test]
fn stage_wire_values_round_trip_through_the_sdk_enum() {
    for value in [
        "draft",
        "proposed",
        "planned",
        "in_progress",
        "blocked",
        "done",
        "cancelled",
        "superseded",
    ] {
        let stage = object_stage_from_wire_value(value).expect("registered stage value");
        assert_eq!(object_stage_wire_value(&stage), value);
    }
    assert!(object_stage_from_wire_value("needs_review").is_none());
    assert!(object_stage_from_wire_value("todo").is_none());
}
