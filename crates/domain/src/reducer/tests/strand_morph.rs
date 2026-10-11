use super::*;

#[test]
fn accepted_topic_set_and_unset_preserve_narrative_and_allow_independent_description_update() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("topic-narrative");
    let realm = "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb";
    let strand = "ak:strand:AbMObYvbipIn0nz_nVS0khLjwBPnTUlKZMk5TJ0w4k6A";
    let content = |body: &str| serde_json::json!({"kind":"ak.content.text", "body":body});
    let create = make_operation(
        arkret_wire::EventKind::StrandCreate,
        realm,
        serde_json::json!({"object":{
            "id":strand, "realm_id":realm,
            "metadata":{"title":"Original Chat"},
            "content":content("Original Description"),
            "created_by":account_actor("ak:did_core:web:alice.example"),
        }}),
    );
    assert!(matches!(
        state.apply(&create, &hlc),
        ProjectionEffect::StrandLifecycle { .. }
    ));
    let tracks = state.strands[strand].tracks.clone();
    // Only accepted updates enter this cache. Admission owns the exact
    // whole-value CAS and target validation in the native current writer.
    for topic in [
        serde_json::json!({"$op":"set", "value":{
            "space_id":"ak:space:ARkwFWDTPrObvpqVAL9kBsWkK8GrMr5FDO--3PcMFEwU", "rank":"a0"
        }}),
        serde_json::json!({"$op":"unset"}),
    ] {
        let update = make_operation(
            arkret_wire::EventKind::StrandUpdate,
            realm,
            serde_json::json!({"target_ref":strand,
                "expected_state_digest":format!("sha256:{}", "1".repeat(64)),
                "patch":{"topic":topic},
            }),
        );
        assert!(matches!(
            state.apply(&update, &hlc),
            ProjectionEffect::StrandLifecycle { .. }
        ));
        assert_eq!(state.strands[strand].title, "Original Chat");
        assert_eq!(
            state.strands[strand].content,
            Some(content("Original Description"))
        );
        assert_eq!(state.strands[strand].tracks, tracks);
    }
    let mixed = make_operation(
        arkret_wire::EventKind::StrandUpdate,
        realm,
        serde_json::json!({"target_ref":strand,
            "expected_state_digest":format!("sha256:{}", "2".repeat(64)),
            "patch":{"topic":{"$op":"set", "value":{
                    "space_id":"ak:space:ARkwFWDTPrObvpqVAL9kBsWkK8GrMr5FDO--3PcMFEwU", "rank":"b0"}},
                "content":{"$op":"set", "value":content("Updated Description")}},
        }),
    );
    assert!(matches!(
        state.apply(&mixed, &hlc),
        ProjectionEffect::StrandLifecycle { .. }
    ));
    assert_eq!(
        state.strands[strand].content,
        Some(content("Updated Description"))
    );
    assert_eq!(state.strands[strand].tracks, tracks);
}

// ── Strand lifecycle state-machine tests ──

/// End-to-end Strand lifecycle through the dispatcher: create → archive →
/// restore (no tombstone for Strand per spec). Verifies projection state
/// transitions correctly and effects carry the new state.
#[test]
fn strand_lifecycle_round_trip() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let realm_id = "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb";
    let strand_id = "ak:strand:ARkwFWDTPrObvpqVAL9kBsWkK8GrMr5FDO--3PcMFEwU";

    let create_effect = state.apply(
        &make_operation(
            arkret_wire::EventKind::StrandCreate,
            realm_id,
            serde_json::json!({
                "object": {
                    "id": strand_id,
                    "realm_id": realm_id,
                    "metadata": { "title": "Payment refactor" },
                    "created_by": account_actor("ak:did_core:web:alice.example"),
                }
            }),
        ),
        &hlc,
    );
    assert!(matches!(
        create_effect,
        ProjectionEffect::StrandLifecycle {
            new_state: ObjectLifecycleState::Active,
            ..
        }
    ));
    assert_eq!(state.strands[strand_id].state, ObjectLifecycleState::Active);

    let archive_effect = state.apply(
        &make_operation(
            arkret_wire::EventKind::StrandArchive,
            realm_id,
            serde_json::json!({ "target_ref": strand_id, "sender": "ak:did_core:web:alice.example" }),
        ),
        &hlc,
    );
    assert!(matches!(
        archive_effect,
        ProjectionEffect::StrandLifecycle {
            new_state: ObjectLifecycleState::Archived,
            ..
        }
    ));
    assert_eq!(
        state.strands[strand_id].state,
        ObjectLifecycleState::Archived
    );

    let restore_effect = state.apply(
        &make_operation(
            arkret_wire::EventKind::StrandRestore,
            realm_id,
            serde_json::json!({ "target_ref": strand_id, "sender": "ak:did_core:web:alice.example" }),
        ),
        &hlc,
    );
    assert!(matches!(
        restore_effect,
        ProjectionEffect::StrandLifecycle {
            new_state: ObjectLifecycleState::Active,
            ..
        }
    ));
    assert_eq!(state.strands[strand_id].state, ObjectLifecycleState::Active);
}

#[test]
fn strand_description_and_synthesis_are_projected_and_updated_independently() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let realm_id = "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb";
    let strand_id = "ak:strand:AbMObYvbipIn0nz_nVS0khLjwBPnTUlKZMk5TJ0w4k6A";

    let content = |body: &str| {
        serde_json::json!({
            "kind": "ak.content.text",
            "body": body,
        })
    };
    let create = make_operation(
        arkret_wire::EventKind::StrandCreate,
        realm_id,
        serde_json::json!({
            "object": {
                "id": strand_id,
                "realm_id": realm_id,
                "metadata": {
                    "title": "Independent narrative surfaces",
                    "summary": "remove me"
                },
                "content": content("Description v1"),
                "tracks": {
                    "synthesis": {
                        "content": content("Synthesis v1")
                    },
                    "discussion": {
                        "profile": "discussion"
                    }
                },
                "created_by": account_actor("ak:did_core:web:alice.example")
            }
        }),
    );
    assert!(matches!(
        state.apply(&create, &hlc),
        ProjectionEffect::StrandLifecycle { .. }
    ));
    assert_eq!(
        state.strands[strand_id].content,
        Some(content("Description v1"))
    );
    assert_eq!(
        serde_json::to_value(
            state.strands[strand_id].tracks["synthesis"]
                .content
                .as_ref()
                .unwrap()
        )
        .unwrap(),
        content("Synthesis v1")
    );

    let update_description = make_operation(
        arkret_wire::EventKind::StrandUpdate,
        realm_id,
        serde_json::json!({
            "target_ref": strand_id,
            "patch": {
                "content": {"$op": "set", "value": content("Description v2")},
                "metadata.summary": {"$op": "unset"}
            }
        }),
    );
    assert!(matches!(
        state.apply(&update_description, &hlc),
        ProjectionEffect::StrandLifecycle { .. }
    ));
    assert_eq!(state.strands[strand_id].summary, None);
    assert_eq!(
        state.strands[strand_id].content,
        Some(content("Description v2"))
    );
    assert_eq!(
        serde_json::to_value(
            state.strands[strand_id].tracks["synthesis"]
                .content
                .as_ref()
                .unwrap()
        )
        .unwrap(),
        content("Synthesis v1")
    );

    let update_synthesis = make_operation(
        arkret_wire::EventKind::StrandUpdate,
        realm_id,
        serde_json::json!({
            "target_ref": strand_id,
            "patch": {
                "tracks.synthesis.content": {
                    "$op": "set",
                    "value": content("Synthesis v2")
                }
            }
        }),
    );
    assert!(matches!(
        state.apply(&update_synthesis, &hlc),
        ProjectionEffect::StrandLifecycle { .. }
    ));
    assert_eq!(
        state.strands[strand_id].content,
        Some(content("Description v2"))
    );
    assert_eq!(
        serde_json::to_value(
            state.strands[strand_id].tracks["synthesis"]
                .content
                .as_ref()
                .unwrap()
        )
        .unwrap(),
        content("Synthesis v2")
    );
}

// ── Morph lifecycle state-machine tests ──

#[test]
fn morph_lifecycle_round_trip() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let realm_id = "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb";
    let morph_id = "ak:morph:AS1d_Z6XKI-1kUKHJzhW03e-rwaqgz8YKTgrTuK1QHRX";

    let create_effect = state.apply(
        &make_operation(
            arkret_wire::EventKind::MorphCreate,
            realm_id,
            serde_json::json!({
                "object": {
                    "id": morph_id,
                    "realm_id": realm_id,
                    "morph_kind": "task",
                    "metadata": { "title": "Backfill" },
                    "created_by": account_actor("ak:did_core:web:alice.example"),
                }
            }),
        ),
        &hlc,
    );
    assert!(matches!(
        create_effect,
        ProjectionEffect::MorphLifecycle {
            new_state: ObjectLifecycleState::Active,
            ..
        }
    ));
    assert_eq!(state.morphs[morph_id].state, ObjectLifecycleState::Active);

    state.apply(
        &make_operation(
            arkret_wire::EventKind::MorphArchive,
            realm_id,
            serde_json::json!({ "target_ref": morph_id }),
        ),
        &hlc,
    );
    assert_eq!(state.morphs[morph_id].state, ObjectLifecycleState::Archived);

    state.apply(
        &make_operation(
            arkret_wire::EventKind::MorphRestore,
            realm_id,
            serde_json::json!({ "target_ref": morph_id }),
        ),
        &hlc,
    );
    assert_eq!(state.morphs[morph_id].state, ObjectLifecycleState::Active);
}

#[test]
fn morph_lifecycle_preflight_rejects_illegal_transitions() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let realm_id = "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb";
    let morph_id = "ak:morph:AUG8WH2O5_vvqyBBXa6ohDqo0UIPecDCuYTH5WNez0yG";

    state.apply(
        &make_operation(
            arkret_wire::EventKind::MorphCreate,
            realm_id,
            serde_json::json!({
                "object": {
                    "id": morph_id,
                    "realm_id": realm_id,
                    "morph_kind": "task",
                    "metadata": { "title": "Backfill" },
                    "created_by": account_actor("ak:did_core:web:alice.example"),
                }
            }),
        ),
        &hlc,
    );

    // restore on Active → morph_not_archived
    let restore_op = make_operation(
        arkret_wire::EventKind::MorphRestore,
        realm_id,
        serde_json::json!({ "target_ref": morph_id }),
    );
    assert_eq!(
        state.check_morph_lifecycle_transition(&restore_op),
        Err("morph_not_archived")
    );

    state.apply(
        &make_operation(
            arkret_wire::EventKind::MorphArchive,
            realm_id,
            serde_json::json!({ "target_ref": morph_id }),
        ),
        &hlc,
    );
    let archive_again = make_operation(
        arkret_wire::EventKind::MorphArchive,
        realm_id,
        serde_json::json!({ "target_ref": morph_id }),
    );
    assert_eq!(
        state.check_morph_lifecycle_transition(&archive_again),
        Err("morph_not_active")
    );

    // Update on Archived → morph_not_active
    let update_op = make_operation(
        arkret_wire::EventKind::MorphUpdate,
        realm_id,
        serde_json::json!({
            "target_ref": morph_id,
            "patch": { "metadata.title": "Edit blocked" }
        }),
    );
    assert_eq!(
        state.check_morph_lifecycle_transition(&update_op),
        Err("morph_not_active")
    );
}

#[test]
fn morph_lifecycle_preflight_tolerates_unknown_morph() {
    let state = ProjectionState::new();
    let archive_unknown = make_operation(
        arkret_wire::EventKind::MorphArchive,
        "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb",
        serde_json::json!({ "target_ref": "ak:morph:nope-not-here" }),
    );
    assert_eq!(
        state.check_morph_lifecycle_transition(&archive_unknown),
        Ok(())
    );
}

// ── Strand position events (move / reorder) ──

fn create_position_spaces(state: &mut ProjectionState, hlc: &ServerHlc, realm_id: &str) {
    let board_id = "ak:space:AWxSgbLLtif391fvK_KYoPG0O0dFZnh9BWozK_Z3AoCj";
    for (id, kind, parent) in [
        (board_id, "board", None),
        (
            "ak:space:AcYTKs4ZiqRv25YJCWQZHLEXQk6KYMtujf2hpo1tUy99",
            "list",
            Some(board_id),
        ),
    ] {
        let effect = state.apply(
            &make_operation(
                arkret_wire::EventKind::SpaceCreate,
                realm_id,
                serde_json::json!({"object": {
                    "id": id,
                    "realm_id": realm_id,
                    "kind": kind,
                    "title": kind,
                    "parent_space_id": parent,
                    "created_by": account_actor("ak:did_core:web:alice.example"),
                }}),
            ),
            hlc,
        );
        assert!(
            !matches!(effect, ProjectionEffect::Rejected { .. }),
            "{effect:?}"
        );
    }
}

/// `ak.strand.move` / `ak.strand.reorder` touch the Strand projection's
/// `updated_at` / `updated_by` but do NOT change state. Position current
/// is installed by the Commit projection (out of scope here).
#[test]
fn strand_position_events_touch_projection_without_changing_state() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let realm_id = "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb";
    create_position_spaces(&mut state, &hlc, realm_id);
    let strand_id = "ak:strand:AU_4I9g0iCGP2wBQxEHHsqgKsyHl7hlCZ78tlwZ4LaoG";
    let board_space_id = "ak:space:AWxSgbLLtif391fvK_KYoPG0O0dFZnh9BWozK_Z3AoCj";

    state.apply(
        &make_operation(
            arkret_wire::EventKind::StrandCreate,
            realm_id,
            serde_json::json!({
                "object": {
                    "id": strand_id,
                    "realm_id": realm_id,
                    "metadata": { "title": "Launch" },
                    "created_by": account_actor("ak:did_core:web:alice.example"),
                }
            }),
        ),
        &hlc,
    );
    let created_state = state.strands[strand_id].state;
    let created_updated_at = state.strands[strand_id].updated_at;
    assert_eq!(created_state, ObjectLifecycleState::Active);
    assert!(
        created_updated_at.is_none(),
        "create does not set updated_at"
    );

    // ak.strand.move — state unchanged, updated_at advances.
    let move_effect = state.apply(
        &make_operation(
            arkret_wire::EventKind::StrandMove,
            realm_id,
            serde_json::json!({
                "strand_id": strand_id,
                "board_space_id": board_space_id,
                "target_space_id": "ak:space:AcYTKs4ZiqRv25YJCWQZHLEXQk6KYMtujf2hpo1tUy99",
                "rank": "a1",
                "sender": "ak:did_core:web:alice.example",
            }),
        ),
        &hlc,
    );
    assert!(matches!(
        move_effect,
        ProjectionEffect::StrandLifecycle {
            new_state: ObjectLifecycleState::Active,
            ..
        }
    ));
    assert_eq!(state.strands[strand_id].state, ObjectLifecycleState::Active);
    assert!(
        state.strands[strand_id].updated_at.is_some(),
        "move bumps updated_at"
    );
    assert_eq!(
        state.strands[strand_id].updated_by.as_deref(),
        Some(account_actor_string("ak:did_core:web:alice.example").as_str())
    );

    // ak.strand.reorder — same family, same effect.
    let reorder_effect = state.apply(
        &make_operation(
            arkret_wire::EventKind::StrandReorder,
            realm_id,
            serde_json::json!({
                "strand_id": strand_id,
                "board_space_id": board_space_id,
                "space_id": "ak:space:AcYTKs4ZiqRv25YJCWQZHLEXQk6KYMtujf2hpo1tUy99",
                "rank": "a2",
                "sender": "ak:did_core:web:alice.example",
            }),
        ),
        &hlc,
    );
    assert!(matches!(
        reorder_effect,
        ProjectionEffect::StrandLifecycle {
            new_state: ObjectLifecycleState::Active,
            ..
        }
    ));
    assert_eq!(state.strands[strand_id].state, ObjectLifecycleState::Active);
}

/// Unknown Strand position events are queued and replayed after backfill.
#[test]
fn strand_position_events_queue_unknown_strand() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let realm_id = "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb";
    create_position_spaces(&mut state, &hlc, realm_id);
    let strand_id = "ak:strand:AfPOoNzailKc-Iv8HrKJc7cV-a6XBnZOJ6gkRV2XI7xm";
    let effect = state.apply(
        &make_operation(
            arkret_wire::EventKind::StrandMove,
            realm_id,
            serde_json::json!({
                "strand_id": strand_id,
                "board_space_id": "ak:space:AWxSgbLLtif391fvK_KYoPG0O0dFZnh9BWozK_Z3AoCj",
                "target_space_id": "ak:space:AcYTKs4ZiqRv25YJCWQZHLEXQk6KYMtujf2hpo1tUy99",
                "rank": "a1",
            }),
        ),
        &hlc,
    );
    assert!(matches!(
        effect,
        ProjectionEffect::PendingReplayQueued { ref target_ref, .. } if target_ref == strand_id
    ));
    state.apply(
        &make_operation(
            arkret_wire::EventKind::StrandCreate,
            realm_id,
            serde_json::json!({
                "object": {
                    "id": strand_id,
                    "realm_id": realm_id,
                    "metadata": { "title": "Backfill target" },
                    "created_by": account_actor("ak:did_core:web:alice.example"),
                }
            }),
        ),
        &hlc,
    );
    assert!(!state.pending_replay.contains_key(strand_id));
    assert!(state.strands[strand_id].updated_at.is_some());
}

// ── ak.redaction -> Strand / Morph terminal-state push ──

/// `ak.redaction` carrying `target_ref: ak:strand:...` flips the
/// StrandProjection state to Redacted (terminal) per spec
/// common-fields.md §5.1.
/// `common-fields.md` §5.2: an active Strand carries exactly one content slot,
/// and `state=redacted` MUST clear both in the same transition. Materializing
/// the slot is what makes that verifiable from the projection alone; before
/// this the slot was never written, so the invariant held only vacuously.
#[test]
fn strand_content_slot_is_materialized_and_cleared_by_redaction() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let realm_id = "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb";

    state.apply(
        &make_operation(
            arkret_wire::EventKind::StrandCreate,
            realm_id,
            serde_json::json!({
                "object": {
                    "realm_id": realm_id,
                    "metadata": { "title": "Synthesis with a body" },
                    "content": {"kind": "ak.content.text", "body": "the synthesis body"},
                    "created_by": account_actor("ak:did_core:web:alice.example"),
                }
            }),
        ),
        &hlc,
    );

    // The Strand id is derived from the create Event, so read it back rather
    // than assuming the payload-supplied value.
    let strand_id = state
        .strands
        .keys()
        .next()
        .expect("create materialized a Strand")
        .clone();
    let created = &state.strands[&strand_id];
    assert_eq!(created.state, ObjectLifecycleState::Active);
    assert_eq!(
        created.content.as_ref().and_then(|c| c.get("body")),
        Some(&serde_json::json!("the synthesis body")),
        "an active Strand MUST materialize the plaintext content slot"
    );
    assert!(
        created.encrypted_content.is_none(),
        "the two content slots are mutually exclusive"
    );

    state.apply(
        &make_operation(
            arkret_wire::EventKind::Redaction,
            realm_id,
            serde_json::json!({
                "target_ref": strand_id,
                "sender": "ak:did_core:web:alice.example",
                "reason": "policy violation",
            }),
        ),
        &hlc,
    );

    let redacted = &state.strands[&strand_id];
    assert_eq!(redacted.state, ObjectLifecycleState::Redacted);
    assert!(
        redacted.content.is_none() && redacted.encrypted_content.is_none(),
        "state=redacted MUST clear both content slots in the same transition"
    );
}

/// Same invariant on the E2EE side and on Morph: `encrypted_content` is the
/// only slot present while active, and redaction clears it.
#[test]
fn morph_encrypted_content_slot_is_materialized_and_cleared_by_redaction() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let realm_id = "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb";

    state.apply(
        &make_operation(
            arkret_wire::EventKind::MorphCreate,
            realm_id,
            serde_json::json!({
                "object": {
                    "realm_id": realm_id,
                    "morph_kind": "task",
                    "encrypted_content": {"scheme": "mls_rfc9420", "ciphertext": "Y2lwaGVy"},
                    "created_by": account_actor("ak:did_core:web:alice.example"),
                }
            }),
        ),
        &hlc,
    );

    let morph_id = state
        .morphs
        .keys()
        .next()
        .expect("create materialized a Morph")
        .clone();
    let created = &state.morphs[&morph_id];
    assert_eq!(created.state, ObjectLifecycleState::Active);
    assert!(
        created.encrypted_content.is_some() && created.content.is_none(),
        "an active E2EE Morph MUST materialize exactly the encrypted slot"
    );

    state.apply(
        &make_operation(
            arkret_wire::EventKind::Redaction,
            realm_id,
            serde_json::json!({
                "target_ref": morph_id,
                "sender": "ak:did_core:web:alice.example",
            }),
        ),
        &hlc,
    );

    let redacted = &state.morphs[&morph_id];
    assert_eq!(redacted.state, ObjectLifecycleState::Redacted);
    assert!(
        redacted.content.is_none() && redacted.encrypted_content.is_none(),
        "state=redacted MUST clear both content slots in the same transition"
    );
}

#[test]
fn redaction_with_strand_target_ref_flips_to_redacted() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let realm_id = "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb";
    let strand_id = "ak:strand:AXyMATIk6ItFEFuxUFYiQILj_V_BJrSnUrD_z8WqOcYU";

    state.apply(
        &make_operation(
            arkret_wire::EventKind::StrandCreate,
            realm_id,
            serde_json::json!({
                "object": {
                    "id": strand_id,
                    "realm_id": realm_id,
                    "metadata": {"title": "Sensitive strand"},
                    "content": {"kind": "ak.content.text", "body": "Description"},
                    "tracks": {
                        "synthesis": {
                            "content": {"kind": "ak.content.text", "body": "Synthesis"}
                        }
                    },
                    "created_by": account_actor("ak:did_core:web:alice.example"),
                }
            }),
        ),
        &hlc,
    );
    assert_eq!(state.strands[strand_id].state, ObjectLifecycleState::Active);

    let effect = state.apply(
        &make_operation(
            arkret_wire::EventKind::Redaction,
            realm_id,
            serde_json::json!({
                "target_ref": strand_id,
                "sender": "ak:did_core:web:alice.example",
                "reason": "policy violation",
            }),
        ),
        &hlc,
    );
    assert!(matches!(
        effect,
        ProjectionEffect::StrandLifecycle {
            new_state: ObjectLifecycleState::Redacted,
            ..
        }
    ));
    assert_eq!(
        state.strands[strand_id].state,
        ObjectLifecycleState::Redacted
    );
    assert_eq!(state.strands[strand_id].content, None);
    assert_eq!(state.strands[strand_id].encrypted_content, None);
    assert_eq!(state.strands[strand_id].tracks["synthesis"].content, None);
    assert_eq!(
        state.strands[strand_id].tracks["synthesis"].encrypted_content,
        None
    );
    assert!(state.strands[strand_id].state.is_terminal());
}

/// Same for Morph via `target_ref: ak:morph:...`.
#[test]
fn redaction_with_morph_target_ref_flips_to_redacted() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let realm_id = "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb";
    let morph_id = "ak:morph:AZmU4Qxl4gM7TMnZH9Rg-nhGrZKjik5PC0e5O60tqnRj";

    state.apply(
        &make_operation(
            arkret_wire::EventKind::MorphCreate,
            realm_id,
            serde_json::json!({
                "object": {
                    "id": morph_id,
                    "realm_id": realm_id,
                    "morph_kind": "task",
                    "metadata": { "title": "Sensitive task" },
                    "created_by": account_actor("ak:did_core:web:alice.example"),
                }
            }),
        ),
        &hlc,
    );
    let effect = state.apply(
        &make_operation(
            arkret_wire::EventKind::Redaction,
            realm_id,
            serde_json::json!({
                "target_ref": morph_id,
                "sender": "ak:did_core:web:alice.example",
            }),
        ),
        &hlc,
    );
    assert!(matches!(
        effect,
        ProjectionEffect::MorphLifecycle {
            new_state: ObjectLifecycleState::Redacted,
            ..
        }
    ));
    assert_eq!(state.morphs[morph_id].state, ObjectLifecycleState::Redacted);
}

/// Preflight rejects `ak.redaction` against an already-terminal
/// Strand with `strand_already_terminal`. Mirror for Morph also covered.
#[test]
fn redaction_preflight_rejects_against_already_terminal() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let realm_id = "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb";
    let strand_id = "ak:strand:Af26wSYmVuaAU2oycakc40XzzWvvIBtczB9u8WHCju7C";
    let morph_id = "ak:morph:Ab3bL3vz55RjfKkZe1F1bZrx5n61CznPWoHlcPph9VpZ";

    // Materialise + redact a Strand once (legal first redaction).
    state.apply(
        &make_operation(
            arkret_wire::EventKind::StrandCreate,
            realm_id,
            serde_json::json!({
                "object": {
                    "id": strand_id,
                    "realm_id": realm_id,
                    "metadata": { "title": "Strand" },
                    "created_by": account_actor("ak:did_core:web:alice.example"),
                }
            }),
        ),
        &hlc,
    );
    state.apply(
        &make_operation(
            arkret_wire::EventKind::Redaction,
            realm_id,
            serde_json::json!({
                "target_ref": strand_id,
            }),
        ),
        &hlc,
    );
    assert_eq!(
        state.strands[strand_id].state,
        ObjectLifecycleState::Redacted
    );

    // Second redaction against the now-Redacted Strand → preflight rejects.
    let second_redact = make_operation(
        arkret_wire::EventKind::Redaction,
        realm_id,
        serde_json::json!({
            "target_ref": strand_id,
        }),
    );
    assert_eq!(
        state.check_redaction_target_transition(&second_redact),
        Err("strand_already_terminal")
    );

    // Same path for Morph.
    state.apply(
        &make_operation(
            arkret_wire::EventKind::MorphCreate,
            realm_id,
            serde_json::json!({
                "object": {
                    "id": morph_id,
                    "realm_id": realm_id,
                    "morph_kind": "task",
                    "metadata": { "title": "Task" },
                    "created_by": account_actor("ak:did_core:web:alice.example"),
                }
            }),
        ),
        &hlc,
    );
    state.apply(
        &make_operation(
            arkret_wire::EventKind::Redaction,
            realm_id,
            serde_json::json!({
                "target_ref": morph_id,
            }),
        ),
        &hlc,
    );
    let second_morph_redact = make_operation(
        arkret_wire::EventKind::Redaction,
        realm_id,
        serde_json::json!({
            "target_ref": morph_id,
        }),
    );
    assert_eq!(
        state.check_redaction_target_transition(&second_morph_redact),
        Err("morph_already_terminal")
    );
}

// ── Strand tracks update ──

/// `ak.strand.tracks.update` touches Strand.updated_at but never flips
/// lifecycle state. Parent Strand must be Active or the touch is
/// rejected with `strand_not_active` (defence-in-depth in the reducer,
/// mirroring the admission preflight).
#[test]
fn strand_tracks_update_touches_active_strand_only() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let realm_id = "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb";
    let strand_id = "ak:strand:Ab7vkkGszG32SQl5XNFwIalW1i5pxeEJuYWaOB_jG07M";

    state.apply(
        &make_operation(
            arkret_wire::EventKind::StrandCreate,
            realm_id,
            serde_json::json!({
                "object": {
                    "id": strand_id,
                    "realm_id": realm_id,
                    "metadata": { "title": "Launch" },
                    "created_by": account_actor("ak:did_core:web:alice.example"),
                }
            }),
        ),
        &hlc,
    );

    let effect = state.apply(
        &make_operation(
            arkret_wire::EventKind::StrandTracksUpdate,
            realm_id,
            serde_json::json!({
                "target_ref": strand_id,
                "patch": {
                    "tracks.synthesis.profile": {"$op": "set", "value": "synthesis"}
                },
                "sender": "ak:did_core:web:alice.example",
            }),
        ),
        &hlc,
    );
    assert!(matches!(
        effect,
        ProjectionEffect::StrandLifecycle {
            new_state: ObjectLifecycleState::Active,
            ..
        }
    ));
    assert_eq!(state.strands[strand_id].state, ObjectLifecycleState::Active);
    assert!(state.strands[strand_id].updated_at.is_some());
}

#[test]
fn strand_tracks_update_projects_discussion_enabled_state() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let realm_id = "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb";
    let strand_id = "ak:strand:Aa5iB1RxjJQGRA3dEWqQw_NLIlApcNM43DChfY6e3zSS";

    state.apply(
        &make_operation(
            arkret_wire::EventKind::StrandCreate,
            realm_id,
            serde_json::json!({
                "object": {
                    "id": strand_id,
                    "realm_id": realm_id,
                    "created_by": account_actor("ak:did_core:web:alice.example"),
                    "tracks": {
                        "discussion": {
                            "is_primary": true,
                            "profile": "discussion"
                        }
                    }
                }
            }),
        ),
        &hlc,
    );

    let tracks_op = make_operation(
        arkret_wire::EventKind::StrandTracksUpdate,
        realm_id,
        serde_json::json!({
            "target_ref": strand_id,
            // `strand-and-message.md` §4.6/§4.8 — closing the current primary
            // track MUST hand primary to another active track in the SAME
            // patch, so this disables `discussion` while promoting `synthesis`.
            "patch": {
                "tracks.discussion.enabled": {"$op": "set", "value": false},
                "tracks.discussion.is_primary": {"$op": "set", "value": false},
                "tracks.synthesis.enabled": {"$op": "set", "value": true},
                "tracks.synthesis.is_primary": {"$op": "set", "value": true}
            },
            "sender": "ak:did_core:web:alice.example",
        }),
    );
    assert_eq!(state.check_strand_tracks_transition(&tracks_op), Ok(()));
    let effect = state.apply(&tracks_op, &hlc);

    assert!(matches!(
        effect,
        ProjectionEffect::StrandLifecycle {
            new_state: ObjectLifecycleState::Active,
            ..
        }
    ));
    assert_eq!(
        state.strands[strand_id]
            .tracks
            .get(arkret_models_collaboration::objects::profiles::STRAND_TRACK_NAME_DISCUSSION)
            .and_then(|track| track.enabled),
        Some(false)
    );
}

#[test]
fn strand_tracks_update_cannot_change_synthesis_content() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let realm_id = "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb";
    let strand_id = "ak:strand:AQgceAHiTo7wM8zIQpQoEaHte0KDL0zzIWHJWEJPsLth";

    state.apply(
        &make_operation(
            arkret_wire::EventKind::StrandCreate,
            realm_id,
            serde_json::json!({
                "object": {
                    "id": strand_id,
                    "realm_id": realm_id,
                    "metadata": {"title": "Protected Synthesis"},
                    "tracks": {
                        "synthesis": {
                            "content": {"kind": "ak.content.text", "body": "Before"}
                        }
                    },
                    "created_by": account_actor("ak:did_core:web:alice.example")
                }
            }),
        ),
        &hlc,
    );

    let tracks_update = make_operation(
        arkret_wire::EventKind::StrandTracksUpdate,
        realm_id,
        serde_json::json!({
            "target_ref": strand_id,
            "patch": {
                "tracks.synthesis.content": {
                    "$op": "set",
                    "value": {"kind": "ak.content.text", "body": "After"}
                }
            }
        }),
    );
    assert_eq!(
        state.check_strand_tracks_transition(&tracks_update),
        Err("strand_tracks_content_forbidden")
    );
    assert!(matches!(
        state.apply(&tracks_update, &hlc),
        ProjectionEffect::Rejected { reason }
            if reason == "strand_tracks_content_forbidden"
    ));
    assert_eq!(
        state.strands[strand_id].tracks["synthesis"]
            .content
            .as_ref()
            .unwrap()
            .body,
        "Before"
    );
}

/// Preflight returns `strand_not_active` when parent Strand is archived
/// (or any non-Active state). Reducer-level enforcement is also
/// present as defence-in-depth — both verified here.
#[test]
fn strand_tracks_preflight_rejects_when_strand_archived() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let realm_id = "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb";
    let strand_id = "ak:strand:AcCWYj-xM3efHJWNJUyHf3deWiGljyO_OxLC6SxHaa1q";

    state.apply(
        &make_operation(
            arkret_wire::EventKind::StrandCreate,
            realm_id,
            serde_json::json!({
                "object": {
                    "id": strand_id,
                    "realm_id": realm_id,
                    "metadata": { "title": "Refactor" },
                    "created_by": account_actor("ak:did_core:web:alice.example"),
                }
            }),
        ),
        &hlc,
    );
    state.apply(
        &make_operation(
            arkret_wire::EventKind::StrandArchive,
            realm_id,
            serde_json::json!({ "target_ref": strand_id }),
        ),
        &hlc,
    );
    assert_eq!(
        state.strands[strand_id].state,
        ObjectLifecycleState::Archived
    );

    let tracks_op = make_operation(
        arkret_wire::EventKind::StrandTracksUpdate,
        realm_id,
        serde_json::json!({
            "target_ref": strand_id,
            "patch": {"tracks.synthesis.profile": {"$op": "set", "value": "synthesis"}}
        }),
    );
    assert_eq!(
        state.check_strand_tracks_transition(&tracks_op),
        Err("strand_not_active")
    );

    // Reducer-level defence: also rejects directly.
    let effect = state.apply(&tracks_op, &hlc);
    assert!(matches!(
        effect,
        ProjectionEffect::Rejected { ref reason } if reason == "strand_not_active"
    ));
}

/// Unknown Strand tolerated at the preflight (causal / backfill).
#[test]
fn strand_tracks_preflight_tolerates_unknown_strand() {
    let state = ProjectionState::new();
    let tracks_op = make_operation(
        arkret_wire::EventKind::StrandTracksUpdate,
        "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb",
        serde_json::json!({
            "target_ref": "ak:strand:nope-not-here",
            "patch": {"tracks.synthesis.profile": {"$op": "set", "value": "synthesis"}}
        }),
    );
    assert_eq!(state.check_strand_tracks_transition(&tracks_op), Ok(()));
}

/// Preflight tolerates redactions against unknown objects (causal /
/// backfill window) and against missing `target_ref` (message
/// redaction path).
#[test]
fn redaction_preflight_tolerates_unknown_object_or_message_path() {
    let state = ProjectionState::new();
    let realm_id = "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb";
    // Unknown target_ref.
    let unknown = make_operation(
        arkret_wire::EventKind::Redaction,
        realm_id,
        serde_json::json!({
            "target_ref": "ak:strand:nope-not-here",
        }),
    );
    assert_eq!(state.check_redaction_target_transition(&unknown), Ok(()));
    // Message redaction path: ak.message.redact carries message_id, never target_ref.
    let message_redact = make_operation(
        arkret_wire::EventKind::MessageRedact,
        realm_id,
        serde_json::json!({
            "message_id": "ak:message:Ac0LRpyxnIykXaDwQskZnvwSYer8TAeFhe0YNbbfj1Ec",
        }),
    );
    assert_eq!(
        state.check_redaction_target_transition(&message_redact),
        Ok(())
    );
}
