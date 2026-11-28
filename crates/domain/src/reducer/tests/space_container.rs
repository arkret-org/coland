use super::*;

fn seed_realm_member(state: &mut ProjectionState, realm_id: &str, member: &str) {
    let now = chrono::Utc::now();
    let member = account_actor_string(member);
    state.realm_states.insert(
        realm_id.to_owned(),
        ColandRealmState {
            realm_id: realm_id.to_owned(),
            owner: Some(member.clone()),
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
        (realm_id.to_owned(), member.clone()),
        ColandMembershipState {
            member,
            realm_id: realm_id.to_owned(),
            state: "join".to_owned(),
            role: "member".to_owned(),
            membership_event_ref: None,
            invited_at: None,
            joined_at: now,
            updated_at: now,
            reason: None,
        },
    );
}

#[test]
fn space_structure_rejects_cross_realm_and_protects_archived_children() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let realm = "ak:realm:ATYL-87CDhaLQem29G2JQCXbZ_8zuu7khej2MbrsGLK6";
    let other = "ak:realm:AS1N4QnbZ6JgVObAF-yTx1GWoK2XnO_vUaZ2qe0WCyQV";
    let parent = "ak:space:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";
    let child = "ak:space:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1";
    let create = |id: &str, realm: &str, parent: Option<&str>| {
        make_operation(
            arkret_wire::EventKind::SpaceCreate,
            realm,
            serde_json::json!({"object": {"id":id,"realm_id":realm,"kind":"folder","title":"Space","parent_space_id":parent}}),
        )
    };
    assert!(matches!(
        state.apply(&create(parent, realm, None), &hlc),
        ProjectionEffect::SpaceContainerLifecycle { .. }
    ));
    assert!(
        matches!(state.apply(&create(child,other,Some(parent)),&hlc), ProjectionEffect::Rejected { reason } if reason == "space_realm_mismatch")
    );
    assert!(!state.space_containers.contains_key(child));
    assert!(matches!(
        state.apply(&create(child, realm, Some(parent)), &hlc),
        ProjectionEffect::SpaceContainerLifecycle { .. }
    ));
    let tombstone = make_operation(
        arkret_wire::EventKind::SpaceTombstone,
        realm,
        serde_json::json!({"space_id":parent}),
    );
    for archived in [false, true] {
        if archived {
            state.apply(
                &make_operation(
                    arkret_wire::EventKind::SpaceArchive,
                    realm,
                    serde_json::json!({"space_id":child}),
                ),
                &hlc,
            );
        }
        assert!(
            matches!(state.apply(&tombstone,&hlc), ProjectionEffect::Rejected { reason } if reason == "space_has_live_dependents")
        );
        assert_eq!(
            state.space_containers[parent].state,
            SpaceContainerLifecycleState::Active
        );
    }
    state.apply(
        &make_operation(
            arkret_wire::EventKind::SpaceTombstone,
            realm,
            serde_json::json!({"space_id":child}),
        ),
        &hlc,
    );
    assert!(matches!(
        state.apply(&tombstone, &hlc),
        ProjectionEffect::SpaceContainerLifecycle {
            new_state: SpaceContainerLifecycleState::Tombstoned,
            ..
        }
    ));
    assert!(
        matches!(state.apply(&create(child,realm,Some(parent)),&hlc), ProjectionEffect::Rejected { reason } if reason == "space_not_active")
    );
}

/// End-to-end Space-container lifecycle through the dispatcher: create →
/// archive (active → archived) → restore (archived → active) →
/// tombstone (active → tombstoned). Verifies the projection's
/// `space_containers` map tracks state transitions correctly and the
/// effects carry the new state.
#[test]
fn space_container_lifecycle_round_trip() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let realm_id = "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb";
    let container_space_id = "ak:space:Af5YDKFhOiySm76T_pF7GQrzaF8vEejTcqTWpmnqGUid";

    // create
    let create_effect = state.apply(
        &make_operation(
            arkret_wire::EventKind::SpaceCreate,
            realm_id,
            serde_json::json!({
                "object": {
                    "id": container_space_id,
                    "realm_id": realm_id,
                    "kind": "board",
                    "title": "Roadmap",
                    "created_by": account_actor("ak:did_core:web:alice.example"),
                }
            }),
        ),
        &hlc,
    );
    assert!(matches!(
        create_effect,
        ProjectionEffect::SpaceContainerLifecycle {
            new_state: SpaceContainerLifecycleState::Active,
            ..
        }
    ));
    assert_eq!(
        state.space_containers[container_space_id].state,
        SpaceContainerLifecycleState::Active
    );

    // archive
    let archive_effect = state.apply(
        &make_operation(
            arkret_wire::EventKind::SpaceArchive,
            realm_id,
            serde_json::json!({ "space_id": container_space_id }),
        ),
        &hlc,
    );
    assert!(matches!(
        archive_effect,
        ProjectionEffect::SpaceContainerLifecycle {
            new_state: SpaceContainerLifecycleState::Archived,
            ..
        }
    ));
    assert_eq!(
        state.space_containers[container_space_id].state,
        SpaceContainerLifecycleState::Archived
    );

    // restore
    let restore_effect = state.apply(
        &make_operation(
            arkret_wire::EventKind::SpaceRestore,
            realm_id,
            serde_json::json!({ "space_id": container_space_id }),
        ),
        &hlc,
    );
    assert!(matches!(
        restore_effect,
        ProjectionEffect::SpaceContainerLifecycle {
            new_state: SpaceContainerLifecycleState::Active,
            ..
        }
    ));
    assert_eq!(
        state.space_containers[container_space_id].state,
        SpaceContainerLifecycleState::Active
    );

    // tombstone
    let tombstone_effect = state.apply(
        &make_operation(
            arkret_wire::EventKind::SpaceTombstone,
            realm_id,
            serde_json::json!({ "space_id": container_space_id }),
        ),
        &hlc,
    );
    assert!(matches!(
        tombstone_effect,
        ProjectionEffect::SpaceContainerLifecycle {
            new_state: SpaceContainerLifecycleState::Tombstoned,
            ..
        }
    ));
    assert_eq!(
        state.space_containers[container_space_id].state,
        SpaceContainerLifecycleState::Tombstoned
    );
}

#[test]
fn space_update_and_parent_accept_canonical_payload_fields() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let realm_id = "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb";
    let container_space_id = "ak:space:ATu1E_hCvaxzpXDswPMlN3ypwETWAa7O994Etg387rA6";
    let parent_space_id = "ak:space:ATw_yJRaz2EEXAz-44u3FE2jGCVrpM3MQQZhKmxheDqW";

    state.apply(
        &make_operation(
            arkret_wire::EventKind::SpaceCreate,
            realm_id,
            serde_json::json!({
                "object": {
                    "id": container_space_id,
                    "realm_id": realm_id,
                    "kind": "list",
                    "title": "Original",
                    "created_by": "ak:did_core:web:alice.example"
                }
            }),
        ),
        &hlc,
    );

    let update = make_operation(
        arkret_wire::EventKind::SpaceUpdate,
        realm_id,
        serde_json::json!({
            "space_id": container_space_id,
            "patch": {
                "title": "Renamed",
                "rank": "mV"
            }
        }),
    );
    assert!(matches!(
        state.apply(&update, &hlc),
        ProjectionEffect::SpaceContainerLifecycle { .. }
    ));
    let projection = state.space_containers.get(container_space_id).unwrap();
    assert_eq!(projection.title, "Renamed");
    assert_eq!(projection.rank.as_deref(), Some("mV"));

    state.apply(
        &make_operation(
            arkret_wire::EventKind::SpaceCreate,
            realm_id,
            serde_json::json!({
                "object": {
                    "id": parent_space_id,
                    "realm_id": realm_id,
                    "kind": "list",
                    "title": "Parent",
                    "created_by": "ak:did_core:web:alice.example"
                }
            }),
        ),
        &hlc,
    );

    let parent = make_operation(
        arkret_wire::EventKind::SpaceParent,
        realm_id,
        serde_json::json!({
            "space_id": container_space_id,
            "parent_space_id": parent_space_id,
            "expected_parent_space_id": null
        }),
    );
    assert!(matches!(
        state.apply(&parent, &hlc),
        ProjectionEffect::SpaceContainerLifecycle { .. }
    ));
    assert_eq!(
        state
            .space_containers
            .get(container_space_id)
            .and_then(|projection| projection.parent_ref.as_deref()),
        Some(parent_space_id)
    );

    let detach = make_operation(
        arkret_wire::EventKind::SpaceParent,
        realm_id,
        serde_json::json!({
            "space_id": container_space_id,
            "parent_space_id": null,
            "expected_parent_space_id": parent_space_id
        }),
    );
    assert!(matches!(
        state.apply(&detach, &hlc),
        ProjectionEffect::SpaceContainerLifecycle { .. }
    ));
    assert_eq!(
        state
            .space_containers
            .get(container_space_id)
            .and_then(|projection| projection.parent_ref.as_deref()),
        None
    );
}

#[test]
fn space_wip_policy_is_projected_and_removed_scope_fields_fail_closed() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let realm_id = "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb";
    let space_id = "ak:space:AS7NdtRvqxhu3wM0FfhkaJOHklRLIXxt2MexCUKLYVNW";

    let create = make_operation(
        arkret_wire::EventKind::SpaceCreate,
        realm_id,
        serde_json::json!({
            "object": {
                "id": space_id,
                "realm_id": realm_id,
                "kind": "list",
                "title": "WIP",
                "fields": {
                    "max_active_strand_count": 5,
                    "active_strand_count_enforcement": "reject"
                }
            }
        }),
    );
    assert!(matches!(
        state.apply(&create, &hlc),
        ProjectionEffect::SpaceContainerLifecycle { .. }
    ));
    assert_eq!(
        state.space_containers[space_id].fields["max_active_strand_count"],
        5
    );

    for object in [
        serde_json::json!({
            "id": "ak:space:ASujtfVbzOJUKUPQGM2haq2Xp3OW3TLYL_OsrGxS14ho",
            "realm_id": realm_id,
            "kind": "board",
            "title": "Old default",
            "default_scope_circle_id": "ak:circle:AcVF18_h1TRZF8dst062H4HVS8SMxo5lixRPD5RAsjO0"
        }),
        serde_json::json!({
            "id": "ak:space:ASnybceDedhi_q3CcYCfbztACY6JONPn7OCMtvGMgAwh",
            "realm_id": realm_id,
            "kind": "list",
            "title": "Old floor",
            "child_scope_policy": {
                "kind": "require_e2ee",
                "metadata_encryption_floor": "e2ee_required"
            }
        }),
        serde_json::json!({
            "id": "ak:space:AR5k5m5-YAF7FIHTwcq19WS0wqEiyugxUIvWPqlos3GR",
            "realm_id": realm_id,
            "kind": "board",
            "title": "Wrong WIP owner",
            "fields": {"max_active_strand_count": 5, "active_strand_count_enforcement": "warn"}
        }),
    ] {
        let effect = state.apply(
            &make_operation(
                arkret_wire::EventKind::SpaceCreate,
                realm_id,
                serde_json::json!({"object": object}),
            ),
            &hlc,
        );
        assert!(matches!(
            effect,
            ProjectionEffect::Rejected { ref reason }
                if reason == arkret_wire::ErrorCode::SCHEMA_VIOLATION
        ));
    }
}

#[test]
fn space_container_child_order_tracks_rank_updates() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let realm_id = "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb";
    let board_id = "ak:space:AdF-OpLT-7la09L28Pgl41aEHXK3MEZNnwMNhc02Uz19";
    let first_id = "ak:space:AYqEzQ3jW02EHkMjxFQTlyeowxPQXJE4fI6JGOnzi23t";
    let second_id = "ak:space:Af0cDOgrSK-qWEvQvEo_FnP9vdEMz6mEq0IN2aIOIege";
    let third_id = "ak:space:Ab011A64KGiD6tDig3uj4h8KCKdwqNOWPLOlgFiyotsB";

    state.apply(
        &make_operation(
            arkret_wire::EventKind::SpaceCreate,
            realm_id,
            serde_json::json!({
                "object": {
                    "id": board_id,
                    "realm_id": realm_id,
                    "kind": "board",
                    "title": "Sprint",
                    "created_by": "ak:did_core:web:alice.example"
                }
            }),
        ),
        &hlc,
    );
    for (space_id, title, rank) in [
        (first_id, "First", "r001"),
        (second_id, "Second", "r002"),
        (third_id, "Third", "r003"),
    ] {
        state.apply(
            &make_operation(
                arkret_wire::EventKind::SpaceCreate,
                realm_id,
                serde_json::json!({
                    "object": {
                        "id": space_id,
                        "realm_id": realm_id,
                        "kind": "list",
                        "title": title,
                        "parent_space_id": board_id,
                        "rank": rank,
                        "created_by": "ak:did_core:web:alice.example"
                    }
                }),
            ),
            &hlc,
        );
    }

    state.apply(
        &make_operation(
            arkret_wire::EventKind::SpaceUpdate,
            realm_id,
            serde_json::json!({
                "space_id": third_id,
                "patch": { "rank": { "$op": "set", "value": "r000" } }
            }),
        ),
        &hlc,
    );

    let value = state.child_order_facet_value(board_id);
    let titles = value["children"]
        .as_array()
        .expect("children array")
        .iter()
        .map(|entry| entry["title"].as_str().expect("title"))
        .collect::<Vec<_>>();
    assert_eq!(titles, ["Third", "First", "Second"]);
    assert_eq!(
        value["order"].as_array().expect("order array")[0].as_str(),
        Some(third_id)
    );
}

#[test]
fn space_list_archive_restore_and_tombstone_protect_card_lifecycle_and_rank() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let realm_id = "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb";
    let board_id = "ak:space:AdF-OpLT-7la09L28Pgl41aEHXK3MEZNnwMNhc02Uz19";
    let list_id = "ak:space:AYqEzQ3jW02EHkMjxFQTlyeowxPQXJE4fI6JGOnzi23t";
    let strand_id = "ak:strand:AUAf2-oZl31wupPqnQLO-zloaqgMoX5xk2tpVSbi8zjD";

    state.apply(
        &make_operation(
            arkret_wire::EventKind::SpaceCreate,
            realm_id,
            serde_json::json!({
                "object": {
                    "id": board_id,
                    "realm_id": realm_id,
                    "kind": "board",
                    "title": "Sprint",
                    "created_by": "ak:did_core:web:alice.example"
                }
            }),
        ),
        &hlc,
    );
    state.apply(
        &make_operation(
            arkret_wire::EventKind::SpaceCreate,
            realm_id,
            serde_json::json!({
                "object": {
                    "id": list_id,
                    "realm_id": realm_id,
                    "kind": "list",
                    "title": "Todo",
                    "parent_space_id": board_id,
                    "rank": "r001",
                    "created_by": "ak:did_core:web:alice.example"
                }
            }),
        ),
        &hlc,
    );
    state.apply(
        &make_operation(
            arkret_wire::EventKind::StrandCreate,
            realm_id,
            serde_json::json!({
                "object": {
                    "id": strand_id,
                    "realm_id": realm_id,
                    "metadata": {
                        "title": "Review PR"
                    },
                    "created_by": "ak:did_core:web:alice.example"
                }
            }),
        ),
        &hlc,
    );
    state.apply(
        &make_operation(
            arkret_wire::EventKind::StrandMove,
            realm_id,
            serde_json::json!({
                "strand_id": strand_id,
                "board_space_id": board_id,
                "target_space_id": list_id,
                "rank": "r007"
            }),
        ),
        &hlc,
    );
    state.apply(
        &make_operation(
            arkret_wire::EventKind::SpaceArchive,
            realm_id,
            serde_json::json!({ "space_id": list_id }),
        ),
        &hlc,
    );
    assert_eq!(state.strands[strand_id].state, ObjectLifecycleState::Active);
    let tombstone = make_operation(
        arkret_wire::EventKind::SpaceTombstone,
        realm_id,
        serde_json::json!({"space_id":list_id}),
    );
    assert!(
        matches!(state.apply(&tombstone, &hlc), ProjectionEffect::Rejected { reason } if reason == "space_has_live_dependents")
    );
    let relation = state
        .relations
        .values()
        .find(|relation| relation.to_object_ref() == Some(strand_id))
        .expect("strand position relation");
    assert_eq!(relation.rank.as_deref(), Some("r007"));

    state.apply(
        &make_operation(
            arkret_wire::EventKind::SpaceRestore,
            realm_id,
            serde_json::json!({ "space_id": list_id }),
        ),
        &hlc,
    );
    assert_eq!(state.strands[strand_id].state, ObjectLifecycleState::Active);
    let relation = state
        .relations
        .values()
        .find(|relation| relation.to_object_ref() == Some(strand_id))
        .expect("strand position relation");
    assert_eq!(relation.rank.as_deref(), Some("r007"));
    state.apply(
        &make_operation(
            arkret_wire::EventKind::StrandArchive,
            realm_id,
            serde_json::json!({"target_ref":strand_id}),
        ),
        &hlc,
    );
    assert_eq!(
        state.strands[strand_id].state,
        ObjectLifecycleState::Archived
    );
    assert!(
        matches!(state.apply(&tombstone, &hlc), ProjectionEffect::Rejected { reason } if reason == "space_has_live_dependents")
    );
    state.apply(
        &make_operation(
            arkret_wire::EventKind::Redaction,
            realm_id,
            serde_json::json!({"target_ref":strand_id,"reason":"test"}),
        ),
        &hlc,
    );
    assert_eq!(
        state.strands[strand_id].state,
        ObjectLifecycleState::Redacted
    );
    assert!(matches!(
        state.apply(&tombstone, &hlc),
        ProjectionEffect::SpaceContainerLifecycle {
            new_state: SpaceContainerLifecycleState::Tombstoned,
            ..
        }
    ));
}

#[test]
fn board_archive_and_restore_preserve_child_lists_and_cards() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let realm_id = "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb";
    let board_id = "ak:space:AdF-OpLT-7la09L28Pgl41aEHXK3MEZNnwMNhc02Uz19";
    let list_id = "ak:space:AYqEzQ3jW02EHkMjxFQTlyeowxPQXJE4fI6JGOnzi23t";
    let strand_id = "ak:strand:AUAf2-oZl31wupPqnQLO-zloaqgMoX5xk2tpVSbi8zjD";

    state.apply(
        &make_operation(
            arkret_wire::EventKind::SpaceCreate,
            realm_id,
            serde_json::json!({
                "object": {
                    "id": board_id,
                    "realm_id": realm_id,
                    "kind": "board",
                    "title": "Sprint",
                    "created_by": "ak:did_core:web:alice.example"
                }
            }),
        ),
        &hlc,
    );
    state.apply(
        &make_operation(
            arkret_wire::EventKind::SpaceCreate,
            realm_id,
            serde_json::json!({
                "object": {
                    "id": list_id,
                    "realm_id": realm_id,
                    "kind": "list",
                    "title": "Todo",
                    "parent_space_id": board_id,
                    "rank": "r001",
                    "created_by": "ak:did_core:web:alice.example"
                }
            }),
        ),
        &hlc,
    );
    state.apply(
        &make_operation(
            arkret_wire::EventKind::StrandCreate,
            realm_id,
            serde_json::json!({
                "object": {
                    "id": strand_id,
                    "realm_id": realm_id,
                    "metadata": {
                        "title": "Review PR"
                    },
                    "created_by": "ak:did_core:web:alice.example"
                }
            }),
        ),
        &hlc,
    );
    state.apply(
        &make_operation(
            arkret_wire::EventKind::StrandMove,
            realm_id,
            serde_json::json!({
                "strand_id": strand_id,
                "board_space_id": board_id,
                "target_space_id": list_id,
                "rank": "r007"
            }),
        ),
        &hlc,
    );

    state.apply(
        &make_operation(
            arkret_wire::EventKind::SpaceArchive,
            realm_id,
            serde_json::json!({ "space_id": board_id }),
        ),
        &hlc,
    );
    assert_eq!(
        state.space_containers[board_id].state,
        SpaceContainerLifecycleState::Archived
    );
    assert_eq!(
        state.space_containers[list_id].state,
        SpaceContainerLifecycleState::Active
    );
    assert_eq!(state.strands[strand_id].state, ObjectLifecycleState::Active);

    // Restoring a parent must not restore independently archived children.
    for (kind, payload) in [
        (
            arkret_wire::EventKind::SpaceArchive,
            serde_json::json!({"space_id": list_id}),
        ),
        (
            arkret_wire::EventKind::StrandArchive,
            serde_json::json!({"target_ref": strand_id}),
        ),
    ] {
        state.apply(&make_operation(kind, realm_id, payload), &hlc);
    }

    state.apply(
        &make_operation(
            arkret_wire::EventKind::SpaceRestore,
            realm_id,
            serde_json::json!({ "space_id": board_id }),
        ),
        &hlc,
    );
    assert_eq!(
        state.space_containers[list_id].state,
        SpaceContainerLifecycleState::Archived
    );
    assert_eq!(
        state.strands[strand_id].state,
        ObjectLifecycleState::Archived
    );
    let relation = state
        .relations
        .values()
        .find(|relation| relation.to_object_ref() == Some(strand_id))
        .expect("strand position relation");
    assert_eq!(relation.rank.as_deref(), Some("r007"));
}

#[test]
fn create_time_placement_rejects_a_list_reference_that_is_not_a_space_id() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let realm_id = "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb";
    let board_id = "ak:space:AdF-OpLT-7la09L28Pgl41aEHXK3MEZNnwMNhc02Uz19";
    let list_id = "ak:space:AYqEzQ3jW02EHkMjxFQTlyeowxPQXJE4fI6JGOnzi23t";
    let strand_id = "ak:strand:AUAf2-oZl31wupPqnQLO-zloaqgMoX5xk2tpVSbi8zjD";
    // The exact shape observed on the wire in the 20260903-121050 joint-e2e
    // run: a client-local operation handle where the List Space id belongs.
    let local_handle = "01a06598-b14a-7d51-ad57-27b1510e8c0b";

    for (id, kind, title, parent) in [
        (board_id, "board", "Sprint", None),
        (list_id, "list", "Todo", Some(board_id)),
    ] {
        let mut object = serde_json::json!({
            "id": id,
            "realm_id": realm_id,
            "kind": kind,
            "title": title,
            "created_by": "ak:did_core:web:alice.example"
        });
        if let Some(parent) = parent {
            object["parent_space_id"] = serde_json::Value::String(parent.to_owned());
            object["rank"] = serde_json::Value::String("r001".to_owned());
        }
        state.apply(
            &make_operation(
                arkret_wire::EventKind::SpaceCreate,
                realm_id,
                serde_json::json!({ "object": object }),
            ),
            &hlc,
        );
    }

    let untyped_create = make_operation(
        arkret_wire::EventKind::StrandCreate,
        realm_id,
        serde_json::json!({
            "object": {
                "id": strand_id,
                "realm_id": realm_id,
                "metadata": {
                    "title": "Card A",
                    "fields": {
                        "board_space_id": board_id,
                        "list_space_id": local_handle,
                        "rank": "U"
                    }
                },
                "created_by": "ak:did_core:web:alice.example"
            }
        }),
    );
    assert_eq!(
        state.check_strand_position_typing(&untyped_create),
        Err("schema_violation"),
        "a create-time placement must not pass admission"
    );

    assert!(matches!(
        state.apply(&untyped_create, &hlc),
        ProjectionEffect::Rejected { reason } if reason == "schema_violation"
    ));
    assert!(
        !state.strands.contains_key(strand_id),
        "a malformed create must not materialize the Strand"
    );
    assert!(
        !state
            .relations
            .values()
            .any(|relation| relation.to_object_ref() == Some(strand_id)),
        "a rejected placement must not leave a position edge behind"
    );

    let typed_create = make_operation(
        arkret_wire::EventKind::StrandCreate,
        realm_id,
        serde_json::json!({
            "object": {
                "id": strand_id,
                "realm_id": realm_id,
                "metadata": {
                    "title": "Card A",
                    "fields": {
                        "board_space_id": board_id,
                        "list_space_id": list_id,
                        "rank": "U"
                    }
                },
                "created_by": "ak:did_core:web:alice.example"
            }
        }),
    );
    assert_eq!(
        state.check_strand_position_typing(&typed_create),
        Err("schema_violation")
    );
    assert!(matches!(
        state.apply(&typed_create, &hlc),
        ProjectionEffect::Rejected { reason } if reason == "schema_violation"
    ));
    assert!(state.relations.is_empty());
}

#[test]
fn create_time_placement_rejects_incomplete_or_invalid_position_shapes() {
    let realm_id = "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb";
    let board_id = "ak:space:AdF-OpLT-7la09L28Pgl41aEHXK3MEZNnwMNhc02Uz19";
    let list_id = "ak:space:AYqEzQ3jW02EHkMjxFQTlyeowxPQXJE4fI6JGOnzi23t";
    let cases = [
        (
            "missing list reference",
            serde_json::json!({
                "board_space_id": board_id,
                "rank": "U"
            }),
        ),
        (
            "non-string list reference",
            serde_json::json!({
                "board_space_id": board_id,
                "list_space_id": 7,
                "rank": "U"
            }),
        ),
        (
            "missing rank",
            serde_json::json!({
                "board_space_id": board_id,
                "list_space_id": list_id
            }),
        ),
        (
            "non-canonical rank",
            serde_json::json!({
                "board_space_id": board_id,
                "list_space_id": list_id,
                "rank": "not-valid"
            }),
        ),
    ];

    for (label, fields) in cases {
        let operation = make_operation(
            arkret_wire::EventKind::StrandCreate,
            realm_id,
            serde_json::json!({
                "object": {
                    "realm_id": realm_id,
                    "metadata": {
                        "title": label,
                        "fields": fields
                    },
                    "created_by": "ak:did_core:web:alice.example"
                }
            }),
        );
        let mut state = ProjectionState::new();
        assert!(
            state.check_strand_position_typing(&operation).is_err(),
            "{label} must fail admission"
        );
        assert!(
            matches!(
                state.apply(&operation, &ServerHlc::new("test")),
                ProjectionEffect::Rejected { .. }
            ),
            "{label} must also fail closed during direct reducer replay"
        );
        assert!(
            state.strands.is_empty() && state.relations.is_empty(),
            "{label} must not leave a partial projection"
        );
    }
}
