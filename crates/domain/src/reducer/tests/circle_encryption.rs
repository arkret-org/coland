use super::*;

// ── AKP-0007 §8 — Circle member one-way add authorization ───────────
//
// Seed a Realm with `alice` (manage holder) + `bob` joined, plus a
// non-member `mallory`, and an `invite`-rule Circle. Exercise the reducer's
// fail-closed second-line check directly.

fn seed_circle_authz_state() -> (ProjectionState, ServerHlc, String, String) {
    let realm = "ak:realm:ASk_eoIHpJ8N_FKjxDcSCUURWkTNTCM3Ry9G5DEyb2gX".to_owned();
    let circle = "ak:circle:AUiSHUfqumU5_UtRrOIga2jjSmucw5MpSQdam3TtzPQu".to_owned();
    let mut state = ProjectionState::new();
    let now = chrono::Utc::now();
    let join_member = |state: &mut ProjectionState, did: &str| {
        let actor = account_actor_string(did);
        state.members.insert(
            (realm.clone(), actor.clone()),
            ColandMembershipState {
                member: actor,
                realm_id: realm.clone(),
                state: "join".to_owned(),
                role: "member".to_owned(),
                membership_event_ref: None,
                invited_at: None,
                joined_at: now,
                updated_at: now,
                reason: None,
            },
        );
    };
    join_member(&mut state, "ak:did_core:web:alice");
    join_member(&mut state, "ak:did_core:web:bob");
    // mallory is intentionally NOT a Realm member.
    state.circles.insert(
        circle.clone(),
        CircleProjection {
            circle_id: circle.clone(),
            realm_id: realm.clone(),
            profile_ref: None,
            title: "Ops".to_owned(),
            summary: None,
            display: serde_json::json!({"short_name":"Ops","color_token":"slate","symbol":{"glyph":"ring"}}),
            directory_visibility: "members".to_owned(),
            join_rule: "invite".to_owned(),
            history_access: "since_join".to_owned(),
            mls_group_ref: None,
            state: CircleLifecycleState::Active,
            state_changed_at: None,
            created_by: account_actor_string("ak:did_core:web:alice"),
            created_at: now,
            updated_by: None,
            updated_at: None,
            members: BTreeSet::new(),
        },
    );
    (state, ServerHlc::new("test"), realm, circle)
}

#[test]
fn circle_manage_pull_realm_member_succeeds() {
    // alice holds `ak.circle.member.manage` (verdict stamped by the HTTP
    // surface). She pulls the already-joined Realm member bob into the
    // Circle; bob performs no action and lands in `members` immediately.
    let (mut state, hlc, realm, circle) = seed_circle_authz_state();
    let op = make_operation(
        arkret_wire::EventKind::CircleMemberState,
        &realm,
        serde_json::json!({
            "circle_id": circle,
            "member_id": account_actor("ak:did_core:web:bob"),
            "membership": "join",
            "sender": "ak:did_core:web:alice",
            "manage_capability_verified": true,
        }),
    );
    let effect = state.apply(&op, &hlc);
    assert!(
        matches!(effect, ProjectionEffect::CircleMemberStateChanged { .. }),
        "manage-backed pull should be accepted, got {effect:?}"
    );
    assert!(
        state.circles[&circle]
            .members
            .contains(&account_actor_string("ak:did_core:web:bob")),
        "bob must be an active Circle member with no accept step"
    );
}

#[test]
fn circle_pull_without_manage_rejected() {
    // alice attempts to pull bob in WITHOUT a stamped manage verdict
    // (e.g. the HTTP gate was bypassed). The reducer fails closed.
    let (mut state, hlc, realm, circle) = seed_circle_authz_state();
    let op = make_operation(
        arkret_wire::EventKind::CircleMemberState,
        &realm,
        serde_json::json!({
            "circle_id": circle,
            "member_id": account_actor("ak:did_core:web:bob"),
            "membership": "join",
            "sender": "ak:did_core:web:alice",
        }),
    );
    assert!(
        matches!(
            state.apply(&op, &hlc),
            ProjectionEffect::Rejected { reason }
                if reason == CIRCLE_MEMBER_MANAGE_CAPABILITY_REQUIRED
        ),
        "cross-actor add without manage capability must be rejected"
    );
    assert!(
        !state.circles[&circle]
            .members
            .contains(&account_actor_string("ak:did_core:web:bob"))
    );
}

#[test]
fn circle_pull_non_realm_member_rejected() {
    // Even with a valid manage verdict, pulling a non-Realm member in
    // violates the strict-subset invariant.
    let (mut state, hlc, realm, circle) = seed_circle_authz_state();
    let op = make_operation(
        arkret_wire::EventKind::CircleMemberState,
        &realm,
        serde_json::json!({
            "circle_id": circle,
            "member_id": account_actor("ak:did_core:web:mallory"),
            "membership": "join",
            "sender": "ak:did_core:web:alice",
            "manage_capability_verified": true,
        }),
    );
    assert!(
        matches!(
            state.apply(&op, &hlc),
            ProjectionEffect::Rejected { reason }
                if reason == "circle_member_must_be_realm_member"
        ),
        "non-Realm member must be rejected regardless of manage capability"
    );
}

#[test]
fn circle_self_join_requires_open_rule() {
    // bob self-joins an `invite`-rule Circle without manage → rejected; an
    // explicit manage verdict can authorize self-add on a non-open Circle; an
    // `open` Circle lets a joined Realm member add themselves with no manage
    // capability.
    let (mut state, hlc, realm, circle) = seed_circle_authz_state();
    let op_invite = make_operation(
        arkret_wire::EventKind::CircleMemberState,
        &realm,
        serde_json::json!({
            "circle_id": circle, "member_id": account_actor("ak:did_core:web:bob"),
            "membership": "join", "sender": "ak:did_core:web:bob",
        }),
    );
    assert!(
        matches!(
            state.apply(&op_invite, &hlc),
            ProjectionEffect::Rejected { reason } if reason == CIRCLE_JOIN_NOT_OPEN
        ),
        "self-join on a non-open Circle must be rejected"
    );
    let op_invite_with_manage = make_operation(
        arkret_wire::EventKind::CircleMemberState,
        &realm,
        serde_json::json!({
            "circle_id": circle, "member_id": account_actor("ak:did_core:web:alice"),
            "membership": "join", "sender": "ak:did_core:web:alice",
            "manage_capability_verified": true,
        }),
    );
    assert!(
        matches!(
            state.apply(&op_invite_with_manage, &hlc),
            ProjectionEffect::CircleMemberStateChanged { .. }
        ),
        "self-join on a non-open Circle must be accepted with explicit manage"
    );
    assert!(
        state.circles[&circle]
            .members
            .contains(&account_actor_string("ak:did_core:web:alice"))
    );
    // Flip the Circle to open and retry.
    state.circles.get_mut(&circle).unwrap().join_rule = "public".to_owned();
    let op_open = make_operation(
        arkret_wire::EventKind::CircleMemberState,
        &realm,
        serde_json::json!({
            "circle_id": circle, "member_id": account_actor("ak:did_core:web:bob"),
            "membership": "join", "sender": "ak:did_core:web:bob",
        }),
    );
    assert!(
        matches!(
            state.apply(&op_open, &hlc),
            ProjectionEffect::CircleMemberStateChanged { .. }
        ),
        "self-join on an open Circle must be accepted"
    );
    assert!(
        state.circles[&circle]
            .members
            .contains(&account_actor_string("ak:did_core:web:bob"))
    );
}
