//! AKP-0007 (P2A.6) — coland reducer-level smoke test for the Circle
//! primitive lifecycle and membership invariants.
//!
//! The full HTTP integration round-trip
//! (create → add member → emit Strand with scope_circle_id → archive)
//! is exercised by the cotest joint-test suite (P5). This smoke test
//! seals the reducer's invariants in coland-local CI so a regression
//! on the projection-side state machine surfaces immediately:
//!
//! 1. `ak.circle.create` writes a live Circle into the projection;
//! 2. `ak.circle.member.state -> membership: join` for a non-Realm member is rejected with the
//!    canonical AKP-0007 reason `circle_member_must_be_realm_member`;
//! 3. After the actor joins the parent Realm, the same membership write is accepted and the Circle
//!    members set is updated;
//! 4. A Strand create with `scope_circle_id` pointing at a Circle in a different Realm is rejected
//!    with `circle_realm_mismatch`;
//! 5. `ak.circle.tombstone` flips the projection to the terminal state and the read helper hides
//!    the row.

use arkret_event_draft::ProjectedEventOperation as Operation;
use arkret_identifiers::{OperationId, RealmId};
use coland_domain::hlc::ServerHlc;
use coland_domain::reducer::{
    CircleLifecycleState, ColandMembershipState, ProjectionEffect, ProjectionState,
};
use serde_json::{Value, json};

const REALM_A: &str = "ak:realm:ATYL-87CDhaLQem29G2JQCXbZ_8zuu7khej2MbrsGLK6";
const REALM_B: &str = "ak:realm:AS1N4QnbZ6JgVObAF-yTx1GWoK2XnO_vUaZ2qe0WCyQV";
const CIRCLE_A: &str = "ak:circle:AcReudaBA9DxPpluEp4JJtMF_LufdP6FdBs1JuhsHdjL";
const CIRCLE_B: &str = "ak:circle:AXW19C_FsRE9VsaX3ZNkkfJaib48WHTD0dFvBtfORoTU";
const STRAND_X: &str = "ak:strand:AcIdv36sZgAnUyLmf0eWHBnC6uHK4tYeTONYoJdRr_qa";
const MORPH_X: &str = "ak:morph:AWJKopXwYqsRtNrpAHu0GlZy-NcK04NxZCmgmva_qUNA";
const ALICE: &str = "ak:did_core:web:alice.example";
const BOB: &str = "ak:did_core:web:bob.example";
const MALLORY: &str = "ak:did_core:web:mallory.example";

fn member_actor(principal: &str) -> arkret_wire::ActorId {
    arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        arkret_identifiers::DidCoreId::new(principal.to_owned()).unwrap(),
        coland_test_support::fixture_station_id(),
    ))
}

fn member_key(principal: &str) -> String {
    member_actor(principal).to_string()
}

fn op(kind: impl AsRef<str>, realm_id: &str, mut payload: Value) -> Operation {
    let kind = kind.as_ref();
    let object = payload.get_mut("object").and_then(Value::as_object_mut);
    let sender = object
        .as_ref()
        .and_then(|object| object.get("created_by"))
        .cloned();
    let producer_event_id = object
        .as_ref()
        .and_then(|object| object.get("id"))
        .and_then(Value::as_str)
        .and_then(|id| id.split_once(':').map(|(_, tail)| tail))
        .and_then(|tail| tail.split_once(':').map(|(_, token)| token))
        .map(|token| format!("ak:event:{token}"))
        .unwrap_or_else(|| coland_test_support::fixture_content_bound_id("ak:event:"));
    if let Some(object) = object {
        object.remove("id");
        object.remove("created_by");
    }
    payload
        .as_object_mut()
        .expect("test payload object")
        .entry("event_id")
        .or_insert_with(|| Value::String(producer_event_id));
    if let Some(sender) = sender {
        payload
            .as_object_mut()
            .expect("test payload object")
            .entry("sender")
            .or_insert(sender);
    }
    let sender = payload
        .as_object_mut()
        .unwrap()
        .remove("sender")
        .map(|value| serde_json::from_value::<arkret_wire::ActorId>(value).unwrap())
        .unwrap_or_else(|| member_actor(ALICE));
    let mut operation = arkret_event_draft::test_support::raw_projected_operation(
        OperationId::new(format!("ak:operation:{}", uuid::Uuid::now_v7())).unwrap(),
        RealmId::new(realm_id).unwrap(),
        kind,
        payload,
    );
    operation.context.sender = sender;
    operation
}

fn seed_realm(state: &mut ProjectionState, _hlc: &ServerHlc, realm_id: &str, owner: &str) {
    seed_realm_projection(state, realm_id, owner, "none");
}

fn seed_realm_projection(
    state: &mut ProjectionState,
    realm_id: &str,
    owner: &str,
    encryption_profile: &str,
) {
    let now = chrono::Utc::now();
    state.realm_states.insert(
        realm_id.to_owned(),
        coland_domain::reducer::ColandRealmState {
            realm_id: realm_id.to_owned(),
            owner: Some(owner.to_owned()),
            title: Some("Test Realm".to_owned()),
            deleted: false,

            created_at: now,
            updated_at: now,
            trust_domain: Some("ak:trust_domain:example.net".to_owned()),
            terminal_state: None,
            successor_realm_id: None,
            default_strand_id: None,
        },
    );
    state.set_realm_facet(
        realm_id,
        coland_domain::reducer::facet::REALM_GENESIS,
        json!({
            "purpose": "collaboration",
            "encryption_profile": encryption_profile,
            "schema_refs": ["ak.schema.realm.v1"]
        }),
    );
}

fn seed_encrypted_realm(
    state: &mut ProjectionState,
    _hlc: &ServerHlc,
    realm_id: &str,
    owner: &str,
) {
    seed_realm_projection(state, realm_id, owner, "mls_rfc9420");
}

/// AKP-0007 smoke helper — write a `(realm_id, actor)` membership entry
/// directly into the projection's `members` cache so the test can focus
/// on the Circle strict-subset invariant without booting the full
/// `ak.member.state` join pipeline. The Circle handler reads
/// the same cache via `ProjectionState::member`.
fn add_realm_member(state: &mut ProjectionState, _hlc: &ServerHlc, realm_id: &str, actor: &str) {
    let now = chrono::Utc::now();
    state.members.insert(
        (realm_id.to_owned(), member_key(actor)),
        ColandMembershipState {
            member: member_key(actor),
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
fn circle_create_writes_projection() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("circles-smoke-test");
    seed_realm(&mut state, &hlc, REALM_A, ALICE);

    let effect = state.apply(
        &op(
            arkret_wire::EventKind::CircleCreate,
            REALM_A,
            json!({
                "object": {
                    "id": CIRCLE_A,
                    "realm_id": REALM_A,
                    "title": "Ops",
                    "directory_visibility": "members",
                    "join_rule": "invite",
                    "history_access": "since_join",
                    "created_by": member_actor(ALICE),
                }
            }),
        ),
        &hlc,
    );

    assert!(
        matches!(effect, ProjectionEffect::CircleLifecycle { ref circle_id, new_state: CircleLifecycleState::Active }
                 if circle_id == CIRCLE_A),
        "circle.create should produce an Active CircleLifecycle effect; got {effect:?}"
    );
    let circle = state.circle(CIRCLE_A).expect("circle projected");
    assert_eq!(circle.realm_id, REALM_A);
    assert_eq!(circle.state, CircleLifecycleState::Active);
    assert!(circle.members.is_empty(), "Circle starts with no members");
}

#[test]
fn circle_remains_plaintext_until_its_own_mls_genesis() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("circles-e2ee-floor-test");
    seed_encrypted_realm(&mut state, &hlc, REALM_A, ALICE);

    let created = state.apply(
        &op(
            arkret_wire::EventKind::CircleCreate,
            REALM_A,
            json!({
                "object": {
                    "id": CIRCLE_A,
                    "realm_id": REALM_A,
                    "title": "Plaintext Ops",
                    "created_by": member_actor(ALICE),
                }
            }),
        ),
        &hlc,
    );

    assert!(matches!(created, ProjectionEffect::CircleLifecycle { .. }));
    assert!(!state.circle_scope_is_mls_activated(CIRCLE_A));
}

#[test]
fn circle_member_must_be_realm_member() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("circles-strict-subset-test");
    seed_realm(&mut state, &hlc, REALM_A, ALICE);
    // Owner joins the Realm so the create event has a member basis;
    // Bob is intentionally NOT added.
    add_realm_member(&mut state, &hlc, REALM_A, ALICE);
    state.apply(
        &op(
            arkret_wire::EventKind::CircleCreate,
            REALM_A,
            json!({
                "object": {
                    "id": CIRCLE_A,
                    "realm_id": REALM_A,
                    "title": "Ops",
                    "created_by": member_actor(ALICE),
                }
            }),
        ),
        &hlc,
    );

    let rejected = state.apply(
        &op(
            arkret_wire::EventKind::CircleMemberState,
            REALM_A,
            json!({
                "circle_id": CIRCLE_A,
                "member_id": member_actor(BOB),
                "membership": "join",
                "sender": member_actor(ALICE),
            }),
        ),
        &hlc,
    );
    assert!(
        matches!(rejected, ProjectionEffect::Rejected { ref reason }
                 if reason == "circle_member_must_be_realm_member"),
        "non-Realm member MUST be rejected with circle_member_must_be_realm_member; got {rejected:?}"
    );

    // Adding Bob to the parent Realm unblocks the Circle write.
    add_realm_member(&mut state, &hlc, REALM_A, BOB);
    // AKP-0007 §8: the owner Alice pulls Bob into a non-`open` Circle, which is
    // an authorised cross-actor add — the payload carries the `sender` + manage
    // stamp the HTTP authz gate would attach. This isolates the strict-subset
    // invariant under test without weakening the §8 authorization door.
    let accepted = state.apply(
        &op(
            arkret_wire::EventKind::CircleMemberState,
            REALM_A,
            json!({
                "circle_id": CIRCLE_A,
                "member_id": member_actor(BOB),
                "membership": "join",
                "sender": member_actor(ALICE),
                "manage_capability_verified": true,
            }),
        ),
        &hlc,
    );
    assert!(matches!(
        accepted,
        ProjectionEffect::CircleMemberStateChanged { ref member, ref target_state, .. }
            if member == &member_key(BOB) && target_state == "join"
    ));
    let circle = state.circle(CIRCLE_A).expect("circle live");
    assert!(
        circle.members.contains(&member_key(BOB)),
        "Bob is now a Circle member"
    );
}

#[test]
fn circle_member_remove_updates_active_set_and_scope_visibility() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("circles-member-remove-test");
    seed_realm(&mut state, &hlc, REALM_A, ALICE);
    add_realm_member(&mut state, &hlc, REALM_A, ALICE);
    add_realm_member(&mut state, &hlc, REALM_A, BOB);
    state.apply(
        &op(
            arkret_wire::EventKind::CircleCreate,
            REALM_A,
            json!({
                "object": {
                    "id": CIRCLE_A,
                    "realm_id": REALM_A,
                    "title": "Private Ops",
                    "created_by": member_actor(ALICE),
                }
            }),
        ),
        &hlc,
    );
    // Owner Alice adds Bob to a non-`open` Circle (authorised cross-actor add):
    // the payload carries the `sender` + manage stamp the HTTP authz gate would
    // attach, so the §8 door passes and we reach the remove/joined-set invariant
    // under test.
    state.apply(
        &op(
            arkret_wire::EventKind::CircleMemberState,
            REALM_A,
            json!({
                "circle_id": CIRCLE_A,
                "member_id": member_actor(BOB),
                "membership": "join",
                "sender": member_actor(ALICE),
                "manage_capability_verified": true,
            }),
        ),
        &hlc,
    );
    assert!(
        state.circle_scope_visible_to_actor(CIRCLE_A, &member_key(BOB)),
        "joined Circle member should see Circle-scoped content"
    );

    let removed = state.apply(
        &op(
            arkret_wire::EventKind::CircleMemberState,
            REALM_A,
            json!({
                "circle_id": CIRCLE_A,
                "member_id": member_actor(BOB),
                "membership": "leave",
                "sender": member_actor(ALICE),
            }),
        ),
        &hlc,
    );
    assert!(matches!(
        removed,
        ProjectionEffect::CircleMemberStateChanged { ref member, ref target_state, .. }
            if member == &member_key(BOB) && target_state == "leave"
    ));
    let circle = state.circle(CIRCLE_A).expect("circle live");
    assert!(
        !circle.members.contains(&member_key(BOB)),
        "Bob left the joined set"
    );
    assert!(
        !state.circle_scope_visible_to_actor(CIRCLE_A, &member_key(BOB)),
        "removed Circle member must not see new Circle-scoped content"
    );
}

fn assert_parent_membership_cascades_circle_membership(target_membership: &str) {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("circles-parent-membership-cascade-test");
    seed_realm(&mut state, &hlc, REALM_A, ALICE);
    add_realm_member(&mut state, &hlc, REALM_A, ALICE);
    add_realm_member(&mut state, &hlc, REALM_A, BOB);

    for circle_id in [CIRCLE_A, CIRCLE_B] {
        state.apply(
            &op(
                arkret_wire::EventKind::CircleCreate,
                REALM_A,
                json!({
                    "object": {
                        "id": circle_id,
                        "realm_id": REALM_A,
                        "title": "Private Ops",
                        "created_by": member_actor(ALICE),
                    }
                }),
            ),
            &hlc,
        );
        state.apply(
            &op(
                arkret_wire::EventKind::CircleMemberState,
                REALM_A,
                json!({
                    "circle_id": circle_id,
                    "member_id": member_actor(BOB),
                    "membership": "join",
                    "sender": member_actor(ALICE),
                    "manage_capability_verified": true,
                }),
            ),
            &hlc,
        );
        assert!(
            state.circle_scope_visible_to_actor(circle_id, &member_key(BOB)),
            "fixture should start with Bob joined in {circle_id}"
        );
    }
    // Only this Circle has accepted its own MLS Genesis. A create payload no
    // longer declares an encryption profile or activates MLS.
    state.circles.get_mut(CIRCLE_A).unwrap().mls_group_ref = Some("ak:mls:group:circle".to_owned());

    let effect = state.apply(
        &op(
            arkret_wire::EventKind::MemberState,
            REALM_A,
            json!({
                "member_id": member_actor(BOB),
                "membership": target_membership,
                "sender": member_actor(ALICE),
            }),
        ),
        &hlc,
    );
    assert!(matches!(
        effect,
        ProjectionEffect::MembershipChanged { ref member, ref action, .. }
            if member == &member_key(BOB) && action == target_membership
    ));
    for circle_id in [CIRCLE_A, CIRCLE_B] {
        assert!(
            !state.circle_scope_visible_to_actor(circle_id, &member_key(BOB)),
            "parent Realm {target_membership} must remove Bob from Circle {circle_id}"
        );
    }
}

#[test]
fn realm_leave_cascades_circle_membership() {
    assert_parent_membership_cascades_circle_membership("leave");
}

#[test]
fn realm_ban_cascades_circle_membership() {
    assert_parent_membership_cascades_circle_membership("ban");
}

#[test]
fn circle_scoped_message_preserves_scope_for_visibility_filtering() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("circles-message-scope-test");
    seed_realm(&mut state, &hlc, REALM_A, ALICE);
    for actor in [ALICE, BOB, MALLORY] {
        add_realm_member(&mut state, &hlc, REALM_A, actor);
    }
    state.apply(
        &op(
            arkret_wire::EventKind::CircleCreate,
            REALM_A,
            json!({
                "object": {
                    "id": CIRCLE_A,
                    "realm_id": REALM_A,
                    "title": "Private Ops",
                    "created_by": member_actor(ALICE),
                }
            }),
        ),
        &hlc,
    );
    // Seed the Circle's joined membership via authorised cross-actor adds: each
    // payload carries a `sender` distinct from the target plus the manage stamp
    // the HTTP authz gate would attach, so the AKP-0007 §8 door passes on a
    // non-`open` Circle and we reach the scope/visibility invariant under test.
    // (`payload_asserts_circle_manage` validates the stamp; the chosen `sender`
    // only needs to differ from the target to route through the manage path.)
    for (actor, sender) in [(ALICE, BOB), (BOB, ALICE)] {
        state.apply(
            &op(
                arkret_wire::EventKind::CircleMemberState,
                REALM_A,
                json!({
                    "circle_id": CIRCLE_A,
                    "member_id": member_actor(actor),
                    "membership": "join",
                    "sender": member_actor(sender),
                    "manage_capability_verified": true,
                }),
            ),
            &hlc,
        );
    }

    // Bind a Strand to the Circle, then submit a Message whose accepted
    // scope_ref was verified against that Strand by the receiver.
    let strand_created = state.apply(
        &op(
            arkret_wire::EventKind::StrandCreate,
            REALM_A,
            json!({
                "object": {
                    "id": STRAND_X,
                    "realm_id": REALM_A,
                    "metadata": {"title": "Circle-scoped Strand"},
                    "scope_circle_id": CIRCLE_A,
                }
            }),
        ),
        &hlc,
    );
    assert!(
        !matches!(strand_created, ProjectionEffect::Rejected { .. }),
        "circle-scoped Strand create must succeed, got {strand_created:?}"
    );

    let mut message = op(
        arkret_wire::EventKind::MessageCreate,
        REALM_A,
        json!({
            "event_id": "ak:event:AfaoXo0TmLK2gbcvCoXuTQMlnz-bWxdaHyOiyqXbYfG6",
            "strand_id": STRAND_X,
            "sender": member_actor(ALICE),
            "content": {
                "body": "circle-only ciphertext placeholder",
                "encrypted": true
            },
            "encrypted": true,
        }),
    );
    message.context.accepted_scope_ref = arkret_wire::ScopeRef::Circle {
        realm_id: RealmId::new(REALM_A).unwrap(),
        circle_id: arkret_wire::CircleId::new(CIRCLE_A).unwrap(),
    };
    let effect = state.apply(&message, &hlc);
    let ProjectionEffect::MessageCreated(message) = effect else {
        panic!("circle-scoped message should be projected, got {effect:?}");
    };
    assert_eq!(
        message.content["scope_circle_id"], CIRCLE_A,
        "projection must preserve the accepted Circle scope so sync/event readers can filter"
    );
    assert!(state.circle_scope_visible_to_actor(CIRCLE_A, &member_key(ALICE)));
    assert!(state.circle_scope_visible_to_actor(CIRCLE_A, &member_key(BOB)));
    assert!(
        !state.circle_scope_visible_to_actor(CIRCLE_A, MALLORY),
        "Realm member outside the Circle must not be eligible for Circle-scoped content"
    );
}

#[test]
fn circle_scoped_morph_preserves_scope_for_update_gates() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("circles-morph-scope-test");
    seed_realm(&mut state, &hlc, REALM_A, ALICE);
    add_realm_member(&mut state, &hlc, REALM_A, ALICE);
    state.apply(
        &op(
            arkret_wire::EventKind::CircleCreate,
            REALM_A,
            json!({
                "object": {
                    "id": CIRCLE_A,
                    "realm_id": REALM_A,
                    "title": "Private Ops",
                    "join_rule": "public",
                    "created_by": member_actor(ALICE),
                }
            }),
        ),
        &hlc,
    );
    state.apply(
        &op(
            arkret_wire::EventKind::CircleMemberState,
            REALM_A,
            json!({
                "circle_id": CIRCLE_A,
                "member_id": member_actor(ALICE),
                "membership": "join",
                "sender": member_actor(ALICE),
            }),
        ),
        &hlc,
    );

    let morph_created = state.apply(
        &op(
            arkret_wire::EventKind::MorphCreate,
            REALM_A,
            json!({
                "object": {
                    "id": MORPH_X,
                    "realm_id": REALM_A,
                    "morph_kind": "task",
                    "metadata": { "title": "Circle task" },
                    "scope_circle_id": CIRCLE_A,
                    "created_by": member_actor(ALICE),
                }
            }),
        ),
        &hlc,
    );
    assert!(
        !matches!(morph_created, ProjectionEffect::Rejected { .. }),
        "circle-scoped Morph create must succeed, got {morph_created:?}"
    );
    let morph = state.morphs.get(MORPH_X).expect("morph projected");
    assert_eq!(morph.scope_circle_id.as_deref(), Some(CIRCLE_A));
    assert_eq!(
        state.morph_scope_circle_id(MORPH_X),
        Some(CIRCLE_A.to_owned())
    );
}

#[test]
fn strand_scope_circle_id_rejects_cross_realm() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("circles-cross-realm-test");
    seed_realm(&mut state, &hlc, REALM_A, ALICE);
    seed_realm(&mut state, &hlc, REALM_B, ALICE);
    // Circle B belongs to Realm B.
    state.apply(
        &op(
            arkret_wire::EventKind::CircleCreate,
            REALM_B,
            json!({
                "object": {
                    "id": CIRCLE_B,
                    "realm_id": REALM_B,
                    "title": "B-Circle",
                    "created_by": member_actor(ALICE),
                }
            }),
        ),
        &hlc,
    );

    // Strand in Realm A pointing at a Circle in Realm B MUST be rejected
    // with the canonical AKP-0007 schema-violation reason
    // `circle_realm_mismatch`.
    let rejected = state.apply(
        &op(
            arkret_wire::EventKind::StrandCreate,
            REALM_A,
            json!({
                "object": {
                    "id": STRAND_X,
                    "realm_id": REALM_A,
                    "metadata": {"title": "Cross-Realm Strand"},
                    "scope_circle_id": CIRCLE_B,
                }
            }),
        ),
        &hlc,
    );
    assert!(
        matches!(rejected, ProjectionEffect::Rejected { ref reason }
                 if reason == "circle_realm_mismatch"),
        "cross-Realm Circle scope MUST reject as circle_realm_mismatch; got {rejected:?}"
    );
}

#[test]
fn circle_tombstone_hides_from_read_helper() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("circles-tombstone-test");
    seed_realm(&mut state, &hlc, REALM_A, ALICE);
    state.apply(
        &op(
            arkret_wire::EventKind::CircleCreate,
            REALM_A,
            json!({
                "object": {
                    "id": CIRCLE_A,
                    "realm_id": REALM_A,
                    "title": "Ops",
                    "created_by": member_actor(ALICE),
                }
            }),
        ),
        &hlc,
    );
    assert!(state.circle(CIRCLE_A).is_some(), "live Circle visible");

    state.apply(
        &op(
            arkret_wire::EventKind::CircleTombstone,
            REALM_A,
            json!({"circle_id": CIRCLE_A}),
        ),
        &hlc,
    );
    assert!(
        state.circle(CIRCLE_A).is_none(),
        "tombstoned Circle MUST be hidden from `ProjectionState::circle` reads"
    );
    // The raw map still carries the row (for admin / audit surfaces) but
    // its state should now be Tombstoned.
    let raw = state
        .circles
        .get(CIRCLE_A)
        .expect("tombstoned Circle still in raw map");
    assert_eq!(raw.state, CircleLifecycleState::Tombstoned);
    assert!(raw.members.is_empty(), "tombstone clears Circle members");

    // Discoverability helper for the parent Realm should also drop the
    // tombstoned row.
    let live = state.circles_for_realm(REALM_A);
    assert!(
        live.iter().all(|c| c.circle_id != CIRCLE_A),
        "tombstoned Circle MUST not appear in circles_for_realm"
    );
}
