use super::*;

const REALM: &str = "ak:realm:AW2XhEBfjbMHqDBzRGwBXCaBZtSGUQTBe5CkC4pjU8O2";
const OWNER: &str = "ak:did_core:web:owner.example";
const SUCCESSOR: &str = "ak:did_core:web:successor.example";

fn operation(kind: impl AsRef<str>, payload: Value) -> Operation {
    arkret_event_draft::test_support::raw_projected_operation(
        arkret_identifiers::OperationId::new(format!("ak:operation:{}", uuid::Uuid::now_v7()))
            .unwrap(),
        arkret_identifiers::RealmId::new(REALM).unwrap(),
        kind.as_ref(),
        payload,
    )
}

fn root_digest(state: &ProjectionState) -> String {
    arkret_canonical::canonical_sha256(state.realm_authority_root(REALM).unwrap()).unwrap()
}

fn controller(state: &ProjectionState) -> arkret_wire::ActorId {
    serde_json::from_value(
        state
            .realm_authority_root(REALM)
            .unwrap()
            .get("controller_actor_id")
            .unwrap()
            .clone(),
    )
    .unwrap()
}

fn controller_epoch(state: &ProjectionState) -> u64 {
    state
        .realm_authority_root(REALM)
        .unwrap()
        .get("controller_epoch")
        .and_then(Value::as_u64)
        .unwrap()
}

fn authority_generation(state: &ProjectionState) -> u64 {
    state
        .realm_authority_root(REALM)
        .unwrap()
        .get("authority_generation")
        .and_then(Value::as_u64)
        .unwrap()
}

fn state_with_successor() -> ProjectionState {
    let mut state = ProjectionState::default();
    state.set_realm_facet(
        REALM,
        facet::REALM_AUTHORITY_ROOT,
        serde_json::json!({
            "controller_actor_id": account_actor(OWNER),
            "controller_epoch": 0,
            "authority_generation": 0,
            "authority_event_ref": REALM.replacen("ak:realm:", "ak:event:", 1),
        }),
    );
    let now = chrono::Utc::now();
    let successor = account_actor_string(SUCCESSOR);
    state.members.insert(
        (REALM.to_owned(), successor.clone()),
        ColandMembershipState {
            member: successor,
            realm_id: REALM.to_owned(),
            state: "join".to_owned(),
            role: "member".to_owned(),
            membership_event_ref: None,
            invited_at: None,
            joined_at: now,
            updated_at: now,
            reason: None,
        },
    );
    state
}

#[test]
fn transfer_changes_only_controller_and_epoch() {
    let mut state = state_with_successor();
    let before_epoch = controller_epoch(&state);
    let before_generation = authority_generation(&state);
    let before_anchor = state.realm_authority_root(REALM).unwrap()["authority_event_ref"].clone();
    let effect = state.apply_realm_authority_transition(
        &operation(
            arkret_wire::EventKind::RealmOwnerTransfer,
            serde_json::json!({
                "realm_id": REALM,
                "expected_state_digest": root_digest(&state),
                "patch": {
                    "controller_actor_id": account_actor(SUCCESSOR)
                },
                "successor_acceptance": { "proof": "accepted" },
                "sender": OWNER
            }),
        ),
        arkret_wire::EventKind::RealmOwnerTransfer,
    );
    assert!(matches!(effect, ProjectionEffect::RealmLifecycle { .. }));
    assert_eq!(
        controller(&state).signing_principal_id().as_str(),
        SUCCESSOR
    );
    assert_eq!(controller_epoch(&state), before_epoch + 1);
    assert_eq!(authority_generation(&state), before_generation);
    assert_eq!(
        state.realm_authority_root(REALM).unwrap()["authority_event_ref"],
        before_anchor
    );
}

#[test]
fn transfer_rejects_nonmember_and_stale_expected_state() {
    let mut state = state_with_successor();
    let expected = root_digest(&state);
    let nonmember = state.apply_realm_authority_transition(
        &operation(
            arkret_wire::EventKind::RealmOwnerTransfer,
            serde_json::json!({
                "realm_id": REALM,
                "expected_state_digest": expected,
                "patch": {
                    "controller_actor_id": account_actor("ak:did_core:web:outsider.example")
                },
                "successor_acceptance": "accepted",
                "sender": OWNER
            }),
        ),
        arkret_wire::EventKind::RealmOwnerTransfer,
    );
    assert!(matches!(
        nonmember,
        ProjectionEffect::Rejected { reason }
            if reason == "realm_authority_controller_mismatch"
    ));

    let stale = state.apply_realm_authority_transition(
        &operation(
            arkret_wire::EventKind::RealmOwnerTransfer,
            serde_json::json!({
                "realm_id": REALM,
                "expected_state_digest": format!("sha256:{}", "0".repeat(64)),
                "patch": {
                    "controller_actor_id": account_actor(SUCCESSOR)
                },
                "successor_acceptance": "accepted",
                "sender": OWNER
            }),
        ),
        arkret_wire::EventKind::RealmOwnerTransfer,
    );
    assert!(matches!(
        stale,
        ProjectionEffect::Rejected { reason } if reason == "realm_authority_root_conflict"
    ));
}

#[test]
fn reset_replaces_the_anchor_and_generation_preserving_controller() {
    let mut state = state_with_successor();
    let before_controller = controller(&state);
    let before_epoch = controller_epoch(&state);
    let reset_event = operation(
        arkret_wire::EventKind::RealmAuthorityReset,
        serde_json::json!({
            "realm_id": REALM,
            "expected_state_digest": root_digest(&state),
            "sender": OWNER
        }),
    );
    let reset_anchor = reset_event.context.accepted_event_id.to_string();
    let reset = state.apply_realm_authority_transition(
        &reset_event,
        arkret_wire::EventKind::RealmAuthorityReset,
    );
    assert!(
        matches!(reset, ProjectionEffect::RealmLifecycle { .. }),
        "authority reset must project a Realm lifecycle effect: {reset:?}"
    );
    assert_eq!(controller(&state), before_controller);
    assert_eq!(controller_epoch(&state), before_epoch);
    assert_eq!(authority_generation(&state), 1);
    assert_eq!(
        state.realm_authority_root(REALM).unwrap()["authority_event_ref"],
        reset_anchor
    );
    assert_eq!(
        state
            .realm_authority_root(REALM)
            .unwrap()
            .as_object()
            .unwrap()
            .len(),
        4
    );
}

/// A governance handoff is an authority-commit effect, not a typed result.
///
/// `authz/capabilities.md` section 10 and `sync/authority-commit-log.md:62`
/// The authority-commit service owns the governance generation, stream-head
/// CAS and double-signed handoff. The product reducer only acknowledges that
/// the already committed effect was observed; it does not mirror a second
/// governance counter or rewrite the authority-root typed result.
#[test]
fn governance_station_change_is_explicit_without_mutating_projection_state() {
    let mut state = state_with_successor();
    let before_controller = controller(&state);
    let before_epoch = controller_epoch(&state);
    let before_root = state.realm_authority_root(REALM).unwrap().clone();
    let effect = state.apply_projected(
        &operation(
            arkret_wire::EventKind::RealmGovernanceStationChange,
            serde_json::json!({
                "expected_governance_generation": 0,
                "expected_realm_stream_commit_id": arkret_wire::RealmCommitId::from_digest([0x11; 32]).to_string(),
                "new_governance_station_id": "ak:did_core:web:successor-station.example",
                "sender": OWNER
            }),
        ),
        &crate::hlc::ServerHlc::new("governance-effect-test"),
    );
    assert!(
        matches!(
            effect,
            ProjectionEffect::AuthorityCommitEffectAccepted { .. }
        ),
        "governance station change must be an explicit authority effect: {effect:?}"
    );
    assert_eq!(state.realm_authority_root(REALM), Some(&before_root));
    assert_eq!(authority_generation(&state), 0);
    assert_eq!(controller(&state), before_controller);
    assert_eq!(controller_epoch(&state), before_epoch);
}

#[test]
fn successor_counter_overflow_fails_closed_without_mutation() {
    let mut state = state_with_successor();
    let mut root = state.realm_authority_root(REALM).unwrap().clone();
    root["authority_generation"] = serde_json::json!(9_007_199_254_740_991u64);
    state.set_realm_facet(REALM, facet::REALM_AUTHORITY_ROOT, root.clone());
    let effect = state.apply_realm_authority_transition(
        &operation(
            arkret_wire::EventKind::RealmAuthorityReset,
            serde_json::json!({
                "realm_id": REALM,
                "expected_state_digest": root_digest(&state),
                "sender": OWNER
            }),
        ),
        arkret_wire::EventKind::RealmAuthorityReset,
    );
    // `authz/capabilities.md` section 3.2 and the `ak.realm.authority.reset`
    // row of `event-kind-registry.json` both name `realm_authority_root_conflict`
    // as the fail-closed verdict when the successor counter would cross the
    // JSON safe-integer ceiling: no wrap, no saturation, no silent old value.
    assert!(
        matches!(
            effect,
            ProjectionEffect::Rejected { ref reason } if reason == "realm_authority_root_conflict"
        ),
        "exhausted authority generation must fail closed: {effect:?}"
    );
    assert_eq!(state.realm_authority_root(REALM), Some(&root));
}
