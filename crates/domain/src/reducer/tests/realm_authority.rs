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

fn transfer_operation(expected_state_digest: String) -> Operation {
    use arkret_models_collaboration::events_payloads::realm::RealmOwnerTransferPayload;
    use arkret_models_crypto::realm_owner_transfer::{
        RealmOwnerTransferAcceptanceIntent, RealmOwnerTransferPatch,
        RealmOwnerTransferUnsignedPayload,
    };
    use arkret_signatures::realm_owner_transfer::{
        sign_realm_owner_transfer_acceptance, verify_realm_owner_transfer_acceptance,
    };

    let realm_id = arkret_wire::RealmId::new(REALM).unwrap();
    let intent = RealmOwnerTransferAcceptanceIntent {
        scope_ref: arkret_wire::ScopeRef::Realm {
            realm_id: realm_id.clone(),
        },
        actor_id: account_actor(OWNER),
        payload_without_successor_acceptance: RealmOwnerTransferUnsignedPayload {
            realm_id,
            expected_state_digest: arkret_wire::Hash::new(expected_state_digest).unwrap(),
            patch: RealmOwnerTransferPatch {
                controller_actor_id: account_actor(SUCCESSOR),
            },
        },
    };
    // Real independent successor signature; native Device authority is an
    // admission responsibility outside this deterministic projection fixture.
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[103; 32]);
    let acceptance = sign_realm_owner_transfer_acceptance(
        &intent,
        arkret_wire::DidUrl::new(
            "did:web:successor.example#ak:device:0199bbbb-bbbb-7bbb-8bbb-bbbbbbbbbbbb",
        )
        .unwrap(),
        "2026-09-20T00:00:00.000Z".parse().unwrap(),
        &signing_key,
    )
    .expect("successor signs the complete current acceptance intent");
    verify_realm_owner_transfer_acceptance(
        &intent,
        &acceptance,
        &arkret_signatures::PublicKeyMaterial::Ed25519Raw {
            bytes: signing_key.verifying_key().to_bytes().to_vec(),
        },
    )
    .expect("fixture acceptance must verify before testing domain state");
    let unsigned = intent.payload_without_successor_acceptance;
    let payload = RealmOwnerTransferPayload {
        realm_id: unsigned.realm_id,
        expected_state_digest: unsigned.expected_state_digest,
        patch: unsigned.patch,
        successor_acceptance: acceptance,
    };
    let mut value = serde_json::to_value(&payload).unwrap();
    serde_json::from_value::<RealmOwnerTransferPayload>(value.clone())
        .expect("current owner-transfer fixture must pass closed payload decoding");
    value["sender"] = serde_json::json!(OWNER);
    operation(arkret_wire::EventKind::RealmOwnerTransfer, value)
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
        .and_then(arkret_canonical::serde_helpers::parse_uint64_decimal_value)
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
            "authority_generation": "0",
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
    let transfer = transfer_operation(root_digest(&state));
    let effect = state
        .apply_realm_authority_transition(&transfer, arkret_wire::EventKind::RealmOwnerTransfer);
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
    let transfer = transfer_operation(root_digest(&state));
    let mut control = state_with_successor();
    assert!(matches!(
        control.apply_realm_authority_transition(
            &transfer,
            arkret_wire::EventKind::RealmOwnerTransfer,
        ),
        ProjectionEffect::RealmLifecycle { .. }
    ));
    let before = state.realm_authority_root(REALM).unwrap().clone();
    state
        .members
        .remove(&(REALM.to_owned(), account_actor_string(SUCCESSOR)))
        .expect("remove only the successor membership from the legal control");
    let nonmember = state
        .apply_realm_authority_transition(&transfer, arkret_wire::EventKind::RealmOwnerTransfer);
    assert!(matches!(
        nonmember,
        ProjectionEffect::Rejected { reason }
            if reason == "realm_authority_controller_mismatch"
    ));
    assert_eq!(state.realm_authority_root(REALM), Some(&before));

    let mut state = state_with_successor();
    let mut advanced = state.realm_authority_root(REALM).unwrap().clone();
    advanced["authority_generation"] = serde_json::json!("1");
    state.set_realm_facet(REALM, facet::REALM_AUTHORITY_ROOT, advanced.clone());
    let stale = state
        .apply_realm_authority_transition(&transfer, arkret_wire::EventKind::RealmOwnerTransfer);
    assert!(matches!(
        stale,
        ProjectionEffect::Rejected { reason } if reason == "realm_authority_root_conflict"
    ));
    assert_eq!(state.realm_authority_root(REALM), Some(&advanced));
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
                "expected_governance_generation": "0",
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
    root["authority_generation"] = serde_json::json!(u64::MAX.to_string());
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
    // as the fail-closed verdict when the full-width decimal counter is
    // exhausted: no wrap, no saturation, no silent old value.
    assert!(
        matches!(
            effect,
            ProjectionEffect::Rejected { ref reason } if reason == "realm_authority_root_conflict"
        ),
        "exhausted authority generation must fail closed: {effect:?}"
    );
    assert_eq!(state.realm_authority_root(REALM), Some(&root));
}

#[test]
fn numeric_authority_generation_is_refused_without_mutation() {
    let mut state = state_with_successor();
    let mut root = state.realm_authority_root(REALM).unwrap().clone();
    root["authority_generation"] = serde_json::json!(0);
    state.set_realm_facet(REALM, facet::REALM_AUTHORITY_ROOT, root.clone());
    let effect = state.apply_realm_authority_transition(
        &operation(
            arkret_wire::EventKind::RealmAuthorityReset,
            serde_json::json!({
                "realm_id": REALM,
                "expected_state_digest": arkret_canonical::canonical_sha256(&root).unwrap(),
                "sender": OWNER,
            }),
        ),
        arkret_wire::EventKind::RealmAuthorityReset,
    );
    assert!(matches!(effect, ProjectionEffect::Rejected { reason }
        if reason == "realm_authority_root_conflict"));
    assert_eq!(state.realm_authority_root(REALM), Some(&root));
}
