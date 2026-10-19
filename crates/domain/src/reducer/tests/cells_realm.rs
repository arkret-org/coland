use super::*;

// ── Facet map tests ──

#[test]
fn facet_value_returns_none_for_unwritten_facet() {
    let state = ProjectionState::new();
    let realm_id = "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb";
    let target = FacetRef::singleton(facet::REALM_READ_RECEIPT_POLICY);
    assert!(state.facet_value(realm_id, &target).is_none());
    assert_eq!(state.facet_revision(realm_id, &target), 0);
}

// ── Membership cache + transition cell tests ──

#[test]
fn membership_join_writes_both_structured_cache_and_transition_cell() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let realm_id = "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb";
    state
        .realm_join_rules
        .insert(realm_id.to_owned(), "public".to_owned());

    let payload = serde_json::json!({
        "realm_id": realm_id,
        "member_id": account_actor("ak:did_core:web:alice"),
        "membership": "join"
    });
    let mut operation = make_operation(arkret_wire::EventKind::MemberState, realm_id, payload);
    operation.context.sender = account_actor("ak:did_core:web:alice");
    let effect = state.apply_projected(&operation, &hlc);
    assert!(
        matches!(effect, ProjectionEffect::MembershipChanged { .. }),
        "effect={effect:?}; payload={:?}",
        operation.payload
    );

    // Structured cache populated with state="join" and the default member
    // role; role assignment is not part of the closed membership payload.
    let m = state
        .member(realm_id, &account_actor_string("ak:did_core:web:alice"))
        .expect("member entry should exist after join");
    assert_eq!(m.state, "join");
    assert_eq!(m.role, "member");

    // transition cell populated.
    assert_eq!(
        state
            .member_transition_state(realm_id, &account_actor_string("ak:did_core:web:alice"))
            .as_deref(),
        Some("join")
    );

    // members_of_realm only returns entries in `state="join"`.
    assert_eq!(state.members_of_realm(realm_id).len(), 1);
}

#[test]
fn validated_bootstrap_creator_join_bypasses_only_the_ordinary_join_gate() {
    let realm_id = "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb";
    let actor = "ak:did_core:web:reducer-test.example";
    let payload = serde_json::json!({
        "realm_id": realm_id,
        "member_id": account_actor(actor),
        "membership": "join"
    });
    let mut operation = make_operation(arkret_wire::EventKind::MemberState, realm_id, payload);
    operation.context.sender = account_actor(actor);

    let mut ordinary = ProjectionState::new();
    ordinary
        .realm_join_rules
        .insert(realm_id.to_owned(), "invite".to_owned());
    assert!(matches!(
        ordinary.apply_projected(&operation, &ServerHlc::new("test")),
        ProjectionEffect::Rejected { reason } if reason == "gate_check_failed"
    ));
    let actor = account_actor_string(actor);
    assert!(ordinary.member(realm_id, &actor).is_none());

    let mut bootstrap = ProjectionState::new();
    bootstrap
        .realm_join_rules
        .insert(realm_id.to_owned(), "invite".to_owned());
    assert!(matches!(
        bootstrap.apply_validated_realm_bootstrap_membership(&operation),
        ProjectionEffect::MembershipChanged { ref member, ref action, .. }
            if member == &actor && action == "join"
    ));
    assert_eq!(
        bootstrap
            .member(realm_id, &actor)
            .map(|member| member.state.as_str()),
        Some("join")
    );

    let mut mismatched = operation;
    mismatched.context.sender = arkret_wire::ActorId::service(
        arkret_wire::project_did_to_core_id(
            &arkret_identifiers::Did::new("did:web:mallory.example").unwrap(),
        )
        .unwrap(),
    );
    assert!(matches!(
        ProjectionState::new()
            .apply_validated_realm_bootstrap_membership(&mismatched),
        ProjectionEffect::Rejected { reason } if reason == "out_of_order_bootstrap"
    ));
}

#[test]
fn validated_direct_conversation_peer_join_has_a_distinct_narrow_bootstrap_path() {
    let realm_id = "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb";
    let peer = "ak:did_core:web:peer.example";
    let payload = serde_json::json!({
        "member_id": account_actor(peer),
        "membership": "join",
        "reason": "direct_conversation_bootstrap"
    });
    let mut operation = make_operation(arkret_wire::EventKind::MemberState, realm_id, payload);
    operation.context.sender = account_actor("ak:did_core:web:reducer-test.example");

    let mut direct = ProjectionState::new();
    direct.set_realm_facet(
        realm_id,
        facet::REALM_GENESIS,
        serde_json::json!({ "purpose": "direct_conversation" }),
    );
    assert!(matches!(
        direct.apply_validated_direct_conversation_bootstrap_membership(&operation),
        ProjectionEffect::MembershipChanged { ref member, ref action, .. }
            if member == &account_actor_string(peer) && action == "join"
    ));

    assert!(matches!(
        ProjectionState::new()
            .apply_validated_direct_conversation_bootstrap_membership(&operation),
        ProjectionEffect::Rejected { reason } if reason == "out_of_order_bootstrap"
    ));

    let mut wrong_reason = operation;
    wrong_reason.payload["reason"] = Value::String("ordinary_join".to_owned());
    let mut direct = ProjectionState::new();
    direct.set_realm_facet(
        realm_id,
        facet::REALM_GENESIS,
        serde_json::json!({ "purpose": "direct_conversation" }),
    );
    assert!(matches!(
        direct.apply_validated_direct_conversation_bootstrap_membership(&wrong_reason),
        ProjectionEffect::Rejected { reason } if reason == "out_of_order_bootstrap"
    ));
}

#[test]
fn bare_member_state_cannot_transition_ban_to_join() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let realm_id = "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb";

    let ban_payload = serde_json::json!({
        "member_id": account_actor("ak:did_core:web:bob"),
        "membership": "ban"
    });
    state.apply_projected(
        &make_operation(arkret_wire::EventKind::MemberState, realm_id, ban_payload),
        &hlc,
    );

    // After ban, Bob is in `members_in_state("ban")` and NOT in
    // `members_of_realm()` (which filters by `state="join"`).
    assert_eq!(state.members_in_state(realm_id, "ban").len(), 1);
    assert_eq!(state.members_of_realm(realm_id).len(), 0);
    assert_eq!(
        state
            .member_transition_state(realm_id, &account_actor_string("ak:did_core:web:bob"))
            .as_deref(),
        Some("ban")
    );

    // A bare member-state write cannot jump directly from `ban` to `join`.
    let invite_payload = serde_json::json!({
        "member_id": account_actor("ak:did_core:web:bob"),
        "membership": "join"
    });
    let effect = state.apply_projected(
        &make_operation(
            arkret_wire::EventKind::MemberState,
            realm_id,
            invite_payload,
        ),
        &hlc,
    );
    assert!(matches!(
        effect,
        ProjectionEffect::Rejected { ref reason }
            if reason.starts_with("invalid_membership_transition")
    ));
    assert_eq!(
        state
            .member_transition_state(realm_id, &account_actor_string("ak:did_core:web:bob"))
            .as_deref(),
        Some("ban")
    );
    assert_eq!(state.members_in_state(realm_id, "ban").len(), 1);
}

#[test]
fn member_state_is_scoped_to_the_target_realm() {
    const REALM_A: &str = "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb";
    const REALM_B: &str = "ak:realm:ASR8x2N1qyfyy6I-eob3l-FNhx4FPBTyMJrIfifkksgW";
    const ACTOR: &str = "ak:did_core:web:bob.example";

    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    state
        .realm_join_rules
        .insert(REALM_A.to_owned(), "public".to_owned());
    let payload = serde_json::json!({
        "realm_id": REALM_A,
        "member_id": account_actor(ACTOR),
        "membership": "join",
    });
    let mut operation = make_operation(arkret_wire::EventKind::MemberState, REALM_A, payload);
    operation.context.sender = account_actor(ACTOR);
    state.apply_projected(&operation, &hlc);

    let member_facet = FacetRef::new(
        facet::MEMBER_STATE,
        actor_facet_subject(&account_actor(ACTOR)),
    );
    // The genesis slot of a member facet is per Realm: joining REALM_A leaves
    // the same actor's REALM_B facet unwritten, so the same actor may still
    // take the first-write slot there.
    assert_eq!(state.facet_revision(REALM_A, &member_facet), 1);
    assert_eq!(
        state
            .facet_value(REALM_A, &member_facet)
            .and_then(Value::as_str),
        Some("join")
    );
    assert_eq!(state.facet_revision(REALM_B, &member_facet), 0);
    assert!(state.facet_value(REALM_B, &member_facet).is_none());
    assert_eq!(
        state.member_transition_state(REALM_B, &account_actor_string(ACTOR)),
        None
    );
}

// ── Realm lifecycle cache + cell tests ──

#[test]
fn realm_create_writes_both_structured_cache_and_ordered_log_facet() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let realm_id = "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb";
    apply_projected_create(
        &mut state,
        realm_id,
        serde_json::json!({
            // The genesis author is the initial authority-root controller and
            // therefore the projected Realm owner. `raw_projected_operation`
            // lifts this top-level `sender` out of the fixture and stamps it as
            // the Event actor, leaving the projected payload the closed
            // `{object}` `realm_create_payload` declares; without it the fixture
            // would fall back to its own default principal and the owner under
            // assertion would be an identity this test never named.
            "sender": "ak:did_core:web:reducer-test.example",
            "object": {
                "schema": "ak.schema.realm_genesis.v1",
                "purpose": "collaboration",
                "genesis_salt": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                "trust_domain": "ak:trust_domain:example.net",
                "schema_refs": ["ak.schema.realm.v1"],
                "digest_algorithm": "sha256",
                "security_class": "standard",
                "governance_station_id": FIXTURE_GOVERNANCE_STATION,
                "initial_join_rule": "invite",
                "initial_history_access": "since_join",
                "initial_discoverability": "invite_only",
            }
        }),
        &hlc,
    );
    state.apply(
        &make_operation(
            arkret_wire::EventKind::RealmProfile,
            realm_id,
            serde_json::json!({
                "schema": "ak.schema.realm_profile.v1",
                "title": "Test Realm"
            }),
        ),
        &hlc,
    );

    // Structured cache populated.
    let realm = state
        .realm_states
        .get(realm_id)
        .expect("realm_states entry should exist after create");
    assert_eq!(
        realm.owner.as_deref(),
        Some(account_actor_string("ak:did_core:web:reducer-test.example").as_str())
    );
    assert_eq!(realm.title.as_deref(), Some("Test Realm"));
    assert!(!realm.deleted);

    // Ordered-log facet has one entry.
    let log = state
        .realm_create_log(realm_id)
        .expect("create facet should hold an array");
    assert_eq!(log.len(), 1);
    assert_eq!(log[0].as_str(), Some(realm_id));
    assert_eq!(
        state
            .realm_profile_value(realm_id)
            .and_then(|profile| profile.get("title"))
            .and_then(Value::as_str),
        Some("Test Realm")
    );
    assert_eq!(
        state.realm_schema_refs(realm_id),
        vec!["ak.schema.realm.v1".to_owned()]
    );
    assert_eq!(
        state.realm_digest_algorithm(realm_id).as_deref(),
        Some("sha256")
    );
}

#[test]
fn audit_regression_realm_non_create_ignores_closed_create_identity_fields() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let realm_id = "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb";
    apply_projected_create(
        &mut state,
        realm_id,
        serde_json::json!({
            "object": {
                "schema": "ak.schema.realm_genesis.v1",
                "purpose": "collaboration",
                "genesis_salt": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                "trust_domain": "ak:trust_domain:example.net",
                "schema_refs": ["ak.schema.realm.v1"],
                "digest_algorithm": "sha256",
                "security_class": "standard",
                "governance_station_id": FIXTURE_GOVERNANCE_STATION,
                "initial_join_rule": "invite",
                "initial_history_access": "since_join",
                "initial_discoverability": "invite_only",
            }
        }),
        &hlc,
    );

    // These fields are not members of the closed RealmProfile schema. A raw
    // reducer caller must not let them relabel create-locked Realm identity or
    // trigger create-only digest-suite validation.
    let effect = state.apply(
        &make_operation(
            arkret_wire::EventKind::RealmProfile,
            realm_id,
            serde_json::json!({
                "schema": "ak.schema.realm_profile.v1",
                "title": "Renamed Realm",
                "trust_domain": "ak:trust_domain:other.example",
                "digest_algorithm": "not-a-digest-suite"
            }),
        ),
        &hlc,
    );

    assert!(matches!(
        effect,
        ProjectionEffect::RealmLifecycle { ref action, .. } if action == "profile"
    ));
    let realm = state.realm_states.get(realm_id).unwrap();
    assert_eq!(realm.title.as_deref(), Some("Renamed Realm"));
    assert_eq!(
        realm.trust_domain.as_deref(),
        Some("ak:trust_domain:example.net")
    );
}

#[test]
fn audit_regression_realm_create_requires_nested_identity_fields() {
    let mut state = ProjectionState::new();
    let realm_id = "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb";
    let effect = state.apply(
        &make_operation(
            arkret_wire::EventKind::RealmCreate,
            realm_id,
            serde_json::json!({
                "object": {
                    "schema": "ak.schema.realm_genesis.v1",
                    "purpose": "collaboration",
                    "genesis_salt": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                    "schema_refs": ["ak.schema.realm.v1"],
                    "security_class": "standard",
                    "governance_station_id": FIXTURE_GOVERNANCE_STATION,
                    "initial_join_rule": "invite",
                    "initial_history_access": "since_join",
                    "initial_discoverability": "invite_only",
                },
                "trust_domain": "ak:trust_domain:example.net",
                "digest_algorithm": "sha256"
            }),
        ),
        &ServerHlc::new("test"),
    );

    assert!(matches!(
        effect,
        ProjectionEffect::Rejected { ref reason }
            if reason == arkret_wire::ErrorCode::SCHEMA_VIOLATION
    ));
    assert!(!state.realm_states.contains_key(realm_id));
}

#[test]
fn realm_profile_writes_the_profile_facet_and_nothing_else() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    state.apply(
        &make_operation(
            arkret_wire::EventKind::RealmProfile,
            "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb",
            serde_json::json!({
                "schema": "ak.schema.realm_profile.v1",
                "title": "Renamed Realm",
            }),
        ),
        &hlc,
    );

    let value = state
        .realm_profile_value("ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb")
        .expect("profile facet should hold a value");
    // Profile writes must not touch the organization relationship facet.
    assert!(
        state
            .facet_value(
                "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb",
                &FacetRef::singleton(facet::REALM_ORGANIZATION),
            )
            .is_none()
    );
    assert_eq!(
        value.get("title").and_then(Value::as_str),
        Some("Renamed Realm")
    );
    assert_eq!(
        value.get("schema").and_then(Value::as_str),
        Some("ak.schema.realm_profile.v1")
    );
}

#[test]
fn realm_destroy_refuses_without_a_registered_confirmation_carrier() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let realm_id = "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb";
    apply_projected_create(
        &mut state,
        realm_id,
        serde_json::json!({"object": {
            "schema": "ak.schema.realm_genesis.v1",
            "purpose": "collaboration",
            "genesis_salt": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "trust_domain": "ak:trust_domain:example.net",
            "schema_refs": ["ak.schema.realm.v1"],
            "digest_algorithm": "sha256",
            "security_class": "standard",
            "governance_station_id": FIXTURE_GOVERNANCE_STATION,
            "initial_join_rule": "invite",
            "initial_history_access": "since_join",
            "initial_discoverability": "invite_only"
        }}),
        &hlc,
    );
    assert!(state.realm_genesis_value(realm_id).is_some());
    assert!(!state.realm_is_destroyed("ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb"));

    // ...then destroy.
    let effect = state.apply(
        &make_operation(
            arkret_wire::EventKind::RealmDestroy,
            "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb",
            serde_json::json!({"action": "destroy"}),
        ),
        &hlc,
    );

    assert!(
        matches!(effect, ProjectionEffect::Rejected { reason } if reason == "failed_precondition")
    );
    assert!(!state.realm_is_destroyed("ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb"));
    assert!(
        state
            .realm_facet_value(
                "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb",
                facet::REALM_DESTROY,
            )
            .is_none()
    );
}

#[test]
fn realm_tombstone_writes_the_tombstone_facet_and_successor() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let realm_id = "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb";
    let successor = "ak:realm:ASR8x2N1qyfyy6I-eob3l-FNhx4FPBTyMJrIfifkksgW";
    state.apply(
        &make_operation(
            arkret_wire::EventKind::RealmCreate,
            realm_id,
            serde_json::json!({"action": "create", "owner": "ak:did_core:web:alice"}),
        ),
        &hlc,
    );
    state.apply(
        &make_operation(
            arkret_wire::EventKind::RealmTombstone,
            realm_id,
            serde_json::json!({
                "reason": "migrated",
                "successor_realm_id": successor
            }),
        ),
        &hlc,
    );

    assert_eq!(
        state
            .realm_facet_value(realm_id, facet::REALM_TOMBSTONE)
            .and_then(|value| value.get("successor_realm_id"))
            .and_then(Value::as_str),
        Some(successor)
    );
    assert!(state.realm_is_tombstoned(realm_id));
    assert_eq!(
        state
            .realm_facet_value(realm_id, facet::REALM_TOMBSTONE)
            .and_then(|value| value.get("terminal_kind"))
            .and_then(Value::as_str),
        Some("tombstone")
    );
    assert!(state.realm_is_in_terminal_state(realm_id));
    assert!(!state.realm_is_destroyed(realm_id));
}

#[test]
fn realm_freeze_requires_explicit_unfreeze_and_preserves_archive() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let realm_id = "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb";
    apply_projected_create(
        &mut state,
        realm_id,
        serde_json::json!({
            "object": {
                "schema": "ak.schema.realm_genesis.v1",
                "purpose": "collaboration",
                "genesis_salt": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                "trust_domain": "ak:trust_domain:example.net",
                "schema_refs": ["ak.schema.realm.v1"],
                "digest_algorithm": "sha256",
                "security_class": "standard",
                "governance_station_id": FIXTURE_GOVERNANCE_STATION,
                "initial_join_rule": "invite",
                "initial_history_access": "since_join",
                "initial_discoverability": "invite_only",
            }
        }),
        &hlc,
    );

    assert!(state.realm_genesis_value(realm_id).is_some());
    assert!(!state.realm_ordinary_writes_blocked(realm_id));
    for kind in [
        arkret_wire::EventKind::RealmArchive,
        arkret_wire::EventKind::RealmFreeze,
    ] {
        state.apply(
            &make_operation(kind, realm_id, serde_json::json!({"reason":"hold"})),
            &hlc,
        );
    }
    assert!(state.realm_is_frozen(realm_id));
    assert_eq!(
        state.realm_facet_value(realm_id, facet::REALM_FREEZE),
        Some(&Value::Bool(true))
    );
    state.apply(
        &make_operation(
            arkret_wire::EventKind::RealmUnfreeze,
            realm_id,
            serde_json::json!({}),
        ),
        &hlc,
    );
    assert!(!state.realm_is_frozen(realm_id));
    assert!(state.realm_is_archived(realm_id));
    state.apply(
        &make_operation(
            arkret_wire::EventKind::RealmRestore,
            realm_id,
            serde_json::json!({}),
        ),
        &hlc,
    );
    assert!(!state.realm_is_archived(realm_id));
    assert!(!state.realm_ordinary_writes_blocked(realm_id));
    // The freeze gate fails closed on anything it cannot read as an explicit
    // `false`: a reloaded projection carrying a shape this Station does not
    // understand blocks ordinary writes instead of silently allowing them.
    state.set_realm_facet(
        realm_id,
        facet::REALM_FREEZE,
        serde_json::json!({ "unreadable": true }),
    );
    assert!(state.realm_ordinary_writes_blocked(realm_id));
    state.set_realm_facet(realm_id, facet::REALM_FREEZE, Value::Bool(false));
    assert!(!state.realm_ordinary_writes_blocked(realm_id));
    assert!(state.realm_ordinary_writes_blocked("unknown"));
}

/// A valid receipt remains a durable fact. It is intentionally not parsed into
/// or defaulted by the shared current-result reducer.
fn valid_erasure_receipt_payload() -> Value {
    serde_json::json!({
        "receipt_id": "ak:receipt:019b5c20-0000-7000-8000-000000000030",
        "trigger": {
            "kind": "account_status_record",
            "account_status_record_id": "ak:account_status_record:AUPhm9XGSn2ah7YYExswNu0yaccqupAufE2bFvqEoD5N"
        },
        "schema": "ak.schema.erasure_receipt.v1",
        "issuer_id": "ak:did_core:webvh:z2dmjYwAPJzv5CZsnAzt8auVZRn1GfuxhpK2t3Q3K3rj4B1x",
        "subject": {
            "kind": "space",
            "subject_ref": "ak:space:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb"
        },
        "scope": {
            "storage_boundary": "projection_store",
            "realm_id": "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb"
        },
        "outcome": "completed",
        "erased_classes": ["projection_rows"],
        "retained_stub_digest": "sha256:aa67f34cd4e055246b8a73abe15734c39945b5c0e2e5693c00cada4e13d93e59",
        "completed_at": "2026-08-02T00:10:00.000Z",
        "proofs": [{
            "verification_method": "did:webvh:z6mkfixtureprincipalexample:principal.example#key-1",
            "payload_digest": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            "signature": "receipt-signature-base64url-placeholder"
        }]
    })
}

#[test]
fn audit_erasure_receipt_is_retained_as_a_durable_fact_without_current_projection() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let operation = make_operation(
        arkret_wire::EventKind::AuditErasureReceipt,
        "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb",
        valid_erasure_receipt_payload(),
    );
    let effect = state.apply(&operation, &hlc);
    assert!(matches!(
        effect,
        ProjectionEffect::DurableFactRetained { kind, event_id }
            if kind == arkret_wire::EventKind::AuditErasureReceipt.as_str()
                && event_id == operation.context.event_id.to_string()
    ));
    assert!(state.realm_states.is_empty());
    assert!(state.messages.is_empty());
}

#[test]
fn realm_create_requires_explicit_creator_member_and_rejects_duplicate_create() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let realm_id = "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb";
    let payload = serde_json::json!({
        "object": {
            "schema": "ak.schema.realm_genesis.v1",
            "purpose": "collaboration",
            "genesis_salt": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "trust_domain": "ak:trust_domain:example.net",
            "schema_refs": ["ak.schema.realm.v1"],
            "digest_algorithm": "sha256",
            "security_class": "standard",
            "governance_station_id": FIXTURE_GOVERNANCE_STATION,
            "initial_join_rule": "invite",
            "initial_history_access": "since_join",
            "initial_discoverability": "invite_only"
        }
    });
    let create = make_operation(
        arkret_wire::EventKind::RealmCreate,
        realm_id,
        payload.clone(),
    );
    let first = state.apply_projected(&create, &hlc);
    assert!(matches!(
        first,
        ProjectionEffect::RealmLifecycle { action, .. } if action == "create"
    ));
    let log = state.realm_create_log(realm_id).unwrap();
    assert_eq!(log.len(), 1, "realm.create should write one genesis entry");
    assert!(
        state
            .member(realm_id, "ak:did_core:web:reducer-test.example")
            .is_none(),
        "ordinary create must not synthesize membership; the final bootstrap slot owns it"
    );
    assert_eq!(
        state.realm_authority_root(realm_id),
        Some(
            &serde_json::to_value(arkret_wire::RealmAuthorityRootValue {
                controller_actor_id: create.context.sender.clone(),
                controller_epoch: 0,
                authority_generation: 0,
                authority_event_ref: create.context.accepted_event_id.clone(),
            })
            .unwrap()
        ),
        "genesis derives the closed four-field root from its exact accepted Event"
    );

    let duplicate = apply_projected_create(&mut state, realm_id, payload, &hlc);
    assert!(matches!(
        duplicate,
        ProjectionEffect::Rejected { reason } if reason == "realm_already_exists"
    ));
    assert_eq!(state.realm_create_log(realm_id).unwrap().len(), 1);
}

#[test]
fn direct_conversation_role_survives_sealed_create_log_reload_via_genesis() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let realm_id =
        arkret_identifiers::RealmId::new("ak:realm:ASR8x2N1qyfyy6I-eob3l-FNhx4FPBTyMJrIfifkksgW")
            .unwrap();
    let payload = arkret_models_collaboration::objects::direct_conversation::direct_conversation_realm_create_payload(
        arkret_wire::GenesisSalt::new("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").unwrap(),
        arkret_identifiers::TrustDomainId::new("ak:trust_domain:example.net").unwrap(),
        arkret_identifiers::DidCoreId::new(FIXTURE_GOVERNANCE_STATION).unwrap(),
        chrono::Utc::now(),
    )
    .unwrap();

    let created = apply_projected_create(
        &mut state,
        realm_id.as_str(),
        serde_json::to_value(payload).unwrap(),
        &hlc,
    );
    assert!(
        matches!(created, ProjectionEffect::RealmLifecycle { ref action, .. } if action == "create"),
        "direct-conversation genesis should create the Realm: {created:?}"
    );

    let projected = state
        .realm_genesis_value(realm_id.as_str())
        .cloned()
        .expect("create writes the realm genesis facet");
    let projected = serde_json::from_value::<
        arkret_models_collaboration::events_payloads::RealmGenesis,
    >(projected)
    .unwrap();
    arkret_models_collaboration::objects::direct_conversation::DirectConversationRealmRole::validate(
        &projected,
    )
    .unwrap();
    assert!(state.realm_is_direct_conversation(realm_id.as_str()));

    state.set_realm_facet(
        realm_id.as_str(),
        facet::REALM_CREATE,
        serde_json::json!([realm_id.as_str()]),
    );

    assert!(
        state.realm_is_direct_conversation(realm_id.as_str()),
        "sealed create-log reload stores only the Realm id; typed role must survive in canonical genesis"
    );

    state.set_realm_facet(
        realm_id.as_str(),
        facet::REALM_GENESIS,
        serde_json::json!({
            "schema": "ak.schema.realm_genesis.v1",
            "purpose": "collaboration",
            "genesis_salt": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "trust_domain": "ak:trust_domain:example.net",
            "schema_refs": ["ak.schema.realm.v1"],
            "digest_algorithm": "sha256",
            "security_class": "standard",
            "governance_station_id": FIXTURE_GOVERNANCE_STATION,
            "initial_join_rule": "invite",
            "initial_history_access": "since_join",
            "initial_discoverability": "invite_only"
        }),
    );
    assert!(
        !state.realm_is_direct_conversation(realm_id.as_str()),
        "a discriminator without the registered profile/security shape must fail closed"
    );
}

#[test]
fn realm_genesis_and_profile_facets_return_none_for_uncreated_realm() {
    let realm_id = "ak:realm:AZs2_wsmWLM4I5GAUgGDI6lUXfsNmT_MguWcgfcxJDn4";
    let state = ProjectionState::new();
    assert!(state.realm_genesis_value(realm_id).is_none());
    assert!(state.realm_profile_value(realm_id).is_none());
    assert!(state.realm_create_log(realm_id).is_none());
    assert!(!state.realm_is_destroyed(realm_id));
}

#[test]
fn invite_entry_evaluates_principal_admission_hard_gate() {
    let mut state = ProjectionState::new();
    let realm_id = "ak:realm:AZpIovRd-lKGm0kpgKgqtWiGni5pA7imt7H99x3r-ot9";
    let invitee_id = "ak:did_core:web:denied.example";
    state.set_realm_facet(
        realm_id,
        facet::REALM_POLICY_BUNDLE,
        serde_json::json!({
            "join_policy": {
                "combinator": "all",
                "gates": [{
                    "gate_id": "principal",
                    "kind": "principal_admission",
                    "auto_resolve": true,
                    "denied_principal_ids": [invitee_id]
                }]
            }
        }),
    );
    let operation = make_operation(
        arkret_wire::EventKind::InviteCreate,
        realm_id,
        serde_json::json!({
            "invitee_id": invitee_id,
            "sender": "ak:did_core:web:inviter_id.example"
        }),
    );
    assert_eq!(
        state.check_membership_join_admission(&operation),
        Err("gate_check_failed")
    );
}

#[test]
fn public_entry_skips_c_axis_but_still_enforces_cooldown() {
    let mut state = ProjectionState::new();
    let realm_id = "ak:realm:Aep78TXQFoYm6MAUTeaLRRCcxM7GgYNbhMKM07j6OLsx";
    let member = "ak:did_core:web:alice.example";
    state
        .realm_join_rules
        .insert(realm_id.to_owned(), "public".to_owned());
    state.members.insert(
        (realm_id.to_owned(), account_actor_string(member)),
        ColandMembershipState {
            member: account_actor_string(member),
            realm_id: realm_id.to_owned(),
            state: "leave".to_owned(),
            role: "member".to_owned(),
            membership_event_ref: None,
            invited_at: None,
            joined_at: chrono::Utc::now() - chrono::Duration::days(1),
            updated_at: chrono::Utc::now() - chrono::Duration::minutes(1),
            reason: None,
        },
    );
    state.set_realm_facet(
        realm_id,
        facet::REALM_POLICY_BUNDLE,
        serde_json::json!({
            "join_policy": {
                "combinator": "all",
                "gates": [
                    {
                        "gate_id": "cooldown",
                        "kind": "cooldown",
                        "auto_resolve": true,
                        "min_interval_since_leave": "PT1H"
                    },
                    {
                        "gate_id": "parent",
                        "kind": "parent_membership",
                        "auto_resolve": true,
                        "membership_source_realm_ids": [
                            "ak:realm:AYCKiTPA1bjQa3rIKg4O1PGpeq_EXPw1fnNCfHYhPsdG"
                        ],
                        "require_min_membership": "join"
                    }
                ]
            }
        }),
    );
    let operation = make_operation(
        arkret_wire::EventKind::MemberState,
        realm_id,
        serde_json::json!({
            "member_id": account_actor(member),
            "sender": member,
            "membership": "join",
        }),
    );
    assert_eq!(
        state.check_membership_join_admission(&operation),
        Err("gate_check_failed")
    );
    state
        .members
        .get_mut(&(realm_id.to_owned(), account_actor_string(member)))
        .unwrap()
        .updated_at = operation.created_at - chrono::Duration::hours(2);
    assert_eq!(state.check_membership_join_admission(&operation), Ok(()));
}

#[test]
fn parent_membership_is_deferred_to_the_durable_admission_cut() {
    let mut state = ProjectionState::new();
    let realm_id = "ak:realm:AehJkZSB3P7C-ch-biRjD2flKZh73AhHpbhFnxWBhjo1";
    let member = "ak:did_core:web:alice.example";
    state
        .realm_join_rules
        .insert(realm_id.to_owned(), "restricted".to_owned());
    state.set_realm_facet(
        realm_id,
        facet::REALM_POLICY_BUNDLE,
        serde_json::json!({
            "join_policy": {
                "combinator": "all",
                "gates": [{
                    "gate_id": "parent",
                    "kind": "parent_membership",
                    "auto_resolve": true,
                    "membership_source_realm_ids": [
                        "ak:realm:AYCKiTPA1bjQa3rIKg4O1PGpeq_EXPw1fnNCfHYhPsdG"
                    ],
                    "require_min_membership": "join"
                }]
            }
        }),
    );
    let operation = make_operation(
        arkret_wire::EventKind::MemberState,
        realm_id,
        serde_json::json!({
            "member_id": account_actor(member),
            "sender": member,
            "membership": "join"
        }),
    );
    assert_eq!(
        state.check_membership_join_admission(&operation),
        Err("gate_check_failed")
    );
    let deferred = state
        .prepare_parent_membership_admission(&operation)
        .unwrap()
        .expect("parent membership must be finalized by PostgreSQL");
    assert!(deferred.require_joined_source);
}

#[test]
fn closed_entry_rejects_self_join_but_allows_authorized_writer_path() {
    let mut state = ProjectionState::new();
    let realm_id = "ak:realm:AehJkZSB3P7C-ch-biRjD2flKZh73AhHpbhFnxWBhjo1";
    let member = "ak:did_core:web:alice.example";
    state
        .realm_join_rules
        .insert(realm_id.to_owned(), "closed".to_owned());
    let self_join = make_operation(
        arkret_wire::EventKind::MemberState,
        realm_id,
        serde_json::json!({
            "member_id": account_actor(member),
            "sender": member,
            "membership": "join",
        }),
    );
    assert_eq!(
        state.check_membership_join_admission(&self_join),
        Err("gate_check_failed")
    );
    let admin_join = make_operation(
        arkret_wire::EventKind::MemberState,
        realm_id,
        serde_json::json!({
            "member_id": account_actor(member),
            "sender": "ak:did_core:web:admin.example",
            "membership": "join"
        }),
    );
    assert_eq!(state.check_membership_join_admission(&admin_join), Ok(()));
    state.members.insert(
        (realm_id.to_owned(), account_actor_string(member)),
        ColandMembershipState {
            member: account_actor_string(member),
            realm_id: realm_id.to_owned(),
            state: "join".to_owned(),
            role: "member".to_owned(),
            membership_event_ref: None,
            invited_at: None,
            joined_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            reason: None,
        },
    );
    assert_eq!(
        state.check_membership_join_admission(&self_join),
        Ok(()),
        "join-to-join delivery refresh is not Realm entry"
    );
}

#[test]
fn bare_member_state_cannot_leave_a_live_invite_state() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("invite-transition");
    let realm_id = "ak:realm:AcPah3GE5X4KORy6n5BoQ_izb3czlMLYgWg6E1hVh883";
    let member = "ak:did_core:web:alice.example";
    state.members.insert(
        (realm_id.to_owned(), account_actor_string(member)),
        ColandMembershipState {
            member: account_actor_string(member),
            realm_id: realm_id.to_owned(),
            state: "invite".to_owned(),
            role: "member".to_owned(),
            membership_event_ref: None,
            invited_at: Some(chrono::Utc::now()),
            joined_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            reason: None,
        },
    );
    let payload = serde_json::json!({
        "member_id": account_actor(member),
        "membership": "ban"
    });
    let admin = "ak:did_core:web:admin.example";
    let mut operation = make_operation(arkret_wire::EventKind::MemberState, realm_id, payload);
    operation.context.sender = account_actor(admin);
    let effect = state.apply_projected(&operation, &hlc);
    assert!(matches!(
        effect,
        ProjectionEffect::Rejected { reason } if reason == "invalid_membership_transition"
    ));
}

#[test]
fn knock_state_visible_in_members_in_state_query() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let realm_id = "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb";
    let payload = serde_json::json!({
        "member_id": account_actor("ak:did_core:web:carol"),
        "membership": "knock"
    });
    state.apply_projected(
        &make_operation(arkret_wire::EventKind::MemberState, realm_id, payload),
        &hlc,
    );
    let knockers = state.members_in_state(
        "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb",
        "knock",
    );
    assert_eq!(knockers.len(), 1);
    assert_eq!(
        knockers[0].member,
        account_actor_string("ak:did_core:web:carol")
    );
    assert_eq!(
        state
            .member_transition_state(realm_id, &account_actor_string("ak:did_core:web:carol"))
            .as_deref(),
        Some("knock")
    );
}

#[test]
fn read_receipt_policy_value_helper_extracts_canonical_value() {
    let mut state = ProjectionState::new();
    state.set_realm_facet(
        "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb",
        facet::REALM_READ_RECEIPT_POLICY,
        serde_json::json!({
            "disclosure": "required",
            "visibility": "members",
        }),
    );
    let value = state
        .read_receipt_policy_value("ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb")
        .expect("policy facet should resolve");
    assert_eq!(
        value.get("disclosure").and_then(Value::as_str),
        Some("required")
    );
    assert_eq!(
        value.get("visibility").and_then(Value::as_str),
        Some("members")
    );
    assert!(value.get("scope_overrides_allowed").is_none());
}

#[test]
fn the_policy_bundle_facet_does_not_leak_across_realms() {
    let mut state = ProjectionState::new();
    state.set_realm_facet(
        "ak:realm:first",
        facet::REALM_POLICY_BUNDLE,
        serde_json::json!({
            "policy_revision": 1,
            "join_policy": {"join_rule": "knock"},
        }),
    );
    state.set_realm_facet(
        "ak:realm:second",
        facet::REALM_POLICY_BUNDLE,
        serde_json::json!({
            "policy_revision": 4,
            "join_policy": {"join_rule": "invite"},
        }),
    );

    assert_eq!(
        state
            .realm_policy_bundle_value("ak:realm:first")
            .and_then(|value| value.get("policy_revision"))
            .and_then(Value::as_u64),
        Some(1)
    );
    assert_eq!(
        state
            .realm_policy_bundle_value("ak:realm:second")
            .and_then(|value| value.get("policy_revision"))
            .and_then(Value::as_u64),
        Some(4)
    );
    assert!(
        state
            .realm_policy_bundle_value("ak:realm:missing")
            .is_none()
    );
}

#[test]
fn a_subject_keyed_facet_keeps_its_values_isolated_by_realm() {
    let mut state = ProjectionState::new();
    let first_realm = "ak:realm:AfIbRfUkX5fr8sWMWUzYZMiIwiHVj7tWH1Sl0W6DR9PQ";
    let second_realm = "ak:realm:AciqNsLTCvFHPZIbNMxgqrpGZT_y58mPatmdG-8CC4UA";
    let target = FacetRef::new(facet::INVITE_LIVE_TARGET, "A".repeat(43));

    state.set_facet(first_realm, target.clone(), serde_json::json!("first"));

    assert_eq!(
        state.facet_value(first_realm, &target),
        Some(&serde_json::json!("first"))
    );
    assert_eq!(state.facet_value(second_realm, &target), None);

    state.set_facet(second_realm, target.clone(), serde_json::json!("second"));

    assert_eq!(
        state.facet_value(first_realm, &target),
        Some(&serde_json::json!("first"))
    );
    assert_eq!(
        state.facet_value(second_realm, &target),
        Some(&serde_json::json!("second"))
    );
    // Each Realm counts its own accepted writes to the same facet.
    assert_eq!(state.facet_revision(first_realm, &target), 1);
    assert_eq!(state.facet_revision(second_realm, &target), 1);
}

fn base_search_policy() -> Value {
    serde_json::json!({
        "enabled_profile_refs": ["ak.profile.search.blind_index.v1"],
        "allowed_service_ids": ["ak:did_core:web:search.example"],
        "data_classes": ["blind_tokens"],
        "revocation_behavior": "fail_closed",
        "leakage_class": "deterministic_token",
        "index_retention_ms": 86_400_000u64,
    })
}

fn apply_search_policy_payload(payload: Value) -> ProjectionEffect {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    state.apply(
        &make_operation(
            arkret_wire::EventKind::RealmSearchPolicy,
            "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb",
            payload,
        ),
        &hlc,
    )
}

fn assert_search_policy_rejected(payload: Value, expected_reason: &str) {
    match apply_search_policy_payload(payload) {
        ProjectionEffect::Rejected { reason } => assert_eq!(reason, expected_reason),
        other => panic!("expected search policy rejection, got {other:?}"),
    }
}

#[test]
fn realm_search_policy_accepts_wrapped_valid_policy_and_projects_inner_value() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let policy = base_search_policy();
    let effect = state.apply(
        &make_operation(
            arkret_wire::EventKind::RealmSearchPolicy,
            "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb",
            serde_json::json!({ "value": policy.clone() }),
        ),
        &hlc,
    );
    assert!(matches!(
        effect,
        ProjectionEffect::RealmSearchPolicyProjected { .. }
    ));
    let cell = state
        .realm_search_policy_value("ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb")
        .expect("search policy cell should resolve");
    assert_eq!(cell, &policy);
}

#[test]
fn realm_search_policy_forward_private_requires_matching_leakage_class() {
    let mut policy = base_search_policy();
    policy["enabled_profile_refs"] = serde_json::json!(["ak.profile.search.forward_private.v1"]);
    policy.as_object_mut().unwrap().remove("leakage_class");
    assert_search_policy_rejected(
        policy,
        "search_policy_forward_private_leakage_class_required",
    );
}

#[test]
fn realm_search_policy_forward_private_requires_token_rotation_cadence() {
    let mut policy = base_search_policy();
    policy["enabled_profile_refs"] = serde_json::json!([
        "ak.profile.search.blind_index.v1",
        "ak.profile.search.forward_private.v1"
    ]);
    policy["leakage_class"] = serde_json::json!("forward_private");
    assert_search_policy_rejected(
        policy,
        "search_policy_forward_private_token_rotation_required",
    );
}

#[test]
fn realm_search_policy_forward_private_requires_blind_index_profile() {
    let mut policy = base_search_policy();
    policy["enabled_profile_refs"] = serde_json::json!(["ak.profile.search.forward_private.v1"]);
    policy["leakage_class"] = serde_json::json!("forward_private");
    policy["token_rotation_cadence_ms"] = serde_json::json!(3_600_000u64);
    assert_search_policy_rejected(policy, "search_policy_forward_private_blind_index_required");
}

#[test]
fn realm_search_policy_rejects_invalid_data_class() {
    let mut policy = base_search_policy();
    policy["data_classes"] = serde_json::json!(["private_plaintext"]);
    assert_search_policy_rejected(policy, "search_policy_data_class_invalid");
}

#[test]
fn realm_search_policy_rejects_missing_revocation_behavior() {
    let mut policy = base_search_policy();
    policy
        .as_object_mut()
        .unwrap()
        .remove("revocation_behavior");
    assert_search_policy_rejected(policy, "search_policy_revocation_behavior_missing");
}

#[test]
fn realm_search_policy_rejects_access_hiding_until_supported_profile_exists() {
    let mut policy = base_search_policy();
    policy["leakage_class"] = serde_json::json!("access_hiding");
    assert_search_policy_rejected(policy, "search_policy_access_hiding_unsupported");
}

// ── 2026-08-01 policy bundle component set ──

fn apply_projected_create(
    state: &mut ProjectionState,
    realm_id: &str,
    payload: Value,
    hlc: &ServerHlc,
) -> ProjectionEffect {
    let operation = make_operation(arkret_wire::EventKind::RealmCreate, realm_id, payload);
    state.apply_projected(&operation, hlc)
}

/// The typed `initial_resolution` a Agent PCR genesis MUST carry.
/// `RealmGenesis::agent_control` owns the field, so the reducer tests
/// build it through the constructor instead of patching the serialized payload.
fn agent_initial_resolution() -> arkret_models_identity::ResolutionCommitment {
    arkret_models_identity::ResolutionCommitment {
        did: arkret_identifiers::Did::new("did:webvh:z6mkreducertest:reducer-test.example")
            .unwrap(),
        method_history_head: format!("sha256:{}", "8".repeat(64)),
        version_id: "1-Qmreducertest".to_owned(),
    }
}

#[test]
fn agent_genesis_activates_the_agent_status_facet_once() {
    let realm_id = "ak:realm:AcCjaDaAwSr00p03dwj9Gz2Aeq-1E2F2dAXTHFzPSdbQ";
    let agent_id = arkret_identifiers::DidCoreId::new("ak:did_core:webvh:z6mkreducertest").unwrap();
    let genesis = arkret_models_collaboration::events_payloads::RealmGenesis::new(
        arkret_models_collaboration::events_payloads::RealmPurpose::AgentControl,
        arkret_wire::GenesisSalt::new("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned())
            .unwrap(),
        arkret_identifiers::TrustDomainId::new("ak:trust_domain:agent-pcr".to_owned()).unwrap(),
        arkret_wire::SecurityClass::HighAssurance,
        arkret_identifiers::DidCoreId::new(FIXTURE_GOVERNANCE_STATION).unwrap(),
        arkret_wire::JoinRule::Invite,
        arkret_wire::HistoryAccess::SinceJoin,
        arkret_wire::Discoverability::InviteOnly,
        None,
        Some(agent_initial_resolution()),
    )
    .unwrap();
    let payload = arkret_models_collaboration::events_payloads::RealmCreatePayload::new(genesis)
        .to_value()
        .unwrap();
    let mut state = ProjectionState::new();

    let event_id = derived_event_id_for_actor(
        arkret_wire::EventKind::RealmCreate,
        realm_id,
        0,
        &payload,
        agent_id.clone(),
    );
    let mut operation = make_operation(
        arkret_wire::EventKind::RealmCreate,
        realm_id,
        payload.clone(),
    );
    operation.context.sender = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        agent_id.clone(),
        agent_id.clone(),
    ));
    operation.context.accepted_event_id = event_id;
    operation.created_at = chrono::DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
        .unwrap()
        .with_timezone(&chrono::Utc);
    let effect = state.apply_projected(&operation, &ServerHlc::new("test"));
    assert!(
        !matches!(effect, ProjectionEffect::Rejected { .. }),
        "Agent genesis unexpectedly rejected: {effect:?}"
    );
    assert_eq!(
        state
            .agent_lifecycles
            .get(&operation.context.sender.canonical_key().unwrap()),
        Some(&arkret_models_collaboration::agent_operations::AgentLifecycleState::Active)
    );
    let actor = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        agent_id.clone(),
        agent_id.clone(),
    ));
    let status = FacetRef::new(facet::AGENT_STATUS, actor_facet_subject(&actor));
    assert_eq!(
        state.facet_value(realm_id, &status),
        Some(&serde_json::json!("active"))
    );
    assert_eq!(state.facet_revision(realm_id, &status), 1);
    let mut replay = make_operation(arkret_wire::EventKind::RealmCreate, realm_id, payload);
    replay.context.sender =
        arkret_wire::ActorId::account(arkret_wire::AccountId::new(agent_id.clone(), agent_id));
    assert!(matches!(
        state.apply_projected(&replay, &ServerHlc::new("test")),
        ProjectionEffect::Rejected { reason }
            if reason == "invalid_agent_lifecycle_transition"
    ));
}

fn apply_bundle(state: &mut ProjectionState, realm_id: &str, payload: Value) -> ProjectionEffect {
    let operation = make_operation(arkret_wire::EventKind::RealmPolicyBundle, realm_id, payload);
    state.apply_realm_policy_bundle(&operation)
}

#[test]
fn policy_bundle_revision_starts_at_one_and_advances_without_gaps() {
    let realm_id = "ak:realm:AcCjaDaAwSr00p03dwj9Gz2Aeq-1E2F2dAXTHFzPSdbQ";
    let mut state = ProjectionState::new();

    assert!(matches!(
        apply_bundle(
            &mut state,
            realm_id,
            serde_json::json!({"policy_revision": 2, "media_service_decrypts": true}),
        ),
        ProjectionEffect::Rejected { reason }
            if reason == arkret_wire::ReasonCode::POLICY_REVISION_GAP
    ));
    assert!(matches!(
        apply_bundle(
            &mut state,
            realm_id,
            serde_json::json!({"policy_revision": 1, "media_service_decrypts": true}),
        ),
        ProjectionEffect::RealmPolicyBundleProjected { .. }
    ));
    assert!(matches!(
        apply_bundle(
            &mut state,
            realm_id,
            serde_json::json!({"policy_revision": 1, "media_service_decrypts": false}),
        ),
        ProjectionEffect::Rejected { reason }
            if reason == arkret_wire::ErrorCode::POLICY_REVISION_ROLLBACK
    ));
    assert!(matches!(
        apply_bundle(
            &mut state,
            realm_id,
            serde_json::json!({"policy_revision": 3, "media_service_decrypts": false}),
        ),
        ProjectionEffect::Rejected { reason }
            if reason == arkret_wire::ReasonCode::POLICY_REVISION_GAP
    ));
    assert!(matches!(
        apply_bundle(
            &mut state,
            realm_id,
            serde_json::json!({"policy_revision": 2, "media_service_decrypts": false}),
        ),
        ProjectionEffect::RealmPolicyBundleProjected { .. }
    ));
}

#[test]
fn bootstrap_policy_bundle_uses_registered_value_without_projection_metadata() {
    let realm_id = "ak:realm:AcCjaDaAwSr00p03dwj9Gz2Aeq-1E2F2dAXTHFzPSdbQ";
    let mut state = ProjectionState::new();
    let payload = serde_json::json!({
        "policy_revision": 1,
        "federation_policy": "restricted"
    });
    let operation = make_operation(arkret_wire::EventKind::RealmPolicyBundle, realm_id, payload);

    assert!(matches!(
        state.apply_realm_bootstrap_facet(&operation),
        ProjectionEffect::RealmPolicyBundleProjected { .. }
    ));
    // The bootstrap path stores the accepted payload verbatim: no projection
    // metadata is wrapped around it.
    assert_eq!(
        state.realm_policy_bundle_value(realm_id),
        Some(&serde_json::json!({
            "policy_revision": 1,
            "federation_policy": "restricted"
        }))
    );
}

/// Every Realm-bootstrap facet kind must reach the reducer through the
/// dispatch registry, not only through a direct call.
///
/// `services::projection::apply_realm_bootstrap_to_state` turns
/// `ProjectionEffect::Ignored` into a hard `RealmBootstrapProjectionError`,
/// so a kind that the registry's no-op fallback swallows fails Realm
/// bootstrap outright rather than degrading quietly. The direct-call tests
/// above cannot see that: they bypass the registry.
#[test]
fn every_bootstrap_facet_kind_is_reachable_through_the_dispatch_registry() {
    let cases = [
        (
            arkret_wire::EventKind::RealmAlias,
            serde_json::json!({ "alias": "#room:example.org" }),
        ),
        (
            arkret_wire::EventKind::RealmJoinRule,
            serde_json::json!({ "value": "invite" }),
        ),
        (
            arkret_wire::EventKind::RealmDiscovery,
            serde_json::json!({ "value": "private" }),
        ),
        (
            arkret_wire::EventKind::RealmPlaintextVisibleServices,
            serde_json::json!({ "services": [] }),
        ),
    ];
    let realm_id = "ak:realm:AZ5nQ0y2uZ3d1tVvJ7mK8sXbR4fPcHlWgEoNiTaUdY6B";
    for (kind, payload) in cases {
        let mut state = ProjectionState::new();
        let operation = make_operation(kind.clone(), realm_id, payload.clone());
        let effect = state.apply(&operation, &ServerHlc::new("test"));
        assert!(
            matches!(
                effect,
                ProjectionEffect::RealmBootstrapFacetProjected { .. }
            ),
            "{kind:?} must project a bootstrap facet, got {effect:?}"
        );
        // Write-once: the bootstrap sequence declares the opening policy and a
        // second accepted Event of the same kind would silently redefine it.
        assert!(
            matches!(
                state.apply(&operation, &ServerHlc::new("test")),
                ProjectionEffect::Rejected { ref reason }
                    if reason == arkret_wire::ErrorCode::CAS_CONFLICT
            ),
            "{kind:?} must be write-once"
        );
    }
}

/// `ak.scope.read_receipt_policy` must reach its reducer through the dispatch
/// registry, not only through a direct call.
///
/// `discovery/read-receipts.md` section 2.5 names this kind the sole carrier of
/// the `scope_read_receipt_policy` current result, and the registry projects
/// the whole payload as the settled value. Before this registration the kind
/// fell through to the registry's no-op fill, so every policy an author wrote
/// was accepted on the wire and then silently dropped, leaving the parent
/// policy every child write is compared against pinned at the SDK default.
#[test]
fn read_receipt_policy_reaches_the_reducer_and_replaces_the_previous_value() {
    let realm_id = "ak:realm:AZ5nQ0y2uZ3d1tVvJ7mK8sXbR4fPcHlWgEoNiTaUdY6B";
    let mut state = ProjectionState::new();
    let strict = serde_json::json!({
        "disclosure": "required",
        "visibility": "private"
    });
    let effect = state.apply(
        &make_operation(
            arkret_wire::EventKind::ScopeReadReceiptPolicy,
            realm_id,
            strict.clone(),
        ),
        &ServerHlc::new("test"),
    );
    assert!(
        matches!(
            effect,
            ProjectionEffect::RealmReadReceiptPolicyProjected { .. }
        ),
        "read receipt policy must project its own effect, got {effect:?}"
    );
    assert_eq!(state.read_receipt_policy_value(realm_id), Some(&strict));

    // The registry projection is `set`, not write-once: a later accepted Event
    // replaces the settled value outright. A partial payload is projected
    // verbatim, so the omitted fields fall back to the section 2.5 defaults on
    // the read side rather than keeping the superseded value.
    let partial = serde_json::json!({ "disclosure": "disabled" });
    let effect = state.apply(
        &make_operation(
            arkret_wire::EventKind::ScopeReadReceiptPolicy,
            realm_id,
            partial.clone(),
        ),
        &ServerHlc::new("test"),
    );
    assert!(
        matches!(
            effect,
            ProjectionEffect::RealmReadReceiptPolicyProjected { .. }
        ),
        "a second policy Event must be accepted, got {effect:?}"
    );
    assert_eq!(state.read_receipt_policy_value(realm_id), Some(&partial));
}

/// `read_receipt_policy_payload` is a closed object with `minProperties: 1`.
///
/// Section 2.5 makes the empty object equivalent to never writing the Event,
/// and 2.5.1 requires an unrecognized field to fail as `schema_violation`
/// rather than be silently ignored -- the retired public-history bypass field
/// is the case it names.
#[test]
fn read_receipt_policy_rejects_the_empty_object_and_unknown_fields() {
    let realm_id = "ak:realm:AZ5nQ0y2uZ3d1tVvJ7mK8sXbR4fPcHlWgEoNiTaUdY6B";
    for payload in [
        serde_json::json!({}),
        serde_json::json!({ "disclosure": "optional", "public_history_bypass": true }),
        serde_json::json!({ "disclosure": "sometimes" }),
    ] {
        let mut state = ProjectionState::new();
        let effect = state.apply(
            &make_operation(
                arkret_wire::EventKind::ScopeReadReceiptPolicy,
                realm_id,
                payload.clone(),
            ),
            &ServerHlc::new("test"),
        );
        assert!(
            matches!(
                effect,
                ProjectionEffect::Rejected { ref reason }
                    if reason == arkret_wire::ErrorCode::SCHEMA_VIOLATION
            ),
            "{payload} must fail closed, got {effect:?}"
        );
        assert_eq!(state.read_receipt_policy_value(realm_id), None);
    }
}

// history_access is a two-state, narrowing-only transition.

#[test]
fn realm_history_access_initializes_an_absent_cell_once() {
    let realm_id = "ak:realm:ARKEyrg59dN-i97Pleo3vwwRkZomIcqPiuK9PtjzGLdh";
    let initialize = make_operation(
        arkret_wire::EventKind::RealmHistoryAccess,
        realm_id,
        serde_json::json!({
            "from": null,
            "to": "since_join"
        }),
    );
    let mut state = ProjectionState::new();
    assert!(!matches!(
        state.apply(&initialize, &ServerHlc::new("test")),
        ProjectionEffect::Rejected { .. }
    ));
    assert!(matches!(
        state.apply(&initialize, &ServerHlc::new("test")),
        ProjectionEffect::Rejected { ref reason }
            if reason == arkret_wire::ErrorCode::CAS_CONFLICT
    ));
}

#[test]
fn realm_history_access_can_only_tighten() {
    let realm_id = "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb";
    let initialize = make_operation(
        arkret_wire::EventKind::RealmHistoryAccess,
        realm_id,
        serde_json::json!({
            "from": null,
            "to": "all_history_for_current_members"
        }),
    );
    let mut state = ProjectionState::new();
    assert!(!matches!(
        state.apply(&initialize, &ServerHlc::new("test")),
        ProjectionEffect::Rejected { .. }
    ));

    let tighten = make_operation(
        arkret_wire::EventKind::RealmHistoryAccess,
        realm_id,
        serde_json::json!({
            "from": "all_history_for_current_members",
            "to": "since_join"
        }),
    );
    assert!(!matches!(
        state.apply(&tighten, &ServerHlc::new("test")),
        ProjectionEffect::Rejected { .. }
    ));

    let widen = make_operation(
        arkret_wire::EventKind::RealmHistoryAccess,
        realm_id,
        serde_json::json!({
            "from": "since_join",
            "to": "all_history_for_current_members"
        }),
    );
    assert!(matches!(
        state.apply(&widen, &ServerHlc::new("test")),
        ProjectionEffect::Rejected { ref reason }
            if reason == "history_access_widening_forbidden"
    ));
}
#[test]
fn the_bundle_projects_every_registered_component() {
    let realm_id = "ak:realm:AceHOoftpthiDkQTbJ0MagMb9U4Z5cfaBq0Oqh_W8EOF";
    let mut state = ProjectionState::new();
    let payload = serde_json::json!({
        "policy_revision": 1,
        "federation_policy": "restricted",
        "media_service_decrypts": true,
        "join_policy": {"combinator": "all", "gates": [{
            "gate_id": "open",
            "kind": "principal_admission",
            "allowed_did_methods": ["did:web"]
        }]},
        "handle_issuer_policies": [{
            "issuer_id": "ak:did_core:web:handles.example",
            "authorized_handle_domains": ["handles.example"],
            "issuer_class": "domain_authority"
        }],
        "agent_participation": {"agent": {
            "reply_message": true,
            "reaction_add": false,
            "reaction_remove": false,
            "accept_third_party_mention": false,
            "act_on_behalf": false
        }},
        "account_deactivation": {"member_action": "leave_all"},
        "preauth": {"consent_required": true},
        "allowed_third_party_invite_verification_ids": ["ak:did_core:web:verifier.example"]
    });
    serde_json::from_value::<
        arkret_models_collaboration::events_payloads::realm::RealmPolicyBundlePayload,
    >(payload.clone())
    .expect("fixture must use the canonical SDK policy-bundle shape");
    let effect = apply_bundle(&mut state, realm_id, payload);
    assert!(
        matches!(&effect, ProjectionEffect::RealmPolicyBundleProjected { .. }),
        "{effect:?}"
    );

    // Every added component has to be readable back out of the facet: the
    // bundle is the only carrier for components with no facet Event kind, so a
    // component the reducer drops is a component the Realm cannot express.
    let projected = state
        .realm_policy_bundle_value(realm_id)
        .expect("bundle projects");
    for component in [
        "federation_policy",
        "media_service_decrypts",
        "join_policy",
        "handle_issuer_policies",
        "agent_participation",
        "account_deactivation",
        "preauth",
        "allowed_third_party_invite_verification_ids",
    ] {
        assert!(
            projected.get(component).is_some(),
            "the reducer dropped '{component}'"
        );
    }
    assert_eq!(
        state.realm_federation_policy(realm_id).as_deref(),
        Some("restricted")
    );
}
