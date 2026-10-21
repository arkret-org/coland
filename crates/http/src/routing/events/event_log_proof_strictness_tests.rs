use coland_storage_postgres::Db;

use super::*;
use crate::config::{AppConfig, ObjectStorageConfig};
use crate::routing::events::operations::validate_operation_policy;

pub(super) fn make_state(development_mode: bool) -> AppState {
    let config = AppConfig {
        object_storage: ObjectStorageConfig::local(std::env::temp_dir().join("coland-test")),
        development_mode,
        did_resolver_allow_methods: vec!["web".to_owned(), "key".to_owned()],
        seed_demo_data: true,
        ..AppConfig::test_default()
    };
    AppState::new(config, Db { pool: None })
}

fn typed_event_envelope(kind: &str, payload: Value) -> Value {
    let event = crate::test_event::raw_event(
        kind,
        arkret_wire::ScopeRef::Realm {
            realm_id: arkret_identifiers::RealmId::new(
                "ak:realm:Ac-UY3Pau13QQGFsa1i0Ncx61I9bOu86K1F-dM8J34tC",
            )
            .unwrap(),
        },
        crate::test_actor_id_str("did:webvh:z6mkfixture:alice.example"),
        7,
        arkret_identifiers::Hlc::new("019041000000-0000-aabbccdd").unwrap(),
        payload,
    )
    .unwrap();
    serde_json::to_value(event).unwrap()
}

// Match the SDK raw projected-operation fixture's explicit self-Station account.
fn projected_fixture_actor(principal: &str) -> arkret_wire::ActorId {
    let principal = arkret_wire::DidCoreId::new(principal).unwrap();
    arkret_wire::ActorId::account(arkret_wire::AccountId::new(principal.clone(), principal))
}

fn dev_proof_envelope() -> serde_json::Map<String, Value> {
    let mut object = serde_json::Map::new();
    object.insert(
        "actor_id".to_owned(),
        json!(crate::test_account_actor(
            &arkret_wire::Did::new("did:web:alice.example").unwrap()
        )),
    );
    object.insert(
        "producer_proof".to_owned(),
        json!({
            "type": "dev-proof",
            "verification_method": "did:web:alice.example#dev_alice",
            "payload_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000"
        }),
    );
    object.insert("payload".to_owned(), json!({"body": "hello"}));
    object
}

/// Project an accepted ordinary collaboration Realm genesis: the lifecycle
/// write gate fails closed as `realm_frozen` for a Realm the projection never
/// accepted, which would mask the admission rule a case exercises.
fn install_collaboration_realm(state: &AppState, realm_id: &str) {
    state.test_projection().lock().set_realm_facet(
        realm_id,
        coland_domain::reducer::facet::REALM_GENESIS,
        json!({
            "schema": "ak.schema.realm_genesis.v1",
            "purpose": "collaboration",
            "genesis_salt": "X-kS8-uBvWQ_iuRqO7Rsv0WGBjZG2S2wJ533Tk2SJJ4",
            "trust_domain": "ak:trust_domain:policy.example",
            "security_class": "high_assurance",
            "governance_station_id": crate::test_event::station_id(),
            "initial_join_rule": "invite",
            "initial_history_access": "since_join",
            "initial_discoverability": "invite_only"
        }),
    );
}

fn session() -> SessionRecord {
    SessionRecord {
        account_pk: None,
        token_hash: "hash".to_owned(),
        actor: "ak:did_core:web:alice.example".to_owned(),
        endpoint: coland_services::identity::SessionEndpointState::HumanDevice {
            device_id: "ak:device:01904100-0000-7000-8000-a11ce0000001".to_owned(),
        },
        audience: crate::test_event::station_id().to_string(),
        session_public_key: None,
        session_grant: None,
        expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
        created_at: chrono::Utc::now(),
        revoked_at: None,
    }
}

#[tokio::test]
async fn media_plaintext_service_is_not_read_from_the_realm_meta_mirror() {
    let state = make_state(true);
    let realm_id = "ak:realm:Ac-UY3Pau13QQGFsa1i0Ncx61I9bOu86K1F-dM8J34tC";
    let now = chrono::Utc::now();
    state
        .realms()
        .store_realm_metadata(
            realm_id,
            coland_services::events::RealmMetadata {
                owner: "did:web:alice.example".to_owned(),
                deleted: false,
                discoverability: "restricted".to_owned(),
                history_access: "since_join".to_owned(),
                preview_policy: None,
                preview_policy_digest: None,
                asset_privacy_policy: None,
                asset_privacy_policy_digest: None,
                encryption_profile: None,
                plaintext_visible_services: std::collections::BTreeSet::from([state
                    .service_id()
                    .clone()]),
                plaintext_visible_service_classes: std::collections::BTreeMap::from([(
                    state.service_id().clone(),
                    std::collections::BTreeSet::from([
                        arkret_wire::PlaintextDataClassKind::MediaPlaintext,
                    ]),
                )]),
                minimal_metadata_realm: false,
                created_at: now,
                updated_at: now,
            },
        )
        .await
        .unwrap();

    let undeclared = json!({ "media_service_decrypts": true });
    assert!(!projected_media_plaintext_service_present(&state, realm_id, &undeclared).await);
    let declared = json!({
        "media_service_decrypts": true,
        "plaintext_visible_services": [{
            "service_id": state.service_id(),
            "data_classes": ["media_plaintext"],
        }],
    });
    assert!(projected_media_plaintext_service_present(&state, realm_id, &declared).await);
}

#[tokio::test]
async fn circle_scoped_write_requires_circle_membership() {
    // circle.md §8 two-layer AND — a Realm-wide capability does NOT let a
    // non-member write into a Circle. The membership conjunct is enforced at
    // admission (`validate_operation_policy`), not only on the delivery side.
    // Regression guard for the gap where a Realm-wide grant (notably an Applet
    // bot / Ghost Actor) could inject content into a Circle it never joined.
    let state = make_state(true);
    let realm_id = "ak:realm:AU3fkxq_f4TuVlpZppN3pSPHhVOTTikXW_-Hw0vr9XCp";
    install_collaboration_realm(&state, realm_id);
    let circle_id = "ak:circle:AZT0NDzMS5h5Oz8ih_r5JqLxOrZZy4HxcAEY5s1MbM9K";
    let member = "ak:did_core:web:alice.example";
    // An Applet bot that holds a Realm-wide grant but never joined the Circle.
    let non_member = "ak:did_core:web:slack-bridge.example:bot";
    let now = chrono::Utc::now();

    // Seed an active Circle whose only member is `member`.
    {
        let mut projection = state.test_projection().lock();
        projection.circles.insert(
            circle_id.to_owned(),
            coland_domain::reducer::CircleProjection {
                circle_id: circle_id.to_owned(),
                realm_id: realm_id.to_owned(),
                profile_ref: None,
                title: "HR-Conf".to_owned(),
                summary: None,
                display: serde_json::json!({"short_name":"HR","color_token":"slate","symbol":{"glyph":"ring"}}),
                directory_visibility: "members".to_owned(),
                join_rule: "invite".to_owned(),
                history_access: "since_join".to_owned(),
                mls_group_ref: None,
                state: coland_domain::reducer::CircleLifecycleState::Active,
                state_changed_at: None,
                created_by: member.to_owned(),
                created_at: now,
                updated_by: None,
                updated_at: None,
                members: std::collections::BTreeSet::from([projected_fixture_actor(member).to_string()]),
            },
        );
    }

    let strand_create = |sender: &str, scope: Option<&str>| {
        let mut object = json!({
            "id": "ak:strand:AYTeR35PxnHtaUMXFLoHqGA1yiou3pai07-tzQyViJnt",
            "metadata": {"title": "t"}
        });
        if let Some(scope) = scope {
            object["scope_circle_id"] = json!(scope);
        }
        arkret_event_draft::test_support::raw_projected_operation(
            arkret_identifiers::OperationId::new(
                "ak:operation:01904100-0000-7000-8000-57d7d8550abc",
            )
            .unwrap(),
            arkret_identifiers::RealmId::new(realm_id.to_owned()).unwrap(),
            arkret_wire::EventKind::StrandCreate.as_str(),
            json!({"sender": sender, "object": object}),
        )
    };

    // Member writing into the Circle → allowed by this gate.
    validate_operation_policy(
        &state,
        std::slice::from_ref(&strand_create(member, Some(circle_id))),
    )
    .await
    .unwrap();

    // Non-member (Applet bot) writing into the Circle → rejected fail-closed.
    let err = validate_operation_policy(
        &state,
        std::slice::from_ref(&strand_create(non_member, Some(circle_id))),
    )
    .await
    .unwrap_err();
    assert_eq!(err, "circle_scope_membership_required");

    // Non-member writing a Realm-default Strand (no Circle scope) → unaffected.
    validate_operation_policy(
        &state,
        std::slice::from_ref(&strand_create(non_member, None)),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn circle_scoped_reaction_requires_circle_membership() {
    // circle.md §8 — a reaction is a write into the target Message's Strand
    // scope, so reacting to a Circle message requires Circle membership too.
    let state = make_state(true);
    let realm_id = "ak:realm:Af5kTRq88MZ71EExjwb7Pm9AHmO7tPZB470XwPwDiYge";
    install_collaboration_realm(&state, realm_id);
    let circle_id = "ak:circle:AS5EmLqkRoAqtHJcDm0xGwZ8A-MgC4120y4IpSAbqFCJ";
    let strand_id = "ak:strand:AekvaCkXy9kgtwfnxzaKIOIIHF_-HZpSbCakATPdwWMH";
    let event_id = "ak:event:ATISmX7h_m-9AlDVmW5cqCG9eM06QsDQFjEjG675Jf3A";
    let member = "ak:did_core:web:alice.example";
    let non_member = "ak:did_core:web:slack-bridge.example:bot";
    let now = chrono::Utc::now();

    {
        let mut projection = state.test_projection().lock();
        projection.circles.insert(
            circle_id.to_owned(),
            coland_domain::reducer::CircleProjection {
                circle_id: circle_id.to_owned(),
                realm_id: realm_id.to_owned(),
                profile_ref: None,
                title: "HR-Conf".to_owned(),
                summary: None,
                display: serde_json::json!({"short_name":"HR","color_token":"slate","symbol":{"glyph":"ring"}}),
                directory_visibility: "members".to_owned(),
                join_rule: "invite".to_owned(),
                history_access: "since_join".to_owned(),
                mls_group_ref: None,
                state: coland_domain::reducer::CircleLifecycleState::Active,
                state_changed_at: None,
                created_by: member.to_owned(),
                created_at: now,
                updated_by: None,
                updated_at: None,
                members: std::collections::BTreeSet::from([projected_fixture_actor(member).to_string()]),
            },
        );
        // A Strand scoped to the Circle, and a Message inside it.
        projection.strands.insert(
            strand_id.to_owned(),
            coland_domain::reducer::StrandProjection {
                strand_id: strand_id.to_owned(),
                realm_id: realm_id.to_owned(),
                tracks: std::collections::BTreeMap::from([(
                    arkret_models_collaboration::objects::profiles::STRAND_TRACK_NAME_DISCUSSION
                        .to_owned(),
                    arkret_models_collaboration::objects::profiles::StrandTrack::discussion_primary(
                    ),
                )]),
                title: String::new(),
                summary: None,
                content: None,
                encrypted_content: None,
                fields: std::collections::BTreeMap::new(),
                state: coland_domain::reducer::ObjectLifecycleState::Active,
                state_changed_at: None,
                stage: None,
                stage_changed_at: None,
                created_by: member.to_owned(),
                created_at: now,
                updated_by: None,
                updated_at: None,
                schema_refs: Vec::new(),
                schedule_revision_source: None,
                scope_circle_id: Some(circle_id.to_owned()),
            },
        );
        projection.messages.insert(
            event_id.to_owned(),
            coland_domain::reducer::MessageState {
                event_id: event_id.to_owned(),
                message_id: coland_domain::reducer::message_id_from_event_id(event_id),
                realm_id: realm_id.to_owned(),
                sender: member.to_owned(),
                thread_id: strand_id.to_owned(),
                content: json!({}),
                encrypted: false,
                operation_id: "ak:operation:01904100-0000-7000-8000-c2c2e0000005".to_owned(),
                created_at: now,
                revision_of: None,
                redacted_at: None,
            },
        );
    }

    let reaction = |sender: &str| {
        arkret_event_draft::test_support::raw_projected_operation(
            arkret_identifiers::OperationId::new(
                "ak:operation:01904100-0000-7000-8000-c2c2e000000a",
            )
            .unwrap(),
            arkret_identifiers::RealmId::new(realm_id.to_owned()).unwrap(),
            arkret_wire::EventKind::ReactionAdd.as_str(),
            json!({"sender": sender, "target_ref": event_id, "key": "👍"}),
        )
    };

    // Member may react in the Circle.
    validate_operation_policy(&state, std::slice::from_ref(&reaction(member)))
        .await
        .unwrap();

    // Non-member reacting to a Circle message is rejected.
    let err = validate_operation_policy(&state, std::slice::from_ref(&reaction(non_member)))
        .await
        .unwrap_err();
    assert_eq!(err, "circle_scope_membership_required");
}

#[tokio::test]
async fn circle_scoped_morph_update_requires_circle_membership() {
    // circle.md §8 - Morph updates are writes into the Morph's effective
    // scope. A Realm-wide grant is insufficient when the Morph was created
    // under a Circle scope.
    let state = make_state(true);
    let realm_id = "ak:realm:ASTX9r6c7ZMAY74JFAIh5TyBTiwEqs5oy5TCX7ubmLVB";
    install_collaboration_realm(&state, realm_id);
    let circle_id = "ak:circle:AQIjwhwC5jFHrCd985kMq2m5ahV3nG7qBK-aMMYLbgAt";
    let scoped_morph_id = "ak:morph:AXlXsex0Kgdp6mgmqub7aKP53d1_Zp7PifQwrYfC-8HO";
    let realm_morph_id = "ak:morph:AXg0u_PNFrZzEeHPh_4tFOFF7XNlDbiHiSewgv_unmDK";
    let member = "ak:did_core:web:alice.example";
    let non_member = "ak:did_core:web:slack-bridge.example:bot";
    let now = chrono::Utc::now();

    {
        let mut projection = state.test_projection().lock();
        projection.circles.insert(
            circle_id.to_owned(),
            coland_domain::reducer::CircleProjection {
                circle_id: circle_id.to_owned(),
                realm_id: realm_id.to_owned(),
                profile_ref: None,
                title: "HR-Conf".to_owned(),
                summary: None,
                display: serde_json::json!({"short_name":"HR","color_token":"slate","symbol":{"glyph":"ring"}}),
                directory_visibility: "members".to_owned(),
                join_rule: "invite".to_owned(),
                history_access: "since_join".to_owned(),
                mls_group_ref: None,
                state: coland_domain::reducer::CircleLifecycleState::Active,
                state_changed_at: None,
                created_by: member.to_owned(),
                created_at: now,
                updated_by: None,
                updated_at: None,
                members: std::collections::BTreeSet::from([projected_fixture_actor(member).to_string()]),
            },
        );
        for (morph_id, scope_circle_id) in [
            (scoped_morph_id, Some(circle_id.to_owned())),
            (realm_morph_id, None),
        ] {
            projection.morphs.insert(
                morph_id.to_owned(),
                coland_domain::reducer::MorphProjection {
                    morph_id: morph_id.to_owned(),
                    realm_id: realm_id.to_owned(),
                    scope_circle_id,
                    morph_kind: "task".to_owned(),
                    title: Some("Task".to_owned()),
                    fields: std::collections::BTreeMap::new(),
                    schema_refs: Vec::new(),
                    facets: BTreeMap::new(),
                    versions: Vec::new(),
                    content: None,
                    encrypted_content: None,
                    state: coland_domain::reducer::ObjectLifecycleState::Active,
                    state_changed_at: None,
                    stage: None,
                    stage_changed_at: None,
                    created_by: member.to_owned(),
                    created_at: now,
                    updated_by: None,
                    updated_at: None,
                },
            );
        }
    }

    let morph_update = |sender: &str, morph_id: &str| {
        arkret_event_draft::test_support::raw_projected_operation(
            arkret_identifiers::OperationId::new(
                "ak:operation:01904100-0000-7000-8000-c3c3e000000a",
            )
            .unwrap(),
            arkret_identifiers::RealmId::new(realm_id.to_owned()).unwrap(),
            arkret_wire::EventKind::MorphUpdate.as_str(),
            json!({
                "sender": sender,
                "target_ref": morph_id,
                "patch": {"fields.status": "done"}
            }),
        )
    };

    validate_operation_policy(
        &state,
        std::slice::from_ref(&morph_update(member, scoped_morph_id)),
    )
    .await
    .unwrap();

    let err = validate_operation_policy(
        &state,
        std::slice::from_ref(&morph_update(non_member, scoped_morph_id)),
    )
    .await
    .unwrap_err();
    assert_eq!(err, "circle_scope_membership_required");

    validate_operation_policy(
        &state,
        std::slice::from_ref(&morph_update(non_member, realm_morph_id)),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn applet_registration_requires_realm_admin() {
    // applet-integration.md §4 — `ak.applet.registration` is gated by the
    // machine-readable `ak.realm.admin` capability. The dedicated install
    // aggregate checks this in its handler, but a raw submit via
    // `/_arkret/self/events` reaches `apply_applet_registration` with no authz of
    // its own — this gate closes that bypass. Realm ownership alone is not a
    // capability; an active `ak.realm.admin` grant is required.
    let state = make_state(true);
    let realm_id = "ak:realm:Aaleb4QrS8SxR5KXmKfDQZMNxW8WlSaUaySdeWV2-hVl";
    install_collaboration_realm(&state, realm_id);
    let owner = "ak:did_core:web:alice.example";
    let outsider = "ak:did_core:web:mallory.example";
    let now = chrono::Utc::now();
    state
        .test_persistence()
        .capability_grant_current_results()
        .seed_test_realm_root(
            &arkret_identifiers::RealmId::new(realm_id).unwrap(),
            &projected_fixture_actor("ak:did_core:web:root-controller.example"),
        )
        .await
        .unwrap();
    state
        .realms()
        .store_realm_metadata(
            realm_id,
            coland_services::events::RealmMetadata {
                owner: owner.to_owned(),
                deleted: false,
                discoverability: "restricted".to_owned(),
                history_access: "since_join".to_owned(),
                preview_policy: None,
                preview_policy_digest: None,
                asset_privacy_policy: None,
                asset_privacy_policy_digest: None,
                encryption_profile: None,
                plaintext_visible_services: std::collections::BTreeSet::new(),
                plaintext_visible_service_classes: Default::default(),
                minimal_metadata_realm: false,
                created_at: now,
                updated_at: now,
            },
        )
        .await
        .unwrap();

    let registration = |sender: &str| {
        arkret_event_draft::test_support::raw_projected_operation(
            arkret_identifiers::OperationId::new(
                "ak:operation:01904100-0000-7000-8000-57d7d855a99e",
            )
            .unwrap(),
            arkret_identifiers::RealmId::new(realm_id.to_owned()).unwrap(),
            arkret_wire::EventKind::AppletRegistration.as_str(),
            json!({
                "sender": sender,
                "applet_id": "ak:applet:01904100-0000-7000-8000-000000000a01",
                "service_id": "ak:did_core:web:slack-bridge.example",
                "namespace": "slack",
            }),
        )
    };

    let err = validate_operation_policy(&state, std::slice::from_ref(&registration(owner)))
        .await
        .unwrap_err();
    assert_eq!(err, "applet_registration_unauthorized");

    // A separate root controller issues the owner an explicit grant: the
    // metadata owner mirror is never the authority root.
    let realm = arkret_identifiers::RealmId::new(realm_id.to_owned()).unwrap();
    let store = state.test_persistence();
    let grants = store.capability_grant_current_results();
    grants
        .seed_test_realm_root(
            &realm,
            &projected_fixture_actor("ak:did_core:web:root-controller.example"),
        )
        .await
        .unwrap();
    grants
        .seed_test_grant(&coland_storage::TestCapabilityGrant {
            realm_id: realm.clone(),
            subject: projected_fixture_actor(owner),
            actions: vec![arkret_wire::CapabilityActionId::REALM_ADMIN.to_owned()],
            resources: vec![arkret_wire::WireResourceSelector::realm(realm)],
            constraints: Vec::new(),
        })
        .await
        .unwrap();
    validate_operation_policy(&state, std::slice::from_ref(&registration(owner)))
        .await
        .unwrap();

    let err = validate_operation_policy(&state, std::slice::from_ref(&registration(outsider)))
        .await
        .unwrap_err();
    assert_eq!(err, "applet_registration_unauthorized");
}

#[test]
fn closed_event_contract_requires_canonical_time_and_rejects_retired_aliases() {
    let original = typed_event_envelope(
        "ak.message.create",
        json!({
            "strand_id": "ak:strand:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "track_name": "discussion", "content": {"kind":"ak.content.text","body":"hello"}
        }),
    );
    serde_json::from_value::<arkret_wire::Event>(original.clone()).unwrap();
    // Use the production envelope validator before payload validation.
    for development in [false, true] {
        let state = make_state(development);
        for timestamp in [None, Some(json!("2026-09-28T00:00:00+00:00"))] {
            let mut invalid = original.clone();
            match timestamp {
                Some(value) => {
                    invalid["created_at"] = value;
                }
                None => {
                    invalid.as_object_mut().unwrap().remove("created_at");
                }
            }
            assert!(
                validate_event_schema_and_payload(
                    &state,
                    "ak.message.create",
                    arkret_wire::SchemaId::EVENT_V1,
                    &invalid,
                    invalid.as_object().unwrap()
                )
                .is_err()
            );
        }
        for alias in [
            "crit",
            "critical",
            "critical_features",
            "requirements",
            "schema_id",
        ] {
            let mut invalid = original.clone();
            invalid[alias] = json!([]);
            assert!(
                validate_event_schema_and_payload(
                    &state,
                    "ak.message.create",
                    arkret_wire::SchemaId::EVENT_V1,
                    &invalid,
                    invalid.as_object().unwrap()
                )
                .is_err(),
                "retired alias {alias}"
            );
        }
    }
}

#[test]
fn top_level_effective_scope_is_reducer_managed() {
    let event = crate::test_event::raw_event(
        arkret_wire::EventKind::RealmCreate.as_str(),
        arkret_wire::ScopeRef::Realm {
            realm_id: arkret_identifiers::RealmId::new(
                "ak:realm:Ac-UY3Pau13QQGFsa1i0Ncx61I9bOu86K1F-dM8J34tC",
            )
            .unwrap(),
        },
        crate::test_actor_id_str("did:web:alice.example"),
        1,
        arkret_identifiers::Hlc::new("019041000000-0000-aabbccdd").unwrap(),
        json!({"object": {"id": "ak:realm:Ac-UY3Pau13QQGFsa1i0Ncx61I9bOu86K1F-dM8J34tC"}}),
    )
    .unwrap();
    let mut envelope = serde_json::to_value(event).unwrap();
    envelope["effective_scope"] = json!("ak:realm:Ac-UY3Pau13QQGFsa1i0Ncx61I9bOu86K1F-dM8J34tC");

    let err = serde_json::from_value::<arkret_wire::Event>(envelope)
        .expect_err("clients must not supply reducer-managed effective_scope");
    assert!(err.to_string().contains("unknown field"));
}

#[test]
fn event_canonical_bytes_use_sdk_canonical_json() {
    let event = crate::test_event::raw_event(
        "ak.test.canonical",
        arkret_wire::ScopeRef::Realm {
            realm_id: arkret_identifiers::RealmId::new(
                "ak:realm:Ac-UY3Pau13QQGFsa1i0Ncx61I9bOu86K1F-dM8J34tC",
            )
            .unwrap(),
        },
        crate::test_actor_id_str("did:webvh:z6mkfixture:alice.example"),
        7,
        arkret_identifiers::Hlc::new("019041000000-0000-aabbccdd").unwrap(),
        json!({"z": 1, "a": {"b": 2, "a": 1}}),
    )
    .unwrap();
    let expected =
        arkret_canonical::canonical_json_bytes(&event.digest_payload().unwrap()).unwrap();
    let mut envelope = serde_json::to_value(&event).unwrap();
    envelope["canonical_digest"] = json!("sha256:old");
    let bytes = event_canonical_bytes(&envelope).unwrap();
    let text = String::from_utf8(bytes).unwrap();
    assert_eq!(text.as_bytes(), expected);
    assert!(text.contains(r#""payload":{"a":{"a":1,"b":2},"z":1}"#));
    assert!(!text.contains("unsigned"));
    assert!(!text.contains("canonical_digest"));
}

#[test]
fn event_canonical_bytes_reject_fractional_numbers() {
    let event = crate::test_event::raw_event(
        "ak.test.canonical",
        arkret_wire::ScopeRef::Realm {
            realm_id: arkret_identifiers::RealmId::new(
                "ak:realm:Ac-UY3Pau13QQGFsa1i0Ncx61I9bOu86K1F-dM8J34tC",
            )
            .unwrap(),
        },
        crate::test_actor_id_str("did:webvh:z6mkfixture:alice.example"),
        7,
        arkret_identifiers::Hlc::new("019041000000-0000-aabbccdd").unwrap(),
        json!({"rank": 1}),
    )
    .unwrap();
    let mut envelope = serde_json::to_value(event).unwrap();
    envelope["payload"]["rank"] = json!(1.5);
    let err = event_canonical_bytes(&envelope)
        .expect_err("Arkret canonical JSON rejects fractional numbers");
    assert_eq!(err.code, "schema_violation");
}

#[test]
fn event_payload_validator_rejects_registered_payload_shape_errors() {
    let state = make_state(true);
    let envelope = typed_event_envelope(
        "ak.strand.move",
        json!({
            "strand_id": "ak:strand:AR3ud0srmtpodQ47XfsVC4uD75mQDAGaKLEww6VGMZZC"
        }),
    );
    let object = envelope.as_object().unwrap();
    let err = validate_event_schema_and_payload(
        &state,
        "ak.strand.move",
        "ak.schema.event.v1",
        &envelope,
        object,
    )
    .expect_err("strand.move without target/rank must fail payload validation");
    assert_eq!(err.code, "schema_violation");
}

#[test]
fn schema_define_admission_executes_the_registered_definition_validator_profile() {
    let state = make_state(true);
    let valid = typed_event_envelope(
        arkret_wire::EventKind::SchemaDefine.as_str(),
        json!({
            "value": {
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "$id": "ak.schema.example.v1",
                "type": "string"
            }
        }),
    );
    validate_event_schema_and_payload(
        &state,
        arkret_wire::EventKind::SchemaDefine.as_str(),
        "ak.schema.event.v1",
        &valid,
        valid.as_object().unwrap(),
    )
    .expect("valid Draft 2020-12 schema definition must pass admission");

    for invalid_payload in [
        json!({
            "value": {
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "type": "string"
            }
        }),
        json!({
            "value": {
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "$id": "ak.schema.example.v1",
                "type": "not_a_json_schema_type"
            }
        }),
    ] {
        let invalid = typed_event_envelope(
            arkret_wire::EventKind::SchemaDefine.as_str(),
            invalid_payload,
        );
        let error = validate_event_schema_and_payload(
            &state,
            arkret_wire::EventKind::SchemaDefine.as_str(),
            "ak.schema.event.v1",
            &invalid,
            invalid.as_object().unwrap(),
        )
        .expect_err("invalid schema definition must fail admission");
        assert_eq!(error.code, "schema_violation");
    }
}

#[test]
fn member_state_join_schema_allows_contextual_invite_ref() {
    let state = make_state(true);
    let valid = typed_event_envelope(
        "ak.member.state",
        json!({
            "member_id": projected_fixture_actor("ak:did_core:web:bob.example"),
            "realm_id": "ak:realm:Abeq9pC3fxOERl1X0ivHa5cJCBy41KfYu5LKvGfPFq5K",
            "membership": "join",
            "reason": "invite_accept",
            "invite_ref": "ak:invite:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19"
        }),
    );
    validate_event_schema_and_payload(
        &state,
        "ak.member.state",
        "ak.schema.event.v1",
        &valid,
        valid.as_object().unwrap(),
    )
    .expect("ak.member.state join schema should allow contextual invite_ref");
}

#[test]
fn event_payload_validator_enforces_strand_update_patch_schema() {
    let state = make_state(true);
    let strand_id = "ak:strand:AR3ud0srmtpodQ47XfsVC4uD75mQDAGaKLEww6VGMZZC";
    let valid = typed_event_envelope(
        "ak.strand.update",
        json!({
            "target_ref": strand_id,
            "patch": {
                "fields.document": {
                    "$op": "set",
                    "value": { "blocks": [] }
                }
            }
        }),
    );
    validate_event_schema_and_payload(
        &state,
        "ak.strand.update",
        "ak.schema.event.v1",
        &valid,
        valid.as_object().unwrap(),
    )
    .expect("canonical ak.strand.update strand_patch_payload should validate");

    let invalid_patch_op = typed_event_envelope(
        "ak.strand.update",
        json!({
            "target_ref": strand_id,
            "patch": {
                "fields.document": {
                    "$op": "replace",
                    "value": { "blocks": [] }
                }
            }
        }),
    );
    let err = validate_event_schema_and_payload(
        &state,
        "ak.strand.update",
        "ak.schema.event.v1",
        &invalid_patch_op,
        invalid_patch_op.as_object().unwrap(),
    )
    .expect_err("ak.strand.update patch operations must match ak.patch.v1 exactly");
    assert_eq!(err.code, "schema_violation");
}

#[test]
fn event_payload_validator_catalog_covers_active_standard_durable_events() {
    const SIBLING_SCHEMA_EVENT_KINDS: &[&str] = &[
        arkret_wire::EventKind::ModerationFrankingProof.as_str(),
        arkret_wire::EventKind::RelationTombstone.as_str(),
    ];
    let catalog = arkret_schema_conformance::event_payload_validator_catalog().unwrap();
    let event_kinds = coland_services::protocol_artifacts::active_durable_event_kinds()
        .iter()
        .map(String::as_str)
        .filter(|kind| arkret_wire::events::is_standard_event_kind(kind))
        .filter(|kind| !SIBLING_SCHEMA_EVENT_KINDS.contains(kind))
        .collect::<Vec<_>>();
    let missing = catalog.missing_payload_validators_for(event_kinds.iter().copied());
    assert!(
        missing.is_empty(),
        "missing payload validators: {missing:?}"
    );
    assert!(
        event_kinds.len() > 20,
        "catalog coverage test should cover the active registry, not a fixture subset"
    );
}

#[test]
fn event_payload_validator_enforces_patch_family_schema() {
    let catalog = arkret_schema_conformance::event_payload_validator_catalog().unwrap();
    let patch_kinds = [
        "ak.strand.update",
        "ak.morph.update",
        "ak.space.update",
        "ak.profile.update",
    ];
    let missing = catalog.missing_payload_validators_for(patch_kinds);
    assert!(
        missing.is_empty(),
        "missing patch payload validators: {missing:?}"
    );

    let payloads = [
        (
            "ak.strand.update",
            json!({
                "target_ref": "ak:strand:AR3ud0srmtpodQ47XfsVC4uD75mQDAGaKLEww6VGMZZC",
                "patch": { "metadata.title": { "$op": "set", "value": "Roadmap" } }
            }),
            json!({
                "target_ref": "ak:strand:AR3ud0srmtpodQ47XfsVC4uD75mQDAGaKLEww6VGMZZC",
                "patch": { "metadata.title": { "$op": "replace", "value": "Roadmap" } }
            }),
        ),
        (
            "ak.morph.update",
            json!({
                "target_ref": "ak:morph:AR3ud0srmtpodQ47XfsVC4uD75mQDAGaKLEww6VGMZZC",
                "patch": { "metadata.title": { "$op": "set", "value": "Roadmap" } }
            }),
            json!({
                "target_ref": "ak:morph:AR3ud0srmtpodQ47XfsVC4uD75mQDAGaKLEww6VGMZZC",
                "patch": { "metadata.title": { "$op": "replace", "value": "Roadmap" } }
            }),
        ),
        (
            "ak.space.update",
            json!({
                "space_id": "ak:space:AR3ud0srmtpodQ47XfsVC4uD75mQDAGaKLEww6VGMZZC",
                "patch": { "title": { "$op": "set", "value": "Roadmap" } }
            }),
            json!({
                "space_id": "ak:space:AR3ud0srmtpodQ47XfsVC4uD75mQDAGaKLEww6VGMZZC",
                "patch": { "title": { "$op": "replace", "value": "Roadmap" } }
            }),
        ),
        (
            "ak.profile.update",
            json!({
                "target_ref": "ak:actor_profile:AR3ud0srmtpodQ47XfsVC4uD75mQDAGaKLEww6VGMZZC",
                "patch": { "title": { "$op": "set", "value": "Roadmap" } }
            }),
            json!({
                "target_ref": "ak:actor_profile:AR3ud0srmtpodQ47XfsVC4uD75mQDAGaKLEww6VGMZZC",
                "patch": { "title": { "$op": "replace", "value": "Roadmap" } }
            }),
        ),
    ];
    for (event_kind, valid_payload, invalid_payload) in payloads {
        catalog
            .validate_payload(event_kind, &valid_payload)
            .unwrap_or_else(|err| {
                panic!("{event_kind} must accept canonical patch payload: {err}");
            });
        assert!(
            catalog
                .validate_payload(event_kind, &invalid_payload)
                .is_err(),
            "{event_kind} must reject patch ops outside ak.patch.v1"
        );
    }

    // ak.profile.realm_override carries a Realm-scoped override and uses the
    // dedicated profile_realm_override_payload (target_ref + target_realm_id
    // + patch), not the generic object_patch_payload.
    catalog
        .validate_payload(
            "ak.profile.realm_override",
            &json!({
                "target_ref": "ak:actor_profile:AR3ud0srmtpodQ47XfsVC4uD75mQDAGaKLEww6VGMZZC",
                "target_realm_id": "ak:realm:AQqDnmYP2y5kt6ZLD--QatyqmmeXf3WAeSGGrAGZoR-6",
                "patch": { "title": { "$op": "set", "value": "Roadmap" } }
            }),
        )
        .unwrap_or_else(|err| {
            panic!("ak.profile.realm_override must accept profile_realm_override_payload: {err}");
        });

    catalog
        .validate_payload(
            "ak.strand.tracks.update",
            &json!({
                "target_ref": "ak:strand:AR3ud0srmtpodQ47XfsVC4uD75mQDAGaKLEww6VGMZZC",
                "patch": {
                    "tracks.discussion.enabled": {"$op": "set", "value": true},
                    "tracks.discussion.is_primary": {"$op": "set", "value": true}
                }
            }),
        )
        .unwrap_or_else(|err| {
            panic!("ak.strand.tracks.update must accept canonical Strand patch payload: {err}");
        });
    assert!(
        catalog
            .validate_payload(
                "ak.strand.tracks.update",
                &json!({
                    "strand_id": "ak:strand:AR3ud0srmtpodQ47XfsVC4uD75mQDAGaKLEww6VGMZZC",
                    "tracks": {}
                }),
            )
            .is_err(),
        "ak.strand.tracks.update must reject retired strand_id/tracks payloads"
    );
}

#[tokio::test]
async fn production_rejects_dev_proof_type_field() {
    let state = make_state(false);
    let session = session();
    let object = dev_proof_envelope();
    let err = validate_event_proofs(
        &object,
        &state,
        &session,
        "ak:did_core:web:alice.example",
        "sha256:dead",
        arkret_canonical::DigestSuite::Sha256,
        b"{}",
        &[],
        None,
    )
    .await
    .expect_err("production must reject dev-proof shape");
    // Missing strict-JWS fields violates the SDK proof schema before verification.
    assert_eq!(err.code, "schema_violation");
}

#[tokio::test]
async fn development_rejects_dev_proof_type_field_even_when_hash_matches() {
    let state = make_state(true);
    let session = session();
    let mut object = dev_proof_envelope();
    // A matching payload-only hash must not create a development-only
    // durable Event protocol.
    let payload_bytes = canonical::canonical_json_bytes(&object["payload"]).unwrap();
    let payload_digest = arkret_canonical::sha256_digest(&payload_bytes);
    if let Some(map) = object
        .get_mut("producer_proof")
        .and_then(Value::as_object_mut)
    {
        map.insert("payload_digest".to_owned(), json!(payload_digest));
    }
    let error = validate_event_proofs(
        &object,
        &state,
        &session,
        "ak:did_core:web:alice.example",
        "sha256:dead",
        arkret_canonical::DigestSuite::Sha256,
        b"{}",
        &[],
        None,
    )
    .await
    .expect_err("development mode must reject the non-SDK proof shape");
    assert_eq!(error.code, "schema_violation");
}
