use arkret_models_collaboration::agent_operations::AgentLifecycleState;
use coland_storage_postgres::Db;
use ed25519_dalek::{Signer as _, SigningKey};
use serde_json::json;

use super::*;

const ALICE_DID: &str = "did:webvh:z6mkalice:alice.example";
const ALICE_CORE_ID: &str = "ak:did_core:webvh:z6mkalice";
const BOB_CORE_ID: &str = "ak:did_core:web:bob.example";
const AGENT_CORE_ID: &str = "ak:did_core:webvh:z6mkfixtureagent";
/// The Agent's own DID. `controller_authorization_ref` is a DID URL on the
/// Agent document, so it must project back to `AGENT_CORE_ID`.
const AGENT_DID: &str = "did:webvh:z6mkfixtureagent:agent.example";

fn fixture_actor(principal: &str) -> arkret_wire::ActorId {
    let principal = match principal {
        "ak:did_core:web:alice.example" => ALICE_CORE_ID,
        "ak:did_core:web:agent.example" => AGENT_CORE_ID,
        principal => principal,
    };
    let principal = arkret_wire::DidCoreId::new(principal).unwrap();
    arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        principal,
        crate::test_event::station_id(),
    ))
}

fn test_config() -> crate::config::AppConfig {
    crate::config::AppConfig {
        object_storage: crate::config::ObjectStorageConfig::local(
            std::env::temp_dir().join("coland-direct-conversation-policy-test-blobs"),
        ),
        development_mode: true,
        did_resolver_allow_methods: vec!["web".to_owned(), "key".to_owned()],
        notary_signing_key_seed: Some([9u8; 32]),
        seed_demo_data: true,
        ..crate::config::AppConfig::test_default()
    }
}

fn op(
    realm_id: arkret_identifiers::RealmId,
    seed: &str,
    kind: impl AsRef<str>,
    mut payload: serde_json::Value,
) -> Operation {
    if let Some(payload) = payload.as_object_mut()
        && let Some(accepted_event_id) = payload.remove("accepted_event_id")
    {
        payload.insert("event_id".to_owned(), accepted_event_id);
    }
    let executed_by = payload
        .as_object_mut()
        .and_then(|payload| payload.remove("executed_by"));
    let sender = payload
        .as_object_mut()
        .and_then(|payload| payload.remove("sender"));
    let mut operation = arkret_event_draft::test_support::raw_projected_operation(
        arkret_identifiers::OperationId::new(format!(
            "ak:operation:01904100-0000-7000-8000-{seed}"
        ))
        .unwrap(),
        realm_id,
        kind.as_ref(),
        payload,
    );
    if let Some(executed_by) = executed_by {
        operation.context.executed_by = Some(fixture_actor(executed_by.as_str().unwrap()));
    }
    if let Some(sender) = sender {
        operation.context.sender = fixture_actor(sender.as_str().unwrap());
    }
    operation
}

#[test]
fn view_admission_rejects_retired_collection_and_actor_lifecycle_fields() {
    let realm_id =
        arkret_identifiers::RealmId::new("ak:realm:AY95PK0h663rCWpc7Z3rVOJ17tol-scPCV546wg6AoVD")
            .unwrap();
    for definition in [
        json!({"collection": {"page_size": 50}}),
        json!({"collection": {"selection_policy": "multiple"}}),
        json!({"collection": {"grouping": {"wip_limit_enforcement": "warn"}}}),
        json!({"state": "tombstoned", "state_changed_at": "2026-07-17T00:00:00.000Z"}),
    ] {
        let operation = op(
            realm_id.clone(),
            "000000000611",
            arkret_wire::EventKind::ViewUpdate,
            json!({
                "view_id": "ak:view:AfNNPHw8rPLcSH3j2BXOmYhEGZkLo7yx1Wcc_ah5qVyn",
                "patch": definition
            }),
        );
        assert_eq!(
            validate_view_payload(&operation),
            Err(arkret_wire::ErrorCode::SCHEMA_VIOLATION)
        );
    }
    let current = op(
        realm_id,
        "000000000612",
        arkret_wire::EventKind::ViewUpdate,
        json!({
            "view_id": "ak:view:AfNNPHw8rPLcSH3j2BXOmYhEGZkLo7yx1Wcc_ah5qVyn",
            "patch": {"state": "tombstoned"}
        }),
    );
    validate_view_payload(&current).unwrap();
}

#[test]
fn shared_view_events_never_carry_a_private_view() {
    // `models/views.md` §3.1: a `visibility="private"` View lives only in
    // `ak.views.private.<view_id>` account data. Admission is what keeps the
    // shared surface clean — a private View that is refused entry to the Event
    // log can never surface from a shared View query, so this is the read-side
    // guarantee as well as the write-side one.
    let realm_id =
        arkret_identifiers::RealmId::new("ak:realm:AcRoZR8_hwxZ-nwNkJO-TrgIrOADX-V8ZP_ETuQAFZNc")
            .unwrap();
    let private_view = json!({
        "kind": "collection",
        "visibility": "private",
        "title": "personal board",
        "query": {"realm_ids": [realm_id.as_str()]},
        "collection": {
            "item_object_kinds": ["task"],
            "item_order_by": [{"field": "title", "direction": "asc"}],
            "grouping": {"mode": "none"}
        }
    });
    for (seed, kind, payload) in [
        (
            "000000000613",
            arkret_wire::EventKind::ViewCreate,
            json!({
                "view_id": "ak:view:ARRwG16aeAEr0aq6GflekmZrsscWhvQoyXuccnqbxT44",
                "object": private_view.clone()
            }),
        ),
        (
            "000000000614",
            arkret_wire::EventKind::ViewUpdate,
            json!({
                "view_id": "ak:view:ARRwG16aeAEr0aq6GflekmZrsscWhvQoyXuccnqbxT44",
                "patch": {"visibility": "private"}
            }),
        ),
        (
            "000000000615",
            arkret_wire::EventKind::ViewReconcile,
            json!({
                "view_id": "ak:view:ARRwG16aeAEr0aq6GflekmZrsscWhvQoyXuccnqbxT44",
                "definition": private_view.clone()
            }),
        ),
        (
            "000000000616",
            arkret_wire::EventKind::ViewUpdate,
            json!({
                "view_id": "ak:view:ARRwG16aeAEr0aq6GflekmZrsscWhvQoyXuccnqbxT44",
                "visibility": "private"
            }),
        ),
    ] {
        let operation = op(realm_id.clone(), seed, kind.clone(), payload);
        assert_eq!(
            validate_view_payload(&operation),
            Err("private_view_requires_account_data"),
            "{kind} must refuse a private View on the shared Event surface"
        );
    }

    // The same shapes with the shared visibility are admitted, so the rejection
    // above is about `visibility`, not about the payload shape.
    let mut shared_view = private_view;
    shared_view["visibility"] = json!("shared");
    let shared = op(
        realm_id,
        "000000000617",
        arkret_wire::EventKind::ViewCreate,
        json!({
            "view_id": "ak:view:ARRwG16aeAEr0aq6GflekmZrsscWhvQoyXuccnqbxT44",
            "object": shared_view
        }),
    );
    validate_view_payload(&shared).unwrap();
}

fn test_state() -> AppState {
    AppState::new(test_config(), Db { pool: None })
}

/// Project an accepted ordinary collaboration Realm genesis.
///
/// The lifecycle write gate fails closed for a Realm the projection has never
/// accepted, so a policy case about some later write needs the Realm to exist
/// first; otherwise every write reads as `realm_frozen` before the policy
/// under test runs.
fn install_collaboration_realm(state: &AppState, realm_id: &arkret_identifiers::RealmId) {
    state.test_projection().lock().set_realm_facet(
        realm_id.as_str(),
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

/// A grant the fixture materialized as a durable `capability_grant` current
/// result.
struct SeededGrant {
    grant_id: String,
}

/// Materialize one active grant from the Realm root controller `issuer` to
/// `subject` over `resource`, exactly as the accepting RealmCommit would.
async fn install_projected_grant(
    state: &AppState,
    realm_id: String,
    issuer: String,
    subject: String,
    resource: String,
    actions: Vec<String>,
) -> SeededGrant {
    install_constrained_grant(
        state,
        realm_id,
        issuer,
        subject,
        resource,
        actions,
        Vec::new(),
    )
    .await
}

/// [`install_projected_grant`] carrying `constraints`.
async fn install_constrained_grant(
    state: &AppState,
    realm_id: String,
    issuer: String,
    subject: String,
    resource: String,
    actions: Vec<String>,
    constraints: Vec<arkret_models_collaboration::governance::grant_constraint::GrantConstraint>,
) -> SeededGrant {
    let realm_id = arkret_identifiers::RealmId::new(realm_id).expect("fixture Realm id");
    let store = state.test_persistence();
    let grants = store.capability_grant_current_states();
    grants
        .seed_test_realm_root(&realm_id, &fixture_actor(&issuer))
        .await
        .expect("fixture Realm root");
    let resource = crate::authz::resource_selector(&realm_id, &resource).expect("fixture resource");
    let grant_id = grants
        .seed_test_grant(&coland_storage::TestCapabilityGrant {
            realm_id,
            subject: fixture_actor(&subject),
            actions,
            resources: vec![resource],
            constraints,
        })
        .await
        .expect("fixture grant");
    SeededGrant {
        grant_id: grant_id.to_string(),
    }
}

fn signed_device_authorize_payload(
    device_signer: &SigningKey,
    signing_key: &SigningKey,
) -> arkret_models_collaboration::events_payloads::device_identity::DeviceAuthorizePayload {
    use arkret_models_collaboration::events_payloads::device_identity::DeviceAuthorizePayload;
    use arkret_models_collaboration::events_payloads::{
        DeviceAuthorizationBindingKind, DeviceOrPrincipalRef, SignatureMaterial,
    };

    let device_public_key = format!(
        "did:key:{}",
        arkret_canonical::ed25519_pubkey_to_did_key_multibase(
            device_signer.verifying_key().as_bytes(),
        )
    );
    let principal_id = crate::test_actor_id_str(ALICE_DID);
    let account_id =
        arkret_wire::AccountId::new(principal_id.clone(), crate::test_event::station_id());
    let mut payload = DeviceAuthorizePayload {
        device_id: arkret_identifiers::DeviceId::new(
            "ak:device:019eefcb-5882-7861-bc30-3033fa32dcf6",
        )
        .unwrap(),
        device_public_key_did: arkret_wire::NonEmptyString::new(device_public_key).unwrap(),
        hpke_key: arkret_wire::NonEmptyString::new(
            "z6LSgy7T8CEsMDMzk1e4EBFVX8CDXWWzvkFZWSXhsC97zjcM",
        )
        .unwrap(),
        algorithms: vec![
            arkret_wire::NonEmptyString::new("ak.hpke_x25519_aead_chacha20poly1305.v1").unwrap(),
            arkret_wire::NonEmptyString::new("ak.mls.v1").unwrap(),
        ],
        device_key_algorithm: arkret_wire::NonEmptyString::new("Ed25519").unwrap(),
        authorized_by: DeviceOrPrincipalRef::Principal(principal_id),
        scopes: None,
        not_before: "2026-06-22T14:45:51Z".parse().unwrap(),
        expires_at: None,
        authorization_binding_kind: DeviceAuthorizationBindingKind::RegistrationAnchor,
        authorized_generation_ref: 1,
        device_signature: SignatureMaterial::NonEmptyString(
            arkret_wire::NonEmptyString::new("pending").unwrap(),
        ),
        recovery_session_id: None,
        pairing_challenge_transcript_digest: None,
        applet_id: None,
        expected_control_revision: None,
        expected_device_revision: None,
    };
    let input = payload
        .device_possession_signature_input(&account_id)
        .expect("device signature input");
    let signature = signing_key.sign(&input);
    payload.device_signature = SignatureMaterial::NonEmptyString(
        arkret_wire::NonEmptyString::new(arkret_canonical::base64url_encode(signature.to_bytes()))
            .unwrap(),
    );
    payload
}

#[test]
fn device_authorize_validates_device_possession_signature() {
    let state = test_state();
    let device_signer = SigningKey::from_bytes(&[7u8; 32]);
    let payload = signed_device_authorize_payload(&device_signer, &device_signer);

    crate::routing::identity::device_signing::validate_device_authorize_binding(
        &state,
        &payload,
        &arkret_wire::AccountId::new(
            crate::test_actor_id_str(ALICE_DID),
            crate::test_event::station_id(),
        ),
    )
    .unwrap();
}

#[test]
fn device_authorize_rejects_signature_from_wrong_device_key() {
    let state = test_state();
    let device_signer = SigningKey::from_bytes(&[7u8; 32]);
    let wrong_signer = SigningKey::from_bytes(&[8u8; 32]);
    let payload = signed_device_authorize_payload(&device_signer, &wrong_signer);

    assert_eq!(
        crate::routing::identity::device_signing::validate_device_authorize_binding(
            &state,
            &payload,
            &arkret_wire::AccountId::new(
                crate::test_actor_id_str(ALICE_DID),
                crate::test_event::station_id(),
            ),
        ),
        Err("device_authorize_device_signature_invalid")
    );
}

/// A grant whose only resource is the one Circle: the selector is the
/// narrowing, so no constraint is needed to keep it off other Circles.
async fn grant_circle_action(
    state: &AppState,
    realm_id: &arkret_identifiers::RealmId,
    circle_id: &str,
    actor: &str,
    action: &str,
) {
    install_projected_grant(
        state,
        realm_id.to_string(),
        "ak:did_core:web:owner.example".to_owned(),
        actor.to_owned(),
        circle_id.to_owned(),
        vec![action.to_owned()],
    )
    .await;
}

fn insert_joined_realm_member(
    state: &AppState,
    realm_id: &arkret_identifiers::RealmId,
    actor_id: &str,
) {
    let now = chrono::Utc::now();
    state.test_projection().lock().members.insert(
        (realm_id.to_string(), fixture_actor(actor_id).to_string()),
        coland_domain::reducer::ColandMembershipState {
            member: fixture_actor(actor_id).to_string(),
            realm_id: realm_id.to_string(),
            state: "join".to_owned(),
            role: "member".to_owned(),
            membership_event_ref: Some(
                "ak:event:AT41F_H8VlBMeU1YjfZKP1IwxWus1cykljb2DVv43LvY".to_owned(),
            ),
            invited_at: None,
            joined_at: now,
            updated_at: now,
            reason: None,
        },
    );
}

async fn grant_moderation_decision(
    state: &AppState,
    realm_id: &arkret_identifiers::RealmId,
    actor: &str,
) {
    install_projected_grant(
        state,
        realm_id.to_string(),
        "ak:did_core:web:owner.example".to_owned(),
        actor.to_owned(),
        realm_id.to_string(),
        vec![arkret_wire::CapabilityActionId::MODERATION_DECISION.to_owned()],
    )
    .await;
}

async fn grant_call_action(
    state: &AppState,
    realm_id: &arkret_identifiers::RealmId,
    actor: &str,
    action: &str,
) {
    install_projected_grant(
        state,
        realm_id.to_string(),
        "ak:did_core:web:owner.example".to_owned(),
        actor.to_owned(),
        realm_id.to_string(),
        vec![action.to_owned()],
    )
    .await;
}

async fn register_agent_selection(
    state: &AppState,
    realm_id: &arkret_identifiers::RealmId,
    agent_id: &str,
    reply: bool,
    acting_on_behalf_allowed: bool,
) {
    let mut record = coland_services::identity::AgentPairingState::new(
        agent_id.to_owned(),
        ALICE_CORE_ID.to_owned(),
        "ak:realm:Abeq9pC3fxOERl1X0ivHa5cJCBy41KfYu5LKvGfPFq5K".to_owned(),
        arkret_wire::DidUrl::new(format!("{AGENT_DID}#managed-controller")).unwrap(),
        AgentLifecycleState::Active,
        chrono::Utc::now(),
    );
    record.display_name = Some("Summary".to_owned());
    record.agent_slug = Some("summary".to_owned());
    state
        .agent_pairings()
        .save_agent(record)
        .await
        .expect("agent record");
    assert!(
        state
            .agent_participations()
            .compare_and_swap_selection(
                json!({
                    "agent_id": agent_id,
                    "scope_kind": "realm",
                    "scope_key": crate::routing::agent_participation::realm_scope_key(realm_id.as_str()),
                    "realm_id": realm_id.as_str(),
                    "scope": { "kind": "realm", "realm_id": realm_id.as_str() },
                    "version": 1,
                    "message_creation_allowed": reply,
                    "reaction_addition_allowed": false,
                    "reaction_removal_allowed": false,
                    "third_party_mention_delivery_allowed": false,
                    "acting_on_behalf_allowed": acting_on_behalf_allowed,
                }),
                0
            )
            .await
            .expect("agent participation selection")
    );
}

fn agent_context(agent_id: &str, authorization_ref: &str) -> serde_json::Value {
    json!({
        "agent_id": agent_id,
        "operator_or_controller": ALICE_CORE_ID,
        "authorization_ref": authorization_ref,
        "execution_purpose": "test_action",
    })
}

fn message_creation_allowed(
    realm_id: arkret_identifiers::RealmId,
    seed: &str,
    agent_id: &str,
    authorization_ref: &str,
) -> Operation {
    op(
        realm_id,
        seed,
        arkret_wire::EventKind::MessageCreate,
        json!({
            "sender": agent_id,
            "content": [{"type": "text", "text": "agent reply"}],
            "agent_context": agent_context(agent_id, authorization_ref),
        }),
    )
}

fn act_on_behalf_message(
    realm_id: arkret_identifiers::RealmId,
    seed: &str,
    agent_id: &str,
    authorization_ref: Option<&str>,
    approval: Option<(&str, &str)>,
) -> Operation {
    let mut payload = json!({
        "sender": "ak:did_core:web:alice.example",
        "executed_by": agent_id,
        "content": [{"type": "text", "text": "approved"}],
    });
    if let Some(authorization_ref) = authorization_ref {
        let object = payload.as_object_mut().expect("payload object");
        object.insert("authorization_ref".to_owned(), json!(authorization_ref));
        object.insert(
            "agent_context".to_owned(),
            agent_context(agent_id, authorization_ref),
        );
    }
    if let Some((request_id, approval_nonce)) = approval {
        let object = payload.as_object_mut().expect("payload object");
        object.insert("request_id".to_owned(), json!(request_id));
        object.insert("approval_nonce".to_owned(), json!(approval_nonce));
    }
    op(
        realm_id,
        seed,
        arkret_wire::EventKind::MessageCreate,
        payload,
    )
}

/// Index a confirmation for `message` that nobody committed. The index alone
/// must never authorize.
fn insert_approved_agent_action(state: &AppState, message: &Operation) {
    insert_resolved_agent_action(
        state,
        message,
        "ak:event:AbuDfbb-uv82LvhWbTydj5wUDvzph0PSFjJTtTJxq7P5",
    );
}

fn insert_resolved_agent_action(state: &AppState, message: &Operation, resolution_event_id: &str) {
    state
        .test_projection()
        .lock()
        .agent_action_confirmations
        .insert(
            message.context.event_id.to_string(),
            arkret_wire::EventId::new(resolution_event_id).expect("confirmation Event id"),
        );
}

#[tokio::test]
async fn act_on_behalf_agent_requires_participation_bit() {
    let state = test_state();
    let realm_id = arkret_identifiers::RealmId::new(
        "ak:realm:AT2g1B8NlsTQnu9kxPR0nPvh-bVNWGGMseceRnfLYwih".to_owned(),
    )
    .unwrap();
    let agent = AGENT_CORE_ID;
    register_agent_selection(&state, &realm_id, agent, true, false).await;
    let grant = install_projected_grant(
        &state,
        realm_id.to_string(),
        "ak:did_core:web:alice.example".to_owned(),
        agent.to_owned(),
        realm_id.to_string(),
        vec![arkret_wire::EventKind::MessageCreate.as_str().to_owned()],
    )
    .await;
    let message = act_on_behalf_message(
        realm_id,
        "000000000701",
        agent,
        Some(grant.grant_id.as_str()),
        None,
    );

    assert_eq!(
        validate_agent_reply_participation(&state, &[message], covering_committed_at())
            .await
            .unwrap_err(),
        "agent_act_on_behalf_not_permitted"
    );
}

#[tokio::test]
async fn act_on_behalf_agent_requires_authorization_ref_covering_action() {
    let state = test_state();
    let realm_id = arkret_identifiers::RealmId::new(
        "ak:realm:AZeoe8skvYdUZma_1pH3dCWvAy7ap4MWYRpM5f16O5yw".to_owned(),
    )
    .unwrap();
    let agent = AGENT_CORE_ID;
    register_agent_selection(&state, &realm_id, agent, true, true).await;
    let grant = install_projected_grant(
        &state,
        realm_id.to_string(),
        "ak:did_core:web:alice.example".to_owned(),
        agent.to_owned(),
        realm_id.to_string(),
        vec![arkret_wire::EventKind::ReactionAdd.as_str().to_owned()],
    )
    .await;
    let message = act_on_behalf_message(
        realm_id,
        "000000000702",
        agent,
        Some(grant.grant_id.as_str()),
        None,
    );

    assert_eq!(
        validate_agent_reply_participation(&state, &[message], covering_committed_at())
            .await
            .unwrap_err(),
        "agent_act_on_behalf_authorization_ref_scope"
    );
}

#[tokio::test]
async fn act_on_behalf_agent_non_message_write_requires_authorization_ref() {
    let state = test_state();
    let realm_id = arkret_identifiers::RealmId::new(
        "ak:realm:AVRRrROGV2ARk6OPXu6lATgiM5XQyZ_JcgwRjMC3Im1B".to_owned(),
    )
    .unwrap();
    let agent = AGENT_CORE_ID;
    register_agent_selection(&state, &realm_id, agent, true, true).await;
    let operation = op(
        realm_id,
        "0000000007a2",
        arkret_wire::EventKind::StrandCreate,
        json!({
            "sender": "ak:did_core:web:alice.example",
            "executed_by": agent,
            "object": {
                "id": "ak:strand:AVdfqhxRnk4959EgJEklIslgnTpVrvncd17v-s916y6P",
                "metadata": {"title": "Work"}
            }
        }),
    );

    assert_eq!(
        validate_agent_reply_participation(&state, &[operation], covering_committed_at())
            .await
            .unwrap_err(),
        "agent_act_on_behalf_authorization_ref_missing"
    );
}

#[tokio::test]
async fn act_on_behalf_agent_strand_write_requires_agent_context() {
    let state = test_state();
    let realm_id = arkret_identifiers::RealmId::new(
        "ak:realm:AUfNT7qSwkDpB8SgZULB6UEnLA6DCqyGx6yfhKn-RnJj".to_owned(),
    )
    .unwrap();
    let agent = AGENT_CORE_ID;
    register_agent_selection(&state, &realm_id, agent, true, true).await;
    let grant = install_projected_grant(
        &state,
        realm_id.to_string(),
        "ak:did_core:web:alice.example".to_owned(),
        agent.to_owned(),
        realm_id.to_string(),
        vec![arkret_wire::EventKind::StrandCreate.as_str().to_owned()],
    )
    .await;
    let operation = op(
        realm_id,
        "0000000007c1",
        arkret_wire::EventKind::StrandCreate,
        json!({
            "sender": "ak:did_core:web:alice.example",
            "executed_by": agent,
            "authorization_ref": grant.grant_id,
            "object": {
                "id": "ak:strand:AS9MRCiS8US6IL2jyf4nBx20bazdnIA8RcwS3yCwHc-h",
                "metadata": {"title": "Work"}
            }
        }),
    );

    assert_eq!(
        validate_agent_reply_participation(&state, &[operation], covering_committed_at())
            .await
            .unwrap_err(),
        "agent_context_missing"
    );
}

#[tokio::test]
async fn agent_member_target_uses_sender_for_agent_write_detection() {
    let state = test_state();
    let realm_id = arkret_identifiers::RealmId::new(
        "ak:realm:AeMbHcOGMt3VgaQzdMnK0nUaMYOGvt35z9V139HW8NEU".to_owned(),
    )
    .unwrap();
    let agent = AGENT_CORE_ID;
    register_agent_selection(&state, &realm_id, agent, true, true).await;
    let operation = op(
        realm_id,
        "0000000007b1",
        arkret_wire::EventKind::MemberState,
        json!({
            "sender": "ak:did_core:web:alice.example",
            "member_id": fixture_actor(agent),
            "membership": "join",
            "realm_id": "ak:realm:AeMbHcOGMt3VgaQzdMnK0nUaMYOGvt35z9V139HW8NEU"
        }),
    );

    validate_agent_reply_participation(&state, &[operation], covering_committed_at())
        .await
        .expect("membership target must not be treated as the executing agent");
}

#[tokio::test]
async fn act_on_behalf_agent_relation_write_rejects_context_authorization_mismatch() {
    let state = test_state();
    let realm_id = arkret_identifiers::RealmId::new(
        "ak:realm:ASX9zvSqYNXNYx7VQIbISCPKKTvGMcKOCnY1RxTDpEgU".to_owned(),
    )
    .unwrap();
    let agent = AGENT_CORE_ID;
    register_agent_selection(&state, &realm_id, agent, true, true).await;
    let envelope_grant = install_projected_grant(
        &state,
        realm_id.to_string(),
        "ak:did_core:web:alice.example".to_owned(),
        agent.to_owned(),
        realm_id.to_string(),
        vec![arkret_wire::EventKind::RelationCreate.as_str().to_owned()],
    )
    .await;
    let context_grant = install_projected_grant(
        &state,
        realm_id.to_string(),
        "ak:did_core:web:alice.example".to_owned(),
        agent.to_owned(),
        realm_id.to_string(),
        vec![arkret_wire::EventKind::RelationCreate.as_str().to_owned()],
    )
    .await;
    let operation = op(
        realm_id,
        "0000000007c2",
        arkret_wire::EventKind::RelationCreate,
        json!({
            "sender": "ak:did_core:web:alice.example",
            "executed_by": agent,
            "authorization_ref": envelope_grant.grant_id,
            "agent_context": agent_context(agent, context_grant.grant_id.as_str()),
            "relation_id": "ak:relation:AT9MgV4wqtfFSX-ooCQnZocjO8g6OURDSEk1JujmyrNf",
            "relation_kind": "references",
            "from_ref": "ak:strand:AT9MgV4wqtfFSX-ooCQnZocjO8g6OURDSEk1JujmyrNf",
            "to_ref": "ak:strand:AXDTq-UrA4iZU_0Xw6aOv4uWM8yGmnIpTstlVPn9zSLd"
        }),
    );

    assert_eq!(
        validate_agent_reply_participation(&state, &[operation], covering_committed_at())
            .await
            .unwrap_err(),
        "agent_context_authorization_ref_mismatch"
    );
}

#[tokio::test]
async fn signed_agent_provenance_unknown_action_fails_closed_before_context() {
    let state = test_state();
    let realm_id = arkret_identifiers::RealmId::new(
        "ak:realm:AXzeZ-Ew-5O_W5FC1b8TyxqwA3twPkBPtlQ6j3xWqBYN".to_owned(),
    )
    .unwrap();
    let operation = op(
        realm_id,
        "0000000007c3",
        arkret_wire::EventKind::RelationCreate,
        json!({
            "sender": "ak:did_core:web:alice.example",
            "provenance": {
                "kind": "agent"
            },
            "relation_id": "ak:relation:AXDTq-UrA4iZU_0Xw6aOv4uWM8yGmnIpTstlVPn9zSLd",
            "relation_kind": "references",
            "from_ref": "ak:strand:AaV0Wjp3LhZKUfcpa_CaAadjRsbPDxliKCkc9QbmZsyu",
            "to_ref": "ak:strand:AVlYG1Uzsm35_Y5x72KDPQXIcI3zCL4H2HF_bh3DgMMy"
        }),
    );

    assert_eq!(
        validate_agent_reply_participation(&state, &[operation], covering_committed_at())
            .await
            .unwrap_err(),
        "agent_participation_action_unknown"
    );
}

#[tokio::test]
async fn act_on_behalf_private_approval_cannot_replace_exact_consumption() {
    let state = test_state();
    let realm_id = arkret_identifiers::RealmId::new(
        "ak:realm:AXlr1KB1QbTZsNhXulSUBNz9IMWJGKWMVdYyTD28xF4T".to_owned(),
    )
    .unwrap();
    let agent = AGENT_CORE_ID;
    register_agent_selection(&state, &realm_id, agent, true, true).await;
    let grant = install_projected_grant(
        &state,
        realm_id.to_string(),
        "ak:did_core:web:alice.example".to_owned(),
        agent.to_owned(),
        realm_id.to_string(),
        vec![arkret_wire::EventKind::ViewCreate.as_str().to_owned()],
    )
    .await;
    let grant_id = grant.grant_id.clone();
    let operation = op(
        realm_id,
        "0000000007c4",
        arkret_wire::EventKind::ViewCreate,
        json!({
            "sender": "ak:did_core:web:alice.example",
            "executed_by": agent,
            "authorization_ref": grant_id.as_str(),
            "agent_context": agent_context(agent, grant_id.as_str()),
            "view_id": "ak:view:AaV0Wjp3LhZKUfcpa_CaAadjRsbPDxliKCkc9QbmZsyu",
            "request_id": "request-7c4",
            "approval_nonce": "nonce-7c4"
        }),
    );
    insert_approved_agent_action(&state, &operation);

    assert_eq!(
        validate_agent_act_on_behalf_approval(&state, &operation, agent, covering_committed_at())
            .await
            .unwrap_err(),
        "dependency_missing"
    );
    let mut substituted = operation;
    substituted.context.event_id =
        arkret_wire::EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [99; 32]);
    assert_eq!(
        validate_agent_act_on_behalf_approval(&state, &substituted, agent, covering_committed_at())
            .await
            .unwrap_err(),
        "dependency_missing"
    );
}

#[tokio::test]
async fn act_on_behalf_agent_unknown_kind_rejects_authorization_action() {
    let state = test_state();
    let realm_id = arkret_identifiers::RealmId::new(
        "ak:realm:AUKn_6c6DSK-7snjal8Dk5AtaL1dGSwfNAhvsig6jsbY".to_owned(),
    )
    .unwrap();
    let agent = AGENT_CORE_ID;
    register_agent_selection(&state, &realm_id, agent, true, true).await;
    let grant = install_projected_grant(
        &state,
        realm_id.to_string(),
        "ak:did_core:web:alice.example".to_owned(),
        agent.to_owned(),
        realm_id.to_string(),
        vec!["*".to_owned()],
    )
    .await;
    let grant_id = grant.grant_id.clone();
    let operation = op(
        realm_id,
        "0000000007c5",
        "ak.agent.unknown.write",
        json!({
            "sender": "ak:did_core:web:alice.example",
            "executed_by": agent,
            "authorization_ref": grant_id.as_str(),
            "agent_context": agent_context(agent, grant_id.as_str()),
        }),
    );

    assert_eq!(
        validate_agent_reply_participation(&state, &[operation], covering_committed_at())
            .await
            .unwrap_err(),
        "agent_act_on_behalf_authorization_action_unsupported"
    );
}

#[tokio::test]
async fn reply_agent_unknown_kind_fails_closed_at_participation_registry() {
    let state = test_state();
    let realm_id = arkret_identifiers::RealmId::new(
        "ak:realm:AeAr0dq27Y12394LKAb3Xv0CnKBcTVG6R0EQTJCQbIe6".to_owned(),
    )
    .unwrap();
    let agent = AGENT_CORE_ID;
    register_agent_selection(&state, &realm_id, agent, true, true).await;
    let grant = install_projected_grant(
        &state,
        realm_id.to_string(),
        "ak:did_core:web:alice.example".to_owned(),
        agent.to_owned(),
        realm_id.to_string(),
        vec!["*".to_owned()],
    )
    .await;
    let grant_id = grant.grant_id.clone();
    let operation = op(
        realm_id,
        "0000000007c6",
        "ak.agent.unknown.reply",
        json!({
            "sender": agent,
            "agent_context": agent_context(agent, grant_id.as_str()),
        }),
    );

    assert_eq!(
        validate_agent_reply_participation(&state, &[operation], covering_committed_at())
            .await
            .unwrap_err(),
        "agent_participation_action_unknown"
    );
}

#[tokio::test]
async fn reply_agent_lifecycle_state_blocks_writes_even_with_participation() {
    let state = test_state();
    let realm_id = arkret_identifiers::RealmId::new(
        "ak:realm:Ad_TMwzMUtHlpgBlzEjvQtjThJ2GNykuHvEjDxchCErV".to_owned(),
    )
    .unwrap();
    let agent = AGENT_CORE_ID;
    register_agent_selection(&state, &realm_id, agent, true, false).await;
    let grant = install_projected_grant(
        &state,
        realm_id.to_string(),
        "ak:did_core:web:alice.example".to_owned(),
        agent.to_owned(),
        realm_id.to_string(),
        vec![arkret_wire::EventKind::MessageCreate.as_str().to_owned()],
    )
    .await;
    let mut record = state
        .agent_pairings()
        .agent(agent)
        .await
        .expect("agent lookup")
        .expect("agent record");
    record.state = AgentLifecycleState::Paused;
    state
        .agent_pairings()
        .save_agent(record)
        .await
        .expect("agent record update");
    let operation =
        message_creation_allowed(realm_id, "0000000007c7", agent, grant.grant_id.as_str());

    assert_eq!(
        validate_agent_reply_participation(&state, &[operation], covering_committed_at())
            .await
            .unwrap_err(),
        "agent_paused"
    );
}

#[tokio::test]
async fn reply_agent_projected_deactivation_blocks_writes_even_with_active_record() {
    let state = test_state();
    let realm_id = arkret_identifiers::RealmId::new(
        "ak:realm:AVvje1NQM-IzvlES2WgCeHRlHlw9b_oeEp3ZmYauIeIj".to_owned(),
    )
    .unwrap();
    let agent = AGENT_CORE_ID;
    register_agent_selection(&state, &realm_id, agent, true, false).await;
    let grant = install_projected_grant(
        &state,
        realm_id.to_string(),
        "ak:did_core:web:alice.example".to_owned(),
        agent.to_owned(),
        realm_id.to_string(),
        vec![arkret_wire::EventKind::MessageCreate.as_str().to_owned()],
    )
    .await;
    let operation =
        message_creation_allowed(realm_id, "0000000007c8", agent, grant.grant_id.as_str());
    state.test_projection().lock().agent_lifecycles.insert(
        operation.context.sender.canonical_key().unwrap(),
        arkret_models_collaboration::agent_operations::AgentLifecycleState::Deactivated,
    );

    assert_eq!(
        validate_agent_reply_participation(&state, &[operation], covering_committed_at())
            .await
            .unwrap_err(),
        "agent_deactivated"
    );
}

/// One issuer-signed accountability grant: `issuer`'s founding device signs
/// the Event, and `proof_seed` signs the inner compact detached JWS over the
/// registered `ak.accountability-grant-v1` binding transcript.
#[allow(clippy::too_many_arguments)]
fn signed_accountability_grant(
    issuer: &coland_test_support::pcr_genesis::PcrGenesisFixture,
    issuer_id: &arkret_wire::DidCoreId,
    subject_id: &arkret_wire::DidCoreId,
    status: &str,
    not_before: &str,
    expires_at: Option<&str>,
    proof_seed: [u8; 32],
) -> arkret_wire::Event {
    let method = issuer.history.device_verification_method.clone();
    let mut value = json!({
        "schema": "ak.schema.accountability_grant.v1",
        "issuer_id": issuer_id,
        "subject_id": subject_id,
        "accountability_scope": "agent_operator",
        "not_before": not_before,
        "grant_status": status,
        "proof": {
            "kind": "detached_jws",
            "verification_method": method,
            "payload_digest": format!("sha256:{}", "0".repeat(64)),
            "created_at": not_before,
            "jws": ""
        }
    });
    if let Some(expires_at) = expires_at {
        value["expires_at"] = json!(expires_at);
    }
    let mut grant: arkret_models_collaboration::governance::accountability::AccountabilityGrantPayload =
        serde_json::from_value(value).unwrap();
    grant.proof.payload_digest = grant.payload_digest().unwrap();
    grant.proof.jws = arkret_signatures::sign_ed25519_detached_jws(
        &SigningKey::from_bytes(&proof_seed),
        &grant.canonical_proof_binding_bytes().unwrap(),
    )
    .unwrap();
    let account = &issuer.history.account;
    coland_test_support::device_authorization_history::sign_event(
        arkret_wire::test_support::raw_event(
            arkret_wire::EventKind::IdentityAccountabilityGrant.as_str(),
            arkret_wire::ScopeRef::Realm {
                realm_id: issuer.history.events[0].realm_id.clone(),
            },
            account.principal_id.clone(),
            account.station_id.clone(),
            serde_json::to_value(&grant).unwrap(),
        )
        .unwrap(),
        method,
        issuer.history.founding_device_signing_seed,
    )
}

/// Admit `event` through the issuer PCR accountability unit: a real
/// Station-signed RealmCommit at the PCR head, written with the
/// `identity_accountability` row in one transaction.
async fn commit_accountability_grant(
    state: &AppState,
    event: &arkret_wire::Event,
) -> coland_storage::PersistenceResult<coland_storage::AccountabilityGrantAdmissionOutcome> {
    let committed_at = chrono::Utc::now();
    let method = arkret_wire::DidUrl::new(
        crate::routing::federation::federation_service_signature_key_id(
            state.service_did().as_str(),
        ),
    )
    .unwrap();
    let transaction = state
        .authority_commits()
        .prepare_self_event_transaction(
            event,
            &state.service_core_id(),
            method,
            state.notary_signing_key().as_ref(),
            committed_at,
        )
        .await
        .expect("PCR head transaction");
    state
        .persistence()
        .admit_accountability_grant(coland_storage::AccountabilityGrantAdmissionWrite {
            commit: transaction,
            queued_at: committed_at,
        })
        .await
}

/// A PG-backed state with the issuer's PCR genesis accepted.
async fn accountability_state() -> (
    AppState,
    coland_test_support::pcr_genesis::PcrGenesisFixture,
    arkret_identifiers::RealmId,
) {
    let state = test_state();
    let issuer = coland_test_support::pcr_genesis::PcrGenesisFixture::new(state.service_did());
    issuer
        .admit_into(state.test_persistence().as_ref())
        .await
        .expect("accepted issuer PCR genesis");
    let realm_id = arkret_identifiers::RealmId::new(
        "ak:realm:ARHX7LGKk2svV3upZ10pEmGoLdgEaEPI06-04trUQQdu".to_owned(),
    )
    .unwrap();
    install_collaboration_realm(&state, &realm_id);
    (state, issuer, realm_id)
}

fn accountable_profile_create(
    realm_id: arkret_identifiers::RealmId,
    seed: &str,
    subject: &str,
    issuer: &arkret_wire::DidCoreId,
) -> Operation {
    op(
        realm_id,
        seed,
        "ak.profile.create",
        json!({
            "sender": subject,
            "object": {
                "principal_id": subject,
                "actor_kind": "agent",
                "display_name": "Agent",
                "accountable_principal_ids": [issuer]
            }
        }),
    )
}

#[tokio::test]
async fn profile_accountable_principal_requires_active_grant() {
    let (state, issuer, realm_id) = accountability_state().await;
    let issuer_id = issuer.history.account.principal_id.clone();
    let profile = accountable_profile_create(realm_id, "0000000007a3", AGENT_CORE_ID, &issuer_id);

    assert_eq!(
        validate_operation_policy(&state, &[profile])
            .await
            .unwrap_err(),
        arkret_wire::ReasonCode::ACCOUNTABILITY_GRANT_MISSING,
        "no committed identity_accountability record exists for the pair"
    );
}

#[tokio::test]
async fn profile_accountable_principal_rejects_batch_grant_signed_by_other_actor() {
    let (state, mallory, realm_id) = accountability_state().await;
    let claimed_issuer = arkret_wire::DidCoreId::new(ALICE_CORE_ID).unwrap();
    let agent = arkret_wire::DidCoreId::new(AGENT_CORE_ID).unwrap();
    // Mallory signs a grant naming Alice as the issuer. The accountability
    // unit refuses it -- the issuer is not the Event actor -- so no record
    // for (Alice, Agent) is ever committed.
    let fake = signed_accountability_grant(
        &mallory,
        &claimed_issuer,
        &agent,
        "active",
        "2026-01-01T00:00:00.000Z",
        Some("2099-01-01T00:00:00.000Z"),
        mallory.history.founding_device_signing_seed,
    );
    let refused = commit_accountability_grant(&state, &fake)
        .await
        .expect_err("a grant whose issuer is not its actor is refused");
    assert_eq!(
        refused.conflict_code(),
        Some(coland_storage::ConflictCode::SignatureInvalid)
    );
    let profile =
        accountable_profile_create(realm_id, "0000000007a4", AGENT_CORE_ID, &claimed_issuer);

    assert_eq!(
        validate_operation_policy(&state, &[profile])
            .await
            .unwrap_err(),
        arkret_wire::ReasonCode::ACCOUNTABILITY_GRANT_MISSING
    );
}

#[tokio::test]
async fn profile_accountable_principal_accepts_committed_active_grant() {
    let (state, issuer, realm_id) = accountability_state().await;
    let issuer_id = issuer.history.account.principal_id.clone();
    let agent = arkret_wire::DidCoreId::new(AGENT_CORE_ID).unwrap();
    let grant = signed_accountability_grant(
        &issuer,
        &issuer_id,
        &agent,
        "active",
        "2026-01-01T00:00:00.000Z",
        Some("2099-01-01T00:00:00.000Z"),
        issuer.history.founding_device_signing_seed,
    );
    assert!(matches!(
        commit_accountability_grant(&state, &grant).await.unwrap(),
        coland_storage::AccountabilityGrantAdmissionOutcome::Committed(_)
    ));
    let profile = accountable_profile_create(realm_id, "0000000007a9", AGENT_CORE_ID, &issuer_id);

    validate_operation_policy(&state, &[profile])
        .await
        .expect("a committed active grant satisfies the profile");
}

#[tokio::test]
async fn profile_accountable_principal_committed_revoke_wins() {
    let (state, issuer, realm_id) = accountability_state().await;
    let issuer_id = issuer.history.account.principal_id.clone();
    let agent = arkret_wire::DidCoreId::new(AGENT_CORE_ID).unwrap();
    for status in ["active", "revoked"] {
        let grant = signed_accountability_grant(
            &issuer,
            &issuer_id,
            &agent,
            status,
            "2026-01-01T00:00:00.000Z",
            Some("2099-01-01T00:00:00.000Z"),
            issuer.history.founding_device_signing_seed,
        );
        commit_accountability_grant(&state, &grant)
            .await
            .expect("the issuer's grant and revoke commit in order");
    }
    let profile = op(
        realm_id,
        "0000000007ac",
        "ak.profile.update",
        json!({
            "sender": AGENT_CORE_ID,
            "target_ref": "ak:actor_profile:AQsHmGu_9sPOyJ4aG8VlWQBp8wGGhdC-BjfAaXqrIbk-",
            "patch": {"accountable_principal_ids": [issuer_id]}
        }),
    );

    assert_eq!(
        validate_operation_policy(&state, &[profile])
            .await
            .unwrap_err(),
        arkret_wire::ReasonCode::ACCOUNTABILITY_GRANT_MISSING,
        "the revoke replaced the same exact-set record"
    );
}

#[tokio::test]
async fn profile_accountability_is_judged_at_the_commit_time_coordinate() {
    let (state, issuer, realm_id) = accountability_state().await;
    let issuer_id = issuer.history.account.principal_id.clone();
    let agent = arkret_wire::DidCoreId::new(AGENT_CORE_ID).unwrap();
    let grant = signed_accountability_grant(
        &issuer,
        &issuer_id,
        &agent,
        "active",
        "2026-01-01T00:00:00.000Z",
        Some("2026-06-01T00:00:00.000Z"),
        issuer.history.founding_device_signing_seed,
    );
    commit_accountability_grant(&state, &grant)
        .await
        .expect("an issuer may commit a bounded grant");
    let mut profile =
        accountable_profile_create(realm_id, "0000000007ae", AGENT_CORE_ID, &issuer_id);
    // The Event's own signed time is inside the grant, but the Station decides
    // at its Commit time coordinate (event-auth-state-resolution: the
    // governance Station reads current state when it assigns the Commit).
    profile.created_at = chrono::DateTime::parse_from_rfc3339("2026-05-01T00:00:00.000Z")
        .unwrap()
        .with_timezone(&chrono::Utc);

    assert_eq!(
        validate_operation_policy(&state, &[profile])
            .await
            .unwrap_err(),
        arkret_wire::ReasonCode::ACCOUNTABILITY_GRANT_MISSING,
        "an expired grant does not verify a profile accepted after expires_at"
    );
}

#[tokio::test]
async fn circle_member_manage_rejects_without_grant() {
    let state = test_state();
    let realm_id = arkret_identifiers::RealmId::new(
        "ak:realm:ASzMBU92ndTUgCFayN1yKHiZ3dJ7Irh18ENIqLIELrIQ".to_owned(),
    )
    .unwrap();
    install_collaboration_realm(&state, &realm_id);
    state
        .test_persistence()
        .capability_grant_current_states()
        .seed_test_realm_root(&realm_id, &fixture_actor("ak:did_core:web:owner.example"))
        .await
        .unwrap();
    insert_joined_realm_member(&state, &realm_id, BOB_CORE_ID);
    let member_add = op(
        realm_id,
        "000000000881",
        arkret_wire::EventKind::CircleMemberState,
        json!({
            "sender": "ak:did_core:web:alice.example",
            "circle_id": "ak:circle:AQzkNesVRZE45KCCmROpUPRV8VQzC-oUQQK8ytMOq1yO",
            "member_id": fixture_actor(BOB_CORE_ID),
            "membership": "join"
        }),
    );

    assert_eq!(
        validate_operation_policy(&state, &[member_add])
            .await
            .unwrap_err(),
        "circle_member_manage_capability_required"
    );
}

#[tokio::test]
async fn circle_member_manage_allows_explicit_circle_scoped_grant() {
    let state = test_state();
    let realm_id = arkret_identifiers::RealmId::new(
        "ak:realm:AW2Ebs3FRn6VzpiCswpoViFTHh-iDZrF_UzakuV14ZSm".to_owned(),
    )
    .unwrap();
    install_collaboration_realm(&state, &realm_id);
    let circle_id = "ak:circle:AbPMdhKXl6Pe1lcCeCC_k_V5tvHDt1LAFRB6g6WrpDLJ";
    insert_joined_realm_member(&state, &realm_id, BOB_CORE_ID);
    grant_circle_action(
        &state,
        &realm_id,
        circle_id,
        ALICE_CORE_ID,
        "ak.circle.member.manage",
    )
    .await;
    let member_add = op(
        realm_id,
        "000000000882",
        arkret_wire::EventKind::CircleMemberState,
        json!({
            "sender": "ak:did_core:web:alice.example",
            "circle_id": circle_id,
            "member_id": fixture_actor(BOB_CORE_ID),
            "membership": "join"
        }),
    );

    validate_operation_policy(&state, &[member_add])
        .await
        .expect("circle-scoped grant authorizes member management");
}

#[tokio::test]
async fn circle_lifecycle_requires_circle_manage_grant() {
    let state = test_state();
    let realm_id = arkret_identifiers::RealmId::new(
        "ak:realm:ASS8zG4z3bNJuUr3YrKuhVUKUOTpX3PhfV-JrJ56QMzs".to_owned(),
    )
    .unwrap();
    install_collaboration_realm(&state, &realm_id);
    state
        .test_persistence()
        .capability_grant_current_states()
        .seed_test_realm_root(&realm_id, &fixture_actor("ak:did_core:web:owner.example"))
        .await
        .unwrap();
    let circle_id = "ak:circle:AT2LoQ65P6bU2ZDxq9XbubTSMDrqzlK8EFJNmM_pxt62";
    let tombstone = op(
        realm_id.clone(),
        "000000000883",
        arkret_wire::EventKind::CircleTombstone,
        json!({
            "sender": "ak:did_core:web:alice.example",
            "circle_id": circle_id
        }),
    );

    assert_eq!(
        validate_operation_policy(&state, std::slice::from_ref(&tombstone))
            .await
            .unwrap_err(),
        "circle_manage_capability_required"
    );

    grant_circle_action(
        &state,
        &realm_id,
        circle_id,
        ALICE_CORE_ID,
        "ak.circle.manage",
    )
    .await;
    validate_operation_policy(&state, &[tombstone])
        .await
        .expect("circle-scoped manage grant authorizes lifecycle");
}

/// `capabilities.md` §5.4: Circle management over the whole Realm is
/// narrowed by `allowed_circle_ids`; an unnarrowed Realm-wide grant is not an
/// authorization shape the evaluator accepts.
#[tokio::test]
async fn realm_wide_circle_management_is_narrowed_by_allowed_circle_ids() {
    use arkret_models_collaboration::governance::grant_constraint::{
        GrantConstraint, GrantConstraintEffect, GrantConstraintKind,
    };
    let state = test_state();
    let realm_id = arkret_identifiers::RealmId::new(
        "ak:realm:AVm2x0Z3uN9m7cDkq5YHn0yVjg3HX2Hc8yHwVnQYc2dM".to_owned(),
    )
    .unwrap();
    install_collaboration_realm(&state, &realm_id);
    let listed = "ak:circle:AdYzZqwOV7QGAA-4lkcJ7t3e37ykrejD-IweH6iPy9vz";
    let other = "ak:circle:AScD0xd0vWSGWhC2n9BZHco7N_jYnNgmEIifpAo_uxUJ";
    let mut narrowing = GrantConstraint::new(
        GrantConstraintKind::ScopeLimitation,
        GrantConstraintEffect::Allow,
    );
    narrowing.allowed_circle_ids = vec![listed.parse().unwrap()];
    install_constrained_grant(
        &state,
        realm_id.to_string(),
        "ak:did_core:web:owner.example".to_owned(),
        ALICE_CORE_ID.to_owned(),
        realm_id.to_string(),
        vec!["ak.circle.manage".to_owned()],
        vec![narrowing],
    )
    .await;
    install_projected_grant(
        &state,
        realm_id.to_string(),
        "ak:did_core:web:owner.example".to_owned(),
        BOB_CORE_ID.to_owned(),
        realm_id.to_string(),
        vec!["ak.circle.manage".to_owned()],
    )
    .await;
    let tombstone = |sender: &str, sequence: &str, circle_id: &str| {
        op(
            realm_id.clone(),
            sequence,
            arkret_wire::EventKind::CircleTombstone,
            json!({"sender": sender, "circle_id": circle_id}),
        )
    };
    validate_operation_policy(
        &state,
        &[tombstone(
            "ak:did_core:web:alice.example",
            "000000000891",
            listed,
        )],
    )
    .await
    .expect("the listed Circle is inside the grant");
    assert_eq!(
        validate_operation_policy(
            &state,
            &[tombstone(
                "ak:did_core:web:alice.example",
                "000000000892",
                other
            )],
        )
        .await
        .unwrap_err(),
        "circle_manage_capability_required"
    );
    assert_eq!(
        validate_operation_policy(&state, &[tombstone(BOB_CORE_ID, "000000000893", listed)],)
            .await
            .unwrap_err(),
        "circle_manage_capability_required"
    );
}

#[tokio::test]
async fn act_on_behalf_agent_selection_and_grant_do_not_replace_accepted_current_or_approval() {
    let state = test_state();
    let realm_id = arkret_identifiers::RealmId::new(
        "ak:realm:AY3EjcWF5Gxh89mCnOZzpF_bpwVEmMWIXv9IkSHmVmMD".to_owned(),
    )
    .unwrap();
    let agent = AGENT_CORE_ID;
    register_agent_selection(&state, &realm_id, agent, true, true).await;
    let grant = install_projected_grant(
        &state,
        realm_id.to_string(),
        "ak:did_core:web:alice.example".to_owned(),
        agent.to_owned(),
        realm_id.to_string(),
        vec![arkret_wire::EventKind::MessageCreate.as_str().to_owned()],
    )
    .await;
    let message = act_on_behalf_message(
        realm_id,
        "000000000703",
        agent,
        Some(grant.grant_id.as_str()),
        Some(("request-703", "nonce-703")),
    );
    insert_approved_agent_action(&state, &message);

    assert_eq!(
        validate_agent_reply_participation(&state, &[message.clone()], covering_committed_at())
            .await
            .unwrap_err(),
        "agent_act_on_behalf_not_permitted"
    );
    assert_eq!(
        validate_agent_act_on_behalf_approval(&state, &message, agent, covering_committed_at())
            .await
            .unwrap_err(),
        "dependency_missing"
    );
}

/// Sign one controller `ak.agent.action_approve` for `realm_id` whose
/// governing Station is this test Station.
async fn agent_action_approval_event(
    state: &AppState,
    realm_id: &arkret_identifiers::RealmId,
    controller: &str,
    controller_did: &str,
    payload: serde_json::Value,
    created_at: chrono::DateTime<chrono::Utc>,
) -> arkret_wire::Event {
    state
        .authority_commits()
        .install_genesis_authority(&coland_storage::CurrentRealmAuthority {
            realm_id: realm_id.clone(),
            generation: 0,
            service_id: crate::test_event::station_id(),
            authority_ref: arkret_wire::RealmCommitAuthorityRef::GenesisOrChangeEvent(
                realm_id.event_id(),
            ),
            last_handoff_ref: None,
        })
        .await
        .expect("genesis authority installs");
    let mut event = crate::test_event::raw_event_at(
        arkret_wire::EventKind::AgentActionApprove.as_str(),
        arkret_wire::ScopeRef::Realm {
            realm_id: realm_id.clone(),
        },
        arkret_wire::DidCoreId::new(controller).unwrap(),
        0,
        arkret_identifiers::Hlc::new("019041000000-0000-aabbccdd").unwrap(),
        payload,
        created_at,
    )
    .unwrap();
    crate::test_event::attach_structural_only_producer_proof(
        &mut event,
        arkret_wire::DidUrl::new(format!("{controller_did}#key-1")).unwrap(),
    );
    event
}

/// Admit one signed confirmation through the governing Station's authority
/// path with the given covering `committed_at`.
async fn admit_agent_action_approval(
    state: &AppState,
    event: &arkret_wire::Event,
    committed_at: chrono::DateTime<chrono::Utc>,
) -> coland_services::ServiceResult<coland_services::authority_commit::AuthorityEventAdmissionOutcome>
{
    state
        .authority_commits()
        .admit_event_for_test(
            event,
            &crate::test_event::station_id(),
            state.service_verification_method("notary-key").unwrap(),
            state.notary_signing_key().as_ref(),
            committed_at,
        )
        .await
}

/// Commit one controller `ak.agent.action_approve` inside its window, exactly
/// as admission leaves it.
async fn commit_agent_action_approval(
    state: &AppState,
    realm_id: &arkret_identifiers::RealmId,
    controller: &str,
    controller_did: &str,
    payload: serde_json::Value,
) -> arkret_wire::EventId {
    let event = agent_action_approval_event(
        state,
        realm_id,
        controller,
        controller_did,
        payload,
        timestamp("2026-05-30T00:00:00.000Z"),
    )
    .await;
    let outcome = admit_agent_action_approval(state, &event, timestamp("2026-05-31T00:00:00.000Z"))
        .await
        .expect("controller confirmation commits");
    assert!(matches!(
        outcome,
        coland_services::authority_commit::AuthorityEventAdmissionOutcome::Committed(_)
    ));
    event.event_id
}

const CONFIRMED_APPROVAL_NONCE: &str = "Q29uZmlybWVkQXBwcm92YWxOb25jZQ";
const CONFIRMED_APPROVAL_EXPIRES_AT: &str = "2027-01-01T00:00:00.000Z";

fn timestamp(value: &str) -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::parse_from_rfc3339(value)
        .unwrap()
        .with_timezone(&chrono::Utc)
}

/// The signed `committed_at` of the RealmCommit covering the Operation under
/// test; well inside every fixture approval window.
fn covering_committed_at() -> chrono::DateTime<chrono::Utc> {
    timestamp("2026-06-01T00:00:00.000Z")
}

fn agent_action_approve_payload(
    realm_id: &arkret_identifiers::RealmId,
    request_id: &str,
    agent_id: &str,
    approved_event_id: &arkret_wire::EventId,
) -> serde_json::Value {
    json!({
        "approval_id": "ak:agent_approval:01904100-0000-7000-8000-0000000007aa",
        "request_id": request_id,
        "agent_id": agent_id,
        "proposed_action": arkret_wire::EventKind::MessageCreate.as_str(),
        "target": { "kind": "realm", "realm_id": realm_id.as_str() },
        "approved_event_id": approved_event_id.as_str(),
        "approval_nonce": CONFIRMED_APPROVAL_NONCE,
        "expires_at": CONFIRMED_APPROVAL_EXPIRES_AT
    })
}

async fn act_on_behalf_with_committed_confirmation(
    realm_seed: u8,
    seed: &str,
    request_id: &str,
    confirm: impl FnOnce(&Operation, &mut serde_json::Value) -> (&'static str, &'static str),
) -> Result<(), &'static str> {
    act_on_behalf_covered_at(
        covering_committed_at(),
        realm_seed,
        seed,
        request_id,
        confirm,
    )
    .await
}

async fn act_on_behalf_covered_at(
    covering_committed_at: chrono::DateTime<chrono::Utc>,
    realm_seed: u8,
    seed: &str,
    request_id: &str,
    confirm: impl FnOnce(&Operation, &mut serde_json::Value) -> (&'static str, &'static str),
) -> Result<(), &'static str> {
    let state = test_state();
    let realm_id = arkret_identifiers::RealmId::from_event_id(&arkret_wire::EventId::from_digest(
        arkret_canonical::DigestSuite::Sha256,
        [realm_seed; 32],
    ));
    let agent = AGENT_CORE_ID;
    register_agent_selection(&state, &realm_id, agent, true, true).await;
    let grant = install_projected_grant(
        &state,
        realm_id.to_string(),
        "ak:did_core:web:alice.example".to_owned(),
        agent.to_owned(),
        realm_id.to_string(),
        vec![arkret_wire::EventKind::MessageCreate.as_str().to_owned()],
    )
    .await;
    let message = act_on_behalf_message(
        realm_id.clone(),
        seed,
        agent,
        Some(grant.grant_id.as_str()),
        Some((request_id, CONFIRMED_APPROVAL_NONCE)),
    );
    let mut payload =
        agent_action_approve_payload(&realm_id, request_id, agent, &message.context.event_id);
    let (controller, controller_did) = confirm(&message, &mut payload);
    let confirmation =
        commit_agent_action_approval(&state, &realm_id, controller, controller_did, payload).await;
    insert_resolved_agent_action(&state, &message, confirmation.as_str());
    validate_agent_act_on_behalf_approval(&state, &message, agent, covering_committed_at).await
}

/// `ak.vector.agent.action_approve_expiry.v1`: the approved Event is judged
/// only by its own covering `committed_at`, inclusive with zero tolerance.
#[tokio::test]
async fn act_on_behalf_approval_window_is_judged_by_the_covering_commit() {
    act_on_behalf_covered_at(
        timestamp(CONFIRMED_APPROVAL_EXPIRES_AT),
        0x7a,
        "00000000070a",
        "request-70a",
        |_, _| (ALICE_CORE_ID, ALICE_DID),
    )
    .await
    .expect("an Event covered exactly at expires_at is inside the window");
    assert_eq!(
        act_on_behalf_covered_at(
            timestamp(CONFIRMED_APPROVAL_EXPIRES_AT) + chrono::Duration::milliseconds(1),
            0x7b,
            "00000000070b",
            "request-70b",
            |_, _| (ALICE_CORE_ID, ALICE_DID),
        )
        .await
        .unwrap_err(),
        arkret_wire::ReasonCode::APPROVAL_REQUIRED
    );
}

/// A confirmation whose own covering `committed_at` is after `expires_at` is
/// refused with `failed_precondition` and writes nothing; the boundary is
/// inclusive, envelope `created_at` never participates, and an exact retry
/// after the window returns the original Commit.
#[tokio::test]
async fn late_confirmation_is_refused_with_zero_writes() {
    let state = test_state();
    let realm_id = arkret_identifiers::RealmId::from_event_id(&arkret_wire::EventId::from_digest(
        arkret_canonical::DigestSuite::Sha256,
        [0x7c; 32],
    ));
    let approved_event_id =
        arkret_wire::EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [0x9c; 32]);
    let expires_at = timestamp(CONFIRMED_APPROVAL_EXPIRES_AT);
    let event = agent_action_approval_event(
        &state,
        &realm_id,
        ALICE_CORE_ID,
        ALICE_DID,
        agent_action_approve_payload(&realm_id, "request-70c", AGENT_CORE_ID, &approved_event_id),
        expires_at + chrono::Duration::minutes(5),
    )
    .await;

    let error = admit_agent_action_approval(
        &state,
        &event,
        expires_at + chrono::Duration::milliseconds(1),
    )
    .await
    .expect_err("a confirmation covered after expires_at is refused");
    assert_eq!(
        error.conflict_code(),
        Some(coland_storage::ConflictCode::FailedPrecondition),
        "{error}"
    );
    assert!(
        state
            .authority_commits()
            .committed_event(&event.event_id)
            .await
            .unwrap()
            .is_none(),
        "a refused confirmation leaves no Event or Commit"
    );

    let coland_services::authority_commit::AuthorityEventAdmissionOutcome::Committed(commit) =
        admit_agent_action_approval(&state, &event, expires_at)
            .await
            .expect("a confirmation covered exactly at expires_at commits")
    else {
        panic!("expected a new Commit");
    };
    assert_eq!(commit.committed_at, expires_at);

    assert_eq!(
        admit_agent_action_approval(&state, &event, expires_at + chrono::Duration::hours(1))
            .await
            .expect("exact retry is not re-judged"),
        coland_services::authority_commit::AuthorityEventAdmissionOutcome::Duplicate(commit)
    );
}

#[tokio::test]
async fn act_on_behalf_committed_controller_confirmation_authorizes_exact_event() {
    act_on_behalf_with_committed_confirmation(0x75, "000000000705", "request-705", |_, _| {
        (ALICE_CORE_ID, ALICE_DID)
    })
    .await
    .expect("the exact committed controller confirmation authorizes this Event");
}

#[tokio::test]
async fn act_on_behalf_committed_confirmation_of_another_event_is_missing() {
    // The private request claims this Event, but the committed confirmation
    // consumed the nonce for a different one.
    assert_eq!(
        act_on_behalf_with_committed_confirmation(
            0x76,
            "000000000706",
            "request-706",
            |_, payload| {
                payload["approved_event_id"] = json!(
                    arkret_wire::EventId::from_digest(
                        arkret_canonical::DigestSuite::Sha256,
                        [0x96; 32]
                    )
                    .as_str()
                );
                (ALICE_CORE_ID, ALICE_DID)
            },
        )
        .await
        .unwrap_err(),
        "dependency_missing"
    );
}

#[tokio::test]
async fn act_on_behalf_confirmation_committed_by_another_account_is_missing() {
    // A committed approval only counts when the Event sender, as controller,
    // issued it; another Account's confirmation cannot stand in.
    assert_eq!(
        act_on_behalf_with_committed_confirmation(0x77, "000000000707", "request-707", |_, _| (
            "ak:did_core:webvh:z6mkbob",
            "did:webvh:z6mkbob:bob.example"
        ),)
        .await
        .unwrap_err(),
        "dependency_missing"
    );
}

#[tokio::test]
async fn act_on_behalf_agent_requires_fresh_approval_request() {
    let state = test_state();
    let realm_id = arkret_identifiers::RealmId::new(
        "ak:realm:AXmGXr7blOycfvMmgehmJJCEpeYG165UnBvugl6pO_40".to_owned(),
    )
    .unwrap();
    let agent = AGENT_CORE_ID;
    register_agent_selection(&state, &realm_id, agent, true, true).await;
    let grant = install_projected_grant(
        &state,
        realm_id.to_string(),
        "ak:did_core:web:alice.example".to_owned(),
        agent.to_owned(),
        realm_id.to_string(),
        vec![arkret_wire::EventKind::MessageCreate.as_str().to_owned()],
    )
    .await;
    let message = act_on_behalf_message(
        realm_id,
        "000000000704",
        agent,
        Some(grant.grant_id.as_str()),
        Some(("request-704", "nonce-704")),
    );

    assert_eq!(
        validate_agent_act_on_behalf_approval(&state, &message, agent, covering_committed_at())
            .await
            .unwrap_err(),
        "dependency_missing"
    );
}

#[tokio::test]
async fn circle_scoped_relation_update_and_delete_require_circle_membership() {
    let state = test_state();
    let realm_id = arkret_identifiers::RealmId::new(
        "ak:realm:AaGPy5t1BAnukci5lpGNiOlo7TufaF-ociC1LVnQpv5B".to_owned(),
    )
    .unwrap();
    install_collaboration_realm(&state, &realm_id);
    let circle_id = "ak:circle:AfF5Vi42N83lUBU2d9UbQFWzHxX2vlXkKpR-Ctx0Oh6D";
    let relation_id = "ak:relation:AfF5Vi42N83lUBU2d9UbQFWzHxX2vlXkKpR-Ctx0Oh6D";
    let now = chrono::Utc::now();
    {
        let mut projection = state.test_projection().lock();
        let mut members = std::collections::BTreeSet::new();
        members.insert(fixture_actor(ALICE_CORE_ID).to_string());
        projection.circles.insert(
            circle_id.to_owned(),
            coland_domain::reducer::CircleProjection {
                circle_id: circle_id.to_owned(),
                realm_id: realm_id.to_string(),
                profile_ref: None,
                title: "Private".to_owned(),
                summary: None,
                display: serde_json::json!({"short_name":"Private","color_token":"slate","symbol":{"glyph":"ring"}}),
                directory_visibility: "private".to_owned(),
                join_rule: "invite".to_owned(),
                history_access: "since_join".to_owned(),
                mls_group_ref: None,
                state: coland_domain::reducer::CircleLifecycleState::Active,
                state_changed_at: None,
                created_by: ALICE_CORE_ID.to_owned(),
                created_at: now,
                updated_by: None,
                updated_at: None,
                members,
            },
        );
        projection.relations.insert(
            relation_id.to_owned(),
            coland_domain::reducer::ColandRelationState {
                relation_id: relation_id.to_owned(),
                realm_id: realm_id.to_string(),
                relation_kind: "confidential_discussion_of".to_owned(),
                scope_circle_id: Some(circle_id.to_owned()),
                from_ref: Some("ak:strand:AYmJuuenMIJ2dTgMqUL3AoeJJOHo5Iap70ImQUPzbJhY".into()),
                to_ref: Some("ak:strand:AcTTTDFcIiz-Tmjh-sPdibSEwAhireChqYZJzVM0K1MY".into()),
                rank: None,
                fields: Default::default(),
                state: "active".to_owned(),
                source_event_id: Some(
                    "ak:event:AfF5Vi42N83lUBU2d9UbQFWzHxX2vlXkKpR-Ctx0Oh6D".to_owned(),
                ),
                source_event_digest: Some(
                    "sha256:1111111111111111111111111111111111111111111111111111111111111111"
                        .to_owned(),
                ),
                created_at: now,
                updated_at: now,
            },
        );
    }

    let bob_update = op(
        realm_id.clone(),
        "000000000802",
        arkret_wire::EventKind::RelationUpdate,
        json!({
            "relation_id": relation_id,
            "sender": "ak:did_core:web:bob.example",
            "patch": {"fields.label": "nope"}
        }),
    );
    assert_eq!(
        validate_operation_policy(&state, &[bob_update])
            .await
            .unwrap_err(),
        "circle_scope_membership_required"
    );

    let alice_update = op(
        realm_id.clone(),
        "000000000803",
        arkret_wire::EventKind::RelationUpdate,
        json!({
            "relation_id": relation_id,
            "sender": "ak:did_core:web:alice.example",
            "patch": {"fields.label": "ok"}
        }),
    );
    validate_operation_policy(&state, &[alice_update])
        .await
        .expect("circle member can update scoped relation");

    let bob_delete = op(
        realm_id,
        "000000000804",
        arkret_wire::EventKind::RelationTombstone,
        json!({
            "relation_id": relation_id,
            "sender": "ak:did_core:web:bob.example"
        }),
    );
    assert_eq!(
        validate_operation_policy(&state, &[bob_delete])
            .await
            .unwrap_err(),
        "circle_scope_membership_required"
    );
}

#[tokio::test]
async fn moderation_decision_checks_issuer_capability_not_sender_spoof() {
    let state = test_state();
    let realm_id = arkret_identifiers::RealmId::new(
        "ak:realm:ARkNLd10PLFU6nWXwpfON7eQhZGezakXw3pvJ5cRGc0Q".to_owned(),
    )
    .unwrap();
    install_collaboration_realm(&state, &realm_id);
    grant_moderation_decision(&state, &realm_id, "ak:did_core:web:moderator.example").await;
    let decision = op(
        realm_id,
        "000000000901",
        arkret_wire::EventKind::ModerationDecision,
        json!({
            "sender": "ak:did_core:web:moderator.example",
            "issuer_id": "did:web:impostor.example",
            "target_ref": "ak:message:AXvyk2cSPhfYUHVSaDoVqdjSO3t5IXRAqpG-6hQjjUAx",
            "decision": "quarantine",
            "request_canonical_digest": "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
        }),
    );

    assert_eq!(
        validate_operation_policy(&state, &[decision])
            .await
            .unwrap_err(),
        "moderation_actor_mismatch"
    );
}

#[tokio::test]
async fn moderation_decision_allows_authorized_issuer() {
    const MODERATOR: &str = "ak:did_core:web:moderator.example";
    let state = test_state();
    let realm_id = arkret_identifiers::RealmId::new(
        "ak:realm:AUYLjBoI0xYRjG5SKmFPOh3Agj-mEAcV6cmiVPn4KB64".to_owned(),
    )
    .unwrap();
    install_collaboration_realm(&state, &realm_id);
    grant_moderation_decision(&state, &realm_id, MODERATOR).await;
    let decision = op(
        realm_id,
        "000000000902",
        arkret_wire::EventKind::ModerationDecision,
        json!({
            "actor_id": MODERATOR,
            "sender": MODERATOR,
            "issuer_id": MODERATOR,
            "target_ref": "ak:message:AR9_0Dn3PqKpHpxvh0C4oIGwx_MZWw6y7PjVc300c93v",
            "decision": "quarantine",
            "request_canonical_digest": "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
        }),
    );

    validate_operation_policy(&state, &[decision])
        .await
        .expect("issuer with matching moderation capability should pass");
}

#[tokio::test]
async fn moderation_decision_rejects_missing_issuer_even_with_sender_grant() {
    let state = test_state();
    let realm_id = arkret_identifiers::RealmId::new(
        "ak:realm:AQsAANkzbRAod6oC5lFzs1OxsLEt5mVJ35YGKc4cf_Vn".to_owned(),
    )
    .unwrap();
    install_collaboration_realm(&state, &realm_id);
    grant_moderation_decision(&state, &realm_id, "ak:did_core:web:moderator.example").await;
    let decision = op(
        realm_id,
        "000000000903",
        arkret_wire::EventKind::ModerationDecision,
        json!({
            "sender": "ak:did_core:web:moderator.example",
            "target_ref": "ak:message:AW8-c0F9KfRq5YWdUYT1ilfjIDzjU3jCt-GT8KmVIeCA",
            "decision": "quarantine",
            "request_canonical_digest": "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        }),
    );

    assert_eq!(
        validate_operation_policy(&state, &[decision])
            .await
            .unwrap_err(),
        "moderation_decision_issuer_missing"
    );
}

#[tokio::test]
async fn call_recording_start_defaults_to_record_capability() {
    let state = test_state();
    let realm_id = arkret_identifiers::RealmId::new(
        "ak:realm:AfBbfcm-ayz4ms4IjZtpa_UeR-zkx9xDxFy3_SgyqMkh".to_owned(),
    )
    .unwrap();
    install_collaboration_realm(&state, &realm_id);
    grant_call_action(
        &state,
        &realm_id,
        "ak:did_core:web:recorder.example",
        arkret_wire::CapabilityActionId::CALL_RECORD,
    )
    .await;
    let start = op(
        realm_id,
        "000000000904",
        arkret_wire::EventKind::CallRecordingStart,
        json!({
            "sender": "ak:did_core:web:recorder.example",
            "call_id": "ak:call:AVy0_LisG9qoB26NeUHZ9StFVOl5nqsG2uOx425ecJtu",
            "recording_id": "recording-904",
            "recording_agent_id": "ak:did_core:web:recorder.example",
            "capture_kind": "recording",
            "mode": "audio_video",
            "visible_notice": true,
            "capture_metadata": {
                "retention": {"consent_confirmed": true}
            }
        }),
    );

    validate_operation_policy(&state, &[start])
        .await
        .expect("ak.call.record should authorize recording capture");
}

#[tokio::test]
async fn call_recording_start_transcript_requires_transcribe_capability() {
    let state = test_state();
    let realm_id = arkret_identifiers::RealmId::new(
        "ak:realm:AbvPRiXVavzVHJKCDG8HK7s2PlyJBga3olAriX06ZGPZ".to_owned(),
    )
    .unwrap();
    install_collaboration_realm(&state, &realm_id);
    grant_call_action(
        &state,
        &realm_id,
        "ak:did_core:web:recorder.example",
        arkret_wire::CapabilityActionId::CALL_RECORD,
    )
    .await;
    let start = op(
        realm_id,
        "000000000905",
        arkret_wire::EventKind::CallRecordingStart,
        json!({
            "sender": "ak:did_core:web:recorder.example",
            "call_id": "ak:call:AbxEzmCDUuUSMHiCmmGdUzGwHpMTRY2ziLp69rH4QcVj",
            "recording_id": "transcript-905",
            "recording_agent_id": "ak:did_core:web:recorder.example",
            "capture_kind": "transcript",
            "mode": "audio",
            "visible_notice": true,
            "capture_metadata": {
                "retention": {"consent_confirmed": true}
            }
        }),
    );

    assert_eq!(
        validate_operation_policy(&state, &[start])
            .await
            .unwrap_err(),
        arkret_wire::ReasonCode::TRANSCRIPTION_DENIED
    );
    assert_eq!(
        operation_policy_reason_code(arkret_wire::ReasonCode::TRANSCRIPTION_DENIED),
        (
            salvo::http::StatusCode::FORBIDDEN,
            arkret_wire::ReasonCode::TRANSCRIPTION_DENIED
        )
    );
}

#[tokio::test]
async fn call_recording_start_transcript_allows_transcribe_capability() {
    let state = test_state();
    let realm_id = arkret_identifiers::RealmId::new(
        "ak:realm:AYMs5egM4i4NiSry19jn62Jo_3_cXrETY3yjnsupOeTI".to_owned(),
    )
    .unwrap();
    install_collaboration_realm(&state, &realm_id);
    grant_call_action(
        &state,
        &realm_id,
        "ak:did_core:web:recorder.example",
        arkret_wire::CapabilityActionId::CALL_TRANSCRIBE,
    )
    .await;
    let start = op(
        realm_id,
        "000000000906",
        arkret_wire::EventKind::CallRecordingStart,
        json!({
            "sender": "ak:did_core:web:recorder.example",
            "call_id": "ak:call:ARUNG7uEIx_HZYhSqahMLGksSz4H88SpeRoxS9E5pnWO",
            "recording_id": "transcript-906",
            "recording_agent_id": "ak:did_core:web:recorder.example",
            "capture_kind": "transcript",
            "mode": "audio",
            "visible_notice": true,
            "capture_metadata": {
                "retention": {"consent_confirmed": true}
            }
        }),
    );

    validate_operation_policy(&state, &[start])
        .await
        .expect("ak.call.transcribe should authorize transcript capture");
}

#[tokio::test]
async fn call_recording_start_rejects_missing_mode_and_noncanonical_recording_id() {
    let state = test_state();
    let realm_id = arkret_identifiers::RealmId::new(
        "ak:realm:AdoFjBodfOdOvxfSAV_E0X6ztrtRXo7FYSVsU9YRV4pE".to_owned(),
    )
    .unwrap();
    install_collaboration_realm(&state, &realm_id);
    grant_call_action(
        &state,
        &realm_id,
        "ak:did_core:web:recorder.example",
        arkret_wire::CapabilityActionId::CALL_RECORD,
    )
    .await;
    let payload = json!({
        "sender": "ak:did_core:web:recorder.example",
        "call_id": "ak:call:ATruBVw3F7e6GxSCTOAQ52Yh0RbzPwJS39bQb-Jz3JJt",
        "recording_id": "recording-907",
        "recording_agent_id": "ak:did_core:web:recorder.example",
        "capture_kind": "recording",
        "visible_notice": true,
        "capture_metadata": {
            "recording_start_event_id": "ak:event:ATruBVw3F7e6GxSCTOAQ52Yh0RbzPwJS39bQb-Jz3JJt",
            "retention": {"consent_confirmed": true}
        }
    });
    let missing_mode = op(
        realm_id.clone(),
        "000000000907",
        arkret_wire::EventKind::CallRecordingStart,
        payload.clone(),
    );
    assert_eq!(
        validate_operation_policy(&state, &[missing_mode])
            .await
            .unwrap_err(),
        arkret_wire::ErrorCode::SCHEMA_VIOLATION
    );

    let mut invalid_recording_id_payload = payload;
    invalid_recording_id_payload["recording_id"] = json!("recording id");
    invalid_recording_id_payload["mode"] = json!("audio_video");
    let invalid_recording_id = op(
        realm_id,
        "000000000908",
        arkret_wire::EventKind::CallRecordingStart,
        invalid_recording_id_payload,
    );
    assert_eq!(
        validate_operation_policy(&state, &[invalid_recording_id])
            .await
            .unwrap_err(),
        arkret_wire::ErrorCode::SCHEMA_VIOLATION
    );
}
