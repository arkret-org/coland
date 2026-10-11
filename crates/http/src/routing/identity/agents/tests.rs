use super::*;

const AGENT_CORE: &str = "ak:did_core:web:agent.example";
const AGENT_DID: &str = "did:web:agent.example";
const CONTROLLER_CORE: &str = "ak:did_core:web:controller.example";
const SERVICE_CORE: &str = "ak:did_core:webvh:z2dmjYwAPJzv5CZsnAzt8auVZRn1GfuxhpK2t3Q3K3rj4B1x";

fn service_pairing_test_state() -> AppState {
    AppState::new(
        crate::config::AppConfig::test_default(),
        coland_storage_postgres::Db { pool: None },
    )
}

async fn save_service_pairing_controller(state: &AppState, account_id: arkret_wire::AccountId) {
    state
        .identities()
        .save_account(coland_services::identity::AccountProfileState {
            pk: coland_storage::AccountPk(0),
            principal_id: account_id.principal_id.clone(),
            localpart: format!("controller-{}", account_id.station_id),
            account_id,
            display_name: None,
            bio: None,
            avatar_blob_ref: None,
            created_at: chrono::Utc::now(),
        })
        .await
        .unwrap();
}

#[tokio::test]
async fn service_pairing_session_binds_the_exact_stored_controller_account() {
    let state = service_pairing_test_state();
    let controller_account = arkret_wire::AccountId::new(
        DidCoreId::new(CONTROLLER_CORE).unwrap(),
        state.service_core_id(),
    );
    let other_account = arkret_wire::AccountId::new(
        controller_account.principal_id.clone(),
        DidCoreId::new("ak:did_core:web:other-station.example").unwrap(),
    );
    save_service_pairing_controller(&state, other_account).await;
    save_service_pairing_controller(&state, controller_account.clone()).await;
    let device_id = "ak:device:01904100-0000-7000-8000-000000000002";
    let session = controller_service_session(&controller_account, device_id, &state)
        .await
        .expect("delegated pairing binds its controller Account");
    let account = state
        .identities()
        .account(&controller_account)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(session.account_pk, Some(account.pk));
    assert_eq!(
        session.human_device_id().map(String::as_str),
        Some(device_id)
    );
    assert_eq!(
        crate::routing::identity::session_actor::validated_session_actor(&state, &session)
            .await
            .expect("delegated context passes the ordinary exact Account gate"),
        arkret_wire::ActorId::account(controller_account),
    );
}

#[tokio::test]
async fn service_pairing_session_rejects_a_missing_controller_account() {
    let state = service_pairing_test_state();
    let controller_account = arkret_wire::AccountId::new(
        DidCoreId::new(CONTROLLER_CORE).unwrap(),
        state.service_core_id(),
    );
    assert!(
        controller_service_session(&controller_account, "device", &state)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn service_pairing_session_rejects_the_same_controller_at_another_station() {
    let state = service_pairing_test_state();
    let controller_account = arkret_wire::AccountId::new(
        DidCoreId::new(CONTROLLER_CORE).unwrap(),
        DidCoreId::new("ak:did_core:web:other-station.example").unwrap(),
    );
    save_service_pairing_controller(&state, controller_account.clone()).await;
    assert!(
        controller_service_session(&controller_account, "device", &state)
            .await
            .is_err()
    );
}

#[test]
fn deployment_bearer_does_not_select_agent_service_auth() {
    let mut request = Request::new();
    request.headers_mut().insert(
        "authorization",
        "Bearer shared-internal-channel-secret".parse().unwrap(),
    );
    assert!(!agent_service_signature_present(&request));

    request
        .headers_mut()
        .insert("signature-input", "sig1=()".parse().unwrap());
    assert!(agent_service_signature_present(&request));
}

#[test]
fn account_authority_agent_service_claims_are_exactly_bound() {
    let validate = |source_service_id: &str,
                    destination_service_id: &str,
                    source_trust_domain: &str,
                    destination_trust_domain: &str,
                    operation: &str,
                    key_id: &str| {
        validate_agent_service_claims(
            "ak:did_core:web:station.example",
            "did:web:station.example",
            "ak:trust_domain:authority.example",
            "ak:trust_domain:station.example",
            GET_AGENT_SERVICE_OPERATION,
            source_service_id,
            destination_service_id,
            source_trust_domain,
            destination_trust_domain,
            operation,
            key_id,
        )
    };
    assert!(
        validate(
            "ak:did_core:web:station.example",
            "ak:did_core:web:station.example",
            "ak:trust_domain:authority.example",
            "ak:trust_domain:station.example",
            GET_AGENT_SERVICE_OPERATION,
            "did:web:station.example#account-authority",
        )
        .is_ok()
    );
    for rejected in [
        validate(
            "ak:did_core:web:other.example",
            "ak:did_core:web:station.example",
            "ak:trust_domain:authority.example",
            "ak:trust_domain:station.example",
            GET_AGENT_SERVICE_OPERATION,
            "did:web:station.example#account-authority",
        ),
        validate(
            "ak:did_core:web:station.example",
            "ak:did_core:web:other.example",
            "ak:trust_domain:authority.example",
            "ak:trust_domain:station.example",
            GET_AGENT_SERVICE_OPERATION,
            "did:web:station.example#account-authority",
        ),
        validate(
            "ak:did_core:web:station.example",
            "ak:did_core:web:station.example",
            "ak:trust_domain:other.example",
            "ak:trust_domain:station.example",
            GET_AGENT_SERVICE_OPERATION,
            "did:web:station.example#account-authority",
        ),
        validate(
            "ak:did_core:web:station.example",
            "ak:did_core:web:station.example",
            "ak:trust_domain:authority.example",
            "ak:trust_domain:other.example",
            GET_AGENT_SERVICE_OPERATION,
            "did:web:station.example#account-authority",
        ),
        validate(
            "ak:did_core:web:station.example",
            "ak:did_core:web:station.example",
            "ak:trust_domain:authority.example",
            "ak:trust_domain:station.example",
            PAIR_AGENT_KEY_SERVICE_OPERATION,
            "did:web:station.example#account-authority",
        ),
        validate(
            "ak:did_core:web:station.example",
            "ak:did_core:web:station.example",
            "ak:trust_domain:authority.example",
            "ak:trust_domain:station.example",
            GET_AGENT_SERVICE_OPERATION,
            "did:web:station.example#service-key",
        ),
    ] {
        assert!(rejected.is_err());
    }
}

fn web_did(core_id: &str) -> String {
    core_id
        .strip_prefix("ak:did_core:web:")
        .map(|authority| format!("did:web:{authority}"))
        .expect("fixture uses a did:web Core identifier")
}

fn test_session(actor: &str) -> SessionRecord {
    SessionRecord {
        account_pk: None,
        token_hash: format!("test-session:{actor}"),
        actor: actor.to_owned(),
        endpoint: coland_services::identity::SessionEndpointState::HumanDevice {
            device_id: "test-device".to_owned(),
        },
        audience: "did:web:coland.test".to_owned(),
        session_public_key: None,
        session_grant: None,
        expires_at: now() + chrono::Duration::minutes(5),
        created_at: now(),
        revoked_at: None,
    }
}

fn agent_record(agent_id: &str, controller_principal_id: &str) -> AgentPrincipalRecord {
    let created_at = chrono::DateTime::parse_from_rfc3339("2026-06-11T00:00:00.000Z")
        .expect("fixture timestamp")
        .with_timezone(&chrono::Utc);
    let controller_did = web_did(controller_principal_id);
    let mut record = AgentPrincipalRecord::new(
        agent_id.to_owned(),
        controller_principal_id.to_owned(),
        "ak:realm:AZbOMvW-csKhom4LhjgFr2cuYB-cQ9oR21-cRX94cL9M".to_owned(),
        arkret_wire::DidUrl::new(format!("{controller_did}#managed-controller")).unwrap(),
        AgentLifecycleState::Active,
        created_at,
    );
    record.display_name = Some("Test Agent".to_owned());
    record.provision_event_refs = Some(json!({ "did_binding_accepted": true }));
    record
}

fn pending_pairing_record(
    agent_id: &str,
    controller_principal_id: &str,
    requested_scope: Value,
    pairing_code: &str,
    pairing_expires_at: &str,
) -> AgentPrincipalRecord {
    let mut record = agent_record(agent_id, controller_principal_id);
    // Lifecycle intent is active from provisioning; the open bootstrap
    // handle drives runtime_state to pending_runtime_key (key-management.md
    // §3.6.1).
    record.state = AgentLifecycleState::Active;
    record.requested_scope = Some(requested_scope);
    record.pairing_request_id = Some(
        arkret_wire::OpaqueLocalId::new(
            "agent_pairing_request:01999999-0000-7000-8000-00000000feed",
        )
        .unwrap(),
    );
    record.approval_request_id = Some(
        arkret_wire::OpaqueLocalId::new(
            "agent_approval_request:01999999-0000-7000-8000-00000000beef",
        )
        .unwrap(),
    );
    record.pairing_code = Some(pairing_code.to_owned());
    record.pairing_expires_at = Some(
        chrono::DateTime::parse_from_rfc3339(pairing_expires_at)
            .expect("fixture pairing expiry")
            .with_timezone(&chrono::Utc),
    );
    record
}

fn requested_agent_scope() -> Value {
    json!({
        "actions": [
            "ak.self.committed_event.stream.subscribe.v1",
            "ak.self.committed_event.read.scan.v1",
            "ak.self.events.command.submit.v1",
            "ak.event.read",
            "ak.message.create"
        ],
        "resources": [
            {
                "kind": "realm",
                "realm_id": "ak:realm:AWRn2H80ZSW4qBxlHzdkMQbOwl5Ts8OnQRef8M3BJ93F"
            },
            { "kind": "service", "service_id": SERVICE_CORE }
        ]
    })
}

fn initial_submission(
    event: arkret_wire::Event,
    _actor_id: arkret_identifiers::DidCoreId,
) -> arkret_wire::EventAdmissionSubmission {
    arkret_wire::EventAdmissionSubmission::new(event)
}
fn key_authorize_envelope(
    record: &mut AgentPrincipalRecord,
    controller: &str,
    agent_id: &str,
    verification_method: &str,
    _public_key_digest: &str,
    service_id: &str,
    scope: Value,
) -> Value {
    let runtime_request =
        runtime_approval_request_body(&web_did(agent_id), verification_method, service_id);
    record.runtime_key_binding_digest = Some(
        runtime_request
            .proof_of_possession
            .runtime_key_binding_digest
            .as_str()
            .to_owned(),
    );
    record.runtime_public_key_digest = Some(
        arkret_signatures::agent::agent_runtime_public_key_digest(&runtime_request.public_key)
            .expect("runtime public key digest")
            .as_str()
            .to_owned(),
    );
    record.runtime_attestation_digest = Some(
        arkret_signatures::agent::agent_runtime_attestation_digest(None)
            .expect("runtime attestation digest")
            .as_str()
            .to_owned(),
    );
    record.runtime_proof_verified_at = Some(runtime_request.proof_of_possession.created_at);
    record.runtime_key_request = Some(runtime_request);
    let request_canonical_digest = pairing_request_binding_digest(
        record,
        controller,
        agent_id,
        verification_method,
        service_id,
    )
    .expect("pairing binding digest");
    json!({
        "event_id": "ak:event:AaWlxNyGs0FzlOCJpyhjSRcmOcoYvk0qQ4X91NlGuKSZ",
        "kind": "ak.agent.key.authorize",
        "actor_id": arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            arkret_wire::DidCoreId::new(agent_id).unwrap(),
            arkret_wire::DidCoreId::new(service_id).unwrap(),
        )),
        "executed_by": arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            arkret_wire::DidCoreId::new(controller).unwrap(),
            arkret_wire::DidCoreId::new(service_id).unwrap(),
        )),
        "authorization_ref": record.controller_authorization_ref.as_str(),
        "realm_id": record.principal_control_realm_id.as_str(),
        "payload": {
            "agent_id": agent_id,
            "key_id": "ak:agent_key:01999999000070008000000000000001",
            "verification_method": verification_method,
            "public_key": record.runtime_key_request.as_ref().unwrap().public_key,
            "accountable_principal_id": controller,
            "agent_key_scope": scope,
            "audience": [service_id],
            "issued_at": "2026-07-06T00:00:00.000Z",
            "expires_at": "2999-01-01T00:00:00.000Z",
            "approval_evidence": {
                "kind": "pairing_request",
                "request_canonical_digest": request_canonical_digest,
                "pairing_request_id": record.pairing_request_id.as_deref(),
                "approved_by": controller,
            },
        },
    })
}

fn runtime_approval_request_body(
    agent: &str,
    verification_method: &str,
    service_id: &str,
) -> AgentRuntimeApprovalRequestBody {
    use base64::Engine as _;
    use ed25519_dalek::{Signer as _, SigningKey};

    let signing_key = SigningKey::from_bytes(&[42u8; 32]);
    let encoded_public_key = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(signing_key.verifying_key().as_bytes());
    let public_key = PublicKey {
        kty: arkret_wire::NonEmptyString::new("OKP").unwrap(),
        kid: arkret_wire::NonEmptyString::new(verification_method).unwrap(),
        algorithm: arkret_wire::NonEmptyString::new("Ed25519").unwrap(),
        key: arkret_wire::Base64UrlString::new(encoded_public_key).unwrap(),
        key_digest: None,
    };
    let agent_did = Did::new(agent.to_owned()).expect("agent DID");
    let agent_id = arkret_wire::project_did_to_core_id(&agent_did).unwrap();
    let pairing_request_id = arkret_wire::OpaqueLocalId::new(
        "agent_pairing_request:01999999-0000-7000-8000-00000000feed",
    )
    .unwrap();
    let verification_method = arkret_wire::DidUrl::new(verification_method).unwrap();
    let runtime_key_binding_digest =
        arkret_models_collaboration::agent_scope::agent_runtime_key_binding_digest(
            &agent_id,
            &pairing_request_id,
            &verification_method,
            &public_key,
            None,
        )
        .expect("runtime key binding digest");
    let created_at = chrono::Utc::now();
    let expires_at = created_at + chrono::Duration::minutes(5);
    let mut proof_of_possession =
        arkret_models_collaboration::agent_scope::AgentRuntimeKeyPossessionProof {
            kind: arkret_models_collaboration::agent_scope::AgentRuntimeKeyPossessionProofKind::AgentRuntimeKeyPossession,
            verification_method: verification_method.clone(),
            signature_algorithm: arkret_models_collaboration::agent_scope::AgentRuntimeKeyAlgorithm::Ed25519,
            challenge: pairing_request_id.clone(),
            audience_id: arkret_wire::DidCoreId::new(service_id).unwrap(),
            created_at,
            expires_at,
            runtime_key_binding_digest,
            transcript_digest: arkret_wire::Hash::new(format!("sha256:{}", "0".repeat(64))).unwrap(),
            signature: arkret_wire::Base64UrlString::new("AA").unwrap(),
        };
    let transcript = proof_of_possession
        .canonical_transcript_bytes("01234567")
        .unwrap();
    proof_of_possession.transcript_digest =
        arkret_wire::Hash::new(arkret_canonical::sha256_digest(&transcript)).unwrap();
    proof_of_possession.signature = arkret_wire::Base64UrlString::new(
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(signing_key.sign(&transcript).to_bytes()),
    )
    .unwrap();
    AgentRuntimeApprovalRequestBody {
        pairing_code: arkret_wire::NonEmptyString::new("01234567").unwrap(),
        pairing_request_id,
        agent_id,
        verification_method,
        public_key,
        proof_of_possession,
        runtime_attestation: None,
    }
}

fn key_pair_request_body(
    agent: &str,
    verification_method: &str,
    service_id: &str,
) -> AgentKeyPairRequestBody {
    let request = runtime_approval_request_body(agent, verification_method, service_id);
    let agent_id = request.agent_id.clone();
    let agent_did = Did::new(agent).unwrap();
    let public_key = request.public_key.clone();
    let pairing_request_id = request.pairing_request_id.clone();
    let verification_method = request.verification_method.clone();
    let controller_principal_id =
        DidCoreId::new("ak:did_core:web:controller.example".to_owned()).unwrap();
    let requested_scope: AgentKeyScope = serde_json::from_value(requested_agent_scope()).unwrap();
    let requested_scope_disclosure = serde_json::from_value(json!({
        "schema": "ak.schema.agent_requested_scope_disclosure.v1",
        "request_id": "ak:request:01999999-0000-7000-8000-000000000099",
        "agent_id": agent_id.as_str(),
        "controller_principal_id": controller_principal_id.as_str(),
        "requested_scope": requested_scope,
        "verifier_id": service_id,
        "audience": "ak.gate.account.command.pair_agent_key.v1",
        "challenge": "pairing-challenge-0001",
        "issued_at": "2026-07-06T00:00:00.000Z",
        "expires_at": "2026-07-06T00:05:00.000Z",
        "proofs": [{
            "kind": "detached_jws",
            "verification_method": "did:web:controller.example#key-1",
            "payload_digest": format!("sha256:{}", "0".repeat(64)),
            "created_at": "2026-07-06T00:00:00.000Z",
            "jws": "eyJhbGciOiJFZDI1NTE5In0..c2ln"
        }]
    }))
    .unwrap();
    let authorize_event = crate::test_event::raw_event(
        "ak.agent.key.authorize",
        arkret_wire::ScopeRef::Realm {
            realm_id: arkret_identifiers::RealmId::new(
                "ak:realm:AZbOMvW-csKhom4LhjgFr2cuYB-cQ9oR21-cRX94cL9M",
            )
            .unwrap(),
        },
        crate::test_actor_id(&agent_did),
        1,
        arkret_identifiers::Hlc::new("01970e589d21-0004-a13f9c2e").unwrap(),
        json!({"agent_id":agent_id,"key_id":"ak:agent_key:01999999000070008000000000000001","verification_method":verification_method,
            "public_key":public_key,"accountable_principal_id":controller_principal_id,
            "agent_key_scope":requested_agent_scope(),"audience":[service_id],"issued_at":"2026-07-06T00:00:00.000Z",
            "approval_evidence":{"kind":"pairing_request","pairing_request_id":pairing_request_id,"approved_by":controller_principal_id,"request_canonical_digest":format!("sha256:{}","0".repeat(64))}}),
    )
    .unwrap();
    AgentKeyPairRequestBody {
        pairing_request_id,
        approval_request_id: arkret_wire::OpaqueLocalId::new("agent_runtime_approval:01999999")
            .unwrap(),
        requested_scope_disclosure,
        authorize_event: initial_submission(authorize_event, agent_id),
    }
}

#[test]
fn agent_id_is_core_did_not_agent_typed_id() {
    validate_agent_id(AGENT_CORE).expect("Core DID-as-id must be accepted");
    assert!(validate_agent_id("ak:agent_principal:01999999-0000-7000-8000-00000000a001").is_err());
}

/// `key-management.md` §7.4.1 — the DID projects onto the Core
/// actor id through its method adapter; a core id concatenated with a
/// fragment is not a DID URL and never matches.
#[test]
fn verification_method_principal_projects_did_to_core_id() {
    assert_eq!(
        verification_method_principal("did:web:agent.example?versionId=1#key-1")
            .as_ref()
            .map(arkret_identifiers::DidCoreId::as_str),
        Some(AGENT_CORE)
    );
    assert_eq!(
        verification_method_principal(&format!("{AGENT_CORE}#key-1")),
        None
    );
}

#[test]
fn verification_method_accepts_runtime_key_labels_without_device_identity() {
    assert_eq!(
        verification_method_principal(&format!("{AGENT_DID}#runtime-pairing"))
            .as_ref()
            .map(arkret_identifiers::DidCoreId::as_str),
        Some(AGENT_CORE)
    );
}

fn bind_pairing_request_to_controller_device(
    body: &mut AgentKeyPairRequestBody,
    controller_principal_id: &str,
) {
    let device_id = "ak:device:01904100-0000-7000-8000-000000000002";
    let mut proof = body.requested_scope_disclosure.proofs[0].clone();
    proof.verification_method =
        arkret_wire::DidUrl::new(format!("{}#{device_id}", web_did(controller_principal_id)))
            .unwrap();
    body.authorize_event.event.executed_by = Some(arkret_wire::ActorId::service(
        crate::test_actor_id_str(&web_did(controller_principal_id)),
    ));
    body.authorize_event.event.producer_proof = Some(arkret_wire::ProducerEventProof {
        kind: proof.kind,
        verification_method: proof.verification_method,
        event_digest: proof.payload_digest,
        created_at: proof.created_at,
        domain: proof.domain,
        audience: proof.audience,
        proof_purpose: proof.proof_purpose,
        jws: proof.jws,
    });
}

#[test]
fn service_pairing_preserves_the_controller_device_bound_by_the_signed_submission() {
    let controller_principal_id = CONTROLLER_CORE;
    let mut body =
        key_pair_request_body(AGENT_DID, "did:web:agent.example#runtime-key", SERVICE_CORE);
    bind_pairing_request_to_controller_device(&mut body, controller_principal_id);

    let device_id = service_pairing_controller_device_id(&body, controller_principal_id)
        .expect("signed submission binds the service session device");

    assert_eq!(device_id, "ak:device:01904100-0000-7000-8000-000000000002");
}

/// The authorize Event is always signed by the controller itself: a device
/// key rooted in another principal's DID never binds the pairing.
#[test]
fn service_pairing_rejects_a_proof_rooted_in_another_controller() {
    let controller_principal_id = CONTROLLER_CORE;
    let mut body =
        key_pair_request_body(AGENT_DID, "did:web:agent.example#runtime-key", SERVICE_CORE);
    bind_pairing_request_to_controller_device(&mut body, controller_principal_id);
    let proof = body
        .authorize_event
        .event
        .producer_proof
        .as_mut()
        .expect("producer proof");
    proof.verification_method = arkret_wire::DidUrl::new(
        "did:web:other-controller.example#ak:device:01904100-0000-7000-8000-000000000002",
    )
    .unwrap();

    assert!(service_pairing_controller_device_id(&body, controller_principal_id).is_err());
}

#[test]
fn service_pairing_rejects_a_non_device_controller_proof() {
    let controller_principal_id = CONTROLLER_CORE;
    let mut body =
        key_pair_request_body(AGENT_DID, "did:web:agent.example#runtime-key", SERVICE_CORE);
    bind_pairing_request_to_controller_device(&mut body, controller_principal_id);
    let proof = body
        .authorize_event
        .event
        .producer_proof
        .as_mut()
        .expect("producer proof");
    proof.verification_method =
        arkret_wire::DidUrl::new(format!("{}#key-1", web_did(controller_principal_id))).unwrap();

    assert!(service_pairing_controller_device_id(&body, controller_principal_id).is_err());
}

#[test]
fn agent_view_projects_spec_shape_dropping_internal_columns() {
    let mut record = agent_record(
        "ak:did_core:web:agent.example",
        "ak:did_core:web:controller.example",
    );
    record.display_name = Some("Summary Assistant".to_owned());
    record.agent_slug = Some("summary".to_owned());
    let view = AgentView {
        agent: agent_projection_from_record(&record, AgentRuntimeState::Ready),
        grants: Vec::new(),
        key_state: None,
    };
    assert_eq!(view.agent.lifecycle, AgentLifecycleState::Active);
    assert_eq!(view.agent.readiness.state, AgentReadinessState::Ready);
    let agent = serde_json::to_value(&view).expect("view serializes");
    assert_eq!(agent["agent"]["slug"], "summary");
    assert_eq!(agent["agent"]["lifecycle"], "active");
    assert_eq!(agent["agent"]["readiness"]["state"], "ready");
    assert_eq!(agent["agent"]["agent_id"], "ak:did_core:web:agent.example");
    // coland-internal columns MUST NOT leak into the protocol projection.
    assert!(agent["agent"].get("controller_principal_id").is_none());
}

#[test]
fn selector_slug_reservation_releases_only_terminal_agents() {
    let now = chrono::DateTime::parse_from_rfc3339("2026-07-07T00:00:00.000Z")
        .unwrap()
        .with_timezone(&chrono::Utc);
    // A keyed agent (authorized_event_ref set) reserves its slug for any
    // non-terminal lifecycle intent (key-management.md §3.6.1).
    let mut active = agent_record(AGENT_CORE, CONTROLLER_CORE);
    active.state = AgentLifecycleState::Active;
    active.authorized_event_ref =
        Some("ak:event:AS8XThowW7JnZc80U10gJh-_lqkA-iSQ-LAvBXj6_9O5".to_owned());
    assert!(agent_record_reserves_selector_slug(&active, &now));

    let mut paused = active.clone();
    paused.state = AgentLifecycleState::Paused;
    assert!(agent_record_reserves_selector_slug(&paused, &now));

    // A never-keyed Agent is recoverable even after its handle expires.
    let pending_future = pending_pairing_record(
        AGENT_CORE,
        CONTROLLER_CORE,
        requested_agent_scope(),
        "01234567",
        "2026-07-08T00:00:00.000Z",
    );
    assert!(agent_record_reserves_selector_slug(&pending_future, &now));

    let pending_expired = pending_pairing_record(
        AGENT_CORE,
        CONTROLLER_CORE,
        requested_agent_scope(),
        "01234567",
        "2026-07-06T00:00:00.000Z",
    );
    assert!(agent_record_reserves_selector_slug(&pending_expired, &now));

    // Readiness and a missing/consumed handle cannot release a live identity.
    let mut bootstrap_lapsed = agent_record(AGENT_CORE, CONTROLLER_CORE);
    bootstrap_lapsed.state = AgentLifecycleState::Active;
    assert!(agent_record_reserves_selector_slug(&bootstrap_lapsed, &now));

    // Deactivation is terminal.
    let mut deactivated = active;
    deactivated.state = AgentLifecycleState::Deactivated;
    assert!(!agent_record_reserves_selector_slug(&deactivated, &now));
    let mut expired_paused = pending_expired.clone();
    expired_paused.state = AgentLifecycleState::Paused;
    assert!(agent_record_reserves_selector_slug(&expired_paused, &now));
    // Even retained future/open pairing fields must not reserve a terminal name.
    let mut terminal_pending = pending_future;
    terminal_pending.state = AgentLifecycleState::Deactivated;
    assert!(!agent_record_reserves_selector_slug(
        &terminal_pending,
        &now
    ));
}

#[test]
fn agent_pairing_token_decodes_compact_request_and_code() {
    let token = URL_SAFE_NO_PAD.encode(br#"{"r":"agent_pairing_request:0193","c":"01234567"}"#);

    assert!(is_agent_pairing_token_shape(&token));
    let decoded = decode_agent_pairing_token(&token).expect("decode token");

    assert_eq!(decoded["r"], json!("agent_pairing_request:0193"));
    assert_eq!(decoded["c"], json!("01234567"));
}

#[test]
fn agent_pairing_code_is_eight_ascii_decimal_digits() {
    for _ in 0..100 {
        let code = generate_pairing_code();
        assert_eq!(code.len(), 8);
        assert!(code.bytes().all(|byte| byte.is_ascii_digit()));
    }
}

#[test]
fn controller_binding_accepts_agent_controller() {
    let session = test_session(CONTROLLER_CORE);
    let record = agent_record(AGENT_CORE, CONTROLLER_CORE);

    ensure_agent_record_controller(&record, AGENT_CORE, &session)
        .expect("controller session must operate its agent");
}

#[test]
fn controller_binding_rejects_non_controller() {
    let session = test_session("ak:did_core:web:mallory.example");
    let record = agent_record(AGENT_CORE, CONTROLLER_CORE);

    let err = ensure_agent_record_controller(&record, AGENT_CORE, &session)
        .expect_err("non-controller session must be rejected");

    assert_eq!(err.wire_code(), "capability_denied");
}

#[test]
fn key_authorize_event_binds_pairing_transcript_and_scope() {
    let controller = CONTROLLER_CORE;
    let agent = AGENT_CORE;
    let verification_method = "did:web:agent.example#runtime-key-1";
    let service_id = SERVICE_CORE;
    let public_key_digest =
        "sha256:b600306cfa76723fdec395e53a9b3d9fdb78b1e2d7a23c32fcbcd2dc6d0c4092";
    let scope = requested_agent_scope();
    let mut record = pending_pairing_record(
        agent,
        controller,
        scope.clone(),
        "01234567",
        "2999-01-01T00:00:00.000Z",
    );
    let envelope = key_authorize_envelope(
        &mut record,
        controller,
        agent,
        verification_method,
        public_key_digest,
        service_id,
        scope,
    );

    ensure_pairing_request_open(&record).expect("pending pairing should be open");
    ensure_key_authorize_event_matches_request(
        &envelope,
        controller,
        &record,
        agent,
        verification_method,
        public_key_digest,
        service_id,
    )
    .expect("matching authorize_event should pass");

    for (field, principal) in [("actor_id", agent), ("executed_by", controller)] {
        let mut wrong_station = envelope.clone();
        wrong_station[field]["account_id"]["station_id"] =
            json!("ak:did_core:web:other-station.example");
        let mut service_kind = envelope.clone();
        service_kind[field] = json!(arkret_wire::ActorId::service(
            arkret_wire::DidCoreId::new(principal).unwrap(),
        ));
        let mut scalar_principal = envelope.clone();
        scalar_principal[field] = json!(principal);
        for rejected in [wrong_station, service_kind, scalar_principal] {
            assert!(
                ensure_key_authorize_event_matches_request(
                    &rejected,
                    controller,
                    &record,
                    agent,
                    verification_method,
                    public_key_digest,
                    service_id,
                )
                .is_err(),
                "{field} must retain its exact Account authority: {rejected}",
            );
        }
    }
}

#[test]
fn key_pair_proof_of_possession_verifies_runtime_key() {
    let agent = AGENT_CORE;
    let verification_method = "did:web:agent.example#runtime-key-1";
    let service_id = SERVICE_CORE;
    let body = key_pair_request_body(AGENT_DID, verification_method, service_id);
    let mut record = pending_pairing_record(
        agent,
        CONTROLLER_CORE,
        requested_agent_scope(),
        "01234567",
        "2999-01-01T00:00:00.000Z",
    );

    let request = runtime_approval_request_body(AGENT_DID, verification_method, service_id);
    record.approval_request_id = Some(body.approval_request_id.clone());
    record.runtime_key_binding_digest = Some(
        request
            .proof_of_possession
            .runtime_key_binding_digest
            .as_str()
            .to_owned(),
    );
    record.runtime_proof_verified_at = Some(request.proof_of_possession.created_at);
    record.runtime_key_request = Some(request);
    verify_runtime_key_pair_proof_of_possession(&body, &record, agent, service_id)
        .expect("runtime PoP must verify");
}

#[test]
fn runtime_approval_request_for_controller_omits_pairing_code() {
    let verification_method = "did:web:agent.example#runtime-key-1";
    let service_id = SERVICE_CORE;
    let key_pair = runtime_approval_request_body(AGENT_DID, verification_method, service_id);
    let request = AgentRuntimeApprovalRequestBody {
        pairing_code: arkret_wire::NonEmptyString::new("01234567").unwrap(),
        pairing_request_id: key_pair.pairing_request_id.clone(),
        agent_id: key_pair.agent_id.clone(),
        verification_method: key_pair.verification_method.clone(),
        public_key: key_pair.public_key.clone(),
        proof_of_possession: key_pair.proof_of_possession.clone(),
        runtime_attestation: None,
    };

    let controller_request = runtime_key_request_for_controller(
        &request,
        arkret_wire::OpaqueLocalId::new("agent_runtime_approval:01999999").unwrap(),
    );

    assert_eq!(
        controller_request.pairing_request_id,
        key_pair.pairing_request_id
    );
    assert_eq!(
        controller_request.verification_method.as_str(),
        verification_method,
    );
}

#[test]
fn agent_key_state_projects_pending_runtime_approval() {
    let mut record = pending_pairing_record(
        AGENT_CORE,
        CONTROLLER_CORE,
        requested_agent_scope(),
        "01234567",
        "2999-01-01T00:00:00.000Z",
    );
    record.approval_request_id =
        Some(arkret_wire::OpaqueLocalId::new("agent_runtime_approval:01999999").unwrap());
    record.approval_requested_at = Some(
        chrono::DateTime::parse_from_rfc3339("2026-07-08T00:00:00.000Z")
            .unwrap()
            .with_timezone(&chrono::Utc),
    );
    let runtime_request = runtime_approval_request_body(
        AGENT_DID,
        "did:web:agent.example#runtime-key-1",
        SERVICE_CORE,
    );
    record.runtime_proof_verified_at = Some(runtime_request.proof_of_possession.created_at);
    record.runtime_key_request = Some(runtime_request);

    let key_state = agent_key_state_from_record(
        &record,
        arkret_wire::AccountId::new(
            DidCoreId::new(CONTROLLER_CORE).unwrap(),
            crate::test_event::station_id(),
        ),
        Vec::new(),
        AgentRuntimeState::PendingRuntimeKey,
    )
    .expect("key state projection");

    assert_eq!(
        key_state.approval_request_id.as_deref(),
        Some("agent_runtime_approval:01999999")
    );
    assert_eq!(
        key_state
            .pending_runtime_key_request
            .as_ref()
            .map(|request| request.verification_method.as_str()),
        Some("did:web:agent.example#runtime-key-1")
    );
    assert_eq!(
        key_state.approval_requested_at,
        record.approval_requested_at
    );
    assert_eq!(key_state.pairing_code.as_deref(), Some("01234567"));
}

fn status_request_body(
    pairing_code: &str,
    agent_id: &str,
) -> AgentRuntimeApprovalStatusRequestBody {
    AgentRuntimeApprovalStatusRequestBody {
        pairing_request_id: arkret_wire::OpaqueLocalId::new(
            "agent_pairing_request:01999999-0000-7000-8000-00000000feed",
        )
        .unwrap(),
        pairing_code: arkret_wire::NonEmptyString::new(pairing_code).unwrap(),
        agent_id: DidCoreId::new(agent_id.to_owned()).unwrap(),
    }
}

fn status_now() -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::parse_from_rfc3339("2026-07-10T00:00:00.000Z")
        .unwrap()
        .with_timezone(&chrono::Utc)
}

#[test]
fn runtime_approval_status_reports_pending_request() {
    let mut record = pending_pairing_record(
        AGENT_CORE,
        CONTROLLER_CORE,
        requested_agent_scope(),
        "01234567",
        "2999-01-01T00:00:00.000Z",
    );
    record.approval_request_id =
        Some(arkret_wire::OpaqueLocalId::new("agent_runtime_approval:01999999").unwrap());

    let outcome = agent_runtime_key_request_status_outcome(
        &record,
        &status_request_body("01234567", AGENT_CORE),
        status_now(),
    )
    .expect("pending status must resolve");

    assert_eq!(outcome.lifecycle, AgentLifecycleState::Active);
    assert_eq!(outcome.runtime_state, AgentRuntimeState::PendingRuntimeKey);
    assert_eq!(
        outcome.approval_request_id.as_deref(),
        Some("agent_runtime_approval:01999999")
    );
    assert!(outcome.authorized_event_ref.is_none());
    assert!(outcome.authorized_public_key_digest.is_none());
}

#[test]
fn runtime_approval_status_lazily_reports_expired_open_pairing() {
    let mut record = pending_pairing_record(
        AGENT_CORE,
        CONTROLLER_CORE,
        requested_agent_scope(),
        "01234567",
        "2026-07-09T00:00:00.000Z",
    );
    record.approval_request_id =
        Some(arkret_wire::OpaqueLocalId::new("agent_runtime_approval:01999999").unwrap());

    let outcome = agent_runtime_key_request_status_outcome(
        &record,
        &status_request_body("01234567", AGENT_CORE),
        status_now(),
    )
    .expect("expired status must resolve");

    assert_eq!(outcome.lifecycle, AgentLifecycleState::Active);
    assert_eq!(outcome.runtime_state, AgentRuntimeState::PairingExpired);
    assert!(outcome.approval_request_id.is_none());
    assert!(outcome.authorized_event_ref.is_none());
}

#[test]
fn runtime_approval_status_mismatch_is_indistinguishable_from_missing_record() {
    let record = pending_pairing_record(
        AGENT_CORE,
        CONTROLLER_CORE,
        requested_agent_scope(),
        "01234567",
        "2999-01-01T00:00:00.000Z",
    );
    let missing = agent_pairing_not_found();

    let wrong_code = agent_runtime_key_request_status_outcome(
        &record,
        &status_request_body("00000000", AGENT_CORE),
        status_now(),
    )
    .expect_err("wrong pairing code must fail closed");
    let wrong_principal = agent_runtime_key_request_status_outcome(
        &record,
        &status_request_body("01234567", "ak:did_core:web:intruder.example"),
        status_now(),
    )
    .expect_err("wrong principal must fail closed");

    assert_eq!(wrong_code.wire_code(), missing.wire_code());
    assert_eq!(wrong_principal.wire_code(), missing.wire_code());
    assert_eq!(wrong_code.to_string(), missing.to_string());
    assert_eq!(wrong_principal.to_string(), missing.to_string());
}

#[test]
fn key_pair_rejects_wrong_pairing_request_id() {
    let record = pending_pairing_record(
        AGENT_CORE,
        CONTROLLER_CORE,
        requested_agent_scope(),
        "01234567",
        "2999-01-01T00:00:00.000Z",
    );

    let err = ensure_pairing_request_id_matches(
        &record,
        "agent_pairing_request:01999999-0000-7000-8000-00000000bad1",
    )
    .expect_err("wrong pairing request must fail closed");

    assert_eq!(err.wire_code(), "failed_precondition");
}

#[test]
fn key_authorize_event_rejects_wrong_stable_approval_identity() {
    let controller = CONTROLLER_CORE;
    let agent = AGENT_CORE;
    let verification_method = "did:web:agent.example#runtime-key-1";
    let service_id = SERVICE_CORE;
    let public_key_digest =
        "sha256:b600306cfa76723fdec395e53a9b3d9fdb78b1e2d7a23c32fcbcd2dc6d0c4092";
    let scope = requested_agent_scope();
    let mut record = pending_pairing_record(
        agent,
        controller,
        scope.clone(),
        "01234567",
        "2999-01-01T00:00:00.000Z",
    );
    let envelope = key_authorize_envelope(
        &mut record,
        controller,
        agent,
        verification_method,
        public_key_digest,
        service_id,
        scope,
    );
    let mut mismatched_record = record.clone();
    mismatched_record.approval_request_id = Some(
        arkret_wire::OpaqueLocalId::new(
            "agent_runtime_approval:01904100-0000-7000-8000-000000000099",
        )
        .unwrap(),
    );

    let err = ensure_key_authorize_event_matches_request(
        &envelope,
        controller,
        &mismatched_record,
        agent,
        verification_method,
        public_key_digest,
        service_id,
    )
    .expect_err("a different stable approval identity must change the expected digest");

    assert_eq!(err.wire_code(), "param_invalid");
    assert!(err.message.contains("request_canonical_digest"));
}

#[test]
fn key_authorize_event_rejects_wrong_controller_executor() {
    let controller = CONTROLLER_CORE;
    let agent = AGENT_CORE;
    let verification_method = "did:web:agent.example#runtime-key-1";
    let service_id = SERVICE_CORE;
    let public_key_digest =
        "sha256:b600306cfa76723fdec395e53a9b3d9fdb78b1e2d7a23c32fcbcd2dc6d0c4092";
    let scope = requested_agent_scope();
    let mut record = pending_pairing_record(
        agent,
        controller,
        scope.clone(),
        "01234567",
        "2999-01-01T00:00:00.000Z",
    );
    let envelope = key_authorize_envelope(
        &mut record,
        "ak:did_core:web:mallory.example",
        agent,
        verification_method,
        public_key_digest,
        service_id,
        scope,
    );

    let err = ensure_key_authorize_event_matches_request(
        &envelope,
        controller,
        &record,
        agent,
        verification_method,
        public_key_digest,
        service_id,
    )
    .expect_err("authorize_event executor must match authenticated controller");

    assert_eq!(err.wire_code(), "capability_denied");
    assert!(err.message.contains("executed_by"));
}

#[test]
fn key_authorize_event_rejects_wrong_approval_principal() {
    let controller = CONTROLLER_CORE;
    let agent = AGENT_CORE;
    let verification_method = "did:web:agent.example#runtime-key-1";
    let service_id = SERVICE_CORE;
    let public_key_digest =
        "sha256:b600306cfa76723fdec395e53a9b3d9fdb78b1e2d7a23c32fcbcd2dc6d0c4092";
    let scope = requested_agent_scope();
    let mut record = pending_pairing_record(
        agent,
        controller,
        scope.clone(),
        "01234567",
        "2999-01-01T00:00:00.000Z",
    );
    let mut envelope = key_authorize_envelope(
        &mut record,
        controller,
        agent,
        verification_method,
        public_key_digest,
        service_id,
        scope,
    );
    envelope["payload"]["approval_evidence"]["approved_by"] =
        json!("ak:did_core:web:mallory.example");

    let err = ensure_key_authorize_event_matches_request(
        &envelope,
        controller,
        &record,
        agent,
        verification_method,
        public_key_digest,
        service_id,
    )
    .expect_err("approval evidence must be issued by the authenticated controller");

    assert_eq!(err.wire_code(), "capability_denied");
    assert!(err.message.contains("approved_by"));
}

#[test]
fn key_authorize_event_rejects_expired_pairing() {
    let record = pending_pairing_record(
        AGENT_CORE,
        CONTROLLER_CORE,
        requested_agent_scope(),
        "01234567",
        "2000-01-01T00:00:00.000Z",
    );

    let err =
        ensure_pairing_request_open(&record).expect_err("expired pairing request must fail closed");

    assert_eq!(err.wire_code(), "failed_precondition");
    assert_eq!(
        err.reason_detail.as_deref(),
        Some("pairing request has expired")
    );
}

#[test]
fn key_authorize_event_accepts_narrower_scope_and_rejects_widening() {
    let controller = CONTROLLER_CORE;
    let agent = AGENT_CORE;
    let verification_method = "did:web:agent.example#runtime-key-1";
    let service_id = SERVICE_CORE;
    let public_key_digest =
        "sha256:b600306cfa76723fdec395e53a9b3d9fdb78b1e2d7a23c32fcbcd2dc6d0c4092";
    let expected_scope = requested_agent_scope();
    let mut record = pending_pairing_record(
        agent,
        controller,
        expected_scope,
        "01234567",
        "2999-01-01T00:00:00.000Z",
    );
    let weaker_scope = json!({
        "actions": ["ak.self.committed_event.stream.subscribe.v1"],
        "resources": [{ "kind": "service", "service_id": service_id }]
    });
    let envelope = key_authorize_envelope(
        &mut record,
        controller,
        agent,
        verification_method,
        public_key_digest,
        service_id,
        weaker_scope,
    );

    ensure_key_authorize_event_matches_request(
        &envelope,
        controller,
        &record,
        agent,
        verification_method,
        public_key_digest,
        service_id,
    )
    .expect("a narrower agent_key_scope must be accepted");

    let widened_scope = json!({
        "actions": ["ak.reaction.add"],
        "resources": [{ "kind": "service", "service_id": service_id }]
    });
    let widened_envelope = key_authorize_envelope(
        &mut record,
        controller,
        agent,
        verification_method,
        public_key_digest,
        service_id,
        widened_scope,
    );
    let err = ensure_key_authorize_event_matches_request(
        &widened_envelope,
        controller,
        &record,
        agent,
        verification_method,
        public_key_digest,
        service_id,
    )
    .expect_err("agent_key_scope must not exceed provisioned requested_scope");
    assert_eq!(err.wire_code(), "param_invalid");
    assert!(err.message.contains("agent_key_scope"));
}

#[test]
fn key_authorize_event_rejects_substituted_raw_authorization_key() {
    let controller = CONTROLLER_CORE;
    let agent = AGENT_CORE;
    let verification_method = "did:web:agent.example#runtime-key-1";
    let service_id = SERVICE_CORE;
    let public_key_digest =
        "sha256:b600306cfa76723fdec395e53a9b3d9fdb78b1e2d7a23c32fcbcd2dc6d0c4092";
    let scope = requested_agent_scope();
    let mut record = pending_pairing_record(
        agent,
        controller,
        scope.clone(),
        "01234567",
        "2999-01-01T00:00:00.000Z",
    );
    let mut envelope = key_authorize_envelope(
        &mut record,
        controller,
        agent,
        verification_method,
        public_key_digest,
        service_id,
        scope,
    );
    envelope["payload"]["public_key"]["key"] = json!("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");

    let err = ensure_key_authorize_event_matches_request(
        &envelope,
        controller,
        &record,
        agent,
        verification_method,
        public_key_digest,
        service_id,
    )
    .expect_err("authorize_event public key digest must bind the raw authorization key");

    assert_eq!(err.wire_code(), "param_invalid");
    assert!(
        err.message
            .contains("raw key differs from frozen candidate")
    );
}

#[test]
fn pairing_terminal_decision_requires_coverage_and_exact_post_state() {
    let expected = ("key-new".to_owned(), "event-new".to_owned());
    let old = ("key-old".to_owned(), "event-old".to_owned());
    let empty = BTreeSet::new();
    let prior = [old.clone()].into_iter().collect();
    assert_eq!(
        pairing_outcome_for_accepted_snapshot(false, &empty, &expected),
        None
    );
    assert_eq!(
        pairing_outcome_for_accepted_snapshot(false, &prior, &expected),
        None
    );
    let exact = [expected.clone()].into_iter().collect();
    assert_eq!(
        pairing_outcome_for_accepted_snapshot(true, &exact, &expected),
        Some(AgentKeyPairActivationState::Active)
    );
    assert_eq!(
        pairing_outcome_for_accepted_snapshot(true, &empty, &expected),
        Some(AgentKeyPairActivationState::Cancelled),
        "covered then revoked"
    );
    assert_eq!(
        pairing_outcome_for_accepted_snapshot(true, &prior, &expected),
        Some(AgentKeyPairActivationState::Cancelled),
        "covered then replaced"
    );
    let concurrent = [expected.clone(), old].into_iter().collect();
    assert_eq!(
        pairing_outcome_for_accepted_snapshot(true, &concurrent, &expected),
        Some(AgentKeyPairActivationState::Cancelled),
        "an additional accepted key changes the approved authority basis"
    );
}

#[test]
fn accepted_lifecycle_rejects_stale_active_row_without_interlocking_pairing() {
    for accepted in [
        Some(AgentLifecycleState::Paused),
        Some(AgentLifecycleState::Deactivated),
        None,
    ] {
        assert!(
            validate_accepted_agent_action_lifecycle(AgentLifecycleState::Active, accepted)
                .is_err(),
            "a stale active local row cannot override accepted pause/terminal/missing state"
        );
    }
    assert!(
        validate_accepted_agent_action_lifecycle(
            AgentLifecycleState::Active,
            Some(AgentLifecycleState::Active)
        )
        .is_ok()
    );
    assert!(
        validate_accepted_agent_action_lifecycle(
            AgentLifecycleState::Paused,
            Some(AgentLifecycleState::Active)
        )
        .is_err(),
        "pending local pause intent remains a conservative deny"
    );
    let key = ("key".to_owned(), "event".to_owned());
    assert_eq!(
        projected_agent_lifecycle(
            AgentLifecycleState::Active,
            Some(AgentLifecycleState::Paused)
        )
        .unwrap(),
        AgentLifecycleState::Paused
    );
    assert_eq!(
        projected_agent_lifecycle(
            AgentLifecycleState::Active,
            Some(AgentLifecycleState::Deactivated)
        )
        .unwrap(),
        AgentLifecycleState::Deactivated
    );
    assert_eq!(
        projected_agent_lifecycle(
            AgentLifecycleState::Paused,
            Some(AgentLifecycleState::Active)
        )
        .unwrap(),
        AgentLifecycleState::Paused
    );
    let keys = [key.clone()].into_iter().collect();
    assert_eq!(
        pairing_outcome_for_accepted_snapshot(true, &keys, &key),
        Some(AgentKeyPairActivationState::Active),
        "pairing's accepted-key decision is independent of the active-action gate; paused may be ready"
    );
}
