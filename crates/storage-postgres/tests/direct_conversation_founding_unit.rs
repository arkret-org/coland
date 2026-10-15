//! Direct Conversation founding unit and profile admission table at the
//! governing Station's transaction cut
//! (`contact-and-direct-conversation.md` sections 5.4 to 6.2 and 8.4).
//!
//! The founder is a genuinely admitted PCR founding device, so every producer
//! guard is rechecked against the Station's device current. The pair's Contact
//! round is this Station's durable `contacts` row: only Contact admission
//! writes it in production, and the founding transaction reads it as the
//! current founding authority.

#[path = "../../test-support/src/device_authorization_history.rs"]
#[allow(dead_code)]
mod device_authorization_history;
#[path = "support/historical_control_source.rs"]
#[expect(
    dead_code,
    reason = "This integration binary uses only its subset of the shared control source fixture."
)]
mod historical_control_source;
#[path = "support/ordinary_realm.rs"]
#[allow(dead_code)]
mod ordinary_realm;
#[path = "../../test-support/src/pcr_genesis.rs"]
#[allow(dead_code)]
mod pcr_genesis;

use arkret_models_collaboration::authority_commit::{
    DirectConversationFoundingUnitKind, DirectConversationFoundingUnitSubmission,
};
use arkret_models_collaboration::contact_operations::{
    ContactCurrentProof, ContactPeer, ContactProducerSigner, ContactRound,
    ContactRoundEvidenceBundle, NormalResponseAcceptanceReceipt, RequestAcceptanceReceipt,
    RequestAcceptanceReceiptCore,
};
use arkret_wire::{AccountId, ActorId, DidCoreId, DidUrl, EventKind, Hash, RealmId};
use coland_storage::{
    AuthorityCommitStore, AuthorityCommitTransaction, ConflictCode, ContactStore,
    CurrentRealmAuthority, DirectConversationAdmissionCut, DirectConversationFoundingCommitOutcome,
    DirectConversationFoundingCommitUnit, EventCommitUnitOfWork, EventStore, PersistenceError,
    SelfProducerCommitGuard,
};
use coland_storage_postgres::test_database::TestDatabase;
use coland_storage_postgres::{
    FoundingProfileAdmissionSpy, PgAuthorityCommitStore, PgContactStore, PgEventCommitUnitOfWork,
    PgEventStore, PgPersistenceStore, PgPool,
};
use diesel::sql_types::{BigInt, Text};
use diesel_async::RunQueryDsl;

#[derive(diesel::QueryableByName)]
struct StationRow {
    #[diesel(sql_type = Text)]
    station_id: String,
}

#[derive(diesel::QueryableByName)]
struct CountRow {
    #[diesel(sql_type = BigInt)]
    count: i64,
}

#[derive(diesel::QueryableByName)]
struct DeliveryRow {
    #[diesel(sql_type = Text)]
    peer_id: String,
    #[diesel(sql_type = Text)]
    payload_json: String,
}

const TRUST_DOMAIN: &str = "ak:trust_domain:direct-conversation.example";

struct CanonicalHydrationAdapter;

impl coland_services::hydration::HydrationProjectionAdapter for CanonicalHydrationAdapter {
    fn operation_from_canonical_record(
        &self,
        record: &coland_services::events::AcceptedEvent,
    ) -> Option<arkret_event_draft::ProjectedEventOperation> {
        let event = serde_json::from_value::<arkret_wire::Event>(record.envelope.clone()).ok()?;
        let operation_id =
            arkret_wire::OperationId::new(format!("ak:operation:{}", uuid::Uuid::now_v7())).ok()?;
        let suite = event.realm_id.digest_suite_code().digest_suite();
        arkret_event_draft::ProjectedEventOperation::from_accepted_event(
            operation_id,
            arkret_wire::OperationKind::Create,
            None,
            &event,
            suite,
        )
        .ok()
    }
}

/// A founder with an accepted founding device, a same-Station peer and their
/// accepted Contact round, in which the founder is the responder.
struct Pair {
    pool: PgPool,
    station: DidCoreId,
    station_did: arkret_wire::Did,
    founder: AccountId,
    founder_method: DidUrl,
    founder_signing_seed: [u8; 32],
    founder_guard: SelfProducerCommitGuard,
    founder_leaf_authority:
        arkret_models_collaboration::events_payloads::MlsGenesisCreatorLeafAuthority,
    peer: AccountId,
    peer_method: DidUrl,
    peer_signing_seed: [u8; 32],
    peer_guard: Option<coland_storage::DeviceRevocationGateSelector>,
    contact_round_id: Hash,
}

impl Pair {
    fn founder_actor(&self) -> ActorId {
        ActorId::account(self.founder.clone())
    }

    fn peer_actor(&self) -> ActorId {
        ActorId::account(self.peer.clone())
    }

    fn guards(&self) -> [SelfProducerCommitGuard; 4] {
        std::array::from_fn(|_| self.founder_guard.clone())
    }

    fn store(&self) -> PgAuthorityCommitStore {
        PgAuthorityCommitStore {
            pool: self.pool.clone(),
        }
    }
}

fn unique_event_id(seed: &str) -> arkret_wire::EventId {
    arkret_wire::EventId::from_digest(
        arkret_canonical::DigestSuite::Sha256,
        arkret_canonical::sha256_bytes(format!("{seed}:{}", uuid::Uuid::now_v7()).as_bytes()),
    )
}

fn fixture_hash(byte: char) -> Hash {
    Hash::new(format!("sha256:{}", byte.to_string().repeat(64))).unwrap()
}

fn station_successor(
    previous: &arkret_wire::RealmCommit,
    event: &arkret_wire::Event,
    station_did: &arkret_wire::Did,
    offset_seconds: i64,
) -> arkret_wire::RealmCommit {
    let mut commit = previous.clone();
    commit.commit_id = arkret_wire::RealmCommitId::from_digest(arkret_canonical::sha256_bytes(
        format!("{}:{}:successor", event.event_id, previous.commit_id).as_bytes(),
    ));
    commit.stream_position = previous.stream_position + 1;
    commit.previous_commit_ref = Some(previous.commit_id.clone());
    commit.event_ref = event.event_id.clone();
    commit.committed_at = previous.committed_at + chrono::TimeDelta::seconds(offset_seconds);
    commit.producer_signer_fact_digest = None;
    let identity =
        arkret_canonical::canonical::unsigned_value(&commit, &["commit_id", "signature"]).unwrap();
    commit.commit_id = arkret_wire::RealmCommitId::from_digest(arkret_canonical::sha256_bytes(
        arkret_canonical::canonical_json_bytes(&identity).unwrap(),
    ));
    let unsigned = arkret_canonical::canonical::unsigned_value(&commit, &["signature"]).unwrap();
    commit.signature = arkret_signatures::detached_object::sign_detached_object(
        &unsigned,
        arkret_wire::DetachedSignatureContext::RealmCommit,
        DidUrl::new(format!("{station_did}#authority")).unwrap(),
        commit.committed_at,
        &ed25519_dalek::SigningKey::from_bytes(&[83; 32]),
    )
    .unwrap();
    commit
}

fn station_genesis_commit(
    template: &arkret_wire::RealmCommit,
    event: &arkret_wire::Event,
    station_did: &arkret_wire::Did,
    committed_at: chrono::DateTime<chrono::Utc>,
) -> arkret_wire::RealmCommit {
    let realm_id = RealmId::from_event_id(&event.event_id);
    let mut commit = template.clone();
    commit.commit_id = arkret_wire::RealmCommitId::from_digest(arkret_canonical::sha256_bytes(
        format!("{}:genesis", event.event_id).as_bytes(),
    ));
    commit.realm_id = realm_id.clone();
    commit.stream_ref = arkret_wire::CommitStreamRef::Realm { realm_id };
    commit.stream_position = 0;
    commit.previous_commit_ref = None;
    commit.event_ref = event.event_id.clone();
    commit.governance_generation = 0;
    commit.authority_ref =
        arkret_wire::RealmCommitAuthorityRef::GenesisOrChangeEvent(event.event_id.clone());
    commit.committed_at = committed_at;
    commit.producer_signer_fact_digest = None;
    let identity =
        arkret_canonical::canonical::unsigned_value(&commit, &["commit_id", "signature"]).unwrap();
    commit.commit_id = arkret_wire::RealmCommitId::from_digest(arkret_canonical::sha256_bytes(
        arkret_canonical::canonical_json_bytes(&identity).unwrap(),
    ));
    let unsigned = arkret_canonical::canonical::unsigned_value(&commit, &["signature"]).unwrap();
    commit.signature = arkret_signatures::detached_object::sign_detached_object(
        &unsigned,
        arkret_wire::DetachedSignatureContext::RealmCommit,
        DidUrl::new(format!("{station_did}#authority")).unwrap(),
        commit.committed_at,
        &ed25519_dalek::SigningKey::from_bytes(&[83; 32]),
    )
    .unwrap();
    commit
}

#[allow(clippy::too_many_arguments)]
fn agent_provision_event(
    controller: &AccountId,
    realm_id: &RealmId,
    method: &DidUrl,
    seed: [u8; 32],
    agent_id: &DidCoreId,
    agent_pcr_id: &RealmId,
    controller_authorization_ref: &str,
    created_at: chrono::DateTime<chrono::Utc>,
) -> arkret_wire::Event {
    let event = arkret_wire::test_support::raw_event_at(
        EventKind::AgentProvision.as_str(),
        arkret_wire::ScopeRef::Realm {
            realm_id: realm_id.clone(),
        },
        controller.principal_id.clone(),
        controller.station_id.clone(),
        serde_json::json!({
            "schema": "ak.schema.agent_provision.v1",
            "agent_id": agent_id,
            "controller_principal_id": controller.principal_id,
            "principal_control_realm_id": agent_pcr_id,
            "controller_authorization_ref": controller_authorization_ref,
            "agent_slug": "direct-helper",
            "accountability_scope": "agent_operator",
            "requested_scope_digest": format!("sha256:{}", "b".repeat(64)),
            "selector_visibility": "private",
            "created_at": arkret_canonical::format_timestamp_canonical(created_at)
        }),
        created_at,
    )
    .unwrap();
    device_authorization_history::sign_event(event, method.clone(), seed)
}

fn agent_control_event(
    controller_method: &DidUrl,
    signing_seed: [u8; 32],
    controller: &AccountId,
    agent: &AccountId,
    agent_pcr: &RealmId,
    authorization_ref: &str,
    payload: serde_json::Value,
    at: chrono::DateTime<chrono::Utc>,
) -> arkret_wire::Event {
    let mut event = arkret_wire::test_support::raw_event_for_actor_at(
        EventKind::AgentKeyAuthorize.as_str(),
        arkret_wire::ScopeRef::Realm {
            realm_id: agent_pcr.clone(),
        },
        ActorId::account(agent.clone()),
        payload,
        at,
    )
    .unwrap();
    event.executed_by = Some(ActorId::account(controller.clone()));
    event.authorization_ref =
        Some(arkret_wire::AuthorizationRef::new(authorization_ref.to_owned()).unwrap());
    device_authorization_history::sign_event(event, controller_method.clone(), signing_seed)
}

fn agent_key_authorization(
    agent_did: &arkret_wire::Did,
    controller: &DidCoreId,
    at: chrono::DateTime<chrono::Utc>,
) -> serde_json::Value {
    let method = format!("{agent_did}#runtime-1");
    let submit = arkret_wire::ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT_V1;
    serde_json::json!({
        "agent_id": arkret_wire::project_did_to_core_id(agent_did).unwrap(),
        "key_id": method,
        "verification_method": method,
        "public_key": {
            "kty": "OKP",
            "kid": method,
            "algorithm": "Ed25519",
            "key": arkret_canonical::base64url_encode(
                ed25519_dalek::SigningKey::from_bytes(&[0x61; 32]).verifying_key().as_bytes()
            )
        },
        "accountable_principal_id": controller,
        "agent_key_scope": {
            "actions": [submit],
            "resources": [{"kind": "operation", "operation": submit}]
        },
        "audience": ["ak:did_core:web:direct-conversation.example"],
        "issued_at": arkret_canonical::format_timestamp_canonical(at),
        "approval_evidence": {
            "kind": "pairing_request",
            "request_canonical_digest": format!("sha256:{}", "d".repeat(64)),
            "pairing_request_id": format!("agent_pairing_request:{}", uuid::Uuid::now_v7()),
            "approved_by": controller
        }
    })
}

fn fixture_signature(
    issuer: &str,
    at: chrono::DateTime<chrono::Utc>,
) -> arkret_wire::ProtocolSignature {
    arkret_wire::ProtocolSignature {
        verification_method: DidUrl::new(format!("{issuer}#service-key")).unwrap(),
        created_at: at,
        jws: format!(
            "{}..{}",
            arkret_canonical::base64url_encode(br#"{"alg":"EdDSA"}"#),
            arkret_canonical::base64url_encode([1_u8; 64])
        ),
    }
}

fn producer_signer(account: &AccountId) -> ContactProducerSigner {
    let did = account
        .principal_id
        .as_str()
        .replace("ak:did_core:", "did:");
    ContactProducerSigner::direct(
        DidUrl::new(format!("{did}#device")).unwrap(),
        arkret_wire::Base64UrlString::new(arkret_canonical::base64url_encode([7_u8; 32])).unwrap(),
    )
    .unwrap()
}

/// A normal-branch Contact round: `requester` asked, `responder` accepted.
fn normal_round(
    requester: &AccountId,
    responder: &AccountId,
    request_event_ref: &arkret_wire::EventId,
    response_event_ref: &arkret_wire::EventId,
    at: chrono::DateTime<chrono::Utc>,
) -> ContactRoundEvidenceBundle {
    let requester_peer = ContactPeer::Human {
        account_id: requester.clone(),
    };
    let responder_peer = ContactPeer::Human {
        account_id: responder.clone(),
    };
    let mut request_receipt = RequestAcceptanceReceipt {
        core: RequestAcceptanceReceiptCore {
            holder: requester_peer.clone(),
            peer: responder_peer.clone(),
            slot_version: 1,
            slot_predecessor: None,
            previous_terminal_contact_round_id: None,
            request_event_ref: request_event_ref.clone(),
            producer_signer: producer_signer(requester),
            source_checkpoint: fixture_hash('2'),
            accepted_at: at,
            issuer_id: requester.station_id.clone(),
        },
        receipt_digest: fixture_hash('0'),
        signature: fixture_signature("did:web:contact-station.example", at),
    };
    request_receipt.receipt_digest = request_receipt.computed_core_digest().unwrap();
    let request_acceptance_receipt_digest =
        Hash::new(arkret_canonical::canonical_sha256(&request_receipt).unwrap()).unwrap();
    let mut sorted_pair_member_ids = [
        ActorId::account(requester.clone()),
        ActorId::account(responder.clone()),
    ];
    sorted_pair_member_ids.sort();
    let contact_round = ContactRound::Normal {
        sorted_pair_member_ids,
        request_event_ref: request_event_ref.clone(),
        request_acceptance_receipt_digest,
    };
    let mut material = b"ak.contact.round.v1\n".to_vec();
    material.extend(arkret_canonical::canonical_json_bytes(&contact_round).unwrap());
    let contact_round_id = Hash::new(arkret_canonical::sha256_digest(material)).unwrap();
    let proof =
        |subject: &AccountId, peer: ContactPeer, head: &arkret_wire::EventId| ContactCurrentProof {
            contact_round_id: contact_round_id.clone(),
            issuer_id: subject.station_id.clone(),
            peer,
            terminal: false,
            accepted_commit_event_ids: vec![head.clone()],
            head_event_ref: head.clone(),
            complete_through: 1,
            fresh_until: at + chrono::Duration::hours(1),
            signature: fixture_signature("did:web:contact-station.example", at),
        };
    ContactRoundEvidenceBundle {
        contact_round_id: contact_round_id.clone(),
        previous_terminal_contact_round_id: None,
        contact_round,
        request_receipts: vec![request_receipt.clone()],
        normal_response_receipt: Some(NormalResponseAcceptanceReceipt {
            contact_round_id: contact_round_id.clone(),
            request_receipt,
            response_event_ref: response_event_ref.clone(),
            producer_signer: producer_signer(responder),
            outgoing_slot_absence_digest: fixture_hash('5'),
            accepted_at: at,
            issuer_id: responder.station_id.clone(),
            signature: fixture_signature("did:web:contact-station.example", at),
        }),
        glare_concurrency_attestations: None,
        current_proofs: vec![
            proof(requester, responder_peer, request_event_ref),
            proof(responder, requester_peer, response_event_ref),
        ],
        continuity_checkpoint: None,
    }
}

/// Record the pair's accepted Contact the way Contact admission leaves it.
async fn accept_contact(
    pool: &PgPool,
    requester: &AccountId,
    responder: &AccountId,
    status: &str,
) -> Hash {
    let at =
        chrono::DateTime::from_timestamp_millis(chrono::Utc::now().timestamp_millis()).unwrap();
    let request_event_ref = unique_event_id("contact-request");
    let response_event_ref = unique_event_id("contact-response");
    let evidence = normal_round(
        requester,
        responder,
        &request_event_ref,
        &response_event_ref,
        at,
    );
    let contact_round_id = evidence.contact_round_id.clone();
    PgContactStore { pool: pool.clone() }
        .put(&coland_storage::ContactRecord {
            requester_id: ActorId::account(requester.clone()),
            target_id: ActorId::account(responder.clone()),
            contact_round_id: Some(contact_round_id.clone()),
            granted_to_target_scopes: vec!["direct_message".to_owned()],
            granted_to_requester_scopes: vec!["direct_message".to_owned()],
            status: status.to_owned(),
            pending_incoming_admitted: true,
            request_event_ref: Some(request_event_ref),
            request_slot_states: Vec::new(),
            request_receipts: evidence.request_receipts.clone(),
            request_mirror_receipts: Vec::new(),
            contact_round_evidence: Some(evidence),
            contact_round_evidence_history: Vec::new(),
            control_outcomes: Vec::new(),
            response_event_ref: Some(response_event_ref),
            tombstone_event_ref: None,
            message: None,
            peer_host_id: None,
            peer_service_resolution: None,
            created_at: at,
            updated_at: at,
        })
        .await
        .unwrap();
    contact_round_id
}

async fn pair(pool: &PgPool) -> Pair {
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query(
        "INSERT INTO device_inventory_station(singleton,station_id) \
         VALUES(TRUE,'ak:did_core:web:direct-conversation-contract.example') \
         ON CONFLICT(singleton) DO NOTHING",
    )
    .execute(&mut *conn)
    .await
    .unwrap();
    let station =
        diesel::sql_query("SELECT station_id FROM device_inventory_station WHERE singleton")
            .get_result::<StationRow>(&mut *conn)
            .await
            .unwrap();
    drop(conn);
    let station = DidCoreId::new(station.station_id).unwrap();
    let pcr = pcr_genesis::PcrGenesisFixture::new(device_authorization_history::did_web_station(
        &station,
    ));
    let selector = Box::pin(pcr.admit_founding_device(&PgPersistenceStore::new(pool.clone())))
        .await
        .expect("accepted founder PCR genesis");
    let founder = pcr.history.account.clone();
    ordinary_realm::human_profile::register_fixture_signer(
        &pcr.history.account,
        pcr.history.device_verification_method.clone(),
        pcr.history.founding_device_signing_seed,
    );
    let peer_pcr = pcr_genesis::PcrGenesisFixture::new_with(
        device_authorization_history::did_web_station(&station),
        device_authorization_history::DeviceHistoryFixtureOptions {
            local_id: format!("dc-peer-{}", uuid::Uuid::now_v7().simple()),
            founding_device_id: arkret_wire::DeviceId::new(
                "ak:device:01904100-0000-7000-8000-000000000082",
            )
            .unwrap(),
            founding_device_signing_seed: [82; 32],
            ..Default::default()
        },
    );
    let peer_selector =
        Box::pin(peer_pcr.admit_founding_device(&PgPersistenceStore::new(pool.clone())))
            .await
            .expect("accepted independent peer PCR genesis");
    let peer = peer_pcr.history.account.clone();
    ordinary_realm::human_profile::register_fixture_signer(
        &peer,
        peer_pcr.history.device_verification_method.clone(),
        peer_pcr.history.founding_device_signing_seed,
    );
    let contact_round_id = accept_contact(pool, &peer, &founder, "accepted").await;
    Pair {
        pool: pool.clone(),
        station_did: pcr.history.station_did.clone(),
        station,
        founder,
        founder_method: pcr.history.device_verification_method.clone(),
        founder_signing_seed: pcr.history.founding_device_signing_seed,
        founder_leaf_authority: founder_leaf_authority(&pcr, &selector),
        founder_guard: SelfProducerCommitGuard::HumanDevice(selector),
        peer,
        peer_method: peer_pcr.history.device_verification_method.clone(),
        peer_signing_seed: peer_pcr.history.founding_device_signing_seed,
        peer_guard: Some(peer_selector),
        contact_round_id,
    }
}

async fn contract_pool() -> (TestDatabase, PgPool) {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    (database, pool)
}

/// One Event genuinely signed by the accepted founding device.
fn authored(
    kind: EventKind,
    scope_ref: arkret_wire::ScopeRef,
    actor: ActorId,
    method: &DidUrl,
    signing_seed: [u8; 32],
    payload: serde_json::Value,
    semantic_refs: Vec<arkret_wire::SemanticRef>,
    at: chrono::DateTime<chrono::Utc>,
) -> arkret_wire::Event {
    let mut event = arkret_wire::test_support::raw_event_for_actor_at(
        kind.as_str(),
        scope_ref,
        actor,
        payload,
        at,
    )
    .unwrap();
    event.semantic_refs = semantic_refs;
    device_authorization_history::sign_event(event, method.clone(), signing_seed)
}

/// Knobs a refusal case turns on an otherwise exact founding unit.
#[derive(Clone)]
struct UnitShape {
    author: ActorId,
    other: ActorId,
    salt: String,
    join_rule: &'static str,
    discoverability: &'static str,
    authority_ref: arkret_wire::SemanticRef,
}

impl UnitShape {
    fn exact(pair: &Pair) -> Self {
        Self {
            author: pair.founder_actor(),
            other: pair.peer_actor(),
            salt: salt(),
            join_rule: "closed",
            discoverability: "invite_only",
            authority_ref: arkret_wire::SemanticRef::new(
                pair.contact_round_id.to_string(),
                "direct_conversation_contact_round",
            ),
        }
    }
}

fn salt() -> String {
    arkret_canonical::base64url_encode(arkret_canonical::sha256_bytes(
        uuid::Uuid::now_v7().as_bytes(),
    ))
}

async fn founding_unit(
    pair: &Pair,
    shape: &UnitShape,
    idempotency_key: arkret_wire::UuidV7,
    at: chrono::DateTime<chrono::Utc>,
) -> DirectConversationFoundingCommitUnit {
    let create = authored(
        EventKind::RealmCreate,
        arkret_wire::ScopeRef::RealmGenesis,
        shape.author.clone(),
        &pair.founder_method,
        pair.founder_signing_seed,
        serde_json::json!({"object":{
            "schema":"ak.schema.realm_genesis.v1",
            "purpose":"direct_conversation",
            "genesis_salt":shape.salt,
            "trust_domain":TRUST_DOMAIN,
            "security_class":"standard",
            "governance_station_id":pair.station,
            "initial_join_rule":shape.join_rule,
            "initial_history_access":"since_join",
            "initial_discoverability":shape.discoverability
        }}),
        vec![shape.authority_ref.clone()],
        at,
    );
    let realm_id = RealmId::from_event_id(&create.event_id);
    let scope = arkret_wire::ScopeRef::Realm {
        realm_id: realm_id.clone(),
    };
    let join = |member: &ActorId, controller_generation_ref: Option<&arkret_wire::EventId>| {
        let mut payload = serde_json::json!({
            "realm_id":realm_id,
            "member_id":member,
            "membership":"join",
            "reason":"direct_conversation_bootstrap"
        });
        if shape.authority_ref.role == "direct_conversation_agent_provision"
            && member == &shape.other
        {
            payload["agent_controller_binding"] = serde_json::json!({
                "controller_account_id": shape.author.as_account_id().unwrap(),
                "controller_membership_generation_ref": controller_generation_ref.unwrap(),
            });
        }
        authored(
            EventKind::MemberState,
            scope.clone(),
            shape.author.clone(),
            &pair.founder_method,
            pair.founder_signing_seed,
            payload,
            Vec::new(),
            at,
        )
    };
    let founder_join = join(&shape.author, None);
    let peer_join = join(&shape.other, Some(&founder_join.event_id));
    let strand = authored(
        EventKind::StrandCreate,
        scope.clone(),
        shape.author.clone(),
        &pair.founder_method,
        pair.founder_signing_seed,
        serde_json::json!({"object":{
            "schema":"ak.schema.strand.v1",
            "realm_id":realm_id,
            "tracks":{"discussion":{"is_primary":true,"profile":"discussion"}},
            "metadata":{"title":"Direct conversation"},
            "state":"active",
            "created_by":shape.author,
            "created_at":arkret_canonical::format_timestamp_canonical(at)
        }}),
        Vec::new(),
        at,
    );
    let events = [create, founder_join, peer_join, strand];
    let authority = CurrentRealmAuthority {
        realm_id: realm_id.clone(),
        generation: 0,
        service_id: pair.station.clone(),
        authority_ref: arkret_wire::RealmCommitAuthorityRef::GenesisOrChangeEvent(
            events[0].event_id.clone(),
        ),
        last_handoff_ref: None,
    };
    let mut previous = None;
    let mut prepared = Vec::new();
    for (index, event) in events.iter().cloned().enumerate() {
        // Only the legal founder has an actual accepted source. Wrong-author
        // negative vectors remain wrong and are refused by the founding gate.
        let fact = if shape.author == pair.founder_actor() {
            pair.store()
                .prepare_human_signer_fact(&event, at)
                .await
                .unwrap()
        } else {
            None
        };
        let mut commit = arkret_wire::RealmCommit {
            producer_signer_fact_digest: fact.as_ref().map(|fact| fact.digest().unwrap()),
            commit_id: arkret_wire::RealmCommitId::from_digest([0; 32]),
            realm_id: realm_id.clone(),
            stream_ref: arkret_wire::CommitStreamRef::Realm {
                realm_id: realm_id.clone(),
            },
            stream_position: index as u64,
            previous_commit_ref: previous.clone(),
            event_ref: event.event_id.clone(),
            governance_generation: 0,
            authority_ref: authority.authority_ref.clone(),
            committed_at: at,
            signature: ordinary_realm::signature_for_did(&pair.station_did, at),
        };
        let identity =
            arkret_canonical::canonical::unsigned_value(&commit, &["commit_id", "signature"])
                .unwrap();
        commit.commit_id = arkret_wire::RealmCommitId::from_digest(arkret_canonical::sha256_bytes(
            arkret_canonical::canonical_json_bytes(&identity).unwrap(),
        ));
        commit.signature = arkret_signatures::detached_object::sign_detached_object(
            &arkret_canonical::canonical::unsigned_value(&commit, &["signature"]).unwrap(),
            arkret_wire::DetachedSignatureContext::RealmCommit,
            DidUrl::new(format!("{}#authority", pair.station_did.clone())).unwrap(),
            at,
            &ed25519_dalek::SigningKey::from_bytes(&[83; 32]),
        )
        .unwrap();
        previous = Some(commit.commit_id.clone());
        prepared.push(AuthorityCommitTransaction {
            expected_authority: authority.clone(),
            event,
            commit,
            producer_signer_fact: fact.map(Into::into),
            mls_state: None,
            welcomes: Vec::new(),
            recipient_queue_capacity: 0,
        });
    }
    let transactions: [AuthorityCommitTransaction; 4] = prepared.try_into().unwrap();
    DirectConversationFoundingCommitUnit {
        submission: DirectConversationFoundingUnitSubmission {
            unit_kind: DirectConversationFoundingUnitKind::DirectConversationFounding,
            idempotency_key,
            events: events.map(arkret_wire::EventAdmissionSubmission::new),
        },
        transactions,
    }
}

fn key() -> arkret_wire::UuidV7 {
    arkret_wire::UuidV7::new(uuid::Uuid::now_v7()).unwrap()
}

fn now() -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::from_timestamp_millis(chrono::Utc::now().timestamp_millis()).unwrap()
}

async fn count(pool: &PgPool, sql: &str, realm_id: &RealmId) -> i64 {
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query(sql)
        .bind::<Text, _>(realm_id.as_str())
        .get_result::<CountRow>(&mut *conn)
        .await
        .unwrap()
        .count
}

/// Every durable row a founding unit or a later Event can leave for `realm_id`.
async fn footprint(pool: &PgPool, realm_id: &RealmId) -> [i64; 5] {
    [
        count(
            pool,
            "SELECT COUNT(*) AS count FROM realm_authorities WHERE realm_id=$1",
            realm_id,
        )
        .await,
        count(
            pool,
            "SELECT COUNT(*) AS count FROM canonical_events WHERE realm_id=$1",
            realm_id,
        )
        .await,
        count(
            pool,
            "SELECT COUNT(*) AS count FROM realm_commits WHERE realm_id=$1",
            realm_id,
        )
        .await,
        count(
            pool,
            "SELECT COUNT(*) AS count FROM direct_conversation_founding_slots WHERE realm_id=$1",
            realm_id,
        )
        .await,
        count(
            pool,
            "SELECT COUNT(*) AS count FROM member_state_current_results WHERE realm_id=$1",
            realm_id,
        )
        .await,
    ]
}

fn refusal_code<T: std::fmt::Debug>(outcome: Result<T, PersistenceError>) -> ConflictCode {
    match outcome {
        Err(PersistenceError::Conflict(detail)) => ConflictCode::from_detail(&detail)
            .unwrap_or_else(|| panic!("unregistered refusal {detail}")),
        other => panic!("expected a registered refusal, got {other:?}"),
    }
}

fn realm_of(unit: &DirectConversationFoundingCommitUnit) -> RealmId {
    unit.transactions[0].event.realm_id.clone()
}

async fn exact_genesis_scan(
    store: &PgAuthorityCommitStore,
    realm: &RealmId,
    account: &AccountId,
    station: &DidCoreId,
) -> arkret_wire::StreamScanOutcome {
    use coland_storage::AccountStreamScan;
    let scan = store
        .scan_stream_for_account(
            &arkret_wire::StreamScanRequest {
                realm_id: realm.clone(),
                stream_ref: arkret_wire::CommitStreamRef::Realm {
                    realm_id: realm.clone(),
                },
                direction: arkret_wire::StreamScanDirection::Before(Some(1)),
                limit: 1,
            },
            account,
            station,
        )
        .await
        .unwrap();
    let AccountStreamScan::Page(page) = scan else {
        panic!("the actual founding member's held interval must be provable");
    };
    page
}

#[tokio::test]
async fn direct_founding_members_read_exact_genesis_and_unmatched_slot_keeps_join_floor() {
    let (_database, pool) = contract_pool().await;
    let pair = pair(&pool).await;
    let store = pair.store();
    let at = now();
    let unit = founding_unit(&pair, &UnitShape::exact(&pair), key(), at).await;
    let DirectConversationFoundingCommitOutcome::Committed(commits) = store
        .admit_self_direct_conversation_founding_unit(&unit, &pair.guards(), at)
        .await
        .unwrap()
    else {
        panic!("actual founding must commit");
    };
    let realm = realm_of(&unit);
    let stream = arkret_wire::CommitStreamRef::Realm {
        realm_id: realm.clone(),
    };
    let readers = store
        .replica_bootstrap_readers(&stream, &pair.station)
        .await
        .unwrap();
    assert_eq!(readers.len(), 2);
    assert!(readers.contains(&(pair.founder.clone(), commits[1].clone())));
    assert!(readers.contains(&(pair.peer.clone(), commits[2].clone())));
    for account in [&pair.founder, &pair.peer] {
        let page = exact_genesis_scan(&store, &realm, account, &pair.station).await;
        let floor = page.readable_floor.unwrap();
        assert_eq!(floor.oldest_position, 0);
        assert_eq!(floor.floor_commit_id, commits[0].commit_id);
        assert_eq!(
            floor.floor_reason,
            arkret_wire::ReadableFloorReason::StreamStart
        );
        assert_eq!(
            page.committed_events,
            vec![arkret_wire::CommittedEventView::Full(
                arkret_wire::CommittedEventFullView {
                    event: unit.transactions[0].event.clone(),
                    commit: commits[0].clone(),
                }
            )]
        );
    }
    // Bootstrap must retain the exact canonical disclosure of both founding
    // members. The old join-position override changes the original snapshot
    // even though every current row and stream head is already complete.
    for (account, join) in [(&pair.founder, &commits[1]), (&pair.peer, &commits[2])] {
        let canonical = coland_storage_postgres::account_snapshot_material(&pool, &realm, account)
            .await
            .unwrap()
            .unwrap();
        let bootstrap = store
            .member_station_bootstrap_material(&realm, account, &join.commit_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(bootstrap, canonical);
        assert_eq!(
            store
                .member_station_bootstrap_floor(&realm, account, &join.commit_id)
                .await
                .unwrap(),
            Some(0)
        );
        let key = ed25519_dalek::SigningKey::from_bytes(&[0x42; 32]);
        let method = DidUrl::new(format!("{}#authority", pair.station_did)).unwrap();
        let snapshot = coland_services::authority_commit::build_signed_realm_state_snapshot(
            &bootstrap, method, &key, at,
        )
        .unwrap();
        assert!(coland_storage::signed_snapshot_matches_material(
            &snapshot, &canonical
        ));
        let mut old_bootstrap = bootstrap.clone();
        old_bootstrap.retention_and_history_floor.stream_floors[0].oldest_position =
            join.stream_position;
        assert!(!coland_storage::signed_snapshot_matches_material(
            &snapshot,
            &old_bootstrap
        ));
        assert_eq!(
            store
                .member_station_bootstrap_floor(&realm, account, &commits[3].commit_id)
                .await
                .unwrap(),
            None
        );
    }
    // A stored slot is not enough if its genesis differs from the real held
    // stream start. It must not grant an unrelated join history before itself.
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query(
        "UPDATE direct_conversation_founding_slots \
         SET commits_json=jsonb_set(commits_json,'{0,commit_id}',to_jsonb($2::text)) \
         WHERE realm_id=$1",
    )
    .bind::<Text, _>(realm.as_str())
    .bind::<Text, _>(commits[3].commit_id.as_str())
    .execute(&mut *conn)
    .await
    .unwrap();
    drop(conn);
    assert!(
        store
            .replica_bootstrap_readers(&stream, &pair.station)
            .await
            .is_err()
    );
    for account in [&pair.founder, &pair.peer] {
        let page = exact_genesis_scan(&store, &realm, account, &pair.station).await;
        assert!(page.committed_events.is_empty());
        let floor = page.readable_floor.unwrap();
        let join = if account == &pair.founder {
            &commits[1]
        } else {
            &commits[2]
        };
        assert_eq!(
            store
                .member_station_bootstrap_floor(&realm, account, &join.commit_id)
                .await
                .unwrap(),
            Some(join.stream_position)
        );
        let bootstrap = store
            .member_station_bootstrap_material(&realm, account, &join.commit_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            bootstrap.retention_and_history_floor.stream_floors[0].oldest_position,
            join.stream_position
        );
        assert_eq!(floor.oldest_position, join.stream_position);
        assert_eq!(floor.floor_commit_id, join.commit_id);
        assert_eq!(
            floor.floor_reason,
            arkret_wire::ReadableFloorReason::MembershipJoin
        );
    }
    // Matching genesis/join coordinates are still insufficient when any one
    // of the four slot Commits is not the actual held atomic prefix.
    let mut incomplete = commits.clone();
    incomplete[3].commit_id = arkret_wire::RealmCommitId::from_digest([99; 32]);
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query(
        "UPDATE direct_conversation_founding_slots SET commits_json=$2 WHERE realm_id=$1",
    )
    .bind::<Text, _>(realm.as_str())
    .bind::<diesel::sql_types::Jsonb, _>(serde_json::to_value(incomplete).unwrap())
    .execute(&mut *conn)
    .await
    .unwrap();
    drop(conn);
    let page = exact_genesis_scan(&store, &realm, &pair.founder, &pair.station).await;
    assert!(
        store
            .replica_bootstrap_readers(&stream, &pair.station)
            .await
            .is_err()
    );
    assert!(page.committed_events.is_empty());
    let floor = page.readable_floor.unwrap();
    assert_eq!(
        store
            .member_station_bootstrap_floor(&realm, &pair.founder, &commits[1].commit_id)
            .await
            .unwrap(),
        Some(commits[1].stream_position)
    );
    assert_eq!(floor.oldest_position, commits[1].stream_position);
    assert_eq!(floor.floor_commit_id, commits[1].commit_id);
    assert_eq!(
        floor.floor_reason,
        arkret_wire::ReadableFloorReason::MembershipJoin
    );
}

#[tokio::test]
async fn direct_participation_inherits_accepted_fixed_baseline_without_a_policy_event() {
    use coland_storage::AgentParticipationStore;
    use coland_storage_postgres::PgAgentParticipationStore;

    let (_database, pool) = contract_pool().await;
    let pair = pair(&pool).await;
    let unit = founding_unit(&pair, &UnitShape::exact(&pair), key(), now()).await;
    let realm = realm_of(&unit);
    let strand = unit.facts().unwrap().main_strand_id;
    assert!(matches!(
        pair.store()
            .admit_self_direct_conversation_founding_unit(&unit, &pair.guards(), now())
            .await
            .unwrap(),
        DirectConversationFoundingCommitOutcome::Committed(_)
    ));
    assert_eq!(
        count(
            &pool,
            "SELECT COUNT(*) AS count FROM realm_policy_bundle_current_results WHERE realm_id=$1",
            &realm
        )
        .await,
        0
    );
    let participation = PgAgentParticipationStore { pool: pool.clone() };
    let scopes = vec![format!("realm:{realm}"), format!("strand:{realm}:{strand}")];
    let rows = participation
        .ceilings_for_scope_keys(&scopes)
        .await
        .unwrap();
    assert_eq!(rows.len(), 2);
    for (row, scope) in rows.iter().zip(&scopes) {
        assert_eq!(row["scope_key"], *scope);
        assert_eq!(row["reply_message"], true);
    }
    // A profile label or a slot cannot substitute for a covering current
    // Commit. Corrupting that coordinate must make the same read unresolved.
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query("UPDATE realm_bootstrap_current_results SET current_stream_position=current_stream_position+1 WHERE realm_id=$1 AND result_family='realm_genesis'")
        .bind::<Text,_>(realm.as_str()).execute(&mut *conn).await.unwrap();
    assert!(
        participation
            .ceilings_for_scope_keys(&scopes)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn founding_unit_commits_four_consecutive_commits_and_exact_retry_replays_them() {
    let (_database, pool) = contract_pool().await;
    let pair = pair(&pool).await;
    let store = pair.store();
    let idempotency_key = key();
    let shape = UnitShape::exact(&pair);
    let at = now();
    let unit = founding_unit(&pair, &shape, idempotency_key, at).await;
    let facts = unit.facts().unwrap();
    let realm_id = realm_of(&unit);

    let DirectConversationFoundingCommitOutcome::Committed(commits) = store
        .admit_self_direct_conversation_founding_unit(&unit, &pair.guards(), at)
        .await
        .unwrap()
    else {
        panic!("the first founding unit commits");
    };
    for transaction in &unit.transactions {
        let SelfProducerCommitGuard::HumanDevice(guard) = &pair.founder_guard else {
            unreachable!()
        };
        let selector = arkret_models_identity::SignerKeyQuerySelector::HistoricalEvent {
            sender: arkret_models_identity::HistoricalSignerKeyQuerySender::AccountDevice {
                actor: pair.founder_actor(),
                device_id: arkret_wire::DeviceId::new(guard.device_id.clone()).unwrap(),
                verification_method: pair.founder_method.clone(),
                committed_event_ref: arkret_wire::CommittedEventRef {
                    event_id: transaction.event.event_id.clone(),
                    commit_id: transaction.commit.commit_id.clone(),
                    stream_ref: transaction.commit.stream_ref.clone(),
                    stream_position: transaction.commit.stream_position,
                },
            },
        };
        let frozen = store
            .historical_producer_signer_key(&realm_id, &selector)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(frozen.selector(), &selector);
        assert_eq!(
            frozen.key().unwrap().authorization_ref,
            guard.authorization_ref
        );
        assert_ne!(
            frozen
                .key()
                .unwrap()
                .authorization_ref
                .stream_ref
                .realm_id(),
            &realm_id
        );
        let authorization = store
            .committed_event(&guard.authorization_ref.event_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            frozen.accepted_at(),
            Some(authorization.commit.committed_at)
        );
    }
    for (position, commit) in commits.iter().enumerate() {
        assert_eq!(commit.stream_position, position as u64);
        assert_eq!(commit.event_ref, unit.transactions[position].event.event_id);
        assert_eq!(
            commit.previous_commit_ref.as_ref(),
            position
                .checked_sub(1)
                .map(|previous| &commits[previous].commit_id)
        );
        let accepted = store
            .committed_event(&commit.event_ref)
            .await
            .unwrap()
            .expect("every founding Event is committed");
        assert_eq!(accepted.commit, *commit);
    }
    assert_eq!(footprint(&pool, &realm_id).await, [1, 4, 4, 1, 2]);
    assert_eq!(facts.realm_id, realm_id);
    // Both joins belong to the same accepted unit as position zero. The
    // caller scan and snapshot must agree on that original stream-start floor.
    let request = arkret_wire::StreamScanRequest {
        realm_id: realm_id.clone(),
        stream_ref: arkret_wire::CommitStreamRef::Realm {
            realm_id: realm_id.clone(),
        },
        direction: arkret_wire::StreamScanDirection::After(None),
        limit: 4,
    };
    for account in [&pair.founder, &pair.peer] {
        let coland_storage::AccountStreamScan::Page(page) = store
            .scan_stream_for_account(&request, account, &pair.station)
            .await
            .unwrap()
        else {
            panic!("founding member must read its accepted unit");
        };
        assert_eq!(
            page.readable_floor,
            Some(arkret_wire::ReadableFloor {
                oldest_position: 0,
                floor_commit_id: commits[0].commit_id.clone(),
                floor_reason: arkret_wire::ReadableFloorReason::StreamStart,
            })
        );
        assert_eq!(page.committed_events.len(), 4);
        for (position, row) in page.committed_events.iter().enumerate() {
            assert_eq!(row.commit(), &commits[position]);
            assert_eq!(
                row.reducer_input(),
                Some(&unit.transactions[position].event)
            );
        }
        let snapshot =
            coland_storage_postgres::account_snapshot_material(&pool, &realm_id, account)
                .await
                .unwrap()
                .expect("founding member snapshot");
        assert_eq!(
            snapshot.retention_and_history_floor.stream_floors,
            vec![arkret_wire::StreamHistoryFloor {
                stream_ref: request.stream_ref.clone(),
                oldest_position: 0,
            }]
        );
    }
    assert_eq!(
        count(
            &pool,
            "SELECT COUNT(*) AS count FROM strand_current_results WHERE realm_id=$1",
            &realm_id,
        )
        .await,
        1,
        "the main Strand current is written with the unit"
    );
    assert_eq!(
        count(
            &pool,
            "SELECT COUNT(*) AS count FROM realm_bootstrap_current_results \
             WHERE realm_id=$1 AND result_family='realm_genesis'",
            &realm_id,
        )
        .await,
        1
    );

    // Sections 5.5 and 9.1.1: the self carrier takes neither the founding
    // evidence nor any founding receipt or coordinate, and the outcome
    // carries no receipt.
    let carrier = serde_json::to_value(
        arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequest::DirectConversationFounding(
            unit.submission.clone(),
        ),
    )
    .unwrap();
    serde_json::from_value::<
        arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequest,
    >(carrier.clone())
    .expect("the exact carrier parses");
    for (member, value) in [
        (
            "founding_authority_evidence",
            serde_json::json!({"kind":"human"}),
        ),
        ("receipt", serde_json::json!({})),
        ("source_acceptance_receipt", serde_json::json!({})),
        ("realm_id", serde_json::to_value(&realm_id).unwrap()),
    ] {
        let mut injected = carrier.clone();
        injected[member] = value;
        assert!(
            serde_json::from_value::<
                arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequest,
            >(injected)
            .is_err(),
            "{member} is not a member of the self founding carrier"
        );
    }
    let mut outcome = serde_json::to_value(
        arkret_models_collaboration::authority_commit::DirectConversationFoundingAcceptanceOutcome {
            unit_kind: DirectConversationFoundingUnitKind::DirectConversationFounding,
            status: arkret_models_collaboration::authority_commit::AggregateAcceptanceStatus::Committed,
            commits: commits.clone(),
        },
    )
    .unwrap();
    outcome["receipt"] = serde_json::json!({});
    assert!(
        serde_json::from_value::<
            arkret_models_collaboration::authority_commit::DirectConversationFoundingAcceptanceOutcome,
        >(outcome)
        .is_err()
    );

    // An exact retry re-signed later still answers with the original four
    // byte-identical Commits; the fourth committed_at never moves.
    let later = at + chrono::Duration::seconds(5);
    let mut retry = unit.clone();
    for transaction in &mut retry.transactions {
        transaction.commit.committed_at = later;
        transaction.commit.signature = ordinary_realm::signature(&pair.station, later);
    }
    assert_eq!(retry.facts().unwrap(), facts);
    let DirectConversationFoundingCommitOutcome::Duplicate(replayed) = store
        .admit_self_direct_conversation_founding_unit(&retry, &pair.guards(), later)
        .await
        .unwrap()
    else {
        panic!("an exact retry is a duplicate");
    };
    assert_eq!(
        serde_json::to_vec(&replayed).unwrap(),
        serde_json::to_vec(&commits).unwrap()
    );
    assert_eq!(replayed[3].committed_at, at);

    // The same key with another unit is a duplicate conflict; another key with
    // another unit for the same pair finds the founder's slot closed.
    let other = UnitShape {
        salt: salt(),
        ..shape.clone()
    };
    let conflicting = founding_unit(&pair, &other, idempotency_key, later).await;
    assert_eq!(
        refusal_code(
            store
                .admit_self_direct_conversation_founding_unit(&conflicting, &pair.guards(), later)
                .await
        ),
        ConflictCode::DuplicateConflict
    );
    assert_eq!(footprint(&pool, &realm_of(&conflicting)).await, [0; 5]);
    let second = founding_unit(&pair, &other, key(), later).await;
    assert_eq!(
        refusal_code(
            store
                .admit_self_direct_conversation_founding_unit(&second, &pair.guards(), later)
                .await
        ),
        ConflictCode::DirectConversationSlotAlreadyCommitted
    );
    assert_eq!(footprint(&pool, &realm_of(&second)).await, [0; 5]);
    assert_eq!(footprint(&pool, &realm_id).await, [1, 4, 4, 1, 2]);
}

#[tokio::test]
async fn committed_direct_conversation_founding_rebuilds_resolver_projection_after_restart() {
    let (_database, pool) = contract_pool().await;
    let pair = pair(&pool).await;
    let at = now();
    let unit = founding_unit(&pair, &UnitShape::exact(&pair), key(), at).await;
    let realm = realm_of(&unit);
    let live = coland_services::projection::ProjectionService::new("dm-live-test");
    let operations = unit
        .transactions
        .iter()
        .map(|transaction| {
            arkret_event_draft::ProjectedEventOperation::from_accepted_event(
                arkret_wire::OperationId::new(format!("ak:operation:{}", uuid::Uuid::now_v7()))
                    .unwrap(),
                arkret_wire::OperationKind::Create,
                None,
                &transaction.event,
                arkret_canonical::DigestSuite::Sha256,
            )
            .unwrap()
        })
        .collect::<Vec<_>>();
    let staged = live.stage_realm_bootstrap(&operations, true).unwrap();
    pair.store()
        .admit_self_direct_conversation_founding_unit(&unit, &pair.guards(), at)
        .await
        .unwrap();
    let strand = arkret_wire::StrandId::from_event_id(&unit.transactions[3].event.event_id);
    live.install_staged_realm_bootstrap(staged).unwrap();
    assert!(
        !live
            .snapshot()
            .realm_ordinary_writes_blocked(realm.as_str())
    );
    assert!(
        live.snapshot()
            .member(realm.as_str(), &pair.peer_actor().to_string())
            .is_some()
    );
    for _ in 0..2 {
        let projection = coland_services::projection::ProjectionService::new("dm-restart-test");
        let persistence = PgPersistenceStore::new(pool.clone());
        projection
            .hydrate_from_persistence(&persistence, &CanonicalHydrationAdapter, [realm.clone()])
            .await
            .unwrap();
        let state = projection.snapshot();
        assert!(!state.realm_ordinary_writes_blocked(realm.as_str()));
        assert!(
            state
                .member(realm.as_str(), &pair.founder_actor().to_string())
                .is_some()
        );
        assert!(
            state
                .member(realm.as_str(), &pair.peer_actor().to_string())
                .is_some()
        );
        assert!(state.strands.contains_key(strand.as_str()));
    }
}

#[tokio::test]
async fn cross_station_founding_commits_one_exact_peer_delivery_atomically() {
    let (_database, pool) = contract_pool().await;
    let mut pair = pair(&pool).await;
    let remote_station = DidCoreId::new(format!(
        "ak:did_core:web:dc-remote-{}.example",
        uuid::Uuid::now_v7().simple()
    ))
    .unwrap();
    pair.peer = AccountId::new(pair.peer.principal_id.clone(), remote_station.clone());
    pair.contact_round_id = accept_contact(&pool, &pair.peer, &pair.founder, "accepted").await;
    let at = now();
    let unit = founding_unit(&pair, &UnitShape::exact(&pair), key(), at).await;
    let commits = match pair
        .store()
        .admit_self_direct_conversation_founding_unit(&unit, &pair.guards(), at)
        .await
        .unwrap()
    {
        DirectConversationFoundingCommitOutcome::Committed(commits) => commits,
        _ => panic!("the cross-Station founding unit must commit once"),
    };
    let mut conn = pool.get().await.unwrap();
    let rows = diesel::sql_query(
        "SELECT peer_id,payload_json FROM federation_outbox WHERE idempotency_key=$1",
    )
    .bind::<Text, _>(format!(
        "direct-conversation-founding:{}",
        unit.facts().unwrap().founding_unit_digest
    ))
    .load::<DeliveryRow>(&mut *conn)
    .await
    .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].peer_id, remote_station.as_str());
    let request: arkret_models_collaboration::authority_commit::PeerAuthoritySubmitRequest =
        serde_json::from_str(&rows[0].payload_json).unwrap();
    let arkret_models_collaboration::authority_commit::PeerAuthoritySubmitRequest::RegisteredAtomicUnit(
        request,
    ) = request
    else {
        panic!("the delivery must use registered_atomic_unit");
    };
    let arkret_models_collaboration::authority_commit::PeerRegisteredAtomicUnit::DirectConversationFounding(
        delivered,
    ) = request.unit
    else {
        panic!("the delivery must carry the founding unit");
    };
    for (index, item) in delivered.committed_events.iter().enumerate() {
        assert_eq!(item.event_submission, unit.submission.events[index]);
        assert_eq!(item.source_commit, commits[index]);
    }
    assert_eq!(footprint(&pool, &realm_of(&unit)).await, [1, 4, 4, 1, 2]);
}

#[tokio::test]
async fn peer_founding_missing_contact_dependency_writes_nothing() {
    let (_source_database, source_pool) = contract_pool().await;
    let mut pair = pair(&source_pool).await;
    let peer_station = DidCoreId::new(format!(
        "ak:did_core:web:dc-missing-peer-{}.example",
        uuid::Uuid::now_v7().simple()
    ))
    .unwrap();
    pair.peer = AccountId::new(pair.peer.principal_id.clone(), peer_station.clone());
    pair.contact_round_id =
        accept_contact(&source_pool, &pair.peer, &pair.founder, "accepted").await;
    let at = now();
    let unit = founding_unit(&pair, &UnitShape::exact(&pair), key(), at).await;
    pair.store()
        .admit_self_direct_conversation_founding_unit(&unit, &pair.guards(), at)
        .await
        .expect("source founding");
    let mut conn = source_pool.get().await.unwrap();
    let row = diesel::sql_query(
        "SELECT peer_id,payload_json FROM federation_outbox WHERE idempotency_key=$1",
    )
    .bind::<Text, _>(format!(
        "direct-conversation-founding:{}",
        unit.facts().unwrap().founding_unit_digest
    ))
    .get_result::<DeliveryRow>(&mut *conn)
    .await
    .unwrap();
    assert_eq!(row.peer_id, peer_station.as_str());
    let submission: arkret_models_collaboration::authority_commit::PeerAuthoritySubmitRequest =
        serde_json::from_str(&row.payload_json).unwrap();
    let arkret_models_collaboration::authority_commit::PeerAuthoritySubmitRequest::RegisteredAtomicUnit(request) = submission else {
        panic!("expected registered_atomic_unit");
    };
    let arkret_models_collaboration::authority_commit::PeerRegisteredAtomicUnit::DirectConversationFounding(delivered) = request.unit else {
        panic!("expected direct_conversation_founding");
    };

    // A separate Station database has none of the Contact round required by
    // this unit. Its refusal cannot persist one, two or three source Commits.
    let peer_database = TestDatabase::lease().await;
    let peer_pool = peer_database.pool();
    let peer_store = PgAuthorityCommitStore {
        pool: peer_pool.clone(),
    };
    let realm_id = realm_of(&unit);
    let refuse = || {
        peer_store.materialize_peer_direct_conversation_founding_unit(
            &unit,
            &delivered.founding_authority_evidence,
            &peer_station,
            at,
        )
    };
    assert_eq!(
        refusal_code(refuse().await),
        ConflictCode::DependencyMissing
    );
    assert_eq!(footprint(&peer_pool, &realm_id).await, [0; 5]);
    for table in [
        "replica_authorization_cuts",
        "replica_authorization_rows",
        "replica_stream_anchors",
    ] {
        assert_eq!(
            count(
                &peer_pool,
                &format!("SELECT COUNT(*) AS count FROM {table} WHERE realm_id=$1"),
                &realm_id,
            )
            .await,
            0,
        );
    }
    assert_eq!(
        refusal_code(refuse().await),
        ConflictCode::DependencyMissing
    );
    assert_eq!(footprint(&peer_pool, &realm_id).await, [0; 5]);
    for table in [
        "replica_authorization_cuts",
        "replica_authorization_rows",
        "replica_stream_anchors",
    ] {
        assert_eq!(
            count(
                &peer_pool,
                &format!("SELECT COUNT(*) AS count FROM {table} WHERE realm_id=$1"),
                &realm_id,
            )
            .await,
            0,
        );
    }

    // Install the same accepted Contact evidence on the peer after the
    // dependency refusal. The peer must now materialize exact source facts
    // while the founder's seven-stage profile admission is armed to fail.
    let source_contact = PgContactStore {
        pool: source_pool.clone(),
    }
    .get(&pair.peer_actor(), &pair.founder_actor())
    .await
    .unwrap()
    .expect("source accepted Contact");
    PgContactStore {
        pool: peer_pool.clone(),
    }
    .put(&source_contact)
    .await
    .unwrap();
    let profile_spy = FoundingProfileAdmissionSpy::watch(&realm_id);
    assert_eq!(
        refuse().await.unwrap(),
        arkret_models_collaboration::authority_commit::AggregateAcceptanceStatus::Committed,
    );
    assert_eq!(
        profile_spy.hits(),
        0,
        "peer materialization invoked founder profile admission"
    );
    assert_eq!(footprint(&peer_pool, &realm_id).await, [1, 4, 4, 1, 2]);

    let peer_genesis = exact_genesis_scan(&peer_store, &realm_id, &pair.peer, &peer_station).await;
    assert_eq!(
        peer_genesis
            .readable_floor
            .as_ref()
            .unwrap()
            .oldest_position,
        0
    );
    assert_eq!(
        peer_genesis.committed_events,
        vec![arkret_wire::CommittedEventView::Full(
            arkret_wire::CommittedEventFullView {
                event: unit.transactions[0].event.clone(),
                commit: unit.transactions[0].commit.clone(),
            }
        )]
    );

    // A control call to the founder path with the same Realm proves that the
    // tripwire was active during peer materialization.
    let self_attempt = peer_store
        .admit_self_direct_conversation_founding_unit(&unit, &pair.guards(), at)
        .await;
    assert!(
        matches!(self_attempt, Err(PersistenceError::Internal(ref detail))
        if detail == "test-only founder profile admission spy tripped")
    );
    assert_eq!(profile_spy.hits(), 1);
    assert_eq!(footprint(&peer_pool, &realm_id).await, [1, 4, 4, 1, 2]);
    let request = arkret_wire::StreamScanRequest {
        realm_id: realm_id.clone(),
        stream_ref: arkret_wire::CommitStreamRef::Realm {
            realm_id: realm_id.clone(),
        },
        direction: arkret_wire::StreamScanDirection::After(None),
        limit: 4,
    };
    let coland_storage::AccountStreamScan::Page(page) = peer_store
        .scan_stream_for_account(&request, &pair.peer, &peer_station)
        .await
        .unwrap()
    else {
        panic!("hosted founding peer must read the held unit");
    };
    let floor = page.readable_floor.expect("peer founding floor");
    assert_eq!(floor.oldest_position, 0);
    assert_eq!(
        floor.floor_reason,
        arkret_wire::ReadableFloorReason::StreamStart
    );
    assert_eq!(floor.floor_commit_id, unit.transactions[0].commit.commit_id);
    assert_eq!(page.committed_events.len(), 4);
    for (row, transaction) in page.committed_events.iter().zip(&unit.transactions) {
        assert_eq!(row.commit(), &transaction.commit);
        assert_eq!(row.reducer_input(), Some(&transaction.event));
    }
    // The exact GET and historical signer query must share the proven unit
    // floor: the foreign founder's join at 1 precedes this member's join at 2.
    let founder_join = &unit.transactions[1];
    assert_eq!(founder_join.commit.stream_position, 1);
    assert_eq!(unit.transactions[2].commit.stream_position, 2);
    assert!(founder_join.commit.stream_position < unit.transactions[2].commit.stream_position);
    let coland_storage::MemberCommittedEventRead::Read(view) = peer_store
        .committed_event_for_member(
            &founder_join.event.event_id,
            &pair.peer_actor(),
            &peer_station,
        )
        .await
        .unwrap()
    else {
        panic!("the founding peer must hold the exact foreign founder join below its own join");
    };
    let arkret_wire::CommittedEventView::Full(exact_founder_join) = *view else {
        panic!("the founding peer must hold full disclosure of the foreign founder join");
    };
    assert_eq!(exact_founder_join.event, founder_join.event);
    assert_eq!(exact_founder_join.commit, founder_join.commit);
    let human = founder_join.event.human_device_producer().unwrap().unwrap();
    let historical_selector = arkret_models_identity::SignerKeyQuerySelector::HistoricalEvent {
        sender: arkret_models_identity::HistoricalSignerKeyQuerySender::AccountDevice {
            actor: founder_join.event.actual_signer().clone(),
            device_id: human.device_id,
            verification_method: founder_join
                .event
                .producer_proof
                .as_ref()
                .unwrap()
                .verification_method
                .clone(),
            committed_event_ref: arkret_wire::CommittedEventRef {
                event_id: founder_join.event.event_id.clone(),
                commit_id: founder_join.commit.commit_id.clone(),
                stream_ref: founder_join.commit.stream_ref.clone(),
                stream_position: founder_join.commit.stream_position,
            },
        },
    };
    let historical = peer_store
        .historical_producer_signer_key(&realm_id, &historical_selector)
        .await
        .unwrap()
        .expect("the same accepted foreign founding original retains its historical signer");
    assert_eq!(historical.selector(), &historical_selector);
    assert!(matches!(
        historical,
        arkret_models_identity::SignerKeyQueryOutcome::HistoricalResolved { .. }
    ));
    historical.validate(&realm_id).unwrap();

    let snapshot =
        coland_storage_postgres::account_snapshot_material(&peer_pool, &realm_id, &pair.peer)
            .await
            .unwrap()
            .expect("hosted peer snapshot");
    assert_eq!(
        snapshot.retention_and_history_floor.stream_floors,
        vec![arkret_wire::StreamHistoryFloor {
            stream_ref: request.stream_ref,
            oldest_position: 0
        }]
    );

    let origin_bootstrap = pair
        .store()
        .member_station_bootstrap_material(
            &realm_id,
            &pair.peer,
            &unit.transactions[2].commit.commit_id,
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(origin_bootstrap, snapshot);
    assert_eq!(
        peer_store
            .replica_bootstrap_readers(
                &arkret_wire::CommitStreamRef::Realm {
                    realm_id: realm_id.clone(),
                },
                &peer_station,
            )
            .await
            .unwrap(),
        vec![(pair.peer.clone(), unit.transactions[2].commit.clone())]
    );
    assert_eq!(
        peer_store
            .member_station_bootstrap_floor(
                &realm_id,
                &pair.peer,
                &unit.transactions[2].commit.commit_id
            )
            .await
            .unwrap(),
        Some(0)
    );
    let snapshot_key = ed25519_dalek::SigningKey::from_bytes(&[0x42; 32]);
    let original = coland_services::authority_commit::build_signed_realm_state_snapshot(
        &origin_bootstrap,
        DidUrl::new(format!("{}#authority", pair.station_did)).unwrap(),
        &snapshot_key,
        at,
    )
    .unwrap();
    // Validate the original governing signature before archiving the snapshot;
    // the accepted founding unit already established the exact current cut.
    arkret_signatures::detached_object::verify_detached_object_signature(
        &original.signature,
        &arkret_canonical::unsigned_value(&original, &["signature"]).unwrap(),
        arkret_wire::DetachedSignatureContext::RealmSnapshot,
        &arkret_signatures::PublicKeyMaterial::Ed25519Raw {
            bytes: snapshot_key.verifying_key().to_bytes().to_vec(),
        },
    )
    .unwrap();
    assert_eq!(original.visible_stream_heads.len(), 1);
    assert_eq!(
        original.visible_stream_heads[0].commit_id,
        unit.transactions[3].commit.commit_id
    );
    peer_store
        .install_verified_account_snapshot(&pair.peer, &peer_station, &original)
        .await
        .unwrap();
    let archived_before = count(
        &peer_pool,
        "SELECT COUNT(*) AS count FROM realm_state_snapshots WHERE realm_id=$1",
        &realm_id,
    )
    .await;
    let mut mismatched_material = origin_bootstrap.clone();
    mismatched_material
        .retention_and_history_floor
        .stream_floors[0]
        .oldest_position = 1;
    let changed = coland_services::authority_commit::build_signed_realm_state_snapshot(
        &mismatched_material,
        DidUrl::new(format!("{}#authority", pair.station_did)).unwrap(),
        &snapshot_key,
        at,
    )
    .unwrap();
    assert!(!coland_storage::signed_snapshot_matches_material(
        &changed, &snapshot
    ));
    assert!(
        peer_store
            .install_verified_account_snapshot(&pair.peer, &peer_station, &changed)
            .await
            .is_err()
    );
    assert_eq!(
        count(
            &peer_pool,
            "SELECT COUNT(*) AS count FROM realm_state_snapshots WHERE realm_id=$1",
            &realm_id,
        )
        .await,
        archived_before
    );

    // A retained founding slot cannot invent a missing physical Genesis.
    // The anchored foreign reader keeps its exact held join interval instead.
    let mut conn = peer_pool.get().await.unwrap();
    // Fault injection removes the exact immutable dependent archive first;
    // the production FK remains strict and no sibling source is touched.
    diesel::sql_query("DELETE FROM agent_producer_signer_keys WHERE commit_id=$1")
        .bind::<Text, _>(unit.transactions[0].commit.commit_id.as_str())
        .execute(&mut *conn)
        .await
        .unwrap();
    assert_eq!(
        diesel::sql_query("DELETE FROM realm_commits WHERE realm_id=$1 AND stream_position=0")
            .bind::<Text, _>(realm_id.as_str())
            .execute(&mut *conn)
            .await
            .unwrap(),
        1
    );
    drop(conn);
    let without_genesis =
        exact_genesis_scan(&peer_store, &realm_id, &pair.peer, &peer_station).await;
    assert!(without_genesis.committed_events.is_empty());
    let floor = without_genesis.readable_floor.unwrap();
    assert_eq!(
        floor.oldest_position,
        unit.transactions[2].commit.stream_position
    );
    assert_eq!(floor.floor_commit_id, unit.transactions[2].commit.commit_id);
    assert_eq!(
        floor.floor_reason,
        arkret_wire::ReadableFloorReason::MembershipJoin
    );
    // Missing the actual genesis invalidates the atomic floor exception; a
    // retained slot or historical fact alone must not disclose position 1.
    assert!(matches!(
        peer_store
            .committed_event_for_member(
                &founder_join.event.event_id,
                &pair.peer_actor(),
                &peer_station
            )
            .await
            .unwrap(),
        coland_storage::MemberCommittedEventRead::NotVisible
    ));
}

#[tokio::test]
async fn founding_refusals_decide_authority_at_the_slot_cut_with_zero_writes() {
    let (_database, pool) = contract_pool().await;
    let pair = pair(&pool).await;
    let store = pair.store();
    let at = now();
    let refuse = async |shape: UnitShape| {
        let unit = founding_unit(&pair, &shape, key(), at).await;
        let code = refusal_code(
            store
                .admit_self_direct_conversation_founding_unit(&unit, &pair.guards(), at)
                .await,
        );
        assert_eq!(footprint(&pool, &realm_of(&unit)).await, [0; 5]);
        code
    };

    // The requester of the normal round is not its founder.
    assert_eq!(
        refuse(UnitShape {
            author: pair.peer_actor(),
            other: pair.founder_actor(),
            ..UnitShape::exact(&pair)
        })
        .await,
        ConflictCode::CapabilityDenied
    );
    // Material from another round is stale at the founding cut.
    assert_eq!(
        refuse(UnitShape {
            authority_ref: arkret_wire::SemanticRef::new(
                fixture_hash('9').to_string(),
                "direct_conversation_contact_round",
            ),
            ..UnitShape::exact(&pair)
        })
        .await,
        ConflictCode::FailedPrecondition
    );
    // No accepted provision is readable for the controller-Agent branch.
    assert_eq!(
        refuse(UnitShape {
            authority_ref: arkret_wire::SemanticRef::new(
                unique_event_id("agent-provision").to_string(),
                "direct_conversation_agent_provision",
            ),
            ..UnitShape::exact(&pair)
        })
        .await,
        ConflictCode::FailedPrecondition
    );
    // The fixed baseline is create-locked: closed, invite_only, since_join.
    assert_eq!(
        refuse(UnitShape {
            join_rule: "invite",
            ..UnitShape::exact(&pair)
        })
        .await,
        ConflictCode::DirectConversationFoundingUnitInvalid
    );
    assert_eq!(
        refuse(UnitShape {
            discoverability: "unlisted",
            ..UnitShape::exact(&pair)
        })
        .await,
        ConflictCode::DirectConversationFoundingUnitInvalid
    );
    // A pair whose Contact is not accepted has no founding authority.
    let stranger = AccountId::new(
        DidCoreId::new(format!(
            "ak:did_core:web:dc-pending-{}.example",
            uuid::Uuid::now_v7().simple()
        ))
        .unwrap(),
        pair.station.clone(),
    );
    let pending_round = accept_contact(&pool, &stranger, &pair.founder, "pending").await;
    assert_eq!(
        refuse(UnitShape {
            other: ActorId::account(stranger),
            authority_ref: arkret_wire::SemanticRef::new(
                pending_round.to_string(),
                "direct_conversation_contact_round",
            ),
            ..UnitShape::exact(&pair)
        })
        .await,
        ConflictCode::FailedPrecondition
    );

    // The exact unit is still admissible afterwards: no refusal left a slot.
    let unit = founding_unit(&pair, &UnitShape::exact(&pair), key(), at).await;
    assert!(matches!(
        store
            .admit_self_direct_conversation_founding_unit(&unit, &pair.guards(), at)
            .await
            .unwrap(),
        DirectConversationFoundingCommitOutcome::Committed(_)
    ));
}

#[tokio::test]
async fn controller_owned_agent_founding_reads_provision_and_runtime_key_at_the_slot_cut() {
    use coland_storage::{
        ActorProfileStore, AgentControlAdmissionOutcome, AgentControlAdmissionWrite,
        AgentPcrGenesisAdmissionWrite, AgentProvisionAdmissionWrite,
    };

    let database = coland_storage_postgres::test_database::TestDatabase::lease().await;
    let pool = database.pool();
    let historical_station = historical_control_source::HistoricalControlStation::new(
        "direct-agent-controller",
        [83; 32],
    );
    let station = historical_station.core.clone();
    let station_did = historical_station.did.clone();
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query("INSERT INTO device_inventory_station(singleton,station_id) VALUES(TRUE,$1)")
        .bind::<Text, _>(station.as_str())
        .execute(&mut conn)
        .await
        .unwrap();
    drop(conn);
    let controller_fixture = pcr_genesis::PcrGenesisFixture::new(station_did.clone());
    let selector = controller_fixture
        .admit_founding_device(&PgPersistenceStore::new(pool.clone()))
        .await
        .unwrap();
    let controller = controller_fixture.history.account.clone();
    historical_control_source::register_device(
        &controller,
        &controller_fixture.history.founding_device_id,
        &controller_fixture.history.events[1].event_id,
    );
    let controller_realm = controller_fixture.unit.transactions[0]
        .commit
        .realm_id
        .clone();
    let controller_head = controller_fixture.unit.transactions[1].commit.clone();
    let controller_authority = controller_fixture.unit.transactions[1]
        .expected_authority
        .clone();
    let controller_method = controller_fixture
        .history
        .device_verification_method
        .clone();
    let controller_seed = controller_fixture.history.founding_device_signing_seed;
    let profiles = coland_storage_postgres::PgActorProfileStore { pool: pool.clone() };
    let store = PgAuthorityCommitStore { pool: pool.clone() };

    let agent_did = historical_control_source::managed_agent_did(
        &controller.principal_id,
        "direct-owned-agent",
        controller_head.committed_at,
    );
    let agent_id = arkret_wire::project_did_to_core_id(&agent_did).unwrap();
    let agent = AccountId::new(agent_id.clone(), station.clone());
    let delegation = format!("{agent_did}#managed-controller");
    let genesis = device_authorization_history::sign_event(
        arkret_bootstrap::build_agent_pcr_create(arkret_bootstrap::AgentPcrCreateEventInput {
            payload: arkret_bootstrap::AgentPcrCreatePayloadInput {
                agent_id: agent_id.clone(),
                governance_station_id: station.clone(),
                initial_resolution: arkret_models_identity::ResolutionCommitment {
                    did: agent_did.clone(),
                    method_history_head: format!("sha256:{}", "c".repeat(64)),
                    version_id: "1-agent".to_owned(),
                },
                genesis_salt: arkret_wire::GenesisSalt::new(
                    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
                )
                .unwrap(),
                trust_domain: arkret_wire::TrustDomainId::new(
                    "ak:trust_domain:pcr-contract.example".to_owned(),
                )
                .unwrap(),
                initial_join_rule: arkret_wire::JoinRule::Closed,
                initial_history_access: arkret_wire::HistoryAccess::SinceJoin,
                initial_discoverability: arkret_wire::Discoverability::Secret,
            },
            executed_by: ActorId::account(controller.clone()),
            authorization_ref: arkret_wire::AuthorizationRef::new(delegation.clone()).unwrap(),
            created_at: controller_head.committed_at,
        })
        .unwrap()
        .into_event(),
        controller_method.clone(),
        controller_seed,
    );
    let agent_pcr = RealmId::from_event_id(&genesis.event_id);
    let mut provision = agent_provision_event(
        &controller,
        &controller_realm,
        &controller_method,
        controller_seed,
        &agent_id,
        &agent_pcr,
        &delegation,
        controller_head.committed_at,
    );
    let mut content_scope: arkret_models_collaboration::events_payloads::agent::AgentKeyScope =
        serde_json::from_value(serde_json::json!({
            "actions":[arkret_wire::CapabilityActionId::EventRead, arkret_wire::CapabilityActionId::MessageCreate,
                arkret_wire::ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT_V1],
            "resources":[{"kind":"realm"},{"kind":"operation","operation":arkret_wire::ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT_V1}]
        })).unwrap();
    content_scope.actions =
        arkret_schema::agent_runtime_scope::complete_agent_runtime_scope(&content_scope.actions)
            .unwrap();
    provision.payload.insert(
        "requested_scope_digest".to_owned(),
        serde_json::to_value(
            arkret_models_collaboration::agent_scope::agent_requested_scope_digest(
                &agent_id,
                &controller.principal_id,
                &content_scope,
            )
            .unwrap(),
        )
        .unwrap(),
    );
    let provision = device_authorization_history::sign_event(
        provision,
        controller_method.clone(),
        controller_seed,
    );
    let provision_commit = station_successor(&controller_head, &provision, &station_did, 1);
    let transaction =
        |authority: CurrentRealmAuthority,
         event: arkret_wire::Event,
         commit: arkret_wire::RealmCommit| AuthorityCommitTransaction {
            expected_authority: authority,
            event,
            commit,
            producer_signer_fact: None,
            mls_state: None,
            welcomes: Vec::new(),
            recipient_queue_capacity: 0,
        };
    profiles
        .admit_agent_provision(AgentProvisionAdmissionWrite {
            commit: transaction(
                controller_authority,
                provision.clone(),
                provision_commit.clone(),
            ),
            queued_at: provision_commit.committed_at,
        })
        .await
        .unwrap();
    let genesis_commit = station_genesis_commit(
        &controller_head,
        &genesis,
        &station_did,
        provision_commit.committed_at + chrono::TimeDelta::seconds(1),
    );
    historical_control_source::admit_genesis(
        &profiles,
        &pool,
        AgentPcrGenesisAdmissionWrite {
            commit: transaction(
                CurrentRealmAuthority {
                    realm_id: agent_pcr.clone(),
                    generation: 0,
                    service_id: station.clone(),
                    authority_ref: genesis_commit.authority_ref.clone(),
                    last_handoff_ref: None,
                },
                genesis.clone(),
                genesis_commit.clone(),
            ),
            queued_at: genesis_commit.committed_at,
        },
    )
    .await
    .unwrap();

    // Native accepted-history supply retains the private scope separately
    // from the shared Provision's digest, as the normal provider does.
    let mut record = coland_storage::AgentPrincipalRecord::new(
        agent_id.to_string(),
        controller.principal_id.to_string(),
        agent_pcr.to_string(),
        DidUrl::new(delegation.clone()).unwrap(),
        arkret_models_collaboration::agent_operations::AgentLifecycleState::Active,
        genesis_commit.committed_at,
    );
    record.requested_scope = Some(serde_json::to_value(&content_scope).unwrap());
    record.provision_event_refs = Some(serde_json::json!({
        "provision_event_id":provision.event_id,
        "initial_resolution":genesis.payload["object"]["initial_resolution"],
    }));
    coland_storage::AgentStore::put(
        &coland_storage_postgres::PgAgentStore { pool: pool.clone() },
        record,
    )
    .await
    .unwrap();

    let pair = Pair {
        pool: pool.clone(),
        station: station.clone(),
        station_did: station_did.clone(),
        founder: controller.clone(),
        founder_method: controller_method.clone(),
        founder_signing_seed: controller_seed,
        founder_leaf_authority: founder_leaf_authority(&controller_fixture, &selector),
        founder_guard: SelfProducerCommitGuard::HumanDevice(selector),
        peer: agent.clone(),
        // Fixture signing configuration only: the no-key stage must still be
        // refused until the real Agent key-authorize is accepted below.
        peer_method: DidUrl::new(format!("{agent_did}#runtime-1")).unwrap(),
        peer_signing_seed: [0x61; 32],
        peer_guard: None,
        contact_round_id: fixture_hash('a'),
    };
    let shape = UnitShape {
        author: ActorId::account(controller.clone()),
        other: ActorId::account(agent.clone()),
        authority_ref: arkret_wire::SemanticRef::new(
            provision.event_id.to_string(),
            "direct_conversation_agent_provision",
        ),
        ..UnitShape::exact(&pair)
    };

    // Provision and Agent PCR alone are insufficient: no current runtime key
    // means the controller binding is not live, and the whole unit writes zero.
    let no_key_at = genesis_commit.committed_at + chrono::TimeDelta::milliseconds(1);
    let no_key = founding_unit(&pair, &shape, key(), no_key_at).await;
    let no_key_result = store
        .admit_self_direct_conversation_founding_unit(&no_key, &pair.guards(), no_key_at)
        .await;
    let no_key_detail = format!("{no_key_result:?}");
    assert_eq!(
        refusal_code(no_key_result),
        ConflictCode::FailedPrecondition,
        "unexpected no-key refusal: {no_key_detail}"
    );
    assert_eq!(footprint(&pool, &realm_of(&no_key)).await, [0; 5]);

    let key_event = agent_control_event(
        &controller_method,
        controller_seed,
        &controller,
        &agent,
        &agent_pcr,
        &delegation,
        {
            let mut payload = agent_key_authorization(
                &agent_did,
                &controller.principal_id,
                genesis_commit.committed_at,
            );
            payload["agent_key_scope"] = serde_json::to_value(&content_scope).unwrap();
            payload
        },
        genesis_commit.committed_at,
    );
    let key_commit = station_successor(&genesis_commit, &key_event, &station_did, 1);
    assert!(matches!(
        historical_control_source::admit_control(
            &profiles,
            &pool,
            AgentControlAdmissionWrite {
                commit: transaction(
                    CurrentRealmAuthority {
                        realm_id: agent_pcr.clone(),
                        generation: 0,
                        service_id: station,
                        authority_ref: genesis_commit.authority_ref.clone(),
                        last_handoff_ref: None,
                    },
                    key_event.clone(),
                    key_commit.clone(),
                ),
                queued_at: key_commit.committed_at,
            }
        )
        .await
        .unwrap(),
        AgentControlAdmissionOutcome::Committed(_)
    ));

    let unit_at = key_commit.committed_at + chrono::TimeDelta::milliseconds(1);
    let unit = founding_unit(&pair, &shape, key(), unit_at).await;
    assert!(matches!(
        store
            .admit_self_direct_conversation_founding_unit(&unit, &pair.guards(), unit_at,)
            .await
            .unwrap(),
        DirectConversationFoundingCommitOutcome::Committed(_)
    ));
    assert_eq!(footprint(&pool, &realm_of(&unit)).await, [1, 4, 4, 1, 2]);

    #[derive(diesel::QueryableByName)]
    struct BasisRow {
        #[diesel(sql_type = diesel::sql_types::Jsonb)]
        authorization_basis: serde_json::Value,
    }
    let mut conn = pool.get().await.unwrap();
    let basis = diesel::sql_query(
        "SELECT authorization_basis FROM direct_conversation_founding_slots WHERE realm_id=$1",
    )
    .bind::<Text, _>(realm_of(&unit).as_str())
    .get_result::<BasisRow>(&mut *conn)
    .await
    .unwrap();
    let refs = basis.authorization_basis["event_refs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| value.as_str().unwrap())
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(basis.authorization_basis["kind"], "agent_controller");
    assert_eq!(
        refs,
        [provision.event_id.as_str(), key_event.event_id.as_str()]
            .into_iter()
            .collect()
    );
    drop(conn);
    let durable = PgEventStore {
        pool: pair.pool.clone(),
    }
    .direct_conversation_durable_state(TRUST_DOMAIN, unit.facts().unwrap().pair_key.as_str())
    .await
    .unwrap()
    .expect("accepted Agent founding is durable");
    assert_eq!(
        serde_json::to_value(durable.founding_slot.authorization_basis).unwrap(),
        basis.authorization_basis
    );

    // An owned Agent never needs a Contact round. Its provisional Message
    // and peer Add use the current controller/provision branch at the cut.
    let realm_id = realm_of(&unit);
    use coland_storage::CapabilityGrantCurrentResultStore;
    let content_request = coland_storage::AgentSessionAuthorityRequest {
        agent_account_id: agent.clone(),
        controller_account_id: controller.clone(),
        agent_key_authorization_ref: key_event.event_id.clone(),
        verification_method: pair.peer_method.clone(),
        intent_digest: fixture_hash('c'),
        requested_scope: vec![arkret_wire::CapabilityActionId::EVENT_READ.to_owned()],
        resource_scope: serde_json::from_value(
            serde_json::json!({"realm_ids":[realm_id],"strand_ids":[],"track_names":[]}),
        )
        .unwrap(),
    };
    let content_store =
        coland_storage_postgres::PgCapabilityGrantCurrentResultStore { pool: pool.clone() };
    let issued = content_store
        .agent_session_authority(&content_request, chrono::Utc::now())
        .await
        .unwrap();
    assert_eq!(issued.granted_scope, content_request.requested_scope);
    assert!(issued.capability_grant_refs.is_empty());
    assert!(
        issued.policy_refs.is_empty(),
        "independent Direct has no unrelated Realm policy"
    );
    let mut write_request = content_request.clone();
    write_request
        .requested_scope
        .push(arkret_wire::CapabilityActionId::MESSAGE_CREATE.to_owned());
    assert_eq!(
        content_store
            .agent_session_authority(&write_request, chrono::Utc::now())
            .await
            .unwrap()
            .granted_scope,
        content_request.requested_scope,
        "pending read authority must not manufacture a settled participant write source"
    );

    let founder = pair.founder_actor();
    let facts = unit.facts().unwrap();
    let create_ref = unit.transactions[0].event.event_id.clone();
    let genesis = with_group(
        cited(
            &unit.transactions[3],
            EventKind::MlsGenesis,
            founder.clone(),
            mls_genesis_payload(&pair, &realm_id, unit_at),
            Cites::Nothing,
        ),
        None,
        0,
        &[&founder],
    );
    PgEventCommitUnitOfWork::new(pool.clone())
        .commit_event(genesis.clone())
        .await
        .unwrap();
    let message = cited(
        &genesis.authority_commit,
        EventKind::MessageCreate,
        founder.clone(),
        ciphertext(
            &facts.main_strand_id,
            0,
            &genesis.authority_commit.event.event_id,
        ),
        Cites::Bootstrap(&create_ref),
    );
    let add = cited(
        &genesis.authority_commit,
        EventKind::MlsCommit,
        founder.clone(),
        mls_commit_payload(
            &realm_id,
            &genesis.authority_commit.event.event_id,
            0,
            b"add-agent",
        ),
        Cites::Bootstrap(&create_ref),
    );
    for request in [&message, &add] {
        assert_eq!(
            store
                .direct_conversation_admission(&request.authority_commit.event)
                .await
                .unwrap(),
            coland_storage::DirectConversationAdmissionCut::Passed
        );
    }
    // The same owned-Agent branch must admit encrypted Session Signals in a
    // read-only cut after exact-pair MLS and binding, without a Contact row.
    let peer = pair.peer_actor();
    let add = with_group(
        add,
        Some((&genesis.authority_commit.event.event_id, 0)),
        1,
        &[&founder, &peer],
    );
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    uow.commit_event(add.clone()).await.unwrap();
    consume_peer_welcome(&pool, &pair.station, &add, &peer).await;
    let add_ref = add.authority_commit.event.event_id.clone();
    let bound = cited(
        &add.authority_commit,
        EventKind::DirectConversationBound,
        founder.clone(),
        serde_json::json!({
            "pair_key":facts.pair_key, "unordered_participant_ids":[founder,peer],
            "realm_id":realm_id,"main_strand_id":facts.main_strand_id,
            "founding_unit_digest":facts.founding_unit_digest,
            "authorization_basis":basis.authorization_basis,
            "initial_exact_pair_group_state_ref":add_ref,
            "created_at":arkret_canonical::format_timestamp_canonical(unit_at),
        }),
        Cites::Bootstrap(&create_ref),
    );
    uow.commit_event(bound.clone()).await.unwrap();
    let signal_scope = arkret_wire::ScopeRef::Realm {
        realm_id: realm_id.clone(),
    };
    let signal_at = bound.authority_commit.commit.committed_at + chrono::TimeDelta::seconds(1);
    let signal = store
        .signal_scope_authority(coland_storage::SignalScopeAuthorityQuery {
            include_product_authority: false,
            product_agent: None,

            scope: &signal_scope,
            authority_commit_id: &bound.authority_commit.commit.commit_id,
            parent_realm_authority_commit_id: None,
            sender: &peer,
            signal_class: arkret_wire::SignalClass::Session,
            sent_at: signal_at,
            at: signal_at,
        })
        .await
        .unwrap()
        .expect("owned-Agent Signal has a complete read-only authority cut without Contact");
    assert_eq!(signal.current_mls.current_mls_commit_event_ref, add_ref);
    assert!(signal.recipient_actors.contains(&founder));
    assert!(signal.recipient_actors.contains(&peer));
    assert_eq!(
        content_store
            .agent_session_authority(&content_request, chrono::Utc::now())
            .await
            .unwrap()
            .granted_scope,
        content_request.requested_scope
    );
    let can_write = content_store
        .agent_session_authority(&write_request, chrono::Utc::now())
        .await
        .unwrap();
    assert_eq!(can_write.granted_scope, write_request.requested_scope);
    assert!(
        can_write.capability_grant_refs.is_empty(),
        "Direct writes use the registered participant profile"
    );
    // Accepted founding coordinates do not bypass a current Agent pause.
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query(
        "UPDATE agent_status_current_results SET value='\"paused\"'::jsonb WHERE agent_id=$1",
    )
    .bind::<Text, _>(agent_id.as_str())
    .execute(&mut *conn)
    .await
    .unwrap();
    drop(conn);
    assert!(
        content_store
            .agent_session_authority(&content_request, chrono::Utc::now())
            .await
            .is_err(),
        "a frozen participant source cannot bypass current Agent pause"
    );
    assert_eq!(
        store
            .direct_conversation_admission(&message.authority_commit.event)
            .await
            .unwrap(),
        coland_storage::DirectConversationAdmissionCut::Refused(
            ConflictCode::DirectConversationParticipantAuthorityDenied
        )
    );
    assert!(
        store
            .signal_scope_authority(coland_storage::SignalScopeAuthorityQuery {
                include_product_authority: false,
                product_agent: None,

                scope: &signal_scope,
                authority_commit_id: &bound.authority_commit.commit.commit_id,
                parent_realm_authority_commit_id: None,
                sender: &peer,
                signal_class: arkret_wire::SignalClass::Session,
                sent_at: signal_at,
                at: signal_at,
            })
            .await
            .unwrap()
            .is_none()
    );
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query(
        "UPDATE agent_status_current_results SET value='\"active\"'::jsonb WHERE agent_id=$1",
    )
    .bind::<Text, _>(agent_id.as_str())
    .execute(&mut *conn)
    .await
    .unwrap();
    diesel::sql_query("DELETE FROM agent_key_current_results WHERE agent_id=$1")
        .bind::<Text, _>(agent_id.as_str())
        .execute(&mut *conn)
        .await
        .unwrap();
    drop(conn);
    assert!(
        store
            .signal_scope_authority(coland_storage::SignalScopeAuthorityQuery {
                include_product_authority: false,
                product_agent: None,

                scope: &signal_scope,
                authority_commit_id: &bound.authority_commit.commit.commit_id,
                parent_realm_authority_commit_id: None,
                sender: &peer,
                signal_class: arkret_wire::SignalClass::Session,
                sent_at: signal_at,
                at: signal_at,
            })
            .await
            .unwrap()
            .is_none()
    );
}

async fn terminal_persistent_rows(pool: &coland_storage_postgres::PgPool) -> serde_json::Value {
    use diesel_async::RunQueryDsl as _;
    #[derive(diesel::QueryableByName)]
    struct Table {
        #[diesel(sql_type = diesel::sql_types::Text)]
        tablename: String,
    }
    #[derive(diesel::QueryableByName)]
    struct Rows {
        #[diesel(sql_type = diesel::sql_types::Jsonb)]
        value: serde_json::Value,
    }
    let mut conn = pool.get().await.unwrap();
    let tables = diesel::sql_query("SELECT tablename::text AS tablename FROM pg_tables WHERE schemaname='public' AND (tablename LIKE '%current_results' OR tablename IN ('canonical_events','realm_commits','realm_authorities','federation_outbox','event_federation_outbox','replica_stream_anchors','replica_authorization_rows','replica_authorization_cuts','account_summary_current','account_summary_versions','account_summary_clock','current_result_heads','current_result_versions','direct_conversation_founding_slots')) ORDER BY tablename")
        .load::<Table>(&mut *conn).await.unwrap();
    let mut snapshot = serde_json::Map::new();
    for table in tables {
        assert!(
            table
                .tablename
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
        );
        let query = format!(
            "SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text),'[]'::jsonb) AS value FROM public.{} r",
            table.tablename
        );
        let rows = diesel::sql_query(query)
            .get_result::<Rows>(&mut *conn)
            .await
            .unwrap();
        snapshot.insert(table.tablename, rows.value);
    }
    for table in [
        "canonical_events",
        "realm_commits",
        "realm_authorities",
        "federation_outbox",
        "event_federation_outbox",
        "realm_bootstrap_current_results",
        "replica_stream_anchors",
        "replica_authorization_rows",
        "replica_authorization_cuts",
        "account_summary_current",
        "account_summary_versions",
        "account_summary_clock",
    ] {
        assert!(
            snapshot.contains_key(table),
            "missing acceptance footprint table: {table}"
        );
    }
    serde_json::Value::Object(snapshot)
}

#[tokio::test]
async fn profile_admission_table_refuses_in_registered_precedence_with_zero_writes() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let pair = Box::pin(pair(&pool)).await;
    let store = pair.store();
    let at = now();
    let unit = Box::pin(founding_unit(&pair, &UnitShape::exact(&pair), key(), at)).await;
    store
        .admit_self_direct_conversation_founding_unit(&unit, &pair.guards(), at)
        .await
        .unwrap();
    let realm_id = realm_of(&unit);
    let facts = unit.facts().unwrap();
    let head = unit.transactions[3].clone();
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    // An unrelated, genuinely accepted Human device reaches the profile
    // admission gate; it has no membership in the founding pair.
    let third = Box::pin(ordinary_realm::human_profile::admit_without_profile(
        &pool,
        &pair.station,
        &format!("dc-third-{}", uuid::Uuid::now_v7().simple()),
    ))
    .await;
    let invite = |invitee: &AccountId| {
        serde_json::json!({
            "invitee_account_id":invitee,
            "introduction_evidence_digest":fixture_hash('4'),
            "expires_at":"2099-01-01T00:00:00.000Z"
        })
    };
    let refused = async |kind: EventKind, actor: &AccountId, payload: serde_json::Value| {
        let request = ordinary_realm::next_request(&head, kind, &actor.principal_id, payload, at);
        let request = Box::pin(ordinary_realm::source_request(&pool, request)).await;
        let before = store
            .realm_state_snapshot_material(&realm_id)
            .await
            .unwrap()
            .unwrap()
            .current_state_entries;
        let outbox_sql = "SELECT COUNT(*) AS count FROM event_federation_outbox o JOIN canonical_events e ON e.pk=o.event_pk WHERE e.realm_id=$1";
        let outbox_before = count(&pool, outbox_sql, &realm_id).await;
        let persistent_before = terminal_persistent_rows(&pool).await;
        let result = uow.commit_event(request.clone()).await;
        assert!(
            !result
                .as_ref()
                .unwrap_err()
                .to_string()
                .contains("realm_terminal_state")
        );
        let code = refusal_code(result);
        assert_eq!(terminal_persistent_rows(&pool).await, persistent_before);
        assert_eq!(footprint(&pool, &realm_id).await, [1, 4, 4, 1, 2]);
        assert_eq!(
            store
                .realm_state_snapshot_material(&realm_id)
                .await
                .unwrap()
                .unwrap()
                .current_state_entries,
            before
        );
        assert_eq!(count(&pool, outbox_sql, &realm_id).await, outbox_before);
        assert!(
            store
                .committed_event(&request.authority_commit.event.event_id)
                .await
                .unwrap()
                .is_none()
        );
        code
    };

    // A pair-external invite hits both the third-party and the invite guard;
    // the third-party reason wins.
    assert_eq!(
        Box::pin(refused(
            EventKind::InviteCreate,
            &pair.founder,
            invite(&third)
        ))
        .await,
        ConflictCode::DirectConversationThirdPartyMemberForbidden
    );
    assert_eq!(
        Box::pin(refused(
            EventKind::MemberState,
            &third,
            serde_json::json!({"realm_id":realm_id,"member_id":ActorId::account(third.clone()),"membership":"join"}),
        )).await,
        ConflictCode::DirectConversationThirdPartyMemberForbidden
    );
    assert_eq!(
        Box::pin(refused(
            EventKind::InviteCreate,
            &pair.founder,
            invite(&pair.peer)
        ))
        .await,
        ConflictCode::DirectConversationInviteForbidden
    );
    // Removing the peer would lean on the technical root's owner aggregate.
    assert_eq!(
        Box::pin(refused(
            EventKind::MemberState,
            &pair.founder,
            serde_json::json!({"realm_id":realm_id,"member_id":pair.peer_actor(),"membership":"ban"}),
        )).await,
        ConflictCode::DirectConversationRootMaskViolation
    );
    // The founder's provisional Message has no accepted group Genesis.
    assert_eq!(
        Box::pin(refused(
            EventKind::MessageCreate,
            &pair.founder,
            ordinary_realm::message_payload(&facts.main_strand_id, "hello"),
        ))
        .await,
        ConflictCode::DirectConversationParticipantAuthorityDenied
    );

    let evaluate = async |kind: EventKind, actor: &AccountId, payload: serde_json::Value| {
        let request = ordinary_realm::next_request(&head, kind, &actor.principal_id, payload, at);
        store
            .direct_conversation_admission(&request.authority_commit.event)
            .await
            .unwrap()
    };
    // Neither terminal action may destroy the canonical participant pair.
    for (kind, payload) in [
        (
            EventKind::RealmDestroy,
            serde_json::json!({"reason":"terminal"}),
        ),
        (
            EventKind::RealmTombstone,
            serde_json::json!({
                "successor_realm_id": "ak:realm:ASR8x2N1qyfyy6I-eob3l-FNhx4FPBTyMJrIfifkksgW",
                "reason":"terminal"
            }),
        ),
    ] {
        assert_eq!(
            Box::pin(evaluate(kind.clone(), &pair.founder, payload.clone())).await,
            DirectConversationAdmissionCut::Refused(
                ConflictCode::DirectConversationTerminalForbidden
            )
        );
        assert_eq!(
            Box::pin(refused(kind, &pair.founder, payload)).await,
            ConflictCode::DirectConversationTerminalForbidden
        );
    }
    assert_eq!(
        Box::pin(evaluate(
            EventKind::DirectConversationBound,
            &pair.peer,
            serde_json::json!({
                "pair_key":facts.pair_key,
                "unordered_participant_ids":[pair.founder_actor(), pair.peer_actor()],
                "realm_id":realm_id,
                "main_strand_id":facts.main_strand_id,
                "founding_unit_digest":facts.founding_unit_digest,
                "authorization_basis":{"kind":"accepted_contact","event_refs":[
                    unique_event_id("request"), unique_event_id("response")
                ]},
                "initial_exact_pair_group_state_ref":unique_event_id("group-state"),
                "created_at":arkret_canonical::format_timestamp_canonical(at)
            }),
        ))
        .await,
        DirectConversationAdmissionCut::Refused(ConflictCode::DirectConversationBindingInvalid)
    );

    // A participant who left still counts for the exact-two gate
    // (`contact-and-direct-conversation.md` Â§8.4): the pair-external invite
    // keeps its third-party reason.  This pre-binding Realm cannot use repair:
    // the registered repair source requires an accepted stable binding.  The
    // complete found -> leave -> rejoin path is exercised below.
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query(
        "UPDATE member_state_current_results \
         SET membership='leave', value=jsonb_set(value,'{membership}','\"leave\"') \
         WHERE realm_id=$1 AND member_id=$2",
    )
    .bind::<Text, _>(realm_id.as_str())
    .bind::<Text, _>(pair.peer_actor().to_string())
    .execute(&mut *conn)
    .await
    .unwrap();
    drop(conn);
    assert_eq!(
        Box::pin(refused(
            EventKind::InviteCreate,
            &pair.founder,
            invite(&third)
        ))
        .await,
        ConflictCode::DirectConversationThirdPartyMemberForbidden
    );
    assert_eq!(
        Box::pin(evaluate(
            EventKind::MemberState,
            &pair.peer,
            serde_json::json!({"realm_id":realm_id,"member_id":pair.peer_actor(),"membership":"join"}),
        )).await,
        DirectConversationAdmissionCut::Refused(
            ConflictCode::DirectConversationParticipantAuthorityDenied
        )
    );

    // Once the membership projection no longer resolves the exact pair, a
    // new write fails the exact-two gate before any later stage.
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query(
        "DELETE FROM member_state_current_results WHERE realm_id=$1 AND member_id=$2",
    )
    .bind::<Text, _>(realm_id.as_str())
    .bind::<Text, _>(pair.peer_actor().to_string())
    .execute(&mut *conn)
    .await
    .unwrap();
    drop(conn);
    assert_eq!(
        Box::pin(evaluate(
            EventKind::InviteCreate,
            &pair.founder,
            invite(&third)
        ))
        .await,
        DirectConversationAdmissionCut::Refused(ConflictCode::DirectConversationMemberCountInvalid)
    );
}

const PARTICIPANT_SOURCE: &str = "ak.authority.direct_conversation_participant.v1";
const BOOTSTRAP_SOURCE: &str = "ak.authority.direct_conversation_bootstrap_participant.v1";
const REPAIR_SOURCE: &str = "ak.authority.direct_conversation_repair.v1";

/// The authority source and critical ref one Direct Conversation Event cites.
enum Cites<'a> {
    Nothing,
    Bootstrap(&'a arkret_wire::EventId),
    Participant(&'a arkret_wire::EventId),
    Repair(&'a arkret_wire::EventId),
}

/// The next structural human-device Realm-stream request citing `cites`.
fn cited(
    previous: &AuthorityCommitTransaction,
    kind: EventKind,
    actor: ActorId,
    payload: serde_json::Value,
    cites: Cites<'_>,
) -> coland_storage::EventCommitRequest {
    let at = previous.commit.committed_at;
    let mut event = ordinary_realm::event_for_actor(
        kind,
        arkret_wire::ScopeRef::Realm {
            realm_id: previous.event.realm_id.clone(),
        },
        actor,
        payload,
        at,
    );
    ordinary_realm::bind_structural_human_device(&mut event);
    let (source, role, reference) = match cites {
        Cites::Nothing => {
            if let Some(fact) = previous
                .producer_signer_fact
                .as_ref()
                .and_then(|fact| fact.as_human())
                .filter(|fact| fact.actor == event.actor_id)
            {
                event = device_authorization_history::sign_event(
                    event,
                    fact.verification_method.clone(),
                    [81; 32],
                );
            }
            return ordinary_realm::request_for_event(previous, event, at);
        }
        Cites::Bootstrap(reference) => (
            BOOTSTRAP_SOURCE,
            "direct_conversation_founding_unit",
            reference,
        ),
        Cites::Participant(reference) => {
            (PARTICIPANT_SOURCE, "direct_conversation_binding", reference)
        }
        Cites::Repair(reference) => (REPAIR_SOURCE, "direct_conversation_binding", reference),
    };
    event.authorization_ref = Some(arkret_wire::AuthorizationRef::new(source).unwrap());
    event.semantic_refs = vec![arkret_wire::SemanticRef::new(reference.to_string(), role)];
    ordinary_realm::reseal(&mut event);
    if let Some(fact) = previous
        .producer_signer_fact
        .as_ref()
        .and_then(|fact| fact.as_human())
        .filter(|fact| fact.actor == event.actor_id)
    {
        event = device_authorization_history::sign_event(
            event,
            fact.verification_method.clone(),
            [81; 32],
        );
    }
    ordinary_realm::request_for_event(previous, event, at)
}

async fn sourced_cited(
    pair: &Pair,
    previous: &AuthorityCommitTransaction,
    kind: EventKind,
    actor: ActorId,
    payload: serde_json::Value,
    cites: Cites<'_>,
) -> coland_storage::EventCommitRequest {
    sourced_cited_at(
        pair,
        previous,
        kind,
        actor,
        payload,
        cites,
        previous.commit.committed_at,
    )
    .await
}

async fn sourced_cited_at(
    pair: &Pair,
    previous: &AuthorityCommitTransaction,
    kind: EventKind,
    actor: ActorId,
    payload: serde_json::Value,
    cites: Cites<'_>,
    at: chrono::DateTime<chrono::Utc>,
) -> coland_storage::EventCommitRequest {
    let mut request = cited(previous, kind, actor.clone(), payload, cites);
    request.authority_commit.event.created_at = at;
    let (method, seed) = if actor == pair.founder_actor() {
        (pair.founder_method.clone(), pair.founder_signing_seed)
    } else {
        assert_eq!(actor, pair.peer_actor());
        (pair.peer_method.clone(), pair.peer_signing_seed)
    };
    let event =
        device_authorization_history::sign_event(request.authority_commit.event, method, seed);
    let mut request = ordinary_realm::request_for_event(previous, event, at);
    request.authority_commit.producer_signer_fact = pair
        .store()
        .prepare_human_signer_fact(
            &request.authority_commit.event,
            request.authority_commit.commit.committed_at,
        )
        .await
        .unwrap()
        .map(Into::into);
    if request
        .authority_commit
        .event
        .human_device_producer()
        .unwrap()
        .is_some()
    {
        assert!(request.authority_commit.producer_signer_fact.is_some());
    } else {
        assert!(request.authority_commit.producer_signer_fact.is_none());
    }
    request.authority_commit.commit.producer_signer_fact_digest = request
        .authority_commit
        .producer_signer_fact
        .as_ref()
        .map(|fact| fact.digest().unwrap());
    let commit = &mut request.authority_commit.commit;
    let identity =
        arkret_canonical::canonical::unsigned_value(commit, &["commit_id", "signature"]).unwrap();
    commit.commit_id = arkret_wire::RealmCommitId::from_digest(arkret_canonical::sha256_bytes(
        arkret_canonical::canonical_json_bytes(&identity).unwrap(),
    ));
    commit.signature = arkret_signatures::detached_object::sign_detached_object(
        &arkret_canonical::canonical::unsigned_value(commit, &["signature"]).unwrap(),
        arkret_wire::DetachedSignatureContext::RealmCommit,
        commit.signature.verification_method.clone(),
        commit.committed_at,
        &ed25519_dalek::SigningKey::from_bytes(&[83; 32]),
    )
    .unwrap();
    commit.verify_commit_id_matches_content().unwrap();
    request
}

/// Attach the verified public MLS transition whose roster holds `principals`.
fn with_group(
    mut request: coland_storage::EventCommitRequest,
    base: Option<(&arkret_wire::EventId, u64)>,
    epoch: u64,
    principals: &[&ActorId],
) -> coland_storage::EventCommitRequest {
    request.authority_commit.mls_state = Some(coland_storage::MlsStateInstallation {
        effective_scope: request.authority_commit.event.scope_ref.clone(),
        base: base.map(|(reference, epoch)| coland_storage::MlsInstalledBase {
            current_mls_commit_event_ref: reference.clone(),
            epoch,
        }),
        epoch,
        public_state: format!("public-state-{epoch}").into_bytes(),
        member_principals: principals.iter().map(|actor| (*actor).clone()).collect(),
        consumed_proposals: Vec::new(),
        public_blobs: if base.is_some() {
            let sha256 = format!("{epoch:064x}");
            vec![coland_storage::MlsPublicBlob {
                blob_ref: arkret_wire::BlobRef::new(format!("ak:blob:sha256:{sha256}")).unwrap(),
                sha256: sha256.clone(),
                size_bytes: 11,
                storage_backend: "local".to_owned(),
                storage_key: format!("sha256/{sha256}"),
            }]
        } else {
            Vec::new()
        },
    });
    request
}

fn founder_leaf_authority(
    fixture: &pcr_genesis::PcrGenesisFixture,
    selector: &coland_storage::DeviceRevocationGateSelector,
) -> arkret_models_collaboration::events_payloads::MlsGenesisCreatorLeafAuthority {
    arkret_models_collaboration::events_payloads::MlsGenesisCreatorLeafAuthority {
        leaf_signature_key_b64u: arkret_wire::Base64UrlString::new(
            arkret_canonical::base64url_encode(
                ed25519_dalek::SigningKey::from_bytes(
                    &fixture.history.founding_device_signing_seed,
                )
                .verifying_key()
                .as_bytes(),
            ),
        )
        .unwrap(),
        endpoint: arkret_wire::MlsWelcomeRecipientEndpoint::Device {
            device_id: fixture.history.founding_device_id.clone(),
        },
        authorization_event_ref: selector.authorization_ref.event_id.clone(),
    }
}

fn mls_genesis_payload(
    pair: &Pair,
    realm_id: &RealmId,
    at: chrono::DateTime<chrono::Utc>,
) -> serde_json::Value {
    serde_json::json!({
        "cipher_suite": "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
        "group_info_ref": format!("ak:blob:sha256:{}", "3".repeat(64)),
        "ratchet_tree_ref": format!("ak:blob:sha256:{}", "4".repeat(64)),
        "creator_leaf_authority": pair.founder_leaf_authority,
        "governance_binding":
            arkret_models_crypto::MlsGovernanceBindingPayload::realm(realm_id.clone(), None, 0, 0, 0)
                .unwrap(),
        "created_at": arkret_canonical::format_timestamp_canonical(at),
    })
}

fn mls_commit_payload(
    realm_id: &RealmId,
    base: &arkret_wire::EventId,
    previous_epoch: u64,
    commit_bytes: &[u8],
) -> serde_json::Value {
    let binding = arkret_models_crypto::MlsGovernanceBindingPayload::realm(
        realm_id.clone(),
        Some(base.clone()),
        previous_epoch,
        previous_epoch + 1,
        0,
    )
    .unwrap();
    let envelope = arkret_models_crypto::MlsCommitEnvelope {
        group_id: binding.mls_group_id().unwrap(),
        epoch: previous_epoch + 1,
        commit: arkret_wire::base64url::base64url_encode(commit_bytes),
        commit_digest: Hash::new(arkret_canonical::sha256_digest(commit_bytes)).unwrap(),
        ratchet_tree: None,
    };
    serde_json::to_value(
        arkret_models_crypto::MlsCommitPayload::new(base.clone(), 0, &envelope, binding).unwrap(),
    )
    .unwrap()
}

/// One MLS ciphertext Message body frozen at `epoch` over `group_state_ref`.
fn ciphertext(
    strand_id: &arkret_wire::StrandId,
    epoch: u64,
    group_state_ref: &arkret_wire::EventId,
) -> serde_json::Value {
    serde_json::json!({
        "strand_id": strand_id,
        "track_name": "discussion",
        "encrypted_content": arkret_models_crypto::EncryptedEnvelope {
            version: "1.0".to_owned(),
            content_type: "application/vnd.arkret.message+json".to_owned(),
            encryption_context: arkret_models_crypto::EncryptedEnvelopeEncryptionContext::standard(
                epoch,
                group_state_ref.clone(),
            ),
            ciphertext: "Y2lwaGVydGV4dA".to_owned(),
        },
    })
}

/// The peer's durable acceptance of its Welcome of `commit`, as the claim,
/// Welcome queue and consume services leave it (their own suites cover how):
/// the claim ledger row consumed, bound to the Welcome, queued to the peer.
async fn consume_peer_welcome(
    pool: &PgPool,
    station: &DidCoreId,
    commit: &coland_storage::EventCommitRequest,
    peer: &ActorId,
) {
    let mut conn = pool.get().await.unwrap();
    let changed=diesel::sql_query("UPDATE peer_keypackage_claims c SET state='consumed' FROM keypackage_claim_welcome_bindings b \
        WHERE b.commit_event_ref=$1 AND c.source_id=b.source_id AND c.claim_request_id=b.claim_request_id")
        .bind::<Text,_>(commit.authority_commit.event.event_id.as_str()).execute(&mut *conn).await.unwrap();
    drop(conn);
    if changed == 0 {
        record_peer_welcome(pool, station, commit, peer, "consumed", 0).await;
    }
}

async fn record_peer_welcome(
    pool: &PgPool,
    station: &DidCoreId,
    commit: &coland_storage::EventCommitRequest,
    peer: &ActorId,
    state: &str,
    ordinal: i64,
) {
    let claim_id = format!("ak:keypackage_claim:{}", uuid::Uuid::now_v7());
    let welcome_id = format!("ak:mls_welcome_delivery:{}", uuid::Uuid::now_v7());
    let request_id = uuid::Uuid::now_v7().simple().to_string();
    let now = chrono::Utc::now();
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query(
        "INSERT INTO peer_keypackage_claims \
         (source_id,claim_request_id,request_digest,key_package_use,keypackage_id,outcome, \
          terminal_receipt,consume_receipt,claim_expires_at_unix_ms,expires_at,state,updated_at) \
         VALUES ($1,$2,$3,'single_use',NULL,'{}'::jsonb,NULL,'{}'::jsonb,$4,$5,$7,$6)",
    )
    .bind::<Text, _>(station.as_str())
    .bind::<Text, _>(&request_id)
    .bind::<Text, _>(format!("sha256:{}", "6".repeat(64)))
    .bind::<BigInt, _>(now.timestamp_millis() + 3_600_000)
    .bind::<BigInt, _>(now.timestamp() + 86_400)
    .bind::<BigInt, _>(now.timestamp())
    .bind::<Text, _>(state)
    .execute(&mut *conn)
    .await
    .unwrap();
    diesel::sql_query(
        "INSERT INTO mls_welcome_deliveries \
         (welcome_id,realm_id,commit_event_pk,recipient,recipient_endpoint_kind,recipient_device_id,\
          recipient_verification_method,recipient_authorization_event_ref,\
          recipient_device_authorization,keypackage_claim_ref,delivery_json,state,delivered_at) \
         SELECT $1,$2,pk,$3,'device','device-1',NULL,$4,'{}'::jsonb,$5,$6,'delivered',now() \
         FROM canonical_events WHERE envelope->>'event_id'=$7",
    )
    .bind::<Text, _>(&welcome_id)
    .bind::<Text, _>(commit.authority_commit.event.realm_id.as_str())
    .bind::<Text, _>(peer.signing_principal_id().as_str())
    .bind::<Text, _>(unique_event_id("peer-device").as_str())
    .bind::<Text, _>(&claim_id)
    .bind::<diesel::sql_types::Jsonb, _>(serde_json::json!({ "recipient_actor_id": peer }))
    .bind::<Text, _>(commit.authority_commit.event.event_id.as_str())
    .execute(&mut *conn)
    .await
    .unwrap();
    diesel::sql_query(
        "INSERT INTO keypackage_claim_welcome_bindings \
         (claim_id,source_id,claim_request_id,welcome_id,welcome_digest,commit_event_ref) \
         VALUES ($1,$2,$3,$4,$5,$6)",
    )
    .bind::<Text, _>(&claim_id)
    .bind::<Text, _>(station.as_str())
    .bind::<Text, _>(&request_id)
    .bind::<Text, _>(&welcome_id)
    .bind::<Text, _>(format!("sha256:{}", "7".repeat(64)))
    .bind::<Text, _>(commit.authority_commit.event.event_id.as_str())
    .execute(&mut *conn)
    .await
    .unwrap();

    // These admission-cut fixtures seed the storage projection left by the
    // separately verified MLS processor, not synthetic protocol acceptance.
    let event = &commit.authority_commit.event;
    let scope_key =
        String::from_utf8(arkret_canonical::canonical_json_bytes(&event.scope_ref).unwrap())
            .unwrap();
    let epoch = commit.authority_commit.mls_state.as_ref().unwrap().epoch;
    diesel::sql_query(
        "INSERT INTO mls_consumed_proposal_provenance \
         (realm_id,scope_key,commit_event_ref,commit_stream_position,epoch,consumed_proposal_ordinal, \
          proposal_type,proposal_wire,proposal_ref,sender_actor_id,sender_leaf_index,sender_signature_key, \
          target_after_actor_id,target_after_leaf_index,target_after_signature_key,created_at) \
         VALUES ($1,$2,$3,$4,$5,$6,1,decode('01','hex'),decode('01','hex'),$7,0,repeat('a',43),$8,1,repeat('b',43),now())",
    ).bind::<Text,_>(event.realm_id.as_str()).bind::<Text,_>(&scope_key)
     .bind::<Text,_>(event.event_id.as_str())
     .bind::<BigInt,_>(commit.authority_commit.commit.stream_position as i64)
     .bind::<BigInt,_>(epoch as i64).bind::<BigInt,_>(ordinal)
     .bind::<diesel::sql_types::Jsonb,_>(serde_json::to_value(&event.actor_id).unwrap())
     .bind::<diesel::sql_types::Jsonb,_>(serde_json::to_value(peer).unwrap())
     .execute(&mut *conn).await.unwrap();
    diesel::sql_query(
        "INSERT INTO mls_welcome_provenance \
         (welcome_id,realm_id,scope_key,commit_event_ref,recipient_station_id,claim_id, \
          delivery_digest,delivery_canonical_json,accepted_at) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,now())",
    )
    .bind::<Text, _>(&welcome_id)
    .bind::<Text, _>(event.realm_id.as_str())
    .bind::<Text, _>(&scope_key)
    .bind::<Text, _>(event.event_id.as_str())
    .bind::<Text, _>(peer.route_service_id().as_str())
    .bind::<Text, _>(&claim_id)
    .bind::<Text, _>(format!("sha256:{}", "7".repeat(64)))
    .bind::<diesel::sql_types::Binary, _>(
        arkret_canonical::canonical_json_bytes(&serde_json::json!({"recipient_actor_id":peer}))
            .unwrap(),
    )
    .execute(&mut *conn)
    .await
    .unwrap();
}

/// Every row an admitted Direct Conversation Event can leave for `realm_id`.
async fn dc_footprint(pool: &PgPool, realm_id: &RealmId) -> [i64; 8] {
    let [authorities, events, commits, slots, members] = footprint(pool, realm_id).await;
    [
        authorities,
        events,
        commits,
        slots,
        members,
        count(
            pool,
            "SELECT COUNT(*) AS count FROM message_revision_current_results WHERE realm_id=$1",
            realm_id,
        )
        .await,
        count(
            pool,
            "SELECT COALESCE(SUM(jsonb_array_length(value->'endorsements')),0)::bigint AS count \
             FROM direct_conversation_binding_current_results WHERE realm_id=$1",
            realm_id,
        )
        .await,
        count(
            pool,
            "SELECT COUNT(*) AS count FROM mls_group_current_results WHERE realm_id=$1",
            realm_id,
        )
        .await,
    ]
}

#[derive(diesel::QueryableByName)]
struct GroupStateRow {
    #[diesel(sql_type = diesel::sql_types::Bool)]
    current_exact_pair: bool,
    #[diesel(sql_type = diesel::sql_types::Nullable<Text>)]
    initial_exact_pair_group_state_ref: Option<String>,
}

async fn group_state(pool: &PgPool, realm_id: &RealmId) -> (bool, Option<String>) {
    let mut conn = pool.get().await.unwrap();
    let row = diesel::sql_query(
        "SELECT current_exact_pair,initial_exact_pair_group_state_ref \
         FROM direct_conversation_group_states WHERE realm_id=$1",
    )
    .bind::<Text, _>(realm_id.as_str())
    .get_result::<GroupStateRow>(&mut *conn)
    .await
    .unwrap();
    (
        row.current_exact_pair,
        row.initial_exact_pair_group_state_ref,
    )
}

/// `contact-and-direct-conversation.md` Â§7.2, Â§8.3 and Â§8.4 at the accepting
/// cut: the root's materialization mask admits the one group Genesis; the
/// bootstrap source's provisional phase lets only the founder send and Add the
/// peer; once the peer's Welcome of the first exact-pair Commit is durable,
/// the completion phase admits only binding endorsements, whose integrity is
/// checked against the founding facts and that Commit; after the first
/// endorsement both phases exit and every participant write names the binding
/// under the participant source, with the pair's Contact still granting
/// `direct_message`. A request authored against an older cut is re-decided
/// at the current one, and every refusal writes nothing.
#[tokio::test]
async fn participant_authority_and_read_only_signal_scope_follow_the_group_and_binding_at_the_cut()
{
    boxed_participant_authority_scenario().await;
}

// Keep signed-source Future construction out of the scenario poll frame.
fn boxed_source<F: std::future::Future>(source: impl FnOnce() -> F) -> std::pin::Pin<Box<F>> {
    Box::pin(source())
}

fn boxed_participant_authority_scenario()
-> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> {
    Box::pin(participant_authority_scenario())
}

async fn participant_authority_scenario() {
    let (_database, pool) = contract_pool().await;
    let pair = pair(&pool).await;
    let store = pair.store();
    let at = now();
    let unit = founding_unit(&pair, &UnitShape::exact(&pair), key(), at).await;
    store
        .admit_self_direct_conversation_founding_unit(&unit, &pair.guards(), at)
        .await
        .unwrap();
    let realm_id = realm_of(&unit);
    let facts = unit.facts().unwrap();
    let create_ref = unit.transactions[0].event.event_id.clone();
    let founder = pair.founder_actor();
    let peer = pair.peer_actor();
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let refused = async |request: &coland_storage::EventCommitRequest| {
        let before = dc_footprint(&pool, &realm_id).await;
        let code = refusal_code(uow.commit_event(request.clone()).await);
        assert_eq!(dc_footprint(&pool, &realm_id).await, before);
        code
    };

    let (genesis_ref, add, add_ref, mut encryption_group, scope) = boxed_source(|| async {
        // realm-and-space.md Â§2.5 row 5: the founding create fixed history.
        assert_eq!(
            count(
                &pool,
                "SELECT COUNT(*) AS count FROM realm_bootstrap_current_results \
             WHERE realm_id=$1 AND result_family='realm_history_access' AND value='\"since_join\"'",
                &realm_id,
            )
            .await,
            1
        );

        // A bootstrap Message before the group Genesis has no provisional phase.
        let early = boxed_source(|| {
            sourced_cited(
                &pair,
                &unit.transactions[3],
                EventKind::MessageCreate,
                founder.clone(),
                ciphertext(&facts.main_strand_id, 0, &create_ref),
                Cites::Bootstrap(&create_ref),
            )
        })
        .await;
        assert_eq!(
            refused(&early).await,
            ConflictCode::DirectConversationParticipantAuthorityDenied
        );

        let SelfProducerCommitGuard::HumanDevice(device) = &pair.founder_guard else {
            unreachable!()
        };
        let scope = arkret_wire::ScopeRef::Realm {
            realm_id: realm_id.clone(),
        };
        let identity = arkret_mls::ArkretMlsIdentity::new_human_device(
            founder.clone(),
            arkret_wire::DeviceId::new(device.device_id.clone()).unwrap(),
            arkret_mls::ArkretMlsSigner::from_ed25519_signing_key(
                ed25519_dalek::SigningKey::from_bytes(&pair.founder_signing_seed),
            ),
        )
        .unwrap();
        let binding = |base, previous, next| {
            arkret_models_crypto::MlsGovernanceBindingPayload::realm(
                realm_id.clone(),
                base,
                previous,
                next,
                0,
            )
            .unwrap()
        };
        let mut encryption_group = identity
            .create_group_with_governance_binding(&scope, &binding(None, 0, 0))
            .unwrap();
        let (group_info, ratchet_tree) = encryption_group.public_group_state_bytes().unwrap();
        let mut tracker = arkret_mls::MlsPublicGroupTracker::from_external(
            &group_info,
            &ratchet_tree,
            encryption_group.group_id().as_str(),
            0,
        )
        .unwrap();
        let blob_ref = |bytes: &[u8]| {
            arkret_wire::BlobRef::new(format!(
                "ak:blob:{}",
                arkret_canonical::sha256_digest(bytes)
            ))
            .unwrap()
        };
        let public_blob = |bytes: &[u8]| {
            let sha256 = arkret_canonical::sha256_digest(bytes)
                .strip_prefix("sha256:")
                .unwrap()
                .to_owned();
            coland_storage::MlsPublicBlob {
                blob_ref: blob_ref(bytes),
                sha256: sha256.clone(),
                size_bytes: i64::try_from(bytes.len()).unwrap(),
                storage_backend: "local".to_owned(),
                storage_key: format!("sha256/{sha256}"),
            }
        };
        let mut genesis_payload = mls_genesis_payload(&pair, &realm_id, at);
        genesis_payload["group_info_ref"] = serde_json::to_value(blob_ref(&group_info)).unwrap();
        genesis_payload["ratchet_tree_ref"] =
            serde_json::to_value(blob_ref(&ratchet_tree)).unwrap();
        // The root's materialization mask admits the scope's one Genesis.
        let mut genesis = with_group(
            boxed_source(|| {
                sourced_cited(
                    &pair,
                    &unit.transactions[3],
                    EventKind::MlsGenesis,
                    founder.clone(),
                    genesis_payload,
                    Cites::Nothing,
                )
            })
            .await,
            None,
            0,
            &[&founder],
        );
        let material = genesis.authority_commit.mls_state.as_mut().unwrap();
        material.public_state = tracker.export_state().unwrap();
        material.public_blobs = vec![public_blob(&group_info), public_blob(&ratchet_tree)];
        uow.commit_event(genesis.clone()).await.unwrap();
        let genesis_ref = genesis.authority_commit.event.event_id.clone();
        assert_eq!(group_state(&pool, &realm_id).await, (false, None));

        // Provisional: the founder alone sends under the bootstrap source.
        let provisional = boxed_source(|| {
            sourced_cited(
                &pair,
                &genesis.authority_commit,
                EventKind::MessageCreate,
                founder.clone(),
                ciphertext(&facts.main_strand_id, 0, &genesis_ref),
                Cites::Bootstrap(&create_ref),
            )
        })
        .await;
        uow.commit_event(provisional.clone()).await.unwrap();
        let head = provisional.authority_commit.clone();
        for denied in [
            boxed_source(|| {
                sourced_cited(
                    &pair,
                    &head,
                    EventKind::MessageCreate,
                    founder.clone(),
                    ciphertext(&facts.main_strand_id, 0, &genesis_ref),
                    Cites::Nothing,
                )
            })
            .await,
            boxed_source(|| {
                sourced_cited(
                    &pair,
                    &head,
                    EventKind::MessageCreate,
                    founder.clone(),
                    ciphertext(&facts.main_strand_id, 0, &genesis_ref),
                    Cites::Bootstrap(&genesis_ref),
                )
            })
            .await,
            boxed_source(|| {
                sourced_cited(
                    &pair,
                    &head,
                    EventKind::MessageCreate,
                    peer.clone(),
                    ciphertext(&facts.main_strand_id, 0, &genesis_ref),
                    Cites::Bootstrap(&create_ref),
                )
            })
            .await,
        ] {
            assert_eq!(
                refused(&denied).await,
                ConflictCode::DirectConversationParticipantAuthorityDenied
            );
        }

        // The founder's Add makes the roster exactly the pair: the first such
        // Commit is the binding's initial group state.
        let peer_device =
            arkret_wire::DeviceId::new(pair.peer_method.as_str().split_once('#').unwrap().1)
                .unwrap();
        let peer_identity = arkret_mls::ArkretMlsIdentity::new_human_device(
            peer.clone(),
            peer_device,
            arkret_mls::ArkretMlsSigner::from_ed25519_signing_key(
                ed25519_dalek::SigningKey::from_bytes(&pair.peer_signing_seed),
            ),
        )
        .unwrap();
        let peer_package = claim_human_peer_package(
            &pair,
            &scope,
            &facts.pair_key,
            &facts.main_strand_id,
            peer_identity.key_package_record().unwrap(),
        )
        .await;
        let add_binding = binding(Some(genesis_ref.clone()), 0, 1);
        let real_add = encryption_group
            .add_member_with_governance_binding(&peer_package, &add_binding)
            .unwrap();
        tracker
            .process_public_handshake(
                &arkret_canonical::base64url_decode(&real_add.commit.commit).unwrap(),
            )
            .unwrap();
        let groups = coland_storage_postgres::PgMlsGroupCurrentStore { pool: pool.clone() };
        let accepted_base = coland_storage::MlsGroupCurrentStore::current(&groups, &scope)
            .await
            .unwrap()
            .unwrap()
            .value;
        let mut add = with_group(
            boxed_source(|| {
                sourced_cited(
                    &pair,
                    &head,
                    EventKind::MlsCommit,
                    founder.clone(),
                    serde_json::to_value(
                        arkret_models_crypto::MlsCommitPayload::new(
                            genesis_ref.clone(),
                            accepted_base.current_key_access_revision,
                            &real_add.commit,
                            add_binding,
                        )
                        .unwrap(),
                    )
                    .unwrap(),
                    Cites::Bootstrap(&create_ref),
                )
            })
            .await,
            Some((&genesis_ref, 0)),
            1,
            &[&founder, &peer],
        );
        let material = add.authority_commit.mls_state.as_mut().unwrap();
        material.public_state = tracker.export_state().unwrap();
        material.public_blobs = vec![public_blob(&tracker.ratchet_tree_bytes().unwrap())];
        uow.commit_event(add.clone()).await.unwrap();
        encryption_group
            .install_accepted_commit(
                &arkret_wire::CommittedEventFullView {
                    event: add.authority_commit.event.clone(),
                    commit: add.authority_commit.commit.clone(),
                },
                &accepted_base,
            )
            .unwrap();
        assert_eq!(encryption_group.epoch(), 1);
        let add_ref = add.authority_commit.event.event_id.clone();
        assert_eq!(
            group_state(&pool, &realm_id).await,
            (true, Some(add_ref.to_string()))
        );

        (genesis_ref, add, add_ref, encryption_group, scope)
    })
    .await;
    let basis = boxed_source(|| async {
        let basis = {
            #[derive(diesel::QueryableByName)]
            struct BasisRow {
                #[diesel(sql_type = diesel::sql_types::Jsonb)]
                authorization_basis: serde_json::Value,
            }
            let mut conn = pool.get().await.unwrap();
            diesel::sql_query(
            "SELECT authorization_basis FROM direct_conversation_founding_slots WHERE realm_id=$1",
        )
        .bind::<Text, _>(realm_id.as_str())
        .get_result::<BasisRow>(&mut *conn)
        .await
        .unwrap()
        .authorization_basis
        };
        basis
    })
    .await;
    // The canonical basis is the round's accepted request and accept heads.
    assert_eq!(basis["kind"], "accepted_contact");
    assert_eq!(basis["event_refs"].as_array().unwrap().len(), 2);
    let endorsement = |group_state_ref: &arkret_wire::EventId, seconds: i64| {
        serde_json::json!({
            "pair_key": facts.pair_key,
            "unordered_participant_ids": [founder.clone(), peer.clone()],
            "realm_id": realm_id,
            "main_strand_id": facts.main_strand_id,
            "founding_unit_digest": facts.founding_unit_digest,
            "authorization_basis": basis,
            "initial_exact_pair_group_state_ref": group_state_ref,
            "created_at": arkret_canonical::format_timestamp_canonical(
                at + chrono::Duration::seconds(seconds),
            ),
        })
    };
    let (stale_provisional, later_provisional) = boxed_source(|| async {
        record_peer_welcome(&pool, &pair.station, &add, &peer, "claimed", 0).await;
        // Until the peer's Welcome is durable the Realm stays provisional: no
        // endorsement, while the founder still sends at the new epoch.
        let early_binding = boxed_source(|| {
            sourced_cited(
                &pair,
                &add.authority_commit,
                EventKind::DirectConversationBound,
                peer.clone(),
                endorsement(&add_ref, 1),
                Cites::Bootstrap(&create_ref),
            )
        })
        .await;
        assert_eq!(
            refused(&early_binding).await,
            ConflictCode::DirectConversationParticipantAuthorityDenied
        );
        // Distinct real RFC 9420 messages use the actual accepted pair Add above,
        // rather than merging a staged transition or manufacturing a receipt.
        let mut encrypted_payload = |plaintext: &[u8]| {
            let header = arkret_models_crypto::EventContentPreEncryptionHeader::reconstruct(
                "1.0",
                "application/vnd.arkret.message+json",
                arkret_wire::EncryptedPayloadScheme::MlsRfc9420,
                scope.clone(),
                EventKind::MessageCreate.as_str(),
                encryption_group.epoch(),
                add_ref.clone(),
                encryption_group.local_content_sender_domain().unwrap(),
                arkret_models_crypto::EventContentRoutingContext::None,
            )
            .unwrap();
            let envelope = encryption_group
                .encrypt_payload(header, plaintext)
                .unwrap()
                .to_envelope()
                .unwrap();
            serde_json::json!({ "strand_id": facts.main_strand_id,
            "track_name": "discussion", "encrypted_content": envelope })
        };
        let stale_payload = encrypted_payload(b"{\"content\":\"older provisional\"}");
        let later_payload = encrypted_payload(b"{\"content\":\"later provisional\"}");
        assert_ne!(
            stale_payload["encrypted_content"]["ciphertext"],
            later_payload["encrypted_content"]["ciphertext"]
        );
        let stale_provisional = boxed_source(|| {
            sourced_cited(
                &pair,
                &add.authority_commit,
                EventKind::MessageCreate,
                founder.clone(),
                stale_payload,
                Cites::Bootstrap(&create_ref),
            )
        })
        .await;
        let later_provisional = boxed_source(|| {
            sourced_cited(
                &pair,
                &add.authority_commit,
                EventKind::MessageCreate,
                founder.clone(),
                later_payload,
                Cites::Bootstrap(&create_ref),
            )
        })
        .await;
        assert_ne!(
            stale_provisional.authority_commit.event.event_id,
            later_provisional.authority_commit.event.event_id
        );
        uow.commit_event(later_provisional.clone()).await.unwrap();

        (stale_provisional, later_provisional)
    })
    .await;
    let (head, binding_ref, founder_endorsement) = boxed_source(|| async {
        // Completion: once the peer consumed its Welcome, only an endorsement is
        // admitted. The provisional Message authored at the older cut is re-decided
        // at this one and refused.
        consume_peer_welcome(&pool, &pair.station, &add, &peer).await;
        let head = later_provisional.authority_commit.clone();
        let replayed = ordinary_realm::request_for_event(
            &head,
            stale_provisional.authority_commit.event.clone(),
            head.commit.committed_at,
        );
        assert_eq!(
            refused(&replayed).await,
            ConflictCode::DirectConversationParticipantAuthorityDenied
        );
        for (mutated, code) in [
            (
                endorsement(&genesis_ref, 1),
                ConflictCode::DirectConversationBindingInvalid,
            ),
            (
                {
                    let mut payload = endorsement(&add_ref, 1);
                    payload["pair_key"] = serde_json::json!(fixture_hash('9'));
                    payload
                },
                ConflictCode::DirectConversationBindingInvalid,
            ),
            (
                {
                    let mut payload = endorsement(&add_ref, 1);
                    payload["authorization_basis"]["event_refs"][0] =
                        serde_json::json!(unique_event_id("other-head"));
                    payload
                },
                ConflictCode::DirectConversationBindingInvalid,
            ),
        ] {
            let request = boxed_source(|| {
                sourced_cited(
                    &pair,
                    &head,
                    EventKind::DirectConversationBound,
                    peer.clone(),
                    mutated,
                    Cites::Bootstrap(&create_ref),
                )
            })
            .await;
            assert_eq!(refused(&request).await, code);
        }
        let peer_endorsement = boxed_source(|| {
            sourced_cited(
                &pair,
                &head,
                EventKind::DirectConversationBound,
                peer.clone(),
                endorsement(&add_ref, 1),
                Cites::Bootstrap(&create_ref),
            )
        })
        .await;
        uow.commit_event(peer_endorsement.clone()).await.unwrap();
        let binding_ref = peer_endorsement.authority_commit.event.event_id.clone();

        // Found: a compatible endorsement by the other participant accumulates;
        // the bootstrap source no longer carries a Message.
        let founder_endorsement = boxed_source(|| {
            sourced_cited(
                &pair,
                &peer_endorsement.authority_commit,
                EventKind::DirectConversationBound,
                founder.clone(),
                endorsement(&add_ref, 2),
                Cites::Bootstrap(&create_ref),
            )
        })
        .await;
        uow.commit_event(founder_endorsement.clone()).await.unwrap();
        let head = founder_endorsement.authority_commit.clone();
        assert_eq!(dc_footprint(&pool, &realm_id).await[6], 2);
        (head, binding_ref, founder_endorsement)
    })
    .await;
    boxed_source(|| async {
    for participant in [&pair.founder, &pair.peer] {
        let snapshot =
            coland_storage_postgres::account_snapshot_material(&pool, &realm_id, participant)
                .await
                .unwrap()
                .expect("accepted Direct Conversation participant has a complete Snapshot cut");
        let binding = snapshot
            .current_state_entries
            .iter()
            .find_map(|entry| match entry {
                arkret_wire::TypedCurrentRow::Value {
                    selector: arkret_wire::CurrentSelector::DirectConversationBinding { pair_key },
                    source_stream_ref,
                    value,
                    ..
                } if pair_key == &facts.pair_key => Some((source_stream_ref, value)),
                _ => None,
            })
            .expect("participant Snapshot retains the exact binding current");
        assert_eq!(
            binding.0,
            &arkret_wire::CommitStreamRef::Realm {
                realm_id: realm_id.clone()
            }
        );
        let value: arkret_models_collaboration::events_payloads::direct_conversation::DirectConversationBindingCurrentValue =
            serde_json::from_value(binding.1.clone()).unwrap();
        assert_eq!(value.endorsements.len(), 2);
        assert!(value.endorsed_by(&binding_ref));
        assert!(value.endorsed_by(&founder_endorsement.authority_commit.event.event_id));
    }
    let stranger = AccountId::new(
        DidCoreId::new("ak:did_core:web:outsider.example".to_owned()).unwrap(),
        pair.station.clone(),
    );
    assert!(
        matches!(
            coland_storage_postgres::account_snapshot_material(&pool, &realm_id, &stranger).await,
            Err(coland_storage::PersistenceError::SchemaViolation(_))
        ),
        "a nonparticipant must fail closed on Direct Conversation Snapshot disclosure"
    );
    // Session eligibility reads the same accepted pair and Contact heads in
    // a REPEATABLE READ, READ ONLY transaction. A row lock here caused 503.
    let signal_at = head.commit.committed_at + chrono::TimeDelta::seconds(1);
    let signal_cut = store
        .signal_scope_authority(coland_storage::SignalScopeAuthorityQuery {
 include_product_authority: false, product_agent: None,

            scope: &arkret_wire::ScopeRef::Realm {
                realm_id: realm_id.clone(),
            },
            authority_commit_id: &head.commit.commit_id,
            parent_realm_authority_commit_id: None,
            sender: &founder,
            signal_class: arkret_wire::SignalClass::Session,
            sent_at: signal_at,
            at: signal_at,
        })
        .await
        .unwrap()
        .expect("accepted DM pair has a complete read-only Signal cut");
    assert_eq!(signal_cut.historical_mls_event_ref, add_ref);
    assert_eq!(signal_cut.current_mls.current_mls_commit_event_ref, add_ref);
    assert_eq!(signal_cut.recipient_actors.len(), 2);
    assert!(signal_cut.recipient_actors.contains(&founder));
    assert!(signal_cut.recipient_actors.contains(&peer));
    let durable = PgEventStore { pool: pool.clone() }
        .direct_conversation_durable_state(TRUST_DOMAIN, facts.pair_key.as_str())
        .await
        .unwrap()
        .expect("accepted founding slot is durable");
    assert_eq!(durable.founding_slot.realm_id, realm_id.as_str());
    assert_eq!(durable.group_state_ref.as_ref(), Some(&add_ref));
    assert_eq!(durable.group_current_exact_pair, Some(true));
    assert_eq!(durable.members.len(), 2);
    assert!(
        durable
            .members
            .iter()
            .all(|member| member.membership == "join")
    );
    assert_eq!(
        PgEventStore { pool: pool.clone() }
            .direct_conversation_durable_state_for_realm(realm_id.as_str())
            .await
            .unwrap()
            .expect("accepted direct Realm resolves to its durable cut"),
        durable
    );
    assert_eq!(durable.binding.unwrap().endorsements.len(), 2);
    assert_eq!(
        refused(
            &boxed_source(|| sourced_cited(
                &pair,
                &head,
                EventKind::MessageCreate,
                founder.clone(),
                ciphertext(&facts.main_strand_id, 1, &add_ref),
                Cites::Bootstrap(&create_ref),
            ))
            .await
        )
        .await,
        ConflictCode::DirectConversationParticipantAuthorityDenied
    );
    // The participant source needs an accepted endorsement as its ref.
    assert_eq!(
        refused(
            &boxed_source(|| sourced_cited(
                &pair,
                &head,
                EventKind::MessageCreate,
                peer.clone(),
                ciphertext(&facts.main_strand_id, 1, &add_ref),
                Cites::Participant(&add_ref),
            ))
            .await
        )
        .await,
        ConflictCode::DirectConversationParticipantAuthorityDenied
    );
    // The technical root carries no masked action once found.
    let second_genesis = with_group(
        boxed_source(|| sourced_cited(
            &pair,
            &head,
            EventKind::MlsGenesis,
            founder.clone(),
            mls_genesis_payload(&pair, &realm_id, at),
            Cites::Nothing,
        ))
        .await,
        None,
        0,
        &[&founder],
    );
    assert_eq!(
        refused(&second_genesis).await,
        ConflictCode::DirectConversationRootMaskViolation
    );

    }).await;
    let head = boxed_source(|| async {
    let head = boxed_source(|| exercise_flat_topics(
        &pair,
        &pool,
        &uow,
        head,
        &binding_ref,
        &add_ref,
        &founder,
        &peer,
        &facts.main_strand_id,
    ))
    .await;

    // Personal watch uses stable participant authority, never the root or bootstrap.
    let mut head = head;
    for actor in [&founder, &peer] {
        let other = if actor == &founder { &peer } else { &founder };
        let payload =
            |watcher: &ActorId| {
                serde_json::to_value(
            arkret_models_collaboration::events_payloads::strand::StrandWatchSetPayload::set(
                facts.main_strand_id.clone(), watcher.clone(),
                arkret_models_collaboration::events_payloads::strand::StrandWatchLevel::All, None,
            )
        ).unwrap()
            };
        let rows_before = count(
            &pool,
            "SELECT COUNT(*) AS count FROM strand_watch_current_results WHERE realm_id=$1",
            &realm_id,
        )
        .await;
        for (watcher, source) in [
            (other, Cites::Participant(&binding_ref)),
            (actor, Cites::Bootstrap(&create_ref)),
        ] {
            assert_eq!(
                refused(
                    &boxed_source(|| sourced_cited(
                        &pair,
                        &head,
                        EventKind::StrandWatchSet,
                        actor.clone(),
                        payload(watcher),
                        source
                    ))
                    .await
                )
                .await,
                ConflictCode::DirectConversationParticipantAuthorityDenied
            );
            assert_eq!(
                count(
                    &pool,
                    "SELECT COUNT(*) AS count FROM strand_watch_current_results WHERE realm_id=$1",
                    &realm_id
                )
                .await,
                rows_before
            );
        }
        let write = boxed_source(|| sourced_cited(
            &pair,
            &head,
            EventKind::StrandWatchSet,
            actor.clone(),
            payload(actor),
            Cites::Participant(&binding_ref),
        ))
        .await;
        uow.commit_event(write.clone()).await.unwrap();
        head = write.authority_commit;
        assert_eq!(count(&pool, "SELECT COUNT(*) AS count FROM strand_watch_current_results WHERE realm_id=$1 AND value->>'level'='all'", &realm_id).await, rows_before + 1);
        let mut stale = payload(actor);
        stale["level"] = serde_json::json!("muted");
        assert_eq!(
            refused(
                &boxed_source(|| sourced_cited(
                    &pair,
                    &head,
                    EventKind::StrandWatchSet,
                    actor.clone(),
                    stale,
                    Cites::Participant(&binding_ref)
                ))
                .await
            )
            .await,
            ConflictCode::FailedPrecondition
        );
        assert_eq!(count(&pool, "SELECT COUNT(*) AS count FROM strand_watch_current_results WHERE realm_id=$1 AND value->>'level'='all'", &realm_id).await, rows_before + 1);
    }

    // Both participants send under the binding, citing either endorsement.
    let peer_message = boxed_source(|| sourced_cited(
        &pair,
        &head,
        EventKind::MessageCreate,
        peer.clone(),
        ciphertext(&facts.main_strand_id, 1, &add_ref),
        Cites::Participant(&binding_ref),
    ))
    .await;
    uow.commit_event(peer_message.clone()).await.unwrap();
    let founder_message = boxed_source(|| sourced_cited(
        &pair,
        &peer_message.authority_commit,
        EventKind::MessageCreate,
        founder.clone(),
        ciphertext(&facts.main_strand_id, 1, &add_ref),
        Cites::Participant(&founder_endorsement.authority_commit.event.event_id),
    ))
    .await;
    uow.commit_event(founder_message.clone()).await.unwrap();
    let head = founder_message.authority_commit.clone();

    head
    }).await;
    boxed_source(|| async {
        // Membership repair stays on the same stable Realm.  A joined
        // participant may leave only through the participant source; while left,
        // participant authority is inactive and only the repair source can carry
        // that same participant's `leave -> join` edge.
        let leave = boxed_source(|| {
            sourced_cited(
                &pair,
                &head,
                EventKind::MemberState,
                peer.clone(),
                serde_json::json!({"realm_id":realm_id,"member_id":peer,"membership":"leave"}),
                Cites::Participant(&binding_ref),
            )
        })
        .await;
        uow.commit_event(leave.clone()).await.unwrap();
        assert_eq!(
            refused(
                &boxed_source(|| sourced_cited(
                    &pair,
                    &leave.authority_commit,
                    EventKind::MemberState,
                    peer.clone(),
                    serde_json::json!({"realm_id":realm_id,"member_id":peer,"membership":"join"}),
                    Cites::Participant(&binding_ref),
                ))
                .await
            )
            .await,
            ConflictCode::DirectConversationParticipantAuthorityDenied
        );
        let rejoin = boxed_source(|| {
            sourced_cited(
                &pair,
                &leave.authority_commit,
                EventKind::MemberState,
                peer.clone(),
                serde_json::json!({"realm_id":realm_id,"member_id":peer,"membership":"join"}),
                Cites::Repair(&binding_ref),
            )
        })
        .await;
        uow.commit_event(rejoin.clone()).await.unwrap();
        let head = rejoin.authority_commit.clone();
        let readers = store
            .replica_bootstrap_readers(
                &arkret_wire::CommitStreamRef::Realm {
                    realm_id: realm_id.clone(),
                },
                &pair.station,
            )
            .await
            .unwrap();
        assert!(readers.contains(&(pair.peer.clone(), head.commit.clone())));
        assert!(!readers.contains(&(pair.peer.clone(), unit.transactions[2].commit.clone())));
        let rejoin_history = exact_genesis_scan(&store, &realm_id, &pair.peer, &pair.station).await;
        assert!(rejoin_history.committed_events.is_empty());
        let rejoin_floor = rejoin_history.readable_floor.unwrap();
        assert_eq!(rejoin_floor.oldest_position, head.commit.stream_position);
        assert_eq!(rejoin_floor.floor_commit_id, head.commit.commit_id);
        // Rejoining does not recover the old atomic unit's below-current-join
        // foreign originals through the exact GET path.
        assert!(matches!(
            store
                .committed_event_for_member(
                    &unit.transactions[1].event.event_id,
                    &pair.peer_actor(),
                    &pair.station
                )
                .await
                .unwrap(),
            coland_storage::MemberCommittedEventRead::NotVisible
        ));
        assert_eq!(
            rejoin_floor.floor_reason,
            arkret_wire::ReadableFloorReason::MembershipJoin
        );

        assert_eq!(
            store
                .member_station_bootstrap_floor(&realm_id, &pair.peer, &head.commit.commit_id)
                .await
                .unwrap(),
            Some(head.commit.stream_position)
        );
        assert_eq!(
            store
                .member_station_bootstrap_floor(
                    &realm_id,
                    &pair.peer,
                    &unit.transactions[2].commit.commit_id
                )
                .await
                .unwrap(),
            None
        );

        // A withdrawn directional Contact stops new sends and personal watch writes.
        // Advance the candidate's own creation/commit time together so this is a
        // distinct Event, not a retry of the accepted peer Message above. This
        // storage-role ciphertext fixture does not prove a peer MLS decryption.
        let mut conn = pool.get().await.unwrap();
        diesel::sql_query(
            "UPDATE contacts SET tombstone_event_ref=request_event_ref \
         WHERE (requester_id=$1 AND target_id=$2) OR (requester_id=$2 AND target_id=$1)",
        )
        .bind::<Text, _>(founder.to_string())
        .bind::<Text, _>(peer.to_string())
        .execute(&mut *conn)
        .await
        .unwrap();
        drop(conn);
        assert_eq!(
            refused(
                &boxed_source(|| sourced_cited_at(
                    &pair,
                    &head,
                    EventKind::MessageCreate,
                    peer.clone(),
                    ciphertext(&facts.main_strand_id, 1, &add_ref),
                    Cites::Participant(&binding_ref),
                    head.commit.committed_at + chrono::Duration::seconds(1),
                ))
                .await
            )
            .await,
            ConflictCode::DirectConversationParticipantAuthorityDenied
        );
        let watch_rows = count(
            &pool,
            "SELECT COUNT(*) AS count FROM strand_watch_current_results WHERE realm_id=$1",
            &realm_id,
        )
        .await;
        let watch =
            arkret_models_collaboration::events_payloads::strand::StrandWatchSetPayload::set(
                facts.main_strand_id.clone(),
                peer.clone(),
                arkret_models_collaboration::events_payloads::strand::StrandWatchLevel::Muted,
                None,
            );
        assert_eq!(
            refused(
                &boxed_source(|| sourced_cited(
                    &pair,
                    &head,
                    EventKind::StrandWatchSet,
                    peer.clone(),
                    serde_json::to_value(watch).unwrap(),
                    Cites::Participant(&binding_ref),
                ))
                .await
            )
            .await,
            ConflictCode::DirectConversationParticipantAuthorityDenied
        );
        assert_eq!(
            count(
                &pool,
                "SELECT COUNT(*) AS count FROM strand_watch_current_results WHERE realm_id=$1",
                &realm_id,
            )
            .await,
            watch_rows
        );
        // The actual structure sequence above includes classification cancellation
        // and lifecycle transitions. Cold hydration must preserve canonical state
        // even though this fixture gives many Commit positions equal timestamps.
        let persistence = PgPersistenceStore::new(pool.clone());
        let canonical =
            coland_storage::EventProjectionStoreRegistry::object_current_snapshot(&persistence)
                .snapshot()
                .await
                .unwrap();
        let projection = coland_services::projection::ProjectionService::new("topic-watch-restart");
        projection
            .hydrate_from_persistence(&persistence, &CanonicalHydrationAdapter, [realm_id.clone()])
            .await
            .unwrap();
        let state = projection.snapshot();
        let expected = canonical
            .strands
            .iter()
            .filter(|strand| strand.realm_id == realm_id);
        let mut expected_count = 0;
        for strand in expected {
            expected_count += 1;
            let id = strand.id.as_ref().unwrap();
            let cached = &state.strands[id.as_str()];
            let lifecycle = match strand.state.as_ref().unwrap() {
                arkret_wire::ObjectState::Active => coland_storage::ObjectLifecycleState::Active,
                arkret_wire::ObjectState::Archived => {
                    coland_storage::ObjectLifecycleState::Archived
                }
                arkret_wire::ObjectState::Redacted => {
                    coland_storage::ObjectLifecycleState::Redacted
                }
            };
            assert_eq!(cached.state, lifecycle);
            assert_eq!(cached.tracks, strand.tracks);
            assert_eq!(cached.stage, strand.stage);
            assert_eq!(
                cached.content,
                strand
                    .content
                    .as_ref()
                    .map(|value| serde_json::to_value(value).unwrap())
            );
            assert_eq!(
                cached.encrypted_content,
                strand
                    .encrypted_content
                    .as_ref()
                    .map(|value| serde_json::to_value(value).unwrap())
            );
        }
        assert_eq!(
            state
                .strands
                .values()
                .filter(|strand| strand.realm_id == realm_id.as_str())
                .count(),
            expected_count
        );
    })
    .await;
}

#[tokio::test]
async fn terminal_founding_claim_repairs_the_same_group_and_keeps_the_first_binding_ref() {
    use arkret_models_collaboration::direct_conversation::DirectConversationPeerMlsAdmission as Admission;
    let (_database, pool) = contract_pool().await;
    let pair = pair(&pool).await;
    let store = pair.store();
    let at = now();
    let unit = founding_unit(&pair, &UnitShape::exact(&pair), key(), at).await;
    store
        .admit_self_direct_conversation_founding_unit(&unit, &pair.guards(), at)
        .await
        .unwrap();
    let realm = realm_of(&unit);
    let facts = unit.facts().unwrap();
    let create_ref = unit.transactions[0].event.event_id.clone();
    let founder = pair.founder_actor();
    let peer = pair.peer_actor();
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let genesis = with_group(
        cited(
            &unit.transactions[3],
            EventKind::MlsGenesis,
            founder.clone(),
            mls_genesis_payload(&pair, &realm, at),
            Cites::Nothing,
        ),
        None,
        0,
        &[&founder],
    );
    uow.commit_event(genesis.clone()).await.unwrap();
    let genesis_ref = genesis.authority_commit.event.event_id.clone();
    let initial = with_group(
        cited(
            &genesis.authority_commit,
            EventKind::MlsCommit,
            founder.clone(),
            mls_commit_payload(&realm, &genesis_ref, 0, b"first-add"),
            Cites::Bootstrap(&create_ref),
        ),
        Some((&genesis_ref, 0)),
        1,
        &[&founder, &peer],
    );
    uow.commit_event(initial.clone()).await.unwrap();
    record_peer_welcome(&pool, &pair.station, &initial, &peer, "revoked", 0).await;
    let initial_ref = initial.authority_commit.event.event_id.clone();
    let read = async || {
        PgEventStore { pool: pool.clone() }
            .direct_conversation_durable_state_for_realm(realm.as_str())
            .await
            .unwrap()
            .unwrap()
    };
    let first = read().await;
    assert_eq!(first.peer_mls_admission, Admission::RepairRequired);
    assert_eq!(
        first.initial_exact_pair_group_state_ref,
        Some(initial_ref.clone())
    );
    let repaired = with_group(
        cited(
            &initial.authority_commit,
            EventKind::MlsCommit,
            founder.clone(),
            mls_commit_payload(&realm, &initial_ref, 1, b"remove-and-add-peer"),
            Cites::Bootstrap(&create_ref),
        ),
        Some((&initial_ref, 1)),
        2,
        &[&founder, &peer],
    );
    uow.commit_event(repaired.clone()).await.unwrap();
    seed_peer_remove(&pool, &repaired, &peer).await;
    record_peer_welcome(&pool, &pair.station, &repaired, &peer, "claimed", 0).await;
    let repaired_ref = repaired.authority_commit.event.event_id.clone();
    assert_eq!(read().await.peer_mls_admission, Admission::Pending);
    let payload = |reference: &arkret_wire::EventId| {
        serde_json::json!({
            "pair_key": facts.pair_key, "unordered_participant_ids":[founder,peer],
            "realm_id":realm, "main_strand_id":facts.main_strand_id,
            "founding_unit_digest":facts.founding_unit_digest,
            "authorization_basis": first.founding_slot.authorization_basis,
            "initial_exact_pair_group_state_ref": reference,
            "created_at": arkret_canonical::format_timestamp_canonical(at),
        })
    };
    let bound = cited(
        &repaired.authority_commit,
        EventKind::DirectConversationBound,
        founder.clone(),
        payload(&initial_ref),
        Cites::Bootstrap(&create_ref),
    );
    let before = dc_footprint(&pool, &realm).await;
    assert_eq!(
        refusal_code(uow.commit_event(bound.clone()).await),
        ConflictCode::DirectConversationParticipantAuthorityDenied
    );
    assert_eq!(dc_footprint(&pool, &realm).await, before);
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query("UPDATE peer_keypackage_claims c SET state='consumed' FROM keypackage_claim_welcome_bindings b \
        WHERE b.commit_event_ref=$1 AND c.source_id=b.source_id AND c.claim_request_id=b.claim_request_id")
        .bind::<Text,_>(repaired_ref.as_str()).execute(&mut *conn).await.unwrap();
    drop(conn);
    let current = read().await;
    assert_eq!(current.peer_mls_admission, Admission::Durable);
    assert_eq!(current.group_state_ref, Some(repaired_ref.clone()));
    assert_eq!(
        current.initial_exact_pair_group_state_ref,
        Some(initial_ref.clone())
    );
    let wrong = cited(
        &repaired.authority_commit,
        EventKind::DirectConversationBound,
        founder.clone(),
        payload(&repaired_ref),
        Cites::Bootstrap(&create_ref),
    );
    assert_eq!(
        refusal_code(uow.commit_event(wrong).await),
        ConflictCode::DirectConversationBindingInvalid
    );
    uow.commit_event(bound.clone()).await.unwrap();
    let binding_ref = bound.authority_commit.event.event_id.clone();
    // A later replacement must not inherit the prior occupied leaf's consumed
    // receipt, even though actor, leaf index and signature key are identical.
    let later = with_group(
        cited(
            &bound.authority_commit,
            EventKind::MlsCommit,
            founder.clone(),
            mls_commit_payload(&realm, &repaired_ref, 2, b"second-replacement"),
            Cites::Participant(&binding_ref),
        ),
        Some((&repaired_ref, 2)),
        3,
        &[&founder, &peer],
    );
    uow.commit_event(later.clone()).await.unwrap();
    seed_peer_remove(&pool, &later, &peer).await;
    record_peer_welcome(&pool, &pair.station, &later, &peer, "claimed", 0).await;
    assert_eq!(read().await.peer_mls_admission, Admission::Pending);
    assert_eq!(
        read().await.initial_exact_pair_group_state_ref,
        Some(initial_ref)
    );
}

async fn seed_peer_remove(
    pool: &PgPool,
    commit: &coland_storage::EventCommitRequest,
    peer: &ActorId,
) {
    let event = &commit.authority_commit.event;
    let scope_key =
        String::from_utf8(arkret_canonical::canonical_json_bytes(&event.scope_ref).unwrap())
            .unwrap();
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query("INSERT INTO mls_consumed_proposal_provenance \
        (realm_id,scope_key,commit_event_ref,commit_stream_position,epoch,consumed_proposal_ordinal,proposal_type, \
         proposal_wire,proposal_ref,sender_actor_id,sender_leaf_index,sender_signature_key, \
         target_before_actor_id,target_before_leaf_index,target_before_signature_key,created_at) \
        VALUES ($1,$2,$3,$4,$5,2,3,decode('01','hex'),decode('01','hex'),$6,0,repeat('a',43),$7,1,repeat('b',43),now())")
        .bind::<Text,_>(event.realm_id.as_str()).bind::<Text,_>(&scope_key).bind::<Text,_>(event.event_id.as_str())
        .bind::<BigInt,_>(commit.authority_commit.commit.stream_position as i64)
        .bind::<BigInt,_>(commit.authority_commit.mls_state.as_ref().unwrap().epoch as i64)
        .bind::<diesel::sql_types::Jsonb,_>(serde_json::to_value(&event.actor_id).unwrap())
        .bind::<diesel::sql_types::Jsonb,_>(serde_json::to_value(peer).unwrap())
        .execute(&mut *conn).await.unwrap();
}

async fn exercise_flat_topics(
    pair: &Pair,
    pool: &PgPool,
    uow: &PgEventCommitUnitOfWork,
    mut head: AuthorityCommitTransaction,
    binding: &arkret_wire::EventId,
    group: &arkret_wire::EventId,
    founder: &ActorId,
    peer: &ActorId,
    main: &arkret_wire::StrandId,
) -> AuthorityCommitTransaction {
    use arkret_models_collaboration::events_payloads::{
        SpaceCreatePayload, StrandCreatePayload, StrandPatchPayload,
    };
    use arkret_models_collaboration::objects::space::Space;
    use arkret_models_collaboration::objects::strand::{Strand, StrandTopic};
    #[derive(diesel::QueryableByName)]
    struct ValueRow {
        #[diesel(sql_type=diesel::sql_types::Jsonb)]
        value: serde_json::Value,
    }
    async fn current(pool: &PgPool, id: &arkret_wire::StrandId) -> serde_json::Value {
        let mut conn = pool.get().await.unwrap();
        diesel::sql_query("SELECT value FROM strand_current_results WHERE strand_id=$1")
            .bind::<Text, _>(id.as_str())
            .get_result::<ValueRow>(&mut *conn)
            .await
            .unwrap()
            .value
    }
    async fn structure(pool: &PgPool, realm: &RealmId) -> serde_json::Value {
        let mut conn = pool.get().await.unwrap();
        diesel::sql_query("SELECT jsonb_build_object('strands',(SELECT jsonb_agg(to_jsonb(s) ORDER BY strand_id) FROM strand_current_results s WHERE realm_id=$1),'spaces',(SELECT jsonb_agg(to_jsonb(s) ORDER BY space_id) FROM space_current_results s WHERE realm_id=$1),'parents',(SELECT jsonb_agg(to_jsonb(s) ORDER BY space_id) FROM space_parent_current_results s WHERE realm_id=$1),'positions',(SELECT jsonb_agg(to_jsonb(s) ORDER BY strand_id) FROM strand_position_current_results s WHERE realm_id=$1)) AS value")
            .bind::<Text,_>(realm.as_str()).get_result::<ValueRow>(&mut *conn).await.unwrap().value
    }
    let realm = head.event.realm_id.clone();
    let before_group = count(
        pool,
        "SELECT COUNT(*) AS count FROM mls_group_current_results WHERE realm_id=$1",
        &realm,
    )
    .await;
    let (mut head, first, second, chat_id, space) = boxed_source(|| async {
        let mut envelope: arkret_models_crypto::EncryptedEnvelope =
            serde_json::from_value(ciphertext(main, 1, group)["encrypted_content"].clone())
                .unwrap();
        envelope.content_type = "application/json".into();
        let mut space = Space::create_object(realm.clone(), "topic", "", founder.clone());
        space.title = None;
        space.encrypted_metadata = Some(envelope.clone());
        space.created_at = head.commit.committed_at;
        space.rank = Some("a0".into());
        for kind in ["list", "board"] {
            let mut other = space.clone();
            other.kind = kind.into();
            let request = boxed_source(|| {
                sourced_cited(
                    pair,
                    &head,
                    EventKind::SpaceCreate,
                    founder.clone(),
                    serde_json::to_value(SpaceCreatePayload::new(other)).unwrap(),
                    Cites::Participant(binding),
                )
            })
            .await;
            let before = dc_footprint(pool, &realm).await;
            let before_structure = structure(pool, &realm).await;
            assert_eq!(
                refusal_code(uow.commit_event(request).await),
                ConflictCode::DirectConversationSpaceForbidden
            );
            assert_eq!(dc_footprint(pool, &realm).await, before);
            assert_eq!(structure(pool, &realm).await, before_structure);
        }
        let create = boxed_source(|| {
            sourced_cited(
                pair,
                &head,
                EventKind::SpaceCreate,
                founder.clone(),
                serde_json::to_value(SpaceCreatePayload::new(space.clone())).unwrap(),
                Cites::Participant(binding),
            )
        })
        .await;
        let first = arkret_wire::SpaceId::from_event_id(&create.authority_commit.event.event_id);
        uow.commit_event(create.clone()).await.unwrap();
        head = create.authority_commit;
        space.created_by = peer.clone();
        space.created_at = head.commit.committed_at;
        space.rank = Some("a1".into());
        let create = boxed_source(|| {
            sourced_cited(
                pair,
                &head,
                EventKind::SpaceCreate,
                peer.clone(),
                serde_json::to_value(SpaceCreatePayload::new(space.clone())).unwrap(),
                Cites::Participant(binding),
            )
        })
        .await;
        let second = arkret_wire::SpaceId::from_event_id(&create.authority_commit.event.event_id);
        uow.commit_event(create.clone()).await.unwrap();
        head = create.authority_commit;
        let mut chat = Strand::new_create(realm.clone(), "", founder.clone());
        chat.metadata = None;
        chat.encrypted_metadata = Some(envelope);
        chat.tracks.clear();
        chat.tracks.insert(
            "discussion".into(),
            arkret_models_collaboration::objects::profiles::StrandTrack::discussion_primary(),
        );
        chat.created_at = head.commit.committed_at;
        let create = boxed_source(|| {
            sourced_cited(
                pair,
                &head,
                EventKind::StrandCreate,
                founder.clone(),
                serde_json::to_value(StrandCreatePayload { object: chat }).unwrap(),
                Cites::Participant(binding),
            )
        })
        .await;
        let chat_id = arkret_wire::StrandId::from_event_id(&create.authority_commit.event.event_id);
        uow.commit_event(create.clone()).await.unwrap();
        head = create.authority_commit;
        (head, first, second, chat_id, space)
    })
    .await;
    let digest = |value: &serde_json::Value| {
        arkret_wire::Hash::new(arkret_canonical::sha256_digest(
            arkret_canonical::canonical_json_bytes(value).unwrap(),
        ))
        .unwrap()
    };
    let mut head = boxed_source(|| async {
    let initial = current(pool, &chat_id).await;
    assert!(initial.get("topic").is_none());
    let stale = digest(&initial);
    for (actor, topic, rank) in [(founder, first.clone(), "a0"), (peer, second.clone(), "a1")] {
        let payload = StrandPatchPayload::for_topic(
            chat_id.clone(),
            Some(StrandTopic {
                space_id: topic.clone(),
                rank: rank.into(),
            }),
            digest(&current(pool, &chat_id).await),
        )
        .unwrap();
        let request = boxed_source(|| {
            sourced_cited(
                pair,
                &head,
                EventKind::StrandUpdate,
                actor.clone(),
                serde_json::to_value(payload).unwrap(),
                Cites::Participant(binding),
            )
        })
        .await;
        uow.commit_event(request.clone()).await.unwrap();
        head = request.authority_commit;
        assert_eq!(
            current(pool, &chat_id).await["topic"],
            serde_json::json!({"space_id":topic,"rank":rank})
        );
    }
    let bad = StrandPatchPayload::for_topic(chat_id.clone(), None, stale).unwrap();
    let request = boxed_source(|| {
        sourced_cited(
            pair,
            &head,
            EventKind::StrandUpdate,
            peer.clone(),
            serde_json::to_value(bad).unwrap(),
            Cites::Participant(binding),
        )
    })
    .await;
    let footprint_before = dc_footprint(pool, &realm).await;
    let structure_before = structure(pool, &realm).await;
    assert!(uow.commit_event(request).await.is_err());
    assert_eq!(dc_footprint(pool, &realm).await, footprint_before);
    assert_eq!(structure(pool, &realm).await, structure_before);
    let invalid = vec![
        (EventKind::SpaceCreate, {
            let mut board = space.clone();
            board.kind = "board".into();
            board.created_by = founder.clone();
            board.created_at = head.commit.committed_at;
            serde_json::to_value(SpaceCreatePayload::new(board)).unwrap()
        }),
        (
            EventKind::SpaceParent,
            serde_json::json!({"space_id":second,"parent_space_id":first,"expected_parent_space_id":null}),
        ),
        (
            EventKind::StrandMove,
            serde_json::json!({"board_space_id":first,"strand_id":chat_id,"target_space_id":second,"rank":"a2"}),
        ),
        (
            EventKind::StrandArchive,
            serde_json::json!({"target_ref":main}),
        ),
        (
            EventKind::SpaceTombstone,
            serde_json::json!({"space_id":second}),
        ),
    ];
    for (kind, payload) in invalid {
        let request = boxed_source(|| {
            sourced_cited(
                pair,
                &head,
                kind.clone(),
                founder.clone(),
                payload,
                Cites::Participant(binding),
            )
        })
        .await;
        let before = dc_footprint(pool, &realm).await;
        let state = structure(pool, &realm).await;
        assert!(uow.commit_event(request).await.is_err(), "{kind}");
        assert_eq!(dc_footprint(pool, &realm).await, before);
        assert_eq!(structure(pool, &realm).await, state);
    }
    head
    }).await;
    boxed_source(|| async {
        let archive = boxed_source(|| {
            sourced_cited(
                pair,
                &head,
                EventKind::StrandArchive,
                peer.clone(),
                serde_json::json!({"target_ref":chat_id}),
                Cites::Participant(binding),
            )
        })
        .await;
        uow.commit_event(archive.clone()).await.unwrap();
        head = archive.authority_commit;
        let delete = boxed_source(|| {
            sourced_cited(
                pair,
                &head,
                EventKind::SpaceTombstone,
                founder.clone(),
                serde_json::json!({"space_id":second}),
                Cites::Participant(binding),
            )
        })
        .await;
        assert_eq!(
            refusal_code(uow.commit_event(delete).await),
            ConflictCode::SpaceHasLiveDependents
        );
        let restore = boxed_source(|| {
            sourced_cited(
                pair,
                &head,
                EventKind::StrandRestore,
                founder.clone(),
                serde_json::json!({"target_ref":chat_id}),
                Cites::Participant(binding),
            )
        })
        .await;
        uow.commit_event(restore.clone()).await.unwrap();
        head = restore.authority_commit;
        let archive = boxed_source(|| {
            sourced_cited(
                pair,
                &head,
                EventKind::SpaceArchive,
                peer.clone(),
                serde_json::json!({"space_id":second}),
                Cites::Participant(binding),
            )
        })
        .await;
        uow.commit_event(archive.clone()).await.unwrap();
        head = archive.authority_commit;
        assert_eq!(current(pool, &chat_id).await["state"], "active");
        let unset = StrandPatchPayload::for_topic(
            chat_id.clone(),
            None,
            digest(&current(pool, &chat_id).await),
        )
        .unwrap();
        let clear = boxed_source(|| {
            sourced_cited(
                pair,
                &head,
                EventKind::StrandUpdate,
                peer.clone(),
                serde_json::to_value(unset).unwrap(),
                Cites::Participant(binding),
            )
        })
        .await;
        uow.commit_event(clear.clone()).await.unwrap();
        head = clear.authority_commit;
        assert!(current(pool, &chat_id).await.get("topic").is_none());
        let delete = boxed_source(|| {
            sourced_cited(
                pair,
                &head,
                EventKind::SpaceTombstone,
                founder.clone(),
                serde_json::json!({"space_id":second}),
                Cites::Participant(binding),
            )
        })
        .await;
        uow.commit_event(delete.clone()).await.unwrap();
        head = delete.authority_commit;
        assert_eq!(current(pool, main).await["state"], "active");
        assert_eq!(
            count(
                pool,
                "SELECT COUNT(*) AS count FROM strand_position_current_results WHERE realm_id=$1",
                &realm
            )
            .await,
            0
        );
        assert_eq!(
            count(
                pool,
                "SELECT COUNT(*) AS count FROM mls_group_current_results WHERE realm_id=$1",
                &realm
            )
            .await,
            before_group
        );
        head
    })
    .await
}

/// Real stored Human package and terminal claim, before SDK Add. The claimed
/// SDK state is derived only from the exact durable successful CAS outcome.
async fn claim_human_peer_package(
    pair: &Pair,
    scope: &arkret_wire::ScopeRef,
    pair_key: &Hash,
    strand_id: &arkret_wire::StrandId,
    mut package: arkret_models_crypto::MlsKeyPackageRecord,
) -> arkret_models_crypto::MlsKeyPackageRecord {
    use arkret_models_crypto::{
        KeyPackageClaimRecord, PeerKeyPackageClaimReceipt, PeerKeyPackageRequesterAuthorization,
        PeerKeyPackagesClaimOutcome, PeerKeyPackagesClaimRequestBody,
    };
    use coland_storage::MlsKeyPackageStore;
    let guard = pair
        .peer_guard
        .as_ref()
        .expect("actual accepted Human peer selector");
    let device = arkret_wire::DeviceId::new(guard.device_id.clone()).unwrap();
    let at =
        chrono::DateTime::from_timestamp_millis(chrono::Utc::now().timestamp_millis()).unwrap();
    let expires = at + chrono::Duration::minutes(30);
    assert_eq!(package.actor_id, pair.peer_actor());
    #[derive(diesel::QueryableByName)]
    struct Owner {
        #[diesel(sql_type=BigInt)]
        pk: i64,
    }
    let mut conn = pair.pool.get().await.unwrap();
    let owner = diesel::sql_query("INSERT INTO accounts(principal_id,station_id) VALUES($1,$2) ON CONFLICT(principal_id,station_id) DO UPDATE SET principal_id=EXCLUDED.principal_id RETURNING pk")
        .bind::<Text,_>(pair.peer.principal_id.as_str()).bind::<Text,_>(pair.peer.station_id.as_str())
        .get_result::<Owner>(&mut conn).await.unwrap().pk;
    drop(conn);
    let store = coland_storage_postgres::PgMlsKeyPackageStore {
        pool: pair.pool.clone(),
    };
    assert!(
        store
            .put(&coland_storage::MlsKeyPackageRow {
                id: package.keypackage_id.clone(),
                keypackage_ref: package.keypackage_ref.to_string(),
                keypackage_digest: package.keypackage_ref.to_string(),
                owner_account_pk: coland_storage::AccountPk(owner),
                actor_id: pair.peer.principal_id.to_string(),
                device_id: Some(device.to_string()),
                endpoint_verification_method: None,
                key_package_bytes: arkret_canonical::base64url_decode(&package.keypackage).unwrap(),
                capabilities: package.capabilities.clone(),
                capabilities_digest: arkret_canonical::canonical_sha256(&package.capabilities)
                    .unwrap(),
                last_resort: false,
                last_resort_realm_id: None,
                lifetime_not_before: package.created_at.timestamp(),
                lifetime_not_after: package.expires_at.unwrap().timestamp(),
                claimed_by_mls_group_id: None,
                device_authorize_event_id: Some(guard.authorization_ref.event_id.to_string()),
                agent_key_authorize_event_id: None,
                claimed_at: None,
                claim_expires_at_unix_ms: None,
                consumed_at: None,
                created_at: package.created_at.timestamp(),
            })
            .await
            .unwrap()
    );
    let claim_id = arkret_wire::KeypackageClaimId::new(format!(
        "ak:keypackage_claim:{}",
        uuid::Uuid::now_v7()
    ))
    .unwrap();
    let request_id = arkret_wire::Base64UrlString::new(arkret_canonical::base64url_encode(
        uuid::Uuid::now_v7().as_bytes(),
    ))
    .unwrap();
    let SelfProducerCommitGuard::HumanDevice(requester_guard) = &pair.founder_guard else {
        panic!("actual Human requester");
    };
    let mut request: PeerKeyPackagesClaimRequestBody = serde_json::from_value(serde_json::json!({
        "claim_request_id":request_id, "target_account_id":pair.peer, "requester_account_id":pair.founder,
        "intended_realm_id":scope.realm_id(), "mls_group_id":scope.canonical_mls_group_id().unwrap(),
        "claim_purpose":"direct_conversation", "required_capabilities":package.capabilities,
        "expires_at":arkret_canonical::format_timestamp_canonical(expires), "target_device_ids":[device],
        "pair_key":pair_key, "strand_id":strand_id, "service_binding":{"source_id":pair.station,"destination_id":pair.station},
        "requester_authorization":{"kind":"device", "verification_method":pair.founder_method,
          "requester_device_id":requester_guard.device_id, "device_authorize_event_id":requester_guard.authorization_ref.event_id,
          "signed_at":arkret_canonical::format_timestamp_canonical(at),
          "signature":{"kid":pair.founder_method,"signature_algorithm":"Ed25519","sig":"AA"}}
    })).unwrap();
    let bytes = arkret_models_crypto::keypackage_claim_authorization_signing_bytes(
        &request.unsigned_request(),
        &request.service_binding,
        &request.requester_authorization,
    )
    .unwrap();
    let PeerKeyPackageRequesterAuthorization::Device { signature, .. } =
        &mut request.requester_authorization
    else {
        unreachable!()
    };
    *signature = arkret_signatures::keypackages::sign_keypackage_signing_input(
        &pair.founder_signing_seed,
        pair.founder_method.as_str(),
        &bytes,
    )
    .unwrap();
    request.validate_shape().unwrap();
    let digest = arkret_canonical::canonical_sha256(&request).unwrap();
    let record = KeyPackageClaimRecord {
        claim_id: claim_id.to_string(),
        keypackage_ref: package.keypackage_ref.to_string(),
        actor_id: pair.peer_actor(),
        principal_id: pair.peer.principal_id.clone(),
        device_id: Some(device),
        agent_id: None,
        agent_verification_method: None,
        keypackage: package.keypackage.clone(),
        capabilities: package.capabilities.clone(),
        device_authorize_event_id: Some(guard.authorization_ref.event_id.clone()),
        agent_key_authorize_event_id: None,
        expires_at: expires,
        revocation_status: Some("active".into()),
        last_resort: None,
    };
    record.validate_shape().unwrap();
    let method = format!("{}#authority", pair.station_did.clone());
    let mut receipt = PeerKeyPackageClaimReceipt {
        claim_request_id: request_id.clone(),
        request_digest: Hash::new(digest.clone()).unwrap(),
        claims_digest: Hash::new(arkret_canonical::canonical_sha256(&[&record]).unwrap()).unwrap(),
        source_id: pair.station.clone(),
        destination_id: pair.station.clone(),
        request: request.unsigned_request(),
        claimed_at: at,
        expires_at: expires,
        signature: arkret_models_crypto::KeyOperationSignature {
            kid: arkret_wire::NonEmptyString::new(method.clone()).unwrap(),
            signature_algorithm: Some(arkret_wire::NonEmptyString::new("Ed25519").unwrap()),
            sig: arkret_wire::Base64UrlString::new("AA").unwrap(),
        },
    };
    receipt.signature = arkret_signatures::keypackages::sign_keypackage_signing_input(
        &[83; 32],
        &method,
        &arkret_models_crypto::peer_keypackage_claim_receipt_signing_bytes(&receipt).unwrap(),
    )
    .unwrap();
    let outcome = PeerKeyPackagesClaimOutcome {
        claim_request_id: request_id.clone(),
        claims: vec![record],
        claim_receipt: receipt,
    };
    outcome.validate_shape().unwrap();
    let ledger = coland_storage::PeerKeyPackageClaimLedgerRecord {
        source_id: pair.station.to_string(),
        claim_request_id: request_id.to_string(),
        request_digest: digest,
        key_package_use: "single_use".into(),
        keypackage_id: Some(package.keypackage_id.clone()),
        outcome: Some(serde_json::to_value(&outcome).unwrap()),
        terminal_receipt: None,
        consume_receipt: None,
        claim_expires_at_unix_ms: Some(expires.timestamp_millis()),
        expires_at: expires.timestamp() + 86400,
        state: "claimed".into(),
        updated_at: at.timestamp(),
    };
    let group = scope.canonical_mls_group_id().unwrap();
    let result = store
        .try_claim_peer(coland_storage::PeerKeyPackageClaimAttempt {
            keypackage_id: &package.keypackage_id,
            mls_group_id: group.as_str(),
            device_authorize_event_id: Some(guard.authorization_ref.event_id.as_str()),
            agent_key_authorize_event_id: None,
            device_revocation_gate: Some(guard.clone()),
            claimed_at_unix_ms: at.timestamp_millis(),
            claim_expires_at_unix_ms: expires.timestamp_millis(),
            ledger: &ledger,
        })
        .await
        .unwrap();
    let coland_storage::PeerKeyPackageClaimAttemptResult::Claimed(row) = result else {
        panic!("actual claim must win");
    };
    assert_eq!(row.claimed_by_mls_group_id.as_deref(), Some(group.as_str()));
    let retained = store
        .get_peer_claim_by_claim_id(claim_id.as_str())
        .await
        .unwrap()
        .unwrap();
    let retained_outcome: PeerKeyPackagesClaimOutcome =
        serde_json::from_value(retained.outcome.unwrap()).unwrap();
    assert_eq!(retained_outcome.claims[0].keypackage, package.keypackage);
    assert_eq!(
        retained_outcome.claims[0].keypackage_ref,
        package.keypackage_ref.to_string()
    );
    package.state = arkret_models_crypto::MlsKeyPackageState::Claimed;
    package.claim_id = Some(retained_outcome.claims[0].claim_id.clone());
    package
}
