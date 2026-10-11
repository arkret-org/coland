//! PostgreSQL-backed Agent Origin fixtures shared by producer/consumer tests.
use arkret_wire::{
    DetachedSignatureContext, Did, DidCoreId, DidUrl, EventKind, RealmCommitId, RealmId,
};
use chrono::{Duration, Utc};
use coland_storage::{
    ActorProfileStore, AgentControlAdmissionWrite, AgentPcrGenesisAdmissionWrite,
    AgentProvisionAdmissionWrite, AuthorityCommitStore, AuthorityCommitTransaction,
};
use coland_storage_postgres::{
    PgActorProfileStore, PgAuthorityCommitStore, PgPersistenceStore, PgPool,
};
use diesel::sql_types::{BigInt, Text};
use diesel_async::RunQueryDsl;
use ed25519_dalek::SigningKey;
use rand_core::SeedableRng;

use super::{
    device_authorization_history as device_history_fixture, pcr_genesis as pcr_genesis_fixture,
};
pub fn agent_provision_event(
    controller: &arkret_wire::AccountId,
    realm_id: &RealmId,
    method: &DidUrl,
    seed: [u8; 32],
    agent_id: &DidCoreId,
    agent_pcr_id: &RealmId,
    slug: &str,
    created_at: chrono::DateTime<chrono::Utc>,
    payload_created_at: chrono::DateTime<chrono::Utc>,
) -> arkret_wire::Event {
    let mut event = arkret_wire::test_support::raw_event_at(
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
            "controller_authorization_ref": "did:webvh:z6mkfixture:agent.example#managed-controller",
            "agent_slug": slug,
            "accountability_scope": "agent_operator",
            "requested_scope_digest": format!("sha256:{}", "b".repeat(64)),
            "selector_visibility": "private",
            "created_at": arkret_canonical::format_timestamp_canonical(payload_created_at)
        }),
        created_at,
    )
    .unwrap();
    event.created_at = created_at;
    device_history_fixture::sign_event(event, method.clone(), seed)
}

pub fn agent_control_event(
    controller_method: &DidUrl,
    signing_seed: [u8; 32],
    executed_by: &arkret_wire::AccountId,
    agent: &arkret_wire::AccountId,
    agent_pcr: &RealmId,
    authorization_ref: &str,
    kind: EventKind,
    payload: serde_json::Value,
    at: chrono::DateTime<chrono::Utc>,
) -> arkret_wire::Event {
    let mut event = arkret_wire::test_support::raw_event_for_actor_at(
        kind.as_str(),
        arkret_wire::ScopeRef::Realm {
            realm_id: agent_pcr.clone(),
        },
        arkret_wire::ActorId::account(agent.clone()),
        payload,
        at,
    )
    .unwrap();
    event.executed_by = Some(arkret_wire::ActorId::account(executed_by.clone()));
    event.authorization_ref =
        Some(arkret_wire::AuthorizationRef::new(authorization_ref.to_owned()).unwrap());
    device_history_fixture::sign_event(event, controller_method.clone(), signing_seed)
}

pub fn agent_key_authorization(
    agent_did: &arkret_wire::Did,
    controller: &DidCoreId,
    fragment: &str,
    runtime_seed: [u8; 32],
    supersedes: Vec<(String, arkret_wire::EventId)>,
    at: chrono::DateTime<chrono::Utc>,
) -> serde_json::Value {
    let method = format!("{agent_did}#{fragment}");
    let submit = arkret_wire::ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT_V1;
    let mut value = serde_json::json!({
        "agent_id": arkret_wire::project_did_to_core_id(agent_did).unwrap(),
        "key_id": method,
        "verification_method": method,
        "public_key": {
            "kty": "OKP",
            "kid": method,
            "algorithm": "Ed25519",
            "key": arkret_canonical::base64url_encode(
                SigningKey::from_bytes(&runtime_seed).verifying_key().as_bytes()
            )
        },
        "accountable_principal_id": controller,
        "agent_key_scope": {
            "actions": [submit],
            "resources": [{"kind": "operation", "operation": submit}]
        },
        "audience": ["ak:did_core:web:pcr-contract.example"],
        "issued_at": arkret_canonical::format_timestamp_canonical(at),
        "approval_evidence": {
            "kind": "pairing_request",
            "request_canonical_digest": format!("sha256:{}", "d".repeat(64)),
            "pairing_request_id": format!("agent_pairing_request:{}", uuid::Uuid::now_v7()),
            "approved_by": controller
        }
    });
    if !supersedes.is_empty() {
        value["supersedes"] = serde_json::Value::Array(
            supersedes
                .into_iter()
                .map(|(key_id, event_id)| {
                    serde_json::json!({"key_id": key_id, "authorized_event_ref": event_id})
                })
                .collect(),
        );
    }
    value
}

pub fn station_genesis_commit(
    template: &arkret_wire::RealmCommit,
    event: &arkret_wire::Event,
    station_did: &arkret_wire::Did,
    committed_at: chrono::DateTime<chrono::Utc>,
) -> arkret_wire::RealmCommit {
    let realm_id = RealmId::from_event_id(&event.event_id);
    let mut commit = template.clone();
    commit.realm_id = realm_id.clone();
    commit.stream_ref = arkret_wire::CommitStreamRef::Realm { realm_id };
    commit.stream_position = 0;
    commit.previous_commit_ref = None;
    commit.event_ref = event.event_id.clone();
    commit.governance_generation = 0;
    commit.authority_ref =
        arkret_wire::RealmCommitAuthorityRef::GenesisOrChangeEvent(event.event_id.clone());
    commit.committed_at = committed_at;
    let identity =
        arkret_canonical::canonical::unsigned_value(&commit, &["commit_id", "signature"]).unwrap();
    commit.commit_id = RealmCommitId::from_digest(arkret_canonical::sha256_bytes(
        &arkret_canonical::canonical_json_bytes(&identity).unwrap(),
    ));
    let unsigned = arkret_canonical::canonical::unsigned_value(&commit, &["signature"]).unwrap();
    commit.signature = arkret_signatures::detached_object::sign_detached_object(
        &unsigned,
        DetachedSignatureContext::RealmCommit,
        DidUrl::new(format!("{station_did}#authority")).unwrap(),
        commit.committed_at,
        &SigningKey::from_bytes(&[83; 32]),
    )
    .unwrap();
    commit
}

pub fn station_successor(
    previous: &arkret_wire::RealmCommit,
    event: &arkret_wire::Event,
    station_did: &arkret_wire::Did,
    offset_seconds: i64,
) -> arkret_wire::RealmCommit {
    let mut commit = previous.clone();
    commit.stream_position = previous.stream_position + 1;
    commit.previous_commit_ref = Some(previous.commit_id.clone());
    commit.event_ref = event.event_id.clone();
    commit.committed_at = previous.committed_at + chrono::TimeDelta::seconds(offset_seconds);
    let identity =
        arkret_canonical::canonical::unsigned_value(&commit, &["commit_id", "signature"]).unwrap();
    commit.commit_id = RealmCommitId::from_digest(arkret_canonical::sha256_bytes(
        &arkret_canonical::canonical_json_bytes(&identity).unwrap(),
    ));
    let unsigned = arkret_canonical::canonical::unsigned_value(&commit, &["signature"]).unwrap();
    commit.signature = arkret_signatures::detached_object::sign_detached_object(
        &unsigned,
        DetachedSignatureContext::RealmCommit,
        DidUrl::new(format!("{station_did}#authority")).unwrap(),
        commit.committed_at,
        &SigningKey::from_bytes(&[83; 32]),
    )
    .unwrap();
    commit
}

pub struct OriginFixture {
    pub _lease: coland_storage_postgres::test_database::TestDatabase,
    pub pool: PgPool,
    pub controller: pcr_genesis_fixture::PcrGenesisFixture,
    pub station: DidCoreId,
    pub station_did: Did,
    pub method: DidUrl,
    pub issuer: SigningKey,
    pub history: arkret_models_identity::AuthenticatedServiceResolution,
    pub inception_log: serde_json::Value,
    pub directory: arkret_models_identity::AccountDeviceSignerEvidence,
    pub agent: arkret_wire::AccountId,
    pub agent_did: Did,
    pub genesis: AuthorityCommitTransaction,
    pub provision: AuthorityCommitTransaction,
}
pub fn origin_tx(
    event: arkret_wire::Event,
    commit: arkret_wire::RealmCommit,
    station: &DidCoreId,
) -> AuthorityCommitTransaction {
    AuthorityCommitTransaction {
        expected_authority: coland_storage::CurrentRealmAuthority {
            realm_id: commit.realm_id.clone(),
            generation: commit.governance_generation,
            service_id: station.clone(),
            authority_ref: commit.authority_ref.clone(),
            last_handoff_ref: None,
        },
        event,
        commit,
        producer_signer_fact: None,
        mls_state: None,
        welcomes: Vec::new(),
        recipient_queue_capacity: 0,
    }
}
pub fn origin_seal(commit: &mut arkret_wire::RealmCommit, method: &DidUrl, key: &SigningKey) {
    commit.commit_id = RealmCommitId::from_digest(arkret_canonical::sha256_bytes(
        &arkret_canonical::canonical_json_bytes(
            &arkret_canonical::canonical::unsigned_value(commit, &["commit_id", "signature"])
                .unwrap(),
        )
        .unwrap(),
    ));
    commit.signature = arkret_signatures::detached_object::sign_detached_object(
        &arkret_canonical::canonical::unsigned_value(commit, &["signature"]).unwrap(),
        DetachedSignatureContext::RealmCommit,
        method.clone(),
        commit.committed_at,
        key,
    )
    .unwrap();
    commit.validate_content_address().unwrap();
}
impl OriginFixture {
    pub fn replacement_provision(
        &self,
        parent: &arkret_wire::RealmCommit,
        slug: &str,
    ) -> AuthorityCommitTransaction {
        let agent = arkret_wire::project_did_to_core_id(
            &Did::new(format!(
                "did:web:replacement-{}.example",
                uuid::Uuid::now_v7().simple()
            ))
            .unwrap(),
        )
        .unwrap();
        let pcr = RealmId::from_event_id(&arkret_wire::EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            arkret_canonical::sha256_bytes(agent.as_str().as_bytes()),
        ));
        let at = parent.committed_at + Duration::seconds(1);
        let event = agent_provision_event(
            &self.controller.history.account,
            &parent.realm_id,
            &self.controller.history.device_verification_method,
            self.controller.history.founding_device_signing_seed,
            &agent,
            &pcr,
            slug,
            at,
            at,
        );
        let mut commit = station_successor(parent, &event, &self.station_did, 1);
        origin_seal(&mut commit, &self.method, &self.issuer);
        origin_tx(event, commit, &self.station)
    }

    pub async fn lifecycle(
        &self,
        parent: &arkret_wire::RealmCommit,
        kind: EventKind,
        transition: &str,
        previous: &str,
    ) -> AuthorityCommitTransaction {
        let at = parent.committed_at + Duration::seconds(1);
        let event = agent_control_event(
            &self.controller.history.device_verification_method,
            self.controller.history.founding_device_signing_seed,
            &self.controller.history.account,
            &self.agent,
            &self.genesis.event.realm_id,
            &format!("{}#managed-controller", self.agent_did),
            kind,
            serde_json::json!({"transition":transition,"previous_status":previous,
                "status_changed_at":arkret_canonical::format_timestamp_canonical(at)}),
            at,
        );
        let mut commit = station_successor(parent, &event, &self.station_did, 1);
        origin_seal(&mut commit, &self.method, &self.issuer);
        let tx = origin_tx(event, commit, &self.station);
        self.stage(&tx).await;
        PgActorProfileStore {
            pool: self.pool.clone(),
        }
        .admit_agent_control_event(AgentControlAdmissionWrite {
            commit: tx.clone(),
            queued_at: tx.commit.committed_at,
        })
        .await
        .unwrap();
        tx
    }

    pub async fn new() -> Self {
        use arkret_models_identity::service_identity::{
            CanonicalServiceUrl, ServiceRegistrationKey,
        };
        let mut rng = rand_chacha::ChaCha20Rng::from_seed([99; 32]);
        let registration = ServiceRegistrationKey::new(
            arkret_wire::ServiceKind::Station,
            CanonicalServiceUrl::new("https://origin.example/").unwrap(),
        )
        .unwrap();
        let inception = arkret_signatures::webvh::prepare_service_registration_inception(
            &mut rng,
            &arkret_signatures::webvh::ServiceRegistrationInceptionInput {
                provider_endpoint: &"https://identity.example/".parse().unwrap(),
                registration_key: &registration,
                also_known_as: &[],
                version_time: "2026-09-01T00:00:00Z".parse().unwrap(),
                did_key_fragment: None,
            },
        )
        .unwrap();
        Self::with_service_inception(inception).await
    }

    pub async fn with_service_inception(
        inception: arkret_signatures::webvh::PreparedInception,
    ) -> Self {
        let lease = coland_storage_postgres::test_database::TestDatabase::lease().await;
        let pool = lease.pool();
        let station_did = Did::new(inception.did.clone()).unwrap();
        let station = arkret_wire::project_did_to_core_id(&station_did).unwrap();
        let method = DidUrl::new(inception.did_key_id.clone()).unwrap();
        let issuer = SigningKey::from_bytes(&inception.did_key_seed);
        let controller = pcr_genesis_fixture::PcrGenesisFixture::new(station_did.clone());
        let mut conn = pool.get().await.unwrap();
        diesel::sql_query(
            "INSERT INTO device_inventory_station(singleton,station_id) VALUES(TRUE,$1)",
        )
        .bind::<Text, _>(station.as_str())
        .execute(&mut *conn)
        .await
        .unwrap();
        drop(conn);
        controller
            .admit_into(&PgPersistenceStore::new(pool.clone()))
            .await
            .unwrap();
        let head = controller.unit.transactions[1].commit.clone();
        let at = head.committed_at;
        let history = arkret_identity::build_authenticated_webvh_service_resolution(
            station.clone(),
            "station".into(),
            serde_json::from_value(inception.log_entry["state"].clone()).unwrap(),
            vec![inception.log_entry.clone()],
            vec![],
            at,
        )
        .unwrap();
        let authorization: arkret_models_collaboration::events_payloads::DeviceAuthorizePayload =
            serde_json::from_value(
                serde_json::to_value(&controller.history.events[1].payload).unwrap(),
            )
            .unwrap();
        let directory = arkret_models_identity::AccountDeviceSignerEvidence {
            device_projection_attestation:
                arkret_signatures::device_projection::sign_device_projection_attestation(
                    arkret_models_crypto::DeviceProjectionAttestationCore {
                        account_id: controller.history.account.clone(),
                        device_id: controller.history.founding_device_id.clone(),
                        device_signing_key_did: arkret_wire::DidKey::new(
                            authorization.device_public_key_did.as_str(),
                        )
                        .unwrap(),
                        hpke_key: arkret_wire::NonEmptyString::new(authorization.hpke_key.as_str())
                            .unwrap(),
                        device_authorize_event_id: controller.history.events[1].event_id.clone(),
                        authorized_generation_ref: 1,
                        device_status: arkret_models_crypto::DeviceStatus::Active,
                        authorization_window: arkret_models_crypto::DeviceAuthorizationWindow {
                            not_before: authorization.not_before,
                            expires_at: None,
                        },
                        attested_at: at,
                        expires_at: at + Duration::minutes(5),
                    },
                    method.clone(),
                    &issuer,
                )
                .unwrap(),
            service_resolution: history.clone(),
        };
        arkret_identity::account_device_signer_evidence::verify_historical_account_device_signer_evidence(&directory,&controller.history.account,&controller.history.founding_device_id).unwrap();
        let agent_did = Did::new(format!(
            "did:web:agent-{}.example",
            uuid::Uuid::now_v7().simple()
        ))
        .unwrap();
        let agent = arkret_wire::AccountId::new(
            arkret_wire::project_did_to_core_id(&agent_did).unwrap(),
            station.clone(),
        );
        let delegation = format!("{agent_did}#managed-controller");
        let genesis = device_history_fixture::sign_event(
            arkret_bootstrap::build_agent_pcr_create(arkret_bootstrap::AgentPcrCreateEventInput {
                payload: arkret_bootstrap::AgentPcrCreatePayloadInput {
                    agent_id: agent.principal_id.clone(),
                    governance_station_id: station.clone(),
                    initial_resolution: arkret_models_identity::ResolutionCommitment {
                        did: agent_did.clone(),
                        method_history_head: format!("sha256:{}", "c".repeat(64)),
                        version_id: "1-agent".into(),
                    },
                    genesis_salt: arkret_wire::GenesisSalt::new(
                        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                    )
                    .unwrap(),
                    trust_domain: arkret_wire::TrustDomainId::new("ak:trust_domain:origin.example")
                        .unwrap(),
                    initial_join_rule: arkret_wire::JoinRule::Closed,
                    initial_history_access: arkret_wire::HistoryAccess::SinceJoin,
                    initial_discoverability: arkret_wire::Discoverability::Secret,
                },
                executed_by: arkret_wire::ActorId::account(controller.history.account.clone()),
                authorization_ref: arkret_wire::AuthorizationRef::new(&delegation).unwrap(),
                created_at: at,
            })
            .unwrap()
            .into_event(),
            controller.history.device_verification_method.clone(),
            controller.history.founding_device_signing_seed,
        );
        let realm = RealmId::from_event_id(&genesis.event_id);
        let mut provision = agent_provision_event(
            &controller.history.account,
            &controller.history.events[0].realm_id,
            &controller.history.device_verification_method,
            controller.history.founding_device_signing_seed,
            &agent.principal_id,
            &realm,
            "origin",
            at,
            at,
        );
        provision.payload.insert(
            "controller_authorization_ref".into(),
            serde_json::json!(delegation),
        );
        provision = device_history_fixture::sign_event(
            provision,
            controller.history.device_verification_method.clone(),
            controller.history.founding_device_signing_seed,
        );
        let mut pc = station_successor(&head, &provision, &station_did, 1);
        origin_seal(&mut pc, &method, &issuer);
        let mut gc =
            station_genesis_commit(&head, &genesis, &station_did, at + Duration::seconds(2));
        origin_seal(&mut gc, &method, &issuer);
        Self {
            _lease: lease,
            pool,
            controller,
            station: station.clone(),
            station_did,
            method,
            issuer,
            inception_log: inception.log_entry.clone(),
            history,
            directory,
            agent,
            agent_did,
            genesis: origin_tx(genesis, gc, &station),
            provision: origin_tx(provision, pc, &station),
        }
    }
    pub async fn stage(&self, transaction: &AuthorityCommitTransaction) {
        let dependency = arkret_models_identity::AgentSignerDependency::AccountDevice {
            signer_resolution_evidence_ref: self.directory.signer_evidence_ref().unwrap(),
            account_device_signer_evidence: self.directory.clone(),
        };
        PgAuthorityCommitStore {
            pool: self.pool.clone(),
        }
        .stage_agent_control_source(
            &arkret_wire::CommittedEventFullView {
                event: transaction.event.clone(),
                commit: transaction.commit.clone(),
            },
            &dependency,
            &self.history,
        )
        .await
        .unwrap();
    }
    pub async fn admit_provision(&self) {
        PgActorProfileStore {
            pool: self.pool.clone(),
        }
        .admit_agent_provision(AgentProvisionAdmissionWrite {
            commit: self.provision.clone(),
            queued_at: self.provision.commit.committed_at,
        })
        .await
        .unwrap();
    }
    pub async fn count(&self, table: &str) -> i64 {
        #[derive(diesel::QueryableByName)]
        struct Count {
            #[diesel(sql_type=BigInt)]
            value: i64,
        }
        let mut conn = self.pool.get().await.unwrap();
        let query = match table {
            "candidate" => "SELECT count(*) AS value FROM agent_origin_control_source_candidates",
            "source" => "SELECT count(*) AS value FROM agent_origin_control_sources",
            "history" => "SELECT count(*) AS value FROM agent_origin_commit_histories",
            _ => panic!("fixed table only"),
        };
        diesel::sql_query(query)
            .get_result::<Count>(&mut *conn)
            .await
            .unwrap()
            .value
    }
    pub async fn admit_genesis(
        &self,
    ) -> Result<coland_storage::AgentPcrGenesisAdmissionOutcome, coland_storage::PersistenceError>
    {
        PgActorProfileStore {
            pool: self.pool.clone(),
        }
        .admit_agent_pcr_genesis(AgentPcrGenesisAdmissionWrite {
            commit: self.genesis.clone(),
            queued_at: self.genesis.commit.committed_at,
        })
        .await
    }
    pub async fn authorize(&self) -> AuthorityCommitTransaction {
        let at = self.genesis.commit.committed_at;
        let mut payload = agent_key_authorization(
            &self.agent_did,
            &self.controller.history.account.principal_id,
            "runtime",
            [0x61; 32],
            Vec::new(),
            at,
        );
        payload["audience"] = serde_json::json!([self.station]);
        let event = agent_control_event(
            &self.controller.history.device_verification_method,
            self.controller.history.founding_device_signing_seed,
            &self.controller.history.account,
            &self.agent,
            &self.genesis.event.realm_id,
            &format!("{}#managed-controller", self.agent_did),
            EventKind::AgentKeyAuthorize,
            payload,
            at,
        );
        let mut commit = station_successor(&self.genesis.commit, &event, &self.station_did, 1);
        origin_seal(&mut commit, &self.method, &self.issuer);
        let tx = origin_tx(event, commit, &self.station);
        self.stage(&tx).await;
        PgActorProfileStore {
            pool: self.pool.clone(),
        }
        .admit_agent_control_event(AgentControlAdmissionWrite {
            commit: tx.clone(),
            queued_at: tx.commit.committed_at,
        })
        .await
        .unwrap();
        tx
    }
    pub fn runtime_event(&self, at: chrono::DateTime<Utc>) -> arkret_wire::Event {
        let event = arkret_wire::test_support::raw_event_for_actor_at(
            EventKind::MessageCreate.as_str(),
            arkret_wire::ScopeRef::Realm {
                realm_id: self.genesis.event.realm_id.clone(),
            },
            arkret_wire::ActorId::account(self.agent.clone()),
            serde_json::json!({"content":{"kind":"text","text":"public fixture"}}),
            at,
        )
        .unwrap();
        device_history_fixture::sign_event(
            event,
            DidUrl::new(format!("{}#runtime", self.agent_did)).unwrap(),
            [0x61; 32],
        )
    }
}
