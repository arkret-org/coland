//! PostgreSQL-backed Agent Origin fixtures shared by producer/consumer tests.
use arkret_wire::{
    DetachedSignatureContext, Did, DidCoreId, DidUrl, EventKind, RealmCommitId, RealmId,
};
use chrono::{Duration, Utc};
use coland_storage::{
    ActorProfileStore, AgentControlAdmissionWrite, AgentPcrGenesisAdmissionWrite,
    AgentProvisionAdmissionWrite, AuthorityCommitStore, AuthorityCommitTransaction,
    RecoveryPolicyStore,
};
use coland_storage_postgres::{
    PgActorProfileStore, PgAuthorityCommitStore, PgPersistenceStore, PgPool,
};
use diesel::sql_types::{BigInt, Text};
use diesel_async::RunQueryDsl;
use ed25519_dalek::{Signer as _, SigningKey};
use rand_core::SeedableRng;

use super::{
    device_authorization_history as device_history_fixture, pcr_genesis as pcr_genesis_fixture,
};
#[expect(
    clippy::too_many_arguments,
    reason = "The fixture independently varies envelope time, payload time and accepted custody."
)]
pub fn agent_provision_event(
    controller: &device_history_fixture::DeviceHistoryFixture,
    history_custody: &arkret_models_crypto::AgentHistoryCustody,
    realm_id: &RealmId,
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
        controller.account.principal_id.clone(),
        controller.account.station_id.clone(),
        serde_json::to_value(arkret_models_collaboration::events_payloads::agent::AgentProvisionPayload {
            schema: arkret_models_collaboration::events_payloads::agent::AgentProvisionSchema::V1,
            agent_id: agent_id.clone(),
            controller_principal_id: controller.account.principal_id.clone(),
            principal_control_realm_id: agent_pcr_id.clone(),
            controller_authorization_ref: arkret_wire::DidUrl::new("did:webvh:z6mkfixture:agent.example#managed-controller").unwrap(),
            agent_slug: slug.to_owned(),
            accountability_scope: arkret_models_collaboration::events_payloads::agent::AgentProvisionAccountabilityScope::AgentOperator,
            requested_scope_digest: arkret_wire::Hash::new(format!("sha256:{}", "b".repeat(64))).unwrap(),
            selector_visibility: arkret_models_identity::handle::HandleVisibility::Private,
            selector_audience: None,
            created_at: payload_created_at,
            history_custody: history_custody.clone(),
        }).unwrap(),
        created_at,
    )
    .unwrap();
    event.created_at = created_at;
    device_history_fixture::sign_event(
        event,
        controller.device_verification_method.clone(),
        controller.founding_device_signing_seed,
    )
}

/// Publish a real controller recovery recipient before Agent provisioning.
/// This uses the native policy transaction, not a self-declared custody ref.
pub async fn admit_controller_history_custody(
    pool: &PgPool,
    principal: &pcr_genesis_fixture::PcrGenesisFixture,
    station_method: &DidUrl,
    station_key: &SigningKey,
) -> (
    arkret_wire::RealmCommit,
    arkret_models_crypto::AgentHistoryCustody,
) {
    let account = &principal.history.account;
    let realm = &principal.unit.transactions[0].event.realm_id;
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    let policies = coland_storage_postgres::PgRecoveryPolicyStore { pool: pool.clone() };
    let mut head = store
        .held_stream_head_commit(&arkret_wire::CommitStreamRef::Realm {
            realm_id: realm.clone(),
        })
        .await
        .unwrap()
        .unwrap();
    let policy = if let Some(accepted) = policies.get_active_for_account(account).await.unwrap() {
        serde_json::from_value::<arkret_models_crypto::RecoveryPolicy>(accepted.raw_payload)
            .unwrap()
    } else {
        let at = arkret_canonical::normalize_timestamp_canonical(
            head.committed_at + Duration::seconds(1),
        );
        let expires = at + Duration::days(3650);
        let issued_at = arkret_canonical::format_timestamp_canonical(at);
        let expires_at = arkret_canonical::format_timestamp_canonical(expires);
        let material =
            arkret::identity_root::derive_identity_recovery_key_material(&[149; 32], 0).unwrap();
        let method = &principal.history.device_verification_method;
        let did = &principal.history.did;
        let trust_domain =
            principal.unit.transactions[0].event.payload["object"]["trust_domain"].clone();
        let mut policy: arkret_models_crypto::RecoveryPolicy = serde_json::from_value(serde_json::json!({
            "schema":"ak.schema.recovery_policy.v1","policy_id":format!("ak:policy:{}",uuid::Uuid::now_v7()),
            "account_id":account,"version":1,"supersedes_id":null,"trust_domain":trust_domain,"issued_at":issued_at,
            "signature_proof":{"verification_method":method,"signature_algorithm":"Ed25519","signature":"AA"},
            "methods":[{"kind":"recovery_unlock","keys":[{
                "verification_method":format!("{did}#recovery-proof-0"),
                "public_key_multibase":material.recovery_proof_public_key_multikey,
                "signature_algorithm":"Ed25519","not_before":issued_at,"expires_at":expires_at,
                "backup_hpke":{"key_agreement_ref":format!("{did}#backup-hpke-0"),
                    "key_agreement_algorithm":"X25519","public_key_multibase":material.backup_hpke_public_key_multikey,
                    "hpke_suites":["ak.hpke_x25519_aead_chacha20poly1305.v1"],"use":"backup_hpke",
                    "not_before":issued_at,"expires_at":expires_at}
            }]}]
        })).unwrap();
        policy.signature_proof.signature =
            arkret_wire::Base64UrlString::new(arkret_canonical::base64url_encode(
                SigningKey::from_bytes(&principal.history.founding_device_signing_seed)
                    .sign(
                        &arkret_models_crypto::recovery_policy_signature_transcript_bytes(&policy)
                            .unwrap(),
                    )
                    .to_bytes(),
            ))
            .unwrap();
        policy.validate_shape().unwrap();
        let event = device_history_fixture::sign_event(
            arkret_wire::test_support::raw_event_for_actor_at(
                EventKind::PolicySet.as_str(),
                arkret_wire::ScopeRef::Realm {
                    realm_id: realm.clone(),
                },
                arkret_wire::ActorId::account(account.clone()),
                serde_json::json!({"policy_id":policy.policy_id,"value":policy}),
                at,
            )
            .unwrap(),
            method.clone(),
            principal.history.founding_device_signing_seed,
        );
        let mut commit = station_successor(&head, &event, &principal.history.station_did, 1);
        origin_seal(&mut commit, station_method, station_key);
        policies
            .commit_publication(coland_storage::RecoveryPolicyPublicationWrite {
                commit: origin_tx(event, commit.clone(), &account.station_id),
                queued_at: commit.committed_at,
            })
            .await
            .unwrap();
        head = commit;
        policy
    };
    let at = head.committed_at;
    let recipient = policy.methods.iter().find_map(|method| match method {
        arkret_models_crypto::RecoveryMethod::RecoveryUnlock { keys } => keys.iter().find(|key| {
            key.not_before <= at && key.expires_at > at && key.revoked_at.is_none_or(|revoked| revoked > at)
                && key.backup_hpke.not_before <= at && key.backup_hpke.expires_at > at
                && key.backup_hpke.revoked_at.is_none_or(|revoked| revoked > at)
                && key.backup_hpke.hpke_suites.contains(&arkret_models_crypto::RecoveryBackupHpkeSuite::X25519AeadChacha20Poly1305V1)
        }),
        _ => None,
    }).expect("the accepted fixture policy has a live real backup-HPKE recipient");
    let custody = arkret_models_crypto::AgentHistoryCustody {
        custodian_actor_id: arkret_wire::ActorId::account(account.clone()),
        recovery_policy_ref: arkret_models_crypto::RecoveryPolicyRef {
            policy_id: policy.policy_id.clone(),
            policy_version: policy.version,
        },
        recipient_key_ref: recipient.backup_hpke.key_agreement_ref.clone(),
    };
    (head, custody)
}

pub fn agent_control_event(
    controller: &device_history_fixture::DeviceHistoryFixture,
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
    event.executed_by = Some(arkret_wire::ActorId::account(controller.account.clone()));
    event.authorization_ref =
        Some(arkret_wire::AuthorizationRef::new(authorization_ref.to_owned()).unwrap());
    device_history_fixture::sign_event(
        event,
        controller.device_verification_method.clone(),
        controller.founding_device_signing_seed,
    )
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
        arkret_canonical::canonical_json_bytes(&identity).unwrap(),
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
        arkret_canonical::canonical_json_bytes(&identity).unwrap(),
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
    pub history_custody: arkret_models_crypto::AgentHistoryCustody,
    pub agent: arkret_wire::AccountId,
    pub agent_did: Did,
    pub agent_inception: arkret_signatures::webvh::PreparedPrincipalInception,
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
        content_backup_source: None,
        mls_state: None,
        welcomes: Vec::new(),
        recipient_queue_capacity: 0,
    }
}
pub fn origin_seal(commit: &mut arkret_wire::RealmCommit, method: &DidUrl, key: &SigningKey) {
    commit.commit_id = RealmCommitId::from_digest(arkret_canonical::sha256_bytes(
        arkret_canonical::canonical_json_bytes(
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
            &self.controller.history,
            &self.history_custody,
            &parent.realm_id,
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
            &self.controller.history,
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
                version_created_at: "2026-09-01T00:00:00Z".parse().unwrap(),
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
        let (head, history_custody) =
            admit_controller_history_custody(&pool, &controller, &method, &issuer).await;
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

                        owner_transfer_acceptance_intent_digest: None,
                    },
                    method.clone(),
                    &issuer,
                )
                .unwrap(),
            service_resolution: history.clone(),
        };
        arkret_identity::account_device_signer_evidence::verify_historical_account_device_signer_evidence(&directory,&controller.history.account,&controller.history.founding_device_id).unwrap();
        let local_id = format!("agent-{}", uuid::Uuid::now_v7().simple());
        let next_root = arkret_canonical::ed25519_pubkey_to_did_key_multibase(
            SigningKey::from_bytes(&[102; 32])
                .verifying_key()
                .as_bytes(),
        );
        let agent_inception = arkret_signatures::webvh::prepare_agent_inception(
            &arkret_signatures::webvh::AgentInceptionInput {
                principal_endpoint: &"https://agent-origin.example/".parse().unwrap(),
                local_id: &local_id,
                controller_principal_id: &controller.history.account.principal_id,
                version_created_at: at - Duration::seconds(2),
                root_seed: &[101; 32],
                next_root_public_key_multibase: &next_root,
            },
        )
        .unwrap();
        let agent_did = Did::new(agent_inception.did.clone()).unwrap();
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
                        method_history_head: arkret_canonical::canonical_sha256(
                            &agent_inception.log_entry,
                        )
                        .unwrap(),
                        version_id: agent_inception.version_id.clone(),
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
            &controller.history,
            &history_custody,
            &controller.history.events[0].realm_id,
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
            history_custody,
            agent,
            agent_did,
            agent_inception,
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
    /// Imported accepted fixture history; this is not normal HTTP binding.
    /// Tests requiring complete bootstrap invoke it only after accepted genesis.
    pub async fn publish_agent_binding(&self) {
        use coland_storage::DeliveryPolicyStoreRegistry as _;
        let provision =
            arkret_models_collaboration::events_payloads::agent::AgentProvisionPayload::try_from(
                &self.provision.event,
            )
            .unwrap();
        let next_root = arkret_canonical::ed25519_pubkey_to_did_key_multibase(
            SigningKey::from_bytes(&[103; 32])
                .verifying_key()
                .as_bytes(),
        );
        let update = arkret_signatures::webvh::prepare_agent_binding_update(
            &arkret_signatures::webvh::AgentBindingUpdateInput {
                did: self.agent_did.as_str(),
                local_id: &self.agent_inception.local_id,
                previous_entries: std::slice::from_ref(&self.agent_inception.log_entry),
                version_created_at: self.genesis.commit.committed_at,
                current_root_seed: &[102; 32],
                next_root_public_key_multibase: &next_root,
                controller_principal_id: &self.controller.history.account.principal_id,
                principal_control_realm_id: &self.genesis.event.realm_id,
                requested_scope_digest: &provision.requested_scope_digest,
            },
        )
        .unwrap();
        let entries = [self.agent_inception.log_entry.clone(), update.log_entry];
        arkret_identity::verify_did_webvh_v1_chain(&self.agent_did, &entries).unwrap();
        let store = PgPersistenceStore::new(self.pool.clone());
        for (i, entry) in entries.iter().enumerate() {
            store
                .webvh()
                .append_log_event(coland_storage::WebvhLogRecord {
                    did: self.agent_did.to_string(),
                    event_digest: arkret_canonical::canonical_sha256(entry).unwrap(),
                    sequence: i as u64 + 1,
                    operation: entry.clone(),
                    created_at: entry["versionTime"].as_str().unwrap().parse().unwrap(),
                })
                .await
                .unwrap();
        }
        let now = Utc::now();
        store
            .webvh()
            .put_document(coland_storage::WebvhDocumentRecord {
                did: self.agent_did.to_string(),
                did_document: entries[1]["state"].clone(),
                key_log_head: Some(arkret_canonical::canonical_sha256(&entries[1]).unwrap()),
                sequence: 2,
                method_evidence: serde_json::json!({}),
                fetched_at: now,
                expires_at: now + Duration::minutes(15),
                updated_at: now,
            })
            .await
            .unwrap();
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
            &self.controller.history,
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
