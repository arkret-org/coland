//! Actual state-port dispatcher and dedicated handlers over real PG.
//! The fixture accepts original controls through the native atomic stores;
//! it never treats a staged candidate as an accepted original. Middleware/TCP
//! authentication itself is outside this selector's proof scope.
use arkret_wire::{
    ActorId, AuthorityCommitStatus, AuthoritySubmitOutcome, Did, DidUrl, Event,
    EventAdmissionSubmission, EventKind, RealmCommit, ScopeRef,
};
use chrono::{DateTime, Duration, Utc};
use coland_services::authority_commit::AuthorityProtocolPort;
use coland_services::identity::{SessionEndpointState, SessionIdentityState};
use coland_storage::{
    AccountPk, AccountRecord, ActorProfileStore, AgentControlAdmissionWrite,
    AgentPcrGenesisAdmissionWrite, AgentProvisionAdmissionWrite, AuthorityCommitStore,
    AuthorityCommitTransaction, IdentityStoreRegistry,
};
use coland_storage_postgres::{
    PgActorProfileStore, PgAuthorityCommitStore, PgPersistenceStore, PgPool,
};
use coland_test_support::device_authorization_history::sign_event;
use coland_test_support::pcr_genesis::PcrGenesisFixture;
use ed25519_dalek::SigningKey;

use crate::state::AppState;

fn seal(commit: &mut RealmCommit, method: &DidUrl) {
    commit.commit_id = arkret_wire::RealmCommitId::from_digest(arkret_canonical::sha256_bytes(
        arkret_canonical::canonical_json_bytes(
            &arkret_canonical::canonical::unsigned_value(commit, &["commit_id", "signature"])
                .unwrap(),
        )
        .unwrap(),
    ));
    commit.signature = arkret_signatures::detached_object::sign_detached_object(
        &arkret_canonical::canonical::unsigned_value(commit, &["signature"]).unwrap(),
        arkret_wire::DetachedSignatureContext::RealmCommit,
        method.clone(),
        commit.committed_at,
        &SigningKey::from_bytes(&[83; 32]),
    )
    .unwrap();
    commit.validate_content_address().unwrap();
}

struct Fixture {
    state: AppState,
    // Own the leased external fixture until this local libtest state is dropped.
    _database_lease: Box<dyn Send + Sync>,
    pool: PgPool,
    pcr: PcrGenesisFixture,
    session: SessionIdentityState,
    method: DidUrl,
    history: arkret_models_identity::AuthenticatedServiceResolution,
    agent: arkret_wire::AccountId,
    agent_did: Did,
    delegation: String,
    genesis: Event,
    originals: Vec<(Event, RealmCommit)>,
}
impl Fixture {
    async fn new() -> Self {
        let mut config = coland_test_support::app_config();
        config.notary_signing_key_seed = Some([83; 32]);
        config.seed_demo_data = false;
        let (leased_state, pool) = coland_test_support::app_state_with_pool(config.clone());
        let identity = coland_test_support::fixture_service_identity(&config);
        let commitment = leased_state
            .service_resolution_commitment()
            .as_ref()
            .clone();
        // Both crates use the same official test_default constructor. Mirror
        // every override of app_config and this fixture into the local type;
        // the accepted service identity/commitment and PG pool are unchanged.
        let local_config = crate::config::AppConfig {
            public_base_url: config.public_base_url.clone(),
            notary_signing_key_seed: config.notary_signing_key_seed,
            seed_demo_data: config.seed_demo_data,
            ..crate::config::AppConfig::test_default()
        };
        assert_eq!(local_config.trust_domain, config.trust_domain);
        let state = AppState::new_with_service_identity(
            local_config,
            coland_storage_postgres::Db {
                pool: Some(pool.clone()),
            },
            std::sync::Arc::new(PgPersistenceStore::new(pool.clone())),
            identity,
            commitment,
            [83; 32],
        );
        let method = DidUrl::new(
            crate::routing::federation::federation_service_signature_key_id(
                state.service_did().as_str(),
            ),
        )
        .unwrap();
        let history =
            crate::routing::system::service_resolution::current_authenticated_service_resolution(
                &state,
            )
            .await
            .unwrap();
        let mut pcr = PcrGenesisFixture::new(state.service_did());
        let mut previous = None;
        for (index, tx) in pcr.unit.transactions.iter_mut().enumerate() {
            tx.commit.previous_commit_ref = previous;
            seal(&mut tx.commit, &method);
            previous = Some(tx.commit.commit_id.clone());
            pcr.history.commits[index] = tx.commit.clone();
        }
        pcr.admit_founding_device(&PgPersistenceStore::new(pool.clone()))
            .await
            .unwrap();
        let controller = &pcr.history.account;
        let persistence = PgPersistenceStore::new(pool.clone());
        let account_pk = persistence
            .accounts()
            .put(&AccountRecord {
                pk: AccountPk(0),
                principal_id: controller.principal_id.clone(),
                station_id: controller.station_id.clone(),
                localpart: "native-replay-controller".into(),
                display_name: None,
                bio: None,
                avatar_blob_ref: None,
                created_at: Utc::now(),
            })
            .await
            .unwrap();
        let at = DateTime::from_timestamp_millis(Utc::now().timestamp_millis()).unwrap();
        let session = SessionIdentityState {
            token_hash: "native-replay-public-fixture".into(),
            account_pk: Some(account_pk),
            actor: controller.principal_id.to_string(),
            endpoint: SessionEndpointState::HumanDevice {
                device_id: pcr.history.founding_device_id.to_string(),
            },
            audience: controller.station_id.to_string(),
            session_public_key: None,
            session_grant: None,
            expires_at: at + Duration::hours(1),
            created_at: at,
            revoked_at: None,
        };
        let next = arkret_canonical::ed25519_pubkey_to_did_key_multibase(
            SigningKey::from_bytes(&[102; 32])
                .verifying_key()
                .as_bytes(),
        );
        let prepared = arkret_signatures::webvh::prepare_agent_inception(
            &arkret_signatures::webvh::AgentInceptionInput {
                principal_endpoint: &"https://native-replay-agent.example/".parse().unwrap(),
                local_id: "native-replay-agent",
                controller_principal_id: &controller.principal_id,
                version_time: at,
                root_seed: &[101; 32],
                next_root_public_key_multibase: &next,
            },
        )
        .unwrap();
        let agent_did = Did::new(prepared.did.clone()).unwrap();
        let agent = arkret_wire::AccountId::new(
            arkret_wire::project_did_to_core_id(&agent_did).unwrap(),
            state.service_core_id(),
        );
        let delegation = format!("{agent_did}#managed-controller");
        let genesis = sign_event(
            arkret_bootstrap::build_agent_pcr_create(arkret_bootstrap::AgentPcrCreateEventInput {
                payload: arkret_bootstrap::AgentPcrCreatePayloadInput {
                    agent_id: agent.principal_id.clone(),
                    governance_station_id: state.service_core_id(),
                    initial_resolution: arkret_models_identity::ResolutionCommitment {
                        did: agent_did.clone(),
                        method_history_head: arkret_canonical::canonical_sha256(
                            &prepared.log_entry,
                        )
                        .unwrap(),
                        version_id: prepared.log_entry["versionId"].as_str().unwrap().to_owned(),
                    },
                    genesis_salt: arkret_wire::GenesisSalt::new(
                        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                    )
                    .unwrap(),
                    trust_domain: state.config().trust_domain.clone(),
                    initial_join_rule: arkret_wire::JoinRule::Closed,
                    initial_history_access: arkret_wire::HistoryAccess::SinceJoin,
                    initial_discoverability: arkret_wire::Discoverability::Secret,
                },
                executed_by: ActorId::account(controller.clone()),
                authorization_ref: arkret_wire::AuthorizationRef::new(delegation.clone()).unwrap(),
                created_at: at,
            })
            .unwrap()
            .into_event(),
            pcr.history.device_verification_method.clone(),
            pcr.history.founding_device_signing_seed,
        );
        let provision=sign_event(arkret_wire::test_support::raw_event_for_actor_at(EventKind::AgentProvision.as_str(),
            ScopeRef::Realm {realm_id:pcr.unit.transactions[0].event.realm_id.clone()},ActorId::account(controller.clone()),
            serde_json::json!({"schema":"ak.schema.agent_provision.v1","agent_id":agent.principal_id,"controller_principal_id":controller.principal_id,
              "principal_control_realm_id":genesis.realm_id,"controller_authorization_ref":delegation,"agent_slug":"native-replay-agent",
              "accountability_scope":"agent_operator","requested_scope_digest":format!("sha256:{}","b".repeat(64)),"selector_visibility":"private",
              "created_at":arkret_canonical::format_timestamp_canonical(at)}),at).unwrap(),
            pcr.history.device_verification_method.clone(),pcr.history.founding_device_signing_seed);
        let application = state.authority_commits();
        let provision_tx = application
            .prepare_self_event_transaction(
                &provision,
                &state.service_core_id(),
                method.clone(),
                state.notary_signing_key().as_ref(),
                at,
            )
            .await
            .unwrap();
        let profiles = PgActorProfileStore { pool: pool.clone() };
        profiles
            .admit_agent_provision(AgentProvisionAdmissionWrite {
                commit: provision_tx,
                queued_at: at,
            })
            .await
            .unwrap();
        let genesis_tx = application
            .prepare_genesis_transaction(
                &genesis,
                &state.service_core_id(),
                method.clone(),
                state.notary_signing_key().as_ref(),
                at,
            )
            .unwrap();
        let mut f = Self {
            state,
            _database_lease: Box::new(leased_state),
            pool,
            pcr,
            session,
            method,
            history,
            agent,
            agent_did,
            delegation,
            genesis: genesis.clone(),
            originals: Vec::new(),
        };
        f.stage(&genesis_tx).await;
        profiles
            .admit_agent_pcr_genesis(AgentPcrGenesisAdmissionWrite {
                commit: genesis_tx.clone(),
                queued_at: at,
            })
            .await
            .unwrap();
        f.originals.push((genesis, genesis_tx.commit));
        f
    }
    async fn stage(&self, tx: &AuthorityCommitTransaction) {
        let original = PgAuthorityCommitStore {
            pool: self.pool.clone(),
        }
        .committed_event(&self.pcr.history.events[1].event_id)
        .await
        .unwrap()
        .unwrap();
        let p: arkret_models_collaboration::events_payloads::DeviceAuthorizePayload =
            serde_json::from_value(serde_json::to_value(&original.event.payload).unwrap()).unwrap();
        let root = arkret_models_identity::AccountDeviceSignerEvidence {
            device_projection_attestation:
                arkret_signatures::device_projection::sign_device_projection_attestation(
                    arkret_models_crypto::DeviceProjectionAttestationCore {
                        account_id: self.pcr.history.account.clone(),
                        device_id: p.device_id,
                        device_signing_key_did: arkret_wire::DidKey::new(
                            p.device_public_key_did.as_str(),
                        )
                        .unwrap(),
                        hpke_key: p.hpke_key,
                        device_authorize_event_id: original.event.event_id,
                        authorized_generation_ref: p.authorized_generation_ref,
                        device_status: arkret_models_crypto::DeviceStatus::Active,
                        authorization_window: arkret_models_crypto::DeviceAuthorizationWindow {
                            not_before: p.not_before,
                            expires_at: p.expires_at.flatten(),
                        },
                        attested_at: tx.commit.committed_at,
                        expires_at: tx.commit.committed_at + Duration::minutes(5),
                    },
                    self.method.clone(),
                    self.state.notary_signing_key().as_ref(),
                )
                .unwrap(),
            service_resolution: self.history.clone(),
        };
        arkret_identity::account_device_signer_evidence::verify_historical_account_device_signer_evidence(&root,&self.pcr.history.account,&self.pcr.history.founding_device_id).unwrap();
        let dependency = arkret_models_identity::AgentSignerDependency::AccountDevice {
            signer_resolution_evidence_ref: root.signer_evidence_ref().unwrap(),
            account_device_signer_evidence: root,
        };
        PgAuthorityCommitStore {
            pool: self.pool.clone(),
        }
        .stage_agent_control_source(
            &arkret_wire::CommittedEventFullView {
                event: tx.event.clone(),
                commit: tx.commit.clone(),
            },
            &dependency,
            &self.history,
        )
        .await
        .unwrap();
    }
    fn control(&self, kind: EventKind, payload: serde_json::Value) -> Event {
        let at = DateTime::from_timestamp_millis(Utc::now().timestamp_millis()).unwrap();
        let mut event = arkret_wire::test_support::raw_event_for_actor_at(
            kind.as_str(),
            ScopeRef::Realm {
                realm_id: self.genesis.realm_id.clone(),
            },
            ActorId::account(self.agent.clone()),
            payload,
            at,
        )
        .unwrap();
        event.executed_by = Some(ActorId::account(self.pcr.history.account.clone()));
        event.authorization_ref =
            Some(arkret_wire::AuthorizationRef::new(self.delegation.clone()).unwrap());
        sign_event(
            event,
            self.pcr.history.device_verification_method.clone(),
            self.pcr.history.founding_device_signing_seed,
        )
    }
    async fn accept(&mut self, event: Event) {
        let at = DateTime::from_timestamp_millis(Utc::now().timestamp_millis()).unwrap();
        let tx = self
            .state
            .authority_commits()
            .prepare_self_event_transaction(
                &event,
                &self.state.service_core_id(),
                self.method.clone(),
                self.state.notary_signing_key().as_ref(),
                at,
            )
            .await
            .unwrap();
        self.stage(&tx).await;
        PgActorProfileStore {
            pool: self.pool.clone(),
        }
        .admit_agent_control_event(AgentControlAdmissionWrite {
            commit: tx.clone(),
            queued_at: at,
        })
        .await
        .unwrap();
        self.originals.push((event, tx.commit));
    }
}

#[tokio::test]
async fn native_control_exact_replay_uses_originals_after_runtime_revocation_and_pause() {
    let mut f = Fixture::new().await;
    let at = Utc::now();
    let method = format!("{}#runtime-1", f.agent_did);
    let authorize=f.control(EventKind::AgentKeyAuthorize,serde_json::json!({
        "agent_id":f.agent.principal_id,"key_id":method,"verification_method":method,
        "public_key":{"kty":"OKP","kid":method,"algorithm":"Ed25519","key":arkret_canonical::base64url_encode(SigningKey::from_bytes(&[97;32]).verifying_key().as_bytes())},
        "accountable_principal_id":f.pcr.history.account.principal_id,
        "agent_key_scope":{"actions":["ak.self.events.command.submit.v1"],"resources":[{"kind":"operation","operation":"ak.self.events.command.submit.v1"}]},
        "audience":[f.state.service_core_id()],"issued_at":arkret_canonical::format_timestamp_canonical(at),
        "approval_evidence":{"kind":"pairing_request","request_canonical_digest":format!("sha256:{}","d".repeat(64)),
            "pairing_request_id":format!("agent_pairing_request:{}",uuid::Uuid::now_v7()),"approved_by":f.pcr.history.account.principal_id}
    }));
    f.accept(authorize).await;
    let revoke=f.control(EventKind::AgentKeyRevoke,serde_json::json!({"agent_id":f.agent.principal_id,"key_id":method,"revoked_by":f.pcr.history.account.principal_id,"revoked_at":arkret_canonical::format_timestamp_canonical(at)}));
    f.accept(revoke).await;
    let pause=f.control(EventKind::SelfAgentPause,serde_json::json!({"transition":"pause","previous_status":"active","status_changed_at":arkret_canonical::format_timestamp_canonical(at)}));
    f.accept(pause).await;
    assert!(
        f.state
            .agent_pairings()
            .agent(f.agent.principal_id.as_str())
            .await
            .unwrap()
            .is_none(),
        "the serving pairing pin is absent despite actual immutable provision/genesis acceptance"
    );
    let before = coland_test_support::native_control_source_footprint(&f.pool).await;
    for (event, commit) in &f.originals {
        let outcome = f
            .state
            .submit_self_event(&f.session, EventAdmissionSubmission::new(event.clone()))
            .await
            .unwrap();
        assert!(
            matches!(outcome,AuthoritySubmitOutcome::Accepted {status:AuthorityCommitStatus::Duplicate,commit:ref original} if original==commit)
        );
    }
    assert_eq!(
        coland_test_support::native_control_source_footprint(&f.pool).await,
        before
    );
    let (event, _) = f.originals.last().unwrap();
    let mut changed = event.clone();
    changed
        .payload
        .insert("previous_status".into(), serde_json::json!("paused"));
    let error = f
        .state
        .submit_self_event(&f.session, EventAdmissionSubmission::new(changed))
        .await
        .unwrap_err();
    assert_eq!(
        error.conflict_code(),
        Some(coland_storage::ConflictCode::EventIdDigestMismatch)
    );
    // A genuinely different Event has no accepted witness, and must run the
    // original new-admission/current source path rather than inheriting a key.
    let fresh=f.control(EventKind::SelfAgentResume,serde_json::json!({"transition":"resume","previous_status":"paused","status_changed_at":arkret_canonical::format_timestamp_canonical(Utc::now())}));
    assert!(
        f.state
            .submit_self_event(&f.session, EventAdmissionSubmission::new(fresh))
            .await
            .is_err()
    );
    assert_eq!(
        coland_test_support::native_control_source_footprint(&f.pool).await,
        before
    );
    let mut foreign = f.session.clone();
    foreign.audience = "ak:did_core:web:other-station.example".into();
    assert!(
        f.state
            .submit_self_event(&foreign, EventAdmissionSubmission::new(event.clone()))
            .await
            .is_err()
    );
    assert_eq!(
        coland_test_support::native_control_source_footprint(&f.pool).await,
        before
    );
}
