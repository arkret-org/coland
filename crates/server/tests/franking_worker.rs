//! The production franking sweeper verifies historical receipts and publishes durable proofs.
#[path = "../../storage-postgres/tests/support/ordinary_realm.rs"]
#[allow(dead_code)]
mod ordinary_realm;

use std::sync::Arc;

use arkret_wire::{ActorId, EventKind, ScopeRef};
use coland_http::config::AppConfig;
use coland_http::state::AppState;
use coland_storage::{AuthorityCommitStore, EventCommitUnitOfWork};
use coland_storage_postgres::{PgAuthorityCommitStore, PgEventCommitUnitOfWork, PgPool};
use coland_test_support::fault_injection::{
    FaultInjectingStore, FaultPlan, FaultPoint, FaultTiming,
};
use coland_test_support::pcr_genesis::PcrGenesisFixture;
use coland_test_support::{AppStateTestExt as _, device_authorization_history};
use diesel_async::RunQueryDsl as _;

struct Fixture {
    state: AppState,
    pool: PgPool,
    config: AppConfig,
    persistence: Arc<dyn coland_storage::PersistenceStore>,
    target: arkret_wire::Event,
}

async fn fixture() -> Fixture {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::WARN)
        .with_test_writer()
        .try_init();
    use arkret_models_crypto::{
        EventContentPreEncryptionHeader, EventContentRoutingContext, MlsGovernanceBindingPayload,
    };
    use arkret_wire::EncryptedPayloadScheme;
    let config = AppConfig {
        notary_signing_key_seed: Some(device_authorization_history::STATION_AUTHORITY_SEED),
        ..coland_test_support::app_config()
    };
    let (state, pool) = coland_test_support::app_state_with_pool(config.clone());
    let persistence = state.test_persistence();
    let fixture = PcrGenesisFixture::new(state.service_did());
    let device = fixture
        .admit_founding_device(persistence.as_ref())
        .await
        .unwrap();
    let account = fixture.history.account.clone();
    let actor = ActorId::account(account.clone());
    let label = uuid::Uuid::now_v7().to_string();
    let method = state.service_verification_method("notary-key").unwrap();
    let key = state.notary_signing_key();
    let app = coland_services::authority_commit::AuthorityCommitApplication::new(
        coland_services::persistence::PersistenceHandle::from_shared(persistence.clone()),
        0,
    );
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let unit = ordinary_realm::bootstrap_unit_for_account(&label, &account, &state.service_did());
    let at = unit.transactions[0].commit.committed_at;
    let mut submission = unit.submission.clone();
    for submitted in &mut submission.events {
        submitted.event = device_authorization_history::sign_event(
            submitted.event.clone(),
            fixture.history.device_verification_method.clone(),
            fixture.history.founding_device_signing_seed,
        );
    }
    let body = serde_json::to_vec(&arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequestBody::OrdinaryRealmBootstrap(submission.clone())).unwrap();
    let unit = app
        .prepare_ordinary_realm_bootstrap_unit(
            submission,
            body,
            &unit.transactions[0].expected_authority,
            method.clone(),
            &key,
            at,
        )
        .await
        .unwrap();
    let guards = vec![
        coland_storage::SelfProducerCommitGuard::HumanDevice(device.clone());
        unit.transactions.len()
    ];
    store
        .admit_self_ordinary_realm_bootstrap_unit(&unit, &guards, at)
        .await
        .unwrap();
    let mut previous = unit.transactions.last().unwrap().clone();
    let realm = previous.event.realm_id.clone();
    let scope = ScopeRef::Realm {
        realm_id: realm.clone(),
    };
    let seal = |event: arkret_wire::Event| {
        device_authorization_history::sign_event(
            event,
            fixture.history.device_verification_method.clone(),
            fixture.history.founding_device_signing_seed,
        )
    };
    let strand = seal(ordinary_realm::event_for_actor(
        EventKind::StrandCreate,
        scope.clone(),
        actor.clone(),
        serde_json::json!({"object":{
            "schema":"ak.schema.strand.v1","realm_id":realm,"tracks":{"discussion":{"is_primary":true,"profile":"discussion"}},
            "metadata":{"title":"Encrypted receipt"},"state":"active","created_by":actor,"created_at":arkret_canonical::format_timestamp_canonical(at)
        }}),
        at,
    ));
    let mut request = ordinary_realm::request_for_event(&previous, strand.clone(), at);
    request.authority_commit = app
        .prepare_self_event_transaction(&strand, &state.service_core_id(), method.clone(), &key, at)
        .await
        .unwrap();
    request.realm_fanout_source = Some(arkret_wire::EventAdmissionSubmission::new(strand.clone()));
    request.self_producer_guard = Some(coland_storage::SelfProducerCommitGuard::HumanDevice(
        device.clone(),
    ));
    uow.commit_event(request.clone()).await.unwrap();
    previous = request.authority_commit;
    let mut group = arkret_mls::ArkretMlsIdentity::new_human_device(
        actor.clone(),
        fixture.history.founding_device_id.clone(),
        arkret_mls::ArkretMlsSigner::from_ed25519_signing_key(
            ed25519_dalek::SigningKey::from_bytes(&fixture.history.founding_device_signing_seed),
        ),
    )
    .unwrap()
    .create_group_with_governance_binding(
        &scope,
        &MlsGovernanceBindingPayload::realm(realm.clone(), None, 0, 0, 0).unwrap(),
    )
    .unwrap();
    let (group_info, tree) = group.public_group_state_bytes().unwrap();
    let leaves =
        arkret_mls::validate_public_group_state(&group_info, &tree, group.group_id().as_str(), 0)
            .unwrap();
    assert_eq!(leaves.len(), 1);
    assert_eq!(leaves[0].actor_id, actor);
    let creator_authorization = fixture
        .unit
        .transactions
        .iter()
        .find(|transaction| transaction.event.kind == EventKind::DeviceAuthorize)
        .expect("the founding Device authorization was accepted with the PCR");
    assert_eq!(
        store
            .committed_event(&creator_authorization.event.event_id)
            .await
            .unwrap()
            .unwrap()
            .event,
        creator_authorization.event
    );
    let tracker = arkret_mls::MlsPublicGroupTracker::from_external(
        &group_info,
        &tree,
        group.group_id().as_str(),
        0,
    )
    .unwrap();
    let genesis = seal(ordinary_realm::event_for_actor(
        EventKind::MlsGenesis,
        scope.clone(),
        actor.clone(),
        serde_json::json!({
            "cipher_suite":group.group_ciphersuite_canonical_id().unwrap(),
            "group_info_ref":format!("ak:blob:{}",arkret_canonical::sha256_digest(&group_info)),
            "ratchet_tree_ref":format!("ak:blob:{}",arkret_canonical::sha256_digest(&tree)),
            "creator_leaf_authority": arkret_models_collaboration::events_payloads::MlsGenesisCreatorLeafAuthority {
                leaf_signature_key_base64url: leaves[0].signature_key.clone(),
                endpoint: arkret_wire::MlsWelcomeRecipientEndpoint::Device {
                    device_id: fixture.history.founding_device_id.clone(),
                },
                authorization_event_ref: creator_authorization.event.event_id.clone(),
            },
            "governance_binding":MlsGovernanceBindingPayload::realm(realm.clone(),None,0,0,0).unwrap(),
            "created_at":arkret_canonical::format_timestamp_canonical(at)
        }),
        at,
    ));
    let mut request = ordinary_realm::request_for_event(&previous, genesis.clone(), at);
    request.authority_commit = app
        .prepare_self_mls_transaction(
            &genesis,
            coland_storage::MlsStateInstallation {
                effective_scope: scope.clone(),
                base: None,
                epoch: 0,
                public_state: tracker.export_state().unwrap(),
                member_principals: leaves.iter().map(|leaf| leaf.actor_id.clone()).collect(),
                consumed_proposals: Vec::new(),
                public_blobs: Vec::new(),
            },
            Vec::new(),
            &state.service_core_id(),
            method.clone(),
            &key,
            at,
        )
        .await
        .unwrap();
    request.realm_fanout_source = Some(arkret_wire::EventAdmissionSubmission::new(genesis.clone()));
    request.self_producer_guard = Some(coland_storage::SelfProducerCommitGuard::HumanDevice(
        device.clone(),
    ));
    uow.commit_event(request.clone()).await.unwrap();
    previous = request.authority_commit;
    group
        .install_local_creator_binding(
            actor.clone(),
            Some(creator_authorization.event.event_id.clone()),
        )
        .unwrap();
    assert_eq!(group.member_actor_ids().unwrap(), vec![actor.clone()]);
    let header = EventContentPreEncryptionHeader::reconstruct(
        "1.0",
        "application/arkret-content+json",
        EncryptedPayloadScheme::MlsRfc9420,
        scope.clone(),
        EventKind::MessageCreate.as_str(),
        0,
        genesis.event_id.clone(),
        group.local_content_sender_domain().unwrap(),
        EventContentRoutingContext::None,
    )
    .unwrap();
    let encrypted = group
        .encrypt_payload(
            header,
            b"{\"kind\":\"ak.content.text\",\"body\":\"receipt\",\"format\":\"plain\"}",
        )
        .unwrap()
        .to_envelope()
        .unwrap();
    // Keep a real high-resolution local observation to cover projection replay.
    let received_at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now())
        + chrono::TimeDelta::nanoseconds(123_456);
    let target = seal(ordinary_realm::event_for_actor(
        EventKind::MessageCreate,
        scope,
        actor.clone(),
        serde_json::json!({
            "strand_id":arkret_wire::StrandId::from_event_id(&strand.event_id),"track_name":"discussion","encrypted_content":encrypted
        }),
        at - chrono::TimeDelta::days(2),
    ));
    let mut request = ordinary_realm::request_for_event(&previous, target.clone(), received_at);
    request.authority_commit = app
        .prepare_self_event_transaction(
            &target,
            &state.service_core_id(),
            method.clone(),
            &key,
            received_at,
        )
        .await
        .unwrap();
    request.realm_fanout_source = Some(arkret_wire::EventAdmissionSubmission::new(target.clone()));
    request.self_producer_guard = Some(coland_storage::SelfProducerCommitGuard::HumanDevice(
        device.clone(),
    ));
    uow.commit_event(request.clone()).await.unwrap();
    request.self_producer_guard = Some(coland_storage::SelfProducerCommitGuard::HumanDevice(
        device.clone(),
    ));
    uow.commit_event(request.clone()).await.unwrap();
    let jobs = persistence
        .authority_commits()
        .pending_franking_proofs(&state.service_core_id())
        .await
        .unwrap();
    assert_eq!(jobs.len(), 1);
    assert_eq!(
        jobs[0].received_at,
        arkret_canonical::normalize_timestamp_canonical(received_at),
        "the durable observation must use the closed FrankingProof timestamp precision"
    );
    Fixture {
        state,
        pool,
        config,
        persistence,
        target,
    }
}

#[derive(diesel::QueryableByName)]
struct Published {
    #[diesel(sql_type = diesel::sql_types::Jsonb)]
    value: serde_json::Value,
    #[diesel(sql_type = diesel::sql_types::Jsonb)]
    envelope: serde_json::Value,
    #[diesel(sql_type = diesel::sql_types::Jsonb)]
    commit_json: serde_json::Value,
}

async fn published(f: &Fixture) -> Option<Published> {
    use diesel::OptionalExtension as _;
    let mut conn = f.pool.get().await.unwrap();
    diesel::sql_query("SELECT p.value,e.envelope,c.commit_json FROM moderation_franking_proof_current_states p JOIN realm_commits c ON c.commit_id=p.current_commit_id JOIN canonical_events e ON e.pk=c.event_pk WHERE p.realm_id=$1 AND p.target_event_id=$2")
        .bind::<diesel::sql_types::Text,_>(f.target.realm_id.as_str())
        .bind::<diesel::sql_types::Text,_>(f.target.event_id.as_str())
        .get_result(&mut *conn).await.optional().unwrap()
}

async fn wait_until(f: &Fixture, fixed_pending: bool) -> Option<Published> {
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            if let Some(result) = published(f).await {
                return Some(result);
            }
            let jobs = f
                .persistence
                .authority_commits()
                .pending_franking_proofs(&f.state.service_core_id())
                .await
                .unwrap();
            if fixed_pending && jobs.len() == 1 && jobs[0].prepared_event.is_some() {
                return None;
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("the immediate production sweep must reach its durable boundary")
}

fn verify_published(f: &Fixture, result: &Published) -> arkret_wire::Event {
    use arkret_signatures::PublicKeyMaterial;
    let event: arkret_wire::Event = serde_json::from_value(result.envelope.clone()).unwrap();
    let commit: arkret_wire::RealmCommit =
        serde_json::from_value(result.commit_json.clone()).unwrap();
    let proof: arkret_models_collaboration::events_payloads::moderation::FrankingProof =
        serde_json::from_value(result.value.clone()).unwrap();
    assert_eq!(event.kind, EventKind::ModerationFrankingProof);
    assert_eq!(event.actor_id, ActorId::service(f.state.service_core_id()));
    assert_eq!(commit.event_ref, event.event_id);
    assert_eq!(proof.realm_id, f.target.realm_id);
    assert_eq!(proof.event_id, f.target.event_id);
    assert_eq!(proof.received_by, f.state.service_core_id());
    assert_eq!(
        proof.verification_method,
        f.state.service_verification_method("notary-key").unwrap()
    );
    assert_eq!(result.value, serde_json::to_value(&event.payload).unwrap());
    let key = f.state.notary_signing_key().verifying_key();
    let signature = ed25519_dalek::Signature::from_slice(
        &arkret_canonical::base64url_decode(&proof.signature).unwrap(),
    )
    .unwrap();
    key.verify_strict(&proof.canonical_signing_bytes().unwrap(), &signature)
        .unwrap();
    let material = PublicKeyMaterial::Ed25519Raw {
        bytes: key.as_bytes().to_vec(),
    };
    arkret_signatures::verify_ed25519_detached_jws_proof_with_digest_suite(
        event.producer_proof.as_ref().unwrap(),
        &arkret_signatures::EventProofBuilder::new()
            .envelope_bytes(&event)
            .unwrap(),
        &event.actor_id,
        &material,
        arkret_canonical::DigestSuite::Sha256,
    )
    .unwrap();
    event
        .verify_event_id_matches_content_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
        .unwrap();
    arkret_signatures::detached_object::verify_detached_object_signature(
        &commit.signature,
        &arkret_canonical::canonical::unsigned_value(&commit, &["signature"]).unwrap(),
        arkret_wire::DetachedSignatureContext::RealmCommit,
        &material,
    )
    .unwrap();
    event
}

#[tokio::test]
async fn production_franking_sweeper_publishes_real_receipt_and_clears_pending() {
    let f = fixture().await;
    assert_eq!(
        f.persistence
            .authority_commits()
            .pending_franking_proofs(&f.state.service_core_id())
            .await
            .unwrap()
            .len(),
        1
    );
    let worker = coland_http::state::spawn_pending_franking_sweeper(f.state.clone());
    let result = wait_until(&f, false).await.unwrap();
    worker.abort();
    let _ = worker.await;
    let event = verify_published(&f, &result);
    assert!(
        f.persistence
            .authority_commits()
            .pending_franking_proofs(&f.state.service_core_id())
            .await
            .unwrap()
            .is_empty()
    );
    let restarted =
        coland_test_support::app_state_with_persistence(f.config.clone(), f.persistence.clone())
            .await;
    let worker = coland_http::state::spawn_pending_franking_sweeper(restarted);
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    worker.abort();
    let _ = worker.await;
    let replay = published(&f).await.unwrap();
    assert_eq!(verify_published(&f, &replay), event);
    assert_eq!(replay.commit_json, result.commit_json);
}

#[tokio::test]
async fn production_franking_sweeper_keeps_fixed_proof_after_failure_and_restart() {
    let f = fixture().await;
    let fault = Arc::new(FaultInjectingStore::new(f.persistence.clone()));
    fault.fault_injector().arm(FaultPlan::new(
        FaultPoint::EventCommit,
        FaultTiming::Before,
        1,
    ));
    let fault_state =
        coland_test_support::app_state_with_persistence(f.config.clone(), fault.clone()).await;
    let worker = coland_http::state::spawn_pending_franking_sweeper(fault_state);
    assert!(wait_until(&f, true).await.is_none());
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    worker.abort();
    let _ = worker.await;
    let jobs = f
        .persistence
        .authority_commits()
        .pending_franking_proofs(&f.state.service_core_id())
        .await
        .unwrap();
    assert_eq!(jobs.len(), 1);
    let fixed = jobs[0].prepared_event.clone().unwrap();
    assert!(published(&f).await.is_none());
    assert!(
        f.persistence
            .authority_commits()
            .committed_event(&fixed.event_id)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        f.persistence
            .authority_commits()
            .committed_event(&f.target.event_id)
            .await
            .unwrap()
            .is_some()
    );
    let restarted =
        coland_test_support::app_state_with_persistence(f.config.clone(), f.persistence.clone())
            .await;
    let worker = coland_http::state::spawn_pending_franking_sweeper(restarted);
    let result = wait_until(&f, false).await.unwrap();
    worker.abort();
    let _ = worker.await;
    assert_eq!(
        verify_published(&f, &result),
        fixed,
        "restart must retain the first nonce and exact proof Event bytes"
    );
    assert!(
        f.persistence
            .authority_commits()
            .pending_franking_proofs(&f.state.service_core_id())
            .await
            .unwrap()
            .is_empty()
    );
}
