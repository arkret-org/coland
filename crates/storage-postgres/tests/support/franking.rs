//! Actual encrypted receipt prerequisites for the PostgreSQL atomic contracts.
use std::sync::Arc;

use arkret_wire::{ActorId, EventKind, ScopeRef};
use coland_storage::{AuthorityCommitStore, EventCommitUnitOfWork};
use coland_storage_postgres::{
    PgAuthorityCommitStore, PgEventCommitUnitOfWork, PgPersistenceStore, PgPool,
};
use ed25519_dalek::{Signer as _, SigningKey};

use super::ordinary_realm::human_profile;
use super::{device_authorization_history, ordinary_realm};

pub struct FrankingFixture {
    pub accepted_target: coland_storage::EventCommitRequest,
    pub prefix: coland_storage::EventCommitRequest,
    pub proof: coland_storage::EventCommitRequest,
    pub proof_payload: arkret_models_collaboration::events_payloads::moderation::FrankingProof,
    pub service_signing_key: SigningKey,
}

/// Accept prerequisites and the target, then durably fix the exact first proof.
/// The later Message prefix and proof are prepared but remain uncommitted.
pub async fn prepare(pool: &PgPool, label: &str) -> FrankingFixture {
    let pool = pool.clone();
    let label = label.to_owned();
    let mut tasks = tokio::task::JoinSet::new();
    tasks.spawn(async move { Box::pin(prepare_inner(&pool, &label)).await });
    tasks.join_next().await.unwrap().unwrap()
}

fn prepared(
    job: &coland_storage::PendingFrankingProof,
    nonce: u8,
    method: arkret_wire::DidUrl,
    key: &SigningKey,
) -> coland_storage::PreparedFrankingProof {
    let mut proof = arkret_models_collaboration::events_payloads::moderation::FrankingProof {
        realm_id: job.realm_id.clone(),
        event_id: job.target_event_id.clone(),
        received_by: job.received_by.clone(),
        verification_method: method.clone(),
        received_at: job.received_at,
        replay_nonce: arkret_canonical::base64url_encode([nonce; 24]),
        signature: String::new(),
    };
    proof.signature = arkret_canonical::base64url_encode(
        key.sign(&proof.canonical_signing_bytes().unwrap())
            .to_bytes(),
    );
    let mut draft = arkret_event_draft::TypedEventDraft::<
        arkret_wire::event_spec::ModerationFrankingProof,
    >::new(
        ScopeRef::Realm {
            realm_id: job.realm_id.clone(),
        },
        ActorId::service(job.received_by.clone()),
        proof,
    )
    .unwrap()
    .author_with_digest_suite(job.received_at, arkret_canonical::DigestSuite::Sha256)
    .unwrap();
    let signer = arkret_signatures::Ed25519PayloadSigner::new(
        key.clone(),
        human_profile::station_did(&job.received_by),
        method,
    );
    arkret_signatures::sign_event(
        &mut draft,
        &signer,
        arkret_signatures::SignEventOptions::new().with_created_at(job.received_at),
    )
    .unwrap();
    coland_storage::PreparedFrankingProof {
        realm_id: job.realm_id.clone(),
        target_event_id: job.target_event_id.clone(),
        received_by: job.received_by.clone(),
        event: draft.event().clone(),
        verification_key: key.verifying_key().as_bytes().to_vec(),
    }
}

async fn prepare_inner(pool: &PgPool, label: &str) -> FrankingFixture {
    use arkret_models_crypto::{
        EventContentPreEncryptionHeader, EventContentRoutingContext, MlsGovernanceBindingPayload,
    };
    use arkret_wire::EncryptedPayloadScheme;
    // Scenario labels also seed the Realm and may contain colon separators;
    // the principal's local ID must use the closed inception grammar.
    let human_label = format!("franking-{}", &arkret_canonical::sha256_hex(label)[..16]);
    let account = Box::pin(human_profile::admit(
        pool,
        &ordinary_realm::station(),
        &human_label,
    ))
    .await;
    let fixture = human_profile::fixture(&ordinary_realm::station(), &human_label);
    assert_eq!(account, fixture.history.account);
    let actor = ActorId::account(account.clone());
    let did = human_profile::station_did(&ordinary_realm::station());
    let method = arkret_wire::DidUrl::new(format!("{did}#authority")).unwrap();
    let key = SigningKey::from_bytes(&device_authorization_history::STATION_AUTHORITY_SEED);
    let app = coland_services::authority_commit::AuthorityCommitApplication::new(
        coland_services::persistence::PersistenceHandle::new(Arc::new(PgPersistenceStore::new(
            pool.clone(),
        ))),
        0,
    );
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let unit = ordinary_realm::bootstrap_unit_for_account(label, &account, &did);
    let at = unit.transactions[0].commit.committed_at;
    let mut submission = unit.submission.clone();
    for submitted in &mut submission.events {
        submitted.event = device_authorization_history::sign_event(
            submitted.event.clone(),
            fixture.history.device_verification_method.clone(),
            fixture.history.founding_device_signing_seed,
        );
    }
    let body=serde_json::to_vec(&arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequest::OrdinaryRealmBootstrap(submission.clone())).unwrap();
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
    store
        .admit_ordinary_realm_bootstrap_unit(&unit, at)
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
        .prepare_self_event_transaction(
            &strand,
            &ordinary_realm::station(),
            method.clone(),
            &key,
            at,
        )
        .await
        .unwrap();
    request.realm_fanout_source = Some(arkret_wire::EventAdmissionSubmission::new(strand.clone()));
    uow.commit_event(request.clone()).await.unwrap();
    previous = request.authority_commit;
    let mut group = arkret_mls::ArkretMlsIdentity::new_test_human_device(
        actor.clone(),
        fixture.history.founding_device_id.clone(),
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
                leaf_signature_key_b64u: leaves[0].signature_key.clone(),
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
                member_principals: group.member_actor_ids().unwrap().into_iter().collect(),
                consumed_proposals: Vec::new(),
                public_blobs: Vec::new(),
            },
            Vec::new(),
            &ordinary_realm::station(),
            method.clone(),
            &key,
            at,
        )
        .await
        .unwrap();
    request.realm_fanout_source = Some(arkret_wire::EventAdmissionSubmission::new(genesis.clone()));
    uow.commit_event(request.clone()).await.unwrap();
    previous = request.authority_commit;
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
    let received_at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    let target = seal(ordinary_realm::event_for_actor(
        EventKind::MessageCreate,
        scope.clone(),
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
            &ordinary_realm::station(),
            method.clone(),
            &key,
            received_at,
        )
        .await
        .unwrap();
    request.realm_fanout_source = Some(arkret_wire::EventAdmissionSubmission::new(target.clone()));
    uow.commit_event(request.clone()).await.unwrap();
    let accepted_target = request;
    let jobs = store
        .pending_franking_proofs(&ordinary_realm::station())
        .await
        .unwrap();
    assert_eq!(jobs.len(), 1);
    let job = &jobs[0];
    assert_eq!(job.received_at, received_at);
    assert!(target.created_at < job.received_at);
    let candidate = prepared(job, 1, method.clone(), &key);
    let fixed = store.fix_franking_proof(&candidate).await.unwrap();
    let proof_payload =
        serde_json::from_value(serde_json::to_value(&fixed.payload).unwrap()).unwrap();
    let prefix_at = received_at + chrono::TimeDelta::microseconds(1);
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
            b"{\"kind\":\"ak.content.text\",\"body\":\"atomic prefix\",\"format\":\"plain\"}",
        )
        .unwrap()
        .to_envelope()
        .unwrap();
    let prefix_event = seal(ordinary_realm::event_for_actor(
        EventKind::MessageCreate,
        scope,
        actor,
        serde_json::json!({"strand_id":arkret_wire::StrandId::from_event_id(&strand.event_id),
            "track_name":"discussion","encrypted_content":encrypted}),
        prefix_at,
    ));
    let mut prefix = ordinary_realm::request_for_event(
        &accepted_target.authority_commit,
        prefix_event.clone(),
        prefix_at,
    );
    prefix.realm_fanout_source = Some(arkret_wire::EventAdmissionSubmission::new(prefix_event));
    let prefix = Box::pin(ordinary_realm::source_request(pool, prefix)).await;
    let mut proof =
        ordinary_realm::request_for_event(&prefix.authority_commit, fixed.clone(), prefix_at);
    proof.realm_fanout_source = Some(arkret_wire::EventAdmissionSubmission::new(fixed.clone()));
    let proof = Box::pin(ordinary_realm::source_request(pool, proof)).await;
    assert_eq!(
        store
            .pending_franking_proofs(&ordinary_realm::station())
            .await
            .unwrap()[0]
            .prepared_event,
        Some(fixed)
    );
    FrankingFixture {
        accepted_target,
        prefix,
        proof,
        proof_payload,
        service_signing_key: key,
    }
}
