#[path = "support/historical_human.rs"]
mod historical_human;

use arkret_models_identity::{HistoricalSignerKeyQuerySender, SignerKeyQuerySelector};
use arkret_wire::{CommittedEventRef, Did};
use coland_storage::{
    AuthorityCommitStore, AuthorityCommitWriteOutcome, DeviceRevocationStore,
    EventCommitUnitOfWork, SelfProducerCommitGuard,
};
use coland_storage_postgres::test_database::TestDatabase;
use coland_storage_postgres::{
    PgAuthorityCommitStore, PgDeviceRevocationStore, PgEventCommitUnitOfWork,
};
use diesel::sql_types::BigInt;
use diesel_async::RunQueryDsl;

#[derive(diesel::QueryableByName, Debug, PartialEq)]
struct Footprint {
    #[diesel(sql_type = BigInt)]
    events: i64,
    #[diesel(sql_type = BigInt)]
    commits: i64,
    #[diesel(sql_type = BigInt)]
    keys: i64,
    #[diesel(sql_type = BigInt)]
    full_source_facts: i64,
    #[diesel(sql_type = BigInt)]
    federation_outbox: i64,
    #[diesel(sql_type = BigInt)]
    event_outbox: i64,
}
async fn footprint(pool: &coland_storage_postgres::PgPool) -> Footprint {
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query("SELECT (SELECT count(*) FROM canonical_events) AS events,(SELECT count(*) FROM realm_commits) AS commits,(SELECT count(*) FROM agent_producer_signer_keys) AS keys,(SELECT count(*) FROM agent_producer_signer_keys WHERE producer_source_fact IS NOT NULL) AS full_source_facts,(SELECT count(*) FROM federation_outbox) AS federation_outbox,(SELECT count(*) FROM event_federation_outbox) AS event_outbox")
        .get_result(&mut *conn).await.unwrap()
}

#[tokio::test]
async fn historical_human_true_signature_atomic_bootstrap_and_exact_coordinate() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let fixture = historical_human::HumanFixture::new(
        &pool,
        Did::new("did:web:human-history.example").unwrap(),
    )
    .await;
    fixture.admit(&pool).await;
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    // Every atomic bootstrap producer was frozen, including its RealmCreate.
    for transaction in &fixture.unit.transactions {
        let original = store
            .account_device_signer_fact(&transaction.event, &transaction.commit)
            .await
            .unwrap();
        assert_eq!(
            original.clone().map(Into::into),
            transaction.producer_signer_fact,
            "cold original-source getter retains every complete immutable field"
        );
        let full = arkret_wire::CommittedEventFullView {
            event: transaction.event.clone(),
            commit: transaction.commit.clone(),
        };
        original
            .as_ref()
            .unwrap()
            .validate_commit_binding(&full, arkret_canonical::DigestSuite::Sha256)
            .unwrap();
        arkret_identity::account_device_signer_evidence::verify_historical_account_device_event_signature(
            &full.event,
            original.as_ref().unwrap(),
            arkret_canonical::DigestSuite::Sha256,
        )
        .unwrap();
        let result = store
            .historical_producer_signer_key(
                &transaction.event.realm_id,
                &fixture.selector(transaction),
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            result.key().unwrap().authorization_ref,
            fixture.guard.authorization_ref
        );
        assert_eq!(
            result.accepted_at(),
            Some(fixture.pcr.unit.transactions[1].commit.committed_at)
        );
        assert_eq!(
            result.key().unwrap().revision.commit_id,
            fixture.pcr.unit.transactions[1].commit.commit_id
        );
        assert_ne!(
            result
                .key()
                .unwrap()
                .authorization_ref
                .stream_ref
                .realm_id(),
            &transaction.event.realm_id
        );
    }
    let ordinary_target = fixture.unit.transactions.last().unwrap();
    assert!(
        store
            .historical_self_pcr_producer_signer_key(
                &ordinary_target.event.realm_id,
                &fixture.selector(ordinary_target),
                &fixture.pcr.history.account
            )
            .await
            .unwrap()
            .is_none(),
        "ordinary facts cannot enter the PCR exception or bypass their reader floor"
    );
    for registration in &fixture.pcr.unit.transactions {
        assert!(
            store
                .historical_self_pcr_producer_signer_key(
                    &registration.event.realm_id,
                    &fixture.selector(registration),
                    &fixture.pcr.history.account
                )
                .await
                .unwrap()
                .is_none(),
            "early registration must not synthesize missing original authorization history"
        );
    }
    let head = fixture.unit.transactions.last().unwrap();
    let bad = fixture.next(head, [0x7f; 32]);
    let before = footprint(&pool).await;
    let error = PgEventCommitUnitOfWork::new(pool.clone())
        .commit_event(bad)
        .await
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("Account Device historical producer signature differs"),
        "wrong Ed key must reach the genuine proof gate: {error}"
    );
    assert_eq!(
        footprint(&pool).await,
        before,
        "bad proof rolls back Event, Commit and frozen key"
    );
    let valid = fixture.next(head, fixture.pcr.history.founding_device_signing_seed);
    PgEventCommitUnitOfWork::new(pool.clone())
        .commit_event(valid.clone())
        .await
        .unwrap();
    let selector = fixture.selector(&valid.authority_commit);
    let frozen = store
        .historical_producer_signer_key(&head.event.realm_id, &selector)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        store
            .admit_self_event_transaction(
                &valid.authority_commit,
                &SelfProducerCommitGuard::HumanDevice(fixture.guard.clone()),
                valid.authority_commit.commit.committed_at
            )
            .await
            .unwrap(),
        AuthorityCommitWriteOutcome::Duplicate
    );
    let mut wrong = selector.clone();
    if let SignerKeyQuerySelector::HistoricalEvent {
        sender:
            HistoricalSignerKeyQuerySender::AccountDevice {
                committed_event_ref,
                ..
            },
    } = &mut wrong
    {
        committed_event_ref.stream_position += 1;
    }
    assert!(
        store
            .historical_producer_signer_key(&head.event.realm_id, &wrong)
            .await
            .unwrap()
            .is_none()
    );
    let mut foreign = selector.clone();
    if let SignerKeyQuerySelector::HistoricalEvent {
        sender: HistoricalSignerKeyQuerySender::AccountDevice { actor, .. },
    } = &mut foreign
    {
        let mut account = actor.as_account_id().unwrap().clone();
        account.station_id =
            arkret_wire::DidCoreId::new("ak:did_core:web:foreign.example").unwrap();
        *actor = arkret_wire::ActorId::account(account);
    }
    assert!(
        store
            .historical_producer_signer_key(&head.event.realm_id, &foreign)
            .await
            .unwrap()
            .is_none(),
        "foreign source coordinates cannot be inferred from a local frozen key"
    );
    drop(store);
    let reopened = PgAuthorityCommitStore { pool: pool.clone() };
    assert_eq!(
        reopened
            .historical_producer_signer_key(&head.event.realm_id, &selector)
            .await
            .unwrap(),
        Some(frozen)
    );
}

#[tokio::test]
async fn historical_human_frozen_fact_survives_current_device_gate_revocation() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let fixture = historical_human::HumanFixture::new(
        &pool,
        Did::new("did:web:human-history-revoke.example").unwrap(),
    )
    .await;
    fixture.admit(&pool).await;
    let transaction = fixture.unit.transactions.last().unwrap();
    let selector = fixture.selector(transaction);
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    let frozen = store
        .historical_producer_signer_key(&transaction.event.realm_id, &selector)
        .await
        .unwrap()
        .unwrap();
    // This test exercises the real durable terminal gate, rather than claiming
    // to execute the separate complete SecurityRotation ceremony.
    PgDeviceRevocationStore { pool: pool.clone() }
        .commit_revocation(&coland_storage::DeviceRevocationTransition {
            selector: fixture.guard.clone(),
            revoke_ref: CommittedEventRef {
                event_id: arkret_wire::EventId::from_digest(
                    arkret_canonical::DigestSuite::Sha256,
                    [0x70; 32],
                ),
                commit_id: arkret_wire::RealmCommitId::from_digest([0x71; 32]),
                stream_ref: fixture.guard.authorization_ref.stream_ref.clone(),
                stream_position: fixture.guard.authorization_ref.stream_position + 1,
            },
            committed_at: transaction.commit.committed_at,
        })
        .await
        .unwrap();
    let before = footprint(&pool).await;
    let fresh = fixture.next(
        transaction,
        fixture.pcr.history.founding_device_signing_seed,
    );
    assert!(
        store
            .admit_self_event_transaction(
                &fresh.authority_commit,
                &SelfProducerCommitGuard::HumanDevice(fixture.guard.clone()),
                fresh.authority_commit.commit.committed_at
            )
            .await
            .is_err(),
        "revoked endpoint cannot authorize a fresh producer"
    );
    assert_eq!(footprint(&pool).await, before);
    assert!(
        matches!(
            store
                .admit_self_event_transaction(
                    transaction,
                    &SelfProducerCommitGuard::HumanDevice(fixture.guard.clone()),
                    transaction.commit.committed_at
                )
                .await
                .unwrap(),
            AuthorityCommitWriteOutcome::Duplicate
        ),
        "exact accepted original is returned without today's revoked key gate"
    );
    assert_eq!(
        footprint(&pool).await,
        before,
        "exact retry writes no historical repair"
    );
    let reopened = PgAuthorityCommitStore { pool: pool.clone() };
    assert_eq!(
        reopened
            .historical_producer_signer_key(&transaction.event.realm_id, &selector)
            .await
            .unwrap(),
        Some(frozen),
        "historical authorization remains frozen after current revocation"
    );
}

#[tokio::test]
async fn historical_human_locked_full_source_equality_rejects_resigned_substitutions_without_writes()
 {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let fixture = historical_human::HumanFixture::new(
        &pool,
        Did::new("did:web:human-source-equality.example").unwrap(),
    )
    .await;
    fixture.admit(&pool).await;
    let head = fixture.unit.transactions.last().unwrap();
    let original = fixture.next(head, fixture.pcr.history.founding_device_signing_seed);
    let before = footprint(&pool).await;
    // Each changed fact is actually digested, given a new correct Commit ID
    // and re-signed. Rejection therefore tests the locked original-source
    // comparison, rather than merely a stale content ID or forged signature.
    for variant in 0..4 {
        let mut request = original.clone();
        let fact = request
            .authority_commit
            .producer_signer_fact
            .as_mut()
            .and_then(|fact| fact.as_account_device_mut())
            .unwrap();
        match variant {
            0 => {
                fact.key.revision.stream_position += 1;
                fact.key.revision.commit_id = arkret_wire::RealmCommitId::from_digest([0x9b; 32]);
            }
            1 => fact.key.governance_generation += 1,
            2 => fact.accepted_at += chrono::TimeDelta::seconds(1),
            3 => {
                fact.key.authorization_ref.event_id = arkret_wire::EventId::from_digest(
                    arkret_canonical::DigestSuite::Sha256,
                    [0x9c; 32],
                )
            }
            _ => unreachable!(),
        }
        request.authority_commit.commit.producer_signer_fact_digest = Some(fact.digest().unwrap());
        historical_human::seal_commit(
            &mut request.authority_commit.commit,
            &fixture.pcr.history.station_did,
        );
        assert!(
            PgEventCommitUnitOfWork::new(pool.clone())
                .commit_event(request)
                .await
                .is_err(),
            "variant {variant}"
        );
        assert_eq!(
            footprint(&pool).await,
            before,
            "variant {variant} must leave zero writes"
        );
    }
    PgEventCommitUnitOfWork::new(pool.clone())
        .commit_event(original)
        .await
        .unwrap();
}

#[tokio::test]
async fn peer_full_scan_carries_each_original_fact_and_never_repairs_missing_archive() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let fixture = historical_human::HumanFixture::new(
        &pool,
        Did::new("did:web:human-peer-facts.example").unwrap(),
    )
    .await;
    fixture.admit(&pool).await;
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    let head = fixture.unit.transactions.last().unwrap();
    let issuer = fixture.pcr.history.account.station_id.clone();
    // Existing PG interval tests also use the actual joined Account's Station
    // as peer and issuer. This tests the genuine authorization/read port;
    // it is not an HTTP federation authentication or live cold-scan claim.
    let request = arkret_wire::StreamScanRequest {
        realm_id: head.event.realm_id.clone(),
        stream_ref: head.commit.stream_ref.clone(),
        direction: arkret_wire::StreamScanDirection::After(None),
        limit: 32,
    };
    let coland_storage::PeerStreamScan::Page(page) = store
        .scan_stream_for_peer(&request, &issuer, &issuer)
        .await
        .unwrap()
    else {
        panic!("actual joined Station has a peer read interval");
    };
    page.validate_for_request(&request).unwrap();
    let full = page
        .committed_events
        .iter()
        .filter_map(|row| match row {
            arkret_wire::CommittedEventView::Full(view) => Some(view),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert!(
        !full.is_empty(),
        "positive reader must disclose actual Full bytes"
    );
    assert_eq!(page.producer_signer_facts.len(), full.len());
    for (row, entry) in full.iter().zip(&page.producer_signer_facts) {
        assert_eq!(entry.target.event_id, row.event.event_id);
        assert_eq!(entry.target.commit_id, row.commit.commit_id);
        assert_eq!(entry.target.stream_ref, row.commit.stream_ref);
        assert_eq!(entry.target.stream_position, row.commit.stream_position);
        assert_eq!(
            entry.producer_signer_fact.as_account_device().cloned(),
            store
                .account_device_signer_fact(&row.event, &row.commit)
                .await
                .unwrap()
        );
        arkret_identity::account_device_signer_evidence::verify_historical_account_device_event_signature(
            &row.event,
            entry.producer_signer_fact.as_account_device().unwrap(),
            arkret_canonical::DigestSuite::Sha256,
        )
        .unwrap();
    }
    let missing_commit = full[0].commit.commit_id.clone();
    let mut conn = pool.get().await.unwrap();
    // Deliberately damaged test database: current PCR and the signed Commit
    // remain intact. The read must fail instead of reconstructing provenance.
    diesel::sql_query(
        "UPDATE agent_producer_signer_keys SET producer_source_fact=NULL WHERE commit_id=$1",
    )
    .bind::<diesel::sql_types::Text, _>(missing_commit.as_str())
    .execute(&mut *conn)
    .await
    .unwrap();
    drop(conn);
    let before = footprint(&pool).await;
    assert!(
        store
            .scan_stream_for_peer(&request, &issuer, &issuer)
            .await
            .is_err()
    );
    assert_eq!(footprint(&pool).await, before);
    let mut conn = pool.get().await.unwrap();
    #[derive(diesel::QueryableByName)]
    struct Missing {
        #[diesel(sql_type=diesel::sql_types::Bool)]
        absent: bool,
    }
    let row = diesel::sql_query("SELECT producer_source_fact IS NULL AS absent FROM agent_producer_signer_keys WHERE commit_id=$1")
        .bind::<diesel::sql_types::Text,_>(missing_commit.as_str()).get_result::<Missing>(&mut *conn).await.unwrap();
    assert!(
        store
            .historical_producer_signer_key(
                &full[0].event.realm_id,
                &fixture.selector(
                    fixture
                        .unit
                        .transactions
                        .iter()
                        .find(|t| t.commit.commit_id == missing_commit)
                        .unwrap()
                )
            )
            .await
            .unwrap()
            .is_none(),
        "historical query also requires complete original source, not merely its old key outcome"
    );
    assert!(
        row.absent,
        "a read never repairs a missing original from current PCR"
    );
}

#[tokio::test]
async fn production_uow_exact_accepted_retry_precedes_current_revocation_and_never_rewrites() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let fixture = historical_human::HumanFixture::new(
        &pool,
        Did::new("did:web:human-exact-uow.example").unwrap(),
    )
    .await;
    fixture.admit(&pool).await;
    let request = fixture.next(
        fixture.unit.transactions.last().unwrap(),
        fixture.pcr.history.founding_device_signing_seed,
    );
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    assert!(
        uow.commit_event(request.clone())
            .await
            .unwrap()
            .event_inserted
    );
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    let original_fact = store
        .account_device_signer_fact(
            &request.authority_commit.event,
            &request.authority_commit.commit,
        )
        .await
        .unwrap();
    PgDeviceRevocationStore { pool: pool.clone() }
        .commit_revocation(&coland_storage::DeviceRevocationTransition {
            selector: fixture.guard.clone(),
            revoke_ref: CommittedEventRef {
                event_id: arkret_wire::EventId::from_digest(
                    arkret_canonical::DigestSuite::Sha256,
                    [0xa7; 32],
                ),
                commit_id: arkret_wire::RealmCommitId::from_digest([0xa8; 32]),
                stream_ref: fixture.guard.authorization_ref.stream_ref.clone(),
                stream_position: fixture.guard.authorization_ref.stream_position + 1,
            },
            committed_at: request.authority_commit.commit.committed_at,
        })
        .await
        .unwrap();
    let before = footprint(&pool).await;
    let replay = uow.commit_event(request.clone()).await.unwrap();
    assert!(!replay.event_inserted);
    assert_eq!(replay.projections_inserted, 0);
    assert_eq!(replay.outbox_inserted, 0);
    assert_eq!(footprint(&pool).await, before);
    assert_eq!(
        store
            .account_device_signer_fact(
                &request.authority_commit.event,
                &request.authority_commit.commit
            )
            .await
            .unwrap(),
        original_fact
    );
    // A changed original Commit is not an exact accepted witness, even when
    // the caller re-signs it using the same real Station fixture key.
    let mut changed = request;
    changed.authority_commit.commit.committed_at += chrono::TimeDelta::milliseconds(1);
    historical_human::seal_commit(
        &mut changed.authority_commit.commit,
        &fixture.pcr.history.station_did,
    );
    assert!(uow.commit_event(changed).await.is_err());
    assert_eq!(footprint(&pool).await, before);
}

#[tokio::test]
async fn withheld_full_upgrade_atomically_retains_original_human_fact_without_head_or_current_rewrite()
 {
    use coland_storage::{
        CommittedChainNode, CommittedReplica, CommittedReplicaOutcome, CommittedReplicaRole,
        ReplicaAnchorInstall,
    };
    let mut source_config = coland_test_support::app_config();
    source_config.public_base_url = "https://full-upgrade-governance.example".into();
    let (source_state, pool) = coland_test_support::app_state_with_pool(source_config);
    let mut member_config = coland_test_support::app_config();
    member_config.public_base_url = "https://full-upgrade-member.example".into();
    let (member_state, member_pool) = coland_test_support::app_state_with_pool(member_config);
    let source = historical_human::HumanFixture::new(&pool, source_state.service_did()).await;
    source.admit(&pool).await;
    // The foreign PCR is accepted only by its true Origin; governance receives
    // the registered fresh whole forward evidence, never a foreign devices row.
    let joining =
        historical_human::HumanFixture::new(&member_pool, member_state.service_did()).await;
    let member_account = joining.pcr.history.account.clone();
    let previous = source.unit.transactions.last().unwrap();
    let at = previous.commit.committed_at + chrono::TimeDelta::seconds(1);
    let actor = arkret_wire::ActorId::account(member_account.clone());
    let event = historical_human::signed_ordinary_event(
        &joining,
        previous,
        arkret_wire::EventKind::MemberState,
        serde_json::json!({"realm_id":previous.event.realm_id,"member_id":actor,"membership":"join","reason":"true source upgrade reader"}),
        at,
    );
    let mut join = historical_human::request_for_event(&joining, previous, event, at);
    let evidence = coland_http::test_fresh_producer_device_evidence(
        &member_state,
        &join.authority_commit.event,
        &source.pcr.history.account.station_id,
    )
    .await
    .unwrap()
    .unwrap();
    let core = &evidence.device_projection_attestation.attestation;
    let fact = arkret_identity::account_device_signer_evidence::verify_forwarded_account_device_signer_fact(
        &evidence,
        &join.authority_commit.event,
        &member_account.station_id,
        &source.pcr.history.account.station_id,
        &core.event_authorization.forward_body_digest,
        arkret_canonical::DigestSuite::Sha256,
        core.attested_at,
    )
    .unwrap()
    .into_fact();
    join.authority_commit.producer_signer_fact = Some(fact.clone().into());
    join.authority_commit.commit.producer_signer_fact_digest = Some(fact.digest().unwrap());
    join.authority_commit.commit.committed_at = core.attested_at;
    join.self_producer_guard = None;
    join.forwarded_producer_evidence =
        Some(coland_storage::ForwardedProducerDeviceEvidence::new(evidence, fact).unwrap());
    // The author is the member; the governance Station seals the actual target.
    historical_human::seal_commit(
        &mut join.authority_commit.commit,
        &source.pcr.history.station_did,
    );
    join.realm_fanout_source = Some(arkret_wire::EventAdmissionSubmission::new(
        join.authority_commit.event.clone(),
    ));
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    uow.commit_event(join.clone()).await.unwrap();
    let source_store = PgAuthorityCommitStore { pool: pool.clone() };
    let member = PgAuthorityCommitStore {
        pool: member_pool.clone(),
    };
    let authority = join.authority_commit.expected_authority.clone();
    let replica = |request: &coland_storage::EventCommitRequest, role| CommittedReplica {
        local_service_id: member_account.station_id.clone(),
        authority: authority.clone(),
        historical_commit: None,
        event: request.authority_commit.event.clone(),
        commit: request.authority_commit.commit.clone(),
        producer_signer_fact: request.authority_commit.producer_signer_fact.clone(),
        role,
        genesis_event_ref: None,
        welcomes: Vec::new(),
        received_at: request.authority_commit.commit.committed_at,
    };
    assert_eq!(
        member
            .install_committed_replica(&replica(
                &join,
                CommittedReplicaRole::OpeningJoin {
                    member_account_id: member_account.clone()
                }
            ))
            .await
            .unwrap(),
        CommittedReplicaOutcome::Stored
    );
    let anchor = |material: coland_storage::RealmStateSnapshotMaterial| {
        let key =
            ed25519_dalek::SigningKey::from_bytes(&historical_human::station_authority_seed());
        let snapshot = coland_services::authority_commit::build_signed_realm_state_snapshot(
            &material,
            arkret_wire::DidUrl::new(format!("{}#authority", source.pcr.history.station_did))
                .unwrap(),
            &key,
            chrono::Utc::now(),
        )
        .unwrap();
        arkret_signatures::detached_object::verify_detached_object_signature(
            &snapshot.signature,
            &arkret_canonical::canonical::unsigned_value(&snapshot, &["signature"]).unwrap(),
            arkret_wire::DetachedSignatureContext::RealmSnapshot,
            &arkret_signatures::PublicKeyMaterial::Ed25519Raw {
                bytes: key.verifying_key().to_bytes().to_vec(),
            },
        )
        .unwrap();
        ReplicaAnchorInstall {
            realm_id: material.realm_id,
            join_commit_id: join.authority_commit.commit.commit_id.clone(),
            governance_generation: material.governance_generation,
            snapshot_head: material.visible_stream_heads[0].clone(),
            visible_stream_heads: material.visible_stream_heads,
            current_state_entries: material.current_state_entries,
            verified_snapshot: snapshot,
        }
    };
    let material = source_store
        .member_station_bootstrap_material(
            &previous.event.realm_id,
            &member_account,
            &join.authority_commit.commit.commit_id,
        )
        .await
        .unwrap()
        .unwrap();
    member
        .install_replica_anchor(&anchor(material))
        .await
        .unwrap();
    let mut target = source.next(
        &join.authority_commit,
        source.pcr.history.founding_device_signing_seed,
    );
    target.realm_fanout_source = Some(arkret_wire::EventAdmissionSubmission::new(
        target.authority_commit.event.clone(),
    ));
    uow.commit_event(target.clone()).await.unwrap();
    let original_fact = source_store
        .account_device_signer_fact(
            &target.authority_commit.event,
            &target.authority_commit.commit,
        )
        .await
        .unwrap()
        .unwrap();
    member
        .install_committed_chain_node(&CommittedChainNode {
            local_service_id: member_account.station_id.clone(),
            authority: authority.clone(),
            historical_commit: None,
            commit: target.authority_commit.commit.clone(),
        })
        .await
        .unwrap();
    // Before the snapshot covers this effect, upgrading must roll back all bytes/facts.
    let full = replica(&target, CommittedReplicaRole::HeldStream);
    let before = footprint(&member_pool).await;
    assert!(member.install_committed_replica(&full).await.is_err());
    assert_eq!(footprint(&member_pool).await, before);
    let material = source_store
        .member_station_bootstrap_material(
            &previous.event.realm_id,
            &member_account,
            &join.authority_commit.commit.commit_id,
        )
        .await
        .unwrap()
        .unwrap();
    member
        .install_replica_anchor(&anchor(material))
        .await
        .unwrap();
    let head_before = member
        .stream_head(&target.authority_commit.commit.stream_ref)
        .await
        .unwrap();
    let current_before = member
        .realm_state_snapshot_material(&previous.event.realm_id)
        .await
        .unwrap();
    assert_eq!(
        member.install_committed_replica(&full).await.unwrap(),
        CommittedReplicaOutcome::Stored
    );
    assert_eq!(
        member
            .committed_event(&target.authority_commit.event.event_id)
            .await
            .unwrap()
            .unwrap()
            .event,
        target.authority_commit.event
    );
    assert_eq!(
        member
            .account_device_signer_fact(
                &target.authority_commit.event,
                &target.authority_commit.commit
            )
            .await
            .unwrap(),
        Some(original_fact.clone())
    );
    assert_eq!(
        member
            .stream_head(&target.authority_commit.commit.stream_ref)
            .await
            .unwrap(),
        head_before
    );
    assert_eq!(
        member
            .realm_state_snapshot_material(&previous.event.realm_id)
            .await
            .unwrap(),
        current_before
    );
    let before = footprint(&member_pool).await;
    assert_eq!(
        member.install_committed_replica(&full).await.unwrap(),
        CommittedReplicaOutcome::Duplicate
    );
    let mut changed = full;
    changed
        .producer_signer_fact
        .as_mut()
        .and_then(|fact| fact.as_account_device_mut())
        .unwrap()
        .accepted_at += chrono::TimeDelta::seconds(1);
    assert!(member.install_committed_replica(&changed).await.is_err());
    assert_eq!(footprint(&member_pool).await, before);
}

mod forward_retention {
    //! Real accepted source originals retained as non-authoritative forwarding
    //! witnesses. These PG ports do not establish peer HTTP authority verification.
    use arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequest;
    use arkret_wire::{Did, EventAdmissionSubmission};
    use coland_storage::{AuthorityCommitStore, ForwardAttemptStatus, QueuedEventStatus};
    use coland_storage_postgres::test_database::TestDatabase;
    use coland_storage_postgres::{PgAuthorityCommitStore, PgPool};
    use diesel::sql_query;
    use diesel::sql_types::Jsonb;
    use diesel_async::RunQueryDsl;

    use super::historical_human;

    #[derive(diesel::QueryableByName)]
    struct InstalledFootprint {
        #[diesel(sql_type = Jsonb)]
        value: serde_json::Value,
    }

    async fn installed(pool: &PgPool) -> serde_json::Value {
        let mut conn = pool.get().await.unwrap();
        sql_query("SELECT jsonb_build_object(        'commits',(SELECT count(*) FROM realm_commits),        'authorities',(SELECT count(*) FROM realm_authorities),        'anchors',(SELECT count(*) FROM replica_stream_anchors),'cuts',(SELECT count(*) FROM replica_authorization_cuts),'rows',(SELECT count(*) FROM replica_authorization_rows),'current_heads',(SELECT count(*) FROM current_result_heads),        'snapshots',(SELECT count(*) FROM realm_state_snapshots),        'members',(SELECT count(*) FROM member_state_current_results),        'facts',(SELECT count(*) FROM agent_producer_signer_keys),        'outbox',(SELECT count(*) FROM federation_outbox)) AS value")
            .get_result::<InstalledFootprint>(&mut *conn).await.unwrap().value
    }

    #[tokio::test]
    async fn genuine_accepted_originals_reopen_without_installing_or_overwriting_forward_witness() {
        let source_db = TestDatabase::lease().await;
        let source_pool = source_db.pool();
        let source = historical_human::HumanFixture::new(
            &source_pool,
            Did::new("did:web:forward-source.example").unwrap(),
        )
        .await;
        source.admit(&source_pool).await;
        let governor = PgAuthorityCommitStore {
            pool: source_pool.clone(),
        };
        let origin_db = TestDatabase::lease().await;
        let pool = origin_db.pool();
        let store = PgAuthorityCommitStore { pool: pool.clone() };
        let before = installed(&pool).await;
        assert!(
            before
                .as_object()
                .unwrap()
                .values()
                .all(|v| v == &serde_json::json!(0))
        );
        for transaction in &source.unit.transactions {
            let original = governor
                .committed_event(&transaction.event.event_id)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(original.event, transaction.event);
            assert_eq!(original.commit, transaction.commit);
            let intent = SelfAuthoritySubmitRequest::Event(EventAdmissionSubmission::new(
                original.event.clone(),
            ));
            store
                .queue_event(&original.event, original.commit.committed_at)
                .await
                .unwrap();
            let missing_intent = store
                .retain_forwarded_acceptance(
                    &original.event,
                    &original.commit,
                    original.commit.committed_at,
                )
                .await
                .unwrap_err();
            assert_eq!(
                missing_intent.conflict_code(),
                Some(coland_storage::ConflictCode::DuplicateConflict)
            );
            assert!(
                store
                    .queued_event(&original.event.event_id)
                    .await
                    .unwrap()
                    .unwrap()
                    .forward_attempt
                    .is_none()
            );
            assert_eq!(installed(&pool).await, before);
            store
                .retain_forwarded_submission(&original.event, &intent, original.commit.committed_at)
                .await
                .unwrap();
            store
                .retain_forwarded_acceptance(
                    &original.event,
                    &original.commit,
                    original.commit.committed_at,
                )
                .await
                .unwrap();
            drop(original);
            let reopened = PgAuthorityCommitStore { pool: pool.clone() };
            let queued = reopened
                .queued_event(&transaction.event.event_id)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(queued.status, QueuedEventStatus::Queued);
            assert!(queued.committed.is_none());
            let attempt = queued.forward_attempt.unwrap();
            assert_eq!(attempt.original_submission, Some(intent.clone()));
            assert_eq!(attempt.accepted_commit, Some(transaction.commit.clone()));
            assert_eq!(attempt.status, ForwardAttemptStatus::Forwarding);
            reopened
                .record_forward_attempt(
                    &transaction.event.event_id,
                    ForwardAttemptStatus::Rejected,
                    Some("not_authorized"),
                    transaction.commit.committed_at,
                )
                .await
                .unwrap();
            let retained = reopened
                .queued_event(&transaction.event.event_id)
                .await
                .unwrap()
                .unwrap()
                .forward_attempt
                .unwrap();
            assert_eq!(retained.original_submission, Some(intent));
            assert_eq!(retained.accepted_commit, Some(transaction.commit.clone()));
            assert_eq!(retained.status, ForwardAttemptStatus::Forwarding);
            assert!(retained.reason_code.is_none());
            let mut fork = transaction.commit.clone();
            fork.committed_at += chrono::TimeDelta::milliseconds(1);
            historical_human::seal_commit(&mut fork, &source.pcr.history.station_did);
            let error = reopened
                .retain_forwarded_acceptance(&transaction.event, &fork, fork.committed_at)
                .await
                .unwrap_err();
            assert_eq!(
                error.conflict_code(),
                Some(coland_storage::ConflictCode::DuplicateConflict)
            );
            let unchanged = reopened
                .queued_event(&transaction.event.event_id)
                .await
                .unwrap()
                .unwrap()
                .forward_attempt
                .unwrap();
            assert_eq!(unchanged, retained);
            let mut wrong_id = transaction.commit.clone();
            wrong_id.commit_id = arkret_wire::RealmCommitId::from_digest([42; 32]);
            assert!(
                reopened
                    .retain_forwarded_acceptance(
                        &transaction.event,
                        &wrong_id,
                        wrong_id.committed_at
                    )
                    .await
                    .is_err()
            );
            assert_eq!(installed(&pool).await, before);
            assert!(
                reopened
                    .committed_event(&transaction.event.event_id)
                    .await
                    .unwrap()
                    .is_none()
            );
        }
        assert_eq!(installed(&pool).await, before);
    }
}
