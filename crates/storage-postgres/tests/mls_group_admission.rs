//! Real PostgreSQL: `ak.mls.genesis` and `ak.mls.commit` install the
//! `mls_group` typed current, the public MLS state and every Welcome in the
//! transaction that commits their Event and RealmCommit, and every refusal
//! leaves zero writes (encryption-and-audit.md §2.2, §2.4.1, §5.1;
//! client-sync.md §10.1).

#[path = "../../test-support/src/device_authorization_history.rs"]
#[allow(dead_code)]
mod device_authorization_history;
#[path = "support/frozen_database.rs"]
mod frozen_database;
#[path = "support/mls_device_revoke_fixture.rs"]
mod mls_device_revoke_fixture;
#[path = "support/mls_local_add_fixture.rs"]
mod mls_local_add_fixture;
#[path = "support/mls_public_fixture.rs"]
mod mls_public_fixture;
#[path = "support/mls_send_content_fixture.rs"]
mod mls_send_content_fixture;
#[path = "support/ordinary_realm.rs"]
#[expect(
    dead_code,
    reason = "Each integration binary uses only its subset of the shared Realm fixture."
)]
mod ordinary_realm;
#[path = "../../test-support/src/pcr_genesis.rs"]
#[allow(dead_code)]
mod pcr_genesis;
#[expect(
    dead_code,
    reason = "This integration uses the shared database support without its contract-schema helpers."
)]
mod support;
use arkret_models_crypto::MlsGovernanceBindingPayload;
use coland_storage::{
    AuthorityCommitStore, ConflictCode, DeviceMessageStore, DeviceRevocationGateSelector,
    EventCommitRequest, EventCommitUnitOfWork, MlsGroupCurrentStore, MlsKeyPackageStore,
    MlsWelcomeClaimLedgerKey, RecipientQueueSelector, VerifiedMlsWelcome,
};
use coland_storage_postgres::test_database::TestDatabase;
use coland_storage_postgres::{
    PgAuthorityCommitStore, PgDeviceMessageStore, PgEventCommitUnitOfWork, PgMlsGroupCurrentStore,
    PgPool,
};
use diesel::sql_types::{BigInt, Binary, Jsonb, Text, Timestamptz};
use diesel_async::RunQueryDsl;
use mls_public_fixture::MlsFixture;

// Complete large Future construction before polling on the default stack.
#[inline(never)]
fn heap_future<F: std::future::Future>(make: impl FnOnce() -> F) -> std::pin::Pin<Box<F>> {
    Box::pin(make())
}

fn realm_scope(realm_id: &arkret_wire::RealmId) -> arkret_wire::ScopeRef {
    arkret_wire::ScopeRef::Realm {
        realm_id: realm_id.clone(),
    }
}

fn welcome(
    commit: &EventCommitRequest,
    recipient: &DeviceRevocationGateSelector,
    claim_id: &str,
) -> arkret_wire::MlsWelcomeDelivery {
    let event = &commit.authority_commit.event;
    arkret_wire::MlsWelcomeDelivery {
        welcome_id: arkret_wire::MlsWelcomeDeliveryId::new(format!(
            "ak:mls_welcome_delivery:{}",
            uuid::Uuid::now_v7()
        ))
        .unwrap(),
        realm_id: event.realm_id.clone(),
        effective_scope: event.scope_ref.clone(),
        commit_event_ref: event.event_id.clone(),
        recipient_actor_id: recipient_actor(recipient),
        recipient_endpoint: arkret_wire::MlsWelcomeRecipientEndpoint::Device {
            device_id: arkret_wire::DeviceId::new(recipient.device_id.clone()).unwrap(),
        },
        keypackage_claim_ref: arkret_wire::KeypackageClaimId::new(claim_id.to_owned()).unwrap(),
        ciphertext_base64url: arkret_wire::Base64UrlString::new("V2VsY29tZQ".to_owned()).unwrap(),
        producer_proof: arkret_wire::DetachedObjectSignature {
            context: arkret_wire::DetachedSignatureContext::MlsWelcomeDelivery,
            signature_algorithm: arkret_wire::DetachedSignatureAlgorithm::Ed25519,
            verification_method: event
                .producer_proof
                .as_ref()
                .unwrap()
                .verification_method
                .clone(),
            signed_digest: arkret_wire::Hash::new(format!("sha256:{}", "5".repeat(64))).unwrap(),
            created_at: commit.authority_commit.commit.committed_at,
            signature: arkret_wire::Base64UrlString::new("c2lnbmF0dXJl".to_owned()).unwrap(),
        },
    }
}

fn recipient_actor(recipient: &DeviceRevocationGateSelector) -> arkret_wire::ActorId {
    arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        recipient.principal_id.clone(),
        recipient.station_id.clone(),
    ))
}

fn claim_id() -> String {
    format!("ak:keypackage_claim:{}", uuid::Uuid::now_v7())
}

/// The recipient joins the Realm as an Invite acceptance would leave it.
async fn join(pool: &PgPool, head: &EventCommitRequest, member: &arkret_wire::ActorId) {
    let basis = &head.authority_commit;
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query(
        "INSERT INTO member_state_current_states \
         (realm_id,member_id,membership,current_commit_id,current_stream_position,value,updated_at) \
         VALUES($1,$2,'join',$3,$4,$5,$6)",
    )
    .bind::<Text, _>(basis.event.realm_id.as_str())
    .bind::<Text, _>(member.to_string())
    .bind::<Text, _>(basis.commit.commit_id.as_str())
    .bind::<BigInt, _>(basis.commit.stream_position as i64)
    .bind::<Jsonb, _>(serde_json::json!({"membership":"join"}))
    .bind::<Timestamptz, _>(basis.commit.committed_at)
    .execute(&mut *conn)
    .await
    .unwrap();
}

async fn local_station(pool: &PgPool) -> arkret_wire::DidCoreId {
    #[derive(diesel::QueryableByName)]
    struct Station {
        #[diesel(sql_type = Text)]
        station_id: String,
    }
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query(
        "INSERT INTO device_inventory_station(singleton,station_id) \
         VALUES(TRUE,$1) ON CONFLICT(singleton) DO NOTHING",
    )
    .bind::<Text, _>(historical_roster_attestor_resolution().service_id.as_str())
    .execute(&mut *conn)
    .await
    .unwrap();
    diesel::sql_query("SELECT station_id FROM device_inventory_station WHERE singleton")
        .get_result::<Station>(&mut *conn)
        .await
        .unwrap()
        .station_id
        .parse()
        .unwrap()
}

/// This Station as the governance Station of every fixture Realm, so an
/// account it hosts is a local member of those Realms.
async fn governing_station(pool: &PgPool) -> arkret_wire::DidCoreId {
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query("INSERT INTO device_inventory_station(singleton,station_id) VALUES(TRUE,$1)")
        .bind::<Text, _>(ordinary_realm::STATION)
        .execute(&mut *conn)
        .await
        .unwrap();
    ordinary_realm::station()
}

async fn welcome_count(pool: &PgPool) -> i64 {
    #[derive(diesel::QueryableByName)]
    struct Count {
        #[diesel(sql_type = BigInt)]
        count: i64,
    }
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query("SELECT COUNT(*) AS count FROM mls_welcome_deliveries")
        .get_result::<Count>(&mut *conn)
        .await
        .unwrap()
        .count
}

async fn provenance_count(pool: &PgPool) -> i64 {
    #[derive(diesel::QueryableByName)]
    struct Count {
        #[diesel(sql_type = BigInt)]
        count: i64,
    }
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query("SELECT COUNT(*) AS count FROM mls_consumed_proposal_provenance")
        .get_result::<Count>(&mut *conn)
        .await
        .unwrap()
        .count
}

/// `request` is refused with `code`; its Event, RealmCommit, group current
/// and Welcomes are all absent.
async fn assert_zero_write_refusal(
    pool: &PgPool,
    request: &EventCommitRequest,
    code: ConflictCode,
) {
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let groups = PgMlsGroupCurrentStore { pool: pool.clone() };
    let scope = &request.authority_commit.event.scope_ref;
    let before = groups.current(scope).await.unwrap();
    let welcomes = welcome_count(pool).await;
    let provenance = provenance_count(pool).await;
    let blobs = coland_storage_postgres::PgBlobStore { pool: pool.clone() };
    let mut public_blobs_before = Vec::new();
    if let Some(installation) = &request.authority_commit.mls_state {
        for blob in &installation.public_blobs {
            let before = coland_storage::BlobStore::get(&blobs, blob.blob_ref.as_str())
                .await
                .unwrap()
                .map(|row| row.storage_key);
            public_blobs_before.push((blob.blob_ref.clone(), before));
        }
    }
    let error = uow.commit_event(request.clone()).await.unwrap_err();
    assert_eq!(error.conflict_code(), Some(code), "{error}");
    assert!(
        PgAuthorityCommitStore { pool: pool.clone() }
            .committed_event(&request.authority_commit.event.event_id)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(groups.current(scope).await.unwrap(), before);
    assert_eq!(welcome_count(pool).await, welcomes);
    assert_eq!(provenance_count(pool).await, provenance);
    for (reference, before) in public_blobs_before {
        let after = coland_storage::BlobStore::get(&blobs, reference.as_str())
            .await
            .unwrap()
            .map(|row| row.storage_key);
        assert_eq!(after, before, "refusal must not register public Blob rows");
    }
}

/// Genesis creates the `mls_group` current at its Commit; a second Genesis
/// is `mls_activation_irreversible`. A Commit merges epoch, current ref and
/// covered revision over the exact base; a stale base or an uncovered
/// key-access revision is `governance_binding_mismatch`, and a non-member
/// committer is `capability_denied`, each with zero writes.
#[tokio::test]
async fn mls_genesis_and_commit_install_the_group_at_their_commits() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let discussion = ordinary_realm::open_discussion(&pool, "mls-group-admission").await;
    let realm_id = discussion.realm_id();
    let scope = realm_scope(&realm_id);
    let founder = discussion
        .head
        .authority_commit
        .event
        .actor_id
        .signing_principal_id()
        .clone();
    let at = discussion.committed_at();
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let groups = PgMlsGroupCurrentStore { pool: pool.clone() };

    let mls = MlsFixture::new(pool.clone(), &discussion.head.authority_commit);

    let genesis = mls.with_installation(
        ordinary_realm::next_request(
            &discussion.head.authority_commit,
            arkret_wire::EventKind::MlsGenesis,
            &founder,
            mls.genesis_payload(&realm_id, at),
            at,
        ),
        None,
        0,
    );
    // Both actual RFC publications are stored atomically with Genesis.
    uow.commit_event(genesis.clone()).await.unwrap();
    let blobs = coland_storage_postgres::PgBlobStore { pool: pool.clone() };
    for blob in &genesis
        .authority_commit
        .mls_state
        .as_ref()
        .unwrap()
        .public_blobs
    {
        let stored = coland_storage::BlobStore::get(&blobs, blob.blob_ref.as_str())
            .await
            .unwrap()
            .expect("the actual publication is stored with the Genesis Commit");
        assert_eq!(stored.storage_key, blob.storage_key);
        assert_eq!(stored.realm_id.as_deref(), Some(realm_id.as_str()));
    }
    let genesis_ref = genesis.authority_commit.event.event_id.clone();
    let installed = groups.current(&scope).await.unwrap().unwrap();
    assert_eq!(
        installed.value,
        arkret_wire::MlsGroupValue {
            effective_scope: scope.clone(),
            genesis_event_ref: genesis_ref.clone(),
            cipher_suite: arkret_wire::NonEmptyString::new(
                "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519"
            )
            .unwrap(),
            current_mls_commit_event_ref: genesis_ref.clone(),
            epoch: 0,
            current_key_access_revision: 0,
            covered_key_access_revision: 0,
            public_tree_ref: genesis
                .authority_commit
                .mls_state
                .as_ref()
                .unwrap()
                .public_blobs[1]
                .blob_ref
                .clone(),
        }
    );
    assert_eq!(
        installed.current_commit_id,
        genesis.authority_commit.commit.commit_id
    );
    assert_eq!(
        installed.public_state,
        genesis
            .authority_commit
            .mls_state
            .as_ref()
            .unwrap()
            .public_state
    );

    let second_genesis = mls.with_installation(
        ordinary_realm::next_request(
            &genesis.authority_commit,
            arkret_wire::EventKind::MlsGenesis,
            &founder,
            mls.genesis_payload(&realm_id, at + chrono::TimeDelta::seconds(1)),
            at + chrono::TimeDelta::seconds(1),
        ),
        None,
        0,
    );
    assert_zero_write_refusal(
        &pool,
        &second_genesis,
        ConflictCode::MlsActivationIrreversible,
    )
    .await;

    let uncovered = mls.with_installation(
        ordinary_realm::next_request(
            &genesis.authority_commit,
            arkret_wire::EventKind::MlsCommit,
            &founder,
            mls.commit_payload(&realm_id, &genesis_ref, 0, 1).await,
            at,
        ),
        Some((&genesis_ref, 0)),
        1,
    );
    assert_zero_write_refusal(&pool, &uncovered, ConflictCode::GovernanceBindingMismatch).await;

    let foreign = Box::pin(mls_local_add_fixture::left_member_commit(&pool)).await;
    assert_zero_write_refusal(&pool, &foreign, ConflictCode::CapabilityDenied).await;

    let commit = mls.with_installation(
        ordinary_realm::next_request(
            &genesis.authority_commit,
            arkret_wire::EventKind::MlsCommit,
            &founder,
            mls.commit_payload(&realm_id, &genesis_ref, 0, 0).await,
            at,
        ),
        Some((&genesis_ref, 0)),
        1,
    );
    uow.commit_event(commit.clone()).await.unwrap();
    let advanced = groups.current(&scope).await.unwrap().unwrap();
    assert_eq!(advanced.value.epoch, 1);
    let tree = &commit
        .authority_commit
        .mls_state
        .as_ref()
        .unwrap()
        .public_blobs[1];
    assert_eq!(advanced.value.public_tree_ref, tree.blob_ref);
    assert_ne!(
        advanced.value.public_tree_ref,
        installed.value.public_tree_ref
    );
    let stored_tree = coland_storage::BlobStore::get(&blobs, tree.blob_ref.as_str())
        .await
        .unwrap()
        .expect("the post-Commit tree row is committed with the current cut");
    assert_eq!(stored_tree.storage_key, tree.storage_key);
    assert_eq!(stored_tree.realm_id.as_deref(), Some(realm_id.as_str()));
    assert_eq!(
        advanced.value.current_mls_commit_event_ref,
        commit.authority_commit.event.event_id
    );
    assert_eq!(advanced.value.genesis_event_ref, genesis_ref);
    for blob in &genesis
        .authority_commit
        .mls_state
        .as_ref()
        .unwrap()
        .public_blobs
    {
        assert!(
            coland_storage::BlobStore::get(&blobs, blob.blob_ref.as_str())
                .await
                .unwrap()
                .is_some(),
            "advancing current preserves both original RFC publications"
        );
    }
    assert_eq!(
        advanced.current_commit_id,
        commit.authority_commit.commit.commit_id
    );
    assert_eq!(
        advanced.public_state,
        commit
            .authority_commit
            .mls_state
            .as_ref()
            .unwrap()
            .public_state
    );
    assert_ne!(advanced.public_state, installed.public_state);

    let stale = mls.with_installation(
        ordinary_realm::next_request(
            &commit.authority_commit,
            arkret_wire::EventKind::MlsCommit,
            &founder,
            mls.commit_payload(&realm_id, &genesis_ref, 0, 0).await,
            at,
        ),
        Some((&genesis_ref, 0)),
        1,
    );
    assert_zero_write_refusal(&pool, &stale, ConflictCode::GovernanceBindingMismatch).await;
    assert_eq!(groups.current(&scope).await.unwrap().unwrap(), advanced);
    let authority_store = PgAuthorityCommitStore { pool: pool.clone() };
    let authority = authority_store
        .current_authority(&realm_id)
        .await
        .unwrap()
        .unwrap();
    let refusal = authority_store
        .finalize_mls_rejection(
            &stale.authority_commit.event,
            &authority,
            "governance_binding_mismatch",
            None,
            None,
        )
        .await
        .unwrap();
    assert!(matches!(
        refusal,
        arkret_wire::AuthoritySubmitResponseBody::Rejected {
            status: arkret_wire::AuthorityRejectionStatus::Rejected,
            ..
        }
    ));
    assert_eq!(
        authority_store
            .finalize_mls_rejection(
                &stale.authority_commit.event,
                &authority,
                "different_late_reason",
                None,
                None,
            )
            .await
            .unwrap(),
        refusal
    );
    assert!(uow.commit_event(stale.clone()).await.is_err());
    assert_eq!(groups.current(&scope).await.unwrap().unwrap(), advanced);
    let mut stale_authority = authority;
    stale_authority.generation += 1;
    let original = authority_store
        .finalize_mls_rejection(
            &commit.authority_commit.event,
            &stale_authority,
            "governance_binding_mismatch",
            None,
            None,
        )
        .await
        .unwrap();
    assert!(
        matches!(original, arkret_wire::AuthoritySubmitResponseBody::Accepted { status: arkret_wire::AuthorityCommitStatus::Duplicate, commit: original } if original == commit.authority_commit.commit)
    );
}

/// The PG unit consumes facts already verified by the serving layer. It does
/// not reparse MLS bytes here; the public tracker test proves their origin.
/// The exact Commit and ordinal remain distinct when Remove+Add restores the
/// same leaf tuple, and an unsuccessful authority CAS inserts no history.
#[tokio::test]
async fn consumed_proposals_freeze_with_winning_commit_and_same_tuple_replacement() {
    #[derive(diesel::QueryableByName)]
    struct ProvenanceRow {
        #[diesel(sql_type = Text)]
        commit_event_ref: String,
        #[diesel(sql_type = BigInt)]
        consumed_proposal_ordinal: i64,
        #[diesel(sql_type = diesel::sql_types::Integer)]
        proposal_type: i32,
        #[diesel(sql_type = Binary)]
        proposal_wire: Vec<u8>,
        #[diesel(sql_type = Jsonb)]
        sender_actor_id: serde_json::Value,
        #[diesel(sql_type = diesel::sql_types::Nullable<Jsonb>)]
        target_before_actor_id: Option<serde_json::Value>,
        #[diesel(sql_type = diesel::sql_types::Nullable<Jsonb>)]
        target_after_actor_id: Option<serde_json::Value>,
    }
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let discussion = ordinary_realm::open_discussion(&pool, "mls-proposal-provenance").await;
    let realm_id = discussion.realm_id();
    let founder = discussion
        .head
        .authority_commit
        .event
        .actor_id
        .signing_principal_id()
        .clone();
    let at = discussion.committed_at();
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let mls = MlsFixture::new(pool.clone(), &discussion.head.authority_commit);
    let genesis = mls.with_installation(
        ordinary_realm::next_request(
            &discussion.head.authority_commit,
            arkret_wire::EventKind::MlsGenesis,
            &founder,
            mls.genesis_payload(&realm_id, at),
            at,
        ),
        None,
        0,
    );
    uow.commit_event(genesis.clone()).await.unwrap();
    let genesis_ref = genesis.authority_commit.event.event_id.clone();
    let recipient_source = pcr_genesis::PcrGenesisFixture::new_with(
        device_authorization_history::did_web_station(&ordinary_realm::station()),
        device_authorization_history::DeviceHistoryFixtureOptions {
            local_id: "mls-provenance-member".into(),
            founding_device_signing_seed: [109; 32],
            ..Default::default()
        },
    );
    let selector = recipient_source
        .admit_founding_device(&coland_storage_postgres::PgPersistenceStore::new(
            pool.clone(),
        ))
        .await
        .unwrap();
    let actor = recipient_actor(&selector);
    join(&pool, &genesis, &actor).await;
    let identity = arkret_mls::ArkretMlsIdentity::new_human_device(
        actor.clone(),
        recipient_source.history.founding_device_id.clone(),
        arkret_mls::ArkretMlsSigner::from_ed25519_signing_key(
            ed25519_dalek::SigningKey::from_bytes(
                &recipient_source.history.founding_device_signing_seed,
            ),
        ),
    )
    .unwrap();
    let claimed = || {
        let mut package = identity.key_package_record().unwrap();
        package.state = arkret_models_crypto::MlsKeyPackageState::Claimed;
        package.claim_id = Some(claim_id());
        package
    };
    let mut group = mls.accepted_private_group(&genesis_ref).await;
    let mut tracker = mls.tracker(&genesis_ref);
    let binding =
        MlsGovernanceBindingPayload::realm(realm_id.clone(), Some(genesis_ref.clone()), 0, 1, 0)
            .unwrap();
    let first_package = claimed();
    let added = group
        .add_member_with_governance_binding(&first_package, &binding)
        .unwrap();
    let first_proposals = mls_public_fixture::consume(&mut tracker, &added.commit);
    mls.register_package(
        &first_package,
        &first_proposals,
        &selector.authorization_ref.event_id,
    );
    let first = mls.transition(
        &genesis.authority_commit,
        group,
        tracker,
        added.commit,
        binding,
        &genesis_ref,
        first_proposals.clone(),
        at,
    );
    uow.commit_event(first.clone()).await.unwrap();
    let first_ref = first.authority_commit.event.event_id.clone();
    let leaf = first_proposals
        .iter()
        .find_map(|p| p.target_after.as_ref())
        .unwrap()
        .clone();

    let mut group = mls.accepted_private_group(&first_ref).await;
    let mut tracker = mls.tracker(&first_ref);
    let binding =
        MlsGovernanceBindingPayload::realm(realm_id.clone(), Some(first_ref.clone()), 1, 2, 0)
            .unwrap();
    let replacement_package = claimed();
    let replaced = group
        .replace_member_endpoint(&replacement_package, &actor, Some(&binding))
        .unwrap();
    let replacement_proposals = mls_public_fixture::consume(&mut tracker, &replaced.commit);
    mls.register_package(
        &replacement_package,
        &replacement_proposals,
        &selector.authorization_ref.event_id,
    );
    assert_eq!(replacement_proposals[0].target_after.as_ref(), Some(&leaf));
    assert_eq!(replacement_proposals[2].target_before.as_ref(), Some(&leaf));
    let replacement = mls.transition(
        &first.authority_commit,
        group,
        tracker,
        replaced.commit,
        binding,
        &first_ref,
        replacement_proposals.clone(),
        at,
    );
    uow.commit_event(replacement.clone()).await.unwrap();
    let replacement_ref = replacement.authority_commit.event.event_id.clone();

    let mut conn = pool.get().await.unwrap();
    let rows = diesel::sql_query(
        "SELECT commit_event_ref,consumed_proposal_ordinal,proposal_type,proposal_wire,sender_actor_id, \
         target_before_actor_id,target_after_actor_id \
         FROM mls_consumed_proposal_provenance WHERE realm_id=$1 \
         ORDER BY commit_stream_position,consumed_proposal_ordinal",
    )
    .bind::<Text, _>(realm_id.as_str())
    .load::<ProvenanceRow>(&mut *conn)
    .await
    .unwrap();
    assert_eq!(rows.len(), 5);
    assert_eq!(rows[0].commit_event_ref, first_ref.as_str());
    assert_eq!(rows[1].commit_event_ref, first_ref.as_str());
    assert_eq!(rows[2].commit_event_ref, replacement_ref.as_str());
    assert_eq!(rows[3].commit_event_ref, replacement_ref.as_str());
    assert_eq!(rows[4].commit_event_ref, replacement_ref.as_str());
    assert_eq!(
        rows.iter()
            .map(|row| row.consumed_proposal_ordinal)
            .collect::<Vec<_>>(),
        vec![0, 1, 0, 1, 2]
    );
    assert_eq!(
        rows.iter()
            .map(|row| row.proposal_wire.as_slice())
            .collect::<Vec<_>>(),
        first_proposals
            .iter()
            .chain(&replacement_proposals)
            .map(|p| p.proposal_wire.as_slice())
            .collect::<Vec<_>>()
    );
    assert_eq!(
        rows.iter().map(|row| row.proposal_type).collect::<Vec<_>>(),
        vec![1, 7, 1, 7, 3]
    );
    assert!(rows.iter().all(|row| row.sender_actor_id
        == serde_json::to_value(&genesis.authority_commit.event.actor_id).unwrap()));
    assert!(rows[1].target_before_actor_id.is_none());
    assert!(rows[1].target_after_actor_id.is_none());
    assert!(rows[3].target_before_actor_id.is_none());
    assert!(rows[3].target_after_actor_id.is_none());
    assert!(rows[4].target_after_actor_id.is_none());
    assert_eq!(rows[0].target_after_actor_id, rows[2].target_after_actor_id);
    assert_eq!(
        rows[0].target_after_actor_id,
        rows[4].target_before_actor_id
    );
    let invalid_group_context = diesel::sql_query(
        "INSERT INTO mls_consumed_proposal_provenance \
         (realm_id,scope_key,commit_event_ref,commit_stream_position,epoch,consumed_proposal_ordinal, \
          proposal_type,proposal_wire,proposal_ref,sender_actor_id,sender_leaf_index,sender_signature_key, \
          target_before_actor_id,target_before_leaf_index,target_before_signature_key, \
          target_after_actor_id,target_after_leaf_index,target_after_signature_key,created_at) \
         SELECT realm_id,scope_key,commit_event_ref,commit_stream_position,epoch,99, \
          7,proposal_wire,proposal_ref,sender_actor_id,sender_leaf_index,sender_signature_key, \
          target_before_actor_id,target_before_leaf_index,target_before_signature_key, \
          target_after_actor_id,target_after_leaf_index,target_after_signature_key,created_at \
         FROM mls_consumed_proposal_provenance \
         WHERE realm_id=$1 AND commit_event_ref=$2 AND consumed_proposal_ordinal=0",
    )
    .bind::<Text, _>(realm_id.as_str())
    .bind::<Text, _>(first_ref.as_str())
    .execute(&mut *conn)
    .await
    .unwrap_err();
    assert!(
        invalid_group_context
            .to_string()
            .contains("mls_consumed_proposal_provenance_check2")
    );
    drop(conn);

    let mut group = mls.accepted_private_group(&first_ref).await;
    let mut tracker = mls.tracker(&first_ref);
    let binding =
        MlsGovernanceBindingPayload::realm(realm_id.clone(), Some(first_ref.clone()), 1, 2, 0)
            .unwrap();
    let stale_package = claimed();
    let replaced = group
        .replace_member_endpoint(&stale_package, &actor, Some(&binding))
        .unwrap();
    let stale_proposals = mls_public_fixture::consume(&mut tracker, &replaced.commit);
    let stale = mls.transition(
        &replacement.authority_commit,
        group,
        tracker,
        replaced.commit,
        binding,
        &first_ref,
        stale_proposals,
        at,
    );
    assert_zero_write_refusal(&pool, &stale, ConflictCode::GovernanceBindingMismatch).await;
    assert_eq!(provenance_count(&pool).await, 5);
}

/// A member's public Genesis material read is decided at one accepted Realm
/// cut. The peer path additionally binds the source Station's replication
/// interval at that target Commit, while a mismatched Actor/epoch is opaque.
#[tokio::test]
async fn realm_mls_material_read_authorizes_exact_member_and_target_cut() {
    use arkret_models_collaboration::mls_group_state_material::MlsGroupStateMaterialRequestBody;
    use coland_storage::MlsMemberGroupStateMaterialRead as Read;

    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let discussion = ordinary_realm::open_discussion(&pool, "mls-material-member-cut").await;
    let realm_id = discussion.realm_id();
    let station = ordinary_realm::station();
    let founder = discussion
        .head
        .authority_commit
        .event
        .actor_id
        .signing_principal_id()
        .clone();
    let at = discussion.committed_at();
    let mls = MlsFixture::new(pool.clone(), &discussion.head.authority_commit);
    let genesis = mls.with_installation(
        ordinary_realm::next_request(
            &discussion.head.authority_commit,
            arkret_wire::EventKind::MlsGenesis,
            &founder,
            mls.genesis_payload(&realm_id, at),
            at,
        ),
        None,
        0,
    );
    PgEventCommitUnitOfWork::new(pool.clone())
        .commit_event(genesis.clone())
        .await
        .unwrap();
    let event = &genesis.authority_commit.event;
    let payload: arkret_models_collaboration::events_payloads::MlsGenesisPayload =
        serde_json::from_value(serde_json::to_value(&event.payload).unwrap()).unwrap();
    let mut request = MlsGroupStateMaterialRequestBody {
        realm_id: realm_id.clone(),
        effective_scope: realm_scope(&realm_id),
        mls_group_id: payload.mls_group_id().unwrap(),
        epoch: Default::default(),
        group_state_event_id: event.event_id.clone(),
        caller_actor_id: Some(event.actor_id.clone()),
        target_commit_event_ref: Some(event.event_id.clone()),
        target_epoch: Some(0),
        group_info_ref: payload.group_info_ref,
        ratchet_tree_ref: payload.ratchet_tree_ref,
        max_response_bytes: None,
    };
    let store = PgAuthorityCommitStore { pool };
    assert!(matches!(
        store
            .mls_member_group_state_material_read(&request, &station, None)
            .await
            .unwrap(),
        Read::Authorized {
            group_state_event: Some(_)
        }
    ));
    assert!(matches!(
        store
            .mls_member_group_state_material_read(&request, &station, Some(&station))
            .await
            .unwrap(),
        Read::Authorized {
            group_state_event: Some(_)
        }
    ));
    let outsider =
        arkret_wire::DidCoreId::new("ak:did_core:web:mls-material-outsider.example").unwrap();
    assert!(matches!(
        store
            .mls_member_group_state_material_read(&request, &station, Some(&outsider))
            .await
            .unwrap(),
        Read::NotFound
    ));
    request.caller_actor_id = Some(arkret_wire::ActorId::service(outsider));
    assert!(matches!(
        store
            .mls_member_group_state_material_read(&request, &station, None)
            .await
            .unwrap(),
        Read::NotFound
    ));
    request.caller_actor_id = Some(event.actor_id.clone());
    request.target_epoch = Some(1);
    assert!(matches!(
        store
            .mls_member_group_state_material_read(&request, &station, None)
            .await
            .unwrap(),
        Read::NotFound
    ));
}

/// A Station hosting a since-join member cannot replicate the prejoin
/// Genesis Event, but it can request epoch-0 public bytes at a later accepted
/// MLS Commit cut that it is allowed to replicate.
#[tokio::test]
async fn realm_mls_material_peer_uses_joined_target_cut_not_prejoin_genesis_cut() {
    use arkret_models_collaboration::mls_group_state_material::MlsGroupStateMaterialRequestBody;
    use coland_storage::MlsMemberGroupStateMaterialRead as Read;

    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let station = ordinary_realm::station();
    let account = Box::pin(ordinary_realm::human_profile::admit(
        &pool,
        &station,
        "ordinary-founder",
    ))
    .await;
    let unit = ordinary_realm::bootstrap_unit_with_history_for_account(
        "mls-material-since-join",
        "public",
        "since_join",
        &account,
        &device_authorization_history::did_web_station(&station),
    );
    let unit = Box::pin(ordinary_realm::source_bootstrap(&pool, unit)).await;
    let at = unit.transactions[0].commit.committed_at;
    PgAuthorityCommitStore { pool: pool.clone() }
        .admit_ordinary_realm_bootstrap_unit(&unit, at)
        .await
        .unwrap();
    let realm_id = unit.transactions[0].event.realm_id.clone();
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let founder = account.principal_id.clone();
    let mls = MlsFixture::new(pool.clone(), unit.transactions.last().unwrap());
    let genesis = mls.with_installation(
        ordinary_realm::next_request(
            unit.transactions.last().unwrap(),
            arkret_wire::EventKind::MlsGenesis,
            &founder,
            mls.genesis_payload(&realm_id, at),
            at,
        ),
        None,
        0,
    );
    uow.commit_event(genesis.clone()).await.unwrap();
    let genesis_ref = genesis.authority_commit.event.event_id.clone();
    let remote_station =
        arkret_wire::DidCoreId::new("ak:did_core:web:mls-material-member.example").unwrap();
    let bob = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        arkret_wire::DidCoreId::new("ak:did_core:web:mls-material-bob.example").unwrap(),
        remote_station.clone(),
    ));
    let mut join = ordinary_realm::next_request_for_actor(
        &genesis.authority_commit,
        arkret_wire::EventKind::MemberState,
        bob.clone(),
        serde_json::json!({
            "realm_id": realm_id,
            "member_id": bob,
            "membership": "join",
            "reason": "MLS material target-cut fixture",
        }),
        at,
    );
    join.realm_fanout_source = Some(arkret_wire::EventAdmissionSubmission::new(
        join.authority_commit.event.clone(),
    ));
    uow.commit_event(join.clone()).await.unwrap();
    let target = mls.with_installation(
        ordinary_realm::next_request(
            &join.authority_commit,
            arkret_wire::EventKind::MlsCommit,
            &founder,
            mls.commit_payload(&realm_id, &genesis_ref, 0, 1).await,
            at,
        ),
        Some((&genesis_ref, 0)),
        1,
    );
    let target = Box::pin(ordinary_realm::source_request(&pool, target)).await;
    uow.commit_event(target.clone()).await.unwrap();
    let genesis_payload: arkret_models_collaboration::events_payloads::MlsGenesisPayload =
        serde_json::from_value(
            serde_json::to_value(&genesis.authority_commit.event.payload).unwrap(),
        )
        .unwrap();
    let request = MlsGroupStateMaterialRequestBody {
        realm_id: realm_id.clone(),
        effective_scope: realm_scope(&realm_id),
        mls_group_id: genesis_payload.mls_group_id().unwrap(),
        epoch: Default::default(),
        group_state_event_id: genesis_ref.clone(),
        caller_actor_id: Some(bob.clone()),
        target_commit_event_ref: Some(target.authority_commit.event.event_id.clone()),
        target_epoch: Some(1),
        group_info_ref: genesis_payload.group_info_ref,
        ratchet_tree_ref: genesis_payload.ratchet_tree_ref,
        max_response_bytes: None,
    };
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    assert!(
        store
            .committed_event_for_peer(&genesis_ref, &remote_station, &station)
            .await
            .unwrap()
            .is_none()
    );
    assert!(matches!(
        store
            .mls_member_group_state_material_read(&request, &station, Some(&remote_station))
            .await
            .unwrap(),
        Read::Authorized {
            group_state_event: Some(_)
        }
    ));
    let mut wrong_genesis = request.clone();
    wrong_genesis.group_state_event_id =
        arkret_wire::EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [0x7c; 32]);
    assert!(matches!(
        store
            .mls_member_group_state_material_read(&wrong_genesis, &station, Some(&remote_station))
            .await
            .unwrap(),
        Read::NotFound
    ));
    // Simulate the Account Station's verified anchored since-join replica:
    // it has the target Commit but no prejoin Genesis or governance MLS
    // current. Its only authorized result is a forwarding decision, never
    // public bytes or a locally invented Genesis selector.
    let mut conn = pool.get().await.unwrap();
    let stream_key = String::from_utf8(
        arkret_canonical::canonical_json_bytes(&arkret_wire::CommitStreamRef::Realm {
            realm_id: realm_id.clone(),
        })
        .unwrap(),
    )
    .unwrap();
    diesel::sql_query(
        "INSERT INTO replica_stream_anchors \
         (stream_key,realm_id,join_commit_id,member_account_id,anchor_commit_id,anchor_stream_position,anchored_at) \
         VALUES ($1,$2,$3,$4,$3,$5,now())",
    )
    .bind::<Text, _>(stream_key)
    .bind::<Text, _>(realm_id.as_str())
    .bind::<Text, _>(join.authority_commit.commit.commit_id.as_str())
    .bind::<Jsonb, _>(serde_json::to_value(bob.as_account_id().unwrap()).unwrap())
    .bind::<BigInt, _>(join.authority_commit.commit.stream_position as i64)
    .execute(&mut conn)
    .await
    .unwrap();
    diesel::sql_query("DELETE FROM mls_group_current_states WHERE realm_id=$1")
        .bind::<Text, _>(realm_id.as_str())
        .execute(&mut conn)
        .await
        .unwrap();
    assert!(matches!(
        store
            .mls_member_group_state_material_read(&wrong_genesis, &remote_station, None)
            .await
            .unwrap(),
        Read::Authorized {
            group_state_event: None
        }
    ));
    use arkret_models_collaboration::mls_roster_authority::MlsMemberRosterAuthorityReadRequestBody;
    use coland_storage::MlsMemberRosterSelectorRead as Selected;
    let member = MlsMemberRosterAuthorityReadRequestBody {
        realm_id: realm_id.clone(),
        effective_scope: realm_scope(&realm_id),
        mls_group_id: request.mls_group_id.clone(),
        target_commit_event_ref: target.authority_commit.event.event_id.clone(),
        target_epoch: 1,
        caller_actor_id: bob.clone(),
        cursor: None,
    };
    assert!(matches!(
        store
            .mls_member_roster_selector(&member, &remote_station)
            .await
            .unwrap(),
        Selected::RevisionUnavailable
    ));
    let scope_key =
        String::from_utf8(arkret_canonical::canonical_json_bytes(&member.effective_scope).unwrap())
            .unwrap();
    diesel::sql_query("INSERT INTO mls_replica_genesis_provenance (realm_id,scope_key,mls_group_id,genesis_event_ref,first_carried_commit_event_ref,created_at) VALUES ($1,$2,$3,$4,$5,now())")
        .bind::<Text,_>(realm_id.as_str()).bind::<Text,_>(&scope_key).bind::<Text,_>(member.mls_group_id.as_str())
        .bind::<Text,_>(genesis_ref.as_str()).bind::<Text,_>(member.target_commit_event_ref.as_str()).execute(&mut conn).await.unwrap();
    match store
        .mls_member_roster_selector(&member, &remote_station)
        .await
        .unwrap()
    {
        Selected::Authorized {
            request: selected,
            governance_station_id,
        } => {
            assert_eq!(*selected, member.with_accepted_genesis(genesis_ref.clone()));
            assert_eq!(governance_station_id, station);
        }
        result => panic!("authorized member without a prejoin baseline was refused: {result:?}"),
    }
    for field in ["actor", "realm", "scope", "group", "target", "epoch"] {
        let mut wrong = member.clone();
        match field {
            "actor" => {
                wrong.caller_actor_id = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
                    founder.clone(),
                    remote_station.clone(),
                ))
            }
            "realm" => {
                wrong.realm_id =
                    arkret_wire::RealmId::from_event_id(&wrong_genesis.group_state_event_id);
                wrong.effective_scope = realm_scope(&wrong.realm_id);
            }
            "scope" => {
                wrong.effective_scope = arkret_wire::ScopeRef::Sidecar {
                    realm_id: realm_id.clone(),
                    sidecar_id: arkret_wire::SidecarId::from_event_id(
                        &wrong_genesis.group_state_event_id,
                    ),
                }
            }
            "group" => {
                wrong.mls_group_id =
                    arkret_wire::MlsGroupId::new(arkret_canonical::base64url_encode([25; 32]))
                        .unwrap()
            }
            "target" => wrong.target_commit_event_ref = wrong_genesis.group_state_event_id.clone(),
            _ => wrong.target_epoch = 2,
        }
        assert!(
            matches!(
                store
                    .mls_member_roster_selector(&wrong, &remote_station)
                    .await
                    .unwrap(),
                Selected::NotFound
            ),
            "{field}"
        );
    }
    diesel::sql_query(
        "UPDATE mls_replica_genesis_provenance SET mls_group_id=$1 WHERE scope_key=$2",
    )
    .bind::<Text, _>(arkret_canonical::base64url_encode([25; 32]))
    .bind::<Text, _>(&scope_key)
    .execute(&mut conn)
    .await
    .unwrap();
    assert!(matches!(
        store
            .mls_member_roster_selector(&member, &remote_station)
            .await
            .unwrap(),
        Selected::RevisionUnavailable
    ));
    diesel::sql_query("UPDATE mls_replica_genesis_provenance SET mls_group_id=$1,genesis_event_ref='corrupt' WHERE scope_key=$2")
        .bind::<Text,_>(member.mls_group_id.as_str()).bind::<Text,_>(&scope_key).execute(&mut conn).await.unwrap();
    assert!(matches!(
        store
            .mls_member_roster_selector(&member, &remote_station)
            .await
            .unwrap(),
        Selected::RevisionUnavailable
    ));
}

#[tokio::test]
async fn realm_mls_material_read_rejects_wrong_genesis_ref() {
    use arkret_models_collaboration::mls_group_state_material::MlsGroupStateMaterialRequestBody;
    use coland_storage::MlsMemberGroupStateMaterialRead as Read;

    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let discussion = ordinary_realm::open_discussion(&pool, "mls-material-wrong-genesis").await;
    let realm_id = discussion.realm_id();
    let station = ordinary_realm::station();
    let at = discussion.committed_at();
    let mls = MlsFixture::new(pool.clone(), &discussion.head.authority_commit);
    let genesis = mls.with_installation(
        ordinary_realm::next_request(
            &discussion.head.authority_commit,
            arkret_wire::EventKind::MlsGenesis,
            &discussion
                .head
                .authority_commit
                .event
                .actor_id
                .signing_principal_id()
                .clone(),
            mls.genesis_payload(&realm_id, at),
            at,
        ),
        None,
        0,
    );
    PgEventCommitUnitOfWork::new(pool.clone())
        .commit_event(genesis.clone())
        .await
        .unwrap();
    let event = &genesis.authority_commit.event;
    let target = mls.with_installation(
        ordinary_realm::next_request(
            &genesis.authority_commit,
            arkret_wire::EventKind::MlsCommit,
            &discussion
                .head
                .authority_commit
                .event
                .actor_id
                .signing_principal_id()
                .clone(),
            mls.commit_payload(&realm_id, &event.event_id, 0, 0).await,
            at,
        ),
        Some((&event.event_id, 0)),
        1,
    );
    PgEventCommitUnitOfWork::new(pool.clone())
        .commit_event(target.clone())
        .await
        .unwrap();
    let payload: arkret_models_collaboration::events_payloads::MlsGenesisPayload =
        serde_json::from_value(serde_json::to_value(&event.payload).unwrap()).unwrap();
    let mut request = MlsGroupStateMaterialRequestBody {
        realm_id: realm_id.clone(),
        effective_scope: realm_scope(&realm_id),
        mls_group_id: payload.mls_group_id().unwrap(),
        epoch: Default::default(),
        group_state_event_id: event.event_id.clone(),
        caller_actor_id: Some(event.actor_id.clone()),
        target_commit_event_ref: Some(target.authority_commit.event.event_id.clone()),
        target_epoch: Some(1),
        group_info_ref: payload.group_info_ref,
        ratchet_tree_ref: payload.ratchet_tree_ref,
        max_response_bytes: None,
    };
    let store = PgAuthorityCommitStore { pool };
    assert!(matches!(
        store
            .mls_member_group_state_material_read(&request, &station, None)
            .await
            .unwrap(),
        Read::Authorized {
            group_state_event: Some(_)
        }
    ));
    request.group_state_event_id =
        arkret_wire::EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [0x7b; 32]);
    assert!(matches!(
        store
            .mls_member_group_state_material_read(&request, &station, None)
            .await
            .unwrap(),
        Read::NotFound
    ));
}

#[tokio::test]
async fn realm_mls_material_read_rejects_target_retention_and_redaction() {
    use arkret_models_collaboration::mls_group_state_material::MlsGroupStateMaterialRequestBody;
    use coland_storage::MlsMemberGroupStateMaterialRead as Read;

    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let discussion = ordinary_realm::open_discussion(&pool, "mls-material-withheld-target").await;
    let realm_id = discussion.realm_id();
    let station = ordinary_realm::station();
    let at = discussion.committed_at();
    let mls = MlsFixture::new(pool.clone(), &discussion.head.authority_commit);
    let genesis = mls.with_installation(
        ordinary_realm::next_request(
            &discussion.head.authority_commit,
            arkret_wire::EventKind::MlsGenesis,
            &discussion
                .head
                .authority_commit
                .event
                .actor_id
                .signing_principal_id()
                .clone(),
            mls.genesis_payload(&realm_id, at),
            at,
        ),
        None,
        0,
    );
    PgEventCommitUnitOfWork::new(pool.clone())
        .commit_event(genesis.clone())
        .await
        .unwrap();
    let event = &genesis.authority_commit.event;
    let payload: arkret_models_collaboration::events_payloads::MlsGenesisPayload =
        serde_json::from_value(serde_json::to_value(&event.payload).unwrap()).unwrap();
    let request = MlsGroupStateMaterialRequestBody {
        realm_id: realm_id.clone(),
        effective_scope: realm_scope(&realm_id),
        mls_group_id: payload.mls_group_id().unwrap(),
        epoch: Default::default(),
        group_state_event_id: event.event_id.clone(),
        caller_actor_id: Some(event.actor_id.clone()),
        target_commit_event_ref: Some(event.event_id.clone()),
        target_epoch: Some(0),
        group_info_ref: payload.group_info_ref,
        ratchet_tree_ref: payload.ratchet_tree_ref,
        max_response_bytes: None,
    };
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    assert!(matches!(
        store
            .mls_member_group_state_material_read(&request, &station, None)
            .await
            .unwrap(),
        Read::Authorized {
            group_state_event: Some(_)
        }
    ));
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query(
        "INSERT INTO retention_tombstones \
         (event_id,realm_id,reason,policy_ttl_seconds,expired_at,tombstoned_at) \
         SELECT id,realm_id,'retention_policy.ttl',60,now(),now() \
         FROM canonical_events WHERE envelope->>'event_id'=$1",
    )
    .bind::<Text, _>(event.event_id.as_str())
    .execute(&mut conn)
    .await
    .unwrap();
    assert!(matches!(
        store
            .mls_member_group_state_material_read(&request, &station, None)
            .await
            .unwrap(),
        Read::NotFound
    ));
    diesel::sql_query(
        "DELETE FROM retention_tombstones WHERE event_id IN \
         (SELECT id FROM canonical_events WHERE envelope->>'event_id'=$1)",
    )
    .bind::<Text, _>(event.event_id.as_str())
    .execute(&mut conn)
    .await
    .unwrap();
    diesel::sql_query(
        "INSERT INTO object_redaction_current_states \
         (realm_id,target_ref,current_commit_id,current_stream_position,value,updated_at) \
         VALUES ($1,$2,$3,$4,$5,now())",
    )
    .bind::<Text, _>(realm_id.as_str())
    .bind::<Text, _>(event.event_id.as_str())
    .bind::<Text, _>(genesis.authority_commit.commit.commit_id.as_str())
    .bind::<BigInt, _>(genesis.authority_commit.commit.stream_position as i64)
    .bind::<Jsonb, _>(serde_json::json!({"assertions": [{"test": true}]}))
    .execute(&mut conn)
    .await
    .unwrap();
    assert!(matches!(
        store
            .mls_member_group_state_material_read(&request, &station, None)
            .await
            .unwrap(),
        Read::NotFound
    ));
}

/// A Commit and its Welcome commit together; a full recipient queue rolls the
/// whole Commit back; a reused claim is `duplicate_conflict`; the queued
/// Welcome is read and ACKed only by its exact endpoint and becomes
/// unreadable once that endpoint's device is revoked.
#[tokio::test]
async fn mls_commit_welcome_queue_is_atomic_exact_endpoint_and_revocation_gated() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let station = local_station(&pool).await;
    let persistence = coland_storage_postgres::PgPersistenceStore::new(pool.clone());
    let mut source = pcr_genesis::PcrGenesisFixture::new_with(
        historical_roster_attestor_resolution()
            .normalized_did_document
            .id
            .clone(),
        device_authorization_history::DeviceHistoryFixtureOptions {
            founding_device_signing_seed: [112; 32],
            ..Default::default()
        },
    );
    let recipient = source
        .admit_founding_device(&persistence)
        .await
        .expect("accepted recipient device");
    let second_device = source
        .admit_accepted_device(&persistence, [41; 32])
        .await
        .expect("accepted second recipient device");

    let discussion = ordinary_realm::open_discussion_for_station(
        &pool,
        "mls-welcome-queue",
        &station,
        &historical_roster_attestor_resolution()
            .normalized_did_document
            .id,
    )
    .await;
    let realm_id = discussion.realm_id();
    let founder = discussion
        .head
        .authority_commit
        .event
        .actor_id
        .signing_principal_id()
        .clone();
    let at = discussion.committed_at();
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let mls = MlsFixture::new(pool.clone(), &discussion.head.authority_commit);
    let genesis = mls.with_installation(
        ordinary_realm::next_request(
            &discussion.head.authority_commit,
            arkret_wire::EventKind::MlsGenesis,
            &founder,
            mls.genesis_payload(&realm_id, at),
            at,
        ),
        None,
        0,
    );
    uow.commit_event(genesis.clone()).await.unwrap();

    let first_claim = claim_id();
    let (mut commit, first_package) = Box::pin(mls_local_add_fixture::add(
        &pool,
        &mls,
        &genesis,
        &recipient,
        [112; 32],
        &first_claim,
        0,
        None,
    ))
    .await;
    let first_key = commit.authority_commit.welcomes[0].claim.clone().unwrap();
    commit.authority_commit.recipient_queue_capacity = 1;
    assert_zero_write_refusal(&pool, &commit, ConflictCode::FailedPrecondition).await;
    join(&pool, &discussion.head, &recipient_actor(&recipient)).await;
    uow.commit_event(commit.clone()).await.unwrap();
    assert_eq!(welcome_count(&pool).await, 1);
    let commit_ref = commit.authority_commit.event.event_id.clone();
    // decision 0121: the queueing transaction binds the claim to its Welcome.
    let queued = &commit.authority_commit.welcomes[0].delivery;
    assert_eq!(
        coland_storage_postgres::PgMlsKeyPackageStore { pool: pool.clone() }
            .get_claim_welcome_binding(&first_claim)
            .await
            .unwrap(),
        Some(coland_storage::MlsWelcomeClaimBinding {
            claim_id: first_claim.clone(),
            source_id: first_key.source_id.clone(),
            claim_request_id: first_key.claim_request_id.clone(),
            welcome_id: queued.welcome_id.to_string(),
            welcome_digest: queued.durable_receipt_digest().unwrap().to_string(),
            commit_event_ref: commit_ref.to_string(),
        })
    );

    let second_claim = claim_id();
    let (mut full, _) = Box::pin(mls_local_add_fixture::add(
        &pool,
        &mls,
        &commit,
        &recipient,
        [112; 32],
        &second_claim,
        0,
        None,
    ))
    .await;
    full.authority_commit.recipient_queue_capacity = 1;
    assert_zero_write_refusal(&pool, &full, ConflictCode::RecipientQueueAtCapacity).await;

    let (mut reused, _) = Box::pin(mls_local_add_fixture::add(
        &pool,
        &mls,
        &commit,
        &recipient,
        [112; 32],
        &first_claim,
        0,
        Some((&first_package, &commit.authority_commit.welcomes[0])),
    ))
    .await;
    reused.authority_commit.recipient_queue_capacity = 10;
    assert_zero_write_refusal(&pool, &reused, ConflictCode::DuplicateConflict).await;

    let queue = PgDeviceMessageStore { pool: pool.clone() };
    let endpoint = |device: &DeviceRevocationGateSelector| RecipientQueueSelector::HumanDevice {
        recipient: device.principal_id.to_string(),
        device_id: device.device_id.clone(),
    };
    let listed = queue
        .list_recipient_deliveries(&endpoint(&recipient), 0, 10)
        .await
        .unwrap();
    assert_eq!(listed.len(), 1);
    assert!(matches!(
        &listed[0].delivery,
        arkret_models_collaboration::device_messages::RecipientDelivery::MlsWelcome { mls_welcome }
            if mls_welcome.keypackage_claim_ref.as_str() == first_claim
    ));
    assert!(
        queue
            .list_recipient_deliveries(&endpoint(&second_device.authorization), 0, 10)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        queue
            .issue_recipient_ack_token(&endpoint(&second_device.authorization), listed[0].position)
            .await
            .unwrap()
            .is_none()
    );
    let token = queue
        .issue_recipient_ack_token(&endpoint(&recipient), listed[0].position)
        .await
        .unwrap()
        .expect("the exact endpoint ACKs its own Welcome");
    assert!(
        queue
            .ack_recipient_with_token(&endpoint(&second_device.authorization), &token)
            .await
            .unwrap()
            .is_none_or(|count| count == 0)
    );
    assert_eq!(
        queue
            .list_recipient_deliveries(&endpoint(&recipient), 0, 10)
            .await
            .unwrap()
            .len(),
        1
    );

    mls_device_revoke_fixture::accept_revoke(&pool, &source, &recipient, &second_device).await;
    assert!(
        queue
            .list_recipient_deliveries(&endpoint(&recipient), 0, 10)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        queue
            .ack_recipient_with_token(&endpoint(&recipient), &token)
            .await
            .unwrap()
            .is_none()
    );
}

/// The Realm root's grant of `ak.message.create` to `subject`.
async fn grant_message_create(
    pool: &PgPool,
    previous: &coland_storage::AuthorityCommitTransaction,
    subject: &arkret_wire::ActorId,
) -> EventCommitRequest {
    #[derive(diesel::QueryableByName)]
    struct Root {
        #[diesel(sql_type = Text)]
        authority_event_ref: String,
    }
    let realm_id = previous.event.realm_id.clone();
    let root = {
        let mut conn = pool.get().await.unwrap();
        diesel::sql_query(
            "SELECT authority_event_ref FROM realm_authority_root_current_states WHERE realm_id=$1",
        )
        .bind::<Text, _>(realm_id.as_str())
        .get_result::<Root>(&mut *conn)
        .await
        .unwrap()
        .authority_event_ref
    };
    let founder = previous.event.actor_id.clone();
    let at = previous.commit.committed_at;
    let grant = ordinary_realm::next_request(
        previous,
        arkret_wire::EventKind::CapabilityGrant,
        founder.signing_principal_id(),
        serde_json::json!({
            "grant": {
                "schema": "ak.schema.capability.v1",
                "realm_id": realm_id,
                "issuer_id": founder,
                "subject": subject,
                "actions": ["ak.message.create"],
                "resources": [{"kind": "realm", "realm_id": realm_id}],
                "issuer_authority_refs": [{
                    "kind": "realm_root",
                    "realm_id": realm_id,
                    "authority_event_ref": root,
                    "authority_generation": "0"
                }],
                "issued_at": arkret_canonical::format_timestamp_canonical(at),
            }
        }),
        at,
    );
    PgEventCommitUnitOfWork::new(pool.clone())
        .commit_event(grant.clone())
        .await
        .unwrap();
    grant
}

/// Admit the two actual Device endpoints before freezing this send cut.
/// Keeping the finite enrollment phase separate also keeps its large Add
/// return values and UOW temporaries out of the parent test's poll frame.
async fn admit_send_gate_endpoints(
    pool: &PgPool,
    mls: &MlsFixture,
    previous: Box<EventCommitRequest>,
    endpoints: [(&DeviceRevocationGateSelector, [u8; 32]); 2],
) -> Box<mls_send_content_fixture::Enrolled> {
    Box::pin(mls_send_content_fixture::enroll(
        pool, mls, previous, endpoints,
    ))
    .await
}

/// encryption-and-audit.md §2.5.2 and §2.4.1: the send gate decides the
/// actual signer's endpoint authorization at the cut it reads the current
/// `mls_group`. A revoked device's ciphertext -- even frozen at a stale epoch
/// -- is `device_revoked`, while the same account's other device and another
/// member keep sending at the current epoch; plaintext into the activated
/// scope is `mls_activation_required` and a stale epoch `epoch_mismatch`. The
/// revocation never advances the key-access revision, and each refusal
/// writes nothing.
#[tokio::test]
async fn the_send_gate_refuses_a_revoked_device_at_the_mls_group_cut() {
    heap_future(case_the_send_gate_refuses_a_revoked_device_at_the_mls_group_cut).await;
}

async fn case_the_send_gate_refuses_a_revoked_device_at_the_mls_group_cut() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let station = local_station(&pool).await;
    let persistence = coland_storage_postgres::PgPersistenceStore::new(pool.clone());
    let mut source = pcr_genesis::PcrGenesisFixture::new_with(
        historical_roster_attestor_resolution()
            .normalized_did_document
            .id
            .clone(),
        device_authorization_history::DeviceHistoryFixtureOptions {
            founding_device_signing_seed: [112; 32],
            ..Default::default()
        },
    );
    let revoked = Box::pin(source.admit_founding_device(&persistence))
        .await
        .expect("accepted founding device");
    let active_device = Box::pin(source.admit_accepted_device(&persistence, [43; 32]))
        .await
        .expect("accepted second device");
    let active = active_device.authorization.clone();

    let discussion = Box::new(
        Box::pin(ordinary_realm::open_discussion_for_station(
            &pool,
            "mls-send-gate",
            &station,
            &historical_roster_attestor_resolution()
                .normalized_did_document
                .id,
        ))
        .await,
    );
    let realm_id = discussion.realm_id();
    let scope = realm_scope(&realm_id);
    let founder = discussion
        .head
        .authority_commit
        .event
        .actor_id
        .signing_principal_id()
        .clone();
    let at = discussion.committed_at();
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let groups = PgMlsGroupCurrentStore { pool: pool.clone() };
    Box::pin(join(&pool, &discussion.head, &recipient_actor(&revoked))).await;
    let grant = Box::new(
        Box::pin(grant_message_create(
            &pool,
            &discussion.head.authority_commit,
            &recipient_actor(&revoked),
        ))
        .await,
    );
    let mls = MlsFixture::new(pool.clone(), &discussion.head.authority_commit);
    let genesis = Box::new(mls.with_installation(
        ordinary_realm::next_request(
            &grant.authority_commit,
            arkret_wire::EventKind::MlsGenesis,
            &founder,
            mls.genesis_payload(&realm_id, at),
            at,
        ),
        None,
        0,
    ));
    Box::pin(uow.commit_event((*genesis).clone()))
        .await
        .unwrap();
    let genesis_ref = genesis.authority_commit.event.event_id.clone();
    let commit = Box::new(mls.with_installation(
        ordinary_realm::next_request(
            &genesis.authority_commit,
            arkret_wire::EventKind::MlsCommit,
            &founder,
            mls.commit_payload(&realm_id, &genesis_ref, 0, 0).await,
            at,
        ),
        Some((&genesis_ref, 0)),
        1,
    ));
    Box::pin(uow.commit_event((*commit).clone())).await.unwrap();
    // PCR acceptance and business membership do not put a Device in the MLS
    // tree. Accept both real Adds, complete signed claims and Welcomes
    // before freezing the revocation cut; no endpoint row is injected.
    let enrolled = Box::pin(admit_send_gate_endpoints(
        &pool,
        &mls,
        commit,
        [
            (&revoked, source.history.founding_device_signing_seed),
            (&active, [43; 32]),
        ],
    ))
    .await;
    let commit = &enrolled.head;
    let commit_ref = commit.authority_commit.event.event_id.clone();
    let before = groups.current(&scope).await.unwrap().unwrap();
    let current_epoch = before.value.epoch;
    assert_eq!(
        current_epoch,
        commit.authority_commit.mls_state.as_ref().unwrap().epoch
    );
    let leaves = mls.tracker(&commit_ref).leaves().unwrap();
    for (device, seed) in [
        (&revoked, source.history.founding_device_signing_seed),
        (&active, [43; 32]),
    ] {
        let signature_key = arkret_canonical::base64url_encode(
            ed25519_dalek::SigningKey::from_bytes(&seed)
                .verifying_key()
                .to_bytes(),
        );
        assert_eq!(
            leaves
                .iter()
                .filter(|leaf| leaf.actor_id == recipient_actor(device)
                    && leaf.signature_key.as_str() == signature_key)
                .count(),
            1
        );
    }
    let content = Box::pin(mls_send_content_fixture::prepare(
        &pool,
        &mls,
        &enrolled,
        &mut source,
    ))
    .await;
    let revoked_author = mls_send_content_fixture::Author::new(
        &revoked,
        &source.history.did,
        source.history.founding_device_signing_seed,
    );
    let active_author =
        mls_send_content_fixture::Author::new(&active, &source.history.did, [43; 32]);
    let strand = &discussion.strand_id;
    let authorized = Box::pin(content.message(
        &pool,
        &commit.authority_commit,
        &revoked_author,
        strand,
        false,
        "authorized target before revocation",
    ))
    .await;
    Box::pin(uow.commit_event((*authorized).clone()))
        .await
        .unwrap();
    assert_eq!(groups.current(&scope).await.unwrap().unwrap(), before);
    // Freeze later requests only after a genuine accepted current-epoch send
    // proves this exact Device's native source and MLS endpoint are usable.
    let mut revoked_messages = Vec::new();
    for stale in [true, false] {
        revoked_messages.push(
            Box::pin(content.message(
                &pool,
                &authorized.authority_commit,
                &revoked_author,
                strand,
                stale,
                "new target message after accepted pre-send",
            ))
            .await,
        );
    }
    assert_eq!(revoked_messages.len(), 2);
    for request in &revoked_messages {
        assert_ne!(
            request.authority_commit.event.event_id,
            authorized.authority_commit.event.event_id
        );
        assert_eq!(
            request.authority_commit.commit.previous_commit_ref.as_ref(),
            Some(&authorized.authority_commit.commit.commit_id)
        );
    }
    assert_ne!(
        revoked_messages[0].authority_commit.event.event_id,
        revoked_messages[1].authority_commit.event.event_id
    );
    assert_eq!(
        PgAuthorityCommitStore { pool: pool.clone() }
            .committed_event(&authorized.authority_commit.event.event_id)
            .await
            .unwrap()
            .unwrap()
            .event,
        authorized.authority_commit.event
    );
    mls_device_revoke_fixture::accept_revoke(&pool, &source, &revoked, &active_device).await;
    Box::pin(content.assert_originals(&pool)).await;
    for request in revoked_messages {
        Box::pin(assert_zero_write_refusal(
            &pool,
            &request,
            ConflictCode::DeviceRevoked,
        ))
        .await;
    }
    assert_eq!(groups.current(&scope).await.unwrap().unwrap(), before);

    let plaintext_at = arkret_canonical::normalize_timestamp_canonical(
        chrono::Utc::now().max(authorized.authority_commit.commit.committed_at)
            + chrono::TimeDelta::milliseconds(1),
    );
    let plaintext = ordinary_realm::next_request(
        &authorized.authority_commit,
        arkret_wire::EventKind::MessageCreate,
        &founder,
        ordinary_realm::message_payload(strand, "plaintext after activation"),
        plaintext_at,
    );
    let plaintext = Box::pin(ordinary_realm::source_request(&pool, plaintext)).await;
    Box::pin(assert_zero_write_refusal(
        &pool,
        &plaintext,
        ConflictCode::MlsActivationRequired,
    ))
    .await;
    let stale = Box::pin(content.message(
        &pool,
        &authorized.authority_commit,
        &content.founder,
        strand,
        true,
        "founder uses a genuinely old joined epoch",
    ))
    .await;
    Box::pin(assert_zero_write_refusal(
        &pool,
        &stale,
        ConflictCode::EpochMismatch,
    ))
    .await;

    let sibling = Box::pin(content.message(
        &pool,
        &authorized.authority_commit,
        &active_author,
        strand,
        false,
        "live sibling after revocation",
    ))
    .await;
    Box::pin(uow.commit_event((*sibling).clone()))
        .await
        .unwrap();
    let member = Box::pin(content.message(
        &pool,
        &sibling.authority_commit,
        &content.founder,
        strand,
        false,
        "live founder after revocation",
    ))
    .await;
    Box::pin(uow.commit_event(*member)).await.unwrap();
    Box::pin(content.assert_originals(&pool)).await;
    let after = groups.current(&scope).await.unwrap().unwrap();
    assert_eq!(
        after.value, before.value,
        "no revocation advances the group"
    );
}

/// A Welcome to a device of `member` on another Station.
fn remote_welcome(
    commit: &EventCommitRequest,
    member: &arkret_wire::ActorId,
) -> VerifiedMlsWelcome {
    let recipient = DeviceRevocationGateSelector {
        principal_id: member.signing_principal_id().clone(),
        station_id: member
            .fixed_route_service_id()
            .expect("fixture recipient is an Account")
            .clone(),
        device_id: format!("ak:device:{}", uuid::Uuid::now_v7()),
        authorization_ref: arkret_wire::CommittedEventRef {
            event_id: commit.authority_commit.event.event_id.clone(),
            commit_id: commit.authority_commit.commit.commit_id.clone(),
            stream_ref: commit.authority_commit.commit.stream_ref.clone(),
            stream_position: commit.authority_commit.commit.stream_position,
        },
    };
    VerifiedMlsWelcome {
        delivery: welcome(commit, &recipient, &claim_id()),
        claim: None,
        applet_device_scope_guard: None,
        roster_witness: None,
    }
}

async fn replication_payloads(
    pool: &PgPool,
    commit: &EventCommitRequest,
) -> Vec<(String, serde_json::Value)> {
    #[derive(diesel::QueryableByName)]
    struct Row {
        #[diesel(sql_type = Text)]
        peer_id: String,
        #[diesel(sql_type = Text)]
        payload_json: String,
    }
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query(
        "SELECT peer_id,payload_json FROM federation_outbox WHERE idempotency_key=$1 \
         ORDER BY peer_id",
    )
    .bind::<Text, _>(format!(
        "realm-fanout:{}",
        commit.authority_commit.commit.commit_id
    ))
    .load::<Row>(&mut *conn)
    .await
    .unwrap()
    .into_iter()
    .map(|row| {
        (
            row.peer_id,
            serde_json::from_str(&row.payload_json).unwrap(),
        )
    })
    .collect()
}

async fn frozen_remote_welcomes(
    pool: &PgPool,
    commit: &EventCommitRequest,
) -> Vec<(String, Vec<u8>)> {
    #[derive(diesel::QueryableByName)]
    struct Row {
        #[diesel(sql_type = Text)]
        welcome_id: String,
        #[diesel(sql_type = Binary)]
        delivery_canonical_json: Vec<u8>,
    }
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query(
        "SELECT welcome_id,delivery_canonical_json FROM mls_welcome_provenance \
         WHERE commit_event_ref=$1 ORDER BY welcome_id",
    )
    .bind::<Text, _>(commit.authority_commit.event.event_id.as_str())
    .load::<Row>(&mut *conn)
    .await
    .unwrap()
    .into_iter()
    .map(|row| (row.welcome_id, row.delivery_canonical_json))
    .collect()
}

fn signed_remote_add_attestation(
    commit: &EventCommitRequest,
    genesis_ref: &arkret_wire::EventId,
    welcome: &VerifiedMlsWelcome,
    keypackage: &arkret_models_crypto::MlsKeyPackageRecord,
    station: &arkret_wire::DidCoreId,
    leaf_key: arkret_wire::Base64UrlString,
) -> arkret_models_collaboration::mls_roster_authority::MlsAttestAddRequestBody {
    signed_add_attestation(
        commit,
        genesis_ref,
        welcome,
        keypackage,
        station,
        leaf_key,
        arkret_wire::EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [71_u8; 32]),
        None,
    )
}

#[allow(clippy::too_many_arguments)]
fn signed_add_attestation(
    commit: &EventCommitRequest,
    genesis_ref: &arkret_wire::EventId,
    welcome: &VerifiedMlsWelcome,
    keypackage: &arkret_models_crypto::MlsKeyPackageRecord,
    station: &arkret_wire::DidCoreId,
    leaf_key: arkret_wire::Base64UrlString,
    authorization_event_ref: arkret_wire::EventId,
    original_claim: Option<arkret_models_crypto::KeyPackagesClaimResponseBody>,
) -> arkret_models_collaboration::mls_roster_authority::MlsAttestAddRequestBody {
    use arkret_models_collaboration::mls_roster_authority::{
        MlsAddAuthorityAttestation, MlsAttestAddRequestBody,
    };
    use arkret_models_crypto::{
        KeyOperationSignature, KeyPackageClaimRecord, KeyPackagesClaimResponseBody,
        PeerKeyPackageClaimReceipt, PeerKeyPackagesClaimFields,
        peer_keypackage_claim_receipt_signing_bytes,
    };

    let delivery = &welcome.delivery;
    let at = commit.authority_commit.commit.committed_at;
    let signer = ed25519_dalek::SigningKey::from_bytes(&[19; 32]);
    let multibase =
        arkret_canonical::ed25519_pubkey_to_did_key_multibase(signer.verifying_key().as_bytes());
    let method = format!("did:key:{multibase}#{multibase}");
    let placeholder = || KeyOperationSignature {
        kid: arkret_wire::NonEmptyString::new(method.clone()).unwrap(),
        signature_algorithm: Some(arkret_wire::NonEmptyString::new("Ed25519").unwrap()),
        signature: arkret_wire::Base64UrlString::new("AA").unwrap(),
    };
    let device_id = match &delivery.recipient_endpoint {
        arkret_wire::MlsWelcomeRecipientEndpoint::Device { device_id } => device_id.clone(),
        _ => panic!("fixture uses a device"),
    };
    let record = KeyPackageClaimRecord {
        claim_id: delivery.keypackage_claim_ref.to_string(),
        keypackage_ref: keypackage.keypackage_ref.to_string(),
        actor_id: delivery.recipient_actor_id.clone(),
        principal_id: delivery
            .recipient_actor_id
            .as_account_id()
            .unwrap()
            .principal_id
            .clone(),
        device_id: Some(device_id),
        agent_id: None,
        agent_verification_method: None,
        keypackage: keypackage.keypackage.clone(),
        capabilities: keypackage.capabilities.clone(),
        device_authorize_event_id: Some(authorization_event_ref.clone()),
        agent_key_authorize_event_id: None,
        expires_at: at + chrono::Duration::hours(1),
        revocation_status: None,
        last_resort: None,
    };
    record.validate_shape().unwrap();
    let outcome = match original_claim {
        Some(outcome) => outcome,
        None => {
            let claim_request: PeerKeyPackagesClaimFields = serde_json::from_value(serde_json::json!({
        "claim_request_id": uuid::Uuid::now_v7().simple().to_string(),
        "intended_realm_id": delivery.realm_id,
        "effective_scope": delivery.effective_scope,
        "mls_group_id": delivery.effective_scope.canonical_mls_group_id().unwrap(),
        "claim_purpose": "realm_membership",
        "requester_account_id": commit.authority_commit.event.actor_id.as_account_id().unwrap(),
        "target_account_id": delivery.recipient_actor_id.as_account_id().unwrap(),
        "target_device_ids": [record.device_id.as_ref().unwrap()],
        "required_capabilities": [arkret_models_crypto::ARKRET_CONTENT_V1],
        "expires_at": arkret_canonical::format_timestamp_canonical(at + chrono::Duration::hours(1)),
    }))
    .unwrap();
            let mut receipt = PeerKeyPackageClaimReceipt {
                claim_authority_ref: None,
                claim_request_id: claim_request.claim_request_id.clone(),
                request_digest: arkret_wire::Hash::new(
                    arkret_canonical::canonical_sha256(&claim_request).unwrap(),
                )
                .unwrap(),
                claims_digest: arkret_wire::Hash::new(
                    arkret_canonical::canonical_sha256(&[&record]).unwrap(),
                )
                .unwrap(),
                source_id: station.clone(),
                destination_id: delivery
                    .recipient_actor_id
                    .fixed_route_service_id()
                    .expect("fixture recipient is an Account")
                    .clone(),
                request: claim_request,
                claimed_at: at,
                expires_at: at + chrono::Duration::hours(1),
                signature: placeholder(),
            };
            receipt.signature = arkret_signatures::keypackages::sign_keypackage_signing_input(
                &[19; 32],
                &method,
                &peer_keypackage_claim_receipt_signing_bytes(&receipt).unwrap(),
            )
            .unwrap();
            KeyPackagesClaimResponseBody {
                claim_request_id: receipt.claim_request_id.clone(),
                claims: vec![record.clone()],
                claim_receipt: receipt,
            }
        }
    };
    assert_eq!(
        arkret_canonical::canonical_json_bytes(&outcome.claims).unwrap(),
        arkret_canonical::canonical_json_bytes(&[record]).unwrap(),
    );
    let receipt = outcome.claim_receipt.clone();
    let mut attestation = MlsAddAuthorityAttestation {
        claim_authority_ref: None,
        attestor_station_id: delivery
            .recipient_actor_id
            .fixed_route_service_id()
            .expect("fixture recipient is an Account")
            .clone(),
        realm_id: delivery.realm_id.clone(),
        effective_scope: delivery.effective_scope.clone(),
        mls_group_id: delivery.effective_scope.canonical_mls_group_id().unwrap(),
        genesis_event_ref: genesis_ref.clone(),
        commit_event_ref: delivery.commit_event_ref.clone(),
        commit_stream_position: commit.authority_commit.commit.stream_position,
        epoch: commit.authority_commit.mls_state.as_ref().unwrap().epoch,
        welcome_id: delivery.welcome_id.clone(),
        claim_id: delivery.keypackage_claim_ref.clone(),
        actor_id: delivery.recipient_actor_id.clone(),
        endpoint: delivery.recipient_endpoint.clone(),
        authorization_event_ref,
        leaf_signature_key_base64url: leaf_key,
        claim_record_digest: arkret_wire::Hash::new(
            arkret_canonical::canonical_sha256(&outcome.claims[0]).unwrap(),
        )
        .unwrap(),
        claim_receipt: receipt,
        attested_at: at,
        signature: placeholder(),
    };
    attestation.signature = arkret_signatures::keypackages::sign_keypackage_signing_input(
        &[19; 32],
        &method,
        &attestation.signing_bytes().unwrap(),
    )
    .unwrap();
    let request = MlsAttestAddRequestBody {
        attestation,
        claim_outcome: outcome,
    };
    request.validate_claim_binding().unwrap();
    request
}

fn historical_roster_attestor_resolution() -> arkret_models_identity::AuthenticatedServiceResolution
{
    use arkret_identity::{DidKeyResolver, DidResolver};
    use arkret_models_identity::{
        AuthenticatedServiceResolution, DidBindingEvidenceKind, DidBindingEvidenceReceipt,
        DidDocument, ResolutionMethodEvidenceBoundary, ResolutionMethodHistoryEvidence,
    };
    let signer = ed25519_dalek::SigningKey::from_bytes(&[19; 32]);
    let multibase =
        arkret_canonical::ed25519_pubkey_to_did_key_multibase(signer.verifying_key().as_bytes());
    let did = arkret_wire::Did::new(format!("did:key:{multibase}")).unwrap();
    let station = arkret_wire::project_did_to_core_id(&did).unwrap();
    let document: DidDocument = DidKeyResolver::new().resolve_did(&did).unwrap().document;
    let digest = arkret_models_identity::normalized_did_document_digest(&document).unwrap();
    let head = arkret_canonical::sha256_digest(did.as_str().as_bytes());
    let version = format!(
        "synthetic-did-sha256:{}",
        head.trim_start_matches("sha256:")
    );
    AuthenticatedServiceResolution {
        service_id: station,
        service_kind: "station".to_owned(),
        normalized_did_document: document,
        method_history_evidence: ResolutionMethodHistoryEvidence::DidKeyExpansion {
            boundary: ResolutionMethodEvidenceBoundary {
                from_method_history_head: head.clone(),
                to_method_history_head: head,
                from_version_id: version.clone(),
                to_version_id: version,
            },
            evidence: DidBindingEvidenceReceipt {
                kind: DidBindingEvidenceKind::AkDidBindingEvidenceV1,
                method: "key".to_owned(),
                document_digest: digest,
                method_proofs: vec![],
            },
        },
    }
}

async fn installed_add_attestation_count(pool: &PgPool) -> i64 {
    #[derive(diesel::QueryableByName)]
    struct Row {
        #[diesel(sql_type = BigInt)]
        count: i64,
    }
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query("SELECT COUNT(*) AS count FROM mls_add_authority_attestations")
        .get_result::<Row>(&mut *conn)
        .await
        .unwrap()
        .count
}

async fn frozen_roster_attestor_resolution(pool: &PgPool) -> Vec<u8> {
    #[derive(diesel::QueryableByName)]
    struct Row {
        #[diesel(sql_type = Binary)]
        attestor_resolution_canonical_json: Vec<u8>,
    }
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query(
        "SELECT attestor_resolution_canonical_json FROM mls_add_authority_attestations",
    )
    .get_result::<Row>(&mut *conn)
    .await
    .unwrap()
    .attestor_resolution_canonical_json
}

#[tokio::test]
async fn same_station_add_installs_signed_history_atomically() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let resolution = historical_roster_attestor_resolution();
    let station = resolution.service_id.clone();
    let station_did = resolution.normalized_did_document.id.clone();
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query("INSERT INTO device_inventory_station(singleton,station_id) VALUES(TRUE,$1)")
        .bind::<Text, _>(station.as_str())
        .execute(&mut *conn)
        .await
        .unwrap();
    drop(conn);
    let persistence = coland_storage_postgres::PgPersistenceStore::new(pool.clone());
    let recipient_source = pcr_genesis::PcrGenesisFixture::new_with(
        station_did.clone(),
        device_authorization_history::DeviceHistoryFixtureOptions {
            founding_device_signing_seed: [110; 32],
            ..Default::default()
        },
    );
    let recipient = recipient_source
        .admit_founding_device(&persistence)
        .await
        .unwrap();
    let discussion = ordinary_realm::open_discussion_for_station(
        &pool,
        "mls-local-signed-history",
        &station,
        &station_did,
    )
    .await;
    let realm_id = discussion.realm_id();
    let founder = discussion
        .head
        .authority_commit
        .event
        .actor_id
        .signing_principal_id()
        .clone();
    let at = discussion.committed_at();
    join(&pool, &discussion.head, &recipient_actor(&recipient)).await;
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let mls = MlsFixture::new(pool.clone(), &discussion.head.authority_commit);
    let genesis = mls.with_installation(
        ordinary_realm::next_request(
            &discussion.head.authority_commit,
            arkret_wire::EventKind::MlsGenesis,
            &founder,
            mls.genesis_payload(&realm_id, at),
            at,
        ),
        None,
        0,
    );
    uow.commit_event(genesis.clone()).await.unwrap();
    let genesis_ref = genesis.authority_commit.event.event_id.clone();
    let claim_id = claim_id();
    let actor = recipient_actor(&recipient);
    let device_id = arkret_wire::DeviceId::new(recipient.device_id.clone()).unwrap();
    let mut group = mls.accepted_private_group(&genesis_ref).await;
    let mut tracker = mls.tracker(&genesis_ref);
    let member_identity = arkret_mls::ArkretMlsIdentity::new_human_device(
        actor.clone(),
        device_id,
        arkret_mls::ArkretMlsSigner::from_ed25519_signing_key(
            ed25519_dalek::SigningKey::from_bytes(
                &recipient_source.history.founding_device_signing_seed,
            ),
        ),
    )
    .unwrap();
    let mut package = member_identity.key_package_record().unwrap();
    package.state = arkret_models_crypto::MlsKeyPackageState::Claimed;
    package.claim_id = Some(claim_id.clone());
    let binding =
        MlsGovernanceBindingPayload::realm(realm_id.clone(), Some(genesis_ref.clone()), 0, 1, 0)
            .unwrap();
    let added = group
        .add_member_with_governance_binding(&package, &binding)
        .unwrap();
    let proposals = mls_public_fixture::consume(&mut tracker, &added.commit);
    mls.register_package(&package, &proposals, &recipient.authorization_ref.event_id);
    let mut commit = mls.transition(
        &genesis.authority_commit,
        group,
        tracker,
        added.commit,
        binding,
        &genesis_ref,
        proposals,
        at,
    );
    let mut delivery = welcome(&commit, &recipient, &claim_id);
    mls.seal_welcome(&mut delivery, &added.welcome);
    let parsed = arkret_mls::verify_add_proposal_leaf(
        &commit
            .authority_commit
            .mls_state
            .as_ref()
            .unwrap()
            .consumed_proposals[0]
            .proposal_wire,
    )
    .unwrap();
    let mut local = VerifiedMlsWelcome {
        delivery,
        claim: None,
        applet_device_scope_guard: None,
        roster_witness: None,
    };
    let proof = signed_add_attestation(
        &commit,
        &genesis_ref,
        &local,
        &package,
        &station,
        parsed.leaf_signature_key,
        recipient.authorization_ref.event_id.clone(),
        None,
    );
    let receipt = &proof.claim_outcome.claim_receipt;
    let key = MlsWelcomeClaimLedgerKey {
        source_id: station.to_string(),
        claim_request_id: receipt.claim_request_id.to_string(),
        request_digest: receipt.request_digest.to_string(),
    };
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query(
        "INSERT INTO peer_keypackage_claims \
         (source_id,claim_request_id,request_digest,key_package_use,keypackage_id,outcome, \
          terminal_receipt,consume_receipt,claim_expires_at_unix_ms,expires_at,state,updated_at) \
         VALUES ($1,$2,$3,'single_use',NULL,$4,NULL,NULL,$5,$6,'claimed',$7)",
    )
    .bind::<Text, _>(&key.source_id)
    .bind::<Text, _>(&key.claim_request_id)
    .bind::<Text, _>(&key.request_digest)
    .bind::<Jsonb, _>(serde_json::to_value(&proof.claim_outcome).unwrap())
    .bind::<BigInt, _>(receipt.expires_at.timestamp_millis())
    .bind::<BigInt, _>(receipt.expires_at.timestamp())
    .bind::<BigInt, _>(at.timestamp())
    .execute(&mut *conn)
    .await
    .unwrap();
    drop(conn);
    local.claim = Some(key);
    local.roster_witness = Some(coland_storage::VerifiedMlsRecipientRosterWitness {
        claim_issuer_resolution: None,
        accepted_genesis_event_ref: genesis_ref.clone(),
        signed_attest_add_request_canonical_json: arkret_canonical::canonical_json_bytes(&proof)
            .unwrap(),
        local_attestor_resolution: Some(resolution.clone()),
    });
    commit.authority_commit.welcomes = vec![local.clone()];
    commit.authority_commit.recipient_queue_capacity = 4;
    let mut tampered = commit.clone();
    tampered.authority_commit.welcomes[0]
        .roster_witness
        .as_mut()
        .unwrap()
        .local_attestor_resolution
        .as_mut()
        .unwrap()
        .service_kind = "other".to_owned();
    assert_zero_write_refusal(&pool, &tampered, ConflictCode::DuplicateConflict).await;
    assert_eq!(installed_add_attestation_count(&pool).await, 0);
    uow.commit_event(commit.clone()).await.unwrap();
    assert_eq!(welcome_count(&pool).await, 1);
    assert_eq!(installed_add_attestation_count(&pool).await, 1);
    assert_eq!(
        frozen_roster_attestor_resolution(&pool).await,
        arkret_canonical::canonical_json_bytes(&resolution).unwrap(),
    );
}

/// encryption-and-audit.md §2.2 cross-Station recipient: the governance Station
/// verifies everything but the claim of a Welcome whose recipient another
/// Station hosts and writes it, in submission order, into the Commit's
/// committed-replication intent to exactly that Station, next to the local
/// recipient's queued Welcome; a Station without a joined recipient receives
/// no Welcome, and a remote recipient that is no current joined member
/// refuses the whole Commit with zero writes.
#[tokio::test]
async fn a_remote_recipient_welcome_rides_the_commit_replication_intent() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let station = governing_station(&pool).await;
    let discussion = ordinary_realm::open_discussion(&pool, "mls-remote-welcome").await;
    let realm_id = discussion.realm_id();
    let founder = discussion
        .head
        .authority_commit
        .event
        .actor_id
        .signing_principal_id()
        .clone();
    let at = discussion.committed_at();
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let attestor = historical_roster_attestor_resolution();
    let remote_station_id = attestor.service_id.clone();
    let remote_station = remote_station_id.as_str();
    let other_station = "ak:did_core:web:mls-other-station.example";
    let member = |label: &str, station: &str| {
        arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            arkret_wire::DidCoreId::new(format!("ak:did_core:web:{label}.example")).unwrap(),
            arkret_wire::DidCoreId::new(station).unwrap(),
        ))
    };
    let (first, second, bystander) = (
        member("mls-remote-first", remote_station),
        member("mls-remote-second", remote_station),
        member("mls-remote-bystander", other_station),
    );
    for joined in [&first, &second, &bystander] {
        join(&pool, &discussion.head, joined).await;
    }
    let mls = MlsFixture::new(pool.clone(), &discussion.head.authority_commit);
    let genesis = mls.with_installation(
        ordinary_realm::next_request(
            &discussion.head.authority_commit,
            arkret_wire::EventKind::MlsGenesis,
            &founder,
            mls.genesis_payload(&realm_id, at),
            at,
        ),
        None,
        0,
    );
    uow.commit_event(genesis.clone()).await.unwrap();
    let genesis_ref = genesis.authority_commit.event.event_id.clone();

    let add = async || {
        mls.with_installation(
            ordinary_realm::next_request(
                &genesis.authority_commit,
                arkret_wire::EventKind::MlsCommit,
                &founder,
                mls.commit_payload(&realm_id, &genesis_ref, 0, 0).await,
                at,
            ),
            Some((&genesis_ref, 0)),
            1,
        )
    };
    let mut stranger = add().await;
    stranger.authority_commit.welcomes = vec![remote_welcome(
        &stranger,
        &member("mls-remote-stranger", remote_station),
    )];
    stranger.authority_commit.recipient_queue_capacity = 4;
    assert_zero_write_refusal(&pool, &stranger, ConflictCode::FailedPrecondition).await;
    assert!(replication_payloads(&pool, &stranger).await.is_empty());
    assert!(frozen_remote_welcomes(&pool, &stranger).await.is_empty());

    let mut commit = add().await;
    let mut welcomes = vec![
        remote_welcome(&commit, &first),
        remote_welcome(&commit, &second),
    ];
    welcomes.sort_by(|left, right| left.delivery.welcome_id.cmp(&right.delivery.welcome_id));
    let mut group = mls.accepted_private_group(&genesis_ref).await;
    let mut tracker = mls.tracker(&genesis_ref);
    let packages = welcomes
        .iter()
        .map(|welcome| {
            let arkret_wire::MlsWelcomeRecipientEndpoint::Device { device_id } =
                &welcome.delivery.recipient_endpoint
            else {
                unreachable!()
            };
            let identity = arkret_mls::ArkretMlsIdentity::new_test_human_device(
                welcome.delivery.recipient_actor_id.clone(),
                device_id.clone(),
            )
            .unwrap();
            let mut package = identity.key_package_record().unwrap();
            package.state = arkret_models_crypto::MlsKeyPackageState::Claimed;
            package.claim_id = Some(welcome.delivery.keypackage_claim_ref.to_string());
            package
        })
        .collect::<Vec<_>>();
    let member_keypackage = packages
        .iter()
        .find(|p| p.actor_id == first)
        .unwrap()
        .clone();
    let binding =
        MlsGovernanceBindingPayload::realm(realm_id.clone(), Some(genesis_ref.clone()), 0, 1, 0)
            .unwrap();
    let added = group
        .add_members_with_governance_binding(&packages, &binding)
        .unwrap();
    let proposals = mls_public_fixture::consume(&mut tracker, &added.commit);
    let remote_authorization =
        arkret_wire::EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [71; 32]);
    for package in &packages {
        mls.register_package(package, &proposals, &remote_authorization);
    }
    commit = mls.transition(
        &genesis.authority_commit,
        group,
        tracker,
        added.commit,
        binding,
        &genesis_ref,
        proposals,
        at,
    );
    for welcome in &mut welcomes {
        welcome.delivery.commit_event_ref = commit.authority_commit.event.event_id.clone();
        let draft = added
            .welcomes
            .iter()
            .find(|draft| draft.keypackage_claim_ref == welcome.delivery.keypackage_claim_ref)
            .unwrap();
        mls.seal_welcome(&mut welcome.delivery, draft);
    }
    commit.authority_commit.welcomes = welcomes.clone();
    commit.authority_commit.recipient_queue_capacity = 4;
    uow.commit_event(commit.clone()).await.unwrap();
    assert_eq!(welcome_count(&pool).await, 0);

    let payloads = replication_payloads(&pool, &commit).await;
    let expected_frozen = welcomes
        .iter()
        .filter(|welcome| welcome.claim.is_none())
        .map(|welcome| {
            (
                welcome.delivery.welcome_id.to_string(),
                arkret_canonical::canonical_json_bytes(&welcome.delivery).unwrap(),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        frozen_remote_welcomes(&pool, &commit).await,
        expected_frozen,
        "the original producer-signed remote delivery is retained independently"
    );
    let first_welcome = welcomes
        .iter()
        .find(|welcome| welcome.delivery.recipient_actor_id == first)
        .unwrap();
    let add_proposal = commit
        .authority_commit
        .mls_state
        .as_ref()
        .unwrap()
        .consumed_proposals
        .iter()
        .find(|proposal| {
            proposal.proposal_type == 1
                && proposal
                    .target_after
                    .as_ref()
                    .is_some_and(|leaf| leaf.actor_id == first)
        })
        .unwrap();
    let add_leaf = arkret_mls::verify_add_proposal_leaf(&add_proposal.proposal_wire).unwrap();
    assert_eq!(add_leaf.actor_id, first);
    let proof = signed_remote_add_attestation(
        &commit,
        &genesis_ref,
        first_welcome,
        &member_keypackage,
        &station,
        add_leaf.leaf_signature_key,
    );
    let governance = PgAuthorityCommitStore { pool: pool.clone() };
    let roster_request =
        arkret_models_collaboration::mls_roster_authority::MlsRosterAuthorityReadRequestBody {
            realm_id: realm_id.clone(),
            effective_scope: realm_scope(&realm_id),
            mls_group_id: realm_scope(&realm_id).canonical_mls_group_id().unwrap(),
            genesis_event_ref: genesis_ref.clone(),
            target_commit_event_ref: commit.authority_commit.event.event_id.clone(),
            target_epoch: 1,
            caller_actor_id: arkret_wire::ActorId::account(arkret_wire::AccountId::new(
                founder.clone(),
                station.clone(),
            )),
            cursor: None,
        };
    assert!(matches!(
        governance
            .mls_roster_authority_read(&roster_request, &station, None)
            .await
            .unwrap(),
        coland_storage::MlsRosterAuthorityRead::RevisionUnavailable
    ));
    let verified = coland_storage::VerifiedMlsAddAuthorityAttestation {
        claim_issuer_resolution: attestor.clone(),
        source_station_id: arkret_wire::DidCoreId::new(remote_station).unwrap(),
        request: proof.clone(),
        attestor_resolution: attestor,
    };
    arkret::verify_mls_attest_add_request(
        &verified.request,
        &verified.attestor_resolution,
        &verified.attestor_resolution,
    )
    .unwrap();
    let closure_bytes =
        arkret_canonical::canonical_json_bytes(&verified.attestor_resolution).unwrap();
    let closure_roundtrip: arkret_models_identity::AuthenticatedServiceResolution =
        serde_json::from_slice(&closure_bytes).unwrap();
    assert_eq!(
        closure_bytes,
        arkret_canonical::canonical_json_bytes(&closure_roundtrip).unwrap(),
        "historical closure must have stable typed canonical bytes"
    );
    arkret::verify_mls_attest_add_request(
        &verified.request,
        &closure_roundtrip,
        &closure_roundtrip,
    )
    .unwrap();
    let mut wrong_source = verified.clone();
    wrong_source.source_station_id = station.clone();
    assert!(
        governance
            .install_mls_add_authority_attestation(&wrong_source, &station)
            .await
            .is_err()
    );
    let mut wrong_resolution = verified.clone();
    wrong_resolution.attestor_resolution.service_kind = "other".to_owned();
    assert!(
        governance
            .install_mls_add_authority_attestation(&wrong_resolution, &station)
            .await
            .is_err(),
        "a non-Station historical closure cannot be installed"
    );
    let mut wrong_leaf = verified.clone();
    wrong_leaf.request.attestation.leaf_signature_key_base64url =
        arkret_wire::Base64UrlString::new(arkret_canonical::base64url_encode([8_u8; 32])).unwrap();
    assert!(
        governance
            .install_mls_add_authority_attestation(&wrong_leaf, &station)
            .await
            .is_err()
    );
    let mut wrong_genesis = verified.clone();
    wrong_genesis.request.attestation.genesis_event_ref =
        arkret_wire::EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [72_u8; 32]);
    assert!(
        governance
            .install_mls_add_authority_attestation(&wrong_genesis, &station)
            .await
            .is_err()
    );
    let fresh_keypackage = arkret_mls::ArkretMlsIdentity::new_test_human_device(
        first.clone(),
        match &first_welcome.delivery.recipient_endpoint {
            arkret_wire::MlsWelcomeRecipientEndpoint::Device { device_id } => device_id.clone(),
            _ => unreachable!(),
        },
    )
    .unwrap()
    .key_package_record()
    .unwrap();
    let wrong_keypackage = coland_storage::VerifiedMlsAddAuthorityAttestation {
        claim_issuer_resolution: verified.claim_issuer_resolution.clone(),
        source_station_id: verified.source_station_id.clone(),
        attestor_resolution: verified.attestor_resolution.clone(),
        request: signed_remote_add_attestation(
            &commit,
            &genesis_ref,
            first_welcome,
            &fresh_keypackage,
            &station,
            verified
                .request
                .attestation
                .leaf_signature_key_base64url
                .clone(),
        ),
    };
    assert!(
        governance
            .install_mls_add_authority_attestation(&wrong_keypackage, &station)
            .await
            .is_err(),
        "a newly signed claim for another KeyPackage cannot match the frozen Add"
    );
    let unknown_welcome = remote_welcome(&commit, &first);
    let wrong_welcome = coland_storage::VerifiedMlsAddAuthorityAttestation {
        claim_issuer_resolution: verified.claim_issuer_resolution.clone(),
        source_station_id: verified.source_station_id.clone(),
        attestor_resolution: verified.attestor_resolution.clone(),
        request: signed_remote_add_attestation(
            &commit,
            &genesis_ref,
            &unknown_welcome,
            &member_keypackage,
            &station,
            verified
                .request
                .attestation
                .leaf_signature_key_base64url
                .clone(),
        ),
    };
    assert!(
        governance
            .install_mls_add_authority_attestation(&wrong_welcome, &station)
            .await
            .is_err(),
        "an unaccepted Welcome cannot install an Add proof"
    );
    assert_eq!(installed_add_attestation_count(&pool).await, 0);
    let installed = governance
        .install_mls_add_authority_attestation(&verified, &station)
        .await
        .unwrap();
    assert_eq!(
        installed.status,
        arkret_models_collaboration::mls_roster_authority::MlsAttestAddStatus::Installed
    );
    assert_eq!(
        governance
            .install_mls_add_authority_attestation(&verified, &station)
            .await
            .unwrap()
            .status,
        arkret_models_collaboration::mls_roster_authority::MlsAttestAddStatus::Duplicate
    );
    assert_eq!(installed_add_attestation_count(&pool).await, 1);
    let original_resolution = frozen_roster_attestor_resolution(&pool).await;
    assert_eq!(
        original_resolution,
        arkret_canonical::canonical_json_bytes(&verified.attestor_resolution).unwrap(),
        "ingress freezes the complete verified method-native closure"
    );
    assert!(
        governance
            .install_mls_add_authority_attestation(&wrong_resolution, &station)
            .await
            .is_err(),
        "a replay cannot replace retained evidence with a non-Station closure"
    );
    assert_eq!(
        frozen_roster_attestor_resolution(&pool).await,
        original_resolution
    );
    let second_welcome = welcomes
        .iter()
        .find(|w| w.delivery.recipient_actor_id == second)
        .unwrap();
    let second_package = packages.iter().find(|p| p.actor_id == second).unwrap();
    let second_leaf = commit
        .authority_commit
        .mls_state
        .as_ref()
        .unwrap()
        .consumed_proposals
        .iter()
        .filter(|p| p.proposal_type == 1)
        .map(|p| arkret_mls::verify_add_proposal_leaf(&p.proposal_wire).unwrap())
        .find(|leaf| leaf.actor_id == second)
        .unwrap();
    let second_verified = coland_storage::VerifiedMlsAddAuthorityAttestation {
        claim_issuer_resolution: verified.claim_issuer_resolution.clone(),
        source_station_id: verified.source_station_id.clone(),
        attestor_resolution: verified.attestor_resolution.clone(),
        request: signed_remote_add_attestation(
            &commit,
            &genesis_ref,
            second_welcome,
            second_package,
            &station,
            second_leaf.leaf_signature_key,
        ),
    };
    governance
        .install_mls_add_authority_attestation(&second_verified, &station)
        .await
        .unwrap();
    assert_eq!(installed_add_attestation_count(&pool).await, 2);
    let roster = governance
        .mls_roster_authority_read(&roster_request, &station, None)
        .await
        .unwrap();
    let coland_storage::MlsRosterAuthorityRead::Authorized { facts: Some(facts) } = roster else {
        panic!("complete installed Add history is authorized for the founder")
    };
    assert_eq!(facts.records.len(), 3);
    assert_eq!(facts.historical_add_proofs.len(), 2);
    assert_eq!(
        arkret_canonical::canonical_json_bytes(
            facts
                .historical_add_proofs
                .iter()
                .find(|p| p.attestation.welcome_id == first_welcome.delivery.welcome_id)
                .unwrap()
        )
        .unwrap(),
        arkret_canonical::canonical_json_bytes(&verified.request).unwrap(),
        "the private original claim outcome is selected from the same governing cut"
    );
    assert_eq!(
        facts.authority_head_commit_event_ref,
        commit.authority_commit.event.event_id
    );
    assert!(matches!(
        &facts.records[0],
        arkret_models_collaboration::mls_roster_authority::MlsRosterRecord::Genesis { genesis_event_ref, .. }
            if genesis_event_ref == &genesis_ref
    ));
    let expected_ordinal = commit
        .authority_commit
        .mls_state
        .as_ref()
        .unwrap()
        .consumed_proposals
        .iter()
        .find(|p| {
            p.target_after
                .as_ref()
                .is_some_and(|leaf| leaf.actor_id == first)
        })
        .unwrap()
        .ordinal;
    assert!(facts.records.iter().any(|record|matches!(record,
        arkret_models_collaboration::mls_roster_authority::MlsRosterRecord::Add {commit_event_ref,consumed_proposal_ordinal,attestor_resolution,..}
        if commit_event_ref==&commit.authority_commit.event.event_id
            && *consumed_proposal_ordinal==expected_ordinal
            && arkret_canonical::canonical_json_bytes(attestor_resolution).unwrap()==original_resolution)));
    let conflicting_replay = coland_storage::VerifiedMlsAddAuthorityAttestation {
        claim_issuer_resolution: verified.claim_issuer_resolution.clone(),
        source_station_id: verified.source_station_id.clone(),
        attestor_resolution: verified.attestor_resolution.clone(),
        request: signed_remote_add_attestation(
            &commit,
            &genesis_ref,
            first_welcome,
            &member_keypackage,
            &station,
            verified
                .request
                .attestation
                .leaf_signature_key_base64url
                .clone(),
        ),
    };
    assert!(
        governance
            .install_mls_add_authority_attestation(&conflicting_replay, &station)
            .await
            .is_err(),
        "same Welcome with a different signed historical claim must not replace the winner"
    );
    assert_eq!(installed_add_attestation_count(&pool).await, 2);
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query(
        "UPDATE mls_add_authority_attestations SET attestor_resolution_canonical_json=$1",
    )
    .bind::<Binary, _>(vec![b'{'])
    .execute(&mut *conn)
    .await
    .unwrap();
    drop(conn);
    assert!(matches!(
        governance
            .mls_roster_authority_read(&roster_request, &station, None)
            .await
            .unwrap(),
        coland_storage::MlsRosterAuthorityRead::RevisionUnavailable
    ));
    assert!(
        governance
            .install_mls_add_authority_attestation(&verified, &station)
            .await
            .is_err(),
        "a damaged retained closure cannot be replaced by replay"
    );
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query(
        "UPDATE mls_add_authority_attestations SET attestor_resolution_canonical_json=$1",
    )
    .bind::<Binary, _>(original_resolution)
    .execute(&mut *conn)
    .await
    .unwrap();
    drop(conn);
    assert_eq!(
        payloads
            .iter()
            .map(|(peer, _)| peer.as_str())
            .collect::<Vec<_>>(),
        [remote_station, other_station]
    );
    let item = |payload: &serde_json::Value| payload["replications"][0].clone();
    for (_, payload) in &payloads {
        assert_eq!(
            item(payload)["genesis_event_ref"],
            serde_json::json!(genesis_ref),
            "each signed peer item freezes the same accepted Genesis"
        );
    }
    assert!(item(&payloads[1].1).get("welcomes").is_none());
    let expected = welcomes
        .iter()
        .filter(|welcome| welcome.claim.is_none())
        .map(|welcome| serde_json::to_value(&welcome.delivery).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        item(&payloads[0].1)["welcomes"],
        serde_json::json!(expected)
    );
    let request: arkret_models_collaboration::authority_commit::PeerAuthoritySubmitRequestBody =
        serde_json::from_value(payloads[0].1.clone()).unwrap();
    request.validate().unwrap();
    uow.commit_event(commit.clone()).await.unwrap();
    assert_eq!(
        frozen_remote_welcomes(&pool, &commit).await,
        expected_frozen,
        "an exact accepted Commit replay cannot duplicate or rewrite remote Welcome provenance"
    );

    let commit_ref = commit.authority_commit.event.event_id.clone();
    let later = mls.with_installation(
        ordinary_realm::next_request(
            &commit.authority_commit,
            arkret_wire::EventKind::MlsCommit,
            &founder,
            mls.commit_payload(&realm_id, &commit_ref, 1, 0).await,
            at,
        ),
        Some((&commit_ref, 1)),
        2,
    );
    let mut conflicting_later = later.clone();
    let mut reused_welcome = remote_welcome(&conflicting_later, &first);
    reused_welcome.delivery.welcome_id = welcomes
        .iter()
        .find(|welcome| welcome.claim.is_none())
        .unwrap()
        .delivery
        .welcome_id
        .clone();
    conflicting_later.authority_commit.welcomes = vec![reused_welcome];
    conflicting_later.authority_commit.recipient_queue_capacity = 4;
    assert_zero_write_refusal(&pool, &conflicting_later, ConflictCode::DuplicateConflict).await;
    assert_eq!(
        frozen_remote_welcomes(&pool, &commit).await,
        expected_frozen
    );
    assert!(
        frozen_remote_welcomes(&pool, &conflicting_later)
            .await
            .is_empty()
    );
    uow.commit_event(later.clone()).await.unwrap();
    assert!(frozen_remote_welcomes(&pool, &later).await.is_empty());
    for (_, payload) in replication_payloads(&pool, &later).await {
        assert_eq!(
            item(&payload)["genesis_event_ref"],
            serde_json::json!(genesis_ref),
            "a later Commit's base is not substituted for immutable Genesis"
        );
    }
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query(
        "UPDATE mls_add_authority_attestations SET request_json = request_json - 'attestation' WHERE commit_event_ref = $1",
    )
    .bind::<Text, _>(commit.authority_commit.event.event_id.as_str())
    .execute(&mut *conn)
    .await
    .unwrap();
    drop(conn);
    assert!(
        matches!(
            governance
                .mls_roster_authority_read(&roster_request, &station, None)
                .await
                .unwrap(),
            coland_storage::MlsRosterAuthorityRead::RevisionUnavailable
        ),
        "an installed Add with missing signed historical proof cannot be disclosed"
    );
}

// These tests exercise the ordinary Self/Peer shared PG unit over real RFC
// transitions, signed Welcomes and signed local claim/history originals. The
// fixture supplies the claim-service port; it does not claim HTTP coverage.
async fn mls_retry_base(
    pool: &PgPool,
    seed: &str,
) -> (EventCommitRequest, DeviceRevocationGateSelector, MlsFixture) {
    let station = local_station(pool).await;
    let persistence = coland_storage_postgres::PgPersistenceStore::new(pool.clone());
    let source = pcr_genesis::PcrGenesisFixture::new_with(
        historical_roster_attestor_resolution()
            .normalized_did_document
            .id
            .clone(),
        device_authorization_history::DeviceHistoryFixtureOptions {
            founding_device_signing_seed: [112; 32],
            ..Default::default()
        },
    );
    let recipient = Box::pin(source.admit_founding_device(&persistence))
        .await
        .unwrap();
    let discussion = Box::pin(ordinary_realm::open_discussion_for_station(
        pool,
        seed,
        &station,
        &historical_roster_attestor_resolution()
            .normalized_did_document
            .id,
    ))
    .await;
    join(pool, &discussion.head, &recipient_actor(&recipient)).await;
    let mls = MlsFixture::new(pool.clone(), &discussion.head.authority_commit);
    let genesis = mls.with_installation(
        ordinary_realm::next_request(
            &discussion.head.authority_commit,
            arkret_wire::EventKind::MlsGenesis,
            discussion
                .head
                .authority_commit
                .event
                .actor_id
                .signing_principal_id(),
            mls.genesis_payload(&discussion.realm_id(), discussion.committed_at()),
            discussion.committed_at(),
        ),
        None,
        0,
    );
    PgEventCommitUnitOfWork::new(pool.clone())
        .commit_event(genesis.clone())
        .await
        .unwrap();
    (genesis, recipient, mls)
}

async fn mls_retry_commit(
    pool: &PgPool,
    mls: &MlsFixture,
    previous: &EventCommitRequest,
    recipient: &DeviceRevocationGateSelector,
    claim_id: &str,
    revision: u64,
) -> EventCommitRequest {
    let (request, _) = Box::pin(mls_local_add_fixture::add(
        pool, mls, previous, recipient, [112; 32], claim_id, revision, None,
    ))
    .await;
    assert!(request.self_producer_guard.is_none());
    assert!(request.authority_commit.event.applet_id.is_none());
    request
}

fn mls_complete_retry_record(
    request: &EventCommitRequest,
    key: uuid::Uuid,
    outcome: arkret_wire::AuthoritySubmitResponseBody,
) -> coland_storage::IdempotencyRecord {
    use arkret_models_collaboration::authority_commit::{
        SelfAuthoritySubmitRequestBody, SelfAuthoritySubmitResponseBody,
    };
    let submission = arkret_wire::MlsCommitSubmission {
        commit_event: request.authority_commit.event.clone(),
        welcomes: request
            .authority_commit
            .welcomes
            .iter()
            .map(|w| w.delivery.clone())
            .collect(),
        idempotency_key: arkret_wire::UuidV7::new(key).unwrap(),
        recovery_source: None,
    };
    submission.validate().unwrap();
    let body = SelfAuthoritySubmitRequestBody::MlsCommit(submission);
    let bytes = arkret_canonical::canonical_json_bytes(&body).unwrap();
    let at = request.authority_commit.commit.committed_at;
    coland_storage::IdempotencyRecord {
        authenticated_actor: request.authority_commit.event.actual_signer().clone(),
        operation_id: arkret_wire::ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT_V1.into(),
        idempotency_key: key.to_string(),
        request_hash: arkret_canonical::sha256_digest(&bytes),
        response_status: 200,
        response_body: serde_json::to_value(SelfAuthoritySubmitResponseBody::Ordinary(outcome))
            .unwrap(),
        created_at: at,
        expires_at: at + chrono::Duration::days(30),
    }
}

fn mls_committed_retry_record(
    request: &EventCommitRequest,
    key: uuid::Uuid,
) -> coland_storage::IdempotencyRecord {
    mls_complete_retry_record(
        request,
        key,
        arkret_wire::AuthoritySubmitResponseBody::Accepted {
            status: arkret_wire::AuthorityCommitStatus::Committed,
            commit: request.authority_commit.commit.clone(),
        },
    )
}

// All durable MLS effects, including the claim binding and complete request
// ledger. Sequence gaps are not durable accepted effects and are not compared.
async fn mls_complete_retry_footprint(pool: &PgPool) -> serde_json::Value {
    #[derive(diesel::QueryableByName)]
    struct Rows {
        #[diesel(sql_type = Jsonb)]
        value: serde_json::Value,
    }
    let mut conn = pool.get().await.unwrap();
    let mut result = serde_json::Map::new();
    for table in [
        "canonical_events",
        "realm_commits",
        "realm_commit_event_kinds",
        "realm_authorities",
        "current_state_heads",
        "current_state_versions",
        "mls_group_current_states",
        "mls_endpoint_current_bindings",
        "mls_consumed_proposal_provenance",
        "mls_welcome_deliveries",
        "mls_welcome_provenance",
        "peer_keypackage_claims",
        "keypackage_claim_welcome_bindings",
        "mls_add_authority_attestations",
        "mls_add_authority_attestation_outbox",
        "blobs",
        "projection_events",
        "federation_outbox",
        "event_federation_outbox",
        "idempotency_keys",
    ] {
        let rows = diesel::sql_query(format!(
            "SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text),'[]'::jsonb) AS value FROM public.{table} t"
        )).get_result::<Rows>(&mut *conn).await.unwrap();
        result.insert(table.into(), rows.value);
    }
    serde_json::Value::Object(result)
}

async fn assert_original_mls_retry(pool: &PgPool, original: &coland_storage::IdempotencyRecord) {
    use coland_storage::IdempotencyStore;
    let stored = coland_storage_postgres::PgIdempotencyStore { pool: pool.clone() }
        .get(
            &original.authenticated_actor,
            &original.operation_id,
            &original.idempotency_key,
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored, *original);
    assert_eq!(
        arkret_canonical::canonical_json_bytes(&stored.response_body).unwrap(),
        arkret_canonical::canonical_json_bytes(&original.response_body).unwrap(),
    );
}

#[tokio::test]
async fn ordinary_mls_complete_retry_returns_original_committed_outcome_without_aliases() {
    use coland_storage::IdempotencyStore;
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let (genesis, recipient, mls) = Box::pin(mls_retry_base(&pool, "mls-complete-committed")).await;
    let claim_id = claim_id();
    let mut request = Box::pin(mls_retry_commit(
        &pool, &mls, &genesis, &recipient, &claim_id, 0,
    ))
    .await;
    let key = uuid::Uuid::now_v7();
    let original = mls_committed_retry_record(&request, key);
    request.idempotency = Some(original.clone());
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    assert!(
        uow.commit_event(request.clone())
            .await
            .unwrap()
            .event_inserted
    );
    assert_original_mls_retry(&pool, &original).await;
    let before = mls_complete_retry_footprint(&pool).await;
    assert!(
        !uow.commit_event(request.clone())
            .await
            .unwrap()
            .event_inserted
    );
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    let mut old_authority = store
        .current_authority(&request.authority_commit.event.realm_id)
        .await
        .unwrap()
        .unwrap();
    old_authority.generation += 1;
    let recovered = store
        .finalize_mls_rejection(
            &request.authority_commit.event,
            &old_authority,
            "late_current_failure",
            None,
            Some(&original),
        )
        .await
        .unwrap();
    let recovered = serde_json::to_value(
        arkret_models_collaboration::authority_commit::SelfAuthoritySubmitResponseBody::Ordinary(
            recovered,
        ),
    )
    .unwrap();
    assert_eq!(
        arkret_canonical::canonical_json_bytes(&recovered).unwrap(),
        arkret_canonical::canonical_json_bytes(&original.response_body).unwrap()
    );
    assert_eq!(mls_complete_retry_footprint(&pool).await, before);

    // The Event is unchanged, while one signed Welcome byte changes the full hash.
    let mut changed = request.clone();
    changed.authority_commit.welcomes[0]
        .delivery
        .ciphertext_base64url = arkret_wire::Base64UrlString::new("Y2hhbmdlZA").unwrap();
    let changed_record = mls_committed_retry_record(&changed, key);
    assert_ne!(changed_record.request_hash, original.request_hash);
    changed.idempotency = Some(changed_record.clone());
    assert_eq!(
        uow.commit_event(changed).await.unwrap_err().conflict_code(),
        Some(ConflictCode::DuplicateConflict)
    );
    assert_eq!(
        store
            .finalize_mls_rejection(
                &request.authority_commit.event,
                &old_authority,
                "late_current_failure",
                None,
                Some(&changed_record)
            )
            .await
            .unwrap_err()
            .conflict_code(),
        Some(ConflictCode::DuplicateConflict)
    );

    let alias = mls_committed_retry_record(&request, uuid::Uuid::now_v7());
    let mut aliased = request.clone();
    aliased.idempotency = Some(alias.clone());
    assert_eq!(
        uow.commit_event(aliased).await.unwrap_err().conflict_code(),
        Some(ConflictCode::DuplicateConflict)
    );
    assert_eq!(
        store
            .finalize_mls_rejection(
                &request.authority_commit.event,
                &old_authority,
                "late_current_failure",
                None,
                Some(&alias)
            )
            .await
            .unwrap_err()
            .conflict_code(),
        Some(ConflictCode::DuplicateConflict)
    );
    assert!(
        coland_storage_postgres::PgIdempotencyStore { pool: pool.clone() }
            .get(
                &alias.authenticated_actor,
                &alias.operation_id,
                &alias.idempotency_key
            )
            .await
            .unwrap()
            .is_none()
    );
    let mut wrong_outcome = request.clone();
    wrong_outcome.idempotency.as_mut().unwrap().response_body = serde_json::to_value(
        arkret_models_collaboration::authority_commit::SelfAuthoritySubmitResponseBody::Ordinary(
            arkret_wire::AuthoritySubmitResponseBody::Accepted {
                status: arkret_wire::AuthorityCommitStatus::Duplicate,
                commit: request.authority_commit.commit.clone(),
            },
        ),
    )
    .unwrap();
    assert_eq!(
        uow.commit_event(wrong_outcome)
            .await
            .unwrap_err()
            .conflict_code(),
        Some(ConflictCode::DuplicateConflict)
    );
    assert_original_mls_retry(&pool, &original).await;
    assert_eq!(mls_complete_retry_footprint(&pool).await, before);
}

#[tokio::test]
async fn ordinary_mls_conflicting_complete_key_rolls_back_every_effect_after_ledger_wait() {
    use diesel::sql_types::{Bool, Integer};
    use diesel_async::SimpleAsyncConnection;
    #[derive(diesel::QueryableByName)]
    struct Pid {
        #[diesel(sql_type = Integer)]
        pid: i32,
    }
    #[derive(diesel::QueryableByName)]
    struct Waiting {
        #[diesel(sql_type = Bool)]
        waiting: bool,
    }
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let (genesis, recipient, mls) = Box::pin(mls_retry_base(&pool, "mls-complete-conflict")).await;
    let first_claim_id = claim_id();
    let mut first = Box::pin(mls_retry_commit(
        &pool,
        &mls,
        &genesis,
        &recipient,
        &first_claim_id,
        0,
    ))
    .await;
    let key = uuid::Uuid::now_v7();
    let original = mls_committed_retry_record(&first, key);
    first.idempotency = Some(original.clone());
    PgEventCommitUnitOfWork::new(pool.clone())
        .commit_event(first.clone())
        .await
        .unwrap();
    let second_claim_id = claim_id();
    let mut candidate = Box::pin(mls_retry_commit(
        &pool,
        &mls,
        &first,
        &recipient,
        &second_claim_id,
        0,
    ))
    .await;
    let conflicting = mls_committed_retry_record(&candidate, key);
    assert_ne!(conflicting.request_hash, original.request_hash);
    candidate.idempotency = Some(conflicting);
    let before = mls_complete_retry_footprint(&pool).await;

    // Hold a genuine uncommitted MVCC version of the original retry row,
    // without changing any key or value. The contender's late INSERT must
    // resolve that writer before its complete-unit conflict can be classified.
    let mut holder = pool.get().await.unwrap();
    holder.batch_execute("BEGIN").await.unwrap();
    let pid = diesel::sql_query("UPDATE idempotency_keys SET request_hash=request_hash WHERE actor_key=$1 AND operation_id=$2 AND idempotency_key=$3 RETURNING pg_backend_pid() AS pid")
        .bind::<Text,_>(original.authenticated_actor.canonical_key().unwrap())
        .bind::<Text,_>(&original.operation_id).bind::<Text,_>(&original.idempotency_key)
        .get_result::<Pid>(&mut *holder).await.unwrap().pid;
    let attempted = candidate.clone();
    let writer_pool = pool.clone();
    let mut writer = tokio::spawn(async move {
        PgEventCommitUnitOfWork::new(writer_pool)
            .commit_event(attempted)
            .await
    });
    let observed = tokio::time::timeout(std::time::Duration::from_secs(30), async {
        tokio::select! {
            result = &mut writer => Err(result),
            () = async {
                let mut observer = pool.get().await.unwrap();
                loop {
                    let waiting = diesel::sql_query("SELECT EXISTS(SELECT 1 FROM pg_stat_activity a WHERE a.datname=current_database() AND $1=ANY(pg_blocking_pids(a.pid)) AND a.wait_event_type='Lock' AND a.query ILIKE '%idempotency_keys%') AS waiting")
                        .bind::<Integer,_>(pid).get_result::<Waiting>(&mut *observer).await.unwrap().waiting;
                    if waiting { break; }
                    tokio::task::yield_now().await;
                }
            } => Ok(()),
        }
    }).await;
    // Always release the real lock before an assertion can unwind this test.
    holder.batch_execute("ROLLBACK").await.unwrap();
    let waited = match observed {
        Ok(Ok(())) => true,
        Ok(Err(result)) => {
            panic!("candidate completed before the complete-unit ledger barrier: {result:?}")
        }
        Err(_) => false,
    };
    assert!(
        waited,
        "the candidate must reach the complete-unit ledger barrier"
    );
    let error = tokio::time::timeout(std::time::Duration::from_secs(30), writer)
        .await
        .unwrap()
        .unwrap()
        .unwrap_err();
    assert_eq!(error.conflict_code(), Some(ConflictCode::DuplicateConflict));
    assert_eq!(mls_complete_retry_footprint(&pool).await, before);
    assert_original_mls_retry(&pool, &original).await;
    assert!(
        PgAuthorityCommitStore { pool: pool.clone() }
            .committed_event(&candidate.authority_commit.event.event_id)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        coland_storage_postgres::PgMlsKeyPackageStore { pool: pool.clone() }
            .get_claim_welcome_binding(&second_claim_id)
            .await
            .unwrap()
            .is_none()
    );

    // A new unit with a new key really is admissible: the same installation,
    // Welcome and claim commit successfully once the conflicting key is removed.
    let fresh = mls_committed_retry_record(&candidate, uuid::Uuid::now_v7());
    candidate.idempotency = Some(fresh.clone());
    assert!(
        PgEventCommitUnitOfWork::new(pool.clone())
            .commit_event(candidate)
            .await
            .unwrap()
            .event_inserted
    );
    assert!(
        coland_storage_postgres::PgMlsKeyPackageStore { pool: pool.clone() }
            .get_claim_welcome_binding(&second_claim_id)
            .await
            .unwrap()
            .is_some()
    );
    assert_original_mls_retry(&pool, &fresh).await;
}

#[tokio::test]
async fn ordinary_mls_complete_retry_preserves_original_rejected_outcome_without_aliases() {
    use coland_storage::IdempotencyStore;
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let (genesis, recipient, mls) = Box::pin(mls_retry_base(&pool, "mls-complete-rejected")).await;
    let claim_id = claim_id();
    let mut request = Box::pin(mls_retry_commit(
        &pool, &mls, &genesis, &recipient, &claim_id, 1,
    ))
    .await;
    let original = mls_complete_retry_record(
        &request,
        uuid::Uuid::now_v7(),
        arkret_wire::AuthoritySubmitResponseBody::Rejected {
            status: arkret_wire::AuthorityRejectionStatus::Rejected,
            reason_code: "governance_binding_mismatch".into(),
        },
    );
    request.idempotency = Some(original.clone());
    let unaccepted = mls_complete_retry_footprint(&pool).await;
    assert_zero_write_refusal(&pool, &request, ConflictCode::GovernanceBindingMismatch).await;
    assert_eq!(mls_complete_retry_footprint(&pool).await, unaccepted);
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    let authority = store
        .current_authority(&request.authority_commit.event.realm_id)
        .await
        .unwrap()
        .unwrap();
    let first = store
        .finalize_mls_rejection(
            &request.authority_commit.event,
            &authority,
            "governance_binding_mismatch",
            None,
            Some(&original),
        )
        .await
        .unwrap();
    let before = mls_complete_retry_footprint(&pool).await;
    let replay = store
        .finalize_mls_rejection(
            &request.authority_commit.event,
            &authority,
            "different_late_reason",
            None,
            Some(&original),
        )
        .await
        .unwrap();
    assert_eq!(replay, first);
    let bytes = arkret_canonical::canonical_json_bytes(
        &arkret_models_collaboration::authority_commit::SelfAuthoritySubmitResponseBody::Ordinary(
            replay,
        ),
    )
    .unwrap();
    assert_eq!(
        bytes,
        arkret_canonical::canonical_json_bytes(&original.response_body).unwrap()
    );
    let alias = mls_complete_retry_record(&request, uuid::Uuid::now_v7(), first.clone());
    assert_eq!(
        store
            .finalize_mls_rejection(
                &request.authority_commit.event,
                &authority,
                "different_late_reason",
                None,
                Some(&alias)
            )
            .await
            .unwrap_err()
            .conflict_code(),
        Some(ConflictCode::DuplicateConflict)
    );
    let key = uuid::Uuid::parse_str(&original.idempotency_key).unwrap();
    request.authority_commit.welcomes[0]
        .delivery
        .ciphertext_base64url = arkret_wire::Base64UrlString::new("Y2hhbmdlZA").unwrap();
    let changed = mls_complete_retry_record(&request, key, first);
    assert_ne!(changed.request_hash, original.request_hash);
    assert_eq!(
        store
            .finalize_mls_rejection(
                &request.authority_commit.event,
                &authority,
                "different_late_reason",
                None,
                Some(&changed)
            )
            .await
            .unwrap_err()
            .conflict_code(),
        Some(ConflictCode::DuplicateConflict)
    );
    assert!(
        coland_storage_postgres::PgIdempotencyStore { pool: pool.clone() }
            .get(
                &alias.authenticated_actor,
                &alias.operation_id,
                &alias.idempotency_key
            )
            .await
            .unwrap()
            .is_none()
    );
    assert_original_mls_retry(&pool, &original).await;
    assert_eq!(mls_complete_retry_footprint(&pool).await, before);
    assert_eq!(welcome_count(&pool).await, 0);
    assert!(
        coland_storage_postgres::PgMlsKeyPackageStore { pool: pool.clone() }
            .get_claim_welcome_binding(&claim_id)
            .await
            .unwrap()
            .is_none()
    );
}

async fn mls_result_source_pk(
    pool: &PgPool,
    record: &coland_storage::IdempotencyRecord,
) -> Option<i64> {
    #[derive(diesel::QueryableByName)]
    struct Source {
        #[diesel(sql_type = diesel::sql_types::Nullable<BigInt>)]
        pk: Option<i64>,
    }
    let mut conn = pool.get().await.unwrap();
    let rows = diesel::sql_query("SELECT source_event_pk AS pk FROM idempotency_keys WHERE actor_key=$1 AND operation_id=$2 AND idempotency_key=$3")
        .bind::<Text,_>(record.authenticated_actor.canonical_key().unwrap())
        .bind::<Text,_>(&record.operation_id).bind::<Text,_>(&record.idempotency_key)
        .get_results::<Source>(&mut *conn).await.unwrap();
    assert!(rows.len() <= 1);
    rows.as_slice().first().and_then(|row| row.pk)
}

async fn mls_original_pk(pool: &PgPool, event: &arkret_wire::Event) -> i64 {
    #[derive(diesel::QueryableByName)]
    struct Source {
        #[diesel(sql_type = BigInt)]
        pk: i64,
    }
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query("SELECT pk FROM canonical_events WHERE id=$1")
        .bind::<Binary, _>(
            coland_storage::ids::parse_event_id(event.event_id.as_str())
                .unwrap()
                .to_vec(),
        )
        .get_result::<Source>(&mut *conn)
        .await
        .unwrap()
        .pk
}

#[tokio::test]
async fn mls_source_results_survive_generic_cache_gc_and_follow_actual_source_deletion() {
    use coland_storage::IdempotencyStore;
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let (genesis, recipient, mls) = Box::pin(mls_retry_base(&pool, "mls-result-retention")).await;
    let id = claim_id();
    let mut accepted = Box::pin(mls_retry_commit(&pool, &mls, &genesis, &recipient, &id, 0)).await;
    let original = mls_committed_retry_record(&accepted, uuid::Uuid::now_v7());
    accepted.idempotency = Some(original.clone());
    PgEventCommitUnitOfWork::new(pool.clone())
        .commit_event(accepted.clone())
        .await
        .unwrap();
    assert_eq!(
        mls_result_source_pk(&pool, &original).await,
        Some(mls_original_pk(&pool, &accepted.authority_commit.event).await)
    );
    let id = claim_id();
    let rejected = Box::pin(mls_retry_commit(&pool, &mls, &accepted, &recipient, &id, 1)).await;
    let rejected_record = mls_complete_retry_record(
        &rejected,
        uuid::Uuid::now_v7(),
        arkret_wire::AuthoritySubmitResponseBody::Rejected {
            status: arkret_wire::AuthorityRejectionStatus::Rejected,
            reason_code: "governance_binding_mismatch".into(),
        },
    );
    assert_zero_write_refusal(&pool, &rejected, ConflictCode::GovernanceBindingMismatch).await;
    let authority = PgAuthorityCommitStore { pool: pool.clone() }
        .current_authority(&accepted.authority_commit.event.realm_id)
        .await
        .unwrap()
        .unwrap();
    PgAuthorityCommitStore { pool: pool.clone() }
        .finalize_mls_rejection(
            &rejected.authority_commit.event,
            &authority,
            "governance_binding_mismatch",
            None,
            Some(&rejected_record),
        )
        .await
        .unwrap();
    let keys = coland_storage_postgres::PgIdempotencyStore { pool: pool.clone() };
    // This is deliberately an unbound cache-control row, not an accepted unit.
    let mut cache = original.clone();
    cache.idempotency_key = uuid::Uuid::now_v7().to_string();
    keys.record(&cache).await.unwrap();
    assert!(mls_result_source_pk(&pool, &cache).await.is_none());
    assert!(
        keys.prune_expired(original.expires_at + chrono::Duration::seconds(1))
            .await
            .unwrap()
            >= 1
    );
    assert!(
        keys.get(
            &cache.authenticated_actor,
            &cache.operation_id,
            &cache.idempotency_key
        )
        .await
        .unwrap()
        .is_none()
    );
    assert_original_mls_retry(&pool, &original).await;
    assert_original_mls_retry(&pool, &rejected_record).await;
    let replay = PgAuthorityCommitStore { pool: pool.clone() }
        .finalize_mls_rejection(
            &accepted.authority_commit.event,
            &authority,
            "late_failure",
            None,
            Some(&original),
        )
        .await
        .unwrap();
    assert!(matches!(
        replay,
        arkret_wire::AuthoritySubmitResponseBody::Accepted {
            status: arkret_wire::AuthorityCommitStatus::Committed,
            ..
        }
    ));
    // Exercise the real FK retention dependency on a no-Commit refusal source.
    // This is not a claim that Account erasure or shared-Event policy was run.
    let mut conn = pool.get().await.unwrap();
    assert_eq!(
        diesel::sql_query("DELETE FROM canonical_events WHERE id=$1 AND state='rejected'")
            .bind::<Binary, _>(
                coland_storage::ids::parse_event_id(
                    rejected.authority_commit.event.event_id.as_str()
                )
                .unwrap()
                .to_vec()
            )
            .execute(&mut *conn)
            .await
            .unwrap(),
        1
    );
    drop(conn);
    assert!(
        keys.get(
            &rejected_record.authenticated_actor,
            &rejected_record.operation_id,
            &rejected_record.idempotency_key
        )
        .await
        .unwrap()
        .is_none()
    );
    assert_original_mls_retry(&pool, &original).await;
}

#[tokio::test]
async fn mls_native_private_import_preserves_exact_source_results_with_remapped_local_keys() {
    use coland_storage::IdempotencyStore;
    let source = Box::pin(TestDatabase::lease()).await;
    let target = Box::pin(TestDatabase::lease()).await;
    assert_ne!(source.url(), target.url());
    let incoming: arkret_wire::DidCoreId =
        "ak:did_core:web:mls-import-target.example".parse().unwrap();
    target.bind_device_inventory_station(incoming.as_str());
    let pool = source.pool();
    let (genesis, recipient, mls) =
        Box::pin(mls_retry_base(&pool, "mls-native-retry-import")).await;
    let id = claim_id();
    let mut accepted =
        Box::new(Box::pin(mls_retry_commit(&pool, &mls, &genesis, &recipient, &id, 0)).await);
    let original = mls_committed_retry_record(&accepted, uuid::Uuid::now_v7());
    accepted.idempotency = Some(original.clone());
    PgEventCommitUnitOfWork::new(pool.clone())
        .commit_event((*accepted).clone())
        .await
        .unwrap();
    let id = claim_id();
    let rejected =
        Box::new(Box::pin(mls_retry_commit(&pool, &mls, &accepted, &recipient, &id, 1)).await);
    let refused = mls_complete_retry_record(
        &rejected,
        uuid::Uuid::now_v7(),
        arkret_wire::AuthoritySubmitResponseBody::Rejected {
            status: arkret_wire::AuthorityRejectionStatus::Rejected,
            reason_code: "governance_binding_mismatch".into(),
        },
    );
    assert_zero_write_refusal(&pool, &rejected, ConflictCode::GovernanceBindingMismatch).await;
    let old = PgAuthorityCommitStore { pool: pool.clone() };
    let authority = old
        .current_authority(&accepted.authority_commit.event.realm_id)
        .await
        .unwrap()
        .unwrap();
    old.finalize_mls_rejection(
        &rejected.authority_commit.event,
        &authority,
        "governance_binding_mismatch",
        None,
        Some(&refused),
    )
    .await
    .unwrap();
    let source_refused_pk = mls_original_pk(&pool, &rejected.authority_commit.event).await;
    let station = &genesis.authority_commit.expected_authority.service_id;
    let other = Box::pin(ordinary_realm::open_discussion_for_station(
        &pool,
        "mls-other-result-realm",
        station,
        &historical_roster_attestor_resolution()
            .normalized_did_document
            .id,
    ))
    .await;
    join(&pool, &other.head, &recipient_actor(&recipient)).await;
    let other_genesis = Box::new(
        mls.with_installation(
            ordinary_realm::next_request(
                &other.head.authority_commit,
                arkret_wire::EventKind::MlsGenesis,
                other
                    .head
                    .authority_commit
                    .event
                    .actor_id
                    .signing_principal_id(),
                mls.genesis_payload(&other.realm_id(), other.committed_at()),
                other.committed_at(),
            ),
            None,
            0,
        ),
    );
    PgEventCommitUnitOfWork::new(pool.clone())
        .commit_event((*other_genesis).clone())
        .await
        .unwrap();
    let id = claim_id();
    let mut other_mls = Box::new(
        Box::pin(mls_retry_commit(
            &pool,
            &mls,
            &other_genesis,
            &recipient,
            &id,
            0,
        ))
        .await,
    );
    let other_record = mls_committed_retry_record(&other_mls, uuid::Uuid::now_v7());
    other_mls.idempotency = Some(other_record.clone());
    PgEventCommitUnitOfWork::new(pool.clone())
        .commit_event((*other_mls).clone())
        .await
        .unwrap();
    assert_eq!(
        other_record.authenticated_actor,
        original.authenticated_actor
    );
    assert_ne!(
        other_mls.authority_commit.event.realm_id,
        accepted.authority_commit.event.realm_id
    );
    let change = ordinary_realm::next_request(
        &accepted.authority_commit,
        arkret_wire::EventKind::RealmGovernanceStationChange,
        accepted
            .authority_commit
            .event
            .actor_id
            .signing_principal_id(),
        serde_json::json!({"expected_governance_generation":"0",
            "expected_realm_stream_commit_id":accepted.authority_commit.commit.commit_id,
            "new_governance_station_id":incoming}),
        accepted.authority_commit.commit.committed_at + chrono::Duration::seconds(1),
    );
    PgEventCommitUnitOfWork::new(pool.clone())
        .commit_event(change)
        .await
        .unwrap();
    let realm = accepted.authority_commit.event.realm_id.clone();
    let keys = coland_storage_postgres::PgIdempotencyStore { pool: pool.clone() };
    let mut unrelated_cache = original.clone();
    unrelated_cache.idempotency_key = uuid::Uuid::now_v7().to_string();
    keys.record(&unrelated_cache).await.unwrap();
    let (manifest, bytes) = old.export_management_private_state(&realm).await.unwrap();
    let archive: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let rows = archive["tables"]["idempotency_keys"].as_array().unwrap();
    assert_eq!(rows.len(), 2, "export only the source-bound Realm results");
    assert!(
        rows.iter()
            .all(|row| row["source_event_pk"].as_str().is_some())
    );
    assert!(
        rows.iter().any(|row| row["source_event_pk"]
            == serde_json::json!(accepted.authority_commit.event.event_id))
    );
    assert!(
        rows.iter().any(|row| row["source_event_pk"]
            == serde_json::json!(rejected.authority_commit.event.event_id))
    );
    assert_eq!(
        archive["tables"]["canonical_events"]
            .as_array()
            .unwrap()
            .len(),
        1,
        "the no-Commit refusal source is a private dependency, not a fabricated Commit"
    );
    Box::pin(frozen_database::copy_frozen_archive_preserving_deployment(
        source.url(),
        target.url(),
        &target.pool(),
    ))
    .await;
    let target_pool = target.pool();
    let mut conn = target_pool.get().await.unwrap();
    diesel::sql_query("DELETE FROM idempotency_keys")
        .execute(&mut *conn)
        .await
        .unwrap();
    diesel::sql_query("DELETE FROM canonical_events WHERE id=$1 AND state='rejected'")
        .bind::<Binary, _>(
            coland_storage::ids::parse_event_id(rejected.authority_commit.event.event_id.as_str())
                .unwrap()
                .to_vec(),
        )
        .execute(&mut *conn)
        .await
        .unwrap();
    #[derive(diesel::QueryableByName)]
    struct Sequence {
        #[diesel(sql_type = BigInt)]
        value: i64,
    }
    let _ = diesel::sql_query("SELECT setval(pg_get_serial_sequence('public.canonical_events','pk'),(SELECT max(pk)+1000 FROM canonical_events),true) AS value")
        .get_result::<Sequence>(&mut *conn).await.unwrap().value;
    drop(conn);
    let incoming_store = PgAuthorityCommitStore {
        pool: target_pool.clone(),
    };
    // Mutated private bytes receive a matching test manifest hash so these
    // negatives reach source validation, rather than only a transport digest gate.
    // No altered manifest is ever presented as a valid dual-signed handoff.
    for fault in [
        "missing_source",
        "wrong_source",
        "wrong_actor",
        "wrong_outcome",
    ] {
        let before = mls_complete_retry_footprint(&target_pool).await;
        let mut changed = archive.clone();
        let index = changed["tables"]["idempotency_keys"]
            .as_array()
            .unwrap()
            .iter()
            .position(|row| row["idempotency_key"] == serde_json::json!(refused.idempotency_key))
            .unwrap();
        match fault {
            "missing_source" => changed["tables"]["canonical_events"] = serde_json::json!([]),
            "wrong_source" => {
                changed["tables"]["idempotency_keys"][index]["source_event_pk"] =
                    serde_json::json!(other_mls.authority_commit.event.event_id)
            }
            "wrong_actor" => {
                changed["tables"]["idempotency_keys"][index]["authenticated_actor"] =
                    serde_json::json!(recipient_actor(&recipient));
                changed["tables"]["idempotency_keys"][index]["actor_key"] =
                    serde_json::json!(recipient_actor(&recipient).canonical_key().unwrap());
            }
            _ => {
                changed["tables"]["idempotency_keys"][index]["response_body"]["reason_code"] =
                    serde_json::json!("different_refusal")
            }
        }
        let changed = arkret_canonical::canonical_json_bytes(&changed).unwrap();
        let mut changed_manifest = manifest.clone();
        changed_manifest.state_digest =
            arkret_wire::Hash::new(arkret_canonical::sha256_digest(&changed)).unwrap();
        assert!(
            incoming_store
                .import_management_private_state(&changed_manifest, &changed)
                .await
                .is_err(),
            "{fault}"
        );
        assert_eq!(
            mls_complete_retry_footprint(&target_pool).await,
            before,
            "{fault}"
        );
    }
    let target_keys = coland_storage_postgres::PgIdempotencyStore {
        pool: target_pool.clone(),
    };
    let mut conflicting_cache = original.clone();
    conflicting_cache.request_hash = arkret_canonical::sha256_digest(b"another complete request");
    target_keys.record(&conflicting_cache).await.unwrap();
    let before = mls_complete_retry_footprint(&target_pool).await;
    assert!(
        incoming_store
            .import_management_private_state(&manifest, &bytes)
            .await
            .is_err()
    );
    assert_eq!(mls_complete_retry_footprint(&target_pool).await, before);
    let mut conn = target_pool.get().await.unwrap();
    diesel::sql_query("DELETE FROM idempotency_keys WHERE actor_key=$1 AND operation_id=$2 AND idempotency_key=$3")
        .bind::<Text,_>(original.authenticated_actor.canonical_key().unwrap())
        .bind::<Text,_>(&original.operation_id).bind::<Text,_>(&original.idempotency_key)
        .execute(&mut *conn).await.unwrap();
    drop(conn);
    let mut mirror = original.clone();
    mirror.created_at += chrono::Duration::seconds(1);
    mirror.expires_at += chrono::Duration::days(1);
    target_keys.record(&mirror).await.unwrap();
    assert!(mls_result_source_pk(&target_pool, &mirror).await.is_none());
    incoming_store
        .import_management_private_state(&manifest, &bytes)
        .await
        .unwrap();
    assert_original_mls_retry(&target_pool, &original).await;
    assert_original_mls_retry(&target_pool, &refused).await;
    let target_refused_pk = mls_original_pk(&target_pool, &rejected.authority_commit.event).await;
    assert_ne!(
        target_refused_pk, source_refused_pk,
        "local surrogate keys are actually different"
    );
    assert_eq!(
        mls_result_source_pk(&target_pool, &refused).await,
        Some(target_refused_pk)
    );
    assert_eq!(
        mls_result_source_pk(&target_pool, &original).await,
        Some(mls_original_pk(&target_pool, &accepted.authority_commit.event).await)
    );
    let (_, reexported) = incoming_store
        .export_management_private_state(&realm)
        .await
        .unwrap();
    assert_eq!(
        reexported, bytes,
        "normalize every local FK to its immutable original EventId"
    );
    assert!(
        target_keys
            .get(
                &unrelated_cache.authenticated_actor,
                &unrelated_cache.operation_id,
                &unrelated_cache.idempotency_key
            )
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        target_keys
            .get(
                &other_record.authenticated_actor,
                &other_record.operation_id,
                &other_record.idempotency_key
            )
            .await
            .unwrap()
            .is_none(),
        "do not export all results for the same actor"
    );
    let before = mls_complete_retry_footprint(&target_pool).await;
    incoming_store
        .import_management_private_state(&manifest, &bytes)
        .await
        .unwrap();
    assert_eq!(mls_complete_retry_footprint(&target_pool).await, before);
    for (event, record) in [
        (&accepted.authority_commit.event, &original),
        (&rejected.authority_commit.event, &refused),
    ] {
        let result = incoming_store
            .finalize_mls_rejection(event, &authority, "late_reason", None, Some(record))
            .await
            .unwrap();
        let body = serde_json::to_value(
            arkret_models_collaboration::authority_commit::SelfAuthoritySubmitResponseBody::Ordinary(result)).unwrap();
        assert_eq!(
            arkret_canonical::canonical_json_bytes(&body).unwrap(),
            arkret_canonical::canonical_json_bytes(&record.response_body).unwrap()
        );
        let mut alias = record.clone();
        alias.idempotency_key = uuid::Uuid::now_v7().to_string();
        assert_eq!(
            incoming_store
                .finalize_mls_rejection(event, &authority, "late_reason", None, Some(&alias))
                .await
                .unwrap_err()
                .conflict_code(),
            Some(ConflictCode::DuplicateConflict)
        );
    }
    assert_eq!(mls_complete_retry_footprint(&target_pool).await, before);
}
