//! Real PostgreSQL: `ak.mls.genesis` and `ak.mls.commit` install the
//! `mls_group` typed current, the public MLS state and every Welcome in the
//! transaction that commits their Event and RealmCommit, and every refusal
//! leaves zero writes (encryption-and-audit.md §2.2, §2.4.1, §5.1;
//! client-sync.md §10.1).

#[path = "../../test-support/src/device_authorization_history.rs"]
#[allow(dead_code)]
mod device_authorization_history;
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

use arkret_models_crypto::{MlsCommitEnvelope, MlsCommitPayload, MlsGovernanceBindingPayload};
use coland_storage::{
    AuthorityCommitStore, ConflictCode, DeviceMessageStore, DeviceRevocationGateSelector,
    EventCommitRequest, EventCommitUnitOfWork, IdentityStoreRegistry,
    MlsConsumedProposalInstallation, MlsGroupCurrentStore, MlsInstalledBase, MlsKeyPackageStore,
    MlsProposalLeafProvenance, MlsStateInstallation, MlsWelcomeClaimLedgerKey,
    RecipientQueueSelector, VerifiedMlsWelcome,
};
use coland_storage_postgres::test_database::TestDatabase;
use coland_storage_postgres::{
    PgAuthorityCommitStore, PgDeviceMessageStore, PgEventCommitUnitOfWork, PgMlsGroupCurrentStore,
    PgPool,
};
use diesel::sql_types::{BigInt, Binary, Jsonb, Text, Timestamptz};
use diesel_async::RunQueryDsl;

fn realm_scope(realm_id: &arkret_wire::RealmId) -> arkret_wire::ScopeRef {
    arkret_wire::ScopeRef::Realm {
        realm_id: realm_id.clone(),
    }
}

fn blob(seed: char) -> String {
    format!("ak:blob:sha256:{}", seed.to_string().repeat(64))
}

fn genesis_payload(
    realm_id: &arkret_wire::RealmId,
    at: chrono::DateTime<chrono::Utc>,
) -> serde_json::Value {
    serde_json::json!({
        "cipher_suite": "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
        "group_info_ref": blob('3'),
        "ratchet_tree_ref": blob('4'),
        "creator_leaf_authority": {
            "leaf_signature_key_base64url": arkret_canonical::base64url_encode([7_u8; 32]),
            "endpoint": {"kind": "device", "device_id": format!("ak:device:{}", uuid::Uuid::now_v7())},
            "authorization_event_ref": arkret_wire::EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [8_u8; 32]),
        },
        "governance_binding":
            MlsGovernanceBindingPayload::realm(realm_id.clone(), None, 0, 0, 0).unwrap(),
        "created_at": arkret_canonical::format_timestamp_canonical(at),
    })
}

fn commit_payload(
    realm_id: &arkret_wire::RealmId,
    base: &arkret_wire::EventId,
    previous_epoch: u64,
    revision: u64,
    commit_bytes: &[u8],
) -> serde_json::Value {
    let binding = MlsGovernanceBindingPayload::realm(
        realm_id.clone(),
        Some(base.clone()),
        previous_epoch,
        previous_epoch + 1,
        revision,
    )
    .unwrap();
    let envelope = MlsCommitEnvelope {
        group_id: binding.mls_group_id().unwrap(),
        epoch: previous_epoch + 1,
        commit: arkret_wire::base64url::base64url_encode(commit_bytes),
        commit_digest: arkret_wire::Hash::new(arkret_canonical::sha256_digest(commit_bytes))
            .unwrap(),
        ratchet_tree: None,
    };
    serde_json::to_value(MlsCommitPayload::new(base.clone(), revision, &envelope, binding).unwrap())
        .unwrap()
}

fn with_installation(
    mut request: EventCommitRequest,
    base: Option<(&arkret_wire::EventId, u64)>,
    epoch: u64,
) -> EventCommitRequest {
    let scope = request.authority_commit.event.scope_ref.clone();
    // A joined member hosted by another Station receives the Commit Event,
    // never its Welcomes, through committed replication.
    request.realm_fanout_source = Some(arkret_wire::EventAdmissionSubmission::new(
        request.authority_commit.event.clone(),
    ));
    request.authority_commit.mls_state = Some(MlsStateInstallation {
        effective_scope: scope,
        base: base.map(|(reference, epoch)| MlsInstalledBase {
            current_mls_commit_event_ref: reference.clone(),
            epoch,
        }),
        epoch,
        public_state: format!("public-state-{epoch}").into_bytes(),
        member_principals: Default::default(),
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

/// One live claim ledger row as the claim service leaves it after a
/// successful same-Station claim.
async fn live_claim(pool: &PgPool, station: &str, claim_id: &str) -> MlsWelcomeClaimLedgerKey {
    let key = MlsWelcomeClaimLedgerKey {
        source_id: station.to_owned(),
        claim_request_id: uuid::Uuid::now_v7().simple().to_string(),
        request_digest: format!("sha256:{}", "6".repeat(64)),
    };
    let now = chrono::Utc::now();
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
    .bind::<Jsonb, _>(serde_json::json!({"claims": [{"claim_id": claim_id}]}))
    .bind::<BigInt, _>(now.timestamp_millis() + 3_600_000)
    .bind::<BigInt, _>(now.timestamp() + 86_400)
    .bind::<BigInt, _>(now.timestamp())
    .execute(&mut *conn)
    .await
    .unwrap();
    key
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
         VALUES(TRUE,'ak:did_core:web:mls-admission.example') ON CONFLICT(singleton) DO NOTHING",
    )
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

    let mut genesis = with_installation(
        ordinary_realm::next_request(
            &discussion.head.authority_commit,
            arkret_wire::EventKind::MlsGenesis,
            &founder,
            genesis_payload(&realm_id, at),
            at,
        ),
        None,
        0,
    );
    // encryption-and-audit.md §5.1.2: a forwarded Genesis stores the two
    // Blobs it carried with its Commit.
    let carried = |seed: char| coland_storage::MlsPublicBlob {
        blob_ref: arkret_wire::BlobRef::new(blob(seed)).unwrap(),
        sha256: seed.to_string().repeat(64),
        size_bytes: 11,
        storage_backend: "local".to_owned(),
        storage_key: format!("sha256/{}", seed.to_string().repeat(64)),
    };
    genesis
        .authority_commit
        .mls_state
        .as_mut()
        .unwrap()
        .public_blobs = vec![carried('3'), carried('4')];
    uow.commit_event(genesis.clone()).await.unwrap();
    let blobs = coland_storage_postgres::PgBlobStore { pool: pool.clone() };
    for seed in ['3', '4'] {
        let stored = coland_storage::BlobStore::get(&blobs, &blob(seed))
            .await
            .unwrap()
            .expect("the carried Blob is stored with the Genesis Commit");
        assert_eq!(stored.storage_key, carried(seed).storage_key);
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
            public_tree_ref: arkret_wire::BlobRef::new(blob('4')).unwrap(),
        }
    );
    assert_eq!(
        installed.current_commit_id,
        genesis.authority_commit.commit.commit_id
    );
    assert_eq!(installed.public_state, b"public-state-0");

    let second_genesis = with_installation(
        ordinary_realm::next_request(
            &genesis.authority_commit,
            arkret_wire::EventKind::MlsGenesis,
            &founder,
            genesis_payload(&realm_id, at + chrono::TimeDelta::seconds(1)),
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

    let uncovered = with_installation(
        ordinary_realm::next_request(
            &genesis.authority_commit,
            arkret_wire::EventKind::MlsCommit,
            &founder,
            commit_payload(&realm_id, &genesis_ref, 0, 1, b"uncovered"),
            at,
        ),
        Some((&genesis_ref, 0)),
        1,
    );
    assert_zero_write_refusal(&pool, &uncovered, ConflictCode::GovernanceBindingMismatch).await;

    let outsider = Box::pin(ordinary_realm::human_profile::admit(
        &pool,
        &genesis.authority_commit.expected_authority.service_id,
        "mls-outsider",
    ))
    .await
    .principal_id;
    let foreign = with_installation(
        ordinary_realm::next_request(
            &genesis.authority_commit,
            arkret_wire::EventKind::MlsCommit,
            &outsider,
            commit_payload(&realm_id, &genesis_ref, 0, 0, b"foreign"),
            at,
        ),
        Some((&genesis_ref, 0)),
        1,
    );
    let foreign = Box::pin(ordinary_realm::source_request(&pool, foreign)).await;
    assert_zero_write_refusal(&pool, &foreign, ConflictCode::CapabilityDenied).await;

    let commit = with_installation(
        ordinary_realm::next_request(
            &genesis.authority_commit,
            arkret_wire::EventKind::MlsCommit,
            &founder,
            commit_payload(&realm_id, &genesis_ref, 0, 0, b"first"),
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
        .public_blobs[0];
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
    for seed in ['3', '4'] {
        assert!(
            coland_storage::BlobStore::get(&blobs, &blob(seed))
                .await
                .unwrap()
                .is_some(),
            "advancing current must preserve the original Genesis artifacts"
        );
    }
    assert_eq!(
        advanced.current_commit_id,
        commit.authority_commit.commit.commit_id
    );
    assert_eq!(advanced.public_state, b"public-state-1");

    let stale = with_installation(
        ordinary_realm::next_request(
            &commit.authority_commit,
            arkret_wire::EventKind::MlsCommit,
            &founder,
            commit_payload(&realm_id, &genesis_ref, 0, 0, b"stale"),
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
    let genesis = with_installation(
        ordinary_realm::next_request(
            &discussion.head.authority_commit,
            arkret_wire::EventKind::MlsGenesis,
            &founder,
            genesis_payload(&realm_id, at),
            at,
        ),
        None,
        0,
    );
    uow.commit_event(genesis.clone()).await.unwrap();
    let genesis_ref = genesis.authority_commit.event.event_id.clone();
    let leaf = MlsProposalLeafProvenance {
        leaf_index: 1,
        actor_id: genesis.authority_commit.event.actor_id.clone(),
        signature_key: arkret_wire::Base64UrlString::new(arkret_canonical::base64url_encode(
            [7_u8; 32],
        ))
        .unwrap(),
    };
    let proposal = |ordinal, proposal_type, wire, before, after| MlsConsumedProposalInstallation {
        ordinal,
        proposal_ref: vec![wire],
        proposal_type,
        proposal_wire: vec![wire],
        sender_leaf: leaf.clone(),
        target_before: before,
        target_after: after,
    };
    let mut first = with_installation(
        ordinary_realm::next_request(
            &genesis.authority_commit,
            arkret_wire::EventKind::MlsCommit,
            &founder,
            commit_payload(&realm_id, &genesis_ref, 0, 0, b"first-proposal"),
            at,
        ),
        Some((&genesis_ref, 0)),
        1,
    );
    first
        .authority_commit
        .mls_state
        .as_mut()
        .unwrap()
        .consumed_proposals = vec![
        proposal(0, 1, 11, None, Some(leaf.clone())),
        proposal(1, 7, 12, None, None),
    ];
    uow.commit_event(first.clone()).await.unwrap();
    let first_ref = first.authority_commit.event.event_id.clone();

    let mut replacement = with_installation(
        ordinary_realm::next_request(
            &first.authority_commit,
            arkret_wire::EventKind::MlsCommit,
            &founder,
            commit_payload(&realm_id, &first_ref, 1, 0, b"replacement"),
            at,
        ),
        Some((&first_ref, 1)),
        2,
    );
    replacement
        .authority_commit
        .mls_state
        .as_mut()
        .unwrap()
        .consumed_proposals = vec![
        proposal(0, 3, 21, Some(leaf.clone()), None),
        proposal(1, 1, 22, None, Some(leaf.clone())),
    ];
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
    assert_eq!(rows.len(), 4);
    assert_eq!(rows[0].commit_event_ref, first_ref.as_str());
    assert_eq!(rows[1].commit_event_ref, first_ref.as_str());
    assert_eq!(rows[2].commit_event_ref, replacement_ref.as_str());
    assert_eq!(rows[3].commit_event_ref, replacement_ref.as_str());
    assert_eq!(
        rows.iter()
            .map(|row| row.consumed_proposal_ordinal)
            .collect::<Vec<_>>(),
        vec![0, 1, 0, 1]
    );
    assert_eq!(
        rows.iter()
            .map(|row| row.proposal_wire[0])
            .collect::<Vec<_>>(),
        vec![11, 12, 21, 22]
    );
    assert_eq!(
        rows.iter().map(|row| row.proposal_type).collect::<Vec<_>>(),
        vec![1, 7, 3, 1]
    );
    assert!(
        rows.iter()
            .all(|row| row.sender_actor_id == serde_json::to_value(&leaf.actor_id).unwrap())
    );
    assert!(rows[1].target_before_actor_id.is_none());
    assert!(rows[1].target_after_actor_id.is_none());
    assert!(rows[2].target_after_actor_id.is_none());
    assert_eq!(rows[0].target_after_actor_id, rows[3].target_after_actor_id);
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

    let mut stale = with_installation(
        ordinary_realm::next_request(
            &replacement.authority_commit,
            arkret_wire::EventKind::MlsCommit,
            &founder,
            commit_payload(&realm_id, &first_ref, 1, 0, b"stale-provenance"),
            at,
        ),
        Some((&first_ref, 1)),
        2,
    );
    stale
        .authority_commit
        .mls_state
        .as_mut()
        .unwrap()
        .consumed_proposals = vec![proposal(0, 1, 31, None, Some(leaf.clone()))];
    assert_zero_write_refusal(&pool, &stale, ConflictCode::GovernanceBindingMismatch).await;
    assert_eq!(provenance_count(&pool).await, 4);
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
    let genesis = with_installation(
        ordinary_realm::next_request(
            &discussion.head.authority_commit,
            arkret_wire::EventKind::MlsGenesis,
            &founder,
            genesis_payload(&realm_id, at),
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
        Read::Authorized { genesis: Some(_) }
    ));
    assert!(matches!(
        store
            .mls_member_group_state_material_read(&request, &station, Some(&station))
            .await
            .unwrap(),
        Read::Authorized { genesis: Some(_) }
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
    let genesis = with_installation(
        ordinary_realm::next_request(
            unit.transactions.last().unwrap(),
            arkret_wire::EventKind::MlsGenesis,
            &founder,
            genesis_payload(&realm_id, at),
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
    let target = with_installation(
        ordinary_realm::next_request(
            &join.authority_commit,
            arkret_wire::EventKind::MlsCommit,
            &founder,
            commit_payload(&realm_id, &genesis_ref, 0, 1, b"member-target-cut"),
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
        Read::Authorized { genesis: Some(_) }
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
        Read::Authorized { genesis: None }
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
                wrong.effective_scope = arkret_wire::ScopeRef::Circle {
                    realm_id: realm_id.clone(),
                    circle_id: arkret_wire::CircleId::from_event_id(
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
    let genesis = with_installation(
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
            genesis_payload(&realm_id, at),
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
    let target = with_installation(
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
            commit_payload(&realm_id, &event.event_id, 0, 0, b"genesis-selector-target"),
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
        Read::Authorized { genesis: Some(_) }
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
    let genesis = with_installation(
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
            genesis_payload(&realm_id, at),
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
        Read::Authorized { genesis: Some(_) }
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
    let mut source = pcr_genesis::PcrGenesisFixture::new(
        device_authorization_history::did_web_station(&station),
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
        &device_authorization_history::did_web_station(&station),
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
    let genesis = with_installation(
        ordinary_realm::next_request(
            &discussion.head.authority_commit,
            arkret_wire::EventKind::MlsGenesis,
            &founder,
            genesis_payload(&realm_id, at),
            at,
        ),
        None,
        0,
    );
    uow.commit_event(genesis.clone()).await.unwrap();
    let genesis_ref = genesis.authority_commit.event.event_id.clone();

    let first_claim = claim_id();
    let first_key = live_claim(&pool, station.as_str(), &first_claim).await;
    let mut commit = with_installation(
        ordinary_realm::next_request(
            &genesis.authority_commit,
            arkret_wire::EventKind::MlsCommit,
            &founder,
            commit_payload(&realm_id, &genesis_ref, 0, 0, b"add"),
            at,
        ),
        Some((&genesis_ref, 0)),
        1,
    );
    commit.authority_commit.welcomes = vec![VerifiedMlsWelcome {
        delivery: welcome(&commit, &recipient, &first_claim),
        claim: Some(first_key.clone()),
        applet_device_scope_guard: None,
        roster_witness: None,
    }];
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
    let second_key = live_claim(&pool, station.as_str(), &second_claim).await;
    let mut full = with_installation(
        ordinary_realm::next_request(
            &commit.authority_commit,
            arkret_wire::EventKind::MlsCommit,
            &founder,
            commit_payload(&realm_id, &commit_ref, 1, 0, b"full"),
            at,
        ),
        Some((&commit_ref, 1)),
        2,
    );
    full.authority_commit.welcomes = vec![VerifiedMlsWelcome {
        delivery: welcome(&full, &recipient, &second_claim),
        claim: Some(second_key),
        applet_device_scope_guard: None,
        roster_witness: None,
    }];
    full.authority_commit.recipient_queue_capacity = 1;
    assert_zero_write_refusal(&pool, &full, ConflictCode::RecipientQueueAtCapacity).await;

    let mut reused = with_installation(
        ordinary_realm::next_request(
            &commit.authority_commit,
            arkret_wire::EventKind::MlsCommit,
            &founder,
            commit_payload(&realm_id, &commit_ref, 1, 0, b"reused"),
            at,
        ),
        Some((&commit_ref, 1)),
        2,
    );
    reused.authority_commit.welcomes = vec![VerifiedMlsWelcome {
        delivery: welcome(&reused, &recipient, &first_claim),
        claim: Some(first_key),
        applet_device_scope_guard: None,
        roster_witness: None,
    }];
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

    persistence
        .device_revocations()
        .commit_revocation(&coland_storage::DeviceRevocationTransition {
            selector: recipient.clone(),
            revoke_ref: arkret_wire::CommittedEventRef {
                event_id: arkret_wire::EventId::from_digest(
                    arkret_canonical::DigestSuite::Sha256,
                    [0x52; 32],
                ),
                commit_id: arkret_wire::RealmCommitId::from_digest([0x53; 32]),
                stream_ref: recipient.authorization_ref.stream_ref.clone(),
                stream_position: recipient.authorization_ref.stream_position + 10,
            },
            committed_at: chrono::Utc::now(),
        })
        .await
        .unwrap();
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

/// One MLS ciphertext Message body frozen at `epoch` over `group_state_ref`.
fn ciphertext_message(
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

/// A Message by the account of `device`, signed by that device and guarded
/// by its exact revocation-gate selector as the self submit preflight pins it.
fn device_message(
    previous: &coland_storage::AuthorityCommitTransaction,
    device: &DeviceRevocationGateSelector,
    payload: serde_json::Value,
    did: &arkret_wire::Did,
    signing_seed: [u8; 32],
) -> EventCommitRequest {
    let event = ordinary_realm::event_for_actor(
        arkret_wire::EventKind::MessageCreate,
        previous.event.scope_ref.clone(),
        recipient_actor(device),
        payload,
        previous.commit.committed_at,
    );
    let signed = device_authorization_history::sign_event(
        event,
        arkret_wire::DidUrl::new(format!("{did}#{}", device.device_id)).unwrap(),
        signing_seed,
    );
    let mut request =
        ordinary_realm::request_for_event(previous, signed, previous.commit.committed_at);
    request.self_producer_guard = Some(coland_storage::SelfProducerCommitGuard::HumanDevice(
        device.clone(),
    ));
    request.realm_fanout_source = Some(arkret_wire::EventAdmissionSubmission::new(
        request.authority_commit.event.clone(),
    ));
    request
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
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let station = governing_station(&pool).await;
    let persistence = coland_storage_postgres::PgPersistenceStore::new(pool.clone());
    let mut source = pcr_genesis::PcrGenesisFixture::new(
        device_authorization_history::did_web_station(&station),
    );
    let revoked = Box::pin(source.admit_founding_device(&persistence))
        .await
        .expect("accepted founding device");
    let active = Box::pin(source.admit_accepted_device(&persistence, [43; 32]))
        .await
        .expect("accepted second device")
        .authorization;

    let discussion =
        Box::new(Box::pin(ordinary_realm::open_discussion(&pool, "mls-send-gate")).await);
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
    let genesis = Box::new(with_installation(
        ordinary_realm::next_request(
            &grant.authority_commit,
            arkret_wire::EventKind::MlsGenesis,
            &founder,
            genesis_payload(&realm_id, at),
            at,
        ),
        None,
        0,
    ));
    Box::pin(uow.commit_event((*genesis).clone()))
        .await
        .unwrap();
    let genesis_ref = genesis.authority_commit.event.event_id.clone();
    let commit = Box::new(with_installation(
        ordinary_realm::next_request(
            &genesis.authority_commit,
            arkret_wire::EventKind::MlsCommit,
            &founder,
            commit_payload(&realm_id, &genesis_ref, 0, 0, b"epoch-one"),
            at,
        ),
        Some((&genesis_ref, 0)),
        1,
    ));
    Box::pin(uow.commit_event((*commit).clone())).await.unwrap();
    let commit_ref = commit.authority_commit.event.event_id.clone();
    let before = groups.current(&scope).await.unwrap().unwrap();
    assert_eq!(before.value.epoch, 1);

    let strand = &discussion.strand_id;
    let mut revoked_messages = Vec::new();
    for payload in [
        ciphertext_message(strand, 0, &genesis_ref),
        ciphertext_message(strand, 1, &commit_ref),
    ] {
        let request = device_message(
            &commit.authority_commit,
            &revoked,
            payload,
            &source.history.did,
            source.history.founding_device_signing_seed,
        );
        revoked_messages.push(Box::new(
            Box::pin(ordinary_realm::source_request(&pool, request)).await,
        ));
    }
    persistence
        .device_revocations()
        .commit_revocation(&coland_storage::DeviceRevocationTransition {
            selector: revoked.clone(),
            revoke_ref: arkret_wire::CommittedEventRef {
                event_id: arkret_wire::EventId::from_digest(
                    arkret_canonical::DigestSuite::Sha256,
                    [0x54; 32],
                ),
                commit_id: arkret_wire::RealmCommitId::from_digest([0x55; 32]),
                stream_ref: revoked.authorization_ref.stream_ref.clone(),
                stream_position: revoked.authorization_ref.stream_position + 10,
            },
            committed_at: chrono::Utc::now(),
        })
        .await
        .unwrap();
    for request in revoked_messages {
        Box::pin(assert_zero_write_refusal(
            &pool,
            &request,
            ConflictCode::DeviceRevoked,
        ))
        .await;
    }
    assert_eq!(groups.current(&scope).await.unwrap().unwrap(), before);

    let plaintext = ordinary_realm::next_request(
        &commit.authority_commit,
        arkret_wire::EventKind::MessageCreate,
        &founder,
        ordinary_realm::message_payload(strand, "plaintext after activation"),
        at,
    );
    Box::pin(assert_zero_write_refusal(
        &pool,
        &plaintext,
        ConflictCode::MlsActivationRequired,
    ))
    .await;
    let stale = ordinary_realm::next_request(
        &commit.authority_commit,
        arkret_wire::EventKind::MessageCreate,
        &founder,
        ciphertext_message(strand, 0, &genesis_ref),
        at,
    );
    Box::pin(assert_zero_write_refusal(
        &pool,
        &stale,
        ConflictCode::EpochMismatch,
    ))
    .await;

    let sibling = device_message(
        &commit.authority_commit,
        &active,
        ciphertext_message(strand, 1, &commit_ref),
        &source.history.did,
        [43; 32],
    );
    let sibling = Box::pin(ordinary_realm::source_request(&pool, sibling)).await;
    Box::pin(uow.commit_event(sibling.clone())).await.unwrap();
    let member = ordinary_realm::next_request(
        &sibling.authority_commit,
        arkret_wire::EventKind::MessageCreate,
        &founder,
        ciphertext_message(strand, 1, &commit_ref),
        at,
    );
    let member = Box::pin(ordinary_realm::source_request(&pool, member)).await;
    Box::pin(uow.commit_event(member)).await.unwrap();
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
    let authorization_event_ref =
        arkret_wire::EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [71_u8; 32]);
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
    let claim_request: PeerKeyPackagesClaimFields = serde_json::from_value(serde_json::json!({
        "claim_request_id": uuid::Uuid::now_v7().simple().to_string(),
        "intended_realm_id": delivery.realm_id,
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
        request_digest: arkret_wire::Hash::new(format!("sha256:{}", "6".repeat(64))).unwrap(),
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
    let outcome = KeyPackagesClaimResponseBody {
        claim_request_id: receipt.claim_request_id.clone(),
        claims: vec![record],
        claim_receipt: receipt.clone(),
    };
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
        epoch: 1,
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
    let recipient = pcr_genesis::PcrGenesisFixture::new(station_did.clone())
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
    let genesis = with_installation(
        ordinary_realm::next_request(
            &discussion.head.authority_commit,
            arkret_wire::EventKind::MlsGenesis,
            &founder,
            genesis_payload(&realm_id, at),
            at,
        ),
        None,
        0,
    );
    uow.commit_event(genesis.clone()).await.unwrap();
    let genesis_ref = genesis.authority_commit.event.event_id.clone();
    let mut commit = with_installation(
        ordinary_realm::next_request(
            &genesis.authority_commit,
            arkret_wire::EventKind::MlsCommit,
            &founder,
            commit_payload(&realm_id, &genesis_ref, 0, 0, b"local signed add"),
            at,
        ),
        Some((&genesis_ref, 0)),
        1,
    );
    let claim_id = claim_id();
    let delivery = welcome(&commit, &recipient, &claim_id);
    let actor = recipient_actor(&recipient);
    let device_id = match &delivery.recipient_endpoint {
        arkret_wire::MlsWelcomeRecipientEndpoint::Device { device_id } => device_id.clone(),
        _ => unreachable!(),
    };
    let founder_device =
        arkret_wire::DeviceId::new(format!("ak:device:{}", uuid::Uuid::now_v7())).unwrap();
    let founder_actor = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        founder.clone(),
        station.clone(),
    ));
    let mut group =
        arkret_mls::ArkretMlsIdentity::new_test_human_device(founder_actor, founder_device)
            .unwrap()
            .create_group_with_governance_binding(
                &realm_scope(&realm_id),
                &MlsGovernanceBindingPayload::realm(realm_id.clone(), None, 0, 0, 0).unwrap(),
            )
            .unwrap();
    let (group_info, tree) = group.public_group_state_bytes().unwrap();
    let mut tracker = arkret_mls::MlsPublicGroupTracker::from_external(
        &group_info,
        &tree,
        group.group_id().as_str(),
        0,
    )
    .unwrap();
    let member_identity =
        arkret_mls::ArkretMlsIdentity::new_test_human_device(actor.clone(), device_id).unwrap();
    let mut package = member_identity.key_package_record().unwrap();
    package.state = arkret_models_crypto::MlsKeyPackageState::Claimed;
    package.claim_id = Some(claim_id.clone());
    let added = group
        .add_member_with_governance_binding(
            &package,
            &MlsGovernanceBindingPayload::realm(
                realm_id.clone(),
                Some(genesis_ref.clone()),
                0,
                1,
                0,
            )
            .unwrap(),
        )
        .unwrap();
    let arkret_mls::MlsPublicHandshakeTransition::Commit {
        consumed_proposals, ..
    } = tracker
        .process_public_handshake(
            &arkret_canonical::base64url_decode(&added.commit.commit).unwrap(),
        )
        .unwrap()
    else {
        panic!("a real Add must produce a Commit")
    };
    let leaf = |leaf: arkret_mls::MlsPublicEndpointLeaf| MlsProposalLeafProvenance {
        leaf_index: leaf.leaf_index,
        actor_id: leaf.actor_id,
        signature_key: leaf.signature_key,
    };
    commit
        .authority_commit
        .mls_state
        .as_mut()
        .unwrap()
        .consumed_proposals = consumed_proposals
        .into_iter()
        .map(|proposal| MlsConsumedProposalInstallation {
            ordinal: proposal.ordinal,
            proposal_ref: proposal.proposal_ref,
            proposal_type: proposal.proposal_type,
            proposal_wire: proposal.proposal_wire,
            sender_leaf: leaf(proposal.sender_leaf),
            target_before: proposal.target_before.map(leaf),
            target_after: proposal.target_after.map(leaf),
        })
        .collect();
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
    let proof = signed_remote_add_attestation(
        &commit,
        &genesis_ref,
        &local,
        &package,
        &station,
        parsed.leaf_signature_key,
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

/// encryption-and-audit.md §2.2 "跨站 recipient": the governance Station
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
    let genesis = with_installation(
        ordinary_realm::next_request(
            &discussion.head.authority_commit,
            arkret_wire::EventKind::MlsGenesis,
            &founder,
            genesis_payload(&realm_id, at),
            at,
        ),
        None,
        0,
    );
    uow.commit_event(genesis.clone()).await.unwrap();
    let genesis_ref = genesis.authority_commit.event.event_id.clone();

    let add = |bytes: &[u8]| {
        with_installation(
            ordinary_realm::next_request(
                &genesis.authority_commit,
                arkret_wire::EventKind::MlsCommit,
                &founder,
                commit_payload(&realm_id, &genesis_ref, 0, 0, bytes),
                at,
            ),
            Some((&genesis_ref, 0)),
            1,
        )
    };
    let mut stranger = add(b"stranger");
    stranger.authority_commit.welcomes = vec![remote_welcome(
        &stranger,
        &member("mls-remote-stranger", remote_station),
    )];
    stranger.authority_commit.recipient_queue_capacity = 4;
    assert_zero_write_refusal(&pool, &stranger, ConflictCode::FailedPrecondition).await;
    assert!(replication_payloads(&pool, &stranger).await.is_empty());
    assert!(frozen_remote_welcomes(&pool, &stranger).await.is_empty());

    let mut commit = add(b"cross-station add");
    let mut welcomes = vec![
        remote_welcome(&commit, &first),
        remote_welcome(&commit, &second),
    ];
    welcomes.sort_by(|left, right| left.delivery.welcome_id.cmp(&right.delivery.welcome_id));
    // Feed storage the exact Add and GCE consumed by a real RFC 9420 Commit.
    // The ingress below reparses the frozen Add; arbitrary fixture bytes must
    // never be enough to install a historical recipient authority proof.
    let founder_device =
        arkret_wire::DeviceId::new(format!("ak:device:{}", uuid::Uuid::now_v7())).unwrap();
    let member_device = welcomes
        .iter()
        .find(|welcome| welcome.delivery.recipient_actor_id == first)
        .and_then(|welcome| match &welcome.delivery.recipient_endpoint {
            arkret_wire::MlsWelcomeRecipientEndpoint::Device { device_id } => {
                Some(device_id.clone())
            }
            _ => None,
        })
        .unwrap();
    let founder_actor = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        founder.clone(),
        station.clone(),
    ));
    let mut group =
        arkret_mls::ArkretMlsIdentity::new_test_human_device(founder_actor, founder_device)
            .unwrap()
            .create_group_with_governance_binding(
                &realm_scope(&realm_id),
                &MlsGovernanceBindingPayload::realm(realm_id.clone(), None, 0, 0, 0).unwrap(),
            )
            .unwrap();
    let (group_info, tree) = group.public_group_state_bytes().unwrap();
    let mut tracker = arkret_mls::MlsPublicGroupTracker::from_external(
        &group_info,
        &tree,
        group.group_id().as_str(),
        0,
    )
    .unwrap();
    let member_identity =
        arkret_mls::ArkretMlsIdentity::new_test_human_device(first.clone(), member_device).unwrap();
    let mut member_keypackage = member_identity.key_package_record().unwrap();
    member_keypackage.state = arkret_models_crypto::MlsKeyPackageState::Claimed;
    member_keypackage.claim_id = Some(
        welcomes
            .iter()
            .find(|welcome| welcome.delivery.recipient_actor_id == first)
            .unwrap()
            .delivery
            .keypackage_claim_ref
            .to_string(),
    );
    let add_result = group
        .add_member_with_governance_binding(
            &member_keypackage,
            &MlsGovernanceBindingPayload::realm(
                realm_id.clone(),
                Some(genesis_ref.clone()),
                0,
                1,
                0,
            )
            .unwrap(),
        )
        .unwrap();
    let transition = tracker
        .process_public_handshake(
            &arkret_canonical::base64url::base64url_decode(add_result.commit.commit.as_bytes())
                .unwrap(),
        )
        .unwrap();
    let arkret_mls::MlsPublicHandshakeTransition::Commit {
        consumed_proposals, ..
    } = transition
    else {
        panic!("the real Add transition must be a Commit")
    };
    let leaf = |leaf: arkret_mls::MlsPublicEndpointLeaf| MlsProposalLeafProvenance {
        leaf_index: leaf.leaf_index,
        actor_id: leaf.actor_id,
        signature_key: leaf.signature_key,
    };
    commit
        .authority_commit
        .mls_state
        .as_mut()
        .unwrap()
        .consumed_proposals = consumed_proposals
        .into_iter()
        .map(|proposal| MlsConsumedProposalInstallation {
            ordinal: proposal.ordinal,
            proposal_ref: proposal.proposal_ref,
            proposal_type: proposal.proposal_type,
            proposal_wire: proposal.proposal_wire,
            sender_leaf: leaf(proposal.sender_leaf),
            target_before: proposal.target_before.map(leaf),
            target_after: proposal.target_after.map(leaf),
        })
        .collect();
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
        .find(|proposal| proposal.proposal_type == 1)
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
    let roster = governance
        .mls_roster_authority_read(&roster_request, &station, None)
        .await
        .unwrap();
    let coland_storage::MlsRosterAuthorityRead::Authorized { facts: Some(facts) } = roster else {
        panic!("complete installed Add history is authorized for the founder")
    };
    assert_eq!(facts.records.len(), 2);
    assert_eq!(facts.historical_add_proofs.len(), 1);
    assert_eq!(
        arkret_canonical::canonical_json_bytes(&facts.historical_add_proofs[0]).unwrap(),
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
    assert!(matches!(
        &facts.records[1],
        arkret_models_collaboration::mls_roster_authority::MlsRosterRecord::Add { commit_event_ref, consumed_proposal_ordinal, attestor_resolution, .. }
            if commit_event_ref == &commit.authority_commit.event.event_id
                && *consumed_proposal_ordinal == 0
                && arkret_canonical::canonical_json_bytes(attestor_resolution).unwrap() == original_resolution
    ));
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
    assert_eq!(installed_add_attestation_count(&pool).await, 1);
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
    let later = with_installation(
        ordinary_realm::next_request(
            &commit.authority_commit,
            arkret_wire::EventKind::MlsCommit,
            &founder,
            commit_payload(&realm_id, &commit_ref, 1, 0, b"later epoch"),
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
