#[path = "support/applet_authoring.rs"]
mod applet_authoring;
#[path = "../../test-support/src/device_authorization_history.rs"]
#[allow(dead_code)]
mod device_authorization_history;
#[path = "support/franking.rs"]
mod franking;
#[path = "support/ordinary_realm.rs"]
#[expect(
    dead_code,
    reason = "This integration binary uses only its subset of the shared Realm fixture."
)]
mod ordinary_realm;
#[path = "../../test-support/src/pcr_genesis.rs"]
#[allow(dead_code)]
mod pcr_genesis;

use coland_storage::contract_tests::{
    AppletFormalCommitContractStores, EventCommitContractMessages, EventCommitContractStores,
    assert_account_localpart_remove_contract, assert_applet_formal_commit_transaction_contract,
    assert_atomic_event_admission_contract, assert_device_message_snapshot_guard_contract,
    assert_event_commit_unit_of_work_contract, assert_federation_outbox_store_contract,
    assert_idempotency_store_contract, assert_invite_new_source_ledger_contract,
    assert_last_resort_claim_ledger_contract, assert_mimi_consent_correlation_store_contract,
    assert_mls_keypackage_retirement_contract, assert_organization_registration_store_contract,
};
use coland_storage::{
    AccountDataCasResult, AccountDataRecord, AccountDataStore, AccountNotificationDeltaWrite,
    AgentPrincipalRecord, AgentStore, AppletAuthoringPreviewRecord, AppletStore,
    AuthorityCommitStore, AuthorityCommitTransaction, CurrentRealmAuthority, MlsKeyPackageStore,
    NotificationStore, PeerKeyPackageClaimLedgerRecord, PeerKeyPackageClaimLedgerWriteResult,
    RelationCurrentResultStore, SyncCursorStore,
};
use coland_storage_postgres::{
    PgAccountDataStore, PgAccountLocalpartStore, PgAccountStore, PgAgentStore, PgAppletStore,
    PgAuthorityCommitStore, PgContactStore, PgDeviceInventoryStore, PgDeviceMessageStore,
    PgEventCommitUnitOfWork, PgEventStore, PgFederationOutboxStore, PgIdempotencyStore,
    PgInviteNewSourceLedgerStore, PgInviteReceivePolicyStore, PgMimiConsentCorrelationStore,
    PgMlsKeyPackageStore, PgNotificationStore, PgOrganizationRegistrationStore, PgPool,
    PgProjectionEventStore, PgRelationCurrentResultStore, PgSyncCursorStore,
};

#[tokio::test]
async fn postgres_agent_participation_cas_mismatch_has_zero_effect_and_serializes_replacement() {
    use coland_storage::AgentParticipationStore;
    use coland_storage_postgres::PgAgentParticipationStore;
    let database = coland_storage_postgres::test_database::TestDatabase::lease().await;
    let pool = database.pool();
    let _guard = DB_GUARD.lock().await;
    let store = PgAgentParticipationStore { pool: pool.clone() };
    let realm = arkret_wire::RealmId::from_event_id(&arkret_wire::EventId::from_digest(
        arkret_canonical::DigestSuite::Sha256,
        arkret_canonical::sha256_bytes(uuid::Uuid::now_v7().as_bytes()),
    ));
    let scid = format!("z{}", uuid::Uuid::now_v7().simple());
    let agent = format!("ak:did_core:webvh:{scid}");
    PgAgentStore { pool: pool.clone() }
        .put(AgentPrincipalRecord::new(
            agent.clone(),
            "ak:did_core:web:controller.example".to_owned(),
            realm.to_string(),
            arkret_wire::DidUrl::new(format!("did:webvh:{scid}:agent.example#managed-controller"))
                .unwrap(),
            arkret_models_collaboration::agent_operations::AgentLifecycleState::Active,
            chrono::Utc::now(),
        ))
        .await
        .unwrap();
    let record = |version, allowed| {
        serde_json::json!({
            "agent_id":agent,"scope_kind":"realm","scope_key":format!("realm:{realm}"),
            "realm_id":realm,"scope":{"kind":"realm","realm_id":realm},"version":version,
            "reply_message":allowed,"reaction_add":allowed,"reaction_remove":allowed,
            "accept_third_party_mention":allowed,"act_on_behalf":allowed
        })
    };
    #[derive(diesel::QueryableByName)]
    struct Count {
        #[diesel(sql_type=diesel::sql_types::BigInt)]
        count: i64,
    }
    use diesel_async::RunQueryDsl;
    let mut conn = pool.get().await.unwrap();
    let count =
        diesel::sql_query("SELECT COUNT(*) AS count FROM canonical_realms WHERE wire_id=$1")
            .bind::<diesel::sql_types::Text, _>(realm.as_str())
            .get_result::<Count>(&mut conn)
            .await
            .unwrap()
            .count;
    assert!(
        !store
            .compare_and_swap_selection(record(6, true), 5)
            .await
            .unwrap()
    );
    assert!(store.list_selections(&agent).await.unwrap().is_empty());
    let after =
        diesel::sql_query("SELECT COUNT(*) AS count FROM canonical_realms WHERE wire_id=$1")
            .bind::<diesel::sql_types::Text, _>(realm.as_str())
            .get_result::<Count>(&mut conn)
            .await
            .unwrap()
            .count;
    assert_eq!(count, after);
    assert!(
        store
            .compare_and_swap_selection(record(1, true), 0)
            .await
            .unwrap()
    );
    let (first, second) = tokio::join!(
        store.compare_and_swap_selection(record(2, false), 1),
        store.compare_and_swap_selection(record(2, false), 1)
    );
    assert_ne!(first.unwrap(), second.unwrap());
    let rows = store.list_selections(&agent).await.unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["version"], 2);
    assert_eq!(rows[0]["reply_message"], false);
}

#[tokio::test]
async fn postgres_agent_participation_ceiling_reads_accepted_governance_and_refuses_missing_current()
 {
    use coland_storage::AgentParticipationStore;
    use coland_storage_postgres::PgAgentParticipationStore;
    let database = coland_storage_postgres::test_database::TestDatabase::lease().await;
    let pool = database.pool();
    let _guard = DB_GUARD.lock().await;
    let store = PgAgentParticipationStore { pool: pool.clone() };
    let discussion = ordinary_realm::open_discussion(
        &pool,
        &format!("participation-current:{}", uuid::Uuid::now_v7()),
    )
    .await;
    let scope = format!("realm:{}", discussion.realm_id());
    let rows = store
        .ceilings_for_scope_keys(std::slice::from_ref(&scope))
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["scope_key"], scope);
    assert_eq!(rows[0]["reply_message"], true);
    let absent = format!(
        "strand:{}:{}",
        discussion.realm_id(),
        arkret_wire::StrandId::from_event_id(&arkret_wire::EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            [99; 32]
        ))
    );
    assert!(
        store
            .ceilings_for_scope_keys(&[scope, absent])
            .await
            .is_err()
    );
}

#[tokio::test]
async fn postgres_audit_regression_satisfies_account_localpart_remove_contract() {
    let database = coland_storage_postgres::test_database::TestDatabase::lease().await;
    let pool = database.pool();
    let _db_guard = DB_GUARD.lock().await;
    let accounts = PgAccountStore { pool: pool.clone() };
    let localparts = PgAccountLocalpartStore { pool };
    assert_account_localpart_remove_contract(
        &accounts,
        &localparts,
        &format!("postgres-{}", uuid::Uuid::now_v7().simple()),
    )
    .await;
}

#[tokio::test]
async fn postgres_adapter_guards_repair_device_snapshots_atomically() {
    let database = coland_storage_postgres::test_database::TestDatabase::lease().await;
    let pool = database.pool();
    let _db_guard = DB_GUARD.lock().await;
    // This contract bypasses runtime bootstrap, so install its trusted local
    // inventory owner explicitly before exercising device writes.
    {
        use diesel_async::RunQueryDsl;
        let mut conn = pool.get().await.unwrap();
        diesel::sql_query("INSERT INTO device_inventory_station(singleton,station_id) VALUES(TRUE,'ak:did_core:web:storage-contract.example') ON CONFLICT(singleton) DO NOTHING")
            .execute(&mut *conn).await.unwrap();
    }
    use diesel::sql_types::Text;
    use diesel_async::RunQueryDsl;
    #[derive(diesel::QueryableByName)]
    struct Station {
        #[diesel(sql_type=Text)]
        station_id: String,
    }
    let mut conn = pool.get().await.unwrap();
    let station =
        diesel::sql_query("SELECT station_id FROM device_inventory_station WHERE singleton")
            .get_result::<Station>(&mut *conn)
            .await
            .unwrap();
    drop(conn);
    let namespace = format!("postgres-repair-snapshot-{}", uuid::Uuid::now_v7());
    // A device queue is keyed by (actor, device_id), and the contract leaves one
    // durable message in that queue on purpose; the fixture's fresh WebVH local
    // id gives every run its own principal, so no run reads a previous run's
    // queue. Both devices are accepted by the Station: the founding device by
    // the PCR genesis unit, the second by the accepted_device unit.
    let persistence = coland_storage_postgres::PgPersistenceStore::new(pool.clone());
    let mut source = pcr_genesis::PcrGenesisFixture::new(
        device_authorization_history::did_web_station(&station.station_id.parse().unwrap()),
    );
    let founding = source
        .admit_founding_device(&persistence)
        .await
        .expect("accepted PCR genesis");
    let second = source
        .admit_accepted_device(&persistence, [97; 32])
        .await
        .expect("accepted second device");
    let inventory = PgDeviceInventoryStore { pool: pool.clone() };
    let messages = PgDeviceMessageStore { pool };
    assert_device_message_snapshot_guard_contract(
        &inventory,
        &messages,
        &namespace,
        &founding,
        &second.authorization,
    )
    .await;
}

/// One confirmed, unrevoked human device authorization in this Station's
/// current device inventory.
///
/// The founding device of a genuinely signed PCR genesis the Station admitted
/// through its registered unit; the fixture's fresh WebVH local id gives every
/// run its own principal (and so its own Account) in the shared contract
/// database.
async fn confirmed_contract_device(pool: &PgPool) -> coland_storage::DeviceRevocationGateSelector {
    use diesel::sql_types::Text;
    use diesel_async::RunQueryDsl;
    #[derive(diesel::QueryableByName)]
    struct Station {
        #[diesel(sql_type = Text)]
        station_id: String,
    }
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query("INSERT INTO device_inventory_station(singleton,station_id) VALUES(TRUE,'ak:did_core:web:storage-contract.example') ON CONFLICT(singleton) DO NOTHING")
        .execute(&mut *conn)
        .await
        .unwrap();
    let station =
        diesel::sql_query("SELECT station_id FROM device_inventory_station WHERE singleton")
            .get_result::<Station>(&mut *conn)
            .await
            .unwrap();
    drop(conn);
    pcr_genesis::PcrGenesisFixture::new(device_authorization_history::did_web_station(
        &station.station_id.parse().unwrap(),
    ))
    .admit_founding_device(&coland_storage_postgres::PgPersistenceStore::new(
        pool.clone(),
    ))
    .await
    .expect("accepted PCR genesis")
}

#[tokio::test]
async fn postgres_realm_directory_hydration_preserves_unrelated_live_metadata() {
    use coland_storage::IdentityStoreRegistry as _;
    use coland_storage_postgres::PgPersistenceStore;

    // A retained contract database can contain a previous run's revoked
    // fixed founder. Lease a clean real database for this recovery invariant.
    let database = coland_storage_postgres::TestDatabase::lease().await;
    let pool = database.pool();
    let seed = uuid::Uuid::now_v7().to_string();
    let target = ordinary_realm::open_discussion(&pool, &format!("directory-target-{seed}")).await;
    let other = ordinary_realm::open_discussion(&pool, &format!("directory-other-{seed}")).await;
    let store = std::sync::Arc::new(PgPersistenceStore::new(pool.clone()));
    let handle = coland_services::persistence::PersistenceHandle::new(store.clone());
    handle
        .hydrate_realm_directory_entry(&other.realm_id())
        .await
        .unwrap()
        .expect("other Realm directory entry");
    let expected = handle
        .hydrate_realm_directory_entry(&target.realm_id())
        .await
        .unwrap()
        .expect("target Realm directory entry");
    assert!(!expected.members.is_empty());

    // A hot-path founding install must not overwrite another live Realm's
    // metadata with the defaults from its historical genesis.
    let mut other_meta = store
        .realm_meta()
        .get(other.realm_id().as_str())
        .await
        .unwrap()
        .unwrap();
    other_meta.deleted = true;
    other_meta.updated_at += chrono::TimeDelta::days(1);
    store
        .realm_meta()
        .put(other.realm_id().as_str(), &other_meta)
        .await
        .unwrap();
    let actual = handle
        .hydrate_realm_directory_entry(&target.realm_id())
        .await
        .unwrap()
        .expect("target Realm directory entry");
    assert_eq!(actual.realm_id, target.realm_id());
    assert_eq!(actual.title, expected.title);
    assert_eq!(actual.members, expected.members);
    assert_eq!(actual.source_refs, expected.source_refs);
    let unchanged = store
        .realm_meta()
        .get(other.realm_id().as_str())
        .await
        .unwrap()
        .unwrap();
    assert!(unchanged.deleted);
    assert_eq!(unchanged.updated_at, other_meta.updated_at);
}

#[tokio::test]
async fn postgres_notification_relay_delivers_large_payload_by_committed_reference() {
    use coland_storage_postgres::{load_event_notification, publish_event_notification};
    use diesel::sql_query;
    use diesel_async::RunQueryDsl;
    use tokio_postgres::{AsyncMessage, NoTls};

    let database = coland_storage_postgres::test_database::TestDatabase::lease().await;
    let pool = database.pool();
    let _db_guard = DB_GUARD.lock().await;
    let (client, mut connection) = tokio_postgres::connect(database.url(), NoTls)
        .await
        .unwrap();
    let (sender, mut receiver) = tokio::sync::mpsc::unbounded_channel();
    let listener = tokio::spawn(async move {
        while let Some(message) = std::future::poll_fn(|cx| connection.poll_message(cx)).await {
            if let AsyncMessage::Notification(notification) = message.unwrap() {
                sender.send(notification.payload().to_owned()).unwrap();
            }
        }
    });
    client
        .batch_execute("LISTEN coland_event_notifications")
        .await
        .unwrap();
    let payload = serde_json::json!({"welcome": "x".repeat(32_768)}).to_string();
    let id = publish_event_notification(&pool, &payload).await.unwrap();
    let reference = tokio::time::timeout(std::time::Duration::from_secs(5), receiver.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(reference, id.to_string());
    assert_eq!(reference.len(), 36);
    assert_eq!(
        load_event_notification(&pool, id).await.unwrap(),
        Some(payload.clone())
    );
    // Another subscriber can read the same record; delivery is not a destructive dequeue.
    assert_eq!(
        load_event_notification(&pool, id).await.unwrap(),
        Some(payload)
    );
    assert_eq!(
        load_event_notification(&pool, uuid::Uuid::now_v7())
            .await
            .unwrap(),
        None
    );

    let mut conn = pool.get().await.unwrap();
    sql_query(
        "UPDATE event_notification_relay SET created_at = NOW() - INTERVAL '2 days' WHERE id = $1",
    )
    .bind::<diesel::sql_types::Uuid, _>(id)
    .execute(&mut *conn)
    .await
    .unwrap();
    let current = publish_event_notification(&pool, "current").await.unwrap();
    assert_eq!(load_event_notification(&pool, id).await.unwrap(), None);
    assert_eq!(
        load_event_notification(&pool, current).await.unwrap(),
        Some("current".into())
    );
    listener.abort();
}

#[tokio::test]
async fn postgres_structured_projection_identities_round_trip() {
    use arkret_wire::{AccountId, ActorId, DidCoreId};
    use coland_storage::{
        CircleProjectionStore, MorphProjectionStore, SpaceContainerProjectionStore,
        StrandProjectionStore,
    };
    let database = coland_storage_postgres::test_database::TestDatabase::lease().await;
    let pool = database.pool();
    let _db_guard = DB_GUARD.lock().await;
    let principal = DidCoreId::new("ak:did_core:web:projection-alice.example").unwrap();
    let account = AccountId::new(
        principal.clone(),
        DidCoreId::new("ak:did_core:web:station-a.example").unwrap(),
    );
    let other_account = AccountId::new(
        principal,
        DidCoreId::new("ak:did_core:web:station-b.example").unwrap(),
    );
    let author = ActorId::account(account.clone()).to_string();
    let other_author = ActorId::account(other_account.clone()).to_string();
    let service =
        ActorId::service(DidCoreId::new("ak:did_core:web:notary.example").unwrap()).to_string();
    let realm_id = "ak:realm:AV0aa7N4-6SpEMTq2vRgjNbMjn0vCIqfM5PxnJ-qQpPP";
    let now = chrono::DateTime::parse_from_rfc3339("2026-08-31T00:00:00.000Z")
        .unwrap()
        .with_timezone(&chrono::Utc);
    // New adapters read only PostgreSQL; there is no in-memory projection cache.
    macro_rules! round_trip {
        ($adapter:ident, $record:expr, $id:ident) => {{
            let mut record = $record;
            coland_storage_postgres::$adapter { pool: pool.clone() }
                .put(&record)
                .await
                .unwrap();
            let reopened = coland_storage_postgres::$adapter { pool: pool.clone() };
            assert_eq!(reopened.get(&record.$id).await.unwrap().unwrap(), record);
            assert!(
                reopened
                    .list_for_realm(realm_id)
                    .await
                    .unwrap()
                    .contains(&record)
            );
            for updated_by in [Some(other_author.clone()), Some(service.clone()), None] {
                record.updated_by = updated_by;
                reopened.put(&record).await.unwrap();
                assert_eq!(reopened.get(&record.$id).await.unwrap().unwrap(), record);
                assert!(reopened.snapshot_all().await.unwrap().contains(&record));
            }
            record.created_by = "ak:did_core:web:unbound.example".into();
            assert!(
                reopened.put(&record).await.is_err(),
                "scalar bylines must fail closed"
            );
        }};
    }
    round_trip!(
        PgSpaceContainerProjectionStore,
        coland_storage::SpaceContainerProjectionRecord {
            container_space_id: "ak:space:AeJsr0sf3TZ_Cuzj2uLddhd-O-Cywvdj8ypnqpVG8zim".into(),
            kind: "navigation".into(),
            title: "identity persistence".into(),
            fields: Default::default(),
            scope_circle_id: None,
            child_scope_policy: None,
            child_scope_policy_scope_circle_id: None,
            parent_ref: None,
            rank: None,
            realm_id: realm_id.into(),
            state: "active".into(),
            state_changed_at: None,
            created_by: author.clone(),
            created_at: now,
            updated_by: None,
            updated_at: Some(now),
        },
        container_space_id
    );
    round_trip!(
        PgStrandProjectionStore,
        coland_storage::StrandProjectionRecord {
            strand_id: "ak:strand:AeJsr0sf3TZ_Cuzj2uLddhd-O-Cywvdj8ypnqpVG8zim".into(),
            tracks: Default::default(),
            title: "identity persistence".into(),
            summary: None,
            content: Some(serde_json::json!({"text":"test"})),
            encrypted_content: None,
            fields: Default::default(),
            schema_refs: vec!["ak.schema.calendar_event.v1".to_owned()],
            scope_circle_id: None,
            realm_id: realm_id.into(),
            state: "active".into(),
            state_changed_at: None,
            stage: None,
            stage_changed_at: None,
            created_by: author.clone(),
            created_at: now,
            updated_by: None,
            updated_at: Some(now),
        },
        strand_id
    );
    round_trip!(
        PgMorphProjectionStore,
        coland_storage::MorphProjectionRecord {
            morph_id: "ak:morph:AeJsr0sf3TZ_Cuzj2uLddhd-O-Cywvdj8ypnqpVG8zim".into(),
            scope_circle_id: None,
            morph_kind: "document".into(),
            title: None,
            fields: serde_json::json!({}),
            schema_refs: serde_json::json!([]),
            facets: serde_json::json!({}),
            versions: serde_json::json!([]),
            content: Some(serde_json::json!({"text":"test"})),
            encrypted_content: None,
            realm_id: realm_id.into(),
            state: "active".into(),
            state_changed_at: None,
            stage: None,
            stage_changed_at: None,
            created_by: author.clone(),
            created_at: now,
            updated_by: None,
            updated_at: Some(now),
        },
        morph_id
    );
    round_trip!(
        PgCircleProjectionStore,
        coland_storage::CircleProjectionRecord {
            circle_id: "ak:circle:AeJsr0sf3TZ_Cuzj2uLddhd-O-Cywvdj8ypnqpVG8zim".into(),
            profile_ref: None,
            title: "identity persistence".into(),
            summary: None,
            display: serde_json::json!({}),
            directory_visibility: "members".into(),
            join_rule: "invite".into(),
            history_access: "since_join".into(),
            encryption_profile: "none".into(),
            mls_group_ref: None,
            realm_id: realm_id.into(),
            state: "active".into(),
            state_changed_at: None,
            created_by: author.clone(),
            created_at: now,
            updated_by: None,
            updated_at: Some(now),
        },
        circle_id
    );
}

#[tokio::test]
async fn postgres_key_backup_identity_and_series_round_trip() {
    use arkret_wire::{AccountId, ActorId, DidCoreId};
    use coland_storage::{KeyBackupStore, PersistenceError};
    use coland_storage_postgres::PgKeyBackupStore;
    let database = coland_storage_postgres::test_database::TestDatabase::lease().await;
    let pool = database.pool();
    let _db_guard = DB_GUARD.lock().await;
    let principal = DidCoreId::new(format!(
        "ak:did_core:web:backup-{}.example",
        uuid::Uuid::now_v7().simple()
    ))
    .unwrap();
    let actor = |station| {
        ActorId::account(AccountId::new(
            principal.clone(),
            DidCoreId::new(station).unwrap(),
        ))
    };
    let actor_a = actor("ak:did_core:web:station-a.example");
    let actor_b = actor("ak:did_core:web:station-b.example");
    let series_id = format!("ak:backup_series:{}", uuid::Uuid::now_v7());
    let mut records = Vec::new();
    for actor_id in [&actor_a, &actor_b] {
        let backup_id = format!("ak:backup:{}", uuid::Uuid::now_v7());
        let payload = backup_page_envelope(&backup_id, actor_id, &series_id, 0, None);
        PgKeyBackupStore { pool: pool.clone() }
            .put(backup_id.clone(), payload.clone())
            .await
            .unwrap();
        records.push((backup_id, payload));
    }
    let reopened = PgKeyBackupStore { pool };
    for ((backup_id, payload), actor_id) in records.iter().zip([&actor_a, &actor_b]) {
        assert_eq!(
            reopened.get(backup_id).await.unwrap().as_ref(),
            Some(payload)
        );
        assert_eq!(
            reopened
                .list_for_actor(&actor_id.to_string())
                .await
                .unwrap(),
            vec![payload.clone()]
        );
    }
    let duplicate_id = format!("ak:backup:{}", uuid::Uuid::now_v7());
    let mut duplicate = records[0].1.clone();
    duplicate["backup_id"] = duplicate_id.clone().into();
    assert!(matches!(
        reopened.put(duplicate_id, duplicate).await,
        Err(PersistenceError::Conflict(_))
    ));
    let mut invalid = records[0].1.clone();
    invalid["actor_id"] = principal.to_string().into();
    assert!(reopened.put(records[0].0.clone(), invalid).await.is_err());
    assert!(reopened.list_for_actor(principal.as_str()).await.is_err());
    assert_eq!(
        reopened.get(&records[0].0).await.unwrap().as_ref(),
        Some(&records[0].1)
    );
}

/// One stored backup page.
///
/// `supersedes` names the page this one replaces. A series genesis has none;
/// every successor must name one, because the model refuses a successor that
/// cannot be chained back to the page it replaces.
fn backup_page_envelope(
    id: &str,
    actor: &arkret_wire::ActorId,
    series: &str,
    seq: u64,
    supersedes: Option<&str>,
) -> serde_json::Value {
    let mut page = serde_json::json!({
        "backup_id":id, "actor_id":actor, "backup_kind":"secret_storage", "backup_version":"kb_1",
        "created_at":"2026-09-09T00:00:00.000Z", "series_id":series, "series_seq":seq,
        "encryption":{"recipient_method":"secret_storage_key", "recipient_key_ref":"backup-key", "aead":{"name":"xchacha20_poly1305", "nonce":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}},
        "domain_separation":{"subdomain":"secret_storage"},
        "contents":[{"item_kind":"recovery_key_share", "secret_id":"share"}],
        "ciphertext":"AAAA", "ciphertext_digest":"sha256:709e80c88487a2411e1ee4dfb9f22a861492d20c4765150c0c794abd70f8147c",
        // A stored page names the device that signed it and the committed
        // authorization that device held, so the page is attributable after
        // the fact rather than anonymous bytes.
        "auth_data":{
            "device_id":"ak:device:01904100-0000-7000-8000-000000000001",
            "verification_method":"did:web:backup.example#device-signer",
            "signature_algorithm":"Ed25519",
            "signature":"AAAA",
            "device_authorize_event_id":"ak:event:AcIMom-0qqAXx_hmDJfxxaUJb_oJ64S3ARW1-WKFDCoD"
        }
    });
    if let Some(previous) = supersedes {
        page["supersedes_id"] = serde_json::json!(previous);
        page["supersedes_digest"] = serde_json::json!(
            "sha256:709e80c88487a2411e1ee4dfb9f22a861492d20c4765150c0c794abd70f8147c"
        );
    }
    page
}

#[tokio::test]
async fn postgres_key_backup_pages_are_ordered_bounded_and_revisioned() {
    use coland_storage::{KeyBackupListPosition, KeyBackupListQuery, KeyBackupStore};
    use coland_storage_postgres::PgKeyBackupStore;
    let database = coland_storage_postgres::test_database::TestDatabase::lease().await;
    let pool = database.pool();
    let _guard = DB_GUARD.lock().await;
    let actor = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        arkret_wire::DidCoreId::new(format!(
            "ak:did_core:web:page-{}.example",
            uuid::Uuid::now_v7().simple()
        ))
        .unwrap(),
        arkret_wire::DidCoreId::new("ak:did_core:web:station.example").unwrap(),
    ));
    let series = format!("ak:backup_series:{}", uuid::Uuid::now_v7());
    let store = PgKeyBackupStore { pool: pool.clone() };
    let mut ids: Vec<String> = Vec::new();
    for seq in 0..5 {
        let id = format!("ak:backup:{}", uuid::Uuid::now_v7());
        let mut body =
            backup_page_envelope(&id, &actor, &series, seq, ids.last().map(String::as_str));
        body["ciphertext"] = "A".repeat(100_000).into();
        store.put(id.clone(), body).await.unwrap();
        ids.push(id);
    }
    let mut query = KeyBackupListQuery {
        actor_id: actor.to_string(),
        backup_kind: Some("secret_storage".into()),
        series_id: Some(series.clone()),
        after: None,
        limit: 2,
    };
    let first = store.list_page(&query).await.unwrap();
    assert_eq!(first.revision, 5);
    assert_eq!(first.payloads.len(), 2);
    assert!(!first.byte_limited);
    assert_eq!(first.payloads[0]["series_seq"], 0);
    assert_eq!(first.payloads[1]["series_seq"], 1);
    assert!(
        first
            .payloads
            .iter()
            .all(|row| row.get("ciphertext").is_none())
    );
    query.after = Some(KeyBackupListPosition {
        backup_kind: "secret_storage".into(),
        series_id: series,
        series_seq: 1,
        backup_id: ids[1].clone(),
    });
    let reopened = PgKeyBackupStore { pool: pool.clone() };
    reopened.get(&ids[0]).await.unwrap();
    let second = reopened.list_page(&query).await.unwrap();
    assert_eq!(second.revision, first.revision);
    assert_eq!(second.payloads[0]["series_seq"], 2);
    assert_eq!(second.payloads[1]["series_seq"], 3);
    reopened.delete(&ids[4]).await.unwrap();
    assert_eq!(reopened.list_page(&query).await.unwrap().revision, 6);
    let mut replacement = reopened.get(&ids[3]).await.unwrap().unwrap();
    // Only the closed `backup_metadata` projection reaches a list row
    // (decision 0095 keeps `contents` out of it), so the page grows through a
    // listed member.
    replacement["encryption"]["recipient_key_ref"] = "k".repeat(910_000).into();
    reopened.put(ids[3].clone(), replacement).await.unwrap();
    let bounded = reopened.list_page(&query).await.unwrap();
    assert_eq!(bounded.revision, 7);
    assert!(bounded.byte_limited);
    assert_eq!(bounded.payloads.len(), 1);
    query.limit = 202;
    assert!(reopened.list_page(&query).await.is_err());
}

/// These contracts share one database and several of them exercise
/// row/advisory locking (`lock_organization`, the event-commit unit of work).
/// Running them concurrently against a single pool intermittently starves a
/// connection and surfaces as `Database("connection closed")` or a spurious
/// conflict, so each case holds this guard for its duration.
static DB_GUARD: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[derive(diesel::QueryableByName)]
struct TimestampRow {
    #[diesel(sql_type = diesel::sql_types::Timestamptz)]
    value: chrono::DateTime<chrono::Utc>,
}

#[derive(diesel::QueryableByName)]
struct LedgerCountRow {
    #[diesel(sql_type = diesel::sql_types::BigInt)]
    value: i64,
}

#[derive(diesel::QueryableByName)]
struct RelationCurrentResultContractRow {
    #[diesel(sql_type = diesel::sql_types::Text)]
    relation_id: String,
    #[diesel(sql_type = diesel::sql_types::Text)]
    state: String,
    #[diesel(sql_type = diesel::sql_types::Text)]
    current_commit_id: String,
    #[diesel(sql_type = diesel::sql_types::BigInt)]
    current_stream_position: i64,
    #[diesel(sql_type = diesel::sql_types::Jsonb)]
    value: serde_json::Value,
}

/// Whether the fixture expects the adapter to keep this commit.
#[derive(Clone, Copy, PartialEq, Eq)]
enum FixtureCommitSettlement {
    /// The adapter accepts it, so it advances the durable stream head.
    Accepted,
    /// The adapter rolls it back, so the head stays where it is and the next
    /// accepted Event reuses the position this attempt claimed.
    RolledBack,
}

/// One independent commit stream a Postgres fixture drives.
///
/// A `RealmCommit` orders exactly one Event, so a fixture that commits several
/// Events into one Realm owes a chained sequence: consecutive `stream_position`s
/// and a `previous_commit_ref` naming the current stream head.
struct FixtureCommitStream {
    authority: CurrentRealmAuthority,
    next_position: u64,
    previous_commit_ref: Option<arkret_wire::RealmCommitId>,
}

impl FixtureCommitStream {
    /// A Realm id retypes the 33-byte token of the Event that created the
    /// Realm, so the genesis authority reference is recoverable from the Realm
    /// id alone and no fixture has to carry the same seed twice.
    fn new(realm_id: &arkret_identifiers::RealmId, station_id: &arkret_wire::DidCoreId) -> Self {
        let genesis_event_ref = arkret_identifiers::EventIdentityKey::new(
            realm_id.digest_suite_code(),
            realm_id.digest_bytes(),
        )
        .event_id();
        Self {
            authority: CurrentRealmAuthority {
                realm_id: realm_id.clone(),
                generation: 0,
                service_id: station_id.clone(),
                authority_ref: arkret_wire::RealmCommitAuthorityRef::GenesisOrChangeEvent(
                    genesis_event_ref,
                ),
                last_handoff_ref: None,
            },
            next_position: 0,
            previous_commit_ref: None,
        }
    }

    /// The adapter refuses to order an Event for a Realm whose current
    /// authority it cannot read, so the genesis decision is installed first.
    async fn install(&self, pool: &PgPool) {
        PgAuthorityCommitStore { pool: pool.clone() }
            .install_genesis_authority(&self.authority)
            .await
            .expect("install fixture genesis authority");
    }

    fn order(
        &mut self,
        settlement: FixtureCommitSettlement,
        event: &arkret_wire::Event,
        committed_at: chrono::DateTime<chrono::Utc>,
    ) -> AuthorityCommitTransaction {
        let stream_ref = arkret_wire::CommitStreamRef::from_scope(
            &event.scope_ref,
            Some(event.realm_id.clone()),
        )
        .expect("fixture Event scope names one commit stream");
        let commit_id = arkret_wire::RealmCommitId::from_digest(arkret_canonical::sha256_bytes(
            format!("{}:{}", event.event_id, self.next_position).as_bytes(),
        ));
        let transaction = AuthorityCommitTransaction {
            expected_authority: self.authority.clone(),
            commit: arkret_wire::RealmCommit {
                producer_signer_fact_digest: None,
                commit_id: commit_id.clone(),
                realm_id: event.realm_id.clone(),
                stream_ref,
                stream_position: self.next_position,
                previous_commit_ref: self.previous_commit_ref.clone(),
                event_ref: event.event_id.clone(),
                governance_generation: self.authority.generation,
                authority_ref: self.authority.authority_ref.clone(),
                committed_at,
                signature: fixture_authority_signature(&self.authority.service_id, committed_at),
            },
            event: event.clone(),
            producer_signer_fact: None,
            mls_state: None,
            welcomes: Vec::new(),
            recipient_queue_capacity: 0,
        };
        if settlement == FixtureCommitSettlement::Accepted {
            self.next_position += 1;
            self.previous_commit_ref = Some(commit_id);
        }
        transaction
    }
}

/// The DID a fixture core id projects from.
fn fixture_did(core_id: &arkret_wire::DidCoreId) -> String {
    format!(
        "did:{}",
        core_id
            .as_str()
            .strip_prefix("ak:did_core:")
            .expect("fixture core id carries the projected prefix")
    )
}

/// The current Station's detached signature over a fixture `RealmCommit`.
///
/// The adapter authenticates the signer by projecting the verification
/// method's controller to a service id, so the method has to name the same
/// service the genesis authority carries.
fn fixture_authority_signature(
    service_id: &arkret_wire::DidCoreId,
    created_at: chrono::DateTime<chrono::Utc>,
) -> arkret_wire::DetachedObjectSignature {
    arkret_wire::DetachedObjectSignature {
        context: arkret_wire::DetachedSignatureContext::RealmCommit,
        signature_algorithm: arkret_wire::DetachedSignatureAlgorithm::Ed25519,
        verification_method: arkret_wire::DidUrl::new(format!(
            "{}#authority",
            fixture_did(service_id)
        ))
        .expect("fixture authority verification method"),
        signed_digest: arkret_wire::Hash::new(format!("sha256:{}", "3".repeat(64)))
            .expect("fixture authority signed digest"),
        created_at,
        sig: arkret_wire::Base64UrlString::new("c2lnbmF0dXJl".to_owned())
            .expect("fixture authority signature bytes"),
    }
}

/// One idempotency row bound to a fixture Event's own authenticated actor.
fn fixture_idempotency_record(
    request: &coland_storage::EventCommitRequest,
    idempotency_key: String,
    created_at: chrono::DateTime<chrono::Utc>,
) -> coland_storage::IdempotencyRecord {
    coland_storage::IdempotencyRecord {
        authenticated_actor: request.authority_commit.event.actor_id.clone(),
        operation_id: "ak.peer.events.command.submit.v1".to_owned(),
        idempotency_key,
        request_hash: request.event.canonical_digest.clone(),
        response_status: 202,
        response_body: serde_json::json!({"event_id": request.event.event_id}),
        created_at,
        expires_at: created_at + chrono::TimeDelta::hours(24),
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "The fixture keeps independent signed originals, accepted references and source-time coordinates explicit."
)]
fn franking_event_request(
    stream: &mut FixtureCommitStream,
    settlement: FixtureCommitSettlement,
    realm_id: &arkret_identifiers::RealmId,
    actor_id: arkret_wire::DidCoreId,
    station_id: &arkret_wire::DidCoreId,
    kind: &str,
    payload: serde_json::Value,
    received_at: chrono::DateTime<chrono::Utc>,
) -> coland_storage::EventCommitRequest {
    let mut event = arkret_wire::test_support::raw_event_at(
        kind,
        arkret_wire::ScopeRef::Realm {
            realm_id: realm_id.clone(),
        },
        actor_id.clone(),
        station_id.clone(),
        payload,
        received_at,
    )
    .unwrap();
    let canonical_digest = event
        .event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
        .unwrap();
    // Every admitted Event carries exactly one producer proof. This fixture's
    // case is the storage boundary and not signature verification, so it
    // carries the structural-only detached JWS bound to these exact bytes.
    let event_digest =
        arkret_wire::Hash::new(canonical_digest.clone()).expect("fixture event digest hash");
    event.producer_proof = Some(arkret_wire::ProducerEventProof {
        kind: arkret_wire::proof_kind::DETACHED_JWS.to_owned(),
        verification_method: arkret_wire::DidUrl::new(format!(
            "{}#franking-device",
            fixture_did(&actor_id)
        ))
        .expect("fixture producer verification method"),
        event_digest: event_digest.clone(),
        created_at: arkret_canonical::normalize_timestamp_canonical(received_at),
        domain: None,
        audience: None,
        proof_purpose: None,
        jws: arkret_wire::test_support::structural_only_detached_jws(&event_digest),
    });
    let canonical_bytes =
        arkret_canonical::canonical_json_bytes(&event.digest_payload().unwrap()).unwrap();
    let authority_commit = stream.order(settlement, &event, received_at);
    coland_storage::EventCommitRequest {
        verified_media_participant: None,
        authority_commit,
        self_producer_guard: None,
        applet_producer_guard: None,
        widget_token_gate: None,
        agent_grant_scope_evidence: None,
        forwarded_producer_evidence: None,
        forwarded_agent_producer: None,
        agent_deployment_ceiling:
            arkret_models_collaboration::governance::agent_participation::ParticipationBits::ALL,
        parent_membership_admission: None,
        contact_projection: None,

        event: coland_storage::CanonicalEventRecord {
            event_id: event.event_id.to_string(),
            actor_id: event.actor_id.to_string(),
            realm_id: Some(realm_id.to_string()),
            kind: kind.to_owned(),
            schema_id: "ak.schema.franking_fixture.v1".to_owned(),
            digest_suite: arkret_canonical::DigestSuite::Sha256,
            canonical_digest,
            canonical_bytes,
            envelope: serde_json::to_value(&event).unwrap(),
            received_at,
        },
        device_revocation_transition: None,
        device_revocation_gate: None,
        projections: Vec::new(),
        idempotency: None,
        outbox: Vec::new(),
        realm_fanout_source: None,
    }
}

async fn assert_event_and_commit_absent(
    pool: &PgPool,
    event_id: arkret_wire::EventId,
    commit_id: arkret_wire::RealmCommitId,
) {
    use coland_storage::EventStore;
    use diesel::sql_types::Text;
    use diesel_async::RunQueryDsl;

    assert!(
        !PgEventStore { pool: pool.clone() }
            .contains(event_id.as_str())
            .await
            .unwrap()
    );
    let mut conn = pool.get().await.unwrap();
    let count =
        diesel::sql_query("SELECT COUNT(*)::bigint AS value FROM realm_commits WHERE commit_id=$1")
            .bind::<Text, _>(commit_id.as_str())
            .get_result::<LedgerCountRow>(&mut *conn)
            .await
            .unwrap();
    assert_eq!(
        count.value, 0,
        "rejected CAS must roll back its RealmCommit"
    );
}

#[tokio::test]
async fn postgres_self_producer_guard_rejects_before_event_and_commit_writes() {
    use coland_storage::EventCommitUnitOfWork;

    let database = coland_storage_postgres::test_database::TestDatabase::lease().await;
    let pool = database.pool();
    let _db_guard = DB_GUARD.lock().await;
    let namespace = format!("self-producer-guard:{}", uuid::Uuid::now_v7());
    let realm_id = arkret_identifiers::RealmId::new(event_derived_realm_id(namespace.as_bytes()))
        .expect("fixture Realm id");
    let station_id =
        arkret_wire::DidCoreId::new("ak:did_core:web:self-guard-station.example").unwrap();
    let actor_id = arkret_wire::DidCoreId::new("ak:did_core:web:self-guard-actor.example").unwrap();
    let mut stream = FixtureCommitStream::new(&realm_id, &station_id);
    stream.install(&pool).await;
    let now = chrono::Utc::now();
    let mut request = franking_event_request(
        &mut stream,
        FixtureCommitSettlement::RolledBack,
        &realm_id,
        actor_id.clone(),
        &station_id,
        arkret_wire::EventKind::MessageCreate.as_str(),
        serde_json::json!({"body":"guard must reject"}),
        now,
    );
    let event_id = request.authority_commit.event.event_id.clone();
    let commit_id = request.authority_commit.commit.commit_id.clone();
    request.self_producer_guard = Some(coland_storage::SelfProducerCommitGuard::Agent {
        pcr_realm_id: realm_id.clone(),
        agent_id: actor_id,
        authorization_ref: arkret_wire::CommittedEventRef {
            event_id: event_id.clone(),
            commit_id: commit_id.clone(),
            stream_ref: request.authority_commit.commit.stream_ref.clone(),
            stream_position: request.authority_commit.commit.stream_position,
        },
        verification_method: request
            .authority_commit
            .event
            .producer_proof
            .as_ref()
            .unwrap()
            .verification_method
            .clone(),
    });
    assert!(
        PgEventCommitUnitOfWork::new(pool.clone())
            .commit_event(request)
            .await
            .is_err()
    );
    assert_event_and_commit_absent(&pool, event_id, commit_id).await;
}

#[tokio::test]
async fn postgres_oversized_realm_snapshot_rejects_the_commit_without_writes() {
    use coland_storage::{EventCommitUnitOfWork, PersistenceError};
    use diesel::sql_types::{BigInt, Text};
    use diesel_async::RunQueryDsl;

    let database = coland_storage_postgres::test_database::TestDatabase::lease().await;
    let pool = database.pool();
    let _db_guard = DB_GUARD.lock().await;
    let discussion = ordinary_realm::open_discussion(
        &pool,
        &format!("snapshot-capacity:{}", uuid::Uuid::now_v7()),
    )
    .await;
    let realm_id = discussion.realm_id();

    // Grow an already-authoritative typed row -- the bootstrap Realm profile,
    // still covered by the RealmCommit that installed it -- until the closed
    // signed snapshot is necessarily larger than 8 MiB. The next admission
    // must measure the full post-commit durable cut and roll the whole
    // transaction back.
    let mut conn = pool.get().await.unwrap();
    let grown = diesel::sql_query(
        "UPDATE realm_bootstrap_current_results \
         SET value = jsonb_set(value, '{name}', to_jsonb(repeat('x', $2::int))) \
         WHERE realm_id = $1 AND result_family = 'realm_profile'",
    )
    .bind::<Text, _>(realm_id.as_str())
    .bind::<BigInt, _>(8 * 1024 * 1024_i64)
    .execute(&mut *conn)
    .await
    .unwrap();
    assert_eq!(
        grown, 1,
        "the bootstrap unit installs the Realm profile row"
    );
    drop(conn);

    let request = discussion.message_after(
        &discussion.head.authority_commit,
        "must roll back",
        discussion.committed_at(),
    );
    let event_id = request.authority_commit.event.event_id.clone();
    let commit_id = request.authority_commit.commit.commit_id.clone();
    let error = PgEventCommitUnitOfWork::new(pool.clone())
        .commit_event(request)
        .await
        .expect_err("an oversized maximal snapshot must reject admission");
    assert!(matches!(error, PersistenceError::Conflict(_)), "{error:?}");
    assert_eq!(
        error.conflict_code(),
        Some(coland_storage::ConflictCode::SnapshotCapacityExceeded)
    );
    assert_event_and_commit_absent(&pool, event_id, commit_id).await;
}

#[tokio::test]
async fn postgres_relation_current_result_is_exact_commit_cas_and_atomic() {
    use coland_storage::{EventCommitUnitOfWork, PersistenceError};
    use diesel::sql_types::{Jsonb, Text};
    use diesel_async::RunQueryDsl;

    let database = coland_storage_postgres::test_database::TestDatabase::lease().await;
    let pool = database.pool();
    let _db_guard = DB_GUARD.lock().await;
    let namespace = format!("relation-current:{}", uuid::Uuid::now_v7());
    let discussion = ordinary_realm::open_discussion(&pool, &namespace).await;
    let realm_id = discussion.realm_id();
    let station_id = discussion
        .head
        .authority_commit
        .expected_authority
        .service_id
        .clone();
    let actor_id = discussion.unit.transactions[0]
        .event
        .actor_id
        .signing_principal_id()
        .clone();
    let mut stream = FixtureCommitStream {
        authority: discussion.head.authority_commit.expected_authority.clone(),
        next_position: discussion.head.authority_commit.commit.stream_position + 1,
        previous_commit_ref: Some(discussion.head.authority_commit.commit.commit_id.clone()),
    };
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let now =
        chrono::DateTime::from_timestamp_micros(chrono::Utc::now().timestamp_micros()).unwrap();
    let domain = serde_json::json!({
        "domain_kind":"tuple",
        "relation_kind":"references",
        "from_ref":discussion.strand_id,
        "to_ref":realm_id
    });
    let definition = serde_json::json!({
        "relation_kind":"references",
        "from_ref":discussion.strand_id,
        "to_ref":realm_id,
        "rank":"A1",
        "fields":{"note":"initial"}
    });
    let request = |stream: &mut FixtureCommitStream,
                   settlement: FixtureCommitSettlement,
                   kind: arkret_wire::EventKind,
                   payload: serde_json::Value,
                   at: chrono::DateTime<chrono::Utc>| {
        franking_event_request(
            stream,
            settlement,
            &realm_id,
            actor_id.clone(),
            &station_id,
            kind.as_str(),
            payload,
            at,
        )
    };
    let load = || async {
        let mut conn = pool.get().await.unwrap();
        diesel::sql_query(
            "SELECT relation_id,state,current_commit_id,current_stream_position,value \
             FROM relation_current_results WHERE realm_id=$1",
        )
        .bind::<Text, _>(realm_id.as_str())
        .get_result::<RelationCurrentResultContractRow>(&mut *conn)
        .await
        .unwrap()
    };
    let mut create = request(
        &mut stream,
        FixtureCommitSettlement::Accepted,
        arkret_wire::EventKind::RelationCreate,
        serde_json::json!({
            "primary_conflict_domain":domain,
            "expected_revision":null,
            "relation":definition
        }),
        now,
    );
    let create_lifecycle_time = now + chrono::TimeDelta::seconds(1);
    create.authority_commit.commit.committed_at = create_lifecycle_time;
    let create_replay = create.clone();
    let create_commit = create.authority_commit.commit.clone();
    let first_relation_id =
        arkret_wire::RelationId::from_event_id(&create.authority_commit.event.event_id);
    assert!(uow.commit_event(create).await.unwrap().event_inserted);
    let row = load().await;
    assert_eq!(row.relation_id, first_relation_id.as_str());
    assert_eq!(row.state, "active");
    assert_eq!(row.current_commit_id, create_commit.commit_id.as_str());
    assert_eq!(
        row.current_stream_position,
        create_commit.stream_position as i64
    );
    assert_eq!(
        row.value["created_at"],
        serde_json::json!(arkret_canonical::format_timestamp_canonical(
            create_lifecycle_time
        ))
    );

    // A lost response may replay the byte-identical authority transaction.
    // Duplicate skips Relation CAS and therefore returns successfully instead
    // of treating the already-installed revision as stale.
    assert!(
        !uow.commit_event(create_replay)
            .await
            .unwrap()
            .event_inserted
    );
    assert_eq!(
        load().await.current_commit_id,
        create_commit.commit_id.as_str()
    );

    let active_create = request(
        &mut stream,
        FixtureCommitSettlement::RolledBack,
        arkret_wire::EventKind::RelationCreate,
        serde_json::json!({
            "primary_conflict_domain":domain,
            "expected_revision":{
                "commit_id":create_commit.commit_id,
                "stream_position":create_commit.stream_position
            },
            "relation":definition
        }),
        now + chrono::TimeDelta::seconds(1),
    );
    let rejected_event_id = active_create.authority_commit.event.event_id.clone();
    let rejected_commit_id = active_create.authority_commit.commit.commit_id.clone();
    assert!(matches!(
        uow.commit_event(active_create).await,
        Err(PersistenceError::Conflict(reason)) if reason.starts_with("failed_precondition:")
    ));
    assert_event_and_commit_absent(&pool, rejected_event_id, rejected_commit_id).await;
    assert_eq!(load().await.relation_id, first_relation_id.as_str());

    let stale_update = request(
        &mut stream,
        FixtureCommitSettlement::RolledBack,
        arkret_wire::EventKind::RelationUpdate,
        serde_json::json!({
            "primary_conflict_domain":domain,
            "expected_revision":{
                "commit_id":arkret_wire::RealmCommitId::from_digest([0x55;32]),
                "stream_position":create_commit.stream_position
            },
            "patch":{"fields.note":"stale"},
            "relation_id":first_relation_id
        }),
        now + chrono::TimeDelta::seconds(2),
    );
    let rejected_event_id = stale_update.authority_commit.event.event_id.clone();
    let rejected_commit_id = stale_update.authority_commit.commit.commit_id.clone();
    assert!(matches!(
        uow.commit_event(stale_update).await,
        Err(PersistenceError::Conflict(reason)) if reason.starts_with("failed_precondition:")
    ));
    assert_event_and_commit_absent(&pool, rejected_event_id, rejected_commit_id).await;
    assert_eq!(load().await.value["fields"]["note"], "initial");

    let missing_domain = serde_json::json!({
        "domain_kind":"tuple",
        "relation_kind":"references",
        "from_ref":realm_id,
        "to_ref":discussion.strand_id
    });
    let missing_update = request(
        &mut stream,
        FixtureCommitSettlement::RolledBack,
        arkret_wire::EventKind::RelationUpdate,
        serde_json::json!({
            "primary_conflict_domain":missing_domain,
            "expected_revision":{
                "commit_id":create_commit.commit_id,
                "stream_position":create_commit.stream_position
            },
            "patch":{"fields.note":"missing"},
            "relation_id":first_relation_id
        }),
        now + chrono::TimeDelta::seconds(3),
    );
    let rejected_event_id = missing_update.authority_commit.event.event_id.clone();
    let rejected_commit_id = missing_update.authority_commit.commit.commit_id.clone();
    assert!(matches!(
        uow.commit_event(missing_update).await,
        Err(PersistenceError::Conflict(reason)) if reason.starts_with("failed_precondition:")
    ));
    assert_event_and_commit_absent(&pool, rejected_event_id, rejected_commit_id).await;

    let update = request(
        &mut stream,
        FixtureCommitSettlement::Accepted,
        arkret_wire::EventKind::RelationUpdate,
        serde_json::json!({
            "primary_conflict_domain":domain,
            "expected_revision":{
                "commit_id":create_commit.commit_id,
                "stream_position":create_commit.stream_position
            },
            "patch":{"fields.note":"updated"},
            "relation_id":first_relation_id
        }),
        now + chrono::TimeDelta::seconds(4),
    );
    let update_commit = update.authority_commit.commit.clone();
    assert!(uow.commit_event(update).await.unwrap().event_inserted);
    assert_eq!(load().await.value["fields"]["note"], "updated");

    let mut tombstone = request(
        &mut stream,
        FixtureCommitSettlement::Accepted,
        arkret_wire::EventKind::RelationTombstone,
        serde_json::json!({
            "primary_conflict_domain":domain,
            "expected_revision":{
                "commit_id":update_commit.commit_id,
                "stream_position":update_commit.stream_position
            },
            "relation_id":first_relation_id,
            "reason":"superseded"
        }),
        now + chrono::TimeDelta::seconds(5),
    );
    let tombstone_lifecycle_time = now + chrono::TimeDelta::seconds(6);
    tombstone.authority_commit.commit.committed_at = tombstone_lifecycle_time;
    let tombstone_commit = tombstone.authority_commit.commit.clone();
    assert!(uow.commit_event(tombstone).await.unwrap().event_inserted);
    let row = load().await;
    assert_eq!(row.state, "tombstoned");
    assert_eq!(
        row.value["state_changed_at"],
        serde_json::json!(arkret_canonical::format_timestamp_canonical(
            tombstone_lifecycle_time
        ))
    );
    assert_eq!(
        row.value["updated_at"],
        serde_json::json!(arkret_canonical::format_timestamp_canonical(
            tombstone_lifecycle_time
        ))
    );

    let replacement = request(
        &mut stream,
        FixtureCommitSettlement::Accepted,
        arkret_wire::EventKind::RelationCreate,
        serde_json::json!({
            "primary_conflict_domain":domain,
            "expected_revision":{
                "commit_id":tombstone_commit.commit_id,
                "stream_position":tombstone_commit.stream_position
            },
            "relation":definition
        }),
        now + chrono::TimeDelta::seconds(7),
    );
    let replacement_id =
        arkret_wire::RelationId::from_event_id(&replacement.authority_commit.event.event_id);
    assert_ne!(replacement_id, first_relation_id);
    assert!(uow.commit_event(replacement).await.unwrap().event_inserted);
    let row = load().await;
    assert_eq!(row.relation_id, replacement_id.as_str());
    assert_eq!(row.state, "active");

    // The restart reader must expose the same authoritative row written by
    // the RealmCommit transaction, including its exact CAS revision.
    let stored = PgRelationCurrentResultStore { pool: pool.clone() }
        .snapshot_all()
        .await
        .unwrap()
        .into_iter()
        .find(|record| record.realm_id == realm_id)
        .expect("current Relation row is restart-readable");
    assert_eq!(
        stored.relation.id.as_ref().map(ToString::to_string),
        Some(replacement_id.to_string())
    );
    assert_eq!(
        stored.relation.state,
        Some(arkret_wire::RelationState::Active)
    );
    assert_eq!(stored.revision.commit_id.as_str(), row.current_commit_id);
    assert_eq!(
        stored.revision.stream_position,
        u64::try_from(row.current_stream_position).unwrap()
    );

    // The selected row and its materialized Relation must describe the same
    // signed domain. Corrupting only the value reaches schema_violation, not
    // the absent-domain CAS branch exercised above.
    let healthy_value = row.value.clone();
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query(
        "UPDATE relation_current_results \
         SET value=jsonb_set(value,'{from_ref}',to_jsonb($2::text),false) WHERE realm_id=$1",
    )
    .bind::<Text, _>(realm_id.as_str())
    .bind::<Text, _>("ak:strand:AQdknt9AByYY2gb16KB093xeB4J8b02mTEd4Mt8z2rO-")
    .execute(&mut *conn)
    .await
    .unwrap();
    drop(conn);
    let domain_mismatch = request(
        &mut stream,
        FixtureCommitSettlement::RolledBack,
        arkret_wire::EventKind::RelationUpdate,
        serde_json::json!({
            "primary_conflict_domain":domain,
            "expected_revision":{
                "commit_id":row.current_commit_id,
                "stream_position":row.current_stream_position
            },
            "patch":{"fields.note":"must-not-land"},
            "relation_id":replacement_id
        }),
        now + chrono::TimeDelta::seconds(8),
    );
    let rejected_event_id = domain_mismatch.authority_commit.event.event_id.clone();
    let rejected_commit_id = domain_mismatch.authority_commit.commit.commit_id.clone();
    assert!(matches!(
        uow.commit_event(domain_mismatch).await,
        Err(PersistenceError::SchemaViolation(reason))
            if reason.contains("primary conflict domain does not match current value")
    ));
    assert_event_and_commit_absent(&pool, rejected_event_id, rejected_commit_id).await;
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query("UPDATE relation_current_results SET value=$2 WHERE realm_id=$1")
        .bind::<Text, _>(realm_id.as_str())
        .bind::<Jsonb, _>(&healthy_value)
        .execute(&mut *conn)
        .await
        .unwrap();
    drop(conn);

    // A corrupted legacy value without lifecycle state must not be healed to
    // active by a subsequent update. The failed admission also rolls back its
    // queued Event and RealmCommit.
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query("UPDATE relation_current_results SET value=value-'state' WHERE realm_id=$1")
        .bind::<Text, _>(realm_id.as_str())
        .execute(&mut *conn)
        .await
        .unwrap();
    drop(conn);
    let row = load().await;
    let invalid_state_update = request(
        &mut stream,
        FixtureCommitSettlement::RolledBack,
        arkret_wire::EventKind::RelationUpdate,
        serde_json::json!({
            "primary_conflict_domain":domain,
            "expected_revision":{
                "commit_id":row.current_commit_id,
                "stream_position":row.current_stream_position
            },
            "patch":{"fields.note":"must-not-heal"},
            "relation_id":replacement_id
        }),
        now + chrono::TimeDelta::seconds(9),
    );
    let rejected_event_id = invalid_state_update.authority_commit.event.event_id.clone();
    let rejected_commit_id = invalid_state_update
        .authority_commit
        .commit
        .commit_id
        .clone();
    assert!(matches!(
        uow.commit_event(invalid_state_update).await,
        Err(PersistenceError::Conflict(reason)) if reason.starts_with("failed_precondition:")
    ));
    assert_event_and_commit_absent(&pool, rejected_event_id, rejected_commit_id).await;
    assert!(load().await.value.get("state").is_none());
    assert!(matches!(
        PgRelationCurrentResultStore { pool: pool.clone() }
            .snapshot_all()
            .await,
        Err(PersistenceError::Database(_))
    ));
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query("UPDATE relation_current_results SET value=$2 WHERE realm_id=$1")
        .bind::<Text, _>(realm_id.as_str())
        .bind::<Jsonb, _>(&healthy_value)
        .execute(&mut *conn)
        .await
        .unwrap();
}

#[tokio::test]
async fn postgres_franking_nonce_ledger_is_bounded_atomic_and_restart_stable() {
    ordinary_realm::case_future(postgres_franking_nonce_ledger_case).await;
}

async fn postgres_franking_nonce_ledger_case() {
    use coland_storage::{
        AuthorityCommitTransaction, EventBatchCommitRequest, EventCommitUnitOfWork, EventStore,
        FrankingReplayNonceCommit, PersistenceError,
    };
    use diesel::sql_types::{BigInt, Text, Timestamptz};
    use diesel_async::RunQueryDsl;
    use ed25519_dalek::Signer as _;

    let database = coland_storage_postgres::test_database::TestDatabase::lease().await;
    let pool = database.pool();
    let _db_guard = DB_GUARD.lock().await;
    // Every report in this ledger belongs to one ordinary Realm, so they share
    // one authority and one chained Realm stream; the nonce binding requires
    // the report and its nonce commit to name the same Realm. The reporter is
    // the Realm's confirmed joined founder and every report targets one
    // committed discussion Message.
    let fixture = Box::pin(franking::prepare(
        &pool,
        &format!("franking-ledger:{}", uuid::Uuid::now_v7()),
    ))
    .await;
    let target = fixture.accepted_target.clone();
    let realm_id = target.authority_commit.event.realm_id.clone();
    let received_by = fixture.proof_payload.received_by.clone();
    let reporter = target
        .authority_commit
        .event
        .actor_id
        .signing_principal_id();
    let target_event_id = target.authority_commit.event.event_id.clone();
    // Only an accepted report advances the Realm stream head; a refused one
    // leaves it where it is, and the next report reuses that position.
    let mut head: AuthorityCommitTransaction = target.authority_commit.clone();
    let make_request = async |head: &AuthorityCommitTransaction,
                              replay_nonce: &str,
                              consumed_at: chrono::DateTime<chrono::Utc>| {
        let mut payload =
            ordinary_realm::report_payload(&realm_id, target_event_id.as_str(), reporter);
        let mut receipt = fixture.proof_payload.clone();
        receipt.replay_nonce = replay_nonce.to_owned();
        receipt.signature = arkret_canonical::base64url_encode(
            fixture
                .service_signing_key
                .sign(&receipt.canonical_signing_bytes().unwrap())
                .to_bytes(),
        );
        payload["franking_proof"] = serde_json::to_value(receipt).unwrap();
        let event = ordinary_realm::next_request(
            head,
            arkret_wire::EventKind::SelfModerationReport,
            reporter,
            payload,
            consumed_at,
        );
        let event = Box::pin(ordinary_realm::source_request(&pool, event)).await;
        let event_id = event.event.event_id.clone();
        (
            event,
            FrankingReplayNonceCommit {
                realm_id: realm_id.to_string(),
                received_by: received_by.clone(),
                replay_nonce: replay_nonce.to_owned(),
                report_event_id: event_id,
                consumed_at,
            },
        )
    };
    let commit = |event, nonce| EventBatchCommitRequest {
        audit_unit: None,
        events: vec![event],
        realm_organization_proof: None,
        invite_claim_proof: None,
        event_approvals: None,
        franking_replay_nonce: Some(nonce),
        applet_record: None,
        applet_authoring_preview: None,
        agent_membership_cascade: None,
    };
    let consumed_at =
        chrono::DateTime::from_timestamp_micros(chrono::Utc::now().timestamp_micros()).unwrap();
    let replay_nonce = "shared_nonce_0123456789";
    let (first_event, first_nonce) = make_request(&head, replay_nonce, consumed_at).await;
    let first_event_id = first_event.event.event_id.clone();
    let first_head = first_event.authority_commit.clone();
    PgEventCommitUnitOfWork::new(pool.clone())
        .commit_event_batch(commit(first_event, first_nonce))
        .await
        .unwrap();
    head = first_head;

    // Treat the successful write above as a lost response: reconstruct the
    // adapter and retry the same durable nonce with a competing Event.
    let (replay_event, replay_commit) = make_request(
        &head,
        replay_nonce,
        consumed_at + chrono::TimeDelta::seconds(1),
    )
    .await;
    let replay_event_id = replay_event.event.event_id.clone();
    let replay_error = PgEventCommitUnitOfWork::new(pool.clone())
        .commit_event_batch(commit(replay_event, replay_commit))
        .await
        .unwrap_err();
    assert!(matches!(
        replay_error,
        PersistenceError::Conflict(reason) if reason == "duplicate_conflict"
    ));
    let event_store = PgEventStore { pool: pool.clone() };
    assert!(event_store.contains(&first_event_id).await.unwrap());
    assert!(!event_store.contains(&replay_event_id).await.unwrap());

    let expires_at = coland_storage::franking_replay_nonce_expires_at(consumed_at).unwrap();
    let mut conn = pool.get().await.unwrap();
    let stored_expiry = diesel::sql_query(
        "SELECT expires_at AS value FROM moderation_franking_replay_nonces \
         WHERE realm_id = $1 AND received_by = $2 AND replay_nonce = $3",
    )
    .bind::<Text, _>(realm_id.as_str())
    .bind::<Text, _>(received_by.as_str())
    .bind::<Text, _>(replay_nonce)
    .get_result::<TimestampRow>(&mut conn)
    .await
    .unwrap()
    .value;
    assert_eq!(stored_expiry, expires_at);

    let (just_before_event, just_before_nonce) = make_request(
        &head,
        replay_nonce,
        expires_at - chrono::TimeDelta::microseconds(1),
    )
    .await;
    let just_before_event_id = just_before_event.event.event_id.clone();
    let just_before_error = PgEventCommitUnitOfWork::new(pool.clone())
        .commit_event_batch(commit(just_before_event, just_before_nonce))
        .await
        .unwrap_err();
    assert!(matches!(
        just_before_error,
        PersistenceError::Conflict(reason) if reason == "duplicate_conflict"
    ));
    assert!(!event_store.contains(&just_before_event_id).await.unwrap());

    let (at_expiry_event, at_expiry_nonce) = make_request(&head, replay_nonce, expires_at).await;
    let at_expiry_event_id = at_expiry_event.event.event_id.clone();
    let at_expiry_head = at_expiry_event.authority_commit.clone();
    PgEventCommitUnitOfWork::new(pool.clone())
        .commit_event_batch(commit(at_expiry_event, at_expiry_nonce))
        .await
        .unwrap();
    head = at_expiry_head;
    assert!(event_store.contains(&at_expiry_event_id).await.unwrap());

    diesel::sql_query(
        "INSERT INTO moderation_franking_replay_nonces \
         (realm_id, received_by, replay_nonce, report_event_id, consumed_at, expires_at) \
         VALUES ($1, $2, 'expired_nonce_0123456789', $3, $4, $5)",
    )
    .bind::<Text, _>(realm_id.as_str())
    .bind::<Text, _>(received_by.as_str())
    .bind::<Text, _>(format!("expired-report-{}", uuid::Uuid::now_v7()))
    .bind::<Timestamptz, _>(consumed_at - chrono::TimeDelta::hours(25))
    .bind::<Timestamptz, _>(consumed_at - chrono::TimeDelta::hours(1))
    .execute(&mut conn)
    .await
    .unwrap();
    drop(conn);
    let (after_expiry_event, after_expiry_nonce) = make_request(
        &head,
        "after_expiry_nonce_0123456789",
        consumed_at + chrono::TimeDelta::seconds(2),
    )
    .await;
    let after_expiry_head = after_expiry_event.authority_commit.clone();
    PgEventCommitUnitOfWork::new(pool.clone())
        .commit_event_batch(commit(after_expiry_event, after_expiry_nonce))
        .await
        .unwrap();
    head = after_expiry_head;
    let mut conn = pool.get().await.unwrap();
    let expired_count = diesel::sql_query(
        "SELECT COUNT(*) AS value FROM moderation_franking_replay_nonces \
         WHERE replay_nonce = 'expired_nonce_0123456789'",
    )
    .get_result::<LedgerCountRow>(&mut conn)
    .await
    .unwrap()
    .value;
    assert_eq!(expired_count, 0);

    diesel::sql_query(
        "DELETE FROM moderation_franking_replay_nonces \
         WHERE realm_id = $1 AND received_by = $2",
    )
    .bind::<Text, _>(realm_id.as_str())
    .bind::<Text, _>(received_by.as_str())
    .execute(&mut conn)
    .await
    .unwrap();
    diesel::sql_query(
        "INSERT INTO moderation_franking_replay_nonces \
         (realm_id, received_by, replay_nonce, report_event_id, consumed_at, expires_at) \
         SELECT $1, $2, 'capacity_nonce_' || n, 'capacity_report_' || $1 || '_' || n, $3, $4 \
         FROM generate_series(1, $5) AS n",
    )
    .bind::<Text, _>(realm_id.as_str())
    .bind::<Text, _>(received_by.as_str())
    .bind::<Timestamptz, _>(consumed_at)
    .bind::<Timestamptz, _>(expires_at)
    .bind::<BigInt, _>(
        i64::try_from(coland_storage::LOCAL_FRANKING_REPLAY_NONCE_MAX_ACTIVE_PER_SCOPE).unwrap(),
    )
    .execute(&mut conn)
    .await
    .unwrap();
    drop(conn);
    let (overflow_event, overflow_nonce) = make_request(
        &head,
        "overflow_nonce_0123456789",
        consumed_at + chrono::TimeDelta::seconds(3),
    )
    .await;
    let overflow_event_id = overflow_event.event.event_id.clone();
    let overflow_error = PgEventCommitUnitOfWork::new(pool.clone())
        .commit_event_batch(commit(overflow_event, overflow_nonce))
        .await
        .unwrap_err();
    assert!(matches!(
        overflow_error,
        PersistenceError::Conflict(reason) if reason == "duplicate_conflict"
    ));
    assert!(!event_store.contains(&overflow_event_id).await.unwrap());
    let mut conn = pool.get().await.unwrap();
    let active_count = diesel::sql_query(
        "SELECT COUNT(*) AS value FROM moderation_franking_replay_nonces \
         WHERE realm_id = $1 AND received_by = $2",
    )
    .bind::<Text, _>(realm_id.as_str())
    .bind::<Text, _>(received_by.as_str())
    .get_result::<LedgerCountRow>(&mut conn)
    .await
    .unwrap()
    .value;
    assert_eq!(
        active_count,
        i64::try_from(coland_storage::LOCAL_FRANKING_REPLAY_NONCE_MAX_ACTIVE_PER_SCOPE).unwrap()
    );
}

#[tokio::test]
async fn postgres_franking_target_proof_fault_and_restart_contract() {
    Box::pin(postgres_franking_target_proof_case()).await;
}

async fn postgres_franking_target_proof_case() {
    use coland_storage::{
        EventBatchCommitRequest, EventCommitUnitOfWork, EventStore, PersistenceError,
    };

    let database = coland_storage_postgres::test_database::TestDatabase::lease().await;
    let pool = database.pool();
    let _db_guard = DB_GUARD.lock().await;
    let fixture = Box::pin(franking::prepare(
        &pool,
        &format!("franking-target-proof:{}", uuid::Uuid::now_v7()),
    ))
    .await;
    let realm_id = fixture.proof_payload.realm_id.clone();
    let received_by = fixture.proof_payload.received_by.clone();
    let receipt_target_id = fixture
        .accepted_target
        .authority_commit
        .event
        .event_id
        .clone();
    // Spec content-moderation section 3.4 fixes the authenticated receipt only
    // after accepting its encrypted target. A later batch's new Message prefix
    // and that exact proof must both roll back if publication's last write fails.
    let target = fixture.prefix;
    let mut proof = fixture.proof;
    let created_at = proof.authority_commit.commit.committed_at;
    let target_event_id = target.event.event_id.clone();
    let proof_event_id = proof.event.event_id.clone();
    // The fault has to fail inside the database rather than before it, so it
    // rides the proof element's last durable write: a NUL byte cannot be
    // stored in a text column, and the idempotency row is written after the
    // proof Event's own commit and inside the same batch transaction.
    let clean_idempotency_key = format!("franking-proof-{}", uuid::Uuid::now_v7());
    proof.idempotency = Some(fixture_idempotency_record(
        &proof,
        format!("{clean_idempotency_key}\0"),
        created_at,
    ));
    let failing_batch = EventBatchCommitRequest {
        audit_unit: None,
        events: vec![target.clone(), proof.clone()],
        realm_organization_proof: None,
        invite_claim_proof: None,
        event_approvals: None,
        franking_replay_nonce: None,
        applet_record: None,
        applet_authoring_preview: None,
        agent_membership_cascade: None,
    };

    let database_error = PgEventCommitUnitOfWork::new(pool.clone())
        .commit_event_batch(failing_batch)
        .await
        .unwrap_err();
    assert!(
        matches!(database_error, PersistenceError::Database(_)),
        "{database_error:?}"
    );
    let event_store = PgEventStore { pool: pool.clone() };
    assert!(!event_store.contains(&target_event_id).await.unwrap());
    assert!(!event_store.contains(&proof_event_id).await.unwrap());
    assert!(
        event_store
            .contains(receipt_target_id.as_str())
            .await
            .unwrap()
    );
    assert!(
        event_store
            .franking_proofs_for_target(realm_id.as_str(), &received_by, receipt_target_id.as_str())
            .await
            .unwrap()
            .is_empty(),
        "a database error while inserting the proof must roll back its target prefix"
    );

    proof.idempotency = Some(fixture_idempotency_record(
        &proof,
        clean_idempotency_key,
        created_at,
    ));
    let clean_batch = EventBatchCommitRequest {
        audit_unit: None,
        events: vec![target, proof],
        realm_organization_proof: None,
        invite_claim_proof: None,
        event_approvals: None,
        franking_replay_nonce: None,
        applet_record: None,
        applet_authoring_preview: None,
        agent_membership_cascade: None,
    };
    PgEventCommitUnitOfWork::new(pool.clone())
        .commit_event_batch(clean_batch.clone())
        .await
        .unwrap();

    // Model a lost success response by reconstructing the adapter without
    // carrying the first outcome into the retry. This is not a process-kill
    // claim; it proves only the durable retry boundary.
    let retry = PgEventCommitUnitOfWork::new(pool.clone())
        .commit_event_batch(clean_batch)
        .await
        .unwrap();
    assert_eq!(retry, coland_storage::EventCommitOutcome::default());
    assert_eq!(
        event_store
            .franking_proofs_for_target(realm_id.as_str(), &received_by, receipt_target_id.as_str())
            .await
            .unwrap()
            .len(),
        1,
        "restart retry must not materialize a second proof Event"
    );
}

#[tokio::test]
async fn postgres_queue_refuses_a_second_envelope_under_one_event_id() {
    use coland_storage::{
        EventBatchCommitRequest, EventCommitUnitOfWork, EventStore, PersistenceError,
    };

    let database = coland_storage_postgres::test_database::TestDatabase::lease().await;
    let pool = database.pool();
    let _db_guard = DB_GUARD.lock().await;
    let discussion = ordinary_realm::open_discussion(
        &pool,
        &format!("event-id-collision:{}", uuid::Uuid::now_v7()),
    )
    .await;
    let created_at =
        chrono::DateTime::from_timestamp_micros(chrono::Utc::now().timestamp_micros()).unwrap();
    let batch = |event| EventBatchCommitRequest {
        audit_unit: None,
        events: vec![event],
        realm_organization_proof: None,
        invite_claim_proof: None,
        event_approvals: None,
        franking_replay_nonce: None,
        applet_record: None,
        applet_authoring_preview: None,
        agent_membership_cascade: None,
    };

    let admitted = discussion.message_after(
        &discussion.head.authority_commit,
        "collision fixture",
        created_at,
    );
    let event_id = admitted.event.event_id.clone();
    let admitted_envelope = serde_json::to_value(&admitted.authority_commit.event).unwrap();
    PgEventCommitUnitOfWork::new(pool.clone())
        .commit_event_batch(batch(admitted.clone()))
        .await
        .unwrap();

    // An Event id commits to the digest payload, which excludes proofs, so a
    // second element can carry the same id under a different envelope. The
    // queued row is the one durable body for that id: the adapter must refuse
    // the second envelope as a hash collision instead of replacing it.
    let mut rebound =
        discussion.message_after(&admitted.authority_commit, "collision fixture", created_at);
    assert_eq!(
        rebound.event.event_id, event_id,
        "a different proof set must not change the content-bound Event id"
    );
    rebound
        .authority_commit
        .event
        .producer_proof
        .as_mut()
        .expect("producer proof")
        .verification_method = arkret_wire::DidUrl::new(format!(
        "{}#rebound-device",
        fixture_did(&ordinary_realm::founder())
    ))
    .unwrap();
    rebound.event.envelope = serde_json::to_value(&rebound.authority_commit.event).unwrap();
    assert_ne!(rebound.event.envelope, admitted_envelope);
    let collision = PgEventCommitUnitOfWork::new(pool.clone())
        .commit_event_batch(batch(rebound))
        .await
        .unwrap_err();
    assert!(
        matches!(collision, PersistenceError::Conflict(ref reason) if reason == "event_hash_collision"),
        "unexpected error for a reused Event id: {collision:?}"
    );

    let stored = PgEventStore { pool: pool.clone() }
        .get(&event_id)
        .await
        .unwrap()
        .expect("the admitted Event stays readable after the refusal");
    assert_eq!(
        stored.envelope, admitted_envelope,
        "the refused envelope must not overwrite the admitted one"
    );
}

#[tokio::test]
async fn postgres_agent_store_accepts_spec_agent_binding() {
    let database = coland_storage_postgres::test_database::TestDatabase::lease().await;
    let pool = database.pool();
    let _db_guard = DB_GUARD.lock().await;
    let store = PgAgentStore { pool: pool.clone() };
    let suffix = uuid::Uuid::now_v7().simple().to_string();
    let scid = format!("zTest{suffix}");
    let agent_id = format!("ak:did_core:webvh:{scid}");
    let did = format!("did:webvh:{scid}:agent.example");
    let now = chrono::DateTime::from_timestamp_micros(chrono::Utc::now().timestamp_micros())
        .expect("timestamp round-trip");
    let record = AgentPrincipalRecord::new(
        agent_id.clone(),
        "ak:did_core:web:controller.example".to_owned(),
        event_derived_realm_id(agent_id.as_bytes()),
        arkret_wire::DidUrl::new(format!("{did}#managed-controller")).unwrap(),
        arkret_models_collaboration::agent_operations::AgentLifecycleState::Active,
        now,
    );

    store
        .put(record.clone())
        .await
        .expect("spec-valid Agent binding must persist");
    assert_eq!(store.get(&agent_id).await.unwrap(), Some(record));

    use diesel::sql_types::Text;
    use diesel_async::RunQueryDsl;
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query("DELETE FROM agent_principals WHERE id = $1")
        .bind::<Text, _>(&agent_id)
        .execute(&mut *conn)
        .await
        .unwrap();
}

#[tokio::test]
async fn postgres_agent_table_rejects_mismatched_did_and_core_agent_ids() {
    let database = coland_storage_postgres::test_database::TestDatabase::lease().await;
    let pool = database.pool();
    let _db_guard = DB_GUARD.lock().await;
    let suffix = uuid::Uuid::now_v7().simple().to_string();
    let agent_id = format!("ak:did_core:webvh:zLeft{suffix}");
    let authorization_ref = format!("did:webvh:zRight{suffix}:agent.example#managed-controller");
    let realm_id = event_derived_realm_id(agent_id.as_bytes());
    let now = chrono::DateTime::from_timestamp_micros(chrono::Utc::now().timestamp_micros())
        .expect("timestamp round-trip");

    use diesel::sql_types::{Text, Timestamptz};
    use diesel_async::RunQueryDsl;
    let mut conn = pool.get().await.unwrap();
    let error = diesel::sql_query(
        "INSERT INTO agent_principals \
         (id, controller_principal_id, principal_control_realm_id, controller_authorization_ref, \
          created_at, updated_at) \
         VALUES ($1, $2, $3, $4, $5, $5)",
    )
    .bind::<Text, _>(&agent_id)
    .bind::<Text, _>("ak:did_core:web:controller.example")
    .bind::<Text, _>(&realm_id)
    .bind::<Text, _>(&authorization_ref)
    .bind::<Timestamptz, _>(now)
    .execute(&mut *conn)
    .await
    .expect_err("database must reject a DID that projects to a different Agent core id");
    assert!(
        error
            .to_string()
            .contains("agent_principals_controller_authorization_ref_check"),
        "{error}"
    );
}

fn event_derived_realm_id(seed: &[u8]) -> String {
    let event_id = arkret_identifiers::EventId::from_digest(
        arkret_canonical::DigestSuite::Sha256,
        arkret_canonical::sha256_bytes(seed),
    );
    arkret_identifiers::RealmId::from_event_id(&event_id).to_string()
}

#[tokio::test]
async fn postgres_adapter_satisfies_shared_idempotency_contract() {
    let database = coland_storage_postgres::test_database::TestDatabase::lease().await;
    let pool = database.pool();
    let _db_guard = DB_GUARD.lock().await;
    let store = PgIdempotencyStore { pool };
    let namespace = format!("postgres-contract-{}", uuid::Uuid::now_v7());
    assert_idempotency_store_contract(&store, &namespace).await;
}

#[tokio::test]
async fn postgres_account_notification_upsert_and_remove_stream_as_typed_deltas() {
    use diesel::{QueryableByName, sql_query};
    use diesel_async::RunQueryDsl;

    #[derive(QueryableByName)]
    struct AccountNotificationStorageRow {
        #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Text>)]
        notification_kind: Option<String>,
        #[diesel(sql_type = diesel::sql_types::Text)]
        projection_action: String,
        #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Jsonb>)]
        projection_data: Option<serde_json::Value>,
    }

    let database = coland_storage_postgres::test_database::TestDatabase::lease().await;
    let pool = database.pool();
    let _db_guard = DB_GUARD.lock().await;
    let store = PgNotificationStore { pool: pool.clone() };
    let run_id = uuid::Uuid::now_v7();
    let notification_uuid = uuid::Uuid::now_v7();
    let notification_id =
        arkret_wire::NotificationId::new(format!("ak:notification:{notification_uuid}")).unwrap();
    let controller_account_pk = coland_storage::AccountPk(1);
    let recipient_actor_id = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        arkret_wire::DidCoreId::new(format!("ak:did_core:web:notification-{run_id}.example"))
            .unwrap(),
        arkret_wire::DidCoreId::new("ak:did_core:web:principal.example").unwrap(),
    ));
    let recipient_id =
        arkret_wire::DidCoreId::new(format!("ak:did_core:web:controller-{run_id}.example"))
            .unwrap();
    let artifact_id = format!("agent_runtime_approval:{run_id}");
    // The approval correlation id is its own newtype: the frame schema forbids
    // the `ak:` namespace on it, so it is not an opaque local id.
    let approval_request_id =
        arkret_models_collaboration::account_subscribe_projections::AgentRuntimeApprovalRequestId::new(
            artifact_id.clone(),
        )
        .unwrap();
    let agent_id =
        arkret_wire::DidCoreId::new(format!("ak:did_core:web:agent-{run_id}.example")).unwrap();
    let timestamp = |value: &str| {
        chrono::DateTime::parse_from_rfc3339(value)
            .unwrap()
            .with_timezone(&chrono::Utc)
    };

    let upsert = |expires_at: &str| {
        arkret_models_collaboration::sync_frames::account_subscribe::NotificationDelta::try_new(
            arkret_models_collaboration::objects::read_receipts::NotificationIdentity::AgentApproval(
                notification_id.clone(),
            ),
            arkret_models_collaboration::sync_frames::account_subscribe::NotificationDeltaAction::Upsert,
            Some(
                arkret_models_collaboration::sync_frames::account_subscribe::NotificationData::AgentRuntimeApproval(
                    arkret_models_collaboration::account_subscribe_projections::AgentRuntimeApprovalNotificationData {
                        approval_request_id: approval_request_id.clone(),
                        agent_id: agent_id.clone(),
                        requested_at: timestamp("2026-08-26T10:00:00.000Z"),
                        expires_at: timestamp(expires_at),
                    },
                ),
            ),
        )
        .unwrap()
    };
    let write = |delta| AccountNotificationDeltaWrite {
        delta,
        recipient_actor_id: recipient_actor_id.clone(),
        controller_account_pk,
        recipient_id: recipient_id.clone(),
        source_account_artifact_id: artifact_id.clone(),
    };

    store
        .put_account_delta(write(upsert("2026-08-26T10:15:00.000Z")))
        .await
        .unwrap();
    let inserted = store
        .list_for_account(&controller_account_pk, recipient_id.as_str(), None)
        .await
        .unwrap();
    assert_eq!(inserted.len(), 1);
    assert_eq!(
        inserted[0].record.delta.action,
        arkret_models_collaboration::sync_frames::account_subscribe::NotificationDeltaAction::Upsert
    );
    assert!(
        store
            .list_for_recipient(recipient_id.as_str())
            .await
            .unwrap()
            .is_empty(),
        "account-private deltas must not enter the generic Event notification projection"
    );
    let mut conn = pool.get().await.unwrap();
    let stored = sql_query(
        "SELECT notification_kind, projection_action, projection_data \
         FROM notifications WHERE id = $1",
    )
    .bind::<diesel::sql_types::Uuid, _>(notification_uuid)
    .get_result::<AccountNotificationStorageRow>(&mut *conn)
    .await
    .unwrap();
    assert!(stored.notification_kind.is_none());
    assert_eq!(stored.projection_action, "upsert");
    assert!(
        stored
            .projection_data
            .as_ref()
            .is_some_and(|data| data.get("kind").is_none())
    );
    drop(conn);
    let inserted_position = inserted[0].projection_position;

    store
        .put_account_delta(write(upsert("2026-08-26T10:20:00.000Z")))
        .await
        .unwrap();
    let updated = store
        .list_for_account(
            &controller_account_pk,
            recipient_id.as_str(),
            Some(inserted_position),
        )
        .await
        .unwrap();
    assert_eq!(updated.len(), 1);
    assert!(updated[0].projection_position > inserted_position);
    assert_eq!(
        updated[0]
            .record
            .delta
            .agent_runtime_approval()
            .unwrap()
            .expires_at,
        timestamp("2026-08-26T10:20:00.000Z")
    );
    let updated_position = updated[0].projection_position;

    let removal =
        arkret_models_collaboration::sync_frames::account_subscribe::NotificationDelta::try_new(
            arkret_models_collaboration::objects::read_receipts::NotificationIdentity::AgentApproval(
                notification_id,
            ),
            arkret_models_collaboration::sync_frames::account_subscribe::NotificationDeltaAction::Remove,
            Some(
                arkret_models_collaboration::sync_frames::account_subscribe::NotificationData::AgentRuntimeApprovalRemoval(
                    arkret_models_collaboration::sync_frames::account_subscribe::AgentRuntimeApprovalNotificationRemovalData {
                        reason: arkret_models_collaboration::sync_frames::account_subscribe::AgentRuntimeApprovalRemovalReason::Approved,
                    },
                ),
            ),
        )
        .unwrap();
    store.put_account_delta(write(removal)).await.unwrap();
    let removed = store
        .list_for_account(
            &controller_account_pk,
            recipient_id.as_str(),
            Some(updated_position),
        )
        .await
        .unwrap();
    assert_eq!(removed.len(), 1);
    assert_eq!(
        removed[0].record.delta.action,
        arkret_models_collaboration::sync_frames::account_subscribe::NotificationDeltaAction::Remove
    );
    assert!(removed[0].record.delta.agent_runtime_approval().is_none());
}

#[tokio::test]
async fn postgres_agent_approval_trigger_emits_a_readable_account_notification() {
    use diesel::{QueryableByName, sql_query, sql_types};
    use diesel_async::RunQueryDsl;

    #[derive(QueryableByName)]
    struct AccountRow {
        #[diesel(sql_type = sql_types::BigInt)]
        pk: i64,
    }

    #[derive(QueryableByName)]
    struct ActorKeyRow {
        #[diesel(sql_type = sql_types::Text)]
        actor_key: String,
    }

    let database = coland_storage_postgres::test_database::TestDatabase::lease().await;
    let pool = database.pool();
    let _db_guard = DB_GUARD.lock().await;
    let suffix = uuid::Uuid::now_v7().simple().to_string();
    let station_id = format!("ak:did_core:webvh:Qs{suffix}");
    let controller_id = format!("ak:did_core:webvh:Qc{suffix}");
    let agent_scid = format!("Qa{suffix}");
    let agent_id = format!("ak:did_core:webvh:{agent_scid}");
    let realm_id = event_derived_realm_id(suffix.as_bytes());
    let approval_request_id = format!("agent_runtime_approval:{}", uuid::Uuid::now_v7());
    let approval_notification_id = uuid::Uuid::now_v7();
    let controller_authorization_ref =
        format!("did:webvh:{agent_scid}:station.example#managed-controller");
    let mut conn = pool.get().await.unwrap();
    let account =
        sql_query("INSERT INTO accounts(principal_id, station_id) VALUES($1, $2) RETURNING pk")
            .bind::<sql_types::Text, _>(&controller_id)
            .bind::<sql_types::Text, _>(&station_id)
            .get_result::<AccountRow>(&mut *conn)
            .await
            .unwrap();
    sql_query(
        "INSERT INTO agent_principals(
            id, controller_principal_id, principal_control_realm_id,
            controller_authorization_ref, controller_account_pk, recipient_id,
            approval_request_id, approval_notification_id,
            approval_requested_at, pairing_expires_at, created_at, updated_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8,
                  NOW(), NOW() + INTERVAL '15 minutes', NOW(), NOW())",
    )
    .bind::<sql_types::Text, _>(&agent_id)
    .bind::<sql_types::Text, _>(&controller_id)
    .bind::<sql_types::Text, _>(&realm_id)
    .bind::<sql_types::Text, _>(&controller_authorization_ref)
    .bind::<sql_types::BigInt, _>(account.pk)
    .bind::<sql_types::Text, _>(&station_id)
    .bind::<sql_types::Text, _>(&approval_request_id)
    .bind::<sql_types::Uuid, _>(approval_notification_id)
    .execute(&mut *conn)
    .await
    .unwrap();
    drop(conn);

    let account_actor = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        arkret_wire::DidCoreId::new(controller_id.clone()).unwrap(),
        arkret_wire::DidCoreId::new(station_id.clone()).unwrap(),
    ));
    let expected_actor_key = account_actor.to_string();
    let mut conn = pool.get().await.unwrap();
    let notification_key =
        sql_query("SELECT recipient_actor_id AS actor_key FROM notifications WHERE id = $1")
            .bind::<sql_types::Uuid, _>(approval_notification_id)
            .get_result::<ActorKeyRow>(&mut *conn)
            .await
            .unwrap();
    assert_eq!(notification_key.actor_key, expected_actor_key);
    let current_key = sql_query(
        "SELECT actor_key FROM account_global_versions \
         WHERE actor_key = $1 AND channel = 'notifications' AND item_key = $2",
    )
    .bind::<sql_types::Text, _>(&expected_actor_key)
    .bind::<sql_types::Text, _>(approval_notification_id.to_string())
    .get_result::<ActorKeyRow>(&mut *conn)
    .await
    .unwrap();
    assert_eq!(current_key.actor_key, expected_actor_key);
    let sync = PgSyncCursorStore { pool: pool.clone() };
    let watermark = sync.account_global_watermark().await.unwrap();
    let current_payload = sync
        .account_global_page(
            &expected_actor_key,
            "notifications",
            watermark,
            "",
            None,
            10,
        )
        .await
        .unwrap()
        .into_iter()
        .find(|row| row.item_key == approval_notification_id.to_string())
        .unwrap();
    let upsert: arkret_models_collaboration::sync_frames::account_subscribe::NotificationDelta =
        serde_json::from_value(current_payload.payload).unwrap();
    assert!(upsert.agent_runtime_approval().is_some());
    drop(conn);

    // Authorization can clear the pending timestamp before clearing the
    // request id. That intermediate row must not replace the readable upsert
    // with an Agent approval payload containing a null requested_at.
    let mut conn = pool.get().await.unwrap();
    sql_query("UPDATE agent_principals SET approval_requested_at = NULL, updated_at = NOW() WHERE id = $1")
        .bind::<sql_types::Text, _>(&agent_id)
        .execute(&mut *conn)
        .await
        .unwrap();
    drop(conn);
    let watermark = sync.account_global_watermark().await.unwrap();
    let pending_payload = sync
        .account_global_page(
            &expected_actor_key,
            "notifications",
            watermark,
            "",
            None,
            10,
        )
        .await
        .unwrap()
        .into_iter()
        .find(|row| row.item_key == approval_notification_id.to_string())
        .unwrap();
    let pending: arkret_models_collaboration::sync_frames::account_subscribe::NotificationDelta =
        serde_json::from_value(pending_payload.payload).unwrap();
    assert!(pending.agent_runtime_approval().is_some());

    let authorize_event_ref = arkret_identifiers::EventId::from_digest(
        arkret_canonical::DigestSuite::Sha256,
        arkret_canonical::sha256_bytes(suffix.as_bytes()),
    )
    .to_string();
    let pairing_request_id = format!("agent_pairing_request:{}", uuid::Uuid::now_v7());
    let request_digest = format!("sha256:{}", "a".repeat(64));
    let runtime_key_binding_digest = format!("sha256:{}", "c".repeat(64));
    let scope_custody_ref = coland_storage::AgentScopeCustodyRef {
        key_ref: format!("scope-custody:{suffix}"),
        content_digest: arkret_wire::Hash::new(format!("sha256:{}", "d".repeat(64))).unwrap(),
    };
    let mut conn = pool.get().await.unwrap();
    sql_query(
        "INSERT INTO agent_pairing_receipts(
            authorize_event_ref, agent_id, controller_principal_id, pairing_request_id,
            request_digest, approval_request_id, runtime_key_binding_digest, raw_key_digest,
            expires_at, activation_state, scope_custody_ref
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW() + INTERVAL '15 minutes', 'active', $9)",
    )
    .bind::<sql_types::Text, _>(&authorize_event_ref)
    .bind::<sql_types::Text, _>(&agent_id)
    .bind::<sql_types::Text, _>(&controller_id)
    .bind::<sql_types::Text, _>(&pairing_request_id)
    .bind::<sql_types::Text, _>(&request_digest)
    .bind::<sql_types::Text, _>(&approval_request_id)
    .bind::<sql_types::Text, _>(&runtime_key_binding_digest)
    .bind::<sql_types::Text, _>(format!("sha256:{}", "b".repeat(64)))
    .bind::<sql_types::Jsonb, _>(serde_json::to_value(&scope_custody_ref).unwrap())
    .execute(&mut *conn)
    .await
    .unwrap();
    drop(conn);
    let receipt = PgAgentStore { pool: pool.clone() }
        .pairing_receipt(&authorize_event_ref)
        .await
        .unwrap()
        .expect("durable Agent pairing receipt");
    assert_eq!(receipt.authorize_event_ref, authorize_event_ref);
    assert_eq!(receipt.agent_id, agent_id);
    assert_eq!(receipt.controller_principal_id, controller_id);
    assert_eq!(receipt.pairing_request_id.as_str(), pairing_request_id);
    assert_eq!(receipt.request_digest, request_digest);
    assert_eq!(receipt.approval_request_id.as_str(), approval_request_id);
    assert_eq!(
        receipt.runtime_key_binding_digest,
        runtime_key_binding_digest
    );
    assert_eq!(receipt.scope_custody_ref, Some(scope_custody_ref));
    assert_eq!(
        receipt.outcome.authorize_event_ref.as_str(),
        authorize_event_ref
    );
    assert_eq!(
        receipt.outcome.activation_state,
        arkret_models_collaboration::agent_operations::AgentKeyPairActivationState::Active
    );

    let rows = PgNotificationStore { pool: pool.clone() }
        .list_for_account(&coland_storage::AccountPk(account.pk), &station_id, None)
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].record.recipient_actor_id, account_actor);
    let data = rows[0]
        .record
        .delta
        .agent_runtime_approval()
        .expect("typed Agent approval notification");
    assert_eq!(data.approval_request_id.as_str(), approval_request_id);
    assert_eq!(data.agent_id.as_str(), agent_id);

    let mut conn = pool.get().await.unwrap();
    sql_query(
        "UPDATE agent_principals SET approval_request_id = NULL, updated_at = NOW() WHERE id = $1",
    )
    .bind::<sql_types::Text, _>(&agent_id)
    .execute(&mut *conn)
    .await
    .unwrap();
    drop(conn);
    let removed = PgNotificationStore { pool: pool.clone() }
        .list_for_account(&coland_storage::AccountPk(account.pk), &station_id, None)
        .await
        .unwrap();
    assert_eq!(removed.len(), 1);
    assert_eq!(
        removed[0].record.delta.agent_runtime_approval_removal_reason(),
        Some(arkret_models_collaboration::sync_frames::account_subscribe::AgentRuntimeApprovalRemovalReason::Superseded)
    );
    let watermark = sync.account_global_watermark().await.unwrap();
    let removed_payload = sync
        .account_global_page(
            &expected_actor_key,
            "notifications",
            watermark,
            "",
            None,
            10,
        )
        .await
        .unwrap()
        .into_iter()
        .find(|row| row.item_key == approval_notification_id.to_string())
        .unwrap();
    let removal: arkret_models_collaboration::sync_frames::account_subscribe::NotificationDelta =
        serde_json::from_value(removed_payload.payload).unwrap();
    assert_eq!(
        removal.agent_runtime_approval_removal_reason(),
        Some(arkret_models_collaboration::sync_frames::account_subscribe::AgentRuntimeApprovalRemovalReason::Superseded)
    );
}

#[tokio::test]
async fn postgres_adapter_satisfies_mimi_consent_correlation_contract() {
    let database = coland_storage_postgres::test_database::TestDatabase::lease().await;
    let pool = database.pool();
    let _db_guard = DB_GUARD.lock().await;
    let store = PgMimiConsentCorrelationStore { pool };
    let namespace = format!("postgres-mimi-consent-{}", uuid::Uuid::now_v7());
    assert_mimi_consent_correlation_store_contract(&store, &namespace).await;
}

#[tokio::test]
async fn postgres_adapter_atomically_admits_authority_events() {
    let database = coland_storage_postgres::test_database::TestDatabase::lease().await;
    let pool = database.pool();
    let _db_guard = DB_GUARD.lock().await;
    let authority = PgAuthorityCommitStore { pool };
    let namespace = format!("postgres-atomic-admission-{}", uuid::Uuid::now_v7());
    assert_atomic_event_admission_contract(&authority, &namespace).await;
}

#[tokio::test]
async fn postgres_local_current_member_read_requires_matching_authority_and_commit() {
    use diesel::sql_types::{BigInt, Binary, Jsonb, SmallInt, Text, Timestamptz};
    use diesel_async::RunQueryDsl;

    let database = coland_storage_postgres::test_database::TestDatabase::lease().await;
    let pool = database.pool();
    let _db_guard = DB_GUARD.lock().await;
    let namespace = format!("local-current-member:{}", uuid::Uuid::now_v7());
    let realm_id = arkret_identifiers::RealmId::new(event_derived_realm_id(namespace.as_bytes()))
        .expect("fixture Realm id");
    let other_realm = arkret_identifiers::RealmId::new(event_derived_realm_id(
        format!("{namespace}:other").as_bytes(),
    ))
    .expect("other fixture Realm id");
    let station = arkret_wire::DidCoreId::new("ak:did_core:web:member-station.example").unwrap();
    let wrong_station =
        arkret_wire::DidCoreId::new("ak:did_core:web:other-member-station.example").unwrap();
    let member = arkret_wire::ActorId::service(
        arkret_wire::DidCoreId::new("ak:did_core:web:member-reader.example").unwrap(),
    );
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    FixtureCommitStream::new(&realm_id, &station)
        .install(&pool)
        .await;
    FixtureCommitStream::new(&other_realm, &station)
        .install(&pool)
        .await;

    let event_digest = arkret_canonical::sha256_bytes(namespace.as_bytes());
    let mut event_id = vec![1_u8];
    event_id.extend_from_slice(&event_digest);
    let commit_id = arkret_wire::RealmCommitId::from_digest(arkret_canonical::sha256_bytes(
        format!("{namespace}:commit").as_bytes(),
    ));
    let now = chrono::Utc::now();
    let stream_ref = serde_json::json!({"kind":"realm","realm_id":realm_id});
    let mut conn = pool.get().await.unwrap();
    let event_pk: i64 = {
        #[derive(diesel::QueryableByName)]
        struct EventPk {
            #[diesel(sql_type = BigInt)]
            pk: i64,
        }
        diesel::sql_query(
            "INSERT INTO canonical_events \
             (id,digest_suite,digest,actor_id,realm_id,scope_ref,kind,canonical_bytes,envelope,state,committed_at) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,'committed',$10) RETURNING pk",
        )
        .bind::<Binary, _>(&event_id)
        .bind::<SmallInt, _>(1_i16)
        .bind::<Binary, _>(event_digest.to_vec())
        .bind::<Text, _>(member.to_string())
        .bind::<Text, _>(realm_id.as_str())
        .bind::<Jsonb, _>(&stream_ref)
        .bind::<Text, _>("ak.member.state")
        .bind::<Binary, _>(b"fixture-current-member".to_vec())
        .bind::<Jsonb, _>(serde_json::json!({}))
        .bind::<Timestamptz, _>(now)
        .get_result::<EventPk>(&mut *conn)
        .await
        .unwrap()
        .pk
    };
    diesel::sql_query(
        "INSERT INTO realm_commits \
         (commit_id,realm_id,stream_key,stream_ref,stream_position,event_pk,governance_generation,commit_json,committed_at) \
         VALUES ($1,$2,$3,$4,0,$5,0,$6,$7)",
    )
    .bind::<Text, _>(commit_id.as_str())
    .bind::<Text, _>(realm_id.as_str())
    .bind::<Text, _>(format!("realm:{}", realm_id.as_str()))
    .bind::<Jsonb, _>(&stream_ref)
    .bind::<BigInt, _>(event_pk)
    .bind::<Jsonb, _>(serde_json::json!({}))
    .bind::<Timestamptz, _>(now)
    .execute(&mut *conn)
    .await
    .unwrap();
    diesel::sql_query(
        "INSERT INTO member_state_current_results \
         (realm_id,member_id,membership,current_commit_id,current_stream_position,value,updated_at) \
         VALUES ($1,$2,'join',$3,0,$4,$5)",
    )
    .bind::<Text, _>(realm_id.as_str())
    .bind::<Text, _>(member.to_string())
    .bind::<Text, _>(commit_id.as_str())
    .bind::<Jsonb, _>(serde_json::json!({"membership":"join"}))
    .bind::<Timestamptz, _>(now)
    .execute(&mut *conn)
    .await
    .unwrap();
    drop(conn);
    assert!(
        store
            .local_current_member_joined(&realm_id, &member, &station)
            .await
            .unwrap()
    );
    assert!(
        !store
            .local_current_member_joined(&realm_id, &member, &wrong_station)
            .await
            .unwrap()
    );
    assert!(
        !store
            .local_current_member_joined(&other_realm, &member, &station)
            .await
            .unwrap()
    );

    let mut conn = pool.get().await.unwrap();
    diesel::sql_query(
        "UPDATE member_state_current_results SET current_stream_position=1 \
         WHERE realm_id=$1 AND member_id=$2",
    )
    .bind::<Text, _>(realm_id.as_str())
    .bind::<Text, _>(member.to_string())
    .execute(&mut *conn)
    .await
    .unwrap();
    drop(conn);
    assert!(
        !store
            .local_current_member_joined(&realm_id, &member, &station)
            .await
            .unwrap()
    );
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query(
        "UPDATE member_state_current_results SET current_stream_position=0, \
         membership='leave',value=$3 WHERE realm_id=$1 AND member_id=$2",
    )
    .bind::<Text, _>(realm_id.as_str())
    .bind::<Text, _>(member.to_string())
    .bind::<Jsonb, _>(serde_json::json!({"membership":"leave"}))
    .execute(&mut *conn)
    .await
    .unwrap();
    drop(conn);
    assert!(
        !store
            .local_current_member_joined(&realm_id, &member, &station)
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn postgres_adapter_satisfies_shared_event_commit_contract() {
    let database = coland_storage_postgres::test_database::TestDatabase::lease().await;
    let pool = database.pool();
    let _db_guard = DB_GUARD.lock().await;
    let unit_of_work = PgEventCommitUnitOfWork::new(pool.clone());
    let authority = PgAuthorityCommitStore { pool: pool.clone() };
    let events = PgEventStore { pool: pool.clone() };
    let projections = PgProjectionEventStore { pool: pool.clone() };
    let idempotency = PgIdempotencyStore { pool: pool.clone() };
    let outbox = PgFederationOutboxStore { pool: pool.clone() };
    let contacts = PgContactStore { pool: pool.clone() };
    let invite_policies = PgInviteReceivePolicyStore { pool: pool.clone() };
    let namespace = format!("postgres-event-commit-{}", uuid::Uuid::now_v7());
    let discussion = ordinary_realm::open_discussion(&pool, &namespace).await;
    let at = discussion.committed_at();
    let accepted = discussion.message_after(&discussion.head.authority_commit, "accepted", at);
    let rollback = discussion.message_after(&accepted.authority_commit, "rolled back", at);
    assert_event_commit_unit_of_work_contract(
        EventCommitContractStores {
            unit_of_work: &unit_of_work,
            authority: &authority,
            events: &events,
            projections: &projections,
            idempotency: &idempotency,
            outbox: &outbox,
            contacts: &contacts,
            invite_policies: &invite_policies,
        },
        EventCommitContractMessages { accepted, rollback },
        &namespace,
    )
    .await;
}

#[tokio::test]
async fn postgres_adapter_satisfies_formal_applet_commit_transaction_contract() {
    let database = coland_storage_postgres::test_database::TestDatabase::lease().await;
    let pool = database.pool();
    let _db_guard = DB_GUARD.lock().await;
    let unit_of_work = PgEventCommitUnitOfWork::new(pool.clone());
    let authority = PgAuthorityCommitStore { pool: pool.clone() };
    let events = PgEventStore { pool: pool.clone() };
    let factory = Box::pin(applet_authoring::AppletAuthoringFactory::new(pool.clone())).await;
    let applets = PgAppletStore { pool };
    let namespace = format!("postgres-formal-applet-{}", uuid::Uuid::now_v7().simple());
    assert_applet_formal_commit_transaction_contract(
        AppletFormalCommitContractStores {
            unit_of_work: &unit_of_work,
            authority: &authority,
            events: &events,
            applets: &applets,
            factory: &factory,
        },
        &namespace,
    )
    .await;
}

#[tokio::test]
async fn postgres_applet_authoring_preview_has_one_durable_exact_winner() {
    let database = coland_storage_postgres::test_database::TestDatabase::lease().await;
    let pool = database.pool();
    let _db_guard = DB_GUARD.lock().await;
    let store = PgAppletStore { pool };
    let subject_key = format!("applet-preview:{}", uuid::Uuid::now_v7());
    let now = chrono::Utc::now();
    let candidate = |basis: &str, request: &str, issued_at: chrono::DateTime<chrono::Utc>| {
        AppletAuthoringPreviewRecord {
            subject_key: subject_key.clone(),
            basis_digest: basis.to_owned(),
            request_digest: request.to_owned(),
            signed_request: serde_json::json!({"request": request}),
            issued_at,
            expires_at: issued_at + chrono::Duration::minutes(5),
        }
    };
    let first = candidate("basis-a", "request-a", now);
    assert_eq!(
        store
            .issue_authoring_preview(first.clone())
            .await
            .unwrap()
            .signed_request,
        first.signed_request
    );
    assert_eq!(
        store
            .issue_authoring_preview(candidate(
                "basis-a",
                "request-a-new-signature",
                now + chrono::Duration::seconds(1),
            ))
            .await
            .unwrap()
            .request_digest,
        "request-a"
    );
    assert_eq!(
        store
            .issue_authoring_preview(candidate(
                "basis-b",
                "request-b",
                now + chrono::Duration::seconds(2),
            ))
            .await
            .unwrap()
            .request_digest,
        "request-b"
    );
    assert_eq!(
        store
            .issue_authoring_preview(candidate(
                "basis-b",
                "request-b-reissued",
                now + chrono::Duration::minutes(7),
            ))
            .await
            .unwrap()
            .request_digest,
        "request-b-reissued"
    );
    assert_eq!(
        store
            .current_authoring_preview(&subject_key)
            .await
            .unwrap()
            .unwrap()
            .request_digest,
        "request-b-reissued"
    );
}

#[tokio::test]
async fn postgres_adapter_satisfies_shared_federation_outbox_contract() {
    let database = coland_storage_postgres::test_database::TestDatabase::lease().await;
    let pool = database.pool();
    let _db_guard = DB_GUARD.lock().await;
    let store = PgFederationOutboxStore { pool };
    let namespace = format!("postgres-federation-outbox-{}", uuid::Uuid::now_v7());
    assert_federation_outbox_store_contract(&store, &namespace).await;
}

#[tokio::test]
async fn postgres_adapter_satisfies_mls_keypackage_retirement_contract() {
    let database = coland_storage_postgres::test_database::TestDatabase::lease().await;
    let pool = database.pool();
    let _db_guard = DB_GUARD.lock().await;
    let namespace = format!("postgres-retirement-{}", uuid::Uuid::now_v7());
    let store = PgMlsKeyPackageStore { pool: pool.clone() };
    let accounts = coland_storage_postgres::PgAccountStore { pool: pool.clone() };
    let device = confirmed_contract_device(&pool).await;
    assert_mls_keypackage_retirement_contract(&store, &accounts, &namespace, &device).await;

    let restarted_store = PgMlsKeyPackageStore { pool };
    let retired_id = format!("{namespace}-keypackage-published");
    let replayed = restarted_store
        .get(&retired_id)
        .await
        .expect("reload retired KeyPackage after store restart")
        .expect("retired KeyPackage survives store restart");
    assert_eq!(replayed.claimed_by_mls_group_id.as_deref(), Some("retired"));
}

#[tokio::test]
async fn postgres_adapter_satisfies_last_resort_claim_ledger_contract() {
    let database = coland_storage_postgres::test_database::TestDatabase::lease().await;
    let pool = database.pool();
    let _db_guard = DB_GUARD.lock().await;
    let namespace = format!("postgres-last-resort-{}", uuid::Uuid::now_v7());
    let store = PgMlsKeyPackageStore { pool: pool.clone() };
    let accounts = coland_storage_postgres::PgAccountStore { pool: pool.clone() };
    let device = confirmed_contract_device(&pool).await;
    assert_last_resort_claim_ledger_contract(&store, &accounts, &namespace, &device).await;

    let restarted_store = PgMlsKeyPackageStore { pool };
    let claim_request_id = format!("local-last-resort:{namespace}-01");
    let replayed = restarted_store
        .get_peer_claim(
            &format!("ak:did_core:web:{namespace}.example"),
            &claim_request_id,
        )
        .await
        .expect("reload last-resort ledger after store restart")
        .expect("last-resort ledger survives store restart");
    assert_eq!(replayed.claim_request_id, claim_request_id);
    assert_eq!(replayed.state, "consumed");
    assert_eq!(
        replayed.consume_receipt,
        Some(serde_json::json!({"receipt": "first-writer"}))
    );
    let expired = restarted_store
        .get_peer_claim(
            &format!("ak:did_core:web:{namespace}.example"),
            &format!("local-last-resort:{namespace}-02"),
        )
        .await
        .expect("reload expired last-resort ledger after store restart")
        .expect("expired last-resort ledger survives store restart");
    assert_eq!(expired.state, "expired");
    assert!(expired.outcome.is_some());
    assert!(expired.consume_receipt.is_none());

    let delayed = restarted_store
        .get_peer_claim(
            &format!("ak:did_core:web:{namespace}.example"),
            &format!("local-last-resort:{namespace}-03"),
        )
        .await
        .expect("reload delayed consumed source mirror after restart")
        .expect("delayed consumed source mirror survives restart");
    assert_eq!(delayed.state, "consumed");
    assert_eq!(delayed.key_package_use, "last_resort");
    assert_eq!(
        delayed.consume_receipt,
        Some(serde_json::json!({"receipt": "signed-before-deadline"}))
    );

    let terminal = restarted_store
        .get_peer_claim(
            &format!("ak:did_core:web:{namespace}.example"),
            &format!("local-last-resort:{namespace}-04"),
        )
        .await
        .expect("reload terminal source mirror after restart")
        .expect("terminal source mirror survives restart");
    assert_eq!(terminal.state, "revoked");
    assert_eq!(terminal.key_package_use, "last_resort");
    assert_eq!(
        terminal.terminal_receipt,
        Some(serde_json::json!({"receipt": "terminal"}))
    );
    assert!(
        restarted_store
            .get_peer_claim(
                &format!("ak:did_core:web:{namespace}.example"),
                &format!("local-last-resort:{namespace}-05"),
            )
            .await
            .expect("check rejected fractional-deadline claim")
            .is_none()
    );

    let concurrent = PeerKeyPackageClaimLedgerRecord {
        source_id: format!("ak:did_core:web:{namespace}.example"),
        claim_request_id: format!("local-last-resort:{namespace}-concurrent"),
        request_digest: "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
            .to_owned(),
        key_package_use: "last_resort".to_owned(),
        state: "last_resort_claimed".to_owned(),
        outcome: Some(serde_json::json!({"response": {"claims": ["concurrent"]}})),
        consume_receipt: None,
        terminal_receipt: None,
        keypackage_id: Some(format!("{namespace}-keypackage-last-resort")),
        claim_expires_at_unix_ms: Some(20_000),
        expires_at: i64::MAX,
        updated_at: 10,
    };
    let first_writer = PgMlsKeyPackageStore {
        pool: restarted_store.pool.clone(),
    };
    let second_writer = PgMlsKeyPackageStore {
        pool: restarted_store.pool.clone(),
    };
    let (first_result, second_result) = tokio::join!(
        first_writer.record_peer_claim_terminal(&concurrent),
        second_writer.record_peer_claim_terminal(&concurrent)
    );
    let results = [
        first_result.expect("first concurrent ledger writer"),
        second_result.expect("second concurrent ledger writer"),
    ];
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, PeerKeyPackageClaimLedgerWriteResult::Inserted))
            .count(),
        1
    );
    assert_eq!(
        results
            .iter()
            .filter(|result| {
                matches!(
                    result,
                    PeerKeyPackageClaimLedgerWriteResult::Existing(existing)
                        if existing.as_ref() == &concurrent
                )
            })
            .count(),
        1
    );
    // This is the persistence contract boundary: the shared contract above
    // supplies durable audit rows, without claiming an HTTP Device admission.
    keypackage_revocation_closes_active_ledgers_atomically(
        &restarted_store,
        &namespace,
        &concurrent,
    )
    .await;
}

async fn keypackage_revocation_closes_active_ledgers_atomically(
    store: &PgMlsKeyPackageStore,
    namespace: &str,
    active: &PeerKeyPackageClaimLedgerRecord,
) {
    use diesel_async::RunQueryDsl;
    let id = format!("{namespace}-keypackage-last-resort");
    let original = store.get(&id).await.unwrap().unwrap();
    let consumed = store
        .get_peer_claim(
            &active.source_id,
            &format!("local-last-resort:{namespace}-01"),
        )
        .await
        .unwrap()
        .unwrap();
    let expired = store
        .get_peer_claim(
            &active.source_id,
            &format!("local-last-resort:{namespace}-02"),
        )
        .await
        .unwrap()
        .unwrap();
    let mut conn = store.pool.get().await.unwrap();
    diesel::sql_query("CREATE FUNCTION fail_keypackage_revoke_ledger() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'revoke ledger failure'; END $$").execute(&mut conn).await.unwrap();
    diesel::sql_query("CREATE TRIGGER fail_keypackage_revoke_ledger BEFORE UPDATE ON peer_keypackage_claims FOR EACH ROW EXECUTE FUNCTION fail_keypackage_revoke_ledger()").execute(&mut conn).await.unwrap();
    drop(conn);
    let revoke = || coland_storage::MlsKeyPackageClaim {
        applet_device_scope_guard: None,
        id: &id,
        target: coland_storage::MlsKeyPackageClaimTarget::Revoke,
        intended_realm_id: None,
        device_authorize_event_id: original.device_authorize_event_id.as_deref(),
        agent_key_authorize_event_id: None,
        device_revocation_gate: None,
        claimed_at: 12,
        claim_expires_at_unix_ms: None,
    };
    let failed = store.try_claim(revoke()).await;
    let mut conn = store.pool.get().await.unwrap();
    diesel::sql_query("DROP TRIGGER fail_keypackage_revoke_ledger ON peer_keypackage_claims")
        .execute(&mut conn)
        .await
        .unwrap();
    diesel::sql_query("DROP FUNCTION fail_keypackage_revoke_ledger()")
        .execute(&mut conn)
        .await
        .unwrap();
    drop(conn);
    assert!(
        failed.is_err(),
        "ledger write failure refuses package revocation"
    );
    assert_eq!(
        store.get(&id).await.unwrap().unwrap(),
        original,
        "package update rolls back with its ledger"
    );
    assert_eq!(
        store
            .get_peer_claim(&active.source_id, &active.claim_request_id)
            .await
            .unwrap()
            .as_ref(),
        Some(active)
    );
    let revoked = store.try_claim(revoke()).await.unwrap().unwrap();
    assert_eq!(revoked.claimed_by_mls_group_id.as_deref(), Some("revoked"));
    let closed = store
        .get_peer_claim(&active.source_id, &active.claim_request_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(closed.state, "revoked");
    assert_eq!(
        closed.outcome, active.outcome,
        "the first outcome is immutable"
    );
    assert_eq!(closed.request_digest, active.request_digest);
    assert_eq!(
        store
            .get_peer_claim(&consumed.source_id, &consumed.claim_request_id)
            .await
            .unwrap()
            .unwrap(),
        consumed
    );
    assert_eq!(
        store
            .get_peer_claim(&expired.source_id, &expired.claim_request_id)
            .await
            .unwrap()
            .unwrap(),
        expired
    );
    assert!(
        store
            .attach_peer_claim_consume_receipt(
                &active.source_id,
                &active.claim_request_id,
                &active.request_digest,
                &serde_json::json!({"receipt":"too-late"}),
                13_000
            )
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        store.try_claim(revoke()).await.unwrap().is_none(),
        "terminal package does not rearm"
    );
}

#[tokio::test]
async fn postgres_adapter_satisfies_organization_registration_contract() {
    let database = coland_storage_postgres::test_database::TestDatabase::lease().await;
    let pool = database.pool();
    let _db_guard = DB_GUARD.lock().await;
    let store = PgOrganizationRegistrationStore::new(pool);
    let namespace = format!(
        "postgres-organization-registration-{}",
        uuid::Uuid::now_v7()
    );
    assert_organization_registration_store_contract(&store, &namespace).await;
}

#[tokio::test]
async fn postgres_account_data_cas_treats_an_absent_key_as_revision_zero() {
    let database = coland_storage_postgres::test_database::TestDatabase::lease().await;
    let pool = database.pool();
    let _db_guard = DB_GUARD.lock().await;
    let store = PgAccountDataStore { pool };
    let key = format!("client.postgres-cas.{}", uuid::Uuid::now_v7());
    let actor = "did:web:postgres-cas.example";
    let invalid_create = AccountDataRecord {
        actor: actor.to_owned(),
        account_data_key: key.clone(),
        revision: 8,
        payload: serde_json::json!({"value": "must-not-land"}),
        tombstone: false,
        updated_at: chrono::Utc::now(),
    };
    assert!(matches!(
        store.compare_and_set(&invalid_create, 7).await.unwrap(),
        AccountDataCasResult::Conflict(None)
    ));
    assert!(store.get(actor, &key).await.unwrap().is_none());

    let created = AccountDataRecord {
        actor: actor.to_owned(),
        account_data_key: key.clone(),
        revision: 1,
        payload: serde_json::json!({"value": 1}),
        tombstone: false,
        updated_at: chrono::Utc::now(),
    };
    assert!(matches!(
        store.compare_and_set(&created, 0).await.unwrap(),
        AccountDataCasResult::Applied(record) if record.revision == 1
    ));
    assert!(matches!(
        store.compare_and_set(&created, 0).await.unwrap(),
        AccountDataCasResult::Conflict(Some(record)) if record.revision == 1
    ));
}

#[tokio::test]
async fn postgres_retention_policy_preserves_full_actor_after_reopen() {
    use arkret_wire::{AccountId, ActorId, DidCoreId};
    use coland_storage::{RetentionPolicyRecord, RetentionPolicyStore};
    use coland_storage_postgres::PgRetentionPolicyStore;
    let database = coland_storage_postgres::test_database::TestDatabase::lease().await;
    let pool = database.pool();
    let _guard = DB_GUARD.lock().await;
    let store = PgRetentionPolicyStore { pool: pool.clone() };
    let principal = DidCoreId::new("ak:did_core:web:retention-author.example").unwrap();
    let realm = format!("retention-roundtrip-{}", uuid::Uuid::now_v7());
    for station in [
        "ak:did_core:web:station-a.example",
        "ak:did_core:web:station-b.example",
    ] {
        let author = ActorId::account(AccountId::new(
            principal.clone(),
            DidCoreId::new(station).unwrap(),
        ));
        let record = RetentionPolicyRecord {
            realm_id: realm.clone(),
            ttl_seconds: 86_400,
            updated_by: author.clone(),
            updated_at: chrono::Utc::now(),
        };
        store.put(&record).await.unwrap();
        let reopened = PgRetentionPolicyStore { pool: pool.clone() };
        let loaded = reopened.get(&realm).await.unwrap().unwrap();
        assert_eq!(loaded.updated_by, author);
        assert_eq!(loaded.ttl_seconds, 86_400);
        let snapshot = reopened.snapshot_all().await.unwrap();
        assert_eq!(
            snapshot
                .iter()
                .find(|r| r.realm_id == realm)
                .unwrap()
                .updated_by,
            author
        );
    }
}

#[tokio::test]
async fn postgres_adapter_satisfies_invite_new_source_ledger_contract() {
    use coland_storage::AccountStore;
    let database = coland_storage_postgres::test_database::TestDatabase::lease().await;
    let pool = database.pool();
    let _db_guard = DB_GUARD.lock().await;
    let ledger = PgInviteNewSourceLedgerStore { pool: pool.clone() };
    let namespace = format!("postgres-invite-new-source-{}", uuid::Uuid::now_v7());
    let station = arkret_wire::DidCoreId::new("ak:did_core:web:coland.example").unwrap();
    let holder = ordinary_realm::case_future(|| {
        ordinary_realm::human_profile::admit(&pool, &station, &namespace)
    })
    .await;
    PgAccountStore { pool: pool.clone() }
        .put(&coland_storage::AccountRecord {
            pk: coland_storage::AccountPk(0),
            principal_id: holder.principal_id.clone(),
            station_id: holder.station_id.clone(),
            localpart: String::new(),
            display_name: None,
            bio: None,
            avatar_blob_ref: None,
            created_at: chrono::Utc::now(),
        })
        .await
        .unwrap();
    assert_invite_new_source_ledger_contract(&ledger, &holder, &namespace).await;
}
