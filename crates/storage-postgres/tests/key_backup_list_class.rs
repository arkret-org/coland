//! `KeysBackupsList` has exactly one backup class on real PostgreSQL.
//!
//! key-management §7.5.0 / §7.6.1 (decision 0097): the list producer returns
//! the confirmed `secret_storage` pointer and nothing else, and the metadata
//! page it serves can only hold `secret_storage` envelopes. `mls_history`,
//! private classes and class-less rows are rejected by the initial schema,
//! not filtered out at read time.

mod support;

use std::sync::OnceLock;

use arkret_models_crypto::{BackupActiveSeriesPointer, BackupActiveSeriesState};
use arkret_wire::{
    AccountId, ActorId, CommitStreamRef, DidCoreId, Event, EventKind, RealmCommit, RealmId,
    ScopeRef,
};
use coland_storage::{KeyBackupListQuery, KeyBackupStore};
use coland_storage_postgres::{Db, PgKeyBackupStore, PgPool};
use diesel::sql_types::{BigInt, Binary, Jsonb, Nullable, Text, Timestamptz, Uuid};
use diesel_async::RunQueryDsl;

static TEST_POOL: OnceLock<PgPool> = OnceLock::new();

async fn test_pool() -> PgPool {
    if let Some(pool) = TEST_POOL.get() {
        return pool.clone();
    }
    let url = support::contract_database_url();
    support::ensure_contract_database(&url).await;
    let pool = Db::connect(Some(&url), Default::default())
        .await
        .expect("initialize test database")
        .pool
        .expect("a configured URL always yields a pool");
    let _ = TEST_POOL.set(pool.clone());
    pool
}

fn unique() -> String {
    uuid::Uuid::now_v7().simple().to_string()
}

fn random_digest() -> [u8; 32] {
    use sha2::Digest as _;
    sha2::Sha256::digest(uuid::Uuid::now_v7().as_bytes()).into()
}

fn commit(event: &Event, realm_id: &RealmId) -> RealmCommit {
    let now = chrono::DateTime::parse_from_rfc3339("2026-09-24T00:00:00Z")
        .unwrap()
        .with_timezone(&chrono::Utc);
    RealmCommit {
        producer_signer_fact_digest: None,
        commit_id: arkret_wire::RealmCommitId::from_digest(random_digest()),
        realm_id: realm_id.clone(),
        stream_ref: CommitStreamRef::Realm {
            realm_id: realm_id.clone(),
        },
        stream_position: 0,
        previous_commit_ref: None,
        event_ref: event.event_id.clone(),
        governance_generation: 0,
        authority_ref: arkret_wire::RealmCommitAuthorityRef::GenesisOrChangeEvent(
            event.event_id.clone(),
        ),
        committed_at: now,
        signature: arkret_wire::DetachedObjectSignature {
            context: arkret_wire::DetachedSignatureContext::RealmCommit,
            signature_algorithm: arkret_wire::DetachedSignatureAlgorithm::Ed25519,
            verification_method: arkret_wire::DidUrl::new("did:web:station.example#authority")
                .unwrap(),
            signed_digest: arkret_wire::Hash::new(format!("sha256:{}", "aa".repeat(32))).unwrap(),
            created_at: now,
            sig: arkret_wire::Base64UrlString::new("c2lnbmF0dXJl").unwrap(),
        },
    }
}

/// A PCR whose confirmed head is its genesis commit and that has no accepted
/// pointer: the producer must answer the explicit `absent` branch.
async fn seed_confirmed_pcr(pool: &PgPool) -> (AccountId, RealmCommit) {
    let run = unique();
    let account = AccountId::new(
        DidCoreId::new(format!("ak:did_core:web:kb-{run}.example")).unwrap(),
        DidCoreId::new(format!("ak:did_core:web:station-{run}.example")).unwrap(),
    );
    let realm_id = RealmId::from_event_id(&arkret_wire::EventId::from_digest(
        arkret_canonical::DigestSuite::Sha256,
        random_digest(),
    ));
    let genesis = arkret_wire::test_support::raw_event(
        EventKind::RealmCreate.as_str(),
        ScopeRef::Realm {
            realm_id: realm_id.clone(),
        },
        account.principal_id.clone(),
        account.station_id.clone(),
        serde_json::json!({"genesis": true, "run": run}),
    )
    .unwrap();
    let genesis_commit = commit(&genesis, &realm_id);
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query(
        "INSERT INTO realm_authorities(realm_id,generation,service_id,authority_ref) \
         VALUES($1,0,$2,$3)",
    )
    .bind::<Text, _>(realm_id.as_str())
    .bind::<Text, _>(account.station_id.as_str())
    .bind::<Jsonb, _>(serde_json::to_value(&genesis_commit.authority_ref).unwrap())
    .execute(&mut conn)
    .await
    .unwrap();
    diesel::sql_query(
        "INSERT INTO principal_resolutions \
         (principal_id,station_id,pcr_realm_id,genesis_event_id,current_event_id,projection,updated_at) \
         VALUES($1,$2,$3,$4,$4,'{}'::jsonb,now())",
    )
    .bind::<Text, _>(account.principal_id.as_str())
    .bind::<Text, _>(account.station_id.as_str())
    .bind::<Text, _>(realm_id.as_str())
    .bind::<Text, _>(genesis.event_id.as_str())
    .execute(&mut conn)
    .await
    .unwrap();
    let token =
        coland_storage::ids::event_token_part_expect_internal(genesis.event_id.as_str(), "event");
    diesel::sql_query(
        "INSERT INTO canonical_events \
         (id,digest_suite,digest,actor_id,realm_id,scope_ref,kind,canonical_bytes,envelope,state,received_at,committed_at) \
         VALUES($1,1,$2,$3,$4,$5,$6,'\\x00'::bytea,$7,'committed',$8,$8)",
    )
    .bind::<Binary, _>(token.to_vec())
    .bind::<Binary, _>(token[1..].to_vec())
    .bind::<Text, _>(genesis.actor_id.to_string())
    .bind::<Text, _>(genesis.realm_id.as_str())
    .bind::<Jsonb, _>(serde_json::to_value(&genesis.scope_ref).unwrap())
    .bind::<Text, _>(genesis.kind.as_str())
    .bind::<Jsonb, _>(serde_json::to_value(&genesis).unwrap())
    .bind::<Timestamptz, _>(genesis_commit.committed_at)
    .execute(&mut conn)
    .await
    .unwrap();
    diesel::sql_query(
        "INSERT INTO realm_commits \
         (commit_id,realm_id,stream_key,stream_ref,stream_position,previous_commit_ref,event_pk,governance_generation,commit_json,committed_at) \
         SELECT $1,$2,$3,$4,$5,$6,pk,0,$7,$8 FROM canonical_events WHERE id=$9",
    )
    .bind::<Text, _>(genesis_commit.commit_id.as_str())
    .bind::<Text, _>(genesis_commit.realm_id.as_str())
    .bind::<Text, _>(arkret_canonical::canonical_json_string(&genesis_commit.stream_ref).unwrap())
    .bind::<Jsonb, _>(serde_json::to_value(&genesis_commit.stream_ref).unwrap())
    .bind::<BigInt, _>(0)
    .bind::<Nullable<Text>, _>(None::<&str>)
    .bind::<Jsonb, _>(serde_json::to_value(&genesis_commit).unwrap())
    .bind::<Timestamptz, _>(genesis_commit.committed_at)
    .bind::<Binary, _>(token.to_vec())
    .execute(&mut conn)
    .await
    .unwrap();
    (account, genesis_commit)
}

fn envelope(id: &str, actor: &ActorId, series: &str, backup_kind: &str) -> serde_json::Value {
    serde_json::json!({
        "backup_id":id, "actor_id":actor, "backup_kind":backup_kind, "backup_version":"kb_1",
        "created_at":"2026-09-09T00:00:00.000Z", "series_id":series, "series_seq":0,
        "encryption":{"recipient_method":"secret_storage_key", "recipient_key_ref":"backup-key", "aead":{"name":"xchacha20_poly1305", "nonce":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}},
        "domain_separation":{"subdomain":"secret_storage"},
        "contents":[{"item_kind":"recovery_key_share", "secret_id":"share"}],
        "ciphertext":"AAAA", "ciphertext_digest":"sha256:709e80c88487a2411e1ee4dfb9f22a861492d20c4765150c0c794abd70f8147c",
        "auth_data":{
            "device_id":"ak:device:01904100-0000-7000-8000-000000000001",
            "verification_method":"did:web:backup.example#device-signer",
            "signature_algorithm":"Ed25519", "signature":"AAAA",
            "device_authorize_event_id":"ak:event:AcIMom-0qqAXx_hmDJfxxaUJb_oJ64S3ARW1-WKFDCoD"
        }
    })
}

fn assert_closed_absent_state(
    state: &BackupActiveSeriesState,
    account: &AccountId,
    head: &RealmCommit,
) {
    assert_eq!(&state.account_id, account);
    assert_eq!(state.control_realm_id, head.realm_id);
    assert_eq!(state.authority_commit_id, head.commit_id);
    assert_eq!(state.secret_storage, BackupActiveSeriesPointer::Absent {});
    let wire = serde_json::to_value(state).unwrap();
    let members = wire
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect::<Vec<_>>();
    assert_eq!(
        members,
        [
            "account_id",
            "authority_commit_id",
            "control_realm_id",
            "secret_storage"
        ]
    );
    assert_eq!(
        wire["secret_storage"],
        serde_json::json!({"state": "absent"})
    );
    let reparsed: BackupActiveSeriesState = serde_json::from_value(wire).unwrap();
    assert_eq!(&reparsed, state);
}

fn page_query(actor: &ActorId, backup_kind: Option<&str>) -> KeyBackupListQuery {
    KeyBackupListQuery {
        actor_id: actor.to_string(),
        backup_kind: backup_kind.map(ToOwned::to_owned),
        series_id: None,
        after: None,
        limit: 51,
    }
}

#[tokio::test]
async fn confirmed_list_pointer_is_the_single_secret_storage_class() {
    let pool = test_pool().await;
    let (account, head) = seed_confirmed_pcr(&pool).await;
    let backups = PgKeyBackupStore { pool: pool.clone() };
    let actor = ActorId::account(account.clone());

    let initial = backups
        .confirmed_active_series(&account)
        .await
        .unwrap()
        .expect("confirmed PCR head yields a pointer result");
    assert_closed_absent_state(&initial, &account, &head);

    let series = format!("ak:backup_series:{}", uuid::Uuid::now_v7());
    let backup_id = format!("ak:backup:{}", uuid::Uuid::now_v7());
    backups
        .put(
            backup_id.clone(),
            envelope(&backup_id, &actor, &series, "secret_storage"),
        )
        .await
        .unwrap();

    let all = backups.list_page(&page_query(&actor, None)).await.unwrap();
    let filtered = backups
        .list_page(&page_query(&actor, Some("secret_storage")))
        .await
        .unwrap();
    for page in [&all, &filtered] {
        assert_eq!(page.payloads.len(), 1);
        assert_eq!(page.payloads[0]["backup_id"], backup_id);
        assert_eq!(page.payloads[0]["backup_kind"], "secret_storage");
    }
    assert!(
        backups
            .list_page(&page_query(&actor, Some("mls_history")))
            .await
            .unwrap()
            .payloads
            .is_empty()
    );

    // The pointer does not follow envelopes or list filters.
    let after_put = backups
        .confirmed_active_series(&account)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(after_put, initial);
}

#[tokio::test]
async fn initial_schema_rejects_every_other_backup_class() {
    let pool = test_pool().await;
    let (account, head) = seed_confirmed_pcr(&pool).await;
    let backups = PgKeyBackupStore { pool: pool.clone() };
    let actor = ActorId::account(account.clone());
    let series = format!("ak:backup_series:{}", uuid::Uuid::now_v7());

    // The typed write path refuses the class before SQL.
    for class in ["mls_history", "org.example.private"] {
        let backup_id = format!("ak:backup:{}", uuid::Uuid::now_v7());
        assert!(
            backups
                .put(
                    backup_id.clone(),
                    envelope(&backup_id, &actor, &series, class)
                )
                .await
                .is_err(),
            "{class}"
        );
    }

    // A raw row cannot bypass it: the envelope table admits only secret_storage.
    let mut conn = pool.get().await.unwrap();
    let mut raw_payloads = Vec::new();
    for class in ["mls_history", "org.example.private", ""] {
        let backup_id = format!("ak:backup:{}", uuid::Uuid::now_v7());
        raw_payloads.push((
            class.to_owned(),
            backup_id.clone(),
            envelope(&backup_id, &actor, &series, class),
        ));
    }
    let class_less_id = format!("ak:backup:{}", uuid::Uuid::now_v7());
    let mut class_less = envelope(&class_less_id, &actor, &series, "secret_storage");
    class_less.as_object_mut().unwrap().remove("backup_kind");
    raw_payloads.push(("<missing>".to_owned(), class_less_id, class_less));
    for (class, backup_id, payload) in raw_payloads {
        let error =
            diesel::sql_query("INSERT INTO key_backups(id,actor_id,payload) VALUES($1,$2,$3)")
                .bind::<Uuid, _>(coland_storage::ids::typed_uuid_part_expect_internal(
                    &backup_id,
                ))
                .bind::<Text, _>(actor.to_string())
                .bind::<Jsonb, _>(&payload)
                .execute(&mut conn)
                .await
                .expect_err(&format!("{class} envelope row must be rejected"));
        assert!(
            error.to_string().contains("key_backups_backup_kind_check"),
            "{class}: {error}"
        );
    }

    // The typed current pointer table has the same single class.
    let error = diesel::sql_query(
        "INSERT INTO key_backup_active_series_current_results \
         (realm_id,current_key,actor_id,backup_kind,current_event_id,current_commit_id, \
          current_stream_position,value,updated_at) \
         VALUES($1,$2,$3,'mls_history',$4,$5,0,$6,now())",
    )
    .bind::<Text, _>(head.realm_id.as_str())
    .bind::<Text, _>(format!("mls-history-{}", unique()))
    .bind::<Jsonb, _>(serde_json::to_value(&actor).unwrap())
    .bind::<Text, _>(head.event_ref.as_str())
    .bind::<Text, _>(head.commit_id.as_str())
    .bind::<Jsonb, _>(serde_json::json!({
        "schema": "ak.schema.key_backup_active_series.v1",
        "actor_id": actor,
        "backup_kind": "mls_history",
        "series_pointer_version": 1
    }))
    .execute(&mut conn)
    .await
    .expect_err("mls_history pointer row must be rejected");
    assert!(
        error
            .to_string()
            .contains("key_backup_active_series_current_results_backup_kind_check"),
        "{error}"
    );

    assert!(
        backups
            .list_page(&page_query(&actor, None))
            .await
            .unwrap()
            .payloads
            .is_empty()
    );
    let state = backups
        .confirmed_active_series(&account)
        .await
        .unwrap()
        .unwrap();
    assert_closed_absent_state(&state, &account, &head);
}
