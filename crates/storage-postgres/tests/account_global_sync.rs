#[path = "support/ordinary_realm.rs"]
#[allow(dead_code)]
mod ordinary_realm;
mod support;
use coland_storage::{
    AccountDataCasResult, AccountDataRecord, AccountDataStore, AgentDraftPendingIntentStore,
    SyncCursorStore,
};
use coland_storage_postgres::{
    Db, PgAccountDataStore, PgAgentDraftPendingIntentStore, PgPool, PgSyncCursorStore,
};
use deadpool::managed::Pool;
use diesel_async::pooled_connection::AsyncDieselConnectionManager;

async fn pool() -> PgPool {
    let url = support::contract_database_url();
    support::ensure_contract_database(&url).await;
    Db::connect(Some(&url), Default::default()).await.unwrap();
    Pool::builder(AsyncDieselConnectionManager::new(&url))
        .build()
        .unwrap()
}
async fn put(store: &PgAccountDataStore, actor: &str, key: &str, revision: u64, deleted: bool) {
    let row = AccountDataRecord {
        actor: actor.into(),
        account_data_key: key.into(),
        revision,
        payload: serde_json::json!({"revision":revision}),
        tombstone: deleted,
        updated_at: chrono::Utc::now(),
    };
    assert!(matches!(
        store.compare_and_set(&row, revision - 1).await.unwrap(),
        AccountDataCasResult::Applied(_)
    ));
}

#[tokio::test]
async fn agent_draft_pending_intent_projects_live_and_terminal_redacted_versions() {
    use diesel::sql_types::{Jsonb, Text, Timestamptz};
    use diesel_async::RunQueryDsl;

    let pool = pool().await;
    let mut conn = pool.get().await.unwrap();
    let controller = arkret_wire::AccountId::new(
        arkret_wire::DidCoreId::new(format!(
            "ak:did_core:web:controller-{}.example",
            uuid::Uuid::now_v7()
        ))
        .unwrap(),
        arkret_wire::DidCoreId::new("ak:did_core:web:station.example").unwrap(),
    );
    let controller_key = controller.to_string();
    let controller_actor_key = arkret_wire::ActorId::account(controller.clone())
        .canonical_key()
        .unwrap();
    let agent = arkret_wire::DidCoreId::new("ak:did_core:web:agent.example").unwrap();
    let digest = |byte: char| format!("sha256:{}", byte.to_string().repeat(64));
    // The source Event id is unique per accepted proposal, and this contract
    // database outlives a run, so the id derives from this run's controller.
    let event_id = arkret_wire::EventId::from_digest(
        arkret_canonical::DigestSuite::Sha256,
        arkret_canonical::sha256_bytes(controller_key.as_bytes()),
    );
    let created_at = "2026-09-20T00:00:00Z"
        .parse::<chrono::DateTime<chrono::Utc>>()
        .unwrap();
    let expires_at = created_at + chrono::TimeDelta::minutes(5);
    let handoff = serde_json::json!({
        "scheme":"ak.hpke_x25519_aead_chacha20poly1305.v1",
        "recipients":[{
            "recipient_device_id":"ak:device:01964137-0000-7000-8000-000000000001",
            "recipient_hpke_key_digest":digest('2'),
            "enc":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "ciphertext":"AAAAAAAAAAAAAAAAAAAAAA",
            "ciphertext_digest":digest('3')
        }]
    });
    diesel::sql_query(
        "INSERT INTO agent_draft_pending_intents \
         (controller_account_id,controller_account_key,agent_id,draft_id,proposed_action,target, \
          content_digest,content_handoff,canonical_event_digest,accepted_event_id,expires_at,created_at) \
         VALUES($1,$2,$3,'draft-1','compose',$4,$5,$6,$7,$8,$9,$10)",
    )
    .bind::<Jsonb, _>(serde_json::to_value(&controller).unwrap())
    .bind::<Text, _>(&controller_key)
    .bind::<Text, _>(agent.as_str())
    .bind::<Jsonb, _>(serde_json::json!({
        "kind":"account_data",
        "account_data_key":"opaque"
    }))
    .bind::<Text, _>(digest('1'))
    .bind::<Jsonb, _>(handoff)
    .bind::<Text, _>(digest('4'))
    .bind::<Text, _>(event_id.as_str())
    .bind::<Timestamptz, _>(expires_at)
    .bind::<Timestamptz, _>(created_at)
    .execute(&mut *conn)
    .await
    .unwrap();

    let sync = PgSyncCursorStore { pool: pool.clone() };
    let live_cut = sync.account_global_watermark().await.unwrap();
    let live = sync
        .account_global_page(
            &controller_actor_key,
            "agent_draft_pending_intents",
            live_cut,
            "",
            None,
            100,
        )
        .await
        .unwrap();
    assert_eq!(live.len(), 1);
    assert_eq!(live[0].channel_position, 1);
    assert!(!live[0].deleted);
    assert_eq!(live[0].payload["state"], "available");
    assert!(live[0].payload.get("content_handoff").is_some());

    let store = PgAgentDraftPendingIntentStore::new(pool.clone());
    let expired = store
        .get_by_source_event(&controller, &event_id, expires_at)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        expired.state,
        coland_storage::AgentDraftPendingIntentState::Expired
    );
    assert!(expired.content_handoff.is_none());
    assert_eq!(expired.expired_at, Some(expires_at));

    let terminal_cut = sync.account_global_watermark().await.unwrap();
    let terminal = sync
        .account_global_page(
            &controller_actor_key,
            "agent_draft_pending_intents",
            terminal_cut,
            "",
            Some(live[0].revision),
            100,
        )
        .await
        .unwrap();
    assert_eq!(terminal.len(), 1);
    assert_eq!(terminal[0].channel_position, 2);
    assert!(!terminal[0].deleted);
    assert_eq!(terminal[0].payload["state"], "expired");
    assert!(terminal[0].payload.get("content_handoff").is_none());
    assert_eq!(
        terminal[0].payload["expired_at"],
        serde_json::json!(arkret_canonical::format_timestamp_canonical(expires_at))
    );

    let deletion = diesel::sql_query(
        "DELETE FROM agent_draft_pending_intents \
         WHERE controller_account_key=$1 AND agent_id=$2 AND draft_id='draft-1'",
    )
    .bind::<Text, _>(&controller_key)
    .bind::<Text, _>(agent.as_str())
    .execute(&mut *conn)
    .await;
    assert!(
        deletion.is_err(),
        "create-once identity must survive terminal retention"
    );
}
#[tokio::test]
async fn account_global_snapshot_is_frozen_and_changes_are_page_bounded() {
    let pool = pool().await;
    let cas = PgAccountDataStore { pool: pool.clone() };
    let sync = PgSyncCursorStore { pool };
    let actor = format!("global-sync-{}", uuid::Uuid::now_v7());
    for n in 0..103 {
        put(&cas, &actor, &format!("key:{n:03}"), 1, false).await;
    }
    let (_, cut) = sync.account_sync_watermarks().await.unwrap();
    let first = sync
        .account_global_page(&actor, "station_cas", cut, "", None, 100)
        .await
        .unwrap();
    assert_eq!(first.len(), 100);
    assert_eq!(first[99].item_key, "key:099");
    put(&cas, &actor, "key:100", 2, false).await;
    put(&cas, &actor, "key:101", 2, true).await;
    let second = sync
        .account_global_page(&actor, "station_cas", cut, "key:099", None, 100)
        .await
        .unwrap();
    assert_eq!(second.len(), 3);
    assert_eq!(second[0].payload["revision"], 1);
    assert!(!second[1].deleted);
    let latest = sync.account_global_watermark().await.unwrap();
    let changes = sync
        .account_global_page(&actor, "station_cas", latest, "", Some(cut), 1)
        .await
        .unwrap();
    assert_eq!(changes.len(), 1);
    assert_eq!(changes[0].item_key, "key:100");
    let last = sync
        .account_global_page(
            &actor,
            "station_cas",
            latest,
            "",
            Some(changes[0].revision),
            100,
        )
        .await
        .unwrap();
    assert_eq!(last.len(), 1);
    assert!(last[0].deleted);
    assert!(
        sync.account_global_page("another-actor", "station_cas", latest, "", None, 100)
            .await
            .unwrap()
            .is_empty()
    );
}

/// The fixture principal-control Realm of `principal` at `station`.
fn pcr_realm(
    principal: &arkret_wire::DidCoreId,
    station: &arkret_wire::DidCoreId,
) -> arkret_wire::RealmId {
    arkret_wire::RealmId::from_event_id(&arkret_wire::EventId::from_digest(
        arkret_canonical::DigestSuite::Sha256,
        arkret_canonical::sha256_bytes(format!("fixture-pcr:{principal}:{station}").as_bytes()),
    ))
}

/// Resolve the Account to its fixture principal-control Realm, where its
/// account data lives.
async fn seed_pcr(
    pool: &PgPool,
    principal: &arkret_wire::DidCoreId,
    station: &arkret_wire::DidCoreId,
) {
    use diesel::sql_types::Text;
    use diesel_async::RunQueryDsl;
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query(
        "INSERT INTO principal_resolutions \
         (principal_id, station_id, pcr_realm_id, genesis_event_id, current_event_id, projection, updated_at) \
         VALUES ($1,$2,$3,'fixture-genesis','fixture-current','{}'::jsonb,now()) ON CONFLICT DO NOTHING",
    )
    .bind::<Text, _>(principal.as_str())
    .bind::<Text, _>(station.as_str())
    .bind::<Text, _>(pcr_realm(principal, station).as_str())
    .execute(&mut *conn)
    .await
    .unwrap();
}

/// One structurally signed actor-private Event of `principal` at `station`
/// on its principal-control Realm.
fn private_event(
    kind: arkret_wire::EventKind,
    principal: &arkret_wire::DidCoreId,
    station: &arkret_wire::DidCoreId,
    payload: serde_json::Value,
    at: chrono::DateTime<chrono::Utc>,
) -> arkret_wire::Event {
    arkret_wire::test_support::raw_event_at(
        kind.as_str(),
        arkret_wire::ScopeRef::Realm {
            realm_id: pcr_realm(principal, station),
        },
        principal.clone(),
        station.clone(),
        payload,
        at,
    )
    .unwrap()
}

/// Admit `event` through the actor-private transaction with the holder CAS
/// it asks for; no producer guard, no RealmCommit.
async fn admit(
    store: &PgAccountDataStore,
    event: &arkret_wire::Event,
    key: &str,
    expected_revision: u64,
    payload: serde_json::Value,
    tombstone: bool,
) -> coland_storage::PersistenceResult<coland_storage::ActorPrivateAccountDataOutcome> {
    store
        .admit_actor_private_event(&coland_storage::ActorPrivateAccountDataAdmission {
            canonical_event_digest: arkret_canonical::sha256_bytes(
                arkret_canonical::canonical_json_bytes(event).unwrap(),
            )
            .to_vec(),
            cas: coland_storage::AccountDataCasCommit {
                record: AccountDataRecord {
                    actor: event.actor_id.to_string(),
                    account_data_key: key.into(),
                    revision: expected_revision + 1,
                    payload,
                    tombstone,
                    updated_at: event.created_at,
                },
                expected_revision,
                conflict_code: "cas_conflict".to_owned(),
            },
            event: event.clone(),
            producer_guard: None,
            accepted_at: event.created_at,
        })
        .await
}

#[tokio::test]
async fn holder_current_event_changes_only_with_successful_cas_and_the_private_source_is_immutable()
{
    use coland_storage::ActorPrivateAccountDataOutcome::{Applied, Replayed};
    use diesel::sql_types::Binary;
    use diesel_async::RunQueryDsl;
    let pool = pool().await;
    let cas = PgAccountDataStore { pool: pool.clone() };
    let sync = PgSyncCursorStore { pool: pool.clone() };
    let principal =
        arkret_wire::DidCoreId::new(format!("ak:did_core:web:{}.example", uuid::Uuid::now_v7()))
            .unwrap();
    let station = arkret_wire::DidCoreId::new("ak:did_core:web:station.example").unwrap();
    let key = "ak.dnd_schedule";
    let now = chrono::Utc::now();
    seed_pcr(&pool, &principal, &station).await;
    let set = |expected: u64, value: u64, offset: i64| {
        private_event(
            arkret_wire::EventKind::AccountDataSet,
            &principal,
            &station,
            serde_json::json!({"key":key,"expected_server_revision":expected,"body":{"v":value}}),
            now + chrono::Duration::milliseconds(offset),
        )
    };
    let first = set(0, 1, 1);
    let actor = first.actor_id.to_string();
    let before = sync.account_global_watermark().await.unwrap();
    assert!(
        sync.account_global_page(&actor, "account_data_events", before, "", None, 100)
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        admit(&cas, &first, key, 0, serde_json::json!({"v":1}), false)
            .await
            .unwrap(),
        Applied
    );
    let second = set(1, 2, 2);
    assert_eq!(
        admit(&cas, &second, key, 1, serde_json::json!({"v":2}), false)
            .await
            .unwrap(),
        Applied
    );
    let cut = sync.account_global_watermark().await.unwrap();
    // The byte-identical first Event is an exact retry: its first outcome,
    // nothing written and nothing published.
    assert_eq!(
        admit(&cas, &first, key, 0, serde_json::json!({"v":1}), false)
            .await
            .unwrap(),
        Replayed
    );
    let late = set(0, 9, 3);
    let refused = admit(&cas, &late, key, 0, serde_json::json!({"v":9}), false)
        .await
        .unwrap_err();
    assert_eq!(
        refused.conflict_code(),
        Some(coland_storage::ConflictCode::CasConflict)
    );
    // The clock is Station-wide, and other tests legitimately publish for
    // different accounts concurrently. A replay or a failed CAS must leave
    // this account's register and change stream untouched.
    let after_conflicts = sync.account_global_watermark().await.unwrap();
    assert!(
        sync.account_global_page(
            &actor,
            "account_data_events",
            after_conflicts,
            "",
            Some(cut),
            100,
        )
        .await
        .unwrap()
        .is_empty(),
        "a replay or a conflicting source must not publish an account change"
    );
    let current = cas.get(&actor, key).await.unwrap().unwrap();
    assert_eq!(current.revision, 2);
    assert_eq!(current.payload, serde_json::json!({"v":2}));
    let page = sync
        .account_global_page(&actor, "account_data_events", cut, "", None, 100)
        .await
        .unwrap();
    assert_eq!(
        page[0].payload["value"]["event_id"],
        serde_json::json!(second.event_id)
    );
    let mut conn = pool.get().await.unwrap();
    let rows = diesel::sql_query("SELECT count(*) AS count FROM actor_private_events WHERE id=$1")
        .bind::<Binary, _>(late.event_id.token_bytes().to_vec())
        .get_result::<Count>(&mut *conn)
        .await
        .unwrap();
    assert_eq!(rows.count, 0, "a refused source leaves no ledger row");
    for statement in [
        "UPDATE actor_private_events SET accepted_at=now() WHERE id=$1",
        "DELETE FROM actor_private_events WHERE id=$1",
    ] {
        assert!(
            diesel::sql_query(statement)
                .bind::<Binary, _>(second.event_id.token_bytes().to_vec())
                .execute(&mut *conn)
                .await
                .is_err(),
            "the accepted actor-private source is immutable: {statement}"
        );
    }
    assert_eq!(cas.get(&actor, key).await.unwrap().unwrap().revision, 2);
}

#[tokio::test]
async fn device_station_is_bound_only_by_identity_and_rejects_rebinding() {
    use diesel_async::{RunQueryDsl, SimpleAsyncConnection};
    let pool = pool().await;
    let mut conn = pool.get().await.unwrap();
    // Isolate ownership without changing the shared contract database's identity.
    conn.batch_execute("CREATE TEMP TABLE device_inventory_station (singleton boolean PRIMARY KEY CHECK(singleton), station_id text UNIQUE NOT NULL); CREATE TRIGGER immutable_owner BEFORE UPDATE ON device_inventory_station FOR EACH ROW EXECUTE FUNCTION public.immutable_device_inventory_station(); CREATE TEMP TABLE service_identity (id text PRIMARY KEY, identity jsonb NOT NULL); CREATE TRIGGER bind_owner BEFORE INSERT OR UPDATE ON service_identity FOR EACH ROW EXECUTE FUNCTION public.bind_device_inventory_station(); CREATE TEMP TABLE devices (id text PRIMARY KEY, station_id text NOT NULL DEFAULT public.current_device_inventory_station() REFERENCES device_inventory_station(station_id));").await.unwrap();
    assert!(
        diesel::sql_query("INSERT INTO devices(id) VALUES('before')")
            .execute(&mut *conn)
            .await
            .is_err()
    );
    conn.batch_execute(r#"INSERT INTO service_identity VALUES('singleton','{"identity":{"service_id":"ak:did_core:web:local.example"}}'); INSERT INTO devices(id) VALUES('after'); UPDATE service_identity SET identity=identity;"#).await.unwrap();
    assert!(diesel::sql_query(r#"UPDATE service_identity SET identity='{"identity":{"service_id":"ak:did_core:web:foreign.example"}}'"#).execute(&mut *conn).await.is_err());
    assert!(
        diesel::sql_query(
            "INSERT INTO devices(id,station_id) VALUES('foreign','ak:did_core:web:foreign.example')"
        )
        .execute(&mut *conn)
        .await
        .is_err()
    );
}

#[derive(diesel::QueryableByName)]
struct Visible {
    #[diesel(sql_type=diesel::sql_types::Bool)]
    visible: bool,
}
async fn visible(pool: &PgPool, recipient: &str, owner: &str) -> bool {
    use diesel_async::RunQueryDsl;
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query("SELECT COALESCE(account_device_interest_visible($1,$2),FALSE) AS visible")
        .bind::<diesel::sql_types::Text, _>(recipient)
        .bind::<diesel::sql_types::Text, _>(owner)
        .get_result::<Visible>(&mut *conn)
        .await
        .unwrap()
        .visible
}
/// Device interest follows the account summary the authority transaction
/// derives from typed member state: a real bootstrap, a real join Commit and
/// a real leave Commit, never a hand-written summary row.
#[tokio::test]
async fn device_interest_requires_exact_actor_current_membership() {
    use coland_storage::EventCommitUnitOfWork;
    use ordinary_realm::{next_request, open_discussion, source_request};

    let database = coland_storage_postgres::test_database::TestDatabase::lease().await;
    let pool = database.pool();
    let run = uuid::Uuid::now_v7();
    let account = |principal: &arkret_wire::DidCoreId, station: &str| {
        arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            principal.clone(),
            arkret_wire::DidCoreId::new(station).unwrap(),
        ))
    };
    let peer_principal =
        arkret_wire::DidCoreId::new(format!("ak:did_core:web:peer-{run}.example")).unwrap();
    let peer_actor = account(&peer_principal, "ak:did_core:web:remote.example");
    let peer = peer_actor.canonical_key().unwrap();
    let same_principal_other_station = account(&peer_principal, "ak:did_core:web:other.example")
        .canonical_key()
        .unwrap();

    let discussion = Box::pin(open_discussion(&pool, &format!("device-interest-{run}"))).await;
    let creator = &discussion.unit.transactions[0].event.actor_id;
    let recipient = creator.canonical_key().unwrap();
    let founder = creator.signing_principal_id();
    assert!(
        !visible(&pool, &recipient, &peer).await,
        "an actor with no member state shares no Realm"
    );
    let at = discussion.committed_at();
    let uow = coland_storage_postgres::PgEventCommitUnitOfWork::new(pool.clone());
    // The peer is hosted by another Station, so each Commit plans its
    // committed-replication fanout from the exact source submission.
    let with_fanout_source = |mut request: coland_storage::EventCommitRequest| {
        request.realm_fanout_source = Some(arkret_wire::EventAdmissionSubmission::new(
            request.authority_commit.event.clone(),
        ));
        request
    };
    // The invite-only Realm admits the peer by the founder's directed Invite
    // and the peer's own acceptance.
    let invite = next_request(
        &discussion.head.authority_commit,
        arkret_wire::EventKind::InviteCreate,
        founder,
        serde_json::json!({
            "invitee_account_id": peer_actor.as_account_id().unwrap(),
            "introduction_evidence_digest": format!("sha256:{}", "d".repeat(64)),
            "expires_at": arkret_canonical::format_timestamp_canonical(
                at + chrono::TimeDelta::days(7)
            ),
        }),
        at,
    );
    let invite = Box::pin(source_request(&pool, invite)).await;
    uow.commit_event(invite.clone()).await.unwrap();
    let join = with_fanout_source(ordinary_realm::next_request_for_actor(
        &invite.authority_commit,
        arkret_wire::EventKind::InviteAccept,
        peer_actor.clone(),
        serde_json::json!({
            "invite_id": arkret_wire::InviteId::from_event_id(&invite.authority_commit.event.event_id),
            "previous_state": "pending",
            "invitee_account_id": peer_actor.as_account_id().unwrap(),
        }),
        at,
    ));
    uow.commit_event(join.clone()).await.unwrap();
    assert!(visible(&pool, &recipient, &peer).await);
    assert!(visible(&pool, &peer, &recipient).await);
    assert!(!visible(&pool, &recipient, &same_principal_other_station).await);

    let leave = with_fanout_source(next_request(
        &join.authority_commit,
        arkret_wire::EventKind::MemberState,
        founder,
        serde_json::json!({"member_id": peer_actor, "membership": "leave"}),
        at,
    ));
    let leave = Box::pin(source_request(&pool, leave)).await;
    uow.commit_event(leave).await.unwrap();
    assert!(!visible(&pool, &recipient, &peer).await);
    assert!(!visible(&pool, &peer, &recipient).await);
    assert!(visible(&pool, &recipient, &recipient).await);
}

#[derive(diesel::QueryableByName)]
struct Station {
    #[diesel(sql_type=diesel::sql_types::Text)]
    station: String,
}
#[derive(diesel::QueryableByName)]
struct Count {
    #[diesel(sql_type=diesel::sql_types::BigInt)]
    count: i64,
}
#[tokio::test]
async fn racing_realm_commit_accepts_only_one_event_and_rolls_back_the_loser() {
    use coland_storage::EventCommitUnitOfWork;
    use diesel_async::RunQueryDsl;
    let pool = pool().await;
    let mut conn = pool.get().await.unwrap();
    let station=diesel::sql_query("SELECT COALESCE(current_device_inventory_station(),'ak:did_core:web:storage-contract.example') AS station").get_result::<Station>(&mut *conn).await.unwrap().station;
    diesel::sql_query("INSERT INTO service_identity(id,identity) VALUES('self',jsonb_build_object('identity',jsonb_build_object('service_id',$1))) ON CONFLICT(id) DO NOTHING").bind::<diesel::sql_types::Text,_>(&station).execute(&mut *conn).await.unwrap();
    let principal = arkret_wire::DidCoreId::new(format!(
        "ak:did_core:web:cas-{}.example",
        uuid::Uuid::now_v7()
    ))
    .unwrap();
    let station = arkret_wire::DidCoreId::new(station).unwrap();
    let realm = arkret_wire::RealmId::from_event_id(&arkret_wire::EventId::from_digest(
        arkret_canonical::DigestSuite::Sha256,
        arkret_canonical::sha256_bytes(uuid::Uuid::now_v7().as_bytes()),
    ));
    let now = chrono::Utc::now();
    // Both writers claim the Realm stream's genesis position, so the authority
    // commit is the mutual exclusion the racing holders contend on.
    let authority = coland_storage::CurrentRealmAuthority {
        realm_id: realm.clone(),
        generation: 0,
        service_id: station.clone(),
        authority_ref: arkret_wire::RealmCommitAuthorityRef::GenesisOrChangeEvent(
            arkret_identifiers::EventIdentityKey::new(
                realm.digest_suite_code(),
                realm.digest_bytes(),
            )
            .event_id(),
        ),
        last_handoff_ref: None,
    };
    coland_storage::AuthorityCommitStore::install_genesis_authority(
        &coland_storage_postgres::PgAuthorityCommitStore { pool: pool.clone() },
        &authority,
    )
    .await
    .unwrap();
    let make = |value| {
        let mut event=arkret_wire::test_support::raw_event_at("ak.message",arkret_wire::ScopeRef::Realm{realm_id:realm.clone()},principal.clone(),station.clone(),serde_json::json!({"content":{"kind":"ak.content.text","text":format!("message-{value}")}}),now).unwrap();
        let event_digest = arkret_wire::Hash::new(
            event
                .event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
                .unwrap(),
        )
        .unwrap();
        event.producer_proof = Some(arkret_wire::ProducerEventProof {
            kind: arkret_wire::proof_kind::DETACHED_JWS.to_owned(),
            verification_method: arkret_wire::DidUrl::new(format!(
                "did:{}#cas-device",
                principal.as_str().strip_prefix("ak:did_core:").unwrap()
            ))
            .unwrap(),
            event_digest: event_digest.clone(),
            created_at: arkret_canonical::normalize_timestamp_canonical(now),
            domain: None,
            audience: None,
            proof_purpose: None,
            jws: arkret_wire::test_support::structural_only_detached_jws(&event_digest),
        });
        let record = coland_storage::CanonicalEventRecord {
            event_id: event.event_id.to_string(),
            actor_id: event.actor_id.to_string(),
            realm_id: Some(realm.to_string()),
            kind: event.kind.to_string(),
            schema_id: "schemas/event-payload.schema.json#/$defs/message_payload".into(),
            digest_suite: arkret_canonical::DigestSuite::Sha256,
            canonical_digest: event
                .event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
                .unwrap(),
            canonical_bytes: arkret_canonical::canonical_json_bytes(
                &event.digest_payload().unwrap(),
            )
            .unwrap(),
            envelope: serde_json::to_value(&event).unwrap(),
            received_at: now,
        };
        coland_storage::EventCommitRequest {
            authority_commit: coland_storage::AuthorityCommitTransaction {
                expected_authority: authority.clone(),
                commit: arkret_wire::RealmCommit {
                    producer_signer_fact_digest: None,
                    commit_id: arkret_wire::RealmCommitId::from_digest(
                        arkret_canonical::sha256_bytes(event.event_id.as_str().as_bytes()),
                    ),
                    realm_id: realm.clone(),
                    stream_ref: arkret_wire::CommitStreamRef::Realm {
                        realm_id: realm.clone(),
                    },
                    stream_position: 0,
                    previous_commit_ref: None,
                    event_ref: event.event_id.clone(),
                    governance_generation: 0,
                    authority_ref: authority.authority_ref.clone(),
                    committed_at: now,
                    signature: arkret_wire::DetachedObjectSignature {
                        context: arkret_wire::DetachedSignatureContext::RealmCommit,
                        signature_algorithm: arkret_wire::DetachedSignatureAlgorithm::Ed25519,
                        verification_method: arkret_wire::DidUrl::new(format!(
                            "did:{}#authority",
                            station.as_str().strip_prefix("ak:did_core:").unwrap()
                        ))
                        .unwrap(),
                        signed_digest: event_digest,
                        created_at: now,
                        sig: arkret_wire::Base64UrlString::new("c2lnbmF0dXJl".to_owned()).unwrap(),
                    },
                },
                event,
                producer_signer_fact: None,
                mls_state: None,
                welcomes: Vec::new(),
                recipient_queue_capacity: 0,
            },
            self_producer_guard: None,
            applet_producer_guard: None,
            widget_token_gate: None,
            agent_grant_scope_evidence: None,
            call_media_binding_key: None,
            forwarded_producer_evidence: None,
            forwarded_agent_producer: None,
            agent_deployment_ceiling:
                arkret_models_collaboration::governance::agent_participation::ParticipationBits::ALL,
            parent_membership_admission: None,
            event: record,
            contact_projection: None,

            device_revocation_transition: None,
            device_revocation_gate: None,
            projections: vec![],
            idempotency: None,
            outbox: vec![],
            realm_fanout_source: None,
        }
    };
    let a = make(1);
    let b = make(2);
    let a_id = a.event.event_id.clone();
    let b_id = b.event.event_id.clone();
    let first = coland_storage_postgres::PgEventCommitUnitOfWork::new(pool.clone());
    let second = coland_storage_postgres::PgEventCommitUnitOfWork::new(pool.clone());
    let (a_result, b_result) = tokio::join!(first.commit_event(a), second.commit_event(b));
    assert_ne!(
        a_result.is_ok(),
        b_result.is_ok(),
        "{a_result:?} / {b_result:?}"
    );
    let rejected_error = a_result
        .as_ref()
        .err()
        .or_else(|| b_result.as_ref().err())
        .unwrap();
    // The Realm stream head is the durable compare-and-set the racing holders
    // contend on. The loser produced no Commit and may retry the exact Event,
    // so it answers the registered retryable code, not a schema fault.
    assert_eq!(
        rejected_error.conflict_code(),
        Some(coland_storage::ConflictCode::TemporarilyUnavailable),
        "{rejected_error}"
    );
    let rejected = if a_result.is_err() { a_id } else { b_id };
    let rejected_count = diesel::sql_query(
        "SELECT count(*) AS count FROM canonical_events WHERE envelope->>'event_id'=$1",
    )
    .bind::<diesel::sql_types::Text, _>(&rejected)
    .get_result::<Count>(&mut *conn)
    .await
    .unwrap();
    assert_eq!(
        rejected_count.count, 0,
        "failed CAS must roll back the canonical Event insertion"
    );
    let committed = diesel::sql_query(
        "SELECT count(*) AS count FROM canonical_events WHERE realm_id=$1 AND state='committed'",
    )
    .bind::<diesel::sql_types::Text, _>(realm.as_str())
    .get_result::<Count>(&mut *conn)
    .await
    .unwrap();
    assert_eq!(committed.count, 1);
    let commits =
        diesel::sql_query("SELECT count(*) AS count FROM realm_commits WHERE realm_id=$1")
            .bind::<diesel::sql_types::Text, _>(realm.as_str())
            .get_result::<Count>(&mut *conn)
            .await
            .unwrap();
    assert_eq!(commits.count, 1);
}

#[tokio::test]
async fn account_blocklist_value_replays_exactly_and_cas_conflict_rolls_back_every_write() {
    use coland_storage::ActorPrivateAccountDataOutcome::{Applied, Replayed};
    use diesel_async::RunQueryDsl;

    let pool = pool().await;
    let store = PgAccountDataStore { pool: pool.clone() };
    let principal = arkret_wire::DidCoreId::new(format!(
        "ak:did_core:web:blocklist-{}.example",
        uuid::Uuid::now_v7()
    ))
    .unwrap();
    let station = arkret_wire::DidCoreId::new("ak:did_core:web:station.example").unwrap();
    let now = chrono::Utc::now();
    let key = arkret_wire::AccountDataKey::ACCOUNT_BLOCKLIST;
    seed_pcr(&pool, &principal, &station).await;
    let blocklist = |expected: u64, offset: i64| {
        let value = serde_json::json!({"entries": []});
        (
            private_event(
                arkret_wire::EventKind::AccountDataSet,
                &principal,
                &station,
                serde_json::json!({"key": key, "expected_server_revision": expected, "body": value}),
                now + chrono::Duration::milliseconds(offset),
            ),
            value,
        )
    };
    let changes = |actor: String| {
        let pool = pool.clone();
        async move {
            let mut conn = pool.get().await.unwrap();
            diesel::sql_query(
                "SELECT count(*) AS count FROM account_data_changes WHERE actor_id=$1 AND account_data_key=$2",
            )
            .bind::<diesel::sql_types::Text, _>(actor)
            .bind::<diesel::sql_types::Text, _>(arkret_wire::AccountDataKey::ACCOUNT_BLOCKLIST)
            .get_result::<Count>(&mut *conn)
            .await
            .unwrap()
            .count
        }
    };

    let (first, first_payload) = blocklist(0, 1);
    let actor = first.actor_id.to_string();
    assert_eq!(
        admit(&store, &first, key, 0, first_payload.clone(), false)
            .await
            .unwrap(),
        Applied
    );
    let after_first = changes(actor.clone()).await;
    assert_eq!(
        admit(&store, &first, key, 0, first_payload, false)
            .await
            .unwrap(),
        Replayed
    );
    assert_eq!(changes(actor.clone()).await, after_first);

    let (conflict, conflict_payload) = blocklist(0, 2);
    let error = admit(&store, &conflict, key, 0, conflict_payload, false)
        .await
        .unwrap_err();
    assert_eq!(
        error.conflict_code(),
        Some(coland_storage::ConflictCode::CasConflict)
    );
    let mut conn = pool.get().await.unwrap();
    let rolled_back =
        diesel::sql_query("SELECT count(*) AS count FROM actor_private_events WHERE event_id=$1")
            .bind::<diesel::sql_types::Text, _>(conflict.event_id.as_str())
            .get_result::<Count>(&mut *conn)
            .await
            .unwrap();
    assert_eq!(rolled_back.count, 0);
    assert_eq!(store.get(&actor, key).await.unwrap().unwrap().revision, 1);

    let (second, second_payload) = blocklist(1, 3);
    assert_eq!(
        admit(&store, &second, key, 1, second_payload, false)
            .await
            .unwrap(),
        Applied
    );
    let current = store.get(&actor, key).await.unwrap().unwrap();
    assert_eq!(current.revision, 2);
    assert_eq!(current.payload, serde_json::json!({"entries": []}));
}
