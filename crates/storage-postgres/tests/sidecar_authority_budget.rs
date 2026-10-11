//! A source admission must preserve the whole 64-ref cut atomically.
#[path = "../../test-support/src/device_authorization_history.rs"]
#[allow(dead_code)]
mod device_authorization_history;
#[path = "support/ordinary_realm.rs"]
#[expect(
    dead_code,
    reason = "This integration binary uses only its subset of the shared Realm fixture."
)]
mod ordinary_realm;
#[path = "../../test-support/src/pcr_genesis.rs"]
#[allow(dead_code)]
mod pcr_genesis;
#[path = "support/sidecar_agent.rs"]
#[expect(
    dead_code,
    reason = "This integration binary uses only its subset of the shared Agent fixture."
)]
mod sidecar_agent;

use coland_storage::{
    ActorProfileStore, AgentProvisionAdmissionWrite, AuthorityCommitStore, EventCommitUnitOfWork,
};
use diesel::sql_types::BigInt;
use diesel_async::RunQueryDsl;

#[derive(diesel::QueryableByName, Debug, PartialEq)]
struct Counts {
    #[diesel(sql_type = BigInt)]
    events: i64,
    #[diesel(sql_type = BigInt)]
    commits: i64,
    #[diesel(sql_type = BigInt)]
    provisions: i64,
    #[diesel(sql_type = BigInt)]
    declarations: i64,
    #[diesel(sql_type = BigInt)]
    accountability: i64,
    #[diesel(sql_type = BigInt)]
    selectors: i64,
    #[diesel(sql_type = BigInt)]
    deliveries: i64,
}

async fn counts(pool: &coland_storage_postgres::PgPool) -> Counts {
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query(
        "SELECT (SELECT COUNT(*) FROM canonical_events) AS events, \
        (SELECT COUNT(*) FROM realm_commits) AS commits, \
        (SELECT COUNT(*) FROM agent_provisioning_current_results) AS provisions, \
        (SELECT COUNT(*) FROM agent_pcr_genesis_declaration_current_results) AS declarations, \
        (SELECT COUNT(*) FROM identity_accountability_current_results) AS accountability, \
        (SELECT COUNT(*) FROM agent_selector_claim_current_results) AS selectors, \
        (SELECT COUNT(*) FROM federation_outbox) AS deliveries",
    )
    .get_result(&mut conn)
    .await
    .unwrap()
}

#[tokio::test]
async fn provision_ref_65_is_refused_without_accepted_source_or_current_writes() {
    let database = coland_storage_postgres::test_database::TestDatabase::lease().await;
    let pool = database.pool();
    let station = ordinary_realm::station();
    let station_did = device_authorization_history::did_web_station(&station);
    let principal = pcr_genesis::PcrGenesisFixture::new(station_did.clone());
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query("INSERT INTO device_inventory_station(singleton,station_id) VALUES(TRUE,$1)")
        .bind::<diesel::sql_types::Text, _>(station.as_str())
        .execute(&mut conn)
        .await
        .unwrap();
    drop(conn);
    principal
        .admit_founding_device(&coland_storage_postgres::PgPersistenceStore::new(
            pool.clone(),
        ))
        .await
        .unwrap();
    let controller = &principal.history.account;
    ordinary_realm::human_profile::register_fixture_signer(
        controller,
        principal.history.device_verification_method.clone(),
        principal.history.founding_device_signing_seed,
    );
    let unit =
        ordinary_realm::bootstrap_unit_for_account("sidecar-ref-budget", controller, &station_did);
    let unit = ordinary_realm::source_bootstrap(&pool, unit).await;
    let store = coland_storage_postgres::PgAuthorityCommitStore { pool: pool.clone() };
    store
        .admit_ordinary_realm_bootstrap_unit(&unit, unit.transactions[0].commit.committed_at)
        .await
        .unwrap();
    let parent = unit.transactions.last().unwrap();
    let create = ordinary_realm::next_request(
        parent,
        arkret_wire::EventKind::SidecarCreate,
        &controller.principal_id,
        serde_json::json!({}),
        parent.commit.committed_at,
    );
    let create = ordinary_realm::source_request(&pool, create).await;
    coland_storage_postgres::PgEventCommitUnitOfWork::new(pool.clone())
        .commit_event(create.clone())
        .await
        .unwrap();
    let realm = &create.authority_commit.event.realm_id;
    let sidecar = arkret_wire::SidecarId::from_event_id(&create.authority_commit.event.event_id);
    let mut head = principal.unit.transactions[1].commit.clone();
    let authority = principal.unit.transactions[1].expected_authority.clone();
    let profiles = coland_storage_postgres::PgActorProfileStore { pool: pool.clone() };
    // Two initial refs (Sidecar creation and controller parent join) leave
    // exactly 62 refs for accepted ownership declarations. The Agent PCRs
    // have not been founded, so none of these Agents is a desired participant.
    for ordinal in 0..63 {
        let did = arkret_wire::Did::new(format!(
            "did:web:budget-{}-{}.example",
            ordinal,
            uuid::Uuid::now_v7().simple()
        ))
        .unwrap();
        let agent = arkret_wire::project_did_to_core_id(&did).unwrap();
        let future_genesis = arkret_wire::EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            arkret_canonical::sha256_bytes(did.as_str().as_bytes()),
        );
        let agent_pcr = arkret_wire::RealmId::from_event_id(&future_genesis);
        let at = head.committed_at + chrono::TimeDelta::seconds(1);
        let event = sidecar_agent::agent_provision_event(
            controller,
            &head.realm_id,
            &principal.history.device_verification_method,
            principal.history.founding_device_signing_seed,
            &agent,
            &agent_pcr,
            &format!("{did}#managed-controller"),
            at,
        );
        let commit = sidecar_agent::station_successor(&head, &event, &station_did, 1);
        let write = AgentProvisionAdmissionWrite {
            commit: coland_storage::AuthorityCommitTransaction {
                expected_authority: authority.clone(),
                event,
                commit: commit.clone(),
                producer_signer_fact: None,
                mls_state: None,
                welcomes: Vec::new(),
                recipient_queue_capacity: 0,
            },
            queued_at: commit.committed_at,
        };
        if ordinal < 62 {
            profiles.admit_agent_provision(write).await.unwrap();
            head = commit;
        } else {
            let before = counts(&pool).await;
            let error = profiles.admit_agent_provision(write).await.unwrap_err();
            assert!(error.to_string().contains("failed_precondition"), "{error}");
            assert_eq!(
                counts(&pool).await,
                before,
                "overflow must roll back accepted Event, Commit and all current carriers"
            );
        }
        let cut = coland_storage_postgres::sidecar_authority_cut::read(
            &pool, realm, &sidecar, controller,
        )
        .await
        .unwrap()
        .unwrap();
        assert!(cut.desired_agent_ids.is_empty());
        assert_eq!(cut.authority_stream_head.len(), (ordinal + 3).min(64));
        assert_eq!(
            cut.visible_stream_heads
                .iter()
                .find(|entry| entry.stream_ref == head.stream_ref)
                .unwrap()
                .commit_id,
            head.commit_id
        );
    }
}
