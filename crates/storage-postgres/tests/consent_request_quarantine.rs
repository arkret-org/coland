//! The Consent request ledger charge and holder-private queue CAS form one PG cut.

#[path = "../../test-support/src/device_authorization_history.rs"]
#[expect(dead_code, reason = "Shared accepted PCR fixture subset.")]
mod device_authorization_history;
#[path = "../../test-support/src/pcr_genesis.rs"]
#[expect(dead_code, reason = "Shared accepted PCR fixture subset.")]
mod pcr_genesis;

use arkret_models_collaboration::governance::holder_quarantine::{
    HolderQuarantine, HolderQuarantineSurfaceKind,
};
use arkret_models_collaboration::governance::invite_addressing::InviteReceivePolicy;
use arkret_wire::{
    AccountDataKey, AccountId, ConsentProfile, ConsentRequestScope, DidCoreId,
    NewSourceQuotaConstraints,
};
use chrono::Utc;
use coland_storage::{
    AccountDataStore, AccountPk, AccountRecord, AccountStore, ConsentRequestQuarantineInput,
    ConsentRequestQuarantineOutcome, ConsentRequestQuarantineStore, InviteReceivePolicyStore,
};
use coland_storage_postgres::test_database::TestDatabase;
use coland_storage_postgres::{
    PgAccountDataStore, PgAccountStore, PgConsentRequestQuarantineStore,
    PgInviteReceivePolicyStore, PgPool,
};
use diesel::sql_types::BigInt;
use diesel_async::RunQueryDsl;

#[derive(diesel::QueryableByName)]
struct CountRow {
    #[diesel(sql_type = BigInt)]
    count: i64,
}

async fn count(pool: &PgPool, table: &str) -> i64 {
    let mut conn = pool.get().await.unwrap();
    let query = match table {
        "ledger" => "SELECT count(*) AS count FROM invite_new_source_ledgers",
        "changes" => "SELECT count(*) AS count FROM account_data_changes",
        _ => unreachable!(),
    };
    diesel::sql_query(query)
        .get_result::<CountRow>(&mut *conn)
        .await
        .unwrap()
        .count
}

fn account(name: &str) -> AccountId {
    AccountId::new(
        DidCoreId::new(format!("ak:did_core:web:{name}.example")).unwrap(),
        DidCoreId::new("ak:did_core:web:coland.example").unwrap(),
    )
}

fn input(
    holder: &AccountId,
    requester: &AccountId,
    scope: ConsentRequestScope,
) -> ConsentRequestQuarantineInput {
    let mut quota_constraints = NewSourceQuotaConstraints::default();
    quota_constraints.default_source_count_per_window = Some(1);
    quota_constraints.max_source_count_per_window = Some(1);
    ConsentRequestQuarantineInput {
        holder: holder.clone(),
        acceptor_service_id: holder.station_id.clone(),
        requester: requester.clone(),
        consent_scope: scope,
        received_at: Utc::now(),
        quota_constraints,
    }
}

async fn holder_fixture() -> (TestDatabase, PgPool, AccountId) {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let fixture = pcr_genesis::PcrGenesisFixture::new(
        arkret_wire::Did::new("did:web:coland.example").unwrap(),
    );
    let holder = fixture.history.account.clone();
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query("INSERT INTO device_inventory_station(singleton,station_id) VALUES(TRUE,$1)")
        .bind::<diesel::sql_types::Text, _>(holder.station_id.as_str())
        .execute(&mut conn)
        .await
        .unwrap();
    drop(conn);
    fixture
        .admit_founding_device(&coland_storage_postgres::PgPersistenceStore::new(
            pool.clone(),
        ))
        .await
        .unwrap();
    let accounts = PgAccountStore { pool: pool.clone() };
    accounts
        .put(&AccountRecord {
            pk: AccountPk(0),
            principal_id: holder.principal_id.clone(),
            station_id: holder.station_id.clone(),
            localpart: String::new(),
            display_name: None,
            biography: None,
            avatar_blob_ref: None,
            created_at: Utc::now(),
        })
        .await
        .unwrap();
    (database, pool, holder)
}

#[tokio::test]
async fn consent_request_quarantine_charges_and_writes_in_one_cut_or_nothing() {
    let (_database, pool, holder) = holder_fixture().await;
    let first = account("consent-request-first");
    let second = account("consent-request-second");
    let store = PgConsentRequestQuarantineStore { pool: pool.clone() };
    let first_input = input(&holder, &first, ConsentRequestScope::VideoCall);
    let outcome = store.admit(first_input).await.unwrap();
    let ConsentRequestQuarantineOutcome::Queued(row) = outcome else {
        panic!("first Consent request must queue")
    };
    assert_eq!(row.revision, 1);
    let cell: HolderQuarantine = serde_json::from_value(row.payload).unwrap();
    let pending: Vec<_> = cell
        .entries_for(HolderQuarantineSurfaceKind::ConsentRequest)
        .collect();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].source_peer_principal_id, first.principal_id);
    assert_eq!(
        pending[0].source_peer_actor_id,
        arkret_wire::ActorId::account(first.clone())
    );
    assert!(pending[0].surface.invite_event_id().is_none());
    assert_eq!(count(&pool, "ledger").await, 1);
    assert_eq!(count(&pool, "changes").await, 1);

    assert!(matches!(
        store
            .admit(input(&holder, &first, ConsentRequestScope::VideoCall))
            .await
            .unwrap(),
        ConsentRequestQuarantineOutcome::AlreadyPending
    ));
    assert_eq!(count(&pool, "ledger").await, 1);
    assert_eq!(count(&pool, "changes").await, 1);

    assert!(matches!(
        store
            .admit(input(&holder, &second, ConsentRequestScope::VideoCall))
            .await
            .unwrap(),
        ConsentRequestQuarantineOutcome::Dropped
    ));
    assert_eq!(count(&pool, "ledger").await, 1);
    assert_eq!(count(&pool, "changes").await, 1);

    // A second scope from the already charged source gets one more live entry,
    // with no second source charge.
    let outcome = store
        .admit(input(&holder, &first, ConsentRequestScope::VoiceCall))
        .await
        .unwrap();
    assert!(matches!(
        outcome,
        ConsentRequestQuarantineOutcome::Queued(_)
    ));
    let row = PgAccountDataStore { pool: pool.clone() }
        .get(
            &arkret_wire::ActorId::account(holder.clone()).to_string(),
            AccountDataKey::ACCOUNT_HOLDER_QUARANTINE,
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.revision, 2);
    assert_eq!(count(&pool, "ledger").await, 1);
    assert_eq!(count(&pool, "changes").await, 2);

    let mut policy = InviteReceivePolicy::spec_default(holder.clone());
    policy.consent_profile = ConsentProfile::RequireExplicitConsent;
    PgInviteReceivePolicyStore { pool: pool.clone() }
        .put(&holder, &policy)
        .await
        .unwrap();
    assert!(matches!(
        store
            .admit(input(&holder, &second, ConsentRequestScope::Presence))
            .await
            .unwrap(),
        ConsentRequestQuarantineOutcome::Dropped
    ));
    assert_eq!(count(&pool, "ledger").await, 1);
    assert_eq!(count(&pool, "changes").await, 2);

    assert!(matches!(
        store
            .admit(input(
                &account("consent-request-missing"),
                &second,
                ConsentRequestScope::Presence
            ))
            .await
            .unwrap(),
        ConsentRequestQuarantineOutcome::Dropped
    ));
    assert_eq!(count(&pool, "ledger").await, 1);
    assert_eq!(count(&pool, "changes").await, 2);
}

#[tokio::test]
async fn quarantine_dedup_keeps_station_accounts_distinct_without_changing_principal_quota() {
    let (_database, pool, holder) = holder_fixture().await;
    let first = account("consent-request-shared-principal");
    let other = AccountId::new(
        first.principal_id.clone(),
        DidCoreId::new("ak:did_core:web:other-station.example").unwrap(),
    );
    let store = PgConsentRequestQuarantineStore { pool: pool.clone() };
    for (requester, revision) in [(&first, 1), (&other, 2)] {
        let ConsentRequestQuarantineOutcome::Queued(row) = store
            .admit(input(&holder, requester, ConsentRequestScope::VideoCall))
            .await
            .unwrap()
        else {
            panic!("a different exact source must retain its own pending entry")
        };
        assert_eq!(row.revision, revision);
        assert!(matches!(
            store
                .admit(input(&holder, requester, ConsentRequestScope::VideoCall))
                .await
                .unwrap(),
            ConsentRequestQuarantineOutcome::AlreadyPending
        ));
    }
    let row = PgAccountDataStore { pool: pool.clone() }
        .get(
            &arkret_wire::ActorId::account(holder.clone()).to_string(),
            AccountDataKey::ACCOUNT_HOLDER_QUARANTINE,
        )
        .await
        .unwrap()
        .unwrap();
    let cell: HolderQuarantine = serde_json::from_value(row.payload).unwrap();
    let pending: Vec<_> = cell
        .entries_for(HolderQuarantineSurfaceKind::ConsentRequest)
        .collect();
    assert_eq!(pending.len(), 2);
    for requester in [&first, &other] {
        assert!(
            pending.iter().any(|entry| entry.source_peer_actor_id
                == arkret_wire::ActorId::account(requester.clone()))
        );
    }
    assert!(
        pending
            .iter()
            .all(|entry| entry.source_peer_principal_id == first.principal_id)
    );
    assert_eq!(count(&pool, "ledger").await, 1);
    assert_eq!(count(&pool, "changes").await, 2);
    assert!(matches!(
        store
            .admit(input(
                &holder,
                &account("consent-request-new-principal"),
                ConsentRequestScope::VideoCall
            ))
            .await
            .unwrap(),
        ConsentRequestQuarantineOutcome::Dropped
    ));
    assert_eq!(count(&pool, "ledger").await, 1);
    assert_eq!(count(&pool, "changes").await, 2);
}
