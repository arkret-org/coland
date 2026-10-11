//! Real PCR signatures, exact revisions and rollback for Consent admission.

#[path = "../../test-support/src/device_authorization_history.rs"]
#[expect(
    dead_code,
    reason = "This integration binary uses only its subset of the shared device history fixture."
)]
mod device_authorization_history;
#[path = "../../test-support/src/pcr_genesis.rs"]
#[expect(
    dead_code,
    reason = "This integration binary uses only its subset of the shared PCR fixture."
)]
mod pcr_genesis;

use arkret_models_collaboration::consent_operations::ConsentState;
use arkret_wire::{
    ActorId, DetachedSignatureContext, Did, DidUrl, EventKind, RealmCommit, RealmCommitId,
};
use coland_storage::{
    AuthorityCommitStore, AuthorityCommitTransaction, ConsentAdmissionOutcome,
    ConsentAdmissionWrite, ConsentCurrentStore,
};
use coland_storage_postgres::test_database::TestDatabase;
use coland_storage_postgres::{
    PgAuthorityCommitStore, PgConsentCurrentStore, PgPersistenceStore, PgPool,
};
use diesel::sql_types::{Jsonb, Text};
use diesel_async::RunQueryDsl;
use ed25519_dalek::SigningKey;

async fn fixture(pool: &PgPool) -> pcr_genesis::PcrGenesisFixture {
    let fixture = pcr_genesis::PcrGenesisFixture::new(Did::new("did:web:coland.example").unwrap());
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query("INSERT INTO device_inventory_station(singleton,station_id) VALUES(TRUE,$1) ON CONFLICT(singleton) DO NOTHING")
        .bind::<Text,_>(fixture.history.account.station_id.as_str()).execute(&mut conn).await.unwrap();
    drop(conn);
    fixture
        .admit_founding_device(&PgPersistenceStore::new(pool.clone()))
        .await
        .unwrap();
    fixture
}

fn write(
    f: &pcr_genesis::PcrGenesisFixture,
    previous: &RealmCommit,
    kind: EventKind,
    payload: serde_json::Value,
) -> ConsentAdmissionWrite {
    let at = previous.committed_at + chrono::TimeDelta::seconds(1);
    let mut event = arkret_wire::test_support::raw_event_at(
        kind.as_str(),
        arkret_wire::ScopeRef::Realm {
            realm_id: previous.realm_id.clone(),
        },
        f.history.account.principal_id.clone(),
        f.history.account.station_id.clone(),
        payload,
        at,
    )
    .unwrap();
    event.authorization_ref = Some(f.unit.transactions[0].event.event_id.clone().into());
    event = device_authorization_history::sign_event(
        event,
        f.history.device_verification_method.clone(),
        f.history.founding_device_signing_seed,
    );
    let mut commit = previous.clone();
    commit.event_ref = event.event_id.clone();
    commit.stream_position += 1;
    commit.previous_commit_ref = Some(previous.commit_id.clone());
    commit.committed_at = at;
    let identity =
        arkret_canonical::canonical::unsigned_value(&commit, &["commit_id", "signature"]).unwrap();
    commit.commit_id = RealmCommitId::from_digest(arkret_canonical::sha256_bytes(
        &arkret_canonical::canonical_json_bytes(&identity).unwrap(),
    ));
    let unsigned = arkret_canonical::canonical::unsigned_value(&commit, &["signature"]).unwrap();
    commit.signature = arkret_signatures::detached_object::sign_detached_object(
        &unsigned,
        DetachedSignatureContext::RealmCommit,
        DidUrl::new("did:web:coland.example#authority").unwrap(),
        at,
        &SigningKey::from_bytes(&device_authorization_history::STATION_AUTHORITY_SEED),
    )
    .unwrap();
    ConsentAdmissionWrite {
        transaction: AuthorityCommitTransaction {
            expected_authority: f.unit.transactions[1].expected_authority.clone(),
            event,
            commit,
            producer_signer_fact: None,
            mls_state: None,
            welcomes: Vec::new(),
            recipient_queue_capacity: 0,
        },
    }
}

fn grant(id: &str, peer: &ActorId, scope: &str) -> serde_json::Value {
    serde_json::json!({"consent_id":id,"peer":{"kind":"actor","actor_id":peer},"consent_scope":scope})
}

#[derive(diesel::QueryableByName, Debug, PartialEq)]
struct Footprint {
    #[diesel(sql_type=Jsonb)]
    footprint: serde_json::Value,
}
async fn footprint(pool: &PgPool) -> Footprint {
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query("SELECT jsonb_build_array((SELECT count(*) FROM canonical_events),(SELECT count(*) FROM realm_commits),(SELECT jsonb_agg(to_jsonb(r) ORDER BY consent_id) FROM consent_current_results r),(SELECT count(*) FROM consent_result_versions),(SELECT count(*) FROM account_data_changes)) AS footprint").get_result(&mut conn).await.unwrap()
}

#[tokio::test]
async fn consent_current_is_create_once_exact_cas_and_replay_preserves_original_view() {
    let db = TestDatabase::lease().await;
    let pool = db.pool();
    let f = fixture(&pool).await;
    let store = PgConsentCurrentStore { pool: pool.clone() };
    let peer = ActorId::account(f.history.account.clone());
    let id = "ak:consent:01964137-0000-7000-8000-000000000021";
    let original = write(
        &f,
        &f.unit.transactions[1].commit,
        EventKind::ConsentGrant,
        grant(id, &peer, "invite"),
    );
    let ConsentAdmissionOutcome::Committed(record) = store.admit(original.clone()).await.unwrap()
    else {
        panic!("new grant")
    };
    assert_eq!(record.value.status, ConsentState::Active);
    let before = footprint(&pool).await;
    let ConsentAdmissionOutcome::Duplicate(replayed) = store.admit(original.clone()).await.unwrap()
    else {
        panic!("exact replay")
    };
    assert_eq!(replayed.view(), record.view());
    assert_eq!(footprint(&pool).await, before);
    let rebind = write(
        &f,
        &record.commit,
        EventKind::ConsentGrant,
        grant(id, &peer, "presence"),
    );
    assert!(
        store
            .admit(rebind)
            .await
            .unwrap_err()
            .to_string()
            .contains("failed_precondition")
    );
    assert_eq!(footprint(&pool).await, before);
    let stale = write(
        &f,
        &record.commit,
        EventKind::ConsentRevoke,
        serde_json::json!({"consent_id":id,"expected_revision":{"commit_id":f.unit.transactions[1].commit.commit_id,"stream_position":1}}),
    );
    assert!(
        store
            .admit(stale)
            .await
            .unwrap_err()
            .to_string()
            .contains("cas_conflict")
    );
    assert_eq!(footprint(&pool).await, before);
    let revoke = write(
        &f,
        &record.commit,
        EventKind::ConsentRevoke,
        serde_json::json!({"consent_id":id,"expected_revision":record.view().revision,"reason":"holder_request"}),
    );
    let ConsentAdmissionOutcome::Committed(revoked) = store.admit(revoke.clone()).await.unwrap()
    else {
        panic!("revoke")
    };
    assert_eq!(revoked.value.status, ConsentState::Revoked);
    assert_eq!(
        revoked.value.revoked_at,
        Some(revoke.transaction.event.created_at)
    );
    let ConsentAdmissionOutcome::Duplicate(old_grant) = store.admit(original).await.unwrap() else {
        panic!("grant replay")
    };
    assert_eq!(old_grant.value.status, ConsentState::Active);
    assert_eq!(
        store.list(&f.history.account).await.unwrap()[0]
            .value
            .status,
        ConsentState::Revoked
    );
    let before = footprint(&pool).await;
    let repeated = write(
        &f,
        &revoked.commit,
        EventKind::ConsentRevoke,
        serde_json::json!({"consent_id":id,"expected_revision":revoked.view().revision}),
    );
    assert!(
        store
            .admit(repeated)
            .await
            .unwrap_err()
            .to_string()
            .contains("failed_precondition")
    );
    assert_eq!(footprint(&pool).await, before);
    let rebuilt = PgConsentCurrentStore { pool: pool.clone() };
    assert_eq!(
        rebuilt.list(&f.history.account).await.unwrap()[0].view(),
        revoked.view()
    );
}

#[tokio::test]
async fn consent_current_rejects_wrong_root_and_concurrent_head_loser_without_writes() {
    let db = TestDatabase::lease().await;
    let pool = db.pool();
    let f = fixture(&pool).await;
    let store = PgConsentCurrentStore { pool: pool.clone() };
    let peer = ActorId::account(f.history.account.clone());
    let a = write(
        &f,
        &f.unit.transactions[1].commit,
        EventKind::ConsentGrant,
        grant(
            "ak:consent:01964137-0000-7000-8000-000000000022",
            &peer,
            "any",
        ),
    );
    let b = write(
        &f,
        &f.unit.transactions[1].commit,
        EventKind::ConsentGrant,
        grant(
            "ak:consent:01964137-0000-7000-8000-000000000023",
            &peer,
            "invite",
        ),
    );
    let before = footprint(&pool).await;
    let mut bad_signature = a.clone();
    bad_signature.transaction.event = device_authorization_history::sign_event(
        bad_signature.transaction.event,
        f.history.device_verification_method.clone(),
        [7; 32],
    );
    assert!(
        store
            .admit(bad_signature)
            .await
            .unwrap_err()
            .to_string()
            .contains("signature_invalid")
    );
    assert_eq!(footprint(&pool).await, before);
    let mut wrong = a.clone();
    wrong.transaction.event.authorization_ref =
        Some(f.unit.transactions[1].event.event_id.clone().into());
    wrong.transaction.event = device_authorization_history::sign_event(
        wrong.transaction.event,
        f.history.device_verification_method.clone(),
        f.history.founding_device_signing_seed,
    );
    wrong.transaction.commit.event_ref = wrong.transaction.event.event_id.clone();
    let unsigned =
        arkret_canonical::canonical::unsigned_value(&wrong.transaction.commit, &["signature"])
            .unwrap();
    wrong.transaction.commit.signature = arkret_signatures::detached_object::sign_detached_object(
        &unsigned,
        DetachedSignatureContext::RealmCommit,
        DidUrl::new("did:web:coland.example#authority").unwrap(),
        wrong.transaction.commit.committed_at,
        &SigningKey::from_bytes(&device_authorization_history::STATION_AUTHORITY_SEED),
    )
    .unwrap();
    assert!(
        store
            .admit(wrong)
            .await
            .unwrap_err()
            .to_string()
            .contains("capability_denied")
    );
    assert_eq!(footprint(&pool).await, before);
    let (left, right) = tokio::join!(store.admit(a), store.admit(b));
    assert_ne!(left.is_ok(), right.is_ok());
    assert_eq!(store.list(&f.history.account).await.unwrap().len(), 1);
    let head = PgAuthorityCommitStore { pool: pool.clone() }
        .held_stream_head_commit(&f.unit.transactions[1].commit.stream_ref)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        head.stream_position,
        f.unit.transactions[1].commit.stream_position + 1
    );
}

#[tokio::test]
async fn consent_any_revoke_preserves_concrete_grant_and_invalidates_quarantine_in_same_cut() {
    use arkret_models_collaboration::governance::holder_quarantine::{
        HolderQuarantine, HolderQuarantineEntry, HolderQuarantineSurface,
    };
    use arkret_wire::{
        AccountDataKey, AccountId, ConsentRequestScope, ConsentScope, DidCoreId, Hash,
    };
    use coland_storage::{AccountDataRecord, AccountDataStore};
    let db = TestDatabase::lease().await;
    let pool = db.pool();
    let f = fixture(&pool).await;
    let store = PgConsentCurrentStore { pool: pool.clone() };
    let peer_account = AccountId::new(
        DidCoreId::new("ak:did_core:web:consent-peer.example").unwrap(),
        f.history.account.station_id.clone(),
    );
    let peer = ActorId::account(peer_account.clone());
    let any_id = "ak:consent:01964137-0000-7000-8000-000000000024";
    let concrete_id = "ak:consent:01964137-0000-7000-8000-000000000025";
    let any = write(
        &f,
        &f.unit.transactions[1].commit,
        EventKind::ConsentGrant,
        grant(any_id, &peer, "any"),
    );
    let ConsentAdmissionOutcome::Committed(any) = store.admit(any).await.unwrap() else {
        panic!("any grant")
    };
    assert!(any.permits(&peer, ConsentScope::VoiceCall, any.commit.committed_at));
    let concrete = write(
        &f,
        &any.commit,
        EventKind::ConsentGrant,
        grant(concrete_id, &peer, "voice_call"),
    );
    let ConsentAdmissionOutcome::Committed(concrete) = store.admit(concrete).await.unwrap() else {
        panic!("concrete grant")
    };
    let actor = ActorId::account(f.history.account.clone()).to_string();
    let mut cell = HolderQuarantine::new(concrete.commit.committed_at);
    let entry = HolderQuarantineEntry {
        entry_digest: Hash::new(arkret_canonical::sha256_digest(b"pending consent peer")).unwrap(),
        account_id: f.history.account.clone(),
        source_peer_principal_id: peer_account.principal_id.clone(),
        source_id: peer_account.station_id.clone(),
        surface: HolderQuarantineSurface::ConsentRequest {
            consent_scope: ConsentRequestScope::VideoCall,
        },
        received_at: concrete.commit.committed_at,
        expires_at: concrete.commit.committed_at + chrono::TimeDelta::days(1),
    };
    cell.quarantine_entries.push(entry);
    let accounts = coland_storage_postgres::PgAccountDataStore { pool: pool.clone() };
    accounts
        .compare_and_set(
            &AccountDataRecord {
                actor: actor.clone(),
                account_data_key: AccountDataKey::ACCOUNT_HOLDER_QUARANTINE.to_owned(),
                revision: 1,
                payload: serde_json::to_value(&cell).unwrap(),
                tombstone: false,
                updated_at: cell.updated_at,
            },
            0,
        )
        .await
        .unwrap();
    let revoke = write(
        &f,
        &concrete.commit,
        EventKind::ConsentRevoke,
        serde_json::json!({"consent_id":any_id,"expected_revision":any.view().revision}),
    );
    let ConsentAdmissionOutcome::Committed(revoked) = store.admit(revoke.clone()).await.unwrap()
    else {
        panic!("revoke any")
    };
    assert!(!revoked.permits(&peer, ConsentScope::VideoCall, revoked.commit.committed_at));
    assert_eq!(revoked.quarantine_update.as_ref().unwrap().revision, 2);
    let row = accounts
        .get(&actor, AccountDataKey::ACCOUNT_HOLDER_QUARANTINE)
        .await
        .unwrap()
        .unwrap();
    let cell: HolderQuarantine = serde_json::from_value(row.payload).unwrap();
    assert!(cell.quarantine_entries.is_empty());
    assert_eq!(cell.last_invalidation.unwrap().removed_entries, 1);
    let list = store.list(&f.history.account).await.unwrap();
    let concrete = list
        .iter()
        .find(|r| r.value.consent_id.as_str() == concrete_id)
        .unwrap();
    assert!(concrete.permits(&peer, ConsentScope::VoiceCall, revoked.commit.committed_at));
    assert_eq!(concrete.value.status, ConsentState::Active);
    let mut cross_station = peer_account.clone();
    cross_station.station_id = DidCoreId::new("ak:did_core:web:other-station.example").unwrap();
    assert!(!concrete.permits(
        &ActorId::account(cross_station),
        ConsentScope::VoiceCall,
        revoked.commit.committed_at
    ));
    let ConsentAdmissionOutcome::Duplicate(replay) = store.admit(revoke).await.unwrap() else {
        panic!("replay revoke")
    };
    assert!(replay.quarantine_update.is_none());
    assert_eq!(
        accounts
            .get(&actor, AccountDataKey::ACCOUNT_HOLDER_QUARANTINE)
            .await
            .unwrap()
            .unwrap()
            .revision,
        2
    );
}

#[tokio::test]
async fn consent_current_guards_invite_delivery_cas_and_rejects_a_pre_revoke_proof() {
    use arkret_models_collaboration::governance::invite_addressing::InviteDelivery;
    use coland_storage::{AccountDataCasResult, AccountDataRecord, ConsentDeliveryWrite};
    let db = TestDatabase::lease().await;
    let pool = db.pool();
    let f = fixture(&pool).await;
    let store = PgConsentCurrentStore { pool: pool.clone() };
    let peer = ActorId::account(f.history.account.clone());
    let id = "ak:consent:01964137-0000-7000-8000-000000000026";
    let grant = write(
        &f,
        &f.unit.transactions[1].commit,
        EventKind::ConsentGrant,
        grant(id, &peer, "invite"),
    );
    let ConsentAdmissionOutcome::Committed(active) = store.admit(grant).await.unwrap() else {
        panic!("grant")
    };
    let at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    let delivery = ConsentDeliveryWrite {
        holder: f.history.account.clone(),
        peer: peer.clone(),
        consent_grant_ref: active.event.event_id.clone(),
        consent_id: Some(active.value.consent_id.clone()),
        record: AccountDataRecord {
            actor: ActorId::account(f.history.account.clone()).to_string(),
            account_data_key: arkret_wire::AccountDataKey::ACCOUNT_INVITE_DELIVERY.to_owned(),
            revision: 1,
            payload: serde_json::to_value(InviteDelivery::new(at, vec![])).unwrap(),
            tombstone: false,
            updated_at: at,
        },
        expected_revision: 0,
    };
    let before = footprint(&pool).await;
    let mut wrong_peer = delivery.clone();
    wrong_peer.peer = ActorId::account(arkret_wire::AccountId::new(
        f.history.account.principal_id.clone(),
        "ak:did_core:web:other-station.example".parse().unwrap(),
    ));
    assert!(
        store
            .admit_invite_delivery(wrong_peer)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(footprint(&pool).await, before);
    assert!(matches!(
        store.admit_invite_delivery(delivery.clone()).await.unwrap(),
        Some(AccountDataCasResult::Applied(_))
    ));
    let before = footprint(&pool).await;
    assert!(matches!(
        store.admit_invite_delivery(delivery.clone()).await.unwrap(),
        Some(AccountDataCasResult::Conflict(_))
    ));
    assert_eq!(footprint(&pool).await, before);
    let revoke = write(
        &f,
        &active.commit,
        EventKind::ConsentRevoke,
        serde_json::json!({"consent_id":id,"expected_revision":active.view().revision}),
    );
    store.admit(revoke).await.unwrap();
    // The caller already read active and prepared its write before Revoke.
    // Admission must recheck under the shared PCR lock before private CAS.
    let mut in_flight = delivery;
    in_flight.expected_revision = 1;
    in_flight.record.revision = 2;
    let before = footprint(&pool).await;
    assert!(
        store
            .admit_invite_delivery(in_flight)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(footprint(&pool).await, before);
}
