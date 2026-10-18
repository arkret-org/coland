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
    let historical = store
        .historical_basis(
            &f.history.account,
            &record.value.consent_id,
            &record.view().revision,
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(historical.event, record.event);
    assert_eq!(historical.commit, record.commit);
    assert!(
        store
            .historical_basis(
                &f.history.account,
                &record.value.consent_id,
                &revoked.view().revision
            )
            .await
            .unwrap()
            .is_none()
    );
    let mut wrong = record.view().revision;
    wrong.stream_position -= 1;
    assert!(
        store
            .historical_basis(&f.history.account, &record.value.consent_id, &wrong)
            .await
            .unwrap()
            .is_none()
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
        acceptor_service_id: f.history.account.station_id.clone(),
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

#[tokio::test]
async fn private_commands_and_scoped_native_import_preserve_one_authority_cut() {
    use arkret_models_collaboration::consent_private::*;
    use arkret_models_collaboration::governance::invite_addressing::InviteReceivePolicy;
    use coland_storage::{AccountPk, AccountRecord, AccountStore, InviteNewSourceLedgerStore};
    use coland_storage_postgres::{PgAccountStore, PgInviteNewSourceLedgerStore};
    let db = TestDatabase::lease().await;
    let pool = db.pool();
    let f = fixture(&pool).await;
    let holder = f.history.account.clone();
    let accounts = PgAccountStore { pool: pool.clone() };
    accounts
        .put(&AccountRecord {
            pk: AccountPk(0),
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
    let store = PgConsentCurrentStore { pool: pool.clone() };
    let authority = PgAuthorityCommitStore { pool: pool.clone() };
    let mut request = ConsentPrivateProxyRequest {
        holder_account_id: holder.clone(),
        realm_id: f.unit.transactions[1].event.realm_id.clone(),
        governance_generation: 0,
        nonce: arkret_canonical::base64url_encode([21; 32]),
        expires_at: arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now())
            + chrono::Duration::seconds(30),
        context: ConsentPrivateContext::HolderSession(ConsentPrivateHolderSessionContext {
            kind: ConsentPrivateHolderSessionContextKind::HolderSession,
            actor_id: ActorId::account(holder.clone()),
            device_id: f.history.founding_device_id.clone(),
        }),
        command: ConsentPrivateCommand::InvitePolicy(ConsentPrivateInvitePolicyCommand {
            kind: ConsentPrivateInvitePolicyCommandKind::InvitePolicy,
            body: InviteReceivePolicy::spec_default(holder.clone()),
        }),
    };
    let quota = arkret_wire::NewSourceQuotaConstraints::default();
    let first = store
        .private_command(&request, &holder.station_id, &holder.station_id, &quota)
        .await
        .unwrap();
    assert_eq!(
        first,
        store
            .private_command(&request, &holder.station_id, &holder.station_id, &quota)
            .await
            .unwrap()
    );
    store.observe_private_cut(&request, &first).await.unwrap();
    let mut rollback = first.clone();
    rollback.effective_stream_head.stream_position -= 1;
    assert!(
        store
            .observe_private_cut(&request, &rollback)
            .await
            .is_err()
    );
    let mut fork = first.clone();
    fork.effective_stream_head.commit_id = RealmCommitId::from_digest([99; 32]);
    assert!(store.observe_private_cut(&request, &fork).await.is_err());
    let mut rebound = request.clone();
    if let ConsentPrivateCommand::InvitePolicy(policy) = &mut rebound.command {
        policy.body.holder_allowed_introduction_kinds.clear();
    }
    assert!(
        store
            .private_command(&rebound, &holder.station_id, &holder.station_id, &quota)
            .await
            .is_err()
    );
    let wrong: arkret_wire::DidCoreId = "ak:did_core:web:other-authority.example".parse().unwrap();
    assert!(
        store
            .private_command(&request, &holder.station_id, &wrong, &quota)
            .await
            .is_err()
    );
    assert!(authority.export_pcr_private_state(&holder).await.is_err());
    let tag = PgInviteNewSourceLedgerStore { pool: pool.clone() }
        .source_digest(&holder, &holder.principal_id)
        .await
        .unwrap();
    let change = write(
        &f,
        &f.unit.transactions[1].commit,
        EventKind::RealmGovernanceStationChange,
        serde_json::json!({"expected_governance_generation":0,"expected_realm_stream_commit_id":f.unit.transactions[1].commit.commit_id,"new_governance_station_id":wrong}),
    );
    assert!(matches!(
        authority
            .admit_pcr_governance_change(&change.transaction)
            .await
            .unwrap(),
        coland_storage::AuthorityCommitWriteOutcome::Committed
    ));
    request.nonce = arkret_canonical::base64url_encode([22; 32]);
    assert!(
        store
            .private_command(&request, &holder.station_id, &holder.station_id, &quota)
            .await
            .is_err()
    );
    let (manifest, bytes) = authority.export_pcr_private_state(&holder).await.unwrap();
    let target_db = TestDatabase::lease().await;
    let target_pool = target_db.pool();
    let other = arkret_wire::AccountId::new(wrong.clone(), wrong.clone());
    let target_accounts = PgAccountStore {
        pool: target_pool.clone(),
    };
    target_accounts
        .put(&AccountRecord {
            pk: AccountPk(0),
            principal_id: other.principal_id.clone(),
            station_id: other.station_id.clone(),
            localpart: String::new(),
            display_name: None,
            bio: None,
            avatar_blob_ref: None,
            created_at: chrono::Utc::now(),
        })
        .await
        .unwrap();
    let target = PgAuthorityCommitStore {
        pool: target_pool.clone(),
    };
    let before = footprint(&target_pool).await;
    let mut bad = manifest.clone();
    bad.state_digest = arkret_wire::Hash::new(arkret_canonical::sha256_digest(b"wrong")).unwrap();
    assert!(target.import_pcr_private_state(&bad, &bytes).await.is_err());
    assert_eq!(before, footprint(&target_pool).await);
    target
        .import_pcr_private_state(&manifest, &bytes)
        .await
        .unwrap();
    let (imported, reexported) = target.export_pcr_private_state(&holder).await.unwrap();
    assert_eq!(imported.state_digest, manifest.state_digest);
    assert_eq!(reexported, bytes);
    assert!(target_accounts.get(&other).await.unwrap().is_some());
    assert_eq!(
        PgInviteNewSourceLedgerStore {
            pool: target_pool.clone()
        }
        .source_digest(&holder, &holder.principal_id)
        .await
        .unwrap(),
        tag
    );
    assert!(
        PgConsentCurrentStore {
            pool: target_pool.clone()
        }
        .private_command(&request, &holder.station_id, &wrong, &quota)
        .await
        .is_err()
    );
    let mut material = authority
        .realm_state_snapshot_material(&manifest.realm_id)
        .await
        .unwrap()
        .unwrap();
    material
        .visible_stream_heads
        .sort_by(|a, b| a.stream_ref.cmp(&b.stream_ref));
    let at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    let old_key = SigningKey::from_bytes(&device_authorization_history::STATION_AUTHORITY_SEED);
    let new_key = SigningKey::from_bytes(&[41; 32]);
    let old_method = DidUrl::new("did:web:coland.example#authority").unwrap();
    let new_method = DidUrl::new("did:web:other-authority.example#authority").unwrap();
    let snapshot = coland_services::authority_commit::build_signed_realm_state_snapshot(
        &material,
        old_method.clone(),
        &old_key,
        at,
    )
    .unwrap();
    let mut handoff = arkret_wire::RealmAuthorityHandoff {
        handoff_id: arkret_wire::RealmAuthorityHandoffId::from_digest([42; 32]),
        realm_id: manifest.realm_id.clone(),
        from_generation: 0,
        to_generation: 1,
        from_service_id: holder.station_id.clone(),
        to_service_id: wrong.clone(),
        change_event_ref: change.transaction.event.event_id.clone(),
        change_commit_id: change.transaction.commit.commit_id.clone(),
        final_stream_heads_digest: arkret_wire::Hash::new(
            arkret_canonical::canonical_sha256(&material.visible_stream_heads).unwrap(),
        )
        .unwrap(),
        historical_signer_facts_digest: Some(
            arkret_models_collaboration::authority_commit::historical_signer_facts_digest(&[])
                .unwrap(),
        ),
        pcr_private_state_digest: Some(manifest.digest().unwrap()),
        snapshot_ref: snapshot.snapshot_id.clone(),
        old_authority_signature: change.transaction.commit.signature.clone(),
        new_authority_acceptance_signature: change.transaction.commit.signature.clone(),
    };
    let unsigned = arkret_canonical::unsigned_value(
        &handoff,
        &[
            "old_authority_signature",
            "new_authority_acceptance_signature",
        ],
    )
    .unwrap();
    handoff.old_authority_signature = arkret_signatures::detached_object::sign_detached_object(
        &unsigned,
        DetachedSignatureContext::RealmAuthorityHandoffOld,
        old_method,
        at,
        &old_key,
    )
    .unwrap();
    handoff.new_authority_acceptance_signature =
        arkret_signatures::detached_object::sign_detached_object(
            &unsigned,
            DetachedSignatureContext::RealmAuthorityHandoffNewAcceptance,
            new_method,
            at,
            &new_key,
        )
        .unwrap();
    // The old ordinary bootstrap reader has no native PCR purpose projection.
    // Applicability is proved by the accepted stream-zero genesis original.
    assert!(
        target
            .install_handoff(&handoff, &material.visible_stream_heads, &snapshot)
            .await
            .is_err()
    );
    target
        .install_handoff_with_private_state(
            &handoff,
            &material.visible_stream_heads,
            &snapshot,
            Some(&manifest),
        )
        .await
        .unwrap();
    target
        .install_handoff_with_private_state(
            &handoff,
            &material.visible_stream_heads,
            &snapshot,
            Some(&manifest),
        )
        .await
        .unwrap();
    request.governance_generation = 1;
    request.command = ConsentPrivateCommand::List(ConsentPrivateListCommand {
        kind: ConsentPrivateListCommandKind::List,
        body: ConsentPrivateEmptyBody {},
    });
    assert_eq!(
        PgConsentCurrentStore {
            pool: target_pool.clone()
        }
        .private_command(&request, &holder.station_id, &wrong, &quota)
        .await
        .unwrap()
        .governance_generation,
        1
    );
}

#[tokio::test]
async fn private_effect_publication_is_atomic_recoverable_and_rejects_rebinding() {
    use arkret_models_collaboration::consent_private::*;
    use arkret_models_collaboration::governance::invite_addressing::InviteReceivePolicy;
    use coland_storage::{AccountPk, AccountRecord, AccountStore};
    use coland_storage_postgres::PgAccountStore;
    let db = TestDatabase::lease().await;
    let pool = db.pool();
    let f = fixture(&pool).await;
    let holder = f.history.account.clone();
    PgAccountStore { pool: pool.clone() }
        .put(&AccountRecord {
            pk: AccountPk(0),
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
    let store = PgConsentCurrentStore { pool: pool.clone() };
    let mut request = ConsentPrivateProxyRequest {
        holder_account_id: holder.clone(),
        realm_id: f.unit.transactions[1].event.realm_id.clone(),
        governance_generation: 0,
        nonce: arkret_canonical::base64url_encode([71; 32]),
        expires_at: arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now())
            + chrono::Duration::seconds(30),
        context: ConsentPrivateContext::HolderSession(ConsentPrivateHolderSessionContext {
            kind: ConsentPrivateHolderSessionContextKind::HolderSession,
            actor_id: ActorId::account(holder.clone()),
            device_id: f.history.founding_device_id.clone(),
        }),
        command: ConsentPrivateCommand::InvitePolicy(ConsentPrivateInvitePolicyCommand {
            kind: ConsentPrivateInvitePolicyCommandKind::InvitePolicy,
            body: InviteReceivePolicy::spec_default(holder.clone()),
        }),
    };
    store
        .private_command(
            &request,
            &holder.station_id,
            &holder.station_id,
            &Default::default(),
        )
        .await
        .unwrap();
    assert_eq!(
        store
            .pending_effect_holders(&holder.station_id)
            .await
            .unwrap(),
        vec![holder.clone()]
    );
    let first = store
        .prepare_effect_publication(
            &holder,
            &holder.station_id,
            arkret_canonical::base64url_encode([72; 32]),
        )
        .await
        .unwrap()
        .unwrap();
    let authority = PgAuthorityCommitStore { pool: pool.clone() }
        .current_authority(&request.realm_id)
        .await
        .unwrap()
        .unwrap();
    let apply = |publication: ConsentPrivateEffectsPublishRequest| {
        let store = PgConsentCurrentStore { pool: pool.clone() };
        let holder = holder.clone();
        let authority = authority.clone();
        async move {
            store
                .project_effect_publication(
                    &publication,
                    &holder.station_id,
                    &holder.station_id,
                    &authority,
                    &publication.effective_stream_head,
                )
                .await
        }
    };
    let original = apply(first.request.clone()).await.unwrap();
    assert!(original.updates.is_empty());
    assert_eq!(
        apply(first.request.clone()).await.unwrap().outcome,
        original.outcome
    );
    let mut fork = first.request.clone();
    fork.effects
        .invite_receive_policy
        .as_mut()
        .unwrap()
        .content
        .holder_allowed_introduction_kinds
        .clear();
    assert!(apply(fork).await.is_err());
    let mut expired = first.request.clone();
    expired.expires_at = expired.evaluated_at - chrono::Duration::seconds(1);
    assert!(apply(expired).await.is_err());
    let mut wrong_generation = first.request.clone();
    wrong_generation.governance_generation = 1;
    assert!(apply(wrong_generation).await.is_err());
    request.nonce = arkret_canonical::base64url_encode([73; 32]);
    let requester = arkret_wire::AccountId::new(
        "ak:did_core:web:requester.example".parse().unwrap(),
        holder.station_id.clone(),
    );
    let actor = ActorId::account(requester);
    request.context = ConsentPrivateContext::Station(ConsentPrivateStationContext {
        kind: ConsentPrivateStationContextKind::Station,
        actor_id: ActorId::service(holder.station_id.clone()),
    });
    request.command = ConsentPrivateCommand::Request(ConsentPrivateRequestCommand {
        kind: ConsentPrivateRequestCommandKind::Request,
        body: ConsentPrivateRequestBody {
            requester_actor_id: actor,
            request: serde_json::from_value(
                serde_json::json!({"holder_account_id":holder,"consent_scope":"voice_call"}),
            )
            .unwrap(),
        },
    });
    store
        .private_command(
            &request,
            &holder.station_id,
            &holder.station_id,
            &Default::default(),
        )
        .await
        .unwrap();
    let second = store
        .prepare_effect_publication(
            &holder,
            &holder.station_id,
            arkret_canonical::base64url_encode([74; 32]),
        )
        .await
        .unwrap()
        .unwrap();
    assert!(second.sequence > first.sequence);
    assert!(second.request.effects.holder_quarantine.is_some());
    // A stale network ACK cannot erase a later accepted private effect.
    store
        .acknowledge_effect_publication(&holder, &holder.station_id, first.sequence)
        .await
        .unwrap();
    assert_eq!(
        store
            .pending_effect_holders(&holder.station_id)
            .await
            .unwrap(),
        vec![holder.clone()]
    );
    let accepted = apply(second.request.clone()).await.unwrap();
    assert_eq!(accepted.updates.len(), 1);
    assert!(
        apply(second.request.clone())
            .await
            .unwrap()
            .updates
            .is_empty()
    );
    let recovered = store
        .prepare_effect_publication(
            &holder,
            &holder.station_id,
            arkret_canonical::base64url_encode([75; 32]),
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(recovered.request.effects, second.request.effects);
    assert!(
        apply(recovered.request.clone())
            .await
            .unwrap()
            .updates
            .is_empty()
    );
    store
        .acknowledge_effect_publication(&holder, &holder.station_id, recovered.sequence)
        .await
        .unwrap();
    assert!(
        store
            .pending_effect_holders(&holder.station_id)
            .await
            .unwrap()
            .is_empty()
    );
}
