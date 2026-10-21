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
    use coland_storage::{AccountPk, AccountRecord, AccountStore};
    coland_storage_postgres::PgAccountStore { pool: pool.clone() }
        .put(&AccountRecord {
            pk: AccountPk(0),
            principal_id: fixture.history.account.principal_id.clone(),
            station_id: fixture.history.account.station_id.clone(),
            localpart: String::new(),
            display_name: None,
            bio: None,
            avatar_blob_ref: None,
            created_at: chrono::Utc::now(),
        })
        .await
        .unwrap();
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

fn replacement(
    peer: &ActorId,
    revision: Option<arkret_wire::CurrentRevision>,
    scopes: &[&str],
) -> serde_json::Value {
    serde_json::json!({"peer":{"kind":"actor","actor_id":peer},"expected_current": revision.map_or(serde_json::json!({"state":"never_written"}), |revision| serde_json::json!({"state":"present","revision":revision})),"permissions":scopes.iter().map(|scope|serde_json::json!({"consent_scope":scope})).collect::<Vec<_>>()})
}

#[derive(diesel::QueryableByName, Debug, PartialEq)]
struct Footprint {
    #[diesel(sql_type=Jsonb)]
    footprint: serde_json::Value,
}
async fn footprint(pool: &PgPool) -> Footprint {
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query("SELECT jsonb_build_array((SELECT count(*) FROM canonical_events),(SELECT count(*) FROM realm_commits),(SELECT jsonb_agg(to_jsonb(r) ORDER BY peer_id) FROM consent_current_results r),(SELECT count(*) FROM consent_result_versions),(SELECT count(*) FROM account_data_changes)) AS footprint").get_result(&mut conn).await.unwrap()
}

#[tokio::test]
async fn consent_current_rejects_duplicate_unknown_and_any_scopes_without_writes() {
    let db = TestDatabase::lease().await;
    let pool = db.pool();
    let f = fixture(&pool).await;
    let store = PgConsentCurrentStore { pool: pool.clone() };
    let peer = ActorId::account(f.history.account.clone());
    let all = ["invite", "voice_call", "video_call", "presence"];
    let accepted = write(
        &f,
        &f.unit.transactions[1].commit,
        EventKind::ConsentReplace,
        replacement(&peer, None, &all),
    );
    let ConsentAdmissionOutcome::Committed(original) = store.admit(accepted).await.unwrap() else {
        panic!("explicit full permission set")
    };
    assert_eq!(original.value.permissions.len(), 4);
    for scope in arkret_wire::ConsentScope::ALL {
        assert!(original.permits(&peer, *scope, chrono::Utc::now()));
    }
    let before = footprint(&pool).await;
    // Malformed wire strings remain JSON; no future/any protocol enum or
    // fallback permission is introduced into the implementation.
    for scopes in [
        vec!["voice_call", "voice_call"],
        vec!["future_scope"],
        vec!["any"],
    ] {
        let candidate = write(
            &f,
            &original.commit,
            EventKind::ConsentReplace,
            replacement(&peer, Some(original.view().revision), &scopes),
        );
        assert!(
            store.admit(candidate).await.is_err(),
            "invalid permission scopes {scopes:?}"
        );
        assert_eq!(footprint(&pool).await, before);
        let current = store.list(&f.history.account).await.unwrap();
        assert_eq!(current.len(), 1);
        assert_eq!(current[0].value, original.value);
        assert_eq!(current[0].event, original.event);
        assert_eq!(current[0].commit, original.commit);
    }
}

#[tokio::test]
async fn consent_current_full_replacement_empty_and_exact_replay_preserve_original_sources() {
    let db = TestDatabase::lease().await;
    let pool = db.pool();
    let f = fixture(&pool).await;
    let store = PgConsentCurrentStore { pool: pool.clone() };
    let peer = ActorId::account(f.history.account.clone());
    let original = write(
        &f,
        &f.unit.transactions[1].commit,
        EventKind::ConsentReplace,
        replacement(&peer, None, &["invite", "voice_call"]),
    );
    let ConsentAdmissionOutcome::Committed(record) = store.admit(original.clone()).await.unwrap()
    else {
        panic!("initial replacement")
    };
    assert_eq!(record.value.permissions.len(), 2);
    let before = footprint(&pool).await;
    let ConsentAdmissionOutcome::Duplicate(replay) = store.admit(original.clone()).await.unwrap()
    else {
        panic!("exact replay")
    };
    assert_eq!(replay.view(), record.view());
    assert_eq!(footprint(&pool).await, before);
    let overwrite = write(
        &f,
        &record.commit,
        EventKind::ConsentReplace,
        replacement(&peer, None, &["presence"]),
    );
    assert!(
        store
            .admit(overwrite)
            .await
            .unwrap_err()
            .to_string()
            .contains("failed_precondition")
    );
    assert_eq!(footprint(&pool).await, before);
    let empty = write(
        &f,
        &record.commit,
        EventKind::ConsentReplace,
        replacement(&peer, Some(record.view().revision), &[]),
    );
    let ConsentAdmissionOutcome::Committed(closed) = store.admit(empty.clone()).await.unwrap()
    else {
        panic!("empty is a current")
    };
    assert!(closed.value.permissions.is_empty());
    let ConsentAdmissionOutcome::Duplicate(replay) = store.admit(original).await.unwrap() else {
        panic!("historical replay")
    };
    assert_eq!(replay.view(), record.view());
    assert!(
        store.list(&f.history.account).await.unwrap()[0]
            .value
            .permissions
            .is_empty()
    );
    for current in [&record, &closed] {
        let recovered = store
            .historical_basis(&f.history.account, &peer, &current.view().revision)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(recovered.event, current.event);
        assert_eq!(recovered.commit, current.commit);
    }
    let before = footprint(&pool).await;
    let stale = write(
        &f,
        &closed.commit,
        EventKind::ConsentReplace,
        replacement(&peer, Some(record.view().revision), &["presence"]),
    );
    assert!(
        store
            .admit(stale)
            .await
            .unwrap_err()
            .to_string()
            .contains("failed_precondition")
    );
    assert_eq!(footprint(&pool).await, before);
    let never_again = write(
        &f,
        &closed.commit,
        EventKind::ConsentReplace,
        replacement(&peer, None, &["presence"]),
    );
    assert!(
        store
            .admit(never_again)
            .await
            .unwrap_err()
            .to_string()
            .contains("failed_precondition")
    );
    assert_eq!(footprint(&pool).await, before);
    let reopened = write(
        &f,
        &closed.commit,
        EventKind::ConsentReplace,
        replacement(&peer, Some(closed.view().revision), &["presence"]),
    );
    assert!(matches!(
        store.admit(reopened).await.unwrap(),
        ConsentAdmissionOutcome::Committed(_)
    ));
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
        EventKind::ConsentReplace,
        replacement(&peer, None, &["presence"]),
    );
    let b = write(
        &f,
        &f.unit.transactions[1].commit,
        EventKind::ConsentReplace,
        replacement(&peer, None, &["invite"]),
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
    let loser = if left.is_err() { left } else { right };
    assert!(
        loser
            .unwrap_err()
            .to_string()
            .contains("failed_precondition")
    );
    let after = footprint(&pool).await;
    for index in [0, 1, 3] {
        assert_eq!(
            after.footprint[index].as_u64().unwrap(),
            before.footprint[index].as_u64().unwrap() + 1,
            "only the winning replacement writes its Event, Commit and version"
        );
    }
    assert_eq!(after.footprint[4], before.footprint[4]);
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
async fn consent_replacement_preserves_quarantine_until_invite_closes_for_exact_peer() {
    use arkret_models_collaboration::governance::holder_quarantine::{
        HolderQuarantine, HolderQuarantineEntry, HolderQuarantineIntroductionKind,
        HolderQuarantineInviteScope, HolderQuarantineSurface, InviteTrustTier,
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
    let initial = write(
        &f,
        &f.unit.transactions[1].commit,
        EventKind::ConsentReplace,
        replacement(&peer, None, &["voice_call"]),
    );
    let ConsentAdmissionOutcome::Committed(active) = store.admit(initial).await.unwrap() else {
        panic!("replacement")
    };
    let other = ActorId::account(AccountId::new(
        peer_account.principal_id.clone(),
        "ak:did_core:web:other-station.example".parse().unwrap(),
    ));
    let mut cell = HolderQuarantine::new(active.commit.committed_at);
    for (index, actor) in [peer.clone(), other.clone()].into_iter().enumerate() {
        cell.quarantine_entries.push(HolderQuarantineEntry {
            entry_digest: Hash::new(arkret_canonical::sha256_digest([index as u8])).unwrap(),
            account_id: f.history.account.clone(),
            source_peer_principal_id: peer_account.principal_id.clone(),
            source_peer_actor_id: actor,
            source_id: peer_account.station_id.clone(),
            surface: HolderQuarantineSurface::InviteDelivery {
                consent_scope: HolderQuarantineInviteScope::Invite,
                introduction_kind: HolderQuarantineIntroductionKind::ExplicitAddress,
                effective_kind: HolderQuarantineIntroductionKind::ExplicitAddress,
                trust_tier: InviteTrustTier::Low,
                invite_event_id: f.unit.transactions[0].event.event_id.clone(),
                request_digest: Hash::new(arkret_canonical::sha256_digest([index as u8, 1]))
                    .unwrap(),
                idempotency_key_digest: Hash::new(arkret_canonical::sha256_digest([
                    index as u8,
                    2,
                ]))
                .unwrap(),
            },
            received_at: active.commit.committed_at,
            expires_at: active.commit.committed_at + chrono::TimeDelta::days(1),
        });
    }
    cell.quarantine_entries.push(HolderQuarantineEntry {
        entry_digest: Hash::new(arkret_canonical::sha256_digest([2])).unwrap(),
        account_id: f.history.account.clone(),
        source_peer_principal_id: peer_account.principal_id.clone(),
        source_peer_actor_id: peer.clone(),
        source_id: peer_account.station_id.clone(),
        surface: HolderQuarantineSurface::ConsentRequest {
            consent_scope: ConsentRequestScope::VideoCall,
        },
        received_at: active.commit.committed_at,
        expires_at: active.commit.committed_at + chrono::TimeDelta::days(1),
    });
    let actor = ActorId::account(f.history.account.clone()).to_string();
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
    let opening = write(
        &f,
        &active.commit,
        EventKind::ConsentReplace,
        replacement(
            &peer,
            Some(active.view().revision),
            &["invite", "voice_call"],
        ),
    );
    let ConsentAdmissionOutcome::Committed(opened) = store.admit(opening).await.unwrap() else {
        panic!("open invite")
    };
    assert!(opened.quarantine_update.is_none());
    let unchanged = accounts
        .get(&actor, AccountDataKey::ACCOUNT_HOLDER_QUARANTINE)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(unchanged.revision, 1);
    assert_eq!(unchanged.payload, serde_json::to_value(&cell).unwrap());
    let closing = write(
        &f,
        &opened.commit,
        EventKind::ConsentReplace,
        replacement(&peer, Some(opened.view().revision), &["voice_call"]),
    );
    let ConsentAdmissionOutcome::Committed(closed) = store.admit(closing).await.unwrap() else {
        panic!("close invite")
    };
    assert!(!closed.permits(&peer, ConsentScope::Invite, closed.commit.committed_at));
    assert!(closed.permits(&peer, ConsentScope::VoiceCall, closed.commit.committed_at));
    let update = closed
        .quarantine_update
        .as_ref()
        .expect("atomic invalidation");
    let cell: HolderQuarantine = serde_json::from_value(update.payload.clone()).unwrap();
    assert_eq!(update.revision, 2);
    assert_eq!(cell.quarantine_entries.len(), 2);
    assert_eq!(cell.quarantine_entries[0].source_peer_actor_id, other);
    assert_eq!(cell.quarantine_entries[1].source_peer_actor_id, peer);
    assert_eq!(
        cell.quarantine_entries[1].consent_scope(),
        ConsentScope::VideoCall
    );
    let invalidation = cell.last_invalidation.unwrap();
    assert_eq!(invalidation.peer_actor_id, peer);
    assert_eq!(invalidation.removed_entries, 1);
    assert_eq!(store.list(&f.history.account).await.unwrap().len(), 1);
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
    let grant = write(
        &f,
        &f.unit.transactions[1].commit,
        EventKind::ConsentReplace,
        replacement(&peer, None, &["invite", "voice_call"]),
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
        EventKind::ConsentReplace,
        replacement(&peer, Some(active.view().revision), &["voice_call"]),
    );
    store.admit(revoke).await.unwrap();
    assert!(
        store
            .historical_basis(&f.history.account, &peer, &active.view().revision)
            .await
            .unwrap()
            .is_some(),
        "the prior accepted invite grant still exists as immutable history"
    );
    let current = store.list(&f.history.account).await.unwrap();
    assert_eq!(current.len(), 1);
    assert!(current[0].permits(
        &peer,
        arkret_wire::ConsentScope::VoiceCall,
        chrono::Utc::now()
    ));
    assert!(!current[0].permits(&peer, arkret_wire::ConsentScope::Invite, chrono::Utc::now()));
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
async fn native_human_policy_retry_and_durable_effect_drain_do_not_create_proxy_state() {
    use arkret_models_collaboration::consent_private::*;
    use coland_storage::{AccountPk, AccountRecord, AccountStore};
    let db = TestDatabase::lease().await;
    let pool = db.pool();
    let f = fixture(&pool).await;
    let holder = &f.history.account;
    coland_storage_postgres::PgAccountStore { pool: pool.clone() }
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
    let context = ConsentPrivateContext::HolderSession(ConsentPrivateHolderSessionContext {
        kind: ConsentPrivateHolderSessionContextKind::HolderSession,
        actor_id: ActorId::account(holder.clone()),
        device_id: f.history.founding_device_id.clone(),
    });
    let command=ConsentPrivateCommand::InvitePolicy(ConsentPrivateInvitePolicyCommand{kind:ConsentPrivateInvitePolicyCommandKind::InvitePolicy,body:arkret_models_collaboration::governance::invite_addressing::InviteReceivePolicy::spec_default(holder.clone())});
    let first = store
        .native_command(
            holder,
            &context,
            &command,
            &holder.station_id,
            &Default::default(),
            None,
        )
        .await
        .unwrap();
    let retry = store
        .native_command(
            holder,
            &context,
            &command,
            &holder.station_id,
            &Default::default(),
            None,
        )
        .await
        .unwrap();
    assert_eq!(
        serde_json::to_value(first).unwrap(),
        serde_json::to_value(retry).unwrap()
    );
    assert_eq!(
        store
            .pending_effect_holders(&holder.station_id)
            .await
            .unwrap(),
        vec![holder.clone()]
    );
    assert!(
        store
            .prepare_effect_publication(
                holder,
                &holder.station_id,
                arkret_canonical::base64url_encode([1; 32])
            )
            .await
            .is_err()
    );
    store
        .drain_native_effects(holder, &holder.station_id)
        .await
        .unwrap();
    assert!(
        store
            .pending_effect_holders(&holder.station_id)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        store
            .drain_native_effects(holder, &holder.station_id)
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn human_pcr_rejects_change_export_proxy_import_and_activation_without_any_effect() {
    use arkret_models_collaboration::consent_private::*;
    let db = TestDatabase::lease().await;
    let pool = db.pool();
    let f = fixture(&pool).await;
    let account = &f.history.account;
    let tail = &f.unit.transactions.last().unwrap().commit;
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    let before = footprint(&pool).await;
    let current = store
        .current_authority(&tail.realm_id)
        .await
        .unwrap()
        .unwrap();
    let change = write(
        &f,
        tail,
        EventKind::RealmGovernanceStationChange,
        serde_json::json!({"expected_governance_generation":0,"expected_realm_stream_commit_id":tail.commit_id,"new_governance_station_id":"ak:did_core:web:other.example"}),
    );
    let error = store
        .admit_pcr_governance_change(&change.transaction)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("Human PCR"), "{error}");
    assert!(store.export_pcr_private_state(account).await.is_err());
    let commands = PgConsentCurrentStore { pool: pool.clone() };
    let context = ConsentPrivateContext::HolderSession(ConsentPrivateHolderSessionContext {
        kind: ConsentPrivateHolderSessionContextKind::HolderSession,
        actor_id: ActorId::account(account.clone()),
        device_id: f.history.founding_device_id.clone(),
    });
    let command = ConsentPrivateCommand::List(ConsentPrivateListCommand {
        kind: ConsentPrivateListCommandKind::List,
        body: ConsentPrivateEmptyBody {},
    });
    // The native read succeeds on the same accepted account and device. A peer
    // envelope naming that very same Station still cannot proxy a Human PCR.
    assert!(matches!(
        commands
            .native_command(
                account,
                &context,
                &command,
                &account.station_id,
                &Default::default(),
                None
            )
            .await
            .unwrap(),
        ConsentPrivateCommandOutcome::List(_)
    ));
    let now = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    let request = ConsentPrivateProxyRequest {
        holder_account_id: account.clone(),
        realm_id: tail.realm_id.clone(),
        governance_generation: 0,
        nonce: arkret_canonical::base64url_encode([7u8; 24]),
        expires_at: now + chrono::Duration::seconds(30),
        context,
        command,
    };
    let error = commands
        .private_command(
            &request,
            &account.station_id,
            &account.station_id,
            &Default::default(),
        )
        .await
        .unwrap_err();
    assert!(error.to_string().contains("Human PCR"), "{error}");
    let mut tables = serde_json::Map::new();
    for table in [
        "accounts",
        "canonical_realms",
        "canonical_events",
        "realm_authorities",
        "realm_commits",
        "realm_commit_event_kinds",
        "realm_authority_handoffs",
        "pcr_private_handoff_imports",
        "realm_state_snapshots",
        "realm_bootstrap_current_results",
        "realm_authority_root_current_results",
        "realm_policy_bundle_current_results",
        "member_state_current_results",
        "current_result_heads",
        "current_result_versions",
        "relation_current_results",
        "governance_current_ready",
        "realm_meta",
        "principal_resolutions",
        "principal_resolution_events",
        "pcr_device_generation_current_results",
        "pcr_device_authorization_current_results",
        "pcr_device_revocation_proposals",
        "actor_profile_current_results",
        "actor_profile_result_versions",
        "consent_current_results",
        "consent_result_versions",
        "agent_producer_signer_keys",
        "account_datas",
        "actor_private_events",
        "account_global_versions",
        "invite_receive_policies",
        "invite_new_source_hmac_keys",
        "invite_new_source_ledgers",
        "consent_private_effect_jobs",
        "consent_private_proxy_fences",
        "mimi_consent_correlations",
    ] {
        tables.insert(table.into(), serde_json::json!([]));
    }
    tables["canonical_events"] = serde_json::json!([{"envelope":f.unit.transactions[0].event}]);
    let archive = serde_json::json!({"format":"postgres-native-v1","holder_account_id":account,"realm_id":tail.realm_id,"tables":tables});
    let bytes = arkret_canonical::canonical_json_bytes(&archive).unwrap();
    let manifest = arkret_models_collaboration::authority_commit::PcrPrivateHandoffManifest {
        realm_id: tail.realm_id.clone(),
        holder_account_id: account.clone(),
        governance_generation: 0,
        effective_stream_head: arkret_wire::CommitStreamHead {
            stream_ref: tail.stream_ref.clone(),
            stream_position: tail.stream_position,
            commit_id: tail.commit_id.clone(),
        },
        nonce: arkret_canonical::base64url_encode([9u8; 32]),
        state_digest: arkret_wire::Hash::new(arkret_canonical::sha256_digest(&bytes)).unwrap(),
    };
    let error = store
        .import_pcr_private_state(&manifest, &bytes)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("Human PCR"), "{error}");
    // Even a content-addressed Snapshot, matching private manifest and both
    // real Station signatures cannot activate a Human PCR at another Station.
    let material = store
        .realm_state_snapshot_material(&tail.realm_id)
        .await
        .unwrap()
        .unwrap();
    let old_key = SigningKey::from_bytes(&device_authorization_history::STATION_AUTHORITY_SEED);
    let old_method = f.history.authority_method();
    let snapshot = coland_services::authority_commit::build_signed_realm_state_snapshot(
        &material,
        old_method.clone(),
        &old_key,
        now,
    )
    .unwrap();
    let heads = material.visible_stream_heads.clone();
    // This is an unaccepted hostile handoff candidate. The Human governance
    // gate must refuse it before any private inventory can be imported.
    let management_bytes = arkret_canonical::canonical_json_bytes(&serde_json::json!({
        "format":"realm-management-postgres-v1","realm_id":tail.realm_id,"tables":{}
    }))
    .unwrap();
    let management =
        arkret_models_collaboration::authority_commit::ManagementPrivateHandoffManifest {
            realm_id: tail.realm_id.clone(),
            governance_generation: 0,
            final_stream_heads_digest: arkret_wire::Hash::new(
                arkret_canonical::canonical_sha256(&heads).unwrap(),
            )
            .unwrap(),
            nonce: arkret_canonical::base64url_encode([8u8; 32]),
            state_digest: arkret_wire::Hash::new(arkret_canonical::sha256_digest(
                &management_bytes,
            ))
            .unwrap(),
        };
    let new_key = SigningKey::from_bytes(&[0xb2; 32]);
    let mut handoff = arkret_wire::RealmAuthorityHandoff {
        management_private_state_digest: Some(management.digest().unwrap()),
        pcr_private_state_digest: Some(manifest.digest().unwrap()),
        handoff_id: arkret_wire::RealmAuthorityHandoffId::from_digest([0x43; 32]),
        realm_id: tail.realm_id.clone(),
        from_generation: 0,
        to_generation: 1,
        from_service_id: account.station_id.clone(),
        to_service_id: "ak:did_core:web:other.example".parse().unwrap(),
        change_event_ref: change.transaction.event.event_id.clone(),
        change_commit_id: change.transaction.commit.commit_id.clone(),
        final_stream_heads_digest: arkret_wire::Hash::new(
            arkret_canonical::canonical_sha256(&heads).unwrap(),
        )
        .unwrap(),
        historical_signer_facts_digest: None,
        snapshot_ref: snapshot.snapshot_id.clone(),
        old_authority_signature: tail.signature.clone(),
        new_authority_acceptance_signature: tail.signature.clone(),
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
        now,
        &old_key,
    )
    .unwrap();
    handoff.new_authority_acceptance_signature =
        arkret_signatures::detached_object::sign_detached_object(
            &unsigned,
            DetachedSignatureContext::RealmAuthorityHandoffNewAcceptance,
            DidUrl::new("did:web:other.example#authority").unwrap(),
            now,
            &new_key,
        )
        .unwrap();
    handoff.validate_shape().unwrap();
    let refused = store
        .install_handoff_with_private_state(
            &handoff,
            &heads,
            &snapshot,
            Some(&manifest),
            &management,
        )
        .await
        .unwrap_err();
    assert!(refused.to_string().contains("Human PCR"), "{refused}");
    assert_eq!(
        store
            .current_authority(&tail.realm_id)
            .await
            .unwrap()
            .unwrap(),
        current
    );
    assert_eq!(footprint(&pool).await, before);
    let mut conn = pool.get().await.unwrap();
    #[derive(diesel::QueryableByName)]
    struct Empty {
        #[diesel(sql_type=diesel::sql_types::BigInt)]
        count: i64,
    }
    let row=diesel::sql_query("SELECT (SELECT count(*) FROM consent_private_proxy_fences)+(SELECT count(*) FROM consent_private_proxy_cuts)+(SELECT count(*) FROM consent_private_effect_fences)+(SELECT count(*) FROM consent_private_effect_cuts)+(SELECT count(*) FROM pcr_private_handoff_imports) AS count").get_result::<Empty>(&mut conn).await.unwrap();
    assert_eq!(row.count, 0);
}

#[tokio::test]
async fn disabled_human_account_cannot_execute_native_commands_or_drain_notifications() {
    use arkret_models_collaboration::consent_private::*;
    let db = TestDatabase::lease().await;
    let pool = db.pool();
    let f = fixture(&pool).await;
    let holder = &f.history.account;
    let store = PgConsentCurrentStore { pool: pool.clone() };
    let context = ConsentPrivateContext::HolderSession(ConsentPrivateHolderSessionContext {
        kind: ConsentPrivateHolderSessionContextKind::HolderSession,
        actor_id: ActorId::account(holder.clone()),
        device_id: f.history.founding_device_id.clone(),
    });
    let command=ConsentPrivateCommand::InvitePolicy(ConsentPrivateInvitePolicyCommand{kind:ConsentPrivateInvitePolicyCommandKind::InvitePolicy,body:arkret_models_collaboration::governance::invite_addressing::InviteReceivePolicy::spec_default(holder.clone())});
    store
        .native_command(
            holder,
            &context,
            &command,
            &holder.station_id,
            &Default::default(),
            None,
        )
        .await
        .unwrap();
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query(
        "UPDATE accounts SET disabled_at=now() WHERE principal_id=$1 AND station_id=$2",
    )
    .bind::<Text, _>(holder.principal_id.as_str())
    .bind::<Text, _>(holder.station_id.as_str())
    .execute(&mut conn)
    .await
    .unwrap();
    drop(conn);
    let before = footprint(&pool).await;
    assert!(
        store
            .native_command(
                holder,
                &context,
                &command,
                &holder.station_id,
                &Default::default(),
                None
            )
            .await
            .is_err()
    );
    assert!(
        store
            .drain_native_effects(holder, &holder.station_id)
            .await
            .is_err()
    );
    assert_eq!(footprint(&pool).await, before);
    assert_eq!(
        store
            .pending_effect_holders(&holder.station_id)
            .await
            .unwrap(),
        vec![holder.clone()]
    );
}
