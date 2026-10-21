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
    expected: serde_json::Value,
    permissions: serde_json::Value,
) -> serde_json::Value {
    serde_json::json!({"peer":{"kind":"actor","actor_id":peer},"expected_current":expected,"permissions":permissions})
}
fn initial(peer: &ActorId, scope: &str) -> serde_json::Value {
    replacement(
        peer,
        serde_json::json!({"state":"never_written"}),
        serde_json::json!([{"consent_scope":scope}]),
    )
}
fn replacing(
    peer: &ActorId,
    record: &coland_storage::ConsentCurrentRecord,
    permissions: serde_json::Value,
) -> serde_json::Value {
    replacement(
        peer,
        serde_json::json!({"state":"present","revision":record.view().revision}),
        permissions,
    )
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
async fn exact_peer_full_set_cas_empty_and_replay_keep_the_original_version() {
    use serde_json::json;
    let db = TestDatabase::lease().await;
    let pool = db.pool();
    let f = fixture(&pool).await;
    let store = PgConsentCurrentStore { pool: pool.clone() };
    let peer = ActorId::account(f.history.account.clone());
    let original = write(
        &f,
        &f.unit.transactions[1].commit,
        EventKind::ConsentReplace,
        initial(&peer, "invite"),
    );
    let ConsentAdmissionOutcome::Committed(first) = store.admit(original.clone()).await.unwrap()
    else {
        panic!("first")
    };
    let before = footprint(&pool).await;
    let wrong = write(
        &f,
        &first.commit,
        EventKind::ConsentReplace,
        initial(&peer, "presence"),
    );
    assert!(
        store
            .admit(wrong)
            .await
            .unwrap_err()
            .to_string()
            .contains("failed_precondition")
    );
    assert_eq!(footprint(&pool).await, before);
    let full = json!([{"consent_scope":"invite","constraints":[],"reason":""},{"consent_scope":"voice_call","not_before":"2020-01-01T00:00:00.000Z","expires_at":"2020-02-01T00:00:00.000Z","constraints":[{"unknown":true}],"evidence_ref":"original"}]);
    let edit = write(
        &f,
        &first.commit,
        EventKind::ConsentReplace,
        replacing(&peer, &first, full.clone()),
    );
    let ConsentAdmissionOutcome::Committed(second) = store.admit(edit).await.unwrap() else {
        panic!("replace")
    };
    assert_eq!(
        serde_json::to_value(&second.value).unwrap(),
        json!({"permissions":full})
    );
    let stale = write(
        &f,
        &second.commit,
        EventKind::ConsentReplace,
        replacing(&peer, &first, json!([])),
    );
    let before = footprint(&pool).await;
    assert!(
        store
            .admit(stale)
            .await
            .unwrap_err()
            .to_string()
            .contains("failed_precondition")
    );
    assert_eq!(footprint(&pool).await, before);
    let empty = write(
        &f,
        &second.commit,
        EventKind::ConsentReplace,
        replacing(&peer, &second, json!([])),
    );
    let ConsentAdmissionOutcome::Committed(empty) = store.admit(empty).await.unwrap() else {
        panic!("empty")
    };
    assert!(empty.value.permissions.is_empty());
    let before = footprint(&pool).await;
    let ConsentAdmissionOutcome::Duplicate(old) = store.admit(original).await.unwrap() else {
        panic!("replay")
    };
    assert_eq!(old.view(), first.view());
    assert_eq!(footprint(&pool).await, before);
    assert_eq!(
        store.list(&f.history.account).await.unwrap()[0].view(),
        empty.view()
    );
    let basis = store
        .historical_basis(&f.history.account, &peer, &second.view().revision)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(basis.event, second.event);
    let cut = store
        .read_cut(
            &f.history.account,
            &arkret_models_collaboration::events_payloads::consent::ConsentPeer::Actor {
                actor_id: peer,
            },
            None,
        )
        .await
        .unwrap();
    assert_eq!(cut.records.len(), 1);
    assert!(cut.records[0].value.permissions.is_empty());
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
        initial(&peer, "presence"),
    );
    let b = write(
        &f,
        &f.unit.transactions[1].commit,
        EventKind::ConsentReplace,
        initial(&peer, "invite"),
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
async fn removing_invite_invalidates_only_that_complete_peer_and_preserves_other_scopes() {
    use arkret_models_collaboration::governance::holder_quarantine::*;
    use arkret_wire::{AccountDataKey, AccountId, ConsentRequestScope, ConsentScope, Hash};
    use coland_storage::{AccountDataRecord, AccountDataStore};
    use serde_json::json;
    let db = TestDatabase::lease().await;
    let pool = db.pool();
    let f = fixture(&pool).await;
    let store = PgConsentCurrentStore { pool: pool.clone() };
    let account = AccountId::new(
        "ak:did_core:web:peer.example".parse().unwrap(),
        f.history.account.station_id.clone(),
    );
    let peer = ActorId::account(account.clone());
    let initial_write = write(
        &f,
        &f.unit.transactions[1].commit,
        EventKind::ConsentReplace,
        replacement(
            &peer,
            json!({"state":"never_written"}),
            json!([{"consent_scope":"invite"},{"consent_scope":"voice_call","reason":"keep"}]),
        ),
    );
    let ConsentAdmissionOutcome::Committed(active) = store.admit(initial_write).await.unwrap()
    else {
        panic!("initial")
    };
    let mut cell = HolderQuarantine::new(active.commit.committed_at);
    for index in 0..3_u8 {
        let mut source = account.clone();
        if index == 1 {
            source.station_id = "ak:did_core:web:other.example".parse().unwrap();
        }
        let surface = if index == 2 {
            HolderQuarantineSurface::ConsentRequest {
                consent_scope: ConsentRequestScope::VideoCall,
            }
        } else {
            HolderQuarantineSurface::InviteDelivery {
                consent_scope: HolderQuarantineInviteScope::Invite,
                introduction_kind: HolderQuarantineIntroductionKind::ExplicitAddress,
                effective_kind: HolderQuarantineIntroductionKind::ExplicitAddress,
                trust_tier: InviteTrustTier::Low,
                invite_event_id: arkret_wire::EventId::from_digest(
                    arkret_canonical::DigestSuite::Sha256,
                    [index; 32],
                ),
                request_digest: Hash::new(arkret_canonical::sha256_digest([index])).unwrap(),
                idempotency_key_digest: Hash::new(arkret_canonical::sha256_digest([index + 4]))
                    .unwrap(),
            }
        };
        cell.quarantine_entries.push(HolderQuarantineEntry {
            entry_digest: Hash::new(arkret_canonical::sha256_digest([index + 8])).unwrap(),
            account_id: f.history.account.clone(),
            source_peer_principal_id: source.principal_id.clone(),
            source_peer_actor_id: ActorId::account(source.clone()),
            source_id: source.station_id,
            surface,
            received_at: cell.updated_at,
            expires_at: cell.updated_at + chrono::Duration::days(1),
        });
    }
    let accounts = coland_storage_postgres::PgAccountDataStore { pool: pool.clone() };
    let actor = ActorId::account(f.history.account.clone()).to_string();
    accounts
        .compare_and_set(
            &AccountDataRecord {
                actor: actor.clone(),
                account_data_key: AccountDataKey::ACCOUNT_HOLDER_QUARANTINE.into(),
                revision: 1,
                payload: serde_json::to_value(&cell).unwrap(),
                tombstone: false,
                updated_at: cell.updated_at,
            },
            0,
        )
        .await
        .unwrap();
    let event = write(
        &f,
        &active.commit,
        EventKind::ConsentReplace,
        replacing(
            &peer,
            &active,
            json!([{"consent_scope":"voice_call","reason":"keep"}]),
        ),
    );
    let ConsentAdmissionOutcome::Committed(removed) = store.admit(event.clone()).await.unwrap()
    else {
        panic!("replace")
    };
    assert!(removed.permits(&peer, ConsentScope::VoiceCall, removed.commit.committed_at));
    assert_eq!(removed.quarantine_update.as_ref().unwrap().revision, 2);
    let row = accounts
        .get(&actor, AccountDataKey::ACCOUNT_HOLDER_QUARANTINE)
        .await
        .unwrap()
        .unwrap();
    let cell: HolderQuarantine = serde_json::from_value(row.payload).unwrap();
    assert_eq!(cell.quarantine_entries.len(), 2);
    assert_eq!(cell.last_invalidation.unwrap().removed_entries, 1);
    let ConsentAdmissionOutcome::Duplicate(replay) = store.admit(event).await.unwrap() else {
        panic!("replay")
    };
    assert!(replay.quarantine_update.is_none());
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
        initial(&peer, "invite"),
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
    let next = write(
        &f,
        &active.commit,
        EventKind::ConsentReplace,
        replacing(
            &peer,
            &active,
            serde_json::json!([{"consent_scope":"invite"},{"consent_scope":"voice_call"}]),
        ),
    );
    let ConsentAdmissionOutcome::Committed(current) = store.admit(next).await.unwrap() else {
        panic!("preserving replacement")
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
        &current.commit,
        EventKind::ConsentReplace,
        replacing(&peer, &current, serde_json::json!([])),
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
        "mimi_consent_updates",
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
    let new_key = SigningKey::from_bytes(&[0xb2; 32]);
    let management =
        arkret_models_collaboration::authority_commit::ManagementPrivateHandoffManifest {
            realm_id: tail.realm_id.clone(),
            governance_generation: 0,
            final_stream_heads_digest: arkret_wire::Hash::new(
                arkret_canonical::canonical_sha256(&heads).unwrap(),
            )
            .unwrap(),
            nonce: "AAAAAAAAAAAAAAAAAAAAAA".into(),
            state_digest: arkret_wire::Hash::new(
                arkret_canonical::canonical_sha256(&serde_json::json!({})).unwrap(),
            )
            .unwrap(),
        };
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
