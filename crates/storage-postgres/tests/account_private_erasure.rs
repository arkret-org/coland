//! Storage transaction components with real captured ASR originals.
//! The receipt signer below is a component-only port. These tests certify no
//! native service/operation coverage; live qualification must use AppState.
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use arkret_models_collaboration::account_status::{AccountStatusReceipt, AccountStatusRecord};
use arkret_models_collaboration::events_payloads::event_wire::{ErasureTrigger, VerificationStub};
use arkret_models_collaboration::governance::erasure::*;
use arkret_wire::{AccountId, ActorId, DidCoreId, DidUrl};
use coland_storage::{
    AccountDataRecord, AccountDataStore, AccountPrivateErasureCompletionStore,
    AccountPrivateErasureReceiptIssuer, AccountRecord, AccountStore, PersistenceError,
    PersistenceResult, SyncStoreRegistry,
};
use coland_storage_postgres::test_database::TestDatabase;
use coland_storage_postgres::{PgAccountDataStore, PgAccountStore, PgPersistenceStore, PgPool};
use diesel::sql_types::Jsonb;
use horme::RunQueryDsl;
use serde_json::{Value, json};

fn original_fixture() -> Value {
    serde_json::from_str(include_str!("fixtures/native_account_erasure_status.json")).unwrap()
}

fn verified_originals() -> Vec<(AccountStatusRecord, AccountStatusReceipt)> {
    let fixture = original_fixture();
    let history: arkret_models_identity::IdentityLogListResponseBody =
        serde_json::from_value(fixture["authority_material"]["account_authority_history"].clone())
            .unwrap();
    let resolution: arkret_models_identity::AuthenticatedServiceResolution =
        serde_json::from_value(fixture["authority_material"]["station_resolution"].clone())
            .unwrap();
    fixture["accepted_records"]
        .as_array()
        .unwrap()
        .iter()
        .map(|original| {
            let record: AccountStatusRecord =
                serde_json::from_value(original["record"].clone()).unwrap();
            let receipt: AccountStatusReceipt =
                serde_json::from_value(original["receipt"].clone()).unwrap();
            arkret_identity::verify_authenticated_service_resolution_history(
                &resolution,
                &record.account_authority_id,
                record.issued_at,
            )
            .unwrap();
            for (method, at, is_record) in [
                (&record.proof.verification_method, record.issued_at, true),
                (
                    &receipt.proof.verification_method,
                    receipt.accepted_at,
                    false,
                ),
            ] {
                let point = arkret_signatures::webvh::validate_webvh_history_at(
                    &history.did,
                    &history.entries,
                    at,
                )
                .unwrap();
                let document: arkret_identity::DidDocument =
                    serde_json::from_value(point.document).unwrap();
                arkret_identity::validate_verification_method_relationship(
                    &document,
                    method,
                    &history.did,
                    arkret_identity::DidVerificationRelationship::AssertionMethod,
                )
                .unwrap();
                let key =
                    arkret_identity::public_key_material_from_document(&document, method).unwrap();
                if is_record {
                    arkret_signatures::account_status::verify_account_status_record(&record, &key)
                        .unwrap();
                } else {
                    arkret_signatures::account_status::verify_account_status_receipt(
                        &receipt, &key,
                    )
                    .unwrap();
                }
            }
            (record, receipt)
        })
        .collect()
}

struct ComponentIssuer {
    account: AccountId,
    record: arkret_wire::AccountStatusRecordId,
    calls: AtomicUsize,
    fail: bool,
}
impl ComponentIssuer {
    fn new(record: &AccountStatusRecord, fail: bool) -> Self {
        Self {
            account: record.account_id.clone(),
            record: record.account_status_record_id.clone(),
            calls: AtomicUsize::new(0),
            fail,
        }
    }
}
impl AccountPrivateErasureReceiptIssuer for ComponentIssuer {
    fn issuer_id(&self) -> DidCoreId {
        "ak:did_core:web:erasure-component.example".parse().unwrap()
    }
    fn issue_completed(
        &self,
        at: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<ErasureReceiptPackage> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.fail {
            return Err(PersistenceError::Internal(
                "component issuer failure".into(),
            ));
        }
        let trigger = ErasureTrigger::AccountStatusRecord {
            account_status_record_id: self.record.clone(),
        };
        let subject = ErasureSubject {
            kind: ErasureSubjectKind::Principal,
            subject_ref: self.account.principal_id.to_string(),
        };
        let scope = ErasureScope {
            storage_boundary: ErasureStorageBoundary::AccountPrivateStore,
            realm_id: None,
            target_refs: Some(vec![subject.subject_ref.clone()]),
            retention_policy_id: None,
            service_scope: Some("storage_transaction_component".into()),
        };
        let id = arkret_wire::ReceiptId::new_v7_at(u64::try_from(at.timestamp_millis()).unwrap())
            .to_string();
        let stub:VerificationStub=serde_json::from_value(json!({"stub_schema":arkret_wire::SchemaId::ERASURE_VERIFICATION_STUB_V1,"receipt_id":id,"trigger":trigger,"subject":subject,"scope":scope,"completed_at":arkret_canonical::format_timestamp_canonical(at)})).unwrap();
        let mut receipt = ErasureReceipt {
            receipt_id: id,
            trigger,
            schema: ErasureReceipt::SCHEMA.into(),
            issuer_id: self.issuer_id(),
            subject,
            scope,
            outcome: ErasureAttemptOutcome::Completed,
            erased_classes: vec![
                ErasedClass::AccountPrivateState,
                ErasedClass::PushRoutes,
                ErasedClass::DeviceSecrets,
                ErasedClass::ProjectionRows,
            ],
            retained_stub_digest: arkret_canonical::canonical_sha256(&stub)
                .unwrap()
                .parse()
                .unwrap(),
            retained_stub: None,
            legal_hold_ref: None,
            completed_at: at,
            issued_at: Some(at),
            proofs: vec![],
            fanout_status: None,
            peer_receipts: None,
        };
        let signature = arkret_signatures::sign_ed25519_detached_jws(
            &ed25519_dalek::SigningKey::from_bytes(&[0x31; 32]),
            &receipt.canonical_proof_input().unwrap(),
        )
        .unwrap();
        receipt.proofs.push(ErasureReceiptProof {
            verification_method: DidUrl::new("did:web:erasure-component.example#component-key")
                .unwrap(),
            payload_digest: receipt.canonical_payload_digest().unwrap(),
            signature,
            extra: Default::default(),
        });
        Ok(ErasureReceiptPackage {
            receipt,
            retained_stub: stub,
        })
    }
}

async fn prepared() -> (TestDatabase, PgPool, AccountStatusRecord) {
    prepared_with_status(true).await
}

async fn prepared_with_status(
    terminal_status: bool,
) -> (TestDatabase, PgPool, AccountStatusRecord) {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let originals = verified_originals();
    let terminal = originals.last().unwrap().0.clone();
    PgAccountStore { pool: pool.clone() }
        .put(&AccountRecord {
            pk: coland_storage::AccountPk(0),
            principal_id: terminal.account_id.principal_id.clone(),
            station_id: terminal.account_id.station_id.clone(),
            localpart: "erasure-component".into(),
            display_name: Some("private display".into()),
            biography: Some("private biography".into()),
            avatar_blob_ref: None,
            created_at: chrono::Utc::now(),
        })
        .await
        .unwrap();
    let data = PgAccountDataStore { pool: pool.clone() };
    data.compare_and_set(
        &AccountDataRecord {
            actor: ActorId::account(terminal.account_id.clone()).to_string(),
            account_data_key: "ak.test.private.erasure".into(),
            revision: 1,
            payload: json!({"secret":"storage component payload"}),
            tombstone: false,
            updated_at: chrono::Utc::now(),
        },
        0,
    )
    .await
    .unwrap();
    let persistence = PgPersistenceStore::new(pool.clone());
    let replicas = persistence.account_status_replicas();
    for (index, (record, receipt)) in originals.into_iter().enumerate() {
        if index == 0 || terminal_status {
            replicas.append(&record, &receipt).await.unwrap();
        }
    }
    (database, pool, terminal)
}

/// Candidate reservation is a storage component, never accepted native Consent evidence.
#[tokio::test]
async fn mimi_new_decision_fences_the_exact_pending_account_before_storing_a_candidate() {
    use coland_storage::{
        MimiConsentCorrelationRecord, MimiConsentCorrelationStore, MimiConsentSourceClass,
    };
    let (_database, pool, terminal) = prepared_with_status(false).await;
    let store = coland_storage_postgres::PgMimiConsentCorrelationStore { pool: pool.clone() };
    let actor = ActorId::account(terminal.account_id.clone());
    let payload = json!({"peer":{"kind":"actor","actor_id":actor},"expected_current":{"state":"never_written"},"permissions":[]});
    let candidate_at = chrono::Utc::now();
    let candidate = |at| {
        arkret_wire::EventAdmissionSubmission::new(
            arkret_wire::test_support::raw_event_for_actor_at(
                arkret_wire::EventKind::ConsentReplace.as_str(),
                arkret_wire::ScopeRef::Realm {
                    realm_id: terminal.principal_control_realm_id.clone(),
                },
                actor.clone(),
                payload.clone(),
                at,
            )
            .unwrap(),
        )
    };
    let submission = candidate(candidate_at);
    let pending_submission = candidate(candidate_at + chrono::Duration::seconds(1));
    assert_ne!(submission.event.event_id, pending_submission.event.event_id);
    for consent_id in ["component-first", "component-pending"] {
        store
            .put(&MimiConsentCorrelationRecord {
                consent_id: consent_id.to_owned(),
                requester_actor_id: actor.to_string(),
                holder_account_id: terminal.account_id.to_string(),
                purpose: "contact".to_owned(),
                strand_id: None,
                source_id: None,
                source_class: MimiConsentSourceClass::Session,
                created_at: chrono::Utc::now(),
                expires_at: None,
            })
            .await
            .unwrap();
    }
    assert!(
        store
            .bind_decision("component-first", "accept", &submission, true)
            .await
            .unwrap()
    );
    let (record, receipt) = verified_originals().last().unwrap().clone();
    PgPersistenceStore::new(pool.clone())
        .account_status_replicas()
        .append(&record, &receipt)
        .await
        .unwrap();
    let mut correlation = store.get("component-first").await.unwrap().unwrap();
    store.put(&correlation).await.unwrap();
    correlation.consent_id = "component-late-correlation".to_owned();
    let error = store.put(&correlation).await.unwrap_err();
    assert!(
        matches!(error, PersistenceError::Conflict(ref message) if message.contains("erasure is irrevocably pending")),
        "{error}"
    );
    assert!(store.get(&correlation.consent_id).await.unwrap().is_none());
    assert!(
        store
            .bind_decision("component-first", "accept", &submission, true)
            .await
            .unwrap()
    );
    let error = store
        .bind_decision("component-pending", "accept", &pending_submission, true)
        .await
        .unwrap_err();
    assert!(
        matches!(error, PersistenceError::Conflict(ref message) if message.contains("erasure is irrevocably pending")),
        "{error}"
    );
    assert!(
        !store
            .bind_decision("component-pending", "accept", &pending_submission, false)
            .await
            .unwrap()
    );
}

#[test]
fn public_native_status_fixture_has_complete_historical_signatures() {
    assert_eq!(verified_originals().len(), 2);
}

#[tokio::test]
async fn failed_issuer_rolls_back_payload_purge_and_handle_release() {
    let (_database, pool, record) = prepared().await;
    let issuer = ComponentIssuer::new(&record, true);
    let store = PgAccountStore { pool: pool.clone() };
    assert!(
        store
            .erase_private_state(
                &record.account_id,
                &record.account_status_record_id,
                &issuer
            )
            .await
            .is_err()
    );
    assert_eq!(issuer.calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        store
            .get(&record.account_id)
            .await
            .unwrap()
            .unwrap()
            .localpart,
        "erasure-component"
    );
    assert!(
        PgAccountDataStore { pool: pool.clone() }
            .get(
                &ActorId::account(record.account_id).to_string(),
                "ak.test.private.erasure"
            )
            .await
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn successful_purge_recovers_one_original_and_rejects_late_private_writes() {
    use coland_storage::{DeviceRevocationGateLinearizationRequest, DeviceRevocationStore};
    let (_database, pool, record) = prepared().await;
    let issuer = ComponentIssuer::new(&record, false);
    let store = PgAccountStore { pool: pool.clone() };
    let completions =
        coland_storage_postgres::PgAccountPrivateErasureCompletionStore { pool: pool.clone() };
    // A mismatch result grants no authority, but its minimal replay identity
    // must survive payload deletion just as an active gate result would.
    let gates = coland_storage_postgres::PgDeviceRevocationStore { pool: pool.clone() };
    let gate_request = DeviceRevocationGateLinearizationRequest {
        principal_id: record.account_id.principal_id.clone(),
        station_id: record.account_id.station_id.clone(),
        device_id: "erasure-component-device".to_owned(),
        expected_authorization_ref: None,
        origin_current_selector: None,
        action_class: arkret_wire::DeviceRevocationDeniedAction::EventWrite,
        intent_digest: arkret_canonical::sha256_digest(b"erasure component gate intent"),
        requested_at: arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now()),
    };
    let original_gate = gates.linearize_gate(gate_request.clone()).await.unwrap();
    assert!(matches!(
        original_gate.status,
        coland_storage::DeviceRevocationGateStatus::AuthorityMismatch
    ));
    assert!(
        completions
            .receipt_id(
                &record.account_id,
                &record.account_status_record_id,
                &issuer.issuer_id()
            )
            .await
            .unwrap()
            .is_none()
    );
    let first = store
        .erase_private_state(
            &record.account_id,
            &record.account_status_record_id,
            &issuer,
        )
        .await
        .unwrap();
    let replay = store
        .erase_private_state(
            &record.account_id,
            &record.account_status_record_id,
            &issuer,
        )
        .await
        .unwrap();
    assert_eq!(json!(first), json!(replay));
    let replayed_gate = gates.linearize_gate(gate_request).await.unwrap();
    assert_eq!(replayed_gate.request, original_gate.request);
    assert_eq!(replayed_gate.status, original_gate.status);
    assert_eq!(
        replayed_gate.linearization_seq,
        original_gate.linearization_seq
    );
    assert_eq!(replayed_gate.linearized_at, original_gate.linearized_at);
    assert_eq!(replayed_gate.expires_at, original_gate.expires_at);
    let original = completions
        .receipt_id(
            &record.account_id,
            &record.account_status_record_id,
            &issuer.issuer_id(),
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(first.receipt.receipt_id, original.as_str());
    let allocated = uuid::Uuid::parse_str(
        first
            .receipt
            .receipt_id
            .strip_prefix("ak:receipt:")
            .unwrap(),
    )
    .unwrap();
    let (seconds, nanos) = allocated.get_timestamp().unwrap().to_unix();
    assert_eq!(
        seconds * 1000 + u64::from(nanos) / 1_000_000,
        u64::try_from(first.receipt.completed_at.timestamp_millis()).unwrap()
    );
    let foreign = AccountId::new(
        record.account_id.principal_id.clone(),
        "ak:did_core:web:foreign.example".parse().unwrap(),
    );
    assert!(
        completions
            .receipt_id(
                &foreign,
                &record.account_status_record_id,
                &issuer.issuer_id()
            )
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        completions
            .receipt_id(
                &record.account_id,
                &record.account_status_record_id,
                &foreign.station_id
            )
            .await
            .is_err()
    );
    assert_eq!(issuer.calls.load(Ordering::SeqCst), 1);
    let erased = store.get(&record.account_id).await.unwrap().unwrap();
    assert!(erased.localpart.is_empty());
    assert!(erased.biography.is_none());
    let data = PgAccountDataStore { pool: pool.clone() };
    let actor = ActorId::account(record.account_id.clone()).to_string();
    assert!(
        data.get(&actor, "ak.test.private.erasure")
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        data.compare_and_set(
            &AccountDataRecord {
                actor,
                account_data_key: "ak.test.private.erasure".into(),
                revision: 1,
                payload: json!({"secret":"late"}),
                tombstone: false,
                updated_at: chrono::Utc::now()
            },
            0
        )
        .await
        .is_err()
    );
    assert!(store.put(&erased).await.is_err());
    let mut connection = pool.get().await.unwrap();
    assert!(diesel::sql_query("INSERT INTO account_datas(id,actor_id,account_data_key,payload) VALUES($1,$2,'late-direct-writer','{}'::jsonb)")
        .bind::<diesel::sql_types::Uuid,_>(uuid::Uuid::now_v7())
        .bind::<diesel::sql_types::Text,_>(ActorId::account(record.account_id.clone()).to_string())
        .execute(&mut *connection).await.is_err());
    assert!(
        diesel::sql_query(
            "UPDATE account_private_erasure_completions SET package=package WHERE account_id=$1"
        )
        .bind::<Jsonb, _>(json!(record.account_id))
        .execute(&mut *connection)
        .await
        .is_err()
    );
}

#[tokio::test]
async fn same_principal_at_another_station_keeps_its_exact_private_values() {
    let (_database, pool, record) = prepared().await;
    let mut unrelated = PgAccountStore { pool: pool.clone() }
        .get(&record.account_id)
        .await
        .unwrap()
        .unwrap();
    unrelated.station_id = "ak:did_core:web:independent-component-station.example"
        .parse()
        .unwrap();
    unrelated.localpart = "independent-component".into();
    unrelated.biography = Some("independent private value".into());
    let store = PgAccountStore { pool: pool.clone() };
    store.put(&unrelated).await.unwrap();
    let other_account =
        AccountId::new(unrelated.principal_id.clone(), unrelated.station_id.clone());
    let before = store.get(&other_account).await.unwrap().unwrap();
    store
        .erase_private_state(
            &record.account_id,
            &record.account_status_record_id,
            &ComponentIssuer::new(&record, false),
        )
        .await
        .unwrap();
    let after = store.get(&other_account).await.unwrap().unwrap();
    assert_eq!(
        (
            before.pk,
            before.principal_id,
            before.station_id,
            before.localpart,
            before.display_name,
            before.biography,
            before.avatar_blob_ref,
            before.created_at
        ),
        (
            after.pk,
            after.principal_id,
            after.station_id,
            after.localpart,
            after.display_name,
            after.biography,
            after.avatar_blob_ref,
            after.created_at
        )
    );
}

#[tokio::test]
async fn old_repeatable_read_snapshot_cannot_repopulate_after_completed_purge() {
    let (_database, pool, record) = prepared().await;
    let mut old = pool.get().await.unwrap();
    diesel::sql_query("BEGIN ISOLATION LEVEL REPEATABLE READ")
        .execute(&mut *old)
        .await
        .unwrap();
    diesel::sql_query("SELECT count(*) FROM accounts")
        .execute(&mut *old)
        .await
        .unwrap();
    let issuer = ComponentIssuer::new(&record, false);
    PgAccountStore { pool: pool.clone() }
        .erase_private_state(
            &record.account_id,
            &record.account_status_record_id,
            &issuer,
        )
        .await
        .unwrap();
    assert!(
        diesel::sql_query("SELECT lock_account_private_storage($1)")
            .bind::<Jsonb, _>(json!(record.account_id))
            .execute(&mut *old)
            .await
            .is_err()
    );
    diesel::sql_query("ROLLBACK")
        .execute(&mut *old)
        .await
        .unwrap();
}

#[tokio::test]
async fn in_flight_private_write_fence_delays_the_physical_purge() {
    let (_database, pool, record) = prepared().await;
    let mut writer = pool.get().await.unwrap();
    diesel::sql_query("BEGIN")
        .execute(&mut *writer)
        .await
        .unwrap();
    diesel::sql_query("SELECT lock_account_private_storage($1)")
        .bind::<Jsonb, _>(json!(record.account_id))
        .execute(&mut *writer)
        .await
        .unwrap();
    let issuer = Arc::new(ComponentIssuer::new(&record, false));
    let cloned = pool.clone();
    let account = record.account_id.clone();
    let id = record.account_status_record_id.clone();
    let task = tokio::spawn(async move {
        PgAccountStore { pool: cloned }
            .erase_private_state(&account, &id, issuer.as_ref())
            .await
    });
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    assert!(!task.is_finished());
    diesel::sql_query("COMMIT")
        .execute(&mut *writer)
        .await
        .unwrap();
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn queued_profile_writes_do_not_upgrade_shared_locks() {
    let (_database, pool, record) = prepared_with_status(false).await;
    let profile = PgAccountStore { pool: pool.clone() }
        .get(&record.account_id)
        .await
        .unwrap()
        .unwrap();
    let other_profile = profile.clone();
    let mut blocker = pool.get().await.unwrap();
    diesel::sql_query("BEGIN")
        .execute(&mut *blocker)
        .await
        .unwrap();
    diesel::sql_query("SELECT lock_account_private_storage($1)")
        .bind::<Jsonb, _>(json!(record.account_id))
        .execute(&mut *blocker)
        .await
        .unwrap();
    let profile_pool = pool.clone();
    let profile_task =
        tokio::spawn(async move { PgAccountStore { pool: profile_pool }.put(&profile).await });
    let other_pool = pool.clone();
    let other_task = tokio::spawn(async move {
        PgAccountStore { pool: other_pool }
            .put(&other_profile)
            .await
    });
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    assert!(!profile_task.is_finished() && !other_task.is_finished());
    diesel::sql_query("COMMIT")
        .execute(&mut *blocker)
        .await
        .unwrap();
    let (profile_result, other_result) =
        tokio::time::timeout(std::time::Duration::from_secs(15), async {
            tokio::join!(profile_task, other_task)
        })
        .await
        .expect("profile writers must serialize without a lock-upgrade cycle");
    profile_result.unwrap().unwrap();
    other_result.unwrap().unwrap();
}

#[tokio::test]
async fn accepted_erasure_pending_refuses_new_private_writes_before_physical_completion() {
    let (_database, pool, record) = prepared().await;
    let store = PgAccountDataStore { pool };
    let actor = ActorId::account(record.account_id).to_string();
    let mut previous = store
        .get(&actor, "ak.test.private.erasure")
        .await
        .unwrap()
        .unwrap();
    previous.revision = 2;
    previous.payload = json!({"secret":"must not be accepted after terminal status"});
    assert!(
        matches!(store.compare_and_set(&previous,1).await,Err(PersistenceError::Conflict(message)) if message.contains("erasure"))
    );
    assert_eq!(
        store
            .get(&actor, "ak.test.private.erasure")
            .await
            .unwrap()
            .unwrap()
            .revision,
        1
    );
}

#[tokio::test]
async fn accepted_terminal_checkpoint_waits_for_an_in_flight_private_writer() {
    let (_database, pool, record) = prepared_with_status(false).await;
    let mut writer = pool.get().await.unwrap();
    diesel::sql_query("BEGIN")
        .execute(&mut *writer)
        .await
        .unwrap();
    diesel::sql_query("SELECT lock_account_private_storage($1)")
        .bind::<Jsonb, _>(json!(record.account_id))
        .execute(&mut *writer)
        .await
        .unwrap();
    let terminal = verified_originals().pop().unwrap();
    let replica_pool = pool.clone();
    let accepted = tokio::spawn(async move {
        PgPersistenceStore::new(replica_pool)
            .account_status_replicas()
            .append(&terminal.0, &terminal.1)
            .await
    });
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    assert!(!accepted.is_finished());
    diesel::sql_query("COMMIT")
        .execute(&mut *writer)
        .await
        .unwrap();
    accepted.await.unwrap().unwrap();
}

#[tokio::test]
async fn old_private_snapshot_cannot_miss_an_accepted_terminal_checkpoint() {
    let (_database, pool, record) = prepared_with_status(false).await;
    let mut old = pool.get().await.unwrap();
    diesel::sql_query("BEGIN ISOLATION LEVEL REPEATABLE READ")
        .execute(&mut *old)
        .await
        .unwrap();
    diesel::sql_query("SELECT count(*) FROM accounts")
        .execute(&mut *old)
        .await
        .unwrap();
    let (terminal, receipt) = verified_originals().pop().unwrap();
    PgPersistenceStore::new(pool.clone())
        .account_status_replicas()
        .append(&terminal, &receipt)
        .await
        .unwrap();
    assert!(
        diesel::sql_query("SELECT lock_account_private_storage($1)")
            .bind::<Jsonb, _>(json!(record.account_id))
            .execute(&mut *old)
            .await
            .is_err()
    );
    diesel::sql_query("ROLLBACK")
        .execute(&mut *old)
        .await
        .unwrap();
}
