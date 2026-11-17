//! Real PG rollback/reopen contracts for the physical completion boundary.
//! Signed AA material is imported through the replica adapter here. These
//! tests do not claim browser authentication, HTTP federation, or Gateway I/O.
use std::sync::atomic::{AtomicUsize, Ordering};

use arkret_models_collaboration::account_status::{
    UnsignedAccountStatusReceipt, UnsignedAccountStatusRecord,
};
use arkret_models_collaboration::governance::erasure::{
    ErasureReceipt, ErasureReceiptPackage, ErasureReceiptProof, ErasureScope, ErasureSubject,
};
use arkret_models_collaboration::objects::account_status::AccountStatus;
use arkret_wire::{AccountId, ActorId, DidCoreId, Hash};
use coland_storage::{
    AccountDataRecord, AccountPk, AccountRecord, AccountStatusReplicaAppend,
    IdentityStoreRegistry as _,
};
use coland_test_support::agent_origin::OriginFixture;
use diesel::sql_types::Bool;
use ed25519_dalek::Signer as _;
use futures_util::FutureExt as _;

use super::*;

#[derive(QueryableByName)]
struct Count {
    #[diesel(sql_type = BigInt)]
    value: i64,
}

#[derive(QueryableByName)]
struct Present {
    #[diesel(sql_type = Bool)]
    value: bool,
}

fn signed_status(
    fixture: &OriginFixture,
    account: &AccountId,
    previous: Option<&AccountStatusRecord>,
    status: AccountStatus,
    pcr: &arkret_wire::RealmId,
) -> AccountStatusRecord {
    let record = arkret_signatures::account_status::sign_account_status_record(
        UnsignedAccountStatusRecord {
            schema: arkret_wire::SchemaId::ACCOUNT_STATUS_RECORD_V1.into(),
            account_authority_id: fixture.station.clone(),
            account_id: account.clone(),
            principal_control_realm_id: pcr.clone(),
            binding_version: 1,
            status_sequence: previous.map_or(1, |record| record.status_sequence + 1),
            previous_account_status_record_id: previous
                .map(|record| record.account_status_record_id.clone()),
            status,
            reason_code: None,
            reason: None,
            issued_at: arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now()),
            expires_at: None,
        },
        fixture.method.clone(),
        &fixture.issuer,
    )
    .unwrap();
    let document = arkret_identity::authenticated_service_document_at(
        &fixture.history,
        &fixture.station,
        record.issued_at,
    )
    .unwrap();
    let key = arkret_identity::jws::resolve_ed25519_pubkey_from_document(
        &document,
        record.proof.verification_method.as_str(),
    )
    .unwrap();
    arkret_signatures::account_status::verify_account_status_record(
        &record,
        &arkret_signatures::PublicKeyMaterial::Ed25519Raw {
            bytes: key.to_bytes().to_vec(),
        },
    )
    .unwrap();
    record
}

fn signed_receipt(
    fixture: &OriginFixture,
    record: &AccountStatusRecord,
    receiver: &DidCoreId,
) -> AccountStatusReceipt {
    let receipt = arkret_signatures::account_status::sign_account_status_receipt(
        UnsignedAccountStatusReceipt {
            receipt_id: format!("ak:receipt:{}", uuid::Uuid::now_v7())
                .parse()
                .unwrap(),
            account_status_record_id: record.account_status_record_id.clone(),
            record_digest: record.payload_digest().unwrap(),
            account_authority_id: record.account_authority_id.clone(),
            account_id: record.account_id.clone(),
            status_sequence: record.status_sequence,
            receiver_id: receiver.clone(),
            accepted_at: arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now()),
            verification_method: fixture.method.clone(),
        },
        &fixture.issuer,
    )
    .unwrap();
    arkret_signatures::account_status::verify_account_status_receipt(
        &receipt,
        &arkret_signatures::PublicKeyMaterial::Ed25519Raw {
            bytes: fixture.issuer.verifying_key().to_bytes().to_vec(),
        },
    )
    .unwrap();
    receipt
}

async fn append(
    store: &PgAccountStatusReplicaStore,
    fixture: &OriginFixture,
    record: &AccountStatusRecord,
    receiver: &DidCoreId,
) {
    let receipt = signed_receipt(fixture, record, receiver);
    assert!(matches!(
        store.append(record, &receipt).await.unwrap(),
        AccountStatusReplicaAppend::Accepted(_)
    ));
}

#[tokio::test]
async fn accepted_terminal_projection_drains_prior_private_writer_and_refuses_late_creation() {
    let fixture = Box::pin(OriginFixture::new()).await;
    let persistence = crate::PgPersistenceStore::new(fixture.pool.clone());
    let account = fixture.controller.history.account.clone();
    persistence
        .accounts()
        .put(&AccountRecord {
            pk: AccountPk(0),
            principal_id: account.principal_id.clone(),
            station_id: account.station_id.clone(),
            localpart: String::new(),
            display_name: None,
            biography: None,
            avatar_blob_ref: None,
            created_at: chrono::Utc::now(),
        })
        .await
        .unwrap();
    let pcr = &fixture.controller.history.events[0].realm_id;
    let active = signed_status(&fixture, &account, None, AccountStatus::Active, pcr);
    let store = PgAccountStatusReplicaStore {
        pool: fixture.pool.clone(),
    };
    append(&store, &fixture, &active, &fixture.station).await;
    let terminal = signed_status(
        &fixture,
        &account,
        Some(&active),
        AccountStatus::ErasurePending,
        pcr,
    );
    let receipt = signed_receipt(&fixture, &terminal, &fixture.station);
    // Hold the same Account gate used by private PG writers;
    // unlike a time-based assertion, the backend PID proves the actual wait.
    let mut writer = crate::account_content_delivery::DeliveryGuard::begin(&fixture.pool)
        .await
        .unwrap();
    crate::pcr_private_authority::require_active_account_owner(writer.connection(), &account)
        .await
        .unwrap();
    let writer_pid = sql_query("SELECT pg_backend_pid()::bigint AS value")
        .get_result::<Count>(writer.connection())
        .await
        .unwrap()
        .value;
    let pool = fixture.pool.clone();
    let waiter = tokio::spawn(async move {
        PgAccountStatusReplicaStore { pool }
            .append(&terminal, &receipt)
            .await
    });
    let observed=tokio::time::timeout(std::time::Duration::from_secs(10),async {
        loop {
            let mut conn=fixture.pool.get().await.unwrap();
            let blocked=sql_query("SELECT EXISTS(SELECT 1 FROM pg_stat_activity a WHERE a.datname=current_database() AND $1::integer=ANY(pg_blocking_pids(a.pid)) AND a.query LIKE 'WITH owner AS (INSERT INTO accounts%') AS value")
                .bind::<BigInt,_>(writer_pid).get_result::<Present>(&mut *conn).await.unwrap();
            if blocked.value {break;}
            tokio::task::yield_now().await;
        }
    }).await;
    let was_waiting = !waiter.is_finished();
    coland_storage::AccountContentDeliveryGuard::finish(writer)
        .await
        .unwrap();
    let outcome = waiter.await.unwrap().unwrap();
    assert!(
        observed.is_ok(),
        "the terminal projection never waited for the actual writer PID"
    );
    assert!(was_waiting);
    assert!(matches!(outcome, AccountStatusReplicaAppend::Accepted(_)));
    let mut conn = fixture.pool.get().await.unwrap();
    let error = crate::pcr_private_authority::require_active_account_owner(&mut conn, &account)
        .await
        .expect_err("terminal owner admitted a new private write");
    assert_eq!(
        error.conflict_code(),
        Some(coland_storage::ConflictCode::AccountErased)
    );
}

fn completion(
    pending: &AccountErasureExecution,
    fixture: &OriginFixture,
    at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<ErasureReceiptPackage> {
    let receipt_id = arkret_models_collaboration::governance::erasure::account_erasure_receipt_id(
        &pending.triggering_status_record_id,
        pending.storage_boundary,
    );
    let subject = ErasureSubject {
        kind: ErasureSubjectKind::Principal,
        subject_ref: pending.principal_id.to_string(),
    };
    let scope = ErasureScope {
        storage_boundary: pending.storage_boundary,
        realm_id: None,
        target_refs: vec![pending.principal_id.to_string()],
        retention_policy_id: None,
        service_scope: Some("account_status.erasure_execution".into()),
    };
    let trigger = ErasureTrigger::AccountStatusRecord {
        account_status_record_id: pending.triggering_status_record_id.clone(),
    };
    let stub = serde_json::from_value(serde_json::json!({
        "stub_schema":arkret_wire::SchemaId::ERASURE_VERIFICATION_STUB_V1,
        "receipt_id":receipt_id,"trigger":trigger,"subject":subject,"scope":scope,
        "completed_at":arkret_canonical::format_timestamp_canonical(at),
    }))
    .map_err(PersistenceError::database)?;
    let mut receipt = ErasureReceipt {
        receipt_id,
        trigger,
        schema: ErasureReceipt::SCHEMA.into(),
        issuer_id: pending.receiver_id.clone(),
        subject,
        scope,
        outcome: ErasureAttemptOutcome::Completed,
        erased_classes: vec![
            ErasedClass::AccountPrivateState,
            ErasedClass::PushRoutes,
            ErasedClass::DeviceSecrets,
            ErasedClass::ProjectionRows,
        ],
        retained_stub_digest: Hash::new(arkret_canonical::canonical_sha256(&stub).unwrap())
            .unwrap(),
        retained_stub: None,
        legal_hold_ref: None,
        completed_at: at,
        issued_at: Some(at),
        proofs: vec![],
        fanout_status: None,
        peer_receipts: vec![],
    };
    let payload = receipt.canonical_proof_input().unwrap();
    let header = arkret_canonical::canonical_json_bytes(&serde_json::json!({
        "alg":"Ed25519","kid":fixture.method,
    }))
    .unwrap();
    let protected = arkret_canonical::base64url_encode(&header);
    let signing_input = format!(
        "{protected}.{}",
        arkret_canonical::base64url_encode(&payload)
    );
    let signature = fixture.issuer.sign(signing_input.as_bytes());
    fixture
        .issuer
        .verifying_key()
        .verify_strict(signing_input.as_bytes(), &signature)
        .unwrap();
    receipt.proofs.push(ErasureReceiptProof {
        verification_method: fixture.method.clone(),
        payload_digest: receipt.canonical_payload_digest().unwrap(),
        signature: format!(
            "{protected}..{}",
            arkret_canonical::base64url_encode(signature.to_bytes())
        ),
        extra: std::collections::BTreeMap::from([
            ("scheme".into(), serde_json::json!("ed25519-detached-jws")),
            (
                "signature_input".into(),
                serde_json::json!("rfc7515-detached-jws"),
            ),
        ]),
    });
    let package = ErasureReceiptPackage {
        receipt,
        retained_stub: stub,
    };
    package
        .validate_bindings()
        .map_err(PersistenceError::database)?;
    Ok(package)
}

async fn intent(
    fixture: &OriginFixture,
    account: &AccountId,
    receiver: &DidCoreId,
) -> AccountErasureExecution {
    intent_with_pcr(
        fixture,
        account,
        receiver,
        &fixture.controller.history.events[0].realm_id,
    )
    .await
}

async fn intent_with_pcr(
    fixture: &OriginFixture,
    account: &AccountId,
    receiver: &DidCoreId,
    pcr: &arkret_wire::RealmId,
) -> AccountErasureExecution {
    let store = PgAccountStatusReplicaStore {
        pool: fixture.pool.clone(),
    };
    let active = signed_status(fixture, account, None, AccountStatus::Active, pcr);
    append(&store, fixture, &active, receiver).await;
    let terminal = signed_status(
        fixture,
        account,
        Some(&active),
        AccountStatus::ErasurePending,
        pcr,
    );
    append(&store, fixture, &terminal, receiver).await;
    let pending = AccountErasureExecution {
        receiver_id: receiver.clone(),
        account_authority_id: fixture.station.clone(),
        account_id: account.clone(),
        principal_id: account.principal_id.clone(),
        triggering_status_record_id: terminal.account_status_record_id,
        storage_boundary: ErasureStorageBoundary::AccountPrivateStore,
        state: AccountErasureExecutionState::Pending,
        package: None,
    };
    let mut conn = fixture.pool.get().await.unwrap();
    let retained = execution_row(&mut conn, &pending, AccountErasureExecutionState::Pending)
        .await
        .unwrap()
        .expect("the actual accepted terminal append retained its intent atomically");
    assert_eq!(retained.request_hash, pending.request_hash().unwrap());
    assert_eq!(
        serde_json::from_value::<AccountErasureExecution>(retained.response_body).unwrap(),
        pending
    );
    pending
}

#[tokio::test]
async fn physical_completion_failure_rolls_back_then_cold_reopen_replays_original_signed_bytes() {
    let fixture = Box::pin(OriginFixture::new()).await;
    let persistence = crate::PgPersistenceStore::new(fixture.pool.clone());
    let account = fixture.controller.history.account.clone();
    let profile = AccountRecord {
        pk: AccountPk(0),
        principal_id: account.principal_id.clone(),
        station_id: account.station_id.clone(),
        localpart: "erase-private-handle".into(),
        display_name: Some("private profile".into()),
        biography: Some("private biography".into()),
        avatar_blob_ref: None,
        created_at: chrono::Utc::now(),
    };
    persistence.accounts().put(&profile).await.unwrap();
    let actor = ActorId::account(account.clone()).to_string();
    let data = AccountDataRecord {
        actor: actor.clone(),
        account_data_key: "ak.private-erasure-test".into(),
        payload: serde_json::json!({"private":"must roll back"}),
        revision: 1,
        tombstone: false,
        updated_at: chrono::Utc::now(),
    };
    assert!(matches!(
        persistence
            .account_data()
            .compare_and_set(&data, 0)
            .await
            .unwrap(),
        coland_storage::AccountDataCasResult::Applied(_)
    ));
    let pending = intent(&fixture, &account, &fixture.station).await;
    let signed = AtomicUsize::new(0);
    let sign = |at| {
        signed.fetch_add(1, Ordering::SeqCst);
        completion(&pending, &fixture, at)
    };
    let failure=std::panic::AssertUnwindSafe(async {
        let mut conn=fixture.pool.get().await.unwrap();
        // The exact key lives in the immutable test-owned predicate. No other
        // job or timing policy changes. Cleanup also runs after a panic.
        sql_query(format!("CREATE FUNCTION erasure_completion_owned_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.idempotency_key='{}' THEN RAISE EXCEPTION 'owned completion fault' USING ERRCODE='40001'; END IF; RETURN NEW; END; $$",pending.key(AccountErasureExecutionState::Completed)))
            .execute(&mut *conn).await.unwrap();
        sql_query("CREATE TRIGGER erasure_completion_owned_fault BEFORE INSERT ON idempotency_keys FOR EACH ROW EXECUTE FUNCTION erasure_completion_owned_fault()")
            .execute(&mut *conn).await.unwrap();
        drop(conn);
        assert!(complete(&fixture.pool, &pending, &sign).await.is_err());
        assert_eq!(signed.load(Ordering::SeqCst), 1);
        assert_eq!(persistence.account_data().get(&actor,&data.account_data_key)
            .await.unwrap().unwrap().payload,data.payload);
        let mut conn=fixture.pool.get().await.unwrap();
        let private=sql_query("SELECT COUNT(*) AS value FROM invite_new_source_hmac_keys h JOIN accounts a ON a.pk=h.account_pk WHERE a.principal_id=$1 AND a.station_id=$2")
            .bind::<Text,_>(account.principal_id.as_str()).bind::<Text,_>(account.station_id.as_str())
            .get_result::<Count>(&mut *conn).await.unwrap();
        assert_eq!(private.value,1);
    }).catch_unwind().await;
    let mut conn = fixture.pool.get().await.unwrap();
    sql_query("DROP TRIGGER IF EXISTS erasure_completion_owned_fault ON idempotency_keys")
        .execute(&mut *conn)
        .await
        .unwrap();
    sql_query("DROP FUNCTION IF EXISTS erasure_completion_owned_fault()")
        .execute(&mut *conn)
        .await
        .unwrap();
    drop(conn);
    if let Err(panic) = failure {
        std::panic::resume_unwind(panic);
    }
    let completed = complete(&fixture.pool, &pending, &sign).await.unwrap();
    assert_eq!(signed.load(Ordering::SeqCst), 2);
    assert!(
        persistence
            .account_data()
            .get(&actor, &data.account_data_key)
            .await
            .unwrap()
            .is_none()
    );
    let bytes = arkret_canonical::canonical_json_bytes(&completed).unwrap();
    let cold = PgAccountStatusReplicaStore {
        pool: fixture.pool.clone(),
    };
    let never_sign = |_| -> PersistenceResult<ErasureReceiptPackage> {
        panic!("durable completion must replay its original signature")
    };
    let replay = cold.complete_erasure(&pending, &never_sign).await.unwrap();
    assert_eq!(
        arkret_canonical::canonical_json_bytes(&replay).unwrap(),
        bytes
    );
    assert_eq!(completed.package, replay.package);
    assert!(
        crate::pcr_private_authority::accepted_governance(
            &mut *fixture.pool.get().await.unwrap(),
            &fixture.controller.history.events[0].realm_id
        )
        .await
        .is_ok()
    );
}

#[tokio::test]
async fn accepted_foreign_receiver_erases_exact_private_boundary_without_importing_human_pcr() {
    let fixture = Box::pin(OriginFixture::new()).await;
    let receiver = fixture.station.clone();
    let account = AccountId::new(
        DidCoreId::new("ak:did_core:web:foreign-org.example").unwrap(),
        DidCoreId::new("ak:did_core:web:foreign-identity-station.example").unwrap(),
    );
    let pending = intent(&fixture, &account, &receiver).await;
    let mut conn = fixture.pool.get().await.unwrap();
    let allowed = sql_query("SELECT account_private_erasure_allowed($1) AS value")
        .bind::<Jsonb, _>(serde_json::to_value(&account).unwrap())
        .get_result::<Present>(&mut *conn)
        .await
        .unwrap();
    assert!(allowed.value);
    let absent=sql_query("SELECT NOT EXISTS(SELECT 1 FROM principal_resolutions WHERE principal_id=$1 AND station_id=$2) AS value")
        .bind::<Text,_>(account.principal_id.as_str()).bind::<Text,_>(account.station_id.as_str())
        .get_result::<Present>(&mut *conn).await.unwrap();
    assert!(absent.value);
    let keys=sql_query("SELECT COUNT(*) AS value FROM invite_new_source_hmac_keys h JOIN accounts a ON a.pk=h.account_pk WHERE a.principal_id=$1 AND a.station_id=$2")
        .bind::<Text,_>(account.principal_id.as_str()).bind::<Text,_>(account.station_id.as_str())
        .get_result::<Count>(&mut *conn).await.unwrap();
    assert_eq!(keys.value, 0);
    drop(conn);
    let sign = |at| completion(&pending, &fixture, at);
    let completed = complete(&fixture.pool, &pending, &sign).await.unwrap();
    assert_eq!(completed.receiver_id, receiver);
    let mut wrong = pending.clone();
    wrong.receiver_id = DidCoreId::new("ak:did_core:web:wrong-receiver.example").unwrap();
    assert!(complete(&fixture.pool, &wrong, &sign).await.is_err());
}

fn queue_batch(
    sender: &AccountId,
    sender_device: &coland_storage::DeviceRevocationGateSelector,
    recipient: &AccountId,
    recipient_device: &coland_storage::DeviceRevocationGateSelector,
) -> coland_storage::DeviceMessageBatchRecord {
    use arkret_models_collaboration::device_messages::{
        DeviceMessageEnvelope, DeviceMessageSender,
    };
    let now = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    let key = uuid::Uuid::now_v7().to_string();
    let message = coland_storage::DeviceMessageRecord {
        idempotency_key: key.clone(),
        sender: sender.principal_id.to_string(),
        recipient: recipient.principal_id.to_string(),
        device_id: recipient_device.device_id.clone(),
        recipient_device_authorization: recipient_device.clone(),
        position: 0,
        envelope: DeviceMessageEnvelope {
            device_message_id: format!("ak:device_message:{key}").parse().unwrap(),
            kind: arkret_wire::wire_strings::ProtocolKind::new("ak.read_cursor.update").unwrap(),
            sender: DeviceMessageSender::Account {
                sender_account_id: sender.clone(),
                sender_device_id: sender_device.device_id.parse().unwrap(),
            },
            recipient_account_id: recipient.clone(),
            recipient_device_id: recipient_device.device_id.parse().unwrap(),
            sent_at: now,
            expires_at: now + chrono::Duration::minutes(5),
            content: std::collections::BTreeMap::from([(
                "fixture".into(),
                serde_json::json!("private queue payload"),
            )]),
            unsigned: None,
        },
    };
    let digest = arkret_canonical::canonical_sha256(&message.envelope).unwrap();
    coland_storage::DeviceMessageBatchRecord {
        request_key: format!("request-{key}"),
        request_digest: digest.clone(),
        idempotency_expires_at: now + chrono::Duration::hours(1),
        per_device_queue_capacity: 0,
        target_snapshot_guard: None,
        device_revocation_gate: Some(sender_device.clone()),
        sender_agent_guard: None,
        items: vec![coland_storage::DeviceMessageBatchItemRecord {
            message_key: format!("message-{key}"),
            intent_digest: digest,
            idempotency_expires_at: now + chrono::Duration::hours(1),
            message: Some(message),
        }],
    }
}

#[tokio::test]
async fn actual_queue_batch_returns_terminal_recipient_unknown_and_sender_typed_erased() {
    use coland_storage::DeviceMessageStore as _;
    let fixture = Box::pin(OriginFixture::new()).await;
    let persistence = crate::PgPersistenceStore::new(fixture.pool.clone());
    let sender = &fixture.controller.history.account;
    let recipient =
        coland_test_support::pcr_genesis::PcrGenesisFixture::new(fixture.station_did.clone());
    let sender_device = fixture
        .controller
        .admit_founding_device(&persistence)
        .await
        .unwrap();
    let recipient_device = recipient.admit_founding_device(&persistence).await.unwrap();
    for account in [sender, &recipient.history.account] {
        persistence
            .accounts()
            .put(&AccountRecord {
                pk: AccountPk(0),
                principal_id: account.principal_id.clone(),
                station_id: account.station_id.clone(),
                localpart: String::new(),
                display_name: None,
                biography: None,
                avatar_blob_ref: None,
                created_at: chrono::Utc::now(),
            })
            .await
            .unwrap();
    }
    let store = crate::devices::PgDeviceMessageStore {
        pool: fixture.pool.clone(),
    };
    let initial = queue_batch(
        sender,
        &sender_device,
        &recipient.history.account,
        &recipient_device,
    );
    let initial_key = initial.items[0].message_key.clone();
    let accepted = store.commit_batch(initial).await.unwrap();
    assert!(
        matches!(accepted,coland_storage::DeviceMessageBatchCommitOutcome::Stored(ref outcomes) if outcomes.get(&initial_key)==Some(&true))
    );
    // Real signed status/receipt admission wins after a preflight could have
    // selected this actual accepted Device. The commit must derive false.
    intent_with_pcr(
        &fixture,
        &recipient.history.account,
        &fixture.station,
        &recipient.history.events[0].realm_id,
    )
    .await;
    let late = queue_batch(
        sender,
        &sender_device,
        &recipient.history.account,
        &recipient_device,
    );
    let late_key = late.items[0].message_key.clone();
    let outcome = store.commit_batch(late).await.unwrap();
    assert!(
        matches!(outcome,coland_storage::DeviceMessageBatchCommitOutcome::Stored(ref outcomes) if outcomes.get(&late_key)==Some(&false))
    );
    let mut conn = fixture.pool.get().await.unwrap();
    let rows = sql_query(
        "SELECT COUNT(*) AS value FROM device_messages WHERE recipient=$1 AND device_id=$2",
    )
    .bind::<Text, _>(recipient.history.account.principal_id.as_str())
    .bind::<Text, _>(&recipient_device.device_id)
    .get_result::<Count>(&mut *conn)
    .await
    .unwrap();
    assert_eq!(
        rows.value, 1,
        "no second delivery was created for the terminal recipient"
    );
    drop(conn);
    intent(&fixture, sender, &fixture.station).await;
    let error = store
        .commit_batch(queue_batch(
            sender,
            &sender_device,
            &recipient.history.account,
            &recipient_device,
        ))
        .await
        .unwrap_err();
    assert_eq!(
        error.conflict_code(),
        Some(coland_storage::ConflictCode::AccountErased)
    );
}

#[path = "completion_tests/mimi_tuple_tests.rs"]
mod mimi_tuple_tests;
