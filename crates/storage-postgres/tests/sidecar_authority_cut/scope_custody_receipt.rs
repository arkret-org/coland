//! Real producer/PoP/intent persistence; imported receipt fixtures are excluded.

use arkret_models_collaboration::account_status::{
    AccountStatusReceipt, AccountStatusRecord, UnsignedAccountStatusReceipt,
    UnsignedAccountStatusRecord,
};
use arkret_models_collaboration::events_payloads::event_wire::ErasureTrigger;
use arkret_models_collaboration::governance::erasure::{
    ErasedClass, ErasureAttemptOutcome, ErasureReceipt, ErasureReceiptPackage, ErasureReceiptProof,
    ErasureScope, ErasureStorageBoundary, ErasureSubject, ErasureSubjectKind,
};
use arkret_models_collaboration::objects::account_status::AccountStatus;
use coland_storage::{
    AccountErasureExecution, AccountErasureExecutionState, AccountStatusReplicaAppend,
    AgentStore as _, PersistenceError, PersistenceResult, SyncStoreRegistry as _,
};
use ed25519_dalek::Signer as _;

use super::*;

#[tokio::test]
async fn scope_custody_original_pairing_transaction_rolls_back_and_concurrent_callers_keep_one_receipt()
 {
    let fixture = fixture_future(|| owned_consumer_fixture_with_receipt_probe(1, true)).await;
    let agent = &fixture.agents[0];
    let store = coland_storage_postgres::PgAgentStore {
        pool: fixture.pool.clone(),
    };
    let original = store
        .pairing_receipt(agent.endpoint.authorization_ref.event_id.as_str())
        .await
        .unwrap()
        .unwrap();
    assert!(original.encrypted_scope_custody.is_some());
    let cold = agent._vault.reopen();
    let restored = fixture_future(|| cold.qualified_agent_scope_evidence(&agent.endpoint))
        .await
        .unwrap();
    assert_eq!(
        Some(restored.custody_ref()),
        original.scope_custody_ref.as_ref()
    );
    let retained = store
        .pairing_receipt(agent.endpoint.authorization_ref.event_id.as_str())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        retained.encrypted_scope_custody,
        original.encrypted_scope_custody
    );
    assert_eq!(retained.scope_custody_ref, original.scope_custody_ref);
}

fn signed_status(
    fixture: &OwnedConsumerFixture,
    previous: Option<&AccountStatusRecord>,
    status: AccountStatus,
) -> AccountStatusRecord {
    let key = ed25519_dalek::SigningKey::from_bytes(&[83; 32]);
    let method = arkret_wire::DidUrl::new(format!("{}#authority", fixture.station.did)).unwrap();
    let record = arkret_signatures::account_status::sign_account_status_record(
        UnsignedAccountStatusRecord {
            schema: arkret_wire::SchemaId::ACCOUNT_STATUS_RECORD_V1.into(),
            account_authority_id: fixture.station.core.clone(),
            account_id: fixture.controller.history.account.clone(),
            principal_control_realm_id: fixture.controller.history.events[0].realm_id.clone(),
            binding_version: 1,
            status_sequence: previous.map_or(1, |old| old.status_sequence + 1),
            previous_account_status_record_id: previous
                .map(|old| old.account_status_record_id.clone()),
            status,
            reason_code: None,
            reason: None,
            issued_at: arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now()),
            expires_at: None,
        },
        method,
        &key,
    )
    .unwrap();
    let document = arkret_identity::authenticated_service_document_at(
        &fixture.station.history,
        &fixture.station.core,
        record.issued_at,
    )
    .unwrap();
    let public = arkret_identity::jws::resolve_ed25519_pubkey_from_document(
        &document,
        record.proof.verification_method.as_str(),
    )
    .unwrap();
    arkret_signatures::account_status::verify_account_status_record(
        &record,
        &arkret_signatures::PublicKeyMaterial::Ed25519Raw {
            bytes: public.to_bytes().to_vec(),
        },
    )
    .unwrap();
    record
}

fn signed_receipt(
    fixture: &OwnedConsumerFixture,
    record: &AccountStatusRecord,
) -> AccountStatusReceipt {
    let key = ed25519_dalek::SigningKey::from_bytes(&[83; 32]);
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
            receiver_id: fixture.station.core.clone(),
            accepted_at: arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now()),
            verification_method: arkret_wire::DidUrl::new(format!(
                "{}#authority",
                fixture.station.did
            ))
            .unwrap(),
        },
        &key,
    )
    .unwrap();
    arkret_signatures::account_status::verify_account_status_receipt(
        &receipt,
        &arkret_signatures::PublicKeyMaterial::Ed25519Raw {
            bytes: key.verifying_key().to_bytes().to_vec(),
        },
    )
    .unwrap();
    receipt
}

fn completion(
    fixture: &OwnedConsumerFixture,
    pending: &AccountErasureExecution,
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
        retained_stub_digest: arkret_wire::Hash::new(
            arkret_canonical::canonical_sha256(&stub).unwrap(),
        )
        .unwrap(),
        retained_stub: None,
        legal_hold_ref: None,
        completed_at: at,
        issued_at: Some(at),
        proofs: vec![],
        fanout_status: None,
        peer_receipts: vec![],
    };
    let method = arkret_wire::DidUrl::new(format!("{}#authority", fixture.station.did)).unwrap();
    let key = ed25519_dalek::SigningKey::from_bytes(&[83; 32]);
    let header =
        arkret_canonical::canonical_json_bytes(&serde_json::json!({"alg":"Ed25519","kid":method}))
            .unwrap();
    let protected = arkret_canonical::base64url_encode(header);
    let input = format!(
        "{protected}.{}",
        arkret_canonical::base64url_encode(receipt.canonical_proof_input().unwrap())
    );
    let signature = key.sign(input.as_bytes());
    key.verifying_key()
        .verify_strict(input.as_bytes(), &signature)
        .unwrap();
    receipt.proofs.push(ErasureReceiptProof {
        verification_method: method,
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

#[tokio::test]
async fn scope_custody_completion_rollback_preserves_body_then_cold_replay_keeps_original_receipt()
{
    // Original Agent PCR, controller source, disclosure, runtime PoP, pairing
    // intent and activation are all produced by the ordinary fixture path.
    // Replica append imports actual signature-verified AA originals; this is
    // a PG completion contract, not an HTTP or external Gateway assertion.
    let fixture = boxed_owned_consumer_fixture(1).await;
    let agent = &fixture.agents[0];
    let store = coland_storage_postgres::PgAgentStore {
        pool: fixture.pool.clone(),
    };
    let original = store
        .pairing_receipt(agent.endpoint.authorization_ref.event_id.as_str())
        .await
        .unwrap()
        .unwrap();
    assert!(original.encrypted_scope_custody.is_some());
    let original_agent = store
        .get(agent.account.principal_id.as_str())
        .await
        .unwrap()
        .unwrap();
    assert!(original_agent.requested_scope.is_some());
    let evidence = fixture_future(|| {
        agent
            ._vault
            .state
            .qualified_agent_scope_evidence(&agent.endpoint)
    })
    .await
    .unwrap();
    let persistence = coland_storage_postgres::PgPersistenceStore::new(fixture.pool.clone());
    let replicas = persistence.account_status_replicas();
    let active = signed_status(&fixture, None, AccountStatus::Active);
    assert!(matches!(
        replicas
            .append(&active, &signed_receipt(&fixture, &active))
            .await
            .unwrap(),
        AccountStatusReplicaAppend::Accepted(_)
    ));
    let terminal = signed_status(&fixture, Some(&active), AccountStatus::ErasurePending);
    assert!(matches!(
        replicas
            .append(&terminal, &signed_receipt(&fixture, &terminal))
            .await
            .unwrap(),
        AccountStatusReplicaAppend::Accepted(_)
    ));
    let pending = AccountErasureExecution {
        receiver_id: fixture.station.core.clone(),
        account_authority_id: fixture.station.core.clone(),
        account_id: fixture.controller.history.account.clone(),
        principal_id: fixture.controller.history.account.principal_id.clone(),
        triggering_status_record_id: terminal.account_status_record_id,
        storage_boundary: ErasureStorageBoundary::AccountPrivateStore,
        state: AccountErasureExecutionState::Pending,
        package: None,
    };
    let failed = |_| -> PersistenceResult<ErasureReceiptPackage> {
        Err(PersistenceError::Internal(
            "owned signing failure after physical purge".into(),
        ))
    };
    assert!(replicas.complete_erasure(&pending, &failed).await.is_err());
    let rolled_back = store
        .pairing_receipt(agent.endpoint.authorization_ref.event_id.as_str())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        rolled_back.encrypted_scope_custody,
        original.encrypted_scope_custody
    );
    assert_eq!(
        store
            .get(agent.account.principal_id.as_str())
            .await
            .unwrap()
            .unwrap()
            .requested_scope,
        original_agent.requested_scope
    );
    let late = coland_storage::AgentPairingCommitIntent {
        agent_id: agent.account.principal_id.to_string(),
        approval_request_id: original.approval_request_id.clone(),
        runtime_key_binding_digest: original.runtime_key_binding_digest.clone(),
        pairing_request_id: original.pairing_request_id.clone(),
        request_digest: original.request_digest.clone(),
        authorize_event_id: original.authorize_event_ref.clone(),
        key_authorization_event: evidence.command().authorize_event.event.clone(),
        scope_custody_ref: original.scope_custody_ref.clone(),
        prepared_scope_custody: None,
    };
    let refusal = store
        .put_pairing_commit_intent_if_compatible(&late)
        .await
        .unwrap_err();
    assert_eq!(
        refusal.conflict_code(),
        Some(coland_storage::ConflictCode::AccountErased)
    );
    let sign = |at| completion(&fixture, &pending, at);
    let completed = replicas.complete_erasure(&pending, &sign).await.unwrap();
    let erased = store
        .pairing_receipt(agent.endpoint.authorization_ref.event_id.as_str())
        .await
        .unwrap()
        .unwrap();
    assert!(erased.encrypted_scope_custody.is_none());
    assert_eq!(erased.scope_custody_ref, original.scope_custody_ref);
    let public_agent = store
        .get(agent.account.principal_id.as_str())
        .await
        .unwrap()
        .unwrap();
    assert!(public_agent.requested_scope.is_none());
    let cold_state = agent._vault.reopen();
    assert!(
        fixture_future(|| cold_state.qualified_agent_scope_evidence(&agent.endpoint))
            .await
            .is_err()
    );
    let cold_persistence = coland_storage_postgres::PgPersistenceStore::new(fixture.pool.clone());
    let cold = cold_persistence.account_status_replicas();
    let never_sign = |_| -> PersistenceResult<ErasureReceiptPackage> {
        panic!("cold replay must retain the original signature")
    };
    let replay = cold.complete_erasure(&pending, &never_sign).await.unwrap();
    assert_eq!(
        arkret_canonical::canonical_json_bytes(&replay).unwrap(),
        arkret_canonical::canonical_json_bytes(&completed).unwrap()
    );
    let retained_genesis = PgAuthorityCommitStore {
        pool: fixture.pool.clone(),
    }
    .committed_event(&agent.genesis.event.event_id)
    .await
    .unwrap()
    .unwrap();
    assert_eq!(retained_genesis.event, agent.genesis.event);
}

#[derive(diesel::QueryableByName)]
struct ScopeWriterBackend {
    #[diesel(sql_type = diesel::sql_types::BigInt)]
    pid: i64,
    #[diesel(sql_type = diesel::sql_types::Text)]
    database_name: String,
    #[diesel(sql_type = diesel::sql_types::Timestamptz)]
    backend_start: chrono::DateTime<chrono::Utc>,
}

#[derive(diesel::QueryableByName)]
struct ScopeDisconnectFlag {
    #[diesel(sql_type = diesel::sql_types::Bool)]
    value: bool,
}

fn isolated_scope_writer_pool(url: &str) -> coland_storage_postgres::PgPool {
    coland_storage_postgres::PgPool::builder(
        diesel_async::pooled_connection::AsyncDieselConnectionManager::new(url),
    )
    .max_size(1)
    .build()
    .unwrap()
}

async fn scope_pairing_effects(
    pool: &coland_storage_postgres::PgPool,
    agent_id: &str,
) -> serde_json::Value {
    use diesel::sql_types::{Jsonb, Text};
    use diesel_async::RunQueryDsl as _;
    #[derive(diesel::QueryableByName)]
    struct Effects {
        #[diesel(sql_type = Jsonb)]
        value: serde_json::Value,
    }
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query(
        "SELECT jsonb_build_object(\
         'agent',(SELECT to_jsonb(a) FROM agent_principals a WHERE a.id=$1),\
         'receipts',COALESCE((SELECT jsonb_agg(to_jsonb(r) ORDER BY r.authorize_event_ref) \
         FROM agent_pairing_receipts r WHERE r.agent_id=$1),'[]'::jsonb)) AS value",
    )
    .bind::<Text, _>(agent_id)
    .get_result::<Effects>(&mut conn)
    .await
    .unwrap()
    .value
}

#[tokio::test]
async fn scope_custody_disconnected_first_writer_rolls_back_before_erasure_and_cold_retry_is_terminal()
 {
    fixture_future(case_scope_custody_disconnected_first_writer).await;
}

async fn case_scope_custody_disconnected_first_writer() {
    use diesel::sql_types::{BigInt, Text, Timestamptz};
    use diesel_async::RunQueryDsl as _;
    use futures_util::FutureExt as _;

    // Preparation includes the actual accepted controller/Agent source,
    // signature-verified runtime PoP and freshly sealed original ciphertext.
    // It stops before the production first receipt transaction or activation.
    let (fixture, prepared) =
        fixture_future(|| owned_consumer_fixture_with_prepared_scope(1, false, true)).await;
    assert!(fixture.agents.is_empty());
    let (vault, intent, activation) = *prepared.unwrap();
    assert_eq!(intent.authorize_event_id, activation.authorized_event_ref);
    assert_eq!(
        intent.key_authorization_event,
        activation.frozen_authorize_event
    );
    let original_evidence = intent
        .prepared_scope_custody
        .as_ref()
        .unwrap()
        .evidence
        .clone();
    let original_reference = intent.scope_custody_ref.clone();
    let original_digest = intent.request_digest.clone();
    let store = coland_storage_postgres::PgAgentStore {
        pool: fixture.pool.clone(),
    };
    assert!(
        store
            .pairing_receipt(&intent.authorize_event_id)
            .await
            .unwrap()
            .is_none()
    );
    let service_secret_file = std::fs::read(vault.directory.join("private-vault.enc")).unwrap();
    let persistence = coland_storage_postgres::PgPersistenceStore::new(fixture.pool.clone());
    let replicas = persistence.account_status_replicas();
    let active = signed_status(&fixture, None, AccountStatus::Active);
    assert!(matches!(
        replicas
            .append(&active, &signed_receipt(&fixture, &active))
            .await
            .unwrap(),
        AccountStatusReplicaAppend::Accepted(_)
    ));
    let before = scope_pairing_effects(&fixture.pool, &intent.agent_id).await;
    assert_eq!(before["receipts"], serde_json::json!([]));
    assert!(before["agent"]["pending_pairing_commit_intent"].is_null());
    assert!(!before["agent"]["requested_scope"].is_null());

    // Only this leased database and a dedicated one-connection client pool
    // participate. Capture its exact backend identity before the real call.
    let writer_pool = isolated_scope_writer_pool(fixture._database.url());
    let mut conn = writer_pool.get().await.unwrap();
    let backend = diesel::sql_query("SELECT pid::bigint AS pid,datname::text AS database_name,backend_start FROM pg_stat_activity WHERE pid=pg_backend_pid() AND backend_type='client backend'")
        .get_result::<ScopeWriterBackend>(&mut conn).await.unwrap();
    drop(conn);
    let mut observer = fixture.pool.get().await.unwrap();
    let own_db = diesel::sql_query("SELECT pid::bigint AS pid,datname::text AS database_name,backend_start FROM pg_stat_activity WHERE pid=pg_backend_pid() AND backend_type='client backend'")
        .get_result::<ScopeWriterBackend>(&mut observer).await.unwrap();
    assert_eq!(backend.database_name, own_db.database_name);
    assert_ne!(backend.pid, own_db.pid);
    let mut holder = fixture.pool.get().await.unwrap();
    let holder_backend = diesel::sql_query("SELECT pid::bigint AS pid,datname::text AS database_name,backend_start FROM pg_stat_activity WHERE pid=pg_backend_pid() AND backend_type='client backend'")
        .get_result::<ScopeWriterBackend>(&mut holder).await.unwrap();
    assert_eq!(holder_backend.database_name, own_db.database_name);
    assert_ne!(holder_backend.pid, backend.pid);
    let barrier_key = rand::random::<i64>();
    diesel::sql_query("BEGIN")
        .execute(&mut holder)
        .await
        .unwrap();
    diesel::sql_query("SELECT pg_advisory_xact_lock($1)")
        .bind::<BigInt, _>(barrier_key)
        .execute(&mut holder)
        .await
        .unwrap();
    let suffix = uuid::Uuid::now_v7().simple().to_string();
    let hook = format!("scope_disconnect_{suffix}");
    assert!(!intent.authorize_event_id.contains('\''));
    let function_sql = format!(
        "CREATE FUNCTION {hook}() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN \
         IF NEW.authorize_event_ref='{}' THEN \
         IF OLD.encrypted_scope_custody IS NOT NULL OR NEW.encrypted_scope_custody IS NULL \
         OR NEW.scope_custody_ref IS NULL THEN RAISE EXCEPTION 'expected first ciphertext update'; END IF; \
         IF NOT EXISTS(SELECT 1 FROM agent_principals a WHERE a.id=NEW.agent_id \
         AND a.pending_pairing_commit_intent->>'authorize_event_id'=NEW.authorize_event_ref \
         AND a.pending_pairing_commit_intent->'scope_custody_ref'=NEW.scope_custody_ref) \
         THEN RAISE EXCEPTION 'original pending intent has not reached its receipt update'; END IF; \
         PERFORM pg_advisory_xact_lock({barrier_key}::bigint); \
         END IF; RETURN NEW; END $$",
        intent.authorize_event_id,
    );
    let trigger_sql = format!(
        "CREATE TRIGGER {hook} BEFORE UPDATE OF encrypted_scope_custody ON agent_pairing_receipts FOR EACH ROW EXECUTE FUNCTION {hook}()"
    );
    let (start_writer, start_receiver) = tokio::sync::oneshot::channel();
    let original_intent = intent.clone();
    let owned_pool = writer_pool.clone();
    let mut writer = tokio::spawn(fixture_future(|| async move {
        start_receiver
            .await
            .expect("the owned receipt barrier is installed before dispatch");
        coland_storage_postgres::PgAgentStore { pool: owned_pool }
            .put_pairing_commit_intent_if_compatible(&original_intent)
            .await
    }));
    let mut joined = false;
    let outcome = std::panic::AssertUnwindSafe(async {
        diesel::sql_query(function_sql).execute(&mut observer).await.unwrap();
        diesel::sql_query(trigger_sql).execute(&mut observer).await.unwrap();
        start_writer.send(()).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(30), async {
            loop {
                let query = diesel::sql_query("SELECT EXISTS(SELECT 1 FROM pg_stat_activity a WHERE a.pid=$1::bigint::integer AND a.datname=$2 AND a.backend_start=$3 AND a.backend_type='client backend' AND a.wait_event_type='Lock' AND a.query LIKE 'UPDATE agent_pairing_receipts SET encrypted_scope_custody=%' AND $4::bigint::integer=ANY(pg_blocking_pids(a.pid)) AND EXISTS(SELECT 1 FROM pg_locks l WHERE l.pid=a.pid AND l.locktype='advisory' AND NOT l.granted)) AS value")
                    .bind::<BigInt, _>(backend.pid).bind::<Text, _>(&backend.database_name)
                    .bind::<Timestamptz, _>(backend.backend_start)
                    .bind::<BigInt, _>(holder_backend.pid)
                    .get_result::<ScopeDisconnectFlag>(&mut observer);
                tokio::select! {
                    early = &mut writer => {
                        joined = true;
                        panic!("original intent returned before the actual ciphertext barrier: {early:?}");
                    }
                    observed = query => {
                        if observed.unwrap().value { break; }
                    }
                }
                tokio::task::yield_now().await;
            }
        }).await.expect("the real intent writer must reach its owned first-ciphertext barrier");
        // The production call has already passed the Account owner gate,
        // Agent row lock, original receipt INSERT and trigger, but none commit.
        // Termination is conditional on the exact same DB/PID/start/client
        // identity and its observed wait on this test's specific holder.
        let terminated = diesel::sql_query("SELECT COALESCE((SELECT pg_terminate_backend(a.pid) FROM pg_stat_activity a WHERE a.pid=$1::bigint::integer AND a.datname=$2 AND a.backend_start=$3 AND a.backend_type='client backend' AND a.pid<>pg_backend_pid() AND a.wait_event_type='Lock' AND a.query LIKE 'UPDATE agent_pairing_receipts SET encrypted_scope_custody=%' AND $4::bigint::integer=ANY(pg_blocking_pids(a.pid))),FALSE) AS value")
            .bind::<BigInt, _>(backend.pid).bind::<Text, _>(&backend.database_name)
            .bind::<Timestamptz, _>(backend.backend_start)
            .bind::<BigInt, _>(holder_backend.pid)
            .get_result::<ScopeDisconnectFlag>(&mut observer).await.unwrap();
        assert!(terminated.value, "only the exact blocked owned writer may be terminated");
        let failed = (&mut writer).await.expect("the original task reports its database error");
        joined = true;
        assert!(matches!(failed, Err(PersistenceError::Database(_))),
            "actual connection loss must be a database failure, not a synthetic serialization refusal");
    }).catch_unwind().await;

    // Clean up owned tasks/schema on both the successful and panic paths.
    // A dedicated pool cannot lend this PID to another caller or database.
    writer_pool.close();
    if !joined {
        writer.abort();
        let _ = (&mut writer).await;
    }
    let _ = diesel::sql_query("SELECT COALESCE((SELECT pg_terminate_backend(a.pid) FROM pg_stat_activity a WHERE a.pid=$1::bigint::integer AND a.datname=$2 AND a.backend_start=$3 AND a.backend_type='client backend' AND a.pid<>pg_backend_pid()),FALSE) AS value")
        .bind::<BigInt, _>(backend.pid).bind::<Text, _>(&backend.database_name)
        .bind::<Timestamptz, _>(backend.backend_start)
        .get_result::<ScopeDisconnectFlag>(&mut observer).await;
    diesel::sql_query("ROLLBACK")
        .execute(&mut holder)
        .await
        .unwrap();
    diesel::sql_query(format!(
        "DROP TRIGGER IF EXISTS {hook} ON agent_pairing_receipts"
    ))
    .execute(&mut observer)
    .await
    .unwrap();
    diesel::sql_query(format!("DROP FUNCTION IF EXISTS {hook}()"))
        .execute(&mut observer)
        .await
        .unwrap();
    drop(holder);
    drop(observer);
    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic);
    }

    assert_eq!(
        scope_pairing_effects(&fixture.pool, &intent.agent_id).await,
        before
    );
    assert!(
        store
            .pairing_receipt(&intent.authorize_event_id)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        std::fs::read(vault.directory.join("private-vault.enc")).unwrap(),
        service_secret_file
    );

    // No successful receipt retry, activation or re-preparation occurs between
    // this disconnect and the genuine signed terminal append/physical commit.
    let terminal = signed_status(&fixture, Some(&active), AccountStatus::ErasurePending);
    assert!(matches!(
        replicas
            .append(&terminal, &signed_receipt(&fixture, &terminal))
            .await
            .unwrap(),
        AccountStatusReplicaAppend::Accepted(_)
    ));
    let pending = AccountErasureExecution {
        receiver_id: fixture.station.core.clone(),
        account_authority_id: fixture.station.core.clone(),
        account_id: fixture.controller.history.account.clone(),
        principal_id: fixture.controller.history.account.principal_id.clone(),
        triggering_status_record_id: terminal.account_status_record_id,
        storage_boundary: ErasureStorageBoundary::AccountPrivateStore,
        state: AccountErasureExecutionState::Pending,
        package: None,
    };
    let sign = |at| completion(&fixture, &pending, at);
    let completed = replicas.complete_erasure(&pending, &sign).await.unwrap();
    assert_eq!(completed.state, AccountErasureExecutionState::Completed);
    let package = completed.package.as_ref().unwrap();
    package.validate_bindings().unwrap();
    assert_eq!(package.receipt.outcome, ErasureAttemptOutcome::Completed);
    let cold_pool = isolated_scope_writer_pool(fixture._database.url());
    let cold_persistence = coland_storage_postgres::PgPersistenceStore::new(cold_pool.clone());
    let cold_replicas = cold_persistence.account_status_replicas();
    let never_sign = |_| -> PersistenceResult<ErasureReceiptPackage> {
        panic!("cold completion must return its original signed package")
    };
    let cold_completed = cold_replicas
        .complete_erasure(&pending, &never_sign)
        .await
        .unwrap();
    assert_eq!(
        arkret_canonical::canonical_json_bytes(&cold_completed).unwrap(),
        arkret_canonical::canonical_json_bytes(&completed).unwrap()
    );
    assert_eq!(intent.request_digest, original_digest);
    assert_eq!(intent.scope_custody_ref, original_reference);
    assert_eq!(
        intent.prepared_scope_custody.as_ref().unwrap().evidence,
        original_evidence
    );
    let cold_store = coland_storage_postgres::PgAgentStore {
        pool: cold_pool.clone(),
    };
    let terminal_effects = scope_pairing_effects(&cold_pool, &intent.agent_id).await;
    assert_eq!(terminal_effects["receipts"], serde_json::json!([]));
    assert!(terminal_effects["agent"]["pending_pairing_commit_intent"].is_null());
    assert!(terminal_effects["agent"]["requested_scope"].is_null());
    let refused = cold_store
        .put_pairing_commit_intent_if_compatible(&intent)
        .await
        .unwrap_err();
    assert_eq!(
        refused.conflict_code(),
        Some(coland_storage::ConflictCode::AccountErased)
    );
    assert_eq!(
        scope_pairing_effects(&cold_pool, &intent.agent_id).await,
        terminal_effects
    );
    assert_eq!(
        std::fs::read(vault.directory.join("private-vault.enc")).unwrap(),
        service_secret_file
    );
}
