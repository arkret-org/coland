//! Real frozen Organization archives against accepted Account erasure.
//! Native Genesis/change and archive export/import use production PG ports;
//! signed status material enters the trusted replica adapter. This does not
//! claim AA authentication, private network delivery or handoff activation.

#[path = "support/organization_change.rs"]
mod organization_change;
#[path = "support/organization_origin.rs"]
mod organization_origin;

use arkret_models_collaboration::account_status::{
    AccountStatusReceipt, AccountStatusRecord, UnsignedAccountStatusReceipt,
    UnsignedAccountStatusRecord,
};
use arkret_models_collaboration::authority_commit::PcrPrivateHandoffManifest;
use arkret_models_collaboration::events_payloads::event_wire::ErasureTrigger;
use arkret_models_collaboration::governance::erasure::*;
use arkret_models_collaboration::objects::account_status::AccountStatus;
use arkret_wire::{AccountId, ActorId, Did, DidCoreId, Hash};
use coland_storage::{
    AccountErasureExecution, AccountErasureExecutionState, AccountPk, AccountRecord,
    AccountStatusReplicaAppend, AuthorityCommitStore as _, ConflictCode, IdempotencyStore as _,
    IdentityStoreRegistry as _, PersistenceError, PersistenceResult, SyncStoreRegistry as _,
};
use coland_storage_postgres::test_database::TestDatabase;
use coland_storage_postgres::{
    PgAuthorityCommitStore, PgIdempotencyStore, PgPersistenceStore, PgPool,
};
use diesel::OptionalExtension as _;
use diesel::sql_types::{BigInt, Jsonb, Text};
use diesel_async::RunQueryDsl as _;
use ed25519_dalek::Signer as _;
use futures_util::FutureExt as _;
use organization_origin::OrganizationFixture;

#[inline(never)]
fn heap_future<F: std::future::Future>(make: impl FnOnce() -> F) -> std::pin::Pin<Box<F>> {
    Box::pin(make())
}

struct FrozenOrg {
    _source: TestDatabase,
    fixture: OrganizationFixture,
    holder: AccountId,
    receiver: DidCoreId,
    manifest: PcrPrivateHandoffManifest,
    bytes: Vec<u8>,
}

#[derive(diesel::QueryableByName)]
struct Count {
    #[diesel(sql_type = BigInt)]
    value: i64,
}
#[derive(diesel::QueryableByName)]
struct JsonRow {
    #[diesel(sql_type = Jsonb)]
    value: serde_json::Value,
}

async fn frozen_org() -> FrozenOrg {
    let source = TestDatabase::lease().await;
    let pool = source.pool();
    let fixture = OrganizationFixture::new(false, true);
    heap_future(|| organization_change::native_create(&pool, &fixture)).await;
    let holder = fixture
        .write
        .transaction
        .event
        .actor_id
        .as_account_id()
        .unwrap()
        .clone();
    let store = PgPersistenceStore::new(pool.clone());
    // A real projection write creates the independent local private HMAC and
    // profile. Neither this write nor the archive grants native authority.
    store
        .accounts()
        .put(&AccountRecord {
            pk: AccountPk(0),
            principal_id: holder.principal_id.clone(),
            station_id: holder.station_id.clone(),
            localpart: String::new(),
            display_name: Some("private Organization profile".into()),
            biography: Some("private archive body".into()),
            avatar_blob_ref: None,
            created_at: chrono::Utc::now(),
        })
        .await
        .unwrap();
    let planned =
        heap_future(|| organization_change::prepare_planned_change(&pool, &fixture)).await;
    let authority = PgAuthorityCommitStore { pool: pool.clone() };
    authority
        .admit_organization_pcr_governance_change(&planned)
        .await
        .unwrap();
    let (manifest, bytes) = authority.export_pcr_private_state(&holder).await.unwrap();
    let original: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        original["tables"]["invite_new_source_hmac_keys"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(manifest.holder_account_id, holder);
    assert_eq!(
        manifest.state_digest.as_str(),
        arkret_canonical::sha256_digest(&bytes)
    );
    let receiver =
        arkret_wire::project_did_to_core_id(&Did::new(&fixture.governor.did).unwrap()).unwrap();
    FrozenOrg {
        _source: source,
        fixture,
        holder,
        receiver,
        manifest,
        bytes,
    }
}

fn status_pair(
    frozen: &FrozenOrg,
    previous: Option<&AccountStatusRecord>,
    status: AccountStatus,
) -> (AccountStatusRecord, AccountStatusReceipt) {
    let fixture = &frozen.fixture;
    let source =
        arkret_wire::project_did_to_core_id(&Did::new(&fixture.producer.did).unwrap()).unwrap();
    let signer = ed25519_dalek::SigningKey::from_bytes(&fixture.producer.did_key_seed);
    let record = arkret_signatures::account_status::sign_account_status_record(
        UnsignedAccountStatusRecord {
            schema: arkret_wire::SchemaId::ACCOUNT_STATUS_RECORD_V1.into(),
            account_authority_id: source,
            account_id: frozen.holder.clone(),
            principal_control_realm_id: frozen.manifest.realm_id.clone(),
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
        arkret_wire::DidUrl::new(&fixture.producer.did_key_id).unwrap(),
        &signer,
    )
    .unwrap();
    let document = arkret_identity::authenticated_service_document_at(
        fixture.write.producer_service_resolution.as_ref().unwrap(),
        &record.account_authority_id,
        record.issued_at,
    )
    .unwrap();
    let public = arkret_identity::jws::resolve_ed25519_pubkey_from_document(
        &document,
        record.proof.verification_method.as_str(),
    )
    .unwrap();
    assert_eq!(public, signer.verifying_key());
    arkret_signatures::account_status::verify_account_status_record(
        &record,
        &arkret_signatures::PublicKeyMaterial::Ed25519Raw {
            bytes: public.to_bytes().to_vec(),
        },
    )
    .unwrap();
    let (receiver_method, receiver_seed) = fixture.governor_signer();
    let receiver_key = ed25519_dalek::SigningKey::from_bytes(&receiver_seed);
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
            receiver_id: frozen.receiver.clone(),
            accepted_at: arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now()),
            verification_method: receiver_method,
        },
        &receiver_key,
    )
    .unwrap();
    let receiver_document =
        serde_json::from_value(fixture.governor.log_entry["state"].clone()).unwrap();
    let receiver_public = arkret_identity::jws::resolve_ed25519_pubkey_from_document(
        &receiver_document,
        receipt.proof.verification_method.as_str(),
    )
    .unwrap();
    assert_eq!(receiver_public, receiver_key.verifying_key());
    arkret_signatures::account_status::verify_account_status_receipt(
        &receipt,
        &arkret_signatures::PublicKeyMaterial::Ed25519Raw {
            bytes: receiver_public.to_bytes().to_vec(),
        },
    )
    .unwrap();
    (record, receipt)
}

async fn accept_status(pool: &PgPool, pair: &(AccountStatusRecord, AccountStatusReceipt)) {
    assert!(matches!(
        PgPersistenceStore::new(pool.clone())
            .account_status_replicas()
            .append(&pair.0, &pair.1)
            .await
            .unwrap(),
        AccountStatusReplicaAppend::Accepted(_)
    ));
}

fn pending(frozen: &FrozenOrg, record: &AccountStatusRecord) -> AccountErasureExecution {
    AccountErasureExecution {
        receiver_id: frozen.receiver.clone(),
        account_authority_id: record.account_authority_id.clone(),
        account_id: frozen.holder.clone(),
        principal_id: frozen.holder.principal_id.clone(),
        triggering_status_record_id: record.account_status_record_id.clone(),
        storage_boundary: ErasureStorageBoundary::AccountPrivateStore,
        state: AccountErasureExecutionState::Pending,
        package: None,
    }
}

async fn execution(
    pool: &PgPool,
    pending: &AccountErasureExecution,
    state: AccountErasureExecutionState,
) -> Option<coland_storage::IdempotencyRecord> {
    PgIdempotencyStore { pool: pool.clone() }
        .get(
            &ActorId::service(pending.receiver_id.clone()),
            coland_storage::INTERNAL_IDEMPOTENCY_OPERATION,
            &pending.key(state),
        )
        .await
        .unwrap()
}

fn completion(
    pending: &AccountErasureExecution,
    signing_key: &ed25519_dalek::SigningKey,
    method: &arkret_wire::DidUrl,
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
        "alg":"Ed25519","kid":method,
    }))
    .unwrap();
    let protected = arkret_canonical::base64url_encode(&header);
    let signing_input = format!(
        "{protected}.{}",
        arkret_canonical::base64url_encode(&payload)
    );
    let signature = signing_key.sign(signing_input.as_bytes());
    signing_key
        .verifying_key()
        .verify_strict(signing_input.as_bytes(), &signature)
        .unwrap();
    receipt.proofs.push(ErasureReceiptProof {
        verification_method: method.clone(),
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

async fn complete(
    pool: &PgPool,
    frozen: &FrozenOrg,
    pending: &AccountErasureExecution,
) -> AccountErasureExecution {
    assert!(
        execution(pool, pending, AccountErasureExecutionState::Pending)
            .await
            .is_some(),
        "only the actually accepted terminal append can authorize this completion"
    );
    let (method, seed) = frozen.fixture.governor_signer();
    let key = ed25519_dalek::SigningKey::from_bytes(&seed);
    let signer = |at| completion(pending, &key, &method, at);
    let result = PgPersistenceStore::new(pool.clone())
        .account_status_replicas()
        .complete_erasure(pending, &signer)
        .await
        .unwrap();
    assert_eq!(result.state, AccountErasureExecutionState::Completed);
    result
        .package
        .as_ref()
        .unwrap()
        .validate_bindings()
        .unwrap();
    let never_sign = |_| -> PersistenceResult<ErasureReceiptPackage> {
        panic!("the cold adapter must return the exact durable original")
    };
    let replay = PgPersistenceStore::new(pool.clone())
        .account_status_replicas()
        .complete_erasure(pending, &never_sign)
        .await
        .unwrap();
    assert_eq!(
        arkret_canonical::canonical_json_bytes(&result).unwrap(),
        arkret_canonical::canonical_json_bytes(&replay).unwrap()
    );
    result
}

async fn private_key_count(pool: &PgPool, holder: &AccountId) -> i64 {
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query("SELECT COUNT(*) AS value FROM invite_new_source_hmac_keys h JOIN accounts a ON a.pk=h.account_pk WHERE a.principal_id=$1 AND a.station_id=$2")
        .bind::<Text,_>(holder.principal_id.as_str()).bind::<Text,_>(holder.station_id.as_str()).get_result::<Count>(&mut *conn).await.unwrap().value
}

async fn public_originals(pool: &PgPool, realm: &arkret_wire::RealmId) -> serde_json::Value {
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query("SELECT jsonb_build_object(\
        'events',(SELECT COALESCE(jsonb_agg(to_jsonb(e) ORDER BY e.pk),'[]'::jsonb) FROM canonical_events e WHERE e.realm_id=$1),\
        'genesis_sources',(SELECT COALESCE(jsonb_agg(to_jsonb(g) ORDER BY g.realm_id),'[]'::jsonb) FROM organization_pcr_genesis_sources g WHERE g.realm_id=$1),\
        'approval_audit',(SELECT COALESCE(jsonb_agg(to_jsonb(a) ORDER BY a.approval_context,a.approver_did,a.nonce),'[]'::jsonb) FROM event_approval_private_audit a WHERE a.realm_id=$1)) AS value")
        .bind::<Text,_>(realm.as_str()).get_result::<JsonRow>(&mut *conn).await.unwrap().value
}

async fn assert_old_archive_refused(pool: &PgPool, frozen: &FrozenOrg) {
    let before = public_originals(pool, &frozen.manifest.realm_id).await;
    assert_eq!(private_key_count(pool, &frozen.holder).await, 0);
    let error = PgAuthorityCommitStore { pool: pool.clone() }
        .import_pcr_private_state(&frozen.manifest, &frozen.bytes)
        .await
        .unwrap_err();
    assert_eq!(error.conflict_code(), Some(ConflictCode::AccountErased));
    assert_eq!(private_key_count(pool, &frozen.holder).await, 0);
    let account = PgPersistenceStore::new(pool.clone())
        .accounts()
        .get(&frozen.holder)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(account.display_name.as_deref(), Some("[user erased]"));
    assert!(account.biography.is_none());
    assert!(account.avatar_blob_ref.is_none());
    assert_eq!(
        public_originals(pool, &frozen.manifest.realm_id).await,
        before
    );
}

#[tokio::test]
async fn lawful_frozen_org_archive_imports_then_real_erasure_prevents_old_private_recreation() {
    heap_future(case_existing_owner).await;
}
async fn case_existing_owner() {
    let frozen = heap_future(frozen_org).await;
    let target = TestDatabase::lease().await;
    let pool = target.pool();
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    store
        .import_pcr_private_state(&frozen.manifest, &frozen.bytes)
        .await
        .unwrap();
    let (manifest, bytes) = store
        .export_pcr_private_state(&frozen.holder)
        .await
        .unwrap();
    assert_eq!(manifest.state_digest, frozen.manifest.state_digest);
    assert_eq!(bytes, frozen.bytes);
    assert_eq!(private_key_count(&pool, &frozen.holder).await, 1);
    let public = public_originals(&pool, &frozen.manifest.realm_id).await;
    let active = status_pair(&frozen, None, AccountStatus::Active);
    accept_status(&pool, &active).await;
    let erased = status_pair(&frozen, Some(&active.0), AccountStatus::ErasurePending);
    accept_status(&pool, &erased).await;
    let pending = pending(&frozen, &erased.0);
    heap_future(|| complete(&pool, &frozen, &pending)).await;
    assert_eq!(
        public_originals(&pool, &frozen.manifest.realm_id).await,
        public
    );
    assert_old_archive_refused(&pool, &frozen).await;
}

#[tokio::test]
async fn real_terminal_projection_on_a_missing_org_account_refuses_first_old_archive_import() {
    heap_future(case_missing_owner).await;
}
async fn case_missing_owner() {
    let frozen = heap_future(frozen_org).await;
    let target = TestDatabase::lease().await;
    let pool = target.pool();
    assert!(
        PgPersistenceStore::new(pool.clone())
            .accounts()
            .get(&frozen.holder)
            .await
            .unwrap()
            .is_none()
    );
    let active = status_pair(&frozen, None, AccountStatus::Active);
    accept_status(&pool, &active).await;
    assert!(
        PgPersistenceStore::new(pool.clone())
            .accounts()
            .get(&frozen.holder)
            .await
            .unwrap()
            .is_none()
    );
    let erased = status_pair(&frozen, Some(&active.0), AccountStatus::ErasurePending);
    accept_status(&pool, &erased).await;
    let pending = pending(&frozen, &erased.0);
    heap_future(|| complete(&pool, &frozen, &pending)).await;
    assert_eq!(
        public_originals(&pool, &frozen.manifest.realm_id).await,
        serde_json::json!({"events":[],"genesis_sources":[],"approval_audit":[]})
    );
    assert_old_archive_refused(&pool, &frozen).await;
}

async fn blocked_pid(pool: &PgPool, blocker: i64, query: &str) -> Option<i64> {
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            let mut conn = pool.get().await.unwrap();
            let row = diesel::sql_query("SELECT a.pid::bigint AS value FROM pg_stat_activity a WHERE a.datname=current_database() AND $1::integer=ANY(pg_blocking_pids(a.pid)) AND a.query LIKE $2 LIMIT 1")
                .bind::<BigInt,_>(blocker).bind::<Text,_>(query).get_result::<Count>(&mut *conn).await.optional().unwrap();
            if let Some(row) = row { break row.value; }
            tokio::task::yield_now().await;
        }
    }).await.ok()
}

#[tokio::test]
async fn actual_org_import_tuple_share_drains_before_real_terminal_acceptance_and_purge() {
    heap_future(case_import_first).await;
}
async fn case_import_first() {
    let frozen = heap_future(frozen_org).await;
    let target = TestDatabase::lease().await;
    let pool = target.pool();
    let active = status_pair(&frozen, None, AccountStatus::Active);
    accept_status(&pool, &active).await;
    let terminal = status_pair(&frozen, Some(&active.0), AccountStatus::ErasurePending);
    let pending = pending(&frozen, &terminal.0);
    // Hold the original production import advisory only as a scheduling
    // barrier. The actual importer must first acquire its tuple SHARE.
    let mut control = pool.get().await.unwrap();
    diesel::sql_query("BEGIN")
        .execute(&mut *control)
        .await
        .unwrap();
    diesel::sql_query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
        .bind::<Text, _>(format!("pcr-native-import:{}", frozen.manifest.realm_id))
        .execute(&mut *control)
        .await
        .unwrap();
    let control_pid = diesel::sql_query("SELECT pg_backend_pid()::bigint AS value")
        .get_result::<Count>(&mut *control)
        .await
        .unwrap()
        .value;
    let (import_pool, manifest, bytes) =
        (pool.clone(), frozen.manifest.clone(), frozen.bytes.clone());
    let mut importer = tokio::spawn(async move {
        PgAuthorityCommitStore { pool: import_pool }
            .import_pcr_private_state(&manifest, &bytes)
            .await
    });
    let mut eraser = None;
    let phase = std::panic::AssertUnwindSafe(async {
        let import_pid = blocked_pid(&pool, control_pid, "%hashtextextended%").await;
        let erase_pool = pool.clone();
        eraser = Some(tokio::spawn(async move {
            PgPersistenceStore::new(erase_pool)
                .account_status_replicas()
                .append(&terminal.0, &terminal.1)
                .await
        }));
        let erased_pid = match import_pid {
            Some(pid) => blocked_pid(&pool, pid, "%account_private_tuple_key%").await,
            None => None,
        };
        let waiting = !eraser.as_ref().unwrap().is_finished();
        let no_intent = execution(&pool, &pending, AccountErasureExecutionState::Pending)
            .await
            .is_none();
        let no_completed = execution(&pool, &pending, AccountErasureExecutionState::Completed)
            .await
            .is_none();
        (import_pid, erased_pid, waiting, no_intent, no_completed)
    })
    .catch_unwind()
    .await;
    diesel::sql_query("ROLLBACK")
        .execute(&mut *control)
        .await
        .unwrap();
    drop(control);
    let imported = tokio::time::timeout(std::time::Duration::from_secs(10), &mut importer).await;
    if imported.is_err() {
        importer.abort();
    }
    let erased = match eraser.as_mut() {
        Some(eraser) => {
            let result =
                tokio::time::timeout(std::time::Duration::from_secs(10), &mut *eraser).await;
            if result.is_err() {
                eraser.abort();
            }
            Some(result)
        }
        None => None,
    };
    let (import_pid, erased_pid, waiting, no_intent, no_completed) = match phase {
        Ok(value) => value,
        Err(panic) => std::panic::resume_unwind(panic),
    };
    assert!(
        import_pid.is_some() && erased_pid.is_some() && waiting && no_intent && no_completed,
        "actual PG blocker chain must precede terminal ACK-able intent"
    );
    imported.unwrap().unwrap().unwrap();
    assert!(matches!(
        erased.unwrap().unwrap().unwrap().unwrap(),
        AccountStatusReplicaAppend::Accepted(_)
    ));
    let public = public_originals(&pool, &frozen.manifest.realm_id).await;
    assert!(public["events"].as_array().unwrap().len() >= 2);
    assert_eq!(public["genesis_sources"].as_array().unwrap().len(), 1);
    assert!(!public["approval_audit"].as_array().unwrap().is_empty());
    heap_future(|| complete(&pool, &frozen, &pending)).await;
    assert_eq!(
        public_originals(&pool, &frozen.manifest.realm_id).await,
        public
    );
    assert_old_archive_refused(&pool, &frozen).await;
}
