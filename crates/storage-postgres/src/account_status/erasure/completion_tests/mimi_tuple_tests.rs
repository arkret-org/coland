//! Actual foreign signed status/receipt adapter against the optional private
//! annotation tuple gate. The source's Human PCR is accepted in its own DB;
//! the receiver never imports it. This is not HTTP or AA browser coverage.

use coland_storage::MimiConsentCorrelationStore as _;
use rand_chacha::rand_core::SeedableRng as _;

use super::*;

async fn source_fixture() -> OriginFixture {
    use arkret_models_identity::service_identity::{CanonicalServiceUrl, ServiceRegistrationKey};
    let registration = ServiceRegistrationKey::new(
        arkret_wire::ServiceKind::Station,
        CanonicalServiceUrl::new("https://mimi-foreign-source.example/").unwrap(),
    )
    .unwrap();
    let inception = arkret_signatures::webvh::prepare_service_registration_inception(
        &mut rand_chacha::ChaCha20Rng::from_seed([179; 32]),
        &arkret_signatures::webvh::ServiceRegistrationInceptionInput {
            provider_endpoint: &"https://mimi-source-identity.example/".parse().unwrap(),
            registration_key: &registration,
            also_known_as: &[],
            version_created_at: "2026-09-01T00:00:00Z".parse().unwrap(),
            did_key_fragment: None,
        },
    )
    .unwrap();
    Box::pin(OriginFixture::with_service_inception(inception)).await
}

async fn actual_blocked_pid(pool: &crate::PgPool, blocker: i64, query: &str) -> Option<i64> {
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            let mut conn = pool.get().await.unwrap();
            let blocked = sql_query("SELECT a.pid::bigint AS value FROM pg_stat_activity a WHERE a.datname=current_database() AND $1::integer=ANY(pg_blocking_pids(a.pid)) AND a.query LIKE $2 LIMIT 1")
                .bind::<BigInt,_>(blocker).bind::<Text,_>(query).get_result::<Count>(&mut *conn).await.optional().unwrap();
            if let Some(row) = blocked { break row.value; }
            tokio::task::yield_now().await;
        }
    }).await.ok()
}

#[tokio::test]
async fn absent_foreign_requester_annotation_and_real_terminal_append_share_one_full_account_cut() {
    let receiver = Box::pin(OriginFixture::new()).await;
    let source = Box::pin(source_fixture()).await;
    let options = coland_test_support::device_authorization_history::DeviceHistoryFixtureOptions {
        local_id: format!("mimi-tuple-{}", uuid::Uuid::now_v7().simple()),
        founding_device_id: arkret_wire::DeviceId::new(format!(
            "ak:device:{}",
            uuid::Uuid::now_v7()
        ))
        .unwrap(),
        ..Default::default()
    };
    let foreign_pcr = coland_test_support::pcr_genesis::PcrGenesisFixture::new_with(
        source.station_did.clone(),
        options.clone(),
    );
    let local_pcr = coland_test_support::pcr_genesis::PcrGenesisFixture::new_with(
        receiver.station_did.clone(),
        options,
    );
    Box::pin(foreign_pcr.admit_into(&crate::PgPersistenceStore::new(source.pool.clone())))
        .await
        .unwrap();
    Box::pin(local_pcr.admit_into(&crate::PgPersistenceStore::new(receiver.pool.clone())))
        .await
        .unwrap();
    let foreign = foreign_pcr.history.account.clone();
    let local = local_pcr.history.account.clone();
    assert_eq!(
        foreign.principal_id, local.principal_id,
        "same Principal, genuinely different Station accounts"
    );
    assert_ne!(foreign.station_id, local.station_id);
    let persistence = crate::PgPersistenceStore::new(receiver.pool.clone());
    persistence
        .accounts()
        .put(&AccountRecord {
            pk: AccountPk(0),
            principal_id: local.principal_id.clone(),
            station_id: local.station_id.clone(),
            localpart: String::new(),
            display_name: None,
            biography: None,
            avatar_blob_ref: None,
            created_at: chrono::Utc::now(),
        })
        .await
        .unwrap();
    assert!(
        persistence
            .accounts()
            .get(&foreign)
            .await
            .unwrap()
            .is_none()
    );
    assert!(persistence.accounts().get(&local).await.unwrap().is_some());
    let surviving = AccountDataRecord {
        actor: ActorId::account(local.clone()).to_string(),
        account_data_key: "ak.mimi-tuple-survivor".into(),
        payload: serde_json::json!({"private":"other full Station Account"}),
        revision: 1,
        tombstone: false,
        updated_at: chrono::Utc::now(),
    };
    assert!(matches!(
        persistence
            .account_data()
            .compare_and_set(&surviving, 0)
            .await
            .unwrap(),
        coland_storage::AccountDataCasResult::Applied(_)
    ));
    let status = PgAccountStatusReplicaStore {
        pool: receiver.pool.clone(),
    };
    let pcr = &foreign_pcr.history.events[0].realm_id;
    let active = signed_status(&source, &foreign, None, AccountStatus::Active, pcr);
    append(&status, &receiver, &active, &receiver.station).await;
    assert!(
        persistence
            .accounts()
            .get(&foreign)
            .await
            .unwrap()
            .is_none(),
        "Active evidence must not synthesize missing local login state"
    );
    let terminal = signed_status(
        &source,
        &foreign,
        Some(&active),
        AccountStatus::ErasurePending,
        pcr,
    );
    let receipt = signed_receipt(&receiver, &terminal, &receiver.station);
    let pending = AccountErasureExecution {
        receiver_id: receiver.station.clone(),
        account_authority_id: source.station.clone(),
        account_id: foreign.clone(),
        principal_id: foreign.principal_id.clone(),
        triggering_status_record_id: terminal.account_status_record_id.clone(),
        storage_boundary: ErasureStorageBoundary::AccountPrivateStore,
        state: AccountErasureExecutionState::Pending,
        package: None,
    };
    let correlation = coland_storage::MimiConsentCorrelationRecord {
        consent_id: format!("ak:consent:{}", uuid::Uuid::now_v7()),
        requester_actor_id: arkret_canonical::canonical_json_string(&ActorId::account(
            foreign.clone(),
        ))
        .unwrap(),
        holder_account_id: arkret_canonical::canonical_json_string(&local).unwrap(),
        purpose: "mimi-private-correlation".into(),
        strand_id: None,
        source_id: Some(source.station.to_string()),
        source_class: coland_storage::MimiConsentSourceClass::Service,
        created_at: arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now()),
        expires_at: None,
    };
    // This fault-free scheduling barrier stops the real INSERT only after
    // its production tuple SHARE gate and missing-row test have executed.
    let control_key =
        i64::from_be_bytes(uuid::Uuid::now_v7().as_bytes()[8..16].try_into().unwrap());
    let mut control = receiver.pool.get().await.unwrap();
    sql_query("BEGIN").execute(&mut *control).await.unwrap();
    sql_query("SELECT pg_advisory_xact_lock($1)")
        .bind::<BigInt, _>(control_key)
        .execute(&mut *control)
        .await
        .unwrap();
    let control_pid = sql_query("SELECT pg_backend_pid()::bigint AS value")
        .get_result::<Count>(&mut *control)
        .await
        .unwrap()
        .value;
    let mut writer = None;
    let mut eraser = None;
    let phase = std::panic::AssertUnwindSafe(async {
        let consent_literal = correlation.consent_id.replace('\'', "''");
        let mut setup = receiver.pool.get().await.unwrap();
        sql_query(format!("CREATE FUNCTION mimi_annotation_owned_barrier() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.consent_id='{consent_literal}' THEN PERFORM pg_advisory_xact_lock({control_key}::bigint); END IF; RETURN NEW; END; $$"))
            .execute(&mut *setup).await.unwrap();
        sql_query("CREATE TRIGGER mimi_annotation_owned_barrier BEFORE INSERT ON mimi_consent_correlations FOR EACH ROW EXECUTE FUNCTION mimi_annotation_owned_barrier()")
            .execute(&mut *setup).await.unwrap();
        drop(setup);
        let copy = correlation.clone();
        let pool = receiver.pool.clone();
        writer = Some(tokio::spawn(async move { crate::PgMimiConsentCorrelationStore { pool }.put(&copy).await }));
        let writer_pid = actual_blocked_pid(&receiver.pool, control_pid, "%INSERT INTO mimi_consent_correlations%").await;
        let pool = receiver.pool.clone();
        eraser = Some(tokio::spawn(async move { PgAccountStatusReplicaStore { pool }.append(&terminal, &receipt).await }));
        let terminal_pid = match writer_pid {
            Some(pid) => actual_blocked_pid(&receiver.pool, pid, "%account_private_tuple_key%").await,
            None => None,
        };
        let pending_not_committed = {
            let mut conn = receiver.pool.get().await.unwrap();
            execution_row(&mut conn, &pending, AccountErasureExecutionState::Pending).await.unwrap().is_none()
        };
        let was_waiting = !eraser.as_ref().unwrap().is_finished();
        (writer_pid, terminal_pid, pending_not_committed, was_waiting)
    }).catch_unwind().await;
    sql_query("ROLLBACK").execute(&mut *control).await.unwrap();
    drop(control);
    let writer_outcome = match writer.as_mut() {
        Some(writer) => {
            let outcome =
                tokio::time::timeout(std::time::Duration::from_secs(10), &mut *writer).await;
            if outcome.is_err() {
                writer.abort();
            }
            Some(outcome)
        }
        None => None,
    };
    let eraser_outcome = match eraser.as_mut() {
        Some(eraser) => {
            let outcome =
                tokio::time::timeout(std::time::Duration::from_secs(10), &mut *eraser).await;
            if outcome.is_err() {
                eraser.abort();
            }
            Some(outcome)
        }
        None => None,
    };
    let mut conn = receiver.pool.get().await.unwrap();
    sql_query("DROP TRIGGER IF EXISTS mimi_annotation_owned_barrier ON mimi_consent_correlations")
        .execute(&mut *conn)
        .await
        .unwrap();
    sql_query("DROP FUNCTION IF EXISTS mimi_annotation_owned_barrier()")
        .execute(&mut *conn)
        .await
        .unwrap();
    drop(conn);
    let (writer_pid, terminal_pid, pending_not_committed, was_waiting) = match phase {
        Ok(observed) => observed,
        Err(panic) => std::panic::resume_unwind(panic),
    };
    assert!(
        writer_pid.is_some(),
        "the real annotation INSERT did not wait on the test-owned blocker"
    );
    assert!(
        terminal_pid.is_some(),
        "the real terminal append did not wait on the annotation's exact tuple SHARE"
    );
    assert!(
        was_waiting && pending_not_committed,
        "no ACK-able erasure intent may precede writer drain"
    );
    writer_outcome.unwrap().unwrap().unwrap().unwrap();
    assert!(matches!(
        eraser_outcome.unwrap().unwrap().unwrap().unwrap(),
        AccountStatusReplicaAppend::Accepted(_)
    ));
    let annotations = crate::PgMimiConsentCorrelationStore {
        pool: receiver.pool.clone(),
    };
    assert_eq!(
        annotations.get(&correlation.consent_id).await.unwrap(),
        Some(correlation.clone())
    );
    let mut conn = receiver.pool.get().await.unwrap();
    assert!(
        execution_row(&mut conn, &pending, AccountErasureExecutionState::Pending)
            .await
            .unwrap()
            .is_some()
    );
    let imported = sql_query("SELECT EXISTS(SELECT 1 FROM principal_resolutions WHERE principal_id=$1 AND station_id=$2) AS value")
        .bind::<Text,_>(foreign.principal_id.as_str()).bind::<Text,_>(foreign.station_id.as_str()).get_result::<Present>(&mut *conn).await.unwrap();
    assert!(!imported.value);
    drop(conn);
    let sign = |at| completion(&pending, &receiver, at);
    let completed = complete(&receiver.pool, &pending, &sign).await.unwrap();
    assert!(
        annotations
            .get(&correlation.consent_id)
            .await
            .unwrap()
            .is_none()
    );
    let mut after = correlation;
    after.consent_id = format!("ak:consent:{}", uuid::Uuid::now_v7());
    let refused = annotations.put(&after).await.unwrap_err();
    assert_eq!(
        refused.conflict_code(),
        Some(coland_storage::ConflictCode::AccountErased)
    );
    assert!(annotations.get(&after.consent_id).await.unwrap().is_none());
    assert_eq!(
        persistence
            .account_data()
            .get(&surviving.actor, &surviving.account_data_key)
            .await
            .unwrap()
            .unwrap()
            .payload,
        surviving.payload
    );
    let cold = PgAccountStatusReplicaStore {
        pool: receiver.pool.clone(),
    };
    let never_sign = |_| -> PersistenceResult<ErasureReceiptPackage> {
        panic!("the durable original completion must replay")
    };
    let replay = cold.complete_erasure(&pending, &never_sign).await.unwrap();
    assert_eq!(
        arkret_canonical::canonical_json_bytes(&completed).unwrap(),
        arkret_canonical::canonical_json_bytes(&replay).unwrap()
    );
}
