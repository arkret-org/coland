//! Real signed native history and an accepted PCR, including transaction faults.
use coland_storage::{EventStore, PrincipalResolutionStore, WebvhStore};

use super::*;

#[tokio::test]
async fn signed_resolution_cas_is_atomic_and_survives_cache_eviction_and_reopen() {
    let database = coland_storage_postgres::test_database::TestDatabase::lease().await;
    let pool = database.pool();
    let station = contract_station(&pool).await;
    let local = format!("resolution-{}", uuid::Uuid::now_v7().simple());
    let make = || {
        DeviceHistoryFixture::new_with(
            device_history_fixture::did_web_station(&station),
            DeviceHistoryFixtureOptions {
                local_id: local.clone(),
                ..Default::default()
            },
        )
    };
    let history = make();
    let unit = assemble(station.clone(), make());
    PgAuthorityCommitStore { pool: pool.clone() }
        .admit_pcr_genesis_unit(&unit, unit.transactions[0].commit.committed_at)
        .await
        .unwrap();
    let account = history.account.clone();
    let resolutions = coland_storage_postgres::PgPrincipalResolutionStore { pool: pool.clone() };
    let initial = resolutions.by_account_id(&account).await.unwrap().unwrap();
    let inception = serde_json::to_value(&history.inception.operation).unwrap();
    let mut entries = vec![inception.clone()];
    let time = chrono::DateTime::parse_from_rfc3339(inception["versionTime"].as_str().unwrap())
        .unwrap()
        .with_timezone(&chrono::Utc);
    let next_key = arkret_canonical::ed25519_pubkey_to_did_key_multibase(
        SigningKey::from_bytes(&[72; 32]).verifying_key().as_bytes(),
    );
    let enabled = arkret_signatures::webvh::prepare_principal_portability_update(
        &arkret_signatures::webvh::PrincipalRotationInput {
            did: history.did.as_str(),
            local_id: &local,
            previous_entries: &entries,
            version_time: time + chrono::TimeDelta::seconds(1),
            current_root_seed: &[71; 32],
            next_root_public_key_multibase: &next_key,
            state: &inception["state"],
        },
        true,
    )
    .unwrap();
    entries.push(enabled.log_entry);
    let target = format!(
        "did:webvh:{}:new-resolution.example:webvh:{}",
        history.did.as_str().split(':').nth(2).unwrap(),
        local
    );
    let mut state = entries.last().unwrap()["state"].clone();
    // Every identity-rooted verification method must move with the native DID.
    fn move_did(v: &mut serde_json::Value, old: &str, new: &str) {
        match v {
            serde_json::Value::String(s) => *s = s.replace(old, new),
            serde_json::Value::Array(a) => a.iter_mut().for_each(|v| move_did(v, old, new)),
            serde_json::Value::Object(o) => o.values_mut().for_each(|v| move_did(v, old, new)),
            _ => {}
        }
    }
    move_did(&mut state, history.did.as_str(), &target);
    state["alsoKnownAs"] = serde_json::json!([history.did]);
    let next_key = arkret_canonical::ed25519_pubkey_to_did_key_multibase(
        SigningKey::from_bytes(&[73; 32]).verifying_key().as_bytes(),
    );
    let moved = arkret_signatures::webvh::prepare_webvh_relocation(
        &arkret_signatures::webvh::WebvhRelocationInput {
            current_did: history.did.as_str(),
            target_did: &target,
            previous_entries: &entries,
            version_time: time + chrono::TimeDelta::seconds(2),
            current_update_seed: &[72; 32],
            next_update_public_key_multibase: &next_key,
            state: &state,
        },
    )
    .unwrap();
    entries.push(moved.log_entry);
    let webvh = coland_storage_postgres::PgWebvhStore { pool: pool.clone() };
    for (index, entry) in entries.iter().enumerate() {
        webvh
            .append_log_event(coland_storage::WebvhLogRecord {
                event_digest: arkret_canonical::canonical_sha256(entry).unwrap(),
                did: entry["state"]["id"].as_str().unwrap().into(),
                seq: index as u64 + 1,
                operation: entry.clone(),
                created_at: time + chrono::TimeDelta::seconds(index as i64),
            })
            .await
            .unwrap();
    }
    let payload = serde_json::json!({
        "expected_revision":{"commit_id":unit.transactions[0].commit.commit_id,"stream_position":0},
        "next":{"did":target,"method_history_head":arkret_canonical::canonical_sha256(entries.last().unwrap()).unwrap(),"version_id":entries.last().unwrap()["versionId"]},
    });
    let prepare = |nonce: i64| {
        let mut fixture = make();
        let mut event = fixture.raw_event(
            EventKind::IdentityResolutionUpdate,
            payload.clone(),
            &initial.pcr_realm_id,
        );
        event.created_at += chrono::TimeDelta::milliseconds(nonce);
        let event = device_history_fixture::sign_event(
            event,
            fixture.device_verification_method.clone(),
            fixture.founding_device_signing_seed,
        );
        fixture.append(vec![event.clone()]);
        let mut commit = fixture.commits.last().unwrap().clone();
        commit.committed_at = chrono::Utc::now();
        let identity =
            arkret_canonical::canonical::unsigned_value(&commit, &["commit_id", "signature"])
                .unwrap();
        commit.commit_id = RealmCommitId::from_digest(arkret_canonical::sha256_bytes(
            arkret_canonical::canonical_json_bytes(&identity).unwrap(),
        ));
        commit.signature = arkret_signatures::detached_object::sign_detached_object(
            &arkret_canonical::canonical::unsigned_value(&commit, &["signature"]).unwrap(),
            DetachedSignatureContext::RealmCommit,
            fixture.authority_method(),
            commit.committed_at,
            &SigningKey::from_bytes(&device_history_fixture::STATION_AUTHORITY_SEED),
        )
        .unwrap();
        let mut transaction = unit.transactions[1].clone();
        transaction.event = event;
        transaction.commit = commit;
        coland_storage::PrincipalResolutionUpdateWrite {
            transaction,
            log_entries: entries.clone(),
            witness_records: vec![],
        }
    };
    let first = prepare(1);
    let second = prepare(2);
    let before = sql_fault_matrix::snapshot(&pool).await;
    let mut broken = first.clone();
    broken.log_entries.remove(0);
    let error = resolutions.admit_update(broken).await.unwrap_err();
    assert_eq!(
        error.conflict_code(),
        Some(ConflictCode::DidMethodSuccessorInvalid),
        "{error:?}"
    );
    assert_eq!(before, sql_fault_matrix::snapshot(&pool).await);
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query("CREATE OR REPLACE FUNCTION fail_resolution_current() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected resolution current failure'; END $$")
        .execute(&mut *conn).await.unwrap();
    diesel::sql_query("CREATE TRIGGER fail_resolution_current BEFORE UPDATE ON principal_resolution_current_results FOR EACH ROW EXECUTE FUNCTION fail_resolution_current()")
        .execute(&mut *conn).await.unwrap();
    drop(conn);
    assert!(resolutions.admit_update(first.clone()).await.is_err());
    assert_eq!(
        before,
        sql_fault_matrix::snapshot(&pool).await,
        "current failure rolls back Event, Commit and historical signer effects"
    );
    assert_eq!(
        resolutions.by_account_id(&account).await.unwrap().unwrap(),
        initial
    );
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query(
        "DROP TRIGGER fail_resolution_current ON principal_resolution_current_results",
    )
    .execute(&mut *conn)
    .await
    .unwrap();
    drop(conn);
    let (a, b) = tokio::join!(
        resolutions.admit_update(first.clone()),
        resolutions.admit_update(second.clone())
    );
    assert_eq!(
        usize::from(a.is_ok()) + usize::from(b.is_ok()),
        1,
        "one exact revision has one winner: {a:?}, {b:?}"
    );
    let winner = if a.is_ok() { &first } else { &second };
    let loser = if a.is_err() {
        a.unwrap_err()
    } else {
        b.unwrap_err()
    };
    assert_eq!(
        loser.conflict_code(),
        Some(ConflictCode::FailedPrecondition)
    );
    assert!(matches!(
        resolutions.admit_update(winner.clone()).await.unwrap(),
        arkret_wire::AuthoritySubmitOutcome::Accepted {
            status: arkret_wire::AuthorityCommitStatus::Duplicate,
            ..
        }
    ));
    let current = resolutions.by_account_id(&account).await.unwrap().unwrap();
    assert_eq!(current.account_id, account);
    assert_eq!(current.projection.did.as_str(), target);
    assert_eq!(current.current_event, winner.transaction.event);
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query("DELETE FROM principal_resolutions WHERE principal_id=$1 AND station_id=$2")
        .bind::<Text, _>(account.principal_id.as_str())
        .bind::<Text, _>(account.station_id.as_str())
        .execute(&mut *conn)
        .await
        .unwrap();
    drop(conn);
    assert_eq!(
        resolutions.by_account_id(&account).await.unwrap().unwrap(),
        current,
        "query-index eviction cannot replace typed current"
    );
    let reopened = Db::connect(Some(database.url()), Default::default())
        .await
        .unwrap()
        .pool
        .unwrap();
    let reopened = coland_storage_postgres::PgPrincipalResolutionStore { pool: reopened };
    assert_eq!(
        reopened.by_account_id(&account).await.unwrap().unwrap(),
        current
    );
    let events = reopened
        .history_newest_first(&account, None, 256)
        .await
        .unwrap();
    assert_eq!(
        events,
        vec![winner.transaction.event.clone(), initial.genesis_event]
    );
    let stranger = arkret_wire::AccountId::new(
        account.principal_id.clone(),
        DidCoreId::new("ak:did_core:web:another-account.example").unwrap(),
    );
    assert!(reopened.by_account_id(&stranger).await.unwrap().is_none());
    for candidate in [&first, &second] {
        let exists = coland_storage_postgres::PgEventStore { pool: pool.clone() }
            .get(candidate.transaction.event.event_id.as_str())
            .await
            .unwrap()
            .is_some();
        assert_eq!(
            exists,
            candidate.transaction.event.event_id == winner.transaction.event.event_id
        );
    }
}
