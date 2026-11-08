//! Native own-PCR archive reads. Status observations are adapter inputs from
//! signed, verified and appended records; these are not HTTP resolve tests.

use std::sync::Arc;

use arkret_event_draft::EventPayloadExt as _;
use arkret_models_collaboration::account_status::{
    AccountStatusRecord, UnsignedAccountStatusReceipt, UnsignedAccountStatusRecord,
};
use arkret_models_collaboration::objects::account_status::AccountStatus;
use arkret_signatures::account_status::{
    sign_account_status_receipt, sign_account_status_record, verify_account_status_receipt,
    verify_account_status_record,
};
use arkret_wire::{CommittedEventView, EventKind, StreamScanDirection, StreamScanRequestBody};
use coland_storage::{
    AccountStatusCurrentObservation, AuthorityCommitStore as _, DeliveryPolicyStoreRegistry as _,
    HumanPcrHistoryRead, HumanPcrHistoryReader, SyncStoreRegistry as _,
};
use coland_storage_postgres::{PgAuthorityCommitStore, PgPersistenceStore, PgPool, TestDatabase};
use diesel::sql_types::{Binary, Text};
use horme::RunQueryDsl as _;
use serde_json::json;

use super::key_backup_tests::RootFixture;

async fn fixture() -> (TestDatabase, RootFixture) {
    let database = TestDatabase::lease().await;
    database.bind_device_inventory_station("ak:did_core:web:backup-test.example");
    let fixture = Box::pin(RootFixture::new(database.pool())).await;
    (database, fixture)
}

fn request(fixture: &RootFixture, after: Option<u64>) -> StreamScanRequestBody {
    let realm = fixture.pcr.history.events[0].realm_id.clone();
    StreamScanRequestBody {
        realm_id: realm.clone(),
        stream_ref: arkret_wire::CommitStreamRef::Realm { realm_id: realm },
        direction: StreamScanDirection::After(after),
        limit: 256,
    }
}

async fn status(
    pool: &PgPool,
    fixture: &RootFixture,
    previous: Option<&AccountStatusRecord>,
) -> AccountStatusRecord {
    let account = &fixture.pcr.history.account;
    let key = ed25519_dalek::SigningKey::from_bytes(&[94; 32]);
    let method = arkret_wire::DidUrl::new("did:web:backup-test.example#status").unwrap();
    let at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    let record = sign_account_status_record(
        UnsignedAccountStatusRecord {
            schema: arkret_wire::SchemaId::ACCOUNT_STATUS_RECORD_V1.to_owned(),
            account_authority_id: account.station_id.clone(),
            account_id: account.clone(),
            principal_control_realm_id: fixture.pcr.history.events[0].realm_id.clone(),
            binding_version: 1,
            status_sequence: previous.map_or(1, |old| old.status_sequence + 1),
            previous_account_status_record_id: previous
                .map(|old| old.account_status_record_id.clone()),
            status: if previous.is_some() {
                AccountStatus::Deactivated
            } else {
                AccountStatus::Active
            },
            reason_code: None,
            reason: None,
            issued_at: at,
            expires_at: None,
        },
        method.clone(),
        &key,
    )
    .unwrap();
    let receipt = sign_account_status_receipt(
        UnsignedAccountStatusReceipt {
            receipt_id: arkret_wire::ReceiptId::new(format!("ak:receipt:{}", uuid::Uuid::now_v7()))
                .unwrap(),
            account_status_record_id: record.account_status_record_id.clone(),
            record_digest: record.payload_digest().unwrap(),
            account_authority_id: account.station_id.clone(),
            account_id: account.clone(),
            status_sequence: record.status_sequence,
            receiver_id: account.station_id.clone(),
            accepted_at: at,
            verification_method: method,
        },
        &key,
    )
    .unwrap();
    let public = arkret_signatures::PublicKeyMaterial::Ed25519Raw {
        bytes: key.verifying_key().to_bytes().to_vec(),
    };
    verify_account_status_record(&record, &public).unwrap();
    verify_account_status_receipt(&receipt, &public).unwrap();
    PgPersistenceStore::new(pool.clone())
        .account_status_replicas()
        .append(&record, &receipt)
        .await
        .unwrap();
    record
}

fn reader(fixture: &RootFixture, status: Option<AccountStatusRecord>) -> HumanPcrHistoryReader {
    HumanPcrHistoryReader {
        account_id: fixture.pcr.history.account.clone(),
        device_id: fixture.pcr.history.founding_device_id.clone(),
        credential_device_binding: Some(
            arkret_models_identity::session_credential::SessionGrantDeviceBinding {
                device_id: fixture.pcr.history.founding_device_id.clone(),
                authorization_event_id: fixture.pcr.history.events[1].event_id.clone(),
                model_generation_ref: fixture.pcr.history.events[1]
                    .as_device_authorize()
                    .unwrap()
                    .authorized_generation_ref,
            },
        ),
        credential_expires_at: chrono::Utc::now() + chrono::Duration::minutes(5),
        account_status_observation: status
            .map(AccountStatusCurrentObservation::after_authenticated_resolve),
    }
}

async fn add_public_profile_history(pool: &PgPool, fixture: &RootFixture) -> arkret_wire::EventId {
    let persistence = Arc::new(PgPersistenceStore::new(pool.clone()));
    let app = crate::authority_commit::AuthorityCommitApplication::new(
        crate::persistence::PersistenceHandle::new(persistence.clone()),
        64,
    );
    let mut create = None;
    let mut last = None;
    let mut previous: Option<arkret_wire::RealmCommit> = None;
    for index in 0..260 {
        let (kind, payload) = if index == 0 {
            (
                EventKind::ProfileCreate,
                json!({"object":{
                    "principal_id":fixture.pcr.history.account.principal_id,
                    "actor_kind":"user","display_name":"Archive control profile"
                }}),
            )
        } else {
            (
                EventKind::ProfileUpdate,
                json!({"target_ref":create,
                "patch":{"display_name":format!("Archive control profile {index}")},
                "expected_revision":{
                    "commit_id":previous.as_ref().unwrap().commit_id,
                    "stream_position":previous.as_ref().unwrap().stream_position
                }}),
            )
        };
        let event = fixture.pcr.history.event(kind, payload);
        let at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
        let transaction = app
            .prepare_self_event_transaction(
                &event,
                &fixture.pcr.history.account.station_id,
                fixture.pcr.history.authority_method(),
                &ed25519_dalek::SigningKey::from_bytes(&[83; 32]),
                at,
            )
            .await
            .unwrap();
        previous = Some(transaction.commit.clone());
        persistence
            .actor_profiles()
            .admit_profile(coland_storage::ActorProfileAdmissionWrite {
                commit: transaction,
                queued_at: at,
            })
            .await
            .unwrap();
        if index == 0 {
            create = Some(arkret_wire::ActorProfileId::from_event_id(&event.event_id));
        }
        last = Some(event.event_id);
    }
    last.unwrap()
}

#[tokio::test]
async fn own_pcr_archive_pages_all_native_originals_without_mls_or_membership() {
    let (database, fixture) = Box::pin(fixture()).await;
    let pool = database.pool();
    let last = Box::pin(add_public_profile_history(&pool, &fixture)).await;
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    let initial = reader(&fixture, None);
    assert!(matches!(
        store
            .read_human_pcr_history_page(
                &initial,
                &request(&fixture, None),
                &initial.account_id.station_id
            )
            .await
            .unwrap(),
        HumanPcrHistoryRead::CurrentStatusRequired
    ));
    let current = reader(&fixture, Some(status(&pool, &fixture, None).await));
    let mut after = None;
    let mut originals = Vec::new();
    loop {
        let HumanPcrHistoryRead::Ready { value, guard } = store
            .read_human_pcr_history_page(
                &current,
                &request(&fixture, after),
                &current.account_id.station_id,
            )
            .await
            .unwrap()
        else {
            panic!("current own Human device must read its PCR");
        };
        assert!(guard.permits_handoff());
        assert_eq!(value.readable_floor.as_ref().unwrap().oldest_position, 0);
        let truncated = value.truncated;
        for row in value.committed_events {
            let CommittedEventView::Full(full) = row else {
                panic!("PCR originals cannot be withheld");
            };
            assert_eq!(full.commit.stream_position, originals.len() as u64);
            after = Some(full.commit.stream_position);
            originals.push(full);
        }
        guard.finish().await.unwrap();
        if !truncated {
            break;
        }
    }
    assert_eq!(originals.len(), 263);
    assert_eq!(
        originals.first().unwrap().event,
        fixture.pcr.history.events[0]
    );
    assert_eq!(originals.last().unwrap().event.event_id, last);
    let HumanPcrHistoryRead::Ready { value, guard } = store
        .read_human_pcr_history_event(&current, &last, &current.account_id.station_id)
        .await
        .unwrap()
    else {
        panic!("exact original must remain readable");
    };
    assert_eq!(value, CommittedEventView::Full(originals.pop().unwrap()));
    guard.finish().await.unwrap();
    #[derive(diesel::QueryableByName)]
    struct Counts {
        #[diesel(sql_type=diesel::sql_types::BigInt)]
        count: i64,
    }
    let mut conn = pool.get().await.unwrap();
    let counts=diesel::sql_query("SELECT (SELECT count(*) FROM mls_group_current_states WHERE realm_id=$1)+(SELECT count(*) FROM member_state_current_states WHERE realm_id=$1) AS count")
        .bind::<Text,_>(fixture.pcr.history.events[0].realm_id.as_str()).get_result::<Counts>(&mut *conn).await.unwrap();
    assert_eq!(counts.count, 0);
}

#[tokio::test]
async fn own_pcr_archive_rechecks_device_credential_and_current_account_status() {
    let (database, fixture) = Box::pin(fixture()).await;
    let pool = database.pool();
    let active = status(&pool, &fixture, None).await;
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    let current = reader(&fixture, Some(active.clone()));
    for case in [
        "device",
        "expiry",
        "station",
        "generation",
        "authorization",
        "missing_binding",
    ] {
        let mut changed = current.clone();
        let mut station = current.account_id.station_id.clone();
        match case {
            "device" => {
                changed.device_id =
                    arkret_wire::DeviceId::new(format!("ak:device:{}", uuid::Uuid::now_v7()))
                        .unwrap()
            }
            "expiry" => {
                changed.credential_expires_at = chrono::Utc::now() - chrono::Duration::seconds(1)
            }
            "station" => {
                station = arkret_wire::DidCoreId::new("ak:did_core:web:foreign.example").unwrap()
            }
            "generation" => {
                changed
                    .credential_device_binding
                    .as_mut()
                    .unwrap()
                    .model_generation_ref = 0
            }
            "authorization" => {
                changed
                    .credential_device_binding
                    .as_mut()
                    .unwrap()
                    .authorization_event_id = fixture.pcr.history.events[0].event_id.clone()
            }
            "missing_binding" => changed.credential_device_binding = None,
            _ => unreachable!(),
        }
        assert!(
            store
                .read_human_pcr_history_page(&changed, &request(&fixture, None), &station)
                .await
                .is_err(),
            "{case}"
        );
    }
    let terminal = status(&pool, &fixture, Some(&active)).await;
    let error = store
        .read_human_pcr_history_page(
            &current,
            &request(&fixture, None),
            &current.account_id.station_id,
        )
        .await
        .err()
        .expect("old status observation cannot authorize");
    assert!(
        error
            .to_string()
            .contains("head changed after current resolve"),
        "{error}"
    );
    let terminal_reader = reader(&fixture, Some(terminal));
    let error = store
        .read_human_pcr_history_page(
            &terminal_reader,
            &request(&fixture, None),
            &current.account_id.station_id,
        )
        .await
        .err()
        .expect("terminal account cannot read");
    assert!(error.to_string().contains("not active or bound"), "{error}");
}

#[tokio::test]
async fn own_pcr_archive_refuses_missing_original_instead_of_returning_a_partial_prefix() {
    let (database, fixture) = Box::pin(fixture()).await;
    let pool = database.pool();
    let current = reader(&fixture, Some(status(&pool, &fixture, None).await));
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query(
        "UPDATE realm_commits SET event_pk=NULL WHERE realm_id=$1 AND stream_position=2",
    )
    .bind::<Text, _>(fixture.pcr.history.events[0].realm_id.as_str())
    .execute(&mut *conn)
    .await
    .unwrap();
    drop(conn);
    let error = PgAuthorityCommitStore { pool }
        .read_human_pcr_history_page(
            &current,
            &request(&fixture, None),
            &current.account_id.station_id,
        )
        .await
        .err()
        .expect("missing PCR original must fail");
    assert!(
        error.to_string().contains("original prefix is unavailable"),
        "{error}"
    );
}

#[tokio::test]
async fn own_pcr_archive_does_not_trust_actor_fields_without_the_accepted_creation_unit() {
    let (database, fixture) = Box::pin(fixture()).await;
    let pool = database.pool();
    let current = reader(&fixture, Some(status(&pool, &fixture, None).await));
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query("UPDATE pcr_genesis_units SET exact_request_body=$2 WHERE realm_id=$1")
        .bind::<Text, _>(fixture.pcr.history.events[0].realm_id.as_str())
        .bind::<Binary, _>(b"[]".as_slice())
        .execute(&mut *conn)
        .await
        .unwrap();
    drop(conn);
    assert!(
        PgAuthorityCommitStore { pool }
            .read_human_pcr_history_page(
                &current,
                &request(&fixture, None),
                &current.account_id.station_id,
            )
            .await
            .is_err()
    );
}

#[tokio::test]
async fn missing_pcr_inception_never_reopens_ordinary_author_read_fallback() {
    let (database, fixture) = Box::pin(fixture()).await;
    let pool = database.pool();
    let current = reader(&fixture, Some(status(&pool, &fixture, None).await));
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query(
        "UPDATE realm_commits SET event_pk=NULL WHERE realm_id=$1 AND stream_position=0",
    )
    .bind::<Text, _>(fixture.pcr.history.events[0].realm_id.as_str())
    .execute(&mut *conn)
    .await
    .unwrap();
    drop(conn);
    let store = PgAuthorityCommitStore { pool };
    assert!(
        store
            .read_human_pcr_history_page(
                &current,
                &request(&fixture, None),
                &current.account_id.station_id,
            )
            .await
            .is_err()
    );
    assert!(
        store
            .read_human_pcr_history_event(
                &current,
                &fixture.pcr.history.events[1].event_id,
                &current.account_id.station_id,
            )
            .await
            .is_err()
    );
}
