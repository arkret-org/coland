//! Real accepted W1 originals cross the existing private management inventory.
//! Ordinary prerequisite copying below is test setup, not operational migration.

use arkret_models_collaboration::authority_commit::ManagementPrivateHandoffManifest;
use arkret_wire::{ActorId, EventKind, Hash};
use coland_storage::EventCommitUnitOfWork as _;
use coland_storage_postgres::test_database::TestDatabase;
use coland_storage_postgres::{PgAuthorityCommitStore, PgEventCommitUnitOfWork, PgPool};
use diesel::sql_types::{Jsonb, Nullable, Text};
use diesel_async::RunQueryDsl as _;
use serde_json::{Value, json};

use super::{native_owner, ordinary_realm};

#[path = "../support/applet_authoring/management_archive_fixture.rs"]
#[expect(
    dead_code,
    reason = "This test uses only the ordinary prerequisite copy helper."
)]
mod management_archive_fixture;

#[derive(diesel::QueryableByName)]
struct WitnessRow {
    #[diesel(sql_type = Nullable<Jsonb>)]
    witness: Option<Value>,
}

async fn stored(pool: &PgPool, fixture: &native_owner::NativeOwnerTransfer) -> Option<Value> {
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query(
        "SELECT successor_device_evidence_json AS witness FROM canonical_events \
         WHERE envelope->>'event_id'=$1 AND realm_id=$2 AND state='committed'",
    )
    .bind::<Text, _>(fixture.event().event_id.as_str())
    .bind::<Text, _>(fixture.realm.as_str())
    .get_result::<WitnessRow>(&mut *conn)
    .await
    .unwrap()
    .witness
}

async fn reject_changed_inventory(
    target: &PgAuthorityCommitStore,
    manifest: &ManagementPrivateHandoffManifest,
    changed: Value,
) {
    let bytes = arkret_canonical::canonical_json_bytes(&changed).unwrap();
    let mut changed_manifest = manifest.clone();
    changed_manifest.state_digest = Hash::new(arkret_canonical::sha256_digest(&bytes)).unwrap();
    assert!(
        target
            .import_management_private_state(&changed_manifest, &bytes)
            .await
            .is_err(),
        "recomputing a transport digest must not make an invalid private inventory admissible"
    );
}

#[tokio::test]
async fn private_inventory_preserves_the_accepted_original_after_its_current_deadline() {
    ordinary_realm::case_future(private_inventory_scenario).await;
}

async fn private_inventory_scenario() {
    let source_database = TestDatabase::lease().await;
    let source_pool = source_database.pool();
    let fixture = ordinary_realm::case_future(|| {
        native_owner::accepted(&source_pool, "owner-private-original")
    })
    .await;
    let original = serde_json::to_value(&fixture.w1).unwrap();
    assert_eq!(stored(&source_pool, &fixture).await, Some(original.clone()));

    while native_owner::now() <= fixture.commit().committed_at {
        tokio::task::yield_now().await;
    }
    let later = ordinary_realm::case_future(|| fixture.fresh_witness()).await;
    assert!(
        later.device_projection_attestation.attestation.attested_at > fixture.commit().committed_at
    );

    let change = ordinary_realm::next_human_request_for_actor(
        &fixture.request.authority_commit,
        EventKind::RealmGovernanceStationChange,
        ActorId::account(fixture.successor.clone()),
        json!({
            "expected_governance_generation": fixture.commit().governance_generation.to_string(),
            "expected_realm_stream_commit_id": fixture.commit().commit_id,
            "new_governance_station_id": "ak:did_core:web:owner-next.example"
        }),
        native_owner::now(),
    );
    let change =
        ordinary_realm::case_future(|| ordinary_realm::source_request(&source_pool, change)).await;
    let unit_of_work = PgEventCommitUnitOfWork::new(source_pool.clone());
    ordinary_realm::case_future(|| unit_of_work.commit_event(change))
        .await
        .expect("freeze the actual outgoing terminal change under the successor's real Device");

    let (manifest, bytes) = fixture
        .store
        .export_management_private_state(&fixture.realm)
        .await
        .unwrap();
    let archive: Value = serde_json::from_slice(&bytes).unwrap();
    let inventory = archive["owner_transfer_acceptances"].as_array().unwrap();
    assert_eq!(inventory.len(), 1);
    assert_eq!(inventory[0].as_object().unwrap().len(), 3);
    assert_eq!(inventory[0]["event_id"], json!(fixture.event().event_id));
    assert_eq!(inventory[0]["commit_id"], json!(fixture.commit().commit_id));
    assert_eq!(inventory[0]["successor_device_evidence"], original);

    let target_database = TestDatabase::lease().await;
    let target_pool = target_database.pool();
    management_archive_fixture::seed_ordinary(
        &source_pool,
        &target_pool,
        archive["tables"].as_object().unwrap(),
    )
    .await;
    let target = PgAuthorityCommitStore {
        pool: target_pool.clone(),
    };
    assert_eq!(stored(&target_pool, &fixture).await, None);

    let mut changed = archive.clone();
    changed["owner_transfer_acceptances"] = json!([]);
    reject_changed_inventory(&target, &manifest, changed).await;
    assert_eq!(stored(&target_pool, &fixture).await, None);

    let mut changed = archive.clone();
    changed["owner_transfer_acceptances"]
        .as_array_mut()
        .unwrap()
        .push(inventory[0].clone());
    reject_changed_inventory(&target, &manifest, changed).await;
    assert_eq!(stored(&target_pool, &fixture).await, None);

    let mut changed = archive.clone();
    changed["owner_transfer_acceptances"][0]["signer_evidence_ref"] =
        json!(fixture.w1.signer_evidence_ref().unwrap());
    reject_changed_inventory(&target, &manifest, changed).await;
    assert_eq!(stored(&target_pool, &fixture).await, None);

    let mut changed = archive.clone();
    changed["owner_transfer_acceptances"][0]["successor_device_evidence"] =
        serde_json::to_value(&later).unwrap();
    reject_changed_inventory(&target, &manifest, changed).await;
    assert_eq!(stored(&target_pool, &fixture).await, None);

    let mut wrong_digest = manifest.clone();
    wrong_digest.state_digest = Hash::new(format!("sha256:{}", "42".repeat(32))).unwrap();
    assert!(
        target
            .import_management_private_state(&wrong_digest, &bytes)
            .await
            .is_err()
    );
    assert_eq!(stored(&target_pool, &fixture).await, None);

    // A historical accepted source remains valid after its short current-use
    // deadline. This is an actual clock boundary, not a fabricated timestamp.
    let expiry = fixture
        .w1
        .device_projection_attestation
        .attestation
        .expires_at;
    if let Ok(remaining) = (expiry - chrono::Utc::now()).to_std() {
        tokio::time::sleep(remaining + std::time::Duration::from_millis(2)).await;
    }
    assert!(native_owner::now() >= expiry);
    target
        .import_management_private_state(&manifest, &bytes)
        .await
        .unwrap();
    assert_eq!(stored(&target_pool, &fixture).await, Some(original.clone()));
    target
        .import_management_private_state(&manifest, &bytes)
        .await
        .unwrap();
    assert_eq!(stored(&target_pool, &fixture).await, Some(original));

    // Deliberately corrupt a private destination slot to exercise the immutable
    // conflict branch. These bytes are not claimed to be an accepted witness.
    let corrupt = json!({"corrupt_private_slot": true});
    let mut conn = target_pool.get().await.unwrap();
    let changed = diesel::sql_query(
        "UPDATE canonical_events SET successor_device_evidence_json=$1 \
         WHERE envelope->>'event_id'=$2 AND realm_id=$3 AND state='committed'",
    )
    .bind::<Jsonb, _>(&corrupt)
    .bind::<Text, _>(fixture.event().event_id.as_str())
    .bind::<Text, _>(fixture.realm.as_str())
    .execute(&mut *conn)
    .await
    .unwrap();
    assert_eq!(changed, 1);
    drop(conn);
    assert!(
        target
            .import_management_private_state(&manifest, &bytes)
            .await
            .is_err()
    );
    assert_eq!(stored(&target_pool, &fixture).await, Some(corrupt));
    assert_eq!(
        stored(&source_pool, &fixture).await,
        Some(serde_json::to_value(&fixture.w1).unwrap())
    );
}
