//! `KeysBackupsPage.backups[]` rows have the closed `backup_metadata` shape on
//! real PostgreSQL.
//!
//! `keys-operations.schema.json#/$defs/backup_metadata` is a closed allowlist
//! projection of the signed envelope (key-management §7.6.1): the ciphertext,
//! `domain_separation`, `contents`, `signature_proof`, `plaintext_commitment`,
//! `mixed_secret_storage`, `x_*` extensions and every `encryption` member other
//! than `recipient_method` / `recipient_key_ref` are withheld. The initial
//! schema generates the list row from the stored envelope, so every page row
//! is decided twice here: by the live Spec schema and by the SDK DTO.

mod support;

use std::fs;
use std::sync::OnceLock;

use arkret_models_crypto::{BackupActiveSeriesPointer, KeyBackupSummary, KeysBackupsPage};
use arkret_schema::ProtocolSchemaRegistry;
use arkret_schema_conformance::{default_spec_artifacts_dir, schema_registry_from_spec_artifacts};
use arkret_wire::{AccountId, ActorId, DidCoreId};
use coland_storage::{KeyBackupListQuery, KeyBackupStore};
use coland_storage_postgres::{Db, PgKeyBackupStore, PgPool};
use diesel::sql_types::{Jsonb, Text, Uuid};
use diesel_async::RunQueryDsl;
use serde_json::{Value, json};

static TEST_POOL: OnceLock<PgPool> = OnceLock::new();

const METADATA_SCHEMA: &str = "test:backup_metadata";
const LIST_SCHEMA: &str = "test:keys_backups_page";
const DIGEST: &str = "sha256:709e80c88487a2411e1ee4dfb9f22a861492d20c4765150c0c794abd70f8147c";
const PRIOR_DIGEST: &str =
    "sha256:1111111111111111111111111111111111111111111111111111111111111111";
const DEVICE: &str = "ak:device:01904100-0000-7000-8000-000000000001";

async fn test_pool() -> PgPool {
    if let Some(pool) = TEST_POOL.get() {
        return pool.clone();
    }
    let url = support::contract_database_url();
    support::ensure_contract_database(&url).await;
    let pool = Db::connect(Some(&url), Default::default())
        .await
        .expect("initialize test database")
        .pool
        .expect("a configured URL always yields a pool");
    let _ = TEST_POOL.set(pool.clone());
    pool
}

fn registry() -> ProtocolSchemaRegistry {
    let artifacts = default_spec_artifacts_dir().expect("arkret-spec artifacts checkout");
    let mut registry = schema_registry_from_spec_artifacts(&artifacts).unwrap();
    let schema: Value = serde_json::from_slice(
        &fs::read(artifacts.join("schemas/keys-operations.schema.json")).unwrap(),
    )
    .unwrap();
    registry
        .register_reference_document(schema.clone())
        .unwrap();
    registry
        .register_fragment(METADATA_SCHEMA, schema.clone(), "#/$defs/backup_metadata")
        .unwrap();
    registry
        .register_fragment(LIST_SCHEMA, schema, "#/$defs/keys_backups_page")
        .unwrap();
    registry
}

fn account() -> AccountId {
    let run = uuid::Uuid::now_v7().simple().to_string();
    AccountId::new(
        DidCoreId::new(format!("ak:did_core:web:kbm-{run}.example")).unwrap(),
        DidCoreId::new(format!("ak:did_core:web:station-{run}.example")).unwrap(),
    )
}

fn signature_proof() -> Value {
    json!({
        "device_id": DEVICE,
        "verification_method": "did:web:backup.example#device-signer",
        "signature_algorithm": "Ed25519", "signature": "AAAA",
        "device_authorize_event_id": "ak:event:AcIMom-0qqAXx_hmDJfxxaUJb_oJ64S3ARW1-WKFDCoD"
    })
}

/// A genesis envelope carrying every envelope-only member the list withholds,
/// and the tristate members as explicit `null`.
fn genesis(id: &str, actor: &ActorId, series: &str) -> Value {
    json!({
        "backup_id": id, "actor_id": actor, "device_id": DEVICE,
        "backup_kind": "secret_storage", "backup_version": "kb_1",
        "series_id": series, "series_sequence": 0, "supersedes_id": null, "expires_at": null,
        "created_at": "2026-09-09T00:00:00.000Z",
        "encryption": {
            "recipient_method": "secret_storage_key", "recipient_key_ref": "backup-key",
            "aead": {"name": "xchacha20_poly1305", "nonce": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
            "key_commitment": DIGEST
        },
        "domain_separation": {"subdomain": "secret_storage"},
        "contents": [{"item_kind": "recovery_key_share", "secret_id": "share"}],
        "ciphertext": "AAAA", "ciphertext_digest": DIGEST,
        "plaintext_commitment": DIGEST,
        "signature_proof": signature_proof(),
        "x_client_hint": {"build": 7}
    })
}

/// A successor carrying envelope-only refs and the remaining optional metadata.
fn successor(id: &str, actor: &ActorId, series: &str, prior: &str) -> Value {
    json!({
        "backup_id": id, "actor_id": actor, "device_id": DEVICE,
        "backup_kind": "secret_storage", "backup_version": "kb_2",
        "series_id": series, "series_sequence": 1,
        "supersedes_id": prior, "supersedes_digest": PRIOR_DIGEST,
        "source_commit_ref": {
            "realm_commit_id": "ak:realm_commit:ARNRmzDi2r78zveOLmoHOb6AephFMwVuGE1fwXmCoeo4",
            "device_generation_ref": 3
        },
        "recovery_policy_ref": {
            "policy_id": "ak:policy:01964137-3000-7000-8000-000000000001",
            "policy_version": 2
        },
        "expires_at": "2027-09-09T00:00:00.000Z",
        "created_at": "2026-09-10T00:00:00.000Z",
        "updated_at": "2026-09-11T00:00:00.000Z",
        "encryption": {
            "recipient_method": "secret_storage_key", "recipient_key_ref": "backup-key",
            "aead": {"name": "xchacha20_poly1305", "nonce": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}
        },
        "domain_separation": {"subdomain": "secret_storage"},
        "contents": [{"item_kind": "recovery_key_share", "secret_id": "share"}],
        "ciphertext": "BBBB", "ciphertext_digest": DIGEST,
        "signature_proof": signature_proof(),
        "retention": {"deletion_eligible_at": null, "legal_hold": false}
    })
}

fn page_query(actor: &ActorId) -> KeyBackupListQuery {
    KeyBackupListQuery {
        actor_id: actor.to_string(),
        backup_kind: None,
        series_id: None,
        after: None,
        limit: 51,
    }
}

/// The schema and the SDK DTO both accept the row, and the DTO round-trips it.
fn assert_closed_summary(registry: &ProtocolSchemaRegistry, row: &Value) -> KeyBackupSummary {
    registry
        .validate_value(METADATA_SCHEMA, row)
        .unwrap_or_else(|error| panic!("schema rejects list row {row}: {error}"));
    let summary = serde_json::from_value::<KeyBackupSummary>(row.clone())
        .unwrap_or_else(|error| panic!("SDK rejects list row {row}: {error}"));
    assert_eq!(&serde_json::to_value(&summary).unwrap(), row);
    summary
}

fn list_page(account: &AccountId, backups: Vec<Value>) -> Value {
    json!({
        "backups": backups,
        "active_series": {
            "account_id": account,
            "control_realm_id": "ak:realm:Ac1aCK8aQdnkYImvdH3DFjq4jDCP198pXYWCGzGuVyj5",
            "authority_commit_id": "ak:realm_commit:ARNRmzDi2r78zveOLmoHOb6AephFMwVuGE1fwXmCoeo4",
            "secret_storage": {"state": "absent"}
        },
        "has_more": false
    })
}

#[tokio::test]
async fn stored_envelopes_list_as_the_closed_backup_metadata_projection() {
    let registry = registry();
    let pool = test_pool().await;
    let backups = PgKeyBackupStore { pool };
    let account = account();
    let actor = ActorId::account(account.clone());
    let series = format!("ak:backup_series:{}", uuid::Uuid::now_v7());
    let first = format!("ak:backup:{}", uuid::Uuid::now_v7());
    let second = format!("ak:backup:{}", uuid::Uuid::now_v7());
    backups
        .put(first.clone(), genesis(&first, &actor, &series))
        .await
        .unwrap();
    backups
        .put(second.clone(), successor(&second, &actor, &series, &first))
        .await
        .unwrap();

    let page = backups.list_page(&page_query(&actor)).await.unwrap();
    assert_eq!(page.payloads.len(), 2);

    // Exact allowlist: envelope-only members are gone, stored values (including
    // the tristate nulls) are kept verbatim, nothing is synthesized.
    assert_eq!(
        page.payloads[0],
        json!({
            "backup_id": first, "actor_id": actor, "device_id": DEVICE,
            "backup_kind": "secret_storage", "backup_version": "kb_1",
            "series_id": series, "series_sequence": 0, "supersedes_id": null, "expires_at": null,
            "created_at": "2026-09-09T00:00:00.000Z", "ciphertext_digest": DIGEST,
            "encryption": {"recipient_method": "secret_storage_key", "recipient_key_ref": "backup-key"}
        })
    );
    let mut expected_successor = successor(&second, &actor, &series, &first);
    for member in [
        "domain_separation",
        "contents",
        "ciphertext",
        "signature_proof",
        "source_commit_ref",
        "recovery_policy_ref",
    ] {
        expected_successor.as_object_mut().unwrap().remove(member);
    }
    expected_successor["encryption"]
        .as_object_mut()
        .unwrap()
        .remove("aead");
    assert_eq!(page.payloads[1], expected_successor);

    let genesis_summary = assert_closed_summary(&registry, &page.payloads[0]);
    assert_eq!(genesis_summary.supersedes_id, Some(None));
    assert_eq!(genesis_summary.expires_at, Some(None));
    let successor_summary = assert_closed_summary(&registry, &page.payloads[1]);
    assert_eq!(
        successor_summary
            .supersedes_id
            .flatten()
            .map(|id| id.to_string()),
        Some(first.clone())
    );
    assert!(page.payloads[1].get("source_commit_ref").is_none());
    assert!(page.payloads[1].get("recovery_policy_ref").is_none());

    // The whole page is the closed `KeysBackupsPage`.
    let wire = list_page(&account, page.payloads.clone());
    registry.validate_value(LIST_SCHEMA, &wire).unwrap();
    let list = serde_json::from_value::<KeysBackupsPage>(wire).unwrap();
    assert_eq!(list.backups.len(), 2);
    assert_eq!(
        list.active_series.secret_storage,
        BackupActiveSeriesPointer::Absent {}
    );
}

#[tokio::test]
async fn list_row_is_generated_and_cannot_be_supplied_or_widened() {
    let registry = registry();
    let pool = test_pool().await;
    let backups = PgKeyBackupStore { pool: pool.clone() };
    let account = account();
    let actor = ActorId::account(account.clone());
    let series = format!("ak:backup_series:{}", uuid::Uuid::now_v7());
    let backup_id = format!("ak:backup:{}", uuid::Uuid::now_v7());
    let envelope = genesis(&backup_id, &actor, &series);
    let row_id = coland_storage::ids::typed_uuid_part_expect_internal(&backup_id);
    let mut conn = pool.get().await.unwrap();

    // The legacy "envelope minus ciphertext" row cannot be written: the list
    // row has no writer.
    let mut legacy = envelope.clone();
    legacy.as_object_mut().unwrap().remove("ciphertext");
    let error = diesel::sql_query(
        "INSERT INTO key_backups(id,actor_id,payload,metadata) VALUES($1,$2,$3,$4)",
    )
    .bind::<Uuid, _>(row_id)
    .bind::<Text, _>(actor.to_string())
    .bind::<Jsonb, _>(&envelope)
    .bind::<Jsonb, _>(&legacy)
    .execute(&mut conn)
    .await
    .expect_err("a supplied list row must be refused");
    assert!(error.to_string().contains("metadata"), "{error}");

    backups.put(backup_id.clone(), envelope).await.unwrap();
    let error = diesel::sql_query("UPDATE key_backups SET metadata=$2 WHERE id=$1")
        .bind::<Uuid, _>(row_id)
        .bind::<Jsonb, _>(&legacy)
        .execute(&mut conn)
        .await
        .expect_err("the list row cannot be rewritten");
    assert!(error.to_string().contains("metadata"), "{error}");

    // Even a raw payload rewrite with unregistered members and extra
    // encryption material still projects to the closed row.
    let mut widened = genesis(&backup_id, &actor, &series);
    widened["legacy_member"] = json!("kept out");
    widened["schema"] = json!("ak.schema.key_backup.v1");
    widened["encryption"]["kdf"] = json!({"name": "argon2id"});
    widened["encryption"]["x_private"] = json!(true);
    diesel::sql_query("UPDATE key_backups SET payload=$2 WHERE id=$1")
        .bind::<Uuid, _>(row_id)
        .bind::<Jsonb, _>(&widened)
        .execute(&mut conn)
        .await
        .unwrap();
    let page = backups.list_page(&page_query(&actor)).await.unwrap();
    assert_eq!(page.payloads.len(), 1);
    let row = &page.payloads[0];
    for withheld in [
        "legacy_member",
        "schema",
        "ciphertext",
        "domain_separation",
        "contents",
        "signature_proof",
        "plaintext_commitment",
        "x_client_hint",
    ] {
        assert!(row.get(withheld).is_none(), "{withheld} leaked: {row}");
    }
    assert_eq!(
        row["encryption"],
        json!({"recipient_method": "secret_storage_key", "recipient_key_ref": "backup-key"})
    );
    assert_closed_summary(&registry, row);

    // The pre-fix producer shape is what the schema and the DTO both refuse.
    let mut old_shape = widened.clone();
    old_shape.as_object_mut().unwrap().remove("ciphertext");
    assert!(
        registry
            .validate_value(METADATA_SCHEMA, &old_shape)
            .is_err()
    );
    assert!(serde_json::from_value::<KeyBackupSummary>(old_shape).is_err());
}
