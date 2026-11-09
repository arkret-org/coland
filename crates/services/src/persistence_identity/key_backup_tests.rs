//! Real PCR genesis and policy admission followed by the production backup
//! persistence port. These cases exercise writer/recipient checks and immutable
//! root-package transactions; they do not claim content decryption or E2E.

#[path = "key_backup_tests/retention.rs"]
mod retention;

use arkret_models_crypto::{KeyBackup, RecoveryPolicy, recovery_policy_signature_transcript_bytes};
use arkret_wire::{BackupId, BackupSeriesId, Hash};
use coland_storage::{
    AuthorityCommitTransaction, DeliveryPolicyStoreRegistry, RecoveryPolicyPublicationWrite,
};
use coland_storage_postgres::{PgPersistenceStore, PgPool, TestDatabase};
use ed25519_dalek::{Signer as _, SigningKey};
use serde_json::json;

#[path = "../../../test-support/src/device_authorization_history.rs"]
#[expect(dead_code, reason = "Only the native PCR fixture subset is used.")]
pub(super) mod device_authorization_history;
#[path = "../../../test-support/src/pcr_genesis.rs"]
#[expect(dead_code, reason = "Only the native PCR fixture subset is used.")]
mod pcr_genesis;

fn sign(package: &mut KeyBackup) {
    package.signature_proof.signature =
        arkret_wire::Base64UrlString::new(arkret_canonical::base64url_encode(
            SigningKey::from_bytes(&[81; 32])
                .sign(&package.signing_payload_bytes().unwrap())
                .to_bytes(),
        ))
        .unwrap();
}

async fn database() -> TestDatabase {
    let database = TestDatabase::lease().await;
    let station = arkret_wire::project_did_to_core_id(
        &arkret_wire::Did::new("did:web:backup-test.example").unwrap(),
    )
    .unwrap();
    database.bind_device_inventory_station(station.as_str());
    database
}

pub(super) struct RootFixture {
    pub(super) package: KeyBackup,
    pub(super) pcr: pcr_genesis::PcrGenesisFixture,
    pub(super) policy: RecoveryPolicy,
    pub(super) recovery_words: Option<String>,
}

impl RootFixture {
    pub(super) async fn new(pool: PgPool) -> Self {
        Box::pin(Self::with_recovery_words(pool, None)).await
    }

    pub(super) async fn new_for_station(pool: PgPool, station: arkret_wire::Did) -> Self {
        Box::pin(Self::with_station(pool, None, station)).await
    }

    pub(super) async fn new_with_recovery_words(pool: PgPool) -> Self {
        let words =
            arkret_crypto::identity_root::generate_bip39_identity_recovery_mnemonic().unwrap();
        Box::pin(Self::with_recovery_words(pool, Some(words))).await
    }

    async fn with_recovery_words(pool: PgPool, recovery_words: Option<String>) -> Self {
        Box::pin(Self::with_station(
            pool,
            recovery_words,
            arkret_wire::Did::new("did:web:backup-test.example").unwrap(),
        ))
        .await
    }

    async fn with_station(
        pool: PgPool,
        recovery_words: Option<String>,
        station: arkret_wire::Did,
    ) -> Self {
        let material = recovery_words.as_ref().map(|words| {
            arkret_crypto::identity_root::derive_identity_recovery_key_material_from_bip39(
                words, "", 1,
            )
            .unwrap()
        });
        let persistence = PgPersistenceStore::new(pool);
        let mut pcr = pcr_genesis::PcrGenesisFixture::new_with(
            station,
            device_authorization_history::DeviceHistoryFixtureOptions {
                local_id: format!("backup-{}", uuid::Uuid::now_v7().simple()),
                founding_device_id: arkret_wire::DeviceId::new(format!(
                    "ak:device:{}",
                    uuid::Uuid::now_v7()
                ))
                .unwrap(),
                ..Default::default()
            },
        );
        pcr.admit_into(&persistence).await.unwrap();
        let mut package = root_package();
        if let Some(material) = &material {
            let key = &material.backup_hpke_public_key_multikey;
            package.encryption.recipient_key_ref = Some(format!("did:key:{key}#{key}"));
        }
        package.actor_id = arkret_wire::ActorId::account(pcr.history.account.clone());
        package.signature_proof.device_id = Some(pcr.history.founding_device_id.clone());
        package.signature_proof.verification_method =
            pcr.history.device_verification_method.clone();
        package.signature_proof.device_authorize_event_id =
            Some(pcr.history.events[1].event_id.clone());
        package.source_commit_ref.as_mut().unwrap().realm_commit_id =
            pcr.history.commits[1].commit_id.clone();
        package.created_at = pcr.history.events[1].created_at;
        let now = package
            .created_at
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let policy_id =
            arkret_wire::PolicyId::new(format!("ak:policy:{}", uuid::Uuid::now_v7())).unwrap();
        package.recovery_policy_ref.as_mut().unwrap().policy_id = policy_id.clone();
        let proof_key = material.as_ref().map_or_else(
            || {
                arkret_canonical::ed25519_pubkey_to_did_key_multibase(
                    &SigningKey::from_bytes(&[92; 32]).verifying_key().to_bytes(),
                )
            },
            |material| material.recovery_proof_public_key_multikey.clone(),
        );
        let backup_key = package
            .encryption
            .recipient_key_ref
            .as_deref()
            .unwrap()
            .strip_prefix("did:key:")
            .unwrap()
            .split('#')
            .next()
            .unwrap();
        let expiry = (package.created_at + chrono::Duration::days(1000))
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let policy: RecoveryPolicy = serde_json::from_value(json!({
            "schema":"ak.schema.recovery_policy.v1","policy_id":policy_id,
            "account_id":pcr.history.account,"version":1,"supersedes_id":null,
            "trust_domain":"ak:trust_domain:backup-test.example","issued_at":now,
            "signature_proof":{"verification_method":pcr.history.device_verification_method,
                "signature_algorithm":"Ed25519","signature":"AA"},
            "methods":[{"kind":"recovery_unlock","keys":[{
                "verification_method":format!("did:key:{proof_key}#{proof_key}"),
                "public_key_multibase":proof_key,"signature_algorithm":"Ed25519",
                "not_before":now,"expires_at":expiry,"backup_hpke":{
                    "key_agreement_ref":package.encryption.recipient_key_ref,
                    "public_key_multibase":backup_key,"key_agreement_algorithm":"X25519",
                    "hpke_suites":["ak.hpke_x25519_aead_chacha20poly1305.v1"],
                    "use":"backup_hpke","not_before":now,"expires_at":expiry
                }
            }]}]
        }))
        .unwrap();
        let policy = Self::publish(&persistence, &mut pcr, policy).await;
        sign(&mut package);
        Self {
            package,
            pcr,
            policy,
            recovery_words,
        }
    }

    pub(super) async fn publish(
        persistence: &PgPersistenceStore,
        pcr: &mut pcr_genesis::PcrGenesisFixture,
        mut policy: RecoveryPolicy,
    ) -> RecoveryPolicy {
        policy.signature_proof.signature =
            arkret_wire::Base64UrlString::new(arkret_canonical::base64url_encode(
                SigningKey::from_bytes(&[81; 32])
                    .sign(&recovery_policy_signature_transcript_bytes(&policy).unwrap())
                    .to_bytes(),
            ))
            .unwrap();
        let event = pcr.history.event(
            arkret_wire::EventKind::PolicySet,
            json!({"policy_id":policy.policy_id,"value":policy}),
        );
        pcr.history.append(vec![event.clone()]);
        persistence
            .recovery_policies()
            .commit_publication(RecoveryPolicyPublicationWrite {
                commit: AuthorityCommitTransaction {
                    expected_authority: pcr.unit.transactions[1].expected_authority.clone(),
                    event,
                    commit: pcr.history.commits.last().unwrap().clone(),
                    producer_signer_fact: None,
                    content_backup_source: None,
                    mls_state: None,
                    welcomes: vec![],
                    recipient_queue_capacity: 0,
                },
                queued_at: policy.issued_at,
            })
            .await
            .unwrap();
        policy
    }

    async fn revoke_recipient(&mut self, pool: PgPool) {
        let mut successor = self.policy.clone();
        successor.policy_id =
            arkret_wire::PolicyId::new(format!("ak:policy:{}", uuid::Uuid::now_v7())).unwrap();
        successor.supersedes_id = Some(self.policy.policy_id.clone());
        successor.version += 1;
        successor.methods.clear();
        self.policy = Self::publish(&PgPersistenceStore::new(pool), &mut self.pcr, successor).await;
    }
}

use super::{Arc, KeyBackupService, PersistenceKeyBackups, Value};

pub(super) fn service(pool: PgPool) -> KeyBackupService {
    KeyBackupService::new(Arc::new(PersistenceKeyBackups(Arc::new(
        PgPersistenceStore::new(pool),
    ))))
}

fn root_package() -> KeyBackup {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../../../arkret-spec/spec/v1/artifacts/fixtures/content-history-fixture.json"
    ))
    .unwrap();
    let mut package: KeyBackup =
        serde_json::from_value(fixture["root_backup"]["envelope"].clone()).unwrap();
    package.backup_id = fresh_id();
    package.series_id =
        BackupSeriesId::new(format!("ak:backup_series:{}", uuid::Uuid::now_v7())).unwrap();
    package.validate().unwrap();
    package
}

fn fresh_id() -> BackupId {
    BackupId::new(format!("ak:backup:{}", uuid::Uuid::now_v7())).unwrap()
}

pub(super) fn successor(previous: &KeyBackup) -> KeyBackup {
    let mut next = previous.clone();
    next.backup_id = fresh_id();
    next.series_sequence = previous.series_sequence + 1;
    next.supersedes_id = Some(previous.backup_id.clone());
    next.supersedes_digest = Some(
        Hash::new(arkret_canonical::sha256_digest(
            previous.signing_payload_bytes().unwrap(),
        ))
        .unwrap(),
    );
    next.validate().unwrap();
    sign(&mut next);
    next
}

pub(super) async fn put(
    service: &KeyBackupService,
    package: &KeyBackup,
) -> crate::ServiceResult<()> {
    service
        .store_backup(
            package.backup_id.to_string(),
            serde_json::to_value(package).unwrap(),
        )
        .await
}

#[tokio::test]
async fn root_package_identity_is_immutable_and_exact_retry_survives_reopen() {
    let database = database().await;
    let store = service(database.pool());
    let fixture = RootFixture::new(database.pool()).await;
    let original = fixture.package;
    put(&store, &original).await.unwrap();
    put(&store, &original).await.unwrap();
    let mut changed = original.clone();
    changed.contents[0].root_ref = Some(Hash::new(format!("sha256:{}", "7".repeat(64))).unwrap());
    sign(&mut changed);
    let error = put(&store, &changed).await.unwrap_err();
    assert_eq!(
        error.conflict_code(),
        Some(coland_storage::ConflictCode::DuplicateConflict)
    );
    let reopened = service(database.pool());
    assert_eq!(
        reopened.backup(original.backup_id.as_str()).await.unwrap(),
        Some(serde_json::to_value(&original).unwrap())
    );
    put(&reopened, &original).await.unwrap();
}

#[tokio::test]
async fn concurrent_successors_have_one_winner_and_cannot_overwrite_its_root_package() {
    let database = database().await;
    let store = service(database.pool());
    let fixture = RootFixture::new(database.pool()).await;
    let original = fixture.package;
    put(&store, &original).await.unwrap();
    let left = successor(&original);
    let right = successor(&original);
    let (a, b) = tokio::join!(put(&store, &left), put(&store, &right));
    assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
    let (winner, loser, error) = match (a, b) {
        (Ok(()), Err(error)) => (&left, &right, error),
        (Err(error), Ok(())) => (&right, &left, error),
        other => panic!("one immutable successor must win: {other:?}"),
    };
    assert_eq!(
        error.conflict_code(),
        Some(coland_storage::ConflictCode::SeriesSeqNotMonotonic)
    );
    assert_eq!(
        store.backup(winner.backup_id.as_str()).await.unwrap(),
        Some(serde_json::to_value(winner).unwrap())
    );
    assert!(
        store
            .backup(loser.backup_id.as_str())
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        store.backup(original.backup_id.as_str()).await.unwrap(),
        Some(serde_json::to_value(&original).unwrap())
    );
}

#[tokio::test]
async fn missing_or_wrong_predecessor_refuses_without_consuming_the_next_sequence() {
    let database = database().await;
    let store = service(database.pool());
    let fixture = RootFixture::new(database.pool()).await;
    let original = fixture.package;
    let next = successor(&original);
    assert!(put(&store, &next).await.is_err());
    assert!(
        store
            .backup(next.backup_id.as_str())
            .await
            .unwrap()
            .is_none()
    );
    put(&store, &original).await.unwrap();
    let mut wrong = next.clone();
    wrong.supersedes_digest = Some(Hash::new(format!("sha256:{}", "8".repeat(64))).unwrap());
    sign(&mut wrong);
    assert!(put(&store, &wrong).await.is_err());
    assert!(
        store
            .backup(next.backup_id.as_str())
            .await
            .unwrap()
            .is_none()
    );
    put(&store, &next).await.unwrap();
    let latest = successor(&next);
    put(&store, &latest).await.unwrap();
    put(&store, &original).await.unwrap();
    assert_eq!(
        store.backup(latest.backup_id.as_str()).await.unwrap(),
        Some(serde_json::to_value(latest).unwrap())
    );
}

#[tokio::test]
async fn another_subject_cannot_rebind_an_existing_backup_identity() {
    let database = database().await;
    let store = service(database.pool());
    let fixture = RootFixture::new(database.pool()).await;
    let original = fixture.package;
    put(&store, &original).await.unwrap();
    let mut other = RootFixture::new(database.pool()).await.package;
    other.backup_id = original.backup_id.clone();
    sign(&mut other);
    let error = put(&store, &other).await.unwrap_err();
    assert_eq!(
        error.conflict_code(),
        Some(coland_storage::ConflictCode::DuplicateConflict)
    );
    assert_eq!(
        store.backup(original.backup_id.as_str()).await.unwrap(),
        Some(serde_json::to_value(original).unwrap())
    );
}

#[tokio::test]
async fn unadmitted_writer_and_forged_native_signature_leave_no_root_package() {
    let database = database().await;
    let store = service(database.pool());
    let unadmitted = root_package();
    let error = put(&store, &unadmitted).await.unwrap_err();
    assert_eq!(
        error.conflict_code(),
        Some(coland_storage::ConflictCode::DeviceUnauthorized)
    );
    assert!(
        store
            .backup(unadmitted.backup_id.as_str())
            .await
            .unwrap()
            .is_none()
    );
    let fixture = RootFixture::new(database.pool()).await;
    let mut forged = fixture.package;
    forged.signature_proof.signature =
        arkret_wire::Base64UrlString::new(arkret_canonical::base64url_encode([7; 64])).unwrap();
    let error = put(&store, &forged).await.unwrap_err();
    assert_eq!(
        error.conflict_code(),
        Some(coland_storage::ConflictCode::SignatureInvalid)
    );
    assert!(
        store
            .backup(forged.backup_id.as_str())
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn policy_revocation_after_preparation_rejects_new_root_and_keeps_old_original() {
    let database = database().await;
    let store = service(database.pool());
    let mut fixture = RootFixture::new(database.pool()).await;
    put(&store, &fixture.package).await.unwrap();
    let prepared = successor(&fixture.package);
    fixture.revoke_recipient(database.pool()).await;
    let error = put(&store, &prepared).await.unwrap_err();
    assert_eq!(
        error.conflict_code(),
        Some(coland_storage::ConflictCode::RecoveryPolicyMismatch)
    );
    assert!(
        store
            .backup(prepared.backup_id.as_str())
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        store
            .backup(fixture.package.backup_id.as_str())
            .await
            .unwrap(),
        Some(serde_json::to_value(&fixture.package).unwrap())
    );
}

#[tokio::test]
async fn wrong_generation_authorization_or_pcr_cannot_consume_the_successor_slot() {
    use coland_storage::ConflictCode;
    let database = database().await;
    let store = service(database.pool());
    let fixture = RootFixture::new(database.pool()).await;
    let foreign = RootFixture::new(database.pool()).await;
    put(&store, &fixture.package).await.unwrap();
    let valid = successor(&fixture.package);
    for (case, expected) in [
        ("generation", ConflictCode::BackupRevisionStale),
        ("authorization", ConflictCode::SignatureInvalid),
        ("pcr", ConflictCode::BackupRevisionStale),
    ] {
        let mut wrong = valid.clone();
        match case {
            "generation" => {
                wrong
                    .source_commit_ref
                    .as_mut()
                    .unwrap()
                    .device_generation_ref += 1
            }
            "authorization" => {
                wrong.signature_proof.device_authorize_event_id = foreign
                    .package
                    .signature_proof
                    .device_authorize_event_id
                    .clone()
            }
            _ => wrong.source_commit_ref = foreign.package.source_commit_ref.clone(),
        }
        sign(&mut wrong);
        let error = put(&store, &wrong).await.unwrap_err();
        assert_eq!(error.conflict_code(), Some(expected), "{case}");
        assert!(
            store
                .backup(valid.backup_id.as_str())
                .await
                .unwrap()
                .is_none()
        );
    }
    let mut wrong = valid.clone();
    wrong.ciphertext_digest = Hash::new(format!("sha256:{}", "6".repeat(64))).unwrap();
    sign(&mut wrong);
    assert!(put(&store, &wrong).await.is_err());
    assert!(
        store
            .backup(valid.backup_id.as_str())
            .await
            .unwrap()
            .is_none()
    );
    put(&store, &valid).await.unwrap();
}

#[tokio::test]
async fn deleted_backup_identity_cannot_be_resurrected_or_rebound_after_reopen() {
    use coland_storage::ConflictCode;
    let database = database().await;
    let store = service(database.pool());
    let fixture = RootFixture::new(database.pool()).await;
    let original = fixture.package;
    put(&store, &original).await.unwrap();
    let replacement = successor(&original);
    put(&store, &replacement).await.unwrap();
    assert!(
        store
            .delete_backup(original.backup_id.as_str())
            .await
            .unwrap()
    );
    let reopened = service(database.pool());
    assert!(
        reopened
            .backup(original.backup_id.as_str())
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        put(&reopened, &original).await.unwrap_err().conflict_code(),
        Some(ConflictCode::FailedPrecondition)
    );
    let mut changed = original.clone();
    changed.series_id =
        BackupSeriesId::new(format!("ak:backup_series:{}", uuid::Uuid::now_v7())).unwrap();
    sign(&mut changed);
    assert_eq!(
        put(&reopened, &changed).await.unwrap_err().conflict_code(),
        Some(ConflictCode::DuplicateConflict)
    );
    assert!(
        reopened
            .backup(original.backup_id.as_str())
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn retained_root_prevents_series_erasure_and_deleted_identity_reuse() {
    use coland_storage::ConflictCode;
    let database = database().await;
    let store = service(database.pool());
    let fixture = RootFixture::new(database.pool()).await;
    let original = fixture.package;
    put(&store, &original).await.unwrap();
    assert_eq!(
        store
            .delete_backup(original.backup_id.as_str())
            .await
            .unwrap_err()
            .conflict_code(),
        Some(ConflictCode::FailedPrecondition),
    );
    let mut restarted = original.clone();
    restarted.backup_id = fresh_id();
    sign(&mut restarted);
    assert_eq!(
        put(&store, &restarted).await.unwrap_err().conflict_code(),
        Some(ConflictCode::SeriesSeqNotMonotonic)
    );
    let next = successor(&original);
    put(&store, &next).await.unwrap();
    assert!(
        store
            .delete_backup(original.backup_id.as_str())
            .await
            .unwrap()
    );
    assert_eq!(
        store
            .delete_backup(next.backup_id.as_str())
            .await
            .unwrap_err()
            .conflict_code(),
        Some(ConflictCode::FailedPrecondition),
    );
    assert_eq!(
        put(&store, &original).await.unwrap_err().conflict_code(),
        Some(ConflictCode::FailedPrecondition),
    );
    restarted.series_id =
        BackupSeriesId::new(format!("ak:backup_series:{}", uuid::Uuid::now_v7())).unwrap();
    sign(&mut restarted);
    put(&store, &restarted).await.unwrap();
    assert!(
        store
            .backup(original.backup_id.as_str())
            .await
            .unwrap()
            .is_none()
    );
}
