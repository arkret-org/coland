//! Real recipient overlap, root rewrap, old-package deletion and history-only
//! delivery against the unchanged original Profile protection.

use std::sync::Arc;

use arkret_models_crypto::*;
use coland_storage::{
    DeliveryPolicyStoreRegistry as _, EventProjectionStoreRegistry as _, PersistenceStore as _,
};
use coland_storage_postgres::{PgPersistenceStore, PgPool};
use ed25519_dalek::{Signer as _, SigningKey};
use horme::RunQueryDsl as _;
use serde_json::json;

use super::{RootFixture, consume, proof, random, sign_with};
use crate::persistence_identity::key_backup_tests::device_authorization_history::sign_event;
use crate::persistence_identity::key_backup_tests::successor;

async fn prepare_policy(
    pool: &PgPool,
    fixture: &RootFixture,
    mut policy: RecoveryPolicy,
    method: &arkret_wire::DidUrl,
    seed: &[u8; 32],
) -> (
    RecoveryPolicy,
    coland_storage::RecoveryPolicyPublicationWrite,
) {
    policy.signature_proof.verification_method = method.clone();
    policy.signature_proof.signature =
        arkret_wire::Base64UrlString::new(arkret_canonical::base64url_encode(
            SigningKey::from_bytes(seed)
                .sign(&recovery_policy_signature_transcript_bytes(&policy).unwrap())
                .to_bytes(),
        ))
        .unwrap();
    let event = sign_event(
        fixture.pcr.history.raw_event(
            arkret_wire::EventKind::PolicySet,
            json!({"policy_id":policy.policy_id,"value":policy}),
            &fixture.pcr.history.events[0].realm_id,
        ),
        method.clone(),
        *seed,
    );
    let app = crate::authority_commit::AuthorityCommitApplication::new(
        crate::persistence::PersistenceHandle::new(Arc::new(PgPersistenceStore::new(pool.clone()))),
        64,
    );
    let at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    let commit = app
        .prepare_self_event_transaction(
            &event,
            &fixture.pcr.history.account.station_id,
            fixture.pcr.history.authority_method(),
            &SigningKey::from_bytes(&[83; 32]),
            at,
        )
        .await
        .unwrap();
    (
        policy,
        coland_storage::RecoveryPolicyPublicationWrite {
            commit,
            queued_at: at,
        },
    )
}

fn next_policy(fixture: &RootFixture) -> RecoveryPolicy {
    let mut policy = fixture.policy.clone();
    policy.policy_id =
        arkret_wire::PolicyId::new(format!("ak:policy:{}", uuid::Uuid::now_v7())).unwrap();
    policy.version += 1;
    policy.supersedes_id = Some(fixture.policy.policy_id.clone());
    policy.issued_at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    policy
}

async fn publish(
    pool: &PgPool,
    fixture: &mut RootFixture,
    policy: RecoveryPolicy,
    method: &arkret_wire::DidUrl,
    seed: &[u8; 32],
) {
    let (policy, write) = prepare_policy(pool, fixture, policy, method, seed).await;
    PgPersistenceStore::new(pool.clone())
        .recovery_policies()
        .commit_publication(write.clone())
        .await
        .unwrap();
    fixture.pcr.history.events.push(write.commit.event);
    fixture.pcr.history.commits.push(write.commit.commit);
    fixture.policy = policy;
}

fn open(
    backup: &KeyBackup,
    private: &[u8],
    signer: &[u8; 32],
) -> arkret_crypto::Result<KeyBackupPlaintext> {
    arkret_crypto::content_history::open_content_root_backup(backup, private, |bytes, signature| {
        if arkret_signatures::verify_detached_ed25519_signature(
            &arkret_signatures::PublicKeyMaterial::Ed25519Raw {
                bytes: SigningKey::from_bytes(signer)
                    .verifying_key()
                    .to_bytes()
                    .to_vec(),
            },
            bytes,
            signature.signature.as_str(),
        ) {
            Ok(())
        } else {
            Err(arkret_crypto::Error::Protocol(
                "replacement original signature differs".into(),
            ))
        }
    })
}

pub(super) async fn exercise(
    pool: &PgPool,
    fixture: &mut RootFixture,
    reader: &coland_storage::HumanPcrHistoryReader,
    previous_proof: &KeyBackupUnlockProof,
    seed: &[u8; 32],
    original: &KeyBackup,
    bag: &KeyBackupPlaintext,
) -> (ContentRootBackupEntry, arkret_wire::BackupId) {
    let words = arkret_crypto::identity_root::generate_bip39_identity_recovery_mnemonic().unwrap();
    let material = arkret_crypto::identity_root::derive_identity_recovery_key_material_from_bip39(
        &words, "", 1,
    )
    .unwrap();
    let old_material =
        arkret_crypto::identity_root::derive_identity_recovery_key_material_from_bip39(
            fixture.recovery_words.as_deref().unwrap(),
            "",
            1,
        )
        .unwrap();
    let RecoveryMethod::RecoveryUnlock { keys } = &fixture.policy.methods[0] else {
        unreachable!()
    };
    let mut new_key = keys[0].clone();
    let factor = &material.recovery_proof_public_key_multikey;
    new_key.verification_method =
        arkret_wire::DidUrl::new(format!("did:key:{factor}#{factor}")).unwrap();
    new_key.public_key_multibase = factor.clone();
    let recipient = &material.backup_hpke_public_key_multikey;
    new_key.backup_hpke.key_agreement_ref =
        arkret_wire::DidUrl::new(format!("did:key:{recipient}#{recipient}")).unwrap();
    new_key.backup_hpke.public_key_multibase = recipient.clone();
    let method = &previous_proof.signature_proof.verification_method;
    let mut premature = next_policy(fixture);
    premature.methods = vec![RecoveryMethod::RecoveryUnlock {
        keys: vec![new_key.clone()],
    }];
    let persistence = PgPersistenceStore::new(pool.clone());
    let (.., write) = prepare_policy(pool, fixture, premature, method, seed).await;
    let head = persistence
        .authority_commits()
        .stream_head(&write.commit.commit.stream_ref)
        .await
        .unwrap();
    let error = persistence
        .recovery_policies()
        .commit_publication(write.clone())
        .await
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("would strand a retained PCR content root"),
        "{error}"
    );
    assert_eq!(
        persistence
            .authority_commits()
            .stream_head(&write.commit.commit.stream_ref)
            .await
            .unwrap(),
        head
    );
    assert!(
        persistence
            .authority_commits()
            .committed_event(&write.commit.event.event_id)
            .await
            .unwrap()
            .is_none()
    );
    let mut overlap = next_policy(fixture);
    let RecoveryMethod::RecoveryUnlock { keys } = &mut overlap.methods[0] else {
        unreachable!()
    };
    keys.push(new_key.clone());
    publish(pool, fixture, overlap, method, seed).await;
    let mut replacement = successor(original);
    replacement.created_at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    replacement.recovery_policy_ref = Some(RecoveryPolicyRef {
        policy_id: fixture.policy.policy_id.clone(),
        policy_version: fixture.policy.version,
    });
    replacement.signature_proof.device_id = Some(reader.device_id.clone());
    replacement.signature_proof.device_authorize_event_id = Some(
        reader
            .credential_device_binding
            .as_ref()
            .unwrap()
            .authorization_event_id
            .clone(),
    );
    replacement.signature_proof.verification_method = method.clone();
    replacement.source_commit_ref = Some(KeyBackupSourceCommitRef {
        realm_commit_id: fixture
            .pcr
            .history
            .commits
            .last()
            .unwrap()
            .commit_id
            .clone(),
        device_generation_ref: 2,
    });
    replacement.encryption.recipient_key_ref =
        Some(new_key.backup_hpke.key_agreement_ref.to_string());
    let mut rewrapped_bag = bag.clone();
    rewrapped_bag.backup_id = replacement.backup_id.clone();
    rewrapped_bag.series_sequence = replacement.series_sequence;
    let replacement = arkret_crypto::content_history::seal_content_root_backup(
        replacement,
        &rewrapped_bag,
        &material.backup_hpke_public_key,
        |bytes| Ok(SigningKey::from_bytes(seed).sign(bytes).to_bytes().to_vec()),
    )
    .unwrap();
    let store = persistence.key_backups();
    store
        .put(
            replacement.backup_id.to_string(),
            serde_json::to_value(&replacement).unwrap(),
        )
        .await
        .unwrap();
    assert_ne!(
        replacement.encryption.aead.enc,
        original.encryption.aead.enc
    );
    assert!(
        open(
            &replacement,
            &old_material.backup_hpke_serialized_private_key,
            seed
        )
        .is_err()
    );
    let verified = open(
        &replacement,
        &material.backup_hpke_serialized_private_key,
        seed,
    )
    .unwrap();
    assert_eq!(
        serde_json::to_value(&verified.items).unwrap(),
        serde_json::to_value(&bag.items).unwrap()
    );
    let mut final_policy = next_policy(fixture);
    final_policy.methods = vec![RecoveryMethod::RecoveryUnlock {
        keys: vec![new_key],
    }];
    publish(pool, fixture, final_policy, method, seed).await;
    fixture.recovery_words = Some(words);
    assert!(store.delete(original.backup_id.as_str()).await.unwrap());
    assert!(
        store
            .get(original.backup_id.as_str())
            .await
            .unwrap()
            .is_none()
    );
    let listed = store
        .confirmed_list_page_for_device(
            &reader.account_id,
            &reader.device_id,
            chrono::Utc::now(),
            &coland_storage::KeyBackupListQuery {
                actor_id: replacement.actor_id.to_string(),
                backup_kind: None,
                series_id: None,
                after: None,
                limit: 200,
            },
        )
        .await
        .unwrap();
    assert!(
        listed
            .page
            .payloads
            .iter()
            .any(|row| row["backup_id"] == replacement.backup_id.as_str())
    );
    let challenge = KeysBackupsUnlockChallenge {
        challenge_id: random(),
        challenge: random(),
        nonce: random(),
        operation: arkret_wire::ServiceOperationId::SELF_KEYS_BACKUPS_COMMAND_UNLOCK_V1.into(),
        account_id: reader.account_id.clone(),
        requesting_device_id: reader.device_id.clone(),
        backup_id: replacement.backup_id.clone(),
        series_id: replacement.series_id.clone(),
        ciphertext_digest: replacement.ciphertext_digest.clone(),
        audience: previous_proof.audience.clone(),
        service_id: previous_proof.service_id.clone(),
        request_id: random(),
        subject_actor_id: None,
        custody_authorization_ref: None,
        content_history: previous_proof.content_history.clone(),
        issued_at: replacement.created_at,
        expires_at: replacement.created_at + chrono::Duration::seconds(300),
    };
    let issued = store
        .issue_human_pcr_history_unlock_challenge(reader, &challenge)
        .await
        .unwrap();
    let mut signed = proof(&issued, fixture);
    signed.signature_proof.verification_method = method.clone();
    sign_with(&mut signed, seed);
    consume(pool, reader, &signed, &replacement).await.unwrap();
    let (delivered, guard) = store
        .human_pcr_history_unlock_delivery(reader, &signed, "authenticated-session:jkt")
        .await
        .unwrap();
    guard.finish().await.unwrap();
    assert_eq!(delivered, replacement);
    // Disabling the recovery-signing factor does not revoke the independently
    // scoped backup HPKE agreement or this already-current Device credential.
    let mut disable_factor = next_policy(fixture);
    let RecoveryMethod::RecoveryUnlock { keys } = &mut disable_factor.methods[0] else {
        unreachable!()
    };
    keys[0].revoked_at = Some(arkret_canonical::normalize_timestamp_canonical(
        chrono::Utc::now(),
    ));
    publish(pool, fixture, disable_factor, method, seed).await;
    let (_, guard) = store
        .human_pcr_history_unlock_delivery(reader, &signed, "authenticated-session:jkt")
        .await
        .unwrap();
    guard.finish().await.unwrap();
    // A missing original index is not replaced by trusting an arbitrary new
    // packet that merely claims the same public root ref.
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query("UPDATE key_backup_identities SET content_index='[]'::jsonb WHERE id=$1")
        .bind::<diesel::sql_types::Uuid, _>(
            uuid::Uuid::parse_str(
                original
                    .backup_id
                    .as_str()
                    .strip_prefix("ak:backup:")
                    .unwrap(),
            )
            .unwrap(),
        )
        .execute(&mut *conn)
        .await
        .unwrap();
    drop(conn);
    let error = store
        .human_pcr_history_unlock_delivery(reader, &signed, "authenticated-session:jkt")
        .await
        .err()
        .expect("missing original mapping must refuse");
    assert!(
        error
            .to_string()
            .contains("no original signed native binding"),
        "{error}"
    );
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query("UPDATE key_backup_identities SET content_index=$2 WHERE id=$1")
        .bind::<diesel::sql_types::Uuid, _>(
            uuid::Uuid::parse_str(
                original
                    .backup_id
                    .as_str()
                    .strip_prefix("ak:backup:")
                    .unwrap(),
            )
            .unwrap(),
        )
        .bind::<diesel::sql_types::Jsonb, _>(serde_json::to_value(&original.contents).unwrap())
        .execute(&mut *conn)
        .await
        .unwrap();
    drop(conn);
    let bag = open(
        &delivered,
        &material.backup_hpke_serialized_private_key,
        seed,
    )
    .unwrap();
    let SecretStorageEntry::ContentRoot(root) = bag.items.into_iter().next().unwrap() else {
        unreachable!()
    };
    (root, delivered.backup_id)
}

#[tokio::test]
async fn first_put_root_requires_recipient_overlap_before_any_encrypted_original() {
    use coland_storage_postgres::TestDatabase;

    use crate::persistence_identity::key_backup_tests::{put, service};

    let database = TestDatabase::lease().await;
    let station = arkret_wire::project_did_to_core_id(
        &arkret_wire::Did::new("did:web:backup-test.example").unwrap(),
    )
    .unwrap();
    database.bind_device_inventory_station(station.as_str());
    let pool = database.pool();
    let mut fixture = RootFixture::new_with_recovery_words(pool.clone()).await;
    let store = service(pool.clone());
    put(&store, &fixture.package).await.unwrap();
    let replacement = fresh_recovery_factor(&fixture);
    let method = fixture.package.signature_proof.verification_method.clone();
    let mut premature = next_policy(&fixture);
    premature.methods = vec![RecoveryMethod::RecoveryUnlock {
        keys: vec![replacement.clone()],
    }];
    let persistence = PgPersistenceStore::new(pool.clone());
    let (_, write) = prepare_policy(&pool, &fixture, premature, &method, &[81; 32]).await;
    let head = persistence
        .authority_commits()
        .stream_head(&write.commit.commit.stream_ref)
        .await
        .unwrap();
    let error = persistence
        .recovery_policies()
        .commit_publication(write.clone())
        .await
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("would strand a retained PCR content root"),
        "{error}"
    );
    assert_eq!(
        persistence
            .authority_commits()
            .stream_head(&write.commit.commit.stream_ref)
            .await
            .unwrap(),
        head
    );
    assert!(
        persistence
            .authority_commits()
            .committed_event(&write.commit.event.event_id)
            .await
            .unwrap()
            .is_none()
    );
    let mut overlap = next_policy(&fixture);
    let RecoveryMethod::RecoveryUnlock { keys } = &mut overlap.methods[0] else {
        unreachable!()
    };
    keys.push(replacement);
    publish(&pool, &mut fixture, overlap, &method, &[81; 32]).await;
    assert!(
        store
            .backup(fixture.package.backup_id.as_str())
            .await
            .unwrap()
            .is_some()
    );
}

fn fresh_recovery_factor(fixture: &RootFixture) -> RecoveryKeyEntry {
    let words = arkret_crypto::identity_root::generate_bip39_identity_recovery_mnemonic().unwrap();
    let material = arkret_crypto::identity_root::derive_identity_recovery_key_material_from_bip39(
        &words, "", 1,
    )
    .unwrap();
    let RecoveryMethod::RecoveryUnlock { keys } = &fixture.policy.methods[0] else {
        panic!("recovery factor expected")
    };
    let mut replacement = keys[0].clone();
    let proof = &material.recovery_proof_public_key_multikey;
    replacement.verification_method =
        arkret_wire::DidUrl::new(format!("did:key:{proof}#{proof}")).unwrap();
    replacement.public_key_multibase = proof.clone();
    let recipient = &material.backup_hpke_public_key_multikey;
    replacement.backup_hpke.key_agreement_ref =
        arkret_wire::DidUrl::new(format!("did:key:{recipient}#{recipient}")).unwrap();
    replacement.backup_hpke.public_key_multibase = recipient.clone();
    replacement
}

#[tokio::test]
async fn first_put_racing_recipient_rotation_cannot_strand_a_new_root() {
    use coland_storage_postgres::TestDatabase;

    use crate::persistence_identity::key_backup_tests::{put, service};

    let database = TestDatabase::lease().await;
    let station = arkret_wire::project_did_to_core_id(
        &arkret_wire::Did::new("did:web:backup-test.example").unwrap(),
    )
    .unwrap();
    database.bind_device_inventory_station(station.as_str());
    let pool = database.pool();
    let fixture = RootFixture::new_with_recovery_words(pool.clone()).await;
    let store = service(pool.clone());
    let mut rotation = next_policy(&fixture);
    rotation.methods = vec![RecoveryMethod::RecoveryUnlock {
        keys: vec![fresh_recovery_factor(&fixture)],
    }];
    let method = fixture.package.signature_proof.verification_method.clone();
    let (_, write) = prepare_policy(&pool, &fixture, rotation, &method, &[81; 32]).await;
    let persistence = PgPersistenceStore::new(pool.clone());
    let policies = persistence.recovery_policies();
    let (root, rotation) = tokio::join!(
        put(&store, &fixture.package),
        policies.commit_publication(write.clone()),
    );
    assert_eq!(
        usize::from(root.is_ok()) + usize::from(rotation.is_ok()),
        1,
        "only the root admission or the disjoint factor rotation may win: root={root:?}, rotation={rotation:?}"
    );
    assert_eq!(
        store
            .backup(fixture.package.backup_id.as_str())
            .await
            .unwrap()
            .is_some(),
        root.is_ok()
    );
    assert_eq!(
        persistence
            .authority_commits()
            .committed_event(&write.commit.event.event_id)
            .await
            .unwrap()
            .is_some(),
        rotation.is_ok()
    );
}
