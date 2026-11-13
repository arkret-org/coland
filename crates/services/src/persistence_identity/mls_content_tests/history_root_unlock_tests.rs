//! Exercise native history-only root issue/consume/handoff against the real
//! accepted encrypted Profile produced by the parent adapter test.

use arkret_models_crypto::*;
use arkret_wire::{CommittedEventRef, SchemaId};
use coland_storage::{
    EventProjectionStoreRegistry as _, KeyBackupUnlockBasis, KeyBackupUnlockCommand,
};
use coland_storage_postgres::{PgPersistenceStore, PgPool};
use ed25519_dalek::Signer as _;

use super::super::pcr_history_tests;
use super::RootFixture;

mod identity_recovery;

mod root_rotation;

mod recovery_source;

mod history_material;

mod claim_fence;

fn random() -> arkret_wire::Base64UrlString {
    arkret_wire::Base64UrlString::new(
        arkret_crypto::content_history::fresh_content_key_salt().unwrap(),
    )
    .unwrap()
}

fn proof(challenge: &KeysBackupsUnlockChallenge, fixture: &RootFixture) -> KeyBackupUnlockProof {
    let mut proof = KeyBackupUnlockProof {
        schema: SchemaId::KEY_BACKUP_UNLOCK_PROOF_V1.into(),
        authority: KeyBackupUnlockAuthority::CurrentDevice {
            challenge_id: challenge.challenge_id.clone(),
            nonce: challenge.nonce.clone(),
        },
        account_id: challenge.account_id.clone(),
        requesting_device_id: challenge.requesting_device_id.clone(),
        backup_id: challenge.backup_id.clone(),
        backup_kind: BackupKind::SecretStorage,
        series_id: challenge.series_id.clone(),
        ciphertext_digest: challenge.ciphertext_digest.clone(),
        challenge: challenge.challenge.clone(),
        service_id: challenge.service_id.clone(),
        audience: challenge.audience.clone(),
        issued_at: challenge.issued_at,
        expires_at: challenge.expires_at,
        signature_proof: KeyBackupUnlockSignatureProof {
            verification_method: fixture.pcr.history.device_verification_method.clone(),
            signature_algorithm: KeyBackupSignatureAlgorithm::Ed25519,
            signature: arkret_wire::Base64UrlString::new("AA").unwrap(),
        },
        subject_actor_id: challenge.subject_actor_id.clone(),
        custody_authorization_ref: challenge.custody_authorization_ref.clone(),
        content_history: challenge.content_history.clone(),
    };
    sign(&mut proof);
    proof
}

fn sign(proof: &mut KeyBackupUnlockProof) {
    sign_with(proof, &[81; 32]);
}

fn sign_with(proof: &mut KeyBackupUnlockProof, seed: &[u8; 32]) {
    proof.signature_proof.signature =
        arkret_wire::Base64UrlString::new(arkret_canonical::base64url_encode(
            ed25519_dalek::SigningKey::from_bytes(seed)
                .sign(&proof.signing_payload_bytes().unwrap())
                .to_bytes(),
        ))
        .unwrap();
}

async fn consume(
    pool: &PgPool,
    reader: &coland_storage::HumanPcrHistoryReader,
    proof: &KeyBackupUnlockProof,
    package: &KeyBackup,
) -> coland_storage::PersistenceResult<serde_json::Value> {
    let persistence = PgPersistenceStore::new(pool.clone());
    let digest = arkret_canonical::canonical_sha256(&KeysBackupsUnlockRequestBody {
        proof: proof.clone(),
    })
    .unwrap();
    persistence
        .key_backups()
        .consume_unlock(KeyBackupUnlockCommand {
            basis: &KeyBackupUnlockBasis::CurrentHumanPcrHistory {
                reader: Box::new(reader.clone()),
                proof: Box::new(proof.clone()),
            },
            authority_id: match &proof.authority {
                KeyBackupUnlockAuthority::CurrentDevice { challenge_id, .. } => {
                    challenge_id.as_str()
                }
                _ => unreachable!(),
            },
            backup: serde_json::to_value(package).unwrap(),
            request_digest: &digest,
            holder: "authenticated-session:jkt",
            ip: "127.0.0.241",
            now: chrono::Utc::now(),
            // Historical reads are not subject to the ordinary object/day bucket.
            daily_limit: 0,
        })
        .await
}

pub(super) async fn exercise(
    pool: &PgPool,
    fixture: &mut RootFixture,
    package: &KeyBackup,
    original: &coland_storage::AuthorityCommitTransaction,
    genesis: &coland_storage::AuthorityCommitTransaction,
) -> (ContentRootBackupEntry, arkret_wire::BackupId) {
    let record = pcr_history_tests::status(pool, fixture, None).await;
    let reader = pcr_history_tests::reader(fixture, Some(record));
    let persistence = PgPersistenceStore::new(pool.clone());
    let store = persistence.key_backups();
    recovery_source::refuse_ordinary(pool, &reader).await;
    let now = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    let challenge = KeysBackupsUnlockChallenge {
        challenge_id: random(),
        challenge: random(),
        nonce: random(),
        operation: arkret_wire::ServiceOperationId::SELF_KEYS_BACKUPS_COMMAND_UNLOCK_V1.into(),
        account_id: fixture.pcr.history.account.clone(),
        requesting_device_id: reader.device_id.clone(),
        backup_id: package.backup_id.clone(),
        series_id: package.series_id.clone(),
        ciphertext_digest: package.ciphertext_digest.clone(),
        audience: arkret_wire::NonEmptyString::new("https://backup-test.example").unwrap(),
        service_id: reader.account_id.station_id.clone(),
        request_id: random(),
        issued_at: now,
        expires_at: now + chrono::Duration::seconds(300),
        subject_actor_id: None,
        custody_authorization_ref: None,
        content_history: Some(ContentHistoryBackupAccess {
            source: CommittedEventRef {
                event_id: original.event.event_id.clone(),
                commit_id: original.commit.commit_id.clone(),
                stream_ref: original.commit.stream_ref.clone(),
                stream_position: original.commit.stream_position,
            },
            root_refs: vec![package.contents[0].root_ref.clone().unwrap()],
        }),
    };
    let issued = store
        .issue_human_pcr_history_unlock_challenge(&reader, &challenge)
        .await
        .unwrap();
    assert_eq!(
        serde_json::to_value(&issued).unwrap(),
        serde_json::to_value(&challenge).unwrap()
    );
    let mut retry = challenge.clone();
    retry.challenge_id = random();
    retry.challenge = random();
    retry.nonce = random();
    assert_eq!(
        serde_json::to_value(
            store
                .issue_human_pcr_history_unlock_challenge(&reader, &retry)
                .await
                .unwrap()
        )
        .unwrap(),
        serde_json::to_value(&challenge).unwrap()
    );
    let mut changed = retry;
    changed.content_history.as_mut().unwrap().root_refs[0] =
        arkret_wire::Hash::new(format!("sha256:{}", "ab".repeat(32))).unwrap();
    let conflict = store
        .issue_human_pcr_history_unlock_challenge(&reader, &changed)
        .await
        .unwrap_err();
    assert!(
        conflict.to_string().contains("duplicate_conflict"),
        "{conflict}"
    );
    let mut changed_source = challenge.clone();
    changed_source
        .content_history
        .as_mut()
        .unwrap()
        .source
        .stream_ref = arkret_wire::CommitStreamRef::Realm {
        realm_id: arkret_wire::RealmId::from_event_id(&original.event.event_id),
    };
    let conflict = store
        .issue_human_pcr_history_unlock_challenge(&reader, &changed_source)
        .await
        .unwrap_err();
    assert!(
        conflict.to_string().contains("duplicate_conflict"),
        "{conflict}"
    );
    let valid = proof(&issued, fixture);
    assert!(
        store
            .human_pcr_history_unlock_delivery(&reader, &valid, "authenticated-session:jkt")
            .await
            .is_err()
    );
    for mutation in ["source", "root", "nonce", "subject", "signature"] {
        let mut bad = valid.clone();
        match mutation {
            "source" => bad.content_history.as_mut().unwrap().source.stream_position += 1,
            "root" => {
                bad.content_history.as_mut().unwrap().root_refs[0] =
                    arkret_wire::Hash::new(format!("sha256:{}", "ab".repeat(32))).unwrap()
            }
            "nonce" => {
                if let KeyBackupUnlockAuthority::CurrentDevice { nonce, .. } = &mut bad.authority {
                    *nonce = random();
                }
            }
            "subject" => {
                bad.subject_actor_id =
                    Some(arkret_wire::ActorId::account(reader.account_id.clone()));
                bad.custody_authorization_ref =
                    Some(fixture.pcr.history.events[0].event_id.clone());
            }
            "signature" => (),
            _ => unreachable!(),
        }
        if mutation != "signature" {
            sign(&mut bad);
        } else {
            bad.signature_proof.signature = random();
        }
        assert!(
            consume(pool, &reader, &bad, package).await.is_err(),
            "{mutation}"
        );
    }
    let mut rebound = reader.clone();
    rebound
        .credential_device_binding
        .as_mut()
        .unwrap()
        .authorization_event_id = original.event.event_id.clone();
    assert!(consume(pool, &rebound, &valid, package).await.is_err());
    let mut expired = reader.clone();
    expired.credential_expires_at = now - chrono::Duration::seconds(1);
    assert!(consume(pool, &expired, &valid, package).await.is_err());
    assert_eq!(
        consume(pool, &reader, &valid, package).await.unwrap(),
        serde_json::to_value(package).unwrap()
    );
    // A new port instance and the same exact proof reuse the durable result.
    assert_eq!(
        consume(pool, &reader, &valid, package).await.unwrap(),
        serde_json::to_value(package).unwrap()
    );
    assert!(
        store
            .human_pcr_history_unlock_delivery(&reader, &valid, "different-session:jkt")
            .await
            .is_err()
    );
    let (delivered, guard) = store
        .human_pcr_history_unlock_delivery(&reader, &valid, "authenticated-session:jkt")
        .await
        .unwrap();
    assert_eq!(&delivered, package);
    assert!(guard.permits_handoff());
    guard.finish().await.unwrap();
    let mut successor = fixture.policy.clone();
    successor.policy_id =
        arkret_wire::PolicyId::new(format!("ak:policy:{}", uuid::Uuid::now_v7())).unwrap();
    successor.supersedes_id = Some(fixture.policy.policy_id.clone());
    successor.version += 1;
    fixture.policy = RootFixture::publish(&persistence, &mut fixture.pcr, successor).await;
    let (retained, guard) = store
        .human_pcr_history_unlock_delivery(&reader, &valid, "authenticated-session:jkt")
        .await
        .unwrap();
    assert_eq!(retained, delivered);
    guard.finish().await.unwrap();
    let device = Box::pin(fixture.pcr.admit_accepted_device(&persistence, [121; 32]))
        .await
        .unwrap();
    let mut new_reader = reader.clone();
    new_reader.device_id = arkret_wire::DeviceId::new(device.authorization.device_id).unwrap();
    new_reader.credential_device_binding = Some(
        arkret_models_identity::session_credential::SessionGrantDeviceBinding {
            device_id: new_reader.device_id.clone(),
            authorization_event_id: device.authorization.authorization_ref.event_id,
            model_generation_ref: 1,
        },
    );
    let mut new_challenge = challenge;
    new_challenge.requesting_device_id = new_reader.device_id.clone();
    new_challenge.request_id = random();
    new_challenge.challenge_id = random();
    new_challenge.challenge = random();
    new_challenge.nonce = random();
    let new_challenge = store
        .issue_human_pcr_history_unlock_challenge(&new_reader, &new_challenge)
        .await
        .unwrap();
    let mut new_proof = proof(&new_challenge, fixture);
    new_proof.signature_proof.verification_method = device.verification_method;
    sign_with(&mut new_proof, &device.signing_seed);
    assert_eq!(
        consume(pool, &new_reader, &new_proof, package)
            .await
            .unwrap(),
        serde_json::to_value(package).unwrap()
    );
    let (new_device_original, mut guard) = store
        .human_pcr_history_unlock_delivery(&new_reader, &new_proof, "authenticated-session:jkt")
        .await
        .unwrap();
    assert_eq!(new_device_original, delivered);
    assert!(guard.prepare_handoff().await);
    guard.finish().await.unwrap();
    // Fresh, individually authenticated reads cross both the ordinary 4/minute
    // IP limit and the 64/day object bucket. Outstanding challenges stay bounded.
    for index in 0..65 {
        let mut fresh = new_challenge.clone();
        fresh.challenge_id = random();
        fresh.challenge = random();
        fresh.nonce = random();
        fresh.request_id = random();
        fresh.issued_at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
        fresh.expires_at = fresh.issued_at + chrono::Duration::seconds(300);
        let issued = store
            .issue_human_pcr_history_unlock_challenge(&new_reader, &fresh)
            .await
            .unwrap();
        let mut signed = proof(&issued, fixture);
        signed.signature_proof.verification_method =
            new_proof.signature_proof.verification_method.clone();
        sign_with(&mut signed, &device.signing_seed);
        consume(pool, &new_reader, &signed, package)
            .await
            .unwrap_or_else(|error| panic!("history read {index}: {error}"));
    }
    // A consumed result is never a lease around a changed current Device cut.
    assert!(
        store
            .human_pcr_history_unlock_delivery(&rebound, &valid, "authenticated-session:jkt")
            .await
            .is_err()
    );
    let (replacement, authorization, method, seed, _session_id) =
        Box::pin(claim_fence::recover(pool, fixture)).await;
    assert!(consume(pool, &reader, &valid, package).await.is_err());
    assert!(
        consume(pool, &new_reader, &new_proof, package)
            .await
            .is_err()
    );
    assert!(
        store
            .human_pcr_history_unlock_delivery(&new_reader, &new_proof, "authenticated-session:jkt")
            .await
            .is_err()
    );
    assert!(
        store
            .issue_human_pcr_history_unlock_challenge(&new_reader, &new_challenge)
            .await
            .is_err()
    );
    assert!(
        store
            .put(
                package.backup_id.to_string(),
                serde_json::to_value(package).unwrap()
            )
            .await
            .is_err()
    );
    let mut replacement_reader = new_reader;
    replacement_reader.device_id = replacement.clone();
    replacement_reader.credential_device_binding = Some(
        arkret_models_identity::session_credential::SessionGrantDeviceBinding {
            device_id: replacement.clone(),
            authorization_event_id: authorization,
            model_generation_ref: 2,
        },
    );
    recovery_source::exercise(pool, &replacement_reader, &reader).await;
    history_material::exercise(pool, &replacement_reader, &reader, genesis).await;
    let mut replacement_challenge = new_challenge;
    replacement_challenge.requesting_device_id = replacement;
    replacement_challenge.request_id = random();
    replacement_challenge.challenge_id = random();
    replacement_challenge.challenge = random();
    replacement_challenge.nonce = random();
    replacement_challenge.issued_at =
        arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    replacement_challenge.expires_at =
        replacement_challenge.issued_at + chrono::Duration::seconds(300);
    let replacement_challenge = store
        .issue_human_pcr_history_unlock_challenge(&replacement_reader, &replacement_challenge)
        .await
        .unwrap();
    let mut replacement_proof = proof(&replacement_challenge, fixture);
    replacement_proof.signature_proof.verification_method = method;
    sign_with(&mut replacement_proof, &seed);
    assert_eq!(
        consume(pool, &replacement_reader, &replacement_proof, package)
            .await
            .unwrap(),
        serde_json::to_value(package).unwrap()
    );
    let (after_recovery, guard) = store
        .human_pcr_history_unlock_delivery(
            &replacement_reader,
            &replacement_proof,
            "authenticated-session:jkt",
        )
        .await
        .unwrap();
    assert_eq!(after_recovery, new_device_original);
    guard.finish().await.unwrap();
    let recovered = arkret_crypto::identity_root::derive_identity_recovery_key_material_from_bip39(
        fixture
            .recovery_words
            .as_deref()
            .expect("fresh same-bundle recovery words"),
        "",
        1,
    )
    .unwrap();
    let author = fixture.pcr.history.events[1]
        .payload
        .get("device_public_key_did")
        .unwrap()
        .as_str()
        .unwrap();
    let author = arkret_canonical::multibase::decode_ed25519_multibase(
        author.strip_prefix("did:key:").unwrap(),
    )
    .unwrap();
    let bag = arkret_crypto::content_history::open_content_root_backup(
        &after_recovery,
        &recovered.backup_hpke_serialized_private_key,
        |bytes, signature| {
            if arkret_signatures::verify_detached_ed25519_signature(
                &arkret_signatures::PublicKeyMaterial::Ed25519Raw {
                    bytes: author.to_vec(),
                },
                bytes,
                signature.signature.as_str(),
            ) {
                Ok(())
            } else {
                Err(arkret_crypto::Error::Protocol(
                    "original signature differs".into(),
                ))
            }
        },
    )
    .unwrap();
    assert_eq!(bag.items.len(), 1);
    let result = Box::pin(root_rotation::exercise(
        pool,
        fixture,
        &replacement_reader,
        &replacement_proof,
        &seed,
        &after_recovery,
        &bag,
    ))
    .await;
    // Current factor revocation and recipient rotation do not invalidate the
    // original completed identity unit used for this replacement episode.
    recovery_source::require_source(pool, &replacement_reader).await;
    result
}
