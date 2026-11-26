//! Signed/encrypted packets use the real admitted Human Device and policy.
//! This exercises backup storage, not acceptance of the referenced Realm Event.
use arkret::crypto::{backup, content_history};
use arkret_models_crypto::{
    BackupKind, KeyBackup, KeyBackupSignatureAlgorithm, SecretStorageItemKind,
};
use arkret_wire::{ActorId, BackupId, BackupSeriesId, Base64UrlString, Hash};
use coland_storage::IdentityStoreRegistry as _;
use coland_test_support::agent_origin::OriginFixture;
use ed25519_dalek::{Signer as _, SigningKey};

use super::*;

async fn active_holder_fixture() -> OriginFixture {
    let fixture = Box::pin(OriginFixture::new()).await;
    let persistence = crate::PgPersistenceStore::new(fixture.pool.clone());
    let owner = &fixture.controller.history.account;
    // Genuine PCR/Device/policy admission is already complete. Its hosting
    // Account projection is a separate owner-private storage prerequisite.
    persistence
        .accounts()
        .put(&coland_storage::AccountRecord {
            pk: coland_storage::AccountPk(0),
            principal_id: owner.principal_id.clone(),
            station_id: owner.station_id.clone(),
            localpart: String::new(),
            display_name: None,
            biography: None,
            avatar_blob_ref: None,
            created_at: fixture.controller.history.commits[0].committed_at,
        })
        .await
        .unwrap();
    fixture
}

#[derive(QueryableByName)]
struct RootIndexRow {
    #[diesel(sql_type=Jsonb)]
    content_index: Value,
}

fn author(fixture: &OriginFixture) -> backup::KeyBackupAuthorizationBinding {
    backup::KeyBackupAuthorizationBinding {
        device_id: fixture.controller.history.founding_device_id.clone(),
        verification_method: fixture
            .controller
            .history
            .device_verification_method
            .clone(),
        signature_algorithm: KeyBackupSignatureAlgorithm::Ed25519,
        device_authorize_event_id: fixture.controller.history.events[1].event_id.clone(),
    }
}

fn private_packet(fixture: &OriginFixture) -> KeyBackup {
    let key = SigningKey::from_bytes(&fixture.controller.history.founding_device_signing_seed);
    let kek = backup::derive_vault_kek(b"storage-index-regression-passphrase").unwrap();
    let items = [
        (
            SecretStorageItemKind::RecoveryKeyShare,
            "private_recovery_name",
        ),
        (
            SecretStorageItemKind::PrivateAccountState,
            "private_account_name",
        ),
    ]
    .into_iter()
    .map(
        |(item_kind, secret_id)| arkret_models_crypto::SecretStorageSecret {
            item_kind,
            secret_id: secret_id.into(),
            secret_base64url: Base64UrlString::new(arkret_canonical::base64url_encode([41; 32]))
                .unwrap(),
            secret_generation: Some(1),
            extra: Default::default(),
        },
    )
    .collect();
    backup::build_key_backup_envelope(
        BackupId::new(format!("ak:backup:{}", uuid::Uuid::now_v7())).unwrap(),
        ActorId::account(fixture.controller.history.account.clone()),
        Some(fixture.controller.history.founding_device_id.clone()),
        BackupKind::SecretStorage,
        "kb_private_index",
        "secret_storage",
        &kek,
        items,
        &author(fixture),
        &|bytes| Ok(key.sign(bytes).to_bytes().to_vec()),
    )
    .unwrap()
}

fn root_packet(fixture: &OriginFixture) -> KeyBackup {
    let sample:Value=serde_json::from_str(include_str!("../../../../../arkret-spec/spec/v1/artifacts/fixtures/realm-actor-content-backup-fixture.json")).unwrap();
    let context: arkret_models_crypto::ContentRootContext =
        serde_json::from_value(sample["native_packet"]["contents"][0]["root_context"].clone())
            .unwrap();
    let root_base64url = arkret_models_crypto::ContentRootSecret::new([43; 32]);
    let root_ref = content_history::content_root_ref(&root_base64url, &context).unwrap();
    let material =
        arkret::identity_root::derive_identity_recovery_key_material(&[149; 32], 0).unwrap();
    let key = SigningKey::from_bytes(&fixture.controller.history.founding_device_signing_seed);
    content_history::ContentRootBackupDraft {
        backup_id: BackupId::new(format!("ak:backup:{}", uuid::Uuid::now_v7())).unwrap(),
        actor_id: ActorId::account(fixture.controller.history.account.clone()),
        created_at: arkret_canonical::normalize_timestamp_canonical(Utc::now()),
        expires_at: None,
        author: content_history::ContentRootBackupAuthor::Device {
            binding: author(fixture),
            source: arkret_models_crypto::KeyBackupSourceCommitRef {
                realm_commit_id: fixture.controller.history.commits[1].commit_id.clone(),
                device_generation_ref: 1,
            },
        },
        recipient_key_ref: fixture.history_custody.recipient_key_ref.to_string(),
        recovery_policy_ref: fixture.history_custody.recovery_policy_ref.clone(),
        domain_separation: arkret_models_crypto::KeyBackupDomainSeparation {
            subdomain: "key_backup".into(),
            aead_aad_extensions: Default::default(),
        },
        series_id: BackupSeriesId::new(format!("ak:backup_series:{}", uuid::Uuid::now_v7()))
            .unwrap(),
        series_sequence: 0,
        supersedes: None,
        custody: None,
    }
    .seal(
        vec![arkret_models_crypto::ContentRootBackupEntry {
            item_kind: arkret_models_crypto::ContentRootItemKind::ContentEpochRoot,
            secret_id: "root_original".into(),
            root_context: context,
            root_ref,
            root_base64url,
        }],
        &material.backup_hpke_public_key,
        |bytes| Ok(key.sign(bytes).to_bytes().to_vec()),
    )
    .unwrap()
}

async fn index(pool: &PgPool, packet: &KeyBackup) -> Value {
    let mut conn = pool.get().await.unwrap();
    sql_query("SELECT content_index FROM key_backup_identities WHERE id=$1")
        .bind::<sql_types::Uuid, _>(ids::typed_uuid_part_expect_internal(
            packet.backup_id.as_str(),
        ))
        .get_result::<RootIndexRow>(&mut *conn)
        .await
        .unwrap()
        .content_index
}

async fn retained_root_rows(pool: &PgPool, packet: &KeyBackup) -> Value {
    let mut conn = pool.get().await.unwrap();
    sql_query("SELECT jsonb_build_object('body',to_jsonb(b),'identity',to_jsonb(i)) AS payload FROM key_backups b JOIN key_backup_identities i USING(id) WHERE b.id=$1")
        .bind::<sql_types::Uuid, _>(ids::typed_uuid_part_expect_internal(packet.backup_id.as_str()))
        .get_result::<crate::JsonPayloadRow>(&mut *conn)
        .await
        .unwrap()
        .payload
}

#[tokio::test]
async fn real_private_packet_never_duplicates_secret_names_in_retained_identity() {
    let fixture = Box::pin(active_holder_fixture()).await;
    let packet = private_packet(&fixture);
    packet.validate().unwrap();
    packet.validate_ciphertext_digest().unwrap();
    assert_eq!(packet.contents.len(), 2);
    let store = PgKeyBackupStore {
        pool: fixture.pool.clone(),
    };
    store
        .put(
            packet.backup_id.to_string(),
            serde_json::to_value(&packet).unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(index(&fixture.pool, &packet).await, serde_json::json!([]));
    let mut conn = fixture.pool.get().await.unwrap();
    let retained =
        crate::content_root_packages::read_retained_envelope(&mut conn, &packet.backup_id)
            .await
            .unwrap();
    assert_eq!(
        serde_json::to_value(retained).unwrap(),
        serde_json::to_value(&packet).unwrap()
    );
    drop(conn);
    assert!(store.delete(packet.backup_id.as_str()).await.unwrap());
    assert_eq!(index(&fixture.pool, &packet).await, serde_json::json!([]));
    let mut conn = fixture.pool.get().await.unwrap();
    assert!(
        crate::content_root_packages::read_retained_envelope(&mut conn, &packet.backup_id)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn signed_root_index_keeps_exact_items_and_refuses_wrong_root_or_deleted_body() {
    let fixture = Box::pin(active_holder_fixture()).await;
    let packet = root_packet(&fixture);
    let store = PgKeyBackupStore {
        pool: fixture.pool.clone(),
    };
    store
        .put(
            packet.backup_id.to_string(),
            serde_json::to_value(&packet).unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        index(&fixture.pool, &packet).await,
        serde_json::to_value(&packet.contents).unwrap()
    );
    let mut conn = fixture.pool.get().await.unwrap();
    let original =
        crate::content_root_packages::original_index_in_connection(&mut conn, &packet.backup_id)
            .await
            .unwrap();
    assert_eq!(
        original.roots[0].0,
        packet.contents[0].root_ref.clone().unwrap()
    );
    let context = packet.contents[0].root_context.as_ref().unwrap();
    assert!(
        crate::content_root_packages::require_original_binding(
            &mut conn,
            std::slice::from_ref(&packet.backup_id),
            &packet.actor_id,
            &Hash::new(arkret_canonical::sha256_digest(b"wrong-root")).unwrap(),
            context
        )
        .await
        .is_err()
    );
    let mut wrong = serde_json::to_value(&packet.contents).unwrap();
    wrong[0]["root_ref"] = serde_json::json!(arkret_canonical::sha256_digest(b"wrong-root"));
    sql_query("UPDATE key_backup_identities SET content_index=$2 WHERE id=$1")
        .bind::<sql_types::Uuid, _>(ids::typed_uuid_part_expect_internal(
            packet.backup_id.as_str(),
        ))
        .bind::<Jsonb, _>(wrong)
        .execute(&mut *conn)
        .await
        .unwrap();
    assert!(
        crate::content_root_packages::read_retained_envelope(&mut conn, &packet.backup_id)
            .await
            .is_err()
    );
    sql_query("UPDATE key_backup_identities SET content_index=$2 WHERE id=$1")
        .bind::<sql_types::Uuid, _>(ids::typed_uuid_part_expect_internal(
            packet.backup_id.as_str(),
        ))
        .bind::<Jsonb, _>(serde_json::to_value(&packet.contents).unwrap())
        .execute(&mut *conn)
        .await
        .unwrap();
    crate::content_root_packages::read_retained_envelope(&mut conn, &packet.backup_id)
        .await
        .unwrap();
    drop(conn);
    // First prove ordinary deletion preserves the only sufficient root.
    let before_delete = retained_root_rows(&fixture.pool, &packet).await;
    assert_eq!(
        store
            .delete(packet.backup_id.as_str())
            .await
            .unwrap_err()
            .conflict_code(),
        Some(coland_storage::ConflictCode::FailedPrecondition)
    );
    assert_eq!(
        retained_root_rows(&fixture.pool, &packet).await,
        before_delete
    );

    // A new original packet really retains this same root for the current policy.
    let replacement = root_packet(&fixture);
    assert_ne!(replacement.backup_id, packet.backup_id);
    assert_eq!(replacement.actor_id, packet.actor_id);
    assert_eq!(replacement.contents, packet.contents);
    assert_eq!(replacement.recovery_policy_ref, packet.recovery_policy_ref);
    assert_eq!(
        replacement.encryption.recipient_key_ref,
        packet.encryption.recipient_key_ref
    );
    let material =
        arkret::identity_root::derive_identity_recovery_key_material(&[149; 32], 0).unwrap();
    let signer = SigningKey::from_bytes(&fixture.controller.history.founding_device_signing_seed);
    let mut opened = content_history::open_content_root_backup(
        &replacement,
        &material.backup_hpke_serialized_private_key,
        |bytes, proof| {
            assert!(arkret_signatures::verify_detached_ed25519_signature(
                &arkret_signatures::PublicKeyMaterial::Ed25519Raw {
                    bytes: signer.verifying_key().to_bytes().to_vec(),
                },
                bytes,
                proof.signature.as_str(),
            ));
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(opened.items.len(), 1);
    let arkret_models_crypto::SecretStorageEntry::ContentRoot(root) = opened.items.remove(0) else {
        panic!("the actual replacement must open its original content root")
    };
    assert_eq!(root.root_context, *context);
    assert_eq!(
        content_history::content_root_ref(&root.root_base64url, &root.root_context).unwrap(),
        original.roots[0].0
    );
    store
        .put(
            replacement.backup_id.to_string(),
            serde_json::to_value(&replacement).unwrap(),
        )
        .await
        .unwrap();
    let mut conn = fixture.pool.get().await.unwrap();
    let retained = crate::content_root_packages::read_in_connection(
        &mut conn,
        &replacement.backup_id,
        &[original.roots[0].0.to_string()],
    )
    .await
    .map_err(crate::PgTransactionError::into_persistence)
    .unwrap();
    assert_eq!(retained.roots, original.roots);
    retained.require_current_recipient(&mut conn).await.unwrap();
    drop(conn);
    assert!(store.delete(packet.backup_id.as_str()).await.unwrap());
    let mut conn = fixture.pool.get().await.unwrap();
    assert!(
        crate::content_root_packages::read_retained_envelope(&mut conn, &packet.backup_id)
            .await
            .is_err()
    );
    assert_eq!(
        crate::content_root_packages::original_index_in_connection(&mut conn, &packet.backup_id)
            .await
            .unwrap()
            .roots,
        original.roots
    );
    crate::content_root_packages::require_original_binding(
        &mut conn,
        std::slice::from_ref(&packet.backup_id),
        &packet.actor_id,
        &original.roots[0].0,
        &original.roots[0].1,
    )
    .await
    .unwrap();
    drop(conn);

    // The surviving replacement is now the last sufficient package itself.
    let replacement_before = retained_root_rows(&fixture.pool, &replacement).await;
    assert_eq!(
        store
            .delete(replacement.backup_id.as_str())
            .await
            .unwrap_err()
            .conflict_code(),
        Some(coland_storage::ConflictCode::FailedPrecondition)
    );
    assert_eq!(
        retained_root_rows(&fixture.pool, &replacement).await,
        replacement_before
    );
    let mut conn = fixture.pool.get().await.unwrap();
    let remaining =
        crate::content_root_packages::read_retained_envelope(&mut conn, &replacement.backup_id)
            .await
            .unwrap();
    assert_eq!(
        serde_json::to_value(remaining).unwrap(),
        serde_json::to_value(&replacement).unwrap()
    );
}

#[tokio::test]
async fn genuinely_signed_root_and_private_mixture_keeps_the_original_zero_write_refusal() {
    let fixture = Box::pin(active_holder_fixture()).await;
    let mut packet = root_packet(&fixture);
    packet
        .contents
        .push(private_packet(&fixture).contents.remove(0));
    let key = SigningKey::from_bytes(&fixture.controller.history.founding_device_signing_seed);
    // The validated signing API deliberately refuses this malformed mixture.
    // Sign its exact JCS preimage only to show that valid Ed bytes grant no bypass.
    let mut unsigned = serde_json::to_value(&packet).unwrap();
    unsigned["signature_proof"]
        .as_object_mut()
        .unwrap()
        .remove("signature");
    let transcript = arkret_canonical::canonical_json_bytes(&unsigned).unwrap();
    packet.signature_proof.signature = Base64UrlString::new(arkret_canonical::base64url_encode(
        key.sign(&transcript).to_bytes(),
    ))
    .unwrap();
    assert!(arkret_signatures::verify_detached_ed25519_signature(
        &arkret_signatures::PublicKeyMaterial::Ed25519Raw {
            bytes: key.verifying_key().to_bytes().to_vec()
        },
        &transcript,
        packet.signature_proof.signature.as_str()
    ));
    assert!(packet.validate().is_err());
    let store = PgKeyBackupStore {
        pool: fixture.pool.clone(),
    };
    assert!(
        store
            .put(
                packet.backup_id.to_string(),
                serde_json::to_value(&packet).unwrap()
            )
            .await
            .is_err()
    );
    assert!(
        store
            .get(packet.backup_id.as_str())
            .await
            .unwrap()
            .is_none()
    );
    let mut conn = fixture.pool.get().await.unwrap();
    assert!(
        sql_query("SELECT content_index FROM key_backup_identities WHERE id=$1")
            .bind::<sql_types::Uuid, _>(ids::typed_uuid_part_expect_internal(
                packet.backup_id.as_str()
            ))
            .get_result::<RootIndexRow>(&mut *conn)
            .await
            .optional()
            .unwrap()
            .is_none()
    );
}
