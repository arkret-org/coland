//! Storage retention fixtures seed a preexisting coverage relationship. They
//! exercise production delete/PUT ports with real PCR/policy admission and
//! correctly sealed root blocks, not the original-to-coverage admission unit.

use coland_storage::{ConflictCode, IdentityStoreRegistry as _, PersistenceStore as _};
use diesel::sql_types::{Jsonb, Text};
use horme::RunQueryDsl as _;

#[derive(diesel::QueryableByName)]
struct CoverageRow {
    #[diesel(sql_type=Jsonb)]
    coverage: Value,
}

#[tokio::test]
async fn pcr_control_coverage_starts_at_genesis_without_mls_activation() {
    let database = database().await;
    let fixture = RootFixture::new(database.pool()).await;
    let mut conn = database.pool().get().await.unwrap();
    for (event, commit) in fixture
        .pcr
        .history
        .events
        .iter()
        .zip(&fixture.pcr.history.commits)
    {
        let row = diesel::sql_query("SELECT coverage FROM content_originals WHERE event_id=$1 AND commit_id=$2 AND retain_full_history=true")
            .bind::<Text,_>(event.event_id.as_str()).bind::<Text,_>(commit.commit_id.as_str())
            .get_result::<CoverageRow>(&mut *conn).await.unwrap();
        let coverage: arkret_models_crypto::ContentCoverageEntry =
            serde_json::from_value(row.coverage).unwrap();
        assert_eq!(coverage.source.event_id, event.event_id);
        assert_eq!(coverage.source.commit_id, commit.commit_id);
        assert_eq!(coverage.source.stream_position, commit.stream_position);
        assert!(coverage.root_refs.is_empty() && coverage.blob_refs.is_empty());
    }
}

#[tokio::test]
async fn pcr_profile_blob_dependency_is_atomic_and_cannot_be_purged_or_rebound() {
    let database = database().await;
    let fixture = RootFixture::new(database.pool()).await;
    let persistence = Arc::new(PgPersistenceStore::new(database.pool()));
    let authority = crate::authority_commit::AuthorityCommitApplication::new(
        crate::persistence::PersistenceHandle::new(persistence.clone()),
        64,
    );
    let digest = arkret_canonical::sha256_digest(b"retained profile avatar");
    let reference = format!("ak:blob:{digest}");
    let payload: arkret_models_collaboration::events_payloads::ActorProfileCreatePayload = serde_json::from_value(json!({"object":{
        "principal_id":fixture.pcr.history.account.principal_id,"actor_kind":"user","display_name":"Recovery fixture","avatar_blob_ref":reference
    }})).unwrap();
    let event = fixture.pcr.history.event(
        arkret_wire::EventKind::ProfileCreate,
        serde_json::to_value(payload).unwrap(),
    );
    let at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    let fact = authority
        .prepare_account_device_signer_fact(&event, at)
        .await
        .unwrap()
        .map(Into::into);
    // PCR originals use the separately registered native control provenance;
    // the ordinary Realm account-device source carrier does not apply here.
    assert!(fact.is_none());
    let stream = arkret_wire::CommitStreamRef::Realm {
        realm_id: event.realm_id.clone(),
    };
    let head = persistence
        .authority_commits()
        .stream_head(&stream)
        .await
        .unwrap();
    let expected = fixture.pcr.unit.transactions[1].expected_authority.clone();
    let commit = authority
        .sign_event_commit_at_authority_cut(
            &event,
            &expected,
            head.as_ref(),
            fixture.pcr.history.authority_method(),
            &SigningKey::from_bytes(&device_authorization_history::STATION_AUTHORITY_SEED),
            at,
            fact.as_ref(),
        )
        .unwrap();
    let transaction = AuthorityCommitTransaction {
        expected_authority: expected,
        event: event.clone(),
        commit: commit.clone(),
        producer_signer_fact: fact,
        mls_state: None,
        welcomes: vec![],
        recipient_queue_capacity: 0,
    };
    let write = coland_storage::ActorProfileAdmissionWrite {
        commit: transaction,
        queued_at: at,
    };
    let missing_blob = persistence
        .actor_profiles()
        .admit_profile(write.clone())
        .await
        .unwrap_err();
    assert_eq!(
        missing_blob.conflict_code(),
        Some(ConflictCode::FailedPrecondition),
        "unexpected admission failure: {missing_blob:?}"
    );
    assert!(
        persistence
            .authority_commits()
            .committed_event(&event.event_id)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        persistence
            .authority_commits()
            .stream_head(&stream)
            .await
            .unwrap(),
        head
    );
    let record = coland_storage::BlobRecord {
        sha256: digest.trim_start_matches("sha256:").into(),
        size_bytes: 23,
        storage_backend: "local".into(),
        storage_key: "retained-profile-fixture".into(),
        media_type: "application/octet-stream".into(),
        filename: None,
        realm_id: Some(event.realm_id.to_string()),
        encryption: None,
        legal_hold: false,
        redacted: false,
        visibility: arkret_models_collaboration::objects::blob::BlobVisibility::ActorPrivate,
        uploaded_by: event.actor_id.to_string(),
        created_at: at,
    };
    persistence
        .blobs()
        .put_if_absent(&reference, &record)
        .await
        .unwrap();
    assert!(matches!(
        persistence
            .actor_profiles()
            .admit_profile(write)
            .await
            .unwrap(),
        coland_storage::ActorProfileAdmissionOutcome::Committed(_)
    ));
    let mut conn = database.pool().get().await.unwrap();
    let coverage = diesel::sql_query(
        "SELECT coverage FROM content_originals WHERE event_id=$1 AND retain_full_history=true",
    )
    .bind::<Text, _>(event.event_id.as_str())
    .get_result::<CoverageRow>(&mut *conn)
    .await
    .unwrap();
    let coverage: arkret_models_crypto::ContentCoverageEntry =
        serde_json::from_value(coverage.coverage).unwrap();
    assert_eq!(
        coverage.blob_refs,
        vec![arkret_wire::BlobRef::new(reference.clone()).unwrap()]
    );
    drop(conn);
    assert_eq!(
        persistence
            .blobs()
            .delete(&reference)
            .await
            .unwrap_err()
            .conflict_code(),
        Some(ConflictCode::FailedPrecondition)
    );
    let mut redacted = record.clone();
    redacted.redacted = true;
    assert!(
        persistence
            .blobs()
            .put(&reference, &redacted)
            .await
            .is_err()
    );
    let mut changed = record.clone();
    changed.sha256 = "00".repeat(32);
    assert!(persistence.blobs().put(&reference, &changed).await.is_err());
    let held = persistence.blobs().get(&reference).await.unwrap().unwrap();
    assert_eq!(held.sha256, record.sha256);
    assert!(!held.redacted);
}

use super::*;

fn sealed(mut package: KeyBackup) -> KeyBackup {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../../../../arkret-spec/spec/v1/artifacts/fixtures/content-history-fixture.json"
    ))
    .unwrap();
    let mut bag: arkret_models_crypto::KeyBackupPlaintext =
        serde_json::from_value(fixture["root_backup"]["plaintext"].clone()).unwrap();
    bag.backup_id = package.backup_id.clone();
    bag.series_id = package.series_id.clone();
    bag.series_sequence = package.series_sequence;
    let reference = package.encryption.recipient_key_ref.as_deref().unwrap();
    let encoded = reference
        .strip_prefix("did:key:")
        .unwrap()
        .split('#')
        .next()
        .unwrap();
    let public = arkret_canonical::decode_multibase_base58btc(encoded).unwrap();
    assert_eq!(&public[..2], &[0xec, 0x01]);
    package.contents = bag.items.iter().map(|item| item.content_index()).collect();
    arkret_crypto::content_history::seal_content_root_backup(package, &bag, &public[2..], |bytes| {
        Ok(SigningKey::from_bytes(&[81; 32])
            .sign(bytes)
            .to_bytes()
            .to_vec())
    })
    .unwrap()
}

async fn seed_retained_original(pool: &PgPool, fixture: &RootFixture, package: &KeyBackup) {
    let source = &fixture.pcr.history.commits[0];
    let root = &package.contents[0];
    let coverage = arkret_models_crypto::ContentCoverageEntry {
        source: arkret_wire::CommittedEventRef {
            event_id: source.event_ref.clone(),
            commit_id: source.commit_id.clone(),
            stream_ref: source.stream_ref.clone(),
            stream_position: source.stream_position,
        },
        root_refs: vec![root.root_ref.clone().unwrap()],
        blob_refs: vec![],
    };
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query("INSERT INTO content_originals(event_id,event_pk,commit_id,scope_key,coverage,retain_full_history) SELECT $1,c.event_pk,c.commit_id,$3,$4,true FROM realm_commits c WHERE c.commit_id=$2 ON CONFLICT(event_id) DO UPDATE SET coverage=EXCLUDED.coverage")
        .bind::<Text,_>(source.event_ref.as_str()).bind::<Text,_>(source.commit_id.as_str())
        .bind::<Text,_>(arkret_canonical::canonical_json_string(&fixture.pcr.history.events[0].scope_ref).unwrap())
        .bind::<Jsonb,_>(serde_json::to_value(coverage).unwrap()).execute(&mut *conn).await.unwrap();
    diesel::sql_query("INSERT INTO content_original_roots(event_id,root_ref,root_context,backup_actor_id) VALUES($1,$2,$3,$4)")
        .bind::<Text,_>(source.event_ref.as_str()).bind::<Text,_>(root.root_ref.as_ref().unwrap().as_str())
        .bind::<Jsonb,_>(serde_json::to_value(root.root_context.as_ref().unwrap()).unwrap())
        .bind::<Text,_>(package.actor_id.to_string()).execute(&mut *conn).await.unwrap();
}

#[tokio::test]
async fn last_retained_root_requires_a_durable_current_recipient_substitute() {
    let database = database().await;
    let store = service(database.pool());
    let fixture = RootFixture::new(database.pool()).await;
    let original = sealed(fixture.package.clone());
    put(&store, &original).await.unwrap();
    seed_retained_original(&database.pool(), &fixture, &original).await;
    assert_eq!(
        store
            .delete_backup(original.backup_id.as_str())
            .await
            .unwrap_err()
            .conflict_code(),
        Some(ConflictCode::FailedPrecondition)
    );
    let replacement = sealed(successor(&original));
    assert_ne!(
        original.encryption.aead.enc,
        replacement.encryption.aead.enc
    );
    // Merely preparing a correctly sealed replacement is insufficient.
    assert_eq!(
        store
            .delete_backup(original.backup_id.as_str())
            .await
            .unwrap_err()
            .conflict_code(),
        Some(ConflictCode::FailedPrecondition)
    );
    put(&store, &replacement).await.unwrap();
    assert!(
        store
            .delete_backup(original.backup_id.as_str())
            .await
            .unwrap()
    );
    assert!(
        store
            .backup(original.backup_id.as_str())
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .backup(replacement.backup_id.as_str())
            .await
            .unwrap()
            .is_some()
    );
    assert_eq!(
        store
            .delete_backup(replacement.backup_id.as_str())
            .await
            .unwrap_err()
            .conflict_code(),
        Some(ConflictCode::FailedPrecondition)
    );
}

#[tokio::test]
async fn concurrent_root_deletion_cannot_remove_every_sufficient_copy() {
    let database = database().await;
    let store = service(database.pool());
    let fixture = RootFixture::new(database.pool()).await;
    let original = sealed(fixture.package.clone());
    let replacement = sealed(successor(&original));
    put(&store, &original).await.unwrap();
    put(&store, &replacement).await.unwrap();
    seed_retained_original(&database.pool(), &fixture, &original).await;
    let (left, right) = tokio::join!(
        store.delete_backup(original.backup_id.as_str()),
        store.delete_backup(replacement.backup_id.as_str())
    );
    assert_eq!(
        usize::from(matches!(left, Ok(true))) + usize::from(matches!(right, Ok(true))),
        1
    );
    let left = store
        .backup(original.backup_id.as_str())
        .await
        .unwrap()
        .is_some();
    let right = store
        .backup(replacement.backup_id.as_str())
        .await
        .unwrap()
        .is_some();
    assert_ne!(left, right);
}

#[tokio::test]
async fn a_revoked_recipient_copy_is_not_a_sufficient_retention_substitute() {
    let database = database().await;
    let store = service(database.pool());
    let mut fixture = RootFixture::new(database.pool()).await;
    let original = sealed(fixture.package.clone());
    let replacement = sealed(successor(&original));
    put(&store, &original).await.unwrap();
    put(&store, &replacement).await.unwrap();
    seed_retained_original(&database.pool(), &fixture, &original).await;
    fixture.revoke_recipient(database.pool()).await;
    for package in [&original, &replacement] {
        assert_eq!(
            store
                .delete_backup(package.backup_id.as_str())
                .await
                .unwrap_err()
                .conflict_code(),
            Some(ConflictCode::FailedPrecondition)
        );
        assert!(
            store
                .backup(package.backup_id.as_str())
                .await
                .unwrap()
                .is_some()
        );
    }
}
