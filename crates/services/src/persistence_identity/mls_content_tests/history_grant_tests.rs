//! Real native Event units, public RFC transitions, HPKE and root custody.
use arkret_event_draft::EventPayloadExt as _;
use arkret_models_crypto::{
    ContentRootContext, ContentRootSecret, HistoryGrant, HistoryGrantEntry, HistoryKeySelector,
};
use arkret_wire::{CommittedEventRef, Event};

use super::*;

fn reference(value: &coland_storage::AuthorityCommitTransaction) -> CommittedEventRef {
    CommittedEventRef {
        event_id: value.event.event_id.clone(),
        commit_id: value.commit.commit_id.clone(),
        stream_ref: value.commit.stream_ref.clone(),
        stream_position: value.commit.stream_position,
    }
}

async fn request(
    pool: &PgPool,
    prepared: &PreparedGroup,
    previous: &coland_storage::AuthorityCommitTransaction,
    cut: &coland_storage::AuthorityCommitTransaction,
    key: &arkret_crypto::hpke::X25519HpkeKeyPair,
) -> EventCommitRequest {
    let at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    let value = ordinary_realm::next_request(
        previous,
        EventKind::MlsHistoryRequest,
        prepared.endpoint.actor_id.signing_principal_id(),
        json!({"recipient":prepared.endpoint,"recipient_hpke_key_base64url":arkret_canonical::base64url_encode(key.public_key()),"history_cut":reference(cut),"expires_at":arkret_canonical::format_timestamp_canonical(at+chrono::Duration::seconds(600))}),
        at,
    );
    ordinary_realm::source_request(pool, value).await
}

fn grant(request: &Event, selector: HistoryKeySelector, secret: &[u8]) -> HistoryGrant {
    let body = request.as_mls_history_request().unwrap();
    let mut value = HistoryGrant {
        recipient: body.recipient,
        recipient_hpke_key_base64url: body.recipient_hpke_key_base64url,
        recipient_key_event_ref: request.event_id.clone(),
        history_cut: body.history_cut,
        expires_at: body.expires_at,
        entries: vec![],
    };
    let sealed_key_base64url =
        arkret_crypto::content_history::seal_history_key(&value, &selector, secret).unwrap();
    value.entries.push(HistoryGrantEntry {
        selector,
        sealed_key_base64url,
    });
    value
}

async fn grant_event(
    pool: &PgPool,
    previous: &coland_storage::AuthorityCommitTransaction,
    grant: &HistoryGrant,
) -> EventCommitRequest {
    let value = ordinary_realm::next_request(
        previous,
        EventKind::MlsHistoryGrant,
        previous.event.actor_id.signing_principal_id(),
        serde_json::to_value(grant).unwrap(),
        arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now()),
    );
    ordinary_realm::source_request(pool, value).await
}

async fn setup(
    pool: &PgPool,
) -> (
    PreparedGroup,
    ContentRootContext,
    ContentRootSecret,
    arkret_models_crypto::KeyBackup,
    EventCommitRequest,
) {
    let fixture = Box::pin(RootFixture::new(pool.clone())).await;
    let discussion = Box::pin(owner_discussion(pool, &fixture)).await;
    let prepared = Box::pin(prepared_group_from_discussion(pool, discussion, false)).await;
    PgEventCommitUnitOfWork::new(pool.clone())
        .commit_event(prepared.request.clone())
        .await
        .unwrap();
    let context = ContentRootContext {
        effective_scope: prepared.request.authority_commit.event.scope_ref.clone(),
        genesis_event_ref: prepared.request.authority_commit.event.event_id.clone(),
        epoch: 0,
        group_state_ref: prepared.request.authority_commit.event.event_id.clone(),
        cipher_suite: "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519".into(),
        encryption_backup_strategy: arkret_wire::EncryptionBackupStrategy::EpochContentRoots,
        backup_strategy_ref: prepared.strategy_event.event_id.clone(),
    };
    let root = prepared.group.export_content_root(&context).unwrap();
    let package = sealed_root_package(&fixture, &context, &root);
    key_backup_tests::put(&key_backup_tests::service(pool.clone()), &package)
        .await
        .unwrap();
    let event = encrypted_message(
        &prepared,
        &prepared.request.authority_commit,
        &context,
        &root,
        &package,
        &arkret_crypto::content_history::fresh_content_key_salt().unwrap(),
        "original before history request",
    );
    let source = ordinary_realm::request_for_event(
        &prepared.request.authority_commit,
        event,
        arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now()),
    );
    let source = ordinary_realm::source_request(pool, source).await;
    PgEventCommitUnitOfWork::new(pool.clone())
        .commit_event(source.clone())
        .await
        .unwrap();
    (prepared, context, root, package, source)
}

#[tokio::test]
async fn native_history_grants_bind_current_endpoint_exact_request_source_cut_and_slot_without_partial_writes()
 {
    let database = TestDatabase::lease().await;
    database.bind_device_inventory_station("ak:did_core:web:backup-test.example");
    let pool = database.pool();
    let (prepared, context, root, package, source) = Box::pin(setup(&pool)).await;
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    let hpke = arkret_crypto::hpke::generate_x25519_keypair().unwrap();
    let requested = request(
        &pool,
        &prepared,
        &source.authority_commit,
        &source.authority_commit,
        &hpke,
    )
    .await;
    uow.commit_event(requested.clone()).await.unwrap();
    let later_event = encrypted_message(
        &prepared,
        &requested.authority_commit,
        &context,
        &root,
        &package,
        &arkret_crypto::content_history::fresh_content_key_salt().unwrap(),
        "after frozen history cut",
    );
    let later = ordinary_realm::request_for_event(
        &requested.authority_commit,
        later_event,
        arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now()),
    );
    let later = ordinary_realm::source_request(&pool, later).await;
    uow.commit_event(later.clone()).await.unwrap();
    let envelope: arkret_models_crypto::EncryptedEnvelope =
        serde_json::from_value(source.authority_commit.event.payload["encrypted_content"].clone())
            .unwrap();
    let material = arkret_models_crypto::EventContentMaterial::from_original(
        &source.authority_commit.event,
        &envelope,
        context.clone(),
        prepared.endpoint.clone(),
    )
    .unwrap();
    let key = arkret_crypto::content_history::derive_content_key(&root, &material.content_context)
        .unwrap();
    let selector = HistoryKeySelector::ContentKey {
        source_event_ref: source.authority_commit.event.event_id.clone(),
        content_path: "/payload/encrypted_content".into(),
    };
    let valid = grant(&requested.authority_commit.event, selector, key.as_ref());
    let mut invalid = Vec::new();
    let mut wrong = valid.clone();
    wrong.recipient_hpke_key_base64url = arkret_canonical::base64url_encode(
        arkret_crypto::hpke::generate_x25519_keypair()
            .unwrap()
            .public_key(),
    );
    invalid.push(wrong);
    let mut wrong = valid.clone();
    wrong.recipient.signature_key_base64url = arkret_canonical::base64url_encode([71; 32]);
    invalid.push(wrong);
    let mut wrong = valid.clone();
    wrong.history_cut.stream_position += 1;
    invalid.push(wrong);
    for (event_id, path, secret) in [
        (
            source.authority_commit.event.event_id.clone(),
            "/payload",
            key.as_ref().to_vec(),
        ),
        (
            source.authority_commit.event.event_id.clone(),
            "/payload/encrypted_content/ciphertext",
            key.as_ref().to_vec(),
        ),
        (
            source.authority_commit.event.event_id.clone(),
            "/payload/encrypted_metadata",
            key.as_ref().to_vec(),
        ),
        (
            source.authority_commit.event.event_id.clone(),
            "/payload/encrypted_content",
            vec![9; 32],
        ),
        (
            later.authority_commit.event.event_id.clone(),
            "/payload/encrypted_content",
            key.as_ref().to_vec(),
        ),
        (
            prepared.strategy_event.event_id.clone(),
            "/payload/encrypted_content",
            key.as_ref().to_vec(),
        ),
    ] {
        invalid.push(grant(
            &requested.authority_commit.event,
            HistoryKeySelector::ContentKey {
                source_event_ref: event_id,
                content_path: path.into(),
            },
            &secret,
        ));
    }
    invalid.push(grant(
        &requested.authority_commit.event,
        HistoryKeySelector::EpochRoot {
            root_context: context.clone(),
            root_ref: material.content_context.root_ref.clone(),
            closed_epoch_cut: reference(&source.authority_commit),
        },
        root.expose(),
    ));
    let before = store
        .stream_head(&later.authority_commit.commit.stream_ref)
        .await
        .unwrap();
    for candidate in invalid {
        let submitted = grant_event(&pool, &later.authority_commit, &candidate).await;
        assert!(uow.commit_event(submitted.clone()).await.is_err());
        assert!(
            store
                .queued_event(&submitted.authority_commit.event.event_id)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .committed_event(&submitted.authority_commit.event.event_id)
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(
            store
                .stream_head(&later.authority_commit.commit.stream_ref)
                .await
                .unwrap(),
            before
        );
    }
    let accepted = grant_event(&pool, &later.authority_commit, &valid).await;
    assert!(
        store
            .admit_event_transaction(&accepted.authority_commit, accepted.event.received_at)
            .await
            .unwrap_err()
            .to_string()
            .contains("native content-history admission is unavailable")
    );
    uow.commit_event(accepted.clone()).await.unwrap();
    uow.commit_event(accepted.clone()).await.unwrap();
    assert_eq!(
        store
            .committed_event(&accepted.authority_commit.event.event_id)
            .await
            .unwrap()
            .unwrap()
            .event,
        accepted.authority_commit.event
    );
    assert_eq!(
        arkret_crypto::content_history::open_history_key(
            &valid,
            &valid.entries[0].selector,
            hpke.private_key(),
            &valid.entries[0].sealed_key_base64url
        )
        .unwrap()
        .as_slice(),
        key.as_ref()
    );
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query("DELETE FROM mls_endpoint_current_bindings WHERE scope_key=$1")
        .bind::<Text, _>(arkret_canonical::canonical_json_string(&context.effective_scope).unwrap())
        .execute(&mut *conn)
        .await
        .unwrap();
    drop(conn);
    uow.commit_event(accepted.clone()).await.unwrap();
    let fresh = grant_event(&pool, &accepted.authority_commit, &valid).await;
    assert!(uow.commit_event(fresh.clone()).await.is_err());
    assert!(
        store
            .committed_event(&fresh.authority_commit.event.event_id)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn native_history_root_requires_a_real_closed_epoch_and_full_authorized_interval() {
    let database = TestDatabase::lease().await;
    database.bind_device_inventory_station("ak:did_core:web:backup-test.example");
    let pool = database.pool();
    let (mut prepared, context, root, _, source) = Box::pin(setup(&pool)).await;
    prepared
        .group
        .install_local_creator_binding(
            prepared.endpoint.actor_id.clone(),
            Some(prepared.endpoint.authorization_event_ref.clone()),
        )
        .unwrap();
    let base = prepared.request.authority_commit.event.event_id.clone();
    let binding = MlsGovernanceBindingPayload::realm(
        source.authority_commit.event.realm_id.clone(),
        Some(base.clone()),
        0,
        1,
        0,
    )
    .unwrap();
    let envelope = prepared
        .group
        .self_update_commit_with_governance_binding(&binding)
        .unwrap();
    let (info, tree) = prepared
        .group
        .pending_public_group_state_bytes(&envelope, &binding)
        .unwrap();
    prepared
        .tracker
        .process_public_handshake(
            &arkret_canonical::base64url_decode(envelope.commit.as_str()).unwrap(),
        )
        .unwrap();
    prepared.tracker.verify_publication(&info, &tree).unwrap();
    let blobs = vec![public_blob(&info), public_blob(&tree)];
    let payload = MlsCommitPayload::new(
        base.clone(),
        0,
        &envelope,
        binding,
        blobs[0].blob_ref.clone(),
        blobs[1].blob_ref.clone(),
    )
    .unwrap();
    let mut closure = ordinary_realm::next_request(
        &source.authority_commit,
        EventKind::MlsCommit,
        prepared.endpoint.actor_id.signing_principal_id(),
        serde_json::to_value(payload).unwrap(),
        arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now()),
    );
    closure.authority_commit.mls_state = Some(MlsStateInstallation {
        effective_scope: context.effective_scope.clone(),
        base: Some(MlsInstalledBase {
            current_mls_commit_event_ref: base,
            epoch: 0,
        }),
        epoch: 1,
        public_state: prepared.tracker.export_state().unwrap(),
        member_principals: [prepared.endpoint.actor_id.clone()].into_iter().collect(),
        consumed_proposals: vec![],
        public_blobs: blobs,
    });
    let closure = ordinary_realm::source_request(&pool, closure).await;
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    uow.commit_event(closure.clone()).await.unwrap();
    let hpke = arkret_crypto::hpke::generate_x25519_keypair().unwrap();
    let requested = request(
        &pool,
        &prepared,
        &closure.authority_commit,
        &closure.authority_commit,
        &hpke,
    )
    .await;
    uow.commit_event(requested.clone()).await.unwrap();
    let root_ref = arkret_crypto::content_history::content_root_ref(&root, &context).unwrap();
    let valid = grant(
        &requested.authority_commit.event,
        HistoryKeySelector::EpochRoot {
            root_context: context.clone(),
            root_ref,
            closed_epoch_cut: reference(&closure.authority_commit),
        },
        root.expose(),
    );
    let accepted = grant_event(&pool, &requested.authority_commit, &valid).await;
    uow.commit_event(accepted.clone()).await.unwrap();
    let opened = arkret_crypto::content_history::open_history_key(
        &valid,
        &valid.entries[0].selector,
        hpke.private_key(),
        &valid.entries[0].sealed_key_base64url,
    )
    .unwrap();
    assert_eq!(opened.as_slice(), root.expose());
    let mut wrong = valid.clone();
    if let HistoryKeySelector::EpochRoot {
        closed_epoch_cut, ..
    } = &mut wrong.entries[0].selector
    {
        *closed_epoch_cut = reference(&source.authority_commit);
    }
    let bad = grant_event(&pool, &accepted.authority_commit, &wrong).await;
    assert!(uow.commit_event(bad.clone()).await.is_err());
    assert!(
        PgAuthorityCommitStore { pool }
            .committed_event(&bad.authority_commit.event.event_id)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn expired_history_request_refuses_new_grants_but_preserves_exact_accepted_replay() {
    let database = TestDatabase::lease().await;
    database.bind_device_inventory_station("ak:did_core:web:backup-test.example");
    let pool = database.pool();
    let (prepared, context, root, _, source) = Box::pin(setup(&pool)).await;
    let hpke = arkret_crypto::hpke::generate_x25519_keypair().unwrap();
    let at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    let expires = at + chrono::Duration::seconds(10);
    let request = ordinary_realm::next_request(
        &source.authority_commit,
        EventKind::MlsHistoryRequest,
        prepared.endpoint.actor_id.signing_principal_id(),
        json!({"recipient":prepared.endpoint,"recipient_hpke_key_base64url":arkret_canonical::base64url_encode(hpke.public_key()),"history_cut":reference(&source.authority_commit),"expires_at":arkret_canonical::format_timestamp_canonical(expires)}),
        at,
    );
    let request = ordinary_realm::source_request(&pool, request).await;
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    uow.commit_event(request.clone()).await.unwrap();
    let envelope =
        serde_json::from_value(source.authority_commit.event.payload["encrypted_content"].clone())
            .unwrap();
    let material = arkret_models_crypto::EventContentMaterial::from_original(
        &source.authority_commit.event,
        &envelope,
        context,
        prepared.endpoint.clone(),
    )
    .unwrap();
    let key = arkret_crypto::content_history::derive_content_key(&root, &material.content_context)
        .unwrap();
    let value = grant(
        &request.authority_commit.event,
        HistoryKeySelector::ContentKey {
            source_event_ref: source.authority_commit.event.event_id.clone(),
            content_path: "/payload/encrypted_content".into(),
        },
        key.as_ref(),
    );
    let accepted = grant_event(&pool, &request.authority_commit, &value).await;
    uow.commit_event(accepted.clone()).await.unwrap();
    tokio::time::sleep(
        (expires - chrono::Utc::now()).to_std().unwrap_or_default()
            + std::time::Duration::from_millis(50),
    )
    .await;
    uow.commit_event(accepted.clone()).await.unwrap();
    let fresh = grant_event(&pool, &accepted.authority_commit, &value).await;
    let error = uow
        .commit_event(fresh.clone())
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("bounded validity window"), "{error}");
    let store = PgAuthorityCommitStore { pool };
    assert!(
        store
            .queued_event(&fresh.authority_commit.event.event_id)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .committed_event(&fresh.authority_commit.event.event_id)
            .await
            .unwrap()
            .is_none()
    );
}
