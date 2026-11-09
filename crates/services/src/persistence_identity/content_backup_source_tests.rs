//! Two isolated storage adapters share only accepted public fixture originals.
//! Root packages and their immutable first-PUT indexes exist only at the issuer.
//! This does not claim HTTP federation or end-user recovery acceptance.

use arkret_models_collaboration::content_history::ContentBackupSource;
use arkret_models_crypto::{ContentBackupSourceDraft, ContentRootContext, KeyOperationSignature};
use coland_storage::RecoveryPolicyPublicationWrite;
use coland_storage_postgres::PgPersistenceStore;

use super::*;

fn sign_source(
    draft: ContentBackupSourceDraft,
    inception: &arkret_signatures::webvh::PreparedInception,
) -> ContentBackupSource {
    let signature = ed25519_dalek::SigningKey::from_bytes(&inception.did_key_seed)
        .sign(&draft.signing_payload_bytes().unwrap());
    let attestation = draft
        .into_attestation(KeyOperationSignature {
            kid: inception.did_key_id.clone().try_into().unwrap(),
            signature_algorithm: Some("Ed25519".to_owned().try_into().unwrap()),
            signature: arkret_canonical::base64url_encode(signature.to_bytes())
                .try_into()
                .unwrap(),
        })
        .unwrap();
    let origin_resolution = arkret_identity::build_authenticated_webvh_service_resolution(
        attestation
            .producer
            .actor_id
            .as_account_id()
            .unwrap()
            .station_id
            .clone(),
        "station".into(),
        serde_json::from_value(inception.log_entry["state"].clone()).unwrap(),
        vec![inception.log_entry.clone()],
        vec![],
        attestation.attested_at,
    )
    .unwrap();
    ContentBackupSource {
        attestation,
        origin_resolution,
    }
}

async fn original_audit(pool: &PgPool, event: &arkret_wire::Event) -> Value {
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query("SELECT jsonb_build_object('originals',(SELECT count(*) FROM content_originals WHERE event_id=$1),'roots',(SELECT count(*) FROM content_original_roots WHERE event_id=$1),'domains',(SELECT count(*) FROM content_key_domains WHERE event_id=$1),'backups',(SELECT count(*) FROM key_backups),'indexes',(SELECT count(*) FROM key_backup_identities)) AS payload")
        .bind::<Text,_>(event.event_id.as_str())
        .get_result::<BindingRow>(&mut *conn).await.unwrap().payload
}

#[tokio::test]
async fn foreign_original_requires_signed_native_custody_without_copying_foreign_backups() {
    use arkret_models_identity::service_identity::{CanonicalServiceUrl, ServiceRegistrationKey};
    use arkret_signatures::webvh::{
        ServiceRegistrationInceptionInput, prepare_service_registration_inception,
    };
    let registration = ServiceRegistrationKey::new(
        arkret_wire::ServiceKind::Station,
        CanonicalServiceUrl::new("https://root-keeper.example/").unwrap(),
    )
    .unwrap();
    let inception = prepare_service_registration_inception(
        &mut rand::rng(),
        &ServiceRegistrationInceptionInput {
            provider_endpoint: &"https://identity.example/".parse().unwrap(),
            registration_key: &registration,
            also_known_as: &[],
            version_created_at: "2026-09-01T00:00:00Z".parse().unwrap(),
            did_key_fragment: None,
        },
    )
    .unwrap();
    let issuer_did = arkret_wire::Did::new(inception.did.clone()).unwrap();
    let issuer = arkret_wire::project_did_to_core_id(&issuer_did).unwrap();
    let governor_did = arkret_wire::Did::new("did:web:root-governor.example").unwrap();
    let governor = arkret_wire::project_did_to_core_id(&governor_did).unwrap();
    let origin_db = TestDatabase::lease().await;
    let governor_db = TestDatabase::lease().await;
    origin_db.bind_device_inventory_station(issuer.as_str());
    governor_db.bind_device_inventory_station(issuer.as_str());
    let origin_pool = origin_db.pool();
    let governor_pool = governor_db.pool();
    let fixture = Box::pin(RootFixture::new_for_station(
        origin_pool.clone(),
        issuer_did,
    ))
    .await;

    // Install the same public PCR originals at both adapters. No key backup,
    // private state, database connection or backend is shared between them.
    let governor_store = PgPersistenceStore::new(governor_pool.clone());
    fixture.pcr.admit_into(&governor_store).await.unwrap();
    governor_store
        .recovery_policies()
        .commit_publication(RecoveryPolicyPublicationWrite {
            commit: coland_storage::AuthorityCommitTransaction {
                expected_authority: fixture.pcr.unit.transactions[1].expected_authority.clone(),
                event: fixture.pcr.history.events.last().unwrap().clone(),
                commit: fixture.pcr.history.commits.last().unwrap().clone(),
                producer_signer_fact: None,
                content_backup_source: None,
                mls_state: None,
                welcomes: vec![],
                recipient_queue_capacity: 0,
            },
            queued_at: fixture.policy.issued_at,
        })
        .await
        .unwrap();
    let profile = Box::pin(admit_owner_profile(&origin_pool, &fixture)).await;
    governor_store
        .actor_profiles()
        .admit_profile(coland_storage::ActorProfileAdmissionWrite {
            queued_at: profile.commit.committed_at,
            commit: profile,
        })
        .await
        .unwrap();
    let unit = ordinary_realm::bootstrap_unit_for_account(
        "foreign-root-custody",
        &fixture.pcr.history.account,
        &governor_did,
    );
    assert_eq!(unit.transactions[0].expected_authority.service_id, governor);
    assert_eq!(
        unit.transactions[0]
            .event
            .actor_id
            .as_account_id()
            .unwrap()
            .station_id,
        issuer
    );
    let origin_discussion = Box::pin(ordinary_realm::open_discussion_unit(
        &origin_pool,
        unit.clone(),
    ))
    .await;
    let governor_discussion =
        Box::pin(ordinary_realm::open_discussion_unit(&governor_pool, unit)).await;
    assert_eq!(
        origin_discussion.head.authority_commit.event,
        governor_discussion.head.authority_commit.event
    );
    let prepared = Box::pin(prepared_group_from_discussion(
        &origin_pool,
        origin_discussion,
        false,
    ))
    .await;
    for pool in [&origin_pool, &governor_pool] {
        PgEventCommitUnitOfWork::new(pool.clone())
            .commit_event(prepared.request.clone())
            .await
            .unwrap();
    }
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
    key_backup_tests::put(&key_backup_tests::service(origin_pool.clone()), &package)
        .await
        .unwrap();
    let event = encrypted_message(
        &prepared,
        &prepared.request.authority_commit,
        &context,
        &root,
        &package,
        &arkret_crypto::content_history::fresh_content_key_salt().unwrap(),
        "foreign custody original",
    );
    let draft = PgAuthorityCommitStore {
        pool: origin_pool.clone(),
    }
    .prepare_content_backup_source(
        &event,
        &issuer,
        &governor,
        &arkret_wire::DidUrl::new(inception.did_key_id.clone()).unwrap(),
    )
    .await
    .unwrap();
    let source = sign_source(draft.clone(), &inception);
    arkret::verify_content_backup_source_signature(&source).unwrap();
    let mut request = Box::pin(ordinary_realm::source_request(
        &governor_pool,
        ordinary_realm::request_for_event(
            &prepared.request.authority_commit,
            event.clone(),
            source.attestation.attested_at,
        ),
    ))
    .await;
    let store = PgAuthorityCommitStore {
        pool: governor_pool.clone(),
    };
    let uow = PgEventCommitUnitOfWork::new(governor_pool.clone());
    let head = store
        .stream_head(&request.authority_commit.commit.stream_ref)
        .await
        .unwrap();
    let empty = original_audit(&governor_pool, &event).await;
    assert_eq!(
        empty,
        json!({"originals":0,"roots":0,"domains":0,"backups":0,"indexes":0})
    );

    let mut bad_digest = draft.clone();
    bad_digest.protections_digest =
        arkret_wire::Hash::new(arkret_canonical::sha256_digest(b"other-slots")).unwrap();
    let mut bad_destination = draft.clone();
    bad_destination.destination_service_id = issuer.clone();
    let mut expired = draft.clone();
    expired.attested_at -= chrono::Duration::seconds(600);
    expired.expires_at = expired.attested_at + chrono::Duration::seconds(60);
    let mut bad_signature = source.clone();
    bad_signature.attestation.signature.signature = arkret_canonical::base64url_encode([0; 64])
        .try_into()
        .unwrap();
    let mut wrong_endpoint = draft.clone();
    wrong_endpoint.producer.signature_key_base64url = arkret_canonical::base64url_encode(
        ed25519_dalek::SigningKey::from_bytes(&[119; 32])
            .verifying_key()
            .to_bytes(),
    );
    let mut wrong_issuer = source.clone();
    wrong_issuer.origin_resolution.service_id = governor.clone();
    for (label, candidate, expected) in [
        (
            "missing source",
            None,
            "foreign encrypted original requires",
        ),
        (
            "signed wrong protections",
            Some(sign_source(bad_digest, &inception)),
            "backup source differs",
        ),
        (
            "signed wrong destination",
            Some(sign_source(bad_destination, &inception)),
            "backup source differs",
        ),
        (
            "expired source",
            Some(sign_source(expired, &inception)),
            "observation window",
        ),
        ("invalid signature", Some(bad_signature), "signature"),
        (
            "signed wrong actual leaf",
            Some(sign_source(wrong_endpoint, &inception)),
            "backup source differs",
        ),
        ("wrong issuer", Some(wrong_issuer), "actual owning Station"),
    ] {
        request.authority_commit.content_backup_source = candidate;
        let error = Box::pin(uow.commit_event(request.clone()))
            .await
            .unwrap_err();
        assert!(error.to_string().contains(expected), "{label}: {error}");
        assert_eq!(
            original_audit(&governor_pool, &event).await,
            empty,
            "{label}"
        );
        assert!(
            store
                .committed_event(&event.event_id)
                .await
                .unwrap()
                .is_none(),
            "{label}"
        );
        assert_eq!(
            store
                .stream_head(&request.authority_commit.commit.stream_ref)
                .await
                .unwrap(),
            head,
            "{label}"
        );
    }
    Box::pin(assert_target_dependency_refusals(TargetDependencyCase {
        origin_pool: &origin_pool,
        governor_pool: &governor_pool,
        prepared: &prepared,
        context: &context,
        root: &root,
        package: &package,
        source: &source,
        event: &event,
        previous: &governor_discussion.head.authority_commit,
        inception: &inception,
    }))
    .await;
    request.authority_commit.content_backup_source = Some(source.clone());
    Box::pin(uow.commit_event(request.clone())).await.unwrap();
    Box::pin(uow.commit_event(request.clone())).await.unwrap();
    assert_eq!(
        original_audit(&governor_pool, &event).await,
        json!({"originals":1,"roots":1,"domains":1,"backups":0,"indexes":0})
    );
    let mut conn = governor_pool.get().await.unwrap();
    let audit = diesel::sql_query("SELECT jsonb_build_object('source',o.backup_source,'foreign_root',r.source_backed,'root_owner',r.backup_actor_id,'context',r.root_context) AS payload FROM content_originals o JOIN content_original_roots r USING(event_id) WHERE o.event_id=$1")
        .bind::<Text,_>(event.event_id.as_str()).get_result::<BindingRow>(&mut *conn).await.unwrap().payload;
    assert_eq!(audit["source"], serde_json::to_value(&source).unwrap());
    assert_eq!(audit["foreign_root"], true);
    assert_eq!(audit["root_owner"], Value::Null);
    assert_eq!(audit["context"], serde_json::to_value(context).unwrap());
    drop(conn);

    // A real outgoing Realm change freezes the private export. Its audit and
    // keeper references survive without exporting any Account root packages.
    let next_station =
        arkret_wire::DidCoreId::new("ak:did_core:web:next-root-governor.example").unwrap();
    let change = Box::pin(ordinary_realm::source_request(
        &governor_pool,
        ordinary_realm::next_request_for_actor(
            &request.authority_commit,
            EventKind::RealmGovernanceStationChange,
            event.actor_id.clone(),
            json!({"expected_governance_generation":"0",
                "expected_realm_stream_commit_id":request.authority_commit.commit.commit_id,
                "new_governance_station_id":next_station}),
            request.authority_commit.commit.committed_at + chrono::Duration::milliseconds(1),
        ),
    ))
    .await;
    Box::pin(uow.commit_event(change)).await.unwrap();
    let (manifest, bytes) = store
        .export_management_private_state(&event.realm_id)
        .await
        .unwrap();
    let archive: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        archive["tables"]["content_originals"][0]["backup_source"],
        serde_json::to_value(&source).unwrap()
    );
    assert_eq!(
        archive["tables"]["content_originals"][0]["event_pk"],
        event.event_id.as_str()
    );
    assert_eq!(
        archive["tables"]["content_original_roots"][0]["source_backed"],
        true
    );
    assert_eq!(
        archive["tables"]["content_key_domains"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert!(archive["tables"].get("key_backups").is_none());
    assert!(archive["tables"].get("key_backup_identities").is_none());
    store
        .import_management_private_state(&manifest, &bytes)
        .await
        .unwrap();
    let (_, reexported) = store
        .export_management_private_state(&event.realm_id)
        .await
        .unwrap();
    assert_eq!(bytes, reexported);
}

struct TargetDependencyCase<'a> {
    origin_pool: &'a PgPool,
    governor_pool: &'a PgPool,
    prepared: &'a PreparedGroup,
    context: &'a ContentRootContext,
    root: &'a arkret_models_crypto::ContentRootSecret,
    package: &'a arkret_models_crypto::KeyBackup,
    source: &'a ContentBackupSource,
    event: &'a arkret_wire::Event,
    previous: &'a coland_storage::AuthorityCommitTransaction,
    inception: &'a arkret_signatures::webvh::PreparedInception,
}

async fn assert_target_dependency_refusals(case: TargetDependencyCase<'_>) {
    let TargetDependencyCase {
        origin_pool,
        governor_pool,
        prepared,
        context,
        root,
        package,
        source,
        event,
        previous,
        inception,
    } = case;
    let issuer = &source
        .attestation
        .producer
        .actor_id
        .as_account_id()
        .unwrap()
        .station_id;
    let governor = &source.attestation.destination_service_id;
    let store = PgAuthorityCommitStore {
        pool: governor_pool.clone(),
    };
    let uow = PgEventCommitUnitOfWork::new(governor_pool.clone());
    let empty = original_audit(governor_pool, event).await;
    let head = store
        .stream_head(&prepared.request.authority_commit.commit.stream_ref)
        .await
        .unwrap();
    let missing_blob = BlobRef::new(format!(
        "ak:blob:{}",
        arkret_canonical::sha256_digest(b"missing physical ciphertext")
    ))
    .unwrap();
    let missing_blob_event = encrypted_message_with_blob_refs(
        prepared,
        &prepared.request.authority_commit,
        context,
        root,
        package,
        (
            &arkret_crypto::content_history::fresh_content_key_salt().unwrap(),
            "valid Root source cannot stand in for the governor's physical Blob",
        ),
        vec![missing_blob],
    );
    let missing_blob_draft = PgAuthorityCommitStore {
        pool: origin_pool.clone(),
    }
    .prepare_content_backup_source(
        &missing_blob_event,
        issuer,
        governor,
        &arkret_wire::DidUrl::new(inception.did_key_id.clone()).unwrap(),
    )
    .await
    .unwrap();
    let missing_blob_source = sign_source(missing_blob_draft, inception);
    let mut missing_blob_request = Box::pin(ordinary_realm::source_request(
        governor_pool,
        ordinary_realm::request_for_event(
            &prepared.request.authority_commit,
            missing_blob_event.clone(),
            missing_blob_source.attestation.attested_at,
        ),
    ))
    .await;
    missing_blob_request.authority_commit.content_backup_source = Some(missing_blob_source);
    let error = Box::pin(uow.commit_event(missing_blob_request))
        .await
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("missing durable ciphertext blob"),
        "{error}"
    );
    assert_eq!(
        original_audit(governor_pool, &missing_blob_event).await,
        empty
    );
    assert!(
        store
            .committed_event(&missing_blob_event.event_id)
            .await
            .unwrap()
            .is_none()
    );

    let mut stale = Box::pin(ordinary_realm::source_request(
        governor_pool,
        ordinary_realm::request_for_event(previous, event.clone(), source.attestation.attested_at),
    ))
    .await;
    stale.authority_commit.content_backup_source = Some(source.clone());
    let error = Box::pin(uow.commit_event(stale)).await.unwrap_err();
    assert!(
        error.to_string().contains("stream head advanced"),
        "{error}"
    );
    assert_eq!(original_audit(governor_pool, event).await, empty);
    assert_eq!(
        store
            .stream_head(&prepared.request.authority_commit.commit.stream_ref)
            .await
            .unwrap(),
        head
    );
}
