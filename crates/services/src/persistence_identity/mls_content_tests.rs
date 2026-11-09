//! Real RFC public groups through native storage units. Event-device and MLS
//! leaf signing keys are deliberately independent. These are adapter tests,
//! not HTTP admission or complete history-recovery acceptance.

#[path = "../../../storage-postgres/tests/support/ordinary_realm.rs"]
#[expect(
    dead_code,
    reason = "Only the native discussion fixture subset is used."
)]
mod ordinary_realm;

use arkret_mls::{ArkretMlsGroup, ArkretMlsIdentity, ArkretMlsSigner, MlsPublicGroupTracker};
use arkret_models_crypto::{ContentEndpoint, MlsCommitPayload, MlsGovernanceBindingPayload};
use arkret_wire::{ActorId, BlobRef, EventKind, MlsWelcomeRecipientEndpoint};
use coland_storage::{
    AuthorityCommitStore as _, DeliveryPolicyStoreRegistry as _, EventCommitRequest,
    EventCommitUnitOfWork as _, MlsGroupCurrentStore as _, MlsInstalledBase, MlsPublicBlob,
    MlsStateInstallation,
};
use coland_storage_postgres::{
    PgAuthorityCommitStore, PgEventCommitUnitOfWork, PgMlsGroupCurrentStore, PgPool, TestDatabase,
};
use diesel::sql_types::{Jsonb, Text};
use ed25519_dalek::Signer as _;
use horme::RunQueryDsl as _;
use serde_json::{Value, json};

use super::key_backup_tests::{self, RootFixture};

#[path = "history_root_unlock_tests.rs"]
mod history_root_unlock_tests;

#[path = "history_forward_intent_tests.rs"]
mod history_forward_intent_tests;

fn public_blob(bytes: &[u8]) -> MlsPublicBlob {
    let digest = arkret_canonical::sha256_digest(bytes);
    let hex = digest.strip_prefix("sha256:").unwrap();
    MlsPublicBlob {
        blob_ref: BlobRef::new(format!("ak:blob:{digest}")).unwrap(),
        sha256: hex.into(),
        size_bytes: i64::try_from(bytes.len()).unwrap(),
        storage_backend: "local".into(),
        storage_key: format!("sha256/{hex}"),
    }
}

struct PreparedGroup {
    request: EventCommitRequest,
    group: ArkretMlsGroup,
    tracker: MlsPublicGroupTracker,
    endpoint: ContentEndpoint,
    strategy_event: arkret_wire::Event,
    strand_id: arkret_wire::StrandId,
}

async fn prepared_group(pool: &PgPool, label: &str, wrong_actor: bool) -> PreparedGroup {
    let discussion = Box::pin(ordinary_realm::open_discussion(pool, label)).await;
    prepared_group_from_discussion(pool, discussion, wrong_actor).await
}

async fn prepared_group_from_discussion(
    pool: &PgPool,
    discussion: ordinary_realm::Discussion,
    wrong_actor: bool,
) -> PreparedGroup {
    let source = discussion
        .head
        .authority_commit
        .producer_signer_fact
        .as_ref()
        .unwrap()
        .as_account_device()
        .unwrap();
    let realm = discussion.realm_id();
    let scope = arkret_wire::ScopeRef::Realm {
        realm_id: realm.clone(),
    };
    let binding = MlsGovernanceBindingPayload::realm(realm.clone(), None, 0, 0, 0).unwrap();
    let actor = if wrong_actor {
        ActorId::account(arkret_wire::AccountId::new(
            arkret_wire::DidCoreId::new("ak:did_core:web:unrelated-leaf.example").unwrap(),
            source.actor.as_account_id().unwrap().station_id.clone(),
        ))
    } else {
        source.actor.clone()
    };
    let identity = ArkretMlsIdentity::new_human_device(
        actor,
        source.device_id.clone(),
        ArkretMlsSigner::from_ed25519_signing_key(ed25519_dalek::SigningKey::from_bytes(
            &[118; 32],
        )),
    )
    .unwrap();
    let group = identity
        .create_group_with_governance_binding(&scope, &binding)
        .unwrap();
    let (info, tree) = group.public_group_state_bytes().unwrap();
    let tracker =
        MlsPublicGroupTracker::from_external(&info, &tree, group.group_id().as_str(), 0).unwrap();
    let leaf = tracker.leaves().unwrap().remove(0);
    assert_ne!(leaf.signature_key, source.key.public_key_base64url);
    let endpoint = ContentEndpoint {
        actor_id: source.actor.clone(),
        endpoint: MlsWelcomeRecipientEndpoint::Device {
            device_id: source.device_id.clone(),
        },
        authorization_event_ref: source.key.authorization_ref.event_id.clone(),
        signature_key_base64url: leaf.signature_key.to_string(),
    };
    let blobs = vec![public_blob(&info), public_blob(&tree)];
    let at = discussion.committed_at();
    let mut request = ordinary_realm::next_request(
        &discussion.head.authority_commit,
        EventKind::MlsGenesis,
        source.actor.signing_principal_id(),
        json!({
            "cipher_suite":"MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
            "group_info_ref":blobs[0].blob_ref,"ratchet_tree_ref":blobs[1].blob_ref,
            "creator_leaf_authority":{
                "leaf_signature_key_base64url":endpoint.signature_key_base64url,
                "endpoint":endpoint.endpoint,"authorization_event_ref":endpoint.authorization_event_ref
            },"governance_binding":binding,
            "created_at":arkret_canonical::format_timestamp_canonical(at)
        }),
        at,
    );
    request.authority_commit.mls_state = Some(MlsStateInstallation {
        effective_scope: scope,
        base: None,
        epoch: 0,
        public_state: tracker.export_state().unwrap(),
        member_principals: [leaf.actor_id].into_iter().collect(),
        consumed_proposals: vec![],
        public_blobs: blobs,
    });
    let request = ordinary_realm::source_request(pool, request).await;
    PreparedGroup {
        request,
        group,
        tracker,
        endpoint,
        strategy_event: discussion.unit.transactions[0].event.clone(),
        strand_id: discussion.strand_id,
    }
}

#[derive(diesel::QueryableByName)]
struct BindingRow {
    #[diesel(sql_type = Jsonb)]
    payload: Value,
}

async fn current_binding(pool: &PgPool, request: &EventCommitRequest) -> ContentEndpoint {
    let mut conn = pool.get().await.unwrap();
    let row = diesel::sql_query("SELECT binding AS payload FROM mls_endpoint_current_bindings WHERE scope_key=$1 AND current_event_ref=$2")
        .bind::<Text,_>(arkret_canonical::canonical_json_string(&request.authority_commit.event.scope_ref).unwrap())
        .bind::<Text,_>(request.authority_commit.event.event_id.as_str())
        .get_result::<BindingRow>(&mut *conn).await.unwrap();
    serde_json::from_value(row.payload).unwrap()
}

async fn endpoint_history(pool: &PgPool, actor: &ActorId) -> Vec<Value> {
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query("SELECT jsonb_build_object('effective_scope',effective_scope,'genesis_event_ref',genesis_event_ref,'binding',binding,'first_source',first_source) AS payload FROM content_endpoint_admission_history WHERE binding->'actor_id'=$1 ORDER BY admission_key")
        .bind::<Jsonb, _>(serde_json::to_value(actor).unwrap())
        .get_results::<BindingRow>(&mut *conn).await.unwrap()
        .into_iter().map(|row| row.payload).collect()
}

fn history_request_payload(prepared: &PreparedGroup) -> Value {
    let base = &prepared.request.authority_commit;
    json!({
        "recipient":prepared.endpoint,
        "recipient_hpke_key_base64url":arkret_canonical::base64url_encode(
            arkret_crypto::hpke::generate_x25519_keypair().unwrap().public_key()),
        "history_cut":{
            "event_id":base.event.event_id,"commit_id":base.commit.commit_id,
            "stream_ref":base.commit.stream_ref,"stream_position":base.commit.stream_position
        },
        "expires_at":arkret_canonical::format_timestamp_canonical(
            base.event.created_at + chrono::Duration::seconds(600))
    })
}

#[tokio::test]
async fn native_history_request_accepts_exact_current_endpoint_with_independent_event_and_leaf_keys()
 {
    let database = TestDatabase::lease().await;
    database.bind_device_inventory_station(ordinary_realm::station().as_str());
    let pool = database.pool();
    let prepared = Box::pin(prepared_group(&pool, "native-history-request", false)).await;
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    uow.commit_event(prepared.request.clone()).await.unwrap();
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    let genesis = store
        .committed_event(&prepared.strategy_event.event_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(genesis.event.scope_ref, arkret_wire::ScopeRef::RealmGenesis);
    let mut previous = prepared.request.authority_commit.clone();
    for use_genesis_cut in [false, true] {
        let mut payload = history_request_payload(&prepared);
        if use_genesis_cut {
            payload["history_cut"] = json!({
                "event_id":genesis.event.event_id,"commit_id":genesis.commit.commit_id,
                "stream_ref":genesis.commit.stream_ref,"stream_position":genesis.commit.stream_position
            });
        }
        let request = ordinary_realm::next_request(
            &previous,
            EventKind::MlsHistoryRequest,
            previous.event.actor_id.signing_principal_id(),
            payload,
            previous.event.created_at + chrono::Duration::milliseconds(1),
        );
        let request = ordinary_realm::source_request(&pool, request).await;
        let key = &request
            .authority_commit
            .producer_signer_fact
            .as_ref()
            .unwrap()
            .as_account_device()
            .unwrap()
            .key
            .public_key_base64url;
        assert_ne!(key.as_str(), prepared.endpoint.signature_key_base64url);
        let id = &request.authority_commit.event.event_id;
        let error = store
            .admit_event_transaction(&request.authority_commit, request.event.received_at)
            .await
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("native content-history admission is unavailable"),
            "{error}"
        );
        assert!(store.queued_event(id).await.unwrap().is_none());
        assert!(store.committed_event(id).await.unwrap().is_none());
        uow.commit_event(request.clone()).await.unwrap();
        uow.commit_event(request.clone()).await.unwrap();
        let accepted = store.committed_event(id).await.unwrap().unwrap();
        assert_eq!(accepted.event, request.authority_commit.event);
        assert_eq!(accepted.commit, request.authority_commit.commit);
        previous = request.authority_commit;
    }
    assert_eq!(
        current_binding(&pool, &prepared.request).await,
        prepared.endpoint
    );
}

#[tokio::test]
async fn native_history_request_refuses_wrong_leaf_cut_low_order_and_invalid_window_atomically() {
    let database = TestDatabase::lease().await;
    database.bind_device_inventory_station(ordinary_realm::station().as_str());
    let pool = database.pool();
    let prepared = Box::pin(prepared_group(
        &pool,
        "native-history-request-refusals",
        false,
    ))
    .await;
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    uow.commit_event(prepared.request.clone()).await.unwrap();
    let base = &prepared.request.authority_commit;
    for case in [
        "leaf",
        "endpoint",
        "authorization",
        "actor",
        "cut",
        "low_order",
        "ttl",
        "expired",
    ] {
        let mut payload = history_request_payload(&prepared);
        let mut created_at = base.event.created_at + chrono::Duration::milliseconds(1);
        match case {
            "leaf" => {
                payload["recipient"]["signature_key_base64url"] = json!(
                    base.producer_signer_fact
                        .as_ref()
                        .unwrap()
                        .as_account_device()
                        .unwrap()
                        .key
                        .public_key_base64url
                )
            }
            "endpoint" => {
                payload["recipient"]["endpoint"]["device_id"] =
                    json!("ak:device:019a0000-0000-7000-8000-000000000099")
            }
            "authorization" => {
                payload["recipient"]["authorization_event_ref"] = json!(base.event.event_id)
            }
            "actor" => {
                payload["recipient"]["actor_id"]["account_id"]["principal_id"] =
                    json!("ak:did_core:web:another-recipient.example")
            }
            "cut" => payload["history_cut"]["stream_position"] = json!(0),
            "low_order" => {
                payload["recipient_hpke_key_base64url"] =
                    json!(arkret_canonical::base64url_encode([0; 32]))
            }
            "ttl" => {
                payload["expires_at"] = json!(arkret_canonical::format_timestamp_canonical(
                    base.event.created_at + chrono::Duration::seconds(901)
                ))
            }
            "expired" => {
                created_at = base.event.created_at;
                let expiry = created_at + chrono::Duration::milliseconds(1);
                assert!(chrono::Utc::now() >= expiry);
                payload["expires_at"] = json!(arkret_canonical::format_timestamp_canonical(expiry))
            }
            _ => unreachable!(),
        }
        let request = ordinary_realm::next_request(
            base,
            EventKind::MlsHistoryRequest,
            base.event.actor_id.signing_principal_id(),
            payload,
            created_at,
        );
        let request = ordinary_realm::source_request(&pool, request).await;
        let error = uow
            .commit_event(request.clone())
            .await
            .unwrap_err()
            .to_string();
        let expected = match case {
            "leaf" | "endpoint" | "authorization" | "actor" => {
                "differs from its native current endpoint"
            }
            "cut" => "history cut differs",
            "low_order" => "noncontributory X25519 recipient",
            _ => "bounded validity window",
        };
        assert!(error.contains(expected), "{case}: {error}");
        assert!(
            PgAuthorityCommitStore { pool: pool.clone() }
                .committed_event(&request.authority_commit.event.event_id)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            PgAuthorityCommitStore { pool: pool.clone() }
                .queued_event(&request.authority_commit.event.event_id)
                .await
                .unwrap()
                .is_none()
        );
        let head = PgAuthorityCommitStore { pool: pool.clone() }
            .stream_head(&base.commit.stream_ref)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(head.commit_id, base.commit.commit_id);
    }
}

#[tokio::test]
async fn independent_mls_leaf_key_binds_to_native_device_and_survives_member_update() {
    let database = TestDatabase::lease().await;
    database.bind_device_inventory_station(ordinary_realm::station().as_str());
    let pool = database.pool();
    let mut prepared = Box::pin(prepared_group(&pool, "independent-content-leaf", false)).await;
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    uow.commit_event(prepared.request.clone()).await.unwrap();
    assert_eq!(
        current_binding(&pool, &prepared.request).await,
        prepared.endpoint
    );
    let history = endpoint_history(&pool, &prepared.endpoint.actor_id).await;
    assert_eq!(
        history.len(),
        1,
        "empty activated groups need an admission origin"
    );
    assert_eq!(
        history[0]["binding"],
        serde_json::to_value(&prepared.endpoint).unwrap()
    );
    assert_eq!(
        history[0]["genesis_event_ref"],
        json!(prepared.request.authority_commit.event.event_id)
    );
    assert_eq!(
        history[0]["first_source"]["commit_id"],
        json!(prepared.request.authority_commit.commit.commit_id)
    );
    prepared
        .group
        .install_local_creator_binding(
            prepared.endpoint.actor_id.clone(),
            Some(prepared.endpoint.authorization_event_ref.clone()),
        )
        .unwrap();

    let base = prepared.request.authority_commit.event.event_id.clone();
    let realm = prepared.request.authority_commit.event.realm_id.clone();
    let binding = MlsGovernanceBindingPayload::realm(realm, Some(base.clone()), 0, 1, 0).unwrap();
    let envelope = prepared
        .group
        .self_update_commit_with_governance_binding(&binding)
        .unwrap();
    let (info, tree) = prepared
        .group
        .pending_public_group_state_bytes(&envelope, &binding)
        .unwrap();
    let wire = arkret_canonical::base64url_decode(envelope.commit.as_str()).unwrap();
    prepared.tracker.process_public_handshake(&wire).unwrap();
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
    let mut update = ordinary_realm::next_request(
        &prepared.request.authority_commit,
        EventKind::MlsCommit,
        prepared.endpoint.actor_id.signing_principal_id(),
        serde_json::to_value(&payload).unwrap(),
        prepared.request.authority_commit.commit.committed_at,
    );
    update.authority_commit.mls_state = Some(MlsStateInstallation {
        effective_scope: prepared.request.authority_commit.event.scope_ref.clone(),
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
    let update = ordinary_realm::source_request(&pool, update).await;
    let forged = payload
        .with_recovery_binding(arkret_models_crypto::ContentRecoveryBinding {
            replacement: prepared.endpoint.clone(),
            authorization_event_ref: prepared.endpoint.authorization_event_ref.clone(),
            base_group_state_ref: prepared.request.authority_commit.event.event_id.clone(),
            expected_epoch: 0,
            inventory_digest: arkret_wire::Hash::new(format!("sha256:{}", "77".repeat(32)))
                .unwrap(),
        })
        .unwrap();
    let mut forged = ordinary_realm::next_request(
        &prepared.request.authority_commit,
        EventKind::MlsCommit,
        prepared.endpoint.actor_id.signing_principal_id(),
        serde_json::to_value(forged).unwrap(),
        prepared.request.authority_commit.commit.committed_at,
    );
    forged.authority_commit.mls_state = update.authority_commit.mls_state.clone();
    let forged = ordinary_realm::source_request(&pool, forged).await;
    let error = uow.commit_event(forged.clone()).await.unwrap_err();
    assert!(
        error
            .to_string()
            .contains("native content recovery inventory"),
        "{error}"
    );
    let authority = PgAuthorityCommitStore { pool: pool.clone() };
    assert!(
        authority
            .queued_event(&forged.authority_commit.event.event_id)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        authority
            .stream_head(&prepared.request.authority_commit.commit.stream_ref)
            .await
            .unwrap()
            .unwrap()
            .commit_id,
        prepared.request.authority_commit.commit.commit_id
    );
    assert_eq!(
        current_binding(&pool, &prepared.request).await,
        prepared.endpoint
    );
    uow.commit_event(update.clone()).await.unwrap();
    assert_eq!(current_binding(&pool, &update).await, prepared.endpoint);
    assert_eq!(
        endpoint_history(&pool, &prepared.endpoint.actor_id).await,
        history,
        "same endpoint epochs preserve the exact first admission without duplication"
    );
    // A missing derived current row is not an absence proof for the inventory.
    // This is a negative projection-loss fixture, not a fabricated MLS Remove.
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query("DELETE FROM mls_endpoint_current_bindings WHERE scope_key=$1")
        .bind::<Text, _>(
            arkret_canonical::canonical_json_string(&update.authority_commit.event.scope_ref)
                .unwrap(),
        )
        .execute(&mut *conn)
        .await
        .unwrap();
    drop(conn);
    assert_eq!(
        endpoint_history(&pool, &prepared.endpoint.actor_id).await,
        history
    );
}

#[tokio::test]
async fn another_rfc_leaf_actor_refuses_genesis_without_installing_any_original_or_group() {
    let database = TestDatabase::lease().await;
    database.bind_device_inventory_station(ordinary_realm::station().as_str());
    let pool = database.pool();
    let prepared = Box::pin(prepared_group(&pool, "foreign-content-leaf", true)).await;
    assert!(
        PgEventCommitUnitOfWork::new(pool.clone())
            .commit_event(prepared.request.clone())
            .await
            .is_err()
    );
    let event = &prepared.request.authority_commit.event;
    assert!(
        PgAuthorityCommitStore { pool: pool.clone() }
            .committed_event(&event.event_id)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        PgMlsGroupCurrentStore { pool }
            .current(&event.scope_ref)
            .await
            .unwrap()
            .is_none()
    );
}

async fn owner_discussion(pool: &PgPool, fixture: &RootFixture) -> ordinary_realm::Discussion {
    let persistence = std::sync::Arc::new(coland_storage_postgres::PgPersistenceStore::new(
        pool.clone(),
    ));
    let app = crate::authority_commit::AuthorityCommitApplication::new(
        crate::persistence::PersistenceHandle::new(persistence.clone()),
        64,
    );
    let event = fixture.pcr.history.event(
        EventKind::ProfileCreate,
        json!({"object":{
            "principal_id":fixture.pcr.history.account.principal_id,
            "actor_kind":"user","display_name":"Native content owner"
        }}),
    );
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
    persistence
        .actor_profiles()
        .admit_profile(coland_storage::ActorProfileAdmissionWrite {
            commit: transaction,
            queued_at: at,
        })
        .await
        .unwrap();
    ordinary_realm::human_profile::register_fixture_signer(
        &fixture.pcr.history.account,
        fixture.pcr.history.device_verification_method.clone(),
        fixture.pcr.history.founding_device_signing_seed,
    );
    let unit = ordinary_realm::bootstrap_unit_for_account(
        "native-root-dependent-original",
        &fixture.pcr.history.account,
        &fixture.pcr.history.station_did,
    );
    Box::pin(ordinary_realm::open_discussion_unit(pool, unit)).await
}

fn sealed_root_package(
    fixture: &RootFixture,
    context: &arkret_models_crypto::ContentRootContext,
    root: &arkret_models_crypto::ContentRootSecret,
) -> arkret_models_crypto::KeyBackup {
    use arkret_models_crypto::*;
    let mut package = fixture.package.clone();
    let entry = ContentRootBackupEntry {
        item_kind: ContentRootItemKind::ContentEpochRoot,
        secret_id: "native_root_0".into(),
        root_context: context.clone(),
        root_ref: arkret_crypto::content_history::content_root_ref(root, context).unwrap(),
        root_base64url: root.clone(),
    };
    let bag = KeyBackupPlaintext {
        schema: arkret_wire::SchemaId::KeyBackupPlaintextV1,
        backup_id: package.backup_id.clone(),
        backup_kind: package.backup_kind,
        series_id: package.series_id.clone(),
        series_sequence: package.series_sequence,
        items: vec![entry.into()],
        extra: Default::default(),
    };
    package.contents = bag
        .items
        .iter()
        .map(SecretStorageEntry::content_index)
        .collect();
    let key = package
        .encryption
        .recipient_key_ref
        .as_deref()
        .unwrap()
        .strip_prefix("did:key:")
        .unwrap()
        .split('#')
        .next()
        .unwrap();
    let key = arkret_canonical::decode_multibase_base58btc(key).unwrap();
    assert_eq!(&key[..2], &[0xec, 0x01]);
    arkret_crypto::content_history::seal_content_root_backup(package, &bag, &key[2..], |bytes| {
        Ok(
            ed25519_dalek::SigningKey::from_bytes(
                &fixture.pcr.history.founding_device_signing_seed,
            )
            .sign(bytes)
            .to_bytes()
            .to_vec(),
        )
    })
    .unwrap()
}

async fn prepared_own_pcr_group(
    fixture: &RootFixture,
    wrong_creator: Option<&str>,
) -> (EventCommitRequest, ArkretMlsGroup, ContentEndpoint) {
    let realm = fixture.pcr.history.events[0].realm_id.clone();
    let scope = arkret_wire::ScopeRef::Realm {
        realm_id: realm.clone(),
    };
    let binding = MlsGovernanceBindingPayload::realm(realm.clone(), None, 0, 0, 0).unwrap();
    let actor = ActorId::account(fixture.pcr.history.account.clone());
    let identity = ArkretMlsIdentity::new_human_device(
        actor.clone(),
        fixture.pcr.history.founding_device_id.clone(),
        ArkretMlsSigner::from_ed25519_signing_key(ed25519_dalek::SigningKey::from_bytes(
            &[118; 32],
        )),
    )
    .unwrap();
    let group = identity
        .create_group_with_governance_binding(&scope, &binding)
        .unwrap();
    let (info, tree) = group.public_group_state_bytes().unwrap();
    let tracker =
        MlsPublicGroupTracker::from_external(&info, &tree, group.group_id().as_str(), 0).unwrap();
    let leaf = tracker.leaves().unwrap().remove(0);
    let endpoint = ContentEndpoint {
        actor_id: actor,
        endpoint: MlsWelcomeRecipientEndpoint::Device {
            device_id: fixture.pcr.history.founding_device_id.clone(),
        },
        authorization_event_ref: fixture.pcr.history.events[1].event_id.clone(),
        signature_key_base64url: leaf.signature_key.to_string(),
    };
    let blobs = vec![public_blob(&info), public_blob(&tree)];
    let mut declared = endpoint.clone();
    match wrong_creator {
        None => {}
        Some("authorization") => {
            declared.authorization_event_ref = fixture.pcr.history.events[0].event_id.clone()
        }
        Some("device") => {
            declared.endpoint = MlsWelcomeRecipientEndpoint::Device {
                device_id: arkret_wire::DeviceId::new(format!(
                    "ak:device:{}",
                    uuid::Uuid::now_v7()
                ))
                .unwrap(),
            }
        }
        _ => panic!("unknown negative creator case"),
    }
    let event=fixture.pcr.history.event(EventKind::MlsGenesis,json!({
        "cipher_suite":"MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
        "group_info_ref":blobs[0].blob_ref,"ratchet_tree_ref":blobs[1].blob_ref,
        "creator_leaf_authority":{"leaf_signature_key_base64url":declared.signature_key_base64url,
            "endpoint":declared.endpoint,"authorization_event_ref":declared.authorization_event_ref},
        "governance_binding":binding,
        "created_at":arkret_canonical::format_timestamp_canonical(fixture.pcr.history.events[0].created_at)
    }));
    let previous = coland_storage::AuthorityCommitTransaction {
        expected_authority: fixture.pcr.unit.transactions[1].expected_authority.clone(),
        event: fixture.pcr.history.events.last().unwrap().clone(),
        commit: fixture.pcr.history.commits.last().unwrap().clone(),
        producer_signer_fact: None,
        mls_state: None,
        welcomes: vec![],
        recipient_queue_capacity: 0,
    };
    let at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    let mut request = ordinary_realm::request_for_event(&previous, event, at);
    ordinary_realm::seal_final_commit(&mut request.authority_commit.commit);
    let source = &fixture.pcr.history.commits[1];
    request.self_producer_guard = Some(coland_storage::SelfProducerCommitGuard::HumanDevice(
        coland_storage::DeviceRevocationGateSelector {
            principal_id: fixture.pcr.history.account.principal_id.clone(),
            station_id: fixture.pcr.history.account.station_id.clone(),
            device_id: fixture.pcr.history.founding_device_id.to_string(),
            authorization_ref: arkret_wire::CommittedEventRef {
                event_id: fixture.pcr.history.events[1].event_id.clone(),
                commit_id: source.commit_id.clone(),
                stream_ref: source.stream_ref.clone(),
                stream_position: source.stream_position,
            },
        },
    ));
    request.authority_commit.mls_state = Some(MlsStateInstallation {
        effective_scope: scope,
        base: None,
        epoch: 0,
        public_state: tracker.export_state().unwrap(),
        member_principals: [endpoint.actor_id.clone()].into_iter().collect(),
        consumed_proposals: vec![],
        public_blobs: blobs,
    });
    (request, group, endpoint)
}

async fn own_pcr_group(
    pool: &PgPool,
    fixture: &RootFixture,
) -> (
    coland_storage::AuthorityCommitTransaction,
    ArkretMlsGroup,
    ContentEndpoint,
) {
    let (request, mut group, endpoint) = Box::pin(prepared_own_pcr_group(fixture, None)).await;
    PgEventCommitUnitOfWork::new(pool.clone())
        .commit_event(request.clone())
        .await
        .unwrap();
    group
        .install_local_creator_binding(
            endpoint.actor_id.clone(),
            Some(endpoint.authorization_event_ref.clone()),
        )
        .unwrap();
    (request.authority_commit, group, endpoint)
}

#[tokio::test]
async fn own_pcr_mls_genesis_refuses_mismatched_current_creator_without_membership_fallback() {
    let database = TestDatabase::lease().await;
    database.bind_device_inventory_station("ak:did_core:web:backup-test.example");
    let pool = database.pool();
    let fixture = Box::pin(RootFixture::new(pool.clone())).await;
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    for case in ["device", "authorization"] {
        let (request, ..) = Box::pin(prepared_own_pcr_group(&fixture, Some(case))).await;
        let before = store
            .stream_head(&request.authority_commit.commit.stream_ref)
            .await
            .unwrap();
        let error = uow.commit_event(request.clone()).await.unwrap_err();
        assert!(
            error
                .to_string()
                .contains("PCR Genesis differs from its native Human creator endpoint"),
            "{case}: {error}"
        );
        assert_eq!(
            store
                .stream_head(&request.authority_commit.commit.stream_ref)
                .await
                .unwrap(),
            before
        );
        assert!(
            PgMlsGroupCurrentStore { pool: pool.clone() }
                .current(&request.authority_commit.event.scope_ref)
                .await
                .unwrap()
                .is_none()
        );
        let mut conn = pool.get().await.unwrap();
        let count=diesel::sql_query("SELECT to_jsonb(count(*)) AS payload FROM canonical_events WHERE envelope->>'event_id'=$1")
            .bind::<Text,_>(request.authority_commit.event.event_id.as_str()).get_result::<BindingRow>(&mut *conn).await.unwrap();
        assert_eq!(count.payload, json!(0));
    }
}

#[tokio::test]
async fn own_pcr_private_profile_requires_native_root_before_accepting_exact_encrypted_original() {
    use arkret_crypto::content_history::*;
    use arkret_models_crypto::*;
    use coland_storage::{ActorProfileAdmissionOutcome, ActorProfileAdmissionWrite};
    let database = TestDatabase::lease().await;
    database.bind_device_inventory_station("ak:did_core:web:backup-test.example");
    let pool = database.pool();
    let mut fixture = Box::pin(RootFixture::new_with_recovery_words(pool.clone())).await;
    let mut conn = pool.get().await.unwrap();
    let history=diesel::sql_query("SELECT value AS payload FROM realm_bootstrap_current_states WHERE realm_id=$1 AND state_family='realm_history_access'")
        .bind::<Text,_>(fixture.pcr.history.events[0].realm_id.as_str()).get_result::<BindingRow>(&mut *conn).await.unwrap();
    assert_eq!(history.payload, json!("since_join"));
    drop(conn);
    let (genesis, group, endpoint) = Box::pin(own_pcr_group(&pool, &fixture)).await;
    assert!(genesis.producer_signer_fact.is_none());
    assert_ne!(
        endpoint.signature_key_base64url,
        arkret_canonical::base64url_encode(
            ed25519_dalek::SigningKey::from_bytes(
                &fixture.pcr.history.founding_device_signing_seed
            )
            .verifying_key()
            .to_bytes()
        )
    );
    let context = ContentRootContext {
        effective_scope: genesis.event.scope_ref.clone(),
        genesis_event_ref: genesis.event.event_id.clone(),
        epoch: 0,
        group_state_ref: genesis.event.event_id.clone(),
        cipher_suite: "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519".into(),
        encryption_backup_strategy: arkret_wire::EncryptionBackupStrategy::EpochContentRoots,
        backup_strategy_ref: fixture.pcr.history.events[0].event_id.clone(),
    };
    let root = group.export_content_root(&context).unwrap();
    let package = sealed_root_package(&fixture, &context, &root);
    let content = ContentContext {
        root_context: context.clone(),
        root_ref: content_root_ref(&root, &context).unwrap(),
        purpose: ContentPurpose::EventBody,
        encryption_scheme: arkret_wire::EncryptedPayloadScheme::EpochContentAead,
        encryption_algorithm: ContentEncryptionAlgorithm::Aes128Gcm,
        producer: endpoint.clone(),
        content_key_salt: fresh_content_key_salt().unwrap(),
    };
    let key = derive_content_key(&root, &content).unwrap();
    let commitment = content_key_commitment(&content, &key).unwrap();
    let protection = ContentProtection {
        root_refs: vec![content.root_ref.clone()],
        blob_refs: vec![],
        backup_refs: vec![package.backup_id.clone()],
    };
    let mut public = json!({"principal_id":fixture.pcr.history.account.principal_id,
        "actor_kind":"user","display_name":"Public control profile"});
    let raw = fixture
        .pcr
        .history
        .event(EventKind::ProfileCreate, json!({"object":public}));
    let mut outer = serde_json::to_value(&raw).unwrap();
    for field in ["event_id", "payload", "producer_proof", "unsigned"] {
        outer.as_object_mut().unwrap().remove(field);
    }
    let header = EventContentPreEncryptionHeader::reconstruct(
        "1.0",
        "application/json",
        content.encryption_scheme.clone(),
        context.effective_scope.clone(),
        raw.kind.as_str(),
        0,
        context.group_state_ref.clone(),
        arkret_canonical::canonical_json_string(&endpoint.actor_id).unwrap(),
        EventContentRoutingContext::None,
        EventContentMaterial {
            content_context: content.clone(),
            outer_event: outer,
            protection: protection.clone(),
            key_commitment: commitment.clone(),
        },
    )
    .unwrap();
    let plaintext = arkret_canonical::canonical_json_bytes(
        &json!({"profile_fields":{"biography":"private PCR original"}}),
    )
    .unwrap();
    let ciphertext = seal_content(&root, &header, &plaintext).unwrap();
    let envelope = EncryptedEnvelope {
        version: "1.0".into(),
        content_type: "application/json".into(),
        encryption_scheme: content.encryption_scheme.clone(),
        encryption_context: EncryptedEnvelopeEncryptionContext::EpochContent {
            epoch: 0,
            group_state_ref: context.group_state_ref.clone(),
            content_key_salt: content.content_key_salt.clone(),
            root_ref: content.root_ref.clone(),
            key_commitment: commitment,
            protection,
            routing_context: None,
        },
        ciphertext,
    };
    public["encrypted_private_fields"] = serde_json::to_value(&envelope).unwrap();
    let event = fixture
        .pcr
        .history
        .event(EventKind::ProfileCreate, json!({"object":public}));
    let persistence = std::sync::Arc::new(coland_storage_postgres::PgPersistenceStore::new(
        pool.clone(),
    ));
    let app = crate::authority_commit::AuthorityCommitApplication::new(
        crate::persistence::PersistenceHandle::new(persistence.clone()),
        64,
    );
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
    assert!(transaction.producer_signer_fact.is_none());
    let write = ActorProfileAdmissionWrite {
        commit: transaction.clone(),
        queued_at: at,
    };
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    let before = store
        .stream_head(&transaction.commit.stream_ref)
        .await
        .unwrap();
    let missing = persistence
        .actor_profiles()
        .admit_profile(write.clone())
        .await
        .unwrap_err();
    assert!(
        missing.to_string().contains("missing durable root package"),
        "{missing}"
    );
    assert!(
        store
            .committed_event(&event.event_id)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        store
            .stream_head(&transaction.commit.stream_ref)
            .await
            .unwrap(),
        before
    );
    let backups = key_backup_tests::service(pool.clone());
    key_backup_tests::put(&backups, &package).await.unwrap();
    let accepted = persistence
        .actor_profiles()
        .admit_profile(write.clone())
        .await
        .unwrap();
    let ActorProfileAdmissionOutcome::Committed(original) = accepted else {
        panic!("first original must commit")
    };
    assert_eq!(original.event, event);
    assert_eq!(
        original.profile.encrypted_private_fields.as_ref(),
        Some(&envelope)
    );
    assert!(matches!(
        persistence
            .actor_profiles()
            .admit_profile(write)
            .await
            .unwrap(),
        ActorProfileAdmissionOutcome::Duplicate(_)
    ));
    let mut conn = pool.get().await.unwrap();
    let recorded=diesel::sql_query("SELECT content_context AS payload FROM content_key_domains WHERE event_id=$1 AND content_path='/payload/object/encrypted_private_fields'")
        .bind::<Text,_>(event.event_id.as_str()).get_result::<BindingRow>(&mut *conn).await.unwrap();
    assert_eq!(
        serde_json::from_value::<ContentContext>(recorded.payload).unwrap(),
        content
    );
    drop(conn);
    assert_eq!(
        open_content(&root, &header, &envelope.ciphertext).unwrap(),
        plaintext
    );
    fixture.pcr.history.events.push(genesis.event.clone());
    fixture.pcr.history.commits.push(genesis.commit.clone());
    fixture.pcr.history.events.push(transaction.event.clone());
    fixture.pcr.history.commits.push(transaction.commit.clone());
    let (restored, protected_backup_id) = Box::pin(history_root_unlock_tests::exercise(
        &pool,
        &mut fixture,
        &package,
        &transaction,
    ))
    .await;
    assert_eq!(restored.root_context, context);
    assert_eq!(
        open_content(&restored.root_base64url, &header, &envelope.ciphertext).unwrap(),
        plaintext
    );
    let mut conn = pool.get().await.unwrap();
    let count = diesel::sql_query(
        "SELECT to_jsonb(count(*)) AS payload FROM member_state_current_states WHERE realm_id=$1",
    )
    .bind::<Text, _>(event.realm_id.as_str())
    .get_result::<BindingRow>(&mut *conn)
    .await
    .unwrap();
    assert_eq!(count.payload, json!(0));
    drop(conn);
    let invalid = backups
        .delete_backup(protected_backup_id.as_str())
        .await
        .unwrap_err();
    assert!(
        invalid
            .to_string()
            .contains("last sufficient current-recipient content root package"),
        "{invalid}"
    );
}

fn encrypted_message(
    prepared: &PreparedGroup,
    previous: &coland_storage::AuthorityCommitTransaction,
    context: &arkret_models_crypto::ContentRootContext,
    root: &arkret_models_crypto::ContentRootSecret,
    package: &arkret_models_crypto::KeyBackup,
    salt: &str,
    text: &str,
) -> arkret_wire::Event {
    use arkret_crypto::content_history::*;
    use arkret_models_crypto::*;
    let mut event = ordinary_realm::next_request(
        previous,
        EventKind::MessageCreate,
        prepared.endpoint.actor_id.signing_principal_id(),
        json!({"strand_id":prepared.strand_id,"track_name":"discussion","body":{"text":text}}),
        previous.commit.committed_at,
    )
    .authority_commit
    .event;
    let content = ContentContext {
        root_context: context.clone(),
        root_ref: content_root_ref(root, context).unwrap(),
        purpose: ContentPurpose::EventBody,
        encryption_scheme: arkret_wire::EncryptedPayloadScheme::EpochContentAead,
        encryption_algorithm: ContentEncryptionAlgorithm::Aes128Gcm,
        producer: prepared.endpoint.clone(),
        content_key_salt: salt.to_owned(),
    };
    let key = derive_content_key(root, &content).unwrap();
    let commitment = content_key_commitment(&content, &key).unwrap();
    let protection = ContentProtection {
        root_refs: vec![content.root_ref.clone()],
        blob_refs: vec![],
        backup_refs: vec![package.backup_id.clone()],
    };
    let mut outer = serde_json::to_value(&event).unwrap();
    for member in ["event_id", "payload", "producer_proof", "unsigned"] {
        outer.as_object_mut().unwrap().remove(member);
    }
    let header = EventContentPreEncryptionHeader::reconstruct(
        "1.0",
        "application/vnd.arkret.message+json",
        content.encryption_scheme.clone(),
        context.effective_scope.clone(),
        event.kind.as_str(),
        context.epoch,
        context.group_state_ref.clone(),
        arkret_canonical::canonical_json_string(&prepared.endpoint.actor_id).unwrap(),
        EventContentRoutingContext::None,
        EventContentMaterial {
            content_context: content.clone(),
            outer_event: outer,
            protection: protection.clone(),
            key_commitment: commitment.clone(),
        },
    )
    .unwrap();
    let plaintext = serde_json::to_vec(&json!({"text":text})).unwrap();
    let ciphertext = seal_content(root, &header, &plaintext).unwrap();
    assert_eq!(open_content(root, &header, &ciphertext).unwrap(), plaintext);
    let envelope = EncryptedEnvelope {
        version: "1.0".into(),
        content_type: header.content_type,
        encryption_scheme: content.encryption_scheme,
        encryption_context: EncryptedEnvelopeEncryptionContext::EpochContent {
            epoch: context.epoch,
            group_state_ref: context.group_state_ref.clone(),
            content_key_salt: salt.into(),
            root_ref: content.root_ref,
            key_commitment: commitment,
            protection,
            routing_context: None,
        },
        ciphertext,
    };
    event.payload.remove("body");
    event.payload.insert(
        "encrypted_content".into(),
        serde_json::to_value(envelope).unwrap(),
    );
    ordinary_realm::human_profile::sign_fixture_event(event).unwrap()
}

#[tokio::test]
async fn encrypted_original_requires_real_root_backup_and_binds_one_immutable_key_domain() {
    let database = TestDatabase::lease().await;
    database.bind_device_inventory_station("ak:did_core:web:backup-test.example");
    let pool = database.pool();
    let fixture = Box::pin(RootFixture::new(pool.clone())).await;
    let discussion = Box::pin(owner_discussion(&pool, &fixture)).await;
    let prepared = Box::pin(prepared_group_from_discussion(&pool, discussion, false)).await;
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    uow.commit_event(prepared.request.clone()).await.unwrap();
    let context = arkret_models_crypto::ContentRootContext {
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
    let salt = arkret_crypto::content_history::fresh_content_key_salt().unwrap();
    let event = encrypted_message(
        &prepared,
        &prepared.request.authority_commit,
        &context,
        &root,
        &package,
        &salt,
        "first protected original",
    );
    let request = ordinary_realm::request_for_event(
        &prepared.request.authority_commit,
        event.clone(),
        prepared.request.authority_commit.commit.committed_at,
    );
    let request = ordinary_realm::source_request(&pool, request).await;
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    let before = store
        .stream_head(&request.authority_commit.commit.stream_ref)
        .await
        .unwrap();
    let absent_root = uow.commit_event(request.clone()).await.unwrap_err();
    assert!(
        absent_root
            .to_string()
            .contains("missing durable root package"),
        "unexpected refusal: {absent_root:?}"
    );
    assert!(
        store
            .committed_event(&event.event_id)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        store
            .stream_head(&request.authority_commit.commit.stream_ref)
            .await
            .unwrap(),
        before
    );
    let backups = key_backup_tests::service(pool.clone());
    key_backup_tests::put(&backups, &package).await.unwrap();
    uow.commit_event(request.clone()).await.unwrap();
    uow.commit_event(request.clone()).await.unwrap();
    let mut conn = pool.get().await.unwrap();
    let row = diesel::sql_query("SELECT content_context AS payload FROM content_key_domains WHERE event_id=$1 AND content_path='/payload/encrypted_content'")
        .bind::<Text,_>(event.event_id.as_str()).get_result::<BindingRow>(&mut *conn).await.unwrap();
    let recorded: arkret_models_crypto::ContentContext =
        serde_json::from_value(row.payload).unwrap();
    assert_eq!(recorded.producer, prepared.endpoint);
    assert_eq!(recorded.root_context, context);
    drop(conn);
    let last_root = backups
        .delete_backup(package.backup_id.as_str())
        .await
        .unwrap_err();
    assert!(
        last_root
            .to_string()
            .contains("last sufficient current-recipient content root package"),
        "unexpected deletion refusal: {last_root:?}"
    );
    // The changed plaintext is intentionally given the same key/nonce domain.
    // The native ledger must refuse it even though its Event/AAD differ.
    let reused = encrypted_message(
        &prepared,
        &request.authority_commit,
        &context,
        &root,
        &package,
        &salt,
        "different protected original",
    );
    let reused_request = ordinary_realm::request_for_event(
        &request.authority_commit,
        reused.clone(),
        request.authority_commit.commit.committed_at,
    );
    let reused_request = ordinary_realm::source_request(&pool, reused_request).await;
    let reused_domain = uow.commit_event(reused_request).await.unwrap_err();
    assert!(
        reused_domain.to_string().contains("key and nonce domain"),
        "unexpected reuse refusal: {reused_domain:?}"
    );
    assert!(
        store
            .committed_event(&reused.event_id)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        store
            .stream_head(&request.authority_commit.commit.stream_ref)
            .await
            .unwrap()
            .unwrap()
            .commit_id,
        request.authority_commit.commit.commit_id
    );
}
