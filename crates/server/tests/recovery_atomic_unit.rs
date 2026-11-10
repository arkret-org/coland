//! Recovery storage boundary: an accepted policy and a verified session feed
//! the real terminal unit. Factor/session HTTP verification is outside this
//! fixture; no SQL manufactures a generation, device authorization or Commit.

#[path = "http_api/current_common.rs"]
mod http_common;

use arkret_event_draft::EventPayloadExt as _;
use arkret_models_collaboration::events_payloads::{
    DeviceAuthorizationBindingKind, DeviceOrPrincipalRef, DeviceReanchorPayload, SignatureMaterial,
    device_authorize_payload_digest,
};
use arkret_models_crypto::*;
use arkret_models_identity::{
    HistoricalSignerKeyQuerySender, SignerKeyQuerySelector, SignerKeyResolution,
};
use arkret_wire::*;
use coland_storage::{
    RecoveryAuthorityContext, RecoveryPolicyPublicationWrite, RecoverySessionLifecycle,
    RecoverySessionRecord, RecoveryUnitCommitWrite, SecurityTransactionRecord,
    SecurityTransactionStepOutcomeRecord,
};
use coland_test_support::AppStateTestExt as _;
use coland_test_support::device_authorization_history::{
    DeviceAuthorizationSpec, possession_with, sign_event,
};
use coland_test_support::pcr_genesis::PcrGenesisFixture;
use diesel::sql_types::Jsonb;
use diesel_async::{RunQueryDsl, SimpleAsyncConnection};
use ed25519_dalek::{Signer, SigningKey};
use salvo::test::ResponseExt as _;
use serde_json::{Value, json};

const REPLACEMENT_SIGNING_SEED: [u8; 32] = [96; 32];

fn own_claim_intent(fixture: &Fixture) -> KeyPackagesClaimRequestBody {
    let history = &fixture.pcr.history;
    let original = history
        .events
        .iter()
        .find(|event| event.kind == EventKind::DeviceAuthorize)
        .unwrap();
    let realm = RealmId::from_event_id(&EventId::from_digest(
        arkret_canonical::DigestSuite::Sha256,
        arkret_canonical::sha256_bytes(uuid::Uuid::now_v7().as_bytes()),
    ));
    let scope = ScopeRef::Realm {
        realm_id: realm.clone(),
    };
    let at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    let mut request: KeyPackagesClaimRequestBody = serde_json::from_value(json!({
        "claim_request_id": arkret_canonical::base64url_encode(uuid::Uuid::now_v7().as_bytes()),
        "target_account_id": history.account,
        "target_device_ids": [history.founding_device_id],
        "requester_account_id": history.account,
        "intended_realm_id": realm,
        "effective_scope": scope,
        "mls_group_id": scope.canonical_mls_group_id().unwrap(),
        "claim_purpose": "realm_membership",
        "required_capabilities": ["ak.content.v1"],
        "expires_at": arkret_canonical::format_timestamp_canonical(at + chrono::Duration::minutes(4)),
        "service_binding": {"source_id": history.account.station_id, "destination_id": history.account.station_id},
        "requester_authorization": {
            "kind": "device",
            "verification_method": history.device_verification_method,
            "requester_device_id": history.founding_device_id,
            "device_authorize_event_id": original.event_id,
            "signed_at": arkret_canonical::format_timestamp_canonical(at),
            "signature": {"kid": history.device_verification_method, "signature_algorithm": "Ed25519", "signature": "AA"},
        },
    })).unwrap();
    let bytes = keypackage_claim_authorization_signing_bytes(
        &request.unsigned_request(),
        &request.service_binding,
        &request.requester_authorization,
    )
    .unwrap();
    let PeerKeyPackageRequesterAuthorization::Device {
        signature: proof, ..
    } = &mut request.requester_authorization
    else {
        unreachable!()
    };
    proof.signature = signature(history.founding_device_signing_seed, &bytes);
    request.validate_shape().unwrap();
    request
}

async fn retain_own_claim_intent(fixture: &Fixture) -> KeyPackagesClaimRequestBody {
    let request = own_claim_intent(fixture);
    let store = fixture.state.test_persistence();
    assert!(
        store
            .mls_key_packages()
            .prepare_ordinary_claim_source(&request, request.expires_at)
            .await
            .unwrap()
    );
    // The destination budget port accepts an already authenticated original;
    // it does not allocate a package or manufacture accepted membership.
    assert_eq!(
        store
            .mls_key_packages()
            .record_peer_claim_attempt(&request)
            .await
            .unwrap(),
        coland_storage::PeerKeyPackageClaimRateDecision::Allowed
    );
    request
}

#[tokio::test]
async fn recovery_freezes_unresolved_claims_without_fabricating_prepared_inventory() {
    let fixture = fixture().await;
    let request = retain_own_claim_intent(&fixture).await;
    let store = fixture.state.test_persistence();
    store
        .security_transactions()
        .commit_recovery_unit(fixture.write.clone())
        .await
        .unwrap();
    let before = footprint(&fixture).await;
    let rows = &before["content_recovery_census_sources"];
    assert_eq!(rows.as_array().unwrap().len(), 2);
    for (row, kind) in rows
        .as_array()
        .unwrap()
        .iter()
        .zip(["incoming_claim", "outgoing_claim"])
    {
        assert_eq!(row["source_kind"], kind);
        assert_eq!(
            row["authorization_event_ref"],
            json!(fixture.write.commits[1].event.event_id)
        );
        assert_eq!(row["effective_scope"], json!(request.effective_scope));
        assert_eq!(
            row["source"]["request_digest"],
            json!(arkret_canonical::canonical_sha256(&request).unwrap())
        );
        assert!(row["source"].get("request_body").is_none());
    }
    assert_eq!(
        before["peer_keypackage_claims"],
        json!([]),
        "an intent is not an accepted claim or absence proof"
    );
    let episode = &before["content_recovery_episodes"][0];
    assert_eq!(episode["state"], "pending");
    assert!(episode["inventory_blob_ref"].is_null());
    assert!(episode["security_completed_at"].is_null());
    store
        .security_transactions()
        .commit_recovery_unit(fixture.write.clone())
        .await
        .unwrap();
    assert_eq!(
        footprint(&fixture).await,
        before,
        "exact recovery retry cannot extend or replace its cut"
    );
    let next = own_claim_intent(&fixture);
    assert!(
        store
            .mls_key_packages()
            .prepare_ordinary_claim_source(&next, next.expires_at)
            .await
            .is_err()
    );
    assert_eq!(footprint(&fixture).await, before);
}

#[tokio::test]
async fn damaged_native_claim_original_rolls_back_the_entire_recovery_unit() {
    let fixture = fixture().await;
    retain_own_claim_intent(&fixture).await;
    let mut conn = fixture.pool.get().await.unwrap();
    diesel::sql_query("UPDATE ordinary_keypackage_claim_sources SET request_digest=$1")
        .bind::<diesel::sql_types::Text, _>(format!("sha256:{}", "0".repeat(64)))
        .execute(&mut conn)
        .await
        .unwrap();
    drop(conn);
    let before = footprint(&fixture).await;
    let error = fixture
        .state
        .test_persistence()
        .security_transactions()
        .commit_recovery_unit(fixture.write.clone())
        .await
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("revision_unavailable: recovery census cut claim original differs"),
        "{error}"
    );
    assert_eq!(footprint(&fixture).await, before);
}

fn forward_genesis(fixture: &Fixture, replacement: bool) -> Event {
    let history = &fixture.pcr.history;
    let (device, method, seed, authorization) = if replacement {
        let event = &fixture.write.commits[1].event;
        let payload: arkret_models_collaboration::events_payloads::DeviceAuthorizePayload =
            serde_json::from_value(serde_json::to_value(&event.payload).unwrap()).unwrap();
        (
            payload.device_id,
            event
                .producer_proof
                .as_ref()
                .unwrap()
                .verification_method
                .clone(),
            REPLACEMENT_SIGNING_SEED,
            event.event_id.clone(),
        )
    } else {
        (
            history.founding_device_id.clone(),
            history.device_verification_method.clone(),
            history.founding_device_signing_seed,
            history
                .events
                .iter()
                .find(|event| event.kind == EventKind::DeviceAuthorize)
                .unwrap()
                .event_id
                .clone(),
        )
    };
    let realm = RealmId::from_event_id(&EventId::from_digest(
        arkret_canonical::DigestSuite::Sha256,
        arkret_canonical::sha256_bytes(uuid::Uuid::now_v7().as_bytes()),
    ));
    let scope = ScopeRef::Realm {
        realm_id: realm.clone(),
    };
    let binding = MlsGovernanceBindingPayload::new(scope.clone(), None, 0, 0, 0).unwrap();
    let identity = arkret_mls::ArkretMlsIdentity::new_human_device(
        ActorId::account(history.account.clone()),
        device.clone(),
        arkret_mls::ArkretMlsSigner::from_ed25519_signing_key(SigningKey::from_bytes(&seed)),
    )
    .unwrap();
    let group = identity
        .create_group_with_governance_binding(&scope, &binding)
        .unwrap();
    let (info, tree) = group.public_group_state_bytes().unwrap();
    let mut event = history.raw_event(EventKind::MlsGenesis, json!({
        "cipher_suite": "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
        "group_info_ref": format!("ak:blob:{}", arkret_canonical::sha256_digest(&info)),
        "ratchet_tree_ref": format!("ak:blob:{}", arkret_canonical::sha256_digest(&tree)),
        "creator_leaf_authority": {
            "leaf_signature_key_base64url": arkret_canonical::base64url_encode(SigningKey::from_bytes(&seed).verifying_key().as_bytes()),
            "endpoint": {"kind": "device", "device_id": device},
            "authorization_event_ref": authorization,
        },
        "governance_binding": binding,
        "created_at": arkret_canonical::format_timestamp_canonical(arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now())),
    }), &realm);
    event.created_at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    let event = sign_event(event, method, seed);
    event.as_mls_genesis().unwrap();
    event
}

#[tokio::test]
async fn replacement_cannot_issue_remote_mls_membership_sources_behind_the_census_cut() {
    let fixture = fixture().await;
    let store = fixture.state.test_persistence();
    let destination = DidCoreId::new("ak:did_core:web:remote.example").unwrap();
    let digest = hash("native forward fence");
    let before = forward_genesis(&fixture, false);
    assert!(
        store
            .account_device_signer_evidence()
            .prepare_non_managed_forward_current(&before, &destination, &digest)
            .await
            .unwrap()
            .is_some()
    );
    store
        .security_transactions()
        .commit_recovery_unit(fixture.write.clone())
        .await
        .unwrap();
    let cut = footprint(&fixture).await;
    let event = forward_genesis(&fixture, true);
    let error = store
        .account_device_signer_evidence()
        .prepare_non_managed_forward_current(&event, &destination, &digest)
        .await
        .unwrap_err();
    assert!(
        error.to_string().contains("membership fence is active"),
        "{error}"
    );
    assert_eq!(footprint(&fixture).await, cut);
}

#[derive(Clone, Copy)]
enum RecoveryProofDamage {
    Possession,
    Reanchor,
    Authorize,
}

struct Fixture {
    state: coland_http::state::AppState,
    pool: coland_storage_postgres::PgPool,
    pcr: PcrGenesisFixture,
    initial: SecurityTransactionRecord,
    write: RecoveryUnitCommitWrite,
}

fn hash(value: impl serde::Serialize) -> Hash {
    Hash::new(arkret_canonical::canonical_sha256(&value).unwrap()).unwrap()
}

fn signature(seed: [u8; 32], bytes: &[u8]) -> Base64UrlString {
    Base64UrlString::new(arkret_canonical::base64url_encode(
        SigningKey::from_bytes(&seed).sign(bytes).to_bytes(),
    ))
    .unwrap()
}

async fn fixture() -> Fixture {
    fixture_with_config(coland_test_support::app_config()).await
}

fn old_device_package(fixture: &Fixture, seed: [u8; 32]) -> coland_storage::MlsKeyPackageRow {
    let actor = ActorId::account(fixture.pcr.history.account.clone());
    let identity = arkret_mls::ArkretMlsIdentity::new_human_device(
        actor.clone(),
        fixture.pcr.history.founding_device_id.clone(),
        arkret_mls::ArkretMlsSigner::from_ed25519_signing_key(SigningKey::from_bytes(&seed)),
    )
    .unwrap();
    let package = identity.key_package_record().unwrap();
    let bytes = arkret_canonical::base64url_decode(package.keypackage.as_bytes()).unwrap();
    let authorization = fixture
        .pcr
        .history
        .events
        .iter()
        .find(|event| event.kind.as_str() == "ak.device.authorize")
        .unwrap();
    let now = chrono::Utc::now().timestamp();
    coland_storage::MlsKeyPackageRow {
        id: package.keypackage_id,
        keypackage_ref: package.keypackage_ref.to_string(),
        keypackage_digest: arkret_canonical::sha256_digest(&bytes),
        owner_actor_id: actor,
        effective_scope: None,
        actor_id: fixture.pcr.history.account.principal_id.to_string(),
        device_id: Some(fixture.pcr.history.founding_device_id.to_string()),
        endpoint_verification_method: None,
        key_package_bytes: bytes,
        capabilities_digest: arkret_canonical::canonical_sha256(&package.capabilities).unwrap(),
        capabilities: package.capabilities,
        last_resort: false,
        last_resort_realm_id: None,
        lifetime_not_before: now - 60,
        lifetime_not_after: now + 3600,
        claimed_by_mls_group_id: None,
        device_authorize_event_id: Some(authorization.event_id.to_string()),
        agent_key_authorize_event_id: None,
        claimed_at: None,
        claim_expires_at_unix_ms: None,
        consumed_at: None,
        created_at: now,
    }
}

#[tokio::test]
async fn replacement_cannot_reuse_a_verified_old_keypackage_signing_key() {
    let fixture = fixture_with_config(http_common::test_config()).await;
    http_common::dev_token_for_device(
        fixture.state.clone(),
        fixture.pcr.history.did.as_str(),
        fixture.pcr.history.founding_device_id.as_str(),
        "Publishing device",
    )
    .await;
    let store = fixture.state.test_persistence();
    let package = old_device_package(&fixture, REPLACEMENT_SIGNING_SEED);
    assert!(store.mls_key_packages().put(&package).await.unwrap());
    let before = footprint(&fixture).await;
    let error = store
        .security_transactions()
        .commit_recovery_unit(fixture.write.clone())
        .await
        .unwrap_err();
    assert!(error.to_string().contains("already used"), "{error}");
    assert_eq!(footprint(&fixture).await, before);
}

#[tokio::test]
async fn invalid_keypackage_cannot_pollute_recovery_exclusion_and_episode_fences_publication() {
    let fixture = fixture_with_config(http_common::test_config()).await;
    http_common::dev_token_for_device(
        fixture.state.clone(),
        fixture.pcr.history.did.as_str(),
        fixture.pcr.history.founding_device_id.as_str(),
        "Publishing device",
    )
    .await;
    let store = fixture.state.test_persistence();
    let control = old_device_package(&fixture, [97; 32]);
    assert!(store.mls_key_packages().put(&control).await.unwrap());
    let mut package = old_device_package(&fixture, [98; 32]);
    let last = package.key_package_bytes.len() - 1;
    package.key_package_bytes[last] ^= 1;
    package.keypackage_digest = arkret_canonical::sha256_digest(&package.key_package_bytes);
    let before = footprint(&fixture).await;
    let error = store.mls_key_packages().put(&package).await.unwrap_err();
    assert!(
        error.to_string().contains("KeyPackage signing history"),
        "{error}"
    );
    assert_eq!(footprint(&fixture).await, before);
    store
        .security_transactions()
        .commit_recovery_unit(fixture.write.clone())
        .await
        .unwrap();
    let valid = old_device_package(&fixture, [99; 32]);
    let before = footprint(&fixture).await;
    let error = store.mls_key_packages().put(&valid).await.unwrap_err();
    assert!(
        error.to_string().contains("membership fence is active"),
        "{error}"
    );
    assert_eq!(footprint(&fixture).await, before);
}

#[tokio::test]
async fn pending_episode_fences_new_pairing_by_the_actual_replacement_device() {
    let fixture = fixture().await;
    let store = fixture.state.test_persistence();
    store
        .security_transactions()
        .commit_recovery_unit(fixture.write.clone())
        .await
        .unwrap();
    let replacement = fixture.write.commits[1]
        .event
        .as_device_authorize()
        .unwrap();
    let at = fixture.write.commits[1].commit.committed_at + chrono::Duration::milliseconds(1);
    let payload = possession_with(
        &fixture.pcr.history.account,
        DeviceAuthorizationSpec {
            device_id: DeviceId::new(format!("ak:device:{}", uuid::Uuid::now_v7())).unwrap(),
            signing_seed: [101; 32],
            hpke_seed: [102; 32],
            authorized_by: DeviceOrPrincipalRef::DeviceId(replacement.device_id.clone()),
            not_before: at,
            expires_at: None,
            binding: DeviceAuthorizationBindingKind::AcceptedDevice,
            authorized_generation_ref: replacement.authorized_generation_ref,
            applet_id: None,
        },
    );
    let mut event = fixture.pcr.history.raw_event(
        EventKind::DeviceAuthorize,
        serde_json::to_value(payload).unwrap(),
        &fixture.write.commits[1].event.realm_id,
    );
    event.created_at = at;
    let event = sign_event(
        event,
        fixture.write.commits[1]
            .event
            .producer_proof
            .as_ref()
            .unwrap()
            .verification_method
            .clone(),
        REPLACEMENT_SIGNING_SEED,
    );
    let mut commit = fixture.write.commits[1].commit.clone();
    commit.event_ref = event.event_id.clone();
    commit.previous_commit_ref = Some(commit.commit_id.clone());
    commit.stream_position += 1;
    commit.committed_at = at;
    let identity =
        arkret_canonical::canonical::unsigned_value(&commit, &["commit_id", "signature"]).unwrap();
    commit.commit_id = RealmCommitId::from_digest(arkret_canonical::sha256_bytes(
        arkret_canonical::canonical_json_bytes(&identity).unwrap(),
    ));
    commit.signature = arkret_signatures::detached_object::sign_detached_object(
        &arkret_canonical::canonical::unsigned_value(&commit, &["signature"]).unwrap(),
        DetachedSignatureContext::RealmCommit,
        commit.signature.verification_method.clone(),
        at,
        &SigningKey::from_bytes(
            &coland_test_support::device_authorization_history::STATION_AUTHORITY_SEED,
        ),
    )
    .unwrap();
    commit.verify_commit_id_matches_content().unwrap();
    let queued_at = commit.committed_at;
    let write = coland_storage::AuthorityCommitTransaction {
        expected_authority: fixture.write.commits[1].expected_authority.clone(),
        event,
        commit,
        producer_signer_fact: None,
        content_backup_source: None,
        mls_state: None,
        welcomes: vec![],
        recipient_queue_capacity: 0,
    };
    let before = footprint(&fixture).await;
    let error = store
        .authority_commits()
        .admit_accepted_device_authorization(&write, queued_at)
        .await
        .unwrap_err();
    assert!(
        error.to_string().contains("membership fence is active"),
        "{error}"
    );
    assert_eq!(footprint(&fixture).await, before);
}

async fn fixture_with_config(config: coland_http::config::AppConfig) -> Fixture {
    fixture_with_damage(config, None).await
}

// Signed, verified status is an input at this storage boundary. The account
// authority's HTTP resolve and Standard-grant issuance are outside this fixture.
async fn observed_reader(fixture: &Fixture) -> coland_storage::HumanPcrHistoryReader {
    use arkret_models_collaboration::account_status::{
        UnsignedAccountStatusReceipt, UnsignedAccountStatusRecord,
    };
    use arkret_signatures::account_status::*;
    let account = &fixture.pcr.history.account;
    let key = SigningKey::from_bytes(&[94; 32]);
    let method = DidUrl::new(format!("{}#status", fixture.pcr.history.station_did)).unwrap();
    let at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    let record = sign_account_status_record(
        UnsignedAccountStatusRecord {
            schema: SchemaId::ACCOUNT_STATUS_RECORD_V1.to_owned(),
            account_authority_id: account.station_id.clone(),
            account_id: account.clone(),
            principal_control_realm_id: fixture.pcr.history.events[0].realm_id.clone(),
            binding_version: 1,
            status_sequence: 1,
            previous_account_status_record_id: None,
            status: arkret_models_collaboration::objects::account_status::AccountStatus::Active,
            reason_code: None,
            reason: None,
            issued_at: at,
            expires_at: None,
        },
        method.clone(),
        &key,
    )
    .unwrap();
    let receipt = sign_account_status_receipt(
        UnsignedAccountStatusReceipt {
            receipt_id: ReceiptId::new(format!("ak:receipt:{}", uuid::Uuid::now_v7())).unwrap(),
            account_status_record_id: record.account_status_record_id.clone(),
            record_digest: record.payload_digest().unwrap(),
            account_authority_id: account.station_id.clone(),
            account_id: account.clone(),
            status_sequence: 1,
            receiver_id: account.station_id.clone(),
            accepted_at: at,
            verification_method: method,
        },
        &key,
    )
    .unwrap();
    let public = arkret_signatures::PublicKeyMaterial::Ed25519Raw {
        bytes: key.verifying_key().to_bytes().to_vec(),
    };
    verify_account_status_record(&record, &public).unwrap();
    verify_account_status_receipt(&receipt, &public).unwrap();
    fixture
        .state
        .test_persistence()
        .account_status_replicas()
        .append(&record, &receipt)
        .await
        .unwrap();
    let authorize = &fixture.write.commits[1].event;
    let payload = authorize.as_device_authorize().unwrap();
    coland_storage::HumanPcrHistoryReader {
        account_id: account.clone(),
        device_id: payload.device_id.clone(),
        credential_device_binding: Some(
            arkret_models_identity::session_credential::SessionGrantDeviceBinding {
                device_id: payload.device_id.clone(),
                authorization_event_id: authorize.event_id.clone(),
                model_generation_ref: payload.authorized_generation_ref,
            },
        ),
        credential_expires_at: at + chrono::Duration::minutes(5),
        account_status_observation: Some(
            coland_storage::AccountStatusCurrentObservation::after_authenticated_resolve(record),
        ),
    }
}

#[tokio::test]
async fn native_preparation_is_read_only_fixed_and_current_device_bound() {
    use coland_storage::HumanPcrHistoryRead;
    let fixture = fixture().await;
    let store = fixture.state.test_persistence();
    store
        .security_transactions()
        .commit_recovery_unit(fixture.write.clone())
        .await
        .unwrap();
    let reader = observed_reader(&fixture).await;
    let authorize = &fixture.write.commits[1];
    let before = footprint(&fixture).await;
    let mut no_status = reader.clone();
    no_status.account_status_observation = None;
    assert!(matches!(
        store
            .security_transactions()
            .human_content_recovery_preparation(&no_status, &authorize.event.event_id)
            .await
            .unwrap(),
        HumanPcrHistoryRead::CurrentStatusRequired
    ));
    let mut wrong_device = reader.clone();
    wrong_device.device_id = fixture.pcr.history.founding_device_id.clone();
    assert!(matches!(
        store
            .security_transactions()
            .human_content_recovery_preparation(&wrong_device, &authorize.event.event_id)
            .await
            .unwrap(),
        HumanPcrHistoryRead::NotApplicable
    ));
    for _ in 0..2 {
        let HumanPcrHistoryRead::Ready { value, guard } = store
            .security_transactions()
            .human_content_recovery_preparation(&reader, &authorize.event.event_id)
            .await
            .unwrap()
        else {
            panic!("current replacement must observe its native episode");
        };
        assert_eq!(value.state, ContentRecoveryPreparationState::Pending);
        assert!(value.inventory_blob_ref.is_none());
        assert_eq!(
            value.pcr_cut,
            CommittedEventRef {
                event_id: authorize.event.event_id.clone(),
                commit_id: authorize.commit.commit_id.clone(),
                stream_ref: authorize.commit.stream_ref.clone(),
                stream_position: authorize.commit.stream_position,
            }
        );
        assert_eq!(
            value.replacement.actor_id,
            ActorId::account(reader.account_id.clone())
        );
        assert_eq!(
            value.replacement.authorization_event_ref,
            authorize.event.event_id
        );
        assert_eq!(
            value.replacement.signature_key_base64url,
            arkret_canonical::base64url_encode(
                SigningKey::from_bytes(&REPLACEMENT_SIGNING_SEED)
                    .verifying_key()
                    .to_bytes()
            )
        );
        guard.finish().await.unwrap();
    }
    assert_eq!(
        footprint(&fixture).await,
        before,
        "reads must not create or advance episodes"
    );
    let mut conn = fixture.pool.get().await.unwrap();
    diesel::sql_query(
        "UPDATE content_recovery_episodes SET pcr_cut=$1 WHERE authorization_event_ref=$2",
    )
    .bind::<Jsonb, _>(
        serde_json::to_value(CommittedEventRef {
            event_id: fixture.write.commits[0].event.event_id.clone(),
            commit_id: fixture.write.commits[0].commit.commit_id.clone(),
            stream_ref: fixture.write.commits[0].commit.stream_ref.clone(),
            stream_position: fixture.write.commits[0].commit.stream_position,
        })
        .unwrap(),
    )
    .bind::<diesel::sql_types::Text, _>(authorize.event.event_id.as_str())
    .execute(&mut conn)
    .await
    .unwrap();
    drop(conn);
    let result = store
        .security_transactions()
        .human_content_recovery_preparation(&reader, &authorize.event.event_id)
        .await;
    let Err(error) = result else {
        panic!("damaged fixed cut must fail");
    };
    assert!(
        error.to_string().contains("revision_unavailable"),
        "{error}"
    );
}

async fn fixture_with_damage(
    config: coland_http::config::AppConfig,
    damage: Option<RecoveryProofDamage>,
) -> Fixture {
    let (state, pool) = coland_test_support::app_state_with_pool(config);
    // A killed test can leave its DDL in a reused, exclusively leased database.
    let mut conn = pool.get().await.unwrap();
    conn.batch_execute("DROP FUNCTION IF EXISTS fail_policy_boundary() CASCADE; DROP FUNCTION IF EXISTS fail_recovery_boundary() CASCADE;").await.unwrap();
    drop(conn);
    let store = state.test_persistence();
    let mut pcr = PcrGenesisFixture::new(state.service_did());
    pcr.admit_founding_device(store.as_ref()).await.unwrap();
    let account = pcr.history.account.clone();
    let realm = pcr.history.events[0].realm_id.clone();
    let now =
        chrono::DateTime::from_timestamp_millis(chrono::Utc::now().timestamp_millis()).unwrap();
    let expires = now + chrono::TimeDelta::minutes(15);
    let policy_id = PolicyId::new(format!("ak:policy:{}", uuid::Uuid::now_v7())).unwrap();
    let mut policy: RecoveryPolicy = serde_json::from_value(json!({
        "schema": "ak.schema.recovery_policy.v1", "policy_id": policy_id,
        "account_id": account, "version": 1, "supersedes_id": null,
        "trust_domain": "ak:trust_domain:fixture.example",
        "issued_at": arkret_canonical::format_timestamp_canonical(now),
        "signature_proof": {"verification_method": pcr.history.device_verification_method,
                      "signature_algorithm": "Ed25519", "signature": "AA"},
        "methods": [{"kind": "did_root"}]
    }))
    .unwrap();
    policy.signature_proof.signature = signature(
        pcr.history.founding_device_signing_seed,
        &recovery_policy_signature_transcript_bytes(&policy).unwrap(),
    );
    let policy_event = pcr.history.event(
        EventKind::PolicySet,
        json!({"policy_id": policy_id, "value": policy}),
    );
    pcr.history.append(vec![policy_event.clone()]);
    let policy_commit = pcr.history.commits.last().unwrap().clone();
    store
        .recovery_policies()
        .commit_publication(RecoveryPolicyPublicationWrite {
            commit: coland_storage::AuthorityCommitTransaction {
                expected_authority: pcr.unit.transactions[1].expected_authority.clone(),
                event: policy_event,
                commit: policy_commit.clone(),
                producer_signer_fact: None,
                content_backup_source: None,
                mls_state: None,
                welcomes: Vec::new(),
                recipient_queue_capacity: 0,
            },
            queued_at: now,
        })
        .await
        .unwrap();
    let predecessor = store
        .authority_commits()
        .stream_head(&policy_commit.stream_ref)
        .await
        .unwrap()
        .unwrap();
    let device_id = DeviceId::new(format!("ak:device:{}", uuid::Uuid::now_v7())).unwrap();
    let session_id =
        RecoverySessionId::new(format!("ak:recovery_session:{}", uuid::Uuid::now_v7())).unwrap();
    let replacement_seed = REPLACEMENT_SIGNING_SEED;
    let replacement_method = DidUrl::new(format!("{}#{device_id}", pcr.history.did)).unwrap();
    let mut authorize_payload = possession_with(
        &account,
        DeviceAuthorizationSpec {
            device_id: device_id.clone(),
            signing_seed: replacement_seed,
            hpke_seed: [97; 32],
            authorized_by: DeviceOrPrincipalRef::Principal(account.principal_id.clone()),
            not_before: now,
            expires_at: None,
            binding: DeviceAuthorizationBindingKind::PcrRecovery,
            authorized_generation_ref: 2,
            applet_id: None,
        },
    );
    // Re-sign the possession transcript after binding this unique session.
    authorize_payload.recovery_session_id = Some(session_id.clone());
    authorize_payload.device_signature = SignatureMaterial::NonEmptyString(
        NonEmptyString::new(
            signature(
                replacement_seed,
                &authorize_payload
                    .device_possession_signature_input(&account)
                    .unwrap(),
            )
            .to_string(),
        )
        .unwrap(),
    );
    if matches!(damage, Some(RecoveryProofDamage::Possession)) {
        authorize_payload.device_signature = SignatureMaterial::NonEmptyString(
            NonEmptyString::new(arkret_canonical::base64url_encode([0; 64])).unwrap(),
        );
    }
    let authorize_value = serde_json::to_value(&authorize_payload).unwrap();
    let root_key = arkret_canonical::ed25519_pubkey_to_did_key_multibase(
        &SigningKey::from_bytes(&[70; 32]).verifying_key().to_bytes(),
    );
    let root_method = DidUrl::new(format!("did:key:{root_key}#{root_key}")).unwrap();
    let context: PublicationAuthorityContext = serde_json::from_value(json!({
        "authority_commit_id": policy_commit.commit_id, "scope_ref": policy_commit.stream_ref,
        "authority_set_policy": {
            "schema": "ak.schema.authority_set_policy.v1", "authority_set_id": AuthoritySetId::RECOVERY_IDENTITY_REANCHOR_V1,
            "policy_kind": "principal_control", "scope_ref": policy_commit.stream_ref,
            "source_commit_id": policy_commit.commit_id,
            "authorization_rules": [{"rule_id": "did_root", "issuer_role": "identity_recovery",
                "allowed_actions": ["ak.device.reanchor"], "issuers": [{"verification_method": root_method}], "threshold": 1}]
        }, "allowed_actions": ["ak.device.reanchor"]
    })).unwrap();
    context.validate_shape().unwrap();
    let context_digest = hash(&context);
    let request_id = RequestId::new(format!("ak:request:{}", uuid::Uuid::now_v7())).unwrap();
    let grant_id = SessionGrantId::from_issuance_digest(arkret_canonical::sha256_bytes(
        session_id.as_str().as_bytes(),
    ));
    let challenge = Base64UrlString::new("Y2hhbGxlbmdl").unwrap();
    let transcript = DidRootRecoveryTranscript {
        schema: RECOVERY_PROOF_TRANSCRIPT_SCHEMA.to_owned(),
        kind: RecoveryProofKind::DidRoot,
        request_id: request_id.clone(),
        session_grant_id: grant_id.clone(),
        session_grant_cnf_jkt: Base64UrlString::new("A".repeat(43)).unwrap(),
        account_id: account.clone(),
        requesting_device_id: device_id.clone(),
        requesting_device_public_key_did: DidKey::new(
            authorize_payload.device_public_key_did.to_string(),
        )
        .unwrap(),
        trust_domain: policy.trust_domain.clone(),
        policy_id: policy_id.clone(),
        policy_version: 1,
        recovery_session_id: session_id.clone(),
        identity_model: RecoveryIdentityModel::PcrPolicy,
        model_generation_ref: 1,
        publication_authority_context_digest: context_digest.clone(),
        challenge: challenge.clone(),
        expires_at: expires,
        created_at: now,
    };
    let proof = RecoverySessionProof::DidRoot(DidRootProofBody {
        kind: DidRootProofKind::DidRoot,
        challenge: challenge.clone(),
        verification_method: root_method,
        signature_algorithm: RecoverySignatureAlgorithm::Ed25519,
        signature: signature(
            [70; 32],
            &arkret_canonical::canonical_json_bytes(&transcript).unwrap(),
        ),
    });
    // This is the verified-session storage input boundary, not a claim that
    // the session HTTP factor verifier was exercised by this fixture.
    store
        .recovery_sessions()
        .insert(RecoverySessionRecord {
            request_id: request_id.to_string(),
            create_intent_digest: hash(&transcript).to_string(),
            recovery_session_id: session_id.to_string(),
            session_grant_id: grant_id.to_string(),
            session_grant_cnf_jkt: "A".repeat(43),
            principal_id: account.principal_id.clone(),
            station_id: account.station_id.clone(),
            requesting_device_id: device_id.to_string(),
            requesting_device_public_key_did: authorize_payload.device_public_key_did.to_string(),
            trust_domain: policy.trust_domain.to_string(),
            policy_id: policy_id.to_string(),
            policy_version: 1,
            identity_model: RecoveryIdentityModel::PcrPolicy,
            current_device_generation_ref: 1,
            accepted_stream_head: predecessor.clone(),
            policy_payload: serde_json::to_value(&policy).unwrap(),
            authority_context: RecoveryAuthorityContext {
                realm_id: realm.clone(),
                authority_generation: 0,
                authority_ref: policy_commit.authority_ref.clone(),
                realm_stream_head: predecessor.clone(),
            },
            publication_authority_context: context,
            publication_authority_context_digest: context_digest,
            challenge: challenge.to_string(),
            state: RecoverySessionLifecycle::Verified,
            proof_payload: Some(json!({"proof": proof})),
            transaction_id: None,
            created_at: now,
            updated_at: now,
            expires_at: expires,
        })
        .await
        .unwrap();
    let reanchor_payload = DeviceReanchorPayload {
        account_id: account.clone(),
        recovery_authority_kind: RecoveryAuthorityKind::PcrPolicy,
        recovery_policy_id: policy_id.clone(),
        recovery_policy_version: 1,
        recovery_session_id: session_id.clone(),
        previous_device_generation: 1,
        new_device_generation: 2,
        did_root_evidence_digest: None,
        replacement_authorize_payload_digest: device_authorize_payload_digest(
            &authorize_value,
            arkret_canonical::DigestSuite::Sha256,
        )
        .unwrap(),
    };
    let mut reanchor = sign_event(
        pcr.history.raw_event(
            EventKind::DeviceReanchor,
            serde_json::to_value(reanchor_payload).unwrap(),
            &realm,
        ),
        replacement_method.clone(),
        replacement_seed,
    );
    let mut authorize = sign_event(
        pcr.history
            .raw_event(EventKind::DeviceAuthorize, authorize_value, &realm),
        replacement_method.clone(),
        replacement_seed,
    );
    let damaged = match damage {
        Some(RecoveryProofDamage::Reanchor) => Some(&mut reanchor),
        Some(RecoveryProofDamage::Authorize) => Some(&mut authorize),
        None | Some(RecoveryProofDamage::Possession) => None,
    };
    if let Some(event) = damaged {
        let proof = event.producer_proof.as_mut().unwrap();
        let (header, _) = proof.jws.split_once("..").unwrap();
        proof.jws = format!("{header}..{}", arkret_canonical::base64url_encode([0; 64]));
    }
    let unit = PreparedEventUnit::new(
        arkret_canonical::DigestSuite::Sha256,
        arkret_wire::EventsSubmitBatchRequestBody {
            events: (vec![reanchor.clone(), authorize.clone()])
                .into_iter()
                .map(arkret_wire::EventAdmissionSubmission::new)
                .collect(),
        },
    )
    .unwrap();
    let intent = RecoveryCommitIntent {
        realm_id: realm,
        predecessor_ref: predecessor.commit_id.clone(),
        unit_event_digests: [
            Hash::new(
                reanchor
                    .event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
                    .unwrap(),
            )
            .unwrap(),
            Hash::new(
                authorize
                    .event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
                    .unwrap(),
            )
            .unwrap(),
        ],
    };
    let receipt_id = ReceiptId::new(format!("ak:receipt:{}", uuid::Uuid::now_v7())).unwrap();
    let plan = PcrPolicyRecoveryPlan {
        binding: PcrPolicyRecoveryBinding {
            identity_model: RecoveryIdentityModel::PcrPolicy,
            recovery_session_id: session_id.clone(),
            replacement_device_id: device_id.clone(),
            reanchor_event_id: reanchor.event_id.clone(),
            authorize_event_id: authorize.event_id.clone(),
            terminal_receipt_id: receipt_id.clone(),
        },
        recovery_session_snapshot_digest: hash(&transcript),
        proof_digest: hash(&proof),
        previous_model_generation_ref: 1,
        new_model_generation_ref: 2,
        reanchor_unit: unit.clone(),
        reanchor_commit_intent: intent.clone(),
    };
    let request = RecoveryTransactionCreateRequestBody::new(
        TransactionId::new(format!("ak:transaction:{}", uuid::Uuid::now_v7())).unwrap(),
        account.clone(),
        expires,
        PcrPolicyRecoveryIntent {
            recovery_session_id: session_id.clone(),
            replacement_device_id: device_id.clone(),
            previous_model_generation_ref: 1,
            new_model_generation_ref: 2,
            terminal_receipt_id: receipt_id.clone(),
            reanchor_unit: unit,
            reanchor_commit_intent: intent,
        },
    )
    .unwrap();
    let (resource, canonical_request) = SecurityTransactionCreateRequestBody::Recovery(request)
        .into_initial_resource(SecurityTransactionPreparedPlan::Recovery(plan), now)
        .unwrap();
    let initial = SecurityTransactionRecord {
        resource,
        canonical_request,
    };
    store
        .security_transactions()
        .create(initial.clone())
        .await
        .unwrap();
    let authority = store
        .authority_commits()
        .current_authority(&pcr.history.events[0].realm_id)
        .await
        .unwrap()
        .unwrap();
    let commits = coland_services::authority_commit::AuthorityCommitApplication::new(
        coland_services::persistence::PersistenceHandle::from_shared(store.clone()),
        0,
    )
    .prepare_recovery_unit_commits(
        &[reanchor, authorize],
        &authority,
        &predecessor,
        pcr.history.authority_method(),
        &SigningKey::from_bytes(
            &coland_test_support::device_authorization_history::STATION_AUTHORITY_SEED,
        ),
        now,
    )
    .unwrap();
    let committed_ref = |index: usize| CommittedEventRef {
        event_id: commits[index].event.event_id.clone(),
        commit_id: commits[index].commit.commit_id.clone(),
        stream_ref: commits[index].commit.stream_ref.clone(),
        stream_position: commits[index].commit.stream_position,
    };
    let mut receipt = RecoveryReceipt {
        schema: SchemaId::RECOVERY_RECEIPT_V1.to_owned(),
        receipt_id: receipt_id.clone(),
        transaction_id: initial.resource.transaction_id.clone(),
        transaction_request_digest: initial.resource.request_digest.clone(),
        prepared_plan_digest: initial.resource.prepared_plan_digest.clone(),
        account_id: account.clone(),
        recovery_session_id: session_id.clone(),
        policy_id,
        policy_version: 1,
        trust_domain: policy.trust_domain.clone(),
        new_device_id: device_id.clone(),
        identity_model: RecoveryIdentityModel::PcrPolicy,
        recovery_authority_kind: RecoveryAuthorityKind::PcrPolicy,
        previous_model_generation_ref: 1,
        new_model_generation_ref: 2,
        authorization_event_id: commits[1].event.event_id.clone(),
        reanchor_event_id: commits[0].event.event_id.clone(),
        proof_summary: RecoveryProofSummary {
            kind: RecoveryProofKind::DidRoot,
            proof_digest: hash(&proof),
            quorum_participant_count: None,
        },
        unlocked_backups: Vec::new(),
        welcome_count: 0,
        welcome_realm_summaries: None,
        outcome: RecoveryReceiptOutcome::Completed,
        outcome_reason_code: None,
        started_at: now,
        completed_at: now,
        signature_proof: RecoveryReceiptSignatureProof {
            verification_method: replacement_method.clone(),
            signature_algorithm: "Ed25519".to_owned(),
            signature: Base64UrlString::new("AA").unwrap(),
        },
        extra: Default::default(),
    };
    receipt.signature_proof.signature = signature(
        replacement_seed,
        &receipt.signature_transcript_bytes().unwrap(),
    );
    let terminal = RecoveryTerminalCommit {
        recovery_receipt: receipt.clone(),
    };
    let mut client_attestation = ClientStepAttestation {
        step: SecurityTransactionStep::CommitRecoveryUnit,
        output_ref: receipt_id.to_string(),
        transaction_id: initial.resource.transaction_id.clone(),
        transaction_request_digest: initial.resource.request_digest.clone(),
        prepared_plan_digest: initial.resource.prepared_plan_digest.clone(),
        artifact: ClientStepAttestationArtifact::Recovery(terminal.clone()),
        signature_proof: ClientStepAttestationSignatureProof {
            verification_method: replacement_method,
            signature_algorithm: "Ed25519".to_owned(),
            signature: Base64UrlString::new("AA").unwrap(),
        },
    };
    client_attestation.signature_proof.signature = signature(
        replacement_seed,
        &client_attestation.signing_bytes().unwrap(),
    );
    let terminal_request = SecurityTransactionContinueRequestBody {
        request_digest: initial.resource.request_digest.clone(),
        prepared_plan_digest: initial.resource.prepared_plan_digest.clone(),
        expected_accepted_step_count: 0,
        client_attestation,
    };
    terminal_request
        .validate_for_transaction(&initial.resource)
        .unwrap();
    let unsigned = UnsignedRecoveryCompletionAttestation::new(
        UnsignedRecoveryCompletionAttestationBody {
            transaction_id: initial.resource.transaction_id.clone(),
            transaction_request_digest: initial.resource.request_digest.clone(),
            prepared_plan_digest: initial.resource.prepared_plan_digest.clone(),
            account_id: account,
            recovery_session_id: session_id,
            terminal_receipt_id: receipt_id.clone(),
            terminal_receipt_digest: hash(&receipt),
            replacement_device_id: device_id,
            new_model_generation_ref: 2,
            completed_at: now,
            reanchor_event_ref: committed_ref(0),
            device_authorization_event_ref: committed_ref(1),
        },
        pcr.history.authority_method(),
    )
    .unwrap();
    let completion_signature = signature(
        coland_test_support::device_authorization_history::STATION_AUTHORITY_SEED,
        &unsigned.signing_bytes().unwrap(),
    );
    let completion = unsigned.attach_signature(completion_signature).unwrap();
    let mut completed = initial.clone();
    completed
        .resource
        .accepted_steps
        .push(AcceptedSecurityTransactionStep {
            acceptor: SecurityTransactionAcceptor::Principal {
                principal_id: state.service_core_id(),
            },
            accepted_at: now,
        });
    completed.resource.terminal_outcome = Some(SecurityTransactionTerminalOutcome::Completed {
        completed_at: now,
        receipt_id: Some(receipt_id),
        completion_attestation: Some(completion),
    });
    let write = RecoveryUnitCommitWrite {
        step_outcome: SecurityTransactionStepOutcomeRecord {
            transaction_id: completed.resource.transaction_id.to_string(),
            step: SecurityTransactionStep::CommitRecoveryUnit,
            canonical_request: arkret_canonical::canonical_json_bytes(&terminal_request).unwrap(),
            response: serde_json::to_value(&completed.resource).unwrap(),
            participant_outcome: Some(serde_json::to_value(terminal).unwrap()),
        },
        transaction: completed,
        predecessor,
        commits,
        queued_at: now,
    };
    write.validate().unwrap();
    Fixture {
        state,
        pool,
        pcr,
        initial,
        write,
    }
}

#[derive(diesel::QueryableByName)]
struct JsonRow {
    #[diesel(sql_type = Jsonb)]
    value: Value,
}

async fn footprint(fixture: &Fixture) -> Value {
    let mut conn = fixture.pool.get().await.unwrap();
    let mut result = serde_json::Map::new();
    for table in [
        "canonical_events",
        "realm_commits",
        "realm_commit_event_kinds",
        "realm_authorities",
        "recovery_policies",
        "policy_current_states",
        "agent_producer_signer_keys",
        "content_recovery_episodes",
        "content_recovery_census_sources",
        "content_keypackage_signature_history",
        "content_endpoint_admission_history",
        "ordinary_keypackage_claim_sources",
        "keypackage_claim_sources",
        "keypackage_claim_attempts",
        "peer_keypackage_claims",
        "account_device_signer_evidence",
        "mls_key_packages",
        "devices",
        "pcr_device_generation_current_states",
        "pcr_device_authorization_current_states",
        "account_global_versions",
        "account_global_clock",
        "account_global_channel_clocks",
        "security_transactions",
        "security_transaction_step_attempts",
        "security_transaction_step_outcomes",
        "recovery_sessions",
        "device_messages",
    ] {
        let row = diesel::sql_query(format!("SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text),'[]'::jsonb) AS value FROM {table} t"))
            .get_result::<JsonRow>(&mut conn).await.unwrap();
        result.insert(table.to_owned(), row.value);
    }
    Value::Object(result)
}

async fn assert_old_device_fenced(fixture: &Fixture) {
    let realm_id = RealmId::from_event_id(&EventId::from_digest(
        arkret_canonical::DigestSuite::Sha256,
        arkret_canonical::sha256_bytes(uuid::Uuid::now_v7().as_bytes()),
    ));
    let event = sign_event(
        fixture.pcr.history.raw_event(
            EventKind::RealmProfile,
            arkret_models_collaboration::events_payloads::RealmProfile::new("fenced attempt")
                .unwrap()
                .to_value()
                .unwrap(),
            &realm_id,
        ),
        fixture.pcr.history.device_verification_method.clone(),
        fixture.pcr.history.founding_device_signing_seed,
    );
    let before = footprint(fixture).await;
    let error = coland_http::test_forward_self_event(
        &fixture.state,
        &DidCoreId::new("ak:did_core:web:remote.example").unwrap(),
        EventAdmissionSubmission::new(event.clone()),
    )
    .await
    .unwrap_err();
    assert_eq!(
        error
            .conflict_code()
            .map(coland_storage::ConflictCode::as_str),
        Some("device_generation_fenced"),
        "{error}"
    );
    let store = fixture.state.test_persistence();
    assert!(
        store
            .authority_commits()
            .queued_event(&event.event_id)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .authority_commits()
            .committed_event(&event.event_id)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .authority_commits()
            .stream_head(&CommitStreamRef::Realm { realm_id })
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(footprint(fixture).await, before);
}

#[tokio::test]
async fn recovery_terminal_unit_fences_old_device_and_replays_after_response_loss() {
    let fixture = fixture().await;
    let store = fixture.state.test_persistence();
    // Discard the first result, then retry through a freshly constructed PG adapter.
    store
        .security_transactions()
        .commit_recovery_unit(fixture.write.clone())
        .await
        .unwrap();
    let before = footprint(&fixture).await;
    let restarted = coland_storage_postgres::PgSecurityTransactionStore {
        pool: fixture.pool.clone(),
    };
    use coland_storage::SecurityTransactionStore as _;
    let replay = restarted
        .commit_recovery_unit(fixture.write.clone())
        .await
        .unwrap();
    assert_eq!(replay.response, fixture.write.step_outcome.response);
    assert_eq!(footprint(&fixture).await, before);
    let head = store
        .authority_commits()
        .stream_head(&fixture.write.predecessor.stream_ref)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(head.commit_id, fixture.write.commits[1].commit.commit_id);
    let session = store
        .recovery_sessions()
        .get(
            fixture
                .initial
                .resource
                .recovery_plan()
                .unwrap()
                .binding
                .recovery_session_id
                .as_str(),
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(session.state, RecoverySessionLifecycle::Completed);
    assert_old_device_fenced(&fixture).await;
    let mut changed = fixture.write.clone();
    // Different canonical input cannot reuse the first outcome, even when
    // its outer request remains structurally well formed.
    let mut request: SecurityTransactionContinueRequestBody =
        serde_json::from_slice(&fixture.write.step_outcome.canonical_request).unwrap();
    request.client_attestation.signature_proof.signature = Base64UrlString::new("AQ").unwrap();
    changed.step_outcome.canonical_request =
        arkret_canonical::canonical_json_bytes(&request).unwrap();
    assert!(matches!(
        restarted.commit_recovery_unit(changed).await,
        Err(coland_storage::PersistenceError::Conflict(_))
    ));
    assert_eq!(footprint(&fixture).await, before);
}

async fn assert_recovery_original_has_immutable_signer(slot: usize) {
    use coland_storage::AuthorityCommitStore as _;

    let fixture = fixture().await;
    let account = &fixture.pcr.history.account;
    let target = &fixture.write.commits[slot];
    let authorization = &fixture.write.commits[1];
    let payload: arkret_models_collaboration::events_payloads::DeviceAuthorizePayload =
        serde_json::from_value(serde_json::to_value(&authorization.event.payload).unwrap())
            .unwrap();
    let coordinate = |transaction: &coland_storage::AuthorityCommitTransaction| CommittedEventRef {
        event_id: transaction.event.event_id.clone(),
        commit_id: transaction.commit.commit_id.clone(),
        stream_ref: transaction.commit.stream_ref.clone(),
        stream_position: transaction.commit.stream_position,
    };
    let proof = target.event.producer_proof.as_ref().unwrap();
    let selector = SignerKeyQuerySelector::HistoricalEvent {
        sender: HistoricalSignerKeyQuerySender::AccountDevice {
            actor: target.event.actual_signer().clone(),
            device_id: payload.device_id.clone(),
            verification_method: proof.verification_method.clone(),
            committed_event_ref: coordinate(target),
        },
    };
    let reader = coland_storage_postgres::PgAuthorityCommitStore {
        pool: fixture.pool.clone(),
    };
    assert!(
        reader
            .historical_self_pcr_producer_signer_key(&target.event.realm_id, &selector, account)
            .await
            .unwrap()
            .is_none(),
        "a prepared recovery is not an accepted historical source"
    );
    fixture
        .state
        .test_persistence()
        .security_transactions()
        .commit_recovery_unit(fixture.write.clone())
        .await
        .unwrap();
    // A fresh adapter must consume the original acceptance, not a process cache
    // or the replacement Device's optional display/authorization mirror.
    let restarted = coland_storage_postgres::PgAuthorityCommitStore {
        pool: fixture.pool.clone(),
    };
    let outcome = restarted
        .historical_self_pcr_producer_signer_key(&target.event.realm_id, &selector, account)
        .await
        .unwrap();
    let Some(SignerKeyResolution::HistoricalResolved {
        selector: returned,
        key,
        accepted_at,
    }) = outcome
    else {
        panic!("accepted recovery original {slot} lacks its immutable historical signer");
    };
    assert_eq!(returned, selector);
    assert_eq!(key.authorization_ref, coordinate(authorization));
    assert_eq!(key.revision.commit_id, authorization.commit.commit_id);
    assert_eq!(
        key.revision.stream_position,
        authorization.commit.stream_position
    );
    assert_eq!(key.governance_generation, 0);
    assert_eq!(accepted_at, authorization.commit.committed_at);
    let expected_key = SigningKey::from_bytes(&REPLACEMENT_SIGNING_SEED).verifying_key();
    let bytes = arkret_canonical::base64url_decode(key.public_key_base64url.as_str()).unwrap();
    assert_eq!(bytes, expected_key.to_bytes());
    arkret_signatures::verify_ed25519_detached_jws_proof_with_digest_suite(
        proof,
        &arkret_signatures::EventProofBuilder::new()
            .envelope_bytes(&target.event)
            .unwrap(),
        &target.event.actor_id,
        &arkret_signatures::PublicKeyMaterial::Ed25519Raw { bytes },
        target.event.realm_id.digest_suite_code().digest_suite(),
    )
    .unwrap();
}

#[tokio::test]
async fn recovery_reanchor_retains_its_immutable_historical_signer() {
    assert_recovery_original_has_immutable_signer(0).await;
}

#[tokio::test]
async fn recovery_authorize_retains_its_immutable_historical_signer() {
    assert_recovery_original_has_immutable_signer(1).await;
}

#[tokio::test]
async fn recovery_policy_retains_its_immutable_historical_signer_after_replacement() {
    use coland_storage::AuthorityCommitStore as _;

    let fixture = fixture().await;
    let policy_event = fixture.pcr.history.events.last().unwrap();
    let policy_commit = fixture.pcr.history.commits.last().unwrap();
    assert_eq!(policy_event.kind, EventKind::PolicySet);
    let account = &fixture.pcr.history.account;
    let selector = SignerKeyQuerySelector::HistoricalEvent {
        sender: HistoricalSignerKeyQuerySender::AccountDevice {
            actor: policy_event.actual_signer().clone(),
            device_id: fixture.pcr.history.founding_device_id.clone(),
            verification_method: policy_event
                .producer_proof
                .as_ref()
                .unwrap()
                .verification_method
                .clone(),
            committed_event_ref: CommittedEventRef {
                event_id: policy_event.event_id.clone(),
                commit_id: policy_commit.commit_id.clone(),
                stream_ref: policy_commit.stream_ref.clone(),
                stream_position: policy_commit.stream_position,
            },
        },
    };
    fixture
        .state
        .test_persistence()
        .security_transactions()
        .commit_recovery_unit(fixture.write.clone())
        .await
        .unwrap();
    assert_old_device_fenced(&fixture).await;
    let reader = coland_storage_postgres::PgAuthorityCommitStore {
        pool: fixture.pool.clone(),
    };
    let outcome = reader
        .historical_self_pcr_producer_signer_key(&policy_event.realm_id, &selector, account)
        .await
        .unwrap();
    let Some(SignerKeyResolution::HistoricalResolved {
        selector: returned,
        key,
        accepted_at,
    }) = outcome
    else {
        panic!("accepted recovery policy lost its original signer after the old Device was fenced");
    };
    assert_eq!(returned, selector);
    let founding = &fixture.pcr.unit.transactions[1];
    assert_eq!(key.authorization_ref.event_id, founding.event.event_id);
    assert_eq!(key.authorization_ref.commit_id, founding.commit.commit_id);
    assert_eq!(accepted_at, founding.commit.committed_at);
}

async fn assert_bad_recovery_proof_rolls_back(damage: RecoveryProofDamage) {
    let fixture = fixture_with_damage(coland_test_support::app_config(), Some(damage)).await;
    let before = footprint(&fixture).await;
    assert!(
        fixture
            .state
            .test_persistence()
            .security_transactions()
            .commit_recovery_unit(fixture.write.clone())
            .await
            .is_err()
    );
    assert_eq!(footprint(&fixture).await, before);
}

#[tokio::test]
async fn recovery_unit_rejects_invalid_reanchor_signature_without_history_residue() {
    assert_bad_recovery_proof_rolls_back(RecoveryProofDamage::Reanchor).await;
}

#[tokio::test]
async fn recovery_unit_rejects_invalid_authorize_signature_without_history_residue() {
    assert_bad_recovery_proof_rolls_back(RecoveryProofDamage::Authorize).await;
}

#[tokio::test]
async fn recovery_unit_rejects_invalid_possession_without_history_residue() {
    assert_bad_recovery_proof_rolls_back(RecoveryProofDamage::Possession).await;
}

#[tokio::test]
async fn completed_recovery_device_is_admitted_without_inventory_projection() {
    let fixture = fixture_with_config(http_common::test_config()).await;
    let old_token = http_common::dev_token_for_device(
        fixture.state.clone(),
        fixture.pcr.history.did.as_str(),
        fixture.pcr.history.founding_device_id.as_str(),
        "Old device",
    )
    .await;
    let store = fixture.state.test_persistence();
    store
        .security_transactions()
        .commit_recovery_unit(fixture.write.clone())
        .await
        .unwrap();
    let payload: arkret_models_collaboration::events_payloads::DeviceAuthorizePayload =
        serde_json::from_value(
            serde_json::to_value(&fixture.write.commits[1].event.payload).unwrap(),
        )
        .unwrap();
    let account = &fixture.pcr.history.account;
    let missing = store
        .devices()
        .get(account.principal_id.as_str(), payload.device_id.as_str())
        .await
        .unwrap();
    assert!(
        missing.is_none(),
        "the fixture must not supply an authorization mirror"
    );
    let selector = coland_http::test_active_device_revocation_gate_selector(
        &fixture.state,
        account.principal_id.as_str(),
        payload.device_id.as_str(),
    )
    .await
    .unwrap();
    let committed = &fixture.write.commits[1];
    assert_eq!(
        selector.authorization_ref,
        CommittedEventRef {
            event_id: committed.event.event_id.clone(),
            commit_id: committed.commit.commit_id.clone(),
            stream_ref: committed.commit.stream_ref.clone(),
            stream_position: committed.commit.stream_position,
        }
    );
    let gates = coland_storage_postgres::PgDeviceRevocationStore {
        pool: fixture.pool.clone(),
    };
    assert_eq!(
        gates
            .test_gate_status_in_transaction(&selector)
            .await
            .unwrap(),
        coland_storage::DeviceRevocationGateStatus::Active
    );
    let mut wrong = selector;
    wrong.authorization_ref = CommittedEventRef {
        event_id: fixture.write.commits[0].event.event_id.clone(),
        commit_id: fixture.write.commits[0].commit.commit_id.clone(),
        stream_ref: fixture.write.commits[0].commit.stream_ref.clone(),
        stream_position: fixture.write.commits[0].commit.stream_position,
    };
    assert_eq!(
        gates.test_gate_status_in_transaction(&wrong).await.unwrap(),
        coland_storage::DeviceRevocationGateStatus::GenerationMismatch
    );
    assert_old_device_fenced(&fixture).await;

    let token = http_common::dev_token_for_device(
        fixture.state.clone(),
        fixture.pcr.history.did.as_str(),
        payload.device_id.as_str(),
        "Recovered device",
    )
    .await;
    let preparation_url = format!(
        "http://server/_arkret/self/mls/content-recoveries/{}",
        fixture.write.commits[1].event.event_id
    );
    let before_read = footprint(&fixture).await;
    let mut denied = Vec::new();
    for token in [None, Some(&old_token), Some(&token)] {
        let mut request = http_common::TestClient::get(&preparation_url);
        if let Some(token) = token {
            request = request.add_header("authorization", format!("Bearer {token}"), true);
        }
        let mut response = request
            .send(&http_common::app_from_state(fixture.state.clone()))
            .await;
        assert_eq!(
            response.status_code,
            Some(salvo::http::StatusCode::NOT_FOUND)
        );
        let body: Value = response.take_json().await.unwrap();
        assert_eq!(http_common::problem_code(&body), "not_found");
        assert_eq!(body["detail"], "content recovery preparation not found");
        assert!(body.get("instance").is_none(), "{body}");
        denied.push(body);
    }
    assert!(denied.windows(2).all(|pair| pair[0] == pair[1]));
    assert_eq!(
        footprint(&fixture).await,
        before_read,
        "GET must not create or advance an episode"
    );
    let unknown_episode = format!(
        "http://server/_arkret/self/mls/content-recoveries/{}",
        fixture.write.commits[0].event.event_id
    );
    let response = http_common::TestClient::get(&unknown_episode)
        .add_header("authorization", format!("Bearer {token}"), true)
        .send(&http_common::app_from_state(fixture.state.clone()))
        .await;
    assert_eq!(
        response.status_code,
        Some(salvo::http::StatusCode::NOT_FOUND)
    );
    // Development login may create optional display metadata. It must not
    // become an authorization requirement for a natively accepted recovery.
    let mut conn = fixture.pool.get().await.unwrap();
    diesel::sql_query("DELETE FROM devices WHERE actor_id = $1 AND device_id = $2")
        .bind::<diesel::sql_types::Text, _>(account.principal_id.as_str())
        .bind::<diesel::sql_types::Text, _>(payload.device_id.as_str())
        .execute(&mut conn)
        .await
        .unwrap();
    drop(conn);
    let unknown = DeviceId::new(format!("ak:device:{}", uuid::Uuid::now_v7())).unwrap();
    let mut device_ids = vec![
        payload.device_id.clone(),
        fixture.pcr.history.founding_device_id.clone(),
        unknown,
    ];
    device_ids.sort();
    let request = KeysQueryRequestBody {
        device_keys: vec![QueryAccountDeviceSelector {
            account_id: account.clone(),
            device_ids,
        }],
        timeout_ms: None,
    };
    let mut response = http_common::TestClient::post("http://server/_arkret/self/keys/query")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&request)
        .send(&http_common::app_from_state(fixture.state.clone()))
        .await;
    let response_body: Value = response.take_json().await.unwrap();
    assert_eq!(
        response.status_code,
        Some(salvo::http::StatusCode::OK),
        "{response_body}"
    );
    let historical_selector = |event: &Event, commit: &RealmCommit| {
        let producer = event.account_device_producer().unwrap().unwrap();
        SignerKeyQuerySelector::HistoricalEvent {
            sender: HistoricalSignerKeyQuerySender::AccountDevice {
                actor: event.actual_signer().clone(),
                device_id: producer.device_id,
                verification_method: event
                    .producer_proof
                    .as_ref()
                    .unwrap()
                    .verification_method
                    .clone(),
                committed_event_ref: CommittedEventRef {
                    event_id: event.event_id.clone(),
                    commit_id: commit.commit_id.clone(),
                    stream_ref: commit.stream_ref.clone(),
                    stream_position: commit.stream_position,
                },
            },
        }
    };
    let mut queries: Vec<_> = fixture
        .write
        .commits
        .iter()
        .map(|transaction| historical_selector(&transaction.event, &transaction.commit))
        .collect();
    queries.push(historical_selector(
        fixture.pcr.history.events.last().unwrap(),
        fixture.pcr.history.commits.last().unwrap(),
    ));
    let historical_request = arkret_models_identity::SignerKeysQueryRequestBody {
        request_id: format!("ak:request:{}", uuid::Uuid::now_v7())
            .parse()
            .unwrap(),
        realm_id: committed.event.realm_id.clone(),
        recipient_account_id: Some(account.clone()),
        recipient_actor_id: None,
        queries,
    };
    let mut historical_response =
        http_common::TestClient::post("http://server/_arkret/self/signer-keys/query")
            .add_header("authorization", format!("Bearer {token}"), true)
            .add_header("content-type", "application/json", true)
            .body(arkret_canonical::canonical_json_bytes(&historical_request).unwrap())
            .send(&http_common::app_from_state(fixture.state.clone()))
            .await;
    let historical_body: Value = historical_response.take_json().await.unwrap();
    assert_eq!(
        historical_response.status_code,
        Some(salvo::http::StatusCode::OK),
        "{historical_body}"
    );
    let historical: arkret_models_identity::SignerKeyQueryResponseBody =
        serde_json::from_value(historical_body).unwrap();
    historical
        .validate_for_request(&historical_request)
        .unwrap();
    assert!(
        historical
            .resolutions
            .iter()
            .all(|resolution| matches!(resolution, SignerKeyResolution::HistoricalResolved { .. }))
    );
    let keys: KeysQueryResponseBody = serde_json::from_value(response_body).unwrap();
    let rows = keys
        .devices_for(account)
        .expect("the exact account is visible");
    let row = rows
        .get(&payload.device_id)
        .expect("accepted recovery device must have an authoring projection without inventory");
    assert_eq!(
        rows.len(),
        1,
        "old-generation and unknown devices stay hidden"
    );
    assert_eq!(
        row.device_projection.device_signing_key_did.as_str(),
        payload.device_public_key_did.as_str(),
    );
    assert_eq!(row.device_projection.hpke_key, payload.hpke_key);
    assert_eq!(
        row.device_projection.device_authorize_event_id,
        committed.event.event_id,
    );
    assert_eq!(
        row.device_projection.authorized_generation_ref,
        payload.authorized_generation_ref,
    );
    assert!(row.is_usable_in_generation(keys.generation_for(account)));
    let retained = store
        .account_device_signer_evidence()
        .get(account, &payload.device_id, &row.signer_evidence_ref)
        .await
        .unwrap()
        .expect("the complete signed authoring root is retained");
    assert_eq!(
        retained
            .device_projection_attestation
            .attestation
            .device_signing_key_did
            .as_str(),
        payload.device_public_key_did.as_str(),
    );
    assert!(
        store
            .devices()
            .get(account.principal_id.as_str(), payload.device_id.as_str())
            .await
            .unwrap()
            .is_none(),
        "directory reads must not manufacture a second authorization mirror"
    );
    let recovered_event = &committed.event;
    let proof = recovered_event.producer_proof.as_ref().unwrap();
    let envelope = arkret_signatures::proof::EventProofBuilder::new()
        .envelope_bytes(recovered_event)
        .unwrap();
    let verified_key = coland_http::jws_verify::verify_principal_authorized_event_proof_async(
        proof,
        &envelope,
        &recovered_event.actor_id,
        proof.verification_method.as_str(),
        account.principal_id.as_str(),
        &fixture.state,
    )
    .await
    .expect("native recovery authority must verify Event authoring without inventory");
    assert_eq!(
        verified_key.as_str(),
        payload.device_public_key_did.as_str()
    );
    let raw_input = b"recovered-device-proof-regression";
    for (seed, should_verify) in [(REPLACEMENT_SIGNING_SEED, true), ([95; 32], false)] {
        let proof_result = coland_http::jws_verify::verify_principal_authorized_ed25519_signature_with_account_authority_async(
            raw_input,
            signature(seed, raw_input).as_str(),
            proof.verification_method.as_str(),
            account,
            &payload.device_id,
            &fixture.state,
        ).await;
        assert_eq!(proof_result.is_ok(), should_verify, "{proof_result:?}");
    }

    let mls_identity = arkret_mls::ArkretMlsIdentity::new_human_device(
        ActorId::account(account.clone()),
        payload.device_id.clone(),
        arkret_mls::ArkretMlsSigner::from_ed25519_signing_key(SigningKey::from_bytes(
            &REPLACEMENT_SIGNING_SEED,
        )),
    )
    .unwrap();
    let package = mls_identity.key_package_record().unwrap();
    let package_upload = mls_identity
        .signed_key_packages_upload_request(&[package], proof.verification_method.as_str())
        .unwrap();
    let mut published =
        http_common::TestClient::post("http://server/_arkret/self/keys/keypackages/upload")
            .add_header("authorization", format!("Bearer {token}"), true)
            .add_header("content-type", "application/json", true)
            .body(arkret_canonical::canonical_json_bytes(&package_upload).unwrap())
            .send(&http_common::app_from_state(fixture.state.clone()))
            .await;
    let published_body: Value = published.take_json().await.unwrap();
    assert_eq!(
        published.status_code,
        Some(salvo::http::StatusCode::CONFLICT),
        "{published_body}"
    );
    assert_eq!(
        http_common::problem_code(&published_body),
        "failed_precondition"
    );
    let mut viewer_response =
        http_common::TestClient::get("http://server/_arkret/self/account/viewer")
            .add_header("authorization", format!("Bearer {token}"), true)
            .send(&http_common::app_from_state(fixture.state.clone()))
            .await;
    assert_eq!(
        viewer_response.status_code,
        Some(salvo::http::StatusCode::OK)
    );
    let viewer: Value = viewer_response.take_json().await.unwrap();
    let recovered = viewer["devices"]
        .as_array()
        .unwrap()
        .iter()
        .find(|device| device["device_id"] == payload.device_id.as_str())
        .expect("cold-start viewer must include the natively recovered device");
    assert_eq!(recovered["status"], "active");
    assert_eq!(recovered["verification_state"], "verified");
    assert_eq!(recovered["verification_source"], "recovery");

    let unsigned = KeysUploadFields {
        device_id: payload.device_id.clone(),
        one_time_keys: Default::default(),
        fallback_keys: Default::default(),
    };
    let signing_input = keys_upload_signing_input(&unsigned).unwrap();
    for (seed, expected_status) in [
        ([95; 32], salvo::http::StatusCode::BAD_REQUEST),
        (REPLACEMENT_SIGNING_SEED, salvo::http::StatusCode::OK),
    ] {
        let upload = unsigned.clone().into_signed(KeyOperationSignature {
            kid: NonEmptyString::new(payload.device_public_key_did.to_string()).unwrap(),
            signature_algorithm: Some(NonEmptyString::new("Ed25519").unwrap()),
            signature: signature(seed, &signing_input),
        });
        let mut response = http_common::TestClient::post("http://server/_arkret/self/keys/upload")
            .add_header("authorization", format!("Bearer {token}"), true)
            .add_header("content-type", "application/json", true)
            .body(arkret_canonical::canonical_json_bytes(&upload).unwrap())
            .send(&http_common::app_from_state(fixture.state.clone()))
            .await;
        let body: Value = response.take_json().await.unwrap();
        assert_eq!(response.status_code, Some(expected_status), "{body}");
        let bundle = store
            .device_keys()
            .get(account.principal_id.as_str(), payload.device_id.as_str())
            .await
            .unwrap();
        if expected_status == salvo::http::StatusCode::BAD_REQUEST {
            assert!(
                bundle.is_none(),
                "wrong signer must not persist any key material"
            );
        } else {
            assert_eq!(bundle.unwrap()["device_id"], payload.device_id.as_str());
        }
    }
    // A metadata write by keys/upload must not replace the native authority.
    let mut reopened = http_common::TestClient::post("http://server/_arkret/self/keys/query")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&request)
        .send(&http_common::app_from_state(fixture.state.clone()))
        .await;
    assert_eq!(reopened.status_code, Some(salvo::http::StatusCode::OK));
    let reopened: KeysQueryResponseBody = reopened.take_json().await.unwrap();
    let reopened_row = reopened
        .devices_for(account)
        .unwrap()
        .get(&payload.device_id)
        .unwrap();
    let mut expected_projection = row.device_projection.clone();
    assert!(reopened_row.device_projection.attested_at >= expected_projection.attested_at);
    expected_projection.attested_at = reopened_row.device_projection.attested_at;
    expected_projection.expires_at = reopened_row.device_projection.expires_at;
    assert_eq!(reopened_row.device_projection, expected_projection);
}

#[tokio::test]
async fn recovery_terminal_metadata_must_bind_the_exact_receipt_and_response() {
    let fixture = fixture().await;
    let before = footprint(&fixture).await;
    for case in 0..6 {
        let mut write = fixture.write.clone();
        match case {
            0 => write.step_outcome.response = json!({"unrelated":"response"}),
            1 => write.step_outcome.participant_outcome = None,
            2 => {
                write.step_outcome.participant_outcome.as_mut().unwrap()["recovery_receipt"]["signature_proof"]
                    ["signature"] = json!("AQ")
            }
            3 => {
                let Some(SecurityTransactionTerminalOutcome::Completed {
                    completion_attestation: Some(completion),
                    ..
                }) = &mut write.transaction.resource.terminal_outcome
                else {
                    unreachable!()
                };
                completion.terminal_receipt_digest = hash("different receipt");
                write.step_outcome.response =
                    serde_json::to_value(&write.transaction.resource).unwrap();
            }
            4 => {
                let mut request: SecurityTransactionContinueRequestBody =
                    serde_json::from_slice(&write.step_outcome.canonical_request).unwrap();
                request.expected_accepted_step_count = 1;
                write.step_outcome.canonical_request =
                    arkret_canonical::canonical_json_bytes(&request).unwrap();
            }
            5 => {
                let mut request: SecurityTransactionContinueRequestBody =
                    serde_json::from_slice(&write.step_outcome.canonical_request).unwrap();
                request
                    .client_attestation
                    .signature_proof
                    .verification_method = DidUrl::new("did:web:another.example#device").unwrap();
                write.step_outcome.canonical_request =
                    arkret_canonical::canonical_json_bytes(&request).unwrap();
            }
            _ => unreachable!(),
        }
        assert!(
            matches!(
                fixture
                    .state
                    .test_persistence()
                    .security_transactions()
                    .commit_recovery_unit(write)
                    .await,
                Err(coland_storage::PersistenceError::SchemaViolation(_))
            ),
            "case {case}"
        );
        assert_eq!(
            footprint(&fixture).await,
            before,
            "case {case} wrote durable state"
        );
    }
    fixture
        .state
        .test_persistence()
        .security_transactions()
        .commit_recovery_unit(fixture.write.clone())
        .await
        .unwrap();
    assert_old_device_fenced(&fixture).await;
}

async fn policy_revocation_write(fixture: &mut Fixture) -> RecoveryPolicyPublicationWrite {
    let store = fixture.state.test_persistence();
    let active = store
        .recovery_policies()
        .get_active_for_account(&fixture.pcr.history.account)
        .await
        .unwrap()
        .unwrap();
    let mut revoke: RecoveryPolicy = serde_json::from_value(active.raw_payload).unwrap();
    revoke.supersedes_id = Some(revoke.policy_id.clone());
    revoke.policy_id = PolicyId::new(format!("ak:policy:{}", uuid::Uuid::now_v7())).unwrap();
    revoke.version = 2;
    revoke.methods.clear();
    revoke.signature_proof.signature = signature(
        fixture.pcr.history.founding_device_signing_seed,
        &recovery_policy_signature_transcript_bytes(&revoke).unwrap(),
    );
    let event = fixture.pcr.history.event(
        EventKind::PolicySet,
        json!({"policy_id":revoke.policy_id,"value":revoke}),
    );
    fixture.pcr.history.append(vec![event.clone()]);
    let commit = fixture.pcr.history.commits.last().unwrap().clone();
    RecoveryPolicyPublicationWrite {
        commit: coland_storage::AuthorityCommitTransaction {
            expected_authority: fixture.pcr.unit.transactions[1].expected_authority.clone(),
            event,
            commit: commit.clone(),
            producer_signer_fact: None,
            content_backup_source: None,
            mls_state: None,
            welcomes: Vec::new(),
            recipient_queue_capacity: 0,
        },
        queued_at: chrono::Utc::now(),
    }
}

#[tokio::test]
async fn accepted_policy_revocation_refuses_a_prepared_recovery_without_fencing() {
    let mut fixture = fixture().await;
    let write = policy_revocation_write(&mut fixture).await;
    let store = fixture.state.test_persistence();
    store
        .recovery_policies()
        .commit_publication(write)
        .await
        .unwrap();
    let before = footprint(&fixture).await;
    assert!(
        store
            .security_transactions()
            .commit_recovery_unit(fixture.write.clone())
            .await
            .is_err()
    );
    assert_eq!(footprint(&fixture).await, before);
    assert_eq!(
        store
            .security_transactions()
            .get(fixture.initial.resource.transaction_id.as_str())
            .await
            .unwrap()
            .unwrap()
            .resource,
        fixture.initial.resource
    );
}

#[tokio::test]
async fn policy_revocation_boundaries_roll_back_and_response_loss_replays_without_writes() {
    let mut fixture = fixture().await;
    let history_len = fixture.pcr.history.events.len();
    let write = policy_revocation_write(&mut fixture).await;
    fixture.pcr.history.events.truncate(history_len);
    fixture.pcr.history.commits.truncate(history_len);
    // A second valid publication is prepared at the same original PCR cut.
    let conflicting = policy_revocation_write(&mut fixture).await;
    let before = footprint(&fixture).await;
    for (table, condition) in [
        ("canonical_events", "NEW.kind='ak.policy.set'"),
        ("realm_commits", "TRUE"),
        ("realm_commit_event_kinds", "TRUE"),
        ("policy_current_states", "TRUE"),
        ("recovery_policies", "TRUE"),
        ("recovery_sessions", "NEW.state='rejected'"),
    ] {
        let mut conn = fixture.pool.get().await.unwrap();
        conn.batch_execute(&format!("CREATE FUNCTION fail_policy_boundary() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF {condition} THEN RAISE EXCEPTION 'injected policy durable boundary'; END IF; RETURN NEW; END $$; CREATE TRIGGER fail_policy_boundary BEFORE INSERT OR UPDATE ON {table} FOR EACH ROW EXECUTE FUNCTION fail_policy_boundary();")).await.unwrap();
        drop(conn);
        let result = fixture
            .state
            .test_persistence()
            .recovery_policies()
            .commit_publication(write.clone())
            .await;
        let mut conn = fixture.pool.get().await.unwrap();
        conn.batch_execute(&format!(
            "DROP TRIGGER fail_policy_boundary ON {table}; DROP FUNCTION fail_policy_boundary();"
        ))
        .await
        .unwrap();
        drop(conn);
        let error = result.unwrap_err();
        assert!(
            error
                .to_string()
                .contains("injected policy durable boundary"),
            "{table}: {error}"
        );
        assert_eq!(footprint(&fixture).await, before, "rollback at {table}");
    }
    fixture
        .state
        .test_persistence()
        .recovery_policies()
        .commit_publication(write.clone())
        .await
        .unwrap();
    let accepted = footprint(&fixture).await;
    use coland_storage::RecoveryPolicyStore as _;
    let restarted = coland_storage_postgres::PgRecoveryPolicyStore {
        pool: fixture.pool.clone(),
    };
    let replay = restarted.commit_publication(write.clone()).await.unwrap();
    let coland_storage::RecoveryPolicyPublicationOutcome::Duplicate(policy) = replay else {
        panic!("policy replay created a second acceptance")
    };
    assert_eq!(policy.acceptance_basis, write.commit.commit.commit_id);
    assert_eq!(footprint(&fixture).await, accepted);
    assert!(matches!(
        restarted.commit_publication(conflicting).await,
        Err(coland_storage::PersistenceError::Conflict(_))
    ));
    assert_eq!(footprint(&fixture).await, accepted);
    let session = fixture
        .state
        .test_persistence()
        .recovery_sessions()
        .get(
            fixture
                .initial
                .resource
                .recovery_plan()
                .unwrap()
                .binding
                .recovery_session_id
                .as_str(),
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(session.state, RecoverySessionLifecycle::Rejected);
    let current = restarted
        .get_active_for_account(&fixture.pcr.history.account)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(current.version, 2);
    assert_eq!(current.acceptance_basis, write.commit.commit.commit_id);
}

#[tokio::test]
async fn every_recovery_durable_boundary_rolls_back_both_commits_and_terminal_ledger() {
    let fixture = fixture().await;
    retain_own_claim_intent(&fixture).await;
    let before = footprint(&fixture).await;
    let first = fixture.write.commits[0].commit.stream_position;
    let second = fixture.write.commits[1].commit.stream_position;
    for (table, condition) in [
        (
            "canonical_events",
            "NEW.kind='ak.device.reanchor'".to_owned(),
        ),
        ("realm_commits", format!("NEW.stream_position={first}")),
        (
            "realm_commit_event_kinds",
            "NEW.kind='ak.device.reanchor'".to_owned(),
        ),
        ("pcr_device_generation_current_states", "TRUE".to_owned()),
        (
            "canonical_events",
            "NEW.kind='ak.device.authorize'".to_owned(),
        ),
        ("realm_commits", format!("NEW.stream_position={second}")),
        (
            "realm_commit_event_kinds",
            "NEW.kind='ak.device.authorize'".to_owned(),
        ),
        ("pcr_device_authorization_current_states", "TRUE".to_owned()),
        ("content_recovery_episodes", "TRUE".to_owned()),
        ("content_recovery_census_sources", "TRUE".to_owned()),
        ("account_global_versions", "TRUE".to_owned()),
        ("account_global_clock", "TRUE".to_owned()),
        ("account_global_channel_clocks", "TRUE".to_owned()),
        ("security_transaction_step_attempts", "TRUE".to_owned()),
        ("security_transaction_step_outcomes", "TRUE".to_owned()),
        (
            "security_transactions",
            "NEW.terminal_outcome IS NOT NULL".to_owned(),
        ),
        ("recovery_sessions", "NEW.state='completed'".to_owned()),
    ] {
        let mut conn = fixture.pool.get().await.unwrap();
        conn.batch_execute(&format!("CREATE FUNCTION fail_recovery_boundary() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF {condition} THEN RAISE EXCEPTION 'injected recovery durable boundary'; END IF; RETURN NEW; END $$; CREATE TRIGGER fail_recovery_boundary BEFORE INSERT OR UPDATE ON {table} FOR EACH ROW EXECUTE FUNCTION fail_recovery_boundary();")).await.unwrap();
        drop(conn);
        let result = fixture
            .state
            .test_persistence()
            .security_transactions()
            .commit_recovery_unit(fixture.write.clone())
            .await;
        let mut conn = fixture.pool.get().await.unwrap();
        conn.batch_execute(&format!("DROP TRIGGER fail_recovery_boundary ON {table}; DROP FUNCTION fail_recovery_boundary();")).await.unwrap();
        drop(conn);
        let error = result.unwrap_err();
        assert!(
            error
                .to_string()
                .contains("injected recovery durable boundary"),
            "{table}: {error}"
        );
        assert_eq!(footprint(&fixture).await, before, "rollback at {table}");
    }
    // A failed attempt must not freeze bytes or consume the session; the same
    // corrected terminal input can still become the first accepted outcome.
    fixture
        .state
        .test_persistence()
        .security_transactions()
        .commit_recovery_unit(fixture.write.clone())
        .await
        .unwrap();
    assert_old_device_fenced(&fixture).await;
}
