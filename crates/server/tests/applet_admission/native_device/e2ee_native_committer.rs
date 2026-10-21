//! A real Applet Device commits Add and supplies its independently signed Welcome.
use coland_storage::{DeviceMessageStore as _, MlsKeyPackageStore as _};

use super::super::keypackage;
use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bot_and_ghost_commit_real_add_and_complete_welcome_without_session() {
    for ghost in [false, true] {
        for circle in [false, true] {
            tokio::spawn(native_phase(|| originate(ghost, Case::AddWelcome, circle)))
                .await
                .unwrap();
        }
    }
}

async fn submit(
    state: &AppState,
    authority: &coland_storage::AppletManagedDeviceAuthority,
    key: &SigningKey,
    scope: &ScopeRef,
    request: &SelfAuthoritySubmitRequest,
) -> (StatusCode, Vec<u8>) {
    let SelfAuthoritySubmitRequest::MlsCommit(unit) = request else {
        panic!("complete MLS unit required");
    };
    let mut metadata = managed_device_metadata(authority);
    metadata.effective_scope = scope.clone();
    let token = unit.idempotency_key.as_uuid().to_string();
    let mut response = managed_device_http_request_with_idempotency_at(
        state,
        authority,
        &metadata,
        ServiceOperationId::SelfEventsCommandSubmitV1,
        key,
        Some(arkret_canonical::canonical_json_bytes(request).unwrap()),
        None,
        &token,
    )
    .add_header("content-type", "application/json", true)
    .send(&service(state.clone()))
    .await;
    (
        response.status_code.unwrap(),
        response.take_bytes(None).await.unwrap().to_vec(),
    )
}

struct Checkpoint(std::path::PathBuf);
impl Drop for Checkpoint {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}
fn checkpoint<T: serde::Serialize>(value: &T) -> Checkpoint {
    use std::io::Write as _;
    let path =
        std::env::temp_dir().join(format!("arkret-native-add-{}.json", uuid::Uuid::now_v7()));
    let mut options = std::fs::OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options.open(&path).unwrap();
    file.write_all(&arkret_canonical::canonical_json_bytes(value).unwrap())
        .unwrap();
    file.sync_all().unwrap();
    #[cfg(unix)]
    std::fs::File::open(path.parent().unwrap())
        .unwrap()
        .sync_all()
        .unwrap();
    Checkpoint(path)
}

pub(super) async fn exercise(
    fixture: &Fixture,
    install: &Installed,
    authority: &coland_storage::AppletManagedDeviceAuthority,
    key: &SigningKey,
    scope: &ScopeRef,
    child: &arkret_wire::GrantId,
    group: &mut arkret_mls::ArkretMlsGroup,
) {
    let _read = native_phase(|| {
        native_business_parent_in_scope(
            fixture,
            install,
            vec![],
            vec!["ak.event.read".into()],
            None,
            scope.clone(),
        )
    })
    .await;
    let human = &fixture.pcr.history.account;
    let human_key = SigningKey::from_bytes(&fixture.pcr.history.founding_device_signing_seed);
    let identity = arkret_mls::ArkretMlsIdentity::new_human_device(
        ActorId::account(human.clone()),
        fixture.pcr.history.founding_device_id.clone(),
        arkret_mls::ArkretMlsSigner::from_ed25519_signing_key(human_key.clone()),
    )
    .unwrap();
    let upload = keypackage::fresh_upload(
        &identity,
        fixture.pcr.history.device_verification_method.as_str(),
        &human_key,
        scope,
    );
    let upload_body = serde_json::to_value(&upload).unwrap();
    let (status, value) = native_phase(|| {
        fixture.admin_post(
            "/_arkret/self/keys/keypackages/upload",
            ServiceOperationId::SelfKeysKeypackagesUploadCreateV1.as_str(),
            &upload_body,
            None,
        )
    })
    .await;
    assert_eq!(status, StatusCode::OK, "actual Human package: {value}");
    assert_eq!(value["accepted"], 1);
    let mut command =
        keypackage::claim::request(authority, key, scope, &upload.keypackages[0].keypackage_ref);
    command.target_actor_id = None;
    command.target_account_id = Some(human.clone());
    command.target_device_ids = vec![fixture.pcr.history.founding_device_id.clone()];
    keypackage::claim::resign(&mut command, key);
    let (status, value) =
        native_phase(|| keypackage::claim::claim(fixture, authority, key, scope, &command)).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "native committer claims actual Human: {value}"
    );
    let claim: arkret_models_crypto::KeyPackagesClaimOutcome =
        serde_json::from_value(value).unwrap();
    let receipt = &claim.claim_receipt;
    arkret_signatures::keypackages::verify_keypackage_signing_input(
        &fixture
            .state
            .notary_signing_key()
            .verifying_key()
            .to_bytes(),
        receipt.signature.kid.as_str(),
        &arkret_models_crypto::peer_keypackage_claim_receipt_signing_bytes(receipt).unwrap(),
        &receipt.signature,
    )
    .unwrap();
    let packages = coland_storage_postgres::PgMlsKeyPackageStore {
        pool: fixture.pool.clone(),
    };
    let claim_id = &claim.claims[0].claim_id;
    let original_claim = native_phase(|| packages.get_peer_claim_by_claim_id(claim_id))
        .await
        .unwrap()
        .unwrap();
    let store = PgAuthorityCommitStore {
        pool: fixture.pool.clone(),
    };
    let groups = coland_storage_postgres::PgMlsGroupCurrentStore {
        pool: fixture.pool.clone(),
    };
    let current = native_phase(|| groups.current(scope))
        .await
        .unwrap()
        .unwrap();
    let binding = MlsGovernanceBindingPayload::new(
        scope.clone(),
        Some(current.value.current_mls_commit_event_ref.clone()),
        current.value.epoch,
        current.value.epoch + 1,
        current.value.current_key_access_revision,
    )
    .unwrap();
    let package = arkret_mls::mls_key_package_record_from_claim(&claim.claims[0]).unwrap();
    let mut bindings = group.verified_leaf_bindings().unwrap();
    let added = group
        .add_member_with_governance_binding(&package, &binding)
        .unwrap();
    let at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    let payload = MlsCommitPayload::new(
        current.value.current_mls_commit_event_ref.clone(),
        current.value.current_key_access_revision,
        &added.commit,
        binding,
    )
    .unwrap();
    let event = original_event(
        install,
        authority,
        key,
        child,
        scope,
        EventKind::MlsCommit,
        serde_json::to_value(payload).unwrap(),
        at,
    );
    let mut welcome = arkret_wire::MlsWelcomeDelivery {
        welcome_id: arkret_wire::MlsWelcomeDeliveryId::new(format!(
            "ak:mls_welcome_delivery:{}",
            uuid::Uuid::now_v7()
        ))
        .unwrap(),
        realm_id: scope.realm_id().clone(),
        effective_scope: scope.clone(),
        commit_event_ref: event.event_id.clone(),
        recipient_actor_id: ActorId::account(human.clone()),
        recipient_endpoint: arkret_wire::MlsWelcomeRecipientEndpoint::Device {
            device_id: fixture.pcr.history.founding_device_id.clone(),
        },
        keypackage_claim_ref: added.welcome.keypackage_claim_ref.clone(),
        ciphertext_b64: added.welcome.ciphertext_b64.clone(),
        producer_proof: arkret_signatures::detached_object::sign_detached_object(
            &Value::Null,
            arkret_wire::DetachedSignatureContext::MlsWelcomeDelivery,
            arkret_wire::DidUrl::new(format!("{}#{}", authority.native_did, authority.device_id))
                .unwrap(),
            at,
            key,
        )
        .unwrap(),
    };
    welcome.producer_proof = arkret_signatures::detached_object::sign_detached_object(
        &arkret_canonical::canonical::unsigned_value(&welcome, &["producer_proof"]).unwrap(),
        arkret_wire::DetachedSignatureContext::MlsWelcomeDelivery,
        welcome.producer_proof.verification_method.clone(),
        at,
        key,
    )
    .unwrap();
    welcome.validate_shape().unwrap();
    let request = SelfAuthoritySubmitRequest::MlsCommit(MlsCommitSubmission {
        commit_event: event.clone(),
        welcomes: vec![welcome.clone()],
        idempotency_key: arkret_wire::UuidV7::new(uuid::Uuid::now_v7()).unwrap(),
    });
    // Freeze the exact complete unit, accepted base and SDK pending state before its first
    // network attempt. This is a test checkpoint, not a production runtime.
    let frozen = checkpoint(&(
        &request,
        group.export_state_record().unwrap(),
        &current.value,
    ));
    let (request, pending, base_current): (
        SelfAuthoritySubmitRequest,
        arkret_models_crypto::MlsGroupStateRecord,
        arkret_wire::MlsGroupCurrent,
    ) = serde_json::from_slice(&std::fs::read(&frozen.0).unwrap()).unwrap();
    *group = arkret_mls::ArkretMlsGroup::restore_from_state_record(&pending).unwrap();
    assert!(group.has_pending_commit());
    let mut missing = request.clone();
    let SelfAuthoritySubmitRequest::MlsCommit(unit) = &mut missing else {
        unreachable!()
    };
    unit.idempotency_key = arkret_wire::UuidV7::new(uuid::Uuid::now_v7()).unwrap();
    unit.welcomes.clear();
    let before = native_phase(|| business(fixture)).await;
    let (status, bytes) =
        native_phase(|| submit(&fixture.state, authority, key, scope, &missing)).await;
    assert!(
        !status.is_success(),
        "Add without Welcome accepted: {}",
        String::from_utf8_lossy(&bytes)
    );
    assert_eq!(before, native_phase(|| business(fixture)).await);
    assert_eq!(
        original_claim,
        native_phase(|| packages.get_peer_claim_by_claim_id(claim_id))
            .await
            .unwrap()
            .unwrap()
    );
    let mut wrong = request.clone();
    let SelfAuthoritySubmitRequest::MlsCommit(unit) = &mut wrong else {
        unreachable!()
    };
    unit.idempotency_key = arkret_wire::UuidV7::new(uuid::Uuid::now_v7()).unwrap();
    unit.welcomes[0].producer_proof.sig =
        arkret_wire::Base64UrlString::new(arkret_canonical::base64url_encode([0u8; 64])).unwrap();
    let (status, bytes) =
        native_phase(|| submit(&fixture.state, authority, key, scope, &wrong)).await;
    assert!(
        !status.is_success(),
        "wrong Welcome signature accepted: {}",
        String::from_utf8_lossy(&bytes)
    );
    assert_eq!(before, native_phase(|| business(fixture)).await);
    assert_eq!(
        original_claim,
        native_phase(|| packages.get_peer_claim_by_claim_id(claim_id))
            .await
            .unwrap()
            .unwrap()
    );
    let (status, first) =
        native_phase(|| submit(&fixture.state, authority, key, scope, &request)).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "native complete Add: {}",
        String::from_utf8_lossy(&first)
    );
    let accepted = native_phase(|| store.committed_event(&event.event_id))
        .await
        .unwrap()
        .unwrap();
    let accepted = arkret_wire::CommittedEventFullView {
        event: accepted.event,
        commit: accepted.commit,
    };
    let landed = native_phase(|| groups.current(scope))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(landed.value.epoch, 1);
    group
        .install_accepted_commit(&accepted, &base_current)
        .unwrap();
    assert_eq!(group.epoch(), 1);
    let queue = coland_storage_postgres::PgDeviceMessageStore {
        pool: fixture.pool.clone(),
    };
    let selector = coland_storage::RecipientQueueSelector::HumanDevice {
        recipient: human.principal_id.to_string(),
        device_id: fixture.pcr.history.founding_device_id.to_string(),
    };
    let rows = native_phase(|| queue.list_recipient_deliveries(&selector, 0, 20))
        .await
        .unwrap();
    let queued = rows
        .iter()
        .find_map(|row| match &row.delivery {
            arkret_models_collaboration::device_messages::RecipientDelivery::MlsWelcome {
                mls_welcome,
            } if mls_welcome.welcome_id == welcome.welcome_id => Some(mls_welcome),
            _ => None,
        })
        .expect("native Welcome must be durably queued for exact recipient");
    assert_eq!(queued, &welcome);
    arkret_signatures::detached_object::verify_detached_object_signature(
        &queued.producer_proof,
        &arkret_canonical::canonical::unsigned_value(queued, &["producer_proof"]).unwrap(),
        arkret_wire::DetachedSignatureContext::MlsWelcomeDelivery,
        &arkret_signatures::PublicKeyMaterial::Ed25519Raw {
            bytes: authority.public_key.to_vec(),
        },
    )
    .unwrap();
    let endpoint = garth::mls::LocalMlsEndpoint::device(
        scope.realm_id().clone(),
        ActorId::account(human.clone()),
        fixture.pcr.history.founding_device_id.clone(),
    );
    garth::mls::verify_welcome_claim(
        queued,
        &endpoint,
        &accepted.event,
        &claim,
        &fixture.state.service_core_id(),
        &fixture.pcr.history.events[1].event_id,
    )
    .unwrap();
    let mut joined = arkret_mls::ArkretMlsGroup::join_from_verified_welcome_delivery(
        identity, queued, &accepted,
    )
    .unwrap();
    let claimed_leaf = arkret_mls::author_leaf_from_key_package_bytes(
        &arkret_canonical::base64url_decode(&claim.claims[0].keypackage).unwrap(),
        0,
    )
    .unwrap();
    let leaves = joined.active_author_leaves();
    let mut added_leaves = leaves.iter().filter(|leaf| {
        leaf.signature_key == claimed_leaf.signature_key
            && leaf.credential == claimed_leaf.credential
    });
    let leaf = added_leaves
        .next()
        .expect("the exact claimed leaf is present");
    assert!(added_leaves.next().is_none());
    bindings.push(arkret_mls::MlsVerifiedLeafBinding {
        leaf_index: leaf.leaf_index,
        actor_id: claim.claims[0].actor_id.clone(),
        endpoint: arkret_models_crypto::MlsEndpointIdentity::HumanDevice {
            principal_id: claim.claims[0].principal_id.clone(),
            device_id: claim.claims[0].device_id.clone().unwrap(),
        },
        signature_key: arkret_wire::Base64UrlString::new(arkret_canonical::base64url_encode(
            &claimed_leaf.signature_key,
        ))
        .unwrap(),
        device_authorize_event_id: claim.claims[0].device_authorize_event_id.clone(),
    });
    joined
        .install_verified_leaf_bindings(bindings.clone())
        .unwrap();
    group.install_verified_leaf_bindings(bindings).unwrap();
    assert_eq!(joined.epoch(), group.epoch());
    // Independent recipient/committer secrets agree after real Welcome join;
    // neither side is handed another endpoint's private group state.
    assert!(
        joined
            .export_secret("native-add", b"acceptance", 32)
            .unwrap()
            .as_slice()
            == group
                .export_secret("native-add", b"acceptance", 32)
                .unwrap()
                .as_slice()
    );
    let private = checkpoint(&(
        group.export_state_record().unwrap(),
        joined.export_state_record().unwrap(),
    ));
    let (sender, recipient): (
        arkret_models_crypto::MlsGroupStateRecord,
        arkret_models_crypto::MlsGroupStateRecord,
    ) = serde_json::from_slice(&std::fs::read(&private.0).unwrap()).unwrap();
    let sender = arkret_mls::ArkretMlsGroup::restore_from_state_record(&sender).unwrap();
    let recipient = arkret_mls::ArkretMlsGroup::restore_from_state_record(&recipient).unwrap();
    assert_eq!(sender.epoch(), recipient.epoch());
    assert!(
        sender
            .export_secret("native-add", b"cold", 32)
            .unwrap()
            .as_slice()
            == recipient
                .export_secret("native-add", b"cold", 32)
                .unwrap()
                .as_slice()
    );
    let before = native_phase(|| business(fixture)).await;
    let reopened = native_phase(|| {
        coland_test_support::app_state_with_persistence(
            fixture.state.config().clone(),
            std::sync::Arc::new(coland_storage_postgres::PgPersistenceStore::new(
                fixture.pool.clone(),
            )),
        )
    })
    .await;
    native_phase(|| reopened.hydrate()).await.unwrap();
    let (status, replay) =
        native_phase(|| submit(&reopened, authority, key, scope, &request)).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "cold exact Add retry: {}",
        String::from_utf8_lossy(&replay)
    );
    assert_eq!(first, replay);
    assert_eq!(before, native_phase(|| business(fixture)).await);
}
