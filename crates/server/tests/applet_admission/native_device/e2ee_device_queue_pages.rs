//! Real consecutive Welcomes prove cumulative ACK and acknowledged-prefix pruning.
use super::*;
pub(in super::super) struct Prior {
    pub page: arkret_models_collaboration::device_messages::DeviceMessagesGetOutcome,
    _private: PrivateGroupFile,
}

pub(in super::super) async fn first(
    fixture: &Fixture,
    install: &Installed,
    authority: &coland_storage::AppletManagedDeviceAuthority,
    key: &SigningKey,
    method: &str,
    scope: &ScopeRef,
    genesis: &mut MlsGenesisRuntime,
    ack_first: bool,
) -> Prior {
    let identity = arkret_mls::ArkretMlsIdentity::new_realm_device(
        authority.actor_id.clone(),
        authority.device_id.clone(),
        arkret_mls::ArkretMlsSigner::from_ed25519_signing_key(key.clone()),
    )
    .unwrap();
    let upload = fresh_upload(&identity, method, key, scope);
    assert_eq!(
        native_phase(|| upload_in_scope(fixture, authority, key, &upload, scope))
            .await
            .0,
        StatusCode::OK
    );
    let human_key = SigningKey::from_bytes(&fixture.pcr.history.founding_device_signing_seed);
    let mut command = request(authority, key, scope, &upload.keypackages[0].keypackage_ref);
    command.requester_actor_id = None;
    command.requester_account_id = Some(fixture.pcr.history.account.clone());
    account_requester(&fixture, &mut command);
    resign(&mut command, &human_key);
    let body = serde_json::to_value(&command).unwrap();
    let (status, value) = native_phase(|| {
        fixture.admin_post(
            "/_arkret/self/keys/keypackages/claim",
            ServiceOperationId::SelfKeysKeypackagesCommandClaimV1.as_str(),
            &body,
            Some(command.claim_request_id.as_str()),
        )
    })
    .await;
    assert_eq!(status, StatusCode::OK, "actual first-page claim: {value}");
    let outcome: arkret_models_crypto::KeyPackagesClaimOutcome =
        serde_json::from_value(value).unwrap();
    let guard = coland_storage::AppletManagedDeviceScopeGuard {
        authority: authority.clone(),
        effective_scope: scope.clone(),
        service_did_document: applet_service_id_document(&install.package),
    };
    let groups = coland_storage_postgres::PgMlsGroupCurrentStore {
        pool: fixture.pool.clone(),
    };
    let base = native_phase(|| groups.current(scope))
        .await
        .unwrap()
        .unwrap();
    let (welcome, accepted, mut bindings) = native_phase(|| {
        accepted_add(
            fixture,
            authority,
            scope,
            genesis,
            &outcome.claims[0],
            &guard,
        )
    })
    .await;
    let page = native_phase(|| assert_initial_list(fixture, authority, key, scope, &welcome)).await;
    let query = arkret_models_crypto::KeyPackagesClaimQueryRequestBody {
        claim_id: welcome.keypackage_claim_ref.clone(),
    };
    let (status, bytes) =
        native_phase(|| query_wire(&fixture.state, authority, key, scope, &query)).await;
    assert_eq!(status, StatusCode::OK);
    let read: arkret_models_crypto::KeyPackagesClaimOutcome =
        serde_json::from_slice(&bytes).unwrap();
    let receipt = &read.claim_receipt;
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
    let endpoint = garth::mls::LocalMlsEndpoint::device(
        scope.realm_id().clone(),
        authority.actor_id.clone(),
        authority.device_id.clone(),
    );
    let realm_authority = native_phase(|| verified_realm_authority(fixture)).await;
    let verified = garth::mls::verify_welcome_claim(
        &welcome,
        &endpoint,
        &accepted.event,
        &read,
        garth::mls::WelcomeClaimAuthority::Realm {
            current_station: realm_authority.current_service_id(),
            authority: &realm_authority,
        },
        &authority.authorization_ref.event_id,
    )
    .unwrap();
    let mut joined = arkret_mls::ArkretMlsGroup::join_from_verified_welcome_delivery(
        identity, &welcome, &accepted,
    )
    .unwrap();
    let package_leaf = arkret_mls::author_leaf_from_key_package_bytes(
        &arkret_canonical::base64url_decode(&verified.keypackage).unwrap(),
        0,
    )
    .unwrap();
    let leaves = joined.active_author_leaves();
    let matching = leaves
        .iter()
        .filter(|leaf| {
            leaf.signature_key == package_leaf.signature_key
                && leaf.credential == package_leaf.credential
        })
        .collect::<Vec<_>>();
    assert_eq!(matching.len(), 1);
    bindings.push(arkret_mls::MlsVerifiedLeafBinding {
        leaf_index: matching[0].leaf_index,
        actor_id: verified.actor_id.clone(),
        endpoint: arkret_models_crypto::MlsEndpointIdentity::HumanDevice {
            principal_id: verified.principal_id.clone(),
            device_id: verified.device_id.clone().unwrap(),
        },
        signature_key: arkret_wire::Base64UrlString::new(arkret_canonical::base64url_encode(
            &package_leaf.signature_key,
        ))
        .unwrap(),
        device_authorize_event_id: verified.device_authorize_event_id.clone(),
    });
    joined.install_verified_leaf_bindings(bindings).unwrap();
    let private = PrivateGroupFile(std::env::temp_dir().join(format!(
        "arkret-native-mls-prior-{}.json",
        uuid::Uuid::now_v7()
    )));
    let mut options = std::fs::OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    {
        use std::io::Write as _;
        let mut file = options.open(&private.0).unwrap();
        file.write_all(&arkret_canonical::canonical_json_bytes(&json!({"group":joined.export_state_record().unwrap(),"claim":read,"welcome":welcome,"accepted":accepted})).unwrap()).unwrap();
        file.sync_all().unwrap();
    }
    #[cfg(unix)]
    std::fs::File::open(private.0.parent().unwrap())
        .unwrap()
        .sync_all()
        .unwrap();
    let saved: Value = serde_json::from_slice(&std::fs::read(&private.0).unwrap()).unwrap();
    let restored = arkret_mls::ArkretMlsGroup::restore_from_state_record(
        &serde_json::from_value(saved["group"].clone()).unwrap(),
    )
    .unwrap();
    assert_eq!(restored.epoch(), 1);
    assert_eq!(saved["claim"], serde_json::to_value(&read).unwrap());
    let consume = garth::mls::signed_welcome_consume(
        &welcome,
        &read,
        arkret_models_crypto::RecipientMlsDurableSigner::RealmDevice {
            recipient_actor_id: authority.actor_id.clone(),
            recipient_device_id: authority.device_id.clone(),
            device_verification_method: arkret_wire::DidUrl::new(method.to_owned()).unwrap(),
        },
        &fixture.state.service_core_id(),
        restored.epoch(),
        chrono::Utc::now(),
        |method, bytes| {
            Ok(
                arkret_signatures::keypackages::keypackage_signature_from_bytes(
                    method,
                    &key.sign(bytes).to_bytes(),
                )
                .unwrap(),
            )
        },
    )
    .unwrap();
    let (status, bytes) =
        native_phase(|| consume_wire(fixture, authority, key, scope, &consume)).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "first page consumes only after durable private group and original claim: {}",
        String::from_utf8_lossy(&bytes)
    );
    if ack_first {
        native_phase(|| {
            assert_ack(
                fixture,
                authority,
                key,
                scope,
                page.ack_token.as_deref().unwrap(),
                1,
            )
        })
        .await;
    }
    genesis
        .group
        .install_accepted_commit(&accepted, &base.value)
        .unwrap();
    genesis
        .group
        .install_verified_leaf_bindings(joined.verified_leaf_bindings().unwrap())
        .unwrap();
    genesis.accepted = accepted;
    Prior {
        page,
        _private: private,
    }
}

pub(in super::super) async fn next(
    fixture: &Fixture,
    authority: &coland_storage::AppletManagedDeviceAuthority,
    key: &SigningKey,
    scope: &ScopeRef,
    prior: &Prior,
    welcome: &arkret_wire::MlsWelcomeDelivery,
) -> arkret_models_collaboration::device_messages::DeviceMessagesGetOutcome {
    let path = format!(
        "/_arkret/self/device_messages?after={}&limit=1",
        prior.page.next_cursor.as_deref().unwrap()
    );
    let mut response =
        native_phase(|| list_response(fixture, authority, key, scope, Some(&path))).await;
    let status = response.status_code.unwrap();
    let bytes = response.take_bytes(None).await.unwrap();
    assert_eq!(
        status,
        StatusCode::OK,
        "actual continued second-page Welcome: {}",
        String::from_utf8_lossy(&bytes)
    );
    let page: arkret_models_collaboration::device_messages::DeviceMessagesGetOutcome =
        serde_json::from_slice(&bytes).unwrap();
    assert_eq!(page.deliveries.len(), 1);
    assert!(
        matches!(&page.deliveries[0],arkret_models_collaboration::device_messages::RecipientDelivery::MlsWelcome{mls_welcome} if mls_welcome==welcome)
    );
    assert_ne!(page.ack_token, prior.page.ack_token);
    assert_ne!(page.next_cursor, prior.page.next_cursor);
    assert!(!page.has_more);
    page
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn actual_consecutive_welcomes_ack_cumulatively_and_prune_previously_acknowledged_positions()
{
    for ghost in [false, true] {
        for fenced in [false, true] {
            tokio::spawn(native_phase(|| {
                exercise_consume(ghost, fenced, None, GroupCase::QueuePages)
            }))
            .await
            .unwrap();
        }
    }
}
