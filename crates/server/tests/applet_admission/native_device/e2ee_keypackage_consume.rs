//! Actual native recipient, accepted Add/Welcome and durable private group.
use arkret_models_crypto::{MlsCommitPayload, MlsGovernanceBindingPayload};
use coland_storage::{
    DeviceMessageStore as _, EventCommitUnitOfWork as _, MlsGroupCurrentStore as _,
};

use super::*;
#[path = "e2ee_device_queue.rs"]
mod queue;
#[path = "managed_runtime_welcome.rs"]
mod runtime;
struct PrivateGroupFile(std::path::PathBuf);
impl Drop for PrivateGroupFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_recipient_consumes_a_real_durable_welcome_without_session() {
    for ghost in [false, true] {
        for fenced in [false, true] {
            tokio::spawn(native_phase(|| {
                exercise_consume(ghost, fenced, None, GroupCase::Realm)
            }))
            .await
            .unwrap();
        }
    }
}
#[derive(Clone, Copy)]
enum AddRefusal {
    InstallFence,
    ClaimExpiry,
    ClaimExpiryWhileQueued,
}
#[derive(Clone, Copy)]
enum GroupCase {
    Realm,
    Circle,
    LastResort,
    QueueList,
    QueueClaimExpiry,
    QueueScopes,
    QueuePages,
    QueueBackendDrop,
}
async fn exercise_consume(ghost: bool, fenced: bool, refusal: Option<AddRefusal>, case: GroupCase) {
    let fixture = native_phase(Fixture::new).await;
    let mut scope = ScopeRef::Realm {
        realm_id: fixture.realm.clone(),
    };
    let mut genesis =
        native_phase(|| activate_mls_with_private_state(&fixture, scope.clone())).await;
    let namespace = format!("bridge.{}", uuid::Uuid::now_v7().simple());
    let native = mls_service(&fixture, &namespace);
    let install =
        native_phase(|| fixture.install_package(true, native.package.clone(), &namespace)).await;
    let bundle = if ghost {
        let body = native_phase(|| fixture.ghost_body(&install, &namespace, "claim-device")).await;
        assert_eq!(
            native_phase(|| fixture.ghost_commit(&install, &body, "claim-device"))
                .await
                .0,
            StatusCode::OK
        );
        body["event"].clone()
    } else {
        install.bot_body["event"].clone()
    };
    let key = SigningKey::from_bytes(&[177; 32]);
    let device = DeviceId::new(format!("ak:device:{}", uuid::Uuid::now_v7())).unwrap();
    let mut authority = native_phase(|| {
        authorize(
            &fixture,
            &install,
            &bundle,
            &namespace,
            &key,
            device.clone(),
            true,
        )
    })
    .await;
    let event = join_event(&fixture, &install, &authority, &key, &install.join_grant());
    let (status, outcome) = native_phase(|| post(&fixture, &authority, &key, &event, vec![])).await;
    assert_eq!(status, StatusCode::OK, "real native membership: {outcome}");
    let mut sibling_scope = None;
    if matches!(case, GroupCase::Circle | GroupCase::QueueScopes) {
        authority = native_phase(|| {
            circle_membership(
                &fixture, &install, &namespace, &bundle, &authority, &key, false,
            )
        })
        .await;
        let circle_scope = authority
            .scopes
            .entries()
            .iter()
            .find(|pair| matches!(pair.effective_scope, ScopeRef::Circle { .. }))
            .unwrap()
            .effective_scope
            .clone();
        if matches!(case, GroupCase::Circle) {
            scope = circle_scope;
            genesis =
                native_phase(|| activate_mls_with_private_state(&fixture, scope.clone())).await;
        } else {
            sibling_scope = Some(circle_scope);
        }
    }
    let _read_parent = native_phase(|| {
        native_business_parent_in_scope(
            &fixture,
            &install,
            vec![],
            vec!["ak.event.read".into()],
            None,
            scope.clone(),
        )
    })
    .await;
    let identity = arkret_mls::ArkretMlsIdentity::new_realm_device(
        authority.actor_id.clone(),
        device,
        arkret_mls::ArkretMlsSigner::from_ed25519_signing_key(key.clone()),
    )
    .unwrap();
    let fingerprint =
        arkret_canonical::ed25519_pubkey_to_did_key_multibase(key.verifying_key().as_bytes());
    let method = format!("did:key:{fingerprint}#{fingerprint}");

    let prior = if matches!(case, GroupCase::QueuePages) {
        Some(
            native_phase(|| {
                queue::pages::first(
                    &fixture,
                    &install,
                    &authority,
                    &key,
                    &method,
                    &scope,
                    &mut genesis,
                    ghost,
                )
            })
            .await,
        )
    } else {
        None
    };
    let native_ack_count = if prior.is_some() && !ghost { 2 } else { 1 };
    let sibling = if let Some(other) = &sibling_scope {
        Some(
            native_phase(|| {
                queue::accepted_sibling(
                    &fixture, &install, &authority, &key, &identity, &method, other,
                )
            })
            .await,
        )
    } else {
        None
    };
    let mut upload = fresh_upload(&identity, &method, &key, &scope);
    if matches!(case, GroupCase::LastResort) {
        let mut unsigned = upload.unsigned();
        unsigned.keypackages[0].last_resort = Some(true);
        upload = sign_upload(unsigned, &method, &key);
    }
    assert_eq!(
        native_phase(|| upload_in_scope(&fixture, &authority, &key, &upload, &scope))
            .await
            .0,
        StatusCode::OK
    );
    let human_key = SigningKey::from_bytes(&fixture.pcr.history.founding_device_signing_seed);
    let mut command = request(
        &authority,
        &key,
        &scope,
        &upload.keypackages[0].keypackage_ref,
    );
    command.requester_actor_id = None;
    command.requester_account_id = Some(fixture.pcr.history.account.clone());
    account_requester(&fixture, &mut command);
    if matches!(
        refusal,
        Some(AddRefusal::ClaimExpiry | AddRefusal::ClaimExpiryWhileQueued)
    ) || matches!(case, GroupCase::QueueClaimExpiry)
    {
        command.expires_at = arkret_canonical::normalize_timestamp_canonical(
            chrono::Utc::now()
                + chrono::Duration::seconds(
                    if matches!(refusal, Some(AddRefusal::ClaimExpiryWhileQueued)) {
                        4
                    } else {
                        15
                    },
                ),
        );
    }
    if matches!(case, GroupCase::LastResort) {
        command.last_resort_allowed = Some(true);
        command.target_keypackage_ref = None;
    }
    resign(&mut command, &human_key);
    let value = serde_json::to_value(&command).unwrap();
    let (status, value) = native_phase(|| {
        fixture.admin_post(
            "/_arkret/self/keys/keypackages/claim",
            ServiceOperationId::SelfKeysKeypackagesCommandClaimV1.as_str(),
            &value,
            Some(command.claim_request_id.as_str()),
        )
    })
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "actual Human committer claims native recipient package: {value}"
    );
    let outcome: arkret_models_crypto::KeyPackagesClaimOutcome =
        serde_json::from_value(value).unwrap();
    let claim = outcome.claims[0].clone();
    let target_guard = coland_storage::AppletManagedDeviceScopeGuard {
        authority: authority.clone(),
        effective_scope: scope.clone(),
        service_did_document: applet_service_id_document(&install.package),
    };
    if let Some(refusal) = refusal {
        if matches!(refusal, AddRefusal::InstallFence) {
            native_phase(|| fixture.revoke(&install)).await;
        }
        let (_, prepared, _) = native_phase(|| {
            prepare_add(
                &fixture,
                &authority,
                &scope,
                &mut genesis,
                &claim,
                &target_guard,
            )
        })
        .await;
        if matches!(refusal, AddRefusal::ClaimExpiry) {
            // Keep the already prepared, genuine Add unchanged across expiry.
            // Only the real wall clock advances; no stale-head change can
            // account for the refusal.
            tokio::time::sleep(std::time::Duration::from_secs(16)).await;
        }
        let before = native_phase(|| business_snapshot(&fixture)).await;
        let uow = coland_storage_postgres::PgEventCommitUnitOfWork::new(fixture.pool.clone());
        if matches!(refusal, AddRefusal::ClaimExpiryWhileQueued) {
            native_phase(|| {
                queue::assert_http_queue_expiry(&fixture, &prepared, command.expires_at)
            })
            .await;
            assert_eq!(
                before,
                native_phase(|| business_snapshot(&fixture)).await,
                "the complete attested HTTP unit rolls back after its physical claim expires during queue wait"
            );
            return;
        }
        let error = native_phase(|| uow.commit_event(prepared))
            .await
            .unwrap_err();
        assert_eq!(
            error.conflict_code(),
            Some(match refusal {
                AddRefusal::InstallFence => coland_storage::ConflictCode::AppletRevoked,
                AddRefusal::ClaimExpiry | AddRefusal::ClaimExpiryWhileQueued =>
                    coland_storage::ConflictCode::CapabilityDenied,
            }),
            "the actual current installation or physical claim window must refuse: {error}"
        );
        assert_eq!(
            before,
            native_phase(|| business_snapshot(&fixture)).await,
            "the complete failed unit has zero durable effects"
        );
        return;
    }
    let (welcome, accepted, mut bindings) = native_phase(|| {
        accepted_add(
            &fixture,
            &authority,
            &scope,
            &mut genesis,
            &claim,
            &target_guard,
        )
    })
    .await;
    let deliveries = native_phase(|| durable_realm_welcomes(&fixture, &authority)).await;
    let queued = deliveries
        .iter()
        .find_map(|item| match &item.delivery {
            arkret_models_collaboration::device_messages::RecipientDelivery::MlsWelcome {
                mls_welcome,
            } if mls_welcome.welcome_id == welcome.welcome_id => Some(mls_welcome.clone()),
            _ => None,
        })
        .expect("actual Add atomically queued its Welcome for the complete Realm Device");
    assert_eq!(queued, welcome);
    if let Some(other) = &sibling {
        let position_of = |delivery: &arkret_wire::MlsWelcomeDelivery| {
            deliveries.iter().find(|row|matches!(&row.delivery,arkret_models_collaboration::device_messages::RecipientDelivery::MlsWelcome{mls_welcome} if mls_welcome==delivery)).unwrap().position
        };
        assert!(
            position_of(other) < position_of(&welcome),
            "the unread Circle item must precede the Realm item in the original durable queue"
        );
    }
    if matches!(case, GroupCase::QueueBackendDrop) {
        native_phase(|| queue::assert_backend_loss(&fixture, &install, &authority, &key, &scope))
            .await;
        return;
    }
    if matches!(case, GroupCase::QueueClaimExpiry) {
        native_phase(|| {
            queue::assert_claim_expiry(&fixture, &authority, &key, &scope, command.expires_at)
        })
        .await;
        return;
    }
    let native_page = Some(if let Some(prior) = &prior {
        native_phase(|| queue::pages::next(&fixture, &authority, &key, &scope, prior, &queued))
            .await
    } else {
        native_phase(|| queue::assert_initial_list(&fixture, &authority, &key, &scope, &queued))
            .await
    });
    if let (Some(other), Some(page)) = (&sibling_scope, &native_page) {
        native_phase(|| queue::assert_other_scope_refused(&fixture, &authority, &key, other, page))
            .await;
    }
    if let Some(page) = &native_page {
        native_phase(|| {
            queue::assert_cold_continuation(
                &fixture,
                &authority,
                &key,
                &scope,
                page.next_cursor.as_deref().unwrap(),
            )
        })
        .await;
    }
    if let Some(page) = &native_page {
        native_phase(|| {
            queue::assert_native_token_cannot_use_legacy_ack(
                &fixture,
                &authority,
                page.ack_token.as_deref().unwrap(),
            )
        })
        .await;
    }
    let ack = native_page.as_ref().unwrap().ack_token.clone().unwrap();

    let query = arkret_models_crypto::KeyPackagesClaimQueryRequestBody {
        claim_id: welcome.keypackage_claim_ref.clone(),
    };
    let (status, bytes) =
        native_phase(|| query_wire(&fixture.state, &authority, &key, &scope, &query)).await;
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
    let realm_authority = native_phase(|| verified_realm_authority(&fixture)).await;
    let verified = garth::mls::verify_welcome_claim(
        &queued,
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
        identity, &queued, &accepted,
    )
    .unwrap();
    // Retain the actual accepted Genesis creator binding. The new leaf is
    // attributed only by the verified claim and its exact inline Add in the
    // winning Commit, never by an unproven BasicCredential or fixture index.
    let package_leaf = arkret_mls::author_leaf_from_key_package_bytes(
        &arkret_canonical::base64url_decode(&verified.keypackage).unwrap(),
        0,
    )
    .unwrap();
    let leaves = joined.active_author_leaves();
    let mut added_leaves = leaves.iter().filter(|leaf| {
        leaf.signature_key == package_leaf.signature_key
            && leaf.credential == package_leaf.credential
    });
    let added_leaf = added_leaves
        .next()
        .expect("the accepted Add installed the exact claimed leaf");
    assert!(added_leaves.next().is_none());
    bindings.push(arkret_mls::MlsVerifiedLeafBinding {
        leaf_index: added_leaf.leaf_index,
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
    let state = joined.export_state_record().unwrap();
    let private = PrivateGroupFile(std::env::temp_dir().join(format!(
        "arkret-native-mls-private-{}.json",
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
        file.write_all(&arkret_canonical::canonical_json_bytes(&state).unwrap())
            .unwrap();
        file.sync_all().unwrap();
    }
    #[cfg(unix)]
    std::fs::File::open(private.0.parent().unwrap())
        .unwrap()
        .sync_all()
        .unwrap();
    let restored: arkret_models_crypto::MlsGroupStateRecord =
        serde_json::from_slice(&std::fs::read(&private.0).unwrap()).unwrap();
    let restored = arkret_mls::ArkretMlsGroup::restore_from_state_record(&restored).unwrap();
    let accepted_payload: MlsCommitPayload =
        serde_json::from_value(serde_json::to_value(&accepted.event.payload).unwrap()).unwrap();
    assert_eq!(restored.epoch(), accepted_payload.next_epoch());
    let body = garth::mls::signed_welcome_consume(
        &queued,
        &read,
        arkret_models_crypto::RecipientMlsDurableSigner::RealmDevice {
            recipient_actor_id: authority.actor_id.clone(),
            recipient_device_id: authority.device_id.clone(),
            device_verification_method: arkret_wire::DidUrl::new(method.clone()).unwrap(),
        },
        &fixture.state.service_core_id(),
        restored.epoch(),
        chrono::Utc::now(),
        |method, bytes| {
            arkret_signatures::keypackages::keypackage_signature_from_bytes(
                method,
                &key.sign(bytes).to_bytes(),
            )
            .map_err(|error| garth::Error::Protocol(error.to_string()))
        },
    )
    .unwrap();
    if fenced {
        native_phase(|| fixture.revoke(&install)).await;
    }
    if ghost && native_page.is_some() {
        native_phase(|| {
            queue::assert_ack(&fixture, &authority, &key, &scope, &ack, native_ack_count)
        })
        .await;
        native_phase(|| queue::assert_ack(&fixture, &authority, &key, &scope, &ack, 0)).await;
    }
    assert!(
        private.0.is_file(),
        "the private group remains durable through consume"
    );
    // Every denial checks the complete durable database and the material cache.
    let mut wrong_digest = body.clone();
    wrong_digest.recipient_durable_receipt.welcome_digest =
        arkret_wire::Hash::new(format!("sha256:{}", "a".repeat(64))).unwrap();
    resign_consume(&mut wrong_digest, &key);
    let mut wrong_epoch = body.clone();
    wrong_epoch.recipient_durable_receipt.mls_epoch += 1;
    resign_consume(&mut wrong_epoch, &key);
    let mut wrong_welcome = body.clone();
    wrong_welcome.recipient_durable_receipt.welcome_ref = arkret_wire::MlsWelcomeDeliveryId::new(
        format!("ak:mls_welcome_delivery:{}", uuid::Uuid::now_v7()),
    )
    .unwrap();
    resign_consume(&mut wrong_welcome, &key);
    let mut wrong_claim = body.clone();
    wrong_claim.claim_id = arkret_wire::KeypackageClaimId::new(format!(
        "ak:keypackage_claim:{}",
        uuid::Uuid::now_v7()
    ))
    .unwrap();
    resign_consume(&mut wrong_claim, &key);
    let mut invalid_inner = body.clone();
    invalid_inner.recipient_durable_receipt.signature.sig =
        arkret_wire::Base64UrlString::new(arkret_canonical::base64url_encode(&[0; 64])).unwrap();
    sign_consume_outer(&mut invalid_inner, &key);
    let mut invalid_outer = body.clone();
    invalid_outer.signature.sig =
        arkret_wire::Base64UrlString::new(arkret_canonical::base64url_encode(&[0; 64])).unwrap();
    for (name, invalid) in [
        ("digest", wrong_digest),
        ("epoch", wrong_epoch),
        ("Welcome", wrong_welcome),
        ("claim", wrong_claim),
        ("inner signature", invalid_inner),
        ("outer signature", invalid_outer),
    ] {
        let before = native_phase(|| business_snapshot(&fixture)).await;
        let cache = fixture.state.test_projections().mls_key_package_records();
        let (status, bytes) =
            native_phase(|| consume_wire(&fixture, &authority, &key, &scope, &invalid)).await;
        assert!(
            status.is_client_error(),
            "{name} must refuse: {status}: {}",
            String::from_utf8_lossy(&bytes)
        );
        assert_eq!(
            before,
            native_phase(|| business_snapshot(&fixture)).await,
            "{name} has zero durable effects"
        );
        assert_eq!(
            cache,
            fixture.state.test_projections().mls_key_package_records(),
            "{name} has zero cache effects"
        );
    }
    // Fail the real ledger writer after the package CAS, then prove that the
    // package transition and receipt did not escape the rolled-back transaction.
    native_phase(|| consume_writer_fault(&fixture, true)).await;
    let before = native_phase(|| business_snapshot(&fixture)).await;
    let cache = fixture.state.test_projections().mls_key_package_records();
    let (status, bytes) =
        native_phase(|| consume_wire(&fixture, &authority, &key, &scope, &body)).await;
    assert_eq!(
        status,
        StatusCode::SERVICE_UNAVAILABLE,
        "real writer fault: {}",
        String::from_utf8_lossy(&bytes)
    );
    assert_eq!(
        before,
        native_phase(|| business_snapshot(&fixture)).await,
        "ledger fault rolls the package CAS back"
    );
    assert_eq!(
        cache,
        fixture.state.test_projections().mls_key_package_records()
    );
    native_phase(|| consume_writer_fault(&fixture, false)).await;
    let (status, bytes) =
        native_phase(|| consume_wire(&fixture, &authority, &key, &scope, &body)).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "native durable consume after install fence={fenced}: {}",
        String::from_utf8_lossy(&bytes)
    );
    let result: arkret_models_crypto::KeyPackagesConsumeOutcome =
        serde_json::from_slice(&bytes).unwrap();
    arkret_signatures::keypackages::verify_keypackage_signing_input(
        &fixture
            .state
            .notary_signing_key()
            .verifying_key()
            .to_bytes(),
        result.consume_receipt.signature.kid.as_str(),
        &result.consume_receipt.canonical_signing_bytes().unwrap(),
        &result.consume_receipt.signature,
    )
    .unwrap();
    assert_eq!(
        serde_json::to_value(&result.consume_receipt.recipient_durable_receipt).unwrap(),
        serde_json::to_value(&body.recipient_durable_receipt).unwrap()
    );
    assert_eq!(result.consume_receipt.claim_id, body.claim_id);
    assert_eq!(
        result.consume_receipt.request_digest.as_str(),
        arkret_models_crypto::keypackages_consume_request_digest(&body).unwrap()
    );
    let before = native_phase(|| business_snapshot(&fixture)).await;
    let (status, replay) =
        native_phase(|| consume_wire(&fixture, &authority, &key, &scope, &body)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        bytes, replay,
        "exact signed retry returns the complete first response bytes"
    );
    assert_eq!(
        before,
        native_phase(|| business_snapshot(&fixture)).await,
        "retry creates no second effect"
    );
    let mut changed = body.clone();
    changed.recipient_durable_receipt.durable_at -= chrono::Duration::milliseconds(1);
    resign_consume(&mut changed, &key);
    let (status, _) =
        native_phase(|| consume_wire(&fixture, &authority, &key, &scope, &changed)).await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "a differently signed receipt cannot replace first success"
    );
    assert_eq!(before, native_phase(|| business_snapshot(&fixture)).await);
    if matches!(case, GroupCase::LastResort) {
        let store = coland_storage_postgres::PgMlsKeyPackageStore {
            pool: fixture.pool.clone(),
        };
        let package = native_phase(|| store.get_by_ref(&upload.keypackages[0].keypackage_ref))
            .await
            .unwrap()
            .unwrap();
        assert!(package.last_resort);
        assert!(package.consumed_at.is_none());
        assert!(package.claimed_by_mls_group_id.is_none());
        assert_eq!(
            package.last_resort_realm_id.as_deref(),
            Some(scope.realm_id().as_str())
        );
        let first = native_phase(|| store.get_peer_claim_by_claim_id(body.claim_id.as_str()))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(first.state, "consumed");
        let mut next = command.clone();
        next.claim_request_id =
            arkret_wire::Base64UrlString::new(arkret_canonical::base64url_encode(
                [
                    uuid::Uuid::new_v4().into_bytes(),
                    uuid::Uuid::new_v4().into_bytes(),
                ]
                .concat(),
            ))
            .unwrap();
        next.expires_at = arkret_canonical::normalize_timestamp_canonical(
            chrono::Utc::now() + chrono::Duration::minutes(1),
        );
        if let arkret_models_crypto::PeerKeyPackageRequesterAuthorization::Device {
            signed_at,
            ..
        } = &mut next.requester_authorization
        {
            *signed_at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
        }
        resign(&mut next, &human_key);
        let value = serde_json::to_value(&next).unwrap();
        let (status, value) = native_phase(|| {
            fixture.admin_post(
                "/_arkret/self/keys/keypackages/claim",
                ServiceOperationId::SelfKeysKeypackagesCommandClaimV1.as_str(),
                &value,
                Some(next.claim_request_id.as_str()),
            )
        })
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "last-resort remains independently claimable: {value}"
        );
        let second: arkret_models_crypto::KeyPackagesClaimOutcome =
            serde_json::from_value(value).unwrap();
        assert_ne!(second.claims[0].claim_id, body.claim_id.as_str());
        assert_eq!(
            second.claims[0].keypackage_ref,
            upload.keypackages[0].keypackage_ref
        );
        assert_eq!(
            native_phase(|| store.get_peer_claim_by_claim_id(body.claim_id.as_str()))
                .await
                .unwrap()
                .unwrap(),
            first,
            "another claim never rewrites the first consumed audit"
        );
        let (status, recovered) =
            native_phase(|| consume_wire(&fixture, &authority, &key, &scope, &body)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(bytes, recovered);
    }
    if !ghost && native_page.is_some() {
        native_phase(|| {
            queue::assert_ack(&fixture, &authority, &key, &scope, &ack, native_ack_count)
        })
        .await;
        native_phase(|| queue::assert_ack(&fixture, &authority, &key, &scope, &ack, 0)).await;
    }
    if let Some(prior) = &prior {
        native_phase(|| {
            queue::assert_ack(
                &fixture,
                &authority,
                &key,
                &scope,
                prior.page.ack_token.as_deref().unwrap(),
                0,
            )
        })
        .await;
    }
    if let Some(other) = &sibling {
        native_phase(|| queue::assert_sibling_preserved(&fixture, &authority, &key, other)).await;
    }
    if let Some(page) = native_page {
        let before = native_phase(|| business_snapshot(&fixture)).await;
        native_phase(|| {
            queue::assert_after_ack(
                &fixture,
                &authority,
                &key,
                &scope,
                page.next_cursor.as_deref().unwrap(),
                fenced,
            )
        })
        .await;
        assert_eq!(
            before,
            native_phase(|| business_snapshot(&fixture)).await,
            "empty or fenced continuation allocates no ACK token or cursor"
        );
    }
}

async fn prepare_add(
    fixture: &Fixture,
    authority: &coland_storage::AppletManagedDeviceAuthority,
    scope: &ScopeRef,
    genesis: &mut MlsGenesisRuntime,
    claim: &arkret_models_crypto::KeyPackageClaimRecord,
    target_guard: &coland_storage::AppletManagedDeviceScopeGuard,
) -> (
    arkret_wire::MlsWelcomeDelivery,
    coland_storage::EventCommitRequest,
    Vec<arkret_mls::MlsVerifiedLeafBinding>,
) {
    let mut creator_bindings = genesis.group.verified_leaf_bindings().unwrap();
    let groups = coland_storage_postgres::PgMlsGroupCurrentStore {
        pool: fixture.pool.clone(),
    };
    let current = native_phase(|| groups.current(scope))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        current.value.current_mls_commit_event_ref,
        genesis.accepted.event.event_id
    );
    let binding = MlsGovernanceBindingPayload::new(
        scope.clone(),
        Some(current.value.current_mls_commit_event_ref.clone()),
        current.value.epoch,
        current.value.epoch + 1,
        current.value.current_key_access_revision,
    )
    .unwrap();
    let package = arkret_mls::mls_key_package_record_from_claim(claim).unwrap();
    let actor = authority.actor_id.clone();
    let added = if genesis
        .group
        .member_endpoint_replacement_actor(&package.endpoint, &actor)
        .unwrap()
        .is_some()
    {
        creator_bindings.retain(|leaf| leaf.actor_id != actor || leaf.endpoint != package.endpoint);
        genesis
            .group
            .replace_member_endpoint(&package, &actor, Some(&binding))
            .unwrap()
    } else {
        genesis
            .group
            .add_member_with_governance_binding(&package, &binding)
            .unwrap()
    };
    let mut tracker = arkret_mls::MlsPublicGroupTracker::restore(
        &current.public_state,
        scope.canonical_mls_group_id().unwrap().as_str(),
        current.value.epoch,
    )
    .unwrap();
    let arkret_mls::MlsPublicHandshakeTransition::Commit {
        consumed_proposals, ..
    } = tracker
        .process_public_handshake(
            &arkret_canonical::base64url_decode(added.commit.commit.as_str()).unwrap(),
        )
        .unwrap()
    else {
        panic!("actual Commit transition required")
    };
    let installed_leaf =
        |leaf: arkret_mls::MlsPublicEndpointLeaf| coland_storage::MlsProposalLeafProvenance {
            leaf_index: leaf.leaf_index,
            actor_id: leaf.actor_id,
            signature_key: leaf.signature_key,
        };
    let consumed_proposals = consumed_proposals
        .into_iter()
        .map(|proposal| coland_storage::MlsConsumedProposalInstallation {
            ordinal: proposal.ordinal,
            proposal_ref: proposal.proposal_ref,
            proposal_type: proposal.proposal_type,
            proposal_wire: proposal.proposal_wire,
            sender_leaf: installed_leaf(proposal.sender_leaf),
            target_before: proposal.target_before.map(installed_leaf),
            target_after: proposal.target_after.map(installed_leaf),
        })
        .collect();
    let member_principals = tracker
        .leaves()
        .unwrap()
        .into_iter()
        .map(|leaf| leaf.actor_id)
        .collect();
    let payload = MlsCommitPayload::new(
        current.value.current_mls_commit_event_ref.clone(),
        current.value.current_key_access_revision,
        &added.commit,
        binding,
    )
    .unwrap();
    let event = fixture.admin_event(
        EventKind::MlsCommit,
        scope.clone(),
        serde_json::to_value(payload).unwrap(),
    );
    let mut request = native_phase(|| admin_domain_request(fixture, event.clone())).await;
    let mut welcome = arkret_wire::MlsWelcomeDelivery {
        welcome_id: arkret_wire::MlsWelcomeDeliveryId::new(format!(
            "ak:mls_welcome_delivery:{}",
            uuid::Uuid::now_v7()
        ))
        .unwrap(),
        realm_id: scope.realm_id().clone(),
        effective_scope: scope.clone(),
        commit_event_ref: event.event_id.clone(),
        recipient_actor_id: authority.actor_id.clone(),
        recipient_endpoint: arkret_wire::MlsWelcomeRecipientEndpoint::Device {
            device_id: authority.device_id.clone(),
        },
        keypackage_claim_ref: added.welcome.keypackage_claim_ref.clone(),
        ciphertext_b64: added.welcome.ciphertext_b64.clone(),
        producer_proof: arkret_wire::DetachedObjectSignature {
            context: arkret_wire::DetachedSignatureContext::MlsWelcomeDelivery,
            signature_algorithm: arkret_wire::DetachedSignatureAlgorithm::Ed25519,
            verification_method: fixture.pcr.history.device_verification_method.clone(),
            signed_digest: arkret_wire::Hash::new(format!("sha256:{}", "0".repeat(64))).unwrap(),
            created_at: request.authority_commit.commit.committed_at,
            sig: arkret_wire::Base64UrlString::new("AA").unwrap(),
        },
    };
    welcome.producer_proof = arkret_signatures::detached_object::sign_detached_object(
        &arkret_canonical::canonical::unsigned_value(&welcome, &["producer_proof"]).unwrap(),
        arkret_wire::DetachedSignatureContext::MlsWelcomeDelivery,
        fixture.pcr.history.device_verification_method.clone(),
        request.authority_commit.commit.committed_at,
        &SigningKey::from_bytes(&fixture.pcr.history.founding_device_signing_seed),
    )
    .unwrap();
    let store = coland_storage_postgres::PgMlsKeyPackageStore {
        pool: fixture.pool.clone(),
    };
    let ledger = native_phase(|| store.get_peer_claim_by_claim_id(&claim.claim_id))
        .await
        .unwrap()
        .unwrap();
    let tree = tracker.ratchet_tree_bytes().unwrap();
    let digest = arkret_canonical::sha256_digest(&tree);
    let hex = digest.strip_prefix("sha256:").unwrap();
    request.realm_fanout_source = Some(arkret_wire::EventAdmissionSubmission::new(event.clone()));
    request.authority_commit.mls_state = Some(coland_storage::MlsStateInstallation {
        effective_scope: scope.clone(),
        base: Some(coland_storage::MlsInstalledBase {
            current_mls_commit_event_ref: current.value.current_mls_commit_event_ref,
            epoch: current.value.epoch,
        }),
        epoch: current.value.epoch + 1,
        public_state: tracker.export_state().unwrap(),
        member_principals,
        consumed_proposals,
        public_blobs: vec![coland_storage::MlsPublicBlob {
            blob_ref: arkret_wire::BlobRef::new(format!("ak:blob:{digest}")).unwrap(),
            sha256: hex.to_owned(),
            size_bytes: tree.len() as i64,
            storage_backend: "local".into(),
            storage_key: format!("sha256/{hex}"),
        }],
    });
    request.authority_commit.welcomes = vec![coland_storage::VerifiedMlsWelcome {
        delivery: welcome.clone(),
        claim: Some(coland_storage::MlsWelcomeClaimLedgerKey {
            source_id: ledger.source_id,
            claim_request_id: ledger.claim_request_id,
            request_digest: ledger.request_digest,
        }),
        applet_device_scope_guard: Some(target_guard.clone()),
        roster_witness: None,
    }];
    request.authority_commit.recipient_queue_capacity = 16;
    (welcome, request, creator_bindings)
}

async fn accepted_add(
    fixture: &Fixture,
    authority: &coland_storage::AppletManagedDeviceAuthority,
    scope: &ScopeRef,
    genesis: &mut MlsGenesisRuntime,
    claim: &arkret_models_crypto::KeyPackageClaimRecord,
    target_guard: &coland_storage::AppletManagedDeviceScopeGuard,
) -> (
    arkret_wire::MlsWelcomeDelivery,
    arkret_wire::CommittedEventFullView,
    Vec<arkret_mls::MlsVerifiedLeafBinding>,
) {
    let (welcome, request, creator_bindings) =
        native_phase(|| prepare_add(fixture, authority, scope, genesis, claim, target_guard)).await;
    let event_id = request.authority_commit.event.event_id.clone();
    let uow = coland_storage_postgres::PgEventCommitUnitOfWork::new(fixture.pool.clone());
    let mut omitted = request.clone();
    omitted.authority_commit.welcomes[0].applet_device_scope_guard = None;
    let before = native_phase(|| business_snapshot(fixture)).await;
    let omitted_error = native_phase(|| uow.commit_event(omitted))
        .await
        .unwrap_err();
    assert!(
        omitted_error
            .to_string()
            .contains("Welcome native package requires its exact current proof"),
        "omitting the native current proof must fail at that exact boundary: {omitted_error}"
    );
    assert_eq!(before, native_phase(|| business_snapshot(fixture)).await);
    let idempotency = uuid::Uuid::now_v7();
    let submission =
        arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequest::MlsCommit(
            arkret_wire::MlsCommitSubmission {
                commit_event: request.authority_commit.event.clone(),
                welcomes: vec![welcome.clone()],
                idempotency_key: arkret_wire::UuidV7::new(idempotency).unwrap(),
            },
        );
    let body = serde_json::to_value(&submission).unwrap();
    let token = idempotency.to_string();
    let (status, outcome) = native_phase(|| {
        fixture.admin_post(
            "/_arkret/self/events",
            ServiceOperationId::SelfEventsCommandSubmitV1.as_str(),
            &body,
            Some(&token),
        )
    })
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "actual Human MLS submission must prepare the native recipient's complete historical attestation: {outcome}"
    );
    let store = PgAuthorityCommitStore {
        pool: fixture.pool.clone(),
    };
    let accepted = native_phase(|| store.committed_event(&event_id))
        .await
        .unwrap()
        .unwrap();
    (
        welcome,
        arkret_wire::CommittedEventFullView {
            event: accepted.event,
            commit: accepted.commit,
        },
        creator_bindings,
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_add_refuses_a_target_fenced_after_its_actual_claim() {
    for ghost in [false, true] {
        tokio::spawn(native_phase(|| {
            exercise_consume(
                ghost,
                false,
                Some(AddRefusal::InstallFence),
                GroupCase::Realm,
            )
        }))
        .await
        .unwrap();
    }
}

async fn business_snapshot(fixture: &Fixture) -> Value {
    #[derive(diesel::QueryableByName)]
    struct Table {
        #[diesel(sql_type=diesel::sql_types::Text)]
        name: String,
    }
    #[derive(diesel::QueryableByName)]
    struct Row {
        #[diesel(sql_type=diesel::sql_types::Jsonb)]
        value: Value,
    }
    let mut conn = fixture.pool.get().await.unwrap();
    let tables = diesel::sql_query(
        "SELECT tablename AS name FROM pg_tables WHERE schemaname='public' ORDER BY tablename",
    )
    .load::<Table>(&mut *conn)
    .await
    .unwrap();
    let mut rows = BTreeMap::new();
    for table in tables {
        if table.name == "applet_managed_device_nonces" {
            continue;
        }
        let quoted = format!("\"{}\"", table.name.replace('"', "\"\""));
        let sql = format!(
            "SELECT COALESCE(jsonb_agg(value ORDER BY value::text),'[]'::jsonb) AS value FROM (SELECT to_jsonb(t) AS value FROM public.{quoted} t) items"
        );
        let row = diesel::sql_query(sql)
            .get_result::<Row>(&mut *conn)
            .await
            .unwrap();
        rows.insert(table.name, row.value);
    }
    serde_json::to_value(rows).unwrap()
}

async fn consume_wire(
    fixture: &Fixture,
    authority: &coland_storage::AppletManagedDeviceAuthority,
    key: &SigningKey,
    scope: &ScopeRef,
    body: &arkret_models_crypto::KeyPackagesConsumeRequestBody,
) -> (StatusCode, Vec<u8>) {
    let mut metadata = managed_device_metadata(authority);
    metadata.effective_scope = scope.clone();
    let mut response = managed_device_http_request_body(
        &fixture.state,
        authority,
        &metadata,
        ServiceOperationId::SelfKeysKeypackagesCommandConsumeV1,
        key,
        Some(arkret_canonical::canonical_json_bytes(body).unwrap()),
    )
    .add_header("content-type", "application/json", true)
    .send(&service(fixture.state.clone()))
    .await;
    (
        response.status_code.unwrap(),
        response.take_bytes(None).await.unwrap().to_vec(),
    )
}
fn sign_consume_outer(
    body: &mut arkret_models_crypto::KeyPackagesConsumeRequestBody,
    key: &SigningKey,
) {
    let input = arkret_models_crypto::keypackages_consume_signing_input(&body.unsigned()).unwrap();
    body.signature = arkret_signatures::keypackages::keypackage_signature_from_bytes(
        body.signature.kid.as_str(),
        &key.sign(&input).to_bytes(),
    )
    .unwrap();
}
fn resign_consume(
    body: &mut arkret_models_crypto::KeyPackagesConsumeRequestBody,
    key: &SigningKey,
) {
    let receipt = &mut body.recipient_durable_receipt;
    let input = receipt.canonical_signing_bytes().unwrap();
    receipt.signature = arkret_signatures::keypackages::keypackage_signature_from_bytes(
        receipt.signature.kid.as_str(),
        &key.sign(&input).to_bytes(),
    )
    .unwrap();
    sign_consume_outer(body, key);
}
async fn consume_writer_fault(fixture: &Fixture, install: bool) {
    let mut conn = fixture.pool.get().await.unwrap();
    let sql = if install {
        "CREATE FUNCTION test_native_consume_writer_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.state='consumed' THEN RAISE EXCEPTION 'native consume ledger writer fault'; END IF; RETURN NEW; END $$; CREATE TRIGGER test_native_consume_writer_failure BEFORE UPDATE ON peer_keypackage_claims FOR EACH ROW EXECUTE FUNCTION test_native_consume_writer_failure();"
    } else {
        "DROP TRIGGER test_native_consume_writer_failure ON peer_keypackage_claims; DROP FUNCTION test_native_consume_writer_failure();"
    };
    diesel_async::SimpleAsyncConnection::batch_execute(&mut *conn, sql)
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_add_refuses_a_real_claim_that_expires_after_preparation() {
    for ghost in [false, true] {
        tokio::spawn(native_phase(|| {
            exercise_consume(
                ghost,
                false,
                Some(AddRefusal::ClaimExpiry),
                GroupCase::Realm,
            )
        }))
        .await
        .unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_circle_recipient_consumes_its_own_durable_welcome_without_session() {
    for ghost in [false, true] {
        tokio::spawn(native_phase(|| {
            exercise_consume(ghost, false, None, GroupCase::Circle)
        }))
        .await
        .unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_last_resort_consume_terminates_only_its_exact_claim_audit() {
    for ghost in [false, true] {
        tokio::spawn(native_phase(|| {
            exercise_consume(ghost, false, None, GroupCase::LastResort)
        }))
        .await
        .unwrap();
    }
}

async fn wait_for_welcome_queue_lock(fixture: &Fixture) -> bool {
    #[derive(diesel::QueryableByName)]
    struct Waiting {
        #[diesel(sql_type=diesel::sql_types::Bool)]
        present: bool,
    }
    let mut conn = fixture.pool.get().await.unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(5),async {
        loop {
            let row=diesel::sql_query("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE 'LOCK TABLE device_messages, mls_welcome_deliveries IN SHARE ROW EXCLUSIVE MODE%') AS present")
                .get_result::<Waiting>(&mut *conn).await.unwrap();
            if row.present {break;}
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    }).await.is_ok()
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_add_rolls_back_when_claim_expires_while_its_queue_writer_waits() {
    for ghost in [false, true] {
        tokio::spawn(native_phase(|| {
            exercise_consume(
                ghost,
                false,
                Some(AddRefusal::ClaimExpiryWhileQueued),
                GroupCase::Realm,
            )
        }))
        .await
        .unwrap();
    }
}

// Inspect persisted delivery evidence without using the ordinary Account queue.
async fn durable_realm_welcomes(
    fixture: &Fixture,
    authority: &coland_storage::AppletManagedDeviceAuthority,
) -> Vec<coland_storage::RecipientDeliveryRecord> {
    #[derive(diesel::QueryableByName)]
    struct Row {
        #[diesel(sql_type=diesel::sql_types::BigInt)]
        position: i64,
        #[diesel(sql_type=diesel::sql_types::Jsonb)]
        delivery_json: Value,
    }
    let subject =
        String::from_utf8(arkret_canonical::canonical_json_bytes(&authority.actor_id).unwrap())
            .unwrap();
    let mut conn = fixture.pool.get().await.unwrap();
    diesel::sql_query("SELECT position, delivery_json FROM mls_welcome_deliveries WHERE recipient=$1 AND recipient_endpoint_kind='device' AND recipient_device_id=$2 AND state='queued' ORDER BY position")
        .bind::<diesel::sql_types::Text,_>(subject)
        .bind::<diesel::sql_types::Text,_>(authority.device_id.as_str())
        .load::<Row>(&mut *conn).await.unwrap().into_iter().map(|row| {
            let welcome: arkret_wire::MlsWelcomeDelivery = serde_json::from_value(row.delivery_json).unwrap();
            welcome.validate_shape().unwrap();
            assert_eq!(welcome.recipient_actor_id, authority.actor_id);
            coland_storage::RecipientDeliveryRecord {
                position: row.position,
                delivery: arkret_models_collaboration::device_messages::RecipientDelivery::MlsWelcome { mls_welcome: welcome },
            }
        }).collect()
}

async fn verified_realm_authority(fixture: &Fixture) -> arkret_identity::VerifiedRealmAuthority {
    let base: url::Url = fixture.state.config().public_base_url.parse().unwrap();
    let http = reqwest::Client::builder()
        .tls_backend_rustls()
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .tls_certs_only([reqwest::Certificate::from_pem(include_bytes!(
            "../../fixtures/outbox-test-ca.pem"
        ))
        .unwrap()])
        .build()
        .unwrap();
    let client = arkret_http_client::Client::builder(base.clone())
        .http_client(http)
        .loopback_service_discovery("127.0.0.1", base.port().unwrap())
        .unwrap()
        .build()
        .unwrap();
    let mut nonce = [0u8; 32];
    getrandom::fill(&mut nonce).unwrap();
    let request = arkret::AuthorityBundleRequest {
        realm_id: fixture.realm.clone(),
        nonce: arkret::Base64UrlString::new(arkret_canonical::base64url_encode(nonce)).unwrap(),
    };
    let bundle = garth::AuthorityClient::new(client.clone())
        .resolve_authority(&request)
        .await
        .unwrap();
    let keys = garth::historical_station_keys::fetch_historical_station_key_directory(
        &client, &bundle, None, None,
    )
    .await
    .unwrap();
    arkret_identity::verify_realm_authority_bundle(
        &bundle,
        &arkret_identity::RealmAuthorityFreshness::new(chrono::Utc::now(), request.nonce),
        &keys,
    )
    .unwrap()
}
