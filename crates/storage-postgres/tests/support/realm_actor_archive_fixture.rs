// Included only by the native Service fixture. This separate encrypted DB and
// KEK are never installed into a Device worker or its ordinary authoring store.
pub(super) struct FixtureManagerArchive {
    path: std::path::PathBuf,
    wrapping_key: arkret::KeyBytes,
}

// Server-private fixture custody, encrypted as one immutable record. Neither
// this local lookup identity nor its plaintext is a public protocol carrier.
#[derive(serde::Serialize, serde::Deserialize)]
struct FixtureManagerArchiveImport {
    realm_actor_id: arkret_wire::RealmActorId,
    sealed_digest: arkret_wire::Hash,
    offer_digest: arkret_wire::Hash,
    inventory_digest: arkret_wire::Hash,
    handover_digest: arkret_wire::Hash,
    imported_at: chrono::DateTime<chrono::Utc>,
    plaintext: arkret_models_integration::RealmActorContentBackupHandoverPlaintext,
}

impl FixtureManagerArchiveImport {
    fn from_verified(
        identity: &arkret_identity::realm_actor_backup_handover::RealmActorBackupHandoverImportIdentity,
        plaintext: &arkret_models_integration::RealmActorContentBackupHandoverPlaintext,
        imported_at: chrono::DateTime<chrono::Utc>,
    ) -> Self {
        Self {
            realm_actor_id: identity.realm_actor_id.clone(),
            sealed_digest: identity.sealed_digest.clone(),
            offer_digest: identity.offer_digest.clone(),
            inventory_digest: identity.inventory_digest.clone(),
            handover_digest: identity.handover_digest.clone(),
            imported_at,
            plaintext: plaintext.clone(),
        }
    }

    fn assert_identity(
        &self,
        identity: &arkret_identity::realm_actor_backup_handover::RealmActorBackupHandoverImportIdentity,
    ) {
        assert_eq!(self.realm_actor_id, identity.realm_actor_id);
        assert_eq!(self.sealed_digest, identity.sealed_digest);
        assert_eq!(self.offer_digest, identity.offer_digest);
        assert_eq!(self.inventory_digest, identity.inventory_digest);
        assert_eq!(self.handover_digest, identity.handover_digest);
    }
}

fn fixture_runtime_manager(
    native: &NativeService,
    edge: Arc<arkret_bridge_runtime::ArkretEdge>,
) -> Arc<arkret_bridge_runtime::managed_actor_authoring::ManagedActorManagerService> {
    Arc::new(
        arkret_bridge_runtime::managed_actor_authoring::ManagedActorManagerService::new(
            edge,
            native
                .manager_vault
                .lock()
                .unwrap()
                .as_ref()
                .expect("manager vault must be unlocked by this fixture manager")
                .clone(),
        )
        .unwrap(),
    )
}

async fn fixture_cold_reopen_manager_vault(native: &NativeService) {
    *native.managed_router.lock().unwrap() = None;
    let vault = native
        .manager_vault
        .lock()
        .unwrap()
        .take()
        .expect("one manager deployment vault");
    drop(vault);
    let probe = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&native.manager_archive_path)
        .unwrap();
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        match probe.try_lock() {
            Ok(()) => break,
            Err(error) => {
                assert!(
                    tokio::time::Instant::now() < deadline,
                    "every receiving manager, router and private archive guard must close before a real cold vault open: {error}"
                );
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        }
    }
    probe.unlock().unwrap();
    drop(probe);
    let reopened = arkret_bridge_runtime::manager_archive::ManagerArchiveVault::open(
        &native.manager_archive_path,
        native.manager_archive_wrapping_key.clone(),
    )
    .unwrap();
    let mut slot = native.manager_vault.lock().unwrap();
    assert!(slot.is_none());
    *slot = Some(Arc::new(reopened));
}

impl FixtureManagerArchive {
    fn new() -> Self {
        Self {
            path: std::env::temp_dir().join(format!(
                "arkret-fixture-manager-archive-{}.redb",
                uuid::Uuid::now_v7()
            )),
            wrapping_key: arkret::KeyBytes::new(rand::random::<[u8; 32]>().to_vec()),
        }
    }

    fn put<T: serde::Serialize>(&self, key: &str, value: &T) {
        use arkret_bridge_runtime::AuthoringStore as _;
        use chacha20poly1305::aead::{Aead as _, KeyInit as _, Payload};
        let store = arkret_bridge_runtime::FileAuthoringStore::new(self.path.clone()).unwrap();
        let old = store.load(key).unwrap();
        let bytes = arkret::KeyBytes::new(arkret_canonical::canonical_json_bytes(value).unwrap());
        if old.is_some() {
            drop(store);
            assert_eq!(
                self.read_bytes(key).as_slice(),
                bytes.as_slice(),
                "private archive slots are immutable"
            );
            return;
        }
        let nonce = rand::random::<[u8; 24]>();
        let cipher =
            chacha20poly1305::XChaCha20Poly1305::new_from_slice(self.wrapping_key.as_slice())
                .unwrap();
        let encrypted = cipher
            .encrypt(
                &chacha20poly1305::XNonce::try_from(nonce.as_slice()).unwrap(),
                Payload {
                    msg: bytes.as_slice(),
                    aad: key.as_bytes(),
                },
            )
            .unwrap();
        let raw = format!(
            "{}.{}",
            arkret_canonical::base64url_encode(nonce),
            arkret_canonical::base64url_encode(encrypted)
        );
        assert!(
            store
                .compare_exchange_batch(&[(key.to_owned(), None)], &[(key.to_owned(), Some(raw))])
                .unwrap()
        );
        drop(store);
        assert_eq!(
            self.read_bytes(key).as_slice(),
            bytes.as_slice(),
            "private import must survive a real DB close/open"
        );
    }

    fn read_bytes(&self, key: &str) -> arkret::KeyBytes {
        use arkret_bridge_runtime::AuthoringStore as _;
        use chacha20poly1305::aead::{Aead as _, KeyInit as _, Payload};
        let store = arkret_bridge_runtime::FileAuthoringStore::new(self.path.clone()).unwrap();
        let raw = store
            .load(key)
            .unwrap()
            .expect("private archive record is durable");
        let (nonce, ciphertext) = raw.split_once('.').unwrap();
        let nonce = arkret_canonical::base64url_decode(nonce).unwrap();
        let ciphertext = arkret_canonical::base64url_decode(ciphertext).unwrap();
        let cipher =
            chacha20poly1305::XChaCha20Poly1305::new_from_slice(self.wrapping_key.as_slice())
                .unwrap();
        arkret::KeyBytes::new(
            cipher
                .decrypt(
                    &chacha20poly1305::XNonce::try_from(nonce.as_slice()).unwrap(),
                    Payload {
                        msg: &ciphertext,
                        aad: key.as_bytes(),
                    },
                )
                .unwrap(),
        )
    }

    fn get<T: serde::de::DeserializeOwned>(&self, key: &str) -> T {
        serde_json::from_slice(self.read_bytes(key).as_slice()).unwrap()
    }

    fn get_if_present<T: serde::de::DeserializeOwned>(&self, key: &str) -> Option<T> {
        use arkret_bridge_runtime::AuthoringStore as _;
        let store = arkret_bridge_runtime::FileAuthoringStore::new(self.path.clone()).unwrap();
        let present = store.load(key).unwrap().is_some();
        drop(store);
        present.then(|| self.get(key))
    }

    fn recipient_slot(actor: &ActorId) -> String {
        format!(
            "manager-archive/v1/recipient/{}",
            arkret_canonical::canonical_sha256(actor).unwrap()
        )
    }
}

async fn fixture_archive_inventory(
    fixture: &Fixture,
    service: &NativeService,
    actor: &ActorId,
) -> (
    arkret_models_integration::RealmActorArchiveInventoryManifest,
    arkret_identity::VerifiedRealmAuthority,
    arkret_identity::RealmAuthorityKeyMap,
    arkret_models_identity::AuthenticatedServiceResolution,
) {
    let client = arkret_http_client::Client::builder(
        fixture.state.config().public_base_url.parse().unwrap(),
    )
    .http_client(native_http_client(std::time::Duration::from_secs(30)))
    .retry(arkret_http_client::RetryConfig::disabled())
    .build()
    .unwrap()
    .with_service_http_signer(
        service.package.service_id.clone(),
        fixture.state.service_core_id(),
        arkret_http_client::HttpMessageSigner::new(
            service.package.webhook_signature_policy.key_ref.to_string(),
            applet_service_signing_key(&service.package.webhook_signature_policy.key_ref),
        ),
    );
    let mut query = arkret_models_crypto::RealmActorArchiveInventoryQuery::new(
        actor.as_realm_actor_id().unwrap().clone(),
    );
    query.limit = Some(1);
    let mut entries = Vec::new();
    let mut cut = None;
    let mut cursors = std::collections::BTreeSet::new();
    let (manager_ref, archive_revision, digest) = loop {
        let page = client
            .realm_actor_backup_archive_inventory(&query)
            .await
            .unwrap();
        let observed = (
            page.manager_ref.clone(),
            page.archive_revision,
            page.inventory_digest.clone(),
        );
        if let Some(previous) = &cut {
            assert_eq!(
                previous, &observed,
                "all private pages must use one current-manager frozen inventory cut"
            );
        }
        cut = Some(observed);
        entries.extend(page.entries);
        match page.next_cursor {
            Some(cursor) => {
                assert!(page.has_more);
                assert!(cursors.insert(cursor.to_string()));
                query.cursor = Some(cursor);
            }
            None => {
                assert!(!page.has_more);
                break cut.unwrap();
            }
        }
    };
    let manifest = arkret_models_integration::RealmActorArchiveInventoryManifest {
        realm_actor_id: query.realm_actor_id,
        manager_ref,
        archive_revision,
        entries,
    };
    manifest.validate_order().unwrap();
    assert_eq!(manifest.inventory_digest().unwrap(), digest);
    let nonce =
        arkret_wire::Base64UrlString::new(arkret_canonical::base64url_encode(rand::random::<
            [u8; 32],
        >()))
        .unwrap();
    let bundle = client
        .realm_authority_bundle(&arkret_wire::RealmAuthorityBundleRequestBody {
            realm_id: fixture.realm.clone(),
            nonce: nonce.clone(),
        })
        .await
        .unwrap();
    assert!(
        bundle.authority_transitions.is_empty(),
        "this manual fixture has one actual governance Station"
    );
    let resolution: arkret_models_identity::AuthenticatedServiceResolution =
        serde_json::from_value(bundle.current_route_record.clone()).unwrap();
    let mut keys = arkret_identity::RealmAuthorityKeyMap::new();
    for signature in [
        &bundle.genesis_commit.signature,
        &bundle.current_assertion.signature,
    ] {
        let document = arkret_identity::authenticated_service_document_at(
            &resolution,
            &bundle.current_service_id,
            signature.created_at,
        )
        .unwrap();
        let key = arkret_identity::public_key_material_from_document(
            &document,
            &signature.verification_method,
        )
        .unwrap();
        keys.insert_at(&signature.verification_method, signature.created_at, key);
    }
    let authority = arkret_identity::verify_realm_authority_bundle(
        &bundle,
        &arkret_identity::RealmAuthorityFreshness::new(chrono::Utc::now(), nonce),
        &keys,
    )
    .unwrap();
    arkret_identity::realm_actor_content_backup::verify_realm_actor_archive_inventory(
        &manifest, &authority, &keys,
    )
    .unwrap();
    (manifest, authority, keys, resolution)
}

async fn fixture_select_native_series(
    fixture: &Fixture,
    service: &NativeService,
    actor: &ActorId,
    scope: &ScopeRef,
) -> arkret_models_collaboration::events_payloads::KeyBackupActiveSeries {
    use arkret_models_integration::{
        RealmActorMaterial, RealmActorMaterialCurrentEntry, RealmActorMaterialRequestBody,
        RealmActorRecoveryValue,
    };
    use ed25519_dalek::Signer as _;
    let (inventory, authority, keys, resolution) =
        fixture_archive_inventory(fixture, service, actor).await;
    let signing_key = applet_service_signing_key(&service.package.webhook_signature_policy.key_ref);
    let client = arkret_http_client::Client::builder(
        fixture.state.config().public_base_url.parse().unwrap(),
    )
    .http_client(native_http_client(std::time::Duration::from_secs(30)))
    .retry(arkret_http_client::RetryConfig::disabled())
    .build()
    .unwrap()
    .with_service_http_signer(
        service.package.service_id.clone(),
        fixture.state.service_core_id(),
        arkret_http_client::HttpMessageSigner::new(
            service.package.webhook_signature_policy.key_ref.to_string(),
            signing_key.clone(),
        ),
    );
    let selector = arkret_wire::CurrentSelector::RealmActorKeyBackupActiveSeries {
        actor_id: actor.clone(),
        effective_scope: scope.clone(),
        backup_kind: arkret_wire::RealmActorBackupKind::SecretStorage,
    };
    let request = RealmActorMaterialRequestBody::Current {
        actor_id: actor.clone(),
        request_nonce: arkret_canonical::base64url_encode(rand::random::<[u8; 32]>()),
        selectors: vec![
            arkret_wire::CurrentSelector::RealmActorRecovery {
                actor_id: actor.clone(),
            },
            selector.clone(),
        ],
    };
    let current = client
        .realm_actor_material(
            &request,
            &ActorId::service(service.package.service_id.clone()),
            &authority,
            &resolution,
            &keys,
        )
        .await
        .unwrap();
    let RealmActorMaterial::Current { entries, .. } = &current.material().material else {
        panic!("public current expected");
    };
    let (recovery, recovery_ref) = entries
        .iter()
        .find_map(|entry| match entry {
            RealmActorMaterialCurrentEntry::Present {
                current_state:
                    arkret_wire::CurrentState::Value {
                        selector: arkret_wire::CurrentSelector::RealmActorRecovery { .. },
                        value,
                        ..
                    },
                source_ref,
            } => Some((
                serde_json::from_value::<RealmActorRecoveryValue>(value.clone()).unwrap(),
                source_ref.clone(),
            )),
            _ => None,
        })
        .unwrap();
    let previous = inventory
        .entries
        .iter()
        .filter_map(|entry| match entry {
            arkret_models_integration::RealmActorArchiveInventoryEntry::Series(entry)
                if &entry.effective_scope == scope =>
            {
                Some(&entry.record)
            }
            _ => None,
        })
        .max_by_key(|record| record.series_pointer_version);
    let version = previous.map_or(1, |record| record.series_pointer_version + 1);
    let mut previous_ids = std::collections::BTreeSet::new();
    if let Some(previous) = previous {
        previous_ids.extend(previous.previous_series_ids.iter().cloned());
        previous_ids.insert(previous.active_series_id.clone());
    }
    let at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    let unsigned =
        arkret_models_collaboration::events_payloads::UnsignedRealmActorKeyBackupActiveSeries::new(
            actor.as_realm_actor_id().unwrap().clone(),
            scope.clone(),
            arkret_wire::BackupSeriesId::new(format!("ak:backup_series:{}", uuid::Uuid::now_v7()))
                .unwrap(),
            version,
            previous_ids.into_iter().collect(),
            inventory.manager_ref,
            recovery_ref,
            recovery.content_backup_recipient_ref,
            at,
            service.package.webhook_signature_policy.key_ref.clone(),
        )
        .unwrap();
    let signature = arkret_wire::Base64UrlString::new(arkret_canonical::base64url_encode(
        signing_key
            .sign(&unsigned.signing_payload_bytes().unwrap())
            .to_bytes(),
    ))
    .unwrap();
    let record = unsigned.attach_signature(signature).unwrap();
    let intent =
        arkret_event_draft::TypedEventDraft::<arkret_wire::event_spec::KeyBackupActiveSeries>::new(
            ScopeRef::RealmControl {
                realm_id: fixture.realm.clone(),
            },
            ActorId::service(service.package.service_id.clone()),
            record.clone(),
        )
        .unwrap()
        .with_applet_id(service.package.applet_id.clone())
        .into_intent(at)
        .unwrap();
    let mut event = intent
        .author_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
        .unwrap();
    arkret_signatures::sign_event(
        &mut event,
        &Ed25519PayloadSigner::new(
            signing_key.clone(),
            applet_service_did(&service.package),
            service.package.webhook_signature_policy.key_ref.clone(),
        ),
        arkret_signatures::SignEventOptions::new().with_created_at(at),
    )
    .unwrap();
    let event = event.into_event();
    let context = arkret::ProducerVerificationContext {
        actor: event.actor_id.clone(),
        verification_method: service.package.webhook_signature_policy.key_ref.clone(),
        public_key: arkret_signatures::PublicKeyMaterial::Ed25519Raw {
            bytes: signing_key.verifying_key().to_bytes().to_vec(),
        },
        digest_suite: arkret_canonical::DigestSuite::Sha256,
    };
    let transaction = arkret::VerifiedSubmission::verify(
        arkret_models_integration::AppletTransactionRequestBody::Events(
            arkret_models_integration::AppletEventTransactionRequestBody {
                applet_id: service.package.applet_id.clone(),
                source_id: service.package.service_id.clone(),
                events: vec![event.clone()],
                committed_events: vec![],
                signals: vec![],
            },
        ),
        |_| Ok(context.clone()),
    )
    .unwrap();
    let outcome = client
        .applet_transaction_from_service(
            event.event_id.as_str(),
            &transaction,
            &service.package.service_id,
            &fixture.state.service_core_id(),
        )
        .await
        .unwrap();
    assert!(
        matches!(
            outcome,
            arkret_models_integration::AppletTransactionResponseBody::Accepted { .. }
        ),
        "{outcome:?}"
    );
    let (accepted, ..) = fixture_archive_inventory(fixture, service, actor).await;
    assert!(accepted.entries.iter().any(|entry|matches!(entry,arkret_models_integration::RealmActorArchiveInventoryEntry::Series(entry) if json!(entry.record)==json!(record))),"actual HTTP accepted series must be retained with verified original source");
    record
}

async fn fixture_backup_recovery_toggle(
    fixture: &Fixture,
    actor: &ActorId,
    enabled: bool,
    grant: Option<&arkret_wire::GrantId>,
) -> (arkret_wire::GrantId, CommittedEventRef) {
    use arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequestBody;
    let grant = if let Some(grant) = grant {
        grant.clone()
    } else {
        let admin = ActorId::account(fixture.pcr.history.account.clone());
        let permission=fixture.admin_event(EventKind::CapabilityGrant,ScopeRef::Realm{realm_id:fixture.realm.clone()},json!({"grant":{
            "schema":"ak.schema.capability.v1","realm_id":fixture.realm,"issuer_id":admin,"subject":admin,
            "actions":["ak.realm.actor.recovery.set"],"resources":[{"kind":"realm_actor","actor_id":actor}],"constraints":[],
            "issuer_authority_refs":[{"kind":"realm_root","realm_id":fixture.realm,"authority_event_ref":fixture.authority_event_ref,"authority_generation":"0"}],
            "issued_at":arkret_canonical::format_timestamp_canonical(chrono::Utc::now())
        }}));
        let grant = arkret_wire::GrantId::from_event_id(&permission.event_id);
        let (status, body) = fixture
            .admin_post_network(
                "/_arkret/self/events",
                arkret_wire::ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT_V1,
                &json!(SelfAuthoritySubmitRequestBody::Event(
                    arkret_wire::EventAdmissionSubmission::new(permission)
                )),
                "native-backup-recovery-permission",
            )
            .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "real target recovery permission: {body}"
        );
        grant
    };
    let recovery = actor_current_ref(
        fixture,
        actor,
        json!({"kind":"realm_actor_recovery","actor_id":actor}),
    )
    .await;
    let manager = actor_current_ref(
        fixture,
        actor,
        json!({"kind":"realm_actor_manager","actor_id":actor}),
    )
    .await;
    let mut event=fixture.admin_event(EventKind::RealmActorRecoverySet,ScopeRef::RealmControl{realm_id:fixture.realm.clone()},json!({
        "target_actor_id":actor,"enabled":enabled,
        "expected_recovery_revision":{"commit_id":recovery.commit_id,"stream_position":recovery.stream_position},
        "expected_manager_revision":{"commit_id":manager.commit_id,"stream_position":manager.stream_position},
    }));
    event.authorization_ref = Some(grant.clone().into());
    let event = fixture.sign_admin(event);
    let (status, body) = fixture
        .admin_post_network(
            "/_arkret/self/events",
            arkret_wire::ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT_V1,
            &json!(SelfAuthoritySubmitRequestBody::Event(
                arkret_wire::EventAdmissionSubmission::new(event.clone())
            )),
            if enabled {
                "native-backup-recovery-enable"
            } else {
                "native-backup-recovery-disable"
            },
        )
        .await;
    assert_eq!(status, StatusCode::OK, "real accepted recovery.set: {body}");
    let advanced = actor_current_ref(
        fixture,
        actor,
        json!({"kind":"realm_actor_recovery","actor_id":actor}),
    )
    .await;
    assert_eq!(advanced.event_id, event.event_id);
    assert_ne!(
        advanced.commit_id, recovery.commit_id,
        "an accepted enable toggle advances the real current source"
    );
    (grant, advanced)
}

async fn fixture_native_backup_outcomes(
    fixture: &Fixture,
    native: &NativeService,
    devices: &arkret_bridge_runtime::managed_device::ManagedDeviceRuntime,
    device: &arkret_bridge_runtime::managed_device::ManagedDevice,
    reader: &arkret_bridge_runtime::managed_device::ManagedDeviceReader,
    selection: &arkret_models_collaboration::RealmActorKeyBackupActiveSeriesValue,
    current_recovery: &CommittedEventRef,
    daily_path: &std::path::Path,
) {
    let (inventory, ..) = fixture_archive_inventory(fixture, native, &device.actor_id).await;
    let entry = inventory
        .entries
        .iter()
        .find_map(|entry| match entry {
            arkret_models_integration::RealmActorArchiveInventoryEntry::Backup(entry)
                if entry.backup.device_id.as_ref() == Some(&device.device_id) =>
            {
                Some(entry)
            }
            _ => None,
        })
        .expect("first real Bot portal must first durably PUT its original root");
    assert_eq!(entry.backup.series_id, selection.active_series_id);
    assert_eq!(
        entry.backup.auth_binding.as_ref().unwrap().recovery_ref,
        *current_recovery
    );
    assert_ne!(
        entry.backup.auth_binding.as_ref().unwrap().recovery_ref,
        selection.recovery_ref,
        "new packet binds current Recovery while selected series preserves its historical source"
    );
    let expected = entry.native_source.admission.clone();
    let packet = entry.backup.clone();
    let idempotency = format!(
        "arkret-key-backup-{}",
        expected
            .envelope_digest
            .as_str()
            .strip_prefix("sha256:")
            .unwrap()
    );
    let original_manifest = arkret_canonical::canonical_json_bytes(&inventory).unwrap();
    let retry = reader
        .client()
        .put_native_key_backup(&packet, &idempotency)
        .await
        .unwrap();
    assert_eq!(json!(retry.value().unwrap().admission), json!(expected));
    let (replayed, ..) = fixture_archive_inventory(fixture, native, &device.actor_id).await;
    assert_eq!(
        arkret_canonical::canonical_json_bytes(&replayed).unwrap(),
        original_manifest,
        "exact original retry changes no native archive revision or custody source"
    );
    let mut changed = packet.clone();
    changed.signature_proof.signature =
        arkret_wire::Base64UrlString::new(arkret_canonical::base64url_encode([0_u8; 64])).unwrap();
    native_read_refusal(
        reader
            .client()
            .put_native_key_backup(&changed, &idempotency)
            .await
            .err()
            .expect("changed original packet must be rejected"),
        409,
        arkret_wire::ErrorCode::DuplicateConflict,
    );
    let (unchanged, ..) = fixture_archive_inventory(fixture, native, &device.actor_id).await;
    assert_eq!(
        arkret_canonical::canonical_json_bytes(&unchanged).unwrap(),
        original_manifest,
        "same backup ID with a changed signature has zero custody writes"
    );
    devices
        .set_owner_status(
            &device.actor_id,
            "native-root-pause-after-ack",
            arkret_models_integration::RealmActorStatusSetPayloadState::Paused,
        )
        .await
        .unwrap();
    let paused_retry = reader
        .client()
        .put_native_key_backup(&packet, &idempotency)
        .await
        .unwrap();
    assert_eq!(
        json!(paused_retry.value().unwrap().admission),
        json!(expected),
        "a fixed accepted PUT is recovered before later business status gates"
    );
    let (paused, ..) = fixture_archive_inventory(fixture, native, &device.actor_id).await;
    assert_eq!(
        arkret_canonical::canonical_json_bytes(&paused).unwrap(),
        original_manifest
    );
    devices
        .set_owner_status(
            &device.actor_id,
            "native-root-explicit-resume-after-ack",
            arkret_models_integration::RealmActorStatusSetPayloadState::Active,
        )
        .await
        .unwrap();
    let head = reader
        .client()
        .native_key_backup_head(&arkret_models_crypto::RealmActorBackupHeadQuery::new(
            device.actor_id.as_realm_actor_id().unwrap().clone(),
            device.effective_scope().circle_id().cloned(),
        ))
        .await
        .unwrap();
    let head = head.value().unwrap();
    assert_eq!(head.items.len(), 1);
    let public = serde_json::to_value(&head.items[0]).unwrap();
    assert!(
        public["metadata"].get("ciphertext").is_none(),
        "native metadata cannot carry packet ciphertext"
    );
    for field in [
        "native_source",
        "device_authorization",
        "governance_history",
        "ciphertext",
    ] {
        assert!(
            public.get(field).is_none(),
            "Device head must not disclose manager source or ciphertext"
        );
    }
    assert_eq!(head.items[0].metadata.backup_id, packet.backup_id);
    fixture_native_backup_transactions(fixture, native, device, reader, daily_path, &packet).await;
}

// The fixture knows its own daily wrapping key. This reads real encrypted
// journal material for test authoring; it neither exports a manager key nor
// adds a production secret or signing interface.
fn fixture_daily_plain(key: &str, raw: &str) -> arkret::KeyBytes {
    use chacha20poly1305::aead::{Aead as _, KeyInit as _, Payload};
    let parts = raw.split('.').collect::<Vec<_>>();
    assert_eq!(parts.len(), 3);
    assert_eq!(parts[0], "v1");
    let nonce = arkret_canonical::base64url_decode(parts[1]).unwrap();
    let ciphertext = arkret_canonical::base64url_decode(parts[2]).unwrap();
    let cipher = chacha20poly1305::XChaCha20Poly1305::new_from_slice(&[0x53; 32]).unwrap();
    arkret::KeyBytes::new(
        cipher
            .decrypt(
                &chacha20poly1305::XNonce::try_from(nonce.as_slice()).unwrap(),
                Payload {
                    msg: &ciphertext,
                    aad: key.as_bytes(),
                },
            )
            .unwrap(),
    )
}

async fn fixture_native_backup_transactions(
    fixture: &Fixture,
    native: &NativeService,
    device: &arkret_bridge_runtime::managed_device::ManagedDevice,
    reader: &arkret_bridge_runtime::managed_device::ManagedDeviceReader,
    daily_path: &std::path::Path,
    original: &arkret_models_crypto::KeyBackup,
) {
    use arkret_bridge_runtime::AuthoringStore as _;
    use coland_storage::KeyBackupStore as _;
    use ed25519_dalek::Signer as _;
    let store = arkret_bridge_runtime::FileAuthoringStore::new(daily_path.to_owned()).unwrap();
    let root_ref = original.contents[0].root_ref.as_ref().unwrap();
    let endpoint = arkret_wire::MlsWelcomeRecipientEndpoint::Device {
        device_id: device.device_id.clone(),
    };
    let root_key = format!(
        "content-root/v1/{}",
        arkret_canonical::canonical_sha256(&(&device.actor_id, &endpoint, root_ref)).unwrap()
    );
    let root_plain = fixture_daily_plain(&root_key, &store.load(&root_key).unwrap().unwrap());
    let root_bytes =
        arkret::KeyBytes::new(serde_json::from_slice::<Vec<u8>>(root_plain.as_slice()).unwrap());
    let root: arkret_models_crypto::ContentRootBackupEntry =
        serde_json::from_slice(root_bytes.as_slice()).unwrap();
    assert_eq!(&root.root_ref, root_ref);
    let signing_key = store
        .entries_with_prefix("managed-device/v1/")
        .unwrap()
        .into_iter()
        .find_map(|(key, raw)| {
            let plain = fixture_daily_plain(&key, &raw);
            let record: Value = serde_json::from_slice(plain.as_slice()).unwrap();
            let authored: arkret_wire::AuthoredEvent =
                serde_json::from_value(record["authorization"].clone()).unwrap();
            if authored.event_id() != &device.authorization_event_id {
                return None;
            }
            let seed = arkret::KeyBytes::new(
                arkret_canonical::base64url_decode(record["device_seed"].as_str().unwrap())
                    .unwrap(),
            );
            let key = SigningKey::from_bytes(seed.as_slice().try_into().unwrap());
            assert_eq!(key.verifying_key(), device.signer().verifying_key());
            Some(key)
        })
        .expect("actual original Device signing key must remain in the daily encrypted journal");
    drop(store);
    let (before, authority, keys, resolution) =
        fixture_archive_inventory(fixture, native, &device.actor_id).await;
    let prepare = reader
        .client()
        .realm_actor_backup_prepare_input(
            arkret_canonical::base64url_encode(rand::random::<[u8; 32]>()),
            &authority,
            &resolution,
            &keys,
        )
        .await
        .unwrap();
    let input = prepare.value().unwrap().clone();
    let create_packet = || {
        arkret::crypto::content_history::RealmActorContentRootBackupDraft {
            backup_id: arkret_wire::BackupId::new(format!("ak:backup:{}", uuid::Uuid::now_v7()))
                .unwrap(),
            realm_actor_id: device.actor_id.as_realm_actor_id().unwrap().clone(),
            created_at: arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now()),
            author: arkret::crypto::backup::KeyBackupAuthBinding {
                device_id: device.device_id.clone(),
                verification_method: original.signature_proof.verification_method.clone(),
                signature_algorithm: original.signature_proof.signature_algorithm,
                device_authorize_event_id: device.authorization_event_id.clone(),
            },
            prepare_input: input.clone(),
            domain_separation: original.domain_separation.clone(),
            series_sequence: original.series_sequence + 1,
            supersedes: Some((
                original.backup_id.clone(),
                arkret_wire::Hash::new(arkret_canonical::sha256_digest(
                    original.signing_payload_bytes().unwrap(),
                ))
                .unwrap(),
            )),
        }
        .seal(root.clone(), |bytes| {
            Ok(signing_key.sign(bytes).to_bytes().to_vec())
        })
        .unwrap()
    };
    let first = create_packet();
    let second = create_packet();
    let original_authority = fixture
        .state
        .test_persistence()
        .device_revocations()
        .applet_managed_device_authority(&device.actor_id, &device.device_id, chrono::Utc::now())
        .await
        .unwrap()
        .unwrap();
    let context = coland_storage::RealmActorBackupPutContext {
        endpoint: coland_storage::AppletManagedDeviceScopeGuard {
            authority: original_authority,
            effective_scope: device.effective_scope().clone(),
            service_did_document: applet_service_id_document(&native.package),
        },
        credential_expires_at: chrono::Utc::now() + chrono::Duration::minutes(1),
        authority: authority.clone(),
        authority_keys: keys,
        origin_resolution: resolution,
        governance_history: before
            .entries
            .iter()
            .find_map(|entry| match entry {
                arkret_models_integration::RealmActorArchiveInventoryEntry::Backup(entry) => {
                    Some(entry.native_source.governance_history.clone())
                }
                _ => None,
            })
            .unwrap(),
        max_actor_bytes: 0,
        max_realm_bytes: 0,
        idempotency_key: "native-real-quota-rollback".into(),
    };
    let signer = |input| {
        arkret_signatures::realm_actor_content_backup::sign_realm_actor_content_backup_admission(
            input,
            fixture
                .state
                .service_verification_method("notary-key")
                .unwrap(),
            fixture.state.notary_signing_key().as_ref(),
        )
        .map_err(PersistenceError::database)
    };
    let store = coland_storage_postgres::PgKeyBackupStore {
        pool: fixture.pool.clone(),
    };
    let refused = store
        .put_native(&first, &context, &signer)
        .await
        .unwrap_err();
    assert!(refused.to_string().contains("quota_exceeded"), "{refused}");
    let (after_quota, ..) = fixture_archive_inventory(fixture, native, &device.actor_id).await;
    assert_eq!(
        arkret_canonical::canonical_json_bytes(&before).unwrap(),
        arkret_canonical::canonical_json_bytes(&after_quota).unwrap(),
        "quota failure rolls back the real packet, ACK, identity and archive revision together"
    );
    let idempotency = |packet: &arkret_models_crypto::KeyBackup| {
        format!(
            "arkret-key-backup-{}",
            arkret_canonical::canonical_sha256(packet)
                .unwrap()
                .strip_prefix("sha256:")
                .unwrap()
        )
    };
    let first_key = idempotency(&first);
    let second_key = idempotency(&second);
    let (left, right) = tokio::join!(
        reader.client().put_native_key_backup(&first, &first_key),
        reader.client().put_native_key_backup(&second, &second_key)
    );
    let (winner, accepted, loser) = match (left, right) {
        (Ok(accepted), Err(loser)) => (&first, accepted, loser),
        (Err(loser), Ok(accepted)) => (&second, accepted, loser),
        _ => panic!("two real signed successors of the same head must admit exactly one original"),
    };
    native_read_refusal(loser, 409, arkret_wire::ErrorCode::Conflict);
    assert_eq!(accepted.value().unwrap().backup_id, winner.backup_id);
    let (after, ..) = fixture_archive_inventory(fixture, native, &device.actor_id).await;
    assert_eq!(after.archive_revision, before.archive_revision + 1);
    assert_eq!(
        after.entries.len(),
        before.entries.len() + 1,
        "the CAS loser has no first-PUT custody row"
    );
    let replay = reader
        .client()
        .put_native_key_backup(winner, &idempotency(winner))
        .await
        .unwrap();
    assert_eq!(
        json!(replay.value().unwrap()),
        json!(accepted.value().unwrap())
    );
}

async fn fixture_native_archived_head(
    fixture: &Fixture,
    device: &arkret_bridge_runtime::managed_device::ManagedDevice,
    reader: &arkret_bridge_runtime::managed_device::ManagedDeviceReader,
) {
    use arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequestBody;
    let query = arkret_models_crypto::RealmActorBackupHeadQuery::new(
        device.actor_id.as_realm_actor_id().unwrap().clone(),
        device.effective_scope().circle_id().cloned(),
    );
    let initial = reader
        .client()
        .native_key_backup_head(&query)
        .await
        .unwrap();
    let expected = initial.value().unwrap().clone();
    assert_eq!(expected.items.len(), 1);
    let mut transitions = vec![
        (EventKind::RealmArchive, EventKind::RealmRestore, json!({})),
        (EventKind::RealmFreeze, EventKind::RealmUnfreeze, json!({})),
    ];
    if let Some(circle) = device.effective_scope().circle_id() {
        transitions.push((
            EventKind::CircleArchive,
            EventKind::CircleRestore,
            json!({"target_ref":circle}),
        ));
    }
    for (close, reopen, payload) in transitions {
        for kind in [close, reopen] {
            let scope = if matches!(kind, EventKind::CircleArchive | EventKind::CircleRestore) {
                device.effective_scope().clone()
            } else {
                ScopeRef::Realm {
                    realm_id: fixture.realm.clone(),
                }
            };
            let event = fixture.admin_event(kind.clone(), scope, payload.clone());
            let (status, body) = fixture
                .admin_post_network(
                    "/_arkret/self/events",
                    arkret_wire::ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT_V1,
                    &json!(SelfAuthoritySubmitRequestBody::Event(
                        arkret_wire::EventAdmissionSubmission::new(event)
                    )),
                    &format!("native-backup-head-lifecycle-{}", kind.as_str()),
                )
                .await;
            assert_eq!(
                status,
                StatusCode::OK,
                "actual archive/freeze/restore event: {body}"
            );
            let head = reader
                .client()
                .native_key_backup_head(&query)
                .await
                .unwrap();
            assert_eq!(
                json!(head.value().unwrap()),
                json!(expected),
                "a current member's exact metadata head remains readable through {kind:?}"
            );
            let item = &head.value().unwrap().items[0];
            let challenge=reader.client().issue_native_key_backup_unlock_challenge(&item.metadata.backup_id,&arkret_models_crypto::RealmActorBackupIssueUnlockChallengeRequestBody{
                request_id:arkret_wire::Base64UrlString::new(arkret_canonical::base64url_encode(rand::random::<[u8;32]>())).unwrap(),
                kind:arkret_models_crypto::RealmActorBackupUnlockChallengeKind::RealmActorDevice,
                purpose:arkret_models_crypto::RealmActorBackupUnlockChallengePurpose::SeriesPredecessor,
                realm_actor_id:device.actor_id.as_realm_actor_id().unwrap().clone(),effective_scope:device.effective_scope().clone(),
                envelope_digest:item.admission.envelope_digest.clone(),
            }).await.unwrap();
            let unlocked = reader
                .client()
                .unlock_native_key_backup(&challenge)
                .await
                .unwrap();
            assert_eq!(
                unlocked.value().unwrap().backup.backup_id,
                item.metadata.backup_id
            );
            assert_eq!(
                unlocked.value().unwrap().admission.envelope_digest,
                item.admission.envelope_digest
            );
        }
    }
}
