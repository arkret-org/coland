//! Call capture through real installed Service signing and peer admission.
use arkret_models_collaboration::authority_commit::{
    HistoricalProducerSignerFact, PeerAuthorityForwardEventRequestBody,
    PeerAuthoritySubmitRequestBody,
};
use arkret_models_collaboration::objects::blob::{
    BlobStorageEncryption, BlobStorageEncryptionScheme, BlobVisibility,
};
use diesel::sql_types::{BigInt, Jsonb, Text};
use diesel_async::RunQueryDsl;

use super::*;

mod key_source_cases;

#[derive(diesel::QueryableByName)]
struct Current {
    #[diesel(sql_type = Jsonb)]
    value: Value,
}

#[derive(diesel::QueryableByName)]
struct Count {
    #[diesel(sql_type = BigInt)]
    value: i64,
}

async fn capture_current(pool: &PgPool, call: &arkret_wire::CallId, kind: &str) -> Value {
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query("SELECT value FROM call_component_current_states WHERE call_id=$1 AND selector->>'kind'=$2 AND selector->>'recording_id'='segment-1'")
        .bind::<Text,_>(call.as_str()).bind::<Text,_>(kind).get_result::<Current>(&mut *conn).await.unwrap().value
}

async fn consumption_count(pool: &PgPool, grant: &arkret_wire::GrantId) -> i64 {
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query(
        "SELECT count(*)::bigint AS value FROM capability_quota_consumptions WHERE grant_id=$1",
    )
    .bind::<Text, _>(grant.as_str())
    .get_result::<Count>(&mut *conn)
    .await
    .unwrap()
    .value
}

async fn deactivate_actor_checkpoint(factory: &AppletAuthoringFactory) {
    use arkret_models_collaboration::account_status::{
        UnsignedAccountStatusReceipt, UnsignedAccountStatusRecord,
    };
    use arkret_models_collaboration::objects::account_status::AccountStatus;
    let state = &factory.fixture.state;
    let account = &factory.fixture.pcr.history.account;
    let persistence = state.test_persistence();
    let store = persistence.account_status_replicas();
    let mut previous = store
        .current(account.station_id.as_str(), account)
        .await
        .unwrap();
    let statuses = if previous.is_none() {
        vec![AccountStatus::Active, AccountStatus::Deactivated]
    } else {
        vec![AccountStatus::Deactivated]
    };
    for status in statuses {
        let at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
        let record = arkret_signatures::account_status::sign_account_status_record(
            UnsignedAccountStatusRecord {
                schema: arkret_wire::SchemaId::ACCOUNT_STATUS_RECORD_V1.into(),
                account_authority_id: account.station_id.clone(),
                account_id: account.clone(),
                principal_control_realm_id: factory.fixture.pcr.unit.transactions[0]
                    .event
                    .realm_id
                    .clone(),
                binding_version: 1,
                status_sequence: previous
                    .as_ref()
                    .map_or(1, |record| record.status_sequence + 1),
                previous_account_status_record_id: previous
                    .as_ref()
                    .map(|record| record.account_status_record_id.clone()),
                status,
                reason_code: None,
                reason: None,
                issued_at: at,
                expires_at: None,
            },
            state.service_verification_method("notary-key").unwrap(),
            state.notary_signing_key().as_ref(),
        )
        .unwrap();
        let receipt = arkret_signatures::account_status::sign_account_status_receipt(
            UnsignedAccountStatusReceipt {
                receipt_id: arkret_wire::ReceiptId::new(format!(
                    "ak:receipt:{}",
                    uuid::Uuid::now_v7()
                ))
                .unwrap(),
                account_status_record_id: record.account_status_record_id.clone(),
                record_digest: record.payload_digest().unwrap(),
                account_authority_id: account.station_id.clone(),
                account_id: account.clone(),
                status_sequence: record.status_sequence,
                receiver_id: state.service_core_id(),
                accepted_at: at,
                verification_method: state.service_verification_method("notary-key").unwrap(),
            },
            state.notary_signing_key().as_ref(),
        )
        .unwrap();
        let key = arkret_signatures::PublicKeyMaterial::Ed25519Raw {
            bytes: state.notary_verifying_key().as_bytes().to_vec(),
        };
        arkret_signatures::account_status::verify_account_status_record(&record, &key).unwrap();
        arkret_signatures::account_status::verify_account_status_receipt(&receipt, &key).unwrap();
        receipt.validate_for_record(&record).unwrap();
        assert!(matches!(
            store.append(&record, &receipt).await.unwrap(),
            coland_storage::AccountStatusReplicaAppend::Accepted(_)
        ));
        previous = Some(record);
    }
    assert_eq!(
        store
            .current(account.station_id.as_str(), account)
            .await
            .unwrap()
            .unwrap()
            .status,
        AccountStatus::Deactivated
    );
}

pub async fn registered_call_capture_result(pool: PgPool) {
    realm_native_fixture::boxed_step(|| {
        registered_call_capture_scenario(pool, CaptureScenario::Standard)
    })
    .await;
}

pub async fn registered_call_capture_result_rejects_deactivated_account(pool: PgPool) {
    realm_native_fixture::boxed_step(|| {
        registered_call_capture_scenario(pool, CaptureScenario::DeactivatedActor)
    })
    .await;
}

pub async fn registered_call_capture_key_source_and_geometry(pool: PgPool) {
    realm_native_fixture::boxed_step(|| {
        registered_call_capture_scenario(pool, CaptureScenario::KeySources)
    })
    .await;
}

enum CaptureScenario {
    Standard,
    DeactivatedActor,
    KeySources,
}

async fn registered_call_capture_scenario(pool: PgPool, scenario: CaptureScenario) {
    let factory =
        realm_native_fixture::boxed_step(|| AppletAuthoringFactory::new(pool.clone())).await;
    let id = AppletId::new(format!("ak:applet:{}", uuid::Uuid::now_v7())).unwrap();
    let install = factory.prepare_install(&id, "call-capture").await;
    let store = PgAppletStore { pool: pool.clone() };
    install.commit(&store).await.unwrap();
    let record = store
        .get(
            id.as_str(),
            install.input.package.service_id.as_str(),
            &coland_storage::applet_effective_scope_key(&install.effective_scope).unwrap(),
        )
        .await
        .unwrap()
        .unwrap();
    let package: AppletPackage = serde_json::from_value(record["package"].clone()).unwrap();
    let scope = install.effective_scope.clone();
    let (mut recording_group, mut recording_key_ref) =
        realm_native_fixture::boxed_step(|| key_source_cases::genesis(&factory.fixture, &scope))
            .await;
    if matches!(scenario, CaptureScenario::Standard) {
        recording_key_ref.group_state_ref =
            arkret_models_crypto::EncryptedAttachmentGroupStateRef::Digest(
                recording_key_ref
                    .group_state_ref
                    .event_id()
                    .unwrap()
                    .event_digest(),
            );
    }
    let actor = ActorId::account(factory.fixture.pcr.history.account.clone());
    let permission = factory.fixture.admin_event(EventKind::CapabilityGrant, scope.clone(), json!({"grant":{
        "schema":"ak.schema.capability.v1","realm_id":factory.fixture.realm,"issuer_id":actor,"subject":actor,
        "actions":["ak.call.record"],"resources":[{"kind":"realm","realm_id":factory.fixture.realm}],
        "constraints":[{"constraint_kind":"quota","constraint_subkind":"rate","effect":"allow","max_operation_count":1,"period":"PT1H","constraint_scope":"per_actor"}],
        "issuer_authority_refs":[{"kind":"realm_root","realm_id":factory.fixture.realm,"authority_event_ref":factory.fixture.authority_event_ref,"authority_generation":"0"}],
        "issued_at":arkret_canonical::format_timestamp_canonical(chrono::Utc::now())}}));
    let initiator = arkret_wire::GrantId::from_event_id(&permission.event_id);
    accepted_admin_domain_event(&factory.fixture, permission).await;
    let media = factory.fixture.admin_event(EventKind::RealmMediaService, scope.clone(), json!({"value":{
        "service_id":package.service_id,"recording_supported":true,"foci":[{"focus_id":"capture-focus","focus_kind":"livekit",
        "token_endpoint":"https://media.example/token","connect_url":"wss://media.example/connect"}]}}));
    accepted_admin_domain_event(&factory.fixture, media).await;
    let create = factory.fixture.admin_event(
        EventKind::CallCreate,
        scope.clone(),
        json!({"initial_state":"ringing"}),
    );
    let call = arkret_wire::CallId::from_event_id(&create.event_id);
    accepted_admin_domain_event(&factory.fixture, create).await;
    let active = factory.fixture.admin_event(EventKind::CallState, scope.clone(), json!({"call_id":call,
        "state_transition":{"from":"ringing","to":"active"},"focus":{"mode":"sfu","session_focus":"capture-focus"}}));
    accepted_admin_domain_event(&factory.fixture, active.clone()).await;
    let retention = json!({"consent_confirmed":true,"retention_expires_at":arkret_canonical::format_timestamp_canonical(chrono::Utc::now()+chrono::Duration::hours(1))});
    let mut start = active.clone();
    start.kind = EventKind::CallRecordingStart;
    start.created_at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    start.payload = serde_json::from_value(json!({"call_id":call,"recording_id":"segment-1",
        "recording_agent_id":package.service_id,"capture_kind":"recording","mode":"audio","visible_notice":true,"capture_metadata":{"key_ref":recording_key_ref,"retention":retention}})).unwrap();
    start.authorization_ref =
        Some(arkret_wire::AuthorizationRef::new(initiator.to_string()).unwrap());
    start = factory.fixture.sign_admin(start);
    if matches!(scenario, CaptureScenario::KeySources) {
        realm_native_fixture::boxed_step(|| {
            key_source_cases::before_start(&factory.fixture, &start)
        })
        .await;
    }
    accepted_admin_domain_event(&factory.fixture, start.clone()).await;
    assert_eq!(consumption_count(&pool, &initiator).await, 1);
    assert_eq!(
        capture_current(&pool, &call, "call_recording_state").await,
        json!("recording")
    );
    let pending = capture_current(&pool, &call, "call_recording_artifact").await;
    assert_eq!(pending["status"], "pending");
    assert_eq!(pending["details"]["key_ref"], json!(recording_key_ref));
    assert_eq!(
        pending["details"]["recording_start_event_id"],
        json!(start.event_id)
    );
    let source = PgAuthorityCommitStore { pool: pool.clone() };
    let start_full = source
        .committed_event(&start.event_id)
        .await
        .unwrap()
        .unwrap();
    let stop = factory.fixture.admin_event(
        EventKind::CallState,
        scope.clone(),
        json!({"call_id":call,
        "recording_transition":{"recording_id":"segment-1","from":"recording","to":"stopped"}}),
    );
    accepted_admin_domain_event(&factory.fixture, stop).await;
    assert_eq!(
        capture_current(&pool, &call, "call_recording_artifact").await,
        pending
    );

    let next_recording_key = if matches!(scenario, CaptureScenario::KeySources) {
        let next = realm_native_fixture::boxed_step(|| {
            key_source_cases::advance(&factory.fixture, &scope, &mut recording_group)
        })
        .await;
        realm_native_fixture::boxed_step(|| {
            key_source_cases::reject_stale_start(&factory.fixture, &start, &next)
        })
        .await;
        Some(next)
    } else {
        None
    };

    // Store public ciphertext metadata through the real delivery service. It
    // is deliberately opaque to the Station; receiver AEAD is a separate test.
    let ciphertext = b"opaque encrypted recording fixture".to_vec();
    let digest = arkret_canonical::sha256_hex(&ciphertext);
    let blob_ref = format!("ak:blob:sha256:{digest}");
    let storage_key = factory.fixture.state.test_object_key_for_sha256(&digest);
    factory
        .fixture
        .state
        .test_put_object(&storage_key, ciphertext.clone())
        .await
        .unwrap();
    factory
        .fixture
        .state
        .test_persistence()
        .blobs()
        .put(
            &blob_ref,
            &coland_storage::BlobRecord {
                sha256: digest.clone(),
                size_bytes: ciphertext.len() as i64,
                // app_state_with_persistence supplies the real test object
                // port named `memory`; its metadata remains in PostgreSQL.
                storage_backend: "memory".into(),
                storage_key,
                media_type: "application/octet-stream".into(),
                filename: None,
                realm_id: Some(factory.fixture.realm.to_string()),
                encryption: Some(BlobStorageEncryption {
                    scheme: BlobStorageEncryptionScheme::StreamV1,
                }),
                legal_hold: false,
                redacted: false,
                visibility: BlobVisibility::RealmBound,
                uploaded_by: actor.to_string(),
                created_at: chrono::Utc::now(),
            },
        )
        .await
        .unwrap();
    assert_eq!(
        factory.fixture.state.test_object_by_sha256(&digest).await,
        ciphertext,
        "the exact raw ciphertext must exist behind its content address"
    );
    let stored_blob = factory
        .fixture
        .state
        .test_persistence()
        .blobs()
        .get(&blob_ref)
        .await
        .unwrap()
        .expect("the actual BlobRecord must be durable before ready admission");
    assert_eq!(stored_blob.sha256, digest);
    assert_eq!(stored_blob.size_bytes, ciphertext.len() as i64);
    let artifact = json!({"schema":"ak.schema.call_recording_artifact.v1","realm_id":factory.fixture.realm,"call_id":call,
        "recording_id":"segment-1","recording_start_event_id":start.event_id,"blob_ref":blob_ref,"size_bytes":ciphertext.len(),
        "duration_ms":10,"media_type":"audio/ogg","encryption":{"encryption_algorithm":"mls_exporter_aead_xchacha20poly1305_stream",
            "exporter_label":"ak.rtc-recording-key/v1","context":{"realm_id":factory.fixture.realm,"call_id":call,"recording_id":"segment-1",
                "focus_id":"capture-focus","media_service_id":package.service_id,"recording_start_event_id":start.event_id},
            "key_ref":recording_key_ref,"nonce_prefix":arkret_canonical::base64url_encode([0x53;19]),"segment_bytes":1024},
        "retention":retention,"produced_by":package.service_id,"recording_initiator_capability_ref":initiator,
        "created_at":arkret_canonical::format_timestamp_canonical(chrono::Utc::now())});
    let service_grant_for = |action: &str| {
        let event: Event = serde_json::from_value(
            record["capability_grant_events"]
                .as_array()
                .unwrap()
                .iter()
                .find(|event| {
                    event["payload"]["grant"]["actions"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .any(|named| named == action)
                })
                .unwrap()
                .clone(),
        )
        .unwrap();
        arkret_wire::GrantId::from_event_id(&event.event_id)
    };
    let service_grant = service_grant_for("ak.call.record");
    let sign = |artifact: Value,
                guard: &arkret_wire::RealmCommitId,
                producer_grant: &arkret_wire::GrantId| {
        let mut event = start.clone();
        event.kind = EventKind::CallState;
        event.created_at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
        event.payload = serde_json::from_value(json!({"call_id":call,
            "recording_transition":{"recording_id":"segment-1","from":"stopped","to":"ready",
                "expected_commit_id":guard,"capture_metadata":{"artifact":artifact}}}))
        .unwrap();
        event.executed_by = Some(ActorId::service(package.service_id.clone()));
        event.applet_id = Some(id.clone());
        event.authorization_ref =
            Some(arkret_wire::AuthorizationRef::new(producer_grant.to_string()).unwrap());
        event.producer_proof = None;
        let signer = arkret_test_kit::seeded_signer_for_seed(
            applet_service_signing_key(&package.webhook_signature_policy.key_ref).to_bytes(),
            applet_service_did(&package),
            package.webhook_signature_policy.key_ref.clone(),
        );
        arkret_test_kit::sign_verifiable_event(
            event,
            &signer,
            arkret_canonical::DigestSuite::Sha256,
        )
        .unwrap()
        .expect_verifiable()
    };
    let forward = |event: Event| {
        serde_json::to_value(PeerAuthoritySubmitRequestBody::AuthorityForwardEvent(
            PeerAuthorityForwardEventRequestBody::new(
                arkret_wire::EventAdmissionSubmission::new(event),
                None,
                None,
                None,
            )
            .unwrap(),
        ))
        .unwrap()
    };
    if let Some(next) = &next_recording_key {
        for (label, invalid) in
            key_source_cases::invalid_artifacts(&artifact, &recording_key_ref, next)
        {
            let body = forward(sign(invalid, &start_full.commit.commit_id, &service_grant));
            realm_native_fixture::boxed_step(|| {
                key_source_cases::reject_ready(&factory.fixture, &package, &body, label)
            })
            .await;
        }
    }
    let before = source
        .stream_head(&arkret_wire::CommitStreamRef::from_scope(&scope, None).unwrap())
        .await
        .unwrap();
    let wrong_producer = sign(
        artifact.clone(),
        &start_full.commit.commit_id,
        &service_grant_for("ak.message.create"),
    );
    let (status, refusal) = factory
        .fixture
        .service_post(
            &package,
            "/_arkret/peer/events",
            arkret_wire::ServiceOperationId::PEER_EVENTS_COMMAND_SUBMIT_V1,
            &forward(wrong_producer),
            "call-ready-wrong-producer-grant",
        )
        .await;
    assert!(
        status.is_client_error(),
        "wrong producer action: {status} {refusal}"
    );
    assert_eq!(
        source
            .stream_head(&arkret_wire::CommitStreamRef::from_scope(&scope, None).unwrap())
            .await
            .unwrap(),
        before
    );
    let mut mixed = sign(
        artifact.clone(),
        &start_full.commit.commit_id,
        &service_grant,
    );
    mixed.payload.insert(
        "focus".into(),
        json!({"mode":"sfu","session_focus":"capture-focus"}),
    );
    mixed.producer_proof = None;
    let signer = arkret_test_kit::seeded_signer_for_seed(
        applet_service_signing_key(&package.webhook_signature_policy.key_ref).to_bytes(),
        applet_service_did(&package),
        package.webhook_signature_policy.key_ref.clone(),
    );
    let mixed = arkret_test_kit::sign_verifiable_event(
        mixed,
        &signer,
        arkret_canonical::DigestSuite::Sha256,
    )
    .unwrap()
    .expect_verifiable();
    let (status, refusal) = factory
        .fixture
        .service_post(
            &package,
            "/_arkret/peer/events",
            arkret_wire::ServiceOperationId::PEER_EVENTS_COMMAND_SUBMIT_V1,
            &forward(mixed),
            "call-ready-mixed-axis-without-service-join",
        )
        .await;
    assert!(
        status.is_client_error(),
        "recording grant cannot authorize another axis: {status} {refusal}"
    );
    assert_eq!(
        capture_current(&pool, &call, "call_recording_artifact").await,
        pending
    );
    let other_id = AppletId::new(format!("ak:applet:{}", uuid::Uuid::now_v7())).unwrap();
    let other_install = factory
        .prepare_install(&other_id, "call-capture-other-service")
        .await;
    other_install.commit(&store).await.unwrap();
    let other_record = store
        .get(
            other_id.as_str(),
            other_install.input.package.service_id.as_str(),
            &coland_storage::applet_effective_scope_key(&scope).unwrap(),
        )
        .await
        .unwrap()
        .unwrap();
    let other_package: AppletPackage =
        serde_json::from_value(other_record["package"].clone()).unwrap();
    let other_grant_event: Event = serde_json::from_value(
        other_record["capability_grant_events"]
            .as_array()
            .unwrap()
            .iter()
            .find(|event| {
                event["payload"]["grant"]["actions"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|action| action == "ak.call.record")
            })
            .unwrap()
            .clone(),
    )
    .unwrap();
    let mut other = sign(
        artifact.clone(),
        &start_full.commit.commit_id,
        &service_grant,
    );
    other.executed_by = Some(ActorId::service(other_package.service_id.clone()));
    other.applet_id = Some(other_id);
    other.authorization_ref = Some(
        arkret_wire::AuthorizationRef::new(
            arkret_wire::GrantId::from_event_id(&other_grant_event.event_id).to_string(),
        )
        .unwrap(),
    );
    other.producer_proof = None;
    let signer = arkret_test_kit::seeded_signer_for_seed(
        applet_service_signing_key(&other_package.webhook_signature_policy.key_ref).to_bytes(),
        applet_service_did(&other_package),
        other_package.webhook_signature_policy.key_ref.clone(),
    );
    let other = arkret_test_kit::sign_verifiable_event(
        other,
        &signer,
        arkret_canonical::DigestSuite::Sha256,
    )
    .unwrap()
    .expect_verifiable();
    let (status, refusal) = factory
        .fixture
        .service_post(
            &other_package,
            "/_arkret/peer/events",
            arkret_wire::ServiceOperationId::PEER_EVENTS_COMMAND_SUBMIT_V1,
            &forward(other),
            "call-ready-another-real-service",
        )
        .await;
    assert!(
        status.is_client_error(),
        "another actual installed Service is not the original recorder: {status} {refusal}"
    );
    assert_eq!(
        capture_current(&pool, &call, "call_recording_artifact").await,
        pending
    );
    let mut wrong_source = artifact.clone();
    wrong_source["recording_initiator_capability_ref"] = json!(service_grant);
    let (status, refusal) = factory
        .fixture
        .service_post(
            &package,
            "/_arkret/peer/events",
            arkret_wire::ServiceOperationId::PEER_EVENTS_COMMAND_SUBMIT_V1,
            &forward(sign(
                wrong_source,
                &start_full.commit.commit_id,
                &service_grant,
            )),
            "call-ready-wrong-initiator",
        )
        .await;
    assert!(
        status.is_client_error(),
        "changed original source: {status} {refusal}"
    );
    assert_eq!(
        capture_current(&pool, &call, "call_recording_artifact").await,
        pending
    );
    let consumed = {
        let mut conn = pool.get().await.unwrap();
        let row = diesel::sql_query(
            "SELECT to_jsonb(c) AS value FROM capability_quota_consumptions c WHERE grant_id=$1",
        )
        .bind::<Text, _>(initiator.as_str())
        .get_result::<Current>(&mut *conn)
        .await
        .unwrap()
        .value;
        diesel::sql_query("DELETE FROM capability_quota_consumptions WHERE grant_id=$1")
            .bind::<Text, _>(initiator.as_str())
            .execute(&mut *conn)
            .await
            .unwrap();
        row
    };
    let (status, refusal) = factory
        .fixture
        .service_post(
            &package,
            "/_arkret/peer/events",
            arkret_wire::ServiceOperationId::PEER_EVENTS_COMMAND_SUBMIT_V1,
            &forward(sign(
                artifact.clone(),
                &start_full.commit.commit_id,
                &service_grant,
            )),
            "call-ready-missing-start-consumption",
        )
        .await;
    assert!(
        status.is_client_error() || status.is_server_error(),
        "missing original consumption must refuse: {status} {refusal}"
    );
    {
        let mut conn = pool.get().await.unwrap();
        diesel::sql_query("INSERT INTO capability_quota_consumptions SELECT * FROM jsonb_populate_record(NULL::capability_quota_consumptions,$1)")
            .bind::<Jsonb,_>(consumed).execute(&mut *conn).await.unwrap();
    }
    let ready = sign(
        artifact.clone(),
        &start_full.commit.commit_id,
        &service_grant,
    );
    let request = PeerAuthoritySubmitRequestBody::AuthorityForwardEvent(
        PeerAuthorityForwardEventRequestBody::new(
            arkret_wire::EventAdmissionSubmission::new(ready.clone()),
            None,
            None,
            None,
        )
        .unwrap(),
    );
    let body = serde_json::to_value(request).unwrap();
    let (status, outcome) = factory
        .fixture
        .service_post(
            &package,
            "/_arkret/peer/events",
            arkret_wire::ServiceOperationId::PEER_EVENTS_COMMAND_SUBMIT_V1,
            &body,
            "call-recording-ready",
        )
        .await;
    assert_eq!(status, StatusCode::OK, "real recording ready: {outcome}");
    let full = source
        .committed_event(&ready.event_id)
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(
        source
            .producer_signer_fact(&full.event, &full.commit)
            .await
            .unwrap(),
        Some(HistoricalProducerSignerFact::Service(_))
    ));
    assert_eq!(
        capture_current(&pool, &call, "call_recording_state").await,
        json!("stopped")
    );
    assert_eq!(
        capture_current(&pool, &call, "call_recording_artifact").await,
        json!({"status":"ready","details":{"artifact":artifact}})
    );
    assert_eq!(
        consumption_count(&pool, &initiator).await,
        1,
        "ready must not charge Start again"
    );
    let material = source
        .realm_state_snapshot_material_for_account(
            &factory.fixture.realm,
            &factory.fixture.pcr.history.account,
        )
        .await
        .unwrap()
        .unwrap();
    let mut capture_rows = 0;
    for entry in &material.current_state_entries {
        let arkret_wire::CurrentState::Value {
            selector,
            revision,
            value,
            ..
        } = entry;
        match selector {
            arkret_wire::CurrentSelector::CallRecordingState {
                call_id,
                recording_id,
            } if call_id == &call && recording_id.as_str() == "segment-1" => {
                assert_eq!(value, &json!("stopped"));
                capture_rows += 1;
            }
            arkret_wire::CurrentSelector::CallRecordingArtifact {
                call_id,
                recording_id,
            } if call_id == &call && recording_id.as_str() == "segment-1" => {
                assert_eq!(revision.commit_id, full.commit.commit_id);
                assert_eq!(
                    value,
                    &json!({"status":"ready","details":{"artifact":artifact}})
                );
                capture_rows += 1;
            }
            _ => {}
        }
    }
    assert_eq!(
        capture_rows, 2,
        "authorized whole-current material must contain both independent capture axes"
    );
    let (status, replay) = factory
        .fixture
        .service_post(
            &package,
            "/_arkret/peer/events",
            arkret_wire::ServiceOperationId::PEER_EVENTS_COMMAND_SUBMIT_V1,
            &body,
            "call-recording-ready-replay",
        )
        .await;
    assert_eq!(status, StatusCode::OK, "exact ready replay: {replay}");
    assert_eq!(consumption_count(&pool, &initiator).await, 1);
    if matches!(scenario, CaptureScenario::DeactivatedActor) {
        let mut policy = {
            let mut conn = pool.get().await.unwrap();
            diesel::sql_query(
                "SELECT value FROM realm_policy_bundle_current_states WHERE realm_id=$1",
            )
            .bind::<Text, _>(factory.fixture.realm.as_str())
            .get_result::<Current>(&mut *conn)
            .await
            .unwrap()
            .value
        };
        policy["policy_revision"] = json!(policy["policy_revision"].as_u64().unwrap() + 1);
        policy["account_deactivation"] = json!({"member_action":"retain_membership"});
        let retain =
            factory
                .fixture
                .admin_event(EventKind::RealmPolicyBundle, scope.clone(), policy);
        accepted_admin_domain_event(&factory.fixture, retain).await;
        deactivate_actor_checkpoint(&factory).await;
        let (head, quota_count, membership) = {
            let mut conn = pool.get().await.unwrap();
            let count = diesel::sql_query(
                "SELECT count(*)::bigint AS value FROM capability_quota_consumptions",
            )
            .get_result::<Count>(&mut *conn)
            .await
            .unwrap()
            .value;
            let membership = diesel::sql_query("SELECT to_jsonb(membership) AS value FROM member_state_current_states WHERE realm_id=$1 AND member_id=$2")
                .bind::<Text,_>(factory.fixture.realm.as_str()).bind::<Text,_>(actor.to_string())
                .get_result::<Current>(&mut *conn).await.unwrap().value;
            drop(conn);
            (
                source
                    .stream_head(&arkret_wire::CommitStreamRef::from_scope(&scope, None).unwrap())
                    .await
                    .unwrap(),
                count,
                membership,
            )
        };
        assert_eq!(
            membership,
            json!("join"),
            "the lifecycle barrier must be independent of Realm membership"
        );
        let candidate = sign(artifact.clone(), &full.commit.commit_id, &service_grant);
        let candidate_id = candidate.event_id.clone();
        let (status, refusal) = factory
            .fixture
            .service_post(
                &package,
                "/_arkret/peer/events",
                arkret_wire::ServiceOperationId::PEER_EVENTS_COMMAND_SUBMIT_V1,
                &forward(candidate),
                "call-ready-deactivated-actor",
            )
            .await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "new delegated Account act was not rejected: {status} {refusal}"
        );
        assert_eq!(
            refusal["code"],
            arkret_wire::ErrorCode::ACCOUNT_DEACTIVATED,
            "inactive Account refusal must be a typed protocol failure, not a server error"
        );
        assert!(
            source
                .committed_event(&candidate_id)
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(
            source
                .stream_head(&arkret_wire::CommitStreamRef::from_scope(&scope, None).unwrap())
                .await
                .unwrap(),
            head
        );
        assert_eq!(
            capture_current(&pool, &call, "call_recording_artifact").await,
            json!({"status":"ready","details":{"artifact":artifact}})
        );
        assert_eq!(consumption_count(&pool, &initiator).await, 1);
        let mut conn = pool.get().await.unwrap();
        assert_eq!(
            diesel::sql_query(
                "SELECT count(*)::bigint AS value FROM capability_quota_consumptions"
            )
            .get_result::<Count>(&mut *conn)
            .await
            .unwrap()
            .value,
            quota_count
        );
        drop(conn);
        let (status, replay) = factory
            .fixture
            .service_post(
                &package,
                "/_arkret/peer/events",
                arkret_wire::ServiceOperationId::PEER_EVENTS_COMMAND_SUBMIT_V1,
                &body,
                "call-ready-original-replay-after-deactivation",
            )
            .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "deactivation must not rewrite an already accepted original: {replay}"
        );
        assert_eq!(replay["status"], "duplicate");
        assert_eq!(
            replay["commit"],
            serde_json::to_value(&full.commit).unwrap()
        );
        return;
    }
    let service_source: Event = serde_json::from_value(
        record["capability_grant_events"]
            .as_array()
            .unwrap()
            .iter()
            .find(|event| {
                event["payload"]["grant"]["actions"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|action| action == "ak.call.record")
            })
            .unwrap()
            .clone(),
    )
    .unwrap();
    let mut refusal_grant = json!(service_source.payload)["grant"].clone();
    refusal_grant["issued_at"] = json!(arkret_canonical::format_timestamp_canonical(
        chrono::Utc::now()
    ));
    refusal_grant["constraints"].as_array_mut().unwrap().push(json!({"constraint_kind":"temporal","constraint_subkind":"window","effect":"deny","expires_at":arkret_canonical::format_timestamp_canonical(chrono::Utc::now()+chrono::Duration::hours(1))}));
    let refusal_event = factory.fixture.admin_event(
        EventKind::CapabilityGrant,
        scope.clone(),
        json!({"grant":refusal_grant}),
    );
    let refusal_id = arkret_wire::GrantId::from_event_id(&refusal_event.event_id);
    accepted_admin_domain_event(&factory.fixture, refusal_event.clone()).await;
    let (status, refusal) = factory
        .fixture
        .service_post(
            &package,
            "/_arkret/peer/events",
            arkret_wire::ServiceOperationId::PEER_EVENTS_COMMAND_SUBMIT_V1,
            &forward(sign(
                artifact.clone(),
                &full.commit.commit_id,
                &service_grant,
            )),
            "call-ready-global-service-denial",
        )
        .await;
    assert!(
        status.is_client_error(),
        "another Service grant's denial cannot be hidden by the selected positive source: {status} {refusal}"
    );
    let refusal_full = source
        .committed_event(&refusal_event.event_id)
        .await
        .unwrap()
        .unwrap();
    let revoke_refusal = factory.fixture.admin_event(
        EventKind::CapabilityRevoke,
        scope.clone(),
        json!({"grant_id":refusal_id,"expected_commit_id":refusal_full.commit.commit_id}),
    );
    accepted_admin_domain_event(&factory.fixture, revoke_refusal).await;
    let grant_current = source
        .committed_event(
            &arkret_wire::EventId::new(initiator.as_str().replacen("ak:grant:", "ak:event:", 1))
                .unwrap(),
        )
        .await
        .unwrap()
        .unwrap();
    let revoke = factory.fixture.admin_event(
        EventKind::CapabilityRevoke,
        scope.clone(),
        json!({"grant_id":initiator,"expected_commit_id":grant_current.commit.commit_id}),
    );
    accepted_admin_domain_event(&factory.fixture, revoke).await;
    let (status, refusal) = factory
        .fixture
        .service_post(
            &package,
            "/_arkret/peer/events",
            arkret_wire::ServiceOperationId::PEER_EVENTS_COMMAND_SUBMIT_V1,
            &forward(sign(
                artifact.clone(),
                &full.commit.commit_id,
                &service_grant,
            )),
            "call-ready-revoked-start-source",
        )
        .await;
    assert!(
        status.is_client_error(),
        "revoked original source: {status} {refusal}"
    );
    assert_eq!(
        capture_current(&pool, &call, "call_recording_artifact").await,
        json!({"status":"ready","details":{"artifact":artifact}})
    );
    assert_eq!(consumption_count(&pool, &initiator).await, 1);
}
