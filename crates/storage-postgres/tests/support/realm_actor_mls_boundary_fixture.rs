// Included by realm_actor_mls_fixture.rs. Every case needs a fresh real setup;
// held response cuts from separate cases must never be nested on one Realm.

#[derive(Clone, Copy, Debug)]
pub(super) enum BoundaryCase {
    WorkerPublicationBudget,
    HumanPcrHandoff,
    ClaimExpiry,
    QueryExpiry,
    EncryptedReadExpiry,
    ExactCurrentFloor,
}

pub(super) async fn prepare_boundary_current_source(
    fixture: &Fixture,
) -> (arkret_wire::StrandId, EventId) {
    let scope = ScopeRef::Realm {
        realm_id: fixture.realm.clone(),
    };
    let mut event = fixture.admin_event(EventKind::StrandCreate, scope, json!({"object":{
        "schema":"ak.schema.strand.v1","realm_id":fixture.realm,
        "schema_refs":["ak.schema.calendar_event.v1"],
        "tracks":{"discussion":{"is_primary":true,"profile":"discussion"}},
        "metadata":{"title":"Boundary current source before native membership","fields":{"calendar":{
            "start":"2026-10-19","end":"2026-10-20","timezone":"Etc/UTC","tzdb_version":"2025a","all_day":true,"status":"confirmed"}}},
        "state":"active","created_by":ActorId::account(fixture.pcr.history.account.clone()),
        "created_at":arkret_canonical::format_timestamp_canonical(chrono::Utc::now())
    }}));
    event.payload.get_mut("object").unwrap()["created_at"] = json!(event.created_at);
    event = fixture.sign_admin(event);
    let source = event.event_id.clone();
    let strand = arkret_wire::StrandId::from_event_id(&source);
    boxed_step(|| submit_human_event(fixture, event)).await;
    (strand, source)
}

// This invokes the actual registered Salvo route and real HTTP-signature
// authentication, retaining its production streaming response body. Reading
// the body later exercises the real handoff guard, not a fabricated response.
async fn boundary_native_response(
    fixture: &Fixture,
    state: &AppState,
    authority: &coland_storage::AppletManagedDeviceAuthority,
    path: &str,
    operation: ServiceOperationId,
    body: Option<Value>,
) -> salvo::Response {
    let metadata = AppletManagedDeviceMetadata {
        actor_id: authority.actor_id.clone(),
        device_id: authority.device_id.clone(),
        authorization_event_id: authority.authorization_ref.event_id.clone(),
        applet_id: authority.applet_id.clone(),
        effective_scope: ScopeRef::Realm {
            realm_id: fixture.realm.clone(),
        },
        nonce: arkret_canonical::base64url_encode(rand::random::<[u8; 32]>()),
    };
    let uri = format!(
        "{}{path}",
        state.config().public_base_url.trim_end_matches('/')
    );
    let url = url::Url::parse(&uri).unwrap();
    let mut headers = vec![
        ("arkret-operation".into(), operation.to_string()),
        (
            "destination-service-id".into(),
            state.service_core_id().to_string(),
        ),
        (
            "arkret-managed-device".into(),
            metadata.to_header_value().unwrap(),
        ),
    ];
    let bytes = body
        .as_ref()
        .map(|value| arkret_canonical::canonical_json_bytes(value).unwrap());
    let digest = bytes.as_ref().map(|value| content_digest_header(value));
    let mut covered = vec![];
    if let Some(value) = &body {
        headers.push(("content-type".into(), "application/json".into()));
        headers.push(("content-digest".into(), digest.clone().unwrap()));
        let id = value
            .get("claim_request_id")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .unwrap_or_else(|| uuid::Uuid::now_v7().to_string());
        headers.push(("idempotency-key".into(), id));
        covered.extend(["content-digest", "idempotency-key"]);
    }
    let parts = SignedRequestParts {
        method: if body.is_some() { "POST" } else { "GET" }.into(),
        target_uri: uri.clone(),
        authority: url[url::Position::BeforeHost..url::Position::AfterPort].into(),
        path: path.into(),
        headers,
        body_digest: digest,
    };
    let fingerprint = arkret_canonical::ed25519_pubkey_to_did_key_multibase(&authority.public_key);
    let method = format!("did:key:{fingerprint}#{fingerprint}");
    let signed = sign_http_message_for_scenario(
        &parts,
        HttpSignatureScenario::AppletManagedDeviceV1,
        &covered,
        "sig1",
        &method,
        chrono::Utc::now().timestamp(),
        &SigningKey::from_bytes(&[79; 32]),
    )
    .unwrap();
    let mut request = if body.is_some() {
        TestClient::post(uri)
    } else {
        TestClient::get(uri)
    };
    for (name, value) in parts.headers {
        request = request.add_header(
            salvo::http::header::HeaderName::from_bytes(name.as_bytes()).unwrap(),
            value,
            true,
        );
    }
    if let Some(bytes) = bytes {
        request = request.body(bytes);
    }
    request
        .add_header("signature-input", signed.signature_input_header, true)
        .add_header("signature", signed.signature_header, true)
        .send(&service(state.clone()))
        .await
}

async fn boundary_reopen(fixture: &Fixture) -> AppState {
    let state = boxed_step(|| {
        coland_test_support::app_state_with_persistence(
            fixture.state.config().clone(),
            Arc::new(coland_storage_postgres::PgPersistenceStore::new(
                fixture.pool.clone(),
            )),
        )
    })
    .await;
    boxed_step(|| state.hydrate()).await.unwrap();
    assert_eq!(state.service_core_id(), fixture.state.service_core_id());
    state
}

async fn boundary_publish_human(fixture: &Fixture) -> arkret_wire::KeyPackageRef {
    let history = &fixture.pcr.history;
    let identity = arkret_mls::ArkretMlsIdentity::new_human_device(
        ActorId::account(history.account.clone()),
        history.founding_device_id.clone(),
        arkret_mls::ArkretMlsSigner::from_ed25519_signing_key(SigningKey::from_bytes(
            &history.founding_device_signing_seed,
        )),
    )
    .unwrap();
    let upload = identity
        .signed_key_packages_upload_request(
            &[identity.key_package_record().unwrap()],
            history.device_verification_method.as_str(),
        )
        .unwrap();
    let reference =
        arkret_wire::KeyPackageRef::new(upload.keypackages[0].keypackage_ref.as_str()).unwrap();
    let (status, value) = boxed_step(|| {
        fixture.admin_post(
            "/_arkret/self/keys/keypackages/upload",
            ServiceOperationId::SelfKeysKeypackagesUploadCreateV1.as_str(),
            &json!(upload),
            None,
        )
    })
    .await;
    assert_eq!(status, StatusCode::OK, "real Human publication: {value}");
    assert_eq!(value["accepted"], 1);
    reference
}

// #60 + #61. The first package does not exist when worker B starts. All six
// commands use the same accepted complete RealmActor and genuine Device key.
async fn boundary_worker_publication_and_budget(
    fixture: &Fixture,
    authority: &coland_storage::AppletManagedDeviceAuthority,
) {
    use coland_storage::MlsKeyPackageStore as _;
    let reopened = boxed_step(|| boundary_reopen(fixture)).await;
    let store = coland_storage_postgres::PgMlsKeyPackageStore {
        pool: fixture.pool.clone(),
    };
    let mut originals = vec![];
    let mut commands = vec![];
    for index in 0..6 {
        let reference = boxed_step(|| boundary_publish_human(fixture)).await;
        let row = store.get_by_ref(reference.as_str()).await.unwrap().unwrap();
        assert!(row.claimed_by_mls_group_id.is_none());
        let command = claim_request_with_lifetime(
            authority,
            fixture,
            reference.as_str(),
            chrono::Duration::minutes(4),
        );
        let state = if index % 2 == 0 {
            &reopened
        } else {
            &fixture.state
        };
        let mut response = boxed_step(|| {
            boundary_native_response(
                fixture,
                state,
                authority,
                "/_arkret/self/keys/keypackages/claim",
                ServiceOperationId::SelfKeysKeypackagesCommandClaimV1,
                Some(json!(command)),
            )
        })
        .await;
        let status = response.status_code.unwrap();
        let bytes = response.take_bytes(None).await.unwrap().to_vec();
        let value: Value = serde_json::from_slice(&bytes).unwrap();
        if index < 5 {
            assert_eq!(
                status,
                StatusCode::OK,
                "real native worker attempt {index}: {value}"
            );
            let outcome: KeyPackagesClaimOutcome = serde_json::from_value(value).unwrap();
            assert_eq!(outcome.claims.len(), 1);
            assert_eq!(outcome.claims[0].keypackage_ref, reference.as_str());
            assert_eq!(
                outcome.claims[0].actor_id,
                ActorId::account(fixture.pcr.history.account.clone())
            );
            originals.push(bytes);
        } else {
            assert_eq!(
                status,
                StatusCode::BAD_REQUEST,
                "sixth shared native budget attempt: {value}"
            );
            assert_eq!(value["type"], "https://arkret.org/problems/claim_failed");
            assert!(
                store
                    .get_by_ref(reference.as_str())
                    .await
                    .unwrap()
                    .unwrap()
                    .claimed_by_mls_group_id
                    .is_none()
            );
            let row = store
                .get_peer_claim(
                    command.service_binding.source_id.as_str(),
                    command.claim_request_id.as_str(),
                )
                .await
                .unwrap()
                .unwrap();
            assert_eq!(row.state, "claim_failed");
            assert!(row.keypackage_id.is_none() && row.outcome.is_none());
        }
        commands.push(command);
    }
    let before = boxed_step(|| obligation_mls_footprint(fixture)).await;
    let mut replay = boxed_step(|| {
        boundary_native_response(
            fixture,
            &fixture.state,
            authority,
            "/_arkret/self/keys/keypackages/claim",
            ServiceOperationId::SelfKeysKeypackagesCommandClaimV1,
            Some(json!(commands[0])),
        )
    })
    .await;
    assert_eq!(replay.status_code, Some(StatusCode::OK));
    assert_eq!(
        replay.take_bytes(None).await.unwrap().as_ref(),
        originals[0].as_slice()
    );
    let mut denied = boxed_step(|| {
        boundary_native_response(
            fixture,
            &reopened,
            authority,
            "/_arkret/self/keys/keypackages/claim",
            ServiceOperationId::SelfKeysKeypackagesCommandClaimV1,
            Some(json!(commands[5])),
        )
    })
    .await;
    assert_eq!(denied.status_code, Some(StatusCode::BAD_REQUEST));
    let value: Value = denied.take_json().await.unwrap();
    assert_eq!(value["type"], "https://arkret.org/problems/claim_failed");
    assert_eq!(
        boxed_step(|| obligation_mls_footprint(fixture)).await,
        before,
        "accepted/denied original retries may not make another budget decision or replace material"
    );
}

async fn boundary_install_deadline(
    fixture: &Fixture,
    package: &AppletPackage,
    child: &GrantId,
) -> chrono::DateTime<chrono::Utc> {
    let record = fixture
        .state
        .test_persistence()
        .applets()
        .get(
            package.applet_id.as_str(),
            &coland_storage::applet_effective_scope_key(&ScopeRef::Realm {
                realm_id: fixture.realm.clone(),
            })
            .unwrap(),
        )
        .await
        .unwrap()
        .unwrap();
    let originals: Vec<Event> =
        serde_json::from_value(record["capability_grant_events"].clone()).unwrap();
    assert!(!originals.is_empty());
    let mut deadline = None;
    for event in originals {
        assert_ne!(
            &GrantId::from_event_id(&event.event_id),
            child,
            "separate durable business authority must not be an expiring installation original"
        );
        let payload: CapabilityGrantPayload = serde_json::from_value(json!(event.payload)).unwrap();
        let expiries: Vec<_> = payload
            .grant
            .constraints
            .iter()
            .filter(|c| {
                c.constraint_kind == GrantConstraintKind::Temporal
                    && c.effect == GrantConstraintEffect::Allow
            })
            .filter_map(|c| c.expires_at)
            .collect();
        assert_eq!(
            expiries.len(),
            1,
            "fresh real installation must give every original one independent finite window"
        );
        if let Some(expected) = deadline {
            assert_eq!(expected, expiries[0]);
        } else {
            deadline = Some(expiries[0]);
        }
    }
    let deadline = deadline.unwrap();
    assert!(
        deadline > chrono::Utc::now(),
        "finite installation expired during genuine setup; do not enlarge production TTL or fake time"
    );
    deadline
}

async fn boundary_wait_until(deadline: chrono::DateTime<chrono::Utc>) {
    assert!(
        chrono::Utc::now() < deadline,
        "must prepare the real response while authorization is live"
    );
    tokio::time::sleep(
        (deadline - chrono::Utc::now()).to_std().unwrap() + std::time::Duration::from_millis(80),
    )
    .await;
    assert!(chrono::Utc::now() >= deadline);
}

async fn boundary_business_source_still_live(
    fixture: &Fixture,
    authority: &coland_storage::AppletManagedDeviceAuthority,
    child: &GrantId,
) {
    let rows = fixture
        .state
        .test_persistence()
        .capability_grant_current_results()
        .snapshot_for_realm(&fixture.realm)
        .await
        .unwrap();
    let grants = rows
        .into_iter()
        .map(|row| (row.grant_id, row.value))
        .collect::<BTreeMap<_, _>>();
    let current=arkret_policy::grant_authority::current_subject_grants(&authority.actor_id,"ak.event.read",
        &arkret_wire::WireResourceSelector::realm(fixture.realm.clone()),&grants,chrono::Utc::now(),
        |reference|matches!(reference,IssuerAuthorityRef::RealmRoot{realm_id,authority_event_ref,authority_generation}
            if realm_id==&fixture.realm && Some(authority_event_ref)==fixture.authority_event_ref.as_ref() && *authority_generation==0)).unwrap();
    assert!(
        current.iter().any(|grant| &grant.id == child),
        "separate authentic business/read grant must remain current after every original installation grant expires"
    );
}

async fn boundary_exact_current(
    fixture: &Fixture,
    authority: &coland_storage::AppletManagedDeviceAuthority,
    source: &(arkret_wire::StrandId, EventId),
) -> arkret_models_collaboration::exact_current_results::ExactCurrentResultsReadRequestBody {
    use arkret_models_collaboration::exact_current_results::*;
    let path = format!("/_arkret/self/committed-events/{}", source.1);
    let mut historical = boxed_step(|| {
        boundary_native_response(
            fixture,
            &fixture.state,
            authority,
            &path,
            ServiceOperationId::SelfCommittedEventResourceGetV1,
            None,
        )
    })
    .await;
    if historical.status_code == Some(StatusCode::OK) {
        let value: arkret_wire::CommittedEventView = historical.take_json().await.unwrap();
        assert!(
            !matches!(value, arkret_wire::CommittedEventView::Full(_)),
            "pre-join original must remain below the real history floor"
        );
    } else {
        assert_eq!(historical.status_code, Some(StatusCode::NOT_FOUND));
    }
    let request = ExactCurrentResultsReadRequestBody {
        realm_id: fixture.realm.clone(),
        selector: ExactCurrentResultSelector::CalendarScheduleSource(
            CalendarScheduleSourceExactSelector {
                kind: CalendarScheduleSourceExactSelectorKind::CalendarScheduleSource,
                strand_id: source.0.clone(),
            },
        ),
    };
    request.validate().unwrap();
    let mut response = boxed_step(|| {
        boundary_native_response(
            fixture,
            &fixture.state,
            authority,
            "/_arkret/self/current-results/exact",
            ServiceOperationId::SelfCurrentResultsReadExactV1,
            Some(json!(request)),
        )
    })
    .await;
    assert_eq!(response.status_code, Some(StatusCode::OK));
    let outcome: ExactCurrentResultsReadOutcome = response.take_json().await.unwrap();
    let ExactCurrentResultsReadOutcome::Present {
        governance_generation,
        entry: ExactCurrentResultEntry::CalendarScheduleSource(row),
        ..
    } = &outcome
    else {
        panic!("actual below-floor source current missing")
    };
    outcome
        .validate_for_request(&request, *governance_generation)
        .unwrap();
    assert_eq!(
        row.value.effective_scope,
        ScopeRef::Realm {
            realm_id: fixture.realm.clone()
        }
    );
    assert_eq!(row.value.source.as_ref().unwrap().event_id, source.1);
    assert!(row.value.metadata_context.is_none());
    let reopened = boxed_step(|| boundary_reopen(fixture)).await;
    let mut cold = boxed_step(|| {
        boundary_native_response(
            fixture,
            &reopened,
            authority,
            "/_arkret/self/current-results/exact",
            ServiceOperationId::SelfCurrentResultsReadExactV1,
            Some(json!(request)),
        )
    })
    .await;
    assert_eq!(cold.status_code, Some(StatusCode::OK));
    let cold: ExactCurrentResultsReadOutcome = cold.take_json().await.unwrap();
    assert_eq!(json!(outcome), json!(cold));
    request
}

// #57 and #63 run separately, each with a genuinely accepted finite install.
// A claim's own four-minute lease and the Device lifetime remain live at expiry.
async fn boundary_claim_expiry(
    fixture: &Fixture,
    package: &AppletPackage,
    authority: &coland_storage::AppletManagedDeviceAuthority,
    child: &GrantId,
    query_owner: bool,
) {
    let deadline = boxed_step(|| boundary_install_deadline(fixture, package, child)).await;
    assert!(authority.expires_at > deadline + chrono::Duration::seconds(10));
    let (command, outcome) = if query_owner {
        boxed_step(|| boundary_claim_native_recipient(fixture, authority)).await
    } else {
        let reference = boxed_step(|| boundary_publish_human(fixture)).await;
        let command = claim_request_with_lifetime(
            authority,
            fixture,
            reference.as_str(),
            chrono::Duration::minutes(4),
        );
        let (status, value) = boxed_step(|| {
            device_post(
                fixture,
                authority,
                "/_arkret/self/keys/keypackages/claim",
                ServiceOperationId::SelfKeysKeypackagesCommandClaimV1,
                json!(command),
            )
        })
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "real native claim before separate consent expiry: {value}"
        );
        (command, serde_json::from_value(value).unwrap())
    };
    assert!(outcome.claim_receipt.expires_at > deadline + chrono::Duration::seconds(10));
    let (path, operation, body) = if query_owner {
        (
            "/_arkret/self/keys/keypackages/claims/query",
            ServiceOperationId::SelfKeysKeypackagesReadClaimV1,
            json!(KeyPackagesClaimQueryRequestBody {
                claim_id: arkret_wire::KeypackageClaimId::new(outcome.claims[0].claim_id.as_str())
                    .unwrap()
            }),
        )
    } else {
        (
            "/_arkret/self/keys/keypackages/claim",
            ServiceOperationId::SelfKeysKeypackagesCommandClaimV1,
            json!(command),
        )
    };
    let mut prepared = boxed_step(|| {
        boundary_native_response(
            fixture,
            &fixture.state,
            authority,
            path,
            operation,
            Some(body.clone()),
        )
    })
    .await;
    assert_eq!(
        prepared.status_code,
        Some(StatusCode::OK),
        "real native response must prepare before finite install authorization ends"
    );
    let before = boxed_step(|| obligation_mls_footprint(fixture)).await;
    boxed_step(|| boundary_wait_until(deadline)).await;
    assert!(
        chrono::Utc::now() < outcome.claim_receipt.expires_at
            && chrono::Utc::now() < authority.expires_at
    );
    assert!(
        prepared.take_bytes(None).await.is_err(),
        "actual prepared original must not disclose after independent installation E2EE authorization expiry"
    );
    drop(prepared);
    boxed_step(|| boundary_business_source_still_live(fixture, authority, child)).await;
    assert_eq!(
        boxed_step(|| obligation_mls_footprint(fixture)).await,
        before
    );
    let mut refused = boxed_step(|| {
        boundary_native_response(
            fixture,
            &fixture.state,
            authority,
            path,
            operation,
            Some(body),
        )
    })
    .await;
    assert_eq!(
        refused.status_code,
        Some(if query_owner {
            StatusCode::NOT_FOUND
        } else {
            StatusCode::BAD_REQUEST
        })
    );
    let problem: Value = refused.take_json().await.unwrap();
    assert_eq!(
        problem["type"],
        if query_owner {
            "https://arkret.org/problems/keypackage_unknown"
        } else {
            "https://arkret.org/problems/claim_failed"
        }
    );
    assert!(problem.get("claims").is_none());
    assert_eq!(
        boxed_step(|| obligation_mls_footprint(fixture)).await,
        before
    );
}

async fn boundary_claim_native_recipient(
    fixture: &Fixture,
    authority: &coland_storage::AppletManagedDeviceAuthority,
) -> (KeyPackagesClaimRequestBody, KeyPackagesClaimOutcome) {
    let identity = arkret_mls::ArkretMlsIdentity::new_realm_device(
        authority.actor_id.clone(),
        authority.device_id.clone(),
        arkret_mls::ArkretMlsSigner::from_ed25519_signing_key(SigningKey::from_bytes(&[79; 32])),
    )
    .unwrap();
    let method = format!("{}#{}", authority.native_did, authority.device_id);
    let mut upload = identity
        .signed_key_packages_upload_request(&[identity.key_package_record().unwrap()], &method)
        .unwrap()
        .unsigned();
    upload.mls_group_id = Some(
        ScopeRef::Realm {
            realm_id: fixture.realm.clone(),
        }
        .canonical_mls_group_id()
        .unwrap(),
    );
    let signature = arkret_signatures::keypackages::sign_keypackage_signing_input(
        &[79; 32],
        &method,
        &keypackages_upload_signing_input(&upload).unwrap(),
    )
    .unwrap();
    let upload = upload.into_signed(signature);
    let (status, value) = boxed_step(|| {
        device_post(
            fixture,
            authority,
            "/_arkret/self/keys/keypackages/upload",
            ServiceOperationId::SelfKeysKeypackagesUploadCreateV1,
            json!(upload),
        )
    })
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "genuine native recipient publication: {value}"
    );
    assert_eq!(value["accepted"], 1);
    let history = &fixture.pcr.history;
    let at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    let mut command = claim_request_with_lifetime(
        authority,
        fixture,
        &upload.keypackages[0].keypackage_ref,
        chrono::Duration::minutes(4),
    );
    command.requester_actor_id = None;
    command.requester_account_id = Some(history.account.clone());
    command.target_account_id = None;
    command.target_actor_id = Some(authority.actor_id.clone());
    command.target_device_ids = vec![authority.device_id.clone()];
    command.requester_authorization = PeerKeyPackageRequesterAuthorization::Device {
        verification_method: history.device_verification_method.clone(),
        requester_device_id: history.founding_device_id.clone(),
        device_authorize_event_id: history
            .events
            .iter()
            .find(|e| e.kind == EventKind::DeviceAuthorize)
            .unwrap()
            .event_id
            .clone(),
        signed_at: at,
        signature: arkret_signatures::keypackages::keypackage_signature_from_bytes(
            history.device_verification_method.as_str(),
            &[0; 64],
        )
        .unwrap(),
    };
    let input = keypackage_claim_authorization_signing_bytes(
        &command.unsigned_request(),
        &command.service_binding,
        &command.requester_authorization,
    )
    .unwrap();
    let PeerKeyPackageRequesterAuthorization::Device { signature, .. } =
        &mut command.requester_authorization
    else {
        unreachable!()
    };
    *signature = arkret_signatures::keypackages::sign_keypackage_signing_input(
        &history.founding_device_signing_seed,
        history.device_verification_method.as_str(),
        &input,
    )
    .unwrap();
    command.validate_shape().unwrap();
    let (status, value) = boxed_step(|| {
        fixture.admin_post(
            "/_arkret/self/keys/keypackages/claim",
            ServiceOperationId::SelfKeysKeypackagesCommandClaimV1.as_str(),
            &json!(command),
            Some(command.claim_request_id.as_str()),
        )
    })
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "genuine Human claim of native recipient: {value}"
    );
    let outcome: KeyPackagesClaimOutcome = serde_json::from_value(value).unwrap();
    assert_eq!(outcome.claims.len(), 1);
    assert_eq!(outcome.claims[0].actor_id, authority.actor_id);
    assert_eq!(
        outcome.claims[0].device_id.as_ref(),
        Some(&authority.device_id)
    );
    assert_eq!(
        outcome.claims[0].device_authorize_event_id.as_ref(),
        Some(&authority.authorization_ref.event_id)
    );
    (command, outcome)
}

async fn boundary_encrypted_message(
    fixture: &Fixture,
    package: &AppletPackage,
    candidate: &RealmActorCreatePayload,
    authority: &coland_storage::AppletManagedDeviceAuthority,
    child: &GrantId,
    group: &mut arkret_mls::ArkretMlsGroup,
) -> Event {
    let scope = candidate.creation_scope.clone();
    let mut strand = fixture.admin_event(
        EventKind::StrandCreate,
        scope.clone(),
        json!({"object":{
        "schema":"ak.schema.strand.v1","realm_id":fixture.realm,
        "tracks":{"discussion":{"is_primary":true,"profile":"discussion"}},
        "metadata":{"title":"Actual native encrypted boundary payload"},"state":"active",
        "created_by":ActorId::account(fixture.pcr.history.account.clone()),
        "created_at":arkret_canonical::format_timestamp_canonical(chrono::Utc::now())}}),
    );
    strand.payload.get_mut("object").unwrap()["created_at"] = json!(strand.created_at);
    strand = fixture.sign_admin(strand);
    let strand_id = arkret_wire::StrandId::from_event_id(&strand.event_id);
    boxed_step(|| submit_human_event(fixture, strand)).await;
    let mut payload = arkret::MessageCreatePayload::with_content(
        strand_id,
        "discussion",
        arkret::ContentBlock::new(
            arkret::ContentBlockKind::Text,
            "Real native encrypted bytes before independent E2EE consent expiry",
        ),
    );
    let content = arkret_canonical::canonical_json_bytes(&payload.content.take().unwrap()).unwrap();
    let current = coland_storage_postgres::PgMlsGroupCurrentStore {
        pool: fixture.pool.clone(),
    }
    .current(&scope)
    .await
    .unwrap()
    .unwrap()
    .value;
    let header = arkret::EventContentPreEncryptionHeader::reconstruct(
        "1.0",
        arkret::MESSAGE_CONTENT_BLOCK_MLS_CONTENT_TYPE,
        arkret::EncryptedPayloadScheme::MlsRfc9420,
        scope.clone(),
        EventKind::MessageCreate.as_str(),
        group.epoch(),
        current.current_mls_commit_event_ref,
        group.local_content_sender_domain().unwrap(),
        arkret::EventContentRoutingContext::None,
    )
    .unwrap();
    payload.encrypted_content = Some(
        arkret_mls::encrypted_envelope_from_payload(
            &group.encrypt_payload(header, &content).unwrap(),
        )
        .unwrap(),
    );
    let signer = Ed25519PayloadSigner::new(
        SigningKey::from_bytes(&[79; 32]),
        authority.native_did.clone(),
        DidUrl::new(format!("{}#{}", authority.native_did, authority.device_id)).unwrap(),
    );
    let event = signed_event(
        package,
        candidate.actor_id.clone(),
        scope,
        EventKind::MessageCreate,
        json!(payload),
        Some(child),
        &signer,
    );
    let (status, value) = boxed_step(|| {
        device_post(
            fixture,
            authority,
            "/_arkret/self/events",
            ServiceOperationId::SelfEventsCommandSubmitV1,
            json!(SelfAuthoritySubmitRequest::Event(
                arkret_wire::EventAdmissionSubmission::new(event.clone())
            )),
        )
    })
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "genuine native encrypted Message acceptance: {value}"
    );
    let accepted = fixture
        .state
        .test_persistence()
        .authority_commits()
        .committed_event(&event.event_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(accepted.event, event);
    assert!(event.payload.get("encrypted_content").is_some());
    assert!(event.payload.get("content").is_none());
    event
}

// #80: original encrypted Message, live separate read parent and live Device,
// but all original installation authorization grants expire before body read.
async fn boundary_encrypted_read_expiry(
    fixture: &Fixture,
    package: &AppletPackage,
    candidate: &RealmActorCreatePayload,
    authority: &coland_storage::AppletManagedDeviceAuthority,
    child: &GrantId,
    group: &mut arkret_mls::ArkretMlsGroup,
) {
    let deadline = boxed_step(|| boundary_install_deadline(fixture, package, child)).await;
    assert!(authority.expires_at > deadline + chrono::Duration::seconds(10));
    let event = boxed_step(|| {
        boundary_encrypted_message(fixture, package, candidate, authority, child, group)
    })
    .await;
    let path = format!("/_arkret/self/committed-events/{}", event.event_id);
    let mut positive = boxed_step(|| {
        boundary_native_response(
            fixture,
            &fixture.state,
            authority,
            &path,
            ServiceOperationId::SelfCommittedEventResourceGetV1,
            None,
        )
    })
    .await;
    assert_eq!(positive.status_code, Some(StatusCode::OK));
    let positive: arkret_wire::CommittedEventView = positive.take_json().await.unwrap();
    let arkret_wire::CommittedEventView::Full(original) = positive else {
        panic!("actual encrypted original must initially be Full")
    };
    assert_eq!(original.event, event);
    let mut prepared = boxed_step(|| {
        boundary_native_response(
            fixture,
            &fixture.state,
            authority,
            &path,
            ServiceOperationId::SelfCommittedEventResourceGetV1,
            None,
        )
    })
    .await;
    assert_eq!(prepared.status_code, Some(StatusCode::OK));
    let before = boxed_step(|| obligation_mls_footprint(fixture)).await;
    boxed_step(|| boundary_wait_until(deadline)).await;
    assert!(chrono::Utc::now() < authority.expires_at);
    assert!(
        prepared.take_bytes(None).await.is_err(),
        "actual prepared ciphertext must not be disclosed after original installation consent expires"
    );
    drop(prepared);
    boxed_step(|| boundary_business_source_still_live(fixture, authority, child)).await;
    let mut refused = boxed_step(|| {
        boundary_native_response(
            fixture,
            &fixture.state,
            authority,
            &path,
            ServiceOperationId::SelfCommittedEventResourceGetV1,
            None,
        )
    })
    .await;
    assert_eq!(refused.status_code, Some(StatusCode::NOT_FOUND));
    let problem: Value = refused.take_json().await.unwrap();
    assert!(problem.get("event").is_none());
    assert_eq!(
        boxed_step(|| obligation_mls_footprint(fixture)).await,
        before
    );
}

// #81 uses ordinary installation and a separate, actually authored finite
// EventRead parent. Other original installation grants remain current; this
// expiry is a business read-source boundary, not the independent E2EE gate.
async fn boundary_finite_read_parent(
    fixture: &Fixture,
    package: &AppletPackage,
    authority: &coland_storage::AppletManagedDeviceAuthority,
) -> chrono::DateTime<chrono::Utc> {
    let service = ActorId::service(package.service_id.clone());
    let rows = fixture
        .state
        .test_persistence()
        .capability_grant_current_results()
        .snapshot_for_realm(&fixture.realm)
        .await
        .unwrap();
    for row in rows {
        if matches!(&row.value.subject,CapabilitySubject::Actor(actor) if actor==&service)
            && row.value.actions.iter().any(|action|action=="ak.event.read")
            && row.value.status==arkret_models_collaboration::governance::grant_constraint::CapabilityGrantStatus::Active {
            boxed_step(||obligation_close_grant(fixture,&row.grant_id)).await;
        }
    }
    let deadline = arkret_canonical::normalize_timestamp_canonical(
        chrono::Utc::now() + chrono::Duration::seconds(15),
    );
    let mut temporal =
        GrantConstraint::new(GrantConstraintKind::Temporal, GrantConstraintEffect::Allow);
    temporal.expires_at = Some(deadline);
    let mut control = GrantConstraint::new(
        GrantConstraintKind::AuthorityControl,
        GrantConstraintEffect::Allow,
    );
    control.authority_regrant_allowed = Some(false);
    control.max_authority_depth = Some(0);
    control.allowed_managed_actor_roles = vec![ManagedActorRole::Bot, ManagedActorRole::Ghost];
    let parent = CapabilityGrantCreateBody {
        schema: arkret_wire::SchemaId::CAPABILITY_V1.into(),
        realm_id: Some(fixture.realm.clone()),
        issuer_id: ActorId::account(fixture.pcr.history.account.clone()),
        subject: CapabilitySubject::Actor(service.clone()),
        actions: vec!["ak.event.read".into()],
        resources: vec![arkret_wire::WireResourceSelector::realm(
            fixture.realm.clone(),
        )],
        constraints: vec![
            GrantConstraint::applet_authority(
                package.applet_id.clone(),
                service,
                package.registration_epoch.clone(),
            ),
            control,
            temporal,
        ],
        issuer_authority_refs: vec![IssuerAuthorityRef::RealmRoot {
            realm_id: fixture.realm.clone(),
            authority_event_ref: fixture.authority_event_ref.clone().unwrap(),
            authority_generation: 0,
        }],
        issued_at: arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now()),
    };
    let id = boxed_step(|| obligation_admin_grant(fixture, parent.clone())).await;
    boxed_step(|| {
        obligation_terminal_child(fixture, package, &authority.actor_id, &[(id, parent)])
    })
    .await;
    deadline
}

async fn boundary_exact_floor_expiry(
    fixture: &Fixture,
    package: &AppletPackage,
    authority: &coland_storage::AppletManagedDeviceAuthority,
    source: &(arkret_wire::StrandId, EventId),
) {
    let request = boxed_step(|| boundary_exact_current(fixture, authority, source)).await;
    let deadline = boxed_step(|| boundary_finite_read_parent(fixture, package, authority)).await;
    assert!(authority.expires_at > deadline + chrono::Duration::seconds(10));
    let mut positive = boxed_step(|| {
        boundary_native_response(
            fixture,
            &fixture.state,
            authority,
            "/_arkret/self/current-results/exact",
            ServiceOperationId::SelfCurrentResultsReadExactV1,
            Some(json!(request)),
        )
    })
    .await;
    assert_eq!(positive.status_code, Some(StatusCode::OK));
    let positive:arkret_models_collaboration::exact_current_results::ExactCurrentResultsReadOutcome=positive.take_json().await.unwrap();
    let mut prepared = boxed_step(|| {
        boundary_native_response(
            fixture,
            &fixture.state,
            authority,
            "/_arkret/self/current-results/exact",
            ServiceOperationId::SelfCurrentResultsReadExactV1,
            Some(json!(request)),
        )
    })
    .await;
    assert_eq!(prepared.status_code, Some(StatusCode::OK));
    let before = boxed_step(|| obligation_mls_footprint(fixture)).await;
    boxed_step(|| boundary_wait_until(deadline)).await;
    assert!(
        prepared.take_bytes(None).await.is_err(),
        "prepared below-floor minimal current row must still require live read authority"
    );
    drop(prepared);
    let mut refused = boxed_step(|| {
        boundary_native_response(
            fixture,
            &fixture.state,
            authority,
            "/_arkret/self/current-results/exact",
            ServiceOperationId::SelfCurrentResultsReadExactV1,
            Some(json!(request)),
        )
    })
    .await;
    assert_eq!(refused.status_code, Some(StatusCode::NOT_FOUND));
    let problem: Value = refused.take_json().await.unwrap();
    assert!(problem.get("entry").is_none());
    assert_eq!(
        boxed_step(|| obligation_mls_footprint(fixture)).await,
        before
    );
    assert!(matches!(positive,arkret_models_collaboration::exact_current_results::ExactCurrentResultsReadOutcome::Present{..}));
}

pub(super) async fn realm_actor_mls_boundary(
    fixture: &Fixture,
    package: &AppletPackage,
    candidate: &RealmActorCreatePayload,
    device: &DeviceId,
    authority: &coland_storage::AppletManagedDeviceAuthority,
    child: &GrantId,
    source: (arkret_wire::StrandId, EventId),
    case: BoundaryCase,
) {
    assert_eq!(&candidate.actor_id, &authority.actor_id);
    assert_eq!(device, &authority.device_id);
    let mut group =
        boxed_step(|| genesis(fixture, package, candidate, device, authority, child)).await;
    match case {
        BoundaryCase::WorkerPublicationBudget => {
            boxed_step(|| boundary_worker_publication_and_budget(fixture, authority)).await
        }
        BoundaryCase::HumanPcrHandoff => {
            boxed_step(|| boundary_human_pcr_handoff(fixture, authority)).await
        }
        BoundaryCase::ClaimExpiry => {
            boxed_step(|| boundary_claim_expiry(fixture, package, authority, child, false)).await
        }
        BoundaryCase::QueryExpiry => {
            boxed_step(|| boundary_claim_expiry(fixture, package, authority, child, true)).await
        }
        BoundaryCase::EncryptedReadExpiry => {
            boxed_step(|| {
                boundary_encrypted_read_expiry(
                    fixture, package, candidate, authority, child, &mut group,
                )
            })
            .await
        }
        BoundaryCase::ExactCurrentFloor => {
            boxed_step(|| boundary_exact_floor_expiry(fixture, package, authority, &source)).await
        }
    }
}

pub(super) async fn run_boundary(
    fixture: &Fixture,
    package: &AppletPackage,
    candidate: &RealmActorCreatePayload,
    device: &DeviceId,
    source: (arkret_wire::StrandId, EventId),
    case: BoundaryCase,
) {
    let authority = fixture
        .state
        .test_persistence()
        .device_revocations()
        .applet_managed_device_authority(&candidate.actor_id, device, chrono::Utc::now())
        .await
        .unwrap()
        .unwrap();
    let child = boxed_step(|| business_grant(fixture, package, &candidate.actor_id)).await;
    boxed_step(|| {
        realm_actor_mls_boundary(
            fixture, package, candidate, device, &authority, &child, source, case,
        )
    })
    .await;
}

// #59. The only PCR here belongs to the genuine Human counterpart. The native
// requester retains its complete RealmActor identity and has no personal PCR.
async fn boundary_human_pcr_handoff(
    fixture: &Fixture,
    authority: &coland_storage::AppletManagedDeviceAuthority,
) {
    use diesel_async::RunQueryDsl as _;
    #[derive(diesel::QueryableByName)]
    struct ReaderPid {
        #[diesel(sql_type=diesel::sql_types::Integer)]
        pid: i32,
    }
    #[derive(diesel::QueryableByName)]
    struct Waiting {
        #[diesel(sql_type=diesel::sql_types::Bool)]
        waiting: bool,
    }
    let mut human = boxed_step(|| {
        Fixture::new_at(
            fixture.pool.clone(),
            Some(fixture.state.config().public_base_url.clone()),
            Some([180; 32]),
        )
    })
    .await;
    assert_eq!(
        human.state.service_core_id(),
        fixture.state.service_core_id(),
        "counterpart must be a different accepted Human PCR at this Station"
    );
    assert_ne!(human.pcr.history.account, fixture.pcr.history.account);
    let revoker = boxed_step(|| {
        human
            .pcr
            .admit_accepted_device(human.state.test_persistence().as_ref(), [181; 32])
    })
    .await
    .unwrap();
    assert_eq!(
        human
            .state
            .test_persistence()
            .device_revocations()
            .pcr_device_admission(
                &human.pcr.history.account,
                &human.pcr.history.founding_device_id,
                chrono::Utc::now()
            )
            .await
            .unwrap(),
        arkret_wire::DeviceRevocationAdmissionDecision::Allow
    );
    // Both Accounts are hosted by this Station. The ordinary fixture Realm's
    // accepted join rule is public, so use the real Human's self-signed join;
    // recording a "remote" authority at its own Station would be invalid.
    let join=human.admin_event(EventKind::MemberState,ScopeRef::Realm{realm_id:fixture.realm.clone()},
        json!({"member_id":ActorId::account(human.pcr.history.account.clone()),"membership":"join"}));
    let (status, value) = boxed_step(|| {
        human.admin_post(
            "/_arkret/self/events",
            ServiceOperationId::SelfEventsCommandSubmitV1.as_str(),
            &json!(SelfAuthoritySubmitRequest::Event(
                arkret_wire::EventAdmissionSubmission::new(join)
            )),
            None,
        )
    })
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "actual local Human joins the native requester's public Realm: {value}"
    );
    // Upload uses this Human's own true session/Device, not the native key.
    let reference = boxed_step(|| boundary_publish_human(&human)).await;
    let command = claim_request_with_lifetime(
        authority,
        &human,
        reference.as_str(),
        chrono::Duration::minutes(4),
    );
    let mut response = boxed_step(|| {
        boundary_native_response(
            fixture,
            &fixture.state,
            authority,
            "/_arkret/self/keys/keypackages/claim",
            ServiceOperationId::SelfKeysKeypackagesCommandClaimV1,
            Some(json!(command)),
        )
    })
    .await;
    assert_eq!(response.status_code, Some(StatusCode::OK));
    let mut monitor = fixture.pool.get().await.unwrap();
    let readers=diesel::sql_query("SELECT pid FROM pg_stat_activity WHERE datname=current_database() AND usename=current_user AND pid<>pg_backend_pid() AND state='idle in transaction'")
        .load::<ReaderPid>(&mut monitor).await.unwrap();
    let readers: Vec<i32> = readers.into_iter().map(|row| row.pid).collect();
    assert!(
        !readers.is_empty(),
        "real prepared response must retain its DB cut"
    );
    let revoke = boxed_step(|| boundary_terminal_human_revoke(&human, &revoker));
    tokio::pin!(revoke);
    let until = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
    let mut revoke_finished = false;
    let blocked = loop {
        let early = tokio::select! {
            _=&mut revoke=>true,
            _=tokio::time::sleep(std::time::Duration::from_millis(20))=>false,
        };
        if early {
            revoke_finished = true;
            break Err("actual Human revocation completed before body handoff");
        }
        let row=diesel::sql_query("SELECT EXISTS(SELECT 1 FROM pg_stat_activity a WHERE a.datname=current_database() AND a.pid<>pg_backend_pid() AND a.wait_event_type='Lock' AND a.query ILIKE '%realm_authorities%' AND a.query ILIKE '%FOR UPDATE%' AND pg_blocking_pids(a.pid) && $1::integer[]) AS waiting")
            .bind::<diesel::sql_types::Array<diesel::sql_types::Integer>,_>(&readers)
            .get_result::<Waiting>(&mut monitor).await.unwrap();
        if row.waiting {
            break Ok(());
        }
        if tokio::time::Instant::now() >= until {
            break Err("actual counterpart PCR writer never reached the held response cut");
        }
    };
    drop(monitor);
    let received = response.take_json::<KeyPackagesClaimOutcome>().await;
    drop(response);
    // Always release the held response before finishing this real writer.
    if !revoke_finished {
        tokio::time::timeout(std::time::Duration::from_secs(15), &mut revoke)
            .await
            .expect("Human security rotation remains blocked after body release");
    }
    blocked.unwrap();
    let received = received.unwrap();
    assert_eq!(
        human
            .state
            .test_persistence()
            .device_revocations()
            .pcr_device_admission(
                &human.pcr.history.account,
                &human.pcr.history.founding_device_id,
                chrono::Utc::now()
            )
            .await
            .unwrap(),
        arkret_wire::DeviceRevocationAdmissionDecision::Revoked,
        "independent authoritative PCR reader must observe the real accepted command terminal, not merely a proposal or failed native replay"
    );
    assert_eq!(received.claims.len(), 1);
    assert_eq!(
        received.claims[0].actor_id,
        ActorId::account(human.pcr.history.account.clone())
    );
    assert_eq!(
        received.claims[0].device_id.as_ref(),
        Some(&human.pcr.history.founding_device_id)
    );
    let before = boxed_step(|| obligation_mls_footprint(fixture)).await;
    let mut refused = boxed_step(|| {
        boundary_native_response(
            fixture,
            &fixture.state,
            authority,
            "/_arkret/self/keys/keypackages/claim",
            ServiceOperationId::SelfKeysKeypackagesCommandClaimV1,
            Some(json!(command)),
        )
    })
    .await;
    assert_eq!(refused.status_code, Some(StatusCode::BAD_REQUEST));
    let problem: Value = refused.take_json().await.unwrap();
    assert_eq!(problem["type"], "https://arkret.org/problems/claim_failed");
    assert!(problem.get("claims").is_none());
    assert_eq!(
        boxed_step(|| obligation_mls_footprint(fixture)).await,
        before
    );
}

// Port of the former real Human SecurityRotation fixture. Accepted proposal
// plus command terminal are committed through the current typed store; later
// backup-erasure phases are deliberately not claimed as complete.
async fn boundary_terminal_human_revoke(
    fixture: &Fixture,
    other: &coland_test_support::pcr_genesis::AcceptedDevice,
) {
    use arkret_models_collaboration::events_payloads::{
        ControllerBackupTrustAnchor, DeviceAuthorizePayload, UnsignedKeyBackupActiveSeries,
    };
    use arkret_models_crypto::*;
    use coland_storage::*;
    use ed25519_dalek::Signer as _;
    let at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    let account = fixture.pcr.history.account.clone();
    let device = fixture.pcr.history.founding_device_id.clone();
    let authorizer = arkret_wire::DeviceId::new(other.authorization.device_id.clone()).unwrap();
    let sign_as_other = |mut event: Event| {
        event.producer_proof = None;
        coland_test_support::signed_event::sign_fixture_event(
            event,
            fixture.pcr.history.did.as_str(),
            authorizer.as_str(),
            other.signing_seed,
        )
    };
    let source: DeviceAuthorizePayload = serde_json::from_value(
        serde_json::to_value(&fixture.pcr.history.events.last().unwrap().payload).unwrap(),
    )
    .unwrap();
    let old_series =
        arkret_wire::BackupSeriesId::new(format!("ak:backup_series:{}", uuid::Uuid::now_v7()))
            .unwrap();
    let new_series =
        arkret_wire::BackupSeriesId::new(format!("ak:backup_series:{}", uuid::Uuid::now_v7()))
            .unwrap();
    let backup = |series: &arkret_wire::BackupSeriesId| {
        let mut backup: KeyBackup = serde_json::from_value(json!({
            "backup_id":format!("ak:backup:{}",uuid::Uuid::now_v7()),"actor_id":ActorId::account(account.clone()),
            "backup_kind":"secret_storage","backup_version":"kb_1","created_at":at,"series_id":series,"series_seq":0,
            "encryption":{"recipient_method":"secret_storage_key","recipient_key_ref":"source-history-fixture-key","aead":{"name":"xchacha20_poly1305","nonce":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}},
            "domain_separation":{"subdomain":"secret_storage"},"contents":[{"item_kind":"recovery_key_share","secret_id":"device-source-history"}],
            "ciphertext":"AAAA","ciphertext_digest":arkret_canonical::sha256_digest([0,0,0]),
            "auth_data":{"device_id":other.authorization.device_id,"verification_method":other.verification_method,"signature_algorithm":"Ed25519","signature":"AA","device_authorize_event_id":other.authorization.authorization_ref.event_id}
        })).unwrap();
        let signature = SigningKey::from_bytes(&other.signing_seed)
            .sign(&backup.signing_payload_bytes().unwrap());
        backup.auth_data.signature = arkret_wire::Base64UrlString::new(
            arkret_canonical::base64url_encode(signature.to_bytes()),
        )
        .unwrap();
        backup.validate().unwrap();
        backup
    };
    let old = backup(&old_series);
    let new = backup(&new_series);
    let persistence = fixture.state.test_persistence();
    persistence
        .key_backups()
        .put(
            old.backup_id.to_string(),
            serde_json::to_value(&old).unwrap(),
        )
        .await
        .unwrap();
    let pointer = |series: &arkret_wire::BackupSeriesId, epoch, replaces, head| {
        let unsigned = UnsignedKeyBackupActiveSeries::new(
            ActorId::account(account.clone()),
            BackupKind::SecretStorage,
            series.clone(),
            epoch,
            replaces,
            head,
            at,
            other.verification_method.clone(),
            ControllerBackupTrustAnchor {
                authorize_event_id: other.authorization.authorization_ref.event_id.clone(),
                generation_ref: source.authorized_generation_ref,
            },
        )
        .unwrap();
        let signature = SigningKey::from_bytes(&other.signing_seed)
            .sign(&unsigned.signing_payload_bytes().unwrap());
        let payload = unsigned
            .attach_signature(
                arkret_wire::Base64UrlString::new(arkret_canonical::base64url_encode(
                    signature.to_bytes(),
                ))
                .unwrap(),
            )
            .unwrap();
        sign_as_other(fixture.admin_event(
            EventKind::KeyBackupActiveSeries,
            ScopeRef::Realm {
                realm_id: fixture.pcr.unit.transactions[0].event.realm_id.clone(),
            },
            serde_json::to_value(payload).unwrap(),
        ))
    };
    let store = PgAuthorityCommitStore {
        pool: fixture.pool.clone(),
    };
    let stream = fixture.pcr.unit.transactions[1].commit.stream_ref.clone();
    let head = store.stream_head(&stream).await.unwrap().unwrap();
    let initial_pointer = pointer(&old_series, 1, vec![], head.commit_id);
    let transaction = coland_services::authority_commit::AuthorityCommitApplication::new(
        coland_services::persistence::PersistenceHandle::from_shared(
            fixture.state.test_persistence(),
        ),
        0,
    )
    .prepare_self_event_transaction(
        &initial_pointer,
        &fixture.state.service_core_id(),
        fixture
            .state
            .service_verification_method("notary-key")
            .unwrap(),
        fixture.state.notary_signing_key().as_ref(),
        arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now()),
    )
    .await
    .unwrap();
    persistence
        .key_backups()
        .commit_active_series_pointer(KeyBackupActiveSeriesCommitWrite {
            queued_at: transaction.commit.committed_at,
            commit: transaction,
        })
        .await
        .unwrap();
    let revoke = sign_as_other(fixture.admin_event(EventKind::DeviceRevoke,ScopeRef::Realm {realm_id:stream.realm_id().clone()},json!({"device_id":device,"revoked_by":authorizer,"revoked_at":at,"reason":"security_rotation"})));
    let transaction = coland_services::authority_commit::AuthorityCommitApplication::new(
        coland_services::persistence::PersistenceHandle::from_shared(
            fixture.state.test_persistence(),
        ),
        0,
    )
    .prepare_self_event_transaction(
        &revoke,
        &fixture.state.service_core_id(),
        fixture
            .state
            .service_verification_method("notary-key")
            .unwrap(),
        fixture.state.notary_signing_key().as_ref(),
        arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now()),
    )
    .await
    .unwrap();
    let covering = transaction.commit.clone();
    let active = pointer(
        &new_series,
        2,
        vec![old_series.clone()],
        covering.commit_id.clone(),
    );
    let plan = SecurityRotationTransactionCreateRequest::from_prepared_rotations(
        arkret_wire::TransactionId::new(format!("ak:transaction:{}", uuid::Uuid::now_v7()))
            .unwrap(),
        account.clone(),
        authorizer,
        at + chrono::Duration::hours(1),
        PreparedEventUnit::new(
            arkret_canonical::DigestSuite::Sha256,
            arkret_wire::EventsSubmitBatchRequestBody {
                events: (vec![revoke.clone()])
                    .into_iter()
                    .map(arkret_wire::EventAdmissionSubmission::new)
                    .collect(),
            },
        )
        .unwrap(),
        Hash::new(arkret_canonical::sha256_digest(
            b"new-fixture-storage-secret",
        ))
        .unwrap(),
        vec![BackupRotationPlan {
            binding: BackupRotationBinding {
                backup_kind: BackupRotationKind::SecretStorage,
                previous_series_id: old_series,
                new_series_id: new_series,
                new_backups: vec![BackupObjectRef {
                    backup_id: new.backup_id.clone(),
                    ciphertext_digest: new.ciphertext_digest.clone(),
                }],
                active_series_event_id: active.event_id.clone(),
                old_backups: vec![BackupObjectRef {
                    backup_id: old.backup_id,
                    ciphertext_digest: old.ciphertext_digest,
                }],
            },
            new_backup_envelopes: vec![new],
            active_series_unit: PreparedEventUnit::new(
                arkret_canonical::DigestSuite::Sha256,
                arkret_wire::EventsSubmitBatchRequestBody {
                    events: (vec![active])
                        .into_iter()
                        .map(arkret_wire::EventAdmissionSubmission::new)
                        .collect(),
                },
            )
            .unwrap(),
        }],
    )
    .unwrap();
    let prepared = SecurityTransactionPreparedPlan::SecurityRotation(plan.prepared_plan.clone());
    let (mut initial, canonical_request) = SecurityTransactionCreateRequest::SecurityRotation(plan)
        .into_initial_resource(prepared, at)
        .unwrap();
    let id = initial.transaction_id.clone();
    persistence
        .security_transactions()
        .create(SecurityTransactionRecord {
            resource: initial.clone(),
            canonical_request: canonical_request.clone(),
        })
        .await
        .unwrap();
    initial.revoke_proposal = Some(SecurityRotationRevokeProposal {
        proposal_event_id: revoke.event_id.clone(),
        covering_commit_id: covering.commit_id.clone(),
    });
    persistence
        .security_transactions()
        .commit_revoke_proposal(RevokeProposalCommitWrite {
            transaction: SecurityTransactionRecord {
                resource: initial,
                canonical_request,
            },
            queued_at: covering.committed_at,
            commit: transaction,
        })
        .await
        .unwrap();
    let mut terminal = persistence
        .security_transactions()
        .get(id.as_str())
        .await
        .unwrap()
        .unwrap();
    let decided_at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    terminal
        .resource
        .accepted_steps
        .push(AcceptedSecurityTransactionStep {
            acceptor: SecurityTransactionAcceptor::Principal {
                principal_id: fixture.state.service_core_id(),
            },
            accepted_at: decided_at,
        });
    terminal.resource.revoke_command_outcome = Some(SecurityRotationRevokeCommandOutcome {
        proposal_event_id: revoke.event_id,
        covering_commit_id: covering.commit_id,
        result: SecurityRotationRevokeCommandDecision::Accepted,
        decided_at,
    });
    persistence
        .security_transactions()
        .commit_revoke_command_terminal(RevokeCommandTerminalWrite {
            step_outcome: Some(SecurityTransactionStepOutcomeRecord {
                transaction_id: id.to_string(),
                step: SecurityTransactionStep::Revoke,
                canonical_request: terminal.canonical_request.clone(),
                response: serde_json::to_value(&terminal.resource).unwrap(),
                participant_outcome: None,
            }),
            transaction: terminal,
        })
        .await
        .unwrap();
}
