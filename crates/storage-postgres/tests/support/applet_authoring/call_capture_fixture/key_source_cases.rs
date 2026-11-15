//! Real public RFC MLS transitions and native negative capture publications.
use arkret_mls::{ArkretMlsGroup, ArkretMlsIdentity, ArkretMlsSigner};
use arkret_models_crypto::EncryptedAttachmentKeyRef;
use coland_storage::MlsGroupCurrentStore as _;

use super::*;

async fn public_blob(fixture: &Fixture, bytes: Vec<u8>) -> arkret_wire::BlobRef {
    let sha256 = arkret_canonical::sha256_hex(&bytes);
    let reference = arkret_wire::BlobRef::new(format!("ak:blob:sha256:{sha256}")).unwrap();
    let storage_key = fixture.state.test_object_key_for_sha256(&sha256);
    fixture
        .state
        .test_put_object(&storage_key, bytes.clone())
        .await
        .unwrap();
    fixture
        .state
        .test_persistence()
        .blobs()
        .put(
            reference.as_str(),
            &coland_storage::BlobRecord {
                sha256,
                size_bytes: bytes.len() as i64,
                storage_backend: "memory".into(),
                storage_key,
                media_type: "application/octet-stream".into(),
                filename: None,
                realm_id: Some(fixture.realm.to_string()),
                encryption: None,
                legal_hold: false,
                redacted: false,
                visibility: BlobVisibility::RealmBound,
                uploaded_by: fixture.pcr.history.account.principal_id.to_string(),
                created_at: chrono::Utc::now(),
            },
        )
        .await
        .unwrap();
    reference
}

pub(super) async fn genesis(
    fixture: &Fixture,
    scope: &ScopeRef,
) -> (Box<ArkretMlsGroup>, EncryptedAttachmentKeyRef) {
    let history = &fixture.pcr.history;
    let actor = ActorId::account(history.account.clone());
    let key = SigningKey::from_bytes(&history.founding_device_signing_seed);
    let authorization = history
        .events
        .iter()
        .find(|event| event.kind == EventKind::DeviceAuthorize)
        .unwrap()
        .event_id
        .clone();
    let identity = ArkretMlsIdentity::new_human_device(
        actor.clone(),
        history.founding_device_id.clone(),
        ArkretMlsSigner::from_ed25519_signing_key(key.clone()),
    )
    .unwrap();
    let binding =
        arkret_models_crypto::MlsGovernanceBindingPayload::new(scope.clone(), None, 0, 0, 0)
            .unwrap();
    let mut group = Box::new(
        identity
            .create_group_with_governance_binding(scope, &binding)
            .unwrap(),
    );
    let (info, tree) = group.public_group_state_bytes().unwrap();
    let info = public_blob(fixture, info).await;
    let tree = public_blob(fixture, tree).await;
    let mut event=fixture.admin_event(EventKind::MlsGenesis,scope.clone(),json!({
        "cipher_suite":"MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519","group_info_ref":info,"ratchet_tree_ref":tree,
        "creator_leaf_authority":{"leaf_signature_key_base64url":arkret_canonical::base64url_encode(key.verifying_key().as_bytes()),
            "endpoint":{"kind":"device","device_id":history.founding_device_id},"authorization_event_ref":authorization},
        "governance_binding":binding,"created_at":arkret_canonical::format_timestamp_canonical(chrono::Utc::now())
    }));
    event.payload.insert(
        "created_at".into(),
        json!(arkret_canonical::format_timestamp_canonical(
            event.created_at
        )),
    );
    let event = fixture.sign_admin(event);
    let submission =
        arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequestBody::Event(
            arkret_wire::EventAdmissionSubmission::new(event.clone()),
        );
    let (status, outcome) = realm_native_fixture::boxed_step(|| async {
        fixture
            .admin_post(
                "/_arkret/self/events",
                arkret_wire::ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT_V1,
                &json!(submission),
                None,
            )
            .await
    })
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "actual capture MLS Genesis: {outcome}"
    );
    assert_accepted_event(fixture, &event).await;
    group
        .install_local_creator_binding(actor, Some(authorization))
        .unwrap();
    let reference =
        serde_json::from_value(json!({"algorithm":"MLS","group_state_ref":event.event_id}))
            .unwrap();
    (group, reference)
}

pub(super) async fn advance(
    fixture: &Fixture,
    scope: &ScopeRef,
    group: &mut ArkretMlsGroup,
) -> EncryptedAttachmentKeyRef {
    let previous = coland_storage_postgres::PgMlsGroupCurrentStore {
        pool: fixture.pool.clone(),
    }
    .current(scope)
    .await
    .unwrap()
    .unwrap()
    .value;
    let binding = arkret_models_crypto::MlsGovernanceBindingPayload::new(
        scope.clone(),
        Some(previous.current_mls_commit_event_ref.clone()),
        previous.epoch,
        previous.epoch + 1,
        previous.current_key_access_revision,
    )
    .unwrap();
    let envelope = group
        .self_update_commit_with_governance_binding(&binding)
        .unwrap();
    let payload = super::super::realm_actor_mls_fixture::commit_payload(
        fixture,
        group,
        previous.current_mls_commit_event_ref.clone(),
        previous.current_key_access_revision,
        &envelope,
        binding,
    )
    .await
    .unwrap();
    let event = fixture.admin_event(EventKind::MlsCommit, scope.clone(), json!(payload));
    let submission =
        arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequestBody::MlsCommit(
            arkret_wire::MlsCommitSubmission {
                recovery_source: None,
                commit_event: event.clone(),
                welcomes: Vec::new(),
                idempotency_key: arkret_wire::UuidV7::new(uuid::Uuid::now_v7()).unwrap(),
            },
        );
    let (status, outcome) = realm_native_fixture::boxed_step(|| async {
        fixture
            .admin_post(
                "/_arkret/self/events",
                arkret_wire::ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT_V1,
                &json!(submission),
                None,
            )
            .await
    })
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "actual capture MLS update: {outcome}"
    );
    let accepted = fixture
        .state
        .test_persistence()
        .authority_commits()
        .committed_event(&event.event_id)
        .await
        .unwrap()
        .unwrap();
    let accepted = arkret_wire::CommittedEventFullView {
        event: accepted.event,
        commit: accepted.commit,
    };
    assert_eq!(
        group.install_accepted_commit(&accepted, &previous).unwrap(),
        previous.epoch + 1
    );
    let current = coland_storage_postgres::PgMlsGroupCurrentStore {
        pool: fixture.pool.clone(),
    }
    .current(scope)
    .await
    .unwrap()
    .unwrap()
    .value;
    assert_eq!(current.current_mls_commit_event_ref, event.event_id);
    serde_json::from_value(json!({"algorithm":"MLS","group_state_ref":event.event_id})).unwrap()
}

pub(super) async fn footprint(fixture: &Fixture) -> Value {
    let mut conn = fixture.pool.get().await.unwrap();
    diesel::sql_query("SELECT jsonb_build_object('events',(SELECT COALESCE(jsonb_agg(to_jsonb(e) ORDER BY pk),'[]') FROM canonical_events e WHERE state='committed'),'commits',(SELECT COALESCE(jsonb_agg(to_jsonb(c) ORDER BY commit_id),'[]') FROM realm_commits c),'capture',(SELECT COALESCE(jsonb_agg(to_jsonb(c) ORDER BY call_id,selector::text),'[]') FROM call_component_current_states c),'quota',(SELECT COALESCE(jsonb_agg(to_jsonb(c) ORDER BY to_jsonb(c)::text),'[]') FROM capability_quota_consumptions c)) AS value")
        .get_result::<Current>(&mut *conn).await.unwrap().value
}

pub(super) async fn reject_start(
    fixture: &Fixture,
    start: &Event,
    key: Option<Value>,
    expected_code: arkret_wire::ErrorCode,
    label: &str,
) {
    let mut candidate = start.clone();
    let metadata = candidate
        .payload
        .get_mut("capture_metadata")
        .unwrap()
        .as_object_mut()
        .unwrap();
    match key {
        Some(key) => {
            metadata.insert("key_ref".into(), key);
        }
        None => {
            metadata.remove("key_ref");
        }
    }
    candidate = fixture.sign_admin(candidate);
    let before = footprint(fixture).await;
    let body = json!(
        arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequestBody::Event(
            arkret_wire::EventAdmissionSubmission::new(candidate)
        )
    );
    let (status, outcome) = realm_native_fixture::boxed_step(|| async {
        fixture
            .admin_post(
                "/_arkret/self/events",
                arkret_wire::ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT_V1,
                &body,
                None,
            )
            .await
    })
    .await;
    assert!(
        status.is_client_error(),
        "{label} must reject at native Start: {status} {outcome}"
    );
    let problem: arkret_wire::Problem = serde_json::from_value(outcome).unwrap();
    assert_eq!(problem.status, status.as_u16());
    assert_eq!(
        problem.error_code(),
        Some(expected_code),
        "{label} must reach its registered source or schema refusal"
    );
    assert_eq!(
        footprint(fixture).await,
        before,
        "{label} changed accepted Events/Commits/capture/quota"
    );
}

pub(super) async fn before_start(fixture: &Fixture, start: &Event) {
    reject_start(
        fixture,
        start,
        None,
        arkret_wire::ErrorCode::SchemaViolation,
        "recording Start missing Q",
    )
    .await;
    reject_start(
        fixture,
        start,
        Some(Value::Null),
        arkret_wire::ErrorCode::SchemaViolation,
        "recording Start null Q",
    )
    .await;
    let unknown =
        arkret_wire::EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [0x19; 32]);
    reject_start(
        fixture,
        start,
        Some(json!({"algorithm":"MLS","group_state_ref":unknown})),
        arkret_wire::ErrorCode::FailedPrecondition,
        "unaccepted Q",
    )
    .await;
    let scope = realm_native_fixture::boxed_step(|| fixture.new_circle_scope()).await;
    let actor = ActorId::account(fixture.pcr.history.account.clone());
    let snapshot = fixture
        .state
        .test_persistence()
        .authority_commits()
        .realm_state_snapshot_material(&fixture.realm)
        .await
        .unwrap()
        .unwrap();
    let parent=snapshot.current_state_entries.iter().find_map(|row| {
        let arkret_wire::CurrentState::Value {selector,revision,value,..}=row;
        matches!(selector,arkret_wire::CurrentSelector::MemberState {actor_id} if actor_id==&actor)
            .then_some((revision,value))
    }).expect("the creator has an actual accepted parent membership");
    assert_eq!(parent.1["membership"], "join");
    let ScopeRef::Circle { circle_id, .. } = &scope else {
        panic!("the foreign native scope is a Circle")
    };
    let join=fixture.admin_event(EventKind::CircleMemberState,scope.clone(),json!({
        "circle_id":circle_id,"member_id":actor,"membership":"join","parent_membership_revision":parent.0
    }));
    realm_native_fixture::boxed_step(|| accepted_admin_domain_event(fixture, join)).await;
    let (_, foreign_key) = realm_native_fixture::boxed_step(|| genesis(fixture, &scope)).await;
    reject_start(
        fixture,
        start,
        Some(json!(foreign_key)),
        arkret_wire::ErrorCode::FailedPrecondition,
        "another actual scope's accepted Q",
    )
    .await;
}

pub(super) async fn reject_stale_start(
    fixture: &Fixture,
    start: &Event,
    next: &EncryptedAttachmentKeyRef,
) {
    let current = coland_storage_postgres::PgMlsGroupCurrentStore {
        pool: fixture.pool.clone(),
    }
    .current(&start.scope_ref)
    .await
    .unwrap()
    .unwrap()
    .value;
    assert_eq!(
        next.group_state_ref.event_id().unwrap(),
        current.current_mls_commit_event_ref
    );
    // The original segment consumed its one-shot permission. A new, genuinely
    // accepted permission isolates the stale-Q gate from quota exhaustion.
    let actor = ActorId::account(fixture.pcr.history.account.clone());
    let permission=fixture.admin_event(EventKind::CapabilityGrant,start.scope_ref.clone(),json!({"grant":{
        "schema":"ak.schema.capability.v1","realm_id":fixture.realm,"issuer_id":actor,"subject":actor,
        "actions":["ak.call.record"],"resources":[{"kind":"realm","realm_id":fixture.realm}],
        "constraints":[{"constraint_kind":"quota","constraint_subkind":"rate","effect":"allow","max_operation_count":1,"period":"PT1H","constraint_scope":"per_actor"}],
        "issuer_authority_refs":[{"kind":"realm_root","realm_id":fixture.realm,"authority_event_ref":fixture.authority_event_ref,"authority_generation":"0"}],
        "issued_at":arkret_canonical::format_timestamp_canonical(chrono::Utc::now())}}));
    let grant = arkret_wire::GrantId::from_event_id(&permission.event_id);
    realm_native_fixture::boxed_step(|| accepted_admin_domain_event(fixture, permission)).await;
    let mut candidate = start.clone();
    candidate.created_at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    candidate
        .payload
        .insert("recording_id".into(), json!("stale-q-segment"));
    candidate.authorization_ref =
        Some(arkret_wire::AuthorizationRef::new(grant.to_string()).unwrap());
    let key = candidate.payload["capture_metadata"]["key_ref"].clone();
    reject_start(
        fixture,
        &candidate,
        Some(key),
        arkret_wire::ErrorCode::FailedPrecondition,
        "accepted predecessor Q cannot start a new segment",
    )
    .await;
    assert_eq!(consumption_count(&fixture.pool, &grant).await, 0);
}

pub(super) async fn reject_ready(
    fixture: &Fixture,
    package: &AppletPackage,
    body: &Value,
    label: &str,
) {
    let before = footprint(fixture).await;
    let (status, outcome) = realm_native_fixture::boxed_step(|| async {
        fixture
            .service_post(
                package,
                "/_arkret/peer/events",
                arkret_wire::ServiceOperationId::PEER_EVENTS_COMMAND_SUBMIT_V1,
                body,
                label,
            )
            .await
    })
    .await;
    assert!(
        status.is_client_error(),
        "{label} must reject at actual peer HTTP: {status} {outcome}"
    );
    assert_eq!(
        footprint(fixture).await,
        before,
        "{label} changed accepted Events/Commits/capture/quota"
    );
}

pub(super) fn invalid_artifacts(
    artifact: &Value,
    original: &EncryptedAttachmentKeyRef,
    next: &EncryptedAttachmentKeyRef,
) -> Vec<(&'static str, Value)> {
    let mut cases = Vec::new();
    let mut changed = artifact.clone();
    changed["encryption"]["key_ref"] = json!(next);
    cases.push(("ready-cannot-replace-original-Q-with-current-Q", changed));
    let mut changed = artifact.clone();
    changed["encryption"]["key_ref"]["group_state_ref"] =
        json!(original.group_state_ref.event_id().unwrap().event_digest());
    cases.push((
        "ready-cannot-change-Q-spelling-to-equivalent-digest",
        changed,
    ));
    for (field, label) in [
        ("key_ref", "ready-missing-key-ref"),
        ("nonce_prefix", "ready-missing-nonce-prefix"),
        ("segment_bytes", "ready-missing-segment-size"),
    ] {
        let mut changed = artifact.clone();
        changed["encryption"].as_object_mut().unwrap().remove(field);
        cases.push((label, changed));
    }
    let mut changed = artifact.clone();
    changed["encryption"]["nonce_prefix"] = json!(arkret_canonical::base64url_encode([0x53; 18]));
    cases.push(("ready-short-nonce-prefix", changed));
    let mut changed = artifact.clone();
    changed["encryption"]["segment_bytes"] = json!(1023);
    cases.push(("ready-segment-size-below-minimum", changed));
    let mut changed = artifact.clone();
    changed["encryption"]["encryption_algorithm"] = json!("mls_exporter_aead_xchacha20poly1305");
    cases.push(("ready-retired-whole-file-algorithm", changed));
    for (size, label) in [
        (15_u64, "ready-shorter-than-one-tag"),
        (1041, "ready-size-in-stream-geometry-gap"),
        (1040 * 1_048_576 + 1, "ready-more-than-maximum-segments"),
        (
            9_007_199_254_740_991,
            "ready-maximum-signed-size-exceeds-stream-bound",
        ),
    ] {
        let mut changed = artifact.clone();
        changed["size_bytes"] = json!(size);
        cases.push((label, changed));
    }
    cases
}
