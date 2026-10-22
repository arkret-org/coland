// Included in realm_native_fixture. Runtime revocation fences new business;
// it is neither a Realm Device revocation nor deletion of accepted originals.
async fn active_revoke_footprint(fixture: &Fixture) -> Value {
    use diesel_async::RunQueryDsl as _;
    #[derive(diesel::QueryableByName)]
    struct Row {
        #[diesel(sql_type = diesel::sql_types::Jsonb)]
        value: Value,
    }
    let mut result = boxed_step(|| native_business_footprint(fixture)).await;
    let mut connection = fixture.pool.get().await.unwrap();
    for table in [
        "applet_installations",
        "applet_registration_current_results",
        "capability_grant_current_results",
        "applet_widget_tokens",
    ] {
        let row = diesel::sql_query(format!(
            "SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text),'[]'::jsonb) AS value FROM {table} r"
        ))
        .get_result::<Row>(&mut connection)
        .await
        .unwrap();
        result
            .as_object_mut()
            .unwrap()
            .insert(table.into(), row.value);
    }
    result
}

async fn active_revoke_device_submit(
    fixture: &Fixture,
    authority: &coland_storage::AppletManagedDeviceAuthority,
    event: &Event,
) -> (StatusCode, Value) {
    let metadata = AppletManagedDeviceMetadata {
        actor_id: authority.actor_id.clone(),
        device_id: authority.device_id.clone(),
        authorization_event_id: authority.authorization_ref.event_id.clone(),
        applet_id: authority.applet_id.clone(),
        effective_scope: event.scope_ref.clone(),
        nonce: arkret_canonical::base64url_encode(rand::random::<[u8; 32]>()),
    };
    let fingerprint = arkret_canonical::ed25519_pubkey_to_did_key_multibase(&authority.public_key);
    let request = arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequest::Event(
        arkret_wire::EventAdmissionSubmission::new(event.clone()),
    );
    request.validate().unwrap();
    managed_device_post(
        fixture,
        &metadata,
        &DidUrl::new(format!("did:key:{fingerprint}#{fingerprint}")).unwrap(),
        "/_arkret/self/events",
        arkret_wire::ServiceOperationId::SelfEventsCommandSubmitV1,
        &json!(request),
        &[79; 32],
    )
    .await
}

pub(super) async fn run_active_revoke(
    fixture: &Fixture,
    package: &AppletPackage,
    candidate: &RealmActorCreatePayload,
    creation_commit: &arkret_wire::RealmCommit,
) {
    use arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequest;
    assert!(matches!(candidate.creation_scope, ScopeRef::Realm { .. }));
    let store = PgAppletStore {
        pool: fixture.pool.clone(),
    };
    let installation = store
        .get(
            package.applet_id.as_str(),
            &coland_storage::applet_effective_scope_key(&candidate.creation_scope).unwrap(),
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(installation["status"], "installed");
    let creation = fixture
        .state
        .test_persistence()
        .authority_commits()
        .committed_event(&creation_commit.event_ref)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(creation.commit, *creation_commit);
    assert_eq!(json!(creation.event.payload), json!(candidate));
    let device = boxed_step(|| {
        authorize_device_with_actions(
            fixture,
            candidate,
            creation_commit,
            79,
            &["ak.applet.join", "ak.event.read", "ak.message.create"],
        )
    })
    .await;
    let authority = fixture
        .state
        .test_persistence()
        .device_revocations()
        .applet_managed_device_authority(&candidate.actor_id, &device, chrono::Utc::now())
        .await
        .unwrap()
        .unwrap();
    let authorization_original = fixture
        .state
        .test_persistence()
        .authority_commits()
        .committed_event(&authority.authorization_ref.event_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        authorization_original.commit.commit_id,
        authority.authorization_ref.commit_id
    );
    boxed_step(|| self_join(fixture, candidate, &device, &installation)).await;
    let child = boxed_step(|| {
        realm_actor_mls_fixture::business_grant(fixture, package, &candidate.actor_id)
    })
    .await;
    let admin = ActorId::account(fixture.pcr.history.account.clone());
    let mut strand = fixture.admin_event(EventKind::StrandCreate, candidate.creation_scope.clone(), json!({"object":{
        "schema":"ak.schema.strand.v1", "realm_id":fixture.realm,
        "tracks":{"discussion":{"is_primary":true,"profile":"discussion"}},
        "metadata":{"title":"Active native Applet runtime revocation"}, "state":"active",
        "created_by":admin, "created_at":arkret_canonical::format_timestamp_canonical(chrono::Utc::now())
    }}));
    strand.payload.get_mut("object").unwrap()["created_at"] = json!(
        arkret_canonical::format_timestamp_canonical(strand.created_at)
    );
    strand = fixture.sign_admin(strand);
    let strand_id = arkret_wire::StrandId::from_event_id(&strand.event_id);
    let (status, response) = fixture
        .admin_post(
            "/_arkret/self/events",
            arkret_wire::ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT_V1,
            &json!(SelfAuthoritySubmitRequest::Event(
                arkret_wire::EventAdmissionSubmission::new(strand)
            )),
            None,
        )
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "actual Applet business strand: {response}"
    );
    let signer = Ed25519PayloadSigner::new(
        SigningKey::from_bytes(&[79; 32]),
        authority.native_did.clone(),
        DidUrl::new(format!("{}#{device}", authority.native_did)).unwrap(),
    );
    let make_message = |body: &str| {
        realm_actor_mls_fixture::signed_event(
            package,
            candidate.actor_id.clone(),
            candidate.creation_scope.clone(),
            EventKind::MessageCreate,
            json!(arkret::MessageCreatePayload::with_content(
                strand_id.clone(),
                "discussion",
                arkret::ContentBlock::text(body)
            )),
            Some(&child),
            &signer,
        )
    };
    let accepted_event = make_message("True native Device business before runtime revocation");
    let (status, response) =
        boxed_step(|| active_revoke_device_submit(fixture, &authority, &accepted_event)).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "active RealmActor Device Message: {response}"
    );
    let accepted = fixture
        .state
        .test_persistence()
        .authority_commits()
        .committed_event(&accepted_event.event_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(accepted.event, accepted_event);
    let before_retry = boxed_step(|| active_revoke_footprint(fixture)).await;
    let (status, response) =
        boxed_step(|| active_revoke_device_submit(fixture, &authority, &accepted_event)).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "active native Message original retry: {response}"
    );
    assert_eq!(
        boxed_step(|| active_revoke_footprint(fixture)).await,
        before_retry
    );
    assert_eq!(
        fixture
            .state
            .test_persistence()
            .authority_commits()
            .committed_event(&accepted_event.event_id)
            .await
            .unwrap()
            .unwrap(),
        accepted
    );
    // Freeze the valid Device signature and current original child while the
    // runtime is still active. The later refusal must use the current fence.
    let fresh = make_message("A previously signed fresh original must honor the new runtime fence");
    assert_ne!(fresh.event_id, accepted_event.event_id);
    let historical_before = boxed_step(|| native_business_footprint(fixture)).await;

    let mode = arkret_wire::AppletRevokeMode::RevokeRuntimeOnly;
    let reason = arkret_wire::ReasonCode::from_wire("applet_revoked");
    let preview_request = AppletRevokePreviewRequestBody {
        service_id: package.service_id.clone(),
        effective_scope: candidate.creation_scope.clone(),
        reason_code: reason.clone(),
        revoke_mode: mode,
    };
    let (status, preview) = fixture
        .admin_post(
            &format!("/_arkret/self/applets/{}/revoke/preview", package.applet_id),
            arkret_wire::ServiceOperationId::SELF_APPLET_REVOKE_COMMAND_PREVIEW_V1,
            &json!(preview_request),
            None,
        )
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "active runtime revoke preview: {preview}"
    );
    let preview: AppletRevokePreviewOutcome = serde_json::from_value(preview).unwrap();
    assert_eq!(
        preview.revoke_plan.effective_scope,
        candidate.creation_scope
    );
    assert_eq!(preview.revoke_plan.revoke_mode, mode);
    assert!(
        preview
            .revoke_plan
            .membership_removals
            .iter()
            .any(|item| item.member_id == candidate.actor_id),
        "the preview must observe the actual joined RealmActor"
    );
    let capability_revoke_events = preview
        .revoke_plan
        .capability_revocations
        .iter()
        .map(|intent| {
            arkret_wire::EventAdmissionSubmission::new(fixture.admin_event(
                EventKind::CapabilityRevoke,
                candidate.creation_scope.clone(),
                json!(
                    arkret_models_collaboration::events_payloads::CapabilityRevokePayload {
                        grant_id: intent.grant_id.clone(),
                        expected_revision: intent.expected_revision.clone(),
                        reason: Some(intent.reason_code.as_str().to_owned()),
                    }
                ),
            ))
        })
        .collect();
    let membership_state_events = preview.revoke_plan.membership_removals.iter().map(|intent| {
        arkret_wire::EventAdmissionSubmission::new(fixture.admin_event(
            EventKind::MemberState, candidate.creation_scope.clone(),
            json!({"member_id":intent.member_id,"membership":intent.membership,"reason":intent.reason_code}),
        ))
    }).collect();
    let request = AppletRevokeRequestBody {
        service_id: package.service_id.clone(),
        revoke_plan_digest: Hash::new(
            arkret_canonical::canonical_sha256(&preview.revoke_plan).unwrap(),
        )
        .unwrap(),
        effective_scope: candidate.creation_scope.clone(),
        reason_code: reason,
        revoke_mode: mode,
        capability_revoke_events,
        membership_state_events,
    };
    let path = format!("/_arkret/self/applets/{}/revoke", package.applet_id);
    let key = format!("active-native-revoke-{}", uuid::Uuid::now_v7());
    let (status, response) = fixture
        .admin_post(
            &path,
            arkret_wire::ServiceOperationId::SELF_APPLET_COMMAND_REVOKE_V1,
            &json!(request),
            Some(&key),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "actual active runtime revoke: {response}"
    );
    let outcome: AppletRevokeOutcome = serde_json::from_value(response).unwrap();
    assert_eq!(
        outcome.status,
        AppletRevokeSagaStatus::Complete,
        "{outcome:?}"
    );
    assert!(outcome.rejections.is_empty());
    let fenced = store
        .get(
            package.applet_id.as_str(),
            &coland_storage::applet_effective_scope_key(&candidate.creation_scope).unwrap(),
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(fenced["status"], "revoked");
    assert!(fenced["revoked_at"].is_string());
    let historical_after = boxed_step(|| native_business_footprint(fixture)).await;
    for table in [
        "realm_actor_creations",
        "realm_actor_current_results",
        "realm_actor_private_signer_facts",
        "principal_resolutions",
        "accounts",
        "actor_profile_current_results",
    ] {
        assert_eq!(
            historical_after[table], historical_before[table],
            "runtime fence must not erase/rewrite identity or native Device originals: {table}"
        );
    }
    assert_eq!(
        fixture
            .state
            .test_persistence()
            .device_revocations()
            .applet_managed_device_authority(&candidate.actor_id, &device, chrono::Utc::now())
            .await
            .unwrap(),
        Some(authority.clone())
    );
    assert_eq!(
        fixture
            .state
            .test_persistence()
            .authority_commits()
            .committed_event(&creation_commit.event_ref)
            .await
            .unwrap()
            .unwrap(),
        creation
    );
    assert_eq!(
        fixture
            .state
            .test_persistence()
            .authority_commits()
            .committed_event(&authority.authorization_ref.event_id)
            .await
            .unwrap()
            .unwrap(),
        authorization_original
    );
    assert_eq!(
        fixture
            .state
            .test_persistence()
            .authority_commits()
            .committed_event(&accepted_event.event_id)
            .await
            .unwrap()
            .unwrap(),
        accepted
    );

    let before = boxed_step(|| active_revoke_footprint(fixture)).await;
    let (status, replay) = fixture
        .admin_post(
            &path,
            arkret_wire::ServiceOperationId::SELF_APPLET_COMMAND_REVOKE_V1,
            &json!(request),
            Some(&key),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "exact runtime revoke original: {replay}"
    );
    assert_eq!(
        serde_json::from_value::<AppletRevokeOutcome>(replay).unwrap(),
        outcome
    );
    assert_eq!(
        boxed_step(|| active_revoke_footprint(fixture)).await,
        before,
        "completed revoke retry must add no side effect"
    );
    let (status, problem) =
        boxed_step(|| active_revoke_device_submit(fixture, &authority, &fresh)).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "current runtime fence must reject fresh Device business: {problem}"
    );
    assert_eq!(
        problem["type"],
        "https://arkret.org/problems/applet_revoked"
    );
    assert_eq!(
        boxed_step(|| active_revoke_footprint(fixture)).await,
        before,
        "fenced fresh business must not write an Event/Commit or consume grant/quota"
    );
    assert!(
        fixture
            .state
            .test_persistence()
            .authority_commits()
            .committed_event(&fresh.event_id)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        fixture
            .state
            .test_persistence()
            .authority_commits()
            .committed_event(&accepted_event.event_id)
            .await
            .unwrap()
            .unwrap(),
        accepted
    );
}
