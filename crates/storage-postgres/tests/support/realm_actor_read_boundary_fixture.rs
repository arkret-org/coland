// Included in realm_native_fixture. The caller supplies two genuinely accepted
// Devices from the existing Circle runtime: content reader and Realm-join-only.
// No Account/PCR surrogate or newly asserted receiver authority is constructed.

fn native_read_refusal(
    error: arkret::http_client::Error,
    status: u16,
    code: arkret_wire::ErrorCode,
) {
    let arkret::http_client::Error::Api {
        status: actual,
        error,
    } = error
    else {
        panic!("read boundary must reach the real HTTP route, not a local validation failure");
    };
    assert_eq!(actual, status, "actual HTTP read refusal: {error}");
    assert_eq!(error.error_code(), Some(code));
}

async fn realm_native_read_boundaries(
    fixture: &Fixture,
    circle: &arkret_bridge_runtime::managed_device::ManagedDevice,
    parent: &arkret_bridge_runtime::managed_device::ManagedDevice,
    event_id: &EventId,
) {
    use arkret_models_identity::{
        RealmDeviceSignerKind, SignerKeyQueryOutcome, SignerKeyQuerySelector,
        SignerKeysQueryRequestBody,
    };
    use arkret_wire::{
        CommitStreamRef, CommittedEventRef, CommittedEventView, ErrorCode, ReadableFloorReason,
        StreamScanDirection, StreamScanRequest,
    };

    assert!(matches!(circle.effective_scope(), ScopeRef::Circle { .. }));
    assert_eq!(
        parent.effective_scope(),
        &ScopeRef::Realm {
            realm_id: fixture.realm.clone()
        }
    );
    assert_eq!(circle.actor_id, parent.actor_id);
    assert_ne!(circle.device_id, parent.device_id);
    assert!(circle.actor_id.as_account_id().is_none());
    let authority = fixture
        .state
        .test_persistence()
        .device_revocations()
        .applet_managed_device_authority(&circle.actor_id, &circle.device_id, chrono::Utc::now())
        .await
        .unwrap()
        .unwrap();
    let parent_authority = fixture
        .state
        .test_persistence()
        .device_revocations()
        .applet_managed_device_authority(&parent.actor_id, &parent.device_id, chrono::Utc::now())
        .await
        .unwrap()
        .unwrap();
    assert!(authority.scopes.permits(
        circle.effective_scope(),
        &[arkret_wire::CapabilityActionId::EventRead]
    ));
    assert!(parent_authority.scopes.permits(
        parent.effective_scope(),
        &[arkret_wire::CapabilityActionId::AppletJoin]
    ));
    assert!(!parent_authority.scopes.permits(
        parent.effective_scope(),
        &[arkret_wire::CapabilityActionId::EventRead]
    ));
    assert!(
        !parent_authority
            .scopes
            .contains_scope(circle.effective_scope())
    );

    let original = fixture
        .state
        .test_persistence()
        .authority_commits()
        .committed_event(event_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&original.event.scope_ref, circle.effective_scope());
    assert_eq!(original.event.actor_id, circle.actor_id);
    let before = boxed_step(|| native_business_footprint(fixture)).await;
    let view = boxed_step(|| circle.client().committed_event_get(event_id))
        .await
        .unwrap();
    let CommittedEventView::Full(full) = &view else {
        panic!("own Circle original must be genuinely Full")
    };
    assert_eq!(full.event, original.event);
    assert_eq!(full.commit, original.commit);
    let proof = full.event.producer_proof.as_ref().unwrap();
    let reference = CommittedEventRef {
        event_id: full.event.event_id.clone(),
        commit_id: full.commit.commit_id.clone(),
        stream_ref: full.commit.stream_ref.clone(),
        stream_position: full.commit.stream_position,
    };
    let selector = SignerKeyQuerySelector::HistoricalRealmDevice {
        sender_kind: RealmDeviceSignerKind::RealmDevice,
        actor_id: circle.actor_id.clone(),
        device_id: circle.device_id.clone(),
        verification_method: proof.verification_method.clone(),
        committed_event_ref: reference,
    };
    let current = SignerKeyQuerySelector::CurrentRealmDevice {
        sender_kind: RealmDeviceSignerKind::RealmDevice,
        actor_id: circle.actor_id.clone(),
        device_id: circle.device_id.clone(),
        verification_method: proof.verification_method.clone(),
    };
    let mut wrong_coordinate = selector.clone();
    let SignerKeyQuerySelector::HistoricalRealmDevice {
        committed_event_ref,
        ..
    } = &mut wrong_coordinate
    else {
        unreachable!()
    };
    committed_event_ref.stream_position += 1;
    let query = SignerKeysQueryRequestBody {
        request_id: arkret_wire::RequestId::new(format!("ak:request:{}", uuid::Uuid::now_v7()))
            .unwrap(),
        realm_id: fixture.realm.clone(),
        recipient_account_id: None,
        recipient_actor_id: Some(circle.actor_id.clone()),
        queries: vec![selector.clone(), current, wrong_coordinate],
    };
    query.validate().unwrap();
    let keys = boxed_step(|| circle.client().signer_keys_query(&query))
        .await
        .unwrap();
    keys.validate_for_request(&query).unwrap();
    let SignerKeyQueryOutcome::HistoricalRealmDeviceResolved {
        key, accepted_at, ..
    } = &keys.results[0]
    else {
        panic!("own-scope exact historical native signer must resolve");
    };
    assert_eq!(*accepted_at, original.commit.committed_at);
    assert!(
        matches!(&keys.results[1], SignerKeyQueryOutcome::Unavailable { .. }),
        "current selector has no independently authoritative target scope"
    );
    assert!(
        matches!(&keys.results[2], SignerKeyQueryOutcome::Unavailable { .. }),
        "wrong Commit coordinate cannot resolve a live projection"
    );
    let expected = fixture
        .state
        .test_persistence()
        .authority_commits()
        .historical_producer_signer_key(&fixture.realm, &selector)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(keys.results[0], expected);
    let fact = fixture
        .state
        .test_persistence()
        .authority_commits()
        .producer_signer_fact(&original.event, &original.commit)
        .await
        .unwrap()
        .unwrap();
    let suite = original.event.realm_id.digest_suite_code().digest_suite();
    fact.validate_commit_binding(full, suite).unwrap();
    arkret_identity::account_device_signer_evidence::verify_historical_producer_event_signature(
        &original.event,
        &fact,
        suite,
    )
    .unwrap();
    let material = arkret_signatures::PublicKeyMaterial::Ed25519Raw {
        bytes: arkret_canonical::base64url_decode(key.public_key_b64u.as_str()).unwrap(),
    };
    let signed = arkret_signatures::EventProofBuilder::new()
        .envelope_bytes(&original.event)
        .unwrap();
    arkret_signatures::verify_ed25519_detached_jws_proof_with_digest_suite(
        proof,
        &signed,
        &original.event.actor_id,
        &material,
        suite,
    )
    .unwrap();

    // A complete, structurally valid same-Realm subject may not replace the
    // authenticated recipient. Its principal is the actual native Service,
    // not an invented personal Account or accepted RealmActor assertion.
    let mut wrong_recipient = query.clone();
    wrong_recipient.recipient_actor_id = Some(ActorId::realm(arkret_wire::RealmActorId::new(
        fixture.realm.clone(),
        authority.source_service_id.clone(),
    )));
    assert_ne!(
        wrong_recipient.recipient_actor_id.as_ref(),
        Some(&circle.actor_id)
    );
    wrong_recipient.validate().unwrap();
    native_read_refusal(
        boxed_step(|| circle.client().signer_keys_query(&wrong_recipient))
            .await
            .unwrap_err(),
        404,
        ErrorCode::NotFound,
    );

    let stream = CommitStreamRef::from_scope(circle.effective_scope(), None).unwrap();
    let mut request = StreamScanRequest {
        realm_id: fixture.realm.clone(),
        stream_ref: stream.clone(),
        direction: StreamScanDirection::After(None),
        limit: 1,
    };
    let first = boxed_step(|| circle.client().scan_commit_stream(&request))
        .await
        .unwrap();
    first.validate_for_request(&request).unwrap();
    assert_eq!(first.committed_events.len(), 1);
    let floor = first.readable_floor.clone().unwrap();
    assert_eq!(floor.floor_reason, ReadableFloorReason::MembershipJoin);
    assert!(
        floor.oldest_position > 0,
        "actual native Circle join must have a real private prefix"
    );
    let join = fixture
        .state
        .test_persistence()
        .authority_commits()
        .committed_event_by_commit_id(&floor.floor_commit_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(join.commit.stream_ref, stream);
    assert_eq!(join.commit.stream_position, floor.oldest_position);
    assert_eq!(join.event.kind, EventKind::MemberState);
    assert_eq!(join.event.payload["member_id"], json!(circle.actor_id));
    assert_eq!(join.event.payload["membership"], "join");
    let predecessor = fixture
        .state
        .test_persistence()
        .authority_commits()
        .committed_event_by_commit_id(join.commit.previous_commit_ref.as_ref().unwrap())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(predecessor.commit.stream_ref, stream);
    assert!(predecessor.commit.stream_position < floor.oldest_position);
    // Check actual prefix visibility through the registered resource route.
    match boxed_step(|| {
        circle
            .client()
            .committed_event_get(&predecessor.event.event_id)
    })
    .await
    {
        Ok(view) => assert!(
            !matches!(view, CommittedEventView::Full(_)),
            "actual pre-join canonical bytes must not become Full"
        ),
        Err(error) => native_read_refusal(error, 404, ErrorCode::NotFound),
    }
    let mut previous = first.committed_events[0].commit().clone();
    assert_eq!(previous.commit_id, floor.floor_commit_id);
    let mut seen = std::collections::BTreeSet::new();
    seen.insert(previous.commit_id.clone());
    let mut page = first;
    let mut pages = 1;
    while page.truncated {
        assert!(pages < 128, "bounded real Circle stream did not terminate");
        request.direction = StreamScanDirection::After(Some(previous.stream_position));
        page = boxed_step(|| circle.client().scan_commit_stream(&request))
            .await
            .unwrap();
        page.validate_for_request(&request).unwrap();
        assert_eq!(page.readable_floor.as_ref(), Some(&floor));
        assert_eq!(page.committed_events.len(), 1);
        let row = page.committed_events[0].commit();
        row.validate_successor_of(&previous).unwrap();
        assert!(
            seen.insert(row.commit_id.clone()),
            "physical pages cannot repeat an accepted Commit"
        );
        assert!(row.stream_position >= floor.oldest_position);
        previous = row.clone();
        pages += 1;
    }
    assert!(
        pages > 1,
        "limit=1 must exercise genuine native stream pagination"
    );
    assert!(
        seen.contains(&original.commit.commit_id),
        "scan must reach the supplied accepted native Message"
    );
    request.direction = StreamScanDirection::Before(Some(floor.oldest_position));
    let below = boxed_step(|| circle.client().scan_commit_stream(&request))
        .await
        .unwrap();
    below.validate_for_request(&request).unwrap();
    assert!(below.committed_events.is_empty() && !below.truncated);
    assert_eq!(below.readable_floor.as_ref(), Some(&floor));

    for wrong_stream in [
        CommitStreamRef::Realm {
            realm_id: fixture.realm.clone(),
        },
        CommitStreamRef::RealmControl {
            realm_id: fixture.realm.clone(),
        },
    ] {
        let request = StreamScanRequest {
            realm_id: fixture.realm.clone(),
            stream_ref: wrong_stream,
            direction: StreamScanDirection::After(None),
            limit: 1,
        };
        native_read_refusal(
            boxed_step(|| circle.client().scan_commit_stream(&request))
                .await
                .unwrap_err(),
            403,
            ErrorCode::CapabilityDenied,
        );
    }
    // This is an actual accepted private control original, not a made-up ID.
    assert!(
        fixture
            .state
            .test_persistence()
            .authority_commits()
            .committed_event(&parent.authorization_event_id)
            .await
            .unwrap()
            .is_some()
    );
    native_read_refusal(
        boxed_step(|| {
            circle
                .client()
                .committed_event_get(&parent.authorization_event_id)
        })
        .await
        .unwrap_err(),
        404,
        ErrorCode::NotFound,
    );
    let realm_original = fixture.authority_event_ref.as_ref().unwrap();
    assert!(
        fixture
            .state
            .test_persistence()
            .authority_commits()
            .committed_event(realm_original)
            .await
            .unwrap()
            .is_some()
    );
    native_read_refusal(
        boxed_step(|| circle.client().committed_event_get(realm_original))
            .await
            .unwrap_err(),
        404,
        ErrorCode::NotFound,
    );

    // This independently signed Device can join the parent Realm, but has no
    // EventRead or Circle scope. None of these calls may borrow its sibling's
    // business authority merely because actor_id and host are equal.
    native_read_refusal(
        boxed_step(|| parent.client().committed_event_get(event_id))
            .await
            .unwrap_err(),
        401,
        ErrorCode::Unauthenticated,
    );
    native_read_refusal(
        boxed_step(|| parent.client().signer_keys_query(&query))
            .await
            .unwrap_err(),
        401,
        ErrorCode::Unauthenticated,
    );
    let request = StreamScanRequest {
        realm_id: fixture.realm.clone(),
        stream_ref: stream,
        direction: StreamScanDirection::After(None),
        limit: 1,
    };
    native_read_refusal(
        boxed_step(|| parent.client().scan_commit_stream(&request))
            .await
            .unwrap_err(),
        401,
        ErrorCode::Unauthenticated,
    );
    assert_eq!(
        boxed_step(|| native_business_footprint(fixture)).await,
        before,
        "native event/signer/scan successes and denials must not mutate accepted business or quota state"
    );
}
