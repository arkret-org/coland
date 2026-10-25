async fn account_read(
    fixture: &Fixture,
    method: reqwest::Method,
    path: &str,
    operation: arkret_wire::ServiceOperationId,
    body: Option<Value>,
) -> Value {
    let url = format!(
        "{}{path}",
        fixture.state.config().public_base_url.trim_end_matches('/')
    );
    let proof = arkret_signatures::dpop::build_dpop_proof(
        &arkret_signatures::dpop::DpopProofRequest::new(method.as_str(), &url)
            .access_token(fixture.token.clone()),
        &fixture.holder_key,
    )
    .unwrap();
    let client = realm_native_fixture::native_http_client(std::time::Duration::from_secs(30));
    let mut request = client
        .request(method, &url)
        .header("authorization", format!("DPoP {}", fixture.token))
        .header("dpop", proof.header_value)
        .header("arkret-operation", operation.as_str());
    if let Some(body) = body {
        request = request
            .header("content-type", "application/json")
            .body(arkret_canonical::canonical_json_bytes(&body).unwrap());
    }
    let response = request.send().await.unwrap();
    let status = response.status();
    let value: Value = response.json().await.unwrap();
    assert_eq!(status.as_u16(), 200, "{}: {value}", operation.as_str());
    value
}

pub(super) async fn account_reads(fixture: &Fixture) {
    use arkret_models_collaboration::consent_operations::{
        ConsentList, ConsentReplaceRequestBody, ConsentView,
    };
    use arkret_models_identity::actor_profile_operations::{
        ActorProfileResolveRequestBody, ActorProfileResolveResponseBody,
    };
    use arkret_models_identity::{
        MediaServiceBindingRequestBody, MediaServiceBindingResponseBody,
        PrincipalResolutionAuditEvidence, PrincipalResolutionAuditRequestBody,
        PublicPrincipalResolution,
    };
    use arkret_wire::ServiceOperationId as Op;
    if !recording() {
        return;
    }
    let actor = ActorId::account(fixture.pcr.history.account.clone());
    let client = realm_native_fixture::native_http_client(std::time::Duration::from_secs(30));
    let base = fixture.state.config().public_base_url.trim_end_matches('/');
    let resolution_path =
        arkret_models_identity::canonical_service_resolution_path(&fixture.state.service_core_id());
    let station: arkret_models_identity::AuthenticatedServiceResolution = client
        .get(format!("{base}{resolution_path}"))
        .header("arkret-operation", Op::OpenServiceReadResolutionV1.as_str())
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let path = format!(
        "/_arkret/open/principals/{}/resolution?station_id={}",
        fixture.pcr.history.account.principal_id, fixture.pcr.history.account.station_id
    );
    let value: Value = client
        .get(format!("{base}{path}"))
        .header(
            "arkret-operation",
            Op::OpenIdentityReadResolutionV1.as_str(),
        )
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let public: PublicPrincipalResolution = serde_json::from_value(value.clone()).unwrap();
    let (projection, _) = arkret_identity::verify_embedded_public_principal_resolution_history(
        &public,
        &station,
        chrono::Utc::now(),
    )
    .unwrap();
    assert_eq!(public.account_id, fixture.pcr.history.account);
    assert_eq!(projection.did, fixture.pcr.history.did);
    let mut changed = public.clone();
    changed
        .projection_attestation
        .attestation
        .method_history_evidence_digest = Hash::new(format!("sha256:{}", "0".repeat(64))).unwrap();
    assert!(
        arkret_identity::verify_embedded_public_principal_resolution_history(
            &changed,
            &station,
            chrono::Utc::now()
        )
        .is_err()
    );
    capture(
        Op::OpenIdentityReadResolutionV1,
        "GET",
        &path,
        None,
        value,
        json!({"station_resolution":station,"pcr_genesis":pcr_originals(&fixture.pcr)}),
    );

    let request = PrincipalResolutionAuditRequestBody::new(fixture.pcr.history.account.clone());
    let path = "/_arkret/self/identity/resolution-audit/query";
    let value = account_read(
        fixture,
        reqwest::Method::POST,
        path,
        Op::SelfIdentityReadResolutionAuditV1,
        Some(json!(request)),
    )
    .await;
    let audit: PrincipalResolutionAuditEvidence = serde_json::from_value(value.clone()).unwrap();
    audit.validate().unwrap();
    assert_eq!(audit.account_id, fixture.pcr.history.account);
    for (event, commit) in [
        (&audit.principal_genesis_event, &audit.genesis_commits[0]),
        (
            &audit.founding_device_authorize_event,
            &audit.genesis_commits[1],
        ),
        (&audit.current_resolution_event, &audit.accepted_commit),
    ] {
        let accepted = fixture
            .state
            .test_persistence()
            .authority_commits()
            .committed_event(&event.event_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&accepted.event, event);
        assert_eq!(&accepted.commit, commit);
    }
    capture(
        Op::SelfIdentityReadResolutionAuditV1,
        "POST",
        path,
        Some(json!(request)),
        value,
        json!({"station_resolution":station}),
    );

    let request = ActorProfileResolveRequestBody::new(fixture.realm.clone(), vec![actor.clone()]);
    let path = "/_arkret/self/actor-profiles/query";
    let value = account_read(
        fixture,
        reqwest::Method::POST,
        path,
        Op::SelfActorProfileReadResolveV1,
        Some(json!(request)),
    )
    .await;
    let profiles: ActorProfileResolveResponseBody = serde_json::from_value(value.clone()).unwrap();
    arkret_models_collaboration::actor_profile_resolution::validate_actor_profile_resolve_outcome(
        &profiles,
        std::slice::from_ref(&actor),
    )
    .unwrap();
    assert_eq!(profiles.profiles.len(), 1);
    let profile = &profiles.profiles[0];
    let accepted = fixture
        .state
        .test_persistence()
        .authority_commits()
        .committed_event(&profile.profile_event.event_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(profile.profile_event, accepted.event);
    assert_eq!(profile.profile_commit, accepted.commit);
    assert_eq!(profile.actor_profile.display_name, "Applet admin");
    capture(
        Op::SelfActorProfileReadResolveV1,
        "POST",
        path,
        Some(json!(request)),
        value,
        json!({"profile":accepted_original(&accepted),"pcr_genesis":pcr_originals(&fixture.pcr)}),
    );

    // An exact, distinct peer also has a real accepted PCR. No directory-only peer.
    let peer = PcrGenesisFixture::new(fixture.state.service_did());
    peer.admit(&fixture.state).await.unwrap();
    let payload: arkret_models_collaboration::events_payloads::ConsentReplacePayload =
        serde_json::from_value(json!({
            "peer":{"kind":"actor","actor_id":ActorId::account(peer.history.account.clone())},
            "expected_current":{"state":"never_written"},"permissions":[{"consent_scope":"invite"}]
        }))
        .unwrap();
    let mut event = fixture.admin_event(
        EventKind::ConsentReplace,
        ScopeRef::Realm {
            realm_id: fixture.pcr.unit.transactions[0].event.realm_id.clone(),
        },
        json!(payload),
    );
    event.authorization_ref = Some(
        fixture.pcr.unit.transactions[0]
            .event
            .event_id
            .clone()
            .into(),
    );
    event = fixture.sign_admin(event);
    let request = ConsentReplaceRequestBody {
        consent_event: arkret_wire::EventAdmissionSubmission::new(event.clone()),
    };
    request.validate().unwrap();
    let written = account_read(
        fixture,
        reqwest::Method::POST,
        "/_arkret/self/consent/results/replace",
        Op::SelfConsentCommandReplaceV1,
        Some(json!(request)),
    )
    .await;
    let accepted = fixture
        .state
        .test_persistence()
        .authority_commits()
        .committed_event(&event.event_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(accepted.event, event);
    let mut url = Url::parse(&format!("{base}/_arkret/self/consent/result")).unwrap();
    url.query_pairs_mut().append_pair(
        "peer",
        &arkret_canonical::canonical_json_string(&payload.peer).unwrap(),
    );
    let path = &url[url::Position::BeforePath..];
    let value = account_read(
        fixture,
        reqwest::Method::GET,
        path,
        Op::SelfConsentResourceGetV1,
        None,
    )
    .await;
    let consent: ConsentView = serde_json::from_value(value.clone()).unwrap();
    consent.validate().unwrap();
    assert_eq!(value, written);
    assert_eq!(consent.peer, payload.peer);
    assert_eq!(consent.permission_scopes.len(), 1);
    assert_eq!(consent.revision.commit_id, accepted.commit.commit_id);
    capture(
        Op::SelfConsentResourceGetV1,
        "GET",
        path,
        None,
        value,
        json!({"consent":accepted_original(&accepted),"holder_genesis":pcr_originals(&fixture.pcr),"peer_genesis":pcr_originals(&peer)}),
    );
    let path = "/_arkret/self/consent/results";
    let value = account_read(
        fixture,
        reqwest::Method::GET,
        path,
        Op::SelfConsentReadListV1,
        None,
    )
    .await;
    let list: ConsentList = serde_json::from_value(value.clone()).unwrap();
    list.validate().unwrap();
    assert!(list.consents.contains(&consent));
    capture(
        Op::SelfConsentReadListV1,
        "GET",
        path,
        None,
        value,
        json!({"consent":accepted_original(&accepted),"holder_genesis":pcr_originals(&fixture.pcr),"peer_genesis":pcr_originals(&peer)}),
    );

    let media: arkret_models_collaboration::events_payloads::RealmMediaServicePayload = serde_json::from_value(json!({
        "value":{"service_id":fixture.state.service_core_id(),"foci":[{"focus_id":"native-read","focus_kind":"arkret_native",
            "token_endpoint":format!("{base}/_arkret/self/rtc/token"),"connect_url":base}]}
    })).unwrap();
    media.validate().unwrap();
    let event = fixture.admin_event(
        EventKind::RealmMediaService,
        ScopeRef::Realm {
            realm_id: fixture.realm.clone(),
        },
        json!(media),
    );
    accepted_admin_domain_event(fixture, event.clone()).await;
    let accepted = fixture
        .state
        .test_persistence()
        .authority_commits()
        .committed_event(&event.event_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(accepted.event, event);
    let request = MediaServiceBindingRequestBody {
        request_id: format!("ak:request:{}", uuid::Uuid::now_v7())
            .parse()
            .unwrap(),
        realm_id: fixture.realm.clone(),
    };
    let path = "/_arkret/self/media-service-bindings/query";
    let value = account_read(
        fixture,
        reqwest::Method::POST,
        path,
        Op::SelfMediaServiceBindingReadResolveV1,
        Some(json!(request)),
    )
    .await;
    let binding: MediaServiceBindingResponseBody = serde_json::from_value(value.clone()).unwrap();
    binding
        .validate_for_request(&request, &fixture.state.service_core_id())
        .unwrap();
    assert!(binding.is_reusable_at(chrono::Utc::now()));
    assert_eq!(binding.route.service_kind, "station");
    assert!(!binding.signing_keys.is_empty());
    capture(
        Op::SelfMediaServiceBindingReadResolveV1,
        "POST",
        path,
        Some(json!(request)),
        value,
        json!({"media_service":accepted_original(&accepted),"station_resolution":station}),
    );
}
