async fn native_applet_reads(
    fixture: &Fixture,
    native: &NativeService,
    candidate: &RealmActorCreatePayload,
) {
    if !super::native_read_evidence::recording() {
        return;
    }
    let external = candidate
        .external_ref
        .as_ref()
        .expect("actual accepted Ghost required");
    let view = boxed_step(|| query_managed_actor(fixture, native, &candidate.actor_id))
        .await
        .unwrap();
    assert!(view.exists);
    assert_eq!(view.actor_id.as_ref(), Some(&candidate.actor_id));
    let originals = fixture
        .state
        .test_persistence()
        .authority_commits()
        .applet_realm_actor_creations(&fixture.realm, &candidate.applet_id, None)
        .await
        .unwrap();
    let original = originals
        .iter()
        .find(|original| original.event.payload.get("actor_id") == Some(&json!(candidate.actor_id)))
        .unwrap();
    let mut encoded = String::new();
    for byte in arkret_canonical::canonical_json_bytes(&candidate.actor_id).unwrap() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(char::from(byte));
        } else {
            use std::fmt::Write as _;
            write!(&mut encoded, "%{byte:02X}").unwrap();
        }
    }
    let originals = json!({"creation":{"event":original.event,"commit":original.commit},"applet_package":native.package});
    super::native_read_evidence::capture(
        arkret_wire::ServiceOperationId::EdgeAppletActorReadResolveV1,
        "GET",
        &format!("/_arkret/edge/applet/actors/{encoded}"),
        None,
        json!(view),
        originals.clone(),
    );
    let client = arkret_http_client::Client::builder(native.package.base_url.parse().unwrap())
        .http_client(native_http_client(std::time::Duration::from_secs(30)))
        .retry(arkret_http_client::RetryConfig::disabled())
        .http_message_signer(arkret_http_client::HttpMessageSigner::new(
            fixture
                .state
                .service_verification_method("notary-key")
                .unwrap()
                .to_string(),
            fixture.state.notary_signing_key().as_ref().clone(),
        ))
        .build()
        .unwrap();
    let query = arkret_models_integration::ThirdPartyUserQuery {
        applet_id: candidate.applet_id.clone(),
        realm_id: candidate
            .actor_id
            .as_realm_actor_id()
            .unwrap()
            .realm_id
            .clone(),
        protocol: external.protocol.clone(),
        instance_id: external.instance_id.clone(),
        external_id: external.external_id.clone(),
    };
    let governor = fixture.state.service_core_id();
    let response = boxed_step(|| {
        client.applet_third_party_user(&governor, &native.package.service_id, &query)
    })
    .await
    .unwrap();
    assert!(response.exists);
    assert_eq!(response.actor_id.as_ref(), Some(&candidate.actor_id));
    assert_eq!(response.external_ref.as_ref(), Some(external));
    let encoded = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs([
            ("applet_id", query.applet_id.as_str()),
            ("realm_id", query.realm_id.as_str()),
            ("protocol", query.protocol.as_str()),
            ("instance_id", query.instance_id.as_str()),
            ("external_id", query.external_id.as_str()),
        ])
        .finish();
    super::native_read_evidence::capture(
        arkret_wire::ServiceOperationId::EdgeAppletThirdPartyUsersReadListV1,
        "GET",
        &format!("/_arkret/edge/applet/third_party/users?{encoded}"),
        None,
        json!(response),
        originals,
    );
    let mut unknown = query.clone();
    unknown.external_id.push_str("-unknown");
    let absent = boxed_step(|| {
        client.applet_third_party_user(&governor, &native.package.service_id, &unknown)
    })
    .await
    .unwrap();
    assert!(!absent.exists);
    assert!(absent.actor_id.is_none() && absent.external_ref.is_none());
    assert!(
        boxed_step(|| client.applet_third_party_user(
            &native.package.service_id,
            &native.package.service_id,
            &query
        ))
        .await
        .is_err(),
        "a source identifier does not turn a Service into the current governor"
    );
}
