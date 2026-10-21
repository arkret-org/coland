//! Real private control transport for Realm-owned subjects.
use arkret_wire::{CommittedEventRef, DidUrl, ServiceOperationId};

use super::*;

pub(super) async fn current(
    fixture: &Fixture,
    actor: &ActorId,
    selector: Value,
) -> Option<(CommittedEventRef, Value)> {
    use diesel::OptionalExtension as _;
    use diesel::sql_types::{Jsonb, Text};
    #[derive(diesel::QueryableByName)]
    struct Row {
        #[diesel(sql_type = Jsonb)]
        value: Value,
    }
    let mut connection = fixture.pool.get().await.unwrap();
    let row = diesel::sql_query("SELECT jsonb_build_object('source_ref',jsonb_build_object('event_id',c.commit_json->'event_ref','commit_id',r.current_commit_id,'stream_ref',r.source_stream_ref,'stream_position',r.current_stream_position),'value',r.value) AS value FROM realm_actor_current_results r JOIN realm_commits c ON c.commit_id=r.current_commit_id AND c.stream_position=r.current_stream_position AND c.stream_ref=r.source_stream_ref WHERE r.realm_id=$1 AND r.actor_id=$2 AND r.selector=$3")
        .bind::<Text, _>(fixture.realm.as_str())
        .bind::<Jsonb, _>(json!(actor))
        .bind::<Jsonb, _>(selector)
        .get_result::<Row>(&mut connection).await.optional().unwrap()?;
    Some((
        serde_json::from_value(row.value["source_ref"].clone()).unwrap(),
        row.value["value"].clone(),
    ))
}

pub(super) fn controller(creation: &Event, namespace: &str) -> SigningKey {
    let candidate: RealmActorCreatePayload =
        serde_json::from_value(json!(creation.payload)).unwrap();
    let local = candidate
        .initial_resolution
        .did
        .as_str()
        .rsplit(':')
        .next()
        .unwrap();
    SigningKey::from_bytes(&deterministic_managed_actor_seed(&format!(
        "{}:{local}:controller:{}",
        safe_did_token(namespace),
        candidate.service_id,
    )))
}

pub(super) fn sign(
    candidate: &RealmActorCreatePayload,
    key: &SigningKey,
    kind: EventKind,
    payload: Value,
) -> Event {
    let at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    let mut event = arkret_wire::test_support::raw_event_for_actor_at(
        kind.as_str(),
        ScopeRef::RealmControl {
            realm_id: candidate
                .actor_id
                .as_realm_actor_id()
                .unwrap()
                .realm_id
                .clone(),
        },
        candidate.actor_id.clone(),
        payload,
        at,
    )
    .unwrap();
    event.applet_id = Some(candidate.applet_id.clone());
    event.producer_proof = None;
    let mut authored = arkret_wire::AuthoredEvent::finalize_with_digest_suite(
        event,
        arkret_canonical::DigestSuite::Sha256,
    )
    .unwrap();
    let signer = Ed25519PayloadSigner::new(
        key.clone(),
        candidate.initial_resolution.did.clone(),
        candidate.control_method_kid.clone(),
    );
    arkret_signatures::sign_event(
        &mut authored,
        &signer,
        arkret_signatures::SignEventOptions::new().with_created_at(at),
    )
    .unwrap();
    authored.into_event()
}

pub(super) async fn post(
    fixture: &Fixture,
    metadata: &RealmActorControlHttpMetadata,
    method: &DidUrl,
    key: &SigningKey,
    event: &Event,
) -> (StatusCode, Value) {
    post_with_approvals(fixture, metadata, method, key, event, vec![]).await
}

pub(super) async fn post_with_approvals(
    fixture: &Fixture,
    metadata: &RealmActorControlHttpMetadata,
    method: &DidUrl,
    key: &SigningKey,
    event: &Event,
    approvals: Vec<arkret_wire::ApprovalSignature>,
) -> (StatusCode, Value) {
    let mut body = creation_submission(event.clone());
    if !approvals.is_empty() {
        body["approval_signatures"] = json!(approvals);
    }
    let bytes = arkret_canonical::canonical_json_bytes(&body).unwrap();
    let digest = content_digest_header(&bytes);
    let path = "/_arkret/self/events";
    let scheme = fixture
        .state
        .config()
        .public_base_url
        .split_once("://")
        .unwrap()
        .0;
    let parts = SignedRequestParts {
        method: "POST".into(),
        target_uri: format!("{scheme}://server{path}"),
        authority: "server".into(),
        path: path.into(),
        headers: vec![
            (
                "arkret-operation".into(),
                ServiceOperationId::SelfEventsCommandSubmitV1
                    .as_str()
                    .into(),
            ),
            ("content-type".into(), "application/json".into()),
            ("content-digest".into(), digest.clone()),
            (
                "destination-service-id".into(),
                fixture.state.service_id().into(),
            ),
            (
                "arkret-realm-actor-control".into(),
                metadata.to_header_value().unwrap(),
            ),
            ("idempotency-key".into(), uuid::Uuid::now_v7().to_string()),
        ],
        body_digest: Some(digest),
    };
    let signature = sign_http_message_for_scenario(
        &parts,
        HttpSignatureScenario::RealmActorControlV1,
        &["content-digest", "idempotency-key"],
        "sig1",
        method.as_str(),
        chrono::Utc::now().timestamp(),
        key,
    )
    .unwrap();
    let mut request = TestClient::post(format!("http://server{path}"));
    for (name, value) in parts.headers {
        request = request.add_header(
            salvo::http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
            value,
            true,
        );
    }
    let mut response = request
        .add_header("signature-input", signature.signature_input_header, true)
        .add_header("signature", signature.signature_header, true)
        .body(bytes)
        .send(&service(fixture.state.clone()))
        .await;
    (
        response.status_code.unwrap(),
        response.take_json().await.unwrap(),
    )
}

pub(super) async fn device_event(
    fixture: &Fixture,
    creation: &Event,
    namespace: &str,
    key: &SigningKey,
    device_id: arkret_wire::DeviceId,
    scopes: Value,
    expires_at: Option<chrono::DateTime<chrono::Utc>>,
) -> (Event, RealmActorControlHttpMetadata, SigningKey) {
    use arkret_models_collaboration::events_payloads::DeviceAuthorizePayload;
    use ed25519_dalek::Signer as _;
    let candidate: RealmActorCreatePayload =
        serde_json::from_value(json!(creation.payload)).unwrap();
    let actor = &candidate.actor_id;
    let (control_ref, _) = current(
        fixture,
        actor,
        json!({"kind":"realm_actor_control","actor_id":actor}),
    )
    .await
    .unwrap();
    let previous = current(
        fixture,
        actor,
        json!({"kind":"realm_actor_device_authorization","actor_id":actor,"device_id":device_id}),
    )
    .await;
    let (_, generation) = current(
        fixture,
        actor,
        json!({"kind":"realm_actor_device_generation","actor_id":actor}),
    )
    .await
    .unwrap();
    let at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    let mut hpke = vec![0xec, 0x01];
    hpke.extend([119; 32]);
    let mut payload: DeviceAuthorizePayload = serde_json::from_value(json!({
        "device_id":device_id,
        "device_public_key_did":format!("did:key:{}",arkret_canonical::ed25519_pubkey_to_did_key_multibase(key.verifying_key().as_bytes())),
        "hpke_key":arkret_canonical::encode_multibase_base58btc(hpke),
        "algorithms":["ak.hpke_x25519_aead_chacha20poly1305.v1"],"device_key_algorithm":"Ed25519",
        "authorized_by":actor.signing_principal_id(),"scopes":scopes,
        "not_before":arkret_canonical::format_timestamp_canonical(at-chrono::Duration::seconds(1)),"expires_at":arkret_canonical::format_timestamp_canonical(expires_at.unwrap_or(at+chrono::Duration::hours(1))),
        "authorization_binding_kind":"realm_managed_delegation",
        "authorized_generation_ref":generation["current_device_generation_ref"],
        "device_signature":"unsigned","applet_id":candidate.applet_id,
        "expected_control_revision":{"commit_id":control_ref.commit_id,"stream_position":control_ref.stream_position},
        "expected_device_revision":previous.map(|(source,_)|json!({"commit_id":source.commit_id,"stream_position":source.stream_position})),
    })).unwrap();
    let possession = payload
        .realm_device_possession_signature_input(actor)
        .unwrap();
    payload.device_signature = serde_json::from_value(json!(arkret_canonical::base64url_encode(
        key.sign(&possession).to_bytes()
    )))
    .unwrap();
    let controller = controller(creation, namespace);
    let event = sign(
        &candidate,
        &controller,
        EventKind::DeviceAuthorize,
        json!(payload),
    );
    let metadata = RealmActorControlHttpMetadata {
        actor_id: actor.clone(),
        control_ref,
        nonce: random_nonce(),
    };
    (event, metadata, controller)
}
