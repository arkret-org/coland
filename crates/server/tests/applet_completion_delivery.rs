//! Creation completion preserves the exact Realm original over authenticated TLS retries.
#[path = "../../storage-postgres/tests/support/applet_authoring.rs"]
#[allow(dead_code)]
mod applet_authoring;
#[path = "../../storage-postgres/tests/support/ordinary_realm.rs"]
#[allow(dead_code)]
mod ordinary_realm;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use arkret_models_integration::{AppletTransactionRequestBody, AppletTransactionResponseBody};
use arkret_signatures::http_signature::{
    HttpSignatureScenario, SignatureVerificationPolicy, verify_signed_http_message,
};
use coland_test_support::AppStateTestExt as _;
use salvo::http::StatusCode;

#[tokio::test]
async fn durable_completion_retries_real_signed_delivery_before_ack() {
    let database = coland_storage_postgres::test_database::TestDatabase::lease().await;
    let fixture = Box::pin(applet_authoring::realm_creation_completion_fixture(
        database.pool(),
    ))
    .await;
    let pending = fixture
        .state
        .test_persistence()
        .applets()
        .pending_authoring_completions(16)
        .await
        .unwrap();
    assert_eq!(
        pending.len(),
        1,
        "the actual creation transaction writes one durable completion"
    );
    assert!(
        pending[0].context.is_none(),
        "short-lived material is not fabricated by acceptance"
    );
    let method = fixture
        .state
        .service_verification_method("notary-key")
        .unwrap();
    let expected = applet_authoring::completion_application(&fixture.state)
        .prepare_applet_authoring_completion(
            &pending[0],
            &fixture.state.service_core_id(),
            &method,
            fixture.state.notary_signing_key().as_ref(),
        )
        .await
        .unwrap();
    assert_eq!(expected.endpoint, fixture.package.base_url);
    assert_eq!(expected.applet_id, fixture.package.applet_id);
    assert_eq!(expected.destination_id, fixture.package.service_id);
    assert_eq!(expected.source_id, fixture.state.service_core_id());
    let context = expected.context.clone().unwrap();
    context.validate().unwrap();
    let arkret_models_integration::RealmActorMaterial::Event {
        event,
        commit,
        producer_signer_fact,
    } = &context.material.material
    else {
        panic!("completion must name the original creation")
    };
    assert_eq!(event.kind, arkret_wire::EventKind::RealmActorCreate);
    assert_eq!(event.event_id, expected.creation_ref.event_id);
    assert_eq!(commit.commit_id, expected.creation_ref.commit_id);
    assert_eq!(commit.stream_ref, expected.creation_ref.stream_ref);
    assert_eq!(
        commit.stream_position,
        expected.creation_ref.stream_position
    );
    assert_eq!(context.material.actor_id, expected.actor_id);
    assert!(matches!(
        producer_signer_fact,
        arkret_models_collaboration::authority_commit::HistoricalProducerSignerFact::Service(_)
    ));
    let body = AppletTransactionRequestBody::Authoring(Box::new(
        arkret_models_integration::AppletAuthoringTransactionRequestBody {
            applet_id: expected.applet_id.clone(),
            source_id: expected.source_id.clone(),
            authoring_context: context,
        },
    ));
    let expected_bytes = arkret_canonical::canonical_json_bytes(&body).unwrap();
    let key = fixture.state.notary_signing_key().verifying_key();
    let (send, mut receive) = tokio::sync::mpsc::channel(2);
    let attempts = Arc::new(AtomicUsize::new(0));
    let seen = attempts.clone();
    let exact = expected.clone();
    fixture.set_delivery_handler(Arc::new(move |raw| {
        let attempt=seen.fetch_add(1,Ordering::SeqCst);
        let end=raw.windows(4).position(|bytes|bytes==b"\r\n\r\n").unwrap();
        let block=std::str::from_utf8(&raw[..end]).unwrap();
        let mut lines=block.lines();
        assert_eq!(lines.next().unwrap(),"POST /_arkret/edge/applet/transactions HTTP/1.1");
        let headers=lines.map(|line|line.split_once(':').unwrap()).map(|(name,value)|(name.to_owned(),value.trim().to_owned())).collect::<Vec<_>>();
        let header=|name:&str| headers.iter().find(|(key,_)|key.eq_ignore_ascii_case(name)).unwrap().1.as_str();
        assert_eq!(header("Arkret-Operation"),arkret_wire::ServiceOperationId::EDGE_APPLET_COMMAND_TRANSACTION_V1);
        assert_eq!(header("Source-Service-ID"),exact.source_id.as_str());
        assert_eq!(header("Destination-Service-ID"),exact.destination_id.as_str());
        assert_eq!(header("Idempotency-Key"),exact.idempotency_key);
        assert!(!headers.iter().any(|(name,_)|name.eq_ignore_ascii_case("Authorization")));
        let bytes=&raw[end+4..];
        assert_eq!(bytes,expected_bytes);
        let decoded:AppletTransactionRequestBody=serde_json::from_slice(bytes).unwrap();
        decoded.validate().unwrap();
        assert!(matches!(decoded,AppletTransactionRequestBody::Authoring(_)));
        let target=format!("{}/_arkret/edge/applet/transactions",exact.endpoint.trim_end_matches('/'));
        let url=url::Url::parse(&target).unwrap();
        let policy=SignatureVerificationPolicy::for_scenario(HttpSignatureScenario::ServiceToServiceV1,&["content-digest","idempotency-key"]).unwrap();
        verify_signed_http_message("POST",&target,&url[url::Position::BeforeHost..url::Position::AfterPort],
            "/_arkret/edge/applet/transactions",headers.iter().map(|(name,value)|(name.as_str(),value.as_str())),
            bytes,&key,&policy,chrono::Utc::now().timestamp()).unwrap();
        send.blocking_send((bytes.to_vec(),header("Signature-Input").to_owned())).unwrap();
        if attempt==0 {
            (StatusCode::SERVICE_UNAVAILABLE,serde_json::json!({"type":"https://arkret.org/problems/service_unavailable","title":"Service unavailable","status":503}))
        } else {
            (StatusCode::OK,serde_json::to_value(AppletTransactionResponseBody::Accepted {committed_event_refs:vec![],rejections:vec![],retry_after_ms:None}).unwrap())
        }
    }));
    // Preparing the expected material also schedules the next durable attempt.
    // Let that real deadline elapse before asking the worker to select it.
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    assert_eq!(
        coland_http::state::deliver_pending_applet_completions(&fixture.state)
            .await
            .unwrap(),
        0
    );
    let first = tokio::time::timeout(std::time::Duration::from_secs(5), receive.recv())
        .await
        .unwrap_or_else(|_| {
            panic!(
                "first delivery did not reach the authenticated receiver; attempts={}",
                attempts.load(Ordering::SeqCst)
            )
        })
        .expect("delivery receiver remains open");
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    let retained = fixture
        .state
        .test_persistence()
        .applets()
        .pending_authoring_completions(16)
        .await
        .unwrap();
    assert_eq!(
        retained.len(),
        1,
        "HTTP failure retains the accepted creation task"
    );
    assert_eq!(
        arkret_canonical::canonical_json_bytes(&retained[0].context).unwrap(),
        arkret_canonical::canonical_json_bytes(&expected.context).unwrap()
    );
    assert_eq!(retained[0].request_digest, pending[0].request_digest);
    assert_eq!(
        coland_http::state::deliver_pending_applet_completions(&fixture.state)
            .await
            .unwrap(),
        1
    );
    let second = tokio::time::timeout(std::time::Duration::from_secs(5), receive.recv())
        .await
        .unwrap_or_else(|_| {
            panic!(
                "retry did not reach the authenticated receiver; attempts={}",
                attempts.load(Ordering::SeqCst)
            )
        })
        .expect("delivery receiver remains open");
    assert_eq!(
        first.0, second.0,
        "retry sends the immutable accepted context"
    );
    assert_ne!(
        first.1, second.1,
        "retry uses a fresh per-delivery HTTP signature"
    );
    assert_eq!(attempts.load(Ordering::SeqCst), 2);
    assert!(
        fixture
            .state
            .test_persistence()
            .applets()
            .pending_authoring_completions(16)
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        coland_http::state::deliver_pending_applet_completions(&fixture.state)
            .await
            .unwrap(),
        0,
        "acknowledged completion is not redelivered"
    );
}

#[tokio::test]
async fn expired_completion_refresh_and_old_key_ack_preserve_one_original() {
    let database = coland_storage_postgres::test_database::TestDatabase::lease().await;
    let fixture = Box::pin(applet_authoring::realm_creation_completion_fixture(
        database.pool(),
    ))
    .await;
    let pending = fixture
        .state
        .test_persistence()
        .applets()
        .pending_authoring_completions(16)
        .await
        .unwrap();
    let method = fixture
        .state
        .service_verification_method("notary-key")
        .unwrap();
    let first = applet_authoring::completion_application(&fixture.state)
        .prepare_applet_authoring_completion(
            &pending[0],
            &fixture.state.service_core_id(),
            &method,
            fixture.state.notary_signing_key().as_ref(),
        )
        .await
        .unwrap();
    let expires = first.context.as_ref().unwrap().material.expires_at;
    tokio::time::sleep(
        (expires - chrono::Utc::now()).to_std().unwrap_or_default()
            + std::time::Duration::from_millis(25),
    )
    .await;
    let refreshed = applet_authoring::completion_application(&fixture.state)
        .prepare_applet_authoring_completion(
            &first,
            &fixture.state.service_core_id(),
            &method,
            fixture.state.notary_signing_key().as_ref(),
        )
        .await
        .unwrap();
    assert_ne!(
        first.idempotency_key, refreshed.idempotency_key,
        "new short-lived material has its own delivery identity"
    );
    assert_eq!(refreshed.creation_ref, first.creation_ref);
    assert_eq!(refreshed.actor_id, first.actor_id);
    assert_eq!(refreshed.request_digest, first.request_digest);
    assert_eq!(
        serde_json::to_value(&refreshed.context.as_ref().unwrap().material.material).unwrap(),
        serde_json::to_value(&first.context.as_ref().unwrap().material.material).unwrap(),
        "refresh never replaces the accepted Event/Commit/fact"
    );
    let race = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        tokio::join!(
            async {
                applet_authoring::completion_application(&fixture.state)
                    .prepare_applet_authoring_completion(
                        &refreshed,
                        &fixture.state.service_core_id(),
                        &method,
                        fixture.state.notary_signing_key().as_ref(),
                    )
                    .await
            },
            async {
                fixture
                    .state
                    .test_persistence()
                    .applets()
                    .acknowledge_authoring_completion(
                        &first.applet_id,
                        &first.request_digest,
                        &first.idempotency_key,
                        chrono::Utc::now(),
                    )
                    .await
            }
        )
    })
    .await
    .expect("independent refresh and ACK connections must not deadlock");
    let current = race.0.unwrap();
    assert_eq!(current.idempotency_key, refreshed.idempotency_key);
    let old_ack = race.1.unwrap_err();
    assert_eq!(
        old_ack.conflict_code(),
        Some(coland_storage::ConflictCode::FailedPrecondition)
    );
    fixture
        .state
        .test_persistence()
        .applets()
        .acknowledge_authoring_completion(
            &current.applet_id,
            &current.request_digest,
            &current.idempotency_key,
            chrono::Utc::now(),
        )
        .await
        .unwrap();
    assert!(
        fixture
            .state
            .test_persistence()
            .applets()
            .pending_authoring_completions(16)
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn failing_completion_prefix_does_not_starve_a_later_accepted_creation() {
    let database = coland_storage_postgres::test_database::TestDatabase::lease().await;
    let fixture = Box::pin(applet_authoring::realm_creation_completion_fixtures(
        database.pool(),
        17,
    ))
    .await;
    let originals = fixture
        .state
        .test_persistence()
        .applets()
        .pending_authoring_completions(128)
        .await
        .unwrap();
    assert_eq!(originals.len(), 17);
    let healthy = originals[16].creation_ref.event_id.clone();
    let source = fixture.state.service_core_id();
    let destination = fixture.package.service_id.clone();
    let endpoint = fixture.package.base_url.clone();
    let key = fixture.state.notary_signing_key().verifying_key();
    let seen = Arc::new(std::sync::Mutex::new(std::collections::BTreeMap::<
        String,
        usize,
    >::new()));
    let delivered = seen.clone();
    let healthy_event = healthy.clone();
    fixture.set_delivery_handler(Arc::new(move |raw| {
        let end=raw.windows(4).position(|bytes|bytes==b"\r\n\r\n").unwrap();
        let headers=std::str::from_utf8(&raw[..end]).unwrap().lines().skip(1)
            .map(|line|line.split_once(':').unwrap()).map(|(name,value)|(name.to_owned(),value.trim().to_owned())).collect::<Vec<_>>();
        let header=|name:&str|headers.iter().find(|(field,_)|field.eq_ignore_ascii_case(name)).unwrap().1.as_str();
        assert_eq!(header("Source-Service-ID"),source.as_str());
        assert_eq!(header("Destination-Service-ID"),destination.as_str());
        assert_eq!(header("Arkret-Operation"),arkret_wire::ServiceOperationId::EDGE_APPLET_COMMAND_TRANSACTION_V1);
        assert!(!headers.iter().any(|(name,_)|name.eq_ignore_ascii_case("authorization")));
        let target=format!("{}/_arkret/edge/applet/transactions",endpoint.trim_end_matches('/'));
        let url=url::Url::parse(&target).unwrap();
        let policy=SignatureVerificationPolicy::for_scenario(HttpSignatureScenario::ServiceToServiceV1,&["content-digest","idempotency-key"]).unwrap();
        verify_signed_http_message("POST",&target,&url[url::Position::BeforeHost..url::Position::AfterPort],
            "/_arkret/edge/applet/transactions",headers.iter().map(|(name,value)|(name.as_str(),value.as_str())),
            &raw[end+4..],&key,&policy,chrono::Utc::now().timestamp()).unwrap();
        let body:AppletTransactionRequestBody=serde_json::from_slice(&raw[end+4..]).unwrap();
        body.validate().unwrap();
        let AppletTransactionRequestBody::Authoring(body)=body else { panic!("original creation material only") };
        assert_eq!(body.source_id,source);
        assert_eq!(body.authoring_context.material.requester_actor_id,arkret_wire::ActorId::service(destination.clone()));
        arkret_signatures::detached_object::verify_detached_object_signature(
            &body.authoring_context.material.signature,
            &arkret_canonical::unsigned_value(&body.authoring_context.material,&["signature"]).unwrap(),
            arkret_wire::DetachedSignatureContext::RealmActorMaterial,
            &arkret_signatures::PublicKeyMaterial::Ed25519Raw { bytes:key.to_bytes().to_vec() },
        ).unwrap();
        let arkret_models_integration::RealmActorMaterial::Event {event,commit,..}=&body.authoring_context.material.material else { panic!("real accepted creation result") };
        assert_eq!(commit.event_ref,event.event_id);
        assert_eq!(event.kind,arkret_wire::EventKind::RealmActorCreate);
        *delivered.lock().unwrap().entry(event.event_id.to_string()).or_default()+=1;
        if event.event_id==healthy_event {
            (StatusCode::OK,serde_json::to_value(AppletTransactionResponseBody::Accepted {committed_event_refs:vec![],rejections:vec![],retry_after_ms:None}).unwrap())
        } else {
            (StatusCode::SERVICE_UNAVAILABLE,serde_json::json!({"type":"https://arkret.org/problems/service_unavailable","title":"Service unavailable","status":503}))
        }
    }));
    assert_eq!(
        coland_http::state::deliver_pending_applet_completions(&fixture.state)
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        seen.lock().unwrap().len(),
        16,
        "the first bounded pass reaches its genuine 16 failing deliveries"
    );
    assert!(!seen.lock().unwrap().contains_key(healthy.as_str()));
    assert_eq!(
        coland_http::state::deliver_pending_applet_completions(&fixture.state)
            .await
            .unwrap(),
        1,
        "the unsent seventeenth creation must get a turn despite the permanent failure prefix"
    );
    assert_eq!(seen.lock().unwrap().get(healthy.as_str()), Some(&1));
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    let remaining = fixture
        .state
        .test_persistence()
        .applets()
        .pending_authoring_completions(128)
        .await
        .unwrap();
    assert_eq!(
        remaining.len(),
        16,
        "retry scheduling must retain all failures instead of discarding them"
    );
    for task in remaining {
        assert!(
            originals
                .iter()
                .any(|original| original.creation_ref == task.creation_ref
                    && original.request_digest == task.request_digest)
        );
        assert_ne!(task.creation_ref.event_id, healthy);
    }
}
