//! Independent receipt delivery to historical holders through production TLS.
//! Partial outcomes exercise the notification rail without claiming byte erasure.
use std::sync::atomic::{AtomicU8, Ordering};

use arkret_models_collaboration::events_payloads::event_wire::{
    ErasureTrigger, VerificationStub, VerificationStubScope, VerificationStubSubject,
};
use arkret_models_collaboration::governance::erasure::*;
use salvo::prelude::*;

use super::*;
use crate::routing::federation::{erasure_receipts, outbox};

pub(super) struct ReceiptAckFault(pub(super) Arc<AtomicU8>);

#[salvo::handler]
impl ReceiptAckFault {
    async fn handle(
        &self,
        req: &mut Request,
        depot: &mut Depot,
        res: &mut Response,
        ctrl: &mut FlowCtrl,
    ) {
        ctrl.call_next(req, depot, res).await;
        let mode = self.0.as_ref().load(Ordering::SeqCst);
        if mode == 0
            || req.uri().path() != outbox::ERASURE_RECEIPT_ENDPOINT
            || res.status_code.unwrap_or(StatusCode::OK) != StatusCode::OK
        {
            return;
        }
        let original = res.take_body();
        let value = if mode == 1 {
            serde_json::json!({"status":"accepted"})
        } else {
            let salvo::http::ResBody::Once(bytes) = original else {
                panic!("receipt response must be buffered JSON");
            };
            let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            value["proof"]["jws"] = serde_json::json!("tampered receiver signature");
            value
        };
        res.render(Json(value));
    }
}

async fn signed_request(
    source: &AppState,
    receiver: &AppState,
    method: &str,
    path: &str,
    body: Option<&[u8]>,
    key: &str,
) -> (u16, Vec<u8>) {
    let url = format!(
        "{}{}",
        receiver.config().public_base_url.trim_end_matches('/'),
        path
    );
    let mut headers = reqwest::header::HeaderMap::new();
    for (name, value) in [
        ("content-type", "application/json".to_owned()),
        ("idempotency-key", key.to_owned()),
        (
            "content-digest",
            outbox::content_digest_header_value(body.unwrap_or_default()),
        ),
        ("source-service-id", source.service_id().to_owned()),
        ("destination-service-id", receiver.service_id().to_owned()),
        (
            "source-trust-domain",
            source.config().trust_domain.to_string(),
        ),
        (
            "destination-trust-domain",
            receiver.config().trust_domain.to_string(),
        ),
    ] {
        headers.insert(
            reqwest::header::HeaderName::from_bytes(name.as_bytes()).unwrap(),
            value.parse().unwrap(),
        );
    }
    let headers = outbox::rfc9421_sign(source, headers, method, &url);
    let (url, client) = crate::security::validate_http_url_for_egress_with_pinned_client(
        &url,
        "receipt rail test",
        source.config().development_mode,
        std::time::Duration::from_secs(20),
    )
    .unwrap();
    let response = client
        .request(reqwest::Method::from_bytes(method.as_bytes()).unwrap(), url)
        .headers(headers)
        .body(body.unwrap_or_default().to_vec())
        .send()
        .await
        .unwrap();
    let status = response.status().as_u16();
    (status, response.bytes().await.unwrap().to_vec())
}

async fn snapshot(pool: &PgPool) -> serde_json::Value {
    #[derive(diesel::QueryableByName)]
    struct Row {
        #[diesel(sql_type = diesel::sql_types::Jsonb)]
        value: serde_json::Value,
    }
    let mut rows = terminal_persistent_rows(pool).await;
    let mut conn = pool.get().await.unwrap();
    let idempotency: Row = diesel::sql_query("SELECT COALESCE(jsonb_agg(to_jsonb(r) ORDER BY actor_key,operation_id,idempotency_key),'[]'::jsonb) AS value FROM idempotency_keys r")
        .get_result(&mut *conn).await.unwrap();
    rows["idempotency_keys"] = idempotency.value;
    rows
}

async fn sign_package(state: &AppState, package: &mut ErasureReceiptPackage) {
    package.receipt.retained_stub_digest =
        arkret_wire::Hash::new(arkret_canonical::canonical_sha256(&package.retained_stub).unwrap())
            .unwrap();
    package.receipt.proofs.clear();
    let (_, method) = state.current_service_receipt_binding().await.unwrap();
    package.receipt.proofs.push(ErasureReceiptProof {
        verification_method: method,
        payload_digest: package.receipt.canonical_payload_digest().unwrap(),
        signature: arkret_signatures::jws::sign_jws_ed25519(
            &package.receipt.canonical_proof_input().unwrap(),
            state.notary_signing_key().as_ref(),
        )
        .unwrap(),
        extra: Default::default(),
    });
    package.validate_bindings().unwrap();
}

async fn package(
    source: &AppState,
    target: &coland_storage::AuthorityCommitTransaction,
    redaction: &coland_storage::AuthorityCommitTransaction,
) -> ErasureReceiptPackage {
    let id = format!("ak:receipt:{}", uuid::Uuid::now_v7());
    let at = arkret_canonical::normalize_timestamp_canonical(Utc::now());
    let trigger = ErasureTrigger::Event {
        event_id: redaction.event.event_id.clone(),
    };
    let subject = ErasureSubject {
        kind: ErasureSubjectKind::Event,
        subject_ref: target.event.event_id.to_string(),
    };
    let scope = ErasureScope {
        storage_boundary: ErasureStorageBoundary::ServiceDefined,
        realm_id: Some(target.event.realm_id.clone()),
        target_refs: vec![subject.subject_ref.clone()],
        retention_policy_id: None,
        service_scope: Some("independent receipt rail verification".into()),
    };
    let stub = VerificationStub {
        stub_schema: arkret_wire::SchemaId::ERASURE_VERIFICATION_STUB_V1.into(),
        trigger: trigger.clone(),
        subject: VerificationStubSubject {
            kind: "event".into(),
            subject_ref: subject.subject_ref.clone(),
        },
        scope: VerificationStubScope {
            storage_boundary: "service_defined".into(),
            realm_id: scope.realm_id.clone(),
            target_refs: Some(scope.target_refs.clone()),
            retention_policy_id: None,
            service_scope: scope.service_scope.clone(),
        },
        event_digest: None,
        retained_digests: None,
        commit_ref: None,
        redaction_authorization_ref: Some(redaction.event.event_id.to_string()),
        legal_hold_ref: None,
        receipt_id: id.clone(),
        completed_at: at,
    };
    let mut package = ErasureReceiptPackage {
        retained_stub: stub,
        receipt: ErasureReceipt {
            receipt_id: id,
            trigger,
            schema: ErasureReceipt::SCHEMA.into(),
            issuer_id: source.service_core_id(),
            subject,
            scope,
            outcome: ErasureAttemptOutcome::PartiallyCompleted,
            erased_classes: Vec::new(),
            retained_stub_digest: arkret_wire::Hash::new(arkret_canonical::sha256_digest(
                b"replaced before signing",
            ))
            .unwrap(),
            retained_stub: None,
            legal_hold_ref: None,
            completed_at: at,
            issued_at: Some(at),
            proofs: Vec::new(),
            fanout_status: Some(ErasureFanoutStatus::Pending),
            peer_receipts: Vec::new(),
        },
    };
    sign_package(source, &mut package).await;
    package
}

async fn publish_audit(
    source: &LiveStation,
    previous: &coland_storage::AuthorityCommitTransaction,
    package: &ErasureReceiptPackage,
) -> coland_storage::EventCommitRequest {
    let at = previous.commit.committed_at + Duration::seconds(1);
    let mut event = historical_human::ordinary_realm::event_for_actor(
        EventKind::AuditErasureReceipt,
        arkret_wire::ScopeRef::Realm {
            realm_id: previous.event.realm_id.clone(),
        },
        ActorId::service(source.state.service_core_id()),
        serde_json::to_value(&package.receipt).unwrap(),
        at,
    );
    event.producer_proof = None;
    let mut authored = arkret_wire::AuthoredEvent::finalize_with_digest_suite(
        event,
        arkret_canonical::DigestSuite::Sha256,
    )
    .unwrap();
    let (_, method) = source
        .state
        .current_service_receipt_binding()
        .await
        .unwrap();
    let signer = arkret_signatures::Ed25519DetachedJwsSigner::new(
        source.state.notary_signing_key().as_ref().clone(),
        method.as_str(),
    );
    arkret_signatures::sign_event(
        &mut authored,
        &signer,
        arkret_signatures::SignEventOptions::new().with_created_at(at),
    )
    .unwrap();
    let event = authored.into_event();
    arkret_schema::validate_event_for_submit(&event).unwrap();
    let mut request = historical_human::ordinary_realm::request_for_event(previous, event, at);
    seal_service_commit(&mut request.authority_commit.commit, &source.state);
    request.realm_fanout_source = Some(EventAdmissionSubmission::new(
        request.authority_commit.event.clone(),
    ));
    Box::pin(PgEventCommitUnitOfWork::new(source.pool.clone()).commit_event(request.clone()))
        .await
        .unwrap();
    erasure_receipts::persist_issued_package(
        &source.state,
        package,
        &source.state.service_core_id(),
    )
    .await
    .unwrap();
    // Isolate the receipt rail; retained Audit replication keeps its own obligation.
    execute(&source.pool, "UPDATE federation_outbox SET next_attempt_at=next_attempt_at+3600 WHERE endpoint='/_arkret/peer/events' AND state IN ('pending','pending_route')").await;
    request
}

async fn receipt_delivery(
    source: &LiveStation,
    id: &str,
) -> coland_storage::FederationOutboxRecord {
    let rows = source
        .state
        .persistence()
        .erasure_receipt_deliveries(id)
        .await
        .unwrap();
    assert_eq!(
        rows.len(),
        1,
        "one historical destination, no arbitrary configured peer"
    );
    rows.into_iter().next().unwrap()
}

async fn due(source: &LiveStation, dispatcher: &outbox::FederationDispatcher, id: &str) {
    let row = receipt_delivery(source, id).await;
    execute(
        &source.pool,
        &format!(
            "UPDATE federation_outbox SET next_attempt_at=0 WHERE id='{}'",
            row.id
        ),
    )
    .await;
    Box::pin(dispatcher.run_one_pass()).await.unwrap();
}

#[tokio::test]
async fn departed_leave_holder_receives_independent_signed_erasure_receipt() {
    Box::pin(run(Some("leave"))).await;
}
#[tokio::test]
async fn departed_ban_holder_receives_independent_signed_erasure_receipt() {
    Box::pin(run(Some("ban"))).await;
}
#[tokio::test]
async fn terminal_holder_receives_independent_signed_erasure_receipt() {
    Box::pin(run(None)).await;
}

async fn run(departure: Option<&str>) {
    let source = LiveStation::start().await;
    let fault = Arc::new(AtomicU8::new(1));
    let receiver = LiveStation::start_with_receipt_fault(Some(fault.clone())).await;
    let outsider = LiveStation::start().await;
    install_verified_route(&source.state, &receiver.state).await;
    install_verified_route(&receiver.state, &source.state).await;
    let owner = Box::pin(admitted_owner(&source, &receiver)).await;
    let member = Box::pin(historical_human::HumanFixture::new(
        &receiver.pool,
        receiver.state.service_did(),
    ))
    .await;
    let actor = ActorId::account(member.pcr.history.account.clone());
    let mut join = Box::pin(foreign_request(
        &receiver.state,
        &member,
        &owner,
        owner.unit.transactions.last().unwrap(),
        EventKind::MemberState,
        serde_json::json!({"realm_id":owner.unit.transactions[0].event.realm_id,
            "member_id":actor,"membership":"join","reason":"independent erasure holder"}),
    ))
    .await;
    seal_service_commit(&mut join.authority_commit.commit, &source.state);
    let uow = PgEventCommitUnitOfWork::new(source.pool.clone());
    Box::pin(uow.commit_event(join.clone())).await.unwrap();
    Box::pin(install_opening_anchor(&source, &receiver, &member, &join)).await;
    let dispatcher = outbox::FederationDispatcher::new(source.state.clone());
    Box::pin(dispatch_due(
        &dispatcher,
        &source,
        &join.authority_commit.commit.commit_id,
    ))
    .await;
    let strand = owner_candidate(
        &owner,
        &source.state,
        &join.authority_commit,
        EventKind::StrandCreate,
        serde_json::json!({"object":{"schema":"ak.schema.strand.v1","realm_id":join.authority_commit.event.realm_id,
            "tracks":{"discussion":{"is_primary":true,"profile":"discussion"}},"metadata":{"title":"Receipt holder history"},
            "state":"active","created_by":owner.unit.transactions[0].event.actor_id,"created_at":join.authority_commit.commit.committed_at}}),
    );
    Box::pin(uow.commit_event(strand.clone())).await.unwrap();
    Box::pin(dispatch_due(
        &dispatcher,
        &source,
        &strand.authority_commit.commit.commit_id,
    ))
    .await;
    let strand_id = arkret_wire::StrandId::from_event_id(&strand.authority_commit.event.event_id);
    let message = owner_candidate(
        &owner,
        &source.state,
        &strand.authority_commit,
        EventKind::MessageCreate,
        historical_human::ordinary_realm::message_payload(
            &strand_id,
            "receipt rail retained holder sample",
        ),
    );
    Box::pin(uow.commit_event(message.clone())).await.unwrap();
    Box::pin(dispatch_due(
        &dispatcher,
        &source,
        &message.authority_commit.commit.commit_id,
    ))
    .await;
    let redaction = owner_candidate(
        &owner,
        &source.state,
        &message.authority_commit,
        EventKind::MessageRedact,
        serde_json::json!({"message_id":arkret_wire::MessageId::from_event_id(&message.authority_commit.event.event_id),"reason":"independent erasure authorization"}),
    );
    Box::pin(uow.commit_event(redaction.clone())).await.unwrap();
    Box::pin(dispatch_due(
        &dispatcher,
        &source,
        &redaction.authority_commit.commit.commit_id,
    ))
    .await;
    let mut previous = redaction.authority_commit.clone();
    if let Some(membership) = departure {
        let terminating = owner_candidate(
            &owner,
            &source.state,
            &previous,
            EventKind::MemberState,
            serde_json::json!({"realm_id":previous.event.realm_id,"member_id":actor,"membership":membership,"reason":"last hosted holder leaves"}),
        );
        Box::pin(uow.commit_event(terminating.clone()))
            .await
            .unwrap();
        Box::pin(dispatch_due(
            &dispatcher,
            &source,
            &terminating.authority_commit.commit.commit_id,
        ))
        .await;
        previous = terminating.authority_commit;
        assert_eq!(
            receiver
                .state
                .authority_commits()
                .replica_stream_has_hosted_member(
                    &previous.commit.stream_ref,
                    &receiver.state.service_core_id()
                )
                .await
                .unwrap(),
            Some(false)
        );
    }
    let terminal = owner_candidate(
        &owner,
        &source.state,
        &previous,
        EventKind::RealmTombstone,
        arkret_models_collaboration::governance::realm_lifecycle::RealmTombstonePayload::new(
            "ak:realm:ASR8x2N1qyfyy6I-eob3l-FNhx4FPBTyMJrIfifkksgW"
                .parse()
                .unwrap(),
            "independent receipt follows lifecycle",
        )
        .to_value()
        .unwrap(),
    );
    Box::pin(uow.commit_event(terminal.clone())).await.unwrap();
    if departure.is_some() {
        assert!(
            source
                .state
                .federation()
                .deliveries_for_event(terminal.authority_commit.event.event_id.as_str())
                .await
                .unwrap()
                .is_empty()
        );
        assert!(
            receiver
                .state
                .authority_commits()
                .committed_event(&terminal.authority_commit.event.event_id)
                .await
                .unwrap()
                .is_none()
        );
    } else {
        Box::pin(dispatch_due(
            &dispatcher,
            &source,
            &terminal.authority_commit.commit.commit_id,
        ))
        .await;
    }
    // Peer replication schedules a background scan of the governing stream.
    // Settle it before publishing the Audit: delaying its outbox alone cannot
    // stop that scan from pulling a new tail into the receipt-only snapshot.
    crate::state::replica_anchor::wait_for_converge_stream(
        &receiver.state,
        &terminal.authority_commit.commit.stream_ref,
    )
    .await;
    let package = package(
        &source.state,
        &message.authority_commit,
        &redaction.authority_commit,
    )
    .await;
    let audit = Box::pin(publish_audit(&source, &terminal.authority_commit, &package)).await;
    assert_eq!(
        source
            .state
            .authority_commits()
            .committed_event(&audit.authority_commit.event.event_id)
            .await
            .unwrap()
            .unwrap()
            .event,
        audit.authority_commit.event
    );
    crate::routing::identity::account::lifecycle::fanout_erasure_receipt(
        &source.state,
        &package,
        None,
    )
    .await
    .unwrap();
    let frozen = receipt_delivery(&source, &package.receipt.receipt_id).await;
    let holders = source
        .state
        .persistence()
        .historical_content_holders_for_actor(&ActorId::account(owner.pcr.history.account.clone()))
        .await
        .unwrap();
    assert_eq!(holders, vec![receiver.state.service_core_id()]);
    let same_principal_elsewhere = arkret_wire::AccountId::new(
        owner.pcr.history.account.principal_id.clone(),
        outsider.state.service_core_id(),
    );
    assert!(
        source
            .state
            .persistence()
            .historical_content_holders_for_actor(&ActorId::account(same_principal_elsewhere))
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(frozen.peer_id, receiver.state.service_core_id());
    assert!(frozen.realm_fanout.is_none());
    assert_eq!(
        frozen.payload_json,
        arkret_canonical::canonical_json_string(&package.clone()).unwrap()
    );
    let before = terminal_persistent_rows(&receiver.pool).await;
    let before_receipt = snapshot(&receiver.pool).await;
    execute(&receiver.pool, &format!("CREATE FUNCTION fail_receipt_response() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.idempotency_key='{}' THEN RAISE EXCEPTION 'test-owned receipt response fault'; END IF; RETURN NEW; END $$", frozen.idempotency_key)).await;
    execute(&receiver.pool, "CREATE TRIGGER fail_receipt_response BEFORE INSERT ON idempotency_keys FOR EACH ROW EXECUTE FUNCTION fail_receipt_response()").await;
    Box::pin(due(&source, &dispatcher, &package.receipt.receipt_id)).await;
    let pending = receipt_delivery(&source, &package.receipt.receipt_id).await;
    assert_eq!(
        pending.state,
        coland_storage::FederationOutboxState::Pending
    );
    assert_eq!(pending.last_http_status, Some(500));
    assert_eq!(
        snapshot(&receiver.pool).await,
        before_receipt,
        "lookup and response must roll back together"
    );
    execute(
        &receiver.pool,
        "DROP TRIGGER fail_receipt_response ON idempotency_keys",
    )
    .await;
    execute(&receiver.pool, "DROP FUNCTION fail_receipt_response()").await;
    fault.store(0, Ordering::SeqCst);
    // Competing unconfirmed sends must return the one actually landed response.
    let (first, second) = tokio::join!(
        signed_request(
            &source.state,
            &receiver.state,
            "POST",
            outbox::ERASURE_RECEIPT_ENDPOINT,
            Some(frozen.payload_json.as_bytes()),
            &frozen.idempotency_key
        ),
        signed_request(
            &source.state,
            &receiver.state,
            "POST",
            outbox::ERASURE_RECEIPT_ENDPOINT,
            Some(frozen.payload_json.as_bytes()),
            &frozen.idempotency_key
        )
    );
    assert_eq!(first.0, 200);
    assert_eq!(
        second, first,
        "concurrent first acknowledgement must be byte-identical"
    );
    for mode in [1, 2] {
        fault.store(mode, Ordering::SeqCst);
        Box::pin(due(&source, &dispatcher, &package.receipt.receipt_id)).await;
        let pending = receipt_delivery(&source, &package.receipt.receipt_id).await;
        assert_eq!(
            pending.state,
            coland_storage::FederationOutboxState::Pending
        );
        assert_eq!(pending.last_http_status, Some(200));
        assert!(
            pending
                .last_response_excerpt
                .as_ref()
                .unwrap()
                .contains("erasure_acknowledgement_invalid")
        );
        assert_eq!(pending.semantic_attempts, 0);
        assert_eq!(pending.idempotency_key, frozen.idempotency_key);
        assert_eq!(pending.payload_json, frozen.payload_json);
    }
    fault.store(0, Ordering::SeqCst);
    Box::pin(due(&source, &dispatcher, &package.receipt.receipt_id)).await;
    let delivered = receipt_delivery(&source, &package.receipt.receipt_id).await;
    assert_eq!(
        delivered.state,
        coland_storage::FederationOutboxState::Delivered
    );
    assert_eq!(delivered.attempts, 4);
    assert_eq!(delivered.idempotency_key, frozen.idempotency_key);
    assert_eq!(delivered.payload_json, frozen.payload_json);
    assert_eq!(
        terminal_persistent_rows(&receiver.pool).await,
        before,
        "receipt cannot create Realm acceptance or live effects"
    );
    let ack_text = delivered.last_response_excerpt.as_ref().unwrap();
    let ack = erasure_receipts::verify_acceptance(
        &source.state,
        &package,
        &receiver.state.service_core_id(),
        ack_text,
    )
    .await
    .unwrap();
    let accepted = snapshot(&receiver.pool).await;
    for _ in 0..2 {
        let (status, bytes) = signed_request(
            &source.state,
            &receiver.state,
            "POST",
            outbox::ERASURE_RECEIPT_ENDPOINT,
            Some(frozen.payload_json.as_bytes()),
            &frozen.idempotency_key,
        )
        .await;
        assert_eq!(status, 200);
        assert_eq!(std::str::from_utf8(&bytes).unwrap(), ack_text);
        let replay: ErasureReceiptSubmitResponseBody = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            replay,
            ErasureReceiptSubmitResponseBody::Accepted(ack.clone())
        );
        assert_eq!(snapshot(&receiver.pool).await, accepted);
    }
    let request = package.clone();
    let mut different = package.clone();
    different.receipt.scope.service_scope = Some("changed receipt boundary".into());
    different.retained_stub.scope.service_scope = different.receipt.scope.service_scope.clone();
    sign_package(&source.state, &mut different).await;
    for key in [&frozen.idempotency_key, "another-key-same-receipt"] {
        let bytes = arkret_canonical::canonical_json_bytes(&different.clone()).unwrap();
        let (status, answer) = signed_request(
            &source.state,
            &receiver.state,
            "POST",
            outbox::ERASURE_RECEIPT_ENDPOINT,
            Some(&bytes),
            key,
        )
        .await;
        assert_eq!(status, 409, "{}", String::from_utf8_lossy(&answer));
        assert_eq!(snapshot(&receiver.pool).await, accepted);
    }
    let mut invalids = Vec::new();
    let mut stub = serde_json::to_value(&request).unwrap();
    stub["retained_stub"]["receipt_id"] =
        serde_json::json!(format!("ak:receipt:{}", uuid::Uuid::now_v7()));
    invalids.push((stub, 400));
    let mut proof = serde_json::to_value(&request).unwrap();
    proof["receipt"]["proofs"][0]["signature"] = serde_json::json!("forged");
    invalids.push((proof, 400));
    let mut extra = serde_json::to_value(&request).unwrap();
    extra["receipt"]["undocumented"] = serde_json::json!(true);
    invalids.push((extra, 422));
    for (index, (invalid, expected_status)) in invalids.into_iter().enumerate() {
        let bytes = arkret_canonical::canonical_json_bytes(&invalid).unwrap();
        let (status, answer) = signed_request(
            &source.state,
            &receiver.state,
            "POST",
            outbox::ERASURE_RECEIPT_ENDPOINT,
            Some(&bytes),
            &format!("invalid-receipt-{index}"),
        )
        .await;
        assert_eq!(
            status,
            expected_status,
            "{}",
            String::from_utf8_lossy(&answer)
        );
        assert_eq!(snapshot(&receiver.pool).await, accepted);
    }
    let (status, _) = signed_request(
        &receiver.state,
        &receiver.state,
        "POST",
        outbox::ERASURE_RECEIPT_ENDPOINT,
        Some(frozen.payload_json.as_bytes()),
        "wrong-source-issuer",
    )
    .await;
    assert_eq!(status, 403);
    assert_eq!(snapshot(&receiver.pool).await, accepted);
    let path = format!(
        "{}/{}",
        outbox::ERASURE_RECEIPT_ENDPOINT,
        package.receipt.receipt_id
    );
    let (status, bytes) = signed_request(
        &source.state,
        &receiver.state,
        "GET",
        &path,
        None,
        "get-package",
    )
    .await;
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&bytes));
    assert_eq!(
        serde_json::from_slice::<ErasureReceiptPackage>(&bytes).unwrap(),
        package
    );
    for path in [
        &path,
        &format!(
            "{}/ak:receipt:{}",
            outbox::ERASURE_RECEIPT_ENDPOINT,
            uuid::Uuid::now_v7()
        ),
    ] {
        let (status, answer) = signed_request(
            &outsider.state,
            &receiver.state,
            "GET",
            path,
            None,
            "hidden-package",
        )
        .await;
        assert_eq!(status, 404, "{}", String::from_utf8_lossy(&answer));
    }
    assert_eq!(snapshot(&receiver.pool).await, accepted);
    let (status, peers) =
        erasure_receipts::fanout_progress(&source.state, &package.receipt.receipt_id)
            .await
            .unwrap();
    assert_eq!(status, ErasureFanoutStatus::Pending);
    assert_eq!(
        peers[0].status,
        ErasurePeerStatus::Pending,
        "acknowledgement is not physical-erasure feedback"
    );
    let mut feedback = package.clone();
    feedback.receipt.receipt_id = format!("ak:receipt:{}", uuid::Uuid::now_v7());
    feedback.retained_stub.receipt_id = feedback.receipt.receipt_id.clone();
    feedback.receipt.issuer_id = receiver.state.service_core_id();
    feedback.receipt.completed_at += Duration::milliseconds(1);
    feedback.receipt.issued_at = Some(feedback.receipt.completed_at);
    feedback.retained_stub.completed_at = feedback.receipt.completed_at;
    sign_package(&receiver.state, &mut feedback).await;
    let body = arkret_canonical::canonical_json_string(&feedback.clone()).unwrap();
    let source_before_feedback = terminal_persistent_rows(&source.pool).await;
    outbox::enqueue_outbound(
        &receiver.state,
        &source.state.config().public_base_url,
        source.state.service_id(),
        outbox::ERASURE_RECEIPT_ENDPOINT,
        &format!("ak:outbox:erasure-receipt:{}", feedback.receipt.receipt_id),
        &body,
    )
    .await
    .unwrap();
    let reply_dispatcher = outbox::FederationDispatcher::new(receiver.state.clone());
    Box::pin(reply_dispatcher.run_one_pass()).await.unwrap();
    let (status, peers) =
        erasure_receipts::fanout_progress(&source.state, &package.receipt.receipt_id)
            .await
            .unwrap();
    assert_eq!(
        status,
        ErasureFanoutStatus::Complete,
        "all peers returned independent feedback"
    );
    assert_eq!(
        peers[0].status,
        ErasurePeerStatus::Failed,
        "partial feedback cannot pretend deletion succeeded"
    );
    assert_eq!(
        peers[0].receipt_id.as_ref(),
        Some(&feedback.receipt.receipt_id)
    );
    let reply = receipt_delivery(&receiver, &feedback.receipt.receipt_id).await;
    assert_eq!(
        reply.state,
        coland_storage::FederationOutboxState::Delivered
    );
    assert_eq!(reply.peer_id, source.state.service_core_id());
    assert_eq!(reply.endpoint, outbox::ERASURE_RECEIPT_ENDPOINT);
    assert_eq!(reply.payload_json, body);
    assert_eq!(reply.attempts, 1);
    assert_eq!(reply.semantic_attempts, 0);
    assert!(reply.realm_fanout.is_none());
    erasure_receipts::verify_acceptance(
        &receiver.state,
        &feedback,
        &source.state.service_core_id(),
        reply.last_response_excerpt.as_ref().unwrap(),
    )
    .await
    .unwrap();
    let mut after_feedback = terminal_persistent_rows(&receiver.pool).await;
    let rows = after_feedback["federation_outbox"].as_array_mut().unwrap();
    assert_eq!(rows.iter().filter(|row| row["id"] == reply.id).count(), 1);
    rows.retain(|row| row["id"] != reply.id);
    assert_eq!(
        after_feedback, before,
        "only the explicit feedback intent may change"
    );
    assert_eq!(
        terminal_persistent_rows(&source.pool).await,
        source_before_feedback
    );

    let mut outstanding = package.clone();
    outstanding.receipt.receipt_id = format!("ak:receipt:{}", uuid::Uuid::now_v7());
    outstanding.retained_stub.receipt_id = outstanding.receipt.receipt_id.clone();
    outstanding.receipt.scope.service_scope =
        Some("separate unacknowledged receipt boundary".into());
    outstanding.retained_stub.scope.service_scope = outstanding.receipt.scope.service_scope.clone();
    sign_package(&source.state, &mut outstanding).await;
    Box::pin(publish_audit(
        &source,
        &audit.authority_commit,
        &outstanding,
    ))
    .await;
    crate::routing::identity::account::lifecycle::fanout_erasure_receipt(
        &source.state,
        &outstanding,
        None,
    )
    .await
    .unwrap();
    let pending = receipt_delivery(&source, &outstanding.receipt.receipt_id).await;
    execute(
        &source.pool,
        &format!(
            "UPDATE federation_outbox SET attempts={},next_attempt_at=0 WHERE id='{}'",
            outbox::MAX_ATTEMPTS,
            pending.id
        ),
    )
    .await;
    fault.store(1, Ordering::SeqCst);
    Box::pin(dispatcher.run_one_pass()).await.unwrap();
    let pending = receipt_delivery(&source, &outstanding.receipt.receipt_id).await;
    assert_eq!(
        pending.state,
        coland_storage::FederationOutboxState::Pending
    );
    assert_eq!(
        pending.attempts,
        outbox::MAX_ATTEMPTS + 1,
        "receipt retry lasts through its own propagation window"
    );
    assert_eq!(
        pending.payload_json,
        arkret_canonical::canonical_json_string(&outstanding.clone()).unwrap()
    );
    execute(
        &source.pool,
        &format!(
            "UPDATE federation_outbox SET created_at=created_at-{},next_attempt_at=0 WHERE id='{}'",
            outbox::ERASURE_PROPAGATION_WINDOW_SECS + 1,
            pending.id
        ),
    )
    .await;
    Box::pin(dispatcher.run_one_pass()).await.unwrap();
    let expired = receipt_delivery(&source, &outstanding.receipt.receipt_id).await;
    assert_eq!(
        expired.state,
        coland_storage::FederationOutboxState::DeadLettered
    );
    assert_eq!(
        expired.attempts, pending.attempts,
        "deadline closes without another socket attempt"
    );
    assert_eq!(
        expired.last_error_code.as_deref(),
        Some("erasure_propagation_timed_out")
    );
    let (status, peers) =
        erasure_receipts::fanout_progress(&source.state, &outstanding.receipt.receipt_id)
            .await
            .unwrap();
    assert_eq!(status, ErasureFanoutStatus::Incomplete);
    assert_eq!(peers[0].status, ErasurePeerStatus::TimedOut);
    eprintln!(
        "[erasure-rail] departure={departure:?} actual_tls_stations=3 source_audit_committed=1 historical_holder=1 atomic_response_lookup_rollback=1 concurrent_first_ack_identical=2 invalid_2xx_keeps_original_intent=2 signed_acknowledgement_verified=1 duplicate_zero_writes=2 conflicting_or_invalid_package_zero_writes=6 exact_lookup_and_hidden_404=1 no_realm_acceptance_effects=1 partial_feedback_failed=1 timeout_incomplete=1 no_physical_completion_claim=1"
    );
}
