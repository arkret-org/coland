//! Real PostgreSQL admission, production outbox dispatch and signed TCP HTTPS.
//! Only the already-authorized opening anchor is installed as a precondition.
//! The checked-in outbox CA is explicitly trusted; TLS verification stays enabled.
use arkret_models_collaboration::authority_commit::{
    CommittedEventSubmission, CommittedReplicationBranch, PeerAuthoritySubmitOutcome,
    PeerAuthoritySubmitRequest, PeerCommittedReplicationOutcomeRecord,
    PeerCommittedReplicationRequest,
};
use diesel_async::RunQueryDsl as _;
use salvo::conn::{Acceptor as _, Listener as _};

use super::realm_terminal_peer_tests::terminal_persistent_rows;
use super::*;

#[path = "realm_departure_fanout_tests.rs"]
mod departure_tests;
#[path = "erasure_receipt_live_tests.rs"]
mod erasure_receipt_tests;

struct LiveStation {
    state: AppState,
    pool: PgPool,
    _lease: Arc<dyn coland_storage::PersistenceStore>,
    server: tokio::task::JoinHandle<()>,
}

struct MissingRoute;
#[async_trait::async_trait]
impl ServiceRouteFetcher for MissingRoute {
    async fn fetch_current(
        &self,
        _: &DidCoreId,
        _: &str,
    ) -> coland_services::ServiceResult<Option<VerifiedRouteCandidate>> {
        Ok(None)
    }
}

struct TestTlsConfig(rustls::ServerConfig);
impl salvo::conn::IntoConfigStream<rustls::ServerConfig> for TestTlsConfig {
    type Stream = futures_util::stream::Once<std::future::Ready<rustls::ServerConfig>>;
    fn into_stream(self) -> Self::Stream {
        futures_util::stream::once(std::future::ready(self.0))
    }
}

impl Drop for LiveStation {
    fn drop(&mut self) {
        self.server.abort();
    }
}

impl LiveStation {
    async fn start() -> Self {
        Self::start_with_receipt_fault(None).await
    }

    async fn start_with_receipt_fault(fault: Option<Arc<std::sync::atomic::AtomicU8>>) -> Self {
        let tls = registered_tls_peer();
        let config = TestTlsConfig((*tls.tls).clone());
        drop(tls);
        let acceptor = salvo::conn::TcpListener::new("127.0.0.1:0")
            .rustls(config)
            .bind()
            .await;
        let url = format!(
            "https://{}/",
            acceptor.holdings()[0].local_addr.as_ipv4().unwrap()
        );
        let (state, pool, lease) = station_with_webvh_provider(url, true);
        let mut service = crate::service(state.clone());
        if let Some(fault) = fault {
            service = service.hoop(erasure_receipt_tests::ReceiptAckFault(fault));
        }
        let server = tokio::spawn(async move {
            salvo::Server::new(acceptor).serve(service).await;
        });
        Self {
            state,
            pool,
            _lease: lease,
            server,
        }
    }
}

async fn install_verified_route(sender: &AppState, recipient: &AppState) {
    // Pin actual native method-history evidence. Receipt and HTTP signatures
    // still resolve and verify the source through its live production server.
    let evidence =
        crate::routing::system::service_resolution::current_authenticated_service_resolution(
            recipient,
        )
        .await
        .unwrap();
    let boundary = evidence.method_history_evidence.boundary();
    let description = VerifiedServiceDescribeMetadata {
        service_id: recipient.service_core_id(),
        service_kind: "station".into(),
        service_resolution: ResolutionCommitment {
            did: recipient.service_did(),
            method_history_head: boundary.to_method_history_head.clone(),
            version_id: boundary.to_version_id.clone(),
        },
        http_json_base_url: recipient.config().public_base_url.clone(),
        trust_domain: recipient.config().trust_domain.clone(),
        protocol_version: arkret_wire::PROTOCOL_VERSION.into(),
        supported_operation_bundles: vec![
            arkret_wire::role_describe_bundle_descriptor(arkret_wire::ServiceKind::Station)
                .unwrap()
                .operation_bundle_id
                .into(),
        ],
    };
    sender.test_install_service_route_fetcher(Arc::new(VerifiedSourceRoute(
        VerifiedRouteCandidate {
            evidence,
            description,
        },
    )));
}

async fn admitted_owner(
    source: &LiveStation,
    receiver: &LiveStation,
) -> historical_human::HumanFixture {
    let mut owner = Box::pin(historical_human::HumanFixture::new(
        &source.pool,
        source.state.service_did(),
    ))
    .await;
    let index = owner
        .unit
        .transactions
        .iter()
        .position(|tx| tx.event.kind == EventKind::RealmPlaintextVisibleServices)
        .unwrap();
    let mut disclosure: arkret_models_collaboration::governance::plaintext_visibility::PlaintextVisibleServicesPayload =
        serde_json::from_value(serde_json::to_value(&owner.unit.transactions[index].event.payload).unwrap()).unwrap();
    disclosure.services.push(
        serde_json::from_value(serde_json::json!({
            "service_id": receiver.state.service_core_id(), "service_kind":"station",
            "data_classes":["message_content"], "purposes":["terminal fanout acceptance"],
            "visibility":"private_plaintext"
        }))
        .unwrap(),
    );
    owner.unit.transactions[index].event = historical_human::signed_ordinary_event(
        &owner,
        &owner.unit.transactions[index - 1],
        EventKind::RealmPlaintextVisibleServices,
        disclosure.to_value().unwrap(),
        owner.unit.transactions[index].commit.committed_at,
    );
    let store = PgAuthorityCommitStore {
        pool: source.pool.clone(),
    };
    let mut previous = None;
    for (index, tx) in owner.unit.transactions.iter_mut().enumerate() {
        tx.commit.event_ref = tx.event.event_id.clone();
        tx.producer_signer_fact = store
            .prepare_human_signer_fact(&tx.event, tx.commit.committed_at)
            .await
            .unwrap()
            .map(Into::into);
        tx.commit.producer_signer_fact_digest = tx
            .producer_signer_fact
            .as_ref()
            .map(|fact| fact.digest().unwrap());
        tx.commit.previous_commit_ref = previous;
        seal_service_commit(&mut tx.commit, &source.state);
        previous = Some(tx.commit.commit_id.clone());
        owner.unit.submission.events[index] = EventAdmissionSubmission::new(tx.event.clone());
    }
    owner.unit.exact_request_body = serde_json::to_vec(
        &SelfAuthoritySubmitRequest::OrdinaryRealmBootstrap(owner.unit.submission.clone()),
    )
    .unwrap();
    Box::pin(owner.admit(&source.pool)).await;
    owner
}

async fn install_opening_anchor(
    source: &LiveStation,
    receiver: &LiveStation,
    member: &historical_human::HumanFixture,
    join: &coland_storage::EventCommitRequest,
) {
    let store = PgAuthorityCommitStore {
        pool: receiver.pool.clone(),
    };
    let tx = &join.authority_commit;
    store
        .install_committed_replica(&CommittedReplica {
            local_service_id: receiver.state.service_core_id(),
            authority: tx.expected_authority.clone(),
            event: tx.event.clone(),
            commit: tx.commit.clone(),
            producer_signer_fact: tx.producer_signer_fact.clone(),
            genesis_event_ref: None,
            role: CommittedReplicaRole::OpeningJoin {
                member_account_id: member.pcr.history.account.clone(),
            },
            received_at: tx.commit.committed_at,
            welcomes: vec![],
        })
        .await
        .unwrap();
    let material = PgAuthorityCommitStore {
        pool: source.pool.clone(),
    }
    .member_station_bootstrap_material(
        &tx.event.realm_id,
        &member.pcr.history.account,
        &tx.commit.commit_id,
    )
    .await
    .unwrap()
    .unwrap();
    let snapshot = coland_services::authority_commit::build_signed_realm_state_snapshot(
        &material,
        source
            .state
            .service_verification_method("notary-key")
            .unwrap(),
        &ed25519_dalek::SigningKey::from_bytes(&historical_human::station_authority_seed()),
        Utc::now(),
    )
    .unwrap();
    arkret_signatures::detached_object::verify_detached_object_signature(
        &snapshot.signature,
        &arkret_canonical::unsigned_value(&snapshot, &["signature"]).unwrap(),
        arkret_wire::DetachedSignatureContext::RealmSnapshot,
        &arkret_signatures::PublicKeyMaterial::Ed25519Raw {
            bytes: ed25519_dalek::SigningKey::from_bytes(
                &historical_human::station_authority_seed(),
            )
            .verifying_key()
            .to_bytes()
            .to_vec(),
        },
    )
    .unwrap();
    store
        .install_replica_anchor(&ReplicaAnchorInstall {
            realm_id: tx.event.realm_id.clone(),
            join_commit_id: tx.commit.commit_id.clone(),
            governance_generation: material.governance_generation,
            snapshot_head: material.visible_stream_heads[0].clone(),
            visible_stream_heads: material.visible_stream_heads,
            current_state_entries: material.current_state_entries,
            verified_snapshot: snapshot,
        })
        .await
        .unwrap();
}

fn owner_candidate(
    owner: &historical_human::HumanFixture,
    source: &AppState,
    previous: &coland_storage::AuthorityCommitTransaction,
    kind: EventKind,
    mut payload: serde_json::Value,
) -> coland_storage::EventCommitRequest {
    let at = (previous.commit.committed_at + Duration::seconds(1))
        .max(arkret_canonical::normalize_timestamp_canonical(Utc::now()));
    if kind == EventKind::StrandCreate {
        payload["object"]["created_at"] =
            serde_json::json!(arkret_canonical::format_timestamp_canonical(at));
    }
    let event = historical_human::signed_ordinary_event(owner, previous, kind, payload, at);
    let mut request = historical_human::request_for_event(owner, previous, event, at);
    seal_service_commit(&mut request.authority_commit.commit, source);
    request.realm_fanout_source = Some(EventAdmissionSubmission::new(
        request.authority_commit.event.clone(),
    ));
    request
}

fn replication_body(request: &coland_storage::EventCommitRequest) -> Vec<u8> {
    let tx = &request.authority_commit;
    let body = PeerAuthoritySubmitRequest::CommittedReplication(PeerCommittedReplicationRequest {
        branch: CommittedReplicationBranch::CommittedReplication,
        replications: vec![CommittedEventSubmission::from_source_submission(
            &EventAdmissionSubmission::new(tx.event.clone()),
            tx.commit.clone(),
            tx.producer_signer_fact.clone(),
            None,
            None,
        )],
    });
    body.validate().unwrap();
    arkret_canonical::canonical_json_bytes(&body).unwrap()
}

async fn send_replication(
    source: &AppState,
    receiver: &AppState,
    body: &[u8],
    key: &str,
    corrupt_signature: bool,
) -> (u16, serde_json::Value) {
    let url = format!(
        "{}/_arkret/peer/events",
        receiver.config().public_base_url.trim_end_matches('/')
    );
    let mut headers = reqwest::header::HeaderMap::new();
    for (name, value) in [
        ("content-type", "application/json".to_owned()),
        ("idempotency-key", key.to_owned()),
        (
            "content-digest",
            crate::routing::federation::outbox::content_digest_header_value(body),
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
    let mut headers =
        crate::routing::federation::outbox::rfc9421_sign(source, headers, "POST", &url);
    if corrupt_signature {
        let mut signature = headers["signature"].to_str().unwrap().as_bytes().to_vec();
        let index = signature.iter().position(|byte| *byte == b':').unwrap() + 1;
        signature[index] = if signature[index] == b'A' { b'B' } else { b'A' };
        headers.insert(
            "signature",
            reqwest::header::HeaderValue::from_bytes(&signature).unwrap(),
        );
    }
    let (url, client) = crate::security::validate_http_url_for_egress_with_pinned_client(
        &url,
        "terminal replication test",
        source.config().development_mode,
        std::time::Duration::from_secs(20),
    )
    .unwrap();
    let response = client
        .post(url)
        .headers(headers)
        .body(body.to_vec())
        .send()
        .await
        .unwrap();
    let status = response.status().as_u16();
    let bytes = response.bytes().await.unwrap();
    let value = serde_json::from_slice(&bytes)
        .unwrap_or_else(|_| panic!("HTTP {status}: {}", String::from_utf8_lossy(&bytes)));
    (status, value)
}

fn assert_replication_outcome(
    value: serde_json::Value,
    body: &[u8],
    expected: PeerCommittedReplicationOutcomeRecord,
) {
    let request: PeerAuthoritySubmitRequest = serde_json::from_slice(body).unwrap();
    let outcome: PeerAuthoritySubmitOutcome = serde_json::from_value(value).unwrap();
    outcome.validate_for_request(&request).unwrap();
    let PeerAuthoritySubmitOutcome::CommittedReplication(outcome) = outcome else {
        panic!("wrong response branch")
    };
    assert_eq!(outcome.replication_outcomes, vec![expected]);
}

async fn execute(pool: &PgPool, sql: &str) {
    diesel::sql_query(sql)
        .execute(&mut *pool.get().await.unwrap())
        .await
        .unwrap();
}

fn fanout_row<'a>(
    snapshot: &'a serde_json::Value,
    commit: &arkret_wire::RealmCommitId,
) -> &'a serde_json::Value {
    let key = format!("realm-fanout:{commit}");
    let rows: Vec<_> = snapshot["federation_outbox"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|row| row["idempotency_key"] == key)
        .collect();
    assert_eq!(rows.len(), 1, "one durable intent per recipient Station");
    rows[0]
}

async fn dispatch_due(
    dispatcher: &crate::routing::federation::outbox::FederationDispatcher,
    source: &LiveStation,
    commit: &arkret_wire::RealmCommitId,
) {
    let snapshot = terminal_persistent_rows(&source.pool).await;
    let row = fanout_row(&snapshot, commit);
    let wait = row["next_attempt_at"].as_i64().unwrap() - Utc::now().timestamp();
    // Fixture Commits can be slightly ahead of wall time. Do not bypass the
    // production claim schedule or mistake an unclaimed intent for a retry.
    assert!(wait <= 30, "unexpected fixture schedule: {row}");
    if wait >= 0 {
        tokio::time::sleep(std::time::Duration::from_secs((wait + 1) as u64)).await;
    }
    Box::pin(dispatcher.run_one_pass()).await.unwrap();
}

#[tokio::test]
async fn joined_holder_terminal_real_fanout_signed_http_and_atomic_fence() {
    let source = LiveStation::start().await;
    let receiver = LiveStation::start().await;
    let current_source = receiver
        .state
        .dids()
        .resolve_current_service_did(&source.state.service_did())
        .await
        .unwrap();
    arkret_identity::validate_verification_method_relationship(
        &current_source.document,
        &DidUrl::new(
            crate::routing::federation::federation_service_signature_key_id(
                source.state.service_did().as_str(),
            ),
        )
        .unwrap(),
        &source.state.service_did(),
        arkret_identity::DidVerificationRelationship::AssertionMethod,
    )
    .unwrap();
    install_verified_route(&source.state, &receiver.state).await;
    install_verified_route(&receiver.state, &source.state).await;
    let owner = Box::pin(admitted_owner(&source, &receiver)).await;
    let member = Box::pin(historical_human::HumanFixture::new(
        &receiver.pool,
        receiver.state.service_did(),
    ))
    .await;
    let previous = owner.unit.transactions.last().unwrap();
    let mut join = Box::pin(foreign_request(&receiver.state, &member, &owner, previous, EventKind::MemberState,
        serde_json::json!({"realm_id":previous.event.realm_id,"member_id":ActorId::account(member.pcr.history.account.clone()),"membership":"join","reason":"terminal replica holder"}))).await;
    seal_service_commit(&mut join.authority_commit.commit, &source.state);
    let uow = PgEventCommitUnitOfWork::new(source.pool.clone());
    Box::pin(uow.commit_event(join.clone())).await.unwrap();
    let opening = terminal_persistent_rows(&source.pool).await;
    let opening = fanout_row(&opening, &join.authority_commit.commit.commit_id);
    assert_eq!(opening["state"], "pending_route");
    assert!(opening["peer_url"].is_null());
    Box::pin(install_opening_anchor(&source, &receiver, &member, &join)).await;
    let dispatcher =
        crate::routing::federation::outbox::FederationDispatcher::new(source.state.clone());
    Box::pin(dispatch_due(
        &dispatcher,
        &source,
        &join.authority_commit.commit.commit_id,
    ))
    .await;
    let initial_delivery = terminal_persistent_rows(&source.pool).await;
    let initial_delivery = fanout_row(&initial_delivery, &join.authority_commit.commit.commit_id);
    assert_eq!(
        initial_delivery["state"],
        "delivered",
        "attempts={}, error={}, detail={}",
        initial_delivery["attempts"],
        initial_delivery["last_error_code"],
        initial_delivery["last_response_excerpt"]
    );

    let terminal = owner_candidate(
        &owner,
        &source.state,
        &join.authority_commit,
        EventKind::RealmTombstone,
        arkret_models_collaboration::governance::realm_lifecycle::RealmTombstonePayload::new(
            "ak:realm:ASR8x2N1qyfyy6I-eob3l-FNhx4FPBTyMJrIfifkksgW"
                .parse()
                .unwrap(),
            "migration",
        )
        .to_value()
        .unwrap(),
    );
    // Fail after canonical/current writes, proving the fanout is in that same transaction.
    assert!(
        crate::routing::events::structural_navigation_available(
            &source.state,
            terminal.authority_commit.event.realm_id.as_str()
        )
        .await
        .unwrap()
    );
    execute(&source.pool, "CREATE OR REPLACE FUNCTION reject_terminal_intent() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'terminal fanout rollback'; END $$").await;
    execute(&source.pool, "CREATE TRIGGER reject_terminal_intent BEFORE INSERT ON federation_outbox FOR EACH ROW EXECUTE FUNCTION reject_terminal_intent()").await;
    let before = terminal_persistent_rows(&source.pool).await;
    assert!(Box::pin(uow.commit_event(terminal.clone())).await.is_err());
    assert_eq!(terminal_persistent_rows(&source.pool).await, before);
    execute(
        &source.pool,
        "DROP TRIGGER reject_terminal_intent ON federation_outbox",
    )
    .await;
    execute(&source.pool, "DROP FUNCTION reject_terminal_intent()").await;
    Box::pin(uow.commit_event(terminal.clone())).await.unwrap();
    assert!(
        !crate::routing::events::structural_navigation_available(
            &source.state,
            terminal.authority_commit.event.realm_id.as_str()
        )
        .await
        .unwrap()
    );
    let accepted = terminal_persistent_rows(&source.pool).await;
    let intent = fanout_row(&accepted, &terminal.authority_commit.commit.commit_id);
    assert_eq!(intent["state"], "pending");
    assert_eq!(
        intent["peer_url"].as_str().unwrap().trim_end_matches('/'),
        receiver
            .state
            .config()
            .public_base_url
            .trim_end_matches('/')
    );
    assert_eq!(intent["peer_id"], receiver.state.service_id().as_str());
    let body = replication_body(&terminal);
    let actual: serde_json::Value =
        serde_json::from_str(intent["payload_json"].as_str().unwrap()).unwrap();
    assert_eq!(
        actual,
        serde_json::from_slice::<serde_json::Value>(&body).unwrap()
    );
    assert_eq!(intent["payload_json"].as_str().unwrap().as_bytes(), body);
    let binding: coland_storage::RealmFanoutBinding =
        serde_json::from_value(intent["realm_fanout"].clone()).unwrap();
    assert_eq!(
        binding.realm_id,
        terminal.authority_commit.event.realm_id.as_str()
    );
    assert_eq!(
        binding.authority_witnesses,
        vec![coland_storage::RealmFanoutAuthorityWitness {
            member_id: ActorId::account(member.pcr.history.account.clone()),
            membership_event_ref: join.authority_commit.event.event_id.to_string(),
            circle_membership_event_ref: None,
        }]
    );
    Box::pin(uow.commit_event(terminal.clone())).await.unwrap();
    assert_eq!(terminal_persistent_rows(&source.pool).await, accepted);
    let key = intent["idempotency_key"].as_str().unwrap().to_owned();
    assert_eq!(
        intent["realm_fanout"]["authority_witnesses"]
            .as_array()
            .unwrap()
            .len(),
        1
    );

    // A missing route must not invalidate local acceptance or replace its intent.
    source
        .state
        .test_install_service_route_fetcher(Arc::new(MissingRoute));
    let before = terminal_persistent_rows(&receiver.pool).await;
    Box::pin(dispatch_due(
        &dispatcher,
        &source,
        &terminal.authority_commit.commit.commit_id,
    ))
    .await;
    assert_eq!(terminal_persistent_rows(&receiver.pool).await, before);
    let pending = terminal_persistent_rows(&source.pool).await;
    let pending = fanout_row(&pending, &terminal.authority_commit.commit.commit_id);
    assert_eq!(pending["state"], "pending_route", "{pending}");
    assert_eq!(pending["last_error_code"], "service_route_unavailable");
    assert_eq!(pending["attempts"], 1);
    assert_eq!(pending["idempotency_key"], key);
    assert_eq!(pending["payload_json"], intent["payload_json"]);
    install_verified_route(&source.state, &receiver.state).await;
    execute(
        &source.pool,
        "UPDATE federation_outbox SET next_attempt_at=0 WHERE state='pending_route'",
    )
    .await;

    // An installation failure cannot persist the canonical terminal without its fence.
    execute(&receiver.pool, "CREATE OR REPLACE FUNCTION reject_terminal_fence() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.result_family='realm_tombstone' THEN RAISE EXCEPTION 'terminal fence rollback'; END IF; RETURN NEW; END $$").await;
    execute(&receiver.pool, "CREATE TRIGGER reject_terminal_fence BEFORE INSERT OR UPDATE ON realm_bootstrap_current_results FOR EACH ROW EXECUTE FUNCTION reject_terminal_fence()").await;
    let before = terminal_persistent_rows(&receiver.pool).await;
    Box::pin(dispatcher.run_one_pass()).await.unwrap();
    assert_eq!(terminal_persistent_rows(&receiver.pool).await, before);
    let retry = terminal_persistent_rows(&source.pool).await;
    let retry = fanout_row(&retry, &terminal.authority_commit.commit.commit_id);
    assert_eq!(retry["state"], "pending", "{retry}");
    assert_eq!(retry["idempotency_key"], key);
    assert_eq!(retry["payload_json"], intent["payload_json"]);
    execute(
        &receiver.pool,
        "DROP TRIGGER reject_terminal_fence ON realm_bootstrap_current_results",
    )
    .await;
    execute(&receiver.pool, "DROP FUNCTION reject_terminal_fence()").await;
    execute(
        &source.pool,
        "UPDATE federation_outbox SET next_attempt_at=0 WHERE state IN ('pending','pending_route')",
    )
    .await;
    Box::pin(dispatcher.run_one_pass()).await.unwrap();
    let delivered = terminal_persistent_rows(&source.pool).await;
    let delivered = fanout_row(&delivered, &terminal.authority_commit.commit.commit_id);
    assert_eq!(delivered["state"], "delivered", "{delivered}");
    assert_eq!(delivered["last_http_status"], 200);
    let installed = PgAuthorityCommitStore {
        pool: receiver.pool.clone(),
    }
    .committed_event(&terminal.authority_commit.event.event_id)
    .await
    .unwrap()
    .unwrap();
    assert_eq!(installed.event, terminal.authority_commit.event);
    assert_eq!(installed.commit, terminal.authority_commit.commit);
    assert!(
        !crate::routing::events::structural_navigation_available(
            &receiver.state,
            terminal.authority_commit.event.realm_id.as_str()
        )
        .await
        .unwrap()
    );
    let before = terminal_persistent_rows(&receiver.pool).await;
    assert!(
        before["realm_bootstrap_current_results"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["result_family"] == "realm_tombstone"
                && row["current_commit_id"] == terminal.authority_commit.commit.commit_id.as_str())
    );
    assert!(
        before["federation_outbox"].as_array().unwrap().is_empty(),
        "replication never fans out again"
    );
    let (status, replay) = Box::pin(send_replication(
        &source.state,
        &receiver.state,
        &body,
        // A fresh request tests exact replica duplicate detection; the
        // original key may replay its first Stored result (federation section 4).
        "terminal-exact-original-new-request",
        false,
    ))
    .await;
    assert_eq!(status, 200, "{replay}");
    assert_replication_outcome(
        replay,
        &body,
        PeerCommittedReplicationOutcomeRecord::Duplicate {},
    );
    assert_eq!(terminal_persistent_rows(&receiver.pool).await, before);
    let (status, problem) = Box::pin(send_replication(
        &source.state,
        &receiver.state,
        &body,
        &key,
        true,
    ))
    .await;
    assert!(status >= 400, "{problem}");
    assert!(
        problem.to_string().contains("signature_invalid"),
        "{problem}"
    );
    assert_eq!(terminal_persistent_rows(&receiver.pool).await, before);

    // A correctly signed source assertion still cannot create fresh non-audit effects.
    // This candidate is deliberately never accepted at the source.
    let fresh = owner_candidate(
        &owner,
        &source.state,
        &terminal.authority_commit,
        EventKind::RealmProfile,
        serde_json::json!({"schema":"ak.schema.realm_profile.v1","title":"must not revive"}),
    );
    let source_before = terminal_persistent_rows(&source.pool).await;
    let error = Box::pin(uow.commit_event(fresh.clone())).await.unwrap_err();
    assert!(error.to_string().contains("failed_precondition"), "{error}");
    assert_eq!(terminal_persistent_rows(&source.pool).await, source_before);
    let (status, rejected) = Box::pin(send_replication(
        &source.state,
        &receiver.state,
        &replication_body(&fresh),
        "terminal-fresh-rejection",
        false,
    ))
    .await;
    assert_eq!(status, 200, "{rejected}");
    assert!(
        !rejected.to_string().contains("realm_terminal_state"),
        "{rejected}"
    );
    assert_replication_outcome(
        rejected,
        &replication_body(&fresh),
        PeerCommittedReplicationOutcomeRecord::Rejected {
            reason_code: "failed_precondition".into(),
        },
    );
    assert_eq!(terminal_persistent_rows(&receiver.pool).await, before);
}
