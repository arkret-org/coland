//! Real PG source and a registered TCP PeerScan execute the production recovery
//! helper. The session is the already-authenticated state-port context; this
//! does not claim a live OIDC/DPoP middleware or subprocess-crash test.
//! Box the admission/recovery phases separately so signed multi-Station
//! regression futures fit the ordinary test-thread stack in debug builds.
#[path = "../../../storage-postgres/tests/support/historical_human.rs"]
mod historical_human;
#[path = "realm_terminal_fanout_tests.rs"]
mod realm_terminal_fanout_tests;
#[path = "realm_terminal_peer_tests.rs"]
mod realm_terminal_peer_tests;
#[path = "../../../storage-postgres/tests/support/sql_fault_matrix.rs"]
#[allow(dead_code)]
mod sql_fault_matrix;
#[path = "test_material_evidence_tests.rs"]
mod test_material_evidence_tests;

use std::io::{Read, Write};
use std::sync::Arc;

use arkret_models_collaboration::authority_commit::{
    PeerStreamScanResponseBody, SelfAuthoritySubmitRequestBody,
};
use arkret_models_identity::ResolutionCommitment;
use arkret_models_identity::session_credential::{
    SessionGrantCredentialClass, SessionGrantDeviceBinding, SessionGrantHolderBinding,
};
use arkret_wire::{
    AccountId, ActorId, Base64UrlString, DidUrl, EventAdmissionSubmission, EventKind,
    StreamScanDirection, StreamScanRequestBody,
};
use chrono::{Duration, Utc};
use coland_services::identity::{
    SessionEndpointState, SessionGrantAuthorizationState, SessionIdentityState,
};
use coland_services::service_route::{
    ServiceRouteFetcher, VerifiedRouteCandidate, VerifiedServiceDescribeMetadata,
};
use coland_storage::{
    AccountPk, AccountRecord, AuthorityCommitStore, CommittedReplica, CommittedReplicaRole,
    EventCommitUnitOfWork, ForwardedProducerDeviceEvidence, ReplicaAnchorInstall,
};
use coland_storage_postgres::{
    PgAuthorityCommitStore, PgEventCommitUnitOfWork, PgPersistenceStore, PgPool,
};

use super::*;

// Construct large fixture futures outside the enclosing poll frame.
// The same task, database and cancellation path remain in use.
#[inline(never)]
fn scenario_future<F, Fut>(make: F) -> std::pin::Pin<Box<Fut>>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future,
{
    Box::pin(make())
}

// Actual HTTP admissions run as independent tasks. Preserve that boundary for
// nested parent/Circle fixtures without enlarging the default worker stack.
async fn admit_fixture_event(pool: &PgPool, candidate: coland_storage::EventCommitRequest) {
    let pool = pool.clone();
    let mut admission = tokio::task::JoinSet::new();
    admission.spawn(async move {
        Box::pin(PgEventCommitUnitOfWork::new(pool).commit_event(candidate))
            .await
            .unwrap();
    });
    admission.join_next().await.unwrap().unwrap();
}

struct VerifiedSourceRoute(VerifiedRouteCandidate);
#[async_trait::async_trait]
impl ServiceRouteFetcher for VerifiedSourceRoute {
    async fn fetch_current(
        &self,
        id: &DidCoreId,
        kind: &str,
    ) -> coland_services::ServiceResult<Option<VerifiedRouteCandidate>> {
        Ok((id == &self.0.evidence.service_id && kind == "station").then(|| self.0.clone()))
    }
}

/// Preserve the same accepted fixture identity, original method history and PG
/// store across the local test-crate type boundary (as the native replay test).
fn station(url: String) -> (AppState, PgPool, Arc<dyn coland_storage::PersistenceStore>) {
    let mut external = coland_test_support::app_config();
    external.public_base_url = url.clone();
    external.notary_signing_key_seed = Some([83; 32]);
    external.seed_demo_data = false;
    external.development_mode = true;
    external.did_resolver_allow_methods.push("webvh".into());
    let (leased, pool) = coland_test_support::app_state_with_pool(external.clone());
    let local = crate::config::AppConfig {
        public_base_url: url,
        notary_signing_key_seed: Some([83; 32]),
        seed_demo_data: false,
        development_mode: true,
        did_resolver_allow_methods: external.did_resolver_allow_methods.clone(),
        ..crate::config::AppConfig::test_default()
    };
    assert_eq!(local.trust_domain, external.trust_domain);
    use coland_test_support::AppStateTestExt as _;
    let keep_lease = leased.test_persistence();
    let state = AppState::new_with_service_identity(
        local,
        coland_storage_postgres::Db {
            pool: Some(pool.clone()),
        },
        keep_lease.clone(),
        coland_test_support::fixture_service_identity(&external),
        leased.service_resolution_commitment().as_ref().clone(),
        [83; 32],
    );
    (state, pool, keep_lease)
}

async fn foreign_request(
    origin: &AppState,
    joining: &historical_human::HumanFixture,
    governor: &historical_human::HumanFixture,
    previous: &coland_storage::AuthorityCommitTransaction,
    kind: EventKind,
    payload: serde_json::Value,
) -> coland_storage::EventCommitRequest {
    let at = previous.commit.committed_at + Duration::seconds(1);
    let circle_id = (kind == EventKind::CircleMemberState).then(|| {
        serde_json::from_value::<arkret_wire::CircleId>(payload["circle_id"].clone()).unwrap()
    });
    let mut event = historical_human::signed_ordinary_event(joining, previous, kind, payload, at);
    if let Some(circle_id) = circle_id {
        event.scope_ref = arkret_wire::ScopeRef::Circle {
            realm_id: previous.event.realm_id.clone(),
            circle_id,
        };
        event = coland_test_support::device_authorization_history::sign_event(
            event,
            joining.pcr.history.device_verification_method.clone(),
            joining.pcr.history.founding_device_signing_seed,
        );
    }
    let mut request = historical_human::request_for_event(joining, previous, event, at);
    if let arkret_wire::ScopeRef::Circle {
        realm_id,
        circle_id,
    } = &request.authority_commit.event.scope_ref
    {
        let stream = arkret_wire::CommitStreamRef::Circle {
            realm_id: realm_id.clone(),
            circle_id: circle_id.clone(),
        };
        if previous.commit.stream_ref != stream {
            request.authority_commit.commit.stream_position = 0;
            request.authority_commit.commit.previous_commit_ref = None;
        }
        request.authority_commit.commit.stream_ref = stream;
    }
    let unsigned = arkret_models_collaboration::authority_commit::PeerAuthorityForwardEventRequestBody {
        branch: arkret_models_collaboration::authority_commit::AuthorityForwardBranch::AuthorityForward,
        event_submission: EventAdmissionSubmission::new(request.authority_commit.event.clone()),
        producer_device_evidence: None,
        producer_agent_evidence: None,
        mls_genesis_material: None,
    };
    let mut forward = PeerAuthoritySubmitRequestBody::AuthorityForwardEvent(unsigned);
    super::fresh_device_request(
        origin,
        &governor.pcr.history.account.station_id,
        &mut forward,
    )
    .await
    .unwrap();
    let PeerAuthoritySubmitRequestBody::AuthorityForwardEvent(forward) = forward else {
        unreachable!("constructed an Event forward");
    };
    let evidence = forward.producer_device_evidence.unwrap();
    let core = &evidence.device_projection_attestation.attestation;
    let fact = arkret_identity::account_device_signer_evidence::verify_forwarded_account_device_signer_fact(
        &evidence,
        &request.authority_commit.event,
        &joining.pcr.history.account.station_id,
        &governor.pcr.history.account.station_id,
        &core.event_authorization.forward_body_digest,
        arkret_canonical::DigestSuite::Sha256,
        core.attested_at,
    )
    .unwrap()
    .into_fact();
    request.authority_commit.producer_signer_fact = Some(fact.clone().into());
    request.authority_commit.commit.producer_signer_fact_digest = Some(fact.digest().unwrap());
    request.authority_commit.commit.committed_at = core.attested_at;
    request.self_producer_guard = None;
    request.forwarded_producer_evidence =
        Some(ForwardedProducerDeviceEvidence::new(evidence, fact).unwrap());
    historical_human::seal_commit(
        &mut request.authority_commit.commit,
        &governor.pcr.history.station_did,
    );
    request.realm_fanout_source = Some(EventAdmissionSubmission::new(
        request.authority_commit.event.clone(),
    ));
    request
}

async fn authenticated_context(
    pool: &PgPool,
    human: &historical_human::HumanFixture,
) -> SessionIdentityState {
    use coland_storage::IdentityStoreRegistry;
    let account = &human.pcr.history.account;
    let persistence = PgPersistenceStore::new(pool.clone());
    let pk = persistence
        .accounts()
        .put(&AccountRecord {
            pk: AccountPk(0),
            principal_id: account.principal_id.clone(),
            station_id: account.station_id.clone(),
            localpart: format!("forward-recovery-{}", uuid::Uuid::now_v7().simple()),
            display_name: None,
            biography: None,
            avatar_blob_ref: None,
            created_at: Utc::now(),
        })
        .await
        .unwrap();
    let device = human.pcr.history.founding_device_id.clone();
    SessionIdentityState {
        token_hash: "authenticated-state-port-public-fixture".into(),
        account_pk: Some(pk),
        actor: account.principal_id.to_string(),
        endpoint: SessionEndpointState::HumanDevice {
            device_id: device.to_string(),
        },
        audience: account.station_id.to_string(),
        session_public_key: None,
        session_grant: Some(SessionGrantAuthorizationState {
            grant_id: arkret_identifiers::SessionGrantId::from_issuance_digest([0x64; 32]),
            revocation_ref: "public-state-port-context".into(),
            account_id: account.clone(),
            issuer_id: account.station_id.clone(),
            scopes: vec![],
            credential_class: SessionGrantCredentialClass::Standard,
            holder_binding: SessionGrantHolderBinding::HumanDevice {
                device_binding: device.to_string(),
            },
            device_binding: Some(SessionGrantDeviceBinding {
                device_id: device,
                authorization_event_id: human.guard.authorization_ref.event_id.clone(),
                model_generation_ref: 1,
            }),
            cnf_jkt: "public-state-port-holder".into(),
        }),
        expires_at: Utc::now() + Duration::hours(1),
        created_at: Utc::now(),
        revoked_at: None,
    }
}

/// Exercise real producer preflight and atomic bootstrap admission on the same
/// default worker stack used by the server. Authentication is represented by
/// the already-authenticated state-port context, not a dev-login credential.
#[test]
fn ordinary_realm_bootstrap_and_event_admission_fit_default_worker_stack() {
    for operation_target in [false, true] {
        bootstrap_admission_on_default_worker_stack(operation_target);
    }
}

fn bootstrap_admission_on_default_worker_stack(operation_target: bool) {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .unwrap();
    let (state, pool, _lease) = station("https://bootstrap-default-stack.internal/".into());
    let (human, session) = runtime.block_on(async {
        let mut human = historical_human::HumanFixture::new(&pool, state.service_did()).await;
        let event = &human.unit.submission.events[1].event;
        let provisional =
            arkret_signatures::Ed25519DetachedJwsSigner::from_seed([95; 32], "approval");
        let key = arkret_canonical::ed25519_pubkey_to_did_key_multibase(
            provisional.verifying_key().as_bytes(),
        );
        let did = arkret_wire::Did::new(format!("did:key:{key}")).unwrap();
        let method = DidUrl::new(format!("{did}#{key}")).unwrap();
        let signer =
            arkret_signatures::Ed25519DetachedJwsSigner::from_seed([95; 32], method.as_str());
        let mut approval = arkret_wire::ApprovalSignature {
            input: arkret_wire::ApprovalSignatureInput {
                approval_context: arkret_wire::ApprovalContext::RealmGovernance {},
                approval_target: if operation_target {
                    arkret_wire::ApprovalTarget::Operation
                } else {
                    arkret_wire::ApprovalTarget::Event {
                        event_id: event.event_id.clone(),
                    }
                },
                request_canonical_digest: arkret_wire::Hash::new(if operation_target {
                    arkret_canonical::canonical_sha256(
                        &SelfAuthoritySubmitRequestBody::OrdinaryRealmBootstrap(
                            human.unit.submission.clone(),
                        ),
                    )
                    .unwrap()
                } else {
                    arkret_canonical::canonical_sha256(event).unwrap()
                })
                .unwrap(),
                operation: "ak.self.events.command.submit.v1".into(),
                action: if operation_target {
                    arkret_wire::CapabilityActionId::RealmOwner
                } else {
                    arkret_wire::CapabilityActionId::RealmProfile
                },
                realm_id: event.realm_id.clone(),
                initiating_actor_id: event.actor_id.clone(),
                approver_did: did,
                approved_at: arkret_canonical::normalize_timestamp_canonical(Utc::now()),
                nonce: arkret_canonical::base64url_encode(rand::random::<[u8; 32]>()),
            },
            proof: arkret_wire::ApprovalSignatureProof {
                kind: arkret_wire::ApprovalSignatureProofKind::DetachedJws,
                verification_method: method,
                jws: String::new(),
            },
        };
        approval.proof.jws = signer.sign_detached_jws(
            &arkret_signatures::approval_signature::approval_signature_signing_bytes(&approval)
                .unwrap(),
        );
        if operation_target {
            human.unit.submission.events[2].approval_signatures = Some(vec![approval.clone()]);
        }
        human.unit.submission.events[1].approval_signatures = Some(vec![approval]);
        human.unit.exact_request_body = serde_json::to_vec(
            &SelfAuthoritySubmitRequestBody::OrdinaryRealmBootstrap(human.unit.submission.clone()),
        )
        .unwrap();
        let session = authenticated_context(&pool, &human).await;
        (human, session)
    });
    let http = crate::service(state.clone());
    runtime.block_on(async {
        tokio::spawn(async move {
            let request =
                SelfAuthoritySubmitRequestBody::OrdinaryRealmBootstrap(human.unit.submission.clone());
            let response = salvo::test::TestClient::post("http://server/_arkret/self/events")
                .add_header(
                    "Arkret-Operation",
                    arkret_wire::ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT_V1,
                    true,
                )
                .json(&serde_json::to_value(&request).unwrap())
                .send(&http)
                .await;
            assert_eq!(
                response.status_code,
                Some(salvo::http::StatusCode::UNAUTHORIZED)
            );
            let mut wrong = human.unit.submission.clone();
            wrong.events[1].approval_signatures.as_mut().unwrap()[0].proof.jws = "eyJhbGciOiJFZDI1NTE5In0..bad".into();
            let wrong_request = SelfAuthoritySubmitRequestBody::OrdinaryRealmBootstrap(wrong);
            let wrong_body = serde_json::to_vec(&wrong_request).unwrap();
            assert!(state.authority().submit_self(&session, wrong_request, &wrong_body).await.unwrap_err().to_string().contains("signature_invalid"));
            for item in &human.unit.submission.events {
                assert!(state.authority_commits().committed_event(&item.event.event_id).await.unwrap().is_none());
            }
            let before = sql_fault_matrix::snapshot(&pool).await;
            let mut null_carrier = serde_json::to_value(&request).unwrap();
            null_carrier["events"][0]["approval_signatures"] = serde_json::Value::Null;
            let null_body = serde_json::to_vec(&null_carrier).unwrap();
            let error = state.authority().submit_self(&session, request.clone(), &null_body).await.unwrap_err();
            assert!(matches!(error, ServiceError::SchemaViolation(_)), "null approval carrier: {error}");
            assert_eq!(sql_fault_matrix::snapshot(&pool).await, before);
            for case in 0..3 {
                let mut wrong = human.unit.submission.clone();
                let vote = &mut wrong.events[1].approval_signatures.as_mut().unwrap()[0];
                match case {
                    0 => vote.input.action = arkret_wire::CapabilityActionId::RealmTombstone,
                    1 => vote.input.approval_context = arkret_wire::ApprovalContext::Grant {
                        grant_id: arkret_wire::GrantId::from_event_id(&human.unit.submission.events[0].event.event_id),
                    },
                    _ => {
                        vote.input.approval_target = arkret_wire::ApprovalTarget::Operation;
                        vote.input.request_canonical_digest = arkret_wire::Hash::new(arkret_canonical::canonical_sha256(&EventAdmissionSubmission::new(human.unit.submission.events[1].event.clone())).unwrap()).unwrap();
                    }
                }
                let signer = arkret_signatures::Ed25519DetachedJwsSigner::from_seed([95; 32], vote.proof.verification_method.as_str());
                let bytes = arkret_signatures::approval_signature::approval_signature_signing_bytes(vote).unwrap();
                vote.proof.jws = signer.sign_detached_jws(&bytes);
                vote.validate().unwrap();
                arkret_signatures::Ed25519DetachedJwsVerifier::new().verify_detached_jws(&vote.proof.jws, &bytes,
                    &arkret_signatures::PublicKeyMaterial::Ed25519Raw { bytes: signer.verifying_key().to_bytes().to_vec() }).unwrap();
                let wrong_request = SelfAuthoritySubmitRequestBody::OrdinaryRealmBootstrap(wrong);
                wrong_request.validate().unwrap();
                let body = serde_json::to_vec(&wrong_request).unwrap();
                let error = state.authority().submit_self(&session, wrong_request, &body).await.unwrap_err();
                let code = if case == 1 { "approval_required" } else { "signature_invalid" };
                assert!(error.to_string().contains(code), "case {case}: {error}");
                assert_eq!(sql_fault_matrix::snapshot(&pool).await, before, "case {case}");
            }
            if operation_target {
                let mut wrong = human.unit.submission.clone();
                let vote = &mut wrong.events[2].approval_signatures.as_mut().unwrap()[0];
                vote.input.action = arkret_wire::CapabilityActionId::RealmAdmin;
                let signer = arkret_signatures::Ed25519DetachedJwsSigner::from_seed([95; 32], vote.proof.verification_method.as_str());
                let bytes = arkret_signatures::approval_signature::approval_signature_signing_bytes(vote).unwrap();
                vote.proof.jws = signer.sign_detached_jws(&bytes);
                arkret_signatures::Ed25519DetachedJwsVerifier::new().verify_detached_jws(&vote.proof.jws, &bytes,
                    &arkret_signatures::PublicKeyMaterial::Ed25519Raw { bytes: signer.verifying_key().to_bytes().to_vec() }).unwrap();
                let wrong = SelfAuthoritySubmitRequestBody::OrdinaryRealmBootstrap(wrong);
                wrong.validate().unwrap();
                let body = serde_json::to_vec(&wrong).unwrap();
                assert!(state.authority().submit_self(&session, wrong, &body).await.unwrap_err().to_string().contains("approval_nonce_reused"));
                assert_eq!(sql_fault_matrix::snapshot(&pool).await, before);
            }
            let name = if operation_target { "ordinary_bootstrap_http_operation_approval" } else { "ordinary_bootstrap_http_event_approval" };
            let outcome = sql_fault_matrix::exhaust_writes(&pool, name, || async {
                state.authority().submit_self(&session, request.clone(), &human.unit.exact_request_body).await.map_err(|error| {
                    let detail = error.to_string();
                    if detail.contains("authority_unit_fault:") { coland_storage::PersistenceError::Database(detail) }
                    else { coland_storage::PersistenceError::Internal(detail) }
                })
            }).await;
            outcome.validate_for_request(&request).unwrap();
            let replay = state.authority().submit_self(&session, request.clone(), &human.unit.exact_request_body).await.unwrap();
            let arkret_models_collaboration::authority_commit::SelfAuthoritySubmitResponseBody::OrdinaryRealmBootstrap(first) = outcome else {panic!("bootstrap outcome");};
            let arkret_models_collaboration::authority_commit::SelfAuthoritySubmitResponseBody::OrdinaryRealmBootstrap(replay) = replay else {panic!("bootstrap replay");};
            assert_eq!(first.commits, replay.commits);
            assert_eq!(replay.status, arkret_models_collaboration::authority_commit::AggregateAcceptanceStatus::Duplicate);
            let accepted = sql_fault_matrix::snapshot(&pool).await;
            let audit = accepted["event_approval_private_audit"].as_array().unwrap();
            assert_eq!(audit.len(), 1);
            assert_eq!(audit[0]["accepted_basis"]["authority_cut"]["commits"], serde_json::to_value(&first.commits).unwrap());
            let committed = state
                .authority_commits()
                .committed_event(&human.unit.transactions.last().unwrap().event.event_id)
                .await
                .unwrap()
                .unwrap();
            let mut previous = human.unit.transactions.last().unwrap().clone();
            previous.commit = committed.commit;
            previous.event = committed.event;
            let next = human.next(&previous, human.pcr.history.founding_device_signing_seed);
            let submission = SelfAuthoritySubmitRequestBody::Event(EventAdmissionSubmission::new(
                next.authority_commit.event,
            ));
            let body = serde_json::to_vec(&submission).unwrap();
            let outcome = state
                .authority()
                .submit_self(&session, submission, &body)
                .await
                .unwrap();
            assert!(matches!(
                outcome,
                arkret_models_collaboration::authority_commit::SelfAuthoritySubmitResponseBody::Ordinary(
                    arkret_wire::AuthoritySubmitResponseBody::Accepted {
                        status: arkret_wire::AuthorityCommitStatus::Committed,
                        ..
                    }
                )
            ));
        })
        .await
        .unwrap();
    });
}

/// The same real CA/leaf fixture used by federation_outbox. Production egress
/// loads this explicit trust store and keeps certificate/hostname validation.
/// The driver supplies isolated TLS material shared with production DID egress.
struct RegisteredTlsPeer {
    listener: std::net::TcpListener,
    tls: Arc<rustls::ServerConfig>,
    history: std::sync::RwLock<std::collections::BTreeMap<String, Vec<u8>>>,
}

fn registered_tls_peer() -> Arc<RegisteredTlsPeer> {
    use rustls::pki_types::pem::PemObject as _;
    let read = |name: &str| {
        let path = std::env::var_os(name).unwrap_or_else(|| {
            panic!("{name} is required; run via cotest/scripts/run-native-rust-tests.py")
        });
        std::fs::read(path).unwrap()
    };
    assert_eq!(
        read("SSL_CERT_FILE"),
        read("COTEST_RUN_SCOPED_CA_PEM"),
        "fixture and production DID egress must trust the same run-scoped CA"
    );
    let certificates =
        rustls::pki_types::CertificateDer::pem_slice_iter(&read("COLAND_TLS_CERT_PATH"))
            .collect::<Result<Vec<_>, _>>()
            .expect("native fixture certificate chain PEM");
    let private_key =
        rustls::pki_types::PrivateKeyDer::from_pem_slice(&read("COLAND_TLS_KEY_PATH"))
            .expect("native fixture private key PEM");
    let tls = Arc::new(
        rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(certificates, private_key)
        .unwrap(),
    );
    Arc::new(RegisteredTlsPeer {
        listener: std::net::TcpListener::bind("127.0.0.1:0").unwrap(),
        tls,
        history: std::sync::RwLock::default(),
    })
}

async fn register_original_peer_history(
    listener: &RegisteredTlsPeer,
    governor: &AppState,
    pool: &PgPool,
) {
    use coland_storage::DeliveryPolicyStoreRegistry as _;
    let records = PgPersistenceStore::new(pool.clone())
        .webvh()
        .list_log_events(governor.service_did().as_str())
        .await
        .unwrap();
    assert!(!records.is_empty());
    let mut log = Vec::new();
    for record in records {
        log.extend(arkret_canonical::canonical_json_bytes(&record.operation).unwrap());
        log.push(b'\n');
    }
    let verified = arkret_identity::verify_did_webvh_v1_chain_and_witness_bytes(
        &governor.service_did(),
        &log,
        None,
    )
    .unwrap();
    let document = arkret_canonical::canonical_json_bytes(&verified.log.head_state).unwrap();
    let log_url = reqwest::Url::parse(
        &arkret_identity::DidWebvhResolver::log_url(&governor.service_did()).unwrap(),
    )
    .unwrap();
    let doc_url = reqwest::Url::parse(
        &arkret_identity::DidWebvhResolver::document_url(&governor.service_did()).unwrap(),
    )
    .unwrap();
    let base = reqwest::Url::parse(&governor.config().public_base_url).unwrap();
    assert_eq!(log_url.origin(), base.origin());
    assert_eq!(doc_url.origin(), base.origin());
    let mut history = listener.history.write().unwrap();
    history.insert(log_url.path().to_owned(), log);
    history.insert(doc_url.path().to_owned(), document);
}

/// Fresh pinned-history resolution can occur between any two registered POSTs.
/// Return only the real Station's verified original log/document on this TLS
/// endpoint; the production resolver still validates its chain and pin.
fn registered_post(
    listener: &RegisteredTlsPeer,
) -> (
    rustls::StreamOwned<rustls::ServerConnection, std::net::TcpStream>,
    Vec<u8>,
    usize,
) {
    loop {
        let (socket, _) = listener.listener.accept().unwrap();
        socket
            .set_read_timeout(Some(std::time::Duration::from_secs(10)))
            .unwrap();
        socket
            .set_write_timeout(Some(std::time::Duration::from_secs(10)))
            .unwrap();
        let mut stream = rustls::StreamOwned::new(
            rustls::ServerConnection::new(listener.tls.clone()).unwrap(),
            socket,
        );
        let mut bytes = Vec::new();
        let mut buf = [0u8; 2048];
        let end = loop {
            let n = stream.read(&mut buf).unwrap();
            assert!(n > 0);
            bytes.extend_from_slice(&buf[..n]);
            assert!(bytes.len() < 1024 * 1024);
            if let Some(p) = bytes.windows(4).position(|v| v == b"\r\n\r\n") {
                break p + 4;
            }
        };
        let header = std::str::from_utf8(&bytes[..end]).unwrap();
        if !header.starts_with("GET ") {
            return (stream, bytes, end);
        }
        let target = header
            .lines()
            .next()
            .unwrap()
            .split_whitespace()
            .nth(1)
            .unwrap()
            .split('?')
            .next()
            .unwrap();
        let history = listener.history.read().unwrap();
        let body = history
            .get(target)
            .expect("only the real source's registered method history may be served");
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        stream.write_all(response.as_bytes()).unwrap();
        stream.write_all(body).unwrap();
        stream.flush().unwrap();
        assert!(!stream.conn.is_handshaking());
    }
}

async fn registered_history_until_stop(
    listener: Arc<RegisteredTlsPeer>,
    stop: Arc<std::sync::atomic::AtomicBool>,
) -> usize {
    tokio::task::spawn_blocking(move || {
        listener.listener.set_nonblocking(true).unwrap();
        let mut count = 0;
        while !stop.load(std::sync::atomic::Ordering::SeqCst) {
            let socket = match listener.listener.accept() {
                Ok((socket, _)) => socket,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(std::time::Duration::from_millis(1));
                    continue;
                }
                Err(error) => panic!("registered history: {error}"),
            };
            socket.set_nonblocking(false).unwrap();
            socket.set_read_timeout(Some(std::time::Duration::from_secs(10))).unwrap();
            socket.set_write_timeout(Some(std::time::Duration::from_secs(10))).unwrap();
            let mut stream = rustls::StreamOwned::new(rustls::ServerConnection::new(listener.tls.clone()).unwrap(), socket);
            let mut bytes = Vec::new();
            let mut buf = [0u8; 2048];
            loop {
                let n = stream.read(&mut buf).unwrap(); assert!(n > 0);
                bytes.extend_from_slice(&buf[..n]); assert!(bytes.len() < 1024 * 1024);
                if bytes.windows(4).any(|value| value == b"\r\n\r\n") { break; }
            }
            let request = std::str::from_utf8(&bytes).unwrap();
            let line = request.lines().next().unwrap();
            assert!(line.starts_with("GET "));
            let target = line.split_whitespace().nth(1).unwrap().split('?').next().unwrap();
            let history = listener.history.read().unwrap();
            let body = history.get(target).expect("only registered original history may be fetched");
            let response = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
            stream.write_all(response.as_bytes()).unwrap(); stream.write_all(body).unwrap(); stream.flush().unwrap();
            assert!(!stream.conn.is_handshaking()); count += 1;
        }
        listener.listener.set_nonblocking(false).unwrap();
        count
    }).await.unwrap()
}

async fn tcp_scan(
    listener: Arc<RegisteredTlsPeer>,
    page: PeerStreamScanResponseBody,
    expected: StreamScanRequestBody,
    from: AccountId,
    to: DidCoreId,
) -> usize {
    tokio::task::spawn_blocking(move || {
    let (mut stream, mut bytes, end) = registered_post(&listener);
    let mut buf = [0u8; 2048];
    let header = std::str::from_utf8(&bytes[..end]).unwrap();
    assert!(header.starts_with("POST /_arkret/peer/streams/scan HTTP/1.1"));
    let fields = header
        .lines()
        .filter_map(|v| {
            v.split_once(':')
                .map(|(k, v)| (k.to_ascii_lowercase(), v.trim().to_owned()))
        })
        .collect::<std::collections::BTreeMap<_, _>>();
    assert_eq!(
        fields.get("source-service-id"),
        Some(&from.station_id.to_string())
    );
    assert_eq!(fields.get("destination-service-id"), Some(&to.to_string()));
    assert!(
        fields.contains_key("signature-input")
            && fields.contains_key("signature")
            && fields.contains_key("content-digest")
    );
    let length = fields["content-length"].parse::<usize>().unwrap();
    assert!(length < 1024 * 1024);
    while bytes.len() < end + length {
        let n = stream.read(&mut buf).unwrap();
        assert!(n > 0);
        bytes.extend_from_slice(&buf[..n]);
    }
    let actual: StreamScanRequestBody = serde_json::from_slice(&bytes[end..end + length]).unwrap();
    assert_eq!(actual, expected);
    let body = arkret_canonical::canonical_json_bytes(&page).unwrap();
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(response.as_bytes()).unwrap();
    stream.write_all(&body).unwrap();
    stream.flush().unwrap();
    assert!(!stream.conn.is_handshaking());
    1
    }).await.unwrap()
}

#[tokio::test]
async fn accepted_forward_witness_reopens_then_executes_registered_prefix_without_new_submission() {
    let listener = registered_tls_peer();
    let base = format!("https://{}/", listener.listener.local_addr().unwrap());
    let (governor_state, governor_pool, _governor_lease) = station(base.clone());
    let (origin, origin_pool, _origin_lease) =
        station("https://forward-recovery-origin.internal/".into());
    register_original_peer_history(&listener, &governor_state, &governor_pool).await;
    let mut governor =
        historical_human::HumanFixture::new(&governor_pool, governor_state.service_did()).await;
    // The existing closed bootstrap facet must explicitly authorize the Origin
    // to receive plaintext. Membership/action grants alone grant no such right.
    // Author this before the unit is accepted; never patch accepted state.
    let disclosure_index = governor
        .unit
        .transactions
        .iter()
        .position(|tx| tx.event.kind == EventKind::RealmPlaintextVisibleServices)
        .unwrap();
    assert!(disclosure_index > 0);
    assert_eq!(
        governor
            .unit
            .transactions
            .iter()
            .filter(|tx| tx.event.kind == EventKind::RealmPlaintextVisibleServices)
            .count(),
        1
    );
    let mut disclosure: arkret_models_collaboration::governance::plaintext_visibility::PlaintextVisibleServicesPayload =
        serde_json::from_value(
            serde_json::to_value(&governor.unit.transactions[disclosure_index].event.payload).unwrap(),
        ).unwrap();
    assert_eq!(disclosure.services.len(), 1);
    assert_eq!(
        disclosure.services[0].service_id,
        governor_state.service_core_id()
    );
    assert_ne!(governor_state.service_core_id(), origin.service_core_id());
    disclosure.services.push(
        serde_json::from_value(serde_json::json!({
            "service_id":origin.service_core_id(), "service_kind":"station",
            "data_classes":["message_content"],
            "purposes":["accepted original recovery fixture"],
            "visibility":"private_plaintext"
        }))
        .unwrap(),
    );
    let disclosure_event = historical_human::signed_ordinary_event(
        &governor,
        &governor.unit.transactions[disclosure_index - 1],
        EventKind::RealmPlaintextVisibleServices,
        disclosure.to_value().unwrap(),
        governor.unit.transactions[disclosure_index]
            .commit
            .committed_at,
    );
    governor.unit.transactions[disclosure_index].event = disclosure_event;
    let source = PgAuthorityCommitStore {
        pool: governor_pool.clone(),
    };
    let mut previous_commit = None;
    for (index, transaction) in governor.unit.transactions.iter_mut().enumerate() {
        transaction.commit.event_ref = transaction.event.event_id.clone();
        transaction.producer_signer_fact = source
            .prepare_account_device_signer_fact(&transaction.event, transaction.commit.committed_at)
            .await
            .unwrap()
            .map(Into::into);
        assert!(transaction.producer_signer_fact.is_some());
        transaction.commit.producer_signer_fact_digest = transaction
            .producer_signer_fact
            .as_ref()
            .map(|fact| fact.digest().unwrap());
        transaction.commit.previous_commit_ref = previous_commit;
        seal_service_commit(&mut transaction.commit, &governor_state);
        previous_commit = Some(transaction.commit.commit_id.clone());
        governor.unit.submission.events[index] =
            EventAdmissionSubmission::new(transaction.event.clone());
    }
    governor.unit.exact_request_body = serde_json::to_vec(
        &SelfAuthoritySubmitRequestBody::OrdinaryRealmBootstrap(governor.unit.submission.clone()),
    )
    .unwrap();
    governor.admit(&governor_pool).await;
    assert_eq!(
        source
            .accepted_plaintext_visible_services(&governor.unit.transactions[0].event.realm_id,)
            .await
            .unwrap(),
        Some(disclosure)
    );
    let human = historical_human::HumanFixture::new(&origin_pool, origin.service_did()).await;
    let actor = ActorId::account(human.pcr.history.account.clone());
    let previous = governor.unit.transactions.last().unwrap();
    let at = previous.commit.committed_at + Duration::seconds(1);
    let owner = ActorId::account(governor.pcr.history.account.clone());
    let strand_event = historical_human::signed_ordinary_event(
        &governor,
        previous,
        EventKind::StrandCreate,
        serde_json::json!({"object":{
            "schema":"ak.schema.strand.v1", "realm_id":previous.event.realm_id,
            "tracks":{"discussion":{"is_primary":true,"profile":"discussion"}},
            "metadata":{"title":"forward recovery fixture discussion"}, "state":"active",
            "created_by":owner, "created_at":arkret_canonical::format_timestamp_canonical(at)
        }}),
        at,
    );
    let mut strand = historical_human::request_for_event(&governor, previous, strand_event, at);
    seal_service_commit(&mut strand.authority_commit.commit, &governor_state);
    let uow = PgEventCommitUnitOfWork::new(governor_pool.clone());
    Box::pin(uow.commit_event(strand.clone())).await.unwrap();
    // Membership is not an action grant. Read the actual accepted root cut,
    // then admit the owner's narrow Grant before the foreign member joins. The
    // Grant grants no membership; MessageCreate still runs after the real join.
    #[derive(diesel::QueryableByName)]
    struct RootCut {
        #[diesel(sql_type = diesel::sql_types::Jsonb)]
        controller_actor_id: serde_json::Value,
        #[diesel(sql_type = diesel::sql_types::Text)]
        authority_event_ref: String,
        #[diesel(sql_type = diesel::sql_types::BigInt)]
        authority_generation: i64,
    }
    use diesel_async::RunQueryDsl as _;
    let root_cut = {
        let mut conn = governor_pool.get().await.unwrap();
        diesel::sql_query(
            "SELECT controller_actor_id, authority_event_ref, authority_generation \
             FROM realm_authority_root_current_states WHERE realm_id=$1",
        )
        .bind::<diesel::sql_types::Text, _>(strand.authority_commit.event.realm_id.as_str())
        .get_result::<RootCut>(&mut *conn)
        .await
        .unwrap()
    };
    assert_eq!(
        serde_json::from_value::<ActorId>(root_cut.controller_actor_id).unwrap(),
        owner
    );
    let root_generation = u64::try_from(root_cut.authority_generation).unwrap();
    let previous = &strand.authority_commit;
    let grant_at = previous.commit.committed_at + Duration::seconds(1);
    let grant_payload: arkret_models_collaboration::events_payloads::CapabilityGrantPayload =
        serde_json::from_value(serde_json::json!({"grant": {
            "schema":"ak.schema.capability.v1",
            "realm_id":previous.event.realm_id,
            "issuer_id":owner,
            "subject":actor,
            "actions":["ak.message.create"],
            "resources":[{"kind":"realm","realm_id":previous.event.realm_id}],
            "issuer_authority_refs":[{
                "kind":"realm_root","realm_id":previous.event.realm_id,
                "authority_event_ref":root_cut.authority_event_ref,
                "authority_generation":(root_generation).to_string()
            }],
            "issued_at":arkret_canonical::format_timestamp_canonical(grant_at)
        }}))
        .unwrap();
    let grant_event = historical_human::signed_ordinary_event(
        &governor,
        previous,
        EventKind::CapabilityGrant,
        serde_json::to_value(grant_payload).unwrap(),
        grant_at,
    );
    let mut grant = historical_human::request_for_event(&governor, previous, grant_event, grant_at);
    // This is a fresh PG source candidate, not a cached authorizing capability.
    // The UOW independently prepares and compares it under its admission locks.
    let grant_fact = PgAuthorityCommitStore {
        pool: governor_pool.clone(),
    }
    .prepare_account_device_signer_fact(&grant.authority_commit.event, grant_at)
    .await
    .unwrap()
    .unwrap();
    grant.authority_commit.commit.producer_signer_fact_digest = Some(grant_fact.digest().unwrap());
    grant.authority_commit.producer_signer_fact = Some(grant_fact.into());
    seal_service_commit(&mut grant.authority_commit.commit, &governor_state);
    Box::pin(uow.commit_event(grant.clone())).await.unwrap();
    let previous = &grant.authority_commit;
    let mut join = Box::pin(foreign_request(&origin, &human, &governor, previous, EventKind::MemberState,
        serde_json::json!({"realm_id":previous.event.realm_id,"member_id":actor,"membership":"join","reason":"real forward recovery membership"}))).await;
    seal_service_commit(&mut join.authority_commit.commit, &governor_state);
    Box::pin(uow.commit_event(join.clone())).await.unwrap();
    let source = PgAuthorityCommitStore {
        pool: governor_pool.clone(),
    };
    let store = PgAuthorityCommitStore {
        pool: origin_pool.clone(),
    };
    store
        .install_committed_replica(&CommittedReplica {
            local_service_id: human.pcr.history.account.station_id.clone(),
            authority: join.authority_commit.expected_authority.clone(),
            historical_commit: None,
            event: join.authority_commit.event.clone(),
            commit: join.authority_commit.commit.clone(),
            producer_signer_fact: join.authority_commit.producer_signer_fact.clone(),
            genesis_event_ref: None,
            role: CommittedReplicaRole::OpeningJoin {
                member_account_id: human.pcr.history.account.clone(),
            },
            received_at: join.authority_commit.commit.committed_at,
            welcomes: vec![],
        })
        .await
        .unwrap();
    let realm = &join.authority_commit.event.realm_id;
    let material = source
        .member_station_bootstrap_material(
            realm,
            &human.pcr.history.account,
            &join.authority_commit.commit.commit_id,
        )
        .await
        .unwrap()
        .unwrap();
    let key = ed25519_dalek::SigningKey::from_bytes(&historical_human::station_authority_seed());
    let snapshot = coland_services::authority_commit::build_signed_realm_state_snapshot(
        &material,
        governor_state
            .service_verification_method("notary-key")
            .unwrap(),
        &key,
        Utc::now(),
    )
    .unwrap();
    arkret_signatures::detached_object::verify_detached_object_signature(
        &snapshot.signature,
        &arkret_canonical::unsigned_value(&snapshot, &["signature"]).unwrap(),
        arkret_wire::DetachedSignatureContext::RealmSnapshot,
        &arkret_signatures::PublicKeyMaterial::Ed25519Raw {
            bytes: key.verifying_key().to_bytes().to_vec(),
        },
    )
    .unwrap();
    store
        .install_replica_anchor(&ReplicaAnchorInstall {
            realm_id: realm.clone(),
            join_commit_id: join.authority_commit.commit.commit_id.clone(),
            governance_generation: material.governance_generation,
            snapshot_head: material.visible_stream_heads[0].clone(),
            visible_stream_heads: material.visible_stream_heads,
            current_state_entries: material.current_state_entries,
            verified_snapshot: snapshot,
        })
        .await
        .unwrap();
    let mut predecessor = Box::pin(foreign_request(&origin, &human, &governor, &join.authority_commit, EventKind::MessageCreate,
        serde_json::json!({"strand_id":arkret_wire::StrandId::from_event_id(&strand.authority_commit.event.event_id),"track_name":"discussion","content":{"kind":"ak.content.text","body":"valid prefix before a later invalid peer row","format":"plain"}}))).await;
    seal_service_commit(&mut predecessor.authority_commit.commit, &governor_state);
    Box::pin(uow.commit_event(predecessor.clone()))
        .await
        .unwrap();
    let mut target = Box::pin(foreign_request(&origin, &human, &governor, &predecessor.authority_commit, EventKind::MessageCreate,
        serde_json::json!({"strand_id":arkret_wire::StrandId::from_event_id(&strand.authority_commit.event.event_id),"track_name":"discussion","content":{"kind":"ak.content.text","body":"accepted original transport fixture","format":"plain"}}))).await;
    seal_service_commit(&mut target.authority_commit.commit, &governor_state);
    Box::pin(uow.commit_event(target.clone())).await.unwrap();
    let mut suffix = Box::pin(foreign_request(&origin, &human, &governor, &target.authority_commit, EventKind::MessageCreate,
        serde_json::json!({"strand_id":arkret_wire::StrandId::from_event_id(&strand.authority_commit.event.event_id),"track_name":"discussion","content":{"kind":"ak.content.text","body":"valid suffix beyond the accepted target","format":"plain"}}))).await;
    seal_service_commit(&mut suffix.authority_commit.commit, &governor_state);
    Box::pin(uow.commit_event(suffix.clone())).await.unwrap();
    let event = &target.authority_commit.event;
    let commit = &target.authority_commit.commit;
    assert!(
        store
            .committed_event(&event.event_id)
            .await
            .unwrap()
            .is_none()
    );
    let intent =
        SelfAuthoritySubmitRequestBody::Event(EventAdmissionSubmission::new(event.clone()));
    store.queue_event(event, commit.committed_at).await.unwrap();
    store
        .retain_forwarded_submission(event, &intent, commit.committed_at)
        .await
        .unwrap();
    store
        .retain_forwarded_acceptance(event, commit, commit.committed_at)
        .await
        .unwrap();
    drop(store);
    let reopened = PgAuthorityCommitStore {
        pool: origin_pool.clone(),
    };
    let queued = reopened
        .queued_event(&event.event_id)
        .await
        .unwrap()
        .unwrap();
    assert!(queued.committed.is_none());
    let witness = queued.forward_attempt.unwrap();
    assert_eq!(witness.accepted_commit, Some(commit.clone()));
    assert_eq!(witness.original_submission, Some(intent));
    let session = authenticated_context(&origin_pool, &human).await;
    let route =
        crate::routing::system::service_resolution::current_authenticated_service_resolution(
            &governor_state,
        )
        .await
        .unwrap();
    let boundary = route.method_history_evidence.boundary();
    let description = VerifiedServiceDescribeMetadata {
        supported_profiles: Vec::new(),
        service_id: governor_state.service_core_id(),
        service_kind: "station".into(),
        service_resolution: ResolutionCommitment {
            did: governor_state.service_did(),
            method_history_head: boundary.to_method_history_head.clone(),
            version_id: boundary.to_version_id.clone(),
        },
        http_json_base_url: base,
        trust_domain: governor_state.config().trust_domain.clone(),
        protocol_version: arkret_wire::PROTOCOL_VERSION.into(),
        supported_operation_bundles: vec![
            arkret_wire::role_describe_bundle_descriptor(arkret_wire::ServiceKind::Station)
                .unwrap()
                .operation_bundle_id
                .into(),
        ],
    };
    origin.test_install_service_route_fetcher(Arc::new(VerifiedSourceRoute(
        VerifiedRouteCandidate {
            evidence: route,
            description,
        },
    )));
    let nonce = Base64UrlString::new(arkret_canonical::base64url_encode([0x71; 32])).unwrap();
    let bundle = crate::routing::realm_join::local_authority_bundle(&governor_state, realm, &nonce)
        .await
        .unwrap();
    let mut keys = arkret_identity::RealmAuthorityKeyMap::new();
    for signature in [
        &bundle.genesis_commit.signature,
        &bundle.current_assertion.signature,
        &commit.signature,
        &predecessor.authority_commit.commit.signature,
        &suffix.authority_commit.commit.signature,
    ] {
        keys.insert_at(
            &signature.verification_method,
            signature.created_at,
            arkret_signatures::PublicKeyMaterial::Ed25519Raw {
                bytes: key.verifying_key().to_bytes().to_vec(),
            },
        );
    }
    let authority = arkret_identity::verify_realm_authority_bundle(
        &bundle,
        &arkret_identity::RealmAuthorityFreshness::new(Utc::now(), nonce),
        &keys,
    )
    .unwrap();
    let mut located = crate::routing::realm_join::LocatedRealmAuthority {
        bundle,
        authority,
        keys,
    };
    let scan = StreamScanRequestBody {
        realm_id: realm.clone(),
        stream_ref: commit.stream_ref.clone(),
        direction: StreamScanDirection::After(Some(join.authority_commit.commit.stream_position)),
        limit: 128,
    };
    let coland_storage::PeerStreamScan::Page(page) = source
        .scan_stream_for_peer(
            &scan,
            &human.pcr.history.account.station_id,
            &governor_state.service_core_id(),
        )
        .await
        .unwrap()
    else {
        panic!("actually joined Origin is authorized for the real peer prefix")
    };
    page.validate_for_request(&scan).unwrap();
    let original_target = page
        .committed_events
        .iter()
        .find(|row| row.commit().commit_id == commit.commit_id)
        .unwrap();
    let arkret_wire::CommittedEventView::Full(original_target) = original_target else {
        panic!("the explicitly authorized plaintext target must be a real Full row")
    };
    assert_eq!(&original_target.event, event);
    assert_eq!(&original_target.commit, commit);
    let archived_fact = source.producer_signer_fact(event, commit).await.unwrap();
    assert!(archived_fact.is_some());
    assert_eq!(archived_fact, target.authority_commit.producer_signer_fact);
    assert_eq!(
        page.producer_signer_facts
            .iter()
            .find(|entry| entry.target.commit_id == commit.commit_id)
            .map(|entry| &entry.producer_signer_fact),
        archived_fact.as_ref(),
    );
    assert!(target.authority_commit.producer_signer_fact.is_some());
    let before_head = reopened
        .held_stream_head_commit(&commit.stream_ref)
        .await
        .unwrap();
    let mut withheld_page = page.clone();
    let unchanged = recovery_acceptance_rows(&origin_pool).await;
    for mutation in 0..15 {
        let mut bad = page.clone();
        match mutation {
            0 => bad.producer_signer_facts.clear(),
            1 => bad
                .producer_signer_facts
                .insert(0, bad.producer_signer_facts[0].clone()),
            2 => {
                let mut extra = bad.producer_signer_facts[0].clone();
                extra.target.event_id = arkret_wire::EventId::from_digest(
                    arkret_canonical::DigestSuite::Sha256,
                    [250; 32],
                );
                bad.producer_signer_facts.push(extra);
            }
            3 => {
                bad.producer_signer_facts[0].target.event_id = arkret_wire::EventId::from_digest(
                    arkret_canonical::DigestSuite::Sha256,
                    [251; 32],
                )
            }
            9 => {
                bad.producer_signer_facts[0].target.stream_ref =
                    arkret_wire::CommitStreamRef::Realm {
                        realm_id: arkret_wire::RealmId::from_event_id(
                            &arkret_wire::EventId::from_digest(
                                arkret_canonical::DigestSuite::Sha256,
                                [249; 32],
                            ),
                        ),
                    };
            }
            10 => bad.producer_signer_facts[0].target.stream_position += 1,
            11 => {
                bad.producer_signer_facts[0].target.commit_id =
                    arkret_wire::RealmCommitId::from_digest([248; 32])
            }
            13 => {
                let arkret_wire::CommittedEventView::Full(last) =
                    bad.committed_events.last_mut().unwrap()
                else {
                    panic!("real suffix is Full");
                };
                last.commit.signature.signature =
                    Base64UrlString::new(arkret_canonical::base64url_encode([0u8; 64])).unwrap();
            }
            12 => {
                let arkret_wire::CommittedEventView::Full(last) =
                    bad.committed_events.last_mut().unwrap()
                else {
                    panic!("real suffix is Full");
                };
                assert_eq!(last.commit, suffix.authority_commit.commit);
                last.commit.signature.signed_digest =
                    arkret_wire::Hash::new(format!("sha256:{}", "d".repeat(64))).unwrap();
            }
            _ => {
                let arkret_wire::CommittedEventView::Full(target) = bad
                    .committed_events
                    .iter_mut()
                    .find(|row| row.commit().commit_id == commit.commit_id)
                    .unwrap()
                else {
                    panic!("real accepted target is Full")
                };
                match mutation {
                    4 => {
                        target.commit.commit_id = arkret_wire::RealmCommitId::from_digest([252; 32])
                    }
                    5 => {
                        target.commit.signature.signed_digest =
                            arkret_wire::Hash::new(format!("sha256:{}", "f".repeat(64))).unwrap()
                    }
                    6 => target.commit.previous_commit_ref = None,
                    7 => {
                        target.commit.producer_signer_fact_digest = Some(
                            arkret_wire::Hash::new(format!("sha256:{}", "e".repeat(64))).unwrap(),
                        )
                    }
                    8 => target.event.producer_proof.as_mut().unwrap().jws.push('A'),
                    14 => {
                        let proof = target.event.producer_proof.as_mut().unwrap();
                        let (prefix, signature) = proof.jws.rsplit_once('.').unwrap();
                        let mut signature = arkret_canonical::base64url_decode(signature).unwrap();
                        assert_eq!(signature.len(), 64);
                        signature[0] ^= 1;
                        proof.jws =
                            format!("{prefix}.{}", arkret_canonical::base64url_encode(signature));
                    }
                    _ => unreachable!(),
                }
            }
        }
        if mutation == 14 {
            // Preserve the complete wire shape and all accepted coordinates;
            // this case must reach the producer's cryptographic verifier.
            bad.validate_for_request(&scan).unwrap();
        }
        let fault_server = tokio::spawn(tcp_scan(
            listener.clone(),
            bad,
            scan.clone(),
            human.pcr.history.account.clone(),
            governor_state.service_core_id(),
        ));
        let refused = Box::pin(super::super::replica_anchor::ensure_forwarded_target(
            &origin,
            &governor_state.service_core_id(),
            event,
            Some(commit),
            &mut located,
            &session,
        ))
        .await;
        eprintln!("[2133-peer] mutation={mutation} result={refused:?}");
        assert!(
            refused.is_err(),
            "peer scan mutation {mutation} was installed"
        );
        assert_eq!(fault_server.await.unwrap(), 1);
        let after = recovery_acceptance_rows(&origin_pool).await;
        let changed = unchanged
            .as_object()
            .unwrap()
            .keys()
            .filter(|table| after[*table] != unchanged[*table])
            .collect::<Vec<_>>();
        assert!(
            changed.is_empty(),
            "peer scan mutation {mutation} changed accepted rows in {changed:?}"
        );
    }
    let target_row = withheld_page
        .committed_events
        .iter_mut()
        .find(|row| row.commit().event_ref == event.event_id)
        .unwrap();
    *target_row =
        arkret_wire::CommittedEventView::Withheld(arkret_wire::CommittedEventWithheldView {
            commit: commit.clone(),
            event_disclosure: arkret_wire::EventDisclosure {
                status: arkret_wire::EventDisclosureStatus::Withheld,
            },
        });
    withheld_page
        .producer_signer_facts
        .retain(|entry| entry.target.commit_id != commit.commit_id);
    withheld_page.validate_for_request(&scan).unwrap();
    let fault_server = tokio::spawn(tcp_scan(
        listener.clone(),
        withheld_page,
        scan.clone(),
        human.pcr.history.account.clone(),
        governor_state.service_core_id(),
    ));
    let refused = Box::pin(super::super::replica_anchor::ensure_forwarded_target(
        &origin,
        &governor_state.service_core_id(),
        event,
        Some(commit),
        &mut located,
        &session,
    ))
    .await
    .unwrap_err();
    assert!(
        refused.contains("withheld"),
        "actual withheld-target refusal: {refused}"
    );
    assert_eq!(fault_server.await.unwrap(), 1);
    assert_eq!(
        reopened
            .held_stream_head_commit(&commit.stream_ref)
            .await
            .unwrap(),
        before_head
    );
    assert!(
        reopened
            .committed_event(&event.event_id)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        reopened
            .queued_event(&event.event_id)
            .await
            .unwrap()
            .unwrap()
            .forward_attempt
            .as_ref()
            .unwrap()
            .accepted_commit
            .as_ref(),
        Some(commit)
    );
    let mut bad_fact_page = page.clone();
    bad_fact_page
        .producer_signer_facts
        .iter_mut()
        .find(|entry| entry.target.commit_id == commit.commit_id)
        .unwrap()
        .producer_signer_fact
        .as_account_device_mut()
        .unwrap()
        .key
        .governance_generation += 1;
    let fault_server = tokio::spawn(tcp_scan(
        listener.clone(),
        bad_fact_page,
        scan.clone(),
        human.pcr.history.account.clone(),
        governor_state.service_core_id(),
    ));
    assert!(
        Box::pin(super::super::replica_anchor::ensure_forwarded_target(
            &origin,
            &governor_state.service_core_id(),
            event,
            Some(commit),
            &mut located,
            &session
        ))
        .await
        .is_err()
    );
    assert_eq!(fault_server.await.unwrap(), 1);
    assert_eq!(
        reopened
            .held_stream_head_commit(&commit.stream_ref)
            .await
            .unwrap(),
        before_head
    );
    assert!(
        reopened
            .committed_event(&event.event_id)
            .await
            .unwrap()
            .is_none()
    );
    let server = tokio::spawn(tcp_scan(
        listener.clone(),
        page,
        scan,
        human.pcr.history.account.clone(),
        governor_state.service_core_id(),
    ));
    let recovered = Box::pin(super::super::replica_anchor::ensure_forwarded_target(
        &origin,
        &governor_state.service_core_id(),
        event,
        Some(commit),
        &mut located,
        &session,
    ))
    .await
    .unwrap()
    .unwrap();
    assert_eq!(recovered, *commit);
    assert_eq!(server.await.unwrap(), 1);
    let installed = reopened
        .committed_event(&event.event_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(installed.event, *event);
    assert_eq!(installed.commit, *commit);
    assert_eq!(
        reopened.producer_signer_fact(event, commit).await.unwrap(),
        target.authority_commit.producer_signer_fact
    );
    let held = reopened
        .held_stream_head_commit(&commit.stream_ref)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(held, *commit);
    // The held branch performs no network operation. It revalidates the exact
    // original/fact/prefix and caller disclosure, not today's producer key.
    assert_eq!(
        Box::pin(super::super::replica_anchor::ensure_forwarded_target(
            &origin,
            &governor_state.service_core_id(),
            event,
            Some(commit),
            &mut located,
            &session
        ))
        .await
        .unwrap(),
        Some(commit.clone())
    );
    let mut fork = commit.clone();
    fork.committed_at += Duration::milliseconds(1);
    seal_service_commit(&mut fork, &governor_state);
    assert!(
        Box::pin(super::super::replica_anchor::ensure_forwarded_target(
            &origin,
            &governor_state.service_core_id(),
            event,
            Some(&fork),
            &mut located,
            &session
        ))
        .await
        .is_err()
    );
    assert_eq!(
        reopened
            .held_stream_head_commit(&commit.stream_ref)
            .await
            .unwrap(),
        Some(held.clone())
    );
    let mut expired = session.clone();
    expired.expires_at = Utc::now() - Duration::seconds(1);
    assert!(
        Box::pin(super::super::replica_anchor::ensure_forwarded_target(
            &origin,
            &governor_state.service_core_id(),
            event,
            Some(commit),
            &mut located,
            &expired
        ))
        .await
        .is_err()
    );
    assert_eq!(
        reopened
            .held_stream_head_commit(&commit.stream_ref)
            .await
            .unwrap(),
        Some(held)
    );
}

fn station_with_webvh(
    url: String,
) -> (AppState, PgPool, Arc<dyn coland_storage::PersistenceStore>) {
    station_with_webvh_provider(url, false)
}

fn station_with_webvh_provider(
    url: String,
    embedded: bool,
) -> (AppState, PgPool, Arc<dyn coland_storage::PersistenceStore>) {
    let mut external = coland_test_support::app_config();
    external.public_base_url = url.clone();
    external.notary_signing_key_seed = Some([83; 32]);
    external.seed_demo_data = false;
    external.development_mode = true;
    external.did_resolver_allow_methods.push("webvh".into());
    external.embedded_webvh_provider_enabled = embedded;
    let (leased, pool) = coland_test_support::app_state_with_pool(external.clone());
    let local = crate::config::AppConfig {
        public_base_url: url,
        notary_signing_key_seed: Some([83; 32]),
        seed_demo_data: false,
        development_mode: true,
        did_resolver_allow_methods: external.did_resolver_allow_methods.clone(),
        embedded_webvh_provider_enabled: embedded,
        ..crate::config::AppConfig::test_default()
    };
    assert_eq!(local.trust_domain, external.trust_domain);
    use coland_test_support::AppStateTestExt as _;
    let keep_lease = leased.test_persistence();
    let state = AppState::new_with_service_identity(
        local,
        coland_storage_postgres::Db {
            pool: Some(pool.clone()),
        },
        keep_lease.clone(),
        coland_test_support::fixture_service_identity(&external),
        leased.service_resolution_commitment().as_ref().clone(),
        [83; 32],
    );
    (state, pool, keep_lease)
}

fn seal_service_commit(commit: &mut arkret_wire::RealmCommit, governor: &AppState) {
    let body =
        arkret_canonical::canonical::unsigned_value(commit, &["commit_id", "signature"]).unwrap();
    commit.commit_id = arkret_wire::RealmCommitId::from_digest(arkret_canonical::sha256_bytes(
        &arkret_canonical::canonical_json_bytes(&body).unwrap(),
    ));
    commit.signature = arkret_signatures::detached_object::sign_detached_object(
        &arkret_canonical::canonical::unsigned_value(commit, &["signature"]).unwrap(),
        arkret_wire::DetachedSignatureContext::RealmCommit,
        governor.service_verification_method("notary-key").unwrap(),
        commit.committed_at,
        &ed25519_dalek::SigningKey::from_bytes(&historical_human::station_authority_seed()),
    )
    .unwrap();
    commit.verify_commit_id_matches_content().unwrap();
}
#[tokio::test]
async fn accepted_own_opening_join_without_anchor_uses_original_peer_fact_then_signed_bootstrap() {
    let listener = registered_tls_peer();
    let base = format!("https://{}/", listener.listener.local_addr().unwrap());
    let (governor_state, governor_pool, _governor_lease) = station_with_webvh(base.clone());
    let (origin, origin_pool, _origin_lease) =
        station_with_webvh("https://forward-recovery-origin.internal/".into());
    let mut governor =
        historical_human::HumanFixture::new(&governor_pool, governor_state.service_did()).await;
    // The existing closed bootstrap facet must explicitly authorize the Origin
    // to receive plaintext. Membership/action grants alone grant no such right.
    // Author this before the unit is accepted; never patch accepted state.
    let disclosure_index = governor
        .unit
        .transactions
        .iter()
        .position(|tx| tx.event.kind == EventKind::RealmPlaintextVisibleServices)
        .unwrap();
    assert!(disclosure_index > 0);
    assert_eq!(
        governor
            .unit
            .transactions
            .iter()
            .filter(|tx| tx.event.kind == EventKind::RealmPlaintextVisibleServices)
            .count(),
        1
    );
    let mut disclosure: arkret_models_collaboration::governance::plaintext_visibility::PlaintextVisibleServicesPayload =
        serde_json::from_value(
            serde_json::to_value(&governor.unit.transactions[disclosure_index].event.payload).unwrap(),
        ).unwrap();
    assert_eq!(disclosure.services.len(), 1);
    assert_eq!(
        disclosure.services[0].service_id,
        governor_state.service_core_id()
    );
    assert_ne!(governor_state.service_core_id(), origin.service_core_id());
    disclosure.services.push(
        serde_json::from_value(serde_json::json!({
            "service_id":origin.service_core_id(), "service_kind":"station",
            "data_classes":["message_content"],
            "purposes":["accepted original recovery fixture"],
            "visibility":"private_plaintext"
        }))
        .unwrap(),
    );
    let disclosure_event = historical_human::signed_ordinary_event(
        &governor,
        &governor.unit.transactions[disclosure_index - 1],
        EventKind::RealmPlaintextVisibleServices,
        disclosure.to_value().unwrap(),
        governor.unit.transactions[disclosure_index]
            .commit
            .committed_at,
    );
    governor.unit.transactions[disclosure_index].event = disclosure_event;
    let source = PgAuthorityCommitStore {
        pool: governor_pool.clone(),
    };
    let mut previous_commit = None;
    for (index, transaction) in governor.unit.transactions.iter_mut().enumerate() {
        transaction.commit.event_ref = transaction.event.event_id.clone();
        transaction.producer_signer_fact = source
            .prepare_account_device_signer_fact(&transaction.event, transaction.commit.committed_at)
            .await
            .unwrap()
            .map(Into::into);
        assert!(transaction.producer_signer_fact.is_some());
        transaction.commit.producer_signer_fact_digest = transaction
            .producer_signer_fact
            .as_ref()
            .map(|fact| fact.digest().unwrap());
        transaction.commit.previous_commit_ref = previous_commit;
        seal_service_commit(&mut transaction.commit, &governor_state);
        previous_commit = Some(transaction.commit.commit_id.clone());
        governor.unit.submission.events[index] =
            EventAdmissionSubmission::new(transaction.event.clone());
    }
    governor.unit.exact_request_body = serde_json::to_vec(
        &SelfAuthoritySubmitRequestBody::OrdinaryRealmBootstrap(governor.unit.submission.clone()),
    )
    .unwrap();
    governor.admit(&governor_pool).await;
    assert_eq!(
        source
            .accepted_plaintext_visible_services(&governor.unit.transactions[0].event.realm_id,)
            .await
            .unwrap(),
        Some(disclosure)
    );
    let human = historical_human::HumanFixture::new(&origin_pool, origin.service_did()).await;
    let actor = ActorId::account(human.pcr.history.account.clone());
    let previous = governor.unit.transactions.last().unwrap();
    let at = previous.commit.committed_at + Duration::seconds(1);
    let owner = ActorId::account(governor.pcr.history.account.clone());
    let strand_event = historical_human::signed_ordinary_event(
        &governor,
        previous,
        EventKind::StrandCreate,
        serde_json::json!({"object":{
            "schema":"ak.schema.strand.v1", "realm_id":previous.event.realm_id,
            "tracks":{"discussion":{"is_primary":true,"profile":"discussion"}},
            "metadata":{"title":"forward recovery fixture discussion"}, "state":"active",
            "created_by":owner, "created_at":arkret_canonical::format_timestamp_canonical(at)
        }}),
        at,
    );
    let mut strand = historical_human::request_for_event(&governor, previous, strand_event, at);
    seal_service_commit(&mut strand.authority_commit.commit, &governor_state);
    let uow = PgEventCommitUnitOfWork::new(governor_pool.clone());
    scenario_future(|| async { uow.commit_event(strand.clone()).await })
        .await
        .unwrap();
    // Membership is not an action grant. Read the actual accepted root cut,
    // then admit the owner's narrow Grant before the foreign member joins. The
    // Grant grants no membership; MessageCreate still runs after the real join.
    #[derive(diesel::QueryableByName)]
    struct RootCut {
        #[diesel(sql_type = diesel::sql_types::Jsonb)]
        controller_actor_id: serde_json::Value,
        #[diesel(sql_type = diesel::sql_types::Text)]
        authority_event_ref: String,
        #[diesel(sql_type = diesel::sql_types::BigInt)]
        authority_generation: i64,
    }
    use diesel_async::RunQueryDsl as _;
    let root_cut = {
        let mut conn = governor_pool.get().await.unwrap();
        diesel::sql_query(
            "SELECT controller_actor_id, authority_event_ref, authority_generation \
             FROM realm_authority_root_current_states WHERE realm_id=$1",
        )
        .bind::<diesel::sql_types::Text, _>(strand.authority_commit.event.realm_id.as_str())
        .get_result::<RootCut>(&mut *conn)
        .await
        .unwrap()
    };
    assert_eq!(
        serde_json::from_value::<ActorId>(root_cut.controller_actor_id).unwrap(),
        owner
    );
    let root_generation = u64::try_from(root_cut.authority_generation).unwrap();
    let previous = &strand.authority_commit;
    let grant_at = previous.commit.committed_at + Duration::seconds(1);
    let grant_payload: arkret_models_collaboration::events_payloads::CapabilityGrantPayload =
        serde_json::from_value(serde_json::json!({"grant": {
            "schema":"ak.schema.capability.v1",
            "realm_id":previous.event.realm_id,
            "issuer_id":owner,
            "subject":actor,
            "actions":["ak.message.create"],
            "resources":[{"kind":"realm","realm_id":previous.event.realm_id}],
            "issuer_authority_refs":[{
                "kind":"realm_root","realm_id":previous.event.realm_id,
                "authority_event_ref":root_cut.authority_event_ref,
                "authority_generation":(root_generation).to_string()
            }],
            "issued_at":arkret_canonical::format_timestamp_canonical(grant_at)
        }}))
        .unwrap();
    let grant_event = historical_human::signed_ordinary_event(
        &governor,
        previous,
        EventKind::CapabilityGrant,
        serde_json::to_value(grant_payload).unwrap(),
        grant_at,
    );
    let mut grant = historical_human::request_for_event(&governor, previous, grant_event, grant_at);
    // This is a fresh PG source candidate, not a cached authorizing capability.
    // The UOW independently prepares and compares it under its admission locks.
    let grant_fact = PgAuthorityCommitStore {
        pool: governor_pool.clone(),
    }
    .prepare_account_device_signer_fact(&grant.authority_commit.event, grant_at)
    .await
    .unwrap()
    .unwrap();
    grant.authority_commit.commit.producer_signer_fact_digest = Some(grant_fact.digest().unwrap());
    grant.authority_commit.producer_signer_fact = Some(grant_fact.into());
    seal_service_commit(&mut grant.authority_commit.commit, &governor_state);
    scenario_future(|| async { uow.commit_event(grant.clone()).await })
        .await
        .unwrap();
    let previous = &grant.authority_commit;
    let mut join = scenario_future(|| async { foreign_request(&origin, &human, &governor, previous, EventKind::MemberState,
        serde_json::json!({"realm_id":previous.event.realm_id,"member_id":actor,"membership":"join","reason":"real forward recovery membership"})).await }).await;
    seal_service_commit(&mut join.authority_commit.commit, &governor_state);
    scenario_future(|| async { uow.commit_event(join.clone()).await })
        .await
        .unwrap();
    let source = PgAuthorityCommitStore {
        pool: governor_pool.clone(),
    };
    let store = PgAuthorityCommitStore {
        pool: origin_pool.clone(),
    };
    let realm = &join.authority_commit.event.realm_id;
    let event = &join.authority_commit.event;
    let commit = &join.authority_commit.commit;
    let key = ed25519_dalek::SigningKey::from_bytes(&historical_human::station_authority_seed());
    let session = authenticated_context(&origin_pool, &human).await;
    let route =
        crate::routing::system::service_resolution::current_authenticated_service_resolution(
            &governor_state,
        )
        .await
        .unwrap();
    let boundary = route.method_history_evidence.boundary();
    let description = VerifiedServiceDescribeMetadata {
        supported_profiles: Vec::new(),
        service_id: governor_state.service_core_id(),
        service_kind: "station".into(),
        service_resolution: ResolutionCommitment {
            did: governor_state.service_did(),
            method_history_head: boundary.to_method_history_head.clone(),
            version_id: boundary.to_version_id.clone(),
        },
        http_json_base_url: base,
        trust_domain: governor_state.config().trust_domain.clone(),
        protocol_version: arkret_wire::PROTOCOL_VERSION.into(),
        supported_operation_bundles: vec![
            arkret_wire::role_describe_bundle_descriptor(arkret_wire::ServiceKind::Station)
                .unwrap()
                .operation_bundle_id
                .into(),
        ],
    };
    origin.test_install_service_route_fetcher(Arc::new(VerifiedSourceRoute(
        VerifiedRouteCandidate {
            evidence: route,
            description,
        },
    )));
    let nonce = Base64UrlString::new(arkret_canonical::base64url_encode([0x71; 32])).unwrap();
    let bundle = crate::routing::realm_join::local_authority_bundle(&governor_state, realm, &nonce)
        .await
        .unwrap();
    let mut keys = arkret_identity::RealmAuthorityKeyMap::new();
    for signature in [
        &bundle.genesis_commit.signature,
        &bundle.current_assertion.signature,
        &commit.signature,
    ] {
        keys.insert_at(
            &signature.verification_method,
            signature.created_at,
            arkret_signatures::PublicKeyMaterial::Ed25519Raw {
                bytes: key.verifying_key().to_bytes().to_vec(),
            },
        );
    }
    let authority = arkret_identity::verify_realm_authority_bundle(
        &bundle,
        &arkret_identity::RealmAuthorityFreshness::new(Utc::now(), nonce),
        &keys,
    )
    .unwrap();
    let mut located = crate::routing::realm_join::LocatedRealmAuthority {
        bundle,
        authority,
        keys,
    };
    store
        .record_remote_authority(&located.current_authority(), &origin.service_core_id())
        .await
        .unwrap();
    store.queue_event(event, commit.committed_at).await.unwrap();
    let intent =
        SelfAuthoritySubmitRequestBody::Event(EventAdmissionSubmission::new(event.clone()));
    store
        .retain_forwarded_submission(event, &intent, commit.committed_at)
        .await
        .unwrap();
    store
        .retain_forwarded_acceptance(event, commit, commit.committed_at)
        .await
        .unwrap();
    assert!(
        store
            .replica_anchor_for_stream(&commit.stream_ref)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .committed_event(&event.event_id)
            .await
            .unwrap()
            .is_none()
    );
    let no_write = opening_footprint(&origin_pool, realm).await;
    // A bare original or the wrong authenticated Account never starts a scan.
    assert!(
        scenario_future(|| async {
            super::super::replica_anchor::ensure_forwarded_target(
                &origin,
                &governor_state.service_core_id(),
                event,
                None,
                &mut located,
                &session,
            )
            .await
        })
        .await
        .is_err()
    );
    let mut other_session = session.clone();
    other_session.session_grant.as_mut().unwrap().account_id = governor.pcr.history.account.clone();
    assert!(
        scenario_future(|| async {
            super::super::replica_anchor::ensure_forwarded_target(
                &origin,
                &governor_state.service_core_id(),
                event,
                Some(commit),
                &mut located,
                &other_session,
            )
            .await
        })
        .await
        .is_err()
    );
    assert_eq!(opening_footprint(&origin_pool, realm).await, no_write);
    let scan = StreamScanRequestBody {
        realm_id: realm.clone(),
        stream_ref: commit.stream_ref.clone(),
        direction: StreamScanDirection::Before(Some(commit.stream_position + 1)),
        limit: 1,
    };
    let coland_storage::PeerStreamScan::Page(page) = source
        .scan_stream_for_peer(
            &scan,
            &human.pcr.history.account.station_id,
            &governor_state.service_core_id(),
        )
        .await
        .unwrap()
    else {
        panic!("Gov accepted member grants its routed Station the opening floor");
    };
    page.validate_for_request(&scan).unwrap();
    let full = page
        .committed_events
        .iter()
        .find(|item| item.commit().commit_id == commit.commit_id)
        .unwrap();
    assert!(
        matches!(full, arkret_wire::CommittedEventView::Full(view) if view.event == *event && view.commit == *commit)
    );
    let archived = source
        .producer_signer_fact(event, commit)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        page.producer_signer_facts
            .iter()
            .find(|f| f.target.commit_id == commit.commit_id)
            .unwrap()
            .producer_signer_fact,
        archived
    );
    let mut withheld = page.clone();
    withheld.committed_events = vec![arkret_wire::CommittedEventView::Withheld(
        arkret_wire::CommittedEventWithheldView {
            commit: commit.clone(),
            event_disclosure: arkret_wire::EventDisclosure {
                status: arkret_wire::EventDisclosureStatus::Withheld,
            },
        },
    )];
    withheld.producer_signer_facts.clear();
    let reply = tokio::spawn(tcp_scan(
        listener.clone(),
        withheld,
        scan.clone(),
        human.pcr.history.account.clone(),
        governor_state.service_core_id(),
    ));
    assert!(
        scenario_future(|| async {
            super::super::replica_anchor::ensure_forwarded_target(
                &origin,
                &governor_state.service_core_id(),
                event,
                Some(commit),
                &mut located,
                &session,
            )
            .await
        })
        .await
        .is_err()
    );
    assert_eq!(reply.await.unwrap(), 1);
    assert_eq!(opening_footprint(&origin_pool, realm).await, no_write);
    let mut missing_fact = page.clone();
    missing_fact.producer_signer_facts.clear();
    let reply = tokio::spawn(tcp_scan(
        listener.clone(),
        missing_fact,
        scan.clone(),
        human.pcr.history.account.clone(),
        governor_state.service_core_id(),
    ));
    assert!(
        scenario_future(|| async {
            super::super::replica_anchor::ensure_forwarded_target(
                &origin,
                &governor_state.service_core_id(),
                event,
                Some(commit),
                &mut located,
                &session,
            )
            .await
        })
        .await
        .is_err()
    );
    assert_eq!(reply.await.unwrap(), 1);
    assert_eq!(opening_footprint(&origin_pool, realm).await, no_write);
    let response_listener = listener.clone();
    let response_governor = governor_state.clone();
    let response_pool = governor_pool.clone();
    let response_account = human.pcr.history.account.clone();
    let response_commit = commit.clone();
    let history_stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let response_stop = history_stop.clone();
    let reply = tokio::spawn(async move {
        assert_eq!(
            tcp_scan(
                response_listener.clone(),
                page,
                scan,
                response_account.clone(),
                response_governor.service_core_id()
            )
            .await,
            1
        );
        assert_eq!(
            tcp_opening_bootstrap(
                response_listener,
                response_governor,
                response_pool,
                response_account,
                response_commit,
                response_stop,
            )
            .await,
            1
        );
        2
    });
    let original = scenario_future(|| async {
        super::super::replica_anchor::ensure_forwarded_target(
            &origin,
            &governor_state.service_core_id(),
            event,
            Some(commit),
            &mut located,
            &session,
        )
        .await
    })
    .await;
    history_stop.store(true, std::sync::atomic::Ordering::SeqCst);
    let original = original.unwrap().unwrap();
    assert_eq!(original, *commit);
    assert_eq!(reply.await.unwrap(), 2);
    let held = store
        .committed_event(&event.event_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(held.event, *event);
    assert_eq!(held.commit, *commit);
    assert_eq!(
        store.producer_signer_fact(event, commit).await.unwrap(),
        Some(archived)
    );
    let anchor = store
        .replica_anchor_for_stream(&commit.stream_ref)
        .await
        .unwrap()
        .unwrap();
    assert!(anchor.anchored_head.is_some());
    assert_eq!(anchor.join_commit, *commit);
    let before_replay = opening_footprint(&origin_pool, realm).await;
    assert_eq!(
        scenario_future(|| async {
            super::super::replica_anchor::ensure_forwarded_target(
                &origin,
                &governor_state.service_core_id(),
                event,
                Some(commit),
                &mut located,
                &session,
            )
            .await
        })
        .await
        .unwrap(),
        Some(commit.clone())
    );
    assert_eq!(opening_footprint(&origin_pool, realm).await, before_replay);

    // Alice remains joined while Bob joins at the same Station after an
    // unheld Realm successor. OpeningJoin must not skip that gap: recovery
    // reads the authorized continuous prefix and keeps Alice's old anchor.
    register_original_peer_history(&listener, &governor_state, &governor_pool).await;
    let bob = historical_human::HumanFixture::new(&origin_pool, origin.service_did()).await;
    let bob_actor = ActorId::account(bob.pcr.history.account.clone());
    let gap_at = commit.committed_at + Duration::seconds(1);
    let gap_event = historical_human::signed_ordinary_event(
        &governor,
        &join.authority_commit,
        EventKind::RealmProfile,
        serde_json::json!({"schema":"ak.schema.realm_profile.v1","title":"Authorized held-prefix gap"}),
        gap_at,
    );
    let mut gap =
        historical_human::request_for_event(&governor, &join.authority_commit, gap_event, gap_at);
    seal_service_commit(&mut gap.authority_commit.commit, &governor_state);
    gap.realm_fanout_source = Some(EventAdmissionSubmission::new(
        gap.authority_commit.event.clone(),
    ));
    scenario_future(|| async { uow.commit_event(gap.clone()).await })
        .await
        .unwrap();
    let mut bob_join = scenario_future(|| async { foreign_request(
        &origin, &bob, &governor, &gap.authority_commit, EventKind::MemberState,
        serde_json::json!({"realm_id":realm,"member_id":bob_actor,"membership":"join","reason":"second hosted member"}),
    ).await }).await;
    seal_service_commit(&mut bob_join.authority_commit.commit, &governor_state);
    scenario_future(|| async { uow.commit_event(bob_join.clone()).await })
        .await
        .unwrap();
    let bob_event = &bob_join.authority_commit.event;
    let bob_commit = &bob_join.authority_commit.commit;
    let bob_session = authenticated_context(&origin_pool, &bob).await;
    store
        .queue_event(bob_event, bob_commit.committed_at)
        .await
        .unwrap();
    let bob_intent =
        SelfAuthoritySubmitRequestBody::Event(EventAdmissionSubmission::new(bob_event.clone()));
    store
        .retain_forwarded_submission(bob_event, &bob_intent, bob_commit.committed_at)
        .await
        .unwrap();
    store
        .retain_forwarded_acceptance(bob_event, bob_commit, bob_commit.committed_at)
        .await
        .unwrap();
    let opening_scan = StreamScanRequestBody {
        realm_id: realm.clone(),
        stream_ref: commit.stream_ref.clone(),
        direction: StreamScanDirection::Before(Some(bob_commit.stream_position + 1)),
        limit: 1,
    };
    let continuous_scan = StreamScanRequestBody {
        direction: StreamScanDirection::After(Some(commit.stream_position)),
        limit: 128,
        ..opening_scan.clone()
    };
    let coland_storage::PeerStreamScan::Page(opening_page) = source
        .scan_stream_for_peer(
            &opening_scan,
            &origin.service_core_id(),
            &governor_state.service_core_id(),
        )
        .await
        .unwrap()
    else {
        panic!("the joined hosted members authorize the opening scan")
    };
    let coland_storage::PeerStreamScan::Page(continuous_page) = source
        .scan_stream_for_peer(
            &continuous_scan,
            &origin.service_core_id(),
            &governor_state.service_core_id(),
        )
        .await
        .unwrap()
    else {
        panic!("Alice still authorizes the continuous gap")
    };
    assert_eq!(continuous_page.committed_events.len(), 2);
    assert_eq!(
        continuous_page.committed_events[0].commit(),
        &gap.authority_commit.commit
    );
    assert_eq!(continuous_page.committed_events[1].commit(), bob_commit);
    assert!(
        store
            .committed_event(&gap.authority_commit.event.event_id)
            .await
            .unwrap()
            .is_none()
    );
    let reply_listener = listener.clone();
    let reply_account = bob.pcr.history.account.clone();
    let reply_governor = governor_state.service_core_id();
    let continuous_stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let reply_stop = continuous_stop.clone();
    let reply = tokio::spawn(async move {
        assert_eq!(
            tcp_scan(
                reply_listener.clone(),
                opening_page,
                opening_scan,
                reply_account.clone(),
                reply_governor.clone()
            )
            .await,
            1
        );
        assert_eq!(
            tcp_scan(
                reply_listener.clone(),
                continuous_page,
                continuous_scan,
                reply_account,
                reply_governor
            )
            .await,
            1
        );
        let reads = registered_history_until_stop(reply_listener, reply_stop).await;
        eprintln!("continuous recovery additional method-history reads={reads}");
        2
    });
    let outcome = scenario_future(|| async {
        super::super::replica_anchor::ensure_forwarded_target(
            &origin,
            &governor_state.service_core_id(),
            bob_event,
            Some(bob_commit),
            &mut located,
            &bob_session,
        )
        .await
    })
    .await;
    continuous_stop.store(true, std::sync::atomic::Ordering::SeqCst);
    assert_eq!(outcome.unwrap(), Some(bob_commit.clone()));
    assert_eq!(
        reply.await.unwrap(),
        2,
        "recovery must scan the gap instead of requesting a new bootstrap"
    );
    let recovered_gap = store
        .committed_event(&gap.authority_commit.event.event_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(recovered_gap.event, gap.authority_commit.event);
    assert_eq!(recovered_gap.commit, gap.authority_commit.commit);
    assert_eq!(
        store
            .committed_event(&bob_event.event_id)
            .await
            .unwrap()
            .unwrap()
            .commit,
        *bob_commit
    );
    assert_eq!(
        store
            .replica_anchor_for_stream(&commit.stream_ref)
            .await
            .unwrap()
            .unwrap()
            .join_commit,
        *commit
    );

    // A different, properly signed own join cannot replace the original
    // while its anchor is pending. It must not start a peer read or write.
    let replacement = scenario_future(|| async { foreign_request(
        &origin, &human, &governor, &join.authority_commit, EventKind::MemberState,
        serde_json::json!({"realm_id":realm,"member_id":actor,"membership":"join","reason":"pending anchor replacement candidate"}),
    ).await }).await;
    {
        let mut connection = origin_pool.get().await.unwrap();
        diesel::sql_query("UPDATE replica_stream_anchors SET anchor_commit_id=NULL, anchor_stream_position=NULL, anchored_at=NULL WHERE realm_id=$1")
            .bind::<diesel::sql_types::Text, _>(realm.as_str())
            .execute(&mut *connection).await.unwrap();
    }
    let pending_before = opening_footprint(&origin_pool, realm).await;
    let replacement_error = scenario_future(|| async {
        super::super::replica_anchor::ensure_forwarded_target(
            &origin,
            &governor_state.service_core_id(),
            &replacement.authority_commit.event,
            Some(&replacement.authority_commit.commit),
            &mut located,
            &session,
        )
        .await
    })
    .await
    .unwrap_err();
    assert_eq!(
        replacement_error,
        "forward opening join differs from the pending anchor"
    );
    assert_eq!(opening_footprint(&origin_pool, realm).await, pending_before);
    let unchanged = store
        .replica_anchor_for_stream(&commit.stream_ref)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(unchanged.join_commit, *commit);
    assert!(unchanged.anchored_head.is_none());
}
#[tokio::test]
async fn accepted_own_leave_returns_original_bound_result_after_terminal_membership_and_keeps_reads_closed()
 {
    accepted_own_leave_scenario().await;
}

// Run the complete large fixture on the same default-stack Tokio thread.
#[inline(never)]
fn accepted_own_leave_scenario() -> std::pin::Pin<Box<impl std::future::Future<Output = ()>>> {
    scenario_future(|| async {
        let listener = registered_tls_peer();
        let base = format!("https://{}/", listener.listener.local_addr().unwrap());
        let (governor_state, governor_pool, _governor_lease) = station_with_webvh(base.clone());
        let (origin, origin_pool, _origin_lease) =
            station_with_webvh("https://forward-recovery-origin.internal/".into());
        let mut governor =
            historical_human::HumanFixture::new(&governor_pool, governor_state.service_did()).await;
        // The existing closed bootstrap facet must explicitly authorize the Origin
        // to receive plaintext. Membership/action grants alone grant no such right.
        // Author this before the unit is accepted; never patch accepted state.
        let disclosure_index = governor
            .unit
            .transactions
            .iter()
            .position(|tx| tx.event.kind == EventKind::RealmPlaintextVisibleServices)
            .unwrap();
        assert!(disclosure_index > 0);
        assert_eq!(
            governor
                .unit
                .transactions
                .iter()
                .filter(|tx| tx.event.kind == EventKind::RealmPlaintextVisibleServices)
                .count(),
            1
        );
        let mut disclosure: arkret_models_collaboration::governance::plaintext_visibility::PlaintextVisibleServicesPayload =
        serde_json::from_value(
            serde_json::to_value(&governor.unit.transactions[disclosure_index].event.payload).unwrap(),
        ).unwrap();
        assert_eq!(disclosure.services.len(), 1);
        assert_eq!(
            disclosure.services[0].service_id,
            governor_state.service_core_id()
        );
        assert_ne!(governor_state.service_core_id(), origin.service_core_id());
        disclosure.services.push(
            serde_json::from_value(serde_json::json!({
                "service_id":origin.service_core_id(), "service_kind":"station",
                "data_classes":["message_content"],
                "purposes":["accepted original recovery fixture"],
                "visibility":"private_plaintext"
            }))
            .unwrap(),
        );
        let disclosure_event = historical_human::signed_ordinary_event(
            &governor,
            &governor.unit.transactions[disclosure_index - 1],
            EventKind::RealmPlaintextVisibleServices,
            disclosure.to_value().unwrap(),
            governor.unit.transactions[disclosure_index]
                .commit
                .committed_at,
        );
        governor.unit.transactions[disclosure_index].event = disclosure_event;
        let source = PgAuthorityCommitStore {
            pool: governor_pool.clone(),
        };
        let mut previous_commit = None;
        for (index, transaction) in governor.unit.transactions.iter_mut().enumerate() {
            transaction.commit.event_ref = transaction.event.event_id.clone();
            transaction.producer_signer_fact = source
                .prepare_account_device_signer_fact(
                    &transaction.event,
                    transaction.commit.committed_at,
                )
                .await
                .unwrap()
                .map(Into::into);
            assert!(transaction.producer_signer_fact.is_some());
            transaction.commit.producer_signer_fact_digest = transaction
                .producer_signer_fact
                .as_ref()
                .map(|fact| fact.digest().unwrap());
            transaction.commit.previous_commit_ref = previous_commit;
            seal_service_commit(&mut transaction.commit, &governor_state);
            previous_commit = Some(transaction.commit.commit_id.clone());
            governor.unit.submission.events[index] =
                EventAdmissionSubmission::new(transaction.event.clone());
        }
        governor.unit.exact_request_body =
            serde_json::to_vec(&SelfAuthoritySubmitRequestBody::OrdinaryRealmBootstrap(
                governor.unit.submission.clone(),
            ))
            .unwrap();
        governor.admit(&governor_pool).await;
        assert_eq!(
            source
                .accepted_plaintext_visible_services(&governor.unit.transactions[0].event.realm_id,)
                .await
                .unwrap(),
            Some(disclosure)
        );
        let human = historical_human::HumanFixture::new(&origin_pool, origin.service_did()).await;
        let actor = ActorId::account(human.pcr.history.account.clone());
        let previous = governor.unit.transactions.last().unwrap();
        let at = previous.commit.committed_at + Duration::seconds(1);
        let owner = ActorId::account(governor.pcr.history.account.clone());
        let strand_event = historical_human::signed_ordinary_event(
            &governor,
            previous,
            EventKind::StrandCreate,
            serde_json::json!({"object":{
                "schema":"ak.schema.strand.v1", "realm_id":previous.event.realm_id,
                "tracks":{"discussion":{"is_primary":true,"profile":"discussion"}},
                "metadata":{"title":"forward recovery fixture discussion"}, "state":"active",
                "created_by":owner, "created_at":arkret_canonical::format_timestamp_canonical(at)
            }}),
            at,
        );
        let mut strand = historical_human::request_for_event(&governor, previous, strand_event, at);
        seal_service_commit(&mut strand.authority_commit.commit, &governor_state);
        let uow = PgEventCommitUnitOfWork::new(governor_pool.clone());
        scenario_future(|| async { uow.commit_event(strand.clone()).await })
            .await
            .unwrap();
        let create_at = strand.authority_commit.commit.committed_at + Duration::seconds(1);
        let create_event = historical_human::signed_ordinary_event(
            &governor,
            &strand.authority_commit,
            EventKind::CircleCreate,
            serde_json::json!({"object":{
                "schema":"ak.schema.circle.v1","realm_id":strand.authority_commit.event.realm_id,
                "title":"Own leave bound result","display":{"short_name":"Leave","color_token":"blue","symbol":{"glyph":"lock"}},
                "directory_visibility":"members","join_rule":"public","history_access":"since_join","state":"active",
                "created_by":owner,"created_at":arkret_canonical::format_timestamp_canonical(create_at)
            }}),
            create_at,
        );
        let mut circle_create = historical_human::request_for_event(
            &governor,
            &strand.authority_commit,
            create_event,
            create_at,
        );
        seal_service_commit(&mut circle_create.authority_commit.commit, &governor_state);
        scenario_future(|| async { uow.commit_event(circle_create.clone()).await })
            .await
            .unwrap();
        let circle_id =
            arkret_wire::CircleId::from_event_id(&circle_create.authority_commit.event.event_id);

        // Membership is not an action grant. Read the actual accepted root cut,
        // then admit the owner's narrow Grant before the foreign member joins. The
        // Grant grants no membership; MessageCreate still runs after the real join.
        #[derive(diesel::QueryableByName)]
        struct RootCut {
            #[diesel(sql_type = diesel::sql_types::Jsonb)]
            controller_actor_id: serde_json::Value,
            #[diesel(sql_type = diesel::sql_types::Text)]
            authority_event_ref: String,
            #[diesel(sql_type = diesel::sql_types::BigInt)]
            authority_generation: i64,
        }
        use diesel_async::RunQueryDsl as _;
        let root_cut = {
            let mut conn = governor_pool.get().await.unwrap();
            diesel::sql_query(
                "SELECT controller_actor_id, authority_event_ref, authority_generation \
             FROM realm_authority_root_current_states WHERE realm_id=$1",
            )
            .bind::<diesel::sql_types::Text, _>(strand.authority_commit.event.realm_id.as_str())
            .get_result::<RootCut>(&mut *conn)
            .await
            .unwrap()
        };
        assert_eq!(
            serde_json::from_value::<ActorId>(root_cut.controller_actor_id).unwrap(),
            owner
        );
        let root_generation = u64::try_from(root_cut.authority_generation).unwrap();
        let previous = &circle_create.authority_commit;
        let grant_at = previous.commit.committed_at + Duration::seconds(1);
        let grant_payload: arkret_models_collaboration::events_payloads::CapabilityGrantPayload =
        serde_json::from_value(serde_json::json!({"grant": {
            "schema":"ak.schema.capability.v1",
            "realm_id":previous.event.realm_id,
            "issuer_id":owner,
            "subject":actor,
            "actions":["ak.message.create","ak.circle.member.add"],
            "resources":[{"kind":"realm","realm_id":previous.event.realm_id},{"kind":"circle","realm_id":previous.event.realm_id,"circle_id":circle_id}],
            "issuer_authority_refs":[{
                "kind":"realm_root","realm_id":previous.event.realm_id,
                "authority_event_ref":root_cut.authority_event_ref,
                "authority_generation":(root_generation).to_string()
            }],
            "issued_at":arkret_canonical::format_timestamp_canonical(grant_at)
        }}))
        .unwrap();
        let grant_event = historical_human::signed_ordinary_event(
            &governor,
            previous,
            EventKind::CapabilityGrant,
            serde_json::to_value(grant_payload).unwrap(),
            grant_at,
        );
        let mut grant =
            historical_human::request_for_event(&governor, previous, grant_event, grant_at);
        // This is a fresh PG source candidate, not a cached authorizing capability.
        // The UOW independently prepares and compares it under its admission locks.
        let grant_fact = PgAuthorityCommitStore {
            pool: governor_pool.clone(),
        }
        .prepare_account_device_signer_fact(&grant.authority_commit.event, grant_at)
        .await
        .unwrap()
        .unwrap();
        grant.authority_commit.commit.producer_signer_fact_digest =
            Some(grant_fact.digest().unwrap());
        grant.authority_commit.producer_signer_fact = Some(grant_fact.into());
        seal_service_commit(&mut grant.authority_commit.commit, &governor_state);
        scenario_future(|| async { uow.commit_event(grant.clone()).await })
            .await
            .unwrap();
        let previous = &grant.authority_commit;
        let mut join = scenario_future(|| async { foreign_request(&origin, &human, &governor, previous, EventKind::MemberState,
        serde_json::json!({"realm_id":previous.event.realm_id,"member_id":actor,"membership":"join","reason":"real forward recovery membership"})).await }).await;
        seal_service_commit(&mut join.authority_commit.commit, &governor_state);
        scenario_future(|| async { uow.commit_event(join.clone()).await })
            .await
            .unwrap();
        let source = PgAuthorityCommitStore {
            pool: governor_pool.clone(),
        };
        let store = PgAuthorityCommitStore {
            pool: origin_pool.clone(),
        };
        let realm = &join.authority_commit.event.realm_id;
        let event = &join.authority_commit.event;
        let commit = &join.authority_commit.commit;
        let key =
            ed25519_dalek::SigningKey::from_bytes(&historical_human::station_authority_seed());
        let session = authenticated_context(&origin_pool, &human).await;
        let route =
            crate::routing::system::service_resolution::current_authenticated_service_resolution(
                &governor_state,
            )
            .await
            .unwrap();
        let boundary = route.method_history_evidence.boundary();
        let description = VerifiedServiceDescribeMetadata {
            supported_profiles: Vec::new(),
            service_id: governor_state.service_core_id(),
            service_kind: "station".into(),
            service_resolution: ResolutionCommitment {
                did: governor_state.service_did(),
                method_history_head: boundary.to_method_history_head.clone(),
                version_id: boundary.to_version_id.clone(),
            },
            http_json_base_url: base,
            trust_domain: governor_state.config().trust_domain.clone(),
            protocol_version: arkret_wire::PROTOCOL_VERSION.into(),
            supported_operation_bundles: vec![
                arkret_wire::role_describe_bundle_descriptor(arkret_wire::ServiceKind::Station)
                    .unwrap()
                    .operation_bundle_id
                    .into(),
            ],
        };
        origin.test_install_service_route_fetcher(Arc::new(VerifiedSourceRoute(
            VerifiedRouteCandidate {
                evidence: route,
                description,
            },
        )));
        let nonce = Base64UrlString::new(arkret_canonical::base64url_encode([0x71; 32])).unwrap();
        let bundle =
            crate::routing::realm_join::local_authority_bundle(&governor_state, realm, &nonce)
                .await
                .unwrap();
        let mut keys = arkret_identity::RealmAuthorityKeyMap::new();
        for signature in [
            &bundle.genesis_commit.signature,
            &bundle.current_assertion.signature,
            &commit.signature,
        ] {
            keys.insert_at(
                &signature.verification_method,
                signature.created_at,
                arkret_signatures::PublicKeyMaterial::Ed25519Raw {
                    bytes: key.verifying_key().to_bytes().to_vec(),
                },
            );
        }
        let authority = arkret_identity::verify_realm_authority_bundle(
            &bundle,
            &arkret_identity::RealmAuthorityFreshness::new(Utc::now(), nonce),
            &keys,
        )
        .unwrap();
        let mut located = crate::routing::realm_join::LocatedRealmAuthority {
            bundle,
            authority,
            keys,
        };
        store
            .record_remote_authority(&located.current_authority(), &origin.service_core_id())
            .await
            .unwrap();
        store.queue_event(event, commit.committed_at).await.unwrap();
        let intent =
            SelfAuthoritySubmitRequestBody::Event(EventAdmissionSubmission::new(event.clone()));
        store
            .retain_forwarded_submission(event, &intent, commit.committed_at)
            .await
            .unwrap();
        store
            .retain_forwarded_acceptance(event, commit, commit.committed_at)
            .await
            .unwrap();
        assert!(
            store
                .replica_anchor_for_stream(&commit.stream_ref)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .committed_event(&event.event_id)
                .await
                .unwrap()
                .is_none()
        );
        let no_write = opening_footprint(&origin_pool, realm).await;
        // A bare original or the wrong authenticated Account never starts a scan.
        assert!(
            scenario_future(|| async {
                super::super::replica_anchor::ensure_forwarded_target(
                    &origin,
                    &governor_state.service_core_id(),
                    event,
                    None,
                    &mut located,
                    &session,
                )
                .await
            })
            .await
            .is_err()
        );
        let mut other_session = session.clone();
        other_session.session_grant.as_mut().unwrap().account_id =
            governor.pcr.history.account.clone();
        assert!(
            scenario_future(|| async {
                super::super::replica_anchor::ensure_forwarded_target(
                    &origin,
                    &governor_state.service_core_id(),
                    event,
                    Some(commit),
                    &mut located,
                    &other_session,
                )
                .await
            })
            .await
            .is_err()
        );
        assert_eq!(opening_footprint(&origin_pool, realm).await, no_write);
        let scan = StreamScanRequestBody {
            realm_id: realm.clone(),
            stream_ref: commit.stream_ref.clone(),
            direction: StreamScanDirection::Before(Some(commit.stream_position + 1)),
            limit: 1,
        };
        let coland_storage::PeerStreamScan::Page(page) = source
            .scan_stream_for_peer(
                &scan,
                &human.pcr.history.account.station_id,
                &governor_state.service_core_id(),
            )
            .await
            .unwrap()
        else {
            panic!("Gov accepted member grants its routed Station the opening floor");
        };
        page.validate_for_request(&scan).unwrap();
        let full = page
            .committed_events
            .iter()
            .find(|item| item.commit().commit_id == commit.commit_id)
            .unwrap();
        assert!(
            matches!(full, arkret_wire::CommittedEventView::Full(view) if view.event == *event && view.commit == *commit)
        );
        let archived = source
            .producer_signer_fact(event, commit)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            page.producer_signer_facts
                .iter()
                .find(|f| f.target.commit_id == commit.commit_id)
                .unwrap()
                .producer_signer_fact,
            archived
        );
        let mut withheld = page.clone();
        withheld.committed_events = vec![arkret_wire::CommittedEventView::Withheld(
            arkret_wire::CommittedEventWithheldView {
                commit: commit.clone(),
                event_disclosure: arkret_wire::EventDisclosure {
                    status: arkret_wire::EventDisclosureStatus::Withheld,
                },
            },
        )];
        withheld.producer_signer_facts.clear();
        let reply = tokio::spawn(tcp_scan(
            listener.clone(),
            withheld,
            scan.clone(),
            human.pcr.history.account.clone(),
            governor_state.service_core_id(),
        ));
        assert!(
            scenario_future(|| async {
                super::super::replica_anchor::ensure_forwarded_target(
                    &origin,
                    &governor_state.service_core_id(),
                    event,
                    Some(commit),
                    &mut located,
                    &session,
                )
                .await
            })
            .await
            .is_err()
        );
        assert_eq!(reply.await.unwrap(), 1);
        assert_eq!(opening_footprint(&origin_pool, realm).await, no_write);
        let mut missing_fact = page.clone();
        missing_fact.producer_signer_facts.clear();
        let reply = tokio::spawn(tcp_scan(
            listener.clone(),
            missing_fact,
            scan.clone(),
            human.pcr.history.account.clone(),
            governor_state.service_core_id(),
        ));
        assert!(
            scenario_future(|| async {
                super::super::replica_anchor::ensure_forwarded_target(
                    &origin,
                    &governor_state.service_core_id(),
                    event,
                    Some(commit),
                    &mut located,
                    &session,
                )
                .await
            })
            .await
            .is_err()
        );
        assert_eq!(reply.await.unwrap(), 1);
        assert_eq!(opening_footprint(&origin_pool, realm).await, no_write);
        let response_listener = listener.clone();
        let response_governor = governor_state.clone();
        let response_pool = governor_pool.clone();
        let response_account = human.pcr.history.account.clone();
        let response_commit = commit.clone();
        let history_stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let response_stop = history_stop.clone();
        let reply = tokio::spawn(async move {
            assert_eq!(
                tcp_scan(
                    response_listener.clone(),
                    page,
                    scan,
                    response_account.clone(),
                    response_governor.service_core_id()
                )
                .await,
                1
            );
            assert_eq!(
                tcp_opening_bootstrap(
                    response_listener,
                    response_governor,
                    response_pool,
                    response_account,
                    response_commit,
                    response_stop,
                )
                .await,
                1
            );
            2
        });
        let original = scenario_future(|| async {
            super::super::replica_anchor::ensure_forwarded_target(
                &origin,
                &governor_state.service_core_id(),
                event,
                Some(commit),
                &mut located,
                &session,
            )
            .await
        })
        .await;
        history_stop.store(true, std::sync::atomic::Ordering::SeqCst);
        let original = original.unwrap().unwrap();
        assert_eq!(original, *commit);
        assert_eq!(reply.await.unwrap(), 2);
        let held = store
            .committed_event(&event.event_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(held.event, *event);
        assert_eq!(held.commit, *commit);
        assert_eq!(
            store.producer_signer_fact(event, commit).await.unwrap(),
            Some(archived)
        );
        let anchor = store
            .replica_anchor_for_stream(&commit.stream_ref)
            .await
            .unwrap()
            .unwrap();
        assert!(anchor.anchored_head.is_some());
        assert_eq!(anchor.join_commit, *commit);
        let before_replay = opening_footprint(&origin_pool, realm).await;
        assert_eq!(
            scenario_future(|| async {
                super::super::replica_anchor::ensure_forwarded_target(
                    &origin,
                    &governor_state.service_core_id(),
                    event,
                    Some(commit),
                    &mut located,
                    &session,
                )
                .await
            })
            .await
            .unwrap(),
            Some(commit.clone())
        );
        assert_eq!(opening_footprint(&origin_pool, realm).await, before_replay);
        // Poll the nested Circle lifecycle independently of the large parent
        // fixture, as separate HTTP operations are polled in production. A
        // JoinSet keeps cancellation tied to this test and uses the same runtime.
        let phase_origin = origin.clone();
        let phase_origin_pool = origin_pool.clone();
        let phase_governor = governor_state.clone();
        let phase_governor_pool = governor_pool.clone();
        let phase_join = join.authority_commit.clone();
        let phase_circle = circle_id.clone();
        let phase_listener = listener.clone();
        let phase_session = session.clone();
        let mut circle_phase = tokio::task::JoinSet::new();
        circle_phase.spawn(async move {
            let final_parent = scenario_future(|| {
                circle_own_leave_bound_result_cases(
                    &phase_origin,
                    &phase_origin_pool,
                    &phase_governor,
                    &phase_governor_pool,
                    &human,
                    &governor,
                    &phase_join,
                    &phase_circle,
                    phase_listener,
                    &mut located,
                    &phase_session,
                )
            })
            .await;
            (final_parent, located, human, governor)
        });
        let (final_parent, returned_authority, human, governor) =
            circle_phase.join_next().await.unwrap().unwrap();
        let mut located = returned_authority;
        // Author, sign and admit the real own leave on Gov; Origin keeps its frozen
        // request and the authentic original acceptance without yet installing it.
        let mut leave = scenario_future(|| async { foreign_request(&origin, &human, &governor, &final_parent,
        EventKind::MemberState, serde_json::json!({"realm_id":realm,"member_id":actor,"membership":"leave","reason":"original own leave recovery"})).await }).await;
        seal_service_commit(&mut leave.authority_commit.commit, &governor_state);
        scenario_future(|| async { uow.commit_event(leave.clone()).await })
            .await
            .unwrap();
        let le = &leave.authority_commit.event;
        let lc = &leave.authority_commit.commit;
        let original_fact = source.producer_signer_fact(le, lc).await.unwrap().unwrap();
        assert_eq!(
            Some(original_fact.clone()),
            leave.authority_commit.producer_signer_fact
        );
        store.queue_event(le, lc.committed_at).await.unwrap();
        let intent =
            SelfAuthoritySubmitRequestBody::Event(EventAdmissionSubmission::new(le.clone()));
        store
            .retain_forwarded_submission(le, &intent, lc.committed_at)
            .await
            .unwrap();
        store
            .retain_forwarded_acceptance(le, lc, lc.committed_at)
            .await
            .unwrap();
        let scan = StreamScanRequestBody {
            realm_id: realm.clone(),
            stream_ref: lc.stream_ref.clone(),
            direction: StreamScanDirection::After(Some(final_parent.commit.stream_position)),
            limit: 128,
        };
        let coland_storage::PeerStreamScan::Page(page) = source
            .scan_stream_for_peer(
                &scan,
                &human.pcr.history.account.station_id,
                &governor_state.service_core_id(),
            )
            .await
            .unwrap()
        else {
            panic!("terminating peer interval unavailable")
        };
        assert_eq!(page.committed_events.len(), 1);
        let arkret_wire::CommittedEventView::Full(full) = &page.committed_events[0] else {
            panic!("terminating original is withheld")
        };
        assert_eq!(full.event, *le);
        assert_eq!(full.commit, *lc);
        assert_eq!(page.producer_signer_facts.len(), 1);
        assert_eq!(
            page.producer_signer_facts[0].producer_signer_fact,
            original_fact
        );
        let (rl, rg, rp, ra) = (
            listener.clone(),
            governor_state.clone(),
            governor_pool.clone(),
            human.pcr.history.account.clone(),
        );
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let reply_stop = stop.clone();
        let reply = tokio::spawn(async move {
            let scan_posts = tcp_scan(rl.clone(), page, scan, ra, rg.service_core_id()).await;
            assert_eq!(scan_posts, 1);
            serve_original_service_history_until_stop(rl, rg, rp, reply_stop).await;
            scan_posts
        });
        let recovered = scenario_future(|| async {
            super::super::replica_anchor::ensure_forwarded_target(
                &origin,
                &governor_state.service_core_id(),
                le,
                Some(lc),
                &mut located,
                &session,
            )
            .await
        })
        .await;
        stop.store(true, std::sync::atomic::Ordering::SeqCst);
        assert_eq!(recovered.unwrap(), Some(lc.clone()));
        assert_eq!(reply.await.unwrap(), 1);
        assert_eq!(
            store
                .committed_event(&le.event_id)
                .await
                .unwrap()
                .unwrap()
                .commit,
            *lc
        );
        assert_eq!(
            store.producer_signer_fact(le, lc).await.unwrap(),
            Some(original_fact.clone())
        );
        assert!(
            !store
                .accepted_current_member_joined(realm, &actor)
                .await
                .unwrap()
        );
        assert!(
            store
                .accepted_own_leave_bound_result(
                    le,
                    lc,
                    &human.pcr.history.account,
                    &origin.service_core_id()
                )
                .await
                .unwrap()
        );
        let read = StreamScanRequestBody {
            realm_id: realm.clone(),
            stream_ref: lc.stream_ref.clone(),
            direction: StreamScanDirection::Before(Some(lc.stream_position + 1)),
            limit: 1,
        };
        assert!(matches!(
            store
                .scan_stream_for_account(
                    &read,
                    &human.pcr.history.account,
                    &origin.service_core_id()
                )
                .await
                .unwrap(),
            coland_storage::AccountStreamScan::NotAuthorized
        ));
        // The governor has a real later Full, but the departed peer's original
        // interval ends at the leave, including its terminal node only.
        let future_at = lc.committed_at + Duration::seconds(1);
        let future_event = historical_human::signed_ordinary_event(
            &governor,
            &leave.authority_commit,
            EventKind::MessageCreate,
            serde_json::json!({
                "strand_id":arkret_wire::StrandId::from_event_id(&strand.authority_commit.event.event_id),
                "track_name":"discussion","content":{"kind":"ak.content.text","body":"future owner original","format":"plain"}
            }),
            future_at,
        );
        let mut future = historical_human::request_for_event(
            &governor,
            &leave.authority_commit,
            future_event,
            future_at,
        );
        let future_fact = source
            .prepare_account_device_signer_fact(&future.authority_commit.event, future_at)
            .await
            .unwrap()
            .unwrap();
        future.authority_commit.commit.producer_signer_fact_digest =
            Some(future_fact.digest().unwrap());
        future.authority_commit.producer_signer_fact = Some(future_fact.into());
        seal_service_commit(&mut future.authority_commit.commit, &governor_state);
        scenario_future(|| async { uow.commit_event(future.clone()).await })
            .await
            .unwrap();
        let future_read = StreamScanRequestBody {
            realm_id: realm.clone(),
            stream_ref: lc.stream_ref.clone(),
            direction: StreamScanDirection::After(Some(lc.stream_position)),
            limit: 1,
        };
        let coland_storage::PeerStreamScan::Page(no_future) = source
            .scan_stream_for_peer(
                &future_read,
                &human.pcr.history.account.station_id,
                &governor_state.service_core_id(),
            )
            .await
            .unwrap()
        else {
            panic!("terminal interval read unavailable")
        };
        assert!(no_future.committed_events.is_empty());
        assert!(
            store
                .committed_event(&future.authority_commit.event.event_id)
                .await
                .unwrap()
                .is_none()
        );
        let before = opening_footprint(&origin_pool, realm).await;
        assert_eq!(
            scenario_future(|| async {
                super::super::replica_anchor::ensure_forwarded_target(
                    &origin,
                    &governor_state.service_core_id(),
                    le,
                    Some(lc),
                    &mut located,
                    &session,
                )
                .await
            })
            .await
            .unwrap(),
            Some(lc.clone())
        );
        assert_eq!(opening_footprint(&origin_pool, realm).await, before);
        assert!(
            scenario_future(|| async {
                super::super::replica_anchor::ensure_forwarded_target(
                    &origin,
                    &governor_state.service_core_id(),
                    le,
                    None,
                    &mut located,
                    &session,
                )
                .await
            })
            .await
            .is_err()
        );
        assert!(
            scenario_future(|| async {
                super::super::replica_anchor::ensure_forwarded_target(
                    &origin,
                    &governor_state.service_core_id(),
                    le,
                    Some(lc),
                    &mut located,
                    &other_session,
                )
                .await
            })
            .await
            .is_err()
        );
        assert!(
            !store
                .accepted_own_leave_bound_result(
                    le,
                    lc,
                    &governor.pcr.history.account,
                    &origin.service_core_id()
                )
                .await
                .unwrap()
        );
        let mismatch = historical_human::signed_ordinary_event(
            &human,
            &join.authority_commit,
            EventKind::MemberState,
            serde_json::json!({"realm_id":realm,"member_id":owner,"membership":"leave"}),
            lc.committed_at,
        );
        assert!(
            !store
                .accepted_own_leave_bound_result(
                    &mismatch,
                    lc,
                    &human.pcr.history.account,
                    &origin.service_core_id()
                )
                .await
                .unwrap()
        );
        // Removing an original fact is a negative only: no fallback to today's key
        // and no eligibility from a bare accepted witness.
        {
            let mut conn = origin_pool.get().await.unwrap();
            diesel::sql_query(
            "UPDATE agent_producer_signer_keys SET producer_source_fact=NULL WHERE commit_id=$1",
        )
        .bind::<diesel::sql_types::Text, _>(lc.commit_id.as_str())
        .execute(&mut *conn)
        .await
        .unwrap();
        }
        assert!(
            !store
                .accepted_own_leave_bound_result(
                    le,
                    lc,
                    &human.pcr.history.account,
                    &origin.service_core_id()
                )
                .await
                .unwrap()
        );
        assert!(
            scenario_future(|| async {
                super::super::replica_anchor::ensure_forwarded_target(
                    &origin,
                    &governor_state.service_core_id(),
                    le,
                    Some(lc),
                    &mut located,
                    &session,
                )
                .await
            })
            .await
            .is_err()
        );
        {
            let mut conn = origin_pool.get().await.unwrap();
            diesel::sql_query(
                "UPDATE agent_producer_signer_keys SET producer_source_fact=$2 WHERE commit_id=$1",
            )
            .bind::<diesel::sql_types::Text, _>(lc.commit_id.as_str())
            .bind::<diesel::sql_types::Jsonb, _>(serde_json::to_value(&original_fact).unwrap())
            .execute(&mut *conn)
            .await
            .unwrap();
        }
        assert_eq!(opening_footprint(&origin_pool, realm).await, before);
        // Corrupt durable coordinates only as a negative, then restore the original.
        {
            let mut conn = origin_pool.get().await.unwrap();
            diesel::sql_query("UPDATE replica_stream_anchors SET join_commit_id=$2 WHERE realm_id=$1 AND stream_key=(SELECT stream_key FROM realm_commits WHERE commit_id=$2)")
            .bind::<diesel::sql_types::Text, _>(realm.as_str())
            .bind::<diesel::sql_types::Text, _>(lc.commit_id.as_str())
            .execute(&mut *conn)
            .await
            .unwrap();
        }
        assert!(
            !store
                .accepted_own_leave_bound_result(
                    le,
                    lc,
                    &human.pcr.history.account,
                    &origin.service_core_id()
                )
                .await
                .unwrap()
        );
        assert!(
            scenario_future(|| async {
                super::super::replica_anchor::ensure_forwarded_target(
                    &origin,
                    &governor_state.service_core_id(),
                    le,
                    Some(lc),
                    &mut located,
                    &session,
                )
                .await
            })
            .await
            .is_err()
        );
        {
            let mut conn = origin_pool.get().await.unwrap();
            diesel::sql_query("UPDATE replica_stream_anchors SET join_commit_id=$2 WHERE realm_id=$1 AND stream_key=(SELECT stream_key FROM realm_commits WHERE commit_id=$2)")
            .bind::<diesel::sql_types::Text, _>(realm.as_str())
            .bind::<diesel::sql_types::Text, _>(commit.commit_id.as_str())
            .execute(&mut *conn)
            .await
            .unwrap();
            diesel::sql_query("UPDATE member_state_current_states SET current_commit_id=$3,current_stream_position=$4 WHERE realm_id=$1 AND member_id=$2")
          .bind::<diesel::sql_types::Text,_>(realm.as_str()).bind::<diesel::sql_types::Text,_>(actor.to_string()).bind::<diesel::sql_types::Text,_>(commit.commit_id.as_str()).bind::<diesel::sql_types::BigInt,_>(i64::try_from(commit.stream_position).unwrap()).execute(&mut *conn).await.unwrap();
        }
        assert!(
            !store
                .accepted_own_leave_bound_result(
                    le,
                    lc,
                    &human.pcr.history.account,
                    &origin.service_core_id()
                )
                .await
                .unwrap()
        );
        {
            let mut conn = origin_pool.get().await.unwrap();
            diesel::sql_query("UPDATE member_state_current_states SET current_commit_id=$3,current_stream_position=$4 WHERE realm_id=$1 AND member_id=$2")
          .bind::<diesel::sql_types::Text,_>(realm.as_str()).bind::<diesel::sql_types::Text,_>(actor.to_string()).bind::<diesel::sql_types::Text,_>(lc.commit_id.as_str()).bind::<diesel::sql_types::BigInt,_>(i64::try_from(lc.stream_position).unwrap()).execute(&mut *conn).await.unwrap();
        }
        assert_eq!(opening_footprint(&origin_pool, realm).await, before);
        assert!(matches!(
            store
                .scan_stream_for_account(
                    &read,
                    &human.pcr.history.account,
                    &origin.service_core_id()
                )
                .await
                .unwrap(),
            coland_storage::AccountStreamScan::NotAuthorized
        ));
    })
}

#[expect(
    clippy::too_many_arguments,
    reason = "The regression shares two real Stations and their original signed acceptance fixture."
)]
async fn circle_own_leave_bound_result_cases(
    origin: &AppState,
    origin_pool: &PgPool,
    governor_state: &AppState,
    governor_pool: &PgPool,
    human: &historical_human::HumanFixture,
    governor: &historical_human::HumanFixture,
    parent_join: &coland_storage::AuthorityCommitTransaction,
    circle_id: &arkret_wire::CircleId,
    listener: Arc<RegisteredTlsPeer>,
    located: &mut crate::routing::realm_join::LocatedRealmAuthority,
    session: &SessionIdentityState,
) -> coland_storage::AuthorityCommitTransaction {
    use diesel_async::RunQueryDsl as _;
    register_original_peer_history(&listener, governor_state, governor_pool).await;
    let source = PgAuthorityCommitStore {
        pool: governor_pool.clone(),
    };
    let store = PgAuthorityCommitStore {
        pool: origin_pool.clone(),
    };
    let actor = ActorId::account(human.pcr.history.account.clone());
    let mut parent_join = parent_join.clone();
    let mut previous = parent_join.clone();
    let mut terminal = None;
    for (index, state) in ["join", "leave", "join", "leave", "join"]
        .into_iter()
        .enumerate()
    {
        eprintln!("[2133-circle-recovery] phase={index} state={state}");
        if index == 3 {
            parent_join = scenario_future(|| {
                circle_cleanup_parent_rejoin(
                    origin,
                    governor_state,
                    governor_pool,
                    human,
                    governor,
                    &parent_join,
                    listener.clone(),
                    located,
                    session,
                )
            })
            .await;
        }
        let mut payload = serde_json::json!({"circle_id":circle_id,"member_id":actor,"membership":state,
            "expected_membership":if index == 0 { None } else if state == "leave" { Some("join") } else { Some("leave") }});
        if state == "join" {
            payload["parent_membership_revision"] = serde_json::json!({"commit_id":parent_join.commit.commit_id,
                "stream_position":parent_join.commit.stream_position});
        }
        let mut request = Box::pin(foreign_request(
            origin,
            human,
            governor,
            &previous,
            EventKind::CircleMemberState,
            payload,
        ))
        .await;
        seal_service_commit(&mut request.authority_commit.commit, governor_state);
        admit_fixture_event(governor_pool, request.clone()).await;
        let event = &request.authority_commit.event;
        let commit = &request.authority_commit.commit;
        store.queue_event(event, commit.committed_at).await.unwrap();
        store
            .retain_forwarded_submission(
                event,
                &SelfAuthoritySubmitRequestBody::Event(EventAdmissionSubmission::new(
                    event.clone(),
                )),
                commit.committed_at,
            )
            .await
            .unwrap();
        store
            .retain_forwarded_acceptance(event, commit, commit.committed_at)
            .await
            .unwrap();
        if index == 3 {
            eprintln!("[2133-circle-recovery] cleanup refusal matrix");
            Box::pin(circle_cleanup_install_refusals(
                origin,
                origin_pool,
                governor_state,
                human,
                governor,
                event,
                commit,
                request.authority_commit.producer_signer_fact.clone(),
            ))
            .await;
        }
        let scan = StreamScanRequestBody {
            realm_id: event.realm_id.clone(),
            stream_ref: commit.stream_ref.clone(),
            direction: if state == "leave" {
                StreamScanDirection::After(Some(previous.commit.stream_position))
            } else {
                StreamScanDirection::Before(Some(commit.stream_position + 1))
            },
            limit: if state == "leave" { 128 } else { 1 },
        };
        let coland_storage::PeerStreamScan::Page(page) = source
            .scan_stream_for_peer(
                &scan,
                &human.pcr.history.account.station_id,
                &governor_state.service_core_id(),
            )
            .await
            .unwrap()
        else {
            panic!("Circle opening or terminating interval unavailable")
        };
        assert_eq!(page.committed_events.len(), 1);
        assert!(
            matches!(&page.committed_events[0], arkret_wire::CommittedEventView::Full(full)
            if full.event == *event && full.commit == *commit)
        );
        let (rl, rg, rp, ra, rc) = (
            listener.clone(),
            governor_state.clone(),
            governor_pool.clone(),
            human.pcr.history.account.clone(),
            commit.clone(),
        );
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let reply_stop = stop.clone();
        let reply = tokio::spawn(async move {
            let scan_posts =
                tcp_scan(rl.clone(), page, scan, ra.clone(), rg.service_core_id()).await;
            assert_eq!(scan_posts, 1);
            if state == "join" {
                assert_eq!(
                    tcp_opening_bootstrap(rl, rg, rp, ra, rc, reply_stop).await,
                    1
                );
            } else {
                serve_original_service_history_until_stop(rl, rg, rp, reply_stop).await;
            }
            scan_posts
        });
        let governor_id = governor_state.service_core_id();
        let outcome = scenario_future(|| {
            super::super::replica_anchor::ensure_forwarded_target(
                origin,
                &governor_id,
                event,
                Some(commit),
                located,
                session,
            )
        })
        .await;
        stop.store(true, std::sync::atomic::Ordering::SeqCst);
        assert_eq!(
            outcome.unwrap_or_else(|error| panic!("Circle phase {index} {state}: {error}")),
            Some(commit.clone())
        );
        assert_eq!(reply.await.unwrap(), 1);
        if state == "leave" {
            assert!(
                store
                    .accepted_own_leave_bound_result(
                        event,
                        commit,
                        &human.pcr.history.account,
                        &origin.service_core_id()
                    )
                    .await
                    .unwrap()
            );
            let read = StreamScanRequestBody {
                realm_id: event.realm_id.clone(),
                stream_ref: commit.stream_ref.clone(),
                direction: StreamScanDirection::Before(Some(commit.stream_position + 1)),
                limit: 1,
            };
            // history-visibility §3.1 gives a departed Circle member no readable
            // Commit. This internal replica result proves zero Page/disclosure;
            // it does not assert or change the public HTTP not_found mapping.
            assert_eq!(
                store
                    .scan_stream_for_account(
                        &read,
                        &human.pcr.history.account,
                        &origin.service_core_id()
                    )
                    .await
                    .unwrap(),
                coland_storage::AccountStreamScan::Unproved("the caller has no held Circle join")
            );
            assert!(
                !store
                    .accepted_own_leave_bound_result(
                        event,
                        commit,
                        &governor.pcr.history.account,
                        &origin.service_core_id()
                    )
                    .await
                    .unwrap()
            );
            assert!(
                !store
                    .accepted_own_leave_bound_result(
                        event,
                        &parent_join.commit,
                        &human.pcr.history.account,
                        &origin.service_core_id()
                    )
                    .await
                    .unwrap()
            );
            let other =
                historical_human::HumanFixture::new(origin_pool, origin.service_did()).await;
            let other_session = authenticated_context(origin_pool, &other).await;
            let before_wrong_session = opening_footprint(origin_pool, &event.realm_id).await;
            assert!(
                Box::pin(super::super::replica_anchor::ensure_forwarded_target(
                    origin,
                    &governor_state.service_core_id(),
                    event,
                    Some(commit),
                    located,
                    &other_session,
                ))
                .await
                .is_err()
            );
            assert_eq!(
                opening_footprint(origin_pool, &event.realm_id).await,
                before_wrong_session
            );
            // A typed terminal row cannot replace the original acceptance witness.
            let mut conn = origin_pool.get().await.unwrap();
            diesel::sql_query("UPDATE authority_forward_attempts SET accepted_commit_json=NULL WHERE event_pk=(SELECT pk FROM canonical_events WHERE id=$1)")
                .bind::<diesel::sql_types::Binary,_>(event.event_id.token_bytes().to_vec())
                .execute(&mut *conn).await.unwrap();
            drop(conn);
            assert!(
                !store
                    .accepted_own_leave_bound_result(
                        event,
                        commit,
                        &human.pcr.history.account,
                        &origin.service_core_id()
                    )
                    .await
                    .unwrap()
            );
            let mut conn = origin_pool.get().await.unwrap();
            diesel::sql_query("UPDATE authority_forward_attempts SET accepted_commit_json=$2 WHERE event_pk=(SELECT pk FROM canonical_events WHERE id=$1)")
                .bind::<diesel::sql_types::Binary,_>(event.event_id.token_bytes().to_vec())
                .bind::<diesel::sql_types::Jsonb,_>(serde_json::to_value(commit).unwrap())
                .execute(&mut *conn).await.unwrap();
            drop(conn);
            // A changed parent cut cannot borrow the old Circle opening proof.
            let mut conn = origin_pool.get().await.unwrap();
            diesel::sql_query("UPDATE member_state_current_states SET current_stream_position=current_stream_position+1 WHERE realm_id=$1 AND member_id=$2")
                .bind::<diesel::sql_types::Text,_>(event.realm_id.as_str()).bind::<diesel::sql_types::Text,_>(actor.to_string()).execute(&mut *conn).await.unwrap();
            drop(conn);
            assert!(
                !store
                    .accepted_own_leave_bound_result(
                        event,
                        commit,
                        &human.pcr.history.account,
                        &origin.service_core_id()
                    )
                    .await
                    .unwrap()
            );
            let mut conn = origin_pool.get().await.unwrap();
            diesel::sql_query("UPDATE member_state_current_states SET current_stream_position=current_stream_position-1 WHERE realm_id=$1 AND member_id=$2")
                .bind::<diesel::sql_types::Text,_>(event.realm_id.as_str()).bind::<diesel::sql_types::Text,_>(actor.to_string()).execute(&mut *conn).await.unwrap();
            drop(conn);
            assert!(
                store
                    .accepted_own_leave_bound_result(
                        event,
                        commit,
                        &human.pcr.history.account,
                        &origin.service_core_id()
                    )
                    .await
                    .unwrap()
            );
            terminal = Some((event.clone(), commit.clone()));
        }
        previous = request.authority_commit;
    }
    let (event, commit) = terminal.unwrap();
    assert!(
        !store
            .accepted_own_leave_bound_result(
                &event,
                &commit,
                &human.pcr.history.account,
                &origin.service_core_id()
            )
            .await
            .unwrap(),
        "a real accepted Circle rejoin cannot revive an old leave result"
    );
    parent_join
}

#[expect(
    clippy::too_many_arguments,
    reason = "The regression reuses two actual Stations, their signed parent history and authenticated recovery context."
)]
async fn circle_cleanup_parent_rejoin(
    origin: &AppState,
    governor_state: &AppState,
    governor_pool: &PgPool,
    human: &historical_human::HumanFixture,
    governor: &historical_human::HumanFixture,
    old_parent: &coland_storage::AuthorityCommitTransaction,
    listener: Arc<RegisteredTlsPeer>,
    located: &mut crate::routing::realm_join::LocatedRealmAuthority,
    session: &SessionIdentityState,
) -> coland_storage::AuthorityCommitTransaction {
    let source = PgAuthorityCommitStore {
        pool: governor_pool.clone(),
    };
    let store = origin.authority_commits();
    let head = source
        .held_stream_head_commit(&old_parent.commit.stream_ref)
        .await
        .unwrap()
        .unwrap();
    let full = source
        .committed_event(&head.event_ref)
        .await
        .unwrap()
        .unwrap();
    let mut previous = old_parent.clone();
    previous.event = full.event;
    previous.commit = full.commit;
    previous.producer_signer_fact = source
        .producer_signer_fact(&previous.event, &previous.commit)
        .await
        .unwrap();
    for membership in ["leave", "join"] {
        eprintln!("[2133-parent-recovery] state={membership}");
        let mut request = Box::pin(foreign_request(origin,human,governor,&previous,EventKind::MemberState,
            serde_json::json!({"realm_id":old_parent.event.realm_id,"member_id":old_parent.event.actor_id,
                "membership":membership,"reason":"real parent replacement before explicit Circle cleanup"}))).await;
        seal_service_commit(&mut request.authority_commit.commit, governor_state);
        admit_fixture_event(governor_pool, request.clone()).await;
        let event = &request.authority_commit.event;
        let commit = &request.authority_commit.commit;
        store.queue_event(event, commit.committed_at).await.unwrap();
        store
            .retain_forwarded_submission(
                event,
                &SelfAuthoritySubmitRequestBody::Event(EventAdmissionSubmission::new(
                    event.clone(),
                )),
                commit.committed_at,
            )
            .await
            .unwrap();
        store
            .retain_forwarded_acceptance(event, commit, commit.committed_at)
            .await
            .unwrap();
        let scan = StreamScanRequestBody {
            realm_id: event.realm_id.clone(),
            stream_ref: commit.stream_ref.clone(),
            direction: if membership == "leave" {
                StreamScanDirection::After(Some(previous.commit.stream_position))
            } else {
                StreamScanDirection::Before(Some(commit.stream_position + 1))
            },
            limit: if membership == "leave" { 128 } else { 1 },
        };
        let coland_storage::PeerStreamScan::Page(page) = source
            .scan_stream_for_peer(
                &scan,
                &human.pcr.history.account.station_id,
                &governor_state.service_core_id(),
            )
            .await
            .unwrap()
        else {
            panic!("parent original interval missing");
        };
        assert_eq!(page.committed_events.len(), 1);
        let (rl, rg, rp, ra, rc) = (
            listener.clone(),
            governor_state.clone(),
            governor_pool.clone(),
            human.pcr.history.account.clone(),
            commit.clone(),
        );
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let reply_stop = stop.clone();
        let reply = tokio::spawn(async move {
            let scan_posts =
                tcp_scan(rl.clone(), page, scan, ra.clone(), rg.service_core_id()).await;
            assert_eq!(scan_posts, 1);
            if membership == "join" {
                assert_eq!(
                    tcp_opening_bootstrap(rl, rg, rp, ra, rc, reply_stop).await,
                    1
                );
            } else {
                serve_original_service_history_until_stop(rl, rg, rp, reply_stop).await;
            }
            scan_posts
        });
        eprintln!("[2133-parent-recovery] admitted and scanned");
        let result = Box::pin(super::super::replica_anchor::ensure_forwarded_target(
            origin,
            &governor_state.service_core_id(),
            event,
            Some(commit),
            located,
            session,
        ))
        .await;
        eprintln!("[2133-parent-recovery] recovered");
        stop.store(true, std::sync::atomic::Ordering::SeqCst);
        assert_eq!(result.unwrap(), Some(commit.clone()));
        assert_eq!(reply.await.unwrap(), 1);
        previous = request.authority_commit;
    }
    previous
}

#[expect(
    clippy::too_many_arguments,
    reason = "The negative regression uses the exact accepted Full and its two Station fixtures."
)]
async fn circle_cleanup_install_refusals(
    origin: &AppState,
    pool: &PgPool,
    governor_state: &AppState,
    human: &historical_human::HumanFixture,
    governor: &historical_human::HumanFixture,
    event: &arkret_wire::Event,
    commit: &arkret_wire::RealmCommit,
    fact: Option<arkret_models_collaboration::authority_commit::HistoricalProducerSignerFact>,
) {
    use diesel_async::RunQueryDsl as _;
    #[derive(diesel::QueryableByName)]
    struct Witness {
        #[diesel(sql_type=diesel::sql_types::Nullable<diesel::sql_types::Jsonb>)]
        parent: Option<serde_json::Value>,
    }
    let store = origin.authority_commits();
    scenario_future(|| circle_cleanup_missing_parent_is_frozen(origin, pool, human, event)).await;
    let baseline = opening_footprint(pool, &event.realm_id).await;
    let replica = CommittedReplica {
        local_service_id: origin.service_core_id(),
        authority: governor_state
            .authority_commits()
            .current_authority(&event.realm_id)
            .await
            .unwrap()
            .unwrap(),
        historical_commit: None,
        event: event.clone(),
        commit: commit.clone(),
        producer_signer_fact: fact,
        genesis_event_ref: None,
        role: CommittedReplicaRole::AcceptedOwnCircleLeave {
            member_account_id: human.pcr.history.account.clone(),
        },
        received_at: commit.committed_at,
        welcomes: Vec::new(),
    };
    for role in [
        CommittedReplicaRole::HeldStream,
        CommittedReplicaRole::AcceptedOwnCircleLeave {
            member_account_id: governor.pcr.history.account.clone(),
        },
    ] {
        let mut rejected = replica.clone();
        rejected.role = role;
        assert_eq!(
            store
                .install_committed_replica(&rejected)
                .await
                .unwrap_err()
                .conflict_code(),
            Some(coland_storage::ConflictCode::CapabilityDenied)
        );
        assert_eq!(opening_footprint(pool, &event.realm_id).await, baseline);
    }
    let mut no_fact = replica.clone();
    no_fact.producer_signer_fact = None;
    assert!(store.install_committed_replica(&no_fact).await.is_err());
    assert_eq!(opening_footprint(pool, &event.realm_id).await, baseline);
    let mut wrong_fact = replica.clone();
    wrong_fact
        .producer_signer_fact
        .as_mut()
        .unwrap()
        .as_account_device_mut()
        .unwrap()
        .event_id = human.unit.transactions[0].event.event_id.clone();
    assert!(store.install_committed_replica(&wrong_fact).await.is_err());
    assert_eq!(opening_footprint(pool, &event.realm_id).await, baseline);
    let mut conn = pool.get().await.unwrap();
    let old=diesel::sql_query("SELECT circle_leave_parent_revision AS parent FROM authority_forward_attempts WHERE event_pk=(SELECT pk FROM canonical_events WHERE id=$1)")
        .bind::<diesel::sql_types::Binary,_>(event.event_id.token_bytes().to_vec()).get_result::<Witness>(&mut *conn).await.unwrap().parent;
    assert!(old.is_some());
    let original_intent =
        SelfAuthoritySubmitRequestBody::Event(EventAdmissionSubmission::new(event.clone()));
    for keep_original in [true, false] {
        diesel::sql_query("UPDATE authority_forward_attempts SET accepted_commit_json=NULL,original_submission_json=$2 WHERE event_pk=(SELECT pk FROM canonical_events WHERE id=$1)")
            .bind::<diesel::sql_types::Binary,_>(event.event_id.token_bytes().to_vec())
            .bind::<diesel::sql_types::Nullable<diesel::sql_types::Jsonb>,_>(keep_original.then(||serde_json::to_value(&original_intent).unwrap()))
            .execute(&mut *conn).await.unwrap();
        drop(conn);
        assert_eq!(
            store
                .install_committed_replica(&replica)
                .await
                .unwrap_err()
                .conflict_code(),
            Some(coland_storage::ConflictCode::CapabilityDenied)
        );
        assert_eq!(opening_footprint(pool, &event.realm_id).await, baseline);
        conn = pool.get().await.unwrap();
        diesel::sql_query("UPDATE authority_forward_attempts SET original_submission_json=$2,accepted_commit_json=$3 WHERE event_pk=(SELECT pk FROM canonical_events WHERE id=$1)")
            .bind::<diesel::sql_types::Binary,_>(event.event_id.token_bytes().to_vec())
            .bind::<diesel::sql_types::Jsonb,_>(serde_json::to_value(&original_intent).unwrap())
            .bind::<diesel::sql_types::Jsonb,_>(serde_json::to_value(commit).unwrap())
            .execute(&mut *conn).await.unwrap();
    }
    diesel::sql_query("UPDATE member_state_current_states SET current_stream_position=current_stream_position+1 WHERE realm_id=$1 AND member_id=$2")
        .bind::<diesel::sql_types::Text,_>(event.realm_id.as_str()).bind::<diesel::sql_types::Text,_>(event.actor_id.to_string()).execute(&mut *conn).await.unwrap();
    drop(conn);
    store
        .retain_forwarded_submission(event, &original_intent, commit.committed_at)
        .await
        .unwrap();
    assert_eq!(
        store
            .install_committed_replica(&replica)
            .await
            .unwrap_err()
            .conflict_code(),
        Some(coland_storage::ConflictCode::CapabilityDenied)
    );
    conn = pool.get().await.unwrap();
    let unchanged=diesel::sql_query("SELECT circle_leave_parent_revision AS parent FROM authority_forward_attempts WHERE event_pk=(SELECT pk FROM canonical_events WHERE id=$1)")
        .bind::<diesel::sql_types::Binary,_>(event.event_id.token_bytes().to_vec()).get_result::<Witness>(&mut *conn).await.unwrap().parent;
    assert_eq!(
        unchanged, old,
        "a replay must not replace its first parent cut"
    );
    diesel::sql_query("UPDATE member_state_current_states SET current_stream_position=current_stream_position-1 WHERE realm_id=$1 AND member_id=$2")
        .bind::<diesel::sql_types::Text,_>(event.realm_id.as_str()).bind::<diesel::sql_types::Text,_>(event.actor_id.to_string()).execute(&mut *conn).await.unwrap();
    #[derive(diesel::QueryableByName)]
    struct CleanupCut {
        #[diesel(sql_type=diesel::sql_types::Jsonb)]
        value: serde_json::Value,
    }
    let diagnostic = diesel::sql_query("SELECT jsonb_build_object('anchor_member',a.member_account_id,'join_commit',a.join_commit_id, \
        'member_commit',m.current_commit_id,'member_value',m.value,'parent',f.circle_leave_parent_revision, \
        'parent_commit',p.current_commit_id,'parent_position',p.current_stream_position,'parent_state',p.membership, \
        'join_payload',j.envelope->'payload','active',circle.value->>'state') AS value \
        FROM canonical_events e JOIN authority_forward_attempts f ON f.event_pk=e.pk \
        LEFT JOIN replica_stream_anchors a ON a.realm_id=e.envelope->>'realm_id' AND a.stream_key=(SELECT stream_key FROM realm_commits WHERE commit_id=$2) \
        LEFT JOIN circle_member_state_current_states m ON m.realm_id=a.realm_id AND m.circle_id=e.envelope->'scope_ref'->>'circle_id' AND m.member_id=$3 \
        LEFT JOIN member_state_current_states p ON p.realm_id=a.realm_id AND p.member_id=$3 \
        LEFT JOIN canonical_events j ON j.pk=(SELECT event_pk FROM realm_commits WHERE commit_id=a.join_commit_id) \
        LEFT JOIN circle_current_states circle ON circle.circle_id=e.envelope->'scope_ref'->>'circle_id' WHERE e.id=$1")
        .bind::<diesel::sql_types::Binary,_>(event.event_id.token_bytes().to_vec())
        .bind::<diesel::sql_types::Text,_>(commit.previous_commit_ref.as_ref().unwrap().as_str())
        .bind::<diesel::sql_types::Text,_>(event.actor_id.to_string())
        .get_result::<CleanupCut>(&mut *conn).await.unwrap().value;
    // The replacement parent Snapshot cannot disclose metadata of this
    // effective-invalid Circle. Its own canonical join is still held, and
    // only the separately accepted cleanup result may install its leave.
    assert!(diagnostic["active"].is_null());
    assert_eq!(diagnostic["join_commit"], diagnostic["member_commit"]);
    assert_eq!(
        diagnostic["parent"]["commit_id"],
        diagnostic["parent_commit"]
    );
    assert_eq!(
        diagnostic["parent"]["stream_position"],
        diagnostic["parent_position"]
    );
    assert_ne!(
        diagnostic["parent"],
        diagnostic["join_payload"]["parent_membership_revision"]
    );
    diesel::sql_query("UPDATE authority_forward_attempts SET circle_leave_parent_revision=NULL WHERE event_pk=(SELECT pk FROM canonical_events WHERE id=$1)")
        .bind::<diesel::sql_types::Binary,_>(event.event_id.token_bytes().to_vec()).execute(&mut *conn).await.unwrap();
    drop(conn);
    // An exact duplicate cannot fill an originally absent cut from later current.
    store
        .retain_forwarded_submission(
            event,
            &SelfAuthoritySubmitRequestBody::Event(EventAdmissionSubmission::new(event.clone())),
            commit.committed_at,
        )
        .await
        .unwrap();
    assert_eq!(
        store
            .install_committed_replica(&replica)
            .await
            .unwrap_err()
            .conflict_code(),
        Some(coland_storage::ConflictCode::CapabilityDenied)
    );
    assert_eq!(opening_footprint(pool, &event.realm_id).await, baseline);
    let mut conn = pool.get().await.unwrap();
    let absent=diesel::sql_query("SELECT circle_leave_parent_revision AS parent FROM authority_forward_attempts WHERE event_pk=(SELECT pk FROM canonical_events WHERE id=$1)")
        .bind::<diesel::sql_types::Binary,_>(event.event_id.token_bytes().to_vec()).get_result::<Witness>(&mut *conn).await.unwrap().parent;
    assert_eq!(absent, None);
    diesel::sql_query("UPDATE authority_forward_attempts SET circle_leave_parent_revision=$2 WHERE event_pk=(SELECT pk FROM canonical_events WHERE id=$1)")
        .bind::<diesel::sql_types::Binary,_>(event.event_id.token_bytes().to_vec()).bind::<diesel::sql_types::Nullable<diesel::sql_types::Jsonb>,_>(old)
        .execute(&mut *conn).await.unwrap();
}

async fn circle_cleanup_missing_parent_is_frozen(
    origin: &AppState,
    pool: &PgPool,
    human: &historical_human::HumanFixture,
    event: &arkret_wire::Event,
) {
    use diesel_async::RunQueryDsl as _;
    #[derive(diesel::QueryableByName)]
    struct Witness {
        #[diesel(sql_type=diesel::sql_types::Nullable<diesel::sql_types::Jsonb>)]
        parent: Option<serde_json::Value>,
    }
    let mut queued = event.clone();
    queued.created_at += Duration::milliseconds(1);
    let queued = coland_test_support::device_authorization_history::sign_event(
        queued,
        human.pcr.history.device_verification_method.clone(),
        human.pcr.history.founding_device_signing_seed,
    );
    let store = origin.authority_commits();
    store.queue_event(&queued, queued.created_at).await.unwrap();
    let intent =
        SelfAuthoritySubmitRequestBody::Event(EventAdmissionSubmission::new(queued.clone()));
    let mut conn = pool.get().await.unwrap();
    // Model a local parent cut whose declared revision has no held source.
    // A forwarding intent may be retained, but cannot freeze a proven join.
    diesel::sql_query("UPDATE member_state_current_states SET current_stream_position=current_stream_position+1 WHERE realm_id=$1 AND member_id=$2")
        .bind::<diesel::sql_types::Text,_>(event.realm_id.as_str()).bind::<diesel::sql_types::Text,_>(event.actor_id.to_string()).execute(&mut *conn).await.unwrap();
    drop(conn);
    store
        .retain_forwarded_submission(&queued, &intent, queued.created_at)
        .await
        .unwrap();
    let mut conn = pool.get().await.unwrap();
    let absent=diesel::sql_query("SELECT circle_leave_parent_revision AS parent FROM authority_forward_attempts WHERE event_pk=(SELECT pk FROM canonical_events WHERE id=$1)")
        .bind::<diesel::sql_types::Binary,_>(queued.event_id.token_bytes().to_vec()).get_result::<Witness>(&mut *conn).await.unwrap().parent;
    assert_eq!(absent, None);
    diesel::sql_query("UPDATE member_state_current_states SET current_stream_position=current_stream_position-1 WHERE realm_id=$1 AND member_id=$2")
        .bind::<diesel::sql_types::Text,_>(event.realm_id.as_str()).bind::<diesel::sql_types::Text,_>(event.actor_id.to_string()).execute(&mut *conn).await.unwrap();
    drop(conn);
    store
        .retain_forwarded_submission(&queued, &intent, queued.created_at)
        .await
        .unwrap();
    let mut conn = pool.get().await.unwrap();
    let unchanged=diesel::sql_query("SELECT circle_leave_parent_revision AS parent FROM authority_forward_attempts WHERE event_pk=(SELECT pk FROM canonical_events WHERE id=$1)")
        .bind::<diesel::sql_types::Binary,_>(queued.event_id.token_bytes().to_vec()).get_result::<Witness>(&mut *conn).await.unwrap().parent;
    assert_eq!(
        unchanged, None,
        "a now-proven parent cannot fill the first absent cut"
    );
    drop(conn);
    assert!(
        store
            .committed_event(&queued.event_id)
            .await
            .unwrap()
            .is_none()
    );
}

async fn tcp_opening_bootstrap(
    listener: Arc<RegisteredTlsPeer>,
    governor: AppState,
    pool: PgPool,
    from: AccountId,
    expected: arkret_wire::RealmCommit,
    history_stop: Arc<std::sync::atomic::AtomicBool>,
) -> usize {
    use coland_storage::DeliveryPolicyStoreRegistry as _;
    let records = PgPersistenceStore::new(pool.clone())
        .webvh()
        .list_log_events(governor.service_did().as_str())
        .await
        .unwrap();
    assert!(!records.is_empty());
    let mut log = Vec::new();
    for record in records {
        log.extend(arkret_canonical::canonical_json_bytes(&record.operation).unwrap());
        log.push(b'\n');
    }
    let verified = arkret_identity::verify_did_webvh_v1_chain_and_witness_bytes(
        &governor.service_did(),
        &log,
        None,
    )
    .unwrap();
    let document = arkret_canonical::canonical_json_bytes(&verified.log.head_state).unwrap();
    let log_url = reqwest::Url::parse(
        &arkret_identity::DidWebvhResolver::log_url(&governor.service_did()).unwrap(),
    )
    .unwrap();
    let doc_url = reqwest::Url::parse(
        &arkret_identity::DidWebvhResolver::document_url(&governor.service_did()).unwrap(),
    )
    .unwrap();
    let base = reqwest::Url::parse(&governor.config().public_base_url).unwrap();
    assert_eq!(log_url.origin(), base.origin());
    assert_eq!(doc_url.origin(), base.origin());
    tokio::task::spawn_blocking(move || {
    let (mut stream, mut bytes, end) = registered_post(&listener);
    let mut buf = [0u8; 2048];
    let header = std::str::from_utf8(&bytes[..end]).unwrap();
    assert!(header.starts_with("POST /_arkret/peer/realm-joins/bootstrap HTTP/1.1"));
    let fields = header
        .lines()
        .filter_map(|v| {
            v.split_once(':')
                .map(|(k, v)| (k.to_ascii_lowercase(), v.trim().to_owned()))
        })
        .collect::<std::collections::BTreeMap<_, _>>();
    assert_eq!(
        fields.get("source-service-id"),
        Some(&from.station_id.to_string())
    );
    assert_eq!(fields.get("destination-service-id"), Some(&governor.service_core_id().to_string()));
    assert!(
        fields.contains_key("signature-input")
            && fields.contains_key("signature")
            && fields.contains_key("content-digest")
    );
    let length = fields["content-length"].parse::<usize>().unwrap();
    assert!(length < 1024 * 1024);
    while bytes.len() < end + length {
        let n = stream.read(&mut buf).unwrap();
        assert!(n > 0);
        bytes.extend_from_slice(&buf[..n]);
    }
    let actual: arkret_models_collaboration::governance::realm_join_intake::PeerRealmJoinBootstrapRequestBody =
        serde_json::from_slice(&bytes[end..end + length]).unwrap();
    assert_eq!(actual.realm_id, expected.realm_id);
    assert_eq!(actual.member_account_id, from);
    assert_eq!(actual.membership_commit_id, expected.commit_id);
    let outcome = tokio::runtime::Handle::current().block_on(async {
        let store = PgAuthorityCommitStore { pool };
        let material = store.member_station_bootstrap_material(
            &actual.realm_id, &actual.member_account_id, &actual.membership_commit_id,
        ).await.unwrap().unwrap();
        let key = ed25519_dalek::SigningKey::from_bytes(&historical_human::station_authority_seed());
        let snapshot = coland_services::authority_commit::build_signed_realm_state_snapshot(
            &material, governor.service_verification_method("notary-key").unwrap(),
            &key, Utc::now(),
        ).unwrap();
        let nonce = crate::routing::realm_join::nonce_for_request(&actual.request_id).unwrap();
        let authority_bundle = crate::routing::realm_join::local_authority_bundle(
            &governor, &actual.realm_id, &nonce,
        ).await.unwrap();
        arkret_models_collaboration::governance::realm_join_intake::PeerRealmJoinBootstrapResponseBody {
            request_id: actual.request_id, visible_stream_heads: snapshot.visible_stream_heads.clone(), snapshot, authority_bundle,
        }
    });
    let body = arkret_canonical::canonical_json_bytes(&outcome).unwrap();
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(response.as_bytes()).unwrap();
    stream.write_all(&body).unwrap();
    stream.flush().unwrap();
    assert!(!stream.conn.is_handshaking());
    drop(stream);
    listener.listener.set_nonblocking(true).unwrap();
    let mut history_requests = 0;
    while !history_stop.load(std::sync::atomic::Ordering::SeqCst) {
        let socket = match listener.listener.accept() {
            Ok((socket, _)) => socket,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(std::time::Duration::from_millis(1));
                continue;
            }
            Err(error) => panic!("history listener: {error}"),
        };
        socket.set_nonblocking(false).unwrap();
        socket.set_read_timeout(Some(std::time::Duration::from_secs(10))).unwrap();
        socket.set_write_timeout(Some(std::time::Duration::from_secs(10))).unwrap();
        let mut stream = rustls::StreamOwned::new(
            rustls::ServerConnection::new(listener.tls.clone()).unwrap(), socket);
        let mut request = Vec::new();
        loop {
            let n = stream.read(&mut buf).unwrap();
            assert!(n > 0);
            request.extend_from_slice(&buf[..n]);
            assert!(request.len() < 1024 * 1024);
            if request.windows(4).any(|v| v == b"\r\n\r\n") { break; }
        }
        let request = std::str::from_utf8(&request).unwrap();
        let line = request.lines().next().unwrap();
        let body = if line == format!("GET {} HTTP/1.1", log_url.path()) {
            &log
        } else {
            assert_eq!(line, format!("GET {} HTTP/1.1", doc_url.path()));
            &document
        };
        let header = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
        stream.write_all(header.as_bytes()).unwrap();
        stream.write_all(body).unwrap();
        stream.flush().unwrap();
        assert!(!stream.conn.is_handshaking());
        history_requests += 1;
    }
    // Callers install a freshly authenticated route with verified method history.
    // The receiver still verifies that evidence; it need not refetch the same
    // history over HTTP. Exact originals and fail-closed cases are checked by
    // the calling scenario (identity/did-usage-and-verification.md section 5).
    eprintln!("peer bootstrap additional method-history reads={history_requests}");
    listener.listener.set_nonblocking(false).unwrap();
    1
    }).await.unwrap()
}

async fn opening_footprint(pool: &PgPool, realm: &arkret_wire::RealmId) -> (i64, i64, i64, i64) {
    use diesel_async::RunQueryDsl as _;
    #[derive(diesel::QueryableByName)]
    struct Counts {
        #[diesel(sql_type = diesel::sql_types::BigInt)]
        events: i64,
        #[diesel(sql_type = diesel::sql_types::BigInt)]
        commits: i64,
        #[diesel(sql_type = diesel::sql_types::BigInt)]
        anchors: i64,
        #[diesel(sql_type = diesel::sql_types::BigInt)]
        facts: i64,
    }
    let mut conn = pool.get().await.unwrap();
    let c = diesel::sql_query(
        "SELECT (SELECT count(*) FROM canonical_events WHERE realm_id=$1 AND state='committed') AS events, \
         (SELECT count(*) FROM realm_commits WHERE realm_id=$1) AS commits, \
         (SELECT count(*) FROM replica_stream_anchors WHERE realm_id=$1) AS anchors, \
         (SELECT count(*) FROM agent_producer_signer_keys f JOIN realm_commits c ON c.commit_id=f.commit_id \
          WHERE c.realm_id=$1 AND f.producer_source_fact IS NOT NULL) AS facts"
    ).bind::<diesel::sql_types::Text,_>(realm.as_str())
     .get_result::<Counts>(&mut *conn).await.unwrap();
    (c.events, c.commits, c.anchors, c.facts)
}

async fn recovery_acceptance_rows(pool: &PgPool) -> serde_json::Value {
    use diesel_async::RunQueryDsl as _;
    #[derive(diesel::QueryableByName)]
    struct Row {
        #[diesel(sql_type = diesel::sql_types::Jsonb)]
        value: serde_json::Value,
    }
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query("SELECT jsonb_build_object(\
        'events',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text),'[]') FROM canonical_events r),\
        'commits',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text),'[]') FROM realm_commits r),\
        'anchors',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text),'[]') FROM replica_stream_anchors r),\
        'facts',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text),'[]') FROM agent_producer_signer_keys r),\
        'authority',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text),'[]') FROM realm_authorities r),\
        'current_heads',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text),'[]') FROM current_state_heads r),\
        'current',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text),'[]') FROM current_state_versions r)\
    ) AS value").get_result::<Row>(&mut *conn).await.unwrap().value
}

/// Keep the real verified method history available for this request lifecycle.
/// A fresh authenticated route can already supply it, so zero refetches is valid.
async fn serve_original_service_history_until_stop(
    listener: Arc<RegisteredTlsPeer>,
    governor: AppState,
    pool: PgPool,
    stop: Arc<std::sync::atomic::AtomicBool>,
) {
    register_original_peer_history(&listener, &governor, &pool).await;
    let reads = registered_history_until_stop(listener, stop).await;
    eprintln!("original service additional method-history reads={reads}");
}
