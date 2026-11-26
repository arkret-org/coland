//! Real production peer router and RFC 9421 ingress over a leased PostgreSQL
//! database. Native histories are method-verified and committed through the
//! existing DID owner; no accepted Organization Event is seeded by SQL.

#[path = "../../../../storage-postgres/tests/support/organization_origin.rs"]
mod organization_origin;
use std::sync::Arc;

use arkret_models_collaboration::authority_commit::{
    PeerAuthoritySubmitRequestBody, PeerAuthoritySubmitResponseBody,
};
use arkret_wire::AuthoritySubmitResponseBody;
use chrono::{Duration, Utc};
use coland_storage_postgres::{PgPersistenceStore, PgPool};
use coland_test_support::AppStateTestExt as _;
use organization_origin::OrganizationFixture;
use salvo::conn::{Acceptor as _, Listener as _};
use salvo::http::StatusCode;
use salvo::test::{ResponseExt as _, TestClient};

use super::super::AppState;
use crate::sql_fault_matrix;

struct OriginTls(rustls::ServerConfig);
impl salvo::conn::IntoConfigStream<rustls::ServerConfig> for OriginTls {
    type Stream = futures_util::stream::Once<std::future::Ready<rustls::ServerConfig>>;
    fn into_stream(self) -> Self::Stream {
        futures_util::stream::once(std::future::ready(self.0))
    }
}
struct OriginHandler {
    histories: Arc<std::sync::RwLock<std::collections::BTreeMap<String, Vec<u8>>>>,
    gets: Arc<std::sync::atomic::AtomicUsize>,
}
#[async_trait::async_trait]
impl salvo::Handler for OriginHandler {
    async fn handle(
        &self,
        req: &mut salvo::Request,
        _depot: &mut salvo::Depot,
        res: &mut salvo::Response,
        _ctrl: &mut salvo::FlowCtrl,
    ) {
        self.gets.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let bytes = self
            .histories
            .read()
            .unwrap()
            .get(req.uri().path())
            .cloned();
        if let Some(bytes) = bytes {
            res.status_code = Some(StatusCode::OK);
            res.headers_mut()
                .insert("content-type", "application/jsonl".parse().unwrap());
            res.write_body(bytes).unwrap();
        } else {
            res.status_code = Some(StatusCode::NOT_FOUND);
        }
    }
}
struct NativeOrigin {
    base: String,
    histories: Arc<std::sync::RwLock<std::collections::BTreeMap<String, Vec<u8>>>>,
    gets: Arc<std::sync::atomic::AtomicUsize>,
    server: tokio::task::JoinHandle<()>,
}
impl Drop for NativeOrigin {
    fn drop(&mut self) {
        self.server.abort();
    }
}
impl NativeOrigin {
    async fn start() -> Self {
        let acceptor = salvo::conn::TcpListener::new("127.0.0.1:0")
            .rustls(OriginTls(coland_test_support::native_tls::server_config()))
            .bind()
            .await;
        let base = format!(
            "https://{}/",
            acceptor.holdings()[0].local_addr.as_ipv4().unwrap()
        );
        let histories = Arc::new(std::sync::RwLock::new(std::collections::BTreeMap::new()));
        let gets = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let router = salvo::Router::new().push(salvo::Router::with_path("{**artifact}").get(
            OriginHandler {
                histories: histories.clone(),
                gets: gets.clone(),
            },
        ));
        let server = tokio::spawn(async move {
            salvo::Server::new(acceptor).serve(router).await;
        });
        Self {
            base,
            histories,
            gets,
            server,
        }
    }
    fn publish(&self, entries: &[serde_json::Value]) {
        let did: arkret_wire::Did = entries.last().unwrap()["state"]["id"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap();
        let url =
            url::Url::parse(&arkret_identity::DidWebvhResolver::log_url(&did).unwrap()).unwrap();
        assert_eq!(url.origin().ascii_serialization() + "/", self.base);
        let bytes = entries
            .iter()
            .flat_map(|entry| {
                let mut bytes = arkret_canonical::canonical_json_bytes(entry).unwrap();
                bytes.push(b'\n');
                bytes
            })
            .collect();
        self.histories
            .write()
            .unwrap()
            .insert(url.path().to_owned(), bytes);
    }
    fn publish_fixture(&self, fixture: &OrganizationFixture) {
        self.publish(&fixture.write.organization_log_entries);
        let arkret_models_identity::ResolutionMethodHistoryEvidence::WebvhLog {
            log_entries, ..
        } = &fixture
            .write
            .producer_service_resolution
            .as_ref()
            .unwrap()
            .method_history_evidence
        else {
            panic!("expected native Service")
        };
        self.publish(log_entries);
    }
    async fn warm(&self, state: &AppState, fixture: &OrganizationFixture) {
        self.publish_fixture(fixture);
        super::native_history(state, &fixture.organization_did)
            .await
            .unwrap();
        super::native_history(state, &fixture.producer.did.parse().unwrap())
            .await
            .unwrap();
    }
}

fn station() -> (AppState, PgPool, Arc<dyn coland_storage::PersistenceStore>) {
    station_at(None)
}

fn station_at(base: Option<&str>) -> (AppState, PgPool, Arc<dyn coland_storage::PersistenceStore>) {
    let mut external = coland_test_support::app_config();
    external.notary_signing_key_seed = Some([83; 32]);
    external.seed_demo_data = false;
    external.development_mode = true;
    if let Some(base) = base {
        external.public_base_url = base.to_owned();
    }
    let (leased, pool) = coland_test_support::app_state_with_pool(external.clone());
    let lease = leased.test_persistence();
    let config = crate::config::AppConfig {
        public_base_url: external.public_base_url.clone(),
        notary_signing_key_seed: Some([83; 32]),
        seed_demo_data: false,
        development_mode: true,
        ..crate::config::AppConfig::test_default()
    };
    assert_eq!(config.trust_domain, external.trust_domain);
    let state = AppState::new_with_service_identity(
        config,
        coland_storage_postgres::Db {
            pool: Some(pool.clone()),
        },
        Arc::new(PgPersistenceStore::new(pool.clone())),
        coland_test_support::fixture_service_identity(&external),
        leased.service_resolution_commitment().as_ref().clone(),
        [83; 32],
    );
    (state, pool, lease)
}

async fn submit(
    state: &AppState,
    request: &PeerAuthoritySubmitRequestBody,
    signed: bool,
) -> salvo::Response {
    let signer = if signed {
        Some(super::governor_signer(state).await.unwrap())
    } else {
        None
    };
    submit_peer_source(state, request, state.service_id(), signer).await
}

async fn submit_peer_source(
    state: &AppState,
    request: &PeerAuthoritySubmitRequestBody,
    source: &str,
    signer: Option<(arkret_wire::DidUrl, Arc<ed25519_dalek::SigningKey>)>,
) -> salvo::Response {
    let target = format!(
        "{}/_arkret/peer/events",
        state.config().public_base_url.trim_end_matches('/')
    );
    let body = arkret_canonical::canonical_json_bytes(request).unwrap();
    let mut headers = reqwest::header::HeaderMap::new();
    for (name, value) in [
        ("content-type", "application/json".to_owned()),
        (
            "arkret-operation",
            arkret_wire::ServiceOperationId::PEER_EVENTS_COMMAND_SUBMIT_V1.to_owned(),
        ),
        (
            "content-digest",
            crate::http_signature::rfc9530_content_digest(&body),
        ),
        ("source-service-id", source.to_owned()),
        ("destination-service-id", state.service_id().to_owned()),
        (
            "source-trust-domain",
            state.config().trust_domain.to_string(),
        ),
        (
            "destination-trust-domain",
            state.config().trust_domain.to_string(),
        ),
    ] {
        headers.insert(
            reqwest::header::HeaderName::from_bytes(name.as_bytes()).unwrap(),
            value.parse().unwrap(),
        );
    }
    if let Some((method, signing_key)) = signer {
        let uri: salvo::http::uri::Uri = target.parse().unwrap();
        let parts = arkret_signatures::http_signature::SignedRequestParts {
            method: "POST".into(),
            target_uri: target.clone(),
            authority: uri.authority().unwrap().as_str().to_owned(),
            path: uri.path().to_owned(),
            body_digest: Some(crate::http_signature::rfc9530_content_digest(&body)),
            headers: headers
                .iter()
                .map(|(name, value)| (name.to_string(), value.to_str().unwrap().to_owned()))
                .collect(),
        };
        let signature = arkret_signatures::http_signature::sign_http_message_for_scenario(
            &parts,
            arkret_signatures::http_signature::HttpSignatureScenario::ServiceToServiceV1,
            &[
                "content-digest",
                "source-trust-domain",
                "destination-trust-domain",
            ],
            "sig1",
            method.as_str(),
            Utc::now().timestamp(),
            signing_key.as_ref(),
        )
        .unwrap();
        headers.insert(
            "signature-input",
            signature.signature_input_header.parse().unwrap(),
        );
        headers.insert("signature", signature.signature_header.parse().unwrap());
    }
    let mut builder = TestClient::post(target).body(body);
    for (name, value) in &headers {
        builder = builder.add_header(name.clone(), value.to_str().unwrap(), true);
    }
    builder.send(&crate::service(state.clone())).await
}

#[tokio::test]
async fn signed_peer_single_create_accepts_original_and_cold_replay_without_human_device() {
    crate::boxed_future(|| async {
        let (state, pool, _lease) = station();
        let origin=NativeOrigin::start().await;
        let mut fixture = OrganizationFixture::at_origin(false, true, &origin.base);
        fixture.rebind_hosting(state.service_core_id(), state.config().trust_domain.clone(),
            super::governor_signer(&state).await.unwrap().0, [83; 32]);
        origin.warm(&state,&fixture).await;
        let gets=origin.gets.load(std::sync::atomic::Ordering::SeqCst);
        let request = PeerAuthoritySubmitRequestBody::AuthorityForwardEvent(fixture.write.request.clone());
        let before = sql_fault_matrix::snapshot(&pool).await;
        let unsigned = submit(&state, &request, false).await;
        assert_eq!(unsigned.status_code, Some(StatusCode::UNAUTHORIZED));
        assert_eq!(sql_fault_matrix::snapshot(&pool).await, before);
        let mut first = submit(&state, &request, true).await;
        assert_eq!(first.status_code, Some(StatusCode::OK));
        assert!(origin.gets.load(std::sync::atomic::Ordering::SeqCst)>=gets+2,
            "first admission must freshly fetch both native origins despite retained history");
        let first: PeerAuthoritySubmitResponseBody = first.take_json().await.unwrap();
        let PeerAuthoritySubmitResponseBody::AuthorityForward(arkret_models_collaboration::authority_commit::PeerAuthorityForwardResponseBody {
            response_body: arkret_models_collaboration::authority_commit::ForwardedAuthorityResponseBody::Ordinary(AuthoritySubmitResponseBody::Accepted { commit, .. }), ..
        }) = &first else { panic!("native Organization create was not accepted") };
        assert_eq!(commit.stream_position, 0);
        assert_eq!(commit.governance_generation, 0);
        let event = &fixture.write.request.event_submission.event;
        let (_, projected) = arkret_identity::organization_pcr_genesis::verify_organization_pcr_genesis_source(
            &fixture.write.request, &state.service_core_id(),
            &fixture.write.organization_log_entries, &fixture.write.organization_witness_records,
            fixture.write.producer_service_resolution.as_ref(), commit.committed_at,
        ).unwrap();
        assert_eq!(commit.producer_signer_fact_digest.as_ref(), Some(&projected.digest().unwrap()));
        let retained = state.authority_commits().producer_signer_fact(event, commit).await.unwrap().unwrap();
        assert_eq!(retained, arkret_models_collaboration::authority_commit::HistoricalProducerSignerFact::OrganizationGenesis(projected));
        let fact_bytes = arkret_canonical::canonical_json_bytes(&retained).unwrap();

        let rows = sql_fault_matrix::snapshot(&pool).await;
        assert_eq!(rows["organization_pcr_genesis_sources"].as_array().unwrap().len(), 1);
        assert_eq!(rows["canonical_events"].as_array().unwrap().len(), 1);
        assert_eq!(rows["realm_commits"].as_array().unwrap().len(), 1);
        assert!(rows["devices"].as_array().unwrap().is_empty());
        assert!(rows["sessions"].as_array().unwrap().is_empty());
        // Recreate the real serving state and router over the same durable
        // store, not an in-memory accepted-result or key cache.
        let cold = AppState::new_with_service_identity(state.config().clone(),
            coland_storage_postgres::Db { pool: Some(pool.clone()) }, Arc::new(PgPersistenceStore::new(pool.clone())),
            state.service_identity_state().as_ref().clone(), state.service_resolution_commitment().as_ref().clone(), [83; 32]);
        let mut again = submit(&cold, &request, true).await;
        assert_eq!(again.status_code, Some(StatusCode::OK));
        let again: PeerAuthoritySubmitResponseBody = again.take_json().await.unwrap();
        assert_eq!(arkret_canonical::canonical_json_bytes(&first).unwrap(), arkret_canonical::canonical_json_bytes(&again).unwrap());
        let cold_fact = cold.authority_commits().producer_signer_fact(
            &fixture.write.request.event_submission.event, commit,
        ).await.unwrap().unwrap();
        assert_eq!(arkret_canonical::canonical_json_bytes(&cold_fact).unwrap(), fact_bytes);
        assert_eq!(sql_fault_matrix::snapshot(&pool).await, rows);
    }).await;
}

#[tokio::test]
async fn authenticated_peer_cannot_use_host_identity_instead_of_organization_root_approval() {
    crate::boxed_future(|| async {
        let (state, pool, _lease) = station();
        let origin = NativeOrigin::start().await;
        let mut fixture = OrganizationFixture::at_origin(false, false, &origin.base);
        fixture.rebind_hosting(
            state.service_core_id(),
            state.config().trust_domain.clone(),
            super::governor_signer(&state).await.unwrap().0,
            [83; 32],
        );
        origin.warm(&state, &fixture).await;
        fixture.write.request.event_submission.approval_signatures = None;
        let request = PeerAuthoritySubmitRequestBody::AuthorityForwardEvent(fixture.write.request);
        let before = sql_fault_matrix::snapshot(&pool).await;
        let mut response = submit(&state, &request, true).await;
        assert_eq!(response.status_code, Some(StatusCode::FORBIDDEN));
        let problem: arkret_wire::Problem = response.take_json().await.unwrap();
        assert_eq!(problem.code(), "capability_denied");
        assert_eq!(sql_fault_matrix::snapshot(&pool).await, before);
    })
    .await;
}

#[tokio::test]
async fn current_origin_revocation_overrides_retained_prefix_and_origin_rollback_is_refused() {
    crate::boxed_future(|| async {
        let (state, pool, _lease) = station();
        let origin = NativeOrigin::start().await;
        let mut fixture = OrganizationFixture::at_origin(true, false, &origin.base);
        fixture.rebind_hosting(
            state.service_core_id(),
            state.config().trust_domain.clone(),
            super::governor_signer(&state).await.unwrap().0,
            [83; 32],
        );
        // rebind_hosting authors finite approvals; remove them to exercise the
        // real ongoing-delegation source without changing the signed Event.
        fixture.write.request.event_submission.approval_signatures = None;
        origin.warm(&state, &fixture).await;
        let old = fixture.write.organization_log_entries.clone();
        let mut revoked = fixture.organization_state();
        revoked["arkret_governance"]["delegations"] = serde_json::json!([]);
        fixture.append_organization_state(
            revoked,
            fixture.write.queued_at - Duration::milliseconds(500),
        );
        origin.publish_fixture(&fixture);
        let mut before = sql_fault_matrix::snapshot(&pool).await;
        let request =
            PeerAuthoritySubmitRequestBody::AuthorityForwardEvent(fixture.write.request.clone());
        let mut response = submit(&state, &request, true).await;
        assert_eq!(response.status_code, Some(StatusCode::FORBIDDEN));
        let problem: arkret_wire::Problem = response.take_json().await.unwrap();
        assert_eq!(problem.code(), "capability_denied");
        let mut after = sql_fault_matrix::snapshot(&pool).await;
        // A fresh method-native revocation was legitimately retained by its
        // separate DID owner. No Organization admission or other row changed.
        for table in ["webvh_documents", "webvh_log_events"] {
            before.remove(table);
            after.remove(table);
        }
        assert_eq!(after, before);
        let durable = state
            .dids()
            .document(fixture.organization_did.as_str())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            durable.key_log_head.as_deref(),
            Some(
                arkret_canonical::canonical_sha256(
                    fixture.write.organization_log_entries.last().unwrap()
                )
                .unwrap()
                .as_str()
            )
        );
        origin.publish(&old);
        let before = sql_fault_matrix::snapshot(&pool).await;
        let mut response = submit(&state, &request, true).await;
        assert_eq!(response.status_code, Some(StatusCode::SERVICE_UNAVAILABLE));
        let problem: arkret_wire::Problem = response.take_json().await.unwrap();
        assert_eq!(problem.code(), "temporarily_unavailable");
        assert_eq!(sql_fault_matrix::snapshot(&pool).await, before);
    })
    .await;
}

#[path = "../../../../storage-postgres/tests/support/organization_change.rs"]
mod organization_change;

async fn accepted_executor_device(
    state: &AppState,
    pool: &PgPool,
) -> coland_test_support::pcr_genesis::PcrGenesisFixture {
    use diesel_async::RunQueryDsl as _;
    let mut fixture = coland_test_support::pcr_genesis::PcrGenesisFixture::new(state.service_did());
    let (method, key) = super::governor_signer(state).await.unwrap();
    let mut previous = None;
    for (index, transaction) in fixture.unit.transactions.iter_mut().enumerate() {
        let commit = &mut transaction.commit;
        commit.previous_commit_ref = previous;
        commit.commit_id = arkret_wire::RealmCommitId::from_digest(arkret_canonical::sha256_bytes(
            arkret_canonical::canonical_json_bytes(
                &arkret_canonical::unsigned_value(commit, &["commit_id", "signature"]).unwrap(),
            )
            .unwrap(),
        ));
        commit.signature = arkret_signatures::detached_object::sign_detached_object(
            &arkret_canonical::unsigned_value(commit, &["signature"]).unwrap(),
            arkret_wire::DetachedSignatureContext::RealmCommit,
            method.clone(),
            commit.committed_at,
            key.as_ref(),
        )
        .unwrap();
        previous = Some(commit.commit_id.clone());
        fixture.history.commits[index] = commit.clone();
    }
    // This is deployment inventory configuration, not accepted Device state.
    // Every native PCR/Event/Device row is written by the real admission port.
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query("INSERT INTO device_inventory_station(singleton,station_id) VALUES(TRUE,$1) ON CONFLICT(singleton) DO NOTHING")
        .bind::<diesel::sql_types::Text,_>(state.service_core_id().as_str()).execute(&mut *conn).await.unwrap();
    drop(conn);
    fixture
        .admit_founding_device(&PgPersistenceStore::new(pool.clone()))
        .await
        .unwrap();
    fixture
}

fn accepted_native_commit(response: &PeerAuthoritySubmitResponseBody) -> &arkret_wire::RealmCommit {
    let PeerAuthoritySubmitResponseBody::AuthorityForward(
        arkret_models_collaboration::authority_commit::PeerAuthorityForwardResponseBody {
            response_body:
                arkret_models_collaboration::authority_commit::ForwardedAuthorityResponseBody::Ordinary(
                    AuthoritySubmitResponseBody::Accepted { commit, .. },
                ),
            ..
        },
    ) = response
    else {
        panic!("actual native peer unit was not accepted")
    };
    commit
}

async fn actual_http_organization(
    state: &AppState,
) -> (OrganizationFixture, NativeOrigin, arkret_wire::RealmCommit) {
    let origin = NativeOrigin::start().await;
    let mut fixture = OrganizationFixture::at_origin(false, true, &origin.base);
    fixture.rebind_hosting(
        state.service_core_id(),
        state.config().trust_domain.clone(),
        super::governor_signer(state).await.unwrap().0,
        [83; 32],
    );
    origin.warm(state, &fixture).await;
    let request =
        PeerAuthoritySubmitRequestBody::AuthorityForwardEvent(fixture.write.request.clone());
    let mut response = submit(state, &request, true).await;
    assert_eq!(response.status_code, Some(StatusCode::OK));
    let response: PeerAuthoritySubmitResponseBody = response.take_json().await.unwrap();
    (fixture, origin, accepted_native_commit(&response).clone())
}

fn live_change(
    fixture: &OrganizationFixture,
    genesis: &arkret_wire::RealmCommit,
) -> arkret_wire::EventAdmissionSubmission {
    let now = arkret_canonical::normalize_timestamp_canonical(Utc::now());
    organization_change::author_change(
        fixture,
        fixture.write.transaction.event.event_id.clone(),
        genesis.commit_id.clone(),
        &organization_change::votes(fixture, now + Duration::seconds(1)),
        now + Duration::seconds(2),
    )
}

#[tokio::test]
async fn finite_service_successor_authenticates_the_actual_service_source_not_the_org_host() {
    crate::boxed_future(||async {
        let (state,pool,_lease)=station();
        let (fixture,_origin,genesis)=actual_http_organization(&state).await;
        let submission=live_change(&fixture,&genesis);
        let request=PeerAuthoritySubmitRequestBody::AuthorityForwardEvent(
            arkret_models_collaboration::authority_commit::PeerAuthorityForwardEventRequestBody::new(
                submission,None,None,None).unwrap());
        let source=arkret_wire::project_did_to_core_id(&arkret_wire::Did::new(&fixture.producer.did).unwrap()).unwrap();
        assert_ne!(source,state.service_core_id());
        let before=sql_fault_matrix::snapshot(&pool).await;
        let mut wrong=submit(&state,&request,true).await;
        let problem:arkret_wire::Problem=wrong.take_json().await.unwrap();
        assert_eq!(problem.code(),"failed_precondition");
        assert_eq!(sql_fault_matrix::snapshot(&pool).await,before);
        let signer=(arkret_wire::DidUrl::new(&fixture.producer.did_key_id).unwrap(),
            Arc::new(ed25519_dalek::SigningKey::from_bytes(&fixture.producer.did_key_seed)));
        let mut response=submit_peer_source(&state,&request,source.as_str(),Some(signer.clone())).await;
        assert_eq!(response.status_code,Some(StatusCode::OK));
        let first:PeerAuthoritySubmitResponseBody=response.take_json().await.unwrap();
        let commit=accepted_native_commit(&first);
        assert_eq!(commit.stream_position,1);
        assert_eq!(commit.previous_commit_ref.as_ref(),Some(&genesis.commit_id));
        assert!(commit.producer_signer_fact_digest.is_none());
        let rows=sql_fault_matrix::snapshot(&pool).await;
        let mut again=submit_peer_source(&state,&request,source.as_str(),Some(signer)).await;
        assert_eq!(again.status_code,Some(StatusCode::OK));
        let again:PeerAuthoritySubmitResponseBody=again.take_json().await.unwrap();
        assert_eq!(arkret_canonical::canonical_json_bytes(&first).unwrap(),arkret_canonical::canonical_json_bytes(&again).unwrap());
        assert_eq!(sql_fault_matrix::snapshot(&pool).await,rows);
    }).await;
}

#[tokio::test]
async fn finite_device_successor_uses_its_accepted_device_station_and_exact_complete_body() {
    crate::boxed_future(||async {
        let (state,pool,_lease)=station();
        let (fixture,_origin,genesis)=actual_http_organization(&state).await;
        let executor_origin=NativeOrigin::start().await;
        let (executor,executor_pool,_executor_lease)=station_at(Some(&executor_origin.base));
        assert_ne!(executor.service_core_id(),state.service_core_id());
        let resolution=crate::routing::system::service_resolution::current_authenticated_service_resolution(&executor).await.unwrap();
        let arkret_models_identity::ResolutionMethodHistoryEvidence::WebvhLog {log_entries,..}=&resolution.method_history_evidence
            else {panic!("real executor Station must publish native history")};
        executor_origin.publish(log_entries);
        super::native_history(&state,&executor.service_did()).await.unwrap();
        let human=accepted_executor_device(&executor,&executor_pool).await;
        let mut event=live_change(&fixture,&genesis).event;
        event.executed_by=Some(arkret_wire::ActorId::account(human.history.account.clone()));
        event.producer_proof=None;
        let created_at=event.created_at;
        let mut authored=arkret_wire::AuthoredEvent::finalize_with_digest_suite(event,arkret_canonical::DigestSuite::Sha256).unwrap();
        arkret_signatures::sign_event(&mut authored,
            &arkret_signatures::Ed25519DetachedJwsSigner::from_seed(human.history.founding_device_signing_seed,
                human.history.device_verification_method.as_str()),
            arkret_signatures::SignEventOptions::new().with_created_at(created_at)).unwrap();
        let submission=organization_change::approve_event(&fixture,authored.into_event(),
            &organization_change::votes(&fixture,created_at+Duration::seconds(1)));
        let mut request=PeerAuthoritySubmitRequestBody::AuthorityForwardEvent(
            arkret_models_collaboration::authority_commit::PeerAuthorityForwardEventRequestBody {
                branch:arkret_models_collaboration::authority_commit::AuthorityForwardBranch::AuthorityForward,
                event_submission:submission,mls_group_state_material:None,content_backup_sources:None,
                producer_device_evidence:None,producer_agent_evidence:None,successor_device_evidence:None,
            });
        // Production origin assembly decides current accepted Device status and
        // binds the complete original body, including the finite Org votes.
        super::super::fresh_device_request(&executor,&state.service_core_id(),&mut request).await.unwrap();
        request.validate().unwrap();
        let before=sql_fault_matrix::snapshot(&pool).await;
        let mut wrong=submit(&state,&request,true).await;
        let problem:arkret_wire::Problem=wrong.take_json().await.unwrap();
        assert_eq!(problem.code(),"failed_precondition");
        assert_eq!(sql_fault_matrix::snapshot(&pool).await,before);
        let source=executor.service_core_id();
        let signer=super::governor_signer(&executor).await.unwrap();
        let mut response=submit_peer_source(&state,&request,source.as_str(),Some(signer.clone())).await;
        assert_eq!(response.status_code,Some(StatusCode::OK));
        let first:PeerAuthoritySubmitResponseBody=response.take_json().await.unwrap();
        let commit=accepted_native_commit(&first);
        assert_eq!(commit.stream_position,1);
        assert_eq!(commit.previous_commit_ref.as_ref(),Some(&genesis.commit_id));
        assert!(commit.producer_signer_fact_digest.is_none());
        let rows=sql_fault_matrix::snapshot(&pool).await;
        assert_eq!(rows["realm_commits"].as_array().unwrap().len(),2);
        assert!(rows["devices"].as_array().unwrap().is_empty(),"an executor Device was borrowed into the Org Account");
        let mut again=submit_peer_source(&state,&request,source.as_str(),Some(signer)).await;
        assert_eq!(again.status_code,Some(StatusCode::OK));
        let again:PeerAuthoritySubmitResponseBody=again.take_json().await.unwrap();
        assert_eq!(arkret_canonical::canonical_json_bytes(&first).unwrap(),arkret_canonical::canonical_json_bytes(&again).unwrap());
        assert_eq!(sql_fault_matrix::snapshot(&pool).await,rows);
    }).await;
}
