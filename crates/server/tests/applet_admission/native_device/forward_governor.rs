//! Independent leased Stations consume real managed originals through native authority resolution.
use std::io::{Read as _, Write as _};

use super::*;

struct PublicStation {
    url: String,
    history: Arc<std::sync::RwLock<std::collections::BTreeMap<String, Vec<u8>>>>,
    drop_peer_responses: Arc<std::sync::atomic::AtomicBool>,
    peer_bodies: Arc<Mutex<Vec<Vec<u8>>>>,
    state: Arc<Mutex<Option<AppState>>>,
    stop: Arc<std::sync::atomic::AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl PublicStation {
    fn new() -> Self {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!("https://{}/", listener.local_addr().unwrap());
        let state = Arc::new(Mutex::new(None::<AppState>));
        let history = Arc::new(std::sync::RwLock::new(std::collections::BTreeMap::<
            String,
            Vec<u8>,
        >::new()));
        let served_history = history.clone();
        let drop_peer_responses = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let dropping = drop_peer_responses.clone();
        let peer_bodies = Arc::new(Mutex::new(Vec::new()));
        let captured = peer_bodies.clone();
        let served = state.clone();
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stopping = stop.clone();
        let runtime = tokio::runtime::Handle::current();
        let tls = Arc::new(
            rustls::ServerConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![rustls::pki_types::CertificateDer::from(
                    include_bytes!("../../fixtures/outbox-test-cert.der").to_vec(),
                )],
                rustls::pki_types::PrivateKeyDer::Pkcs8(
                    rustls::pki_types::PrivatePkcs8KeyDer::from(
                        include_bytes!("../../fixtures/outbox-test-key.der").to_vec(),
                    ),
                ),
            )
            .unwrap(),
        );
        let thread = std::thread::spawn(move || {
            let mut connections = Vec::new();
            while !std::sync::atomic::AtomicBool::load(
                &stopping,
                std::sync::atomic::Ordering::Relaxed,
            ) {
                let socket = match listener.accept() {
                    Ok((socket, _)) => socket,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(std::time::Duration::from_millis(5));
                        continue;
                    }
                    Err(error) => panic!("Station listener: {error}"),
                };
                let tls = tls.clone();
                let served = served.clone();
                let history = served_history.clone();
                let dropping = dropping.clone();
                let captured = captured.clone();
                let runtime = runtime.clone();
                connections.push(std::thread::spawn(move || {
                    socket.set_nonblocking(false).unwrap();
                    socket.set_read_timeout(Some(std::time::Duration::from_secs(15))).unwrap();
                    socket.set_write_timeout(Some(std::time::Duration::from_secs(15))).unwrap();
                    let mut stream = rustls::StreamOwned::new(rustls::ServerConnection::new(tls).unwrap(), socket);
                    let mut bytes = Vec::new(); let mut buf = [0;4096];
                    let end = loop {
                        let n=stream.read(&mut buf).unwrap_or(0); if n==0 {return;}
                        bytes.extend_from_slice(&buf[..n]); assert!(bytes.len()<2*1024*1024);
                        if let Some(end)=bytes.windows(4).position(|v|v==b"\r\n\r\n") {break end+4;}
                    };
                    let header=String::from_utf8(bytes[..end].to_vec()).unwrap();
                    let mut line=header.lines().next().unwrap().split_whitespace();
                    let method=line.next().unwrap(); let path=line.next().unwrap();
                    if method == "GET" {
                        if let Some(body) = history.read().unwrap().get(path) {
                            write!(stream,"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",body.len()).unwrap();
                            stream.write_all(body).unwrap(); stream.flush().unwrap(); return;
                        }
                    }
                    let headers=header.lines().skip(1).filter_map(|line|line.split_once(':')).collect::<Vec<_>>();
                    let len=headers.iter().find(|(k,_)|k.eq_ignore_ascii_case("content-length")).map(|(_,v)|v.trim().parse::<usize>().unwrap()).unwrap_or(0);
                    while bytes.len()<end+len {
                        let n=stream.read(&mut buf).unwrap();assert!(n>0);bytes.extend_from_slice(&buf[..n]);
                    }
                    let peer_post = method == "POST" && path == "/_arkret/peer/events";
                    if peer_post { captured.lock().unwrap().push(bytes[end..end+len].to_vec()); }
                    let state=served.lock().unwrap().clone().expect("real Station initialized");
                    let (status,body)=runtime.block_on(async {
                        let url=format!("{}{path}",state.config().public_base_url.trim_end_matches('/'));
                        let mut request=match method {"GET"=>TestClient::get(url),"POST"=>TestClient::post(url),_=>panic!("unexpected method")};
                        for (name,value) in headers { if !name.eq_ignore_ascii_case("host") && !name.eq_ignore_ascii_case("content-length") {request=request.add_header(salvo::http::header::HeaderName::from_bytes(name.as_bytes()).unwrap(),value.trim().to_owned(),true);} }
                        let mut response=request.body(bytes[end..end+len].to_vec()).send(&service(state)).await;
                        (response.status_code.unwrap().as_u16(),response.take_bytes(None).await.unwrap().to_vec())
                    });
                    if peer_post && (200..300).contains(&status) && std::sync::atomic::AtomicBool::load(&dropping, std::sync::atomic::Ordering::Relaxed) { return; }
                    let _=write!(stream,"HTTP/1.1 {status} result\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",body.len());
                    let _=stream.write_all(&body);let _=stream.flush();
                }));
            }
            for connection in connections {
                connection.join().unwrap();
            }
        });
        Self {
            url,
            history,
            drop_peer_responses,
            peer_bodies,
            state,
            stop,
            thread: Some(thread),
        }
    }

    async fn publish_original_history(&self, state: &AppState, pool: &PgPool) {
        use coland_storage::DeliveryPolicyStoreRegistry as _;
        let records = coland_storage_postgres::PgPersistenceStore::new(pool.clone())
            .webvh()
            .list_log_events(state.service_did().as_str())
            .await
            .unwrap();
        assert!(!records.is_empty());
        let mut log = Vec::new();
        for record in records {
            log.extend(arkret_canonical::canonical_json_bytes(&record.operation).unwrap());
            log.push(b'\n');
        }
        let verified = arkret_identity::verify_did_webvh_v1_chain_and_witness_bytes(
            &state.service_did(),
            &log,
            None,
        )
        .unwrap();
        let document = arkret_canonical::canonical_json_bytes(&verified.log.head_state).unwrap();
        let log_url = reqwest::Url::parse(
            &arkret_identity::DidWebvhResolver::log_url(&state.service_did()).unwrap(),
        )
        .unwrap();
        let doc_url = reqwest::Url::parse(
            &arkret_identity::DidWebvhResolver::document_url(&state.service_did()).unwrap(),
        )
        .unwrap();
        let base = reqwest::Url::parse(&self.url).unwrap();
        assert_eq!(log_url.origin(), base.origin());
        assert_eq!(doc_url.origin(), base.origin());
        let mut history = self.history.write().unwrap();
        history.insert(log_url.path().to_owned(), log);
        history.insert(doc_url.path().to_owned(), document);
    }
}
impl Drop for PublicStation {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            thread.join().unwrap();
        }
    }
}

#[path = "forward_handoff.rs"]
mod handoff;

async fn private_sources(pool: &PgPool, realm: &RealmId) -> Value {
    #[derive(diesel::QueryableByName)]
    struct Row {
        #[diesel(sql_type=diesel::sql_types::Jsonb)]
        value: Value,
    }
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query("SELECT jsonb_build_object('audit',(SELECT coalesce(jsonb_agg(to_jsonb(r)),'[]'::jsonb) FROM forwarded_producer_device_evidence r),'pcr',(SELECT coalesce(jsonb_agg(to_jsonb(r)),'[]'::jsonb) FROM principal_resolutions r),'profiles',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text),'[]'::jsonb) FROM actor_profile_current_results r WHERE realm_id<>$1)) AS value")
        .bind::<diesel::sql_types::Text,_>(realm.as_str()).get_result::<Row>(&mut conn).await.unwrap().value
}
async fn domain(pool: &PgPool) -> Value {
    let mut value = native_phase(|| managed_domain_snapshot(pool)).await;
    value.as_object_mut().unwrap().remove("device_nonces");
    value
}
fn rebind_origin(
    state: &AppState,
    request: &mut arkret_models_collaboration::authority_commit::PeerAuthorityForwardEventRequest,
) {
    // Even a fresh origin signature must not replace independent original/authority verification.
    let digest =
        arkret_models_collaboration::authority_commit::authority_forward_body_digest(request)
            .unwrap();
    let evidence = request.producer_device_evidence.as_mut().unwrap();
    let mut core = evidence.device_projection_attestation.attestation.clone();
    core.event_authorization.forward_body_digest = digest;
    evidence.device_projection_attestation =
        arkret_signatures::device_projection::sign_forward_device_projection_attestation(
            core,
            state.service_verification_method("notary-key").unwrap(),
            state.notary_signing_key().as_ref(),
        )
        .unwrap();
}

#[inline(never)]
fn governor_phase<F: std::future::Future>(
    label: &str,
    make: impl FnOnce() -> F,
) -> std::pin::Pin<Box<F>> {
    eprintln!(
        "[managed forward] {label} future={} bytes",
        std::mem::size_of::<F>()
    );
    ordinary_realm::case_future(make)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn independent_governor_accepts_bot_and_ghost_and_rejects_tampered_provenance_without_writes()
{
    for creator in 0..2 {
        tokio::spawn(governor_phase("case", || exercise(creator)))
            .await
            .unwrap();
    }
}
async fn exercise(creator: usize) {
    use arkret_models_collaboration::authority_commit::{
        PeerAuthoritySubmitRequest as R, SelfAuthoritySubmitRequest as S,
    };
    let mut ready = governor_phase("prerequisites", || handoff::prepare(creator)).await;
    let governor_id = ready.state.service_core_id();
    let peer = coland_services::authority_commit::AuthenticatedPeerContext {
        source_service_id: ready.context.fixture.state.service_core_id(),
        replay_receipt: None,
    };
    let realm = &ready.context.fixture.realm;
    let before_private = private_sources(&ready.pool, realm).await;
    assert_eq!(
        before_private["pcr"],
        json!([]),
        "no foreign private PCR is imported with the business Realm"
    );
    let mut profiles = Vec::new();
    for (index, (authority, key, _)) in ready.context.actors.iter().enumerate() {
        let bundle = if index == 0 {
            &ready.context.ghost_bundle
        } else {
            &ready.context.install.bot_body["managed_actor_bundle"]
        };
        let mut event = profile_create(
            &ready.context.fixture,
            &ready.context.install,
            bundle,
            authority,
            key,
            "public",
        );
        event.authorization_ref = Some(
            ready.context.install.outcome.capability_grant_refs[0]
                .clone()
                .into(),
        );
        let event = sign_managed_device_event(
            event,
            authority,
            key,
            arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now()),
        );
        let request = native_phase(|| {
            coland_http::test_fresh_producer_forward_request(
                &ready.context.fixture.state,
                &event,
                &governor_id,
            )
        })
        .await
        .unwrap();
        profiles.push(event.clone());
        assert_ne!(
            request
                .producer_managed_provenance
                .as_ref()
                .unwrap()
                .creation
                .provision
                .event
                .realm_id,
            event.realm_id
        );
        let before = domain(&ready.pool).await;
        let audit_before = private_sources(&ready.pool, realm).await;
        for variant in 0..7 {
            let mut corrupt = request.clone();
            match variant {
                0 => corrupt.producer_managed_provenance = None,
                1 => {
                    let source = corrupt.producer_managed_provenance.as_mut().unwrap();
                    source.creation.provision.event.producer_proof =
                        source.creation.profile.event.producer_proof.clone();
                }
                2 => {
                    corrupt
                        .producer_managed_provenance
                        .as_mut()
                        .unwrap()
                        .current
                        .profile
                        .result
                        .value
                        .actor_kind = arkret_wire::ActorKind::User
                }
                3 => {
                    corrupt
                        .producer_managed_provenance
                        .as_mut()
                        .unwrap()
                        .current
                        .accountability
                        .result
                        .revision
                        .stream_position += 1
                }
                4 => {
                    corrupt
                        .producer_managed_provenance
                        .as_mut()
                        .unwrap()
                        .current
                        .expires_at = arkret_canonical::normalize_timestamp_canonical(
                        chrono::Utc::now() - chrono::Duration::seconds(1),
                    )
                }
                5 => {
                    corrupt
                        .producer_managed_provenance
                        .as_mut()
                        .unwrap()
                        .current
                        .profile
                        .commit
                        .governance_generation = 999
                }
                _ => {
                    corrupt
                        .producer_managed_provenance
                        .as_mut()
                        .unwrap()
                        .current
                        .profile
                        .result
                        .value
                        .profile_fields
                        .insert("budget_probe".into(), json!("x".repeat(1_048_576)));
                }
            }
            rebind_origin(&ready.context.fixture.state, &mut corrupt);
            let result = native_phase(|| {
                coland_http::test_admit_authority_forward(
                    &ready.state,
                    &peer,
                    corrupt,
                    chrono::Utc::now(),
                )
            })
            .await;
            assert!(
                result.is_err(),
                "invalid managed provenance {variant}: {result:?}"
            );
            if variant == 6 {
                assert!(
                    result
                        .unwrap_err()
                        .to_string()
                        .contains("payload_too_large")
                );
            }
            assert_eq!(
                before,
                domain(&ready.pool).await,
                "all domain writes roll back"
            );
            assert_eq!(
                audit_before,
                private_sources(&ready.pool, realm).await,
                "rejected originals are not retained"
            );
        }
        let accepted = native_phase(|| {
            coland_http::test_admit_authority_forward(
                &ready.state,
                &peer,
                request.clone(),
                chrono::Utc::now(),
            )
        })
        .await
        .unwrap();
        assert!(matches!(
            accepted,
            arkret_wire::AuthoritySubmitOutcome::Accepted { .. }
        ));
        let after = domain(&ready.pool).await;
        let after_private = private_sources(&ready.pool, realm).await;
        assert_eq!(before_private["pcr"], after_private["pcr"]);
        assert_eq!(before_private["profiles"], after_private["profiles"]);
        assert_eq!(after_private["audit"].as_array().unwrap().len(), index + 1);
        assert!(
            after_private["audit"]
                .as_array()
                .unwrap()
                .iter()
                .all(|v| v["managed_provenance_json"].is_object())
        );
        let late = request
            .producer_managed_provenance
            .as_ref()
            .unwrap()
            .current
            .expires_at
            + chrono::Duration::seconds(1);
        let replay = native_phase(|| {
            coland_http::test_admit_authority_forward(&ready.state, &peer, request.clone(), late)
        })
        .await
        .unwrap();
        assert!(matches!(
            replay,
            arkret_wire::AuthoritySubmitOutcome::Accepted {
                status: arkret_wire::AuthorityCommitStatus::Duplicate,
                ..
            }
        ));
        assert_eq!(after, domain(&ready.pool).await);
        assert_eq!(after_private, private_sources(&ready.pool, realm).await);
        let wrong_peer = coland_services::authority_commit::AuthenticatedPeerContext {
            source_service_id: governor_id.clone(),
            replay_receipt: None,
        };
        assert!(
            native_phase(|| coland_http::test_admit_authority_forward(
                &ready.state,
                &wrong_peer,
                request.clone(),
                late
            ))
            .await
            .is_err()
        );
    }
    use coland_storage::MlsGroupCurrentStore as _;
    let groups = coland_storage_postgres::PgMlsGroupCurrentStore {
        pool: ready.pool.clone(),
    };
    let scope = ScopeRef::Realm {
        realm_id: ready.context.fixture.realm.clone(),
    };
    let base_current = groups.current(&scope).await.unwrap().unwrap().value;
    let submission = native_phase(|| handoff::commit(&mut ready, creator)).await;
    let original = S::MlsCommit(submission.clone());
    let request = native_phase(|| {
        coland_http::test_fresh_native_forward_request(
            &ready.context.fixture.state,
            &governor_id,
            &original,
        )
    })
    .await
    .unwrap();
    let R::AuthorityForwardMls(full) = &request else {
        panic!("the complete native MLS branch is preserved")
    };
    let bare = S::Event(arkret_wire::EventAdmissionSubmission {
        event: full.mls_submission.commit_event.clone(),
        approval_signatures: None,
    });
    assert!(
        native_phase(|| coland_http::test_fresh_native_forward_request(
            &ready.context.fixture.state,
            &governor_id,
            &bare
        ))
        .await
        .is_err()
    );
    assert_eq!(full.mls_submission, submission);
    let bare_peer =
        arkret_models_collaboration::authority_commit::PeerAuthorityForwardEventRequest {
            branch: full.branch,
            event_submission: arkret_wire::EventAdmissionSubmission::new(
                full.mls_submission.commit_event.clone(),
            ),
            mls_genesis_material: None,
            producer_device_evidence: full.producer_device_evidence.clone(),
            producer_managed_provenance: full.producer_managed_provenance.clone(),
            producer_agent_evidence: None,
        };
    assert!(
        native_phase(|| coland_http::test_admit_authority_forward(
            &ready.state,
            &peer,
            bare_peer,
            chrono::Utc::now()
        ))
        .await
        .is_err()
    );
    let late = full
        .producer_managed_provenance
        .as_ref()
        .unwrap()
        .current
        .expires_at
        + chrono::Duration::seconds(1);
    let before = domain(&ready.pool).await;
    let audit_before = private_sources(&ready.pool, &ready.context.fixture.realm).await;
    let mut tampered = request.clone();
    let R::AuthorityForwardMls(full) = &mut tampered else {
        unreachable!()
    };
    full.mls_submission.idempotency_key = arkret_wire::UuidV7::new(uuid::Uuid::now_v7()).unwrap();
    assert!(
        native_phase(|| coland_http::test_admit_native_forward(
            &ready.state,
            &peer,
            tampered,
            chrono::Utc::now()
        ))
        .await
        .is_err(),
        "the full MLS unit remains in the original Device digest"
    );
    assert_eq!(before, domain(&ready.pool).await);
    assert_eq!(
        audit_before,
        private_sources(&ready.pool, &ready.context.fixture.realm).await
    );
    eprintln!("[managed forward] forwarding complete native MLS through real HTTP");
    native_phase(|| submit_origin_mls(&ready, creator, &submission, &original)).await;
    let accepted = PgAuthorityCommitStore {
        pool: ready.pool.clone(),
    }
    .committed_event(&submission.commit_event.event_id)
    .await
    .unwrap()
    .unwrap();
    ready
        .group
        .install_accepted_commit(
            &arkret_wire::CommittedEventFullView {
                event: accepted.event,
                commit: accepted.commit,
            },
            &base_current,
        )
        .unwrap();
    let after = domain(&ready.pool).await;
    let after_private = private_sources(&ready.pool, &ready.context.fixture.realm).await;
    let wrong_peer = coland_services::authority_commit::AuthenticatedPeerContext {
        source_service_id: governor_id,
        replay_receipt: None,
    };
    assert!(
        native_phase(|| coland_http::test_admit_native_forward(
            &ready.state,
            &wrong_peer,
            request.clone(),
            late
        ))
        .await
        .is_err()
    );
    assert!(matches!(
        native_phase(|| coland_http::test_admit_native_forward(
            &ready.state,
            &peer,
            request.clone(),
            late
        ))
        .await
        .unwrap(),
        arkret_wire::AuthoritySubmitOutcome::Accepted { .. }
    ));
    let mut different = request;
    let R::AuthorityForwardMls(full) = &mut different else {
        unreachable!()
    };
    full.mls_submission.idempotency_key = arkret_wire::UuidV7::new(uuid::Uuid::now_v7()).unwrap();
    assert!(
        native_phase(|| coland_http::test_admit_native_forward(
            &ready.state,
            &peer,
            different,
            late
        ))
        .await
        .is_err(),
        "an accepted Event does not authorize a different complete MLS unit"
    );
    assert_eq!(after, domain(&ready.pool).await);
    assert_eq!(
        after_private,
        private_sources(&ready.pool, &ready.context.fixture.realm).await
    );
    native_phase(|| rejected_complete_mls_retry(&mut ready, creator)).await;
    native_phase(|| lost_response_cold_retry(&mut ready, creator, &profiles[creator])).await;
    for archive_writer in [false, true] {
        native_phase(|| {
            expiry_during_governor_writer_wait(&ready, creator, &profiles[creator], archive_writer)
        })
        .await;
    }
}

async fn rejected_complete_mls_retry(ready: &mut handoff::Ready, creator: usize) {
    use coland_storage::MlsGroupCurrentStore as _;
    let submission = native_phase(|| handoff::commit_with_revision_offset(ready, creator, 1)).await;
    let original =
        arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequest::MlsCommit(
            submission,
        );
    let governor = ready.state.service_core_id();
    let request = native_phase(|| {
        coland_http::test_fresh_native_forward_request(
            &ready.context.fixture.state,
            &governor,
            &original,
        )
    })
    .await
    .unwrap();
    let arkret_models_collaboration::authority_commit::PeerAuthoritySubmitRequest::AuthorityForwardMls(full) = &request else { unreachable!() };
    let late = full
        .producer_managed_provenance
        .as_ref()
        .unwrap()
        .current
        .expires_at
        + chrono::Duration::seconds(1);
    let peer = coland_services::authority_commit::AuthenticatedPeerContext {
        source_service_id: ready.context.fixture.state.service_core_id(),
        replay_receipt: None,
    };
    let groups = coland_storage_postgres::PgMlsGroupCurrentStore {
        pool: ready.pool.clone(),
    };
    let scope = ScopeRef::Realm {
        realm_id: ready.context.fixture.realm.clone(),
    };
    let before = groups.current(&scope).await.unwrap();
    let private = private_sources(&ready.pool, &ready.context.fixture.realm).await;
    let outcome = native_phase(|| {
        coland_http::test_admit_native_forward(
            &ready.state,
            &peer,
            request.clone(),
            chrono::Utc::now(),
        )
    })
    .await
    .unwrap();
    assert!(
        matches!(&outcome, arkret_wire::AuthoritySubmitOutcome::Rejected {reason_code,..} if reason_code == "governance_binding_mismatch"),
        "real public transition with a stale governance coordinate: {outcome:?}"
    );
    assert_eq!(before, groups.current(&scope).await.unwrap());
    assert_eq!(
        private,
        private_sources(&ready.pool, &ready.context.fixture.realm).await
    );
    let after = domain(&ready.pool).await;
    assert_eq!(
        outcome,
        native_phase(|| coland_http::test_admit_native_forward(&ready.state, &peer, request, late))
            .await
            .unwrap()
    );
    assert_eq!(after, domain(&ready.pool).await);
}

async fn lost_response_cold_retry(ready: &mut handoff::Ready, index: usize, original: &Event) {
    let (prior, key, _) = ready.context.actors[index].clone();
    let bundle = if index == 0 {
        ready.context.ghost_bundle.clone()
    } else {
        ready.context.install.bot_body["managed_actor_bundle"].clone()
    };
    let expiry = arkret_canonical::normalize_timestamp_canonical(
        chrono::Utc::now() + chrono::Duration::seconds(6),
    );
    let authority = native_phase(|| authorize_scopes_until(&ready.context.fixture, &ready.context.install, &bundle, &ready.context.namespace, &key, prior.device_id.clone(), json!([{"effective_scope":{"kind":"realm","realm_id":ready.context.fixture.realm},"actions":["ak.applet.join","ak.applet.publish","ak.event.read"]}]), Some(expiry))).await;
    let event = profile_update(
        original,
        &authority,
        &key,
        json!({"display_name":"accepted before the response was lost"}),
    );
    ready
        ._governor
        .drop_peer_responses
        .store(true, std::sync::atomic::Ordering::Relaxed);
    let (status, problem) =
        native_phase(|| post(&ready.context.fixture, &authority, &key, &event, vec![])).await;
    ready
        ._governor
        .drop_peer_responses
        .store(false, std::sync::atomic::Ordering::Relaxed);
    assert!(
        !status.is_success(),
        "a lost response must not manufacture acknowledgement: {problem}"
    );
    let store = PgAuthorityCommitStore {
        pool: ready.context.fixture.pool.clone(),
    };
    let queued = store
        .queued_event(&event.event_id)
        .await
        .unwrap()
        .unwrap()
        .forward_attempt
        .unwrap();
    assert!(queued.accepted_commit.is_none());
    let frozen = queued
        .peer_request
        .expect("complete peer body is durable before transport");
    let sent = arkret_canonical::canonical_json_bytes(frozen.as_ref()).unwrap();
    assert_eq!(
        ready._governor.peer_bodies.lock().unwrap().last(),
        Some(&sent)
    );
    let accepted = domain(&ready.pool).await;
    let audit = private_sources(&ready.pool, &ready.context.fixture.realm).await;
    tokio::time::sleep(
        (expiry - chrono::Utc::now()).to_std().unwrap_or_default()
            + std::time::Duration::from_millis(80),
    )
    .await;
    // Current transport remains authenticated, while publication and the old authorization have
    // ended.
    let replacement = native_phase(|| authorize_scopes(&ready.context.fixture, &ready.context.install, &bundle, &ready.context.namespace, &key, prior.device_id, json!([{"effective_scope":{"kind":"realm","realm_id":ready.context.fixture.realm},"actions":["ak.event.read"]}]))).await;
    let reopened = native_phase(|| {
        coland_test_support::app_state_with_persistence(
            ready.context.fixture.state.config().clone(),
            ready.context.fixture.state.test_persistence(),
        )
    })
    .await;
    native_phase(|| reopened.hydrate()).await.unwrap();
    ready.context.fixture.state = reopened.clone();
    *ready._origin.state.lock().unwrap() = Some(reopened);
    let (status, outcome) =
        native_phase(|| post(&ready.context.fixture, &replacement, &key, &event, vec![])).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "cold exact retry restores the original acceptance: {outcome}"
    );
    assert_eq!(
        ready._governor.peer_bodies.lock().unwrap().last(),
        Some(&sent)
    );
    assert_eq!(accepted, domain(&ready.pool).await);
    assert_eq!(
        audit,
        private_sources(&ready.pool, &ready.context.fixture.realm).await
    );
    assert!(
        store
            .queued_event(&event.event_id)
            .await
            .unwrap()
            .unwrap()
            .forward_attempt
            .unwrap()
            .accepted_commit
            .is_some()
    );
}

async fn expiry_during_governor_writer_wait(
    ready: &handoff::Ready,
    index: usize,
    original: &Event,
    archive_writer: bool,
) {
    use diesel_async::SimpleAsyncConnection as _;
    let context = &ready.context;
    let fixture = &context.fixture;
    let (prior, key, _) = &context.actors[index];
    let bundle = if index == 0 {
        &context.ghost_bundle
    } else {
        &context.install.bot_body["managed_actor_bundle"]
    };
    let expiry = arkret_canonical::normalize_timestamp_canonical(
        chrono::Utc::now() + chrono::Duration::seconds(6),
    );
    let authority = native_phase(|| authorize_scopes_until(fixture, &context.install, bundle, &context.namespace, key, prior.device_id.clone(), json!([{"effective_scope":{"kind":"realm","realm_id":fixture.realm},"actions":["ak.applet.join","ak.applet.publish","ak.event.read","ak.mls.commit","ak.mls.genesis"]}]), Some(expiry))).await;
    let event = profile_update(
        original,
        &authority,
        key,
        json!({"display_name":"must roll back after physical expiry"}),
    );
    let governor_id = ready.state.service_core_id();
    let request = native_phase(|| {
        coland_http::test_fresh_producer_forward_request(&fixture.state, &event, &governor_id)
    })
    .await
    .unwrap();
    let before = domain(&ready.pool).await;
    let audit_before = private_sources(&ready.pool, &fixture.realm).await;
    let mut blocker = ready.pool.get().await.unwrap();
    blocker.batch_execute("BEGIN").await.unwrap();
    if archive_writer {
        blocker
            .batch_execute("LOCK TABLE forwarded_producer_device_evidence IN SHARE MODE")
            .await
            .unwrap();
    } else {
        diesel::sql_query("SELECT realm_id FROM realm_authorities WHERE realm_id=$1 FOR UPDATE")
            .bind::<diesel::sql_types::Text, _>(fixture.realm.as_str())
            .execute(&mut blocker)
            .await
            .unwrap();
    }
    let state = ready.state.clone();
    let peer = coland_services::authority_commit::AuthenticatedPeerContext {
        source_service_id: fixture.state.service_core_id(),
        replay_receipt: None,
    };
    let waiting = tokio::spawn(native_phase(move || async move {
        coland_http::test_admit_authority_forward(&state, &peer, request, chrono::Utc::now()).await
    }));
    let observed = tokio::time::timeout(std::time::Duration::from_secs(3), async {
        #[derive(diesel::QueryableByName)]
        struct Row { #[diesel(sql_type=diesel::sql_types::Bool)] waiting: bool }
        loop {
            let mut observer = ready.pool.get().await.unwrap();
            let query = if archive_writer { "%INSERT INTO forwarded_producer_device_evidence%" } else { "%realm_authorities%" };
            let row = diesel::sql_query("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND pid<>pg_backend_pid() AND wait_event_type='Lock' AND query ILIKE $1) AS waiting").bind::<diesel::sql_types::Text,_>(query).get_result::<Row>(&mut observer).await.unwrap();
            if row.waiting { break; }
            drop(observer);
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }).await;
    let still_live = chrono::Utc::now() < expiry;
    if observed.is_ok() && still_live {
        tokio::time::sleep(
            (expiry - chrono::Utc::now()).to_std().unwrap_or_default()
                + std::time::Duration::from_millis(80),
        )
        .await;
    }
    blocker.batch_execute("ROLLBACK").await.unwrap();
    let result = waiting.await.unwrap();
    assert!(
        observed.is_ok() && still_live,
        "governor must reach the real writer while its source is live: {result:?}"
    );
    assert!(
        result.is_err(),
        "expired managed source must roll back every effect"
    );
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("device_unauthorized")
    );
    assert_eq!(before, domain(&ready.pool).await);
    assert_eq!(
        audit_before,
        private_sources(&ready.pool, &fixture.realm).await
    );
}

async fn submit_origin_mls(
    ready: &handoff::Ready,
    creator: usize,
    submission: &arkret_wire::MlsCommitSubmission,
    original: &arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequest,
) {
    let (authority, key, _) = &ready.context.actors[creator];
    let mut metadata = managed_device_metadata(authority);
    metadata.effective_scope = submission.commit_event.scope_ref.clone();
    let token = submission.idempotency_key.as_uuid().to_string();
    let mut response = managed_device_http_request_with_idempotency_at(
        &ready.context.fixture.state,
        authority,
        &metadata,
        ServiceOperationId::SelfEventsCommandSubmitV1,
        key,
        Some(arkret_canonical::canonical_json_bytes(original).unwrap()),
        None,
        &token,
    )
    .send(&service(ready.context.fixture.state.clone()))
    .await;
    let status = response.status_code.unwrap();
    let outcome: Value = response.take_json().await.unwrap();
    assert_eq!(
        status,
        StatusCode::OK,
        "complete native origin/peer/governor MLS: {outcome}"
    );
    let outcome: arkret_models_collaboration::authority_commit::SelfAuthoritySubmitOutcome =
        serde_json::from_value(outcome).unwrap();
    assert!(matches!(
        outcome,
        arkret_models_collaboration::authority_commit::SelfAuthoritySubmitOutcome::Ordinary(
            arkret_wire::AuthoritySubmitOutcome::Accepted { .. }
        )
    ));
}
