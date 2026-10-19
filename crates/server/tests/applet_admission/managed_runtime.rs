//! Actual host custody, Station admission, and cold recovery over production HTTP.
use arkret_bridge_runtime::managed_actor_authoring::ManagedActorAuthoringService;
use arkret_bridge_runtime::managed_device::{InitialManagedDevicePlan, ManagedDeviceRuntime};
use arkret_bridge_runtime::{
    ArkretEdge, AuthoringJournal, AuthoringStore, BridgeError, Config, FileAuthoringStore,
};
use arkret_models_collaboration::authority_commit::{
    SelfAuthoritySubmitOutcome, SelfAuthoritySubmitRequest,
};
use arkret_signatures::{EventSigner as _, PublicKeyMaterial, SignEventOptions};
use arkret_wire::{AuthoritySubmitOutcome, ServiceOperationId};

use super::*;

#[path = "managed_runtime_mls.rs"]
mod mls;

#[derive(Default)]
pub(crate) struct LostNativeReply {
    pub(crate) armed: std::sync::atomic::AtomicBool,
    pub(crate) cursor_error_once: Mutex<Option<arkret_wire::ErrorCode>>,
    pub(crate) queue_reads: Mutex<Vec<(arkret::AppletManagedDeviceMetadata, Option<String>)>>,
    pub(crate) attempts: Mutex<Vec<(arkret::AppletManagedDeviceMetadata, Vec<u8>, String)>>,
    pub(crate) responses: Mutex<
        Vec<(
            arkret::AppletManagedDeviceMetadata,
            String,
            Option<StatusCode>,
        )>,
    >,
}
#[salvo::handler]
async fn lose_native_reply(
    req: &mut salvo::Request,
    depot: &mut salvo::Depot,
    res: &mut salvo::Response,
    ctrl: &mut salvo::FlowCtrl,
) {
    let state = depot.get_typed::<Arc<LostNativeReply>>().unwrap().clone();
    let native = req
        .headers()
        .get(arkret::AppletManagedDeviceMetadata::HEADER)
        .and_then(|v| v.to_str().ok())
        .map(|v| arkret::AppletManagedDeviceMetadata::from_header_value(v).unwrap());
    if let Some(metadata) = native {
        let response_identity = metadata.clone();
        let response_path = req.uri().path().to_owned();
        let idempotency = req
            .headers()
            .get("Idempotency-Key")
            .map(|value| value.to_str().unwrap().to_owned())
            .unwrap_or_default();
        let body = req.payload().await.unwrap().to_vec();
        state
            .attempts
            .lock()
            .unwrap()
            .push((metadata, body, idempotency));
        if response_path == "/_arkret/self/device_messages"
            && req.method() == salvo::http::Method::GET
        {
            let after = req.query::<String>("after");
            state
                .queue_reads
                .lock()
                .unwrap()
                .push((response_identity.clone(), after.clone()));
            let refusal = if after.is_some() {
                state.cursor_error_once.lock().unwrap().take()
            } else {
                None
            };
            if let Some(code) = refusal {
                let problem = arkret_wire::Problem::from_code(
                    code.as_str(),
                    "injected recipient cursor refusal",
                );
                res.status_code(StatusCode::from_u16(problem.status).unwrap());
                res.render(salvo::prelude::Json(problem));
                res.headers_mut().insert(
                    "content-type",
                    salvo::http::HeaderValue::from_static("application/problem+json"),
                );
                res.headers_mut().insert(
                    "arkret-operation",
                    salvo::http::HeaderValue::from_static(
                        ServiceOperationId::SELF_DEVICE_MESSAGES_READ_LIST_V1,
                    ),
                );
                ctrl.skip_rest();
                state.responses.lock().unwrap().push((
                    response_identity,
                    response_path,
                    res.status_code,
                ));
                return;
            }
        }
        ctrl.call_next(req, depot, res).await;
        if res.status_code == Some(StatusCode::OK)
            && state.armed.swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            res.status_code(StatusCode::SERVICE_UNAVAILABLE);
            res.body("accepted response lost by the test transport");
        }
        state
            .responses
            .lock()
            .unwrap()
            .push((response_identity, response_path, res.status_code));
    } else {
        ctrl.call_next(req, depot, res).await;
    }
}

pub(crate) struct FailOutcomeStore {
    pub(crate) inner: Arc<dyn AuthoringStore>,
    pub(crate) armed: std::sync::atomic::AtomicBool,
}
impl AuthoringStore for FailOutcomeStore {
    fn load(&self, key: &str) -> arkret_bridge_runtime::Result<Option<String>> {
        AuthoringStore::load(self.inner.as_ref(), key)
    }
    fn entries_with_prefix(
        &self,
        prefix: &str,
    ) -> arkret_bridge_runtime::Result<Vec<(String, String)>> {
        self.inner.entries_with_prefix(prefix)
    }
    fn compare_exchange_batch(
        &self,
        expected: &[(String, Option<String>)],
        writes: &[(String, Option<String>)],
    ) -> arkret_bridge_runtime::Result<bool> {
        if expected
            .iter()
            .any(|(key, value)| key.starts_with("managed-device/v1/") && value.is_some())
            && self.armed.swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            return Err(BridgeError::Database(
                "injected post-acceptance persistence failure".into(),
            ));
        }
        self.inner.compare_exchange_batch(expected, writes)
    }
}

pub(crate) fn host(config: Config, store: Arc<dyn AuthoringStore>) -> Arc<ArkretEdge> {
    host_with_retry(config, store, arkret_http_client::RetryConfig::standard(1))
}

pub(crate) fn host_with_retry(
    config: Config,
    store: Arc<dyn AuthoringStore>,
    retry: arkret_http_client::RetryConfig,
) -> Arc<ArkretEdge> {
    let http = reqwest::Client::builder()
        .tls_backend_rustls()
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .tls_certs_only([reqwest::Certificate::from_pem(include_bytes!(
            "../fixtures/outbox-test-ca.pem"
        ))
        .unwrap()])
        .build()
        .unwrap();
    let client = arkret_http_client::Client::builder(config.arkret.server_url.parse().unwrap())
        .http_client(http)
        .retry(retry)
        .build()
        .unwrap();
    let signer = Ed25519PayloadSigner::from_did_key_seed(
        config.signing_seed().unwrap(),
        config.arkret.service_did.clone(),
        config
            .arkret
            .verification_method_for(&config.arkret.service_did)
            .unwrap(),
    );
    Arc::new(
        ArkretEdge::new_outbound(
            Arc::new(config),
            client,
            signer,
            AuthoringJournal::new(store),
        )
        .unwrap(),
    )
}

pub(crate) struct RuntimeContext {
    pub(crate) fixture: Box<Fixture>,
    pub(crate) native: NativeAppletService,
    pub(crate) config: Config,
    pub(crate) store_path: std::path::PathBuf,
    pub(crate) server: tokio::task::JoinHandle<()>,
    pub(crate) server_handle: salvo::server::ServerHandle,
    pub(crate) lost: Arc<LostNativeReply>,
    pub(crate) accepted: Vec<(
        arkret::AccountId,
        AppletAuthoringTransactionRequestBody,
        arkret::GrantId,
    )>,
}

// Separate construction avoids placing the creation and recovery phase frames
// in the same default-stack test driver.
fn setup() -> std::pin::Pin<Box<dyn std::future::Future<Output = RuntimeContext> + Send>> {
    setup_with_mls(false)
}

pub(crate) fn setup_with_mls(
    mls: bool,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = RuntimeContext> + Send>> {
    Box::pin(async move {
        use salvo::Listener as _;
        arkret_bridge_runtime::install_default_crypto_provider();
        let pem = |label: &str, bytes: &[u8]| {
            let encoded = base64::engine::general_purpose::STANDARD.encode(bytes);
            let lines = encoded
                .as_bytes()
                .chunks(64)
                .map(|line| std::str::from_utf8(line).unwrap().to_owned() + "\n")
                .collect::<String>();
            format!("-----BEGIN {label}-----\n{lines}-----END {label}-----\n")
        };
        let keycert = salvo::conn::rustls::Keycert::new()
            .cert(pem(
                "CERTIFICATE",
                include_bytes!("../fixtures/outbox-test-cert.der"),
            ))
            .key(pem(
                "PRIVATE KEY",
                include_bytes!("../fixtures/outbox-test-key.der"),
            ));
        let acceptor = salvo::conn::TcpListener::new("127.0.0.1:0".to_owned())
            .rustls(salvo::conn::rustls::RustlsConfig::new(keycert))
            .try_bind()
            .await
            .unwrap();
        let address = acceptor.inner().local_addr().unwrap();
        let fixture = Box::new(
            Box::pin(Fixture::new_inner_with_public_base_url(
                false,
                Some(format!("https://{address}")),
            ))
            .await,
        );
        let namespace = format!("bridge.{}", uuid::Uuid::now_v7().simple());
        let mut native = NativeAppletService::new(
            &format!("ak:applet:{}", uuid::Uuid::now_v7()),
            &namespace,
            &fixture.state.service_core_id(),
        );
        if mls {
            native.package.e2ee_policy.enabled = true;
            native.package.e2ee_policy.mls_join_requested = Some(true);
            native
                .package
                .claimed_profiles
                .push(arkret_wire::ProfileId::APPLET_E2EE_JOIN_V1.to_owned());
        }
        let endpoint = native.package.base_url.clone();
        let authority = Url::parse(&endpoint)
            .unwrap()
            .authority()
            .replace(':', "%3A");
        native.package.namespaces.actors = vec![AppletNamespaceEntry::exclusive(format!(
            "did:webvh:*:{authority}:webvh:*"
        ))];
        resign_native_applet_package(&mut native.package);
        let server = salvo::Server::new(acceptor);
        let server_handle = server.handle();
        let state = fixture.state.clone();
        let lost = Arc::new(LostNativeReply::default());
        let injected = lost.clone();
        let server = tokio::spawn(async move {
            server
                .serve(
                    coland_http::service(state)
                        .hoop(salvo::affix_state::inject(injected))
                        .hoop(lose_native_reply),
                )
                .await;
        });
        let wrong_host = reqwest::Client::builder()
            .tls_backend_rustls()
            .no_proxy()
            .tls_certs_only([reqwest::Certificate::from_pem(include_bytes!(
                "../fixtures/outbox-test-ca.pem"
            ))
            .unwrap()])
            .resolve("invalid-runtime-host.example", address)
            .build()
            .unwrap();
        let error = wrong_host
            .get(format!(
                "https://invalid-runtime-host.example:{}/_arkret/health",
                address.port()
            ))
            .send()
            .await
            .unwrap_err();
        let detail = format!("{error:?}").to_ascii_lowercase();
        assert!(
            detail.contains("notvalidforname")
                || detail.contains("not valid for")
                || detail.contains("hostname"),
            "TLS must still verify the actual hostname: {detail}"
        );
        let station_method = fixture
            .state
            .service_verification_method("notary-key")
            .unwrap();
        let commit_method = arkret_wire::DidUrl::new(
            coland_http::routing::federation::federation_service_signature_key_id(
                fixture.state.service_did().as_str(),
            ),
        )
        .unwrap();
        let station_document: arkret_identity::DidDocument = serde_json::from_value(
            serde_json::to_value(
                fixture
                    .state
                    .test_persistence()
                    .service_identity()
                    .get()
                    .await
                    .unwrap()
                    .unwrap()
                    .did_document,
            )
            .unwrap(),
        )
        .unwrap();
        let commit_key = arkret_identity::jws::resolve_ed25519_pubkey_from_document(
            &station_document,
            commit_method.as_str(),
        )
        .unwrap();
        assert_eq!(
            commit_key.to_bytes(),
            fixture
                .state
                .notary_signing_key()
                .verifying_key()
                .to_bytes()
        );
        let config:Config=serde_json::from_value(json!({"bridge":{"bridge_id":"actual-managed-runtime"},"arkret":{
        "server_url":format!("https://{address}"),"applet_base_url":endpoint,"service_did":applet_service_did(&native.package),
        "trust_domain":fixture.state.config().trust_domain,"applet_id":native.package.applet_id,"signing_key_seed_hex":"2a".repeat(32),
        "verification_method_fragment":"#applet-native-key","trusted_server_did":fixture.state.service_did(),
        "trusted_verification_methods":[{"verification_method":station_method,"public_key":PublicKeyMaterial::Ed25519Raw{bytes:fixture.state.notary_signing_key().verifying_key().to_bytes().to_vec()}},{"verification_method":commit_method,"public_key":PublicKeyMaterial::Ed25519Raw{bytes:commit_key.to_bytes().to_vec()}}],
        "applet_namespaces":native.package.namespaces,"managed_actor_authoring":{"principal_endpoint":endpoint,"key_encryption_key_hex":"67".repeat(32)}
    }})).unwrap();
        let store_path = std::env::temp_dir().join(format!(
            "arkret-managed-device-{}.redb",
            uuid::Uuid::now_v7()
        ));
        let store = FileAuthoringStore::shared(store_path.clone()).unwrap();
        let edge = host(config.clone(), store);
        let author = Arc::new(ManagedActorAuthoringService::new(edge.clone()).unwrap());
        *native.managed_author.lock().unwrap() = Some(author.clone());
        let (package, ..) = Box::pin(fixture.install_service_with_constraints(
            true,
            native.package.clone(),
            ScopeRef::Realm {
                realm_id: fixture.realm.clone(),
            },
            BTreeMap::new(),
        ))
        .await;
        let mut accepted = Vec::new();
        for ghost in [false, true] {
            let (preview_path, preview_operation, path, operation, preview_body) = if ghost {
                (
                    format!(
                        "/_arkret/self/applets/{}/ghosts/provision/preview",
                        package.applet_id
                    ),
                    ServiceOperationId::SELF_APPLET_GHOST_COMMAND_PREVIEW_V1,
                    format!(
                        "/_arkret/self/applets/{}/ghosts/provision",
                        package.applet_id
                    ),
                    ServiceOperationId::SELF_APPLET_GHOST_COMMAND_PROVISION_V1,
                    serde_json::to_value(GhostPreviewRequestBody {
                        effective_scope: ScopeRef::Realm {
                            realm_id: fixture.realm.clone(),
                        },
                        external_ref: GhostExternalTuple {
                            protocol: "slack".into(),
                            instance_id: "actual-runtime".into(),
                            external_id: "remote".into(),
                        },
                        display_name: Some("Independent Ghost".into()),
                    })
                    .unwrap(),
                )
            } else {
                (
                    format!(
                        "/_arkret/self/applets/{}/bots/provision/preview",
                        package.applet_id
                    ),
                    ServiceOperationId::SELF_APPLET_BOT_COMMAND_PREVIEW_V1,
                    format!("/_arkret/self/applets/{}/bots/provision", package.applet_id),
                    ServiceOperationId::SELF_APPLET_BOT_COMMAND_PROVISION_V1,
                    serde_json::to_value(AppletBotPreviewRequestBody {
                        effective_scope: ScopeRef::Realm {
                            realm_id: fixture.realm.clone(),
                        },
                        request_id: "independent-bot".into(),
                        display_name: Some("Independent Bot".into()),
                    })
                    .unwrap(),
                )
            };
            let (status, preview) = fixture
                .service_post(
                    &package,
                    &preview_path,
                    preview_operation,
                    &preview_body,
                    &format!("runtime-preview-{ghost}"),
                )
                .await;
            assert_eq!(status, StatusCode::OK, "{preview}");
            let request: AppletManagedActorAuthoringRequest =
                serde_json::from_value(preview["authoring_request"].clone()).unwrap();
            let bundle = Box::pin(author.author(&request)).await.unwrap();
            let body = if ghost {
                serde_json::to_value(GhostActorProvisionRequestBody {
                    authoring_request: request,
                    managed_actor_bundle: Some(bundle),
                    existing_managed_actor: None,
                    approval_signatures: vec![],
                })
                .unwrap()
            } else {
                serde_json::to_value(AppletBotProvisionRequestBody {
                    authoring_request: request,
                    managed_actor_bundle: bundle,
                    approval_signatures: vec![],
                })
                .unwrap()
            };
            if !ghost {
                let did = body["managed_actor_bundle"]["managed_actor_provision_event"]["payload"]
                    ["initial_resolution"]["did"]
                    .as_str()
                    .unwrap();
                assert!(
                    fixture
                        .state
                        .test_persistence()
                        .webvh()
                        .get_document(did)
                        .await
                        .unwrap()
                        .is_none()
                );
                assert!(
                    fixture
                        .state
                        .test_persistence()
                        .webvh()
                        .list_log_events(did)
                        .await
                        .unwrap()
                        .is_empty()
                );
                let before = authority_snapshot(&fixture.pool).await;
                let function = format!(
                    "runtime_ingestion_failure_{}",
                    uuid::Uuid::now_v7().simple()
                );
                let trigger = format!("{function}_trigger");
                let mut connection = fixture.pool.get().await.unwrap();
                diesel::sql_query(format!("CREATE FUNCTION {function}() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.id=TG_ARGV[0] THEN RAISE EXCEPTION 'injected native ingestion failure'; END IF; RETURN NEW; END $$"))
                    .execute(&mut *connection).await.unwrap();
                diesel::sql_query(format!("CREATE TRIGGER {trigger} BEFORE INSERT OR UPDATE ON webvh_documents FOR EACH ROW EXECUTE FUNCTION {function}('{did}')"))
                    .execute(&mut *connection).await.unwrap();
                drop(connection);
                let (failed, error) = fixture
                    .service_post(
                        &package,
                        &path,
                        operation,
                        &body,
                        "runtime-create-native-ingestion-failure",
                    )
                    .await;
                // Remove fault DDL before assertions because database slots are reused.
                let mut connection = fixture.pool.get().await.unwrap();
                diesel::sql_query(format!("DROP TRIGGER {trigger} ON webvh_documents"))
                    .execute(&mut *connection)
                    .await
                    .unwrap();
                diesel::sql_query(format!("DROP FUNCTION {function}()"))
                    .execute(&mut *connection)
                    .await
                    .unwrap();
                drop(connection);
                assert_eq!(failed, StatusCode::INTERNAL_SERVER_ERROR, "{error}");
                assert!(
                    fixture
                        .state
                        .test_persistence()
                        .webvh()
                        .get_document(did)
                        .await
                        .unwrap()
                        .is_none()
                );
                assert!(
                    fixture
                        .state
                        .test_persistence()
                        .webvh()
                        .list_log_events(did)
                        .await
                        .unwrap()
                        .is_empty(),
                    "failed document persistence must roll back the complete native log"
                );
                assert_eq!(before, authority_snapshot(&fixture.pool).await);
            }
            let (status, outcome) = fixture
                .service_post(
                    &package,
                    &path,
                    operation,
                    &body,
                    &format!("runtime-create-{ghost}"),
                )
                .await;
            assert_eq!(status, StatusCode::CREATED, "{outcome}");
            let did=body["managed_actor_bundle"]["managed_actor_provision_event"]["payload"]["initial_resolution"]["did"].as_str().unwrap();
            let stored = fixture
                .state
                .test_persistence()
                .webvh()
                .get_document(did)
                .await
                .unwrap()
                .unwrap();
            let original = (
                stored.did_document.clone(),
                stored.key_log_head.clone(),
                stored.seq,
                stored.fetched_at,
                stored.expires_at,
                stored.method_evidence.clone(),
            );
            assert_eq!(
                fixture
                    .state
                    .test_persistence()
                    .webvh()
                    .ingest_verified_history(None, stored)
                    .await
                    .unwrap(),
                coland_storage::WebvhLogCommitOutcome::Conflict,
                "stale expected head must not overwrite accepted native ingestion"
            );
            let after = fixture
                .state
                .test_persistence()
                .webvh()
                .get_document(did)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(
                original,
                (
                    after.did_document,
                    after.key_log_head,
                    after.seq,
                    after.fetched_at,
                    after.expires_at,
                    after.method_evidence
                )
            );
            let pending = fixture
                .state
                .test_persistence()
                .applets()
                .pending_authoring_completions(16)
                .await
                .unwrap();
            let completion = pending
                .iter()
                .find(|c| serde_json::to_value(&c.context.committed_request).unwrap() == body)
                .expect("real committed original completion");
            let original = AppletAuthoringTransactionRequestBody {
                applet_id: completion.applet_id.clone(),
                source_id: completion.source_id.clone(),
                authoring_context: completion.context.clone(),
            };
            edge.install_managed_authoring_completion(
                &original,
                &station_method,
                &PublicKeyMaterial::Ed25519Raw {
                    bytes: fixture
                        .state
                        .notary_signing_key()
                        .verifying_key()
                        .to_bytes()
                        .to_vec(),
                },
            )
            .unwrap();
            let actor: ActorId = serde_json::from_value(
                outcome[if ghost {
                    "ghost_actor_id"
                } else {
                    "bot_actor_id"
                }]
                .clone(),
            )
            .unwrap();
            let grant: arkret::GrantId =
                serde_json::from_value(outcome["authorization_ref"].clone()).unwrap();
            accepted.push((actor.as_account_id().unwrap().clone(), original, grant));
        }
        *native.managed_author.lock().unwrap() = None;
        drop(author);
        drop(edge);
        RuntimeContext {
            fixture,
            native,
            config,
            store_path,
            server,
            server_handle,
            lost,
            accepted,
        }
    })
}

pub(crate) fn recover(
    context: Box<RuntimeContext>,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Box<RuntimeContext>> + Send>> {
    Box::pin(async move {
        use coland_storage::DeviceRevocationStore as _;
        let scope = ScopeRef::Realm {
            realm_id: context.fixture.realm.clone(),
        };
        for (account, original, grant) in &context.accepted {
            let inner = FileAuthoringStore::shared(context.store_path.clone()).unwrap();
            let store = Arc::new(FailOutcomeStore {
                inner,
                armed: std::sync::atomic::AtomicBool::new(true),
            });
            let edge = host(context.config.clone(), store.clone());
            let author = Arc::new(ManagedActorAuthoringService::new(edge.clone()).unwrap());
            *context.native.managed_author.lock().unwrap() = Some(author.clone());
            let runtime = ManagedDeviceRuntime::new(edge.clone()).unwrap();
            let now = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
            let operation = format!(
                "initial-device/{}",
                original
                    .authoring_context
                    .principal_control_commit
                    .event_ref
            );
            let plan = InitialManagedDevicePlan {
                operation_id: operation.clone(),
                account_id: account.clone(),
                scopes: serde_json::from_value(
                    json!([{"effective_scope":scope,"actions":["ak.applet.join","ak.event.read"]}]),
                )
                .unwrap(),
                not_before: now - chrono::Duration::seconds(1),
                expires_at: now + chrono::Duration::hours(1),
            };
            let error = match runtime.authorize_initial_device(plan.clone(), &scope).await {
                Ok(_) => panic!("injected persistence failure must not return a ready Device"),
                Err(e) => e,
            };
            assert!(
                error.to_string().contains("injected post-acceptance"),
                "{error}"
            );
            let before = authority_snapshot(&context.fixture.pool).await;
            let pending = store.entries_with_prefix("managed-device/v1/").unwrap();
            assert!(!pending.is_empty());
            assert!(
                pending
                    .iter()
                    .all(|(_, v)| v.starts_with("v1.") && !v.contains("device_seed"))
            );
            *context.native.managed_author.lock().unwrap() = None;
            drop(runtime);
            drop(author);
            drop(edge);
            drop(store);
            let store = FileAuthoringStore::shared(context.store_path.clone()).unwrap();
            let mut wrong = context.config.clone();
            wrong.arkret.managed_actor_authoring.key_encryption_key_hex = "68".repeat(32);
            assert!(
                ManagedDeviceRuntime::new(host(wrong, store.clone()))
                    .unwrap()
                    .recover_initial_device(account, &operation, &scope)
                    .await
                    .is_err()
            );
            assert_eq!(before, authority_snapshot(&context.fixture.pool).await);
            let edge = host(context.config.clone(), store.clone());
            let author = Arc::new(ManagedActorAuthoringService::new(edge.clone()).unwrap());
            *context.native.managed_author.lock().unwrap() = Some(author.clone());
            let runtime = ManagedDeviceRuntime::new(edge.clone()).unwrap();
            let device = runtime
                .recover_initial_device(account, &operation, &scope)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(
                before,
                authority_snapshot(&context.fixture.pool).await,
                "exact recovery must add no second authorization or Commit"
            );
            let authority = coland_storage_postgres::PgDeviceRevocationStore {
                pool: context.fixture.pool.clone(),
            }
            .applet_managed_device_authority(account, &device.device_id, chrono::Utc::now())
            .await
            .unwrap()
            .unwrap();
            assert_eq!(
                authority.selector.authorization_ref.event_id,
                device.authorization_event_id
            );
            assert_eq!(
                authority.public_key,
                device.signer().verifying_key().to_bytes()
            );
            assert_ne!(
                authority.public_key,
                edge.signer().verifying_key().to_bytes()
            );
            let mut different = plan.clone();
            different.expires_at += chrono::Duration::seconds(1);
            assert!(
                runtime
                    .authorize_initial_device(different, &scope)
                    .await
                    .is_err()
            );
            let roots = store
                .entries_with_prefix("managed-authoring/original-roots/")
                .unwrap();
            let target = roots
                .iter()
                .find(|(key, _)| {
                    key.ends_with(
                        &serde_json::to_string(&ActorId::account(account.clone())).unwrap(),
                    )
                })
                .unwrap()
                .clone();
            assert!(
                store
                    .compare_exchange_batch(
                        &[(target.0.clone(), Some(target.1.clone()))],
                        &[(target.0.clone(), None)]
                    )
                    .unwrap()
            );
            assert!(
                runtime
                    .recover_initial_device(account, &operation, &scope)
                    .await
                    .is_err()
            );
            assert_eq!(before, authority_snapshot(&context.fixture.pool).await);
            assert!(
                store
                    .compare_exchange_batch(
                        &[(target.0.clone(), None)],
                        &[(target.0, Some(target.1))]
                    )
                    .unwrap()
            );
            let mut join =
                arkret_event_draft::TypedEventDraft::<arkret_wire::event_spec::MemberState>::new(
                    scope.clone(),
                    ActorId::account(account.clone()),
                    serde_json::from_value(
                        json!({"member_id":ActorId::account(account.clone()),"membership":"join"}),
                    )
                    .unwrap(),
                )
                .unwrap()
                .with_applet_id(context.native.package.applet_id.clone())
                .with_authorization_ref(grant.clone().into())
                .author_with_digest_suite(now, arkret_canonical::DigestSuite::Sha256)
                .unwrap();
            arkret_signatures::sign_event(
                &mut join,
                device.signer(),
                SignEventOptions::new().with_created_at(now),
            )
            .unwrap();
            let request = SelfAuthoritySubmitRequest::Event(
                arkret_wire::EventAdmissionSubmission::new(join.event().clone()),
            );
            let producer_context = arkret::ProducerVerificationContext {
                actor: ActorId::account(device.account_id.clone()),
                verification_method: arkret::DidUrl::new(
                    device.signer().verification_method().to_owned(),
                )
                .unwrap(),
                public_key: PublicKeyMaterial::Ed25519Raw {
                    bytes: device.signer().verifying_key().to_bytes().to_vec(),
                },
                digest_suite: arkret::DigestSuite::Sha256,
            };
            let request =
                arkret::VerifiedSubmission::verify(request, |_| Ok(producer_context.clone()))
                    .unwrap();
            let options = arkret_http_client::ClientRequestOptions::new()
                .idempotency_key(join.event_id().as_str());
            context.lost.attempts.lock().unwrap().clear();
            context
                .lost
                .armed
                .store(true, std::sync::atomic::Ordering::SeqCst);
            let outcome = device
                .client()
                .submit_to_realm_authority(&request, &options)
                .await
                .unwrap();
            {
                let attempts = context.lost.attempts.lock().unwrap();
                assert_eq!(
                    attempts.len(),
                    2,
                    "real accepted response must be retried once"
                );
                assert_ne!(attempts[0].0.nonce, attempts[1].0.nonce);
                let mut first = attempts[0].0.clone();
                first.nonce = attempts[1].0.nonce.clone();
                assert_eq!(first, attempts[1].0);
                assert_eq!(attempts[0].1, attempts[1].1);
                assert_eq!(attempts[0].2, attempts[1].2);
            }
            let SelfAuthoritySubmitOutcome::Ordinary(AuthoritySubmitOutcome::Accepted {
                commit,
                ..
            }) = outcome
            else {
                panic!("native join failed: {outcome:?}")
            };
            assert_eq!(commit.event_ref, *join.event_id());
            let replay = device
                .client()
                .submit_to_realm_authority(&request, &options)
                .await
                .unwrap();
            assert!(
                matches!(replay,SelfAuthoritySubmitOutcome::Ordinary(AuthoritySubmitOutcome::Accepted{commit:ref old,..}) if *old==commit)
            );
            *context.native.managed_author.lock().unwrap() = None;
            drop(device);
            drop(runtime);
            drop(author);
            drop(edge);
            drop(store);
        }
        context
    })
}

pub(crate) fn retained(
    mut context: Box<RuntimeContext>,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> {
    Box::pin(async move {
        let before = authority_snapshot(&context.fixture.pool).await;
        let _rotated_package = context.native.rotate();
        let mut config = context.config.clone();
        config.arkret.signing_key_seed_hex = "2c".repeat(32);
        config.arkret.verification_method_fragment = "#applet-native-key-new".into();
        config.arkret.managed_actor_authoring.device =
            Some(arkret_bridge_runtime::ManagedDeviceBootstrapConfig {
                actions: vec![
                    arkret_wire::CapabilityActionId::from_wire("ak.applet.join").unwrap(),
                    arkret_wire::CapabilityActionId::from_wire("ak.message.create").unwrap(),
                ],
                lifetime_seconds: 7200,
                mls: false,
                key_package_inventory_target: 20,
            });
        let store = FileAuthoringStore::shared(context.store_path.clone()).unwrap();
        let edge = host(config.clone(), store.clone());
        let author = Arc::new(ManagedActorAuthoringService::new(edge.clone()).unwrap());
        for (_, original, _) in &context.accepted {
            let station_key = &context.config.arkret.trusted_verification_methods[0];
            edge.install_managed_authoring_completion(
                original,
                &station_key.verification_method,
                &station_key.public_key,
            )
            .unwrap();
            let (request, bundle) = match &original.authoring_context.committed_request {
                AppletManagedActorCommittedRequest::Bot(bot) => {
                    (&bot.authoring_request, &bot.managed_actor_bundle)
                }
                AppletManagedActorCommittedRequest::Ghost(ghost) => (
                    &ghost.authoring_request,
                    ghost.managed_actor_bundle.as_ref().unwrap(),
                ),
            };
            let recovered = author.author(request).await.unwrap();
            assert_eq!(
                arkret_canonical::canonical_json_bytes(bundle).unwrap(),
                arkret_canonical::canonical_json_bytes(&recovered).unwrap()
            );
        }
        let devices = ManagedDeviceRuntime::bootstrap_if_configured(edge.clone())
            .await
            .unwrap();
        assert_eq!(devices.len(), 2);
        for device in &devices {
            use coland_storage::DeviceRevocationStore as _;
            let current = coland_storage_postgres::PgDeviceRevocationStore {
                pool: context.fixture.pool.clone(),
            }
            .applet_managed_device_authority(
                &device.account_id,
                &device.device_id,
                chrono::Utc::now(),
            )
            .await
            .unwrap()
            .unwrap();
            assert_eq!(
                serde_json::to_value(&current.scopes).unwrap(),
                json!([{"effective_scope":{"kind":"realm","realm_id":context.fixture.realm},"actions":["ak.applet.join","ak.event.read"]}]),
                "changed host config must not widen an existing signed authorization"
            );
        }
        let roots = store
            .entries_with_prefix("managed-authoring/original-roots/")
            .unwrap();
        let removed = roots[0].clone();
        assert!(
            store
                .compare_exchange_batch(
                    &[(removed.0.clone(), Some(removed.1.clone()))],
                    &[(removed.0.clone(), None)]
                )
                .unwrap()
        );
        let available = ManagedDeviceRuntime::bootstrap_if_configured(edge.clone())
            .await
            .unwrap();
        assert_eq!(
            available.len(),
            1,
            "one unavailable Account must not block the other Account's recovery"
        );
        assert!(
            store
                .compare_exchange_batch(
                    &[(removed.0.clone(), None)],
                    &[(removed.0, Some(removed.1))]
                )
                .unwrap()
        );
        assert_eq!(before, authority_snapshot(&context.fixture.pool).await);
        drop(available);
        drop(devices);
        drop(author);
        drop(edge);
        drop(store);
        context.server_handle.stop_graceful(None);
        (&mut context.server).await.unwrap();
        std::fs::remove_file(&context.store_path).unwrap();
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn independent_bot_and_ghost_devices_recover_exact_authorization_after_outcome_write_failure()
{
    let context = Box::new(setup().await);
    let context = recover(context).await;
    retained(context).await;
}
