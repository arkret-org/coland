//! Real authoring inputs for the shared Applet transaction contract.
//! Mirrors the registered HTTP fixture's signed prerequisites; commits always
//! pass the production closed aggregate, never a synthetic verified flag.

#[path = "applet_widget_inventory_fixture.rs"]
mod applet_widget_inventory_fixture;
#[path = "management_archive_fixture.rs"]
mod management_archive_fixture;
#[path = "realm_actor_mls_fixture.rs"]
mod realm_actor_mls_fixture;

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use arkret_identifiers::{AppletId, Did, EventId, Hash, RealmId};
use arkret_models_collaboration::events_payloads::{
    CapabilityGrantCreateBody, CapabilityGrantPayload,
};
use arkret_models_collaboration::governance::grant_constraint::{
    CapabilitySubject, GrantConstraint, IssuerAuthorityRef,
};
use arkret_models_integration::applet::*;
use arkret_models_integration::*;
use arkret_signatures::Ed25519PayloadSigner;
use arkret_signatures::http_signature::{
    HttpSignatureScenario, SignedRequestParts, sign_http_message_for_scenario,
};
use arkret_wire::{ActorId, Event, EventKind, ScopeRef};
use base64::Engine as _;
use coland_http::config::AppConfig;
use coland_http::service;
use coland_http::state::AppState;
use coland_storage::contract_tests::{
    AppletFormalCommitFactory, AppletFormalCommitUnit, AppletFormalFinalizer,
};
use coland_storage::{AppletStore as _, AuthorityCommitStore, PersistenceError, PersistenceResult};
use coland_storage_postgres::{PgAppletStore, PgAuthorityCommitStore, PgPool};
use coland_test_support::AppStateTestExt as _;
use coland_test_support::pcr_genesis::PcrGenesisFixture;
use ed25519_dalek::SigningKey;
use salvo::http::StatusCode;
use salvo::test::{ResponseExt, TestClient};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use url::Url;

use super::ordinary_realm;

struct Fixture {
    state: AppState,
    pool: PgPool,
    pcr: PcrGenesisFixture,
    realm: RealmId,
    authority_event_ref: Option<EventId>,
    token: String,
    holder_key: SigningKey,
}

impl Fixture {
    async fn new(pool: PgPool) -> Self {
        Box::pin(Self::new_at(pool, None, None)).await
    }

    async fn new_at(
        pool: PgPool,
        public_base: Option<String>,
        founding_device_seed: Option<[u8; 32]>,
    ) -> Self {
        let slot = Arc::new(Mutex::new(Value::Null));
        let management_authority = Arc::new(Mutex::new(None));
        let origin = spawn_introspection_mock(slot.clone(), management_authority.clone()).await;
        let mut config = AppConfig {
            development_mode: true,
            embedded_webvh_registration_bearer: Some("applet-fixture-registration".to_owned()),
            session_grant_introspection_url: Some(format!(
                "{origin}/_coauth/internal/session-grants/introspect"
            )),
            account_authority_url: Some(origin),
            // The fixture Applet Service is a did:webvh; registration epoch
            // evidence admits no did:web Service.
            did_resolver_allow_methods: vec![
                "webvh".to_owned(),
                "web".to_owned(),
                "key".to_owned(),
                "uuid".to_owned(),
            ],
            ..coland_test_support::app_config()
        };
        if let Some(base) = public_base {
            config.public_base_url = base;
            config.embedded_webvh_provider_enabled = true;
        }
        config.register_test_internal_authority_channel("applet-http-standard-grant".to_owned());
        let persistence = Arc::new(coland_storage_postgres::PgPersistenceStore::new(
            pool.clone(),
        ));
        let state = coland_test_support::app_state_with_persistence(config, persistence).await;
        let pcr = match founding_device_seed {
            None => PcrGenesisFixture::new(state.service_did()),
            Some(seed) => PcrGenesisFixture::new_with(
                state.service_did(),
                coland_test_support::device_authorization_history::DeviceHistoryFixtureOptions {
                    local_id: format!("applet-independent-{}", uuid::Uuid::now_v7().simple()),
                    founding_device_signing_seed: seed,
                    ..Default::default()
                },
            ),
        };
        Box::pin(pcr.admit(&state)).await.unwrap();
        let record = arkret_signatures::account_status::sign_account_status_record(
            arkret_models_collaboration::account_status::UnsignedAccountStatusRecord {
                schema: arkret_wire::SchemaId::ACCOUNT_STATUS_RECORD_V1.into(),
                account_authority_id: state.service_core_id(),
                account_id: pcr.history.account.clone(),
                principal_control_realm_id: pcr.unit.transactions[0].event.realm_id.clone(),
                binding_version: 1,
                status_seq: 1,
                previous_account_status_record_id: None,
                status: arkret_models_collaboration::objects::account_status::AccountStatus::Active,
                reason_code: None,
                reason: None,
                issued_at: arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now()),
                expires_at: None,
            },
            state.service_verification_method("notary-key").unwrap(),
            state.notary_signing_key().as_ref(),
        )
        .unwrap();
        *management_authority.lock().unwrap() = Some(ManagementAuthorityFixture {
            record,
            public_key: *state.notary_verifying_key().as_bytes(),
        });
        state
            .test_persistence()
            .accounts()
            .put(&coland_storage::AccountRecord {
                pk: coland_storage::AccountPk(0),
                principal_id: pcr.history.account.principal_id.clone(),
                station_id: pcr.history.account.station_id.clone(),
                localpart: String::new(),
                display_name: Some("Applet admin".to_owned()),
                bio: None,
                avatar_blob_ref: None,
                created_at: chrono::Utc::now(),
            })
            .await
            .expect("production account directory prerequisite after accepted PCR");
        let holder_key = SigningKey::from_bytes(&[88; 32]);
        let token = format!("applet-standard.{}", uuid::Uuid::now_v7());
        let jwk =
            arkret_signatures::JsonWebKey::from_ed25519_verifying_key(&holder_key.verifying_key());
        let jkt = arkret_signatures::dpop::dpop_jwk_thumbprint(&jwk).unwrap();
        let session_public_key =
            arkret_models_identity::session_credential::CanonicalSessionPublicJwk::new(
                serde_json::to_string(&json!({
                    "crv":"Ed25519", "kty":"OKP",
                    "x": arkret_canonical::base64url_encode(holder_key.verifying_key().to_bytes()),
                }))
                .unwrap(),
            )
            .expect("canonical public holder JWK");
        assert_eq!(session_public_key.thumbprint_sha256().unwrap(), jkt);
        let grant = arkret_models_collaboration::session_grants::SessionGrantValidationMetadata {
            id: arkret_identifiers::SessionGrantId::from_issuance_digest(
                Sha256::digest(token.as_bytes()).into(),
            ),
            issuer_id: arkret_wire::DidCoreId::new("ak:did_core:web:coauth.example").unwrap(),
            account_id: pcr.history.account.clone(),
            device_id: Some(pcr.history.founding_device_id.clone()),
            audience_id: state.service_core_id(),
            scopes: vec![
                arkret_wire::ServiceOperationId::SELF_ACCOUNT_COMMAND_UPDATE_PROFILE_V1,
                arkret_wire::ServiceOperationId::SELF_APPLET_INSTALL_COMMAND_PREVIEW_V1,
                arkret_wire::ServiceOperationId::SELF_APPLET_COMMAND_INSTALL_V1,
                arkret_wire::ServiceOperationId::SELF_APPLET_REVOKE_COMMAND_PREVIEW_V1,
                arkret_wire::ServiceOperationId::SELF_APPLET_COMMAND_REVOKE_V1,
                arkret_wire::ServiceOperationId::SELF_SIGNER_KEYS_READ_RESOLVE_V1,
                arkret_wire::ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT_V1,
                arkret_wire::ServiceOperationId::SELF_REALM_ACTOR_READ_MATERIAL_V1,
            ]
            .into_iter()
            .map(str::to_owned)
            .collect(),
            expires_at: chrono::Utc::now() + chrono::Duration::minutes(30),
            revoked_at: None,
            revocation_ref: format!("ak:session:{}", uuid::Uuid::now_v7()),
            session_public_key,
            cnf_jkt: jkt,
            credential_class:
                arkret_models_identity::session_credential::SessionGrantCredentialClass::Standard,
            holder_binding:
                arkret_models_identity::session_credential::SessionGrantHolderBinding::HumanDevice {
                    device_binding: pcr.history.founding_device_id.to_string(),
                },
            device_binding: Some(
                arkret_models_identity::session_credential::SessionGrantDeviceBinding {
                    device_id: pcr.history.founding_device_id.clone(),
                    authorization_event_id: pcr.history.events[1].event_id.clone(),
                    model_generation_ref: 1,
                },
            ),
            scope_details: None,
        };
        grant
            .validate()
            .expect("actual accepted founding-device StandardGrant metadata");
        let introspection = arkret_models_collaboration::session_grants::SessionGrantValidationOutcome {
            active: true,
            status: arkret_models_identity::admin_grant::SessionGrantAdminIntrospectionStatus::Active,
            proof_required: false,
            one_time_use_consumed: false,
            grant: Some(grant),
        };
        let wire = serde_json::to_value(&introspection).unwrap();
        serde_json::from_value::<
            arkret_models_collaboration::session_grants::SessionGrantValidationOutcome,
        >(wire.clone())
        .expect("typed introspection response round-trip")
        .validate()
        .expect("valid serialized introspection metadata");
        *slot.lock().unwrap() = wire;
        let realm = pcr.unit.transactions[0].event.realm_id.clone();
        let mut fixture = Box::new(Self {
            state,
            pool,
            pcr,
            realm,
            authority_event_ref: None,
            token,
            holder_key,
        });
        let profile = fixture.admin_event(EventKind::ProfileCreate,ScopeRef::Realm {realm_id:fixture.pcr.unit.transactions[0].event.realm_id.clone()},
            json!({"object":{"principal_id":fixture.pcr.history.account.principal_id,"actor_kind":"user","display_name":"Applet admin"}}));
        let (status, body) = fixture
            .admin_post(
                "/_arkret/self/account/profile",
                arkret_wire::ServiceOperationId::SELF_ACCOUNT_COMMAND_UPDATE_PROFILE_V1,
                &json!({"profile_event":{"event":profile}}),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "Human Profile: {body}");
        fixture.new_realm().await;
        *fixture
    }

    async fn new_circle_scope(&self) -> ScopeRef {
        let create = self.admin_event(EventKind::CircleCreate, ScopeRef::Realm { realm_id: self.realm.clone() }, json!({"object":{
            "schema":"ak.schema.circle.v1","realm_id":self.realm,"title":"Applet scope","display":{"short_name":format!("Applet-{}",&uuid::Uuid::now_v7().simple().to_string()[24..]),"color_token":"blue","symbol":{"glyph":"lock"}},
            "directory_visibility":"members","join_rule":"public","history_access":"since_join","state":"active","created_by":ActorId::account(self.pcr.history.account.clone()),"created_at":arkret_canonical::format_timestamp_canonical(chrono::Utc::now())
        }}));
        let circle_id = arkret_wire::CircleId::from_event_id(&create.event_id);
        realm_native_fixture::boxed_step(|| accepted_admin_domain_event(self, create)).await;
        ScopeRef::Circle {
            realm_id: self.realm.clone(),
            circle_id,
        }
    }

    async fn new_realm(&mut self) {
        let mut unit = Box::new(ordinary_realm::bootstrap_unit_for_account(
            &uuid::Uuid::now_v7().to_string(),
            &self.pcr.history.account,
            &self.state.service_did(),
        ));
        self.realm = unit.transactions[0].event.realm_id.clone();
        let source = PgAuthorityCommitStore {
            pool: self.pool.clone(),
        };
        let mut previous_commit = None;
        for tx in &mut unit.transactions {
            tx.event = self.sign_admin(tx.event.clone());
            tx.commit.event_ref = tx.event.event_id.clone();
            tx.producer_signer_fact = source
                .prepare_account_device_signer_fact(&tx.event, tx.commit.committed_at)
                .await
                .unwrap()
                .map(Into::into);
            assert!(tx.producer_signer_fact.is_some());
            tx.commit.producer_signer_fact_digest = tx
                .producer_signer_fact
                .as_ref()
                .map(|fact| fact.digest().unwrap());
            tx.commit.previous_commit_ref = previous_commit;
            ordinary_realm::seal_final_commit(&mut tx.commit);
            tx.commit.signature = arkret_signatures::detached_object::sign_detached_object(
                &arkret_canonical::unsigned_value(&tx.commit, &["signature"]).unwrap(),
                arkret_wire::DetachedSignatureContext::RealmCommit,
                self.state
                    .service_verification_method("notary-key")
                    .unwrap(),
                tx.commit.committed_at,
                self.state.notary_signing_key().as_ref(),
            )
            .unwrap();
            previous_commit = Some(tx.commit.commit_id.clone());
        }
        for (submission, tx) in unit.submission.events.iter_mut().zip(&unit.transactions) {
            submission.event = tx.event.clone();
        }
        unit.exact_request_body=arkret_canonical::canonical_json_bytes(&arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequest::OrdinaryRealmBootstrap(unit.submission.clone())).unwrap();
        PgAuthorityCommitStore {
            pool: self.pool.clone(),
        }
        .admit_ordinary_realm_bootstrap_unit(&unit, unit.transactions[0].commit.committed_at)
        .await
        .unwrap();
        self.authority_event_ref = Some(unit.transactions[0].event.event_id.clone());
        self.state.hydrate().await.unwrap();
    }

    fn sign_admin(&self, mut event: Event) -> Event {
        // Replace the bootstrap fixture's structural proof only after finalizing
        // the complete Event content with the real device signer.
        event.producer_proof = None;
        coland_test_support::signed_event::sign_fixture_event(
            event,
            self.pcr.history.did.as_str(),
            self.pcr.history.founding_device_id.as_str(),
            self.pcr.history.founding_device_signing_seed,
        )
    }

    fn admin_event(&self, kind: EventKind, scope: ScopeRef, payload: Value) -> Event {
        let mut event = arkret_wire::test_support::raw_event_at(
            kind.as_str(),
            scope,
            self.pcr.history.account.principal_id.clone(),
            self.state.service_core_id(),
            payload,
            chrono::Utc::now(),
        )
        .unwrap();
        if kind == EventKind::CircleCreate {
            event.payload.get_mut("object").unwrap()["created_at"] = json!(
                arkret_canonical::format_timestamp_canonical(event.created_at)
            );
        }
        self.sign_admin(event)
    }

    fn admin_post<'a>(
        &'a self,
        path: &'a str,
        operation: &'a str,
        body: &'a Value,
        idempotency: Option<&'a str>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = (StatusCode, Value)> + Send + 'a>> {
        Box::pin(async move {
            let htu = format!(
                "{}{}",
                self.state.config().public_base_url.trim_end_matches('/'),
                path
            );
            let dpop = arkret_signatures::dpop::build_dpop_proof(
                &arkret_signatures::dpop::DpopProofRequest::new("POST", htu)
                    .access_token(self.token.clone()),
                &self.holder_key,
            )
            .unwrap();
            let mut request = TestClient::post(format!("http://server{path}"))
                .add_header("authorization", format!("DPoP {}", self.token), true)
                .add_header("dpop", dpop.header_value, true)
                .add_header("Arkret-Operation", operation, true)
                .add_header("content-type", "application/json", true)
                .body(arkret_canonical::canonical_json_bytes(body).unwrap());
            if let Some(key) = idempotency {
                request = request.add_header("Idempotency-Key", key, true);
            }
            let router = service(self.state.clone());
            let mut response = realm_native_fixture::boxed_step(|| request.send(&router)).await;
            let status = response.status_code.unwrap();
            (status, response.take_json().await.unwrap())
        })
    }

    async fn admin_post_network(
        &self,
        path: &str,
        operation: &str,
        body: &Value,
        idempotency: &str,
    ) -> (StatusCode, Value) {
        // Keep the client scenario off the server's authorization call stack.
        let url = format!(
            "{}{}",
            self.state.config().public_base_url.trim_end_matches('/'),
            path
        );
        let dpop = arkret_signatures::dpop::build_dpop_proof(
            &arkret_signatures::dpop::DpopProofRequest::new("POST", &url)
                .access_token(self.token.clone()),
            &self.holder_key,
        )
        .unwrap();
        let client = reqwest::Client::builder()
            .tls_backend_rustls()
            .tls_certs_only(
                reqwest::Certificate::from_pem_bundle(
                    &realm_native_fixture::native_tls_material().ca,
                )
                .unwrap(),
            )
            .build()
            .unwrap();
        let response = client
            .post(url)
            .header("authorization", format!("DPoP {}", self.token))
            .header("dpop", dpop.header_value)
            .header("Arkret-Operation", operation)
            .header("content-type", "application/json")
            .header("Idempotency-Key", idempotency)
            .body(arkret_canonical::canonical_json_bytes(body).unwrap())
            .send()
            .await
            .unwrap();
        let status = response.status();
        (status, response.json().await.unwrap())
    }

    async fn service_post(
        &self,
        package: &AppletPackage,
        path: &str,
        operation: &str,
        body: &Value,
        key: &str,
    ) -> (StatusCode, Value) {
        self.service_post_at(
            package,
            path,
            operation,
            body,
            key,
            chrono::Utc::now().timestamp(),
        )
        .await
    }

    async fn service_post_at(
        &self,
        package: &AppletPackage,
        path: &str,
        operation: &str,
        body: &Value,
        key: &str,
        created: i64,
    ) -> (StatusCode, Value) {
        let bytes = arkret_canonical::canonical_json_bytes(body).unwrap();
        let digest = content_digest_header(&bytes);
        let scheme = self
            .state
            .config()
            .public_base_url
            .split_once("://")
            .map_or("http", |(scheme, _)| scheme);
        let peer_forward =
            operation == arkret_wire::ServiceOperationId::PEER_EVENTS_COMMAND_SUBMIT_V1;
        // A Station forwards the original Service-signed slots. Transport and
        // producer have independently authenticated keys and obligations.
        let source_service_id = if peer_forward {
            self.state.service_core_id().to_string()
        } else {
            package.service_id.to_string()
        };
        let transport_method = if peer_forward {
            self.state
                .service_verification_method("notary-key")
                .unwrap()
                .to_string()
        } else {
            package.webhook_auth.key_ref.to_string()
        };
        let transport_key = if peer_forward {
            self.state.notary_signing_key().as_ref().clone()
        } else {
            applet_service_signing_key(&package.webhook_auth.key_ref)
        };

        let destination_service_id = self.state.service_id().to_owned();
        let request_url = if peer_forward {
            format!(
                "{}{}",
                self.state.config().public_base_url.trim_end_matches('/'),
                path
            )
        } else {
            format!("http://server{path}")
        };
        let target = url::Url::parse(&request_url).unwrap();
        let authority = &target[url::Position::BeforeHost..url::Position::AfterPort];
        let mut signed_request = SignedRequestParts {
            method: "POST".to_owned(),
            target_uri: if peer_forward {
                request_url.clone()
            } else {
                format!("{scheme}://server{path}")
            },
            authority: authority.to_owned(),
            path: path.to_owned(),
            headers: vec![
                ("arkret-operation".to_owned(), operation.to_owned()),
                ("content-type".to_owned(), "application/json".to_owned()),
                ("content-digest".to_owned(), digest.clone()),
                ("source-service-id".to_owned(), source_service_id.clone()),
                (
                    "destination-service-id".to_owned(),
                    destination_service_id.clone(),
                ),
                ("idempotency-key".to_owned(), key.to_owned()),
            ],
            body_digest: Some(digest.clone()),
        };
        if operation == arkret_wire::ServiceOperationId::PEER_EVENTS_COMMAND_SUBMIT_V1 {
            for name in ["source-trust-domain", "destination-trust-domain"] {
                signed_request.headers.push((
                    name.to_owned(),
                    self.state.config().trust_domain.to_string(),
                ));
            }
        }
        let signature = sign_http_message_for_scenario(
            &signed_request,
            if [
                arkret_wire::ServiceOperationId::SELF_APPLET_AUTHORITY_READ_MATERIAL_V1,
                arkret_wire::ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT_V1,
                arkret_wire::ServiceOperationId::SELF_REALM_ACTOR_READ_MATERIAL_V1,
                arkret_wire::ServiceOperationId::PEER_EVENTS_COMMAND_SUBMIT_V1,
            ]
            .contains(&operation)
            {
                HttpSignatureScenario::ServiceToServiceV1
            } else {
                HttpSignatureScenario::AppletTransactionV1
            },
            if operation == arkret_wire::ServiceOperationId::PEER_EVENTS_COMMAND_SUBMIT_V1 {
                &[
                    "content-digest",
                    "idempotency-key",
                    "source-trust-domain",
                    "destination-trust-domain",
                ]
            } else if [
                arkret_wire::ServiceOperationId::SELF_APPLET_AUTHORITY_READ_MATERIAL_V1,
                arkret_wire::ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT_V1,
                arkret_wire::ServiceOperationId::SELF_REALM_ACTOR_READ_MATERIAL_V1,
            ]
            .contains(&operation)
            {
                &["content-digest", "idempotency-key"]
            } else {
                &[]
            },
            "sig1",
            &transport_method,
            created,
            &transport_key,
        )
        .unwrap();
        let mut request = TestClient::post(&request_url)
            .add_header("Arkret-Operation", operation, true)
            .add_header("content-type", "application/json", true)
            .add_header("Content-Digest", digest, true)
            .add_header("Source-Service-ID", source_service_id, true)
            .add_header("Destination-Service-ID", destination_service_id, true)
            .add_header("Idempotency-Key", key, true)
            .add_header("Signature-Input", signature.signature_input_header, true)
            .add_header("Signature", signature.signature_header, true)
            .body(bytes);
        if peer_forward {
            request = request
                .add_header(
                    "Source-Trust-Domain",
                    self.state.config().trust_domain.as_str(),
                    true,
                )
                .add_header(
                    "Destination-Trust-Domain",
                    self.state.config().trust_domain.as_str(),
                    true,
                );
        }
        let mut response = request.send(&service(self.state.clone())).await;
        (
            response.status_code.unwrap(),
            response.take_json().await.unwrap(),
        )
    }
}

fn content_digest_header(bytes: &[u8]) -> String {
    let raw = Sha256::digest(bytes);
    format!(
        "sha-256=:{}:",
        base64::engine::general_purpose::STANDARD.encode(raw)
    )
}

fn applet_service_signing_key(verification_method: &str) -> SigningKey {
    if verification_method.ends_with("#applet-native-key")
        || verification_method.ends_with("#applet-service-key")
    {
        return SigningKey::from_bytes(&[42; 32]);
    }
    if verification_method.ends_with("#applet-native-key-new") {
        return SigningKey::from_bytes(&[44; 32]);
    }
    let mut hasher = Sha256::new();
    hasher.update(b"coland:applet-service-key:");
    hasher.update(verification_method.as_bytes());
    let seed: [u8; 32] = hasher.finalize().into();
    SigningKey::from_bytes(&seed)
}

fn signed_applet_package(
    applet_id: &str,
    namespace: &str,
    _target_station_id: &arkret_identifiers::DidCoreId,
    endpoint: Option<&str>,
) -> AppletPackage {
    let multibase = arkret_canonical::ed25519_pubkey_to_did_key_multibase(
        SigningKey::from_bytes(&[13; 32]).verifying_key().as_bytes(),
    );
    let controller_did = Did::new(format!("did:key:{multibase}")).unwrap();
    let controller_principal_id = arkret_wire::project_did_to_core_id(&controller_did).unwrap();
    // Registration epoch evidence admits only did:webvh / did:key; the Service
    // keeps its own SCID, distinct from every managed actor it provisions.
    let authority = format!("{}.applet.example", safe_did_token(namespace));
    let native = fixture_applet_service_inception(&authority);
    let service_did = Did::new(native.did.clone()).unwrap();
    let service_id = arkret_wire::project_did_to_core_id(&service_did).unwrap();
    let mut package = AppletPackage::new(
        format!("package:{applet_id}"),
        AppletId::new(applet_id.to_owned()).unwrap(),
        service_id.clone(),
        service_did.clone(),
        controller_principal_id.clone(),
        endpoint
            .map(str::to_owned)
            .unwrap_or_else(|| format!("https://{}.applet.example", safe_did_token(namespace))),
        vec!["arkret.portal".to_owned()],
        AppletWireNamespaces {
            handles: vec![AppletNamespaceEntry::exclusive(namespace.to_owned())],
            ..Default::default()
        },
    );
    package.webhook_auth = WebhookAuth::http_message_signature(
        arkret_wire::DidUrl::new(format!("{service_did}#applet-service-key")).unwrap(),
        vec![HttpMessageSignatureAlgorithm::Ed25519],
    );
    let service_document = applet_service_id_document(&package);
    let registration_epoch_evidence =
        arkret_models_integration::applet::AppletRegistrationEpochEvidence::from_did_document(
            &service_document,
            service_method_version_evidence(&package),
        )
        .unwrap();
    package.requested_scopes = vec![
        "ak.message.create".to_owned(),
        "ak.applet.join".to_owned(),
        "ak.applet.bot.provision".to_owned(),
        "ak.applet.ghost.provision".to_owned(),
    ];
    if namespace.starts_with("registered-audit-") {
        package.requested_scopes.extend([
            "ak.strand.watch.set.others".to_owned(),
            "ak.audit.accessed".to_owned(),
        ]);
    }
    package.claimed_profiles = vec![
        "ak.profile.applet_bridge.v1".to_owned(),
        "ak.profile.applet_service.v1".to_owned(),
    ];
    package.endpoint_policy = AppletEndpointPolicy {
        endpoints: [
            "/_arkret/edge/applet/transactions",
            "/_arkret/edge/applet/actors/{actor_id}",
            "/_arkret/edge/applet/realms/{realm_id_or_alias}",
        ]
        .into_iter()
        .map(|path| AppletEndpointEntry {
            method: AppletEndpointMethod::Post,
            path: path.to_owned(),
            auth: Some(AppletEndpointAuth::WebhookSignature),
            description: None,
            extra: Default::default(),
        })
        .collect(),
        extra: Default::default(),
    };
    package.ghost_policy = AppletGhostPolicy {
        enabled: true,
        accountability_template: Some("bot_actor_and_applet_registry".to_owned()),
        ..Default::default()
    };
    package.receive_events = true;
    package.receive_signals = true;
    package
        .stamp_registration_epoch(&registration_epoch_evidence)
        .unwrap();
    package.stamp_package_digest().unwrap();
    let verification_method = arkret_wire::DidUrl::new(format!("{controller_did}#{multibase}"))
        .expect("fixture verification method is a DID URL");
    let signer = Ed25519PayloadSigner::from_did_key_seed(
        [13u8; 32],
        controller_did,
        verification_method.clone(),
    );
    package.sign(&signer, &verification_method).unwrap();
    package
}

fn applet_service_did(package: &AppletPackage) -> Did {
    let did = Did::new(
        package
            .webhook_auth
            .key_ref
            .as_str()
            .split_once('#')
            .expect("fixture signing method has a fragment")
            .0,
    )
    .expect("fixture signing method names a Service DID");
    assert_eq!(
        arkret_wire::project_did_to_core_id(&did).unwrap(),
        package.service_id
    );
    did
}

fn fixture_applet_service_inception(
    authority: &str,
) -> arkret_signatures::webvh::PreparedInception {
    use rand_chacha::rand_core::SeedableRng as _;
    let endpoint: Url = format!("https://{authority}/").parse().unwrap();
    let mut rng =
        rand_chacha::ChaCha20Rng::from_seed(arkret_canonical::sha256_bytes(authority.as_bytes()));
    arkret_signatures::webvh::prepare_service_inception_with_did_key_seed(
        &mut rng,
        &arkret_signatures::webvh::ServiceInceptionInput {
            principal_endpoint: &endpoint,
            local_id: "service",
            also_known_as: &[],
            version_time: "2026-01-01T00:00:00Z".parse().unwrap(),
            did_key_fragment: Some("applet-service-key"),
        },
        &[42; 32],
    )
    .unwrap()
}

fn fixture_applet_service_history(
    package: &AppletPackage,
) -> arkret_models_identity::AuthenticatedServiceResolution {
    let did = applet_service_did(package);
    let authority = did
        .as_str()
        .strip_prefix("did:webvh:")
        .unwrap()
        .split(':')
        .nth(1)
        .unwrap()
        .replace("%3A", ":")
        .replace("%3a", ":");
    let native = fixture_applet_service_inception(&authority);
    assert_eq!(native.did, did.as_str());
    arkret_identity::build_authenticated_webvh_service_resolution(
        package.service_id.clone(),
        "applet_service".to_owned(),
        serde_json::from_value(native.log_entry["state"].clone()).unwrap(),
        vec![native.log_entry.clone()],
        Vec::new(),
        chrono::Utc::now(),
    )
    .unwrap()
}

fn applet_service_id_document(package: &AppletPackage) -> arkret_identity::DidDocument {
    fixture_applet_service_history(package).normalized_did_document
}

async fn ingest_applet_service_id_document(state: &AppState, package: &AppletPackage) {
    let now = chrono::Utc::now();
    let source = fixture_applet_service_history(package);
    let document = source.normalized_did_document.clone();
    let record = coland_storage::WebvhDocumentRecord {
        did: document.id.to_string(),
        did_document: serde_json::to_value(document).unwrap(),
        key_log_head: Some(
            source
                .method_history_evidence
                .boundary()
                .to_method_history_head
                .clone(),
        ),
        seq: 1,
        method_evidence: serde_json::to_value(&source.method_history_evidence).unwrap(),
        fetched_at: now,
        expires_at: now + chrono::Duration::minutes(15),
        updated_at: now,
    };
    state
        .test_persistence()
        .webvh()
        .put_document(record.clone())
        .await
        .unwrap();
    state
        .test_cache_resolved_webvh_record(coland_services::identity::DidDocumentState {
            did: record.did,
            did_document: record.did_document,
            key_log_head: record.key_log_head,
            seq: record.seq,
            method_evidence: record.method_evidence,
            fetched_at: record.fetched_at,
            expires_at: record.expires_at,
            updated_at: record.updated_at,
        })
        .unwrap();
}

fn service_method_version_evidence(package: &AppletPackage) -> AppletDidMethodVersionEvidence {
    AppletDidMethodVersionEvidence::versioned(
        "did:webvh",
        Some(
            fixture_applet_service_history(package)
                .method_history_evidence
                .boundary()
                .to_version_id
                .clone(),
        ),
        None,
    )
    .unwrap()
}

fn applet_registration_epoch_evidence(
    package: &AppletPackage,
) -> arkret_models_integration::AppletRegistrationEpochEvidence {
    arkret_models_integration::AppletRegistrationEpochEvidence::from_did_document(
        &applet_service_id_document(package),
        service_method_version_evidence(package),
    )
    .unwrap()
}

fn safe_did_token(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '.' {
                ch.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect()
}

#[derive(Clone)]
struct ManagementAuthorityFixture {
    record: arkret_models_collaboration::account_status::AccountStatusRecord,
    public_key: [u8; 32],
}

async fn spawn_introspection_mock(
    slot: Arc<Mutex<Value>>,
    authority: Arc<Mutex<Option<ManagementAuthorityFixture>>>,
) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("introspection mock binds");
    let address = listener.local_addr().expect("introspection mock address");
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let slot = slot.clone();
            let authority = authority.clone();
            tokio::spawn(async move {
                let request = read_http_request(&mut stream).await;
                let end = request
                    .windows(4)
                    .position(|bytes| bytes == b"\r\n\r\n")
                    .unwrap()
                    + 4;
                let headers = String::from_utf8_lossy(&request[..end]);
                let body = if headers.lines().next()
                    == Some("POST /_arkret/peer/account-status/resolve HTTP/1.1")
                {
                    use arkret_models_collaboration::account_lifecycle::{
                        AccountStatusResolveOutcome, AccountStatusResolveRequestBody,
                    };
                    let query: AccountStatusResolveRequestBody =
                        serde_json::from_slice(&request[end..]).unwrap();
                    query.validate().unwrap();
                    let source = authority
                        .lock()
                        .unwrap()
                        .clone()
                        .expect("explicit signed AA fixture prerequisite");
                    assert_eq!(query.account_id, source.record.account_id);
                    assert_eq!(
                        query.account_authority_id,
                        source.record.account_authority_id
                    );
                    let pairs = headers
                        .lines()
                        .skip(1)
                        .filter_map(|line| line.split_once(':'))
                        .map(|(name, value)| (name.to_ascii_lowercase(), value.trim().to_owned()))
                        .collect::<Vec<_>>();
                    let policy=arkret_signatures::http_signature::SignatureVerificationPolicy::for_scenario(HttpSignatureScenario::ServiceToServiceV1,&["content-digest","source-trust-domain","destination-trust-domain"]).unwrap();
                    arkret_signatures::http_signature::verify_signed_canonical_json_message(
                        "POST",
                        &format!("http://{address}/_arkret/peer/account-status/resolve"),
                        &address.to_string(),
                        "/_arkret/peer/account-status/resolve",
                        pairs
                            .iter()
                            .map(|(name, value)| (name.as_str(), value.as_str())),
                        false,
                        &request[end..],
                        &ed25519_dalek::VerifyingKey::from_bytes(&source.public_key).unwrap(),
                        &policy,
                        chrono::Utc::now().timestamp(),
                    )
                    .unwrap();
                    let answer = AccountStatusResolveOutcome {
                        account_authority_id: query.account_authority_id.clone(),
                        account_id: query.account_id.clone(),
                        records: if query.from_status_seq <= source.record.status_seq {
                            vec![source.record]
                        } else {
                            vec![]
                        },
                        next_status_seq: None,
                        has_more: false,
                    };
                    answer.validate_for_request(&query).unwrap();
                    arkret_canonical::canonical_json_bytes(&answer).unwrap()
                } else {
                    serde_json::to_vec(&*slot.lock().unwrap()).expect("serialize outcome")
                };
                let headers = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                    body.len()
                );
                stream.write_all(headers.as_bytes()).await.unwrap();
                stream.write_all(&body).await.unwrap();
            });
        }
    });
    format!("http://{address}")
}

async fn read_http_request(stream: &mut tokio::net::TcpStream) -> Vec<u8> {
    let mut request = Vec::new();
    let mut expected = None;
    loop {
        let mut chunk = [0_u8; 2048];
        let read = stream.read(&mut chunk).await.expect("read request");
        assert!(read > 0, "introspection request ended early");
        request.extend_from_slice(&chunk[..read]);
        if expected.is_none()
            && let Some(index) = request.windows(4).position(|part| part == b"\r\n\r\n")
        {
            let headers = String::from_utf8_lossy(&request[..index]);
            let length = headers
                .lines()
                .find_map(|line| {
                    line.to_ascii_lowercase()
                        .strip_prefix("content-length:")
                        .and_then(|value| value.trim().parse::<usize>().ok())
                })
                .unwrap_or(0);
            expected = Some(index + 4 + length);
        }
        if expected.is_some_and(|total| request.len() >= total) {
            return request;
        }
    }
}

async fn admin_domain_request(
    fixture: &Fixture,
    event: Event,
) -> coland_storage::EventCommitRequest {
    let producer = event
        .account_device_producer()
        .unwrap()
        .expect("admin Event has a Human Device producer");
    // Explicit directory issuance is a fixture prerequisite. Local
    // producer validation prepares its root without retaining it.
    let query = arkret_models_crypto::KeysQueryRequestBody {
        device_keys: vec![arkret_models_crypto::QueryAccountDeviceSelector {
            account_id: producer.account_id.clone(),
            device_ids: vec![producer.device_id.clone()],
        }],
        timeout_ms: None,
    };
    let (status, result) = fixture
        .admin_post(
            "/_arkret/self/keys/query",
            arkret_wire::ServiceOperationId::SELF_KEYS_READ_LOOKUP_V1,
            &serde_json::to_value(query).unwrap(),
            None,
        )
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "explicit Device directory issuance: {result}"
    );
    let result: arkret_models_crypto::KeysQueryOutcome = serde_json::from_value(result).unwrap();
    let row = result
        .device_keys
        .iter()
        .find(|entry| entry.account_id == producer.account_id)
        .and_then(|entry| entry.device_keys.get(&producer.device_id))
        .expect("complete current Device directory row");
    let original = fixture
        .state
        .test_persistence()
        .account_device_signer_evidence()
        .get(
            &producer.account_id,
            &producer.device_id,
            &row.signer_evidence_ref,
        )
        .await
        .unwrap()
        .expect("explicitly issued original Device evidence retained");
    original
        .validate_binding(&producer.account_id, &producer.device_id)
        .unwrap();
    assert_eq!(
        original.signer_evidence_ref().unwrap(),
        row.signer_evidence_ref
    );
    let store = PgAuthorityCommitStore {
        pool: fixture.pool.clone(),
    };
    let stream = arkret_wire::CommitStreamRef::Realm {
        realm_id: fixture.realm.clone(),
    };
    let head = store.stream_head(&stream).await.unwrap().unwrap();
    let accepted = store
        .committed_event_by_commit_id(&head.commit_id)
        .await
        .unwrap()
        .unwrap();
    let previous = coland_storage::AuthorityCommitTransaction {
        expected_authority: store
            .current_authority(&fixture.realm)
            .await
            .unwrap()
            .unwrap(),
        event: accepted.event,
        commit: accepted.commit,
        producer_signer_fact: None,
        mls_state: None,
        welcomes: vec![],
        recipient_queue_capacity: 0,
    };
    let request = ordinary_realm::request_for_event(
        &previous,
        event.clone(),
        arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now()),
    );
    let mut request = ordinary_realm::source_request(&fixture.pool, request).await;
    request.authority_commit.commit.signature =
        arkret_signatures::detached_object::sign_detached_object(
            &arkret_canonical::unsigned_value(&request.authority_commit.commit, &["signature"])
                .unwrap(),
            arkret_wire::DetachedSignatureContext::RealmCommit,
            fixture
                .state
                .service_verification_method("notary-key")
                .unwrap(),
            request.authority_commit.commit.committed_at,
            fixture.state.notary_signing_key().as_ref(),
        )
        .unwrap();
    if let Some(fact) = request
        .authority_commit
        .producer_signer_fact
        .as_ref()
        .and_then(|fact| fact.as_account_device())
    {
        let selector = coland_storage::DeviceRevocationGateSelector {
            principal_id: producer.account_id.principal_id,
            station_id: producer.account_id.station_id,
            device_id: producer.device_id.to_string(),
            authorization_ref: fact.key.authorization_ref.clone(),
        };
        assert_eq!(
            original
                .device_projection_attestation
                .attestation
                .device_authorize_event_id,
            selector.authorization_ref.event_id
        );
        request.self_producer_guard = Some(
            coland_storage::SelfProducerCommitGuard::HumanDeviceEvidence {
                selector,
                evidence: Box::new(original),
            },
        );
    }
    request
}

async fn accepted_admin_domain_event(fixture: &Fixture, event: Event) {
    use coland_storage::EventCommitUnitOfWork as _;
    let request = admin_domain_request(fixture, event.clone()).await;
    coland_storage_postgres::PgEventCommitUnitOfWork::new(fixture.pool.clone())
        .commit_event(request)
        .await
        .unwrap();
    assert_accepted_event(fixture, &event).await;
}

async fn assert_accepted_event(fixture: &Fixture, event: &Event) {
    let accepted = fixture
        .state
        .test_persistence()
        .authority_commits()
        .committed_event(&event.event_id)
        .await
        .unwrap()
        .expect("accepted canonical Event and covering Commit");
    assert_eq!(accepted.event.event_id, event.event_id);
    assert_eq!(
        serde_json::to_value(accepted.event).unwrap(),
        serde_json::to_value(event).unwrap()
    );
    assert_eq!(accepted.commit.event_ref, event.event_id);
}

pub struct AppletAuthoringFactory {
    fixture: Fixture,
    packages: tokio::sync::Mutex<BTreeMap<String, AppletPackage>>,
    scopes: tokio::sync::Mutex<BTreeMap<String, ScopeRef>>,
}

impl AppletAuthoringFactory {
    pub async fn new(pool: PgPool) -> Self {
        Self {
            fixture: Box::pin(Fixture::new(pool)).await,
            packages: tokio::sync::Mutex::new(BTreeMap::new()),
            scopes: tokio::sync::Mutex::new(BTreeMap::new()),
        }
    }

    async fn scope(&self, label: &str) -> ScopeRef {
        let mut scopes = self.scopes.lock().await;
        if let Some(scope) = scopes.get(label) {
            return scope.clone();
        }
        // The original contract covers a Realm install and a distinct Circle
        // install under the same identity, including the last-scope fence race.
        let scope = if label.ends_with(":scope-right") || label.ends_with(":scope-conflict") {
            realm_native_fixture::boxed_step(|| self.fixture.new_circle_scope()).await
        } else {
            ScopeRef::Realm {
                realm_id: self.fixture.realm.clone(),
            }
        };
        scopes.insert(label.to_owned(), scope.clone());
        scope
    }

    fn controller_document(package: &AppletPackage) -> arkret_identity::DidDocument {
        let did = Did::new(
            package
                .proof
                .as_ref()
                .unwrap()
                .verification_method
                .as_str()
                .split('#')
                .next()
                .unwrap(),
        )
        .unwrap();
        arkret_identity::DidResolver::resolve_did(&arkret_identity::DidKeyResolver::new(), &did)
            .unwrap()
            .document
    }

    fn callbacks(
        &self,
        guards: &[coland_storage::SelfProducerCommitGuard],
    ) -> (
        coland_storage::AppletCommitAuthor,
        coland_storage::AppletResolutionAttester,
    ) {
        let resolution = guards.first().map(|guard| {
            let coland_storage::SelfProducerCommitGuard::HumanDeviceEvidence { evidence, .. } =
                guard
            else {
                panic!("accepted admin Device evidence required")
            };
            evidence.service_resolution.clone()
        });
        let key = self.fixture.state.notary_signing_key();
        let method = self
            .fixture
            .state
            .service_verification_method("notary-key")
            .unwrap();
        let application = coland_services::authority_commit::AuthorityCommitApplication::new(
            coland_services::persistence::PersistenceHandle::from_shared(
                self.fixture.state.test_persistence(),
            ),
            0,
        );
        let signing_key = key.clone();
        let signing_method = method.clone();
        let author: coland_storage::AppletCommitAuthor = Arc::new(
            move |event, authority, head, at, fact, core| {
                let commit = application
                    .sign_event_commit_at_authority_cut(
                        event,
                        authority,
                        head,
                        signing_method.clone(),
                        signing_key.as_ref(),
                        at,
                        fact,
                    )
                    .map_err(|error| PersistenceError::Conflict(error.to_string()))?;
                let evidence = core.map(|core| {
                Ok::<_, PersistenceError>(arkret_models_identity::AccountDeviceSignerEvidence {
                    device_projection_attestation: arkret_signatures::device_projection::sign_device_projection_attestation(core.clone(), signing_method.clone(), signing_key.as_ref())
                        .map_err(|error| PersistenceError::Conflict(error.to_string()))?,
                    service_resolution: resolution.clone().ok_or_else(|| PersistenceError::Conflict("accepted admin service resolution missing".to_owned()))?,
                })
            }).transpose()?;
                Ok((commit, evidence))
            },
        );
        let attester: coland_storage::AppletResolutionAttester = Arc::new(move |core| {
            arkret_signatures::service_resolution::sign_principal_resolution_projection_attestation(
                core,
                method.clone(),
                key.as_ref(),
            )
            .map_err(|error| PersistenceError::Conflict(error.to_string()))
        });
        (author, attester)
    }

    fn input(
        &self,
        request: coland_storage::AppletAdmissionRequest,
        package: &AppletPackage,
        guards: Vec<coland_storage::SelfProducerCommitGuard>,
        identity: Option<Value>,
        installation: Option<Value>,
        plan: Option<AppletInstallPlan>,
    ) -> coland_storage::AppletAuthoringUnitWrite {
        let (actor, request_digest, operation, preview) = match &request {
            coland_storage::AppletAdmissionRequest::Install(body) => (
                body.authoring_request_basis.install_actor_id.clone(),
                Hash::new(arkret_canonical::canonical_sha256(body.as_ref()).unwrap()).unwrap(),
                "ak.self.applet.command.install",
                String::new(),
            ),
        };
        let digest = Hash::new(arkret_canonical::canonical_sha256(&request).unwrap()).unwrap();
        let creation_service_resolution = None;
        coland_storage::AppletAuthoringUnitWrite {
            candidate: coland_storage::AppletAuthoringCandidate {
                request,
                package: package.clone(),
                recomputed_install_plan: plan,
                service_did_document: applet_service_id_document(package),
                controller_did_document: Self::controller_document(package),
                station_verification_method: self
                    .fixture
                    .state
                    .service_verification_method("notary-key")
                    .unwrap(),
                station_public_key: *self
                    .fixture
                    .state
                    .notary_signing_key()
                    .verifying_key()
                    .as_bytes(),
                admin_actor_id: actor,
                admin_producer_guards: guards,
                request_digest,
                canonical_request_hash: digest,
                prior_managed_refs: vec![],
                prior_service_signer_evidence: None,
                accepted_at: arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now()),
            },
            creation_service_resolution,
            expected_identity: identity,
            expected_installation: installation,
            preview_subject_key: preview,
            operation_id: operation.to_owned(),
            idempotency_key: format!("contract-{}", uuid::Uuid::now_v7()),
            operation_approvals: None,
        }
    }
}

fn finalized(
    input: &coland_storage::AppletAuthoringUnitWrite,
    identity: Value,
    expected_identity: Option<Value>,
    record: Value,
    expected_record: Option<Value>,
    response_body: Value,
) -> coland_storage::AppletUnitFinalization {
    let station = arkret_wire::project_did_to_core_id(
        &Did::new(
            input
                .station_verification_method
                .as_str()
                .split('#')
                .next()
                .unwrap(),
        )
        .unwrap(),
    )
    .unwrap();
    coland_storage::AppletUnitFinalization {
        applet_record: coland_storage::AppletRecordCommit {
            applet_id: input.package.applet_id.clone(),
            identity: coland_storage::AppletIdentityCommit {
                target_station_id: station,
                expected_record: expected_identity,
                record: identity,
            },
            expected_record,
            record,
        },
        idempotency_record: coland_storage::IdempotencyRecord {
            authenticated_actor: input.admin_actor_id.clone(),
            operation_id: input.operation_id.clone(),
            idempotency_key: input.idempotency_key.clone(),
            request_hash: input.canonical_request_hash.to_string(),
            response_status: 201,
            response_body: response_body.clone(),
            created_at: input.accepted_at,
            expires_at: input.accepted_at + chrono::Duration::days(1),
        },
        response_body,
    }
}

fn accepted_ref(
    refs: &[arkret_wire::CommittedEventRef],
    event: &Event,
) -> PersistenceResult<arkret_wire::CommittedEventRef> {
    let matches = refs
        .iter()
        .filter(|reference| reference.event_id == event.event_id)
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        return Err(PersistenceError::Conflict(
            "actual accepted Event ref missing or repeated".to_owned(),
        ));
    }
    Ok(matches[0].clone())
}

#[async_trait::async_trait]
impl AppletFormalCommitFactory for AppletAuthoringFactory {
    async fn prepare_install(
        &self,
        applet_id: &AppletId,
        scope_label: &str,
    ) -> AppletFormalCommitUnit {
        let scope = self.scope(scope_label).await;
        let mut packages = self.packages.lock().await;
        let package = packages
            .entry(applet_id.to_string())
            .or_insert_with(|| {
                let namespace = format!(
                    "{}contract.{}",
                    if scope_label.contains("registered-audit") {
                        "registered-audit-"
                    } else {
                        ""
                    },
                    uuid::Uuid::now_v7().simple()
                );
                signed_applet_package(
                    applet_id.as_str(),
                    &namespace,
                    &self.fixture.state.service_core_id(),
                    None,
                )
            })
            .clone();
        drop(packages);
        ingest_applet_service_id_document(&self.fixture.state, &package).await;
        let evidence = applet_registration_epoch_evidence(&package);
        let (status, current) = self.fixture.admin_post(
            "/_arkret/self/current-results/exact",
            arkret_wire::ServiceOperationId::SELF_CURRENT_RESULTS_READ_EXACT_V1,
            &json!({"realm_id":self.fixture.realm,"selector":{"kind":"applet_registration","applet_id":package.applet_id,"service_id":package.service_id}}),
            None,
        ).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "registration exact current: {current}"
        );
        let current: arkret_models_collaboration::exact_current_results::ExactCurrentResultsReadOutcome = serde_json::from_value(current).unwrap();
        let expected_revision = match current {
            arkret_models_collaboration::exact_current_results::ExactCurrentResultsReadOutcome::Present {
                entry: arkret_models_collaboration::exact_current_results::ExactCurrentResultEntry::AppletRegistration(row), ..
            } => Some(row.revision),
            arkret_models_collaboration::exact_current_results::ExactCurrentResultsReadOutcome::NeverWritten { .. } => None,
            _ => panic!("wrong registration current family"),
        };
        let registration = self.fixture.admin_event(
            EventKind::AppletRegistration,
            ScopeRef::realm(self.fixture.realm.clone()),
            serde_json::to_value(
                package
                    .to_registration(&evidence, expected_revision)
                    .unwrap(),
            )
            .unwrap(),
        );
        let mut actions = vec![
            "ak.message.create",
            "ak.applet.join",
            "ak.applet.bot.provision",
            "ak.applet.ghost.provision",
        ];
        if package.e2ee_policy.enabled {
            actions.extend(["ak.event.read", "ak.mls.commit", "ak.mls.genesis"]);
        }
        if scope_label.contains("registered-audit") {
            actions.extend(["ak.strand.watch.set.others", "ak.audit.accessed"]);
        }
        if package
            .requested_scopes
            .iter()
            .any(|action| action == "ak.applet.bridge_error")
        {
            actions.push("ak.applet.bridge_error");
        }
        // Durable capabilities are the canonical set projection of the
        // accepted grants, as in the production install finalizer.
        actions.sort_unstable();
        let grants = actions
            .iter()
            .map(|action| {
                let grant = CapabilityGrantCreateBody {
                    schema: arkret_wire::SchemaId::CAPABILITY_V1.to_owned(),
                    realm_id: Some(self.fixture.realm.clone()),
                    issuer_id: ActorId::account(self.fixture.pcr.history.account.clone()),
                    subject: CapabilitySubject::Actor(ActorId::service(package.service_id.clone())),
                    actions: vec![(*action).to_owned()],
                    resources: vec![match &scope {
                        ScopeRef::Realm { realm_id } => {
                            arkret_wire::WireResourceSelector::realm(realm_id.clone())
                        }
                        ScopeRef::Circle {
                            realm_id,
                            circle_id,
                        } => {
                            let mut resource = arkret_wire::WireResourceSelector::circle(
                                realm_id.clone(),
                                circle_id.clone(),
                            );
                            resource.match_scope = Some(arkret_wire::ResourceMatchScope::Exact);
                            resource
                        }
                        _ => panic!("fixture only supports Realm/Circle"),
                    }],
                    constraints: vec![GrantConstraint::applet_authority(
                        package.applet_id.clone(),
                        ActorId::service(package.service_id.clone()),
                        package.registration_epoch.clone(),
                    )],
                    issuer_authority_refs: vec![IssuerAuthorityRef::RealmRoot {
                        realm_id: self.fixture.realm.clone(),
                        authority_event_ref: self
                            .fixture
                            .authority_event_ref
                            .as_ref()
                            .expect("accepted Realm genesis authority")
                            .clone(),
                        authority_generation: 0,
                    }],
                    issued_at: chrono::Utc::now(),
                };
                self.fixture.admin_event(
                    EventKind::CapabilityGrant,
                    scope.clone(),
                    serde_json::to_value(CapabilityGrantPayload { grant }).unwrap(),
                )
            })
            .collect::<Vec<_>>();
        let basis:AppletInstallAuthoringRequestBasis=serde_json::from_value(json!({
            "schema":AppletInstallAuthoringRequestBasis::SCHEMA,"purpose":"install_service","target_station_id":self.fixture.state.service_core_id(),
            "install_actor_id":registration.actor_id,"applet_id":package.applet_id,"service_id":package.service_id,"package_digest":package.package_digest,
            "effective_scope":scope,"approval_request":{"approve_actions":actions,
                "ghost_actor_mode":"policy_declared","delegated_native_actors_allowed":false,"e2ee_join_allowed":package.e2ee_policy.enabled,"widget_allowed":false},
            "actor_policy":{"ghost_actor_mode":"policy_declared"},"e2ee_policy":{"mls_join_allowed":package.e2ee_policy.enabled},"widget_policy":{"widget_allowed":false},
            "registration_event":registration,"capability_grant_events":grants,
        })).unwrap();
        let preview_body = serde_json::to_value(AppletInstallPreviewRequestBody {
            applet_package: package.clone(),
            authoring_request_basis: basis.clone(),
        })
        .unwrap();
        let (status, preview) = self
            .fixture
            .admin_post(
                "/_arkret/self/applets/install/preview",
                arkret_wire::ServiceOperationId::SELF_APPLET_INSTALL_COMMAND_PREVIEW_V1,
                &preview_body,
                None,
            )
            .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "install preview for {applet_id} in {scope_label}: {preview}"
        );
        assert!(
            preview.get("authoring_request").is_none(),
            "Service install never authors a managed identity"
        );
        let plan: AppletInstallPlan = serde_json::from_value(preview["plan"].clone()).unwrap();

        let body = AppletInstallRequestBody {
            applet_package: package.clone(),
            authoring_request_basis: basis,
            plan_digest: plan.plan_digest.clone(),
        };
        let mut guards = vec![];
        for event in std::iter::once(&body.authoring_request_basis.registration_event)
            .chain(&body.authoring_request_basis.capability_grant_events)
        {
            guards.push(
                admin_domain_request(&self.fixture, event.clone())
                    .await
                    .self_producer_guard
                    .expect("accepted admin Device evidence"),
            );
        }
        let store = PgAppletStore {
            pool: self.fixture.pool.clone(),
        };
        let identity = store
            .get_identity(applet_id.as_str(), self.fixture.state.service_id())
            .await
            .unwrap();
        let prior = store
            .get(
                applet_id.as_str(),
                package.service_id.as_str(),
                &coland_storage::applet_effective_scope_key(&scope).unwrap(),
            )
            .await
            .unwrap();
        let (author, attester) = self.callbacks(&guards);
        let input = self.input(
            coland_storage::AppletAdmissionRequest::Install(Box::new(body.clone())),
            &package,
            guards,
            identity,
            prior,
            Some(plan),
        );
        let event_ids = std::iter::once(&body.authoring_request_basis.registration_event)
            .chain(&body.authoring_request_basis.capability_grant_events)
            .map(|event| event.event_id.to_string())
            .collect();
        let frozen = input.clone();
        let finalize: AppletFormalFinalizer = Arc::new(
            move |refs, expected_identity, expected_record| {
                let registration = &body.authoring_request_basis.registration_event;
                let grants = &body.authoring_request_basis.capability_grant_events;
                for event in std::iter::once(registration).chain(grants) {
                    accepted_ref(refs, event)?;
                }
                let grant_refs = grants
                    .iter()
                    .map(|event| arkret_wire::GrantId::from_event_id(&event.event_id))
                    .collect::<Vec<_>>();
                let outcome = AppletInstallOutcome {
                    install_id: format!("install-{}", frozen.idempotency_key),
                    applet_id: package.applet_id.clone(),
                    service_id: package.service_id.clone(),
                    registration_event_ref: accepted_ref(refs, registration)?.event_id,
                    registration_epoch: package.registration_epoch.clone(),
                    capability_grant_refs: grant_refs.clone(),
                    e2ee_authorization_refs: body
                        .e2ee_join_authorization_refs()
                        .map_err(|error| PersistenceError::Conflict(error.to_string()))?,
                    widget_policy_ref: None,
                    effective_status: AppletInstallEffectiveStatus::Installed,
                    rejections: vec![],
                };
                let identity = expected_identity.clone().unwrap_or_else(|| json!({
                "applet_id":package.applet_id,"registry_id":package.controller_principal_id,"target_station_id":body.authoring_request_basis.target_station_id,
                "initial_package":package,"initial_owner_actor_id":registration.actor_id,"initial_effective_scope":body.authoring_request_basis.effective_scope,
                "initial_registration_event":registration,"initial_capability_grant_refs":grant_refs,"globally_fenced_at":null,
            }));
                let produced = std::iter::once(registration)
                    .chain(grants)
                    .collect::<Vec<_>>();
                let steps = produced.iter().enumerate().map(|(index,event)| {
                let mut step=json!({"step_index":index,"target_event_kind":event.kind.as_str(),"canonical_event_body_hash":arkret_canonical::canonical_sha256(event).unwrap(),
                    "status":"accepted","planned_event_ref":event.event_id,"event_ref":event.event_id});
                if event.kind == EventKind::CapabilityGrant {step["grant_binding"]=json!({"applet_id":package.applet_id,
                    "grant_id":arkret_wire::GrantId::from_event_id(&event.event_id),"executed_by":ActorId::service(package.service_id.clone()),"registration_epoch":package.registration_epoch});}
                step
            }).collect::<Vec<_>>();
                let record = json!({
                    "applet_id":package.applet_id,"target_station_id":body.authoring_request_basis.target_station_id,"owner_actor_id":registration.actor_id,
                    "portal_realm_id":body.authoring_request_basis.effective_scope.realm_id(),"effective_scope":body.authoring_request_basis.effective_scope,
                    "capabilities":actions,"package":package,"ghost_actors_allowed":true,"status":"installed","registered_at":arkret_canonical::format_timestamp_canonical(frozen.accepted_at),"revoked_at":null,
                    "idempotency_key":frozen.idempotency_key,"install_body_digest":frozen.canonical_request_hash,"install_id":outcome.install_id,"install_response":outcome,
                    "registration_event":registration,"capability_grant_events":grants,
                    "install_execution":{"idempotency_key":frozen.idempotency_key,"body_hash":frozen.canonical_request_hash,"submitted_plan_digest":body.plan_digest,
                        "produced_event_refs":produced.iter().map(|event|&event.event_id).collect::<Vec<_>>(),"steps":steps},
                    "revoke_execution":null,
                });
                Ok(finalized(
                    &frozen,
                    identity,
                    expected_identity,
                    record,
                    expected_record,
                    serde_json::to_value(outcome).unwrap(),
                ))
            },
        );
        AppletFormalCommitUnit {
            input,
            author,
            attester,
            finalize,
            event_ids,
            effective_scope: scope,
        }
    }
}

/// Exercise Service first admission through the actual signed peer endpoint,
/// with an accepted installation and independently signed business/audit slots.
pub async fn registered_service_pair(pool: PgPool) {
    use arkret_models_collaboration::authority_commit::*;
    let factory = Box::pin(AppletAuthoringFactory::new(pool.clone())).await;
    let id = AppletId::new(format!("ak:applet:{}", uuid::Uuid::now_v7())).unwrap();
    let install = factory.prepare_install(&id, "registered-audit").await;
    let applets = PgAppletStore { pool: pool.clone() };
    install.commit(&applets).await.unwrap();
    let record = applets
        .get(
            id.as_str(),
            install.input.package.service_id.as_str(),
            &coland_storage::applet_effective_scope_key(&install.effective_scope).unwrap(),
        )
        .await
        .unwrap()
        .unwrap();
    let package: AppletPackage = serde_json::from_value(record["package"].clone()).unwrap();
    let service_actor = ActorId::service(package.service_id.clone());
    let grant = |action: &str| -> arkret_wire::GrantId {
        let event: Event = serde_json::from_value(
            record["capability_grant_events"]
                .as_array()
                .unwrap()
                .iter()
                .find(|event| {
                    event["payload"]["grant"]["actions"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .any(|value| value == action)
                })
                .unwrap()
                .clone(),
        )
        .unwrap();
        arkret_wire::GrantId::from_event_id(&event.event_id)
    };
    let sign =
        |kind: EventKind, payload: Value, action: &str, refs: Vec<arkret_wire::SemanticRef>| {
            let mut event =
                factory
                    .fixture
                    .admin_event(kind, install.effective_scope.clone(), payload);
            event.executed_by = Some(service_actor.clone());
            event.applet_id = Some(id.clone());
            event.authorization_ref =
                Some(arkret_wire::AuthorizationRef::new(grant(action).to_string()).unwrap());
            event.semantic_refs = refs;
            event.producer_proof = None;
            let signer = arkret_test_kit::seeded_signer_for_seed(
                applet_service_signing_key(&package.webhook_auth.key_ref).to_bytes(),
                applet_service_did(&package),
                package.webhook_auth.key_ref.clone(),
            );
            arkret_test_kit::sign_verifiable_event(
                event,
                &signer,
                arkret_canonical::DigestSuite::Sha256,
            )
            .unwrap()
            .expect_verifiable()
        };
    let accountable = ActorId::account(factory.fixture.pcr.history.account.clone());
    let permission = factory.fixture.admin_event(EventKind::CapabilityGrant, install.effective_scope.clone(), json!({"grant":{
        "schema":"ak.schema.capability.v1","realm_id":factory.fixture.realm,"issuer_id":accountable,"subject":accountable,
        "actions":["ak.strand.watch.set.others","ak.audit.accessed"],"resources":[{"kind":"realm","realm_id":factory.fixture.realm,"match_scope":"realm_wide"}],"constraints":[],
        "issuer_authority_refs":[{"kind":"realm_root","realm_id":factory.fixture.realm,"authority_event_ref":factory.fixture.authority_event_ref,"authority_generation":0}],
        "issued_at":arkret_canonical::format_timestamp_canonical(chrono::Utc::now())}}));
    accepted_admin_domain_event(&factory.fixture, permission).await;
    let mut strand = factory.fixture.admin_event(EventKind::StrandCreate, install.effective_scope.clone(), json!({"object":{
        "schema":"ak.schema.strand.v1","realm_id":factory.fixture.realm,"tracks":{"discussion":{"is_primary":true,"profile":"discussion"}},
        "metadata":{"title":"Service Watch target"},"state":"active","created_by":accountable,
        "created_at":arkret_canonical::format_timestamp_canonical(chrono::Utc::now())}}));
    strand.payload.get_mut("object").unwrap()["created_at"] = json!(
        arkret_canonical::format_timestamp_canonical(strand.created_at)
    );
    strand = factory.fixture.sign_admin(strand);
    let strand_id = arkret_wire::StrandId::from_event_id(&strand.event_id);
    accepted_admin_domain_event(&factory.fixture, strand).await;
    let target = ActorId::account(arkret_wire::AccountId::new(
        "ak:did_core:web:service-watch-target.example"
            .parse()
            .unwrap(),
        factory.fixture.state.service_core_id(),
    ));
    let business = sign(
        EventKind::StrandWatchSet,
        json!({"strand_id":strand_id,"watcher_actor_id":target,"level":"all"}),
        "ak.strand.watch.set.others",
        vec![],
    );
    let audit = sign(
        EventKind::AuditAccessed,
        json!({"access_kind":"watch_set_others","writer_actor_id":accountable,
        "target_actor_id":target,"target_ref":strand_id,"paired_event_id":business.event_id,"purpose":"Service producer admission",
        "accessed_at":arkret_canonical::format_timestamp_canonical(chrono::Utc::now())}),
        "ak.audit.accessed",
        vec![arkret_wire::SemanticRef {
            role: "audit_pair".into(),
            id: business.event_id.to_string(),
            critical: true,
        }],
    );
    let request =
        PeerAuthoritySubmitRequest::AuthorityForwardAtomic(PeerAuthorityForwardAtomicRequest {
            branch: AuthorityForwardBranch::AuthorityForward,
            atomic_submission: AuditPairedEventUnitSubmission {
                unit_kind: AuditPairedEventUnitKind::AuditPairedEvent,
                events: [
                    arkret_wire::EventAdmissionSubmission::new(business),
                    arkret_wire::EventAdmissionSubmission::new(audit),
                ],
            },
            atomic_producer_evidence: [
                AtomicSlotProducerEvidence::Service {},
                AtomicSlotProducerEvidence::Service {},
            ],
        });
    request.validate().unwrap();
    // The Account's permission cannot substitute for the Service's exact
    // signed authorization_ref, even if the Service owns another good grant.
    let mut wrong = request.clone();
    let PeerAuthoritySubmitRequest::AuthorityForwardAtomic(wrong_unit) = &mut wrong else {
        unreachable!()
    };
    wrong_unit.atomic_submission.events[0]
        .event
        .authorization_ref =
        Some(arkret_wire::AuthorizationRef::new(grant("ak.audit.accessed").to_string()).unwrap());
    let signer = arkret_test_kit::seeded_signer_for_seed(
        applet_service_signing_key(&package.webhook_auth.key_ref).to_bytes(),
        applet_service_did(&package),
        package.webhook_auth.key_ref.clone(),
    );
    let mut wrong_business = wrong_unit.atomic_submission.events[0].event.clone();
    wrong_business.producer_proof = None;
    let wrong_business = arkret_test_kit::sign_verifiable_event(
        wrong_business,
        &signer,
        arkret_canonical::DigestSuite::Sha256,
    )
    .unwrap()
    .expect_verifiable();
    let mut wrong_audit = wrong_unit.atomic_submission.events[1].event.clone();
    wrong_audit.producer_proof = None;
    wrong_audit
        .payload
        .insert("paired_event_id".into(), json!(wrong_business.event_id));
    wrong_audit.semantic_refs = vec![arkret_wire::SemanticRef {
        role: "audit_pair".into(),
        id: wrong_business.event_id.to_string(),
        critical: true,
    }];
    let wrong_audit = arkret_test_kit::sign_verifiable_event(
        wrong_audit,
        &signer,
        arkret_canonical::DigestSuite::Sha256,
    )
    .unwrap()
    .expect_verifiable();
    wrong_unit.atomic_submission.events = [
        arkret_wire::EventAdmissionSubmission::new(wrong_business.clone()),
        arkret_wire::EventAdmissionSubmission::new(wrong_audit.clone()),
    ];
    wrong.validate().unwrap();
    let source_before = PgAuthorityCommitStore { pool: pool.clone() };
    let stream = arkret_wire::CommitStreamRef::Realm {
        realm_id: factory.fixture.realm.clone(),
    };
    let head = source_before.stream_head(&stream).await.unwrap();
    let (status, refusal) = factory
        .fixture
        .service_post(
            &package,
            "/_arkret/peer/events",
            arkret_wire::ServiceOperationId::PEER_EVENTS_COMMAND_SUBMIT_V1,
            &serde_json::to_value(&wrong).unwrap(),
            "registered-service-wrong-ref",
        )
        .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "wrong Service authorization_ref: {refusal}"
    );
    assert_eq!(source_before.stream_head(&stream).await.unwrap(), head);
    for event in [wrong_business, wrong_audit] {
        assert!(
            source_before
                .committed_event(&event.event_id)
                .await
                .unwrap()
                .is_none()
        );
    }
    let body = serde_json::to_value(&request).unwrap();
    let (status, value) = factory
        .fixture
        .service_post(
            &package,
            "/_arkret/peer/events",
            arkret_wire::ServiceOperationId::PEER_EVENTS_COMMAND_SUBMIT_V1,
            &body,
            "registered-service-pair",
        )
        .await;
    assert_eq!(status, StatusCode::OK, "Service pair: {value}");
    let outcome: PeerAuthoritySubmitOutcome = serde_json::from_value(value).unwrap();
    outcome.validate_for_request(&request).unwrap();
    let PeerAuthoritySubmitOutcome::AuthorityForward(outcome) = outcome else {
        panic!("forward outcome")
    };
    let PeerAuthorityForwardOutcomeValue::AuditPairedEvent(outcome) = outcome.outcome else {
        panic!("pair outcome")
    };
    let source = PgAuthorityCommitStore { pool };
    for commit in &outcome.commits {
        let full = source
            .committed_event(&commit.event_ref)
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(
            source
                .producer_signer_fact(&full.event, commit)
                .await
                .unwrap(),
            Some(HistoricalProducerSignerFact::Service(_))
        ));
    }
    let scan = arkret_wire::StreamScanRequest {
        realm_id: factory.fixture.realm.clone(),
        stream_ref: stream.clone(),
        direction: arkret_wire::StreamScanDirection::Before(Some(
            outcome.commits.last().unwrap().stream_position + 1,
        )),
        limit: 2,
    };
    let coland_storage::PeerStreamScan::Page(page) = source
        .scan_stream_for_peer(
            &scan,
            &factory.fixture.state.service_core_id(),
            &factory.fixture.state.service_core_id(),
        )
        .await
        .unwrap()
    else {
        panic!("the member-hosting Station must receive its Service-produced tail");
    };
    page.validate_for_request(&scan).unwrap();
    assert_eq!(page.committed_events.len(), 2);
    assert!(
        !page.producer_signer_facts.is_empty(),
        "the positive scan must disclose an actual Service Full row"
    );
    for entry in &page.producer_signer_facts {
        assert!(matches!(
            entry.producer_signer_fact,
            HistoricalProducerSignerFact::Service(_)
        ));
        assert!(
            outcome
                .commits
                .iter()
                .any(|commit| commit.commit_id == entry.target.commit_id
                    && commit.event_ref == entry.target.event_id
                    && commit.stream_ref == entry.target.stream_ref
                    && commit.stream_position == entry.target.stream_position)
        );
    }
    eprintln!(
        "[2133-service-scan] signed_service_pair=1 peer_tail_rows=2 exact_service_facts={}",
        page.producer_signer_facts.len()
    );
    let PeerAuthoritySubmitRequest::AuthorityForwardAtomic(peer) = &request else {
        unreachable!()
    };
    let self_request = SelfAuthoritySubmitRequest::AuditPairedEvent(peer.atomic_submission.clone());
    let (status, self_replay) = factory
        .fixture
        .admin_post(
            "/_arkret/self/events",
            arkret_wire::ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT_V1,
            &serde_json::to_value(&self_request).unwrap(),
            None,
        )
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "Service self exact recovery: {self_replay}"
    );
    let self_replay: SelfAuthoritySubmitOutcome = serde_json::from_value(self_replay).unwrap();
    self_replay.validate_for_request(&self_request).unwrap();
    let self_business = sign(
        EventKind::StrandWatchSet,
        json!({"strand_id":strand_id,"watcher_actor_id":target,"level":"participating","expected_value":{"level":"all"}}),
        "ak.strand.watch.set.others",
        vec![],
    );
    let self_audit = sign(
        EventKind::AuditAccessed,
        json!({"access_kind":"watch_set_others","writer_actor_id":accountable,
        "target_actor_id":target,"target_ref":strand_id,"paired_event_id":self_business.event_id,"purpose":"Service original through authenticated self",
        "accessed_at":arkret_canonical::format_timestamp_canonical(chrono::Utc::now())}),
        "ak.audit.accessed",
        vec![arkret_wire::SemanticRef {
            role: "audit_pair".into(),
            id: self_business.event_id.to_string(),
            critical: true,
        }],
    );
    let self_first = SelfAuthoritySubmitRequest::AuditPairedEvent(AuditPairedEventUnitSubmission {
        unit_kind: AuditPairedEventUnitKind::AuditPairedEvent,
        events: [
            arkret_wire::EventAdmissionSubmission::new(self_business),
            arkret_wire::EventAdmissionSubmission::new(self_audit),
        ],
    });
    self_first.validate().unwrap();
    let (status, value) = factory
        .fixture
        .admin_post(
            "/_arkret/self/events",
            arkret_wire::ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT_V1,
            &serde_json::to_value(&self_first).unwrap(),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "Service first self pair: {value}");
    let value: SelfAuthoritySubmitOutcome = serde_json::from_value(value).unwrap();
    value.validate_for_request(&self_first).unwrap();
    let (status, replay) = factory
        .fixture
        .service_post(
            &package,
            "/_arkret/peer/events",
            arkret_wire::ServiceOperationId::PEER_EVENTS_COMMAND_SUBMIT_V1,
            &body,
            "registered-service-pair-retry",
        )
        .await;
    assert_eq!(status, StatusCode::OK, "Service exact replay: {replay}");
    let replay: PeerAuthoritySubmitOutcome = serde_json::from_value(replay).unwrap();
    replay.validate_for_request(&request).unwrap();
}

mod realm_native_fixture {
    include!("applet_configuration_fixture.rs");
    include!("realm_bot_consumer_fixture.rs");
    include!("realm_actor_transport_fixture.rs");
    include!("realm_actor_queue_boundary_fixture.rs");
    include!("realm_actor_runtime_recovery_fixture.rs");
    include!("realm_actor_read_boundary_fixture.rs");
    include!("realm_actor_completion_fixture.rs");
    include!("realm_manager_runtime_fixture.rs");
    include!("realm_actor_install_admission_fixture.rs");
    include!("realm_actor_authority_admission_fixture.rs");
    include!("realm_actor_revoke_boundary_fixture.rs");
    include!("realm_actor_review_fixture.rs");
    use arkret_canonical::canonical_sha256;
    use arkret_models_identity::*;
    use arkret_signatures::detached_object::sign_detached_object;
    use arkret_signatures::webvh::{RealmActorInceptionInput, prepare_realm_actor_inception};
    use arkret_wire::{
        CommitStreamRef, CommittedEventRef, CurrentRevision, DetachedSignatureContext, DidUrl,
        project_did_to_core_id,
    };

    use super::*;

    /// The native test runner issues one loopback certificate chain and one
    /// client trust store for this process. Every real fixture listener and
    /// explicit client must use that same authority as production DID egress.
    pub(super) struct NativeTlsMaterial {
        chain: Vec<u8>,
        key: Vec<u8>,
        pub(super) ca: Vec<u8>,
    }

    pub(super) fn native_tls_material() -> NativeTlsMaterial {
        let read = |name: &str| {
            let path = std::env::var_os(name).unwrap_or_else(|| {
                panic!("{name} is required; run via cotest/scripts/run-native-rust-tests.py")
            });
            std::fs::read(&path).unwrap_or_else(|error| {
                panic!("unable to read native fixture {name} at {path:?}: {error}")
            })
        };
        let ca = read("COTEST_RUN_SCOPED_CA_PEM");
        assert_eq!(
            read("SSL_CERT_FILE"),
            ca,
            "native fixture and production DID egress must trust the same run-scoped CA"
        );
        NativeTlsMaterial {
            chain: read("COLAND_TLS_CERT_PATH"),
            key: read("COLAND_TLS_KEY_PATH"),
            ca,
        }
    }

    pub(super) fn native_http_client(timeout: std::time::Duration) -> reqwest::Client {
        reqwest::Client::builder()
            .tls_backend_rustls()
            .tls_certs_only(
                reqwest::Certificate::from_pem_bundle(&native_tls_material().ca).unwrap(),
            )
            .timeout(timeout)
            .build()
            .unwrap()
    }

    struct ConfigurationResponseFault {
        completed: tokio::sync::oneshot::Sender<Value>,
        release: Option<std::sync::mpsc::Receiver<()>>,
    }

    pub(super) struct NativeService {
        pub(super) package: AppletPackage,
        service_resolution: Arc<Mutex<arkret_models_identity::AuthenticatedServiceResolution>>,
        actor_log: Arc<Mutex<Vec<Value>>>,
        managed_router: Arc<Mutex<Option<Arc<salvo::Service>>>>,
        principal_router: Arc<Mutex<Option<Arc<salvo::Service>>>>,
        unavailable_principals: Arc<Mutex<std::collections::BTreeSet<String>>>,
        configuration_response_fault: Arc<Mutex<Option<ConfigurationResponseFault>>>,
        completion_handler: Arc<Mutex<Option<CompletionHandler>>>,
        stop: Arc<std::sync::atomic::AtomicBool>,
        thread: Option<std::thread::JoinHandle<()>>,
    }
    type CompletionHandler = Arc<dyn Fn(Vec<u8>) -> (StatusCode, Value) + Send + Sync>;
    impl Drop for NativeService {
        fn drop(&mut self) {
            self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
            if let Some(thread) = self.thread.take() {
                thread.join().unwrap();
            }
        }
    }
    impl NativeService {
        pub(super) fn new(applet: &AppletId, station: &arkret_wire::DidCoreId) -> Self {
            use std::io::{Read as _, Write as _};

            use rustls::pki_types::pem::PemObject as _;
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            listener.set_nonblocking(true).unwrap();
            let authority = listener.local_addr().unwrap().to_string();
            let endpoint = format!("https://{authority}/");
            let native = fixture_applet_service_inception(&authority);
            let did = Did::new(native.did.clone()).unwrap();
            let namespace = format!("realm-native-{}", safe_did_token(applet.as_str()));
            let mut package =
                signed_applet_package(applet.as_str(), &namespace, station, Some(&endpoint));
            package.service_id = project_did_to_core_id(&did).unwrap();
            package.webhook_auth.key_ref = DidUrl::new(native.did_key_id.clone()).unwrap();

            let method = package.proof.as_ref().unwrap().verification_method.clone();
            let evidence = applet_registration_epoch_evidence(&package);
            package.stamp_registration_epoch(&evidence).unwrap();
            package.stamp_package_digest().unwrap();
            let controller = arkret_identity::verification_method_did(method.as_str()).unwrap();
            let signer =
                Ed25519PayloadSigner::from_did_key_seed([13; 32], controller, method.clone());
            package.sign(&signer, &method).unwrap();
            let material = native_tls_material();
            let tls = Arc::new(
                rustls::ServerConfig::builder_with_provider(Arc::new(
                    rustls::crypto::ring::default_provider(),
                ))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(
                    rustls::pki_types::CertificateDer::pem_slice_iter(&material.chain)
                        .collect::<std::result::Result<Vec<_>, _>>()
                        .expect("native fixture certificate chain PEM"),
                    rustls::pki_types::PrivateKeyDer::from_pem_slice(&material.key)
                        .expect("native fixture private key PEM"),
                )
                .unwrap(),
            );
            let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let stopping = stop.clone();
            let actor_log = Arc::new(Mutex::new(Vec::<Value>::new()));
            let published_actor = actor_log.clone();
            let managed_router = Arc::new(Mutex::new(None::<Arc<salvo::Service>>));
            let served_router = managed_router.clone();
            let principal_router = Arc::new(Mutex::new(None::<Arc<salvo::Service>>));
            let served_principal = principal_router.clone();
            let unavailable_principals =
                Arc::new(Mutex::new(std::collections::BTreeSet::<String>::new()));
            let unavailable_resources = unavailable_principals.clone();
            let configuration_response_fault =
                Arc::new(Mutex::new(None::<ConfigurationResponseFault>));
            let response_fault = configuration_response_fault.clone();
            let completion_handler = Arc::new(Mutex::new(None::<CompletionHandler>));
            let served_completion = completion_handler.clone();
            let service_resolution = Arc::new(Mutex::new(fixture_applet_service_history(&package)));
            let served_service_resolution = service_resolution.clone();
            let resolution_path =
                arkret_models_identity::canonical_service_resolution_path(&package.service_id);
            let runtime = tokio::runtime::Handle::current();
            let thread = std::thread::spawn(move || {
                let mut connections = Vec::new();
                while !stopping.load(std::sync::atomic::Ordering::Relaxed) {
                    let stream = match listener.accept() {
                        Ok((stream, _)) => stream,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            std::thread::sleep(std::time::Duration::from_millis(10));
                            continue;
                        }
                        Err(error) => panic!("native service listener: {error}"),
                    };
                    let tls = tls.clone();
                    let entry = native.log_entry.clone();
                    let published_actor = published_actor.clone();
                    let served_router = served_router.clone();
                    let served_principal = served_principal.clone();
                    let unavailable_resources = unavailable_resources.clone();
                    let response_fault = response_fault.clone();
                    let served_completion = served_completion.clone();
                    let service_resolution = served_service_resolution.clone();
                    let resolution_path = resolution_path.clone();
                    let runtime = runtime.clone();
                    let endpoint = endpoint.clone();
                    connections.push(std::thread::spawn(move || {
                        stream.set_nonblocking(false).unwrap();
                        stream.set_read_timeout(Some(std::time::Duration::from_secs(5))).unwrap();
                        stream.set_write_timeout(Some(std::time::Duration::from_secs(5))).unwrap();
                        let mut stream=rustls::StreamOwned::new(rustls::ServerConnection::new(tls).unwrap(),stream);
                        let mut bytes=Vec::new(); let mut buffer=[0;4096];
                        while !bytes.windows(4).any(|v|v==b"\r\n\r\n") {
                            let count=stream.read(&mut buffer).unwrap_or(0); if count==0{return;} bytes.extend_from_slice(&buffer[..count]);
                        }
                        let header_end=bytes.windows(4).position(|v|v==b"\r\n\r\n").unwrap()+4;
                        let request=String::from_utf8(bytes[..header_end].to_vec()).unwrap();
                        let mut first=request.lines().next().unwrap().split_whitespace();
                        let method=first.next().unwrap();
                        let path=first.next().unwrap();
                        if unavailable_resources.lock().unwrap().iter().any(|prefix| path.starts_with(prefix)) {
                            stream.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").unwrap();
                            stream.flush().unwrap();
                            return;
                        }
                        let completion=served_completion.lock().unwrap().clone();
                        if method == "POST" && path == "/_arkret/edge/applet/transactions" && let Some(completion) = completion {
                            let length=request.lines().skip(1).filter_map(|line|line.split_once(':'))
                                .find(|(name,_)|name.eq_ignore_ascii_case("content-length"))
                                .map(|(_,value)|value.trim().parse::<usize>().unwrap()).unwrap();
                            assert!(length<=4_194_304);
                            while bytes.len()<header_end+length {
                                let count=stream.read(&mut buffer).unwrap();assert!(count>0);bytes.extend_from_slice(&buffer[..count]);
                            }
                            bytes.truncate(header_end+length);
                            let (status,body)=completion(bytes);
                            let body=arkret_canonical::canonical_json_bytes(&body).unwrap();
                            let header=format!("HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",status.as_u16(),status.canonical_reason().unwrap_or("Result"),body.len());
                            stream.write_all(header.as_bytes()).unwrap();stream.write_all(&body).unwrap();stream.flush().unwrap();
                            return;
                        }
                        if method == "GET" && path == resolution_path && served_router.lock().unwrap().is_none() {
                            let body = arkret_canonical::canonical_json_bytes(&*service_resolution.lock().unwrap()).unwrap();
                            let header = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
                            let _ = stream.write_all(header.as_bytes());
                            let _ = stream.write_all(&body);
                            let _ = stream.flush();
                            return;
                        }
                        let router = if path.starts_with("/webvh/") {
                            served_principal.lock().unwrap().clone().or_else(|| served_router.lock().unwrap().clone())
                        } else { served_router.lock().unwrap().clone() };
                        // Service identity hosting is independent of the managed principal router.
                        // Replacing the Applet backend must not intercept its native Service DID.
                        if let Some(router)=router.filter(|_| path.starts_with("/_arkret/") || (path.starts_with("/webvh/") && !path.starts_with("/webvh/service/"))) {
                            let headers=request.lines().skip(1).filter_map(|line|line.split_once(':'))
                                .map(|(name,value)|(name.to_owned(),value.trim().to_owned())).collect::<Vec<_>>();
                            let length=headers.iter().find(|(name,_)|name.eq_ignore_ascii_case("content-length"))
                                .map(|(_,value)|value.parse::<usize>().unwrap()).unwrap_or(0);
                            assert!(length<=262144);
                            while bytes.len()<header_end+length {
                                let count=stream.read(&mut buffer).unwrap();
                                assert!(count>0);bytes.extend_from_slice(&buffer[..count]);
                            }
                            let url=format!("{}{path}",endpoint.trim_end_matches('/'));
                            let mut forwarded=if method=="POST" {TestClient::post(url)} else {TestClient::get(url)};
                            for (name,value) in headers { forwarded=forwarded.add_header(salvo::http::header::HeaderName::from_bytes(name.as_bytes()).unwrap(),value,true); }
                            forwarded=forwarded.body(bytes[header_end..header_end+length].to_vec());
                            let (status,body,content_type)=runtime.block_on(async {
                                let mut response=forwarded.send(router.as_ref()).await;
                                let content_type=response.headers().get(salvo::http::header::CONTENT_TYPE)
                                    .map(|value|value.to_str().unwrap().to_owned()).unwrap_or_else(||"application/json".into());
                                (response.status_code.unwrap_or(StatusCode::OK), response.take_bytes(None).await.unwrap(),content_type)
                            });
                            if path == "/_arkret/edge/applet/configuration" && status.is_success() {
                                let fault = response_fault.lock().unwrap().take();
                                if let Some(fault) = fault {
                                    let _ = fault.completed.send(serde_json::from_slice(&body).unwrap());
                                    match fault.release {
                                        Some(release) => {
                                            if release.recv_timeout(std::time::Duration::from_secs(30)).is_err() { return; }
                                        }
                                        None => return,
                                    }
                                }
                            }
                            let header=format!("HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",status.as_u16(),status.canonical_reason().unwrap_or("Result"),content_type,body.len());
                            let _=stream.write_all(header.as_bytes());let _=stream.write_all(&body);let _=stream.flush();
                            return;
                        }
                        let entries = if path.contains("/webvh/") && !path.contains("/service/") { published_actor.lock().unwrap().clone() } else {
                            let resolution=service_resolution.lock().unwrap();
                            match &resolution.method_history_evidence {
                                ResolutionMethodHistoryEvidence::WebvhLog { log_entries, .. } => log_entries.clone(),
                                _ => vec![entry],
                            }
                        };
                        let body=if path.ends_with("did.jsonl") {entries.iter().map(|entry|serde_json::to_string(entry).unwrap()+"\n").collect::<String>()}
                            else if path.ends_with("did.json") {entries.last().map(|entry|serde_json::to_string(&entry["state"]).unwrap()).unwrap_or_default()}
                            else {String::new()};
                        let status=if body.is_empty(){"404 Not Found"}else{"200 OK"};
                        let header=format!("HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",body.len());
                        let _=stream.write_all(header.as_bytes()); let _=stream.write_all(body.as_bytes()); let _=stream.flush();
                    }));
                }
                for connection in connections {
                    connection.join().unwrap();
                }
            });
            Self {
                package,
                service_resolution,
                actor_log,
                managed_router,
                principal_router,
                unavailable_principals,
                configuration_response_fault,
                completion_handler,
                stop,
                thread: Some(thread),
            }
        }
    }

    async fn control_post(
        fixture: &Fixture,
        metadata: &RealmActorControlHttpMetadata,
        method: &DidUrl,
        path: &str,
        operation: arkret_wire::ServiceOperationId,
        body: &Value,
    ) -> (StatusCode, Value) {
        Box::pin(control_post_with_seed(
            fixture, metadata, method, path, operation, body, &[33; 32],
        ))
        .await
    }
    async fn control_post_with_seed(
        fixture: &Fixture,
        metadata: &RealmActorControlHttpMetadata,
        method: &DidUrl,
        path: &str,
        operation: arkret_wire::ServiceOperationId,
        body: &Value,
        seed: &[u8; 32],
    ) -> (StatusCode, Value) {
        let bytes = arkret_canonical::canonical_json_bytes(body).unwrap();
        let digest = content_digest_header(&bytes);
        let metadata = metadata.to_header_value().unwrap();
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
                ("arkret-operation".into(), operation.as_str().into()),
                ("content-type".into(), "application/json".into()),
                ("content-digest".into(), digest.clone()),
                (
                    "destination-service-id".into(),
                    fixture.state.service_id().into(),
                ),
                ("arkret-realm-actor-control".into(), metadata),
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
            &SigningKey::from_bytes(seed),
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

    pub(super) async fn managed_device_post(
        fixture: &Fixture,
        metadata: &arkret_models_integration::AppletManagedDeviceMetadata,
        method: &DidUrl,
        path: &str,
        operation: arkret_wire::ServiceOperationId,
        body: &Value,
        seed: &[u8; 32],
    ) -> (StatusCode, Value) {
        Box::pin(managed_device_post_with_fault(
            fixture, metadata, method, path, operation, body, seed, None,
        ))
        .await
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "The fixture keeps independent signed originals, accepted references and source-time coordinates explicit."
    )]
    async fn managed_device_post_with_fault(
        fixture: &Fixture,
        metadata: &arkret_models_integration::AppletManagedDeviceMetadata,
        method: &DidUrl,
        path: &str,
        operation: arkret_wire::ServiceOperationId,
        body: &Value,
        seed: &[u8; 32],
        fault: Option<&str>,
    ) -> (StatusCode, Value) {
        let mut bytes = arkret_canonical::canonical_json_bytes(body).unwrap();
        let digest = content_digest_header(&bytes);
        let metadata = metadata.to_header_value().unwrap();
        let idempotency = body
            .get("claim_request_id")
            .or_else(|| body.get("idempotency_key"))
            .and_then(Value::as_str)
            .map(str::to_owned)
            .unwrap_or_else(|| uuid::Uuid::now_v7().to_string());
        let request_url = format!(
            "{}{path}",
            fixture.state.config().public_base_url.trim_end_matches('/')
        );
        let target = url::Url::parse(&request_url).unwrap();
        let parts = SignedRequestParts {
            method: "POST".into(),
            target_uri: request_url.clone(),
            authority: target[url::Position::BeforeHost..url::Position::AfterPort].into(),
            path: path.into(),
            headers: vec![
                ("arkret-operation".into(), operation.as_str().into()),
                ("content-type".into(), "application/json".into()),
                ("content-digest".into(), digest.clone()),
                (
                    "destination-service-id".into(),
                    fixture.state.service_id().into(),
                ),
                ("arkret-managed-device".into(), metadata),
                ("idempotency-key".into(), idempotency),
            ],
            body_digest: Some(digest),
        };
        let signature = sign_http_message_for_scenario(
            &parts,
            HttpSignatureScenario::AppletManagedDeviceV1,
            &["content-digest", "idempotency-key"],
            "sig1",
            method.as_str(),
            chrono::Utc::now().timestamp()
                - if fault == Some("expired_signature") {
                    601
                } else {
                    0
                },
            &SigningKey::from_bytes(if fault == Some("wrong_signature") {
                &[81; 32]
            } else {
                seed
            }),
        )
        .unwrap();
        let client = reqwest::Client::builder()
            .tls_backend_rustls()
            .tls_certs_only(
                reqwest::Certificate::from_pem_bundle(&native_tls_material().ca).unwrap(),
            )
            .build()
            .unwrap();
        let mut request = client.post(request_url);
        for (name, mut value) in parts.headers {
            if fault == Some("wrong_destination") && name == "destination-service-id" {
                value = "ak:did_core:web:another-station.example".to_owned();
            }
            request = request.header(name, value);
        }
        if fault == Some("changed_body") {
            let mut changed = body.clone();
            changed["unsigned_transport_field"] = json!(true);
            bytes = arkret_canonical::canonical_json_bytes(&changed).unwrap();
        }
        if fault == Some("mixed_credentials") {
            request = request.header("authorization", "Bearer unrelated-session");
        }
        let response = request
            .header("signature-input", signature.signature_input_header)
            .header("signature", signature.signature_header)
            .body(bytes)
            .send()
            .await
            .unwrap();
        let status = StatusCode::from_u16(response.status().as_u16()).unwrap();
        (status, response.json().await.unwrap())
    }

    async fn peer_audit_post(
        source: &Fixture,
        destination: &Fixture,
        body: &arkret_models_integration::PeerRealmActorMaterialRequest,
        tamper: bool,
    ) -> (StatusCode, Value) {
        let bytes = arkret_canonical::canonical_json_bytes(body).unwrap();
        let digest = content_digest_header(&bytes);
        let path = "/_arkret/peer/realm-actors/material";
        let request_url = format!(
            "{}{path}",
            destination
                .state
                .config()
                .public_base_url
                .trim_end_matches('/')
        );
        let target = url::Url::parse(&request_url).unwrap();
        let parts = SignedRequestParts {
            method: "POST".into(),
            target_uri: request_url.clone(),
            authority: target[url::Position::BeforeHost..url::Position::AfterPort].into(),
            path: path.into(),
            headers: vec![
                (
                    "arkret-operation".into(),
                    arkret_wire::ServiceOperationId::PEER_REALM_ACTOR_READ_MATERIAL_V1.into(),
                ),
                ("content-type".into(), "application/json".into()),
                ("content-digest".into(), digest.clone()),
                ("source-service-id".into(), source.state.service_id().into()),
                (
                    "destination-service-id".into(),
                    destination.state.service_id().into(),
                ),
                (
                    "source-trust-domain".into(),
                    source.state.config().trust_domain.to_string(),
                ),
                (
                    "destination-trust-domain".into(),
                    destination.state.config().trust_domain.to_string(),
                ),
            ],
            body_digest: Some(digest),
        };
        let signature = sign_http_message_for_scenario(
            &parts,
            HttpSignatureScenario::ServiceToServiceV1,
            &[
                "content-digest",
                "source-trust-domain",
                "destination-trust-domain",
            ],
            "sig1",
            source
                .state
                .service_verification_method("notary-key")
                .unwrap()
                .as_str(),
            chrono::Utc::now().timestamp(),
            source.state.notary_signing_key().as_ref(),
        )
        .unwrap();
        let mut request = TestClient::post(request_url);
        for (name, value) in parts.headers {
            request = request.add_header(
                salvo::http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                value,
                true,
            );
        }
        let bytes = if tamper {
            let mut changed = body.clone();
            changed.requester_account_id = destination.pcr.history.account.clone();
            arkret_canonical::canonical_json_bytes(&changed).unwrap()
        } else {
            bytes
        };
        let mut response = request
            .add_header("signature-input", signature.signature_input_header, true)
            .add_header("signature", signature.signature_header, true)
            .body(bytes)
            .send(&service(destination.state.clone()))
            .await;
        (
            response.status_code.unwrap(),
            response.take_json().await.unwrap(),
        )
    }

    async fn peer_keys_post(
        source: &Fixture,
        destination: &Fixture,
        body: &arkret_models_crypto::PeerKeysQueryRequestBody,
    ) -> (StatusCode, Value) {
        let bytes = arkret_canonical::canonical_json_bytes(body).unwrap();
        let digest = content_digest_header(&bytes);
        let path = "/_arkret/peer/keys/query";
        let request_url = format!(
            "{}{path}",
            destination
                .state
                .config()
                .public_base_url
                .trim_end_matches('/')
        );
        let target = url::Url::parse(&request_url).unwrap();
        let parts = SignedRequestParts {
            method: "POST".into(),
            target_uri: request_url.clone(),
            authority: target[url::Position::BeforeHost..url::Position::AfterPort].into(),
            path: path.into(),
            headers: vec![
                (
                    "arkret-operation".into(),
                    arkret_wire::ServiceOperationId::PEER_KEYS_READ_LOOKUP_V1.into(),
                ),
                ("content-type".into(), "application/json".into()),
                ("content-digest".into(), digest.clone()),
                ("source-service-id".into(), source.state.service_id().into()),
                (
                    "destination-service-id".into(),
                    destination.state.service_id().into(),
                ),
                (
                    "source-trust-domain".into(),
                    source.state.config().trust_domain.to_string(),
                ),
                (
                    "destination-trust-domain".into(),
                    destination.state.config().trust_domain.to_string(),
                ),
            ],
            body_digest: Some(digest),
        };
        let signature = sign_http_message_for_scenario(
            &parts,
            HttpSignatureScenario::ServiceToServiceV1,
            &[
                "content-digest",
                "source-trust-domain",
                "destination-trust-domain",
            ],
            "sig1",
            source
                .state
                .service_verification_method("notary-key")
                .unwrap()
                .as_str(),
            chrono::Utc::now().timestamp(),
            source.state.notary_signing_key().as_ref(),
        )
        .unwrap();
        let mut request = TestClient::post(request_url);
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
            .send(&service(destination.state.clone()))
            .await;
        (
            response.status_code.unwrap(),
            response.take_json().await.unwrap(),
        )
    }

    async fn private_material(
        fixture: &Fixture,
        candidate: &RealmActorCreatePayload,
        commit: &arkret_wire::RealmCommit,
    ) {
        let actor = &candidate.actor_id;
        let request: RealmActorMaterialRequest = serde_json::from_value(json!({
            "purpose":"current", "actor_id":actor,
            "request_nonce":arkret_canonical::base64url_encode(rand::random::<[u8;32]>()),
            "selectors":[
                {"kind":"realm_actor_control", "actor_id":actor},
                {"kind":"realm_actor_profile", "actor_id":actor}
            ]
        }))
        .unwrap();
        let metadata = RealmActorControlHttpMetadata {
            actor_id: actor.clone(),
            control_ref: arkret_wire::CommittedEventRef {
                event_id: commit.event_ref.clone(),
                commit_id: commit.commit_id.clone(),
                stream_ref: commit.stream_ref.clone(),
                stream_position: commit.stream_position,
            },
            nonce: arkret_canonical::base64url_encode(rand::random::<[u8; 32]>()),
        };
        let body = serde_json::to_value(&request).unwrap();
        let (status, response) = control_post(
            fixture,
            &metadata,
            &candidate.control_method_kid,
            "/_arkret/self/realm-actors/material",
            arkret_wire::ServiceOperationId::SelfRealmActorReadMaterialV1,
            &body,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "private material: {response}");
        let material: RealmActorMaterialOutcome = serde_json::from_value(response).unwrap();
        material
            .validate_for_request(&request, actor, chrono::Utc::now())
            .unwrap();
        let unsigned = arkret_canonical::unsigned_value(&material, &["signature"]).unwrap();
        let key = arkret_signatures::PublicKeyMaterial::Ed25519Multibase {
            value: arkret_canonical::ed25519_pubkey_to_did_key_multibase(
                fixture
                    .state
                    .notary_signing_key()
                    .verifying_key()
                    .as_bytes(),
            ),
        };
        arkret_signatures::detached_object::verify_detached_object_signature(
            &material.signature,
            &unsigned,
            DetachedSignatureContext::RealmActorMaterial,
            &key,
        )
        .unwrap();
        let RealmActorMaterialResult::Current { entries } = material.result else {
            panic!("current material required");
        };
        let RealmActorMaterialCurrentEntry::Present { source_ref, .. } = &entries[0] else {
            panic!("present private control required");
        };
        assert_eq!(source_ref, &metadata.control_ref);
        assert_eq!(source_ref.event_id, commit.event_ref);

        assert!(matches!(
            &entries[1],
            RealmActorMaterialCurrentEntry::NeverWritten { .. }
        ));
        let (status, _) = control_post(
            fixture,
            &metadata,
            &candidate.control_method_kid,
            "/_arkret/self/realm-actors/material",
            arkret_wire::ServiceOperationId::SelfRealmActorReadMaterialV1,
            &body,
        )
        .await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "control nonce must not be replayed"
        );
    }
    pub(super) async fn authorize_obligation_device(
        fixture: &Fixture,
        candidate: &RealmActorCreatePayload,
        creation_commit: &arkret_wire::RealmCommit,
        key_seed: u8,
        expires_at: chrono::DateTime<chrono::Utc>,
    ) -> arkret_wire::DeviceId {
        boxed_step(|| {
            authorize_device_until(
                fixture,
                candidate,
                creation_commit,
                key_seed,
                &[
                    "ak.applet.join",
                    "ak.event.read",
                    "ak.message.create",
                    "ak.mls.commit",
                    "ak.mls.genesis",
                ],
                Some(expires_at),
            )
        })
        .await
    }

    async fn first_device(
        fixture: &Fixture,
        candidate: &RealmActorCreatePayload,
        creation_commit: &arkret_wire::RealmCommit,
    ) -> arkret_wire::DeviceId {
        authorize_device(fixture, candidate, creation_commit, 79).await
    }

    async fn authorize_device(
        fixture: &Fixture,
        candidate: &RealmActorCreatePayload,
        creation_commit: &arkret_wire::RealmCommit,
        key_seed: u8,
    ) -> arkret_wire::DeviceId {
        Box::pin(authorize_device_with_actions(
            fixture,
            candidate,
            creation_commit,
            key_seed,
            &["ak.applet.join", "ak.message.create"],
        ))
        .await
    }

    async fn authorize_device_with_actions(
        fixture: &Fixture,
        candidate: &RealmActorCreatePayload,
        creation_commit: &arkret_wire::RealmCommit,
        key_seed: u8,
        actions: &[&str],
    ) -> arkret_wire::DeviceId {
        boxed_step(|| {
            authorize_device_until(fixture, candidate, creation_commit, key_seed, actions, None)
        })
        .await
    }

    async fn authorize_device_until(
        fixture: &Fixture,
        candidate: &RealmActorCreatePayload,
        creation_commit: &arkret_wire::RealmCommit,
        key_seed: u8,
        actions: &[&str],
        expires_at: Option<chrono::DateTime<chrono::Utc>>,
    ) -> arkret_wire::DeviceId {
        let scopes = serde_json::from_value(json!([{
            "effective_scope": candidate.creation_scope,
            "actions": actions,
        }]))
        .unwrap();
        boxed_step(|| {
            authorize_native_device_with_scopes(
                fixture,
                candidate,
                creation_commit,
                key_seed,
                &scopes,
                expires_at,
            )
        })
        .await
    }

    pub(super) async fn authorize_native_device_with_scopes(
        fixture: &Fixture,
        candidate: &RealmActorCreatePayload,
        creation_commit: &arkret_wire::RealmCommit,
        key_seed: u8,
        scopes: &arkret_models_collaboration::events_payloads::AppletManagedDeviceScopes,
        expires_at: Option<chrono::DateTime<chrono::Utc>>,
    ) -> arkret_wire::DeviceId {
        use arkret_models_collaboration::authority_commit::{
            SelfAuthoritySubmitOutcome, SelfAuthoritySubmitRequest,
        };
        use arkret_models_collaboration::events_payloads::DeviceAuthorizePayload;
        use ed25519_dalek::Signer as _;
        let head = fixture
            .state
            .test_persistence()
            .authority_commits()
            .stream_head(&creation_commit.stream_ref)
            .await
            .unwrap()
            .unwrap();
        let at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
        let expires_at = arkret_canonical::normalize_timestamp_canonical(
            expires_at.unwrap_or(at + chrono::Duration::hours(1)),
        );
        let key = SigningKey::from_bytes(&[key_seed; 32]);
        let mut hpke = vec![0xec, 0x01];
        hpke.extend([key_seed + 1; 32]);
        let mut payload: DeviceAuthorizePayload = serde_json::from_value(json!({
            "device_id":format!("ak:device:{}",uuid::Uuid::now_v7()),
            "device_public_key_did":format!("did:key:{}",arkret_canonical::ed25519_pubkey_to_did_key_multibase(key.verifying_key().as_bytes())),
            "hpke_key":arkret_canonical::encode_multibase_base58btc(hpke),
            "algorithms":["ak.hpke_x25519_aead_chacha20poly1305.v1"],
            "device_key_algorithm":"Ed25519",
            "authorized_by":candidate.actor_id.signing_principal_id(),
            "scopes":scopes,
            "not_before":arkret_canonical::format_timestamp_canonical(at),
            "expires_at":arkret_canonical::format_timestamp_canonical(expires_at),
            "authorization_binding_kind":"realm_managed_delegation", "authorized_generation_ref":1,
            "device_signature":"unsigned", "applet_id":candidate.applet_id,
            "expected_control_revision":{"commit_id":creation_commit.commit_id,"stream_position":creation_commit.stream_position},
            "expected_device_revision":null
        })).unwrap();
        let possession = payload
            .realm_device_possession_signature_input(&candidate.actor_id)
            .unwrap();
        payload.device_signature = serde_json::from_value(json!(
            arkret_canonical::base64url_encode(key.sign(&possession).to_bytes())
        ))
        .unwrap();
        let intent =
            arkret_event_draft::TypedEventDraft::<arkret_wire::event_spec::DeviceAuthorize>::new(
                ScopeRef::RealmControl {
                    realm_id: fixture.realm.clone(),
                },
                candidate.actor_id.clone(),
                payload.clone(),
            )
            .unwrap()
            .with_applet_id(candidate.applet_id.clone())
            .into_intent(at)
            .unwrap();
        let mut authored = intent
            .author_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
            .unwrap();
        let signer = Ed25519PayloadSigner::new(
            SigningKey::from_bytes(&[33; 32]),
            candidate.initial_resolution.did.clone(),
            candidate.control_method_kid.clone(),
        );
        arkret_signatures::sign_event(
            &mut authored,
            &signer,
            arkret_signatures::SignEventOptions::new().with_created_at(at),
        )
        .unwrap();
        let event = authored.into_event();
        serde_json::from_value::<Event>(json!(event)).expect("Device Event wire round trip");
        serde_json::from_value::<DeviceAuthorizePayload>(json!(payload))
            .expect("Device payload wire round trip");
        let request = SelfAuthoritySubmitRequest::Event(
            arkret_wire::EventAdmissionSubmission::new(event.clone()),
        );
        let metadata = RealmActorControlHttpMetadata {
            actor_id: candidate.actor_id.clone(),
            control_ref: arkret_wire::CommittedEventRef {
                event_id: creation_commit.event_ref.clone(),
                commit_id: creation_commit.commit_id.clone(),
                stream_ref: creation_commit.stream_ref.clone(),
                stream_position: creation_commit.stream_position,
            },
            nonce: arkret_canonical::base64url_encode(rand::random::<[u8; 32]>()),
        };
        if key_seed == 79 {
            boxed_step(|| {
                realm_device_wrong_possession_is_rejected(
                    fixture, candidate, &payload, &metadata, at,
                )
            })
            .await;
        }
        let mut metadata = metadata;
        metadata.nonce = arkret_canonical::base64url_encode(rand::random::<[u8; 32]>());
        let (status, response) = control_post(
            fixture,
            &metadata,
            &candidate.control_method_kid,
            "/_arkret/self/events",
            arkret_wire::ServiceOperationId::SelfEventsCommandSubmitV1,
            &json!(request),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "first Device: {response}");
        let outcome: SelfAuthoritySubmitOutcome = serde_json::from_value(response).unwrap();
        outcome.validate_for_request(&request).unwrap();
        let accepted = fixture
            .state
            .test_persistence()
            .authority_commits()
            .committed_event(&event.event_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(accepted.event, event);
        assert_eq!(accepted.commit.stream_position, head.stream_position + 1);
        assert_eq!(accepted.commit.previous_commit_ref, Some(head.commit_id));
        assert_eq!(accepted.commit.stream_ref, creation_commit.stream_ref);
        payload.device_id
    }

    async fn self_join(
        fixture: &Fixture,
        candidate: &RealmActorCreatePayload,
        device: &arkret_wire::DeviceId,
        installation: &Value,
    ) {
        use arkret_models_collaboration::authority_commit::{
            SelfAuthoritySubmitOutcome, SelfAuthoritySubmitRequest,
        };
        let authority = fixture
            .state
            .test_persistence()
            .device_revocations()
            .applet_managed_device_authority(&candidate.actor_id, device, chrono::Utc::now())
            .await
            .unwrap()
            .unwrap();
        let grant: Event = serde_json::from_value(
            installation["capability_grant_events"]
                .as_array()
                .unwrap()
                .iter()
                .find(|event| {
                    event["payload"]["grant"]["actions"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .any(|action| action == "ak.applet.join")
                })
                .unwrap()
                .clone(),
        )
        .unwrap();
        let at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
        let payload =
            serde_json::from_value(json!({"member_id":candidate.actor_id,"membership":"join"}))
                .unwrap();
        let intent =
            arkret_event_draft::TypedEventDraft::<arkret_wire::event_spec::MemberState>::new(
                candidate.creation_scope.clone(),
                candidate.actor_id.clone(),
                payload,
            )
            .unwrap()
            .with_applet_id(candidate.applet_id.clone())
            .with_authorization_ref(arkret_wire::GrantId::from_event_id(&grant.event_id).into())
            .into_intent(at)
            .unwrap();
        let mut authored = intent
            .author_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
            .unwrap();
        let signer = Ed25519PayloadSigner::new(
            SigningKey::from_bytes(&[79; 32]),
            authority.native_did.clone(),
            DidUrl::new(format!("{}#{}", authority.native_did, device)).unwrap(),
        );
        arkret_signatures::sign_event(
            &mut authored,
            &signer,
            arkret_signatures::SignEventOptions::new().with_created_at(at),
        )
        .unwrap();
        let event = authored.into_event();
        let request = SelfAuthoritySubmitRequest::Event(
            arkret_wire::EventAdmissionSubmission::new(event.clone()),
        );
        let metadata = arkret_models_integration::AppletManagedDeviceMetadata {
            actor_id: candidate.actor_id.clone(),
            device_id: device.clone(),
            authorization_event_id: authority.authorization_ref.event_id,
            applet_id: candidate.applet_id.clone(),
            effective_scope: candidate.creation_scope.clone(),
            nonce: arkret_canonical::base64url_encode(rand::random::<[u8; 32]>()),
        };
        let fingerprint =
            arkret_canonical::ed25519_pubkey_to_did_key_multibase(&authority.public_key);
        let (status, response) = managed_device_post(
            fixture,
            &metadata,
            &DidUrl::new(format!("did:key:{fingerprint}#{fingerprint}")).unwrap(),
            "/_arkret/self/events",
            arkret_wire::ServiceOperationId::SelfEventsCommandSubmitV1,
            &json!(request),
            &[79; 32],
        )
        .await;
        assert_eq!(status, StatusCode::OK, "Realm Device self join: {response}");
        let outcome: SelfAuthoritySubmitOutcome = serde_json::from_value(response).unwrap();
        outcome.validate_for_request(&request).unwrap();
        let accepted = fixture
            .state
            .test_persistence()
            .authority_commits()
            .committed_event(&event.event_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(accepted.event, event);
        boxed_step(|| {
            realm_device_transport_refusals(fixture, candidate, &metadata, &request, &accepted)
        })
        .await;
        let package: AppletPackage =
            serde_json::from_value(installation["package"].clone()).unwrap();
        boxed_step(|| retired_managed_forward_carrier_is_rejected(fixture, &package, &accepted))
            .await;
    }

    fn realm_candidate(
        package: &AppletPackage,
        realm: &RealmId,
        registration: &EventId,
        grant: &arkret_wire::GrantId,
    ) -> (RealmActorCreatePayload, Ed25519PayloadSigner) {
        let at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
        let endpoint = package.base_url.parse().unwrap();
        let root = rand::random::<[u8; 32]>();
        let next = SigningKey::from_bytes(&[32; 32]);
        let control = SigningKey::from_bytes(&[33; 32]);
        let next_key =
            arkret_canonical::ed25519_pubkey_to_did_key_multibase(next.verifying_key().as_bytes());
        let inception = prepare_realm_actor_inception(&RealmActorInceptionInput {
            principal_endpoint: &endpoint,
            local_id: "ghost-1",
            version_time: at,
            root_seed: &root,
            next_root_public_key_multibase: &next_key,
            controller_public_key: control.verifying_key().as_bytes(),
        })
        .unwrap();
        let document: DidDocument =
            serde_json::from_value(inception.log_entry["state"].clone()).unwrap();
        let head = canonical_sha256(&inception.log_entry).unwrap();
        let evidence = ResolutionMethodHistoryEvidence::WebvhLog {
            boundary: ResolutionMethodEvidenceBoundary {
                from_method_history_head: head.clone(),
                from_version_id: inception.version_id.clone(),
                to_method_history_head: head.clone(),
                to_version_id: inception.version_id.clone(),
            },
            evidence: ResolutionDidBindingEvidenceReceipt {
                kind: ResolutionDidBindingEvidenceKind::AkDidBindingEvidenceV1,
                method: "webvh".into(),
                document_digest: normalized_did_document_digest(&document).unwrap(),
                method_proofs: vec![ResolutionDidBindingMethodProof {
                    kind: ResolutionDidBindingMethodProofKind::WebvhLog,
                    history_head: head.clone(),
                    witnesses: vec![],
                    witness_proofs_digest: Hash::new(
                        canonical_sha256(&Vec::<serde_json::Value>::new()).unwrap(),
                    )
                    .unwrap(),
                }],
            },
            log_entries: vec![inception.log_entry],
            witness_records: vec![],
        };
        let service_did = applet_service_did(package);
        let service = package.service_id.clone();
        let signer = Ed25519PayloadSigner::new(
            applet_service_signing_key(&package.webhook_auth.key_ref),
            service_did,
            package.webhook_auth.key_ref.clone(),
        );
        let method = DidUrl::new(format!("{}#managed-controller", inception.did)).unwrap();
        let mut value = json!({
            "schema": RealmActorCreatePayload::SCHEMA,
            "actor_id": {"kind":"realm", "realm_actor_id": {"realm_id":realm,"principal_id":project_did_to_core_id(&document.id).unwrap()}},
            "applet_id":package.applet_id, "service_id":service,
            "actor_role":"ghost", "request_id":"0123456789012345678901",
            "creation_scope":{"kind":"realm","realm_id":realm},
            "registration_ref":registration,
            "creation_authorization_ref":grant,
            "initial_resolution":{"did":document.id,"method_history_head":head,"version_id":inception.version_id},
            "method_history_evidence":evidence,"control_method_kid":method,
            "expires_at":arkret_canonical::format_timestamp_canonical(at + chrono::Duration::minutes(5)),
            "external_ref":{"protocol":"matrix","instance_id":"chat.example","external_id":"external-user"},
            "recovery":{"kind":"manager_native","enabled":true}
        });
        let transcript: RealmActorCreationTranscript =
            serde_json::from_value(value.clone()).unwrap();
        value["control_signature"] = serde_json::to_value(
            sign_detached_object(
                &transcript,
                DetachedSignatureContext::RealmActorCreation,
                method,
                at,
                &control,
            )
            .unwrap(),
        )
        .unwrap();
        (serde_json::from_value(value).unwrap(), signer)
    }

    async fn native_successor_time(previous: &[Value]) -> chrono::DateTime<chrono::Utc> {
        let previous_time: chrono::DateTime<chrono::Utc> = previous.last().unwrap()["versionTime"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap();
        let earliest = previous_time + chrono::Duration::seconds(1);
        loop {
            let at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
            if at >= earliest {
                return at;
            }
            tokio::time::sleep((earliest - at).to_std().unwrap()).await;
        }
    }

    async fn recovery_plan(
        creation: &RealmActorCreatePayload,
        commit: &arkret_wire::RealmCommit,
    ) -> (
        RealmActorRecoveryBeginPayload,
        AppletManagedActorMethodHistoryEvidence,
    ) {
        let (_, previous, _) = creation.method_history_evidence.webvh_material();
        let at = native_successor_time(previous).await;
        let next_control = SigningKey::from_bytes(&[44; 32]);
        let next_update = SigningKey::from_bytes(&[45; 32]);
        let next_method = DidUrl::new(format!(
            "{}#recovered-controller",
            creation.initial_resolution.did
        ))
        .unwrap();
        let state = json!({
            "@context":["https://www.w3.org/ns/did/v1","https://w3id.org/security/multikey/v1"],
            "id":creation.initial_resolution.did,
            "verificationMethod":[{"id":next_method,"type":"Multikey","controller":creation.initial_resolution.did,
                "publicKeyMultibase":arkret_canonical::ed25519_pubkey_to_did_key_multibase(next_control.verifying_key().as_bytes())}],
            "assertionMethod":[next_method], "authentication":[next_method]
        });
        let update = arkret_signatures::webvh::prepare_service_rotation(
            &arkret_signatures::webvh::ServiceRotationInput {
                did: creation.initial_resolution.did.as_str(),
                previous_entries: previous,
                state: &state,
                current_update_seed: &[32; 32],
                next_update_public_key_multibase:
                    &arkret_canonical::ed25519_pubkey_to_did_key_multibase(
                        next_update.verifying_key().as_bytes(),
                    ),
                version_time: at,
            },
        )
        .unwrap();
        let mut entries = previous.to_vec();
        entries.push(update.log_entry);
        let head = canonical_sha256(entries.last().unwrap()).unwrap();
        let resolution = ResolutionCommitment {
            did: creation.initial_resolution.did.clone(),
            method_history_head: head.clone(),
            version_id: update.version_id.clone(),
        };
        let realm = creation
            .actor_id
            .as_realm_actor_id()
            .unwrap()
            .realm_id
            .clone();
        let source = CommittedEventRef {
            event_id: commit.event_ref.clone(),
            commit_id: commit.commit_id.clone(),
            stream_ref: CommitStreamRef::RealmControl { realm_id: realm },
            stream_position: commit.stream_position,
        };
        let revision = CurrentRevision {
            commit_id: source.commit_id.clone(),
            stream_position: commit.stream_position,
        };
        let mut value = json!({
            "target_actor_id":creation.actor_id,"request_id":"0123456789012345678901",
            "manager_ref":source,"recovery_ref":source,"expected_control_revision":revision,
            "expected_owner_status_revision":revision,"expected_governance_status_revision":revision,
            "expected_device_generation_revision":revision,"expected_generation":1,"new_generation":2,
            "replaces_recovery_ref":null,"next_resolution":resolution,
            "method_history_evidence":{"log_entries":entries,"witness_records":[]},
            "next_control_method_kid":next_method,"expires_at":arkret_canonical::format_timestamp_canonical(at + chrono::Duration::minutes(5))
        });
        let transcript:RealmActorRecoveryAcceptanceTranscript=serde_json::from_value(json!({"applet_id":creation.applet_id,"service_id":creation.service_id,"payload_without_control_signature":value})).unwrap();
        value["control_signature"] = json!(
            sign_detached_object(
                &transcript,
                DetachedSignatureContext::RealmActorRecoveryAcceptance,
                next_method,
                at,
                &next_control
            )
            .unwrap()
        );
        let document: DidDocument = serde_json::from_value(state).unwrap();
        let published = ResolutionMethodHistoryEvidence::WebvhLog {
            boundary: ResolutionMethodEvidenceBoundary {
                from_method_history_head: creation.initial_resolution.method_history_head.clone(),
                from_version_id: creation.initial_resolution.version_id.clone(),
                to_method_history_head: head.clone(),
                to_version_id: update.version_id,
            },
            evidence: ResolutionDidBindingEvidenceReceipt {
                kind: ResolutionDidBindingEvidenceKind::AkDidBindingEvidenceV1,
                method: "webvh".into(),
                document_digest: normalized_did_document_digest(&document).unwrap(),
                method_proofs: vec![ResolutionDidBindingMethodProof {
                    kind: ResolutionDidBindingMethodProofKind::WebvhLog,
                    history_head: head,
                    witnesses: vec![],
                    witness_proofs_digest: Hash::new(
                        canonical_sha256(&Vec::<serde_json::Value>::new()).unwrap(),
                    )
                    .unwrap(),
                }],
            },
            log_entries: entries,
            witness_records: vec![],
        };
        let published: AppletManagedActorMethodHistoryEvidence =
            serde_json::from_value(json!(published)).unwrap();
        (serde_json::from_value(value).unwrap(), published)
    }

    fn owner_status_event(
        fixture: &Fixture,
        candidate: &RealmActorCreatePayload,
        source: &CommittedEventRef,
        method: &DidUrl,
        seed: &[u8; 32],
        state: RealmActorStatusSetPayloadState,
    ) -> Event {
        let at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
        let payload = RealmActorStatusSetPayload {
            target_actor_id: candidate.actor_id.clone(),
            gate: RealmActorStatusSetPayloadGate::Owner,
            expected_revision: CurrentRevision {
                commit_id: source.commit_id.clone(),
                stream_position: source.stream_position,
            },
            state,
        };
        let intent = arkret_event_draft::TypedEventDraft::<
            arkret_wire::event_spec::RealmActorStatusSet,
        >::new(
            ScopeRef::RealmControl {
                realm_id: fixture.realm.clone(),
            },
            candidate.actor_id.clone(),
            payload,
        )
        .unwrap()
        .with_applet_id(candidate.applet_id.clone())
        .into_intent(at)
        .unwrap();
        let mut authored = intent
            .author_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
            .unwrap();
        let signer = Ed25519PayloadSigner::new(
            SigningKey::from_bytes(seed),
            candidate.initial_resolution.did.clone(),
            method.clone(),
        );
        arkret_signatures::sign_event(
            &mut authored,
            &signer,
            arkret_signatures::SignEventOptions::new().with_created_at(at),
        )
        .unwrap();
        authored.into_event()
    }

    async fn control_successor(
        candidate: &RealmActorCreatePayload,
        current: &arkret_wire::RealmCommit,
        published: &AppletManagedActorMethodHistoryEvidence,
        keep_old: bool,
    ) -> RealmActorControlUpdatePayload {
        let previous = published.webvh_material().1;
        let at = native_successor_time(previous).await;
        let did = &candidate.initial_resolution.did;
        let next = DidUrl::new(format!("{did}#rotated-controller")).unwrap();
        let key = SigningKey::from_bytes(&[55; 32]);
        let mut state = previous.last().unwrap()["state"].clone();
        if !keep_old {
            state["verificationMethod"] = json!([]);
            state["assertionMethod"] = json!([]);
            state["authentication"] = json!([]);
        }
        state["verificationMethod"].as_array_mut().unwrap().push(json!({"id":next,"type":"Multikey","controller":did,"publicKeyMultibase":arkret_canonical::ed25519_pubkey_to_did_key_multibase(key.verifying_key().as_bytes())}));
        state["assertionMethod"]
            .as_array_mut()
            .unwrap()
            .push(json!(next));
        state["authentication"]
            .as_array_mut()
            .unwrap()
            .push(json!(next));
        let rotation = arkret_signatures::webvh::prepare_service_rotation(
            &arkret_signatures::webvh::ServiceRotationInput {
                did: did.as_str(),
                previous_entries: previous,
                state: &state,
                current_update_seed: &[45; 32],
                next_update_public_key_multibase:
                    &arkret_canonical::ed25519_pubkey_to_did_key_multibase(
                        SigningKey::from_bytes(&[46; 32]).verifying_key().as_bytes(),
                    ),
                version_time: at,
            },
        )
        .unwrap();
        let mut entries = previous.to_vec();
        entries.push(rotation.log_entry);
        let head = canonical_sha256(entries.last().unwrap()).unwrap();
        let document: DidDocument = serde_json::from_value(state).unwrap();
        let evidence = ResolutionMethodHistoryEvidence::WebvhLog {
            boundary: ResolutionMethodEvidenceBoundary {
                from_method_history_head: candidate.initial_resolution.method_history_head.clone(),
                from_version_id: candidate.initial_resolution.version_id.clone(),
                to_method_history_head: head.clone(),
                to_version_id: rotation.version_id.clone(),
            },
            evidence: ResolutionDidBindingEvidenceReceipt {
                kind: ResolutionDidBindingEvidenceKind::AkDidBindingEvidenceV1,
                method: "webvh".into(),
                document_digest: normalized_did_document_digest(&document).unwrap(),
                method_proofs: vec![ResolutionDidBindingMethodProof {
                    kind: ResolutionDidBindingMethodProofKind::WebvhLog,
                    history_head: head.clone(),
                    witnesses: vec![],
                    witness_proofs_digest: Hash::new(
                        canonical_sha256(&Vec::<Value>::new()).unwrap(),
                    )
                    .unwrap(),
                }],
            },
            log_entries: entries,
            witness_records: vec![],
        };
        let transcript = RealmActorControlAcceptanceTranscript {
            actor_id: candidate.actor_id.clone(),
            expected_revision: CurrentRevision {
                commit_id: current.commit_id.clone(),
                stream_position: current.stream_position,
            },
            next_resolution: ResolutionCommitment {
                did: did.clone(),
                method_history_head: head,
                version_id: rotation.version_id,
            },
            method_history_evidence: serde_json::from_value(json!(evidence)).unwrap(),
            next_control_method_kid: next.clone(),
        };
        let signature = sign_detached_object(
            &transcript,
            DetachedSignatureContext::RealmActorControlAcceptance,
            next,
            at,
            &key,
        )
        .unwrap();
        RealmActorControlUpdatePayload {
            expected_revision: transcript.expected_revision,
            next_resolution: transcript.next_resolution,
            method_history_evidence: transcript.method_history_evidence,
            next_control_method_kid: transcript.next_control_method_kid,
            next_method_signature: signature,
        }
    }

    async fn normal_rotation(
        fixture: &Fixture,
        native: &NativeService,
        candidate: &RealmActorCreatePayload,
        current: &arkret_wire::RealmCommit,
        published: &AppletManagedActorMethodHistoryEvidence,
    ) {
        use arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequest;
        let old_method = DidUrl::new(format!(
            "{}#recovered-controller",
            candidate.initial_resolution.did
        ))
        .unwrap();
        let mut metadata = RealmActorControlHttpMetadata {
            actor_id: candidate.actor_id.clone(),
            control_ref: CommittedEventRef {
                event_id: current.event_ref.clone(),
                commit_id: current.commit_id.clone(),
                stream_ref: current.stream_ref.clone(),
                stream_position: current.stream_position,
            },
            nonce: String::new(),
        };
        for keep_old in [false, true] {
            let payload = control_successor(candidate, current, published, keep_old).await;
            if keep_old {
                *native.actor_log.lock().unwrap() =
                    payload.method_history_evidence.webvh_material().1.to_vec();
            } else {
                let last = published.webvh_material().1.last().unwrap();
                let projection = PrincipalResolutionProjection {
                    did: candidate.initial_resolution.did.clone(),
                    method_history_head: canonical_sha256(last).unwrap(),
                    version_id: last["versionId"].as_str().unwrap().to_owned(),
                    resolution_event_ref: current.event_ref.to_string(),
                    updated_at: current.committed_at,
                };
                assert!(
                    arkret_identity::verify_realm_actor_control_successor(
                        &candidate.actor_id,
                        &projection,
                        &old_method,
                        &payload,
                        payload.next_method_signature.created_at
                    )
                    .is_err()
                );
            }
            let at = payload.next_method_signature.created_at;
            let intent = arkret_event_draft::TypedEventDraft::<
                arkret_wire::event_spec::RealmActorControlUpdate,
            >::new(
                ScopeRef::RealmControl {
                    realm_id: fixture.realm.clone(),
                },
                candidate.actor_id.clone(),
                payload.clone(),
            )
            .unwrap()
            .with_applet_id(candidate.applet_id.clone())
            .into_intent(at)
            .unwrap();
            let mut authored = intent
                .author_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
                .unwrap();
            let signer = Ed25519PayloadSigner::new(
                SigningKey::from_bytes(&[44; 32]),
                candidate.initial_resolution.did.clone(),
                old_method.clone(),
            );
            arkret_signatures::sign_event(
                &mut authored,
                &signer,
                arkret_signatures::SignEventOptions::new().with_created_at(at),
            )
            .unwrap();
            let event = authored.into_event();
            let request = SelfAuthoritySubmitRequest::Event(
                arkret_wire::EventAdmissionSubmission::new(event.clone()),
            );
            metadata.nonce = arkret_canonical::base64url_encode(rand::random::<[u8; 32]>());
            let (status, response) = control_post_with_seed(
                fixture,
                &metadata,
                &old_method,
                "/_arkret/self/events",
                arkret_wire::ServiceOperationId::SelfEventsCommandSubmitV1,
                &json!(request),
                &[44; 32],
            )
            .await;
            if !keep_old {
                assert_ne!(
                    status,
                    StatusCode::OK,
                    "normal rotation cannot discard the old method before acceptance"
                );
                assert!(
                    fixture
                        .state
                        .test_persistence()
                        .authority_commits()
                        .committed_event(&event.event_id)
                        .await
                        .unwrap()
                        .is_none()
                );
                continue;
            }
            assert_eq!(
                status,
                StatusCode::OK,
                "normal control rotation: {response}"
            );
            let accepted = fixture
                .state
                .test_persistence()
                .authority_commits()
                .committed_event(&event.event_id)
                .await
                .unwrap()
                .unwrap();
            metadata.nonce = arkret_canonical::base64url_encode(rand::random::<[u8; 32]>());
            let (status, _) = control_post_with_seed(
                fixture,
                &metadata,
                &old_method,
                "/_arkret/self/events",
                arkret_wire::ServiceOperationId::SelfEventsCommandSubmitV1,
                &json!(request),
                &[44; 32],
            )
            .await;
            assert_eq!(
                status,
                StatusCode::UNAUTHORIZED,
                "old control cannot authenticate after accepted rotation"
            );
            metadata.control_ref = CommittedEventRef {
                event_id: event.event_id.clone(),
                commit_id: accepted.commit.commit_id.clone(),
                stream_ref: accepted.commit.stream_ref.clone(),
                stream_position: accepted.commit.stream_position,
            };
            metadata.nonce = arkret_canonical::base64url_encode(rand::random::<[u8; 32]>());
            let (status, response) = control_post_with_seed(
                fixture,
                &metadata,
                &payload.next_control_method_kid,
                "/_arkret/self/events",
                arkret_wire::ServiceOperationId::SelfEventsCommandSubmitV1,
                &json!(request),
                &[55; 32],
            )
            .await;
            assert_eq!(
                status,
                StatusCode::OK,
                "new control must recover the old-method signed original: {response}"
            );
            assert_eq!(
                fixture
                    .state
                    .test_persistence()
                    .authority_commits()
                    .committed_event(&event.event_id)
                    .await
                    .unwrap()
                    .unwrap()
                    .commit,
                accepted.commit
            );
        }
    }

    async fn revoke_material(
        fixture: &Fixture,
        candidate: &RealmActorCreatePayload,
        creation: &arkret_wire::RealmCommit,
        digest: &Hash,
    ) -> (StatusCode, Value) {
        let metadata = RealmActorControlHttpMetadata {
            actor_id: candidate.actor_id.clone(),
            control_ref: CommittedEventRef {
                event_id: creation.event_ref.clone(),
                commit_id: creation.commit_id.clone(),
                stream_ref: creation.stream_ref.clone(),
                stream_position: creation.stream_position,
            },
            nonce: arkret_canonical::base64url_encode(rand::random::<[u8; 32]>()),
        };
        let request = RealmActorMaterialRequest::Outcome {
            actor_id: candidate.actor_id.clone(),
            request_nonce: arkret_canonical::base64url_encode(rand::random::<[u8; 32]>()),
            target_request_digest: digest.clone(),
        };
        let (status, value) = control_post(
            fixture,
            &metadata,
            &candidate.control_method_kid,
            "/_arkret/self/realm-actors/material",
            arkret_wire::ServiceOperationId::SelfRealmActorReadMaterialV1,
            &json!(request),
        )
        .await;
        if status == StatusCode::OK {
            let material: RealmActorMaterialOutcome =
                serde_json::from_value(value.clone()).unwrap();
            material
                .validate_for_request(&request, &candidate.actor_id, chrono::Utc::now())
                .unwrap();
            let key = arkret_signatures::PublicKeyMaterial::Ed25519Multibase {
                value: arkret_canonical::ed25519_pubkey_to_did_key_multibase(
                    fixture
                        .state
                        .notary_signing_key()
                        .verifying_key()
                        .as_bytes(),
                ),
            };
            let unsigned = arkret_canonical::unsigned_value(&material, &["signature"]).unwrap();
            arkret_signatures::detached_object::verify_detached_object_signature(
                &material.signature,
                &unsigned,
                DetachedSignatureContext::RealmActorMaterial,
                &key,
            )
            .unwrap();
            let mut tampered = unsigned.clone();
            tampered["result"]["outcome"]["authorized_generation_ref"] = json!(999);
            assert!(
                arkret_signatures::detached_object::verify_detached_object_signature(
                    &material.signature,
                    &tampered,
                    DetachedSignatureContext::RealmActorMaterial,
                    &key
                )
                .is_err()
            );
        }
        (status, value)
    }

    async fn device_revoke(
        fixture: &Fixture,
        candidate: &RealmActorCreatePayload,
        creation: &arkret_wire::RealmCommit,
    ) {
        use arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequest;
        use arkret_models_collaboration::events_payloads::DeviceRevokePayload;
        use diesel::sql_query;
        use diesel::sql_types::{Jsonb, Text};
        use diesel_async::RunQueryDsl as _;
        let device = boxed_step(|| authorize_device(fixture, candidate, creation, 81)).await;
        let store = fixture.state.test_persistence();
        let mut pending = Vec::new();
        for index in 0..3 {
            let at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
            let payload: DeviceRevokePayload = serde_json::from_value(json!({
                "device_id":device,"revoked_by":candidate.actor_id.signing_principal_id(),
                "revoked_at":arkret_canonical::format_timestamp_canonical(at),"reason":format!("revoke_{index}")
            }))
            .unwrap();
            let intent =
                arkret_event_draft::TypedEventDraft::<arkret_wire::event_spec::DeviceRevoke>::new(
                    ScopeRef::RealmControl {
                        realm_id: fixture.realm.clone(),
                    },
                    candidate.actor_id.clone(),
                    payload,
                )
                .unwrap()
                .with_applet_id(candidate.applet_id.clone())
                .into_intent(at)
                .unwrap();
            let mut authored = intent
                .author_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
                .unwrap();
            let signer = Ed25519PayloadSigner::new(
                SigningKey::from_bytes(&[33; 32]),
                candidate.initial_resolution.did.clone(),
                candidate.control_method_kid.clone(),
            );
            arkret_signatures::sign_event(
                &mut authored,
                &signer,
                arkret_signatures::SignEventOptions::new().with_created_at(at),
            )
            .unwrap();
            let event = authored.into_event();
            let request = SelfAuthoritySubmitRequest::Event(
                arkret_wire::EventAdmissionSubmission::new(event.clone()),
            );
            let metadata = RealmActorControlHttpMetadata {
                actor_id: candidate.actor_id.clone(),
                control_ref: CommittedEventRef {
                    event_id: creation.event_ref.clone(),
                    commit_id: creation.commit_id.clone(),
                    stream_ref: creation.stream_ref.clone(),
                    stream_position: creation.stream_position,
                },
                nonce: arkret_canonical::base64url_encode(rand::random::<[u8; 32]>()),
            };
            let request_body = json!(request);
            let (status, response) = boxed_step(|| {
                control_post(
                    fixture,
                    &metadata,
                    &candidate.control_method_kid,
                    "/_arkret/self/events",
                    arkret_wire::ServiceOperationId::SelfEventsCommandSubmitV1,
                    &request_body,
                )
            })
            .await;
            assert_eq!(status, StatusCode::OK, "revoke proposal: {response}");
            let original = store
                .authority_commits()
                .committed_event(&event.event_id)
                .await
                .unwrap()
                .unwrap();
            let digest = Hash::new(arkret_canonical::canonical_sha256(&request).unwrap()).unwrap();
            let (status, response) =
                boxed_step(|| revoke_material(fixture, candidate, creation, &digest)).await;
            assert_eq!(
                status,
                StatusCode::OK,
                "revoke pending material: {response}"
            );
            let material: RealmActorMaterialOutcome = serde_json::from_value(response).unwrap();
            let RealmActorMaterialResult::Outcome { outcome, .. } = material.result else {
                panic!("outcome required")
            };
            assert!(matches!(
                outcome,
                RealmActorOperationOutcome::DeviceRevoke {
                    state: RealmActorDeviceRevokeState::Pending,
                    decided_at: None,
                    ..
                }
            ));
            let authority = store
                .authority_commits()
                .current_authority(&fixture.realm)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(authority.authority_ref, original.commit.authority_ref);
            pending.push((digest, outcome, authority));
        }
        assert!(
            store
                .device_revocations()
                .applet_managed_device_authority(&candidate.actor_id, &device, chrono::Utc::now())
                .await
                .is_err()
        );
        for (digest, outcome, authority) in &pending[..2] {
            let mut terminal = outcome.clone();
            let RealmActorOperationOutcome::DeviceRevoke {
                state, decided_at, ..
            } = &mut terminal
            else {
                unreachable!()
            };
            *state = RealmActorDeviceRevokeState::Rejected;
            *decided_at = Some(arkret_canonical::normalize_timestamp_canonical(
                chrono::Utc::now(),
            ));
            let mut stale = authority.clone();
            stale.generation += 1;
            assert!(
                store
                    .authority_commits()
                    .finish_realm_actor_device_revocation(&candidate.actor_id, &stale, &terminal)
                    .await
                    .is_err()
            );
            store
                .authority_commits()
                .finish_realm_actor_device_revocation(&candidate.actor_id, authority, &terminal)
                .await
                .unwrap();
            store
                .authority_commits()
                .finish_realm_actor_device_revocation(&candidate.actor_id, authority, &terminal)
                .await
                .unwrap();
            let (_, response) =
                boxed_step(|| revoke_material(fixture, candidate, creation, digest)).await;
            let material: RealmActorMaterialOutcome = serde_json::from_value(response).unwrap();
            let RealmActorMaterialResult::Outcome { outcome: read, .. } = material.result else {
                unreachable!()
            };
            assert_eq!(json!(read), json!(terminal));
            let mut conflict = terminal.clone();
            if let RealmActorOperationOutcome::DeviceRevoke { state, .. } = &mut conflict {
                *state = RealmActorDeviceRevokeState::Accepted;
            }
            assert!(
                store
                    .authority_commits()
                    .finish_realm_actor_device_revocation(&candidate.actor_id, authority, &conflict)
                    .await
                    .is_err()
            );
            assert!(
                store
                    .device_revocations()
                    .applet_managed_device_authority(
                        &candidate.actor_id,
                        &device,
                        chrono::Utc::now()
                    )
                    .await
                    .is_err(),
                "rejecting one proposal must not clear other pending proposals"
            );
        }
        let (digest, outcome, _) = &pending[2];
        let RealmActorOperationOutcome::DeviceRevoke { proposal_ref, .. } = outcome else {
            unreachable!()
        };
        let mut conn = fixture.pool.get().await.unwrap();
        sql_query("UPDATE realm_actor_device_revoke_results SET result_json=jsonb_set(result_json,'{authorized_generation_ref}','999'::jsonb) WHERE proposal_commit_id=$1")
            .bind::<Text,_>(proposal_ref.commit_id.as_str()).execute(&mut conn).await.unwrap();
        let (status, _) =
            boxed_step(|| revoke_material(fixture, candidate, creation, digest)).await;
        assert_eq!(
            status,
            StatusCode::SERVICE_UNAVAILABLE,
            "corrupt ledger cannot become pending"
        );
        sql_query("UPDATE realm_actor_device_revoke_results SET result_json=$1 WHERE proposal_commit_id=$2")
            .bind::<Jsonb,_>(json!(outcome)).bind::<Text,_>(proposal_ref.commit_id.as_str()).execute(&mut conn).await.unwrap();
        #[derive(diesel::QueryableByName)]
        struct Ledger {
            #[diesel(sql_type=Jsonb)]
            value: Value,
        }
        let ledger = sql_query("SELECT to_jsonb(r) AS value FROM realm_actor_device_revoke_results r WHERE proposal_commit_id=$1")
            .bind::<Text,_>(proposal_ref.commit_id.as_str()).get_result::<Ledger>(&mut conn).await.unwrap();
        sql_query("DELETE FROM realm_actor_device_revoke_results WHERE proposal_commit_id=$1")
            .bind::<Text, _>(proposal_ref.commit_id.as_str())
            .execute(&mut conn)
            .await
            .unwrap();
        let (status, _) =
            boxed_step(|| revoke_material(fixture, candidate, creation, digest)).await;
        assert_eq!(
            status,
            StatusCode::SERVICE_UNAVAILABLE,
            "missing ledger cannot become pending or unknown"
        );
        sql_query("INSERT INTO realm_actor_device_revoke_results SELECT * FROM jsonb_populate_record(NULL::realm_actor_device_revoke_results,$1)")
            .bind::<Jsonb,_>(ledger.value).execute(&mut conn).await.unwrap();
        drop(conn);
        assert_eq!(
            coland_http::security_rotation_worker::sweep_realm_device_revocations(&fixture.state)
                .await
                .unwrap(),
            1
        );
        assert_eq!(
            coland_http::security_rotation_worker::sweep_realm_device_revocations(&fixture.state)
                .await
                .unwrap(),
            0
        );
        let (status, response) =
            boxed_step(|| revoke_material(fixture, candidate, creation, digest)).await;
        assert_eq!(status, StatusCode::OK, "terminal material: {response}");
        let material: RealmActorMaterialOutcome = serde_json::from_value(response).unwrap();
        assert!(matches!(
            material.result,
            RealmActorMaterialResult::Outcome {
                outcome: RealmActorOperationOutcome::DeviceRevoke {
                    state: RealmActorDeviceRevokeState::Accepted,
                    decided_at: Some(_),
                    ..
                },
                ..
            }
        ));
        assert!(
            store
                .device_revocations()
                .applet_managed_device_authority(&candidate.actor_id, &device, chrono::Utc::now())
                .await
                .is_err()
        );
    }

    async fn durable_completion(
        fixture: &Fixture,
        actor: &ActorId,
    ) -> coland_storage::AppletAuthoringCompletion {
        use diesel_async::RunQueryDsl as _;
        #[derive(diesel::QueryableByName)]
        struct Row {
            #[diesel(sql_type = diesel::sql_types::Jsonb)]
            value: Value,
        }
        let mut conn = fixture.pool.get().await.unwrap();
        let rows = diesel::sql_query("SELECT to_jsonb(t) AS value FROM applet_authoring_completions t WHERE realm_id=$1 AND actor_id=$2")
            .bind::<diesel::sql_types::Text,_>(fixture.realm.as_str())
            .bind::<diesel::sql_types::Jsonb,_>(json!(actor))
            .load::<Row>(&mut conn).await.unwrap();
        assert_eq!(
            rows.len(),
            1,
            "accepted creation retains one durable completion"
        );
        serde_json::from_value(rows.into_iter().next().unwrap().value).unwrap()
    }

    async fn installation_business_revocation(
        fixture: &Fixture,
        native: &NativeService,
        candidate: &RealmActorCreatePayload,
    ) {
        use arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequest;
        let completion_before = durable_completion(fixture, &candidate.actor_id).await;
        let persistence = fixture.state.test_persistence();
        let grant_source = persistence
            .authority_commits()
            .committed_event(
                &EventId::from_token_bytes(candidate.creation_authorization_ref.token_bytes())
                    .unwrap(),
            )
            .await
            .unwrap()
            .unwrap();
        let revoke = fixture.admin_event(EventKind::CapabilityRevoke, candidate.creation_scope.clone(), json!({
            "grant_id":candidate.creation_authorization_ref,
            "expected_revision":{"commit_id":grant_source.commit.commit_id,"stream_position":grant_source.commit.stream_position}
        }));
        eprintln!("recovery: revoking business grant");
        let authority_path = format!(
            "/_arkret/self/applets/{}/authority/material",
            candidate.applet_id
        );
        let authority_request = json!({"effective_scope":candidate.creation_scope,"grant_ids":[candidate.creation_authorization_ref]});
        let (status, active_material) = fixture
            .service_post(
                &native.package,
                &authority_path,
                arkret_wire::ServiceOperationId::SELF_APPLET_AUTHORITY_READ_MATERIAL_V1,
                &authority_request,
                "installation-before-revoke",
            )
            .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "current installation material: {active_material}"
        );
        assert_eq!(active_material["current_binding"]["status"], "active");
        let revoke_request =
            SelfAuthoritySubmitRequest::Event(arkret_wire::EventAdmissionSubmission::new(revoke));
        let (status, response) = fixture
            .admin_post_network(
                "/_arkret/self/events",
                arkret_wire::ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT_V1,
                &json!(revoke_request),
                "revoke-business-before-recovery",
            )
            .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "real business grant revocation: {response}"
        );
        let (status, partial_material) = fixture
            .service_post(
                &native.package,
                &authority_path,
                arkret_wire::ServiceOperationId::SELF_APPLET_AUTHORITY_READ_MATERIAL_V1,
                &authority_request,
                "installation-after-revoke",
            )
            .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "historical material after one grant revoke: {partial_material}"
        );
        assert_eq!(
            partial_material["current_binding"]["status"], "active",
            "other installation grants remain active"
        );
        let scope_key =
            coland_storage::applet_effective_scope_key(&candidate.creation_scope).unwrap();
        let installation = persistence
            .applets()
            .get(
                candidate.applet_id.as_str(),
                candidate.service_id.as_str(),
                &scope_key,
            )
            .await
            .unwrap()
            .unwrap();
        use diesel::sql_types::{Jsonb, Text};
        use diesel_async::RunQueryDsl as _;
        #[derive(diesel::QueryableByName)]
        struct MissingRegistration {
            #[diesel(sql_type = Jsonb)]
            value: Value,
        }
        let mut conn = fixture.pool.get().await.unwrap();
        let missing = diesel::sql_query("DELETE FROM applet_registration_current_results WHERE realm_id=$1 AND applet_id=$2 RETURNING to_jsonb(applet_registration_current_results) AS value")
            .bind::<Text,_>(fixture.realm.as_str())
            .bind::<Text,_>(candidate.applet_id.as_str())
            .get_result::<MissingRegistration>(&mut conn).await.unwrap();
        let (status, unavailable_material) = fixture
            .service_post(
                &native.package,
                &authority_path,
                arkret_wire::ServiceOperationId::SELF_APPLET_AUTHORITY_READ_MATERIAL_V1,
                &authority_request,
                "installation-missing-current-is-not-inactive",
            )
            .await;
        diesel::sql_query("INSERT INTO applet_registration_current_results SELECT * FROM jsonb_populate_record(NULL::applet_registration_current_results,$1)")
            .bind::<Jsonb,_>(missing.value).execute(&mut conn).await.unwrap();
        drop(conn);
        assert_ne!(
            status,
            StatusCode::OK,
            "missing current registration must fail the entire read: {unavailable_material}"
        );
        assert!(unavailable_material.get("current_binding").is_none());
        for original in installation["capability_grant_events"].as_array().unwrap() {
            let original: arkret_wire::Event = serde_json::from_value(original.clone()).unwrap();
            let grant_id = arkret_wire::GrantId::from_event_id(&original.event_id);
            if grant_id == candidate.creation_authorization_ref {
                continue;
            }
            let source = persistence
                .authority_commits()
                .committed_event(&original.event_id)
                .await
                .unwrap()
                .unwrap();
            let revoke = fixture.admin_event(EventKind::CapabilityRevoke, candidate.creation_scope.clone(), json!({
                "grant_id":grant_id,
                "expected_revision":{"commit_id":source.commit.commit_id,"stream_position":source.commit.stream_position}
            }));
            let request = SelfAuthoritySubmitRequest::Event(
                arkret_wire::EventAdmissionSubmission::new(revoke),
            );
            let (status, result) = fixture
                .admin_post_network(
                    "/_arkret/self/events",
                    arkret_wire::ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT_V1,
                    &json!(request),
                    &format!("revoke-installation-{grant_id}"),
                )
                .await;
            assert_eq!(
                status,
                StatusCode::OK,
                "revoke remaining installation grant: {result}"
            );
        }
        let (status, inactive_material) = fixture
            .service_post(
                &native.package,
                &authority_path,
                arkret_wire::ServiceOperationId::SELF_APPLET_AUTHORITY_READ_MATERIAL_V1,
                &authority_request,
                "installation-after-all-grants-revoked",
            )
            .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "historical source remains readable without business grants: {inactive_material}"
        );
        assert_eq!(
            inactive_material["registration"],
            active_material["registration"]
        );
        assert_eq!(
            inactive_material["grant_events"],
            active_material["grant_events"]
        );
        assert_eq!(
            inactive_material["current_binding"],
            json!({"status":"inactive"})
        );
        let completion = durable_completion(fixture, &candidate.actor_id).await;
        assert_eq!(
            completion.creation_ref, completion_before.creation_ref,
            "revocation preserves the immutable completion even while delivery progresses"
        );
        let historical_delivery = prepare_configuration_completion(fixture, &completion)
            .await
            .unwrap();
        let RealmActorMaterialResult::Event { event, commit, .. } = &historical_delivery
            .context
            .as_ref()
            .unwrap()
            .material
            .result
        else {
            panic!("expected original creation")
        };
        assert_eq!(event.event_id, completion.creation_ref.event_id);
        assert_eq!(commit.commit_id, completion.creation_ref.commit_id);
    }

    async fn recovery(
        fixture: &Fixture,
        native: &NativeService,
        candidate: &RealmActorCreatePayload,
        signer: &Ed25519PayloadSigner,
        creation: &arkret_wire::RealmCommit,
        device: &arkret_wire::DeviceId,
    ) {
        use arkret_models_collaboration::authority_commit::{
            SelfAuthoritySubmitOutcome, SelfAuthoritySubmitRequest,
        };
        use diesel::sql_query;
        use diesel::sql_types::{Jsonb, Text};
        use diesel_async::RunQueryDsl as _;
        #[derive(diesel::QueryableByName)]
        struct Row {
            #[diesel(sql_type=Jsonb)]
            value: Value,
        }
        async fn snapshot(fixture: &Fixture, actor: &ActorId) -> Value {
            let mut conn = fixture.pool.get().await.unwrap();
            sql_query("SELECT jsonb_object_agg(selector->>'kind'||COALESCE(selector->>'gate',''),value) AS value FROM realm_actor_current_results WHERE realm_id=$1 AND actor_id=$2")
                .bind::<Text,_>(fixture.realm.as_str()).bind::<Jsonb,_>(json!(actor)).get_result::<Row>(&mut conn).await.unwrap().value
        }
        eprintln!("recovery: checking current device");
        let persistence = fixture.state.test_persistence();
        assert!(
            persistence
                .device_revocations()
                .applet_managed_device_authority(&candidate.actor_id, device, chrono::Utc::now())
                .await
                .unwrap()
                .is_some()
        );
        boxed_step(|| installation_business_revocation(fixture, native, candidate)).await;
        eprintln!("recovery: authoring native plan");
        let (plan, published) = recovery_plan(candidate, creation).await;
        let make_begin = |payload: RealmActorRecoveryBeginPayload| {
            let at = payload.control_signature.created_at;
            let intent = arkret_event_draft::TypedEventDraft::<
                arkret_wire::event_spec::RealmActorRecoveryBegin,
            >::new(
                ScopeRef::RealmControl {
                    realm_id: fixture.realm.clone(),
                },
                ActorId::service(candidate.service_id.clone()),
                payload,
            )
            .unwrap()
            .with_applet_id(candidate.applet_id.clone())
            .into_intent(at)
            .unwrap();
            let mut authored = intent
                .author_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
                .unwrap();
            arkret_signatures::sign_event(
                &mut authored,
                signer,
                arkret_signatures::SignEventOptions::new().with_created_at(at),
            )
            .unwrap();
            authored.into_event()
        };
        let original = snapshot(fixture, &candidate.actor_id).await;
        let mut bad_plan = plan.clone();
        bad_plan.expected_control_revision.stream_position += 1;
        let bad = make_begin(bad_plan);
        let request = SelfAuthoritySubmitRequest::Event(
            arkret_wire::EventAdmissionSubmission::new(bad.clone()),
        );
        let (status, _) = fixture
            .service_post(
                &native.package,
                "/_arkret/self/events",
                arkret_wire::ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT_V1,
                &json!(request),
                "recovery-bad-cas",
            )
            .await;
        assert_ne!(status, StatusCode::OK);
        assert_eq!(
            snapshot(fixture, &candidate.actor_id).await,
            original,
            "failed recovery must be atomic"
        );
        assert!(
            persistence
                .authority_commits()
                .committed_event(&bad.event_id)
                .await
                .unwrap()
                .is_none()
        );
        eprintln!("recovery: beginning accepted plan");
        let begin = make_begin(plan.clone());
        assert!(begin.authorization_ref.is_none());
        let request = SelfAuthoritySubmitRequest::Event(
            arkret_wire::EventAdmissionSubmission::new(begin.clone()),
        );
        let (status, response) = fixture
            .service_post(
                &native.package,
                "/_arkret/self/events",
                arkret_wire::ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT_V1,
                &json!(request),
                "recovery-begin",
            )
            .await;
        assert_eq!(status, StatusCode::OK, "recovery begin: {response}");
        serde_json::from_value::<SelfAuthoritySubmitOutcome>(response)
            .unwrap()
            .validate_for_request(&request)
            .unwrap();
        let accepted = persistence
            .authority_commits()
            .committed_event(&begin.event_id)
            .await
            .unwrap()
            .unwrap();
        let replay_digest =
            arkret_wire::Hash::new(arkret_canonical::canonical_sha256(&request).unwrap()).unwrap();
        let wrong_governor = persistence
            .authority_commits()
            .realm_actor_recovery_replay(&begin, &replay_digest, &candidate.service_id)
            .await
            .unwrap_err();
        assert!(wrong_governor.to_string().contains("stale_realm_authority"));
        let fenced = snapshot(fixture, &candidate.actor_id).await;
        assert_eq!(fenced["realm_actor_statusowner"], "paused");
        assert_eq!(fenced["realm_actor_statusgovernance"], "active");
        assert_eq!(
            fenced["realm_actor_device_generation"]["current_device_generation_ref"],
            2
        );
        assert_eq!(
            fenced["realm_actor_control"],
            original["realm_actor_control"]
        );
        assert!(
            persistence
                .device_revocations()
                .applet_managed_device_authority(&candidate.actor_id, device, chrono::Utc::now())
                .await
                .is_err()
        );
        let begin_ref = CommittedEventRef {
            event_id: begin.event_id.clone(),
            commit_id: accepted.commit.commit_id.clone(),
            stream_ref: accepted.commit.stream_ref.clone(),
            stream_position: accepted.commit.stream_position,
        };
        let begin_revision = CurrentRevision {
            commit_id: accepted.commit.commit_id.clone(),
            stream_position: accepted.commit.stream_position,
        };
        let pending_resume = owner_status_event(
            fixture,
            candidate,
            &begin_ref,
            &candidate.control_method_kid,
            &[33; 32],
            RealmActorStatusSetPayloadState::Active,
        );
        let pending_control = RealmActorControlHttpMetadata {
            actor_id: candidate.actor_id.clone(),
            control_ref: CommittedEventRef {
                event_id: creation.event_ref.clone(),
                commit_id: creation.commit_id.clone(),
                stream_ref: creation.stream_ref.clone(),
                stream_position: creation.stream_position,
            },
            nonce: arkret_canonical::base64url_encode(rand::random::<[u8; 32]>()),
        };
        let pending_request = SelfAuthoritySubmitRequest::Event(
            arkret_wire::EventAdmissionSubmission::new(pending_resume),
        );
        let (status, _) = control_post(
            fixture,
            &pending_control,
            &candidate.control_method_kid,
            "/_arkret/self/events",
            arkret_wire::ServiceOperationId::SelfEventsCommandSubmitV1,
            &json!(pending_request),
        )
        .await;
        assert_ne!(
            status,
            StatusCode::OK,
            "pending recovery cannot resume owner"
        );
        assert_eq!(snapshot(fixture, &candidate.actor_id).await, fenced);
        let payload = RealmActorControlResetPayload {
            target_actor_id: candidate.actor_id.clone(),
            recovery_begin_ref: begin_ref.clone(),
            expected_recovery_revision: begin_revision.clone(),
            expected_manager_revision: plan.expected_control_revision.clone(),
            expected_control_revision: plan.expected_control_revision.clone(),
            expected_device_generation_revision: begin_revision,
            published_method_history_evidence: published.clone(),
        };
        let at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
        let intent = arkret_event_draft::TypedEventDraft::<
            arkret_wire::event_spec::RealmActorControlReset,
        >::new(
            ScopeRef::RealmControl {
                realm_id: fixture.realm.clone(),
            },
            ActorId::service(candidate.service_id.clone()),
            payload,
        )
        .unwrap()
        .with_applet_id(candidate.applet_id.clone())
        .into_intent(at)
        .unwrap();
        let mut authored = intent
            .author_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
            .unwrap();
        arkret_signatures::sign_event(
            &mut authored,
            signer,
            arkret_signatures::SignEventOptions::new().with_created_at(at),
        )
        .unwrap();
        let reset = authored.into_event();
        let finish = SelfAuthoritySubmitRequest::Event(arkret_wire::EventAdmissionSubmission::new(
            reset.clone(),
        ));
        let (status, _) = fixture
            .service_post(
                &native.package,
                "/_arkret/self/events",
                arkret_wire::ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT_V1,
                &json!(finish),
                "recovery-unpublished",
            )
            .await;
        assert_ne!(
            status,
            StatusCode::OK,
            "unpublished native plan cannot finish"
        );
        assert_eq!(snapshot(fixture, &candidate.actor_id).await, fenced);
        *native.actor_log.lock().unwrap() = published.webvh_material().1.to_vec();
        let (status, response) = fixture
            .service_post(
                &native.package,
                "/_arkret/self/events",
                arkret_wire::ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT_V1,
                &json!(finish),
                "recovery-reset",
            )
            .await;
        assert_eq!(status, StatusCode::OK, "recovery reset: {response}");
        let finished = snapshot(fixture, &candidate.actor_id).await;
        assert_eq!(finished["realm_actor_statusowner"], "paused");
        assert_eq!(
            finished["realm_actor_device_generation"]["current_device_generation_ref"],
            2
        );
        assert_eq!(finished["realm_actor_recovery"]["pending"], Value::Null);
        assert_eq!(
            finished["realm_actor_control"]["control_method_kid"],
            json!(plan.next_control_method_kid)
        );
        assert!(
            persistence
                .device_revocations()
                .applet_managed_device_authority(&candidate.actor_id, device, chrono::Utc::now())
                .await
                .is_err()
        );
        let (status, response) = fixture
            .service_post(
                &native.package,
                "/_arkret/self/events",
                arkret_wire::ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT_V1,
                &json!(request),
                "recovery-begin-retry-after-finish",
            )
            .await;
        assert_eq!(status, StatusCode::OK, "completed begin retry: {response}");
        assert_eq!(snapshot(fixture, &candidate.actor_id).await, finished);
        let stored = persistence
            .authority_commits()
            .committed_event(&begin.event_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored.commit, accepted.commit);
        let material = RealmActorMaterialRequest::Outcome {
            actor_id: candidate.actor_id.clone(),
            request_nonce: arkret_canonical::base64url_encode(rand::random::<[u8; 32]>()),
            target_request_digest: Hash::new(canonical_sha256(&request).unwrap()).unwrap(),
        };
        let (status, response) = fixture
            .service_post(
                &native.package,
                "/_arkret/self/realm-actors/material",
                arkret_wire::ServiceOperationId::SelfRealmActorReadMaterialV1.as_str(),
                &json!(material),
                "recovery-outcome",
            )
            .await;
        assert_eq!(status, StatusCode::OK, "recovery outcome: {response}");
        assert!(
            serde_json::to_string(&response)
                .unwrap()
                .contains("completed"),
            "lifecycle must overlay the immutable submission: {response}"
        );
        let reset_original = persistence
            .authority_commits()
            .committed_event(&reset.event_id)
            .await
            .unwrap()
            .unwrap();
        let control_ref = CommittedEventRef {
            event_id: reset.event_id.clone(),
            commit_id: reset_original.commit.commit_id.clone(),
            stream_ref: reset_original.commit.stream_ref.clone(),
            stream_position: reset_original.commit.stream_position,
        };
        let metadata = RealmActorControlHttpMetadata {
            actor_id: candidate.actor_id.clone(),
            control_ref,
            nonce: arkret_canonical::base64url_encode(rand::random::<[u8; 32]>()),
        };
        let resume = owner_status_event(
            fixture,
            candidate,
            &begin_ref,
            &plan.next_control_method_kid,
            &[44; 32],
            RealmActorStatusSetPayloadState::Active,
        );
        let resume_request =
            SelfAuthoritySubmitRequest::Event(arkret_wire::EventAdmissionSubmission::new(resume));
        let (status, response) = control_post_with_seed(
            fixture,
            &metadata,
            &plan.next_control_method_kid,
            "/_arkret/self/events",
            arkret_wire::ServiceOperationId::SelfEventsCommandSubmitV1,
            &json!(resume_request),
            &[44; 32],
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "explicit new-control owner resume: {response}"
        );
        let resumed = snapshot(fixture, &candidate.actor_id).await;
        assert_eq!(resumed["realm_actor_statusowner"], "active");
        assert_eq!(resumed["realm_actor_statusgovernance"], "active");
        let fenced_device = persistence
            .device_revocations()
            .applet_managed_device_authority(&candidate.actor_id, device, chrono::Utc::now())
            .await;
        assert!(
            fenced_device.is_err(),
            "old Device must stay fenced after both gates are active"
        );
        assert!(fenced_device.unwrap_err().to_string().contains("fenced"));
        let at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
        let reset_devices = RealmActorDevicesResetPayload {
            expected_revision: CurrentRevision {
                commit_id: accepted.commit.commit_id.clone(),
                stream_position: accepted.commit.stream_position,
            },
            expected_generation: 2,
            new_generation: 3,
        };
        let intent = arkret_event_draft::TypedEventDraft::<
            arkret_wire::event_spec::RealmActorDevicesReset,
        >::new(
            ScopeRef::RealmControl {
                realm_id: fixture.realm.clone(),
            },
            candidate.actor_id.clone(),
            reset_devices,
        )
        .unwrap()
        .with_applet_id(candidate.applet_id.clone())
        .into_intent(at)
        .unwrap();
        let mut authored = intent
            .author_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
            .unwrap();
        let recovered_signer = Ed25519PayloadSigner::new(
            SigningKey::from_bytes(&[44; 32]),
            candidate.initial_resolution.did.clone(),
            plan.next_control_method_kid.clone(),
        );
        arkret_signatures::sign_event(
            &mut authored,
            &recovered_signer,
            arkret_signatures::SignEventOptions::new().with_created_at(at),
        )
        .unwrap();
        let devices_request = SelfAuthoritySubmitRequest::Event(
            arkret_wire::EventAdmissionSubmission::new(authored.into_event()),
        );
        let mut metadata = metadata;
        metadata.nonce = arkret_canonical::base64url_encode(rand::random::<[u8; 32]>());
        let (status, response) = control_post_with_seed(
            fixture,
            &metadata,
            &plan.next_control_method_kid,
            "/_arkret/self/events",
            arkret_wire::ServiceOperationId::SelfEventsCommandSubmitV1,
            &json!(devices_request),
            &[44; 32],
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "explicit Device generation reset: {response}"
        );
        assert_eq!(
            snapshot(fixture, &candidate.actor_id).await["realm_actor_device_generation"]["current_device_generation_ref"],
            3
        );
        Box::pin(normal_rotation(
            fixture,
            native,
            candidate,
            &reset_original.commit,
            &published,
        ))
        .await;
        let mut conn = fixture.pool.get().await.unwrap();
        let fact = sql_query(
            "SELECT fact AS value FROM realm_actor_private_signer_facts WHERE event_id=$1",
        )
        .bind::<Text, _>(begin.event_id.as_str())
        .get_result::<Row>(&mut conn)
        .await
        .unwrap()
        .value;
        assert_eq!(fact["kind"], "realm_recovery_service");
        assert!(fact.get("authorization_ref").is_none());
    }

    async fn actor_current_ref(
        fixture: &Fixture,
        actor: &ActorId,
        selector: Value,
    ) -> CommittedEventRef {
        use diesel::sql_types::{Jsonb, Text};
        use diesel::{QueryableByName, sql_query};
        use diesel_async::RunQueryDsl;
        #[derive(QueryableByName)]
        struct Row {
            #[diesel(sql_type=Jsonb)]
            value: Value,
        }
        let mut conn = fixture.pool.get().await.unwrap();
        let row = sql_query("SELECT jsonb_build_object('event_id',c.commit_json->'event_ref','commit_id',r.current_commit_id,'stream_ref',r.source_stream_ref,'stream_position',r.current_stream_position) AS value FROM realm_actor_current_results r JOIN realm_commits c ON c.commit_id=r.current_commit_id WHERE r.realm_id=$1 AND r.actor_id=$2 AND r.selector=$3")
            .bind::<Text,_>(fixture.realm.as_str()).bind::<Jsonb,_>(json!(actor)).bind::<Jsonb,_>(selector)
            .get_result::<Row>(&mut conn).await.unwrap();
        serde_json::from_value(row.value).unwrap()
    }

    async fn manager_handover(
        factory: &AppletAuthoringFactory,
        native: &NativeService,
        candidate: &RealmActorCreatePayload,
    ) {
        use arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequest;
        let fixture = &factory.fixture;
        let actor = &candidate.actor_id;
        let completion = fixture
            .state
            .test_persistence()
            .applets()
            .pending_authoring_completions(128)
            .await
            .unwrap()
            .into_iter()
            .find(|task| &task.actor_id == actor)
            .expect("original creation keeps its durable completion until real delivery ACK");
        let notary_method = fixture
            .state
            .service_verification_method("notary-key")
            .unwrap();
        let original_completion = super::completion_application(&fixture.state)
            .prepare_applet_authoring_completion(
                &completion,
                &fixture.state.service_core_id(),
                &notary_method,
                fixture.state.notary_signing_key().as_ref(),
            )
            .await
            .unwrap();
        let control_ref = actor_current_ref(
            fixture,
            actor,
            json!({"kind":"realm_actor_control","actor_id":actor}),
        )
        .await;
        let manager_ref = actor_current_ref(
            fixture,
            actor,
            json!({"kind":"realm_actor_manager","actor_id":actor}),
        )
        .await;
        let owner_ref = actor_current_ref(
            fixture,
            actor,
            json!({"kind":"realm_actor_status","actor_id":actor,"gate":"owner"}),
        )
        .await;
        let generation_ref = actor_current_ref(
            fixture,
            actor,
            json!({"kind":"realm_actor_device_generation","actor_id":actor}),
        )
        .await;
        let state = snapshot(fixture, actor).await;
        let control: RealmActorControlValue =
            serde_json::from_value(state["realm_actor_control"].clone()).unwrap();
        let generation = state["realm_actor_device_generation"]["current_device_generation_ref"]
            .as_u64()
            .unwrap();
        let metadata = || RealmActorControlHttpMetadata {
            actor_id: actor.clone(),
            control_ref: control_ref.clone(),
            nonce: arkret_canonical::base64url_encode(rand::random::<[u8; 32]>()),
        };
        let pause = owner_status_event(
            fixture,
            candidate,
            &owner_ref,
            &control.control_method_kid,
            &[55; 32],
            RealmActorStatusSetPayloadState::Paused,
        );
        let (status, body) = control_post_with_seed(
            fixture,
            &metadata(),
            &control.control_method_kid,
            "/_arkret/self/events",
            arkret_wire::ServiceOperationId::SelfEventsCommandSubmitV1,
            &json!(SelfAuthoritySubmitRequest::Event(
                arkret_wire::EventAdmissionSubmission::new(pause)
            )),
            &[55; 32],
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "pause before manager handover: {body}"
        );
        let mut receiving =
            NativeService::new(&candidate.applet_id, &fixture.state.service_core_id());
        let controller_method = receiving
            .package
            .proof
            .as_ref()
            .unwrap()
            .verification_method
            .clone();

        let epoch = applet_registration_epoch_evidence(&receiving.package);
        receiving.package.stamp_registration_epoch(&epoch).unwrap();
        receiving.package.stamp_package_digest().unwrap();
        let controller =
            arkret_identity::verification_method_did(controller_method.as_str()).unwrap();
        let signer = Ed25519PayloadSigner::from_did_key_seed(
            [13; 32],
            controller,
            controller_method.clone(),
        );
        receiving.package.sign(&signer, &controller_method).unwrap();
        factory
            .packages
            .lock()
            .await
            .insert(candidate.applet_id.to_string(), receiving.package.clone());
        let install = factory
            .prepare_install(&candidate.applet_id, "realm-native-control")
            .await;
        let applets = PgAppletStore {
            pool: fixture.pool.clone(),
        };
        install.commit(&applets).await.unwrap();
        let record = applets
            .get(
                candidate.applet_id.as_str(),
                install.input.package.service_id.as_str(),
                &coland_storage::applet_effective_scope_key(&install.effective_scope).unwrap(),
            )
            .await
            .unwrap()
            .unwrap();
        let registration: Event =
            serde_json::from_value(record["registration_event"].clone()).unwrap();
        let grant = fixture.admin_event(
            EventKind::CapabilityGrant,
            ScopeRef::Realm {
                realm_id: fixture.realm.clone(),
            },
            json!({"grant":{"schema":"ak.schema.capability.v1","realm_id":fixture.realm,
                "issuer_id":ActorId::account(fixture.pcr.history.account.clone()),
                "subject":ActorId::service(receiving.package.service_id.clone()),
                "actions":["ak.realm.actor.manager.change"],
                "resources":[{"kind":"realm_actor","actor_id":actor}],"constraints":[],
                "issuer_authority_refs":[{"kind":"realm_root","realm_id":fixture.realm,
                    "authority_event_ref":fixture.authority_event_ref,"authority_generation":0}],
                "issued_at":arkret_canonical::format_timestamp_canonical(chrono::Utc::now())}}),
        );
        let grant_request = SelfAuthoritySubmitRequest::Event(
            arkret_wire::EventAdmissionSubmission::new(grant.clone()),
        );
        let (status, response) = fixture
            .admin_post(
                "/_arkret/self/events",
                arkret_wire::ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT_V1,
                &json!(grant_request),
                None,
            )
            .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "receiving Service management grant: {response}"
        );
        let mut entries = native.actor_log.lock().unwrap().clone();
        let mut document = entries.last().unwrap()["state"].clone();
        let method = &control.control_method_kid;
        document["verificationMethod"]
            .as_array_mut()
            .unwrap()
            .retain(|entry| entry["id"] == json!(method));
        document["assertionMethod"] = json!([method]);
        document["authentication"] = json!([method]);
        for (seed, next) in [(46u8, 47u8), (47, 48)] {
            let previous_time: chrono::DateTime<chrono::Utc> =
                entries.last().unwrap()["versionTime"]
                    .as_str()
                    .unwrap()
                    .parse()
                    .unwrap();
            let rotation = arkret_signatures::webvh::prepare_service_rotation(
                &arkret_signatures::webvh::ServiceRotationInput {
                    did: control.resolution.did.as_str(),
                    previous_entries: &entries,
                    state: &document,
                    current_update_seed: &[seed; 32],
                    next_update_public_key_multibase:
                        &arkret_canonical::ed25519_pubkey_to_did_key_multibase(
                            SigningKey::from_bytes(&[next; 32])
                                .verifying_key()
                                .as_bytes(),
                        ),
                    version_time: std::cmp::max(
                        chrono::Utc::now(),
                        previous_time + chrono::Duration::seconds(1),
                    ),
                },
            )
            .unwrap();
            entries.push(rotation.log_entry);
        }
        let last = entries.last().unwrap();
        let published_at: chrono::DateTime<chrono::Utc> =
            last["versionTime"].as_str().unwrap().parse().unwrap();
        if let Ok(delay) = (published_at - chrono::Utc::now()).to_std() {
            tokio::time::sleep(delay).await;
        }
        let head = canonical_sha256(last).unwrap();
        let version = last["versionId"].as_str().unwrap().to_owned();
        let did_document: DidDocument = serde_json::from_value(document).unwrap();
        let evidence = ResolutionMethodHistoryEvidence::WebvhLog {
            boundary: ResolutionMethodEvidenceBoundary {
                from_method_history_head: candidate.initial_resolution.method_history_head.clone(),
                from_version_id: candidate.initial_resolution.version_id.clone(),
                to_method_history_head: head.clone(),
                to_version_id: version.clone(),
            },
            evidence: ResolutionDidBindingEvidenceReceipt {
                kind: ResolutionDidBindingEvidenceKind::AkDidBindingEvidenceV1,
                method: "webvh".into(),
                document_digest: normalized_did_document_digest(&did_document).unwrap(),
                method_proofs: vec![ResolutionDidBindingMethodProof {
                    kind: ResolutionDidBindingMethodProofKind::WebvhLog,
                    history_head: head.clone(),
                    witnesses: vec![],
                    witness_proofs_digest: Hash::new(
                        canonical_sha256(&Vec::<Value>::new()).unwrap(),
                    )
                    .unwrap(),
                }],
            },
            log_entries: entries.clone(),
            witness_records: vec![],
        };
        *native.actor_log.lock().unwrap() = entries;
        let revision = |reference: &CommittedEventRef| CurrentRevision {
            commit_id: reference.commit_id.clone(),
            stream_position: reference.stream_position,
        };
        let at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
        let transcript = RealmActorManagerAcceptanceTranscript {
            actor_id: actor.clone(),
            applet_id: candidate.applet_id.clone(),
            expected_manager_revision: revision(&manager_ref),
            expected_control_revision: revision(&control_ref),
            expected_device_generation_revision: revision(&generation_ref),
            expected_generation: generation,
            new_generation: generation + 1,
            new_service_id: receiving.package.service_id.clone(),
            new_registration_ref: registration.event_id,
            management_authorization_ref: arkret_wire::GrantId::from_event_id(&grant.event_id),
            next_resolution: ResolutionCommitment {
                did: control.resolution.did.clone(),
                version_id: version,
                method_history_head: head,
            },
            method_history_evidence: serde_json::from_value(json!(evidence)).unwrap(),
        };
        let signature = sign_detached_object(
            &transcript,
            DetachedSignatureContext::RealmActorManagerAcceptance,
            receiving.package.webhook_auth.key_ref.clone(),
            at,
            &applet_service_signing_key(&receiving.package.webhook_auth.key_ref),
        )
        .unwrap();
        let mut value = json!(transcript);
        value.as_object_mut().unwrap().remove("actor_id");
        value.as_object_mut().unwrap().remove("applet_id");
        value["new_service_signature"] = json!(signature);
        let payload: RealmActorManagerChangePayload = serde_json::from_value(value).unwrap();
        let author = |payload: RealmActorManagerChangePayload| {
            let intent = arkret_event_draft::TypedEventDraft::<
                arkret_wire::event_spec::RealmActorManagerChange,
            >::new(
                ScopeRef::RealmControl {
                    realm_id: fixture.realm.clone(),
                },
                actor.clone(),
                payload,
            )
            .unwrap()
            .with_applet_id(candidate.applet_id.clone())
            .into_intent(at)
            .unwrap();
            let mut authored = intent
                .author_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
                .unwrap();
            let signer = Ed25519PayloadSigner::new(
                SigningKey::from_bytes(&[55; 32]),
                control.resolution.did.clone(),
                method.clone(),
            );
            arkret_signatures::sign_event(
                &mut authored,
                &signer,
                arkret_signatures::SignEventOptions::new().with_created_at(at),
            )
            .unwrap();
            authored.into_event()
        };
        let before = snapshot(fixture, actor).await;
        let mut wrong = payload.clone();
        wrong.expected_manager_revision.stream_position += 1;
        let rejected = author(wrong);
        let request = SelfAuthoritySubmitRequest::Event(
            arkret_wire::EventAdmissionSubmission::new(rejected.clone()),
        );
        let (status, _) = control_post_with_seed(
            fixture,
            &metadata(),
            method,
            "/_arkret/self/events",
            arkret_wire::ServiceOperationId::SelfEventsCommandSubmitV1,
            &json!(request),
            &[55; 32],
        )
        .await;
        assert_ne!(status, StatusCode::OK);
        assert_eq!(
            snapshot(fixture, actor).await,
            before,
            "failed handover has zero current writes"
        );
        assert!(
            fixture
                .state
                .test_persistence()
                .authority_commits()
                .committed_event(&rejected.event_id)
                .await
                .unwrap()
                .is_none()
        );
        let event = author(payload);
        let request = SelfAuthoritySubmitRequest::Event(
            arkret_wire::EventAdmissionSubmission::new(event.clone()),
        );
        let (status, response) = control_post_with_seed(
            fixture,
            &metadata(),
            method,
            "/_arkret/self/events",
            arkret_wire::ServiceOperationId::SelfEventsCommandSubmitV1,
            &json!(request),
            &[55; 32],
        )
        .await;
        assert_eq!(status, StatusCode::OK, "manager handover: {response}");
        let after = snapshot(fixture, actor).await;
        assert_eq!(
            after["realm_actor_manager"]["service_id"],
            json!(receiving.package.service_id)
        );
        assert_eq!(after["realm_actor_statusowner"], "paused");
        assert_eq!(
            after["realm_actor_statusgovernance"],
            before["realm_actor_statusgovernance"]
        );
        assert_eq!(
            after["realm_actor_device_generation"]["current_device_generation_ref"],
            generation + 1
        );
        assert_eq!(
            after["realm_actor_recovery"],
            before["realm_actor_recovery"]
        );
        let replay_metadata = RealmActorControlHttpMetadata {
            control_ref: actor_current_ref(
                fixture,
                actor,
                json!({"kind":"realm_actor_control","actor_id":actor}),
            )
            .await,
            ..metadata()
        };
        let (status, response) = control_post_with_seed(
            fixture,
            &replay_metadata,
            method,
            "/_arkret/self/events",
            arkret_wire::ServiceOperationId::SelfEventsCommandSubmitV1,
            &json!(request),
            &[55; 32],
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "handover exact retry under the accepted new control: {response}"
        );
        assert_eq!(snapshot(fixture, actor).await, after);
        let before_stale_ack = boxed_step(|| native_business_footprint(fixture)).await;
        let stale_ack = fixture
            .state
            .test_persistence()
            .applets()
            .acknowledge_authoring_completion(
                &original_completion.applet_id,
                &original_completion.request_digest,
                &original_completion.idempotency_key,
                chrono::Utc::now(),
            )
            .await
            .unwrap_err();
        assert!(
            matches!(stale_ack, coland_storage::PersistenceError::NotFound(_)),
            "{stale_ack}"
        );
        assert_eq!(
            boxed_step(|| native_business_footprint(fixture)).await,
            before_stale_ack,
            "a former manager's in-flight delivery ACK cannot terminate its retained creation task"
        );
        assert!(
            super::completion_application(&fixture.state)
                .prepare_applet_authoring_completion(
                    &original_completion,
                    &fixture.state.service_core_id(),
                    &notary_method,
                    fixture.state.notary_signing_key().as_ref(),
                )
                .await
                .is_err(),
            "even an unexpired cached body must reprove today's manager"
        );
        assert!(
            !fixture
                .state
                .test_persistence()
                .applets()
                .pending_authoring_completions(128)
                .await
                .unwrap()
                .iter()
                .any(|task| task.request_digest == original_completion.request_digest),
            "a former manager's task cannot starve eligible current-manager tasks"
        );
        for (package, expected) in [
            (&native.package, StatusCode::NOT_FOUND),
            (&receiving.package, StatusCode::OK),
        ] {
            let request = RealmActorMaterialRequest::Current {
                actor_id: actor.clone(),
                request_nonce: arkret_canonical::base64url_encode(rand::random::<[u8; 32]>()),
                selectors: vec![
                    serde_json::from_value(json!({"kind":"realm_actor_manager","actor_id":actor}))
                        .unwrap(),
                ],
            };
            let (status, body) = fixture
                .service_post(
                    package,
                    "/_arkret/self/realm-actors/material",
                    arkret_wire::ServiceOperationId::SelfRealmActorReadMaterialV1.as_str(),
                    &json!(request),
                    "manager-current-after-transfer",
                )
                .await;
            assert_eq!(
                status, expected,
                "only current manager may read current private identity: {body}"
            );
        }
    }

    async fn snapshot(fixture: &Fixture, actor: &ActorId) -> Value {
        use diesel::sql_query;
        use diesel::sql_types::{Jsonb, Text};
        use diesel_async::RunQueryDsl as _;
        #[derive(diesel::QueryableByName)]
        struct Row {
            #[diesel(sql_type=Jsonb)]
            value: Value,
        }
        let mut conn = fixture.pool.get().await.unwrap();
        sql_query("SELECT jsonb_object_agg(selector->>'kind'||COALESCE(selector->>'gate',''),value) AS value FROM realm_actor_current_results WHERE realm_id=$1 AND actor_id=$2")
            .bind::<Text,_>(fixture.realm.as_str()).bind::<Jsonb,_>(json!(actor)).get_result::<Row>(&mut conn).await.unwrap().value
    }
    async fn current_revision(fixture: &Fixture, actor: &ActorId, kind: &str) -> Value {
        use diesel::sql_query;
        use diesel::sql_types::{Jsonb, Text};
        use diesel_async::RunQueryDsl as _;
        #[derive(diesel::QueryableByName)]
        struct Row {
            #[diesel(sql_type=Jsonb)]
            value: Value,
        }
        let mut conn = fixture.pool.get().await.unwrap();
        sql_query("SELECT jsonb_build_object('commit_id',current_commit_id,'stream_position',current_stream_position) AS value FROM realm_actor_current_results WHERE realm_id=$1 AND actor_id=$2 AND selector->>'kind'=$3")
            .bind::<Text,_>(fixture.realm.as_str()).bind::<Jsonb,_>(json!(actor)).bind::<Text,_>(kind).get_result::<Row>(&mut conn).await.unwrap().value
    }

    async fn governance(
        fixture: &Fixture,
        native: &NativeService,
        candidate: &arkret_models_integration::RealmActorCreatePayload,
        creation: &arkret_wire::RealmCommit,
    ) -> arkret_wire::GrantId {
        use arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequest;
        let admin = ActorId::account(fixture.pcr.history.account.clone());
        let permission = fixture.admin_event(EventKind::CapabilityGrant,
            ScopeRef::Realm { realm_id: fixture.realm.clone() }, json!({"grant":{
                "schema":"ak.schema.capability.v1","realm_id":fixture.realm,"issuer_id":admin,"subject":admin,
                "actions":["ak.realm.actor.manage"],"resources":[{"kind":"realm_actor","actor_id":candidate.actor_id}],"constraints":[],
                "issuer_authority_refs":[{"kind":"realm_root","realm_id":fixture.realm,"authority_event_ref":fixture.authority_event_ref,"authority_generation":0}],
                "issued_at":arkret_canonical::format_timestamp_canonical(chrono::Utc::now())}}));
        let grant = arkret_wire::GrantId::from_event_id(&permission.event_id);
        let command = |kind, payload| {
            let mut event = fixture.admin_event(
                kind,
                ScopeRef::RealmControl {
                    realm_id: fixture.realm.clone(),
                },
                payload,
            );
            event.authorization_ref = Some(grant.clone().into());
            fixture.sign_admin(event)
        };
        let pause = command(
            EventKind::RealmActorStatusSet,
            json!({
                "target_actor_id":candidate.actor_id,"gate":"governance","state":"paused",
                "expected_revision":{"commit_id":creation.commit_id,"stream_position":creation.stream_position}
            }),
        );
        let send = |event: Event| async move {
            fixture
                .admin_post_network(
                    "/_arkret/self/events",
                    arkret_wire::ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT_V1,
                    &json!(SelfAuthoritySubmitRequest::Event(
                        arkret_wire::EventAdmissionSubmission::new(event)
                    )),
                    "governance-control",
                )
                .await
        };
        let before = snapshot(fixture, &candidate.actor_id).await;
        let (status, _) = send(pause.clone()).await;
        assert_ne!(
            status,
            StatusCode::OK,
            "root label alone must not replace the explicit target grant"
        );
        assert_eq!(before, snapshot(fixture, &candidate.actor_id).await);
        accepted_admin_domain_event(fixture, permission).await;
        let audit_request: RealmActorMaterialRequest = serde_json::from_value(json!({
            "purpose":"current", "actor_id":candidate.actor_id,
            "request_nonce":arkret_canonical::base64url_encode(rand::random::<[u8;32]>()),
            "selectors":[{"kind":"realm_actor_recovery","actor_id":candidate.actor_id}]
        }))
        .unwrap();
        let (status, _) = fixture
            .admin_post_network(
                "/_arkret/self/realm-actors/material",
                arkret_wire::ServiceOperationId::SELF_REALM_ACTOR_READ_MATERIAL_V1,
                &json!(audit_request),
                "governance-audit",
            )
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "manage does not imply audit");
        let audit_permission = fixture.admin_event(EventKind::CapabilityGrant,
            ScopeRef::Realm { realm_id: fixture.realm.clone() }, json!({"grant":{
                "schema":"ak.schema.capability.v1","realm_id":fixture.realm,"issuer_id":admin,"subject":admin,
                "actions":["ak.realm.actor.audit"],"resources":[{"kind":"realm_actor","actor_id":candidate.actor_id}],"constraints":[],
                "issuer_authority_refs":[{"kind":"realm_root","realm_id":fixture.realm,"authority_event_ref":fixture.authority_event_ref,"authority_generation":0}],
                "issued_at":arkret_canonical::format_timestamp_canonical(chrono::Utc::now())}}));
        accepted_admin_domain_event(fixture, audit_permission).await;
        let (status, response) = fixture
            .admin_post_network(
                "/_arkret/self/realm-actors/material",
                arkret_wire::ServiceOperationId::SELF_REALM_ACTOR_READ_MATERIAL_V1,
                &json!(audit_request),
                "governance-audit",
            )
            .await;
        assert_eq!(status, StatusCode::OK, "explicit Account audit: {response}");
        let material: RealmActorMaterialOutcome = serde_json::from_value(response).unwrap();
        material
            .validate_for_request(&audit_request, &admin, chrono::Utc::now())
            .unwrap();
        let (status, response) = send(pause.clone()).await;
        assert_eq!(status, StatusCode::OK, "governance pause: {response}");
        let source = fixture
            .state
            .test_persistence()
            .authority_commits()
            .committed_event(&pause.event_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            snapshot(fixture, &candidate.actor_id).await["realm_actor_statusgovernance"],
            "paused"
        );
        assert!(
            fixture
                .state
                .test_persistence()
                .projection_events()
                .get(pause.event_id.as_str())
                .await
                .unwrap()
                .is_none(),
            "private control must never produce member projections"
        );
        let owner_attempt = command(
            EventKind::RealmActorStatusSet,
            json!({
                "target_actor_id":candidate.actor_id,"gate":"owner","state":"paused",
                "expected_revision":{"commit_id":creation.commit_id,"stream_position":creation.stream_position}
            }),
        );
        let (status, _) = send(owner_attempt.clone()).await;
        assert_ne!(
            status,
            StatusCode::OK,
            "Account management must not impersonate the owner control key"
        );
        assert!(
            fixture
                .state
                .test_persistence()
                .authority_commits()
                .committed_event(&owner_attempt.event_id)
                .await
                .unwrap()
                .is_none()
        );
        let recovery_revision =
            current_revision(fixture, &candidate.actor_id, "realm_actor_recovery").await;
        let disable = command(
            EventKind::RealmActorRecoverySet,
            json!({
                "target_actor_id":candidate.actor_id,"enabled":false,"expected_recovery_revision":recovery_revision,
                "expected_manager_revision":{"commit_id":creation.commit_id,"stream_position":creation.stream_position}
            }),
        );
        let (status, response) = send(disable.clone()).await;
        assert_eq!(status, StatusCode::OK, "disable recovery: {response}");
        let disabled = snapshot(fixture, &candidate.actor_id).await;
        assert_eq!(disabled["realm_actor_recovery"]["enabled"], false);
        let updated_revision =
            current_revision(fixture, &candidate.actor_id, "realm_actor_recovery").await;
        let repeated_value = command(
            EventKind::RealmActorRecoverySet,
            json!({
                "target_actor_id":candidate.actor_id,"enabled":false,"expected_recovery_revision":updated_revision,
                "expected_manager_revision":{"commit_id":creation.commit_id,"stream_position":creation.stream_position}
            }),
        );
        let (status, _) = send(repeated_value.clone()).await;
        assert_ne!(
            status,
            StatusCode::OK,
            "a new no-op Event cannot mint a recovery permission generation"
        );
        assert_eq!(disabled, snapshot(fixture, &candidate.actor_id).await);
        assert!(
            fixture
                .state
                .test_persistence()
                .authority_commits()
                .committed_event(&repeated_value.event_id)
                .await
                .unwrap()
                .is_none()
        );
        let (status, response) = send(disable).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "exact recovery policy replay: {response}"
        );
        let enable = command(
            EventKind::RealmActorRecoverySet,
            json!({
                "target_actor_id":candidate.actor_id,"enabled":true,"expected_recovery_revision":updated_revision,
                "expected_manager_revision":{"commit_id":creation.commit_id,"stream_position":creation.stream_position}
            }),
        );
        let (status, response) = send(enable.clone()).await;
        assert_eq!(status, StatusCode::OK, "enable recovery: {response}");
        boxed_step(|| {
            service_recovery_source_after_reenable(fixture, native, candidate, creation, &enable)
        })
        .await;
        let resume = command(
            EventKind::RealmActorStatusSet,
            json!({
                "target_actor_id":candidate.actor_id,"gate":"governance","state":"active",
                "expected_revision":{"commit_id":source.commit.commit_id,"stream_position":source.commit.stream_position}
            }),
        );
        let (status, response) = send(resume).await;
        assert_eq!(status, StatusCode::OK, "governance resume: {response}");
        {
            use diesel::sql_types::{Jsonb, Text};
            use diesel_async::RunQueryDsl;
            #[derive(diesel::QueryableByName)]
            struct Disclosure {
                #[diesel(sql_type = Jsonb)]
                value: Value,
            }
            let mut conn = fixture.pool.get().await.unwrap();
            let facts = diesel::sql_query("SELECT jsonb_build_object('private',EXISTS(SELECT 1 FROM realm_actor_private_signer_facts f JOIN canonical_events e ON e.envelope->>'event_id'=f.event_id WHERE f.realm_id=$1 AND e.envelope#>>'{actor_id,kind}'='account'),'ordinary',EXISTS(SELECT 1 FROM agent_producer_signer_keys k JOIN realm_commits c ON c.commit_id=k.commit_id WHERE c.realm_id=$1 AND c.stream_ref->>'kind'='realm_control')) AS value")
                .bind::<Text,_>(fixture.realm.as_str()).get_result::<Disclosure>(&mut *conn).await.unwrap();
            assert_eq!(
                facts.value,
                json!({"private":true,"ordinary":false}),
                "Account governance signer facts stay on the private control stream"
            );
        }
        grant
    }

    async fn service_recovery_source_after_reenable(
        fixture: &Fixture,
        native: &NativeService,
        candidate: &RealmActorCreatePayload,
        creation: &arkret_wire::RealmCommit,
        enable: &Event,
    ) {
        // The Applet did not author the administrator's replacement. Obtain
        // its complete original coordinate solely through the signed API.
        let request: RealmActorMaterialRequest = serde_json::from_value(json!({
            "purpose":"current", "actor_id":candidate.actor_id,
            "request_nonce":arkret_canonical::base64url_encode(rand::random::<[u8;32]>()),
            "selectors":[{"kind":"realm_actor_recovery","actor_id":candidate.actor_id}]
        }))
        .unwrap();
        let (status, response) = fixture
            .service_post(
                &native.package,
                "/_arkret/self/realm-actors/material",
                arkret_wire::ServiceOperationId::SELF_REALM_ACTOR_READ_MATERIAL_V1,
                &json!(request),
                "current-after-admin-recovery-reenable",
            )
            .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "Service current after re-enable: {response}"
        );
        let material: RealmActorMaterialOutcome = serde_json::from_value(response).unwrap();
        material
            .validate_for_request(
                &request,
                &ActorId::service(candidate.service_id.clone()),
                chrono::Utc::now(),
            )
            .unwrap();
        arkret_signatures::detached_object::verify_detached_object_signature(
            &material.signature,
            &arkret_canonical::unsigned_value(&material, &["signature"]).unwrap(),
            DetachedSignatureContext::RealmActorMaterial,
            &arkret_signatures::PublicKeyMaterial::Ed25519Raw {
                bytes: fixture
                    .state
                    .notary_signing_key()
                    .verifying_key()
                    .to_bytes()
                    .to_vec(),
            },
        )
        .unwrap();
        let RealmActorMaterialResult::Current { entries } = &material.result else {
            panic!("current required")
        };
        let RealmActorMaterialCurrentEntry::Present { row, source_ref } = &entries[0] else {
            panic!("recovery must be present")
        };
        let arkret_wire::TypedCurrentRow::Value {
            revision, value, ..
        } = row;
        assert_eq!(value["enabled"], true);
        assert_eq!(source_ref.event_id, enable.event_id);
        assert_ne!(source_ref.event_id, creation.event_ref);
        assert_eq!(source_ref.commit_id, revision.commit_id);
        assert_eq!(source_ref.stream_position, revision.stream_position);
        let request = RealmActorMaterialRequest::Event {
            actor_id: candidate.actor_id.clone(),
            request_nonce: arkret_canonical::base64url_encode(rand::random::<[u8; 32]>()),
            target: source_ref.clone(),
        };
        let (status, response) = fixture
            .service_post(
                &native.package,
                "/_arkret/self/realm-actors/material",
                arkret_wire::ServiceOperationId::SELF_REALM_ACTOR_READ_MATERIAL_V1,
                &json!(request),
                "original-admin-recovery-reenable",
            )
            .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "Service reads actual re-enable original: {response}"
        );
        let material: RealmActorMaterialOutcome = serde_json::from_value(response).unwrap();
        material
            .validate_for_request(
                &request,
                &ActorId::service(candidate.service_id.clone()),
                chrono::Utc::now(),
            )
            .unwrap();
        let RealmActorMaterialResult::Event { event, .. } = material.result else {
            panic!("original required")
        };
        assert_eq!(&event, enable);
    }

    pub(super) struct NetworkStation(tokio::task::JoinHandle<()>);
    impl Drop for NetworkStation {
        fn drop(&mut self) {
            self.0.abort();
        }
    }

    pub(super) async fn network_fixture(pool: PgPool) -> (Fixture, NetworkStation) {
        boxed_step(|| network_fixture_with_optional_seed(pool, None)).await
    }

    pub(super) async fn network_fixture_with_device_seed(
        pool: PgPool,
        seed: [u8; 32],
    ) -> (Fixture, NetworkStation) {
        boxed_step(|| network_fixture_with_optional_seed(pool, Some(seed))).await
    }

    async fn network_fixture_with_optional_seed(
        pool: PgPool,
        seed: Option<[u8; 32]>,
    ) -> (Fixture, NetworkStation) {
        use salvo::conn::rustls::{Keycert, RustlsConfig};
        use salvo::conn::{Acceptor, Listener, TcpListener};
        let _ = rustls::crypto::ring::default_provider().install_default();
        let material = native_tls_material();
        let acceptor = TcpListener::new("127.0.0.1:0")
            .rustls(RustlsConfig::new(
                Keycert::new().cert(material.chain).key(material.key),
            ))
            .bind()
            .await;
        let address = acceptor.holdings()[0]
            .local_addr
            .clone()
            .into_std()
            .unwrap();
        let fixture = Box::pin(Fixture::new_at(
            pool,
            Some(format!("https://{address}")),
            seed,
        ))
        .await;
        let document = fixture
            .state
            .test_persistence()
            .webvh()
            .get_embedded_webvh_document_by_local_id(
                "service",
                &format!(
                    "{}/webvh/service/did.jsonl",
                    fixture.state.config().public_base_url.trim_end_matches('/')
                ),
            )
            .await
            .unwrap();
        assert!(
            document.is_some(),
            "native serving document: {}",
            fixture.state.service_did()
        );
        let mut response = TestClient::get("http://server/webvh/service/did.jsonl")
            .send(&service(fixture.state.clone()))
            .await;
        let status = response.status_code;
        assert_eq!(
            status,
            Some(StatusCode::OK),
            "native hosting {}: {:?}",
            fixture.state.service_did(),
            response.take_string().await
        );
        let state = fixture.state.clone();
        let task = tokio::spawn(async move {
            salvo::Server::new(acceptor).serve(service(state)).await;
        });
        (fixture, NetworkStation(task))
    }

    async fn realm_peer_device_lookup(
        governor: &Fixture,
        account_station: &Fixture,
        candidate: &RealmActorCreatePayload,
    ) {
        use arkret_models_crypto::{
            PeerKeysQueryOutcome, PeerKeysQueryPurpose, PeerKeysQueryRequestBody,
            PeerKeysRelationshipBasis, QueryAccountDeviceSelector,
        };
        let request = PeerKeysQueryRequestBody {
            request_id: arkret_wire::RequestId::new_v7_at(
                chrono::Utc::now().timestamp_millis() as u64
            ),
            requester_account_id: None,
            requester_actor_id: Some(candidate.actor_id.clone()),
            purpose: PeerKeysQueryPurpose::MlsGroupAdmission,
            relationship_basis: PeerKeysRelationshipBasis::RealmMembership {
                realm_id: governor.realm.clone(),
            },
            device_keys: vec![QueryAccountDeviceSelector {
                account_id: account_station.pcr.history.account.clone(),
                device_ids: vec![account_station.pcr.history.founding_device_id.clone()],
            }],
        };
        let (status, value) = peer_keys_post(governor, account_station, &request).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "Realm requester peer device query: {value}"
        );
        let outcome: PeerKeysQueryOutcome = serde_json::from_value(value).unwrap();
        outcome.validate_for_request(&request).unwrap();
        let row = outcome
            .device_keys
            .iter()
            .find(|entry| entry.account_id == account_station.pcr.history.account)
            .unwrap()
            .device_keys
            .get(&account_station.pcr.history.founding_device_id)
            .unwrap();
        row.validate_attestation_binding(
            &account_station.pcr.history.account,
            &account_station.pcr.history.founding_device_id,
        )
        .unwrap();
        arkret_signatures::device_projection::verify_device_projection_attestation(
            &row.device_projection_attestation,
            &account_station.state.notary_signing_key().verifying_key(),
            chrono::Utc::now(),
        )
        .unwrap();
        let mut changed = request.clone();
        changed.purpose = PeerKeysQueryPurpose::CallMedia;
        assert_ne!(
            peer_keys_post(governor, account_station, &changed).await.0,
            StatusCode::OK
        );
        changed = request.clone();
        changed.relationship_basis = PeerKeysRelationshipBasis::Contact {};
        assert_ne!(
            peer_keys_post(governor, account_station, &changed).await.0,
            StatusCode::OK
        );
        changed = request.clone();
        changed.requester_account_id = Some(governor.pcr.history.account.clone());
        assert_ne!(
            peer_keys_post(governor, account_station, &changed).await.0,
            StatusCode::OK
        );
        // A real authenticated Station that does not govern this Realm is refused.
        assert_ne!(
            peer_keys_post(account_station, account_station, &request)
                .await
                .0,
            StatusCode::OK
        );
        changed = request.clone();
        if let Some(ActorId::Realm { realm_actor_id }) = &mut changed.requester_actor_id {
            realm_actor_id.principal_id = governor.pcr.history.account.principal_id.clone();
        }
        let (status, value) = peer_keys_post(governor, account_station, &changed).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "nonmember indistinguishable directory outcome: {value}"
        );
        let unavailable: PeerKeysQueryOutcome = serde_json::from_value(value).unwrap();
        assert!(unavailable.device_keys.is_empty());
        assert!(unavailable.device_generations.is_empty());
        let mut substituted = outcome;
        substituted.requester_actor_id = changed.requester_actor_id;
        assert!(substituted.validate_for_request(&request).is_err());
    }

    async fn cross_station_audit(fixture: &Fixture, candidate: &RealmActorCreatePayload) {
        use arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequest;
        let database = coland_storage_postgres::test_database::TestDatabase::lease().await;
        let (account_station, _server) = network_fixture(database.pool()).await;
        for (reader, destination) in [(&account_station, fixture), (fixture, &account_station)] {
            let service_id = destination.state.service_core_id();
            let hosted = destination
                .state
                .test_persistence()
                .webvh()
                .get_embedded_webvh_document_by_local_id(
                    "service",
                    &format!(
                        "{}/webvh/service/did.jsonl",
                        destination
                            .state
                            .config()
                            .public_base_url
                            .trim_end_matches('/')
                    ),
                )
                .await
                .unwrap()
                .unwrap();
            assert_eq!(
                hosted.did,
                destination.state.service_did().as_str(),
                "cached foreign Service must not replace local hosting"
            );
            let carrier = arkret_models_identity::ServiceResolutionCarrier::ResolutionUrl {
                resolution_url: format!(
                    "{}{}",
                    destination
                        .state
                        .config()
                        .public_base_url
                        .trim_end_matches('/'),
                    arkret_models_identity::canonical_service_resolution_path(&service_id)
                ),
            };
            reader
                .state
                .service_route_resolver()
                .unwrap()
                .resolve_carrier(&carrier, &service_id, "station", chrono::Utc::now())
                .await
                .expect("real peer discovery verifies the supplied endpoint hint");
        }
        assert_ne!(
            account_station.state.service_core_id(),
            fixture.state.service_core_id()
        );
        let requester = ActorId::account(account_station.pcr.history.account.clone());
        let scope = ScopeRef::Realm {
            realm_id: fixture.realm.clone(),
        };
        let invite = fixture.admin_event(EventKind::InviteCreate, scope.clone(), json!({
            "invitee_account_id":account_station.pcr.history.account,
            "introduction_evidence_digest":format!("sha256:{}", "c".repeat(64)),
            "expires_at":arkret_canonical::format_timestamp_canonical(chrono::Utc::now()+chrono::Duration::hours(1))
        }));
        accepted_admin_domain_event(fixture, invite.clone()).await;
        let authority = fixture
            .state
            .test_persistence()
            .authority_commits()
            .current_authority(&fixture.realm)
            .await
            .unwrap()
            .unwrap();
        account_station
            .state
            .test_persistence()
            .authority_commits()
            .record_remote_authority(&authority, &account_station.state.service_core_id())
            .await
            .unwrap();
        let accept = account_station.admin_event(
            EventKind::InviteAccept,
            scope.clone(),
            json!({
                "invite_id":arkret_wire::InviteId::from_event_id(&invite.event_id),
                "previous_state":"pending", "invitee_account_id":account_station.pcr.history.account
            }),
        );
        let (status, response) = account_station
            .admin_post(
                "/_arkret/self/events",
                arkret_wire::ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT_V1,
                &json!(SelfAuthoritySubmitRequest::Event(
                    arkret_wire::EventAdmissionSubmission::new(accept)
                )),
                None,
            )
            .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "foreign Account joins through its real Station: {response}"
        );
        {
            use diesel::sql_types::{Jsonb, Text};
            use diesel_async::RunQueryDsl;
            #[derive(diesel::QueryableByName)]
            struct Disclosure {
                #[diesel(sql_type = Jsonb)]
                value: Value,
            }
            let mut conn = account_station.pool.get().await.unwrap();
            let disclosed = diesel::sql_query("SELECT jsonb_build_object('registration',EXISTS(SELECT 1 FROM replica_authorization_rows WHERE realm_id=$1 AND selector->>'kind'='applet_registration'),'private',EXISTS(SELECT 1 FROM replica_authorization_rows WHERE realm_id=$1 AND (source_stream_ref->>'kind'='realm_control' OR selector->>'kind' LIKE 'realm_actor_%'))) AS value")
                .bind::<Text,_>(fixture.realm.as_str()).get_result::<Disclosure>(&mut *conn).await.unwrap();
            assert_eq!(
                disclosed.value,
                json!({"registration":true,"private":false})
            );
        }
        boxed_step(|| realm_peer_device_lookup(fixture, &account_station, candidate)).await;
        let request = || -> RealmActorMaterialRequest {
            serde_json::from_value(json!({
                "purpose":"current", "actor_id":candidate.actor_id,
                "request_nonce":arkret_canonical::base64url_encode(rand::random::<[u8;32]>()),
                "selectors":[{"kind":"realm_actor_recovery","actor_id":candidate.actor_id}]
            }))
            .unwrap()
        };
        let (status, _) = account_station
            .admin_post(
                "/_arkret/self/realm-actors/material",
                arkret_wire::ServiceOperationId::SELF_REALM_ACTOR_READ_MATERIAL_V1,
                &json!(request()),
                None,
            )
            .await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "membership does not grant private audit"
        );
        let grant = fixture.admin_event(EventKind::CapabilityGrant, scope.clone(), json!({"grant":{
            "schema":"ak.schema.capability.v1","realm_id":fixture.realm,
            "issuer_id":ActorId::account(fixture.pcr.history.account.clone()),"subject":requester,
            "actions":["ak.realm.actor.audit"],"resources":[{"kind":"realm_actor","actor_id":candidate.actor_id}],"constraints":[],
            "issuer_authority_refs":[{"kind":"realm_root","realm_id":fixture.realm,"authority_event_ref":fixture.authority_event_ref,"authority_generation":0}],
            "issued_at":arkret_canonical::format_timestamp_canonical(chrono::Utc::now())}}));
        let grant_id = arkret_wire::GrantId::from_event_id(&grant.event_id);
        let (status, response) = fixture
            .admin_post(
                "/_arkret/self/events",
                arkret_wire::ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT_V1,
                &json!(SelfAuthoritySubmitRequest::Event(
                    arkret_wire::EventAdmissionSubmission::new(grant.clone())
                )),
                None,
            )
            .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "audit grant through real fanout admission: {response}"
        );
        let peer = || arkret_models_integration::PeerRealmActorMaterialRequest {
            requester_account_id: account_station.pcr.history.account.clone(),
            request: request(),
        };
        let valid_peer = peer();
        let (status, response) =
            boxed_step(|| peer_audit_post(&account_station, fixture, &valid_peer, false)).await;
        assert_eq!(status, StatusCode::OK, "real signed peer audit: {response}");
        let mut wrong_source = peer();
        wrong_source.requester_account_id.station_id = fixture.state.service_core_id();
        let (status, _) =
            boxed_step(|| peer_audit_post(&account_station, fixture, &wrong_source, false)).await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "a Station cannot assert another Station's Account"
        );
        let tampered_peer = peer();
        let (status, _) =
            boxed_step(|| peer_audit_post(&account_station, fixture, &tampered_peer, true)).await;
        assert_ne!(
            status,
            StatusCode::OK,
            "modified peer body must fail transport authentication"
        );
        let request = request();
        let (status, response) = account_station
            .admin_post(
                "/_arkret/self/realm-actors/material",
                arkret_wire::ServiceOperationId::SELF_REALM_ACTOR_READ_MATERIAL_V1,
                &json!(request),
                None,
            )
            .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "real two-Station private audit: {response}"
        );
        let material: RealmActorMaterialOutcome = serde_json::from_value(response).unwrap();
        material
            .validate_for_request(&request, &requester, chrono::Utc::now())
            .unwrap();
        assert_eq!(material.governance_generation, authority.generation);
        assert_eq!(material.authority_ref, authority.authority_ref);
        let mut wrong_account = account_station.pcr.history.account.clone();
        wrong_account.station_id = fixture.state.service_core_id();
        let wrong = ActorId::account(wrong_account);
        assert!(
            material
                .validate_for_request(&request, &wrong, chrono::Utc::now())
                .is_err()
        );
        let source = PgAuthorityCommitStore {
            pool: account_station.pool.clone(),
        };
        let authorization = &account_station.pcr.history.commits[1];
        let authorization_ref = CommittedEventRef {
            event_id: authorization.event_ref.clone(),
            commit_id: authorization.commit_id.clone(),
            stream_ref: authorization.stream_ref.clone(),
            stream_position: authorization.stream_position,
        };
        let input = coland_storage::AccountContentDeliveryInput {
            realm_actor_material: Some(Box::new((
                request.clone(),
                material.clone(),
                authority.clone(),
            ))),
            watch_delivery_device: Some(coland_storage::DeviceRevocationGateSelector {
                principal_id: account_station.pcr.history.account.principal_id.clone(),
                station_id: account_station.pcr.history.account.station_id.clone(),
                device_id: account_station.pcr.history.founding_device_id.to_string(),
                authorization_ref,
            }),
            credential_expires_at: Some(chrono::Utc::now() + chrono::Duration::minutes(1)),
            ..Default::default()
        };
        let local = account_station.state.service_core_id();
        let account = &account_station.pcr.history.account;
        let guard = source
            .acquire_committed_content_delivery(account, &local, &input)
            .await
            .unwrap()
            .unwrap();
        assert!(guard.permits_handoff());
        guard.finish().await.unwrap();
        for fault in ["nonce", "audience", "authority", "device", "expired"] {
            let mut rejected = input.clone();
            let (_, response, authority) = rejected.realm_actor_material.as_deref_mut().unwrap();
            match fault {
                "nonce" => response.request_nonce = "Z".repeat(22),
                "audience" => response.requester_actor_id = wrong.clone(),
                "authority" => authority.generation += 1,
                "device" => {
                    rejected
                        .watch_delivery_device
                        .as_mut()
                        .unwrap()
                        .authorization_ref
                        .commit_id = arkret_wire::RealmCommitId::from_digest([91; 32])
                }
                "expired" => {
                    rejected.credential_expires_at =
                        Some(chrono::Utc::now() - chrono::Duration::seconds(1))
                }
                _ => unreachable!(),
            }
            assert!(
                source
                    .acquire_committed_content_delivery(account, &local, &rejected)
                    .await
                    .is_err(),
                "{fault}"
            );
        }
        let original = fixture
            .state
            .test_persistence()
            .authority_commits()
            .committed_event(&grant.event_id)
            .await
            .unwrap()
            .unwrap();
        let revoke = fixture.admin_event(EventKind::CapabilityRevoke, scope, json!({
            "grant_id":grant_id,"expected_revision":{"commit_id":original.commit.commit_id,"stream_position":original.commit.stream_position}
        }));
        let (status, response) = fixture
            .admin_post(
                "/_arkret/self/events",
                arkret_wire::ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT_V1,
                &json!(SelfAuthoritySubmitRequest::Event(
                    arkret_wire::EventAdmissionSubmission::new(revoke)
                )),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "real audit revocation: {response}");
        {
            use diesel::sql_types::{Jsonb, Text};
            use diesel_async::RunQueryDsl;
            #[derive(diesel::QueryableByName)]
            struct Current {
                #[diesel(sql_type=Jsonb)]
                value: Value,
            }
            let mut governor = fixture.pool.get().await.unwrap();
            let current = diesel::sql_query("SELECT jsonb_build_object('selector',jsonb_build_object('kind','capability_grant','grant_id',grant_id),'source_stream_ref',current_stream_ref,'revision',jsonb_build_object('commit_id',current_commit_id,'stream_position',current_stream_position),'value',value) AS value FROM capability_grant_current_results WHERE realm_id=$1 AND grant_id=$2")
                .bind::<Text,_>(fixture.realm.as_str()).bind::<Text,_>(grant_id.as_str()).get_result::<Current>(&mut *governor).await.unwrap();
            let arkret_wire::TypedCurrentRow::Value {
                selector,
                source_stream_ref,
                revision,
                value,
            } = serde_json::from_value(current.value).unwrap();
            assert_eq!(value["status"], "revoked");
            // Inject the actual accepted governor row at the verified replica
            // storage boundary; this assertion tests final delivery, not transport.
            let mut conn = account_station.pool.get().await.unwrap();
            diesel::sql_query("INSERT INTO replica_authorization_rows(realm_id,selector,source_stream_ref,current_commit_id,current_stream_position,value,updated_at) VALUES($1,$2,$3,$4,$5,$6,clock_timestamp()) ON CONFLICT(realm_id,selector) DO UPDATE SET source_stream_ref=EXCLUDED.source_stream_ref,current_commit_id=EXCLUDED.current_commit_id,current_stream_position=EXCLUDED.current_stream_position,value=EXCLUDED.value,updated_at=EXCLUDED.updated_at")
                .bind::<Text,_>(fixture.realm.as_str()).bind::<Jsonb,_>(json!(selector)).bind::<Jsonb,_>(json!(source_stream_ref))
                .bind::<Text,_>(revision.commit_id.as_str()).bind::<diesel::sql_types::BigInt,_>(i64::try_from(revision.stream_position).unwrap()).bind::<Jsonb,_>(value)
                .execute(&mut *conn).await.unwrap();
        }
        let refused = source
            .acquire_committed_content_delivery(account, &local, &input)
            .await;
        assert!(
            matches!(refused, Err(error) if error.to_string().contains("withdrawal observed")),
            "replica withdrawal must fence the earlier response"
        );
        // Inject a subsequently verified tenure at the production storage port.
        // This checks final delivery fencing, not the handoff verifier itself.
        let mut next = authority.clone();
        let handoff = arkret_wire::RealmAuthorityHandoffId::from_digest([92; 32]);
        next.generation += 1;
        next.authority_ref = arkret_wire::RealmCommitAuthorityRef::Handoff(handoff.clone());
        next.last_handoff_ref = Some(handoff);
        source.record_remote_authority(&next, &local).await.unwrap();
        let refused = source
            .acquire_committed_content_delivery(account, &local, &input)
            .await;
        assert!(
            matches!(refused, Err(error) if error.to_string().contains("authority changed")),
            "an observed new tenure fences an otherwise unchanged signed response"
        );
    }

    async fn independent_management_archive(
        fixture: &Fixture,
        manifest: &arkret_models_collaboration::authority_commit::ManagementPrivateHandoffManifest,
        bytes: &[u8],
        archive: &Value,
    ) {
        use diesel_async::{RunQueryDsl, SimpleAsyncConnection};
        #[derive(diesel::QueryableByName)]
        struct Count {
            #[diesel(sql_type=diesel::sql_types::BigInt)]
            count: i64,
        }
        let target = coland_storage_postgres::test_database::TestDatabase::lease().await;
        let target_pool = target.pool();
        boxed_step(|| {
            management_archive_fixture::seed_ordinary(
                &fixture.pool,
                &target_pool,
                archive["tables"].as_object().unwrap(),
            )
        })
        .await;
        let target_store = PgAuthorityCommitStore {
            pool: target_pool.clone(),
        };
        let mut conn = target_pool.get().await.unwrap();
        conn.batch_execute("CREATE FUNCTION test_private_archive_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'private archive write failure'; END $$; CREATE TRIGGER test_private_archive_failure BEFORE INSERT ON realm_actor_current_results FOR EACH ROW EXECUTE FUNCTION test_private_archive_failure();")
            .await.unwrap();
        assert!(
            target_store
                .import_management_private_state(manifest, bytes)
                .await
                .is_err()
        );
        let count=diesel::sql_query("SELECT (SELECT COUNT(*) FROM realm_actor_creations)+(SELECT COUNT(*) FROM canonical_events WHERE scope_ref->>'kind'='realm_control') AS count")
            .get_result::<Count>(&mut *conn).await.unwrap();
        assert_eq!(
            count.count, 0,
            "a mid-import writer failure rolls back original Events and creations"
        );
        conn.batch_execute("DROP TRIGGER test_private_archive_failure ON realm_actor_current_results; DROP FUNCTION test_private_archive_failure();").await.unwrap();
        if !archive["tables"]["realm_actor_blob_uploads"]
            .as_array()
            .unwrap()
            .is_empty()
        {
            for fault in ["device", "scope", "missing_binding"] {
                let mut changed = archive.clone();
                let uploads = changed["tables"]["realm_actor_blob_uploads"]
                    .as_array_mut()
                    .unwrap();
                match fault {
                    "device" => {
                        uploads[0]["device_id"] =
                            json!(format!("ak:device:{}", uuid::Uuid::now_v7()));
                    }
                    "scope" => {
                        uploads[0]["effective_scope"] = json!({
                            "kind":"circle","realm_id":fixture.realm,
                            "circle_id":format!("ak:circle:{}", uuid::Uuid::now_v7())
                        });
                    }
                    "missing_binding" => {
                        uploads.clear();
                    }
                    _ => unreachable!(),
                }
                let altered = arkret_canonical::canonical_json_bytes(&changed).unwrap();
                let mut bad = manifest.clone();
                bad.state_digest =
                    arkret_wire::Hash::new(arkret_canonical::sha256_digest(&altered)).unwrap();
                assert!(
                    target_store
                        .import_management_private_state(&bad, &altered)
                        .await
                        .is_err(),
                    "a fresh target must reject {fault} without a prior binding"
                );
                let count =
                    diesel::sql_query("SELECT COUNT(*) AS count FROM realm_actor_blob_uploads")
                        .get_result::<Count>(&mut *conn)
                        .await
                        .unwrap();
                assert_eq!(count.count, 0, "invalid import must roll back all bindings");
            }
        }
        target_store
            .import_management_private_state(manifest, bytes)
            .await
            .unwrap();
        let (restored, actual) = target_store
            .export_management_private_state(&fixture.realm)
            .await
            .unwrap();
        assert_eq!(restored.state_digest, manifest.state_digest);
        assert_eq!(
            restored.final_stream_heads_digest,
            manifest.final_stream_heads_digest
        );
        assert_eq!(
            actual, bytes,
            "independent database re-export preserves every private original"
        );
        let event = archive["tables"]["canonical_events"][0]["envelope"]["event_id"]
            .as_str()
            .unwrap();
        let mut source = fixture.pool.get().await.unwrap();
        let source_pk = diesel::sql_query(
            "SELECT pk AS count FROM canonical_events WHERE envelope->>'event_id'=$1",
        )
        .bind::<diesel::sql_types::Text, _>(event)
        .get_result::<Count>(&mut *source)
        .await
        .unwrap()
        .count;
        let target_pk = diesel::sql_query(
            "SELECT pk AS count FROM canonical_events WHERE envelope->>'event_id'=$1",
        )
        .bind::<diesel::sql_types::Text, _>(event)
        .get_result::<Count>(&mut *conn)
        .await
        .unwrap()
        .count;
        assert_ne!(
            source_pk, target_pk,
            "portable originals must not depend on the source database surrogate"
        );
        target_store
            .import_management_private_state(manifest, bytes)
            .await
            .unwrap();
    }

    async fn private_management_archive(fixture: &Fixture, has_blob: bool) {
        use arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequest;
        let store = PgAuthorityCommitStore {
            pool: fixture.pool.clone(),
        };
        assert!(
            store
                .export_management_private_state(&fixture.realm)
                .await
                .is_err(),
            "a live governor must not export a supposedly frozen archive"
        );
        let stream = arkret_wire::CommitStreamRef::Realm {
            realm_id: fixture.realm.clone(),
        };
        let head = store.stream_head(&stream).await.unwrap().unwrap();
        let authority = store
            .current_authority(&fixture.realm)
            .await
            .unwrap()
            .unwrap();
        let change = fixture.admin_event(
            EventKind::RealmGovernanceStationChange,
            ScopeRef::Realm {
                realm_id: fixture.realm.clone(),
            },
            json!({
                "expected_governance_generation":authority.generation,
                "expected_realm_stream_commit_id":head.commit_id,
                "new_governance_station_id":"ak:did_core:web:archive-next.example"
            }),
        );
        let (status, response) = fixture
            .admin_post(
                "/_arkret/self/events",
                arkret_wire::ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT_V1,
                &json!(SelfAuthoritySubmitRequest::Event(
                    arkret_wire::EventAdmissionSubmission::new(change)
                )),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "freeze actual Realm: {response}");
        let (manifest, bytes) = store
            .export_management_private_state(&fixture.realm)
            .await
            .unwrap();
        manifest.validate().unwrap();
        let archive: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            archive["tables"]["realm_actor_creations"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        assert!(
            !archive["tables"]["realm_actor_private_signer_facts"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        if has_blob {
            assert!(
                !archive["tables"]["realm_actor_blob_uploads"]
                    .as_array()
                    .unwrap()
                    .is_empty()
            );
        } else {
            assert!(
                !archive["tables"]["realm_actor_device_revoke_results"]
                    .as_array()
                    .unwrap()
                    .is_empty()
            );
        }
        store
            .import_management_private_state(&manifest, &bytes)
            .await
            .unwrap();
        boxed_step(|| independent_management_archive(fixture, &manifest, &bytes, &archive)).await;
        if has_blob {
            let mut changed = archive.clone();
            changed["tables"]["realm_actor_blob_uploads"][0]["device_id"] =
                json!(format!("ak:device:{}", uuid::Uuid::now_v7()));
            let bytes = arkret_canonical::canonical_json_bytes(&changed).unwrap();
            let mut bad = manifest.clone();
            bad.state_digest =
                arkret_wire::Hash::new(arkret_canonical::sha256_digest(&bytes)).unwrap();
            assert!(
                store
                    .import_management_private_state(&bad, &bytes)
                    .await
                    .is_err(),
                "handoff must not rewrite an original upload binding"
            );
        }
        for fault in [
            "missing_domain",
            "extra_domain",
            "changed_current",
            "missing_event",
        ] {
            let mut changed = archive.clone();
            match fault {
                "missing_domain" => {
                    changed["tables"]
                        .as_object_mut()
                        .unwrap()
                        .remove("realm_actor_control_nonces");
                }
                "extra_domain" => {
                    changed["tables"]["private_keys"] = json!([]);
                }
                "changed_current" => {
                    changed["tables"]["realm_actor_current_results"][0]["value"] = json!(null);
                }
                "missing_event" => {
                    changed["tables"]["canonical_events"]
                        .as_array_mut()
                        .unwrap()
                        .pop();
                }
                _ => unreachable!(),
            }
            let changed = arkret_canonical::canonical_json_bytes(&changed).unwrap();
            let mut bad = manifest.clone();
            bad.state_digest =
                arkret_wire::Hash::new(arkret_canonical::sha256_digest(&changed)).unwrap();
            assert!(
                store
                    .import_management_private_state(&bad, &changed)
                    .await
                    .is_err(),
                "{fault}"
            );
            let (after, actual) = store
                .export_management_private_state(&fixture.realm)
                .await
                .unwrap();
            assert_eq!(
                after.state_digest, manifest.state_digest,
                "{fault} changed durable state"
            );
            assert_eq!(actual, bytes);
        }
    }

    async fn blob_upload_guard(
        fixture: &Fixture,
        package: &AppletPackage,
        device: &arkret_bridge_runtime::managed_device::ManagedDevice,
        expires_at: chrono::DateTime<chrono::Utc>,
    ) -> Box<dyn coland_storage::AccountContentDeliveryGuard> {
        let persistence = fixture.state.test_persistence();
        let authority = persistence
            .device_revocations()
            .applet_managed_device_authority(
                &device.actor_id,
                &device.device_id,
                chrono::Utc::now(),
            )
            .await
            .unwrap()
            .unwrap();
        let input = coland_storage::AccountContentDeliveryInput {
            realms: vec![fixture.realm.clone()],
            native_blob_upload: Some(fixture.realm.clone()),
            credential_expires_at: Some(expires_at),
            applet_endpoint: Some(coland_storage::AppletManagedDeviceScopeGuard {
                authority,
                effective_scope: device.effective_scope().clone(),
                service_did_document: applet_service_id_document(package),
            }),
            ..Default::default()
        };
        persistence
            .authority_commits()
            .acquire_realm_actor_content_delivery(
                &device.actor_id,
                &fixture.state.service_core_id(),
                &input,
            )
            .await
            .unwrap()
            .unwrap()
    }

    async fn commit_install_http(
        fixture: &Fixture,
        install: &AppletFormalCommitUnit,
    ) -> AppletInstallOutcome {
        let body = serde_json::to_value(&install.input.request).unwrap();
        let (status, outcome) = boxed_step(|| {
            fixture.admin_post(
                "/_arkret/self/applets/install",
                arkret_wire::ServiceOperationId::SELF_APPLET_COMMAND_INSTALL_V1,
                &body,
                Some(&install.input.idempotency_key),
            )
        })
        .await;
        assert_eq!(
            status,
            StatusCode::CREATED,
            "actual scope installation: {outcome}"
        );
        serde_json::from_value(outcome).unwrap()
    }

    #[derive(Clone, Copy)]
    pub(super) enum RecoveryScenario {
        Continue,
        CancelBeforePublish,
        ReplaceBeforePublish,
        CloseUnaccepted,
        UnacceptedControl,
        AcceptedControl,
    }

    pub(super) fn run_bridge(
        pool: PgPool,
        circle: bool,
        bot: bool,
        rotate_during_reply: bool,
        recovery_scenario: Option<RecoveryScenario>,
    ) -> impl std::future::Future<Output = ()> {
        run_bridge_case(
            pool,
            circle,
            bot,
            rotate_during_reply,
            recovery_scenario,
            false,
            0,
            false,
        )
    }

    async fn resume_runtime_after_handoff(
        fixture: &Fixture,
        device: &arkret_bridge_runtime::managed_device::ManagedDevice,
        actor: &ActorId,
        make_edge: &impl Fn() -> Arc<arkret_bridge_runtime::ArkretEdge>,
    ) {
        use arkret_bridge_runtime::managed_device::ManagedDeviceRuntime;
        let database =
            boxed_step(coland_storage_postgres::test_database::TestDatabase::lease).await;
        let (next, _next_server) = boxed_step(|| network_fixture(database.pool())).await;
        let _group = boxed_step(|| {
            realm_actor_mls_fixture::human_admits_runtime_after_handoff(fixture, device, &next)
        })
        .await;
        // Restart the real runtime against its own untouched private store.
        // Only governance state moved; no Applet keys or MLS secrets were imported.
        let cold = ManagedDeviceRuntime::new(make_edge()).unwrap();
        let restored = boxed_step(|| cold.device_for_actor(actor)).await.unwrap();
        assert_eq!(restored.device_id, device.device_id);
        assert_eq!(restored.authorization_commit, device.authorization_commit);
        assert_eq!(restored.governance_generation, 1);
        assert_eq!(restored.governance_station, next.state.service_core_id());
        let current_reader = boxed_step(|| cold.open_reader(&restored)).await.unwrap();
        let progress = boxed_step(|| cold.poll_welcome_queue(&restored, &current_reader))
            .await
            .unwrap();
        assert_eq!(progress.durable_welcomes, 1);
        assert!(progress.acknowledged);
        assert_eq!(cold.installed_mls_epoch(&restored).await.unwrap(), Some(1));
        let reopened = ManagedDeviceRuntime::new(make_edge()).unwrap();
        let restored = boxed_step(|| reopened.device_for_actor(actor))
            .await
            .unwrap();
        let current_reader = boxed_step(|| reopened.open_reader(&restored))
            .await
            .unwrap();
        let replay = boxed_step(|| reopened.poll_welcome_queue(&restored, &current_reader))
            .await
            .unwrap();
        assert_eq!(replay.durable_welcomes, 0);
        assert_eq!(
            reopened.installed_mls_epoch(&restored).await.unwrap(),
            Some(1)
        );
    }

    pub(super) async fn run_bridge_recipient_mode(pool: PgPool, circle: bool, mode: u8) {
        run_bridge_case(pool, circle, false, false, None, false, mode, false).await;
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "The fixture keeps independent signed originals, accepted references and source-time coordinates explicit."
    )]
    pub(super) async fn run_bridge_case(
        pool: PgPool,
        circle: bool,
        bot: bool,
        rotate_during_reply: bool,
        recovery_scenario: Option<RecoveryScenario>,
        governance_handoff: bool,
        recipient_mode: u8,
        manager_transfer: bool,
    ) {
        use arkret_bridge_runtime::managed_actor_authoring::ManagedActorAuthoringService;
        use arkret_bridge_runtime::managed_device::ManagedDeviceRuntime;
        use arkret_bridge_runtime::{
            ArkretEdge, AuthoringJournal, AuthoringStore, FileAuthoringStore, PreparedGhost,
        };
        use coland_storage::MlsGroupCurrentStore as _;
        struct LostDeviceReceipt {
            inner: FileAuthoringStore,
            armed: Arc<std::sync::atomic::AtomicBool>,
            authorization_armed: Arc<std::sync::atomic::AtomicBool>,
            control_armed: Arc<std::sync::atomic::AtomicBool>,
            control_plan_skip: Arc<std::sync::atomic::AtomicUsize>,
            fail_after_control_plan: bool,
            recipient_fault: Arc<NativeRecipientStoreFault>,
            runtime_fault: Arc<NativeRuntimeRecoveryFault>,
        }
        impl AuthoringStore for LostDeviceReceipt {
            fn load(&self, key: &str) -> arkret_bridge_runtime::Result<Option<String>> {
                self.inner.load(key)
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
                if self.fail_after_control_plan
                    && expected.iter().any(|(key, value)| {
                        key.starts_with("managed-control/v1/") && value.is_none()
                    })
                    && self
                        .control_armed
                        .swap(false, std::sync::atomic::Ordering::SeqCst)
                {
                    let written = self.inner.compare_exchange_batch(expected, writes)?;
                    assert!(written, "the first recovery plan must become durable");
                    return Err(arkret_bridge_runtime::BridgeError::App(
                        "injected crash after initial recovery plan persistence".into(),
                    ));
                }
                self.recipient_fault
                    .before_compare_exchange(expected, writes, &self.inner)?;
                self.runtime_fault
                    .before_compare_exchange(expected, writes, &self.inner)?;
                if expected.iter().any(|(key, value)| {
                    key.starts_with("managed-device-revocation/v1/") && value.is_some()
                }) && self.armed.swap(false, std::sync::atomic::Ordering::SeqCst)
                {
                    return Err(arkret_bridge_runtime::BridgeError::App(
                        "injected crash before revoke receipt persistence".into(),
                    ));
                }
                if expected
                    .iter()
                    .any(|(key, value)| key.starts_with("managed-device/v1/") && value.is_some())
                    && self
                        .authorization_armed
                        .swap(false, std::sync::atomic::Ordering::SeqCst)
                {
                    return Err(arkret_bridge_runtime::BridgeError::App(
                        "injected crash before authorization receipt persistence".into(),
                    ));
                }
                if expected.iter().any(|(key, value)| {
                    (key.starts_with("managed-control/v1/")
                        || key.starts_with("managed-owner-status/v1/"))
                        && value.is_some()
                }) && self.control_armed.load(std::sync::atomic::Ordering::SeqCst)
                {
                    if self
                        .control_plan_skip
                        .fetch_update(
                            std::sync::atomic::Ordering::SeqCst,
                            std::sync::atomic::Ordering::SeqCst,
                            |count| count.checked_sub(1),
                        )
                        .is_ok()
                    {
                        return self.inner.compare_exchange_batch(expected, writes);
                    }
                    self.control_armed
                        .store(false, std::sync::atomic::Ordering::SeqCst);
                    return Err(arkret_bridge_runtime::BridgeError::App(
                        "injected crash before control receipt persistence".into(),
                    ));
                }
                self.inner.compare_exchange_batch(expected, writes)
            }
        }
        async fn control_nonce_count(pool: &PgPool, actor: &ActorId) -> i64 {
            use diesel_async::RunQueryDsl as _;
            #[derive(diesel::QueryableByName)]
            struct Count {
                #[diesel(sql_type = diesel::sql_types::BigInt)]
                count: i64,
            }
            diesel::sql_query(
                "SELECT COUNT(*) AS count FROM realm_actor_control_nonces WHERE actor_id=$1",
            )
            .bind::<diesel::sql_types::Jsonb, _>(json!(actor))
            .get_result::<Count>(&mut pool.get().await.unwrap())
            .await
            .unwrap()
            .count
        }
        #[allow(
            clippy::too_many_arguments,
            reason = "The fixture keeps independent signed originals, accepted references and source-time coordinates explicit."
        )]
        async fn recover_runtime_key_loss(
            fixture: &Fixture,
            native: &NativeService,
            candidate: &RealmActorCreatePayload,
            edge: Arc<ArkretEdge>,
            devices: ManagedDeviceRuntime,
            author: ManagedActorAuthoringService,
            path: std::path::PathBuf,
            lost_control: Arc<std::sync::atomic::AtomicBool>,
            control_plan_skip: Arc<std::sync::atomic::AtomicUsize>,
            make_edge: impl Fn() -> Arc<ArkretEdge>,
            scenario: RecoveryScenario,
        ) {
            let actor = candidate.actor_id.clone();
            let unaccepted = matches!(scenario, RecoveryScenario::CloseUnaccepted);
            let pending_control = matches!(
                scenario,
                RecoveryScenario::UnacceptedControl | RecoveryScenario::AcceptedControl
            );
            let control_was_accepted = matches!(scenario, RecoveryScenario::AcceptedControl);
            let original = edge
                .installed_managed_authoring(&candidate.creation_scope, &actor)
                .unwrap()
                .unwrap();
            let RealmActorMaterialResult::Event {
                commit: creation, ..
            } = &original.authoring_context.material.result
            else {
                panic!("accepted creation original required");
            };
            eprintln!("independent runtime recovery: administrator re-enable");
            let management_grant =
                boxed_step(|| governance(fixture, native, candidate, creation)).await;
            if pending_control {
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                lost_control.store(true, std::sync::atomic::Ordering::SeqCst);
                let error = boxed_step(|| devices.rotate_control(&actor, "lost-normal-control"))
                    .await
                    .unwrap_err();
                assert!(
                    error.to_string().contains(if control_was_accepted {
                        "injected crash before control receipt persistence"
                    } else {
                        "injected crash after initial recovery plan persistence"
                    }),
                    "{error}"
                );
                let state = snapshot(fixture, &actor).await;
                assert_eq!(
                    state["realm_actor_control"]["control_method_kid"]
                        != json!(candidate.control_method_kid),
                    control_was_accepted
                );
            }
            boxed_step(|| installation_business_revocation(fixture, native, candidate)).await;
            eprintln!("independent runtime recovery: erase daily key only");
            let custody = FileAuthoringStore::new(path.clone()).unwrap();
            // Delete every daily controller copy, including the encrypted
            // rotation journal, while retaining native update custody.
            fn decode_control(storage_key: &str, raw: &str) -> Value {
                use chacha20poly1305::aead::{Aead as _, KeyInit as _, Payload};
                use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
                let parts: Vec<_> = raw.split('.').collect();
                assert_eq!(parts.len(), 3);
                assert_eq!(parts[0], "v1");
                let nonce = arkret::base64url_decode(parts[1]).unwrap();
                let bytes = arkret::base64url_decode(parts[2]).unwrap();
                let cipher = XChaCha20Poly1305::new(&Key::from([0x53; 32]));
                let nonce = XNonce::try_from(nonce.as_slice()).unwrap();
                let plain = cipher
                    .decrypt(
                        &nonce,
                        Payload {
                            msg: &bytes,
                            aad: storage_key.as_bytes(),
                        },
                    )
                    .unwrap();
                serde_json::from_slice(&plain).unwrap()
            }
            fn encode_control(storage_key: &str, value: &Value) -> String {
                use chacha20poly1305::aead::{Aead as _, KeyInit as _, Payload};
                use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
                let nonce = XNonce::from(rand::random::<[u8; 24]>());
                let cipher = XChaCha20Poly1305::new(&Key::from([0x53; 32]));
                let plain = arkret_canonical::canonical_json_bytes(value).unwrap();
                let encrypted = cipher
                    .encrypt(
                        &nonce,
                        Payload {
                            msg: &plain,
                            aad: storage_key.as_bytes(),
                        },
                    )
                    .unwrap();
                format!(
                    "v1.{}.{}",
                    arkret::base64url_encode(nonce),
                    arkret::base64url_encode(encrypted)
                )
            }
            let mut retained_control = None;
            for (storage_key, raw) in custody.entries_with_prefix("managed-control/v1/").unwrap() {
                let mut value = decode_control(&storage_key, &raw);
                if value["actor_id"] != json!(actor) {
                    continue;
                }
                if pending_control {
                    let operation = value["operations"]
                        .as_object()
                        .unwrap()
                        .values()
                        .next()
                        .unwrap()
                        .clone();
                    assert!(operation["outcome"].is_null());
                    assert!(operation["closure"].is_null());
                    retained_control = Some((storage_key.clone(), operation));
                }
                value["controllers"] = json!({});
                assert!(
                    custody
                        .compare_exchange_batch(
                            &[(storage_key.clone(), Some(raw))],
                            &[(
                                storage_key.clone(),
                                Some(encode_control(&storage_key, &value))
                            )]
                        )
                        .unwrap()
                );
            }
            assert_eq!(retained_control.is_some(), pending_control);
            let (storage_key, before) = custody
                .entries_with_prefix("managed-identity/v1/")
                .unwrap()
                .into_iter()
                .find(|(_, raw)| {
                    serde_json::from_str::<Value>(raw).unwrap()["actor_did"]
                        == json!(candidate.initial_resolution.did)
                })
                .expect("independent native identity custody");
            let mut missing: Value = serde_json::from_str(&before).unwrap();
            assert!(missing["encrypted_controller_material"].is_string());
            missing["encrypted_controller_material"] = Value::Null;
            assert!(
                custody
                    .compare_exchange_batch(
                        &[(storage_key.clone(), Some(before))],
                        &[(storage_key, Some(serde_json::to_string(&missing).unwrap()))]
                    )
                    .unwrap()
            );
            if pending_control && !control_was_accepted {
                let before_retry = snapshot(fixture, &actor).await;
                assert!(
                    boxed_step(|| devices.rotate_control(&actor, "lost-normal-control"))
                        .await
                        .is_err()
                );
                assert_eq!(snapshot(fixture, &actor).await, before_retry);
                let (key, _) = retained_control.as_ref().unwrap();
                let raw = custody.load(key).unwrap().unwrap();
                assert!(
                    decode_control(key, &raw)["operations"]
                        .as_object()
                        .unwrap()
                        .values()
                        .all(|op| op["closure"].is_null()),
                    "unknown alone must not close the intent"
                );
            }
            if pending_control {
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
            let before_nonces = control_nonce_count(&fixture.pool, &actor).await;
            if pending_control {
                // Persist the new recovery plan into the existing control row;
                // lose only the subsequent, already accepted begin receipt.
                control_plan_skip.store(1, std::sync::atomic::Ordering::SeqCst);
            }
            lost_control.store(true, std::sync::atomic::Ordering::SeqCst);
            eprintln!("independent runtime recovery: begin with receipt failure");
            let failure = boxed_step(|| devices.recover_control(&actor, "lost-daily-key"))
                .await
                .expect_err("accepted begin receipt persistence must fail");
            assert!(
                failure.to_string().contains(if unaccepted {
                    "injected crash after initial recovery plan persistence"
                } else {
                    "injected crash before control receipt persistence"
                }),
                "{failure}"
            );
            let fenced = snapshot(fixture, &actor).await;
            assert_eq!(
                fenced["realm_actor_statusowner"],
                if unaccepted { "active" } else { "paused" }
            );
            assert_eq!(
                fenced["realm_actor_device_generation"]["current_device_generation_ref"],
                if unaccepted { 1 } else { 2 }
            );
            assert_eq!(
                fenced["realm_actor_control"]["resolution"]["did"],
                json!(candidate.initial_resolution.did)
            );
            let document_url =
                arkret::identity::DidWebvhResolver::document_url(&candidate.initial_resolution.did)
                    .unwrap();
            let parsed = url::Url::parse(&document_url).unwrap();
            let local_id = parsed.path_segments().unwrap().rev().nth(1).unwrap();
            let (_, unpublished) = author.published_principal(local_id).await.unwrap().unwrap();
            assert_eq!(
                unpublished.len(),
                if pending_control { 2 } else { 1 },
                "a missing begin receipt must not publish the planned successor"
            );
            drop(author);
            drop(devices);
            drop(edge);
            let edge = make_edge();
            *native.managed_router.lock().unwrap() = Some(Arc::new(salvo::Service::new(
                arkret_bridge_runtime::web::managed_applet_host_router(edge.clone()).unwrap(),
            )));
            let author = ManagedActorAuthoringService::new(edge.clone()).unwrap();
            let devices = ManagedDeviceRuntime::new(edge.clone()).unwrap();
            let cancelled = matches!(scenario, RecoveryScenario::CancelBeforePublish);
            let replaced = matches!(scenario, RecoveryScenario::ReplaceBeforePublish);
            async fn policy(
                fixture: &Fixture,
                actor: &ActorId,
                creation: &arkret_wire::RealmCommit,
                grant: &arkret_wire::GrantId,
                enabled: bool,
            ) {
                let revision = current_revision(fixture, actor, "realm_actor_recovery").await;
                let mut event = fixture.admin_event(EventKind::RealmActorRecoverySet,
                    ScopeRef::RealmControl { realm_id: fixture.realm.clone() }, json!({
                        "target_actor_id":actor,"enabled":enabled,
                        "expected_recovery_revision":revision,
                        "expected_manager_revision":{"commit_id":creation.commit_id,"stream_position":creation.stream_position}
                    }));
                event.authorization_ref = Some(grant.clone().into());
                let event = fixture.sign_admin(event);
                let body = arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequest::Event(
                    arkret_wire::EventAdmissionSubmission::new(event));
                let (status, response) = fixture
                    .admin_post_network(
                        "/_arkret/self/events",
                        arkret_wire::ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT_V1,
                        &json!(body),
                        if enabled {
                            "recovery-allow-again"
                        } else {
                            "recovery-cancel-pending"
                        },
                    )
                    .await;
                assert_eq!(status, StatusCode::OK, "recovery policy change: {response}");
            }
            if cancelled {
                eprintln!("independent runtime recovery: cancel pending before publication");
                boxed_step(|| policy(fixture, &actor, creation, &management_grant, false)).await;
                let error = boxed_step(|| devices.recover_control(&actor, "lost-daily-key"))
                    .await
                    .unwrap_err();
                assert!(
                    error.to_string().contains("terminated this recovery"),
                    "{error}"
                );
                let (_, history) = author.published_principal(local_id).await.unwrap().unwrap();
                assert_eq!(
                    history.len(),
                    1,
                    "cancelled unpublished plan never appears in native history"
                );
                assert!(
                    snapshot(fixture, &actor).await["realm_actor_recovery"]["pending"].is_null()
                );
                boxed_step(|| policy(fixture, &actor, creation, &management_grant, true)).await;
                assert!(
                    boxed_step(|| devices.recover_control(&actor, "lost-daily-key"))
                        .await
                        .is_err(),
                    "re-enabled permission must not resurrect the cancelled operation"
                );
            }
            if unaccepted {
                let error =
                    boxed_step(|| devices.close_unaccepted_recovery(&actor, "lost-daily-key"))
                        .await
                        .unwrap_err();
                assert!(error.to_string().contains("unknown alone"), "{error}");
                assert!(
                    boxed_step(|| devices.recover_control(&actor, "new-without-proof"))
                        .await
                        .is_err(),
                    "unknown does not release the original intent"
                );
                boxed_step(|| policy(fixture, &actor, creation, &management_grant, false)).await;
                boxed_step(|| policy(fixture, &actor, creation, &management_grant, true)).await;
                boxed_step(|| devices.close_unaccepted_recovery(&actor, "lost-daily-key"))
                    .await
                    .unwrap();
                boxed_step(|| devices.close_unaccepted_recovery(&actor, "lost-daily-key"))
                    .await
                    .unwrap();
                assert!(
                    boxed_step(|| devices.recover_control(&actor, "lost-daily-key"))
                        .await
                        .is_err(),
                    "a closed unaccepted original must never be sent later"
                );
                assert_eq!(
                    snapshot(fixture, &actor).await["realm_actor_device_generation"]["current_device_generation_ref"],
                    1
                );
            }
            let completed_operation = if cancelled {
                "after-cancelled-recovery"
            } else if replaced {
                "explicit-replacement-recovery"
            } else if unaccepted {
                "after-unaccepted-recovery"
            } else {
                "lost-daily-key"
            };
            eprintln!("independent runtime recovery: reopen host and finish original");
            let completed = if replaced {
                let prior: CommittedEventRef = serde_json::from_value(
                    fenced["realm_actor_recovery"]["pending"]["begin_ref"].clone(),
                )
                .unwrap();
                assert!(
                    boxed_step(|| devices.recover_control(&actor, completed_operation))
                        .await
                        .is_err(),
                    "a new operation must not implicitly replace pending recovery"
                );
                let mut wrong = prior.clone();
                wrong.commit_id = creation.commit_id.clone();
                assert!(
                    boxed_step(|| devices.replace_control_recovery(
                        &actor,
                        completed_operation,
                        &wrong
                    ))
                    .await
                    .is_err(),
                    "replacement requires every original coordinate"
                );
                assert_eq!(snapshot(fixture, &actor).await, fenced);
                let result = boxed_step(|| {
                    devices.replace_control_recovery(&actor, completed_operation, &prior)
                })
                .await
                .unwrap();
                assert!(
                    boxed_step(|| devices.recover_control(&actor, "lost-daily-key"))
                        .await
                        .is_err(),
                    "the superseded local intent cannot publish or reset"
                );
                assert_eq!(
                    boxed_step(|| devices.replace_control_recovery(
                        &actor,
                        completed_operation,
                        &prior
                    ))
                    .await
                    .unwrap(),
                    result
                );
                let old = fixture
                    .state
                    .test_persistence()
                    .authority_commits()
                    .committed_event(&prior.event_id)
                    .await
                    .unwrap()
                    .unwrap();
                let request = arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequest::Event(
                    arkret_wire::EventAdmissionSubmission::new(old.event));
                let material = RealmActorMaterialRequest::Outcome {
                    actor_id: actor.clone(),
                    request_nonce: arkret_canonical::base64url_encode(rand::random::<[u8; 32]>()),
                    target_request_digest: Hash::new(canonical_sha256(&request).unwrap()).unwrap(),
                };
                let material_body = json!(material);
                let (status, response) = boxed_step(|| {
                    fixture.service_post(
                        &native.package,
                        "/_arkret/self/realm-actors/material",
                        arkret_wire::ServiceOperationId::SelfRealmActorReadMaterialV1.as_str(),
                        &material_body,
                        "superseded-recovery-outcome",
                    )
                })
                .await;
                assert_eq!(status, StatusCode::OK, "{response}");
                assert_eq!(response["result"]["outcome"]["state"], "superseded");
                result
            } else {
                boxed_step(|| devices.recover_control(&actor, completed_operation))
                    .await
                    .unwrap()
            };
            assert_eq!(completed.stream_ref, creation.stream_ref);
            let after = snapshot(fixture, &actor).await;
            assert_eq!(
                after["realm_actor_statusowner"], "paused",
                "key recovery does not resume business"
            );
            assert_eq!(after["realm_actor_statusgovernance"], "active");
            assert_eq!(
                after["realm_actor_device_generation"]["current_device_generation_ref"],
                if cancelled || replaced { 3 } else { 2 }
            );
            assert_eq!(
                after["realm_actor_control"]["resolution"]["did"],
                json!(candidate.initial_resolution.did)
            );
            assert_ne!(
                after["realm_actor_control"]["control_method_kid"],
                json!(candidate.control_method_kid)
            );
            assert!(after["realm_actor_recovery"]["pending"].is_null());
            assert_eq!(
                control_nonce_count(&fixture.pool, &actor).await,
                before_nonces,
                "independent recovery cannot authenticate with the missing daily control key"
            );
            assert_eq!(
                boxed_step(|| devices.recover_control(&actor, completed_operation))
                    .await
                    .unwrap(),
                completed
            );
            let (_, published) = author.published_principal(local_id).await.unwrap().unwrap();
            assert_eq!(published.len(), if pending_control { 3 } else { 2 });
            if let Some((key, original_operation)) = &retained_control {
                let raw = custody.load(key).unwrap().unwrap();
                let state = decode_control(key, &raw);
                let retained =
                    &state["operations"][original_operation["operation_id"].as_str().unwrap()];
                assert_eq!(
                    retained["event"], original_operation["event"],
                    "recovery must retain the exact original"
                );
                if control_was_accepted {
                    assert!(
                        retained["outcome"].is_array(),
                        "recover the accepted original receipt"
                    );
                    assert!(
                        retained["closure"].is_null(),
                        "accepted is never relabeled unaccepted"
                    );
                } else {
                    assert!(retained["outcome"].is_null());
                    assert_eq!(retained["closure"]["kind"], "unaccepted");
                    assert!(retained["closure"]["advanced_current"]["signature"].is_object());
                    assert!(retained["closure"]["subsequent_unknown"]["signature"].is_object());
                }
                let before_retry = snapshot(fixture, &actor).await;
                assert!(
                    boxed_step(|| devices.rotate_control(&actor, "lost-normal-control"))
                        .await
                        .is_err()
                );
                assert_eq!(
                    snapshot(fixture, &actor).await,
                    before_retry,
                    "old operation cannot revive control after recovery"
                );
            }
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            boxed_step(|| devices.rotate_control(&actor, "recovered-key-rotation"))
                .await
                .unwrap();
            assert_eq!(
                boxed_step(|| devices.recover_control(&actor, completed_operation))
                    .await
                    .unwrap(),
                completed,
                "historical recovery completion survives subsequent normal control changes"
            );
            assert!(
                boxed_step(|| devices.device_for_actor(&actor))
                    .await
                    .is_err(),
                "old authorization remains fenced"
            );
            lost_control.store(true, std::sync::atomic::Ordering::SeqCst);
            let lost_status = boxed_step(|| {
                devices.set_owner_status(
                    &actor,
                    "explicit-resume",
                    RealmActorStatusSetPayloadState::Active,
                )
            })
            .await
            .expect_err("lose the accepted owner status before local receipt persistence");
            assert!(
                lost_status
                    .to_string()
                    .contains("injected crash before control receipt persistence")
            );
            assert_eq!(
                snapshot(fixture, &actor).await["realm_actor_statusowner"],
                "active"
            );
            drop(devices);
            let devices = ManagedDeviceRuntime::new(make_edge()).unwrap();
            let resumed = boxed_step(|| {
                devices.set_owner_status(
                    &actor,
                    "explicit-resume",
                    RealmActorStatusSetPayloadState::Active,
                )
            })
            .await
            .unwrap();
            let paused = boxed_step(|| {
                devices.set_owner_status(
                    &actor,
                    "explicit-pause",
                    RealmActorStatusSetPayloadState::Paused,
                )
            })
            .await
            .unwrap();
            assert!(paused.stream_position > resumed.stream_position);
            let before_replay = snapshot(fixture, &actor).await;
            assert_eq!(
                boxed_step(|| devices.set_owner_status(
                    &actor,
                    "explicit-resume",
                    RealmActorStatusSetPayloadState::Active,
                ))
                .await
                .unwrap(),
                resumed,
                "historical resume must not reactivate after a later pause"
            );
            assert!(
                boxed_step(|| devices.set_owner_status(
                    &actor,
                    "explicit-resume",
                    RealmActorStatusSetPayloadState::Retired,
                ))
                .await
                .is_err(),
                "an operation ID cannot be reused to retire the actor"
            );
            assert_eq!(snapshot(fixture, &actor).await, before_replay);
            assert_eq!(before_replay["realm_actor_statusowner"], "paused");
            assert_eq!(before_replay["realm_actor_statusgovernance"], "active");
            assert!(
                boxed_step(|| devices.device_for_actor(&actor))
                    .await
                    .is_err(),
                "owner resume must not restore a fenced old Device"
            );
            let retained = edge
                .installed_managed_authoring(&candidate.creation_scope, &actor)
                .unwrap()
                .unwrap();
            assert_eq!(
                canonical_sha256(&retained.authoring_context.material.result).unwrap(),
                canonical_sha256(&original.authoring_context.material.result).unwrap()
            );
            drop(custody);
            drop(devices);
            drop(edge);
            std::fs::remove_file(path).unwrap();
        }
        let (fixture, _governor_server) = boxed_step(|| network_fixture(pool.clone())).await;
        let factory = AppletAuthoringFactory {
            fixture,
            packages: Default::default(),
            scopes: Default::default(),
        };
        let id = AppletId::new(format!("ak:applet:{}", uuid::Uuid::now_v7())).unwrap();
        let mut native = NativeService::new(&id, &factory.fixture.state.service_core_id());
        if bot {
            native
                .package
                .endpoint_policy
                .endpoints
                .push(AppletEndpointEntry {
                    method: AppletEndpointMethod::Post,
                    path: "/_arkret/edge/applet/configuration".into(),
                    auth: Some(AppletEndpointAuth::WebhookSignature),
                    description: None,
                    extra: Default::default(),
                });
        }
        realm_actor_mls_fixture::enable(&mut native.package);
        factory
            .packages
            .lock()
            .await
            .insert(id.to_string(), native.package.clone());
        let install_label = if circle {
            "bridge-native-runtime:scope-right"
        } else {
            "bridge-native-runtime"
        };
        let install = boxed_step(|| factory.prepare_install(&id, install_label)).await;
        let content_scope = install.effective_scope.clone();
        install.commit(&PgAppletStore { pool }).await.unwrap();
        let parent_installation = if circle {
            let parent =
                boxed_step(|| factory.prepare_install(&id, "bridge-parent-admission")).await;
            let outcome = boxed_step(|| commit_install_http(&factory.fixture, &parent)).await;
            Some((parent.effective_scope.clone(), outcome))
        } else {
            None
        };
        let package = &native.package;
        let did = applet_service_did(package);
        let config: arkret_bridge_runtime::Config = serde_json::from_value(json!({
            "bridge":{"bridge_id":"native-runtime"},
            "arkret": {
                "server_url":factory.fixture.state.config().public_base_url,
                "applet_base_url":package.base_url,
                "service_resolution":fixture_applet_service_history(package),
                "service_did":did, "trust_domain":factory.fixture.state.config().trust_domain,
                "applet_id":id,"signing_key_seed_hex":"2a".repeat(32),
                "verification_method_fragment":"#applet-service-key", "trusted_server_did":factory.fixture.state.service_did(),
                "applet_namespaces":package.namespaces,
                "managed_actor_authoring":{"principal_endpoint":package.base_url,"key_encryption_key_hex":"53".repeat(32),
                    "device":{"actions":["ak.applet.join","ak.circle.member.add","ak.event.read","ak.message.create","ak.message.redact","ak.mls.commit","ak.object.read_content","ak.self.blob.resource.get.v1","ak.self.blob.command.presign.v1","ak.self.blob.upload.create.v1","ak.strand.create"],
                        "lifetime_seconds":3600,"mls":true,"key_package_inventory_target":2}}
            }
        })).unwrap();
        let path =
            std::env::temp_dir().join(format!("arkret-bridge-real-{}.redb", uuid::Uuid::now_v7()));
        let http = reqwest::Client::builder()
            .tls_backend_rustls()
            .tls_certs_only(
                reqwest::Certificate::from_pem_bundle(&native_tls_material().ca).unwrap(),
            )
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .unwrap();
        let station_url: url::Url = factory
            .fixture
            .state
            .config()
            .public_base_url
            .parse()
            .unwrap();
        let client = arkret::ClientBuilder::new(station_url.clone())
            .loopback_service_discovery(
                station_url.host_str().unwrap(),
                station_url.port().unwrap(),
            )
            .unwrap()
            .http_client(http)
            .build()
            .unwrap();
        let lost_receipt = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let lost_authorization = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let lost_control = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let control_plan_skip = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let recipient_fault = Arc::new(NativeRecipientStoreFault::default());
        let runtime_fault = Arc::new(NativeRuntimeRecoveryFault::default());
        let make_edge = || {
            Arc::new(
                ArkretEdge::new_outbound(
                    Arc::new(config.clone()),
                    client.clone(),
                    Ed25519PayloadSigner::new(
                        SigningKey::from_bytes(&[42; 32]),
                        did.clone(),
                        package.webhook_auth.key_ref.clone(),
                    ),
                    AuthoringJournal::new(Arc::new(LostDeviceReceipt {
                        inner: FileAuthoringStore::new(path.clone()).unwrap(),
                        armed: lost_receipt.clone(),
                        authorization_armed: lost_authorization.clone(),
                        control_armed: lost_control.clone(),
                        control_plan_skip: control_plan_skip.clone(),
                        fail_after_control_plan: matches!(
                            recovery_scenario,
                            Some(
                                RecoveryScenario::CloseUnaccepted
                                    | RecoveryScenario::UnacceptedControl
                            )
                        ),
                        recipient_fault: recipient_fault.clone(),
                        runtime_fault: runtime_fault.clone(),
                    })),
                )
                .unwrap(),
            )
        };
        let edge = make_edge();
        let author = ManagedActorAuthoringService::new(edge.clone()).unwrap();
        let external = arkret::GhostExternalTuple {
            protocol: "fixture".into(),
            instance_id: "bridge-native".into(),
            external_id: "user-1".into(),
        };
        eprintln!("real Bridge runtime: signed governance preview and independent native creation");
        *native.managed_router.lock().unwrap() = Some(Arc::new(salvo::Service::new(
            arkret_bridge_runtime::web::managed_applet_host_router(edge.clone()).unwrap(),
        )));
        let mut creation_commit = None;
        let candidate = if bot {
            use arkret_models_integration::{
                AppletConfigurationAdmissionStatus, AppletConfigurationCommand,
                AppletConfigurationIntent, AppletConfigurationOutcome, AppletConfigurationRequest,
                AppletConfigurationSelection,
            };
            let request = AppletConfigurationRequest {
                command: AppletConfigurationCommand::Configure,
                intent: AppletConfigurationIntent {
                    service_id: package.service_id.clone(),
                    request_id: format!("ak:request:{}", uuid::Uuid::now_v7())
                        .parse()
                        .unwrap(),
                    effective_scope: content_scope.clone(),
                    selection: AppletConfigurationSelection::NewBot {
                        display_name: Some("Native Bot".into()),
                    },
                },
                approval_signatures: None,
            };
            let endpoint = format!("/_arkret/self/applets/{id}/configuration");
            let body = json!(request);
            let (status, value) = boxed_step(|| {
                factory.fixture.admin_post(
                    &endpoint,
                    arkret_wire::ServiceOperationId::SELF_APPLET_CONFIGURATION_COMMAND_SUBMIT_V1,
                    &body,
                    Some(request.intent.request_id.as_str()),
                )
            })
            .await;
            assert_eq!(status, StatusCode::OK, "Bot creation: {value}");
            let accepted: AppletConfigurationOutcome = serde_json::from_value(value).unwrap();
            assert_eq!(
                accepted.admission_status,
                AppletConfigurationAdmissionStatus::Accepted
            );
            let original = accepted.source_outcome.unwrap().create_event.unwrap();
            let candidate: RealmActorCreatePayload =
                serde_json::from_value(json!(original.payload)).unwrap();
            assert_eq!(
                candidate.actor_role,
                arkret::RealmActorCreatePayloadActorRole::Bot
            );
            *native.actor_log.lock().unwrap() = candidate
                .method_history_evidence
                .webvh_material()
                .1
                .to_vec();
            let completion = factory
                .fixture
                .state
                .test_persistence()
                .applets()
                .pending_authoring_completions(128)
                .await
                .unwrap()
                .into_iter()
                .find(|item| item.actor_id == candidate.actor_id)
                .unwrap();
            let delivery =
                boxed_step(|| prepare_configuration_completion(&factory.fixture, &completion))
                    .await
                    .unwrap();
            boxed_step(|| {
                deliver_configuration_completion(&factory.fixture, &completion, &delivery)
            })
            .await
            .unwrap();
            candidate
        } else {
            let prepared =
                boxed_step(|| author.prepare_ghost_in_scope(&id, &content_scope, &external, None))
                    .await
                    .unwrap();
            let PreparedGhost::Create(command) = prepared else {
                panic!("new Ghost must create");
            };
            let candidate: RealmActorCreatePayload = serde_json::from_value(
                serde_json::to_value(&command.create_event.payload).unwrap(),
            )
            .unwrap();
            *native.actor_log.lock().unwrap() = candidate
                .method_history_evidence
                .webvh_material()
                .1
                .to_vec();
            let first = boxed_step(|| edge.submit_managed_creation(&command))
                .await
                .unwrap();
            let arkret_wire::AuthoritySubmitOutcome::Accepted { commit, .. } = first else {
                panic!("creation must be accepted");
            };
            assert_eq!(commit.stream_position, 0);
            assert!(matches!(
                commit.stream_ref,
                CommitStreamRef::RealmControl { .. }
            ));
            let second = boxed_step(|| edge.submit_managed_creation(&command))
                .await
                .unwrap();
            let arkret_wire::AuthoritySubmitOutcome::Accepted { commit: replay, .. } = second
            else {
                panic!("creation replay must be accepted");
            };
            assert_eq!(commit, replay);
            creation_commit = Some(commit);
            candidate
        };
        let actor = candidate.actor_id.clone();
        assert!(
            edge.installed_managed_authoring(&candidate.creation_scope, &actor)
                .unwrap()
                .is_some()
        );
        drop(author);
        drop(edge);
        let edge = make_edge();
        let author = ManagedActorAuthoringService::new(edge.clone()).unwrap();
        if !bot {
            assert!(matches!(
                boxed_step(|| author.prepare_ghost_in_scope(&id, &content_scope, &external, None))
                    .await
                    .unwrap(),
                PreparedGhost::Reuse { .. }
            ));
        }
        if recipient_mode == 3 {
            let commit =
                creation_commit.expect("Ghost completion scenario retains its accepted Commit");
            drop(author);
            drop(edge);
            boxed_step(|| {
                actual_completion_receiver(
                    &factory.fixture,
                    &native,
                    &actor,
                    &commit,
                    &path,
                    &make_edge,
                )
            })
            .await;
            std::fs::remove_file(&path).unwrap();
            return;
        }
        if recipient_mode == 4 {
            drop(author);
            drop(edge);
            boxed_step(|| {
                run_native_runtime_recovery(
                    &factory.fixture,
                    package,
                    &actor,
                    &content_scope,
                    &make_edge,
                    &path,
                    &runtime_fault,
                )
            })
            .await;
            std::fs::remove_file(&path).unwrap();
            return;
        }
        eprintln!("real Bridge runtime: current private control and native Device");
        let devices = ManagedDeviceRuntime::new(edge.clone()).unwrap();
        lost_authorization.store(true, std::sync::atomic::Ordering::SeqCst);
        let failure = boxed_step(|| devices.device_for_actor(&actor))
            .await
            .err()
            .expect("authorization outcome persistence must fail");
        assert!(
            failure
                .to_string()
                .contains("injected crash before authorization receipt persistence"),
            "{failure}"
        );
        if let Some(scenario) = recovery_scenario {
            boxed_step(|| {
                recover_runtime_key_loss(
                    &factory.fixture,
                    &native,
                    &candidate,
                    edge,
                    devices,
                    author,
                    path.clone(),
                    lost_control.clone(),
                    control_plan_skip.clone(),
                    make_edge,
                    scenario,
                )
            })
            .await;
            return;
        }
        lost_control.store(true, std::sync::atomic::Ordering::SeqCst);
        let failure = boxed_step(|| devices.rotate_control(&actor, "native-control-rotation"))
            .await
            .expect_err("control receipt persistence must fail");
        assert!(
            failure
                .to_string()
                .contains("injected crash before control receipt persistence"),
            "{failure}"
        );
        let accepted_rotation_nonces = control_nonce_count(&factory.fixture.pool, &actor).await;
        drop(devices);
        drop(edge);
        let edge = make_edge();
        let devices = ManagedDeviceRuntime::new(edge.clone()).unwrap();
        let rotated = boxed_step(|| devices.rotate_control(&actor, "native-control-rotation"))
            .await
            .unwrap();
        let rotation_nonces = control_nonce_count(&factory.fixture.pool, &actor).await;
        assert_eq!(
            rotation_nonces,
            accepted_rotation_nonces + 1,
            "recovery must reuse the accepted activation and submit only retirement"
        );
        assert_eq!(
            boxed_step(|| devices.rotate_control(&actor, "native-control-rotation"))
                .await
                .unwrap(),
            rotated
        );
        assert_eq!(
            control_nonce_count(&factory.fixture.pool, &actor).await,
            rotation_nonces,
            "completed rotation replay must not submit another control Event"
        );
        let authorized_nonces = control_nonce_count(&factory.fixture.pool, &actor).await;
        drop(devices);
        drop(edge);
        let edge = make_edge();
        let devices = ManagedDeviceRuntime::new(edge.clone()).unwrap();
        if let Some((scope, outcome)) = &parent_installation {
            boxed_step(|| devices.remember_installation_outcome(scope, outcome))
                .await
                .unwrap();
        }
        if recipient_mode == 2 {
            boxed_step(|| {
                same_device_cross_circle_queue(&factory, package, &devices, &actor, &content_scope)
            })
            .await;
            drop(devices);
            drop(author);
            drop(edge);
            std::fs::remove_file(&path).unwrap();
            return;
        }
        let device = boxed_step(|| devices.device_for_actor(&actor))
            .await
            .unwrap();
        assert_eq!(device.actor_id, actor);
        assert_eq!(
            control_nonce_count(&factory.fixture.pool, &actor).await,
            authorized_nonces,
            "accepted authorization recovery must not issue another controller-authenticated request"
        );
        assert_ne!(
            device.signer().verifying_key(),
            SigningKey::from_bytes(&[42; 32]).verifying_key()
        );
        boxed_step(|| {
            realm_actor_mls_fixture::business_parent(
                &factory.fixture,
                package,
                &actor,
                &content_scope,
            )
        })
        .await;
        let parent_device = if circle {
            let parent_scope = ScopeRef::Realm {
                realm_id: factory.fixture.realm.clone(),
            };
            let plan = arkret_bridge_runtime::managed_device::InitialManagedDevicePlan {
                operation_id: "parent-membership-only".into(),
                actor_id: actor.clone(),
                scopes: serde_json::from_value(json!([{
                    "effective_scope": parent_scope, "actions": ["ak.applet.join"]
                }]))
                .unwrap(),
                not_before: chrono::Utc::now(),
                expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
            };
            let parent = boxed_step(|| devices.authorize_initial_device(plan, &parent_scope))
                .await
                .unwrap();
            boxed_step(|| devices.join_circle_after_realm_join(&device, &parent))
                .await
                .unwrap();
            Some(parent)
        } else {
            None
        };
        boxed_step(|| devices.ensure_realm_membership(&device))
            .await
            .unwrap();
        boxed_step(|| devices.maintain_mls_key_packages(&device, 2))
            .await
            .unwrap();
        let reader = boxed_step(|| devices.open_reader(&device)).await.unwrap();
        let snapshot = boxed_step(|| reader.client().snapshot_head(&factory.fixture.realm))
            .await
            .unwrap();
        snapshot.value().unwrap();
        if manager_transfer {
            boxed_step(|| {
                run_manager_runtime_transfer(
                    &factory, &native, &candidate, &config, &client, &devices, &device, &path,
                    &edge,
                )
            })
            .await;
            return;
        }
        if governance_handoff {
            boxed_step(|| {
                resume_runtime_after_handoff(&factory.fixture, &device, &actor, &make_edge)
            })
            .await;
            return;
        }
        eprintln!("real Bridge runtime: ordinary member MLS admission and private Welcome receive");
        let mut human_group =
            boxed_step(|| realm_actor_mls_fixture::human_admits_runtime(&factory.fixture, &device))
                .await;
        if recipient_mode == 1 {
            drop(reader);
            drop(device);
            drop(devices);
            drop(author);
            drop(edge);
            boxed_step(|| {
                welcome_checkpoint_consume_and_ack_recovery(
                    &factory.fixture,
                    &actor,
                    &make_edge,
                    &path,
                    &recipient_fault,
                )
            })
            .await;
            std::fs::remove_file(&path).unwrap();
            return;
        }
        let progress = boxed_step(|| devices.poll_welcome_queue(&device, &reader))
            .await
            .unwrap();
        assert_eq!(progress.durable_welcomes, 1);
        assert!(progress.acknowledged);
        assert_eq!(devices.installed_mls_epoch(&device).await.unwrap(), Some(1));
        let location = json!({
            "protocol":"fixture", "network_id":"bridge-native", "location_id":"portal-1"
        });
        assert!(
            boxed_step(|| devices.find_portal_strand(&actor, &factory.fixture.realm, &location,))
                .await
                .unwrap()
                .is_none()
        );
        let strand_id = boxed_step(|| {
            devices.submit_portal_strand(&actor, &content_scope, "Native portal", &location)
        })
        .await
        .unwrap();
        assert_eq!(
            boxed_step(|| devices.submit_portal_strand(
                &actor,
                &content_scope,
                "Native portal",
                &location,
            ))
            .await
            .unwrap(),
            strand_id
        );
        assert!(
            boxed_step(|| devices.submit_portal_strand(
                &actor,
                &content_scope,
                "Changed portal",
                &location,
            ))
            .await
            .is_err()
        );
        assert_eq!(
            boxed_step(|| devices.find_portal_strand(&actor, &factory.fixture.realm, &location,))
                .await
                .unwrap(),
            Some(strand_id.clone())
        );
        let portal_original = device
            .client()
            .committed_event_get(
                &arkret_wire::EventId::from_token_bytes(strand_id.token_bytes()).unwrap(),
            )
            .await
            .unwrap();
        let portal_event = portal_original.reducer_input().unwrap();
        assert_eq!(portal_event.actor_id, actor);
        assert!(portal_event.authorization_ref.is_some());
        assert!(portal_event.payload["object"].get("id").is_none());
        assert!(portal_event.payload["object"].get("metadata").is_none());
        assert!(
            portal_event.payload["object"]
                .get("encrypted_metadata")
                .is_some()
        );
        eprintln!("real Bridge runtime: encrypted attachments over native Device HTTP");
        let attachment_plaintext = realm_actor_mls_fixture::attachment_plaintext();
        let descriptor = boxed_step(|| {
            devices.upload_attachment(
                &actor,
                &content_scope,
                "attachment-1",
                &attachment_plaintext,
                "text/plain",
            )
        })
        .await
        .unwrap();
        let original_blob = factory
            .fixture
            .state
            .test_persistence()
            .blobs()
            .get(descriptor.blob_ref().as_str())
            .await
            .unwrap()
            .unwrap();
        let replay = boxed_step(|| {
            devices.upload_attachment(
                &actor,
                &content_scope,
                "attachment-1",
                &attachment_plaintext,
                "text/plain",
            )
        })
        .await
        .unwrap();
        assert_eq!(descriptor, replay);
        let replay_blob = factory
            .fixture
            .state
            .test_persistence()
            .blobs()
            .get(descriptor.blob_ref().as_str())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(original_blob.created_at, replay_blob.created_at);
        assert_eq!(original_blob.uploaded_by, actor.to_string());
        {
            use diesel_async::RunQueryDsl as _;
            #[derive(diesel::QueryableByName)]
            struct Binding {
                #[diesel(sql_type = diesel::sql_types::Jsonb)]
                value: Value,
            }
            let mut conn = factory.fixture.pool.get().await.unwrap();
            let binding = diesel::sql_query("SELECT jsonb_build_object('blob_ref',blob_ref,'effective_scope',effective_scope,'actor_id',actor_id,'device_id',device_id,'authorization_ref',authorization_ref,'accepted_at',accepted_at) AS value FROM realm_actor_blob_uploads WHERE blob_ref=$1")
                .bind::<diesel::sql_types::Text,_>(descriptor.blob_ref().as_str())
                .get_result::<Binding>(&mut *conn).await.unwrap().value;
            assert_eq!(binding["effective_scope"], json!(content_scope));
            assert_eq!(binding["actor_id"], json!(actor));
            assert_eq!(binding["device_id"], json!(device.device_id));
            assert!(binding["authorization_ref"]["event_id"].is_string());
            assert!(binding["accepted_at"].is_string());
            assert!(
                diesel::sql_query(
                    "UPDATE realm_actor_blob_uploads SET device_id=$2 WHERE blob_ref=$1"
                )
                .bind::<diesel::sql_types::Text, _>(descriptor.blob_ref().as_str())
                .bind::<diesel::sql_types::Text, _>(format!("ak:device:{}", uuid::Uuid::now_v7()))
                .execute(&mut *conn)
                .await
                .is_err(),
                "the database must reject immutable binding rewrites"
            );
            if circle {
                let authority = factory
                    .fixture
                    .state
                    .test_persistence()
                    .device_revocations()
                    .applet_managed_device_authority(&actor, &device.device_id, chrono::Utc::now())
                    .await
                    .unwrap()
                    .unwrap();
                assert!(authority.scopes.permits(
                    &content_scope,
                    &[arkret_wire::CapabilityActionId::SelfBlobUploadCreateV1]
                ));
                assert!(
                    !authority.scopes.permits(
                        &ScopeRef::Realm {
                            realm_id: factory.fixture.realm.clone()
                        },
                        &[arkret_wire::CapabilityActionId::SelfBlobUploadCreateV1]
                    ),
                    "Circle fixture must not accidentally grant Realm upload"
                );
            }
        }
        // Exact replay consumes no new quota and retains the first metadata.
        let guard = blob_upload_guard(
            &factory.fixture,
            package,
            &device,
            chrono::Utc::now() + chrono::Duration::seconds(30),
        )
        .await;
        let retained = guard
            .commit_native_blob_upload(descriptor.blob_ref(), &original_blob, 0, 0)
            .await
            .unwrap();
        assert_eq!(retained, original_blob);
        let mut rejected_blob = original_blob.clone();
        rejected_blob.sha256 = arkret_canonical::sha256_hex(b"unpublished quota test");
        let rejected_ref =
            arkret::BlobRef::new(format!("ak:blob:sha256:{}", rejected_blob.sha256)).unwrap();
        let guard = blob_upload_guard(
            &factory.fixture,
            package,
            &device,
            chrono::Utc::now() + chrono::Duration::seconds(30),
        )
        .await;
        assert!(
            matches!(guard.commit_native_blob_upload(&rejected_ref, &rejected_blob, 0, 0).await,
            Err(PersistenceError::Conflict(reason)) if reason == "blob_quota_exceeded")
        );
        assert!(
            factory
                .fixture
                .state
                .test_persistence()
                .blobs()
                .get(rejected_ref.as_str())
                .await
                .unwrap()
                .is_none()
        );
        let guard = blob_upload_guard(
            &factory.fixture,
            package,
            &device,
            chrono::Utc::now() + chrono::Duration::seconds(3),
        )
        .await;
        {
            use diesel_async::RunQueryDsl as _;
            let mut blocker = factory.fixture.pool.get().await.unwrap();
            diesel::sql_query("BEGIN")
                .execute(&mut *blocker)
                .await
                .unwrap();
            diesel::sql_query("LOCK TABLE blobs IN SHARE ROW EXCLUSIVE MODE")
                .execute(&mut *blocker)
                .await
                .unwrap();
            let reference = rejected_ref.clone();
            let record = rejected_blob.clone();
            let pending = tokio::spawn(async move {
                guard
                    .commit_native_blob_upload(&reference, &record, u64::MAX, u64::MAX)
                    .await
            });
            tokio::time::sleep(std::time::Duration::from_secs(3)).await;
            diesel::sql_query("COMMIT")
                .execute(&mut *blocker)
                .await
                .unwrap();
            assert!(pending.await.unwrap().is_err());
        }
        assert!(
            factory
                .fixture
                .state
                .test_persistence()
                .blobs()
                .get(rejected_ref.as_str())
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            device
                .client()
                .blob_download(descriptor.blob_ref(), None)
                .await
                .is_err(),
            "upload ownership does not bypass the original content binding"
        );
        assert!(
            boxed_step(|| devices.upload_attachment(
                &actor,
                &content_scope,
                "attachment-1",
                b"changed bytes",
                "text/plain"
            ))
            .await
            .is_err()
        );
        eprintln!(
            "real Bridge runtime: reject authenticated malformed content without blocking the stream"
        );
        let rejected = boxed_step(|| {
            realm_actor_mls_fixture::invalid_human_messages(
                &factory.fixture,
                &content_scope,
                &mut human_group,
                strand_id.clone(),
                &actor,
            )
        })
        .await;
        let progress = boxed_step(|| devices.poll_content_stream(&device, &reader))
            .await
            .unwrap();
        assert_eq!(progress.pending_events, 0);
        assert_eq!(
            devices
                .last_rejected_content(&device)
                .await
                .unwrap()
                .unwrap()
                .event,
            rejected
        );
        assert!(
            !boxed_step(|| devices.drain_content(
                &device,
                &reader,
                &realm_actor_mls_fixture::TextOnlySink
            ))
            .await
            .unwrap()
        );
        drop(reader);
        drop(device);
        drop(devices);
        let devices = ManagedDeviceRuntime::new(edge.clone()).unwrap();
        let device = boxed_step(|| devices.device_for_actor(&actor))
            .await
            .unwrap();
        let reader = boxed_step(|| devices.open_reader(&device)).await.unwrap();
        assert_eq!(
            devices
                .last_rejected_content(&device)
                .await
                .unwrap()
                .unwrap()
                .event,
            rejected
        );
        eprintln!("real Bridge runtime: encrypted content, delivery failure and cold recovery");
        let (incoming, plaintext) = boxed_step(|| {
            realm_actor_mls_fixture::human_message(
                &factory.fixture,
                &content_scope,
                &mut human_group,
                strand_id,
                descriptor.clone(),
                &actor,
            )
        })
        .await;
        let ciphertext = device
            .client()
            .blob_download(descriptor.blob_ref(), None)
            .await
            .unwrap();
        assert_ne!(ciphertext, attachment_plaintext);
        let presign_error = device
            .client()
            .blob_presign(
                &arkret_models_collaboration::objects::blob::BlobPresignRequestBody {
                    blob_ref: descriptor.blob_ref().clone(),
                    realm_id: Some(factory.fixture.realm.clone()),
                    max_age_seconds: Some(30),
                    purpose: Some("media_inline".into()),
                },
            )
            .await
            .unwrap_err();
        assert_eq!(
            presign_error.error_code(),
            Some(arkret_wire::ErrorCode::CapabilityDenied),
            "native presign authenticates the Device but must refuse E2EE bearer delivery: {presign_error}"
        );
        let current = coland_storage_postgres::PgMlsGroupCurrentStore {
            pool: factory.fixture.pool.clone(),
        }
        .current(&content_scope)
        .await
        .unwrap()
        .unwrap()
        .value;
        let context = descriptor.content_key_context(
            content_scope.clone(),
            current.genesis_event_ref,
            human_group.epoch(),
        );
        let secret = arkret_mls::derive_attachment_content_key(&human_group, &context).unwrap();
        let resolver = |reference: &arkret::EncryptedAttachmentGroupStateRef| {
            reference
                .event_id()
                .ok()
                .filter(|id| id == &current.current_mls_commit_event_ref)
                .map(|_| human_group.epoch())
        };
        assert_eq!(
            arkret::crypto::blob_aead::decrypt_stream(&ciphertext, &descriptor, &secret, &resolver)
                .unwrap(),
            attachment_plaintext
        );
        if bot {
            boxed_step(|| {
                verify_bot_consumer(
                    &factory.fixture,
                    edge.clone(),
                    &devices,
                    &device,
                    &reader,
                    &mut human_group,
                    &actor,
                    &content_scope,
                    rotate_during_reply,
                )
            })
            .await;
            return;
        }
        let sink = realm_actor_mls_fixture::ContentSink {
            event: incoming,
            plaintext: plaintext.clone(),
            attempts: std::sync::atomic::AtomicUsize::new(0),
        };
        let progress = boxed_step(|| devices.poll_content_stream(&device, &reader))
            .await
            .unwrap();
        assert_eq!(progress.pending_events, 1);
        let text_only = boxed_step(|| {
            devices.drain_content(&device, &reader, &realm_actor_mls_fixture::TextOnlySink)
        })
        .await
        .unwrap_err();
        assert!(
            text_only
                .to_string()
                .contains("leave the text-only delivery pending")
        );
        assert!(
            boxed_step(|| devices.drain_content(&device, &reader, &sink))
                .await
                .is_err()
        );
        drop(reader);
        drop(device);
        drop(devices);
        drop(author);
        drop(edge);
        let edge = make_edge();
        let devices = ManagedDeviceRuntime::new(edge.clone()).unwrap();
        let device = boxed_step(|| devices.device_for_actor(&actor))
            .await
            .unwrap();
        let reader = boxed_step(|| devices.open_reader(&device)).await.unwrap();
        assert_eq!(devices.installed_mls_epoch(&device).await.unwrap(), Some(1));
        assert!(
            boxed_step(|| devices.drain_content(&device, &reader, &sink))
                .await
                .unwrap()
        );
        assert!(
            !boxed_step(|| devices.drain_content(&device, &reader, &sink))
                .await
                .unwrap()
        );
        assert_eq!(sink.attempts.load(std::sync::atomic::Ordering::SeqCst), 2);
        let mut outbound = plaintext;
        outbound.content.as_mut().unwrap().body = "Native Ghost to human".into();
        let external =
            json!({"protocol":"fixture","instance_id":"bridge-native","message_id":"reply-1"});
        let mut foreign_target = outbound.clone();
        foreign_target
            .content
            .as_mut()
            .unwrap()
            .extra
            .get_mut("mentions")
            .unwrap()[0]["subject_actor_id"]["realm_actor_id"]["realm_id"] =
            json!("ak:realm:AS8XThowW7JnZc80U10gJh-_lqkA-iSQ-LAvBXj6_9O5");
        assert!(
            boxed_step(|| devices.submit_message(
                &actor,
                &content_scope,
                foreign_target,
                external.clone(),
            ))
            .await
            .unwrap_err()
            .to_string()
            .contains("mention subject belongs to another Realm"),
        );
        let event_id = boxed_step(|| {
            devices.submit_message(&actor, &content_scope, outbound.clone(), external.clone())
        })
        .await
        .unwrap();
        boxed_step(|| {
            realm_actor_mls_fixture::verify_runtime_message(
                &factory.fixture,
                &mut human_group,
                &event_id,
                &actor,
                outbound.content.as_ref().unwrap(),
            )
        })
        .await;
        let replay = boxed_step(|| {
            devices.submit_message(&actor, &content_scope, outbound.clone(), external.clone())
        })
        .await
        .unwrap();
        assert_eq!(event_id, replay);
        outbound.content = Some(arkret::ContentBlock::text("Conflicting replacement"));
        assert!(
            boxed_step(|| devices.submit_message(&actor, &content_scope, outbound, external,))
                .await
                .is_err()
        );
        if let Some(parent) = parent_device.as_ref() {
            let original = EventId::new(&event_id).unwrap();
            boxed_step(|| {
                realm_native_read_boundaries(&factory.fixture, &device, parent, &original)
            })
            .await;
        }
        let redaction = arkret::MessageRedactPayload {
            message_id: arkret::MessageId::from_event_id(&arkret::EventId::new(&event_id).unwrap()),
            track_name: None,
            reason: Some("External author withdrew this message".into()),
            preserve: None,
            mimi_provenance: None,
        };
        let external_delete = json!({"protocol":"fixture","message_id":"delete-reply-1"});
        let redaction_id = boxed_step(|| {
            devices.submit_redaction(
                &actor,
                &content_scope,
                redaction.clone(),
                external_delete.clone(),
            )
        })
        .await
        .unwrap();
        assert_eq!(
            boxed_step(|| devices.submit_redaction(
                &actor,
                &content_scope,
                redaction,
                external_delete,
            ))
            .await
            .unwrap(),
            redaction_id
        );
        let progress = boxed_step(|| devices.poll_content_stream(&device, &reader))
            .await
            .unwrap();
        assert_eq!(
            progress.pending_events, 0,
            "own publication never decrypts or echoes itself"
        );
        drop(reader);
        boxed_step(|| devices.ensure_realm_membership(&device))
            .await
            .unwrap();
        let recovered = boxed_step(|| devices.device_for_actor(&actor))
            .await
            .unwrap();
        assert_eq!(recovered.device_id, device.device_id);
        assert_eq!(recovered.authorization_commit, device.authorization_commit);
        eprintln!("real Bridge runtime: restart, membership and native inventory verified");
        drop(recovered);
        let revoke_operation = "retire-runtime-device";
        let revoke_reason = Some("runtime_device_retired".to_owned());
        if circle {
            // The dense Circle setup uses the same real API bucket as revocation.
            // Start response-loss injection in a fresh configured window so the
            // admitted original reaches the persistence failure under test.
            tokio::time::sleep(factory.fixture.state.config().rate_limiter.window).await;
        }
        lost_receipt.store(true, std::sync::atomic::Ordering::SeqCst);
        let failure =
            boxed_step(|| devices.revoke_device(&device, revoke_operation, revoke_reason.clone()))
                .await
                .unwrap_err();
        assert!(
            failure
                .to_string()
                .contains("injected crash before revoke receipt persistence"),
            "{failure}",
        );
        let accepted_nonces = control_nonce_count(&factory.fixture.pool, &actor).await;
        drop(devices);
        drop(edge);
        let edge = make_edge();
        let devices = ManagedDeviceRuntime::new(edge.clone()).unwrap();
        assert_eq!(
            boxed_step(|| devices.revoke_device(&device, revoke_operation, revoke_reason.clone()))
                .await
                .unwrap(),
            arkret::RealmActorDeviceRevokeState::Pending,
        );
        assert_eq!(
            control_nonce_count(&factory.fixture.pool, &actor).await,
            accepted_nonces,
            "cold recovery reads the accepted original without another control-signed submission",
        );
        assert!(
            !boxed_step(|| devices.erase_revoked_device(&device))
                .await
                .unwrap(),
            "proposal acceptance must not erase any private Device custody",
        );
        let pending_custody = boxed_step(|| devices.device_for_actor(&actor))
            .await
            .unwrap();
        assert_eq!(pending_custody.device_id, device.device_id);
        assert_eq!(
            pending_custody.authorization_event_id,
            device.authorization_event_id
        );
        drop(pending_custody);
        assert!(
            boxed_step(|| devices.revoke_device(
                &device,
                revoke_operation,
                Some("changed_intent".into())
            ))
            .await
            .is_err(),
            "an operation must not rewrite its frozen revoke intent",
        );
        assert_eq!(
            coland_http::security_rotation_worker::sweep_realm_device_revocations(
                &factory.fixture.state
            )
            .await
            .unwrap(),
            1,
            "the production worker decides the accepted proposal",
        );
        drop(devices);
        drop(edge);
        let edge = make_edge();
        let devices = ManagedDeviceRuntime::new(edge.clone()).unwrap();
        assert_eq!(
            boxed_step(|| devices.reconcile_device_revocations())
                .await
                .unwrap(),
            vec![(actor.clone(), device.device_id.clone())],
            "cold recovery reads and verifies the original terminal material",
        );
        assert!(
            boxed_step(|| devices.erase_revoked_device(&device))
                .await
                .unwrap(),
            "accepted terminal cleanup is idempotent",
        );
        assert!(
            boxed_step(|| devices.device_for_actor(&actor))
                .await
                .is_err(),
            "bootstrap cannot silently recreate a permanently retired Device operation",
        );
        assert_eq!(
            boxed_step(|| devices.revoke_device(&device, revoke_operation, revoke_reason))
                .await
                .unwrap(),
            arkret::RealmActorDeviceRevokeState::Accepted,
        );
        eprintln!(
            "real Bridge runtime: native revoke terminal and cold private-key cleanup verified"
        );
        drop(device);
        drop(devices);
        drop(edge);
        std::fs::remove_file(path).unwrap();
        boxed_step(|| private_management_archive(&factory.fixture, true)).await;
    }

    #[inline(never)]
    pub(super) fn boxed_step<F, Fut>(make: F) -> std::pin::Pin<Box<Fut>>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future,
    {
        if std::mem::size_of::<Fut>() > 262_144 {
            eprintln!(
                "large boxed fixture future: {} bytes ({})",
                std::mem::size_of::<Fut>(),
                std::any::type_name::<Fut>()
            );
        }
        Box::pin(make())
    }

    pub struct CompletionFixture {
        pub state: AppState,
        pub package: AppletPackage,
        native: NativeService,
        _governor: NetworkStation,
    }
    impl CompletionFixture {
        pub fn set_delivery_handler(&self, handler: CompletionHandler) {
            *self.native.completion_handler.lock().unwrap() = Some(handler);
        }
    }
    pub(super) async fn completion_fixture(pool: PgPool, count: usize) -> CompletionFixture {
        use arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequest;
        let (fixture, governor) = boxed_step(|| network_fixture(pool.clone())).await;
        let factory = AppletAuthoringFactory {
            fixture,
            packages: Default::default(),
            scopes: Default::default(),
        };
        let id = AppletId::new(format!("ak:applet:{}", uuid::Uuid::now_v7())).unwrap();
        let native = NativeService::new(&id, &factory.fixture.state.service_core_id());
        let package = native.package.clone();
        factory
            .packages
            .lock()
            .await
            .insert(id.to_string(), package.clone());
        let install =
            boxed_step(|| factory.prepare_install(&id, "realm-creation-completion")).await;
        let store = PgAppletStore { pool: pool.clone() };
        boxed_step(|| install.commit(&store)).await.unwrap();
        let coland_storage::AppletAdmissionRequest::Install(body) = &install.input.request;
        let source = body
            .authoring_request_basis
            .capability_grant_events
            .iter()
            .find(|event| {
                event.payload.get("grant").unwrap()["actions"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|action| action == "ak.applet.ghost.provision")
            })
            .unwrap();
        let grant = arkret_wire::GrantId::from_event_id(&source.event_id);
        for index in 0..count {
            let (candidate, signer) = realm_candidate(
                &package,
                &factory.fixture.realm,
                &body.authoring_request_basis.registration_event.event_id,
                &grant,
            );
            let mut value = json!(candidate);
            value.as_object_mut().unwrap().remove("control_signature");
            value["request_id"] = json!(uuid::Uuid::now_v7().simple().to_string());
            value["external_ref"]["external_id"] = json!(format!("completion-{index}"));
            let transcript: RealmActorCreationTranscript =
                serde_json::from_value(value.clone()).unwrap();
            value["control_signature"] = json!(
                sign_detached_object(
                    &transcript,
                    DetachedSignatureContext::RealmActorCreation,
                    candidate.control_method_kid.clone(),
                    candidate.control_signature.created_at,
                    &SigningKey::from_bytes(&[33; 32])
                )
                .unwrap()
            );
            let candidate: RealmActorCreatePayload = serde_json::from_value(value).unwrap();
            let event = arkret::author_realm_actor_create(
                candidate.clone(),
                arkret_canonical::DigestSuite::Sha256,
                candidate.control_signature.created_at,
                &signer,
            )
            .unwrap();
            let request = SelfAuthoritySubmitRequest::Event(
                arkret_wire::EventAdmissionSubmission::new(event.clone()),
            );
            let (status, outcome) = boxed_step(|| async {
                factory
                    .fixture
                    .service_post(
                        &package,
                        "/_arkret/self/events",
                        arkret_wire::ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT_V1,
                        &json!(request),
                        &format!("actual-completion-creation-{index}"),
                    )
                    .await
            })
            .await;
            assert_eq!(
                status,
                StatusCode::OK,
                "accepted original with atomic completion: {outcome}"
            );
            let original = factory
                .fixture
                .state
                .test_persistence()
                .authority_commits()
                .committed_event(&event.event_id)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(original.event, event);
        }
        CompletionFixture {
            state: factory.fixture.state.clone(),
            package,
            native,
            _governor: governor,
        }
    }

    pub(super) enum NativeSuite {
        Lifecycle,
        Mls,
        MlsAdmission,
        MlsBoundary(realm_actor_mls_fixture::BoundaryCase),
    }

    pub(super) async fn run(pool: PgPool, mls: bool) {
        let suite = if mls {
            NativeSuite::Mls
        } else {
            NativeSuite::Lifecycle
        };
        boxed_step(|| run_suite(pool, suite)).await;
    }

    pub(super) async fn run_suite(pool: PgPool, suite: NativeSuite) {
        use arkret_models_collaboration::authority_commit::{
            SelfAuthoritySubmitOutcome, SelfAuthoritySubmitRequest,
        };
        let mls = !matches!(suite, NativeSuite::Lifecycle);
        let (fixture, _governor_server) = Box::pin(network_fixture(pool.clone())).await;
        let factory = AppletAuthoringFactory {
            fixture,
            packages: Default::default(),
            scopes: Default::default(),
        };
        let id = AppletId::new(format!("ak:applet:{}", uuid::Uuid::now_v7())).unwrap();
        let mut native = NativeService::new(&id, &factory.fixture.state.service_core_id());
        if mls {
            realm_actor_mls_fixture::enable(&mut native.package);
        }
        factory
            .packages
            .lock()
            .await
            .insert(id.to_string(), native.package.clone());
        let install = boxed_step(|| factory.prepare_install(&id, "realm-native-control")).await;
        let applets = PgAppletStore { pool: pool.clone() };
        if matches!(
            &suite,
            NativeSuite::MlsBoundary(
                realm_actor_mls_fixture::BoundaryCase::ClaimExpiry
                    | realm_actor_mls_fixture::BoundaryCase::QueryExpiry
                    | realm_actor_mls_fixture::BoundaryCase::EncryptedReadExpiry,
            )
        ) {
            let finite = boxed_step(|| {
                prepare_expiring_install(
                    &factory,
                    &id,
                    "realm-native-control",
                    chrono::Utc::now() + chrono::Duration::seconds(90),
                )
            })
            .await;
            let (status, value) = boxed_step(|| async {
                factory
                    .fixture
                    .admin_post(
                        "/_arkret/self/applets/install",
                        arkret_wire::ServiceOperationId::SelfAppletCommandInstallV1.as_str(),
                        &json!(finite),
                        Some("actual-finite-native-boundary-install"),
                    )
                    .await
            })
            .await;
            assert_eq!(
                status,
                StatusCode::CREATED,
                "finite original installation: {value}"
            );
        } else {
            install.commit(&applets).await.unwrap();
        }
        let record = applets
            .get(
                id.as_str(),
                install.input.package.service_id.as_str(),
                &coland_storage::applet_effective_scope_key(&install.effective_scope).unwrap(),
            )
            .await
            .unwrap()
            .unwrap();
        let package: AppletPackage = serde_json::from_value(record["package"].clone()).unwrap();
        let registration: Event =
            serde_json::from_value(record["registration_event"].clone()).unwrap();
        let grant_event: Event = serde_json::from_value(
            record["capability_grant_events"]
                .as_array()
                .unwrap()
                .iter()
                .find(|event| {
                    event["payload"]["grant"]["actions"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .any(|action| action == "ak.applet.ghost.provision")
                })
                .unwrap()
                .clone(),
        )
        .unwrap();
        let creation_grant =
            boxed_step(|| realm_creation_quota_grant(&factory.fixture, &grant_event)).await;
        let (candidate, signer) = realm_candidate(
            &package,
            &factory.fixture.realm,
            &registration.event_id,
            &creation_grant,
        );
        boxed_step(|| {
            retired_managed_pcr_creation_is_rejected(&factory.fixture, &package, &creation_grant)
        })
        .await;
        let event = arkret::author_realm_actor_create(
            candidate.clone(),
            arkret_canonical::DigestSuite::Sha256,
            candidate.control_signature.created_at,
            &signer,
        )
        .unwrap();
        let request = SelfAuthoritySubmitRequest::Event(
            arkret_wire::EventAdmissionSubmission::new(event.clone()),
        );
        let body = serde_json::to_value(&request).unwrap();
        boxed_step(|| realm_creation_writer_failure_rolls_back(&factory.fixture, &package, &body))
            .await;
        let send = |key: &'static str| {
            factory.fixture.service_post(
                &package,
                "/_arkret/self/events",
                arkret_wire::ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT_V1,
                &body,
                key,
            )
        };
        let (status, response) = send("realm-create").await;
        assert_eq!(status, StatusCode::OK, "creation: {response}");
        let parsed: SelfAuthoritySubmitOutcome = serde_json::from_value(response).unwrap();
        parsed.validate_for_request(&request).unwrap();
        let committed = factory
            .fixture
            .state
            .test_persistence()
            .authority_commits()
            .committed_event(&event.event_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(committed.event, event);
        assert!(matches!(
            committed.commit.stream_ref,
            arkret_wire::CommitStreamRef::RealmControl { .. }
        ));
        let digest =
            arkret_wire::Hash::new(arkret_canonical::canonical_sha256(&request).unwrap()).unwrap();
        let wrong_governor = factory
            .fixture
            .state
            .test_persistence()
            .authority_commits()
            .realm_actor_creation_replay(&event, &digest, &candidate.service_id)
            .await
            .unwrap_err();
        assert!(wrong_governor.to_string().contains("stale_realm_authority"));
        let before = committed.commit.clone();
        let (status, _) = send("realm-create-retry").await;
        assert_eq!(status, StatusCode::OK);
        let replay = factory
            .fixture
            .state
            .test_persistence()
            .authority_commits()
            .committed_event(&event.event_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(replay.commit, before);
        boxed_step(|| {
            realm_creation_uniqueness_refuses_new_originals(
                &factory.fixture,
                &package,
                &registration.event_id,
                &grant_event,
                &candidate,
                &committed,
            )
        })
        .await;
        boxed_step(|| {
            realm_creation_quota_exhaustion(
                &factory.fixture,
                &package,
                &registration.event_id,
                &creation_grant,
            )
        })
        .await;
        eprintln!("native lifecycle: private material");
        Box::pin(private_material(&factory.fixture, &candidate, &before)).await;
        boxed_step(|| {
            realm_profile_control_and_writer_atomicity(&factory.fixture, &candidate, &before)
        })
        .await;
        eprintln!("native lifecycle: first Device");
        let device = if mls {
            let mut actions = vec![
                "ak.applet.join",
                "ak.event.read",
                "ak.message.create",
                "ak.mls.commit",
                "ak.mls.genesis",
            ];
            if matches!(
                suite,
                NativeSuite::MlsBoundary(
                    realm_actor_mls_fixture::BoundaryCase::EncryptedReadExpiry
                )
            ) {
                actions.push("ak.object.read_content");
            }
            boxed_step(|| {
                authorize_device_with_actions(&factory.fixture, &candidate, &before, 79, &actions)
            })
            .await
        } else {
            boxed_step(|| first_device(&factory.fixture, &candidate, &before)).await
        };
        let boundary_source = if matches!(suite, NativeSuite::MlsBoundary(_)) {
            Some(
                boxed_step(|| {
                    realm_actor_mls_fixture::prepare_boundary_current_source(&factory.fixture)
                })
                .await,
            )
        } else {
            None
        };
        eprintln!("native lifecycle: Device-authored self join");
        boxed_step(|| self_join(&factory.fixture, &candidate, &device, &record)).await;
        if mls {
            match suite {
                NativeSuite::Mls => {
                    boxed_step(|| {
                        realm_actor_mls_fixture::run(
                            &factory.fixture,
                            &package,
                            &candidate,
                            &device,
                        )
                    })
                    .await
                }
                NativeSuite::MlsAdmission => {
                    boxed_step(|| {
                        realm_actor_mls_fixture::run_admission(
                            &factory.fixture,
                            &package,
                            &candidate,
                            &device,
                        )
                    })
                    .await
                }
                NativeSuite::MlsBoundary(case) => {
                    boxed_step(|| {
                        realm_actor_mls_fixture::run_boundary(
                            &factory.fixture,
                            &package,
                            &candidate,
                            &device,
                            boundary_source.unwrap(),
                            case,
                        )
                    })
                    .await
                }
                NativeSuite::Lifecycle => unreachable!(),
            }
            return;
        }
        eprintln!("native lifecycle: independent Device revoke terminal");
        boxed_step(|| device_revoke(&factory.fixture, &candidate, &before)).await;
        eprintln!("native lifecycle: recovery");
        boxed_step(|| {
            recovery(
                &factory.fixture,
                &native,
                &candidate,
                &signer,
                &before,
                &device,
            )
        })
        .await;
        eprintln!("native lifecycle: Account governance and audit");
        boxed_step(|| governance(&factory.fixture, &native, &candidate, &before)).await;
        eprintln!("native lifecycle: cross-Station Account audit");
        boxed_step(|| cross_station_audit(&factory.fixture, &candidate)).await;
        eprintln!("native lifecycle: management Service handover");
        boxed_step(|| manager_handover(&factory, &native, &candidate)).await;
        eprintln!("native lifecycle: frozen private management archive");
        boxed_step(|| private_management_archive(&factory.fixture, false)).await;
        let store = PgAuthorityCommitStore { pool };
        let originals = store
            .applet_realm_actor_creations(&factory.fixture.realm, &id, None)
            .await
            .unwrap();
        assert_eq!(originals.len(), 1);
        assert_eq!(originals[0].event, event);
        assert!(
            factory
                .fixture
                .state
                .test_persistence()
                .accounts()
                .get(&arkret_wire::AccountId::new(
                    candidate.actor_id.signing_principal_id().clone(),
                    factory.fixture.state.service_core_id()
                ))
                .await
                .unwrap()
                .is_none()
        );
    }
}

pub async fn realm_native_creation(pool: PgPool) {
    realm_native_fixture::run(pool, false).await;
}

pub async fn realm_native_mls(pool: PgPool) {
    realm_native_fixture::run(pool, true).await;
}

pub async fn realm_native_install_admission(pool: PgPool) {
    realm_native_fixture::run_install_admission(pool).await;
}

pub async fn realm_native_authority_admission(pool: PgPool) {
    realm_native_fixture::run_authority_admission(pool).await;
}

pub async fn realm_native_mls_admission(pool: PgPool) {
    realm_native_fixture::run_suite(pool, realm_native_fixture::NativeSuite::MlsAdmission).await;
}

pub async fn realm_native_review_admission(pool: PgPool) {
    realm_native_fixture::run_reviews(pool).await;
}

macro_rules! native_boundary_entry {
    ($name:ident, $case:ident) => {
        pub async fn $name(pool: PgPool) {
            realm_native_fixture::run_suite(
                pool,
                realm_native_fixture::NativeSuite::MlsBoundary(
                    realm_actor_mls_fixture::BoundaryCase::$case,
                ),
            )
            .await;
        }
    };
}
native_boundary_entry!(
    realm_native_worker_publication_budget,
    WorkerPublicationBudget
);
native_boundary_entry!(realm_native_human_pcr_handoff, HumanPcrHandoff);
native_boundary_entry!(realm_native_claim_e2ee_expiry, ClaimExpiry);
native_boundary_entry!(realm_native_query_e2ee_expiry, QueryExpiry);
native_boundary_entry!(realm_native_encrypted_read_e2ee_expiry, EncryptedReadExpiry);
native_boundary_entry!(realm_native_exact_current_floor, ExactCurrentFloor);

pub async fn realm_bridge_runtime(pool: PgPool) {
    realm_native_fixture::run_bridge(pool, false, false, false, None).await;
}

pub async fn realm_bridge_circle_runtime(pool: PgPool) {
    realm_native_fixture::run_bridge(pool, true, false, false, None).await;
}

pub async fn realm_applet_configuration(pool: PgPool) {
    realm_native_fixture::run_configuration(pool).await;
}

pub async fn realm_bot_runtime(pool: PgPool, rotate_during_reply: bool) {
    realm_native_fixture::run_bridge(pool, false, true, rotate_during_reply, None).await;
}

pub async fn realm_runtime_key_loss_recovery(pool: PgPool, bot: bool) {
    realm_native_fixture::run_bridge(
        pool,
        false,
        bot,
        false,
        Some(realm_native_fixture::RecoveryScenario::Continue),
    )
    .await;
}

pub async fn realm_runtime_cancelled_recovery(pool: PgPool) {
    realm_native_fixture::run_bridge(
        pool,
        false,
        false,
        false,
        Some(realm_native_fixture::RecoveryScenario::CancelBeforePublish),
    )
    .await;
}

pub async fn realm_runtime_replaced_recovery(pool: PgPool) {
    realm_native_fixture::run_bridge(
        pool,
        false,
        false,
        false,
        Some(realm_native_fixture::RecoveryScenario::ReplaceBeforePublish),
    )
    .await;
}

pub async fn realm_runtime_unaccepted_recovery(pool: PgPool) {
    realm_native_fixture::run_bridge(
        pool,
        false,
        false,
        false,
        Some(realm_native_fixture::RecoveryScenario::CloseUnaccepted),
    )
    .await;
}

pub async fn realm_runtime_recovery_with_unresolved_control(pool: PgPool, accepted: bool) {
    realm_native_fixture::run_bridge(
        pool,
        false,
        false,
        false,
        Some(if accepted {
            realm_native_fixture::RecoveryScenario::AcceptedControl
        } else {
            realm_native_fixture::RecoveryScenario::UnacceptedControl
        }),
    )
    .await;
}

pub async fn realm_runtime_mls_handoff(pool: PgPool) {
    realm_native_fixture::run_bridge_case(pool, false, false, false, None, true, 0, false).await;
}

pub async fn realm_runtime_manager_transfer(pool: PgPool, bot: bool) {
    realm_native_fixture::run_bridge_case(pool, false, bot, false, None, false, 0, true).await;
}

/// Compose the existing application against the fixture's registered store.
pub fn completion_application(
    state: &AppState,
) -> coland_services::authority_commit::AuthorityCommitApplication {
    coland_services::authority_commit::AuthorityCommitApplication::new(
        coland_services::persistence::PersistenceHandle::from_shared(state.test_persistence()),
        state.config().to_device_queue_capacity,
    )
}

pub async fn realm_creation_completion_fixture(
    pool: PgPool,
) -> realm_native_fixture::CompletionFixture {
    Box::pin(realm_native_fixture::completion_fixture(pool, 1)).await
}

pub async fn realm_creation_completion_fixtures(
    pool: PgPool,
    count: usize,
) -> realm_native_fixture::CompletionFixture {
    Box::pin(realm_native_fixture::completion_fixture(pool, count)).await
}

pub async fn realm_bridge_completion_receiver(pool: PgPool) {
    realm_native_fixture::run_bridge_recipient_mode(pool, false, 3).await;
}

/// Real initial Device and KeyPackage accepted-outcome persistence recovery.
pub async fn realm_native_runtime_recovery(pool: PgPool) {
    realm_native_fixture::run_bridge_recipient_mode(pool, false, 4).await;
}

pub async fn widget_inventory_native_install_and_revoke() {
    applet_widget_inventory_fixture::run_widget_inventory().await;
}

pub async fn realm_bridge_cross_circle_queue_boundaries(pool: PgPool) {
    realm_native_fixture::run_bridge_recipient_mode(pool, true, 2).await;
}

pub async fn realm_bridge_welcome_recovery_boundaries(pool: PgPool) {
    realm_native_fixture::run_bridge_recipient_mode(pool, false, 1).await;
}
