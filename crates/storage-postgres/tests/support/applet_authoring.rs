//! Real authoring inputs for the shared Applet transaction contract.
//! Mirrors the registered HTTP fixture's signed prerequisites; commits always
//! pass the production closed aggregate, never a synthetic verified flag.

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
use diesel_async::RunQueryDsl as _;
use ed25519_dalek::SigningKey;
use salvo::http::StatusCode;
use salvo::test::{ResponseExt, TestClient};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use url::Url;

use super::ordinary_realm;

struct ManagedActorFixture {
    actor_id: arkret_identifiers::DidCoreId,
    initial_resolution: arkret_models_identity::ResolutionCommitment,
    method_history_evidence: arkret_models_identity::ResolutionMethodHistoryEvidence,
    inception_log_entry: Value,
}

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
        let slot = Arc::new(Mutex::new(Value::Null));
        let origin = spawn_introspection_mock(slot.clone()).await;
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
        config.register_test_internal_authority_channel("applet-http-standard-grant".to_owned());
        let persistence = Arc::new(coland_storage_postgres::PgPersistenceStore::new(
            pool.clone(),
        ));
        let state = coland_test_support::app_state_with_persistence(config, persistence).await;
        let pcr = PcrGenesisFixture::new(state.service_did());
        Box::pin(pcr.admit(&state)).await.unwrap();
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
        accepted_admin_domain_event(self, create).await;
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
                .prepare_human_signer_fact(&tx.event, tx.commit.committed_at)
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
            event.payload.get_mut("object").unwrap()["created_at"] =
                serde_json::to_value(event.created_at).unwrap();
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
            let mut response = request.send(&service(self.state.clone())).await;
            let status = response.status_code.unwrap();
            (status, response.take_json().await.unwrap())
        })
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
        let source_service_id = package.service_id.to_string();
        let destination_service_id = self.state.service_id().to_owned();
        let signed_request = SignedRequestParts {
            method: "POST".to_owned(),
            target_uri: format!("{scheme}://server{path}"),
            authority: "server".to_owned(),
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
        let signature = sign_http_message_for_scenario(
            &signed_request,
            if operation == arkret_wire::ServiceOperationId::SELF_APPLET_AUTHORITY_READ_MATERIAL_V1
            {
                HttpSignatureScenario::ServiceToServiceV1
            } else {
                HttpSignatureScenario::AppletTransactionV1
            },
            if operation == arkret_wire::ServiceOperationId::SELF_APPLET_AUTHORITY_READ_MATERIAL_V1
            {
                &["content-digest", "idempotency-key"]
            } else {
                &[]
            },
            "sig1",
            &package.webhook_auth.key_ref,
            created,
            &applet_service_signing_key(&package.webhook_auth.key_ref),
        )
        .unwrap();
        let mut response = TestClient::post(format!("http://server{path}"))
            .add_header("Arkret-Operation", operation, true)
            .add_header("content-type", "application/json", true)
            .add_header("Content-Digest", digest, true)
            .add_header("Source-Service-ID", source_service_id, true)
            .add_header("Destination-Service-ID", destination_service_id, true)
            .add_header("Idempotency-Key", key, true)
            .add_header("Signature-Input", signature.signature_input_header, true)
            .add_header("Signature", signature.signature_header, true)
            .body(bytes)
            .send(&service(self.state.clone()))
            .await;
        (
            response.status_code.unwrap(),
            response.take_json().await.unwrap(),
        )
    }

    fn managed_bundle(
        &self,
        package: &AppletPackage,
        request: &AppletManagedActorAuthoringRequest,
        actor: &ManagedActorFixture,
        registration: EventId,
    ) -> AppletManagedActorAuthoringBundle {
        let signer = Ed25519PayloadSigner::new(
            applet_service_signing_key(&package.webhook_auth.key_ref),
            applet_service_did(package),
            package.webhook_auth.key_ref.clone(),
        );
        arkret::author_applet_managed_actor_bundle(
            request,
            arkret::AppletManagedActorBundleAuthoringInput {
                actor_id: actor.actor_id.clone(),
                initial_resolution: actor.initial_resolution.clone(),
                method_history_evidence: actor.method_history_evidence.clone(),
                registration_ref: registration,
                digest_suite: arkret_canonical::DigestSuite::Sha256,
                genesis_salt: arkret_wire::GenesisSalt::generate().unwrap(),
                trust_domain: arkret_wire::TrustDomainId::new("ak:trust_domain:applet.example")
                    .unwrap(),
                security_class: arkret_wire::SecurityClass::HighAssurance,
                initial_join_rule: arkret_wire::JoinRule::Closed,
                initial_history_access: arkret_wire::HistoryAccess::SinceJoin,
                initial_discoverability: arkret_wire::Discoverability::Secret,
                bot_display_name: "Installed Applet Bot".to_owned(),
            },
            &signer,
        )
        .unwrap()
    }
}

fn deterministic_managed_actor_seed(label: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"coland:extensions-smoke:managed-actor:");
    hasher.update(label.as_bytes());
    hasher.finalize().into()
}

fn managed_actor_fixture(
    namespace: &str,
    local_id: &str,
    controller_principal_id: &arkret_identifiers::DidCoreId,
) -> ManagedActorFixture {
    let endpoint: Url = format!("https://{}.applet.example/", safe_did_token(namespace))
        .parse()
        .expect("fixture managed-actor endpoint");
    let local_id = safe_did_token(local_id);
    let root_seed = deterministic_managed_actor_seed(&format!(
        "{}:{local_id}:root:{controller_principal_id}",
        safe_did_token(namespace)
    ));
    let next_seed = deterministic_managed_actor_seed(&format!(
        "{}:{local_id}:next:{controller_principal_id}",
        safe_did_token(namespace)
    ));
    let next_key = arkret_canonical::ed25519_pubkey_to_did_key_multibase(
        SigningKey::from_bytes(&next_seed)
            .verifying_key()
            .as_bytes(),
    );
    let version_time = chrono::DateTime::parse_from_rfc3339("2026-08-24T00:00:00.000Z")
        .unwrap()
        .with_timezone(&chrono::Utc);
    let inception = arkret_signatures::webvh::prepare_agent_inception(
        &arkret_signatures::webvh::AgentInceptionInput {
            principal_endpoint: &endpoint,
            local_id: &local_id,
            controller_principal_id,
            version_time,
            root_seed: &root_seed,
            next_root_public_key_multibase: &next_key,
        },
    )
    .expect("fixture managed-actor WebVH inception");
    let did = Did::new(inception.did.clone()).expect("fixture managed-actor DID");
    let actor_id = arkret_wire::project_did_to_core_id(&did)
        .expect("fixture managed-actor Core DID projection");
    let method_history_head = arkret_canonical::canonical_sha256(&inception.log_entry)
        .expect("fixture WebVH history head");
    let normalized_document: arkret_models_identity::DidDocument =
        serde_json::from_value(inception.log_entry["state"].clone())
            .expect("fixture WebVH DID document");
    let document_digest = arkret_identity::document_canonical_digest(&normalized_document)
        .expect("fixture WebVH document digest");
    let witness_records = Vec::<Value>::new();
    let witness_proofs_digest = arkret_identifiers::Hash::new(
        arkret_canonical::canonical_sha256(&witness_records).expect("fixture WebVH witness digest"),
    )
    .unwrap();
    let boundary = arkret_models_identity::ResolutionMethodEvidenceBoundary {
        from_method_history_head: method_history_head.clone(),
        from_version_id: inception.version_id.clone(),
        to_method_history_head: method_history_head.clone(),
        to_version_id: inception.version_id.clone(),
    };
    let method_history_evidence =
        arkret_models_identity::ResolutionMethodHistoryEvidence::WebvhLog {
            boundary,
            evidence: arkret_models_identity::ResolutionDidBindingEvidenceReceipt {
                kind:
                    arkret_models_identity::ResolutionDidBindingEvidenceKind::AkDidBindingEvidenceV1,
                method: "webvh".to_owned(),
                document_digest,
                method_proofs: vec![arkret_models_identity::ResolutionDidBindingMethodProof {
                    kind: arkret_models_identity::ResolutionDidBindingMethodProofKind::WebvhLog,
                    history_head: method_history_head.clone(),
                    witnesses: Vec::new(),
                    witness_proofs_digest,
                }],
            },
            log_entries: vec![inception.log_entry.clone()],
            witness_records,
        };
    ManagedActorFixture {
        actor_id,
        initial_resolution: arkret_models_identity::ResolutionCommitment {
            did,
            method_history_head,
            version_id: inception.version_id,
        },
        method_history_evidence,
        inception_log_entry: inception.log_entry,
    }
}

async fn ingest_managed_actor_current_document(state: &AppState, actor: &ManagedActorFixture) {
    let now = chrono::Utc::now();
    let did = actor.initial_resolution.did.to_string();
    let document = actor.inception_log_entry["state"].clone();
    let record = coland_storage::WebvhDocumentRecord {
        did: did.clone(),
        did_document: document,
        key_log_head: Some(actor.initial_resolution.method_history_head.clone()),
        seq: 1,
        method_evidence: serde_json::to_value(&actor.method_history_evidence).unwrap(),
        fetched_at: now,
        expires_at: now + chrono::Duration::minutes(15),
        updated_at: now,
    };
    state
        .test_persistence()
        .webvh()
        .append_log_event(coland_storage::WebvhLogRecord {
            event_digest: actor.initial_resolution.method_history_head.clone(),
            did,
            seq: 1,
            operation: actor.inception_log_entry.clone(),
            created_at: now,
        })
        .await
        .unwrap();
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

fn content_digest_header(bytes: &[u8]) -> String {
    let raw = Sha256::digest(bytes);
    format!(
        "sha-256=:{}:",
        base64::engine::general_purpose::STANDARD.encode(raw)
    )
}

fn applet_service_signing_key(verification_method: &str) -> SigningKey {
    if verification_method.ends_with("#applet-native-key") {
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
    let service_did = Did::new(format!(
        "did:webvh:zsvc{}:{}.applet.example",
        namespace.replace(|ch: char| !ch.is_ascii_alphanumeric(), ""),
        safe_did_token(namespace)
    ))
    .unwrap();
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
            actors: vec![AppletNamespaceEntry::exclusive(format!(
                "did:webvh:*:{}.applet.example:webvh:*",
                safe_did_token(namespace)
            ))],
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
            service_method_version_evidence(),
        )
        .unwrap();
    package.requested_scopes = vec![
        "ak.message.create".to_owned(),
        "ak.applet.bot.provision".to_owned(),
        "ak.applet.ghost.provision".to_owned(),
    ];
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

fn applet_service_id_document(package: &AppletPackage) -> arkret_identity::DidDocument {
    let applet_signing_key = applet_service_signing_key(&package.webhook_auth.key_ref);
    arkret_identity::DidDocument {
        id: applet_service_did(package),
        verification_methods: BTreeMap::from([(
            package.webhook_auth.key_ref.to_string(),
            arkret_canonical::ed25519_pubkey_to_did_key_multibase(
                applet_signing_key.verifying_key().as_bytes(),
            ),
        )]),
        also_known_as: Vec::new(),
        updated_at: Some(package.created_at),
        raw_properties: BTreeMap::new(),
    }
}

async fn ingest_applet_service_id_document(state: &AppState, package: &AppletPackage) {
    let now = chrono::Utc::now();
    let document = applet_service_id_document(package);
    let record = coland_storage::WebvhDocumentRecord {
        did: document.id.to_string(),
        did_document: serde_json::to_value(document).unwrap(),
        key_log_head: None,
        seq: 0,
        method_evidence: serde_json::to_value(service_method_version_evidence()).unwrap(),
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

fn service_method_version_evidence() -> AppletDidMethodVersionEvidence {
    AppletDidMethodVersionEvidence::versioned(
        "did:webvh",
        Some("1-QmFixtureAppletServiceVersion".to_owned()),
        None,
    )
    .unwrap()
}

fn applet_registration_epoch_evidence(
    package: &AppletPackage,
) -> arkret_models_integration::AppletRegistrationEpochEvidence {
    arkret_models_integration::AppletRegistrationEpochEvidence::from_did_document(
        &applet_service_id_document(package),
        service_method_version_evidence(),
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

async fn spawn_introspection_mock(slot: Arc<Mutex<Value>>) -> String {
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
            tokio::spawn(async move {
                read_http_request(&mut stream).await;
                let body = serde_json::to_vec(&*slot.lock().unwrap()).expect("serialize outcome");
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

async fn read_http_request(stream: &mut tokio::net::TcpStream) {
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
            return;
        }
    }
}

async fn admin_domain_request(
    fixture: &Fixture,
    event: Event,
) -> coland_storage::EventCommitRequest {
    let producer = event
        .human_device_producer()
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
    if let Some(fact) = request
        .authority_commit
        .producer_signer_fact
        .as_ref()
        .and_then(|fact| fact.as_human())
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
            self.fixture.new_circle_scope().await
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
            coland_storage::AppletAdmissionRequest::Managed(
                AppletManagedActorCommittedRequest::Ghost(body),
            ) => {
                let basis = body.authoring_request.basis.ghost().unwrap();
                let subject=arkret_canonical::canonical_sha256(&json!({"purpose":"provision_ghost","applet_id":basis.applet_id,
                    "target_station_id":basis.target_station_id,"external_ref":basis.external_ref,"effective_scope":basis.effective_scope})).unwrap();
                (
                    ActorId::service(package.service_id.clone()),
                    body.authoring_request.canonical_digest().unwrap(),
                    "ak.self.applet.ghost.command.provision",
                    subject,
                )
            }
            _ => panic!("contract authoring factory has only Service install/Ghost branches"),
        };
        let digest = Hash::new(arkret_canonical::canonical_sha256(&request).unwrap()).unwrap();
        coland_storage::AppletAuthoringUnitWrite {
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
            expected_identity: identity,
            expected_installation: installation,
            preview_subject_key: preview,
            request_digest,
            canonical_request_hash: digest,
            operation_id: operation.to_owned(),
            idempotency_key: format!("contract-{}", uuid::Uuid::now_v7()),
            prior_managed_refs: vec![],
            prior_service_signer_evidence: None,
            accepted_at: arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now()),
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
                let namespace = format!("contract.{}", uuid::Uuid::now_v7().simple());
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
        let registration = self.fixture.admin_event(
            EventKind::AppletRegistration,
            scope.clone(),
            serde_json::to_value(package.to_registration(&evidence).unwrap()).unwrap(),
        );
        let mut actions = vec![
            "ak.message.create",
            "ak.applet.bot.provision",
            "ak.applet.ghost.provision",
        ];
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
                "ghost_actor_mode":"policy_declared","delegated_native_actors_allowed":false,"e2ee_join_allowed":false,"widget_allowed":false},
            "actor_policy":{"ghost_actor_mode":"policy_declared"},"e2ee_policy":{"mls_join_allowed":false},"widget_policy":{"widget_allowed":false},
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
                    registration_event_ref: accepted_ref(refs, registration)?.event_id,
                    registration_epoch: package.registration_epoch.clone(),
                    capability_grant_refs: grant_refs.clone(),
                    e2ee_authorization_refs: vec![],
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
                    "capabilities":actions,"package":package,"ghost_actors_allowed":true,"status":"installed","registered_at":frozen.accepted_at,"revoked_at":null,
                    "idempotency_key":frozen.idempotency_key,"install_body_digest":frozen.canonical_request_hash,"install_id":outcome.install_id,"install_response":outcome,
                    "registration_event":registration,"capability_grant_events":grants,
                    "install_execution":{"idempotency_key":frozen.idempotency_key,"body_hash":frozen.canonical_request_hash,"submitted_plan_digest":body.plan_digest,
                        "produced_event_refs":produced.iter().map(|event|&event.event_id).collect::<Vec<_>>(),"steps":steps},
                    "revoke_execution":null,"bots":[],"ghosts":[],
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

    async fn prepare_ghost(
        &self,
        applet_id: &AppletId,
        scope: &ScopeRef,
        external: &str,
        actor_label: &str,
    ) -> AppletFormalCommitUnit {
        let store = PgAppletStore {
            pool: self.fixture.pool.clone(),
        };
        let old = store
            .get(
                applet_id.as_str(),
                &coland_storage::applet_effective_scope_key(scope).unwrap(),
            )
            .await
            .unwrap()
            .unwrap();
        let package: AppletPackage = serde_json::from_value(old["package"].clone()).unwrap();
        let identity = store
            .get_identity(applet_id.as_str(), self.fixture.state.service_id())
            .await
            .unwrap()
            .unwrap();
        let display_name = old["ghosts"]
            .as_array()
            .unwrap()
            .iter()
            .find(|ghost| ghost["external_ref"]["external_id"] == external)
            .and_then(|ghost| ghost["display_name"].as_str())
            .unwrap_or(actor_label);
        let path = format!("/_arkret/self/applets/{applet_id}/ghosts/provision/preview");
        let (status, preview) = self.fixture.service_post(&package, &path, arkret_wire::ServiceOperationId::SELF_APPLET_GHOST_COMMAND_PREVIEW_V1,
            &json!({"effective_scope":scope,"external_ref":{"protocol":"slack","instance_id":"team","external_id":external},"display_name":display_name}),
            &format!("preview-{}",uuid::Uuid::now_v7())).await;
        assert_eq!(status, StatusCode::OK, "{preview}");
        let request: AppletManagedActorAuthoringRequest =
            serde_json::from_value(preview["authoring_request"].clone()).unwrap();
        let basis = request.basis.ghost().unwrap().clone();
        let existing = basis.existing_managed_actor.clone();
        let bundle = if existing.is_some() {
            None
        } else {
            let namespace = package.namespaces.handles[0].pattern.clone();
            let actor = managed_actor_fixture(&namespace, actor_label, &package.service_id);
            ingest_managed_actor_current_document(&self.fixture.state, &actor).await;
            Some(
                self.fixture.managed_bundle(
                    &package,
                    &request,
                    &actor,
                    serde_json::from_value(
                        old["install_response"]["registration_event_ref"].clone(),
                    )
                    .unwrap(),
                ),
            )
        };
        let body = GhostActorProvisionRequestBody {
            authoring_request: request.clone(),
            managed_actor_bundle: bundle.clone(),
            existing_managed_actor: existing.clone(),
            approval_signatures: vec![],
        };
        let (author, attester) = self.callbacks(&[]);
        let mut input = self.input(
            coland_storage::AppletAdmissionRequest::Managed(
                AppletManagedActorCommittedRequest::Ghost(Box::new(body.clone())),
            ),
            &package,
            vec![],
            Some(identity),
            Some(old.clone()),
            None,
        );
        let events: Vec<Event> = if let Some(bundle) = &bundle {
            vec![
                bundle.managed_actor_provision_event.clone(),
                bundle.pcr_genesis_event.clone(),
                bundle.accountability_grant_event.clone(),
                bundle.profile_event.clone(),
            ]
        } else {
            let external_json = serde_json::to_value(&basis.external_ref).unwrap();
            let ghost = old["ghosts"]
                .as_array()
                .unwrap()
                .iter()
                .find(|ghost| ghost["external_ref"] == external_json)
                .unwrap();
            [
                "managed_actor_provision_event",
                "pcr_genesis_event",
                "accountability_grant_event",
                "profile_event",
            ]
            .iter()
            .map(|field| serde_json::from_value(ghost[field].clone()).unwrap())
            .collect()
        };
        if existing.is_some() {
            let authority = PgAuthorityCommitStore {
                pool: self.fixture.pool.clone(),
            };
            for event in &events {
                let accepted = authority
                    .committed_event(&event.event_id)
                    .await
                    .unwrap()
                    .unwrap();
                input
                    .prior_managed_refs
                    .push(arkret_wire::CommittedEventRef {
                        event_id: accepted.event.event_id,
                        commit_id: accepted.commit.commit_id,
                        stream_ref: accepted.commit.stream_ref,
                        stream_position: accepted.commit.stream_position,
                    });
            }
        }
        let event_ids = events
            .iter()
            .map(|event| event.event_id.to_string())
            .collect();
        let frozen = input.clone();
        let finalize: AppletFormalFinalizer = Arc::new(
            move |refs, expected_identity, expected_record| {
                for event in &events {
                    accepted_ref(refs, event)?;
                }
                let mut record = expected_record
                    .clone()
                    .expect("Ghost follows an accepted installation");
                let provision: AppletManagedActorProvisionPayload =
                    serde_json::from_value(serde_json::to_value(&events[0].payload).unwrap())
                        .unwrap();
                let ghost = json!({"ghost_actor_id":provision.actor_id,"external_ref":basis.external_ref,"display_name":basis.display_name,
                "request_digest":frozen.canonical_request_hash,"managed_actor_provision_event":events[0],"pcr_genesis_event":events[1],
                "accountability_grant_event":events[2],"profile_event":events[3],"created_at":frozen.accepted_at});
                let ghosts = record["ghosts"].as_array_mut().unwrap();
                if let Some(old) = ghosts.iter_mut().find(|ghost| {
                    ghost["external_ref"] == serde_json::to_value(&basis.external_ref).unwrap()
                }) {
                    // Reuse retains all original accepted anchors and creation time.
                    old["request_digest"] =
                        serde_json::to_value(&frozen.canonical_request_hash).unwrap();
                } else {
                    ghosts.push(ghost);
                }
                let response = GhostActorProvisionOutcome {
                    ghost_actor_id: provision.actor_id.clone(),
                    managed_actor_provision_ref: accepted_ref(refs, &events[0])?.event_id,
                    principal_control_realm_id: RealmId::from_event_id(&events[1].event_id),
                    profile_event_ref: accepted_ref(refs, &events[3])?.event_id,
                    accountability_grant_ref: accepted_ref(refs, &events[2])?.event_id,
                    authorization_ref: basis.authorization_ref.clone(),
                    display_name: basis.display_name.clone(),
                };
                Ok(finalized(
                    &frozen,
                    expected_identity.clone().unwrap(),
                    expected_identity,
                    record,
                    expected_record,
                    serde_json::to_value(response).unwrap(),
                ))
            },
        );
        AppletFormalCommitUnit {
            input,
            author,
            attester,
            finalize,
            event_ids,
            effective_scope: scope.clone(),
        }
    }
}
