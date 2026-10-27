#![forbid(unsafe_code)]

pub mod account_authority;
pub mod agent_origin;
mod agent_origin_http;

pub mod device_authorization_history;
pub mod fault_injection;
pub mod governance_authority;
pub mod native_tls;
pub mod pcr_genesis;
pub mod signed_event;

pub fn fixture_signer_evidence_ref() -> arkret_wire::SignerEvidenceRef {
    let digest = arkret_wire::Hash::new(format!("sha256:{}", "11".repeat(32)))
        .expect("fixture signer evidence digest");
    arkret_wire::SignerEvidenceRef::new(format!("ak:signer_evidence:{digest}"))
        .expect("fixture signer evidence reference")
}

use std::collections::{BTreeMap, BTreeSet};
use std::ops::Range;
use std::path::Path;
use std::sync::{Arc, OnceLock, Weak};

use arkret_identifiers::{Did, Hash};
use arkret_identity::service_identity::{
    DidCoreIdentityKeyRef, DidCoreIdentityState, LocalDidCoreIdentity, StoredDidCoreIdentity,
};
use arkret_models_identity::service_identity::{
    CanonicalServiceUrl, ServiceDidDocument, ServiceDidEndpoint, ServiceDidVerificationMethod,
    ServiceRegistrationKey, ServiceRegistrationReceipt,
};
use arkret_wire::{DidCoreId, ServiceKind, project_did_to_core_id};
use async_trait::async_trait;
use bytes::Bytes;
use coland_domain::reducer::ProjectionState;
use coland_http::config::AppConfig;
use coland_http::state::{AppState, AppStateRuntime, EventBroadcast};
use coland_services::delivery::ObjectStoragePort;
use coland_services::events::RealmDirectoryIndex;
use coland_services::governance::RuntimeSettingsPort;
use coland_services::jobs::RuntimeHealthPort;
use coland_services::persistence::PersistenceHandle;
use coland_services::projection::ProjectionService;
use coland_storage::PersistenceStore;
use coland_storage_postgres::PgPersistenceStore;
use coland_storage_postgres::test_database::{TestDatabase, block_on_lease_runtime};
use futures_util::stream::{self, BoxStream, StreamExt};
use parking_lot::Mutex;
use rand_core::SeedableRng;
use serde_json::Value;
use sha2::{Digest, Sha256};

pub fn app_config() -> AppConfig {
    AppConfig {
        public_base_url: "https://server.test".to_owned(),
        ..AppConfig::test_default()
    }
}

/// Lease a database and seed the fixture service identity into it.
///
/// Coland stores through one adapter, so a fixture takes a real database
/// rather than a second in-memory implementation. The lease is owned by the
/// store, so the slot returns when the last holder drops.
fn leased_fixture_persistence_with_pool(
    config: &AppConfig,
    identity: &DidCoreIdentityState,
    signing_seed: [u8; 32],
    seed_webvh_log: bool,
) -> (Arc<dyn PersistenceStore>, coland_storage_postgres::PgPool) {
    let leased = Arc::new(TestDatabase::lease_blocking());
    let pool = leased
        .db()
        .pool
        .expect("leased fixture requires PostgreSQL");
    let persistence: Arc<dyn PersistenceStore> = Arc::new(PgPersistenceStore::leased(leased));
    let stored = fixture_stored_service_identity(config, identity, signing_seed);
    let webvh_log = seed_webvh_log.then(|| fixture_service_webvh_log(config, signing_seed));
    let serve_webvh = config.embedded_webvh_provider_enabled;
    let demo = config.seed_demo_data;
    let store = persistence.clone();
    block_on_lease_runtime(async move {
        store
            .service_identity()
            .put(stored)
            .await
            .expect("fixture service identity seed");
        if let Some(log) = webvh_log {
            if serve_webvh {
                // A serving fixture needs the exact signed inception document
                // and log in one formal transaction, just like native startup.
                let now = chrono::Utc::now();
                let document = coland_storage::WebvhDocumentRecord {
                    did: log.did.clone(),
                    did_document: log.operation["state"].clone(),
                    key_log_head: Some(log.event_digest.clone()),
                    sequence: log.sequence,
                    method_evidence: serde_json::json!({"version_id":log.operation["versionId"]}),
                    fetched_at: now,
                    expires_at: now,
                    updated_at: now,
                };
                assert_eq!(
                    store
                        .webvh()
                        .commit_log_operation(None, document, log, None)
                        .await
                        .expect("fixture service WebVH inception"),
                    coland_storage::WebvhLogCommitOutcome::Accepted
                );
            } else {
                store
                    .webvh()
                    .append_log_event(log)
                    .await
                    .expect("fixture service WebVH history seed");
            }
        }
        if demo {
            seed_demo_data(store.as_ref()).await;
        }
    });
    (persistence, pool)
}

fn leased_fixture_persistence(
    config: &AppConfig,
    identity: &DidCoreIdentityState,
    signing_seed: [u8; 32],
    seed_webvh_log: bool,
) -> Arc<dyn PersistenceStore> {
    leased_fixture_persistence_with_pool(config, identity, signing_seed, seed_webvh_log).0
}

/// The demo Realm the development projection reads. The Realm id the directory
/// advertises is derived from config and identity, not read back from storage.
const DEMO_REALM_ID: &str = "ak:realm:AZAySZA7XRDeJ9cO4MqaDWrJD-rqPk6Cudk7CCzsDQz1";

/// The two rows the development demo projection reads.
async fn seed_demo_data(store: &dyn PersistenceStore) {
    let now = chrono::Utc::now();
    store
        .accounts()
        .put(&coland_storage::AccountRecord {
            // The store assigns the primary key.
            pk: coland_storage::AccountPk(0),
            principal_id: arkret_wire::DidCoreId::new("ak:did_core:web:alice.example".to_owned())
                .expect("demo principal id is canonical"),
            station_id: arkret_wire::DidCoreId::new("ak:did_core:web:server.example".to_owned())
                .expect("demo Station id is canonical"),
            localpart: "alice".to_owned(),
            display_name: Some("Alice Example".to_owned()),
            biography: None,
            avatar_blob_ref: None,
            created_at: now,
        })
        .await
        .expect("seed the demo account");
    store
        .realm_meta()
        .put(
            DEMO_REALM_ID,
            &coland_storage::RealmMetaRecord {
                owner: "ak:did_core:web:alice.example".to_owned(),
                deleted: false,
                discoverability: "public".to_owned(),
                history_access: "all_history_for_current_members".to_owned(),
                preview_policy: None,
                preview_policy_digest: None,
                asset_privacy_policy: None,
                asset_privacy_policy_digest: None,
                encryption_profile: None,
                plaintext_visible_services: BTreeSet::new(),
                plaintext_visible_service_classes: BTreeMap::new(),
                minimal_metadata_realm: false,
                created_at: now,
                updated_at: now,
            },
        )
        .await
        .expect("seed the demo Realm metadata");
}

pub fn app_state(config: AppConfig) -> AppState {
    let identity = fixture_service_identity(&config);
    let signing_seed = fixture_signing_seed(&config, &identity);
    let persistence = leased_fixture_persistence(&config, &identity, signing_seed, true);
    app_state_with_identity(config, persistence, identity, signing_seed)
}

/// Construct a test state and retain direct access to its leased PostgreSQL
/// pool. This is reserved for integration tests that must install a durable
/// pre-crash state which no public protocol operation can construct directly.
pub fn app_state_with_pool(config: AppConfig) -> (AppState, coland_storage_postgres::PgPool) {
    let identity = fixture_service_identity(&config);
    let signing_seed = fixture_signing_seed(&config, &identity);
    let (persistence, pool) =
        leased_fixture_persistence_with_pool(&config, &identity, signing_seed, true);
    let state = app_state_with_identity(config, persistence, identity, signing_seed);
    (state, pool)
}

/// Construct a test state over the same PostgreSQL authority store as production.
pub fn app_state_with_postgres_governance(config: AppConfig) -> AppState {
    app_state(config)
}
pub fn app_state_with_service_did(config: AppConfig, did: Did) -> AppState {
    let identity = fixture_service_identity_for_did(&config, did);
    let signing_seed = fixture_signing_seed(&config, &identity);
    let persistence = leased_fixture_persistence(&config, &identity, signing_seed, false);
    app_state_with_identity(config, persistence, identity, signing_seed)
}

pub async fn app_state_with_persistence(
    config: AppConfig,
    persistence: Arc<dyn PersistenceStore>,
) -> AppState {
    let identity = fixture_service_identity(&config);
    let signing_seed = fixture_signing_seed(&config, &identity);
    let stored = persistence
        .service_identity()
        .get()
        .await
        .expect("fixture service identity lookup");
    if stored.is_none() {
        persistence
            .service_identity()
            .put(fixture_stored_service_identity(
                &config,
                &identity,
                signing_seed,
            ))
            .await
            .expect("fixture service identity seed");
    }
    if persistence
        .webvh()
        .list_log_events(
            identity
                .identity()
                .expect("fixture has a serving identity")
                .did
                .as_str(),
        )
        .await
        .expect("fixture service WebVH history lookup")
        .is_empty()
    {
        let log = fixture_service_webvh_log(&config, signing_seed);
        if config.embedded_webvh_provider_enabled {
            let now = chrono::Utc::now();
            let document = coland_storage::WebvhDocumentRecord {
                did: log.did.clone(),
                did_document: log.operation["state"].clone(),
                key_log_head: Some(log.event_digest.clone()),
                sequence: log.sequence,
                method_evidence: serde_json::json!({"version_id":log.operation["versionId"]}),
                fetched_at: now,
                expires_at: now,
                updated_at: now,
            };
            assert_eq!(
                persistence
                    .webvh()
                    .commit_log_operation(None, document, log, None)
                    .await
                    .expect("fixture service WebVH inception"),
                coland_storage::WebvhLogCommitOutcome::Accepted
            );
        } else {
            persistence
                .webvh()
                .append_log_event(log)
                .await
                .expect("fixture service WebVH history seed");
        }
    }
    if config.seed_demo_data
        && persistence
            .realm_meta()
            .get(DEMO_REALM_ID)
            .await
            .expect("demo Realm metadata lookup")
            .is_none()
    {
        seed_demo_data(persistence.as_ref()).await;
    }
    app_state_with_identity(config, persistence, identity, signing_seed)
}

/// Mint a syntactically valid v1 Event-derived token for an out-of-band fixture.
///
/// The returned token is always the full 33-byte `SHA-256 suite || digest`
/// wire form. It is deliberately not an object derivation because the fixture
/// has no producer Event; fixtures that model a real create flow must build the
/// Event first and call the typed `from_event_id` constructor instead.
pub fn fixture_content_bound_id(prefix: &str) -> String {
    use sha2::Digest as _;
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let sequence = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let mut hasher = sha2::Sha256::new();
    hasher.update(b"coland:fixture-content-bound-id:v1:");
    hasher.update(prefix.as_bytes());
    hasher.update(sequence.to_be_bytes());
    hasher.update(std::process::id().to_be_bytes());
    let digest: [u8; 32] = hasher.finalize().into();
    let event_id =
        arkret_identifiers::EventId::from_digest(arkret_canonical::DigestSuite::Sha256, digest);
    arkret_identifiers::encode_event_token(prefix, event_id.token_bytes())
}

pub fn fixture_signing_seed(config: &AppConfig, identity: &DidCoreIdentityState) -> [u8; 32] {
    let _ = identity.identity().expect("fixture has a serving identity");
    fixture_service_signing_seed(config)
}

fn fixture_service_signing_seed(config: &AppConfig) -> [u8; 32] {
    config.notary_signing_key_seed.unwrap_or_else(|| {
        let mut hasher = Sha256::new();
        hasher.update(b"coland:test-fixture-notary:");
        hasher.update(config.public_base_url.as_bytes());
        hasher.finalize().into()
    })
}

fn fixture_prepared_service_inception(
    config: &AppConfig,
    signing_seed: [u8; 32],
) -> arkret_signatures::webvh::PreparedInception {
    let principal_endpoint = CanonicalServiceUrl::canonicalize(&config.public_base_url)
        .expect("test public base must be canonicalizable");
    let mut rng_seed = Sha256::new();
    rng_seed.update(b"coland:test-fixture-webvh-update:");
    rng_seed.update(config.public_base_url.as_bytes());
    let mut rng = rand_chacha::ChaCha20Rng::from_seed(rng_seed.finalize().into());
    let version_created_at = chrono::DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
        .expect("fixture WebVH timestamp")
        .with_timezone(&chrono::Utc);
    arkret_signatures::webvh::prepare_service_inception_with_did_key_seed(
        &mut rng,
        &arkret_signatures::webvh::ServiceInceptionInput {
            principal_endpoint: &principal_endpoint.as_url(),
            local_id: "service",
            also_known_as: &[],
            version_created_at,
            did_key_fragment: Some("notary-key"),
        },
        &signing_seed,
    )
    .expect("fixture service WebVH inception")
}

fn fixture_service_webvh_log(
    config: &AppConfig,
    signing_seed: [u8; 32],
) -> coland_storage::WebvhLogRecord {
    let prepared = fixture_prepared_service_inception(config, signing_seed);
    let event_digest = arkret_canonical::canonical_sha256(&prepared.log_entry)
        .expect("fixture service WebVH history digest");
    coland_storage::WebvhLogRecord {
        event_digest,
        did: prepared.did.clone(),
        sequence: 1,
        operation: prepared.log_entry.clone(),
        created_at: chrono::DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
            .expect("fixture WebVH timestamp")
            .with_timezone(&chrono::Utc),
    }
}

pub fn app_state_with_identity(
    config: AppConfig,
    persistence: Arc<dyn PersistenceStore>,
    service_identity: DidCoreIdentityState,
    resolved_signing_seed: [u8; 32],
) -> AppState {
    app_state_with_identity_and_stores(config, persistence, service_identity, resolved_signing_seed)
}

fn app_state_with_identity_and_stores(
    config: AppConfig,
    persistence: Arc<dyn PersistenceStore>,
    service_identity: DidCoreIdentityState,
    resolved_signing_seed: [u8; 32],
) -> AppState {
    let serving_identity = service_identity
        .identity()
        .expect("fixture has a serving identity");
    let service_id = serving_identity.service_id.to_string();
    let service_resolution_commitment = {
        let prepared = fixture_prepared_service_inception(&config, resolved_signing_seed);
        let method_history_head = if prepared.did == serving_identity.did.as_str() {
            arkret_canonical::canonical_sha256(&prepared.log_entry)
                .expect("fixture service WebVH history digest")
        } else {
            format!("sha256:{}", "0".repeat(64))
        };
        arkret_models_identity::ResolutionCommitment {
            did: serving_identity.did.clone(),
            method_history_head,
            version_id: serving_identity.version_id.clone(),
        }
    };
    let projections = ProjectionService::new(&service_id);
    let projection = Box::leak(Box::new(projections.test_state().clone()));
    let realm_directory = coland_http::state::build_realm_directory(
        &config,
        &serving_identity.did,
        &serving_identity.service_id,
        resolved_signing_seed,
    );
    let realms = Box::leak(Box::new(realm_directory.test_index().clone()));
    let state = AppState::from_runtime(
        config,
        AppStateRuntime {
            persistence: PersistenceHandle::from_shared(persistence.clone()),
            projections,
            realm_directory,
            object_storage: Arc::new(MemoryObjectStorage::default()),
            settings_persistence: Arc::new(NoRuntimeSettings),
            runtime_health: Arc::new(MemoryRuntimeHealth),
            event_broadcast: EventBroadcast::new(1024),
            storage_mode: "postgres",
        },
        service_identity,
        service_resolution_commitment,
        resolved_signing_seed,
    );
    register_state_resources(
        app_state_key(&state),
        StateTestResources {
            persistence: Arc::downgrade(&persistence),
            projection: Some(projection),
            realms: Some(realms),
        },
    );
    state
}
fn register_state_resources(key: usize, resources: StateTestResources) {
    let mut registry = state_test_registry().lock();
    registry.retain(|_, entry| entry.persistence.strong_count() > 0);
    registry.insert(key, resources);
}

pub trait AppStateTestExt {
    fn test_persistence(&self) -> Arc<dyn PersistenceStore>;
    fn test_projection(&self) -> &'static Arc<Mutex<ProjectionState>>;
    fn test_realms(&self) -> &'static Arc<Mutex<RealmDirectoryIndex>>;
}

impl pcr_genesis::PcrGenesisFixture {
    /// [`Self::admit_into`] against the persistence behind `state`.
    pub async fn admit(
        &self,
        state: &AppState,
    ) -> coland_storage::PersistenceResult<coland_storage::PcrGenesisCommitOutcome> {
        self.admit_into(state.test_persistence().as_ref()).await
    }
}

pub fn register_persistence(state: &AppState, persistence: &Arc<dyn PersistenceStore>) {
    register_state_resources(
        app_state_key(state),
        StateTestResources {
            persistence: Arc::downgrade(persistence),
            projection: None,
            realms: None,
        },
    );
}

impl AppStateTestExt for AppState {
    fn test_persistence(&self) -> Arc<dyn PersistenceStore> {
        state_test_registry()
            .lock()
            .get(&app_state_key(self))
            .and_then(|resources| resources.persistence.upgrade())
            .expect("AppState was not constructed by coland-test-support")
    }

    fn test_projection(&self) -> &'static Arc<Mutex<ProjectionState>> {
        state_test_registry()
            .lock()
            .get(&app_state_key(self))
            .and_then(|resources| resources.projection)
            .expect("test projection is unavailable for this AppState")
    }

    fn test_realms(&self) -> &'static Arc<Mutex<RealmDirectoryIndex>> {
        state_test_registry()
            .lock()
            .get(&app_state_key(self))
            .and_then(|resources| resources.realms)
            .expect("test Realm directory is unavailable for this AppState")
    }
}
fn app_state_key(state: &AppState) -> usize {
    state.test_registry_key()
}

struct StateTestResources {
    persistence: Weak<dyn PersistenceStore>,
    projection: Option<&'static Arc<Mutex<ProjectionState>>>,
    realms: Option<&'static Arc<Mutex<RealmDirectoryIndex>>>,
}
fn state_test_registry() -> &'static Mutex<BTreeMap<usize, StateTestResources>> {
    static REGISTRY: OnceLock<Mutex<BTreeMap<usize, StateTestResources>>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(BTreeMap::new()))
}

#[must_use]
pub fn fixture_station_id() -> DidCoreId {
    fixture_service_identity(&app_config())
        .identity()
        .expect("fixture has a serving identity")
        .service_id
        .clone()
}

pub fn fixture_service_identity(config: &AppConfig) -> DidCoreIdentityState {
    let signing_seed = fixture_service_signing_seed(config);
    let prepared = fixture_prepared_service_inception(config, signing_seed);
    fixture_service_identity_for_did_and_version(
        config,
        Did::new(prepared.did.clone()).expect("prepared fixture service DID"),
        prepared.version_id.clone(),
    )
}

fn fixture_service_identity_for_did(config: &AppConfig, did: Did) -> DidCoreIdentityState {
    fixture_service_identity_for_did_and_version(config, did, "fixture-v1".to_owned())
}

fn fixture_service_identity_for_did_and_version(
    config: &AppConfig,
    did: Did,
    version_id: String,
) -> DidCoreIdentityState {
    let registration_key = ServiceRegistrationKey::new(
        ServiceKind::Station,
        CanonicalServiceUrl::canonicalize(&config.public_base_url)
            .expect("test public base must be canonicalizable"),
    )
    .expect("station registration key");
    let signing_key_ref =
        DidCoreIdentityKeyRef::new("fixture:coland:service-signing-key").expect("fixture key ref");
    let service_id =
        project_did_to_core_id(&did).expect("fixture service DID projects to a core id");
    DidCoreIdentityState::Ready {
        identity: LocalDidCoreIdentity {
            service_id,
            did,
            registration_key,
            provider: None,
            signing_key_refs: vec![signing_key_ref.clone()],
            active_signing_key_ref: signing_key_ref,
            control_key_ref: DidCoreIdentityKeyRef::new("fixture:coland:webvh-control-key")
                .expect("fixture control key ref"),
            version_id,
            last_verified_at: chrono::Utc::now(),
        },
    }
}

fn fixture_stored_service_identity(
    config: &AppConfig,
    state: &DidCoreIdentityState,
    signing_seed: [u8; 32],
) -> StoredDidCoreIdentity {
    let identity = state
        .identity()
        .expect("fixture has a serving identity")
        .clone();
    let verification_method = format!("{}#notary-key", identity.did);
    let prepared = fixture_prepared_service_inception(config, signing_seed);
    let prepared_matches_identity = prepared.did == identity.did.as_str();
    let did_document = if prepared_matches_identity {
        serde_json::from_value(
            prepared
                .log_entry
                .get("state")
                .cloned()
                .expect("fixture WebVH inception state"),
        )
        .expect("fixture WebVH DID document")
    } else {
        ServiceDidDocument {
            context: vec!["https://www.w3.org/ns/did/v1".to_owned()],
            id: identity.did.clone(),
            also_known_as: Vec::new(),
            verification_method: vec![ServiceDidVerificationMethod {
                id: verification_method.clone(),
                method_type: "Multikey".to_owned(),
                controller: identity.did.clone(),
                public_key_multibase: arkret_canonical::ed25519_pubkey_to_did_key_multibase(
                    ed25519_dalek::SigningKey::from_bytes(&signing_seed)
                        .verifying_key()
                        .as_bytes(),
                ),
            }],
            authentication: vec![verification_method.clone()],
            assertion_method: vec![verification_method],
            service: vec![ServiceDidEndpoint {
                id: format!("{}#service", identity.did),
                endpoint_type: "ArkretService".to_owned(),
                service_kind: ServiceKind::Station,
                service_endpoint: identity.registration_key.public_base_url().clone(),
            }],
        }
    };
    let log_head_digest = if prepared_matches_identity {
        arkret_canonical::canonical_sha256(&prepared.log_entry)
            .expect("fixture service WebVH history digest")
    } else {
        format!("sha256:{}", "0".repeat(64))
    };
    let issued_at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    let provider_did = Did::new("did:webvh:z6mkfixture:provider.example:webvh:service".to_owned())
        .expect("fixture provider DID");
    let mut receipt = ServiceRegistrationReceipt {
        registration_receipt_id: arkret_wire::ServiceRegistrationReceiptId::new(format!(
            "ak:service_registration_receipt:{}",
            "a".repeat(64)
        ))
        .expect("fixture receipt id"),
        registration_key: identity.registration_key.clone(),
        service_id: identity.service_id.clone(),
        did: identity.did.clone(),
        version_id: identity.version_id.clone(),
        log_head_digest,
        control_key_digest: format!("sha256:{}", "1".repeat(64)),
        issued_at,
        provider_id: project_did_to_core_id(&provider_did).expect("fixture provider projection"),
        proof: arkret_wire::PayloadProof {
            kind: arkret_wire::proof_kind::DETACHED_JWS.to_owned(),
            verification_method: arkret_wire::DidUrl::new(format!("{provider_did}#service-key"))
                .expect("fixture provider method"),
            payload_digest: Hash::new(format!("sha256:{}", "0".repeat(64)))
                .expect("fixture receipt digest"),
            created_at: issued_at,
            domain: None,
            audience: None,
            proof_purpose: None,
            jws: format!(
                "eyJhbGciOiJFZDI1NTE5In0..{}",
                arkret_canonical::base64url::base64url_encode([0_u8; 64])
            ),
        },
    };
    receipt.registration_receipt_id = receipt
        .expected_registration_receipt_id()
        .expect("fixture receipt id binding");
    receipt.proof.payload_digest = receipt
        .expected_payload_digest()
        .expect("fixture receipt payload digest");
    let stored = StoredDidCoreIdentity {
        identity,
        did_document,
        registration_receipt: receipt,
        stored_at: issued_at,
    };
    stored
        .validate()
        .expect("valid stored fixture service identity");
    stored
}

#[derive(Default)]
struct MemoryObjectStorage {
    objects: Mutex<BTreeMap<String, Vec<u8>>>,
}

#[async_trait]
impl ObjectStoragePort for MemoryObjectStorage {
    fn backend_name(&self) -> String {
        "memory".to_owned()
    }

    fn object_key_for_sha256(&self, sha256: &str) -> String {
        format!("sha256/{sha256}")
    }

    async fn put(&self, key: &str, bytes: Vec<u8>) -> Result<(), String> {
        self.objects.lock().insert(key.to_owned(), bytes);
        Ok(())
    }

    async fn put_file(&self, key: &str, file_path: &Path) -> Result<(), String> {
        let bytes = std::fs::read(file_path).map_err(|error| error.to_string())?;
        self.put(key, bytes).await
    }

    async fn get(&self, key: &str) -> Result<Vec<u8>, String> {
        self.objects
            .lock()
            .get(key)
            .cloned()
            .ok_or_else(|| format!("object not found: {key}"))
    }

    async fn get_range_stream(
        &self,
        key: &str,
        range: Range<u64>,
    ) -> Result<BoxStream<'static, Result<Bytes, String>>, String> {
        let bytes = self.get(key).await?;
        let start = usize::try_from(range.start).map_err(|error| error.to_string())?;
        let end = usize::try_from(range.end).map_err(|error| error.to_string())?;
        let slice = bytes
            .get(start..end.min(bytes.len()))
            .ok_or_else(|| "object range is out of bounds".to_owned())?
            .to_vec();
        Ok(stream::once(async move { Ok(Bytes::from(slice)) }).boxed())
    }

    async fn delete(&self, key: &str) -> Result<(), String> {
        self.objects.lock().remove(key);
        Ok(())
    }
}

struct NoRuntimeSettings;

#[async_trait]
impl RuntimeSettingsPort for NoRuntimeSettings {
    async fn load_overrides(&self) -> coland_services::ServiceResult<Vec<(String, Value)>> {
        Ok(Vec::new())
    }

    async fn store_override(
        &self,
        _key: &str,
        _value: &Value,
        _updated_by: &str,
    ) -> coland_services::ServiceResult<()> {
        Ok(())
    }
}

struct MemoryRuntimeHealth;

#[async_trait]
impl RuntimeHealthPort for MemoryRuntimeHealth {
    async fn database_ready(&self) -> bool {
        true
    }

    fn storage_mode(&self) -> &'static str {
        "memory"
    }

    fn migrations_applied(&self) -> bool {
        true
    }

    fn database_configured(&self) -> bool {
        false
    }

    fn database_pool_in_use(&self) -> u32 {
        0
    }
}

/// Real PostgreSQL Human source/admission fixture shared by transport regressions.
#[path = "../../storage-postgres/tests/support/historical_human.rs"]
pub mod historical_human;

/// Counts only: actual native-control accepted/staging/history/outbox footprint.
/// No identity, key, payload or protocol material is returned.
pub async fn native_control_source_footprint(
    pool: &coland_storage_postgres::PgPool,
) -> serde_json::Value {
    use diesel_async::RunQueryDsl;
    #[derive(diesel::QueryableByName)]
    struct Counts {
        #[diesel(sql_type=diesel::sql_types::Jsonb)]
        value: serde_json::Value,
    }
    let mut conn = pool.get().await.expect("fixture PG connection");
    diesel::sql_query("SELECT jsonb_build_object('events',(SELECT count(*) FROM canonical_events),'commits',(SELECT count(*) FROM realm_commits),'sources',(SELECT count(*) FROM agent_origin_control_sources),'histories',(SELECT count(*) FROM agent_origin_commit_histories),'staging',(SELECT count(*) FROM agent_origin_control_source_candidates),'facts',(SELECT count(*) FROM agent_producer_signer_keys),'outbox',(SELECT count(*) FROM event_federation_outbox),'roots',(SELECT count(*) FROM account_device_signer_evidence),'gates',(SELECT count(*) FROM agent_origin_gate_intents),'forward',(SELECT count(*) FROM agent_origin_forward_evidence)) AS value")
        .get_result::<Counts>(&mut conn).await.expect("actual source footprint").value
}
