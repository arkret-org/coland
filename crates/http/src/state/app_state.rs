use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};

use arc_swap::ArcSwap;
use arkret_identifiers::{Did, DidCoreId, Hash, RealmId};
use arkret_identity::service_identity::DidCoreIdentityState;
#[cfg(test)]
use arkret_identity::service_identity::{DidCoreIdentityKeyRef, LocalDidCoreIdentity};
use arkret_models_collaboration::objects::account_status::AccountStatus;
use arkret_models_identity::ResolutionCommitment;
use arkret_models_identity::account::AccountRegistrationPolicy;
#[cfg(test)]
use arkret_models_identity::service_identity::{CanonicalServiceUrl, ServiceRegistrationKey};
#[cfg(test)]
use arkret_wire::ServiceKind;
#[cfg(test)]
use coland_domain::reducer::ProjectionState;
use coland_services::authority_commit::AuthorityCommitApplication;
use coland_services::delivery::{DeliveryService, ObjectStoragePort};
use coland_services::events::{
    EventQueryService, EventService, InviteLocatorService, MlsGroupQueryService,
    MlsKeyPackageService, RealmDirectoryEntry, RealmDirectoryIndex, RealmDirectoryService,
    RealmQueryService,
};
use coland_services::federation::FederationService;
use coland_services::governance::{GovernanceService, RuntimeSettingsPort};
use coland_services::hydration::HydrationProjectionAdapter;
use coland_services::identity::{
    AccountDataService, AgentPairingService, AgentParticipationService, ConsentService,
    ContactService, DidService, IdentityService, KeyBackupService, KeyMaterialService,
    RecoveryPolicyService, RecoverySessionService, SecurityTransactionService, SessionService,
};
use coland_services::jobs::{JobsService, RuntimeHealthPort};
use coland_services::organization_registration::OrganizationRegistrationService;
use coland_services::persistence::PersistenceHandle;
use coland_services::persistence_events::PersistenceEventServices;
use coland_services::persistence_identity::PersistenceIdentityServices;
use coland_services::persistence_operations::PersistenceOperationalServices;
use coland_services::projection::{ProjectionService, ServiceClock};
use coland_services::runtime_guards::{
    KeyBackupDownloadOutcome, ModerationReportRateOutcome, RuntimeGuardService,
};
use coland_services::service_route::ServiceRouteResolver;
use coland_services::sync::SyncService;
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde_json::Value;
use sha2::{Digest, Sha256};

use super::member_identity::MemberIdentityRegistry;
use super::notification::{EventBroadcast, EventNotification, Mutex};
use super::{
    AccountAuthorityDevicePairingPort, PrivateAccountAuthorityDevicePairing,
    VerifiedBindingRouteFetcher, did_resolver_chain,
};
use crate::config::{AppConfig, NotarySigningKeyOrigin};
use crate::verified_profiles::VerifiedProfileArtifactEntry;

/// Upper bound on accepted DID bindings held in process. Eviction is
/// deterministic (oldest `verified_at` first) in the SDK store, and evicting a
/// binding only costs one re-acceptance — never a downgrade of trust.
const DID_BINDING_STORE_CAPACITY: usize = 4_096;

/// Reconnect delay a drained peer must honour before dialling again. It gives
/// the replacement instance time to become the one that answers.
const CONNECTION_DRAIN_RECONNECT_AFTER_MS: u32 = 5_000;

/// A published service drain: reconnect no sooner than `reconnect_after_ms`,
/// and expect this instance to stop serving at `deadline`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConnectionDrain {
    pub reconnect_after_ms: u32,
    pub deadline: chrono::DateTime<chrono::Utc>,
}

/// Single-process service state. Every long-lived data surface lives behind
/// `persistence` (a `dyn PersistenceStore`); the few remaining fields are
/// either non-record state (config, db pool, hlc, authz engine) or runtime
/// facets that don't fit the trait shape (in-memory `RealmDirectoryIndex`,
/// DID resolver service, `ProjectionState`).
#[derive(Clone)]
pub struct AppState {
    verifier_private_keystore: Option<Arc<dyn arkret_keystore::KeyStore>>,
    config: AppConfig,
    /// Runtime-authoritative service DID. It is resolved from durable identity
    /// state before construction and is never loaded from configuration.
    service_id: String,
    /// Full service-identity lifecycle state used by readiness, doctor, and
    /// identity-mutation gates.
    service_identity: Arc<ArcSwap<DidCoreIdentityState>>,
    /// Exact current service method-history coordinates. Public describe,
    /// open resolution, and Account-Authority gate assembly all read this
    /// same snapshot instead of projecting a stable DidCoreId back into a DID.
    service_resolution_commitment: Arc<ArcSwap<ResolutionCommitment>>,
    /// Mutable operational overlay (admin allowlist, rate-limit ceilings,
    /// federation peers, feature toggles). Seeded from `config` at boot,
    /// overlaid by the `server_settings` DB row in [`AppState::hydrate`], and
    /// hot-swapped by the admin settings endpoint. Read a consistent snapshot
    /// via [`AppState::settings`]. See [`crate::runtime_settings`].
    settings: Arc<ArcSwap<crate::runtime_settings::RuntimeSettings>>,
    storage_mode: &'static str,
    persistence: PersistenceHandle,
    authority_commits: AuthorityCommitApplication,
    events: EventService,
    event_queries: EventQueryService,
    mls_groups: MlsGroupQueryService,
    mls_key_packages: MlsKeyPackageService,
    realms: RealmQueryService,
    invite_locators: InviteLocatorService,
    deliveries: DeliveryService,
    identities: IdentityService,
    account_data: AccountDataService,
    key_material: KeyMaterialService,
    consents: ConsentService,
    pub(crate) call_invitations: Arc<
        Mutex<
            BTreeMap<
                String,
                arkret_models_collaboration::call_invitation::CallInvitationSendRequestBody,
            >,
        >,
    >,
    contacts: ContactService,
    agent_pairings: AgentPairingService,
    account_authority_device_pairing: Arc<dyn AccountAuthorityDevicePairingPort>,
    agent_participations: AgentParticipationService,
    key_backups: KeyBackupService,
    sessions: SessionService,
    recovery_policies: RecoveryPolicyService,
    recovery_sessions: RecoverySessionService,
    security_transactions: SecurityTransactionService,
    dids: DidService,
    /// Unique process-wide injection point for outbound service routing.
    /// Sending code must use this shared resolver (and fail closed while it is
    /// absent) so cache, durable floor, and quarantine decisions cannot split
    /// across ad-hoc resolver instances.
    service_route_resolver: Arc<Mutex<Option<Arc<ServiceRouteResolver>>>>,
    /// Immutable deployment trust roots for public Push Gateways.  Resolver
    /// output remains untrusted for handoff until it is bound to one of these
    /// exact origin/DID/receipt-key tuples.
    trusted_push_gateways: Arc<crate::push_gateway_registry::TrustedPushGatewayRegistry>,
    /// Accepted DID authority bindings (`did-usage-and-verification.md` §5).
    ///
    /// This is the SDK's shared value object + store — coland deliberately does
    /// not define a parallel model. Ordinary Event ingress consults it before
    /// touching the authority path, so a second Event signed by the same
    /// accepted key resolves nothing.
    did_bindings: Arc<dyn arkret_identity::VerifiedDidBindingStore>,
    organization_registrations: OrganizationRegistrationService,
    federation: FederationService,
    governance: GovernanceService,
    sync: SyncService,
    jobs: JobsService,
    projections: ProjectionService,
    pub(crate) device_history_cache: Arc<
        tokio::sync::Mutex<
            BTreeMap<
                arkret_wire::AccountId,
                Arc<crate::routing::identity::device_generation::ConfirmedDeviceHistory>,
            >,
        >,
    >,
    realm_directory: RealmDirectoryService,
    /// Deployment-local account registration policy. It uses the canonical
    /// account-operation DTO so the HTTP handler, audit payload, tests, and a
    /// future admin policy cell all speak the same wire vocabulary.
    account_registration_policy: Arc<Mutex<AccountRegistrationPolicy>>,
    runtime_guards: RuntimeGuardService,
    /// Domain-separated root key for service-scoped push target pseudonyms.
    /// Per-epoch keys are derived from this root inside the push routing
    /// module; only public epoch labels are exposed on describe.
    /// Revoked cursor authorities (`ak.self.account.command.revoke_cursor.v1`). High-assurance
    /// optional endpoint: a revoked cursor returns `cursor_revoked` and MUST NOT
    /// advance to-device ack, account-subscribe resume position, wait-for barrier
    /// state, or dropped-recovery state. Entries are pruned once the revoked
    /// cursor's maximum TTL has elapsed (`CursorRevocation::expires_at`).
    /// Monotonic position allocator for to-device queues. Cursor ack uses
    /// numeric `position <= ack_position` pruning, so positions must advance
    /// even when multiple fanout writes land in the same wall-clock microsecond.
    to_device_position_counter: Arc<AtomicI64>,
    /// Runtime-only verification keys learned from endpoint-discovered
    /// federation peer DID documents. Entries are keyed either by service DID
    /// (the HTTP Message Signature key) or by an exact verification-method
    /// DID URL (artifact-specific assertion keys). Configuration contains
    /// endpoints, not copied service DIDs or public-key pins; discovery
    /// validates the document's Station endpoint binding before
    /// publishing a key.
    federation_peer_verifying_keys: Arc<ArcSwap<BTreeMap<String, VerifyingKey>>>,
    /// Contact assertions can reuse one method URL across service-key
    /// rotations. Keys resolved from verified DID history therefore bind to
    /// the signature's evidence time as well as its exact method.
    historical_contact_assertion_keys:
        Arc<Mutex<BTreeMap<(String, chrono::DateTime<chrono::Utc>), VerifyingKey>>>,
    /// Live event notification bus for `ak.self.committed_event.stream.subscribe.v1`.
    /// Memory mode uses the local broadcast channel; PostgreSQL mode also
    /// publishes over LISTEN/NOTIFY so subscribers connected to another
    /// replica receive the same live frames.
    event_broadcast: EventBroadcast,
    /// Latched service-drain notice for long-lived transports. `None` until a
    /// shutdown signal arrives; a `watch` (not a broadcast) because a
    /// connection that opens mid-drain must observe the notice immediately
    /// rather than wait for an edge that already passed.
    connection_drain: Arc<tokio::sync::watch::Sender<Option<ConnectionDrain>>>,
    /// Lossy process-local acceleration signal. Durable pending rows remain
    /// the reconciliation source of truth after missed wakeups or restarts.
    /// Inbound admission slots for Applet edge transactions. Saturation is a
    /// protocol outcome, not a timeout: applet-integration.md 7.3 requires the
    /// shed delivery to come back as per-event `queue_full` with
    /// `retry_after_ms`, and to leave the idempotency identity unconsumed so
    /// the sender may re-deliver the same bytes.
    applet_transaction_slots: Arc<tokio::sync::Semaphore>,
    /// Server-enforced reconnect windows advertised by subscribe control
    /// frames. This prevents a faulty or overloaded client from immediately
    /// re-opening the same subscribe scope after `dropped` /
    /// `resync_required`.
    /// Persistent Ed25519 signing key for the NotaryWorker and service-owned signing paths.
    /// Production construction receives the exact seed resolved and
    /// key-bound by service-identity bootstrap; AppState never re-resolves or
    /// independently mints this signer.
    ///
    /// Shared across service-owned signing paths so they bind to the same
    /// key/DID identity.
    /// Readers acquire the current key via `ArcSwap::load_full()`. The
    /// historical signing-key-only rotation path is fail-closed because it
    /// cannot atomically update WebVH, the DID document, durable identity,
    /// KeyStore, and recovery bundle.
    notary_signing_key: Arc<ArcSwap<SigningKey>>,
    /// The origin tag rotates with the key. Stored alongside it
    /// behind a [`Mutex`] (one-shot writes from the rotation path are not
    /// in the hot read path; the per-pass diagnostic helper just snapshots).
    notary_signing_key_origin: Arc<Mutex<NotarySigningKeyOrigin>>,
    /// G4.T3 — verified-profile descriptors loaded from the artifact path in
    /// `COLAND_VERIFIED_PROFILES_ARTIFACT` at startup. Filtered to entries
    /// whose `service_role == "station"` and additionally
    /// cross-checked against the local `supported_profiles[]` set inside
    /// `describe.rs::apply_conformance_evidence`. Empty when the env var
    /// is unset / file missing / file malformed — that's the dev-mode
    /// invariant in service-surface.md §3.0.
    verified_profiles: Arc<Vec<VerifiedProfileArtifactEntry>>,
    /// MID-1..6 (R3.1 spec-sync 2026-05-27, arkret-spec @ 7157ee8) — in-
    /// memory registry of `ak.member.identity.update` events. Reducer
    /// dispatch (`apply_member_identity_update`) and the sync roster
    /// projection (`SYNC-MEM-1..3`) both go through this. See
    /// [`MemberIdentityRegistry`] above for storage and effective-set
    /// semantics; writers persist through the durable
    /// [`coland_storage::MemberIdentityStore`] first and startup hydration
    /// rebuilds this registry from it. Plaintext Ed25519 MemberIdentity
    /// proofs are verified on
    /// event ingest; encrypted/non-Ed25519 proof forms are refused
    /// fail-closed. Reducer-shape validation (digest binding, segment
    /// whitelist) IS real per MID-2.
    member_identity: Arc<Mutex<MemberIdentityRegistry>>,
    /// In-memory projection of the spec's `deactivation_partial` flag
    /// (`account-lifecycle.md` §3 / §7.1): DIDs whose push-gateway
    /// deactivation fanout has failed and is still being retried. Durable
    /// truth is the account-lifecycle registry plus the fanout completion
    /// markers in the jobs idempotency ledger; the inline fanout attempt and
    /// the [`crate::deactivation_push_fanout`] worker keep this set
    /// converged (including after a restart, on the worker's first pass).
    /// Orthogonal to `deactivation_federation_incomplete` — never merged.
    deactivation_push_partial: Arc<Mutex<std::collections::BTreeSet<String>>>,
}

pub struct AppStateRuntime {
    pub persistence: PersistenceHandle,
    pub projections: ProjectionService,
    pub realm_directory: RealmDirectoryService,
    pub object_storage: Arc<dyn ObjectStoragePort>,
    pub settings_persistence: Arc<dyn RuntimeSettingsPort>,
    pub runtime_health: Arc<dyn RuntimeHealthPort>,
    pub event_broadcast: EventBroadcast,
    pub storage_mode: &'static str,
}

/// Founding principal of the development demo Realm.
pub const DEVELOPMENT_DEMO_SUBJECT_DID: &str = "did:web:alice.example";
const DEVELOPMENT_DEMO_TRUST_DOMAIN: &str = "ak:trust_domain:coland.test";
const DEVELOPMENT_DEMO_GENESIS_CREATED_AT: &str = "2026-01-01T00:00:00Z";

/// Canonical `ak.realm.create` payload for a deterministic Realm genesis.
#[must_use]
pub fn realm_genesis_payload(
    _subject: &str,
    governance_station_id: &DidCoreId,
    trust_domain: &str,
) -> Value {
    serde_json::json!({
        "object": {
            "schema": arkret_wire::SchemaId::REALM_GENESIS_V1,
            "purpose": "collaboration",
            "genesis_salt": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "trust_domain": trust_domain,
            "security_class": "standard",
            "governance_station_id": governance_station_id,
            "initial_join_rule": "invite",
            "initial_history_access": "all_history_for_current_members",
            "initial_discoverability": "listed"
        }
    })
}

/// The development demo Realm's canonical genesis Event.
///
/// Every input except the deployment identity is a development constant, so the
/// Event — and therefore the Realm id it derives — is fully determined by this
/// deployment's own service identity and the current `arkret-spec` artifacts.
/// There is no parameterless variant: a demo Realm id
/// derived from a copied service DID is a Realm no running deployment can
/// re-derive.
#[must_use]
pub fn development_demo_genesis_event(
    _service_did: &Did,
    service_id: &DidCoreId,
    _signing_seed: [u8; 32],
) -> arkret_wire::AuthoredEvent {
    let created_at = chrono::DateTime::parse_from_rfc3339(DEVELOPMENT_DEMO_GENESIS_CREATED_AT)
        .expect("development demo genesis timestamp")
        .with_timezone(&chrono::Utc);
    let payload: arkret_models_collaboration::events_payloads::RealmCreatePayload =
        serde_json::from_value(realm_genesis_payload(
            DEVELOPMENT_DEMO_SUBJECT_DID,
            service_id,
            DEVELOPMENT_DEMO_TRUST_DOMAIN,
        ))
        .expect("development demo genesis payload");
    arkret_event_draft::TypedEventDraft::<arkret_wire::event_spec::RealmCreate>::new(
        arkret_wire::ScopeRef::RealmGenesis,
        arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            arkret_wire::project_did_to_core_id(
                &Did::new(DEVELOPMENT_DEMO_SUBJECT_DID.to_owned())
                    .expect("development demo subject DID"),
            )
            .expect("development demo subject projection"),
            service_id.clone(),
        )),
        payload,
    )
    .expect("development demo genesis draft")
    .author_with_digest_suite(created_at, arkret_canonical::DigestSuite::Sha256)
    .expect("development demo genesis Event")
}

/// Realm identity of the development demo Realm served by this deployment.
///
/// This is content-derived (`retype(genesis_event.event_id)`), so it moves
/// whenever anything inside the genesis Event's canonical bytes moves — the
/// deployment's own service identity included, because the genesis payload
/// freezes the generation-0 governance Station. It is therefore
/// **derived**, never copied: a hard-coded literal went stale four times, most
/// recently as a service DID copied from one deployment into another.
#[must_use]
pub fn development_demo_realm_id(
    service_did: &Did,
    service_id: &DidCoreId,
    signing_seed: [u8; 32],
) -> RealmId {
    RealmId::from_event_id(
        development_demo_genesis_event(service_did, service_id, signing_seed).event_id(),
    )
}

pub fn build_realm_directory(
    config: &AppConfig,
    service_did: &Did,
    service_id: &DidCoreId,
    resolved_signing_seed: [u8; 32],
) -> RealmDirectoryService {
    let mut realms = RealmDirectoryIndex::new();
    if config.seed_demo_data {
        let mut demo = RealmDirectoryEntry::new(
            development_demo_realm_id(service_did, service_id, resolved_signing_seed),
            "Arkret Demo Realm",
            // Seeded locally, not projected from an Event.
            coland_services::events::DirectoryProvenance::LocalOnly,
        );
        demo.description = Some("Shared demo Realm served by coland".to_owned());
        demo.public = true;
        demo.members
            .insert(DidCoreId::new("ak:did_core:web:alice.example").expect("valid principal id"));
        demo.tags.insert("demo".to_owned());
        demo.category = Some("collaboration".to_owned());
        realms.upsert(demo);
    }
    RealmDirectoryService::new(realms)
}

#[cfg(test)]
fn development_fixture_service_identity(config: &AppConfig) -> DidCoreIdentityState {
    let registration_key = ServiceRegistrationKey::new(
        ServiceKind::Station,
        CanonicalServiceUrl::canonicalize(&config.public_base_url)
            .expect("test/development public base must be canonicalizable"),
    )
    .expect("station registration key");
    let signing_key_ref =
        DidCoreIdentityKeyRef::new("fixture:coland:service-signing-key").expect("fixture key ref");
    DidCoreIdentityState::Ready {
        identity: LocalDidCoreIdentity {
            did: Did::new(
                "did:webvh:z2dmjYwAPJzv5CZsnAzt8auVZRn1GfuxhpK2t3Q3K3rj4B1x:coland.local:webvh:service",
            )
            .expect("fixture service DID"),
            service_id: arkret_wire::project_did_to_core_id(
                    &Did::new(
                        "did:webvh:z2dmjYwAPJzv5CZsnAzt8auVZRn1GfuxhpK2t3Q3K3rj4B1x:coland.local:webvh:service",
                    )
                    .expect("fixture service DID"),
                )
                .expect("fixture service projection"),
            registration_key,
            provider: None,
            signing_key_refs: vec![signing_key_ref.clone()],
            active_signing_key_ref: signing_key_ref,
            control_key_ref: DidCoreIdentityKeyRef::new("fixture:coland:webvh-control-key")
                .expect("fixture control key ref"),
            version_id: "fixture-v1".to_owned(),
            last_verified_at: chrono::Utc::now(),
        },
    }
}

#[cfg(test)]
fn development_fixture_resolution_commitment(
    identity: &DidCoreIdentityState,
) -> ResolutionCommitment {
    ResolutionCommitment {
        did: arkret_wire::Did::new(
            identity
                .identity()
                .expect("fixture has a serving identity")
                .did
                .to_string(),
        )
        .expect("fixture service DID"),
        method_history_head: format!("sha256:{}", "0".repeat(64)),
        version_id: "fixture-v1".to_owned(),
    }
}

#[cfg(test)]
mod test_construction {
    use std::collections::{BTreeMap, BTreeSet};
    use std::ops::Range;
    use std::path::Path;

    use async_trait::async_trait;
    use bytes::Bytes;
    use coland_services::governance::RuntimeSettingsPort;
    use coland_services::jobs::RuntimeHealthPort;
    use coland_storage::PersistenceStore;
    use coland_storage_postgres::test_database::{TestDatabase, block_on_lease_runtime};
    use coland_storage_postgres::{Db, PgPersistenceStore};
    use futures_util::stream::{self, BoxStream, StreamExt};
    use parking_lot::Mutex;

    use super::*;

    impl AppState {
        /// Build a fixture `AppState`.
        ///
        /// A caller that already has a pool keeps it. A caller that does not
        /// leases a real database: Coland stores through one adapter, so a
        /// fixture reaching for a second implementation would prove nothing
        /// about what production runs. The lease is owned by the persistence
        /// store, so the slot is returned when the last holder drops.
        pub fn new(config: AppConfig, db: Db) -> Self {
            let (db, persistence): (Db, Arc<dyn PersistenceStore>) = match db.pool.clone() {
                Some(pool) => (db, Arc::new(PgPersistenceStore::new(pool))),
                None => {
                    // The lease supplies the persistence store only. The
                    // state-resolution plane keeps the SDK's in-process stores
                    // it already used here: its traits are synchronous, and
                    // driving the durable ones from a current-thread test
                    // runtime deadlocks the connection that serves them.
                    let leased = Arc::new(TestDatabase::lease_blocking());
                    leased.bind_device_inventory_station(
                        &development_fixture_service_identity(&config)
                            .identity()
                            .expect("fixture has a serving identity")
                            .service_id
                            .to_string(),
                    );
                    (
                        Db { pool: None },
                        Arc::new(PgPersistenceStore::leased(leased)),
                    )
                }
            };
            if config.seed_demo_data {
                seed_demo_data(&persistence);
            }
            Self::new_with_persistence(config, db, persistence)
        }

        pub fn new_with_persistence(
            config: AppConfig,
            db: Db,
            persistence: Arc<dyn PersistenceStore>,
        ) -> Self {
            let identity = development_fixture_service_identity(&config);
            let signing_seed = fixture_signing_seed(&config, &identity);
            let commitment = development_fixture_resolution_commitment(&identity);
            Self::new_with_service_identity(
                config,
                db,
                persistence,
                identity,
                commitment,
                signing_seed,
            )
        }

        pub fn new_with_service_identity(
            config: AppConfig,
            db: Db,
            persistence: Arc<dyn PersistenceStore>,
            service_identity: DidCoreIdentityState,
            service_resolution_commitment: ResolutionCommitment,
            resolved_signing_seed: [u8; 32],
        ) -> Self {
            let storage_mode = db.mode();
            let service_id = service_identity
                .identity()
                .expect("fixture has a serving identity")
                .service_id
                .to_string();
            let projections = ProjectionService::new(&service_id);
            let identity = service_identity
                .identity()
                .expect("fixture has a serving identity");
            let realm_directory = build_realm_directory(
                &config,
                &identity.did,
                &identity.service_id,
                resolved_signing_seed,
            );
            Self::from_runtime(
                config,
                AppStateRuntime {
                    persistence: PersistenceHandle::from_shared(persistence),
                    projections,
                    realm_directory,
                    object_storage: Arc::new(MemoryObjectStorage::default()),
                    settings_persistence: Arc::new(NoRuntimeSettings),
                    runtime_health: Arc::new(TestRuntimeHealth(db)),
                    event_broadcast: EventBroadcast::new(1024),
                    storage_mode,
                },
                service_identity,
                service_resolution_commitment,
                resolved_signing_seed,
            )
        }
    }

    /// The two rows the development demo projection reads.
    ///
    /// The demo Realm id itself is derived from config and identity, not read
    /// back from storage, so only these rows need seeding.
    const DEMO_REALM_ID: &str = "ak:realm:AZAySZA7XRDeJ9cO4MqaDWrJD-rqPk6Cudk7CCzsDQz1";

    fn seed_demo_data(persistence: &Arc<dyn PersistenceStore>) {
        use coland_storage::{AccountRecord, RealmMetaRecord};

        let store = persistence.clone();
        block_on_lease_runtime(async move {
            let now = chrono::Utc::now();
            store
                .accounts()
                .put(&AccountRecord {
                    // The store assigns the primary key.
                    pk: coland_storage::AccountPk(0),
                    principal_id: arkret_wire::DidCoreId::new(
                        "ak:did_core:web:alice.example".to_owned(),
                    )
                    .expect("demo principal id is canonical"),
                    station_id: arkret_wire::DidCoreId::new(
                        "ak:did_core:web:server.example".to_owned(),
                    )
                    .expect("demo Station id is canonical"),
                    localpart: "alice".to_owned(),
                    display_name: Some("Alice Example".to_owned()),
                    bio: None,
                    avatar_blob_ref: None,
                    created_at: now,
                })
                .await
                .expect("seed the demo account");
            store
                .realm_meta()
                .put(
                    DEMO_REALM_ID,
                    &RealmMetaRecord {
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
        });
    }

    fn fixture_signing_seed(config: &AppConfig, identity: &DidCoreIdentityState) -> [u8; 32] {
        config.notary_signing_key_seed.unwrap_or_else(|| {
            let mut hasher = Sha256::new();
            hasher.update(b"coland:test-fixture-notary:");
            hasher.update(
                identity
                    .identity()
                    .expect("fixture has a serving identity")
                    .service_id
                    .as_str()
                    .as_bytes(),
            );
            hasher.finalize().into()
        })
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
            self.put(
                key,
                std::fs::read(file_path).map_err(|error| error.to_string())?,
            )
            .await
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

    struct TestRuntimeHealth(Db);

    #[async_trait]
    impl RuntimeHealthPort for TestRuntimeHealth {
        async fn database_ready(&self) -> bool {
            coland_storage_postgres::database_ready(self.0.pool.as_ref()).await
        }

        fn storage_mode(&self) -> &'static str {
            self.0.mode()
        }

        fn migrations_applied(&self) -> bool {
            self.0.migrations_applied()
        }

        fn database_configured(&self) -> bool {
            self.0.pool.is_some()
        }

        fn database_pool_in_use(&self) -> u32 {
            self.0.pool_in_use()
        }
    }
}

impl AppState {
    pub fn config(&self) -> &AppConfig {
        &self.config
    }

    pub fn service_id(&self) -> &String {
        &self.service_id
    }

    pub fn service_core_id(&self) -> DidCoreId {
        DidCoreId::new(self.service_id.clone())
            .expect("runtime service_id was validated during AppState construction")
    }

    /// Return the currently resolved, version-pinned service DID.
    ///
    /// `service_id` is the projected Arkret core identifier and must never be
    /// used as the base of a DID URL. Signing surfaces use this DID so a
    /// core-id/DID mismatch is rejected at this single typed boundary.
    pub fn service_did(&self) -> Did {
        self.service_resolution_commitment().did.clone()
    }

    pub fn service_verification_method(
        &self,
        fragment: &str,
    ) -> Result<arkret_wire::DidUrl, String> {
        arkret_wire::DidUrl::new(format!("{}#{fragment}", self.service_did()))
            .map_err(|error| format!("service verification method is invalid: {error}"))
    }

    /// The development demo Realm this deployment seeds when `seed_demo_data`
    /// is on.
    ///
    /// Derived from exactly the three inputs [`build_realm_directory`] used, so
    /// the directory entry, the canonical genesis Event and every fixture that
    /// re-seeds that Event agree by construction rather than by a copied
    /// literal.
    #[must_use]
    pub fn development_demo_realm_id(&self) -> RealmId {
        let identity_state = self.service_identity_state();
        let identity = identity_state
            .identity()
            .expect("AppState requires a serving service identity");
        development_demo_realm_id(
            &identity.did,
            &identity.service_id,
            self.notary_signing_key().to_bytes(),
        )
    }

    pub fn storage_mode(&self) -> &'static str {
        self.storage_mode
    }

    pub async fn current_service_receipt_binding(
        &self,
    ) -> Result<(Hash, arkret_wire::DidUrl), String> {
        let stored = self
            .persistence
            .stored_service_identity()
            .await
            .map_err(|error| error.to_string())?
            .ok_or_else(|| "durable service identity is unavailable".to_owned())?;
        if stored.identity.service_id.as_str() != self.service_id {
            return Err("durable service identity does not match the serving service".to_owned());
        }
        let expected_multibase = arkret_canonical::ed25519_pubkey_to_did_key_multibase(
            self.notary_verifying_key().as_bytes(),
        );
        let assertion_method = stored
            .did_document
            .verification_method
            .iter()
            .find(|method| {
                method.public_key_multibase == expected_multibase
                    && stored.did_document.assertion_method.contains(&method.id)
            })
            .ok_or_else(|| "runtime signer is not a current service assertion method".to_owned())?;
        let normalized_document: arkret_models_identity::DidDocument = serde_json::from_value(
            serde_json::to_value(&stored.did_document).map_err(|error| error.to_string())?,
        )
        .map_err(|error| error.to_string())?;
        let document_digest = arkret_identity::document_canonical_digest(&normalized_document)
            .map_err(|error| error.to_string())?;
        let assertion_method = arkret_wire::DidUrl::new(assertion_method.id.clone())
            .map_err(|error| error.to_string())?;
        Ok((document_digest, assertion_method))
    }

    pub async fn stored_service_identity(
        &self,
    ) -> Result<arkret_identity::service_identity::StoredDidCoreIdentity, String> {
        self.persistence
            .stored_service_identity()
            .await
            .map_err(|error| error.to_string())?
            .ok_or_else(|| "durable service identity is unavailable".to_owned())
    }

    pub fn install_federation_peer_verifying_key(
        &self,
        previous_service_id: Option<&str>,
        service_id: &str,
        verifying_key: VerifyingKey,
    ) {
        self.federation_peer_verifying_keys.rcu(|current| {
            let mut next = (**current).clone();
            if let Some(previous_service_id) = previous_service_id
                && previous_service_id != service_id
            {
                next.remove(previous_service_id);
            }
            next.insert(service_id.to_owned(), verifying_key);
            Arc::new(next)
        });
    }

    pub fn install_federation_peer_verification_method_key(
        &self,
        previous_verification_method: Option<&str>,
        verification_method: &str,
        verifying_key: VerifyingKey,
    ) {
        self.federation_peer_verifying_keys.rcu(|current| {
            let mut next = (**current).clone();
            if let Some(previous_verification_method) = previous_verification_method
                && previous_verification_method != verification_method
            {
                next.remove(previous_verification_method);
            }
            next.insert(verification_method.to_owned(), verifying_key);
            Arc::new(next)
        });
    }

    pub fn discard_federation_peer_verification_keys(
        &self,
        service_id: &str,
        verification_method: &str,
    ) {
        self.federation_peer_verifying_keys.rcu(|current| {
            let mut next = (**current).clone();
            next.remove(service_id);
            next.remove(verification_method);
            Arc::new(next)
        });
    }

    /// Atomically replace the endpoint-discovered signing keys for one peer.
    ///
    /// Exact verification-method entries from an older WebVH version must be
    /// removed when the peer rotates its DID. Leaving them cached would
    /// allow a transcript naming the retired key id to bypass the refreshed
    /// endpoint document.
    pub fn install_discovered_federation_peer_keys(
        &self,
        previous_service_id: Option<&str>,
        service_id: &str,
        federation_verification_method: &str,
        federation_verifying_key: VerifyingKey,
        receipt_verification_method: &str,
        receipt_verifying_key: VerifyingKey,
    ) {
        self.federation_peer_verifying_keys.rcu(|current| {
            let mut next = (**current).clone();
            next.retain(|candidate, _| {
                !verification_key_belongs_to_service(candidate, service_id)
                    && !previous_service_id.is_some_and(|previous| {
                        verification_key_belongs_to_service(candidate, previous)
                    })
            });
            next.insert(service_id.to_owned(), federation_verifying_key);
            next.insert(
                federation_verification_method.to_owned(),
                federation_verifying_key,
            );
            next.insert(
                receipt_verification_method.to_owned(),
                receipt_verifying_key,
            );
            Arc::new(next)
        });
    }

    pub fn apply_resolved_federation_peers(&self, resolved: &HashMap<String, String>) {
        self.settings.rcu(|current| {
            let mut next = (**current).clone();
            for entry in &mut next.federation_peers {
                if let Some(discovered) = resolved.get(entry) {
                    *entry = discovered.clone();
                }
            }
            Arc::new(next)
        });
    }

    #[cfg(feature = "test-support")]
    #[doc(hidden)]
    pub fn test_registry_key(&self) -> usize {
        Arc::as_ptr(&self.settings) as usize
    }

    /// Snapshot the current service-identity lifecycle state.
    pub fn service_identity_state(&self) -> Arc<DidCoreIdentityState> {
        self.service_identity.load_full()
    }

    pub fn replace_service_identity_state(&self, state: DidCoreIdentityState) {
        self.service_identity.store(Arc::new(state));
    }

    pub fn service_resolution_commitment(&self) -> Arc<ResolutionCommitment> {
        self.service_resolution_commitment.load_full()
    }

    pub fn replace_service_resolution_commitment(&self, commitment: ResolutionCommitment) {
        self.service_resolution_commitment
            .store(Arc::new(commitment));
    }

    /// Snapshot the persistent Ed25519 signing key shared by
    /// the NotaryWorker and service-owned signing paths. Returns a fresh
    /// `Arc<SigningKey>` (lock-free `ArcSwap::load_full`) so callers can
    /// hold the snapshot for the duration of a signing pass.
    pub fn notary_signing_key(&self) -> Arc<SigningKey> {
        self.notary_signing_key.load_full()
    }

    /// Public Ed25519 verifying key for the current notary signing key.
    ///
    /// Used by the `ak.call.state` participant_binding verifier: in the
    /// arkret_native self-signed deployment the binding `sig` is minted with
    /// the notary signing key (`routing::interop::webrtc`), so the receiver
    /// verifies against this key after anchoring `issuer_kid` to the current
    /// media_service epoch.
    pub fn notary_verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        self.notary_signing_key.load().verifying_key()
    }

    /// Snapshot a verification key learned from a federation peer's
    /// endpoint-bound DID document.
    pub fn federation_peer_verifying_key(&self, service_id: &str) -> Option<VerifyingKey> {
        self.federation_peer_verifying_keys
            .load()
            .get(service_id)
            .copied()
    }

    /// Snapshot a peer assertion key bound to an exact verification-method
    /// DID URL in the endpoint-discovered service DID document.
    pub fn federation_peer_verification_method_key(
        &self,
        verification_method: &str,
    ) -> Option<VerifyingKey> {
        self.federation_peer_verifying_keys
            .load()
            .get(verification_method)
            .copied()
    }

    pub(crate) fn install_historical_contact_assertion_key(
        &self,
        verification_method: &str,
        created_at: chrono::DateTime<chrono::Utc>,
        verifying_key: VerifyingKey,
    ) -> bool {
        let mut keys = self.historical_contact_assertion_keys.lock();
        let coordinate = (verification_method.to_owned(), created_at);
        match keys.get(&coordinate) {
            Some(existing) => *existing == verifying_key,
            None => {
                keys.insert(coordinate, verifying_key);
                true
            }
        }
    }

    pub(crate) fn historical_contact_assertion_key(
        &self,
        verification_method: &str,
        created_at: chrono::DateTime<chrono::Utc>,
    ) -> Option<VerifyingKey> {
        self.historical_contact_assertion_keys
            .lock()
            .get(&(verification_method.to_owned(), created_at))
            .copied()
    }

    /// Origin tag for diagnostics (`Configured` / `Ephemeral` / `Rotated`).
    pub fn notary_signing_key_origin(&self) -> NotarySigningKeyOrigin {
        *self.notary_signing_key_origin.lock()
    }

    /// The original durable vault is shared with service bootstrap, never reopened
    /// with a different namespace or derived from a rotating signing seed.
    pub fn with_verifier_private_keystore(
        mut self,
        store: Arc<dyn arkret_keystore::KeyStore>,
    ) -> Self {
        self.verifier_private_keystore = Some(store);
        self
    }
    pub(crate) fn verifier_private_keystore(
        &self,
    ) -> Result<&dyn arkret_keystore::KeyStore, crate::error::AppError> {
        self.verifier_private_keystore.as_deref().ok_or_else(|| {
            crate::error::AppError::capability_denied(
                "verifier-private scope custody is unavailable",
            )
        })
    }
    pub async fn verify_and_retain_agent_scope_custody(
        &self,
        body: &arkret_models_collaboration::agent_scope::AgentKeyPairRequestBody,
    ) -> Result<coland_storage::AgentScopeCustodyRef, crate::error::AppError> {
        crate::routing::identity::agents::verify_and_retain_agent_scope_custody(self, body).await
    }
    pub async fn qualified_agent_scope_evidence(
        &self,
        guard: &coland_storage::AgentEndpointGuard,
    ) -> Result<coland_storage::VerifiedAgentScopeEvidence, crate::error::AppError> {
        crate::routing::identity::agents::qualified_agent_scope_evidence(self, guard).await
    }

    pub fn from_runtime(
        config: AppConfig,
        runtime: AppStateRuntime,
        service_identity: DidCoreIdentityState,
        service_resolution_commitment: ResolutionCommitment,
        resolved_signing_seed: [u8; 32],
    ) -> Self {
        let AppStateRuntime {
            persistence,
            projections,
            realm_directory,
            object_storage,
            settings_persistence,
            runtime_health,
            event_broadcast,
            storage_mode,
        } = runtime;
        let now = chrono::Utc::now();
        let applet_transaction_inflight_capacity = config.applet_transaction_inflight_capacity;

        let service_id = service_identity
            .identity()
            .expect("AppState requires a serving service identity")
            .service_id
            .to_string();
        let service_identity = Arc::new(ArcSwap::from_pointee(service_identity));
        let service_resolution_commitment =
            Arc::new(ArcSwap::from_pointee(service_resolution_commitment));

        // Build the production DID resolver chain before the struct literal
        // so we can still
        // borrow `&config` for the helper before `config` itself is
        // moved into `Self.config`.
        let did_resolver = Arc::new(did_resolver_chain::build_coland_did_resolver(&config));
        // §5 — one process-wide accepted-binding store. Building it here (not
        // per request) is what makes "second Event under the same accepted key
        // costs zero resolver calls" structural rather than incidental.
        let did_bindings: Arc<dyn arkret_identity::VerifiedDidBindingStore> = Arc::new(
            arkret_identity::InMemoryVerifiedDidBindingStore::new(DID_BINDING_STORE_CAPACITY),
        );

        // Bootstrap has already validated that this exact seed is the key
        // published by the resolved service DID document. Re-reading a
        // differently-derived key here would split the runtime signer from
        // its authoritative service identity.
        let signing_seed = resolved_signing_seed;
        let notary_signing_key_origin =
            if config.notary_signing_key_seed.is_some() || config.key_store.is_durable() {
                NotarySigningKeyOrigin::Configured
            } else {
                // Only fixture constructors can reach this branch. Production
                // bootstrap requires durable key custody or an explicit secret.
                NotarySigningKeyOrigin::Ephemeral
            };

        let notary_signing_key =
            Arc::new(ArcSwap::from_pointee(SigningKey::from_bytes(&signing_seed)));
        let notary_signing_key_origin = Arc::new(Mutex::new(notary_signing_key_origin));

        let push_target_hmac_key: [u8; 32] = {
            let mut hasher = Sha256::new();
            hasher.update(b"coland:push-target-id:v1:");
            hasher.update(signing_seed);
            hasher.finalize().into()
        };

        // Seed the mutable overlay from boot config; `hydrate` overlays the
        // persisted `server_settings` row on top if one exists.
        let initial_settings = Arc::new(ArcSwap::from_pointee(
            crate::runtime_settings::RuntimeSettings::from_config(&config),
        ));

        let authority_commits =
            AuthorityCommitApplication::new(persistence.clone(), config.to_device_queue_capacity);
        let PersistenceEventServices {
            events,
            queries: event_queries,
            mls_groups,
            mls_key_packages,
            realm_queries: realms,
            invite_locators,
        } = persistence.event_services();
        let deliveries = persistence.delivery_service(object_storage, push_target_hmac_key);
        let PersistenceIdentityServices {
            identity: identities,
            account_data,
            key_material,
            consent: consents,
            contact: contacts,
            agent_pairing: agent_pairings,
            agent_participation: agent_participations,
            key_backup: key_backups,
            session: sessions,
            recovery_policy: recovery_policies,
            recovery_session: recovery_sessions,
            security_transaction: security_transactions,
            did: dids,
            organization_registration: organization_registrations,
        } = persistence.identity_services(did_resolver.clone());
        let PersistenceOperationalServices {
            federation,
            governance,
            sync,
            jobs,
        } = persistence.operational_services(settings_persistence, runtime_health);
        let service_route_store: Arc<dyn coland_storage::ServiceRouteStore> =
            Arc::new(persistence.clone());
        let service_route_resolver = Arc::new(ServiceRouteResolver::new(
            service_route_store.clone(),
            Arc::new(VerifiedBindingRouteFetcher::new(
                dids.clone(),
                service_route_store,
                config.development_mode,
            )),
        ));

        // Read before `config` is moved into the struct below.
        let verified_profiles = crate::verified_profiles::load_from_configured_path(
            config.verified_profiles_artifact.as_deref(),
        );
        let trusted_push_gateways = Arc::new(config.trusted_push_gateways.clone());

        Self {
            verifier_private_keystore: None,
            config,
            service_id: service_id.clone(),
            service_identity,
            service_resolution_commitment,
            settings: initial_settings,
            storage_mode,
            persistence,
            authority_commits,
            events,
            event_queries,
            mls_groups,
            mls_key_packages,
            realms,
            invite_locators,
            deliveries,
            identities,
            account_data,
            key_material,
            consents,
            contacts,
            agent_pairings,
            account_authority_device_pairing: Arc::new(PrivateAccountAuthorityDevicePairing),
            agent_participations,
            key_backups,
            sessions,
            recovery_policies,
            recovery_sessions,
            security_transactions,
            dids,
            service_route_resolver: Arc::new(Mutex::new(Some(service_route_resolver))),
            trusted_push_gateways,
            did_bindings,
            organization_registrations,
            federation,
            governance,
            sync,
            jobs,
            projections,
            device_history_cache: Default::default(),
            call_invitations: Default::default(),
            realm_directory,
            account_registration_policy: Arc::new(Mutex::new(AccountRegistrationPolicy::default())),
            runtime_guards: RuntimeGuardService::default(),
            to_device_position_counter: Arc::new(AtomicI64::new(now.timestamp_micros())),
            federation_peer_verifying_keys: Arc::new(ArcSwap::from_pointee(BTreeMap::new())),
            historical_contact_assertion_keys: Arc::new(Mutex::new(BTreeMap::new())),
            event_broadcast,
            connection_drain: Arc::new(tokio::sync::watch::Sender::new(None)),
            applet_transaction_slots: Arc::new(tokio::sync::Semaphore::new(
                applet_transaction_inflight_capacity,
            )),
            notary_signing_key,
            notary_signing_key_origin,
            // G4.T3 — load verified-profile descriptors at startup. An unset
            // artifact path IS the feature flag; absence keeps the dev-mode
            // verified_profiles=[] invariant. See
            // crate::verified_profiles::load_from_configured_path for the file
            // schema and logging policy.
            verified_profiles,
            member_identity: Arc::new(Mutex::new(MemberIdentityRegistry::new())),
            deactivation_push_partial: Arc::new(Mutex::new(std::collections::BTreeSet::new())),
        }
    }

    /// Load a consistent snapshot of the mutable operational settings. Cheap
    /// (an atomic pointer load + refcount bump); call per request rather than
    /// caching, so a hot-swap by the admin endpoint is observed immediately.
    #[inline]
    pub fn settings(&self) -> Arc<crate::runtime_settings::RuntimeSettings> {
        self.settings.load_full()
    }

    pub fn replace_settings(&self, settings: crate::runtime_settings::RuntimeSettings) {
        self.settings.store(Arc::new(settings));
    }

    pub fn verified_profiles(&self) -> &[VerifiedProfileArtifactEntry] {
        self.verified_profiles.as_ref()
    }

    pub(crate) fn events(&self) -> &EventService {
        &self.events
    }

    pub(crate) fn authority_commits(&self) -> &AuthorityCommitApplication {
        &self.authority_commits
    }

    pub(crate) fn authority(
        &self,
    ) -> &dyn coland_services::authority_commit::AuthorityProtocolPort {
        self
    }

    pub(crate) fn event_queries(&self) -> &EventQueryService {
        &self.event_queries
    }

    pub(crate) fn mls_groups(&self) -> &MlsGroupQueryService {
        &self.mls_groups
    }

    pub(crate) fn mls_key_packages(&self) -> &MlsKeyPackageService {
        &self.mls_key_packages
    }

    pub(crate) fn realms(&self) -> &RealmQueryService {
        &self.realms
    }

    pub(crate) fn invite_locators(&self) -> &InviteLocatorService {
        &self.invite_locators
    }

    pub(crate) fn deliveries(&self) -> &DeliveryService {
        &self.deliveries
    }

    pub(crate) fn identities(&self) -> &IdentityService {
        &self.identities
    }

    pub(crate) fn account_data(&self) -> &AccountDataService {
        &self.account_data
    }

    pub(crate) fn key_material(&self) -> &KeyMaterialService {
        &self.key_material
    }

    pub(crate) fn consents(&self) -> &ConsentService {
        &self.consents
    }

    pub(crate) fn contacts(&self) -> &ContactService {
        &self.contacts
    }

    pub(crate) fn dids(&self) -> &DidService {
        &self.dids
    }

    /// Retain a peer document that has already passed the standard
    /// ServiceDescribe, registration-key, and assertion-method checks.
    pub fn cache_verified_federation_peer_document(
        &self,
        document: coland_services::identity::DidDocumentState,
    ) -> Result<(), String> {
        let decoded: arkret_identity::DidDocument =
            serde_json::from_value(document.did_document.clone())
                .map_err(|error| format!("peer DID document decode failed: {error}"))?;
        if let Err(error) = crate::test_material_admission::enforce_did_document_admission(
            &decoded,
            Some(&self.config().trust_domain),
        ) {
            self.dids.discard_cached_document(&decoded.id);
            self.invalidate_did_bindings(&decoded.id);
            return Err(error);
        }
        self.dids
            .cache_resolved_document_state(document)
            .map(|_| ())
    }

    /// Obtain the shared resolver for a production send. Absence is a hard
    /// configuration error; callers must never fall back to a raw URL/cache.
    pub fn service_route_resolver(&self) -> Result<Arc<ServiceRouteResolver>, &'static str> {
        self.service_route_resolver
            .lock()
            .clone()
            .ok_or("service route resolver is not installed")
    }

    /// Deployment-onboarded public Push Gateway trust roots.
    #[must_use]
    pub fn trusted_push_gateways(
        &self,
    ) -> Arc<crate::push_gateway_registry::TrustedPushGatewayRegistry> {
        self.trusted_push_gateways.clone()
    }

    /// Replace the production route fetcher at test composition time while
    /// retaining the same durable floor, cache, and quarantine store.
    ///
    /// This hook exists only for integration fixtures that model an
    /// independently verified route source. It must be called before the
    /// state performs any route resolution; production callers cannot enable
    /// it and sending code still resolves exclusively through the shared
    /// [`ServiceRouteResolver`].
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn test_install_service_route_fetcher(
        &self,
        fetcher: Arc<dyn coland_services::service_route::ServiceRouteFetcher>,
    ) {
        let resolver = Arc::new(ServiceRouteResolver::new(
            Arc::new(self.persistence.clone()),
            fetcher,
        ));
        *self.service_route_resolver.lock() = Some(resolver);
    }

    /// Accepted DID authority bindings (`did-usage-and-verification.md` §5).
    pub fn did_bindings(&self) -> &dyn arkret_identity::VerifiedDidBindingStore {
        self.did_bindings.as_ref()
    }

    /// The §5.3 `policy_digest` every binding this deployment accepts is scoped
    /// to.
    ///
    /// The computation is the SDK's canonical resolver policy snapshot
    /// (`ak.did.resolver_policy.v1`) and nothing else, so coland, flagon,
    /// bridges, coauth and inkson derive byte-identical digests from the same
    /// policy value instead of each encoding one.
    ///
    /// The snapshot's three required members — the accepted DID methods, the
    /// resolver fail mode and the trust roots — are what decide whether a
    /// resolution is admissible, and changing any of them changes the digest,
    /// which changes every [`arkret_identity::VerifiedDidBindingKey`], which
    /// makes every acceptance taken under the old policy structurally
    /// unreachable.
    ///
    /// # Why `development_mode` is no longer an input
    ///
    /// It used to be a digest extension. §5.3 closed the snapshot: a deployment
    /// with extra admissibility dimensions MUST register its own
    /// `policy_profile` with a closed `profile_policy` schema, and v1 registers
    /// only the base profile. Registering one would be right if the dimension
    /// could discriminate anything here — it cannot. `development_mode` comes
    /// from the startup `AppConfig` snapshot, and the acceptance store is the
    /// process-local `InMemoryVerifiedDidBindingStore` built alongside it in
    /// `AppState::new`, so no process can ever read an acceptance made under a
    /// different value of the flag. Keeping it would state a scoping property
    /// the store already provides structurally.
    ///
    /// Giving this store a durable backend would change that, and would then
    /// require a registered profile rather than a re-added extension.
    ///
    /// `trust_domain` is likewise not an input:
    /// [`arkret_identity::VerifiedDidBindingKey`] already carries it as its own
    /// key dimension, so folding it in here scopes nothing extra.
    pub fn did_binding_policy_digest(
        &self,
    ) -> Result<arkret_identifiers::Hash, arkret_identity::DigestError> {
        crate::state::did_resolver_chain::did_resolver_policy(self.config()).policy_digest()
    }

    /// Drop every accepted binding for `did` in this trust domain
    /// (`did-usage-and-verification.md` §5: rotation / deactivation /
    /// controller or service delegation change MUST invalidate).
    ///
    /// Called from the single place coland learns a DID document moved —
    /// [`Self::cache_resolved_did_document`] — so an ordinary Event can never
    /// keep verifying against a superseded key.
    pub fn invalidate_did_bindings(&self, did: &arkret_identifiers::Did) -> usize {
        self.did_bindings
            .invalidate(&arkret_identity::BindingInvalidation::for_did(did.clone()))
    }

    /// Ingest a freshly resolved / verified DID document into the resolver
    /// snapshot **and** invalidate any binding that pinned the previous one.
    pub(crate) fn cache_resolved_did_document(
        &self,
        record: coland_services::identity::DidDocumentState,
    ) -> Result<arkret_identity::DidDocument, String> {
        let decoded: arkret_identity::DidDocument =
            serde_json::from_value(record.did_document.clone())
                .map_err(|error| format!("resolved DID document decode failed: {error}"))?;
        if let Err(error) = crate::test_material_admission::enforce_did_document_admission(
            &decoded,
            Some(&self.config().trust_domain),
        ) {
            self.dids.discard_cached_document(&decoded.id);
            self.invalidate_did_bindings(&decoded.id);
            return Err(error);
        }
        let document = self.dids.cache_resolved_document_state(record)?;
        // Only a document that actually moved invalidates: re-caching the same
        // bytes (which the freshness gate does on every high-risk check) must
        // not churn accepted bindings.
        if let Ok(digest) = arkret_identity::document_canonical_digest(&document) {
            let superseded = self.did_bindings.snapshot().into_iter().any(|accepted| {
                accepted.binding().did() == &document.id
                    && accepted.binding().document_digest() != &digest
            });
            if superseded {
                self.invalidate_did_bindings(&document.id);
            }
        }
        Ok(document)
    }

    /// This deployment's trust domain as the typed identifier the SDK binding
    /// key expects.
    pub fn did_binding_trust_domain(&self) -> Result<arkret_identifiers::TrustDomainId, String> {
        Ok(self.config().trust_domain.clone())
    }

    pub(crate) fn organization_registrations(&self) -> &OrganizationRegistrationService {
        &self.organization_registrations
    }

    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn test_set_organization_registration_service(
        &mut self,
        service: OrganizationRegistrationService,
    ) {
        self.organization_registrations = service;
    }

    pub(crate) fn agent_pairings(&self) -> &AgentPairingService {
        &self.agent_pairings
    }

    pub(crate) fn account_authority_device_pairing(
        &self,
    ) -> &dyn AccountAuthorityDevicePairingPort {
        self.account_authority_device_pairing.as_ref()
    }

    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn test_set_account_authority_device_pairing(
        &mut self,
        port: Arc<dyn AccountAuthorityDevicePairingPort>,
    ) {
        self.account_authority_device_pairing = port;
    }

    pub(crate) fn agent_participations(&self) -> &AgentParticipationService {
        &self.agent_participations
    }

    pub(crate) fn key_backups(&self) -> &KeyBackupService {
        &self.key_backups
    }

    pub(crate) fn sessions(&self) -> &SessionService {
        &self.sessions
    }

    pub(crate) fn recovery_policies(&self) -> &RecoveryPolicyService {
        &self.recovery_policies
    }

    pub(crate) fn recovery_sessions(&self) -> &RecoverySessionService {
        &self.recovery_sessions
    }

    pub(crate) fn security_transactions(&self) -> &SecurityTransactionService {
        &self.security_transactions
    }

    pub(crate) fn federation(&self) -> &FederationService {
        &self.federation
    }

    pub(crate) fn governance(&self) -> &GovernanceService {
        &self.governance
    }

    pub(crate) fn sync(&self) -> &SyncService {
        &self.sync
    }

    pub(crate) fn jobs(&self) -> &JobsService {
        &self.jobs
    }

    pub(crate) fn projections(&self) -> &ProjectionService {
        &self.projections
    }

    #[cfg(feature = "test-support")]
    #[doc(hidden)]
    pub fn test_projections(&self) -> &ProjectionService {
        &self.projections
    }

    pub(crate) fn persistence(&self) -> &PersistenceHandle {
        &self.persistence
    }

    /// Runtime-authoritative admin-allowlist check. Reads the live overlay,
    /// so an admin added via the settings endpoint takes effect without a
    /// restart.
    #[inline]
    pub fn is_admin_principal(&self, actor: &str) -> bool {
        self.settings().is_admin_principal(actor)
    }

    /// Effective admin-API auth posture from the live overlay + boot
    /// `development_mode`. Mirrors [`crate::config::AppConfig::admin_auth_mode`]
    /// but reflects runtime allowlist changes.
    pub fn admin_auth_mode(&self) -> &'static str {
        if self.config.development_harness_enabled() {
            "development"
        } else if !self.settings().admin_principal_ids.is_empty() {
            "principal_id_allowlist"
        } else {
            "closed"
        }
    }

    /// Touch the (now async) persistence store to finish boot:
    ///   * seed the demo account + Realm metadata when `seed_demo_data` is on,
    ///   * hydrate the Realm directory from persisted `ak.realm.create` events,
    ///   * hydrate Space-container/Strand/Morph projections from durable rows.
    ///
    /// Extracted out of the synchronous `new` constructor so the DB work runs
    /// in an async context (driven from `main`); see the diesel-async
    /// conversion. Safe to call in memory mode — every store read returns an
    /// empty snapshot, so this is a no-op there.
    pub async fn hydrate(&self) -> coland_services::ServiceResult<()> {
        // Overlay the persisted per-key operational settings on top of the
        // boot-config seed. Only overridden keys have rows; everything else
        // keeps its env default. Per-key decode failures are logged and
        // skipped so a corrupt row can never brick startup.
        match self.governance.runtime_setting_overrides().await {
            Ok(rows) if !rows.is_empty() => {
                let mut merged =
                    crate::runtime_settings::RuntimeSettings::from_config(&self.config);
                let count = rows.len();
                merged.apply_override_rows(rows);
                self.settings.store(Arc::new(merged));
                tracing::info!(count, "applied server_settings overrides");
            }
            Ok(_) => {}
            Err(error) => {
                tracing::warn!(%error, "failed to load server_settings; using boot config");
            }
        }
        if self.config.seed_demo_data
            && let Err(error) = self.persistence.seed_demo_identity().await
        {
            tracing::warn!(%error, "failed to seed demo identity into persistence store");
        }

        // Build the hydrated views off-lock (the async DB reads must not hold
        // a std::sync Mutex guard across `.await`), then merge under a short
        // synchronous critical section.
        let realm_updates = self.persistence.hydrate_realm_directory().await?;
        for (_, entry) in realm_updates.entries_iter() {
            self.realm_directory.upsert(entry.clone());
        }

        let hydrated_realm_ids: Vec<RealmId> = {
            let realms = self.realm_directory.snapshot();
            realms
                .entries_iter()
                .map(|(_, entry)| entry.realm_id.clone())
                .collect()
        };
        self.persistence
            .hydrate_projection(
                &self.projections,
                &RuntimeHydrationProjectionAdapter,
                hydrated_realm_ids,
            )
            .await?;
        let mut reconciled_realms = self.realm_directory.snapshot();
        coland_services::hydration::reconcile_hydrated_agent_memberships(
            &mut reconciled_realms,
            &self.projections.snapshot(),
        );
        for (_, entry) in reconciled_realms.entries_iter() {
            self.realm_directory.upsert(entry.clone());
        }
        // Hydrate per-subject invite_receive_policy overrides into the
        // application-owned working projection.
        self.contacts.hydrate_runtime().await?;

        // Hydrate the holder-private consent-cell working projection owned by
        // the application service.

        // MID-1..6 — rebuild the in-memory member-identity registry from the
        // durable store so a restart does not reset the R3.2 effective-set
        // digests (`expected_state_digest` guard) or the roster projection.
        {
            let store = self.persistence.member_identity_store();
            match (
                store.snapshot_events().await,
                store.snapshot_handle_claims().await,
            ) {
                (Ok(events), Ok(claims)) => {
                    let mut registry = super::member_identity::MemberIdentityRegistry::new();
                    let event_count = events.len();
                    let claim_count = claims.len();
                    for event in events {
                        registry.insert(event);
                    }
                    for claim in claims {
                        registry.restore_handle_claim(claim);
                    }
                    *self.member_identity.lock() = registry;
                    if event_count > 0 || claim_count > 0 {
                        tracing::info!(
                            event_count,
                            claim_count,
                            "hydrated member identity registry from persistence store"
                        );
                    }
                }
                (events, claims) => {
                    if let Err(error) = events {
                        tracing::warn!(%error, "failed to hydrate member identity events");
                    }
                    if let Err(error) = claims {
                        tracing::warn!(%error, "failed to hydrate member identity handle claims");
                    }
                }
            }
        }

        self.identities.hydrate_account_lifecycles().await?;

        self.governance.hydrate_projections().await?;
        Ok(())
    }

    pub(crate) fn handle_claims_snapshot(
        &self,
    ) -> BTreeMap<arkret_wire::DidCoreId, Vec<super::HandleClaimEvidenceRecord>> {
        self.member_identity.lock().snapshot_handle_claims()
    }

    pub(crate) async fn invalidate_cached_handle_claims_for_subject(
        &self,
        subject_id: &str,
    ) -> usize {
        let Ok(subject_id) = arkret_wire::DidCoreId::new(subject_id.to_owned()) else {
            return 0;
        };
        if let Err(error) = self
            .persistence
            .member_identity_store()
            .delete_handle_claims_for_subject(&subject_id)
            .await
        {
            tracing::error!(%error, subject_id = %subject_id, "failed to persist handle claim invalidation");
        }
        self.member_identity
            .lock()
            .invalidate_handle_claims_for_subject(&subject_id)
    }

    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn test_insert_member_identity(&self, record: super::MemberIdentityEventRecord) {
        self.member_identity.lock().insert(record);
    }

    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn test_cache_handle_claim(&self, envelope: Value) -> Option<String> {
        let record = super::member_identity::handle_claim_record_from_envelope(&envelope)?;
        let digest = record.digest.clone();
        self.member_identity.lock().restore_handle_claim(record);
        Some(digest)
    }

    pub fn next_to_device_position(&self) -> i64 {
        let wall = chrono::Utc::now().timestamp_micros();
        loop {
            let current = self.to_device_position_counter.load(Ordering::Relaxed);
            let next = wall.max(current.saturating_add(1));
            match self.to_device_position_counter.compare_exchange(
                current,
                next,
                Ordering::SeqCst,
                Ordering::Relaxed,
            ) {
                Ok(_) => return next,
                Err(_) => continue,
            }
        }
    }

    pub fn account_registration_policy(&self) -> AccountRegistrationPolicy {
        self.account_registration_policy.lock().clone()
    }

    pub fn account_lifecycle_status(&self, did: &str) -> AccountStatus {
        self.identities.account_lifecycle_status(did)
    }

    pub fn account_lifecycle_state(&self, did: &str) -> String {
        self.identities.account_lifecycle_state(did)
    }

    /// Whether the push-gateway leg of `did`'s deactivation fanout is still
    /// incomplete (`deactivation_partial`, `account-lifecycle.md` §3/§7.1).
    /// Always `false` when no push gateway is configured — in that posture
    /// the local push-route purge is the complete Push-route action.
    pub fn deactivation_push_partial(&self, did: &str) -> bool {
        self.deactivation_push_partial.lock().contains(did)
    }

    /// Raise or clear the `deactivation_partial` projection for `did`.
    /// Only the deactivation fanout path and its reconciliation worker
    /// call this.
    pub fn set_deactivation_push_partial(&self, did: &str, partial: bool) {
        let mut set = self.deactivation_push_partial.lock();
        if partial {
            set.insert(did.to_owned());
        } else {
            set.remove(did);
        }
    }

    /// Layered quota for the two authenticated device-pairing handoff
    /// operations (`device-lifecycle.md` §2.1.1 clauses 5 and 8).
    pub fn device_pairing_handoff_rate_limited(
        &self,
        caller_device_id: &str,
        account_key: &str,
    ) -> bool {
        self.runtime_guards
            .device_pairing_handoff_rate_limited(caller_device_id, account_key)
    }

    pub fn realm_join_bootstrap_rate_limited(
        &self,
        realm_id: &str,
        applicant_account_id: &str,
    ) -> bool {
        self.runtime_guards
            .realm_join_bootstrap_rate_limited(realm_id, applicant_account_id)
    }

    pub fn peer_device_lookup_rate_limited(&self, keys: &[String]) -> bool {
        let policy = &self.config().rate_limiter;
        self.runtime_guards.peer_device_lookup_rate_limited(
            keys,
            policy.max_requests,
            chrono::Duration::from_std(policy.window)
                .unwrap_or_else(|_| chrono::Duration::seconds(60)),
        )
    }

    /// Spec `identity/key-management.md` §7.8 — record a full-ciphertext
    /// key-backup download for `principal_id` and report whether the rolling
    /// 24h quota ([`KEY_BACKUP_DOWNLOAD_WINDOW`]) is exhausted. Once
    /// `count > limit` the caller MUST withhold the ciphertext (HTTP 429)
    /// and write the `access_kind="key_backup_read"` audit entry — encrypted
    /// backups are offline-KDF-cracking ammunition, so bulk dumps must be
    /// throttled even for the legitimate owner session.
    pub fn record_key_backup_download(
        &self,
        principal_id: &str,
        limit: u32,
    ) -> KeyBackupDownloadOutcome {
        self.runtime_guards
            .record_key_backup_download(principal_id, limit)
    }

    /// Record one moderation report attempt across the entrypoint's layered
    /// anti-abuse buckets. The generic HTTP rate limiter remains the broad
    /// transport guard; this protocol-level limiter adds reporter_id, source
    /// service, Realm, source IP, and duplicate-target pressure.
    pub fn record_moderation_report_attempt(
        &self,
        reporter_id: &str,
        source_service: Option<&str>,
        realm_id: &str,
        source_ip_hash: &str,
        target_ref: &str,
    ) -> ModerationReportRateOutcome {
        self.runtime_guards.record_moderation_report_attempt(
            reporter_id,
            source_service,
            realm_id,
            source_ip_hash,
            target_ref,
        )
    }
}

fn verification_key_belongs_to_service(candidate: &str, service_id: &str) -> bool {
    if candidate == service_id {
        return true;
    }
    let Ok(controller) = arkret_identity::verification_method_did(candidate) else {
        return false;
    };
    arkret_wire::project_did_to_core_id(&controller)
        .is_ok_and(|controller| controller.as_str() == service_id)
}

impl AppState {
    #[cfg(test)]
    pub(crate) fn test_persistence(&self) -> Arc<dyn coland_storage::PersistenceStore> {
        self.persistence.shared_for_tests()
    }

    #[cfg(test)]
    pub(crate) fn test_projection(&self) -> &Arc<Mutex<ProjectionState>> {
        self.projections.test_state()
    }

    pub(crate) fn realm_directory(&self) -> &RealmDirectoryService {
        &self.realm_directory
    }

    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn test_hlc(&self) -> &ServiceClock {
        self.hlc()
    }

    /// One content-addressed object as this Station stored it.
    ///
    /// A snapshot manifest commits to its chunks only through their content
    /// address, so a test that wants to assert on chunk contents has to read the
    /// bytes back rather than trust the manifest.
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub async fn test_object_by_sha256(&self, sha256: &str) -> Vec<u8> {
        let key = self.deliveries().object_key_for_sha256(sha256);
        self.deliveries()
            .get_object(&key)
            .await
            .expect("the object this Station persisted is readable")
    }

    pub(crate) fn hlc(&self) -> &ServiceClock {
        self.projections.clock()
    }

    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn test_object_key_for_sha256(&self, sha256: &str) -> String {
        self.deliveries.object_key_for_sha256(sha256)
    }

    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub async fn test_put_object(&self, key: &str, bytes: Vec<u8>) -> Result<(), String> {
        self.deliveries.put_object(key, bytes).await
    }

    pub(crate) fn subscribe_event_notifications(
        &self,
    ) -> tokio::sync::broadcast::Receiver<EventNotification> {
        self.event_broadcast.subscribe()
    }

    /// Announce a bounded service drain. Long-lived transports tell their peers
    /// to checkpoint and reconnect elsewhere, then stop by `deadline`.
    ///
    /// Idempotent: a second signal keeps the first deadline, so a repeated
    /// SIGTERM cannot extend the window a client was already given.
    pub fn begin_connection_drain(&self, grace: std::time::Duration) {
        self.connection_drain.send_if_modified(|current| {
            if current.is_some() {
                return false;
            }
            *current = Some(ConnectionDrain {
                reconnect_after_ms: CONNECTION_DRAIN_RECONNECT_AFTER_MS,
                deadline: chrono::Utc::now()
                    + chrono::Duration::from_std(grace).unwrap_or(chrono::Duration::zero()),
            });
            true
        });
    }

    pub(crate) fn subscribe_connection_drain(
        &self,
    ) -> tokio::sync::watch::Receiver<Option<ConnectionDrain>> {
        self.connection_drain.subscribe()
    }

    pub(crate) fn publish_event_notification(
        &self,
        notification: EventNotification,
    ) -> Result<usize, tokio::sync::broadcast::error::SendError<EventNotification>> {
        self.event_broadcast.send(notification)
    }

    /// Claim one inbound Applet-transaction admission slot, or `None` when the
    /// Station is already at capacity. The permit is released when the returned
    /// guard drops, so a delivery holds a slot for exactly as long as it is
    /// being processed.
    pub(crate) fn try_claim_applet_transaction_slot(
        &self,
    ) -> Option<tokio::sync::OwnedSemaphorePermit> {
        Arc::clone(&self.applet_transaction_slots)
            .try_acquire_owned()
            .ok()
    }

    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn test_subscribe_event_notifications(
        &self,
    ) -> tokio::sync::broadcast::Receiver<EventNotification> {
        self.subscribe_event_notifications()
    }

    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn test_cache_resolved_webvh_record(
        &self,
        record: coland_services::identity::DidDocumentState,
    ) -> Result<arkret_identity::DidDocument, String> {
        self.dids.cache_resolved_document_state(record)
    }

    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn test_account_registration_policy(&self) -> &Arc<Mutex<AccountRegistrationPolicy>> {
        &self.account_registration_policy
    }
}

struct RuntimeHydrationProjectionAdapter;

impl HydrationProjectionAdapter for RuntimeHydrationProjectionAdapter {
    fn operation_from_canonical_record(
        &self,
        record: &coland_services::events::AcceptedEvent,
    ) -> Option<arkret_event_draft::ProjectedEventOperation> {
        crate::routing::events::event_log::projection_operation_from_canonical_record(record)
    }
}

/// Fill `out` with cryptographically secure random bytes via `rand::rng`.
/// Used by service-identity bootstrap.
pub fn getrandom_seed(out: &mut [u8; 32]) {
    use rand::RngExt;
    rand::rng().fill(out);
}

#[cfg(test)]
#[path = "../../../storage-postgres/tests/support/ordinary_realm.rs"]
#[allow(dead_code)]
mod hydration_ordinary_realm;

#[cfg(test)]
mod committed_event_hydration_tests {
    use coland_storage::{EventProjectionStoreRegistry, PersistenceStore, QueuedEventStatus};
    use coland_storage_postgres::PgPersistenceStore;
    use coland_storage_postgres::test_database::TestDatabase;

    use super::*;

    #[tokio::test]
    async fn committed_realm_policy_is_rebuilt_by_the_restart_hydration_wrapper() {
        let database = TestDatabase::lease().await;
        let store = PgPersistenceStore::new(database.pool());
        let pool = database.pool();
        let station = hydration_ordinary_realm::station();
        let account = Box::pin(hydration_ordinary_realm::human_profile::admit(
            &pool,
            &station,
            "policy-hydration-founder",
        ))
        .await;
        let unit = hydration_ordinary_realm::bootstrap_unit_for_account(
            "policy-hydration-restart",
            &account,
            &hydration_ordinary_realm::human_profile::station_did(&station),
        );
        let unit = Box::pin(hydration_ordinary_realm::source_bootstrap(&pool, unit)).await;
        store
            .authority_commits()
            .admit_ordinary_realm_bootstrap_unit(&unit, unit.transactions[0].commit.committed_at)
            .await
            .unwrap();
        let realm = unit.transactions[0].event.realm_id.clone();
        let expected_policy = unit
            .transactions
            .iter()
            .find(|transaction| transaction.event.kind == arkret_wire::EventKind::RealmPolicyBundle)
            .unwrap()
            .event
            .payload
            .clone();
        // A new projection wrapper has no policy cache. Hydration must read
        // the accepted Event log, with the same result on a second reopen.
        for _ in 0..2 {
            let reopened_store = PgPersistenceStore::new(database.pool());
            let projection = ProjectionService::new("policy-hydration-restart");
            assert!(
                projection
                    .snapshot()
                    .realm_policy_bundle_value(realm.as_str())
                    .is_none()
            );
            projection
                .hydrate_from_persistence(
                    &reopened_store,
                    &RuntimeHydrationProjectionAdapter,
                    [realm.clone()],
                )
                .await
                .unwrap();
            assert_eq!(
                projection
                    .snapshot()
                    .realm_policy_bundle_value(realm.as_str())
                    .cloned(),
                Some(serde_json::to_value(&expected_policy).unwrap()),
            );
        }
    }

    #[tokio::test]
    async fn queued_event_is_not_a_restart_projection_source() {
        let database = TestDatabase::lease().await;
        let store = PgPersistenceStore::new(database.pool());
        let signer = arkret_test_kit::proof::StructuralOnlyPayloadSigner::new(
            Did::new(DEVELOPMENT_DEMO_SUBJECT_DID).unwrap(),
            arkret_wire::DidUrl::new("did:web:alice.example#key-1").unwrap(),
        );
        let authored = development_demo_genesis_event(
            &Did::new("did:web:server.example").unwrap(),
            &DidCoreId::new("ak:did_core:web:server.example").unwrap(),
            [7; 32],
        );
        let event = arkret_test_kit::sign_structural_only_event(
            authored.into_event(),
            &signer,
            arkret_canonical::DigestSuite::Sha256,
        )
        .unwrap()
        .expect_structural_only();

        store
            .authority_commits()
            .queue_event(&event, chrono::Utc::now())
            .await
            .unwrap();
        assert!(matches!(
            store
                .authority_commits()
                .queued_event(&event.event_id)
                .await
                .unwrap()
                .unwrap()
                .status,
            QueuedEventStatus::Queued
        ));
        assert!(
            store
                .events()
                .get(event.event_id.as_str())
                .await
                .unwrap()
                .is_none()
        );
        assert!(store.events().snapshot_all().await.unwrap().is_empty());

        let projection = ProjectionService::new("queued-event-hydration-test");
        projection
            .hydrate_from_persistence(
                &store,
                &RuntimeHydrationProjectionAdapter,
                [RealmId::from_event_id(&event.event_id)],
            )
            .await
            .unwrap();
        assert!(projection.snapshot().realm_states.is_empty());
    }
}
