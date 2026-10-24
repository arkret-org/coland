//! Real historical issuer and controller-device sources for native Agent tests.
//! This helper prepares material only; production admission decides and freezes it.
use arkret_wire::{AccountId, DeviceId, Did, DidCoreId, DidUrl, EventId};
use chrono::{DateTime, Duration, Utc};
use coland_storage::AuthorityCommitStore;
use coland_storage_postgres::{PgAuthorityCommitStore, PgPool};
use ed25519_dalek::SigningKey;
use rand_core::SeedableRng;

#[derive(Clone)]
pub struct HistoricalControlStation {
    pub did: Did,
    pub core: DidCoreId,
    pub history: arkret_models_identity::AuthenticatedServiceResolution,
    seed: [u8; 32],
    inception: arkret_signatures::webvh::PreparedInception,
    registration: arkret_models_identity::service_identity::ServiceRegistrationKey,
}
impl HistoricalControlStation {
    pub fn new(label: &str, seed: [u8; 32]) -> Self {
        Self::new_with_assertion_keys(label, seed, &[])
    }
    pub fn new_with_assertion_keys(
        label: &str,
        seed: [u8; 32],
        assertion_keys: &[(&str, &str)],
    ) -> Self {
        use arkret_models_identity::service_identity::{
            CanonicalServiceUrl, ServiceRegistrationKey,
        };
        let mut rng =
            rand_chacha::ChaCha20Rng::from_seed(arkret_canonical::sha256_bytes(label.as_bytes()));
        let registration = ServiceRegistrationKey::new(
            arkret_wire::ServiceKind::Station,
            CanonicalServiceUrl::new(format!("https://{label}.example/")).unwrap(),
        )
        .unwrap();
        let inception =
            arkret_signatures::webvh::prepare_service_registration_inception_with_assertion_keys(
                &mut rng,
                &arkret_signatures::webvh::ServiceRegistrationInceptionInput {
                    provider_endpoint: &"https://historical-fixture.example/".parse().unwrap(),
                    registration_key: &registration,
                    also_known_as: &[],
                    version_created_at: "2026-01-01T00:00:00Z".parse().unwrap(),
                    did_key_fragment: Some("authority"),
                },
                &seed,
                assertion_keys,
            )
            .unwrap();
        let did = Did::new(inception.did.clone()).unwrap();
        let core = arkret_wire::project_did_to_core_id(&did).unwrap();
        let history = arkret_identity::build_authenticated_webvh_service_resolution(
            core.clone(),
            "station".into(),
            serde_json::from_value(inception.log_entry["state"].clone()).unwrap(),
            vec![inception.log_entry.clone()],
            vec![],
            "2026-09-01T00:00:00Z".parse().unwrap(),
        )
        .unwrap();
        let station = Self {
            did,
            core,
            history,
            seed,
            inception,
            registration,
        };
        stations()
            .lock()
            .unwrap()
            .insert(station.core.to_string(), station.clone());
        station
    }
    /// Install the real signed Station history before issuing fresh Device
    /// evidence. The registration receipt is an explicit historical import,
    /// not a claim that this fixture exercised Provider registration HTTP.
    pub async fn install_runtime_identity(
        &self,
        persistence: &dyn coland_storage::PersistenceStore,
    ) -> arkret_identity::service_identity::DidCoreIdentityState {
        use arkret_identity::service_identity::{
            DidCoreIdentityKeyRef, DidCoreIdentityState, LocalDidCoreIdentity,
            StoredDidCoreIdentity,
        };
        use arkret_models_identity::service_identity::ServiceRegistrationReceipt;

        let key_ref = DidCoreIdentityKeyRef::new("fixture:coland:service-signing-key").unwrap();
        let identity = LocalDidCoreIdentity {
            did: self.did.clone(),
            service_id: self.core.clone(),
            registration_key: self.registration.clone(),
            provider: None,
            signing_key_refs: vec![key_ref.clone()],
            active_signing_key_ref: key_ref,
            control_key_ref: DidCoreIdentityKeyRef::new("fixture:coland:webvh-control-key")
                .unwrap(),
            version_id: self.inception.version_id.clone(),
            last_verified_at: Utc::now(),
        };
        let now = arkret_canonical::normalize_timestamp_canonical(Utc::now());
        let provider_did =
            Did::new("did:webvh:z6mkfixture:provider.example:webvh:service").unwrap();
        let log_head_digest =
            arkret_canonical::canonical_sha256(&self.inception.log_entry).unwrap();
        let mut receipt = ServiceRegistrationReceipt {
            registration_receipt_id: arkret_wire::ServiceRegistrationReceiptId::new(format!(
                "ak:service_registration_receipt:{}",
                "0".repeat(64)
            ))
            .unwrap(),
            registration_key: self.registration.clone(),
            service_id: self.core.clone(),
            did: self.did.clone(),
            version_id: self.inception.version_id.clone(),
            log_head_digest: log_head_digest.clone(),
            control_key_digest: arkret_canonical::sha256_digest(
                self.inception.update_public_key_multibase.as_bytes(),
            ),
            issued_at: now,
            provider_id: arkret_wire::project_did_to_core_id(&provider_did).unwrap(),
            proof: arkret_wire::PayloadProof {
                kind: "detached_jws".to_owned(),
                verification_method: DidUrl::new(format!("{provider_did}#service-key")).unwrap(),
                payload_digest: arkret_wire::Hash::new(format!("sha256:{}", "0".repeat(64)))
                    .unwrap(),
                created_at: now,
                domain: None,
                audience: None,
                proof_purpose: None,
                jws: "eyJhbGciOiJFZDI1NTE5In0..c2ln".to_owned(),
            },
        };
        receipt.registration_receipt_id = receipt.expected_registration_receipt_id().unwrap();
        receipt.proof.payload_digest = receipt.expected_payload_digest().unwrap();
        receipt.proof = arkret_signatures::service_identity::sign_registration_receipt_proof(
            &receipt,
            &SigningKey::from_bytes(&[86; 32]),
        )
        .unwrap();
        let stored = StoredDidCoreIdentity {
            identity: identity.clone(),
            did_document: serde_json::from_value(self.inception.log_entry["state"].clone())
                .unwrap(),
            registration_receipt: receipt,
            stored_at: now,
        };
        stored.validate().unwrap();
        arkret_identity::verify_did_webvh_v1_chain(&self.did, &[self.inception.log_entry.clone()])
            .unwrap();
        persistence.service_identity().put(stored).await.unwrap();
        persistence
            .webvh()
            .append_log_event(coland_storage::WebvhLogRecord {
                event_digest: log_head_digest,
                did: self.did.to_string(),
                sequence: 1,
                created_at: self.inception.version_created_at.parse().unwrap(),
                operation: self.inception.log_entry.clone(),
            })
            .await
            .unwrap();
        DidCoreIdentityState::Ready { identity }
    }
    /// The authorization must already be accepted in this database. Its exact
    /// original is used rather than today’s cached key or a synthetic device row.
    pub async fn stage(
        &self,
        pool: &PgPool,
        transaction: &coland_storage::AuthorityCommitTransaction,
        controller: &AccountId,
        device: &DeviceId,
        authorization: &EventId,
    ) {
        assert_eq!(controller.station_id, self.core);
        if let Some(original) = (PgAuthorityCommitStore { pool: pool.clone() })
            .committed_event(&transaction.event.event_id)
            .await
            .unwrap()
        {
            if original.event == transaction.event && original.commit == transaction.commit {
                return;
            }
        }
        assert_eq!(
            coland_storage::DeviceRevocationStore::pcr_device_admission(
                &coland_storage_postgres::PgDeviceRevocationStore { pool: pool.clone() },
                controller,
                device,
                transaction.commit.committed_at
            )
            .await
            .unwrap(),
            arkret_wire::AccountDeviceRevocationAdmissionDecision::Allow,
            "a new current Directory projection is issued only from the real confirmed device cut"
        );
        let store = PgAuthorityCommitStore { pool: pool.clone() };
        let original = store.committed_event(authorization).await.unwrap().unwrap();
        assert_eq!(
            original.event.actual_signer().as_account_id(),
            Some(controller)
        );
        let payload: arkret_models_collaboration::events_payloads::DeviceAuthorizePayload =
            serde_json::from_value(serde_json::to_value(&original.event.payload).unwrap()).unwrap();
        assert_eq!(payload.device_id, *device);
        let at: DateTime<Utc> = transaction.commit.committed_at;
        let root = arkret_models_identity::AccountDeviceSignerEvidence {
            device_projection_attestation:
                arkret_signatures::device_projection::sign_device_projection_attestation(
                    arkret_models_crypto::DeviceProjectionAttestationCore {
                        account_id: controller.clone(),
                        device_id: device.clone(),
                        device_signing_key_did: arkret_wire::DidKey::new(
                            payload.device_public_key_did.as_str(),
                        )
                        .unwrap(),
                        hpke_key: arkret_wire::NonEmptyString::new(payload.hpke_key.as_str())
                            .unwrap(),
                        device_authorize_event_id: authorization.clone(),
                        authorized_generation_ref: payload.authorized_generation_ref,
                        device_status: arkret_models_crypto::DeviceStatus::Active,
                        authorization_window: arkret_models_crypto::DeviceAuthorizationWindow {
                            not_before: payload.not_before,
                            expires_at: payload.expires_at.flatten(),
                        },
                        attested_at: at,
                        expires_at: at + Duration::minutes(5),
                    },
                    DidUrl::new(format!("{}#authority", self.did)).unwrap(),
                    &SigningKey::from_bytes(&self.seed),
                )
                .unwrap(),
            service_resolution: self.history.clone(),
        };
        arkret_identity::account_device_signer_evidence::verify_historical_account_device_signer_evidence(
            &root, controller, device).unwrap();
        let dependency = arkret_models_identity::AgentSignerDependency::AccountDevice {
            signer_resolution_evidence_ref: root.signer_evidence_ref().unwrap(),
            account_device_signer_evidence: root,
        };
        store
            .stage_agent_control_source(
                &arkret_wire::CommittedEventFullView {
                    event: transaction.event.clone(),
                    commit: transaction.commit.clone(),
                },
                &dependency,
                &self.history,
            )
            .await
            .unwrap();
    }
}

fn stations()
-> &'static std::sync::Mutex<std::collections::BTreeMap<String, HistoricalControlStation>> {
    static STATIONS: std::sync::OnceLock<
        std::sync::Mutex<std::collections::BTreeMap<String, HistoricalControlStation>>,
    > = std::sync::OnceLock::new();
    STATIONS.get_or_init(Default::default)
}
/// Immutable fixture signing material only. The source authorization is read
/// anew as an accepted original from PG by stage; no Fact/current is cached.
fn descriptors() -> &'static std::sync::Mutex<std::collections::BTreeMap<String, EventId>> {
    static DEVICES: std::sync::OnceLock<
        std::sync::Mutex<std::collections::BTreeMap<String, EventId>>,
    > = std::sync::OnceLock::new();
    DEVICES.get_or_init(Default::default)
}
pub fn register_device(account: &AccountId, device: &DeviceId, authorization: &EventId) {
    descriptors().lock().unwrap().insert(
        format!(
            "{}:{}",
            arkret_wire::ActorId::account(account.clone()),
            device
        ),
        authorization.clone(),
    );
}
pub async fn stage_registered(pool: &PgPool, tx: &coland_storage::AuthorityCommitTransaction) {
    let producer = tx
        .event
        .account_device_producer()
        .unwrap()
        .expect("native controller fixture is a real Human device");
    let authorization = descriptors()
        .lock()
        .unwrap()
        .get(&format!(
            "{}:{}",
            arkret_wire::ActorId::account(producer.account_id.clone()),
            producer.device_id
        ))
        .cloned()
        .expect("registered fixture descriptor");
    let station = stations()
        .lock()
        .unwrap()
        .get(producer.account_id.station_id.as_str())
        .cloned()
        .expect("real historical Station fixture");
    station
        .stage(
            pool,
            tx,
            &producer.account_id,
            &producer.device_id,
            &authorization,
        )
        .await;
}
pub async fn admit_control(
    store: &impl coland_storage::ActorProfileStore,
    pool: &PgPool,
    write: coland_storage::AgentControlAdmissionWrite,
) -> coland_storage::PersistenceResult<coland_storage::AgentControlAdmissionOutcome> {
    stage_registered(pool, &write.commit).await;
    store.admit_agent_control_event(write).await
}
pub async fn admit_genesis(
    store: &impl coland_storage::ActorProfileStore,
    pool: &PgPool,
    write: coland_storage::AgentPcrGenesisAdmissionWrite,
) -> coland_storage::PersistenceResult<coland_storage::AgentPcrGenesisAdmissionOutcome> {
    stage_registered(pool, &write.commit).await;
    store.admit_agent_pcr_genesis(write).await
}

pub fn managed_agent_did(
    controller: &arkret_wire::DidCoreId,
    label: &str,
    at: DateTime<Utc>,
) -> Did {
    let endpoint = "https://agent-fixture.example/".parse().unwrap();
    let local_id = format!("{label}-{}", uuid::Uuid::now_v7().simple());
    let next = arkret_canonical::ed25519_pubkey_to_did_key_multibase(
        SigningKey::from_bytes(&[102; 32])
            .verifying_key()
            .as_bytes(),
    );
    let inception = arkret_signatures::webvh::prepare_agent_inception(
        &arkret_signatures::webvh::AgentInceptionInput {
            principal_endpoint: &endpoint,
            local_id: &local_id,
            controller_principal_id: controller,
            version_created_at: at,
            root_seed: &[101; 32],
            next_root_public_key_multibase: &next,
        },
    )
    .unwrap();
    Did::new(inception.did).unwrap()
}

/// Negative fixtures with an invalid producer proof are intentionally not
/// transformed into valid candidates. The unchanged PG admission decides
/// their original cryptographic refusal. Valid candidates stage the complete
/// real source, and any storage/source error remains a hard fixture failure.
pub async fn stage_registered_signed_candidate(
    pool: &PgPool,
    tx: &coland_storage::AuthorityCommitTransaction,
) {
    let Ok(Some(producer)) = tx.event.account_device_producer() else {
        return;
    };
    let Some(auth) = descriptors()
        .lock()
        .unwrap()
        .get(&format!(
            "{}:{}",
            arkret_wire::ActorId::account(producer.account_id.clone()),
            producer.device_id
        ))
        .cloned()
    else {
        return;
    };
    let full = PgAuthorityCommitStore { pool: pool.clone() }
        .committed_event(&auth)
        .await
        .unwrap()
        .unwrap();
    let payload: arkret_models_collaboration::events_payloads::DeviceAuthorizePayload =
        serde_json::from_value(serde_json::to_value(&full.event.payload).unwrap()).unwrap();
    let key = arkret_signatures::PublicKeyMaterial::Ed25519Multibase {
        value: payload
            .device_public_key_did
            .as_str()
            .strip_prefix("did:key:")
            .unwrap()
            .to_owned(),
    };
    let proof = tx.event.producer_proof.as_ref().unwrap();
    if arkret_signatures::verify_ed25519_detached_jws_proof_with_digest_suite(
        proof,
        &arkret_signatures::EventProofBuilder::new()
            .envelope_bytes(&tx.event)
            .unwrap(),
        &tx.event.actor_id,
        &key,
        tx.event.event_id.digest_suite_code().digest_suite(),
    )
    .is_err()
    {
        return;
    }
    if coland_storage::DeviceRevocationStore::pcr_device_admission(
        &coland_storage_postgres::PgDeviceRevocationStore { pool: pool.clone() },
        &producer.account_id,
        &producer.device_id,
        tx.commit.committed_at,
    )
    .await
    .unwrap()
        != arkret_wire::AccountDeviceRevocationAdmissionDecision::Allow
    {
        return;
    }
    stage_registered(pool, tx).await;
}

/// Preserve the full WebVH DID retained by this fixture; never reconstruct
/// its endpoint from a projected SCID. Legacy non-native fixtures remain web.
pub fn did_for_core(core: &DidCoreId) -> Did {
    if let Some(station) = stations().lock().unwrap().get(core.as_str()) {
        return station.did.clone();
    }
    assert!(core.as_str().starts_with("ak:did_core:web:"));
    Did::new(core.as_str().replacen("ak:did_core:", "did:", 1)).unwrap()
}
