//! `authority_forward` producer device evidence (device-lifecycle §8.2.2) on
//! real Stations over PostgreSQL, following
//! `ak.vector.federation.authority_forward_producer_device_evidence.v1`.
//!
//! The governance Station runs its whole check sequence through the same
//! admission function its peer ingress calls, with the service clock instant
//! passed explicitly. The forwarding Station signs and retains evidence from
//! an accepted PCR genesis.

use arkret_models_collaboration::authority_commit::{
    AuthorityForwardBranch, MlsGenesisMaterial, PeerAuthorityForwardEventRequest,
};
use arkret_models_crypto::{
    DeviceAuthorizationWindow, DeviceStatus, ForwardDeviceProjectionAttestation,
    ForwardDeviceProjectionAttestationCore,
};
use arkret_models_identity::service_identity::{CanonicalServiceUrl, ServiceRegistrationKey};
use arkret_models_identity::{AuthenticatedServiceResolution, ForwardAccountDeviceSignerEvidence};
use arkret_signatures::webvh::{
    ServiceRegistrationInceptionInput, prepare_service_registration_inception,
};
use arkret_wire::{
    AccountId, AuthorityCommitStatus, AuthoritySubmitOutcome, DeviceId, Did, DidCoreId, DidKey,
    DidUrl, Event, EventAdmissionSubmission, EventId, EventKind, NonEmptyString, ProtocolSignature,
    RealmId, ScopeRef, ServiceKind,
};
use chrono::{DateTime, Duration, Utc};
use coland_http::state::AppState;
use coland_services::ServiceError;
use coland_services::authority_commit::AuthenticatedPeerContext;
use coland_storage::CurrentRealmAuthority;
use coland_test_support::AppStateTestExt as _;
use coland_test_support::device_authorization_history::sign_event;
use coland_test_support::pcr_genesis::PcrGenesisFixture;
use ed25519_dalek::SigningKey;
use rand_chacha::ChaCha20Rng;
use rand_chacha::rand_core::SeedableRng;

#[path = "../../storage-postgres/tests/support/historical_human.rs"]
mod historical_human;

const PRINCIPAL_DID: &str = "did:web:forwarded-alice.example";
const DEVICE: &str = "ak:device:0196419b-0000-7000-8000-00000000f0a1";
const OTHER_DEVICE: &str = "ak:device:0196419b-0000-7000-8000-00000000f0a2";
const DEVICE_SEED: [u8; 32] = [0x51; 32];

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
}

fn now() -> DateTime<Utc> {
    DateTime::from_timestamp_millis(Utc::now().timestamp_millis()).unwrap()
}

/// A registered Station that is *not* the governance Station: its WebVH
/// inception and the key its attestations are signed with.
struct Station {
    service_id: DidCoreId,
    method: DidUrl,
    signing_key: SigningKey,
    log_entry: serde_json::Value,
    registered_at: DateTime<Utc>,
}

impl Station {
    fn new(seed: u8, host: &str, registered_at: DateTime<Utc>) -> Self {
        let mut rng = ChaCha20Rng::from_seed([seed; 32]);
        let registration = ServiceRegistrationKey::new(
            ServiceKind::Station,
            CanonicalServiceUrl::new(format!("https://{host}/")).unwrap(),
        )
        .unwrap();
        let inception = prepare_service_registration_inception(
            &mut rng,
            &ServiceRegistrationInceptionInput {
                provider_endpoint: &"https://identity.example/".parse().unwrap(),
                registration_key: &registration,
                also_known_as: &[],
                version_time: registered_at,
                did_key_fragment: None,
            },
        )
        .unwrap();
        let did = Did::new(inception.did.clone()).unwrap();
        Self {
            service_id: arkret_wire::project_did_to_core_id(&did).unwrap(),
            method: DidUrl::new(inception.did_key_id.clone()).unwrap(),
            signing_key: SigningKey::from_bytes(&inception.did_key_seed),
            log_entry: inception.log_entry.clone(),
            registered_at,
        }
    }

    fn resolution(&self, at: DateTime<Utc>) -> AuthenticatedServiceResolution {
        arkret_identity::build_authenticated_webvh_service_resolution(
            self.service_id.clone(),
            "station".into(),
            serde_json::from_value(self.log_entry["state"].clone()).unwrap(),
            vec![self.log_entry.clone()],
            vec![],
            at,
        )
        .unwrap()
    }

    fn account(&self) -> AccountId {
        AccountId::new(
            arkret_wire::project_did_to_core_id(&Did::new(PRINCIPAL_DID).unwrap()).unwrap(),
            self.service_id.clone(),
        )
    }
}

fn device_key_did(seed: [u8; 32]) -> DidKey {
    let public = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
    DidKey::new(format!(
        "did:key:{}",
        arkret_canonical::ed25519_pubkey_to_did_key_multibase(&public)
    ))
    .unwrap()
}

/// The attestation core a healthy forwarding Station signs at `now`.
fn core(station: &Station, now: DateTime<Utc>) -> ForwardDeviceProjectionAttestationCore {
    let attested_at = now - Duration::seconds(30);
    ForwardDeviceProjectionAttestationCore {
        account_id: station.account(),
        device_id: DeviceId::new(DEVICE).unwrap(),
        device_signing_key_did: device_key_did(DEVICE_SEED),
        hpke_key: NonEmptyString::new("hpke-forwarded").unwrap(),
        device_authorize_event_id: EventId::new(
            "ak:event:AfAnsJqSlM9bHVI7P1QBMOEW3p5P1PNQu7BBMpiSnD_e",
        )
        .unwrap(),
        // Signed source coordinates are negative-test claims, not an accepted
        // PCR fixture. The production Origin regression below uses real PCR rows.
        event_authorization: arkret_models_crypto::HumanEventAuthorization {
            event_id: EventId::new("ak:event:AfAnsJqSlM9bHVI7P1QBMOEW3p5P1PNQu7BBMpiSnD_e")
                .unwrap(),
            verification_method: DidUrl::new(format!("{PRINCIPAL_DID}#{DEVICE}")).unwrap(),
            destination_service_id: station.service_id.clone(),
            forward_body_digest: arkret_wire::Hash::new(format!("sha256:{}", "0".repeat(64)))
                .unwrap(),
            authorization_ref: arkret_wire::CommittedEventRef {
                event_id: EventId::new("ak:event:AfAnsJqSlM9bHVI7P1QBMOEW3p5P1PNQu7BBMpiSnD_e")
                    .unwrap(),
                commit_id: arkret_wire::RealmCommitId::from_digest([0x31; 32]),
                stream_ref: arkret_wire::CommitStreamRef::Realm {
                    realm_id: RealmId::from_event_id(&EventId::from_digest(
                        arkret_canonical::DigestSuite::Sha256,
                        [0x32; 32],
                    )),
                },
                stream_position: 1,
            },
            revision: arkret_wire::CurrentRevision {
                commit_id: arkret_wire::RealmCommitId::from_digest([0x31; 32]),
                stream_position: 1,
            },
            governance_generation: 0,
            accepted_at: now - Duration::days(1),
        },
        authorized_generation_ref: 1,
        device_status: DeviceStatus::Active,
        authorization_window: DeviceAuthorizationWindow {
            not_before: now - Duration::days(30),
            expires_at: None,
        },
        attested_at,
        expires_at: attested_at + Duration::minutes(5),
    }
}

/// Sign any core with any Station key, the way a buggy or compromised origin
/// could, so the governance Station's checks are exercised independently.
fn sign_raw(
    core: ForwardDeviceProjectionAttestationCore,
    method: &DidUrl,
    key: &SigningKey,
) -> ForwardDeviceProjectionAttestation {
    let mut attestation = ForwardDeviceProjectionAttestation {
        proof: ProtocolSignature {
            verification_method: method.clone(),
            created_at: core.attested_at,
            jws: "eyJhbGciOiJFZDI1NTE5In0..AA".to_owned(),
        },
        attestation: core,
    };
    attestation.proof.jws = arkret_signatures::sign_ed25519_detached_jws(
        key,
        &attestation.proof_signing_bytes().unwrap(),
    )
    .unwrap();
    attestation
}

fn evidence(
    station: &Station,
    core: ForwardDeviceProjectionAttestationCore,
    resolved_at: DateTime<Utc>,
) -> ForwardAccountDeviceSignerEvidence {
    ForwardAccountDeviceSignerEvidence {
        device_projection_attestation: sign_raw(core, &station.method, &station.signing_key),
        service_resolution: station.resolution(resolved_at),
    }
}

/// A Control Event (`ak.realm.profile`) produced on `station` by the human
/// device named by `fragment`.
fn producer_event(
    station: &Station,
    realm_id: &RealmId,
    fragment: &str,
    created_at: DateTime<Utc>,
    name: &str,
) -> Event {
    let account = station.account();
    let event = arkret_wire::test_support::raw_event_at(
        EventKind::RealmProfile.as_str(),
        ScopeRef::Realm {
            realm_id: realm_id.clone(),
        },
        account.principal_id,
        account.station_id,
        arkret_models_collaboration::events_payloads::RealmProfile::new(name)
            .unwrap()
            .to_value()
            .unwrap(),
        created_at,
    )
    .unwrap();
    sign_event(
        event,
        DidUrl::new(format!("{PRINCIPAL_DID}#{fragment}")).unwrap(),
        DEVICE_SEED,
    )
}

fn forward(
    event: Event,
    evidence: Option<ForwardAccountDeviceSignerEvidence>,
    destination: &DidCoreId,
    signers: &[&Station],
) -> PeerAuthorityForwardEventRequest {
    forward_with_material(event, evidence, destination, signers, None)
}

fn forward_with_material(
    event: Event,
    evidence: Option<ForwardAccountDeviceSignerEvidence>,
    destination: &DidCoreId,
    signers: &[&Station],
    material: Option<MlsGenesisMaterial>,
) -> PeerAuthorityForwardEventRequest {
    let mut request = PeerAuthorityForwardEventRequest {
        branch: AuthorityForwardBranch::AuthorityForward,
        event_submission: EventAdmissionSubmission::new(event.clone()),
        mls_genesis_material: material,
        producer_device_evidence: None,
        producer_agent_evidence: None,
    };
    if let Some(mut evidence) = evidence {
        let method = evidence
            .device_projection_attestation
            .proof
            .verification_method
            .clone();
        let signer = signers
            .iter()
            .find(|station| station.method == method)
            .expect("actual fixture signing key");
        let core = &mut evidence.device_projection_attestation.attestation;
        core.event_authorization.event_id = event.event_id.clone();
        core.event_authorization.verification_method = event
            .producer_proof
            .as_ref()
            .unwrap()
            .verification_method
            .clone();
        core.event_authorization.destination_service_id = destination.clone();
        core.event_authorization.forward_body_digest =
            arkret_models_collaboration::authority_commit::authority_forward_body_digest(&request)
                .unwrap();
        evidence.device_projection_attestation =
            sign_raw(core.clone(), &method, &signer.signing_key);
        request.producer_device_evidence = Some(evidence);
    }
    request
}

fn peer(source: &DidCoreId) -> AuthenticatedPeerContext {
    AuthenticatedPeerContext {
        source_service_id: source.clone(),
    }
}

fn refusal_code(result: Result<AuthoritySubmitOutcome, ServiceError>) -> String {
    match result.expect_err("the forward must be refused") {
        ServiceError::SchemaViolation(_) => "schema_violation".to_owned(),
        ServiceError::UnsupportedEventKind(_) => "unsupported_event_kind".to_owned(),
        error => error
            .conflict_code()
            .map(|code| code.as_str().to_owned())
            .unwrap_or_else(|| format!("{error:?}")),
    }
}

/// A governance Station over its own leased database, governing one Realm.
async fn governance_station() -> (AppState, RealmId) {
    let state =
        coland_test_support::app_state_with_postgres_governance(coland_test_support::app_config());
    let realm_id = RealmId::from_event_id(&EventId::from_digest(
        arkret_canonical::DigestSuite::Sha256,
        arkret_canonical::sha256_bytes(uuid::Uuid::now_v7().as_bytes()),
    ));
    state
        .test_persistence()
        .authority_commits()
        .install_genesis_authority(&CurrentRealmAuthority {
            realm_id: realm_id.clone(),
            generation: 0,
            service_id: state.service_core_id(),
            authority_ref: arkret_wire::RealmCommitAuthorityRef::GenesisOrChangeEvent(
                realm_id.event_id(),
            ),
            last_handoff_ref: None,
        })
        .await
        .unwrap();
    (state, realm_id)
}

async fn assert_nothing_written(state: &AppState, event: &Event) {
    let store = state.test_persistence();
    assert!(
        store
            .authority_commits()
            .committed_event(&event.event_id)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .authority_commits()
            .queued_event(&event.event_id)
            .await
            .unwrap()
            .is_none()
    );
}

#[test]
fn governance_station_refuses_every_evidence_negative_with_zero_writes() {
    runtime().block_on(async {
        let (state, realm_id) = governance_station().await;
        let at = now();
        let a = Station::new(0x61, "forwarder.example", at - Duration::hours(1));
        let c = Station::new(0x62, "elsewhere.example", at - Duration::hours(1));
        let created_at = at - Duration::seconds(60);
        let human = |name: &str| producer_event(&a, &realm_id, DEVICE, created_at, name);
        let source = peer(&a.service_id);

        type RejectionCase<'a> = (
            &'a str,
            Event,
            Option<ForwardAccountDeviceSignerEvidence>,
            AuthenticatedPeerContext,
            DateTime<Utc>,
            &'a str,
        );
        let cases: Vec<RejectionCase<'_>> = vec![
            (
                "human_producer_without_evidence",
                human("no evidence"),
                None,
                source.clone(),
                at,
                "schema_violation",
            ),
            (
                "service_producer_carries_evidence",
                producer_event(&a, &realm_id, "key-1", created_at, "service"),
                Some(evidence(&a, core(&a, at), at)),
                source.clone(),
                at,
                "schema_violation",
            ),
            (
                "source_station_differs_from_attested_account_station",
                human("wrong source"),
                Some(evidence(&a, core(&a, at), at)),
                peer(&c.service_id),
                at,
                "signature_invalid",
            ),
            (
                "attestation_signed_by_non_account_station_key",
                human("foreign key"),
                Some(ForwardAccountDeviceSignerEvidence {
                    device_projection_attestation: sign_raw(
                        core(&a, at),
                        &c.method,
                        &c.signing_key,
                    ),
                    service_resolution: a.resolution(at),
                }),
                source.clone(),
                at,
                "signature_invalid",
            ),
            (
                "service_history_lacks_method_at_attested_at",
                human("before registration"),
                Some(evidence(
                    &a,
                    ForwardDeviceProjectionAttestationCore {
                        attested_at: a.registered_at - Duration::minutes(10),
                        expires_at: at + Duration::minutes(1),
                        ..core(&a, at)
                    },
                    at,
                )),
                source.clone(),
                at,
                "signature_invalid",
            ),
            (
                "proof_fragment_differs_from_attested_device",
                human("other device"),
                Some(evidence(
                    &a,
                    ForwardDeviceProjectionAttestationCore {
                        device_id: DeviceId::new(OTHER_DEVICE).unwrap(),
                        ..core(&a, at)
                    },
                    at,
                )),
                source.clone(),
                at,
                "signature_invalid",
            ),
            (
                "attested_key_does_not_verify_producer_proof",
                human("other key"),
                Some(evidence(
                    &a,
                    ForwardDeviceProjectionAttestationCore {
                        device_signing_key_did: device_key_did([0x52; 32]),
                        ..core(&a, at)
                    },
                    at,
                )),
                source.clone(),
                at,
                "signature_invalid",
            ),
            (
                "evidence_expired",
                human("expired"),
                Some(evidence(&a, core(&a, at), at)),
                source.clone(),
                core(&a, at).expires_at,
                "device_unauthorized",
            ),
            (
                "authorization_window_not_yet_valid",
                human("not yet"),
                Some(evidence(
                    &a,
                    ForwardDeviceProjectionAttestationCore {
                        authorization_window: DeviceAuthorizationWindow {
                            not_before: created_at + Duration::seconds(1),
                            expires_at: None,
                        },
                        ..core(&a, at)
                    },
                    at,
                )),
                source.clone(),
                at,
                "device_unauthorized",
            ),
            (
                "authorization_window_expired_before_now",
                human("window over"),
                Some(evidence(
                    &a,
                    ForwardDeviceProjectionAttestationCore {
                        authorization_window: DeviceAuthorizationWindow {
                            not_before: at - Duration::days(30),
                            expires_at: Some(at - Duration::seconds(1)),
                        },
                        ..core(&a, at)
                    },
                    at,
                )),
                source.clone(),
                at,
                "device_unauthorized",
            ),
            (
                "attested_device_revoked",
                human("revoked"),
                Some(evidence(
                    &a,
                    ForwardDeviceProjectionAttestationCore {
                        device_status: DeviceStatus::Revoked,
                        ..core(&a, at)
                    },
                    at,
                )),
                source.clone(),
                at,
                "device_revoked",
            ),
        ];
        for (name, event, carried, peer, instant, expected) in cases {
            let result = coland_http::test_admit_authority_forward(
                &state,
                &peer,
                forward(event.clone(), carried, &state.service_core_id(), &[&a, &c]),
                instant,
            )
            .await;
            assert_eq!(refusal_code(result), expected, "variant {name}");
            assert_nothing_written(&state, &event).await;
        }

        // Valid fresh evidence passes every §8.2.2 check; the Event then
        // reaches ordinary admission. This fixture installed only Station
        // tenure, so the missing durable Realm authority root refuses it.
        let valid = human("valid");
        let result = coland_http::test_admit_authority_forward(
            &state,
            &source,
            forward(valid.clone(), Some(evidence(&a, core(&a, at), at)), &state.service_core_id(), &[&a, &c]),
            at,
        )
        .await;
        assert!(
            matches!(&result, Err(ServiceError::Conflict(detail)) if detail == "failed_precondition: the Realm has no authority root at this cut"),
            "valid producer evidence reaches Realm authorization: {result:?}"
        );
        assert_nothing_written(&state, &valid).await;
    });
}

#[test]
fn exact_replay_returns_the_original_outcome_before_evidence_freshness() {
    runtime().block_on(async {
        let (state, pool) =
            coland_test_support::app_state_with_pool(coland_test_support::app_config());
        let fixture = historical_human::HumanFixture::new(&pool, state.service_did()).await;
        fixture.admit(&pool).await;
        let accepted = fixture.unit.transactions.last().unwrap();
        let event = accepted.event.clone();
        let commit = accepted.commit.clone();
        let at = commit.committed_at;
        let a = Station::new(0x63, "replayer.example", at - Duration::hours(1));
        let store = state.test_persistence();
        let stream_ref = commit.stream_ref.clone();
        let original = AuthoritySubmitOutcome::Accepted {
            status: AuthorityCommitStatus::Duplicate,
            commit: commit.clone(),
        };

        // The original Event/Commit are a real atomic PG bootstrap acceptance.
        // Replay is checked before evidence or current-source admission; the
        // attached signed negative-test claim is deliberately not a new
        // authorizing source for this already accepted Event.
        let late = at + Duration::hours(1);
        let replay = coland_http::test_admit_authority_forward(
            &state,
            &peer(&a.service_id),
            forward(
                event.clone(),
                Some(evidence(&a, core(&a, at), at)),
                &state.service_core_id(),
                &[&a],
            ),
            late,
        )
        .await
        .unwrap();
        assert_eq!(replay, original);

        // A new attempt with freshly signed evidence gets the same outcome.
        let fresh = coland_http::test_admit_authority_forward(
            &state,
            &peer(&a.service_id),
            forward(
                event.clone(),
                Some(evidence(&a, core(&a, late), late)),
                &state.service_core_id(),
                &[&a],
            ),
            late,
        )
        .await
        .unwrap();
        assert_eq!(fresh, original);
        let head = store
            .authority_commits()
            .stream_head(&stream_ref)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(head.commit_id, commit.commit_id, "no second RealmCommit");
    });
}

#[test]
fn forwarding_station_signs_fresh_retained_evidence_the_governance_station_verifies() {
    runtime().block_on(async {
        let forwarder = coland_test_support::app_state_with_postgres_governance(
            coland_test_support::app_config(),
        );
        let fixture = PcrGenesisFixture::new(forwarder.service_did());
        fixture
            .admit(&forwarder)
            .await
            .expect("accepted PCR genesis");
        let account = fixture.history.account.clone();
        let device = fixture.history.founding_device_id.clone();
        let (governance, realm_id) = governance_station().await;
        let signed = |name: &str, method: DidUrl| {
            let event = arkret_wire::test_support::raw_event_at(
                EventKind::RealmProfile.as_str(),
                ScopeRef::Realm {
                    realm_id: realm_id.clone(),
                },
                account.principal_id.clone(),
                account.station_id.clone(),
                arkret_models_collaboration::events_payloads::RealmProfile::new(name).unwrap().to_value().unwrap(),
                now() - Duration::seconds(1),
            )
            .unwrap();
            sign_event(event, method, fixture.history.founding_device_signing_seed)
        };
        let event = signed(
            "forwarded Control Event",
            fixture.history.device_verification_method.clone(),
        );

        // Every forwarding attempt signs its own evidence and retains the
        // complete object and ref before anything could be sent.
        let first = coland_http::test_fresh_producer_device_evidence(&forwarder, &event, &governance.service_core_id())
            .await
            .unwrap()
            .expect("a human-device producer carries evidence");
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        let second = coland_http::test_fresh_producer_device_evidence(&forwarder, &event, &governance.service_core_id())
            .await
            .unwrap()
            .expect("a human-device producer carries evidence");
        assert!(
            second.device_projection_attestation.attestation.attested_at
                > first.device_projection_attestation.attestation.attested_at
        );
        for issued in [&first, &second] {
            let reference = coland_storage::forwarded_producer_device_evidence_ref(issued).unwrap();
            let retained = forwarder
                .test_persistence()
                .account_device_signer_evidence()
                .get_forward(&account, &device, &reference)
                .await
                .unwrap()
                .expect("forwarded evidence is retained before sending");
            assert_eq!(&retained, issued);
        }

        // The governance Station accepts exactly that evidence from the
        // producer's Station: every §8.2.2 check passes and the Event reaches
        // ordinary admission. Its deliberately incomplete Realm cut has no
        // authority root; it must still refuse the write after verifying proof.
        let result = coland_http::test_admit_authority_forward(
            &governance,
            &peer(&account.station_id),
            PeerAuthorityForwardEventRequest::new(
                EventAdmissionSubmission::new(event.clone()),
                None,
                Some(second),
            )
            .unwrap(),
            now(),
        )
        .await;
        assert!(
            matches!(&result, Err(ServiceError::Conflict(detail)) if detail == "failed_precondition: the Realm has no authority root at this cut"),
            "valid producer evidence reaches Realm authorization: {result:?}"
        );
        assert_nothing_written(&governance, &event).await;

        // A non-device producer method carries no evidence at all.
        let service_signed = signed(
            "non-device producer",
            DidUrl::new(format!("{}#key-1", fixture.history.did)).unwrap(),
        );
        assert!(
            coland_http::test_fresh_producer_device_evidence(&forwarder, &service_signed, &governance.service_core_id())
                .await
                .unwrap()
                .is_none()
        );

        // A device the forwarding Station has no PCR material for is not
        // forwarded: the Station cannot obtain its evidence.
        let unknown = signed(
            "unknown device",
            DidUrl::new(format!("{}#{OTHER_DEVICE}", fixture.history.did)).unwrap(),
        );
        let refused = coland_http::test_fresh_producer_device_evidence(&forwarder, &unknown, &governance.service_core_id())
            .await
            .unwrap_err();
        assert_eq!(
            refused.conflict_code(),
            Some(coland_storage::ConflictCode::TemporarilyUnavailable),
            "{refused:?}"
        );

    });
}

#[test]
fn forwarding_device_refusal_precedes_the_local_queue_write() {
    runtime().block_on(async {
        let forwarder = coland_test_support::app_state_with_postgres_governance(
            coland_test_support::app_config(),
        );
        let fixture = PcrGenesisFixture::new(forwarder.service_did());
        fixture
            .admit(&forwarder)
            .await
            .expect("accepted PCR genesis");
        let realm_id = RealmId::from_event_id(&EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            arkret_canonical::sha256_bytes(uuid::Uuid::now_v7().as_bytes()),
        ));
        let event = arkret_wire::test_support::raw_event_at(
            EventKind::RealmProfile.as_str(),
            ScopeRef::Realm { realm_id },
            fixture.history.account.principal_id.clone(),
            fixture.history.account.station_id.clone(),
            arkret_models_collaboration::events_payloads::RealmProfile::new(
                "unknown device forward",
            )
            .unwrap()
            .to_value()
            .unwrap(),
            now() - Duration::seconds(1),
        )
        .unwrap();
        let event = sign_event(
            event,
            DidUrl::new(format!("{}#{OTHER_DEVICE}", fixture.history.did)).unwrap(),
            fixture.history.founding_device_signing_seed,
        );

        // The route-level forwarding function must run the PCR device gate
        // before it queues the Event. This unknown generation exercises the
        // same preflight boundary used by revoked, pending and fenced devices.
        let refused = coland_http::test_forward_self_event(
            &forwarder,
            &DidCoreId::new("ak:did_core:web:governance.example").unwrap(),
            EventAdmissionSubmission::new(event.clone()),
        )
        .await
        .unwrap_err();
        assert_eq!(
            refused.conflict_code(),
            Some(coland_storage::ConflictCode::TemporarilyUnavailable),
            "{refused:?}"
        );
        assert_nothing_written(&forwarder, &event).await;
    });
}

/// An `ak.mls.genesis` of the Realm scope produced on `station` by its human
/// device, naming the two Blobs by their content addresses.
fn genesis_event(
    station: &Station,
    realm_id: &RealmId,
    created_at: DateTime<Utc>,
    group_info: &[u8],
    tree: &[u8],
) -> Event {
    let account = station.account();
    let event = arkret_wire::test_support::raw_event_at(
        EventKind::MlsGenesis.as_str(),
        ScopeRef::Realm {
            realm_id: realm_id.clone(),
        },
        account.principal_id,
        account.station_id,
        serde_json::json!({
            "cipher_suite": "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
            "group_info_ref": format!("ak:blob:{}", arkret_canonical::sha256_digest(group_info)),
            "ratchet_tree_ref": format!("ak:blob:{}", arkret_canonical::sha256_digest(tree)),
            // Complete signed endpoint shape for negative Blob vectors; this
            // does not claim a successful PCR/MLS source admission.
            "creator_leaf_authority": arkret_models_collaboration::events_payloads::MlsGenesisCreatorLeafAuthority {
                leaf_signature_key_b64u: arkret_wire::Base64UrlString::new(arkret_canonical::base64url_encode(SigningKey::from_bytes(&DEVICE_SEED).verifying_key().as_bytes())).unwrap(),
                endpoint: arkret_wire::MlsWelcomeRecipientEndpoint::Device { device_id: DeviceId::new(DEVICE).unwrap() },
                authorization_event_ref: core(station, created_at).device_authorize_event_id,
            },
            "governance_binding": arkret_models_crypto::MlsGovernanceBindingPayload::realm(
                realm_id.clone(),
                None,
                0,
                0,
                0,
            )
            .unwrap(),
            "created_at": arkret_canonical::format_timestamp_canonical(created_at),
        }),
        created_at,
    )
    .unwrap();
    sign_event(
        event,
        DidUrl::new(format!("{PRINCIPAL_DID}#{DEVICE}")).unwrap(),
        DEVICE_SEED,
    )
}

/// The registered code a refusal carries, including a protocol code that is
/// no persistence conflict code.
fn protocol_code(result: Result<AuthoritySubmitOutcome, ServiceError>) -> String {
    match result.expect_err("the forward must be refused") {
        ServiceError::SchemaViolation(_) => "schema_violation".to_owned(),
        ServiceError::Conflict(detail) => detail
            .split_once(": ")
            .map_or(detail.as_str(), |(code, _)| code)
            .to_owned(),
        error => format!("{error:?}"),
    }
}

/// encryption-and-audit.md §5.1.2 and
/// `ak.vector.federation.authority_forward_genesis_material.v1`: the governance
/// Station checks the carried Genesis material before any write -- a Genesis
/// without it or another kind with it is `schema_violation`, bytes that do
/// not address the Genesis refs are `digest_mismatch`, and addressed bytes
/// that are no RFC 9420 epoch-0 public state are `schema_violation` -- and
/// stores neither the Event nor a Blob.
#[test]
fn forwarded_genesis_material_is_checked_before_any_write() {
    runtime().block_on(async {
        let (state, realm_id) = governance_station().await;
        let at = now();
        let a = Station::new(0x64, "genesis-forwarder.example", at - Duration::hours(1));
        let created_at = at - Duration::seconds(60);
        let source = peer(&a.service_id);
        let group_info = b"forwarded GroupInfo".to_vec();
        let tree = b"forwarded ratchet tree".to_vec();
        let genesis = genesis_event(&a, &realm_id, created_at, &group_info, &tree);
        let with_material = |event: &Event, group_info: &[u8], tree: &[u8]| {
            forward_with_material(
                event.clone(),
                Some(evidence(&a, core(&a, at), at)),
                &state.service_core_id(),
                &[&a],
                Some(MlsGenesisMaterial::from_bytes(group_info, tree)),
            )
        };
        let profile = producer_event(&a, &realm_id, DEVICE, created_at, "no material here");
        let cases = [
            (
                "genesis_without_material",
                genesis.clone(),
                forward(
                    genesis.clone(),
                    Some(evidence(&a, core(&a, at), at)),
                    &state.service_core_id(),
                    &[&a],
                ),
                "schema_violation",
            ),
            (
                "other_kind_with_material",
                profile.clone(),
                with_material(&profile, &group_info, &tree),
                "schema_violation",
            ),
            (
                "material_does_not_address_the_refs",
                genesis.clone(),
                with_material(&genesis, &group_info, b"another ratchet tree"),
                "digest_mismatch",
            ),
            (
                "addressed_material_is_no_public_group_state",
                genesis.clone(),
                with_material(&genesis, &group_info, &tree),
                "schema_violation",
            ),
        ];
        for (name, event, request, expected) in cases {
            let result =
                coland_http::test_admit_authority_forward(&state, &source, request, at).await;
            assert_eq!(protocol_code(result), expected, "variant {name}");
            assert_nothing_written(&state, &event).await;
        }
        for bytes in [&group_info, &tree] {
            let blob_ref = format!("ak:blob:{}", arkret_canonical::sha256_digest(bytes));
            assert!(
                state
                    .test_persistence()
                    .blobs()
                    .get(&blob_ref)
                    .await
                    .unwrap()
                    .is_none(),
                "a refused Genesis stores no Blob"
            );
        }
    });
}
