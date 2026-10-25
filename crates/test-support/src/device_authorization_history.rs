//! Signed canonical PCR material for device persistence/recovery tests.
//!
//! Every signature is real: the webvh principal inception, the
//! device-possession signature over the authorize payload, the producer
//! detached JWS on each Event, and the governance Station's detached signature
//! on each `RealmCommit` (under the fixture authority key
//! [`STATION_AUTHORITY_SEED`]). Ordering is the authority-commit
//! model -- the current governance Station appends exactly one `RealmCommit`
//! per Event on the Realm's stream -- so a consumer that has to prove a device
//! authorization was accepted cites its `CommittedEventRef`.
//!
//! This material makes no acceptance claim on its own. A device counts as
//! authorized only once a Station admitted it through a registered unit;
//! `pcr_genesis` does that and hands out selectors built from the admission
//! result.

use arkret_canonical::DigestSuite;
use arkret_models_collaboration::events_payloads::*;
use arkret_models_identity::{DidDocument, PrincipalRegistrationAnchor, ResolutionCommitment};
use arkret_wire::*;
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signer, SigningKey};

fn hash(label: &str) -> Hash {
    Hash::new(arkret_canonical::sha256_digest(label.as_bytes())).unwrap()
}
/// The governance Station authority key that signs every fixture Commit.
pub const STATION_AUTHORITY_SEED: [u8; 32] = [83; 32];

pub fn device(index: u8) -> DeviceId {
    DeviceId::new(format!("ak:device:01904100-0000-7000-8000-{index:012}")).unwrap()
}
fn at() -> DateTime<Utc> {
    "2026-09-12T00:00:00Z".parse().unwrap()
}
/// The `did:web` Station DID a `did:web` core id was projected from.
///
/// Only `did:web` projects reversibly; a `did:webvh` core id drops the host,
/// so callers holding such a Station pass its DID directly.
pub fn did_web_station(core_id: &DidCoreId) -> Did {
    let host = core_id
        .as_str()
        .strip_prefix("ak:did_core:web:")
        .expect("only a did:web Station core id projects back to its DID");
    Did::new(format!("did:web:{host}")).expect("did:web Station DID")
}
#[derive(Clone)]
pub struct DeviceAuthorizationSpec {
    pub device_id: DeviceId,
    pub signing_seed: [u8; 32],
    pub hpke_seed: [u8; 32],
    pub authorized_by: DeviceOrPrincipalRef,
    pub not_before: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub binding: DeviceAuthorizationBindingKind,
    pub authorized_generation_ref: u64,
    /// Present on exactly `applet_managed_delegation`
    /// (`device-lifecycle.md` 5.2.3); every other branch forbids it.
    pub applet_id: Option<AppletId>,
}

pub fn possession_with(
    account: &AccountId,
    spec: DeviceAuthorizationSpec,
) -> DeviceAuthorizePayload {
    let key = SigningKey::from_bytes(&spec.signing_seed);
    let public =
        arkret_canonical::ed25519_pubkey_to_did_key_multibase(&key.verifying_key().to_bytes());
    let mut hpke = vec![0xec, 0x01];
    hpke.extend(spec.hpke_seed);
    let mut payload = DeviceAuthorizePayload {
        device_id: spec.device_id,
        device_public_key_did: NonEmptyString::new(format!("did:key:{public}")).unwrap(),
        hpke_key: NonEmptyString::new(arkret_canonical::encode_multibase_base58btc(hpke)).unwrap(),
        algorithms: vec![NonEmptyString::new("ak.hpke_x25519_aead_chacha20poly1305.v1").unwrap()],
        device_key_algorithm: NonEmptyString::new("Ed25519").unwrap(),
        authorized_by: spec.authorized_by,
        scopes: None,
        not_before: spec.not_before,
        expires_at: spec.expires_at.map(Some),
        authorization_binding_kind: spec.binding,
        authorized_generation_ref: spec.authorized_generation_ref,
        // The possession transcript excludes this field, so the placeholder is
        // replaced below by the real signature over that transcript.
        device_signature: SignatureMaterial::NonEmptyString(
            NonEmptyString::new("unsigned").unwrap(),
        ),
        recovery_session_id: (spec.binding == DeviceAuthorizationBindingKind::PcrRecovery).then(
            || {
                RecoverySessionId::new("ak:recovery_session:01904100-0000-7000-8000-000000000002")
                    .unwrap()
            },
        ),
        pairing_challenge_transcript_digest: (spec.binding
            == DeviceAuthorizationBindingKind::AcceptedDevice)
            .then(|| hash("pairing")),
        applet_id: spec.applet_id,
        expected_control_revision: None,
        expected_device_revision: None,
    };
    let bytes = payload.device_possession_signature_input(account).unwrap();
    payload.device_signature = SignatureMaterial::NonEmptyString(
        NonEmptyString::new(arkret_canonical::base64url_encode(
            key.sign(&bytes).to_bytes(),
        ))
        .unwrap(),
    );
    payload
}

#[derive(Clone)]
pub struct DeviceHistoryFixtureOptions {
    pub local_id: String,
    pub root_seed: [u8; 32],
    pub next_root_seed: [u8; 32],
    pub founding_device_id: DeviceId,
    pub founding_device_signing_seed: [u8; 32],
    pub founding_device_hpke_seed: [u8; 32],
    pub founding_not_before: DateTime<Utc>,
    pub founding_expires_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

impl Default for DeviceHistoryFixtureOptions {
    fn default() -> Self {
        Self {
            local_id: "alice".to_owned(),
            root_seed: [70; 32],
            next_root_seed: [71; 32],
            founding_device_id: device(1),
            founding_device_signing_seed: [81; 32],
            founding_device_hpke_seed: [1; 32],
            founding_not_before: at(),
            founding_expires_at: None,
            created_at: at(),
        }
    }
}
/// Refresh the content-bound identity of `event` and attach the producer's
/// detached JWS proof made by `seed` under `method`.
pub fn sign_event(mut event: Event, method: DidUrl, seed: [u8; 32]) -> Event {
    event.producer_proof = None;
    event
        .refresh_content_bound_identity_with_digest_suite(DigestSuite::Sha256)
        .unwrap();
    let mut proof = ProducerEventProof {
        kind: proof_kind::DETACHED_JWS.into(),
        verification_method: method,
        event_digest: event.event_id.event_digest(),
        created_at: event.created_at,
        domain: None,
        audience: None,
        proof_purpose: None,
        jws: String::new(),
    };
    proof.jws = arkret_signatures::jws::sign_jws_ed25519(
        &proof.canonical_binding_bytes(&event.actor_id).unwrap(),
        &SigningKey::from_bytes(&seed),
    )
    .unwrap();
    event.producer_proof = Some(proof);
    event
}

pub struct DeviceHistoryFixture {
    pub account: AccountId,
    pub did: Did,
    /// The governance Station DID whose controller signs every fixture commit.
    pub station_did: Did,
    pub inception: arkret_models_identity::DidOperationSubmitRequestBody,
    pub registration_anchor: PrincipalRegistrationAnchor,
    pub events: Vec<Event>,
    /// One accepted `RealmCommit` per Event in `events`, in the same order.
    pub commits: Vec<RealmCommit>,
    pub founding_device_id: DeviceId,
    pub founding_device_signing_seed: [u8; 32],
    /// The founding device's verification method; every Event the fixture
    /// appends after the PCR create is signed with the founding device key.
    pub device_verification_method: DidUrl,
    created_at: DateTime<Utc>,
}
impl DeviceHistoryFixture {
    // Real inception/root/device/producer signatures and a deterministic
    // commit chain. This fixture does not assert HTTP admission, authority
    // signature verification or recovery-session policy.
    pub fn new(station_did: Did) -> Self {
        Self::new_with(station_did, DeviceHistoryFixtureOptions::default())
    }

    pub fn new_with(station_did: Did, options: DeviceHistoryFixtureOptions) -> Self {
        let next_root = arkret_canonical::ed25519_pubkey_to_did_key_multibase(
            &SigningKey::from_bytes(&options.next_root_seed)
                .verifying_key()
                .to_bytes(),
        );
        let prepared = arkret_signatures::webvh::prepare_principal_inception(
            &arkret_signatures::webvh::PrincipalInceptionInput {
                provider_endpoint: &"https://principal.example/".parse().unwrap(),
                principal_endpoint: &"https://principal.example/".parse().unwrap(),
                local_id: &options.local_id,
                also_known_as: &[],
                version_created_at: options.created_at,
                root_seed: &options.root_seed,
                next_root_public_key_multibase: &next_root,
                witness_policy: None,
            },
        )
        .unwrap();
        let verified_root =
            arkret_signatures::webvh::validate_principal_inception_operation(&prepared.submit_body)
                .unwrap();
        // The anchor's DID document is normalized on the wire; hold the parsed
        // wire form so it equals every anchor a Station decodes from bytes.
        let registration_anchor: PrincipalRegistrationAnchor = serde_json::from_value(
            serde_json::to_value(PrincipalRegistrationAnchor::WebvhRegistration {
                registration_did_operation: Box::new(prepared.submit_body.clone()),
                log_entries: vec![serde_json::from_value(prepared.log_entry.clone()).unwrap()],
                witness_records: Vec::new(),
                normalized_did_document: serde_json::from_value::<DidDocument>(
                    prepared.log_entry["state"].clone(),
                )
                .unwrap(),
            })
            .unwrap(),
        )
        .unwrap();
        arkret_identity::validate_principal_registration_anchor(&registration_anchor).unwrap();
        let did = Did::new(prepared.did.clone()).unwrap();
        let account = AccountId::new(
            project_did_to_core_id(&did).unwrap(),
            project_did_to_core_id(&station_did).unwrap(),
        );
        let payload = possession_with(
            &account,
            DeviceAuthorizationSpec {
                device_id: options.founding_device_id.clone(),
                signing_seed: options.founding_device_signing_seed,
                hpke_seed: options.founding_device_hpke_seed,
                authorized_by: DeviceOrPrincipalRef::Principal(account.principal_id.clone()),
                not_before: options.founding_not_before,
                expires_at: options.founding_expires_at,
                binding: DeviceAuthorizationBindingKind::RegistrationAnchor,
                authorized_generation_ref: 1,
                applet_id: None,
            },
        );
        let device_verification_method =
            DidUrl::new(format!("{did}#{}", options.founding_device_id)).unwrap();
        let root = arkret_canonical::ed25519_pubkey_to_did_key_multibase(
            &SigningKey::from_bytes(&options.root_seed)
                .verifying_key()
                .to_bytes(),
        );
        let create = arkret_bootstrap::build_self_principal_pcr_create(
            arkret_bootstrap::SelfPrincipalPcrCreateInput {
                principal_id: account.principal_id.clone(),
                governance_station_id: account.station_id.clone(),
                principal_did: did.clone(),
                genesis_salt: GenesisSalt::new("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
                    .unwrap(),
                trust_domain: TrustDomainId::new("ak:trust_domain:example.net").unwrap(),
                initial_resolution: ResolutionCommitment {
                    did: did.clone(),
                    method_history_head: verified_root.log_head_digest.to_string(),
                    version_id: verified_root.did_version_id.clone(),
                },
                founding_device_descriptor: FoundingDeviceDescriptor {
                    descriptor_version: 1,
                    device_id: payload.device_id.clone(),
                    device_public_key_did: payload.device_public_key_did.clone(),
                    device_key_algorithm: FoundingDeviceKeyAlgorithm::Ed25519,
                    device_key_purpose: FoundingDeviceKeyPurpose::EventSigningAndMlsIdentity,
                    hpke_key: payload.hpke_key.clone(),
                    hpke_key_algorithm: FoundingDeviceHpkeKeyAlgorithm::X25519,
                    algorithms: payload.algorithms.clone(),
                    founding_authorize_payload_digest: typed_device_authorize_payload_digest(
                        &payload,
                        DigestSuite::Sha256,
                    )
                    .unwrap(),
                },
                initial_join_rule: JoinRule::Invite,
                initial_history_access: HistoryAccess::SinceJoin,
                initial_discoverability: Discoverability::InviteOnly,
                created_at: options.created_at,
            },
        )
        .unwrap()
        .into_event();
        let create = sign_event(
            create,
            DidUrl::new(format!("did:key:{root}#{root}")).unwrap(),
            options.root_seed,
        );
        let mut fixture = Self {
            account,
            did,
            station_did,
            inception: prepared.submit_body,
            registration_anchor,
            events: Vec::new(),
            commits: Vec::new(),
            founding_device_id: options.founding_device_id,
            founding_device_signing_seed: options.founding_device_signing_seed,
            device_verification_method,
            created_at: options.created_at,
        };
        let authorize = fixture.raw_event(
            EventKind::DeviceAuthorize,
            serde_json::to_value(payload).unwrap(),
            &create.realm_id,
        );
        let authorize = sign_event(
            authorize,
            fixture.device_verification_method.clone(),
            fixture.founding_device_signing_seed,
        );
        fixture.append(vec![create, authorize]);
        fixture
    }

    pub fn raw_event(&self, kind: EventKind, payload: serde_json::Value, realm: &RealmId) -> Event {
        test_support::raw_event_at(
            kind.as_str(),
            ScopeRef::Realm {
                realm_id: realm.clone(),
            },
            self.account.principal_id.clone(),
            self.account.station_id.clone(),
            payload,
            self.created_at,
        )
        .unwrap()
    }

    pub fn event(&self, kind: EventKind, payload: serde_json::Value) -> Event {
        let event = self.raw_event(kind, payload, &self.events[0].realm_id);
        sign_event(
            event,
            self.device_verification_method.clone(),
            self.founding_device_signing_seed,
        )
    }

    /// Accept `events` in order: each one takes the next position on the
    /// Realm's commit stream and gets a `RealmCommit` chained to the current
    /// head.
    pub fn append(&mut self, events: Vec<Event>) {
        let genesis_event_ref = self.events.first().unwrap_or(&events[0]).event_id.clone();
        let authority_ref = RealmCommitAuthorityRef::GenesisOrChangeEvent(genesis_event_ref);
        for event in events {
            let stream_ref =
                CommitStreamRef::from_scope(&event.scope_ref, Some(event.realm_id.clone()))
                    .expect("a fixture Event scope always names one commit stream");
            let stream_position = self.commits.len() as u64;
            let mut commit = RealmCommit {
                producer_signer_fact_digest: None,
                commit_id: RealmCommitId::from_digest(arkret_canonical::sha256_bytes(
                    format!("{}:{stream_position}", event.event_id).as_bytes(),
                )),
                realm_id: event.realm_id.clone(),
                stream_ref,
                stream_position,
                previous_commit_ref: self.commits.last().map(|commit| commit.commit_id.clone()),
                event_ref: event.event_id.clone(),
                governance_generation: 0,
                authority_ref: authority_ref.clone(),
                committed_at: self.created_at,
                signature: DetachedObjectSignature {
                    context: DetachedSignatureContext::RealmCommit,
                    signature_algorithm: DetachedSignatureAlgorithm::Ed25519,
                    verification_method: self.authority_method(),
                    signed_digest: hash("unsigned"),
                    created_at: self.created_at,
                    signature: Base64UrlString::new("AA".to_owned()).unwrap(),
                },
            };
            let identity =
                arkret_canonical::canonical::unsigned_value(&commit, &["commit_id", "signature"])
                    .expect("fixture Commit identity");
            commit.commit_id = RealmCommitId::from_digest(arkret_canonical::sha256_bytes(
                arkret_canonical::canonical_json_bytes(&identity)
                    .expect("canonical fixture Commit identity"),
            ));
            commit.signature = self.authority_signature(&commit);
            commit
                .verify_commit_id_matches_content()
                .expect("fixture Commit exact content ID");
            commit
                .validate_shape()
                .expect("a fixture RealmCommit is well shaped");
            self.commits.push(commit);
            self.events.push(event);
        }
    }

    /// The governance Station authority method every fixture Commit names.
    pub fn authority_method(&self) -> DidUrl {
        DidUrl::new(format!("{}#authority", self.station_did))
            .expect("a Station DID names a DID URL")
    }

    /// The governance Station's detached signature over `commit`, made with
    /// [`STATION_AUTHORITY_SEED`] under [`Self::authority_method`].
    fn authority_signature(&self, commit: &RealmCommit) -> DetachedObjectSignature {
        let unsigned = arkret_canonical::canonical::unsigned_value(commit, &["signature"])
            .expect("a fixture RealmCommit serializes as an object");
        arkret_signatures::detached_object::sign_detached_object(
            &unsigned,
            DetachedSignatureContext::RealmCommit,
            self.authority_method(),
            commit.committed_at,
            &SigningKey::from_bytes(&STATION_AUTHORITY_SEED),
        )
        .expect("fixture RealmCommit authority signature")
    }
}
