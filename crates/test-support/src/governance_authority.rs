//! A verified Realm authority chain with real Ed25519 signatures: genesis under
//! governance Station A, one planned doubly signed handoff to Station B, and a
//! nonce-bound current assertion from B whose key comes from B's route record.
//!
//! Every Commit this fixture seals is signed exactly the way the SDK verifier
//! reconstructs it, so a test mutates one thing and observes that mutation.

use arkret_canonical::canonical;
use arkret_identity::{
    RealmAuthorityFreshness, RealmAuthorityKeyMap, VerifiedRealmAuthority,
    build_authenticated_did_web_service_resolution, verify_realm_authority_bundle,
};
use arkret_models_identity::DidDocument;
use arkret_signatures::PublicKeyMaterial;
use arkret_signatures::detached_object::sign_detached_object;
use arkret_wire::{
    Base64UrlString, CommitStreamHead, CommitStreamRef, DetachedObjectSignature,
    DetachedSignatureAlgorithm, DetachedSignatureContext, Did, DidCoreId, DidUrl, Event, EventId,
    EventKind, Hash, RealmAuthorityBundle, RealmAuthorityCurrentAssertion, RealmAuthorityHandoff,
    RealmAuthorityHandoffId, RealmAuthorityTransition, RealmCommit, RealmCommitAuthorityRef,
    RealmCommitId, RealmId, RealmSnapshotId, ScopeRef, project_did_to_core_id,
};
use chrono::{DateTime, Duration, Utc};
use ed25519_dalek::SigningKey;
use serde_json::json;

const STATION_A: &str = "did:web:governance-a.example";
const STATION_B: &str = "did:web:governance-b.example";
const NONCE: &str = "AAAAAAAAAAAAAAAAAAAAAA";

fn method(did: &str) -> DidUrl {
    DidUrl::new(format!("{did}#realm-authority")).expect("fixture authority method")
}

fn core_id(did: &str) -> DidCoreId {
    project_did_to_core_id(&Did::new(did.to_owned()).expect("fixture Station DID"))
        .expect("fixture Station core id")
}

fn public(key: &SigningKey) -> PublicKeyMaterial {
    PublicKeyMaterial::Ed25519Raw {
        bytes: key.verifying_key().to_bytes().to_vec(),
    }
}

fn hash(byte: char) -> Hash {
    Hash::new(format!("sha256:{}", format!("{byte}{byte}").repeat(32))).expect("fixture hash")
}

fn placeholder_signature(
    context: DetachedSignatureContext,
    at: DateTime<Utc>,
) -> DetachedObjectSignature {
    DetachedObjectSignature {
        context,
        signature_algorithm: DetachedSignatureAlgorithm::Ed25519,
        verification_method: method(STATION_A),
        signed_digest: hash('1'),
        created_at: at,
        sig: Base64UrlString::new("A".repeat(86)).expect("placeholder signature"),
    }
}

fn route_record(did: &str, key: &SigningKey, now: DateTime<Utc>) -> serde_json::Value {
    let document: DidDocument = serde_json::from_value(json!({
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": did,
        "verificationMethod": [{
            "id": format!("{did}#realm-authority"),
            "controller": did,
            "type": "Multikey",
            "publicKeyMultibase": arkret_canonical::ed25519_pubkey_to_did_key_multibase(
                key.verifying_key().as_bytes()
            ),
        }],
        "authentication": [format!("{did}#realm-authority")],
        "assertionMethod": [format!("{did}#realm-authority")],
        "service": [{
            "id": format!("{did}#station"),
            "type": "ArkretService",
            "serviceEndpoint": "https://governance-b.example/",
            "serviceKind": "station",
        }],
    }))
    .expect("fixture route document");
    serde_json::to_value(
        build_authenticated_did_web_service_resolution(
            core_id(did),
            "station".to_owned(),
            document,
            now,
        )
        .expect("fixture route resolution"),
    )
    .expect("fixture route record")
}

#[allow(clippy::too_many_arguments)]
fn unsigned_commit(
    realm_id: &RealmId,
    at: DateTime<Utc>,
    seed: u8,
    stream_position: u64,
    previous: Option<&RealmCommitId>,
    event_ref: &EventId,
    generation: u64,
    authority_ref: RealmCommitAuthorityRef,
) -> RealmCommit {
    RealmCommit {
        producer_signer_fact_digest: None,
        commit_id: RealmCommitId::from_digest([seed; 32]),
        realm_id: realm_id.clone(),
        stream_ref: CommitStreamRef::Realm {
            realm_id: realm_id.clone(),
        },
        stream_position,
        previous_commit_ref: previous.cloned(),
        event_ref: event_ref.clone(),
        governance_generation: generation,
        authority_ref,
        committed_at: at,
        signature: placeholder_signature(DetachedSignatureContext::RealmCommit, at),
    }
}

/// Seal a Commit exactly the way the verifier reconstructs it: the unsigned
/// projection is the object minus its `signature` member.
fn seal_commit(
    mut commit: RealmCommit,
    did: &str,
    key: &SigningKey,
    at: DateTime<Utc>,
) -> RealmCommit {
    let identity =
        canonical::unsigned_value(&commit, &["commit_id", "signature"]).expect("Commit identity");
    commit.commit_id = RealmCommitId::from_digest(arkret_canonical::sha256_bytes(
        arkret_canonical::canonical_json_bytes(&identity).expect("canonical Commit identity"),
    ));
    let unsigned = canonical::unsigned_value(&commit, &["signature"]).expect("unsigned Commit");
    commit.signature = sign_detached_object(
        &unsigned,
        DetachedSignatureContext::RealmCommit,
        method(did),
        at,
        key,
    )
    .expect("Commit signature");
    commit
        .verify_commit_id_matches_content()
        .expect("fixture Commit content ID");
    commit
}

/// Both handoff signatures seal the same unsigned body under different
/// domains.
fn seal_handoff(
    mut handoff: RealmAuthorityHandoff,
    key_a: &SigningKey,
    key_b: &SigningKey,
    at: DateTime<Utc>,
) -> RealmAuthorityHandoff {
    let unsigned = canonical::unsigned_value(
        &handoff,
        &[
            "old_authority_signature",
            "new_authority_acceptance_signature",
        ],
    )
    .expect("unsigned handoff");
    handoff.old_authority_signature = sign_detached_object(
        &unsigned,
        DetachedSignatureContext::RealmAuthorityHandoffOld,
        method(STATION_A),
        at,
        key_a,
    )
    .expect("old authority signature");
    handoff.new_authority_acceptance_signature = sign_detached_object(
        &unsigned,
        DetachedSignatureContext::RealmAuthorityHandoffNewAcceptance,
        method(STATION_B),
        at,
        key_b,
    )
    .expect("new authority acceptance signature");
    handoff
}

/// Which governance Station key seals a fixture Commit.
#[derive(Clone, Copy, Debug)]
pub enum GovernanceSigner {
    /// Station A: governance of generation 0 only.
    GenesisStation,
    /// Station B: governance of generation 1, the current generation.
    CurrentStation,
}

/// A Realm whose authority passed from Station A (generation 0) to Station B
/// (generation 1), verified end to end.
pub struct GovernanceChain {
    pub realm_id: RealmId,
    pub authority: VerifiedRealmAuthority,
    pub keys: RealmAuthorityKeyMap,
    /// The Realm-stream head a member Station holds: the first Commit B made.
    pub head: RealmCommit,
    key_a: SigningKey,
    key_b: SigningKey,
    handoff_id: RealmAuthorityHandoffId,
    at: DateTime<Utc>,
}

impl Default for GovernanceChain {
    fn default() -> Self {
        Self::new()
    }
}

impl GovernanceChain {
    #[must_use]
    pub fn new() -> Self {
        let now = DateTime::from_timestamp(Utc::now().timestamp(), 0).expect("fixture clock");
        let at = now - Duration::seconds(50);
        let key_a = SigningKey::from_bytes(&[0xA1; 32]);
        let key_b = SigningKey::from_bytes(&[0xB2; 32]);
        let handoff_id = RealmAuthorityHandoffId::from_digest([0x21; 32]);
        use arkret_models_collaboration::events_payloads::{
            RealmCreatePayload, RealmGenesis, RealmPurpose,
        };
        let salt = arkret_wire::GenesisSalt::new(arkret_canonical::base64url_encode(
            arkret_canonical::sha256_bytes(uuid::Uuid::now_v7().as_bytes()),
        ))
        .expect("fixture salt");
        let payload = RealmCreatePayload::new(
            RealmGenesis::new(
                RealmPurpose::Collaboration,
                salt,
                arkret_wire::TrustDomainId::new("ak:trust_domain:fixture.example")
                    .expect("trust domain"),
                arkret_wire::SecurityClass::Standard,
                core_id(STATION_A),
                arkret_wire::JoinRule::Invite,
                arkret_wire::HistoryAccess::SinceJoin,
                arkret_wire::Discoverability::InviteOnly,
                None,
                None,
            )
            .expect("ordinary genesis"),
        )
        .to_value()
        .expect("genesis payload");
        let genesis_event = arkret_wire::test_support::raw_event_at(
            EventKind::RealmCreate.as_str(),
            ScopeRef::RealmGenesis,
            DidCoreId::new("ak:did_core:web:founder.example").expect("founder"),
            core_id(STATION_A),
            payload,
            at - Duration::seconds(10),
        )
        .expect("fixture genesis");
        let realm_id = genesis_event.realm_id.clone();
        let genesis_commit = seal_commit(
            unsigned_commit(
                &realm_id,
                at,
                0x01,
                0,
                None,
                &genesis_event.event_id,
                0,
                RealmCommitAuthorityRef::GenesisOrChangeEvent(genesis_event.event_id.clone()),
            ),
            STATION_A,
            &key_a,
            at,
        );
        let change_event = arkret_wire::test_support::raw_event_at(
            EventKind::RealmGovernanceStationChange.as_str(), ScopeRef::Realm { realm_id: realm_id.clone() },
            DidCoreId::new("ak:did_core:web:founder.example").expect("founder"), core_id(STATION_A),
            json!({"expected_governance_generation":0,"expected_realm_stream_commit_id":genesis_commit.commit_id,"new_governance_station_id":core_id(STATION_B)}),
            at - Duration::seconds(9),
        ).expect("fixture governance change");
        let change_commit = seal_commit(
            unsigned_commit(
                &realm_id,
                at,
                0x02,
                1,
                Some(&genesis_commit.commit_id),
                &change_event.event_id,
                0,
                RealmCommitAuthorityRef::GenesisOrChangeEvent(genesis_event.event_id.clone()),
            ),
            STATION_A,
            &key_a,
            at,
        );
        let handoff = seal_handoff(
            RealmAuthorityHandoff {
                pcr_private_state_digest: None,
                management_private_state_digest: None,
                handoff_id: handoff_id.clone(),
                realm_id: realm_id.clone(),
                from_generation: 0,
                to_generation: 1,
                from_service_id: core_id(STATION_A),
                to_service_id: core_id(STATION_B),
                final_stream_heads_digest: hash('a'),
                snapshot_ref: RealmSnapshotId::from_digest([0x44; 32]),
                historical_signer_facts_digest: None,
                change_event_ref: change_event.event_id.clone(),
                change_commit_id: change_commit.commit_id.clone(),
                old_authority_signature: placeholder_signature(
                    DetachedSignatureContext::RealmAuthorityHandoffOld,
                    at,
                ),
                new_authority_acceptance_signature: placeholder_signature(
                    DetachedSignatureContext::RealmAuthorityHandoffNewAcceptance,
                    at,
                ),
            },
            &key_a,
            &key_b,
            at,
        );
        let head_event = arkret_wire::test_support::raw_event_at(
            EventKind::MessageCreate.as_str(),
            ScopeRef::Realm {
                realm_id: realm_id.clone(),
            },
            DidCoreId::new("ak:did_core:web:founder.example").expect("founder"),
            core_id(STATION_A),
            json!({}),
            at - Duration::seconds(8),
        )
        .expect("fixture head Event");
        let head = seal_commit(
            unsigned_commit(
                &realm_id,
                at,
                0x03,
                2,
                Some(&change_commit.commit_id),
                &head_event.event_id,
                1,
                RealmCommitAuthorityRef::Handoff(handoff_id.clone()),
            ),
            STATION_B,
            &key_b,
            at,
        );
        let stream_head = CommitStreamHead {
            stream_ref: head.stream_ref.clone(),
            stream_position: head.stream_position,
            commit_id: head.commit_id.clone(),
        };
        let mut assertion = RealmAuthorityCurrentAssertion {
            realm_id: realm_id.clone(),
            current_generation: 1,
            current_service_id: core_id(STATION_B),
            last_handoff_ref: Some(handoff_id.clone()),
            realm_stream_head: stream_head.clone(),
            nonce: Base64UrlString::new(NONCE.to_owned()).expect("fixture nonce"),
            expires_at: now + Duration::seconds(300),
            signature: placeholder_signature(
                DetachedSignatureContext::RealmAuthorityCurrentAssertion,
                at,
            ),
        };
        let unsigned =
            canonical::unsigned_value(&assertion, &["signature"]).expect("unsigned assertion");
        assertion.signature = sign_detached_object(
            &unsigned,
            DetachedSignatureContext::RealmAuthorityCurrentAssertion,
            method(STATION_B),
            at,
            &key_b,
        )
        .expect("assertion signature");
        let bundle = RealmAuthorityBundle {
            realm_id: realm_id.clone(),
            genesis_event,
            genesis_commit,
            authority_transitions: vec![RealmAuthorityTransition {
                change_event,
                change_commit,
                handoff,
            }],
            current_generation: 1,
            current_service_id: core_id(STATION_B),
            current_route_record: route_record(STATION_B, &key_b, now),
            realm_stream_head: stream_head,
            bundle_issued_at: at,
            current_assertion: assertion,
        };
        let keys = RealmAuthorityKeyMap::new()
            .with_key(&method(STATION_A), public(&key_a))
            .with_key(&method(STATION_B), public(&key_b));
        let authority = verify_realm_authority_bundle(
            &bundle,
            &RealmAuthorityFreshness::new(
                now,
                Base64UrlString::new(NONCE.to_owned()).expect("fixture nonce"),
            ),
            &keys,
        )
        .expect("the fixture authority chain verifies");
        Self {
            realm_id,
            authority,
            keys,
            head,
            key_a,
            key_b,
            handoff_id,
            at,
        }
    }

    /// The Commit that directly succeeds [`Self::head`] and admits `event`,
    /// sealed by `signer` under generation 1.
    #[must_use]
    pub fn commit_next(&self, event: &Event, signer: GovernanceSigner) -> RealmCommit {
        let commit = unsigned_commit(
            &self.realm_id,
            self.at,
            0,
            self.head.stream_position + 1,
            Some(&self.head.commit_id),
            &event.event_id,
            1,
            RealmCommitAuthorityRef::Handoff(self.handoff_id.clone()),
        );
        self.seal(commit, signer)
    }

    /// Re-seal an edited Commit with `signer`'s real key.
    #[must_use]
    pub fn seal(&self, commit: RealmCommit, signer: GovernanceSigner) -> RealmCommit {
        match signer {
            GovernanceSigner::GenesisStation => {
                seal_commit(commit, STATION_A, &self.key_a, self.at)
            }
            GovernanceSigner::CurrentStation => {
                seal_commit(commit, STATION_B, &self.key_b, self.at)
            }
        }
    }
}
