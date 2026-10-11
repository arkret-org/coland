//! PCR genesis fixture backed by the formal two-Event/two-Commit authority unit.
//!
//! This builds signed protocol material and a storage transaction. Tests that
//! need an *accepted* PCR must admit it and use the durable result; constructing
//! the fixture alone makes no authority claim. Further devices are accepted
//! only through the registered `accepted_device` unit, approved by the founding
//! device, so every device authorization a test stands on is one the Station
//! decided.
//!
//! This module names its sibling as `super::device_authorization_history`, so a
//! crate that cannot depend on this one (storage-postgres) can include both
//! files side by side.

use arkret_models_collaboration::events_payloads::{
    DeviceAuthorizationBindingKind, DeviceOrPrincipalRef, device_authorize_payload_digest,
};
use arkret_models_collaboration::principal_operations::PcrGenesisAdmissionInput;
use arkret_models_identity::{
    IdentityBindingPurpose, IdentityCreationControlProofKind, PCR_GENESIS_UNIT_KINDS,
    UnsignedIdentityCreationControlProof, UnsignedIdentityCreationControlProofBody,
};
use arkret_wire::{
    CommittedEventRef, DeviceId, DidUrl, EventKind, Hash, IdempotencyKey, PcrGenesisUnit,
    RealmCommit, RealmCommitAuthorityRef, TrustDomainId, WebOrigin,
};
use coland_storage::{
    AcceptedDeviceAuthorizationOutcome, AuthorityCommitTransaction, CurrentRealmAuthority,
    DeviceRevocationGateSelector, PcrGenesisCommitOutcome, PcrGenesisCommitUnit, PersistenceResult,
    PersistenceStore, WebvhLogRecord,
};

use super::device_authorization_history::{
    DeviceAuthorizationSpec, DeviceHistoryFixture, DeviceHistoryFixtureOptions, possession_with,
};

fn hash(value: &str) -> Hash {
    Hash::new(arkret_canonical::sha256_digest(value.as_bytes())).expect("fixture digest")
}

/// Signed PCR material with its exact request body and atomic PG command.
pub struct PcrGenesisFixture {
    pub history: DeviceHistoryFixture,
    pub unit: PcrGenesisCommitUnit,
}

/// A non-founding device the Station accepted through the `accepted_device`
/// unit, with the key it signs as.
#[derive(Clone, Debug)]
pub struct AcceptedDevice {
    /// The revocation-gate selector built from the Commit the store returned.
    pub authorization: DeviceRevocationGateSelector,
    pub verification_method: DidUrl,
    pub signing_seed: [u8; 32],
}

/// The gate selector of the device authorization `commit` ordered.
fn accepted_selector(
    principal_id: arkret_wire::DidCoreId,
    station_id: arkret_wire::DidCoreId,
    device_id: &DeviceId,
    commit: &RealmCommit,
) -> DeviceRevocationGateSelector {
    DeviceRevocationGateSelector {
        principal_id,
        station_id,
        device_id: device_id.to_string(),
        authorization_ref: CommittedEventRef {
            event_id: commit.event_ref.clone(),
            commit_id: commit.commit_id.clone(),
            stream_ref: commit.stream_ref.clone(),
            stream_position: commit.stream_position,
        },
    }
}

impl PcrGenesisFixture {
    /// Build unique principal history routed through the supplied governance Station.
    #[must_use]
    pub fn new(station_did: arkret_wire::Did) -> Self {
        Self::new_with(
            station_did,
            DeviceHistoryFixtureOptions {
                local_id: format!("pcr-{}", uuid::Uuid::now_v7().simple()),
                ..Default::default()
            },
        )
    }

    /// Build the principal history `options` describe, routed through the
    /// supplied governance Station. Equal options give an equal principal, so
    /// one principal can hold a PCR at each of several Stations.
    #[must_use]
    pub fn new_with(station_did: arkret_wire::Did, options: DeviceHistoryFixtureOptions) -> Self {
        let history = DeviceHistoryFixture::new_with(station_did, options);
        let station = history.account.station_id.clone();
        let at = history.commits[0].committed_at;
        let evidence = arkret_signatures::webvh::sign_registration_did_evidence_draft(
            &history.inception,
            at,
            &[70; 32],
        )
        .expect("fixture registration DID evidence")
        .accept(at)
        .expect("fixture registration DID evidence acceptance");
        let create = history.events[0].clone();
        let authorize = history.events[1].clone();
        let authorize_value =
            serde_json::Value::Object(authorize.payload.clone().into_iter().collect());
        let create_digest =
            Hash::new(arkret_canonical::canonical_sha256(&create.payload).unwrap()).unwrap();
        let authorize_digest = device_authorize_payload_digest(
            &authorize_value,
            arkret_canonical::DigestSuite::Sha256,
        )
        .expect("fixture authorize payload digest");
        let proof = arkret_signatures::webvh::sign_identity_creation_control_proof(
            UnsignedIdentityCreationControlProof::new(UnsignedIdentityCreationControlProofBody {
                proof_kind: IdentityCreationControlProofKind::DidWebvhInceptionUpdateKey,
                challenge_id: "fixture-challenge".to_owned(),
                challenge: "fixture-challenge-value".to_owned(),
                purpose: IdentityBindingPurpose::AccountBindingAndPcrGenesis,
                account_subject: hash("fixture-account"),
                principal_id: history.account.principal_id.clone(),
                did: history.did.clone(),
                registration_anchor_digest: history
                    .registration_anchor
                    .canonical_digest()
                    .expect("registration anchor digest"),
                did_version_id: evidence.version_id.clone(),
                control_key_digest: evidence.control_key_digest.clone(),
                pcr_realm_id: create.realm_id.clone(),
                realm_create_payload_digest: create_digest,
                founding_authorize_payload_digest: authorize_digest,
                initial_session_request_digest: hash("fixture-initial-session"),
                genesis_unit_kinds: PCR_GENESIS_UNIT_KINDS,
                identity_creation_lease_id: "fixture-lease".to_owned(),
                lease_fence: 1,
                dpop_jkt: "fixture-thumbprint".to_owned(),
                audience_id: station.clone(),
                origin: WebOrigin::new("https://principal.example").unwrap(),
                trust_domain: TrustDomainId::new("ak:trust_domain:example.net").unwrap(),
                issued_at: at,
                expires_at: at + chrono::TimeDelta::minutes(5),
                verification_key_multibase: arkret_canonical::ed25519_pubkey_to_did_key_multibase(
                    &ed25519_dalek::SigningKey::from_bytes(&[70; 32])
                        .verifying_key()
                        .to_bytes(),
                ),
                signature_algorithm: arkret_wire::DetachedSignatureAlgorithm::Ed25519,
            })
            .expect("identity creation control proof body"),
            &[70; 32],
        )
        .expect("identity creation control signature");
        let submission = PcrGenesisAdmissionInput {
            account_authority_id: station.clone(),
            principal_id: history.account.principal_id.clone(),
            did: history.did.clone(),
            pcr_realm_id: create.realm_id.clone(),
            did_version_id: evidence.version_id.clone(),
            control_key_digest: evidence.control_key_digest.clone(),
            idempotency_key: IdempotencyKey::new(uuid::Uuid::now_v7().to_string()).unwrap(),
            registration_request_digest: hash("fixture-registration"),
            principal_registration_anchor: history.registration_anchor.clone(),
            registration_did_evidence: evidence,
            identity_creation_control_proof: proof,
            genesis_unit: PcrGenesisUnit::new(create.clone(), authorize.clone())
                .expect("closed PCR genesis unit"),
        };
        let authority = CurrentRealmAuthority {
            realm_id: create.realm_id.clone(),
            generation: 0,
            service_id: station,
            authority_ref: RealmCommitAuthorityRef::GenesisOrChangeEvent(create.event_id.clone()),
            last_handoff_ref: None,
        };
        let transactions = [
            (create, history.commits[0].clone()),
            (authorize, history.commits[1].clone()),
        ]
        .map(|(event, commit)| AuthorityCommitTransaction {
            expected_authority: authority.clone(),
            event,
            commit,
            producer_signer_fact: None,
            mls_state: None,
            welcomes: Vec::new(),
            recipient_queue_capacity: 0,
        });
        let exact_request_body =
            serde_json::to_vec(&submission).expect("fixture request body bytes");
        let unit = PcrGenesisCommitUnit {
            submission,
            exact_request_body,
            transactions,
        };
        unit.validate().expect("valid formal PCR genesis unit");
        Self { history, unit }
    }

    /// Submit the unit to the same durable AuthorityCommitStore used in
    /// production.
    ///
    /// The principal's DID inception is registered first, as the WebVH
    /// registration provider does before any PCR genesis relay reaches the
    /// Station; account projection re-verifies the genesis against it.
    pub async fn admit_into(
        &self,
        persistence: &dyn PersistenceStore,
    ) -> PersistenceResult<PcrGenesisCommitOutcome> {
        let did = self.history.did.to_string();
        if persistence.webvh().list_log_events(&did).await?.is_empty() {
            let operation = serde_json::to_value(&self.history.inception.operation)
                .expect("fixture DID inception serializes");
            persistence
                .webvh()
                .append_log_event(WebvhLogRecord {
                    event_digest: arkret_canonical::canonical_sha256(&operation)
                        .expect("fixture DID inception digest"),
                    did,
                    seq: self.history.inception.seq.unwrap_or(1),
                    operation,
                    created_at: self.history.events[0].created_at,
                })
                .await?;
        }
        persistence
            .authority_commits()
            .admit_pcr_genesis_unit(&self.unit, self.unit.transactions[0].commit.committed_at)
            .await
    }

    /// Admit the genesis and return the founding device's gate selector, taken
    /// from the admission result rather than from the fixture's own material.
    pub async fn admit_founding_device(
        &self,
        persistence: &dyn PersistenceStore,
    ) -> PersistenceResult<DeviceRevocationGateSelector> {
        let (PcrGenesisCommitOutcome::Committed(result)
        | PcrGenesisCommitOutcome::Duplicate(result)) = self.admit_into(persistence).await?;
        Ok(accepted_selector(
            result.principal_id,
            self.unit.submission.account_authority_id.clone(),
            &result.accepted_device_id,
            &result.commits[1],
        ))
    }

    /// Accept one more device of this principal through the registered
    /// `accepted_device` unit (device-lifecycle.md 5.4): the founding device
    /// approves it in the current generation and signs the Event, the target
    /// key signs its possession proof, and the Station admits Event, Commit
    /// and typed device current in one transaction. The genesis must already
    /// be admitted.
    pub async fn admit_accepted_device(
        &mut self,
        persistence: &dyn PersistenceStore,
        signing_seed: [u8; 32],
    ) -> PersistenceResult<AcceptedDevice> {
        let device_id = DeviceId::new(format!("ak:device:{}", uuid::Uuid::now_v7()))
            .expect("fixture device id");
        let payload = possession_with(
            &self.history.account,
            DeviceAuthorizationSpec {
                device_id: device_id.clone(),
                signing_seed,
                hpke_seed: [signing_seed[0].wrapping_add(1); 32],
                authorized_by: DeviceOrPrincipalRef::DeviceId(
                    self.history.founding_device_id.clone(),
                ),
                not_before: self.history.events[1].created_at,
                expires_at: None,
                binding: DeviceAuthorizationBindingKind::AcceptedDevice,
                authorized_generation_ref: 1,
                applet_id: None,
            },
        );
        let event = self.history.event(
            EventKind::DeviceAuthorize,
            serde_json::to_value(payload).expect("fixture authorize payload"),
        );
        self.history.append(vec![event.clone()]);
        let commit = self
            .history
            .commits
            .last()
            .expect("the appended Event has its Commit")
            .clone();
        let queued_at = commit.committed_at;
        let transaction = AuthorityCommitTransaction {
            expected_authority: self.unit.transactions[1].expected_authority.clone(),
            event,
            commit,
            producer_signer_fact: None,
            mls_state: None,
            welcomes: Vec::new(),
            recipient_queue_capacity: 0,
        };
        let (AcceptedDeviceAuthorizationOutcome::Committed(accepted)
        | AcceptedDeviceAuthorizationOutcome::Duplicate(accepted)) = persistence
            .authority_commits()
            .admit_accepted_device_authorization(&transaction, queued_at)
            .await?;
        Ok(AcceptedDevice {
            authorization: accepted_selector(
                self.history.account.principal_id.clone(),
                self.unit.submission.account_authority_id.clone(),
                &device_id,
                &accepted,
            ),
            verification_method: DidUrl::new(format!("{}#{device_id}", self.history.did))
                .expect("accepted device verification method"),
            signing_seed,
        })
    }
}
