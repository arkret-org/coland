use arkret_models_identity::AccountDeviceSignerEvidence;
use arkret_wire::{AccountId, CommittedEventRef, DeviceId, SignerEvidenceRef};
use async_trait::async_trait;

use crate::{PersistenceError, PersistenceResult};

/// Internal issuance result, never a transport model. The body already contains
/// the original managed source before its Device attestation digest is formed.
#[derive(Clone, Debug)]
pub struct PreparedManagedForward {
    pub request: arkret_models_collaboration::authority_commit::PeerAuthoritySubmitRequest,
    pub core: arkret_models_crypto::ForwardDeviceProjectionAttestationCore,
}

/// The complete `producer_device_evidence` a governance Station verified for
/// a cross-Station human-device producer, with its content address.
///
/// It is retained in the same transaction that writes the Event's first
/// `RealmCommit`, for audit only: nothing reads it back as device authority,
/// and historical replay relies on the Commit and the authority chain.
#[derive(Clone, Debug, PartialEq)]
pub struct ForwardedProducerDeviceEvidence {
    pub evidence: arkret_models_identity::ForwardAccountDeviceSignerEvidence,
    pub producer_signer_fact:
        arkret_models_collaboration::authority_commit::AccountDeviceHistoricalSignerFact,
    pub evidence_ref: SignerEvidenceRef,
}

impl ForwardedProducerDeviceEvidence {
    /// Address the complete object exactly as the evidence ref rule requires.
    pub fn new(
        evidence: arkret_models_identity::ForwardAccountDeviceSignerEvidence,
        producer_signer_fact: arkret_models_collaboration::authority_commit::AccountDeviceHistoricalSignerFact,
    ) -> PersistenceResult<Self> {
        let evidence_ref = forwarded_producer_device_evidence_ref(&evidence)?;
        Ok(Self {
            evidence,
            evidence_ref,
            producer_signer_fact,
        })
    }
}

/// Internal immutable archive address of the complete forward sibling, including
/// its proof and Service history. This is not a directory evidence projection
/// or a signature-verification operation.
pub fn forwarded_producer_device_evidence_ref(
    evidence: &arkret_models_identity::ForwardAccountDeviceSignerEvidence,
) -> PersistenceResult<SignerEvidenceRef> {
    let bytes = arkret_canonical::canonical::canonical_json_bytes(evidence)
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    SignerEvidenceRef::new(format!(
        "ak:signer_evidence:sha256:{}",
        arkret_canonical::canonical::sha256_hex(bytes),
    ))
    .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))
}

/// Durable origin roots. A current issuer must use the checked same-cut write;
/// historical reads require the caller to authorize disclosure separately.
#[async_trait]
pub trait AccountDeviceSignerEvidenceStore: Send + Sync {
    /// Freeze the complete managed source and native Device core under one
    /// confirmed PCR cut. Only ordinary Event and MLS forward branches apply.
    async fn prepare_managed_forward(
        &self,
        request: &arkret_models_collaboration::authority_commit::PeerAuthoritySubmitRequest,
        destination: &arkret_wire::DidCoreId,
    ) -> PersistenceResult<PreparedManagedForward>;

    /// Recheck the entire signed body at its original issuance cut and retain
    /// its exact private bytes before the first network attempt.
    async fn retain_managed_forward(
        &self,
        request: &arkret_models_collaboration::authority_commit::PeerAuthoritySubmitRequest,
    ) -> PersistenceResult<SignerEvidenceRef>;

    /// Private immutable read for recovery of this exact original request.
    /// Callers still authenticate its Account/Device and authorize forwarding.
    async fn get_managed_forward(
        &self,
        account: &AccountId,
        device: &DeviceId,
        reference: &SignerEvidenceRef,
    ) -> PersistenceResult<
        Option<arkret_models_collaboration::authority_commit::PeerAuthoritySubmitRequest>,
    >;

    /// Prepare the existing forward-only unsigned core from a locked native
    /// authorization cut. This grants neither directory disclosure nor business
    /// authority; retaining its signed wrapper rechecks the same source.
    async fn prepare_forward_current(
        &self,
        event: &arkret_wire::Event,
        destination: &arkret_wire::DidCoreId,
        body_digest: &arkret_wire::Hash,
    ) -> PersistenceResult<Option<arkret_models_crypto::ForwardDeviceProjectionAttestationCore>>;

    /// Resolve only an immutable origin source already bound by this Commit.
    /// This neither authorizes current admission nor installs a stream replica.
    async fn forwarded_bound_account_device_signer_fact(
        &self,
        event: &arkret_wire::Event,
        commit: &arkret_wire::RealmCommit,
        governance: &arkret_wire::DidCoreId,
    ) -> PersistenceResult<
        Option<arkret_models_collaboration::authority_commit::AccountDeviceHistoricalSignerFact>,
    >;

    async fn get_forward(
        &self,
        account: &AccountId,
        device: &DeviceId,
        reference: &SignerEvidenceRef,
    ) -> PersistenceResult<Option<arkret_models_identity::ForwardAccountDeviceSignerEvidence>>;
    async fn retain_forward_current(
        &self,
        event: &arkret_wire::Event,
        evidence: &arkret_models_identity::ForwardAccountDeviceSignerEvidence,
    ) -> PersistenceResult<SignerEvidenceRef>;

    async fn retain_current(
        &self,
        evidence: &AccountDeviceSignerEvidence,
        authorization_ref: &CommittedEventRef,
    ) -> PersistenceResult<SignerEvidenceRef>;

    async fn get(
        &self,
        account: &AccountId,
        device: &DeviceId,
        reference: &SignerEvidenceRef,
    ) -> PersistenceResult<Option<AccountDeviceSignerEvidence>>;
}
