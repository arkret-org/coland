use arkret_models_identity::AccountDeviceSignerEvidence;
use arkret_wire::{AccountId, CommittedEventRef, DeviceId, SignerEvidenceRef};
use async_trait::async_trait;

use crate::{PersistenceError, PersistenceResult};

/// Prepared at one locked origin cut before the Station signs the Device core.
#[derive(Clone, Debug)]
pub struct PreparedAccountDeviceForwardSource {
    pub device: arkret_models_crypto::ForwardDeviceProjectionAttestationCore,
    pub managed:
        Option<arkret_models_collaboration::authority_commit::ForwardManagedActorProvenance>,
}

/// Verified source of this exact managed Device Event; never a stored current authority.
#[derive(Clone, Debug)]
pub struct ForwardedManagedActorSource {
    verified: arkret_identity::managed_actor_provenance::VerifiedManagedActorProvenance,
    original_event_digest: String,
    service_did_document: arkret_identity::DidDocument,
    provision: arkret_models_integration::AppletManagedActorProvisionPayload,
}
impl PartialEq for ForwardedManagedActorSource {
    fn eq(&self, other: &Self) -> bool {
        self.original_event_digest == other.original_event_digest
            && self.service_did_document == other.service_did_document
            && self.provision == other.provision
            && self.verified.original() == other.verified.original()
            && self.verified.account() == other.verified.account()
            && self.verified.source_time() == other.verified.source_time()
    }
}
impl ForwardedManagedActorSource {
    pub fn new(
        verified: arkret_identity::managed_actor_provenance::VerifiedManagedActorProvenance,
        event: &arkret_wire::Event,
        service_did_document: arkret_identity::DidDocument,
    ) -> PersistenceResult<Self> {
        let provision = serde_json::from_value(
            serde_json::to_value(&verified.original().creation.provision.event.payload)
                .map_err(PersistenceError::database)?,
        )
        .map_err(PersistenceError::database)?;
        let source = Self {
            verified,
            original_event_digest: arkret_canonical::canonical_sha256(event)
                .map_err(PersistenceError::database)?,
            service_did_document,
            provision,
        };
        source.ensure_event(event, source.verified.source_time())?;
        Ok(source)
    }
    pub fn provision(&self) -> &arkret_models_integration::AppletManagedActorProvisionPayload {
        &self.provision
    }
    pub fn service_did_document(&self) -> &arkret_identity::DidDocument {
        &self.service_did_document
    }
    pub fn verified(
        &self,
    ) -> &arkret_identity::managed_actor_provenance::VerifiedManagedActorProvenance {
        &self.verified
    }
    pub fn ensure_event(
        &self,
        event: &arkret_wire::Event,
        at: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<()> {
        self.verified
            .ensure_live(at)
            .map_err(|e| PersistenceError::Conflict(format!("device_unauthorized: {e}")))?;
        if event.actor_id.as_account_id() != Some(self.verified.account())
            || event.executed_by.is_some()
            || event.applet_id.as_ref() != Some(&self.provision.applet_id)
            || arkret_canonical::canonical_sha256(event).map_err(PersistenceError::database)?
                != self.original_event_digest
        {
            return Err(PersistenceError::Conflict(
                "signature_invalid: managed source belongs to another exact Event".into(),
            ));
        }
        Ok(())
    }
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
    pub managed: Option<Box<ForwardedManagedActorSource>>,
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
            managed: None,
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
    async fn prepare_non_managed_forward_current(
        &self,
        event: &arkret_wire::Event,
        destination: &arkret_wire::DidCoreId,
        body_digest: &arkret_wire::Hash,
    ) -> PersistenceResult<Option<arkret_models_crypto::ForwardDeviceProjectionAttestationCore>>;

    async fn prepare_forward_request(
        &self,
        request: &arkret_models_collaboration::authority_commit::PeerAuthoritySubmitRequest,
        destination: &arkret_wire::DidCoreId,
        managed_service: Option<&arkret_models_identity::AuthenticatedServiceResolution>,
    ) -> PersistenceResult<Option<PreparedAccountDeviceForwardSource>>;

    async fn retain_forward_request(
        &self,
        request: &arkret_models_collaboration::authority_commit::PeerAuthoritySubmitRequest,
    ) -> PersistenceResult<SignerEvidenceRef>;

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
