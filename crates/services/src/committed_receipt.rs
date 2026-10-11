//! Non-governance receipt of one committed Event (federation §3,
//! device-lifecycle §8.2.2).
//!
//! Digest-bearing ordinary Human and Applet Service receipts use the exact original frozen fact:
//! governance chain, Commit content ID/signature, target binding and real Event
//! Ed signature are independently checked. Receipt never resolves current PCR
//! keys for these rows. Legacy/native receipts keep their separate role gates;
//! absence never manufactures a historical signer fact.

use arkret_canonical::DigestSuite;
use arkret_identity::{
    RealmAuthorityChainError, RealmAuthorityKeyDirectory, VerifiedRealmAuthority,
};
use arkret_wire::{CommitStreamRef, DidCoreId, ErrorCode, Event, HumanDeviceProducer, RealmCommit};
use coland_storage::DeviceRevocationStore;

use crate::{ServiceError, ServiceResult};

/// Where the receiver already stands on the Commit's stream.
#[derive(Clone, Copy, Debug)]
pub enum CommitContinuity<'a> {
    /// The receiver holds the stream up to this head; the Commit must be its
    /// direct successor.
    After(&'a RealmCommit),
    /// The receiver holds nothing of the stream; the Commit must open it.
    StreamStart,
    /// Verify the receipt without an unlocked stream-head check. A caller
    /// either receives it outside a held stream (invite delivery), or proves
    /// exact replay/direct succession inside the locked replica transaction.
    Standalone,
}

/// How the producer of an accepted receipt is established.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReceivedProducer {
    /// A Human device on another Station; the complete receipt boundary also
    /// verifies its original frozen key against the governance-bound fact.
    GovernanceCommittedHumanDevice,
    /// A human device of an Account this Station hosts; its producer proof
    /// verifies under the original frozen fact, independently of current PCR.
    HostedHumanDevice(HumanDeviceProducer),
    /// An Applet Service whose original installation and producer key were
    /// verified through the immutable source bound by the governance Commit.
    GovernanceCommittedService,
    /// Not a human Account device (Agent, Service or controller method); the
    /// caller applies that producer's own signer evidence rule.
    OtherSigner,
}

/// Verify one committed Event as a non-governance receiver.
pub fn verify_non_governance_committed_event(
    event: &Event,
    commit: &RealmCommit,
    continuity: CommitContinuity<'_>,
    authority: &VerifiedRealmAuthority,
    keys: &dyn RealmAuthorityKeyDirectory,
    receiver: &DidCoreId,
    digest_suite: DigestSuite,
) -> ServiceResult<ReceivedProducer> {
    event
        .verify_event_id_matches_content_with_digest_suite(digest_suite)
        .map_err(|error| ServiceError::SchemaViolation(error.to_string()))?;
    let producer = event
        .verify_producer_proof_self_consistency(digest_suite)
        .map_err(|error| {
            ServiceError::protocol(
                error.error_code().unwrap_or(ErrorCode::SignatureInvalid),
                error,
            )
        })?;
    verify_commit_binding(event, commit)?;
    authority
        .verify_commit(commit, keys)
        .map_err(governance_commit_refusal)?;
    verify_continuity(commit, continuity)?;
    Ok(match producer {
        Some(producer) if producer.account_id.station_id == *receiver => {
            ReceivedProducer::HostedHumanDevice(producer)
        }
        Some(_) => ReceivedProducer::GovernanceCommittedHumanDevice,
        None => ReceivedProducer::OtherSigner,
    })
}

/// Receipt compatibility entry without an immutable Human fact. Ordinary
/// Human rows remain unavailable here; callers holding the registered fact
/// use `verify_committed_event_receipt_with_fact`.
#[allow(clippy::too_many_arguments)]
pub async fn verify_committed_event_receipt(
    local_pcr: &dyn DeviceRevocationStore,
    event: &Event,
    commit: &RealmCommit,
    continuity: CommitContinuity<'_>,
    authority: &VerifiedRealmAuthority,
    keys: &(dyn RealmAuthorityKeyDirectory + Sync),
    receiver: &DidCoreId,
    digest_suite: DigestSuite,
) -> ServiceResult<ReceivedProducer> {
    verify_committed_event_receipt_with_fact(
        local_pcr,
        event,
        commit,
        continuity,
        authority,
        keys,
        receiver,
        digest_suite,
        None,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn verify_committed_event_receipt_with_fact(
    local_pcr: &dyn DeviceRevocationStore,
    event: &Event,
    commit: &RealmCommit,
    continuity: CommitContinuity<'_>,
    authority: &VerifiedRealmAuthority,
    keys: &(dyn RealmAuthorityKeyDirectory + Sync),
    receiver: &DidCoreId,
    digest_suite: DigestSuite,
    fact: Option<&arkret_models_collaboration::authority_commit::HistoricalProducerSignerFact>,
) -> ServiceResult<ReceivedProducer> {
    verify_committed_event_receipt_with_source(
        local_pcr,
        event,
        commit,
        continuity,
        authority,
        keys,
        receiver,
        digest_suite,
        fact,
    )
    .await
}

/// Verify either registered original producer source. Neither branch resolves
/// a current key or replays hidden authorization history at the receiver.
#[allow(clippy::too_many_arguments)]
pub async fn verify_committed_event_receipt_with_source(
    local_pcr: &dyn DeviceRevocationStore,
    event: &Event,
    commit: &RealmCommit,
    continuity: CommitContinuity<'_>,
    authority: &VerifiedRealmAuthority,
    keys: &(dyn RealmAuthorityKeyDirectory + Sync),
    receiver: &DidCoreId,
    digest_suite: DigestSuite,
    fact: Option<&arkret_models_collaboration::authority_commit::HistoricalProducerSignerFact>,
) -> ServiceResult<ReceivedProducer> {
    let received = verify_non_governance_committed_event(
        event,
        commit,
        continuity,
        authority,
        keys,
        receiver,
        digest_suite,
    )?;
    match (commit.producer_signer_fact_digest.as_ref(), fact) {
        (Some(_), Some(fact)) => {
            arkret_identity::account_device_signer_evidence::verify_historical_producer_committed_event(
                &arkret_wire::CommittedEventFullView { event: event.clone(), commit: commit.clone() },
                fact, authority, keys, digest_suite,
            ).map_err(|e| ServiceError::protocol(ErrorCode::SignatureInvalid, e))?;
            return Ok(if matches!(
                fact,
                arkret_models_collaboration::authority_commit::HistoricalProducerSignerFact::Service(_)
            ) {
                ReceivedProducer::GovernanceCommittedService
            } else {
                received
            });
        }
        (None, None) => {}
        (Some(_), None) => {
            return Err(ServiceError::protocol(
                ErrorCode::TemporarilyUnavailable,
                "original producer signer source is unavailable",
            ));
        }
        _ => {
            return Err(ServiceError::protocol(
                ErrorCode::SignatureInvalid,
                "original producer source and Commit digest must be paired",
            ));
        }
    }
    if received != ReceivedProducer::OtherSigner
        || (event.applet_id.is_some()
            && matches!(event.actual_signer(), arkret_wire::ActorId::Service { .. }))
    {
        return Err(ServiceError::protocol(
            ErrorCode::TemporarilyUnavailable,
            "original ordinary producer signer source is unavailable",
        ));
    }
    // Native PCR audit does not enter this ordinary Full receipt boundary.
    let _ = local_pcr;
    Ok(received)
}

fn verify_commit_binding(event: &Event, commit: &RealmCommit) -> ServiceResult<()> {
    let stream_ref = CommitStreamRef::from_scope(&event.scope_ref, Some(event.realm_id.clone()))
        .map_err(|error| ServiceError::SchemaViolation(error.to_string()))?;
    if commit.event_ref != event.event_id
        || commit.realm_id != event.realm_id
        || commit.stream_ref != stream_ref
    {
        return Err(ServiceError::protocol(
            ErrorCode::SignatureInvalid,
            "RealmCommit does not bind the exact committed Event",
        ));
    }
    Ok(())
}

/// The SDK maps an invalid signature and a signer that is not the governance
/// Station of the Commit's generation to `signature_invalid`. Of the variants
/// it leaves to the caller, a key this Station could not resolve is retryable
/// and a Commit that is not well formed is `schema_violation`.
fn governance_commit_refusal(error: RealmAuthorityChainError) -> ServiceError {
    let code = error.error_code().unwrap_or(match error {
        RealmAuthorityChainError::MaterialIncomplete(_) | RealmAuthorityChainError::NotFresh(_) => {
            ErrorCode::TemporarilyUnavailable
        }
        _ => ErrorCode::SchemaViolation,
    });
    ServiceError::protocol(code, format!("governance RealmCommit: {error}"))
}

fn verify_continuity(commit: &RealmCommit, continuity: CommitContinuity<'_>) -> ServiceResult<()> {
    let discontinuous =
        |detail: &str| ServiceError::protocol(ErrorCode::FailedPrecondition, detail);
    match continuity {
        CommitContinuity::Standalone => Ok(()),
        CommitContinuity::StreamStart => {
            if commit.stream_position != 0 || commit.previous_commit_ref.is_some() {
                return Err(ServiceError::protocol(
                    ErrorCode::DependencyMissing,
                    "RealmCommit predecessors on its stream are not held",
                ));
            }
            Ok(())
        }
        CommitContinuity::After(head) => {
            if head.stream_ref != commit.stream_ref {
                return Err(discontinuous(
                    "RealmCommit predecessor is on another stream",
                ));
            }
            if commit.stream_position > head.stream_position.saturating_add(1) {
                return Err(ServiceError::protocol(
                    ErrorCode::DependencyMissing,
                    "RealmCommit predecessors between the held head and it are not held",
                ));
            }
            commit
                .validate_successor_of(head)
                .map_err(|error| discontinuous(&error.to_string()))
        }
    }
}
