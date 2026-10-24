use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use arkret_models_identity::{
    OrganizationControlProof, OrganizationControlProofKind, OrganizationHandleAttestationStatus,
    OrganizationRegistrationChallenge, OrganizationRegistrationChallengeRequestBody,
    OrganizationRegistrationEnsureRequestBody, OrganizationRegistrationReceipt,
    OrganizationRegistrationRefreshRequestBody, OrganizationRegistrationResponseBody,
    OrganizationRegistrationRevokeReason, OrganizationRegistrationRevokeRequestBody,
    OrganizationRegistrationStatus, next_organization_registration_generation,
};
use arkret_signatures::{Ed25519DetachedJwsVerifier, PublicKeyMaterial};
use arkret_wire::{Did, DidCoreId, DidUrl, Hash, PayloadProof, ProofContextId, TrustDomainId};
use chrono::{DateTime, Duration, Utc};
use coland_storage::{
    OrganizationRegistrationCurrent, OrganizationRegistrationEnsureCommit,
    OrganizationRegistrationLifecycleCommit, OrganizationRegistrationRefreshCommit,
    OrganizationRegistrationStore, OrganizationRegistrationTerminalReason, PersistenceError,
    PersistenceStore,
};
use serde_json::{Map, Value, json};

use crate::identity::{DidService, PinnedDidDocumentState, PinnedDidVersionStatus};

const CHALLENGE_LIFETIME: Duration = Duration::seconds(300);
const RECEIPT_LIFETIME: Duration = Duration::days(90);
const GOVERNANCE_PROFILE: &str = "ak.organization.governance.v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OrganizationRegistrationErrorCode {
    SchemaViolation,
    DidNotFound,
    ChallengeInvalid,
    ControlProofInvalid,
    QuorumNotMet,
    ScopeUnsupported,
    Revoked,
    Stale,
    Internal,
}

#[derive(Debug, thiserror::Error)]
#[error("{code:?}: {detail}")]
pub struct OrganizationRegistrationError {
    pub code: OrganizationRegistrationErrorCode,
    pub detail: String,
}

impl OrganizationRegistrationError {
    fn new(code: OrganizationRegistrationErrorCode, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
        }
    }

    fn challenge(detail: impl Into<String>) -> Self {
        Self::new(OrganizationRegistrationErrorCode::ChallengeInvalid, detail)
    }

    fn proof(detail: impl Into<String>) -> Self {
        Self::new(
            OrganizationRegistrationErrorCode::ControlProofInvalid,
            detail,
        )
    }
}

pub trait OrganizationRegistrationReceiptSigner: Send + Sync {
    fn issuer_id(&self) -> &DidCoreId;
    /// `did-usage-and-verification.md` §2.2 / §6: a receipt-signing key is a
    /// concrete verification method, so the identifier is a typed DID URL and
    /// a DID without a verification-method fragment cannot be handed in.
    fn verification_method(&self) -> &DidUrl;
    fn sign_detached_jws(&self, signing_bytes: &[u8]) -> Result<String, String>;
}

#[async_trait::async_trait]
pub trait OrganizationDidResolutionPort: Send + Sync {
    async fn resolve_current_webvh_state(
        &self,
        did: &Did,
    ) -> Result<PinnedDidDocumentState, String>;

    async fn resolve_pinned_webvh_state(
        &self,
        did: &Did,
        version_id: &str,
        log_head_digest: &Hash,
    ) -> Result<PinnedDidDocumentState, String>;
}

#[async_trait::async_trait]
impl OrganizationDidResolutionPort for DidService {
    async fn resolve_current_webvh_state(
        &self,
        did: &Did,
    ) -> Result<PinnedDidDocumentState, String> {
        DidService::resolve_current_webvh_state(self, did)
            .await
            .map_err(|error| error.to_string())
    }

    async fn resolve_pinned_webvh_state(
        &self,
        did: &Did,
        version_id: &str,
        log_head_digest: &Hash,
    ) -> Result<PinnedDidDocumentState, String> {
        DidService::resolve_pinned_webvh_state(self, did, version_id, log_head_digest)
            .await
            .map_err(|error| error.to_string())
    }
}

#[derive(Clone)]
pub struct OrganizationRegistrationService {
    persistence: Arc<dyn PersistenceStore>,
    resolver: Arc<dyn OrganizationDidResolutionPort>,
}

impl OrganizationRegistrationService {
    pub fn new(persistence: Arc<dyn PersistenceStore>, dids: DidService) -> Self {
        Self::with_resolver(persistence, Arc::new(dids))
    }

    #[doc(hidden)]
    pub fn with_resolver(
        persistence: Arc<dyn PersistenceStore>,
        resolver: Arc<dyn OrganizationDidResolutionPort>,
    ) -> Self {
        Self {
            persistence,
            resolver,
        }
    }

    fn store(&self) -> &dyn OrganizationRegistrationStore {
        self.persistence.organization_registrations()
    }

    pub async fn prepare(
        &self,
        request: OrganizationRegistrationChallengeRequestBody,
        origin: &str,
        trust_domain: &str,
        issuer_id: &DidCoreId,
        now: DateTime<Utc>,
    ) -> Result<OrganizationRegistrationChallenge, OrganizationRegistrationError> {
        request
            .validate()
            .map_err(|error| schema(error.to_string()))?;
        let trust_domain = TrustDomainId::new(trust_domain)
            .map_err(|error| schema(format!("invalid trust_domain: {error}")))?;
        let origin = arkret_wire::WebOrigin::new(origin)
            .map_err(|error| schema(format!("invalid origin: {error}")))?;
        let pinned = self
            .resolver
            .resolve_current_webvh_state(&request.organization_did)
            .await
            .map_err(|error| OrganizationRegistrationError::proof(error.to_string()))?;
        if pinned.status == PinnedDidVersionStatus::Deactivated {
            return Err(OrganizationRegistrationError::proof(
                "organization DID is deactivated",
            ));
        }

        let created_at = canonical_time(now);
        let nonce_bytes = uuid::Uuid::now_v7();
        let nonce = arkret_canonical::base64url_encode(nonce_bytes.as_bytes());
        let challenge_digest = arkret_canonical::canonical_sha256(&json!({
            "organization_id": &request.organization_id,
            "organization_did": &request.organization_did,
            "local_admin_subject_id": &request.local_admin_subject_id,
            "requested_scopes": &request.requested_scopes,
            "nonce": &nonce,
            "created_at": created_at,
        }))
        .map_err(|error| internal(error.to_string()))?;
        let challenge = OrganizationRegistrationChallenge {
            challenge_id: format!(
                "ak:organization_registration_challenge:{}",
                challenge_digest
                    .strip_prefix("sha256:")
                    .unwrap_or(&challenge_digest)
            ),
            organization_id: request.organization_id,
            organization_did: request.organization_did,
            purpose: ProofContextId::ORGANIZATION_REGISTRATION_CONTROL_PROOF_V1.to_owned(),
            nonce,
            audience_id: issuer_id.clone(),
            origin,
            trust_domain,
            local_admin_subject_id: request.local_admin_subject_id,
            requested_scopes: request.requested_scopes,
            expires_at: created_at + CHALLENGE_LIFETIME,
            created_at,
        };
        challenge
            .validate_for_at(
                &OrganizationRegistrationChallengeRequestBody {
                    organization_id: challenge.organization_id.clone(),
                    organization_did: challenge.organization_did.clone(),
                    local_admin_subject_id: challenge.local_admin_subject_id.clone(),
                    requested_scopes: challenge.requested_scopes.clone(),
                },
                created_at,
            )
            .map_err(|error| OrganizationRegistrationError::challenge(error.to_string()))?;
        self.store()
            .prepare_challenge(challenge.clone())
            .await
            .map_err(map_storage)?;
        Ok(challenge)
    }

    pub async fn ensure(
        &self,
        request: OrganizationRegistrationEnsureRequestBody,
        signer: &dyn OrganizationRegistrationReceiptSigner,
        now: DateTime<Utc>,
    ) -> Result<OrganizationRegistrationResponseBody, OrganizationRegistrationError> {
        validate_handle_attestation(&request, now)?;
        let request_digest = request
            .canonical_request_digest()
            .map_err(|error| schema(error.to_string()))?;
        if let Some(replay) = self
            .challenge_replay(&request.challenge_id, &request_digest, now)
            .await?
        {
            let pinned = self
                .resolver
                .resolve_pinned_webvh_state(
                    &request.organization_did,
                    &request.version_id,
                    &request.log_head_digest,
                )
                .await
                .map_err(|error| OrganizationRegistrationError::proof(error.to_string()))?;
            let current = self
                .store()
                .get_current(&request.organization_id)
                .await
                .map_err(map_storage)?;
            validate_replay_current(&replay, current.as_ref())?;
            self.require_current_authority(&pinned, current.as_ref(), signer, now, true)
                .await?;
            return Ok(replay);
        }
        let challenge = self
            .store()
            .get_challenge(&request.challenge_id)
            .await
            .map_err(map_storage)?
            .ok_or_else(|| OrganizationRegistrationError::challenge("challenge not found"))?;
        validate_ensure_challenge_binding(&request, &challenge.challenge, now)?;

        let pinned = self
            .resolver
            .resolve_pinned_webvh_state(
                &request.organization_did,
                &request.version_id,
                &request.log_head_digest,
            )
            .await
            .map_err(|error| OrganizationRegistrationError::proof(error.to_string()))?;
        let current = self
            .store()
            .get_current(&request.organization_id)
            .await
            .map_err(map_storage)?;
        self.require_ensure_current_state(&request, current.as_ref(), now)
            .await?;
        self.require_current_authority(&pinned, current.as_ref(), signer, now, true)
            .await?;
        let control_key_digest = verify_control_proof(&request.control_proof, &request, &pinned)?;

        let expected_generation = current
            .as_ref()
            .map(|current| current.generation.registration_generation);
        let needs_new_generation = current.as_ref().is_none_or(|current| {
            current.generation.status != OrganizationRegistrationStatus::Active
                || current.generation.local_admin_subject_id != request.local_admin_subject_id
                || current.generation.delegated_scopes != request.requested_scopes
        });
        let new_outcome = if needs_new_generation {
            let generation = next_organization_registration_generation(expected_generation)
                .map_err(|error| internal(error.to_string()))?;
            Some(sign_outcome(
                signer,
                &request.organization_id,
                &request.organization_did,
                generation,
                &request.version_id,
                &request.log_head_digest,
                request.control_proof.proof_kind,
                &control_key_digest,
                &request.local_admin_subject_id,
                &request.requested_scopes,
                OrganizationRegistrationStatus::Active,
                now,
                true,
            )?)
        } else {
            None
        };
        self.store()
            .ensure(OrganizationRegistrationEnsureCommit {
                challenge_id: request.challenge_id,
                canonical_request_digest: request_digest,
                expected_current_generation: expected_generation,
                new_outcome,
                committed_at: canonical_time(now),
            })
            .await
            .map_err(map_storage)
    }

    pub async fn current(
        &self,
        organization_id: &DidCoreId,
    ) -> Result<Option<OrganizationRegistrationCurrent>, OrganizationRegistrationError> {
        self.store()
            .get_current(organization_id)
            .await
            .map_err(map_storage)
    }

    pub async fn refresh(
        &self,
        request: OrganizationRegistrationRefreshRequestBody,
        current: &OrganizationRegistrationCurrent,
        signer: &dyn OrganizationRegistrationReceiptSigner,
        now: DateTime<Utc>,
    ) -> Result<OrganizationRegistrationResponseBody, OrganizationRegistrationError> {
        validate_refresh_request(&request)?;
        let request_digest = request
            .canonical_request_digest()
            .map_err(|error| schema(error.to_string()))?;
        if let Some(replay) = self
            .challenge_replay(&request.challenge_id, &request_digest, now)
            .await?
        {
            let pinned = self
                .resolver
                .resolve_pinned_webvh_state(
                    &request.organization_did,
                    &request.version_id,
                    &request.log_head_digest,
                )
                .await
                .map_err(|error| OrganizationRegistrationError::proof(error.to_string()))?;
            validate_replay_current(&replay, Some(current))?;
            self.require_current_authority(&pinned, Some(current), signer, now, false)
                .await?;
            return Ok(replay);
        }
        if current.generation.organization_id != request.organization_id {
            return Err(not_found("authorized organization registration differs"));
        }
        if current.generation.status == OrganizationRegistrationStatus::Revoked {
            return Err(OrganizationRegistrationError::new(
                OrganizationRegistrationErrorCode::Revoked,
                "organization registration is revoked",
            ));
        }
        let challenge = self
            .store()
            .get_challenge(&request.challenge_id)
            .await
            .map_err(map_storage)?
            .ok_or_else(|| OrganizationRegistrationError::challenge("challenge not found"))?;
        validate_refresh_challenge_binding(&request, &challenge.challenge, current, now)?;
        let pinned = self
            .resolver
            .resolve_pinned_webvh_state(
                &request.organization_did,
                &request.version_id,
                &request.log_head_digest,
            )
            .await
            .map_err(|error| OrganizationRegistrationError::proof(error.to_string()))?;
        self.require_current_authority(&pinned, Some(current), signer, now, false)
            .await?;
        let control_key_digest =
            verify_refresh_control_proof(&request.control_proof, &request, current, &pinned)?;
        let outcome = sign_outcome(
            signer,
            &request.organization_id,
            &request.organization_did,
            current.generation.registration_generation,
            &request.version_id,
            &request.log_head_digest,
            request.control_proof.proof_kind,
            &control_key_digest,
            &current.generation.local_admin_subject_id,
            &current.generation.delegated_scopes,
            OrganizationRegistrationStatus::Active,
            now,
            false,
        )?;
        self.store()
            .refresh(OrganizationRegistrationRefreshCommit {
                challenge_id: request.challenge_id,
                canonical_request_digest: request_digest,
                expected_current_generation: current.generation.registration_generation,
                expected_current_outcome_id: current.generation.current_outcome_id.clone(),
                outcome,
                committed_at: canonical_time(now),
            })
            .await
            .map_err(map_storage)
    }

    pub async fn revoke(
        &self,
        request: OrganizationRegistrationRevokeRequestBody,
        current: &OrganizationRegistrationCurrent,
        signer: &dyn OrganizationRegistrationReceiptSigner,
        now: DateTime<Utc>,
    ) -> Result<OrganizationRegistrationResponseBody, OrganizationRegistrationError> {
        if current.generation.organization_id != request.organization_id {
            return Err(not_found("authorized organization registration differs"));
        }
        if current.generation.status == OrganizationRegistrationStatus::Revoked {
            let mut outcome = current.outcome.clone();
            outcome.created = false;
            return Ok(outcome);
        }
        let receipt = &current.outcome.registration_receipt;
        let outcome = sign_outcome(
            signer,
            &request.organization_id,
            &current.generation.organization_did,
            current.generation.registration_generation,
            &receipt.version_id,
            &receipt.log_head_digest,
            receipt.control_proof_kind,
            &receipt.control_key_digest,
            &current.generation.local_admin_subject_id,
            &current.generation.delegated_scopes,
            OrganizationRegistrationStatus::Revoked,
            now,
            false,
        )?;
        let reason = match request
            .reason_code
            .unwrap_or(OrganizationRegistrationRevokeReason::OrganizationRegistrationWithdrawn)
        {
            OrganizationRegistrationRevokeReason::OrganizationRegistrationSuperseded => {
                OrganizationRegistrationTerminalReason::OrganizationRegistrationSuperseded
            }
            OrganizationRegistrationRevokeReason::OrganizationRegistrationWithdrawn => {
                OrganizationRegistrationTerminalReason::OrganizationRegistrationWithdrawn
            }
        };
        self.store()
            .revoke(OrganizationRegistrationLifecycleCommit {
                organization_id: request.organization_id,
                expected_current_generation: current.generation.registration_generation,
                expected_current_outcome_id: current.generation.current_outcome_id.clone(),
                outcome,
                reason,
                committed_at: canonical_time(now),
            })
            .await
            .map_err(map_storage)
    }

    async fn challenge_replay(
        &self,
        challenge_id: &str,
        request_digest: &Hash,
        now: DateTime<Utc>,
    ) -> Result<Option<OrganizationRegistrationResponseBody>, OrganizationRegistrationError> {
        let Some(record) = self
            .store()
            .get_challenge(challenge_id)
            .await
            .map_err(map_storage)?
        else {
            return Ok(None);
        };
        let Some(committed_digest) = record.consumed_request_digest else {
            return Ok(None);
        };
        if &committed_digest != request_digest {
            return Err(OrganizationRegistrationError::challenge(
                "challenge was consumed by another request",
            ));
        }
        let outcome_id = record.consumed_outcome_id.ok_or_else(|| {
            internal("consumed challenge is missing its immutable outcome reference")
        })?;
        let mut outcome = self
            .store()
            .get_outcome(&outcome_id)
            .await
            .map_err(map_storage)?
            .ok_or_else(|| internal("consumed challenge outcome is missing"))?;
        let current = self
            .store()
            .get_current(&outcome.registration_receipt.organization_id)
            .await
            .map_err(map_storage)?
            .ok_or_else(|| {
                OrganizationRegistrationError::challenge(
                    "consumed challenge no longer belongs to the current generation",
                )
            })?;
        if current.generation.registration_generation
            != outcome.registration_receipt.registration_generation
            || current.generation.current_outcome_id
                != outcome.registration_receipt.registration_receipt_id
        {
            return Err(OrganizationRegistrationError::challenge(
                "consumed challenge no longer belongs to the current generation",
            ));
        }
        match current.generation.status {
            OrganizationRegistrationStatus::Revoked => {
                return Err(OrganizationRegistrationError::new(
                    OrganizationRegistrationErrorCode::Revoked,
                    "organization registration is revoked",
                ));
            }
            OrganizationRegistrationStatus::Stale => {
                return Err(OrganizationRegistrationError::new(
                    OrganizationRegistrationErrorCode::Stale,
                    "organization registration is stale",
                ));
            }
            OrganizationRegistrationStatus::Active
                if current.outcome.registration_receipt.expires_at <= now =>
            {
                self.store()
                    .mark_stale(
                        &current.generation.organization_id,
                        current.generation.registration_generation,
                        &current.generation.current_outcome_id,
                        canonical_time(now),
                    )
                    .await
                    .map_err(map_storage)?;
                return Err(OrganizationRegistrationError::new(
                    OrganizationRegistrationErrorCode::Stale,
                    "organization registration receipt is expired",
                ));
            }
            OrganizationRegistrationStatus::Active => {}
        }
        outcome.created = false;
        Ok(Some(outcome))
    }

    async fn require_current_authority(
        &self,
        pinned: &PinnedDidDocumentState,
        current: Option<&OrganizationRegistrationCurrent>,
        signer: &dyn OrganizationRegistrationReceiptSigner,
        now: DateTime<Utc>,
        reject_expired_receipt: bool,
    ) -> Result<(), OrganizationRegistrationError> {
        if reject_expired_receipt
            && let Some(current) = current
            && current.generation.status == OrganizationRegistrationStatus::Active
            && current.outcome.registration_receipt.expires_at <= now
        {
            self.store()
                .mark_stale(
                    &current.generation.organization_id,
                    current.generation.registration_generation,
                    &current.generation.current_outcome_id,
                    canonical_time(now),
                )
                .await
                .map_err(map_storage)?;
            return Err(OrganizationRegistrationError::new(
                OrganizationRegistrationErrorCode::Stale,
                "organization registration receipt is expired",
            ));
        }
        match pinned.status {
            PinnedDidVersionStatus::Current => Ok(()),
            PinnedDidVersionStatus::Rotated => {
                if let Some(current) = current
                    && current.generation.status == OrganizationRegistrationStatus::Active
                {
                    self.store()
                        .mark_stale(
                            &current.generation.organization_id,
                            current.generation.registration_generation,
                            &current.generation.current_outcome_id,
                            canonical_time(now),
                        )
                        .await
                        .map_err(map_storage)?;
                }
                Err(OrganizationRegistrationError::new(
                    OrganizationRegistrationErrorCode::Stale,
                    "pinned organization DID version is no longer current",
                ))
            }
            PinnedDidVersionStatus::Deactivated => {
                if let Some(current) = current
                    && current.generation.status != OrganizationRegistrationStatus::Revoked
                {
                    let receipt = &current.outcome.registration_receipt;
                    let outcome = sign_outcome(
                        signer,
                        &current.generation.organization_id,
                        &current.generation.organization_did,
                        current.generation.registration_generation,
                        &receipt.version_id,
                        &receipt.log_head_digest,
                        receipt.control_proof_kind,
                        &receipt.control_key_digest,
                        &current.generation.local_admin_subject_id,
                        &current.generation.delegated_scopes,
                        OrganizationRegistrationStatus::Revoked,
                        now,
                        false,
                    )?;
                    self.store()
                        .deactivate(OrganizationRegistrationLifecycleCommit {
                            organization_id: current.generation.organization_id.clone(),
                            expected_current_generation: current.generation.registration_generation,
                            expected_current_outcome_id: current
                                .generation
                                .current_outcome_id
                                .clone(),
                            outcome,
                            reason: OrganizationRegistrationTerminalReason::ExternalDidDeactivated,
                            committed_at: canonical_time(now),
                        })
                        .await
                        .map_err(map_storage)?;
                }
                Err(OrganizationRegistrationError::new(
                    OrganizationRegistrationErrorCode::Revoked,
                    "organization DID is deactivated",
                ))
            }
        }
    }

    async fn require_ensure_current_state(
        &self,
        request: &OrganizationRegistrationEnsureRequestBody,
        current: Option<&OrganizationRegistrationCurrent>,
        now: DateTime<Utc>,
    ) -> Result<(), OrganizationRegistrationError> {
        let Some(current) = current else {
            return Ok(());
        };
        if current.generation.status == OrganizationRegistrationStatus::Stale {
            return Err(OrganizationRegistrationError::new(
                OrganizationRegistrationErrorCode::Stale,
                "organization registration must be refreshed before ensure",
            ));
        }
        let receipt = &current.outcome.registration_receipt;
        if current.generation.status == OrganizationRegistrationStatus::Active
            && (receipt.version_id != request.version_id
                || receipt.log_head_digest != request.log_head_digest)
        {
            self.store()
                .mark_stale(
                    &current.generation.organization_id,
                    current.generation.registration_generation,
                    &current.generation.current_outcome_id,
                    canonical_time(now),
                )
                .await
                .map_err(map_storage)?;
            return Err(OrganizationRegistrationError::new(
                OrganizationRegistrationErrorCode::Stale,
                "organization registration DID head changed and must be refreshed",
            ));
        }
        Ok(())
    }
}

fn verify_control_proof(
    proof: &OrganizationControlProof,
    request: &OrganizationRegistrationEnsureRequestBody,
    pinned: &PinnedDidDocumentState,
) -> Result<Hash, OrganizationRegistrationError> {
    verify_control_proof_inner(
        proof,
        ControlProofVerificationContext {
            challenge_id: &request.challenge_id,
            organization_id: &request.organization_id,
            organization_did: &request.organization_did,
            local_admin_subject_id: &request.local_admin_subject_id,
            version_id: &request.version_id,
            log_head_digest: &request.log_head_digest,
            pinned,
        },
    )
}

fn validate_replay_current(
    replay: &OrganizationRegistrationResponseBody,
    current: Option<&OrganizationRegistrationCurrent>,
) -> Result<(), OrganizationRegistrationError> {
    let Some(current) = current else {
        return Err(OrganizationRegistrationError::challenge(
            "consumed challenge no longer belongs to the current generation",
        ));
    };
    if current.generation.registration_generation
        != replay.registration_receipt.registration_generation
        || current.generation.current_outcome_id
            != replay.registration_receipt.registration_receipt_id
    {
        return Err(OrganizationRegistrationError::challenge(
            "consumed challenge no longer belongs to the current generation",
        ));
    }
    match current.generation.status {
        OrganizationRegistrationStatus::Active => Ok(()),
        OrganizationRegistrationStatus::Stale => Err(OrganizationRegistrationError::new(
            OrganizationRegistrationErrorCode::Stale,
            "organization registration is stale",
        )),
        OrganizationRegistrationStatus::Revoked => Err(OrganizationRegistrationError::new(
            OrganizationRegistrationErrorCode::Revoked,
            "organization registration is revoked",
        )),
    }
}

fn verify_refresh_control_proof(
    proof: &OrganizationControlProof,
    request: &OrganizationRegistrationRefreshRequestBody,
    current: &OrganizationRegistrationCurrent,
    pinned: &PinnedDidDocumentState,
) -> Result<Hash, OrganizationRegistrationError> {
    verify_control_proof_inner(
        proof,
        ControlProofVerificationContext {
            challenge_id: &request.challenge_id,
            organization_id: &request.organization_id,
            organization_did: &request.organization_did,
            local_admin_subject_id: &current.generation.local_admin_subject_id,
            version_id: &request.version_id,
            log_head_digest: &request.log_head_digest,
            pinned,
        },
    )
}

fn validate_ensure_challenge_binding(
    request: &OrganizationRegistrationEnsureRequestBody,
    challenge: &OrganizationRegistrationChallenge,
    now: DateTime<Utc>,
) -> Result<(), OrganizationRegistrationError> {
    let challenge_request = OrganizationRegistrationChallengeRequestBody {
        organization_id: request.organization_id.clone(),
        organization_did: request.organization_did.clone(),
        local_admin_subject_id: request.local_admin_subject_id.clone(),
        requested_scopes: request.requested_scopes.clone(),
    };
    challenge
        .validate_for_at(&challenge_request, now)
        .map_err(|error| OrganizationRegistrationError::challenge(error.to_string()))?;
    if request.challenge_id != challenge.challenge_id {
        return Err(OrganizationRegistrationError::challenge(
            "organization registration ensure challenge_id mismatch",
        ));
    }
    validate_control_proof_challenge_binding(
        &request.control_proof,
        &request.challenge_id,
        &request.organization_id,
        &request.organization_did,
        &request.local_admin_subject_id,
        &request.version_id,
        &request.log_head_digest,
        challenge,
    )
}

fn validate_refresh_challenge_binding(
    request: &OrganizationRegistrationRefreshRequestBody,
    challenge: &OrganizationRegistrationChallenge,
    current: &OrganizationRegistrationCurrent,
    now: DateTime<Utc>,
) -> Result<(), OrganizationRegistrationError> {
    let challenge_request = OrganizationRegistrationChallengeRequestBody {
        organization_id: request.organization_id.clone(),
        organization_did: request.organization_did.clone(),
        local_admin_subject_id: current.generation.local_admin_subject_id.clone(),
        requested_scopes: current.generation.delegated_scopes.clone(),
    };
    challenge
        .validate_for_at(&challenge_request, now)
        .map_err(|error| OrganizationRegistrationError::challenge(error.to_string()))?;
    if request.challenge_id != challenge.challenge_id {
        return Err(OrganizationRegistrationError::challenge(
            "organization registration refresh challenge_id mismatch",
        ));
    }
    validate_control_proof_challenge_binding(
        &request.control_proof,
        &request.challenge_id,
        &request.organization_id,
        &request.organization_did,
        &current.generation.local_admin_subject_id,
        &request.version_id,
        &request.log_head_digest,
        challenge,
    )
}

#[allow(clippy::too_many_arguments)]
fn validate_control_proof_challenge_binding(
    proof: &OrganizationControlProof,
    challenge_id: &str,
    organization_id: &DidCoreId,
    organization_did: &Did,
    local_admin_subject_id: &DidCoreId,
    version_id: &str,
    log_head_digest: &Hash,
    challenge: &OrganizationRegistrationChallenge,
) -> Result<(), OrganizationRegistrationError> {
    proof
        .validate_transcript_bindings(
            challenge_id,
            organization_id,
            organization_did,
            local_admin_subject_id,
            version_id,
            log_head_digest,
        )
        .map_err(|error| control_proof_error(proof.proof_kind, error.to_string()))?;
    if proof.proofs.iter().any(|proof| {
        proof.created_at < challenge.created_at || proof.created_at >= challenge.expires_at
    }) {
        return Err(OrganizationRegistrationError::challenge(
            "organization control proof was not created during the challenge lifetime",
        ));
    }
    Ok(())
}

fn control_proof_error(
    proof_kind: OrganizationControlProofKind,
    detail: impl Into<String>,
) -> OrganizationRegistrationError {
    let code = match proof_kind {
        OrganizationControlProofKind::ResolvedVerificationMethod => {
            OrganizationRegistrationErrorCode::ControlProofInvalid
        }
        OrganizationControlProofKind::GovernanceQuorum => {
            OrganizationRegistrationErrorCode::QuorumNotMet
        }
    };
    OrganizationRegistrationError::new(code, detail)
}

struct ControlProofVerificationContext<'a> {
    challenge_id: &'a str,
    organization_id: &'a DidCoreId,
    organization_did: &'a Did,
    local_admin_subject_id: &'a DidCoreId,
    version_id: &'a str,
    log_head_digest: &'a Hash,
    pinned: &'a PinnedDidDocumentState,
}

fn verify_control_proof_inner(
    proof: &OrganizationControlProof,
    context: ControlProofVerificationContext<'_>,
) -> Result<Hash, OrganizationRegistrationError> {
    let ControlProofVerificationContext {
        challenge_id,
        organization_id,
        organization_did,
        local_admin_subject_id,
        version_id,
        log_head_digest,
        pinned,
    } = context;
    if proof.proof_kind == OrganizationControlProofKind::GovernanceQuorum
        && proof
            .quorum_threshold
            .is_some_and(|threshold| proof.proofs.len() < threshold as usize)
    {
        return Err(OrganizationRegistrationError::new(
            OrganizationRegistrationErrorCode::QuorumNotMet,
            "governance proof count is below quorum_threshold",
        ));
    }
    proof
        .validate_transcript_bindings(
            challenge_id,
            organization_id,
            organization_did,
            local_admin_subject_id,
            version_id,
            log_head_digest,
        )
        .map_err(|error| control_proof_error(proof.proof_kind, error.to_string()))?;

    let document = pinned.document.as_object().ok_or_else(|| {
        OrganizationRegistrationError::proof("pinned DID document is not an object")
    })?;
    let methods = verification_methods(document, organization_did)?;
    let authorized = match proof.proof_kind {
        OrganizationControlProofKind::ResolvedVerificationMethod => {
            resolved_control_methods(document, pinned, organization_did)?
        }
        OrganizationControlProofKind::GovernanceQuorum => {
            governance_control_methods(document, proof.quorum_threshold)?
        }
    };

    for item in &proof.proofs {
        if !authorized.contains(item.verification_method.as_str()) {
            return Err(control_proof_error(
                proof.proof_kind,
                format!(
                    "verification method {} is not authorized by the pinned control relationship",
                    item.verification_method
                ),
            ));
        }
        let material = methods
            .get(item.verification_method.as_str())
            .cloned()
            .or_else(|| update_key_material(pinned, item.verification_method.as_str()))
            .ok_or_else(|| {
                control_proof_error(
                    proof.proof_kind,
                    format!(
                        "verification method {} is absent from the pinned DID state",
                        item.verification_method
                    ),
                )
            })?;
        let transcript = control_transcript_bytes(
            challenge_id,
            organization_id,
            organization_did,
            local_admin_subject_id,
            version_id,
            log_head_digest,
            item,
        )?;
        Ed25519DetachedJwsVerifier::new()
            .verify_detached_jws(&item.jws, &transcript, &material)
            .map_err(|error| control_proof_error(proof.proof_kind, error.to_string()))?;
    }

    match proof.proof_kind {
        OrganizationControlProofKind::ResolvedVerificationMethod => {
            let method = proof.proofs[0].verification_method.as_str();
            let material = methods
                .get(method)
                .cloned()
                .or_else(|| update_key_material(pinned, method))
                .ok_or_else(|| {
                    OrganizationRegistrationError::proof(
                        "resolved control key material is unavailable",
                    )
                })?;
            let bytes = canonical_public_key_bytes(&material)?;
            Hash::new(arkret_canonical::sha256_digest(&bytes))
                .map_err(|error| internal(error.to_string()))
        }
        OrganizationControlProofKind::GovernanceQuorum => {
            let governance = governance_policy(document)?;
            let threshold = governance
                .get("threshold")
                .and_then(Value::as_object)
                .ok_or_else(|| {
                    OrganizationRegistrationError::proof(
                        "organization governance threshold is missing",
                    )
                })?;
            let required = threshold
                .get("required")
                .and_then(Value::as_u64)
                .ok_or_else(|| {
                    OrganizationRegistrationError::proof(
                        "organization governance threshold.required is invalid",
                    )
                })?;
            let mut eligible = threshold
                .get("eligible_methods")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .map(ToOwned::to_owned)
                .collect::<Vec<_>>();
            eligible.sort();
            eligible.dedup();
            Hash::new(
                arkret_canonical::canonical_sha256(&json!({
                    "profile": GOVERNANCE_PROFILE,
                    "threshold": {
                        "required": required,
                        "eligible_methods": eligible,
                    }
                }))
                .map_err(|error| internal(error.to_string()))?,
            )
            .map_err(|error| internal(error.to_string()))
        }
    }
}

fn resolved_control_methods(
    document: &Map<String, Value>,
    pinned: &PinnedDidDocumentState,
    did: &Did,
) -> Result<BTreeSet<String>, OrganizationRegistrationError> {
    let mut methods = BTreeSet::new();
    for relationship in ["authentication", "assertionMethod", "capabilityInvocation"] {
        methods.extend(relationship_methods(document, relationship));
    }
    for update_key in &pinned.update_keys {
        methods.insert(format!("did:key:{update_key}#{update_key}"));
    }
    // `did-usage-and-verification.md` §2.2 — every control method is a DID URL
    // with a `#fragment`. Two roots are legitimate here:
    //
    // * `{organization_id}#…` — a verification method the organization DID document itself
    //   declares; and
    // * `did:key:…#…` — the self-describing `updateKeys` synthesised just above from
    //   `pinned.update_keys`, which is how did:webvh expresses its own update authority.
    //
    // The second disjunct used to be a bare `starts_with("did:key:")`, which
    // also retained an arbitrary (including fragment-less) `did:key:` value
    // that merely appeared in the document's `authentication` /
    // `assertionMethod` arrays. Parsing through `DidUrl` removes the bare form
    // from the value domain, so only fragment-carrying methods survive.
    methods.retain(|method| {
        let Ok(method_url) = DidUrl::new(method.clone()) else {
            return false;
        };
        let root = method_url
            .as_str()
            .split_once('#')
            .map(|(did, _)| did)
            .expect("DidUrl always carries a fragment");
        root == did.as_str() || root.starts_with("did:key:")
    });
    if methods.is_empty() {
        return Err(OrganizationRegistrationError::proof(
            "pinned DID state has no control relationship",
        ));
    }
    Ok(methods)
}

fn governance_control_methods(
    document: &Map<String, Value>,
    declared_threshold: Option<u64>,
) -> Result<BTreeSet<String>, OrganizationRegistrationError> {
    let governance = governance_policy(document)?;
    let threshold = governance
        .get("threshold")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            OrganizationRegistrationError::proof("organization governance threshold is missing")
        })?;
    let required = threshold
        .get("required")
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            OrganizationRegistrationError::proof(
                "organization governance threshold.required is invalid",
            )
        })?;
    if declared_threshold != Some(required) {
        return Err(OrganizationRegistrationError::new(
            OrganizationRegistrationErrorCode::QuorumNotMet,
            "declared quorum_threshold does not match the pinned governance policy",
        ));
    }
    let eligible = threshold
        .get("eligible_methods")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            OrganizationRegistrationError::proof(
                "organization governance eligible_methods is missing",
            )
        })?
        .iter()
        .map(|value| {
            value.as_str().map(ToOwned::to_owned).ok_or_else(|| {
                OrganizationRegistrationError::proof(
                    "organization governance eligible method is invalid",
                )
            })
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    if eligible.len() < required as usize {
        return Err(OrganizationRegistrationError::new(
            OrganizationRegistrationErrorCode::QuorumNotMet,
            "pinned governance key set is smaller than its required threshold",
        ));
    }
    Ok(eligible)
}

fn governance_policy(
    document: &Map<String, Value>,
) -> Result<&Map<String, Value>, OrganizationRegistrationError> {
    let governance = document
        .get("arkret_governance")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            OrganizationRegistrationError::proof(
                "pinned DID document has no arkret_governance policy",
            )
        })?;
    if governance.get("profile").and_then(Value::as_str) != Some(GOVERNANCE_PROFILE) {
        return Err(OrganizationRegistrationError::proof(
            "pinned DID governance profile is not ak.organization.governance.v1",
        ));
    }
    Ok(governance)
}

fn verification_methods(
    document: &Map<String, Value>,
    did: &Did,
) -> Result<BTreeMap<String, PublicKeyMaterial>, OrganizationRegistrationError> {
    let mut methods = BTreeMap::new();
    for method in document
        .get("verificationMethod")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let object = method.as_object().ok_or_else(|| {
            OrganizationRegistrationError::proof("verificationMethod entry is not an object")
        })?;
        let id = object.get("id").and_then(Value::as_str).ok_or_else(|| {
            OrganizationRegistrationError::proof("verificationMethod id is missing")
        })?;
        if object.get("controller").and_then(Value::as_str) != Some(did.as_str()) {
            continue;
        }
        let material =
            if let Some(multibase) = object.get("publicKeyMultibase").and_then(Value::as_str) {
                PublicKeyMaterial::Ed25519Multibase {
                    value: multibase.to_owned(),
                }
            } else if let Some(jwk) = object.get("publicKeyJwk") {
                PublicKeyMaterial::Jwk { value: jwk.clone() }
            } else {
                return Err(OrganizationRegistrationError::proof(format!(
                    "verification method {id} has no supported public key material"
                )));
            };
        if methods.insert(id.to_owned(), material).is_some() {
            return Err(OrganizationRegistrationError::proof(
                "pinned DID document has duplicate verification method ids",
            ));
        }
    }
    Ok(methods)
}

fn relationship_methods(document: &Map<String, Value>, field: &str) -> BTreeSet<String> {
    document
        .get(field)
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|value| {
            value.as_str().map(ToOwned::to_owned).or_else(|| {
                value
                    .as_object()
                    .and_then(|object| object.get("id"))
                    .and_then(Value::as_str)
                    .map(ToOwned::to_owned)
            })
        })
        .collect()
}

fn update_key_material(
    pinned: &PinnedDidDocumentState,
    verification_method: &str,
) -> Option<PublicKeyMaterial> {
    let key = verification_method
        .strip_prefix("did:key:")?
        .split_once('#')?
        .0;
    pinned
        .update_keys
        .iter()
        .any(|candidate| candidate == key)
        .then(|| PublicKeyMaterial::Ed25519Multibase {
            value: key.to_owned(),
        })
}

fn canonical_public_key_bytes(
    material: &PublicKeyMaterial,
) -> Result<Vec<u8>, OrganizationRegistrationError> {
    match material {
        PublicKeyMaterial::Ed25519Multibase { value } => Ok(value.as_bytes().to_vec()),
        PublicKeyMaterial::Ed25519Raw { bytes } => Ok(bytes.clone()),
        PublicKeyMaterial::Jwk { value } => arkret_canonical::canonical_json_bytes(value)
            .map_err(|error| internal(error.to_string())),
    }
}

fn control_transcript_bytes(
    challenge_id: &str,
    organization_id: &DidCoreId,
    organization_did: &Did,
    local_admin_subject_id: &DidCoreId,
    version_id: &str,
    log_head_digest: &Hash,
    proof: &PayloadProof,
) -> Result<Vec<u8>, OrganizationRegistrationError> {
    arkret_canonical::canonical_json_bytes(&json!({
        "context": ProofContextId::ORGANIZATION_REGISTRATION_CONTROL_PROOF_V1,
        "challenge_id": challenge_id,
        "organization_id": organization_id,
        "organization_did": organization_did,
        "local_admin_subject_id": local_admin_subject_id,
        "version_id": version_id,
        "log_head_digest": log_head_digest,
        "verification_method": proof.verification_method,
        "created_at": proof.created_at,
    }))
    .map_err(|error| internal(error.to_string()))
}

#[allow(clippy::too_many_arguments)]
fn sign_outcome(
    signer: &dyn OrganizationRegistrationReceiptSigner,
    organization_id: &DidCoreId,
    organization_did: &Did,
    registration_generation: u64,
    version_id: &str,
    log_head_digest: &Hash,
    control_proof_kind: OrganizationControlProofKind,
    control_key_digest: &Hash,
    local_admin_subject_id: &DidCoreId,
    delegated_scopes: &[arkret_models_identity::OrganizationRegistrationScope],
    status: OrganizationRegistrationStatus,
    now: DateTime<Utc>,
    created: bool,
) -> Result<OrganizationRegistrationResponseBody, OrganizationRegistrationError> {
    let issued_at = canonical_time(now);
    let mut receipt = OrganizationRegistrationReceipt {
        registration_receipt_id: "ak:organization_registration_receipt:placeholder".to_owned(),
        organization_id: organization_id.clone(),
        organization_did: organization_did.clone(),
        registration_generation,
        version_id: version_id.to_owned(),
        log_head_digest: log_head_digest.clone(),
        control_proof_kind,
        control_key_digest: control_key_digest.clone(),
        local_admin_subject_id: local_admin_subject_id.clone(),
        delegated_scopes: delegated_scopes.to_vec(),
        status,
        issued_at,
        expires_at: issued_at + RECEIPT_LIFETIME,
        issuer_id: signer.issuer_id().clone(),
        proof: PayloadProof {
            kind: arkret_wire::proof_kind::DETACHED_JWS.to_owned(),
            verification_method: signer.verification_method().to_owned(),
            payload_digest: Hash::new(format!("sha256:{}", "0".repeat(64)))
                .expect("constant digest is valid"),
            created_at: issued_at,
            domain: None,
            audience: None,
            proof_purpose: None,
            jws: "pending".to_owned(),
        },
    };
    receipt.registration_receipt_id = receipt
        .expected_receipt_id()
        .map_err(|error| internal(error.to_string()))?;
    receipt.proof.payload_digest = receipt
        .expected_payload_digest()
        .map_err(|error| internal(error.to_string()))?;
    let signing_bytes = receipt
        .proof_signing_bytes()
        .map_err(|error| internal(error.to_string()))?;
    receipt.proof.jws = signer.sign_detached_jws(&signing_bytes).map_err(internal)?;
    receipt
        .validate()
        .map_err(|error| internal(error.to_string()))?;
    let outcome = OrganizationRegistrationResponseBody {
        registration_receipt: receipt,
        created,
    };
    outcome
        .validate()
        .map_err(|error| internal(error.to_string()))?;
    Ok(outcome)
}

fn validate_handle_attestation(
    request: &OrganizationRegistrationEnsureRequestBody,
    now: DateTime<Utc>,
) -> Result<(), OrganizationRegistrationError> {
    validate_declared_governance_quorum(&request.control_proof)?;
    request
        .validate()
        .map_err(|error| schema(error.to_string()))?;
    if let Some(attestation) = &request.handle_attestation {
        if attestation.status != OrganizationHandleAttestationStatus::Active
            || attestation.expires_at <= now
        {
            return Err(OrganizationRegistrationError::proof(
                "organization handle attestation is revoked or expired",
            ));
        }
        return Err(OrganizationRegistrationError::proof(
            "organization handle attestation issuer revocation status cannot be verified",
        ));
    }
    Ok(())
}

fn validate_refresh_request(
    request: &OrganizationRegistrationRefreshRequestBody,
) -> Result<(), OrganizationRegistrationError> {
    validate_declared_governance_quorum(&request.control_proof)?;
    request
        .validate()
        .map_err(|error| schema(error.to_string()))
}

fn validate_declared_governance_quorum(
    proof: &OrganizationControlProof,
) -> Result<(), OrganizationRegistrationError> {
    if proof.proof_kind == OrganizationControlProofKind::GovernanceQuorum
        && proof
            .quorum_threshold
            .is_some_and(|threshold| threshold >= 2 && proof.proofs.len() < threshold as usize)
    {
        return Err(OrganizationRegistrationError::new(
            OrganizationRegistrationErrorCode::QuorumNotMet,
            "governance proof count is below quorum_threshold",
        ));
    }
    Ok(())
}

fn canonical_time(value: DateTime<Utc>) -> DateTime<Utc> {
    arkret_canonical::normalize_timestamp_canonical(value)
}

fn map_storage(error: PersistenceError) -> OrganizationRegistrationError {
    // Registered conflict codes decide the outcome; the detail is diagnostics.
    let conflict_code = error.conflict_code();
    match error {
        PersistenceError::NotFound(detail) => not_found(detail),
        PersistenceError::Conflict(detail) => match conflict_code {
            Some(coland_storage::ConflictCode::OrganizationRegistrationChallengeInvalid) => {
                OrganizationRegistrationError::challenge(detail)
            }
            Some(coland_storage::ConflictCode::OrganizationRegistrationRevoked) => {
                OrganizationRegistrationError::new(
                    OrganizationRegistrationErrorCode::Revoked,
                    detail,
                )
            }
            Some(coland_storage::ConflictCode::OrganizationRegistrationStale) => {
                OrganizationRegistrationError::new(OrganizationRegistrationErrorCode::Stale, detail)
            }
            _ => internal(detail),
        },
        PersistenceError::SchemaViolation(detail) => schema(detail),
        PersistenceError::Database(detail) | PersistenceError::Internal(detail) => internal(detail),
    }
}

fn schema(detail: impl Into<String>) -> OrganizationRegistrationError {
    OrganizationRegistrationError::new(OrganizationRegistrationErrorCode::SchemaViolation, detail)
}

fn not_found(detail: impl Into<String>) -> OrganizationRegistrationError {
    OrganizationRegistrationError::new(OrganizationRegistrationErrorCode::DidNotFound, detail)
}

fn internal(detail: impl Into<String>) -> OrganizationRegistrationError {
    OrganizationRegistrationError::new(OrganizationRegistrationErrorCode::Internal, detail)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use arkret_models_identity::{
        OrganizationControlProof, OrganizationControlProofKind, OrganizationRegistrationScope,
        validate_organization_registration_authorization_at,
    };
    use arkret_signatures::{Ed25519DetachedJwsSigner, EventSigner};
    use arkret_wire::PayloadProof;
    use coland_storage::PersistenceStore;
    use parking_lot::RwLock;

    use super::*;

    struct StaticResolver {
        state: RwLock<PinnedDidDocumentState>,
    }

    #[async_trait::async_trait]
    impl OrganizationDidResolutionPort for StaticResolver {
        async fn resolve_current_webvh_state(
            &self,
            did: &Did,
        ) -> Result<PinnedDidDocumentState, String> {
            let state = self.state.read().clone();
            (state.did == *did)
                .then_some(state)
                .ok_or_else(|| "DID not found".to_owned())
        }

        async fn resolve_pinned_webvh_state(
            &self,
            did: &Did,
            version_id: &str,
            log_head_digest: &Hash,
        ) -> Result<PinnedDidDocumentState, String> {
            let state = self.state.read().clone();
            (state.did == *did
                && state.version_id == version_id
                && state.log_head_digest == *log_head_digest)
                .then_some(state)
                .ok_or_else(|| "pinned DID state not found".to_owned())
        }
    }

    struct TestReceiptSigner {
        issuer: DidCoreId,
        verification_method: DidUrl,
        signer: Ed25519DetachedJwsSigner,
    }

    impl OrganizationRegistrationReceiptSigner for TestReceiptSigner {
        fn issuer_id(&self) -> &DidCoreId {
            &self.issuer
        }

        fn verification_method(&self) -> &DidUrl {
            &self.verification_method
        }

        fn sign_detached_jws(&self, signing_bytes: &[u8]) -> Result<String, String> {
            Ok(self.signer.sign_detached_jws(signing_bytes))
        }
    }

    struct SemanticFixture {
        service: OrganizationRegistrationService,
        resolver: Arc<StaticResolver>,
        organization_id: DidCoreId,
        organization_did: Did,
        admin_id: DidCoreId,
        pinned: PinnedDidDocumentState,
        control_signer: Ed25519DetachedJwsSigner,
        governance_signers: Vec<Ed25519DetachedJwsSigner>,
        receipt_signer: TestReceiptSigner,
        now: DateTime<Utc>,
    }

    fn semantic_fixture(
        persistence: Arc<dyn PersistenceStore>,
        namespace: &str,
    ) -> SemanticFixture {
        let did = Did::new(format!("did:webvh:z{namespace}:acme.example:semantic")).unwrap();
        let organization_id = arkret_wire::project_did_to_core_id(&did).unwrap();
        let admin_id = DidCoreId::new("ak:did_core:webvh:z6mkadminfixture".to_owned()).unwrap();
        let issuer_did =
            Did::new("did:webvh:z6mkregistryfixture:registry.example".to_owned()).unwrap();
        let issuer = arkret_wire::project_did_to_core_id(&issuer_did).unwrap();
        let control_key =
            Ed25519DetachedJwsSigner::from_seed([31; 32], format!("{did}#org-control-key-1"));
        let governance_key_1 =
            Ed25519DetachedJwsSigner::from_seed([32; 32], format!("{did}#org-governance-key-1"));
        let governance_key_2 =
            Ed25519DetachedJwsSigner::from_seed([33; 32], format!("{did}#org-governance-key-2"));
        let control_multibase = arkret_canonical::ed25519_pubkey_to_did_key_multibase(
            control_key.verifying_key().as_bytes(),
        );
        let governance_multibase_1 = arkret_canonical::ed25519_pubkey_to_did_key_multibase(
            governance_key_1.verifying_key().as_bytes(),
        );
        let governance_multibase_2 = arkret_canonical::ed25519_pubkey_to_did_key_multibase(
            governance_key_2.verifying_key().as_bytes(),
        );
        let control_method = control_key.verification_method().to_owned();
        let governance_method_1 = governance_key_1.verification_method().to_owned();
        let governance_method_2 = governance_key_2.verification_method().to_owned();
        let document = json!({
            "id": did,
            "verificationMethod": [
                {
                    "id": control_method,
                    "type": "Multikey",
                    "controller": did,
                    "publicKeyMultibase": control_multibase,
                },
                {
                    "id": governance_method_1,
                    "type": "Multikey",
                    "controller": did,
                    "publicKeyMultibase": governance_multibase_1,
                },
                {
                    "id": governance_method_2,
                    "type": "Multikey",
                    "controller": did,
                    "publicKeyMultibase": governance_multibase_2,
                }
            ],
            "authentication": [control_method, governance_method_1, governance_method_2],
            "assertionMethod": [control_method, governance_method_1, governance_method_2],
            "arkret_governance": {
                "profile": GOVERNANCE_PROFILE,
                "threshold": {
                    "required": 2,
                    "eligible_methods": [governance_method_1, governance_method_2],
                }
            }
        });
        let pinned = PinnedDidDocumentState {
            did: did.clone(),
            version_id: "3-zFixtureVersionThree".to_owned(),
            log_head_digest: Hash::new(format!("sha256:{}", "4".repeat(64))).unwrap(),
            document,
            update_keys: Vec::new(),
            current_version_id: "3-zFixtureVersionThree".to_owned(),
            status: PinnedDidVersionStatus::Current,
        };
        let resolver = Arc::new(StaticResolver {
            state: RwLock::new(pinned.clone()),
        });
        let receipt_vm = format!("{issuer_did}#registry-signing-key-1");
        SemanticFixture {
            service: OrganizationRegistrationService::with_resolver(persistence, resolver.clone()),
            resolver,
            organization_id,
            organization_did: did,
            admin_id,
            pinned,
            control_signer: control_key,
            governance_signers: vec![governance_key_1, governance_key_2],
            receipt_signer: TestReceiptSigner {
                issuer,
                verification_method: DidUrl::new(receipt_vm.clone())
                    .expect("registry receipt verification method is a DID URL"),
                signer: Ed25519DetachedJwsSigner::from_seed([41; 32], receipt_vm),
            },
            now: DateTime::parse_from_rfc3339("2026-05-01T00:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
        }
    }

    fn challenge_request(
        fixture: &SemanticFixture,
        scopes: Vec<OrganizationRegistrationScope>,
    ) -> OrganizationRegistrationChallengeRequestBody {
        OrganizationRegistrationChallengeRequestBody {
            organization_id: fixture.organization_id.clone(),
            organization_did: fixture.organization_did.clone(),
            local_admin_subject_id: fixture.admin_id.clone(),
            requested_scopes: scopes,
        }
    }

    fn signed_proof(
        challenge: &OrganizationRegistrationChallenge,
        pinned: &PinnedDidDocumentState,
        local_admin_subject_id: &DidCoreId,
        proof_kind: OrganizationControlProofKind,
        signers: &[&Ed25519DetachedJwsSigner],
        created_at: DateTime<Utc>,
    ) -> OrganizationControlProof {
        let mut proofs = Vec::new();
        for signer in signers {
            let mut proof = PayloadProof {
                kind: arkret_wire::proof_kind::DETACHED_JWS.to_owned(),
                verification_method: DidUrl::new(signer.verification_method().to_owned())
                    .expect("fixture signer verification method is a DID URL"),
                payload_digest: Hash::new(format!("sha256:{}", "0".repeat(64))).unwrap(),
                created_at,
                domain: None,
                audience: None,
                proof_purpose: None,
                jws: "pending".to_owned(),
            };
            let bytes = control_transcript_bytes(
                &challenge.challenge_id,
                &challenge.organization_id,
                &challenge.organization_did,
                local_admin_subject_id,
                &pinned.version_id,
                &pinned.log_head_digest,
                &proof,
            )
            .unwrap();
            proof.payload_digest = Hash::new(arkret_canonical::sha256_digest(&bytes)).unwrap();
            proof.jws = signer.sign_detached_jws(&bytes);
            proofs.push(proof);
        }
        OrganizationControlProof {
            proof_kind,
            quorum_threshold: (proof_kind == OrganizationControlProofKind::GovernanceQuorum)
                .then_some(2),
            proofs,
        }
    }

    fn ensure_request(
        fixture: &SemanticFixture,
        challenge: &OrganizationRegistrationChallenge,
        scopes: Vec<OrganizationRegistrationScope>,
        proof: OrganizationControlProof,
    ) -> OrganizationRegistrationEnsureRequestBody {
        OrganizationRegistrationEnsureRequestBody {
            organization_id: fixture.organization_id.clone(),
            organization_did: fixture.organization_did.clone(),
            challenge_id: challenge.challenge_id.clone(),
            version_id: fixture.pinned.version_id.clone(),
            log_head_digest: fixture.pinned.log_head_digest.clone(),
            control_proof: proof,
            local_admin_subject_id: fixture.admin_id.clone(),
            requested_scopes: scopes,
            handle_attestation: None,
        }
    }

    fn tamper_detached_jws(jws: &str) -> String {
        let mut bytes = jws.as_bytes().to_vec();
        let signature_start = jws.find("..").expect("detached JWS separator") + 2;
        bytes[signature_start] = if bytes[signature_start] == b'A' {
            b'B'
        } else {
            b'A'
        };
        String::from_utf8(bytes).expect("JWS is ASCII")
    }

    fn fixture_schema_case_is_valid(case: &Value) -> bool {
        let instance = case["instance"].clone();
        let schema_only_valid = case["schema_only_valid"].as_bool() == Some(true);
        match case["schema_ref"]
            .as_str()
            .unwrap()
            .rsplit('/')
            .next()
            .unwrap()
        {
            "OrganizationRegistrationChallenge" => {
                serde_json::from_value::<OrganizationRegistrationChallenge>(instance).is_ok()
            }
            "OrganizationRegistrationChallengeRequestBody" => {
                serde_json::from_value::<OrganizationRegistrationChallengeRequestBody>(instance)
                    .is_ok()
            }
            "OrganizationRegistrationEnsureRequestBody" => serde_json::from_value::<
                OrganizationRegistrationEnsureRequestBody,
            >(instance)
            .and_then(|body| {
                if schema_only_valid {
                    Ok(())
                } else {
                    body.validate()
                        .map_err(|error| serde_json::Error::io(std::io::Error::other(error)))
                }
            })
            .is_ok(),
            "OrganizationRegistrationRefreshRequestBody" => serde_json::from_value::<
                OrganizationRegistrationRefreshRequestBody,
            >(instance)
            .and_then(|body| {
                if schema_only_valid {
                    Ok(())
                } else {
                    body.validate()
                        .map_err(|error| serde_json::Error::io(std::io::Error::other(error)))
                }
            })
            .is_ok(),
            "OrganizationControlProof" => {
                serde_json::from_value::<OrganizationControlProof>(instance)
                    .and_then(|proof| {
                        if schema_only_valid {
                            Ok(())
                        } else {
                            proof.validate().map_err(|error| {
                                serde_json::Error::io(std::io::Error::other(error))
                            })
                        }
                    })
                    .is_ok()
            }
            "OrganizationRegistrationReceipt" => {
                serde_json::from_value::<OrganizationRegistrationReceipt>(instance).is_ok()
            }
            "OrganizationRegistrationResponseBody" => {
                serde_json::from_value::<OrganizationRegistrationResponseBody>(instance).is_ok()
            }
            other => panic!("unhandled organization registration schema {other}"),
        }
    }

    type SemanticObservation = (&'static str, Option<&'static str>);

    fn observe_registration<T>(
        result: &Result<T, OrganizationRegistrationError>,
    ) -> SemanticObservation {
        match result {
            Ok(_) => ("accept", None),
            Err(error) => (
                "reject",
                Some(match error.code {
                    OrganizationRegistrationErrorCode::SchemaViolation => "schema_violation",
                    OrganizationRegistrationErrorCode::DidNotFound => "did_not_found",
                    OrganizationRegistrationErrorCode::ChallengeInvalid => {
                        "organization_registration_challenge_invalid"
                    }
                    OrganizationRegistrationErrorCode::ControlProofInvalid => {
                        "organization_registration_control_proof_invalid"
                    }
                    OrganizationRegistrationErrorCode::QuorumNotMet => {
                        "organization_registration_quorum_not_met"
                    }
                    OrganizationRegistrationErrorCode::ScopeUnsupported => {
                        "unsupported_organization_registration_scope"
                    }
                    OrganizationRegistrationErrorCode::Revoked => {
                        "organization_registration_revoked"
                    }
                    OrganizationRegistrationErrorCode::Stale => "organization_registration_stale",
                    OrganizationRegistrationErrorCode::Internal => "internal",
                }),
            ),
        }
    }

    fn observe_validation<T, E>(
        result: &Result<T, E>,
        rejection_code: &'static str,
    ) -> SemanticObservation {
        if result.is_ok() {
            ("accept", None)
        } else {
            ("reject", Some(rejection_code))
        }
    }

    fn observe_schema_case(case: &Value, rejection_code: &'static str) -> SemanticObservation {
        if fixture_schema_case_is_valid(case) {
            ("accept", None)
        } else {
            ("reject", Some(rejection_code))
        }
    }

    async fn run_embedded_fixture(persistence: Arc<dyn PersistenceStore>) {
        let namespace = uuid::Uuid::now_v7().simple().to_string();
        let fixture = semantic_fixture(persistence.clone(), &namespace);
        let profile = vec![OrganizationRegistrationScope::OrganizationProfileManage];
        let realm = vec![OrganizationRegistrationScope::OrganizationRealmEndorse];

        let challenge = fixture
            .service
            .prepare(
                challenge_request(&fixture, profile.clone()),
                "https://registry.example",
                "ak:trust_domain:registry.example",
                fixture.receipt_signer.issuer_id(),
                fixture.now,
            )
            .await
            .unwrap();
        let challenge_validation = challenge.validate_for_at(
            &OrganizationRegistrationChallengeRequestBody {
                organization_id: challenge.organization_id.clone(),
                organization_did: challenge.organization_did.clone(),
                local_admin_subject_id: challenge.local_admin_subject_id.clone(),
                requested_scopes: challenge.requested_scopes.clone(),
            },
            fixture.now,
        );
        let challenge_observation = observe_validation(
            &challenge_validation,
            "organization_registration_challenge_invalid",
        );
        let resolved_proof = signed_proof(
            &challenge,
            &fixture.pinned,
            &fixture.admin_id,
            OrganizationControlProofKind::ResolvedVerificationMethod,
            &[&fixture.control_signer],
            fixture.now + Duration::minutes(1),
        );
        let resolved_request = ensure_request(
            &fixture,
            &challenge,
            profile.clone(),
            resolved_proof.clone(),
        );
        let first_result = fixture
            .service
            .ensure(
                resolved_request.clone(),
                &fixture.receipt_signer,
                fixture.now + Duration::minutes(2),
            )
            .await;
        let resolved_observation = observe_registration(&first_result);
        let first = first_result.unwrap();
        let receipt_validation = first.registration_receipt.validate();
        let receipt_observation = observe_validation(&receipt_validation, "schema_violation");
        let replay_result = fixture
            .service
            .ensure(
                resolved_request.clone(),
                &fixture.receipt_signer,
                fixture.now + Duration::minutes(2),
            )
            .await;
        let replay_observation = observe_registration(&replay_result);
        let replay = replay_result.unwrap();
        assert!(!replay.created);

        let mut scope_mismatch = resolved_request.clone();
        scope_mismatch
            .requested_scopes
            .push(OrganizationRegistrationScope::OrganizationServiceDelegate);
        let scope_mismatch_result = fixture
            .service
            .ensure(
                scope_mismatch,
                &fixture.receipt_signer,
                fixture.now + Duration::minutes(2),
            )
            .await;
        let scope_mismatch_observation = observe_registration(&scope_mismatch_result);

        let quorum_short_challenge = fixture
            .service
            .prepare(
                challenge_request(&fixture, profile.clone()),
                "https://registry.example",
                "ak:trust_domain:registry.example",
                fixture.receipt_signer.issuer_id(),
                fixture.now + Duration::minutes(2),
            )
            .await
            .unwrap();
        let quorum_short_result = fixture
            .service
            .ensure(
                ensure_request(
                    &fixture,
                    &quorum_short_challenge,
                    profile.clone(),
                    signed_proof(
                        &quorum_short_challenge,
                        &fixture.pinned,
                        &fixture.admin_id,
                        OrganizationControlProofKind::GovernanceQuorum,
                        &[&fixture.governance_signers[0]],
                        fixture.now + Duration::minutes(2),
                    ),
                ),
                &fixture.receipt_signer,
                fixture.now + Duration::minutes(2),
            )
            .await;
        let quorum_short_observation = observe_registration(&quorum_short_result);

        let invalid_resolved_challenge = fixture
            .service
            .prepare(
                challenge_request(&fixture, profile.clone()),
                "https://registry.example",
                "ak:trust_domain:registry.example",
                fixture.receipt_signer.issuer_id(),
                fixture.now + Duration::minutes(2),
            )
            .await
            .unwrap();
        let mut invalid_resolved_proof = signed_proof(
            &invalid_resolved_challenge,
            &fixture.pinned,
            &fixture.admin_id,
            OrganizationControlProofKind::ResolvedVerificationMethod,
            &[&fixture.control_signer],
            fixture.now + Duration::minutes(2),
        );
        invalid_resolved_proof.proofs[0].jws =
            tamper_detached_jws(&invalid_resolved_proof.proofs[0].jws);
        let invalid_resolved_result = fixture
            .service
            .ensure(
                ensure_request(
                    &fixture,
                    &invalid_resolved_challenge,
                    profile.clone(),
                    invalid_resolved_proof,
                ),
                &fixture.receipt_signer,
                fixture.now + Duration::minutes(2),
            )
            .await;
        assert_eq!(
            observe_registration(&invalid_resolved_result),
            (
                "reject",
                Some("organization_registration_control_proof_invalid"),
            )
        );

        let invalid_quorum_challenge = fixture
            .service
            .prepare(
                challenge_request(&fixture, profile.clone()),
                "https://registry.example",
                "ak:trust_domain:registry.example",
                fixture.receipt_signer.issuer_id(),
                fixture.now + Duration::minutes(2),
            )
            .await
            .unwrap();
        let mut invalid_quorum_proof = signed_proof(
            &invalid_quorum_challenge,
            &fixture.pinned,
            &fixture.admin_id,
            OrganizationControlProofKind::GovernanceQuorum,
            &[
                &fixture.governance_signers[0],
                &fixture.governance_signers[1],
            ],
            fixture.now + Duration::minutes(2),
        );
        invalid_quorum_proof.proofs[0].jws =
            tamper_detached_jws(&invalid_quorum_proof.proofs[0].jws);
        let invalid_quorum_result = fixture
            .service
            .ensure(
                ensure_request(
                    &fixture,
                    &invalid_quorum_challenge,
                    profile.clone(),
                    invalid_quorum_proof,
                ),
                &fixture.receipt_signer,
                fixture.now + Duration::minutes(2),
            )
            .await;
        assert_eq!(
            observe_registration(&invalid_quorum_result),
            ("reject", Some("organization_registration_quorum_not_met"),)
        );

        let redirect_challenge = fixture
            .service
            .prepare(
                challenge_request(&fixture, profile.clone()),
                "https://registry.example",
                "ak:trust_domain:registry.example",
                fixture.receipt_signer.issuer_id(),
                fixture.now + Duration::minutes(2),
            )
            .await
            .unwrap();
        let mut redirected = ensure_request(
            &fixture,
            &redirect_challenge,
            profile.clone(),
            signed_proof(
                &redirect_challenge,
                &fixture.pinned,
                &fixture.admin_id,
                OrganizationControlProofKind::ResolvedVerificationMethod,
                &[&fixture.control_signer],
                fixture.now + Duration::minutes(2),
            ),
        );
        redirected.local_admin_subject_id =
            DidCoreId::new("ak:did_core:webvh:z6mkattackerfixture".to_owned()).unwrap();
        let redirect_result = fixture
            .service
            .ensure(
                redirected,
                &fixture.receipt_signer,
                fixture.now + Duration::minutes(2),
            )
            .await;
        let redirect_observation = observe_registration(&redirect_result);

        fixture
            .service
            .revoke(
                OrganizationRegistrationRevokeRequestBody {
                    organization_id: fixture.organization_id.clone(),
                    reason_code: None,
                },
                &fixture
                    .service
                    .current(&fixture.organization_id)
                    .await
                    .unwrap()
                    .unwrap(),
                &fixture.receipt_signer,
                fixture.now + Duration::minutes(3),
            )
            .await
            .unwrap();
        let refresh_challenge = fixture
            .service
            .prepare(
                challenge_request(&fixture, profile.clone()),
                "https://registry.example",
                "ak:trust_domain:registry.example",
                fixture.receipt_signer.issuer_id(),
                fixture.now + Duration::minutes(4),
            )
            .await
            .unwrap();
        let refresh_proof = signed_proof(
            &refresh_challenge,
            &fixture.pinned,
            &fixture.admin_id,
            OrganizationControlProofKind::ResolvedVerificationMethod,
            &[&fixture.control_signer],
            fixture.now + Duration::minutes(4),
        );
        let refresh_result = fixture
            .service
            .refresh(
                OrganizationRegistrationRefreshRequestBody {
                    organization_id: fixture.organization_id.clone(),
                    organization_did: fixture.organization_did.clone(),
                    challenge_id: refresh_challenge.challenge_id,
                    version_id: fixture.pinned.version_id.clone(),
                    log_head_digest: fixture.pinned.log_head_digest.clone(),
                    control_proof: refresh_proof,
                },
                &fixture
                    .service
                    .current(&fixture.organization_id)
                    .await
                    .unwrap()
                    .unwrap(),
                &fixture.receipt_signer,
                fixture.now + Duration::minutes(4),
            )
            .await;
        let refresh_observation = observe_registration(&refresh_result);

        let generation_two_challenge = fixture
            .service
            .prepare(
                challenge_request(&fixture, profile.clone()),
                "https://registry.example",
                "ak:trust_domain:registry.example",
                fixture.receipt_signer.issuer_id(),
                fixture.now + Duration::minutes(5),
            )
            .await
            .unwrap();
        let generation_two_result = fixture
            .service
            .ensure(
                ensure_request(
                    &fixture,
                    &generation_two_challenge,
                    profile.clone(),
                    signed_proof(
                        &generation_two_challenge,
                        &fixture.pinned,
                        &fixture.admin_id,
                        OrganizationControlProofKind::ResolvedVerificationMethod,
                        &[&fixture.control_signer],
                        fixture.now + Duration::minutes(5),
                    ),
                ),
                &fixture.receipt_signer,
                fixture.now + Duration::minutes(5),
            )
            .await;
        let generation_two_observation = observe_registration(&generation_two_result);
        let generation_two = generation_two_result.unwrap();
        assert_eq!(generation_two.registration_generation(), 2);
        let superseded_replay = fixture
            .service
            .ensure(
                resolved_request.clone(),
                &fixture.receipt_signer,
                fixture.now + Duration::minutes(5),
            )
            .await;
        assert_eq!(
            observe_registration(&superseded_replay),
            (
                "reject",
                Some("organization_registration_challenge_invalid"),
            )
        );

        let scope_change_challenge = fixture
            .service
            .prepare(
                challenge_request(&fixture, realm.clone()),
                "https://registry.example",
                "ak:trust_domain:registry.example",
                fixture.receipt_signer.issuer_id(),
                fixture.now + Duration::minutes(6),
            )
            .await
            .unwrap();
        let scope_change_result = fixture
            .service
            .ensure(
                ensure_request(
                    &fixture,
                    &scope_change_challenge,
                    realm.clone(),
                    signed_proof(
                        &scope_change_challenge,
                        &fixture.pinned,
                        &fixture.admin_id,
                        OrganizationControlProofKind::ResolvedVerificationMethod,
                        &[&fixture.control_signer],
                        fixture.now + Duration::minutes(6),
                    ),
                ),
                &fixture.receipt_signer,
                fixture.now + Duration::minutes(6),
            )
            .await;
        let scope_change_observation = observe_registration(&scope_change_result);
        let scope_change = scope_change_result.unwrap();
        assert_eq!(scope_change.registration_generation(), 3);

        fixture
            .service
            .revoke(
                OrganizationRegistrationRevokeRequestBody {
                    organization_id: fixture.organization_id.clone(),
                    reason_code: None,
                },
                &fixture
                    .service
                    .current(&fixture.organization_id)
                    .await
                    .unwrap()
                    .unwrap(),
                &fixture.receipt_signer,
                fixture.now + Duration::minutes(7),
            )
            .await
            .unwrap();
        let quorum_challenge = fixture
            .service
            .prepare(
                challenge_request(&fixture, realm.clone()),
                "https://registry.example",
                "ak:trust_domain:registry.example",
                fixture.receipt_signer.issuer_id(),
                fixture.now + Duration::minutes(8),
            )
            .await
            .unwrap();
        let quorum_result = fixture
            .service
            .ensure(
                ensure_request(
                    &fixture,
                    &quorum_challenge,
                    realm,
                    signed_proof(
                        &quorum_challenge,
                        &fixture.pinned,
                        &fixture.admin_id,
                        OrganizationControlProofKind::GovernanceQuorum,
                        &[
                            &fixture.governance_signers[0],
                            &fixture.governance_signers[1],
                        ],
                        fixture.now + Duration::minutes(8),
                    ),
                ),
                &fixture.receipt_signer,
                fixture.now + Duration::minutes(8),
            )
            .await;
        let quorum_observation = observe_registration(&quorum_result);
        let quorum = quorum_result.unwrap();
        assert!(quorum.created);

        let stale_fixture =
            semantic_fixture(persistence.clone(), &format!("{namespace}-expired-receipt"));
        let stale_challenge = stale_fixture
            .service
            .prepare(
                challenge_request(&stale_fixture, profile.clone()),
                "https://registry.example",
                "ak:trust_domain:registry.example",
                stale_fixture.receipt_signer.issuer_id(),
                stale_fixture.now,
            )
            .await
            .unwrap();
        let stale_request = ensure_request(
            &stale_fixture,
            &stale_challenge,
            profile.clone(),
            signed_proof(
                &stale_challenge,
                &stale_fixture.pinned,
                &stale_fixture.admin_id,
                OrganizationControlProofKind::ResolvedVerificationMethod,
                &[&stale_fixture.control_signer],
                stale_fixture.now + Duration::minutes(1),
            ),
        );
        stale_fixture
            .service
            .ensure(
                stale_request.clone(),
                &stale_fixture.receipt_signer,
                stale_fixture.now + Duration::minutes(1),
            )
            .await
            .unwrap();
        let expired_at = stale_fixture.now + RECEIPT_LIFETIME + Duration::minutes(2);
        let stale_result = stale_fixture
            .service
            .ensure(
                stale_request,
                &stale_fixture.receipt_signer,
                expired_at + Duration::minutes(1),
            )
            .await;
        let stale_observation = observe_registration(&stale_result);
        let stale_recovery_challenge = stale_fixture
            .service
            .prepare(
                challenge_request(&stale_fixture, profile.clone()),
                "https://registry.example",
                "ak:trust_domain:registry.example",
                stale_fixture.receipt_signer.issuer_id(),
                expired_at + Duration::minutes(2),
            )
            .await
            .unwrap();
        let stale_recovery_proof = signed_proof(
            &stale_recovery_challenge,
            &stale_fixture.pinned,
            &stale_fixture.admin_id,
            OrganizationControlProofKind::ResolvedVerificationMethod,
            &[&stale_fixture.control_signer],
            expired_at + Duration::minutes(3),
        );
        let stale_reensure_result = stale_fixture
            .service
            .ensure(
                ensure_request(
                    &stale_fixture,
                    &stale_recovery_challenge,
                    profile.clone(),
                    stale_recovery_proof.clone(),
                ),
                &stale_fixture.receipt_signer,
                expired_at + Duration::minutes(3),
            )
            .await;
        assert_eq!(
            observe_registration(&stale_reensure_result),
            ("reject", Some("organization_registration_stale"),)
        );
        let refreshed = stale_fixture
            .service
            .refresh(
                OrganizationRegistrationRefreshRequestBody {
                    organization_id: stale_fixture.organization_id.clone(),
                    organization_did: stale_fixture.organization_did.clone(),
                    challenge_id: stale_recovery_challenge.challenge_id,
                    version_id: stale_fixture.pinned.version_id.clone(),
                    log_head_digest: stale_fixture.pinned.log_head_digest.clone(),
                    control_proof: stale_recovery_proof,
                },
                &stale_fixture
                    .service
                    .current(&stale_fixture.organization_id)
                    .await
                    .unwrap()
                    .unwrap(),
                &stale_fixture.receipt_signer,
                expired_at + Duration::minutes(3),
            )
            .await
            .unwrap();
        assert_eq!(
            refreshed.registration_receipt.status,
            OrganizationRegistrationStatus::Active
        );

        let rotation_fixture =
            semantic_fixture(persistence.clone(), &format!("{namespace}-rotated-replay"));
        let rotation_challenge = rotation_fixture
            .service
            .prepare(
                challenge_request(&rotation_fixture, profile.clone()),
                "https://registry.example",
                "ak:trust_domain:registry.example",
                rotation_fixture.receipt_signer.issuer_id(),
                rotation_fixture.now,
            )
            .await
            .unwrap();
        let rotation_request = ensure_request(
            &rotation_fixture,
            &rotation_challenge,
            profile,
            signed_proof(
                &rotation_challenge,
                &rotation_fixture.pinned,
                &rotation_fixture.admin_id,
                OrganizationControlProofKind::ResolvedVerificationMethod,
                &[&rotation_fixture.control_signer],
                rotation_fixture.now + Duration::minutes(1),
            ),
        );
        rotation_fixture
            .service
            .ensure(
                rotation_request.clone(),
                &rotation_fixture.receipt_signer,
                rotation_fixture.now + Duration::minutes(1),
            )
            .await
            .unwrap();
        {
            let mut state = rotation_fixture.resolver.state.write();
            state.status = PinnedDidVersionStatus::Rotated;
            state.current_version_id = "4-zFixtureVersionFour".to_owned();
        }
        let rotated_replay = rotation_fixture
            .service
            .ensure(
                rotation_request,
                &rotation_fixture.receipt_signer,
                rotation_fixture.now + Duration::minutes(2),
            )
            .await;
        assert_eq!(
            observe_registration(&rotated_replay),
            ("reject", Some("organization_registration_stale"),)
        );
        assert_eq!(
            rotation_fixture
                .service
                .current(&rotation_fixture.organization_id)
                .await
                .unwrap()
                .unwrap()
                .generation
                .status,
            OrganizationRegistrationStatus::Stale
        );

        let superseded_result = validate_organization_registration_authorization_at(
            &first.registration_receipt,
            scope_change.registration_generation(),
            OrganizationRegistrationStatus::Active,
            fixture.now + Duration::days(1),
        );
        let superseded_observation =
            observe_validation(&superseded_result, "organization_registration_revoked");

        let embedded = arkret_schema_conformance::spec_json_artifact(
            "fixtures/organization-registration-fixture.json",
        )
        .unwrap();
        let cases = embedded["schema_validation_cases"].as_array().unwrap();
        assert_eq!(cases.len(), 19);
        let case_named = |name: &str| {
            cases
                .iter()
                .find(|case| case["name"].as_str() == Some(name))
                .unwrap_or_else(|| panic!("missing fixture case {name}"))
        };
        let long_challenge: OrganizationRegistrationChallenge = serde_json::from_value(
            case_named("challenge_window_over_300_seconds_is_rejected")["instance"].clone(),
        )
        .unwrap();
        let long_challenge_validation = long_challenge.validate_for_at(
            &OrganizationRegistrationChallengeRequestBody {
                organization_id: long_challenge.organization_id.clone(),
                organization_did: long_challenge.organization_did.clone(),
                local_admin_subject_id: long_challenge.local_admin_subject_id.clone(),
                requested_scopes: long_challenge.requested_scopes.clone(),
            },
            long_challenge.created_at,
        );
        let challenge_window_observation = observe_validation(
            &long_challenge_validation,
            "organization_registration_challenge_invalid",
        );

        let mut actual = BTreeMap::<&str, SemanticObservation>::new();
        actual.insert("challenge_valid", challenge_observation);
        actual.insert(
            "ensure_with_resolved_verification_method_valid",
            resolved_observation,
        );
        actual.insert("ensure_with_governance_quorum_valid", quorum_observation);
        actual.insert("receipt_valid", receipt_observation);
        actual.insert(
            "quorum_threshold_on_single_signature_branch_is_invalid",
            observe_schema_case(
                case_named("quorum_threshold_on_single_signature_branch_is_invalid"),
                "schema_violation",
            ),
        );
        actual.insert(
            "governance_quorum_without_threshold_is_invalid",
            observe_schema_case(
                case_named("governance_quorum_without_threshold_is_invalid"),
                "schema_violation",
            ),
        );
        actual.insert(
            "receipt_without_expiry_is_invalid",
            observe_schema_case(
                case_named("receipt_without_expiry_is_invalid"),
                "schema_violation",
            ),
        );
        actual.insert(
            "unregistered_scope_is_invalid",
            observe_schema_case(
                case_named("unregistered_scope_is_invalid"),
                "unsupported_organization_registration_scope",
            ),
        );
        actual.insert(
            "handle_attestation_without_subject_is_invalid",
            observe_schema_case(
                case_named("handle_attestation_without_subject_is_invalid"),
                "schema_violation",
            ),
        );
        actual.insert(
            "challenge_window_over_300_seconds_is_rejected",
            challenge_window_observation,
        );
        actual.insert(
            "quorum_proofs_below_declared_threshold_is_rejected",
            quorum_short_observation,
        );
        actual.insert(
            "ensure_scopes_disagreeing_with_challenge_is_rejected",
            scope_mismatch_observation,
        );
        actual.insert(
            "refresh_of_revoked_binding_is_rejected",
            refresh_observation,
        );
        actual.insert("stale_binding_blocks_high_risk_path", stale_observation);
        actual.insert(
            "control_proof_redirected_to_another_admin_is_rejected",
            redirect_observation,
        );
        actual.insert(
            "replay_of_current_generation_is_idempotent",
            replay_observation,
        );
        actual.insert(
            "re_registration_after_revoke_opens_new_generation",
            generation_two_observation,
        );
        actual.insert(
            "scope_change_atomically_opens_new_generation",
            scope_change_observation,
        );
        actual.insert(
            "superseded_active_receipt_cannot_authorize",
            superseded_observation,
        );

        for case in cases {
            let name = case["name"].as_str().unwrap();
            assert_eq!(
                fixture_schema_case_is_valid(case),
                case["expect_valid"].as_bool().unwrap(),
                "server schema runner result for {name}",
            );
            let expected_outcome = case["semantic_outcome"].as_str().unwrap();
            let expected_reason = case.get("expected_reason_code").and_then(Value::as_str);
            let observed = actual
                .get(name)
                .unwrap_or_else(|| panic!("unhandled case {name}"));
            assert_eq!(observed.0, expected_outcome, "semantic outcome for {name}");
            assert_eq!(observed.1, expected_reason, "semantic reason for {name}");
        }
    }

    /// The 19 semantic outcomes, run against the one storage implementation
    /// Coland has. The lease fails rather than skips when no database is
    /// configured, so an unconfigured run breaks the build instead of
    /// emptying this suite.
    #[tokio::test]
    async fn embedded_fixture_runner_executes_all_19_semantic_outcomes() {
        let database = coland_storage_postgres::test_database::TestDatabase::lease().await;
        run_embedded_fixture(Arc::new(coland_storage_postgres::PgPersistenceStore::new(
            database.pool(),
        )))
        .await;
    }
}
