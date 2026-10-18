use super::{
    AuthorityCommitTransaction, BackupSeriesEraseProgressRecord, PersistenceError,
    PersistenceResult, RecoveryPolicyRecord, RecoverySessionRecord, SecurityTransactionRecord,
    SecurityTransactionStepAttemptRecord, SecurityTransactionStepOutcomeRecord, async_trait,
};

/// The complete terminal recovery unit admitted under one PCR stream-head and
/// generation CAS. Both signed Commits, both producer Events, the consumed
/// session and the terminal ledger must become visible in one durable write.
#[derive(Clone, Debug)]
pub struct RecoveryUnitCommitWrite {
    pub transaction: SecurityTransactionRecord,
    pub step_outcome: SecurityTransactionStepOutcomeRecord,
    pub predecessor: arkret_wire::CommitStreamHead,
    pub commits: [AuthorityCommitTransaction; 2],
    pub queued_at: chrono::DateTime<chrono::Utc>,
}

/// One accepted SecurityRotation revoke proposal. The command result belongs
/// to a later worker decision; this write may only publish a pending proposal.
#[derive(Clone, Debug)]
pub struct RevokeProposalCommitWrite {
    pub transaction: SecurityTransactionRecord,
    pub commit: AuthorityCommitTransaction,
    pub queued_at: chrono::DateTime<chrono::Utc>,
}

/// One immutable worker decision for the exact accepted revoke proposal.
/// Accepted carries the first durable step outcome; rejected terminates the
/// transaction without any accepted step.
#[derive(Clone, Debug)]
pub struct RevokeCommandTerminalWrite {
    pub transaction: SecurityTransactionRecord,
    pub step_outcome: Option<SecurityTransactionStepOutcomeRecord>,
}

impl RevokeCommandTerminalWrite {
    pub fn validate(&self) -> PersistenceResult<()> {
        use arkret_models_crypto::{
            SecurityRotationRevokeCommandDecision, SecurityTransactionStep,
            SecurityTransactionTerminalOutcome,
        };

        let resource = &self.transaction.resource;
        resource
            .validate_structural()
            .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
        resource.security_rotation_plan().ok_or_else(|| {
            PersistenceError::SchemaViolation(
                "revoke terminal requires SecurityRotation".to_owned(),
            )
        })?;
        let outcome = resource.revoke_command_outcome.as_ref().ok_or_else(|| {
            PersistenceError::SchemaViolation("revoke command outcome is missing".to_owned())
        })?;
        match outcome.result {
            SecurityRotationRevokeCommandDecision::Accepted => {
                let step = self.step_outcome.as_ref().ok_or_else(|| {
                    PersistenceError::SchemaViolation(
                        "accepted revoke requires its durable step outcome".to_owned(),
                    )
                })?;
                if step.transaction_id != resource.transaction_id.as_str()
                    || step.step != SecurityTransactionStep::Revoke
                    || step.response
                        != serde_json::to_value(resource)
                            .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?
                    || resource.accepted_steps.is_empty()
                {
                    return Err(PersistenceError::SchemaViolation(
                        "accepted revoke step differs from prepared unit or terminal resource"
                            .to_owned(),
                    ));
                }
            }
            SecurityRotationRevokeCommandDecision::Rejected => {
                if self.step_outcome.is_some()
                    || !resource.accepted_steps.is_empty()
                    || !matches!(
                        resource.terminal_outcome,
                        Some(
                            SecurityTransactionTerminalOutcome::Aborted { .. }
                                | SecurityTransactionTerminalOutcome::Expired { .. }
                        )
                    )
                {
                    return Err(PersistenceError::SchemaViolation(
                        "rejected revoke must atomically abort or expire without accepted step"
                            .to_owned(),
                    ));
                }
            }
        }
        Ok(())
    }
}

impl RevokeProposalCommitWrite {
    pub fn validate(&self) -> PersistenceResult<()> {
        let resource = &self.transaction.resource;
        resource
            .validate_structural()
            .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
        let plan = resource.security_rotation_plan().ok_or_else(|| {
            PersistenceError::SchemaViolation(
                "revoke proposal requires SecurityRotation".to_owned(),
            )
        })?;
        let proposal = resource.revoke_proposal.as_ref().ok_or_else(|| {
            PersistenceError::SchemaViolation("revoke proposal binding is missing".to_owned())
        })?;
        if resource.revoke_command_outcome.is_some()
            || resource.terminal_outcome.is_some()
            || !resource.accepted_steps.is_empty()
            || !matches!(plan.revoke_unit.request.events.as_slice(), [slot] if slot.event == self.commit.event)
            || proposal.proposal_event_id != self.commit.event.event_id
            || proposal.covering_commit_id != self.commit.commit.commit_id
            || self.commit.event.actor_id
                != arkret_wire::ActorId::account(resource.account_id.clone())
            || self.commit.event.kind != arkret_wire::EventKind::DeviceRevoke
        {
            return Err(PersistenceError::SchemaViolation(
                "revoke proposal unit differs from its prepared Event or covering Commit"
                    .to_owned(),
            ));
        }
        let suite = arkret_canonical::canonical::digest_suite(
            self.commit.event.event_id.digest_suite_code().as_str(),
        )
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
        self.commit
            .event
            .verify_event_id_matches_content_with_digest_suite(suite)
            .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
        self.commit
            .validate()
            .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))
    }
}

/// SecurityRotation `upload_new_material`: every planned replacement envelope
/// of the prepared `new_backup_envelopes` and `accepted_steps[1]` become
/// visible in one durable write. The unit re-derives the envelopes from the
/// frozen plan; the caller supplies no bytes of its own.
#[derive(Clone, Debug)]
pub struct RotationUploadCommitWrite {
    pub transaction: SecurityTransactionRecord,
    pub step_outcome: SecurityTransactionStepOutcomeRecord,
}

/// SecurityRotation `switch_authoritative_pointer`: the prepared
/// `ak.key_backup.active_series` Event, the Station-signed covering Commit,
/// the typed pointer and `accepted_steps[2]` become visible in one durable
/// write through the registered same-cut pointer unit.
#[derive(Clone, Debug)]
pub struct RotationPointerSwitchWrite {
    pub transaction: SecurityTransactionRecord,
    pub step_outcome: SecurityTransactionStepOutcomeRecord,
    pub commit: AuthorityCommitTransaction,
    pub queued_at: chrono::DateTime<chrono::Utc>,
}

/// SecurityRotation `local_commit`: the client-attested terminal step. The
/// attesting device's `client_attestation` is re-verified inside the unit
/// against that device's current accepted PCR authorization key at the locked
/// PCR cut (never a device mirror), and `accepted_steps[4]` commits together
/// with the `completed` terminal outcome and the first response.
#[derive(Clone, Debug)]
pub struct RotationLocalCommitWrite {
    pub transaction: SecurityTransactionRecord,
    pub step_outcome: SecurityTransactionStepOutcomeRecord,
    pub attestation: arkret_models_crypto::ClientStepAttestation,
}

fn single_backup_rotation(
    plan: &arkret_models_crypto::SecurityRotationPlan,
) -> PersistenceResult<&arkret_models_crypto::BackupRotationPlan> {
    match plan.backup_rotations.as_slice() {
        [rotation] => Ok(rotation),
        _ => Err(PersistenceError::SchemaViolation(
            "security rotation plan must carry exactly one secret_storage rotation".to_owned(),
        )),
    }
}

/// Shared shape of a worker step outcome: it appends exactly `step` at
/// `index`, is acceptored by the Station and is stored
/// with the resulting resource as its first response.
fn validate_worker_step_outcome(
    transaction: &SecurityTransactionRecord,
    step_outcome: &SecurityTransactionStepOutcomeRecord,
    step: arkret_models_crypto::SecurityTransactionStep,
    index: usize,
) -> PersistenceResult<()> {
    let resource = &transaction.resource;
    let accepted = resource.accepted_steps.get(index);
    if resource.accepted_steps.len() != index + 1
        || resource.terminal_outcome.is_some()
        || resource
            .step_order()
            .ok()
            .and_then(|order| order.get(index).copied())
            != Some(step)
        || step_outcome.step != step
        || step_outcome.transaction_id != resource.transaction_id.as_str()
        || step_outcome.canonical_request != transaction.canonical_request
        || step_outcome.participant_outcome.is_some()
        || step_outcome.response
            != serde_json::to_value(resource)
                .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?
        || accepted.is_none_or(|accepted| {
            !matches!(
                accepted.acceptor,
                arkret_models_crypto::SecurityTransactionAcceptor::Principal { ref principal_id }
                    if *principal_id == resource.account_id.station_id
            )
        })
    {
        return Err(PersistenceError::SchemaViolation(format!(
            "rotation {step:?} outcome differs from its durable result or resource"
        )));
    }
    Ok(())
}

impl RotationUploadCommitWrite {
    pub fn validate(&self) -> PersistenceResult<()> {
        let resource = &self.transaction.resource;
        resource
            .validate_structural()
            .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
        resource.security_rotation_plan().ok_or_else(|| {
            PersistenceError::SchemaViolation(
                "rotation upload requires SecurityRotation".to_owned(),
            )
        })?;
        validate_worker_step_outcome(
            &self.transaction,
            &self.step_outcome,
            arkret_models_crypto::SecurityTransactionStep::UploadNewMaterial,
            1,
        )
    }
}

impl RotationLocalCommitWrite {
    /// Structural binding of the attestation to the frozen plan and to the
    /// appended step. Signature and device status are durable-state checks
    /// and belong to the unit.
    pub fn validate(&self) -> PersistenceResult<()> {
        use arkret_models_crypto::{
            ClientStepAttestationArtifact, SecurityTransactionStep,
            SecurityTransactionTerminalOutcome,
        };
        let invalid = |reason: &str| PersistenceError::SchemaViolation(reason.to_owned());
        let resource = &self.transaction.resource;
        resource
            .validate_structural()
            .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
        let plan = resource
            .security_rotation_plan()
            .ok_or_else(|| invalid("rotation local commit requires SecurityRotation"))?;
        self.attestation
            .validate()
            .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
        let ClientStepAttestationArtifact::SecurityRotation(artifact) = &self.attestation.artifact
        else {
            return Err(invalid("local commit requires SecurityRotationLocalCommit"));
        };
        let accepted = resource.accepted_steps.get(4);
        if resource.accepted_steps.len() != 5
            || resource.step_order().ok().and_then(|order| order.get(4).copied())
                != Some(SecurityTransactionStep::LocalCommit)
            || !matches!(
                resource.terminal_outcome,
                Some(SecurityTransactionTerminalOutcome::Completed {
                    receipt_id: None,
                    completion_attestation: None,
                    ..
                })
            )
            || self.attestation.step != SecurityTransactionStep::LocalCommit
            || self.attestation.output_ref != plan.local_commit_digest.as_str()
            || self.attestation.transaction_id != resource.transaction_id
            || self.attestation.transaction_request_digest != resource.request_digest
            || self.attestation.prepared_plan_digest != resource.prepared_plan_digest
            || artifact.transaction_id != resource.transaction_id
            || artifact.transaction_request_digest != resource.request_digest
            || artifact.prepared_plan_digest != resource.prepared_plan_digest
            || artifact.local_commit_digest != plan.local_commit_digest
            || self.step_outcome.step != SecurityTransactionStep::LocalCommit
            || self.step_outcome.transaction_id != resource.transaction_id.as_str()
            || self.step_outcome.participant_outcome
                != Some(
                    serde_json::to_value(artifact)
                        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?,
                )
            || self.step_outcome.response
                != serde_json::to_value(resource)
                    .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?
            || accepted.is_none_or(|accepted| {
                !matches!(
                        accepted.acceptor,
                        arkret_models_crypto::SecurityTransactionAcceptor::Principal { ref principal_id }
                            if *principal_id == resource.account_id.station_id
                    )
            })
        {
            return Err(invalid(
                "rotation local commit differs from its frozen plan, attestation or resource",
            ));
        }
        Ok(())
    }
}

impl RotationPointerSwitchWrite {
    pub fn validate(&self) -> PersistenceResult<()> {
        let resource = &self.transaction.resource;
        resource
            .validate_structural()
            .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
        let plan = resource.security_rotation_plan().ok_or_else(|| {
            PersistenceError::SchemaViolation(
                "rotation switch requires SecurityRotation".to_owned(),
            )
        })?;
        let rotation = single_backup_rotation(plan)?;
        if !matches!(rotation.active_series_unit.request.events.as_slice(), [slot] if slot.event == self.commit.event)
            || self.commit.event.event_id != rotation.binding.active_series_event_id
            || self.commit.event.kind != arkret_wire::EventKind::KeyBackupActiveSeries
            || self.commit.event.actor_id
                != arkret_wire::ActorId::account(resource.account_id.clone())
        {
            return Err(PersistenceError::SchemaViolation(
                "rotation switch differs from its prepared active-series Event".to_owned(),
            ));
        }
        self.commit
            .validate()
            .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
        validate_worker_step_outcome(
            &self.transaction,
            &self.step_outcome,
            arkret_models_crypto::SecurityTransactionStep::SwitchAuthoritativePointer,
            2,
        )
    }
}

impl RecoveryUnitCommitWrite {
    pub fn validate(&self) -> PersistenceResult<()> {
        self.transaction
            .resource
            .validate_structural()
            .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
        let plan = self.transaction.resource.recovery_plan().ok_or_else(|| {
            PersistenceError::SchemaViolation(
                "recovery unit requires a RecoveryTransaction plan".to_owned(),
            )
        })?;
        let intent = &plan.reanchor_commit_intent;
        let [planned_reanchor_submission, planned_authorize_submission] =
            plan.reanchor_unit.request.events.as_slice()
        else {
            return Err(PersistenceError::SchemaViolation(
                "recovery plan must contain exactly two ordered Events".to_owned(),
            ));
        };
        let (planned_reanchor, planned_authorize) = (
            &planned_reanchor_submission.event,
            &planned_authorize_submission.event,
        );
        let [reanchor, authorize] = &self.commits;
        let reanchor_payload: arkret_models_collaboration::events_payloads::DeviceReanchorPayload =
            serde_json::from_value(
                serde_json::to_value(&reanchor.event.payload)
                    .map_err(PersistenceError::database)?,
            )
            .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
        let authorize_payload: arkret_models_collaboration::events_payloads::DeviceAuthorizePayload = serde_json::from_value(
            serde_json::to_value(&authorize.event.payload).map_err(PersistenceError::database)?,
        ).map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
        let request: arkret_models_crypto::SecurityTransactionContinueRequest =
            serde_json::from_slice(&self.step_outcome.canonical_request).map_err(|error| {
                PersistenceError::SchemaViolation(format!(
                    "invalid recovery terminal request: {error}"
                ))
            })?;
        request
            .client_attestation
            .validate()
            .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
        let arkret_models_crypto::ClientStepAttestationArtifact::Recovery(terminal) =
            &request.client_attestation.artifact
        else {
            return Err(PersistenceError::SchemaViolation(
                "recovery terminal request has no recovery receipt".to_owned(),
            ));
        };
        let receipt = &terminal.recovery_receipt;
        let Some(arkret_models_crypto::SecurityTransactionTerminalOutcome::Completed {
            completion_attestation: Some(completion),
            ..
        }) = &self.transaction.resource.terminal_outcome
        else {
            return Err(PersistenceError::SchemaViolation(
                "recovery unit requires a completed terminal attestation".to_owned(),
            ));
        };
        let expected_stream = arkret_wire::CommitStreamRef::Realm {
            realm_id: intent.realm_id.clone(),
        };
        let committed_ref = |commit: &AuthorityCommitTransaction| arkret_wire::CommittedEventRef {
            event_id: commit.event.event_id.clone(),
            commit_id: commit.commit.commit_id.clone(),
            stream_ref: commit.commit.stream_ref.clone(),
            stream_position: commit.commit.stream_position,
        };
        let resource = &self.transaction.resource;
        let canonical =
            arkret_canonical::canonical_json_bytes(&request).map_err(PersistenceError::database)?;
        let receipt_digest = arkret_wire::Hash::new(
            arkret_canonical::canonical_sha256(receipt).map_err(PersistenceError::database)?,
        )
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
        let authorize_digest =
            arkret_models_collaboration::events_payloads::device_authorize_payload_digest(
                &serde_json::to_value(&authorize_payload).map_err(PersistenceError::database)?,
                arkret_canonical::DigestSuite::Sha256,
            )
            .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
        if self.step_outcome.step
            != arkret_models_crypto::SecurityTransactionStep::CommitRecoveryUnit
            || self.step_outcome.transaction_id != self.transaction.resource.transaction_id.as_str()
            || self.predecessor.stream_ref != expected_stream
            || self.predecessor.commit_id != intent.predecessor_ref
            || reanchor.event != *planned_reanchor
            || authorize.event != *planned_authorize
            || reanchor.commit.stream_ref != expected_stream
            || authorize.commit.stream_ref != expected_stream
            || reanchor.expected_authority != authorize.expected_authority
            || reanchor.commit.previous_commit_ref.as_ref() != Some(&self.predecessor.commit_id)
            || authorize.commit.previous_commit_ref.as_ref() != Some(&reanchor.commit.commit_id)
            || reanchor.commit.stream_position
                != self
                    .predecessor
                    .stream_position
                    .checked_add(1)
                    .ok_or_else(|| {
                        PersistenceError::SchemaViolation("PCR stream position overflow".to_owned())
                    })?
            || authorize.commit.stream_position
                != reanchor
                    .commit
                    .stream_position
                    .checked_add(1)
                    .ok_or_else(|| {
                        PersistenceError::SchemaViolation("PCR stream position overflow".to_owned())
                    })?
            || self.transaction.resource.terminal_outcome.is_none()
            || canonical != self.step_outcome.canonical_request
            || self.step_outcome.response != serde_json::to_value(resource).map_err(PersistenceError::database)?
            || self.step_outcome.participant_outcome.as_ref() != Some(&serde_json::to_value(terminal).map_err(PersistenceError::database)?)
            || request.request_digest != resource.request_digest
            || request.prepared_plan_digest != resource.prepared_plan_digest
            || request.expected_accepted_step_count.checked_add(1) != Some(resource.accepted_steps.len() as u64)
            || request.client_attestation.transaction_id != resource.transaction_id
            || request.client_attestation.transaction_request_digest != resource.request_digest
            || request.client_attestation.prepared_plan_digest != resource.prepared_plan_digest
            || request.client_attestation.output_ref != receipt.receipt_id.as_str()
            || receipt.transaction_id != resource.transaction_id
            || receipt.transaction_request_digest != resource.request_digest
            || receipt.prepared_plan_digest != resource.prepared_plan_digest
            || receipt.account_id != resource.account_id
            || receipt.receipt_id != plan.binding.terminal_receipt_id
            || receipt.recovery_session_id != plan.binding.recovery_session_id
            || receipt.new_device_id != plan.binding.replacement_device_id
            || receipt.reanchor_event_id != reanchor.event.event_id
            || receipt.authorization_event_id != authorize.event.event_id
            || receipt.previous_model_generation_ref != plan.previous_model_generation_ref
            || receipt.result_model_generation_ref != plan.result_model_generation_ref
            || receipt.proof_summary.proof_digest != plan.proof_digest
            || receipt.recovery_authority_kind != arkret_models_crypto::RecoveryAuthorityKind::PcrPolicy
            || receipt.outcome != arkret_models_crypto::RecoveryReceiptOutcome::Completed
            || receipt.policy_id != reanchor_payload.recovery_policy_id
            || receipt.policy_version != reanchor_payload.recovery_policy_version
            || completion.terminal_receipt_digest != receipt_digest
            || completion.reanchor_event_ref != committed_ref(reanchor)
            || completion.device_authorization_event_ref != committed_ref(authorize)
            || reanchor_payload.account_id != resource.account_id
            || reanchor_payload.recovery_authority_kind != arkret_models_crypto::RecoveryAuthorityKind::PcrPolicy
            || reanchor_payload.recovery_session_id != plan.binding.recovery_session_id
            || reanchor_payload.previous_device_generation != plan.previous_model_generation_ref
            || reanchor_payload.new_device_generation != plan.result_model_generation_ref
            || reanchor_payload.replacement_authorize_payload_digest != authorize_digest
            || authorize_payload.device_id != plan.binding.replacement_device_id
            || authorize_payload.recovery_session_id.as_ref() != Some(&plan.binding.recovery_session_id)
            || authorize_payload.authorization_binding_kind != arkret_models_collaboration::events_payloads::DeviceAuthorizationBindingKind::PcrRecovery
            || authorize_payload.authorized_generation_ref != plan.result_model_generation_ref
            || reanchor.event.producer_proof.as_ref().is_none_or(|proof|
                proof.verification_method != request.client_attestation.auth_data.verification_method
                || proof.verification_method != receipt.auth_data.verification_method)
        {
            return Err(PersistenceError::SchemaViolation(
                "recovery unit does not bind the exact ordered Event/Commit pair and terminal result"
                    .to_owned(),
            ));
        }
        for commit in &self.commits {
            commit.validate().map_err(|error| {
                PersistenceError::SchemaViolation(format!("invalid recovery Commit: {error}"))
            })?;
        }
        Ok(())
    }
}
/// Durable recovery policy store. Implementations enforce policy_id
/// uniqueness, `(account_id, version)` uniqueness, and the per-account
/// supersedes/version monotonicity check before accepting a new snapshot.
#[async_trait]
pub trait RecoveryPolicyStore: Send + Sync {
    async fn get_by_policy_id(
        &self,
        policy_id: &str,
    ) -> PersistenceResult<Option<RecoveryPolicyRecord>>;
    async fn get_active_for_account(
        &self,
        account_id: &arkret_wire::AccountId,
    ) -> PersistenceResult<Option<RecoveryPolicyRecord>>;
    /// All policies for a principal, newest version first (REC-1 read API /
    /// UI audit history).
    async fn list_for_account(
        &self,
        account_id: &arkret_wire::AccountId,
    ) -> PersistenceResult<Vec<RecoveryPolicyRecord>>;
    /// Admit one device-signed `ak.policy.set` recovery policy publication
    /// (key-management.md §8, §8.1). The Event, its RealmCommit and the
    /// accepted policy row are written in one transaction; any refusal writes
    /// nothing.
    async fn commit_publication(
        &self,
        write: RecoveryPolicyPublicationWrite,
    ) -> PersistenceResult<RecoveryPolicyPublicationOutcome>;
}

/// One `ak.policy.set` recovery policy Event and the Station-signed PCR Commit
/// prepared at the head it was read against.
#[derive(Clone, Debug)]
pub struct RecoveryPolicyPublicationWrite {
    pub commit: AuthorityCommitTransaction,
    pub queued_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Debug)]
pub enum RecoveryPolicyPublicationOutcome {
    /// This call accepted the policy together with its Event and Commit.
    Committed(RecoveryPolicyRecord),
    /// The exact Event was already accepted; this is the policy it produced.
    Duplicate(RecoveryPolicyRecord),
}

/// Durable recovery session lifecycle store.
///
/// A verified session is consumed only by atomically binding it to a recovery
/// security transaction. Completion is represented by the transaction's
/// accepted terminal result, never by a parallel session-complete command.
#[async_trait]
pub trait RecoverySessionStore: Send + Sync {
    async fn get(
        &self,
        recovery_session_id: &str,
    ) -> PersistenceResult<Option<RecoverySessionRecord>>;
    async fn get_by_grant_id(
        &self,
        session_grant_id: &str,
    ) -> PersistenceResult<Option<RecoverySessionRecord>>;
    async fn get_by_grant_request(
        &self,
        session_grant_id: &str,
        request_id: &str,
    ) -> PersistenceResult<Option<RecoverySessionRecord>>;
    async fn insert(&self, record: RecoverySessionRecord) -> PersistenceResult<()>;
    async fn save_verified_with_unlock_manifest(
        &self,
        record: RecoverySessionRecord,
        manifest: serde_json::Value,
    ) -> PersistenceResult<()>;
    async fn update(&self, record: RecoverySessionRecord) -> PersistenceResult<()>;
}

#[async_trait]
pub trait SecurityTransactionStore: Send + Sync {
    async fn commit_revoke_command_terminal(
        &self,
        write: RevokeCommandTerminalWrite,
    ) -> PersistenceResult<SecurityTransactionRecord>;
    /// Commits the exact prepared revoke Event/RealmCommit, immutable proposal
    /// dot and transaction binding in one PCR authority transaction.
    async fn commit_revoke_proposal(
        &self,
        write: RevokeProposalCommitWrite,
    ) -> PersistenceResult<arkret_wire::RealmCommit>;
    /// Atomically queues and commits the ordered PCR recovery Event pair and
    /// accepts the terminal step. An error leaves zero accepted Event, Commit,
    /// session consumption or terminal ledger writes visible.
    async fn commit_recovery_unit(
        &self,
        write: RecoveryUnitCommitWrite,
    ) -> PersistenceResult<SecurityTransactionStepOutcomeRecord>;
    /// Persists the canonical request and initial resource atomically.
    ///
    /// Recovery transactions additionally CAS-bind their already verified
    /// recovery session in the same durable commit.
    async fn create(
        &self,
        record: SecurityTransactionRecord,
    ) -> PersistenceResult<SecurityTransactionRecord>;
    async fn get(
        &self,
        transaction_id: &str,
    ) -> PersistenceResult<Option<SecurityTransactionRecord>>;
    async fn update(&self, record: SecurityTransactionRecord) -> PersistenceResult<()>;
    /// Live SecurityRotation transactions whose next step is one the durable
    /// rotation worker owns (`revoke`, `upload_new_material`,
    /// `switch_authoritative_pointer`, `erase_old_material`), oldest first. The list carries no
    /// authority; every transition rechecks its own preconditions.
    async fn rotations_awaiting_worker(&self, limit: u32) -> PersistenceResult<Vec<String>>;
    /// Stores the planned replacement envelopes, re-verified against the
    /// authorizing device at the confirmed PCR cut, and accepts
    /// `upload_new_material` in one PostgreSQL transaction.
    async fn commit_rotation_upload(
        &self,
        write: RotationUploadCommitWrite,
    ) -> PersistenceResult<SecurityTransactionRecord>;
    /// Admits the prepared active-series Event through the same-cut pointer
    /// unit and accepts `switch_authoritative_pointer` in one PostgreSQL
    /// transaction.
    async fn commit_rotation_pointer_switch(
        &self,
        write: RotationPointerSwitchWrite,
    ) -> PersistenceResult<SecurityTransactionRecord>;
    /// Re-verifies the client attestation against the attesting device's
    /// current accepted PCR authorization key at the locked PCR cut and
    /// accepts `local_commit` with the `completed` terminal outcome in one
    /// PostgreSQL transaction.
    async fn commit_rotation_local_commit(
        &self,
        write: RotationLocalCommitWrite,
    ) -> PersistenceResult<SecurityTransactionRecord>;
    async fn step_outcome(
        &self,
        transaction_id: &str,
        step: arkret_models_crypto::SecurityTransactionStep,
    ) -> PersistenceResult<Option<SecurityTransactionStepOutcomeRecord>>;
    async fn step_attempt(
        &self,
        transaction_id: &str,
        step: arkret_models_crypto::SecurityTransactionStep,
    ) -> PersistenceResult<Option<SecurityTransactionStepAttemptRecord>>;
    /// Durably fixes the first canonical request bytes before a participant
    /// side effect. Identical retries return the first attempt; different
    /// bytes conflict.
    async fn begin_step(
        &self,
        attempt: SecurityTransactionStepAttemptRecord,
    ) -> PersistenceResult<SecurityTransactionStepAttemptRecord>;
    /// Atomically appends exactly one accepted step, persists its first
    /// response, and advances the authoritative resource. A byte-identical
    /// replay returns the stored outcome; different bytes conflict.
    async fn accept_step(
        &self,
        record: SecurityTransactionRecord,
        outcome: SecurityTransactionStepOutcomeRecord,
    ) -> PersistenceResult<SecurityTransactionStepOutcomeRecord>;
    async fn backup_erase_progress(
        &self,
        transaction_id: &str,
    ) -> PersistenceResult<Option<BackupSeriesEraseProgressRecord>>;
    /// Fixes the first complete erase request and its initial all-remaining
    /// progress before the first object deletion.
    async fn begin_backup_erase(
        &self,
        progress: BackupSeriesEraseProgressRecord,
    ) -> PersistenceResult<BackupSeriesEraseProgressRecord>;
    /// Persists a monotonic progress snapshot. Implementations must serialize
    /// concurrent updates for the same transaction.
    async fn update_backup_erase(
        &self,
        progress: BackupSeriesEraseProgressRecord,
    ) -> PersistenceResult<BackupSeriesEraseProgressRecord>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[doc(hidden)]
pub enum SecurityTransactionFirstWriteDecision {
    Insert,
    ExactRetry,
}

/// Classifies the immutable canonical bytes fixed by the first writer for a
/// transaction, step, outcome, or transaction-bound erase operation.
#[doc(hidden)]
pub fn classify_security_transaction_first_write(
    existing: Option<&[u8]>,
    proposed: &[u8],
) -> PersistenceResult<SecurityTransactionFirstWriteDecision> {
    match existing {
        None => Ok(SecurityTransactionFirstWriteDecision::Insert),
        Some(existing) if existing == proposed => {
            Ok(SecurityTransactionFirstWriteDecision::ExactRetry)
        }
        Some(_) => Err(PersistenceError::Conflict(
            "security transaction first canonical request bytes changed".to_owned(),
        )),
    }
}

#[doc(hidden)]
pub fn validate_backup_erase_progress_initial(
    progress: &BackupSeriesEraseProgressRecord,
) -> PersistenceResult<()> {
    if progress.transaction_id.is_empty() || progress.canonical_request.is_empty() {
        return Err(PersistenceError::SchemaViolation(
            "backup erase progress requires a transaction and request".to_owned(),
        ));
    }
    let request: crate::BackupSeriesEraseWorkerRequest =
        serde_json::from_slice(&progress.canonical_request)
            .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    let canonical_request = arkret_canonical::canonical_json_bytes(&request)
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    if progress.canonical_request != canonical_request {
        return Err(PersistenceError::SchemaViolation(
            "backup erase progress request must use canonical JSON".to_owned(),
        ));
    }
    if progress.transaction_id != request.transaction_id.as_str() {
        return Err(PersistenceError::SchemaViolation(
            "backup erase progress transaction differs from its canonical request".to_owned(),
        ));
    }
    progress.outcome.validate_for_request(&request)?;
    Ok(())
}

#[doc(hidden)]
pub fn validate_backup_erase_progress_update(
    existing: &BackupSeriesEraseProgressRecord,
    proposed: &BackupSeriesEraseProgressRecord,
) -> PersistenceResult<()> {
    if existing.transaction_id != proposed.transaction_id
        || existing.canonical_request != proposed.canonical_request
    {
        return Err(PersistenceError::Conflict(
            "backup erase progress changed its immutable request".to_owned(),
        ));
    }
    validate_backup_erase_progress_initial(proposed)?;
    validate_backup_erase_progress_initial(existing)?;
    let previous = &existing.outcome.series_records[0];
    let next = &proposed.outcome.series_records[0];
    if existing.outcome.status == crate::BackupSeriesEraseStatus::Complete
        && proposed.outcome != existing.outcome
    {
        return Err(PersistenceError::Conflict(
            "completed backup erase progress cannot change".to_owned(),
        ));
    }
    if !previous
        .erased_backups
        .iter()
        .all(|object| next.erased_backups.contains(object))
        || !next
            .remaining_backups
            .iter()
            .all(|object| previous.remaining_backups.contains(object))
    {
        return Err(PersistenceError::Conflict(
            "backup erase progress cannot restore erased material".to_owned(),
        ));
    }
    Ok(())
}

#[doc(hidden)]
pub fn validate_security_transaction_update(
    existing: &SecurityTransactionRecord,
    proposed: &SecurityTransactionRecord,
) -> PersistenceResult<()> {
    let current = &existing.resource;
    let next = &proposed.resource;
    if existing.canonical_request != proposed.canonical_request
        || current.transaction_id != next.transaction_id
        || current.kind != next.kind
        || current.account_id != next.account_id
        || current.authorizing_device_id != next.authorizing_device_id
        || current.expires_at != next.expires_at
        || current.created_at != next.created_at
        || current.request_digest != next.request_digest
        || current.prepared_plan != next.prepared_plan
        || current.prepared_plan_digest != next.prepared_plan_digest
    {
        return Err(PersistenceError::Conflict(
            "security transaction immutable request, identity, or plan changed".to_owned(),
        ));
    }
    if current == next {
        return Ok(());
    }
    if current.terminal_outcome.is_some() {
        return Err(PersistenceError::Conflict(
            "terminal security transaction cannot change".to_owned(),
        ));
    }
    if current.revoke_proposal != next.revoke_proposal
        || (current.revoke_command_outcome.is_some()
            && current.revoke_command_outcome != next.revoke_command_outcome)
    {
        return Err(PersistenceError::Conflict(
            "security rotation revoke proposal requires its Event/Commit unit and command result is immutable".to_owned(),
        ));
    }
    if next.accepted_steps.len() < current.accepted_steps.len()
        || next.accepted_steps.len() > current.accepted_steps.len() + 1
        || !next
            .accepted_steps
            .starts_with(current.accepted_steps.as_slice())
    {
        return Err(PersistenceError::Conflict(
            "security transaction accepted steps must advance by at most one immutable step"
                .to_owned(),
        ));
    }
    Ok(())
}

#[doc(hidden)]
pub fn validate_security_transaction_step_accept(
    existing: &SecurityTransactionRecord,
    proposed: &SecurityTransactionRecord,
    attempt: &SecurityTransactionStepAttemptRecord,
    outcome: &SecurityTransactionStepOutcomeRecord,
) -> PersistenceResult<()> {
    proposed
        .resource
        .validate_structural()
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    let transaction_id = proposed.resource.transaction_id.as_str();
    if attempt.transaction_id != transaction_id
        || outcome.transaction_id != transaction_id
        || attempt.step != outcome.step
    {
        return Err(PersistenceError::SchemaViolation(
            "security transaction step records belong to different transactions or steps"
                .to_owned(),
        ));
    }
    if attempt.canonical_request != outcome.canonical_request {
        return Err(PersistenceError::Conflict(format!(
            "security transaction step {:?} outcome changed the durable request bytes",
            outcome.step
        )));
    }
    validate_security_transaction_update(existing, proposed)?;
    if proposed.resource.accepted_steps.len() != existing.resource.accepted_steps.len() + 1
        || existing
            .resource
            .next_required_step()
            .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?
            != Some(outcome.step)
    {
        return Err(PersistenceError::SchemaViolation(
            "accepted step outcome must match the single appended transaction step".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn security_transaction_first_writer_distinguishes_insert_retry_and_conflict() {
        assert_eq!(
            classify_security_transaction_first_write(None, b"request").unwrap(),
            SecurityTransactionFirstWriteDecision::Insert
        );
        assert_eq!(
            classify_security_transaction_first_write(Some(b"request"), b"request").unwrap(),
            SecurityTransactionFirstWriteDecision::ExactRetry
        );
        assert!(classify_security_transaction_first_write(Some(b"request"), b"changed").is_err());
    }
}
