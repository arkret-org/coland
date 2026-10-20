use std::collections::BTreeMap;

use arkret_models_identity::{
    OrganizationRegistrationChallenge, OrganizationRegistrationChallengeRequestBody,
    OrganizationRegistrationOutcome, OrganizationRegistrationScope, OrganizationRegistrationStatus,
    next_organization_registration_generation, organization_registration_replay_outcome,
};
use arkret_wire::{Did, DidCoreId, Hash};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::{PersistenceError, PersistenceResult, async_trait};

const CHALLENGE_INVALID: &str = "organization_registration_challenge_invalid";
const REGISTRATION_REVOKED: &str = "organization_registration_revoked";
const REGISTRATION_STALE: &str = "organization_registration_stale";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OrganizationRegistrationTerminalReason {
    OrganizationRegistrationSuperseded,
    OrganizationRegistrationWithdrawn,
    ExternalDidDeactivated,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrganizationRegistrationChallengeRecord {
    pub challenge: OrganizationRegistrationChallenge,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub consumed_request_digest: Option<Hash>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub consumed_outcome_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub consumed_at: Option<DateTime<Utc>>,
}

impl OrganizationRegistrationChallengeRecord {
    #[must_use]
    pub fn prepared(challenge: OrganizationRegistrationChallenge) -> Self {
        Self {
            challenge,
            consumed_request_digest: None,
            consumed_outcome_id: None,
            consumed_at: None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrganizationRegistrationGenerationRecord {
    pub organization_id: DidCoreId,
    pub organization_did: Did,
    pub registration_generation: u64,
    pub local_admin_subject_id: DidCoreId,
    pub delegated_scopes: Vec<OrganizationRegistrationScope>,
    pub status: OrganizationRegistrationStatus,
    pub current_outcome_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub terminal_reason: Option<OrganizationRegistrationTerminalReason>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrganizationRegistrationStateRecord {
    pub organization_id: DidCoreId,
    pub current_generation: u64,
    pub generations: BTreeMap<u64, OrganizationRegistrationGenerationRecord>,
}

impl OrganizationRegistrationStateRecord {
    pub fn current(&self) -> PersistenceResult<&OrganizationRegistrationGenerationRecord> {
        self.generations
            .get(&self.current_generation)
            .ok_or_else(|| {
                PersistenceError::Internal(
                    "organization registration current pointer is dangling".to_owned(),
                )
            })
    }

    pub fn validate(&self) -> PersistenceResult<()> {
        if self.current_generation == 0
            || self.generations.is_empty()
            || self.generations.iter().any(|(generation, record)| {
                *generation == 0
                    || *generation != record.registration_generation
                    || record.organization_id != self.organization_id
            })
        {
            return Err(PersistenceError::Internal(
                "organization registration state is inconsistent".to_owned(),
            ));
        }
        let _ = self.current()?;
        let active = self
            .generations
            .values()
            .filter(|record| record.status == OrganizationRegistrationStatus::Active)
            .count();
        if active > 1 {
            return Err(PersistenceError::Internal(
                "organization registration contains multiple active generations".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OrganizationRegistrationCurrent {
    pub generation: OrganizationRegistrationGenerationRecord,
    pub outcome: OrganizationRegistrationOutcome,
}

#[derive(Clone, Debug)]
pub struct OrganizationRegistrationEnsureCommit {
    pub challenge_id: String,
    pub canonical_request_digest: Hash,
    pub expected_current_generation: Option<u64>,
    /// Required only when the transition opens a new generation. Receipt
    /// signing and control-proof verification happen outside this storage
    /// owner; this layer validates only state bindings and immutability.
    pub new_outcome: Option<OrganizationRegistrationOutcome>,
    pub committed_at: DateTime<Utc>,
}

#[derive(Clone, Debug)]
pub struct OrganizationRegistrationRefreshCommit {
    pub challenge_id: String,
    pub canonical_request_digest: Hash,
    pub expected_current_generation: u64,
    pub expected_current_outcome_id: String,
    pub outcome: OrganizationRegistrationOutcome,
    pub committed_at: DateTime<Utc>,
}

#[derive(Clone, Debug)]
pub struct OrganizationRegistrationLifecycleCommit {
    pub organization_id: DidCoreId,
    pub expected_current_generation: u64,
    pub expected_current_outcome_id: String,
    pub outcome: OrganizationRegistrationOutcome,
    pub reason: OrganizationRegistrationTerminalReason,
    pub committed_at: DateTime<Utc>,
}

#[async_trait]
pub trait OrganizationRegistrationStore: Send + Sync {
    async fn prepare_challenge(
        &self,
        challenge: OrganizationRegistrationChallenge,
    ) -> PersistenceResult<OrganizationRegistrationChallengeRecord>;

    async fn get_challenge(
        &self,
        challenge_id: &str,
    ) -> PersistenceResult<Option<OrganizationRegistrationChallengeRecord>>;

    async fn get_current(
        &self,
        organization_id: &DidCoreId,
    ) -> PersistenceResult<Option<OrganizationRegistrationCurrent>>;

    async fn get_generation(
        &self,
        organization_id: &DidCoreId,
        generation: u64,
    ) -> PersistenceResult<Option<OrganizationRegistrationGenerationRecord>>;

    async fn get_outcome(
        &self,
        outcome_id: &str,
    ) -> PersistenceResult<Option<OrganizationRegistrationOutcome>>;

    async fn ensure(
        &self,
        commit: OrganizationRegistrationEnsureCommit,
    ) -> PersistenceResult<OrganizationRegistrationOutcome>;

    async fn refresh(
        &self,
        commit: OrganizationRegistrationRefreshCommit,
    ) -> PersistenceResult<OrganizationRegistrationOutcome>;

    async fn mark_stale(
        &self,
        organization_id: &DidCoreId,
        expected_current_generation: u64,
        expected_current_outcome_id: &str,
        changed_at: DateTime<Utc>,
    ) -> PersistenceResult<OrganizationRegistrationCurrent>;

    async fn revoke(
        &self,
        commit: OrganizationRegistrationLifecycleCommit,
    ) -> PersistenceResult<OrganizationRegistrationOutcome>;

    async fn deactivate(
        &self,
        commit: OrganizationRegistrationLifecycleCommit,
    ) -> PersistenceResult<OrganizationRegistrationOutcome>;
}

#[doc(hidden)]
pub fn validate_prepared_challenge(
    challenge: &OrganizationRegistrationChallenge,
) -> PersistenceResult<()> {
    let request = OrganizationRegistrationChallengeRequestBody {
        organization_id: challenge.organization_id.clone(),
        organization_did: challenge.organization_did.clone(),
        local_admin_subject_id: challenge.local_admin_subject_id.clone(),
        requested_scopes: challenge.requested_scopes.clone(),
    };
    challenge
        .validate_for_at(&request, challenge.created_at)
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))
}

#[doc(hidden)]
pub fn apply_organization_registration_ensure(
    challenge: &mut OrganizationRegistrationChallengeRecord,
    state: &mut Option<OrganizationRegistrationStateRecord>,
    outcomes: &mut BTreeMap<String, OrganizationRegistrationOutcome>,
    commit: OrganizationRegistrationEnsureCommit,
) -> PersistenceResult<OrganizationRegistrationOutcome> {
    if challenge.challenge.challenge_id != commit.challenge_id {
        return Err(challenge_invalid("challenge id mismatch"));
    }
    if let Some(committed_digest) = &challenge.consumed_request_digest {
        let outcome = consumed_outcome(challenge, outcomes)?;
        return organization_registration_replay_outcome(
            committed_digest,
            &commit.canonical_request_digest,
            &outcome,
        )
        .map_err(|_| challenge_invalid("challenge was consumed by another request"));
    }
    validate_challenge_at(challenge, commit.committed_at)?;
    validate_expected_generation(state.as_ref(), commit.expected_current_generation)?;

    if let Some(existing_state) = state.as_mut() {
        existing_state.validate()?;
        let current = existing_state.current()?.clone();
        let same_delegation = current.local_admin_subject_id
            == challenge.challenge.local_admin_subject_id
            && current.delegated_scopes == challenge.challenge.requested_scopes;
        if same_delegation && current.status == OrganizationRegistrationStatus::Active {
            if commit.new_outcome.is_some() {
                return Err(PersistenceError::Conflict(
                    "organization registration generation replacement is not allowed for an unchanged active delegation"
                        .to_owned(),
                ));
            }
            let outcome = outcomes
                .get(&current.current_outcome_id)
                .cloned()
                .ok_or_else(|| dangling_outcome(&current.current_outcome_id))?;
            consume_challenge(
                challenge,
                commit.canonical_request_digest,
                &current.current_outcome_id,
                commit.committed_at,
            );
            let mut replay = outcome;
            replay.created = false;
            replay
                .validate()
                .map_err(|error| PersistenceError::Internal(error.to_string()))?;
            return Ok(replay);
        }
        if same_delegation && current.status == OrganizationRegistrationStatus::Stale {
            return Err(PersistenceError::Conflict(REGISTRATION_STALE.to_owned()));
        }
    }

    let mut outcome = commit.new_outcome.ok_or_else(|| {
        PersistenceError::Conflict(
            "organization registration transition requires a signed new-generation outcome"
                .to_owned(),
        )
    })?;
    validate_new_generation_outcome(&outcome, &challenge.challenge, state.as_ref())?;
    outcome.created = true;
    store_immutable_outcome(outcomes, &outcome)?;

    let receipt = &outcome.registration_receipt;
    let generation = receipt.registration_generation;
    let outcome_id = receipt.registration_receipt_id.clone();
    match state {
        Some(existing_state) => {
            let previous_generation = existing_state.current_generation;
            let previous = existing_state
                .generations
                .get_mut(&previous_generation)
                .ok_or_else(|| {
                    PersistenceError::Internal(
                        "organization registration current pointer is dangling".to_owned(),
                    )
                })?;
            if previous.status != OrganizationRegistrationStatus::Revoked {
                previous.status = OrganizationRegistrationStatus::Revoked;
                previous.terminal_reason = Some(
                    OrganizationRegistrationTerminalReason::OrganizationRegistrationSuperseded,
                );
                previous.updated_at = commit.committed_at;
            }
            existing_state.generations.insert(
                generation,
                OrganizationRegistrationGenerationRecord {
                    organization_id: receipt.organization_id.clone(),
                    organization_did: receipt.organization_did.clone(),
                    registration_generation: generation,
                    local_admin_subject_id: receipt.local_admin_subject_id.clone(),
                    delegated_scopes: receipt.delegated_scopes.clone(),
                    status: OrganizationRegistrationStatus::Active,
                    current_outcome_id: outcome_id.clone(),
                    terminal_reason: None,
                    created_at: commit.committed_at,
                    updated_at: commit.committed_at,
                },
            );
            existing_state.current_generation = generation;
            existing_state.validate()?;
        }
        None => {
            let organization_id = receipt.organization_id.clone();
            let generation_record = OrganizationRegistrationGenerationRecord {
                organization_id: organization_id.clone(),
                organization_did: receipt.organization_did.clone(),
                registration_generation: generation,
                local_admin_subject_id: receipt.local_admin_subject_id.clone(),
                delegated_scopes: receipt.delegated_scopes.clone(),
                status: OrganizationRegistrationStatus::Active,
                current_outcome_id: outcome_id.clone(),
                terminal_reason: None,
                created_at: commit.committed_at,
                updated_at: commit.committed_at,
            };
            *state = Some(OrganizationRegistrationStateRecord {
                organization_id,
                current_generation: generation,
                generations: BTreeMap::from([(generation, generation_record)]),
            });
        }
    }
    consume_challenge(
        challenge,
        commit.canonical_request_digest,
        &outcome_id,
        commit.committed_at,
    );
    Ok(outcome)
}

#[doc(hidden)]
pub fn apply_organization_registration_refresh(
    challenge: &mut OrganizationRegistrationChallengeRecord,
    state: &mut OrganizationRegistrationStateRecord,
    outcomes: &mut BTreeMap<String, OrganizationRegistrationOutcome>,
    commit: OrganizationRegistrationRefreshCommit,
) -> PersistenceResult<OrganizationRegistrationOutcome> {
    if challenge.challenge.challenge_id != commit.challenge_id {
        return Err(challenge_invalid("challenge id mismatch"));
    }
    if let Some(committed_digest) = &challenge.consumed_request_digest {
        let outcome = consumed_outcome(challenge, outcomes)?;
        return organization_registration_replay_outcome(
            committed_digest,
            &commit.canonical_request_digest,
            &outcome,
        )
        .map_err(|_| challenge_invalid("challenge was consumed by another request"));
    }
    validate_challenge_at(challenge, commit.committed_at)?;
    state.validate()?;
    let current = state.current()?.clone();
    validate_current_cas(
        &current,
        commit.expected_current_generation,
        &commit.expected_current_outcome_id,
    )?;
    if current.status == OrganizationRegistrationStatus::Revoked {
        return Err(PersistenceError::Conflict(REGISTRATION_REVOKED.to_owned()));
    }
    if challenge.challenge.organization_id != state.organization_id
        || challenge.challenge.organization_did != current.organization_did
        || challenge.challenge.local_admin_subject_id != current.local_admin_subject_id
        || challenge.challenge.requested_scopes != current.delegated_scopes
    {
        return Err(challenge_invalid(
            "refresh challenge does not match the current delegation",
        ));
    }
    validate_same_generation_outcome(
        &commit.outcome,
        &current,
        OrganizationRegistrationStatus::Active,
        false,
    )?;
    store_immutable_outcome(outcomes, &commit.outcome)?;
    let outcome_id = commit
        .outcome
        .registration_receipt
        .registration_receipt_id
        .clone();
    let mutable_current = state
        .generations
        .get_mut(&state.current_generation)
        .expect("validated current generation exists");
    mutable_current.status = OrganizationRegistrationStatus::Active;
    mutable_current
        .organization_did
        .clone_from(&commit.outcome.registration_receipt.organization_did);
    mutable_current.current_outcome_id.clone_from(&outcome_id);
    mutable_current.terminal_reason = None;
    mutable_current.updated_at = commit.committed_at;
    consume_challenge(
        challenge,
        commit.canonical_request_digest,
        &outcome_id,
        commit.committed_at,
    );
    Ok(commit.outcome)
}

#[doc(hidden)]
pub fn apply_organization_registration_stale(
    state: &mut OrganizationRegistrationStateRecord,
    outcomes: &BTreeMap<String, OrganizationRegistrationOutcome>,
    organization_id: &DidCoreId,
    expected_current_generation: u64,
    expected_current_outcome_id: &str,
    changed_at: DateTime<Utc>,
) -> PersistenceResult<OrganizationRegistrationCurrent> {
    state.validate()?;
    if &state.organization_id != organization_id {
        return Err(PersistenceError::NotFound(
            "organization registration".to_owned(),
        ));
    }
    let current = state.current()?.clone();
    validate_current_cas(
        &current,
        expected_current_generation,
        expected_current_outcome_id,
    )?;
    if current.status == OrganizationRegistrationStatus::Revoked {
        return Err(PersistenceError::Conflict(REGISTRATION_REVOKED.to_owned()));
    }
    let mutable_current = state
        .generations
        .get_mut(&state.current_generation)
        .expect("validated current generation exists");
    mutable_current.status = OrganizationRegistrationStatus::Stale;
    mutable_current.updated_at = changed_at;
    let outcome = outcomes
        .get(&mutable_current.current_outcome_id)
        .cloned()
        .ok_or_else(|| dangling_outcome(&mutable_current.current_outcome_id))?;
    Ok(OrganizationRegistrationCurrent {
        generation: mutable_current.clone(),
        outcome,
    })
}

#[doc(hidden)]
pub fn apply_organization_registration_lifecycle(
    state: &mut OrganizationRegistrationStateRecord,
    outcomes: &mut BTreeMap<String, OrganizationRegistrationOutcome>,
    commit: OrganizationRegistrationLifecycleCommit,
    required_reason: Option<OrganizationRegistrationTerminalReason>,
) -> PersistenceResult<OrganizationRegistrationOutcome> {
    state.validate()?;
    if state.organization_id != commit.organization_id {
        return Err(PersistenceError::NotFound(
            "organization registration".to_owned(),
        ));
    }
    if let Some(required_reason) = required_reason
        && commit.reason != required_reason
    {
        return Err(PersistenceError::Conflict(
            "organization registration lifecycle reason mismatch".to_owned(),
        ));
    }
    let current = state.current()?.clone();
    validate_current_cas(
        &current,
        commit.expected_current_generation,
        &commit.expected_current_outcome_id,
    )?;
    if current.status == OrganizationRegistrationStatus::Revoked {
        let mut existing = outcomes
            .get(&current.current_outcome_id)
            .cloned()
            .ok_or_else(|| dangling_outcome(&current.current_outcome_id))?;
        existing.created = false;
        return Ok(existing);
    }
    validate_same_generation_outcome(
        &commit.outcome,
        &current,
        OrganizationRegistrationStatus::Revoked,
        false,
    )?;
    store_immutable_outcome(outcomes, &commit.outcome)?;
    let outcome_id = commit
        .outcome
        .registration_receipt
        .registration_receipt_id
        .clone();
    let mutable_current = state
        .generations
        .get_mut(&state.current_generation)
        .expect("validated current generation exists");
    mutable_current.status = OrganizationRegistrationStatus::Revoked;
    mutable_current
        .organization_did
        .clone_from(&commit.outcome.registration_receipt.organization_did);
    mutable_current.current_outcome_id = outcome_id;
    mutable_current.terminal_reason = Some(commit.reason);
    mutable_current.updated_at = commit.committed_at;
    Ok(commit.outcome)
}

fn validate_challenge_at(
    record: &OrganizationRegistrationChallengeRecord,
    now: DateTime<Utc>,
) -> PersistenceResult<()> {
    let request = OrganizationRegistrationChallengeRequestBody {
        organization_id: record.challenge.organization_id.clone(),
        organization_did: record.challenge.organization_did.clone(),
        local_admin_subject_id: record.challenge.local_admin_subject_id.clone(),
        requested_scopes: record.challenge.requested_scopes.clone(),
    };
    record
        .challenge
        .validate_for_at(&request, now)
        .map_err(|_| challenge_invalid("challenge expired or has invalid bindings"))
}

fn validate_expected_generation(
    state: Option<&OrganizationRegistrationStateRecord>,
    expected: Option<u64>,
) -> PersistenceResult<()> {
    let actual = state.map(|state| state.current_generation);
    if actual != expected {
        return Err(PersistenceError::Conflict(
            "organization registration current-generation CAS failed".to_owned(),
        ));
    }
    Ok(())
}

fn validate_current_cas(
    current: &OrganizationRegistrationGenerationRecord,
    expected_generation: u64,
    expected_outcome_id: &str,
) -> PersistenceResult<()> {
    if current.registration_generation != expected_generation
        || current.current_outcome_id != expected_outcome_id
    {
        return Err(PersistenceError::Conflict(
            "organization registration current pointer CAS failed".to_owned(),
        ));
    }
    Ok(())
}

fn validate_new_generation_outcome(
    outcome: &OrganizationRegistrationOutcome,
    challenge: &OrganizationRegistrationChallenge,
    state: Option<&OrganizationRegistrationStateRecord>,
) -> PersistenceResult<()> {
    outcome
        .validate()
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    let expected_generation =
        next_organization_registration_generation(state.map(|state| state.current_generation))
            .map_err(|error| PersistenceError::Conflict(error.to_string()))?;
    let receipt = &outcome.registration_receipt;
    if !outcome.created
        || receipt.organization_id != challenge.organization_id
        || receipt.organization_did != challenge.organization_did
        || receipt.registration_generation != expected_generation
        || receipt.local_admin_subject_id != challenge.local_admin_subject_id
        || receipt.delegated_scopes != challenge.requested_scopes
        || receipt.status != OrganizationRegistrationStatus::Active
    {
        return Err(PersistenceError::Conflict(
            "organization registration new-generation outcome does not match the prepared challenge"
                .to_owned(),
        ));
    }
    Ok(())
}

fn validate_same_generation_outcome(
    outcome: &OrganizationRegistrationOutcome,
    current: &OrganizationRegistrationGenerationRecord,
    required_status: OrganizationRegistrationStatus,
    required_created: bool,
) -> PersistenceResult<()> {
    outcome
        .validate()
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    let receipt = &outcome.registration_receipt;
    if outcome.created != required_created
        || receipt.organization_id != current.organization_id
        || receipt.registration_generation != current.registration_generation
        || receipt.local_admin_subject_id != current.local_admin_subject_id
        || receipt.delegated_scopes != current.delegated_scopes
        || receipt.status != required_status
    {
        return Err(PersistenceError::Conflict(
            "organization registration outcome does not match the current generation".to_owned(),
        ));
    }
    Ok(())
}

fn store_immutable_outcome(
    outcomes: &mut BTreeMap<String, OrganizationRegistrationOutcome>,
    outcome: &OrganizationRegistrationOutcome,
) -> PersistenceResult<()> {
    let id = outcome.registration_receipt.registration_receipt_id.clone();
    if let Some(existing) = outcomes.get(&id) {
        if existing != outcome {
            return Err(PersistenceError::Conflict(
                "organization registration outcome is immutable".to_owned(),
            ));
        }
        return Ok(());
    }
    outcomes.insert(id, outcome.clone());
    Ok(())
}

fn consume_challenge(
    challenge: &mut OrganizationRegistrationChallengeRecord,
    request_digest: Hash,
    outcome_id: &str,
    consumed_at: DateTime<Utc>,
) {
    challenge.consumed_request_digest = Some(request_digest);
    challenge.consumed_outcome_id = Some(outcome_id.to_owned());
    challenge.consumed_at = Some(consumed_at);
}

fn consumed_outcome(
    challenge: &OrganizationRegistrationChallengeRecord,
    outcomes: &BTreeMap<String, OrganizationRegistrationOutcome>,
) -> PersistenceResult<OrganizationRegistrationOutcome> {
    let id = challenge
        .consumed_outcome_id
        .as_deref()
        .ok_or_else(|| challenge_invalid("consumed challenge has no committed outcome"))?;
    outcomes
        .get(id)
        .cloned()
        .ok_or_else(|| dangling_outcome(id))
}

fn challenge_invalid(detail: &str) -> PersistenceError {
    PersistenceError::Conflict(format!("{CHALLENGE_INVALID}: {detail}"))
}

fn dangling_outcome(id: &str) -> PersistenceError {
    PersistenceError::Internal(format!("organization registration outcome {id} is missing"))
}
