//! PCR-resident Actor Profile and accountability typed current results.
//!
//! `actor_profile` (`zh/discovery/profiles-presence.md` section 2.3) and
//! `identity_accountability` (`zh/models/actor.md` section 3.3.1) are written
//! only by the transaction that commits their source Event. Profile admission
//! reads the accountability records at that same transaction, with the
//! accepting Commit's time as the frozen admission instant.

use arkret_models_collaboration::events_payloads::agent::{
    AgentPcrGenesisDeclarationValue, AgentProvisioningValue,
};
use arkret_models_collaboration::governance::accountability::AccountabilityProjection;
use arkret_models_identity::{ActorProfile, AgentSelectorClaimValue};
use arkret_wire::{AccountId, DidCoreId, Event, RealmCommit, RealmId};
use async_trait::async_trait;

use crate::{AuthorityCommitTransaction, PersistenceResult};

/// One holder-signed `ak.profile.create` / `ak.profile.update` and the
/// Station-signed PCR Commit prepared at the head it was read against.
#[derive(Clone, Debug)]
pub struct ActorProfileAdmissionWrite {
    pub commit: AuthorityCommitTransaction,
    pub queued_at: chrono::DateTime<chrono::Utc>,
}

/// The profile value one accepted profile Event produced, with that exact
/// Event and its covering Commit.
#[derive(Clone, Debug)]
pub struct ActorProfileResultRecord {
    pub profile: ActorProfile,
    pub event: Event,
    pub commit: RealmCommit,
}

#[derive(Clone, Debug)]
pub enum ActorProfileAdmissionOutcome {
    /// This call accepted the Event, its Commit and the profile result.
    Committed(ActorProfileResultRecord),
    /// The exact Event was already accepted; this is the result it produced.
    Duplicate(ActorProfileResultRecord),
}

/// One issuer-signed `ak.identity.accountability_grant` and the PCR Commit
/// prepared at the head it was read against.
#[derive(Clone, Debug)]
pub struct AccountabilityGrantAdmissionWrite {
    pub commit: AuthorityCommitTransaction,
    pub queued_at: chrono::DateTime<chrono::Utc>,
}

/// One `identity_accountability` current row with its head Commit.
#[derive(Clone, Debug)]
pub struct IdentityAccountabilityRecord {
    pub realm_id: RealmId,
    pub value: AccountabilityProjection,
    pub commit: RealmCommit,
}

#[derive(Clone, Debug)]
pub enum AccountabilityGrantAdmissionOutcome {
    Committed(IdentityAccountabilityRecord),
    Duplicate(IdentityAccountabilityRecord),
}

/// One controller-signed `ak.agent.provision` and the controller PCR Commit
/// prepared at the head it was read against.
#[derive(Clone, Debug)]
pub struct AgentProvisionAdmissionWrite {
    pub commit: AuthorityCommitTransaction,
    pub queued_at: chrono::DateTime<chrono::Utc>,
}

/// The four typed current values one accepted `ak.agent.provision` wrote
/// (key-management.md section 3.6.3), with that exact Event and its Commit.
#[derive(Clone, Debug)]
pub struct AgentProvisionRecord {
    pub event: Event,
    pub commit: RealmCommit,
    pub provisioning: AgentProvisioningValue,
    pub accountability: AccountabilityProjection,
    pub selector: AgentSelectorClaimValue,
    pub declaration: AgentPcrGenesisDeclarationValue,
}

#[derive(Clone, Debug)]
pub enum AgentProvisionAdmissionOutcome {
    /// This call accepted the Event, its Commit and all four typed results.
    Committed(AgentProvisionRecord),
    /// The exact Event was already accepted; these are the results it wrote.
    Duplicate(AgentProvisionRecord),
}

/// One controller-executed Agent PCR `ak.realm.create` and the position-zero
/// Commit this Station prepared for the new Realm.
#[derive(Clone, Debug)]
pub struct AgentPcrGenesisAdmissionWrite {
    pub commit: AuthorityCommitTransaction,
    pub queued_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Debug)]
pub enum AgentPcrGenesisAdmissionOutcome {
    /// This call created the Agent PCR with its genesis Commit.
    Committed(RealmCommit),
    /// The exact genesis was already accepted with this Commit.
    Duplicate(RealmCommit),
}

/// One controller-executed Agent PCR control Event (`ak.agent.key.authorize`,
/// `ak.agent.key.revoke`, `ak.self.agent.{pause,resume,deactivate}`) and the
/// Agent PCR Commit prepared at the head it was read against.
#[derive(Clone, Debug)]
pub struct AgentControlAdmissionWrite {
    pub commit: AuthorityCommitTransaction,
    pub queued_at: chrono::DateTime<chrono::Utc>,
}

pub type AgentControlOriginSource = (
    arkret_models_identity::AgentSignerDependency,
    arkret_models_identity::AuthenticatedServiceResolution,
);

#[derive(Clone, Debug)]
pub enum AgentControlAdmissionOutcome {
    Committed(RealmCommit),
    Duplicate(RealmCommit),
}

#[async_trait]
pub trait ActorProfileStore: Send + Sync {
    /// Admit one profile Event under the owner's PCR authority lock: the
    /// signing device is active at the same cut, create/update presence and
    /// target match the PCR's one profile lineage, the registered projection
    /// applies, and every `accountable_principal_ids` entry has an active
    /// accountability record at the Commit time. Any refusal writes nothing.
    async fn admit_profile(
        &self,
        write: ActorProfileAdmissionWrite,
    ) -> PersistenceResult<ActorProfileAdmissionOutcome>;

    /// Admit one accountability grant in the issuer's PCR: the signing device
    /// is active at the same cut, the inner issuer proof and the Event proof
    /// verify against its accepted key, and the typed current row is written
    /// with the Commit. Any refusal writes nothing.
    async fn admit_accountability_grant(
        &self,
        write: AccountabilityGrantAdmissionWrite,
    ) -> PersistenceResult<AccountabilityGrantAdmissionOutcome>;

    /// Admit one controller-signed `ak.agent.provision` in the controller
    /// PCR: the signing device is active at the same cut, the payload binds
    /// the envelope, neither the Agent nor the declared Agent PCR id is
    /// already declared, and the four typed results are written with the
    /// Commit. Any refusal writes nothing.
    async fn admit_agent_provision(
        &self,
        write: AgentProvisionAdmissionWrite,
    ) -> PersistenceResult<AgentProvisionAdmissionOutcome>;

    /// Admit one Agent PCR genesis: an accepted provision in the controller's
    /// PCR declares its realm id, the controller's signing device is active
    /// at the Commit, and the Realm authority, genesis Commit and create
    /// results are written together. Any refusal writes nothing.
    async fn admit_agent_pcr_genesis(
        &self,
        write: AgentPcrGenesisAdmissionWrite,
    ) -> PersistenceResult<AgentPcrGenesisAdmissionOutcome>;

    /// Admit one Agent PCR control Event under the Agent PCR lock: the
    /// provision binding, the controller device's active status and proof,
    /// the controller's accountability for the Agent and the kind's
    /// lifecycle or key-set gate all hold at that cut, and the Event, its
    /// Commit and the registered Agent results are written together. Any
    /// refusal writes nothing.
    async fn admit_agent_control_event(
        &self,
        write: AgentControlAdmissionWrite,
    ) -> PersistenceResult<AgentControlAdmissionOutcome>;

    async fn admit_agent_control_event_with_origin(
        &self,
        write: AgentControlAdmissionWrite,
        origin: Option<AgentControlOriginSource>,
    ) -> PersistenceResult<AgentControlAdmissionOutcome> {
        if origin.is_some() {
            return Err(crate::PersistenceError::Internal(
                "atomic Agent origin admission unavailable".to_owned(),
            ));
        }
        self.admit_agent_control_event(write).await
    }

    /// Renew an already active key without the fresh-key pairing ceremony.
    /// The current key material and immutable provision ceiling are checked
    /// under the same lock as the signed supersession basis and Commit.
    async fn admit_agent_same_key_renewal(
        &self,
        _write: AgentControlAdmissionWrite,
        _origin: Option<AgentControlOriginSource>,
    ) -> PersistenceResult<AgentControlAdmissionOutcome> {
        Err(crate::PersistenceError::Internal(
            "atomic Agent same-key renewal unavailable".to_owned(),
        ))
    }

    /// The current profile of the account's local PCR, with the exact Event
    /// and Commit that produced it.
    async fn current_profile(
        &self,
        account: &AccountId,
    ) -> PersistenceResult<Option<ActorProfileResultRecord>>;

    /// Whether some committed `identity_accountability` record with this
    /// issuer and subject verifies at `at`.
    async fn accountability_verified_at(
        &self,
        issuer_id: &DidCoreId,
        subject_id: &DidCoreId,
        at: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<bool>;
}
