use std::collections::BTreeMap;
use std::sync::Arc;

use arkret_identifiers::{BlobRef, Did, DidCoreId, EventId, Hash};
use arkret_models_collaboration::agent_operations::AgentLifecycleState;
use arkret_models_collaboration::objects::account_status::AccountStatus;
use arkret_models_identity::service_identity::{
    ServiceRegistrationKey, ServiceRegistrationOutcome,
};
use arkret_models_identity::{DeviceSummaryVerificationSource, DeviceSummaryVerificationState};
use arkret_wire::{AccountId, DidUrl, OpaqueLocalId, TrustDomainId};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use coland_storage::{AccountPk, AgentRuntimeEnqueueOutcome, EnqueueAgentRuntimeMessage};
use ed25519_dalek::Signer as _;
use parking_lot::Mutex;
use serde_json::Value;

use crate::ServiceError;

/// Sign canonical payload bytes with the SDK-owned detached-JWS `kid` binding
/// required by [`arkret_wire::PayloadSignature`].
pub fn sign_ed25519_detached_jws(
    canonical_bytes: &[u8],
    verification_method: &DidUrl,
    signing_key: &ed25519_dalek::SigningKey,
) -> Result<String, String> {
    let signing_input = arkret_signatures::proof::ed25519_detached_jws_signing_input(
        canonical_bytes,
        Some(verification_method.as_str()),
    )
    .map_err(|error| error.to_string())?;
    let signature = signing_key.sign(signing_input.as_bytes());
    arkret_signatures::proof::ed25519_detached_jws_from_signature(
        &signature.to_bytes(),
        Some(verification_method.as_str()),
    )
    .map_err(|error| error.to_string())
}

/// SDK [`arkret_wire::PayloadSigner`] adapter over a locally held Ed25519 key.
pub struct Ed25519PayloadSigner {
    signing_key: ed25519_dalek::SigningKey,
    signer_did: Did,
    verification_method: DidUrl,
}

impl Ed25519PayloadSigner {
    #[must_use]
    pub fn from_seed(seed: [u8; 32], signer_did: Did, verification_method: DidUrl) -> Self {
        Self {
            signing_key: ed25519_dalek::SigningKey::from_bytes(&seed),
            signer_did,
            verification_method,
        }
    }

    #[must_use]
    pub fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        self.signing_key.verifying_key()
    }
}

impl arkret_wire::PayloadSigner for Ed25519PayloadSigner {
    fn signer_did(&self) -> &Did {
        &self.signer_did
    }

    fn verification_method_id(&self) -> &DidUrl {
        &self.verification_method
    }

    fn sign_payload(
        &self,
        canonical_bytes: &[u8],
    ) -> arkret_wire::Result<arkret_wire::PayloadSignature> {
        let payload_digest = Hash::new(arkret_canonical::sha256_digest(canonical_bytes))?;
        let jws = sign_ed25519_detached_jws(
            canonical_bytes,
            &self.verification_method,
            &self.signing_key,
        )
        .map_err(arkret_wire::WireError::Protocol)?;
        Ok(arkret_wire::PayloadSignature {
            verification_method: self.verification_method.clone(),
            payload_digest,
            created_at: Utc::now(),
            jws,
        })
    }
}

pub use coland_domain::identity::{ContactRecord, ContactRequestSlotState};
pub use coland_storage::MimiConsentCorrelationRecord as MimiConsentCorrelation;

/// The coordinates one `ak.direct_conversation.bound` endorsement settles.
///
/// `contact-and-direct-conversation.md` §8.3: the binding is written once and
/// never retired, so this carries no lifecycle state, no `supersedes` ref and
/// no separately mutable `mls_group_id`; the MLS group is uniquely derived
/// from the immutable Realm scope.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirectConversationBindingRecord {
    pub participants_unordered: Vec<String>,
    pub realm_id: String,
    pub main_strand_id: String,
    pub created_at: DateTime<Utc>,
    /// One Event that endorsed these coordinates. The or_set can hold an
    /// endorsement per participant; this is the lowest endorsing `actor_id`'s,
    /// so every replica names the same one. It is evidence, not a head — the
    /// binding has no successor to point at.
    pub binding_event_ref: String,
}

use crate::ServiceResult;

fn lifecycle_status_from_wire(value: &str) -> AccountStatus {
    match value {
        "erased" => AccountStatus::ErasurePending,
        _ => AccountStatus::from_wire(value).unwrap_or_else(|| {
            tracing::warn!(state = value, "unknown account lifecycle state");
            AccountStatus::Suspended
        }),
    }
}

#[derive(Clone, Debug)]
pub struct FindAccountByActorQuery {
    pub account_id: AccountId,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccountIdentity {
    pub account_pk: AccountPk,
    pub account_id: AccountId,
}

#[derive(Clone, Debug)]
pub struct AccountProfileState {
    pub pk: AccountPk,
    pub account_id: AccountId,
    pub principal_id: DidCoreId,
    pub localpart: String,
    pub display_name: Option<String>,
    pub bio: Option<String>,
    pub avatar_blob_ref: Option<BlobRef>,
    pub created_at: DateTime<Utc>,
}

impl AccountProfileState {
    pub fn handle(&self) -> String {
        if self.localpart.is_empty() {
            String::new()
        } else {
            format!("@{}", self.localpart)
        }
    }
}

pub use coland_storage::{
    AccountLifecycleRecord as AccountLifecycleState,
    AccountLocalpartRecord as AccountLocalpartState,
};

#[derive(Clone, Debug)]
pub struct RegisterAccountCommand {
    pub account_id: AccountId,
    pub localpart: String,
    pub display_name: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Debug)]
pub struct AccountDataState {
    pub actor_id: String,
    pub account_data_key: String,
    pub revision: u64,
    pub payload: Value,
    pub tombstone: bool,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug)]
pub enum AccountDataCasOutcome {
    Applied(AccountDataState),
    Conflict(Option<AccountDataState>),
}

#[async_trait]
pub trait AccountDataPort: Send + Sync {
    async fn entry(
        &self,
        actor_id: &str,
        account_data_key: &str,
    ) -> ServiceResult<Option<AccountDataState>>;
    async fn entries_for_actor(&self, actor_id: &str) -> ServiceResult<Vec<AccountDataState>>;
    async fn changes_after(
        &self,
        actor_id: &str,
        position: u64,
    ) -> ServiceResult<Vec<AccountDataChangeState>>;
    async fn latest_change_position(&self, actor_id: &str) -> ServiceResult<u64>;
    async fn change_position_is_replayable(
        &self,
        actor_id: &str,
        position: u64,
    ) -> ServiceResult<bool>;
    async fn prune_changes_before(&self, cutoff: DateTime<Utc>) -> ServiceResult<u64>;
    async fn snapshot_for_actor(
        &self,
        actor_id: &str,
    ) -> ServiceResult<(Vec<AccountDataState>, u64)>;
    async fn compare_and_set(
        &self,
        entry: AccountDataState,
        expected_revision: u64,
    ) -> ServiceResult<AccountDataCasOutcome>;
}

#[derive(Clone, Debug)]
pub struct AccountDataChangeState {
    pub position: u64,
    pub entry: AccountDataState,
}

#[derive(Clone)]
pub struct AccountDataService {
    account_data: Arc<dyn AccountDataPort>,
}

#[async_trait]
pub trait MimiConsentCorrelationPort: Send + Sync {
    async fn save_correlation(&self, correlation: MimiConsentCorrelation) -> ServiceResult<()>;
    async fn correlation(&self, consent_id: &str) -> ServiceResult<Option<MimiConsentCorrelation>>;
}

#[derive(Clone)]
pub struct ConsentService {
    mimi_correlations: Arc<dyn MimiConsentCorrelationPort>,
}

#[async_trait]
pub trait ContactPort: Send + Sync {
    async fn contact_any(
        &self,
        requester_id: &arkret_wire::ActorId,
        target_id: &arkret_wire::ActorId,
    ) -> ServiceResult<Option<ContactRecord>>;
    async fn contacts_for_actor(
        &self,
        actor_id: &arkret_wire::ActorId,
    ) -> ServiceResult<Vec<ContactRecord>>;
    async fn save_contact(&self, contact: ContactRecord) -> ServiceResult<()>;
    async fn save_contact_if_updated_at(
        &self,
        expected_updated_at: DateTime<Utc>,
        contact: ContactRecord,
    ) -> ServiceResult<bool>;
}

#[async_trait]
pub trait InviteReceivePolicyPort: Send + Sync {
    async fn save_policy(
        &self,
        account_id: &AccountId,
        policy: arkret_models_collaboration::governance::invite_addressing::InviteReceivePolicy,
    ) -> ServiceResult<()>;
    async fn policies(
        &self,
    ) -> ServiceResult<
        Vec<(
            AccountId,
            arkret_models_collaboration::governance::invite_addressing::InviteReceivePolicy,
        )>,
    >;
}

#[derive(Clone)]
pub struct ContactService {
    contacts: Arc<dyn ContactPort>,
    invite_policies: Arc<dyn InviteReceivePolicyPort>,
    runtime_invite_policies: Arc<
        Mutex<
            BTreeMap<
                arkret_wire::AccountId,
                arkret_models_collaboration::governance::invite_addressing::InviteReceivePolicy,
            >,
        >,
    >,
    runtime_policy_reload: Arc<tokio::sync::Mutex<()>>,
}

impl ContactService {
    pub async fn hydrate_runtime(&self) -> ServiceResult<()> {
        let _reload = self.runtime_policy_reload.lock().await;
        self.replace_runtime_invite_policies(self.invite_policies.policies().await?);
        Ok(())
    }

    pub fn new(
        contacts: Arc<dyn ContactPort>,
        invite_policies: Arc<dyn InviteReceivePolicyPort>,
    ) -> Self {
        Self {
            contacts,
            invite_policies,
            runtime_invite_policies: Arc::new(Mutex::new(BTreeMap::new())),
            runtime_policy_reload: Arc::new(tokio::sync::Mutex::new(())),
        }
    }

    pub async fn contact_any(
        &self,
        requester_id: &arkret_wire::ActorId,
        target_id: &arkret_wire::ActorId,
    ) -> ServiceResult<Option<ContactRecord>> {
        self.contacts.contact_any(requester_id, target_id).await
    }

    pub async fn contacts_for_actor(
        &self,
        actor_id: &arkret_wire::ActorId,
    ) -> ServiceResult<Vec<ContactRecord>> {
        self.contacts.contacts_for_actor(actor_id).await
    }

    pub async fn save_contact(&self, contact: ContactRecord) -> ServiceResult<()> {
        self.contacts.save_contact(contact).await
    }

    pub async fn save_contact_if_updated_at(
        &self,
        expected_updated_at: DateTime<Utc>,
        contact: ContactRecord,
    ) -> ServiceResult<bool> {
        self.contacts
            .save_contact_if_updated_at(expected_updated_at, contact)
            .await
    }

    pub async fn save_invite_policy(
        &self,
        account_id: &AccountId,
        policy: arkret_models_collaboration::governance::invite_addressing::InviteReceivePolicy,
    ) -> ServiceResult<()> {
        coland_storage::validate_invite_policy_account(account_id, &policy)?;
        let _reload = self.runtime_policy_reload.lock().await;
        self.invite_policies
            .save_policy(account_id, policy.clone())
            .await?;
        self.runtime_invite_policies
            .lock()
            .insert(account_id.clone(), policy);
        Ok(())
    }

    pub fn replace_runtime_invite_policies(
        &self,
        policies: impl IntoIterator<
            Item = (
                AccountId,
                arkret_models_collaboration::governance::invite_addressing::InviteReceivePolicy,
            ),
        >,
    ) {
        *self.runtime_invite_policies.lock() = policies.into_iter().collect();
    }

    /// Seed an isolated fixture policy. Production refreshes only the durable
    /// result of an exact committed command through `hydrate_runtime`.
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn apply_committed_invite_policy(
        &self,
        account_id: AccountId,
        policy: arkret_models_collaboration::governance::invite_addressing::InviteReceivePolicy,
    ) {
        self.runtime_invite_policies
            .lock()
            .insert(account_id, policy);
    }

    pub fn invite_policy(
        &self,
        account_id: &arkret_wire::AccountId,
    ) -> Option<arkret_models_collaboration::governance::invite_addressing::InviteReceivePolicy>
    {
        self.runtime_invite_policies.lock().get(account_id).cloned()
    }
}

impl ConsentService {
    pub fn new(mimi_correlations: Arc<dyn MimiConsentCorrelationPort>) -> Self {
        Self { mimi_correlations }
    }

    pub async fn save_mimi_correlation(
        &self,
        correlation: MimiConsentCorrelation,
    ) -> ServiceResult<()> {
        self.mimi_correlations.save_correlation(correlation).await
    }

    pub async fn mimi_correlation(
        &self,
        consent_id: &str,
    ) -> ServiceResult<Option<MimiConsentCorrelation>> {
        self.mimi_correlations.correlation(consent_id).await
    }
}

impl AccountDataService {
    pub fn new(account_data: Arc<dyn AccountDataPort>) -> Self {
        Self { account_data }
    }

    pub async fn entry(
        &self,
        actor_id: &str,
        account_data_key: &str,
    ) -> ServiceResult<Option<AccountDataState>> {
        self.account_data.entry(actor_id, account_data_key).await
    }

    pub async fn entries_for_actor(&self, actor_id: &str) -> ServiceResult<Vec<AccountDataState>> {
        self.account_data.entries_for_actor(actor_id).await
    }

    pub async fn changes_after(
        &self,
        actor_id: &str,
        position: u64,
    ) -> ServiceResult<Vec<AccountDataChangeState>> {
        self.account_data.changes_after(actor_id, position).await
    }

    pub async fn latest_change_position(&self, actor_id: &str) -> ServiceResult<u64> {
        self.account_data.latest_change_position(actor_id).await
    }

    pub async fn change_position_is_replayable(
        &self,
        actor_id: &str,
        position: u64,
    ) -> ServiceResult<bool> {
        self.account_data
            .change_position_is_replayable(actor_id, position)
            .await
    }

    pub async fn prune_changes_before(&self, cutoff: DateTime<Utc>) -> ServiceResult<u64> {
        self.account_data.prune_changes_before(cutoff).await
    }

    pub async fn snapshot_for_actor(
        &self,
        actor_id: &str,
    ) -> ServiceResult<(Vec<AccountDataState>, u64)> {
        self.account_data.snapshot_for_actor(actor_id).await
    }

    pub async fn compare_and_set(
        &self,
        entry: AccountDataState,
        expected_revision: u64,
    ) -> ServiceResult<AccountDataCasOutcome> {
        self.account_data
            .compare_and_set(entry, expected_revision)
            .await
    }
}

#[derive(Clone, Debug, Default)]
pub struct ListActiveDeviceActorsQuery;

#[derive(Clone, Debug)]
pub struct FindDeviceQuery {
    pub actor_id: String,
    pub device_id: String,
}

#[derive(Clone, Debug)]
pub struct DeviceIdentity {
    pub actor_id: String,
    pub device_id: String,
    pub display_name: Option<String>,
    pub verification_state: String,
    pub payload: Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
}

/// Fold the durable checkpoint facts and the current PCR generation into the
/// account-facing verification projection.
///
/// Device verification is intentionally a read-side fold, not a second stored
/// lifecycle axis. The authorization binding kind is the closed provenance
/// source, while the current generation result can make a formerly verified
/// exact-key checkpoint stale without erasing that provenance.
#[must_use]
pub fn fold_device_verification_checkpoint(
    stored_state: &str,
    has_successful_confirmation: bool,
    authorization_binding_kind: Option<&str>,
    generation_fenced: bool,
) -> (
    DeviceSummaryVerificationState,
    Option<DeviceSummaryVerificationSource>,
) {
    let source = match authorization_binding_kind {
        Some("registration_anchor") => Some(DeviceSummaryVerificationSource::Genesis),
        Some("accepted_device") => Some(DeviceSummaryVerificationSource::PairingCode),
        Some("pcr_recovery") => Some(DeviceSummaryVerificationSource::Recovery),
        _ => None,
    };
    let had_verified_checkpoint =
        stored_state == "verified" && has_successful_confirmation && source.is_some();

    let state = if had_verified_checkpoint && generation_fenced {
        DeviceSummaryVerificationState::Stale
    } else {
        match stored_state {
            "verified" if had_verified_checkpoint => DeviceSummaryVerificationState::Verified,
            "stale" if source.is_some() => DeviceSummaryVerificationState::Stale,
            _ => DeviceSummaryVerificationState::Unresolved,
        }
    };

    let source = (state != DeviceSummaryVerificationState::Unresolved)
        .then_some(source)
        .flatten();
    (state, source)
}

/// Current facts required before a verification checkpoint can authorize a
/// live device action. The accepted authorization Event is the durable
/// checkpoint; the `current_*` values are the projection presented for use.
#[derive(Clone, Copy, Debug)]
pub struct DeviceCheckpointLiveFacts<'a> {
    pub lifecycle_active: bool,
    pub verification_state: DeviceSummaryVerificationState,
    pub verification_source: Option<DeviceSummaryVerificationSource>,
    pub revocation_gate_active: bool,
    pub checkpoint_authorization_event_id: Option<&'a str>,
    pub current_authorization_event_id: Option<&'a str>,
    pub checkpoint_generation_ref: Option<u64>,
    pub current_generation_ref: Option<u64>,
    pub checkpoint_signing_key: Option<&'a str>,
    pub current_signing_key: Option<&'a str>,
    pub checkpoint_hpke_key: Option<&'a str>,
    pub current_hpke_key: Option<&'a str>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeviceCheckpointIneligibility {
    LifecycleNotActive,
    VerificationNotCurrent,
    MissingVerificationSource,
    RevocationGateNotActive,
    AuthorizationEventMismatch,
    GenerationMismatch,
    SigningKeyMismatch,
    HpkeKeyMismatch,
}

/// Evaluate the complete live-authorization fence for one durable device
/// verification checkpoint.
///
/// Revocation and revocation-pending are represented by a non-active
/// revocation gate and do not rewrite the orthogonal verification projection.
/// Generation or exact-key mismatch prevents use of the former checkpoint;
/// callers may separately project generation mismatch as `stale`.
pub fn evaluate_device_checkpoint_live_eligibility(
    facts: DeviceCheckpointLiveFacts<'_>,
) -> Result<(), DeviceCheckpointIneligibility> {
    if !facts.lifecycle_active {
        return Err(DeviceCheckpointIneligibility::LifecycleNotActive);
    }
    if facts.verification_state != DeviceSummaryVerificationState::Verified {
        return Err(DeviceCheckpointIneligibility::VerificationNotCurrent);
    }
    if facts.verification_source.is_none() {
        return Err(DeviceCheckpointIneligibility::MissingVerificationSource);
    }
    if !facts.revocation_gate_active {
        return Err(DeviceCheckpointIneligibility::RevocationGateNotActive);
    }
    if !exact_present_match(
        facts.checkpoint_authorization_event_id,
        facts.current_authorization_event_id,
    ) {
        return Err(DeviceCheckpointIneligibility::AuthorizationEventMismatch);
    }
    if facts.checkpoint_generation_ref.is_none()
        || facts.checkpoint_generation_ref != facts.current_generation_ref
    {
        return Err(DeviceCheckpointIneligibility::GenerationMismatch);
    }
    if !exact_present_match(facts.checkpoint_signing_key, facts.current_signing_key) {
        return Err(DeviceCheckpointIneligibility::SigningKeyMismatch);
    }
    if !exact_present_match(facts.checkpoint_hpke_key, facts.current_hpke_key) {
        return Err(DeviceCheckpointIneligibility::HpkeKeyMismatch);
    }
    Ok(())
}

fn exact_present_match(checkpoint: Option<&str>, current: Option<&str>) -> bool {
    matches!(
        (checkpoint.map(str::trim), current.map(str::trim)),
        (Some(checkpoint), Some(current)) if !checkpoint.is_empty() && checkpoint == current
    )
}

#[async_trait]
pub trait DeviceKeyPort: Send + Sync {
    async fn save_bundle(
        &self,
        authorization: &coland_storage::DeviceRevocationGateSelector,
        payload: Value,
    ) -> ServiceResult<()>;
    async fn bundle(&self, actor_id: &str, device_id: &str) -> ServiceResult<Option<Value>>;
}

#[async_trait]
pub trait OneTimeKeyPort: Send + Sync {
    async fn save_keys(
        &self,
        authorization: &coland_storage::DeviceRevocationGateSelector,
        keys: Vec<Value>,
    ) -> ServiceResult<()>;
    async fn claim_key(&self, actor_id: &str, device_id: &str) -> ServiceResult<Option<Value>>;
}

#[derive(Clone)]
pub struct KeyMaterialService {
    device_keys: Arc<dyn DeviceKeyPort>,
    one_time_keys: Arc<dyn OneTimeKeyPort>,
}

impl KeyMaterialService {
    pub fn new(
        device_keys: Arc<dyn DeviceKeyPort>,
        one_time_keys: Arc<dyn OneTimeKeyPort>,
    ) -> Self {
        Self {
            device_keys,
            one_time_keys,
        }
    }

    pub async fn save_bundle(
        &self,
        authorization: &coland_storage::DeviceRevocationGateSelector,
        payload: Value,
    ) -> ServiceResult<()> {
        self.device_keys.save_bundle(authorization, payload).await
    }

    pub async fn bundle(&self, actor_id: &str, device_id: &str) -> ServiceResult<Option<Value>> {
        self.device_keys.bundle(actor_id, device_id).await
    }

    pub async fn save_one_time_keys(
        &self,
        authorization: &coland_storage::DeviceRevocationGateSelector,
        keys: Vec<Value>,
    ) -> ServiceResult<()> {
        self.one_time_keys.save_keys(authorization, keys).await
    }

    pub async fn claim_one_time_key(
        &self,
        actor_id: &str,
        device_id: &str,
    ) -> ServiceResult<Option<Value>> {
        self.one_time_keys.claim_key(actor_id, device_id).await
    }
}

#[derive(Clone, Debug)]
pub struct SaveDeviceCommand {
    pub actor_id: String,
    pub device_id: String,
    pub display_name: Option<String>,
    pub device: DeviceIdentity,
}

#[derive(Clone, Debug)]
pub struct FindAgentControllerQuery {
    pub agent_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentController {
    pub controller_principal_id: String,
}

#[async_trait]
pub trait AccountLookupPort: Send + Sync {
    async fn find_account_by_actor(
        &self,
        account_id: &AccountId,
    ) -> ServiceResult<Option<AccountIdentity>>;
    async fn account_by_id(
        &self,
        account_pk: AccountPk,
    ) -> ServiceResult<Option<AccountProfileState>>;
    async fn register_account(
        &self,
        command: RegisterAccountCommand,
    ) -> ServiceResult<AccountIdentity>;
    async fn account(&self, account_id: &AccountId) -> ServiceResult<Option<AccountProfileState>>;
    async fn accounts(&self) -> ServiceResult<Vec<AccountProfileState>>;
    async fn save_account(&self, account: AccountProfileState) -> ServiceResult<()>;
    async fn delete_account(&self, account_id: &AccountId) -> ServiceResult<()>;
    async fn account_localparts(
        &self,
        account_pk: AccountPk,
    ) -> ServiceResult<Vec<AccountLocalpartState>>;
    async fn localpart_owner(
        &self,
        localpart: &str,
    ) -> ServiceResult<Option<AccountLocalpartState>>;
    async fn add_localpart(
        &self,
        account_pk: AccountPk,
        localpart: &str,
        primary: bool,
    ) -> ServiceResult<AccountLocalpartState>;
    async fn remove_localpart(&self, account_pk: AccountPk, localpart: &str) -> ServiceResult<()>;
    async fn clear_localparts(&self, account_pk: AccountPk) -> ServiceResult<()>;
    async fn record_handle_release(
        &self,
        localpart: &str,
        released_at: DateTime<Utc>,
    ) -> ServiceResult<()>;
    async fn save_account_lifecycle(
        &self,
        account_pk: AccountPk,
        actor_id: &str,
        lifecycle: AccountLifecycleState,
    ) -> ServiceResult<()>;
    async fn delete_account_lifecycle(
        &self,
        account_pk: AccountPk,
        actor_id: &str,
    ) -> ServiceResult<()>;
    async fn account_lifecycles(&self) -> ServiceResult<Vec<(AccountId, AccountLifecycleState)>> {
        Ok(Vec::new())
    }
}

#[async_trait]
pub trait DeviceDirectoryPort: Send + Sync {
    async fn list_active_device_actors(&self) -> ServiceResult<Vec<String>>;
    async fn devices(&self) -> ServiceResult<Vec<DeviceIdentity>>;
    async fn find_device(
        &self,
        actor_id: &str,
        device_id: &str,
    ) -> ServiceResult<Option<DeviceIdentity>>;
    async fn save_device(&self, command: SaveDeviceCommand) -> ServiceResult<()>;
    async fn save_device_if_absent(&self, device: DeviceIdentity) -> ServiceResult<bool>;
    async fn devices_for_actor(&self, actor_id: &str) -> ServiceResult<Vec<DeviceIdentity>>;
}

#[async_trait]
pub trait AgentDirectoryPort: Send + Sync {
    async fn find_agent_controller(&self, agent_id: &str)
    -> ServiceResult<Option<AgentController>>;
}

#[derive(Clone)]
pub struct IdentityService {
    accounts: Arc<dyn AccountLookupPort>,
    devices: Arc<dyn DeviceDirectoryPort>,
    agents: Arc<dyn AgentDirectoryPort>,
    account_registration_attempts: AccountRegistrationAttempts,
    account_lifecycles: Arc<Mutex<BTreeMap<String, AccountLifecycleState>>>,
}

type AccountRegistrationAttempts = Arc<Mutex<BTreeMap<String, (DateTime<Utc>, u32)>>>;

#[derive(Clone, Debug)]
pub struct ActivateAgentRuntimeCommand {
    pub agent_id: String,
    pub approval_request_id: OpaqueLocalId,
    pub runtime_key_binding_digest: String,
    pub pairing_request_id: OpaqueLocalId,
    pub paired_request_digest: String,
    pub authorized_event_ref: String,
    pub authorized_verification_method: String,
    pub authorized_public_key_digest: String,
    /// Exact controller Event retained with its producer proof.
    pub frozen_authorize_event: arkret_wire::Event,
    /// Authority-signed commit that admitted `frozen_authorize_event`. It is
    /// the sole activation precondition: one `RealmCommit` carries exactly one
    /// `event_ref`, so this names the Event and the commit that settled it.
    pub authorize_ref: arkret_wire::CommittedEventRef,
    pub status: AgentLifecycleState,
    pub authorized_key_event: arkret_wire::Event,
    pub signer_resolution_evidence_ref: Option<arkret_wire::SignerEvidenceRef>,
    pub current_signer_evidence:
        Option<arkret_models_identity::authenticated_signer_resolution_evidence::AuthenticatedSignerResolutionEvidence>,
    pub authorized_at: DateTime<Utc>,
}

#[derive(Clone, Debug)]
pub struct RecordAgentPairingCommitIntentCommand {
    pub agent_id: String,
    pub approval_request_id: OpaqueLocalId,
    pub runtime_key_binding_digest: String,
    pub pairing_request_id: OpaqueLocalId,
    pub request_digest: String,
    pub authorize_event_id: String,
    pub key_authorization_event: arkret_wire::Event,
}

pub use coland_storage::PendingAgentPairingCommitIntent as AgentPairingCommitIntentState;

#[derive(Clone, Debug, PartialEq)]
pub struct AgentPairingState {
    pub id: String,
    pub controller_principal_id: String,
    pub principal_control_realm_id: String,
    pub controller_authorization_ref: DidUrl,
    pub display_name: Option<String>,
    pub agent_slug: Option<String>,
    pub avatar_blob_ref: Option<String>,
    pub state: AgentLifecycleState,
    pub requested_scope: Option<Value>,
    pub accountability: Option<Value>,
    pub provision_event_refs: Option<Value>,
    pub pairing_request_id: Option<OpaqueLocalId>,
    pub paired_pairing_request_id: Option<OpaqueLocalId>,
    pub paired_request_digest: Option<String>,
    pub pending_pairing_commit_intent: Option<AgentPairingCommitIntentState>,
    pub pairing_code: Option<String>,
    pub pairing_expires_at: Option<DateTime<Utc>>,
    pub approval_request_id: Option<OpaqueLocalId>,
    pub controller_account_pk: Option<AccountPk>,
    pub recipient_id: Option<String>,
    pub runtime_key_binding_digest: Option<String>,
    pub runtime_public_key_digest: Option<String>,
    pub runtime_attestation_digest: Option<String>,
    pub runtime_proof_verified_at: Option<DateTime<Utc>>,
    pub approval_notification_id: Option<uuid::Uuid>,
    pub runtime_key_request:
        Option<arkret_models_collaboration::agent_scope::AgentRuntimeApprovalRequestBody>,
    pub approval_requested_at: Option<DateTime<Utc>>,
    pub authorized_event_ref: Option<String>,
    pub authorized_verification_method: Option<String>,
    pub authorized_public_key_digest: Option<String>,
    pub authorized_key_event: Option<arkret_wire::Event>,
    pub signer_resolution_evidence_ref: Option<arkret_wire::SignerEvidenceRef>,
    pub current_signer_evidence:
        Option<arkret_models_identity::authenticated_signer_resolution_evidence::AuthenticatedSignerResolutionEvidence>,
    pub state_changed_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct OpenAgentPairingHandle {
    pub pairing_request_id: OpaqueLocalId,
    pub pairing_code: String,
    pub expires_at: DateTime<Utc>,
    pub pending_runtime_key_request:
        Option<arkret_models_collaboration::agent_scope::AgentRuntimeApprovalRequestBody>,
}

impl OpenAgentPairingHandle {
    pub fn is_live_at(&self, now: DateTime<Utc>) -> bool {
        self.expires_at > now
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct ActiveAgentRuntimeBinding {
    pub completed_pairing_request_id: OpaqueLocalId,
    pub authorized_event_ref: EventId,
    pub verification_method: DidUrl,
    pub public_key_digest: Hash,
    pub key_authorization_event: arkret_wire::Event,
    pub signer_resolution_evidence_ref: arkret_wire::SignerEvidenceRef,
    pub current_signer_evidence:
        arkret_models_identity::authenticated_signer_resolution_evidence::AuthenticatedSignerResolutionEvidence,
}

#[derive(Clone, Debug, PartialEq)]
pub struct AgentRuntimeBindings {
    pub open_handle: Option<OpenAgentPairingHandle>,
    pub active_binding: Option<ActiveAgentRuntimeBinding>,
}

impl AgentPairingState {
    pub fn new(
        id: String,
        controller_principal_id: String,
        principal_control_realm_id: String,
        controller_authorization_ref: DidUrl,
        state: AgentLifecycleState,
        created_at: DateTime<Utc>,
    ) -> Self {
        Self {
            id,
            controller_principal_id,
            principal_control_realm_id,
            controller_authorization_ref,
            display_name: None,
            agent_slug: None,
            avatar_blob_ref: None,
            state,
            requested_scope: None,
            accountability: None,
            provision_event_refs: None,
            pairing_request_id: None,
            paired_pairing_request_id: None,
            paired_request_digest: None,
            pending_pairing_commit_intent: None,
            pairing_code: None,
            pairing_expires_at: None,
            approval_request_id: None,
            controller_account_pk: None,
            recipient_id: None,
            runtime_key_binding_digest: None,
            runtime_public_key_digest: None,
            runtime_attestation_digest: None,
            runtime_proof_verified_at: None,
            approval_notification_id: None,
            runtime_key_request: None,
            approval_requested_at: None,
            authorized_event_ref: None,
            authorized_verification_method: None,
            authorized_public_key_digest: None,
            authorized_key_event: None,
            signer_resolution_evidence_ref: None,
            current_signer_evidence: None,
            state_changed_at: Some(created_at),
            created_at,
            updated_at: created_at,
        }
    }

    /// Reconstruct the two protocol states hidden behind the flat persistence
    /// columns. Partial tuples are rejected instead of being interpreted as a
    /// weaker state.
    pub fn runtime_bindings(&self) -> Result<AgentRuntimeBindings, String> {
        let active_binding = match self.authorized_event_ref.as_ref() {
            Some(authorized_event_ref) => {
                let completed_pairing_request_id =
                    self.paired_pairing_request_id.clone().ok_or_else(|| {
                        "active Agent runtime binding is missing paired_pairing_request_id"
                            .to_owned()
                    })?;
                let authorized_event_ref =
                    EventId::new(authorized_event_ref.clone()).map_err(|error| {
                        format!("active Agent runtime authorized_event_ref is invalid: {error}")
                    })?;
                let verification_method = self
                    .authorized_verification_method
                    .clone()
                    .ok_or_else(|| {
                        "active Agent runtime binding is missing verification_method".to_owned()
                    })
                    .and_then(|value| {
                        DidUrl::new(value).map_err(|error| {
                            format!("active Agent runtime verification_method is invalid: {error}")
                        })
                    })?;
                let public_key_digest = self
                    .authorized_public_key_digest
                    .clone()
                    .ok_or_else(|| {
                        "active Agent runtime binding is missing public_key_digest".to_owned()
                    })
                    .and_then(|value| {
                        Hash::new(value).map_err(|error| {
                            format!("active Agent runtime public_key_digest is invalid: {error}")
                        })
                    })?;
                let key_authorization_event =
                    self.authorized_key_event.clone().ok_or_else(|| {
                        "active Agent runtime binding is missing key_authorization_event".to_owned()
                    })?;
                let signer_resolution_evidence_ref =
                    self.signer_resolution_evidence_ref.clone().ok_or_else(|| {
                        "active Agent runtime binding is missing signer evidence reference"
                            .to_owned()
                    })?;
                let current_signer_evidence =
                    self.current_signer_evidence.clone().ok_or_else(|| {
                        "active Agent runtime binding is missing current signer evidence".to_owned()
                    })?;
                // The evidence is content-addressed: recompute the address from
                // the carried bytes instead of trusting the stored sibling.
                if !current_signer_evidence
                    .matches_ref(&signer_resolution_evidence_ref)
                    .map_err(|error| error.to_string())?
                {
                    return Err(
                        "active Agent runtime signer evidence reference does not address its evidence"
                            .to_owned(),
                    );
                }
                let key = arkret_models_identity::agent_signer_evidence::AgentAuthorizedSigningKey::from_event(&key_authorization_event).map_err(|error| error.to_string())?;
                if key.agent_id.as_str() != self.id
                    || key.agent_key_authorize_event_id != authorized_event_ref
                    || key.verification_method != verification_method
                    || key.public_key_digest != public_key_digest
                {
                    return Err(
                        "active Agent authorization Event does not match its indexed key"
                            .to_owned(),
                    );
                }
                Some(ActiveAgentRuntimeBinding {
                    completed_pairing_request_id,
                    authorized_event_ref,
                    verification_method,
                    public_key_digest,
                    key_authorization_event,
                    signer_resolution_evidence_ref,
                    current_signer_evidence,
                })
            }
            None => {
                if self.paired_pairing_request_id.is_some()
                    || self.authorized_verification_method.is_some()
                    || self.authorized_public_key_digest.is_some()
                    || self.authorized_key_event.is_some()
                    || self.signer_resolution_evidence_ref.is_some()
                    || self.current_signer_evidence.is_some()
                {
                    return Err(
                        "Agent runtime authorization columns contain a partial active binding"
                            .to_owned(),
                    );
                }
                None
            }
        };

        let open_handle = match self.pairing_request_id.as_ref() {
            Some(pairing_request_id)
                if self.paired_pairing_request_id.as_deref()
                    != Some(pairing_request_id.as_str()) =>
            {
                let pairing_code = self.pairing_code.clone().ok_or_else(|| {
                    "open Agent pairing handle is missing pairing_code".to_owned()
                })?;
                let expires_at = self.pairing_expires_at.ok_or_else(|| {
                    "open Agent pairing handle is missing pairing_expires_at".to_owned()
                })?;
                if self.runtime_key_request.as_ref().is_some_and(|request| {
                    request.pairing_request_id.as_str() != pairing_request_id.as_str()
                        || request.agent_id.as_str() != self.id
                }) {
                    return Err(
                        "pending Agent runtime key request does not match its open handle"
                            .to_owned(),
                    );
                }
                Some(OpenAgentPairingHandle {
                    pairing_request_id: pairing_request_id.clone(),
                    pairing_code,
                    expires_at,
                    pending_runtime_key_request: self.runtime_key_request.clone(),
                })
            }
            _ => {
                if self.runtime_key_request.is_some() {
                    return Err(
                        "pending Agent runtime key request has no unconsumed pairing handle"
                            .to_owned(),
                    );
                }
                None
            }
        };

        Ok(AgentRuntimeBindings {
            open_handle,
            active_binding,
        })
    }
}

#[derive(Clone, Debug)]
pub struct StoreAgentRuntimeApprovalCommand {
    pub agent_id: String,
    pub pairing_request_id: OpaqueLocalId,
    pub approval_request_id: OpaqueLocalId,
    pub approval_notification_id: String,
    pub approval_requested_at: DateTime<Utc>,
    pub proof_verified_at: DateTime<Utc>,
    pub controller_account_pk: AccountPk,
    pub recipient_id: String,
    pub runtime_key_binding_digest: String,
    pub runtime_public_key_digest: String,
    pub runtime_attestation_digest: String,
    pub runtime_key_request:
        arkret_models_collaboration::agent_scope::AgentRuntimeApprovalRequestBody,
}

#[async_trait]
pub trait AgentPairingPort: Send + Sync {
    async fn pairing_receipt(
        &self,
        event_id: &str,
    ) -> ServiceResult<Option<coland_storage::AgentPairingReceipt>>;
    async fn pending_pairings_after(
        &self,
        after_id: &str,
        limit: usize,
    ) -> ServiceResult<Vec<AgentPairingState>>;
    async fn pairing_record(
        &self,
        pairing_request_id: &str,
    ) -> ServiceResult<Option<AgentPairingState>>;
    async fn agent(&self, agent_id: &str) -> ServiceResult<Option<AgentPairingState>>;
    async fn agents_for_controller(
        &self,
        controller_principal_id: &str,
    ) -> ServiceResult<Vec<AgentPairingState>>;
    async fn save_agent(&self, agent: AgentPairingState) -> ServiceResult<()>;
    async fn store_runtime_approval(
        &self,
        command: &StoreAgentRuntimeApprovalCommand,
    ) -> ServiceResult<Option<AgentPairingState>>;
    async fn activate_runtime_if_current(
        &self,
        command: &ActivateAgentRuntimeCommand,
    ) -> ServiceResult<bool>;
    async fn record_pairing_commit_intent(
        &self,
        command: &RecordAgentPairingCommitIntentCommand,
    ) -> ServiceResult<Option<AgentPairingState>>;
    async fn clear_approval_notification_if_current(
        &self,
        agent_id: &str,
        approval_request_id: &str,
    ) -> ServiceResult<bool>;
    async fn enqueue_runtime_message_if_current(
        &self,
        command: &EnqueueAgentRuntimeMessage,
    ) -> ServiceResult<AgentRuntimeEnqueueOutcome>;
}

pub use coland_storage::{
    AgentSidecarContextRecord as AgentSidecarContextState, AgentSidecarRecord as AgentSidecarState,
};

#[async_trait]
pub trait SidecarPort: Send + Sync {
    async fn ensure_sidecar(&self, sidecar: AgentSidecarState) -> ServiceResult<AgentSidecarState>;
    async fn sidecar(&self, sidecar_id: &str) -> ServiceResult<Option<AgentSidecarState>>;
    async fn sidecar_for_realm_controller(
        &self,
        realm_id: &str,
        controller_account_id: &arkret_wire::AccountId,
    ) -> ServiceResult<Option<AgentSidecarState>>;
    async fn sidecars_for_controller(
        &self,
        controller_account_id: &arkret_wire::AccountId,
        realm_id: Option<&str>,
    ) -> ServiceResult<Vec<AgentSidecarState>>;
    async fn ensure_context(
        &self,
        context: AgentSidecarContextState,
    ) -> ServiceResult<AgentSidecarContextState>;
    async fn context(
        &self,
        sidecar_id: &str,
        digest: &str,
    ) -> ServiceResult<Option<AgentSidecarContextState>>;
}

#[derive(Clone)]
pub struct AgentPairingService {
    pairing: Arc<dyn AgentPairingPort>,
    sidecars: Arc<dyn SidecarPort>,
}

pub use coland_storage::RecoveryPolicyRecord as RecoveryPolicyState;

#[async_trait]
pub trait RecoveryPolicyPort: Send + Sync {
    async fn active_policy(
        &self,
        account_id: &arkret_wire::AccountId,
    ) -> ServiceResult<Option<RecoveryPolicyState>>;
    async fn policy_history(
        &self,
        account_id: &arkret_wire::AccountId,
    ) -> ServiceResult<Vec<RecoveryPolicyState>>;
    async fn commit_publication(
        &self,
        write: coland_storage::RecoveryPolicyPublicationWrite,
    ) -> ServiceResult<coland_storage::RecoveryPolicyPublicationOutcome>;
}

#[derive(Clone)]
pub struct RecoveryPolicyService {
    policies: Arc<dyn RecoveryPolicyPort>,
}

impl RecoveryPolicyService {
    pub fn new(policies: Arc<dyn RecoveryPolicyPort>) -> Self {
        Self { policies }
    }

    pub async fn active_policy(
        &self,
        account_id: &arkret_wire::AccountId,
    ) -> ServiceResult<Option<RecoveryPolicyState>> {
        self.policies.active_policy(account_id).await
    }

    pub async fn policy_history(
        &self,
        account_id: &arkret_wire::AccountId,
    ) -> ServiceResult<Vec<RecoveryPolicyState>> {
        self.policies.policy_history(account_id).await
    }

    /// Admit one device-signed recovery policy publication through the
    /// registered PCR unit (key-management.md §8.1).
    pub async fn commit_publication(
        &self,
        write: coland_storage::RecoveryPolicyPublicationWrite,
    ) -> ServiceResult<coland_storage::RecoveryPolicyPublicationOutcome> {
        self.policies.commit_publication(write).await
    }
}

pub use coland_storage::RecoverySessionRecord as RecoverySessionState;

#[async_trait]
pub trait RecoverySessionPort: Send + Sync {
    async fn session(
        &self,
        recovery_session_id: &str,
    ) -> ServiceResult<Option<RecoverySessionState>>;
    async fn session_for_grant(
        &self,
        session_grant_id: &str,
    ) -> ServiceResult<Option<RecoverySessionState>>;
    async fn session_for_request(
        &self,
        session_grant_id: &str,
        request_id: &str,
    ) -> ServiceResult<Option<RecoverySessionState>>;
    async fn insert_session(&self, session: RecoverySessionState) -> ServiceResult<()>;
    async fn save_verified_with_unlock_manifest(
        &self,
        session: RecoverySessionState,
        manifest: Value,
    ) -> ServiceResult<()>;
    async fn update_session(&self, session: RecoverySessionState) -> ServiceResult<()>;
}

#[derive(Clone)]
pub struct RecoverySessionService {
    sessions: Arc<dyn RecoverySessionPort>,
}

impl RecoverySessionService {
    pub fn new(sessions: Arc<dyn RecoverySessionPort>) -> Self {
        Self { sessions }
    }

    pub async fn session(
        &self,
        recovery_session_id: &str,
    ) -> ServiceResult<Option<RecoverySessionState>> {
        self.sessions.session(recovery_session_id).await
    }

    pub async fn session_for_grant(
        &self,
        session_grant_id: &str,
    ) -> ServiceResult<Option<RecoverySessionState>> {
        self.sessions.session_for_grant(session_grant_id).await
    }

    pub async fn session_for_request(
        &self,
        session_grant_id: &str,
        request_id: &str,
    ) -> ServiceResult<Option<RecoverySessionState>> {
        self.sessions
            .session_for_request(session_grant_id, request_id)
            .await
    }

    pub async fn create_session(&self, session: RecoverySessionState) -> ServiceResult<()> {
        self.sessions.insert_session(session).await
    }

    pub async fn save_verified_with_unlock_manifest(
        &self,
        session: RecoverySessionState,
        manifest: Value,
    ) -> ServiceResult<()> {
        self.sessions
            .save_verified_with_unlock_manifest(session, manifest)
            .await
    }
    pub async fn save_session(&self, session: RecoverySessionState) -> ServiceResult<()> {
        self.sessions.update_session(session).await
    }
}

pub use coland_storage::{
    BackupSeriesEraseProgressRecord as BackupSeriesEraseProgressState, RecoveryUnitCommitWrite,
    RevokeCommandTerminalWrite, RevokeProposalCommitWrite, RotationLocalCommitWrite,
    RotationPointerSwitchWrite, RotationUploadCommitWrite, SecurityTransactionRecord,
    SecurityTransactionStepAttemptRecord as SecurityTransactionStepAttemptState,
    SecurityTransactionStepOutcomeRecord as SecurityTransactionStepOutcomeState,
};

#[async_trait]
pub trait SecurityTransactionPort: Send + Sync {
    async fn commit_revoke_proposal(
        &self,
        write: RevokeProposalCommitWrite,
    ) -> ServiceResult<arkret_wire::RealmCommit>;
    async fn commit_revoke_command_terminal(
        &self,
        write: RevokeCommandTerminalWrite,
    ) -> ServiceResult<SecurityTransactionRecord>;
    async fn create(
        &self,
        transaction: SecurityTransactionRecord,
    ) -> ServiceResult<SecurityTransactionRecord>;
    async fn transaction(
        &self,
        transaction_id: &str,
    ) -> ServiceResult<Option<SecurityTransactionRecord>>;
    async fn save(&self, transaction: SecurityTransactionRecord) -> ServiceResult<()>;
    async fn rotations_awaiting_worker(&self, limit: u32) -> ServiceResult<Vec<String>>;
    async fn commit_rotation_upload(
        &self,
        write: RotationUploadCommitWrite,
    ) -> ServiceResult<SecurityTransactionRecord>;
    async fn commit_rotation_pointer_switch(
        &self,
        write: RotationPointerSwitchWrite,
    ) -> ServiceResult<SecurityTransactionRecord>;
    async fn commit_rotation_local_commit(
        &self,
        write: RotationLocalCommitWrite,
    ) -> ServiceResult<SecurityTransactionRecord>;
    async fn step_outcome(
        &self,
        transaction_id: &str,
        step: arkret_models_crypto::security_transaction::SecurityTransactionStep,
    ) -> ServiceResult<Option<SecurityTransactionStepOutcomeState>>;
    async fn step_attempt(
        &self,
        transaction_id: &str,
        step: arkret_models_crypto::security_transaction::SecurityTransactionStep,
    ) -> ServiceResult<Option<SecurityTransactionStepAttemptState>>;
    async fn begin_step(
        &self,
        attempt: SecurityTransactionStepAttemptState,
    ) -> ServiceResult<SecurityTransactionStepAttemptState>;
    async fn accept_step(
        &self,
        transaction: SecurityTransactionRecord,
        outcome: SecurityTransactionStepOutcomeState,
    ) -> ServiceResult<SecurityTransactionStepOutcomeState>;
    async fn commit_recovery_unit(
        &self,
        write: RecoveryUnitCommitWrite,
    ) -> ServiceResult<SecurityTransactionStepOutcomeState>;
    async fn backup_erase_progress(
        &self,
        transaction_id: &str,
    ) -> ServiceResult<Option<BackupSeriesEraseProgressState>>;
    async fn begin_backup_erase(
        &self,
        progress: BackupSeriesEraseProgressState,
    ) -> ServiceResult<BackupSeriesEraseProgressState>;
    async fn update_backup_erase(
        &self,
        progress: BackupSeriesEraseProgressState,
    ) -> ServiceResult<BackupSeriesEraseProgressState>;
}

#[derive(Clone)]
pub struct SecurityTransactionService {
    transactions: Arc<dyn SecurityTransactionPort>,
}

impl SecurityTransactionService {
    pub fn new(transactions: Arc<dyn SecurityTransactionPort>) -> Self {
        Self { transactions }
    }

    pub async fn commit_revoke_proposal(
        &self,
        write: RevokeProposalCommitWrite,
    ) -> ServiceResult<arkret_wire::RealmCommit> {
        self.transactions.commit_revoke_proposal(write).await
    }

    pub async fn commit_revoke_command_terminal(
        &self,
        write: RevokeCommandTerminalWrite,
    ) -> ServiceResult<SecurityTransactionRecord> {
        self.transactions
            .commit_revoke_command_terminal(write)
            .await
    }

    pub async fn rotations_awaiting_worker(&self, limit: u32) -> ServiceResult<Vec<String>> {
        self.transactions.rotations_awaiting_worker(limit).await
    }

    pub async fn commit_rotation_upload(
        &self,
        write: RotationUploadCommitWrite,
    ) -> ServiceResult<SecurityTransactionRecord> {
        self.transactions.commit_rotation_upload(write).await
    }

    pub async fn commit_rotation_pointer_switch(
        &self,
        write: RotationPointerSwitchWrite,
    ) -> ServiceResult<SecurityTransactionRecord> {
        self.transactions
            .commit_rotation_pointer_switch(write)
            .await
    }

    pub async fn commit_rotation_local_commit(
        &self,
        write: RotationLocalCommitWrite,
    ) -> ServiceResult<SecurityTransactionRecord> {
        self.transactions.commit_rotation_local_commit(write).await
    }

    pub async fn create(
        &self,
        transaction: SecurityTransactionRecord,
    ) -> ServiceResult<SecurityTransactionRecord> {
        self.transactions.create(transaction).await
    }

    pub async fn transaction(
        &self,
        transaction_id: &str,
    ) -> ServiceResult<Option<SecurityTransactionRecord>> {
        self.transactions.transaction(transaction_id).await
    }

    pub async fn save(&self, transaction: SecurityTransactionRecord) -> ServiceResult<()> {
        self.transactions.save(transaction).await
    }

    pub async fn step_outcome(
        &self,
        transaction_id: &str,
        step: arkret_models_crypto::security_transaction::SecurityTransactionStep,
    ) -> ServiceResult<Option<SecurityTransactionStepOutcomeState>> {
        self.transactions.step_outcome(transaction_id, step).await
    }

    pub async fn step_attempt(
        &self,
        transaction_id: &str,
        step: arkret_models_crypto::security_transaction::SecurityTransactionStep,
    ) -> ServiceResult<Option<SecurityTransactionStepAttemptState>> {
        self.transactions.step_attempt(transaction_id, step).await
    }

    pub async fn begin_step(
        &self,
        attempt: SecurityTransactionStepAttemptState,
    ) -> ServiceResult<SecurityTransactionStepAttemptState> {
        self.transactions.begin_step(attempt).await
    }

    pub async fn accept_step(
        &self,
        transaction: SecurityTransactionRecord,
        outcome: SecurityTransactionStepOutcomeState,
    ) -> ServiceResult<SecurityTransactionStepOutcomeState> {
        self.transactions.accept_step(transaction, outcome).await
    }

    pub async fn commit_recovery_unit(
        &self,
        write: RecoveryUnitCommitWrite,
    ) -> ServiceResult<SecurityTransactionStepOutcomeState> {
        self.transactions.commit_recovery_unit(write).await
    }

    pub async fn backup_erase_progress(
        &self,
        transaction_id: &str,
    ) -> ServiceResult<Option<BackupSeriesEraseProgressState>> {
        self.transactions
            .backup_erase_progress(transaction_id)
            .await
    }

    pub async fn begin_backup_erase(
        &self,
        progress: BackupSeriesEraseProgressState,
    ) -> ServiceResult<BackupSeriesEraseProgressState> {
        self.transactions.begin_backup_erase(progress).await
    }

    pub async fn update_backup_erase(
        &self,
        progress: BackupSeriesEraseProgressState,
    ) -> ServiceResult<BackupSeriesEraseProgressState> {
        self.transactions.update_backup_erase(progress).await
    }
}

#[async_trait]
pub trait AgentParticipationPort: Send + Sync {
    async fn compare_and_swap_selection(
        &self,
        selection: Value,
        expected_version: u64,
    ) -> ServiceResult<bool>;
    async fn selections(&self, agent_id: &str) -> ServiceResult<Vec<Value>>;
    async fn ceilings(&self, scope_keys: &[String]) -> ServiceResult<Vec<Value>>;
}

#[derive(Clone)]
pub struct AgentParticipationService {
    participation: Arc<dyn AgentParticipationPort>,
}

impl AgentParticipationService {
    pub fn new(participation: Arc<dyn AgentParticipationPort>) -> Self {
        Self { participation }
    }

    pub async fn compare_and_swap_selection(
        &self,
        selection: Value,
        expected_version: u64,
    ) -> ServiceResult<bool> {
        self.participation
            .compare_and_swap_selection(selection, expected_version)
            .await
    }

    pub async fn selections(&self, agent_id: &str) -> ServiceResult<Vec<Value>> {
        self.participation.selections(agent_id).await
    }

    pub async fn ceilings(&self, scope_keys: &[String]) -> ServiceResult<Vec<Value>> {
        self.participation.ceilings(scope_keys).await
    }
}

/// Re-exported so the HTTP layer can name a delete challenge without depending
/// on `coland-storage` directly (it is a dev-dependency there): the service
/// facade is the only boundary the routing code crosses.
pub use coland_storage::{
    ConfirmedKeyBackupAuthorityBasis, KeyBackupDeleteChallengeRecord, KeyBackupListPage,
    KeyBackupListPosition, KeyBackupListQuery,
};

#[async_trait]
pub trait KeyBackupPort: Send + Sync {
    async fn confirmed_list_page_for_account(
        &self,
        account_id: &AccountId,
        query: &KeyBackupListQuery,
    ) -> ServiceResult<coland_storage::ConfirmedKeyBackupListPage>;
    async fn confirmed_list_page_for_device(
        &self,
        account_id: &AccountId,
        device_id: &arkret_wire::DeviceId,
        now: DateTime<Utc>,
        query: &KeyBackupListQuery,
    ) -> ServiceResult<coland_storage::ConfirmedKeyBackupListPage>;
    async fn confirmed_active_series_for_device(
        &self,
        account_id: &AccountId,
        device_id: &arkret_wire::DeviceId,
        now: DateTime<Utc>,
    ) -> ServiceResult<Option<arkret_models_crypto::BackupActiveSeriesState>>;
    async fn commit_active_series_pointer(
        &self,
        write: coland_storage::KeyBackupActiveSeriesCommitWrite,
    ) -> ServiceResult<coland_storage::KeyBackupActiveSeriesCommitOutcome>;
    async fn confirmed_active_series(
        &self,
        account_id: &AccountId,
    ) -> ServiceResult<Option<arkret_models_crypto::BackupActiveSeriesState>>;
    async fn confirmed_active_series_basis(
        &self,
        account_id: &AccountId,
    ) -> ServiceResult<Option<ConfirmedKeyBackupAuthorityBasis>>;
    async fn issue_unlock_challenge(
        &self,
        challenge: Value,
        now: chrono::DateTime<Utc>,
    ) -> ServiceResult<Value>;
    async fn reserve_recovery_unlock_attempt(
        &self,
        authority_id: &str,
        holder: &str,
        request_digest: &str,
        now: chrono::DateTime<Utc>,
    ) -> ServiceResult<bool>;
    async fn unlock_challenge(&self, authority_id: &str) -> ServiceResult<Option<Value>>;
    async fn consume_unlock(
        &self,
        command: coland_storage::KeyBackupUnlockCommand<'_>,
    ) -> ServiceResult<Value>;
    async fn backup(&self, backup_id: &str) -> ServiceResult<Option<Value>>;
    async fn backups_for_actor(&self, actor_id: &str) -> ServiceResult<Vec<Value>>;
    async fn list_page(&self, query: &KeyBackupListQuery) -> ServiceResult<KeyBackupListPage>;
    async fn store_backup(&self, backup_id: String, payload: Value) -> ServiceResult<()>;
    async fn delete_backup(&self, backup_id: &str) -> ServiceResult<bool>;
    async fn issue_delete_challenge(
        &self,
        record: coland_storage::KeyBackupDeleteChallengeRecord,
        now: DateTime<Utc>,
    ) -> ServiceResult<coland_storage::KeyBackupDeleteChallengeRecord>;
    async fn delete_challenge(
        &self,
        challenge_id: &str,
    ) -> ServiceResult<Option<coland_storage::KeyBackupDeleteChallengeRecord>>;
    async fn consume_delete_challenge(
        &self,
        gate: &coland_storage::KeyBackupDeleteGate,
        challenge_id: &str,
        backup: Value,
        recovery_session_id: Option<&str>,
        now: DateTime<Utc>,
    ) -> ServiceResult<bool>;
    async fn prune_expired_delete_challenges(&self, now: DateTime<Utc>) -> ServiceResult<usize>;
}

#[derive(Clone)]
pub struct KeyBackupService {
    backups: Arc<dyn KeyBackupPort>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct AgentSessionState {
    pub granted_scope: Vec<String>,
    pub scope_details: Value,
    pub freshness_state: arkret_wire::FreshnessState,
}

#[derive(Clone, Debug)]
pub struct SessionGrantAuthorizationState {
    pub grant_id: arkret_identifiers::SessionGrantId,
    pub revocation_ref: String,
    pub account_id: AccountId,
    pub issuer_id: arkret_identifiers::DidCoreId,
    /// Scopes the Account Authority bound into the presented grant. They are
    /// the only wire-visible statement about what the grant was authorized
    /// for, so deployment policies that gate a high-risk self-service action
    /// on a step-up authentication (`account-lifecycle.md` §8.1) read them
    /// here rather than re-deriving authentication strength locally.
    pub scopes: Vec<String>,
    pub credential_class: arkret_models_identity::session_credential::SessionGrantCredentialClass,
    pub holder_binding: arkret_models_identity::session_credential::SessionGrantHolderBinding,
    pub device_binding:
        Option<arkret_models_identity::session_credential::SessionGrantDeviceBinding>,
    pub cnf_jkt: String,
}

#[derive(Clone, Debug)]
pub struct SessionIdentityState {
    pub token_hash: String,
    /// Exact service-local account binding carried by the credential that
    /// established this session. It must never be derived from `actor`.
    pub account_pk: Option<AccountPk>,
    pub actor: String,
    pub endpoint: SessionEndpointState,
    pub audience: String,
    pub session_public_key: Option<String>,
    /// Present only for request-scoped `ak.session.grant` authentication. This
    /// preserves the credential class and closed bootstrap binding through
    /// authorization; local/dev sessions deliberately carry `None`.
    pub session_grant: Option<SessionGrantAuthorizationState>,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
}

/// The authenticated endpoint kind. Only a Human session carries a DeviceId.
#[derive(Clone, Debug, PartialEq)]
pub enum SessionEndpointState {
    HumanDevice { device_id: String },
    AgentRuntime { state: AgentSessionState },
    ServiceSynthetic,
}

impl SessionIdentityState {
    pub fn human_device_id(&self) -> Option<&String> {
        match &self.endpoint {
            SessionEndpointState::HumanDevice { device_id } => Some(device_id),
            SessionEndpointState::AgentRuntime { .. } | SessionEndpointState::ServiceSynthetic => {
                None
            }
        }
    }

    /// Use only after the request's Human endpoint gate. An unexpected Agent
    /// or service call cannot acquire a synthetic DeviceId.
    pub fn require_human_device_id(&self) -> &String {
        self.human_device_id()
            .expect("Human endpoint gate must precede DeviceId use")
    }

    pub fn agent_session(&self) -> Option<&AgentSessionState> {
        match &self.endpoint {
            SessionEndpointState::AgentRuntime { state } => Some(state),
            SessionEndpointState::HumanDevice { .. } | SessionEndpointState::ServiceSynthetic => {
                None
            }
        }
    }
}

#[async_trait]
pub trait SessionIdentityPort: Send + Sync {
    async fn session(&self, token_hash: &str) -> ServiceResult<Option<SessionIdentityState>>;
    async fn sessions(&self) -> ServiceResult<Vec<SessionIdentityState>>;
    async fn save_session(&self, session: SessionIdentityState) -> ServiceResult<()>;
    async fn revoke_session(
        &self,
        token_hash: &str,
        revoked_at: DateTime<Utc>,
    ) -> ServiceResult<Option<SessionIdentityState>>;
    async fn revoke_actor_sessions(
        &self,
        actor_id: &str,
        revoked_at: DateTime<Utc>,
    ) -> ServiceResult<usize>;
    async fn revoke_actor_device_sessions(
        &self,
        actor_id: &str,
        device_id: &str,
        revoked_at: DateTime<Utc>,
    ) -> ServiceResult<usize>;
}

#[derive(Clone)]
pub struct SessionService {
    sessions: Arc<dyn SessionIdentityPort>,
}

impl SessionService {
    pub fn new(sessions: Arc<dyn SessionIdentityPort>) -> Self {
        Self { sessions }
    }

    pub async fn session(&self, token_hash: &str) -> ServiceResult<Option<SessionIdentityState>> {
        self.sessions.session(token_hash).await
    }

    pub async fn create_session(&self, session: SessionIdentityState) -> ServiceResult<()> {
        self.sessions.save_session(session).await
    }

    pub async fn revoke_session(
        &self,
        token_hash: &str,
        revoked_at: DateTime<Utc>,
    ) -> ServiceResult<Option<SessionIdentityState>> {
        self.sessions.revoke_session(token_hash, revoked_at).await
    }

    pub async fn revoke_actor_sessions(
        &self,
        actor_id: &str,
        revoked_at: DateTime<Utc>,
    ) -> ServiceResult<usize> {
        self.sessions
            .revoke_actor_sessions(actor_id, revoked_at)
            .await
    }

    pub async fn revoke_actor_device_sessions(
        &self,
        actor_id: &str,
        device_id: &str,
        revoked_at: DateTime<Utc>,
    ) -> ServiceResult<usize> {
        self.sessions
            .revoke_actor_device_sessions(actor_id, device_id, revoked_at)
            .await
    }
}

impl KeyBackupService {
    pub fn new(backups: Arc<dyn KeyBackupPort>) -> Self {
        Self { backups }
    }

    pub async fn confirmed_active_series(
        &self,
        account_id: &AccountId,
    ) -> ServiceResult<Option<arkret_models_crypto::BackupActiveSeriesState>> {
        self.backups.confirmed_active_series(account_id).await
    }

    pub async fn confirmed_active_series_basis(
        &self,
        account_id: &AccountId,
    ) -> ServiceResult<Option<ConfirmedKeyBackupAuthorityBasis>> {
        self.backups.confirmed_active_series_basis(account_id).await
    }

    pub async fn confirmed_active_series_for_device(
        &self,
        account_id: &AccountId,
        device_id: &arkret_wire::DeviceId,
        now: DateTime<Utc>,
    ) -> ServiceResult<Option<arkret_models_crypto::BackupActiveSeriesState>> {
        self.backups
            .confirmed_active_series_for_device(account_id, device_id, now)
            .await
    }

    /// Accept one self-authored active-series pointer through the registered
    /// same-cut PCR unit. The storage unit is the only admission authority.
    pub async fn commit_active_series_pointer(
        &self,
        write: coland_storage::KeyBackupActiveSeriesCommitWrite,
    ) -> ServiceResult<coland_storage::KeyBackupActiveSeriesCommitOutcome> {
        self.backups.commit_active_series_pointer(write).await
    }

    pub async fn confirmed_list_page_for_account(
        &self,
        account_id: &AccountId,
        query: &KeyBackupListQuery,
    ) -> ServiceResult<coland_storage::ConfirmedKeyBackupListPage> {
        self.backups
            .confirmed_list_page_for_account(account_id, query)
            .await
    }

    pub async fn confirmed_list_page_for_device(
        &self,
        account_id: &AccountId,
        device_id: &arkret_wire::DeviceId,
        now: DateTime<Utc>,
        query: &KeyBackupListQuery,
    ) -> ServiceResult<coland_storage::ConfirmedKeyBackupListPage> {
        self.backups
            .confirmed_list_page_for_device(account_id, device_id, now, query)
            .await
    }

    pub async fn backup(&self, backup_id: &str) -> ServiceResult<Option<Value>> {
        self.backups.backup(backup_id).await
    }

    pub async fn list_page(&self, query: &KeyBackupListQuery) -> ServiceResult<KeyBackupListPage> {
        self.backups.list_page(query).await
    }

    pub async fn backups_for_actor(&self, actor_id: &str) -> ServiceResult<Vec<Value>> {
        self.backups.backups_for_actor(actor_id).await
    }

    pub async fn store_backup(&self, backup_id: String, payload: Value) -> ServiceResult<()> {
        self.backups.store_backup(backup_id, payload).await
    }

    /// Issue, or re-issue verbatim, the delete challenge for one
    /// `(account_id, backup_id, request_id)` (`key-management.md` §7.8.1).
    pub async fn issue_unlock_challenge(
        &self,
        challenge: Value,
        now: chrono::DateTime<Utc>,
    ) -> ServiceResult<Value> {
        self.backups.issue_unlock_challenge(challenge, now).await
    }
    pub async fn reserve_recovery_unlock_attempt(
        &self,
        authority_id: &str,
        holder: &str,
        request_digest: &str,
        now: chrono::DateTime<Utc>,
    ) -> ServiceResult<bool> {
        self.backups
            .reserve_recovery_unlock_attempt(authority_id, holder, request_digest, now)
            .await
    }
    pub async fn unlock_challenge(&self, authority_id: &str) -> ServiceResult<Option<Value>> {
        self.backups.unlock_challenge(authority_id).await
    }
    pub async fn consume_unlock(
        &self,
        command: coland_storage::KeyBackupUnlockCommand<'_>,
    ) -> ServiceResult<Value> {
        self.backups.consume_unlock(command).await
    }
    pub async fn issue_delete_challenge(
        &self,
        record: coland_storage::KeyBackupDeleteChallengeRecord,
        now: DateTime<Utc>,
    ) -> ServiceResult<coland_storage::KeyBackupDeleteChallengeRecord> {
        self.backups.issue_delete_challenge(record, now).await
    }

    pub async fn delete_challenge(
        &self,
        challenge_id: &str,
    ) -> ServiceResult<Option<coland_storage::KeyBackupDeleteChallengeRecord>> {
        self.backups.delete_challenge(challenge_id).await
    }

    /// Delete the exact authorized backup and consume its challenge atomically.
    /// `false` means the challenge is no longer available.
    pub async fn consume_delete_challenge(
        &self,
        gate: &coland_storage::KeyBackupDeleteGate,
        challenge_id: &str,
        backup: Value,
        recovery_session_id: Option<&str>,
        now: DateTime<Utc>,
    ) -> ServiceResult<bool> {
        self.backups
            .consume_delete_challenge(gate, challenge_id, backup, recovery_session_id, now)
            .await
    }

    pub async fn prune_expired_delete_challenges(
        &self,
        now: DateTime<Utc>,
    ) -> ServiceResult<usize> {
        self.backups.prune_expired_delete_challenges(now).await
    }

    pub async fn delete_backup(&self, backup_id: &str) -> ServiceResult<bool> {
        self.backups.delete_backup(backup_id).await
    }
}

impl AgentPairingService {
    pub async fn pairing_receipt(
        &self,
        event_id: &str,
    ) -> ServiceResult<Option<coland_storage::AgentPairingReceipt>> {
        self.pairing.pairing_receipt(event_id).await
    }
    pub async fn pending_pairings_after(
        &self,
        after_id: &str,
        limit: usize,
    ) -> ServiceResult<Vec<AgentPairingState>> {
        self.pairing.pending_pairings_after(after_id, limit).await
    }
    pub fn new(pairing: Arc<dyn AgentPairingPort>, sidecars: Arc<dyn SidecarPort>) -> Self {
        Self { pairing, sidecars }
    }

    pub async fn pairing_record(
        &self,
        pairing_request_id: &str,
    ) -> ServiceResult<Option<AgentPairingState>> {
        self.pairing.pairing_record(pairing_request_id).await
    }

    pub async fn agent(&self, agent_id: &str) -> ServiceResult<Option<AgentPairingState>> {
        self.pairing.agent(agent_id).await
    }

    pub async fn agents_for_controller(
        &self,
        controller_principal_id: &str,
    ) -> ServiceResult<Vec<AgentPairingState>> {
        self.pairing
            .agents_for_controller(controller_principal_id)
            .await
    }

    pub async fn save_agent(&self, agent: AgentPairingState) -> ServiceResult<()> {
        self.pairing.save_agent(agent).await
    }

    pub async fn store_runtime_approval(
        &self,
        command: &StoreAgentRuntimeApprovalCommand,
    ) -> ServiceResult<Option<AgentPairingState>> {
        self.pairing.store_runtime_approval(command).await
    }

    pub async fn activate_runtime(
        &self,
        command: &ActivateAgentRuntimeCommand,
    ) -> ServiceResult<bool> {
        self.pairing.activate_runtime_if_current(command).await
    }

    pub async fn record_pairing_commit_intent(
        &self,
        command: &RecordAgentPairingCommitIntentCommand,
    ) -> ServiceResult<Option<AgentPairingState>> {
        self.pairing.record_pairing_commit_intent(command).await
    }

    pub async fn clear_approval_notification(
        &self,
        agent_id: &str,
        approval_request_id: &str,
    ) -> ServiceResult<bool> {
        self.pairing
            .clear_approval_notification_if_current(agent_id, approval_request_id)
            .await
    }

    pub async fn enqueue_runtime_message_if_current(
        &self,
        command: &EnqueueAgentRuntimeMessage,
    ) -> ServiceResult<AgentRuntimeEnqueueOutcome> {
        self.pairing
            .enqueue_runtime_message_if_current(command)
            .await
    }

    pub async fn ensure_sidecar(
        &self,
        sidecar: AgentSidecarState,
    ) -> ServiceResult<AgentSidecarState> {
        self.sidecars.ensure_sidecar(sidecar).await
    }
    pub async fn sidecar(&self, sidecar_id: &str) -> ServiceResult<Option<AgentSidecarState>> {
        self.sidecars.sidecar(sidecar_id).await
    }
    pub async fn sidecar_for_realm_controller(
        &self,
        realm_id: &str,
        controller_account_id: &arkret_wire::AccountId,
    ) -> ServiceResult<Option<AgentSidecarState>> {
        self.sidecars
            .sidecar_for_realm_controller(realm_id, controller_account_id)
            .await
    }
    pub async fn sidecars_for_controller(
        &self,
        controller_account_id: &arkret_wire::AccountId,
        realm_id: Option<&str>,
    ) -> ServiceResult<Vec<AgentSidecarState>> {
        self.sidecars
            .sidecars_for_controller(controller_account_id, realm_id)
            .await
    }
    pub async fn ensure_sidecar_context(
        &self,
        context: AgentSidecarContextState,
    ) -> ServiceResult<AgentSidecarContextState> {
        self.sidecars.ensure_context(context).await
    }
    pub async fn sidecar_context(
        &self,
        sidecar_id: &str,
        digest: &str,
    ) -> ServiceResult<Option<AgentSidecarContextState>> {
        self.sidecars.context(sidecar_id, digest).await
    }
}

impl IdentityService {
    pub fn new(
        accounts: Arc<dyn AccountLookupPort>,
        devices: Arc<dyn DeviceDirectoryPort>,
        agents: Arc<dyn AgentDirectoryPort>,
    ) -> Self {
        Self {
            accounts,
            devices,
            agents,
            account_registration_attempts: Arc::new(Mutex::new(BTreeMap::new())),
            account_lifecycles: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }

    pub fn account_registration_retry_after_ms(
        &self,
        actor_id: &str,
        max_attempts: u32,
        window_seconds: u64,
        now: DateTime<Utc>,
    ) -> Option<u64> {
        if max_attempts == 0 || window_seconds == 0 {
            return Some(0);
        }
        let window = chrono::Duration::seconds(window_seconds as i64);
        let mut attempts = self.account_registration_attempts.lock();
        let entry = attempts.entry(actor_id.to_owned()).or_insert((now, 0));
        if now.signed_duration_since(entry.0) >= window {
            *entry = (now, 0);
        }
        if entry.1 >= max_attempts {
            return Some(
                window
                    .checked_sub(&now.signed_duration_since(entry.0))
                    .unwrap_or_else(chrono::Duration::zero)
                    .num_milliseconds()
                    .max(0) as u64,
            );
        }
        entry.1 += 1;
        None
    }

    pub async fn find_account_by_actor(
        &self,
        query: FindAccountByActorQuery,
    ) -> ServiceResult<Option<AccountIdentity>> {
        self.accounts.find_account_by_actor(&query.account_id).await
    }

    pub async fn account_by_id(
        &self,
        account_pk: AccountPk,
    ) -> ServiceResult<Option<AccountProfileState>> {
        self.accounts.account_by_id(account_pk).await
    }

    pub async fn register_account(
        &self,
        command: RegisterAccountCommand,
    ) -> ServiceResult<AccountIdentity> {
        self.accounts.register_account(command).await
    }

    pub async fn account(
        &self,
        account_id: &AccountId,
    ) -> ServiceResult<Option<AccountProfileState>> {
        self.accounts.account(account_id).await
    }

    pub async fn accounts(&self) -> ServiceResult<Vec<AccountProfileState>> {
        self.accounts.accounts().await
    }

    pub async fn save_account(&self, account: AccountProfileState) -> ServiceResult<()> {
        self.accounts.save_account(account).await
    }

    pub async fn delete_account(&self, account_id: &AccountId) -> ServiceResult<()> {
        self.accounts.delete_account(account_id).await
    }

    pub async fn account_localparts(
        &self,
        account_pk: AccountPk,
    ) -> ServiceResult<Vec<AccountLocalpartState>> {
        self.accounts.account_localparts(account_pk).await
    }

    pub async fn localpart_owner(
        &self,
        localpart: &str,
    ) -> ServiceResult<Option<AccountLocalpartState>> {
        self.accounts.localpart_owner(localpart).await
    }

    pub async fn add_localpart(
        &self,
        account_pk: AccountPk,
        localpart: &str,
        primary: bool,
    ) -> ServiceResult<AccountLocalpartState> {
        self.accounts
            .add_localpart(account_pk, localpart, primary)
            .await
    }

    pub async fn remove_localpart(
        &self,
        account_pk: AccountPk,
        localpart: &str,
    ) -> ServiceResult<()> {
        self.accounts.remove_localpart(account_pk, localpart).await
    }

    pub async fn clear_localparts(&self, account_pk: AccountPk) -> ServiceResult<()> {
        self.accounts.clear_localparts(account_pk).await
    }

    pub async fn record_handle_release(
        &self,
        localpart: &str,
        released_at: DateTime<Utc>,
    ) -> ServiceResult<()> {
        self.accounts
            .record_handle_release(localpart, released_at)
            .await
    }

    pub async fn save_account_lifecycle(
        &self,
        account_pk: AccountPk,
        actor_id: &str,
        lifecycle: AccountLifecycleState,
    ) -> ServiceResult<()> {
        self.accounts
            .save_account_lifecycle(account_pk, actor_id, lifecycle.clone())
            .await?;
        if lifecycle.state == "active" {
            self.account_lifecycles.lock().remove(actor_id);
        } else {
            self.account_lifecycles
                .lock()
                .insert(actor_id.to_owned(), lifecycle);
        }
        Ok(())
    }

    pub async fn delete_account_lifecycle(
        &self,
        account_pk: AccountPk,
        actor_id: &str,
    ) -> ServiceResult<()> {
        self.accounts
            .delete_account_lifecycle(account_pk, actor_id)
            .await?;
        self.account_lifecycles.lock().remove(actor_id);
        Ok(())
    }

    pub async fn hydrate_account_lifecycles(&self) -> ServiceResult<()> {
        let lifecycles = self.accounts.account_lifecycles().await?;
        *self.account_lifecycles.lock() = lifecycles
            .into_iter()
            .filter(|(_, lifecycle)| lifecycle.state != "active")
            .map(|(account_id, lifecycle)| (account_id.principal_id.to_string(), lifecycle))
            .collect();
        Ok(())
    }

    pub fn account_lifecycle_status(&self, actor_id: &str) -> AccountStatus {
        self.account_lifecycles
            .lock()
            .get(actor_id)
            .map(|lifecycle| lifecycle_status_from_wire(&lifecycle.state))
            .unwrap_or(AccountStatus::Active)
    }

    pub fn account_lifecycle_state(&self, actor_id: &str) -> String {
        self.account_lifecycle_status(actor_id).as_str().to_owned()
    }

    /// Snapshot of every non-`active` account lifecycle record.
    ///
    /// The map is hydrated from durable storage at boot
    /// ([`Self::hydrate_account_lifecycles`]) and kept current by the save /
    /// delete paths, so reconciliation workers (e.g. the deactivation push
    /// fanout) can enumerate deactivated accounts without a storage scan.
    pub fn account_lifecycles_snapshot(&self) -> Vec<(String, AccountLifecycleState)> {
        self.account_lifecycles
            .lock()
            .iter()
            .map(|(actor_id, lifecycle)| (actor_id.clone(), lifecycle.clone()))
            .collect()
    }

    pub async fn list_active_device_actors(
        &self,
        _query: ListActiveDeviceActorsQuery,
    ) -> ServiceResult<Vec<String>> {
        self.devices.list_active_device_actors().await
    }

    pub async fn devices(&self) -> ServiceResult<Vec<DeviceIdentity>> {
        self.devices.devices().await
    }

    pub async fn find_device(
        &self,
        query: FindDeviceQuery,
    ) -> ServiceResult<Option<DeviceIdentity>> {
        self.devices
            .find_device(&query.actor_id, &query.device_id)
            .await
    }

    pub async fn save_device(&self, command: SaveDeviceCommand) -> ServiceResult<()> {
        self.devices.save_device(command).await
    }

    pub async fn save_device_if_absent(&self, device: DeviceIdentity) -> ServiceResult<bool> {
        self.devices.save_device_if_absent(device).await
    }

    pub async fn devices_for_actor(&self, actor_id: &str) -> ServiceResult<Vec<DeviceIdentity>> {
        self.devices.devices_for_actor(actor_id).await
    }

    pub async fn find_agent_controller(
        &self,
        query: FindAgentControllerQuery,
    ) -> ServiceResult<Option<AgentController>> {
        self.agents.find_agent_controller(&query.agent_id).await
    }
}

pub use coland_storage::WebvhDocumentRecord as DidDocumentState;

pub const DID_DOCUMENT_HIGH_RISK_TTL_SECS: i64 = 15 * 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DidDocumentFreshness {
    Fresh,
    Stale,
}

pub fn evaluate_did_document_freshness(
    record: &DidDocumentState,
    now: DateTime<Utc>,
    max_age: chrono::Duration,
) -> DidDocumentFreshness {
    if now.signed_duration_since(record.fetched_at) > max_age {
        DidDocumentFreshness::Stale
    } else {
        DidDocumentFreshness::Fresh
    }
}

pub use coland_storage::WebvhLogRecord as DidLogEvent;

/// Relationship between a verified pinned did:webvh version and the verified
/// head observed during the same history resolution.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PinnedDidVersionStatus {
    /// The requested version is the current verified head.
    Current,
    /// A later verified rotation exists. The pinned document remains usable
    /// only for proofs whose transcript names this exact historical version.
    Rotated,
    /// The verified history head deactivates the DID. No pinned version may be
    /// used to establish or refresh an active control relationship.
    Deactivated,
}

/// Method-history-verified did:webvh state selected by both native version id
/// and the canonical digest of that exact log entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PinnedDidDocumentState {
    pub did: Did,
    pub version_id: String,
    pub log_head_digest: Hash,
    pub document: Value,
    pub update_keys: Vec<String>,
    pub current_version_id: String,
    pub status: PinnedDidVersionStatus,
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PinnedDidResolutionError {
    #[error("pinned DID resolution requires did:webvh")]
    UnsupportedMethod,
    #[error("did:webvh method is disabled by resolver policy")]
    MethodNotAllowed,
    #[error("verified did:webvh history is unavailable")]
    HistoryUnavailable,
    #[error("did:webvh history could not be verified: {0}")]
    HistoryUnverifiable(String),
    #[error("requested did:webvh version was not found: {0}")]
    VersionNotFound(String),
    #[error("verified did:webvh history has no version at or before {0}")]
    VersionTimeNotFound(DateTime<Utc>),
    #[error("did:webvh was deactivated at or before {0}")]
    DeactivatedAt(DateTime<Utc>),
    #[error("requested did:webvh version digest does not match verified history")]
    DigestMismatch,
}

/// Select a pinned state only after the SDK verifier has authenticated the
/// complete history. This deliberately never accepts a separately resolved
/// current document as evidence for a historical version.
pub fn select_pinned_did_webvh_state(
    did: &Did,
    history: &arkret_identity::VerifiedDidWebvhLog,
    version_id: &str,
    log_head_digest: &Hash,
) -> Result<PinnedDidDocumentState, PinnedDidResolutionError> {
    if did.method() != "webvh" {
        return Err(PinnedDidResolutionError::UnsupportedMethod);
    }
    if history.entries.len() != history.raw_entries.len() || history.entries.is_empty() {
        return Err(PinnedDidResolutionError::HistoryUnverifiable(
            "verified history has inconsistent entry projections".to_owned(),
        ));
    }
    let selected_index = history
        .entries
        .iter()
        .position(|entry| entry.version_id == version_id)
        .ok_or_else(|| PinnedDidResolutionError::VersionNotFound(version_id.to_owned()))?;
    let selected_raw = &history.raw_entries[selected_index];
    let actual_digest = arkret_canonical::canonical_sha256(selected_raw).map_err(|error| {
        PinnedDidResolutionError::HistoryUnverifiable(format!(
            "pinned log entry digest failed: {error}"
        ))
    })?;
    if actual_digest != log_head_digest.as_str() {
        return Err(PinnedDidResolutionError::DigestMismatch);
    }

    let deactivated_index = history.entries.iter().position(|entry| {
        entry.parameters.get("deactivated").and_then(Value::as_bool) == Some(true)
    });
    if deactivated_index.is_some_and(|index| index + 1 != history.entries.len()) {
        return Err(PinnedDidResolutionError::HistoryUnverifiable(
            "did:webvh history continues after terminal deactivation".to_owned(),
        ));
    }
    let status = if deactivated_index.is_some() {
        PinnedDidVersionStatus::Deactivated
    } else if selected_index + 1 == history.entries.len() {
        PinnedDidVersionStatus::Current
    } else {
        PinnedDidVersionStatus::Rotated
    };
    let selected = &history.entries[selected_index];
    let update_keys = selected
        .parameters
        .get("updateKeys")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(ToOwned::to_owned)
        .collect();
    let selected_did = selected
        .state
        .get("id")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            PinnedDidResolutionError::HistoryUnverifiable("native state omits DID".into())
        })?;
    let selected_did = Did::new(selected_did)
        .map_err(|e| PinnedDidResolutionError::HistoryUnverifiable(e.to_string()))?;
    if arkret_wire::project_did_to_core_id(&selected_did).ok()
        != arkret_wire::project_did_to_core_id(did).ok()
    {
        return Err(PinnedDidResolutionError::HistoryUnverifiable(
            "native state changed service core".into(),
        ));
    }
    Ok(PinnedDidDocumentState {
        did: selected_did,
        version_id: selected.version_id.clone(),
        log_head_digest: log_head_digest.clone(),
        document: selected.state.clone(),
        update_keys,
        current_version_id: history.head_version_id.clone(),
        status,
    })
}

/// Select the last verified did:webvh version whose native `versionTime` is
/// not later than the signed protocol instant. The exact raw log entry is
/// digested and passed back through the pinned selector, so callers cannot
/// accidentally verify historical evidence with the current document.
pub fn select_did_webvh_state_at(
    did: &Did,
    history: &arkret_identity::VerifiedDidWebvhLog,
    at: DateTime<Utc>,
) -> Result<PinnedDidDocumentState, PinnedDidResolutionError> {
    if did.method() != "webvh" {
        return Err(PinnedDidResolutionError::UnsupportedMethod);
    }
    if history.entries.len() != history.raw_entries.len() || history.entries.is_empty() {
        return Err(PinnedDidResolutionError::HistoryUnverifiable(
            "verified history has inconsistent entry projections".to_owned(),
        ));
    }
    if history.entries.iter().any(|entry| {
        entry.version_time <= at
            && entry.parameters.get("deactivated").and_then(Value::as_bool) == Some(true)
    }) {
        return Err(PinnedDidResolutionError::DeactivatedAt(at));
    }
    let selected_index = history
        .entries
        .iter()
        .enumerate()
        .filter(|(_, entry)| entry.version_time <= at)
        .map(|(index, _)| index)
        .next_back()
        .ok_or(PinnedDidResolutionError::VersionTimeNotFound(at))?;
    let selected = history.entries.get(selected_index).ok_or_else(|| {
        PinnedDidResolutionError::HistoryUnverifiable(
            "verified history entry projection is missing".to_owned(),
        )
    })?;
    let selected_raw = history.raw_entries.get(selected_index).ok_or_else(|| {
        PinnedDidResolutionError::HistoryUnverifiable(
            "verified history raw entry is missing".to_owned(),
        )
    })?;
    let digest = Hash::new(
        arkret_canonical::canonical_sha256(selected_raw).map_err(|error| {
            PinnedDidResolutionError::HistoryUnverifiable(format!(
                "historical did:webvh entry digest failed: {error}"
            ))
        })?,
    )
    .map_err(|error| PinnedDidResolutionError::HistoryUnverifiable(error.to_string()))?;
    select_pinned_did_webvh_state(did, history, &selected.version_id, &digest)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DidLogCommitResult {
    Accepted,
    Duplicate,
    Conflict,
}

#[derive(Clone, Debug)]
pub enum ServiceRegistrationCommitResult {
    Created(ServiceRegistrationOutcome),
    Existing(ServiceRegistrationOutcome),
    Conflict,
}

#[async_trait]
pub trait DidDocumentPort: Send + Sync {
    async fn document(&self, did: &str) -> ServiceResult<Option<DidDocumentState>>;
    async fn embedded_document(&self, local_id: &str) -> ServiceResult<Option<DidDocumentState>>;
    async fn log_events(&self, did: &str) -> ServiceResult<Vec<DidLogEvent>>;
    async fn store_document(&self, document: DidDocumentState) -> ServiceResult<()>;
    async fn append_log_event(&self, event: DidLogEvent) -> ServiceResult<()>;
    async fn service_registration(
        &self,
        key: &ServiceRegistrationKey,
    ) -> ServiceResult<Option<ServiceRegistrationOutcome>>;
    async fn commit_service_registration(
        &self,
        key: ServiceRegistrationKey,
        outcome: ServiceRegistrationOutcome,
        document: DidDocumentState,
        event: DidLogEvent,
    ) -> ServiceResult<ServiceRegistrationCommitResult>;
    async fn commit_log_operation(
        &self,
        expected_current_head: Option<String>,
        document: DidDocumentState,
        event: DidLogEvent,
    ) -> ServiceResult<DidLogCommitResult>;
}

#[async_trait]
pub trait DidResolverPort: arkret_identity::DidResolver + Send + Sync {
    async fn resolve_did_async(&self, did: &Did) -> Result<arkret_identity::DidDocument, String>;
    /// Remove any process-local resolution snapshot for a terminally refused
    /// DID. Durable identity state, when present, remains the responsibility of
    /// the trust-admission transaction that attempted to publish it.
    fn discard_cached_document(&self, _did: &Did) {}
    async fn resolve_current_service_did(
        &self,
        _did: &Did,
    ) -> Result<arkret_identity::ResolvedDid, String> {
        Err("current service DID resolver unavailable".into())
    }
    async fn resolve_current_external_webvh_state(
        &self,
        did: &Did,
    ) -> Result<PinnedDidDocumentState, PinnedDidResolutionError>;
    async fn resolve_external_pinned_webvh_state(
        &self,
        did: &Did,
        version_id: &str,
        log_head_digest: &Hash,
    ) -> Result<PinnedDidDocumentState, PinnedDidResolutionError>;
    async fn resolve_external_webvh_state_at(
        &self,
        did: &Did,
        at: DateTime<Utc>,
    ) -> Result<PinnedDidDocumentState, PinnedDidResolutionError>;
    fn cache_document_state(
        &self,
        document: DidDocumentState,
    ) -> Result<arkret_identity::DidDocument, String>;
}

fn verify_local_service_history(
    did: &Did,
    entries: &[Value],
) -> arkret_identity::Result<arkret_identity::VerifiedDidWebvhLog> {
    let current = entries
        .last()
        .and_then(|e| e.pointer("/state/id"))
        .and_then(Value::as_str)
        .ok_or_else(|| {
            arkret_identity::IdentityError::Protocol("native history omits head DID".into())
        })?;
    let current = Did::new(current)?;
    if arkret_wire::project_did_to_core_id(&current)? != arkret_wire::project_did_to_core_id(did)? {
        return Err(arkret_identity::IdentityError::Protocol(
            "native history changed identity core".into(),
        ));
    }
    arkret_identity::verify_did_webvh_v1_chain(&current, entries)
}

#[derive(Clone)]
pub struct DidService {
    documents: Arc<dyn DidDocumentPort>,
    resolver: Arc<dyn DidResolverPort>,
}

/// Apply the SDK's canonical formal test-material policy to every selectable
/// Ed25519 method in a decoded DID document. This is the application-layer
/// trust boundary shared by durable DID commits and HTTP resolver adapters.
pub fn enforce_formal_did_document_admission(
    document: &arkret_identity::DidDocument,
    trust_domain: Option<&TrustDomainId>,
) -> Result<(), String> {
    arkret_identity::test_material::enforce_formal_test_material_policy(
        None,
        Some(&document.id),
        None,
        trust_domain,
    )
    .map_err(|error| error.to_string())?;
    for (method, public_key_multibase) in &document.verification_methods {
        let verification_method = DidUrl::new(method.clone())
            .map_err(|error| format!("DID verification method is invalid: {error}"))?;
        let public_key = arkret_canonical::decode_ed25519_multibase(public_key_multibase)
            .map_err(|error| format!("DID verification method key is invalid: {error}"))?;
        arkret_identity::test_material::enforce_formal_test_material_policy(
            Some(
                &arkret_identity::test_material::PublicKeyFingerprintInput::Ed25519Rfc8032(
                    &public_key,
                ),
            ),
            Some(&document.id),
            Some(&verification_method),
            trust_domain,
        )
        .map_err(|error| error.to_string())?;
    }
    Ok(())
}

impl DidService {
    pub fn new(documents: Arc<dyn DidDocumentPort>, resolver: Arc<dyn DidResolverPort>) -> Self {
        Self {
            documents,
            resolver,
        }
    }

    pub fn resolver(&self) -> &dyn arkret_identity::DidResolver {
        self.resolver.as_ref()
    }

    pub async fn resolve_did(&self, did: &Did) -> Result<arkret_identity::DidDocument, String> {
        if let Some(document) = self
            .documents
            .document(did.as_str())
            .await
            .map_err(|error| error.to_string())?
        {
            return self.resolver.cache_document_state(document);
        }
        self.resolver.resolve_did_async(did).await
    }

    /// Resolve a did:webvh document at an exact native version and canonical
    /// log-entry digest. Durable native history is preferred; external
    /// resolution is used only when no local log exists.
    pub async fn resolve_pinned_webvh_state(
        &self,
        did: &Did,
        version_id: &str,
        log_head_digest: &Hash,
    ) -> Result<PinnedDidDocumentState, PinnedDidResolutionError> {
        if did.method() != "webvh" {
            return Err(PinnedDidResolutionError::UnsupportedMethod);
        }
        let local_events = self.verified_local_webvh_history(did).await?;
        if local_events.is_empty() {
            return self
                .resolver
                .resolve_external_pinned_webvh_state(did, version_id, log_head_digest)
                .await;
        }
        let history = verify_local_service_history(did, &local_events)
            .map_err(|error| PinnedDidResolutionError::HistoryUnverifiable(error.to_string()))?;
        select_pinned_did_webvh_state(did, &history, version_id, log_head_digest)
    }

    /// Resolve the exact verified did:webvh state effective at `at`.
    /// Durable local history is authoritative when present; otherwise the
    /// resolver must fetch and verify the complete external method history.
    pub async fn resolve_webvh_state_at(
        &self,
        did: &Did,
        at: DateTime<Utc>,
    ) -> Result<PinnedDidDocumentState, PinnedDidResolutionError> {
        if did.method() != "webvh" {
            return Err(PinnedDidResolutionError::UnsupportedMethod);
        }
        let local_events = self.verified_local_webvh_history(did).await?;
        if local_events.is_empty() {
            return self.resolver.resolve_external_webvh_state_at(did, at).await;
        }
        let history = verify_local_service_history(did, &local_events)
            .map_err(|error| PinnedDidResolutionError::HistoryUnverifiable(error.to_string()))?;
        select_did_webvh_state_at(did, &history, at)
    }

    /// Resolve and verify the complete did:webvh history, then return its
    /// current method-native head. This is used before issuing a registration
    /// challenge so an unresolvable or deactivated DID never receives a
    /// challenge that no valid control proof can satisfy.
    pub async fn resolve_current_service_did(
        &self,
        did: &Did,
    ) -> Result<arkret_identity::ResolvedDid, String> {
        self.resolver.resolve_current_service_did(did).await
    }

    pub async fn resolve_current_webvh_state(
        &self,
        did: &Did,
    ) -> Result<PinnedDidDocumentState, PinnedDidResolutionError> {
        if did.method() != "webvh" {
            return Err(PinnedDidResolutionError::UnsupportedMethod);
        }
        let local_events = self.verified_local_webvh_history(did).await?;
        if local_events.is_empty() {
            return self
                .resolver
                .resolve_current_external_webvh_state(did)
                .await;
        }
        let history = verify_local_service_history(did, &local_events)
            .map_err(|error| PinnedDidResolutionError::HistoryUnverifiable(error.to_string()))?;
        let head = history.raw_entries.last().ok_or_else(|| {
            PinnedDidResolutionError::HistoryUnverifiable(
                "verified did:webvh history has no head".to_owned(),
            )
        })?;
        let digest = Hash::new(arkret_canonical::canonical_sha256(head).map_err(|error| {
            PinnedDidResolutionError::HistoryUnverifiable(format!(
                "verified did:webvh head digest failed: {error}"
            ))
        })?)
        .map_err(|error| PinnedDidResolutionError::HistoryUnverifiable(error.to_string()))?;
        select_pinned_did_webvh_state(did, &history, &history.head_version_id, &digest)
    }

    async fn verified_local_webvh_history(
        &self,
        did: &Did,
    ) -> Result<Vec<Value>, PinnedDidResolutionError> {
        let mut local_events = self
            .documents
            .log_events(did.as_str())
            .await
            .map_err(|error| {
                PinnedDidResolutionError::HistoryUnverifiable(format!(
                    "local DID history lookup failed: {error}"
                ))
            })?;
        local_events.sort_by_key(|event| event.seq);
        let mut raw_entries = Vec::with_capacity(local_events.len());
        for (index, event) in local_events.iter().enumerate() {
            let expected_seq = index as u64 + 1;
            let entry_did = Did::new(&event.did)
                .map_err(|e| PinnedDidResolutionError::HistoryUnverifiable(e.to_string()))?;
            if arkret_wire::project_did_to_core_id(&entry_did).ok()
                != arkret_wire::project_did_to_core_id(did).ok()
                || event.operation.pointer("/state/id").and_then(Value::as_str)
                    != Some(event.did.as_str())
                || event.seq != expected_seq
            {
                return Err(PinnedDidResolutionError::HistoryUnverifiable(
                    "local did:webvh log identity or sequence is inconsistent".to_owned(),
                ));
            }
            let canonical_digest =
                arkret_canonical::canonical_sha256(&event.operation).map_err(|error| {
                    PinnedDidResolutionError::HistoryUnverifiable(format!(
                        "local did:webvh event digest failed: {error}"
                    ))
                })?;
            if canonical_digest != event.event_digest {
                return Err(PinnedDidResolutionError::HistoryUnverifiable(
                    "local did:webvh event digest does not match stored operation".to_owned(),
                ));
            }
            if event.operation.pointer("/parameters/witness").is_some() {
                return Err(PinnedDidResolutionError::HistoryUnverifiable(
                    "local did:webvh witness evidence is unavailable at the resolver boundary"
                        .to_owned(),
                ));
            }
            raw_entries.push(event.operation.clone());
        }
        Ok(raw_entries)
    }

    pub fn cache_resolved_document_state(
        &self,
        document: DidDocumentState,
    ) -> Result<arkret_identity::DidDocument, String> {
        self.resolver.cache_document_state(document)
    }

    pub fn discard_cached_document(&self, did: &Did) {
        self.resolver.discard_cached_document(did);
    }

    pub async fn document(&self, did: &str) -> ServiceResult<Option<DidDocumentState>> {
        self.documents.document(did).await
    }

    pub async fn embedded_document(
        &self,
        local_id: &str,
    ) -> ServiceResult<Option<DidDocumentState>> {
        self.documents.embedded_document(local_id).await
    }

    pub async fn log_events(&self, did: &str) -> ServiceResult<Vec<DidLogEvent>> {
        self.documents.log_events(did).await
    }

    pub async fn store_document(&self, document: DidDocumentState) -> ServiceResult<()> {
        self.documents.store_document(document).await
    }

    pub async fn append_log_event(&self, event: DidLogEvent) -> ServiceResult<()> {
        self.documents.append_log_event(event).await
    }

    pub async fn service_registration(
        &self,
        key: &ServiceRegistrationKey,
    ) -> ServiceResult<Option<ServiceRegistrationOutcome>> {
        self.documents.service_registration(key).await
    }

    pub async fn commit_service_registration(
        &self,
        key: ServiceRegistrationKey,
        outcome: ServiceRegistrationOutcome,
        document: DidDocumentState,
        event: DidLogEvent,
    ) -> ServiceResult<ServiceRegistrationCommitResult> {
        self.documents
            .commit_service_registration(key, outcome, document, event)
            .await
    }

    pub async fn commit_formal_service_registration(
        &self,
        trust_domain: &TrustDomainId,
        key: ServiceRegistrationKey,
        outcome: ServiceRegistrationOutcome,
        document: DidDocumentState,
        event: DidLogEvent,
    ) -> ServiceResult<ServiceRegistrationCommitResult> {
        let decoded: arkret_identity::DidDocument =
            serde_json::from_value(document.did_document.clone()).map_err(|error| {
                ServiceError::SchemaViolation(format!("service DID document is invalid: {error}"))
            })?;
        enforce_formal_did_document_admission(&decoded, Some(trust_domain))
            .map_err(ServiceError::SchemaViolation)?;
        self.commit_service_registration(key, outcome, document, event)
            .await
    }

    pub async fn commit_log_operation(
        &self,
        expected_current_head: Option<String>,
        document: DidDocumentState,
        event: DidLogEvent,
    ) -> ServiceResult<DidLogCommitResult> {
        self.documents
            .commit_log_operation(expected_current_head, document, event)
            .await
    }

    pub async fn commit_formal_log_operation(
        &self,
        trust_domain: &TrustDomainId,
        expected_current_head: Option<String>,
        document: DidDocumentState,
        event: DidLogEvent,
    ) -> ServiceResult<DidLogCommitResult> {
        let decoded: arkret_identity::DidDocument =
            serde_json::from_value(document.did_document.clone()).map_err(|error| {
                ServiceError::SchemaViolation(format!("DID document is invalid: {error}"))
            })?;
        enforce_formal_did_document_admission(&decoded, Some(trust_domain))
            .map_err(ServiceError::SchemaViolation)?;
        self.commit_log_operation(expected_current_head, document, event)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verification_checkpoint_sources_are_the_closed_formal_three() {
        for (binding_kind, expected_source) in [
            (
                "registration_anchor",
                DeviceSummaryVerificationSource::Genesis,
            ),
            (
                "accepted_device",
                DeviceSummaryVerificationSource::PairingCode,
            ),
            ("pcr_recovery", DeviceSummaryVerificationSource::Recovery),
        ] {
            assert_eq!(
                fold_device_verification_checkpoint("verified", true, Some(binding_kind), false,),
                (
                    DeviceSummaryVerificationState::Verified,
                    Some(expected_source),
                ),
                "{binding_kind} must project its formal checkpoint provenance",
            );
        }

        assert_eq!(
            fold_device_verification_checkpoint("verified", true, Some("server_asserted"), false,),
            (DeviceSummaryVerificationState::Unresolved, None),
            "an unregistered source must not mint a checkpoint",
        );
    }

    #[test]
    fn verification_checkpoint_generation_fence_makes_it_stale_and_keeps_provenance() {
        for binding_kind in ["registration_anchor", "accepted_device", "pcr_recovery"] {
            let (_, expected_source) =
                fold_device_verification_checkpoint("verified", true, Some(binding_kind), false);
            assert_eq!(
                fold_device_verification_checkpoint("verified", true, Some(binding_kind), true,),
                (DeviceSummaryVerificationState::Stale, expected_source),
            );
        }
    }

    #[test]
    fn verification_checkpoint_unresolved_state_drops_any_claimed_provenance() {
        assert_eq!(
            fold_device_verification_checkpoint("unresolved", true, Some("accepted_device"), false,),
            (DeviceSummaryVerificationState::Unresolved, None),
        );
        assert_eq!(
            fold_device_verification_checkpoint(
                "verified",
                false,
                Some("registration_anchor"),
                true,
            ),
            (DeviceSummaryVerificationState::Unresolved, None),
            "an unconfirmed bootstrap row never had a portable checkpoint to stale",
        );
    }

    fn live_checkpoint_facts() -> DeviceCheckpointLiveFacts<'static> {
        DeviceCheckpointLiveFacts {
            lifecycle_active: true,
            verification_state: DeviceSummaryVerificationState::Verified,
            verification_source: Some(DeviceSummaryVerificationSource::PairingCode),
            revocation_gate_active: true,
            checkpoint_authorization_event_id: Some("ak:event:checkpoint"),
            current_authorization_event_id: Some("ak:event:checkpoint"),
            checkpoint_generation_ref: Some(7),
            current_generation_ref: Some(7),
            checkpoint_signing_key: Some("did:key:z6MkCheckpoint"),
            current_signing_key: Some("did:key:z6MkCheckpoint"),
            checkpoint_hpke_key: Some("z6LSCheckpoint"),
            current_hpke_key: Some("z6LSCheckpoint"),
        }
    }

    #[test]
    fn device_checkpoint_live_eligibility_requires_active_lifecycle_and_revocation_gate() {
        assert_eq!(
            evaluate_device_checkpoint_live_eligibility(live_checkpoint_facts()),
            Ok(()),
        );

        let mut revoked = live_checkpoint_facts();
        revoked.lifecycle_active = false;
        revoked.revocation_gate_active = false;
        assert_eq!(
            evaluate_device_checkpoint_live_eligibility(revoked),
            Err(DeviceCheckpointIneligibility::LifecycleNotActive),
        );

        let mut revocation_pending = live_checkpoint_facts();
        revocation_pending.revocation_gate_active = false;
        assert_eq!(
            evaluate_device_checkpoint_live_eligibility(revocation_pending),
            Err(DeviceCheckpointIneligibility::RevocationGateNotActive),
        );
    }

    #[test]
    fn device_checkpoint_live_eligibility_fences_generation_and_exact_key_rotation() {
        let mut generation_fenced = live_checkpoint_facts();
        generation_fenced.current_generation_ref = Some(8);
        assert_eq!(
            evaluate_device_checkpoint_live_eligibility(generation_fenced),
            Err(DeviceCheckpointIneligibility::GenerationMismatch),
        );

        let mut signing_key_rotated = live_checkpoint_facts();
        signing_key_rotated.current_signing_key = Some("did:key:z6MkRotated");
        assert_eq!(
            evaluate_device_checkpoint_live_eligibility(signing_key_rotated),
            Err(DeviceCheckpointIneligibility::SigningKeyMismatch),
        );

        let mut hpke_key_rotated = live_checkpoint_facts();
        hpke_key_rotated.current_hpke_key = Some("z6LSRotated");
        assert_eq!(
            evaluate_device_checkpoint_live_eligibility(hpke_key_rotated),
            Err(DeviceCheckpointIneligibility::HpkeKeyMismatch),
        );
    }

    struct StaticAccount;

    struct NoDevices;

    struct NoAgents;

    struct StaticDidDocuments;

    struct NoDidResolver;

    impl arkret_identity::DidResolver for NoDidResolver {
        fn supports(&self, _did: &Did) -> bool {
            false
        }

        fn resolve_did(&self, _did: &Did) -> arkret_identity::Result<arkret_identity::ResolvedDid> {
            Err(arkret_identity::IdentityError::Protocol(
                "DID resolver is unused in this test".to_owned(),
            ))
        }
    }

    #[async_trait]
    impl DidResolverPort for NoDidResolver {
        async fn resolve_did_async(
            &self,
            _did: &Did,
        ) -> Result<arkret_identity::DidDocument, String> {
            Err("DID resolver is unused in this test".to_owned())
        }

        async fn resolve_current_external_webvh_state(
            &self,
            _did: &Did,
        ) -> Result<PinnedDidDocumentState, PinnedDidResolutionError> {
            Err(PinnedDidResolutionError::HistoryUnavailable)
        }

        async fn resolve_external_pinned_webvh_state(
            &self,
            _did: &Did,
            _version_id: &str,
            _log_head_digest: &Hash,
        ) -> Result<PinnedDidDocumentState, PinnedDidResolutionError> {
            Err(PinnedDidResolutionError::HistoryUnavailable)
        }

        async fn resolve_external_webvh_state_at(
            &self,
            _did: &Did,
            _at: DateTime<Utc>,
        ) -> Result<PinnedDidDocumentState, PinnedDidResolutionError> {
            Err(PinnedDidResolutionError::HistoryUnavailable)
        }

        fn cache_document_state(
            &self,
            _document: DidDocumentState,
        ) -> Result<arkret_identity::DidDocument, String> {
            Err("DID resolver is unused in this test".to_owned())
        }
    }

    fn pinned_history_fixture() -> (Did, arkret_identity::VerifiedDidWebvhLog, Hash) {
        let did = Did::new("did:webvh:zFixture:organization.example".to_owned()).unwrap();
        let first_state = serde_json::json!({
            "id": did,
            "verificationMethod": [{
                "id": format!("{did}#control-1"),
                "type": "Multikey",
                "controller": did,
                "publicKeyMultibase": "z6MkrJVnaZkeFzdQyHL9T5yCDonTuB9R2cZWLMgLMN8GX4gu"
            }]
        });
        let second_state = serde_json::json!({
            "id": did,
            "verificationMethod": [{
                "id": format!("{did}#control-2"),
                "type": "Multikey",
                "controller": did,
                "publicKeyMultibase": "z6MkrJVnaZkeFzdQyHL9T5yCDonTuB9R2cZWLMgLMN8GX4gu"
            }]
        });
        let first_raw = serde_json::json!({
            "versionId": "1-first",
            "versionTime": "2026-07-01T00:00:00Z",
            "parameters": {
                "method": "did:webvh:1.0",
                "scid": "zFixture",
                "updateKeys": ["z6MkrJVnaZkeFzdQyHL9T5yCDonTuB9R2cZWLMgLMN8GX4gu"]
            },
            "state": first_state,
            "proof": []
        });
        let second_raw = serde_json::json!({
            "versionId": "2-second",
            "versionTime": "2026-07-02T00:00:00Z",
            "parameters": {
                "method": "did:webvh:1.0",
                "scid": "zFixture",
                "updateKeys": ["z6MkrJVnaZkeFzdQyHL9T5yCDonTuB9R2cZWLMgLMN8GX4gu"]
            },
            "state": second_state,
            "proof": []
        });
        let first_digest =
            Hash::new(arkret_canonical::canonical_sha256(&first_raw).unwrap()).unwrap();
        let history = arkret_identity::VerifiedDidWebvhLog {
            raw_entries: vec![first_raw, second_raw],
            entries: vec![
                arkret_identity::DidWebvhLogEntry {
                    version_id: "1-first".to_owned(),
                    version_time: "2026-07-01T00:00:00Z".parse().unwrap(),
                    parameters: serde_json::json!({
                        "method": "did:webvh:1.0",
                        "scid": "zFixture",
                        "updateKeys": ["z6MkrJVnaZkeFzdQyHL9T5yCDonTuB9R2cZWLMgLMN8GX4gu"]
                    }),
                    state: first_state,
                    proof: Vec::new(),
                },
                arkret_identity::DidWebvhLogEntry {
                    version_id: "2-second".to_owned(),
                    version_time: "2026-07-02T00:00:00Z".parse().unwrap(),
                    parameters: serde_json::json!({
                        "method": "did:webvh:1.0",
                        "scid": "zFixture",
                        "updateKeys": ["z6MkrJVnaZkeFzdQyHL9T5yCDonTuB9R2cZWLMgLMN8GX4gu"]
                    }),
                    state: second_state,
                    proof: Vec::new(),
                },
            ],
            head_version_id: "2-second".to_owned(),
            head_state: serde_json::Value::Null,
            active_update_keys: vec!["z6MkrJVnaZkeFzdQyHL9T5yCDonTuB9R2cZWLMgLMN8GX4gu".to_owned()],
        };
        (did, history, first_digest)
    }

    #[test]
    fn pinned_webvh_selection_returns_exact_historical_state_and_rotation_status() {
        let (did, history, first_digest) = pinned_history_fixture();
        let selected =
            select_pinned_did_webvh_state(&did, &history, "1-first", &first_digest).unwrap();
        assert_eq!(selected.version_id, "1-first");
        assert_eq!(selected.current_version_id, "2-second");
        assert_eq!(selected.status, PinnedDidVersionStatus::Rotated);
        assert_eq!(
            selected.document["verificationMethod"][0]["id"],
            format!("{did}#control-1")
        );
    }

    #[test]
    fn pinned_webvh_selection_rejects_digest_substitution() {
        let (did, history, _) = pinned_history_fixture();
        let wrong_digest = Hash::new(format!("sha256:{}", "0".repeat(64))).unwrap();
        assert_eq!(
            select_pinned_did_webvh_state(&did, &history, "1-first", &wrong_digest),
            Err(PinnedDidResolutionError::DigestMismatch)
        );
    }

    #[test]
    fn pinned_webvh_selection_surfaces_terminal_deactivation() {
        let (did, mut history, first_digest) = pinned_history_fixture();
        history.entries[1]
            .parameters
            .as_object_mut()
            .unwrap()
            .insert("deactivated".to_owned(), Value::Bool(true));
        let selected =
            select_pinned_did_webvh_state(&did, &history, "1-first", &first_digest).unwrap();
        assert_eq!(selected.status, PinnedDidVersionStatus::Deactivated);
    }

    #[test]
    fn webvh_selection_at_uses_the_last_version_not_after_the_evidence() {
        let (did, history, _) = pinned_history_fixture();
        let selected =
            select_did_webvh_state_at(&did, &history, "2026-07-01T12:00:00Z".parse().unwrap())
                .unwrap();
        assert_eq!(selected.version_id, "1-first");
        assert_eq!(selected.status, PinnedDidVersionStatus::Rotated);

        let selected =
            select_did_webvh_state_at(&did, &history, "2026-07-02T00:00:00Z".parse().unwrap())
                .unwrap();
        assert_eq!(selected.version_id, "2-second");
        assert_eq!(selected.status, PinnedDidVersionStatus::Current);
    }

    #[test]
    fn webvh_selection_at_rejects_evidence_before_genesis() {
        let (did, history, _) = pinned_history_fixture();
        assert!(matches!(
            select_did_webvh_state_at(&did, &history, "2026-06-30T23:59:59Z".parse().unwrap(),),
            Err(PinnedDidResolutionError::VersionTimeNotFound(_))
        ));
    }

    #[test]
    fn webvh_selection_at_rejects_evidence_after_deactivation() {
        let (did, mut history, _) = pinned_history_fixture();
        history.entries[1]
            .parameters
            .as_object_mut()
            .unwrap()
            .insert("deactivated".to_owned(), Value::Bool(true));
        assert!(matches!(
            select_did_webvh_state_at(&did, &history, "2026-07-02T00:00:01Z".parse().unwrap(),),
            Err(PinnedDidResolutionError::DeactivatedAt(_))
        ));
        assert!(
            select_did_webvh_state_at(&did, &history, "2026-07-01T12:00:00Z".parse().unwrap(),)
                .is_ok()
        );
    }

    #[async_trait]
    impl AccountLookupPort for StaticAccount {
        async fn find_account_by_actor(
            &self,
            account_id: &AccountId,
        ) -> ServiceResult<Option<AccountIdentity>> {
            Ok(
                (account_id.principal_id.as_str() == "ak:did_core:web:alice.example").then(|| {
                    AccountIdentity {
                        account_pk: AccountPk(1),
                        account_id: account_id.clone(),
                    }
                }),
            )
        }

        async fn account_by_id(
            &self,
            account_pk: AccountPk,
        ) -> ServiceResult<Option<AccountProfileState>> {
            Ok((account_pk == AccountPk(1)).then(|| AccountProfileState {
                pk: AccountPk(1),
                account_id: AccountId::new(
                    DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
                    DidCoreId::new("ak:did_core:web:principal.example").unwrap(),
                ),
                principal_id: DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
                localpart: "alice".to_owned(),
                display_name: None,
                bio: None,
                avatar_blob_ref: None,
                created_at: Utc::now(),
            }))
        }

        async fn register_account(
            &self,
            command: RegisterAccountCommand,
        ) -> ServiceResult<AccountIdentity> {
            Ok(AccountIdentity {
                account_pk: AccountPk(1),
                account_id: command.account_id,
            })
        }

        async fn account(
            &self,
            _account_id: &AccountId,
        ) -> ServiceResult<Option<AccountProfileState>> {
            Ok(None)
        }

        async fn accounts(&self) -> ServiceResult<Vec<AccountProfileState>> {
            Ok(Vec::new())
        }

        async fn save_account(&self, _account: AccountProfileState) -> ServiceResult<()> {
            Ok(())
        }

        async fn delete_account(&self, _account_id: &AccountId) -> ServiceResult<()> {
            Ok(())
        }

        async fn account_localparts(
            &self,
            _account_pk: AccountPk,
        ) -> ServiceResult<Vec<AccountLocalpartState>> {
            Ok(Vec::new())
        }

        async fn localpart_owner(
            &self,
            _localpart: &str,
        ) -> ServiceResult<Option<AccountLocalpartState>> {
            Ok(None)
        }

        async fn add_localpart(
            &self,
            _account_pk: AccountPk,
            _localpart: &str,
            _primary: bool,
        ) -> ServiceResult<AccountLocalpartState> {
            unreachable!()
        }

        async fn remove_localpart(
            &self,
            _account_pk: AccountPk,
            _localpart: &str,
        ) -> ServiceResult<()> {
            Ok(())
        }

        async fn clear_localparts(&self, _account_pk: AccountPk) -> ServiceResult<()> {
            Ok(())
        }

        async fn record_handle_release(
            &self,
            _localpart: &str,
            _released_at: DateTime<Utc>,
        ) -> ServiceResult<()> {
            Ok(())
        }

        async fn save_account_lifecycle(
            &self,
            _account_pk: AccountPk,
            _actor_id: &str,
            _lifecycle: AccountLifecycleState,
        ) -> ServiceResult<()> {
            Ok(())
        }

        async fn delete_account_lifecycle(
            &self,
            _account_pk: AccountPk,
            _actor_id: &str,
        ) -> ServiceResult<()> {
            Ok(())
        }
    }

    #[async_trait]
    impl DeviceDirectoryPort for NoDevices {
        async fn list_active_device_actors(&self) -> ServiceResult<Vec<String>> {
            Ok(Vec::new())
        }

        async fn devices(&self) -> ServiceResult<Vec<DeviceIdentity>> {
            Ok(Vec::new())
        }

        async fn find_device(
            &self,
            _actor_id: &str,
            _device_id: &str,
        ) -> ServiceResult<Option<DeviceIdentity>> {
            Ok(None)
        }

        async fn save_device(&self, _command: SaveDeviceCommand) -> ServiceResult<()> {
            Ok(())
        }

        async fn save_device_if_absent(&self, _device: DeviceIdentity) -> ServiceResult<bool> {
            Ok(true)
        }

        async fn devices_for_actor(&self, _actor_id: &str) -> ServiceResult<Vec<DeviceIdentity>> {
            Ok(Vec::new())
        }
    }

    #[async_trait]
    impl AgentDirectoryPort for NoAgents {
        async fn find_agent_controller(
            &self,
            _agent_id: &str,
        ) -> ServiceResult<Option<AgentController>> {
            Ok(None)
        }
    }

    #[async_trait]
    impl DidDocumentPort for StaticDidDocuments {
        async fn document(&self, did: &str) -> ServiceResult<Option<DidDocumentState>> {
            let now = Utc::now();
            Ok((did == "did:web:alice.example").then(|| DidDocumentState {
                did: did.to_owned(),
                did_document: serde_json::json!({"id": did}),
                key_log_head: None,
                seq: 1,
                method_evidence: Value::Null,
                fetched_at: now,
                expires_at: now,
                updated_at: now,
            }))
        }

        async fn embedded_document(
            &self,
            _local_id: &str,
        ) -> ServiceResult<Option<DidDocumentState>> {
            Ok(None)
        }

        async fn log_events(&self, _did: &str) -> ServiceResult<Vec<DidLogEvent>> {
            Ok(Vec::new())
        }

        async fn store_document(&self, _document: DidDocumentState) -> ServiceResult<()> {
            Ok(())
        }

        async fn append_log_event(&self, _event: DidLogEvent) -> ServiceResult<()> {
            Ok(())
        }

        async fn service_registration(
            &self,
            _key: &ServiceRegistrationKey,
        ) -> ServiceResult<Option<ServiceRegistrationOutcome>> {
            Ok(None)
        }

        async fn commit_service_registration(
            &self,
            _key: ServiceRegistrationKey,
            _outcome: ServiceRegistrationOutcome,
            _document: DidDocumentState,
            _event: DidLogEvent,
        ) -> ServiceResult<ServiceRegistrationCommitResult> {
            Ok(ServiceRegistrationCommitResult::Conflict)
        }

        async fn commit_log_operation(
            &self,
            _expected_current_head: Option<String>,
            _document: DidDocumentState,
            _event: DidLogEvent,
        ) -> ServiceResult<DidLogCommitResult> {
            Ok(DidLogCommitResult::Conflict)
        }
    }

    #[tokio::test]
    async fn account_lookup_returns_application_owned_result() {
        let service = IdentityService::new(
            Arc::new(StaticAccount),
            Arc::new(NoDevices),
            Arc::new(NoAgents),
        );
        let account = service
            .find_account_by_actor(FindAccountByActorQuery {
                account_id: AccountId::new(
                    DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
                    DidCoreId::new("ak:did_core:web:principal.example").unwrap(),
                ),
            })
            .await
            .expect("lookup account")
            .expect("account exists");
        assert_eq!(
            account.account_id.principal_id.as_str(),
            "ak:did_core:web:alice.example"
        );
    }

    #[tokio::test]
    async fn did_lookup_is_independent_from_http_and_app_state() {
        let service = DidService::new(Arc::new(StaticDidDocuments), Arc::new(NoDidResolver));
        let document = service
            .document("did:web:alice.example")
            .await
            .expect("lookup DID")
            .expect("DID exists");
        assert_eq!(
            document.did_document,
            serde_json::json!({"id": document.did})
        );
    }

    #[tokio::test]
    async fn formal_test_material_is_rejected_before_the_durable_did_ledger_port() {
        let service = DidService::new(Arc::new(StaticDidDocuments), Arc::new(NoDidResolver));
        let did = Did::new("did:web:real-deployment.company".to_owned()).unwrap();
        let verification_method = format!("{did}#renamed-production-key");
        let seed: [u8; 32] = std::array::from_fn(|index| index as u8);
        let published_key = ed25519_dalek::SigningKey::from_bytes(&seed).verifying_key();
        let document = arkret_identity::DidDocument {
            id: did.clone(),
            verification_methods: BTreeMap::from([(
                verification_method,
                arkret_canonical::ed25519_pubkey_to_did_key_multibase(published_key.as_bytes()),
            )]),
            also_known_as: Vec::new(),
            updated_at: Some(Utc::now()),
            raw_properties: BTreeMap::new(),
        };
        let now = Utc::now();
        let document = DidDocumentState {
            did: did.to_string(),
            did_document: serde_json::to_value(document).unwrap(),
            key_log_head: None,
            seq: 1,
            method_evidence: serde_json::json!({"mode": "verified-production-resolution"}),
            fetched_at: now,
            expires_at: now,
            updated_at: now,
        };
        let event = DidLogEvent {
            event_digest: arkret_canonical::sha256_digest(b"formal-test-material"),
            did: did.to_string(),
            seq: 1,
            operation: serde_json::json!({"state": {"id": did}}),
            created_at: now,
        };
        let trust_domain =
            TrustDomainId::new("ak:trust_domain:production.company".to_owned()).unwrap();

        let error = service
            .commit_formal_log_operation(&trust_domain, None, document, event)
            .await
            .expect_err("published signing material must not reach durable commit");

        assert_eq!(
            error.to_string(),
            "schema violation: test_signing_material_denied"
        );
        assert!(
            service.document(did.as_str()).await.unwrap().is_none(),
            "the rejected DID must leave no durable document row"
        );
        assert!(service.log_events(did.as_str()).await.unwrap().is_empty());
    }
}
