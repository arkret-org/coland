use arkret_models_collaboration::governance::third_party_invite::{
    ThirdPartyInvite, ThirdPartyInviteAcceptanceAttestation,
    ThirdPartyInviteAcceptanceAttestationOutcome, ThirdPartyInviteAcceptanceAttestationRequestBody,
};

use super::{PersistenceResult, async_trait};

/// One directed Invite read from its `invite_lifecycle` and
/// `invite_directed_invitee` typed current results and completed from the
/// committed `ak.invite.create` its InviteId retypes, all at one cut.
#[derive(Clone, Debug)]
pub struct DirectedInviteCurrent {
    pub realm_id: arkret_wire::RealmId,
    pub invite_id: arkret_wire::InviteId,
    pub state: arkret_wire::InviteState,
    pub state_updated_at: chrono::DateTime<chrono::Utc>,
    pub inviter: arkret_wire::ActorId,
    pub invitee_account_id: arkret_wire::AccountId,
    pub introduction_evidence_digest: arkret_wire::Hash,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// One Invite assembled at one database cut from its lifecycle result,
/// committed create Event, and (for a claimed 3PID Invite) committed claim.
#[derive(Clone, Debug)]
pub struct InviteCurrent {
    pub realm_id: arkret_wire::RealmId,
    pub invite_id: arkret_wire::InviteId,
    pub state: arkret_wire::InviteState,
    pub state_updated_at: chrono::DateTime<chrono::Utc>,
    pub inviter: arkret_wire::ActorId,
    pub invitee_account_id: Option<arkret_wire::AccountId>,
    pub introduction_evidence_digest: Option<arkret_wire::Hash>,
    pub third_party_invite: Option<ThirdPartyInvite>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub accepted_claim: Option<AcceptedThirdPartyClaim>,
}

#[derive(Clone, Debug)]
pub struct AcceptedThirdPartyClaim {
    pub event_id: arkret_wire::EventId,
    pub subject_account_id: arkret_wire::AccountId,
    pub claim_nonce: String,
    pub token_commitment: arkret_wire::Hash,
    pub verification_id: arkret_wire::DidCoreId,
    pub claimed_at: chrono::DateTime<chrono::Utc>,
}

/// Local signing capability invoked before releasing the accepted Realm cut.
pub type InviteAcceptanceAttestationSigner<'a> = dyn Fn(&ThirdPartyInviteAcceptanceAttestation) -> PersistenceResult<arkret_wire::PayloadProof>
    + Send
    + Sync
    + 'a;

/// Frozen public invite binding for a same-Station delegated provider.
/// This is an in-process storage contract, never an HTTP payload.
#[derive(Clone, Debug)]
pub struct ThirdPartyInviteProviderLivenessRequest {
    pub realm_id: arkret_wire::RealmId,
    pub invite_id: arkret_wire::InviteId,
    pub inviter_account_id: arkret_wire::AccountId,
    pub third_party_invite: ThirdPartyInvite,
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

/// Holds the governing cut through private consume or actual delivery.
/// Dropping an unfinished guard must release and discard its database session.
#[async_trait]
pub trait ThirdPartyInviteProviderLivenessGuard: Send {
    fn observed_at(&self) -> chrono::DateTime<chrono::Utc>;
    async fn finish(self: Box<Self>) -> PersistenceResult<()>;
}

/// Reads over the Invite typed current results.
#[async_trait]
pub trait InviteCurrentResultStore: Send + Sync {
    /// Sign only while the local governing Realm cut still holds the accepted
    /// pending invite, its exact author and the current verifier allowlist.
    /// The callback returns a proof over the SDK attestation; it executes before
    /// releasing that cut. No private provisioning material is read here.
    async fn third_party_invite_acceptance_attestation(
        &self,
        request: &ThirdPartyInviteAcceptanceAttestationRequestBody,
        caller: &arkret_wire::AccountId,
        station: &arkret_wire::DidCoreId,
        verification_method: &arkret_wire::DidUrl,
        observe: &(dyn Fn() -> chrono::DateTime<chrono::Utc> + Send + Sync),
        sign: &InviteAcceptanceAttestationSigner<'_>,
    ) -> PersistenceResult<ThirdPartyInviteAcceptanceAttestationOutcome>;

    /// Verify the inviter's current accepted Device over the original SDK
    /// provisioning transcript and hold that PCR cut through private minting.
    async fn acquire_third_party_invite_provision_device(
        &self,
        _request: &arkret_models_collaboration::governance::third_party_invite::ThirdPartyInviteProvisionRequestBody,
        _station: &arkret_wire::DidCoreId,
        _observe: &(dyn Fn() -> chrono::DateTime<chrono::Utc> + Send + Sync),
    ) -> PersistenceResult<Box<dyn ThirdPartyInviteProviderLivenessGuard>> {
        Err(super::PersistenceError::Conflict(
            "revision_unavailable: current inviter Device cut is unavailable".into(),
        ))
    }

    /// Acquire current liveness; portable activation evidence is insufficient
    /// to authorize a later token consume or out-of-band delivery.
    async fn acquire_third_party_invite_provider_liveness(
        &self,
        _request: &ThirdPartyInviteProviderLivenessRequest,
        _station: &arkret_wire::DidCoreId,
        _observe: &(dyn Fn() -> chrono::DateTime<chrono::Utc> + Send + Sync),
    ) -> PersistenceResult<Box<dyn ThirdPartyInviteProviderLivenessGuard>> {
        Err(super::PersistenceError::Conflict(
            "revision_unavailable: current governing invite cut is unavailable".into(),
        ))
    }

    /// Invite results, optionally filtered to one Realm, completed from
    /// committed create and claim Events under one repeatable-read snapshot.
    async fn invites_in_realm(
        &self,
        realm_id: Option<&arkret_wire::RealmId>,
    ) -> PersistenceResult<Vec<InviteCurrent>>;
    /// Every directed Invite addressed to exactly `invitee` whose lifecycle is
    /// still open (`pending` or `claimed`), optionally within one Realm.
    async fn open_directed_invites_for_invitee(
        &self,
        invitee: &arkret_wire::AccountId,
        realm_id: Option<&arkret_wire::RealmId>,
    ) -> PersistenceResult<Vec<DirectedInviteCurrent>>;
}
