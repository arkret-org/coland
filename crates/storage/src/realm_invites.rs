use super::{PersistenceResult, async_trait};

/// One directed Invite completed from its committed create Event and typed current at one cut.
#[derive(Clone, Debug)]
pub struct InviteCurrent {
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

#[async_trait]
pub trait InviteCurrentStateStore: Send + Sync {
    async fn check_realm_invite_link_preview(
        &self,
        request: &arkret_models_collaboration::governance::realm_join_intake::PeerRealmJoinPreviewRequestBody,
        at: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<()>;

    async fn invites_in_realm(
        &self,
        realm_id: Option<&arkret_wire::RealmId>,
    ) -> PersistenceResult<Vec<InviteCurrent>>;
    async fn open_directed_invites_for_invitee(
        &self,
        invitee: &arkret_wire::AccountId,
        realm_id: Option<&arkret_wire::RealmId>,
    ) -> PersistenceResult<Vec<InviteCurrent>>;
}
