//! Holder-private PCR Consent current, never a process-local authority cache.

use arkret_models_collaboration::consent_operations::{ConsentValue, ConsentView};
use arkret_wire::{AccountId, CurrentRevision, Event, RealmCommit};
use async_trait::async_trait;

use crate::{AuthorityCommitTransaction, PersistenceResult};

#[derive(Clone, Debug)]
pub struct ConsentAdmissionWrite {
    pub transaction: AuthorityCommitTransaction,
}

#[derive(Clone, Debug)]
pub struct ConsentCurrentRecord {
    pub peer: arkret_models_collaboration::events_payloads::consent::ConsentPeer,
    pub value: ConsentValue,
    pub event: Event,
    pub commit: RealmCommit,
    /// Successful invalidation CAS; absent on reads and exact retries.
    pub quarantine_update: Option<crate::AccountDataRecord>,
}

impl ConsentCurrentRecord {
    /// Evaluate the complete peer and the current grant at the read cut.
    /// Unimplemented constraint semantics never silently widen consent.
    pub fn permits(
        &self,
        peer: &arkret_wire::ActorId,
        scope: arkret_wire::ConsentScope,
        at: chrono::DateTime<chrono::Utc>,
    ) -> bool {
        self.peer
            == (arkret_models_collaboration::events_payloads::consent::ConsentPeer::Actor {
                actor_id: peer.clone(),
            })
            && self.value.permissions.iter().any(|permission| {
                permission.consent_scope == scope
                    && permission.not_before.is_none_or(|start| start <= at)
                    && permission.expires_at.is_none_or(|end| at < end)
                    && permission.constraints.as_ref().is_none_or(Vec::is_empty)
            })
    }

    pub fn view(&self) -> ConsentView {
        ConsentView {
            peer: self.peer.clone(),
            permission_scopes: self
                .value
                .permissions
                .iter()
                .map(|p| p.consent_scope)
                .collect(),
            updated_at: self.commit.committed_at,
            revision: CurrentRevision {
                commit_id: self.commit.commit_id.clone(),
                stream_position: self.commit.stream_position,
            },
        }
    }
}

#[derive(Clone, Debug)]
pub enum ConsentAdmissionOutcome {
    Committed(ConsentCurrentRecord),
    Duplicate(ConsentCurrentRecord),
}

/// Internal private-delivery CAS bound to a current Consent at its write cut.
#[derive(Clone, Debug)]
pub struct ConsentDeliveryWrite {
    pub holder: AccountId,
    pub acceptor_service_id: arkret_wire::DidCoreId,
    pub peer: arkret_wire::ActorId,
    pub consent_grant_ref: arkret_wire::EventId,
    pub record: crate::AccountDataRecord,
    pub expected_revision: u64,
}

/// Complete targeted PCR read, serialized with its current writers.
#[derive(Clone, Debug)]
pub struct ConsentCurrentCut {
    pub realm_id: arkret_wire::RealmId,
    pub generation: u64,
    pub service_id: arkret_wire::DidCoreId,
    pub head: arkret_wire::CommitStreamHead,
    pub records: Vec<ConsentCurrentRecord>,
    pub evaluated_at: chrono::DateTime<chrono::Utc>,
    pub device_admitted: bool,
}

#[async_trait]
pub trait ConsentCurrentStore: Send + Sync {
    /// An immutable signed CAS basis; never proof of the present permission.
    async fn historical_basis(
        &self,
        holder: &AccountId,
        peer: &arkret_wire::ActorId,
        revision: &CurrentRevision,
    ) -> PersistenceResult<Option<crate::CommittedEventRecord>>;
    async fn drain_native_effects(
        &self,
        _holder: &AccountId,
        _issuer: &arkret_wire::DidCoreId,
    ) -> PersistenceResult<Vec<crate::AccountDataRecord>> {
        Err(crate::PersistenceError::Conflict(
            "native effect recovery is unavailable".into(),
        ))
    }
    async fn pending_effect_holders(
        &self,
        _issuer: &arkret_wire::DidCoreId,
    ) -> PersistenceResult<Vec<AccountId>> {
        Ok(Vec::new())
    }
    async fn prepare_effect_publication(
        &self,
        _holder: &AccountId,
        _issuer: &arkret_wire::DidCoreId,
        _nonce: String,
    ) -> PersistenceResult<Option<PrivateEffectsPublication>> {
        Err(crate::PersistenceError::Conflict(
            "temporarily_unavailable: private effect publisher is unavailable".into(),
        ))
    }
    async fn acknowledge_effect_publication(
        &self,
        _holder: &AccountId,
        _issuer: &arkret_wire::DidCoreId,
        _sequence: u64,
    ) -> PersistenceResult<()> {
        Err(crate::PersistenceError::Conflict(
            "temporarily_unavailable: private effect acknowledgement is unavailable".into(),
        ))
    }
    async fn project_effect_publication(
        &self,
        _request:&arkret_models_collaboration::consent_private::ConsentPrivateEffectsPublishRequest,
        _source: &arkret_wire::DidCoreId,
        _receiver: &arkret_wire::DidCoreId,
        _authority: &crate::CurrentRealmAuthority,
        _known_head: &arkret_wire::CommitStreamHead,
    ) -> PersistenceResult<PrivateEffectsProjection> {
        Err(crate::PersistenceError::Conflict(
            "temporarily_unavailable: private effect projection is unavailable".into(),
        ))
    }
    /// A hosting projection can only reject rollback; it never authorizes effects.
    async fn observe_private_cut(
        &self,
        _request: &arkret_models_collaboration::consent_private::ConsentPrivateProxyRequest,
        _outcome: &arkret_models_collaboration::consent_private::ConsentPrivateProxyOutcome,
    ) -> PersistenceResult<()> {
        Err(crate::PersistenceError::Conflict(
            "temporarily_unavailable: private proxy high water is unavailable".into(),
        ))
    }
    async fn native_command(
        &self,
        _holder: &AccountId,
        _context: &arkret_models_collaboration::consent_private::ConsentPrivateContext,
        _command: &arkret_models_collaboration::consent_private::ConsentPrivateCommand,
        _acceptor: &arkret_wire::DidCoreId,
        _quota: &arkret_wire::NewSourceQuotaConstraints,
        _prepared: Option<&PreparedPrivateInviteDelivery>,
    ) -> PersistenceResult<arkret_models_collaboration::consent_private::ConsentPrivateCommandOutcome>
    {
        Err(crate::PersistenceError::Conflict(
            "native Human commands are unavailable".into(),
        ))
    }
    async fn private_command_prepared(
        &self,
        request: &arkret_models_collaboration::consent_private::ConsentPrivateProxyRequest,
        source: &arkret_wire::DidCoreId,
        acceptor: &arkret_wire::DidCoreId,
        quota: &arkret_wire::NewSourceQuotaConstraints,
        prepared: Option<&PreparedPrivateInviteDelivery>,
    ) -> PersistenceResult<arkret_models_collaboration::consent_private::ConsentPrivateProxyOutcome>
    {
        if prepared.is_some() {
            return Err(crate::PersistenceError::Conflict(
                "temporarily_unavailable: verified private Invite admission is unavailable".into(),
            ));
        }
        self.private_command(request, source, acceptor, quota).await
    }
    /// Execute a closed private command at the current accepting PCR authority.
    async fn private_command(
        &self,
        _request: &arkret_models_collaboration::consent_private::ConsentPrivateProxyRequest,
        _source_service: &arkret_wire::DidCoreId,
        _acceptor_service: &arkret_wire::DidCoreId,
        _quota_constraints: &arkret_wire::NewSourceQuotaConstraints,
    ) -> PersistenceResult<arkret_models_collaboration::consent_private::ConsentPrivateProxyOutcome>
    {
        Err(crate::PersistenceError::Conflict(
            "temporarily_unavailable: native private command is unavailable".into(),
        ))
    }
    async fn read_cut(
        &self,
        holder: &AccountId,
        peer: &arkret_models_collaboration::events_payloads::consent::ConsentPeer,
        device: Option<&arkret_wire::DeviceId>,
    ) -> PersistenceResult<ConsentCurrentCut>;
    async fn admit(
        &self,
        write: ConsentAdmissionWrite,
    ) -> PersistenceResult<ConsentAdmissionOutcome>;
    /// `None` refuses a no-longer-valid proof without any private write.
    async fn admit_invite_delivery(
        &self,
        write: ConsentDeliveryWrite,
    ) -> PersistenceResult<Option<crate::AccountDataCasResult>>;
    async fn list(&self, holder: &AccountId) -> PersistenceResult<Vec<ConsentCurrentRecord>>;
}

/// A receiver's original verified Invite receipt, bound to the entire private
/// command. It cannot be constructed by deserializing a caller-controlled flag.
#[derive(Clone)]
pub struct PreparedPrivateInviteDelivery {
    request_digest: Option<String>,
    native_command: Option<(
        AccountId,
        arkret_models_collaboration::consent_private::ConsentPrivateCommand,
    )>,
    locator_verified: bool,
    constraints: Option<arkret_wire::ReceivePolicyConstraints>,
}
impl PreparedPrivateInviteDelivery {
    pub fn from_verified_receipt(
        request: &arkret_models_collaboration::consent_private::ConsentPrivateProxyRequest,
        fact: &arkret_identity::account_device_signer_evidence::VerifiedAccountDeviceHistoricalSignerFact,
        locator_verified: bool,
        constraints: Option<arkret_wire::ReceivePolicyConstraints>,
    ) -> PersistenceResult<Self> {
        let mut prepared = Self::from_verified_native_receipt(
            &request.holder_account_id,
            &request.command,
            fact,
            locator_verified,
            constraints,
        )?;
        prepared.request_digest = Some(
            request
                .digest()
                .map_err(|e| crate::PersistenceError::SchemaViolation(e.to_string()))?,
        );
        prepared.native_command = None;
        Ok(prepared)
    }
    pub fn from_verified_native_receipt(
        holder: &AccountId,
        command: &arkret_models_collaboration::consent_private::ConsentPrivateCommand,
        fact: &arkret_identity::account_device_signer_evidence::VerifiedAccountDeviceHistoricalSignerFact,
        locator_verified: bool,
        constraints: Option<arkret_wire::ReceivePolicyConstraints>,
    ) -> PersistenceResult<Self> {
        let full_command = command.clone();
        let arkret_models_collaboration::consent_private::ConsentPrivateCommand::InviteDelivery(
            command,
        ) = command
        else {
            return Err(crate::PersistenceError::SchemaViolation(
                "verified Invite material requires an Invite command".into(),
            ));
        };
        let delivery = &command.body.delivery;
        let full = arkret_wire::CommittedEventFullView {
            event: delivery.invite_event.clone(),
            commit: delivery.invite_commit.clone(),
        };
        fact.fact()
            .validate_commit_binding(
                &full,
                delivery
                    .invite_event
                    .realm_id
                    .digest_suite_code()
                    .digest_suite(),
            )
            .map_err(|e| crate::PersistenceError::SchemaViolation(e.to_string()))?;
        if delivery.producer_signer_fact.as_ref() != Some(fact.fact()) {
            return Err(crate::PersistenceError::SchemaViolation(
                "verified receipt differs from the submitted original".into(),
            ));
        }
        Ok(Self {
            request_digest: None,
            native_command: Some((holder.clone(), full_command)),
            locator_verified,
            constraints,
        })
    }
    pub fn matches(
        &self,
        request: &arkret_models_collaboration::consent_private::ConsentPrivateProxyRequest,
    ) -> bool {
        request
            .digest()
            .is_ok_and(|digest| Some(digest) == self.request_digest)
    }
    pub fn bind_proxy(
        mut self,
        request: &arkret_models_collaboration::consent_private::ConsentPrivateProxyRequest,
    ) -> PersistenceResult<Self> {
        if !self.matches_native(&request.holder_account_id, &request.command) {
            return Err(crate::PersistenceError::SchemaViolation(
                "verified Invite changed before proxy binding".into(),
            ));
        }
        self.request_digest = Some(
            request
                .digest()
                .map_err(|e| crate::PersistenceError::SchemaViolation(e.to_string()))?,
        );
        self.native_command = None;
        Ok(self)
    }
    pub fn matches_native(
        &self,
        holder: &AccountId,
        command: &arkret_models_collaboration::consent_private::ConsentPrivateCommand,
    ) -> bool {
        self.native_command
            .as_ref()
            .is_some_and(|(h, c)| h == holder && c == command)
    }
    pub fn locator_verified(&self) -> bool {
        self.locator_verified
    }
    pub fn constraints(&self) -> Option<&arkret_wire::ReceivePolicyConstraints> {
        self.constraints.as_ref()
    }
}

pub struct PrivateEffectsPublication {
    pub sequence: u64,
    pub request: arkret_models_collaboration::consent_private::ConsentPrivateEffectsPublishRequest,
}
pub struct PrivateEffectsProjection {
    pub outcome: arkret_models_collaboration::consent_private::ConsentPrivateEffectsPublishOutcome,
    pub updates: Vec<crate::AccountDataRecord>,
}
