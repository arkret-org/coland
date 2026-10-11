//! Adapter from the public authority protocol to this Station's durable store.
//!
//! Stream reads, guarded ordinary Realm bootstrap and the guarded Event unit
//! are live. A self Event whose Realm another Station governs is forwarded
//! with fresh producer device evidence, and a forwarded Event is admitted
//! here from that evidence (device-lifecycle §8.2.2). Other mutation branches
//! remain closed until the serving layer can prove the producer and current
//! authorization at the authority transaction cut.

use arkret_models_collaboration::authority_commit::{
    AggregateAcceptanceStatus, AuthorityHandoffRequest,
    DirectConversationFoundingAcceptanceOutcome, DirectConversationFoundingUnitSubmission,
    OrdinaryRealmBootstrapAcceptanceOutcome, OrdinaryRealmBootstrapUnitSubmission,
    PeerAuthorityForwardEventRequest, PeerAuthorityForwardMlsRequest,
};
use arkret_wire::{
    AuthorityBundleRequest, AuthoritySubmitOutcome, EventAdmissionSubmission, MlsCommitSubmission,
    RealmAuthorityBundle, RealmAuthorityHandoff, StreamScanRequest,
};
use chrono::Utc;
use coland_services::authority_commit::AuthorityProtocolPort;
use coland_services::identity::SessionIdentityState;
use coland_services::{ServiceError, ServiceResult};

use super::AppState;

/// The self Event admission unit a kind reaches on this Station.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SelfEventRoute {
    /// `ak.key_backup.active_series`: the same-cut pointer unit.
    KeyBackupPointer,
    /// `ak.identity.accountability_grant`: the issuer-PCR accountability unit.
    AccountabilityGrant,
    Consent,
    /// `ak.mls.genesis` and `ak.mls.commit`: the MLS public-transition unit.
    Mls,
    /// Kinds with a guarded current-result authority cut in their source scope.
    GuardedUnit,
}

/// Select the self Event unit for `kind` before any authority cut is read.
///
/// Every other active standard kind has no current-result authority cut here
/// and is refused with the universal `unsupported_event_kind`, never an
/// internal failure, so the refusal is a stable wire code and nothing is
/// written. A kind outside the registry cannot pass envelope validation; if
/// one did, it is a closed-schema violation, not an unsupported active kind.
fn self_event_route(kind: &arkret_wire::EventKind) -> ServiceResult<SelfEventRoute> {
    use arkret_wire::EventKind;
    match kind {
        EventKind::KeyBackupActiveSeries => Ok(SelfEventRoute::KeyBackupPointer),
        EventKind::IdentityAccountabilityGrant => Ok(SelfEventRoute::AccountabilityGrant),
        EventKind::ConsentGrant | EventKind::ConsentRevoke => Ok(SelfEventRoute::Consent),
        EventKind::MlsGenesis | EventKind::MlsCommit => Ok(SelfEventRoute::Mls),
        EventKind::CircleCreate
        | EventKind::AppletBridgeError
        | EventKind::SidecarCreate
        | EventKind::SidecarContextAttach
        | EventKind::AgentSidecarExchangeControl
        | EventKind::RealmOrganization
        | EventKind::CircleMemberState
        | EventKind::StrandCreate
        | EventKind::RealmProfile
        | EventKind::RealmTombstone
        | EventKind::RealmDestroy
        | EventKind::RealmArchive
        | EventKind::RealmRestore
        | EventKind::RealmFreeze
        | EventKind::RealmUnfreeze
        | EventKind::StrandUpdate
        | EventKind::StrandTracksUpdate
        | EventKind::RsvpSet
        | EventKind::StrandArchive
        | EventKind::StrandRestore
        | EventKind::StrandStageSet
        | EventKind::StrandMove
        | EventKind::StrandReorder
        | EventKind::StrandWatchSet
        | EventKind::AgentInteractionSet
        | EventKind::SpaceCreate
        | EventKind::SpaceUpdate
        | EventKind::SpaceParent
        | EventKind::SpaceTombstone
        | EventKind::SchemaDefine
        | EventKind::RealmPolicyBundle
        | EventKind::DirectConversationBound
        | EventKind::RealmSetDefaultStrand
        | EventKind::RealmReadReceiptPolicy
        | EventKind::RealmPreviewPolicy
        | EventKind::MemberIdentityUpdate
        | EventKind::CallCreate
        | EventKind::MessageCreate
        | EventKind::MemberState
        | EventKind::CapabilityGrant
        | EventKind::MessageRevise
        | EventKind::MessageRedact
        | EventKind::ModerationDecision
        | EventKind::ModerationDecisionLift
        | EventKind::InviteCreate
        | EventKind::InviteThirdParty
        | EventKind::InviteClaim
        | EventKind::InviteRevoke
        | EventKind::InviteCancel
        | EventKind::InviteAccept
        | EventKind::CapabilityRevoke
        | EventKind::CapabilityRelinquish
        | EventKind::RelationCreate
        | EventKind::RelationUpdate
        | EventKind::RelationTombstone
        | EventKind::SpaceArchive
        | EventKind::SpaceRestore
        | EventKind::ReactionAdd
        | EventKind::ReactionRemove
        | EventKind::PinAdd
        | EventKind::PinRemove
        | EventKind::PinReorder
        | EventKind::MimiRoomBinding => Ok(SelfEventRoute::GuardedUnit),
        EventKind::Unknown(raw) => Err(ServiceError::SchemaViolation(format!(
            "self Event kind {raw} is not registered"
        ))),
        other => Err(ServiceError::UnsupportedEventKind(format!(
            "this Station has no self Event authority cut for {}",
            other.as_str()
        ))),
    }
}

/// actor-private-effects.md §2.1: the self Event submit and the peer Event
/// ingress admit only shared durable Events. Every `actor_private_event` kind
/// is refused as `unsupported_event_kind` before any producer, forwarding or
/// storage step, so it never enters RealmCommit coverage.
pub(super) fn refuse_actor_private_event(kind: &arkret_wire::EventKind) -> ServiceResult<()> {
    if kind.wire_scope() == arkret_wire::EventWireScope::ActorPrivateEvent {
        return Err(ServiceError::UnsupportedEventKind(format!(
            "{} is an actor-private Event and is never a shared Realm Event",
            kind.as_str()
        )));
    }
    Ok(())
}

/// A shared Event of a kind this Station admits through no unit: the
/// Direct Conversation profile table still answers first for its Realm
/// (contact-and-direct-conversation.md section 8.4), otherwise the refusal
/// stays the universal `unsupported_event_kind`. `None` for a routed kind.
pub(super) async fn refuse_unrouted_event(
    state: &AppState,
    event: &arkret_wire::Event,
) -> ServiceResult<Option<AuthoritySubmitOutcome>> {
    match self_event_route(&event.kind) {
        Ok(_) => Ok(None),
        Err(unsupported @ ServiceError::UnsupportedEventKind(_)) => {
            super::authority_direct_conversation::refuse_unadmitted_event(state, event, unsupported)
                .await
                .map(Some)
        }
        Err(error) => Err(error),
    }
}

/// Preconditions shared by every Event admitted through the guarded unit,
/// whether its producer was resolved locally or from a forward.
pub(super) fn require_guarded_unit_event(request: &EventAdmissionSubmission) -> ServiceResult<()> {
    let event = &request.event;
    if self_event_route(&event.kind)? != SelfEventRoute::GuardedUnit {
        return Err(ServiceError::UnsupportedEventKind(format!(
            "{} is admitted only on its producer's own Station",
            event.kind.as_str()
        )));
    }
    if !matches!(event.scope_ref, arkret_wire::ScopeRef::Realm { .. })
        && !(matches!(event.scope_ref, arkret_wire::ScopeRef::Circle { .. })
            && matches!(
                event.kind,
                arkret_wire::EventKind::CircleMemberState
                    | arkret_wire::EventKind::StrandCreate
                    | arkret_wire::EventKind::AppletBridgeError
                    | arkret_wire::EventKind::MessageCreate
                    | arkret_wire::EventKind::ModerationDecision
                    | arkret_wire::EventKind::ModerationDecisionLift
                    | arkret_wire::EventKind::RelationCreate
                    | arkret_wire::EventKind::RelationUpdate
                    | arkret_wire::EventKind::RelationTombstone
                    | arkret_wire::EventKind::ReactionAdd
                    | arkret_wire::EventKind::ReactionRemove
                    | arkret_wire::EventKind::PinAdd
                    | arkret_wire::EventKind::PinRemove
                    | arkret_wire::EventKind::PinReorder
            ))
        && !(matches!(event.scope_ref, arkret_wire::ScopeRef::Sidecar { .. })
            && matches!(
                event.kind,
                arkret_wire::EventKind::SidecarContextAttach
                    | arkret_wire::EventKind::MessageCreate
                    | arkret_wire::EventKind::AgentSidecarExchangeControl
            ))
    {
        return Err(ServiceError::Conflict(
            "this Event kind has no source target cut in its signed scope".to_owned(),
        ));
    }
    Ok(())
}

/// The other Station that currently governs `realm_id`, if any. Only a
/// durable current-authority record names it; a Realm this Station knows
/// nothing about has no forwarding target.
async fn remote_governance(
    state: &AppState,
    realm_id: &arkret_wire::RealmId,
) -> ServiceResult<Option<arkret_wire::DidCoreId>> {
    Ok(state
        .authority_commits()
        .current_authority(realm_id)
        .await?
        .map(|authority| authority.service_id)
        .filter(|service_id| service_id != &state.service_core_id()))
}

#[async_trait::async_trait]
impl AuthorityProtocolPort for AppState {
    async fn submit_self_ordinary_realm_bootstrap(
        &self,
        session: &SessionIdentityState,
        request: OrdinaryRealmBootstrapUnitSubmission,
        exact_request_body: &[u8],
    ) -> ServiceResult<OrdinaryRealmBootstrapAcceptanceOutcome> {
        #[cfg(feature = "conformance-harness")]
        tracing::warn!(
            phase = "entered",
            event_count = request.events.len(),
            "ordinary bootstrap execution boundary"
        );
        request
            .validate()
            .map_err(|error| ServiceError::SchemaViolation(error.to_string()))?;
        let actor = crate::routing::identity::session_actor::validated_session_actor(self, session)
            .await
            .map_err(|error| {
                ServiceError::Conflict(format!("authenticated Account unavailable: {error}"))
            })?;
        if request
            .events
            .iter()
            .any(|item| item.event.actor_id != actor || item.event.executed_by.is_some())
        {
            return Err(ServiceError::protocol(
                arkret_wire::ErrorCode::CapabilityDenied,
                "ordinary bootstrap retry must bind the authenticated Account",
            ));
        }
        if let Some(commits) = self
            .authority_commits()
            .ordinary_realm_bootstrap_replay(&request, exact_request_body)
            .await?
        {
            return Ok(OrdinaryRealmBootstrapAcceptanceOutcome {
                unit_kind: request.unit_kind,
                status: AggregateAcceptanceStatus::Duplicate,
                commits,
            });
        }
        let genesis = &request.events[0].event;
        let existing = self
            .authority_commits()
            .current_authority(&genesis.realm_id)
            .await?;
        let (producer_guards, staged) =
            super::authority_bootstrap_validation::verify_ordinary_realm_bootstrap(
                self,
                session,
                &request,
                existing.is_none(),
            )
            .await?;
        #[cfg(feature = "conformance-harness")]
        tracing::warn!(
            phase = "producer_verified",
            "ordinary bootstrap execution boundary"
        );
        let expected_authority = coland_storage::CurrentRealmAuthority {
            realm_id: genesis.realm_id.clone(),
            generation: 0,
            service_id: self.service_core_id(),
            authority_ref: arkret_wire::RealmCommitAuthorityRef::GenesisOrChangeEvent(
                genesis.event_id.clone(),
            ),
            last_handoff_ref: None,
        };
        let method = arkret_wire::DidUrl::new(
            crate::routing::federation::federation_service_signature_key_id(
                self.service_did().as_str(),
            ),
        )
        .map_err(|error| ServiceError::Internal(error.to_string()))?;
        let committed_at = Utc::now();
        let mut unit = self
            .authority_commits()
            .prepare_ordinary_realm_bootstrap_unit(
                request.clone(),
                exact_request_body.to_vec(),
                &expected_authority,
                method,
                self.notary_signing_key().as_ref(),
                committed_at,
            )
            .await?;
        for (submitted, transaction) in request.events.iter().zip(&unit.transactions) {
            unit.event_approvals.push(
                crate::approval_admission::prepare_event_approvals(
                    self,
                    submitted,
                    transaction.commit.committed_at,
                )
                .await?,
            );
        }
        #[cfg(feature = "conformance-harness")]
        tracing::warn!(
            phase = "unit_prepared",
            "ordinary bootstrap execution boundary"
        );
        let result = self
            .authority_commits()
            .admit_self_ordinary_realm_bootstrap_unit(&unit, &producer_guards, committed_at)
            .await?;
        #[cfg(feature = "conformance-harness")]
        tracing::warn!(
            phase = "unit_admitted",
            "ordinary bootstrap execution boundary"
        );
        let (status, commits) = match result {
            coland_storage::OrdinaryRealmBootstrapCommitOutcome::Committed(commits) => {
                (AggregateAcceptanceStatus::Committed, commits)
            }
            coland_storage::OrdinaryRealmBootstrapCommitOutcome::Duplicate(commits) => {
                (AggregateAcceptanceStatus::Duplicate, commits)
            }
        };
        if status == AggregateAcceptanceStatus::Committed {
            let mut repair_needed = false;
            match staged {
                Some(staged) => {
                    if let Err(error) = self.projections().install_staged_realm_bootstrap(staged) {
                        tracing::error!(realm_id = %genesis.realm_id, reason = %error.reason,
                            "durably committed ordinary bootstrap needs local projection repair");
                        repair_needed = true;
                    }
                }
                None => {
                    tracing::error!(realm_id = %genesis.realm_id,
                        "durably committed ordinary bootstrap has no staged local projection");
                    repair_needed = true;
                }
            }
            // The directory is a separate, rebuildable view used by the
            // ordinary Realm reads and subsequent local Event admission.
            // Replay only this Realm's confirmed Events; unrelated Station
            // history must not delay the new Realm's accepted response.
            // Durable Commit/current rows remain the truth on read failure.
            match self
                .persistence()
                .hydrate_realm_directory_entry(&genesis.realm_id)
                .await
            {
                Ok(Some(entry)) => self.realm_directory().upsert(entry),
                Ok(None) => {
                    tracing::error!(realm_id = %genesis.realm_id,
                        "durably committed ordinary bootstrap is absent from directory hydration");
                    repair_needed = true;
                }
                Err(error) => {
                    tracing::error!(realm_id = %genesis.realm_id, %error,
                        "durably committed ordinary bootstrap directory hydration failed");
                    repair_needed = true;
                }
            }
            #[cfg(feature = "conformance-harness")]
            tracing::warn!(
                phase = "directory_reconciled",
                "ordinary bootstrap execution boundary"
            );
            if repair_needed {
                let repair_state = self.clone();
                tokio::spawn(async move {
                    let mut delay = std::time::Duration::from_secs(1);
                    loop {
                        match repair_state.hydrate().await {
                            Ok(()) => break,
                            Err(error) => {
                                tracing::error!(%error, "ordinary bootstrap projection repair failed")
                            }
                        }
                        tokio::time::sleep(delay).await;
                        delay = (delay * 2).min(std::time::Duration::from_secs(30));
                    }
                });
            }
        }
        let outcome = OrdinaryRealmBootstrapAcceptanceOutcome {
            unit_kind: request.unit_kind,
            status,
            commits,
        };
        outcome
            .validate()
            .map_err(|error| ServiceError::Internal(error.to_string()))?;
        Ok(outcome)
    }

    async fn submit_self_direct_conversation_founding(
        &self,
        session: &SessionIdentityState,
        request: DirectConversationFoundingUnitSubmission,
    ) -> ServiceResult<DirectConversationFoundingAcceptanceOutcome> {
        super::authority_direct_conversation::submit_self_direct_conversation_founding(
            self, session, request,
        )
        .await
    }

    async fn submit_self_event(
        &self,
        session: &SessionIdentityState,
        request: EventAdmissionSubmission,
    ) -> ServiceResult<AuthoritySubmitOutcome> {
        request
            .validate()
            .map_err(|error| ServiceError::SchemaViolation(error.to_string()))?;
        let event = &request.event;
        super::authority_self_event_unit::validate_replay_event_identity(event)?;
        refuse_actor_private_event(&event.kind)?;
        if matches!(
            event.kind,
            arkret_wire::EventKind::ConsentGrant | arkret_wire::EventKind::ConsentRevoke
        ) {
            let result = super::authority_consent::submit(self, session, &request).await?;
            let (status, record) = match result {
                coland_storage::ConsentAdmissionOutcome::Committed(record) => {
                    (arkret_wire::AuthorityCommitStatus::Committed, record)
                }
                coland_storage::ConsentAdmissionOutcome::Duplicate(record) => {
                    (arkret_wire::AuthorityCommitStatus::Duplicate, record)
                }
            };
            return Ok(AuthoritySubmitOutcome::Accepted {
                status,
                commit: record.commit,
            });
        }
        // The Agent PCR genesis is executed by the controller on the Agent's
        // behalf; its unit verifies that delegated producer itself.
        if super::authority_agent_pcr_genesis::is_agent_pcr_genesis(event) {
            return super::authority_agent_pcr_genesis::submit_self_agent_pcr_genesis(
                self, session, &request,
            )
            .await;
        }
        // A key revocation is likewise controller-executed for the Agent and
        // decided by the Agent control unit.
        if event.kind == arkret_wire::EventKind::AgentKeyRevoke {
            return super::authority_agent_control::submit_self_agent_key_revoke(
                self, session, &request,
            )
            .await;
        }
        // Native controller submissions keep authentication and shape checks,
        // but an exact accepted original must not refresh today's device or
        // Directory state. New submissions still run the producer gate below.
        if matches!(
            event.kind,
            arkret_wire::EventKind::AgentKeyAuthorize
                | arkret_wire::EventKind::SelfAgentPause
                | arkret_wire::EventKind::SelfAgentResume
                | arkret_wire::EventKind::SelfAgentDeactivate
        ) {
            arkret_schema::validate_event_for_submit(event)
                .map_err(|error| ServiceError::SchemaViolation(error.to_string()))?;
            if request.approval_signatures.is_some() {
                return Err(ServiceError::SchemaViolation(
                    "an Agent control Event carries no approval signatures".to_owned(),
                ));
            }
            let controller =
                crate::routing::identity::session_actor::validated_session_actor(self, session)
                    .await
                    .map_err(|error| {
                        ServiceError::Conflict(format!(
                            "authenticated Account unavailable: {error}"
                        ))
                    })?;
            if event.executed_by.as_ref() != Some(&controller) {
                return Err(ServiceError::Conflict(
                    "an Agent control Event is executed by the authenticated controller".to_owned(),
                ));
            }
            if let Some(original) =
                super::authority_self_event_unit::exact_replay(self, event).await?
            {
                return Ok(original);
            }
        }
        if let Some(original) = super::authority_forward::recover_forwarded_original(
            self,
            session,
            &arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequest::Event(
                request.clone(),
            ),
        )
        .await?
        {
            return Ok(original);
        }
        let (producer_guard, producer_key) =
            super::authority_producer_validation::verify_self_event_producer_key(
                self, session, event,
            )
            .await
            .inspect_err(|_error| {
                #[cfg(feature = "conformance-harness")]
                crate::routing::trace_submission_refusal(
                    "producer_preflight",
                    crate::routing::submission_kind_class(&event.kind),
                    if session.agent_session().is_some() {
                        "agent"
                    } else {
                        "human"
                    },
                    Some(_error),
                );
            })?;
        if let Some(governance) = remote_governance(self, &event.realm_id).await? {
            let outcome = super::authority_forward::forward_self_event_with_session(
                self,
                &governance,
                request,
                session,
            )
            .await;
            #[cfg(feature = "conformance-harness")]
            if let Err(error) = &outcome {
                crate::routing::trace_submission_refusal(
                    "remote_forward",
                    "ordinary_event",
                    if session.agent_session().is_some() {
                        "agent"
                    } else {
                        "human"
                    },
                    Some(error),
                );
            }
            return outcome;
        }
        if let Some(outcome) = refuse_unrouted_event(self, event).await? {
            return Ok(outcome);
        }
        match self_event_route(&event.kind)? {
            SelfEventRoute::Mls => {
                if request.approval_signatures.is_some() {
                    return Err(ServiceError::SchemaViolation(
                        "an MLS Event carries no approval signatures".to_owned(),
                    ));
                }
                return super::authority_mls_unit::admit_mls_event(
                    self,
                    event,
                    &[],
                    None,
                    super::authority_self_event_unit::AdmittedProducer::Local(Box::new(
                        producer_guard,
                    )),
                    &producer_key,
                )
                .await;
            }
            SelfEventRoute::KeyBackupPointer => {
                return super::authority_key_backup_pointer::submit_self_key_backup_pointer(
                    self, &request,
                )
                .await
                .inspect_err(|_error| {
                    #[cfg(feature = "conformance-harness")]
                    crate::routing::trace_submission_refusal(
                        "key_backup_pointer_unit",
                        "key_backup_pointer",
                        if session.agent_session().is_some() {
                            "agent"
                        } else {
                            "human"
                        },
                        Some(_error),
                    );
                });
            }
            SelfEventRoute::AccountabilityGrant => {
                return super::authority_accountability_grant::submit_self_accountability_grant(
                    self, &request,
                )
                .await;
            }
            SelfEventRoute::GuardedUnit => {}
            SelfEventRoute::Consent => {
                unreachable!("Consent is admitted before ordinary forwarding")
            }
        }
        require_guarded_unit_event(&request)?;
        super::authority_self_event_unit::commit_event_unit(
            self,
            &request,
            super::authority_self_event_unit::AdmittedProducer::Local(Box::new(producer_guard)),
            super::authority_self_event_unit::SelfEventUnitEffects::default(),
        )
        .await
        .inspect_err(|_error| {
            #[cfg(feature = "conformance-harness")]
            crate::routing::trace_submission_refusal(
                "guarded_event_unit",
                crate::routing::submission_kind_class(&event.kind),
                if session.agent_session().is_some() {
                    "agent"
                } else {
                    "human"
                },
                Some(_error),
            );
        })
    }

    async fn submit_self_mls(
        &self,
        session: &SessionIdentityState,
        request: MlsCommitSubmission,
    ) -> ServiceResult<AuthoritySubmitOutcome> {
        request
            .validate()
            .map_err(|error| ServiceError::SchemaViolation(error.to_string()))?;
        let event = &request.commit_event;
        super::authority_self_event_unit::validate_replay_event_identity(event)?;
        if self
            .authority_commits()
            .queued_event(&event.event_id)
            .await?
            .is_some()
        {
            super::authority_forward::validate_recovery_caller(self, session, event).await?;
            if let Some(original) =
                super::authority_self_event_unit::exact_replay(self, event).await?
            {
                return Ok(original);
            }
        }
        if let Some(original) = super::authority_forward::recover_forwarded_original(
            self,
            session,
            &arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequest::MlsCommit(
                request.clone(),
            ),
        )
        .await?
        {
            return Ok(original);
        }
        let (producer_guard, producer_key) =
            super::authority_producer_validation::verify_self_event_producer_key(
                self, session, event,
            )
            .await?;
        if let Some(governance) = remote_governance(self, &event.realm_id).await? {
            return super::authority_forward::forward_self_mls(self, &governance, request, session)
                .await;
        }
        super::authority_mls_unit::admit_mls_event(
            self,
            event,
            &request.welcomes,
            None,
            super::authority_self_event_unit::AdmittedProducer::Local(Box::new(producer_guard)),
            &producer_key,
        )
        .await
    }

    async fn submit_peer_authority_forward_event(
        &self,
        peer: &coland_services::authority_commit::AuthenticatedPeerContext,
        request: PeerAuthorityForwardEventRequest,
    ) -> ServiceResult<AuthoritySubmitOutcome> {
        super::authority_forward::admit_forwarded_event(self, peer, request, crate::wire::now())
            .await
    }

    async fn submit_peer_authority_forward_mls(
        &self,
        peer: &coland_services::authority_commit::AuthenticatedPeerContext,
        request: PeerAuthorityForwardMlsRequest,
    ) -> ServiceResult<AuthoritySubmitOutcome> {
        super::authority_forward::admit_forwarded_mls(self, peer, request, crate::wire::now()).await
    }

    async fn submit_peer_committed_replication(
        &self,
        peer: &coland_services::authority_commit::AuthenticatedPeerContext,
        request: arkret_models_collaboration::authority_commit::PeerCommittedReplicationRequest,
    ) -> ServiceResult<arkret_models_collaboration::authority_commit::PeerCommittedReplicationOutcome>
    {
        super::committed_replication::receive(self, peer, request).await
    }

    async fn submit_peer_direct_conversation_founding(
        &self,
        peer: &coland_services::authority_commit::AuthenticatedPeerContext,
        request: arkret_models_collaboration::authority_commit::DirectConversationFoundingFederationSubmission,
    ) -> ServiceResult<DirectConversationFoundingAcceptanceOutcome> {
        super::authority_direct_conversation::submit_peer_direct_conversation_founding(
            self, peer, request,
        )
        .await
    }

    async fn scan_stream_for_account(
        &self,
        account: &arkret_wire::AccountId,
        request: StreamScanRequest,
    ) -> ServiceResult<coland_storage::AccountStreamScan> {
        self.authority_commits()
            .scan_stream_for_account(&request, account, &self.service_core_id())
            .await
    }

    async fn scan_stream_for_peer(
        &self,
        peer: &coland_services::authority_commit::AuthenticatedPeerContext,
        request: StreamScanRequest,
    ) -> ServiceResult<coland_storage::PeerStreamScan> {
        self.authority_commits()
            .scan_stream_for_peer(&request, &peer.source_service_id, &self.service_core_id())
            .await
    }

    /// The nonce-bound genesis-to-current chain, signed by this Station's
    /// notary method and carrying its current authenticated service route.
    async fn authority_bundle(
        &self,
        request: AuthorityBundleRequest,
    ) -> ServiceResult<RealmAuthorityBundle> {
        let route =
            crate::routing::system::service_resolution::current_authenticated_service_resolution(
                self,
            )
            .await
            .map_err(|error| {
                ServiceError::Internal(format!(
                    "current authenticated service route is unavailable: {}",
                    error.message
                ))
            })?;
        let route = serde_json::to_value(route)
            .map_err(|error| ServiceError::Internal(error.to_string()))?;
        let verification_method = self
            .service_verification_method("notary-key")
            .map_err(|error| ServiceError::Internal(error.to_string()))?;
        self.authority_commits()
            .authority_bundle(
                &request,
                &self.service_core_id(),
                route,
                verification_method,
                self.notary_signing_key().as_ref(),
                crate::wire::now(),
            )
            .await
    }

    async fn install_authority_handoff(
        &self,
        _request: AuthorityHandoffRequest,
    ) -> ServiceResult<RealmAuthorityHandoff> {
        Err(ServiceError::Internal(
            "peer handoff authentication and fencing are unavailable".to_owned(),
        ))
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn authority_objects_keep_the_http_canonical_and_signature_contract() {
        let (commit, handoff) = arkret_test_kit::authority_objects::objects();
        let commit: arkret_wire::RealmCommit =
            serde_json::from_slice(&serde_json::to_vec(&commit).unwrap()).unwrap();
        let handoff: arkret_wire::RealmAuthorityHandoff =
            serde_json::from_slice(&serde_json::to_vec(&handoff).unwrap()).unwrap();
        arkret_test_kit::authority_objects::assert_canonical_objects(&commit, &handoff);
    }
    use arkret_wire::EventKind;
    use coland_services::ServiceError;

    use super::{
        SelfEventRoute, refuse_actor_private_event, require_guarded_unit_event, self_event_route,
    };

    #[test]
    fn only_kinds_with_a_self_authority_cut_are_routed() {
        assert_eq!(
            self_event_route(&EventKind::KeyBackupActiveSeries).unwrap(),
            SelfEventRoute::KeyBackupPointer
        );
        assert_eq!(
            self_event_route(&EventKind::IdentityAccountabilityGrant).unwrap(),
            SelfEventRoute::AccountabilityGrant
        );
        for kind in [EventKind::MlsGenesis, EventKind::MlsCommit] {
            assert_eq!(self_event_route(&kind).unwrap(), SelfEventRoute::Mls);
        }
        for kind in [
            EventKind::AppletBridgeError,
            EventKind::PinAdd,
            EventKind::PinRemove,
            EventKind::PinReorder,
            EventKind::MimiRoomBinding,
            EventKind::SidecarCreate,
            EventKind::SidecarContextAttach,
            EventKind::AgentSidecarExchangeControl,
            EventKind::SpaceUpdate,
            EventKind::SchemaDefine,
            EventKind::RealmPolicyBundle,
            EventKind::DirectConversationBound,
            EventKind::InviteClaim,
            EventKind::CircleCreate,
            EventKind::CircleMemberState,
            EventKind::MemberIdentityUpdate,
            EventKind::RealmOrganization,
            EventKind::StrandCreate,
            EventKind::RealmProfile,
            EventKind::RealmReadReceiptPolicy,
            EventKind::RealmPreviewPolicy,
            EventKind::RealmTombstone,
            EventKind::RealmDestroy,
            EventKind::RealmArchive,
            EventKind::RealmRestore,
            EventKind::RealmFreeze,
            EventKind::RealmUnfreeze,
            EventKind::StrandUpdate,
            EventKind::StrandTracksUpdate,
            EventKind::RsvpSet,
            EventKind::StrandArchive,
            EventKind::StrandRestore,
            EventKind::StrandStageSet,
            EventKind::StrandMove,
            EventKind::StrandReorder,
            EventKind::StrandWatchSet,
            EventKind::AgentInteractionSet,
            EventKind::SpaceCreate,
            EventKind::SpaceParent,
            EventKind::SpaceTombstone,
            EventKind::RealmSetDefaultStrand,
            EventKind::CallCreate,
            EventKind::MessageCreate,
            EventKind::MemberState,
            EventKind::CapabilityGrant,
            EventKind::MessageRevise,
            EventKind::MessageRedact,
            EventKind::ModerationDecision,
            EventKind::ModerationDecisionLift,
            EventKind::InviteCreate,
            EventKind::InviteThirdParty,
            EventKind::InviteRevoke,
            EventKind::InviteCancel,
            EventKind::InviteAccept,
            EventKind::CapabilityRevoke,
            EventKind::CapabilityRelinquish,
            EventKind::RelationCreate,
            EventKind::RelationUpdate,
            EventKind::RelationTombstone,
            EventKind::SpaceArchive,
            EventKind::SpaceRestore,
            EventKind::ReactionAdd,
            EventKind::ReactionRemove,
        ] {
            assert_eq!(
                self_event_route(&kind).unwrap(),
                SelfEventRoute::GuardedUnit
            );
        }
    }

    #[test]
    fn every_other_active_kind_is_unsupported_event_kind_not_internal() {
        let routed = [
            EventKind::AppletBridgeError,
            EventKind::ConsentGrant,
            EventKind::ConsentRevoke,
            EventKind::KeyBackupActiveSeries,
            EventKind::IdentityAccountabilityGrant,
            EventKind::MlsGenesis,
            EventKind::MlsCommit,
            EventKind::CircleCreate,
            EventKind::CircleMemberState,
            EventKind::MemberIdentityUpdate,
            EventKind::RealmOrganization,
            EventKind::StrandCreate,
            EventKind::RealmProfile,
            EventKind::RealmReadReceiptPolicy,
            EventKind::RealmPreviewPolicy,
            EventKind::RealmTombstone,
            EventKind::RealmDestroy,
            EventKind::RealmArchive,
            EventKind::RealmRestore,
            EventKind::RealmFreeze,
            EventKind::RealmUnfreeze,
            EventKind::StrandUpdate,
            EventKind::StrandTracksUpdate,
            EventKind::RsvpSet,
            EventKind::StrandArchive,
            EventKind::StrandRestore,
            EventKind::StrandStageSet,
            EventKind::StrandMove,
            EventKind::StrandReorder,
            EventKind::StrandWatchSet,
            EventKind::AgentInteractionSet,
            EventKind::SpaceCreate,
            EventKind::SpaceParent,
            EventKind::SpaceTombstone,
            EventKind::DirectConversationBound,
            EventKind::RealmSetDefaultStrand,
            EventKind::CallCreate,
            EventKind::MessageCreate,
            EventKind::MemberState,
            EventKind::CapabilityGrant,
            EventKind::MessageRevise,
            EventKind::MessageRedact,
            EventKind::ModerationDecision,
            EventKind::ModerationDecisionLift,
            EventKind::InviteCreate,
            EventKind::InviteThirdParty,
            EventKind::InviteRevoke,
            EventKind::InviteCancel,
            EventKind::InviteAccept,
            EventKind::CapabilityRevoke,
            EventKind::CapabilityRelinquish,
            EventKind::RelationCreate,
            EventKind::RelationUpdate,
            EventKind::RelationTombstone,
            EventKind::SpaceArchive,
            EventKind::SpaceRestore,
            EventKind::ReactionAdd,
            EventKind::ReactionRemove,
            EventKind::InviteClaim,
            EventKind::MimiRoomBinding,
            EventKind::PinAdd,
            EventKind::PinRemove,
            EventKind::PinReorder,
            EventKind::RealmPolicyBundle,
            EventKind::SchemaDefine,
            EventKind::SidecarContextAttach,
            EventKind::AgentSidecarExchangeControl,
            EventKind::SidecarCreate,
            EventKind::SpaceUpdate,
        ];
        let unique_routed: std::collections::BTreeSet<_> =
            routed.iter().map(EventKind::as_str).collect();
        assert_eq!(
            unique_routed.len(),
            routed.len(),
            "routed kinds must be unique"
        );
        let mut refused = 0;
        for kind in EventKind::ALL.iter().filter(|kind| !routed.contains(kind)) {
            match self_event_route(kind) {
                Err(ServiceError::UnsupportedEventKind(detail)) => {
                    assert!(detail.contains(kind.as_str()), "{detail}");
                }
                other => panic!(
                    "{} must be unsupported_event_kind, got {other:?}",
                    kind.as_str()
                ),
            }
            refused += 1;
        }
        assert_eq!(refused, EventKind::ALL.len() - routed.len());
    }

    #[test]
    fn every_actor_private_kind_is_refused_by_the_shared_ingress() {
        let mut refused = Vec::new();
        for kind in EventKind::ALL {
            if refuse_actor_private_event(kind).is_err() {
                refused.push(kind.as_str());
            }
        }
        refused.sort_unstable();
        assert_eq!(
            refused,
            [
                "ak.account_data.set",
                "ak.agent.action_reject",
                "ak.agent.action_request",
                "ak.agent.draft.propose",
                "ak.device.push_route",
                "ak.read_cursor.advance",
            ]
        );
        assert!(matches!(
            refuse_actor_private_event(&EventKind::DevicePushRoute),
            Err(ServiceError::UnsupportedEventKind(_))
        ));
        assert!(refuse_actor_private_event(&EventKind::MessageCreate).is_ok());
    }

    #[test]
    fn native_sidecar_units_do_not_authorize_other_scope_operations() {
        let event_id =
            arkret_wire::EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [119; 32]);
        let realm_id = arkret_wire::RealmId::from_event_id(&event_id);
        let scope = arkret_wire::ScopeRef::Sidecar {
            realm_id: realm_id.clone(),
            sidecar_id: arkret_wire::SidecarId::from_event_id(&event_id),
        };
        let mut event = arkret_wire::Event {
            event_id,
            kind: EventKind::MessageCreate,
            realm_id,
            scope_ref: scope,
            actor_id: arkret_wire::ActorId::account(arkret_wire::AccountId::new(
                arkret_wire::DidCoreId::new("ak:did_core:web:controller.example").unwrap(),
                arkret_wire::DidCoreId::new("ak:did_core:web:station.example").unwrap(),
            )),
            executed_by: None,
            authorization_ref: None,
            applet_id: None,
            external_ref: None,
            created_at: chrono::Utc::now(),
            semantic_refs: Vec::new(),
            payload: Default::default(),
            producer_proof: None,
        };
        for kind in [
            EventKind::MessageCreate,
            EventKind::SidecarContextAttach,
            EventKind::AgentSidecarExchangeControl,
        ] {
            event.kind = kind;
            assert!(
                require_guarded_unit_event(&arkret_wire::EventAdmissionSubmission::new(
                    event.clone()
                ))
                .is_ok()
            );
        }
        for kind in [
            EventKind::StrandCreate,
            EventKind::CircleMemberState,
            EventKind::RealmProfile,
            EventKind::MessageRevise,
        ] {
            event.kind = kind;
            assert!(
                require_guarded_unit_event(&arkret_wire::EventAdmissionSubmission::new(
                    event.clone()
                ))
                .is_err()
            );
        }
    }

    #[test]
    fn an_unregistered_kind_is_a_schema_violation() {
        assert!(matches!(
            self_event_route(&EventKind::Unknown("ak.example.unregistered".to_owned())),
            Err(ServiceError::SchemaViolation(_))
        ));
    }
}
