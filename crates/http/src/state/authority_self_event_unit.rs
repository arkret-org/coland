//! The guarded producer-signed Event unit of work.
//!
//! One producer-signed Event is admitted by the current governing Station in
//! a single PostgreSQL transaction: the queued Event, its Station-signed
//! `RealmCommit` at the exact per-stream head, the kind's registered typed
//! current result, the source outbox (empty for the supported local-only
//! Realm kinds), the projection event and any kind-specific effect such as the
//! consumed franking replay nonce. A same-Station producer guard is rechecked
//! against the local PCR, and a cross-Station producer's verified
//! `producer_device_evidence` is retained, inside that transaction together
//! with the stream head, so a failure leaves zero writes.
//!
//! Only kinds with a registered same-cut current writer enter this unit. The
//! generic `/_arkret/self/events` route, `authority_forward` on
//! `/_arkret/peer/events` and dedicated operations such as
//! `ak.self.moderation.command.report.v1` share it; every other kind stays
//! closed at its caller.

use arkret_wire::{
    AuthorityCommitStatus, AuthoritySubmitResponseBody, Event, EventAdmissionSubmission,
};
use chrono::Utc;
use coland_services::identity::SessionIdentityState;
use coland_services::{ServiceError, ServiceResult};
use coland_storage::SelfProducerCommitGuard;

use super::AppState;

/// Refresh the already registered remote claim's durable consume receipt
/// before evaluating a Direct Conversation completion cut. The peer read and
/// signature checks happen before the accepting database transaction.
pub(crate) async fn refresh_direct_conversation_peer_claim(
    state: &AppState,
    realm_id: &arkret_wire::RealmId,
) -> ServiceResult<()> {
    let Some(pending) = state
        .authority_commits()
        .direct_conversation_pending_peer_claim_query(realm_id)
        .await?
    else {
        return Ok(());
    };
    let query = serde_json::json!({
        "claim_request_id": pending.claim_request_id,
        "request_digest": pending.request_digest,
    });
    let body = arkret_canonical::canonical_json_bytes(&query)
        .map_err(|error| ServiceError::internal(error.to_string()))?;
    let response = crate::routing::federation::outbox::signed_peer_request(
        state,
        &pending.peer_id,
        "/_arkret/peer/keys/keypackages/claims/query",
        &body,
        64 * 1024,
    )
    .await
    .map_err(|_| {
        ServiceError::Conflict("temporarily_unavailable: peer claim read unavailable".into())
    })?;
    if response.status != 200 {
        return Err(ServiceError::Conflict(
            "temporarily_unavailable: peer claim read was refused".into(),
        ));
    }
    let outcome: arkret_models_crypto::PeerKeyPackagesClaimQueryResponseBody =
        serde_json::from_slice(&response.body)
            .map_err(|_| ServiceError::internal("peer claim query response is invalid"))?;
    outcome
        .validate_shape()
        .map_err(|_| ServiceError::internal("peer claim query shape is invalid"))?;
    crate::routing::mls::capture_relayed_keypackage_claim_query(
        state,
        &pending.peer_id,
        &pending.original_request_body,
        &outcome,
    )
    .await
    .map_err(|_| {
        ServiceError::Conflict("temporarily_unavailable: peer claim receipt unavailable".into())
    })?;
    Ok(())
}

/// How the Event's real Account Device, Service or Agent producer was resolved
/// (device-lifecycle §8.2.2): locally at this Station's PCR, or from the
/// evidence an `authority_forward` carried from the producer's Station.
pub(super) enum AdmittedProducer {
    /// Same-Station producer; the guard is rechecked in the unit.
    Local(Box<SelfProducerCommitGuard>),
    Applet(coland_storage::AppletEventProducerGuard),
    /// Cross-Station human device; the verified evidence is retained with
    /// the Event's first Commit.
    Forwarded(Box<coland_storage::ForwardedProducerDeviceEvidence>),
    ForwardedAgent(Box<arkret_identity::agent_authority_evidence::VerifiedAgentProducer>),
}

impl AdmittedProducer {
    pub(super) fn is_managed_device(&self) -> bool {
        match self {
            Self::Local(guard) => matches!(
                guard.as_ref(),
                SelfProducerCommitGuard::AppletManagedDevice(_)
            ),
            _ => false,
        }
    }
}

/// Kind-specific durable effects committed atomically with the Event.
#[derive(Default)]
pub(super) struct SelfEventUnitEffects {
    /// The report's embedded franking proof nonce; its `consumed_at` is set to
    /// the accepting Commit time inside the unit.
    pub(super) franking_replay_nonce: Option<coland_storage::FrankingReplayNonceCommit>,
    /// The verified public MLS transition and Welcomes of an `ak.mls.genesis`
    /// or `ak.mls.commit` (`authority_mls_unit`).
    pub(super) mls: Option<super::authority_mls_unit::MlsUnitInstallation>,
}

/// Kinds whose authorization and domain pre-state are decided only at the
/// accepting transaction's cut, by the same-cut evaluator and their typed
/// current writers. The in-process projection is not consulted for admission.
fn decided_at_commit_cut(kind: &arkret_wire::EventKind) -> bool {
    matches!(
        kind,
        arkret_wire::EventKind::RealmActorStatusSet
            | arkret_wire::EventKind::RealmActorRecoverySet
            | arkret_wire::EventKind::CircleCreate
            | arkret_wire::EventKind::ProfileCreate
            | arkret_wire::EventKind::ProfileUpdate
            | arkret_wire::EventKind::SidecarCreate
            | arkret_wire::EventKind::SidecarContextAttach
            | arkret_wire::EventKind::AgentSidecarExchangeControl
            | arkret_wire::EventKind::CircleMemberState
            | arkret_wire::EventKind::RealmOrganization
            | arkret_wire::EventKind::RealmLink
            | arkret_wire::EventKind::RealmSetDefaultStrand
            | arkret_wire::EventKind::RealmJoinRule
            | arkret_wire::EventKind::RealmHistoryAccess
            | arkret_wire::EventKind::SelfModerationReport
            | arkret_wire::EventKind::ModerationDecision
            | arkret_wire::EventKind::ModerationDecisionLift
            | arkret_wire::EventKind::SpaceCreate
            | arkret_wire::EventKind::SpaceUpdate
            | arkret_wire::EventKind::SpaceParent
            | arkret_wire::EventKind::SpaceTombstone
            | arkret_wire::EventKind::SchemaDefine
            | arkret_wire::EventKind::RealmPolicyBundle
            | arkret_wire::EventKind::PolicySet
            | arkret_wire::EventKind::PolicyAction
            | arkret_wire::EventKind::AgentActionApprove
            | arkret_wire::EventKind::StrandCreate
            | arkret_wire::EventKind::RealmProfile
            | arkret_wire::EventKind::ScopeReadReceiptPolicy
            | arkret_wire::EventKind::RealmPlaintextVisibleServices
            | arkret_wire::EventKind::RealmPreviewPolicy
            | arkret_wire::EventKind::RealmAssetPrivacyPolicy
            | arkret_wire::EventKind::RealmTombstone
            | arkret_wire::EventKind::RealmDestroy
            | arkret_wire::EventKind::RealmArchive
            | arkret_wire::EventKind::RealmRestore
            | arkret_wire::EventKind::RealmFreeze
            | arkret_wire::EventKind::RealmUnfreeze
            | arkret_wire::EventKind::StrandUpdate
            | arkret_wire::EventKind::StrandTracksUpdate
            | arkret_wire::EventKind::RsvpSet
            | arkret_wire::EventKind::StrandArchive
            | arkret_wire::EventKind::StrandRestore
            | arkret_wire::EventKind::StrandStageSet
            | arkret_wire::EventKind::StrandMove
            | arkret_wire::EventKind::StrandReorder
            | arkret_wire::EventKind::StrandWatchSet
            | arkret_wire::EventKind::AgentInteractionSet
            | arkret_wire::EventKind::RealmInviteLinkCreate
            | arkret_wire::EventKind::RealmInviteLinkRevoke
            | arkret_wire::EventKind::RealmInviteLinkAccept
            | arkret_wire::EventKind::InviteCreate
            | arkret_wire::EventKind::InviteRevoke
            | arkret_wire::EventKind::InviteCancel
            | arkret_wire::EventKind::InviteAccept
            | arkret_wire::EventKind::MemberState
            | arkret_wire::EventKind::CapabilityGrant
            | arkret_wire::EventKind::CapabilityRevoke
            | arkret_wire::EventKind::CapabilityRelinquish
            | arkret_wire::EventKind::MessageRevise
            | arkret_wire::EventKind::MemberIdentityUpdate
            | arkret_wire::EventKind::CallCreate
            | arkret_wire::EventKind::CallState
            | arkret_wire::EventKind::RealmMediaService
            | arkret_wire::EventKind::MessageCreate
            | arkret_wire::EventKind::MessageRedact
            | arkret_wire::EventKind::MlsGenesis
            | arkret_wire::EventKind::MlsCommit
            | arkret_wire::EventKind::RelationCreate
            | arkret_wire::EventKind::RelationUpdate
            | arkret_wire::EventKind::RelationTombstone
            | arkret_wire::EventKind::SpaceArchive
            | arkret_wire::EventKind::SpaceRestore
            | arkret_wire::EventKind::ReactionAdd
            | arkret_wire::EventKind::PinAdd
            | arkret_wire::EventKind::PinRemove
            | arkret_wire::EventKind::PinReorder
            | arkret_wire::EventKind::ReactionRemove
            | arkret_wire::EventKind::MimiRoomBinding
            | arkret_wire::EventKind::AppletBridgeError
    )
}

/// Content identity and the immutable Genesis timestamp contract are checked
/// before any Event-ID lookup, without refreshing the historical producer's
/// current authority or device state.
pub(super) fn validate_replay_event_identity(event: &Event) -> ServiceResult<()> {
    let derived = event
        .derive_event_id_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
        .map_err(|error| ServiceError::SchemaViolation(error.to_string()))?;
    if derived != event.event_id {
        return Err(ServiceError::Conflict(
            coland_storage::ConflictCode::EventIdDigestMismatch.to_string(),
        ));
    }
    if event.kind == arkret_wire::EventKind::MlsGenesis {
        let payload: arkret_models_collaboration::events_payloads::MlsGenesisPayload =
            serde_json::from_value(
                serde_json::to_value(&event.payload)
                    .map_err(|error| ServiceError::SchemaViolation(error.to_string()))?,
            )
            .map_err(|error| ServiceError::SchemaViolation(error.to_string()))?;
        payload
            .validate()
            .map_err(|error| ServiceError::SchemaViolation(error.to_string()))?;
        if event.created_at != payload.created_at {
            return Err(ServiceError::protocol(
                arkret_wire::ErrorCode::FailedPrecondition,
                "Genesis Event and payload must preserve one creation timestamp",
            ));
        }
    }
    Ok(())
}

/// An immutable inception restriction is not waived by an accepted receipt.
/// Keep this gate separate from today's producer, ACL and lifecycle checks.
pub(super) async fn require_governance_change_eligibility(
    state: &AppState,
    event: &Event,
) -> ServiceResult<()> {
    if event.kind == arkret_wire::EventKind::RealmGovernanceStationChange
        && let coland_storage::DirectConversationAdmissionCut::Refused(code) = state
            .authority_commits()
            .direct_conversation_admission(event)
            .await?
    {
        return Err(ServiceError::Conflict(format!(
            "{}: governance change is refused by immutable Realm inception",
            code.as_str()
        )));
    }
    Ok(())
}

/// The original outcome of an exact duplicate Event, before any producer,
/// evidence freshness or admission check runs again.
pub(super) async fn exact_replay(
    state: &AppState,
    event: &Event,
) -> ServiceResult<Option<AuthoritySubmitResponseBody>> {
    validate_replay_event_identity(event)?;
    let Some(existing) = state
        .authority_commits()
        .queued_event(&event.event_id)
        .await?
    else {
        return Ok(None);
    };
    if existing.event != *event {
        return Err(ServiceError::Conflict(
            "duplicate_conflict: event_id is already committed with different canonical content"
                .to_owned(),
        ));
    }
    if let Some(commit) = existing.committed {
        require_governance_change_eligibility(state, event).await?;
        return Ok(Some(AuthoritySubmitResponseBody::Accepted {
            status: AuthorityCommitStatus::Duplicate,
            commit,
        }));
    }
    if event.kind == arkret_wire::EventKind::MlsCommit
        && existing.status == coland_storage::QueuedEventStatus::Rejected
    {
        return Ok(Some(AuthoritySubmitResponseBody::Rejected {
            status: arkret_wire::AuthorityRejectionStatus::Rejected,
            reason_code: existing.rejection_reason.ok_or_else(|| {
                ServiceError::Internal("durable MLS refusal has no reason".into())
            })?,
        }));
    }
    Ok(None)
}

/// Admit one producer-verified Event through the guarded unit.
///
/// `submission` is the exact admission submission; a committed Event is
/// replicated to every remote Station hosting a joined member from it, with
/// the fanout planned in the same transaction.
pub(super) fn commit_event_unit<'a>(
    state: &'a AppState,
    submission: &'a EventAdmissionSubmission,
    producer: AdmittedProducer,
    effects: SelfEventUnitEffects,
) -> impl std::future::Future<Output = ServiceResult<AuthoritySubmitResponseBody>> + Send + 'a {
    commit_event_unit_with_idempotency(state, submission, producer, effects, None)
}

pub(super) fn commit_event_unit_with_idempotency<'a>(
    state: &'a AppState,
    submission: &'a EventAdmissionSubmission,
    producer: AdmittedProducer,
    effects: SelfEventUnitEffects,
    idempotency: Option<coland_services::events::IdempotentResponse>,
) -> impl std::future::Future<Output = ServiceResult<AuthoritySubmitResponseBody>> + Send + 'a {
    Box::pin(async move {
        let result = commit_event_unit_with_idempotency_impl(
            state,
            submission,
            producer,
            effects,
            idempotency,
        )
        .await;
        if let Err(error) = &result
            && error.conflict_code() == Some(coland_storage::ConflictCode::TemporarilyUnavailable)
        {
            tracing::warn!(event_id = %submission.event.event_id, %error,
            "accepting cut temporarily unavailable for exact Event");
        }
        result
    })
}

fn commit_event_unit_with_idempotency_impl<'a>(
    state: &'a AppState,
    submission: &'a EventAdmissionSubmission,
    producer: AdmittedProducer,
    effects: SelfEventUnitEffects,
    idempotency: Option<coland_services::events::IdempotentResponse>,
) -> impl std::future::Future<Output = ServiceResult<AuthoritySubmitResponseBody>> + Send + 'a {
    // Construct the large accepting state machine outside its caller's poll frame.
    Box::pin(async move {
        let event = &submission.event;
        let private_governance =
            matches!(event.scope_ref, arkret_wire::ScopeRef::RealmControl { .. });
        if private_governance
            && (!matches!(
                event.kind,
                arkret_wire::EventKind::RealmActorStatusSet
                    | arkret_wire::EventKind::RealmActorRecoverySet
            ) || event.actor_id.as_account_id().is_none()
                || event.executed_by.is_some())
        {
            return Err(ServiceError::SchemaViolation(
                "private governance requires a direct Account Device".into(),
            ));
        }

        if let Some(outcome) = Box::pin(exact_replay(state, event)).await? {
            return Ok(outcome);
        }
        let envelope = serde_json::to_value(event)
            .map_err(|error| ServiceError::SchemaViolation(error.to_string()))?;
        let operation_id = crate::routing::events::event_log::event_operation_id(
            &envelope,
            event.event_id.as_str(),
        )
        .ok_or_else(|| {
            ServiceError::SchemaViolation("self Event projection id is invalid".to_owned())
        })?;
        let mut operation = arkret_event_draft::ProjectedEventOperation::from_accepted_event(
            operation_id,
            arkret_wire::OperationKind::Create,
            None,
            event,
            arkret_canonical::DigestSuite::Sha256,
        )
        .map_err(|error| ServiceError::SchemaViolation(error.to_string()))?;
        // A governance change never consumes MLS claims. In particular, a
        // Direct Conversation must reach its immutable-Genesis refusal before
        // any peer read or durable consume-receipt refresh.
        if event.kind != arkret_wire::EventKind::RealmGovernanceStationChange {
            Box::pin(refresh_direct_conversation_peer_claim(
                state,
                &event.realm_id,
            ))
            .await?;
        }
        // contact-and-direct-conversation.md section 8.4: a Direct Conversation
        // Realm's profile table precedes every other authority, so its Events
        // skip the reducer preflight; the accepting transaction evaluates the
        // table again at its own cut.
        let direct_conversation = match state
            .authority_commits()
            .direct_conversation_admission(event)
            .await?
        {
            coland_storage::DirectConversationAdmissionCut::Refused(code) => {
                return super::authority_direct_conversation::direct_conversation_refusal(code);
            }
            coland_storage::DirectConversationAdmissionCut::Passed => true,
            coland_storage::DirectConversationAdmissionCut::NotDirectConversation => false,
        };
        if !private_governance
            && !direct_conversation
            && event.kind != arkret_wire::EventKind::CallState
        {
            crate::routing::events::operations::validate_operation_semantics(
                state,
                std::slice::from_ref(&operation),
            )
            .map_err(|reason| ServiceError::SchemaViolation(reason.to_owned()))?;
        }
        let poll_at_cut = event.kind == arkret_wire::EventKind::MessageCreate
            && matches!(
                operation
                    .payload
                    .get("content")
                    .and_then(|content| content.get("kind"))
                    .and_then(serde_json::Value::as_str),
                Some("ak.content.poll" | "ak.content.poll.response")
            );
        let decided_at_cut = direct_conversation
            || decided_at_commit_cut(&event.kind)
            || poll_at_cut
            || (event.kind == arkret_wire::EventKind::MessageCreate
                && producer.is_managed_device());
        if !decided_at_cut {
            Box::pin(
                crate::routing::events::operations::validate_operation_policy(
                    state,
                    std::slice::from_ref(&operation),
                ),
            )
            .await
            .map_err(|reason| ServiceError::Conflict(reason.to_owned()))?;
            if event.kind == arkret_wire::EventKind::MessageCreate {
                Box::pin(crate::routing::message_authoring::message_create_send_gate(
                    state, event,
                ))
                .await?;
            }
            if let Some(reason) = state
                .projections()
                .preflight_projected_batch_rejection(std::iter::once(&operation))
            {
                return Err(ServiceError::Conflict(reason));
            }
        }
        let origin_source = super::authority_forward::prepare_control_source(state, event).await?;
        let committed_at = Utc::now();
        let method = arkret_wire::DidUrl::new(
            crate::routing::federation::federation_service_signature_key_id(
                state.service_did().as_str(),
            ),
        )
        .map_err(|error| ServiceError::Internal(error.to_string()))?;
        let SelfEventUnitEffects {
            franking_replay_nonce,
            mls,
        } = effects;
        let is_mls = matches!(
            event.kind,
            arkret_wire::EventKind::MlsGenesis | arkret_wire::EventKind::MlsCommit
        );
        let candidate = match &producer {
            AdmittedProducer::Forwarded(retained) => {
                Some(retained.producer_signer_fact.clone().into())
            }
            AdmittedProducer::Applet(guard) => Some(
                state
                    .authority_commits()
                    .prepare_service_signer_fact(event, guard, committed_at)
                    .await?,
            ),
            AdmittedProducer::Local(guard) if matches!(guard.as_ref(), SelfProducerCommitGuard::AppletManagedDevice(_)) => Some(
                arkret_models_collaboration::authority_commit::HistoricalProducerSignerFact::RealmDevice(
                    state.authority_commits().prepare_realm_device_signer_fact(event, committed_at).await?
                )
            ),
            _ => None,
        };
        let native_mls_request = mls
            .as_ref()
            .and_then(|installation| installation.native_request.clone());
        let mut transaction = match mls {
            Some(mls) if is_mls => {
                state
                    .authority_commits()
                    .prepare_self_mls_transaction_with_signer_fact(
                        event,
                        mls.state,
                        mls.welcomes,
                        &state.service_core_id(),
                        method,
                        state.notary_signing_key().as_ref(),
                        committed_at,
                        candidate.as_ref(),
                    )
                    .await?
            }
            None if !is_mls => {
                state
                    .authority_commits()
                    .prepare_self_event_transaction_with_signer_fact(
                        event,
                        &state.service_core_id(),
                        method,
                        state.notary_signing_key().as_ref(),
                        committed_at,
                        candidate.as_ref(),
                    )
                    .await?
            }
            _ => {
                return Err(ServiceError::Internal(
                    "an MLS Event commits only through the MLS unit".to_owned(),
                ));
            }
        };
        Box::pin(super::authority_forward::stage_control_source(
            state,
            &transaction,
            origin_source,
        ))
        .await?;
        if event.kind == arkret_wire::EventKind::MlsCommit {
            Box::pin(super::authority_mls_unit::attach_local_roster_witnesses(
                state,
                &mut transaction,
            ))
            .await?;
        }
        let canonical_bytes = arkret_canonical::canonical_json_bytes(
            &event
                .digest_payload()
                .map_err(|error| ServiceError::SchemaViolation(error.to_string()))?,
        )
        .map_err(|error| ServiceError::SchemaViolation(error.to_string()))?;
        let canonical_digest = event
            .event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
            .map_err(|error| ServiceError::SchemaViolation(error.to_string()))?;
        let record = coland_storage::CanonicalEventRecord {
            event_id: event.event_id.to_string(),
            actor_id: event.actor_id.to_string(),
            realm_id: Some(event.realm_id.to_string()),
            kind: event.kind.as_str().to_owned(),
            schema_id: arkret_wire::SchemaId::EVENT_V1.to_owned(),
            digest_suite: arkret_canonical::DigestSuite::Sha256,
            canonical_digest,
            canonical_bytes,
            envelope,
            received_at: committed_at,
        };
        let (
            self_producer_guard,
            forwarded_producer_evidence,
            forwarded_agent_producer,
            applet_producer_guard,
        ) = match producer {
            AdmittedProducer::Local(guard) => (Some(*guard), None, None, None),
            AdmittedProducer::Forwarded(evidence) => (None, Some(*evidence), None, None),
            AdmittedProducer::ForwardedAgent(evidence) => (None, None, Some(*evidence), None),
            AdmittedProducer::Applet(guard) => (None, None, None, Some(guard)),
        };
        let agent_grant_scope_evidence =
            Box::pin(super::authority_agent_grant::prepare_agent_grant_scope(
                state,
                event,
                transaction.commit.committed_at,
            ))
            .await?;
        let idempotency = match native_mls_request {
            Some(context) => Some(context.accepted_response(&transaction.commit)?),
            None => idempotency,
        };
        let command = coland_services::events::CommitAcceptedEventCommand {
            verified_media_participant:
                crate::routing::interop::webrtc::prepare_verified_roster_participant(state, event)
                    .await?,
            authority_commit: transaction.clone(),
            self_producer_guard,
            applet_producer_guard,
            widget_token_gate: None,
            agent_grant_scope_evidence,
            forwarded_producer_evidence,
            forwarded_agent_producer,
            agent_deployment_ceiling: state.config().agent_participation_ceiling,
            event: record,
            parent_membership_admission: None,
            contact_projection: None,

            device_revocation_transition: None,
            device_revocation_gate: None,
            projections: if private_governance {
                Vec::new()
            } else {
                vec![coland_services::events::ProjectedEvent {
                    event_id: event.event_id.to_string(),
                    realm_id: event.realm_id.to_string(),
                    event_kind: event.kind.clone(),
                    operation_kind: "create".to_owned(),
                    operation_id: Some(operation.operation_id.to_string()),
                    sender: Some(event.actor_id.to_string()),
                    payload: serde_json::to_value(&event.payload)
                        .map_err(|error| ServiceError::SchemaViolation(error.to_string()))?,
                    created_at: event.created_at,
                    received_at: committed_at,
                }]
            },
            idempotency,
            deliveries: Vec::new(),
            realm_fanout_source: (!private_governance)
                .then(|| EventAdmissionSubmission::new(submission.event.clone())),
        };
        let realm_organization_proof =
            Box::pin(crate::routing::organizations::prepare_realm_organization_proof(state, event))
                .await
                .map_err(|reason| ServiceError::Conflict(reason.to_owned()))?;
        let franking_replay_nonce = franking_replay_nonce.map(|mut nonce| {
            nonce.consumed_at = committed_at;
            nonce
        });
        let event_approvals = Box::pin(crate::approval_admission::prepare_event_approvals(
            state,
            submission,
            transaction.commit.committed_at,
        ))
        .await?;
        let committed = if franking_replay_nonce.is_some()
            || realm_organization_proof.is_some()
            || event_approvals.is_some()
        {
            crate::boxed_future(|| {
                state.events().commit_accepted_event_batch(
                    coland_services::events::CommitAcceptedEventBatchCommand {
                        audit_unit: None,
                        events: vec![command],
                        franking_replay_nonce,
                        realm_organization_proof,
                        event_approvals,
                        applet_record: None,
                        applet_authoring_preview: None,
                        agent_membership_cascade: None,
                    },
                )
            })
            .await
        } else {
            crate::boxed_future(|| state.events().commit_accepted_event(command)).await
        };
        if let Err(error) = committed {
            // A concurrent exact replay may have won the same Event identity; it
            // answers with the stored outcome instead of the losing rollback.
            if let Some(outcome) = Box::pin(exact_replay(state, event)).await? {
                return Ok(outcome);
            }
            return super::authority_direct_conversation::relay_direct_conversation_refusal(error);
        }
        if private_governance {
            return Ok(AuthoritySubmitResponseBody::Accepted {
                status: AuthorityCommitStatus::Committed,
                commit: transaction.commit,
            });
        }
        // The Commit is durable. This Station's recipients' ordinary notification
        // rows are a derived projection; their failure never changes the outcome.
        #[cfg(feature = "conformance-harness")]
        tracing::warn!(phase = "unit_committed", kind = %event.kind.as_str(), "self Event execution boundary");
        Box::pin(
            crate::routing::events::notify::dispatch_committed_event_notifications(state, event),
        )
        .await;
        #[cfg(feature = "conformance-harness")]
        tracing::warn!(phase = "notifications_dispatched", kind = %event.kind.as_str(), "self Event execution boundary");
        if decided_at_cut && !poll_at_cut && event.kind != arkret_wire::EventKind::StrandCreate {
            return Ok(AuthoritySubmitResponseBody::Accepted {
                status: AuthorityCommitStatus::Committed,
                commit: transaction.commit,
            });
        }
        operation = operation
            .with_committed_ref(arkret_wire::CommittedEventRef {
                event_id: event.event_id.clone(),
                commit_id: transaction.commit.commit_id.clone(),
                stream_ref: transaction.commit.stream_ref.clone(),
                stream_position: transaction.commit.stream_position,
            })
            .map_err(|error| ServiceError::Internal(error.to_string()))?;
        #[cfg(feature = "conformance-harness")]
        tracing::warn!(phase = "projection_installing", kind = %event.kind.as_str(), "self Event execution boundary");
        let effect = state.projections().apply_projected(&operation, state.hlc());
        #[cfg(feature = "conformance-harness")]
        tracing::warn!(phase = "projection_installed", kind = %event.kind.as_str(), "self Event execution boundary");
        let needs_repair = matches!(
            effect,
            coland_services::projection::ProjectionEffectView::Rejected { .. }
        ) || (!poll_at_cut
            && matches!(
                effect,
                coland_services::projection::ProjectionEffectView::Ignored
            ));
        if needs_repair {
            let repair_state = state.clone();
            tokio::spawn(async move {
                let mut delay = std::time::Duration::from_secs(1);
                loop {
                    if repair_state.hydrate().await.is_ok() {
                        break;
                    }
                    tokio::time::sleep(delay).await;
                    delay = (delay * 2).min(std::time::Duration::from_secs(30));
                }
            });
        }
        Ok(AuthoritySubmitResponseBody::Accepted {
            status: AuthorityCommitStatus::Committed,
            commit: transaction.commit,
        })
    })
}

/// `ak.self.moderation.command.report.v1`: admit the reporter's exact signed
/// `ak.self.moderation.report` Event (content-moderation.md §3.1/§3.3).
///
/// The Station never authors, re-signs or injects guards into the Event; it
/// only signs the covering RealmCommit. The report's current state and
/// any consumed franking nonce commit with it. Realm and Circle reports use
/// their exact signed source stream; MIMI facade reports have their own ingress.
pub(crate) async fn submit_self_moderation_report(
    state: &AppState,
    session: &SessionIdentityState,
    request: EventAdmissionSubmission,
) -> ServiceResult<AuthoritySubmitResponseBody> {
    request
        .validate()
        .map_err(|error| ServiceError::SchemaViolation(error.to_string()))?;
    let event = &request.event;
    if event.kind != arkret_wire::EventKind::SelfModerationReport {
        return Err(ServiceError::SchemaViolation(
            "report_event must be ak.self.moderation.report".to_owned(),
        ));
    }
    if request.approval_signatures.is_some() {
        return Err(ServiceError::SchemaViolation(
            "self moderation report carries no approval signatures".to_owned(),
        ));
    }
    if event.executed_by.is_some() || event.authorization_ref.is_some() || event.applet_id.is_some()
    {
        return Err(ServiceError::SchemaViolation(
            "self moderation report must be directly authored by its reporter".to_owned(),
        ));
    }
    let producer_guard =
        super::authority_producer_validation::verify_self_event_producer(state, session, event)
            .await?;
    let payload: arkret_models_collaboration::events_payloads::moderation::ModerationReportPayload =
        serde_json::from_value(
            serde_json::to_value(&event.payload)
                .map_err(|error| ServiceError::SchemaViolation(error.to_string()))?,
        )
        .map_err(|error| ServiceError::SchemaViolation(error.to_string()))?;
    payload
        .validate_self_endpoint(event.actor_id.signing_principal_id())
        .map_err(|error| ServiceError::SchemaViolation(error.to_owned()))?;
    let franking_replay_nonce =
        payload
            .franking_proof
            .map(|proof| coland_storage::FrankingReplayNonceCommit {
                realm_id: event.realm_id.to_string(),
                received_by: proof.received_by,
                replay_nonce: proof.replay_nonce,
                report_event_id: event.event_id.to_string(),
                consumed_at: Utc::now(),
            });
    commit_event_unit(
        state,
        &request,
        AdmittedProducer::Local(Box::new(producer_guard)),
        SelfEventUnitEffects {
            franking_replay_nonce,
            mls: None,
        },
    )
    .await
}

/// Admit an Applet producer using its independently checked current Service key.
pub(crate) async fn submit_applet_event(
    state: &AppState,
    event: Event,
    service_did_document: arkret_identity::DidDocument,
) -> ServiceResult<AuthoritySubmitResponseBody> {
    let submission = EventAdmissionSubmission {
        event,
        approval_signatures: None,
    };
    submission
        .validate()
        .map_err(|e| ServiceError::SchemaViolation(e.to_string()))?;
    if !matches!(
        submission.event.kind,
        arkret_wire::EventKind::MessageCreate
            | arkret_wire::EventKind::MemberState
            | arkret_wire::EventKind::InviteAccept
            | arkret_wire::EventKind::CapabilityRelinquish
            | arkret_wire::EventKind::AppletBridgeError
            | arkret_wire::EventKind::CapabilityGrant
            | arkret_wire::EventKind::CapabilityRevoke
    ) {
        return Err(ServiceError::SchemaViolation(
            "Applet Event kind has no accepting domain unit".into(),
        ));
    }
    commit_event_unit(
        state,
        &submission,
        AdmittedProducer::Applet(coland_storage::AppletEventProducerGuard {
            service_did_document,
        }),
        SelfEventUnitEffects::default(),
    )
    .await
}

/// MIMI room binding: HTTP provider authentication and the independent native
/// Account/device producer proof authorize separate identities.
pub(crate) async fn submit_mimi_binding_event(
    state: &AppState,
    submission: &EventAdmissionSubmission,
) -> ServiceResult<AuthoritySubmitResponseBody> {
    if submission.event.kind != arkret_wire::EventKind::MimiRoomBinding {
        return Err(ServiceError::SchemaViolation(
            "MIMI binding ingress only accepts room bindings".into(),
        ));
    }
    let guard = super::verify_mimi_binding_producer(state, &submission.event).await?;
    commit_event_unit(
        state,
        submission,
        AdmittedProducer::Local(Box::new(guard)),
        SelfEventUnitEffects::default(),
    )
    .await
}

#[cfg(test)]
mod claim_privacy_tests {
    use super::*;

    #[test]
    fn relationship_and_scope_policy_admission_use_the_durable_current_cut() {
        for kind in [
            arkret_wire::EventKind::RealmLink,
            arkret_wire::EventKind::RealmJoinRule,
            arkret_wire::EventKind::RealmHistoryAccess,
        ] {
            assert!(decided_at_commit_cut(&kind));
        }
    }

    #[test]
    fn genesis_creation_timestamp_rejects_one_millisecond_drift_before_lookup() {
        use arkret_models_collaboration::events_payloads::{
            MlsGenesisCreatorLeafAuthority, MlsGenesisPayload,
        };
        use arkret_wire::{Base64UrlString, BlobRef, DeviceId, EventId, NonEmptyString};

        let realm = arkret_wire::RealmId::from_event_id(&EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            [31; 32],
        ));
        let at = chrono::DateTime::parse_from_rfc3339("2026-10-10T00:00:00.123Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let payload = MlsGenesisPayload {
            cipher_suite: NonEmptyString::new("MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519")
                .unwrap(),
            group_info_ref: BlobRef::new(format!("ak:blob:sha256:{}", "1".repeat(64))).unwrap(),
            ratchet_tree_ref: BlobRef::new(format!("ak:blob:sha256:{}", "2".repeat(64))).unwrap(),
            creator_leaf_authority: MlsGenesisCreatorLeafAuthority {
                leaf_signature_key_base64url: Base64UrlString::new(
                    arkret_canonical::base64url_encode([7; 32]),
                )
                .unwrap(),
                endpoint: arkret_wire::MlsWelcomeRecipientEndpoint::Device {
                    device_id: DeviceId::new("ak:device:01904100-0000-7000-8000-000000000086")
                        .unwrap(),
                },
                authorization_event_ref: EventId::from_digest(
                    arkret_canonical::DigestSuite::Sha256,
                    [32; 32],
                ),
            },
            governance_binding: arkret_models_crypto::MlsGovernanceBindingPayload::realm(
                realm.clone(),
                None,
                0,
                0,
                0,
            )
            .unwrap(),
            created_at: at,
        };
        payload.validate().unwrap();
        for (outer_delta, inner_delta) in [(0, 0), (-1, 0), (1, 0), (0, -1), (0, 1)] {
            let mut candidate = payload.clone();
            candidate.created_at += chrono::Duration::milliseconds(inner_delta);
            let event = arkret_wire::test_support::raw_event_for_actor_at(
                arkret_wire::EventKind::MlsGenesis.as_str(),
                arkret_wire::ScopeRef::Realm {
                    realm_id: realm.clone(),
                },
                arkret_wire::ActorId::account(arkret_wire::AccountId::new(
                    arkret_wire::DidCoreId::new("ak:did_core:web:genesis-creator.example").unwrap(),
                    arkret_wire::DidCoreId::new("ak:did_core:web:genesis-station.example").unwrap(),
                )),
                serde_json::to_value(candidate).unwrap(),
                at + chrono::Duration::milliseconds(outer_delta),
            )
            .unwrap();
            // Every candidate has a valid content-derived Event ID. Drift must
            // fail as a timestamp refusal rather than an unrelated digest error.
            let result = validate_replay_event_identity(&event);
            if outer_delta == inner_delta {
                result.unwrap();
            } else {
                assert_eq!(
                    result.unwrap_err().conflict_code(),
                    Some(coland_storage::ConflictCode::FailedPrecondition),
                    "outer={outer_delta}ms, inner={inner_delta}ms",
                );
            }
        }
    }

    #[test]
    fn replay_identity_accepts_exact_content_and_rejects_drift_before_lookup() {
        let mut event = arkret_wire::test_support::raw_event(
            "ak.message.create",
            arkret_wire::ScopeRef::Realm {
                realm_id: arkret_wire::RealmId::new(
                    "ak:realm:Ac1aCK8aQdnkYImvdH3DFjq4jDCP198pXYWCGzGuVyj5",
                )
                .unwrap(),
            },
            arkret_wire::DidCoreId::new("ak:did_core:webvh:z6mkfixture").unwrap(),
            arkret_wire::DidCoreId::new("ak:did_core:webvh:z6mkfixtureps").unwrap(),
            serde_json::json!({"body": "original"}),
        )
        .unwrap();
        validate_replay_event_identity(&event).unwrap();
        let original_id = event.event_id.clone();
        event
            .payload
            .insert("body".into(), serde_json::json!("drift"));
        let error = validate_replay_event_identity(&event).unwrap_err();
        assert_eq!(
            error.conflict_code(),
            Some(coland_storage::ConflictCode::EventIdDigestMismatch)
        );
        assert_eq!(event.event_id, original_id);
        event.event_id = event
            .derive_event_id_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
            .unwrap();
        validate_replay_event_identity(&event).unwrap();
    }

    #[test]
    fn claim_token_state_refusals_have_one_public_error() {
        for reason in [
            "expired_invite_token: expired",
            "claim_invalid: unknown invite",
            "duplicate_conflict: already consumed",
            "capability_denied: inviter left",
            "capability_denied: inviter lost authority",
            "claim_invalid: revoked invite",
        ] {
            let error = private_claim_refusal(ServiceError::Conflict(reason.to_owned()));
            assert!(matches!(&error, ServiceError::NotFound(_)));
            assert_eq!(error.detail(), "invite claim not found");
        }
        let missing = private_claim_refusal(ServiceError::NotFound("unknown invite".to_owned()));
        assert_eq!(missing.detail(), "invite claim not found");
    }

    #[test]
    fn a_moved_claim_cut_is_retryable_without_a_token_verdict() {
        let error = private_claim_refusal(ServiceError::Conflict(
            "temporarily_unavailable: stream head advanced".to_owned(),
        ));
        assert_eq!(
            error.conflict_code(),
            Some(coland_storage::ConflictCode::TemporarilyUnavailable),
        );
        let database = private_claim_refusal(ServiceError::Database("unavailable".to_owned()));
        assert!(matches!(database, ServiceError::Database(_)));
    }
}
