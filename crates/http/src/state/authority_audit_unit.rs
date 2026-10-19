//! First admission of the two closed audit operations on the shared event UoW.

use arkret_models_collaboration::authority_commit::{
    AtomicSlotProducerEvidence, AuditPairedEventAcceptanceOutcome, AuditPairedEventUnitSubmission,
    AuthorityForwardBranch, PeerAuthorityForwardAtomicRequest, PeerAuthorityForwardOutcomeValue,
    PeerAuthoritySubmitOutcome, PeerAuthoritySubmitRequest,
};
use arkret_models_collaboration::strand_watch_operations::{
    PEER_STRAND_WATCH_AUDIT_PATH, PeerWatchAuditReadRequest, STRAND_WATCH_AUDIT_MAX_BYTES,
    WatchAuditReadOutcome, WatchAuditReadRequest,
};
use arkret_wire::{EventAdmissionSubmission, ServiceOperationId};
use coland_services::identity::SessionIdentityState;
use coland_services::{ServiceError, ServiceResult};
use coland_storage::{RegisteredAuditCommit, RegisteredAuditOutcome};

use super::AppState;
use super::authority_self_event_unit::AdmittedProducer;

fn refusal(error: arkret_wire::WireError) -> ServiceError {
    ServiceError::protocol(
        error
            .error_code()
            .unwrap_or(arkret_wire::ErrorCode::SchemaViolation),
        error,
    )
}

pub(crate) async fn verified_governor(
    state: &AppState,
    realm: &arkret_wire::RealmId,
) -> ServiceResult<coland_storage::CurrentRealmAuthority> {
    let current = state
        .authority_commits()
        .current_authority(realm)
        .await?
        .ok_or_else(|| {
            ServiceError::Conflict("revision_unavailable: Realm authority unavailable".to_owned())
        })?;
    if current.service_id == state.service_core_id() {
        return Ok(current);
    }
    use arkret_models_collaboration::governance::realm_join_intake::{
        AuthorityLocatorSource, RealmJoinCandidate, RealmJoinCandidateServiceKind,
    };
    let hint = RealmJoinCandidate {
        service_kind: RealmJoinCandidateServiceKind::Station,
        service_id: current.service_id.clone(),
        endpoint_url: None,
        source: AuthorityLocatorSource::Cache,
    };
    let nonce =
        arkret_wire::Base64UrlString::new(arkret_canonical::base64url_encode(rand::random::<
            [u8; 32],
        >()))
        .map_err(ServiceError::internal)?;
    let located =
        crate::routing::realm_join::resolve_verified_authority(state, realm, &[hint], &nonce)
            .await
            .map_err(|error| {
                ServiceError::Conflict(format!(
                    "revision_unavailable: fresh governor unavailable: {error}"
                ))
            })?;
    let verified = located.current_authority();
    if verified.generation < current.generation
        || (verified.generation == current.generation && verified != current)
    {
        return Err(ServiceError::Conflict(
            "revision_unavailable: governing cut conflicts with observed authority".to_owned(),
        ));
    }
    Ok(verified)
}

async fn exact_pair(
    state: &AppState,
    request: &AuditPairedEventUnitSubmission,
) -> ServiceResult<Option<AuditPairedEventAcceptanceOutcome>> {
    let bytes = arkret_canonical::canonical_json_bytes(request)
        .map_err(|e| ServiceError::SchemaViolation(e.to_string()))?;
    for slot in &request.events {
        if let Some(original) = state
            .authority_commits()
            .registered_audit_result(&slot.event.event_id)
            .await?
        {
            if original.canonical_request != bytes {
                return Err(ServiceError::Conflict(
                    "duplicate_conflict: Event belongs to another complete audit unit".to_owned(),
                ));
            }
            return match original.outcome {
                RegisteredAuditOutcome::Pair(outcome) => {
                    outcome.validate_for_request(request).map_err(refusal)?;
                    Ok(Some(outcome))
                }
                _ => Err(ServiceError::Conflict(
                    "duplicate_conflict: Event belongs to another audit operation".to_owned(),
                )),
            };
        }
    }
    Ok(None)
}

async fn validate_caller(
    state: &AppState,
    session: &SessionIdentityState,
    event: &arkret_wire::Event,
    operation: &'static str,
) -> ServiceResult<()> {
    crate::routing::events::require_agent_session_scope(session, operation)
        .map_err(|e| ServiceError::Conflict(format!("capability_denied: {e}")))?;
    let actor = crate::routing::identity::session_actor::validated_session_actor(state, session)
        .await
        .map_err(|e| {
            ServiceError::Conflict(format!(
                "capability_denied: authenticated actor unavailable: {e}"
            ))
        })?;
    if event.actor_id != actor
        || actor
            .as_account_id()
            .is_none_or(|account| account.station_id != state.service_core_id())
    {
        return Err(ServiceError::NotFound("audit actor not found".to_owned()));
    }
    Ok(())
}

async fn commit(
    state: &AppState,
    submissions: &[EventAdmissionSubmission],
    producers: Vec<AdmittedProducer>,
    read: Option<&WatchAuditReadRequest>,
    pair: Option<&AuditPairedEventUnitSubmission>,
) -> ServiceResult<RegisteredAuditOutcome> {
    let at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    let events = submissions
        .iter()
        .map(|slot| slot.event.clone())
        .collect::<Vec<_>>();
    let mut facts = Vec::with_capacity(producers.len());
    for (event, producer) in events.iter().zip(&producers) {
        facts.push(match producer {
            AdmittedProducer::Forwarded(source) => Some(source.producer_signer_fact.clone().into()),
            AdmittedProducer::Applet(guard) => Some(
                state
                    .authority_commits()
                    .prepare_service_signer_fact(event, guard, at)
                    .await?
                    .into(),
            ),
            _ => None,
        });
    }
    let method = arkret_wire::DidUrl::new(
        crate::routing::federation::federation_service_signature_key_id(
            state.service_did().as_str(),
        ),
    )
    .map_err(ServiceError::internal)?;
    let transactions = state
        .authority_commits()
        .prepare_registered_event_transactions(
            &events,
            &state.service_core_id(),
            method,
            state.notary_signing_key().as_ref(),
            at,
            &facts,
        )
        .await?;
    let mut commands = Vec::with_capacity(submissions.len());
    let mut approvals = Vec::with_capacity(submissions.len());
    for ((slot, producer), transaction) in submissions.iter().zip(producers).zip(transactions) {
        let event = &slot.event;
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
        let envelope = serde_json::to_value(event)
            .map_err(|e| ServiceError::SchemaViolation(e.to_string()))?;
        let operation_id = crate::routing::events::event_log::event_operation_id(
            &envelope,
            event.event_id.as_str(),
        )
        .ok_or_else(|| {
            ServiceError::SchemaViolation("invalid audit operation identity".to_owned())
        })?;
        approvals.push(crate::approval_admission::prepare_event_approvals(state, slot, at).await?);
        let agent_grant_scope_evidence =
            super::authority_agent_grant::prepare_agent_grant_scope(state, event, at).await?;
        commands.push(coland_services::events::CommitAcceptedEventCommand {
            verified_media_participant: None,
            authority_commit: transaction,
            self_producer_guard,
            forwarded_producer_evidence,
            forwarded_agent_producer,
            applet_producer_guard,
            widget_token_gate: None,
            agent_grant_scope_evidence,
            agent_deployment_ceiling: state.config().agent_participation_ceiling,
            event: coland_storage::CanonicalEventRecord {
                event_id: event.event_id.to_string(),
                actor_id: event.actor_id.to_string(),
                realm_id: Some(event.realm_id.to_string()),
                kind: event.kind.as_str().to_owned(),
                schema_id: arkret_wire::SchemaId::EVENT_V1.to_owned(),
                digest_suite: arkret_canonical::DigestSuite::Sha256,
                canonical_digest: event
                    .event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
                    .map_err(refusal)?,
                canonical_bytes: arkret_canonical::canonical_json_bytes(
                    &event.digest_payload().map_err(refusal)?,
                )
                .map_err(|e| ServiceError::SchemaViolation(e.to_string()))?,
                envelope,
                received_at: at,
            },
            parent_membership_admission: None,
            contact_projection: None,
            device_revocation_transition: None,
            device_revocation_gate: None,
            projections: vec![coland_services::events::ProjectedEvent {
                event_id: event.event_id.to_string(),
                realm_id: event.realm_id.to_string(),
                event_kind: event.kind.clone(),
                operation_kind: "create".to_owned(),
                operation_id: Some(operation_id.to_string()),
                sender: Some(event.actor_id.to_string()),
                payload: serde_json::to_value(&event.payload)
                    .map_err(|e| ServiceError::SchemaViolation(e.to_string()))?,
                created_at: event.created_at,
                received_at: at,
            }],
            idempotency: None,
            deliveries: Vec::new(),
            realm_fanout_source: Some(EventAdmissionSubmission::new(event.clone())),
        });
    }
    let (audit_unit, event_approvals) = if let Some(pair) = pair {
        let approvals = approvals.try_into().map_err(|_| {
            ServiceError::SchemaViolation("audit pair requires two approval slots".to_owned())
        })?;
        (
            RegisteredAuditCommit::Pair {
                request: Box::new(pair.clone()),
                approvals,
            },
            None,
        )
    } else {
        let request =
            read.ok_or_else(|| ServiceError::internal("unregistered audit transaction"))?;
        (
            RegisteredAuditCommit::WatchRead {
                request: Box::new(request.clone()),
            },
            approvals.pop().flatten(),
        )
    };
    let result = state
        .events()
        .commit_accepted_event_batch(coland_services::events::CommitAcceptedEventBatchCommand {
            audit_unit: Some(audit_unit),
            events: commands,
            event_approvals,
            franking_replay_nonce: None,
            realm_organization_proof: None,
            invite_claim_proof: None,
            applet_record: None,
            applet_authoring_preview: None,
            agent_membership_cascade: None,
        })
        .await?;
    result.audit_outcome.ok_or_else(|| {
        ServiceError::internal("registered audit transaction omitted its durable outcome")
    })
}

pub(super) async fn submit_self_pair(
    state: &AppState,
    session: &SessionIdentityState,
    request: AuditPairedEventUnitSubmission,
) -> ServiceResult<AuditPairedEventAcceptanceOutcome> {
    request.validate().map_err(refusal)?;
    validate_caller(
        state,
        session,
        &request.events[0].event,
        ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT_V1,
    )
    .await?;
    if let Some(outcome) = exact_pair(state, &request).await? {
        return Ok(outcome);
    }
    let authority = verified_governor(state, &request.events[0].event.realm_id).await?;
    if authority.service_id != state.service_core_id() {
        return forward_pair(state, session, request, &authority).await;
    }
    let mut producers = Vec::with_capacity(2);
    for slot in &request.events {
        if let Some((producer, _)) =
            super::authority_forward::resolve_service_producer(state, &slot.event)?
        {
            producers.push(producer);
            continue;
        }

        let (guard, _) = super::authority_producer_validation::verify_self_event_producer_key(
            state,
            session,
            &slot.event,
        )
        .await?;
        producers.push(AdmittedProducer::Local(Box::new(guard)));
    }
    match commit(state, &request.events, producers, None, Some(&request)).await? {
        RegisteredAuditOutcome::Pair(outcome) => Ok(outcome),
        _ => Err(ServiceError::internal("audit pair returned a read outcome")),
    }
}

pub(super) async fn submit_peer_pair(
    state: &AppState,
    peer: &coland_services::authority_commit::AuthenticatedPeerContext,
    request: PeerAuthorityForwardAtomicRequest,
) -> ServiceResult<AuditPairedEventAcceptanceOutcome> {
    let event = &request.atomic_submission.events[0].event;
    if event
        .actual_signer()
        .as_account_id()
        .is_some_and(|account| account.station_id != peer.source_service_id)
    {
        return Err(ServiceError::NotFound("audit source not found".to_owned()));
    }
    if let Some(outcome) = exact_pair(state, &request.atomic_submission).await? {
        return Ok(outcome);
    }
    request.validate().map_err(refusal)?;
    let digest =
        arkret_models_collaboration::authority_commit::authority_forward_body_digest(&request)
            .map_err(refusal)?;
    let mut producers = Vec::with_capacity(2);
    for (slot, evidence) in request
        .atomic_submission
        .events
        .iter()
        .zip(&request.atomic_producer_evidence)
    {
        let (producer, _) = super::authority_forward::resolve_forwarded_producer(
            state,
            peer,
            &slot.event,
            evidence.device(),
            evidence.agent(),
            &digest,
            chrono::Utc::now(),
        )?;
        producers.push(producer);
    }
    match commit(
        state,
        &request.atomic_submission.events,
        producers,
        None,
        Some(&request.atomic_submission),
    )
    .await?
    {
        RegisteredAuditOutcome::Pair(outcome) => Ok(outcome),
        _ => Err(ServiceError::internal("audit pair returned a read outcome")),
    }
}

async fn forward_pair(
    state: &AppState,
    session: &SessionIdentityState,
    unit: AuditPairedEventUnitSubmission,
    authority: &coland_storage::CurrentRealmAuthority,
) -> ServiceResult<AuditPairedEventAcceptanceOutcome> {
    state
        .authority_commits()
        .retain_registered_pair_forward(&unit, None)
        .await?;
    let mut request = PeerAuthorityForwardAtomicRequest {
        branch: AuthorityForwardBranch::AuthorityForward,
        atomic_submission: unit,
        atomic_producer_evidence: [
            AtomicSlotProducerEvidence::Service {},
            AtomicSlotProducerEvidence::Service {},
        ],
    };
    let digest =
        arkret_models_collaboration::authority_commit::authority_forward_body_digest(&request)
            .map_err(refusal)?;
    let [first, second] = &request.atomic_submission.events;
    let service = matches!(
        first.event.actual_signer(),
        arkret_wire::ActorId::Service { .. }
    );
    if !service {
        for slot in &request.atomic_submission.events {
            super::authority_forward::validate_recovery_caller(state, session, &slot.event).await?;
        }
    }
    request.atomic_producer_evidence = if service {
        // The authenticated Account submits its original Service-signed unit.
        // These empty slots assert no Device/Agent authority; the governor
        // verifies both Service originals and their current grants at its cut.
        [
            AtomicSlotProducerEvidence::Service {},
            AtomicSlotProducerEvidence::Service {},
        ]
    } else if let Some(agent) =
        super::authority_forward::fresh_producer_agent_evidence(state, &first.event).await?
    {
        let verified = arkret_identity::agent_authority_evidence::verify_forwarded_agent_producer(
            &second.event,
            &agent,
            &state.service_core_id(),
            crate::wire::now(),
            None,
        )
        .map_err(|error| {
            ServiceError::protocol(
                error
                    .error_code()
                    .unwrap_or(arkret_wire::ErrorCode::SignatureInvalid),
                error,
            )
        })?;
        state
            .authority_commits()
            .retain_agent_forward_evidence_at_same_cut(
                &second.event,
                verified.evidence(),
                crate::wire::now(),
            )
            .await?;
        [
            AtomicSlotProducerEvidence::Agent {
                producer_agent_evidence: agent.clone(),
            },
            AtomicSlotProducerEvidence::Agent {
                producer_agent_evidence: agent,
            },
        ]
    } else if let Some(device) = super::authority_forward::fresh_non_managed_device_evidence(
        state,
        &first.event,
        &authority.service_id,
        &digest,
    )
    .await?
    {
        let mut core = device.device_projection_attestation.attestation.clone();
        core.event_authorization.event_id = second.event.event_id.clone();
        let attestation =
            arkret_signatures::device_projection::sign_forward_device_projection_attestation(
                core,
                state
                    .service_verification_method("notary-key")
                    .map_err(ServiceError::internal)?,
                state.notary_signing_key().as_ref(),
            )
            .map_err(refusal)?;
        let second_evidence = arkret_models_identity::ForwardAccountDeviceSignerEvidence {
            device_projection_attestation: attestation,
            service_resolution: device.service_resolution.clone(),
        };
        state
            .persistence()
            .retain_forward_current_signer_evidence(&second.event, &second_evidence)
            .await?;
        [
            AtomicSlotProducerEvidence::Device {
                producer_device_evidence: device,
            },
            AtomicSlotProducerEvidence::Device {
                producer_device_evidence: second_evidence,
            },
        ]
    } else {
        return Err(ServiceError::Conflict(
            "revision_unavailable: audit Service forwarding has no verified source".to_owned(),
        ));
    };
    request.validate().map_err(refusal)?;
    let body = PeerAuthoritySubmitRequest::AuthorityForwardAtomic(request);
    let bytes = arkret_canonical::canonical_json_bytes(&body)
        .map_err(|e| ServiceError::SchemaViolation(e.to_string()))?;
    let response = crate::routing::federation::outbox::signed_peer_request(
        state,
        authority.service_id.as_str(),
        "/_arkret/peer/events",
        &bytes,
        STRAND_WATCH_AUDIT_MAX_BYTES,
    )
    .await
    .map_err(|e| {
        ServiceError::Conflict(format!(
            "revision_unavailable: audit forwarding unavailable: {e}"
        ))
    })?;
    if response.status != 200 {
        return Err(super::authority_forward::relayed_refusal(
            response.status,
            &response.body,
        ));
    }
    let outcome: PeerAuthoritySubmitOutcome = serde_json::from_slice(&response.body)
        .map_err(|e| ServiceError::internal(e.to_string()))?;
    outcome.validate_for_request(&body).map_err(refusal)?;
    let PeerAuthoritySubmitOutcome::AuthorityForward(outcome) = outcome else {
        return Err(ServiceError::internal(
            "audit forward response branch mismatch",
        ));
    };
    let PeerAuthorityForwardOutcomeValue::AuditPairedEvent(outcome) = outcome.outcome else {
        return Err(ServiceError::internal("audit forward returned one Event"));
    };
    let PeerAuthoritySubmitRequest::AuthorityForwardAtomic(request) = body else {
        unreachable!()
    };
    for (slot, commit) in request
        .atomic_submission
        .events
        .iter()
        .zip(&outcome.commits)
    {
        // Exact recovery may return an original from an earlier tenure.
        // The freshly verified current chain must authorize that original
        // generation; its Commit never becomes the new current predecessor.
        super::authority_forward::verify_forwarded_acknowledgement(
            state,
            &authority.service_id,
            &slot.event,
            commit,
        )
        .await?;
    }
    state
        .authority_commits()
        .retain_registered_pair_forward(&request.atomic_submission, Some(&outcome))
        .await?;
    super::replica_anchor::spawn_converge_stream(state, outcome.commits[0].stream_ref.clone());
    Ok(outcome)
}

pub(crate) async fn submit_self_read(
    state: &AppState,
    session: &SessionIdentityState,
    request: &WatchAuditReadRequest,
) -> ServiceResult<(WatchAuditReadOutcome, coland_storage::CurrentRealmAuthority)> {
    request.validate().map_err(refusal)?;
    validate_caller(
        state,
        session,
        &request.audit_submission.event,
        ServiceOperationId::SELF_STRAND_WATCH_COMMAND_AUDIT_READ_V1,
    )
    .await?;
    let authority = verified_governor(state, &request.audit_submission.event.realm_id).await?;
    if authority.service_id != state.service_core_id() {
        let mut peer = PeerWatchAuditReadRequest {
            audit_submission: request.audit_submission.clone(),
            producer_device_evidence: None,
            producer_agent_evidence: None,
        };
        peer.producer_agent_evidence = super::authority_forward::fresh_producer_agent_evidence(
            state,
            &request.audit_submission.event,
        )
        .await?;
        let digest =
            arkret_models_collaboration::authority_commit::authority_forward_body_digest(&peer)
                .map_err(refusal)?;
        peer.producer_device_evidence =
            super::authority_forward::fresh_non_managed_device_evidence(
                state,
                &request.audit_submission.event,
                &authority.service_id,
                &digest,
            )
            .await?;
        peer.validate().map_err(refusal)?;
        let bytes = arkret_canonical::canonical_json_bytes(&peer)
            .map_err(|e| ServiceError::SchemaViolation(e.to_string()))?;
        let response = crate::routing::federation::outbox::signed_peer_request(
            state,
            authority.service_id.as_str(),
            PEER_STRAND_WATCH_AUDIT_PATH,
            &bytes,
            STRAND_WATCH_AUDIT_MAX_BYTES,
        )
        .await
        .map_err(|e| {
            ServiceError::Conflict(format!("revision_unavailable: audit read unavailable: {e}"))
        })?;
        if response.status != 200 {
            return Err(super::authority_forward::relayed_refusal(
                response.status,
                &response.body,
            ));
        }
        let outcome: WatchAuditReadOutcome = serde_json::from_slice(&response.body)
            .map_err(|e| ServiceError::internal(e.to_string()))?;
        outcome
            .validate_for_request(request, authority.generation)
            .map_err(refusal)?;
        super::authority_forward::verify_forwarded_acknowledgement(
            state,
            &authority.service_id,
            &request.audit_submission.event,
            &outcome.audit_commit,
        )
        .await?;
        return Ok((outcome, authority));
    }
    if let Some(outcome) = original_read(state, request).await? {
        return Ok((outcome, authority));
    }
    let (guard, _) = super::authority_producer_validation::verify_self_event_producer_key(
        state,
        session,
        &request.audit_submission.event,
    )
    .await?;
    match commit(
        state,
        std::slice::from_ref(&request.audit_submission),
        vec![AdmittedProducer::Local(Box::new(guard))],
        Some(request),
        None,
    )
    .await?
    {
        RegisteredAuditOutcome::WatchRead(outcome) => Ok((outcome, authority)),
        _ => Err(ServiceError::internal("audit read returned a pair outcome")),
    }
}

async fn original_read(
    state: &AppState,
    request: &WatchAuditReadRequest,
) -> ServiceResult<Option<WatchAuditReadOutcome>> {
    if let Some(original) = state
        .authority_commits()
        .registered_audit_result(&request.audit_submission.event.event_id)
        .await?
    {
        if original.canonical_request
            != arkret_canonical::canonical_json_bytes(request)
                .map_err(|e| ServiceError::SchemaViolation(e.to_string()))?
        {
            return Err(ServiceError::Conflict(
                "duplicate_conflict: audit already belongs to another request".to_owned(),
            ));
        }
        let RegisteredAuditOutcome::WatchRead(outcome) = original.outcome else {
            return Err(ServiceError::Conflict(
                "duplicate_conflict: audit belongs to another operation".to_owned(),
            ));
        };
        state
            .authority_commits()
            .watch_audit_read_disclosure(request, &outcome, &state.service_core_id())
            .await?;
        return Ok(Some(outcome));
    }
    Ok(None)
}

pub(crate) async fn submit_peer_read(
    state: &AppState,
    peer: &coland_services::authority_commit::AuthenticatedPeerContext,
    request: &PeerWatchAuditReadRequest,
) -> ServiceResult<WatchAuditReadOutcome> {
    let event = &request.audit_submission.event;
    if event
        .actor_id
        .as_account_id()
        .is_none_or(|account| account.station_id != peer.source_service_id)
        || event
            .actual_signer()
            .as_account_id()
            .is_none_or(|account| account.station_id != peer.source_service_id)
    {
        return Err(ServiceError::NotFound("audit source not found".to_owned()));
    }
    if let Some(outcome) = original_read(state, &request.logical_request()).await? {
        return Ok(outcome);
    }
    request.validate().map_err(refusal)?;
    let digest =
        arkret_models_collaboration::authority_commit::authority_forward_body_digest(request)
            .map_err(refusal)?;
    let (producer, _) = super::authority_forward::resolve_forwarded_producer(
        state,
        peer,
        event,
        request.producer_device_evidence.as_ref(),
        request.producer_agent_evidence.as_ref(),
        &digest,
        chrono::Utc::now(),
    )?;
    match commit(
        state,
        std::slice::from_ref(&request.audit_submission),
        vec![producer],
        Some(&request.logical_request()),
        None,
    )
    .await?
    {
        RegisteredAuditOutcome::WatchRead(outcome) => Ok(outcome),
        _ => Err(ServiceError::internal("audit read returned a pair outcome")),
    }
}
