//! Direct Conversation admission on the governing Station.
//!
//! `contact-and-direct-conversation.md` sections 5.5 and 8.4. The founder's
//! current Station admits the caller-authored four-Event founding unit through
//! the self events union; after founding, every write to the Realm is first
//! judged by the profile admission table at the accepting cut. This module is
//! the serving side of both: it authenticates the founder's four producers,
//! signs the four Commits and relays the table's closed refusal as the
//! `{status="rejected",reason_code}` Event outcome.

use arkret_models_collaboration::authority_commit::{
    AggregateAcceptanceStatus, DirectConversationFoundingAcceptanceOutcome,
    DirectConversationFoundingFederationSubmission, DirectConversationFoundingUnitSubmission,
};
use arkret_models_collaboration::objects::direct_conversation::DirectConversationFoundingAuthorityEvidence;
use arkret_wire::{AuthorityRejectionStatus, AuthoritySubmitOutcome, Event};
use chrono::Utc;
use coland_services::identity::SessionIdentityState;
use coland_services::projection::StagedRealmBootstrap;
use coland_services::{ServiceError, ServiceResult};
use coland_storage::{
    AuthorityCommitTransaction, ConflictCode, CurrentRealmAuthority,
    DirectConversationAdmissionCut, DirectConversationFoundingCommitUnit, SelfProducerCommitGuard,
};

use super::AppState;

/// Stage the exact four caller-authored Events without making them visible.
/// The accepted PG unit remains authoritative if this rebuildable cache is
/// temporarily unable to stage (for example, during an exact retry).
fn stage_founding_projection(
    state: &AppState,
    events: &[&Event; 4],
) -> Option<StagedRealmBootstrap> {
    let operations = events
        .iter()
        .map(|event| {
            let envelope = serde_json::to_value(event).ok()?;
            let operation_id = crate::routing::events::event_log::event_operation_id(
                &envelope,
                event.event_id.as_str(),
            )?;
            arkret_event_draft::ProjectedEventOperation::from_accepted_event(
                operation_id,
                arkret_wire::OperationKind::Create,
                None,
                event,
                arkret_canonical::DigestSuite::Sha256,
            )
            .ok()
        })
        .collect::<Option<Vec<_>>>()?;
    match state.projections().stage_realm_bootstrap(&operations, true) {
        Ok(staged) => Some(staged),
        Err(error) => {
            tracing::warn!(realm_id = %events[0].realm_id, slot = error.operation_index,
                reason = %error.reason, "Direct Conversation founding projection needs durable repair");
            None
        }
    }
}

/// Reconcile process-local views only after the four-Commit unit is durable.
/// A failed cache install never changes the authority outcome; confirmed
/// Events can rebuild both views through the normal hydration path.
async fn reconcile_founding_projection(
    state: &AppState,
    realm_id: &arkret_wire::RealmId,
    staged: Option<StagedRealmBootstrap>,
) {
    let mut repair_needed = staged.is_none();
    if let Some(staged) = staged
        && let Err(error) = state.projections().install_staged_realm_bootstrap(staged)
    {
        tracing::error!(%realm_id, slot = error.operation_index, reason = %error.reason,
                "durable Direct Conversation founding projection install failed");
        repair_needed = true;
    }
    repair_needed |= state
        .projections()
        .snapshot()
        .realm_ordinary_writes_blocked(realm_id.as_str());
    match state
        .persistence()
        .hydrate_realm_directory_entry(realm_id)
        .await
    {
        Ok(Some(entry)) => state.realm_directory().upsert(entry),
        Ok(None) => {
            tracing::error!(%realm_id, "durable Direct Conversation founding is absent from directory hydration");
            repair_needed = true;
        }
        Err(error) => {
            tracing::error!(%realm_id, %error, "durable Direct Conversation directory hydration failed");
            repair_needed = true;
        }
    }
    if repair_needed {
        // In particular, recover a process that accepted the durable unit
        // before this projection path existed. The resolver must see the
        // confirmed Realm state before founding is acknowledged.
        if let Err(error) = state.hydrate().await {
            tracing::error!(%realm_id, %error, "durable Direct Conversation projection hydration failed");
            let repair_state = state.clone();
            tokio::spawn(async move {
                let mut delay = std::time::Duration::from_secs(1);
                loop {
                    match repair_state.hydrate().await {
                        Ok(()) => break,
                        Err(error) => {
                            tracing::error!(%error, "Direct Conversation projection repair failed")
                        }
                    }
                    tokio::time::sleep(delay).await;
                    delay = (delay * 2).min(std::time::Duration::from_secs(30));
                }
            });
        }
    }
}

/// The closed Event outcome for a table refusal, or the refusal as an error
/// when the code is not one of the seven mapped reasons.
pub(super) fn direct_conversation_refusal(
    code: ConflictCode,
) -> ServiceResult<AuthoritySubmitOutcome> {
    match code.direct_conversation_admission_reason() {
        Some(reason_code) => Ok(AuthoritySubmitOutcome::Rejected {
            status: AuthorityRejectionStatus::Rejected,
            reason_code: reason_code.to_owned(),
        }),
        None => Err(ServiceError::Conflict(format!(
            "{}: the Direct Conversation profile refuses this Event",
            code.as_str()
        ))),
    }
}

/// The closed outcome for a table refusal raised inside an accepting
/// transaction; any other error passes through unchanged.
pub(super) fn relay_direct_conversation_refusal(
    error: ServiceError,
) -> ServiceResult<AuthoritySubmitOutcome> {
    match error.conflict_code() {
        Some(code) if code.direct_conversation_admission_reason().is_some() => {
            direct_conversation_refusal(code)
        }
        _ => Err(error),
    }
}

/// Judge an Event this Station has no admission unit for. A Direct
/// Conversation Realm's table still answers first, in registered precedence;
/// otherwise the Event keeps its `unsupported` refusal.
pub(super) async fn refuse_unadmitted_event(
    state: &AppState,
    event: &Event,
    unsupported: ServiceError,
) -> ServiceResult<AuthoritySubmitOutcome> {
    match state
        .authority_commits()
        .direct_conversation_admission(event)
        .await?
    {
        DirectConversationAdmissionCut::Refused(code) => direct_conversation_refusal(code),
        DirectConversationAdmissionCut::NotDirectConversation
        | DirectConversationAdmissionCut::Passed => Err(unsupported),
    }
}

/// `direct_conversation_founding_unit_submission` on the self events union.
///
/// The Station never re-authors or reorders the four Events; it only verifies
/// their producers, signs the four consecutive Commits and hands the unit to
/// the one transaction that claims the founder's slot and reads the founding
/// authority at its cut.
pub(super) async fn submit_self_direct_conversation_founding(
    state: &AppState,
    session: &SessionIdentityState,
    request: DirectConversationFoundingUnitSubmission,
) -> ServiceResult<DirectConversationFoundingAcceptanceOutcome> {
    request.validate().map_err(|error| {
        ServiceError::Conflict(format!(
            "{}: {error}",
            ConflictCode::DirectConversationFoundingUnitInvalid.as_str()
        ))
    })?;
    let mut guards = Vec::with_capacity(4);
    for submitted in &request.events {
        guards.push(
            super::authority_producer_validation::verify_self_event_producer(
                state,
                session,
                &submitted.event,
            )
            .await?,
        );
    }
    let guards: [SelfProducerCommitGuard; 4] = guards
        .try_into()
        .map_err(|_| ServiceError::internal("four founding producer guards expected"))?;
    let genesis = &request.events[0].event;
    let staged =
        stage_founding_projection(state, &request.events.each_ref().map(|item| &item.event));
    let authority = coland_storage::CurrentRealmAuthority {
        realm_id: arkret_wire::RealmId::from_event_id(&genesis.event_id),
        generation: 0,
        service_id: state.service_core_id(),
        authority_ref: arkret_wire::RealmCommitAuthorityRef::GenesisOrChangeEvent(
            genesis.event_id.clone(),
        ),
        last_handoff_ref: None,
    };
    let method = arkret_wire::DidUrl::new(
        crate::routing::federation::federation_service_signature_key_id(
            state.service_did().as_str(),
        ),
    )
    .map_err(|error| ServiceError::Internal(error.to_string()))?;
    let committed_at = Utc::now();
    let unit = state
        .authority_commits()
        .prepare_direct_conversation_founding_unit(
            request.clone(),
            &authority,
            method,
            state.notary_signing_key().as_ref(),
            committed_at,
        )
        .await?;
    let (status, commits) = match state
        .authority_commits()
        .admit_self_direct_conversation_founding_unit(&unit, &guards, committed_at)
        .await?
    {
        coland_storage::DirectConversationFoundingCommitOutcome::Committed(commits) => {
            (AggregateAcceptanceStatus::Committed, commits)
        }
        coland_storage::DirectConversationFoundingCommitOutcome::Duplicate(commits) => {
            (AggregateAcceptanceStatus::Duplicate, commits)
        }
    };
    reconcile_founding_projection(state, &genesis.realm_id, staged).await;
    let outcome = DirectConversationFoundingAcceptanceOutcome {
        unit_kind: request.unit_kind,
        status,
        commits,
    };
    outcome
        .validate()
        .map_err(|error| ServiceError::Internal(error.to_string()))?;
    Ok(outcome)
}

/// Verify the source-committed founding unit before its peer-only atomic
/// materialization. The source Station's signed Commits are the sole finality;
/// the peer does not run profile admission or sign a second Commit chain.
pub(super) async fn submit_peer_direct_conversation_founding(
    state: &AppState,
    peer: &coland_services::authority_commit::AuthenticatedPeerContext,
    request: DirectConversationFoundingFederationSubmission,
) -> ServiceResult<DirectConversationFoundingAcceptanceOutcome> {
    request
        .validate()
        .map_err(|error| ServiceError::SchemaViolation(error.to_string()))?;
    let genesis = &request.committed_events[0].event_submission.event;
    let authority = CurrentRealmAuthority {
        realm_id: genesis.realm_id.clone(),
        generation: 0,
        service_id: peer.source_service_id.clone(),
        authority_ref: arkret_wire::RealmCommitAuthorityRef::GenesisOrChangeEvent(
            genesis.event_id.clone(),
        ),
        last_handoff_ref: None,
    };
    let submission = DirectConversationFoundingUnitSubmission {
        unit_kind: request.unit_kind,
        idempotency_key: arkret_wire::UuidV7::new(uuid::Uuid::now_v7())
            .map_err(|error| ServiceError::internal(error.to_string()))?,
        events: request
            .committed_events
            .each_ref()
            .map(|item| item.event_submission.clone()),
    };
    if request.committed_events.iter().any(|item| matches!(
        item.producer_signer_fact,
        Some(arkret_models_collaboration::authority_commit::HistoricalProducerSignerFact::Service(_))
    )) {
        return Err(ServiceError::protocol(
            arkret_wire::ErrorCode::SignatureInvalid,
            "Direct Conversation founding requires original Account producer sources",
        ));
    }
    let transactions = request
        .committed_events
        .each_ref()
        .map(|item| AuthorityCommitTransaction {
            expected_authority: authority.clone(),
            event: item.event_submission.event.clone(),
            commit: item.source_commit.clone(),
            producer_signer_fact: item.producer_signer_fact.clone(),
            mls_state: None,
            welcomes: Vec::new(),
            recipient_queue_capacity: 0,
        });
    let unit = DirectConversationFoundingCommitUnit {
        submission,
        transactions,
    };
    let facts = unit.facts().map_err(|error| {
        ServiceError::Conflict(format!(
            "{}: {error}",
            ConflictCode::DirectConversationFoundingUnitInvalid
        ))
    })?;
    if facts.governance_station_id != peer.source_service_id
        || facts.founder_id.as_account_id().map(|a| &a.station_id) != Some(&peer.source_service_id)
        || facts.peer_id.as_account_id().map(|a| &a.station_id) != Some(&state.service_core_id())
        || unit.transactions.iter().any(|transaction| {
            transaction
                .event
                .actor_id
                .as_account_id()
                .map(|a| &a.station_id)
                != Some(&peer.source_service_id)
                || transaction.event.executed_by.is_some()
        })
    {
        return Err(ServiceError::Conflict(format!(
            "{}: founding source, actual authors or destination do not route to the expected Stations",
            ConflictCode::DirectConversationFoundingUnitInvalid
        )));
    }
    if request.founding_authority_evidence.founding_ref().id
        != match &facts.authority_ref {
            coland_storage::DirectConversationFoundingAuthorityRef::ContactRound(id) => {
                id.to_string()
            }
            coland_storage::DirectConversationFoundingAuthorityRef::AgentProvision(id) => {
                id.to_string()
            }
        }
    {
        return Err(ServiceError::Conflict(format!(
            "{}: the founding authority evidence names another source",
            ConflictCode::DirectConversationFoundingUnitInvalid
        )));
    }
    if let DirectConversationFoundingAuthorityEvidence::Human { .. } =
        &request.founding_authority_evidence
    {
        let (participants, founder) = request
            .founding_authority_evidence
            .participants_and_founder()
            .map_err(|error| ServiceError::SchemaViolation(error.to_string()))?;
        if founder != facts.founder_id
            || !participants.contains(&facts.founder_id)
            || !participants.contains(&facts.peer_id)
        {
            return Err(ServiceError::Conflict(format!(
                "{}: the evidence and Event pair disagree",
                ConflictCode::DirectConversationFoundingUnitInvalid
            )));
        }
    }
    let mut located = crate::routing::realm_join::resolve_verified_authority_of_service(
        state,
        &facts.realm_id,
        &peer.source_service_id,
    )
    .await
    .map_err(|error| {
        ServiceError::Conflict(format!("{}: {error}", ConflictCode::TemporarilyUnavailable))
    })?;
    for (index, item) in request.committed_events.iter().enumerate() {
        let commit = &item.source_commit;
        if arkret_identity::RealmAuthorityKeyDirectory::public_key_at(
            &located.keys,
            &commit.signature.verification_method,
            commit.signature.created_at,
        )
        .is_none()
        {
            crate::routing::realm_join::insert_historical_method_key(
                state,
                &mut located.keys,
                &commit.signature.verification_method,
                commit.signature.created_at,
            )
            .await
            .map_err(|error| {
                ServiceError::Conflict(format!("{}: {error}", ConflictCode::TemporarilyUnavailable))
            })?;
        }
        let continuity = if index == 0 {
            coland_services::committed_receipt::CommitContinuity::StreamStart
        } else {
            coland_services::committed_receipt::CommitContinuity::After(
                &request.committed_events[index - 1].source_commit,
            )
        };
        coland_services::committed_receipt::verify_committed_event_receipt_with_source(
            state.persistence(),
            &item.event_submission.event,
            commit,
            continuity,
            &located.authority,
            &located.keys,
            &state.service_core_id(),
            state
                .projections()
                .realm_digest_suite(facts.realm_id.as_str()),
            item.producer_signer_fact.as_ref(),
        )
        .await?;
    }
    let staged =
        stage_founding_projection(state, &unit.transactions.each_ref().map(|item| &item.event));
    let status = state
        .authority_commits()
        .materialize_peer_direct_conversation_founding_unit(
            &unit,
            &request.founding_authority_evidence,
            &state.service_core_id(),
            crate::wire::now(),
        )
        .await?;
    reconcile_founding_projection(state, &facts.realm_id, staged).await;
    Ok(DirectConversationFoundingAcceptanceOutcome {
        unit_kind: request.unit_kind,
        status,
        commits: unit.commits(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_seven_table_reasons_are_closed_rejected_outcomes_and_others_stay_errors() {
        let mapped = [
            ConflictCode::DirectConversationBindingInvalid,
            ConflictCode::DirectConversationTerminalForbidden,
            ConflictCode::DirectConversationMemberCountInvalid,
            ConflictCode::DirectConversationThirdPartyMemberForbidden,
            ConflictCode::DirectConversationInviteForbidden,
            ConflictCode::DirectConversationRootMaskViolation,
            ConflictCode::DirectConversationParticipantAuthorityDenied,
        ];
        for code in mapped {
            let outcome = direct_conversation_refusal(code).unwrap();
            assert_eq!(
                serde_json::to_value(&outcome).unwrap(),
                serde_json::json!({"status":"rejected","reason_code":code.as_str()})
            );
            let relayed = relay_direct_conversation_refusal(ServiceError::Conflict(format!(
                "{}: refused at the accepting cut",
                code.as_str()
            )))
            .unwrap();
            assert_eq!(relayed, outcome);
        }
        for code in [
            ConflictCode::DirectConversationSpaceForbidden,
            ConflictCode::DirectConversationFoundingUnitInvalid,
            ConflictCode::DirectConversationSlotAlreadyCommitted,
            ConflictCode::CapabilityDenied,
        ] {
            assert!(direct_conversation_refusal(code).is_err());
            let error = ServiceError::Conflict(format!("{}: refused", code.as_str()));
            assert_eq!(
                relay_direct_conversation_refusal(error)
                    .unwrap_err()
                    .conflict_code(),
                Some(code)
            );
        }
    }
}
