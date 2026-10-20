//! Freeze the selected proposal before effects; acceptance and response share a CAS.
use arkret_models_collaboration::contact_operations::{
    BilateralContinuityCheckpoint, BilateralContinuityCheckpointProposal,
    ContactContinuityCheckpointStatus, ContactContinuityEvidence, ContactRoundEvidenceBundle,
    PeerContactSubmitRequestBody,
};

use super::*;
use crate::routing::identity::contact_federation as federation;

const OPERATION: &str = "ak.self.contact.command.checkpoint";
const PLAN_OPERATION: &str = "coland://internal/contact-checkpoint-plan";

pub(crate) async fn completed_request(
    state: &AppState,
    holder: &arkret_wire::AccountId,
    request: &ContactContinuityCheckpointRequestBody,
) -> Result<Option<ContactContinuityCheckpointOutcome>, AppError> {
    let actor = ActorId::account(holder.clone());
    let key = format!(
        "contact-checkpoint-result:{}",
        request.idempotency_key.as_str()
    );
    let Some(record) = state
        .jobs()
        .scoped_idempotency_record(&actor, OPERATION, &key)
        .await
        .map_err(|e| AppError::internal(e.to_string()))?
    else {
        return Ok(None);
    };
    let hash = arkret_canonical::canonical_sha256(request)
        .map_err(|e| AppError::internal(e.to_string()))?;
    if record.request_hash != hash {
        return Err(crate::app_error!(
            DuplicateConflict,
            "checkpoint retry key names different bytes"
        ));
    }
    let outcome: ContactContinuityCheckpointOutcome = serde_json::from_value(record.response_body)
        .map_err(|e| AppError::internal(e.to_string()))?;
    outcome
        .validate_for_request(holder, request)
        .map_err(|e| AppError::internal(e.to_string()))?;
    if outcome.status != ContactContinuityCheckpointStatus::Committed {
        return Err(AppError::internal("checkpoint completion is not committed"));
    }
    Ok(Some(outcome))
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CheckpointPlan {
    request: ContactContinuityCheckpointRequestBody,
    pub(crate) proposal: BilateralContinuityCheckpointProposal,
    local_checkpoint: Option<BilateralContinuityCheckpoint>,
    tail: Vec<ContactRoundEvidenceBundle>,
    delivery: Option<(DidCoreId, PeerContactSubmitRequestBody)>,
}

impl CheckpointPlan {
    pub(crate) fn outcome(
        &self,
        checkpoint: BilateralContinuityCheckpoint,
    ) -> Result<ContactContinuityCheckpointOutcome, AppError> {
        if checkpoint.core != self.proposal.core
            || checkpoint.checkpoint_digest != self.proposal.checkpoint_digest
        {
            return Err(AppError::internal(
                "checkpoint completion changed frozen core",
            ));
        }
        let mut tail = self.tail.clone();
        let first = tail
            .first_mut()
            .ok_or_else(|| AppError::internal("checkpoint has no frozen tail"))?;
        first.continuity_checkpoint = Some(checkpoint.clone());
        let outcome = ContactContinuityCheckpointOutcome {
            status: ContactContinuityCheckpointStatus::Committed,
            checkpoint_digest: checkpoint.checkpoint_digest.clone(),
            continuity_evidence: Some(ContactContinuityEvidence {
                checkpoint,
                uncompressed_tail_entries: tail,
            }),
        };
        outcome
            .validate_for_request(&self.proposal.proposer_signature.signer, &self.request)
            .map_err(|error| AppError::internal(error.to_string()))?;
        Ok(outcome)
    }

    pub(crate) fn result_record(
        &self,
        outcome: &ContactContinuityCheckpointOutcome,
    ) -> Result<coland_services::jobs::IdempotencyState, AppError> {
        if outcome.status != ContactContinuityCheckpointStatus::Committed
            || outcome.checkpoint_digest != self.proposal.checkpoint_digest
        {
            return Err(AppError::internal(
                "only the frozen committed checkpoint can be recorded",
            ));
        }
        let at = now();
        Ok(coland_services::jobs::IdempotencyState {
            authenticated_actor: ActorId::account(self.proposal.proposer_signature.signer.clone()),
            operation_id: OPERATION.into(),
            idempotency_key: format!(
                "contact-checkpoint-result:{}",
                self.request.idempotency_key.as_str()
            ),
            request_hash: arkret_canonical::canonical_sha256(&self.request)
                .map_err(|e| AppError::internal(e.to_string()))?,
            response_status: 200,
            response_body: serde_json::to_value(outcome)
                .map_err(|e| AppError::internal(e.to_string()))?,
            created_at: at,
            expires_at: at + chrono::Duration::days(30),
        })
    }

    async fn completed(
        &self,
        state: &AppState,
    ) -> Result<Option<ContactContinuityCheckpointOutcome>, AppError> {
        let outcome = completed_request(
            state,
            &self.proposal.proposer_signature.signer,
            &self.request,
        )
        .await?;
        if outcome
            .as_ref()
            .is_some_and(|outcome| outcome.checkpoint_digest != self.proposal.checkpoint_digest)
        {
            return Err(AppError::internal(
                "checkpoint completion does not bind frozen proposal",
            ));
        }
        Ok(outcome)
    }

    fn pending(&self) -> ContactContinuityCheckpointOutcome {
        ContactContinuityCheckpointOutcome {
            status: ContactContinuityCheckpointStatus::Pending,
            checkpoint_digest: self.proposal.checkpoint_digest.clone(),
            continuity_evidence: None,
        }
    }
}

pub(crate) async fn frozen_outbound_plan(
    state: &AppState,
    request: &PeerContactSubmitRequestBody,
) -> Result<CheckpointPlan, AppError> {
    let PeerContactSubmitRequestBody::ContinuityCheckpoint {
        proposal,
        idempotency_key,
        ..
    } = request
    else {
        return Err(AppError::internal(
            "checkpoint completion paired with another command",
        ));
    };
    let holder = ActorId::account(proposal.proposer_signature.signer.clone());
    let key = format!("contact-checkpoint:{}", idempotency_key.as_str());
    let stored = state
        .jobs()
        .scoped_idempotency_record(&holder, PLAN_OPERATION, &key)
        .await
        .map_err(|e| AppError::internal(e.to_string()))?
        .ok_or_else(|| AppError::internal("checkpoint command was not frozen"))?;
    let plan: CheckpointPlan = serde_json::from_value(stored.response_body)
        .map_err(|e| AppError::internal(e.to_string()))?;
    let (_, frozen) = plan
        .delivery
        .as_ref()
        .ok_or_else(|| AppError::internal("checkpoint delivery is not frozen"))?;
    let canonical = |value: &PeerContactSubmitRequestBody| {
        arkret_canonical::canonical_json_bytes(value).map_err(|e| AppError::internal(e.to_string()))
    };
    if canonical(frozen)? != canonical(request)? {
        return Err(AppError::internal(
            "checkpoint delivery differs from frozen command",
        ));
    }
    Ok(plan)
}

#[salvo::oapi::endpoint(operation_id = "ak.self.contact.command.checkpoint", tags("contacts"))]
pub(crate) async fn contact_continuity_checkpoint(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<ContactContinuityCheckpointRequestBody>,
) -> JsonResult<ContactContinuityCheckpointOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let body = body.into_inner();
    let holder = crate::routing::identity::auth_grant_dpop::authenticated_session_account_id(
        state, &session,
    )
    .await?;
    let actor = ActorId::account(holder.clone());
    let peer = body.peer.contact_actor_id();
    if peer == actor {
        return Err(AppError::param_invalid("checkpoint peer equals holder"));
    }
    // Completed responses survive independently if an older pending plan is GC'd.
    if let Some(result) = completed_request(state, &holder, &body).await? {
        return crate::json_ok(result);
    }
    let hash =
        arkret_canonical::canonical_sha256(&body).map_err(|e| AppError::internal(e.to_string()))?;
    let key = format!("contact-checkpoint:{}", body.idempotency_key.as_str());
    if state
        .jobs()
        .scoped_idempotency_record(&actor, PLAN_OPERATION, &key)
        .await
        .map_err(|e| AppError::internal(e.to_string()))?
        .is_none()
    {
        let record = state
            .contacts()
            .contact_any(&actor, &peer)
            .await
            .map_err(|e| AppError::internal(e.to_string()))?
            .ok_or_else(|| crate::app_error!(NotFound, "Contact lineage not found"))?;
        let proposal = federation::create_continuity_checkpoint_proposal(
            state,
            &record,
            holder.principal_id.as_str(),
        )?;
        let local = record
            .peer_host_id
            .as_ref()
            .is_none_or(|id| id == &state.service_core_id());
        let local_checkpoint = if local {
            Some(federation::complete_same_service_checkpoint(
                state, &proposal,
            )?)
        } else {
            None
        };
        let delivery = if local {
            None
        } else {
            let peer_id = record.peer_host_id.clone().expect("remote Station");
            let resolution = serde_json::from_value(
                record
                    .peer_service_resolution
                    .clone()
                    .ok_or_else(|| AppError::internal("checkpoint peer route unavailable"))?,
            )
            .map_err(|e| AppError::internal(format!("checkpoint peer route: {e}")))?;
            let address = arkret_models_collaboration::governance::peer_contact::PeerContactAddress::for_recipient(body.peer.clone(), resolution);
            Some((
                peer_id,
                PeerContactSubmitRequestBody::ContinuityCheckpoint {
                    idempotency_key: body.idempotency_key.clone(),
                    proposal: proposal.clone(),
                    contact_address: address,
                },
            ))
        };
        let plan = CheckpointPlan {
            request: body.clone(),
            tail: federation::checkpoint_tail(
                &record,
                &proposal.core.covered_through_contact_round_id,
            )?,
            proposal,
            local_checkpoint,
            delivery,
        };
        let at = now();
        // First-writer-wins storage freezes one exact proposal even under concurrent requests.
        state
            .jobs()
            .store_idempotency_record(coland_services::jobs::IdempotencyState {
                authenticated_actor: actor.clone(),
                operation_id: PLAN_OPERATION.into(),
                idempotency_key: key.clone(),
                request_hash: hash.clone(),
                response_status: 200,
                response_body: serde_json::to_value(plan)
                    .map_err(|e| AppError::internal(e.to_string()))?,
                created_at: at,
                expires_at: at + chrono::Duration::days(30),
            })
            .await
            .map_err(|e| AppError::internal(e.to_string()))?;
    }
    let stored = state
        .jobs()
        .scoped_idempotency_record(&actor, PLAN_OPERATION, &key)
        .await
        .map_err(|e| AppError::internal(e.to_string()))?
        .ok_or_else(|| AppError::internal("frozen checkpoint request unavailable"))?;
    if stored.request_hash != hash {
        return Err(crate::app_error!(
            DuplicateConflict,
            "checkpoint retry key names different bytes"
        ));
    }
    let plan: CheckpointPlan = serde_json::from_value(stored.response_body)
        .map_err(|e| AppError::internal(e.to_string()))?;
    if let Some(result) = plan.completed(state).await? {
        return crate::json_ok(result);
    }
    if let Some(checkpoint) = &plan.local_checkpoint {
        let outcome = plan.outcome(checkpoint.clone())?;
        federation::install_checkpoint_with_result(
            state,
            &actor,
            &peer,
            checkpoint,
            plan.result_record(&outcome)?,
        )
        .await?;
    } else if let Some((peer_id, delivery)) = &plan.delivery {
        federation::enqueue_peer_contact_carrier(state, peer_id.as_str(), delivery).await?;
    }
    crate::json_ok(
        plan.completed(state)
            .await?
            .unwrap_or_else(|| plan.pending()),
    )
}
