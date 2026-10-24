use super::*;

/// Renew only this Station's attestations, using the accepted directional
/// heads rather than extending a cached proof's lifetime. Foreign expired
/// evidence must be refreshed by its issuer, never signed on its behalf.
pub(crate) async fn fresh_direct_contact_evidence(
    state: &AppState,
    record: &ContactRecord,
) -> Result<
    Option<arkret_models_collaboration::contact_operations::ContactRoundEvidenceBundle>,
    AppError,
> {
    if record.status != "accepted" {
        return Ok(None);
    }
    let incomplete = record.current_state.initial_identity.is_none()
        || record.current_state.round_basis.is_none()
        || record.current_state.directions.len() != 2;
    if incomplete {
        if let Some(local) = record.current_state.directions.iter().find(|d| {
            d.head_operation.holder().delivery_station_id().as_str() == state.service_id()
        }) {
            crate::routing::identity::contact_federation::request_remote_contact_current(
                state,
                local.head_operation.holder(),
                local.head_operation.peer(),
                &record.current_state,
            )
            .await?;
        }
        return Ok(None);
    }
    let mut updated = record.clone();
    let at = now();
    for direction in record.current_state.directions.iter() {
        let holder = direction.head_operation.holder();
        let op = &direction.head_operation;
        let original_digest = arkret_wire::Hash::new(
            arkret_canonical::canonical_sha256(op)
                .map_err(|e| AppError::internal(e.to_string()))?,
        )
        .map_err(|e| AppError::internal(e.to_string()))?;
        if record
            .request_slot_states
            .iter()
            .find(|slot| slot.owner_id == holder.contact_actor_id())
            .is_none_or(|slot| {
                slot.version != op.version()
                    || slot.head_event_ref != op.event().event_id
                    || slot.operation_digest.as_ref() != Some(&original_digest)
            })
        {
            if holder.delivery_station_id().as_str() != state.service_id() {
                crate::routing::identity::contact_federation::request_remote_contact_current(
                    state,
                    op.peer(),
                    holder,
                    &record.current_state,
                )
                .await?;
            }
            return Ok(None);
        }

        if holder.delivery_station_id().as_str() == state.service_id() {
            let proof =
                crate::routing::identity::contact_federation::refresh_local_contact_direction(
                    state,
                    &record.current_state,
                    holder,
                )
                .await?;
            updated
                .current_state
                .directions
                .iter_mut()
                .find(|d| d.head_operation.holder() == holder)
                .expect("direction exists")
                .current_proof = Some(proof);
        } else if direction
            .current_proof
            .as_ref()
            .is_none_or(|p| p.cache_expires_at <= at)
        {
            crate::routing::identity::contact_federation::request_remote_contact_current(
                state,
                direction.head_operation.peer(),
                holder,
                &record.current_state,
            )
            .await?;
            return Ok(None);
        }
    }
    let Ok(bundle) = updated.current_state.evidence_bundle() else {
        return Ok(None);
    };
    crate::routing::identity::contact_federation::verify_contact_bundle(state, &bundle).await?;
    if bundle.current_proofs.iter().any(|proof|proof.contact_round_id.as_ref()!=Some(&bundle.contact_round_id) || proof.closed_round.as_ref().is_some_and(|c|c.contact_round_id==bundle.contact_round_id) || !proof.scope_instances.iter().any(|i|i.contact_scope==arkret_models_collaboration::contact_operations::ContactScope::DirectMessage)) {return Ok(None);}
    updated.contact_round_evidence = Some(bundle.clone());
    updated.updated_at = now().max(record.updated_at + chrono::Duration::microseconds(1));
    if !state
        .contacts()
        .save_contact_if_updated_at(record.updated_at, updated)
        .await
        .map_err(|e| AppError::internal(e.to_string()))?
    {
        return Ok(None);
    }
    Ok(Some(bundle))
}

pub(crate) fn direct_pair_key(
    state: &AppState,
    left: &arkret_wire::ActorId,
    right: &arkret_wire::ActorId,
) -> Result<String, AppError> {
    let trust_domain = state.config().trust_domain.clone();
    let left = direct_pair_key_participant(left);
    let right = direct_pair_key_participant(right);
    arkret_models_collaboration::objects::direct_conversation::direct_conversation_pair_key(
        trust_domain,
        left,
        right,
    )
    .map(|pair_key| pair_key.into_string())
    .map_err(|error| AppError::internal(format!("direct pair key construction failed: {error}")))
}

pub(super) fn direct_pair_key_participant(
    identity: &arkret_wire::ActorId,
) -> arkret_models_collaboration::objects::direct_conversation::DirectConversationPairKeyParticipant
{
    arkret_models_collaboration::objects::direct_conversation::DirectConversationPairKeyParticipant::unmapped(
        identity.clone(),
    )
}

pub(crate) fn direct_binding_matches_projection(
    state: &AppState,
    binding: &DirectConversationBindingRecord,
) -> bool {
    if binding.participants_unordered.len() != 2 {
        return false;
    }
    let projection = state.projections().snapshot();
    if !projection.realm_is_direct_conversation(&binding.realm_id)
        || projection.realm_is_destroyed(&binding.realm_id)
        || projection.realm_is_tombstoned(&binding.realm_id)
    {
        return false;
    }
    let active_members: BTreeSet<_> = projection
        .members_of_realm(&binding.realm_id)
        .into_iter()
        .map(|membership| membership.member.as_str())
        .collect();
    let participants: BTreeSet<_> = binding
        .participants_unordered
        .iter()
        .map(String::as_str)
        .collect();
    if active_members != participants {
        return false;
    }
    projection
        .strands
        .get(&binding.main_strand_id)
        .is_some_and(|strand| {
            strand.realm_id == binding.realm_id
                && strand.scope_circle_id.is_none()
                && strand.state.as_str() == "active"
                && strand
                    .tracks
                    .get(arkret_models_collaboration::objects::profiles::STRAND_TRACK_NAME_DISCUSSION)
                    .is_some_and(|discussion| {
                        discussion.enabled != Some(false) && discussion.is_primary == Some(true)
                    })
        })
}

/// Derive the founding authority from an accepted Contact record.
///
/// Normal branch: the founder is the **responder**, i.e. the participant that is not the request
/// issuer. This is normative, not a coin flip. The authority is lit up by the responder's
/// `normal_response_acceptance_receipt`, which proves the responder was online at the moment the
/// authority came into existence; the requester_id may have gone offline days earlier. Base v1
/// defines no fallback, so naming the possibly-absent party would leave the pair unable to ever
/// create the conversation.
pub(crate) fn direct_founding_authority_from_contact(
    record: &ContactRecord,
) -> Result<
    arkret_models_collaboration::objects::direct_conversation::DirectConversationFoundingAuthority,
    &'static str,
> {
    use arkret_models_collaboration::contact_operations::ContactRound;
    use arkret_models_collaboration::objects::direct_conversation::DirectConversationFoundingAuthority as Authority;
    let initial = record
        .current_state
        .initial_identity
        .as_ref()
        .ok_or("direct_conversation_founding_authority_unavailable")?;
    initial
        .validate_shape()
        .map_err(|_| "direct_conversation_founding_authority_unavailable")?;
    let request_ref = match &initial.round.contact_round {
        ContactRound::Normal {
            request_event_ref, ..
        } => request_event_ref,
        ContactRound::Glare { requests, .. } => &requests[0].request_event_ref,
    };
    let author = initial
        .round
        .request_receipts
        .iter()
        .find(|r| &r.core.request_event_ref == request_ref)
        .map(|r| r.core.holder.contact_actor_id())
        .ok_or("direct_conversation_founding_authority_unavailable")?;
    Ok(match &initial.round.contact_round {
        ContactRound::Normal { .. } => Authority::Normal {
            request_author_actor_id: author,
        },
        ContactRound::Glare { .. } => Authority::Glare {
            first_request_author_actor_id: author,
        },
    })
}

/// Which participant may author the founding unit for this pair, if it can be determined now.
///
/// Returns `None` when the authority cannot be verified, so the caller reports
/// `temporarily_unavailable` rather than inventing an answer.
pub(crate) async fn direct_founder_for_pair(
    state: &AppState,
    actor: &arkret_wire::ActorId,
    peer: &arkret_wire::ActorId,
    contact: Option<&ContactRecord>,
    agent: bool,
) -> Result<Option<String>, AppError> {
    use arkret_models_collaboration::objects::direct_conversation::{
        DirectConversationFoundingAuthority, direct_conversation_founder,
    };

    let authority = if agent {
        // controller-to-own-Agent has no Contact round; the founder is fixed to the controller so
        // an Agent runtime key never needs Direct Conversation founding scope.
        let controller = if state
            .agent_pairings()
            .agent(peer.signing_principal_id().as_str())
            .await
            .map_err(|error| AppError::internal(format!("Agent lookup failed: {error}")))?
            .is_some()
        {
            actor
        } else {
            peer
        };
        DirectConversationFoundingAuthority::ControllerOwnedAgent {
            controller_actor_id: controller.clone(),
        }
    } else {
        let Some(record) = contact else {
            return Ok(None);
        };
        match direct_founding_authority_from_contact(record) {
            Ok(authority) => authority,
            Err(_) => return Ok(None),
        }
    };

    Ok(
        direct_conversation_founder([actor.clone(), peer.clone()], &authority)
            .ok()
            .map(|founder| founder.to_string()),
    )
}
