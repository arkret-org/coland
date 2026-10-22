use arkret_models_collaboration::agent_operations::AgentLifecycleState;
use salvo::oapi::endpoint;

use super::*;

pub(crate) mod direct;

pub(crate) use direct::{direct_binding_matches_projection, direct_pair_key};

mod contact_write;

pub(crate) use contact_write::{
    contact_assertion_signer, contact_delivery_address, contact_detached_jws,
    materialize_contact_completions, validate_request_receipt_cryptography,
    verify_contact_service_signature_bytes, verify_contact_service_signature_bytes_at,
};

fn contact_summary_diagnostic(branch: &'static str) {
    #[cfg(feature = "conformance-harness")]
    tracing::warn!(target: "conformance_harness", stage = "contact_summary", diag_branch = branch,
        "Contact summary fixed diagnostic");
    #[cfg(not(feature = "conformance-harness"))]
    let _ = branch;
}

#[endpoint(
    operation_id = "ak.self.contact.command.request",
    summary = "Prepare or commit a holder-signed Contact request",
    tags("contacts")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.contact.command.request.v1"))]
pub(crate) async fn contact_request(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<ContactOperationRequestBody>,
) -> JsonResult<ContactOperationOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    Box::pin(contact_write::request(state, &session, body.into_inner())).await
}

#[endpoint(
    operation_id = "ak.self.contact.command.respond",
    summary = "Prepare or commit a normal Contact acceptance",
    tags("contacts")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.contact.command.respond.v1"))]
pub(crate) async fn contact_respond(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<ContactAcceptRequestBody>,
) -> JsonResult<ContactOperationOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    Box::pin(contact_write::respond(state, &session, body.into_inner())).await
}

#[endpoint(
    operation_id = "ak.self.contact.command.reject",
    summary = "Prepare or commit a terminal Contact request rejection",
    tags("contacts")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.contact.command.reject.v1"))]
pub(crate) async fn contact_reject(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<ContactRejectRequestBody>,
) -> JsonResult<ContactOperationOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    Box::pin(contact_write::reject(state, &session, body.into_inner())).await
}

#[endpoint(
    operation_id = "ak.self.contact.command.scope_update",
    summary = "Prepare or commit a directional Contact scope replacement",
    tags("contacts")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.contact.command.scope_update.v1"))]
pub(crate) async fn contact_scope_update(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<ContactScopeUpdateRequestBody>,
) -> JsonResult<ContactOperationOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    Box::pin(contact_write::scope_update(
        state,
        &session,
        body.into_inner(),
    ))
    .await
}

#[endpoint(
    operation_id = "ak.self.contact.command.tombstone",
    summary = "Prepare or commit a terminal Contact tombstone",
    tags("contacts")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.contact.command.tombstone.v1"))]
pub(crate) async fn contact_tombstone(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<ContactTombstoneRequestBody>,
) -> JsonResult<ContactOperationOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    Box::pin(contact_write::tombstone(state, &session, body.into_inner())).await
}

#[endpoint(
    operation_id = "ak.self.invite_receive_policy.resource.get",
    summary = "Get the invite receive policy",
    tags("contacts")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.invite_receive_policy.resource.get.v1"))]
pub(crate) async fn get_invite_receive_policy(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<InviteReceivePolicy> {
    // Spec invite-addressing.md §5 — return the subject's private override,
    // falling back to the recommended default when none is set. Contact
    // tombstones and invite receive policy are independent state machines.
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let account_id = crate::routing::identity::auth_grant_dpop::authenticated_session_account_id(
        state, &session,
    )
    .await?;
    if account_id.station_id != state.service_core_id() {
        return Err(AppError::capability_denied(
            "invite receive policy is owned by another Station",
        ));
    }
    use arkret_models_collaboration::consent_private::*;
    let ConsentPrivateCommandOutcome::Effects(outcome) =
        crate::routing::consent_private::holder_command(
            state,
            &session,
            ConsentPrivateCommand::Effects(ConsentPrivateEffectsCommand {
                kind: ConsentPrivateEffectsCommandKind::Effects,
                body: ConsentPrivateEmptyBody {},
            }),
        )
        .await?
    else {
        return Err(AppError::internal(
            "private authority returned another command",
        ));
    };
    let policy = outcome
        .body
        .invite_receive_policy
        .map(|cell| cell.content)
        .unwrap_or_else(|| InviteReceivePolicy::spec_default(account_id));
    json_ok(policy)
}

#[endpoint(
    operation_id = "ak.self.invite_receive_policy.resource.replace",
    summary = "Replace the invite receive policy",
    tags("contacts")
)]
#[tracing::instrument(
    skip_all,
    fields(op = "ak.self.invite_receive_policy.resource.replace.v1")
)]
pub(crate) async fn set_invite_receive_policy(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<InviteReceivePolicy>,
) -> JsonResult<InviteReceivePolicy> {
    // The holder may only replace the exact authenticated Station account policy.
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let policy = body.into_inner();
    let account_id = crate::routing::identity::auth_grant_dpop::authenticated_session_account_id(
        state, &session,
    )
    .await?;
    if policy.account_id != account_id || account_id.station_id != state.service_core_id() {
        return Err(AppError::capability_denied(
            "invite_receive_policy.account_id must equal the authenticated Station account",
        ));
    }
    use arkret_models_collaboration::consent_private::*;
    let ConsentPrivateCommandOutcome::InvitePolicy(outcome) =
        crate::routing::consent_private::holder_command(
            state,
            &session,
            ConsentPrivateCommand::InvitePolicy(ConsentPrivateInvitePolicyCommand {
                kind: ConsentPrivateInvitePolicyCommandKind::InvitePolicy,
                body: policy,
            }),
        )
        .await?
    else {
        return Err(AppError::internal(
            "private authority returned another command",
        ));
    };
    let policy = outcome.body.content;
    json_ok(policy)
}

#[endpoint(
    operation_id = "ak.self.contact.read.list",
    summary = "List contacts",
    tags("contacts")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.contact.read.list.v1"))]
pub(crate) async fn list_contacts(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<ContactList> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let actor_id = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        DidCoreId::new(session.actor.clone())
            .map_err(|error| AppError::internal(format!("invalid session actor: {error}")))?,
        state.service_core_id().clone(),
    ));
    let records = state
        .contacts()
        .contacts_for_actor(&actor_id)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    let contacts = contact_list_rows(state, &actor_id, records).await?;
    json_ok(ContactList {
        contacts,
        has_more: false,
        next_cursor: None,
    })
}

fn optional_contact_event_ref(value: &Option<EventId>) -> Option<EventId> {
    value.clone()
}
fn contact_peer_endpoint(
    record: &ContactRecord,
    peer: &arkret_wire::ActorId,
) -> Option<arkret_models_collaboration::contact_operations::ContactPeerEndpoint> {
    use arkret_models_collaboration::contact_operations::ContactPeerEndpoint;
    let account = peer.as_account_id()?;
    let bundle = record.contact_round_evidence.as_ref()?;
    if record.contact_round_id.as_ref() != Some(&bundle.contact_round_id) {
        return None;
    }
    if let Some(response) = &bundle.normal_response_receipt {
        // The response is authored by the request's peer (the target).
        if response.request_receipt.core.peer.contact_actor_id() == *peer
            && response.issuer_id == account.station_id
            && record.response_event_ref.as_ref() == Some(&response.response_event_ref)
            && response.contact_round_id == bundle.contact_round_id
        {
            return ContactPeerEndpoint::from_verified_producer(
                account,
                response.response_event_ref.clone(),
                &response.producer_signer,
            )
            .ok();
        }
    }
    let receipts = bundle
        .request_receipts
        .iter()
        .filter(|receipt| {
            receipt.core.holder.contact_actor_id() == *peer
                && receipt.core.issuer_id == account.station_id
                && match &bundle.contact_round {
                    arkret_models_collaboration::contact_operations::ContactRound::Normal {
                        request_event_ref,
                        ..
                    } => *request_event_ref == receipt.core.request_event_ref,
                    arkret_models_collaboration::contact_operations::ContactRound::Glare {
                        requests,
                        ..
                    } => requests
                        .iter()
                        .any(|request| request.request_event_ref == receipt.core.request_event_ref),
                }
        })
        .collect::<Vec<_>>();
    if receipts.len() != 1 {
        return None;
    }
    ContactPeerEndpoint::from_verified_producer(
        account,
        receipts[0].core.request_event_ref.clone(),
        &receipts[0].core.producer_signer,
    )
    .ok()
}

async fn contact_list_rows(
    state: &AppState,
    actor: &arkret_wire::ActorId,
    records: Vec<ContactRecord>,
) -> Result<Vec<ContactListRow>, AppError> {
    let mut rows: BTreeMap<String, ContactListRow> = BTreeMap::new();
    let mut selected = BTreeMap::<String, (ContactState, chrono::DateTime<chrono::Utc>)>::new();
    let mut records = records;
    records.sort_by(|left, right| {
        left.created_at
            .cmp(&right.created_at)
            .then_with(|| left.contact_round_id.cmp(&right.contact_round_id))
    });
    for record in records {
        let peer = if record.requester_id == *actor {
            record.target_id.clone()
        } else {
            record.requester_id.clone()
        };
        let row_state = match directional_contact_state(actor, &record) {
            Some(state) => state,
            None => continue,
        };
        let peer_model = if let Some(agent) = state
            .agent_pairings()
            .agent(peer.signing_principal_id().as_str())
            .await
            .map_err(|error| AppError::internal(error.to_string()))?
        {
            ContactPeer::Agent {
                actor_id: peer.clone(),
                controller_account_id: arkret_wire::AccountId::new(
                    arkret_identifiers::DidCoreId::new(agent.controller_principal_id)
                        .expect("stored Agent controller DID is validated"),
                    peer.as_account_id()
                        .ok_or_else(|| {
                            AppError::internal("stored Contact Agent is not an Account")
                        })?
                        .station_id
                        .clone(),
                ),
            }
        } else {
            ContactPeer::Human {
                account_id: peer.as_account_id().cloned().ok_or_else(|| {
                    AppError::internal("stored human Contact peer is not an account actor")
                })?,
            }
        };
        let request_message = if row_state == ContactState::PendingIncoming {
            let request_event_ref = record.request_event_ref.as_ref().ok_or_else(|| {
                AppError::internal("pending incoming Contact has no request Event reference")
            })?;
            if !record
                .request_receipts
                .iter()
                .any(|receipt| receipt.core.request_event_ref == *request_event_ref)
            {
                return Err(AppError::internal(
                    "pending incoming Contact has no verified request receipt",
                ));
            }
            record.message.clone()
        } else {
            None
        };
        let next_prepare_input = if row_state == ContactState::Accepted {
            let contact_round_id = record
                .contact_round_id
                .as_ref()
                .ok_or_else(|| AppError::internal("accepted Contact has no contact_round_id"))?;
            // The holder's own direction: its committed head and that head's
            // confirmed version (section 3 founding edge included).
            let (predecessor, current_version) =
                contact_write::local_direction_current(state, &record, actor)
                    .await?
                    .ok_or_else(|| {
                        AppError::internal("accepted Contact has no holder-local lineage head")
                    })?;
            Some(ContactNextPrepareInput {
                contact_round_id: contact_round_id.clone(),
                version: current_version.checked_add(1).ok_or_else(|| {
                    AppError::internal("accepted Contact lineage version overflow")
                })?,
                predecessor_event_ref: predecessor,
            })
        } else {
            None
        };
        let peer_endpoint = if row_state == ContactState::Accepted
            && matches!(peer_model, ContactPeer::Human { .. })
        {
            // Reverify the selected durable round before projecting its peer
            // producer. Failure omits a selector instead of guessing a device.
            match Box::pin(contact_write::verify_stored_contact_evidence_for_read(
                state, &record,
            ))
            .await
            {
                Ok(()) => contact_peer_endpoint(&record, &peer),
                Err(error) => {
                    tracing::debug!(%error, "stored Contact peer endpoint evidence unavailable");
                    None
                }
            }
        } else {
            None
        };
        let candidate = ContactListRow {
            peer: peer_model,
            state: row_state,
            request_event_ref: optional_contact_event_ref(&record.request_event_ref),
            request_message,
            response_event_ref: optional_contact_event_ref(&record.response_event_ref),
            tombstone_event_ref: optional_contact_event_ref(&record.tombstone_event_ref),
            next_prepare_input,
            granted_to_peer_scopes: if record.requester_id == *actor {
                &record.granted_to_target_scopes
            } else {
                &record.granted_to_requester_scopes
            }
            .iter()
            .filter_map(|scope| contact_scope_model(scope))
            .collect(),
            granted_by_peer_scopes: if record.requester_id == *actor {
                &record.granted_to_requester_scopes
            } else {
                &record.granted_to_target_scopes
            }
            .iter()
            .filter_map(|scope| contact_scope_model(scope))
            .collect(),
            bidirectional_scopes: Vec::new(),
            effective_scopes: None,
            direct_conversation: None,
            contact_agent_projections: Vec::new(),
            peer_endpoint,
        };
        let candidate_order = (row_state, record.updated_at);
        if selected
            .get(&peer.to_string())
            .is_none_or(|current| contact_candidate_replaces(*current, candidate_order))
        {
            selected.insert(peer.to_string(), candidate_order);
            rows.insert(peer.to_string(), candidate);
        }
    }
    let mut out = Vec::with_capacity(rows.len());
    for mut row in rows.into_values() {
        row.bidirectional_scopes =
            intersection(&row.granted_to_peer_scopes, &row.granted_by_peer_scopes);
        row.effective_scopes = Some(row.bidirectional_scopes.clone());
        if let Ok(pair_key) = direct_pair_key(state, actor, &row.peer.contact_actor_id())
            .inspect_err(|_| {
                contact_summary_diagnostic("pair_key_failed");
            })
            && let Some(facts) = state
                .event_queries()
                .direct_conversation_durable_state(state.config().trust_domain.as_str(), &pair_key)
                .await
                .map_err(|error| {
                    contact_summary_diagnostic("durable_lookup_failed");
                    AppError::internal(format!("direct durable-state lookup failed: {error}"))
                })?
            && let Some(current) = facts.binding.as_ref()
        {
            let binding = super::durable_binding_record(current)?;
            let summary_state = if direct_binding_matches_projection(state, &binding) {
                contact_summary_diagnostic("found");
                DirectConversationSummaryState::Found
            } else {
                contact_summary_diagnostic("suspended");
                DirectConversationSummaryState::Suspended
            };
            row.direct_conversation = Some(direct_summary(binding, summary_state));
        }
        out.push(row);
    }
    let mut agent_peers = BTreeSet::new();
    let mut agents_by_controller = BTreeMap::<String, Vec<ContactAgentProjection>>::new();
    for row in &out {
        let can_receive_direct_messages = row.state == ContactState::Accepted
            && row.effective_scopes.as_ref().is_some_and(|scopes| {
                scopes.contains(
                    &arkret_models_collaboration::contact_operations::ContactScope::DirectMessage,
                )
            });
        if !can_receive_direct_messages {
            continue;
        }
        let ContactPeer::Agent {
            actor_id,
            controller_account_id,
        } = &row.peer
        else {
            continue;
        };
        let Some(record) = state
            .agent_pairings()
            .agent(actor_id.signing_principal_id().as_str())
            .await
            .map_err(|error| AppError::internal(error.to_string()))?
        else {
            continue;
        };
        if record.state != AgentLifecycleState::Active {
            continue;
        }
        if record.controller_principal_id != controller_account_id.principal_id.as_str() {
            continue;
        }
        let controller_actor = arkret_wire::ActorId::account(controller_account_id.clone());
        if &controller_actor == actor {
            continue;
        }
        let display_name = record
            .display_name
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned);
        let agent_slug = record
            .agent_slug
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned);
        let avatar_blob_ref = record
            .avatar_blob_ref
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .and_then(|value| BlobRef::new(value.to_owned()).ok());
        agent_peers.insert(actor_id.to_string());
        agents_by_controller
            .entry(controller_actor.to_string())
            .or_default()
            .push(ContactAgentProjection {
                actor_id: actor_id.clone(),
                controller_account_id: controller_account_id.clone(),
                display_name,
                agent_slug,
                avatar_blob_ref,
                direct_conversation: row.direct_conversation.clone(),
            });
    }
    out.retain(|row| !agent_peers.contains(&row.peer.contact_actor_id().to_string()));
    for row in &mut out {
        row.contact_agent_projections = agents_by_controller
            .remove(&row.peer.contact_actor_id().to_string())
            .unwrap_or_default();
        row.contact_agent_projections.sort_by_key(|projection| {
            projection
                .display_name
                .clone()
                .unwrap_or_else(|| projection.actor_id.to_string())
        });
    }
    out.sort_by(|left, right| {
        left.peer
            .contact_actor_id()
            .cmp(&right.peer.contact_actor_id())
    });
    Ok(out)
}

/// Map a stored contact transition status to its actor-relative [`ContactState`].
///
/// Returns `None` for an unrecognized stored status. `status` is written
/// by the server-side contact transition (never request-controlled), so an
/// unknown value implies a migration / partial-write / writer bug; read
/// paths fail soft (skip the row) and write outcomes surface an internal
/// error rather than panicking and taking down the whole endpoint.
fn directional_contact_state(
    actor: &arkret_wire::ActorId,
    record: &ContactRecord,
) -> Option<ContactState> {
    Some(match record.status.as_str() {
        "pending" if &record.requester_id == actor => ContactState::PendingOutgoing,
        "pending" if !record.pending_incoming_admitted => return None,
        "pending" => ContactState::PendingIncoming,
        "accepted" => ContactState::Accepted,
        "rejected" => ContactState::Rejected,
        "tombstoned" => ContactState::Tombstoned,
        other => {
            tracing::warn!(
                stored_status = %other,
                "skipping contact row with unrecognized stored state"
            );
            return None;
        }
    })
}

fn contact_state_rank(state: &ContactState) -> u8 {
    match state {
        ContactState::Accepted => 5,
        // During incomplete glare the holder's own outstanding proposal is
        // still the only authorable slot.  Never replace it with the mirrored
        // incoming request merely because both directional rows are present.
        ContactState::PendingOutgoing => 4,
        ContactState::PendingIncoming => 3,
        ContactState::Rejected => 2,
        ContactState::Expired => 2,
        ContactState::Tombstoned => 1,
    }
}

fn contact_candidate_replaces(
    current: (ContactState, chrono::DateTime<chrono::Utc>),
    candidate: (ContactState, chrono::DateTime<chrono::Utc>),
) -> bool {
    match (current.0, candidate.0) {
        (ContactState::PendingOutgoing, ContactState::PendingIncoming) => false,
        (ContactState::PendingIncoming, ContactState::PendingOutgoing) => true,
        _ => {
            candidate.1 > current.1
                || (candidate.1 == current.1
                    && contact_state_rank(&candidate.0) > contact_state_rank(&current.0))
        }
    }
}

fn contact_scope_wire(scope: &str) -> String {
    scope.to_owned()
}

fn contact_scope_model(
    scope: &str,
) -> Option<arkret_models_collaboration::contact_operations::ContactScope> {
    serde_json::from_value(Value::String(scope.to_owned())).ok()
}

fn intersection(
    left: &[arkret_models_collaboration::contact_operations::ContactScope],
    right: &[arkret_models_collaboration::contact_operations::ContactScope],
) -> Vec<arkret_models_collaboration::contact_operations::ContactScope> {
    let right = right.iter().collect::<BTreeSet<_>>();
    left.iter()
        .filter(|scope| right.contains(scope))
        .cloned()
        .collect()
}

pub(crate) async fn accepted_contact_for_pair(
    state: &AppState,
    actor: &arkret_wire::ActorId,
    peer: &arkret_wire::ActorId,
    scope: &str,
) -> Result<Option<ContactRecord>, AppError> {
    let mut records = Vec::new();
    for (requester_id, target_id) in [(actor, peer), (peer, actor)] {
        if let Some(contact) = state
            .contacts()
            .contact_any(requester_id, target_id)
            .await
            .map_err(|error| AppError::internal(error.to_string()))?
        {
            records.push(contact);
        }
    }
    let current = records.into_iter().max_by(|left, right| {
        left.updated_at
            .cmp(&right.updated_at)
            // Equal-time terminal/non-accepted evidence must fail closed over
            // an accepted mirror; a later recontact has a later accepted_at.
            .then_with(|| (left.status != "accepted").cmp(&(right.status != "accepted")))
    });
    Ok(current.filter(|contact| {
        contact.status == "accepted"
            && contact_has_scope_for_both(contact, scope)
            && accepted_contact_has_fact_refs(contact)
    }))
}

pub(super) fn contact_has_scope_for_both(contact: &ContactRecord, scope: &str) -> bool {
    let scope = contact_scope_wire(scope);
    contact
        .granted_to_target_scopes
        .iter()
        .any(|candidate| contact_scope_wire(candidate) == scope)
        && contact
            .granted_to_requester_scopes
            .iter()
            .any(|candidate| contact_scope_wire(candidate) == scope)
}

pub(super) fn accepted_contact_has_fact_refs(contact: &ContactRecord) -> bool {
    if let Some(bundle) = contact.contact_round_evidence.as_ref()
        && matches!(
            &bundle.contact_round,
            arkret_models_collaboration::contact_operations::ContactRound::Glare { .. }
        )
    {
        return bundle.request_receipts.len() == 2
            && bundle.glare_concurrency_attestations.is_some()
            && bundle.current_proofs.len() == 2
            && contact.tombstone_event_ref.is_none();
    }
    contact
        .request_event_ref
        .as_ref()
        .map(EventId::as_str)
        .is_some_and(valid_contact_event_ref)
        && contact
            .response_event_ref
            .as_ref()
            .map(EventId::as_str)
            .is_some_and(valid_contact_event_ref)
        && contact.tombstone_event_ref.is_none()
}

fn valid_contact_event_ref(event_ref: &str) -> bool {
    EventId::new(event_ref.to_owned()).is_ok()
}

pub(crate) fn direct_resolve_precondition(reason: &'static str, message: &'static str) -> AppError {
    contact_failed_precondition(reason, message)
}

fn contact_failed_precondition(reason: &'static str, message: &'static str) -> AppError {
    crate::app_error!(FailedPrecondition, message).with_rejection_code(reason)
}

fn direct_summary(
    binding: DirectConversationBindingRecord,
    state: DirectConversationSummaryState,
) -> DirectConversationSummary {
    DirectConversationSummary {
        realm_id: RealmId::new(binding.realm_id).expect("direct conversation realm id is valid"),
        main_strand_id: StrandId::new(binding.main_strand_id)
            .expect("direct conversation strand id is valid"),
        binding_event_ref: EventId::new(binding.binding_event_ref)
            .expect("direct conversation event id is valid"),
        state,
    }
}
