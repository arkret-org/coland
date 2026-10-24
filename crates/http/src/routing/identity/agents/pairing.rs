use salvo::oapi::endpoint;

use super::*;

#[endpoint(
    operation_id = "ak.open.agent_pairing.read.resolve",
    summary = "Resolve an agent pairing bootstrap",
    tags("agent_pairing")
)]
#[tracing::instrument(skip_all, fields(op = "ak.open.agent_pairing.read.resolve.v1"))]
pub(super) async fn resolve_agent_pairing(
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AgentPairingBootstrap> {
    if agent_pairing_token_appears_in_url(req) {
        return Err(AppError::schema_violation(
            "pairing_token must be sent in the JSON body, never in URL path or query",
        ));
    }
    let state = depot.get_typed::<AppState>().expect("state injected");
    let body = req
        .parse_json::<AgentPairingResolveRequestBody>()
        .await
        .map_err(|_| AppError::json_invalid("invalid agent pairing resolve request body"))?;
    let pairing_token = body.pairing_token.trim();
    if !is_agent_pairing_token_shape(pairing_token) {
        return Err(agent_pairing_not_found());
    }
    let token = decode_agent_pairing_token(pairing_token).ok_or_else(agent_pairing_not_found)?;
    let pairing_request_id = token
        .get("r")
        .or_else(|| token.get("pairing_request_id"))
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(agent_pairing_not_found)?;
    let pairing_code = token
        .get("c")
        .or_else(|| token.get("pairing_code"))
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(agent_pairing_not_found)?;
    let record = lookup_pairing_record(state, pairing_request_id, pairing_code, None).await?;
    ensure_pairing_request_open(&record).map_err(|_| agent_pairing_not_found())?;
    let agent_id = record.id.as_str();
    let pairing_expires_at = required_pairing_expires_at(&record)?;
    let controller_account_id =
        crate::routing::identity::agent_pcr::agent_controller_account(state, &record).await?;
    let runtime_identity = pairing_runtime_identity(
        &record.controller_authorization_ref,
        controller_account_id,
        pairing_request_id,
    )?;
    let bootstrap = AgentPairingBootstrap {
        runtime_identity: Some(runtime_identity),
        arkret_base_url: state
            .config()
            .public_base_url
            .trim_end_matches('/')
            .to_owned(),
        service_id: arkret_identifiers::DidCoreId::new(state.service_id().clone()).map_err(
            |error| AppError::internal(format!("configured service_id invalid: {error}")),
        )?,
        agent_id: arkret_wire::DidCoreId::new(agent_id)
            .map_err(|error| AppError::internal(format!("agent principal DID invalid: {error}")))?,
        pairing_request_id: arkret_wire::OpaqueLocalId::new(pairing_request_id.to_owned())
            .map_err(|error| {
                AppError::internal(format!("stored pairing request id invalid: {error}"))
            })?,
        pairing_code: pairing_code.to_owned(),
        pairing_expires_at,
    };
    bootstrap
        .validated_runtime_identity()
        .map_err(AppError::internal)?;
    json_ok(bootstrap)
}

fn pairing_runtime_identity(
    controller_authorization_ref: &arkret_wire::DidUrl,
    controller_account_id: arkret_wire::AccountId,
    pairing_request_id: &str,
) -> Result<arkret_models_collaboration::agent_operations::AgentPairingRuntimeIdentity, AppError> {
    // The accepted controller delegation retains the complete Agent DID; its
    // stable identity core alone cannot recover the DID method's locator.
    let agent_did = arkret_identity::verification_method_did(controller_authorization_ref.as_str())
        .map_err(|error| {
            AppError::internal(format!("invalid Agent controller delegation: {error}"))
        })?;
    let digest = arkret_canonical::sha256_digest(pairing_request_id.as_bytes());
    let verification_method = arkret_wire::DidUrl::new(format!(
        "{}#runtime-{}",
        agent_did.as_str(),
        digest.trim_start_matches("sha256:")
    ))
    .map_err(|error| AppError::internal(format!("invalid pairing runtime DID URL: {error}")))?;
    Ok(
        arkret_models_collaboration::agent_operations::AgentPairingRuntimeIdentity {
            controller_account_id,
            verification_method,
        },
    )
}

#[endpoint(
    operation_id = "ak.open.agent_pairing.command.submit_runtime_key_request",
    summary = "Submit an agent runtime key request",
    tags("agent_pairing")
)]
#[tracing::instrument(
    skip_all,
    fields(op = "ak.open.agent_pairing.command.submit_runtime_key_request.v1")
)]
pub(super) async fn submit_agent_runtime_key_request(
    body: JsonBody<AgentRuntimeApprovalRequestBody>,
    depot: &mut Depot,
) -> JsonResult<AgentRuntimeApprovalResponseBody> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let body = body.into_inner();
    body.validate()
        .map_err(|error| AppError::schema_violation(error.to_string()))?;
    let pairing_code = body.pairing_code.trim();
    if pairing_code.is_empty() {
        return Err(AppError::param_invalid("pairing_code is required"));
    }
    let agent_id = body.agent_id.as_str();
    validate_agent_id(agent_id)?;
    if body.verification_method.trim().is_empty() {
        return Err(AppError::param_invalid("verification_method is required"));
    }
    if verification_method_principal(&body.verification_method)
        .is_none_or(|principal| principal.as_str() != agent_id)
    {
        return Err(AppError::param_invalid(
            "verification_method DID must project to agent_id",
        ));
    }
    let agent_record = lookup_pairing_record(
        state,
        &body.pairing_request_id,
        pairing_code,
        Some(agent_id),
    )
    .await?;
    ensure_pairing_request_open(&agent_record)?;
    ensure_pairing_request_id_matches(&agent_record, &body.pairing_request_id)?;
    let proof_verified_at = chrono::Utc::now();
    verify_runtime_approval_proof_of_possession(
        &body,
        &agent_record,
        agent_id,
        state.service_id(),
        proof_verified_at,
    )?;
    let agent_id = arkret_wire::DidCoreId::new(agent_id.to_owned())
        .map_err(|error| AppError::param_invalid(format!("agent_id invalid: {error}")))?;
    let public_key_digest = arkret_signatures::agent::validate_agent_runtime_public_key(
        &body.public_key,
        &body.verification_method,
    )
    .map_err(|error| AppError::param_invalid(format!("public_key invalid: {error}")))?
    .public_key_digest;
    let runtime_attestation = runtime_attestation_value(body.runtime_attestation.as_ref())?;
    let attestation_digest =
        arkret_signatures::agent::agent_runtime_attestation_digest(runtime_attestation.as_ref())
            .map_err(|error| {
                AppError::param_invalid(format!("runtime_attestation invalid: {error}"))
            })?;
    let binding_digest = arkret_signatures::agent::agent_runtime_key_binding_digest_from_digests(
        &agent_id,
        &body.pairing_request_id,
        &body.verification_method,
        &public_key_digest,
        &attestation_digest,
    )
    .map_err(|error| AppError::param_invalid(format!("runtime key binding invalid: {error}")))?;
    let existing_binding = agent_record.runtime_key_binding_digest.as_deref();
    if existing_binding.is_some_and(|existing| existing != binding_digest.as_str()) {
        return Err(crate::app_error!(
            Conflict,
            "a different runtime key binding is already pending for this pairing request",
        )
        .with_reason_code("agent_runtime_request_conflict"));
    }

    let controller_principal_id = agent_record.controller_principal_id.clone();
    let account = state
        .identities()
        .find_account_by_actor(coland_services::identity::FindAccountByActorQuery {
            account_id: arkret_wire::AccountId::new(
                arkret_wire::DidCoreId::new(controller_principal_id.clone()).map_err(|error| {
                    AppError::internal(format!("controller account id is invalid: {error}"))
                })?,
                state.service_core_id().clone(),
            ),
        })
        .await
        .map_err(|error| AppError::internal(format!("controller account lookup failed: {error}")))?
        .ok_or_else(|| AppError::internal("controller account is missing"))?;
    let proposed_approval_request_id =
        agent_record.approval_request_id.clone().unwrap_or_else(|| {
            arkret_wire::OpaqueLocalId::new(format!(
                "agent_runtime_approval:{}",
                uuid::Uuid::now_v7()
            ))
            .expect("generated approval request id must be valid")
        });
    let proposed_notification_id = agent_record
        .approval_notification_id
        .map(|id| ids::format_typed_uuid("notification", &id))
        .unwrap_or_else(|| ids::generate("notification"));
    let proposed_requested_at = agent_record
        .approval_requested_at
        .unwrap_or_else(chrono::Utc::now);
    let expires_at = required_pairing_expires_at(&agent_record)?;
    let write = coland_services::identity::StoreAgentRuntimeApprovalCommand {
        agent_id: agent_id.to_string(),
        pairing_request_id: body.pairing_request_id.clone(),
        approval_request_id: proposed_approval_request_id.clone(),
        approval_notification_id: proposed_notification_id.clone(),
        approval_requested_at: proposed_requested_at,
        proof_verified_at,
        controller_account_pk: account.account_pk,
        recipient_id: state.service_id().clone(),
        runtime_key_binding_digest: binding_digest.as_str().to_owned(),
        runtime_public_key_digest: public_key_digest.as_str().to_owned(),
        runtime_attestation_digest: attestation_digest.as_str().to_owned(),
        runtime_key_request: body.clone(),
    };
    let stored = state
        .agent_pairings()
        .store_runtime_approval(&write)
        .await
        .map_err(|err| AppError::internal(format!("runtime approval request save failed: {err}")))?
        .ok_or_else(|| {
            crate::app_error!(
                Conflict,
                "a different runtime key binding is already pending for this pairing request",
            )
            .with_reason_code("agent_runtime_request_conflict")
        })?;
    let approval_request_id = stored.approval_request_id.clone().ok_or_else(|| {
        pairing_failed_precondition("agent pairing metadata is incomplete")
            .with_reason_detail("missing approval_request_id")
    })?;
    let notification_id = stored
        .approval_notification_id
        .map(|id| ids::format_typed_uuid("notification", &id))
        .ok_or_else(|| {
            pairing_failed_precondition("agent pairing metadata is incomplete")
                .with_reason_detail("missing approval_notification_id")
        })?;
    let requested_at = stored.approval_requested_at.ok_or_else(|| {
        pairing_failed_precondition("agent pairing metadata is incomplete")
            .with_reason_detail("missing approval_requested_at")
    })?;
    let delta =
        arkret_models_collaboration::sync_frames::account_subscribe::NotificationDelta::try_new(
            arkret_models_collaboration::objects::read_receipts::NotificationIdentity::AgentApproval(
                arkret_wire::NotificationId::new(notification_id.clone()).map_err(|error| {
                    AppError::internal(format!("approval notification id is invalid: {error}"))
                })?,
            ),
            arkret_models_collaboration::sync_frames::account_subscribe::NotificationDeltaAction::Upsert,
            Some(
                arkret_models_collaboration::sync_frames::account_subscribe::NotificationData::AgentRuntimeApproval(
                    arkret_models_collaboration::account_subscribe_projections::AgentRuntimeApprovalNotificationData {
                        approval_request_id: arkret_models_collaboration::account_subscribe_projections::AgentRuntimeApprovalRequestId::new(
                            approval_request_id.as_str().to_owned(),
                        )
                        .map_err(|error| {
                            AppError::internal(format!(
                                "stored approval request id is invalid: {error}"
                            ))
                        })?,
                        agent_id: body.agent_id.clone(),
                        requested_at,
                        expires_at,
                    },
                ),
            ),
        )
        .map_err(|error| {
            AppError::internal(format!("approval notification delta is invalid: {error}"))
        })?;
    state
        .deliveries()
        .store_account_delta(
            coland_services::delivery::StoreAccountNotificationDeltaCommand {
                record: coland_services::delivery::AccountNotificationDeltaWrite {
                    delta,
                    recipient_actor_id: arkret_wire::ActorId::account(arkret_wire::AccountId::new(
                        arkret_identifiers::DidCoreId::new(controller_principal_id).map_err(
                            |error| {
                                AppError::internal(format!(
                                    "approval notification recipient is invalid: {error}"
                                ))
                            },
                        )?,
                        state.service_core_id().clone(),
                    )),
                    controller_account_pk: account.account_pk,
                    recipient_id: arkret_identifiers::DidCoreId::new(state.service_id().clone())
                        .map_err(|error| {
                            AppError::internal(format!(
                                "approval notification service is invalid: {error}"
                            ))
                        })?,
                    source_account_artifact_id: approval_request_id.to_string(),
                },
            },
        )
        .await
        .map_err(|error| {
            AppError::internal(format!(
                "runtime approval notification save failed: {error}"
            ))
        })?;
    let _ = state.publish_event_notification(crate::state::EventNotification::account(
        account.account_id,
        state.service_core_id().clone(),
    ));
    json_ok(AgentRuntimeApprovalResponseBody {
        approval_request_id,
        status: agent_lifecycle_from_record(&stored),
    })
}

#[endpoint(
    operation_id = "ak.open.agent_pairing.read.runtime_key_request_status",
    summary = "Get an agent runtime key request status",
    tags("agent_pairing")
)]
#[tracing::instrument(
    skip_all,
    fields(op = "ak.open.agent_pairing.read.runtime_key_request_status.v1")
)]
pub(super) async fn agent_runtime_key_request_status(
    body: JsonBody<AgentRuntimeApprovalStatusRequestBody>,
    depot: &mut Depot,
    res: &mut Response,
) -> JsonResult<AgentRuntimeApprovalStatusResponseBody> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let body = body.into_inner();
    body.validate()
        .map_err(|error| AppError::schema_violation(error.to_string()))?;
    let agent_record = lookup_pairing_record(
        state,
        &body.pairing_request_id,
        &body.pairing_code,
        Some(body.agent_id.as_str()),
    )
    .await?;
    res.headers_mut()
        .insert(salvo::http::header::RETRY_AFTER, "1".parse().unwrap());
    json_ok(agent_runtime_key_request_status_outcome(
        &agent_record,
        &body,
        chrono::Utc::now(),
    )?)
}

/// Resolve the private pairing credential tuple without revealing which
/// component failed. Endpoint-specific lifecycle checks remain at the caller.
async fn lookup_pairing_record(
    state: &AppState,
    pairing_request_id: &str,
    pairing_code: &str,
    agent_id: Option<&str>,
) -> Result<AgentPrincipalRecord, AppError> {
    if pairing_request_id.trim().is_empty() || pairing_code.trim().is_empty() {
        return Err(agent_pairing_not_found());
    }
    let record = state
        .agent_pairings()
        .pairing_record(pairing_request_id)
        .await
        .map_err(|err| AppError::internal(format!("agent pairing lookup failed: {err}")))?
        .ok_or_else(agent_pairing_not_found)?;
    let record = reconcile_accepted_agent_authorization(state, record).await?;
    if record.pairing_code.as_deref() != Some(pairing_code)
        || agent_id.is_some_and(|expected| record.id != expected)
    {
        return Err(agent_pairing_not_found());
    }
    Ok(record)
}

/// Read exact active authorization instances from the current accepted PCR frontier.
pub(crate) async fn accepted_agent_key_authorizations(
    state: &AppState,
    agent: &AgentPrincipalRecord,
) -> Result<BTreeSet<(String, String)>, AppError> {
    accepted_agent_key_authorization_snapshot(state, agent)
        .await
        .map(|(keys, ..)| keys)
}

pub(crate) async fn accepted_active_agent_key_authorizations(
    state: &AppState,
    agent: &AgentPrincipalRecord,
) -> Result<BTreeSet<(String, String)>, AppError> {
    let (keys, _, lifecycle) = accepted_agent_key_authorization_snapshot(state, agent).await?;
    validate_accepted_agent_action_lifecycle(agent.state, lifecycle)?;
    Ok(keys)
}

pub(super) fn validate_accepted_agent_action_lifecycle(
    local_intent: AgentLifecycleState,
    accepted: Option<AgentLifecycleState>,
) -> Result<(), AppError> {
    if local_intent != AgentLifecycleState::Active || accepted != Some(AgentLifecycleState::Active)
    {
        return Err(pairing_failed_precondition(
            "Agent runtime action requires active accepted lifecycle",
        ));
    }
    Ok(())
}

/// Read accepted Agent status and all key dots from one durable Realm cut.
pub(super) async fn accepted_agent_key_authorization_snapshot(
    state: &AppState,
    agent: &AgentPrincipalRecord,
) -> Result<
    (
        BTreeSet<(String, String)>,
        Vec<arkret_wire::CommitStreamHead>,
        Option<AgentLifecycleState>,
    ),
    AppError,
> {
    use arkret_models_collaboration::events_payloads::agent::AgentKeyAuthorizePayload;

    let realm = arkret_wire::RealmId::new(agent.principal_control_realm_id.clone())
        .map_err(|error| AppError::internal(error.to_string()))?;
    let material = state
        .authority_commits()
        .realm_state_snapshot_material(&realm)
        .await
        .map_err(|error| {
            AppError::internal(format!("Agent current snapshot unavailable: {error}"))
        })?
        .ok_or_else(|| {
            pairing_failed_precondition("Agent control Realm has no committed snapshot")
        })?;
    let mut lifecycle = None;
    let mut active = BTreeSet::new();
    for entry in &material.current_state_entries {
        let arkret_wire::CurrentState::Value {
            selector, value, ..
        } = entry;
        match selector {
            arkret_wire::CurrentSelector::AgentStatus { agent_id }
                if agent_id.as_str() == agent.id =>
            {
                if lifecycle.is_some() {
                    return Err(pairing_failed_precondition(
                        "duplicate Agent status in accepted cut",
                    ));
                }
                lifecycle = Some(
                    serde_json::from_value::<AgentLifecycleState>(value.clone()).map_err(
                        |error| {
                            AppError::internal(format!("accepted Agent status is invalid: {error}"))
                        },
                    )?,
                );
            }
            arkret_wire::CurrentSelector::AgentKey {
                agent_id,
                agent_key_id,
            } if agent_id.as_str() == agent.id => {
                let entries = value
                    .get("authorizations")
                    .and_then(Value::as_array)
                    .ok_or_else(|| {
                        pairing_failed_precondition("accepted Agent key set is invalid")
                    })?;
                for entry in entries {
                    let Some(authorization) = entry.get("value") else {
                        return Err(pairing_failed_precondition(
                            "accepted Agent key dot has no value",
                        ));
                    };
                    if authorization.get("verification_method").is_none() {
                        continue;
                    }
                    let payload: AgentKeyAuthorizePayload =
                        serde_json::from_value(authorization.clone()).map_err(|error| {
                            AppError::internal(format!(
                                "accepted Agent key authorization is invalid: {error}"
                            ))
                        })?;
                    if payload.agent_id != *agent_id
                        || payload.key_id.as_str() != agent_key_id.as_str()
                    {
                        return Err(pairing_failed_precondition(
                            "accepted Agent key selector and payload disagree",
                        ));
                    }
                    arkret_signatures::agent::validate_agent_runtime_public_key(
                        &payload.public_key,
                        &payload.verification_method,
                    )
                    .map_err(|error| {
                        AppError::internal(format!("accepted Agent raw key is invalid: {error}"))
                    })?;
                    if payload
                        .expires_at
                        .is_some_and(|expiry| expiry <= chrono::Utc::now())
                    {
                        continue;
                    }
                    let tag = entry
                        .get("tag_id")
                        .and_then(Value::as_str)
                        .and_then(|tag| tag.strip_suffix(":1"))
                        .ok_or_else(|| {
                            pairing_failed_precondition("Agent authorization add dot is invalid")
                        })?;
                    let event_id = EventId::new(tag).map_err(|error| {
                        AppError::internal(format!(
                            "Agent authorization Event id is invalid: {error}"
                        ))
                    })?;
                    active.insert((payload.key_id.to_string(), event_id.to_string()));
                }
            }
            _ => {}
        }
    }
    Ok((active, material.visible_stream_heads, lifecycle))
}

pub(super) fn pairing_outcome_for_accepted_snapshot(
    event_is_covered: bool,
    active: &BTreeSet<(String, String)>,
    expected: &(String, String),
) -> Option<AgentKeyPairActivationState> {
    if !event_is_covered {
        return None;
    }
    Some(if active.len() == 1 && active.contains(expected) {
        AgentKeyPairActivationState::Active
    } else {
        AgentKeyPairActivationState::Cancelled
    })
}

pub(super) async fn reconcile_accepted_agent_authorization(
    state: &AppState,
    agent_record: AgentPrincipalRecord,
) -> Result<AgentPrincipalRecord, AppError> {
    let Some(approval_request_id) = agent_record.approval_request_id.clone() else {
        return Ok(agent_record);
    };
    let Some(runtime_request) = agent_record.runtime_key_request.as_ref() else {
        if agent_record.paired_pairing_request_id == agent_record.pairing_request_id
            && let Some(context) = account_notification_context(&agent_record)
        {
            finalize_terminal_account_notification(state, &agent_record.id, context,
                    arkret_models_collaboration::sync_frames::account_subscribe::AgentRuntimeApprovalRemovalReason::Approved).await?;
        }
        return Ok(agent_record);
    };
    let agent_id = agent_record.id.clone();
    let controller_principal_id = agent_record.controller_principal_id.clone();
    let Some(pairing_request_id) = agent_record.pairing_request_id.clone() else {
        return Ok(agent_record);
    };
    let verification_method = runtime_request.verification_method.to_string();
    let Some(_public_key_digest) = agent_record.runtime_public_key_digest.clone() else {
        return Ok(agent_record);
    };
    let Some(pending_commit_intent) = agent_record.pending_pairing_commit_intent.clone() else {
        return Ok(agent_record);
    };
    let reference = pending_commit_intent
        .scope_custody_ref
        .as_ref()
        .ok_or_else(|| {
            pairing_failed_precondition("pending pairing lacks private scope custody")
        })?;
    let private = load_scope_custody(state, reference)?;
    if private.command.authorize_event.event.event_id.as_str()
        != pending_commit_intent.authorize_event_id
        || private.request_digest != pending_commit_intent.request_digest
        || private.command.pairing_request_id != pairing_request_id
        || private.command.approval_request_id != approval_request_id
        || private.runtime_key_binding_digest
            != agent_record
                .runtime_key_binding_digest
                .clone()
                .unwrap_or_default()
        || private.command.requested_scope_disclosure.agent_id.as_str() != agent_id
        || private.command.authorize_event.event
            != pending_commit_intent
                .key_authorization_event
                .clone()
                .ok_or_else(|| pairing_failed_precondition("pending authorize Event is missing"))?
    {
        return Err(pairing_failed_precondition(
            "pending pairing private custody differs",
        ));
    }
    let paired_request_digest = pending_commit_intent.request_digest;
    let pending_authorize_event_id = pending_commit_intent.authorize_event_id;
    let key_authorization_event =
        pending_commit_intent
            .key_authorization_event
            .ok_or_else(|| {
                pairing_failed_precondition(
                    "pending pairing commit intent is missing its controller authorize Event",
                )
            })?;
    let authorized_key =
        arkret_models_identity::agent_signer_evidence::AgentAuthorizedSigningKey::from_event(
            &key_authorization_event,
        )
        .map_err(|error| AppError::param_invalid(error.to_string()))?;
    let authorized_public_key_digest = authorized_key.public_key_digest.clone();
    ensure_pairing_request_open(&agent_record)?;
    crate::routing::identity::agent_pcr::validate_agent_controller_binding(
        state,
        &agent_record,
        chrono::Utc::now(),
    )
    .await?;
    let expected_realm_id = agent_record.principal_control_realm_id.clone();
    let expected_authorization_ref = agent_record.controller_authorization_ref.clone();
    let expected_request_digest = pairing_request_binding_digest(
        &agent_record,
        &controller_principal_id,
        &agent_id,
        &verification_method,
        state.service_id(),
    )?;
    let agent_actor = pairing_account_actor(&agent_id, state.service_id())?;
    let controller_actor = pairing_account_actor(&controller_principal_id, state.service_id())?;
    let controller_account_pk = agent_record.controller_account_pk.ok_or_else(|| {
        pairing_failed_precondition("pairing controller has no exact Account binding")
    })?;
    let controller_account = state
        .identities()
        .account_by_id(controller_account_pk)
        .await
        .map_err(|error| AppError::internal(format!("pairing controller lookup failed: {error}")))?
        .ok_or_else(|| pairing_failed_precondition("pairing controller Account is missing"))?;
    if controller_actor.as_account_id() != Some(&controller_account.account_id) {
        return Err(pairing_failed_precondition(
            "pairing controller Account belongs to another Station",
        ));
    }
    // The exact frozen command either has a covering RealmCommit or the
    // pairing stays awaiting it; a cached Event row alone proves nothing.
    let pending_event_id = EventId::new(pending_authorize_event_id.clone()).map_err(|error| {
        AppError::internal(format!("pending authorize Event id is invalid: {error}"))
    })?;
    let Some(accepted) = state
        .authority_commits()
        .committed_event(&pending_event_id)
        .await
        .map_err(|error| {
            AppError::internal(format!("authorization reconciliation failed: {error}"))
        })?
    else {
        return Ok(agent_record);
    };
    let envelope = serde_json::to_value(&accepted.event)
        .map_err(|error| AppError::internal(error.to_string()))?;
    let payload = envelope.get("payload").unwrap_or(&Value::Null);
    let evidence = payload.get("approval_evidence").unwrap_or(&Value::Null);
    let matches = accepted.event.kind == arkret_wire::EventKind::AgentKeyAuthorize
        && accepted.event.actor_id == agent_actor
        && envelope_actor(&envelope, "executed_by").as_ref() == Some(&controller_actor)
        && envelope.get("authorization_ref").and_then(Value::as_str)
            == Some(expected_authorization_ref.as_str())
        && accepted.event.realm_id.as_str() == expected_realm_id
        && payload.get("agent_id").and_then(Value::as_str) == Some(agent_id.as_str())
        && payload.get("verification_method").and_then(Value::as_str)
            == Some(verification_method.as_str())
        && payload.get("public_key") == key_authorization_event.payload.get("public_key")
        && payload
            .get("accountable_principal_id")
            .and_then(Value::as_str)
            == Some(controller_principal_id.as_str())
        && payload
            .get("agent_key_scope")
            .is_some_and(|scope| agent_key_scope_within_requested_scope(&agent_record, scope))
        && payload
            .get("audience")
            .and_then(Value::as_array)
            .is_some_and(|audience| {
                audience
                    .iter()
                    .any(|entry| entry.as_str() == Some(state.service_id().as_str()))
            })
        && evidence.get("kind").and_then(Value::as_str) == Some("pairing_request")
        && evidence.get("approved_by").and_then(Value::as_str)
            == Some(controller_principal_id.as_str())
        && evidence.get("pairing_request_id").and_then(Value::as_str)
            == Some(pairing_request_id.as_str())
        && evidence
            .get("request_canonical_digest")
            .and_then(Value::as_str)
            == Some(expected_request_digest.as_str());
    if !matches {
        return Err(pairing_failed_precondition(
            "accepted authorize Event differs from the frozen pairing command",
        ));
    }
    let authorize_event = accepted.event.clone();
    if authorize_event.event_id != key_authorization_event.event_id
        || authorize_event.payload != key_authorization_event.payload
    {
        return Err(pairing_failed_precondition(
            "accepted Event differs from the frozen controller command",
        ));
    }
    let committed = accepted;
    let (active_authorizations, visible_heads, lifecycle) =
        accepted_agent_key_authorization_snapshot(state, &agent_record).await?;
    let covered = visible_heads.iter().any(|head| {
        head.stream_ref == committed.commit.stream_ref
            && head.stream_position >= committed.commit.stream_position
    });
    let Some(outcome) = pairing_outcome_for_accepted_snapshot(
        covered,
        &active_authorizations,
        &(
            authorized_key.agent_key_id.to_string(),
            committed.event.event_id.to_string(),
        ),
    ) else {
        return Ok(agent_record);
    };
    if lifecycle != Some(AgentLifecycleState::Active) {
        return Err(pairing_failed_precondition(
            "Agent activation requires active accepted status",
        ));
    }
    if outcome != AgentKeyPairActivationState::Active {
        return Err(pairing_failed_precondition(
            "Agent authorization is not the unique active key",
        ));
    }

    let (signer_resolution_evidence_ref, current_signer_evidence) =
        if outcome == AgentKeyPairActivationState::Active {
            let mut frozen_agent = agent_record.clone();
            frozen_agent.paired_pairing_request_id = Some(pairing_request_id.clone());
            frozen_agent.authorized_event_ref = Some(committed.event.event_id.to_string());
            frozen_agent.authorized_verification_method = Some(verification_method.clone());
            frozen_agent.authorized_public_key_digest =
                Some(authorized_public_key_digest.as_str().to_owned());
            frozen_agent.authorized_key_event = Some(authorize_event.clone());
            let verification_method_id = arkret_wire::DidUrl::new(verification_method.clone())
                .map_err(|error| AppError::internal(error.to_string()))?;
            let selector = super::evidence::AgentSignerEvidenceQuerySelector::CurrentAdmission {
                actor: agent_actor.clone(),
                verification_method: verification_method_id.clone(),
            };
            let (root, dependencies) =
                super::evidence::current_authenticated_agent_signer_evidence_for_record(
                    state,
                    &selector,
                    Some(&frozen_agent),
                )
                .await
                .map_err(|reason| {
                    pairing_failed_precondition(format!(
                        "Agent activation signer evidence is unavailable: {reason:?}"
                    ))
                })?;
            let delivery = super::evidence::current_agent_evidence_delivery(
                agent_actor.clone(),
                verification_method_id,
                &root,
                dependencies,
            )?;
            (Some(delivery.0), Some(delivery.1))
        } else {
            (None, None)
        };

    let terminal_notification = account_notification_context(&agent_record);
    let activation = coland_services::identity::ActivateAgentRuntimeCommand {
        agent_id: agent_id.clone(),
        approval_request_id: approval_request_id.clone(),
        runtime_key_binding_digest: agent_record
            .runtime_key_binding_digest
            .clone()
            .unwrap_or_default(),
        pairing_request_id,
        paired_request_digest,
        authorized_event_ref: committed.event.event_id.to_string(),
        authorized_verification_method: verification_method,
        authorized_public_key_digest: authorized_public_key_digest.as_str().to_owned(),
        signer_resolution_evidence_ref,
        current_signer_evidence,
        scope_custody_ref: pending_commit_intent.scope_custody_ref.clone(),
        frozen_authorize_event: key_authorization_event,
        authorize_ref: arkret_wire::CommittedEventRef {
            event_id: committed.event.event_id.clone(),
            commit_id: committed.commit.commit_id.clone(),
            stream_ref: committed.commit.stream_ref.clone(),
            stream_position: committed.commit.stream_position,
        },
        status: AgentLifecycleState::Active,
        authorized_key_event: authorize_event,
        authorized_at: committed.commit.committed_at,
    };
    let activated = state
        .agent_pairings()
        .activate_runtime(&activation)
        .await
        .map_err(|error| {
            AppError::internal(format!(
                "authorization reconciliation persist failed: {error}"
            ))
        })?;
    if !activated {
        return state
            .agent_pairings()
            .agent(&agent_id)
            .await
            .map_err(|error| {
                AppError::internal(format!(
                    "authorization reconciliation reload failed: {error}"
                ))
            })?
            .ok_or_else(|| {
                AppError::internal("Agent disappeared during authorization reconciliation")
            });
    }
    if let Some(context) = terminal_notification {
        finalize_terminal_account_notification(
            state,
            &agent_id,
            context,
            if outcome == AgentKeyPairActivationState::Active {
                arkret_models_collaboration::sync_frames::account_subscribe::AgentRuntimeApprovalRemovalReason::Approved
            } else {
                arkret_models_collaboration::sync_frames::account_subscribe::AgentRuntimeApprovalRemovalReason::Superseded
            },
        )
        .await?;
    }
    tracing::info!(
        agent_id,
        approval_request_id = %approval_request_id,
        ?outcome,
        "reconciled accepted Agent authorization into terminal pairing outcome"
    );
    state
        .agent_pairings()
        .agent(&agent_id)
        .await
        .map_err(|error| {
            AppError::internal(format!(
                "authorization reconciliation reload failed: {error}"
            ))
        })?
        .ok_or_else(|| AppError::internal("Agent disappeared after authorization reconciliation"))
}

/// Pure decision core for the open runtime-key-request status poll.
///
/// Anti-enumeration: a record miss and a `pairing_code` /
/// `agent_id` mismatch are indistinguishable — every mismatch maps
/// to the same not_found as an unknown `pairing_request_id`. An open pairing
/// whose `pairing_expires_at` has passed is reported as `pairing_expired`
/// without waiting for the lazy-expiry write.
pub(super) fn agent_runtime_key_request_status_outcome(
    agent_record: &AgentPrincipalRecord,
    body: &AgentRuntimeApprovalStatusRequestBody,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<AgentRuntimeApprovalStatusResponseBody, AppError> {
    let pairing_code = body.pairing_code.trim();
    if pairing_code.is_empty() {
        return Err(agent_pairing_not_found());
    }
    if agent_record.pairing_code.as_deref() != Some(pairing_code) {
        return Err(agent_pairing_not_found());
    }
    if agent_record.id != body.agent_id.as_str() {
        return Err(agent_pairing_not_found());
    }
    // Two orthogonal axes (key-management.md §3.6.1): the lifecycle intent and
    // the derived runtime readiness. An expired bootstrap handle projects
    // pairing_expired; an expired replacement handle projects ready with no
    // authorized fields for this request, which the runtime treats as expired.
    let lifecycle = agent_lifecycle_from_record(agent_record);
    let bindings = agent_record.runtime_bindings().map_err(|error| {
        AppError::internal(format!(
            "persisted Agent runtime binding state is invalid: {error}"
        ))
    })?;
    let has_active_authorization = bindings.active_binding.is_some();
    let handle_live = bindings
        .open_handle
        .as_ref()
        .is_some_and(|handle| handle.is_live_at(now));
    let runtime_state = AgentRuntimeState::derive(has_active_authorization, handle_live);
    let approval_request_id = if runtime_state == AgentRuntimeState::PendingRuntimeKey {
        agent_record.approval_request_id.clone()
    } else {
        None
    };
    // Replacement pairing keeps the previous authorization active until the
    // new request is approved. Do not expose that previous binding as the
    // outcome for this handle: runtimes may reuse the same key digest, which
    // would otherwise make a pending replacement look approved and persist a
    // reference that is revoked as soon as replacement completes.
    let completed_binding = bindings.active_binding.as_ref().filter(|binding| {
        binding.completed_pairing_request_id.as_str() == body.pairing_request_id.as_str()
    });
    let authorized_event_ref =
        completed_binding.map(|binding| binding.authorized_event_ref.clone());
    let projection = agent_projection_from_record(agent_record, runtime_state);
    Ok(AgentRuntimeApprovalStatusResponseBody {
        lifecycle,
        runtime_state,
        readiness: projection.readiness,
        presence: projection.presence,
        approval_request_id,
        authorized_event_ref,
        authorized_verification_method: completed_binding
            .map(|binding| binding.verification_method.clone()),
        authorized_public_key_digest: completed_binding
            .map(|binding| binding.public_key_digest.clone()),
        signer_resolution_evidence_ref: completed_binding
            .map(|binding| binding.signer_resolution_evidence_ref.clone()),
        current_signer_evidence: completed_binding.map(|binding| {
            arkret_models_collaboration::agent_operations::KeyStateCurrentSignerEvidence {
                signer_resolution_evidence_ref: binding.signer_resolution_evidence_ref.clone(),
                authenticated_signer_evidence: binding.current_signer_evidence.clone(),
            }
        }),
    })
}

#[endpoint(
    operation_id = "ak.gate.account.command.pair_agent_key",
    summary = "Pair an agent device key",
    tags("agent_pairing")
)]
#[tracing::instrument(skip_all, fields(op = "ak.gate.account.command.pair_agent_key.v1"))]
pub(super) async fn agent_key_pair(
    aa: AuthArgs,
    body: JsonBody<AgentKeyPairRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AgentKeyPairResponseBody> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let service_authorized =
        agent_projection_service_authorized(state, req, PAIR_AGENT_KEY_SERVICE_OPERATION, true)
            .await?;
    let body = body.into_inner();
    body.authorize_event
        .event
        .verify_event_id_matches_content_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
        .map_err(|_| AppError::param_invalid("event_id_digest_mismatch"))?;
    let event_id = body.authorize_event.event.event_id.as_str();
    let idempotency_key = req
        .headers()
        .get("idempotency-key")
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| AppError::param_missing("Idempotency-Key header is required"))?;
    if idempotency_key != event_id {
        return Err(AppError::conflict(
            "Idempotency-Key must equal authorize_event.event.event_id",
        )
        .with_wire_code("duplicate_conflict"));
    }
    let session = if service_authorized {
        let controller_account =
            body.authorize_event
                .event
                .executed_by
                .as_ref()
                .and_then(arkret_wire::ActorId::as_account_id)
                .ok_or_else(|| {
                    AppError::capability_denied(
                        "authorize_event.executed_by must be a controller Account for delegated pairing",
                    )
                })?;
        let controller_principal_id = controller_account.principal_id.as_str();
        let controller_device_id =
            service_pairing_controller_device_id(&body, controller_principal_id)?;
        controller_service_session(controller_account, &controller_device_id, state).await?
    } else {
        aa.authenticated_session(state, req).await?
    };
    let proposed_authorization =
        arkret_models_collaboration::events_payloads::agent::AgentKeyAuthorizePayload::try_from(
            &body.authorize_event.event,
        )
        .map_err(|error| AppError::param_invalid(error.to_string()))?;
    let agent_id = proposed_authorization.agent_id.as_str();
    validate_agent_id(agent_id)?;
    if proposed_authorization.verification_method.trim().is_empty() {
        return Err(AppError::param_invalid("verification_method is required"));
    }
    if verification_method_principal(&proposed_authorization.verification_method)
        .is_none_or(|principal| principal.as_str() != agent_id)
    {
        return Err(
            AppError::param_invalid("verification_method DID must project to agent_id")
                .with_reason_code(arkret_wire::ReasonCode::VERIFICATION_METHOD_PRINCIPAL_MISMATCH),
        );
    }
    let agent_record = require_agent_controller(state, &session, agent_id).await?;
    let paired_request_digest = agent_key_pair_request_digest(&body)?;
    if let Some(receipt) = state
        .agent_pairings()
        .pairing_receipt(event_id)
        .await
        .map_err(|error| AppError::internal(format!("pairing receipt lookup failed: {error}")))?
    {
        if receipt.agent_id != agent_id
            || receipt.controller_principal_id != agent_record.controller_principal_id
            || receipt.request_digest != paired_request_digest
        {
            return Err(AppError::conflict(
                "authorize Event was bound to a different exact request",
            )
            .with_wire_code("duplicate_conflict"));
        }
        if receipt.outcome.activation_state != AgentKeyPairActivationState::AwaitingSourceCommit {
            return json_ok(receipt.outcome);
        }
    }
    let agent_record = reconcile_accepted_agent_authorization(state, agent_record).await?;
    if let Some(receipt) = state
        .agent_pairings()
        .pairing_receipt(event_id)
        .await
        .map_err(|_| AppError::internal("pairing receipt reload failed"))?
        && receipt.request_digest == paired_request_digest
        && receipt.outcome.activation_state != AgentKeyPairActivationState::AwaitingSourceCommit
    {
        return json_ok(receipt.outcome);
    }
    let existing_scope_custody = agent_record
        .pending_pairing_commit_intent
        .as_ref()
        .map(|intent| {
            let reference = intent.scope_custody_ref.as_ref().ok_or_else(|| {
                pairing_failed_precondition("pending command lacks private scope custody")
            })?;
            let original = load_scope_custody(state, reference)?;
            if !same_scope_command(&original.command, &body)?
                || original.request_digest != paired_request_digest
            {
                return Err(AppError::conflict(
                    "pairing command differs from private scope custody",
                ));
            }
            Ok(reference.clone())
        })
        .transpose()?;
    let provision_scope = body.requested_scope_disclosure.requested_scope.clone();
    validate_agent_runtime_key_scopes(&provision_scope, &proposed_authorization.agent_key_scope)?;
    validate_agent_key_authorize_effects(&body.authorize_event.event)?;
    if agent_record.authorized_event_ref.as_deref() == Some(event_id) {
        let same_request = agent_record.paired_pairing_request_id.as_deref()
            == Some(body.pairing_request_id.as_str())
            && agent_record.paired_request_digest.as_deref()
                == Some(paired_request_digest.as_str());
        if !same_request {
            return Err(AppError::conflict(
                "authorize_event.event_id was already accepted for a different pairing request",
            )
            .with_wire_code("duplicate_conflict"));
        }
        if let Some(context) = account_notification_context(&agent_record) {
            finalize_terminal_account_notification(
                state,
                agent_id,
                context,
                arkret_models_collaboration::sync_frames::account_subscribe::AgentRuntimeApprovalRemovalReason::Approved,
            )
            .await?;
        }
        return json_ok(AgentKeyPairResponseBody {
            activation_state: AgentKeyPairActivationState::Active,
            authorize_event_ref: body.authorize_event.event.event_id.clone(),
        });
    }
    ensure_pairing_request_open(&agent_record)?;
    ensure_pairing_request_id_matches(&agent_record, &body.pairing_request_id)?;
    let (current_authorizations, _, lifecycle) =
        accepted_agent_key_authorization_snapshot(state, &agent_record).await?;
    if !matches!(
        lifecycle,
        Some(AgentLifecycleState::Active | AgentLifecycleState::Paused)
    ) {
        return Err(pairing_failed_precondition(
            "Agent pairing requires non-terminal accepted lifecycle",
        ));
    }
    let supplied_authorizations: BTreeSet<_> = proposed_authorization
        .supersedes
        .iter()
        .map(|entry| {
            (
                entry.key_id.to_string(),
                entry.authorized_event_ref.to_string(),
            )
        })
        .collect();
    if supplied_authorizations != current_authorizations
        || supplied_authorizations.len() != proposed_authorization.supersedes.len()
    {
        return Err(pairing_failed_precondition(
            "supersedes must equal the exact current active authorization set",
        ));
    }

    let runtime_public_key_digest = runtime_public_key_digest(
        &proposed_authorization.public_key,
        &proposed_authorization.verification_method,
    )?;
    // An exact, authenticated pending custody command already passed this
    // frozen runtime proof. Current candidate/key/lifecycle gates below still
    // run; recovering the accepted intent is not a new presentation.
    if existing_scope_custody.is_none() {
        verify_runtime_key_pair_proof_of_possession(
            &body,
            &agent_record,
            agent_id,
            state.service_id(),
        )?;
    }
    if agent_record.authorized_public_key_digest.as_deref()
        == Some(runtime_public_key_digest.as_str())
    {
        return Err(pairing_failed_precondition(
            "pairing must use a fresh raw key; same-key reauthorization retains its sequence allocator",
        ));
    }
    ensure_current_runtime_key_request_matches(&agent_record, &body)?;
    ensure_controller_pairing_authorization(
        &body.authorize_event.event,
        &proposed_authorization,
        &agent_record,
        state.service_id(),
    )?;
    crate::routing::identity::agent_pcr::validate_agent_controller_binding(
        state,
        &agent_record,
        chrono::Utc::now(),
    )
    .await?;
    // Invalid signatures must not reserve the exact command receipt or consume
    // a raw key: the executing controller's active device must have signed it.
    let event = &body.authorize_event.event;
    let controller_account = event
        .executed_by
        .as_ref()
        .and_then(arkret_wire::ActorId::as_account_id)
        .filter(|account| account.principal_id.as_str() == agent_record.controller_principal_id)
        .ok_or_else(|| {
            AppError::capability_denied("authorize Event is not executed by the Agent's controller")
        })?;
    let scope_custody_ref = if let Some(reference) = existing_scope_custody {
        reference
    } else {
        crate::state::verify_account_device_producer(state, controller_account, event)
            .await
            .map_err(|_| {
                AppError::param_invalid("authorize Event controller signature invalid")
                    .with_reason_code(arkret_wire::ReasonCode::PROOF_INVALID)
            })?;
        retain_verified_scope_custody(state, &agent_record, &body).await?
    };
    let commit_intent = coland_services::identity::RecordAgentPairingCommitIntentCommand {
        agent_id: agent_id.to_owned(),
        approval_request_id: agent_record.approval_request_id.clone().ok_or_else(|| {
            pairing_failed_precondition("agent pairing approval metadata is incomplete")
        })?,
        runtime_key_binding_digest: agent_record.runtime_key_binding_digest.clone().ok_or_else(
            || pairing_failed_precondition("agent runtime key binding metadata is incomplete"),
        )?,
        pairing_request_id: body.pairing_request_id.clone(),
        request_digest: paired_request_digest.clone(),
        authorize_event_id: event_id.to_owned(),
        key_authorization_event: body.authorize_event.event.clone(),
        scope_custody_ref: Some(scope_custody_ref),
    };
    let committed = state
        .agent_pairings()
        .record_pairing_commit_intent(&commit_intent)
        .await
        .map_err(|error| {
            AppError::internal(format!(
                "agent pairing commit intent persist failed: {error}"
            ))
        })?;
    if committed.is_none() {
        let current = state
            .agent_pairings()
            .agent(agent_id)
            .await
            .map_err(|error| {
                AppError::internal(format!(
                    "agent pairing commit intent reload failed: {error}"
                ))
            })?;
        if current.as_ref().is_some_and(|record| {
            record
                .pending_pairing_commit_intent
                .as_ref()
                .is_some_and(|intent| {
                    intent.request_digest != paired_request_digest
                        || intent.authorize_event_id != event_id
                        || intent.key_authorization_event.as_ref()
                            != Some(&body.authorize_event.event)
                })
        }) {
            return Err(AppError::conflict(
                "pairing handle is already bound to a different final request",
            )
            .with_wire_code("duplicate_conflict"));
        }
        return Err(pairing_failed_precondition(
            "runtime approval was already consumed or changed",
        ));
    }
    // Development and production consume the exact controller-signed Event
    // supplied by the client. A server-generated substitute would break the
    // Agent-PCR authorship and idempotency contract.
    let event_id = submit_production_key_authorize_event(
        state,
        &session,
        &agent_record,
        body.authorize_event.clone(),
    )
    .await?;
    let authorized_event_ref = EventId::new(event_id)
        .map_err(|err| AppError::internal(format!("authorize event id invalid: {err}")))?;
    // The Event is durable, but is intentionally not authorization state yet.
    // Accepted Seal processing reconciles the durable command automatically.
    json_ok(AgentKeyPairResponseBody {
        activation_state: AgentKeyPairActivationState::AwaitingSourceCommit,
        authorize_event_ref: authorized_event_ref,
    })
}

pub(super) fn service_pairing_controller_device_id(
    body: &AgentKeyPairRequestBody,
    controller_principal_id: &str,
) -> Result<String, AppError> {
    let submission = &body.authorize_event;
    let agent_core = body
        .authorize_event
        .event
        .actor_id
        .signing_principal_id()
        .clone();
    if submission.event.actor_id.signing_principal_id() != &agent_core {
        return Err(AppError::capability_denied(
            "delegated pairing Event must name the Agent",
        ));
    }
    if submission
        .event
        .executed_by
        .as_ref()
        .map(|actor| actor.signing_principal_id().as_str())
        != Some(controller_principal_id)
    {
        return Err(AppError::capability_denied(
            "delegated pairing Event executor must match the controller",
        ));
    }

    let verification_method = submission
        .event
        .producer_proof
        .as_ref()
        .map(|proof| proof.verification_method.as_str())
        .ok_or_else(|| {
            AppError::capability_denied(
                "delegated pairing Event must carry a controller device proof",
            )
        })?;
    let (verification_method_principal, device_id) =
        verification_method.split_once('#').ok_or_else(|| {
            AppError::capability_denied(
                "delegated pairing Event proof must use a controller verification method",
            )
        })?;
    let verification_method_controller =
        arkret_wire::Did::new(verification_method_principal.to_owned())
            .and_then(|did| arkret_wire::project_did_to_core_id(&did))
            .map_err(|_| {
                AppError::capability_denied(
                    "delegated pairing Event proof must use a controller verification method",
                )
            })?;
    if verification_method_controller.as_str() != controller_principal_id {
        return Err(AppError::capability_denied(
            "delegated pairing Event proof must use a controller verification method",
        ));
    }
    arkret_wire::DeviceId::new(device_id.to_owned()).map_err(|_| {
        AppError::capability_denied(
            "delegated pairing Event proof must name a typed controller device",
        )
    })?;
    Ok(device_id.to_owned())
}

fn validate_agent_key_authorize_effects(event: &arkret_wire::Event) -> Result<(), AppError> {
    let _ =
        arkret_models_collaboration::events_payloads::agent::AgentKeyAuthorizePayload::try_from(
            event,
        )
        .map_err(|error| {
            AppError::param_invalid(format!("authorize_event.payload invalid: {error}"))
        })?;
    Ok(())
}

async fn validate_requested_scope_disclosure(
    body: &AgentKeyPairRequestBody,
    agent_record: &AgentPrincipalRecord,
    state: &AppState,
) -> Result<coland_storage::AgentScopeAcceptedBinding, AppError> {
    let disclosure = &body.requested_scope_disclosure;
    disclosure.validate().map_err(|error| {
        AppError::param_invalid(format!("requested_scope_disclosure invalid: {error}"))
    })?;
    if disclosure.agent_id.as_str() != agent_record.id
        || disclosure.controller_principal_id.as_str() != agent_record.controller_principal_id
    {
        return Err(AppError::param_invalid(
            "requested_scope_disclosure principal binding does not match the Agent record",
        ));
    }
    if disclosure.verifier_id.as_str() != state.service_id()
        || disclosure.audience.as_str()
            != arkret_wire::ServiceOperationId::GATE_ACCOUNT_COMMAND_PAIR_AGENT_KEY_V1
    {
        return Err(AppError::param_invalid(
            "requested_scope_disclosure verifier or audience does not match this operation",
        ));
    }
    let pairing_request_id = required_pairing_request_id(agent_record)?;
    let pairing_request_uuid = pairing_request_id
        .strip_prefix("agent_pairing_request:")
        .ok_or_else(|| incomplete_pairing_metadata("pairing_request_id"))?;
    if disclosure.request_id.as_str() != format!("ak:request:{pairing_request_uuid}")
        || disclosure.challenge.as_str() != pairing_request_id
    {
        return Err(AppError::param_invalid(
            "requested_scope_disclosure request or challenge does not match the open pairing request",
        ));
    }
    let now = chrono::Utc::now();
    if now < disclosure.issued_at || now > disclosure.expires_at {
        return Err(AppError::param_invalid(
            "requested_scope_disclosure presentation window is not active",
        ));
    }
    let stored_scope = agent_record.requested_scope.as_ref().ok_or_else(|| {
        crate::app_error!(
            FailedPrecondition,
            "Agent record is missing its immutable requested_scope",
        )
    })?;
    let stored_scope: AgentKeyScope =
        serde_json::from_value(stored_scope.clone()).map_err(|error| {
            AppError::internal(format!("stored Agent requested_scope is invalid: {error}"))
        })?;
    let agent_id = arkret_wire::DidCoreId::new(agent_record.id.clone())
        .map_err(|error| AppError::internal(format!("stored Agent DID is invalid: {error}")))?;
    let controller_principal_id =
        arkret_identifiers::DidCoreId::new(agent_record.controller_principal_id.clone()).map_err(
            |error| AppError::internal(format!("stored Agent controller DID is invalid: {error}")),
        )?;
    let stored_digest = arkret_signatures::agent::agent_requested_scope_digest(
        &agent_id,
        &controller_principal_id,
        &stored_scope,
    )
    .map_err(|error| {
        AppError::internal(format!(
            "stored Agent requested_scope digest failed: {error}"
        ))
    })?;
    let disclosed_digest = arkret_signatures::agent::agent_requested_scope_digest(
        &disclosure.agent_id,
        &disclosure.controller_principal_id,
        &disclosure.requested_scope,
    )
    .map_err(|error| AppError::param_invalid(error.to_string()))?;
    if disclosed_digest != stored_digest {
        return Err(AppError::param_invalid(
            "requested_scope_disclosure does not match the provisioned Agent ceiling",
        ));
    }
    let accepted_binding = crate::routing::identity::agent_pcr::qualified_agent_scope_binding_at(
        state,
        agent_record,
        &disclosed_digest,
        now,
    )
    .await?;
    // The controller's current proof is by one of its active devices at its
    // PCR cut; a DID Document lists no device keys.
    let controller_account =
        crate::routing::identity::agent_pcr::agent_controller_account(state, agent_record).await?;
    let mut proof_errors = Vec::new();
    for proof in &disclosure.proofs {
        if proof.created_at < disclosure.issued_at || proof.created_at > disclosure.expires_at {
            proof_errors.push("proof created_at is outside the disclosure window".to_owned());
            continue;
        }
        let binding_bytes = match disclosure.canonical_proof_binding_bytes(proof) {
            Ok(bytes) => bytes,
            Err(error) => {
                proof_errors.push(error.to_string());
                continue;
            }
        };
        match crate::state::verify_account_device_payload_proof(
            state,
            &controller_account,
            proof,
            &binding_bytes,
        )
        .await
        {
            Ok(()) => return Ok(accepted_binding),
            Err(error) => proof_errors.push(error.to_string()),
        }
    }
    Err(AppError::param_invalid(format!(
        "requested_scope_disclosure has no valid controller proof: {}",
        proof_errors.join("; ")
    )))
}

fn ensure_current_runtime_key_request_matches(
    agent_record: &AgentPrincipalRecord,
    body: &AgentKeyPairRequestBody,
) -> Result<(), AppError> {
    let current = agent_record
        .runtime_key_request
        .as_ref()
        .ok_or_else(|| pairing_failed_precondition("runtime candidate is no longer pending"))?;
    let payload =
        arkret_models_collaboration::events_payloads::agent::AgentKeyAuthorizePayload::try_from(
            &body.authorize_event.event,
        )
        .map_err(|error| AppError::param_invalid(error.to_string()))?;
    if current.pairing_request_id != body.pairing_request_id
        || agent_record.approval_request_id.as_ref() != Some(&body.approval_request_id)
        || current.agent_id != payload.agent_id
        || current.verification_method != payload.verification_method
        || current.public_key != payload.public_key
        || current.runtime_attestation != payload.runtime_attestation
    {
        return Err(pairing_failed_precondition(
            "approval does not match the frozen runtime candidate",
        ));
    }
    let digest = arkret_models_collaboration::agent_scope::agent_runtime_key_binding_digest(
        &current.agent_id,
        &current.pairing_request_id,
        &current.verification_method,
        &current.public_key,
        current.runtime_attestation.as_ref(),
    )
    .map_err(|error| AppError::param_invalid(error.to_string()))?;
    if agent_record.runtime_key_binding_digest.as_deref() != Some(digest.as_str()) {
        return Err(pairing_failed_precondition(
            "runtime candidate changed after controller discovery",
        ));
    }
    Ok(())
}

fn ensure_controller_pairing_authorization(
    event: &arkret_wire::Event,
    payload: &arkret_models_collaboration::events_payloads::agent::AgentKeyAuthorizePayload,
    record: &AgentPrincipalRecord,
    service_id: &str,
) -> Result<(), AppError> {
    let controller = &record.controller_principal_id;
    if event.actor_id != pairing_account_actor(&record.id, service_id)?
        || event.executed_by.as_ref() != Some(&pairing_account_actor(controller, service_id)?)
        || event.authorization_ref.as_ref().map(|value| value.as_str())
            != Some(record.controller_authorization_ref.as_str())
        || event.realm_id.as_str() != record.principal_control_realm_id
        || payload.accountable_principal_id.as_str() != controller
    {
        return Err(AppError::capability_denied(
            "authorize Event must bind the exact Agent Account, controller, delegation and PCR",
        ));
    }
    if !payload
        .audience
        .iter()
        .any(|audience| audience == service_id)
    {
        return Err(AppError::param_invalid(
            "authorize_event.payload.audience must include this Station",
        ));
    }
    if payload
        .expires_at
        .is_some_and(|expiry| expiry <= chrono::Utc::now())
    {
        return Err(pairing_failed_precondition(
            "authorize_event payload has expired",
        ));
    }
    let evidence = &payload.approval_evidence;
    if evidence.kind
        != arkret_models_collaboration::events_payloads::agent::AgentKeyApprovalEvidenceKind::PairingRequest
        || evidence.evidence_ref.is_some()
        || evidence.approved_by.as_ref().map(|value| value.as_str()) != Some(controller.as_str())
        || evidence.pairing_request_id.as_ref().map(|value| value.as_str())
            != Some(required_pairing_request_id(record)?)
    {
        return Err(AppError::param_invalid(
            "authorize_event.payload.approval_evidence must bind the current controller pairing request",
        ));
    }
    let expected = pairing_request_binding_digest(
        record,
        controller,
        &record.id,
        &payload.verification_method,
        service_id,
    )?;
    if evidence
        .request_canonical_digest
        .as_ref()
        .map(|value| value.as_str())
        != Some(expected.as_str())
    {
        return Err(AppError::param_invalid(
            "authorize_event.payload.approval_evidence.request_canonical_digest must bind the pairing request",
        ));
    }
    Ok(())
}

pub(super) struct AccountNotificationContext {
    notification_id: arkret_wire::NotificationId,
    recipient_actor_id: arkret_wire::ActorId,
    controller_account_pk: coland_storage::AccountPk,
    recipient_id: arkret_wire::DidCoreId,
    approval_request_id: arkret_wire::OpaqueLocalId,
}

pub(super) fn account_notification_context(
    agent_record: &AgentPrincipalRecord,
) -> Option<AccountNotificationContext> {
    Some(AccountNotificationContext {
        notification_id: arkret_wire::NotificationId::new(ids::format_typed_uuid(
            "notification",
            &agent_record.approval_notification_id?,
        ))
        .ok()?,
        recipient_actor_id: arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            arkret_identifiers::DidCoreId::new(agent_record.controller_principal_id.clone())
                .ok()?,
            arkret_identifiers::DidCoreId::new(agent_record.recipient_id.clone()?).ok()?,
        )),
        controller_account_pk: agent_record.controller_account_pk?,
        recipient_id: arkret_identifiers::DidCoreId::new(agent_record.recipient_id.clone()?)
            .ok()?,
        approval_request_id: agent_record.approval_request_id.clone()?,
    })
}

pub(super) async fn persist_terminal_account_notification(
    state: &AppState,
    context: AccountNotificationContext,
    reason: arkret_models_collaboration::sync_frames::account_subscribe::AgentRuntimeApprovalRemovalReason,
) -> Result<(), AppError> {
    let account_id = context
        .recipient_actor_id
        .as_account_id()
        .cloned()
        .ok_or_else(|| {
            AppError::internal("terminal approval notification requires an Account Actor")
        })?;
    let delta =
        arkret_models_collaboration::sync_frames::account_subscribe::NotificationDelta::try_new(
            arkret_models_collaboration::objects::read_receipts::NotificationIdentity::AgentApproval(
                context.notification_id,
            ),
            arkret_models_collaboration::sync_frames::account_subscribe::NotificationDeltaAction::Remove,
            Some(
                arkret_models_collaboration::sync_frames::account_subscribe::NotificationData::AgentRuntimeApprovalRemoval(
                    arkret_models_collaboration::sync_frames::account_subscribe::AgentRuntimeApprovalNotificationRemovalData {
                        reason,
                    },
                ),
            ),
        )
        .map_err(|error| {
            AppError::internal(format!("terminal notification delta is invalid: {error}"))
        })?;
    state
        .deliveries()
        .store_account_delta(
            coland_services::delivery::StoreAccountNotificationDeltaCommand {
                record: coland_services::delivery::AccountNotificationDeltaWrite {
                    delta,
                    recipient_actor_id: context.recipient_actor_id,
                    controller_account_pk: context.controller_account_pk,
                    recipient_id: context.recipient_id.clone(),
                    source_account_artifact_id: context.approval_request_id.to_string(),
                },
            },
        )
        .await
        .map_err(|error| {
            AppError::internal(format!(
                "terminal approval notification save failed: {error}"
            ))
        })?;
    let _ = state.publish_event_notification(crate::state::EventNotification::account(
        account_id,
        context.recipient_id,
    ));
    Ok(())
}

/// Persist the terminal notification delta before clearing the correlation
/// retained by the activation compare-and-set. If the process crashes after
/// either write, an exact pairing retry observes the accepted Event, repeats
/// the idempotent remove delta, and then clears the same approval id. This
/// prevents a durable activation from leaving a permanently visible approval.
async fn finalize_terminal_account_notification(
    state: &AppState,
    agent_id: &str,
    context: AccountNotificationContext,
    reason: arkret_models_collaboration::sync_frames::account_subscribe::AgentRuntimeApprovalRemovalReason,
) -> Result<(), AppError> {
    let approval_request_id = context.approval_request_id.clone();
    persist_terminal_account_notification(state, context, reason).await?;
    state
        .agent_pairings()
        .clear_approval_notification(agent_id, &approval_request_id)
        .await
        .map_err(|error| {
            AppError::internal(format!(
                "terminal approval correlation cleanup failed: {error}"
            ))
        })?;
    Ok(())
}

/// Admit the exact controller-signed `ak.agent.key.authorize` in the Agent
/// PCR. The Agent control unit rechecks the provision binding, the
/// controller's active device, a non-terminal lifecycle and the exact active
/// set it supersedes at the Agent PCR cut; activation follows the accepted
/// Commit through the reconciler.
pub(super) async fn submit_production_key_authorize_event(
    state: &AppState,
    session: &SessionRecord,
    agent_record: &AgentPrincipalRecord,
    submission: arkret_wire::EventAdmissionSubmission,
) -> Result<String, AppError> {
    let event = &submission.event;
    if event.kind != arkret_wire::EventKind::AgentKeyAuthorize
        || event.realm_id.as_str() != agent_record.principal_control_realm_id
        || event.authorization_ref.as_deref()
            != Some(agent_record.controller_authorization_ref.as_str())
    {
        return Err(pairing_failed_precondition(
            "authorize Event is not the Agent PCR key authorization of this pairing",
        ));
    }
    super::dev_fanout::submit_signed_agent_event(state, session, submission).await
}

fn pairing_account_actor(principal: &str, station: &str) -> Result<arkret_wire::ActorId, AppError> {
    Ok(arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        arkret_wire::DidCoreId::new(principal.to_owned())
            .map_err(|_| AppError::capability_denied("pairing principal is invalid"))?,
        arkret_wire::DidCoreId::new(station.to_owned())
            .map_err(|_| AppError::capability_denied("pairing Station is invalid"))?,
    )))
}

fn envelope_actor(envelope: &Value, field: &str) -> Option<arkret_wire::ActorId> {
    serde_json::from_value(envelope.get(field)?.clone()).ok()
}

#[cfg(test)]
pub(super) fn ensure_key_authorize_event_matches_request(
    envelope: &Value,
    controller: &str,
    agent_record: &AgentPrincipalRecord,
    agent_id: &str,
    verification_method: &str,
    authorized_public_key_digest: &str,
    service_id: &str,
) -> Result<(), AppError> {
    if envelope.get("kind").and_then(Value::as_str)
        != Some(arkret_wire::event_kind_str::AGENT_KEY_AUTHORIZE)
    {
        return Err(AppError::param_invalid(
            "authorize_event.kind must be ak.agent.key.authorize",
        ));
    }
    if envelope_actor(envelope, "actor_id") != Some(pairing_account_actor(agent_id, service_id)?) {
        return Err(AppError::capability_denied(
            "authorize_event.actor_id must match the Agent Account",
        ));
    }
    if envelope_actor(envelope, "executed_by")
        != Some(pairing_account_actor(controller, service_id)?)
    {
        return Err(AppError::capability_denied(
            "authorize_event.executed_by must match the authenticated controller Account",
        ));
    }
    let expected_authorization_ref = agent_record.controller_authorization_ref.as_str();
    if expected_authorization_ref.is_empty() {
        return Err(AppError::capability_denied(
            "Agent has no controller delegation binding",
        ));
    }
    if envelope.get("authorization_ref").and_then(Value::as_str) != Some(expected_authorization_ref)
    {
        return Err(AppError::capability_denied(
            "authorize_event.authorization_ref must match the Agent DID controller delegation",
        ));
    }
    let expected_realm_id = agent_record.principal_control_realm_id.as_str();
    if expected_realm_id.is_empty() {
        return Err(AppError::capability_denied(
            "Agent has no authoritative Principal Control Realm binding",
        ));
    }
    if envelope.get("realm_id").and_then(Value::as_str) != Some(expected_realm_id) {
        return Err(AppError::capability_denied(
            "authorize_event.realm_id must match the Agent Principal Control Realm",
        ));
    }
    let payload = envelope
        .get("payload")
        .ok_or_else(|| AppError::param_invalid("authorize_event.payload is required"))?;
    if payload.get("agent_id").and_then(Value::as_str) != Some(agent_id) {
        return Err(AppError::param_invalid(
            "authorize_event.payload.agent_id must match the pairing request",
        ));
    }
    if payload.get("verification_method").and_then(Value::as_str) != Some(verification_method) {
        return Err(AppError::param_invalid(
            "authorize_event.payload.verification_method must match the pairing request",
        ));
    }
    if payload
        .get("accountable_principal_id")
        .and_then(Value::as_str)
        != Some(controller)
    {
        return Err(AppError::capability_denied(
            "authorize_event.payload.accountable_principal_id must match the authenticated controller",
        ));
    }
    ensure_authorize_event_scope_within_requested(agent_record, payload)?;
    let audience = payload
        .get("audience")
        .and_then(Value::as_array)
        .ok_or_else(|| AppError::param_invalid("authorize_event.payload.audience is required"))?;
    if !audience
        .iter()
        .any(|value| value.as_str() == Some(service_id))
    {
        return Err(AppError::param_invalid(
            "authorize_event.payload.audience must include this Station",
        ));
    }
    if let Some(expires_at) = payload.get("expires_at") {
        let expires_at = expires_at
            .as_str()
            .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
            .ok_or_else(|| {
                AppError::param_invalid("authorize_event.payload.expires_at must be rfc3339")
            })?;
        if expires_at.with_timezone(&chrono::Utc) <= chrono::Utc::now() {
            return Err(pairing_failed_precondition(
                "authorize_event payload has expired",
            ));
        }
    }
    let public_key = payload
        .get("public_key")
        .ok_or_else(|| AppError::param_invalid("authorize Event omits public_key"))?;
    let digest = arkret_signatures::agent::agent_runtime_public_key_digest(public_key)
        .map_err(|error| AppError::param_invalid(error.to_string()))?;
    if digest.as_str() != authorized_public_key_digest {
        return Err(AppError::param_invalid(
            "authorize Event raw key differs from frozen candidate",
        ));
    }
    let expected_digest = pairing_request_binding_digest(
        agent_record,
        controller,
        agent_id,
        verification_method,
        service_id,
    )?;
    let approval_evidence = payload.get("approval_evidence").ok_or_else(|| {
        AppError::param_invalid("authorize_event.payload.approval_evidence is required")
    })?;
    if approval_evidence.get("kind").and_then(Value::as_str) != Some("pairing_request") {
        return Err(AppError::param_invalid(
            "authorize_event.payload.approval_evidence.kind must be pairing_request",
        ));
    }
    if approval_evidence.get("evidence_ref").is_some() {
        return Err(AppError::param_invalid(
            "authorize_event.payload.approval_evidence.ref must be absent for pairing_request evidence",
        ));
    }
    if approval_evidence.get("approved_by").and_then(Value::as_str) != Some(controller) {
        return Err(AppError::capability_denied(
            "authorize_event.payload.approval_evidence.approved_by must match the authenticated controller",
        ));
    }
    let pairing_request_id = required_pairing_request_id(agent_record)?;
    if approval_evidence
        .get("pairing_request_id")
        .and_then(Value::as_str)
        != Some(pairing_request_id)
    {
        return Err(AppError::param_invalid(
            "authorize_event.payload.approval_evidence.pairing_request_id must match the pairing request",
        ));
    }
    if approval_evidence
        .get("request_canonical_digest")
        .and_then(Value::as_str)
        != Some(expected_digest.as_str())
    {
        return Err(AppError::param_invalid(
            "authorize_event.payload.approval_evidence.request_canonical_digest must bind the pairing request",
        ));
    }
    Ok(())
}

fn agent_key_pair_request_digest(body: &AgentKeyPairRequestBody) -> Result<String, AppError> {
    let value = serde_json::to_value(body)
        .map_err(|error| AppError::param_invalid(format!("pairing request invalid: {error}")))?;
    let canonical = arkret_canonical::canonical_json_bytes(&value).map_err(|error| {
        AppError::param_invalid(format!("pairing request canonicalization failed: {error}"))
    })?;
    Ok(arkret_canonical::sha256_digest(&canonical))
}

pub(super) fn ensure_pairing_request_open(
    agent_record: &AgentPrincipalRecord,
) -> Result<(), AppError> {
    // Only the terminal lifecycle intent forbids completing a pairing
    // (key-management.md §3.6.1). Both active and paused agents may complete a
    // bootstrap or replacement handle; completion atomically supersedes any
    // prior active key with no forced pause. renew_pairing rotates
    // `pairing_request_id` while leaving the last consumed handle in
    // `paired_pairing_request_id`, so a live handle exists iff the current one
    // has not yet been consumed.
    if agent_record.state == AgentLifecycleState::Deactivated {
        return Err(
            pairing_failed_precondition("agent is not accepting runtime key pairing")
                .with_reason_code(arkret_wire::ReasonCode::AGENT_DEACTIVATED),
        );
    }
    if !agent_pairing_handle_is_open(agent_record) {
        return Err(pairing_failed_precondition(
            "agent has no open runtime key pairing handle",
        ));
    }
    let expires_at = required_pairing_expires_at(agent_record)?;
    if expires_at <= chrono::Utc::now() {
        return Err(pairing_failed_precondition("pairing request has expired")
            .with_reason_code(arkret_wire::ReasonCode::PAIRING_REQUEST_EXPIRED));
    }
    Ok(())
}

/// Whether the agent record carries an unconsumed pairing handle. The
/// completion transaction stamps `paired_pairing_request_id` with the handle
/// it consumed; renew_pairing installs a fresh `pairing_request_id` without
/// touching that stamp. A current handle that differs from the last consumed
/// one is therefore a live, single-use pairing handle.
pub(super) fn agent_pairing_handle_is_open(agent_record: &AgentPrincipalRecord) -> bool {
    let current = agent_record.pairing_request_id.as_deref();
    let consumed = agent_record.paired_pairing_request_id.as_deref();
    current.is_some() && current != consumed
}

pub(super) fn agent_record_reserves_selector_slug(
    agent_record: &AgentPrincipalRecord,
    _now: &chrono::DateTime<chrono::Utc>,
) -> bool {
    // Pairing expiry, unbinding and missing keys do not end the identity:
    // active/paused Agents can still renew pairing. Only terminal lifecycle
    // releases the name; retained key/handle history must not keep it reserved.
    agent_record.state != AgentLifecycleState::Deactivated
}

pub(super) fn ensure_pairing_request_id_matches(
    agent_record: &AgentPrincipalRecord,
    supplied_pairing_request_id: &str,
) -> Result<(), AppError> {
    let expected = required_pairing_request_id(agent_record)?;
    if expected != supplied_pairing_request_id {
        return Err(pairing_failed_precondition(
            "pairing_request_id does not match the open pairing request",
        ));
    }
    Ok(())
}

pub(super) fn runtime_key_request_for_controller(
    body: &AgentRuntimeApprovalRequestBody,
    approval_request_id: arkret_wire::OpaqueLocalId,
) -> arkret_models_collaboration::agent_operations::AgentRuntimeApprovalControllerProjection {
    arkret_models_collaboration::agent_operations::AgentRuntimeApprovalControllerProjection {
        pairing_request_id: body.pairing_request_id.clone(),
        agent_id: body.agent_id.clone(),
        verification_method: body.verification_method.clone(),
        public_key: body.public_key.clone(),
        approval_request_id,
        runtime_key_binding_digest: body.proof_of_possession.runtime_key_binding_digest.clone(),
        runtime_attestation: body.runtime_attestation.clone(),
    }
}

fn runtime_attestation_value(
    runtime_attestation: Option<&arkret_models_collaboration::events_payloads::agent::AgentKeyAuthorizePayloadRuntimeAttestation>,
) -> Result<Option<Value>, AppError> {
    runtime_attestation
        .map(serde_json::to_value)
        .transpose()
        .map_err(|error| AppError::param_invalid(format!("runtime_attestation invalid: {error}")))
}

pub(super) fn runtime_ed25519_public_key(
    public_key: &PublicKey,
    verification_method: &str,
) -> Result<[u8; 32], AppError> {
    let verification_method = arkret_wire::DidUrl::new(verification_method.to_owned())
        .map_err(|error| AppError::param_invalid(error.to_string()))?;
    arkret_signatures::agent::validate_agent_runtime_public_key(public_key, &verification_method)
        .map(|validated| validated.raw_public_key)
        .map_err(|error| AppError::param_invalid(format!("public_key invalid: {error}")))
}

pub(super) fn verify_runtime_key_pair_proof_of_possession(
    body: &AgentKeyPairRequestBody,
    agent_record: &AgentPrincipalRecord,
    agent_id: &str,
    service_id: &str,
) -> Result<(), AppError> {
    ensure_current_runtime_key_request_matches(agent_record, body)?;
    let candidate = agent_record
        .runtime_key_request
        .as_ref()
        .ok_or_else(|| pairing_failed_precondition("frozen runtime candidate is missing"))?;
    verify_runtime_key_proof_of_possession(
        &candidate.pairing_request_id,
        &candidate.verification_method,
        &candidate.public_key,
        &candidate.proof_of_possession,
        candidate.runtime_attestation.as_ref(),
        required_pairing_code(agent_record)?,
        required_pairing_expires_at(agent_record)?,
        agent_id,
        service_id,
        agent_record.runtime_proof_verified_at.ok_or_else(|| {
            pairing_failed_precondition("runtime proof verification time is missing")
        })?,
    )
}

fn verify_runtime_approval_proof_of_possession(
    body: &AgentRuntimeApprovalRequestBody,
    agent_record: &AgentPrincipalRecord,
    agent_id: &str,
    service_id: &str,
    proof_verified_at: chrono::DateTime<chrono::Utc>,
) -> Result<(), AppError> {
    verify_runtime_key_proof_of_possession(
        &body.pairing_request_id,
        &body.verification_method,
        &body.public_key,
        &body.proof_of_possession,
        body.runtime_attestation.as_ref(),
        required_pairing_code(agent_record)?,
        required_pairing_expires_at(agent_record)?,
        agent_id,
        service_id,
        proof_verified_at,
    )
}

fn verify_runtime_key_proof_of_possession(
    pairing_request_id: &arkret_wire::OpaqueLocalId,
    verification_method: &arkret_wire::DidUrl,
    public_key: &PublicKey,
    proof_of_possession: &arkret_models_collaboration::agent_scope::AgentRuntimeKeyPossessionProof,
    runtime_attestation: Option<&arkret_models_collaboration::events_payloads::agent::AgentKeyAuthorizePayloadRuntimeAttestation>,
    pairing_code: &str,
    pairing_expires_at: chrono::DateTime<chrono::Utc>,
    agent_id: &str,
    service_id: &str,
    proof_verified_at: chrono::DateTime<chrono::Utc>,
) -> Result<(), AppError> {
    let agent_id = arkret_wire::DidCoreId::new(agent_id.to_owned())
        .map_err(|error| AppError::param_invalid(format!("agent_id invalid: {error}")))?;
    let service_id = arkret_wire::DidCoreId::new(service_id.to_owned())
        .map_err(|error| AppError::internal(format!("configured service_id invalid: {error}")))?;
    let public_key_bytes = runtime_ed25519_public_key(public_key, verification_method)?;
    if proof_of_possession.audience_id != service_id {
        return Err(AppError::param_invalid(
            "proof_of_possession.audience_id must match this Station",
        ));
    }
    let expected_binding =
        arkret_models_collaboration::agent_scope::agent_runtime_key_binding_digest(
            &agent_id,
            pairing_request_id,
            verification_method,
            public_key,
            runtime_attestation,
        )
        .map_err(|error| {
            AppError::param_invalid(format!("runtime key binding invalid: {error}"))
        })?;
    let signing_bytes = proof_of_possession
        .validate_shape(
            &agent_id,
            pairing_request_id,
            verification_method,
            public_key,
            &expected_binding,
            pairing_code,
            pairing_expires_at,
            proof_verified_at,
        )
        .map_err(|error| {
            AppError::param_invalid(format!("proof_of_possession invalid: {error}"))
        })?;
    let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&public_key_bytes)
        .map_err(|error| AppError::param_invalid(format!("public_key invalid: {error}")))?;
    let signature_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(proof_of_possession.signature.as_bytes())
        .map_err(|_| AppError::param_invalid("proof_of_possession.signature is not base64url"))?;
    let signature = ed25519_dalek::Signature::from_slice(&signature_bytes).map_err(|_| {
        AppError::param_invalid("proof_of_possession.signature must be a 64-byte Ed25519 signature")
    })?;
    verifying_key
        .verify_strict(&signing_bytes, &signature)
        .map_err(|_| AppError::param_invalid("proof_of_possession.signature is invalid"))?;
    Ok(())
}

pub(super) fn pairing_failed_precondition(reason: impl Into<String>) -> AppError {
    let reason = reason.into();
    crate::app_error!(FailedPrecondition, reason.clone()).with_reason_detail(reason)
}

fn required_pairing_request_id(record: &AgentPrincipalRecord) -> Result<&str, AppError> {
    record
        .pairing_request_id
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| incomplete_pairing_metadata("pairing_request_id"))
}

fn required_pairing_code(record: &AgentPrincipalRecord) -> Result<&str, AppError> {
    record
        .pairing_code
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| incomplete_pairing_metadata("pairing_code"))
}

fn required_pairing_expires_at(
    record: &AgentPrincipalRecord,
) -> Result<chrono::DateTime<chrono::Utc>, AppError> {
    record
        .pairing_expires_at
        .ok_or_else(|| incomplete_pairing_metadata("pairing_expires_at"))
}

fn incomplete_pairing_metadata(field: &str) -> AppError {
    pairing_failed_precondition("agent pairing metadata is incomplete")
        .with_reason_detail(format!("missing {field}"))
}

pub(super) fn runtime_public_key_digest(
    public_key: &PublicKey,
    verification_method: &str,
) -> Result<String, AppError> {
    let verification_method = arkret_wire::DidUrl::new(verification_method.to_owned())
        .map_err(|error| AppError::param_invalid(error.to_string()))?;
    arkret_signatures::agent::validate_agent_runtime_public_key(public_key, &verification_method)
        .map(|validated| validated.public_key_digest.as_str().to_owned())
        .map_err(|error| AppError::param_invalid(format!("public_key is invalid: {error}")))
}

#[cfg(test)]
pub(super) fn ensure_authorize_event_scope_within_requested(
    agent_record: &AgentPrincipalRecord,
    payload: &Value,
) -> Result<(), AppError> {
    let scope = payload.get("agent_key_scope").ok_or_else(|| {
        AppError::param_invalid("authorize_event.payload.agent_key_scope is required")
    })?;
    let actions = scope
        .get("actions")
        .and_then(Value::as_array)
        .filter(|actions| !actions.is_empty())
        .ok_or_else(|| {
            AppError::param_invalid("authorize_event.payload.agent_key_scope.actions is required")
        })?;
    if actions
        .iter()
        .any(|action| action.as_str().is_none_or(str::is_empty))
    {
        return Err(AppError::param_invalid(
            "authorize_event.payload.agent_key_scope.actions must be non-empty strings",
        ));
    }
    if !agent_key_scope_within_requested_scope(agent_record, scope) {
        return Err(AppError::param_invalid(
            "authorize_event.payload.agent_key_scope must be within the provisioned requested_scope",
        ));
    }
    Ok(())
}

pub(super) fn pairing_request_binding_digest(
    agent_record: &AgentPrincipalRecord,
    controller: &str,
    agent_id: &str,
    _verification_method: &str,
    service_id: &str,
) -> Result<String, AppError> {
    let pairing_request_id =
        arkret_wire::OpaqueLocalId::new(required_pairing_request_id(agent_record)?.to_owned())
            .map_err(|error| {
                AppError::internal(format!("stored pairing request id invalid: {error}"))
            })?;
    let approval_request_id = agent_record
        .approval_request_id
        .as_ref()
        .ok_or_else(|| incomplete_pairing_metadata("approval_request_id"))?;
    let expires_at = required_pairing_expires_at(agent_record)?;
    let controller = arkret_wire::DidCoreId::new(controller.to_owned())
        .map_err(|error| AppError::param_invalid(format!("controller DID invalid: {error}")))?;
    let agent_id = arkret_wire::DidCoreId::new(agent_id.to_owned())
        .map_err(|error| AppError::param_invalid(format!("agent DID invalid: {error}")))?;
    let audience = arkret_wire::DidCoreId::new(service_id.to_owned()).map_err(|error| {
        AppError::internal(format!("configured service core_id invalid: {error}"))
    })?;
    let runtime_key_binding_digest = Hash::new(
        agent_record
            .runtime_key_binding_digest
            .clone()
            .ok_or_else(|| incomplete_pairing_metadata("runtime_key_binding_digest"))?,
    )
    .map_err(|_| AppError::internal("stored runtime key binding digest is invalid"))?;
    arkret_models_collaboration::agent_operations::agent_key_pairing_request_binding_digest(
        arkret_wire::ServiceOperationId::GATE_ACCOUNT_COMMAND_PAIR_AGENT_KEY_V1,
        &controller,
        &agent_id,
        &pairing_request_id,
        approval_request_id,
        expires_at,
        &audience,
        &runtime_key_binding_digest,
    )
    .map(|digest| digest.as_str().to_owned())
    .map_err(|error| {
        AppError::internal(format!(
            "pairing binding digest canonicalization failed: {error}"
        ))
    })
}

/// Generate a uniform eight-digit decimal code, retaining leading zeroes.
pub(super) fn generate_pairing_code() -> String {
    use rand::RngExt;
    format!("{:08}", rand::rng().random_range(0u32..100_000_000))
}

pub(super) fn agent_pairing_token_appears_in_url(req: &Request) -> bool {
    req.uri().query().is_some_and(|query| {
        query.contains("pairing_token=")
            || query.contains("pairing_request_id=")
            || query.contains("token=")
    })
}

pub(super) fn is_agent_pairing_token_shape(value: &str) -> bool {
    (22..=512).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

pub(super) fn decode_agent_pairing_token(pairing_token: &str) -> Option<Value> {
    let bytes = URL_SAFE_NO_PAD.decode(pairing_token.as_bytes()).ok()?;
    serde_json::from_slice::<Value>(&bytes).ok()
}

pub(super) fn agent_pairing_not_found() -> AppError {
    AppError::not_found("agent pairing token not found")
}

#[cfg(test)]
mod requested_scope_tests {
    use super::*;

    #[test]
    fn pairing_identity_preserves_complete_did_and_account_across_retries() {
        let delegation = arkret_wire::DidUrl::new(
            "did:webvh:z6mkfixture:agent.example#managed-controller".to_owned(),
        )
        .unwrap();
        let account: arkret_wire::AccountId = serde_json::from_value(json!({
            "principal_id": "ak:did_core:web:controller.example",
            "station_id": "ak:did_core:web:station.example"
        }))
        .unwrap();
        let first = pairing_runtime_identity(&delegation, account.clone(), "pair-1").unwrap();
        let retry = pairing_runtime_identity(&delegation, account.clone(), "pair-1").unwrap();
        let replacement = pairing_runtime_identity(&delegation, account.clone(), "pair-2").unwrap();
        assert_eq!(first.controller_account_id, account);
        assert_eq!(first.verification_method, retry.verification_method);
        assert_ne!(first.verification_method, replacement.verification_method);
        assert!(
            first
                .verification_method
                .as_str()
                .starts_with("did:webvh:z6mkfixture:agent.example#runtime-")
        );
        assert!(!first.verification_method.as_str().contains("ak:device:"));
    }

    fn agent_record(requested_scope: Option<Value>) -> AgentPrincipalRecord {
        let mut record = AgentPrincipalRecord::new(
            "ak:did_core:web:agent.example".to_owned(),
            "ak:did_core:web:controller.example".to_owned(),
            "ak:realm:ASt7OPzypn1OkvoZOKtcz8H8ydfZ7fLDhL3nI1jLWTfX".to_owned(),
            arkret_wire::DidUrl::new("did:web:controller.example#controller").unwrap(),
            AgentLifecycleState::Active,
            chrono::Utc::now(),
        );
        record.requested_scope = requested_scope;
        record
    }

    #[test]
    fn authorize_scope_may_narrow_but_cannot_widen_provision_ceiling() {
        let approval = json!({
            "constraint_kind":"claim_based",
            "constraint_subkind":"approval",
            "effect":"allow",
            "controller_approval_required":true
        });
        let ceiling = json!({
            "actions": ["ak.message.create", "ak.self.events.command.submit.v1"],
            "resources": [{
                "kind": "operation",
                "operation": "ak.self.events.command.submit.v1"
            }],
            "constraints": [approval.clone()]
        });
        let payload = json!({
            "agent_key_scope": {
                "actions": ["ak.self.events.command.submit.v1"],
                "resources": ceiling["resources"].clone(),
                "constraints": [approval]
            }
        });
        assert!(
            ensure_authorize_event_scope_within_requested(
                &agent_record(Some(ceiling.clone())),
                &payload,
            )
            .is_ok()
        );

        let widened = json!({
            "agent_key_scope": {
                "actions": [
                    "ak.message.create",
                    "ak.reaction.add",
                    "ak.self.events.command.submit.v1"
                ],
                "resources": ceiling["resources"].clone(),
                "constraints": ceiling["constraints"].clone()
            }
        });
        assert!(
            ensure_authorize_event_scope_within_requested(
                &agent_record(Some(ceiling.clone())),
                &widened,
            )
            .is_err()
        );

        let dropped_constraint = json!({
            "agent_key_scope": {
                "actions": ["ak.self.events.command.submit.v1"],
                "resources": ceiling["resources"].clone()
            }
        });
        assert!(
            ensure_authorize_event_scope_within_requested(
                &agent_record(Some(ceiling.clone())),
                &dropped_constraint,
            )
            .is_err()
        );

        let escaped_resource = json!({
            "agent_key_scope": {
                "actions": ["ak.self.events.command.submit.v1"],
                "resources": [{
                    "kind": "operation",
                    "operation": "ak.self.committed_event.read.scan.v1"
                }],
                "constraints": ceiling["constraints"].clone()
            }
        });
        assert!(
            ensure_authorize_event_scope_within_requested(
                &agent_record(Some(ceiling)),
                &escaped_resource,
            )
            .is_err()
        );
        assert!(
            ensure_authorize_event_scope_within_requested(&agent_record(None), &payload).is_err()
        );
    }

    #[test]
    fn account_notification_context_restores_typed_ids_from_persisted_uuids() {
        let mut record = agent_record(None);
        record.approval_notification_id = Some(
            uuid::Uuid::parse_str("019f6131-3dc4-76f1-ade6-00f4225a8528")
                .expect("valid notification uuid"),
        );
        record.controller_account_pk = Some(coland_storage::AccountPk(1));
        record.recipient_id = Some("ak:did_core:web:coland.example".to_owned());
        record.approval_request_id =
            Some(arkret_wire::OpaqueLocalId::new("agent_runtime_approval:test").unwrap());

        let context = account_notification_context(&record).expect("complete notification context");

        assert_eq!(
            context.notification_id.as_str(),
            "ak:notification:019f6131-3dc4-76f1-ade6-00f4225a8528"
        );
        assert_eq!(context.controller_account_pk.get(), 1);
    }

    #[test]
    fn active_and_paused_agents_complete_pairing_without_forced_pause() {
        let now = chrono::Utc::now();
        let mut record = agent_record(None);
        record.pairing_request_id =
            Some(arkret_wire::OpaqueLocalId::new("agent_pairing_request:open").unwrap());
        record.pairing_expires_at = Some(now + chrono::Duration::minutes(5));

        // Both active and paused agents may complete an open bootstrap or
        // replacement handle; there is no forced pause (key-management.md
        // §3.6.1) and resume never interlocks with an open handle.
        record.state = AgentLifecycleState::Active;
        assert!(ensure_pairing_request_open(&record).is_ok());
        record.state = AgentLifecycleState::Paused;
        assert!(ensure_pairing_request_open(&record).is_ok());

        // Deactivation is terminal.
        record.state = AgentLifecycleState::Deactivated;
        assert!(ensure_pairing_request_open(&record).is_err());

        // A consumed handle is no longer open.
        record.state = AgentLifecycleState::Active;
        record.paired_pairing_request_id = record.pairing_request_id.clone();
        assert!(ensure_pairing_request_open(&record).is_err());

        // An expired handle is rejected.
        record.paired_pairing_request_id = None;
        record.pairing_expires_at = Some(now - chrono::Duration::seconds(1));
        assert!(ensure_pairing_request_open(&record).is_err());
    }
}

// The only serialized copy lives in the original encrypted vault. This is an
// internal custody record, never a request/response or public Event carrier.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentScopeCustodyMaterial {
    command: AgentKeyPairRequestBody,
    accepted_binding: coland_storage::AgentScopeAcceptedBinding,
    runtime_key_binding_digest: String,
    request_digest: String,
}

fn same_scope_command(
    left: &AgentKeyPairRequestBody,
    right: &AgentKeyPairRequestBody,
) -> Result<bool, AppError> {
    let left = serde_json::to_value(left)
        .map_err(|_| AppError::internal("private command encoding failed"))?;
    let right = serde_json::to_value(right)
        .map_err(|_| AppError::internal("private command encoding failed"))?;
    Ok(left == right)
}

fn custody_bytes(material: &AgentScopeCustodyMaterial) -> Result<Vec<u8>, AppError> {
    let value = serde_json::to_value(material)
        .map_err(|_| AppError::internal("private scope custody encoding failed"))?;
    arkret_canonical::canonical_json_bytes(&value)
        .map_err(|_| AppError::internal("private scope custody canonicalization failed"))
}

fn scope_custody_key(material: &AgentScopeCustodyMaterial) -> Result<String, AppError> {
    let disclosure = &material.command.requested_scope_disclosure;
    let tuple = serde_json::json!([
        disclosure.agent_id,
        material.accepted_binding.requested_scope_digest,
        disclosure.verifier_id,
        disclosure.audience,
        material.command.authorize_event.event.event_id,
        material.request_digest
    ]);
    let bytes = arkret_canonical::canonical_json_bytes(&tuple)
        .map_err(|_| AppError::internal("private scope custody address failed"))?;
    Ok(format!(
        "{}:{}",
        material.command.authorize_event.event.event_id,
        arkret_canonical::sha256_digest(&bytes)
    ))
}

fn validate_custody_material(
    material: &AgentScopeCustodyMaterial,
    state: &AppState,
) -> Result<(), AppError> {
    let command = &material.command;
    let disclosure = &command.requested_scope_disclosure;
    let binding = &material.accepted_binding;
    disclosure
        .validate()
        .map_err(|_| AppError::capability_denied("private scope evidence is malformed"))?;
    let digest = arkret_signatures::agent::agent_requested_scope_digest(
        &disclosure.agent_id,
        &disclosure.controller_principal_id,
        &disclosure.requested_scope,
    )
    .map_err(|_| AppError::capability_denied("private scope evidence digest is invalid"))?;
    let event = &command.authorize_event.event;
    let payload =
        arkret_models_collaboration::events_payloads::agent::AgentKeyAuthorizePayload::try_from(
            event,
        )
        .map_err(|_| AppError::capability_denied("private scope authorize material is invalid"))?;
    event
        .verify_event_id_matches_content_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
        .map_err(|_| AppError::capability_denied("private scope authorize content differs"))?;
    validate_agent_runtime_key_scopes(&disclosure.requested_scope, &payload.agent_key_scope)?;
    if payload.agent_id != disclosure.agent_id
        || payload.accountable_principal_id != disclosure.controller_principal_id
        || event.realm_id != *binding.pcr_genesis_ref.stream_ref.realm_id()
        || event
            .executed_by
            .as_ref()
            .and_then(arkret_wire::ActorId::as_account_id)
            != Some(&binding.controller_account)
    {
        return Err(AppError::capability_denied(
            "private scope authorizing principal differs",
        ));
    }
    let request_uuid = command
        .pairing_request_id
        .as_str()
        .strip_prefix("agent_pairing_request:")
        .ok_or_else(|| AppError::capability_denied("private scope pairing binding is invalid"))?;
    if digest != binding.requested_scope_digest
        || disclosure.controller_principal_id != binding.controller_account.principal_id
        || binding.controller_account.station_id != state.service_core_id()
        || disclosure.verifier_id.as_str() != state.service_id()
        || disclosure.audience.as_str()
            != arkret_wire::ServiceOperationId::GATE_ACCOUNT_COMMAND_PAIR_AGENT_KEY_V1
        || disclosure.challenge.as_str() != command.pairing_request_id.as_str()
        || disclosure.request_id.as_str() != format!("ak:request:{request_uuid}")
        || binding.verified_at < disclosure.issued_at
        || binding.verified_at > disclosure.expires_at
        || agent_key_pair_request_digest(command)? != material.request_digest
        || arkret_wire::project_did_to_core_id(&binding.initial_resolution.did)
            .ok()
            .as_ref()
            != Some(&disclosure.agent_id)
        || binding.initial_resolution.did != binding.binding_resolution.did
        || !binding.initial_resolution.version_id.starts_with("1-")
        || !binding.binding_resolution.version_id.starts_with("2-")
    {
        return Err(AppError::capability_denied(
            "private scope evidence binding differs",
        ));
    }
    // This only verifies the original transcript consistency, not the current
    // Device signature or today's presentation window. Those were verified on
    // first receipt; current key/lifecycle checks are independent.
    if !disclosure.proofs.iter().any(|proof| {
        proof.created_at >= disclosure.issued_at
            && proof.created_at <= disclosure.expires_at
            && disclosure.canonical_proof_binding_bytes(proof).is_ok()
    }) {
        return Err(AppError::capability_denied(
            "private scope evidence lacks its frozen proof",
        ));
    }
    Ok(())
}

fn load_scope_custody(
    state: &AppState,
    reference: &coland_storage::AgentScopeCustodyRef,
) -> Result<AgentScopeCustodyMaterial, AppError> {
    let bytes = state
        .verifier_private_keystore()?
        .load(&reference.key_ref)
        .map_err(|_| AppError::capability_denied("private scope custody is unavailable"))?;
    if arkret_canonical::sha256_digest(bytes.as_ref()) != reference.content_digest.as_str() {
        return Err(AppError::capability_denied(
            "private scope custody integrity differs",
        ));
    }
    let material: AgentScopeCustodyMaterial = serde_json::from_slice(bytes.as_ref())
        .map_err(|_| AppError::capability_denied("private scope custody is invalid"))?;
    if custody_bytes(&material)? != bytes.as_ref()
        || scope_custody_key(&material)? != reference.key_ref
    {
        return Err(AppError::capability_denied(
            "private scope custody canonical binding differs",
        ));
    }
    validate_custody_material(&material, state)?;
    Ok(material)
}

async fn retain_verified_scope_custody(
    state: &AppState,
    record: &AgentPrincipalRecord,
    body: &AgentKeyPairRequestBody,
) -> Result<coland_storage::AgentScopeCustodyRef, AppError> {
    let accepted_binding =
        Box::pin(validate_requested_scope_disclosure(body, record, state)).await?;
    let runtime_key_binding_digest = record
        .runtime_key_binding_digest
        .clone()
        .ok_or_else(|| pairing_failed_precondition("frozen runtime binding is missing"))?;
    let material = AgentScopeCustodyMaterial {
        command: body.clone(),
        accepted_binding,
        runtime_key_binding_digest,
        request_digest: agent_key_pair_request_digest(body)?,
    };
    validate_custody_material(&material, state)?;
    let key_ref = scope_custody_key(&material)?;
    let bytes = custody_bytes(&material)?;
    let winner = state
        .verifier_private_keystore()?
        .create_if_absent(&key_ref, &bytes)
        .map_err(|_| AppError::capability_denied("private scope durable custody failed"))?;
    let stored: AgentScopeCustodyMaterial = serde_json::from_slice(winner.as_ref())
        .map_err(|_| AppError::capability_denied("private scope custody winner is invalid"))?;
    let normalized =
        |binding: &coland_storage::AgentScopeAcceptedBinding| -> Result<Value, AppError> {
            let mut value = serde_json::to_value(binding)
                .map_err(|_| AppError::internal("private source encoding failed"))?;
            value
                .as_object_mut()
                .ok_or_else(|| AppError::internal("private source shape failed"))?
                .remove("verified_at");
            Ok(value)
        };
    if !same_scope_command(&stored.command, &material.command)?
        || stored.runtime_key_binding_digest != material.runtime_key_binding_digest
        || stored.request_digest != material.request_digest
        || normalized(&stored.accepted_binding)? != normalized(&material.accepted_binding)?
    {
        return Err(AppError::conflict(
            "private scope custody is bound to different exact material",
        ));
    }
    let reference = coland_storage::AgentScopeCustodyRef {
        key_ref,
        content_digest: Hash::new(arkret_canonical::sha256_digest(winner.as_ref()))
            .map_err(|_| AppError::internal("private scope custody digest failed"))?,
    };
    load_scope_custody(state, &reference)?;
    Ok(reference)
}

pub(crate) async fn verify_and_retain_agent_scope_custody(
    state: &AppState,
    body: &AgentKeyPairRequestBody,
) -> Result<coland_storage::AgentScopeCustodyRef, AppError> {
    let record = state
        .agent_pairings()
        .agent(body.requested_scope_disclosure.agent_id.as_str())
        .await
        .map_err(|_| AppError::internal("Agent pairing lookup failed"))?
        .ok_or_else(|| pairing_failed_precondition("Agent pairing is unavailable"))?;
    ensure_pairing_request_open(&record)?;
    ensure_current_runtime_key_request_matches(&record, body)?;
    let payload =
        arkret_models_collaboration::events_payloads::agent::AgentKeyAuthorizePayload::try_from(
            &body.authorize_event.event,
        )
        .map_err(|error| AppError::param_invalid(error.to_string()))?;
    ensure_controller_pairing_authorization(
        &body.authorize_event.event,
        &payload,
        &record,
        state.service_id(),
    )?;
    let controller =
        crate::routing::identity::agent_pcr::agent_controller_account(state, &record).await?;
    Box::pin(crate::state::verify_account_device_producer(
        state,
        &controller,
        &body.authorize_event.event,
    ))
    .await
    .map_err(|_| AppError::capability_denied("private scope authorize producer is invalid"))?;
    Box::pin(retain_verified_scope_custody(state, &record, body)).await
}

pub(crate) async fn qualified_agent_scope_evidence(
    state: &AppState,
    guard: &coland_storage::AgentEndpointGuard,
) -> Result<coland_storage::VerifiedAgentScopeEvidence, AppError> {
    let record = state
        .agent_pairings()
        .agent(guard.agent_id.as_str())
        .await
        .map_err(|_| AppError::internal("Agent custody lookup failed"))?
        .ok_or_else(|| AppError::capability_denied("Agent custody is unavailable"))?;
    // A same-key current authorization can retain the original immutable
    // qualified presentation. It cannot create a receipt or replace its bytes.
    let source_id = record
        .paired_request_digest
        .as_ref()
        .and(record.paired_pairing_request_id.as_ref())
        .ok_or_else(|| AppError::capability_denied("Agent qualified pairing is unavailable"))?;
    let receipts = state
        .agent_pairings()
        .qualified_scope_receipt_for_pairing(guard.agent_id.as_str(), source_id.as_str())
        .await
        .map_err(|_| AppError::internal("Agent qualified receipt lookup failed"))?
        .ok_or_else(|| AppError::capability_denied("Agent qualified receipt is unavailable"))?;
    if receipts.outcome.activation_state != AgentKeyPairActivationState::Active {
        return Err(AppError::capability_denied(
            "Agent qualified receipt is not active",
        ));
    }
    let reference = receipts
        .scope_custody_ref
        .as_ref()
        .ok_or_else(|| AppError::capability_denied("Agent qualified receipt lacks custody"))?;
    let material = load_scope_custody(state, reference)?;
    let controller =
        crate::routing::identity::agent_pcr::agent_controller_account(state, &record).await?;
    if material.command.requested_scope_disclosure.agent_id != guard.agent_id
        || material.accepted_binding.controller_account != controller
    {
        return Err(AppError::capability_denied(
            "Agent qualified custody binding differs",
        ));
    }
    let authorization = state
        .authority_commits()
        .committed_event(&material.command.authorize_event.event.event_id)
        .await
        .map_err(|_| AppError::internal("Agent original authorization source lookup failed"))?
        .ok_or_else(|| {
            AppError::capability_denied("Agent original authorization source is unavailable")
        })?;
    if authorization.event != material.command.authorize_event.event
        || authorization.commit.event_ref != authorization.event.event_id
        || authorization.commit.realm_id != guard.pcr_realm_id
        || material
            .accepted_binding
            .pcr_genesis_ref
            .stream_ref
            .realm_id()
            != &guard.pcr_realm_id
        || receipts.agent_id != guard.agent_id.as_str()
        || receipts.controller_principal_id != controller.principal_id.as_str()
        || receipts.authorize_event_ref != authorization.event.event_id.as_str()
        || receipts.request_digest != material.request_digest
        || receipts.runtime_key_binding_digest != material.runtime_key_binding_digest
        || receipts.pairing_request_id != material.command.pairing_request_id
        || receipts.approval_request_id != material.command.approval_request_id
    {
        return Err(AppError::capability_denied(
            "Agent original qualified receipt differs",
        ));
    }
    let accepted_authorization_ref = arkret_wire::CommittedEventRef {
        event_id: authorization.event.event_id.clone(),
        commit_id: authorization.commit.commit_id.clone(),
        stream_ref: authorization.commit.stream_ref.clone(),
        stream_position: authorization.commit.stream_position,
    };
    Ok(
        coland_storage::VerifiedAgentScopeEvidence::from_verified_custody(
            reference.clone(),
            material.command,
            material.accepted_binding,
            material.runtime_key_binding_digest,
            material.request_digest,
            accepted_authorization_ref,
        ),
    )
}

#[cfg(test)]
mod private_scope_custody_tests {
    use arkret_keystore::{EncryptedFileKeyStore, KeyStore};

    use super::*;

    struct VaultDirectory(std::path::PathBuf);
    impl VaultDirectory {
        fn new() -> Self {
            let path =
                std::env::temp_dir().join(format!("coland-private-scope-{}", uuid::Uuid::new_v4()));
            std::fs::create_dir(&path).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
            }
            Self(path)
        }
    }
    impl Drop for VaultDirectory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn imported_material(state: &AppState) -> AgentScopeCustodyMaterial {
        let (command, accepted_binding, runtime_key_binding_digest) =
            super::super::tests::imported_scope_custody_fixture(state.service_id());
        let request_digest = agent_key_pair_request_digest(&command).unwrap();
        let material = AgentScopeCustodyMaterial {
            command,
            accepted_binding,
            runtime_key_binding_digest,
            request_digest,
        };
        validate_custody_material(&material, state).unwrap();
        material
    }

    #[tokio::test]
    async fn qualified_agent_private_custody_encrypted_reopen_preserves_expired_presentation() {
        let directory = VaultDirectory::new();
        let master = rand::random();
        let path = directory.0.join("vault");
        let first = std::sync::Arc::new(
            EncryptedFileKeyStore::new(&path, crate::config::SERVICE_IDENTITY_KEYSTORE_APP, master)
                .unwrap(),
        );
        let state = AppState::new(
            crate::config::AppConfig::test_default(),
            coland_storage_postgres::Db { pool: None },
        )
        .with_verifier_private_keystore(first.clone());
        let material = imported_material(&state);
        assert!(material.command.requested_scope_disclosure.expires_at < chrono::Utc::now());
        let bytes = custody_bytes(&material).unwrap();
        let key_ref = scope_custody_key(&material).unwrap();
        let winner = first.create_if_absent(&key_ref, &bytes).unwrap();
        assert!(winner.as_ref() == bytes);
        let reference = coland_storage::AgentScopeCustodyRef {
            key_ref,
            content_digest: Hash::new(arkret_canonical::sha256_digest(&bytes)).unwrap(),
        };
        let disk = std::fs::read(&path).unwrap();
        assert!(
            !disk
                .windows(b"requested_scope".len())
                .any(|window| window == b"requested_scope")
        );
        drop(state);
        drop(first);
        let second = std::sync::Arc::new(
            EncryptedFileKeyStore::new(&path, crate::config::SERVICE_IDENTITY_KEYSTORE_APP, master)
                .unwrap(),
        );
        let reopened = AppState::new(
            crate::config::AppConfig::test_default(),
            coland_storage_postgres::Db { pool: None },
        )
        .with_verifier_private_keystore(second);
        let restored = load_scope_custody(&reopened, &reference).unwrap();
        assert!(same_scope_command(&restored.command, &material.command).unwrap());
        assert!(restored.runtime_key_binding_digest == material.runtime_key_binding_digest);
    }

    #[tokio::test]
    async fn qualified_agent_private_custody_rejects_digest_substitution_and_wrong_master_key() {
        let directory = VaultDirectory::new();
        let path = directory.0.join("vault");
        let first = std::sync::Arc::new(
            EncryptedFileKeyStore::new(
                &path,
                crate::config::SERVICE_IDENTITY_KEYSTORE_APP,
                rand::random(),
            )
            .unwrap(),
        );
        let state = AppState::new(
            crate::config::AppConfig::test_default(),
            coland_storage_postgres::Db { pool: None },
        )
        .with_verifier_private_keystore(first.clone());
        let material = imported_material(&state);
        let bytes = custody_bytes(&material).unwrap();
        let key_ref = scope_custody_key(&material).unwrap();
        first.create_if_absent(&key_ref, &bytes).unwrap();
        let mut reference = coland_storage::AgentScopeCustodyRef {
            key_ref,
            content_digest: Hash::new(arkret_canonical::sha256_digest(&bytes)).unwrap(),
        };
        let correct = reference.clone();
        reference.content_digest = Hash::new(format!("sha256:{}", "0".repeat(64))).unwrap();
        assert!(load_scope_custody(&state, &reference).is_err());
        let mut changed = material;
        changed.command.requested_scope_disclosure.challenge =
            arkret_wire::NonEmptyString::new("a-different-challenge").unwrap();
        first
            .store(&correct.key_ref, &custody_bytes(&changed).unwrap())
            .unwrap();
        assert!(load_scope_custody(&state, &correct).is_err());
        let wrong = AppState::new(
            crate::config::AppConfig::test_default(),
            coland_storage_postgres::Db { pool: None },
        )
        .with_verifier_private_keystore(std::sync::Arc::new(
            EncryptedFileKeyStore::new(
                &path,
                crate::config::SERVICE_IDENTITY_KEYSTORE_APP,
                rand::random(),
            )
            .unwrap(),
        ));
        assert!(load_scope_custody(&wrong, &correct).is_err());
    }
}
