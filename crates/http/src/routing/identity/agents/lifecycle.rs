use salvo::oapi::endpoint;

use super::*;

const AGENT_PROVISION_ALLOCATION_TTL_HOURS: i64 = 24;
const AGENT_PROVISION_ALLOCATION_DOMAIN: &str = "org.arkret.coland.agent_provision_allocation.v1";
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct PreparedAgentProvision {
    outcome: AgentProvisionOutcome,
    controller_authority: arkret_wire::AccountId,
    slug: String,
    requested_scope: AgentKeyScope,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pairing_ttl_ms: Option<u64>,
}

fn agent_provision_phase_key(
    phase: &str,
    operation_id: &arkret_wire::ProtocolOperationId,
    idempotency_key: &arkret_wire::IdempotencyKey,
) -> String {
    format!(
        "agent-provision:{phase}:{}:{}",
        operation_id.as_str(),
        idempotency_key.as_str()
    )
}

fn agent_provision_request_hash(body: &AgentProvisionRequestBody) -> Result<String, AppError> {
    arkret_canonical::canonical_sha256(&serde_json::to_value(body).map_err(|error| {
        AppError::param_invalid(format!("Agent provision request invalid: {error}"))
    })?)
    .map(|digest| digest.to_string())
    .map_err(|error| AppError::internal(format!("Agent provision request digest failed: {error}")))
}

fn allocation_binding(
    controller_principal_id: &str,
    operation_id: &arkret_wire::ProtocolOperationId,
    idempotency_key: &arkret_wire::IdempotencyKey,
    nonce: &str,
) -> Result<Vec<u8>, AppError> {
    arkret_canonical::canonical::canonical_json_bytes(&json!({
        "domain": AGENT_PROVISION_ALLOCATION_DOMAIN,
        "controller_principal_id": controller_principal_id,
        "operation_id": operation_id,
        "idempotency_key": idempotency_key,
        "nonce": nonce,
    }))
    .map_err(|error| AppError::internal(format!("Agent allocation binding failed: {error}")))
}

fn issue_allocation_handle(
    state: &AppState,
    controller_principal_id: &str,
    operation_id: &arkret_wire::ProtocolOperationId,
    idempotency_key: &arkret_wire::IdempotencyKey,
) -> Result<arkret_wire::ProtocolOpaqueId, AppError> {
    use ed25519_dalek::Signer as _;

    let nonce = uuid::Uuid::now_v7().simple().to_string();
    let binding = allocation_binding(
        controller_principal_id,
        operation_id,
        idempotency_key,
        &nonce,
    )?;
    let signing_key = state.notary_signing_key();
    let signature = signing_key.sign(&binding);
    arkret_wire::ProtocolOpaqueId::new(format!(
        "{nonce}.{}.{}",
        URL_SAFE_NO_PAD.encode(signing_key.verifying_key().to_bytes()),
        URL_SAFE_NO_PAD.encode(signature.to_bytes())
    ))
    .map_err(|error| AppError::internal(format!("generated allocation handle invalid: {error}")))
}

fn verify_allocation_handle(
    controller_principal_id: &str,
    operation_id: &arkret_wire::ProtocolOperationId,
    idempotency_key: &arkret_wire::IdempotencyKey,
    handle: &arkret_wire::ProtocolOpaqueId,
) -> Result<(), AppError> {
    let mut parts = handle.as_str().split('.');
    let (Some(nonce), Some(encoded_public_key), Some(encoded_signature), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(crate::app_error!(
            FailedPrecondition,
            "Agent provision allocation handle is malformed",
        )
        .with_internal_reason("agent_provision_allocation_mismatch"));
    };
    let public_key_bytes = URL_SAFE_NO_PAD.decode(encoded_public_key).map_err(|_| {
        crate::app_error!(
            FailedPrecondition,
            "Agent provision allocation handle public key is malformed",
        )
        .with_internal_reason("agent_provision_allocation_mismatch")
    })?;
    let public_key_bytes: [u8; 32] = public_key_bytes.try_into().map_err(|_| {
        crate::app_error!(
            FailedPrecondition,
            "Agent provision allocation handle public key is malformed",
        )
        .with_internal_reason("agent_provision_allocation_mismatch")
    })?;
    let verifying_key =
        ed25519_dalek::VerifyingKey::from_bytes(&public_key_bytes).map_err(|_| {
            crate::app_error!(
                FailedPrecondition,
                "Agent provision allocation handle public key is malformed",
            )
            .with_internal_reason("agent_provision_allocation_mismatch")
        })?;
    let signature_bytes = URL_SAFE_NO_PAD.decode(encoded_signature).map_err(|_| {
        crate::app_error!(
            FailedPrecondition,
            "Agent provision allocation handle signature is malformed",
        )
        .with_internal_reason("agent_provision_allocation_mismatch")
    })?;
    let signature = ed25519_dalek::Signature::from_slice(&signature_bytes).map_err(|_| {
        crate::app_error!(
            FailedPrecondition,
            "Agent provision allocation handle signature is malformed",
        )
        .with_internal_reason("agent_provision_allocation_mismatch")
    })?;
    let binding = allocation_binding(
        controller_principal_id,
        operation_id,
        idempotency_key,
        nonce,
    )?;
    verifying_key.verify(&binding, &signature).map_err(|_| {
        crate::app_error!(
            FailedPrecondition,
            "Agent provision allocation handle signature is invalid",
        )
        .with_internal_reason("agent_provision_allocation_mismatch")
    })
}

async fn lookup_provision_allocation(
    state: &AppState,
    controller_principal_id: &str,
    key: &str,
) -> Result<Option<coland_services::jobs::IdempotencyState>, AppError> {
    let controller_principal_id = DidCoreId::new(controller_principal_id.to_owned())
        .map_err(|error| AppError::internal(format!("controller principal id invalid: {error}")))?;
    state
        .jobs()
        .scoped_idempotency_record(
            &arkret_wire::ActorId::account(arkret_wire::AccountId::new(
                controller_principal_id,
                state.service_core_id(),
            )),
            "ak.self.agent.command.provision",
            key,
        )
        .await
        .map_err(|error| {
            AppError::internal(format!("Agent provision allocation lookup failed: {error}"))
        })
}

fn allocation_missing() -> AppError {
    crate::app_error!(
        FailedPrecondition,
        "Agent provision commit has no active server allocation",
    )
    .with_internal_reason("agent_provision_allocation_missing")
}

fn allocation_mismatch() -> AppError {
    crate::app_error!(
        FailedPrecondition,
        "Agent provision commit differs from its server allocation",
    )
    .with_internal_reason("agent_provision_allocation_mismatch")
}

#[endpoint(
    operation_id = "ak.self.agent.command.provision",
    summary = "Provision an agent",
    tags("agents")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.agent.command.provision.v1"))]
pub(super) async fn provision_agent(
    aa: AuthArgs,
    body: JsonBody<AgentProvisionRequestBody>,
    depot: &mut Depot,
    res: &mut Response,
    req: &mut Request,
) -> JsonResult<AgentProvisionOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let controller_principal_id = session.actor.clone();
    let body = body.into_inner();
    let requested_scope = match &body {
        AgentProvisionRequestBody::Prepare(request) => &request.requested_scope,
        AgentProvisionRequestBody::Commit(request) => &request.requested_scope,
    };
    validate_agent_runtime_provision_scope(requested_scope)?;
    let request_hash = agent_provision_request_hash(&body)?;
    let now_utc = chrono::DateTime::<chrono::Utc>::from_timestamp_millis(
        chrono::Utc::now().timestamp_millis(),
    )
    .ok_or_else(|| AppError::internal("current agent provision timestamp is out of range"))?;

    match body {
        AgentProvisionRequestBody::Prepare(
            arkret_models_collaboration::agent_operations::AgentProvisionPrepareRequestBody {
                phase: _,
                operation_id,
                idempotency_key,
                did,
                controller_station_id,
                slug,
                requested_scope,
                pairing_ttl_ms,
            },
        ) => {
            let key = agent_provision_phase_key("prepare", &operation_id, &idempotency_key);
            if let Some(record) =
                lookup_provision_allocation(state, &controller_principal_id, &key).await?
            {
                if record.expires_at <= now_utc {
                    state
                        .jobs()
                        .prune_expired_idempotency(now_utc)
                        .await
                        .map_err(|error| {
                            AppError::internal(format!(
                                "expired allocation cleanup failed: {error}"
                            ))
                        })?;
                } else if record.request_hash != request_hash {
                    return Err(AppError::conflict(
                        "Agent provision prepare idempotency key was reused with different inputs",
                    ));
                } else {
                    let prepared: PreparedAgentProvision =
                        serde_json::from_value(record.response_body).map_err(|error| {
                            AppError::internal(format!(
                                "stored Agent provision allocation invalid: {error}"
                            ))
                        })?;
                    return json_ok(prepared.outcome);
                }
            }

            let prepared_slug = arkret_wire::string_profiles::prepare_agent_slug(&slug)
                .map_err(|error| AppError::param_invalid(format!("slug is invalid: {error}")))?;
            if prepared_slug != slug {
                return Err(AppError::param_invalid(
                    "slug must already use the canonical agent-slug profile",
                ));
            }
            validate_agent_slug(&slug)
                .map_err(|error| AppError::param_invalid(format!("slug is invalid: {error}")))?;
            let controller_principal_id =
                DidCoreId::new(controller_principal_id.clone()).map_err(|error| {
                    AppError::internal(format!("authenticated controller id is invalid: {error}"))
                })?;
            let controller_authority =
                arkret_wire::AccountId::new(controller_principal_id.clone(), controller_station_id);
            let active_recovery_policy = state
                .recovery_policies()
                .active_policy(&controller_authority)
                .await
                .map_err(|error| {
                    AppError::internal(format!("controller recovery policy lookup failed: {error}"))
                })?;
            if active_recovery_policy.is_none() {
                return Err(crate::app_error!(
                    FailedPrecondition,
                    "controller must accept a recovery policy before provisioning a Agent",
                )
                .with_internal_reason("recovery_policy_required"));
            }
            let controller_realm =
                require_controller_principal_control_realm(state, &session, &controller_authority)
                    .await?;
            let mut existing = state
                .agent_pairings()
                .agents_for_controller(controller_principal_id.as_str())
                .await
                .map_err(|error| {
                    AppError::internal(format!("agent slug conflict check failed: {error}"))
                })?;
            for record in &mut existing {
                *record = lazily_expire_pairing(state, record.clone()).await?;
                if record.agent_slug.as_deref() == Some(slug.as_str())
                    && agent_record_is_materialized(record)
                {
                    let (_, _, lifecycle) =
                        accepted_agent_key_authorization_snapshot(state, record).await?;
                    // Name availability follows accepted terminal state, not a
                    // possibly stale private lifecycle intent.
                    record.state = lifecycle.ok_or_else(|| {
                        pairing_failed_precondition("Agent accepted lifecycle is unavailable")
                    })?;
                }
            }
            if existing.iter().any(|record| {
                record.agent_slug.as_deref() == Some(slug.as_str())
                    && agent_record_reserves_selector_slug(record, &now_utc)
            }) {
                return Err(AppError::param_invalid(
                    "slug is already bound to a recoverable agent for this controller",
                ));
            }

            let agent_id = arkret_wire::project_did_to_core_id(&did).map_err(|error| {
                AppError::param_invalid(format!("Agent did projection failed: {error}"))
            })?;
            let initial_resolution =
                crate::routing::identity::agent_pcr::accepted_agent_initial_resolution(
                    state,
                    &did,
                    &controller_principal_id,
                )
                .await?;
            let controller_authorization_ref =
                crate::routing::identity::agent_pcr::controller_authorization_ref(&did)?;
            let allocation_handle = issue_allocation_handle(
                state,
                controller_principal_id.as_str(),
                &operation_id,
                &idempotency_key,
            )?;
            let outcome = AgentProvisionOutcome::AwaitingControllerEvent(
                AgentProvisionAwaitingControllerEvent {
                    status: AgentProvisionAwaitingControllerEventStatus::AwaitingControllerEvent,
                    agent_id,
                    did,
                    initial_resolution,
                    controller_realm_id: RealmId::new(controller_realm).map_err(|error| {
                        AppError::internal(format!("controller PCR id invalid: {error}"))
                    })?,
                    allocation_handle,
                    controller_authorization_ref,
                },
            );
            let prepared = PreparedAgentProvision {
                outcome: outcome.clone(),
                controller_authority,
                slug,
                requested_scope,
                pairing_ttl_ms,
            };
            state
                .jobs()
                .store_idempotency_record(coland_services::jobs::IdempotencyState {
                    authenticated_actor: arkret_wire::ActorId::account(
                        arkret_wire::AccountId::new(
                            controller_principal_id.clone(),
                            state.service_core_id(),
                        ),
                    ),
                    operation_id: "ak.self.agent.command.provision".to_owned(),
                    idempotency_key: key.clone(),
                    request_hash: request_hash.clone(),
                    response_status: i32::from(StatusCode::OK.as_u16()),
                    response_body: serde_json::to_value(&prepared).map_err(|error| {
                        AppError::internal(format!(
                            "Agent provision prepare outcome failed: {error}"
                        ))
                    })?,
                    created_at: now_utc,
                    expires_at: now_utc
                        + chrono::Duration::hours(AGENT_PROVISION_ALLOCATION_TTL_HOURS),
                })
                .await
                .map_err(|error| {
                    AppError::internal(format!(
                        "Agent provision allocation persist failed: {error}"
                    ))
                })?;

            let landed = lookup_provision_allocation(state, controller_principal_id.as_str(), &key)
                .await?
                .ok_or_else(|| {
                    AppError::internal("Agent provision allocation disappeared after persist")
                })?;
            if landed.request_hash != request_hash {
                return Err(AppError::conflict(
                    "Agent provision prepare lost a concurrent idempotency race",
                ));
            }
            let landed: PreparedAgentProvision = serde_json::from_value(landed.response_body)
                .map_err(|error| {
                    AppError::internal(format!(
                        "stored Agent provision allocation invalid: {error}"
                    ))
                })?;
            json_ok(landed.outcome)
        }
        AgentProvisionRequestBody::Commit(
            arkret_models_collaboration::agent_operations::AgentProvisionCommitRequestBody {
                phase: _,
                operation_id,
                idempotency_key,
                agent_id,
                did,
                principal_control_realm_id,
                allocation_handle,
                slug,
                requested_scope,
                provision_event,
                pairing_ttl_ms,
            },
        ) => {
            let prepare_key = agent_provision_phase_key("prepare", &operation_id, &idempotency_key);
            let allocation =
                lookup_provision_allocation(state, &controller_principal_id, &prepare_key)
                    .await?
                    .filter(|record| record.expires_at > now_utc)
                    .ok_or_else(allocation_missing)?;
            let prepared: PreparedAgentProvision =
                serde_json::from_value(allocation.response_body.clone()).map_err(|error| {
                    AppError::internal(format!(
                        "stored Agent provision allocation invalid: {error}"
                    ))
                })?;
            let AgentProvisionOutcome::AwaitingControllerEvent(
                AgentProvisionAwaitingControllerEvent {
                    status: _,
                    agent_id: allocated_agent_id,
                    did: allocated_did,
                    initial_resolution,
                    controller_realm_id,
                    allocation_handle: allocated_handle,
                    controller_authorization_ref,
                },
            ) = prepared.outcome
            else {
                return Err(AppError::internal(
                    "stored Agent provision prepare outcome has a terminal status",
                ));
            };
            let expected_prepare = AgentProvisionRequestBody::Prepare(
                arkret_models_collaboration::agent_operations::AgentProvisionPrepareRequestBody {
                    phase: AgentProvisionPreparePhase::Prepare,
                    operation_id: operation_id.clone(),
                    idempotency_key: idempotency_key.clone(),
                    did: did.clone(),
                    controller_station_id: prepared.controller_authority.station_id.clone(),
                    slug: slug.clone(),
                    requested_scope: requested_scope.clone(),
                    pairing_ttl_ms,
                },
            );
            if allocation.request_hash != agent_provision_request_hash(&expected_prepare)?
                || allocated_agent_id != agent_id
                || allocated_did != did
                || allocated_handle != allocation_handle
                || prepared.slug != slug
                || prepared.requested_scope != requested_scope
                || prepared.pairing_ttl_ms != pairing_ttl_ms
            {
                return Err(allocation_mismatch());
            }
            verify_allocation_handle(
                &controller_principal_id,
                &operation_id,
                &idempotency_key,
                &allocation_handle,
            )?;

            let requested_scope_digest = arkret_signatures::agent::agent_requested_scope_digest(
                &agent_id,
                &prepared.controller_authority.principal_id,
                &requested_scope,
            )
            .map_err(|error| {
                AppError::internal(format!("requested_scope digest failed: {error}"))
            })?;

            let controller_realm_now = require_controller_principal_control_realm(
                state,
                &session,
                &prepared.controller_authority,
            )
            .await?;
            if controller_realm_id.as_str() != controller_realm_now {
                return Err(allocation_mismatch());
            }
            let provision_payload =
                arkret_models_collaboration::events_payloads::agent::AgentProvisionPayload::try_from(
                    &provision_event.event,
                )
                .map_err(|error| AppError::param_invalid(error.to_string()))?;
            let controller_core_id = &prepared.controller_authority.principal_id;
            if provision_event.event.actor_id
                != arkret_wire::ActorId::account(prepared.controller_authority.clone())
                || provision_event.event.realm_id != controller_realm_id
                || provision_payload.agent_id != agent_id
                || &provision_payload.controller_principal_id != controller_core_id
                || provision_payload.principal_control_realm_id != principal_control_realm_id
                || provision_payload.controller_authorization_ref != controller_authorization_ref
                || provision_payload.agent_slug != slug
                || provision_payload.requested_scope_digest != requested_scope_digest
            {
                return Err(AppError::param_invalid(
                    "provision_event does not match its authenticated allocation",
                ));
            }

            let requested_scope_value =
                serde_json::to_value(&requested_scope).map_err(|error| {
                    AppError::param_invalid(format!("requested_scope is invalid: {error}"))
                })?;
            let provision_event_id = provision_event.event.event_id.to_string();
            let commit_key = agent_provision_phase_key("commit", &operation_id, &idempotency_key);
            if let Some(record) =
                lookup_provision_allocation(state, &controller_principal_id, &commit_key).await?
            {
                if record.request_hash != request_hash {
                    return Err(AppError::conflict(
                        "Agent provision commit idempotency key was reused with different inputs",
                    ));
                }
                let outcome = serde_json::from_value(record.response_body).map_err(|error| {
                    AppError::internal(format!(
                        "stored Agent provision commit outcome invalid: {error}"
                    ))
                })?;
                res.status_code(StatusCode::CREATED);
                return json_ok(outcome);
            }
            let mut existing = state
                .agent_pairings()
                .agents_for_controller(&controller_principal_id)
                .await
                .map_err(|error| AppError::internal(format!("agent lookup failed: {error}")))?;
            for record in &mut existing {
                *record = lazily_expire_pairing(state, record.clone()).await?;
                if record.agent_slug.as_deref() == Some(slug.as_str())
                    && agent_record_is_materialized(record)
                {
                    let (_, _, lifecycle) =
                        accepted_agent_key_authorization_snapshot(state, record).await?;
                    // Name availability follows accepted terminal state, not a
                    // possibly stale private lifecycle intent.
                    record.state = lifecycle.ok_or_else(|| {
                        pairing_failed_precondition("Agent accepted lifecycle is unavailable")
                    })?;
                }
            }
            let existing_record = existing
                .iter()
                .find(|record| record.id == agent_id.as_str())
                .cloned();
            if let Some(record) = existing_record.as_ref() {
                let replay_matches = record.controller_principal_id == controller_principal_id
                    && record.principal_control_realm_id == principal_control_realm_id.as_str()
                    && record.agent_slug.as_deref() == Some(slug.as_str())
                    && record.requested_scope.as_ref() == Some(&requested_scope_value)
                    && record.provision_event_refs.as_ref().is_some_and(|refs| {
                        refs.get("provision_event_id").and_then(Value::as_str)
                            == Some(provision_event_id.as_str())
                            && refs.get("commit_request_hash").and_then(Value::as_str)
                                == Some(request_hash.as_str())
                            && refs.get("operation_id").and_then(Value::as_str)
                                == Some(operation_id.as_str())
                            && refs.get("idempotency_key").and_then(Value::as_str)
                                == Some(idempotency_key.as_str())
                            && refs.get("allocation_handle").and_then(Value::as_str)
                                == Some(allocation_handle.as_str())
                    });
                if !replay_matches {
                    return Err(AppError::conflict(
                        "Agent provision commit reuses an allocation with different inputs",
                    ));
                }
            }
            if existing_record.is_none()
                && existing.iter().any(|record| {
                    record.agent_slug.as_deref() == Some(slug.as_str())
                        && agent_record_reserves_selector_slug(record, &now_utc)
                })
            {
                return Err(AppError::param_invalid(
                    "slug is already bound to a recoverable agent for this controller",
                ));
            }

            let mut principal = if let Some(record) = existing_record {
                record
            } else {
                let accepted_provision_event_id = submit_provision_event(
                    state,
                    &session,
                    &controller_realm_now,
                    &agent_id,
                    &principal_control_realm_id,
                    &controller_authorization_ref,
                    &slug,
                    &requested_scope_digest,
                    provision_event,
                )
                .await?;
                debug_assert_eq!(accepted_provision_event_id, provision_event_id);

                let mut principal = AgentPrincipalRecord::new(
                    agent_id.to_string(),
                    controller_principal_id.clone(),
                    principal_control_realm_id.as_str().to_owned(),
                    controller_authorization_ref.clone(),
                    AgentLifecycleState::Active,
                    allocation.created_at,
                );
                principal.agent_slug = Some(slug.clone());
                principal.requested_scope = Some(requested_scope_value.clone());
                principal.provision_event_refs = Some(json!({
                    "provision_event_id": accepted_provision_event_id,
                    "operation_id": operation_id,
                    "idempotency_key": idempotency_key,
                    "allocation_handle": allocation_handle,
                    "commit_request_hash": request_hash,
                    "did": did,
                    "initial_resolution": initial_resolution,
                    "controller_authority": prepared.controller_authority,
                    "pcr_genesis_accepted": false,
                    "did_binding_accepted": false,
                }));
                state
                    .agent_pairings()
                    .save_agent(principal.clone())
                    .await
                    .map_err(|error| {
                        AppError::internal(format!(
                            "Agent provision reservation persist failed: {error}"
                        ))
                    })?;
                principal
            };

            let Some(_pcr_genesis_accepted_at) =
                crate::routing::identity::agent_pcr::agent_pcr_genesis_accepted_at(
                    state,
                    agent_id.as_str(),
                    principal_control_realm_id.as_str(),
                )
                .await?
            else {
                return json_ok(AgentProvisionOutcome::AwaitingPcrGenesis(
                    AgentProvisionAwaitingPcrGenesis {
                        status: AgentProvisionAwaitingPcrGenesisStatus::AwaitingPcrGenesis,
                        agent_id,
                        did,
                        initial_resolution,
                        principal_control_realm_id,
                        allocation_handle,
                        controller_authorization_ref,
                    },
                ));
            };

            if !crate::routing::identity::agent_pcr::agent_binding_is_accepted(
                state,
                &initial_resolution,
                controller_principal_id.as_str(),
                &principal_control_realm_id,
                &controller_authorization_ref,
                &requested_scope_digest,
            )
            .await?
            {
                principal.provision_event_refs = Some(json!({
                    "provision_event_id": provision_event_id,
                    "operation_id": operation_id,
                    "idempotency_key": idempotency_key,
                    "allocation_handle": allocation_handle,
                    "commit_request_hash": request_hash,
                    "did": did,
                    "initial_resolution": initial_resolution,
                    "controller_authority": prepared.controller_authority,
                    "pcr_genesis_accepted": true,
                    "did_binding_accepted": false,
                }));
                state
                    .agent_pairings()
                    .save_agent(principal)
                    .await
                    .map_err(|error| {
                        AppError::internal(format!(
                            "Agent DID binding checkpoint persist failed: {error}"
                        ))
                    })?;
                return json_ok(AgentProvisionOutcome::AwaitingDidBinding(
                    AgentProvisionAwaitingDidBinding {
                        status: AgentProvisionAwaitingDidBindingStatus::AwaitingDidBinding,
                        agent_id,
                        did,
                        initial_resolution,
                        principal_control_realm_id,
                        allocation_handle,
                        controller_authorization_ref,
                    },
                ));
            }
            let controller_account = state
                .identities()
                .find_account_by_actor(coland_services::identity::FindAccountByActorQuery {
                    account_id: prepared.controller_authority.clone(),
                })
                .await
                .map_err(|error| {
                    AppError::internal(format!("controller account lookup failed: {error}"))
                })?
                .ok_or_else(|| AppError::internal("controller account is missing"))?;
            let pairing_request_id = arkret_wire::OpaqueLocalId::new(format!(
                "agent_pairing_request:{}",
                uuid::Uuid::now_v7()
            ))
            .expect("generated pairing request id must be valid");
            let pairing_code = generate_pairing_code();
            let effective_pairing_ttl_ms = pairing_ttl_ms
                .unwrap_or(15 * 60 * 1000)
                .min(12 * 60 * 60 * 1000);
            let expires_at =
                now_utc + chrono::Duration::milliseconds(effective_pairing_ttl_ms as i64);
            principal.controller_account_pk = Some(controller_account.account_pk);
            principal.recipient_id = Some(state.service_id().clone());
            principal.provision_event_refs = Some(json!({
                "provision_event_id": provision_event_id,
                "operation_id": operation_id,
                "idempotency_key": idempotency_key,
                "allocation_handle": allocation_handle,
                "commit_request_hash": request_hash,
                "did": did,
                "initial_resolution": initial_resolution,
                "controller_authority": prepared.controller_authority,
                "pcr_genesis_accepted": true,
                "did_binding_accepted": true,
            }));
            principal.pairing_request_id = Some(pairing_request_id.clone());
            principal.pairing_code = Some(pairing_code.clone());
            principal.pairing_expires_at = Some(expires_at);
            state
                .agent_pairings()
                .save_agent(principal)
                .await
                .map_err(|error| AppError::internal(format!("agent persist failed: {error}")))?;

            let outcome = AgentProvisionOutcome::Complete(AgentProvisionComplete {
                status: AgentProvisionCompleteStatus::Complete,
                agent_id: agent_id.clone(),
                did: did.clone(),
                initial_resolution: initial_resolution.clone(),
                principal_control_realm_id: principal_control_realm_id.clone(),
                controller_authorization_ref: controller_authorization_ref.clone(),
                pairing_request_id: pairing_request_id.clone(),
                pairing_code: Some(pairing_code.clone()),
                expires_at,
            });
            state
                .jobs()
                .store_idempotency_record(coland_services::jobs::IdempotencyState {
                    authenticated_actor: arkret_wire::ActorId::account(
                        arkret_wire::AccountId::new(
                            DidCoreId::new(controller_principal_id.clone()).map_err(|error| {
                                AppError::internal(format!(
                                    "controller principal id invalid: {error}"
                                ))
                            })?,
                            state.service_core_id(),
                        ),
                    ),
                    operation_id: "ak.self.agent.command.provision".to_owned(),
                    idempotency_key: commit_key,
                    request_hash,
                    response_status: i32::from(StatusCode::CREATED.as_u16()),
                    response_body: serde_json::to_value(&outcome).map_err(|error| {
                        AppError::internal(format!(
                            "Agent provision commit outcome failed: {error}"
                        ))
                    })?,
                    created_at: now_utc,
                    expires_at: allocation.expires_at,
                })
                .await
                .map_err(|error| {
                    AppError::internal(format!("Agent provision commit persist failed: {error}"))
                })?;
            append_audit_log(
                state,
                Some(&session.actor),
                arkret_wire::ServiceOperationId::SELF_AGENT_COMMAND_PROVISION_V1,
                json!({
                    "agent_id": agent_id,
                    "controller_principal_id": controller_principal_id,
                    "slug": slug,
                    "pairing_request_id": pairing_request_id,
                    "principal_control_realm_id": principal_control_realm_id,
                    "controller_authorization_ref": controller_authorization_ref,
                    "requested_scope_digest": requested_scope_digest,
                    "provision_event_id": provision_event_id,
                }),
                "accepted",
            )
            .await;
            res.status_code(StatusCode::CREATED);
            json_ok(outcome)
        }
    }
}

/// `ak.self.agent.command.renew_pairing.v1` — re-open pairing for a bootstrap or
/// a runtime-replacement agent (key-management.md §3.6.1). Both branches share
/// the one-time-handle invariant (the fresh `pairing_request_id` +
/// `pairing_code` replace the old tuple, which becomes permanently unresolvable
/// through the same anti-enumeration lookup; the PRINCIPAL is not one-time):
///
/// - Bootstrap re-open (never-keyed agent): the derived runtime_state returns to
///   `pending_runtime_key` without changing the lifecycle intent or Realm grants.
/// - Runtime replacement (agent already holds an active key, lifecycle `active` or `paused`): the
///   lifecycle intent, existing keys, sessions, and grants all stay untouched and runtime_state
///   projects `replacing`; completing the new pairing supersedes every old active key
///   (reason=`superseded_by_repairing`) in the pair transaction, preserving the lifecycle intent —
///   an `active` agent needs no resume.
///
/// Re-opening is never a lifecycle transition and never requires a forced
/// pause; `deactivated` is terminal.
#[endpoint(
    operation_id = "ak.self.agent.command.renew_pairing",
    summary = "Renew an agent's pairing",
    tags("agents")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.agent.command.renew_pairing.v1"))]
pub(super) async fn renew_agent_pairing(
    aa: AuthArgs,
    agent_id: PathParam<String>,
    body: JsonBody<AgentRenewPairingRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AgentRenewPairingOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let agent_id = agent_id.into_inner();
    let body = body.into_inner();
    let record = require_agent_controller(state, &session, &agent_id).await?;
    // Lazy-expire first so a stale pending record renews through the same
    // state path as an observed-expired one.
    let mut record = lazily_expire_pairing(state, record).await?;
    crate::routing::identity::agent_pcr::validate_agent_controller_binding(
        state,
        &record,
        chrono::Utc::now(),
    )
    .await?;
    let (_, _, lifecycle) = accepted_agent_key_authorization_snapshot(state, &record).await?;
    record.state = projected_agent_lifecycle(record.state, lifecycle)?;
    if record.state == AgentLifecycleState::Deactivated {
        return Err(
            pairing_failed_precondition("agent is deactivated; deactivation is terminal")
                .with_reason_code(arkret_wire::ReasonCode::AGENT_DEACTIVATED),
        );
    }
    let now_utc = chrono::DateTime::<chrono::Utc>::from_timestamp_millis(
        chrono::Utc::now().timestamp_millis(),
    )
    .ok_or_else(|| AppError::internal("current agent pairing timestamp is out of range"))?;
    let pairing_request_id =
        arkret_wire::OpaqueLocalId::new(format!("agent_pairing_request:{}", uuid::Uuid::now_v7()))
            .expect("generated pairing request id must be valid");
    let pairing_code = generate_pairing_code();
    let pairing_ttl_ms = body
        .pairing_ttl_ms
        .unwrap_or(15 * 60 * 1000)
        .min(12 * 60 * 60 * 1000);
    let expires_at = now_utc + chrono::Duration::milliseconds(pairing_ttl_ms as i64);
    let terminal_notification = account_notification_context(&record);
    // Re-opening pairing is never a lifecycle transition (key-management.md
    // §3.6.1): the lifecycle intent stays exactly as it was and only the
    // derived runtime_state moves (to pending_runtime_key for bootstrap, or
    // replacing for runtime replacement) while the fresh handle is open.
    record.pairing_request_id = Some(pairing_request_id.clone());
    record.pairing_code = Some(pairing_code.clone());
    record.pairing_expires_at = Some(expires_at);
    // A runtime-key request submitted against the dead handle must not
    // survive into the renewed pairing.
    record.approval_request_id = None;
    record.runtime_key_request = None;
    record.approval_requested_at = None;
    record.runtime_key_binding_digest = None;
    record.runtime_public_key_digest = None;
    record.runtime_attestation_digest = None;
    record.runtime_proof_verified_at = None;
    record.pending_pairing_commit_intent = None;
    record.approval_notification_id = None;
    record.updated_at = now_utc;
    state
        .agent_pairings()
        .save_agent(record.clone())
        .await
        .map_err(|err| AppError::internal(format!("agent persist failed: {err}")))?;
    if let Some(context) = terminal_notification {
        persist_terminal_account_notification(
            state,
            context,
            arkret_models_collaboration::sync_frames::account_subscribe::AgentRuntimeApprovalRemovalReason::Renewed,
        )
        .await?;
    }
    append_audit_log(
        state,
        Some(&session.actor),
        arkret_wire::ServiceOperationId::SELF_AGENT_COMMAND_RENEW_PAIRING_V1,
        json!({
            "agent_id": agent_id,
            "controller_principal_id": session.actor,
            "pairing_request_id": pairing_request_id,
        }),
        "accepted",
    )
    .await;
    let agent_id = arkret_identifiers::DidCoreId::new(agent_id)
        .map_err(|err| AppError::internal(format!("persisted agent id invalid: {err}")))?;
    let principal_control_realm_id = RealmId::new(record.principal_control_realm_id.clone())
        .map_err(|error| AppError::internal(format!("persisted Agent PCR invalid: {error}")))?;
    let controller_authorization_ref = record.controller_authorization_ref.clone();
    let requested_scope_digest =
        crate::routing::identity::agent_pcr::requested_scope_digest_for_record(&record)?;
    json_ok(AgentRenewPairingOutcome {
        agent_id,
        principal_control_realm_id,
        controller_authorization_ref,
        requested_scope_digest,
        pairing_request_id,
        pairing_code,
        expires_at,
    })
}

#[endpoint(
    operation_id = "ak.self.agent.read.list",
    summary = "List agents",
    tags("agents")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.agent.read.list.v1"))]
pub(super) async fn list_agents(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AgentList> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let records = state
        .agent_pairings()
        .agents_for_controller(&session.actor)
        .await
        .map_err(|err| AppError::internal(format!("agent list failed: {err}")))?
        .into_iter()
        .collect::<Vec<_>>();
    // Lazily expire any agent past its pairing window before projecting, so
    // the derived runtime_state reflects `pairing_expired` without changing the
    // lifecycle intent or Realm grants.
    let mut agents = Vec::with_capacity(records.len());
    for record in records {
        if !agent_record_is_materialized(&record) {
            continue;
        }
        let record = reconcile_accepted_agent_authorization(state, record).await?;
        let mut record = lazily_expire_pairing(state, record).await?;
        let (keys, _, lifecycle) =
            accepted_agent_key_authorization_snapshot(state, &record).await?;
        record.state = projected_agent_lifecycle(record.state, lifecycle)?;
        let runtime_state =
            agent_runtime_state_from_record(&record, !keys.is_empty(), chrono::Utc::now());
        agents.push(agent_projection_from_record(&record, runtime_state));
    }
    // spec `agent_list` = `{agents: [agent_projection], next_cursor?, has_more}`.
    json_ok(AgentList {
        agents,
        next_cursor: None,
        has_more: false,
    })
}

#[endpoint(
    operation_id = "ak.self.agent.resource.get",
    summary = "Get one agent",
    tags("agents")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.agent.resource.get.v1"))]
pub(super) async fn get_agent(
    aa: AuthArgs,
    agent_id: PathParam<String>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AgentView> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let service_authorized =
        agent_projection_service_authorized(state, req, GET_AGENT_SERVICE_OPERATION, false).await?;
    let session = if service_authorized {
        None
    } else {
        Some(aa.authenticated_session(state, req).await?)
    };
    let agent_id = agent_id.into_inner();
    validate_agent_id(&agent_id)?;
    let record = state
        .agent_pairings()
        .agent(&agent_id)
        .await
        .map_err(|err| AppError::internal(format!("agent get failed: {err}")))?
        .ok_or_else(|| AppError::not_found("agent not found"))?;
    if !agent_record_is_materialized(&record) {
        return Err(AppError::not_found("agent not found"));
    }
    // Controller-self only: hide others' agents behind 404 to avoid enumeration.
    if let Some(session) = session.as_ref()
        && record.controller_principal_id != session.actor
    {
        return Err(AppError::not_found("agent not found"));
    }
    let record = reconcile_accepted_agent_authorization(state, record).await?;
    let record = lazily_expire_pairing(state, record).await?;
    crate::routing::identity::agent_pcr::validate_agent_controller_binding(
        state,
        &record,
        chrono::Utc::now(),
    )
    .await?;
    // This Station owns the pairing candidate and verifies its raw possession
    // proof here. The Account Authority consumes the authenticated exact
    // outcome and never reads verifier-only raw material through this
    // operation, so no response carries it.
    let mut view = agent_view_from_record(state, &record).await?;

    // Surface every durable `active` grant so terminal deactivation can
    // author complete revocation coverage. Lifecycle alone decides the row:
    // a grant whose window has not opened or has elapsed is still active and
    // must not disappear from the controller's revocation surface.
    let agent_actor = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        arkret_wire::DidCoreId::new(agent_id.clone())
            .map_err(|error| AppError::internal(format!("invalid agent id: {error}")))?,
        state.service_core_id().clone(),
    ));
    view.grants = state
        .persistence()
        .active_capability_grants_for_subject(&agent_actor)
        .await
        .map_err(|error| AppError::internal(format!("agent grant read failed: {error}")))?
        .into_iter()
        .map(|record| GrantSnapshot {
            expires_at: coland_storage::capability_grant_expires_at(&record.value),
            grant_id: record.grant_id,
            realm_id: record.realm_id,
            grant_digest: None,
        })
        .map(serde_json::to_value)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| {
            AppError::internal(format!(
                "agent grant snapshot serialization failed: {error}"
            ))
        })?;
    json_ok(view)
}

/// Lazily clean up an agent whose open pairing window has elapsed. Pairing is
/// independent from the lifecycle intent and from Realm grants, so expiry never
/// changes the lifecycle, creates, revokes, or rewrites a grant; the derived
/// runtime_state simply falls to `pairing_expired` (never-keyed) or `ready`
/// (keyed) once the handle lapses (key-management.md §3.6.1).
pub(super) async fn lazily_expire_pairing(
    state: &AppState,
    mut record: AgentPrincipalRecord,
) -> Result<AgentPrincipalRecord, AppError> {
    if !agent_pairing_handle_is_open(&record) {
        return Ok(record);
    }
    let expired = record
        .pairing_expires_at
        .map(|expires| chrono::Utc::now() > expires)
        .unwrap_or(false);
    if !expired {
        return Ok(record);
    }
    let agent_id = record.id.clone();
    let terminal_notification = account_notification_context(&record);
    let now = chrono::Utc::now();
    // Pairing expiry is not a lifecycle transition (key-management.md §3.6.1):
    // the lifecycle intent is untouched, and the derived runtime_state falls to
    // pairing_expired (never-keyed) or ready (keyed) once the handle lapses.
    // Only the dead pending runtime-key request is cleaned up here.
    record.pending_pairing_commit_intent = None;
    record.approval_request_id = None;
    record.runtime_key_request = None;
    record.approval_requested_at = None;
    record.runtime_key_binding_digest = None;
    record.runtime_public_key_digest = None;
    record.runtime_attestation_digest = None;
    record.runtime_proof_verified_at = None;
    record.approval_notification_id = None;
    record.updated_at = now;
    state
        .agent_pairings()
        .save_agent(record.clone())
        .await
        .map_err(|error| {
            AppError::internal(format!("failed to persist expired Agent pairing: {error}"))
        })?;
    if let Some(context) = terminal_notification
        && let Err(error) = persist_terminal_account_notification(
            state,
            context,
            arkret_models_collaboration::sync_frames::account_subscribe::AgentRuntimeApprovalRemovalReason::Expired,
        )
        .await
    {
        tracing::error!(message = %error.message, agent_id, "failed to persist expired Agent approval notification");
    }
    Ok(record)
}

pub(super) async fn lifecycle_transition(
    state: &AppState,
    session: &SessionRecord,
    agent_id: String,
    new_state: AgentLifecycleState,
    event_kind: &str,
    reason: Option<String>,
    lifecycle_event: Option<arkret_wire::EventAdmissionSubmission>,
) -> Result<AgentLifecycleOutcome, AppError> {
    // Authentication is deliberately completed by the endpoint before this
    // helper is entered. A DPoP proof is single-use, so passing `AuthArgs` and
    // `Request` through here would verify the same proof twice and reject the
    // lifecycle command as a replay.
    let mut record = require_agent_controller(state, session, &agent_id).await?;
    let terminal_notification = (event_kind == arkret_wire::event_kind_str::SELF_AGENT_DEACTIVATE)
        .then(|| account_notification_context(&record))
        .flatten();
    // Never synthesize an Agent-authored control Event from a session request.
    // Pause/resume/deactivate carry the exact SDK-authored lifecycle envelope.
    // Accepted terminal lifecycle is the parent gate for keys and grants.
    let Some(lifecycle_event) = lifecycle_event else {
        if state.config().development_mode {
            return Err(crate::app_error!(
                ControllerSignedEventRequired,
                "operation requires a controller-signed delegated SDK Event",
            ));
        }
        return Err(AppError::unsupported_feature(
            "production agent lifecycle transitions require protocol-valid delegated fan-out",
        )
        .with_internal_reason("agent_lifecycle_fanout_unavailable"));
    };
    if state
        .authority_commits()
        .committed_event(&lifecycle_event.event.event_id)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
        .is_some()
    {
        let original_previous_status = lifecycle_event
            .event
            .payload
            .get("previous_status")
            .and_then(Value::as_str)
            .ok_or_else(|| AppError::param_invalid("lifecycle_event has no previous_status"))?
            .to_owned();
        submit_durable_agent_lifecycle(
            state,
            session,
            &record.principal_control_realm_id,
            &agent_id,
            &record.controller_authorization_ref,
            event_kind,
            &original_previous_status,
            reason.as_deref(),
            lifecycle_event,
        )
        .await?;
        return Ok(AgentLifecycleOutcome { status: new_state });
    }
    let (_, _, lifecycle) = accepted_agent_key_authorization_snapshot(state, &record).await?;
    record.state = projected_agent_lifecycle(record.state, lifecycle)?;
    if record.state == AgentLifecycleState::Deactivated {
        return Err(
            pairing_failed_precondition("agent is deactivated; deactivation is terminal")
                .with_reason_code(arkret_wire::ReasonCode::AGENT_DEACTIVATED),
        );
    }
    if record.state == AgentLifecycleState::Paused && new_state == AgentLifecycleState::Paused {
        return Err(pairing_failed_precondition("agent is already paused")
            .with_reason_code(arkret_wire::ReasonCode::AGENT_PAUSED));
    }
    // Resume is a pure lifecycle-intent write and MUST NOT interlock with an
    // open pairing handle (key-management.md §3.6.1): an in-flight replacement
    // handle keeps running across resume and closes only on consumption or
    // expiry. Sidecar desired rosters are re-derived after Event admission.
    let status_changed_at = chrono::Utc::now();
    // Read the current persisted state so the durable transition carries the
    // accurate `previous_status` (resume comes from `paused`, etc.).
    let previous_status = record.state;
    // Drive the transition reducer with the exact durable
    // `ak.self.agent.{pause,resume,deactivate}` Event authored as the Agent and
    // executed/signed by its controller. Deactivation uses the same single
    // lifecycle Event, without auxiliary key/grant revocation Events.
    let realm = record.principal_control_realm_id.clone();
    let authorization_ref = record.controller_authorization_ref.clone();
    let lifecycle_event_id = submit_durable_agent_lifecycle(
        state,
        session,
        &realm,
        &agent_id,
        &authorization_ref,
        event_kind,
        previous_status.as_wire_str(),
        reason.as_deref(),
        lifecycle_event,
    )
    .await?;
    let event_id = arkret_wire::EventId::new(lifecycle_event_id)
        .map_err(|error| AppError::internal(error.to_string()))?;
    let committed = state
        .authority_commits()
        .committed_event(&event_id)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
        .ok_or_else(|| AppError::internal("accepted Agent lifecycle Event has no RealmCommit"))?;
    if committed.commit.event_ref != event_id {
        return Err(AppError::internal(
            "Agent lifecycle Event/Commit reference mismatch",
        ));
    }
    // Persist the lifecycle state transition on the agent_principal row so
    // list/get reflect the new status (the durable event drives the reducer
    // transition; this row is the read-side projection consumed by the HTTP API).
    let mut updated_record = record;
    updated_record.state = new_state;
    updated_record.state_changed_at = Some(status_changed_at);
    updated_record.updated_at = status_changed_at;
    // Pause is a pure lifecycle-intent write and MUST NOT touch an open pairing
    // handle (key-management.md §3.6.1): pausing mid-replacement leaves the
    // handle live so the controller can still complete or let it expire.
    if event_kind == arkret_wire::event_kind_str::SELF_AGENT_DEACTIVATE {
        updated_record.approval_request_id = None;
        updated_record.runtime_key_request = None;
        updated_record.approval_requested_at = None;
        updated_record.runtime_key_binding_digest = None;
        updated_record.runtime_public_key_digest = None;
        updated_record.runtime_attestation_digest = None;
        updated_record.approval_notification_id = None;
    }
    state
        .agent_pairings()
        .save_agent(updated_record)
        .await
        .map_err(|error| AppError::internal(format!("agent lifecycle persist failed: {error}")))?;
    if let Some(context) = terminal_notification {
        persist_terminal_account_notification(
            state,
            context,
            arkret_models_collaboration::sync_frames::account_subscribe::AgentRuntimeApprovalRemovalReason::Deactivated,
        )
        .await?;
    }
    // spec `agent_lifecycle_state` = `operation_status_outcome` =
    // `{status}` (status is the post-transition `agent_status`).
    Ok(AgentLifecycleOutcome { status: new_state })
}

#[endpoint(
    operation_id = "ak.self.agent.command.pause",
    summary = "Pause an agent",
    tags("agents")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.agent.command.pause.v1"))]
pub(super) async fn pause_agent(
    aa: AuthArgs,
    agent_id: PathParam<String>,
    body: JsonBody<AgentPauseRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AgentLifecycleOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let body = body.into_inner();
    json_ok(
        lifecycle_transition(
            state,
            &session,
            agent_id.into_inner(),
            AgentLifecycleState::Paused,
            arkret_wire::event_kind_str::SELF_AGENT_PAUSE,
            body.reason.map(arkret_wire::AuditReasonText::into_string),
            Some(body.lifecycle_event),
        )
        .await?,
    )
}

#[endpoint(
    operation_id = "ak.self.agent.command.resume",
    summary = "Resume an agent",
    tags("agents")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.agent.command.resume.v1"))]
pub(super) async fn resume_agent(
    aa: AuthArgs,
    agent_id: PathParam<String>,
    body: JsonBody<AgentResumeRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AgentLifecycleOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let body = body.into_inner();
    json_ok(
        lifecycle_transition(
            state,
            &session,
            agent_id.into_inner(),
            AgentLifecycleState::Active,
            arkret_wire::event_kind_str::SELF_AGENT_RESUME,
            None,
            Some(body.lifecycle_event),
        )
        .await?,
    )
}

#[endpoint(
    operation_id = "ak.self.agent.command.deactivate",
    summary = "Deactivate an agent",
    tags("agents")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.agent.command.deactivate.v1"))]
pub(super) async fn deactivate_agent(
    aa: AuthArgs,
    agent_id: PathParam<String>,
    body: JsonBody<AgentDeactivateRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AgentLifecycleOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let agent_id = agent_id.into_inner();
    let body = body.into_inner();

    // The final contract makes the accepted terminal lifecycle Event the
    // single atomic cascade boundary.  Key and grant invalidation is reducer
    // derived; accepting caller-supplied auxiliary revocation arrays created
    // a partial-deactivation state and has therefore been removed from wire.
    json_ok(
        lifecycle_transition(
            state,
            &session,
            agent_id,
            AgentLifecycleState::Deactivated,
            arkret_wire::event_kind_str::SELF_AGENT_DEACTIVATE,
            body.reason.map(arkret_wire::AuditReasonText::into_string),
            Some(body.lifecycle_event),
        )
        .await?,
    )
}

#[cfg(test)]
mod deactivation_tests {
    use super::*;

    #[test]
    fn lifecycle_transition_contract_uses_a_pre_authenticated_session() {
        // This compile-time contract keeps the transition layer below the HTTP
        // authentication boundary. In particular, it must not regain access
        // to AuthArgs/Request and consume a single-use DPoP proof twice.
        async fn call_transition(state: &AppState, session: &SessionRecord) {
            let _ = lifecycle_transition(
                state,
                session,
                "did:web:agent.example".to_owned(),
                AgentLifecycleState::Paused,
                "ak.self.agent.pause",
                None,
                None,
            )
            .await;
        }

        let _ = call_transition;
    }
}
