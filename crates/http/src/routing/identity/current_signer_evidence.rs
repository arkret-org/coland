//! Authenticated signer-key self query over committed authority state.

use arkret_canonical::base64url::base64url_decode;
use arkret_models_collaboration::agent_operations::AgentLifecycleState;
use arkret_models_collaboration::events_payloads::agent::AgentKeyAuthorizePayload;
use arkret_models_identity::{
    CurrentDeviceSigningKey, CurrentSignerKeyQuerySender, ResolvedSignerKey, SignerKeyQueryOutcome,
    SignerKeyQuerySelector, SignerKeysQueryOutcome, SignerKeysQueryRequestBody,
};
use arkret_wire::{
    CommittedEventRef, CurrentSelector, EventId, RealmId, StationSigningKey, TypedCurrentRow,
};
use coland_http::error::AppError;
use coland_http::result::{GuardedJsonResult, guarded_json_ok};
use salvo::oapi::extract::JsonBody;
use salvo::prelude::*;

use super::AuthArgs;
use crate::state::AppState;

fn signer_query_diagnostic(stage: &'static str, branch: &'static str) {
    #[cfg(feature = "conformance-harness")]
    tracing::warn!(target: "conformance_harness", stage, diag_branch = branch,
        "historical signer query fixed diagnostic");
    #[cfg(not(feature = "conformance-harness"))]
    let _ = (stage, branch);
}

fn observed_signer_lookup<T, E>(result: Result<T, E>, stage: &'static str) -> Option<T> {
    match result {
        Ok(value) => Some(value),
        Err(_) => {
            signer_query_diagnostic(stage, "lookup_failed");
            None
        }
    }
}

pub(crate) fn self_router() -> Router {
    Router::with_path("signer-keys/query").post(self_query)
}

#[salvo::oapi::endpoint(operation_id = "ak.self.signer_keys.read.resolve", tags("identity"))]
async fn self_query(
    aa: AuthArgs,
    body: JsonBody<SignerKeysQueryRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> GuardedJsonResult<SignerKeysQueryOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let body = body.into_inner();
    if let Ok(device) =
        depot.get_typed::<super::applet_managed_device::VerifiedAppletManagedDevice>()
    {
        return native_self_query(state, device, &body).await;
    }
    let session = aa.authenticated_session(state, req).await?;
    body.validate().map_err(self_request_error)?;
    let actor = super::session_actor::validated_session_actor(state, &session).await?;
    if actor.as_account_id() != body.recipient_account_id.as_ref()
        || body
            .recipient_account_id
            .as_ref()
            .is_none_or(|account| account.station_id != state.service_core_id())
    {
        return Err(AppError::not_found("signer key unavailable"));
    }
    guarded_json_ok(
        resolve_self_signer_keys(state, &session, &body).await?,
        None,
    )
}

/// Historical dependencies disclose only a fact for an exact Full Event the
/// real recipient may currently receive. No PCR/control fallback is available.
async fn native_self_query(
    state: &AppState,
    device: &super::applet_managed_device::VerifiedAppletManagedDevice,
    body: &SignerKeysQueryRequestBody,
) -> GuardedJsonResult<SignerKeysQueryOutcome> {
    body.validate().map_err(self_request_error)?;
    if device.operation != arkret_wire::ServiceOperationId::SelfSignerKeysReadResolveV1
        || body.recipient_actor_id.as_ref() != Some(&device.authority.actor_id)
        || device.authority.governance_service_id != state.service_core_id()
        || body.realm_id != *device.metadata.effective_scope.realm_id()
    {
        return Err(AppError::not_found("signer key unavailable"));
    }
    let actor = device.authority.actor_id.clone();
    let mut results = Vec::with_capacity(body.queries.len());
    let mut views = Vec::new();
    for selector in &body.queries {
        let mut resolved = None;
        if let Some(reference) = selector.committed_event_ref() {
            if let Ok(coland_storage::MemberCommittedEventRead::Read(view)) = state
                .authority_commits()
                .committed_event_for_member(&reference.event_id, &actor, &state.service_core_id())
                .await
            {
                let Some(view) = (*view)
                    .into_effective_scope(&device.metadata.effective_scope)
                    .map_err(|_| AppError::not_found("signer key unavailable"))?
                else {
                    return Err(AppError::not_found("signer key unavailable"));
                };
                let commit = view.commit();
                if let arkret_wire::CommittedEventView::Full(_) = &view {
                    if commit.realm_id == body.realm_id
                        && commit.event_ref == reference.event_id
                        && commit.commit_id == reference.commit_id
                        && commit.stream_ref == reference.stream_ref
                        && commit.stream_position == reference.stream_position
                    {
                        // Signed metadata cannot substitute for the original
                        // resource's authoritative scope, including mixed batches.
                        if view
                            .disclosure_scope()
                            .map_err(|_| AppError::not_found("signer key unavailable"))?
                            != device.metadata.effective_scope
                        {
                            return Err(AppError::not_found("signer key unavailable"));
                        }
                        resolved = state
                            .authority_commits()
                            .historical_producer_signer_key(&body.realm_id, selector)
                            .await
                            .ok()
                            .flatten();
                        if resolved.is_some()
                            && !views
                                .iter()
                                .any(|v: &arkret_wire::CommittedEventView| v.commit() == commit)
                        {
                            views.push(view);
                        }
                    }
                }
            }
        }
        // A current selector alone has no authoritative target scope. It cannot
        // mint a disclosure path from the caller's metadata or PCR identity.
        results.push(
            resolved.unwrap_or_else(|| SignerKeyQueryOutcome::Unavailable {
                selector: selector.clone(),
            }),
        );
    }
    let guard = if views.is_empty() {
        None
    } else {
        Some(
            super::applet_managed_device::content_delivery_guard(state, device, &views)
                .await
                .map_err(|_| AppError::not_found("signer key unavailable"))?,
        )
    };
    let outcome = SignerKeysQueryOutcome {
        request_id: body.request_id.clone(),
        realm_id: body.realm_id.clone(),
        recipient_account_id: body.recipient_account_id.clone(),
        recipient_actor_id: body.recipient_actor_id.clone(),
        results,
    };
    outcome
        .validate_for_request(body)
        .map_err(self_result_error)?;
    guarded_json_ok(outcome, guard)
}

pub(crate) fn self_request_error(error: arkret_wire::WireError) -> AppError {
    AppError::from_rejection(
        match error.error_code() {
            Some(arkret_wire::ErrorCode::PayloadTooLarge) => {
                arkret_wire::ErrorCode::PayloadTooLarge
            }
            _ => arkret_wire::ErrorCode::SchemaViolation,
        },
        error.to_string(),
    )
}

pub(crate) fn self_result_error(error: arkret_wire::WireError) -> AppError {
    AppError::from_rejection(
        match error.error_code() {
            Some(arkret_wire::ErrorCode::LimitExceeded) => arkret_wire::ErrorCode::LimitExceeded,
            _ => arkret_wire::ErrorCode::SchemaViolation,
        },
        error.to_string(),
    )
}

pub(crate) async fn resolve_self_signer_keys(
    state: &AppState,
    session: &coland_services::identity::SessionIdentityState,
    body: &SignerKeysQueryRequestBody,
) -> Result<SignerKeysQueryOutcome, AppError> {
    body.validate().map_err(self_request_error)?;
    let recipient = body
        .recipient_account_id
        .as_ref()
        .ok_or_else(|| AppError::not_found("signer key unavailable"))?;
    let requester = arkret_wire::ActorId::account(recipient.clone());
    // Read the accepted typed state, including verified replica anchors below
    // the reader's since_join floor; legacy projection caches are not authority.
    let requester_is_member = observed_signer_lookup(
        state
            .authority_commits()
            .accepted_current_member_joined(&body.realm_id, &requester)
            .await,
        "member_classification",
    )
    .unwrap_or(false);
    let ordinary = observed_signer_lookup(
        state
            .authority_commits()
            .accepted_ordinary_realm(&body.realm_id)
            .await,
        "realm_classification",
    )
    .unwrap_or(false);
    let self_recipient = super::session_actor::validated_session_actor(state, session)
        .await
        .ok()
        .is_some_and(|actor| actor.as_account_id() == Some(recipient))
        && recipient.station_id == state.service_core_id();
    let mut results = Vec::with_capacity(body.queries.len());
    for selector in &body.queries {
        let category = match selector {
            SignerKeyQuerySelector::HistoricalEvent {
                sender:
                    arkret_models_identity::HistoricalSignerKeyQuerySender::AccountDevice {
                        actor, ..
                    },
            } if actor.fixed_route_service_id() == Some(&state.service_core_id()) => "local_human",
            SignerKeyQuerySelector::HistoricalEvent {
                sender: arkret_models_identity::HistoricalSignerKeyQuerySender::AccountDevice { .. },
            } => "foreign_human",
            SignerKeyQuerySelector::HistoricalEvent {
                sender: arkret_models_identity::HistoricalSignerKeyQuerySender::Agent { .. },
            } => "agent",
            SignerKeyQuerySelector::HistoricalEvent {
                sender: arkret_models_identity::HistoricalSignerKeyQuerySender::Service { .. },
            } => "service",
            SignerKeyQuerySelector::CurrentRealmDevice { .. } => "current_realm_device",
            SignerKeyQuerySelector::HistoricalRealmDevice { .. } => "historical_realm_device",
            SignerKeyQuerySelector::CurrentAdmission { .. } => "current_selector",
        };
        signer_query_diagnostic("selector_classification", category);
        let visible = ordinary
            && if let Some(reference) = selector.committed_event_ref() {
                exact_visible_committed_event(state, session, &body.realm_id, reference).await
            } else {
                requester_is_member
                    && state
                        .authority_commits()
                        .accepted_current_member_joined(&body.realm_id, selector.actor())
                        .await
                        .ok()
                        .unwrap_or(false)
            };
        let resolved = if visible {
            match selector {
                SignerKeyQuerySelector::CurrentAdmission {
                    sender: CurrentSignerKeyQuerySender::AccountDevice { .. },
                } => current_device_key(state, body, selector).await,
                SignerKeyQuerySelector::CurrentAdmission {
                    sender: CurrentSignerKeyQuerySender::Agent { .. },
                } => current_agent_key(state, &body.realm_id, selector).await,
                SignerKeyQuerySelector::CurrentRealmDevice { .. } => {
                    current_realm_device_key(state, selector).await
                }
                SignerKeyQuerySelector::HistoricalRealmDevice { .. } => state
                    .authority_commits()
                    .historical_producer_signer_key(&body.realm_id, selector)
                    .await
                    .ok()
                    .flatten(),
                SignerKeyQuerySelector::HistoricalEvent {
                    sender:
                        arkret_models_identity::HistoricalSignerKeyQuerySender::Agent { .. }
                        | arkret_models_identity::HistoricalSignerKeyQuerySender::AccountDevice { .. }
                        | arkret_models_identity::HistoricalSignerKeyQuerySender::Service { .. },
                } => {
                    let found = observed_signer_lookup(
                        state
                            .authority_commits()
                            .historical_producer_signer_key(&body.realm_id, selector)
                            .await,
                        "ordinary_historical",
                    );
                    if matches!(found, Some(None)) {
                        signer_query_diagnostic("ordinary_historical", "immutable_fact_not_found");
                    }
                    found.flatten()
                }
            }
        } else if !ordinary && self_recipient && selector.actor().as_account_id() == Some(recipient)
        {
            let found = observed_signer_lookup(
                state
                    .authority_commits()
                    .historical_self_pcr_producer_signer_key(&body.realm_id, selector, recipient)
                    .await,
                "restricted_self_pcr_historical",
            );
            if matches!(found, Some(None)) {
                signer_query_diagnostic(
                    "restricted_self_pcr_historical",
                    "immutable_fact_not_found",
                );
            }
            found.flatten()
        } else {
            signer_query_diagnostic(
                "selection",
                if ordinary {
                    "ordinary_visibility_not_held"
                } else {
                    "domain_or_self_recipient_not_held"
                },
            );
            None
        };
        if resolved.is_none() {
            signer_query_diagnostic("result", "unavailable");
        }
        results.push(
            resolved.unwrap_or_else(|| SignerKeyQueryOutcome::Unavailable {
                selector: selector.clone(),
            }),
        );
    }
    let outcome = SignerKeysQueryOutcome {
        request_id: body.request_id.clone(),
        realm_id: body.realm_id.clone(),
        recipient_account_id: body.recipient_account_id.clone(),
        recipient_actor_id: body.recipient_actor_id.clone(),
        results,
    };
    outcome
        .validate_for_request(body)
        .map_err(self_result_error)?;
    Ok(outcome)
}

async fn current_device_key(
    state: &AppState,
    body: &SignerKeysQueryRequestBody,
    selector: &SignerKeyQuerySelector,
) -> Option<SignerKeyQueryOutcome> {
    let account = selector.actor().as_account_id()?;
    let device = selector.device_id()?;
    let projection = super::keys::current_device_projection_for_signer(
        state,
        body.recipient_account_id.as_ref()?,
        &body.realm_id,
        account,
        device,
    )
    .await?;
    // The selector's method names the principal's exact device, not the
    // did:key used as the projection's raw key material.
    let (did, fragment) = selector.verification_method().as_str().split_once('#')?;
    if fragment != device.as_str()
        || arkret_wire::project_did_to_core_id(&arkret_wire::Did::new(did).ok()?).ok()?
            != account.principal_id
    {
        return None;
    }
    let document = state
        .dids()
        .resolve_did(&arkret_wire::Did::new(did).ok()?)
        .await
        .ok()?;
    if document.id.as_str() != did {
        return None;
    }
    let multibase = projection
        .device_projection
        .device_signing_key_did
        .as_str()
        .strip_prefix("did:key:")?;
    let raw = arkret_canonical::decode_ed25519_multibase(multibase).ok()?;
    let key = CurrentDeviceSigningKey {
        public_key_b64u: arkret_wire::Base64UrlString::new(arkret_canonical::base64url_encode(raw))
            .ok()?,
    };
    key.validate().ok()?;
    Some(SignerKeyQueryOutcome::CurrentDeviceResolved {
        selector: selector.clone(),
        key,
    })
}

async fn exact_visible_committed_event(
    state: &AppState,
    session: &coland_services::identity::SessionIdentityState,
    realm_id: &RealmId,
    reference: &CommittedEventRef,
) -> bool {
    let record = match state
        .authority_commits()
        .committed_event(&reference.event_id)
        .await
    {
        Ok(Some(record)) => record,
        Ok(None) => {
            signer_query_diagnostic("exact_visibility", "target_missing");
            return false;
        }
        Err(_) => {
            signer_query_diagnostic("exact_visibility", "target_lookup_failed");
            return false;
        }
    };
    if record.event.event_id != reference.event_id
        || record.event.realm_id != *realm_id
        || record.commit.event_ref != reference.event_id
        || record.commit.commit_id != reference.commit_id
        || record.commit.stream_ref != reference.stream_ref
        || record.commit.stream_position != reference.stream_position
    {
        signer_query_diagnostic("exact_visibility", "coordinate_mismatch");
        return false;
    }
    let event_record = match state
        .event_queries()
        .canonical_event(reference.event_id.as_str())
        .await
    {
        Ok(Some(record)) => record,
        Ok(None) => {
            signer_query_diagnostic("exact_visibility", "canonical_original_missing");
            return false;
        }
        Err(_) => {
            signer_query_diagnostic("exact_visibility", "canonical_lookup_failed");
            return false;
        }
    };
    let visible = event_record.realm_id.as_deref() == Some(realm_id.as_str())
        && crate::routing::events::event_log::event_visible_to_session(
            state,
            &event_record,
            session,
        )
        .await;
    if !visible {
        signer_query_diagnostic("exact_visibility", "event_visibility_not_held");
    }
    visible
}

async fn current_agent_key(
    state: &AppState,
    realm_id: &RealmId,
    selector: &SignerKeyQuerySelector,
) -> Option<SignerKeyQueryOutcome> {
    let agent_id = &selector.actor().as_account_id()?.principal_id;
    let agent = state
        .agent_pairings()
        .agent(agent_id.as_str())
        .await
        .ok()??;
    if agent.id != agent_id.as_str() {
        return None;
    }
    let pcr_realm_id = RealmId::new(agent.principal_control_realm_id).ok()?;
    let material = state
        .authority_commits()
        .realm_state_snapshot_material(&pcr_realm_id)
        .await
        .ok()??;
    let mut status = None;
    let mut active = Vec::new();
    for entry in &material.current_state_entries {
        let TypedCurrentRow::Value {
            selector: current,
            value,
            revision,
            ..
        } = entry;
        match current {
            CurrentSelector::AgentStatus { agent_id: subject } if subject == agent_id => {
                if status
                    .replace(serde_json::from_value::<AgentLifecycleState>(value.clone()).ok()?)
                    .is_some()
                {
                    return None;
                }
            }
            CurrentSelector::AgentKey {
                agent_id: subject,
                agent_key_id,
            } if subject == agent_id => {
                for authorization in value.get("authorizations")?.as_array()? {
                    let entry_value = authorization.get("value")?;
                    // Keyed-set revoke markers share this family but have no
                    // verification_method; they are not active authorizations.
                    if entry_value.get("verification_method").is_none() {
                        continue;
                    }
                    let payload: AgentKeyAuthorizePayload =
                        serde_json::from_value(entry_value.clone()).ok()?;
                    if payload.agent_id != *agent_id
                        || payload.key_id.as_str() != agent_key_id.as_str()
                    {
                        return None;
                    }
                    if payload
                        .expires_at
                        .is_some_and(|expiry| expiry <= chrono::Utc::now())
                    {
                        continue;
                    }
                    let event_id =
                        EventId::new(authorization.get("tag_id")?.as_str()?.strip_suffix(":1")?)
                            .ok()?;
                    active.push((payload, event_id, revision.clone()));
                }
            }
            _ => {}
        }
    }
    if status != Some(AgentLifecycleState::Active) || active.len() != 1 {
        return None;
    }
    let (payload, event_id, revision) = active.pop()?;
    if payload.verification_method != *selector.verification_method() {
        return None;
    }
    let raw_key = arkret_signatures::agent::validate_agent_runtime_public_key(
        &payload.public_key,
        &payload.verification_method,
    )
    .ok()?
    .raw_public_key;
    let record = state
        .authority_commits()
        .committed_event(&event_id)
        .await
        .ok()??;
    let revision_record = state
        .authority_commits()
        .committed_event_by_commit_id(&revision.commit_id)
        .await
        .ok()??;
    let accepted_payload = AgentKeyAuthorizePayload::try_from(&record.event).ok()?;
    let accepted_key = arkret_signatures::agent::validate_agent_runtime_public_key(
        &accepted_payload.public_key,
        &accepted_payload.verification_method,
    )
    .ok()?;
    if record.event.event_id != event_id
        || record.event.realm_id != pcr_realm_id
        || record.commit.event_ref != event_id
        || accepted_payload.agent_id != *agent_id
        || accepted_payload.key_id != payload.key_id
        || accepted_payload.verification_method != payload.verification_method
        || accepted_key.raw_public_key != raw_key
        || serde_json::to_value(&accepted_payload).ok()? != serde_json::to_value(&payload).ok()?
        || revision_record.commit.commit_id != revision.commit_id
        || revision_record.commit.stream_ref != record.commit.stream_ref
        || revision_record.commit.stream_position != revision.stream_position
        || record.commit.stream_position > revision.stream_position
        || !material.visible_stream_heads.iter().any(|head| {
            head.stream_ref == record.commit.stream_ref
                && head.stream_position >= revision.stream_position
        })
    {
        return None;
    }
    let authorization_ref = CommittedEventRef {
        event_id,
        commit_id: record.commit.commit_id,
        stream_ref: record.commit.stream_ref,
        stream_position: record.commit.stream_position,
    };
    let key = StationSigningKey {
        actor: selector.actor().clone(),
        verification_method: selector.verification_method().clone(),
        public_key_b64u: arkret_wire::Base64UrlString::new(arkret_canonical::base64url_encode(
            raw_key,
        ))
        .ok()?,
        authorization_ref: authorization_ref.event_id.clone(),
    };
    let key = ResolvedSignerKey::from_station_key(
        key,
        authorization_ref,
        revision,
        material.governance_generation,
        selector,
        realm_id,
    )
    .ok()?;
    Some(SignerKeyQueryOutcome::CurrentResolved {
        selector: selector.clone(),
        key,
    })
}

/// Resolve the active Agent producer key for an Event being admitted now.
///
/// This checks the durable Agent status/key projection and the exact accepted
/// authorization Commit at one PCR snapshot cut. Callers still verify the
/// Event producer proof and enforce the Agent's action scope separately. This
/// must never be used for a historical Event whose key may since have rotated.
pub(crate) async fn current_agent_producer_binding(
    state: &AppState,
    event: &arkret_wire::Event,
) -> Result<([u8; 32], CommittedEventRef), String> {
    let producer = event
        .producer_proof
        .as_ref()
        .ok_or_else(|| "Agent Event has no producer proof".to_owned())?;
    let actor = event.executed_by.as_ref().unwrap_or(&event.actor_id);
    current_agent_endpoint_key(state, actor, &producer.verification_method).await
}

/// The Agent endpoint's current accepted signing key for exactly
/// `verification_method`, with the committed authorization that installed it.
pub(crate) async fn current_agent_endpoint_key(
    state: &AppState,
    actor: &arkret_wire::ActorId,
    verification_method: &arkret_wire::DidUrl,
) -> Result<([u8; 32], CommittedEventRef), String> {
    let agent_id = &actor
        .as_account_id()
        .ok_or_else(|| "Agent producer is not an account ActorId".to_owned())?
        .principal_id;
    let agent = state
        .agent_pairings()
        .agent(agent_id.as_str())
        .await
        .map_err(|error| error.to_string())?
        .ok_or_else(|| "Agent producer record unavailable".to_owned())?;
    let realm_id =
        RealmId::new(agent.principal_control_realm_id).map_err(|error| error.to_string())?;
    let selector = SignerKeyQuerySelector::CurrentAdmission {
        sender: CurrentSignerKeyQuerySender::Agent {
            actor: actor.clone(),
            verification_method: verification_method.clone(),
        },
    };
    let Some(SignerKeyQueryOutcome::CurrentResolved { key, .. }) =
        current_agent_key(state, &realm_id, &selector).await
    else {
        return Err("Agent producer has no current accepted signing key".to_owned());
    };
    let raw_key = base64url_decode(key.public_key_b64u.as_str())
        .map_err(|error| error.to_string())?
        .try_into()
        .map_err(|_| "Agent producer key must be 32 bytes".to_owned())?;
    Ok((raw_key, key.authorization_ref))
}

pub(super) async fn current_device_projection_document(
    state: &AppState,
    attestation: &arkret_models_crypto::DeviceProjectionAttestation,
) -> Result<arkret_identity::DidDocument, AppError> {
    let unavailable = || AppError::not_found("current signer evidence is unavailable");
    let did =
        arkret_identity::verification_method_did(attestation.proof.verification_method.as_str())
            .map_err(|_| unavailable())?;
    if arkret_wire::project_did_to_core_id(&did).map_err(|_| unavailable())?
        != attestation.attestation.account_id.station_id
    {
        return Err(unavailable());
    }
    let current = state
        .dids()
        .resolve_current_service_did(&did)
        .await
        .map_err(|_| unavailable())?;
    Ok(current.document)
}

pub(super) fn verify_current_device_projection(
    attestation: &arkret_models_crypto::DeviceProjectionAttestation,
    document: &arkret_identity::DidDocument,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<(), String> {
    let method = &attestation.proof.verification_method;
    let did = arkret_identity::verification_method_did(method.as_str())
        .map_err(|error| error.to_string())?;
    if document.id != did
        || arkret_wire::project_did_to_core_id(&did).map_err(|error| error.to_string())?
            != attestation.attestation.account_id.station_id
    {
        return Err("device projection issuer mismatch".to_owned());
    }
    arkret_identity::validate_verification_method_relationship(
        document,
        method,
        &did,
        arkret_identity::DidVerificationRelationship::AssertionMethod,
    )
    .map_err(|error| error.to_string())?;
    let key = arkret_identity::jws::resolve_ed25519_pubkey_from_document(document, method.as_str())
        .map_err(|error| error.to_string())?;
    arkret_signatures::device_projection::verify_device_projection_attestation(
        attestation,
        &key,
        now,
    )
    .map_err(|error| error.to_string())
}

async fn current_realm_device_key(
    state: &AppState,
    selector: &SignerKeyQuerySelector,
) -> Option<SignerKeyQueryOutcome> {
    let SignerKeyQuerySelector::CurrentRealmDevice {
        actor_id,
        device_id,
        verification_method,
        ..
    } = selector
    else {
        return None;
    };
    let authority = state
        .persistence()
        .applet_managed_device_authority(actor_id, device_id, chrono::Utc::now())
        .await
        .ok()??;
    if authority.governance_service_id != state.service_core_id()
        || verification_method.as_str() != format!("{}#{}", authority.native_did, device_id)
    {
        return None;
    }
    Some(SignerKeyQueryOutcome::CurrentDeviceResolved {
        selector: selector.clone(),
        key: CurrentDeviceSigningKey {
            public_key_b64u: arkret_wire::Base64UrlString::new(arkret_canonical::base64url_encode(
                authority.public_key,
            ))
            .ok()?,
        },
    })
}
