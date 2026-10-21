//! Hosting-side private PCR proxy. No credential crosses the Station boundary.

use arkret_models_collaboration::consent_private::*;
use arkret_wire::AccountId;
use coland_http::error::AppError;
use coland_services::identity::SessionIdentityState;
use salvo::prelude::*;

use crate::state::AppState;
use crate::{JsonResult, json_ok};

fn invalid(error: impl std::fmt::Display) -> AppError {
    AppError::param_invalid(error.to_string())
}
fn unavailable(error: impl std::fmt::Display) -> AppError {
    crate::app_error!(TemporarilyUnavailable, error.to_string())
}

pub(super) fn peer_router() -> Router {
    Router::with_path("consent")
        .push(Router::with_path("proxy").post(peer_proxy))
        .push(Router::with_path("effects").post(peer_effects))
}
fn quota(state: &AppState) -> arkret_wire::NewSourceQuotaConstraints {
    state
        .config()
        .receive_policy_constraints
        .as_ref()
        .and_then(|c| c.new_source_quota.clone())
        .unwrap_or_default()
}
#[salvo::handler]
#[tracing::instrument(skip_all, fields(op = "ak.peer.consent.command.proxy.v1"))]
async fn peer_proxy(
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<ConsentPrivateProxyOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let peer = super::events::peer::authenticated_peer_context(state, req, true).await?;
    let bytes = req.payload().await.map_err(invalid)?;
    if bytes.len() > 65_536 {
        return Err(invalid("private PCR request exceeds 64 KiB"));
    }
    let request: ConsentPrivateProxyRequest = serde_json::from_slice(bytes).map_err(invalid)?;
    request
        .validate_at(&peer.source_service_id, chrono::Utc::now())
        .map_err(invalid)?;
    let outcome = execute_at_authority(state, &request, &peer.source_service_id).await?;
    json_ok(outcome)
}

pub(super) async fn require_peer_holder(
    state: &AppState,
    holder: &AccountId,
) -> Result<(), AppError> {
    let origin = state
        .persistence()
        .principal_resolution_by_account_id(holder)
        .await
        .map_err(unavailable)?
        .ok_or_else(|| unavailable("accepted holder inception is missing"))?;
    arkret_wire::GenesisGovernance::from_genesis(&origin.genesis_event)
        .map_err(unavailable)?
        .require_transferable()
        .map_err(|e| {
            AppError::from_rejection(
                coland_http::error::ErrorCode::FailedPrecondition,
                e.to_string(),
            )
        })
}
async fn execute_at_authority(
    state: &AppState,
    request: &ConsentPrivateProxyRequest,
    source: &arkret_wire::DidCoreId,
) -> Result<ConsentPrivateProxyOutcome, AppError> {
    require_peer_holder(state, &request.holder_account_id).await?;
    let prepared = super::invites::prepare_private_invite(state, request).await?;
    state
        .persistence()
        .consent_private_command_prepared(
            request,
            source,
            &state.service_core_id(),
            &quota(state),
            prepared.as_ref(),
        )
        .await
        .map_err(unavailable)
}

pub(crate) async fn holder_command(
    state: &AppState,
    session: &SessionIdentityState,
    command: ConsentPrivateCommand,
) -> Result<ConsentPrivateCommandOutcome, AppError> {
    let actor = super::identity::session_actor::validated_session_actor(state, session).await?;
    let holder = actor
        .as_account_id()
        .ok_or_else(|| invalid("private read requires the holder Account"))?
        .clone();
    let device = arkret_wire::DeviceId::new(
        session
            .human_device_id()
            .ok_or_else(|| invalid("private read requires an actual holder Device"))?
            .clone(),
    )
    .map_err(invalid)?;
    execute(
        state,
        &holder,
        ConsentPrivateContext::HolderSession(ConsentPrivateHolderSessionContext {
            kind: ConsentPrivateHolderSessionContextKind::HolderSession,
            actor_id: actor,
            device_id: device,
        }),
        command,
    )
    .await
}

pub(crate) async fn execute(
    state: &AppState,
    holder: &AccountId,
    context: ConsentPrivateContext,
    command: ConsentPrivateCommand,
) -> Result<ConsentPrivateCommandOutcome, AppError> {
    if holder.station_id != state.service_core_id() {
        return Err(invalid(
            "only the holder hosting Station may originate a private proxy",
        ));
    }
    let origin = state
        .persistence()
        .principal_resolution_by_account_id(holder)
        .await
        .map_err(unavailable)?
        .ok_or_else(|| unavailable("accepted holder inception is missing"))?;
    if arkret_wire::GenesisGovernance::from_genesis(&origin.genesis_event)
        .map_err(unavailable)?
        .is_human()
    {
        super::call_admission::holder_location(state, holder).await?;
        let prepared = super::invites::prepare_native_invite(state, holder, &command).await?;
        return state
            .persistence()
            .consent_native_command(
                holder,
                &context,
                &command,
                &state.service_core_id(),
                &quota(state),
                prepared.as_ref(),
            )
            .await
            .map_err(unavailable);
    }
    require_peer_holder(state, holder).await?;
    let (realm, service) = super::call_admission::holder_location(state, holder).await?;
    let located =
        super::realm_join::resolve_verified_authority_of_service(state, &realm, &service).await?;
    let request = ConsentPrivateProxyRequest {
        holder_account_id: holder.clone(),
        realm_id: realm.clone(),
        governance_generation: located.authority.current_generation(),
        nonce: super::call_admission::nonce(),
        expires_at: arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now())
            + chrono::Duration::seconds(30),
        context,
        command,
    };
    request
        .validate_at(&state.service_core_id(), chrono::Utc::now())
        .map_err(invalid)?;
    let outcome = if service == state.service_core_id() {
        execute_at_authority(state, &request, &state.service_core_id()).await?
    } else {
        let bytes = arkret_canonical::canonical_json_bytes(&request).map_err(invalid)?;
        if bytes.len() > 65_536 {
            return Err(invalid("private PCR request exceeds 64 KiB"));
        }
        let response = super::federation::outbox::signed_peer_request(
            state,
            service.as_str(),
            "/_arkret/peer/consent/proxy",
            &bytes,
            65_536,
        )
        .await
        .map_err(unavailable)?;
        if response.status != 200 {
            return Err(unavailable(
                "private accepting authority refused the command",
            ));
        }
        serde_json::from_slice::<ConsentPrivateProxyOutcome>(&response.body).map_err(unavailable)?
    };
    outcome
        .validate_for_request(&request, chrono::Utc::now())
        .map_err(unavailable)?;
    let current =
        super::realm_join::resolve_verified_authority_of_service(state, &realm, &service).await?;
    if current.authority.current_generation() != outcome.governance_generation
        || current.authority.current_service_id() != &service
    {
        return Err(unavailable("private reply crossed an authority transition"));
    }
    state
        .persistence()
        .observe_consent_private_cut(&request, &outcome)
        .await
        .map_err(unavailable)?;
    if let ConsentPrivateCommandOutcome::Effects(effects) = &outcome.outcome {
        let publication = ConsentPrivateEffectsPublishRequest {
            holder_account_id: holder.clone(),
            realm_id: outcome.realm_id.clone(),
            governance_generation: outcome.governance_generation,
            nonce: request.nonce.clone(),
            effective_stream_head: outcome.effective_stream_head.clone(),
            evaluated_at: outcome.evaluated_at,
            expires_at: outcome.expires_at,
            effects: effects.body.clone(),
        };
        // Normalize the already verified original response for the same projection.
        // This value is internal; B never sends or signs a publication as C.
        project_verified_effects(
            state,
            &publication,
            &service,
            &current.current_authority(),
            &current.bundle.realm_stream_head,
        )
        .await?;
    }
    Ok(outcome.outcome)
}

pub(crate) async fn list(
    state: &AppState,
    session: &SessionIdentityState,
) -> Result<arkret_models_collaboration::consent_operations::ConsentList, AppError> {
    match holder_command(
        state,
        session,
        ConsentPrivateCommand::List(ConsentPrivateListCommand {
            kind: ConsentPrivateListCommandKind::List,
            body: ConsentPrivateEmptyBody {},
        }),
    )
    .await?
    {
        ConsentPrivateCommandOutcome::List(outcome) => Ok(outcome.body),
        _ => Err(unavailable("private authority returned another command")),
    }
}

pub(crate) async fn submit_consent(
    state: &AppState,
    session: &SessionIdentityState,
    submission: &arkret_wire::EventAdmissionSubmission,
) -> Result<arkret_models_collaboration::consent_operations::ConsentView, AppError> {
    let actor = super::identity::session_actor::validated_session_actor(state, session).await?;
    if submission.event.actor_id != actor {
        return Err(AppError::capability_denied(
            "Consent Event does not belong to the authenticated holder",
        ));
    }
    let outcome = crate::state::authority_pcr::submit_self(state, session, submission)
        .await
        .map_err(super::identity::consent::consent_error)?
        .ok_or_else(|| invalid("Consent Event is outside the accepted inception PCR"))?;
    let arkret_wire::AuthoritySubmitOutcome::Accepted { commit, .. } = outcome else {
        return Err(unavailable("Consent original was not accepted"));
    };
    let payload: arkret_models_collaboration::events_payloads::consent::ConsentReplacePayload =
        serde_json::from_value(serde_json::to_value(&submission.event.payload).map_err(invalid)?)
            .map_err(invalid)?;
    let arkret_models_collaboration::events_payloads::consent::ConsentPeer::Actor {
        actor_id: peer_id,
    } = payload.peer;
    let body = ConsentPrivateVersionBody {
        peer: arkret_models_collaboration::events_payloads::consent::ConsentPeer::Actor {
            actor_id: peer_id,
        },
        event_id: submission.event.event_id.clone(),
        commit_id: commit.commit_id,
    };
    match holder_command(
        state,
        session,
        ConsentPrivateCommand::Version(ConsentPrivateVersionCommand {
            kind: ConsentPrivateVersionCommandKind::Version,
            body,
        }),
    )
    .await?
    {
        ConsentPrivateCommandOutcome::Version(outcome) => Ok(outcome.body),
        _ => Err(unavailable(
            "private authority did not return the accepted original version",
        )),
    }
}

#[salvo::handler]
#[tracing::instrument(skip_all, fields(op = "ak.peer.consent.command.publish_effects.v1"))]
async fn peer_effects(
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<ConsentPrivateEffectsPublishOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let peer = super::events::peer::authenticated_peer_context(state, req, true).await?;
    let bytes = req.payload().await.map_err(invalid)?;
    if bytes.len() > 1_048_576 {
        return Err(invalid("private effects exceed 1 MiB"));
    }
    let request: ConsentPrivateEffectsPublishRequest =
        serde_json::from_slice(bytes).map_err(invalid)?;
    json_ok(project_publication(state, &request, &peer.source_service_id).await?)
}
async fn project_publication(
    state: &AppState,
    request: &ConsentPrivateEffectsPublishRequest,
    source: &arkret_wire::DidCoreId,
) -> Result<ConsentPrivateEffectsPublishOutcome, AppError> {
    require_peer_holder(state, &request.holder_account_id).await?;
    if request.holder_account_id.station_id != state.service_core_id() {
        return Err(invalid(
            "publication destination is not the holder hosting Station",
        ));
    }
    let (realm, service) =
        super::call_admission::holder_location(state, &request.holder_account_id).await?;
    if realm != request.realm_id || &service != source {
        return Err(unavailable(
            "publication Source is not the independently located authority",
        ));
    }
    let located =
        super::realm_join::resolve_verified_authority_of_service(state, &realm, &service).await?;
    project_verified_effects(
        state,
        request,
        source,
        &located.current_authority(),
        &located.bundle.realm_stream_head,
    )
    .await
}
async fn project_verified_effects(
    state: &AppState,
    request: &ConsentPrivateEffectsPublishRequest,
    source: &arkret_wire::DidCoreId,
    authority: &coland_storage::CurrentRealmAuthority,
    head: &arkret_wire::CommitStreamHead,
) -> Result<ConsentPrivateEffectsPublishOutcome, AppError> {
    let projection = state
        .persistence()
        .project_consent_effect_publication(
            request,
            source,
            &state.service_core_id(),
            authority,
            head,
        )
        .await
        .map_err(unavailable)?;
    fanout_native_updates(state, &request.holder_account_id, projection.updates).await;
    Ok(projection.outcome)
}
async fn fanout_native_updates(
    state: &AppState,
    holder: &AccountId,
    updates: Vec<coland_storage::AccountDataRecord>,
) {
    for update in updates {
        use super::identity::device_messages::{
            ActorPrivateAccountDataOperation, ActorPrivateAccountDataUpdate,
            ActorPrivateDeviceUpdate, fanout_actor_private_update, station_device_message_sender,
        };
        fanout_actor_private_update(
            state,
            holder.principal_id.as_str(),
            ActorPrivateDeviceUpdate::AccountData {
                sender: station_device_message_sender(state),
                content: ActorPrivateAccountDataUpdate {
                    operation: ActorPrivateAccountDataOperation::Put,
                    account_data_key: update.account_data_key,
                    revision: update.revision,
                    content: Some(update.payload),
                    updated_at: update.updated_at,
                },
                created_at: update.updated_at,
            },
        )
        .await;
    }
}
async fn publish_pending(state: &AppState) -> Result<(), AppError> {
    // Development-only scheduler control; it never changes admission or durable state.
    if state.config().development_mode
        && let Some(path) = std::env::var_os("COLAND_CONFORMANCE_PRIVATE_EFFECTS_PAUSE_FILE")
        && tokio::fs::try_exists(path).await.map_err(unavailable)?
    {
        return Ok(());
    }
    let issuer = state.service_core_id();
    let holders = state
        .persistence()
        .pending_consent_effect_holders(&issuer)
        .await
        .map_err(unavailable)?;
    for holder in holders {
        let attempt = async {
            let origin = state
                .persistence()
                .principal_resolution_by_account_id(&holder)
                .await
                .map_err(unavailable)?
                .ok_or_else(|| unavailable("accepted holder inception is missing"))?;
            if arkret_wire::GenesisGovernance::from_genesis(&origin.genesis_event)
                .map_err(unavailable)?
                .is_human()
            {
                let updates = state
                    .persistence()
                    .drain_native_consent_effects(&holder, &issuer)
                    .await
                    .map_err(unavailable)?;
                fanout_native_updates(state, &holder, updates).await;
                return Ok::<(), AppError>(());
            }
            let Some(publication) = state
                .persistence()
                .prepare_consent_effect_publication(
                    &holder,
                    &issuer,
                    super::call_admission::nonce(),
                )
                .await
                .map_err(unavailable)?
            else {
                return Ok::<(), AppError>(());
            };
            let request = &publication.request;
            let outcome = if holder.station_id == issuer {
                project_publication(state, request, &issuer).await?
            } else {
                let bytes = arkret_canonical::canonical_json_bytes(request).map_err(invalid)?;
                if bytes.len() > 1_048_576 {
                    return Err(unavailable(
                        "private effects exceed the registered publication bound",
                    ));
                }
                let response = super::federation::outbox::signed_peer_request(
                    state,
                    holder.station_id.as_str(),
                    "/_arkret/peer/consent/effects",
                    &bytes,
                    1_048_576,
                )
                .await
                .map_err(unavailable)?;
                if response.status != 200 {
                    return Err(unavailable(
                        "hosting Station has not acknowledged the private publication",
                    ));
                }
                serde_json::from_slice::<ConsentPrivateEffectsPublishOutcome>(&response.body)
                    .map_err(unavailable)?
            };
            outcome.validate_for_request(request).map_err(unavailable)?;
            state
                .persistence()
                .acknowledge_consent_effect_publication(&holder, &issuer, publication.sequence)
                .await
                .map_err(unavailable)
        }
        .await;
        if let Err(error) = attempt {
            tracing::debug!(code=?error.code,"private effect publication retained for recovery");
        }
    }
    Ok(())
}
pub fn spawn_effect_publication_worker(state: AppState) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(1));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tick.tick().await;
            if let Err(error) = publish_pending(&state).await {
                tracing::debug!(code=?error.code,"private effect recovery scan deferred");
            }
        }
    })
}

pub(crate) async fn refresh_holder_effects(
    state: &AppState,
    session: &SessionIdentityState,
) -> Result<(), AppError> {
    let result = holder_command(
        state,
        session,
        ConsentPrivateCommand::Effects(ConsentPrivateEffectsCommand {
            kind: ConsentPrivateEffectsCommandKind::Effects,
            body: ConsentPrivateEmptyBody {},
        }),
    )
    .await?;
    if !matches!(result, ConsentPrivateCommandOutcome::Effects(_)) {
        return Err(unavailable("private authority returned another command"));
    }
    Ok(())
}
