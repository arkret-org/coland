use arkret_models_collaboration::event_query::{
    EventDeliveryStatusOutcome, EventDeliveryStatusRequestBody,
};
use coland_storage::MemberCommittedEventRead;

use super::*;

pub(in crate::routing::events) fn router() -> Router {
    Router::new()
        .push(Router::with_path("events/delivery-status").query(event_delivery_status))
        .push(
            Router::with_path("committed-events/subscribe")
                .get(super::super::sync::events_subscribe),
        )
        .push(Router::with_path("events").post(crate::routing::authority_commit::submit_self))
        .push(Router::with_path("committed-events/{event_id}").get(get_committed_event))
}

#[salvo::oapi::endpoint(operation_id = "ak.self.committed_event.resource.get", tags("events"))]
#[tracing::instrument(skip_all, fields(op = "ak.self.committed_event.resource.get.v1"))]
async fn get_committed_event(
    aa: AuthArgs,
    event_id: PathParam<String>,
    depot: &mut Depot,
    req: &mut Request,
) -> coland_http::result::GuardedJsonResult<CommittedEventView> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let event_id = EventId::new(event_id.into_inner())
        .map_err(|_| AppError::not_found("committed event not found"))?;
    if let Ok(device) = depot
        .get_typed::<crate::routing::identity::applet_managed_device::VerifiedAppletManagedDevice>(
    ) {
        return native_committed_event(state, device, &event_id).await;
    }
    let session = aa.authenticated_session(state, req).await?;
    let caller =
        crate::routing::identity::session_actor::session_actor_from_credential(state, &session)
            .map_err(|_| AppError::not_found("committed event not found"))?;
    // An ordinary Realm's Realm stream is read from this Station's typed
    // current, governing or held as an anchored replica (`federation.md`
    // §4.1.1, `history-visibility.md` §3.1).
    let view = match state
        .authority_commits()
        .committed_event_for_member(&event_id, &caller, &state.service_core_id())
        .await
        .map_err(|error| {
            if error.conflict_code() == Some(coland_storage::ConflictCode::CapabilityDenied) {
                // The disclosure reader applies the current Owned Agent and
                // management ceiling before returning canonical bytes. A
                // registered refusal is not a storage failure, and its private
                // controller basis must not escape in the public Problem.
                AppError::capability_denied("current content read is unavailable")
            } else {
                AppError::internal(format!("committed Event read failed: {error}"))
            }
        })? {
        MemberCommittedEventRead::Read(view) => *view,
        MemberCommittedEventRead::NotVisible => {
            return Err(AppError::not_found("committed event not found"));
        }
        MemberCommittedEventRead::PendingAnchor => {
            return Err(crate::app_error!(
                TemporarilyUnavailable,
                "the held Realm stream is pending its bootstrap anchor",
            ));
        }
        MemberCommittedEventRead::OutsideOrdinaryRealmStream => {
            principal_control_or_scoped_event(state, &session, &event_id).await?
        }
    };
    view.validate_shape().map_err(|error| {
        AppError::internal(format!("durable committed Event view is invalid: {error}"))
    })?;
    let input = coland_storage::AccountContentDeliveryInput::committed(std::slice::from_ref(&view));
    let guard = super::super::sync::content_delivery_guard(state, &session, &input).await?;
    coland_http::result::guarded_json_ok(view, guard)
}

/// The actual authenticated Account reads through the ordinary history and
/// disclosure reducer; its final native guard independently holds all current
/// Device, installation, role, source and resource bounds through handoff.
async fn native_committed_event(
    state: &AppState,
    device: &crate::routing::identity::applet_managed_device::VerifiedAppletManagedDevice,
    event_id: &EventId,
) -> coland_http::result::GuardedJsonResult<CommittedEventView> {
    if device.operation != arkret_wire::ServiceOperationId::SelfCommittedEventResourceGetV1 {
        return Err(AppError::unauthenticated(
            "native operation differs from actual route",
        ));
    }
    let caller = arkret_wire::ActorId::account(device.authority.account_id.clone());
    let view = match state
        .authority_commits()
        .committed_event_for_member(event_id, &caller, &state.service_core_id())
        .await
        .map_err(|_| AppError::not_found("committed event not found"))?
    {
        MemberCommittedEventRead::Read(view) => *view,
        MemberCommittedEventRead::PendingAnchor => {
            return Err(crate::app_error!(
                TemporarilyUnavailable,
                "the held Realm stream is pending its bootstrap anchor"
            ));
        }
        _ => return Err(AppError::not_found("committed event not found")),
    };
    view.validate_shape()
        .map_err(|_| AppError::not_found("committed event not found"))?;
    let guard = crate::routing::identity::applet_managed_device::content_delivery_guard(
        state,
        device,
        std::slice::from_ref(&view),
    )
    .await
    .map_err(|_| AppError::not_found("committed event not found"))?;
    coland_http::result::guarded_json_ok(view, Some(guard))
}

/// A committed Event outside an ordinary Realm's Realm stream -- in a
/// principal-control Realm, or on a Circle or Sidecar stream -- read in full
/// when visible to the session.
async fn principal_control_or_scoped_event(
    state: &AppState,
    session: &SessionRecord,
    event_id: &EventId,
) -> Result<CommittedEventView, AppError> {
    let Some(record) = state
        .event_queries()
        .canonical_event(event_id.as_str())
        .await
        .ok()
        .flatten()
    else {
        return Err(AppError::not_found("committed event not found"));
    };
    if !event_visible_to_session(state, &record, session).await {
        return Err(AppError::not_found("committed event not found"));
    }
    let committed = state
        .persistence()
        .committed_event(event_id)
        .await
        .map_err(|error| AppError::internal(format!("committed Event lookup failed: {error}")))?
        .ok_or_else(|| AppError::not_found("committed event not found"))?;
    Ok(CommittedEventView::Full(CommittedEventFullView {
        commit: committed.commit,
        event: committed.event,
    }))
}

#[handler]
#[tracing::instrument(skip_all, fields(op = "ak.self.events.read.delivery_status.v1"))]
async fn event_delivery_status(
    aa: AuthArgs,
    body: JsonBody<EventDeliveryStatusRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<EventDeliveryStatusOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    super::super::require_agent_session_scope(
        &session,
        arkret_wire::ServiceOperationId::SELF_EVENTS_READ_DELIVERY_STATUS_V1,
    )?;
    let body = body.into_inner();
    let event_id = body.event_id.as_str();
    let record = state
        .event_queries()
        .canonical_event(event_id)
        .await
        .ok()
        .flatten()
        .ok_or_else(|| AppError::not_found("event not found"))?;
    if !event_visible_to_session(state, &record, &session).await {
        return Err(AppError::not_found("event not found"));
    }
    let deliveries = state
        .federation()
        .deliveries_for_event(event_id)
        .await
        .map_err(|error| {
            AppError::internal(format!("Event delivery status unavailable: {error}"))
        })?;
    let mut targets = BTreeMap::new();
    for delivery in deliveries {
        let Some(mut target) =
            coland_services::federation::event_delivery_target_status(&delivery, event_id)
                .map_err(|error| AppError::internal(error.to_string()))?
        else {
            continue;
        };
        let binding =
            delivery.delivery.realm_fanout.as_ref().ok_or_else(|| {
                AppError::internal("projected Realm fanout target lost its binding")
            })?;
        let can_read_service_id = caller_can_read_delivery_target_service(
            state,
            &session,
            binding,
            delivery.delivery.peer_id.as_str(),
        )
        .await;
        if can_read_service_id {
            target.service_id = Some(delivery.delivery.peer_id.clone());
        }
        if targets.insert(target.target_id.clone(), target).is_some() {
            return Err(AppError::internal(
                "duplicate durable Realm fanout target for one Event",
            ));
        }
    }
    let targets = targets.into_values().collect::<Vec<_>>();
    let outcome = EventDeliveryStatusOutcome {
        event_id: body.event_id,
        targets,
    };
    outcome
        .validate()
        .map_err(|error| AppError::internal(format!("invalid Event delivery status: {error}")))?;
    json_ok(outcome)
}

async fn caller_can_read_delivery_target_service(
    state: &AppState,
    session: &SessionRecord,
    binding: &coland_services::federation::RealmFanoutBinding,
    recipient_id: &str,
) -> bool {
    for witness in &binding.authority_witnesses {
        let member_key = witness.member_id.to_string();
        let witness_is_current = state
            .projections()
            .snapshot()
            .member(&binding.realm_id, &member_key)
            .is_some_and(|member| {
                member.state == "join"
                    && witness.member_id.route_service_id().as_str() == recipient_id
                    && member.membership_event_ref.as_deref()
                        == Some(witness.membership_event_ref.as_str())
            });
        if !witness_is_current {
            continue;
        }
        let Ok(Some(membership_event)) = state
            .event_queries()
            .canonical_event(&witness.membership_event_ref)
            .await
        else {
            continue;
        };
        if !event_visible_to_session(state, &membership_event, session).await {
            continue;
        }
        return true;
    }
    false
}
