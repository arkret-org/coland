use super::*;

fn session_actor(state: &AppState, session: &SessionIdentityState) -> Option<arkret_wire::ActorId> {
    crate::routing::identity::session_actor::session_actor_from_credential(state, session).ok()
}

/// Build one snapshot of the account-aggregate sync response for the next
/// `ak.self.account.stream.subscribe.v1` delta frame.
pub(crate) async fn build_sync_snapshot(
    state: &AppState,
    session: Option<&SessionIdentityState>,
    body: &SyncRequestBody,
    after_cursor: &SyncCursor,
) -> Result<
    arkret_models_collaboration::sync_frames::account_subscribe::AccountSubscribeFrame,
    Box<arkret_wire::Problem>,
> {
    if let Some(frame) = current_details::frame(state, session, body, after_cursor).await? {
        return Ok(frame);
    }
    build_global_sync_snapshot(state, session, body, after_cursor).await
}

async fn build_global_sync_snapshot(
    state: &AppState,
    session: Option<&SessionIdentityState>,
    body: &SyncRequestBody,
    after_cursor: &SyncCursor,
) -> Result<
    arkret_models_collaboration::sync_frames::account_subscribe::AccountSubscribeFrame,
    Box<arkret_wire::Problem>,
> {
    let filter_value = sync_filter_value(body.filter.as_ref());
    // Capture the Station-CAS retention coordinate before reading the
    // account-global projection. A later CAS may therefore cause a harmless
    // conservative resync, but this cursor can never claim coverage for a
    // change that was not yet eligible for this snapshot.
    let account_data_change_position = if let Some(session) = session {
        let Some(actor) = session_actor(state, session) else {
            return Ok(
                serde_json::from_value(json!({"kind":"unauthorized"})).expect("unauthorized frame")
            );
        };
        match state
            .account_data()
            .latest_change_position(&actor.to_string())
            .await
        {
            Ok(position) => match i64::try_from(position) {
                Ok(position) => position,
                Err(_) => {
                    tracing::error!(%actor, position, "account-data change position exceeds cursor range");
                    return Err(account_unavailable());
                }
            },
            Err(error) => {
                tracing::error!(%actor, %error, "account-data replay frontier unavailable");
                return Err(account_unavailable());
            }
        }
    } else {
        after_cursor.account_data_change_position
    };
    let summary_delta = if let Some(session) = session {
        match demand_list::read(state, session, body, after_cursor).await {
            Ok(delta) => Some(delta),
            Err(global_channels::GlobalReadError::Cursor(error)) => {
                return Err(cursor::issuance_problem(error));
            }
            Err(global_channels::GlobalReadError::ResyncRequired) => {
                return Ok(serde_json::from_value(json!({"kind":"resync_required"}))
                    .expect("resync frame"));
            }
            Err(global_channels::GlobalReadError::Unavailable(error)) => {
                tracing::warn!(%error, "account summary snapshot unavailable");
                return Err(account_unavailable());
            }
        }
    } else {
        None
    };

    let timeline_positions = after_cursor.positions.clone();
    let account_positions = after_cursor.account_positions.clone();
    let global = if let Some(session) = session {
        match global_channels::read(
            state,
            session,
            after_cursor,
            summary_delta
                .as_ref()
                .and_then(|delta| delta.initial_global_snapshot),
        )
        .await
        {
            Ok(delta) => delta,
            Err(global_channels::GlobalReadError::Cursor(error)) => {
                return Err(cursor::issuance_problem(error));
            }
            Err(global_channels::GlobalReadError::ResyncRequired) => {
                return Ok(serde_json::from_value(json!({"kind":"resync_required"}))
                    .expect("resync frame"));
            }
            Err(global_channels::GlobalReadError::Unavailable(error)) => {
                tracing::error!(%error, "account global slice unavailable");
                return Err(account_unavailable());
            }
        }
    } else {
        return Ok(
            serde_json::from_value(json!({"kind":"unauthorized"})).expect("unauthorized frame")
        );
    };
    let sync_realms = BTreeMap::new();
    let mut to_device_position = after_cursor.to_device_position;
    let mut to_device_ack_token = None;
    let mut to_device_limited = false;
    let mut to_device_next_cursor = None;
    let mut to_device_lost = None;
    let to_device = if let Some(session) =
        session.filter(|session| session.agent_session().is_none())
    {
        let lost_watermark = match state
            .deliveries()
            .device_message_lost_watermark(&session.actor, session.require_human_device_id())
            .await
        {
            Ok(watermark) => watermark,
            Err(error) => {
                tracing::error!(%error, "failed to read to-device lost watermark during sync snapshot");
                return Err(account_unavailable());
            }
        };
        if lost_watermark.is_some_and(|position| position > after_cursor.to_device_position) {
            to_device_lost = Some(true);
            if let Some(lost_watermark) = lost_watermark {
                to_device_position = to_device_position.max(lost_watermark);
            }
        }
        let selector = crate::routing::identity::device_messages::recipient_queue_selector(session)
            .expect("human account stream has a human recipient selector");
        let queued = match state
            .deliveries()
            .recipient_deliveries_after(&selector, after_cursor.to_device_position, 101)
            .await
        {
            Ok(queued) => queued,
            Err(error) => {
                tracing::error!(%error, "recipient delivery queue unavailable during account delta");
                return Err(account_unavailable());
            }
        };
        let queued_count = queued.len();
        let mut page = Vec::new();
        let mut page_bytes = 0usize;
        for message in queued.into_iter().take(100) {
            let bytes = arkret_canonical::canonical_json_bytes(&message.delivery)
                .map_or(usize::MAX, |value| value.len());
            if page_bytes.saturating_add(bytes) > 512 * 1024 {
                break;
            }
            page_bytes += bytes;
            page.push(message);
        }
        if page.is_empty() && queued_count > 0 {
            tracing::warn!(
                "recipient delivery exceeds account delta frame budget; use the queue pull operation"
            );
            return Err(account_unavailable());
        }
        to_device_limited = page.len() < queued_count;
        let deliveries = page.iter().map(|record| record.delivery.clone()).collect();
        if let Some(max_position) = page.iter().map(|message| message.position).max() {
            to_device_position = to_device_position.max(max_position);
            to_device_ack_token = match state
                .deliveries()
                .issue_recipient_ack_token(&selector, max_position)
                .await
            {
                Ok(Some(token)) => Some(token),
                Ok(None) => {
                    tracing::error!("recipient delivery ACK token was not issued for a queued row");
                    return Err(account_unavailable());
                }
                Err(error) => {
                    tracing::error!(%error, "recipient delivery ACK token unavailable");
                    return Err(account_unavailable());
                }
            };
            if to_device_limited {
                to_device_next_cursor = match cursor::device_messages_cursor(
                    state,
                    session,
                    to_device_position,
                )
                .await
                {
                    Ok(cursor) => Some(cursor),
                    Err(error) => {
                        tracing::error!(?error, "recipient queue continuation unavailable");
                        return Err(account_unavailable());
                    }
                };
            }
        }
        if to_device_limited && to_device_next_cursor.is_none() {
            to_device_next_cursor =
                match cursor::device_messages_cursor(state, session, to_device_position).await {
                    Ok(cursor) => Some(cursor),
                    Err(error) => {
                        tracing::error!(?error, "recipient queue continuation unavailable");
                        return Err(account_unavailable());
                    }
                };
        }
        deliveries
    } else {
        Vec::new()
    };

    if to_device_next_cursor.as_ref().is_some_and(String::is_empty) {
        return Err(account_unavailable());
    }

    let cursor = cursor::sync_token_for_account_positions(
        state,
        session,
        filter_value.as_ref(),
        timeline_positions,
        account_positions,
        to_device_position,
        summary_delta
            .as_ref()
            .map_or(after_cursor.account_summary_position, |delta| {
                delta.position
            }),
        account_data_change_position,
        Some(global.context),
        after_cursor.detail_positions.clone(),
        true,
        after_cursor.detail_next_realm.clone(),
        &after_cursor.input_authorities,
    )
    .await;
    let cursor = match cursor {
        Ok(cursor) => cursor,
        Err(error) => {
            tracing::error!(?error, "account continuation unavailable");
            return Err(cursor::issuance_problem(error));
        }
    };
    let response = arkret_models_collaboration::sync_frames::account_subscribe::AccountSubscribeFrame {
        realm_list: summary_delta.as_ref().and_then(|delta| delta.page.clone()),
        realm_list_changes: summary_delta.as_ref().and_then(|delta| delta.changes.clone()),
        realm_invalidations: summary_delta.and_then(|delta| delta.invalidations),
        baseline: global.baseline,
        kind: arkret_models_collaboration::sync_frames::account_subscribe::AccountSubscribeFrameKind::Delta,
        cursor: Some(cursor),
        realms: Some(arkret_models_collaboration::sync_frames::account_subscribe::AccountSubscribeRealms {
            entries: sync_realms,
        }),
        to_device: Some(arkret_models_collaboration::sync_frames::account_subscribe::RecipientDeliveryContainer {
            deliveries: to_device,
            ack_token: to_device_ack_token,
            lost: to_device_lost,
            limited: to_device_limited.then_some(true),
            next_cursor: to_device_next_cursor,
        }),
        device_lists: Some(global.device_lists),
        account_data: Some(global.account_data),
        agent_draft_pending_intents: global.agent_draft_pending_intents,
        notifications: Some(global.notifications),
        partial: None,
        priority: None,
        reconnect_after_ms: None,
    };
    // An empty global delta is not sent: the long poll keeps waiting and the
    // caller keeps its cursor. There is no cursor-only "frontier" frame kind.
    Ok(response)
}

fn account_unavailable() -> Box<arkret_wire::Problem> {
    Box::new(arkret_wire::Problem::from_code(
        "temporarily_unavailable",
        "Account global cut could not be proved",
    ))
}

#[cfg(test)]
pub(crate) async fn projection_record_visible_to_session(
    state: &AppState,
    event: &ProjectedEvent,
    session: Option<&SessionIdentityState>,
) -> bool {
    if !realm_event_visible_to_session(
        state,
        &event.realm_id,
        event.received_at,
        event.sender.as_deref(),
        session,
    )
    .await
    {
        return false;
    }
    let projection = state.projections().snapshot();
    let sidecar_id = match &event.event_kind {
        arkret_wire::EventKind::SidecarCreate => event
            .event_id
            .strip_prefix("ak:event:")
            .map(|event_token| format!("ak:sidecar:{event_token}")),
        arkret_wire::EventKind::SidecarContextAttach
        | arkret_wire::EventKind::AgentSidecarExchangeControl => event
            .payload
            .get("sidecar_id")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
        // Remaining sidecar-bearing kinds are the MLS events, whose payloads
        // name the binding `governance_binding` (`mls_governance_binding` is a
        // profile / reason-code prefix, never a payload field).
        _ => crate::routing::mls::payload_fields::governance_binding(&event.payload)
            .and_then(|binding| binding.get("sidecar_id"))
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
    };
    if let Some(sidecar_id) = sidecar_id {
        return session.is_some_and(|session| {
            projection.sidecars.get(&sidecar_id).is_some_and(|sidecar| {
                session_actor(state, session).is_some_and(|actor| {
                    actor.as_account_id() == Some(&sidecar.controller_account_id)
                })
            })
        });
    }
    let scope_circle_id = projection_event_scope_circle_id(&projection, event);
    circle_scope_visible_to_session(
        state,
        &projection,
        scope_circle_id.as_deref(),
        event.received_at,
        session,
        event.sender.as_deref(),
    )
}

#[cfg(test)]
fn projection_event_scope_circle_id(
    projection: &ProjectionState,
    event: &ProjectedEvent,
) -> Option<String> {
    if event.event_kind == arkret_wire::EventKind::MessageCreate {
        return event
            .payload
            .get("strand_id")
            .and_then(Value::as_str)
            .and_then(|strand_id| projection.strand_scope_circle_id(strand_id));
    }
    let explicit_scope = event
        .payload
        .get("scope_circle_id")
        .and_then(Value::as_str)
        .or_else(|| {
            event
                .payload
                .get("object")
                .and_then(Value::as_object)
                .and_then(|object| object.get("scope_circle_id"))
                .and_then(Value::as_str)
        })
        .or_else(|| {
            event
                .payload
                .get("relation")
                .and_then(Value::as_object)
                .and_then(|relation| relation.get("scope_circle_id"))
                .and_then(Value::as_str)
        })
        .filter(|value| value.starts_with("ak:circle:"))
        .map(ToOwned::to_owned);
    if explicit_scope.is_some() {
        return explicit_scope;
    }
    if event.event_kind == arkret_wire::EventKind::RelationCreate {
        let relation = event.payload.get("relation").and_then(Value::as_object);
        return relation
            .and_then(|value| value.get("from_ref"))
            .and_then(Value::as_str)
            .or_else(|| {
                relation
                    .and_then(|value| value.get("to_ref"))
                    .and_then(Value::as_str)
            })
            .and_then(|object_ref| {
                projection
                    .strand_scope_circle_id(object_ref)
                    .or_else(|| projection.relation_scope_circle_id(object_ref))
                    .or_else(|| projection.morph_scope_circle_id(object_ref))
                    .or_else(|| projection.space_container_scope_circle_id(object_ref))
            });
    }
    None
}

#[cfg(test)]
pub(super) fn circle_scope_visible_to_session(
    state: &AppState,
    projection: &ProjectionState,
    scope_circle_id: Option<&str>,
    event_created_at: chrono::DateTime<chrono::Utc>,
    session: Option<&SessionIdentityState>,
    sender: Option<&str>,
) -> bool {
    let Some(scope_circle_id) = scope_circle_id else {
        return true;
    };
    let Some(actor) = session.and_then(|session| session_actor(state, session)) else {
        return false;
    };
    let actor_key = actor.to_string();
    if sender == Some(actor_key.as_str()) {
        return true;
    }
    projection.circle_scope_visible_to_actor_at(scope_circle_id, &actor_key, event_created_at)
}

#[cfg(test)]
mod account_notification_tests {
    use super::*;

    #[test]
    fn typed_agent_approval_uses_discriminator_free_notification_delta() {
        let delta =
            arkret_models_collaboration::sync_frames::account_subscribe::NotificationDelta::try_new(
                arkret_models_collaboration::objects::read_receipts::NotificationIdentity::AgentApproval(
                    arkret_wire::NotificationId::new(
                        "ak:notification:019fa1ef-00ee-77e0-9f06-2f2d36bf2475".to_owned(),
                    )
                    .expect("test notification id"),
                ),
                arkret_models_collaboration::sync_frames::account_subscribe::NotificationDeltaAction::Upsert,
                Some(
                    arkret_models_collaboration::sync_frames::account_subscribe::NotificationData::AgentRuntimeApproval(
                        arkret_models_collaboration::account_subscribe_projections::AgentRuntimeApprovalNotificationData {
                            approval_request_id: arkret_models_collaboration::account_subscribe_projections::AgentRuntimeApprovalRequestId::new(
                                "agent_runtime_approval:019fa1ef-00ee-77e0-9f06-2f1d9ed5e3fa",
                            )
                            .unwrap(),
                            agent_id: arkret_wire::DidCoreId::new(
                                "ak:did_core:web:agent.example".to_owned(),
                            )
                            .expect("test Agent core id"),
                            requested_at: "2026-07-27T04:57:02.959Z"
                                .parse()
                                .expect("test requested_at"),
                            expires_at: "2026-07-27T05:07:02.959Z"
                                .parse()
                                .expect("test expires_at"),
                        },
                    ),
                ),
            )
            .expect("typed Agent approval must be valid");
        let wire = serde_json::to_value(delta).expect("NotificationDelta must serialize");

        assert!(wire.get("notification_kind").is_none());
        assert!(wire["data"].get("kind").is_none());
        assert_eq!(wire.get("action").and_then(Value::as_str), Some("upsert"));
    }
}
