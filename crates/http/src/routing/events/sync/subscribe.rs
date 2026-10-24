//! Account-aggregate describe + long-lived subscribe stream
//! (`ak.self.account.stream.subscribe.v1`): the timeline / account-data /
//! to_device NDJSON delta machinery and its auth-material gate.

use super::*;

#[endpoint(operation_id = "ak.self.account.read.describe")]
#[tracing::instrument(skip_all, fields(op = "ak.self.account.read.describe.v1"))]
pub(super) async fn account_describe(
    depot: &mut Depot,
) -> coland_http::result::JsonResult<arkret_models_discovery::ServiceDescribe> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    coland_http::result::json_ok(crate::routing::system::describe::build_server_description(
        state,
    ))
}

/// Bounded account long-poll window. An incremental request with no visible
/// changes waits for a durable/broadcast wake-up and completes after 30s with
/// a projection-neutral frontier. The client then reconnects from that cursor.
const ACCOUNT_SUBSCRIBE_DEFAULT_WAIT_MS: u64 = 30_000;
/// SOL-02-005 — debounce window for `account_subscribe` long-poll wakeups.
/// When a broadcast notification passes the visibility filter, further
/// notifications arriving within this window are drained and coalesced so a
/// burst of N broadcasts triggers ONE snapshot rebuild instead of N. Keeps
/// the read-amplification of busy Realms bounded at the cost of up to this
/// much extra delivery latency per long-poll turn.
const SUBSCRIBE_REBUILD_DEBOUNCE_MS: u64 = 150;
#[cfg(test)]
/// Pure predicate: do the `Authorization` header value and/or query string
/// carry authentication material? Split out from the `Request` so the
/// degrade-vs-propagate decision is unit-testable without a live request.
///
/// Mirrors the positions `authenticated_session` inspects: a `Bearer` header,
/// or a token smuggled into the query string (which it rejects outright).
pub(crate) fn auth_material_present(authorization: Option<&str>, query: Option<&str>) -> bool {
    let header_bearer = authorization
        .is_some_and(|value| value.starts_with("Bearer ") || value.starts_with("bearer "));
    let query_token = query.is_some_and(arkret_wire::contains_query_auth_material);
    header_bearer || query_token
}

/// Resolve the required session for account subscribe long-poll.
///
/// client-sync.md requires `Authorization` on this surface. Fail closed on
/// every auth error so clients observe the real 401/auth wire code instead of
/// replaying as anonymous.
pub(crate) async fn account_subscribe_session_or_render(
    state: &AppState,
    req: &Request,
    res: &mut Response,
) -> Option<SessionIdentityState> {
    match authenticated_session(state, req).await {
        Ok(session) => Some(session),
        Err((status, code, message)) => {
            render_error(res, status, code, message);
            None
        }
    }
}

pub(super) fn stream_grant(req: &Request) -> Option<String> {
    coland_http::util::dpop_token(req).map(str::to_owned)
}

pub(super) async fn stream_session_current(
    state: &AppState,
    session: &SessionIdentityState,
    grant: Option<&str>,
) -> bool {
    crate::routing::identity::auth::revalidate_stream_session(state, session, grant)
        .await
        .is_ok()
}

#[handler]
#[tracing::instrument(skip_all, fields(op = "ak.self.account.stream.subscribe.v1"))]
pub(super) async fn account_subscribe(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot
        .get_typed::<AppState>()
        .expect("state injected")
        .clone();
    let body = match account_subscribe_query(req) {
        Ok(body) => body,
        Err(message) => {
            render_error(res, StatusCode::BAD_REQUEST, "param_invalid", &message);
            return;
        }
    };
    let session = match account_subscribe_session_or_render(&state, req, res).await {
        Some(session) => session,
        None => return,
    };
    let grant = stream_grant(req);
    account_response(depot, req, res, state, session, body, grant).await;
}

pub(super) async fn account_response(
    depot: &mut Depot,
    req: &Request,
    res: &mut Response,
    state: AppState,
    session: SessionIdentityState,
    body: AccountSubscribeParameters,
    grant: Option<String>,
) {
    if let Some(token) = body
        .realm_list_parameters
        .as_ref()
        .and_then(|request| request.after.as_ref())
        && let Err(error) = cursor::parse_realm_list_cursor(&state, &session, token.as_str()).await
    {
        render_account_cursor_error(res, error, false);
        return;
    }
    let filter_value = sync_filter_value(body.filter.as_ref());
    let wait_for_event_id =
        if let Ok(wait_for) = depot.get_typed::<coland_http::openapi_routes::WaitForSyncToken>() {
            match parse_and_validate_barrier_cursor(
                &wait_for.0,
                &state,
                &session,
                chrono::Utc::now().timestamp_millis(),
            )
            .await
            {
                Ok(event_id) => Some(event_id),
                Err(error) => {
                    render_account_cursor_error(res, error, true);
                    return;
                }
            }
        } else {
            None
        };
    let subscribe_scope_key = account_subscribe_scope_key(req, Some(&session), &body);
    if reject_subscribe_reconnect(&state, &subscribe_scope_key, res) {
        return;
    }
    let mut after_cursor = if let Some(after) = body.after.as_deref() {
        match cursor::parse_account_cursor(
            after,
            &state,
            Some(&session),
            filter_value.as_ref(),
            chrono::Utc::now().timestamp_millis(),
            body.replace_filter == Some(true),
        )
        .await
        {
            Ok(cursor) => cursor,
            Err(SyncCursorError::Unavailable(message)) => {
                coland_http::error::render_error_code(
                    coland_http::error::ErrorCode::TemporarilyUnavailable,
                    res,
                    message,
                );
                return;
            }
            Err(SyncCursorError::Expired) => {
                coland_http::error::render_error_code(
                    coland_http::error::ErrorCode::CursorExpired,
                    res,
                    "cursor has expired",
                );
                return;
            }
            Err(SyncCursorError::Invalid(message)) => {
                // encoding.md §8.3 closed set: syntax/schema failures pin the
                // top-level `param_invalid` code with reason `invalid_cursor`.
                coland_http::error::render_error_with_reason_code(
                    res,
                    coland_http::error::error_http_status(
                        coland_http::error::ErrorCode::ParamInvalid,
                    ),
                    coland_http::error::ErrorCode::ParamInvalid.as_str(),
                    message,
                    arkret_wire::ReasonCode::INVALID_CURSOR,
                    None,
                );
                return;
            }
            Err(SyncCursorError::Mismatch(message)) | Err(SyncCursorError::Integrity(message)) => {
                coland_http::error::render_error_code(
                    coland_http::error::ErrorCode::CursorIntegrityInvalid,
                    res,
                    message,
                );
                return;
            }
            Err(SyncCursorError::Revoked) => {
                coland_http::error::render_error_code(
                    coland_http::error::ErrorCode::CursorRevoked,
                    res,
                    "cursor authority has been revoked",
                );
                return;
            }
        }
    } else {
        SyncCursor::default()
    };
    if body.after.is_some() {
        let actor = match crate::routing::identity::session_actor::session_actor_from_credential(
            &state, &session,
        ) {
            Ok(actor) => actor,
            Err(error) => {
                tracing::error!(%error, "authenticated account subscribe session has no actor");
                render_error(
                    res,
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    "authenticated session actor is unavailable",
                );
                return;
            }
        };
        if let Some(account) = actor.as_account_id() {
            match current_details::continuation_heads_covered(&state, account, &body, &after_cursor)
                .await
            {
                Ok(true) => {}
                outcome => {
                    if matches!(outcome, Ok(false)) {
                        match current_details::continuation_recoverable(
                            &state,
                            account,
                            &body,
                            &after_cursor,
                        )
                        .await
                        {
                            Ok(true) => {
                                if !stream_session_current(&state, &session, grant.as_deref()).await
                                {
                                    coland_http::error::render_error_code(
                                        coland_http::error::ErrorCode::Unauthenticated,
                                        res,
                                        "session authority is no longer current",
                                    );
                                    return;
                                }
                                let wait = depot
                                    .get_typed::<coland_http::openapi_routes::WaitForSyncToken>()
                                    .ok()
                                    .map(|wait| wait.0.as_str());
                                if let Err(error) =
                                    account_read_inputs_current(&state, &session, &body, wait).await
                                {
                                    render_account_cursor_error(res, error, false);
                                    return;
                                }
                                let details =
                                    arkret_wire::AccountRevisionStaleProblemExtensions::new(
                                        body.after
                                            .clone()
                                            .expect("validated continuation has after"),
                                    )
                                    .expect("validated cursor satisfies the continuation schema");
                                crate::error::render_problem_envelope(
                                    res,
                                    StatusCode::CONFLICT,
                                    arkret_wire::Problem::account_revision_stale(
                                        "verified serving prefix is recovering its accepted head",
                                        details,
                                    ),
                                );
                                return;
                            }
                            Ok(false) => {}
                            Err(error) => {
                                tracing::warn!(%error, "Account continuation recovery is unproved");
                            }
                        }
                    }
                    if let Err(error) = outcome {
                        tracing::warn!(%error, "Account continuation minimum head proof unavailable");
                    }
                    render_error(
                        res,
                        StatusCode::SERVICE_UNAVAILABLE,
                        "temporarily_unavailable",
                        "account continuation head coverage is temporarily unavailable",
                    );
                    return;
                }
            }
        }
        let position = u64::try_from(after_cursor.account_data_change_position)
            .expect("validated account-data change position is non-negative");
        match state
            .account_data()
            .change_position_is_replayable(&actor.to_string(), position)
            .await
        {
            Ok(true) => {}
            Ok(false) => {
                // Reject before subscribing to broadcast or building any
                // incremental snapshot: crossing a retained floor is a
                // terminal resync condition, never a best-effort delta.
                coland_http::error::render_error_code(
                    coland_http::error::ErrorCode::StreamResyncRequired,
                    res,
                    "account-data changes are no longer retained; initial resync is required",
                );
                return;
            }
            Err(error) => {
                tracing::error!(%actor, %error, "failed to verify account-data cursor coverage");
                render_error(
                    res,
                    StatusCode::SERVICE_UNAVAILABLE,
                    "temporarily_unavailable",
                    "account-data cursor coverage is temporarily unavailable",
                );
                return;
            }
        }
    }
    // A newer request does not prove older in-flight responses were installed.
    // Keep unexpired handles available for exact retry and filter replacement;
    // the durable TTL sweeper performs safe reclamation.
    // client-sync.md: the account subscribe surface is read-only. Transient
    // state is not carried here at all in v1 — presence, typing, receipts and
    // call signalling are encrypted Signals on `ak.self.signal.*`, so no
    // `set_presence`-style subscribe parameter exists and establishing or
    // replaying a subscription never triggers a server-side mutation.

    // Subscribe to broadcast BEFORE checking the barrier/building the initial snapshot so an
    // event landing between snapshot-build and long-poll subscribe is not
    // missed.
    let mut rx = state.subscribe_event_notifications();
    if let Some(event_id) = wait_for_event_id.as_deref() {
        let barrier_result = wait_for_account_projection_barrier(&state, &mut rx, event_id).await;
        if let Ok(wait) = depot.get_typed::<coland_http::openapi_routes::WaitForSyncToken>()
            && let Err(error) = parse_and_validate_barrier_cursor(
                &wait.0,
                &state,
                &session,
                chrono::Utc::now().timestamp_millis(),
            )
            .await
        {
            render_account_cursor_error(res, error, true);
            return;
        }
        if let Some(envelope) = account_barrier_refusal(barrier_result) {
            crate::error::render_problem_envelope(res, StatusCode::SERVICE_UNAVAILABLE, envelope);
            return;
        }
        res.headers_mut().insert(
            salvo::http::header::HeaderName::from_static("x-arkret-wait-for-satisfied"),
            salvo::http::HeaderValue::from_static("true"),
        );
    }
    let wait_for_token = depot
        .get_typed::<coland_http::openapi_routes::WaitForSyncToken>()
        .ok()
        .map(|wait| wait.0.clone());
    if let Err(error) =
        account_read_inputs_current(&state, &session, &body, wait_for_token.as_deref()).await
    {
        render_account_cursor_error(res, error, false);
        return;
    }
    after_cursor.input_authorities =
        match cursor::account_input_authorities(&state, &body, wait_for_token.as_deref()).await {
            Ok(records) => records,
            Err(error) => {
                render_account_cursor_error(res, error, false);
                return;
            }
        };
    let response = match build_sync_snapshot(&state, Some(&session), &body, &after_cursor).await {
        Ok(response) => response,
        Err(problem) => {
            let status = arkret_wire::ErrorCode::from_wire(problem.code())
                .map(coland_http::error::error_http_status)
                .unwrap_or(StatusCode::SERVICE_UNAVAILABLE);
            crate::error::render_problem_envelope(res, status, *problem);
            return;
        }
    };
    let initial_cursor = response.cursor.clone();
    // An unavailable detail has no new data or durable detail position. If
    // returned immediately on every continuation, the detail/global turn
    // alternation becomes an unbounded reconnect loop. Use the ordinary idle
    // window, while retaining the unavailable result at timeout and allowing
    // a relevant notification to wake it early.
    let initial_has_delta = body.after.is_none()
        || (!delta_is_empty(&response) && !only_unavailable_details(&response));
    let body_stream = async_stream::stream! {
        if account_read_inputs_current(&state, &session, &body, wait_for_token.as_deref()).await.is_err() {
            yield Err(std::io::Error::other("account cursor authority changed before publication"));
            return;
        }
        if !stream_session_current(&state, &session, grant.as_deref()).await {
            yield Ok::<Bytes,std::io::Error>(ndjson_line(&account_unauthorized_frame()));
            return;
        }
        if initial_has_delta {
            let delivery = match Box::pin(super::account_frame_delivery_guard(&state, &session, &response)).await {
                Ok(guard) => guard,
                Err(_) => {
                    yield Ok::<Bytes,std::io::Error>(ndjson_line(&account_unauthorized_frame()));
                    return;
                }
            };
            let line = ndjson_line(&response);
            if delivery.as_ref().is_some_and(|guard| !guard.permits_handoff()) {
                yield Ok::<Bytes,std::io::Error>(ndjson_line(&account_unauthorized_frame()));
                return;
            }
            yield Ok::<Bytes, std::io::Error>(line);
            if let Some(guard) = delivery && guard.finish().await.is_err() { return; };
            if body.catchup.unwrap_or(false) && initial_cursor.is_some() {
                yield Ok::<Bytes, std::io::Error>(ndjson_line(&account_catchup_complete_frame(
                    initial_cursor.clone(),
                )));
            }
            return;
        }

        let current_cursor = after_cursor;
        let current_cursor_token = body.after.clone();
        let deadline = tokio::time::Instant::now()
            + Duration::from_millis(ACCOUNT_SUBSCRIBE_DEFAULT_WAIT_MS);

        loop {
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_millis((session.expires_at-Utc::now()).num_milliseconds().max(0) as u64)) => {
                    yield Ok::<Bytes,std::io::Error>(ndjson_line(&account_unauthorized_frame()));
                    break;
                }
                _ = tokio::time::sleep_until(deadline) => {
                    if !stream_session_current(&state, &session, grant.as_deref()).await {
                        yield Ok::<Bytes,std::io::Error>(ndjson_line(&account_unauthorized_frame()));
                        break;
                    }
                    if account_read_inputs_current(&state, &session, &body, wait_for_token.as_deref()).await.is_err() {
                        yield Err(std::io::Error::other("account cursor authority changed while waiting"));
                        break;
                    }
                    // Re-read durable projections at timeout. Broadcast is only
                    // a latency hint, so a lost wake-up must not hide data.
                    let final_snapshot = match build_sync_snapshot(
                        &state,
                        Some(&session),
                        &body,
                        &current_cursor,
                    ).await {
                        Ok(frame) => frame,
                        Err(_) => break,
                    };
                    let final_cursor = final_snapshot.cursor.clone();
                    if account_read_inputs_current(&state, &session, &body, wait_for_token.as_deref()).await.is_err() {
                        yield Err(std::io::Error::other("account cursor authority changed before publication"));
                        break;
                    }
                    if delta_is_empty(&final_snapshot) {
                        yield Ok::<Bytes, std::io::Error>(ndjson_line(
                            &account_checkpoint_frame(final_cursor.clone()),
                        ));
                    } else {
                        let delivery = match Box::pin(super::account_frame_delivery_guard(&state, &session, &final_snapshot)).await {
                            Ok(guard) => guard,
                            Err(_) => {
                                yield Ok::<Bytes,std::io::Error>(ndjson_line(&account_unauthorized_frame()));
                                return;
                            }
                        };
                        let line = ndjson_line(&final_snapshot);
                        if delivery.as_ref().is_some_and(|guard| !guard.permits_handoff()) {
                            yield Ok::<Bytes,std::io::Error>(ndjson_line(&account_unauthorized_frame()));
                            return;
                        }
                        yield Ok::<Bytes, std::io::Error>(line);
                        if let Some(guard) = delivery && guard.finish().await.is_err() { return; };
                    }
                    if body.catchup.unwrap_or(false) && final_cursor.is_some() {
                        yield Ok::<Bytes, std::io::Error>(ndjson_line(
                            &account_catchup_complete_frame(final_cursor),
                        ));
                    }
                    break;
                }
                recv = rx.recv() => match recv {
                    Ok(notification) => {
                        if !account_subscribe_notification_should_wake(
                            &state,
                            &notification,
                            Some(&session),
                        ).await {
                            continue;
                        }
                        let drain_until = tokio::time::Instant::now()
                            + Duration::from_millis(SUBSCRIBE_REBUILD_DEBOUNCE_MS);
                        let mut lagged = false;
                        loop {
                            tokio::select! {
                                _ = tokio::time::sleep_until(drain_until) => break,
                                more = rx.recv() => match more {
                                    Ok(_) => {}
                                    Err(RecvError::Lagged(_)) => {
                                        lagged = true;
                                        break;
                                    }
                                    Err(RecvError::Closed) => break,
                                }
                            }
                        }
                        if lagged {
                            arm_subscribe_reconnect(
                                &state,
                                &subscribe_scope_key,
                                SUBSCRIBE_RECONNECT_AFTER_MS,
                            );
                            yield Ok::<Bytes, std::io::Error>(ndjson_line(
                                &account_reconnect_control_frame(
                                    current_cursor_token.as_deref(),
                                    "broadcast_lagged",
                                    SUBSCRIBE_RECONNECT_AFTER_MS,
                                ),
                            ));
                            break;
                        }
                        if !stream_session_current(&state, &session, grant.as_deref()).await {
                            yield Ok::<Bytes,std::io::Error>(ndjson_line(&account_unauthorized_frame()));
                            break;
                        }
                        if account_read_inputs_current(&state, &session, &body, wait_for_token.as_deref()).await.is_err() {
                            yield Err(std::io::Error::other("account cursor authority changed while waiting"));
                            break;
                        }
                        let delta = match build_sync_snapshot(
                            &state,
                            Some(&session),
                            &body,
                            &current_cursor,
                        ).await {
                            Ok(frame) => frame,
                            Err(_) => break,
                        };
                        if delta_is_empty(&delta) {
                            continue;
                        }
                        let delta_cursor = delta.cursor.clone();
                        if account_read_inputs_current(&state, &session, &body, wait_for_token.as_deref()).await.is_err() {
                            yield Err(std::io::Error::other("account cursor authority changed before publication"));
                            break;
                        }
                        let delivery = match Box::pin(super::account_frame_delivery_guard(&state, &session, &delta)).await {
                            Ok(guard) => guard,
                            Err(_) => {
                                yield Ok::<Bytes,std::io::Error>(ndjson_line(&account_unauthorized_frame()));
                                return;
                            }
                        };
                        let line = ndjson_line(&delta);
                        if delivery.as_ref().is_some_and(|guard| !guard.permits_handoff()) {
                            yield Ok::<Bytes,std::io::Error>(ndjson_line(&account_unauthorized_frame()));
                            return;
                        }
                        yield Ok::<Bytes, std::io::Error>(line);
                        if let Some(guard) = delivery && guard.finish().await.is_err() { return; };
                        if body.catchup.unwrap_or(false) && delta_cursor.is_some() {
                            yield Ok::<Bytes, std::io::Error>(ndjson_line(
                                &account_catchup_complete_frame(delta_cursor),
                            ));
                        }
                        break;
                    }
                    Err(RecvError::Lagged(_)) => {
                        arm_subscribe_reconnect(
                            &state,
                            &subscribe_scope_key,
                            SUBSCRIBE_RECONNECT_AFTER_MS,
                        );
                        yield Ok::<Bytes, std::io::Error>(ndjson_line(
                            &account_reconnect_control_frame(
                                current_cursor_token.as_deref(),
                                "broadcast_lagged",
                                SUBSCRIBE_RECONNECT_AFTER_MS,
                            ),
                        ));
                        break;
                    }
                    Err(RecvError::Closed) => break,
                }
            }
        }
    };
    let _ = res.add_header("content-type", "application/x-ndjson", true);
    res.stream(body_stream.boxed());
}

pub(super) fn account_unauthorized_frame()
-> arkret_models_collaboration::sync_frames::account_subscribe::AccountSubscribeFrame {
    let mut frame = account_checkpoint_frame(None);
    frame.kind = arkret_models_collaboration::sync_frames::account_subscribe::AccountSubscribeFrameKind::Unauthorized;
    frame
}

pub(super) async fn account_read_inputs_current(
    state: &AppState,
    session: &SessionIdentityState,
    body: &AccountSubscribeParameters,
    wait_for: Option<&str>,
) -> Result<(), SyncCursorError> {
    if let Some(after) = body.after.as_deref() {
        cursor::parse_account_cursor(
            after,
            state,
            Some(session),
            sync_filter_value(body.filter.as_ref()).as_ref(),
            Utc::now().timestamp_millis(),
            body.replace_filter == Some(true),
        )
        .await?;
    }
    if let Some(after) = body
        .realm_list_parameters
        .as_ref()
        .and_then(|page| page.after.as_ref())
    {
        cursor::parse_realm_list_cursor(state, session, after.as_str()).await?;
    }
    if let Some(wait) = wait_for {
        parse_and_validate_barrier_cursor(wait, state, session, Utc::now().timestamp_millis())
            .await?;
    }
    Ok(())
}

pub(crate) fn account_checkpoint_frame(
    cursor: Option<String>,
) -> arkret_models_collaboration::sync_frames::account_subscribe::AccountSubscribeFrame {
    arkret_models_collaboration::sync_frames::account_subscribe::AccountSubscribeFrame {
        realm_list: None,
        realm_list_changes: None,
        realm_invalidations: None,
        baseline: None,
        kind: arkret_models_collaboration::sync_frames::account_subscribe::AccountSubscribeFrameKind::Checkpoint,
        cursor,
        realms: None,
        to_device: None,
        device_lists: None,
        account_data: None,
        agent_draft_pending_intents: None,
        notifications: None,
        partial: None,
        priority: None,
        reconnect_after_ms: None,
    }
}

pub(crate) fn account_catchup_complete_frame(
    cursor: Option<String>,
) -> arkret_models_collaboration::sync_frames::account_subscribe::AccountSubscribeFrame {
    arkret_models_collaboration::sync_frames::account_subscribe::AccountSubscribeFrame {
        realm_list: None,
        realm_list_changes: None,
        realm_invalidations: None,
        baseline: None,
        kind: arkret_models_collaboration::sync_frames::account_subscribe::AccountSubscribeFrameKind::CatchupComplete,
        cursor,
        realms: None,
        to_device: None,
        device_lists: None,
        account_data: None,
        agent_draft_pending_intents: None,
        notifications: None,
        partial: None,
        priority: None,
        reconnect_after_ms: None,
    }
}

/// A snapshot is "delta-empty" when an incremental sync would carry no
/// new realm state, no membership departure, no queued device messages,
/// and no queued notifications. `account_data` is intentionally excluded — it
/// is always emitted in full for authenticated sessions today, so it
/// would defeat long-poll entirely.
pub(crate) fn delta_is_empty(
    response: &arkret_models_collaboration::sync_frames::account_subscribe::AccountSubscribeFrame,
) -> bool {
    if response.kind != arkret_models_collaboration::sync_frames::account_subscribe::AccountSubscribeFrameKind::Delta
        || response.realm_list.is_some() || response.realm_list_changes.is_some()
        || response.realm_invalidations.as_ref().is_some_and(|items| !items.is_empty())
        || response.baseline.is_some() { return false; }
    response.account_data.as_ref().is_none_or(|data| {
        data.events.is_empty()
            && data
                .station_cas
                .as_ref()
                .is_none_or(|cas| cas.upserts.is_empty() && cas.removals.is_empty())
    }) && response
        .agent_draft_pending_intents
        .as_ref()
        .is_none_or(|pending| match pending {
            arkret_models_collaboration::sync_frames::account_subscribe::AgentDraftPendingIntentContainer::Delta { items, .. }
            | arkret_models_collaboration::sync_frames::account_subscribe::AgentDraftPendingIntentContainer::Baseline { items, .. } => items.is_empty(),
        })
        && response
        .device_lists
        .as_ref()
        .is_none_or(|devices| devices.changed_ids.is_empty() && devices.left_ids.is_empty())
        && response
            .realms
            .as_ref()
            .is_none_or(|realms| realms.entries.is_empty())
        && response
            .to_device
            .as_ref()
            .is_none_or(|to_device| to_device.deliveries.is_empty() && to_device.lost != Some(true))
        && response
            .notifications
            .as_ref()
            .is_none_or(|notifications| notifications.items.is_empty())
}

fn only_unavailable_details(
    response: &arkret_models_collaboration::sync_frames::account_subscribe::AccountSubscribeFrame,
) -> bool {
    let Some(realms) = &response.realms else {
        return false;
    };
    if realms.entries.is_empty()
        || !realms
            .entries
            .values()
            .all(|entry| entry.unavailable.is_some())
    {
        return false;
    }
    let mut without_details = response.clone();
    without_details.realms = None;
    delta_is_empty(&without_details)
}

pub(crate) async fn account_subscribe_notification_should_wake(
    state: &AppState,
    notification: &crate::state::EventNotification,
    session: Option<&SessionIdentityState>,
) -> bool {
    if let crate::state::EventNotificationKind::Account {
        account_id,
        recipient_id,
    } = &notification.kind
    {
        let Some(session) = session else {
            return false;
        };
        if recipient_id != &state.service_core_id() {
            return false;
        }
        let Ok(principal_id) = arkret_wire::DidCoreId::new(session.actor.clone()) else {
            return false;
        };
        let lookup_account_id =
            arkret_wire::AccountId::new(principal_id, state.service_core_id().clone());
        return state
            .identities()
            .account(&lookup_account_id)
            .await
            .ok()
            .flatten()
            .is_some_and(|account| account.account_id == *account_id);
    }
    if realm_id_accessible(state, &notification.realm_id, session).await {
        return true;
    }
    false
}

fn account_subscribe_query(req: &mut Request) -> Result<AccountSubscribeParameters, String> {
    parse_account_subscribe_query(req.uri().query().unwrap_or_default())
}

fn parse_account_subscribe_query(query: &str) -> Result<AccountSubscribeParameters, String> {
    let mut values = BTreeMap::new();
    for pair in query.split('&').filter(|pair| !pair.is_empty()) {
        let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
        let name = decode_account_query_component(name)?;
        let value = decode_account_query_component(value)?;
        if !matches!(
            name.as_str(),
            "after" | "catchup" | "filter" | "realm_list_parameters" | "replace_filter"
        ) {
            return Err(format!("unsupported account subscribe parameter {name}"));
        }
        if values.insert(name, value).is_some() {
            return Err("account subscribe parameters must appear exactly once".to_owned());
        }
    }
    let filter = values
        .remove("filter")
        .map(|value| {
            require_canonical_query_object(&value)?;
            serde_json::from_str::<
                arkret_models_collaboration::sync_frames::account_subscribe::AccountFilter,
            >(&value)
            .map_err(|error| format!("invalid account filter: {error}"))
        })
        .transpose()?;
    let realm_list = values
        .remove("realm_list_parameters")
        .map(|value| {
            require_canonical_query_object(&value)?;
            serde_json::from_str::<
                arkret_models_collaboration::sync_frames::account_subscribe::RealmListParameters,
            >(&value)
            .map_err(|error| format!("invalid Realm list request: {error}"))
        })
        .transpose()?;
    let catchup = values
        .remove("catchup")
        .map(|value| {
            value
                .parse::<bool>()
                .map_err(|_| "invalid catchup boolean".to_owned())
        })
        .transpose()?;
    let replace_filter = values
        .remove("replace_filter")
        .map(|value| {
            value
                .parse::<bool>()
                .map_err(|_| "invalid replace_filter boolean".to_owned())
        })
        .transpose()?;
    let body = AccountSubscribeParameters {
        after: values.remove("after"),
        catchup,
        filter,
        realm_list_parameters: realm_list,
        replace_filter,
    };
    body.validate().map_err(|error| error.to_string())?;
    Ok(body)
}

pub(super) fn decode_account_query_component(value: &str) -> Result<String, String> {
    let mut decoded = Vec::with_capacity(value.len());
    let mut bytes = value.bytes();
    while let Some(byte) = bytes.next() {
        match byte {
            b'%' => {
                let high = bytes.next().and_then(|byte| (byte as char).to_digit(16));
                let low = bytes.next().and_then(|byte| (byte as char).to_digit(16));
                let (Some(high), Some(low)) = (high, low) else {
                    return Err("invalid query percent encoding".to_owned());
                };
                decoded.push((high * 16 + low) as u8);
            }
            b'+' => decoded.push(b' '),
            byte => decoded.push(byte),
        }
    }
    String::from_utf8(decoded).map_err(|_| "account query must be UTF-8".to_owned())
}

fn require_canonical_query_object(value: &str) -> Result<(), String> {
    let object: Value = serde_json::from_str(value).map_err(|error| error.to_string())?;
    if !object.is_object()
        || arkret_canonical::canonical_json_bytes(&object).map_err(|error| error.to_string())?
            != value.as_bytes()
    {
        return Err("account query object must use canonical JSON".to_owned());
    }
    Ok(())
}

pub(crate) async fn wait_for_account_projection_barrier(
    state: &AppState,
    rx: &mut tokio::sync::broadcast::Receiver<crate::state::EventNotification>,
    event_id: &str,
) -> coland_services::ServiceResult<bool> {
    let deadline =
        tokio::time::Instant::now() + Duration::from_millis(ACCOUNT_SUBSCRIBE_DEFAULT_WAIT_MS);
    loop {
        match state.event_queries().projected_event(event_id).await {
            Ok(Some(_)) => return Ok(true),
            Ok(None) => {}
            Err(error) => {
                tracing::warn!(%error, event_id, "account barrier projection lookup failed");
                return Err(error);
            }
        }
        tokio::select! {
            _ = tokio::time::sleep_until(deadline) => return Ok(false),
            notification = rx.recv() => match notification {
                Ok(_) | Err(RecvError::Lagged(_)) => {}
                Err(RecvError::Closed) => return Err(coland_services::ServiceError::Internal(
                    "account barrier notification source closed".into(),
                )),
            }
        }
    }
}

fn account_barrier_refusal(
    outcome: coland_services::ServiceResult<bool>,
) -> Option<arkret_wire::Problem> {
    let detail = match outcome {
        Ok(true) => return None,
        // A missing projection alone does not prove a recoverable accepted
        // prefix. Never build a snapshot or mint any continuation on refusal.
        Ok(false) => "account barrier coverage could not be proved before timeout",
        Err(_) => "account barrier coverage is temporarily unavailable",
    };
    Some(
        arkret_wire::Problem::from_code("temporarily_unavailable", detail)
            .with_instance(arkret_identifiers::new_prefixed_uuid7("ak:request:")),
    )
}

pub(crate) fn render_account_cursor_error(
    res: &mut Response,
    error: SyncCursorError,
    barrier: bool,
) {
    let context = if barrier {
        "X-Arkret-Wait-For"
    } else {
        "after"
    };
    match error {
        SyncCursorError::Unavailable(message) => coland_http::error::render_error_code(
            coland_http::error::ErrorCode::TemporarilyUnavailable,
            res,
            message,
        ),
        SyncCursorError::Expired => coland_http::error::render_error_code(
            coland_http::error::ErrorCode::CursorExpired,
            res,
            &format!("{context} cursor has expired"),
        ),
        // encoding.md §8.3 closed set: syntax/schema failures pin the top-level
        // `param_invalid` code with reason `invalid_cursor`.
        SyncCursorError::Invalid(message) => coland_http::error::render_error_with_reason_code(
            res,
            coland_http::error::error_http_status(coland_http::error::ErrorCode::ParamInvalid),
            coland_http::error::ErrorCode::ParamInvalid.as_str(),
            message,
            arkret_wire::ReasonCode::INVALID_CURSOR,
            None,
        ),
        SyncCursorError::Mismatch(message) | SyncCursorError::Integrity(message) => {
            coland_http::error::render_error_code(
                coland_http::error::ErrorCode::CursorIntegrityInvalid,
                res,
                message,
            )
        }
        SyncCursorError::Revoked => coland_http::error::render_error_code(
            coland_http::error::ErrorCode::CursorRevoked,
            res,
            &format!("{context} cursor authority has been revoked"),
        ),
    }
}

pub(crate) fn sync_filter_value(
    filter: Option<&arkret_models_collaboration::sync_frames::account_subscribe::AccountFilter>,
) -> Option<Value> {
    let Some(filter) = filter else {
        return Some(json!({}));
    };
    let mut value = serde_json::to_value(filter).ok()?;
    if let Some(object) = value.as_object_mut() {
        if let Some(Value::Array(items)) = object.get_mut("realm_ids") {
            items.sort_by(|left, right| left.as_str().cmp(&right.as_str()));
            items.dedup();
        }
        // A stream selection is a set: its digest binds the members, not the
        // order they were listed in. Order by canonical `stream_ref` bytes.
        if let Some(Value::Array(items)) = object.get_mut("stream_refs") {
            items.sort_by_cached_key(|item| {
                arkret_canonical::canonical_json_bytes(item).unwrap_or_default()
            });
        }
    }
    Some(value)
}

fn account_reconnect_control_frame(
    after: Option<&str>,
    _reason: impl Into<String>,
    reconnect_after_ms: u64,
) -> arkret_models_collaboration::sync_frames::account_subscribe::AccountSubscribeFrame {
    let (kind, cursor) = match after {
        Some(cursor) if !cursor.is_empty() => (
            arkret_models_collaboration::sync_frames::account_subscribe::AccountSubscribeFrameKind::Dropped,
            Some(cursor.to_owned()),
        ),
        _ => (arkret_models_collaboration::sync_frames::account_subscribe::AccountSubscribeFrameKind::ResyncRequired, None),
    };
    arkret_models_collaboration::sync_frames::account_subscribe::AccountSubscribeFrame {
        kind,
        cursor,
        baseline: None,
        realm_list: None,
        realm_list_changes: None,
        realm_invalidations: None,
        realms: None,
        to_device: None,
        device_lists: None,
        account_data: None,
        agent_draft_pending_intents: None,
        notifications: None,
        partial: None,
        priority: None,
        reconnect_after_ms: Some(reconnect_after_ms),
    }
}

fn account_subscribe_scope_key(
    req: &Request,
    session: Option<&SessionIdentityState>,
    body: &AccountSubscribeParameters,
) -> String {
    let filter_value = sync_filter_value(body.filter.as_ref());
    format!(
        "ak.self.account.stream.subscribe.v1|{}|filter={}",
        subscribe_subject(req, session),
        cursor::account_filter_digest(filter_value.as_ref())
    )
}

#[cfg(test)]
mod account_query_tests {
    use super::*;

    #[test]
    fn barrier_refusal_never_supplies_a_cut_or_ack_material() {
        assert!(account_barrier_refusal(Ok(true)).is_none());
        for outcome in [
            Ok(false),
            Err(coland_services::ServiceError::Database(
                "storage unavailable".into(),
            )),
        ] {
            let problem = account_barrier_refusal(outcome).unwrap();
            assert_eq!(problem.status, 503);
            assert_eq!(
                problem.error_code(),
                Some(arkret_wire::ErrorCode::TemporarilyUnavailable)
            );
            assert!(problem.extensions.is_empty());
            assert!(problem.account_revision_stale_details().unwrap().is_none());
            assert!(!problem.detail.contains("storage unavailable"));
        }
    }

    #[test]
    fn unavailable_details_wait_without_hiding_other_progress() {
        let pending = serde_json::json!({
            "kind": "delta",
            "cursor": "ak:cursor:pending",
            "realms": {
                "ak:realm:pending": {"unavailable": {"error_code": "revision_unavailable"}}
            }
        });
        let frame = serde_json::from_value(pending.clone()).unwrap();
        assert!(only_unavailable_details(&frame));
        // Timeout must still deliver the pending status, not erase it into
        // an empty frontier. Control frames must also remain immediate.
        assert!(!delta_is_empty(&frame));
        let control = serde_json::from_value(json!({"kind":"resync_required"})).unwrap();
        assert!(!only_unavailable_details(&control));
        let mut with_progress = pending;
        with_progress["realms"]["ak:realm:ready"] = json!({});
        assert!(!only_unavailable_details(
            &serde_json::from_value(with_progress).unwrap()
        ));
    }

    #[test]
    fn closed_query_preserves_empty_interest_and_rejects_ambiguous_encodings() {
        let empty = parse_account_subscribe_query(
            "filter=%7B%22realm_ids%22%3A%5B%5D%7D&realm_list_parameters=%7B%7D",
        )
        .unwrap();
        assert_eq!(empty.filter.unwrap().realm_ids, Some(Vec::new()));
        let bounded = parse_account_subscribe_query("filter=%7B%22window_limit%22%3A0%7D").unwrap();
        assert_eq!(bounded.filter.unwrap().window_limit, Some(0));
        for query in [
            "filter.realm_ids=x",
            "filter=%7B%7D&filter=%7B%7D",
            "catchup=garbage",
            "catchup=true&catchup=false",
            "filter=%7B%22realm_ids%22%3Anull%7D",
            "filter=%7B%22window_limit%22%3A1%2C%22window_limit%22%3A2%7D",
            // The closed filter rejects the retired member.
            "filter=%7B%22timeline_limit%22%3A20%7D",
            "filter=%7B%22window_limit%22%3A101%7D",
            "filter=%7B%20%7D",
            "filter=%FF",
            "filter=%GG",
            "realm_list_parameters=%7B%22limit%22%3A101%7D",
            "replace_filter=true",
        ] {
            assert!(parse_account_subscribe_query(query).is_err(), "{query}");
        }
    }
}
