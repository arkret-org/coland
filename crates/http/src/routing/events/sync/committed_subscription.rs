//! Bounded committed-event subscription over independent authorized streams.

use arkret_models_collaboration::sync_frames::committed_event_subscribe::{
    CommittedEventSubscribeFrame as Frame, CommittedEventSubscribeFrameKind as Kind,
    CommittedEventSubscribeFramePayload as Payload,
};
use arkret_wire::{
    CommitStreamHead, CommitStreamRef, RealmStreamView, StreamScanDirection, StreamScanRequestBody,
};
use coland_http::error::AppError;

use super::*;

const PAGE_ITEMS: u16 = 64;
const RESPONSE_BYTES: usize = 1_048_576;
const WAIT: Duration = Duration::from_secs(30);

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct StreamProgress {
    stream_ref: CommitStreamRef,
    head: CommitStreamHead,
    readable_floor: Option<arkret_wire::ReadableFloor>,
    history_digest: String,
}

#[derive(Clone)]
struct AuthorizedStream {
    row: RealmStreamView,
    history_digest: String,
}
impl std::ops::Deref for AuthorizedStream {
    type Target = RealmStreamView;
    fn deref(&self) -> &Self::Target {
        &self.row
    }
}
impl std::ops::DerefMut for AuthorizedStream {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.row
    }
}

#[derive(Clone, Debug)]
pub(super) struct Selection {
    realms: Vec<String>,
    actors: BTreeSet<String>,
    after: Option<String>,
    catchup: bool,
}

fn invalid(message: impl Into<String>) -> AppError {
    AppError::param_invalid(message)
}
fn unavailable(message: impl Into<String>) -> AppError {
    crate::app_error!(TemporarilyUnavailable, message.into())
}
fn denied() -> AppError {
    AppError::capability_denied("the subscription is not readable by this caller")
}
fn render(res: &mut Response, error: AppError) {
    render_error(res, error.http_status(), error.wire_code(), &error.message);
}

fn selection(query: &str) -> Result<Selection, AppError> {
    let mut realms = Vec::new();
    let mut actors = Vec::new();
    let mut single = BTreeMap::new();
    for pair in query.split('&').filter(|pair| !pair.is_empty()) {
        let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
        let name = super::subscribe::decode_account_query_component(name).map_err(invalid)?;
        let value = super::subscribe::decode_account_query_component(value).map_err(invalid)?;
        match name.as_str() {
            "realm_ids" => {
                arkret_wire::RealmId::new(&value).map_err(|error| invalid(error.to_string()))?;
                realms.push(value);
            }
            "actor_ids" => actors.push(value),
            "after" | "catchup" if !single.contains_key(&name) => {
                single.insert(name, value);
            }
            _ => {
                return Err(invalid(
                    "unknown or duplicate committed-event subscribe parameter",
                ));
            }
        }
    }
    if realms.len() > 256 || realms.iter().collect::<BTreeSet<_>>().len() != realms.len() {
        return Err(invalid("realm_ids must be unique and at most 256 entries"));
    }
    let actors = super::events_query::canonical_actor_selectors(&actors)?;
    if realms.is_empty() && actors.is_empty() {
        return Err(invalid("a Realm or Actor selector is required"));
    }
    realms.sort();
    let catchup = match single.remove("catchup").as_deref() {
        None | Some("false") => false,
        Some("true") => true,
        _ => return Err(invalid("catchup must be true or false")),
    };
    let after = single.remove("after");
    if catchup && after.is_none() {
        return Err(invalid("catchup requires after"));
    }
    Ok(Selection {
        realms,
        actors,
        after,
        catchup,
    })
}

async fn streams(
    state: &AppState,
    session: &SessionIdentityState,
    selected: &Selection,
) -> Result<Vec<AuthorizedStream>, AppError> {
    if session.expires_at <= Utc::now() {
        return Err(denied());
    }
    let actor =
        crate::routing::identity::session_actor::validated_session_actor(state, session).await?;
    let account = actor.as_account_id().ok_or_else(denied)?;
    let mut realms = selected.realms.clone();
    if realms.is_empty() {
        super::events_query::authorize_actor_only_selectors(state, Some(session), &selected.actors)
            .await?;
        // An actor selector never grants the holder access to someone else's
        // private stream. Enumerate only the holder's currently readable Realms.
        realms = state
            .authority_commits()
            .signal_recipient_realms(&actor)
            .await
            .map_err(|error| unavailable(error.to_string()))?
            .into_iter()
            .map(|realm| realm.to_string())
            .collect();
    }
    let mut result = Vec::new();
    for realm in realms {
        let realm = arkret_wire::RealmId::new(realm).map_err(|error| invalid(error.to_string()))?;
        let cut = state
            .authority_commits()
            .realm_stream_subscription_cut(&realm, account, &state.service_core_id())
            .await
            .map_err(|error| unavailable(error.to_string()))?;
        match cut.listing {
            coland_storage::AccountRealmStreamList::Listed(rows) => {
                let history_digest = cut
                    .history_digest
                    .ok_or_else(|| unavailable("history policy binding is missing"))?;
                result.extend(rows.into_iter().map(|row| AuthorizedStream {
                    row,
                    history_digest: history_digest.clone(),
                }));
            }
            coland_storage::AccountRealmStreamList::NotVisible => return Err(denied()),
            coland_storage::AccountRealmStreamList::Unproved(reason) => {
                return Err(unavailable(reason));
            }
        }
    }
    result.sort_by(|a, b| a.stream_ref.cmp(&b.stream_ref));
    Ok(result)
}

fn initial_progress(rows: &[AuthorizedStream]) -> Result<Vec<StreamProgress>, AppError> {
    rows.iter()
        .map(|row| {
            Ok(StreamProgress {
                stream_ref: row.stream_ref.clone(),
                head: CommitStreamHead {
                    stream_ref: row.stream_ref.clone(),
                    commit_id: row.head_commit_ref.clone(),
                    stream_position: row
                        .next_position
                        .checked_sub(1)
                        .ok_or_else(|| unavailable("stream head has no position"))?,
                },
                readable_floor: row.readable_floor.clone(),
                history_digest: row.history_digest.clone(),
            })
        })
        .collect()
}

/// A history policy change cannot silently reinterpret an old continuation.
fn validate_progress(
    progress: &[StreamProgress],
    rows: &[AuthorizedStream],
) -> Result<(), AppError> {
    if progress.len() != rows.len() {
        return Err(crate::app_error!(
            StreamResyncRequired,
            "readable stream set changed"
        ));
    }
    for (saved, row) in progress.iter().zip(rows) {
        if saved.stream_ref != row.stream_ref
            || saved.head.stream_ref != row.stream_ref
            || saved.readable_floor != row.readable_floor
            || saved.history_digest != row.history_digest
        {
            return Err(crate::app_error!(
                StreamResyncRequired,
                "stream history binding changed"
            ));
        }
        if saved.head.stream_position >= row.next_position
            || (saved.head.stream_position + 1 == row.next_position
                && saved.head.commit_id != row.head_commit_ref)
        {
            return Err(crate::app_error!(
                StreamResyncRequired,
                "stream continuation is no longer an accepted ancestor"
            ));
        }
    }
    Ok(())
}

async fn cursor(
    state: &AppState,
    session: &SessionIdentityState,
    digest: &str,
    progress: &[StreamProgress],
) -> Result<String, AppError> {
    super::cursor::committed_stream_cursor(
        state,
        session,
        digest,
        serde_json::to_value(progress).map_err(|error| unavailable(error.to_string()))?,
    )
    .await
    .map_err(super::events_query::events_query_cursor_error)
}

fn control(kind: Kind, cursor: Option<String>) -> Frame {
    Frame {
        kind,
        realm_id: None,
        cursor,
        payload: None,
        reconnect_after_ms: None,
    }
}

pub(super) async fn subscribe(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot
        .get_typed::<AppState>()
        .expect("state injected")
        .clone();
    let selected = match selection(req.uri().query().unwrap_or_default()) {
        Ok(value) => value,
        Err(error) => {
            render(res, error);
            return;
        }
    };
    let Some(session) =
        super::subscribe::account_subscribe_session_or_render(&state, req, res).await
    else {
        return;
    };
    let grant = super::subscribe::stream_grant(req);
    response(state, session, grant, selected, res).await;
}

pub(super) async fn websocket_response(
    state: AppState,
    session: SessionIdentityState,
    grant: String,
    parameters: arkret_models_collaboration::sync_frames::websocket::WebSocketEventsOpenParameters,
    res: &mut Response,
) {
    if let Err(error) = parameters.validate() {
        render(res, invalid(error.to_string()));
        return;
    }
    let mut realms = parameters
        .realm_ids
        .unwrap_or_default()
        .into_iter()
        .map(|r| r.to_string())
        .collect::<Vec<_>>();
    realms.sort();
    let selected = Selection {
        realms,
        actors: parameters
            .actor_ids
            .unwrap_or_default()
            .into_iter()
            .map(|a| a.to_string())
            .collect(),
        after: parameters.after,
        catchup: parameters.catchup.unwrap_or(false),
    };
    if selected.catchup && selected.after.is_none() {
        render(res, invalid("catchup requires after"));
        return;
    }
    response(state, session, Some(grant), selected, res).await;
}

async fn response(
    state: AppState,
    session: SessionIdentityState,
    grant: Option<String>,
    selected: Selection,
    res: &mut Response,
) {
    if let Err(error) = crate::routing::events::require_agent_session_scope(
        &session,
        arkret_wire::ServiceOperationId::SELF_COMMITTED_EVENT_STREAM_SUBSCRIBE_V1,
    ) {
        render(res, error);
        return;
    }
    // Register before freezing any heads. Broadcast is a hint; every wake and
    // timeout reads the durable current before emitting a page.
    let mut rx = state.subscribe_event_notifications();
    let rows = match streams(&state, &session, &selected).await {
        Ok(rows) => rows,
        Err(error) => {
            render(res, error);
            return;
        }
    };
    let digest =
        super::events_query::events_subscribe_filter_digest(&selected.realms, &selected.actors);
    let mut progress = if let Some(token) = selected.after.as_deref() {
        match super::cursor::parse_committed_stream_cursor(&state, &session, &digest, token)
            .await
            .map_err(super::events_query::events_query_cursor_error)
            .and_then(|value| {
                serde_json::from_value::<Vec<StreamProgress>>(value).map_err(|_| {
                    crate::app_error!(
                        StreamResyncRequired,
                        "subscription continuation requires a new authorized cut"
                    )
                })
            }) {
            Ok(progress) => progress,
            Err(error) => {
                render(res, error);
                return;
            }
        }
    } else {
        match initial_progress(&rows) {
            Ok(progress) => progress,
            Err(error) => {
                render(res, error);
                return;
            }
        }
    };
    if let Err(error) = validate_progress(&progress, &rows) {
        render(res, error);
        return;
    }
    let initial_cursor = match cursor(&state, &session, &digest, &progress).await {
        Ok(token) => token,
        Err(error) => {
            render(res, error);
            return;
        }
    };
    let body = async_stream::stream! {
        let mut token = initial_cursor;
        let mut current_rows = rows;
        let mut bytes = 0usize;
        let deadline = tokio::time::Instant::now() + WAIT;
        let mut caught_up = false;
        loop {
            if !super::subscribe::stream_session_current(&state,&session,grant.as_deref()).await {
                yield Ok::<Bytes,std::io::Error>(super::events_query::ndjson_line(&control(Kind::Unauthorized,None)));
                break;
            }
            if validate_progress(&progress,&current_rows).is_err() {
                yield Ok(super::events_query::ndjson_line(&control(Kind::ResyncRequired,None)));
                break;
            }
            let actor = crate::routing::identity::session_actor::session_actor_from_credential(&state,&session).expect("validated session");
            let Some(account) = actor.as_account_id() else { break; };
            let mut failed = false;
            let mut more = false;
            for index in 0..progress.len() {
                if progress[index].head.stream_position + 1 >= current_rows[index].next_position { continue; }
                let request = StreamScanRequestBody { realm_id:progress[index].stream_ref.realm_id().clone(),
                    stream_ref:progress[index].stream_ref.clone(),direction:StreamScanDirection::After(Some(progress[index].head.stream_position)),limit:PAGE_ITEMS };
                let page = match state.authority().scan_stream_for_account(account,request.clone()).await {
                    Ok(coland_storage::AccountStreamScan::Page(page)) if page.validate_for_request(&request).is_ok()
                        && page.readable_floor == progress[index].readable_floor => page,
                    Ok(coland_storage::AccountStreamScan::NotAuthorized) => {
                        yield Ok(super::events_query::ndjson_line(&control(Kind::Unauthorized,None))); failed=true; break;
                    }
                    _ => { yield Ok(super::events_query::ndjson_line(&control(Kind::ResyncRequired,None))); failed=true; break; }
                };
                if page.committed_events.is_empty() {
                    yield Ok(super::events_query::ndjson_line(&control(Kind::ResyncRequired,None)));
                    failed=true; break;
                }
                for row in page.committed_events {
                    if !super::subscribe::stream_session_current(&state,&session,grant.as_deref()).await {
                        yield Ok(super::events_query::ndjson_line(&control(Kind::Unauthorized,None))); failed=true; break;
                    }
                    match streams(&state,&session,&selected).await {
                        Ok(rows) if validate_progress(&progress,&rows).is_ok() => {},
                        Err(error) if error.wire_code()=="capability_denied" => {
                            yield Ok(super::events_query::ndjson_line(&control(Kind::Unauthorized,None))); failed=true; break;
                        }
                        _ => {
                            yield Ok(super::events_query::ndjson_line(&control(Kind::ResyncRequired,None))); failed=true; break;
                        }
                    }
                    let commit = row.commit();
                    if commit.stream_position != progress[index].head.stream_position + 1
                        || commit.previous_commit_ref.as_ref() != Some(&progress[index].head.commit_id) {
                        yield Ok(super::events_query::ndjson_line(&control(Kind::ResyncRequired,None))); failed=true; break;
                    }
                    let mut next = progress.clone();
                    next[index].head = CommitStreamHead { stream_ref:commit.stream_ref.clone(),commit_id:commit.commit_id.clone(),stream_position:commit.stream_position };
                    let next_token = match cursor(&state,&session,&digest,&next).await {
                        Ok(token) => token, Err(_) => {
                            yield Ok(super::events_query::ndjson_line(&Frame { kind:Kind::Dropped,
                                realm_id:Some(progress[index].stream_ref.realm_id().clone()),cursor:Some(token.clone()),payload:None,
                                reconnect_after_ms:Some(1) }));
                            failed=true; break;
                        }
                    };
                    let visible = selected.actors.is_empty() || match &row {
                        arkret_wire::CommittedEventView::Full(full) => selected.actors.contains(&full.event.actor_id.to_string()),
                        _ => false,
                    };
                    let frame = if visible { Frame { kind:Kind::CommittedEvent,realm_id:Some(commit.realm_id.clone()),cursor:Some(next_token.clone()),payload:Some(Payload::CommittedEvent(Box::new(row))),reconnect_after_ms:None } }
                        else { control(Kind::Checkpoint,Some(next_token.clone())) };
                    let line = super::events_query::ndjson_line(&frame);
                    if bytes + line.len() > RESPONSE_BYTES {
                        // The last delivered cursor remains authoritative; no
                        // undelivered row is covered by this rollover.
                        yield Ok(super::events_query::ndjson_line(&Frame { kind:Kind::Dropped,
                            realm_id:Some(progress[index].stream_ref.realm_id().clone()),cursor:Some(token.clone()),payload:None,
                            reconnect_after_ms:Some(1) }));
                        failed=true; break;
                    }
                    let delivery = if let Some(Payload::CommittedEvent(row)) = &frame.payload {
                        let input = coland_storage::AccountContentDeliveryInput::committed(std::slice::from_ref(row.as_ref()));
                        match super::content_delivery_guard(&state, &session, &input).await {
                            Ok(guard) => guard,
                            Err(_) => {
                                yield Ok(super::events_query::ndjson_line(&control(Kind::Unauthorized,None)));
                                failed=true; break;
                            }
                        }
                    } else { None };
                    if delivery.as_ref().is_some_and(|guard| !guard.permits_handoff()) {
                        yield Ok(super::events_query::ndjson_line(&control(Kind::Unauthorized,None)));
                        failed=true; break;
                    }
                    bytes += line.len(); progress=next; token=next_token;
                    yield Ok(line);
                    if let Some(guard) = delivery && guard.finish().await.is_err() { failed=true; break; }
                }
                if failed { break; }
                more |= progress[index].head.stream_position + 1 < current_rows[index].next_position;
            }
            if failed { break; }
            if more { continue; }
            if !caught_up {
                yield Ok(super::events_query::ndjson_line(&control(Kind::Checkpoint,Some(token.clone()))));
                if selected.catchup { yield Ok(super::events_query::ndjson_line(&control(Kind::CatchupComplete,Some(token.clone())))); }
                caught_up=true;
            }
            // A resumed response with data rolls over immediately; an idle
            // response waits, avoiding empty-frame reconnect loops.
            if bytes > 0 { break; }
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_millis((session.expires_at-Utc::now()).num_milliseconds().max(0) as u64)) => {
                    yield Ok(super::events_query::ndjson_line(&control(Kind::Unauthorized,None)));
                    break;
                }
                _ = tokio::time::sleep_until(deadline) => {
                    if !super::subscribe::stream_session_current(&state,&session,grant.as_deref()).await {
                        yield Ok(super::events_query::ndjson_line(&control(Kind::Unauthorized,None))); break;
                    }
                    match streams(&state,&session,&selected).await {
                        Ok(rows) if validate_progress(&progress,&rows).is_ok() => {
                            if rows.iter().zip(&progress).any(|(r,p)| r.next_position > p.head.stream_position+1) { current_rows=rows; continue; }
                            yield Ok(super::events_query::ndjson_line(&control(Kind::Heartbeat,None)));
                        }
                        Err(error) if error.wire_code() == "capability_denied" => { yield Ok(super::events_query::ndjson_line(&control(Kind::Unauthorized,None))); }
                        _ => { yield Ok(super::events_query::ndjson_line(&control(Kind::ResyncRequired,None))); }
                    }
                    break;
                }
                result = rx.recv() => match result {
                    Ok(notification) if !matches!(notification.kind,crate::state::EventNotificationKind::Signal { .. }) => {
                        if !selected.realms.is_empty() && !selected.realms.contains(&notification.realm_id) { continue; }
                        if !super::subscribe::stream_session_current(&state,&session,grant.as_deref()).await {
                            yield Ok(super::events_query::ndjson_line(&control(Kind::Unauthorized,None))); break;
                        }
                        match streams(&state,&session,&selected).await {
                            Ok(rows) => {
                                current_rows=rows;
                                if matches!(notification.kind,crate::state::EventNotificationKind::RealmRefreshHint) {
                                    metrics::counter!("coland_mimi_notify_refresh_consumed_total", "transport" => "committed_events").increment(1);
                                    yield Ok(super::events_query::ndjson_line(&control(Kind::Checkpoint,Some(token.clone()))));
                                }
                            },
                            Err(_) => { yield Ok(super::events_query::ndjson_line(&control(Kind::Unauthorized,None))); break; }
                        }
                    }
                    Ok(_) => continue,
                    Err(RecvError::Lagged(_)) => { yield Ok(super::events_query::ndjson_line(&control(Kind::ResyncRequired,None))); break; }
                    Err(RecvError::Closed) => break,
                }
            }
        }
    };
    let _ = res.add_header("content-type", "application/x-ndjson", true);
    let _ = res.add_header("cache-control", "no-store", true);
    res.stream(body.boxed());
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn fixture() -> (
        AppState,
        SessionIdentityState,
        super::super::tests::CommittedRealm,
    ) {
        let state = super::super::tests::test_state();
        let store = state.test_persistence();
        let genesis = coland_test_support::pcr_genesis::PcrGenesisFixture::new(state.service_did());
        let device = genesis.admit_founding_device(store.as_ref()).await.unwrap();
        let account = genesis.history.account.clone();
        state
            .identities()
            .save_account(coland_services::identity::AccountProfileState {
                pk: coland_storage::AccountPk(0),
                principal_id: account.principal_id.clone(),
                account_id: account.clone(),
                localpart: "stream-reader".to_owned(),
                display_name: None,
                biography: None,
                avatar_blob_ref: None,
                created_at: Utc::now(),
            })
            .await
            .unwrap();
        let mut session =
            super::super::tests::roster_session(&state, account.principal_id.as_str());
        session.account_pk = Some(
            state
                .identities()
                .account(&account)
                .await
                .unwrap()
                .unwrap()
                .pk,
        );
        session.endpoint = coland_services::identity::SessionEndpointState::HumanDevice {
            device_id: device.device_id,
        };
        state
            .sessions()
            .create_session(session.clone())
            .await
            .unwrap();
        let realm = super::super::tests::CommittedRealm::bootstrap(
            store.as_ref(),
            &account,
            state.service_verification_method("notary-key").unwrap(),
        )
        .await;
        (state, session, realm)
    }

    // Keep the real database lease and bootstrap material in the fixture task;
    // the test immediately awaits it on the runtime's default worker stack.
    fn fixture_task() -> tokio::task::JoinHandle<(
        AppState,
        SessionIdentityState,
        super::super::tests::CommittedRealm,
    )> {
        tokio::spawn(fixture())
    }

    async fn next(body: &mut salvo::http::ResBody) -> Frame {
        let chunk = tokio::time::timeout(Duration::from_secs(4), body.next())
            .await
            .expect("bounded frame wait")
            .expect("stream frame")
            .expect("body chunk");
        let frame: Frame = serde_json::from_slice(&chunk.into_data().unwrap()).unwrap();
        frame.validate().unwrap();
        frame
    }

    #[tokio::test]
    async fn accepted_stream_baseline_then_tail_returns_formal_commits_and_bound_cursors() {
        let (state, session, mut realm) = fixture_task().await.unwrap();
        let selected = selection(&format!("realm_ids={}", realm.head.event.realm_id)).unwrap();
        let mut baseline = Response::new();
        Box::pin(response(
            state.clone(),
            session.clone(),
            None,
            selected.clone(),
            &mut baseline,
        ))
        .await;
        assert!(
            baseline
                .status_code
                .is_none_or(|status| status.is_success()),
            "baseline refused: {:?}",
            baseline.body
        );
        let checkpoint = next(&mut baseline.take_body()).await;
        assert_eq!(checkpoint.kind, Kind::Checkpoint);
        let token = checkpoint.cursor.unwrap();
        assert_ne!(token, realm.head.commit.commit_id.to_string());
        let peer = coland_test_support::pcr_genesis::PcrGenesisFixture::new(state.service_did());
        Box::pin(peer.admit_into(state.test_persistence().as_ref()))
            .await
            .unwrap();
        Box::pin(realm.member_state(
            state.test_persistence().as_ref(),
            &peer.history.account,
            &peer.history.account,
            "join",
        ))
        .await;
        let mut resumed = selected.clone();
        resumed.after = Some(token.clone());
        resumed.catchup = true;
        let mut tail = Response::new();
        Box::pin(response(
            state.clone(),
            session.clone(),
            None,
            resumed,
            &mut tail,
        ))
        .await;
        let mut body = tail.take_body();
        let event = next(&mut body).await;
        assert_eq!(event.kind, Kind::CommittedEvent);
        assert_eq!(
            event.committed_event().unwrap().commit(),
            &realm.head.commit
        );
        assert_ne!(event.cursor.as_deref(), Some(token.as_str()));
        assert_eq!(next(&mut body).await.kind, Kind::Checkpoint);
        assert_eq!(next(&mut body).await.kind, Kind::CatchupComplete);
        assert!(body.next().await.is_none());

        let digest = super::super::events_query::events_subscribe_filter_digest(
            &selected.realms,
            &selected.actors,
        );
        let mut other_device = session.clone();
        other_device.endpoint = coland_services::identity::SessionEndpointState::HumanDevice {
            device_id: "other-device".to_owned(),
        };
        assert!(
            super::super::cursor::parse_committed_stream_cursor(
                &state,
                &other_device,
                &digest,
                &token
            )
            .await
            .is_err()
        );
        assert!(
            super::super::cursor::parse_committed_stream_cursor(
                &state,
                &session,
                "different-selector",
                &token
            )
            .await
            .is_err()
        );
    }

    #[tokio::test]
    async fn established_stream_ends_at_original_session_expiry() {
        let (state, mut session, realm) = fixture_task().await.unwrap();
        session.expires_at = arkret_canonical::normalize_timestamp_canonical(
            Utc::now() + chrono::Duration::seconds(2),
        );
        state
            .sessions()
            .create_session(session.clone())
            .await
            .unwrap();
        let selected = selection(&format!("realm_ids={}", realm.head.event.realm_id)).unwrap();
        let mut result = Response::new();
        response(state, session, None, selected, &mut result).await;
        assert!(
            result.status_code.is_none_or(|status| status.is_success()),
            "stream refused: {:?}",
            result.body
        );
        let mut body = result.take_body();
        assert_eq!(next(&mut body).await.kind, Kind::Checkpoint);
        let ended = next(&mut body).await;
        assert_eq!(ended.kind, Kind::Unauthorized);
        assert!(ended.cursor.is_none());
        assert!(body.next().await.is_none());
    }
    #[test]
    fn subscribe_parameters_are_closed_and_selector_bound() {
        let realm = "ak:realm:ATdMSXE70ijF1u9M9PvT4WFuWRgKpqVf-tiHDAD-_stf";
        assert!(selection(&format!("realm_ids={realm}")).is_ok());
        for query in [
            format!("realm_ids={realm}&realm_ids={realm}"),
            format!("realm_ids={realm}&catchup=true"),
            format!("realm_ids={realm}&catchup=yes"),
            format!("realm_ids={realm}&from=old"),
            format!("realm_ids={realm}&after=a&after=b"),
        ] {
            assert!(selection(&query).is_err(), "{query}");
        }
    }

    #[test]
    fn continuation_rejects_history_changes_and_exact_head_forks() {
        let realm =
            arkret_wire::RealmId::new("ak:realm:ATdMSXE70ijF1u9M9PvT4WFuWRgKpqVf-tiHDAD-_stf")
                .unwrap();
        let row = RealmStreamView {
            stream_ref: CommitStreamRef::Realm { realm_id: realm },
            head_commit_ref: arkret_wire::RealmCommitId::from_digest([1; 32]),
            next_position: 5,
            readable_floor: Some(arkret_wire::ReadableFloor {
                oldest_position: 0,
                floor_commit_id: arkret_wire::RealmCommitId::from_digest([2; 32]),
                floor_reason: arkret_wire::ReadableFloorReason::StreamStart,
            }),
        };
        let row = AuthorizedStream {
            row,
            history_digest: "policy-cut-a".to_owned(),
        };
        let progress = initial_progress(std::slice::from_ref(&row)).unwrap();
        validate_progress(&progress, std::slice::from_ref(&row)).unwrap();
        let mut later = row.clone();
        later.next_position = 6;
        later.head_commit_ref = arkret_wire::RealmCommitId::from_digest([3; 32]);
        validate_progress(&progress, &[later]).unwrap();
        let mut changed_policy = row.clone();
        changed_policy.history_digest = "policy-cut-b".to_owned();
        assert!(validate_progress(&progress, &[changed_policy]).is_err());
        let mut changed = row.clone();
        changed.readable_floor.as_mut().unwrap().oldest_position = 1;
        assert!(validate_progress(&progress, &[changed]).is_err());
        let mut fork = row;
        fork.head_commit_ref = arkret_wire::RealmCommitId::from_digest([4; 32]);
        assert!(validate_progress(&progress, &[fork]).is_err());
        assert!(validate_progress(&progress, &[]).is_err());
    }
}
