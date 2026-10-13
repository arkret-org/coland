//! Socket delivery over the canonical authenticated subscription readers.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::Arc;

use arkret_models_collaboration::sync_frames::account_subscribe::{
    AccountSubscribeFrame, AccountSubscribeFrameKind,
};
use arkret_models_collaboration::sync_frames::committed_event_subscribe::{
    CommittedEventSubscribeFrame, CommittedEventSubscribeFrameKind,
};
use arkret_models_collaboration::sync_frames::websocket::*;
use arkret_signatures::websocket_auth::{
    WebSocketAuthVerificationRequest, verify_websocket_auth_proof, websocket_holder_thumbprint,
};
use arkret_wire::websocket_binding::{
    WEBSOCKET_SUBPROTOCOL, WebSocketChallengeRecord, WebSocketCloseCode, WebSocketOperationId,
    canonical_http_origin,
};
use arkret_wire::{ErrorCode, SignalStreamFrame, WebSocketTransportError};
use futures_util::{SinkExt, StreamExt};
use salvo::websocket::{Message, WebSocket, WebSocketUpgrade};
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore, mpsc, watch};

use super::*;

#[cfg(feature = "conformance-harness")]
mod cursor_emission_probe;

pub(crate) const MAX_FRAME: u32 = 262_144;
pub(crate) const MAX_CHANNELS: u32 = 16;
const QUEUE_FRAMES: u32 = 8;
const HEARTBEAT_MS: u32 = 15_000;
const MAX_USED_CHANNEL_IDS: usize = 4096;

fn limits() -> WebSocketConnectionLimits {
    WebSocketConnectionLimits {
        max_frame_bytes: MAX_FRAME,
        max_channels: MAX_CHANNELS,
        max_connection_pending_bytes: u64::from(MAX_FRAME)
            * u64::from(QUEUE_FRAMES)
            * u64::from(MAX_CHANNELS),
        max_channel_pending_bytes: u64::from(MAX_FRAME) * u64::from(QUEUE_FRAMES),
        max_connection_pending_frames: QUEUE_FRAMES * MAX_CHANNELS,
        max_channel_pending_frames: QUEUE_FRAMES,
        heartbeat_interval_ms: HEARTBEAT_MS,
    }
}

#[derive(Clone)]
struct Credential {
    session: SessionIdentityState,
    grant: Arc<zeroize::Zeroizing<String>>,
}

fn opaque() -> String {
    arkret_canonical::base64url_encode(rand::random::<[u8; 32]>())
}

async fn prepare_challenge(
    state: &AppState,
    connection_id: &str,
    origin: &str,
    base_url: &str,
) -> Result<WebSocketChallengeRecord, WebSocketCloseCode> {
    // JWT NumericDate is an integer second. Use its precision for the
    // challenge lower bound so an immediate proof is representable.
    let issued_at = DateTime::<Utc>::from_timestamp(Utc::now().timestamp(), 0)
        .ok_or(WebSocketCloseCode::InternalError)?;
    let record = WebSocketChallengeRecord {
        connection_id: connection_id.to_owned(),
        nonce: opaque(),
        canonical_origin: arkret_wire::WebOrigin::new(origin)
            .map_err(|_| WebSocketCloseCode::PolicyViolation)?,
        canonical_base_url: base_url.to_owned(),
        issued_at,
        expires_at: issued_at + chrono::Duration::seconds(5),
        consumed: false,
    };
    record
        .validate()
        .map_err(|_| WebSocketCloseCode::InternalError)?;
    state
        .sync()
        .websocket_auth()
        .prepare_challenge(&coland_services::sync::WebsocketChallengeState {
            connection_id: record.connection_id.clone(),
            nonce: record.nonce.clone(),
            canonical_origin: record.canonical_origin.clone(),
            canonical_base_url: record.canonical_base_url.clone(),
            issued_at: record.issued_at,
            expires_at: record.expires_at,
            consumed: false,
            retain_until: record.expires_at + chrono::Duration::seconds(300),
        })
        .await
        .map_err(|_| WebSocketCloseCode::InternalError)?;
    Ok(record)
}

async fn authenticate(
    state: &AppState,
    origin: &str,
    challenge: &WebSocketChallengeRecord,
    frame: &WebSocketClientFrame,
) -> Result<Credential, WebSocketCloseCode> {
    let WebSocketClientFrame::Authenticate {
        connection_id,
        session_grant,
        dpop_proof,
    } = frame
    else {
        return Err(WebSocketCloseCode::ProtocolError);
    };
    if connection_id != &challenge.connection_id || Utc::now() > challenge.expires_at {
        return Err(WebSocketCloseCode::PolicyViolation);
    }
    let protected = dpop_proof
        .split('.')
        .next()
        .and_then(|part| arkret_canonical::base64url_decode(part).ok())
        .and_then(|bytes| {
            serde_json::from_slice::<arkret_wire::websocket_binding::WebSocketDpopProtectedHeader>(
                &bytes,
            )
            .ok()
        })
        .ok_or(WebSocketCloseCode::PolicyViolation)?;
    let claimed_jkt = websocket_holder_thumbprint(&protected.jwk)
        .map_err(|_| WebSocketCloseCode::PolicyViolation)?;
    // Verify the signature and socket context before any grant or durable
    // challenge lookup. The second verification pins the introspected holder.
    verify_websocket_auth_proof(&WebSocketAuthVerificationRequest {
        compact_jws: dpop_proof,
        connection_id,
        session_grant,
        socket_origin: origin,
        challenge,
        grant_cnf_jkt: &claimed_jkt,
        replay_ledger_hit: false,
        now: Utc::now(),
    })
    .map_err(|_| WebSocketCloseCode::PolicyViolation)?;
    let stored = state
        .sync()
        .websocket_auth()
        .challenge(connection_id, &challenge.nonce)
        .await
        .map_err(|_| WebSocketCloseCode::InternalError)?
        .ok_or(WebSocketCloseCode::PolicyViolation)?;
    if stored.consumed
        || stored.canonical_origin != challenge.canonical_origin
        || stored.canonical_base_url != challenge.canonical_base_url
    {
        return Err(WebSocketCloseCode::PolicyViolation);
    }
    let session = crate::routing::identity::auth::websocket_session(state, session_grant)
        .await
        .map_err(|_| WebSocketCloseCode::PolicyViolation)?;
    let jkt = session
        .session_grant
        .as_ref()
        .map(|grant| grant.cnf_jkt.as_str())
        .ok_or(WebSocketCloseCode::PolicyViolation)?;
    let verified = verify_websocket_auth_proof(&WebSocketAuthVerificationRequest {
        compact_jws: dpop_proof,
        connection_id,
        session_grant,
        socket_origin: origin,
        challenge,
        grant_cnf_jkt: jkt,
        replay_ledger_hit: false,
        now: Utc::now(),
    })
    .map_err(|_| WebSocketCloseCode::PolicyViolation)?;
    let key = verified.replay_ledger_key;
    let consumed = state
        .sync()
        .websocket_auth()
        .consume_challenge(
            connection_id,
            &challenge.nonce,
            &coland_services::sync::WebsocketReplayState {
                cnf_jkt: key.cnf_jkt,
                jti: key.jti,
                proof_context: key.context,
                consumed_at: Utc::now(),
                retain_until: Utc::now() + chrono::Duration::seconds(300),
            },
        )
        .await
        .map_err(|_| WebSocketCloseCode::InternalError)?;
    if !consumed {
        return Err(WebSocketCloseCode::PolicyViolation);
    }
    Ok(Credential {
        session,
        grant: Arc::new(zeroize::Zeroizing::new(session_grant.clone())),
    })
}

fn same_holder(old: &Credential, new: &Credential) -> bool {
    old.session.actor == new.session.actor
        && old.session.endpoint == new.session.endpoint
        && old.session.account_pk == new.session.account_pk
        && old.session.audience == new.session.audience
        && old
            .session
            .session_grant
            .as_ref()
            .map(|g| (&g.account_id, &g.holder_binding))
            == new
                .session
                .session_grant
                .as_ref()
                .map(|g| (&g.account_id, &g.holder_binding))
}

struct TrafficBudget {
    started: tokio::time::Instant,
    frames: usize,
    bytes: usize,
    max_frames: usize,
    max_bytes: usize,
}
impl TrafficBudget {
    fn new(max_frames: usize, max_bytes: usize) -> Self {
        Self {
            started: tokio::time::Instant::now(),
            frames: 0,
            bytes: 0,
            max_frames,
            max_bytes,
        }
    }
    fn take(&mut self, bytes: usize) -> bool {
        if self.started.elapsed() >= Duration::from_secs(1) {
            self.started = tokio::time::Instant::now();
            self.frames = 0;
            self.bytes = 0;
        }
        if self.frames >= self.max_frames || self.bytes.saturating_add(bytes) > self.max_bytes {
            return false;
        }
        self.frames += 1;
        self.bytes += bytes;
        true
    }
    fn add_bytes(&mut self, bytes: usize) -> bool {
        if self.bytes.saturating_add(bytes) > self.max_bytes {
            return false;
        }
        self.bytes += bytes;
        true
    }
    async fn wait(&mut self, bytes: usize) -> Result<(), WebSocketCloseCode> {
        if bytes > self.max_bytes {
            return Err(WebSocketCloseCode::MessageTooBig);
        }
        while !self.take(bytes) {
            tokio::time::sleep_until(self.started + Duration::from_secs(1)).await;
        }
        Ok(())
    }
}

async fn send(
    socket: &mut WebSocket,
    budget: &mut TrafficBudget,
    frame: &WebSocketServerFrame,
) -> Result<(), WebSocketCloseCode> {
    let bytes = arkret_canonical::canonical_json_bytes(frame)
        .map_err(|_| WebSocketCloseCode::InternalError)?;
    budget.wait(bytes.len()).await?;
    send_unmetered(socket, frame).await
}

async fn send_unmetered(
    socket: &mut WebSocket,
    frame: &WebSocketServerFrame,
) -> Result<(), WebSocketCloseCode> {
    frame
        .validate()
        .map_err(|_| WebSocketCloseCode::InternalError)?;
    let bytes = arkret_canonical::canonical_json_bytes(frame)
        .map_err(|_| WebSocketCloseCode::InternalError)?;
    if bytes.len() > MAX_FRAME as usize {
        return Err(WebSocketCloseCode::MessageTooBig);
    }
    tokio::time::timeout(
        Duration::from_secs(5),
        socket.send(Message::text(
            String::from_utf8(bytes).map_err(|_| WebSocketCloseCode::InternalError)?,
        )),
    )
    .await
    .map_err(|_| WebSocketCloseCode::InternalError)?
    .map_err(|_| WebSocketCloseCode::InternalError)
}

fn channel_error(id: &str, code: ErrorCode) -> WebSocketServerFrame {
    WebSocketServerFrame::ChannelError {
        frame_scope: WebSocketChannelScope::Channel,
        channel_id: id.to_owned(),
        error: WebSocketTransportError::new(
            code,
            "channel cannot continue under its requested authorization",
        ),
    }
}

fn account_frame(id: &str, frame: AccountSubscribeFrame) -> WebSocketServerFrame {
    if frame.kind == AccountSubscribeFrameKind::Delta {
        WebSocketServerFrame::Data {
            channel_id: id.to_owned(),
            payload: WebSocketDataPayload::Account(Box::new(frame)),
        }
    } else {
        WebSocketServerFrame::ChannelControl {
            frame_scope: WebSocketChannelScope::Channel,
            channel_id: id.to_owned(),
            payload: WebSocketChannelControlPayload::Account(Box::new(frame)),
        }
    }
}
fn events_frame(id: &str, frame: CommittedEventSubscribeFrame) -> WebSocketServerFrame {
    if frame.kind == CommittedEventSubscribeFrameKind::CommittedEvent {
        WebSocketServerFrame::Data {
            channel_id: id.to_owned(),
            payload: WebSocketDataPayload::Events(Box::new(frame)),
        }
    } else {
        WebSocketServerFrame::ChannelControl {
            frame_scope: WebSocketChannelScope::Channel,
            channel_id: id.to_owned(),
            payload: WebSocketChannelControlPayload::Events(Box::new(frame)),
        }
    }
}
fn signal_frame(id: &str, frame: SignalStreamFrame) -> WebSocketServerFrame {
    if matches!(frame, SignalStreamFrame::Signal { .. }) {
        WebSocketServerFrame::Data {
            channel_id: id.to_owned(),
            payload: WebSocketDataPayload::Signal(Box::new(frame)),
        }
    } else {
        WebSocketServerFrame::ChannelControl {
            frame_scope: WebSocketChannelScope::Channel,
            channel_id: id.to_owned(),
            payload: WebSocketChannelControlPayload::Signal(Box::new(frame)),
        }
    }
}

fn terminal(frame: &WebSocketServerFrame) -> bool {
    matches!(frame, WebSocketServerFrame::ChannelError { .. })
        || matches!(frame,WebSocketServerFrame::ChannelControl {payload,..} if payload.is_terminal())
}

/// Revalidate the exact read inputs without building a snapshot or issuing
/// another handle. Queue progress is not authority to replace these inputs.
async fn current_read_inputs(
    state: &AppState,
    credential: &Credential,
    parameters: &WebSocketOpenParameters,
) -> Result<(), ErrorCode> {
    let result = match parameters {
        WebSocketOpenParameters::Account(p) => {
            let body = SyncRequestBody {
                after: p.after.clone(),
                catchup: p.catchup,
                filter: p.filter.clone(),
                realm_list: p.realm_list.clone(),
                replace_filter: p.replace_filter,
            };
            super::subscribe::account_read_inputs_current(
                state,
                &credential.session,
                &body,
                p.wait_for.as_deref(),
            )
            .await
        }
        WebSocketOpenParameters::Events(p) => {
            if let Some(after) = p.after.as_deref() {
                let realms = p
                    .realm_ids
                    .iter()
                    .flatten()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>();
                let actors = p
                    .actor_ids
                    .iter()
                    .flatten()
                    .map(ToString::to_string)
                    .collect::<BTreeSet<_>>();
                let digest = super::events_query::events_subscribe_filter_digest(&realms, &actors);
                super::cursor::parse_committed_stream_cursor(
                    state,
                    &credential.session,
                    &digest,
                    after,
                )
                .await
                .map(|_| ())
            } else {
                Ok(())
            }
        }
        WebSocketOpenParameters::Signal(_) => Ok(()),
    };
    result.map_err(|error| {
        ErrorCode::from_wire(super::cursor::cursor_revoke_error(error).wire_code())
            .unwrap_or(ErrorCode::TemporarilyUnavailable)
    })
}

/// Queuing is not delivery authorization. A revoke after enqueue must still
/// suppress the payload at the physical send boundary.
async fn current_delivery(
    state: &AppState,
    credential: &Credential,
    frame: &mut WebSocketServerFrame,
    parameters: &WebSocketOpenParameters,
) -> Result<Option<Box<dyn coland_storage::AccountContentDeliveryGuard>>, ErrorCode> {
    if !super::subscribe::stream_session_current(
        state,
        &credential.session,
        Some(credential.grant.as_str()),
    )
    .await
    {
        return Err(ErrorCode::Unauthenticated);
    }
    let actor = crate::routing::identity::session_actor::validated_session_actor(
        state,
        &credential.session,
    )
    .await
    .map_err(|_| ErrorCode::Unauthenticated)?;
    let operation = match frame {
        WebSocketServerFrame::Data {
            payload: WebSocketDataPayload::Account(_),
            ..
        } => Some(WebSocketOperationId::AccountStreamSubscribe),
        WebSocketServerFrame::Data {
            payload: WebSocketDataPayload::Events(_),
            ..
        } => Some(WebSocketOperationId::CommittedEventStreamSubscribe),
        WebSocketServerFrame::Data {
            payload: WebSocketDataPayload::Signal(_),
            ..
        } => Some(WebSocketOperationId::SignalStreamSubscribe),
        _ => None,
    };
    if operation.is_some_and(|op| {
        crate::routing::events::require_agent_session_scope(&credential.session, op.as_str())
            .is_err()
    }) {
        return Err(ErrorCode::CapabilityDenied);
    }
    match frame {
        WebSocketServerFrame::Data {
            payload: WebSocketDataPayload::Signal(signal),
            ..
        } => {
            let SignalStreamFrame::Signal { envelope, .. } = signal.as_ref() else {
                return Err(ErrorCode::SchemaViolation);
            };
            **signal =
                super::signal::admitted_signal_frame(state, &credential.session, envelope.clone())
                    .await
                    .map_err(|_| ErrorCode::CapabilityDenied)?;
        }
        WebSocketServerFrame::Data {
            payload: WebSocketDataPayload::Events(events),
            ..
        } => {
            let account = actor.as_account_id().ok_or(ErrorCode::CapabilityDenied)?;
            let commit = events
                .committed_event()
                .ok_or(ErrorCode::SchemaViolation)?
                .commit();
            let rows = state
                .authority_commits()
                .list_realm_streams_for_account(&commit.realm_id, account, &state.service_core_id())
                .await
                .map_err(|_| ErrorCode::TemporarilyUnavailable)?;
            let coland_storage::AccountRealmStreamList::Listed(rows) = rows else {
                return Err(ErrorCode::CapabilityDenied);
            };
            let Some(row) = rows.iter().find(|r| r.stream_ref == commit.stream_ref) else {
                return Err(ErrorCode::CapabilityDenied);
            };
            if row
                .readable_floor
                .as_ref()
                .is_some_and(|floor| commit.stream_position < floor.oldest_position)
            {
                return Err(ErrorCode::StreamResyncRequired);
            }
        }
        WebSocketServerFrame::Data {
            payload: WebSocketDataPayload::Account(account_frame),
            ..
        } => {
            let account = actor.as_account_id().ok_or(ErrorCode::CapabilityDenied)?;
            if let Some(realms) = &account_frame.realms {
                for (id, detail) in &realms.entries {
                    if detail.unavailable.is_some() {
                        continue;
                    }
                    let realm =
                        arkret_wire::RealmId::new(id).map_err(|_| ErrorCode::SchemaViolation)?;
                    let rows = state
                        .authority_commits()
                        .list_realm_streams_for_account(&realm, account, &state.service_core_id())
                        .await
                        .map_err(|_| ErrorCode::TemporarilyUnavailable)?;
                    let coland_storage::AccountRealmStreamList::Listed(rows) = rows else {
                        return Err(ErrorCode::CapabilityDenied);
                    };
                    for window in detail.streams.as_deref().unwrap_or_default() {
                        if !rows.iter().any(|r| r.stream_ref == window.stream_ref) {
                            return Err(ErrorCode::StreamResyncRequired);
                        }
                    }
                    for view in detail.committed_events.as_deref().unwrap_or_default() {
                        let commit = view.commit();
                        if !rows.iter().any(|row| {
                            row.stream_ref == commit.stream_ref
                                && row.readable_floor.as_ref().is_none_or(|floor| {
                                    commit.stream_position >= floor.oldest_position
                                })
                        }) {
                            return Err(ErrorCode::StreamResyncRequired);
                        }
                    }
                }
            }
        }
        _ => {}
    }
    current_read_inputs(state, credential, parameters).await?;
    let input = match frame {
        WebSocketServerFrame::Data {
            payload: WebSocketDataPayload::Events(events),
            ..
        } => {
            let row = events.committed_event().ok_or(ErrorCode::SchemaViolation)?;
            Some(coland_storage::AccountContentDeliveryInput::committed(
                std::slice::from_ref(row),
            ))
        }
        WebSocketServerFrame::Data {
            payload: WebSocketDataPayload::Account(frame),
            ..
        } => Some(
            coland_storage::AccountContentDeliveryInput::account_frame(frame)
                .map_err(|_| ErrorCode::SchemaViolation)?,
        ),
        _ => None,
    };
    if let Some(input) = input {
        // The governing cut can require a large provenance future. Poll it in
        // its own task instead of on top of the socket pump's async frames.
        // Cancellation must still drop an in-flight acquisition, and the
        // returned original guard remains held by the physical send below.
        struct CancelDeliveryAcquisition(tokio::task::AbortHandle);
        impl Drop for CancelDeliveryAcquisition {
            fn drop(&mut self) {
                self.0.abort();
            }
        }
        let state = state.clone();
        let session = credential.session.clone();
        let task = tokio::spawn(Box::pin(async move {
            Box::pin(super::content_delivery_guard(&state, &session, &input))
                .await
                .map_err(|_| ErrorCode::CapabilityDenied)
        }));
        let _cancel = CancelDeliveryAcquisition(task.abort_handle());
        task.await.map_err(|_| ErrorCode::TemporarilyUnavailable)?
    } else {
        Ok(None)
    }
}

struct Channel {
    operation: WebSocketOperationId,
    queue: mpsc::Receiver<QueuedFrame>,
    pending: Option<QueuedFrame>,
    worker: tokio::task::JoinHandle<()>,
}
struct QueuedFrame {
    frame: WebSocketServerFrame,
    read_inputs: WebSocketOpenParameters,
    _permit: OwnedSemaphorePermit,
}
impl Drop for Channel {
    fn drop(&mut self) {
        self.worker.abort();
    }
}

async fn response_for(
    state: &AppState,
    credential: &Credential,
    parameters: &WebSocketOpenParameters,
) -> Response {
    let mut response = Response::new();
    match parameters {
        WebSocketOpenParameters::Account(p) => {
            let mut depot = Depot::new();
            if let Some(wait_for) = p.wait_for.as_ref() {
                depot.insert_typed(coland_http::openapi_routes::WaitForSyncToken(
                    wait_for.clone(),
                ));
            }
            let request = Request::new();
            let body = SyncRequestBody {
                after: p.after.clone(),
                catchup: p.catchup,
                filter: p.filter.clone(),
                realm_list: p.realm_list.clone(),
                replace_filter: p.replace_filter,
            };
            super::subscribe::account_response(
                &mut depot,
                &request,
                &mut response,
                state.clone(),
                credential.session.clone(),
                body,
                Some(credential.grant.as_str().to_owned()),
            )
            .await;
        }
        WebSocketOpenParameters::Events(p) => {
            super::committed_subscription::websocket_response(
                state.clone(),
                credential.session.clone(),
                credential.grant.as_str().to_owned(),
                p.clone(),
                &mut response,
            )
            .await
        }
        WebSocketOpenParameters::Signal(_) => super::signal::signal_response(
            state.clone(),
            credential.session.clone(),
            Some(credential.grant.as_str().to_owned()),
            &mut response,
            None,
            HEARTBEAT_MS as u64,
        ),
    }
    response
}

fn problem_code(response: &Response) -> ErrorCode {
    if let salvo::http::ResBody::Once(bytes) = &response.body
        && let Ok(problem) = serde_json::from_slice::<arkret_wire::Problem>(bytes)
        && let Some(code) = ErrorCode::from_wire(problem.code())
    {
        return code;
    }
    match response
        .status_code
        .map(|code| code.as_u16())
        .unwrap_or(200)
    {
        401 => ErrorCode::Unauthenticated,
        403 => ErrorCode::CapabilityDenied,
        429 => ErrorCode::RateLimited,
        400 => ErrorCode::ParamInvalid,
        409 => ErrorCode::StreamResyncRequired,
        _ => ErrorCode::TemporarilyUnavailable,
    }
}

fn start_channel(
    state: AppState,
    id: String,
    operation: WebSocketOperationId,
    mut parameters: WebSocketOpenParameters,
    mut credentials: watch::Receiver<Credential>,
    ready: Arc<Notify>,
    failure: mpsc::Sender<(String, ErrorCode)>,
    initial_response: Response,
) -> Channel {
    let (tx, queue) = mpsc::channel(QUEUE_FRAMES as usize);
    let pending = Arc::new(Semaphore::new(QUEUE_FRAMES as usize));
    let worker = tokio::spawn(async move {
        let mut prepared = Some(initial_response);
        loop {
            let credential = credentials.borrow_and_update().clone();
            if !super::subscribe::stream_session_current(
                &state,
                &credential.session,
                Some(credential.grant.as_str()),
            )
            .await
            {
                let _ = failure.send((id.clone(), ErrorCode::Unauthenticated)).await;
                ready.notify_one();
                return;
            }
            if let Err(error) = crate::routing::events::require_agent_session_scope(
                &credential.session,
                operation.as_str(),
            ) {
                let _ = failure
                    .send((
                        id.clone(),
                        arkret_wire::ErrorCode::from_wire(error.wire_code())
                            .unwrap_or(ErrorCode::CapabilityDenied),
                    ))
                    .await;
                ready.notify_one();
                return;
            }
            let read_inputs = parameters.clone();
            let mut response = match prepared.take() {
                Some(response) => response,
                None => response_for(&state, &credential, &parameters).await,
            };
            if response.status_code.is_some_and(|s| !s.is_success()) {
                let _ = failure.send((id.clone(), problem_code(&response))).await;
                ready.notify_one();
                return;
            }
            let mut body = response.take_body();
            loop {
                let permit = match tokio::time::timeout(
                    Duration::from_secs(3),
                    pending.clone().acquire_owned(),
                )
                .await
                {
                    Ok(Ok(permit)) => permit,
                    _ => {
                        let _ = failure.send((id.clone(), ErrorCode::RateLimited)).await;
                        ready.notify_one();
                        return;
                    }
                };
                let chunk = tokio::select! {
                    chunk=body.next()=>chunk,
                    changed=credentials.changed()=>{if changed.is_err(){return;} break;}
                };
                let Some(chunk) = chunk else {
                    break;
                };
                let Ok(chunk) = chunk else {
                    let code = current_read_inputs(&state, &credential, &read_inputs)
                        .await
                        .err()
                        .unwrap_or(ErrorCode::TemporarilyUnavailable);
                    let _ = failure.send((id.clone(), code)).await;
                    ready.notify_one();
                    return;
                };
                let Ok(bytes) = chunk.into_data() else {
                    continue;
                };
                let converted = match &mut parameters {
                    WebSocketOpenParameters::Account(p) => {
                        serde_json::from_slice::<AccountSubscribeFrame>(&bytes).map(|frame| {
                            if let Some(cursor) = frame.cursor.as_ref() {
                                p.after = Some(cursor.clone());
                            }
                            account_frame(&id, frame)
                        })
                    }
                    WebSocketOpenParameters::Events(p) => serde_json::from_slice::<
                        CommittedEventSubscribeFrame,
                    >(&bytes)
                    .map(|frame| {
                        if let Some(cursor) = frame.cursor.as_ref() {
                            p.after = Some(cursor.clone());
                        }
                        events_frame(&id, frame)
                    }),
                    WebSocketOpenParameters::Signal(_) => {
                        serde_json::from_slice::<SignalStreamFrame>(&bytes)
                            .map(|frame| signal_frame(&id, frame))
                    }
                };
                let Ok(frame) = converted else {
                    let _ = failure.send((id.clone(), ErrorCode::InternalError)).await;
                    ready.notify_one();
                    return;
                };
                let ending = terminal(&frame);
                let bounded = frame.validate().is_ok()
                    && arkret_canonical::canonical_json_bytes(&frame)
                        .is_ok_and(|bytes| bytes.len() <= MAX_FRAME as usize);
                let queued = QueuedFrame {
                    frame,
                    read_inputs: read_inputs.clone(),
                    _permit: permit,
                };
                let delivered = if !bounded {
                    false
                } else if operation == WebSocketOperationId::SignalStreamSubscribe {
                    tx.try_send(queued).is_ok()
                } else {
                    matches!(
                        tokio::time::timeout(Duration::from_secs(3), tx.send(queued)).await,
                        Ok(Ok(()))
                    )
                };
                if !delivered {
                    let _ = failure.send((id.clone(), ErrorCode::RateLimited)).await;
                    ready.notify_one();
                    return;
                }
                ready.notify_one();
                if ending {
                    return;
                }
            }
            if let WebSocketOpenParameters::Account(p) = &mut parameters {
                p.catchup = Some(false);
                p.wait_for = None;
                p.replace_filter = None;
            }
            if let WebSocketOpenParameters::Events(p) = &mut parameters {
                p.catchup = Some(false);
            }
        }
    });
    Channel {
        operation,
        queue,
        pending: None,
        worker,
    }
}

/// The application pump is kept unmounted until transport conformance and
/// all three authenticated readers have been verified together.
async fn connection(
    socket: &mut WebSocket,
    state: AppState,
    origin: String,
    base_url: String,
) -> WebSocketCloseCode {
    let id = opaque();
    let result = connection_inner(socket, state.clone(), origin, base_url, id.clone()).await;
    if state
        .sync()
        .websocket_auth()
        .release_connection(&id)
        .await
        .is_err()
    {
        return WebSocketCloseCode::InternalError;
    }
    result
}

fn connection_lease(
    id: &str,
    state: &AppState,
    credential: &Credential,
) -> Result<coland_services::sync::WebsocketConnectionLease, WebSocketCloseCode> {
    let grant = credential
        .session
        .session_grant
        .as_ref()
        .ok_or(WebSocketCloseCode::PolicyViolation)?;
    let digest = |value: serde_json::Value| -> Result<String, WebSocketCloseCode> {
        let bytes = arkret_canonical::canonical_json_bytes(&value)
            .map_err(|_| WebSocketCloseCode::InternalError)?;
        Ok(arkret_canonical::base64url_encode(
            arkret_canonical::sha256_bytes(&bytes),
        ))
    };
    Ok(coland_services::sync::WebsocketConnectionLease {
        connection_id: id.to_owned(),
        session_binding: digest(serde_json::json!([
            state.service_id(),
            credential.session.token_hash
        ]))?,
        device_binding: digest(serde_json::json!([
            state.service_id(),
            credential.session.actor,
            grant.account_id,
            grant.holder_binding
        ]))?,
        expires_at: arkret_canonical::normalize_timestamp_canonical(
            (Utc::now() + chrono::Duration::seconds(30)).min(credential.session.expires_at),
        ),
    })
}

async fn connection_inner(
    socket: &mut WebSocket,
    state: AppState,
    origin: String,
    base_url: String,
    id: String,
) -> WebSocketCloseCode {
    let mut outgoing = TrafficBudget::new(64, 4 * 1024 * 1024);
    let mut incoming_budget = TrafficBudget::new(64, 2 * 1024 * 1024);
    let mut signal_budget = TrafficBudget::new(16, 1024 * 1024);
    let mut lease_renewed = tokio::time::Instant::now();
    let mut challenge = match prepare_challenge(&state, &id, &origin, &base_url).await {
        Ok(c) => Some(c),
        Err(code) => return code,
    };
    let c = challenge.as_ref().unwrap();
    if let Err(code) = send(
        socket,
        &mut outgoing,
        &WebSocketServerFrame::Challenge {
            connection_id: id.clone(),
            nonce: c.nonce.clone(),
            expires_at: c.expires_at,
        },
    )
    .await
    {
        return code;
    }
    let ingress = WebSocketFrameIngress::new(MAX_FRAME, Some(MAX_FRAME));
    let mut credential: Option<Credential> = None;
    let mut credential_updates = None;
    let mut channels = BTreeMap::<String, Channel>::new();
    let mut used = BTreeSet::new();
    let mut schedule = VecDeque::<String>::new();
    let ready = Arc::new(Notify::new());
    let (failures, mut failure_rx) = mpsc::channel::<(String, ErrorCode)>(MAX_CHANNELS as usize);
    let started = tokio::time::Instant::now();
    let mut heartbeat = tokio::time::interval(Duration::from_millis(u64::from(HEARTBEAT_MS)));
    heartbeat.tick().await;
    let mut maintenance = tokio::time::interval(Duration::from_millis(250));
    let mut outstanding_ping: Option<String> = None;
    let mut drain_deadline = None;
    loop {
        tokio::select! {
            _=maintenance.tick()=>{
                if challenge.as_ref().is_some_and(|c|Utc::now()>c.expires_at) {return WebSocketCloseCode::PolicyViolation;}
                if credential.as_ref().is_some_and(|c|Utc::now()>=c.session.expires_at) {return WebSocketCloseCode::PolicyViolation;}
                if let Some(current)=credential.as_ref() {
                    if lease_renewed.elapsed()>=Duration::from_secs(10) {
                        if crate::routing::identity::auth::websocket_session(&state,current.grant.as_str()).await.is_err() {
                            return WebSocketCloseCode::PolicyViolation;
                        }
                        if !super::subscribe::stream_session_current(&state,&current.session,Some(current.grant.as_str())).await {return WebSocketCloseCode::PolicyViolation;}
                        let lease=match connection_lease(&id,&state,current){Ok(lease)=>lease,Err(code)=>return code};
                        match state.sync().websocket_auth().reserve_connection(&lease).await {Ok(true)=>{},_=>return WebSocketCloseCode::InternalError}
                        lease_renewed=tokio::time::Instant::now();
                    }
                    if challenge.is_none() && current.session.expires_at-Utc::now()<=chrono::Duration::seconds(5) {
                        let c=match prepare_challenge(&state,&id,&origin,&base_url).await {Ok(c)=>c,Err(code)=>return code};
                        if let Err(code)=send(socket,&mut outgoing,&WebSocketServerFrame::ReauthRequired {connection_id:id.clone(),nonce:c.nonce.clone(),expires_at:c.expires_at,reason:WebSocketReauthReason::GrantExpiring}).await {return code;}
                        challenge=Some(c);
                    }
                }
                if drain_deadline.is_some_and(|deadline|tokio::time::Instant::now()>=deadline) {
                    return WebSocketCloseCode::GoingAway;
                }
                if drain_deadline.is_none() && started.elapsed().as_secs()>=state.config().websocket_max_lifetime_seconds {
                    let frame=WebSocketServerFrame::ConnectionControl {frame_scope:WebSocketConnectionScope::Connection,payload:WebSocketConnectionDrainPayload {kind:WebSocketDrainMarker::Drain,reconnect_after_ms:250,deadline:Utc::now()+chrono::Duration::seconds(1),reason:None}};
                    if let Err(code)=send(socket,&mut outgoing,&frame).await {return code;}
                    drain_deadline=Some(tokio::time::Instant::now()+Duration::from_secs(1));
                }
                if !channels.is_empty(){ready.notify_one();}
            }
            _=heartbeat.tick(),if credential.is_some()=>{
                if outstanding_ping.is_some(){return WebSocketCloseCode::PolicyViolation;}
                let ping=opaque();
                if let Err(code)=send(socket,&mut outgoing,&WebSocketServerFrame::Ping {ping_id:ping.clone(),sent_at:Utc::now()}).await{return code;}
                outstanding_ping=Some(ping);
            }
            Some((channel_id,code))=failure_rx.recv()=>{
                if !channels.contains_key(&channel_id){continue;}
                channels.remove(&channel_id);schedule.retain(|id|id!=&channel_id);
                if let Err(code)=send(socket,&mut outgoing,&channel_error(&channel_id,code)).await{return code;}
                if let Err(code)=send(socket,&mut outgoing,&WebSocketServerFrame::Closed {channel_id,reason:WebSocketClosedReason::Error}).await{return code;}
            }
            _=ready.notified(),if credential.is_some()=>{
                let count=schedule.len();
                for _ in 0..count {
                    let Some(channel_id)=schedule.pop_front() else{break;};
                    schedule.push_back(channel_id.clone());
                    let Some(channel)=channels.get_mut(&channel_id) else{continue;};
                    let Some(queued)=channel.pending.take().or_else(||channel.queue.try_recv().ok()) else{continue;};
                    let length=match arkret_canonical::canonical_json_bytes(&queued.frame){Ok(bytes)=>bytes.len(),Err(_)=>return WebSocketCloseCode::InternalError};
                    if channel.operation==WebSocketOperationId::SignalStreamSubscribe && !signal_budget.take(length) {
                        channel.pending=Some(queued);continue;
                    }
                    if let Err(code)=outgoing.wait(length).await{return code;}
                    let QueuedFrame {mut frame,read_inputs,_permit}=queued;
                    let current=credential.as_ref().unwrap();
                    #[cfg(feature = "conformance-harness")]
                    if let Err(error)=cursor_emission_probe::pause(&state,&read_inputs,&frame).await {
                        channels.remove(&channel_id);schedule.retain(|id|id!=&channel_id);
                        if let Err(code)=send(socket,&mut outgoing,&channel_error(&channel_id,error)).await{return code;}
                        if let Err(code)=send(socket,&mut outgoing,&WebSocketServerFrame::Closed {channel_id,reason:WebSocketClosedReason::Error}).await{return code;}
                        continue;
                    }
                    let delivery=match current_delivery(&state,current,&mut frame,&read_inputs).await {
                        Ok(guard)=>guard,
                        Err(error)=>{
                            if error==ErrorCode::Unauthenticated{return WebSocketCloseCode::PolicyViolation;}
                            channels.remove(&channel_id);schedule.retain(|id|id!=&channel_id);
                            if let Err(code)=send(socket,&mut outgoing,&channel_error(&channel_id,error)).await{return code;}
                            if let Err(code)=send(socket,&mut outgoing,&WebSocketServerFrame::Closed {channel_id,reason:WebSocketClosedReason::Unauthorized}).await{return code;}
                            ready.notify_one();continue;
                        }
                    };
                    let actual_length=match arkret_canonical::canonical_json_bytes(&frame){Ok(bytes)=>bytes.len(),Err(_)=>return WebSocketCloseCode::InternalError};
                    if actual_length>length && !outgoing.add_bytes(actual_length-length) {
                        if let Some(channel)=channels.get_mut(&channel_id){channel.pending=Some(QueuedFrame {frame,read_inputs,_permit});}
                        continue;
                    }
                    let ending=terminal(&frame);
                    if delivery.as_ref().is_some_and(|guard| !guard.permits_handoff()) {
                        return WebSocketCloseCode::PolicyViolation;
                    }
                    if let Err(code)=send_unmetered(socket,&frame).await{return code;}
                    if let Some(guard) = delivery && guard.finish().await.is_err() {return WebSocketCloseCode::InternalError;}
                    if ending {
                        channels.remove(&channel_id);schedule.retain(|id|id!=&channel_id);
                        if let Err(code)=send(socket,&mut outgoing,&WebSocketServerFrame::Closed {channel_id,reason:WebSocketClosedReason::Completed}).await{return code;}
                    }
                    ready.notify_one();
                    break;
                }
            }
            message=socket.recv()=>{
                let message=match message {
                    Some(Ok(message))=>message,
                    Some(Err(salvo::Error::Other(error)))=>return match error.downcast_ref::<tokio_tungstenite::tungstenite::Error>() {
                        Some(tokio_tungstenite::tungstenite::Error::Capacity(_))=>WebSocketCloseCode::MessageTooBig,
                        Some(tokio_tungstenite::tungstenite::Error::Utf8(_)|tokio_tungstenite::tungstenite::Error::Protocol(_))=>WebSocketCloseCode::ProtocolError,
                        _=>WebSocketCloseCode::Normal,
                    },
                    _=>return WebSocketCloseCode::Normal,
                };
                if message.is_close(){return WebSocketCloseCode::Normal;}
                if !incoming_budget.take(message.as_bytes().len()) {
                    let frame=WebSocketServerFrame::ConnectionError {frame_scope:WebSocketConnectionScope::Connection,error:WebSocketTransportError::new(ErrorCode::RateLimited,"connection traffic quota exceeded")};
                    let _=send(socket,&mut outgoing,&frame).await;
                    return WebSocketCloseCode::Normal;
                }
                if message.is_ping()||message.is_pong(){continue;}
                if !message.is_text(){return WebSocketCloseCode::ProtocolError;}
                let incoming=match ingress.decode_server_ingress(message.as_bytes()){Ok(frame)=>frame,Err(error)=>return error.close_code.unwrap_or(WebSocketCloseCode::ProtocolError)};
                match incoming {
                    WebSocketClientIngress::SelectorRefused {channel_id,error}=>{
                        if credential.is_none()||challenge.is_some(){return WebSocketCloseCode::ProtocolError;}
                        if used.len()>=MAX_USED_CHANNEL_IDS {return WebSocketCloseCode::PolicyViolation;}
                        let frame=if used.insert(channel_id.clone()){WebSocketServerFrame::ChannelError {frame_scope:WebSocketChannelScope::Channel,channel_id:channel_id.clone(),error}}else{channel_error(&channel_id,ErrorCode::Conflict)};
                        channels.remove(&channel_id);schedule.retain(|id|id!=&channel_id);
                        if let Err(code)=send(socket,&mut outgoing,&frame).await{return code;}
                        if let Err(code)=send(socket,&mut outgoing,&WebSocketServerFrame::Closed {channel_id,reason:WebSocketClosedReason::Error}).await{return code;}
                    }
                    WebSocketClientIngress::Frame(WebSocketClientFrame::Authenticate {connection_id,session_grant,dpop_proof})=>{
                        let Some(c)=challenge.as_ref() else{return WebSocketCloseCode::ProtocolError;};
                        let frame=WebSocketClientFrame::Authenticate {connection_id,session_grant,dpop_proof};
                        let next=match authenticate(&state,&origin,c,&frame).await{Ok(c)=>c,Err(code)=>return code};
                        if credential.as_ref().is_some_and(|old|!same_holder(old,&next)){return WebSocketCloseCode::PolicyViolation;}
                        let lease=match connection_lease(&id,&state,&next){Ok(lease)=>lease,Err(code)=>return code};
                        match state.sync().websocket_auth().reserve_connection(&lease).await {
                            Ok(true)=>{},Ok(false)=>{
                                let frame=WebSocketServerFrame::ConnectionError {frame_scope:WebSocketConnectionScope::Connection,error:WebSocketTransportError::new(ErrorCode::RateLimited,"session or device connection quota exceeded")};
                                let _=send(socket,&mut outgoing,&frame).await;return WebSocketCloseCode::Normal;
                            },Err(_)=>return WebSocketCloseCode::InternalError,
                        }
                        lease_renewed=tokio::time::Instant::now();
                        if let Some(tx)=credential_updates.as_ref(){watch::Sender::<Credential>::send_replace(tx,next.clone());}
                        else {let (tx,_)=watch::channel(next.clone());credential_updates=Some(tx);}
                        if let Err(code)=send(socket,&mut outgoing,&WebSocketServerFrame::Welcome {connection_id:id.clone(),limits:limits(),auth_expires_at:next.session.expires_at}).await{return code;}
                        credential=Some(next);challenge=None;
                    }
                    WebSocketClientIngress::Frame(WebSocketClientFrame::Open {channel_id,operation_id,parameters})=>{
                        let Some(current)=credential.as_ref() else{return WebSocketCloseCode::ProtocolError;};
                        if challenge.is_some(){return WebSocketCloseCode::ProtocolError;}
                        if used.len()>=MAX_USED_CHANNEL_IDS {return WebSocketCloseCode::PolicyViolation;}
                        let error=if !used.insert(channel_id.clone()){Some(ErrorCode::Conflict)}
                            else if drain_deadline.is_some(){Some(ErrorCode::TemporarilyUnavailable)}
                            else if channels.len()>=MAX_CHANNELS as usize || (operation_id!=WebSocketOperationId::CommittedEventStreamSubscribe && channels.values().any(|channel|channel.operation==operation_id)){Some(ErrorCode::RateLimited)}
                            else if crate::routing::events::require_agent_session_scope(&current.session,operation_id.as_str()).is_err(){Some(ErrorCode::CapabilityDenied)}else{None};
                        if let Some(error)=error {
                            channels.remove(&channel_id);schedule.retain(|id|id!=&channel_id);
                            if let Err(code)=send(socket,&mut outgoing,&channel_error(&channel_id,error)).await{return code;}
                            if let Err(code)=send(socket,&mut outgoing,&WebSocketServerFrame::Closed {channel_id,reason:WebSocketClosedReason::Error}).await{return code;}
                            continue;
                        }
                        if !super::subscribe::stream_session_current(&state,&current.session,Some(current.grant.as_str())).await{return WebSocketCloseCode::PolicyViolation;}
                        let response=response_for(&state,current,&parameters).await;
                        if response.status_code.is_some_and(|s|!s.is_success()) {
                            if let Err(code)=send(socket,&mut outgoing,&channel_error(&channel_id,problem_code(&response))).await{return code;}
                            if let Err(code)=send(socket,&mut outgoing,&WebSocketServerFrame::Closed {channel_id,reason:WebSocketClosedReason::Error}).await{return code;}
                            continue;
                        }
                        if let Err(code)=send(socket,&mut outgoing,&WebSocketServerFrame::Opened {channel_id:channel_id.clone(),operation_id}).await{return code;}
                        let channel=start_channel(state.clone(),channel_id.clone(),operation_id,parameters,credential_updates.as_ref().unwrap().subscribe(),ready.clone(),failures.clone(),response);
                        channels.insert(channel_id.clone(),channel);schedule.push_back(channel_id);
                    }
                    WebSocketClientIngress::Frame(WebSocketClientFrame::Close {channel_id,..})=>{
                        if !used.contains(&channel_id){return WebSocketCloseCode::ProtocolError;}
                        channels.remove(&channel_id);schedule.retain(|id|id!=&channel_id);
                        if let Err(code)=send(socket,&mut outgoing,&WebSocketServerFrame::Closed {channel_id,reason:WebSocketClosedReason::ClientRequest}).await{return code;}
                    }
                    WebSocketClientIngress::Frame(WebSocketClientFrame::Pong {ping_id})=>{
                        if outstanding_ping.as_deref()!=Some(&ping_id){return WebSocketCloseCode::ProtocolError;}
                        outstanding_ping=None;
                    }
                }
            }
        }
    }
}

#[handler]
pub(crate) async fn upgrade(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot
        .get_typed::<AppState>()
        .expect("state injected")
        .clone();
    let reject = |res: &mut Response| {
        render_error(
            res,
            StatusCode::FORBIDDEN,
            "capability_denied",
            "WebSocket upgrade is not allowed",
        )
    };
    let Ok(public) = url::Url::parse(&state.config().public_base_url) else {
        reject(res);
        return;
    };
    if public.scheme() != "https" || req.scheme().as_str() != "https" || req.uri().query().is_some()
    {
        reject(res);
        return;
    }
    let mut hosts = req.headers().get_all("host").iter();
    let expected = public[url::Position::BeforeHost..url::Position::AfterPort].to_owned();
    if hosts.next().and_then(|h| h.to_str().ok()) != Some(expected.as_str())
        || hosts.next().is_some()
    {
        reject(res);
        return;
    }
    let mut origins = req.headers().get_all("origin").iter();
    let Some(origin) = origins.next().and_then(|h| h.to_str().ok()) else {
        reject(res);
        return;
    };
    if origins.next().is_some() {
        reject(res);
        return;
    }
    let Ok(origin) = canonical_http_origin(origin) else {
        reject(res);
        return;
    };
    let same_origin = canonical_http_origin(&public.origin().ascii_serialization())
        .is_ok_and(|configured| configured == origin);
    let allowed = same_origin
        || state
            .config()
            .cors_allow_origin
            .as_deref()
            .is_some_and(|raw| {
                raw.split(',').any(|configured| {
                    canonical_http_origin(configured.trim())
                        .is_ok_and(|configured| configured == origin)
                })
            });
    if !allowed {
        reject(res);
        return;
    }
    let protocols = req
        .headers()
        .get_all("sec-websocket-protocol")
        .iter()
        .filter_map(|h| h.to_str().ok())
        .flat_map(|s| s.split(','))
        .map(str::trim)
        .collect::<Vec<_>>();
    if !protocols.contains(&WEBSOCKET_SUBPROTOCOL) {
        reject(res);
        return;
    }
    let base_url = format!(
        "wss{}{}_arkret/ws",
        public
            .as_str()
            .strip_prefix("https")
            .unwrap()
            .trim_end_matches('/'),
        "/"
    );
    if arkret_wire::websocket_binding::validate_websocket_base_url(&base_url).is_err() {
        reject(res);
        return;
    }
    let origin = origin.to_string();
    if WebSocketUpgrade::new()
        .protocols(&[WEBSOCKET_SUBPROTOCOL])
        // Reassemble at most the profile hard ceiling, then enforce the
        // advertised lower limit in ingress. This consumes a bounded frame
        // before sending 1009 instead of dropping its unread TLS payload.
        .max_message_size(arkret_wire::websocket_binding::WEBSOCKET_HARD_MAX_FRAME_BYTES)
        .max_frame_size(arkret_wire::websocket_binding::WEBSOCKET_HARD_MAX_FRAME_BYTES)
        .write_buffer_size(0)
        .max_write_buffer_size(2 * MAX_FRAME as usize)
        .upgrade(req, res, move |mut socket| async move {
            // The peer receives only a bounded non-secret close reason.
            let code = connection(&mut socket, state, origin, base_url).await;
            let sent = tokio::time::timeout(
                Duration::from_secs(5),
                socket.send(Message::close_with(code.as_u16(), "connection_closed")),
            )
            .await;
            if matches!(sent, Ok(Ok(()))) {
                // Keep the transport alive until the peer acknowledges Close.
                // Dropping unread TLS data can reset TCP and discard the code.
                let _ = tokio::time::timeout(Duration::from_secs(5), async {
                    while let Some(Ok(message)) = socket.recv().await {
                        if message.is_close() {
                            break;
                        }
                    }
                })
                .await;
            }
            // Receiving the peer's Close already queues tungstenite's reply.
            // An explicit send may then fail in Closing state; closing the
            // Sink still flushes that queued reply before dropping the stream.
            let _ = tokio::time::timeout(Duration::from_secs(5), SinkExt::close(&mut socket)).await;
        })
        .await
        .is_err()
    {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "param_invalid",
            "WebSocket upgrade failed",
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn traffic_quota_bounds_both_bytes_and_frames_before_a_fresh_delivery_gate() {
        let mut budget = TrafficBudget::new(2, 100);
        assert!(budget.take(60));
        assert!(!budget.take(41));
        assert!(budget.take(40));
        assert!(!budget.take(1));
        let started = tokio::time::Instant::now();
        budget.wait(50).await.unwrap();
        assert!(started.elapsed() >= Duration::from_millis(900));
        assert!(budget.take(50));
        assert!(!budget.add_bytes(1));
        assert!(budget.wait(101).await.is_err());
    }
}
