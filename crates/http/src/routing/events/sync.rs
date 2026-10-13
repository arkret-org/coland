//! Account aggregate + snapshot handlers + the cursor-helper machinery they share
//! with events and device-message modules.
//!
//! Surfaces for the current sync/event wire layout:
//! - `GET  /_arkret/self/account/describe`
//! - `GET  /_arkret/self/account/subscribe`       — `ak.self.account.stream.subscribe.v1`
//!   (account-aggregate NDJSON: timeline, account data, to_device).
//! - `POST /_arkret/self/signal`                  — `ak.self.signal.command.send.v1` (Signal
//!   Extension send rail; encrypted-only)
//! - `GET  /_arkret/self/signal/subscribe`        — `ak.self.signal.stream.subscribe.v1` (Signal
//!   Extension receive rail; verbatim envelope NDJSON)
//! - `GET  /_arkret/self/committed-events/subscribe` — committed Event live tail. Multi-Realm /
//!   multi-actor stream; frame `kind` field replaces `type`.
//! - `GET  /_arkret/self/realm-state-snapshot/head`
//! - `GET  /_arkret/self/realm-state-snapshot/{snapshot_id}` — exact issued by-ref read
//!
//! `SyncCursor`, `SyncCursorError`, `parse_and_validate_sync_cursor`,
//! `decode_sync_cursor_value`, `sync_token_for_client_sync`, `sync_filter_digest`,
//! are `pub` because sibling routing modules reuse them. They
//! live here because the cursor lifecycle is sealed to account subscribe.
//!
//! The implementation is split across submodules; this module file owns the
//! shared imports / constants, the protocol router, the scope-selector helpers,
//! and re-exports the per-topic items so `sync::xxx` paths and the `super::*`
//! views in `snapshot.rs` / `sync_tests.rs` keep resolving unchanged.

pub(crate) use std::collections::{BTreeMap, BTreeSet};
pub(crate) use std::time::Duration;

pub(crate) use arkret_identifiers::RealmId;
#[cfg(test)]
pub(crate) use base64::Engine;
#[cfg(test)]
pub(crate) use base64::engine::general_purpose::URL_SAFE_NO_PAD;
pub(crate) use bytes::Bytes;
pub(crate) use chrono::{DateTime, Utc};
#[cfg(test)]
pub(crate) use coland_domain::reducer::ProjectionState;
#[cfg(test)]
pub(crate) use coland_services::events::ProjectedEvent;
pub(crate) use coland_services::identity::SessionIdentityState;
pub(crate) use coland_services::sync::CursorState;
pub(crate) use futures_util::stream::StreamExt;
pub(crate) use salvo::http::{StatusCode, header};
pub(crate) use salvo::prelude::*;
pub(crate) use serde_json::{Value, json};
pub(crate) use tokio::sync::broadcast::error::RecvError;

#[cfg(test)]
use super::realm_event_visible_to_session;
use super::{
    authenticated_session, is_realm_deleted, now, query_param, realm_id_accessible,
    realm_state_snapshot_manifest_for_realm, render_error, sha256_hex,
};
pub(crate) use crate::ids;
pub(crate) use crate::state::AppState;
pub(crate) use crate::wire::SyncRequestBody;

/// Default reconnect guard advertised on subscribe terminal control frames.
/// Shared by `account_subscribe` (subscribe.rs) and `events_subscribe`
/// (events_query.rs).
pub(crate) const SUBSCRIBE_RECONNECT_AFTER_MS: u64 = 10_000;
/// Group revocations cover all issuances until the stream TTL hard cap.
pub(crate) const CURSOR_MAX_TTL_SECONDS: i64 = arkret_hlc::Cursor::STREAM_TTL_MAX_MS / 1000;
/// `account_data_tombstone_retention_ms` is 90 days. This dominates the
/// one-hour cursor TTL, so Station-CAS change records cannot be collected
/// before every valid cursor that could name them has expired.
const ACCOUNT_DATA_CHANGE_RETENTION_DAYS: i64 = 90;
const ACCOUNT_DATA_CHANGE_SWEEP_INTERVAL: Duration = Duration::from_secs(900);

mod snapshot;

pub(crate) use snapshot::*;
mod current_details;
mod cursor;
mod demand_list;
mod global_channels;
pub(crate) mod signal;
// `spawn_sync_cursor_ttl_sweeper` is `pub` (boot worker entry re-exported at
// `crate::routing::spawn_sync_cursor_ttl_sweeper` for `main`); the explicit
// `pub use` overrides the `pub(crate)` glob above for this one name.
pub use cursor::spawn_sync_cursor_ttl_sweeper;
pub fn spawn_account_data_change_retention_sweeper(state: AppState) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(ACCOUNT_DATA_CHANGE_SWEEP_INTERVAL);
        loop {
            ticker.tick().await;
            let cutoff =
                chrono::Utc::now() - chrono::Duration::days(ACCOUNT_DATA_CHANGE_RETENTION_DAYS);
            match state.account_data().prune_changes_before(cutoff).await {
                Ok(pruned) if pruned > 0 => {
                    tracing::info!(pruned, "pruned retained account-data change records");
                }
                Ok(_) => {}
                Err(error) => {
                    tracing::error!(%error, "failed to prune retained account-data change records");
                }
            }
        }
    })
}
pub(crate) use cursor::*;
pub(crate) fn content_delivery_guard<'a>(
    state: &'a AppState,
    session: &'a SessionIdentityState,
    input: &'a coland_storage::AccountContentDeliveryInput,
) -> impl std::future::Future<
    Output = Result<
        Option<Box<dyn coland_storage::AccountContentDeliveryGuard>>,
        crate::error::AppError,
    >,
> + Send
+ 'a {
    // Keep the credential preflight out of every enclosing stream's inline
    // state machine. The held transaction and cancellation path stay intact.
    Box::pin(content_delivery_guard_inner(state, session, input))
}

async fn content_delivery_guard_inner(
    state: &AppState,
    session: &SessionIdentityState,
    input: &coland_storage::AccountContentDeliveryInput,
) -> Result<Option<Box<dyn coland_storage::AccountContentDeliveryGuard>>, crate::error::AppError> {
    let actor =
        crate::routing::identity::session_actor::validated_session_actor(state, session).await?;
    let account = actor.as_account_id().ok_or_else(|| {
        crate::error::AppError::capability_denied("content recipient is not an Account")
    })?;
    let mut input = input.clone();
    if let Some(agent_session) = session.agent_session() {
        let grant = session.session_grant.as_ref().ok_or_else(|| {
            crate::error::AppError::capability_denied("Agent delivery credential is unavailable")
        })?;
        input.credential_expires_at = Some(session.expires_at);
        let details = agent_session
            .scope_details
            .get("scope_details")
            .and_then(Value::as_object)
            .ok_or_else(|| {
                crate::error::AppError::capability_denied(
                    "Agent current session resource ceiling is unavailable",
                )
            })?;
        input.agent_session_scope = Some((grant.scopes.clone(), details.clone()));
        let arkret_models_identity::session_credential::SessionGrantHolderBinding::AgentRuntime {
            agent_id,
            agent_key_authorization_ref,
            verification_method,
        } = &grant.holder_binding
        else {
            return Err(crate::error::AppError::capability_denied(
                "Agent delivery credential differs",
            ));
        };
        if &account.principal_id != agent_id {
            return Err(crate::error::AppError::capability_denied(
                "Agent delivery recipient differs",
            ));
        }
        let (_, current) =
            crate::routing::identity::current_signer_evidence::current_agent_endpoint_key(
                state,
                &actor,
                verification_method,
            )
            .await
            .map_err(|_| {
                crate::error::AppError::capability_denied(
                    "Agent current delivery key is unavailable",
                )
            })?;
        if current.event_id != *agent_key_authorization_ref {
            return Err(crate::error::AppError::capability_denied(
                "Agent delivery authorization changed",
            ));
        }
        let guard = coland_storage::AgentEndpointGuard {
            pcr_realm_id: current.stream_ref.realm_id().clone(),
            agent_id: agent_id.clone(),
            authorization_ref: current,
            verification_method: verification_method.clone(),
        };
        input.qualified_agent_scope_evidence =
            Some(state.qualified_agent_scope_evidence(&guard).await?);
        input.agent_endpoint = Some(guard);
    }
    state
        .authority_commits()
        .acquire_committed_content_delivery(account, &state.service_core_id(), &input)
        .await
        .map_err(|_| {
            crate::error::AppError::capability_denied("current content delivery is unavailable")
        })
}

/// Private process factory for the fixed reply consumer. The request is the
/// actual original committed-Event GET signed by the live Agent session key.
/// No caller-provided Actor/session fields are treated as authentication.
pub async fn acquire_native_message_reply_cut(
    state: &AppState,
    req: &mut Request,
    grant_jwt: &str,
    agent: &arkret_wire::AccountId,
    controller: &arkret_wire::AccountId,
    caller: &arkret_wire::AccountId,
    source: &arkret_wire::CommittedEventFullView,
    scope: &arkret_wire::ScopeRef,
    strand: &arkret_wire::StrandId,
    operation: arkret_wire::ServiceOperationId,
) -> Result<Box<dyn coland_storage::AccountContentDeliveryGuard>, crate::error::AppError> {
    let invalid =
        || crate::error::AppError::unauthenticated("native reply source request binding differs");
    let expected = format!(
        "{}/_arkret/self/committed-events/{}",
        state.config().public_base_url.trim_end_matches('/'),
        source.event.event_id.as_str()
    );
    if req.method() != salvo::http::Method::GET
        || req.uri().to_string() != expected
        || operation.as_str()
            != arkret_wire::ServiceOperationId::SELF_COMMITTED_EVENT_RESOURCE_GET_V1
        || scope != &source.event.scope_ref
        || req.uri().query().is_some()
        || req
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            != Some(format!("DPoP {grant_jwt}").as_str())
    {
        return Err(invalid());
    }
    // Obtain one force-fresh authoritative result before PoP verification so
    // both original credential checks use the same exact request memo.
    crate::routing::identity::auth_grant_dpop::take_request_authoritative_grant(
        state, req, grant_jwt, true,
    )
    .await
    .map_err(|(_, code, _)| native_reply_auth_error(code))?;
    crate::routing::identity::session_pop::enforce_native_reply_session_pop(state, req).await?;
    let authenticated =
        crate::routing::identity::auth_grant_dpop::authenticate_native_reply_session(
            state, req, grant_jwt,
        )
        .await
        .map_err(|(_, code, _)| native_reply_auth_error(code))?;
    native_message_reply_preparation_guard(
        state,
        &authenticated,
        agent,
        controller,
        caller,
        source,
        strand,
    )
    .await
}

fn native_reply_auth_error(code: &str) -> crate::error::AppError {
    crate::error::AppError::from_rejection(
        crate::error::ErrorCode::from_wire(code)
            .unwrap_or(crate::error::ErrorCode::TemporarilyUnavailable),
        "native reply credential is unavailable",
    )
}

/// Assemble only trusted native reply credential/current material before the
/// PG held cut. This does not authorize generic model/tools or issue a ticket.
pub(crate) async fn native_message_reply_preparation_guard(
    state: &AppState,
    authenticated: &crate::routing::identity::auth_grant_dpop::NativeReplyAuthenticatedSession,
    expected_agent: &arkret_wire::AccountId,
    expected_controller: &arkret_wire::AccountId,
    caller: &arkret_wire::AccountId,
    source: &arkret_wire::CommittedEventFullView,
    strand: &arkret_wire::StrandId,
) -> Result<Box<dyn coland_storage::AccountContentDeliveryGuard>, crate::error::AppError> {
    let denied = || {
        crate::error::AppError::capability_denied("native reply current authority is unavailable")
    };
    let session = authenticated.session();
    let actor =
        crate::routing::identity::session_actor::validated_session_actor(state, session).await?;
    let account = actor.as_account_id().ok_or_else(denied)?;
    let grant = session.session_grant.as_ref().ok_or_else(denied)?;
    let agent_session = session.agent_session().ok_or_else(denied)?;
    if account != expected_agent
        || session.expires_at <= chrono::Utc::now()
        || session.revoked_at.is_some()
    {
        return Err(denied());
    }
    let arkret_models_identity::session_credential::SessionGrantHolderBinding::AgentRuntime {
        agent_id,
        agent_key_authorization_ref,
        verification_method,
    } = &grant.holder_binding
    else {
        return Err(denied());
    };
    if &account.principal_id != agent_id {
        return Err(denied());
    }
    let (_, current) =
        crate::routing::identity::current_signer_evidence::current_agent_endpoint_key(
            state,
            &actor,
            verification_method,
        )
        .await
        .map_err(|_| denied())?;
    if current.event_id != *agent_key_authorization_ref {
        return Err(denied());
    }
    let endpoint = coland_storage::AgentEndpointGuard {
        pcr_realm_id: current.stream_ref.realm_id().clone(),
        agent_id: agent_id.clone(),
        authorization_ref: current,
        verification_method: verification_method.clone(),
    };
    let evidence = state.qualified_agent_scope_evidence(&endpoint).await?;
    if &evidence.accepted_binding().controller_account != expected_controller {
        return Err(denied());
    }
    let details = agent_session
        .scope_details
        .get("scope_details")
        .and_then(Value::as_object)
        .ok_or_else(denied)?;
    let mut input = coland_storage::AccountContentDeliveryInput::committed(&[
        arkret_wire::CommittedEventView::Full(source.clone()),
    ]);
    input.credential_expires_at = Some(session.expires_at);
    input.agent_session_scope = Some((grant.scopes.clone(), details.clone()));
    input.agent_endpoint = Some(endpoint);
    input.qualified_agent_scope_evidence = Some(evidence);
    // Original authenticated AA resolve/verify/append happens before acquiring
    // any local delivery/PCR locks; a held guard never calls back to the issuer.
    for human in [expected_controller, caller] {
        input
            .account_status_observations
            .push(super::peer::refresh_current_account_status(state, human).await?);
    }
    state
        .authority_commits()
        .acquire_native_message_reply_preparation(coland_storage::NativeMessageReplyPreparation {
            agent: expected_agent,
            controller: expected_controller,
            caller,
            station: &state.service_core_id(),
            source,
            strand,
            input: &input,
            deployment: state.config().agent_participation_ceiling,
        })
        .await
        .map_err(|_| denied())
}

async fn account_frame_delivery_guard(
    state: &AppState,
    session: &SessionIdentityState,
    frame: &arkret_models_collaboration::sync_frames::account_subscribe::AccountSubscribeFrame,
) -> Result<Option<Box<dyn coland_storage::AccountContentDeliveryGuard>>, crate::error::AppError> {
    let input =
        coland_storage::AccountContentDeliveryInput::account_frame(frame).map_err(|_| {
            crate::error::AppError::capability_denied("current content delivery is unavailable")
        })?;
    content_delivery_guard(state, session, &input).await
}

mod subscribe;
pub(crate) use subscribe::*;
mod committed_subscription;
mod events_query;
pub(crate) mod websocket;
pub(crate) use events_query::*;

pub(super) fn protocol_router() -> Router {
    Router::new()
        .push(Router::with_path("account/describe").get(subscribe::account_describe))
        .push(Router::with_path("account/subscribe").get(subscribe::account_subscribe))
        .push(Router::with_path("account/cursor/revoke").post(cursor::account_cursor_revoke))
        .push(Router::with_path("signal").post(signal::submit_signal))
        .push(Router::with_path("signal/subscribe").get(signal::signal_subscribe))
        .push(
            Router::with_path("realm-state-snapshot/head")
                .get(events_query::realm_state_snapshot_head),
        )
        .push(
            Router::with_path("realm-state-snapshot/{snapshot_id}")
                .get(events_query::realm_state_snapshot_by_ref),
        )
}

pub(crate) fn scope_selector_to_realm_id(
    value: &str,
) -> Result<String, coland_http::error::AppError> {
    if RealmId::new(value.to_owned()).is_ok() {
        return Ok(value.to_owned());
    }
    Err(coland_http::error::AppError::param_invalid(
        "invalid realm_id",
    ))
}

#[cfg(test)]
#[path = "sync_tests.rs"]
mod tests;
