//! To-device message transport.
//!
//! Surfaces:
//! - `POST /_arkret/self/device_messages` — send to-device messages, idempotent on `(actor,
//!   idempotency_key)` so duplicate retries return 200 without re-queueing. The idempotency key is
//!   supplied via the `Idempotency-Key` request header.
//! - `GET /_arkret/self/device_messages` — pull pending to-device messages for the bound
//!   session/device. A `from` cursor is read-only pagination state; it never prunes the queue.
//! - `POST /_arkret/self/device_messages/ack` — consume a bearer ack token and prune the messages
//!   covered by that delivery batch.

use std::collections::BTreeMap;

use arkret_models_collaboration::device_messages::{
    DeviceMessageDeliveredRow, DeviceMessageDeliveredStatus, DeviceMessageTarget,
    DeviceMessageUnknownRow, DeviceMessageUnknownStatus,
};
use coland_http::error::AppError;
use coland_http::result::{JsonResult, json_ok};
use coland_services::delivery::{
    DeviceMessageBatchCommitOutcome, DeviceMessageBatchInspection, DeviceMessageBatchItemRecord,
    DeviceMessageBatchRecord, DeviceMessageIntentRecord, DeviceMessageState,
    RecipientQueueSelector,
};
use coland_services::identity::{DeviceIdentity, SessionIdentityState};
use salvo::oapi::extract::{JsonBody, QueryParam};
use salvo::prelude::*;
use serde_json::{Value, json};

use super::{SyncCursorError, now};
use crate::routing::events::sync::{device_messages_cursor, parse_device_messages_cursor};
use crate::routing::system::extract::AuthArgs;
use crate::state::AppState;
pub(crate) use crate::wire::DeviceMessageSender;
use crate::wire::{
    DeviceMessageEnvelope, DeviceMessagesAckOutcome, DeviceMessagesAckRequestBody,
    DeviceMessagesGetOutcome, DeviceMessagesSendOutcome, DeviceMessagesSendRequestBody,
};

pub(crate) const TO_DEVICE_PAGE_LIMIT: usize = 100;
const TO_DEVICE_DEFAULT_PAGE_LIMIT: usize = 20;
/// Default maximum enqueue TTL (`device-lifecycle.md` §7). This Station
/// declares no service, Realm or profile bound that changes it.
const DEVICE_MESSAGE_MAX_ENQUEUE_TTL_HOURS: i64 = 24;

/// `device-lifecycle.md` §7: a new enqueue is admissible only while
/// `sent_at < expires_at <= sent_at + max TTL`. An `expires_at` at or before
/// the queue-materialized `sent_at` is already expired.
fn device_message_expiry_admissible(
    sent_at: chrono::DateTime<chrono::Utc>,
    expires_at: chrono::DateTime<chrono::Utc>,
) -> bool {
    expires_at > sent_at
        && expires_at <= sent_at + chrono::Duration::hours(DEVICE_MESSAGE_MAX_ENQUEUE_TTL_HOURS)
}

pub(crate) fn recipient_queue_selector(
    session: &SessionIdentityState,
) -> Result<RecipientQueueSelector, AppError> {
    if session.agent_session().is_some() {
        let Some(grant) = session.session_grant.as_ref() else {
            return Err(AppError::capability_denied(
                "Agent recipient queue requires an authenticated Agent grant",
            ));
        };
        let arkret_models_identity::session_credential::SessionGrantHolderBinding::AgentRuntime {
            agent_id,
            agent_key_authorization_ref,
            verification_method,
            ..
        } = &grant.holder_binding
        else {
            return Err(AppError::capability_denied(
                "Agent recipient queue grant binding is invalid",
            ));
        };
        if session.actor != agent_id.as_str() {
            return Err(AppError::capability_denied(
                "Agent recipient queue actor differs from the grant",
            ));
        }
        return Ok(RecipientQueueSelector::AgentRuntime {
            agent_id: agent_id.to_string(),
            verification_method: verification_method.to_string(),
            authorization_event_ref: agent_key_authorization_ref.to_string(),
        });
    }
    let device_id = session.human_device_id().ok_or_else(|| {
        AppError::capability_denied("recipient queue requires a Human device endpoint")
    })?;
    Ok(RecipientQueueSelector::HumanDevice {
        recipient: session.actor.clone(),
        device_id: device_id.clone(),
    })
}

/// Internal actor-private queue materialization. These values are built only
/// from an accepted local current result, then serialized as the closed
/// `content` object of a regular DeviceMessageEnvelope.
#[derive(Clone, Copy, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ActorPrivateAccountDataOperation {
    Put,
    Delete,
}

#[derive(Clone, serde::Serialize)]
pub(crate) struct ActorPrivateAccountDataUpdate {
    pub operation: ActorPrivateAccountDataOperation,
    pub account_data_key: String,
    pub revision: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<Value>,
    #[serde(with = "arkret_wire::serde_helpers::canonical_timestamp")]
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, serde::Serialize)]
pub(crate) struct ActorPrivateReadCursorUpdate {
    pub schema: String,
    pub actor_id: arkret_wire::ActorId,
    pub device_id: arkret_wire::DeviceId,
    pub realm_id: arkret_wire::RealmId,
    pub read_scope: arkret_wire::ReadCursorScope,
    pub position: arkret_models_collaboration::objects::read_receipts::ReadCursorPosition,
    #[serde(with = "arkret_wire::serde_helpers::canonical_timestamp")]
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

pub(crate) enum ActorPrivateDeviceUpdate {
    AccountData {
        sender: DeviceMessageSender,
        content: ActorPrivateAccountDataUpdate,
        created_at: chrono::DateTime<chrono::Utc>,
    },
    ReadCursor {
        sender: DeviceMessageSender,
        content: ActorPrivateReadCursorUpdate,
        created_at: chrono::DateTime<chrono::Utc>,
    },
}

impl ActorPrivateDeviceUpdate {
    fn kind(&self) -> &'static str {
        match self {
            Self::AccountData { .. } => "ak.account_data.update",
            Self::ReadCursor { .. } => "ak.read_cursor.update",
        }
    }

    fn created_at(&self) -> chrono::DateTime<chrono::Utc> {
        match self {
            Self::AccountData { created_at, .. } | Self::ReadCursor { created_at, .. } => {
                *created_at
            }
        }
    }
}

/// Build the only service sender accepted by the internal actor-private
/// materializer. Keeping this constructor beside the fanout prevents CAS
/// producers from accepting or copying a caller-supplied service identity.
pub(crate) fn station_device_message_sender(state: &AppState) -> DeviceMessageSender {
    DeviceMessageSender::Station {
        sender_id: arkret_identifiers::DidCoreId::new(state.service_id().to_owned())
            .expect("the loaded Station identity is a core DID"),
    }
}

struct PreparedDeviceMessageTarget {
    recipient: String,
    device_id: String,
    recipient_id: arkret_wire::DidCoreId,
    recipient_device_id: arkret_wire::DeviceId,
    target: DeviceMessageTarget,
    message_key: String,
    intent_digest: String,
}

/// Canonical preimage of one to-device message intent, digested for
/// idempotent-send conflict detection. The shape is typed so `kind` and
/// `content` cannot be paired by hand-authored JSON; `content` stays the
/// spec-open object declared by `device-message.schema.json` and arrives
/// already validated through [`DeviceMessageTarget`].
#[derive(serde::Serialize)]
struct DeviceMessageIntentPreimage<'a> {
    device_message_id: &'a arkret_wire::DeviceMessageId,
    kind: &'a arkret_wire::ProtocolKind,
    #[serde(flatten)]
    sender: &'a DeviceMessageSender,
    recipient_account_id: &'a arkret_wire::AccountId,
    recipient_device_id: &'a arkret_wire::DeviceId,
    expires_at: chrono::DateTime<chrono::Utc>,
    content: &'a BTreeMap<String, Value>,
}

/// The authenticated sending endpoint of `ak.self.device_messages.command.send.v1`
/// (device-lifecycle §7): a human device with its revocation gate, or an Agent
/// runtime endpoint with its current key authorization. The Station branch is
/// never reachable from this client surface.
struct SendingEndpoint {
    sender: DeviceMessageSender,
    device_revocation_gate: Option<coland_storage::DeviceRevocationGateSelector>,
    agent_guard: Option<coland_storage::AgentEndpointGuard>,
}

async fn sending_endpoint(
    state: &AppState,
    session: &SessionIdentityState,
) -> Result<SendingEndpoint, AppError> {
    if session.agent_session().is_some() {
        crate::routing::events::require_agent_session_scope(
            session,
            arkret_wire::ServiceOperationId::SELF_DEVICE_MESSAGES_COMMAND_SEND_V1,
        )?;
        let denied = |detail: &str| AppError::capability_denied(detail.to_owned());
        let grant = session
            .session_grant
            .as_ref()
            .ok_or_else(|| denied("Agent sender requires an authenticated Agent grant"))?;
        let arkret_models_identity::session_credential::SessionGrantHolderBinding::AgentRuntime {
            agent_id,
            agent_key_authorization_ref,
            verification_method,
        } = &grant.holder_binding
        else {
            return Err(denied("Agent sender grant binding is invalid"));
        };
        if session.actor != agent_id.as_str() {
            return Err(denied("Agent sender actor differs from the grant"));
        }
        let actor =
            crate::routing::identity::session_actor::validated_session_actor(state, session)
                .await
                .map_err(|error| denied(&error.message))?;
        let (_, current) = super::current_signer_evidence::current_agent_endpoint_key(
            state,
            &actor,
            verification_method,
        )
        .await
        .map_err(|error| denied(&error))?;
        if current.event_id != *agent_key_authorization_ref {
            return Err(denied(
                "Agent sender grant authorization is no longer current",
            ));
        }
        return Ok(SendingEndpoint {
            sender: DeviceMessageSender::Agent {
                sender_agent_id: agent_id.clone(),
                sender_agent_verification_method: verification_method.clone(),
                sender_agent_key_authorize_event_id: agent_key_authorization_ref.clone(),
            },
            device_revocation_gate: None,
            agent_guard: Some(coland_storage::AgentEndpointGuard {
                pcr_realm_id: current.stream_ref.realm_id().clone(),
                agent_id: agent_id.clone(),
                authorization_ref: current,
                verification_method: verification_method.clone(),
            }),
        });
    }
    let sender_account_id =
        super::auth_grant_dpop::authenticated_session_account_id(state, session).await?;
    let device_unauthorized = |detail: &str| {
        AppError::capability_denied(detail.to_owned()).with_wire_code("device_unauthorized")
    };
    let endpoint_device_id = session
        .human_device_id()
        .ok_or_else(|| device_unauthorized("to-device send requires a Human device endpoint"))?;
    let sender_device_id = arkret_wire::DeviceId::new(endpoint_device_id.clone())
        .map_err(|_| device_unauthorized("to-device send requires a typed sender device"))?;
    let gate = match super::device_generation::active_device_revocation_gate_selector(
        state,
        &session.actor,
        endpoint_device_id,
    )
    .await
    {
        Ok(selector) => selector,
        Err(error) if error.is_not_found() => {
            return Err(device_unauthorized("device authorization is not active"));
        }
        Err(error) => {
            return Err(AppError::internal(format!(
                "current device revocation selector unavailable: {error}"
            )));
        }
    };
    Ok(SendingEndpoint {
        sender: DeviceMessageSender::Account {
            sender_account_id,
            sender_device_id,
        },
        device_revocation_gate: Some(gate),
        agent_guard: None,
    })
}

/// The closed-sender idempotency identity of one logical message
/// (device-lifecycle §7): `(sender_account_id, sender_device_id,
/// device_message_id)` for a human device, `(sender_agent_id,
/// device_message_id)` for an Agent and `(sender_id, device_message_id)` for
/// the Station materializer. An Agent key rotation keeps the same identity.
fn sender_idempotency_identity(
    sender: &DeviceMessageSender,
    device_message_id: &arkret_wire::DeviceMessageId,
) -> Value {
    match sender {
        DeviceMessageSender::Account {
            sender_account_id,
            sender_device_id,
        } => json!({
            "sender_account_id": sender_account_id,
            "sender_device_id": sender_device_id,
            "device_message_id": device_message_id,
        }),
        DeviceMessageSender::Agent {
            sender_agent_id, ..
        } => json!({
            "sender_agent_id": sender_agent_id,
            "device_message_id": device_message_id,
        }),
        DeviceMessageSender::Station { sender_id } => json!({
            "sender_id": sender_id,
            "device_message_id": device_message_id,
        }),
    }
}

pub(super) fn protocol_router() -> Router {
    Router::new()
        .push(
            Router::with_path("device_messages")
                .post(send_device_messages)
                .get(get_device_messages),
        )
        .push(Router::with_path("device_messages/ack").post(ack_device_messages))
}

#[handler]
#[tracing::instrument(skip_all, fields(op = "ak.self.device_messages.command.send.v1"))]
async fn send_device_messages(
    aa: AuthArgs,
    body: JsonBody<Value>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<DeviceMessagesSendOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let body = device_messages_send_request_body(body.into_inner())?;
    let SendingEndpoint {
        sender,
        device_revocation_gate: sender_revocation_gate,
        agent_guard: sender_agent_guard,
    } = sending_endpoint(state, &session).await?;
    let idempotency_key = req
        .headers()
        .get("Idempotency-Key")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| AppError::param_missing("Idempotency-Key header is required"))?
        .trim();
    if idempotency_key.is_empty() || idempotency_key.len() > 128 {
        return Err(AppError::param_invalid(
            "Idempotency-Key must contain 1 to 128 characters",
        ));
    }
    let idempotency_key = idempotency_key.to_owned();
    let request_digest = arkret_canonical::canonical_sha256(&body)
        .map_err(|error| AppError::internal(error.to_string()))?;
    let request_key = arkret_canonical::canonical_sha256(&json!([session.actor, idempotency_key,]))
        .map_err(|error| AppError::internal(error.to_string()))?;
    // The queue materializes one `sent_at` for every envelope of this batch;
    // expiry admission is judged against exactly that value.
    let sent_at = arkret_canonical::normalize_timestamp_canonical(now());
    let mut prepared_targets = Vec::new();
    for (recipient, devices) in body.messages {
        for (device_id, target) in devices {
            if matches!(target.kind.as_str(), "ak.secret.request" | "ak.secret.send") {
                return Err(AppError::param_invalid(
                    "ak.secret.request and ak.secret.send are not admitted in v1",
                ));
            }
            let message_key = arkret_canonical::canonical_sha256(&sender_idempotency_identity(
                &sender,
                &target.device_message_id,
            ))
            .map_err(|error| AppError::internal(error.to_string()))?;
            let recipient_account_id =
                arkret_wire::AccountId::new(recipient.clone(), state.service_core_id().clone());
            let intent_digest = arkret_canonical::canonical_sha256(&DeviceMessageIntentPreimage {
                device_message_id: &target.device_message_id,
                kind: &target.kind,
                sender: &sender,
                recipient_account_id: &recipient_account_id,
                recipient_device_id: &device_id,
                expires_at: target.expires_at,
                content: &target.content,
            })
            .map_err(|error| AppError::internal(error.to_string()))?;
            prepared_targets.push(PreparedDeviceMessageTarget {
                recipient: recipient.to_string(),
                device_id: device_id.to_string(),
                recipient_id: recipient.clone(),
                recipient_device_id: device_id.clone(),
                target,
                message_key,
                intent_digest,
            });
        }
    }
    let intents = prepared_targets
        .iter()
        .map(|target| DeviceMessageIntentRecord {
            message_key: target.message_key.clone(),
            intent_digest: target.intent_digest.clone(),
        })
        .collect::<Vec<_>>();
    let inspection = state
        .deliveries()
        .inspect_device_message_batch(&request_key, &request_digest, &intents)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    let existing_message_outcomes = match inspection {
        DeviceMessageBatchInspection::Fresh {
            existing_message_outcomes,
        } => existing_message_outcomes,
        DeviceMessageBatchInspection::Duplicate(outcomes) => {
            return json_ok(device_message_send_outcome(&prepared_targets, &outcomes)?);
        }
        DeviceMessageBatchInspection::RequestConflict => {
            return Err(device_message_request_conflict());
        }
        DeviceMessageBatchInspection::MessageConflict { .. } => {
            return Err(device_message_intent_conflict());
        }
    };
    // Exact idempotency was judged above; expiry admission applies to every
    // remaining new enqueue. One inadmissible target fails the whole request
    // before either idempotency ledger or any queue is written.
    if prepared_targets.iter().any(|target| {
        !existing_message_outcomes.contains_key(&target.message_key)
            && !device_message_expiry_admissible(sent_at, target.target.expires_at)
    }) {
        return Err(AppError::param_invalid(
            "every new DeviceMessage expires_at must be later than sent_at and within the enqueue TTL",
        ));
    }
    let has_fresh_targets = prepared_targets
        .iter()
        .any(|target| !existing_message_outcomes.contains_key(&target.message_key));
    // An Agent endpoint is proved by its grant triple against the current
    // accepted key authorization, rechecked in the queue transaction.
    let sender_verified = if has_fresh_targets && sender_agent_guard.is_none() {
        let sender_device = state
            .identities()
            .find_device(coland_services::identity::FindDeviceQuery {
                actor_id: session.actor.clone(),
                device_id: session.require_human_device_id().clone(),
            })
            .await
            .map_err(|error| AppError::internal(error.to_string()))?;
        device_is_active_verified(sender_device.as_ref())
    } else {
        sender_agent_guard.is_some()
    };
    if has_fresh_targets && !sender_verified {
        return Err(AppError::capability_denied(
            "to-device send requires an accepted current sender device",
        )
        .with_wire_code("device_unauthorized"));
    }

    let mut batch_items = Vec::with_capacity(prepared_targets.len());
    for prepared in &prepared_targets {
        let message = if existing_message_outcomes.contains_key(&prepared.message_key) {
            None
        } else {
            let secret_message = prepared.target.kind.starts_with("ak.secret.");
            let target_record = state
                .identities()
                .find_device(coland_services::identity::FindDeviceQuery {
                    actor_id: prepared.recipient.clone(),
                    device_id: prepared.device_id.clone(),
                })
                .await
                .map_err(|error| AppError::internal(error.to_string()))?;
            let target_verified = device_is_active_verified(target_record.as_ref());
            if secret_message && !target_verified {
                return Err(AppError::capability_denied(
                    "secret to-device messages require authorized sender and recipient devices",
                )
                .with_wire_code("device_unauthorized"));
            }
            let deliverable = target_verified;
            if deliverable {
                // The queue materializes `sent_at` at enqueue; the persisted
                // row and every later read carry this exact closed envelope.
                let envelope = DeviceMessageEnvelope {
                    device_message_id: prepared.target.device_message_id.clone(),
                    kind: prepared.target.kind.clone(),
                    // The closed sender branch of the authenticated endpoint.
                    sender: sender.clone(),
                    recipient_account_id: arkret_wire::AccountId::new(
                        prepared.recipient_id.clone(),
                        state.service_core_id().clone(),
                    ),
                    recipient_device_id: prepared.recipient_device_id.clone(),
                    sent_at,
                    expires_at: prepared.target.expires_at,
                    content: prepared.target.content.clone(),
                    unsigned: None,
                };
                Some(DeviceMessageState {
                    idempotency_key: idempotency_key.clone(),
                    sender: session.actor.clone(),
                    recipient: prepared.recipient.clone(),
                    device_id: prepared.device_id.clone(),
                    recipient_device_authorization: recipient_authorization(
                        state,
                        target_record.as_ref().expect("verified target exists"),
                    )
                    .await?,
                    position: state.next_to_device_position(),
                    envelope,
                })
            } else {
                None
            }
        };
        batch_items.push(DeviceMessageBatchItemRecord {
            message_key: prepared.message_key.clone(),
            intent_digest: prepared.intent_digest.clone(),
            idempotency_expires_at: prepared.target.expires_at + chrono::Duration::hours(1),
            message,
        });
    }
    let idempotency_expires_at = batch_items
        .iter()
        .map(|item| item.idempotency_expires_at)
        .fold(sent_at + chrono::Duration::hours(1), std::cmp::max);
    let batch_outcome = state
        .deliveries()
        .commit_device_message_batch(DeviceMessageBatchRecord {
            request_key,
            request_digest,
            idempotency_expires_at,
            per_device_queue_capacity: state.config().to_device_queue_capacity,
            device_revocation_gate: sender_revocation_gate,
            sender_agent_guard,
            target_snapshot_guard: None,
            items: batch_items,
        })
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    let message_outcomes = match batch_outcome {
        DeviceMessageBatchCommitOutcome::Stored(outcomes) => {
            if prepared_targets
                .iter()
                .any(|target| !outcomes.contains_key(&target.message_key))
            {
                return Err(AppError::internal(
                    "stored device-message outcome differs from the admitted targets",
                ));
            }
            outcomes
        }
        DeviceMessageBatchCommitOutcome::Duplicate(outcomes) => outcomes,
        DeviceMessageBatchCommitOutcome::RequestConflict => {
            return Err(device_message_request_conflict());
        }
        DeviceMessageBatchCommitOutcome::MessageConflict { .. } => {
            return Err(device_message_intent_conflict());
        }
        DeviceMessageBatchCommitOutcome::SnapshotConflict => {
            return Err(AppError::conflict("recipient device snapshot changed"));
        }
        DeviceMessageBatchCommitOutcome::DeviceRevocationPending => {
            return Err(AppError::conflict("device revocation is pending")
                .with_wire_code("device_revocation_pending"));
        }
        DeviceMessageBatchCommitOutcome::DeviceRevoked => {
            return Err(
                AppError::conflict("device generation is revoked").with_wire_code("device_revoked")
            );
        }
        DeviceMessageBatchCommitOutcome::SenderAgentUnauthorized => {
            return Err(AppError::capability_denied(
                "the sending Agent endpoint is no longer its current accepted key",
            ));
        }
        DeviceMessageBatchCommitOutcome::QueueAtCapacity => {
            return Err(
                crate::app_error!(QuotaExceeded, "recipient queue is at capacity")
                    .with_wire_code("quota_exceeded"),
            );
        }
    };
    let outcome = device_message_send_outcome(&prepared_targets, &message_outcomes)?;
    json_ok(outcome)
}

fn device_message_send_outcome(
    targets: &[PreparedDeviceMessageTarget],
    outcomes: &BTreeMap<String, bool>,
) -> Result<DeviceMessagesSendOutcome, AppError> {
    let mut delivered = BTreeMap::new();
    let mut unknown_devices = BTreeMap::new();
    for target in targets {
        let outcome = outcomes.get(&target.message_key).copied().ok_or_else(|| {
            AppError::internal("stored device-message outcome is missing a target")
        })?;
        let recipient = arkret_wire::DidCoreId::new(target.recipient.clone())
            .map_err(|error| AppError::internal(format!("stored recipient id: {error}")))?;
        let device_id = arkret_wire::DeviceId::new(target.device_id.clone())
            .map_err(|error| AppError::internal(format!("stored device id: {error}")))?;
        if outcome {
            delivered
                .entry(recipient)
                .or_insert_with(BTreeMap::new)
                .insert(
                    device_id,
                    DeviceMessageDeliveredRow {
                        device_message_id: target.target.device_message_id.clone(),
                        status: DeviceMessageDeliveredStatus::Delivered,
                    },
                );
        } else {
            unknown_devices
                .entry(recipient)
                .or_insert_with(BTreeMap::new)
                .insert(
                    device_id,
                    DeviceMessageUnknownRow {
                        device_message_id: target.target.device_message_id.clone(),
                        status: DeviceMessageUnknownStatus::Unknown,
                    },
                );
        }
    }
    Ok(DeviceMessagesSendOutcome {
        delivered,
        unknown_devices,
    })
}

/// Decode the send body. `device-lifecycle.md` §7 makes a target without
/// `expires_at` a sender request defect judged like any other inadmissible
/// window (`param_invalid`), so that member is checked before the typed
/// decoder turns its absence into a generic schema violation.
fn device_messages_send_request_body(
    body: Value,
) -> Result<DeviceMessagesSendRequestBody, AppError> {
    let missing_expiry = body
        .get("messages")
        .and_then(Value::as_object)
        .into_iter()
        .flat_map(|recipients| recipients.values())
        .filter_map(Value::as_object)
        .flat_map(|devices| devices.values())
        .filter_map(Value::as_object)
        .any(|target| target.get("expires_at").is_none_or(Value::is_null));
    if missing_expiry {
        return Err(AppError::param_invalid(
            "every DeviceMessage target must carry expires_at",
        ));
    }
    serde_json::from_value(body).map_err(|error| {
        AppError::schema_violation(format!(
            "request body violates the declared schema: {error}"
        ))
    })
}

fn device_message_request_conflict() -> AppError {
    AppError::conflict("Idempotency-Key was already used for a different request body")
        .with_wire_code("duplicate_conflict")
}

fn device_message_intent_conflict() -> AppError {
    AppError::conflict("device_message_id was already used for a different canonical target")
        .with_wire_code("duplicate_conflict")
        .with_reason_code(arkret_wire::ReasonCode::DEVICE_MESSAGE_ID_CONFLICT)
}

/// Fan an actor-private update (account-data / blocklist / read-cursor
/// deltas, plaintext `content`) out to the holder's active devices. A real
/// device sender excludes its origin device; the local Station
/// materializer has no origin device and therefore reaches every active one.
///
/// Sidecar isolation note (zh/models/sidecar.md §7 / private-objects.md
/// §4.2): controller-private account-data plaintext travels over this surface,
/// and the target set is exactly `devices_for_actor(actor)` — the device
/// directory rows registered under the controller principal itself. Agent
/// runtime endpoints are NOT in that set: agent pairing never writes a
/// `DeviceIdentity` row under the controller (there is no `save_device` call
/// anywhere in the pairing flow), agent sessions authenticate as the agent's
/// own DID with `ak.agent.key.authorize`, and their to-device endpoints are
/// MLS key-package rows keyed by the *agent* principal
/// (`active_agent_keypackage_endpoint` resolves `row.actor_id ==
/// agent principal`). Controller-actor device rows can only be created by the
/// controller's own device flows (registration placeholder, login/device
/// pair, and the `ak.device.authorize` projection for the controller
/// principal), so this fanout is naturally isolated from agent-bound devices;
/// `fanout_skips_devices_registered_under_other_principals` pins that fact.
/// After at least one durable queue write, the materializer also publishes an
/// account-context wakeup. The wakeup carries no private body and is only a
/// latency hint; account subscribe always rebuilds its delta from durable
/// queue positions.
pub(crate) async fn fanout_actor_private_update(
    state: &AppState,
    actor: &str,
    update: ActorPrivateDeviceUpdate,
) -> usize {
    let event_type = update.kind();
    let created_at = arkret_canonical::normalize_timestamp_canonical(update.created_at());
    let sender = match &update {
        ActorPrivateDeviceUpdate::AccountData { sender, .. }
        | ActorPrivateDeviceUpdate::ReadCursor { sender, .. } => sender,
    };
    let (origin_device_id, sender_endpoint_id, sender_revocation_gate) = match sender {
        DeviceMessageSender::Account {
            sender_account_id,
            sender_device_id,
        } => {
            if sender_account_id.principal_id.as_str() != actor
                || sender_account_id.station_id != state.service_core_id()
            {
                tracing::warn!(
                    actor,
                    "actor-private fanout rejected because sender AccountId differs from holder"
                );
                return 0;
            }
            let sender_revocation_gate =
                match super::device_generation::active_device_revocation_gate_selector(
                    state,
                    actor,
                    sender_device_id.as_str(),
                )
                .await
                {
                    Ok(selector) => Some(selector),
                    Err(error) => {
                        tracing::warn!(
                            %error,
                            actor,
                            origin_device_id = sender_device_id.as_str(),
                            "actor-private fanout rejected because the sender device authority is not active"
                        );
                        return 0;
                    }
                };
            (
                Some(sender_device_id.as_str()),
                sender_device_id.as_str(),
                sender_revocation_gate,
            )
        }
        DeviceMessageSender::Station { sender_id } => {
            if sender_id.as_str() != state.service_id() {
                tracing::warn!(
                    actor,
                    sender_id = sender_id.as_str(),
                    local_service_id = state.service_id(),
                    "actor-private fanout rejected because the service sender is not local"
                );
                return 0;
            }
            // This internal materializer always writes `sender == recipient ==
            // actor` below. A Station update is therefore scoped to
            // the holder whose cell changed, does not borrow a holder device's
            // authority, and has neither a device-revocation gate nor an
            // origin device to exclude.
            (None, sender_id.as_str(), None)
        }
        DeviceMessageSender::Agent { .. } => {
            tracing::warn!(
                actor,
                "actor-private fanout rejected because Agent senders are not cell materializers"
            );
            return 0;
        }
    };
    let content = match &update {
        ActorPrivateDeviceUpdate::AccountData { content, .. } => serde_json::to_value(content),
        ActorPrivateDeviceUpdate::ReadCursor { content, .. } => serde_json::to_value(content),
    };
    let Ok(Value::Object(content)) = content else {
        tracing::error!(
            actor,
            "failed to serialize actor-private DeviceMessage content"
        );
        return 0;
    };
    let content: BTreeMap<String, Value> = content.into_iter().collect();
    let devices = state
        .identities()
        .devices_for_actor(actor)
        .await
        .unwrap_or_default();
    let mut delivered = 0;
    for device in devices {
        if !device_is_active_verified(Some(&device))
            || origin_device_id.is_some_and(|origin| device.device_id == origin)
        {
            continue;
        }
        let recipient_device_authorization = match recipient_authorization(state, &device).await {
            Ok(source) => source,
            Err(error) => {
                tracing::error!(%error, "actor-private target lacks its original device authorization");
                continue;
            }
        };
        let position = state.next_to_device_position();
        let envelope = DeviceMessageEnvelope {
            device_message_id: arkret_identifiers::DeviceMessageId::new(crate::ids::generate(
                "device_message",
            ))
            .expect("the server device-message generator returns a typed UUIDv7 id"),
            kind: arkret_wire::wire_strings::ProtocolKind::new(event_type)
                .expect("actor-private update kinds are registered protocol kinds"),
            sender: sender.clone(),
            recipient_account_id: arkret_wire::AccountId::new(
                arkret_identifiers::DidCoreId::new(actor.to_owned())
                    .expect("authenticated actor-private holder is a core DID"),
                state.service_core_id().clone(),
            ),
            recipient_device_id: arkret_identifiers::DeviceId::new(device.device_id.clone())
                .expect("persisted active device has a typed device id"),
            sent_at: created_at,
            expires_at: created_at + chrono::Duration::hours(1),
            content: content.clone(),
            unsigned: None,
        };
        let idempotency_key = format!("{event_type}:{actor}:{sender_endpoint_id}:{position}");
        match state
            .deliveries()
            .append_device_message(
                sender_revocation_gate.as_ref(),
                DeviceMessageState {
                    idempotency_key,
                    sender: actor.to_owned(),
                    recipient: actor.to_owned(),
                    device_id: device.device_id,
                    recipient_device_authorization,
                    position,
                    envelope,
                },
                state.config().to_device_queue_capacity,
            )
            .await
        {
            Ok(()) => delivered += 1,
            Err(error) => tracing::error!(%error, actor, "failed to fan out actor-private update"),
        }
    }
    if delivered > 0 {
        let Ok(principal_id) = arkret_wire::DidCoreId::new(actor.to_owned()) else {
            tracing::warn!(actor, "actor-private fanout actor is invalid");
            return delivered;
        };
        let account_id = arkret_wire::AccountId::new(principal_id, state.service_core_id().clone());
        match state.identities().account(&account_id).await {
            Ok(Some(account)) => {
                let _ = state.publish_event_notification(crate::state::EventNotification::account(
                    account.account_id,
                    state.service_core_id().clone(),
                ));
            }
            Ok(None) => {
                tracing::warn!(
                    actor,
                    "actor-private fanout queued messages without a local account wakeup target"
                );
            }
            Err(error) => {
                // The queue rows are durable and the bounded account long poll
                // re-reads them at timeout. A failed lookup can delay delivery,
                // but it must not turn an accepted private update into a
                // failed or duplicated write.
                tracing::warn!(
                    %error,
                    actor,
                    "actor-private fanout could not publish an account-stream wakeup"
                );
            }
        }
    }
    delivered
}

#[handler]
#[tracing::instrument(skip_all, fields(op = "ak.self.device_messages.read.list.v1"))]
async fn get_device_messages(
    aa: AuthArgs,
    after: QueryParam<String, false>,
    limit: QueryParam<u32, false>,
    depot: &mut Depot,
    req: &mut Request,
) -> coland_http::result::GuardedJsonResult<DeviceMessagesGetOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let cursor = after.into_inner();
    let cursor_position = match cursor {
        Some(cursor) => match parse_device_messages_cursor(
            &cursor,
            state,
            &session,
            chrono::Utc::now().timestamp_millis(),
        )
        .await
        {
            Ok(position) => position,
            Err(SyncCursorError::Unavailable(message)) => {
                return Err(crate::app_error!(TemporarilyUnavailable, message));
            }
            Err(SyncCursorError::Expired) => {
                return Err(crate::app_error!(CursorExpired, "cursor has expired",));
            }
            Err(SyncCursorError::Invalid(message)) => {
                return Err(AppError::param_invalid(message)
                    .with_reason_code(arkret_wire::ReasonCode::INVALID_CURSOR));
            }
            Err(SyncCursorError::Mismatch(message)) => {
                return Err(crate::app_error!(CursorIntegrityInvalid, message));
            }
            Err(SyncCursorError::Integrity(message)) => {
                return Err(crate::app_error!(CursorIntegrityInvalid, message));
            }
            Err(SyncCursorError::Revoked) => {
                return Err(crate::app_error!(
                    CursorRevoked,
                    "cursor authority has been revoked",
                ));
            }
        },
        None => 0,
    };
    let page_limit = match limit.into_inner() {
        Some(0) => return Err(AppError::param_invalid("limit must be greater than zero")),
        Some(limit) => (limit as usize).min(TO_DEVICE_PAGE_LIMIT),
        None => TO_DEVICE_DEFAULT_PAGE_LIMIT,
    };
    let selector = recipient_queue_selector(&session)?;
    let lost_watermark = if matches!(&selector, RecipientQueueSelector::HumanDevice { .. }) {
        state
            .deliveries()
            .device_message_lost_watermark(&session.actor, session.require_human_device_id())
            .await
            .map_err(|error| AppError::internal(error.to_string()))?
    } else {
        None
    };
    let lost = lost_watermark.is_some_and(|position| position > cursor_position);
    let queued = state
        .deliveries()
        .recipient_deliveries_after(&selector, cursor_position, page_limit + 1)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    let has_more = queued.len() > page_limit;
    let page = queued.into_iter().take(page_limit).collect::<Vec<_>>();
    let deliveries = page.iter().map(|record| record.delivery.clone()).collect();
    let delivered_position = page
        .iter()
        .map(|message| message.position)
        .max()
        .unwrap_or(cursor_position);
    let mut to_device_position = delivered_position;
    if lost && let Some(lost_watermark) = lost_watermark {
        to_device_position = to_device_position.max(lost_watermark);
    }
    // Current permission and future-material authority precede every private
    // ACK/cursor allocation, including continuation reads. Keep this same cut
    // through the original guarded response handoff.
    let future_materials = page
        .iter()
        .filter_map(|record| match &record.delivery {
            arkret_models_collaboration::device_messages::RecipientDelivery::MlsWelcome {
                mls_welcome,
            } => Some(mls_welcome.clone()),
            _ => None,
        })
        .collect::<Vec<_>>();
    let input = coland_storage::AccountContentDeliveryInput {
        realms: future_materials
            .iter()
            .map(|welcome| welcome.realm_id.clone())
            .collect(),
        future_materials,
        ..Default::default()
    };
    let guard =
        crate::routing::events::sync::content_delivery_guard(state, &session, &input).await?;
    let ack_token = if page.is_empty() {
        None
    } else {
        Some(
            state
                .deliveries()
                .issue_recipient_ack_token(&selector, delivered_position)
                .await
                .map_err(|error| AppError::internal(error.to_string()))?
                .ok_or_else(|| {
                    crate::app_error!(
                        ServiceUnavailable,
                        "recipient delivery ACK token unavailable"
                    )
                })?,
        )
    };
    let next_cursor = if page.is_empty() && !lost {
        None
    } else {
        Some(
            device_messages_cursor(state, &session, to_device_position)
                .await
                .map_err(|_| AppError::internal("cannot persist device queue cursor".to_owned()))?,
        )
    };
    coland_http::result::guarded_json_ok(
        DeviceMessagesGetOutcome {
            deliveries,
            ack_token,
            next_cursor,
            has_more,
            limited: Some(has_more),
            lost: Some(lost),
        },
        guard,
    )
}

#[handler]
#[tracing::instrument(skip_all, fields(op = "ak.self.device_messages.command.ack.v1"))]
async fn ack_device_messages(
    aa: AuthArgs,
    body: JsonBody<DeviceMessagesAckRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<DeviceMessagesAckOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let body = body.into_inner();
    let selector = recipient_queue_selector(&session)?;
    let ack_token = body.ack_token.as_str();
    if ack_token.is_empty() || ack_token.len() > 1024 {
        return Err(AppError::param_invalid("invalid ack token")
            .with_reason_code(arkret_wire::ReasonCode::INVALID_ACK_TOKEN));
    }
    let Some(pruned_count) = state
        .deliveries()
        .acknowledge_recipient_deliveries(&selector, ack_token)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
    else {
        return Err(AppError::param_invalid("invalid ack token")
            .with_reason_code(arkret_wire::ReasonCode::INVALID_ACK_TOKEN));
    };
    json_ok(DeviceMessagesAckOutcome {
        pruned_count: pruned_count as u64,
    })
}

#[cfg(test)]
pub(crate) fn device_message_envelopes_after(
    state: &AppState,
    messages: &[DeviceMessageState],
) -> Vec<DeviceMessageEnvelope> {
    messages
        .iter()
        .filter_map(|message| device_message_envelope_from_record(state, message))
        .collect()
}

fn device_is_active_verified(record: Option<&DeviceIdentity>) -> bool {
    record.is_some_and(|record| {
        record.revoked_at.is_none() && record.verification_state == "verified"
    })
}

async fn recipient_authorization(
    state: &AppState,
    record: &DeviceIdentity,
) -> Result<coland_storage::DeviceRevocationGateSelector, AppError> {
    if !device_is_active_verified(Some(record)) {
        return Err(AppError::capability_denied(
            "recipient device authorization is unavailable",
        ));
    }
    super::device_generation::active_device_revocation_gate_selector(
        state,
        &record.actor_id,
        &record.device_id,
    )
    .await
    .map_err(|error| {
        tracing::warn!(%error, "recipient device has no accepted current authorization");
        AppError::capability_denied("recipient device authorization is unavailable")
    })
}

#[cfg(test)]
fn device_message_envelope_from_record(
    state: &AppState,
    message: &DeviceMessageState,
) -> Option<DeviceMessageEnvelope> {
    // Queue rows carry a complete closed envelope. Never repair missing
    // sender, recipient, or expiry fields while serving authenticated reads.
    message.validate_binding().ok()?;
    let envelope = message.envelope.clone();
    if envelope.recipient_account_id.station_id != state.service_core_id() {
        return None;
    }
    if matches!(
        envelope.kind.as_str(),
        "ak.secret.request" | "ak.secret.send"
    ) {
        return None;
    }
    if let DeviceMessageSender::Station { sender_id } = &envelope.sender {
        if *sender_id != state.service_core_id()
            || !matches!(
                envelope.kind.as_str(),
                "ak.account_data.update" | "ak.read_cursor.update"
            )
        {
            return None;
        }
    }
    Some(envelope)
}

#[cfg(test)]
mod tests {
    use coland_services::identity::AccountProfileState;
    use coland_test_support::AppStateTestExt as _;
    use coland_test_support::pcr_genesis::PcrGenesisFixture;
    use serde_json::json;

    use super::*;

    /// A Station over a leased PostgreSQL database that holds this Station's
    /// persisted service identity. Persisting the identity is what binds the
    /// device inventory to the Station in a deployment, so every device row
    /// written below carries the Station it belongs to.
    fn station_config(development_mode: bool) -> crate::config::AppConfig {
        crate::config::AppConfig {
            object_storage: crate::config::ObjectStorageConfig::local(
                std::env::temp_dir().join("coland-device-messages-test-blobs"),
            ),
            development_mode,
            seed_demo_data: false,
            ..crate::config::AppConfig::test_default()
        }
    }

    fn station(development_mode: bool) -> AppState {
        let config = station_config(development_mode);
        let service_did =
            AppState::new(config.clone(), coland_storage_postgres::Db { pool: None }).service_did();
        let persisted = coland_test_support::app_state_with_service_did(
            coland_test_support::app_config(),
            service_did,
        );
        let state = AppState::new_with_persistence(
            config,
            coland_storage_postgres::Db { pool: None },
            persisted.test_persistence(),
        );
        assert_eq!(state.service_id(), persisted.service_id());
        state
    }

    /// Admit a genuinely signed PCR genesis at this Station. Its founding
    /// device is the principal's accepted current device: the only authority
    /// a to-device fanout target or sender may stand on.
    async fn accepted_principal(state: &AppState) -> (String, String) {
        let fixture = PcrGenesisFixture::new(state.service_did());
        fixture
            .admit_into(state.test_persistence().as_ref())
            .await
            .expect("accepted PCR genesis");
        (
            fixture.history.account.principal_id.to_string(),
            fixture.history.founding_device_id.to_string(),
        )
    }

    fn account_data_update(sender: DeviceMessageSender) -> ActorPrivateDeviceUpdate {
        ActorPrivateDeviceUpdate::AccountData {
            sender,
            content: ActorPrivateAccountDataUpdate {
                operation: ActorPrivateAccountDataOperation::Put,
                account_data_key: "ak.account.blocklist".to_owned(),
                revision: 1,
                content: Some(json!({"private": true})),
                updated_at: now(),
            },
            created_at: now(),
        }
    }

    /// S-3 (spec review): controller-private account-data plaintext fanned out
    /// by `fanout_actor_private_update` only reaches device rows registered
    /// under the controller principal itself. Agent runtime devices live under
    /// the agent's own principal (agent pairing registers no controller-actor
    /// device row), so the fanout surface is naturally isolated from agents —
    /// this test pins that fact with an agent principal whose device is itself
    /// accepted and asserts the controller fanout never enqueues for it. A
    /// human-device sender additionally never echoes to its origin device.
    #[tokio::test]
    async fn fanout_skips_devices_registered_under_other_principals() {
        let state = station(true);
        let (controller, controller_device) = accepted_principal(&state).await;
        let (agent, agent_device) = accepted_principal(&state).await;

        let origin_sender = DeviceMessageSender::Account {
            sender_account_id: arkret_wire::AccountId::new(
                arkret_wire::DidCoreId::new(controller.clone()).unwrap(),
                state.service_core_id(),
            ),
            sender_device_id: arkret_identifiers::DeviceId::new(controller_device.clone()).unwrap(),
        };
        assert_eq!(
            fanout_actor_private_update(&state, &controller, account_data_update(origin_sender))
                .await,
            0,
            "a human-device sender never echoes the update to its origin device"
        );

        let delivered = fanout_actor_private_update(
            &state,
            &controller,
            account_data_update(station_device_message_sender(&state)),
        )
        .await;
        assert_eq!(
            delivered, 1,
            "only the controller's own accepted device receives the fanout"
        );
        let controller_queue = state
            .deliveries()
            .device_messages_after(&controller, &controller_device, 0, 101)
            .await
            .expect("controller queue");
        assert_eq!(controller_queue.len(), 1);
        // Both fixture principals found with the same device id, so the
        // isolation below is by principal alone: the agent endpoint shares
        // the controller device's id and still receives nothing.
        assert_eq!(agent_device, controller_device);
        let agent_queue = state
            .deliveries()
            .device_messages_after(&agent, &agent_device, 0, 101)
            .await
            .expect("agent queue");
        assert!(
            agent_queue.is_empty(),
            "agent-principal devices must never receive controller-private fanout"
        );
    }

    #[tokio::test]
    async fn production_service_fanout_reaches_every_active_holder_device_and_is_readable() {
        let state = station(false);
        let (holder, holder_device) = accepted_principal(&state).await;
        let account_id = arkret_wire::AccountId::new(
            arkret_wire::DidCoreId::new(holder.clone()).unwrap(),
            state.service_core_id().clone(),
        );
        state
            .identities()
            .save_account(AccountProfileState {
                pk: coland_storage::AccountPk(0),
                account_id: account_id.clone(),
                principal_id: arkret_wire::DidCoreId::new(holder.clone()).unwrap(),
                localpart: "holder".to_owned(),
                display_name: None,
                bio: None,
                avatar_blob_ref: None,
                created_at: now(),
            })
            .await
            .expect("holder account saved");
        // A directory row that no accepted `ak.device.authorize` stands behind
        // is not an active device and must not be reached. The directory write
        // path only ever creates such a row unverified.
        let unauthorized_device = "ak:device:01904100-0000-7000-8000-0000000000d2";
        let registered_at = now();
        state
            .identities()
            .save_device(coland_services::identity::SaveDeviceCommand {
                actor_id: holder.clone(),
                device_id: unauthorized_device.to_owned(),
                display_name: None,
                device: DeviceIdentity {
                    actor_id: holder.clone(),
                    device_id: unauthorized_device.to_owned(),
                    display_name: None,
                    verification_state: "unverified".to_owned(),
                    payload: json!({"device_id": unauthorized_device}),
                    created_at: registered_at,
                    updated_at: registered_at,
                    revoked_at: None,
                },
            })
            .await
            .expect("unauthorized device row saved");
        let updated_at = now();
        let cell = json!({"entries": [{"invite_id": "one"}]});
        let mut account_wakeups = state.test_subscribe_event_notifications();

        let delivered = fanout_actor_private_update(
            &state,
            &holder,
            ActorPrivateDeviceUpdate::AccountData {
                sender: station_device_message_sender(&state),
                content: ActorPrivateAccountDataUpdate {
                    operation: ActorPrivateAccountDataOperation::Put,
                    account_data_key: "ak.account.invite_delivery".to_owned(),
                    revision: 7,
                    content: Some(cell.clone()),
                    updated_at,
                },
                created_at: updated_at,
            },
        )
        .await;

        assert_eq!(
            delivered, 1,
            "service fanout reaches every accepted holder device and nothing else"
        );
        let wakeup =
            tokio::time::timeout(std::time::Duration::from_secs(1), account_wakeups.recv())
                .await
                .expect("account stream wakeup timeout")
                .expect("account stream wakeup channel");
        assert!(matches!(
            wakeup.kind,
            crate::state::EventNotificationKind::Account {
                account_id: ref received_account_id,
                recipient_id: ref received_recipient_id,
            } if received_account_id == &account_id
                && received_recipient_id.as_str() == state.service_id()
        ));
        assert!(
            state
                .deliveries()
                .device_messages_after(&holder, unauthorized_device, 0, 101)
                .await
                .expect("unauthorized device queue")
                .is_empty()
        );
        let queued = state
            .deliveries()
            .device_messages_after(&holder, &holder_device, 0, 101)
            .await
            .expect("holder device queue");
        assert_eq!(queued.len(), 1);
        let envelopes = device_message_envelopes_after(&state, &queued);
        assert_eq!(
            envelopes.len(),
            1,
            "service sender must parse without repair"
        );
        let envelope = &envelopes[0];
        assert_eq!(&envelope.recipient_account_id, &account_id);
        assert_eq!(envelope.recipient_device_id.as_str(), holder_device);
        assert!(matches!(
            &envelope.sender,
            DeviceMessageSender::Station { sender_id }
                if sender_id.as_str() == state.service_id()
        ));
        let content = serde_json::to_value(&envelope.content).unwrap();
        assert_eq!(content.get("revision"), Some(&json!(7)));
        assert_eq!(content.get("content"), Some(&cell));

        // A restarted Station over the same database serves the identical
        // unacknowledged envelope: the queue is durable, never process state.
        let restarted = AppState::new_with_persistence(
            station_config(false),
            coland_storage_postgres::Db { pool: None },
            state.test_persistence(),
        );
        let requeued = restarted
            .deliveries()
            .device_messages_after(&holder, &holder_device, 0, 101)
            .await
            .expect("restarted holder device queue");
        let reread = device_message_envelopes_after(&restarted, &requeued);
        assert_eq!(
            serde_json::to_value(&reread).unwrap(),
            serde_json::to_value(&envelopes).unwrap()
        );
    }
}
