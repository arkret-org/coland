//! Actor-private Event admission (actor-private-effects.md).
//!
//! An actor-private Event is admitted by its owner's Station into the
//! account-private store only: the producer is verified against the local PCR,
//! the exact signed bytes enter the actor-private ledger, and the effect is
//! written in one private transaction. No RealmCommit covers it, no Realm
//! reducer sees it and it never enters federation. Sibling devices observe the
//! accepted value as an actor-private DeviceMessage update.

use arkret_models_collaboration::events_payloads::account_data::AccountDataSetPayload;
use arkret_wire::Event;
use coland_http::error::AppError;
use coland_services::identity::SessionIdentityState;
use coland_services::{ServiceError, ServiceResult};
use coland_storage::{
    AccountDataCasCommit, AccountDataRecord, ActorPrivateAccountDataAdmission,
    ActorPrivateAccountDataOutcome,
};

use super::AppState;
use crate::routing::identity::device_messages::{
    ActorPrivateAccountDataOperation, ActorPrivateAccountDataUpdate, ActorPrivateDeviceUpdate,
    DeviceMessageSender, fanout_actor_private_update,
};

/// SHA-256 of the complete canonical Event bytes: with the Event id, the
/// exact-retry identity of every actor-private branch.
pub(crate) fn canonical_event_digest(event: &Event) -> ServiceResult<Vec<u8>> {
    Ok(arkret_canonical::sha256_bytes(
        &arkret_canonical::canonical_json_bytes(event)
            .map_err(|error| ServiceError::SchemaViolation(error.to_string()))?,
    )
    .to_vec())
}

/// Admit one holder-signed `ak.account_data.set` (section 3.1): the whole value
/// replaces the register when `expected_server_revision` equals the stored
/// revision, the stored revision becomes that value plus one, and `updated_at`
/// is the signed payload value or else the envelope `created_at`.
pub(crate) async fn admit_account_data_set(
    state: &AppState,
    session: &SessionIdentityState,
    event: &Event,
) -> ServiceResult<ActorPrivateAccountDataOutcome> {
    if event.kind != arkret_wire::EventKind::AccountDataSet {
        return Err(ServiceError::SchemaViolation(
            "set_event.kind must be ak.account_data.set".to_owned(),
        ));
    }
    let producer_guard =
        super::authority_producer_validation::verify_self_event_producer(state, session, event)
            .await?;
    let owner = event
        .actor_id
        .as_account_id()
        .ok_or_else(|| ServiceError::Conflict("account data is owned by an Account".to_owned()))?;
    if owner.station_id != state.service_core_id() {
        return Err(ServiceError::Conflict(
            "account data is stored only at its owner's Station".to_owned(),
        ));
    }
    let payload = serde_json::to_value(&event.payload)
        .map_err(|error| ServiceError::SchemaViolation(error.to_string()))?;
    let typed: AccountDataSetPayload = serde_json::from_value(payload.clone())
        .map_err(|error| ServiceError::SchemaViolation(error.to_string()))?;
    let revision = typed
        .expected_server_revision
        .checked_add(1)
        .ok_or_else(|| {
            ServiceError::Conflict(
                "cas_conflict: account data revision high-water mark is exhausted".to_owned(),
            )
        })?;
    let value = if typed.tombstone {
        serde_json::Value::Null
    } else {
        payload
            .get("body")
            .or_else(|| payload.get("encrypted_payload"))
            .cloned()
            .ok_or_else(|| {
                ServiceError::SchemaViolation("account data Event carries no value".to_owned())
            })?
    };
    let admission = ActorPrivateAccountDataAdmission {
        canonical_event_digest: canonical_event_digest(event)?,
        cas: AccountDataCasCommit {
            record: AccountDataRecord {
                actor: event.actor_id.to_string(),
                account_data_key: typed.key.as_str().to_owned(),
                revision,
                payload: value,
                tombstone: typed.tombstone,
                updated_at: typed.updated_at.unwrap_or(event.created_at),
            },
            expected_revision: typed.expected_server_revision,
            conflict_code: "cas_conflict".to_owned(),
        },
        event: event.clone(),
        producer_guard: Some(producer_guard),
        accepted_at: chrono::Utc::now(),
    };
    let outcome = state
        .persistence()
        .admit_actor_private_account_data(&admission)
        .await?;
    if outcome == ActorPrivateAccountDataOutcome::Applied {
        fanout_account_data(state, session, &admission.cas.record).await;
    }
    Ok(outcome)
}

/// Sibling devices of the holder observe the accepted value; the authoring
/// device is never echoed.
async fn fanout_account_data(
    state: &AppState,
    session: &SessionIdentityState,
    record: &AccountDataRecord,
) {
    let (Ok(sender_account_id), Ok(sender_device_id)) = (
        crate::routing::identity::auth_grant_dpop::authenticated_session_account_id(state, session)
            .await,
        arkret_wire::DeviceId::new(session.require_human_device_id().clone()),
    ) else {
        tracing::warn!("accepted account data has no human-device sender to fan out from");
        return;
    };
    let content = ActorPrivateAccountDataUpdate {
        operation: if record.tombstone {
            ActorPrivateAccountDataOperation::Delete
        } else {
            ActorPrivateAccountDataOperation::Put
        },
        account_data_key: record.account_data_key.clone(),
        revision: record.revision,
        content: (!record.tombstone).then(|| record.payload.clone()),
        updated_at: record.updated_at,
    };
    let sender = DeviceMessageSender::Account {
        sender_account_id: sender_account_id.clone(),
        sender_device_id,
    };
    let update = ActorPrivateDeviceUpdate::AccountData {
        sender,
        content,
        created_at: record.updated_at,
    };
    fanout_actor_private_update(state, sender_account_id.principal_id.as_str(), update).await;
}

/// Producer and storage refusals of an actor-private admission keep their
/// registered device, signature, schema, duplicate and availability codes;
/// any other producer binding refusal is `capability_denied`.
pub(crate) fn actor_private_refusal(error: ServiceError) -> AppError {
    use coland_storage::ConflictCode;
    match &error {
        ServiceError::SchemaViolation(detail) => AppError::schema_violation(detail.clone()),
        ServiceError::Conflict(detail) => match error.conflict_code() {
            Some(
                code @ (ConflictCode::DeviceRevoked
                | ConflictCode::DeviceRevocationPending
                | ConflictCode::DeviceGenerationFenced
                | ConflictCode::DeviceUnauthorized
                | ConflictCode::SignatureInvalid
                | ConflictCode::SchemaViolation
                | ConflictCode::DuplicateConflict
                | ConflictCode::FailedPrecondition
                | ConflictCode::TemporarilyUnavailable),
            ) => coland_http::error::ErrorCode::from_wire(code.as_str()).map_or_else(
                || AppError::internal(format!("unregistered refusal code {code}")),
                |wire| AppError::from_rejection(wire, detail.clone()),
            ),
            _ => AppError::capability_denied(detail.clone()),
        },
        ServiceError::NotFound(detail) => AppError::capability_denied(detail.clone()),
        ServiceError::UnsupportedEventKind(detail) => {
            crate::app_error!(UnsupportedEventKind, "{detail}")
        }
        ServiceError::Database(_) | ServiceError::Internal(_) => {
            AppError::internal(error.to_string())
        }
    }
}
