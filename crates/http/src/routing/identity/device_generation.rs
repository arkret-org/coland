mod confirmed;

use std::hash::{Hash as _, Hasher};
use std::sync::{Arc, OnceLock};

use arkret_identifiers::RealmId;
use coland_services::ServiceError;
pub(crate) use confirmed::{ConfirmedDeviceHistory, load_confirmed_device_history};
use serde_json::Value;

use crate::state::AppState;

const DEVICE_GENERATION_ADMISSION_LOCK_SHARDS: usize = 1024;

static DEVICE_GENERATION_ADMISSION_LOCKS: OnceLock<Vec<Arc<tokio::sync::Mutex<()>>>> =
    OnceLock::new();

pub fn device_generation_admission_lock(scope_id: &str) -> Arc<tokio::sync::Mutex<()>> {
    let locks = DEVICE_GENERATION_ADMISSION_LOCKS.get_or_init(|| {
        (0..DEVICE_GENERATION_ADMISSION_LOCK_SHARDS)
            .map(|_| Arc::new(tokio::sync::Mutex::new(())))
            .collect()
    });
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    scope_id.hash(&mut hasher);
    locks[(hasher.finish() as usize) % DEVICE_GENERATION_ADMISSION_LOCK_SHARDS].clone()
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeviceGenerationView {
    pub current_ref: u64,
}

/// The accepted PCR `device_generation` typed current of this Station's
/// Account (device-lifecycle.md §5.5.4), read at one confirmed cut. `None` when this Station holds
/// no PCR for the Account.
pub async fn current_device_generation(
    state: &AppState,
    principal_id: &str,
) -> Result<Option<DeviceGenerationView>, ServiceError> {
    let principal_id =
        arkret_identifiers::DidCoreId::new(principal_id.to_owned()).map_err(|error| {
            ServiceError::SchemaViolation(format!("principal id is invalid: {error}"))
        })?;
    let station_id = arkret_identifiers::DidCoreId::new(state.service_id().clone())
        .map_err(|error| ServiceError::Internal(format!("local Station id is invalid: {error}")))?;
    let account = arkret_wire::AccountId::new(principal_id, station_id);
    Ok(state
        .persistence()
        .pcr_device_generation(&account)
        .await?
        .map(|generation| DeviceGenerationView {
            current_ref: generation.current_device_generation_ref,
        }))
}

fn generation_fenced(detail: &str) -> ServiceError {
    ServiceError::device_admission_refusal(
        arkret_wire::DeviceRevocationAdmissionDecision::GenerationMismatch,
        detail,
    )
    .unwrap_or_else(|| ServiceError::internal("generation mismatch must refuse"))
}

/// Resolve the exact accepted device authorization tuple used by every
/// revocation-sensitive durable write. The returned selector is derived from
/// accepted local state; it is never accepted from an authoring payload.
pub async fn active_device_revocation_gate_selector(
    state: &AppState,
    principal_id: &str,
    device_id: &str,
) -> Result<coland_storage::DeviceRevocationGateSelector, ServiceError> {
    let principal_id =
        arkret_identifiers::DidCoreId::new(principal_id.to_owned()).map_err(|error| {
            ServiceError::SchemaViolation(format!("principal id is invalid: {error}"))
        })?;
    let station_id = arkret_identifiers::DidCoreId::new(state.service_id().clone())
        .map_err(|error| ServiceError::Internal(format!("local Station id is invalid: {error}")))?;
    let device_id = arkret_identifiers::DeviceId::new(device_id.to_owned())
        .map_err(|error| ServiceError::SchemaViolation(format!("device id is invalid: {error}")))?;
    let account = arkret_wire::AccountId::new(principal_id.clone(), station_id.clone());
    // Every PCR read below selects the account's PCR through the replaceable
    // principal resolution index. Reading it through the store first rebuilds
    // an evicted row from the account's immutable creation anchor, so eviction
    // never turns into a device refusal.
    state
        .persistence()
        .principal_resolution_by_account_id(&account)
        .await?;
    let generation = current_device_generation(state, principal_id.as_str())
        .await?
        .ok_or_else(|| generation_fenced("device generation is not active"))?;
    let history = load_confirmed_device_history(state, &account)
        .await
        .map_err(|error| {
            ServiceError::Conflict(format!("confirmed device history unavailable: {error}"))
        })?;
    let history = history.ok_or_else(|| {
        ServiceError::Conflict("device authorization has no confirmed PCR history".into())
    })?;
    let authorization = history.current_authorization(&device_id).ok_or_else(|| {
        ServiceError::NotFound(
            "device authorization is not active at the accepted PCR head".to_owned(),
        )
    })?;
    let target_device_authorize_event_id = authorization.event_id().clone();
    let authorized_generation_ref = authorization.authorized_generation_ref();
    // The confirmed history names the authorization instance; whether that
    // device is still usable (not pending, revoked or fenced) is
    // the same-cut PCR device status, and nothing else.
    let admission = state
        .persistence()
        .pcr_device_admission(&account, &device_id, chrono::Utc::now())
        .await
        .map_err(|error| {
            ServiceError::Conflict(format!("PCR device status unavailable: {error}"))
        })?;
    if let Some(refusal) =
        ServiceError::device_admission_refusal(admission, "device is not active at the PCR cut")
    {
        return Err(refusal);
    }
    let target_device_generation_ref = generation.current_ref;
    if authorized_generation_ref != target_device_generation_ref {
        return Err(generation_fenced(
            "device authorization is outside the current generation",
        ));
    }
    let accepted = state
        .persistence()
        .committed_event(&target_device_authorize_event_id)
        .await?
        .ok_or_else(|| {
            ServiceError::Conflict("device authorization has no accepted RealmCommit".to_owned())
        })?;
    Ok(coland_storage::DeviceRevocationGateSelector {
        principal_id,
        station_id,
        device_id: device_id.to_string(),
        authorization_ref: arkret_wire::CommittedEventRef {
            event_id: target_device_authorize_event_id,
            commit_id: accepted.commit.commit_id,
            stream_ref: accepted.commit.stream_ref,
            stream_position: accepted.commit.stream_position,
        },
    })
}

pub(crate) fn verified_device_authorization_binding(
    device: &coland_services::identity::DeviceIdentity,
) -> Result<Option<(arkret_identifiers::EventId, u64)>, ServiceError> {
    if device.verification_state != "verified" || device.revoked_at.is_some() {
        return Ok(None);
    }
    let target_device_authorize_event_id = device
        .payload
        .get("device_authorize_event_id")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            ServiceError::SchemaViolation(
                "device authorization omits its accepted Event id".to_owned(),
            )
        })?;
    let target_device_authorize_event_id = arkret_identifiers::EventId::new(
        target_device_authorize_event_id.to_owned(),
    )
    .map_err(|error| {
        ServiceError::SchemaViolation(format!("device authorization Event id is invalid: {error}"))
    })?;
    let authorized_generation_ref = device
        .payload
        .get("authorized_generation_ref")
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            ServiceError::SchemaViolation(
                "device authorization omits its generation binding".to_owned(),
            )
        })?;
    Ok(Some((
        target_device_authorize_event_id,
        authorized_generation_ref,
    )))
}

/// Return the unique confirmed head. Pending competing commands cannot erase
/// or rewind an already authenticated prefix.
pub async fn accepted_device_generation_commit_head(
    state: &AppState,
    principal_id: &str,
    realm_id: &RealmId,
) -> Result<Option<arkret_wire::CommitStreamHead>, ServiceError> {
    let principal = arkret_identifiers::DidCoreId::new(principal_id.to_owned())
        .map_err(|error| ServiceError::SchemaViolation(error.to_string()))?;
    let account = arkret_wire::AccountId::new(principal, state.service_core_id().clone());
    let history = load_confirmed_device_history(state, &account)
        .await
        .map_err(|error| {
            ServiceError::Conflict(format!("confirmed device history unavailable: {error}"))
        })?;
    history
        .map(|history| {
            if history.realm_id() != realm_id {
                return Err(ServiceError::Conflict(
                    "device history belongs to another PCR".to_owned(),
                ));
            }
            Ok(history.confirmed_head().clone())
        })
        .transpose()
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use serde_json::json;

    use super::*;

    fn device(
        verification_state: &str,
        payload: Value,
    ) -> coland_services::identity::DeviceIdentity {
        coland_services::identity::DeviceIdentity {
            actor_id: "ak:did_core:webvh:z6mkfixture:alice.example".to_owned(),
            device_id: "ak:device:01904100-0000-7000-8000-000000000030".to_owned(),
            display_name: None,
            verification_state: verification_state.to_owned(),
            payload,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            revoked_at: None,
        }
    }

    #[test]
    fn absent_authorization_and_malformed_verified_projection_are_distinct() {
        assert_eq!(
            verified_device_authorization_binding(&device("unverified", json!({}))).unwrap(),
            None
        );

        let malformed = verified_device_authorization_binding(&device(
            "verified",
            json!({"authorized_generation_ref": 1}),
        ));
        assert!(matches!(malformed, Err(ServiceError::SchemaViolation(_))));

        let malformed = verified_device_authorization_binding(&device(
            "verified",
            json!({
                "device_authorize_event_id": "ak:event:ATyaOl1JkDDCC-6ZytsgoAKvlQJ6s6NJuDC_bmWKARBa"
            }),
        ));
        assert!(matches!(malformed, Err(ServiceError::SchemaViolation(_))));
    }

    /// The generation half of the same re-check: the projection's
    /// `authorized_generation_ref` is read back verbatim so the caller can
    /// compare it with the account's current active generation and reject an
    /// authorization that sits outside it.
    #[test]
    fn verified_projection_surfaces_the_authorized_generation_ref() {
        let binding = verified_device_authorization_binding(&device(
            "verified",
            json!({
                "device_authorize_event_id":
                    "ak:event:ATyaOl1JkDDCC-6ZytsgoAKvlQJ6s6NJuDC_bmWKARBa",
                "authorized_generation_ref": 3
            }),
        ))
        .expect("well-formed verified projection")
        .expect("verified device carries a binding");
        assert_eq!(binding.1, 3);
    }
}
