//! Device possession, directory, and recovery-policy verification helpers.

use arkret_identifiers::EventId;
use arkret_models_collaboration::events_payloads::device_identity::DeviceAuthorizePayload;
use arkret_models_crypto::DeviceStatus;
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use coland_services::identity::{FindDeviceQuery, RecoveryPolicyState};
use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};

use crate::state::AppState;

pub(crate) fn policy_device_quorum_threshold(policy: &RecoveryPolicyState) -> Option<u32> {
    let policy: arkret_models_crypto::RecoveryPolicy =
        serde_json::from_value(policy.raw_payload.clone()).ok()?;
    policy.validate_shape().ok()?;
    policy.methods.iter().find_map(|method| match method {
        arkret_models_crypto::RecoveryMethod::DeviceQuorum { k, .. } => Some(*k),
        _ => None,
    })
}

pub fn validate_device_authorize_binding(
    _state: &AppState,
    payload: &DeviceAuthorizePayload,
    subject_account_id: &arkret_wire::AccountId,
) -> Result<(), &'static str> {
    arkret_signatures::verify_device_authorize_possession(payload, subject_account_id)
        .map_err(|_| "device_authorize_device_signature_invalid")
}

pub(crate) struct DeviceSigningDirectoryFacet {
    pub signing_key_did: Option<String>,
    pub hpke_key: Option<String>,
    pub trust_algorithms: Option<Vec<String>>,
    pub status: DeviceStatus,
    pub device_authorize_event_id: Option<EventId>,
    pub authorized_generation_ref: Option<u64>,
}

/// Resolve the exact current accepted authorization, not merely an Active
/// directory label. Consumers must not extend this authority with a session
/// lifetime, a cached directory result, or a newly issued attestation TTL.
pub(crate) async fn current_device_authorization(
    state: &AppState,
    actor: &arkret_wire::ActorId,
    device_id: &arkret_wire::DeviceId,
    facet: &DeviceSigningDirectoryFacet,
) -> Result<Option<DeviceAuthorizePayload>, coland_services::ServiceError> {
    if !actor
        .as_account_id()
        .is_some_and(|account| account.station_id.as_str() == state.service_id())
        || facet.status != DeviceStatus::Active
    {
        return Ok(None);
    }
    let (Some(event_id), Some(generation)) = (
        facet.device_authorize_event_id.as_ref(),
        facet
            .authorized_generation_ref
            .filter(|generation| *generation >= 1),
    ) else {
        return Ok(None);
    };
    let Some(event) = state
        .event_queries()
        .canonical_event(event_id.as_str())
        .await
        .map_err(|error| coland_services::ServiceError::internal(error.to_string()))?
    else {
        return Ok(None);
    };
    let Some(payload) = event.envelope.get("payload") else {
        return Ok(None);
    };
    let Ok(authorization) = serde_json::from_value::<DeviceAuthorizePayload>(payload.clone())
    else {
        return Ok(None);
    };
    if event.actor_id != actor.to_string() || authorization.device_id != *device_id {
        return Ok(None);
    }
    // Resolve all authority material before the final current-state gate;
    // no unrelated asynchronous lookup may extend its freshness window.
    let Ok(selector) = super::device_generation::active_device_revocation_gate_selector(
        state,
        actor.signing_principal_id().as_str(),
        device_id.as_str(),
    )
    .await
    else {
        return Ok(None);
    };
    let revocation_gate_active = state
        .persistence()
        .device_revocation_gate_status(&selector)
        .await?
        == coland_storage::DeviceRevocationGateStatus::Active;
    let authorization_binding_kind = match authorization.authorization_binding_kind {
        arkret_models_collaboration::events_payloads::device_identity::DeviceAuthorizationBindingKind::RegistrationAnchor => "registration_anchor",
        arkret_models_collaboration::events_payloads::device_identity::DeviceAuthorizationBindingKind::AcceptedDevice => "accepted_device",
        arkret_models_collaboration::events_payloads::device_identity::DeviceAuthorizationBindingKind::PcrRecovery => "pcr_recovery",
        arkret_models_collaboration::events_payloads::device_identity::DeviceAuthorizationBindingKind::AppletManagedDelegation => "applet_managed_delegation",
    };
    let (verification_state, verification_source) =
        coland_services::identity::fold_device_verification_checkpoint(
            "verified",
            true,
            Some(authorization_binding_kind),
            false,
        );
    if coland_services::identity::evaluate_device_checkpoint_live_eligibility(
        coland_services::identity::DeviceCheckpointLiveFacts {
            lifecycle_active: facet.status == DeviceStatus::Active,
            verification_state,
            verification_source,
            revocation_gate_active,
            checkpoint_authorization_event_id: Some(event_id.as_str()),
            current_authorization_event_id: Some(selector.authorization_ref.event_id.as_str()),
            checkpoint_generation_ref: Some(generation),
            // `active_device_revocation_gate_selector` has already compared
            // this durable authorization generation with the current PCR
            // generation and returns no selector on a fence.
            current_generation_ref: Some(generation),
            checkpoint_signing_key: Some(authorization.device_public_key_did.as_str()),
            current_signing_key: facet.signing_key_did.as_deref(),
            checkpoint_hpke_key: Some(authorization.hpke_key.as_str()),
            current_hpke_key: facet.hpke_key.as_deref(),
        },
    )
    .is_err()
        || !device_authorization_is_effective_at(&authorization, chrono::Utc::now())
    {
        return Ok(None);
    }
    Ok(Some(authorization))
}

pub(crate) fn device_authorization_is_effective_at(
    authorization: &DeviceAuthorizePayload,
    at: chrono::DateTime<chrono::Utc>,
) -> bool {
    authorization.not_before <= at
        && authorization
            .expires_at
            .flatten()
            .is_none_or(|expiry| at < expiry)
}

#[derive(Debug, Default, serde::Deserialize)]
pub(crate) struct ProjectedDevicePayload {
    #[serde(default)]
    pub device_public_key_did: Option<String>,
    #[serde(default)]
    pub hpke_key: Option<String>,
    #[serde(default)]
    pub algorithms: Option<Vec<String>>,
    #[serde(default)]
    pub device_authorize_event_id: Option<String>,
    #[serde(default)]
    pub authorized_generation_ref: Option<u64>,
}

pub(crate) async fn resolve_device_signing_directory_facet(
    state: &AppState,
    principal_id: &str,
    device_id: &str,
) -> DeviceSigningDirectoryFacet {
    try_resolve_device_signing_directory_facet(state, principal_id, device_id)
        .await
        .unwrap_or_else(|error| {
            tracing::error!(%error, %principal_id, %device_id, "failed to resolve device signing directory facet");
            revoked_device_signing_directory_facet()
        })
}

pub(crate) async fn try_resolve_device_signing_directory_facet(
    state: &AppState,
    principal_id: &str,
    device_id: &str,
) -> Result<DeviceSigningDirectoryFacet, coland_services::ServiceError> {
    let record = match state
        .identities()
        .find_device(FindDeviceQuery {
            actor_id: principal_id.to_owned(),
            device_id: device_id.to_owned(),
        })
        .await?
    {
        Some(record) => record,
        None => return Ok(revoked_device_signing_directory_facet()),
    };
    if record.revoked_at.is_some() || record.verification_state != "verified" {
        return Ok(revoked_device_signing_directory_facet());
    }
    let payload: ProjectedDevicePayload =
        serde_json::from_value(record.payload.clone()).unwrap_or_default();
    let generation =
        crate::routing::identity::device_generation::current_device_generation(state, principal_id)
            .await?;
    let generation_usable = match generation {
        Some(generation) => payload.authorized_generation_ref == Some(generation.current_ref),
        None => payload.authorized_generation_ref.is_none(),
    };
    if !generation_usable {
        return Ok(DeviceSigningDirectoryFacet {
            authorized_generation_ref: payload.authorized_generation_ref,
            ..revoked_device_signing_directory_facet()
        });
    }
    let signing_key_did = payload
        .device_public_key_did
        .as_deref()
        .map(str::trim)
        .filter(|value| value.starts_with("did:key:"))
        .filter(|value| decode_ed25519_key(value, "multibase").is_ok())
        .map(ToOwned::to_owned);
    let hpke_key = payload
        .hpke_key
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned);
    let trust_algorithms = payload.algorithms.filter(|values| !values.is_empty());
    let device_authorize_event_id = payload
        .device_authorize_event_id
        .and_then(|value| EventId::new(value).ok());
    Ok(DeviceSigningDirectoryFacet {
        signing_key_did,
        hpke_key,
        trust_algorithms,
        status: DeviceStatus::Active,
        device_authorize_event_id,
        authorized_generation_ref: payload.authorized_generation_ref,
    })
}

fn revoked_device_signing_directory_facet() -> DeviceSigningDirectoryFacet {
    DeviceSigningDirectoryFacet {
        signing_key_did: None,
        hpke_key: None,
        trust_algorithms: None,
        status: DeviceStatus::Revoked,
        device_authorize_event_id: None,
        authorized_generation_ref: None,
    }
}

pub(crate) fn decode_ed25519_key(material: &str, key_format: &str) -> Result<VerifyingKey, String> {
    let material = material.strip_prefix("did:key:").unwrap_or(material);
    let raw: Vec<u8> = match key_format {
        "multibase" => arkret_canonical::decode_ed25519_multibase(material)
            .map(|bytes| bytes.to_vec())
            .map_err(|error| error.to_string())?,
        "raw_base64url" => URL_SAFE_NO_PAD
            .decode(material.as_bytes())
            .or_else(|_| STANDARD.decode(material.as_bytes()))
            .map_err(|error| format!("base64 decode: {error}"))?,
        other => return Err(format!("unsupported key_format `{other}`")),
    };
    let bytes: [u8; 32] = raw
        .as_slice()
        .try_into()
        .map_err(|_| "Ed25519 public key must be 32 bytes".to_owned())?;
    VerifyingKey::from_bytes(&bytes).map_err(|error| format!("invalid Ed25519 public key: {error}"))
}

pub(crate) fn ed25519_verify(key: &VerifyingKey, message: &[u8], signature_b64: &str) -> bool {
    let Ok(raw) = URL_SAFE_NO_PAD
        .decode(signature_b64.as_bytes())
        .or_else(|_| STANDARD.decode(signature_b64.as_bytes()))
    else {
        return false;
    };
    let Ok(signature) = Signature::from_slice(&raw) else {
        return false;
    };
    key.verify(message, &signature).is_ok()
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn device_authorization_time_window_has_exact_inclusive_start_and_exclusive_expiry() {
        let start = chrono::DateTime::parse_from_rfc3339("2026-09-01T00:00:00.000Z")
            .unwrap()
            .to_utc();
        let mut authorization: DeviceAuthorizePayload = serde_json::from_value(json!({
            "device_id": "ak:device:01904100-0000-7000-8000-a11ce0000001",
            "device_public_key_did": "did:key:z6MkFixture",
            "hpke_key": "z6LSFixture",
            "algorithms": ["ak.mls.v1"],
            "device_key_algorithm": "Ed25519",
            "authorized_by": "ak:did_core:web:alice.example",
            "authorized_generation_ref": 1,
            "not_before": "2026-09-01T00:00:00.000Z",
            "authorization_binding_kind": "registration_anchor",
            "device_signature": "c2ln"
        }))
        .unwrap();
        assert!(!device_authorization_is_effective_at(
            &authorization,
            start - chrono::Duration::milliseconds(1)
        ));
        assert!(device_authorization_is_effective_at(&authorization, start));
        assert!(device_authorization_is_effective_at(
            &authorization,
            start + chrono::Duration::days(1)
        ));
        authorization.expires_at = Some(None);
        assert!(device_authorization_is_effective_at(&authorization, start));
        let expiry = start + chrono::Duration::seconds(1);
        authorization.expires_at = Some(Some(expiry));
        assert!(device_authorization_is_effective_at(
            &authorization,
            expiry - chrono::Duration::milliseconds(1)
        ));
        assert!(!device_authorization_is_effective_at(
            &authorization,
            expiry
        ));
        assert!(!device_authorization_is_effective_at(
            &authorization,
            expiry + chrono::Duration::milliseconds(1)
        ));
    }
}
