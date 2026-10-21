use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{PersistenceError, PersistenceResult};

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct DeviceRevocationGateSelector {
    pub principal_id: arkret_wire::DidCoreId,
    pub station_id: arkret_wire::DidCoreId,
    pub device_id: String,
    pub authorization_ref: arkret_wire::CommittedEventRef,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct DeviceRevocationTransition {
    pub selector: DeviceRevocationGateSelector,
    pub revoke_ref: arkret_wire::CommittedEventRef,
    pub committed_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum DeviceRevocationGateStatus {
    Active,
    Revoked {
        revoke_ref: arkret_wire::CommittedEventRef,
        committed_at: DateTime<Utc>,
    },
    AuthorityMismatch,
    GenerationMismatch,
}

impl DeviceRevocationGateStatus {
    /// The current-device admission decision this durable gate state denotes.
    #[must_use]
    pub const fn admission_decision(&self) -> arkret_wire::DeviceRevocationAdmissionDecision {
        use arkret_wire::DeviceRevocationAdmissionDecision as Decision;
        match self {
            Self::Active => Decision::Allow,
            Self::Revoked { .. } => Decision::Revoked,
            Self::AuthorityMismatch => Decision::AuthorityMismatch,
            Self::GenerationMismatch => Decision::GenerationMismatch,
        }
    }

    /// Refuse anything but an admitted device with the SDK's registered code.
    pub fn ensure_allowed(&self) -> PersistenceResult<()> {
        match self.admission_decision().error_code() {
            None => Ok(()),
            Some(code) => Err(PersistenceError::Conflict(format!(
                "{}: device revocation gate does not admit the exact device generation",
                code.as_str()
            ))),
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct DeviceRevocationTargetRecord {
    pub selector: DeviceRevocationGateSelector,
    pub revoke_ref: arkret_wire::CommittedEventRef,
    pub committed_at: DateTime<Utc>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeviceRevocationTransitionDecision {
    Insert,
    Duplicate,
}

pub fn classify_device_revocation_transition(
    transition: &DeviceRevocationTransition,
    existing: Option<&DeviceRevocationTargetRecord>,
) -> PersistenceResult<DeviceRevocationTransitionDecision> {
    match existing {
        None => Ok(DeviceRevocationTransitionDecision::Insert),
        Some(existing)
            if existing.selector == transition.selector
                && existing.revoke_ref == transition.revoke_ref =>
        {
            Ok(DeviceRevocationTransitionDecision::Duplicate)
        }
        Some(_) => Err(PersistenceError::Conflict(
            "duplicate_conflict: device revocation target differs".to_owned(),
        )),
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DeviceRevocationGateLinearizationRequest {
    pub principal_id: arkret_wire::DidCoreId,
    pub station_id: arkret_wire::DidCoreId,
    pub device_id: String,
    pub expected_authorization_ref: Option<arkret_wire::CommittedEventRef>,
    /// Receiver-derived current binding; never populated from peer bytes.
    pub origin_current_selector: Option<DeviceRevocationGateSelector>,
    pub action_class: arkret_wire::DeviceRevocationDeniedAction,
    pub intent_digest: String,
    pub requested_at: DateTime<Utc>,
}

#[must_use]
pub fn selector_comparison_status(
    request: &DeviceRevocationGateLinearizationRequest,
    current: Option<&DeviceRevocationGateSelector>,
) -> Option<DeviceRevocationGateStatus> {
    let Some(current) = current else {
        return Some(DeviceRevocationGateStatus::AuthorityMismatch);
    };
    if request.principal_id != current.principal_id
        || request.station_id != current.station_id
        || request.device_id != current.device_id
    {
        return Some(DeviceRevocationGateStatus::AuthorityMismatch);
    }
    if request.expected_authorization_ref.as_ref() != Some(&current.authorization_ref) {
        return Some(DeviceRevocationGateStatus::GenerationMismatch);
    }
    None
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DeviceRevocationGateLinearization {
    pub request: DeviceRevocationGateLinearizationRequest,
    pub status: DeviceRevocationGateStatus,
    pub linearization_seq: u64,
    pub linearized_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DeviceRevocationCleanupIntent {
    pub revoke_ref: arkret_wire::CommittedEventRef,
    pub selector: DeviceRevocationGateSelector,
    pub created_at: DateTime<Utc>,
    pub material_cleanup_completed_at: Option<DateTime<Utc>>,
    pub mls_obligation_completed_at: Option<DateTime<Utc>>,
}

/// The PCR `device_generation` typed current (device-lifecycle.md §5.5.4)
/// read at one confirmed cut.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PcrDeviceGeneration {
    pub current_device_generation_ref: u64,
}

/// Receiver-derived identity at one accepted RealmActor private control cut.
/// This is transport authority, not permission to act on any business resource. Consumers must
/// still check the actual resource scope and all current business gates.
#[derive(Clone, Debug, PartialEq)]
pub struct AppletManagedDeviceAuthority {
    pub actor_id: arkret_wire::ActorId,
    pub device_id: arkret_wire::DeviceId,
    pub authorization_ref: arkret_wire::CommittedEventRef,
    pub applet_id: arkret_wire::AppletId,
    pub source_service_id: arkret_wire::DidCoreId,
    pub native_did: arkret_wire::Did,
    pub realm_id: arkret_wire::RealmId,
    pub current_device_generation_ref: u64,
    pub public_key: [u8; 32],
    pub scopes: arkret_models_collaboration::events_payloads::AppletManagedDeviceScopes,
    pub not_before: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub governance_service_id: arkret_wire::DidCoreId,
    pub governance_generation: u64,
}

#[async_trait]
pub trait DeviceRevocationStore: Send + Sync {
    /// Verify the original Event against one accepted managed Device cut.
    /// `None` identifies a different producer branch, never a successful proof.
    /// This selects signer identity only; it grants no business permission.
    async fn applet_managed_event_producer(
        &self,
        _event: &arkret_wire::Event,
        _now: DateTime<Utc>,
    ) -> PersistenceResult<Option<AppletManagedDeviceAuthority>> {
        Err(PersistenceError::SchemaViolation(
            "managed Device Event producer provider is unavailable".to_owned(),
        ))
    }

    /// After cryptographic verification, re-read the exact Device instance
    /// under its RealmControl writer lock and durably consume the HTTP nonce.
    /// This does not consume business approvals or grant permission to a resource.
    async fn consume_applet_managed_device_nonce(
        &self,
        _expected: &AppletManagedDeviceAuthority,
        _metadata: &arkret_models_integration::AppletManagedDeviceMetadata,
        _retain_until: DateTime<Utc>,
    ) -> PersistenceResult<AppletManagedDeviceAuthority> {
        Err(PersistenceError::SchemaViolation(
            "managed Device nonce provider is unavailable".to_owned(),
        ))
    }

    /// Return only a currently active, accepted managed Device. Ordinary
    /// Devices and absent authorizations return `None`; incomplete authority
    /// and known inactive devices fail closed. No Human Account row is needed.
    async fn applet_managed_device_authority(
        &self,
        _actor: &arkret_wire::ActorId,
        _device_id: &arkret_wire::DeviceId,
        _now: DateTime<Utc>,
    ) -> PersistenceResult<Option<AppletManagedDeviceAuthority>> {
        Err(PersistenceError::SchemaViolation(
            "managed Device authority provider is unavailable".to_owned(),
        ))
    }

    /// The accepted `device_generation` of the Account's PCR at one confirmed
    /// cut whose projection matches its latest writer Commit. `None` when this
    /// Station holds no PCR for the Account.
    async fn pcr_device_generation(
        &self,
        _account: &arkret_wire::AccountId,
    ) -> PersistenceResult<Option<PcrDeviceGeneration>> {
        Err(PersistenceError::SchemaViolation(
            "PCR device generation provider is unavailable".to_owned(),
        ))
    }

    /// Authoritative PCR human-device admission at `now`, folded from one
    /// confirmed cut of the accepted `device_authorization`,
    /// `device_generation` and revoke proposals. Missing or
    /// incomplete typed current is an error, never an implicit active device.
    async fn pcr_device_admission(
        &self,
        _account: &arkret_wire::AccountId,
        _device_id: &arkret_wire::DeviceId,
        _now: DateTime<Utc>,
    ) -> PersistenceResult<arkret_wire::DeviceRevocationAdmissionDecision> {
        Err(PersistenceError::SchemaViolation(
            "PCR device status provider is unavailable".to_owned(),
        ))
    }

    /// Signing key of the latest accepted `device_authorization` of a device
    /// whose Account this Station hosts, read from one confirmed PCR cut whose
    /// `device_authorization`/`device_generation` projections match their
    /// accepted Commits. `None` when this Station holds no PCR for the Account
    /// or no authorization for the device.
    async fn pcr_device_authorization_key(
        &self,
        _account: &arkret_wire::AccountId,
        _device_id: &arkret_wire::DeviceId,
    ) -> PersistenceResult<Option<arkret_wire::DidKey>> {
        Err(PersistenceError::SchemaViolation(
            "PCR device authorization provider is unavailable".to_owned(),
        ))
    }

    async fn gate_status(
        &self,
        selector: &DeviceRevocationGateSelector,
    ) -> PersistenceResult<DeviceRevocationGateStatus>;

    async fn list_targets(
        &self,
        selector: &DeviceRevocationGateSelector,
    ) -> PersistenceResult<Vec<DeviceRevocationTargetRecord>>;

    async fn target_for_event(
        &self,
        event_id: &arkret_wire::EventId,
    ) -> PersistenceResult<Option<DeviceRevocationTargetRecord>>;

    async fn linearize_gate(
        &self,
        request: DeviceRevocationGateLinearizationRequest,
    ) -> PersistenceResult<DeviceRevocationGateLinearization>;

    /// Installs the revocation projection only after the authority's commit is
    /// durable. Exact retries are idempotent.
    async fn commit_revocation(
        &self,
        transition: &DeviceRevocationTransition,
    ) -> PersistenceResult<DeviceRevocationTransitionDecision>;

    async fn pending_cleanup_intents(
        &self,
        limit: usize,
    ) -> PersistenceResult<Vec<DeviceRevocationCleanupIntent>>;

    async fn complete_material_cleanup(
        &self,
        event_id: &arkret_wire::EventId,
        completed_at: DateTime<Utc>,
    ) -> PersistenceResult<bool>;

    async fn complete_mls_obligation(
        &self,
        event_id: &arkret_wire::EventId,
        completed_at: DateTime<Utc>,
    ) -> PersistenceResult<bool>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_current_selector_fails_closed() {
        let request = DeviceRevocationGateLinearizationRequest {
            principal_id: arkret_wire::DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
            station_id: arkret_wire::DidCoreId::new("ak:did_core:web:station.example").unwrap(),
            device_id: "device-a".to_owned(),
            expected_authorization_ref: None,
            origin_current_selector: None,
            action_class: arkret_wire::DeviceRevocationDeniedAction::EventWrite,
            intent_digest: "sha256:test".to_owned(),
            requested_at: Utc::now(),
        };
        assert_eq!(
            selector_comparison_status(&request, None),
            Some(DeviceRevocationGateStatus::AuthorityMismatch)
        );
    }
}
