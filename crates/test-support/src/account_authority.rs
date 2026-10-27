//! Component-only issuer doubles. These do not establish native contract coverage.

use std::sync::{Arc, Mutex};

use arkret_models_collaboration::session_grants::{
    AuthenticationSessionTerminationInput, AuthenticationSessionTerminationResponseBody,
    SessionGrantValidationInput, SessionGrantValidationResponseBody,
};
use arkret_models_identity::agent_signer_evidence::{
    ControllerAccountGateAttestationIssueResponseBody, ControllerAccountGateIssuanceInput,
};
use arkret_wire::DidCoreId;
pub use coland_contracts::account_authority::AccountAuthorityUnavailable;
use coland_contracts::account_authority::{AccountAuthorityCall, LocalAccountAuthority};

pub struct ComponentAccountAuthority {
    station_id: DidCoreId,
    namespace: String,
    validate: Box<
        dyn Fn(
                SessionGrantValidationInput,
            )
                -> Result<SessionGrantValidationResponseBody, AccountAuthorityUnavailable>
            + Send
            + Sync,
    >,
}

impl ComponentAccountAuthority {
    pub fn new(
        station_id: DidCoreId,
        validate: impl Fn(
            SessionGrantValidationInput,
        )
            -> Result<SessionGrantValidationResponseBody, AccountAuthorityUnavailable>
        + Send
        + Sync
        + 'static,
    ) -> Arc<Self> {
        Arc::new(Self {
            station_id,
            namespace: uuid::Uuid::now_v7().to_string(),
            validate: Box::new(validate),
        })
    }

    pub fn from_json_slot(station_id: DidCoreId, slot: Arc<Mutex<serde_json::Value>>) -> Arc<Self> {
        Self::new(station_id, move |_| {
            serde_json::from_value(
                slot.lock()
                    .map_err(|_| AccountAuthorityUnavailable)?
                    .clone(),
            )
            .map_err(|_| AccountAuthorityUnavailable)
        })
    }
}

impl LocalAccountAuthority for ComponentAccountAuthority {
    fn stage_device_pairing(
        &self,
        _: arkret_models_collaboration::device_pairing::DevicePairingStageRequestBody,
        _: String,
    ) -> coland_contracts::account_authority::AccountAuthorityCall<
        '_,
        arkret_models_collaboration::device_pairing::DevicePairingStageResponseBody,
        coland_contracts::account_authority::AccountAuthorityPairingError,
    > {
        Box::pin(async {
            Err(coland_contracts::account_authority::AccountAuthorityPairingError::Unavailable)
        })
    }
    fn resolve_device_pairing(
        &self,
        _: arkret_models_collaboration::device_pairing::DevicePairingResolveRequestBody,
    ) -> coland_contracts::account_authority::AccountAuthorityCall<
        '_,
        arkret_models_collaboration::device_pairing::DevicePairingBootstrap,
        coland_contracts::account_authority::AccountAuthorityPairingError,
    > {
        Box::pin(async {
            Err(coland_contracts::account_authority::AccountAuthorityPairingError::Unavailable)
        })
    }
    fn device_pairing_status(
        &self,
        _: arkret_models_collaboration::device_pairing::DevicePairingStatusRequestBody,
    ) -> coland_contracts::account_authority::AccountAuthorityCall<
        '_,
        arkret_models_collaboration::device_pairing::DevicePairingStatusResponseBody,
        coland_contracts::account_authority::AccountAuthorityPairingError,
    > {
        Box::pin(async {
            Err(coland_contracts::account_authority::AccountAuthorityPairingError::Unavailable)
        })
    }

    fn station_id(&self) -> &DidCoreId {
        &self.station_id
    }
    fn cache_namespace(&self) -> &str {
        &self.namespace
    }

    fn validate_session_grant(
        &self,
        input: SessionGrantValidationInput,
    ) -> AccountAuthorityCall<'_, SessionGrantValidationResponseBody> {
        Box::pin(async move { (self.validate)(input) })
    }

    fn terminate_authentication_session(
        &self,
        _: AuthenticationSessionTerminationInput,
    ) -> AccountAuthorityCall<'_, AuthenticationSessionTerminationResponseBody> {
        Box::pin(async { Err(AccountAuthorityUnavailable) })
    }

    fn issue_controller_gate(
        &self,
        _: ControllerAccountGateIssuanceInput,
    ) -> AccountAuthorityCall<'_, ControllerAccountGateAttestationIssueResponseBody> {
        Box::pin(async { Err(AccountAuthorityUnavailable) })
    }
}
