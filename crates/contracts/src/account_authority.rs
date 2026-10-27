//! Same-Station issuer capability. This is not an HTTP or protocol surface.

use std::future::Future;
use std::pin::Pin;

use arkret_models_collaboration::session_grants::{
    AuthenticationSessionTerminationInput, AuthenticationSessionTerminationResponseBody,
    SessionGrantValidationInput, SessionGrantValidationResponseBody,
};
use arkret_models_identity::agent_signer_evidence::{
    ControllerAccountGateAttestationIssueResponseBody, ControllerAccountGateIssuanceInput,
};
use arkret_wire::DidCoreId;

/// An unavailable issuer never grants authority or exposes private repository errors.
#[derive(Clone, Copy, Debug)]
pub struct AccountAuthorityUnavailable;

impl std::fmt::Display for AccountAuthorityUnavailable {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("the configured local Account Authority is unavailable")
    }
}

impl std::error::Error for AccountAuthorityUnavailable {}

pub type AccountAuthorityCall<'a, T, E = AccountAuthorityUnavailable> =
    Pin<Box<dyn Future<Output = Result<T, E>> + Send + 'a>>;

/// Only public pairing failures cross the same-Station capability boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AccountAuthorityPairingError {
    Unavailable,
    NotFound,
    DuplicateConflict,
}

/// Implemented by the actual issuer repository owner and injected at startup.
/// It must preserve issuer-ledger and live Agent authority checks; a JWT-only
/// projection or a copied Station session table cannot implement this contract.
pub trait LocalAccountAuthority: Send + Sync {
    fn station_id(&self) -> &DidCoreId;

    /// A process-unique capability instance identifier, never a token or database URL.
    fn cache_namespace(&self) -> &str;

    fn validate_session_grant(
        &self,
        input: SessionGrantValidationInput,
    ) -> AccountAuthorityCall<'_, SessionGrantValidationResponseBody>;

    fn terminate_authentication_session(
        &self,
        input: AuthenticationSessionTerminationInput,
    ) -> AccountAuthorityCall<'_, AuthenticationSessionTerminationResponseBody>;

    fn issue_controller_gate(
        &self,
        input: ControllerAccountGateIssuanceInput,
    ) -> AccountAuthorityCall<'_, ControllerAccountGateAttestationIssueResponseBody>;

    fn stage_device_pairing(
        &self,
        request: arkret_models_collaboration::device_pairing::DevicePairingStageRequestBody,
        idempotency_key: String,
    ) -> AccountAuthorityCall<
        '_,
        arkret_models_collaboration::device_pairing::DevicePairingStageResponseBody,
        AccountAuthorityPairingError,
    >;

    fn resolve_device_pairing(
        &self,
        request: arkret_models_collaboration::device_pairing::DevicePairingResolveRequestBody,
    ) -> AccountAuthorityCall<
        '_,
        arkret_models_collaboration::device_pairing::DevicePairingBootstrap,
        AccountAuthorityPairingError,
    >;

    fn device_pairing_status(
        &self,
        request: arkret_models_collaboration::device_pairing::DevicePairingStatusRequestBody,
    ) -> AccountAuthorityCall<
        '_,
        arkret_models_collaboration::device_pairing::DevicePairingStatusResponseBody,
        AccountAuthorityPairingError,
    >;
}
