//! Same-Station device-pairing capability backed by the actual issuer ledger.

use arkret_models_collaboration::device_pairing::{
    DevicePairingBootstrap, DevicePairingResolveRequestBody, DevicePairingStageRequestBody,
    DevicePairingStageResponseBody, DevicePairingStatusRequestBody,
    DevicePairingStatusResponseBody,
};
use async_trait::async_trait;
use coland_contracts::account_authority::AccountAuthorityPairingError;

use super::AppState;
use crate::error::AppError;

/// Typed issuer boundary for the three registered public pairing operations.
/// The ingress owns parsing, rate limits and a fresh stage invocation key.
#[async_trait]
pub trait AccountAuthorityDevicePairingPort: Send + Sync {
    async fn stage(
        &self,
        state: &AppState,
        request: &DevicePairingStageRequestBody,
        idempotency_key: &str,
    ) -> Result<DevicePairingStageResponseBody, AppError>;
    async fn resolve(
        &self,
        state: &AppState,
        request: &DevicePairingResolveRequestBody,
    ) -> Result<DevicePairingBootstrap, AppError>;
    async fn status(
        &self,
        state: &AppState,
        request: &DevicePairingStatusRequestBody,
    ) -> Result<DevicePairingStatusResponseBody, AppError>;
}

#[derive(Debug, Default)]
pub(crate) struct LocalAccountAuthorityDevicePairing;

#[async_trait]
impl AccountAuthorityDevicePairingPort for LocalAccountAuthorityDevicePairing {
    async fn stage(
        &self,
        state: &AppState,
        request: &DevicePairingStageRequestBody,
        idempotency_key: &str,
    ) -> Result<DevicePairingStageResponseBody, AppError> {
        let authority = state
            .local_account_authority()
            .ok_or_else(|| pairing_error(AccountAuthorityPairingError::Unavailable))?;
        authority
            .stage_device_pairing(request.clone(), idempotency_key.to_owned())
            .await
            .map_err(pairing_error)
    }
    async fn resolve(
        &self,
        state: &AppState,
        request: &DevicePairingResolveRequestBody,
    ) -> Result<DevicePairingBootstrap, AppError> {
        let authority = state
            .local_account_authority()
            .ok_or_else(|| pairing_error(AccountAuthorityPairingError::Unavailable))?;
        authority
            .resolve_device_pairing(request.clone())
            .await
            .map_err(pairing_error)
    }
    async fn status(
        &self,
        state: &AppState,
        request: &DevicePairingStatusRequestBody,
    ) -> Result<DevicePairingStatusResponseBody, AppError> {
        let authority = state
            .local_account_authority()
            .ok_or_else(|| pairing_error(AccountAuthorityPairingError::Unavailable))?;
        authority
            .device_pairing_status(request.clone())
            .await
            .map_err(pairing_error)
    }
}

fn pairing_error(error: AccountAuthorityPairingError) -> AppError {
    match error {
        AccountAuthorityPairingError::NotFound => {
            AppError::not_found("device pairing request not found")
        }
        AccountAuthorityPairingError::DuplicateConflict => crate::app_error!(
            DuplicateConflict,
            "device pairing stage idempotency conflict"
        ),
        AccountAuthorityPairingError::Unavailable => crate::app_error!(
            TemporarilyUnavailable,
            "Account Authority device pairing is temporarily unavailable"
        ),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn pairing_adapter_has_no_private_http_transport_or_shadow_ledger() {
        let source = include_str!("account_authority_device_pairing.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap();
        assert!(source.contains("local_account_authority()"));
        for removed in [
            "/_coauth/",
            "reqwest",
            ".send()",
            "TRANSPORT_ATTEMPTS",
            "private_headers",
        ] {
            assert!(
                !source.contains(removed),
                "retired pairing transport: {removed}"
            );
        }
    }
}
