use std::time::Duration;

use arkret_models_collaboration::device_pairing::{
    DevicePairingBootstrap, DevicePairingResolveRequestBody, DevicePairingStageRequestBody,
    DevicePairingStageResponseBody, DevicePairingStatusRequestBody,
    DevicePairingStatusResponseBody,
};
use async_trait::async_trait;
use reqwest::StatusCode;
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE, HeaderMap, HeaderValue};

use super::AppState;
use crate::error::AppError;

const STAGE_PATH: &str = "/_coauth/internal/device-pairing/stages";
const RESOLVE_PATH: &str = "/_coauth/internal/device-pairing/resolutions";
const STATUS_PATH: &str = "/_coauth/internal/device-pairing/status-queries";
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
/// One initial send plus one retry when no HTTP response was received.
const TRANSPORT_ATTEMPTS: usize = 2;

/// Typed Station -> Account Authority boundary for the three public
/// device-pairing handoff operations.
///
/// The public handlers own request parsing, their public rate bucket, and the
/// fresh stage idempotency key. The production implementation owns the private
/// shared-secret transport and transport retry. Every retry of one [`Self::stage`]
/// call reuses the supplied key; a later public ingress receives a different key
/// from the handler.
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

/// Production Station -> Account Authority private TCB transport.
///
/// This client authenticates only with the deployment's registered shared
/// secret. It emits no Arkret operation selector, Content-Digest, RFC 9421
/// signature, or source/destination identity headers.
#[derive(Debug, Default)]
pub(crate) struct PrivateAccountAuthorityDevicePairing;

#[async_trait]
impl AccountAuthorityDevicePairingPort for PrivateAccountAuthorityDevicePairing {
    async fn stage(
        &self,
        state: &AppState,
        request: &DevicePairingStageRequestBody,
        idempotency_key: &str,
    ) -> Result<DevicePairingStageResponseBody, AppError> {
        post_json(
            state,
            STAGE_PATH,
            "device pairing stage",
            request,
            Some(idempotency_key),
        )
        .await
    }

    async fn resolve(
        &self,
        state: &AppState,
        request: &DevicePairingResolveRequestBody,
    ) -> Result<DevicePairingBootstrap, AppError> {
        post_json(state, RESOLVE_PATH, "device pairing resolve", request, None).await
    }

    async fn status(
        &self,
        state: &AppState,
        request: &DevicePairingStatusRequestBody,
    ) -> Result<DevicePairingStatusResponseBody, AppError> {
        post_json(state, STATUS_PATH, "device pairing status", request, None).await
    }
}

async fn post_json<Request, Response>(
    state: &AppState,
    path: &str,
    operation: &str,
    request: &Request,
    idempotency_key: Option<&str>,
) -> Result<Response, AppError>
where
    Request: serde::Serialize + ?Sized,
    Response: serde::de::DeserializeOwned,
{
    let target = account_authority_target(state, path)?;
    let (target_url, client) = crate::security::validate_http_url_for_egress_with_pinned_client(
        &target,
        operation,
        state.config().development_mode,
        REQUEST_TIMEOUT,
    )
    .map_err(|error| unavailable(operation, error))?;
    let body = arkret_canonical::canonical_json_bytes(request)
        .map_err(|error| unavailable(operation, format!("canonical request failed: {error}")))?;

    for attempt in 0..TRANSPORT_ATTEMPTS {
        let headers = private_headers(state, idempotency_key)?;
        match client
            .post(target_url.clone())
            .headers(headers)
            .body(body.clone())
            .send()
            .await
        {
            Ok(response) => return decode_response(response, operation).await,
            Err(error) if attempt + 1 < TRANSPORT_ATTEMPTS => {
                tracing::warn!(%error, %operation, "retrying Account Authority request after transport failure");
            }
            Err(error) => return Err(unavailable(operation, error.to_string())),
        }
    }
    unreachable!("the bounded transport loop returns on its final attempt")
}

fn account_authority_target(state: &AppState, path: &str) -> Result<String, AppError> {
    let base = state
        .config()
        .account_authority_url
        .as_deref()
        .ok_or_else(|| unavailable("device pairing", "Account Authority URL is not configured"))?;
    state
        .config()
        .account_authority_trust_domain
        .as_ref()
        .ok_or_else(|| {
            unavailable(
                "device pairing",
                "Account Authority trust domain is not configured",
            )
        })?;

    let mut target = url::Url::parse(base).map_err(|error| {
        unavailable("device pairing", format!("invalid authority URL: {error}"))
    })?;
    target.set_path(path);
    target.set_query(None);
    target.set_fragment(None);
    Ok(target.into())
}

fn private_headers(state: &AppState, idempotency_key: Option<&str>) -> Result<HeaderMap, AppError> {
    let credential = state
        .config()
        .internal_authority_shared_secret
        .as_deref()
        .ok_or_else(|| {
            unavailable(
                "device pairing",
                "private authority channel is not configured",
            )
        })?;
    private_headers_with_credential(credential, idempotency_key)
}

fn private_headers_with_credential(
    credential: &str,
    idempotency_key: Option<&str>,
) -> Result<HeaderMap, AppError> {
    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    insert_header(
        &mut headers,
        AUTHORIZATION.as_str(),
        &format!("Bearer {credential}"),
    )?;
    if let Some(idempotency_key) = idempotency_key {
        insert_header(&mut headers, "idempotency-key", idempotency_key)?;
    }
    Ok(headers)
}

fn insert_header(headers: &mut HeaderMap, name: &'static str, value: &str) -> Result<(), AppError> {
    let value = HeaderValue::from_str(value)
        .map_err(|error| unavailable("device pairing", format!("invalid {name}: {error}")))?;
    headers.insert(name, value);
    Ok(())
}

async fn decode_response<Response>(
    response: reqwest::Response,
    operation: &str,
) -> Result<Response, AppError>
where
    Response: serde::de::DeserializeOwned,
{
    let status = response.status();
    let body = response
        .bytes()
        .await
        .map_err(|error| unavailable(operation, format!("response read failed: {error}")))?;
    if status.is_success() {
        return serde_json::from_slice(&body)
            .map_err(|error| unavailable(operation, format!("invalid response: {error}")));
    }

    // Only protocol failures that belong to the public pairing contract cross
    // the process boundary. Signature/configuration/topology failures collapse
    // to temporarily_unavailable rather than exposing the internal split.
    let remote_code = serde_json::from_slice::<arkret_wire::problem_details::Problem>(&body)
        .ok()
        .and_then(|problem| problem.error_code());
    if status == StatusCode::NOT_FOUND
        && remote_code.is_none_or(|code| code == arkret_wire::ErrorCode::NotFound)
    {
        return Err(AppError::not_found("device pairing request not found"));
    }
    if status == StatusCode::CONFLICT
        && remote_code == Some(arkret_wire::ErrorCode::DuplicateConflict)
    {
        return Err(crate::app_error!(
            DuplicateConflict,
            "device pairing stage idempotency conflict",
        ));
    }
    Err(unavailable(
        operation,
        format!("Account Authority returned HTTP {status}"),
    ))
}

fn unavailable(operation: &str, detail: impl std::fmt::Display) -> AppError {
    tracing::warn!(%operation, %detail, "Account Authority device-pairing transport unavailable");
    crate::app_error!(
        TemporarilyUnavailable,
        format!("{operation} is temporarily unavailable"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operation_paths_are_the_registered_internal_bindings() {
        assert_eq!(STAGE_PATH, "/_coauth/internal/device-pairing/stages");
        assert_eq!(RESOLVE_PATH, "/_coauth/internal/device-pairing/resolutions");
        assert_eq!(
            STATUS_PATH,
            "/_coauth/internal/device-pairing/status-queries"
        );
        for path in [STAGE_PATH, RESOLVE_PATH, STATUS_PATH] {
            assert!(arkret_wire::ServiceOperationId::from_http_request("POST", path).is_none());
        }
    }

    #[test]
    fn transport_retry_source_keeps_stage_key_without_protocol_headers() {
        let source = include_str!("account_authority_device_pairing.rs")
            .split("#[cfg(test)]")
            .next()
            .expect("production section");
        assert!(source.contains("for attempt in 0..TRANSPORT_ATTEMPTS"));
        assert!(source.contains("private_headers(state, idempotency_key)"));
        assert!(source.contains("Err(error) if attempt + 1 < TRANSPORT_ATTEMPTS"));
        assert!(!source.contains("Arkret-Operation"));
        assert!(!source.contains("rfc9421_sign"));
    }

    #[test]
    fn private_headers_are_bearer_only_with_optional_replay_key() {
        let headers = private_headers_with_credential(
            "shared-secret",
            Some("device-pairing-stage:019f0000-0000-7000-8000-000000000001"),
        )
        .expect("private headers");
        assert_eq!(headers[AUTHORIZATION], "Bearer shared-secret");
        assert_eq!(
            headers["idempotency-key"],
            "device-pairing-stage:019f0000-0000-7000-8000-000000000001"
        );
        assert_eq!(headers.len(), 3);
    }
}
