//! Optional same-Station IVS delegation over registered, typed operations.

use std::time::Duration;

use arkret_models_collaboration::governance::third_party_invite::*;
use arkret_wire::{ErrorCode, ServiceOperationId};
use coland_http::error::AppError;
use coland_http::result::{JsonResult, json_ok};
use salvo::oapi::endpoint;
use salvo::prelude::*;

use crate::state::AppState;

const PREFIX: &str = "/_arkret/open/third-party-invites/";

#[derive(Clone, Copy)]
struct PresentRequestStarted(tokio::time::Instant);

pub(crate) fn open_router() -> Router {
    Router::with_path("third-party-invites")
        .push(Router::with_path("provision").post(provision))
        .push(Router::with_path("activate").post(activate))
        .push(Router::with_path("status").post(status))
        .push(Router::with_path("present").post(present))
}

/// Run before any generic body reader. URL credentials never reach transport,
/// access metrics, a canonical-body parser or the delegated provider.
#[handler]
pub(crate) async fn reject_url_credentials(
    req: &mut Request,
    depot: &mut Depot,
    res: &mut Response,
    ctrl: &mut FlowCtrl,
) {
    let path = req.uri().path();
    let Some(suffix) = path.strip_prefix(PREFIX) else {
        ctrl.call_next(req, depot, res).await;
        return;
    };
    if req.uri().query().is_none()
        && matches!(suffix, "provision" | "activate" | "status" | "present")
    {
        if suffix == "present" {
            // Start before the shared wire-size and canonical-body readers.
            // Those readers run before the operation handler itself.
            depot.insert_typed(PresentRequestStarted(tokio::time::Instant::now()));
        }
        ctrl.call_next(req, depot, res).await;
        return;
    }
    let error = if suffix == "present" || suffix.starts_with("present/") {
        crate::app_error!(
            FailedPrecondition,
            "invitation credentials belong only in the request body"
        )
        .with_reason_code(arkret_wire::ReasonCode::THIRD_PARTY_INVITE_TOKEN_IN_QUERY)
    } else {
        AppError::schema_violation("invitation inputs belong only in the request body")
    };
    error.write(req, depot, res).await;
    ctrl.skip_rest();
}

async fn post<RequestBody, ResponseBody>(
    state: &AppState,
    operation: &'static str,
    path: &'static str,
    body: &RequestBody,
) -> Result<ResponseBody, AppError>
where
    RequestBody: serde::Serialize,
    ResponseBody: serde::de::DeserializeOwned,
{
    if !state.config().third_party_invite_provider_enabled {
        return Err(crate::app_error!(
            UnsupportedFeature,
            "invitation provider is unavailable"
        ));
    }
    let base = state
        .config()
        .account_authority_url
        .as_deref()
        .ok_or_else(unavailable)?;
    let mut target = url::Url::parse(base).map_err(|_| unavailable())?;
    target.set_path(path);
    target.set_query(None);
    target.set_fragment(None);
    let (target, client) = crate::security::validate_http_url_for_egress_with_pinned_client(
        target.as_str(),
        "third-party invite provider",
        state.config().development_mode,
        Duration::from_secs(30),
    )
    .map_err(|_| unavailable())?;
    let bytes = arkret_canonical::canonical_json_bytes(body).map_err(|_| unavailable())?;
    let response = super::with_arkret_operation(
        client
            .post(target)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(bytes),
        operation,
    )
    .send()
    .await
    .map_err(|_| unavailable())?;
    let upstream_status = response.status();
    if response
        .content_length()
        .is_some_and(|size| size > 64 * 1024)
    {
        return Err(unavailable());
    }
    // Stream into a bounded buffer even when the provider uses chunked HTTP.
    let mut response = response;
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| unavailable())? {
        if bytes.len().saturating_add(chunk.len()) > 64 * 1024 {
            return Err(unavailable());
        }
        bytes.extend_from_slice(&chunk);
    }
    if upstream_status.is_success() {
        return serde_json::from_slice(&bytes).map_err(|_| unavailable());
    }
    let problem: arkret_wire::problem_details::Problem =
        serde_json::from_slice(&bytes).map_err(|_| unavailable())?;
    let code = problem.error_code().ok_or_else(unavailable)?;
    if code.http_status() != upstream_status.as_u16() {
        return Err(unavailable());
    }
    if operation == ServiceOperationId::OPEN_THIRD_PARTY_INVITE_COMMAND_PRESENT_TOKEN_V1
        && code == ErrorCode::NotFound
    {
        return Err(AppError::indistinguishable_not_found(
            "third-party invite unavailable",
        ));
    }
    // No arbitrary upstream detail, instance, URL or private extension crosses
    // this public boundary. Only registry-checked classification survives.
    let mut error =
        AppError::from_rejection(code, "third-party invite request could not be completed");
    if let Some(reason) = problem
        .extensions
        .get("reason_code")
        .and_then(serde_json::Value::as_str)
        && arkret_wire::ReasonCode::is_registered(reason)
    {
        error = error.with_reason_code(reason);
    }
    if matches!(
        code,
        ErrorCode::RateLimited | ErrorCode::TemporarilyUnavailable
    ) && let Some(delay) = problem
        .extensions
        .get("retry_after_ms")
        .and_then(serde_json::Value::as_u64)
    {
        error.wire_details = Some(Box::new(std::collections::BTreeMap::from([(
            "retry_after_ms".into(),
            serde_json::json!(delay),
        )])));
    }
    Err(error)
}

fn unavailable() -> AppError {
    crate::app_error!(
        TemporarilyUnavailable,
        "invitation provider is temporarily unavailable"
    )
}

#[endpoint(
    operation_id = "ak.open.third_party_invite.command.provision",
    request_body = ThirdPartyInviteProvisionRequestBody,
    tags("invites")
)]
#[tracing::instrument(skip_all, fields(op = ServiceOperationId::OPEN_THIRD_PARTY_INVITE_COMMAND_PROVISION_V1))]
async fn provision(
    req: &mut Request,
    depot: &Depot,
) -> JsonResult<ThirdPartyInviteProvisionOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let body: ThirdPartyInviteProvisionRequestBody = req
        .parse_json()
        .await
        .map_err(|_| AppError::json_invalid("invalid invite request"))?;
    body.validate_for_service(&state.service_core_id())
        .map_err(|_| AppError::not_found("third-party invite unavailable"))?;
    let outcome: ThirdPartyInviteProvisionOutcome = post(
        state,
        ServiceOperationId::OPEN_THIRD_PARTY_INVITE_COMMAND_PROVISION_V1,
        "/_arkret/open/third-party-invites/provision",
        &body,
    )
    .await?;
    outcome
        .validate_for_request(&body)
        .map_err(|_| unavailable())?;
    json_ok(outcome)
}

#[endpoint(
    operation_id = "ak.open.third_party_invite.command.activate",
    request_body = ThirdPartyInviteActivationRequestBody,
    tags("invites")
)]
#[tracing::instrument(skip_all, fields(op = ServiceOperationId::OPEN_THIRD_PARTY_INVITE_COMMAND_ACTIVATE_V1))]
async fn activate(
    req: &mut Request,
    depot: &Depot,
) -> JsonResult<ThirdPartyInviteActivationOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let body: ThirdPartyInviteActivationRequestBody = req
        .parse_json()
        .await
        .map_err(|_| AppError::json_invalid("invalid invite request"))?;
    body.validate()
        .map_err(|_| AppError::not_found("third-party invite unavailable"))?;
    let outcome: ThirdPartyInviteActivationOutcome = post(
        state,
        ServiceOperationId::OPEN_THIRD_PARTY_INVITE_COMMAND_ACTIVATE_V1,
        "/_arkret/open/third-party-invites/activate",
        &body,
    )
    .await?;
    outcome
        .validate_for_request(&body)
        .map_err(|_| unavailable())?;
    json_ok(outcome)
}

#[endpoint(
    operation_id = "ak.open.third_party_invite.read.provisioning_status",
    request_body = ThirdPartyInviteProvisioningStatusRequestBody,
    tags("invites")
)]
#[tracing::instrument(skip_all, fields(op = ServiceOperationId::OPEN_THIRD_PARTY_INVITE_READ_PROVISIONING_STATUS_V1))]
async fn status(
    req: &mut Request,
    depot: &Depot,
) -> JsonResult<ThirdPartyInviteProvisioningStatusOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let body: ThirdPartyInviteProvisioningStatusRequestBody = req
        .parse_json()
        .await
        .map_err(|_| AppError::json_invalid("invalid invite request"))?;
    let outcome: ThirdPartyInviteProvisioningStatusOutcome = post(
        state,
        ServiceOperationId::OPEN_THIRD_PARTY_INVITE_READ_PROVISIONING_STATUS_V1,
        "/_arkret/open/third-party-invites/status",
        &body,
    )
    .await?;
    outcome.validate().map_err(|_| unavailable())?;
    if outcome.provisioning_id != body.provisioning_id {
        return Err(unavailable());
    }
    json_ok(outcome)
}

#[endpoint(
    operation_id = "ak.open.third_party_invite.command.present_token",
    request_body = ThirdPartyInvitePresentRequestBody,
    tags("invites")
)]
#[tracing::instrument(skip_all, fields(op = ServiceOperationId::OPEN_THIRD_PARTY_INVITE_COMMAND_PRESENT_TOKEN_V1))]
async fn present(req: &mut Request, depot: &Depot) -> JsonResult<ThirdPartyInvitePresentOutcome> {
    let handler_started = tokio::time::Instant::now();
    let started = depot
        .get_typed::<PresentRequestStarted>()
        .map(|value| value.0)
        .unwrap_or(handler_started);
    let result = present_inner(req, depot).await;
    let evaluated = tokio::time::Instant::now();
    let negative = result
        .as_ref()
        .is_err_and(|error| error.code == ErrorCode::NotFound);
    let result = finish_present_at_deadline(started, result).await;
    if negative {
        // Closed numeric observations only: never log inputs, identities,
        // credentials or the private reason for a uniform rejection.
        tracing::debug!(
            boundary = "third_party_invite_present_negative",
            before_handler_ms = (handler_started - started).as_secs_f64() * 1000.0,
            evaluation_ms = (evaluated - handler_started).as_secs_f64() * 1000.0,
            padding_ms = evaluated.elapsed().as_secs_f64() * 1000.0,
            total_ms = started.elapsed().as_secs_f64() * 1000.0,
            "uniform invite response timing"
        );
    }
    result
}

const PRESENT_NEGATIVE_RESPONSE_BUDGET: Duration = Duration::from_secs(1);

async fn finish_present_at_deadline<T>(
    started: tokio::time::Instant,
    result: Result<T, AppError>,
) -> Result<T, AppError> {
    if result
        .as_ref()
        .is_err_and(|error| error.code == ErrorCode::NotFound)
    {
        tokio::time::sleep_until(started + PRESENT_NEGATIVE_RESPONSE_BUDGET).await;
    }
    // Positive outcomes and registered operational errors keep their original
    // semantics; the uniform claim-not-found response owns this deadline.
    result
}

async fn present_inner(
    req: &mut Request,
    depot: &Depot,
) -> JsonResult<ThirdPartyInvitePresentOutcome> {
    let body: ThirdPartyInvitePresentRequestBody = req
        .parse_json()
        .await
        .map_err(|_| AppError::indistinguishable_not_found("third-party invite unavailable"))?;
    let state = depot.get_typed::<AppState>().expect("state injected");
    // The fixed provider owns claim validation, rate budgets and the uniform
    // negative response boundary. Keep the original typed request unchanged.
    let outcome: ThirdPartyInvitePresentOutcome = post(
        state,
        ServiceOperationId::OPEN_THIRD_PARTY_INVITE_COMMAND_PRESENT_TOKEN_V1,
        "/_arkret/open/third-party-invites/present",
        &body,
    )
    .await?;
    outcome
        .binding_proof
        .validate()
        .map_err(|_| unavailable())?;
    if outcome.binding_proof.subject_account_id != body.subject_account_id
        || outcome.binding_proof.realm_id != body.realm_id
        || outcome.binding_proof.claim_nonce != body.claim_nonce
        || outcome.binding_proof.verification_id != state.service_core_id()
    {
        return Err(unavailable());
    }
    json_ok(outcome)
}

#[cfg(test)]
mod tests {
    use salvo::test::{ResponseExt as _, TestClient};

    use super::*;

    #[tokio::test(start_paused = true)]
    async fn public_present_not_found_deadline_includes_outer_work_for_all_failure_classes() {
        // Vary complete public work, including costs outside the provider's
        // existing 250ms floor. No token or private terminal classification
        // needs to cross the delegation boundary to share this deadline.
        for millis in [0, 40, 80, 160, 240, 350] {
            let started = tokio::time::Instant::now();
            tokio::time::sleep(Duration::from_millis(millis)).await;
            let result = finish_present_at_deadline::<()>(
                started,
                Err(AppError::indistinguishable_not_found(
                    "third-party invite unavailable",
                )),
            )
            .await;
            assert_eq!(result.unwrap_err().code, ErrorCode::NotFound);
            assert_eq!(started.elapsed(), PRESENT_NEGATIVE_RESPONSE_BUDGET);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn public_present_deadline_preserves_success_rate_limit_and_unavailable_outcomes() {
        let started = tokio::time::Instant::now();
        assert!(finish_present_at_deadline(started, Ok(())).await.is_ok());
        assert_eq!(started.elapsed(), Duration::ZERO);
        for code in [ErrorCode::RateLimited, ErrorCode::TemporarilyUnavailable] {
            let started = tokio::time::Instant::now();
            let result = finish_present_at_deadline::<()>(
                started,
                Err(AppError::from_rejection(code, "controlled")),
            )
            .await;
            assert_eq!(result.unwrap_err().code, code);
            assert_eq!(started.elapsed(), Duration::ZERO);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn public_present_malformed_body_uses_the_same_not_found_deadline() {
        let service = Service::new(Router::with_path("present").post(present));
        let started = tokio::time::Instant::now();
        let mut response = TestClient::post("http://server/present")
            .add_header("Content-Type", "application/json", true)
            .body("invalid JSON")
            .send(&service)
            .await;
        let body: arkret_wire::problem_details::Problem = response.take_json().await.unwrap();
        assert_eq!(response.status_code, Some(StatusCode::NOT_FOUND));
        assert_eq!(body.error_code(), Some(ErrorCode::NotFound));
        assert!(body.instance.is_none());
        assert_eq!(started.elapsed(), PRESENT_NEGATIVE_RESPONSE_BUDGET);
    }

    #[handler]
    async fn delayed_body_reader(
        req: &mut Request,
        depot: &mut Depot,
        res: &mut Response,
        ctrl: &mut FlowCtrl,
    ) {
        tokio::time::sleep(Duration::from_millis(350)).await;
        let _ = req.payload().await;
        ctrl.call_next(req, depot, res).await;
    }

    #[tokio::test(start_paused = true)]
    async fn public_present_deadline_includes_shared_body_readers_before_dispatch() {
        let service = Service::new(
            Router::new()
                .hoop(reject_url_credentials)
                .hoop(delayed_body_reader)
                .hoop(coland_http::canonical_body::CanonicalJsonBodyLimitMiddleware)
                .push(Router::with_path("/_arkret/open").push(open_router())),
        );
        let started = tokio::time::Instant::now();
        let mut response =
            TestClient::post("http://server/_arkret/open/third-party-invites/present")
                .add_header("Content-Type", "application/json", true)
                .body("invalid JSON")
                .send(&service)
                .await;
        let body: arkret_wire::problem_details::Problem = response.take_json().await.unwrap();
        assert_eq!(response.status_code, Some(StatusCode::NOT_FOUND));
        assert_eq!(body.error_code(), Some(ErrorCode::NotFound));
        assert!(body.instance.is_none());
        assert_eq!(started.elapsed(), PRESENT_NEGATIVE_RESPONSE_BUDGET);
    }

    #[test]
    fn generated_openapi_preserves_original_sdk_request_and_success_models() {
        let router = Router::with_path("/_arkret/open").push(open_router());
        let doc =
            serde_json::to_value(salvo::oapi::OpenApi::new("invites", "v1").merge_router(&router))
                .unwrap();
        for (suffix, request_model, response_model) in [
            (
                "provision",
                "ThirdPartyInviteProvisionRequestBody",
                "ThirdPartyInviteProvisionOutcome",
            ),
            (
                "activate",
                "ThirdPartyInviteActivationRequestBody",
                "ThirdPartyInviteActivationOutcome",
            ),
            (
                "status",
                "ThirdPartyInviteProvisioningStatusRequestBody",
                "ThirdPartyInviteProvisioningStatusOutcome",
            ),
            (
                "present",
                "ThirdPartyInvitePresentRequestBody",
                "ThirdPartyInvitePresentOutcome",
            ),
        ] {
            let operation =
                &doc["paths"][format!("/_arkret/open/third-party-invites/{suffix}")]["post"];
            let request = &operation["requestBody"]["content"]["application/json"]["schema"];
            let response = &operation["responses"]["200"]["content"]["application/json"]["schema"];
            for (schema, model) in [(request, request_model), (response, response_model)] {
                let reference = schema["$ref"].as_str().expect("SDK model reference");
                assert!(reference.ends_with(model), "{suffix}: {schema}");
                let pointer = reference.strip_prefix('#').expect("local schema reference");
                assert!(
                    doc.pointer(pointer)
                        .is_some_and(serde_json::Value::is_object),
                    "unresolved {reference}"
                );
            }
        }
        for nested in [
            "ThirdPartyInvite",
            "ThirdPartyInviteProvisioningId",
            "ThirdPartyInviteAcceptanceAttestation",
            "InviteClaimBindingProof",
        ] {
            assert!(
                doc["components"]["schemas"]
                    .as_object()
                    .unwrap()
                    .iter()
                    .any(|(name, schema)| name.rsplit('.').next() == Some(nested)
                        && schema.is_object()),
                "missing {nested}"
            );
        }
    }

    #[tokio::test]
    async fn url_credentials_are_rejected_before_invalid_json_and_unadvertised_dispatch() {
        let service = crate::service(AppState::new(
            crate::config::AppConfig::test_default(),
            coland_storage_postgres::Db { pool: None },
        ));
        for url in [
            "http://server/_arkret/open/third-party-invites/present?token=ABC123",
            "http://server/_arkret/open/third-party-invites/present/ABC123",
        ] {
            let mut response = TestClient::post(url)
                .add_header(
                    "Arkret-Operation",
                    ServiceOperationId::OPEN_THIRD_PARTY_INVITE_COMMAND_PRESENT_TOKEN_V1,
                    true,
                )
                .add_header("Content-Type", "application/json", true)
                .body("invalid JSON must not be parsed")
                .send(&service)
                .await;
            let body: serde_json::Value = response.take_json().await.unwrap();
            assert_eq!(response.status_code, Some(StatusCode::CONFLICT));
            assert_eq!(body["reason_code"], "third_party_invite_token_in_query");
            assert!(!body.to_string().contains("ABC123"));
        }
    }
}
