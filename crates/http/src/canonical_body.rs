//! Canonical JSON operation-body admission.
//!
//! The transport wire limit is 16 MiB, while every parsed non-streaming JSON
//! operation has a separate 8 MiB JCS-canonical body limit. The middleware uses
//! the SDK's duplicate-aware, depth-bounded ingress boundary and derives lower
//! per-operation limits from the generated operation registry.

use arkret_canonical::CanonicalError;
use arkret_wire::{SERVICE_OPERATION_DESCRIPTORS, ServiceOperationId, WireBodyClass, WireError};
use salvo::prelude::*;

use crate::content_encoding::is_canonical_json_request;
use crate::error::AppError;

fn operation_canonical_body_limit(method: &str, path: &str) -> Option<usize> {
    SERVICE_OPERATION_DESCRIPTORS
        .iter()
        .find(|descriptor| {
            descriptor.body_class == Some("non_streaming_json")
                && descriptor.http_method == method
                && http_path_matches(descriptor.http_path, path)
        })
        .and_then(|descriptor| descriptor.max_canonical_body_bytes)
}

fn requires_mimi_provider_signature(method: &str, path: &str) -> bool {
    matches!(
        ServiceOperationId::from_http_request(method, path),
        Some(
            ServiceOperationId::OpenMimiCommandNotifyV1
                | ServiceOperationId::OpenMimiCommandProxyDownloadV1
                | ServiceOperationId::OpenMimiCommandReportAbuseV1
                | ServiceOperationId::OpenMimiCommandRequestConsentV1
                | ServiceOperationId::OpenMimiCommandSubmitMessageV1
                | ServiceOperationId::OpenMimiCommandUpdateConsentV1
                | ServiceOperationId::OpenMimiCommandUpdateRoomV1
                | ServiceOperationId::OpenMimiExchangeRequestKeyMaterialV1
                | ServiceOperationId::OpenMimiReadIdentifiersV1
        )
    )
}

fn mimi_content_preflight(req: &Request, body: &[u8]) -> Result<(), AppError> {
    if !req.headers().contains_key("signature") || !req.headers().contains_key("signature-input") {
        return Err(crate::app_error!(
            HttpSignatureRequired,
            "MIMI requires provider Signature and Signature-Input"
        ));
    }
    use arkret_signatures::http_signature::{
        HttpSignatureScenario, http_signature_scenario_descriptor,
    };
    let mut required = http_signature_scenario_descriptor(HttpSignatureScenario::MimiProviderV1)
        .required_headers
        .to_vec();
    if matches!(
        ServiceOperationId::from_http_request(req.method().as_str(), req.uri().path()),
        Some(
            ServiceOperationId::OpenMimiCommandNotifyV1
                | ServiceOperationId::OpenMimiCommandSubmitMessageV1
                | ServiceOperationId::OpenMimiCommandUpdateRoomV1
        )
    ) {
        required.push("MIMI-Room-URI");
    }
    for name in required {
        let mut values = req.headers().get_all(name).iter();
        let valid = values
            .next()
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| !value.trim().is_empty());
        if !valid || values.next().is_some() {
            return Err(crate::app_error!(
                HttpSignatureInvalid,
                format!("MIMI requires one nonempty {name} header")
            ));
        }
    }
    let values = req
        .headers()
        .get_all("content-digest")
        .iter()
        .map(|value| value.to_str().map(|value| ("content-digest", value)))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| {
            crate::app_error!(
                HttpSignatureInvalid,
                "MIMI Content-Digest is not a valid header"
            )
        })?;
    arkret_signatures::http_signature::verify_http_content_digest(values, body, true)
        .map(|_| ())
        .map_err(|error| {
            crate::app_error!(
                HttpSignatureInvalid,
                format!("MIMI exact content digest: {error}")
            )
        })
}

fn http_path_matches(template: &str, actual: &str) -> bool {
    let template_segments = template.trim_matches('/').split('/');
    let actual_segments = actual.trim_matches('/').split('/');
    template_segments
        .zip(actual_segments)
        .all(|(expected, found)| {
            (expected.starts_with('{') && expected.ends_with('}')) || expected == found
        })
        && template.trim_matches('/').split('/').count()
            == actual.trim_matches('/').split('/').count()
}

/// Reject a request whose wire body exceeds the transport limit.
///
/// `scalability-constraints.md` §2.1.8 step 4 is a `Content-Length` precheck
/// that answers `payload_too_large` (HTTP 413). Salvo's `SecureMaxSize` drops
/// the oversized body instead of answering, which leaves the handler parsing an
/// empty payload and reporting `schema_violation` — a byte-limit failure
/// surfacing as a schema failure. This runs the precheck the spec describes so
/// the size answer is the one that reaches the caller.
#[derive(Clone)]
pub struct RequestWireSizeLimitMiddleware {
    max_bytes: usize,
}

impl RequestWireSizeLimitMiddleware {
    #[must_use]
    pub fn new(max_bytes: usize) -> Self {
        Self { max_bytes }
    }
}

#[async_trait]
impl Handler for RequestWireSizeLimitMiddleware {
    async fn handle(
        &self,
        req: &mut Request,
        depot: &mut Depot,
        res: &mut Response,
        ctrl: &mut FlowCtrl,
    ) {
        let declared = req
            .headers()
            .get("content-length")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<usize>().ok());
        // A caller that sends no `Content-Length` (chunked transfer) still owes
        // the same bound, so fall back to the bytes actually received. Only
        // canonical JSON bodies are buffered for this: reading a streaming or
        // multipart upload here would consume the very stream its handler needs.
        let observed = match declared {
            Some(length) => Some(length),
            None if is_canonical_json_request(req) => match req.payload().await {
                Ok(payload) => Some(payload.len()),
                Err(salvo::http::ParseError::PayloadTooLarge) => {
                    write_payload_too_large(req, depot, res).await;
                    ctrl.skip_rest();
                    return;
                }
                Err(_) => {
                    let error = AppError::json_invalid("unable to read the request body");
                    error.write(req, depot, res).await;
                    ctrl.skip_rest();
                    return;
                }
            },
            None => None,
        };
        if observed.is_some_and(|length| length > self.max_bytes) {
            write_payload_too_large(req, depot, res).await;
            ctrl.skip_rest();
            return;
        }
        ctrl.call_next(req, depot, res).await;
    }
}

/// Admit a canonical JSON body under the operation's registered byte budget.
///
/// Syntactically invalid JSON is deliberately passed through so operation
/// handlers remain the authority for `json_invalid`. Duplicate keys, excessive
/// depth, forbidden canonical values and non-canonical spelling are valid JSON
/// schema violations and are rejected here before typed decoding.
#[derive(Clone)]
pub struct CanonicalJsonBodyLimitMiddleware;

#[async_trait]
impl Handler for CanonicalJsonBodyLimitMiddleware {
    async fn handle(
        &self,
        req: &mut Request,
        depot: &mut Depot,
        res: &mut Response,
        ctrl: &mut FlowCtrl,
    ) {
        if is_canonical_json_request(req) {
            let method = req.method().as_str().to_owned();
            let path = req.uri().path().to_owned();
            let mimi_provider = requires_mimi_provider_signature(&method, &path);
            let payload = match req.payload().await {
                Ok(payload) => payload.clone(),
                Err(salvo::http::ParseError::PayloadTooLarge) => {
                    write_payload_too_large(req, depot, res).await;
                    ctrl.skip_rest();
                    return;
                }
                Err(_) => {
                    let error = AppError::json_invalid("unable to read the request body");
                    error.write(req, depot, res).await;
                    ctrl.skip_rest();
                    return;
                }
            };
            // Representation integrity precedes JSON parsing for the closed MIMI
            // provider surface. Transport encoding/byte guards already ran.
            if mimi_provider {
                if let Err(error) = mimi_content_preflight(req, &payload) {
                    error.write(req, depot, res).await;
                    ctrl.skip_rest();
                    return;
                }
            }
            let class = WireBodyClass::NonStreamingJsonOperation {
                max_canonical_body_bytes: operation_canonical_body_limit(&method, &path),
            };
            match class.admit_canonical(&payload) {
                Ok(_) => {}
                Err(
                    WireError::BodyWireBytesExceeded { .. }
                    | WireError::BodyCanonicalBytesExceeded { .. },
                ) => {
                    let error = crate::app_error!(
                        PayloadTooLarge,
                        "canonical JSON operation body exceeds its registered byte limit",
                    )
                    .with_wire_code("payload_too_large");
                    error.write(req, depot, res).await;
                    ctrl.skip_rest();
                    return;
                }
                Err(error) if mimi_provider => {
                    let error = crate::app_error!(
                        HttpSignatureInvalid,
                        format!("MIMI signed content is not canonical JSON: {error}")
                    );
                    error.write(req, depot, res).await;
                    ctrl.skip_rest();
                    return;
                }
                Err(WireError::Canonical(CanonicalError::CanonicalJson(_))) => {
                    // Preserve the handler's operation-specific `json_invalid`
                    // response for malformed syntax.
                }
                Err(error) => {
                    let error = crate::app_error!(
                        SchemaViolation,
                        format!("canonical JSON operation body is invalid: {error}"),
                    )
                    .with_wire_code("schema_violation");
                    error.write(req, depot, res).await;
                    ctrl.skip_rest();
                    return;
                }
            }
        }
        ctrl.call_next(req, depot, res).await;
    }
}

async fn write_payload_too_large(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let error = crate::app_error!(
        PayloadTooLarge,
        "request body exceeds the transport wire limit",
    )
    .with_wire_code("payload_too_large");
    error.write(req, depot, res).await;
}

#[cfg(test)]
mod tests {
    use salvo::http::StatusCode;
    use salvo::http::request::SecureMaxSize;
    use salvo::test::{ResponseExt, TestClient};

    use super::*;

    #[handler]
    async fn echo_raw_body(req: &mut Request, res: &mut Response) {
        let payload = req
            .payload()
            .await
            .expect("middleware cached an admitted request body")
            .clone();
        res.write_body(payload).expect("write echoed request body");
    }

    #[handler]
    async fn self_events_body_boundary(req: &mut Request, res: &mut Response) {
        // Match the self/events ingress order: preserve exact bytes first,
        // then retain Salvo's JSON Content-Type gate for typed decoding.
        let exact = req.payload().await.unwrap().to_vec();
        match req.parse_json::<serde_json::Value>().await {
            Ok(_) => {
                res.write_body(exact).unwrap();
            }
            Err(_) => {
                res.status_code(StatusCode::BAD_REQUEST);
            }
        }
    }

    fn canonical_body_test_service(max_wire_bytes: usize) -> Service {
        let router = Router::new()
            .hoop(crate::content_encoding::RejectContentEncodingMiddleware)
            .hoop(SecureMaxSize::new(max_wire_bytes))
            .hoop(RequestWireSizeLimitMiddleware::new(max_wire_bytes))
            .hoop(CanonicalJsonBodyLimitMiddleware)
            .push(Router::with_path("_arkret/peer/signal").post(echo_raw_body))
            .push(Router::with_path("_arkret/self/events").post(self_events_body_boundary))
            .push(
                Router::with_path("_arkret/open/mimi/strands/{strand_id}/notify")
                    .post(echo_raw_body),
            )
            .push(Router::with_path("_arkret/open/mimi/provider-directory").get(echo_raw_body));
        Service::new(router)
    }

    #[test]
    fn operation_registry_supplies_lower_signal_limits() {
        assert_eq!(
            operation_canonical_body_limit("POST", "/_arkret/self/signal"),
            Some(65_536)
        );
        assert_eq!(
            operation_canonical_body_limit("POST", "/_arkret/peer/signal"),
            Some(1_048_576)
        );
        assert_eq!(
            operation_canonical_body_limit("POST", "/_arkret/self/events"),
            None
        );
    }

    #[test]
    fn query_operation_uses_general_non_streaming_json_limit() {
        let descriptor = SERVICE_OPERATION_DESCRIPTORS
            .iter()
            .find(|descriptor| {
                descriptor.http_method == "QUERY"
                    && descriptor.http_path == "/_arkret/self/events/delivery-status"
            })
            .expect("the delivery-status QUERY operation is registered");
        assert_eq!(descriptor.body_class, Some("non_streaming_json"));

        let class = WireBodyClass::NonStreamingJsonOperation {
            max_canonical_body_bytes: operation_canonical_body_limit(
                descriptor.http_method,
                descriptor.http_path,
            ),
        };
        assert_eq!(class.canonical_byte_limit(), 8_388_608);
    }

    #[test]
    fn path_matcher_supports_registered_parameters_without_prefix_matches() {
        assert!(http_path_matches(
            "/_arkret/self/committed-events/{event_id}",
            "/_arkret/self/committed-events/ak:event:1"
        ));
        assert!(!http_path_matches(
            "/_arkret/self/committed-events/{event_id}",
            "/_arkret/self/committed-events"
        ));
    }

    #[tokio::test]
    async fn body_without_content_length_is_cached_byte_identically() {
        let body = r#"{"value":"unchanged"}"#.to_owned();
        let mut response = TestClient::post("http://server/_arkret/peer/signal")
            .add_header("content-type", "application/json", true)
            .body(body.clone())
            .send(&canonical_body_test_service(16 * 1024 * 1024))
            .await;
        assert_eq!(response.status_code, Some(StatusCode::OK));
        assert_eq!(response.take_string().await.unwrap(), body);
    }

    #[tokio::test]
    async fn chunked_body_above_salvo_default_but_within_operation_limit_is_admitted() {
        let body = format!("\"{}\"", "a".repeat(70 * 1024));
        let mut response = TestClient::post("http://server/_arkret/peer/signal")
            .add_header("content-type", "application/json", true)
            .add_header("transfer-encoding", "chunked", true)
            .body(body.clone())
            .send(&canonical_body_test_service(16 * 1024 * 1024))
            .await;
        assert_eq!(response.status_code, Some(StatusCode::OK));
        assert_eq!(response.take_string().await.unwrap(), body);
    }

    #[tokio::test]
    async fn body_above_operation_limit_is_payload_too_large() {
        let body = format!("\"{}\"", "a".repeat(1_048_576));
        let mut response = TestClient::post("http://server/_arkret/peer/signal")
            .add_header("content-type", "application/json", true)
            .body(body)
            .send(&canonical_body_test_service(16 * 1024 * 1024))
            .await;
        assert_eq!(response.status_code, Some(StatusCode::PAYLOAD_TOO_LARGE));
        let response_body = response.take_string().await.unwrap();
        assert!(response_body.contains("payload_too_large"));
    }

    #[tokio::test]
    async fn declared_body_above_wire_limit_is_rejected_before_handler() {
        let mut response = TestClient::post("http://server/_arkret/peer/signal")
            .add_header("content-type", "application/json", true)
            .add_header("content-length", "129", true)
            .body("{}")
            .send(&canonical_body_test_service(128))
            .await;
        assert_eq!(response.status_code, Some(StatusCode::PAYLOAD_TOO_LARGE));
        let response_body = response.take_string().await.unwrap();
        assert!(response_body.contains("payload_too_large"));
    }

    #[tokio::test]
    async fn self_events_exact_body_capture_keeps_content_type_and_size_gates() {
        let service = canonical_body_test_service(128);
        let wrong_type = TestClient::post("http://server/_arkret/self/events")
            .add_header("content-type", "text/plain", true)
            .body("{}")
            .send(&service)
            .await;
        assert_eq!(wrong_type.status_code, Some(StatusCode::BAD_REQUEST));

        let oversize = TestClient::post("http://server/_arkret/self/events")
            .add_header("content-type", "application/json", true)
            .add_header("content-length", "129", true)
            .body("{}")
            .send(&service)
            .await;
        assert_eq!(oversize.status_code, Some(StatusCode::PAYLOAD_TOO_LARGE));

        let mut admitted = TestClient::post("http://server/_arkret/self/events")
            .add_header("content-type", "application/json", true)
            .body("{\"value\":1}")
            .send(&service)
            .await;
        assert_eq!(admitted.status_code, Some(StatusCode::OK));
        assert_eq!(admitted.take_string().await.unwrap(), "{\"value\":1}");
    }

    #[test]
    fn provider_preflight_matches_only_the_nine_registered_operations() {
        let selected: Vec<_> = SERVICE_OPERATION_DESCRIPTORS
            .iter()
            .filter(|item| requires_mimi_provider_signature(item.http_method, item.http_path))
            .collect();
        assert_eq!(selected.len(), 9);
        assert!(!requires_mimi_provider_signature(
            "GET",
            "/_arkret/open/mimi/provider-directory"
        ));
        assert!(!requires_mimi_provider_signature(
            "POST",
            "/_arkret/open/mimi/unknown"
        ));
        assert!(!requires_mimi_provider_signature(
            "POST",
            "/_arkret/self/events"
        ));
    }
    #[tokio::test]
    async fn mimi_body_preflight_keeps_exact_bytes_error_priority_and_public_exemption() {
        let service = canonical_body_test_service(16 * 1024 * 1024);
        for (body, digest, signature, expected) in [
            (" {\"ok\":true}", "{}", true, "http_signature_invalid"),
            (
                " {\"ok\":true}",
                " {\"ok\":true}",
                true,
                "http_signature_invalid",
            ),
            ("not json", "not json", true, "http_signature_invalid"),
            ("not json", "{}", false, "http_signature_required"),
        ] {
            let mut request =
                TestClient::post("http://server/_arkret/open/mimi/strands/room/notify")
                    .add_header("content-type", "application/json", true)
                    .add_header("arkret-operation", "ak.open.mimi.command.notify.v1", true)
                    .add_header("source-service-id", "ak:did_core:web:source.example", true)
                    .add_header(
                        "destination-service-id",
                        "ak:did_core:web:receiver.example",
                        true,
                    )
                    .add_header("provider-id", "mimi://source.example", true)
                    .add_header("mimi-room-uri", "mimi://receiver.example/rooms/room", true)
                    .add_header(
                        "content-digest",
                        crate::http_signature::rfc9530_content_digest(digest.as_bytes()),
                        true,
                    )
                    .body(body);
            if signature {
                request = request.add_header("signature", "present", true).add_header(
                    "signature-input",
                    "present",
                    true,
                );
            }
            let mut response = request.send(&service).await;
            assert_eq!(response.status_code, Some(StatusCode::UNAUTHORIZED));
            let value: serde_json::Value =
                serde_json::from_str(&response.take_string().await.unwrap()).unwrap();
            assert_eq!(
                value["type"],
                format!("https://arkret.org/problems/{expected}")
            );
        }
        // The echo target only tests body admission, not provider authority.
        let mut response = TestClient::post("http://server/_arkret/open/mimi/strands/room/notify")
            .add_header("content-type", "application/json", true)
            .add_header("arkret-operation", "ak.open.mimi.command.notify.v1", true)
            .add_header("source-service-id", "ak:did_core:web:source.example", true)
            .add_header(
                "destination-service-id",
                "ak:did_core:web:receiver.example",
                true,
            )
            .add_header("provider-id", "mimi://source.example", true)
            .add_header("mimi-room-uri", "mimi://receiver.example/rooms/room", true)
            .add_header("signature", "present", true)
            .add_header("signature-input", "present", true)
            .add_header(
                "content-digest",
                crate::http_signature::rfc9530_content_digest(b"{}"),
                true,
            )
            .body("{}")
            .send(&service)
            .await;
        assert_eq!(response.status_code, Some(StatusCode::OK));
        assert_eq!(response.take_string().await.unwrap(), "{}");
        let response = TestClient::get("http://server/_arkret/open/mimi/provider-directory")
            .send(&service)
            .await;
        assert_eq!(response.status_code, Some(StatusCode::OK));
    }
    #[tokio::test]
    async fn mimi_encoding_and_wire_limits_precede_signature_and_json() {
        let service = canonical_body_test_service(128);
        for (encoded, expected) in [
            (false, StatusCode::PAYLOAD_TOO_LARGE),
            (true, StatusCode::UNSUPPORTED_MEDIA_TYPE),
        ] {
            let mut request =
                TestClient::post("http://server/_arkret/open/mimi/strands/room/notify")
                    .add_header("content-type", "application/json", true)
                    .add_header("content-length", "129", true)
                    .body("{}");
            if encoded {
                request = request.add_header("content-encoding", "gzip", true);
            }
            let response = request.send(&service).await;
            assert_eq!(response.status_code, Some(expected));
        }
    }
}
