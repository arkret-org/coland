//! HTTP requests shared by committed-stream integration tests.
use arkret_wire::StreamScanRequestBody;
use coland_http::service;
use salvo::http::StatusCode;
use salvo::test::{ResponseExt, TestClient};
use serde_json::Value;
const SCAN_PATH: &str = "/_arkret/self/streams/scan";

pub(super) async fn scan(
    state: &coland_http::state::AppState,
    token: &str,
    request: &StreamScanRequestBody,
) -> (StatusCode, Value) {
    let canonical_body = String::from_utf8(
        arkret_canonical::canonical_json_bytes(request).expect("canonical scan request"),
    )
    .expect("canonical JSON is UTF-8");
    let mut response = TestClient::post(format!("http://server{SCAN_PATH}"))
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header(
            "Arkret-Operation",
            arkret_wire::ServiceOperationId::SELF_COMMITTED_EVENT_READ_SCAN_V1,
            true,
        )
        .raw_json(canonical_body)
        .send(&service(state.clone()))
        .await;
    (
        response.status_code.expect("scan status"),
        response.take_json().await.expect("scan JSON"),
    )
}
