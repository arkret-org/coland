use super::common::*;

/// The served OpenAPI document is generated from the live salvo router via
/// salvo-oapi (`OpenApi::merge_router`), not from any embedded/static
/// artifact. Typed JSON routes are annotated `#[endpoint]`; the remaining
/// transport-specialized handlers are intentionally outside the ordinary
/// generated operation surface.
#[test]
fn served_openapi_is_generated_from_the_router() {
    run_on_test_runtime(
        "served_openapi_is_generated_from_the_router",
        served_openapi_is_generated_from_the_router_body,
    );
}

async fn served_openapi_is_generated_from_the_router_body() {
    let spec: Value = TestClient::get("http://server/.well-known/arkret/openapi.json")
        .send(&app())
        .await
        .take_json()
        .await
        .unwrap();

    assert_eq!(spec["openapi"], "3.2.0");
    assert_eq!(spec["info"]["title"], "Arkret Service API");
    assert_eq!(
        spec["x-arkret-artifacts"]["openapi_source"],
        "salvo-oapi::OpenApi::merge_router"
    );
    assert_eq!(
        spec["x-arkret-artifacts"]["registered_route_source"],
        "salvo::routing::FilterInfo"
    );
    assert!(
        spec["paths"].is_object(),
        "generated document must expose a paths object"
    );
    assert_required_migrated_operations(&spec);
    assert_event_read_query_bindings(&spec);
    assert_operation_selectors_are_required(&spec);
    assert_operation_ids_are_unique(&spec);
    assert_component_refs_resolve(&spec, &spec);
}

fn assert_operation_selectors_are_required(root: &Value) {
    let operation = &root["paths"]["/_arkret/describe"]["get"];
    assert_eq!(operation["operationId"], "ak.server.read.describe");
    let selector = operation["parameters"]
        .as_array()
        .expect("describe parameters")
        .iter()
        .find(|parameter| parameter["name"] == "Arkret-Operation")
        .expect("describe Arkret-Operation parameter");
    assert_eq!(selector["required"], true);
    assert_eq!(selector["schema"]["const"], "ak.server.read.describe.v1");
}

#[test]
fn served_openapi_yaml_renders() {
    run_on_test_runtime(
        "served_openapi_yaml_renders",
        served_openapi_yaml_renders_body,
    );
}

async fn served_openapi_yaml_renders_body() {
    let response = TestClient::get("http://server/.well-known/arkret/openapi.yaml")
        .send(&app())
        .await;
    assert_eq!(response.status_code, Some(StatusCode::OK));
    let content_type = response
        .headers()
        .get(salvo::http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    assert!(
        content_type.starts_with("application/yaml"),
        "unexpected content type: {content_type}"
    );
}

fn assert_component_refs_resolve(root: &Value, value: &Value) {
    match value {
        Value::Object(object) => {
            if let Some(reference) = object.get("$ref").and_then(Value::as_str)
                && let Some(pointer) = reference.strip_prefix('#')
                && pointer.starts_with("/components/")
            {
                assert!(
                    root.pointer(pointer).is_some(),
                    "unresolved OpenAPI component reference: {reference}"
                );
            }
            for child in object.values() {
                assert_component_refs_resolve(root, child);
            }
        }
        Value::Array(array) => {
            for child in array {
                assert_component_refs_resolve(root, child);
            }
        }
        _ => {}
    }
}

fn assert_required_migrated_operations(root: &Value) {
    let operation_ids = operation_ids(root);
    for expected in [
        "org.arkret.coland.system.health",
        "ak.server.read.describe",
        "ak.self.realm_state_snapshot.read.manifest_head",
        "ak.self.blob.command.presign",
        "org.arkret.coland.interop.mimi.protocol_directory",
        "org.arkret.coland.well_known.arkret",
    ] {
        assert!(
            operation_ids.contains(&expected),
            "migrated operation is absent from generated OpenAPI: {expected}"
        );
    }
}

fn assert_event_read_query_bindings(root: &Value) {
    for retired in [
        "/_arkret/self/events/describe",
        "/_arkret/self/events/frontier",
        "/_arkret/self/events/resolve",
        "/_arkret/peer/events/frontier",
        "/_arkret/peer/events/resolve",
        "/_arkret/peer/events/sibling-positions",
        "/_arkret/self/seals/frontier",
        "/_arkret/peer/seals/frontier",
        "/_arkret/self/seals/mls-governance-proof",
        "/_arkret/peer/seals/mls-governance-proof",
    ] {
        assert!(
            root["paths"].get(retired).is_none(),
            "retired path leaked: {retired}"
        );
    }
    {
        let (path, operation_id) = (
            "/_arkret/peer/mls/group-state-material",
            "ak.peer.mls.read.group_state_material",
        );
        let operation = &root["paths"][path]["post"];
        assert_eq!(operation["operationId"], operation_id);
        assert!(
            operation["requestBody"]["content"]["application/json"].is_object(),
            "peer MLS POST binding {operation_id} must expose JSON content"
        );
    }
}

fn assert_operation_ids_are_unique(root: &Value) {
    let mut seen = std::collections::BTreeSet::new();
    for operation_id in operation_ids(root) {
        assert!(
            seen.insert(operation_id),
            "duplicate generated OpenAPI operationId: {operation_id}"
        );
    }
}

fn operation_ids(root: &Value) -> Vec<&str> {
    const METHODS: &[&str] = &[
        "get", "head", "post", "put", "patch", "delete", "options", "query", "trace",
    ];
    root["paths"]
        .as_object()
        .into_iter()
        .flat_map(|paths| paths.values())
        .filter_map(Value::as_object)
        .flat_map(|path_item| {
            path_item
                .iter()
                .filter(|(method, _)| METHODS.contains(&method.as_str()))
                .filter_map(|(_, operation)| operation["operationId"].as_str())
        })
        .collect()
}

/// A path that exists only in the canonical spec artifact (never registered as
/// a live route) must be treated as unknown by the 404/405 disambiguator,
/// which is now driven by the router walk rather than the OpenAPI document.
#[test]
fn artifact_only_path_is_not_treated_as_a_registered_route() {
    run_on_test_runtime(
        "artifact_only_path_is_not_treated_as_a_registered_route",
        artifact_only_path_is_not_treated_as_a_registered_route_body,
    );
}

async fn artifact_only_path_is_not_treated_as_a_registered_route_body() {
    let response: Value = TestClient::post("http://server/_arkret/gate/account/session-grants")
        .send(&app())
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(response["status"], 404);
    assert_eq!(
        response["type"],
        "https://arkret.org/problems/unrecognized_endpoint"
    );
}

/// Framework-level 404 and 405 responses carry the Arkret problem envelope.
#[test]
fn framework_errors_use_problem_details() {
    run_on_test_runtime(
        "framework_errors_use_problem_details",
        framework_errors_use_problem_details_body,
    );
}

async fn framework_errors_use_problem_details_body() {
    let not_found: Value = TestClient::get("http://server/_arkret/self/missing")
        .send(&app())
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(problem_code(&not_found), "unrecognized_endpoint");

    let method_not_allowed: Value = TestClient::post("http://server/_arkret/describe")
        .send(&app())
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(problem_code(&method_not_allowed), "method_not_allowed");
}
