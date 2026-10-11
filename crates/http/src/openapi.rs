use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

use anyhow::bail;
use salvo::oapi::{OpenApi, OpenApiVersion};
use salvo::prelude::*;
use salvo::routing::FilterInfo;
use serde_json::{Value, json};

use crate::openapi_routes::{ArkretOpenApiDoc, populate_known_routes};

static ARKRET_OPENAPI_DOC: OnceLock<Value> = OnceLock::new();
static TRANSPORT_OPERATION_IDS: OnceLock<std::result::Result<Vec<String>, String>> =
    OnceLock::new();

/// Build (once) and return the served OpenAPI document.
///
/// The document is generated from the live salvo router via salvo-oapi
/// (`OpenApi::merge_router`) rather than from any embedded/static artifact, so
/// every advertised operation comes from a real registered `#[endpoint]`
/// handler. The remaining `#[handler]` routes are deliberately limited to
/// streaming, multipart/binary transfer, protocol middleware, documentation
/// rendering, and framework catchers that cannot be described by the ordinary
/// typed JSON endpoint macro.
///
/// The 404/405 `Allow`-header table (`KNOWN_ROUTES`) is populated separately
/// from a direct router walk (`collect_registered_routes`), so error-envelope
/// correctness never depends on OpenAPI annotation coverage.
pub fn cached_arkret_openapi_doc(router: &Router, artifact_registry_summary: Value) -> Value {
    let registered_routes = collect_registered_routes(router)
        .unwrap_or_else(|error| panic!("failed to walk router for OpenAPI: {error:#}"));
    populate_known_routes(&registered_routes);
    ARKRET_OPENAPI_DOC
        .get_or_init(|| generate_openapi_doc(router, artifact_registry_summary))
        .clone()
}

fn generate_openapi_doc(router: &Router, artifact_registry_summary: Value) -> Value {
    let generated = OpenApi::new("Arkret Service API", env!("CARGO_PKG_VERSION"))
        .openapi_version(OpenApiVersion::Version3_2)
        .merge_router(router);
    let mut doc = serde_json::to_value(&generated)
        .unwrap_or_else(|error| panic!("failed to serialize generated OpenAPI: {error:#}"));
    let root = doc
        .as_object_mut()
        .expect("generated OpenAPI root must be an object");
    // Coland-specific extension metadata carried over from the previous
    // artifact-first document. Operation aliases map spec stream/command kinds
    // onto their canonical operationIds for clients that resolve by alias.
    root.insert(
        "x-operation-aliases".to_owned(),
        json!({
            "events.submit": arkret_wire::ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT_V1,
            "events.read": arkret_wire::ServiceOperationId::SELF_COMMITTED_EVENT_READ_SCAN_V1,
            "events.subscribe": arkret_wire::ServiceOperationId::SELF_COMMITTED_EVENT_STREAM_SUBSCRIBE_V1,
            "account.subscribe": arkret_wire::ServiceOperationId::SELF_ACCOUNT_STREAM_SUBSCRIBE_V1,
        }),
    );
    root.insert(
        "x-arkret-artifacts".to_owned(),
        json!({
            "registries": artifact_registry_summary,
            "openapi_source": "salvo-oapi::OpenApi::merge_router",
            "registered_route_source": "salvo::routing::FilterInfo",
            // View facets are declared by individual spec event kinds and bound
            // through cell-family registry mappings.
            "authz_constraint_kinds": ["allowed_object_facets"],
        }),
    );
    install_generated_query_operations(router, &mut doc);
    install_operation_selector_parameters(&mut doc);
    doc
}

const OPENAPI_METHODS: &[&str] = &[
    "get", "head", "post", "put", "patch", "delete", "options", "query", "trace",
];

fn install_operation_selector_parameters(doc: &mut Value) {
    let paths = doc["paths"]
        .as_object_mut()
        .expect("generated OpenAPI paths must be an object");
    for path_item in paths.values_mut() {
        let Some(path_item) = path_item.as_object_mut() else {
            continue;
        };
        for method in OPENAPI_METHODS {
            let Some(operation) = path_item.get_mut(*method).and_then(Value::as_object_mut) else {
                continue;
            };
            let Some(endpoint_operation_id) = operation
                .get("operationId")
                .and_then(Value::as_str)
                .map(str::to_owned)
            else {
                continue;
            };
            let candidates = arkret_wire::ServiceOperationId::ALL
                .iter()
                .map(|operation| operation.as_str())
                .filter(|operation_id| {
                    stable_endpoint_operation_id(operation_id) == endpoint_operation_id
                })
                .collect::<Vec<_>>();
            if candidates.is_empty() {
                continue;
            }
            let parameters = operation
                .entry("parameters".to_owned())
                .or_insert_with(|| json!([]))
                .as_array_mut()
                .expect("OpenAPI operation parameters must be an array");
            parameters.retain(|parameter| {
                parameter.get("name").and_then(Value::as_str) != Some("Arkret-Operation")
            });
            let selector_schema = if candidates.len() == 1 {
                json!({
                    "type": "string",
                    "const": candidates[0]
                })
            } else {
                json!({
                    "type": "string",
                    "enum": candidates
                })
            };
            parameters.push(json!({
                "name": "Arkret-Operation",
                "in": "header",
                "required": true,
                "description": "Required exact versioned operation_id selector for every canonical Arkret HTTP request.",
                "schema": selector_schema
            }));
        }
    }
}

fn stable_endpoint_operation_id(operation_id: &str) -> &str {
    operation_id
        .rsplit_once(".v")
        .filter(|(_, version)| {
            !version.is_empty() && version.bytes().all(|byte| byte.is_ascii_digit())
        })
        .map_or(operation_id, |(endpoint_id, _)| endpoint_id)
}

/// salvo-oapi can emit an OpenAPI 3.2 document, while its typed `PathItemType`
/// still predates the 3.2 `query` member. The spec code generator therefore
/// emits only the canonical QUERY Operation Objects and their referenced local
/// components as Rust expressions. We merge an operation only when the live
/// router exposes the same path with QUERY, and reject any live QUERY route
/// absent from that generated catalog.
fn install_generated_query_operations(router: &Router, doc: &mut Value) {
    let registered = collect_registered_routes(router)
        .unwrap_or_else(|error| panic!("failed to walk router for QUERY OpenAPI: {error:#}"));
    let mut operations = arkret_schema::openapi_query_operations()
        .into_iter()
        .collect::<BTreeMap<_, _>>();
    for (path, methods) in &registered {
        if !methods.contains("query") {
            continue;
        }
        let operation = operations.remove(path.as_str()).unwrap_or_else(|| {
            panic!("live QUERY route {path} has no generated canonical OpenAPI operation")
        });
        doc["paths"][path]["query"] = operation;
    }

    let generated_components = doc["components"]
        .as_object_mut()
        .expect("generated OpenAPI components must be an object");
    let supplement = arkret_schema::openapi_query_components();
    for (section_name, section) in supplement
        .as_object()
        .expect("generated QUERY OpenAPI components must be an object")
    {
        let destination = generated_components
            .entry(section_name.clone())
            .or_insert_with(|| json!({}))
            .as_object_mut()
            .expect("generated OpenAPI component section must be an object");
        for (name, component) in section
            .as_object()
            .expect("generated QUERY OpenAPI component section must be an object")
        {
            destination
                .entry(name.clone())
                .or_insert_with(|| component.clone());
        }
    }
}

/// Walk the live salvo router and collect every registered `path -> methods`
/// pair. This is the single source of truth for the 404/405 known-route table
/// and is independent of OpenAPI generation.
type RegisteredRoutes = BTreeMap<String, BTreeSet<String>>;

fn collect_registered_routes(router: &Router) -> anyhow::Result<RegisteredRoutes> {
    fn walk(
        router: &Router,
        parent_path: &str,
        parent_method: Option<&str>,
        routes: &mut RegisteredRoutes,
    ) -> anyhow::Result<()> {
        let mut path = parent_path.to_owned();
        let mut method = parent_method.map(str::to_owned);
        for filter in router.filters() {
            match filter.info() {
                FilterInfo::Path(fragment) => path = join_route_path(&path, &fragment),
                FilterInfo::Method(candidate) => {
                    let candidate = candidate.as_str().to_ascii_lowercase();
                    if candidate == "options" {
                        return Ok(());
                    }
                    if let Some(existing) = &method
                        && existing != &candidate
                    {
                        bail!(
                            "route `{path}` has conflicting method filters `{existing}` and `{candidate}`"
                        );
                    }
                    method = Some(candidate);
                }
                FilterInfo::Scheme(_)
                | FilterInfo::Host(_)
                | FilterInfo::Port(_)
                | FilterInfo::Other(_) => {}
            }
        }

        if router.goal.is_some()
            && let Some(method) = &method
            && !path.contains("{**")
        {
            routes
                .entry(path.clone())
                .or_default()
                .insert(method.clone());
        }
        for child in router.routers() {
            walk(child, &path, method.as_deref(), routes)?;
        }
        Ok(())
    }

    let mut routes = RegisteredRoutes::new();
    walk(router, "", None, &mut routes)?;
    Ok(routes)
}

fn join_route_path(parent: &str, fragment: &str) -> String {
    let parent = parent.trim_matches('/');
    let fragment = fragment.trim_matches('/');
    match (parent.is_empty(), fragment.is_empty()) {
        (true, true) => "/".to_owned(),
        (true, false) => format!("/{fragment}"),
        (false, true) => format!("/{parent}"),
        (false, false) => format!("/{parent}/{fragment}"),
    }
}

/// The coland extension operationIds advertised through `*.describe`.
///
/// Raw transport handlers that cannot contribute an OpenAPI operation are
/// declared in a small registry. Every ordinary HTTP endpoint comes from the
/// live router document; duplicating one in the transport registry is rejected.
pub fn coland_extension_operation_ids() -> Vec<String> {
    let mut operation_ids = TRANSPORT_OPERATION_IDS
        .get_or_init(|| {
            serde_json::from_str(include_str!("transport_operation_ids.json")).map_err(|error| {
                format!("failed to parse transport operation-id registry: {error}")
            })
        })
        .as_ref()
        .unwrap_or_else(|error| panic!("{error}"))
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();

    let generated;
    let document = if let Some(document) = ARKRET_OPENAPI_DOC.get() {
        document
    } else {
        generated = product_openapi_surface_doc();
        &generated
    };
    let generated_operation_ids = document
        .get("paths")
        .and_then(Value::as_object)
        .into_iter()
        .flat_map(|paths| paths.values())
        .filter_map(Value::as_object)
        .flat_map(|path_item| {
            path_item
                .iter()
                .filter(|(method, _)| OPENAPI_METHODS.contains(&method.as_str()))
                .filter_map(|(_, operation)| operation.get("operationId"))
                .filter_map(Value::as_str)
        })
        .filter(|operation_id| operation_id.starts_with("org.arkret.coland."))
        .map(ToOwned::to_owned)
        .collect::<BTreeSet<_>>();
    if let Some(duplicate) = operation_ids.intersection(&generated_operation_ids).next() {
        panic!("transport operation-id registry duplicates live OpenAPI operation `{duplicate}`");
    }
    operation_ids.extend(generated_operation_ids);
    operation_ids.into_iter().collect()
}

/// Generate an OpenAPI document from the state-independent portion of the
/// production Salvo router. This is intentionally not cached: the served
/// document has its own cache, while inventory tests should inspect a fresh
/// router tree and detect route declaration drift.
pub fn product_openapi_surface_doc() -> Value {
    let router = crate::routing::openapi_surface_router();
    let generated = OpenApi::new("Arkret Service API", env!("CARGO_PKG_VERSION"))
        .openapi_version(OpenApiVersion::Version3_2)
        .merge_router(&router);
    let mut document = serde_json::to_value(generated)
        .unwrap_or_else(|error| panic!("failed to serialize product OpenAPI surface: {error:#}"));
    install_generated_query_operations(&router, &mut document);
    install_operation_selector_parameters(&mut document);
    document
}

/// Return the exact path/method registry from the state-independent portion of
/// the production router, including transport-specialized handlers that do not
/// contribute an OpenAPI operation.
pub fn product_registered_routes() -> anyhow::Result<BTreeMap<String, BTreeSet<String>>> {
    collect_registered_routes(&crate::routing::openapi_surface_router())
}

#[handler]
#[tracing::instrument(skip_all, fields(op = "org.arkret.coland.openapi.json"))]
pub async fn arkret_openapi_json(depot: &mut Depot, res: &mut Response) {
    let doc = depot
        .get_typed::<ArkretOpenApiDoc>()
        .expect("openapi doc injected");
    let spec = serde_json::to_vec_pretty(&doc.0).unwrap_or_else(|error| {
        tracing::error!(%error, "failed to render openapi json");
        b"{}\n".to_vec()
    });
    write_openapi_body(res, "application/json; charset=utf-8", spec);
}

#[handler]
#[tracing::instrument(skip_all, fields(op = "org.arkret.coland.openapi.yaml"))]
pub async fn arkret_openapi_yaml(depot: &mut Depot, res: &mut Response) {
    let doc = depot
        .get_typed::<ArkretOpenApiDoc>()
        .expect("openapi doc injected");
    let spec = serde_saphyr::to_string(&doc.0).unwrap_or_else(|error| {
        tracing::error!(%error, "failed to render openapi yaml");
        "{}\n".to_owned()
    });
    write_openapi_body(res, "application/yaml; charset=utf-8", spec.into_bytes());
}

fn write_openapi_body(res: &mut Response, content_type: &'static str, body: Vec<u8>) {
    res.headers_mut().insert(
        salvo::http::header::CONTENT_TYPE,
        content_type.parse().expect("valid OpenAPI content type"),
    );
    res.headers_mut().insert(
        salvo::http::header::CONTENT_LENGTH,
        body.len()
            .to_string()
            .parse()
            .expect("valid OpenAPI content length"),
    );
    res.write_body(body).ok();
}
