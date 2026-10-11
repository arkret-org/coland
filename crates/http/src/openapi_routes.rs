use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

use salvo::http::Method;
use salvo::prelude::*;
use serde_json::Value;

use crate::util::render_error;

#[derive(Clone)]
pub struct ArkretOpenApiDoc(pub Value);

/// Catch-all handler under `/_arkret/*` (and the deployment-local
/// `/_coland/*` operator + product namespace, which carries its own
/// catch-all and must answer errors identically).
///
/// Per `arkret-spec/spec/v1/zh/sync/api-conventions.md` §10:
/// * Unknown path -> `404 Not Found` + JSON envelope `{"error":{"code": "unrecognized_endpoint",
///   ...}}`.
/// * Known path, wrong method -> `405 Method Not Allowed` + JSON envelope `{"error":{"code":
///   "method_not_allowed", ...}}` AND the `Allow` response header MUST list the supported methods.
///
/// Salvo's own 405 logic doesn't populate `Allow`, so we do the
/// disambiguation here using the registered OpenAPI route table (see
/// [`KNOWN_ROUTES`] / [`allow_methods_for_path`]).
#[handler]
pub async fn api_not_found(req: &mut Request, res: &mut Response) {
    let path = req.uri().path();
    if let Some(methods) = allow_methods_for_path(path) {
        let allow = methods
            .iter()
            .map(|m| m.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        if let Ok(allow_value) = salvo::http::HeaderValue::from_str(&allow) {
            res.headers_mut()
                .insert(salvo::http::header::ALLOW, allow_value);
        }
        render_error(
            res,
            StatusCode::METHOD_NOT_ALLOWED,
            "method_not_allowed",
            "method not allowed",
        );
        return;
    }
    render_error(
        res,
        StatusCode::NOT_FOUND,
        "unrecognized_endpoint",
        "unrecognized endpoint",
    );
}

/// Map of registered route patterns → supported HTTP methods. Populated
/// once at startup from a direct walk of the live salvo router (see
/// [`cached_arkret_openapi_doc`] / `collect_registered_routes`) so that
/// [`api_not_found`] can decide whether to return 404
/// (`unrecognized_endpoint`) or 405 (`method_not_allowed` + `Allow` header)
/// for a given request path. This is deliberately independent of the
/// generated OpenAPI document, so 404/405 correctness never depends on
/// `#[endpoint]` annotation coverage.
///
/// Keys are route patterns with `{param}` segments, e.g.
/// `/_coland/self/spaces/{space_id}`. Pattern→URI matching is segment-based
/// (see [`pattern_matches_path`]) so concrete URIs like
/// `/_coland/self/spaces/ak:space:abc` resolve back to their declaring
/// pattern without any regex compilation.
static KNOWN_ROUTES: OnceLock<Vec<(String, Vec<Method>)>> = OnceLock::new();

pub fn populate_known_routes(registered_routes: &BTreeMap<String, BTreeSet<String>>) {
    let _ = KNOWN_ROUTES.get_or_init(|| {
        let mut out: Vec<(String, Vec<Method>)> = Vec::new();
        for (path, methods) in registered_routes {
            // The protocol surface (`/_arkret/...`, trust segments
            // self/gate/root/find/peer/open/edge) is spec-mandated to return
            // the canonical error envelope; the deployment-local
            // `/_coland/...` operator + product namespace carries its own
            // catch-all, so it participates in 404/405 disambiguation too —
            // otherwise the two mounts would answer wrong-method requests
            // differently. Other prefixes (`/health`, `/.well-known/...`) are
            // out of scope for the `unrecognized_endpoint` /
            // `method_not_allowed` contract.
            if !(path.starts_with("/_arkret/") || path.starts_with("/_coland/")) {
                continue;
            }
            let methods: Vec<Method> = methods
                .iter()
                .filter_map(|method| method_name_to_method(method))
                .collect();
            if methods.is_empty() {
                continue;
            }
            out.push((path.clone(), methods));
        }
        out
    });
}

fn method_name_to_method(method: &str) -> Option<Method> {
    Some(match method {
        "get" => Method::GET,
        "post" => Method::POST,
        "put" => Method::PUT,
        "delete" => Method::DELETE,
        "patch" => Method::PATCH,
        "head" => Method::HEAD,
        "options" => Method::OPTIONS,
        "query" => Method::QUERY,
        // TRACE is not part of the Arkret HTTP binding; exclude it so it
        // doesn't pollute the `Allow` header.
        "trace" => return None,
        _ => return None,
    })
}

/// Resolve a concrete request path to the list of HTTP methods supported
/// by any registered pattern that matches it. Returns `None` when the
/// path doesn't correspond to a known route (→ caller emits 404), or
/// `Some(methods)` otherwise (→ caller emits 405 with `Allow`).
fn allow_methods_for_path(path: &str) -> Option<Vec<Method>> {
    let routes = KNOWN_ROUTES.get()?;
    // `http::Method` doesn't implement `Ord`, so we collect into a `Vec`
    // and de-duplicate by string identity. The ordering used for the
    // emitted `Allow` header is the canonical CRUD order
    // (`METHOD_HEADER_ORDER`) so two distinct route patterns that
    // contribute the same method set yield a stable, comparable header.
    let mut all: Vec<Method> = Vec::new();
    let mut matched = false;
    for (pattern, methods) in routes {
        if pattern_matches_path(pattern, path) {
            matched = true;
            for m in methods {
                if !all.iter().any(|existing| existing == m) {
                    all.push(m.clone());
                }
            }
        }
    }
    if !matched {
        return None;
    }
    let mut sorted: Vec<Method> = Vec::with_capacity(all.len());
    for canonical in METHOD_HEADER_ORDER {
        if let Some(idx) = all.iter().position(|m| m == canonical) {
            sorted.push(all.remove(idx));
        }
    }
    // Append anything left over (shouldn't happen — protocol is bounded
    // to the canonical set) so we never silently drop methods.
    sorted.extend(all);
    Some(sorted)
}

pub(crate) fn is_registered_route(method: &Method, path: &str) -> bool {
    allow_methods_for_path(path).is_some_and(|methods| methods.iter().any(|item| item == method))
}

/// Canonical order for the `Allow` response header. Matches the order
/// the spec example uses (`Allow: POST, GET, ...`) so produced headers
/// are stable across runs and easy to diff in tests.
const METHOD_HEADER_ORDER: &[Method] = &[
    Method::QUERY,
    Method::GET,
    Method::HEAD,
    Method::POST,
    Method::PUT,
    Method::PATCH,
    Method::DELETE,
    Method::OPTIONS,
];

/// Segment-based match between an OpenAPI pattern (which may contain
/// `{param}` placeholders) and a concrete request path. Both must have
/// the same segment count; literal segments must compare byte-equal and
/// `{...}` segments accept any non-empty single segment.
///
/// Catchall wildcards (`{**rest}`) intentionally do not appear in the
/// route map — they're only used by the unrecognized-endpoint catch-all
/// itself and so should never participate in 405 disambiguation.
pub fn pattern_matches_path(pattern: &str, path: &str) -> bool {
    let pattern_parts: Vec<&str> = pattern.trim_matches('/').split('/').collect();
    let path_parts: Vec<&str> = path.trim_matches('/').split('/').collect();
    if pattern_parts.len() != path_parts.len() {
        return false;
    }
    for (p, q) in pattern_parts.iter().zip(path_parts.iter()) {
        if p.starts_with('{') && p.ends_with('}') {
            // `{...}` placeholder — accept any single non-empty segment.
            if q.is_empty() {
                return false;
            }
            continue;
        }
        if p != q {
            return false;
        }
    }
    true
}

#[handler]
pub async fn error_catcher(res: &mut Response, ctrl: &mut FlowCtrl) {
    let status = res.status_code.unwrap_or(StatusCode::NOT_FOUND);
    if !(status.is_client_error() || status.is_server_error()) {
        return;
    }
    if !(res.body_mut().is_none() || res.body_mut().is_error()) {
        return;
    }

    // error-code-registry.json alignment for typed-body extractor rejections
    // (`JsonBody<T>` surfaces a 400 StatusError caused by
    // `ParseError::SerdeJson`):
    //   * body parses as JSON but violates the declared schema contract (missing field / bad typed
    //     value) → 422 `schema_violation`;
    //   * body is not valid JSON at all (syntax / EOF) → 400 `param_invalid` — it never parsed, so
    //     `schema_violation` ("parsed input…") does not apply, and `bad_request` is not a
    //     registered code.
    if status == StatusCode::BAD_REQUEST
        && let salvo::http::ResBody::Error(status_error) = &res.body
        && let Some(parse_error) = status_error
            .cause
            .as_ref()
            .and_then(|cause| cause.downcast_ref::<salvo::http::ParseError>())
        && let salvo::http::ParseError::SerdeJson(serde_error) = parse_error
    {
        if serde_error.classify() == serde_json::error::Category::Data {
            let detail = format!("request body violates the declared schema: {serde_error}");
            render_error(
                res,
                StatusCode::UNPROCESSABLE_ENTITY,
                "schema_violation",
                &detail,
            );
        } else {
            let detail = format!("request body is not valid JSON: {serde_error}");
            render_error(res, StatusCode::BAD_REQUEST, "param_invalid", &detail);
        }
        ctrl.skip_rest();
        return;
    }

    let (code, message) = match status {
        StatusCode::NOT_FOUND => ("not_found", "not found"),
        StatusCode::METHOD_NOT_ALLOWED => ("method_not_allowed", "method not allowed"),
        StatusCode::UNSUPPORTED_MEDIA_TYPE => ("unsupported_media_type", "unsupported media type"),
        StatusCode::PAYLOAD_TOO_LARGE => ("payload_too_large", "payload too large"),
        StatusCode::TOO_MANY_REQUESTS => ("rate_limited", "rate limited"),
        StatusCode::INTERNAL_SERVER_ERROR => ("internal_error", "internal server error"),
        // Fallback for framework-originated client errors that carry no typed
        // AppError. `param_invalid` is the registered generic 400; other 4xx
        // statuses without a specific code also degrade to it rather than an
        // unregistered `bad_request`.
        _ if status.is_client_error() => ("param_invalid", "invalid request"),
        _ => ("internal_error", "internal server error"),
    };
    render_error(res, status, code, message);
    ctrl.skip_rest();
}

#[handler]
pub async fn wait_for_sync_token(
    req: &mut Request,
    depot: &mut Depot,
    res: &mut Response,
    ctrl: &mut FlowCtrl,
) {
    let header_name = salvo::http::header::HeaderName::from_static("x-arkret-wait-for");
    let values: Vec<_> = req.headers().get_all(&header_name).iter().collect();
    let query_alias = req.uri().query().is_some_and(|query| {
        url::form_urlencoded::parse(query.as_bytes())
            .any(|(name, _)| name == "wait_for" || name.starts_with("consistency"))
    });
    if values.is_empty() && !query_alias {
        ctrl.call_next(req, depot, res).await;
        return;
    }
    let operation = req
        .headers()
        .get("arkret-operation")
        .and_then(|value| value.to_str().ok())
        .and_then(arkret_wire::ServiceOperationId::from_wire);
    if query_alias
        || values.len() != 1
        || operation
            .filter(|op| op.matches_http_request(req.method().as_str(), req.uri().path()))
            .and_then(|op| op.wait_for_carrier("http_json"))
            != Some(("header", "X-Arkret-Wait-For"))
    {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "param_invalid",
            "unregistered or duplicate wait-for carrier",
        );
        return;
    }
    let Ok(header_value) = values[0].to_str() else {
        crate::error::render_error_with_reason_code(
            res,
            StatusCode::BAD_REQUEST,
            "param_invalid",
            "X-Arkret-Wait-For must be ASCII",
            arkret_wire::ReasonCode::INVALID_CURSOR,
            None,
        );
        return;
    };
    let token = header_value.trim();
    // The authenticated consumer performs typed purpose/expiry/binding
    // validation. Do not collapse an expired token to param_invalid here.
    if arkret_wire::Cursor::new(token.to_owned()).is_err() {
        crate::error::render_error_with_reason_code(
            res,
            StatusCode::BAD_REQUEST,
            "param_invalid",
            "exactly one cursor is required",
            arkret_wire::ReasonCode::INVALID_CURSOR,
            None,
        );
        return;
    }
    depot.insert_typed(WaitForSyncToken(token.to_owned()));
    ctrl.call_next(req, depot, res).await;
}

#[derive(Clone, Debug)]
pub struct WaitForSyncToken(pub String);

/// Unit tests for the `api_not_found` 404/405 disambiguation logic —
/// specifically [`pattern_matches_path`] and the supporting helpers.
/// Salvo wiring (the actual HTTP shape returned by the catch-all router)
/// is covered by the integration test
/// `framework_errors_use_problem_details` in `tests/http_api/openapi.rs`.
#[cfg(test)]
#[path = "openapi_routes_tests.rs"]
mod framework_error_routing_tests;
