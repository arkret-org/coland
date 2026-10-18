use coland_http::ratelimit::{RateLimiter, RateLimiterConfig, RateLimiterMiddleware};
use salvo::affix_state;
use salvo::cors::{Cors, CorsHandler};
use salvo::http::request::SecureMaxSize;
use salvo::http::{HeaderValue, Method};
use salvo::prelude::*;

use super::*;
use crate::state::AppState;

const ARKRET_OPERATION_HEADER: &str = "Arkret-Operation";

#[derive(Clone)]
struct OperationSelectorMiddleware;

#[async_trait]
impl Handler for OperationSelectorMiddleware {
    async fn handle(
        &self,
        req: &mut Request,
        depot: &mut Depot,
        res: &mut Response,
        ctrl: &mut FlowCtrl,
    ) {
        if req.method() == Method::OPTIONS {
            ctrl.call_next(req, depot, res).await;
            return;
        }
        let method = req.method().as_str();
        let path = req.uri().path();
        if !crate::openapi_routes::is_registered_route(req.method(), path) {
            ctrl.call_next(req, depot, res).await;
            return;
        }
        let binding_kind = if is_tus_operation_path(method, path) {
            arkret_wire::BindingKind::Tus
        } else {
            arkret_wire::BindingKind::HttpJson
        };
        let Ok(state) = depot.get_typed::<AppState>() else {
            ctrl.call_next(req, depot, res).await;
            return;
        };
        let candidates = if binding_kind == arkret_wire::BindingKind::Tus {
            [arkret_wire::ServiceOperationId::SelfBlobUploadCreateV1]
                .into_iter()
                .filter(|operation| locally_advertises(state, *operation, binding_kind))
                .collect::<Vec<_>>()
        } else {
            arkret_wire::ServiceOperationId::ALL
                .iter()
                .copied()
                .filter(|operation| operation.matches_http_request(method, path))
                .filter(|operation| locally_advertises(state, *operation, binding_kind))
                .collect::<Vec<_>>()
        };
        if candidates.is_empty()
            && !arkret_wire::ServiceOperationId::ALL
                .iter()
                .copied()
                .any(|operation| operation.matches_http_request(method, path))
            && !is_tus_operation_path(method, path)
        {
            ctrl.call_next(req, depot, res).await;
            return;
        }

        let mut header_values = req.headers().get_all(ARKRET_OPERATION_HEADER).iter();
        let first = header_values.next();
        if first.is_none() {
            let error = crate::app_error!(
                OperationSelectorRequired,
                "canonical Arkret HTTP requests require Arkret-Operation",
            );
            error.write(req, depot, res).await;
            ctrl.skip_rest();
            return;
        }
        let supplied = first
            .and_then(|value| value.to_str().ok())
            .and_then(arkret_wire::ServiceOperationId::from_wire);
        let duplicate_selector = header_values.next().is_some();
        let Some(selected) = supplied.filter(|operation| candidates.contains(operation)) else {
            let error = crate::app_error!(
                UnsupportedOperationVersion,
                "Arkret-Operation does not select an advertised operation version for this method and path",
            );
            error.write(req, depot, res).await;
            ctrl.skip_rest();
            return;
        };
        if duplicate_selector {
            let error = crate::app_error!(
                UnsupportedOperationVersion,
                "Arkret-Operation must occur exactly once",
            );
            error.write(req, depot, res).await;
            ctrl.skip_rest();
            return;
        }
        ctrl.call_next(req, depot, res).await;
        if res.status_code.unwrap_or(StatusCode::OK).is_success() {
            res.headers_mut().insert(
                ARKRET_OPERATION_HEADER,
                HeaderValue::from_static(selected.as_str()),
            );
        }
    }
}

fn is_tus_operation_path(method: &str, path: &str) -> bool {
    matches!(method, "POST" | "PATCH" | "HEAD" | "DELETE")
        && (path == "/_arkret/self/blob/resumable"
            || path.starts_with("/_arkret/self/blob/resumable/"))
}

fn locally_advertises(
    state: &AppState,
    operation: arkret_wire::ServiceOperationId,
    binding_kind: arkret_wire::BindingKind,
) -> bool {
    if crate::routing::system::describe::build_server_description(state)
        .supports_operation_binding(operation, binding_kind)
    {
        return true;
    }
    crate::routing::spaces::directory::DIRECTORY_OPERATION_BUNDLES
        .iter()
        .chain(crate::routing::identity::did::IDENTITY_REGISTRY_OPERATION_BUNDLES.iter())
        .any(|bundle_id| {
            arkret_wire::operation_bundle_descriptor(bundle_id).is_some_and(|bundle| {
                bundle.members.iter().any(|member| {
                    member.operation_id == operation && member.binding_kind == binding_kind
                })
            })
        })
}

pub fn router(state: AppState) -> Router {
    // Derive the limiter ceilings from the deployment posture (+ env overrides)
    // so the live `describe` policy and the enforced quota share one source.
    let rate_limiter_config = state.config().rate_limiter.clone();
    router_with_rate_limiter_config(state, rate_limiter_config)
}

pub fn router_with_rate_limiter_config(
    state: AppState,
    rate_limiter_config: RateLimiterConfig,
) -> Router {
    let max_request_size_bytes = state.config().max_request_size_bytes;
    router_with_rate_limiter_and_request_size_config(
        state,
        rate_limiter_config,
        max_request_size_bytes,
    )
}

pub fn router_with_rate_limiter_and_request_size_config(
    state: AppState,
    rate_limiter_config: RateLimiterConfig,
    max_request_size_bytes: usize,
) -> Router {
    // NOTE: CORS is NOT a router hoop. Router hoops only run on a matched
    // route, so any response produced by the Catcher (404/405 on an unmatched
    // path or wrong method, size/rate-limit short-circuits, handler errors that
    // fall through to `error_catcher`) would come back WITHOUT
    // `Access-Control-Allow-Origin` and the browser would report a CORS error
    // instead of the real status. The CORS layer is therefore attached at the
    // `Service` level (see `crate::service`), where salvo runs it even when no
    // route matches — so it can never be missed.
    // Make the caller-supplied rate-limiter config authoritative for the
    // runtime overlay the middleware actually enforces against. The limiter
    // middleware reads `state.settings().rate_limit` (the hot-swappable admin
    // overlay) once `AppState` is injected below; `RuntimeSettings::from_config`
    // seeds that overlay from the environment (see `runtime_settings.rs`), so
    // without this reconciliation an explicit config passed through
    // `service_with_rate_limiter_config` (integration coverage of the A.3
    // ceilings) would be silently ignored whenever state is present. The
    // default `router()` path passes the same env-derived config the overlay was
    // seeded with, so this is a no-op there.
    {
        let mut settings = (*state.settings()).clone();
        settings.rate_limit =
            crate::runtime_settings::RateLimitSettings::from_limiter_config(&rate_limiter_config);
        settings.floor_rate_limit();
        state.replace_settings(settings);
    }
    let rate_limiter = RateLimiter::new(rate_limiter_config);
    let rate_limit_state = state.clone();
    let rate_limit_middleware = RateLimiterMiddleware::with_config_provider(
        rate_limiter,
        std::sync::Arc::new(move || rate_limit_state.settings().rate_limit.to_limiter_config()),
    );
    // COT-06-002 / service-http-binding.md §2.1.2: decide whether to expose the
    // test-only `/_arkret/_conformance/*` namespace before `state` is moved into
    // the affix hoop. The namespace is mounted only when the
    // service runs with `development_mode=true`; otherwise the
    // segment stays unknown and falls through to `api_not_found` (404
    // `unrecognized_endpoint`), exactly as §2.1.2 requires.
    let conformance_harness_enabled = conformance_harness_enabled(state.config());
    let third_party_invite_provider_enabled = state.config().third_party_invite_provider_enabled;
    let error_exposure = coland_http::error::ErrorExposure {
        development_mode: state.config().development_mode,
    };
    let router = Router::new()
        .hoop(crate::metrics::MetricsMiddleware)
        .hoop(third_party_invites::reject_url_credentials)
        // scalability-constraints.md 2.1.8 orders the Content-Encoding rejection (step 3)
        // ahead of every body read: an encoded body must fail 415 on the coding,
        // not 413 on a size it never legally had.
        .hoop(coland_http::content_encoding::RejectContentEncodingMiddleware)
        // SecureMaxSize only installs the bound used by Salvo's body reader;
        // it does not read the request. Install it before the wire-size hoop so
        // a no-Content-Length body is counted against 16 MiB instead of
        // Salvo's unrelated 64 KiB fallback.
        .hoop(SecureMaxSize::new(max_request_size_bytes))
        .hoop(
            coland_http::canonical_body::RequestWireSizeLimitMiddleware::new(
                max_request_size_bytes,
            ),
        )
        // Step 5: after the 16 MiB transport precheck, apply the independent
        // 8 MiB JCS-canonical operation-body bound to valid JSON.
        .hoop(coland_http::canonical_body::CanonicalJsonBodyLimitMiddleware)
        .hoop(affix_state::inject(error_exposure))
        .hoop(affix_state::inject(state))
        .hoop(rate_limit_middleware);
    let router = mount_application_routes(
        router,
        conformance_harness_enabled,
        third_party_invite_provider_enabled,
    );
    let doc = cached_arkret_openapi_doc(
        &router,
        serde_json::json!(coland_services::protocol_artifacts::registry_summary()),
    );
    router
        .unshift(
            Router::with_path(".well-known/arkret/openapi.yaml")
                .hoop(affix_state::inject(ArkretOpenApiDoc(doc.clone())))
                .get(arkret_openapi_yaml),
        )
        .unshift(
            Router::with_path(".well-known/arkret/openapi.json")
                .hoop(affix_state::inject(ArkretOpenApiDoc(doc)))
                .get(arkret_openapi_json),
        )
        .unshift(Router::new().get(home_page))
}

/// Build the same state-independent application route tree used by the live
/// service. OpenAPI inventory checks use this entry point so route coverage is
/// derived from production router declarations instead of a committed copy of
/// the generated document.
pub(crate) fn openapi_surface_router() -> Router {
    mount_application_routes(Router::new(), true, true)
}

fn mount_application_routes(
    router: Router,
    conformance_harness_enabled: bool,
    third_party_invite_provider_enabled: bool,
) -> Router {
    router
        .push(system::health_router())
        .push(interop::well_known_router())
        // Spec: B.3 — `/.well-known/arkret` server-description stub.
        .push(federation::well_known_arkret_router())
        .push(identity::embedded_webvh_public_router())
        // Admin surface lives at the deployment-local `/_coland/admin/*`
        // namespace (NOT under the `/_arkret/...` protocol prefix). Renamed
        // from the historical bare `/admin/*` to `/_coland/admin/*` so the
        // operator surface is unambiguously coland-local and cannot collide
        // with application-level routes. The four admin sub-routers below
        // still declare their paths relative to `admin/...`; the shared
        // `_coland` parent prepends the new namespace segment in one place.
        // Four sibling sub-trees are resolved by salvo fallthrough; ordering
        // matters only where paths overlap:
        //   1. `server_ops_router` — coland-local admin endpoints (server/status, accounts,
        //      devices, moderation/queue).
        //   2. `admin_router`  — operator surface (Realm and account administration).
        //   3. `router`        — collection (`/_coland/admin/{resource}`), cells, control-frames,
        //      retention.
        .push(
            Router::with_path("_coland")
                .push(admin::server_ops_router())
                .push(admin::admin_router())
                .push(admin::router())
                .push(coland_local_router()),
        )
        .push(arkret_protocol_router(
            conformance_harness_enabled,
            third_party_invite_provider_enabled,
        ))
}

/// Whether the development conformance harness is both compiled in and
/// enabled by configuration.
///
/// The harness is gated twice: `conformance-harness` decides whether the module
/// exists in this build, and `development_mode` decides whether it is mounted.
/// Without the feature the answer is unconditionally `false`, so the
/// `/_arkret/_conformance` segment stays unknown and falls through to
/// `api_not_found` exactly as it does with the feature on and dev mode off.
#[cfg(any(test, feature = "conformance-harness"))]
fn conformance_harness_enabled(config: &coland_http::config::AppConfig) -> bool {
    conformance::conformance_harness_enabled(config)
}

#[cfg(not(any(test, feature = "conformance-harness")))]
fn conformance_harness_enabled(_config: &coland_http::config::AppConfig) -> bool {
    false
}

/// Push the `/_arkret/_conformance/*` sub-router when the harness is active.
#[cfg(any(test, feature = "conformance-harness"))]
fn push_conformance_harness(router: Router, enabled: bool) -> Router {
    if enabled {
        router.push(conformance::router())
    } else {
        router
    }
}

#[cfg(not(any(test, feature = "conformance-harness")))]
fn push_conformance_harness(router: Router, _enabled: bool) -> Router {
    router
}

/// Protocol surface, mounted under the negative-space root `/_arkret/...`.
///
/// API-URL trust-namespace migration: the historical `/api/v1/*` +
/// `/arkret/v1/*` prefixes are gone. Every protocol path now lives under a
/// single `/_arkret/` root with no version segment (version is negotiated
/// via `*.describe` / registered operation bundles). The first path segment names
/// the trust concentric circle (self/gate/root/find/peer/open/edge); the
/// deployment-local operator surface stays separate at `/_coland/admin/*`.
///
/// Each module's `router()` declares its own trust segment in the paths it
/// pushes (e.g. `events::router()` returns `self/events/...`), so the parent
/// here only supplies the shared `_arkret` root.
fn arkret_protocol_router(
    conformance_harness_enabled: bool,
    third_party_invite_provider_enabled: bool,
) -> Router {
    let mut router = Router::with_path("_arkret")
        .hoop(OperationSelectorMiddleware)
        .hoop(wait_for_sync_token)
        .push(Router::with_path("ws").get(events::sync::websocket::upgrade))
        // `/_arkret/describe` (root meta). Integration describe is mounted
        // under `/_coland/self/integration/describe`.
        .push(system::router())
        // root/identity/*, self/account*, self/keys*, gate/account/*, etc.
        // (`identity::router()` declares its own trust segments.)
        .push(identity::router())
        // `self` — the principal's own authenticated session surface.
        .push(
            Router::with_path("self")
                // SPEC-CR-001 — RFC 9421 sender-constrained (PoP) verification:
                // verify any presented session signature, and use the embedded
                // operation registry to require PoP on high-security deployments.
                .hoop(identity::session_pop::verify_session_pop)
                // self/events/account/snapshot/projection/keys/authz/policy etc.
                .push(spaces::router())
                // self/events/*.
                .push(events::router())
                // self/streams/scan (ak.self.committed_event.read.scan.v1).
                .push(authority_commit::self_router())
                // self/realms/{realm_id}/streams, self/current-results/exact,
                // self/strands/watch/current, self/media-service-bindings/query.
                .push(self_current_reads::router())
                .push(call_admission::self_router())
                .push(management_review::router())
                // self/authz/*. (Owner-scoped policy
                // document CRUD lives on the product surface at
                // `/_coland/self/policies*`, see `coland_local_router`.)
                .push(access::router())
                // self/circles/* (ak.self.circle.*).
                .push(circles::router())
                // self/realms/{realm_id}/links
                // (ak.self.realm_link.*).
                .push(realms::router())
                .push(realm_join::self_router())
                .push(message_authoring::router())
                .push(invites::self_router())
                // self/realms/{realm_id}/organizations (ak.self.realm_organization.read.list.v1).
                .push(realm_organization::router())
                // G3.S1: MLS / keys lifecycle — spec-canonical path is
                // `/_arkret/self/keys/keypackages/*` (see `mls::router`).
                .push(mls::router()),
        )
        // `peer` — service-to-service federation surface.
        .push(
            Router::with_path("peer")
                .push(events::peer_router())
                .push(invites::peer_router())
                .push(identity::contact_federation::peer_router())
                .push(identity::peer_keys_router())
                .push(federation::erasure_receipts::router())
                .push(realm_join::peer_router())
                .push(call_admission::peer_router())
                .push(consent_private::peer_router())
                .push(mls::peer_router())
                // peer/streams/scan (ak.peer.committed_event.read.scan.v1).
                .push(authority_commit::peer_router()),
        )
        // `open` - unauthenticated, body-only handoff resolver surface.
        .push(
            Router::with_path("open")
                .push(system::open_router())
                .push(invites::open_router())
                .push(identity::agents::open_router())
                .push(identity::device_pairing_open::open_router())
                // open/realm-authority/bundle (ak.open.realm_authority.read.bundle.v1).
                .push(authority_commit::open_router()),
        )
        // `find` — directory discovery surface.
        .push(Router::with_path("find").push(spaces::find_router()))
        // edge/push/*, edge/applet, self/rtc/*, self/webrtc/*, self/blob/*,
        // self/moderation/*, open/mimi/* — `interop::router()` declares its
        // own trust segments.
        .push(interop::router());
    // Applet install/package and applet-service interop operations.
    router = router.push(extensions::protocol_router());
    if third_party_invite_provider_enabled {
        router = router.push(Router::with_path("open").push(third_party_invites::open_router()));
    }
    // COT-06-002 / service-http-binding.md §2.1.2: the test-only
    // `/_arkret/_conformance/*` namespace is mounted ONLY when the
    // `ak.profile.conformance_harness.v1` profile is active. In production it is
    // never pushed, so the segment stays unknown and the catch-all below returns
    // `404 unrecognized_endpoint` — no business logic, not advertised in
    // describe / OpenAPI production binding.
    router = push_conformance_harness(router, conformance_harness_enabled);
    // Catch-all so that anything under `/_arkret/...` that the typed
    // routers above don't match returns the canonical Arkret JSON
    // error envelope. `cors_preflight` is registered as an OPTIONS
    // child so CORS preflight stays 204; every other method falls
    // through to `api_not_found`, which itself decides between 404
    // (`unrecognized_endpoint`) and 405 (`method_not_allowed` + the
    // mandatory `Allow` header) based on whether the request path
    // pattern is registered in the OpenAPI route map. Using `.goal()`
    // (rather than per-method `.get/.post/...`) is what lets us
    // distinguish "unknown path, any method" from "known path, wrong
    // method" centrally instead of leaning on salvo's default 405
    // logic which has no way to populate the `Allow` header.
    router.push(
        Router::with_path("{**rest}")
            .options(cors_preflight)
            .goal(api_not_found),
    )
}

fn coland_local_router() -> Router {
    Router::new()
        // Reject protocol wait carriers on unregistered local operations.
        .hoop(wait_for_sync_token)
        .push(system::local_router())
        .push(identity::local_router())
        .push(events::account_authority_private_router())
        .push(
            Router::with_path("self")
                .hoop(identity::session_pop::verify_session_pop)
                .push(identity::account::local_router())
                // Product-private relation edge list
                // (`/_coland/self/relations`). See `events::local_router`.
                .push(events::local_router())
                // Owner-scoped policy document storage CRUD
                // (`/_coland/self/policies*`). This is deployment-local
                // management state and stays off the `/_arkret/...` protocol
                // root.
                .push(access::product_router())
                // Organization governance CRUD is deployment-local product
                // state; it must not occupy the `ak.self.*` protocol surface.
                .push(organizations::router()),
        )
        // `/_coland/find/directory/*` mirror retired — directory
        // discovery is served only from the canonical `/_arkret/find/...`
        // protocol tree (see `arkret_protocol_router`).
        //
        // `/_coland/peer/federation/*` read diagnostics retired — peer reads
        // are served only from the registered protocol federation track.
        .push(interop::local_router())
        // Catch-all for the `/_coland/...` tree, mirroring the `/_arkret/`
        // one: unmatched paths/methods get the canonical Arkret JSON error
        // envelope (404 `unrecognized_endpoint` / 405 `method_not_allowed`
        // + `Allow`) instead of salvo's bare defaults, so the local
        // namespace and the protocol tree answer errors identically. This
        // router is pushed last under the shared `_coland` parent, so the
        // catch-all is the final fallthrough for the whole namespace (admin
        // included).
        .push(
            Router::with_path("{**rest}")
                .options(cors_preflight)
                .goal(api_not_found),
        )
}

#[handler]
async fn home_page(res: &mut Response) {
    res.render(Text::Html(
        r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>coland</title>
  <style>
    body {
      margin: 0;
      min-height: 100vh;
      display: grid;
      place-items: center;
      font: 16px/1.5 system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      color: #172033;
      background: #f7f8fb;
    }
    main {
      text-align: center;
    }
    h1 {
      margin: 0 0 8px;
      font-size: 40px;
      letter-spacing: 0;
    }
    p {
      margin: 0;
      color: #586174;
    }
  </style>
</head>
<body>
  <main>
    <h1>it works</h1>
    <p>coland is running</p>
  </main>
</body>
</html>"#,
    ));
}

#[handler]
async fn cors_preflight(res: &mut Response) {
    res.status_code(StatusCode::NO_CONTENT);
}

/// Build a `CorsHandler` from the `COLAND_CORS_ALLOW_ORIGIN` config string.
///
/// API conventions section 10 requires an explicit allowlist for authenticated
/// endpoints. Configuration loading rejects wildcards; direct `AppConfig`
/// construction must also fail closed rather than mirror arbitrary origins.
pub(crate) fn cors_handler_for_origin_spec(raw: &str) -> CorsHandler {
    let mut entries: Vec<String> = raw
        .split(',')
        .map(|v| v.trim().to_owned())
        .filter(|v| !v.is_empty())
        .collect();
    if entries.iter().any(|v| v == "*") {
        entries.clear();
    }

    let base = Cors::new()
        .allow_methods(vec![
            Method::GET,
            Method::QUERY,
            Method::POST,
            Method::PUT,
            Method::PATCH,
            Method::DELETE,
            Method::HEAD,
            Method::OPTIONS,
        ])
        .allow_headers(vec![
            "authorization",
            "content-type",
            // Every canonical Arkret HTTP request selects its exact version.
            "arkret-operation",
            // RFC 9421 message signatures ride on every `/_arkret/self/*` and
            // `/_arkret/root/*` request the SDK signs; without these three the
            // browser preflight rejects the request before it reaches us.
            "signature",
            "signature-input",
            "content-digest",
            "dpop",
            "idempotency-key",
            "x-arkret-request-id",
            "x-arkret-wait-for",
            "range",
        ]);

    let refs: Vec<&str> = entries.iter().map(|s| s.as_str()).collect();
    let cors = base
        .allow_origin(refs)
        .allow_credentials(!entries.is_empty());

    cors.expose_headers(vec![
        "arkret-operation",
        "retry-after",
        "x-arkret-wait-for-satisfied",
        "content-range",
        "accept-ranges",
    ])
    .max_age(3600)
    .into_handler()
}

#[cfg(test)]
mod tests {
    use coland_storage_postgres::Db;

    use super::*;

    /// Live `/_arkret` routes as `(METHOD, path pattern)`, from a walk of the
    /// production router (not from the OpenAPI annotations).
    fn mounted_protocol_routes() -> Vec<(String, String)> {
        crate::openapi::product_registered_routes()
            .expect("production router walks")
            .into_iter()
            .filter(|(path, _)| path.starts_with("/_arkret/"))
            .flat_map(|(path, methods)| {
                methods
                    .into_iter()
                    .map(move |method| (method.to_ascii_uppercase(), path.clone()))
            })
            .collect()
    }

    fn is_mounted(routes: &[(String, String)], operation: arkret_wire::ServiceOperationId) -> bool {
        routes
            .iter()
            .any(|(method, path)| operation.matches_http_request(method, path))
    }

    /// Advertised JSON bundle members this Station does not mount. Each is a
    /// false claim: `service-surface.md` §3 allows advertising only bundles
    /// the deployment really implements. This existing implementation backlog
    /// must shrink as the remaining current-v1 operations are mounted.
    const KNOWN_ADVERTISED_UNMOUNTED: &[(&str, arkret_wire::ServiceOperationId)] = &[(
        "ak.operation_bundle.station.applet.v1",
        arkret_wire::ServiceOperationId::EdgeAppletManagedActorCommandAuthorV1,
    )];

    /// Advertised Station members served by the Account Authority of the
    /// same Station TCB: the deployment gateway routes pairing and issuer-
    /// ledger revocation to Coauth, while exact hard logout stays on Coland.
    /// These are not an implementation backlog for the bare Coland router.
    const SERVED_BY_ACCOUNT_AUTHORITY: &[arkret_wire::ServiceOperationId] = &[
        arkret_wire::ServiceOperationId::GateAccountCommandPairDeviceV1,
        arkret_wire::ServiceOperationId::GateAccountCommandRevokeSessionV1,
    ];

    /// `service-surface.md` §3: Describe advertises only bundles this
    /// deployment really implements, and the expanded `(operation_id,
    /// binding_kind)` union is the reachability source. Every advertised JSON
    /// member must therefore be mounted, and every mounted canonical route
    /// must be selectable; a mounted route the selector always refuses is
    /// dead, and an advertised member without a route is a false claim.
    #[test]
    fn advertised_operations_and_mounted_routes_agree() {
        let mut config = crate::config::AppConfig::test_default();
        config.third_party_invite_provider_enabled = true;
        config.account_authority_url = Some("https://auth.example/".into());
        let state = AppState::new(config, Db { pool: None });
        let routes = mounted_protocol_routes();
        let description = crate::routing::system::describe::build_server_description(&state);
        let mut unmounted = Vec::new();
        for bundle_id in &description.supported_operation_bundles {
            let bundle = arkret_wire::operation_bundle_descriptor(bundle_id)
                .unwrap_or_else(|| panic!("unregistered advertised bundle {bundle_id}"));
            for member in bundle.members {
                if member.binding_kind == arkret_wire::BindingKind::HttpJson
                    && !SERVED_BY_ACCOUNT_AUTHORITY.contains(&member.operation_id)
                    && !is_mounted(&routes, member.operation_id)
                {
                    unmounted.push((bundle_id.as_str(), member.operation_id));
                }
            }
        }
        unmounted.sort_by_key(|(bundle, operation)| (*bundle, operation.as_str()));
        assert_eq!(
            unmounted, KNOWN_ADVERTISED_UNMOUNTED,
            "advertised but unmounted bundle members changed"
        );
        assert!(
            !unmounted.iter().any(|(_, operation)| {
                *operation == arkret_wire::ServiceOperationId::PeerCommittedEventReadScanV1
            }),
            "the peer stream scan is mounted"
        );

        // Registered operations mounted here but selectable by no advertised
        // bundle are refused before dispatch on every call: none may exist.
        let dead = arkret_wire::ServiceOperationId::ALL
            .iter()
            .copied()
            .filter(|operation| is_mounted(&routes, *operation))
            .filter(|operation| {
                !locally_advertises(&state, *operation, arkret_wire::BindingKind::HttpJson)
                    && !locally_advertises(&state, *operation, arkret_wire::BindingKind::Websocket)
            })
            .collect::<Vec<_>>();
        assert!(
            dead.is_empty(),
            "mounted operations the selector refuses: {dead:?}"
        );
    }

    #[test]
    fn peer_stream_scan_and_delivery_status_are_selectable() {
        let state = AppState::new(crate::config::AppConfig::test_default(), Db { pool: None });
        for operation in [
            arkret_wire::ServiceOperationId::PeerCommittedEventReadScanV1,
            arkret_wire::ServiceOperationId::SelfEventsReadDeliveryStatusV1,
        ] {
            assert!(
                locally_advertises(&state, operation, arkret_wire::BindingKind::HttpJson),
                "{operation}"
            );
        }
    }

    /// The selector admits the core delivery-status read, so the request is
    /// dispatched and authenticates instead of being refused pre-dispatch.
    #[tokio::test]
    async fn delivery_status_selector_dispatches_to_the_authenticated_read() {
        use salvo::test::{ResponseExt as _, TestClient};

        let service = crate::service(AppState::new(
            crate::config::AppConfig::test_default(),
            Db { pool: None },
        ));
        let mut response = TestClient::query("http://server/_arkret/self/events/delivery-status")
            .add_header(
                "Arkret-Operation",
                arkret_wire::ServiceOperationId::SELF_EVENTS_READ_DELIVERY_STATUS_V1,
                true,
            )
            .json(&serde_json::json!({"event_id": "ak:event:AdP2S6y0Ms7yp9-GNvXZ3sVfvTEo8mtnV3G_RfApIOn0"}))
            .send(&service)
            .await;
        let body: serde_json::Value = response.take_json().await.expect("problem body");
        assert_eq!(
            response.status_code,
            Some(StatusCode::UNAUTHORIZED),
            "{body}"
        );
        assert_eq!(
            body["type"], "https://arkret.org/problems/unauthenticated",
            "{body}"
        );
    }

    /// The four self current reads are selectable and reach the
    /// authenticated handler instead of the unrecognized-endpoint catch-all.
    #[tokio::test]
    async fn self_current_reads_dispatch_to_authenticated_handlers() {
        use salvo::test::{ResponseExt as _, TestClient};

        let service = crate::service(AppState::new(
            crate::config::AppConfig::test_default(),
            Db { pool: None },
        ));
        let realm = "ak:realm:AUGIFvQctz4TjQTmvvO4Wdy-xdc5XP2ZnJ5Qpbh4s8Ru";
        for (operation, request) in [
            (
                arkret_wire::ServiceOperationId::SELF_REALM_READ_STREAMS_V1,
                TestClient::get(format!("http://server/_arkret/self/realms/{realm}/streams")),
            ),
            (
                arkret_wire::ServiceOperationId::SELF_CURRENT_RESULTS_READ_EXACT_V1,
                TestClient::post("http://server/_arkret/self/current-results/exact")
                    .json(&serde_json::json!({})),
            ),
            (
                arkret_wire::ServiceOperationId::SELF_STRAND_WATCH_READ_CURRENT_V1,
                TestClient::post("http://server/_arkret/self/strands/watch/current")
                    .json(&serde_json::json!({})),
            ),
            (
                arkret_wire::ServiceOperationId::SELF_MEDIA_SERVICE_BINDING_READ_RESOLVE_V1,
                TestClient::post("http://server/_arkret/self/media-service-bindings/query")
                    .json(&serde_json::json!({})),
            ),
        ] {
            let state = AppState::new(crate::config::AppConfig::test_default(), Db { pool: None });
            let operation_id = arkret_wire::ServiceOperationId::from_wire(operation).unwrap();
            assert!(
                locally_advertises(&state, operation_id, arkret_wire::BindingKind::HttpJson),
                "{operation}"
            );
            let mut response = request
                .add_header("Arkret-Operation", operation, true)
                .send(&service)
                .await;
            let body: serde_json::Value = response.take_json().await.expect("problem body");
            assert_eq!(
                response.status_code,
                Some(StatusCode::UNAUTHORIZED),
                "{operation}: {body}"
            );
            assert_eq!(
                body["type"], "https://arkret.org/problems/unauthenticated",
                "{operation}: {body}"
            );
        }
    }

    #[tokio::test]
    async fn peer_watch_current_is_advertised_and_reaches_the_signature_gate() {
        use salvo::test::{ResponseExt as _, TestClient};
        let state = AppState::new(crate::config::AppConfig::test_default(), Db { pool: None });
        let operation = arkret_wire::ServiceOperationId::PeerStrandWatchReadCurrentV1;
        assert!(locally_advertises(
            &state,
            operation,
            arkret_wire::BindingKind::HttpJson
        ));
        let source =
            arkret_wire::DidCoreId::new("ak:did_core:web:remote-watch-reader.example").unwrap();
        let destination = state.service_core_id();
        let domain = state.config().trust_domain.to_string();
        let body = serde_json::json!({"realm_id":"ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19", "strand_id":"ak:strand:AdP2S6y0Ms7yp9-GNvXZ3sVfvTEo8mtnV3G_RfApIOn0", "watcher_actor_id":arkret_wire::ActorId::account(arkret_wire::AccountId::new(source.clone(),source.clone()))});
        let service = crate::service(state);
        let mut response = TestClient::post("http://server/_arkret/peer/strands/watch/current")
            .add_header("Arkret-Operation", operation.as_str(), true)
            .add_header("Source-Service-ID", source.as_str(), true)
            .add_header("Destination-Service-ID", destination.as_str(), true)
            .add_header("Source-Trust-Domain", &domain, true)
            .add_header("Destination-Trust-Domain", &domain, true)
            .add_header(
                "Content-Digest",
                crate::routing::federation::rfc9530_content_digest(
                    &arkret_canonical::canonical_json_bytes(&body).unwrap(),
                ),
                true,
            )
            .json(&body)
            .send(&service)
            .await;
        let problem: serde_json::Value = response.take_json().await.unwrap();
        assert!(!response.status_code.unwrap().is_success());
        assert_ne!(
            problem["type"],
            "https://arkret.org/problems/unrecognized_endpoint"
        );
        assert_ne!(
            problem["type"],
            "https://arkret.org/problems/unsupported_operation_version"
        );
    }

    #[test]
    fn device_pairing_selectors_are_reachable_through_the_registered_bundle() {
        let state = AppState::new(crate::config::AppConfig::test_default(), Db { pool: None });
        let operations = [
            arkret_wire::ServiceOperationId::OpenDevicePairingCommandStageV1,
            arkret_wire::ServiceOperationId::OpenDevicePairingReadResolveV1,
            arkret_wire::ServiceOperationId::OpenDevicePairingReadStatusV1,
        ];

        for operation in operations {
            assert!(locally_advertises(
                &state,
                operation,
                arkret_wire::BindingKind::HttpJson,
            ));
            assert!(operation.matches_http_request("POST", operation.descriptor().http_path));
        }
    }
}
