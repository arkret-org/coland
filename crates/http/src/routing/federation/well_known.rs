//! Federation discovery for the peer service surface.
//!
//! - `GET /.well-known/arkret` — server description. Spec-aligned shape so peers can discover the
//!   service DID, trust domain, public base URL, and fanout topology without an auth round-trip.
//!   The body is built from the live `AppConfig`; the route is unauthenticated.

use coland_http::result::{JsonResult, json_ok};
use salvo::prelude::*;
use serde::{Deserialize, Serialize};

use crate::state::AppState;

/// Build the `/.well-known/arkret` router. Mounted alongside the
/// existing `/.well-known/arkret/openapi.json` entry; salvo routes the
/// exact-match path here and falls through to the openapi router for
/// the `/openapi.{json,yaml}` siblings.
pub fn well_known_arkret_router() -> Router {
    Router::with_path(".well-known/arkret").get(well_known_arkret)
}

#[derive(salvo::oapi::ToSchema, Clone, Debug, Serialize, Deserialize)]
struct WellKnownArkretEndpoints {
    openapi: String,
    peer_events: String,
}

#[derive(salvo::oapi::ToSchema, Clone, Debug, Serialize, Deserialize)]
struct WellKnownArkretOutcome {
    schema: String,
    service_id: String,
    trust_domain: String,
    public_base_url: String,
    fanout_topology: String,
    endpoints: WellKnownArkretEndpoints,
    version: String,
}

#[endpoint(operation_id = "org.arkret.coland.well_known.arkret")]
#[tracing::instrument(skip_all, fields(op = "org.arkret.coland.well_known.arkret"))]
async fn well_known_arkret(depot: &mut Depot) -> JsonResult<WellKnownArkretOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    // Spec: B.3 — server description endpoint. Returns the small set
    // of identifiers a peer needs before opening an authenticated
    // session: service DID, trust domain, public base URL, and the
    // fanout topology advertised to peers. The body is deliberately
    // stable + minimal so cache/proxy layers can serve it without
    // re-validating on every request.
    let fanout_topology = state.settings().federation_fanout_topology.as_str();
    let public_base_url = state.config().public_base_url.trim_end_matches('/');
    json_ok(WellKnownArkretOutcome {
        schema: arkret_wire::SchemaId::SERVICE_DESCRIBE_V1.to_owned(),
        service_id: state.service_id().clone(),
        trust_domain: state.config().trust_domain.to_string(),
        public_base_url: state.config().public_base_url.clone(),
        fanout_topology: fanout_topology.to_owned(),
        endpoints: WellKnownArkretEndpoints {
            openapi: format!("{}/.well-known/arkret/openapi.json", public_base_url),
            peer_events: format!("{}/_arkret/peer/events", public_base_url),
        },
        version: env!("CARGO_PKG_VERSION").to_owned(),
    })
}
