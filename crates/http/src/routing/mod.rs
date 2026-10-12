use crate::wire::now;

mod access;
mod account_data_encryption;
mod admin;
pub(crate) mod agent_participation;
mod authority_commit;
#[cfg(feature = "conformance-harness")]
pub(crate) use authority_commit::{submission_kind_class, trace_submission_refusal};
// AKP-0007 (P2A.3) — `/_arkret/self/circles/*` admin surface.
pub(crate) mod circles;
#[cfg(any(test, feature = "conformance-harness"))]
pub(crate) mod conformance;
pub(crate) mod events;
// Protocol Applet bridge.
pub mod extensions;
pub mod federation;
pub(crate) mod identity;
mod interop;
pub(crate) use interop::moderation::validate_franking_covering_commit;
pub(crate) mod invites;
// G3.S1: MLS lifecycle (KeyPackage claim, Welcome to-device, commit_epoch).
pub(crate) mod mls;
pub(crate) mod organizations;
pub(crate) mod realms;
pub(crate) mod spaces;
pub(crate) mod system;
// SOL-ORG-06: realm organization-relationship read surface
mod management_review;
pub(crate) mod message_authoring;
pub(crate) mod realm_join;
pub(crate) mod realm_organization;
mod self_current_reads;
mod third_party_invites;

use access::policy::policy_document_to_response;
pub(crate) use admin::audit::append_audit_log;
#[cfg(test)]
use coland_http::util::validate_space_id;
use coland_http::util::{
    bearer_token, dpop_token, is_valid_sha256_hex, query_param, render_error, sha256_hex,
    validate_device_id, validate_did,
};
#[cfg(any(test, feature = "conformance-harness"))]
use coland_http::util::{handle_for_did, normalize_localpart};
use events::operations::validate_canonical_json_value;
#[cfg(test)]
use events::operations::validate_operation_semantics;
use events::projection::projection_event_from_operation;
use events::strand::{
    discussion_track_for_projection_event, strand_id_for_projection_event, strand_id_from_realm_id,
    strand_projection_for_realm,
};
use events::sync::SyncCursorError;
use identity::auth::{auth_or_render, authenticated_session};
#[cfg(test)]
use spaces::space::realm_allows_plaintext_service_for_data_class;
use spaces::space::{
    is_realm_deleted, realm_discoverability, realm_event_visible_to_session, realm_has_member,
    realm_history_access, realm_id_accessible,
};
use system::extract::AuthArgs;

const ARKRET_OPERATION_HEADER: &str = "Arkret-Operation";

/// Select the exact canonical operation on outbound Arkret HTTP calls.
///
/// Coauth validates this header before its handlers run, so every Coland ->
/// Account Authority request must use the same generated operation id that
/// selected the route locally.
pub(crate) fn with_arkret_operation(
    builder: reqwest::RequestBuilder,
    operation_id: &'static str,
) -> reqwest::RequestBuilder {
    builder.header(ARKRET_OPERATION_HEADER, operation_id)
}

// Router construction (router builders, CORS handler, root/preflight handlers).
mod router_build;
// OpenAPI document construction + the coland-extension operation table.
// 404/405 disambiguation, framework error catcher, sync-token guard, and the
// `ArkretOpenApiDoc` depot type.
// Snapshot manifest builders + small inventory/token helpers.
mod realm_state_snapshot;

// Public router entry points (`crate::routing::router` and the rate-limiter /
// request-size variants stay reachable at the same paths for `lib.rs`).
// OpenAPI internals + 404/405 helpers shared across the routing children. The
// glob re-exports keep these reachable from `super::*` in the child modules
// (and from `wire.rs` via `crate::routing::coland_extension_operation_ids`).
pub(crate) use coland_http::openapi::coland_extension_operation_ids;
use coland_http::openapi::{arkret_openapi_json, arkret_openapi_yaml, cached_arkret_openapi_doc};
// Framework error catcher + OpenAPI doc depot type consumed by `crate::service`
// and `crate::routing` children.
pub use coland_http::openapi_routes::ArkretOpenApiDoc;
pub(crate) use coland_http::openapi_routes::error_catcher;
use coland_http::openapi_routes::{api_not_found, wait_for_sync_token};
/// Boot-time worker re-export (`events` is crate-private; `main` only needs
/// this one entry point from it).
pub use events::sync::acquire_native_message_reply_cut;
pub use events::sync::{
    spawn_account_data_change_retention_sweeper, spawn_sync_cursor_ttl_sweeper,
};
pub(crate) use interop::{MAX_BLOB_UPLOAD_BYTES, push_target_privacy_derivation_claim};
pub use interop::{spawn_public_push_revoke_retry_worker, spawn_resumable_upload_ttl_sweeper};
// Snapshot manifest builder reachable from children and other crate modules
// via `crate::routing::*`.
pub(crate) use realm_state_snapshot::realm_state_snapshot_manifest_for_realm;
// CORS handler consumed by `crate::service`.
pub(crate) use router_build::{cors_handler_for_origin_spec, openapi_surface_router};
pub use router_build::{
    router, router_with_rate_limiter_and_request_size_config, router_with_rate_limiter_config,
};

#[cfg(test)]
mod outbound_operation_selector_tests {
    #[test]
    fn outbound_arkret_request_carries_exact_operation_selector() {
        let request = super::with_arkret_operation(
            reqwest::Client::new().post("http://127.0.0.1/_arkret/gate/account/logout"),
            arkret_wire::ServiceOperationId::GATE_ACCOUNT_COMMAND_LOGOUT_V1,
        )
        .build()
        .expect("request builds");

        assert_eq!(
            request
                .headers()
                .get(super::ARKRET_OPERATION_HEADER)
                .and_then(|value| value.to_str().ok()),
            Some(arkret_wire::ServiceOperationId::GATE_ACCOUNT_COMMAND_LOGOUT_V1)
        );
    }
}

#[cfg(test)]
#[path = "operation_conformance_tests.rs"]
mod operation_conformance_tests;

#[cfg(test)]
#[path = "canonical_conformance_vectors.rs"]
mod canonical_conformance_vectors;
