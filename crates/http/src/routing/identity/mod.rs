use salvo::prelude::*;

pub(crate) mod account;
pub(crate) mod account_authority_client;
pub(crate) mod account_data;
pub(crate) mod agents;
pub(crate) mod applet_managed_device;
pub(crate) mod auth;
// api-conventions.md §3.3 — `/_arkret/self/*` inbound credential: a
// `ak.session.grant` presented directly with a DPoP (RFC 9449) holder proof,
// validated against a TTL-cached coauth introspection. The default ② session
// path has no local credential issuance step.
pub(crate) mod auth_grant_dpop;
pub(crate) mod consent;
pub(crate) mod contact_federation;
pub(crate) mod current_signer_evidence;
pub(crate) mod device_generation;
pub(crate) mod device_messages;
pub(crate) mod device_pairing_open;
pub(crate) mod device_signing;
pub(super) mod did;
pub(in crate::routing) mod key_backup;
pub(crate) mod keys;
pub(crate) use keys::{device_signature_kid_points_to_device_key, peer_router as peer_keys_router};
pub(crate) mod agent_pcr;
mod organization_registration;
// R3 spec-sync (arkret-spec b47ff6ec) — recovery policy / receipt
// endpoints (HTTP-4 / REC-1).
pub(crate) mod recovery;
mod service_registration;
// SPEC-CR-001 — RFC 9421 sender-constrained (PoP) verification hoop for the
// `/_arkret/self/*` surface. pub(in crate::routing) so `routing::mod` can mount
// `verify_session_pop` on the self routers.
pub(crate) mod session_actor;
pub(in crate::routing) mod session_pop;
pub(crate) mod webvh_validation;

use super::system::describe;
use super::{
    AuthArgs, SyncCursorError, append_audit_log, bearer_token, dpop_token, now, render_error,
    sha256_hex, validate_did,
};
#[cfg(any(test, feature = "conformance-harness"))]
use super::{handle_for_did, normalize_localpart, validate_device_id};

pub fn router() -> Router {
    protocol_router()
}

pub fn protocol_router() -> Router {
    Router::new()
        .push(
            Router::with_path("gate")
                .push(auth::protocol_account_router())
                .push(Router::with_path("account").push(agents::agent_key_pair_router())),
        )
        .push(
            Router::with_path("root").push(
                Router::with_path("identity")
                    .push(Router::with_path("describe").get(did::identity_describe))
                    .push(Router::with_path("resolve").post(did::identity_resolve))
                    .push(Router::with_path("document").get(did::identity_document))
                    .push(Router::with_path("log").get(did::identity_log))
                    .push(
                        Router::with_path("service-registrations:ensure")
                            .post(service_registration::ensure),
                    )
                    .push(Router::with_path("service-registrations").get(service_registration::get))
                    .push(
                        Router::with_path("organization-registrations:prepare")
                            .post(organization_registration::prepare),
                    )
                    .push(
                        Router::with_path("organization-registrations:ensure")
                            .post(organization_registration::ensure),
                    )
                    .push(
                        Router::with_path("organization-registrations")
                            .get(organization_registration::get),
                    )
                    .push(
                        Router::with_path("organization-registrations:refresh")
                            .post(organization_registration::refresh),
                    )
                    .push(
                        Router::with_path("organization-registrations:revoke")
                            .post(organization_registration::revoke),
                    )
                    .push(
                        Router::with_path("submit-did-operation")
                            .post(did::identity_submit_did_operation),
                    )
                    .push(Router::with_path("receipts").get(did::identity_receipts)),
            ),
        )
        // SOL-06-001: recovery_session.* is a core-tier protocol surface; mount
        // the spec-canonical recovery-sessions routes under /_arkret/root.
        .push(Router::with_path("root").push(recovery::protocol_router()))
        .push(
            Router::with_path("self")
                .push(account::protocol_router())
                // Spec `account_data` group (`ak.self.account_data.*`).
                .push(account_data::router())
                // Spec `consent` group (`ak.self.consent.*`).
                .push(consent::router())
                .push(current_signer_evidence::self_router())
                .push(keys::router())
                .push(key_backup::protocol_router())
                .push(recovery::self_protocol_router())
                .push(device_messages::protocol_router())
                .push(agents::protocol_router()),
        )
}

pub fn local_router() -> Router {
    Router::new()
        // Product-private authentication entry. Canonical account operations
        // are exposed only by `protocol_router` under `/_arkret`.
        .push(
            Router::with_path("gate")
                .push(auth::router())
                // Deployment-private durable account projection, invoked by
                // the Account Authority after canonical registration.
                .push(account::local_gate_router()),
        )
        // Server-to-server device signing-key directory read at
        // `/_coland/gate/account/device-signing-keys/query`. The Account Authority process
        // (coauth) calls this while verifying a device holder proof
        // (session-grant refresh / soft-logout restore): the holder key is the
        // `ak.device.authorize`-authorized device signing key projected into
        // this Station's directory, NOT a DID-document
        // verificationMethod. Bearer-gated (see `keys::product_router`).
        .push(keys::product_router())
        .push(account::local_service_router())
        .push(Router::with_path("root").push(recovery::router()))
}

pub(super) fn embedded_webvh_public_router() -> Router {
    Router::with_path("webvh")
        .push(Router::with_path("{local_id}/did.json").get(did::embedded_webvh_document))
        .push(Router::with_path("{local_id}/did.jsonl").get(did::embedded_webvh_log))
}
