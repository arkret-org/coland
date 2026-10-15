use salvo::prelude::*;

mod blob;
mod blob_resumable;
mod mimi;
pub(crate) mod moderation;
pub(crate) mod participant_binding;
mod push;
mod push_handoff;
pub(crate) mod webrtc;

pub(crate) use blob::MAX_BLOB_UPLOAD_BYTES;
pub use blob_resumable::spawn_resumable_upload_ttl_sweeper;
pub(crate) use push::push_target_privacy_derivation_claim;
pub use push_handoff::spawn_public_push_revoke_retry_worker;
pub(crate) use push_handoff::unregister_for_hard_logout as unregister_public_push_for_hard_logout;

/// HMAC-SHA256 (RFC 2104) over `data` keyed by `key`.
///
/// Shared by the two interop surfaces that need a raw MAC: push target
/// pseudonym derivation (`push.rs`) and the LiveKit JWT / TURN credential
/// signatures (`webrtc.rs`, `bindings/livekit.md` §2). The station calls the
/// audited `hmac` crate directly rather than routing a five-line MAC through
/// an SDK feature.
pub(crate) fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    use hmac::{Hmac, KeyInit, Mac};
    use sha2::Sha256;

    let mut mac =
        <Hmac<Sha256> as KeyInit>::new_from_slice(key).expect("HMAC accepts keys of any length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

use super::admin::audit;
use super::{
    append_audit_log, auth_or_render, authenticated_session, is_valid_sha256_hex, now, query_param,
    render_error, sha256_hex, validate_device_id,
};

pub fn router() -> Router {
    protocol_router()
}

pub fn protocol_router() -> Router {
    Router::new()
        // `edge` — Station-owned push registration surface.
        .push(
            Router::with_path("edge").push(
                Router::new()
                    .push(Router::with_path("push/register-device").post(push::push_register))
                    .push(Router::with_path("push/unregister-device").post(push::push_unregister)),
            ),
        )
        // `self` — RTC, blob, moderation report.
        .push(
            Router::with_path("self")
                .push(webrtc::protocol_router())
                .push(blob::router())
                .push(blob_resumable::router())
                .push(moderation::protocol_router()),
        )
        // `open` — non-Arkret external vendor interop (MIMI).
        .push(Router::with_path("open").push(mimi::router()))
}

pub fn local_router() -> Router {
    Router::new()
    // NOTE: the MIMI provider facade is served only from its canonical
    // `/_arkret/open/mimi/*` surface (see `protocol_router` / `mimi.rs`).
    // The historical `/_coland/open/mimi/*` duplicate mount had no caller and
    // was removed; MIMI providers discover the surface via the well-known
    // `mimi-protocol-directory`, not this vendor namespace.
}

pub fn well_known_router() -> Router {
    mimi::well_known_router()
}
