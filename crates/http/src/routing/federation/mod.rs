//! Federation surface helpers.
//!
//! The formal server-to-server HTTP surface is `/_arkret/peer/*`; this module
//! holds the trust-header, signature and outbound-dispatch utilities that
//! surface is built from, plus the operator seal-signing router.
//!
//! Production gaps: `validation_class` instead of bool and revocation fanout.

pub(crate) mod erasure_receipts;
mod mls_recipient_attestations;
mod outbound;
pub mod outbox;
pub mod outbox_operator;

mod signature;
pub(crate) mod well_known;
mod wire;

pub(crate) use outbound::{
    configured_peer_targets, resolved_peer_base_url, resolved_peer_route, resolved_peer_target,
};
#[cfg(test)]
use salvo::http::StatusCode;
// SPEC-CR-001 — `signature_authority` / `signature_target_uri` are reused by
// `identity::session_pop` so self-PoP and the federation rail reconstruct the
// signed `@target-uri` / `@authority` identically.
pub(in crate::routing) use signature::{
    VerifiedPeerKeyDigest, signature_authority, signature_target_uri,
    verify_inbound_peer_http_signature,
};
#[cfg(test)]
use signature::{validate_federation_headers, validate_signature_input};
pub use well_known::well_known_arkret_router;
pub(crate) use wire::FederationTrustHeaders;

#[cfg(test)]
#[path = "federation_tests.rs"]
mod tests;

/// RFC 9530 `Content-Digest` structured-field value over `bytes`:
/// `sha-256=:<base64(SHA256(bytes))>:`.
///
/// Single source of truth for the federation S2S surface — the outbound
/// dispatcher, the per-peer outbox, and the invite delivery rail all derive the
/// same header from this helper so the wire byte encoding / base64 variant can
/// never drift between sign and verify. Callers decide which bytes to feed (raw
/// body vs canonical JSON); this only maps `bytes -> header string`.
pub(crate) fn rfc9530_content_digest(bytes: &[u8]) -> String {
    coland_http::http_signature::rfc9530_content_digest(bytes)
}

/// DID verification method used by the service's persistent assertion key
/// for federation HTTP Message Signatures. Service identity bootstrap
/// publishes this method in the Provider-registered DID document.
pub fn federation_service_signature_key_id(service_did: &str) -> String {
    format!("{service_did}#federation-fanout-key")
}
