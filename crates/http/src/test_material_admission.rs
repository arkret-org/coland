//! Formal test-material rejection at Coland's production trust boundary.
//!
//! The canonical registry and matching rules live in `arkret-identity`.  This
//! module only adapts Coland's decoded DID-document representation to that
//! guard, so every caller fingerprints algorithm-defined public-key bytes
//! before a document, route, or accepted binding can be retained.

use arkret_identity::test_material::{
    PublicKeyFingerprintInput, enforce_formal_test_material_policy,
};
use arkret_wire::{Did, DidUrl, TrustDomainId};
use ed25519_dalek::VerifyingKey;

pub(crate) fn enforce_ed25519_admission(
    public_key: &VerifyingKey,
    did: &Did,
    verification_method: &DidUrl,
    trust_domain: Option<&TrustDomainId>,
) -> Result<(), String> {
    enforce_formal_test_material_policy(
        Some(&PublicKeyFingerprintInput::Ed25519Rfc8032(
            public_key.as_bytes(),
        )),
        Some(did),
        Some(verification_method),
        trust_domain,
    )
    .map_err(|error| error.to_string())
}

pub(crate) fn enforce_did_document_admission(
    document: &arkret_identity::DidDocument,
    trust_domain: Option<&TrustDomainId>,
) -> Result<(), String> {
    coland_services::identity::enforce_formal_did_document_admission(document, trust_domain)
}
