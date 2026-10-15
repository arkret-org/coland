//! Verify an exact compact binding using an independently anchored issuer key.

use arkret_signatures::media::{ParticipantBindingContext, participant_binding_signing_input};
use ed25519_dalek::{Signature, VerifyingKey};

pub(crate) fn verify_binding_signature(
    context: &ParticipantBindingContext<'_>,
    sig: &str,
    verifying_key: &VerifyingKey,
) -> bool {
    let Ok(bytes) = arkret_canonical::base64url_decode(sig) else {
        return false;
    };
    let Ok(signature) = Signature::from_slice(&bytes) else {
        return false;
    };
    let Ok(input) = participant_binding_signing_input(context) else {
        return false;
    };
    verifying_key.verify_strict(&input, &signature).is_ok()
}
