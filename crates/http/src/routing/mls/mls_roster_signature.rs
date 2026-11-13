//! Historical recipient-Station signatures for the MLS Add roster ingress.
//! The caller still needs the governance store's exact accepted-cut checks.

use arkret_models_collaboration::mls_roster_authority::MlsAttestAddRequestBody;
use arkret_models_crypto::{KeyOperationSignature, peer_keypackage_claim_receipt_signing_bytes};
use arkret_models_identity::{AuthenticatedServiceResolution, DidDocument};
use arkret_wire::{DidCoreId, DidUrl, project_did_to_core_id};
use chrono::{DateTime, Utc};
use coland_http::error::AppError;

fn signature_invalid() -> AppError {
    crate::app_error!(
        SignatureInvalid,
        "MLS roster historical Station signature is invalid",
    )
}

fn dependency_unavailable() -> AppError {
    crate::app_error!(
        RevisionUnavailable,
        "MLS roster historical Station resolution is unavailable",
    )
}

fn verify_station_signature(
    station_id: &DidCoreId,
    signed_at: DateTime<Utc>,
    signature: &KeyOperationSignature,
    signing_bytes: &[u8],
    resolution: &AuthenticatedServiceResolution,
) -> Result<(), AppError> {
    if &resolution.service_id != station_id {
        return Err(signature_invalid());
    }
    let document =
        arkret_identity::authenticated_service_document_at(resolution, station_id, signed_at)
            .map_err(|_| dependency_unavailable())?;
    verify_signature_in_document(station_id, signature, signing_bytes, &document)
}

fn verify_signature_in_document(
    station_id: &DidCoreId,
    signature: &KeyOperationSignature,
    signing_bytes: &[u8],
    document: &DidDocument,
) -> Result<(), AppError> {
    if project_did_to_core_id(&document.id).ok().as_ref() != Some(station_id) {
        return Err(signature_invalid());
    }
    let method = DidUrl::new(signature.kid.as_str().to_owned()).map_err(|_| signature_invalid())?;
    if !method
        .as_str()
        .starts_with(&format!("{}#", document.id.as_str()))
    {
        return Err(signature_invalid());
    }
    arkret_identity::validate_verification_method_relationship(
        document,
        &method,
        &document.id,
        arkret_identity::DidVerificationRelationship::AssertionMethod,
    )
    .map_err(|_| signature_invalid())?;
    let public_key = arkret_identity::public_key_material_from_document(document, &method)
        .map_err(|_| signature_invalid())?
        .ed25519_bytes()
        .map_err(|_| signature_invalid())?;
    arkret_signatures::keypackages::verify_keypackage_signing_input(
        &public_key,
        method.as_str(),
        signing_bytes,
        signature,
    )
    .map_err(|_| signature_invalid())
}

/// RFC 9421 verifies the peer transport; these two independent historical
/// signatures bind the original claim receipt and the exact Add attestation.
/// Storage must still compare the accepted Commit, Welcome, Proposal and
/// immutable Genesis ref inside one transaction before installation.
pub(super) async fn verify_peer_attest_add_signatures(
    state: &crate::state::AppState,
    source_id: &DidCoreId,
    request: &MlsAttestAddRequestBody,
) -> Result<
    (
        AuthenticatedServiceResolution,
        AuthenticatedServiceResolution,
    ),
    AppError,
> {
    if &request.attestation.attestor_station_id != source_id {
        return Err(signature_invalid());
    }
    request
        .validate_claim_binding()
        .map_err(|_| signature_invalid())?;
    let resolution = crate::routing::identity::agents::evidence::fetch_service_resolution(
        state, source_id, None,
    )
    .await
    .map_err(|_| dependency_unavailable())?;
    let receipt = &request.claim_outcome.claim_receipt;
    let claim_resolution = if &receipt.destination_id == source_id {
        resolution.clone()
    } else {
        crate::routing::identity::agents::evidence::fetch_service_resolution(
            state,
            &receipt.destination_id,
            None,
        )
        .await
        .map_err(|_| dependency_unavailable())?
    };
    let receipt_bytes =
        peer_keypackage_claim_receipt_signing_bytes(receipt).map_err(|_| signature_invalid())?;
    verify_station_signature(
        &receipt.destination_id,
        receipt.claimed_at,
        &receipt.signature,
        &receipt_bytes,
        &claim_resolution,
    )?;
    let attestation = &request.attestation;
    let attestation_bytes = attestation
        .signing_bytes()
        .map_err(|_| signature_invalid())?;
    verify_station_signature(
        source_id,
        attestation.attested_at,
        &attestation.signature,
        &attestation_bytes,
        &resolution,
    )?;
    Ok((resolution, claim_resolution))
}

#[cfg(test)]
mod tests {
    use arkret_models_crypto::KeyOperationSignature;
    use arkret_models_identity::DidDocument;
    use arkret_wire::{Did, DidCoreId, project_did_to_core_id};
    use serde_json::json;

    use super::verify_signature_in_document;

    #[test]
    fn accepted_historical_station_signature_rejects_changed_bytes_and_wrong_station() {
        let did = Did::new("did:web:roster-fixture.example".to_owned()).unwrap();
        let station = project_did_to_core_id(&did).unwrap();
        let seed = [41_u8; 32];
        let signer = ed25519_dalek::SigningKey::from_bytes(&seed);
        let method = format!("{}#roster", did.as_str());
        let document: DidDocument = serde_json::from_value(json!({
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": did.as_str(),
            "verificationMethod": [{
                "id": method,
                "controller": did.as_str(),
                "type": "Multikey",
                "publicKeyMultibase": arkret_canonical::ed25519_pubkey_to_did_key_multibase(
                    signer.verifying_key().as_bytes()
                )
            }],
            "authentication": [method],
            "assertionMethod": [method],
            "service": [{
                "id": format!("{}#station", did.as_str()),
                "type": "ArkretService",
                "serviceEndpoint": "https://roster-fixture.example/",
                "serviceKind": "station"
            }]
        }))
        .unwrap();
        let bytes = b"ak.mls_add_authority_attestation.v1\n{\"fixture\":true}";
        let signature: KeyOperationSignature =
            arkret_signatures::keypackages::sign_keypackage_signing_input(&seed, &method, bytes)
                .unwrap();
        assert!(verify_signature_in_document(&station, &signature, bytes, &document).is_ok());
        assert!(verify_signature_in_document(&station, &signature, b"changed", &document).is_err());
        let other = DidCoreId::new("ak:did_core:web:other-station.example").unwrap();
        assert!(verify_signature_in_document(&other, &signature, bytes, &document).is_err());
        let mut wrong_controller = signature.clone();
        wrong_controller.kid =
            arkret_wire::NonEmptyString::new("did:web:other-station.example#roster".to_owned())
                .unwrap();
        assert!(
            verify_signature_in_document(&station, &wrong_controller, bytes, &document).is_err()
        );
        let mut revoked_assertion = serde_json::to_value(&document).unwrap();
        revoked_assertion["assertionMethod"] = json!([]);
        let revoked_assertion: DidDocument = serde_json::from_value(revoked_assertion).unwrap();
        assert!(
            verify_signature_in_document(&station, &signature, bytes, &revoked_assertion).is_err()
        );
    }
}
