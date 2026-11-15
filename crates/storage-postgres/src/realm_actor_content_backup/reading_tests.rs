//! Host-directory tests; original Commit crypto remains the SDK verifier's job.
use arkret_identity::{
    DidKeyResolver, DidResolver, RealmAuthorityKeyDirectory, RealmAuthorityKeyMap,
};
use arkret_models_identity::*;
use arkret_signatures::PublicKeyMaterial;
use arkret_wire::*;

use super::insert_archive_signature_key;

fn fixture() -> (AuthenticatedServiceResolution, DetachedObjectSignature) {
    let key = ed25519_dalek::SigningKey::from_bytes(&[118; 32]);
    let multibase =
        arkret_canonical::ed25519_pubkey_to_did_key_multibase(key.verifying_key().as_bytes());
    let did = Did::new(format!("did:key:{multibase}")).unwrap();
    let service_id = project_did_to_core_id(&did).unwrap();
    let document = DidKeyResolver::new().resolve_did(&did).unwrap().document;
    let head = arkret_canonical::sha256_digest(did.as_str().as_bytes());
    let version = format!(
        "synthetic-did-sha256:{}",
        head.trim_start_matches("sha256:")
    );
    let resolution = AuthenticatedServiceResolution {
        service_id,
        service_kind: ServiceKind::Station.as_str().into(),
        method_history_evidence: ResolutionMethodHistoryEvidence::DidKeyExpansion {
            boundary: ResolutionMethodEvidenceBoundary {
                from_method_history_head: head.clone(),
                to_method_history_head: head,
                from_version_id: version.clone(),
                to_version_id: version,
            },
            evidence: DidBindingEvidenceReceipt {
                kind: DidBindingEvidenceKind::AkDidBindingEvidenceV1,
                method: "key".into(),
                document_digest: normalized_did_document_digest(&document).unwrap(),
                method_proofs: vec![],
            },
        },
        normalized_did_document: document,
    };
    let signature = DetachedObjectSignature {
        context: DetachedSignatureContext::RealmCommit,
        signature_algorithm: DetachedSignatureAlgorithm::Ed25519,
        verification_method: DidUrl::new(format!("{did}#{multibase}")).unwrap(),
        signed_digest: Hash::new(arkret_canonical::sha256_digest(b"directory test only")).unwrap(),
        created_at: chrono::DateTime::parse_from_rfc3339("2026-11-15T00:00:00.000Z")
            .unwrap()
            .to_utc(),
        signature: Base64UrlString::new("c2lnbmF0dXJl").unwrap(),
    };
    (resolution, signature)
}

#[test]
fn archive_directory_pins_only_the_original_method_and_time() {
    let (history, signature) = fixture();
    let mut keys = RealmAuthorityKeyMap::new();
    insert_archive_signature_key(&mut keys, &[history], &signature).unwrap();
    assert!(keys.public_key(&signature.verification_method).is_none());
    assert!(
        keys.public_key_at(&signature.verification_method, signature.created_at)
            .is_some()
    );
    assert!(
        keys.public_key_at(
            &signature.verification_method,
            signature.created_at + chrono::Duration::milliseconds(1)
        )
        .is_none()
    );
    // Equivalent encodings of one already pinned key are not a conflict.
    let bytes = keys
        .public_key_at(&signature.verification_method, signature.created_at)
        .unwrap()
        .ed25519_bytes()
        .unwrap();
    keys.insert_at(
        &signature.verification_method,
        signature.created_at,
        PublicKeyMaterial::Ed25519Multibase {
            value: arkret_canonical::ed25519_pubkey_to_did_key_multibase(&bytes),
        },
    );
    let (history, _) = fixture();
    insert_archive_signature_key(&mut keys, &[history], &signature).unwrap();
}

#[test]
fn archive_directory_rejects_unknown_issuer_non_station_and_invalid_history() {
    let (history, signature) = fixture();
    for histories in [
        vec![],
        vec![AuthenticatedServiceResolution {
            service_id: DidCoreId::new("ak:did_core:web:other.example").unwrap(),
            ..history.clone()
        }],
        vec![AuthenticatedServiceResolution {
            service_kind: "applet".into(),
            ..history.clone()
        }],
        {
            let mut invalid = history.clone();
            invalid.normalized_did_document.id = Did::new("did:web:other.example").unwrap();
            vec![invalid]
        },
    ] {
        let mut keys = RealmAuthorityKeyMap::new();
        assert!(insert_archive_signature_key(&mut keys, &histories, &signature).is_err());
        assert!(keys.is_empty());
    }
    let mut wrong_method = signature.clone();
    wrong_method.verification_method = DidUrl::new(format!(
        "{}#unregistered",
        history.normalized_did_document.id
    ))
    .unwrap();
    assert!(
        insert_archive_signature_key(&mut RealmAuthorityKeyMap::new(), &[history], &wrong_method)
            .is_err()
    );
}

#[test]
fn archive_directory_rejects_conflicts_without_overwriting_the_pin() {
    let (history, signature) = fixture();
    let mut keys = RealmAuthorityKeyMap::new();
    keys.insert_at(
        &signature.verification_method,
        signature.created_at,
        PublicKeyMaterial::Ed25519Raw {
            bytes: vec![99; 32],
        },
    );
    let before = keys.clone();
    assert!(insert_archive_signature_key(&mut keys, &[history], &signature).is_err());
    assert_eq!(keys, before);
}

#[test]
fn archive_directory_uses_the_carrier_that_proves_the_method_at_the_original_time() {
    use arkret_models_identity::service_identity::{CanonicalServiceUrl, ServiceRegistrationKey};
    use arkret_signatures::webvh::{
        ServiceRegistrationInceptionInput, ServiceRotationInput,
        prepare_service_registration_inception, prepare_service_rotation,
    };
    use rand_core::SeedableRng as _;
    use serde_json::json;

    let (_, mut signature) = fixture();
    let at = signature.created_at;
    let mut rng = rand_chacha::ChaCha20Rng::from_seed([42; 32]);
    let registration = ServiceRegistrationKey::new(
        ServiceKind::Station,
        CanonicalServiceUrl::new("https://archive.example/").unwrap(),
    )
    .unwrap();
    let inception = prepare_service_registration_inception(
        &mut rng,
        &ServiceRegistrationInceptionInput {
            provider_endpoint: &"https://identity.example/".parse().unwrap(),
            registration_key: &registration,
            also_known_as: &[],
            version_created_at: at,
            did_key_fragment: None,
        },
    )
    .unwrap();
    let did = Did::new(inception.did.clone()).unwrap();
    let issuer = project_did_to_core_id(&did).unwrap();
    let earlier = arkret_identity::build_authenticated_webvh_service_resolution(
        issuer.clone(),
        ServiceKind::Station.as_str().into(),
        serde_json::from_value(inception.log_entry["state"].clone()).unwrap(),
        vec![inception.log_entry.clone()],
        vec![],
        at,
    )
    .unwrap();
    let method = DidUrl::new(format!("{did}#archive-added-key")).unwrap();
    let new_key = ed25519_dalek::SigningKey::from_bytes(&[119; 32]);
    let new_multibase =
        arkret_canonical::ed25519_pubkey_to_did_key_multibase(new_key.verifying_key().as_bytes());
    let mut state = inception.log_entry["state"].clone();
    state["verificationMethod"].as_array_mut().unwrap().push(json!({
        "id": method, "controller": did, "type": "Multikey", "publicKeyMultibase": new_multibase,
    }));
    state["assertionMethod"]
        .as_array_mut()
        .unwrap()
        .push(json!(method));
    let rotated = prepare_service_rotation(&ServiceRotationInput {
        did: did.as_str(),
        previous_entries: std::slice::from_ref(&inception.log_entry),
        state: &state,
        current_update_seed: &inception.next_update_key_seed,
        next_update_public_key_multibase: &arkret_canonical::ed25519_pubkey_to_did_key_multibase(
            ed25519_dalek::SigningKey::from_bytes(&[120; 32])
                .verifying_key()
                .as_bytes(),
        ),
        version_created_at: at + chrono::Duration::seconds(1),
    })
    .unwrap();
    let later = arkret_identity::build_authenticated_webvh_service_resolution(
        issuer,
        ServiceKind::Station.as_str().into(),
        serde_json::from_value(state).unwrap(),
        vec![inception.log_entry.clone(), rotated.log_entry],
        vec![],
        at + chrono::Duration::seconds(2),
    )
    .unwrap();
    signature.verification_method = method;
    signature.created_at = at + chrono::Duration::seconds(2);
    let mut keys = RealmAuthorityKeyMap::new();
    assert!(
        insert_archive_signature_key(&mut keys, std::slice::from_ref(&earlier), &signature)
            .is_err()
    );
    assert!(keys.is_empty());
    let histories = [earlier, later];
    insert_archive_signature_key(&mut keys, &histories, &signature).unwrap();
    assert_eq!(
        keys.public_key_at(&signature.verification_method, signature.created_at)
            .unwrap()
            .ed25519_bytes()
            .unwrap(),
        new_key.verifying_key().to_bytes()
    );
    // The complete later log must not authorize the new method before its entry.
    signature.created_at = at;
    assert!(
        insert_archive_signature_key(&mut RealmAuthorityKeyMap::new(), &histories, &signature)
            .is_err()
    );
}
