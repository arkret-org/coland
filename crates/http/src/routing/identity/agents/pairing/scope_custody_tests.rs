//! Private encryption tests. Imported accepted references are not pairing admission.

use arkret_keystore::{EncryptedFileKeyStore, KeyStore as _};

use super::*;

fn state_with_store(store: std::sync::Arc<EncryptedFileKeyStore>) -> AppState {
    AppState::new(
        crate::config::AppConfig::test_default(),
        coland_storage_postgres::Db { pool: None },
    )
    .with_verifier_private_keystore(store)
}

fn imported_material(state: &AppState) -> AgentScopeCustodyMaterial {
    let (command, accepted_binding, runtime_key_binding_digest) =
        super::super::tests::imported_scope_custody_fixture(state.service_id());
    let request_digest = agent_key_pair_request_digest(&command).unwrap();
    let material = AgentScopeCustodyMaterial {
        command,
        accepted_binding,
        runtime_key_binding_digest,
        request_digest,
    };
    validate_custody_material(&material, state).unwrap();
    material
}

#[test]
fn encrypted_receipt_reopens_after_presentation_expiry_without_material_keystore_copy() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("vault");
    let master = rand::random();
    let store = std::sync::Arc::new(
        EncryptedFileKeyStore::new(&path, crate::config::SERVICE_IDENTITY_KEYSTORE_APP, master)
            .unwrap(),
    );
    crate::config::provision_service_custody_key(store.as_ref()).unwrap();
    let state = state_with_store(store.clone());
    let material = imported_material(&state);
    assert!(material.command.requested_scope_disclosure.expires_at < chrono::Utc::now());
    let plaintext = custody_bytes(&material).unwrap();
    let prepared = seal_scope_custody(&state, &material).unwrap();
    let ciphertext =
        arkret_canonical::base64url_decode(prepared.evidence.ciphertext.as_str()).unwrap();
    assert!(
        !ciphertext
            .windows(plaintext.len())
            .any(|value| value == plaintext)
    );
    assert_eq!(
        store.list().unwrap(),
        vec![crate::config::SERVICE_CUSTODY_KEY_REF.to_owned()]
    );
    assert!(store.load(&prepared.reference.key_ref).is_err());
    drop(state);
    drop(store);
    let cold = state_with_store(std::sync::Arc::new(
        EncryptedFileKeyStore::new(&path, crate::config::SERVICE_IDENTITY_KEYSTORE_APP, master)
            .unwrap(),
    ));
    let restored = open_scope_custody(&cold, &prepared.reference, &prepared.evidence).unwrap();
    assert_eq!(custody_bytes(&restored).unwrap(), plaintext);
    assert_eq!(
        restored.accepted_binding.verified_at,
        material.accepted_binding.verified_at
    );
}

#[test]
fn encrypted_receipt_binds_every_aad_coordinate_and_original_plaintext_digest() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("vault");
    let store = std::sync::Arc::new(
        EncryptedFileKeyStore::new(
            &path,
            crate::config::SERVICE_IDENTITY_KEYSTORE_APP,
            [31; 32],
        )
        .unwrap(),
    );
    crate::config::provision_service_custody_key(store.as_ref()).unwrap();
    let state = state_with_store(store.clone());
    let material = imported_material(&state);
    let prepared = seal_scope_custody(&state, &material).unwrap();
    for coordinate in 0..7 {
        let mut substituted = prepared.evidence.clone();
        substituted.associated_data.as_array_mut().unwrap()[coordinate] =
            json!(["different original coordinate", coordinate]);
        assert!(open_scope_custody(&state, &prepared.reference, &substituted).is_err());
    }
    let mut changed_ciphertext = prepared.evidence.clone();
    let mut bytes =
        arkret_canonical::base64url_decode(changed_ciphertext.ciphertext.as_str()).unwrap();
    bytes[0] ^= 1;
    changed_ciphertext.ciphertext =
        arkret_wire::Base64UrlString::new(arkret_canonical::base64url_encode(bytes)).unwrap();
    assert!(open_scope_custody(&state, &prepared.reference, &changed_ciphertext).is_err());
    let mut changed_digest = prepared.reference.clone();
    changed_digest.content_digest = Hash::new(format!("sha256:{}", "0".repeat(64))).unwrap();
    assert!(open_scope_custody(&state, &changed_digest, &prepared.evidence).is_err());
    let disk = std::fs::read(&path).unwrap();
    let wrong_key = state_with_store(std::sync::Arc::new(
        EncryptedFileKeyStore::new(
            &path,
            crate::config::SERVICE_IDENTITY_KEYSTORE_APP,
            [32; 32],
        )
        .unwrap(),
    ));
    assert!(open_scope_custody(&wrong_key, &prepared.reference, &prepared.evidence).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), disk);
}

#[test]
fn first_receipt_keeps_original_verified_time_and_nonce_is_not_a_business_identity() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("vault");
    let store = std::sync::Arc::new(
        EncryptedFileKeyStore::new(
            &path,
            crate::config::SERVICE_IDENTITY_KEYSTORE_APP,
            [33; 32],
        )
        .unwrap(),
    );
    crate::config::provision_service_custody_key(store.as_ref()).unwrap();
    let state = state_with_store(store);
    let original = imported_material(&state);
    let first = seal_scope_custody(&state, &original).unwrap();
    let mut later: AgentScopeCustodyMaterial =
        serde_json::from_slice(&custody_bytes(&original).unwrap()).unwrap();
    later.accepted_binding.verified_at += chrono::TimeDelta::milliseconds(1);
    validate_custody_material(&later, &state).unwrap();
    let second = seal_scope_custody(&state, &later).unwrap();
    assert_eq!(first.reference.key_ref, second.reference.key_ref);
    assert_ne!(
        first.reference.content_digest,
        second.reference.content_digest
    );
    assert_ne!(first.evidence.nonce, second.evidence.nonce);
    second
        .validate_first_winner(&first.reference, &first.evidence)
        .unwrap();
    let winner = open_scope_custody(&state, &first.reference, &first.evidence).unwrap();
    assert_eq!(
        winner.accepted_binding.verified_at,
        original.accepted_binding.verified_at
    );
    assert_eq!(
        custody_bytes(&winner).unwrap(),
        custody_bytes(&original).unwrap()
    );
    later.runtime_key_binding_digest = format!("sha256:{}", "f".repeat(64));
    let different = seal_scope_custody(&state, &later).unwrap();
    assert!(
        different
            .validate_first_winner(&first.reference, &first.evidence)
            .is_err()
    );
}

#[test]
fn request_encryption_never_initializes_or_replaces_a_missing_or_bad_service_key() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("vault");
    let store = std::sync::Arc::new(
        EncryptedFileKeyStore::new(
            &path,
            crate::config::SERVICE_IDENTITY_KEYSTORE_APP,
            [34; 32],
        )
        .unwrap(),
    );
    let state = state_with_store(store.clone());
    let material = imported_material(&state);
    assert!(seal_scope_custody(&state, &material).is_err());
    assert!(store.list().unwrap().is_empty());
    store
        .store(crate::config::SERVICE_CUSTODY_KEY_REF, b"bad original key")
        .unwrap();
    assert!(seal_scope_custody(&state, &material).is_err());
    assert_eq!(
        store
            .load(crate::config::SERVICE_CUSTODY_KEY_REF)
            .unwrap()
            .as_ref(),
        b"bad original key"
    );
}
