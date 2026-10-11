//! Real WebVH assertion-key rotation and encrypted KeyStore reopen coverage.
use std::sync::Arc;

use arkret_identity::service_identity::DidCoreIdentityKeyRef;
use arkret_signatures::webvh::{
    ServiceInceptionInput, ServiceRotationInput, prepare_service_inception,
    prepare_service_rotation, validate_webvh_history_at,
};
use arkret_wire::{Did, EventId};
use chrono::{Duration, TimeZone as _};
use ed25519_dalek::SigningKey;

use super::*;

#[test]
fn confirmed_contact_receipt_uses_historical_key_after_rotation_and_keystore_reopen() {
    let started = chrono::Utc.with_ymd_and_hms(2026, 9, 10, 0, 0, 0).unwrap();
    let accepted_at = started + Duration::seconds(10);
    let rotated_at = started + Duration::seconds(20);
    let endpoint = "https://receipt-custody.example/".parse().unwrap();
    let inception = prepare_service_inception(
        &mut rand::rng(),
        &ServiceInceptionInput {
            principal_endpoint: &endpoint,
            local_id: "service",
            also_known_as: &[],
            version_time: started,
            did_key_fragment: Some("receipt-key"),
        },
    )
    .unwrap();
    let did = Did::new(inception.did.clone()).unwrap();
    let old = SigningKey::from_bytes(&inception.did_key_seed);
    let current = SigningKey::from_bytes(&[45_u8; 32]);
    let current_multibase =
        arkret_canonical::ed25519_pubkey_to_did_key_multibase(current.verifying_key().as_bytes());
    let mut document = inception.log_entry["state"].clone();
    for method in document["verificationMethod"].as_array_mut().unwrap() {
        if method["id"] == inception.did_key_id {
            method["publicKeyMultibase"] = serde_json::Value::String(current_multibase.clone());
        }
    }
    let following_key = SigningKey::from_bytes(&[71_u8; 32]);
    let following_multibase = arkret_canonical::ed25519_pubkey_to_did_key_multibase(
        following_key.verifying_key().as_bytes(),
    );
    let rotation = prepare_service_rotation(&ServiceRotationInput {
        did: did.as_str(),
        previous_entries: &[inception.log_entry.clone()],
        state: &document,
        current_update_seed: &inception.next_update_key_seed,
        next_update_public_key_multibase: &following_multibase,
        version_time: rotated_at,
    })
    .unwrap();
    let history = vec![inception.log_entry.clone(), rotation.log_entry];
    let historical = validate_webvh_history_at(&did, &history, accepted_at).unwrap();
    let current_point =
        validate_webvh_history_at(&did, &history, rotated_at + Duration::seconds(1)).unwrap();
    let methods = receipt_assertion_methods(historical.document).unwrap();
    let new_methods = receipt_assertion_methods(current_point.document).unwrap();
    assert!(
        methods
            .iter()
            .any(|(_, key)| key == old.verifying_key().as_bytes())
    );
    assert!(
        !methods
            .iter()
            .any(|(_, key)| key == current.verifying_key().as_bytes())
    );
    assert!(
        new_methods
            .iter()
            .any(|(_, key)| key == current.verifying_key().as_bytes())
    );
    let path = std::env::temp_dir().join(format!(
        "coland-contact-receipt-{}.keys",
        uuid::Uuid::now_v7()
    ));
    let mut config = crate::config::AppConfig::test_default();
    config.key_store = crate::config::KeyStoreConfig::EncryptedFile {
        path: path.clone(),
        master_key: Arc::new(zeroize::Zeroizing::new([87_u8; 32])),
    };
    let old_ref = DidCoreIdentityKeyRef::new("contact-receipt-old").unwrap();
    let new_ref = DidCoreIdentityKeyRef::new("contact-receipt-current").unwrap();
    {
        let store = config
            .key_store
            .open(crate::config::SERVICE_IDENTITY_KEYSTORE_APP)
            .unwrap()
            .unwrap();
        store
            .store(old_ref.as_str(), &inception.did_key_seed)
            .unwrap();
        store.store(new_ref.as_str(), &[45_u8; 32]).unwrap();
    }
    // No live KeyStore object crosses this boundary. The same loader used after
    // a process restart reopens encrypted storage and matches historical keys.
    let refs = vec![new_ref.clone(), old_ref.clone()];
    let (method, restored) = load_retained_receipt_key(&methods, &config, &refs).unwrap();
    assert_eq!(restored.verifying_key(), old.verifying_key());
    assert_eq!(method.as_str(), inception.did_key_id);
    let station = arkret_wire::project_did_to_core_id(&did).unwrap();
    let holder = ContactPeer::Human {
        account_id: arkret_wire::AccountId::new(
            "ak:did_core:web:receipt-holder.example".parse().unwrap(),
            station.clone(),
        ),
    };
    let peer = ContactPeer::Human {
        account_id: arkret_wire::AccountId::new(
            "ak:did_core:web:receipt-peer.example".parse().unwrap(),
            "ak:did_core:web:peer-station.example".parse().unwrap(),
        ),
    };
    let receipt = RequestAcceptanceReceipt::sign_with(
        arkret_models_collaboration::contact_operations::RequestAcceptanceReceiptCore {
            holder,
            peer,
            slot_version: 1,
            slot_predecessor: None,
            previous_terminal_contact_round_id: None,
            request_event_ref: EventId::from_digest(
                arkret_canonical::DigestSuite::Sha256,
                [3_u8; 32],
            ),
            producer_signer:
                arkret_models_collaboration::contact_operations::ContactProducerSigner::Direct(
                    arkret_models_collaboration::contact_operations::ContactDirectProducerSigner {
                        verification_method: method.clone(),
                        public_key_b64u: Base64UrlString::new(arkret_canonical::base64url_encode(
                            old.verifying_key().to_bytes(),
                        ))
                        .unwrap(),
                    },
                ),
            source_checkpoint: format!("sha256:{}", "3".repeat(64)).parse().unwrap(),
            accepted_at,
            issuer_id: station,
        },
        |bytes| {
            Ok(ProtocolSignature {
                verification_method: method,
                created_at: rotated_at + Duration::seconds(2),
                jws: contact_detached_jws(&restored, bytes).unwrap(),
            })
        },
    )
    .unwrap();
    // The receipt carries the SDK compact detached JWS and verifies through
    // the SDK Contact receipt verifier only under the historical key.
    assert!(arkret_wire::is_compact_detached_jws(&receipt.signature.jws));
    let persisted: RequestAcceptanceReceipt =
        serde_json::from_value(serde_json::to_value(&receipt).unwrap()).unwrap();
    arkret_signatures::contact_receipt::verify_contact_request_acceptance_receipt(
        &persisted,
        &persisted.core.request_event_ref,
        &old.verifying_key(),
    )
    .unwrap();
    assert!(
        arkret_signatures::contact_receipt::verify_contact_request_acceptance_receipt(
            &persisted,
            &persisted.core.request_event_ref,
            &current.verifying_key(),
        )
        .is_err()
    );
    assert_eq!(receipt.core.accepted_at, accepted_at);
    assert!(receipt.signature.created_at > rotated_at);
    assert!(
        load_retained_receipt_key(&methods, &config, std::slice::from_ref(&new_ref)).is_err(),
        "missing historical reference must not use the current signer"
    );
    {
        let store = config
            .key_store
            .open(crate::config::SERVICE_IDENTITY_KEYSTORE_APP)
            .unwrap()
            .unwrap();
        store.store(old_ref.as_str(), &[45_u8; 32]).unwrap();
    }
    assert!(
        load_retained_receipt_key(&methods, &config, &refs).is_err(),
        "a reused historical KeyRef with different material grants no authority"
    );
    let (_, new_signer) =
        load_retained_receipt_key(&new_methods, &config, std::slice::from_ref(&new_ref)).unwrap();
    assert_eq!(new_signer.verifying_key(), current.verifying_key());
    let mut tampered = history;
    tampered[0]["state"]["assertionMethod"] = serde_json::json!([]);
    assert!(
        validate_webvh_history_at(&did, &tampered, accepted_at).is_err(),
        "raw history cannot assign an arbitrary key"
    );
    std::fs::remove_file(path).unwrap();
}
