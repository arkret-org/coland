//! Formal trust admission over real durable stores, without a test-policy mode.
use std::collections::BTreeMap;
use std::sync::Arc;

use arkret_identity::test_material::{PublicKeyFingerprintInput, reserved_identifier_matches};
use arkret_wire::{Did, DidUrl, TrustDomainId};
use chrono::Utc;
use coland_services::identity::{DidDocumentState, DidLogEvent};
use ed25519_dalek::{Signer as _, SigningKey};

use super::{sql_fault_matrix, station, *};

#[test]
fn reserved_material_and_identifiers_leave_no_pg_cache_binding_or_auth_state() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .unwrap();
    let (original, pool, _lease) = station("https://material-admission.internal/".into());
    runtime.block_on(async {
        let safe = SigningKey::from_bytes(&[91; 32]);
        let published = SigningKey::from_bytes(&std::array::from_fn(|index| index as u8));
        let rules: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../../arkret-spec/spec/v1/artifacts/registry/test-material-registry.json"
        ))
        .unwrap();
        let did_rule = rules["reserved_identifiers"][0]["examples"][0]
            .as_str()
            .unwrap();
        let key_rule = rules["reserved_identifiers"][1]["examples"][0]
            .as_str()
            .unwrap()
            .split_once('#')
            .unwrap()
            .1;
        let domain_rule = rules["reserved_identifiers"][2]["examples"][0]
            .as_str()
            .unwrap();
        for (did, fragment, domain, key, expected_rule) in [
            (
                did_rule,
                "runtime-1",
                "ak:trust_domain:production.company",
                &safe,
                "did",
            ),
            (
                "did:web:deployment.company",
                key_rule,
                "ak:trust_domain:production.company",
                &safe,
                "key_id",
            ),
            (
                "did:web:deployment.company",
                "runtime-1",
                domain_rule,
                &safe,
                "trust_domain",
            ),
            (
                "did:web:deployment.company",
                "renamed-production-key",
                "ak:trust_domain:production.company",
                &published,
                "fingerprint",
            ),
        ] {
            let did = Did::new(did).unwrap();
            let method = DidUrl::new(format!("{did}#{fragment}")).unwrap();
            let domain = TrustDomainId::new(domain).unwrap();
            let matches = reserved_identifier_matches(Some(&did), Some(&method), Some(&domain));
            assert_eq!(
                (matches.did, matches.key_id, matches.trust_domain),
                match expected_rule {
                    "did" => (true, false, false),
                    "key_id" => (false, true, false),
                    "trust_domain" => (false, false, true),
                    _ => (false, false, false),
                }
            );
            let key_bytes = key.verifying_key().to_bytes();
            let fingerprint = PublicKeyFingerprintInput::Ed25519Rfc8032(&key_bytes);
            assert_eq!(
                arkret_identity::test_material::enforce_formal_test_material_policy(
                    Some(&fingerprint),
                    None,
                    None,
                    None
                )
                .is_err(),
                expected_rule == "fingerprint"
            );
            // The negative's key remains cryptographically valid independently
            // of the formal test-material guard and every reserved identifier.
            let transcript = b"otherwise-valid-production-admission";
            key.verifying_key()
                .verify_strict(transcript, &key.sign(transcript))
                .unwrap();
            let mut config = original.config().clone();
            config.trust_domain = domain.clone();
            let state = AppState::new_with_service_identity(
                config,
                coland_storage_postgres::Db {
                    pool: Some(pool.clone()),
                },
                Arc::new(coland_storage_postgres::PgPersistenceStore::new(
                    pool.clone(),
                )),
                original.service_identity_state().as_ref().clone(),
                original.service_resolution_commitment().as_ref().clone(),
                [83; 32],
            );
            let now = Utc::now();
            let document = arkret_identity::DidDocument {
                id: did.clone(),
                verification_methods: BTreeMap::from([(
                    method.to_string(),
                    arkret_canonical::ed25519_pubkey_to_did_key_multibase(&key_bytes),
                )]),
                also_known_as: vec![],
                updated_at: Some(now),
                raw_properties: BTreeMap::new(),
            };
            let record = DidDocumentState {
                did: did.to_string(),
                did_document: serde_json::to_value(&document).unwrap(),
                key_log_head: Some(arkret_canonical::canonical_sha256(&document).unwrap()),
                seq: 1,
                method_evidence: serde_json::json!({"mode":"verified-production-resolution"}),
                fetched_at: now,
                expires_at: now + chrono::Duration::minutes(5),
                updated_at: now,
            };
            let event = DidLogEvent {
                did: did.to_string(),
                seq: 1,
                event_digest: arkret_canonical::canonical_sha256(&document).unwrap(),
                operation: serde_json::json!({"state": document}),
                created_at: now,
            };
            let before = sql_fault_matrix::snapshot(&pool).await;
            let projection = format!("{:?}", state.projections().snapshot());
            for _ in 0..2 {
                assert_eq!(
                    state
                        .cache_verified_federation_peer_document(record.clone())
                        .unwrap_err(),
                    "test_signing_material_denied"
                );
                assert_eq!(
                    state
                        .cache_resolved_did_document(record.clone())
                        .unwrap_err(),
                    "test_signing_material_denied"
                );
                let error = state
                    .dids()
                    .commit_formal_log_operation(&domain, None, record.clone(), event.clone())
                    .await
                    .unwrap_err();
                assert_eq!(
                    error.to_string(),
                    "schema violation: test_signing_material_denied"
                );
                assert!(state.did_bindings().snapshot().is_empty());
                assert!(state.dids().document(did.as_str()).await.unwrap().is_none());
                assert!(
                    state
                        .dids()
                        .log_events(did.as_str())
                        .await
                        .unwrap()
                        .is_empty()
                );
                assert_eq!(sql_fault_matrix::snapshot(&pool).await, before);
                assert_eq!(format!("{:?}", state.projections().snapshot()), projection);
            }
        }
        let did = Did::new("did:web:unlisted-positive.company").unwrap();
        let now = Utc::now();
        let document = arkret_identity::DidDocument {
            id: did.clone(),
            verification_methods: BTreeMap::from([(
                format!("{did}#runtime-1"),
                arkret_canonical::ed25519_pubkey_to_did_key_multibase(
                    safe.verifying_key().as_bytes(),
                ),
            )]),
            also_known_as: vec![],
            updated_at: Some(now),
            raw_properties: BTreeMap::new(),
        };
        let record = DidDocumentState {
            did: did.to_string(),
            did_document: serde_json::to_value(&document).unwrap(),
            key_log_head: Some(arkret_canonical::canonical_sha256(&document).unwrap()),
            seq: 1,
            method_evidence: serde_json::json!({"mode":"verified-production-resolution"}),
            fetched_at: now,
            expires_at: now + chrono::Duration::minutes(5),
            updated_at: now,
        };
        original
            .cache_verified_federation_peer_document(record.clone())
            .unwrap();
        original
            .cache_resolved_did_document(record.clone())
            .unwrap();
        let event = DidLogEvent {
            did: did.to_string(),
            seq: 1,
            event_digest: arkret_canonical::canonical_sha256(&document).unwrap(),
            operation: serde_json::json!({"state": document}),
            created_at: now,
        };
        let before = sql_fault_matrix::snapshot(&pool).await;
        assert_eq!(
            original
                .dids()
                .commit_formal_log_operation(&original.config().trust_domain, None, record, event)
                .await
                .unwrap(),
            coland_services::identity::DidLogCommitResult::Accepted
        );
        assert!(
            original
                .dids()
                .document(did.as_str())
                .await
                .unwrap()
                .is_some()
        );
        assert_eq!(
            original
                .dids()
                .log_events(did.as_str())
                .await
                .unwrap()
                .len(),
            1
        );
        assert_ne!(sql_fault_matrix::snapshot(&pool).await, before);
    });
}
