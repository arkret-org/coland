use arkret_identity::{DidKeyResolver, DidResolver};
use arkret_models_crypto::*;
use arkret_models_identity::*;
use coland_storage::MlsClaimRemoteDeviceEvidence;
use ed25519_dalek::SigningKey;

use super::*;

fn fixture() -> (KeyPackageClaimRecord, MlsClaimRemoteDeviceEvidence) {
    let key = SigningKey::from_bytes(&[118; 32]);
    let multibase =
        arkret_canonical::ed25519_pubkey_to_did_key_multibase(key.verifying_key().as_bytes());
    let did = arkret_wire::Did::new(format!("did:key:{multibase}")).unwrap();
    let station = arkret_wire::project_did_to_core_id(&did).unwrap();
    let document = DidKeyResolver::new().resolve_did(&did).unwrap().document;
    let head = arkret_canonical::sha256_digest(did.as_str().as_bytes());
    let version = format!(
        "synthetic-did-sha256:{}",
        head.trim_start_matches("sha256:")
    );
    let resolution = AuthenticatedServiceResolution {
        service_id: station.clone(),
        service_kind: "station".into(),
        method_history_evidence: ResolutionMethodHistoryEvidence::DidKeyExpansion {
            boundary: ResolutionMethodEvidenceBoundary {
                from_method_history_head: head.clone(),
                to_method_history_head: head,
                from_version_id: version.clone(),
                to_version_id: version,
            },
            evidence: ResolutionDidBindingEvidenceReceipt {
                kind: ResolutionDidBindingEvidenceKind::AkDidBindingEvidenceV1,
                method: "key".into(),
                document_digest: normalized_did_document_digest(&document).unwrap(),
                method_proofs: vec![],
            },
        },
        normalized_did_document: document,
    };
    let account = AccountId::new(
        DidCoreId::new("ak:did_core:web:member.example").unwrap(),
        station,
    );
    let device = DeviceId::new("ak:device:0196419b-0000-7000-8000-000000000001").unwrap();
    let device_key = SigningKey::from_bytes(&[119; 32]);
    let identity = arkret_mls::ArkretMlsIdentity::new_human_device(
        ActorId::account(account.clone()),
        device.clone(),
        arkret_mls::ArkretMlsSigner::from_ed25519_signing_key(device_key.clone()),
    )
    .unwrap();
    let package = identity.key_package_record().unwrap();
    let at = arkret_canonical::normalize_timestamp_canonical(Utc::now());
    let event = EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [121; 32]);
    let core = DeviceProjectionAttestationCore {
        account_id: account.clone(),
        device_id: device.clone(),
        device_signing_key_did: arkret_wire::DidKey::new(format!(
            "did:key:{}",
            arkret_canonical::ed25519_pubkey_to_did_key_multibase(
                device_key.verifying_key().as_bytes()
            )
        ))
        .unwrap(),
        hpke_key: arkret_wire::NonEmptyString::new("opaque-hpke-key").unwrap(),
        device_authorize_event_id: event.clone(),
        authorized_generation_ref: 3,
        device_status: DeviceStatus::Active,
        attested_at: at,
        expires_at: at + chrono::Duration::seconds(60),
        authorization_window: DeviceAuthorizationWindow {
            not_before: at,
            expires_at: None,
        },
    };
    let attestation = arkret_signatures::device_projection::sign_device_projection_attestation(
        core,
        DidUrl::new(format!("{did}#{multibase}")).unwrap(),
        &key,
    )
    .unwrap();
    let evidence = MlsClaimRemoteDeviceEvidence {
        account_id: account.clone(),
        device_id: device.clone(),
        generation: AccountDeviceGenerationEntry {
            account_id: account.clone(),
            generation_state: keys::DeviceGenerationState {
                current_device_generation_ref: 3,
            },
        },
        record: PeerQueryDeviceRecord {
            signer_evidence_ref: arkret_wire::SignerEvidenceRef::new(format!(
                "ak:signer_evidence:sha256:{}",
                "a".repeat(64)
            ))
            .unwrap(),
            algorithms: Default::default(),
            trust_algorithms: vec![],
            device_projection_attestation: attestation,
        },
        issuer_resolution: resolution,
    };
    let claim = KeyPackageClaimRecord {
        claim_id: format!("ak:keypackage_claim:{}", uuid::Uuid::now_v7()),
        keypackage_ref: package.keypackage_ref.to_string(),
        actor_id: ActorId::account(account.clone()),
        principal_id: account.principal_id,
        device_id: Some(device),
        agent_id: None,
        agent_verification_method: None,
        keypackage: package.keypackage,
        capabilities: package.capabilities,
        device_authorize_event_id: Some(event),
        agent_key_authorize_event_id: None,
        expires_at: at + chrono::Duration::minutes(2),
        revocation_status: None,
        last_resort: None,
    };
    (claim, evidence)
}

#[test]
fn remote_device_delivery_requires_original_signature_generation_and_real_leaf() {
    let (claim, evidence) = fixture();
    let accepted = remote_device_window(&claim, std::slice::from_ref(&evidence)).unwrap();
    assert!(accepted.permits_at(Utc::now()));
    assert!(!accepted.permits_at(Utc::now() + chrono::Duration::minutes(1)));
    let mut historical = claim.clone();
    historical.expires_at = Utc::now() - chrono::Duration::seconds(1);
    // Device proof remains current; the separate locked ledger decides whether
    // this is a consumed recovery or unavailable expired material.
    assert!(remote_device_window(&historical, std::slice::from_ref(&evidence)).is_ok());
    assert!(remote_device_window(&claim, &[]).is_err());
    assert!(remote_device_window(&claim, &[evidence.clone(), evidence.clone()]).is_err());
    let mut changed = evidence.clone();
    changed
        .generation
        .generation_state
        .current_device_generation_ref += 1;
    assert!(remote_device_window(&claim, &[changed]).is_err());
    let mut changed = evidence.clone();
    changed
        .record
        .device_projection_attestation
        .attestation
        .expires_at += chrono::Duration::seconds(1);
    assert!(remote_device_window(&claim, &[changed]).is_err());
    let mut changed = evidence.clone();
    changed
        .issuer_resolution
        .normalized_did_document
        .raw_properties
        .insert("assertionMethod".into(), serde_json::json!([]));
    assert!(remote_device_window(&claim, &[changed]).is_err());
    let mut changed = claim.clone();
    changed.device_authorize_event_id = Some(EventId::from_digest(
        arkret_canonical::DigestSuite::Sha256,
        [122; 32],
    ));
    assert!(remote_device_window(&changed, std::slice::from_ref(&evidence)).is_err());
    let other = arkret_mls::ArkretMlsIdentity::new_human_device(
        claim.actor_id.clone(),
        claim.device_id.clone().unwrap(),
        arkret_mls::ArkretMlsSigner::from_ed25519_signing_key(SigningKey::from_bytes(&[120; 32])),
    )
    .unwrap()
    .key_package_record()
    .unwrap();
    changed = claim;
    changed.keypackage = other.keypackage;
    changed.keypackage_ref = other.keypackage_ref.to_string();
    assert!(remote_device_window(&changed, &[evidence]).is_err());
}
