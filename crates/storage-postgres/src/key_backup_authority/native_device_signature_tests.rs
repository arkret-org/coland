//! The cut below models an already-qualified native authorization. This unit
//! tests packet binding and Ed verification, not original governance admission.

use arkret_models_collaboration::events_payloads::{
    AppletManagedDeviceScope, AppletManagedDeviceScopes,
};
use arkret_models_crypto::KeyBackup;
use arkret_models_integration::{
    RealmActorArchiveInventoryEntry, RealmActorArchiveInventoryManifest,
    RealmActorContentBackupSource,
};
use arkret_wire::{
    Base64UrlString, CapabilityActionId, CommittedEventRef, Did, DidUrl, ServiceOperationId,
};
use coland_storage::AppletManagedDeviceAuthority;
use ed25519_dalek::{Signer, SigningKey};

use super::verify_realm_device_backup_signature;

fn fixture() -> serde_json::Value {
    serde_json::from_str(include_str!("../../../../../arkret-spec/spec/v1/artifacts/fixtures/realm-actor-content-backup-fixture.json")).unwrap()
}

fn packet_and_qualified_cut() -> (KeyBackup, AppletManagedDeviceAuthority) {
    let fixture = fixture();
    let packet: KeyBackup = serde_json::from_value(fixture["native_packet"].clone()).unwrap();
    let source: RealmActorContentBackupSource =
        serde_json::from_value(fixture["native_source"].clone()).unwrap();
    let inventory: RealmActorArchiveInventoryManifest =
        serde_json::from_value(fixture["archive_inventory"].clone()).unwrap();
    let manager_id = inventory
        .entries
        .iter()
        .find_map(|entry| match entry {
            RealmActorArchiveInventoryEntry::Recipient(entry) => {
                entry.declaration.event.payload.get("service_id").cloned()
            }
            _ => None,
        })
        .unwrap();
    let original = &source.device_authorization.event;
    let payload = &original.payload;
    let native_did: Did = serde_json::from_value(fixture["native_history"]["did"].clone()).unwrap();
    assert_eq!(
        arkret_wire::project_did_to_core_id(&native_did).unwrap(),
        original.actor_id.signing_principal_id().clone()
    );
    let fingerprint = payload["device_public_key_did"]
        .as_str()
        .unwrap()
        .strip_prefix("did:key:")
        .unwrap();
    let authorization_ref = CommittedEventRef {
        event_id: original.event_id.clone(),
        commit_id: source.device_authorization.commit.commit_id,
        stream_ref: source.device_authorization.commit.stream_ref,
        stream_position: source.device_authorization.commit.stream_position,
    };
    assert_eq!(authorization_ref, source.admission.device_authorize_ref);
    let authority = AppletManagedDeviceAuthority {
        actor_id: original.actor_id.clone(),
        device_id: serde_json::from_value(payload["device_id"].clone()).unwrap(),
        authorization_ref,
        applet_id: original.applet_id.clone().unwrap(),
        source_service_id: serde_json::from_value(manager_id).unwrap(),
        native_did,
        realm_id: original.realm_id.clone(),
        current_device_generation_ref: payload["authorized_generation_ref"].as_u64().unwrap(),
        public_key: arkret_canonical::decode_ed25519_multibase(fingerprint).unwrap(),
        // This helper does not consume scopes. The fixture's signed scope list
        // predates canonical ordering; do not normalize that immutable Event or
        // claim it passed native admission. Use one valid, unused cut sentinel.
        scopes: AppletManagedDeviceScopes::new(vec![AppletManagedDeviceScope {
            effective_scope: source.admission.effective_scope,
            actions: vec![
                CapabilityActionId::from_wire(
                    ServiceOperationId::SELF_KEYS_BACKUPS_RESOURCE_REPLACE_V1,
                )
                .unwrap(),
            ],
        }])
        .unwrap(),
        not_before: serde_json::from_value(payload["not_before"].clone()).unwrap(),
        expires_at: serde_json::from_value(payload["expires_at"].clone()).unwrap(),
        governance_service_id: source.admission.service_id,
        governance_generation: source.admission.governance_generation,
    };
    (packet, authority)
}

fn sign_negative_packet(packet: &mut KeyBackup, authority: &AppletManagedDeviceAuthority) {
    let fixture = fixture();
    let hex = fixture["test_material"]["device_seed_hex"]
        .as_str()
        .unwrap();
    let seed = std::array::from_fn(|index| {
        u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16).unwrap()
    });
    let key = SigningKey::from_bytes(&seed);
    assert_eq!(key.verifying_key().to_bytes(), authority.public_key);
    packet.signature_proof.signature = Base64UrlString::new(arkret_canonical::base64url_encode(
        key.sign(&packet.signing_payload_bytes().unwrap())
            .to_bytes(),
    ))
    .unwrap();
    assert!(arkret_signatures::verify_detached_ed25519_signature(
        &arkret_signatures::PublicKeyMaterial::Ed25519Raw {
            bytes: authority.public_key.to_vec(),
        },
        &packet.signing_payload_bytes().unwrap(),
        packet.signature_proof.signature.as_str(),
    ));
}

#[test]
fn native_backup_accepts_the_original_principal_device_method() {
    let (packet, authority) = packet_and_qualified_cut();
    let witness =
        verify_realm_device_backup_signature(&packet, &authority, packet.created_at).unwrap();
    witness.verify_retained_envelope(&packet).unwrap();
}

#[test]
fn native_backup_rejects_other_methods_even_with_the_original_device_key() {
    let (packet, authority) = packet_and_qualified_cut();
    let fingerprint = arkret_canonical::ed25519_pubkey_to_did_key_multibase(&authority.public_key);
    for method in [
        format!("did:web:other.example#{}", authority.device_id),
        format!(
            "{}#ak:device:019a0000-0000-7000-8000-000000000012",
            authority.native_did
        ),
        format!("did:key:{fingerprint}#{fingerprint}"),
    ] {
        let mut negative = packet.clone();
        negative.signature_proof.verification_method = DidUrl::new(method).unwrap();
        sign_negative_packet(&mut negative, &authority);
        assert!(
            verify_realm_device_backup_signature(&negative, &authority, packet.created_at).is_err()
        );
    }
}

#[test]
fn native_backup_keeps_authorization_generation_window_and_ed_gates() {
    let (packet, authority) = packet_and_qualified_cut();
    let source: RealmActorContentBackupSource =
        serde_json::from_value(fixture()["native_source"].clone()).unwrap();
    let mut wrong_authorization = packet.clone();
    wrong_authorization
        .signature_proof
        .device_authorize_event_id = Some(source.governance_history.genesis.event.event_id);
    assert_ne!(
        wrong_authorization
            .signature_proof
            .device_authorize_event_id,
        packet.signature_proof.device_authorize_event_id
    );
    sign_negative_packet(&mut wrong_authorization, &authority);
    assert!(
        verify_realm_device_backup_signature(&wrong_authorization, &authority, packet.created_at)
            .is_err()
    );
    let mut wrong_generation = authority.clone();
    wrong_generation.current_device_generation_ref += 1;
    assert!(
        verify_realm_device_backup_signature(&packet, &wrong_generation, packet.created_at)
            .is_err()
    );
    assert!(
        verify_realm_device_backup_signature(&packet, &authority, authority.expires_at).is_err()
    );
    let mut tampered = packet;
    let mut raw =
        arkret_canonical::base64url_decode(tampered.signature_proof.signature.as_str()).unwrap();
    raw[0] ^= 1;
    tampered.signature_proof.signature =
        Base64UrlString::new(arkret_canonical::base64url_encode(raw)).unwrap();
    assert!(
        verify_realm_device_backup_signature(&tampered, &authority, tampered.created_at).is_err()
    );
}
