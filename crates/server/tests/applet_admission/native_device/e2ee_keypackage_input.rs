//! Upload identities are registered MLS identifiers, including on native transport.
use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_upload_rejects_opaque_keypackage_identity_before_publication() {
    tokio::spawn(native_phase(|| async {
        let fixture = native_phase(Fixture::new).await;
        let scope = ScopeRef::Realm {
            realm_id: fixture.realm.clone(),
        };
        let namespace = format!("bridge.{}", uuid::Uuid::now_v7().simple());
        let native = mls_service(&fixture, &namespace);
        let install =
            native_phase(|| fixture.install_package(true, native.package.clone(), &namespace))
                .await;
        let ghost =
            native_phase(|| fixture.ghost_body(&install, &namespace, "input-identity")).await;
        assert_eq!(
            fixture
                .ghost_commit(&install, &ghost, "input-identity")
                .await
                .0,
            StatusCode::OK
        );
        for bundle in [&install.bot_body["event"], &ghost["event"]] {
            let key = SigningKey::from_bytes(&[172; 32]);
            let device = DeviceId::new(format!("ak:device:{}", uuid::Uuid::now_v7())).unwrap();
            let authority = native_phase(|| {
                authorize(
                    &fixture,
                    &install,
                    bundle,
                    &namespace,
                    &key,
                    device.clone(),
                    true,
                )
            })
            .await;
            let join = join_event(&fixture, &install, &authority, &key, &install.join_grant());
            let (status, outcome) =
                native_phase(|| post(&fixture, &authority, &key, &join, vec![])).await;
            assert_eq!(
                status,
                StatusCode::OK,
                "real current Device membership: {outcome}"
            );
            let identity = arkret_mls::ArkretMlsIdentity::new_realm_device(
                authority.actor_id.clone(),
                device,
                arkret_mls::ArkretMlsSigner::from_ed25519_signing_key(key.clone()),
            )
            .unwrap();
            let fingerprint = arkret_canonical::ed25519_pubkey_to_did_key_multibase(
                key.verifying_key().as_bytes(),
            );
            let method = format!("did:key:{fingerprint}#{fingerprint}");
            for invalid in [
                "opaque-package",
                "ak:mls:kp:01964137-0000-4000-8000-000000000001",
                "ak:mls:kp:01964137-0000-7000-7000-000000000001",
                "ak:mls:kp:01964137-0000-7000-8000-00000000000A",
            ] {
                let mut body = fresh_upload(&identity, &method, &key, &scope).unsigned();
                body.keypackages[0].keypackage_id = invalid.to_owned();
                native_phase(|| refused_input(&fixture, &authority, &key, &method, &scope, body))
                    .await;
            }
            let mut duplicate = fresh_upload(&identity, &method, &key, &scope).unsigned();
            let mut second = fresh_upload(&identity, &method, &key, &scope)
                .unsigned()
                .keypackages
                .remove(0);
            second.keypackage_id = duplicate.keypackages[0].keypackage_id.clone();
            duplicate.keypackages.push(second);
            native_phase(|| refused_input(&fixture, &authority, &key, &method, &scope, duplicate))
                .await;
            let mut mixed = fresh_upload(&identity, &method, &key, &scope).unsigned();
            let mut bad = fresh_upload(&identity, &method, &key, &scope)
                .unsigned()
                .keypackages
                .remove(0);
            bad.keypackage_id = "opaque-second-entry".to_owned();
            mixed.keypackages.push(bad);
            native_phase(|| refused_input(&fixture, &authority, &key, &method, &scope, mixed))
                .await;
            let valid = fresh_upload(&identity, &method, &key, &scope);
            let (status, outcome) =
                native_phase(|| upload_in_scope(&fixture, &authority, &key, &valid, &scope)).await;
            assert_eq!(
                status,
                StatusCode::OK,
                "registered fresh identity: {outcome}"
            );
            assert_eq!(outcome["accepted"], 1, "{outcome}");
        }
    }))
    .await
    .unwrap();
}

async fn refused_input(
    fixture: &Fixture,
    authority: &coland_storage::AppletManagedDeviceAuthority,
    key: &SigningKey,
    method: &str,
    scope: &ScopeRef,
    unsigned: arkret_models_crypto::KeyPackagesUploadUnsignedRequest,
) {
    assert!(arkret_models_crypto::keypackages_upload_signing_input(&unsigned).is_err());
    // Deliberately send malicious bytes from the complete typed projection.
    // The production signer refuses this input; the receiver also rejects it.
    let mut input = arkret_models_crypto::http_bodies::KEYPACKAGES_UPLOAD_SIGNATURE_DOMAIN
        .as_bytes()
        .to_vec();
    input.extend(arkret_canonical::canonical_json_bytes(&unsigned).unwrap());
    let signature = arkret_signatures::keypackages::sign_keypackage_signing_input(
        &key.to_bytes(),
        method,
        &input,
    )
    .unwrap();
    let body = unsigned.into_signed(signature);
    let before = native_phase(|| snapshot(fixture)).await;
    let (status, error) =
        native_phase(|| upload_in_scope(fixture, authority, key, &body, scope)).await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "registered unique UUIDv7 identity is mandatory: {error}"
    );
    assert_eq!(
        error["type"], "https://arkret.org/problems/schema_violation",
        "{error}"
    );
    assert_eq!(
        before,
        native_phase(|| snapshot(fixture)).await,
        "no earlier entry may be partially published"
    );
}
