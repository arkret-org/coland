use coland_http::config::AppConfig;
use ed25519_dalek::SigningKey;
use proptest::prelude::*;
use proptest::test_runner::{Config, TestRunner};

/// Development mode resolves the real method and verifies its signature.
#[test]
fn development_mode_rejects_unsigned_well_formed_detached_jws() {
    let state = coland_test_support::app_state(AppConfig {
        development_mode: true,
        ..coland_test_support::app_config()
    });
    let signing_key = SigningKey::from_bytes(&[41; 32]);
    let multibase = arkret_canonical::ed25519_pubkey_to_did_key_multibase(
        signing_key.verifying_key().as_bytes(),
    );
    let issuer = format!("did:key:{multibase}");
    let method = format!("{issuer}#{multibase}");
    let mut runner = TestRunner::new(Config {
        cases: 64,
        ..Config::default()
    });
    runner
        .run(&prop::collection::vec(any::<u8>(), 1..128), |payload| {
            let signed = arkret_signatures::sign_ed25519_detached_jws(&signing_key, &payload)
                .expect("fixture signing");
            coland_http::jws_verify::verify_did_controlled_jws(
                &payload, &signed, &method, &issuer, &state,
            )
            .expect("positive control must reach signature verification");
            let mut signature = arkret_canonical::base64url_decode(
                signed
                    .rsplit_once('.')
                    .expect("detached signature segment")
                    .1,
            )
            .expect("unpadded base64url signature");
            signature[0] ^= 1;
            let header = signed.split('.').next().unwrap();
            let mutated = format!(
                "{header}..{}",
                arkret_canonical::base64url_encode(signature)
            );
            prop_assert!(
                coland_http::jws_verify::verify_did_controlled_jws(
                    &payload, &mutated, &method, &issuer, &state,
                )
                .is_err()
            );
            Ok(())
        })
        .unwrap();
}
