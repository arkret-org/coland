use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use coland_http::config::AppConfig;
use proptest::prelude::*;
use proptest::test_runner::{Config, TestRunner};

fn ed25519_detached_jws(signature: &[u8]) -> String {
    let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"Ed25519"}"#);
    let signature = URL_SAFE_NO_PAD.encode(signature);
    format!("{header}..{signature}")
}

/// Development mode shares the production verifier: a well-formed detached
/// JWS whose signature was not produced by the resolved method key never
/// verifies, so no shape-only acceptance path exists.
#[test]
fn development_mode_rejects_unsigned_well_formed_detached_jws() {
    let state = coland_test_support::app_state(AppConfig {
        development_mode: true,
        ..coland_test_support::app_config()
    });
    let mut runner = TestRunner::new(Config {
        cases: 64,
        ..Config::default()
    });
    runner
        .run(
            &(
                prop::collection::vec(any::<u8>(), 1..128),
                prop::collection::vec(any::<u8>(), 64),
            ),
            |(payload, signature)| {
                let jws = ed25519_detached_jws(&signature);
                prop_assert!(
                    coland_http::jws_verify::verify_did_controlled_jws(
                        &payload,
                        &jws,
                        "did:web:alice.example#k1",
                        "did:web:alice.example",
                        &state,
                    )
                    .is_err()
                );
                Ok(())
            },
        )
        .unwrap();
}
