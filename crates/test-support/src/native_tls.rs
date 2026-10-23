//! TLS fixtures bound to the canonical native runner's temporary CA.

use std::path::PathBuf;

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

fn required_path(variable: &str) -> PathBuf {
    std::env::var_os(variable)
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            panic!("{variable} is required; run via cotest/scripts/run-native-rust-tests.py")
        })
        .canonicalize()
        .unwrap_or_else(|error| panic!("invalid {variable}: {error}"))
}

/// Require production clients and fixture servers to use the same run CA.
pub fn require_trust_store() {
    assert_eq!(
        required_path("SSL_CERT_FILE"),
        required_path("COTEST_RUN_SCOPED_CA_PEM"),
        "native TLS fixtures must use the canonical run-scoped CA",
    );
}

/// Build a real TLS server using the current run's certificate and private key.
pub fn server_config() -> rustls::ServerConfig {
    require_trust_store();
    let certificates = CertificateDer::pem_file_iter(required_path("COLAND_TLS_CERT_PATH"))
        .expect("read the canonical server certificate")
        .collect::<Result<Vec<_>, _>>()
        .expect("parse the canonical server certificate chain");
    let key = PrivateKeyDer::from_pem_file(required_path("COLAND_TLS_KEY_PATH"))
        .expect("parse the canonical server private key");
    rustls::ServerConfig::builder_with_provider(std::sync::Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("supported TLS protocol versions")
    .with_no_client_auth()
    .with_single_cert(certificates, key)
    .expect("the canonical certificate matches its private key")
}
