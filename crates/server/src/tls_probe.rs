//! Verify the public TLS terminator, including rejection of classical fallback.
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};
use coland_http::config::AppConfig;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore};

const IO_TIMEOUT: Duration = Duration::from_secs(3);

fn client(roots: &RootCertStore, hybrid: bool, tls12: bool) -> Result<Arc<ClientConfig>> {
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    provider.kx_groups = if hybrid {
        vec![rustls::crypto::aws_lc_rs::kx_group::X25519MLKEM768]
    } else {
        vec![
            rustls::crypto::aws_lc_rs::kx_group::X25519,
            rustls::crypto::aws_lc_rs::kx_group::SECP256R1,
            rustls::crypto::aws_lc_rs::kx_group::SECP384R1,
        ]
    };
    let versions = if tls12 {
        &[&rustls::version::TLS12][..]
    } else {
        &[&rustls::version::TLS13][..]
    };
    Ok(Arc::new(
        ClientConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(versions)?
            .with_root_certificates(roots.clone())
            .with_no_client_auth(),
    ))
}

fn handshake(
    address: SocketAddr,
    host: &str,
    config: Arc<ClientConfig>,
) -> Result<ClientConnection, std::io::Error> {
    let mut socket = TcpStream::connect_timeout(&address, IO_TIMEOUT)?;
    socket.set_read_timeout(Some(IO_TIMEOUT))?;
    socket.set_write_timeout(Some(IO_TIMEOUT))?;
    let name = ServerName::try_from(host.to_owned()).map_err(std::io::Error::other)?;
    let mut connection = ClientConnection::new(config, name).map_err(std::io::Error::other)?;
    while connection.is_handshaking() {
        connection.complete_io(&mut socket)?;
    }
    Ok(connection)
}

fn require_rejection(result: Result<ClientConnection, std::io::Error>) -> Result<()> {
    match result {
        Ok(_) => bail!("public TLS endpoint accepts classical-only TLS"),
        Err(error) => {
            // A timeout, certificate failure or reset does not prove that the
            // server enforces its policy. Require a TLS policy rejection.
            let policy_rejection = matches!(
                error
                    .get_ref()
                    .and_then(|e| e.downcast_ref::<rustls::Error>()),
                Some(rustls::Error::AlertReceived(
                    rustls::AlertDescription::HandshakeFailure
                        | rustls::AlertDescription::InsufficientSecurity
                        | rustls::AlertDescription::ProtocolVersion
                ))
            );
            ensure!(
                policy_rejection,
                "TLS rejection probe was inconclusive: {error}"
            );
            Ok(())
        }
    }
}

fn verify_address(address: SocketAddr, host: &str, roots: &RootCertStore) -> Result<()> {
    let connection = handshake(address, host, client(roots, true, false)?)
        .context("public PQ-hybrid TLS handshake failed")?;
    ensure!(
        connection.protocol_version() == Some(rustls::ProtocolVersion::TLSv1_3),
        "TLS 1.3 required"
    );
    ensure!(
        connection
            .negotiated_key_exchange_group()
            .is_some_and(|group| group.name() == rustls::NamedGroup::X25519MLKEM768),
        "X25519MLKEM768 required"
    );
    require_rejection(handshake(address, host, client(roots, false, false)?))?;
    require_rejection(handshake(address, host, client(roots, false, true)?))?;
    Ok(())
}

fn verify_public_endpoint(base: &str) -> Result<()> {
    let url = url::Url::parse(base)?;
    ensure!(url.scheme() == "https", "public TLS probe requires HTTPS");
    let host = url.host_str().context("public URL has no host")?;
    let port = url
        .port_or_known_default()
        .context("public URL has no port")?;
    let explicit_roots =
        std::env::var_os("SSL_CERT_FILE").is_some() || std::env::var_os("SSL_CERT_DIR").is_some();
    let mut roots = if explicit_roots {
        RootCertStore::empty()
    } else {
        RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned())
    };
    let loaded = rustls_native_certs::load_native_certs();
    roots.add_parsable_certificates(loaded.certs);
    ensure!(
        !roots.is_empty(),
        "no native certificate roots for TLS probe"
    );
    let addresses: Vec<_> = (host, port).to_socket_addrs()?.collect();
    ensure!(
        !addresses.is_empty(),
        "public TLS endpoint resolved no addresses"
    );
    // Every advertised address must enforce the policy. Test positive and
    // negative handshakes against each same address, with the real SNI name.
    for address in addresses {
        verify_address(address, host, &roots)?;
    }
    Ok(())
}

pub async fn verify_deployment(config: &mut AppConfig) {
    if config.development_mode || config.pq_hybrid_tls_probe.is_some() {
        return;
    }
    for attempt in 1..=3 {
        let base = config.public_base_url.clone();
        let result = tokio::time::timeout(
            Duration::from_secs(15),
            tokio::task::spawn_blocking(move || verify_public_endpoint(&base)),
        )
        .await;
        match result {
            Ok(Ok(Ok(()))) => {
                config.pq_hybrid_tls_probe = Some("verified".to_owned());
                tracing::info!(
                    group = "X25519MLKEM768",
                    "public TLS deployment probe verified; classical TLS 1.3 and TLS 1.2 rejected"
                );
                return;
            }
            result => {
                tracing::warn!(attempt, error = ?result, "public TLS deployment probe failed; readiness remains fail-closed")
            }
        }
        if attempt < 3 {
            tokio::time::sleep(Duration::from_secs(3)).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};

    use super::*;

    fn fixture(
        hybrid_only: bool,
        tls12: bool,
        count: usize,
    ) -> (SocketAddr, RootCertStore, std::thread::JoinHandle<()>) {
        let cert =
            CertificateDer::from(include_bytes!("../tests/fixtures/outbox-test-cert.der").to_vec());
        let key = PrivateKeyDer::try_from(
            include_bytes!("../tests/fixtures/outbox-test-key.der").to_vec(),
        )
        .unwrap();
        let mut provider = rustls::crypto::aws_lc_rs::default_provider();
        if hybrid_only {
            provider.kx_groups = vec![rustls::crypto::aws_lc_rs::kx_group::X25519MLKEM768];
        }
        let versions = if tls12 {
            &[&rustls::version::TLS13, &rustls::version::TLS12][..]
        } else {
            &[&rustls::version::TLS13][..]
        };
        let server = Arc::new(
            rustls::ServerConfig::builder_with_provider(Arc::new(provider))
                .with_protocol_versions(versions)
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(vec![cert], key)
                .unwrap(),
        );
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let task = std::thread::spawn(move || {
            for _ in 0..count {
                let (mut socket, _) = listener.accept().unwrap();
                socket.set_read_timeout(Some(IO_TIMEOUT)).unwrap();
                socket.set_write_timeout(Some(IO_TIMEOUT)).unwrap();
                let mut connection = rustls::ServerConnection::new(server.clone()).unwrap();
                while connection.is_handshaking() {
                    if connection.complete_io(&mut socket).is_err() {
                        break;
                    }
                }
            }
        });
        let mut roots = RootCertStore::empty();
        roots
            .add(
                CertificateDer::from_pem_slice(include_bytes!(
                    "../tests/fixtures/outbox-test-ca.pem"
                ))
                .unwrap(),
            )
            .unwrap();
        (address, roots, task)
    }

    #[test]
    fn verifies_hybrid_only_tls13_endpoint() {
        let (address, roots, server) = fixture(true, false, 3);
        verify_address(address, "127.0.0.1", &roots).unwrap();
        server.join().unwrap();
    }

    #[test]
    fn rejects_classical_fallback_even_with_hybrid_support() {
        let (address, roots, server) = fixture(false, false, 2);
        assert!(
            verify_address(address, "127.0.0.1", &roots)
                .unwrap_err()
                .to_string()
                .contains("classical-only")
        );
        server.join().unwrap();
    }

    #[test]
    fn network_failure_is_not_verified_rejection() {
        assert!(
            require_rejection(Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "timeout"
            )))
            .is_err()
        );
    }
}
