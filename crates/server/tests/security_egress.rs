//! Egress guard behaviour that holds under the default (empty) egress policy.
//!
//! The sovereign-enclave cases that used to live here configured the gate by
//! mutating `COLAND_SOVEREIGN_ENCLAVE*` in the process environment behind an
//! `unsafe` block and a process-wide lock. The gate now reads a typed
//! `EgressPolicy` installed once at startup, so those cases belong with the
//! parameterised checks in `coland_http::security`
//! (`federation_outbound_trust_domain_denial_with_policy`), which take the
//! policy as an argument and need no globals at all.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use reqwest::Url;

#[test]
fn production_egress_rejects_private_targets() {
    for raw in [
        "http://127.0.0.1:8080/sink",
        "https://10.0.0.2/federation",
        "https://172.16.0.2/federation",
        "https://192.168.1.9/federation",
        "http://169.254.169.254/latest/meta-data",
        "http://[::1]/sink",
        "http://[fd00::1]/sink",
        "http://[fe80::1]/sink",
        "http://[64:ff9b::a00:1]/sink",
        "http://[2002:0a00:0001::1]/sink",
        "http://[2001:0000::f5ff:fffe]/sink",
    ] {
        let url = Url::parse(raw).unwrap();
        assert!(coland_http::security::validate_url_for_egress(&url, "test", false).is_err());
    }
}

#[test]
fn production_egress_rejects_transition_dns_private_answers() {
    let url = Url::parse("https://relay.example/federation").unwrap();
    for ip in [
        IpAddr::V6("64:ff9b::a00:1".parse().unwrap()),
        IpAddr::V6("2002:0a00:0001::1".parse().unwrap()),
        IpAddr::V6("2001:0000::f5ff:fffe".parse().unwrap()),
    ] {
        assert!(
            coland_http::security::validate_url_for_egress_with_resolved_ips(
                &url,
                "test",
                false,
                &[ip],
            )
            .is_err(),
            "{ip} should be blocked"
        );
    }
}

#[test]
fn production_egress_allows_public_ip_literal() {
    let url = Url::parse("https://93.184.216.34/federation").unwrap();
    assert!(coland_http::security::validate_url_for_egress(&url, "test", false).is_ok());
}

#[test]
fn production_egress_rejects_dns_private_answers() {
    let url = Url::parse("https://relay.example/federation").unwrap();
    let error = coland_http::security::validate_url_for_egress_with_resolved_ips(
        &url,
        "test",
        false,
        &[IpAddr::V4(Ipv4Addr::new(10, 42, 0, 12))],
    )
    .unwrap_err();
    assert!(
        error.contains("private address"),
        "unexpected error: {error}"
    );
}

#[test]
fn production_egress_rejects_mixed_dns_answers_to_limit_rebinding() {
    let url = Url::parse("https://relay.example/federation").unwrap();
    let error = coland_http::security::validate_url_for_egress_with_resolved_ips(
        &url,
        "test",
        false,
        &[
            IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
        ],
    )
    .unwrap_err();
    assert!(error.contains("loopback"));
}

#[test]
fn development_egress_can_allow_loopback() {
    let url = Url::parse("http://127.0.0.1:8698/health").unwrap();
    assert!(coland_http::security::validate_url_for_egress(&url, "test", true).is_ok());
}
