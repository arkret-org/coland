// ════════════════════════════════════════════════════════════════════════
// Federation S2S trust-domain headers.
// ════════════════════════════════════════════════════════════════════════

/// Spec B1.7 — the two federation trust-domain headers that MUST appear
/// on every inbound federation request.
#[derive(Debug, Clone)]
pub(crate) struct FederationTrustHeaders {
    // Retain the validated source; peer signature verification authenticates it separately.
    pub _source_trust_domain: arkret_identifiers::TrustDomainId,
    pub destination_trust_domain: arkret_identifiers::TrustDomainId,
}

impl FederationTrustHeaders {
    /// Spec B1.7 — extract + validate the three headers from a salvo
    /// `Request`. Returns the typed pair on success or a
    /// [`HeaderViolation`] on the first missing / malformed header.
    pub(crate) fn from_salvo_request(req: &salvo::http::Request) -> Result<Self, HeaderViolation> {
        let header_value = |name: &str| -> Result<&str, HeaderViolation> {
            let value = req
                .headers()
                .get(name)
                .ok_or_else(|| HeaderViolation::Missing(name.to_owned()))?;
            value
                .to_str()
                .map_err(|_| HeaderViolation::Malformed(name.to_owned()))
        };
        let source = header_value(arkret_wire::constants::HEADER_SOURCE_TRUST_DOMAIN)?.to_owned();
        let destination =
            header_value(arkret_wire::constants::HEADER_DESTINATION_TRUST_DOMAIN)?.to_owned();
        let source = arkret_identifiers::TrustDomainId::new(source).map_err(|_| {
            HeaderViolation::Malformed(
                arkret_wire::constants::HEADER_SOURCE_TRUST_DOMAIN.to_owned(),
            )
        })?;
        let destination = arkret_identifiers::TrustDomainId::new(destination).map_err(|_| {
            HeaderViolation::Malformed(
                arkret_wire::constants::HEADER_DESTINATION_TRUST_DOMAIN.to_owned(),
            )
        })?;
        Ok(Self {
            _source_trust_domain: source,
            destination_trust_domain: destination,
        })
    }

    /// Spec B1.7 — verify the inbound `destination_trust_domain` matches
    /// the receiver's configured trust domain. Mismatch →
    /// `cross_domain_replay_rejected`.
    pub(crate) fn verify_destination(
        &self,
        expected: &arkret_identifiers::TrustDomainId,
    ) -> Result<(), &'static str> {
        if self.destination_trust_domain != *expected {
            return Err(arkret_wire::ReasonCode::CROSS_DOMAIN_REPLAY_REJECTED);
        }
        Ok(())
    }
}

/// Spec B1.7 — reasons a federation header check can fail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum HeaderViolation {
    Missing(String),
    Malformed(String),
}

impl HeaderViolation {
    pub(crate) fn message(&self) -> String {
        match self {
            Self::Missing(name) => format!("required federation header {name} missing"),
            Self::Malformed(name) => format!("federation header {name} malformed"),
        }
    }
}
