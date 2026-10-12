use std::time::{Duration as StdDuration, Instant};

use arkret_signatures::http_signature::{
    HttpMessageVerificationError, HttpSignatureScenario, SignatureError, SignatureInput,
    SignaturePolicyError, SignatureVerificationPolicy,
};
use arkret_wire::{ErrorCode, ServiceOperationId};
use coland_http::error::AppError;
use coland_http::http_signature;
use ed25519_dalek::VerifyingKey;
use salvo::prelude::*;

use super::wire::FederationTrustHeaders;
use crate::state::AppState;

pub(super) const FEDERATION_AUTH_FAILURE_MESSAGE: &str = "federation request authentication failed";
const FEDERATION_AUTH_FAILURE_TIMING_BUCKET: StdDuration = StdDuration::from_millis(80);

/// Pad a failed federation/peer auth attempt that started at `started_at` up to
/// the constant [`FEDERATION_AUTH_FAILURE_TIMING_BUCKET`] (federation.md §3.2 /
/// §8.3 timing-bucket normalization), waiting via `tokio::time::sleep().await`
/// so the pad never blocks a tokio worker thread.
///
/// Previously this used a thread-local timing guard plus `std::thread::sleep`,
/// which pinned a worker for the full 80ms bucket on every failure — letting an
/// unauthenticated peer exhaust the runtime thread pool. The start instant is
/// now a plain local captured at verify entry and the sleep is async, so there
/// is no thread-local-across-`.await` hazard and no worker blocking.
async fn apply_federation_auth_failure_delay(started_at: Instant) {
    let remaining = FEDERATION_AUTH_FAILURE_TIMING_BUCKET
        .checked_sub(started_at.elapsed())
        .unwrap_or(FEDERATION_AUTH_FAILURE_TIMING_BUCKET);
    if remaining.as_nanos() > 0 {
        tokio::time::sleep(remaining).await;
    }
}

pub(super) fn validate_federation_request_binding(
    trust_domain: &str,
    req: &Request,
) -> Result<(), AppError> {
    let headers = FederationTrustHeaders::from_salvo_request(req).map_err(|violation| {
        signature_error(format!(
            "federation trust header validation failed: {}",
            violation.message()
        ))
    })?;
    let expected_destination = arkret_identifiers::TrustDomainId::new(trust_domain.to_owned())
        .map_err(|error| AppError::internal(format!("configured trust_domain invalid: {error}")))?;
    validate_federation_headers(&headers, &expected_destination)
}

pub(super) fn validate_federation_headers(
    headers: &FederationTrustHeaders,
    expected_destination: &arkret_identifiers::TrustDomainId,
) -> Result<(), AppError> {
    headers
        .verify_destination(expected_destination)
        .map_err(|_| {
            cross_domain_replay_error(
                "federation Destination-Trust-Domain header does not match this service",
            )
        })?;
    Ok(())
}

#[derive(Clone, Copy, Debug)]
pub(in crate::routing) struct VerifiedPeerKeyDigest(pub [u8; 32]);

/// Verify the inbound RFC 9421 HTTP Message Signature for a spec-canonical
/// `/_arkret/peer/*` request and enforce the local peer deny policy.
///
/// The canonical peer surface authenticates purely on the federation trust headers:
/// the origin is the `source-service-id` header, so there is no relay-inner
/// hop to verify. The function handles both bodied requests (POST submit /
/// query_post / resolve / invites / contacts) and bodyless GETs (query /
/// frontier / snapshot.head), binding the signature to an empty-body
/// Content-Digest in the latter case.
pub(in crate::routing) async fn verify_inbound_peer_http_signature(
    state: &AppState,
    req: &mut Request,
    has_body: bool,
) -> Result<(), AppError> {
    let body_bytes = match has_body {
        true => Some(
            req.payload()
                .await
                .map_err(|error| {
                    AppError::json_invalid(format!("unable to read peer request body: {error}"))
                })?
                .to_vec(),
        ),
        false => None,
    };
    // Bucket-normalize the failure timing without blocking a tokio worker:
    // run the synchronous verify body, then async-pad on the error path.
    let started_at = Instant::now();
    let outcome = verify_inbound_peer_http_signature_inner(state, req, body_bytes.as_deref()).await;
    if outcome.is_err() {
        apply_federation_auth_failure_delay(started_at).await;
    }
    let digest = outcome?;
    req.extensions_mut().insert(VerifiedPeerKeyDigest(digest));
    Ok(())
}

async fn verify_inbound_peer_http_signature_inner(
    state: &AppState,
    req: &Request,
    body_bytes: Option<&[u8]>,
) -> Result<[u8; 32], AppError> {
    let closed_peer_submit = is_closed_peer_submit(req.method().as_str(), req.uri().path());
    if body_bytes.is_some() {
        validate_federation_request_binding(state.config().trust_domain.as_str(), req)?;
    }

    let source_id = required_header(req, "source-service-id")?;
    let destination_id = required_header(req, "destination-service-id")?;
    let source_trust_domain = required_header(req, "source-trust-domain")?;
    let destination_trust_domain = required_header(req, "destination-trust-domain")?;

    if destination_id != *state.service_id() {
        return Err(signature_error(
            "Destination-Service-ID does not match this service",
        ));
    }
    if destination_trust_domain != state.config().trust_domain.as_str() {
        return Err(signature_error(
            "Destination-Trust-Domain does not match this service",
        ));
    }
    // Keep the asserted source domain in the signature transcript. A service
    // DID may legitimately describe a separately named deployment domain, so
    // deriving and comparing a domain from the DID would reject valid peers.
    let target_uri = signature_target_uri(req, state);
    let authority = signature_authority(req, state);
    let endpoint_digest = validate_destination_authority(state, req, &authority, &destination_id)?;
    let signature_input = http_signature::parse_signature_input_header(req)
        .map_err(|error| federation_verification_error(error, "outer", closed_peer_submit))?;
    validate_signature_input(&signature_input, &source_id, "outer")?;
    let idempotency_key = req
        .headers()
        .get("idempotency-key")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let (source_verifying_key, key_state_digest) = verifying_key_and_current_state_for_service_id(
        state,
        &source_id,
        &signature_input.key_id,
        closed_peer_submit,
    )
    .await?;
    let source_did = arkret_identity::verification_method_did(&signature_input.key_id)
        .map_err(|_| signature_error("source verification method is not a DID URL"))?;
    let source_verification_method = arkret_wire::DidUrl::new(signature_input.key_id.clone())
        .map_err(|_| signature_error("source verification method is not a DID URL"))?;
    let source_trust_domain = arkret_wire::TrustDomainId::new(source_trust_domain)
        .map_err(|_| signature_error("Source-Trust-Domain is invalid"))?;
    if let Err(error) = crate::test_material_admission::enforce_ed25519_admission(
        &source_verifying_key,
        &source_did,
        &source_verification_method,
        Some(&source_trust_domain),
    ) {
        state.discard_federation_peer_verification_keys(&source_id, &signature_input.key_id);
        state.dids().discard_cached_document(&source_did);
        state.invalidate_did_bindings(&source_did);
        return Err(current_peer_key_error(error, closed_peer_submit));
    }
    let scenario = if endpoint_digest.is_some() {
        HttpSignatureScenario::SignalRelayV1
    } else {
        HttpSignatureScenario::ServiceToServiceV1
    };
    let mut applicable_conditionals = vec!["source-trust-domain", "destination-trust-domain"];
    if body_bytes.is_some() {
        applicable_conditionals.push("content-digest");
    }
    if idempotency_key.is_some() {
        applicable_conditionals.push("idempotency-key");
    }
    if endpoint_digest.is_some() {
        applicable_conditionals.push("destination-service-endpoint-digest");
    }
    let policy = SignatureVerificationPolicy::for_scenario(scenario, &applicable_conditionals)
        .map_err(|error| {
            federation_verification_error(
                HttpMessageVerificationError::Policy(error),
                "outer",
                closed_peer_submit,
            )
        })?;
    let verification = match body_bytes {
        Some(body) => http_signature::verify_signed_canonical_json_request(
            req,
            &target_uri,
            &authority,
            body,
            &source_verifying_key,
            &policy,
        ),
        None => http_signature::verify_signed_http_request(
            req,
            &target_uri,
            &authority,
            &[],
            &source_verifying_key,
            &policy,
        ),
    };
    verification
        .map_err(|error| federation_verification_error(error, "outer", closed_peer_submit))?;
    state.install_federation_peer_verifying_key(None, &source_id, source_verifying_key);
    state.install_federation_peer_verification_method_key(
        None,
        &signature_input.key_id,
        source_verifying_key,
    );

    if crate::security::federation_origin_denied(&source_id) {
        return Err(signature_error("peer is denied by local federation policy"));
    }

    Ok(key_state_digest)
}

/// federation.md §3.2 line 105-106: verify the signed `@authority` host matches
/// the endpoint registered for the Destination-Service-ID. Because the inbound
/// path already enforces `destination_id == this service`, the
/// authoritative endpoint is this service's own published `public_base_url`.
///
/// Returns the `Destination-Service-Endpoint-Digest` to bind into the transcript
/// when the request carries that header (required on shared ingress, line 180);
/// when present it MUST equal the sha256 digest of the registered endpoint
/// canonical URL.
fn validate_destination_authority(
    state: &AppState,
    req: &Request,
    authority: &str,
    destination_id: &str,
) -> Result<Option<String>, AppError> {
    // The registered endpoint authority for this (destination) service.
    if let Some(expected_authority) = public_base_url_authority(state)
        && !authority.eq_ignore_ascii_case(&expected_authority)
    {
        crate::metrics::record_digest_mismatch("federation_authority_mismatch");
        return Err(signature_error(
            "signed @authority host does not match the Destination-Service-ID endpoint",
        ));
    }

    // Optional endpoint-digest binding (conditional-required on shared ingress).
    let observed = req
        .headers()
        .get("destination-service-endpoint-digest")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned);
    if let Some(observed_digest) = observed {
        let expected_digest = arkret_canonical::sha256_digest(
            state
                .config()
                .public_base_url
                .trim_end_matches('/')
                .as_bytes(),
        );
        if observed_digest != expected_digest {
            crate::metrics::record_digest_mismatch("federation_endpoint_digest_mismatch");
            return Err(signature_error(
                "Destination-Service-Endpoint-Digest does not match the registered endpoint",
            ));
        }
        // Sanity: the digest must be for *this* service's destination DID.
        debug_assert_eq!(destination_id, state.service_id());
        return Ok(Some(observed_digest));
    }
    Ok(None)
}

fn required_header(req: &Request, name: &str) -> Result<String, AppError> {
    http_signature::required_header(req, name, |name| {
        signature_error(format!("missing required federation header: {name}"))
    })
}

pub(super) fn validate_signature_input(
    signature_input: &SignatureInput,
    expected_service_id: &str,
    label: &str,
) -> Result<(), AppError> {
    if signature_input.label != "sig1" {
        return Err(signature_error(format!(
            "{label} Signature-Input must use the sig1 label"
        )));
    }
    let controller =
        arkret_identity::verification_method_did(&signature_input.key_id).map_err(|_| {
            signature_error(format!(
                "{label} Signature-Input keyid is not a DID verification method"
            ))
        })?;
    let expected_controller = arkret_identifiers::DidCoreId::new(expected_service_id.to_owned())
        .map_err(|_| signature_error(format!("{label} source service DID is invalid")))?;
    let controller_core = arkret_wire::project_did_to_core_id(&controller)
        .map_err(|_| signature_error(format!("{label} keyid controller cannot project")))?;
    if controller_core != expected_controller {
        return Err(signature_error(format!(
            "{label} Signature-Input keyid mismatch; key_rotation_hint=refresh_origin_service_id"
        )));
    }
    Ok(())
}

fn is_closed_peer_submit(method: &str, path: &str) -> bool {
    ServiceOperationId::from_http_request(method, path)
        == Some(ServiceOperationId::PeerEventsCommandSubmitV1)
}

fn federation_verification_error(
    error: HttpMessageVerificationError,
    label: &str,
    closed_peer_submit: bool,
) -> AppError {
    match error {
        HttpMessageVerificationError::ContentEncodingNotAllowed
        | HttpMessageVerificationError::NonCanonicalJson(_) => crate::app_error!(
            SchemaViolation,
            format!("peer signed JSON request is invalid: {error}"),
        ),
        HttpMessageVerificationError::Signature(SignatureError::ContentDigestMismatch) => {
            crate::metrics::record_digest_mismatch("peer_request_content_digest");
            signature_error("Content-Digest does not match peer canonical request body")
        }
        HttpMessageVerificationError::Signature(SignatureError::SignatureInvalid)
            if closed_peer_submit =>
        {
            current_peer_key_error(format!("{label} signature verification failed"), true)
        }
        HttpMessageVerificationError::Signature(
            SignatureError::MissingSignatureInputParameter("created" | "expires"),
        )
        | HttpMessageVerificationError::Policy(
            SignaturePolicyError::InvalidValidityWindow
            | SignaturePolicyError::CreatedInFuture
            | SignaturePolicyError::CreatedTooOld
            | SignaturePolicyError::Expired,
        ) => {
            // service-http-binding.md 8.3: every scenario shares
            // `ak.http_signature.freshness.v1`, whose failure is
            // `signature_window_invalid`.
            signature_error_with_code(
                format!("{label} signature window invalid: {error}"),
                ErrorCode::SignatureWindowInvalid,
            )
        }
        _ => signature_error(format!(
            "{label} signature verification failed: {error}; key_rotation_hint=refresh_origin_service_id"
        )),
    }
}

pub(in crate::routing) async fn verifying_key_for_service_id(
    state: &AppState,
    service_id: &str,
    verification_method: &str,
    closed_peer_submit: bool,
) -> Result<VerifyingKey, AppError> {
    verifying_key_and_current_state_for_service_id(
        state,
        service_id,
        verification_method,
        closed_peer_submit,
    )
    .await
    .map(|(key, _)| key)
}

async fn verifying_key_and_current_state_for_service_id(
    state: &AppState,
    service_id: &str,
    verification_method: &str,
    closed_peer_submit: bool,
) -> Result<(VerifyingKey, [u8; 32]), AppError> {
    if service_id == state.service_id() {
        // A split Account Authority signs as this Station using a method
        // delegated by its verified, durable DID history. A request-supplied
        // key or the equality of Source-Service-ID alone is never authority.
        let stored = state.stored_service_identity().await.map_err(|error| {
            current_peer_key_error(
                format!("local service identity unavailable: {error}"),
                closed_peer_submit,
            )
        })?;
        let document = &stored.did_document;
        let method = document
            .verification_method
            .iter()
            .find(|method| {
                method.id == verification_method
                    && method.controller == state.service_did()
                    && document.assertion_method.contains(&method.id)
            })
            .ok_or_else(|| {
                current_peer_key_error(
                    "local service signature method is not an active assertion key",
                    closed_peer_submit,
                )
            })?;
        let bytes =
            arkret_canonical::multibase::decode_ed25519_multibase(&method.public_key_multibase)
                .map_err(|error| {
                    current_peer_key_error(
                        format!("local assertion key is invalid: {error}"),
                        closed_peer_submit,
                    )
                })?;
        let key = VerifyingKey::from_bytes(&bytes).map_err(|error| {
            current_peer_key_error(
                format!("local assertion key is invalid: {error}"),
                closed_peer_submit,
            )
        })?;
        return Ok((key, verified_document_digest(document)?));
    }
    // Cached peer keys are historical verification material, not current
    // transport authority. Resolve the service's current method state on every
    // request, including an exact retry, before any inner admission is reached.
    let did = arkret_identity::verification_method_did(verification_method).map_err(|_| {
        current_peer_key_error(
            "source verification method is not a DID URL",
            closed_peer_submit,
        )
    })?;
    let current = match state.dids().resolve_current_service_did(&did).await {
        Ok(current) => current,
        Err(error) => {
            state.discard_federation_peer_verification_keys(service_id, verification_method);
            return Err(current_peer_key_error(
                format!("current source service key state unavailable: {error}"),
                closed_peer_submit,
            ));
        }
    };
    match current_peer_key_from_document(&current.document, &did, verification_method) {
        Ok(key) => Ok((key, verified_document_digest(&current.document)?)),
        Err(error) => {
            state.discard_federation_peer_verification_keys(service_id, verification_method);
            Err(current_peer_key_error(error, closed_peer_submit))
        }
    }
}

fn verified_document_digest(document: &impl serde::Serialize) -> Result<[u8; 32], AppError> {
    // Bind the verified current document, including assertion relationships
    // and every control key; the selected method alone is not a state cut.
    let bytes = arkret_canonical::canonical_json_bytes(document)
        .map_err(|error| AppError::internal(error.to_string()))?;
    Ok(arkret_canonical::sha256_bytes(&bytes))
}

fn current_peer_key_from_document(
    document: &arkret_identity::DidDocument,
    did: &arkret_wire::Did,
    verification_method: &str,
) -> Result<VerifyingKey, String> {
    let method = arkret_wire::DidUrl::new(verification_method.to_owned())
        .map_err(|error| error.to_string())?;
    arkret_identity::validate_verification_method_relationship(
        document,
        &method,
        did,
        arkret_identity::DidVerificationRelationship::AssertionMethod,
    )
    .map_err(|error| error.to_string())?;
    arkret_identity::jws::resolve_ed25519_pubkey_from_document(document, verification_method)
        .map_err(|error| error.to_string())
}

pub(in crate::routing) fn signature_target_uri(req: &Request, state: &AppState) -> String {
    // The signed target is the destination service's registered public
    // endpoint, not the reverse proxy's internal upstream URI. Salvo can
    // expose the Caddy -> Coland hop as `http://...` even when the client used
    // the advertised `https://...` endpoint, so the configured public origin
    // must win whenever it is available.
    let scheme = signature_target_scheme(&state.config().public_base_url, req.uri().scheme_str());
    let authority = signature_authority(req, state);
    let path_and_query = req
        .uri()
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or_else(|| req.uri().path());
    format!("{scheme}://{authority}{path_and_query}")
}

pub(in crate::routing) fn signature_authority(req: &Request, state: &AppState) -> String {
    // Behind a deployment gateway the upstream `Host` may be rewritten to the
    // internal origin, so prefer the client-visible `X-Forwarded-Host` (first
    // hop) the gateway records — matching how the peer / client signed the
    // `@authority` (and the DPoP `htu`, see `auth_grant_dpop::request_authority`).
    // Falls back to the request authority / `Host` / configured public origin for
    // a same-origin deployment with no proxy in front.
    forwarded_host_authority(req)
        .or_else(|| {
            req.uri()
                .authority()
                .map(|authority| authority.as_str().to_owned())
        })
        .or_else(|| {
            req.headers()
                .get("host")
                .and_then(|value| value.to_str().ok())
                .map(ToOwned::to_owned)
        })
        .or_else(|| public_base_url_authority(state))
        .unwrap_or_else(|| "server".to_owned())
}

/// Client-visible authority from `X-Forwarded-Host` (first hop), set by the
/// deployment gateway when it rewrites the upstream `Host`. Absent / empty →
/// `None` so the caller falls back to the request authority / `Host`.
fn forwarded_host_authority(req: &Request) -> Option<String> {
    req.headers()
        .get("x-forwarded-host")
        .and_then(|value| value.to_str().ok())
        .map(|value| value.split(',').next().unwrap_or(value).trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn signature_target_scheme(public_base_url: &str, request_scheme: Option<&str>) -> String {
    reqwest::Url::parse(public_base_url)
        .ok()
        .map(|url| url.scheme().to_owned())
        .or_else(|| request_scheme.map(ToOwned::to_owned))
        .unwrap_or_else(|| "http".to_owned())
}

fn public_base_url_authority(state: &AppState) -> Option<String> {
    let url = reqwest::Url::parse(&state.config().public_base_url).ok()?;
    let host = url.host_str()?;
    Some(
        url.port()
            .map(|port| format!("{host}:{port}"))
            .unwrap_or_else(|| host.to_owned()),
    )
}

fn signature_error(message: impl Into<String>) -> AppError {
    signature_error_with_code(message, ErrorCode::Unauthenticated)
}

fn current_peer_key_error(message: impl Into<String>, closed_peer_submit: bool) -> AppError {
    let code = if closed_peer_submit {
        ErrorCode::SignatureInvalid
    } else {
        ErrorCode::Unauthenticated
    };
    signature_error_with_code(message, code)
}

fn signature_error_with_code(message: impl Into<String>, code: ErrorCode) -> AppError {
    let detail = message.into();
    tracing::warn!(
        federation_auth_detail = %detail,
        "federation request authentication failed"
    );
    AppError::from_rejection(code, FEDERATION_AUTH_FAILURE_MESSAGE)
}

#[cfg(test)]
mod signature_target_tests {
    use super::signature_target_scheme;

    #[test]
    fn public_endpoint_scheme_wins_over_reverse_proxy_upstream_scheme() {
        assert_eq!(
            signature_target_scheme("https://local.host/", Some("http")),
            "https"
        );
    }

    #[test]
    fn request_scheme_is_used_when_public_endpoint_is_invalid() {
        assert_eq!(signature_target_scheme("not a URL", Some("https")), "https");
    }
}

fn cross_domain_replay_error(message: impl Into<String>) -> AppError {
    let detail = message.into();
    tracing::warn!(
        federation_auth_detail = %detail,
        "federation cross-domain replay check failed"
    );
    AppError::unauthenticated(FEDERATION_AUTH_FAILURE_MESSAGE)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn federation_auth_errors_share_public_message() {
        assert_eq!(
            signature_error("missing required federation header: signature")
                .message
                .as_ref(),
            FEDERATION_AUTH_FAILURE_MESSAGE
        );
        assert_eq!(
            cross_domain_replay_error("Destination-Trust-Domain mismatch")
                .message
                .as_ref(),
            FEDERATION_AUTH_FAILURE_MESSAGE
        );
    }

    #[test]
    fn only_closed_peer_submit_classifies_current_key_failure_as_signature_invalid() {
        assert!(is_closed_peer_submit("POST", "/_arkret/peer/events"));
        assert!(!is_closed_peer_submit("GET", "/_arkret/peer/events"));
        assert!(!is_closed_peer_submit("POST", "/_arkret/peer/events/scan"));
        for closed in [false, true] {
            let expected = if closed {
                ErrorCode::SignatureInvalid
            } else {
                ErrorCode::Unauthenticated
            };
            let current_key = current_peer_key_error("private key-state reason", closed);
            let invalid_signature = federation_verification_error(
                HttpMessageVerificationError::Signature(SignatureError::SignatureInvalid),
                "outer",
                closed,
            );
            for error in [current_key, invalid_signature] {
                assert_eq!(error.code, expected);
                assert_eq!(error.http_status(), salvo::http::StatusCode::UNAUTHORIZED);
                assert_eq!(error.message.as_ref(), FEDERATION_AUTH_FAILURE_MESSAGE);
            }
        }
        let expired = federation_verification_error(
            HttpMessageVerificationError::Policy(SignaturePolicyError::Expired),
            "outer",
            true,
        );
        assert_eq!(expired.code, ErrorCode::SignatureWindowInvalid);
        assert_eq!(expired.http_status(), salvo::http::StatusCode::UNAUTHORIZED);
        assert_eq!(expired.message.as_ref(), FEDERATION_AUTH_FAILURE_MESSAGE);
    }

    /// The failure-timing pad is now applied via `tokio::time::sleep().await`
    /// (non-blocking) rather than `std::thread::sleep`, so a fast auth failure
    /// is still padded up to the constant bucket but without pinning a worker.
    #[tokio::test(start_paused = true)]
    async fn federation_auth_failure_delay_pads_to_bucket() {
        // The pad is `tokio::time::sleep(remaining).await`. Under
        // `start_paused`, tokio auto-advances its *virtual* clock to satisfy the
        // sleep, so we measure with `tokio::time::Instant` (which tracks the
        // virtual clock) rather than `std::time::Instant` (wall-clock, which the
        // paused runtime does not advance). `started_at` is a `std`-clock value
        // captured immediately before the call, so its `elapsed()` is ~0 and the
        // function pads by the full bucket.
        let virtual_start = tokio::time::Instant::now();
        let started_at = Instant::now();
        apply_federation_auth_failure_delay(started_at).await;
        assert!(virtual_start.elapsed() >= FEDERATION_AUTH_FAILURE_TIMING_BUCKET);
    }

    #[tokio::test]
    async fn current_peer_key_does_not_restore_revoked_cache_when_resolver_is_unavailable() {
        let state = AppState::new(
            crate::config::AppConfig {
                development_mode: true,
                did_resolver_allow_methods: vec!["web".into()],
                ..crate::config::AppConfig::test_default()
            },
            coland_storage_postgres::Db { pool: None },
        );
        let did = arkret_wire::Did::new("did:web:127.0.0.1%3A9".to_owned()).unwrap();
        let service_id = arkret_wire::project_did_to_core_id(&did)
            .unwrap()
            .to_string();
        let method = format!("{did}#federation-fanout-key");
        let historical = ed25519_dalek::SigningKey::from_bytes(&[79; 32]).verifying_key();
        state.install_federation_peer_verifying_key(None, &service_id, historical);
        state.install_federation_peer_verification_method_key(None, &method, historical);
        state.discard_federation_peer_verification_keys(&service_id, &method);
        // Old historical material may still arrive from another proof rail.
        // Current transport authentication must never recover it from a cache
        // or a deterministic development key after a fresh lookup fails.
        state.install_federation_peer_verifying_key(None, &service_id, historical);
        state.install_federation_peer_verification_method_key(None, &method, historical);
        let error = verifying_key_for_service_id(&state, &service_id, &method, true)
            .await
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::SignatureInvalid);
        assert_eq!(error.message.as_ref(), FEDERATION_AUTH_FAILURE_MESSAGE);
        assert!(state.federation_peer_verifying_key(&service_id).is_none());
    }

    #[test]
    fn current_peer_key_refuses_a_removed_assertion_even_if_key_bytes_remain() {
        let did = arkret_wire::Did::new("did:web:peer.example").unwrap();
        let method = format!("{did}#service-key");
        let key = ed25519_dalek::SigningKey::from_bytes(&[79; 32]).verifying_key();
        let mut document = arkret_identity::DidDocument {
            id: did.clone(),
            verification_methods: std::collections::BTreeMap::from([(
                method.clone(),
                arkret_canonical::ed25519_pubkey_to_did_key_multibase(key.as_bytes()),
            )]),
            also_known_as: Vec::new(),
            updated_at: None,
            raw_properties: std::collections::BTreeMap::from([(
                "assertionMethod".to_owned(),
                serde_json::json!([method]),
            )]),
        };
        assert_eq!(
            current_peer_key_from_document(&document, &did, &method).unwrap(),
            key
        );
        document
            .raw_properties
            .insert("assertionMethod".to_owned(), serde_json::json!([]));
        assert!(current_peer_key_from_document(&document, &did, &method).is_err());
        document.raw_properties.insert(
            "assertionMethod".to_owned(),
            serde_json::json!(["#replacement"]),
        );
        assert!(current_peer_key_from_document(&document, &did, &method).is_err());
    }
}
