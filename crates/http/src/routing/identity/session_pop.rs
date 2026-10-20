//! RFC 9421 sender-constrained (PoP) verification for `/_arkret/self/*`.
//!
//! `ak.session.grant` binds a short-lived `session_public_key` to the
//! principal / device / audience (api-conventions.md §3.2). This hoop turns
//! "holds a bearer token" into "holds the bound signing key" for the
//! authenticated self surface:
//!
//! - When the client presents an RFC 9421 HTTP Message Signature, it MUST verify against the
//!   session's `session_public_key`: covered components, `content-digest` over the body, the
//!   `created`/`expires` window (≤300s, ±30s skew, same scale as the federation rail) and the
//!   `keyid` binding. Any failure is rejected as `unauthenticated`.
//! - On a high-security deployment (`sovereign_enclave_enabled`), protected self-surface operations
//!   are classified from generated operation descriptors and MUST be PoP-presented; unknown
//!   operations fail closed. Explicit public-projection exceptions are treated as unauthenticated
//!   when no valid proof is present.
//! - The session key the signature verifies against is sourced per inbound credential: for the ②
//!   grant+DPoP path it is the grant's `session_public_key` (read via introspection, since that
//!   session is request-scoped and never persisted); for a dev-login bearer it is the persisted
//!   `SessionRecord`'s key. Under ② the same Ed25519 device key backs both the DPoP `cnf.jkt`
//!   sender-constraint and this 9421 body-integrity layer.
//!
//! Session credential validation itself still runs in the per-handler
//! `AuthArgs::authenticated_session`; this hoop only adds the RFC 9421 layer.

use arkret_signatures::http_signature::{
    ContentDigest, HttpSignatureScenario, SignatureVerificationPolicy, public_key_from_bytes,
    verify_content_digest, verify_signed_http_message,
};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use coland_http::error::AppError;
use coland_http::util::{bearer_token, dpop_token};
use ed25519_dalek::VerifyingKey;
use salvo::prelude::*;

use crate::routing::federation::{signature_authority, signature_target_uri};
use crate::routing::identity::auth::session_credential_hash;
use crate::state::AppState;

/// Hoop mounted on the `self` surface. Continues the chain on success, renders
/// the canonical error envelope and stops on PoP failure.
#[handler]
pub async fn verify_session_pop(
    req: &mut Request,
    depot: &mut Depot,
    res: &mut Response,
    ctrl: &mut FlowCtrl,
) {
    let state = depot
        .get_typed::<AppState>()
        .expect("state injected")
        .clone();
    if req.headers().contains_key("arkret-realm-actor-control") {
        match super::realm_actor_control::verify(&state, req).await {
            Ok(verified) => {
                depot.insert_typed(verified);
                ctrl.call_next(req, depot, res).await;
            }
            Err(error) => error.write(req, depot, res).await,
        }
        return;
    }
    if req.headers().contains_key("arkret-managed-device") {
        match super::applet_managed_device::verify(&state, req).await {
            Ok(verified) => {
                depot.insert_typed(verified);
                ctrl.call_next(req, depot, res).await;
            }
            Err(error) => error.write(req, depot, res).await,
        }
        return;
    }
    match enforce_session_pop(&state, req).await {
        Ok(()) => {
            ctrl.call_next(req, depot, res).await;
        }
        Err(error) => {
            error.write(req, depot, res).await;
        }
    }
}

/// Keep the credential pipeline's own classification when its rejection is
/// rendered here.
///
/// `api-conventions.md` §3.3: a dependency that is unreachable or answers
/// incompletely MUST fail closed as `temporarily_unavailable`; it MUST NOT be
/// reported as the user's grant having failed authentication. Flattening every
/// rejection to `unauthenticated` did exactly that.
fn auth_rejection(rejection: (StatusCode, &'static str, &'static str)) -> AppError {
    let (status, code, message) = rejection;
    match coland_http::error::ErrorCode::from_wire(code) {
        Some(code) => AppError::from_rejection(code, message),
        None if status.is_server_error() => AppError::internal(message).with_internal_reason(code),
        None => AppError::unauthenticated(message).with_internal_reason(code),
    }
}

/// The fixed native consumer reuses the exact original self-resource PoP gate.
/// It introduces no new endpoint, signature scenario, or exempt request class.
pub(crate) async fn enforce_native_reply_session_pop(
    state: &AppState,
    req: &mut Request,
) -> Result<(), AppError> {
    enforce_session_pop(state, req).await
}

async fn enforce_session_pop(state: &AppState, req: &mut Request) -> Result<(), AppError> {
    if request_matches_operation(req, arkret_wire::ServiceOperationId::SelfAgentResourceGetV1)
        && super::agents::agent_projection_service_authorized(
            state,
            req,
            arkret_wire::ServiceOperationId::SELF_AGENT_RESOURCE_GET_V1,
            false,
        )
        .await?
    {
        return Ok(());
    }
    // This registered Service branch is authenticated in the handler with
    // its own current assertion key, never with a session or a Device key.
    if req.headers().contains_key("source-service-id")
        && [
            arkret_wire::ServiceOperationId::SelfEventsCommandSubmitV1,
            arkret_wire::ServiceOperationId::SelfRealmActorReadMaterialV1,
            arkret_wire::ServiceOperationId::SelfAgentResourceGetV1,
            arkret_wire::ServiceOperationId::SelfManagementReviewCommandRequestV1,
            arkret_wire::ServiceOperationId::SelfManagementReviewReadStatusV1,
            arkret_wire::ServiceOperationId::SelfManagementReviewCommandDecideV1,
        ]
        .into_iter()
        .any(|operation| request_matches_operation(req, operation))
    {
        return Ok(());
    }
    let presented = req.headers().contains_key("signature-input");
    if !presented {
        if pop_required(state, req) {
            return Err(AppError::unauthenticated(
                "RFC 9421 PoP signature required for this operation on this deployment",
            ));
        }
        if state.config().sovereign_enclave_enabled && is_public_projection_request(req) {
            req.headers_mut().remove(salvo::http::header::AUTHORIZATION);
            req.headers_mut().remove("dpop");
        }
        return Ok(());
    }

    // A signature is present: it MUST verify against the session signing key.
    let jwk = session_signing_key_jwk(state, req).await?;
    let (public_key, explicit_kid, thumbprint) = parse_session_jwk(&jwk)?;

    coland_http::http_signature::reject_content_encoding(req, || {
        AppError::unauthenticated("PoP-signed JSON requests must not use Content-Encoding")
    })?;
    let body = req
        .payload()
        .await
        .map_err(|error| {
            crate::app_error!(
                JsonInvalid,
                format!("unable to read request body for PoP verification: {error}"),
            )
        })?
        .to_vec();
    if !body.is_empty() {
        let content_digest = req
            .headers()
            .get("content-digest")
            .and_then(|value| value.to_str().ok())
            .ok_or_else(|| {
                AppError::unauthenticated("PoP-signed request is missing Content-Digest")
            })?;
        let content_digest = ContentDigest::parse(content_digest).map_err(|error| {
            AppError::unauthenticated(format!("PoP Content-Digest is invalid: {error}"))
        })?;
        verify_content_digest(&content_digest, &body).map_err(|error| {
            AppError::unauthenticated(format!(
                "PoP Content-Digest does not match exact request bytes: {error}"
            ))
        })?;
        arkret_signatures::http_signature::validate_signed_canonical_json_body(false, &body)
            .map_err(|error| {
                AppError::unauthenticated(format!(
                    "PoP-signed request body is not canonical JSON: {error}"
                ))
            })?;
    }

    let method = req.method().as_str().to_owned();
    let target_uri = signature_target_uri(req, state);
    let authority = signature_authority(req, state);
    let path = req.uri().path().to_owned();
    let headers: Vec<(String, String)> = req
        .headers()
        .iter()
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|value| (name.as_str().to_owned(), value.to_owned()))
        })
        .collect();

    let mut applicable_conditionals = Vec::with_capacity(3);
    if !body.is_empty() {
        applicable_conditionals.push("content-digest");
    }
    for header_name in ["idempotency-key", "x-arkret-wait-for"] {
        if req.headers().contains_key(header_name) {
            applicable_conditionals.push(header_name);
        }
    }
    let policy = SignatureVerificationPolicy::for_scenario(
        HttpSignatureScenario::ClientSessionPopV1,
        &applicable_conditionals,
    )
    .map_err(|error| {
        AppError::unauthenticated(format!("RFC 9421 PoP policy is invalid: {error}"))
    })?;

    let verified = verify_signed_http_message(
        &method,
        &target_uri,
        &authority,
        &path,
        headers
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str())),
        &body,
        &public_key,
        &policy,
        chrono::Utc::now().timestamp(),
    )
    .map_err(|error| {
        AppError::unauthenticated(format!("RFC 9421 PoP verification failed: {error}"))
    })?;

    // The generated scenario policy enforces the shared created/expires
    // freshness profile as well as this request's conditional covered set.
    // keyid MUST point at the session's bound signing key (api-conventions.md
    // §3.2). The cryptographic binding is already enforced above by verifying
    // against the session key bytes; this rejects a mismatched selector.
    // Accept either the JWK's explicit `kid` or its RFC 7638 thumbprint, so a
    // client that selects by thumbprint and one that echoes the issued kid both
    // satisfy the binding.
    let key_id = &verified.signature_input.key_id;
    let key_id_bound = *key_id == thumbprint || explicit_kid.as_deref() == Some(key_id.as_str());
    if !key_id_bound {
        return Err(AppError::unauthenticated(
            "PoP signature keyid is not bound to the session signing key",
        ));
    }

    Ok(())
}

/// Resolve the session signing-key JWK that an RFC 9421 PoP signature MUST
/// verify against, for whichever inbound credential is being presented
/// (account-lifecycle.md §4.1 D6):
///
/// - **② grant + DPoP** (`DPoP` header present): the session is request-scoped and is NEVER
///   persisted as a local bearer, so the bound signing key is read from the grant's
///   `session_public_key`. The grant binds the same Ed25519 device key as both the DPoP `cnf.jkt`
///   and the 9421 `session_public_key`, so DPoP supplies the per-request sender-constraint while
///   this 9421 layer adds body integrity.
/// - **dev-login bearer**: the key comes from the persisted `SessionRecord`.
///
/// This hoop runs before the handler's own credential validation, so it is the
/// place that takes the request's **single** authoritative introspection result
/// (`api-conventions.md` §3.3). It takes it at the strictest freshness this
/// operation will need — the same predicate the handler uses — and memoizes it
/// on the request, so the later credential gate reuses this exact result
/// instead of introspecting a second time, and the `session_public_key` this
/// signature verifies against comes from that same result.
async fn session_signing_key_jwk(state: &AppState, req: &mut Request) -> Result<String, AppError> {
    if super::auth_grant_dpop::is_grant_dpop_presentation(req) {
        let token = dpop_token(req)
            .ok_or_else(|| AppError::unauthenticated("PoP presentation requires a session token"))?
            .to_owned();
        let force_fresh = super::auth::request_requires_fresh_introspection(req);
        let grant = super::auth_grant_dpop::take_request_authoritative_grant(
            state,
            req,
            &token,
            force_fresh,
        )
        .await
        .map_err(auth_rejection)?;
        return Ok(grant.session_public_key.into_string());
    }
    let token = bearer_token(req)
        .ok_or_else(|| AppError::unauthenticated("PoP presentation requires a session token"))?
        .to_owned();
    let token_hash = session_credential_hash(&token, state.service_id());
    let session = state
        .sessions()
        .session(&token_hash)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
        .ok_or_else(|| AppError::unauthenticated("session not found for PoP presentation"))?;
    session.session_public_key.ok_or_else(|| {
        AppError::unauthenticated("session is not bound to a signing key for PoP presentation")
    })
}

/// Whether an unsigned request must be rejected on a high-security deployment.
/// The classifier comes from generated operation descriptors; an unknown self
/// operation fails closed.
fn pop_required(state: &AppState, req: &Request) -> bool {
    if !state.config().sovereign_enclave_enabled || req.method() == salvo::http::Method::OPTIONS {
        return false;
    }
    !is_public_projection_request(req)
}

fn is_public_projection_request(req: &Request) -> bool {
    arkret_schema::UNAUTHENTICATED_PUBLIC_PROJECTION_OPERATIONS
        .iter()
        .copied()
        .any(|operation| request_matches_operation(req, operation))
}

pub(super) fn request_matches_operation(
    req: &Request,
    operation: arkret_wire::ServiceOperationId,
) -> bool {
    let descriptor = operation.descriptor();
    descriptor.http_method == req.method().as_str()
        && path_template_matches(descriptor.http_path, req.uri().path())
}

fn path_template_matches(template: &str, actual: &str) -> bool {
    let template_segments = template.trim_matches('/').split('/').collect::<Vec<_>>();
    let actual_segments = actual.trim_matches('/').split('/').collect::<Vec<_>>();
    template_segments.len() == actual_segments.len()
        && template_segments
            .iter()
            .zip(actual_segments)
            .all(|(expected, observed)| {
                (expected.starts_with('{') && expected.ends_with('}')) || *expected == observed
            })
}

/// Parse the stored session signing key JWK into its Ed25519 public key, the
/// explicit JWK `kid` (if any), and its RFC 7638 thumbprint. A presented keyid
/// is accepted if it matches either.
fn parse_session_jwk(jwk: &str) -> Result<(VerifyingKey, Option<String>, String), AppError> {
    let value: serde_json::Value = serde_json::from_str(jwk)
        .map_err(|_| AppError::unauthenticated("session signing key is not valid JWK JSON"))?;
    let kty = value
        .get("kty")
        .and_then(|value| value.as_str())
        .unwrap_or_default();
    let crv = value
        .get("crv")
        .and_then(|value| value.as_str())
        .unwrap_or_default();
    if kty != "OKP" || crv != "Ed25519" {
        return Err(AppError::unauthenticated(
            "session signing key is not an Ed25519 OKP JWK",
        ));
    }
    let x = value
        .get("x")
        .and_then(|value| value.as_str())
        .ok_or_else(|| AppError::unauthenticated("session signing key JWK is missing x"))?;
    let bytes = URL_SAFE_NO_PAD
        .decode(x.as_bytes())
        .map_err(|_| AppError::unauthenticated("session signing key JWK x is not base64url"))?;
    let public_key = public_key_from_bytes(&bytes).map_err(|_| {
        AppError::unauthenticated("session signing key JWK x is not a valid Ed25519 public key")
    })?;
    let explicit_kid = value
        .get("kid")
        .and_then(|value| value.as_str())
        .filter(|kid| !kid.is_empty())
        .map(ToOwned::to_owned);
    Ok((public_key, explicit_kid, jwk_thumbprint(x)?))
}

/// RFC 7638 JWK thumbprint for an Ed25519 OKP key with base64url `x`.
///
/// Delegates to the SDK's JCS-based `dpop_jwk_thumbprint` instead of
/// interpolating `x` into a JSON string template. The template was only safe
/// because every caller happened to validate `x` as base64url first — an
/// implicit call-order invariant that any reuse would have broken, producing
/// illegal JSON and a silently wrong thumbprint.
fn jwk_thumbprint(x: &str) -> Result<String, AppError> {
    let x = arkret_wire::Base64UrlString::new(x.to_owned())
        .map_err(|_| AppError::unauthenticated("session signing key JWK x is not base64url"))?;
    arkret_signatures::dpop_jwk_thumbprint(&arkret_signatures::JsonWebKey::ed25519(x))
        .map_err(|_| AppError::unauthenticated("session signing key JWK has no thumbprint"))
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 8037 §A.2 sample Ed25519 public key (a valid curve point).
    const RFC8037_X: &str = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo";
    // RFC 8037 §A.3 thumbprint of the key above.
    const RFC8037_THUMBPRINT: &str = "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k";

    #[tokio::test]
    async fn agent_authority_projection_reaches_its_service_authenticator_without_a_session() {
        let state = AppState::new(
            crate::config::AppConfig::test_default(),
            coland_storage_postgres::Db { pool: None },
        );
        let mut request = salvo::test::TestClient::get(
            "http://localhost/_arkret/self/agents/ak:did_core:web:agent.example",
        )
        .build();
        request
            .headers_mut()
            .insert("source-service-id", "unverified-service".parse().unwrap());
        // This only dispatches to the handler; its mandatory service verifier
        // still rejects missing, partial, or unauthorized signatures.
        assert!(enforce_session_pop(&state, &mut request).await.is_ok());
    }

    #[tokio::test]
    async fn agent_service_dispatch_does_not_exempt_sessions_or_unregistered_routes() {
        let state = AppState::new(
            crate::config::AppConfig::test_default(),
            coland_storage_postgres::Db { pool: None },
        );
        for (method, path, source) in [
            (
                "GET",
                "/_arkret/self/agents/ak:did_core:web:agent.example",
                false,
            ),
            ("GET", "/_arkret/self/agents", true),
            ("GET", "/_arkret/self/agents/agent/extra", true),
            (
                "POST",
                "/_arkret/self/agents/ak:did_core:web:agent.example",
                true,
            ),
            ("GET", "/_arkret/self/account/viewer", true),
        ] {
            let mut request =
                salvo::test::TestClient::get(format!("http://localhost{path}")).build();
            *request.method_mut() = method.parse().unwrap();
            request
                .headers_mut()
                .insert("signature-input", "sig1=()".parse().unwrap());
            if source {
                request
                    .headers_mut()
                    .insert("source-service-id", "unverified-service".parse().unwrap());
            }
            assert!(
                enforce_session_pop(&state, &mut request).await.is_err(),
                "{method} {path}"
            );
        }
    }

    #[test]
    fn thumbprint_matches_rfc8037_vector() {
        assert_eq!(jwk_thumbprint(RFC8037_X).unwrap(), RFC8037_THUMBPRINT);
    }

    #[test]
    fn jwk_without_kid_yields_thumbprint_only() {
        let jwk = format!("{{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"{RFC8037_X}\"}}");
        let (_key, explicit_kid, thumbprint) = parse_session_jwk(&jwk).expect("valid JWK");
        assert_eq!(explicit_kid, None);
        assert_eq!(thumbprint, RFC8037_THUMBPRINT);
    }

    #[test]
    fn jwk_with_explicit_kid_is_surfaced_alongside_thumbprint() {
        let jwk = format!(
            "{{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"{RFC8037_X}\",\"kid\":\"session-abc\"}}"
        );
        let (_key, explicit_kid, thumbprint) = parse_session_jwk(&jwk).expect("valid JWK");
        assert_eq!(explicit_kid.as_deref(), Some("session-abc"));
        assert_eq!(thumbprint, RFC8037_THUMBPRINT);
    }

    #[test]
    fn rejects_non_ed25519_jwk() {
        let jwk = format!("{{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"{RFC8037_X}\"}}");
        assert!(parse_session_jwk(&jwk).is_err());
    }

    #[test]
    fn rejects_jwk_missing_x() {
        let jwk = "{\"kty\":\"OKP\",\"crv\":\"Ed25519\"}";
        assert!(parse_session_jwk(jwk).is_err());
    }

    #[test]
    fn rejects_non_base64url_x() {
        let jwk = "{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"not base64!!\"}";
        assert!(parse_session_jwk(jwk).is_err());
    }

    #[test]
    fn operation_path_templates_match_only_the_registered_shape() {
        assert!(path_template_matches(
            "/_arkret/self/realms/{realm_id}/strands",
            "/_arkret/self/realms/realm-1/strands"
        ));
        assert!(!path_template_matches(
            "/_arkret/self/realms/{realm_id}/strands",
            "/_arkret/self/realms/realm-1/links"
        ));
        assert!(!path_template_matches(
            "/_arkret/self/realms/{realm_id}/strands",
            "/_arkret/self/realms/realm-1/strands/extra"
        ));
    }

    #[test]
    fn generated_policy_has_explicit_public_projection_exceptions() {
        let policy = arkret_schema::UNAUTHENTICATED_PUBLIC_PROJECTION_OPERATIONS;
        assert!(policy.contains(&arkret_wire::ServiceOperationId::SelfAccountReadDescribeV1));
        assert!(!policy.contains(&arkret_wire::ServiceOperationId::SelfCommittedEventReadScanV1));
    }

    #[tokio::test]
    async fn agent_service_claims_are_verified_before_session_pop() {
        let state = AppState::new(
            crate::config::AppConfig::test_default(),
            coland_storage_postgres::Db { pool: None },
        );
        let mut request = Request::new();
        *request.uri_mut() = "/_arkret/self/agents/agent".parse().unwrap();
        request
            .headers_mut()
            .insert("source-service-id", "untrusted".parse().unwrap());
        request
            .headers_mut()
            .insert("signature-input", "sig1=()".parse().unwrap());
        let error = enforce_session_pop(&state, &mut request).await.unwrap_err();
        assert_eq!(error.wire_code(), "unauthenticated");
        assert_eq!(
            error.message.as_ref(),
            "Agent service authentication failed"
        );

        // Trust headers on a different self operation cannot select this branch.
        *request.uri_mut() = "/_arkret/self/agents".parse().unwrap();
        let error = enforce_session_pop(&state, &mut request).await.unwrap_err();
        assert_eq!(
            error.message.as_ref(),
            "PoP presentation requires a session token"
        );
    }

    #[tokio::test]
    async fn signed_agent_user_read_still_requires_its_session_key() {
        let state = AppState::new(
            crate::config::AppConfig::test_default(),
            coland_storage_postgres::Db { pool: None },
        );
        let mut request = Request::new();
        *request.uri_mut() = "/_arkret/self/agents/agent".parse().unwrap();
        request
            .headers_mut()
            .insert("authorization", "Bearer missing-session".parse().unwrap());
        request
            .headers_mut()
            .insert("signature-input", "sig1=()".parse().unwrap());
        let error = enforce_session_pop(&state, &mut request).await.unwrap_err();
        assert_eq!(error.wire_code(), "unauthenticated");
        assert_eq!(
            error.message.as_ref(),
            "session not found for PoP presentation"
        );
    }
}
