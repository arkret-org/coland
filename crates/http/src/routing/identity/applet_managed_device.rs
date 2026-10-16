//! Session-free managed Device transport identity. Business permission is
//! checked by each consumer against its authoritative target resources.

use arkret_models_integration::AppletManagedDeviceMetadata;
use arkret_signatures::http_signature::{HttpSignatureScenario, SignatureVerificationPolicy};
use arkret_wire::ServiceOperationId;
use coland_http::error::AppError;
use coland_http::http_signature;
use salvo::prelude::Request;

use crate::state::AppState;

/// Process-local result of the mounted authentication hoop. Never a Session,
/// wire credential, resource permission or reusable delivery authorization.
#[derive(Clone, Debug)]
pub(crate) struct VerifiedAppletManagedDevice {
    pub metadata: AppletManagedDeviceMetadata,
    pub authority: coland_storage::AppletManagedDeviceAuthority,
    pub operation: ServiceOperationId,
    pub transport_expires_at: chrono::DateTime<chrono::Utc>,
}

fn refused(detail: impl std::fmt::Display) -> AppError {
    AppError::unauthenticated(format!("managed Device authentication failed: {detail}"))
}

fn authority_error(error: coland_storage::PersistenceError) -> AppError {
    match error {
        coland_storage::PersistenceError::Conflict(_) => {
            refused("current identity or nonce refused")
        }
        _ => crate::app_error!(
            TemporarilyUnavailable,
            "managed Device current authority is unavailable"
        ),
    }
}

fn one_header<'a>(req: &'a Request, name: &str) -> Result<&'a str, AppError> {
    let all_values = req.headers().get_all(name);
    let mut values = all_values.iter();
    let value = values
        .next()
        .ok_or_else(|| refused(format!("missing {name}")))?;
    if values.next().is_some() {
        return Err(refused(format!("ambiguous {name}")));
    }
    value
        .to_str()
        .map_err(|_| refused(format!("invalid {name}")))
}

pub(crate) async fn verify(
    state: &AppState,
    req: &mut Request,
) -> Result<VerifiedAppletManagedDevice, AppError> {
    for name in ["authorization", "dpop", "source-service-id"] {
        if req.headers().contains_key(name) {
            return Err(refused("mixed authentication credentials"));
        }
    }
    for name in [
        "signature-input",
        "signature",
        "content-digest",
        "idempotency-key",
        "content-type",
    ] {
        if req.headers().contains_key(name) {
            one_header(req, name)?;
        }
    }
    let operation = ServiceOperationId::from_wire(one_header(req, "arkret-operation")?)
        .filter(|operation| arkret_wire::applet_managed_device_scope_rule(*operation).is_some())
        .ok_or_else(|| refused("operation is outside the managed Device allowlist"))?;
    if !super::session_pop::request_matches_operation(req, operation) {
        return Err(refused(
            "operation does not match the actual method and path",
        ));
    }
    let metadata =
        AppletManagedDeviceMetadata::from_header_value(one_header(req, "arkret-managed-device")?)
            .map_err(refused)?;
    if one_header(req, "destination-service-id")? != state.service_id()
        || metadata.account_id.station_id != state.service_core_id()
    {
        return Err(refused("target is not the Device's own Station"));
    }
    http_signature::reject_content_encoding(req, || refused("Content-Encoding is not permitted"))?;
    let bytes = req.payload().await.map_err(refused)?.to_vec();
    if !bytes.is_empty() && operation.descriptor().body_class != Some("binary_stream") {
        arkret_canonical::canonical::validate_canonical_bytes(&bytes).map_err(refused)?;
    }
    let authority = coland_storage::DeviceRevocationStore::applet_managed_device_authority(
        state.persistence(),
        &metadata.account_id,
        &metadata.device_id,
        chrono::Utc::now(),
    )
    .await
    .map_err(authority_error)?
    .ok_or_else(|| refused("accepted identity unavailable"))?;
    if metadata.authorization_event_id != authority.selector.authorization_ref.event_id
        || metadata.applet_id != authority.applet_id
        || !authority.scopes.contains_scope(&metadata.effective_scope)
    {
        return Err(refused(
            "metadata does not bind the current original authorization",
        ));
    }
    if let Some(arkret_wire::ManagedDeviceScopeRule::AllActions(actions)) =
        arkret_wire::applet_managed_device_scope_rule(operation)
        && !authority.scopes.permits(&metadata.effective_scope, actions)
    {
        return Err(refused(
            "original scope does not cover the operation's required actions",
        ));
    }
    let fingerprint = arkret_canonical::ed25519_pubkey_to_did_key_multibase(&authority.public_key);
    let key_id = format!("did:key:{fingerprint}#{fingerprint}");
    let input = http_signature::parse_signature_input_header(req).map_err(refused)?;
    if input.label != "sig1" || input.key_id != key_id {
        return Err(refused(
            "keyid is not the exact accepted Device fingerprint URL",
        ));
    }
    let mut conditional = Vec::new();
    if !bytes.is_empty() {
        conditional.push("content-digest");
    }
    if req.headers().contains_key("idempotency-key") {
        conditional.push("idempotency-key");
    }
    let policy = SignatureVerificationPolicy::for_scenario(
        HttpSignatureScenario::AppletManagedDeviceV1,
        &conditional,
    )
    .map_err(refused)?;
    let key = ed25519_dalek::VerifyingKey::from_bytes(&authority.public_key).map_err(refused)?;
    let verified = http_signature::verify_signed_http_request(
        req,
        &crate::routing::federation::signature_target_uri(req, state),
        &crate::routing::federation::signature_authority(req, state),
        &bytes,
        &key,
        &policy,
    )
    .map_err(refused)?;
    let retain_until = chrono::DateTime::from_timestamp(verified.signature_input.expires, 0)
        .ok_or_else(|| refused("signature expiry cannot be represented"))?;
    let authority = state
        .persistence()
        .consume_applet_managed_device_nonce(&authority, &metadata, retain_until)
        .await
        .map_err(authority_error)?;
    Ok(VerifiedAppletManagedDevice {
        metadata,
        authority,
        operation,
        transport_expires_at: retain_until,
    })
}

/// A component harness for the exact mounted production authentication hoop.
/// Its downstream echo is not an implementation of any business operation.
#[cfg(feature = "test-support")]
pub(crate) fn test_service(state: AppState) -> salvo::Service {
    use salvo::prelude::*;
    #[handler]
    async fn echo(depot: &Depot, res: &mut Response) {
        let verified = depot
            .get_typed::<VerifiedAppletManagedDevice>()
            .expect("production hoop identity");
        assert_eq!(verified.authority.account_id, verified.metadata.account_id);
        assert!(arkret_wire::applet_managed_device_scope_rule(verified.operation).is_some());
        res.render(Json(verified.metadata.clone()));
    }
    salvo::Service::new(
        Router::with_path("{**rest}")
            .hoop(salvo::affix_state::inject(state))
            .hoop(super::session_pop::verify_session_pop)
            .goal(echo),
    )
}
