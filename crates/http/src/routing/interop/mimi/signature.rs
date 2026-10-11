use super::*;

/// Verify the per-request RFC 9421 provider-source signature.
///
/// The profile's applicability is closed by operation id, not by the
/// `read` / `command` half of that id: `ak.open.mimi.read.identifiers.v1`
/// carries the anti-enumeration boundary and MUST be signed, while
/// `ak.open.mimi.read.provider_directory.v1` MUST NOT inherit the profile.
/// See zh/extensions/mimi-interop.md section 5.
pub(super) async fn verify_mimi_source_service_signature(
    state: &AppState,
    req: &mut Request,
    room_uri: Option<&str>,
) -> Result<String, AppError> {
    let signature_present =
        req.headers().get("signature").is_some() && req.headers().get("signature-input").is_some();
    if !signature_present {
        return Err(mimi_signature_error_required(
            "this MIMI operation requires RFC 9421 Signature and Signature-Input headers",
        ));
    }

    let body_bytes = req
        .payload()
        .await
        .map_err(|error| {
            AppError::json_invalid(format!("unable to read MIMI request body: {error}"))
        })?
        .to_vec();
    let source_id = mimi_required_header(req, "source-service-id")?;
    let source_id = arkret_wire::DidCoreId::new(source_id)
        .map_err(|_| mimi_signature_error_invalid("Source-Service-ID must be a core id"))?;
    let destination_id = mimi_required_header(req, "destination-service-id")?;
    if destination_id != state.service_id().as_str() {
        return Err(mimi_signature_error_invalid(
            "Destination-Service-ID does not match this service",
        ));
    }
    let provider_id = mimi_required_header(req, "provider-id")?;
    if !provider_id.starts_with("mimi://") {
        return Err(mimi_signature_error_invalid(
            "Provider-ID must be a MIMI provider URI",
        ));
    }
    let signed_room_uri = match room_uri {
        Some(expected) => {
            let observed = mimi_required_header(req, "mimi-room-uri")?;
            if observed != expected {
                return Err(mimi_signature_error_invalid(
                    "MIMI-Room-URI does not match the addressed room",
                ));
            }
            Some(observed)
        }
        None => None,
    };

    let signature_input =
        http_signature::parse_signature_input_header(req).map_err(mimi_verification_error)?;
    let verification_method = mimi_validate_signature_input(&signature_input, &source_id)?;
    let target_uri = crate::routing::federation::signature_target_uri(req, state);
    let authority = crate::routing::federation::signature_authority(req, state);
    let applicable_conditionals = signed_room_uri
        .as_ref()
        .map(|_| &["mimi-room-uri"][..])
        .unwrap_or_default();
    let policy = SignatureVerificationPolicy::for_scenario(
        HttpSignatureScenario::MimiProviderV1,
        applicable_conditionals,
    )
    .map_err(|error| mimi_verification_error(HttpMessageVerificationError::Policy(error)))?;
    let verifying_key = mimi_resolve_verifying_key(state, &verification_method)?;
    http_signature::verify_signed_canonical_json_request(
        req,
        &target_uri,
        &authority,
        &body_bytes,
        &verifying_key,
        &policy,
    )
    .map_err(mimi_verification_error)?;
    Ok(source_id.to_string())
}

pub(super) fn mimi_required_header(req: &Request, name: &str) -> Result<String, AppError> {
    http_signature::required_header(req, name, |name| {
        mimi_signature_error_invalid(format!("missing required MIMI signature header: {name}"))
    })
}

pub(super) fn mimi_validate_signature_input(
    signature_input: &SignatureInput,
    source_id: &arkret_wire::DidCoreId,
) -> Result<String, AppError> {
    if signature_input.label != "sig1" {
        return Err(mimi_signature_error_invalid(
            "Signature-Input must use the sig1 label",
        ));
    }
    let verification_method = signature_input.key_id.clone();
    let controller = verification_method
        .split_once('?')
        .map_or(verification_method.as_str(), |(head, _)| head)
        .split_once('#')
        .map_or(verification_method.as_str(), |(head, _)| head);
    let controller_matches = arkret_wire::Did::new(controller.to_owned())
        .ok()
        .and_then(|did| arkret_wire::project_did_to_core_id(&did).ok())
        .as_ref()
        == Some(source_id);
    if !controller_matches {
        return Err(mimi_signature_error_invalid(
            "Signature-Input keyid controller must project to Source-Service-ID",
        ));
    }
    Ok(verification_method)
}

fn mimi_verification_error(error: HttpMessageVerificationError) -> AppError {
    match error {
        HttpMessageVerificationError::MissingHeader("Signature-Input" | "Signature") => {
            mimi_signature_error_required(error.to_string())
        }
        HttpMessageVerificationError::Signature(
            SignatureError::MissingSignatureInputParameter("created" | "expires"),
        )
        | HttpMessageVerificationError::Policy(
            SignaturePolicyError::InvalidValidityWindow
            | SignaturePolicyError::CreatedInFuture
            | SignaturePolicyError::CreatedTooOld
            | SignaturePolicyError::Expired,
        ) => mimi_signature_error_window(error.to_string()),
        _ => mimi_signature_error_invalid(error.to_string()),
    }
}

pub(super) fn mimi_resolve_verifying_key(
    state: &AppState,
    verification_method: &str,
) -> Result<ed25519_dalek::VerifyingKey, AppError> {
    crate::jws_verify::resolve_ed25519_pubkey(state, verification_method)
        .map_err(|_| mimi_signature_error_invalid("MIMI provider verification key is unavailable"))
}

/// `mimi-interop.md` §5 shares the per-delivery signature failure codes with
/// `applet-integration.md` §7.3.1: each failure carries its own registered
/// top-level code, never a generic code plus a `reason` extension.
pub(super) fn mimi_signature_error_required(message: impl Into<String>) -> AppError {
    crate::app_error!(HttpSignatureRequired, message)
}

pub(super) fn mimi_signature_error_invalid(message: impl Into<String>) -> AppError {
    crate::app_error!(HttpSignatureInvalid, message)
}

pub(super) fn mimi_signature_error_window(message: impl Into<String>) -> AppError {
    crate::app_error!(SignatureWindowInvalid, message)
}

#[cfg(test)]
mod signature_boundary_tests {
    use super::*;

    #[tokio::test]
    async fn bearer_does_not_replace_provider_transport_signature() {
        let mut config = crate::config::AppConfig::test_default();
        config.development_mode = true;
        let state = AppState::new(config, coland_storage_postgres::Db { pool: None });
        let mut request = Request::default();
        request
            .headers_mut()
            .insert("authorization", "Bearer arbitrary-session".parse().unwrap());
        let error = verify_mimi_source_service_signature(&state, &mut request, None)
            .await
            .unwrap_err();
        assert_eq!(error.code, arkret_wire::ErrorCode::HttpSignatureRequired);
    }

    #[test]
    fn unavailable_provider_key_is_not_synthesized_in_development() {
        let mut config = crate::config::AppConfig::test_default();
        config.development_mode = true;
        let state = AppState::new(config, coland_storage_postgres::Db { pool: None });
        let error =
            mimi_resolve_verifying_key(&state, "did:web:unresolved-provider.invalid#provider-key")
                .unwrap_err();
        assert_eq!(error.code, arkret_wire::ErrorCode::HttpSignatureInvalid);
    }
}
