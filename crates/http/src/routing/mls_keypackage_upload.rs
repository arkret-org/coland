//! One publication source, without manufacturing a Session for native Devices.
use super::*;

pub(super) struct UploadAuthority {
    pub owner_account_id: arkret_wire::AccountId,
    pub device_id: Option<String>,
    pub trust_binding: Option<KeyPackageTrustBinding>,
    pub publish_trust_anchor: coland_domain::reducer::mls::MlsKeyPackagePublishTrustAnchor,
    pub native: Option<(
        coland_storage::AppletManagedDeviceScopeGuard,
        chrono::DateTime<chrono::Utc>,
    )>,
}

pub(super) async fn resolve(
    state: &AppState,
    aa: &AuthArgs,
    req: &Request,
    body: &KeyPackagesUploadRequestBody,
    native: Option<&crate::routing::identity::applet_managed_device::VerifiedAppletManagedDevice>,
) -> Result<UploadAuthority, AppError> {
    body.validate_shape().map_err(AppError::param_invalid)?;
    if let Some(native) = native {
        let authority = &native.authority;
        if body.actor_id != arkret_wire::ActorId::account(authority.account_id.clone())
            || body.principal_id != authority.account_id.principal_id
            || body.device_id.as_ref() != Some(&authority.device_id)
            || body.agent_verification_method.is_some()
            || body.agent_key_authorize_event_id.is_some()
        {
            return Err(AppError::capability_denied(
                "KeyPackage owner must be the authenticated Account Device",
            ));
        }
        let scope = &native.metadata.effective_scope;
        let group = scope
            .canonical_mls_group_id()
            .map_err(|error| AppError::param_invalid(error.to_string()))?;
        if body.mls_group_id.as_ref() != Some(&group) || body.strand_id.is_some() {
            return Err(AppError::capability_denied(
                "native KeyPackage needs one exact signed MLS group target",
            ));
        }
        let fingerprint =
            arkret_canonical::ed25519_pubkey_to_did_key_multibase(&authority.public_key);
        if !crate::routing::identity::device_signature_kid_points_to_device_key(
            body.endpoint_signature.kid.as_str(),
            authority.account_id.principal_id.as_str(),
            &format!("did:key:{fingerprint}"),
        ) {
            return Err(AppError::param_invalid(
                "KeyPackage signature is not the original Device key",
            ));
        }
        let input = arkret_models_crypto::keypackages_upload_signing_input(&body.unsigned())
            .map_err(|error| AppError::param_invalid(error.to_string()))?;
        arkret_signatures::keypackages::verify_keypackage_signing_input(
            &authority.public_key,
            body.endpoint_signature.kid.as_str(),
            &input,
            &body.endpoint_signature,
        )
        .map_err(|_| AppError::param_invalid("device_signature_invalid"))?;
        let guard =
            crate::routing::identity::applet_managed_device::scope_guard(state, native).await?;
        let original = authority.selector.authorization_ref.event_id.to_string();
        return Ok(UploadAuthority {
            owner_account_id: authority.account_id.clone(),
            device_id: Some(authority.device_id.to_string()),
            trust_binding: Some(KeyPackageTrustBinding::device_authorize(original.clone())),
            publish_trust_anchor:
                coland_domain::reducer::mls::MlsKeyPackagePublishTrustAnchor::DeviceAuthorize(
                    original,
                ),
            native: Some((guard, native.transport_expires_at)),
        });
    }
    let session = aa.authenticated_session(state, req).await?;
    if session.account_pk.is_none() && session.agent_session().is_none() {
        return Err(AppError::capability_denied(
            "KeyPackage upload requires an account- or Agent-bound session",
        ));
    }
    // Resolve the actual full Account (or the accepted Agent controller),
    // never a credential issuer's local SQL identity.
    let owner_account_id = local_keypackage_owner_account_id(state, &session).await?;

    body.validate_shape().map_err(AppError::param_invalid)?;
    if session.agent_session().is_some()
        != (body.device_id.is_none()
            && body.agent_verification_method.is_some()
            && body.agent_key_authorize_event_id.is_some())
    {
        return Err(AppError::capability_denied(
            "KeyPackage signer branch must match the calling session",
        ));
    }
    let principal_id = body.principal_id.clone();
    let actor_id = body.principal_id.to_string();
    let expected_actor = arkret_wire::ActorId::account(arkret_wire::AccountId {
        principal_id: principal_id.clone(),
        station_id: state.service_core_id().clone(),
    });
    if actor_id != session.actor || body.actor_id != expected_actor {
        return Err(AppError::capability_denied(
            "actor_id must match the calling session",
        ));
    }
    if body.keypackages.is_empty() {
        return Err(AppError::param_missing("keypackages is required"));
    }
    let (device_id, trust_binding, publish_trust_anchor) = if let Some(device_id) = &body.device_id
    {
        if device_id.as_str() != session.require_human_device_id() {
            return Err(AppError::capability_denied(
                "device_id must match the calling session",
            ));
        }
        // `device-lifecycle.md` 15: an Applet-managed principal's delegated
        // device loses new KeyPackage publication the moment its install is
        // fenced, without waiting for an `ak.device.revoke`. The accepted
        // authorize still standing in the PCR is explicitly not enough.
        crate::routing::extensions::applet_bridge::ensure_delegated_device_not_fenced(
            state,
            &principal_id,
        )
        .await?;
        let binding =
            current_keypackage_trust_binding(state, &principal_id, device_id.as_str()).await?;
        let anchor = match (
            binding.device_authorize_event_id.as_ref(),
            binding.agent_key_authorize_event_id.as_ref(),
        ) {
            (Some(event_id), None) => {
                coland_domain::reducer::mls::MlsKeyPackagePublishTrustAnchor::DeviceAuthorize(
                    event_id.clone(),
                )
            }
            _ => {
                return Err(AppError::param_invalid(
                    "device upload has no active device authorization",
                ));
            }
        };
        (Some(device_id.as_str().to_owned()), Some(binding), anchor)
    } else if let (Some(method), Some(event_id)) = (
        &body.agent_verification_method,
        &body.agent_key_authorize_event_id,
    ) {
        if !current_agent_key_authorization_matches_method(
            state,
            &principal_id,
            event_id.as_str(),
            method.as_str(),
        )
        .await
        {
            return Err(AppError::capability_denied(
                "Agent KeyPackage method or authorization is not current",
            ));
        }
        (
            None,
            Some(KeyPackageTrustBinding::agent_key_authorize(
                event_id.as_str().to_owned(),
            )),
            coland_domain::reducer::mls::MlsKeyPackagePublishTrustAnchor::AgentKeyAuthorize {
                event_id: event_id.as_str().to_owned(),
                verification_method: method.as_str().to_owned(),
            },
        )
    } else {
        return Err(AppError::param_invalid(
            "KeyPackage upload has no valid endpoint",
        ));
    };
    let endpoint_device_id = device_id.as_deref();
    let unsigned_upload = body.unsigned();
    let upload_signing_input =
        arkret_models_crypto::http_bodies::keypackages_upload_signing_input(&unsigned_upload)
            .map_err(|error| {
                AppError::param_invalid(format!(
                    "KeyPackage upload canonical input failed: {error}"
                ))
            })?;
    if let Some(authorize_event_id) = trust_binding
        .as_ref()
        .and_then(|binding| binding.agent_key_authorize_event_id.as_deref())
    {
        verify_agent_keypackage_batch(
            state,
            &principal_id,
            authorize_event_id,
            &body.endpoint_signature,
            &upload_signing_input,
        )
        .await
        .map_err(AppError::param_invalid)?;
    } else if device_id.is_some() {
        verify_device_keypackage_signature(
            state,
            &principal_id,
            endpoint_device_id.expect("validated device upload has a device id"),
            &body.endpoint_signature,
            &upload_signing_input,
        )
        .await?;
    } else {
        return Err(AppError::param_invalid(
            "KeyPackage upload has no authorized signer",
        ));
    }

    Ok(UploadAuthority {
        owner_account_id,
        device_id,
        trust_binding,
        publish_trust_anchor,
        native: None,
    })
}

pub(super) fn service_error(error: coland_services::ServiceError) -> AppError {
    match error {
        coland_services::ServiceError::Conflict(detail) => {
            let code = coland_storage::ConflictCode::from_detail(&detail)
                .and_then(|code| arkret_wire::ErrorCode::from_wire(code.as_str()))
                .unwrap_or(arkret_wire::ErrorCode::Conflict);
            AppError::from_rejection(
                code,
                "KeyPackage publication refused by its current authority",
            )
        }
        coland_services::ServiceError::NotFound(_) => {
            AppError::not_found("KeyPackage source unavailable")
        }
        coland_services::ServiceError::SchemaViolation(_) => {
            crate::app_error!(SchemaViolation, "KeyPackage source is invalid")
        }
        _ => crate::app_error!(TemporarilyUnavailable, "KeyPackage storage is unavailable"),
    }
}
