//! True native requester/recipient evidence, without a synthetic Session.
use coland_storage::{AppletManagedDeviceScopeGuard, DeviceRevocationStore};

use super::*;
use crate::routing::identity::applet_managed_device::{self, VerifiedAppletManagedDevice};

type NativeRequester = (AppletManagedDeviceScopeGuard, DateTime<Utc>);

pub(super) async fn requester(
    state: &AppState,
    native: &VerifiedAppletManagedDevice,
    body: &KeyPackagesClaimRequestBody,
) -> Result<NativeRequester, AppError> {
    body.validate_shape()
        .map_err(|error| peer_claim_schema_violation(error.to_string()))?;
    let PeerKeyPackageRequesterAuthorization::Device {
        verification_method,
        requester_device_id,
        device_authorize_event_id,
        signature,
        ..
    } = &body.requester_authorization
    else {
        return Err(peer_claim_failed());
    };
    let authority = &native.authority;
    if body.requester_account_id.as_ref() != Some(&authority.account_id)
        || body.service_binding.source_id != state.service_core_id()
        || requester_device_id != &authority.device_id
        || device_authorize_event_id != &authority.selector.authorization_ref.event_id
        || verification_method.as_str()
            != format!("{}#{}", authority.native_did, authority.device_id)
        || body.intended_realm_id != *native.metadata.effective_scope.realm_id()
        || body.mls_group_id
            != native
                .metadata
                .effective_scope
                .canonical_mls_group_id()
                .map_err(|_| peer_claim_failed())?
    {
        return Err(peer_claim_failed());
    }
    let input = keypackage_claim_authorization_signing_bytes(
        &body.unsigned_request(),
        &body.service_binding,
        &body.requester_authorization,
    )
    .map_err(|_| peer_claim_failed())?;
    arkret_signatures::keypackages::verify_keypackage_signing_input(
        &authority.public_key,
        verification_method.as_str(),
        &input,
        signature,
    )
    .map_err(|_| peer_claim_failed())?;
    Ok((
        applet_managed_device::scope_guard(state, native).await?,
        native.transport_expires_at,
    ))
}

async fn target(
    state: &AppState,
    account: &arkret_wire::AccountId,
    device: &arkret_wire::DeviceId,
    realm: &RealmId,
    group: &arkret_wire::MlsGroupId,
) -> Result<Option<AppletManagedDeviceScopeGuard>, AppError> {
    let Some(authority) = state
        .persistence()
        .applet_managed_device_authority(account, device, Utc::now())
        .await
        .map_err(|_| peer_claim_failed())?
    else {
        return Ok(None);
    };
    let mut scopes = authority.scopes.entries().iter().filter(|pair| {
        pair.effective_scope.realm_id() == realm
            && pair.effective_scope.canonical_mls_group_id().ok().as_ref() == Some(group)
    });
    let scope = scopes
        .next()
        .ok_or_else(peer_claim_failed)?
        .effective_scope
        .clone();
    if scopes.next().is_some() {
        return Err(peer_claim_failed());
    }
    applet_managed_device::scope_guard_for_authority(state, &authority, &scope)
        .await
        .map(Some)
        .map_err(|_| peer_claim_failed())
}

pub(super) async fn targets(
    state: &AppState,
    body: &PeerKeyPackagesClaimRequestBody,
) -> Result<BTreeMap<String, AppletManagedDeviceScopeGuard>, AppError> {
    let Some(account) = &body.target_account_id else {
        return Ok(BTreeMap::new());
    };
    let mut devices = body
        .target_device_ids
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    if devices.is_empty() {
        devices.extend(
            state
                .projections()
                .mls_key_package_records()
                .iter()
                .filter(|row| &row.owner_account_id == account)
                .filter_map(|row| {
                    row.device_id
                        .as_ref()
                        .and_then(|id| arkret_wire::DeviceId::new(id.clone()).ok())
                }),
        );
    }
    let mut result = BTreeMap::new();
    for device in devices {
        if let Some(guard) = target(
            state,
            account,
            &device,
            &body.intended_realm_id,
            &body.mls_group_id,
        )
        .await?
        {
            result.insert(device.to_string(), guard);
        }
    }
    Ok(result)
}

pub(super) async fn delivery_guard(
    state: &AppState,
    outcome: &PeerKeyPackagesClaimOutcome,
    source: Option<&NativeRequester>,
    credential_deadline: DateTime<Utc>,
    command: Option<&PeerKeyPackagesClaimRequestBody>,
) -> Result<Option<Box<dyn coland_storage::AccountContentDeliveryGuard>>, AppError> {
    let mut endpoints = source
        .map(|(guard, _)| vec![guard.clone()])
        .unwrap_or_default();
    for claim in &outcome.claims {
        if let (Some(account), Some(device)) =
            (claim.actor_id.as_account_id(), claim.device_id.as_ref())
        {
            if let Some(guard) = target(
                state,
                account,
                device,
                &outcome.claim_receipt.request.intended_realm_id,
                &outcome.claim_receipt.request.mls_group_id,
            )
            .await?
            {
                if !endpoints.contains(&guard) {
                    endpoints.push(guard);
                }
            } else if state
                .projections()
                .mls_key_package_records()
                .iter()
                .any(|row| {
                    row.keypackage_ref == claim.keypackage_ref && row.effective_scope.is_some()
                })
            {
                return Err(peer_claim_failed());
            }
        }
    }
    let Some(primary) = endpoints.first().cloned() else {
        return Ok(None);
    };
    let input = coland_storage::AccountContentDeliveryInput {
        realms: vec![primary.effective_scope.realm_id().clone()],
        keypackage_claims: vec![coland_storage::MlsKeyPackageClaimDelivery {
            outcome: outcome.clone(),
            endpoints,
            command: command.cloned(),
        }],
        applet_endpoint: Some(primary.clone()),
        credential_expires_at: Some(credential_deadline),
        ..Default::default()
    };
    state
        .authority_commits()
        .acquire_committed_content_delivery(
            &primary.authority.account_id,
            &state.service_core_id(),
            &input,
        )
        .await
        .map_err(|error| {
            tracing::debug!(%error,"native claim delivery refused");
            peer_claim_failed()
        })?
        .map(Some)
        .ok_or_else(peer_claim_failed)
}

pub(super) fn claim_error(error: coland_services::ServiceError) -> AppError {
    match error {
        coland_services::ServiceError::Conflict(_)
        | coland_services::ServiceError::NotFound(_)
        | coland_services::ServiceError::SchemaViolation(_) => peer_claim_failed(),
        _ => crate::app_error!(
            TemporarilyUnavailable,
            "KeyPackage claim persistence is unavailable"
        ),
    }
}

pub(super) fn peer_deadline(req: &Request) -> Result<DateTime<Utc>, AppError> {
    let signature = coland_http::http_signature::parse_signature_input_header(req)
        .map_err(|_| peer_claim_failed())?;
    DateTime::from_timestamp(signature.expires, 0).ok_or_else(peer_claim_failed)
}
