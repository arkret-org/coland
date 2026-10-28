//! True native requester/recipient evidence, without a synthetic Session.
use coland_storage::AppletManagedDeviceScopeGuard;

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
    let PeerKeyPackageRequesterAuthorization::RealmDevice {
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
    if body.requester_actor_id.as_ref() != Some(&authority.actor_id)
        || requester_device_id != &authority.device_id
        || device_authorize_event_id != &authority.authorization_ref.event_id
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
    if body.service_binding.source_id != state.service_core_id() {
        require_relay_source(state, body)
            .await
            .map_err(|_| peer_claim_failed())?;
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

pub(super) async fn claim(
    state: &AppState,
    body: &KeyPackagesClaimRequestBody,
    source: &NativeRequester,
) -> JsonResult<KeyPackagesClaimResponseBody> {
    let peer = body.clone();
    let target_actor = match (
        &body.target_actor_id,
        &body.target_account_id,
        &body.target_agent_id,
    ) {
        (Some(actor), None, None) => actor.clone(),
        (None, Some(account), None) => arkret_wire::ActorId::account(account.clone()),
        (None, None, Some(agent)) => arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            agent.clone(),
            body.service_binding.destination_id.clone(),
        )),
        _ => return Err(peer_claim_failed()),
    };
    let destination = super::super::actor_delivery_station(state, &target_actor).await?;
    if destination != state.service_core_id() && body.target_agent_id.is_some() {
        return Err(crate::app_error!(
            TemporarilyUnavailable,
            "Realm requester Agent signer verification is unavailable"
        ));
    }
    let digest = arkret_canonical::canonical_sha256(&peer)
        .map_err(|error| AppError::internal(error.to_string()))?;
    if body.service_binding.destination_id != destination
        && state
            .mls_key_packages()
            .peer_claim_original(body.claim_request_id.as_str(), &digest)
            .await
            .map_err(|error| AppError::internal(error.to_string()))?
            .is_none()
    {
        return Err(keypackage_claim_unknown());
    }
    let fresh = state
        .mls_key_packages()
        .prepare_realm_claim_source(&peer, &source.0, source.1)
        .await
        .map_err(claim_error)?;
    if let Some(record) = state
        .mls_key_packages()
        .realm_claim_source(
            body.service_binding.source_id.as_str(),
            body.claim_request_id.as_str(),
        )
        .await
        .map_err(claim_error)?
        && let Some(result) = record.result
        && !(result.state == PeerKeyPackagesClaimQueryState::Claimed
            && result
                .claim_outcome
                .as_ref()
                .is_some_and(|outcome| outcome.claim_receipt.expires_at <= Utc::now()))
    {
        return replay_source_result(result);
    }
    let original = arkret_canonical::canonical_json_bytes(&peer)
        .map_err(|error| AppError::internal(error.to_string()))?;
    let query_body = PeerKeyPackagesClaimQueryRequestBody {
        claim_request_id: body.claim_request_id.clone(),
        request_digest: arkret_wire::Hash::new(digest.clone())
            .map_err(|error| AppError::internal(error.to_string()))?,
    };
    let query = if fresh {
        None
    } else if destination == state.service_core_id() {
        Some(
            query_claim_ledger(state, query_body.clone(), state.service_id().clone())
                .await?
                .0,
        )
    } else {
        Some(
            read_remote_claim(
                state,
                &destination,
                "/_arkret/peer/keys/keypackages/claims/query",
                &arkret_canonical::canonical_json_bytes(&query_body)
                    .map_err(|error| AppError::internal(error.to_string()))?,
                None,
            )
            .await?,
        )
    };
    let query = match query {
        Some(query) if query.state != PeerKeyPackagesClaimQueryState::Unknown => query,
        _ => {
            // A successor may recover a registered result, never execute an
            // unknown original command under a different source/destination.
            if body.service_binding.source_id != state.service_core_id()
                || body.service_binding.destination_id != destination
                || body.expires_at <= Utc::now()
            {
                return Err(keypackage_claim_unknown());
            }
            validate_peer_claim_time_window(&peer)?;
            if destination == state.service_core_id() {
                let authorization = VerifiedClaimAuthorization::for_verified_request(&peer)?;
                let attempt =
                    claim_keypackage_at_destination(state, &peer, authorization, Some(source))
                        .await;
                let query =
                    query_claim_ledger(state, query_body.clone(), state.service_id().clone())
                        .await?
                        .0;
                if query.state == PeerKeyPackagesClaimQueryState::Unknown {
                    return attempt;
                }
                query
            } else {
                read_remote_claim(
                    state,
                    &destination,
                    "/_arkret/peer/keys/keypackages/claim",
                    &original,
                    Some(body.claim_request_id.as_str()),
                )
                .await?
            }
        }
    };
    if matches!(
        query.state,
        PeerKeyPackagesClaimQueryState::Unknown | PeerKeyPackagesClaimQueryState::Pending
    ) {
        return Err(crate::app_error!(
            TemporarilyUnavailable,
            "original KeyPackage claim has no terminal result"
        ));
    }
    let result = capture_source_result(state, &peer, &query).await?;
    replay_source_result(result)
}

fn replay_source_result(
    result: PeerKeyPackagesClaimQueryResponseBody,
) -> JsonResult<KeyPackagesClaimResponseBody> {
    result
        .validate_shape()
        .map_err(|e| AppError::internal(e.to_string()))?;
    result.claim_outcome.map(Json).ok_or_else(peer_claim_failed)
}

/// Retain full authenticated Station method histories before exposing a result.
/// Storage rechecks signatures, original bindings and installed governance
/// tenure under the same lock that freezes this requester's private archive.
pub(super) async fn capture_source_result(
    state: &AppState,
    request: &KeyPackagesClaimRequestBody,
    result: &PeerKeyPackagesClaimQueryResponseBody,
) -> Result<PeerKeyPackagesClaimQueryResponseBody, AppError> {
    let retained = state
        .mls_key_packages()
        .realm_claim_source(
            request.service_binding.source_id.as_str(),
            request.claim_request_id.as_str(),
        )
        .await
        .map_err(claim_error)?
        .ok_or_else(keypackage_claim_unknown)?;
    let mut histories = retained.issuer_histories;
    let mut issuers = Vec::new();
    if let Some(outcome) = &result.claim_outcome {
        issuers.push(outcome.claim_receipt.destination_id.clone());
    }
    for signature in [
        result.consume_receipt.as_ref().map(|r| &r.signature),
        result.terminal_receipt.as_ref().map(|r| &r.signature),
    ]
    .into_iter()
    .flatten()
    {
        let did = signature
            .kid
            .as_str()
            .split_once('#')
            .ok_or_else(peer_claim_failed)?
            .0;
        let issuer = arkret_wire::Did::new(did)
            .and_then(|did| arkret_wire::project_did_to_core_id(&did))
            .map_err(|_| peer_claim_failed())?;
        if !issuers.contains(&issuer) {
            issuers.push(issuer);
        }
    }
    for issuer in issuers {
        let verifies = |history: &arkret_models_identity::AuthenticatedServiceResolution| {
            if history.service_id != issuer {
                return false;
            }
            let claim = result.claim_outcome.as_ref().is_none_or(|o| {
                o.claim_receipt.destination_id != issuer
                    || arkret::verify_peer_keypackage_claim_receipt_signature(
                        &o.claim_receipt,
                        history,
                    )
                    .is_ok()
            });
            let consume = result.consume_receipt.as_ref().is_none_or(|r| {
                let own = r
                    .signature
                    .kid
                    .as_str()
                    .starts_with(&format!("{}#", history.normalized_did_document.id));
                !own || arkret::verify_peer_keypackage_consume_receipt_signature(
                    r, &issuer, history,
                )
                .is_ok()
            });
            let terminal = result.terminal_receipt.as_ref().is_none_or(|r| {
                let own = r
                    .signature
                    .kid
                    .as_str()
                    .starts_with(&format!("{}#", history.normalized_did_document.id));
                !own || arkret::verify_peer_keypackage_terminal_receipt_signature(
                    r, &issuer, history,
                )
                .is_ok()
            });
            claim && consume && terminal
        };
        if histories.iter().any(verifies) {
            continue;
        }
        if let Some(history) = state
            .mls_key_packages()
            .realm_claim_issuer_resolution(
                request.service_binding.source_id.as_str(),
                request.claim_request_id.as_str(),
            )
            .await
            .map_err(claim_error)?
            && verifies(&history)
        {
            histories.push(history);
            continue;
        }
        let history = crate::routing::identity::agents::evidence::fetch_service_resolution(
            state, &issuer, None,
        )
        .await
        .map_err(|_| {
            crate::app_error!(
                RevisionUnavailable,
                "claim issuer method history unavailable"
            )
        })?;
        if !verifies(&history) {
            return Err(crate::app_error!(
                SignatureInvalid,
                "claim result historical signature invalid"
            ));
        }
        histories.push(history);
    }
    state
        .mls_key_packages()
        .retain_realm_claim_source_result(request, result, &histories, &state.service_core_id())
        .await
        .map_err(claim_error)
}

pub(super) async fn verify_ordinary_target(
    state: &AppState,
    request: &KeyPackagesClaimRequestBody,
    outcome: &KeyPackagesClaimResponseBody,
    deadline: DateTime<Utc>,
) -> Result<
    (
        DateTime<Utc>,
        Vec<coland_storage::MlsClaimRemoteDeviceEvidence>,
    ),
    AppError,
> {
    let Some(account) = &request.target_account_id else {
        return Ok((deadline, Vec::new()));
    };
    if account.station_id == state.service_core_id() {
        return Ok((deadline, Vec::new()));
    }
    let requester = request
        .requester_actor_id
        .as_ref()
        .ok_or_else(peer_claim_failed)?;
    // The locked source ledger separately bounds claimed versus consumed
    // recovery. A current origin projection must not renew either window.
    let mut deadline = deadline;
    let mut evidence = Vec::new();
    for claim in &outcome.claims {
        let device = claim.device_id.as_ref().ok_or_else(peer_claim_failed)?;
        if claim.actor_id != arkret_wire::ActorId::account(account.clone())
            || !request.target_device_ids.contains(device)
            || request.required_capabilities.iter().any(|value| {
                !claim
                    .capabilities
                    .iter()
                    .any(|actual| actual == value.as_str())
            })
        {
            return Err(peer_claim_failed());
        }
        let (record, original) = crate::routing::identity::keys::realm_mls_device_projection(
            state, requester, account, device,
        )
        .await?;
        let projection = &record.device_projection;
        if claim.device_authorize_event_id.as_ref() != Some(&projection.device_authorize_event_id) {
            return Err(peer_claim_failed());
        }
        let key = crate::routing::identity::device_signing::decode_ed25519_key(
            projection.device_signing_key_did.as_str(),
            "multibase",
        )
        .map_err(|_| peer_claim_failed())?;
        let bytes = decode_key_package(&claim.keypackage).map_err(|_| peer_claim_failed())?;
        if arkret_canonical::sha256_digest(&bytes) != claim.keypackage_ref {
            return Err(peer_claim_failed());
        }
        validate_actor_keypackage_leaf(&claim.actor_id, &key.to_bytes(), &bytes)
            .map_err(|_| peer_claim_failed())?;
        arkret_mls::validate_keypackage_capability_binding(&bytes, &claim.capabilities)
            .map_err(|_| peer_claim_failed())?;
        deadline = deadline.min(projection.expires_at);
        if let Some(expiry) = projection.authorization_window.expires_at {
            deadline = deadline.min(expiry);
        }
        evidence.push(original);
    }
    if deadline <= Utc::now() {
        return Err(peer_claim_failed());
    }
    Ok((deadline, evidence))
}

async fn read_remote_claim(
    state: &AppState,
    destination: &arkret_wire::DidCoreId,
    path: &str,
    body: &[u8],
    idempotency_key: Option<&str>,
) -> Result<PeerKeyPackagesClaimQueryResponseBody, AppError> {
    let response = if let Some(key) = idempotency_key {
        crate::routing::federation::outbox::signed_peer_command(
            state,
            destination.as_str(),
            path,
            body,
            key,
            2 * 1024 * 1024,
        )
        .await
    } else {
        crate::routing::federation::outbox::signed_peer_request(
            state,
            destination.as_str(),
            path,
            body,
            2 * 1024 * 1024,
        )
        .await
    }
    .map_err(|error| {
        tracing::warn!(%error, "native KeyPackage peer request failed");
        crate::app_error!(
            TemporarilyUnavailable,
            "original KeyPackage peer result unavailable"
        )
    })?;
    if response.status != 200 {
        tracing::warn!(
            status = response.status,
            "native KeyPackage peer request rejected"
        );
        return Err(crate::app_error!(
            TemporarilyUnavailable,
            "original KeyPackage peer result unavailable"
        ));
    }
    let outcome: PeerKeyPackagesClaimQueryResponseBody = serde_json::from_slice(&response.body)
        .map_err(|_| {
            crate::app_error!(
                TemporarilyUnavailable,
                "invalid original KeyPackage peer result"
            )
        })?;
    outcome.validate_shape().map_err(|_| {
        crate::app_error!(
            TemporarilyUnavailable,
            "invalid original KeyPackage peer result"
        )
    })?;
    Ok(outcome)
}

async fn target(
    state: &AppState,
    actor: &arkret_wire::ActorId,
    device: &arkret_wire::DeviceId,
    realm: &RealmId,
    group: &arkret_wire::MlsGroupId,
) -> Result<Option<AppletManagedDeviceScopeGuard>, AppError> {
    let Some(authority) = state
        .persistence()
        .applet_managed_device_authority(actor, device, Utc::now())
        .await
        .map_err(claim_error)?
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
        .map_err(|error| {
            tracing::debug!(%error, "native KeyPackage target scope refused");
            peer_claim_failed()
        })
}

pub(super) async fn targets(
    state: &AppState,
    body: &KeyPackagesClaimRequestBody,
) -> Result<BTreeMap<String, AppletManagedDeviceScopeGuard>, AppError> {
    let Some(actor) = &body.target_actor_id else {
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
                .filter(|row| &row.owner_actor_id == actor)
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
            actor,
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
    operation: arkret_wire::ServiceOperationId,
    outcome: &KeyPackagesClaimResponseBody,
    source: Option<&NativeRequester>,
    credential_deadline: DateTime<Utc>,
    command: Option<&KeyPackagesClaimRequestBody>,
    remote_devices: Vec<coland_storage::MlsClaimRemoteDeviceEvidence>,
) -> Result<Option<Box<dyn coland_storage::AccountContentDeliveryGuard>>, AppError> {
    let mut endpoints = source
        .map(|(guard, _)| vec![guard.clone()])
        .unwrap_or_default();
    for claim in &outcome.claims {
        if let Some(device) = claim.device_id.as_ref() {
            if let Some(guard) = target(
                state,
                &claim.actor_id,
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
            operation,
            outcome: outcome.clone(),
            endpoints,
            command: command.cloned(),
            remote_devices,
        }],
        applet_endpoint: Some(primary.clone()),
        credential_expires_at: Some(credential_deadline),
        ..Default::default()
    };
    state
        .authority_commits()
        .acquire_realm_actor_content_delivery(
            &primary.authority.actor_id,
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
    tracing::debug!(%error, "native KeyPackage admission refused");
    match error {
        coland_services::ServiceError::Conflict(ref detail)
            if detail.starts_with("duplicate_conflict:") =>
        {
            crate::app_error!(DuplicateConflict, "claim request bytes differ")
        }
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

pub(super) async fn consume(
    state: &AppState,
    native: &VerifiedAppletManagedDevice,
    body: &KeyPackagesConsumeRequestBody,
) -> JsonResult<KeyPackagesConsumeResponseBody> {
    body.validate_shape().map_err(AppError::param_invalid)?;
    let receipt = &body.recipient_durable_receipt;
    let authority = &native.authority;
    let arkret_models_crypto::RecipientMlsDurableSigner::RealmDevice {
        recipient_actor_id,
        recipient_device_id,
        device_verification_method,
    } = &receipt.recipient
    else {
        return Err(AppError::capability_denied(
            "native consume requires its real Device",
        ));
    };
    let fingerprint = arkret_canonical::ed25519_pubkey_to_did_key_multibase(&authority.public_key);
    if native.operation != arkret_wire::ServiceOperationId::SelfKeysKeypackagesCommandConsumeV1
        || recipient_actor_id != &authority.actor_id
        || recipient_device_id != &authority.device_id
        || !crate::routing::identity::device_signature_kid_points_to_device_key(
            device_verification_method.as_str(),
            authority.actor_id.signing_principal_id().as_str(),
            &format!("did:key:{fingerprint}"),
        )
    {
        return Err(AppError::capability_denied(
            "native consume differs from its original Device",
        ));
    }
    let issuance_state = state.clone();
    let issuer: coland_storage::MlsKeyPackageConsumeReceiptIssuer =
        std::sync::Arc::new(move |body, at| {
            build_keypackage_consume_receipt(&issuance_state, body, at)
                .map_err(|error| coland_storage::PersistenceError::Internal(error.to_string()))
        });
    let consumed = state
        .mls_key_packages()
        .consume_for_applet_device(coland_storage::AppletDeviceKeyPackageConsume {
            body,
            authority,
            effective_scope: &native.metadata.effective_scope,
            transport_expires_at: native.transport_expires_at,
            issue_receipt: &issuer,
        })
        .await
        .map_err(consume_error)?;
    if let Some(at) = consumed.record.consumed_at {
        state
            .projections()
            .mark_key_package_consumed(&consumed.record.id, at);
    }
    json_ok(consumed.outcome)
}

/// Preserve current Device authorization refusal separately from a changed
/// original durable delivery. Diagnostic text never decides a wire status.
fn consume_error(error: coland_services::ServiceError) -> AppError {
    match error.conflict_code() {
        Some(coland_storage::ConflictCode::DeviceUnauthorized) => {
            crate::app_error!(
                DeviceUnauthorized,
                "native consume current Device is unavailable"
            )
        }
        Some(coland_storage::ConflictCode::CapabilityDenied) => {
            AppError::capability_denied("native consume current Device is unavailable")
        }
        _ => match error {
            coland_services::ServiceError::Conflict(_)
            | coland_services::ServiceError::NotFound(_) => {
                AppError::conflict("native consume differs from its original durable delivery")
            }
            coland_services::ServiceError::SchemaViolation(_) => {
                AppError::param_invalid("native consume is invalid")
            }
            _ => crate::app_error!(
                TemporarilyUnavailable,
                "native consume persistence is unavailable"
            ),
        },
    }
}

#[cfg(test)]
mod consume_error_tests {
    use salvo::http::StatusCode;

    use super::*;

    #[test]
    fn current_device_refusal_preserves_its_registered_consume_code() {
        let original = coland_storage::PersistenceError::Conflict(
            "device_unauthorized: Realm Device is outside its original authorization window".into(),
        );
        let error = consume_error(original.into());
        assert_eq!(error.code, arkret_wire::ErrorCode::DeviceUnauthorized);
        assert_eq!(error.http_status(), StatusCode::FORBIDDEN);
        assert_eq!(
            error.message.as_ref(),
            "native consume current Device is unavailable"
        );
        assert!(
            arkret_wire::ServiceOperationId::SelfKeysKeypackagesCommandConsumeV1
                .operation_specific_errors()
                .contains(&arkret_wire::OperationSpecificError::Code(error.code))
        );
        let capability = consume_error(coland_services::ServiceError::protocol(
            arkret_wire::ErrorCode::CapabilityDenied,
            "the current Device lacks permission for this consume scope",
        ));
        assert_eq!(capability.code, arkret_wire::ErrorCode::CapabilityDenied);
        assert_eq!(capability.http_status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn durable_delivery_conflict_is_not_reclassified_by_device_diagnostic_text() {
        let original = coland_storage::PersistenceError::Conflict(
            "conflict: original binding changed; diagnostic mentions device_unauthorized".into(),
        );
        let error = consume_error(original.into());
        assert_eq!(error.code, arkret_wire::ErrorCode::Conflict);
        assert_eq!(error.http_status(), StatusCode::CONFLICT);
        assert_eq!(
            error.message.as_ref(),
            "native consume differs from its original durable delivery"
        );
    }
}
