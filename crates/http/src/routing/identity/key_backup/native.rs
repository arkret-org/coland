//! Native custody uses immutable admission evidence, not an Account Session.

use arkret_models_crypto::{KeyBackup, KeysBackupsReplaceOperationResponseBody};
use arkret_models_identity::AuthenticatedServiceResolution;
use arkret_models_integration::{
    RealmActorBackupGovernanceHistory, RealmActorBackupGovernanceOriginal,
    RealmActorBackupGovernanceTransition,
};
use arkret_wire::{Base64UrlString, Event, RealmCommit};
use coland_http::error::AppError;
use coland_http::result::{JsonResult, json_ok};
use salvo::prelude::Request;

use crate::routing::identity::applet_managed_device;
use crate::state::AppState;

fn unavailable(error: impl std::fmt::Display) -> AppError {
    crate::app_error!(
        TemporarilyUnavailable,
        format!("native backup source unavailable: {error}")
    )
}

pub(super) fn storage_error(error: coland_storage::PersistenceError) -> AppError {
    use coland_storage::ConflictCode;
    if let coland_storage::PersistenceError::SchemaViolation(detail) = &error {
        return crate::app_error!(SchemaViolation, detail.clone());
    }
    match error.conflict_code() {
        Some(ConflictCode::RecipientQueueAtCapacity) => {
            crate::app_error!(QuotaExceeded, error.to_string())
        }
        Some(ConflictCode::CapabilityDenied) => {
            crate::app_error!(CapabilityDenied, error.to_string())
        }
        Some(ConflictCode::RealmFrozen) => crate::app_error!(RealmFrozen, error.to_string()),
        Some(ConflictCode::EpochUpdateRequired) => crate::app_error!(Conflict, error.to_string())
            .with_reason_code(arkret_wire::ReasonCode::EPOCH_UPDATE_REQUIRED),
        Some(ConflictCode::SeriesChainBroken) => crate::app_error!(Conflict, error.to_string())
            .with_reason_code(arkret_wire::ReasonCode::SERIES_CHAIN_BROKEN),
        Some(ConflictCode::SeriesSeqNotMonotonic) => crate::app_error!(Conflict, error.to_string())
            .with_reason_code(arkret_wire::ReasonCode::SERIES_SEQ_NOT_MONOTONIC),
        Some(ConflictCode::SeriesPredecessorNotFound) => {
            crate::app_error!(Conflict, error.to_string())
                .with_reason_code(arkret_wire::ReasonCode::SERIES_PREDECESSOR_NOT_FOUND)
        }
        Some(ConflictCode::DuplicateConflict) => {
            crate::app_error!(DuplicateConflict, error.to_string())
        }
        Some(ConflictCode::SchemaViolation) => {
            crate::app_error!(SchemaViolation, error.to_string())
        }
        Some(ConflictCode::SignatureInvalid) => {
            crate::app_error!(SignatureInvalid, error.to_string())
        }
        Some(ConflictCode::DeviceUnauthorized) => {
            crate::app_error!(DeviceUnauthorized, error.to_string())
        }
        Some(ConflictCode::DeviceGenerationFenced) => {
            crate::app_error!(DeviceGenerationFenced, error.to_string())
        }
        Some(ConflictCode::DeviceRevoked) => crate::app_error!(DeviceRevoked, error.to_string()),
        Some(ConflictCode::DeviceRevocationPending) => {
            crate::app_error!(DeviceRevocationPending, error.to_string())
        }
        Some(ConflictCode::FailedPrecondition) => {
            crate::app_error!(FailedPrecondition, error.to_string())
        }
        Some(ConflictCode::TemporarilyUnavailable) => unavailable(error),
        _ => AppError::internal(error.to_string()),
    }
}

pub(super) async fn put(
    state: &AppState,
    device: &applet_managed_device::VerifiedAppletManagedDevice,
    path: &str,
    backup: KeyBackup,
    request: &Request,
) -> JsonResult<KeysBackupsReplaceOperationResponseBody> {
    let id = arkret_wire::BackupId::new(path.to_owned())
        .map_err(|error| super::schema_error(error.to_string()))?;
    backup
        .validate()
        .map_err(|error| super::schema_error(error.to_string()))?;
    if backup.backup_id != id || backup.actor_id != device.authority.actor_id {
        return Err(super::schema_error("native backup path or subject differs"));
    }
    let key = request
        .headers()
        .get("idempotency-key")
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty() && value.len() <= 128)
        .ok_or_else(|| {
            AppError::param_invalid("Idempotency-Key is required and bounded to 128 bytes")
        })?;
    // A fixed first-PUT receipt precedes all new publication gates. Its
    // original requester is nevertheless reauthenticated under the same lock.
    if let Some(reply) = state
        .persistence()
        .recover_native_backup_put(
            &backup,
            &device.authority,
            &device.metadata.effective_scope,
            device.transport_expires_at,
            key,
        )
        .await
        .map_err(storage_error)?
    {
        return json_ok(KeysBackupsReplaceOperationResponseBody::Native(reply));
    }
    let mut context = publication_context(state, device).await?;
    context.idempotency_key = key.to_owned();
    let method = state
        .service_verification_method("notary-key")
        .map_err(unavailable)?;
    let key = state.notary_signing_key();
    let sign = move |input| {
        arkret_signatures::realm_actor_content_backup::sign_realm_actor_content_backup_admission(
            input,
            method.clone(),
            &key,
        )
        .map_err(coland_storage::PersistenceError::database)
    };
    let reply = state
        .persistence()
        .put_native_backup(&backup, &context, &sign)
        .await
        .map_err(storage_error)?;
    json_ok(KeysBackupsReplaceOperationResponseBody::Native(reply))
}

async fn original(
    state: &AppState,
    event: Event,
    commit: RealmCommit,
) -> Result<RealmActorBackupGovernanceOriginal, AppError> {
    let fact = state
        .authority_commits()
        .producer_signer_fact(&event, &commit)
        .await
        .map_err(unavailable)?;
    Ok(RealmActorBackupGovernanceOriginal {
        event,
        commit,
        producer_signer_fact: fact,
    })
}

async fn resolution(
    state: &AppState,
    signature: &arkret_wire::DetachedObjectSignature,
    local: &AuthenticatedServiceResolution,
) -> Result<AuthenticatedServiceResolution, AppError> {
    let service = arkret_wire::detached_signature_service_id(signature).map_err(unavailable)?;
    if service == local.service_id {
        return Ok(local.clone());
    }
    let did = arkret_identity::verification_method_did(signature.verification_method.as_str())
        .map_err(unavailable)?;
    state
        .dids()
        .retained_service_resolution(
            &did,
            arkret_wire::ServiceKind::Station,
            signature.created_at,
        )
        .await
        .map_err(unavailable)
}

pub(super) async fn head(
    depot: &mut salvo::Depot,
    request: &mut Request,
    query: arkret_models_crypto::RealmActorBackupHeadQuery,
) -> coland_http::result::GuardedJsonResult<arkret_models_integration::KeysBackupsListResponseBody>
{
    let state = depot.get_typed::<AppState>().expect("state injected");
    let device = depot
        .get_typed::<applet_managed_device::VerifiedAppletManagedDevice>()
        .map_err(|_| {
            AppError::unauthenticated("native predecessor needs an authenticated native Device")
        })?;
    if device.authority.actor_id.as_realm_actor_id() != Some(&query.realm_actor_id)
        || device.metadata.effective_scope != query.effective_scope()
    {
        return Err(AppError::capability_denied(
            "native predecessor must name its exact Device actor and scope",
        ));
    }
    let context = publication_context(state, device).await?;
    let (result, guard) = state
        .persistence()
        .native_backup_head(&context)
        .await
        .map_err(storage_error)?;
    let _ = request;
    coland_http::result::guarded_json_ok(
        arkret_models_integration::KeysBackupsListResponseBody::Device(result),
        Some(guard),
    )
}

pub(super) async fn manager_reader(
    state: &AppState,
    request: &mut Request,
    actor: arkret_wire::RealmActorId,
) -> Result<coland_storage::RealmActorBackupManagerReader, AppError> {
    let service = crate::routing::extensions::applet_bridge::verify_native_backup_manager_service(
        state, request,
    )
    .await?;
    let nonce = Base64UrlString::new(arkret_canonical::base64url_encode(
        rand::random::<[u8; 32]>(),
    ))
    .map_err(unavailable)?;
    let bundle =
        crate::routing::realm_join::local_authority_bundle(state, &actor.realm_id, &nonce).await?;
    let located = crate::routing::realm_join::verify_served_bundle(state, bundle, &nonce).await?;
    Ok(coland_storage::RealmActorBackupManagerReader {
        actor,
        service_id: service.service_id,
        verification_method: service.verification_method,
        service_did_document: service.authenticated_document,
        transport_expires_at: service.expires_at,
        authority: located.authority,
        authority_keys: located.keys,
    })
}

async fn unlock_reader(
    depot: &mut salvo::Depot,
    request: &mut Request,
    actor: arkret_wire::RealmActorId,
    scope: arkret_wire::ScopeRef,
    device_role: bool,
) -> Result<coland_storage::RealmActorBackupReader, AppError> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    if device_role {
        let device = depot
            .get_typed::<applet_managed_device::VerifiedAppletManagedDevice>()
            .map_err(|_| {
                AppError::unauthenticated("native predecessor needs a native Device transport")
            })?;
        if device.authority.actor_id.as_realm_actor_id() != Some(&actor)
            || device.metadata.effective_scope != scope
        {
            return Err(AppError::capability_denied(
                "native unlock exact requester actor/scope differs",
            ));
        }
        Ok(coland_storage::RealmActorBackupReader::Device(Box::new(
            publication_context(state, device).await?,
        )))
    } else {
        if depot
            .get_typed::<applet_managed_device::VerifiedAppletManagedDevice>()
            .is_ok()
        {
            return Err(AppError::capability_denied(
                "native Device cannot request manager archive source",
            ));
        }
        Ok(coland_storage::RealmActorBackupReader::Manager(Box::new(
            manager_reader(state, request, actor).await?,
        )))
    }
}

pub(super) async fn issue_unlock(
    depot: &mut salvo::Depot,
    request: &mut Request,
    path: String,
    body: arkret_models_crypto::RealmActorBackupIssueUnlockChallengeRequestBody,
) -> JsonResult<arkret_models_crypto::KeysBackupsIssueUnlockChallengeResponseBody> {
    body.validate()
        .map_err(|error| super::schema_error(error.to_string()))?;
    let id =
        arkret_wire::BackupId::new(path).map_err(|error| super::schema_error(error.to_string()))?;
    let device_role =
        body.kind == arkret_models_crypto::RealmActorBackupUnlockChallengeKind::RealmActorDevice;
    let reader = unlock_reader(
        depot,
        request,
        body.realm_actor_id.clone(),
        body.effective_scope.clone(),
        device_role,
    )
    .await?;
    let state = depot.get_typed::<AppState>().expect("state injected");
    let audience = super::unlock::unlock_audience(state)?;
    let result = state
        .persistence()
        .issue_native_backup_unlock(&reader, &id, &body, &audience, &state.service_core_id())
        .await
        .map_err(storage_error)?;
    json_ok(arkret_models_crypto::KeysBackupsIssueUnlockChallengeResponseBody::Native(result))
}

pub(super) async fn unlock(
    depot: &mut salvo::Depot,
    request: &mut Request,
    path: String,
    proof: arkret_models_crypto::KeyBackupUnlockProofBody,
) -> coland_http::result::GuardedJsonResult<arkret_models_integration::KeysBackupsUnlockResponseBody>
{
    let (id, actor, scope, device_role) = match &proof {
        arkret_models_crypto::KeyBackupUnlockProofBody::Device(proof) => {
            proof
                .validate()
                .map_err(|error| super::schema_error(error.to_string()))?;
            (
                &proof.backup_id,
                proof.realm_actor_id.clone(),
                proof.effective_scope.clone(),
                true,
            )
        }
        arkret_models_crypto::KeyBackupUnlockProofBody::Manager(proof) => {
            proof
                .validate()
                .map_err(|error| super::schema_error(error.to_string()))?;
            (
                &proof.backup_id,
                proof.realm_actor_id.clone(),
                proof.effective_scope.clone(),
                false,
            )
        }
        _ => {
            return Err(super::schema_error(
                "Account unlock cannot select a native role",
            ));
        }
    };
    if id.as_str() != path {
        return Err(super::schema_error(
            "native unlock path and proof backup differ",
        ));
    }
    let reader = unlock_reader(depot, request, actor, scope, device_role).await?;
    let state = depot.get_typed::<AppState>().expect("state injected");
    let (result, guard) = state
        .persistence()
        .consume_native_backup_unlock(&reader, &proof)
        .await
        .map_err(storage_error)?;
    coland_http::result::guarded_json_ok(result, Some(guard))
}

pub(super) async fn inventory(
    depot: &mut salvo::Depot,
    request: &mut Request,
    query: arkret_models_crypto::RealmActorArchiveInventoryQuery,
) -> coland_http::result::GuardedJsonResult<arkret_models_integration::KeysBackupsListResponseBody>
{
    use arkret_server::{CursorAuthority, CursorBindingContext};
    if depot
        .get_typed::<applet_managed_device::VerifiedAppletManagedDevice>()
        .is_ok()
    {
        return Err(AppError::capability_denied(
            "a Device cannot enumerate manager archive inventory",
        ));
    }
    let state = depot.get_typed::<AppState>().expect("state injected");
    let reader = manager_reader(state, request, query.realm_actor_id.clone()).await?;
    let manifest = state
        .persistence()
        .native_backup_inventory(&reader)
        .await
        .map_err(storage_error)?;
    let digest = manifest.inventory_digest().map_err(unavailable)?;
    let limit = query.limit.unwrap_or(50);
    if !(1..=200).contains(&limit) {
        return Err(crate::app_error!(
            QueryInvalid,
            "inventory limit must be 1..200"
        ));
    }
    let filter=arkret_server::cursor_filter_digest(&serde_json::json!({
        "operation":arkret_wire::ServiceOperationId::SELF_KEYS_BACKUPS_READ_LIST_V1,
        "purpose":"archive_inventory","actor":query.realm_actor_id,"manager_ref":manifest.manager_ref,
        "archive_revision":manifest.archive_revision,"inventory_digest":digest,"limit":limit,
    })).map_err(unavailable)?;
    let subject = String::from_utf8(
        arkret_canonical::canonical_json_bytes(&query.realm_actor_id).map_err(unavailable)?,
    )
    .map_err(unavailable)?;
    let context = CursorBindingContext::new(subject, None, reader.service_id.clone(), filter);
    let mut offset = 0_usize;
    let mut expires = chrono::Utc::now().timestamp_millis() + 15 * 60 * 1000;
    if let Some(cursor) = &query.cursor {
        let decoded = CursorAuthority::decode_stream(cursor.as_str())
            .map_err(super::listing::cursor_authority_error)?;
        let row = state
            .sync()
            .cursor(&decoded.h)
            .await
            .map_err(unavailable)?
            .map(coland_http::util::cursor_binding_record_from_state)
            .transpose()
            .map_err(unavailable)?;
        let position = CursorAuthority::resolve_stream(&decoded, &context, row.as_ref())
            .map_err(super::listing::cursor_authority_error)?;
        offset = serde_json::from_value(position).map_err(unavailable)?;
        expires = decoded.expires_at.timestamp_millis();
    }
    if offset > manifest.entries.len() {
        return Err(crate::app_error!(
            CursorIntegrityInvalid,
            "inventory cursor is outside the frozen cut"
        ));
    }
    let mut end = offset
        .saturating_add(limit as usize)
        .min(manifest.entries.len());
    // Full encrypted packets and their immutable author evidence vary in size.
    // Bound the actual typed page, including its continuation, before writing
    // any cursor or obtaining the final delivery lease.
    let (result, continuation) = loop {
        let has_more = end < manifest.entries.len();
        let continuation = if has_more {
            Some(
                CursorAuthority::mint_stream_until(
                    context.clone(),
                    serde_json::json!(end),
                    expires,
                )
                .map_err(super::listing::cursor_authority_error)?,
            )
        } else {
            None
        };
        let result = arkret_models_integration::RealmActorArchiveInventoryPage {
            purpose: arkret_models_integration::RealmActorArchiveInventoryPagePurpose::Value,
            realm_actor_id: manifest.realm_actor_id.clone(),
            manager_ref: manifest.manager_ref.clone(),
            archive_revision: manifest.archive_revision,
            inventory_digest: digest.clone(),
            entries: manifest.entries[offset..end].to_vec(),
            next_cursor: continuation
                .as_ref()
                .map(|(token, _)| arkret_wire::Cursor::new(token.clone()))
                .transpose()
                .map_err(unavailable)?,
            has_more,
        };
        if arkret_canonical::canonical_json_bytes(&result)
            .map_err(unavailable)?
            .len()
            <= 4_194_304
        {
            break (result, continuation);
        }
        if end <= offset + 1 {
            return Err(crate::app_error!(
                LimitExceeded,
                "one immutable native inventory entry cannot fit the canonical page budget"
            ));
        }
        end -= 1;
    };
    if let Some((_, record)) = continuation {
        state
            .sync()
            .upsert_cursor(&coland_services::sync::CursorState {
                handle: record.handle,
                binding_subject: Some(record.context.binding_subject),
                device_id: None,
                session_id: None,
                service_id: record.context.service_id,
                filter_digest: Some(record.context.filter_digest),
                purpose: "stream".into(),
                positions: Some(record.positions),
                target: None,
                issued_at_ms: record.issued_at_ms,
                expires_at_ms: record.expires_at_ms,
            })
            .await
            .map_err(unavailable)?;
    }
    let guard = state
        .persistence()
        .native_backup_inventory_delivery(&reader, &manifest)
        .await
        .map_err(storage_error)?;
    coland_http::result::guarded_json_ok(
        arkret_models_integration::KeysBackupsListResponseBody::Manager(result),
        Some(guard),
    )
}

pub(super) async fn publication_context(
    state: &AppState,
    device: &applet_managed_device::VerifiedAppletManagedDevice,
) -> Result<coland_storage::RealmActorBackupPutContext, AppError> {
    let endpoint = applet_managed_device::scope_guard(state, device).await?;
    let nonce = Base64UrlString::new(arkret_canonical::base64url_encode(
        rand::random::<[u8; 32]>(),
    ))
    .map_err(unavailable)?;
    let bundle = crate::routing::realm_join::local_authority_bundle(
        state,
        &device.authority.realm_id,
        &nonce,
    )
    .await?;
    let located = crate::routing::realm_join::verify_served_bundle(state, bundle, &nonce).await?;
    let local =
        crate::routing::system::service_resolution::current_authenticated_service_resolution(state)
            .await?;
    let bundle = located.bundle;
    let genesis_resolution = resolution(state, &bundle.genesis_commit.signature, &local).await?;
    let genesis = original(state, bundle.genesis_event, bundle.genesis_commit).await?;
    let mut transitions = Vec::with_capacity(bundle.authority_transitions.len());
    for transition in bundle.authority_transitions {
        let from_resolution =
            resolution(state, &transition.handoff.old_authority_signature, &local).await?;
        let to_resolution = resolution(
            state,
            &transition.handoff.new_authority_acceptance_signature,
            &local,
        )
        .await?;
        transitions.push(RealmActorBackupGovernanceTransition {
            original: original(state, transition.change_event, transition.change_commit).await?,
            handoff: transition.handoff,
            from_resolution,
            to_resolution,
        });
    }
    Ok(coland_storage::RealmActorBackupPutContext {
        endpoint,
        credential_expires_at: device.transport_expires_at,
        authority: located.authority,
        authority_keys: located.keys,
        origin_resolution: local,
        governance_history: RealmActorBackupGovernanceHistory {
            genesis,
            genesis_resolution,
            authority_transitions: transitions,
        },
        max_actor_bytes: 50 * 1024 * 1024,
        max_realm_bytes: 100 * 1024 * 1024,
        idempotency_key: String::new(),
    })
}
