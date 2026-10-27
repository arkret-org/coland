//! Durable Station-to-public-Gateway active registration handoff.

use std::future::Future;
use std::time::Duration;

use arkret_http_client::{Client, HttpMessageSigner};
use arkret_models_integration::{
    PushRegisterDeviceRequestBody, PushRegisterDeviceResponseBody,
    PushRegistrationHandoffRequestBody, PushRegistrationId, PushRegistrationInstallationReceipt,
    PushRegistrationRecord,
};
use arkret_wire::{AccountId, ServiceKind, WebOrigin};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Utc};
use coland_http::error::{AppError, ErrorCode};
use coland_services::push_handoff::{
    ActivePushRegistrationPlan, active_push_registration_client_input_digest,
    plan_active_push_registration, retry_revoked_handoff_page,
};
use coland_storage::{
    DeviceRevocationGateSelector, PushRegistrationHandoffExpiryCursor,
    PushRegistrationHandoffIntentRecord, PushRegistrationHandoffIntentStatus,
    PushRegistrationHandoffIntentWrite, PushRegistrationHandoffRetryCursor,
    PushRegistrationHandoffRouteLocator,
};

use crate::push_gateway_registry::TrustedPushGateway;
use crate::state::AppState;

const GATEWAY_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const REVOKE_RETRY_POLL_INTERVAL: Duration = Duration::from_secs(5);
const REVOKE_RETRY_BATCH_LIMIT: usize = 64;

pub(super) struct PublicPushRegistration<'a> {
    pub account_id: AccountId,
    pub authorization: &'a DeviceRevocationGateSelector,
    pub body: PushRegisterDeviceRequestBody,
    pub push_route_id: String,
    pub push_target_id: arkret_identifiers::PushTargetId,
    pub prepared_at: DateTime<Utc>,
    pub session_revocation_ref: Option<&'a str>,
}

pub(super) async fn register(
    state: &AppState,
    input: PublicPushRegistration<'_>,
) -> Result<PushRegisterDeviceResponseBody, AppError> {
    let origin = canonical_gateway_origin(&input.body.push_gateway_url)?;
    let gateway = trusted_gateway_for_origin(state, &origin)?;
    let source_station_id = state.service_core_id();
    let local_route = PushRegistrationHandoffRouteLocator {
        account_id: input.account_id.clone(),
        device_id: input.body.device_id.clone(),
        push_route_id: input.push_route_id.clone(),
        destination_gateway_id: gateway.service_id().clone(),
    };
    let client_input_digest = active_push_registration_client_input_digest(
        &input.account_id,
        &input.body,
        &input.push_route_id,
        &origin,
        gateway.service_id(),
    )
    .map_err(service_storage_error)?;
    let existing = state
        .persistence()
        .push_registration_handoff_for_local_route(&source_station_id, &local_route)
        .await
        .map_err(service_storage_error)?;

    let plan =
        match plan_active_push_registration(existing, &client_input_digest, &input.push_target_id)
            .map_err(service_storage_error)?
        {
            ActivePushRegistrationPlan::ReturnVerified(record) => {
                return replay_verified_registration(
                    state,
                    &source_station_id,
                    &local_route,
                    input.authorization,
                    &input.account_id,
                    &input.push_route_id,
                    &origin,
                    input.session_revocation_ref,
                    record,
                )
                .await;
            }
            other => other,
        };
    // Only pending or new work needs live ServiceDescribe route verification.
    // A durable verified replay is a local CAS operation and remains available
    // while discovery is temporarily unavailable.
    let intent = match plan {
        ActivePushRegistrationPlan::ReplayPending(record) => record,
        ActivePushRegistrationPlan::Create { predecessor } => {
            let request = PushRegistrationHandoffRequestBody::Active {
                registration_id: random_registration_id()?,
                push_target_id: input.push_target_id,
                device_id: input.body.device_id.clone(),
                push_key: input.body.push_key.clone(),
                platform: input.body.platform.clone(),
                app_id: input.body.app_id.clone(),
                visible_notification_opt_in: input.body.visible_notification_opt_in,
                expires_at: None,
                supersedes_registration_id: predecessor,
            };
            let write = state
                .persistence()
                .ensure_push_registration_handoff_intent(
                    &source_station_id,
                    &local_route,
                    input.authorization,
                    &client_input_digest,
                    &request,
                    input.session_revocation_ref,
                    input.prepared_at,
                )
                .await
                .map_err(service_storage_error)?;
            match write {
                PushRegistrationHandoffIntentWrite::Created(record)
                | PushRegistrationHandoffIntentWrite::ExactReplay(record) => record,
                PushRegistrationHandoffIntentWrite::AdvancedToRevoked(_) => {
                    return Err(AppError::internal(
                        "active Push Gateway registration advanced to revoked unexpectedly",
                    ));
                }
            }
        }
        ActivePushRegistrationPlan::ReturnVerified(_) => unreachable!("returned above"),
    };

    if intent.status == PushRegistrationHandoffIntentStatus::ReceiptVerified {
        return Err(AppError::internal(
            "push registration planner returned a verified intent for network delivery",
        ));
    }
    let (request, receipt) =
        send_and_verify_handoff_intent(state, &origin, &gateway, &intent).await?;

    let registration = local_registration(
        &intent,
        &request,
        &input.account_id,
        &input.push_route_id,
        &origin,
    )?;
    let committed = state
        .persistence()
        .commit_verified_push_registration_handoff(
            &source_station_id,
            &local_route,
            &intent.registration_id,
            &intent.request_digest,
            &receipt,
            input.authorization,
            &registration,
            input.session_revocation_ref,
            Utc::now(),
        )
        .await
        .map_err(service_storage_error)?;
    match committed {
        coland_storage::PushRegistrationHandoffReceiptWrite::Stored(record)
        | coland_storage::PushRegistrationHandoffReceiptWrite::ExactReplay(record) => {
            outcome_from_record(&record)
        }
    }
}

pub(super) async fn unregister(
    state: &AppState,
    account_id: &AccountId,
    device_id: &arkret_wire::DeviceId,
    push_key: Option<&str>,
    app_id: Option<&str>,
) -> Result<usize, AppError> {
    let source_station_id = state.service_core_id();
    let intents = state
        .persistence()
        .begin_public_push_unregistration(account_id, device_id, push_key, app_id, Utc::now())
        .await
        .map_err(service_storage_error)?;
    confirm_revoked_intents(intents, |intent| {
        confirm_revoked_intent(state, &source_station_id, intent)
    })
    .await
    .map_err(unregistration_error)
}

pub(crate) async fn unregister_for_hard_logout(
    state: &AppState,
    account_id: &AccountId,
    device_id: &arkret_wire::DeviceId,
) -> Result<(), AppError> {
    unregister(state, account_id, device_id, None, None).await?;
    Ok(())
}

async fn confirm_revoked_intents<F, Fut>(
    intents: Vec<PushRegistrationHandoffIntentRecord>,
    mut confirm: F,
) -> Result<usize, AppError>
where
    F: FnMut(PushRegistrationHandoffIntentRecord) -> Fut,
    Fut: Future<Output = Result<(), AppError>>,
{
    let mut confirmed = 0;
    for intent in intents {
        let request = intent.request().map_err(persistence_error)?;
        if request.state() != arkret_models_integration::PushRegistrationHandoffState::Revoked
            || intent.status != PushRegistrationHandoffIntentStatus::AwaitingReceipt
        {
            return Err(AppError::internal(
                "public Push Gateway unregistration selected a non-awaiting revoke intent",
            ));
        }
        confirm(intent).await?;
        confirmed += 1;
    }
    Ok(confirmed)
}

async fn retry_awaiting_revocations_once(
    state: &AppState,
    expiry_cursor: &mut Option<PushRegistrationHandoffExpiryCursor>,
    revoke_cursor: &mut Option<PushRegistrationHandoffRetryCursor>,
) -> Result<coland_services::push_handoff::RevokeRetryReport, AppError> {
    let source_station_id = state.service_core_id();
    match state
        .persistence()
        .expire_public_push_registrations(
            &source_station_id,
            Utc::now(),
            expiry_cursor.as_ref(),
            REVOKE_RETRY_BATCH_LIMIT,
        )
        .await
    {
        Ok(page) => {
            *expiry_cursor = page.next_cursor;
            if page.failed > 0 {
                tracing::warn!(
                    worker = "public_push_revoke_retry",
                    stage = "expire_public_push_registrations",
                    scanned = page.scanned,
                    expired = page.expired.len(),
                    failed = page.failed,
                    "public Push Gateway expiry sweep completed with isolated failures"
                );
            }
        }
        Err(_) => tracing::warn!(
            worker = "public_push_revoke_retry",
            stage = "expire_public_push_registrations",
            "public Push Gateway expiry sweep could not load its bounded page"
        ),
    }
    retry_revoked_handoff_page(
        revoke_cursor,
        REVOKE_RETRY_BATCH_LIMIT,
        |after, limit| {
            let source_station_id = source_station_id.clone();
            async move {
                state
                    .persistence()
                    .awaiting_public_push_revocations(&source_station_id, after.as_ref(), limit)
                    .await
                    .map_err(service_storage_error)
            }
        },
        |intent| confirm_revoked_intent(state, &source_station_id, intent),
    )
    .await
}

async fn reconcile_confirmed_hard_logouts_once(
    state: &AppState,
    cursor: &mut Option<String>,
) -> Result<(), AppError> {
    let rows = state
        .persistence()
        .pending_confirmed_push_hard_logouts(cursor.as_deref(), REVOKE_RETRY_BATCH_LIMIT)
        .await
        .map_err(service_storage_error)?;
    let full_page = rows.len() == REVOKE_RETRY_BATCH_LIMIT;
    for row in rows {
        *cursor = Some(row.grant_token_digest.clone());
        let actor = row.account_id.principal_id.as_str();
        let device_id = row.device_id.as_str();
        let result = async {
            crate::routing::identity::auth::revoke_sessions_for_hard_logout_device(
                state, actor, device_id,
            )
            .await?;
            unregister_for_hard_logout(state, &row.account_id, &row.device_id).await?;
            state
                .deliveries()
                .purge_device_delivery(actor, device_id)
                .await
                .map_err(|error| AppError::internal(error.to_string()))?;
            state
                .persistence()
                .mark_push_hard_logout_completed(&row.grant_token_digest, Utc::now())
                .await
                .map_err(service_storage_error)
        }
        .await;
        if result.is_err() {
            tracing::warn!(
                worker = "public_push_revoke_retry",
                stage = "reconcile_confirmed_hard_logout",
                "confirmed hard logout local cleanup failed"
            );
        }
    }
    if !full_page {
        *cursor = None;
    }
    Ok(())
}

/// Spawn the bounded recovery loop for durable public-Gateway tombstones.
///
/// Each pass selects at most [`REVOKE_RETRY_BATCH_LIMIT`] awaiting revokes.
/// Items are confirmed independently so one unavailable Gateway cannot starve
/// another. The durable request bytes and registration id are always replayed
/// by [`confirm_revoked_intent`]; this worker never reconstructs wire intent.
pub fn spawn_public_push_revoke_retry_worker(
    state: AppState,
) -> Option<std::sync::Arc<tokio::task::JoinHandle<()>>> {
    Some(std::sync::Arc::new(tokio::spawn(async move {
        let mut ticker = tokio::time::interval(REVOKE_RETRY_POLL_INTERVAL);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut drain = state.subscribe_connection_drain();
        let mut expiry_cursor = None;
        let mut revoke_cursor = None;
        let mut hard_logout_cursor = None;
        // The lifecycle snapshot is durable. Re-run once per terminal
        // transition on each process start, then let the receipt worker
        // confirm any tombstones left awaiting a Gateway response.
        let mut reconciled_deactivations = std::collections::BTreeMap::new();
        loop {
            tokio::select! {
                _ = ticker.tick() => {}
                changed = drain.changed() => {
                    if changed.is_err() || drain.borrow().is_some() {
                        break;
                    }
                    continue;
                }
            }
            let reconcile = async {
                for (principal_id, lifecycle) in state.identities().account_lifecycles_snapshot() {
                    if !matches!(lifecycle.state.as_str(), "deactivated" | "erasure_pending")
                        || reconciled_deactivations.get(&principal_id)
                            == Some(&lifecycle.changed_at)
                    {
                        continue;
                    }
                    let principal_id = match arkret_wire::DidCoreId::new(principal_id.clone()) {
                        Ok(principal_id) => principal_id,
                        Err(_) => continue,
                    };
                    let account_id = AccountId::new(principal_id, state.service_core_id().clone());
                    match state
                        .persistence()
                        .begin_public_push_account_deactivation(&account_id, Utc::now())
                        .await
                    {
                        Ok(_) => {
                            reconciled_deactivations.insert(
                                account_id.principal_id.as_str().to_owned(),
                                lifecycle.changed_at,
                            );
                        }
                        Err(_) => tracing::warn!(
                            worker = "public_push_revoke_retry",
                            stage = "reconcile_account_deactivation",
                            "public Push Gateway account deactivation reconciliation failed"
                        ),
                    }
                }
            };
            tokio::select! {
                _ = reconcile => {}
                changed = drain.changed() => {
                    if changed.is_err() || drain.borrow().is_some() {
                        break;
                    }
                    continue;
                }
            }
            if reconcile_confirmed_hard_logouts_once(&state, &mut hard_logout_cursor)
                .await
                .is_err()
            {
                tracing::warn!(
                    worker = "public_push_revoke_retry",
                    stage = "scan_confirmed_hard_logout",
                    "confirmed hard logout journal scan failed"
                );
            }
            let pass =
                retry_awaiting_revocations_once(&state, &mut expiry_cursor, &mut revoke_cursor);
            let report = tokio::select! {
                result = pass => result,
                changed = drain.changed() => {
                    if changed.is_err() || drain.borrow().is_some() {
                        break;
                    }
                    continue;
                }
            };
            match report {
                Ok(report) if report.failed > 0 => tracing::warn!(
                    worker = "public_push_revoke_retry",
                    scanned = report.scanned,
                    confirmed = report.confirmed,
                    failed = report.failed,
                    "public Push Gateway revoke retry pass completed with failures"
                ),
                Ok(report) if report.confirmed > 0 => tracing::info!(
                    worker = "public_push_revoke_retry",
                    scanned = report.scanned,
                    confirmed = report.confirmed,
                    "public Push Gateway revoke retry pass completed"
                ),
                Ok(_) => {}
                Err(_) => tracing::warn!(
                    worker = "public_push_revoke_retry",
                    stage = "durable revoke scan failed",
                    "public Push Gateway revoke retry pass failed"
                ),
            }
        }
    })))
}

/// Reconcile one full local Account without disclosing that Account upstream.
/// Only the existing cryptographically verified and durably committed Gateway
/// receipt completes a tombstone. Exhaust the stable paginated retry view so
/// another Account's pending intent cannot be mistaken for this Account's work.
pub(crate) async fn confirm_deactivated_account_push_revocations(
    state: &AppState,
    account: &AccountId,
) -> Result<bool, AppError> {
    let source_station_id = state.service_core_id();
    if account.station_id != source_station_id {
        return Err(AppError::internal("push deactivation Account is not local"));
    }
    state
        .persistence()
        .begin_public_push_account_deactivation(account, Utc::now())
        .await
        .map_err(service_storage_error)?;
    let mut cursor = None;
    let mut complete = true;
    loop {
        let page = state
            .persistence()
            .awaiting_public_push_revocations(
                &source_station_id,
                cursor.as_ref(),
                REVOKE_RETRY_BATCH_LIMIT,
            )
            .await
            .map_err(service_storage_error)?;
        let full_page = page.len() == REVOKE_RETRY_BATCH_LIMIT;
        // Capture the scan coordinate before receipt commits change updated_at.
        cursor = page.last().map(PushRegistrationHandoffRetryCursor::after);
        for intent in page {
            if intent.local_route.account_id == *account
                && confirm_revoked_intent(state, &source_station_id, intent)
                    .await
                    .is_err()
            {
                complete = false;
            }
        }
        if !full_page {
            return Ok(complete);
        }
    }
}

async fn confirm_revoked_intent(
    state: &AppState,
    source_station_id: &arkret_wire::DidCoreId,
    intent: PushRegistrationHandoffIntentRecord,
) -> Result<(), AppError> {
    let registry = state.trusted_push_gateways();
    let gateway = registry
        .get_by_service_id(&intent.destination_gateway_id)
        .cloned()
        .ok_or_else(|| {
            handoff_unavailable(
                "Gateway destination is not onboarded",
                &intent.destination_gateway_id,
            )
        })?;
    let origin = gateway.canonical_origin().clone();
    let (_, receipt) = send_and_verify_handoff_intent(state, &origin, &gateway, &intent).await?;
    let committed = state
        .persistence()
        .commit_verified_push_registration_handoff_receipt(
            source_station_id,
            &intent.registration_id,
            &intent.request_digest,
            &receipt,
            Utc::now(),
        )
        .await
        .map_err(service_storage_error)?;
    match committed {
        coland_storage::PushRegistrationHandoffReceiptWrite::Stored(record)
        | coland_storage::PushRegistrationHandoffReceiptWrite::ExactReplay(record)
            if record.desired_state
                == arkret_models_integration::PushRegistrationHandoffState::Revoked
                && record.status == PushRegistrationHandoffIntentStatus::ReceiptVerified =>
        {
            Ok(())
        }
        _ => Err(AppError::internal(
            "public Push Gateway revoke receipt did not commit terminal state",
        )),
    }
}

async fn send_and_verify_handoff_intent(
    state: &AppState,
    origin: &WebOrigin,
    gateway: &TrustedPushGateway,
    intent: &PushRegistrationHandoffIntentRecord,
) -> Result<
    (
        PushRegistrationHandoffRequestBody,
        PushRegistrationInstallationReceipt,
    ),
    AppError,
> {
    if intent.destination_gateway_id != *gateway.service_id()
        || intent.local_route.destination_gateway_id != *gateway.service_id()
        || origin != gateway.canonical_origin()
    {
        return Err(handoff_unavailable(
            "Gateway intent destination does not match onboarding",
            "destination mismatch",
        ));
    }
    let request = intent.request().map_err(persistence_error)?;
    let route = resolve_trusted_gateway(state, origin, gateway).await?;
    let (_, assertion_method) = state
        .current_service_receipt_binding()
        .await
        .map_err(|error| handoff_unavailable("source signer is not current", error))?;
    let (_, http) = crate::security::validate_http_url_for_egress_with_pinned_client(
        route.base_url(),
        "public Push Gateway registration handoff",
        state.config().development_mode,
        GATEWAY_REQUEST_TIMEOUT,
    )
    .map_err(|error| handoff_unavailable("Gateway egress denied", error))?;
    let base_url = reqwest::Url::parse(route.base_url())
        .map_err(|error| handoff_unavailable("verified Gateway route is invalid", error))?;
    let client = Client::builder(base_url)
        .http_client(http)
        .http_message_signer(HttpMessageSigner::new(
            assertion_method.as_str(),
            state.notary_signing_key().as_ref().clone(),
        ))
        .build()
        .map_err(|error| handoff_unavailable("Gateway client setup failed", error))?;
    let outcome = client
        .push_apply_registration(&request, &intent.source_station_id, gateway.service_id())
        .await
        .map_err(|error| handoff_unavailable("Gateway request failed", error))?;
    verify_handoff_receipt(gateway, intent, &request, &outcome.receipt)?;
    Ok((request, outcome.receipt))
}

fn verify_handoff_receipt(
    gateway: &TrustedPushGateway,
    intent: &PushRegistrationHandoffIntentRecord,
    request: &PushRegistrationHandoffRequestBody,
    receipt: &PushRegistrationInstallationReceipt,
) -> Result<(), AppError> {
    if receipt.proof.verification_method != *gateway.receipt_verification_method() {
        return Err(handoff_unavailable(
            "Gateway receipt used an unapproved verification method",
            "receipt method mismatch",
        ));
    }
    arkret::verify_push_registration_installation_receipt(
        receipt,
        request,
        &intent.source_station_id,
        gateway.service_id(),
        gateway.receipt_verifying_key(),
    )
    .map_err(|error| handoff_unavailable("Gateway receipt verification failed", error))
}

#[allow(clippy::too_many_arguments)]
async fn replay_verified_registration(
    state: &AppState,
    source_station_id: &arkret_wire::DidCoreId,
    local_route: &PushRegistrationHandoffRouteLocator,
    authorization: &DeviceRevocationGateSelector,
    account_id: &AccountId,
    push_route_id: &str,
    origin: &WebOrigin,
    session_revocation_ref: Option<&str>,
    record: PushRegistrationHandoffIntentRecord,
) -> Result<PushRegisterDeviceResponseBody, AppError> {
    let request = record.request().map_err(persistence_error)?;
    let receipt = record.receipt.as_ref().ok_or_else(|| {
        AppError::internal("verified push registration replay is missing its durable receipt")
    })?;
    let registration = local_registration(&record, &request, account_id, push_route_id, origin)?;
    let committed = state
        .persistence()
        .commit_verified_push_registration_handoff(
            source_station_id,
            local_route,
            &record.registration_id,
            &record.request_digest,
            receipt,
            authorization,
            &registration,
            session_revocation_ref,
            Utc::now(),
        )
        .await
        .map_err(service_storage_error)?;
    match committed {
        coland_storage::PushRegistrationHandoffReceiptWrite::ExactReplay(record) => {
            outcome_from_record(&record)
        }
        coland_storage::PushRegistrationHandoffReceiptWrite::Stored(_) => Err(AppError::internal(
            "verified push registration replay unexpectedly stored a new receipt",
        )),
    }
}

fn canonical_gateway_origin(raw: &str) -> Result<WebOrigin, AppError> {
    let url = reqwest::Url::parse(raw)
        .map_err(|_| AppError::param_invalid("invalid push gateway URL"))?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || url.query().is_some()
        || url.fragment().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(AppError::param_invalid("invalid push gateway URL"));
    }
    WebOrigin::new(url.origin().ascii_serialization())
        .map_err(|_| AppError::param_invalid("invalid push gateway URL"))
}

async fn resolve_trusted_gateway(
    state: &AppState,
    origin: &WebOrigin,
    gateway: &TrustedPushGateway,
) -> Result<coland_services::service_route::ResolvedServiceRoute, AppError> {
    let resolver = state
        .service_route_resolver()
        .map_err(|error| handoff_unavailable("Gateway route resolver unavailable", error))?;
    let now = Utc::now();
    let route = match resolver
        .resolve_route(
            gateway.service_id(),
            ServiceKind::PushGateway.as_str(),
            now,
            false,
        )
        .await
    {
        Ok(route) => route,
        Err(coland_services::ServiceError::NotFound(_)) => {
            let base = arkret_models_identity::service_identity::CanonicalServiceUrl::canonicalize(
                origin.as_str(),
            )
            .map_err(|error| handoff_unavailable("Gateway origin is invalid", error))?;
            let carrier = arkret_models_identity::ServiceResolutionCarrier::ResolutionUrl {
                resolution_url: format!(
                    "{}{}",
                    base,
                    arkret_models_identity::canonical_service_resolution_path(gateway.service_id())
                        .trim_start_matches('/')
                ),
            };
            carrier
                .validate_shape(gateway.service_id())
                .map_err(|error| handoff_unavailable("Gateway carrier is invalid", error))?;
            resolver
                .resolve_carrier(
                    &carrier,
                    gateway.service_id(),
                    ServiceKind::PushGateway.as_str(),
                    now,
                )
                .await
                .map_err(|error| handoff_unavailable("Gateway route verification failed", error))?;
            resolver
                .resolve_route(
                    gateway.service_id(),
                    ServiceKind::PushGateway.as_str(),
                    now,
                    false,
                )
                .await
                .map_err(|error| handoff_unavailable("Gateway route unavailable", error))?
        }
        Err(error) => {
            return Err(handoff_unavailable(
                "Gateway route verification failed",
                error,
            ));
        }
    };
    state
        .trusted_push_gateways()
        .authorize_route(origin, &route, now)
        .map_err(|error| handoff_unavailable("Gateway route is not trusted", error))?;
    Ok(route)
}

fn trusted_gateway_for_origin(
    state: &AppState,
    origin: &WebOrigin,
) -> Result<TrustedPushGateway, AppError> {
    state
        .trusted_push_gateways()
        .get(origin)
        .cloned()
        .ok_or_else(|| handoff_unavailable("Gateway origin is not onboarded", origin))
}

fn random_registration_id() -> Result<PushRegistrationId, AppError> {
    PushRegistrationId::new(URL_SAFE_NO_PAD.encode(rand::random::<[u8; 16]>())).map_err(|error| {
        AppError::internal(format!(
            "generated push registration id is invalid: {error}"
        ))
    })
}

fn local_registration(
    intent: &PushRegistrationHandoffIntentRecord,
    request: &PushRegistrationHandoffRequestBody,
    account_id: &AccountId,
    push_route_id: &str,
    origin: &WebOrigin,
) -> Result<PushRegistrationRecord, AppError> {
    let PushRegistrationHandoffRequestBody::Active {
        registration_id,
        push_target_id,
        device_id,
        push_key,
        platform,
        app_id,
        visible_notification_opt_in,
        expires_at,
        ..
    } = request
    else {
        return Err(AppError::internal(
            "revoked Push Gateway intent cannot complete active registration",
        ));
    };
    Ok(PushRegistrationRecord {
        registration_id: arkret_wire::OpaqueLocalId::new(registration_id.as_str().to_owned())
            .map_err(|error| {
                AppError::internal(format!("push registration id projection failed: {error}"))
            })?,
        account_id: account_id.clone(),
        device_id: device_id.clone(),
        push_gateway: format!("{origin}/"),
        push_key: push_key.clone(),
        platform: platform.clone(),
        app_id: app_id.clone(),
        visible_notification_opt_in: *visible_notification_opt_in,
        push_route_id: push_route_id.to_owned(),
        push_target_id: push_target_id.clone(),
        salt_epoch_id: super::push::push_target_salt_epoch_id_at(intent.created_at),
        expires_at: *expires_at,
        retained_push_targets: Vec::new(),
    })
}

fn outcome_from_record(
    record: &PushRegistrationHandoffIntentRecord,
) -> Result<PushRegisterDeviceResponseBody, AppError> {
    record.validate().map_err(persistence_error)?;
    if record.status != PushRegistrationHandoffIntentStatus::ReceiptVerified
        || record.receipt.is_none()
    {
        return Err(AppError::internal(
            "push registration outcome requested before receipt commit",
        ));
    }
    let request = record.request().map_err(persistence_error)?;
    let PushRegistrationHandoffRequestBody::Active {
        registration_id,
        push_target_id,
        expires_at,
        ..
    } = request
    else {
        return Err(AppError::internal(
            "revoked Push Gateway intent cannot produce active registration outcome",
        ));
    };
    Ok(PushRegisterDeviceResponseBody {
        push_target_id,
        registration_id,
        expires_at,
    })
}

fn service_storage_error(error: coland_services::ServiceError) -> AppError {
    let detail = error.to_string();
    if error.is_conflict_kind() {
        AppError::conflict("push registration state changed concurrently")
            .with_private_detail(detail)
    } else {
        AppError::internal("push registration persistence failed").with_private_detail(detail)
    }
}

fn persistence_error(error: coland_storage::PersistenceError) -> AppError {
    let is_conflict = matches!(&error, coland_storage::PersistenceError::Conflict(_));
    let detail = error.to_string();
    if is_conflict {
        AppError::conflict("push registration state changed concurrently")
            .with_private_detail(detail)
    } else {
        AppError::internal("push registration persistence failed").with_private_detail(detail)
    }
}

/// Every handoff failure — an origin that is not onboarded, route/Describe
/// verification, egress, remote rejection or an unverifiable receipt — means
/// the requested Gateway is unavailable for this route.  Register reports the
/// operation-specific `push_gateway_unreachable`; it is not a missing signed
/// dependency, so `dependency_missing` is outside the operation's error set.
fn handoff_unavailable(stage: &'static str, _error: impl std::fmt::Display) -> AppError {
    tracing::warn!(stage, "public Push Gateway registration handoff failed");
    crate::app_error!(
        PushGatewayUnreachable,
        "public Push Gateway registration is unavailable",
    )
    .with_private_detail(stage)
}

/// Unregister has no operation-specific Gateway failure code.  A durable
/// revoke intent whose remote tombstone is not yet confirmed is the universal
/// retryable `temporarily_unavailable`, never a 204.
fn unregistration_error(error: AppError) -> AppError {
    if error.code != ErrorCode::PushGatewayUnreachable {
        return error;
    }
    let mut unavailable = crate::app_error!(
        TemporarilyUnavailable,
        "public Push Gateway unregistration is not yet confirmed",
    );
    unavailable.private_detail = error.private_detail;
    unavailable
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use arkret_models_integration::PushRegistrationHandoffState;
    use arkret_wire::{Audience, DeviceId, DidCoreId, DidUrl, Hash, PayloadProof};
    use serde_json::json;

    use super::*;

    fn device_authorization(
        source: &DidCoreId,
        device_id: &DeviceId,
    ) -> DeviceRevocationGateSelector {
        let event_id =
            arkret_wire::EventId::new("ak:event:AcIMom-0qqAXx_hmDJfxxaUJb_oJ64S3ARW1-WKFDCoD")
                .unwrap();
        DeviceRevocationGateSelector {
            principal_id: DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
            station_id: source.clone(),
            device_id: device_id.as_str().to_owned(),
            authorization_ref: arkret_wire::CommittedEventRef {
                commit_id: arkret_wire::RealmCommitId::from_digest(arkret_canonical::sha256_bytes(
                    event_id.as_str().as_bytes(),
                )),
                stream_ref: arkret_wire::CommitStreamRef::Realm {
                    realm_id: arkret_wire::RealmId::new(
                        "ak:realm:ARQRpvtCGBgQfVQzTK4_Hgbg0D0HSnc3gPCvXOQUICir",
                    )
                    .unwrap(),
                },
                stream_position: 1,
                event_id,
            },
        }
    }

    fn request(registration_id: &str) -> PushRegistrationHandoffRequestBody {
        serde_json::from_value(json!({
            "registration_id": registration_id,
            "push_target_id": "ak:pseudonym:push:kosc9iQ4gVct1OB-b6X364WIFIsJFVbVzn7BMBs1sm8",
            "device_id": "ak:device:01904100-0000-7000-8000-000000000001",
            "state": "active",
            "push_key": "provider-secret",
            "platform": "desktop",
            "app_id": "inkson",
            "visible_notification_opt_in": false
        }))
        .unwrap()
    }

    fn client_body() -> PushRegisterDeviceRequestBody {
        serde_json::from_value(json!({
            "device_id": "ak:device:01904100-0000-7000-8000-000000000001",
            "push_gateway_url": "https://push.example/_arkret/edge/push/notify",
            "push_key": "provider-secret",
            "platform": "desktop",
            "app_id": "inkson",
            "visible_notification_opt_in": false
        }))
        .unwrap()
    }

    fn record(status: PushRegistrationHandoffIntentStatus) -> PushRegistrationHandoffIntentRecord {
        let source = DidCoreId::new("ak:did_core:web:station.example").unwrap();
        let destination = DidCoreId::new("ak:did_core:web:push.example").unwrap();
        let request = request("registration_0123456789abcdef");
        let device_id = request.device_id().clone();
        let digest = Hash::new(format!("sha256:{}", "2".repeat(64))).unwrap();
        let now = DateTime::parse_from_rfc3339("2026-09-22T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let mut record = PushRegistrationHandoffIntentRecord::prepare(
            source.clone(),
            PushRegistrationHandoffRouteLocator {
                account_id: AccountId::new(
                    DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
                    source.clone(),
                ),
                device_id: DeviceId::new("ak:device:01904100-0000-7000-8000-000000000001").unwrap(),
                push_route_id: "inkson".to_owned(),
                destination_gateway_id: destination.clone(),
            },
            device_authorization(&source, &device_id),
            digest,
            &request,
            now,
        )
        .unwrap();
        if status == PushRegistrationHandoffIntentStatus::ReceiptVerified {
            let mut receipt = arkret_models_integration::PushRegistrationInstallationReceipt {
                registration_id: request.registration_id().clone(),
                push_target_id: request.push_target_id().clone(),
                device_id: request.device_id().clone(),
                state: PushRegistrationHandoffState::Active,
                request_digest: request.request_digest().unwrap(),
                source_station_id: source,
                destination_gateway_id: destination,
                stored_at: now,
                proof: PayloadProof {
                    kind: arkret_wire::proof_kind::DETACHED_JWS.to_owned(),
                    verification_method: DidUrl::new("did:web:push.example#receipt").unwrap(),
                    payload_digest: Hash::new(format!("sha256:{}", "0".repeat(64))).unwrap(),
                    created_at: now,
                    domain: None,
                    audience: Some(Audience::Single(
                        "ak:did_core:web:station.example".to_owned(),
                    )),
                    proof_purpose: None,
                    jws: "fixture..signature".to_owned(),
                },
            };
            receipt.proof.payload_digest = receipt.expected_payload_digest().unwrap();
            record.status = status;
            record.receipt = Some(receipt);
        }
        record
    }

    fn revoked_record() -> PushRegistrationHandoffIntentRecord {
        let active = record(PushRegistrationHandoffIntentStatus::AwaitingReceipt);
        let active_request = active.request().unwrap();
        let revoked = PushRegistrationHandoffRequestBody::Revoked {
            registration_id: active.registration_id.clone(),
            push_target_id: active_request.push_target_id().clone(),
            device_id: active_request.device_id().clone(),
        };
        PushRegistrationHandoffIntentRecord::prepare(
            active.source_station_id,
            active.local_route,
            active.device_authorization,
            active.client_input_digest,
            &revoked,
            active.created_at,
        )
        .unwrap()
    }

    fn trusted_gateway() -> TrustedPushGateway {
        let key = ed25519_dalek::SigningKey::from_bytes(&[7; 32]).verifying_key();
        let mut multicodec = vec![0xed, 0x01];
        multicodec.extend_from_slice(key.as_bytes());
        let registry = crate::push_gateway_registry::TrustedPushGatewayRegistry::from_json(
            &serde_json::to_string(&serde_json::json!([{
                "canonical_origin": "https://push.example",
                "service_did": "did:web:push.example",
                "receipt_verification_method": "did:web:push.example#receipt",
                "receipt_public_key_multibase": format!(
                    "z{}",
                    bs58::encode(multicodec).into_string()
                ),
            }]))
            .unwrap(),
        )
        .unwrap();
        registry
            .get(&WebOrigin::new("https://push.example").unwrap())
            .unwrap()
            .clone()
    }

    #[test]
    fn retry_replays_pending_and_returns_verified_without_allocating_another_id() {
        let pending = record(PushRegistrationHandoffIntentStatus::AwaitingReceipt);
        let digest = pending.client_input_digest.clone();
        let target = pending.request().unwrap().push_target_id().clone();
        assert!(matches!(
            plan_active_push_registration(Some(pending), &digest, &target).unwrap(),
            ActivePushRegistrationPlan::ReplayPending(_)
        ));

        let verified = record(PushRegistrationHandoffIntentStatus::ReceiptVerified);
        let durable_outcome = outcome_from_record(&verified).unwrap();
        assert_eq!(
            durable_outcome.registration_id.as_str(),
            verified.registration_id.as_str()
        );
        assert!(matches!(
            plan_active_push_registration(Some(verified), &digest, &target).unwrap(),
            ActivePushRegistrationPlan::ReturnVerified(_)
        ));
    }

    #[test]
    fn changed_input_conflicts_while_pending_and_supersedes_only_after_verification() {
        let changed = Hash::new(format!("sha256:{}", "3".repeat(64))).unwrap();
        let pending = record(PushRegistrationHandoffIntentStatus::AwaitingReceipt);
        let target = pending.request().unwrap().push_target_id().clone();
        assert!(plan_active_push_registration(Some(pending), &changed, &target).is_err());

        let verified = record(PushRegistrationHandoffIntentStatus::ReceiptVerified);
        let expected = verified.registration_id.clone();
        match plan_active_push_registration(Some(verified), &changed, &target).unwrap() {
            ActivePushRegistrationPlan::Create { predecessor } => {
                assert_eq!(predecessor, Some(expected));
            }
            _ => panic!("changed verified input must create a successor"),
        }
    }

    #[test]
    fn registration_ids_have_full_random_128_bit_payload_and_origins_are_canonical() {
        let first = random_registration_id().unwrap();
        let second = random_registration_id().unwrap();
        assert_eq!(first.as_str().len(), 22);
        assert_ne!(first, second);
        assert_eq!(
            canonical_gateway_origin("https://push.example/_arkret/edge/push/notify")
                .unwrap()
                .as_str(),
            "https://push.example"
        );
        assert!(canonical_gateway_origin("http://push.example/notify").is_err());
        assert!(canonical_gateway_origin("https://user@push.example/notify").is_err());
    }

    #[test]
    fn client_digest_binds_local_identity_destination_and_desired_route_semantics() {
        let source = DidCoreId::new("ak:did_core:web:station.example").unwrap();
        let account = AccountId::new(
            DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
            source,
        );
        let destination = DidCoreId::new("ak:did_core:web:push.example").unwrap();
        let origin = WebOrigin::new("https://push.example").unwrap();
        let body = client_body();
        let digest = active_push_registration_client_input_digest(
            &account,
            &body,
            "inkson",
            &origin,
            &destination,
        )
        .unwrap();

        let mut changed = body.clone();
        changed.visible_notification_opt_in = true;
        assert_ne!(
            digest,
            active_push_registration_client_input_digest(
                &account,
                &changed,
                "inkson",
                &origin,
                &destination,
            )
            .unwrap()
        );
        assert_ne!(
            digest,
            active_push_registration_client_input_digest(
                &account,
                &body,
                "inkson.voip",
                &origin,
                &destination
            )
            .unwrap()
        );
        let other_destination = DidCoreId::new("ak:did_core:web:push-2.example").unwrap();
        assert_ne!(
            digest,
            active_push_registration_client_input_digest(
                &account,
                &body,
                "inkson",
                &origin,
                &other_destination
            )
            .unwrap()
        );
        let next_epoch_target = arkret_identifiers::PushTargetId::new(
            "ak:pseudonym:push:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        )
        .unwrap();
        assert_eq!(
            digest,
            active_push_registration_client_input_digest(
                &account,
                &body,
                "inkson",
                &origin,
                &destination
            )
            .unwrap(),
            "derived target rotation is handled after pending replay planning"
        );
        let verified = record(PushRegistrationHandoffIntentStatus::ReceiptVerified);
        assert!(matches!(
            plan_active_push_registration(Some(verified), &digest, &next_epoch_target).unwrap(),
            ActivePushRegistrationPlan::Create { .. }
        ));
    }

    #[test]
    fn remote_error_detail_is_not_logged_or_exposed() {
        let error = handoff_unavailable(
            "Gateway request failed",
            "remote body echoed provider-secret",
        );
        assert_eq!(error.code, ErrorCode::PushGatewayUnreachable);
        assert_eq!(error.http_status().as_u16(), 503);
        assert_eq!(
            error.message.as_ref(),
            "public Push Gateway registration is unavailable"
        );
        assert_eq!(
            error.private_detail.as_deref(),
            Some("Gateway request failed")
        );
        assert!(!format!("{error:?}").contains("provider-secret"));
    }

    #[test]
    fn handoff_failures_stay_inside_each_operation_error_set() {
        use arkret_wire::generated::OperationSpecificError;

        let register_codes = arkret_wire::ServiceOperationId::EdgePushCommandRegisterDeviceV1
            .operation_specific_errors();
        let not_onboarded =
            handoff_unavailable("Gateway origin is not onboarded", "https://push.example");
        assert!(
            register_codes
                .iter()
                .any(|code| *code == OperationSpecificError::Code(not_onboarded.code)),
            "register must report a registered push Gateway failure"
        );
        assert_ne!(not_onboarded.code, ErrorCode::DependencyMissing);

        let unregister = unregistration_error(handoff_unavailable(
            "Gateway request failed",
            "simulated timeout",
        ));
        assert_eq!(unregister.code, ErrorCode::TemporarilyUnavailable);
        assert_eq!(
            unregister.private_detail.as_deref(),
            Some("Gateway request failed")
        );
        let untouched = unregistration_error(AppError::internal("storage failed"));
        assert_eq!(untouched.code, ErrorCode::InternalError);
    }

    #[test]
    fn wrong_gateway_receipt_binding_fails_before_commit() {
        let intent = record(PushRegistrationHandoffIntentStatus::ReceiptVerified);
        let request = intent.request().unwrap();
        let mut receipt = intent.receipt.clone().unwrap();
        receipt.destination_gateway_id =
            DidCoreId::new("ak:did_core:web:other-gateway.example").unwrap();
        let error = verify_handoff_receipt(&trusted_gateway(), &intent, &request, &receipt)
            .expect_err("wrong destination must fail closed");
        assert_eq!(
            error.private_detail.as_deref(),
            Some("Gateway receipt verification failed")
        );
    }

    #[tokio::test]
    async fn revoke_batch_returns_failure_on_partial_remote_error_and_zero_is_success() {
        let intent = revoked_record();
        let calls = Arc::new(AtomicUsize::new(0));
        let observed = calls.clone();
        let result = confirm_revoked_intents(vec![intent.clone(), intent], move |_| {
            let observed = observed.clone();
            async move {
                let call = observed.fetch_add(1, Ordering::SeqCst) + 1;
                if call == 2 {
                    Err(handoff_unavailable(
                        "Gateway request failed",
                        "simulated timeout",
                    ))
                } else {
                    Ok(())
                }
            }
        })
        .await;
        assert!(
            result.is_err(),
            "a partial remote failure must not become 204"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 2);

        assert_eq!(
            confirm_revoked_intents(Vec::new(), |_| async { Ok(()) })
                .await
                .unwrap(),
            0,
            "no local or public matches remain idempotent success"
        );
    }
}
