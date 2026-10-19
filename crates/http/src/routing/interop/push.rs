//! Station-owned authenticated push registration surfaces.
//!
//! Surfaces:
//! - `POST /_arkret/edge/push/register-device` — register a device token + push gateway
//! - `POST /_arkret/edge/push/unregister-device` — remove an authenticated actor's device token
//!
//! Device registration authenticates with an ordinary bearer session; there is
//! no header-carried alternative.
//! Spec rule: no DID in push payload / TURN username.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use coland_http::error::AppError;
use coland_http::result::{JsonResult, json_ok};
use salvo::oapi::extract::JsonBody;
use salvo::prelude::*;
use serde_json::json;

use super::audit::append_audit_log;
use super::{authenticated_session, hmac_sha256, now, sha256_hex};
use crate::routing::system::extract::AuthArgs;
use crate::state::AppState;
use crate::wire::{PushRegisterDeviceRequestBody, PushUnregisterDeviceRequestBody};

pub(crate) const PUSH_TARGET_SALT_ROTATION_SECONDS: i64 = 30 * 24 * 60 * 60;

pub(super) fn push_target_salt_epoch_id_at(now: chrono::DateTime<chrono::Utc>) -> String {
    let epoch = now
        .timestamp()
        .div_euclid(PUSH_TARGET_SALT_ROTATION_SECONDS);
    format!("ak.push.salt_epoch.{epoch}")
}

const PUSH_TARGET_ID_PREFIX: &str = "ak:pseudonym:push:";

/// The keyed pairwise tag both the push target pseudonym and the gateway-local
/// registration handle are spelled from.
fn derive_push_target_tag(
    root_key: &[u8; 32],
    account_id: &arkret_wire::AccountId,
    device_id: &str,
    push_route_id: &str,
    salt_epoch_id: &str,
) -> Result<String, AppError> {
    let input = json!({
        "account_id": account_id,
        "device_id": device_id,
        "push_route_id": push_route_id,
        "salt_epoch_id": salt_epoch_id,
    });
    let canonical = arkret_canonical::canonical_json_bytes(&input)
        .map_err(|error| AppError::internal(format!("push target canonicalize: {error}")))?;
    let epoch_key = hmac_sha256(root_key, salt_epoch_id.as_bytes());
    let tag = hmac_sha256(&epoch_key, &canonical);
    Ok(URL_SAFE_NO_PAD.encode(tag))
}

/// The registration path composes this inline because it also needs the bare
/// tag for `push_registration_id`. Only the derivation tests want the wire
/// spelling on its own, so this carries their gate rather than an allow.
#[cfg(test)]
fn derive_push_target_id(
    root_key: &[u8; 32],
    account_id: &arkret_wire::AccountId,
    device_id: &str,
    push_route_id: &str,
    salt_epoch_id: &str,
) -> Result<arkret_identifiers::PushTargetId, AppError> {
    let tag = derive_push_target_tag(
        root_key,
        account_id,
        device_id,
        push_route_id,
        salt_epoch_id,
    )?;
    arkret_identifiers::PushTargetId::new(format!("{PUSH_TARGET_ID_PREFIX}{tag}"))
        .map_err(|error| AppError::internal(format!("derived push target is invalid: {error}")))
}

#[salvo::oapi::endpoint(operation_id = "ak.edge.push.command.register_device", tags("interop"))]
#[tracing::instrument(skip_all, fields(op = "ak.edge.push.command.register_device.v1"))]
pub(super) async fn push_register(
    body: JsonBody<PushRegisterDeviceRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<arkret_models_integration::models_push::PushRegisterDeviceOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let auth_result = authenticated_session(state, req);
    let body = body.into_inner();
    let session = match auth_result.await {
        Ok(session) => session,
        Err((_status, code, message)) => {
            return Err(AppError::from_rejection(
                coland_http::error::ErrorCode::from_wire(code)
                    .unwrap_or(coland_http::error::ErrorCode::InternalError),
                message,
            ));
        }
    };
    if body.device_id.as_str().trim().is_empty() {
        return Err(AppError::param_invalid("invalid device_id"));
    }
    let account_id = crate::routing::identity::auth_grant_dpop::authenticated_session_account_id(
        state, &session,
    )
    .await?;
    if account_id.station_id.as_str() != state.service_id() {
        return Err(AppError::param_invalid(
            "registration account must belong to this Station",
        ));
    }
    let device_id = body.device_id.as_str().to_owned();
    let authorization =
        crate::routing::identity::device_generation::active_device_revocation_gate_selector(
            state,
            account_id.principal_id.as_str(),
            &device_id,
        )
        .await
        .map_err(|error| AppError::capability_denied(error.to_string()))?;
    let push_route_id = push_route_id_for_registration(&body);
    let prepared_at = now();
    let salt_epoch_id = push_target_salt_epoch_id_at(prepared_at);
    let push_target_tag = derive_push_target_tag(
        state.deliveries().push_target_hmac_key(),
        &account_id,
        &device_id,
        &push_route_id,
        &salt_epoch_id,
    )?;
    let push_target_id =
        arkret_identifiers::PushTargetId::new(format!("{PUSH_TARGET_ID_PREFIX}{push_target_tag}"))
            .map_err(|error| {
                AppError::internal(format!("derived push target is invalid: {error}"))
            })?;
    let session_revocation_ref = match session.session_grant.as_ref() {
        Some(grant)
            if grant.credential_class
                == arkret_models_identity::SessionGrantCredentialClass::Standard
                && matches!(
                    &grant.holder_binding,
                    arkret_models_identity::SessionGrantHolderBinding::HumanDevice { .. }
                )
                && grant
                    .revocation_ref
                    .starts_with("org.arkret.coauth.browser_session:")
                && grant.revocation_ref != "org.arkret.coauth.browser_session:" =>
        {
            Some(grant.revocation_ref.as_str())
        }
        #[cfg(any(test, feature = "conformance-harness"))]
        None if state.config().development_harness_enabled() => None,
        _ => {
            return Err(AppError::unauthenticated(
                "public push registration requires a browser-bound standard human grant",
            ));
        }
    };
    let outcome = super::push_handoff::register(
        state,
        super::push_handoff::PublicPushRegistration {
            account_id,
            authorization: &authorization,
            body,
            push_route_id,
            push_target_id,
            prepared_at,
            session_revocation_ref,
        },
    )
    .await?;
    json_ok(outcome)
}

fn push_route_id_for_registration(body: &PushRegisterDeviceRequestBody) -> String {
    body.app_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .or_else(|| {
            body.platform
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(|value| format!("platform:{value}"))
        })
        .unwrap_or_else(|| {
            let route_digest =
                sha256_hex(format!("{}|{}", body.push_gateway_url, body.push_key).as_bytes());
            format!("gateway:{route_digest}")
        })
}

#[salvo::oapi::endpoint(
    operation_id = "ak.edge.push.command.unregister_device",
    tags("interop")
)]
#[tracing::instrument(skip_all, fields(op = "ak.edge.push.command.unregister_device.v1"))]
pub(super) async fn push_unregister(
    aa: AuthArgs,
    body: JsonBody<PushUnregisterDeviceRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
    res: &mut Response,
) -> Result<(), AppError> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let body = body.into_inner();
    if body.device_id.as_str().trim().is_empty() {
        return Err(AppError::param_invalid("invalid device_id"));
    }
    let account_id = crate::routing::identity::auth_grant_dpop::authenticated_session_account_id(
        state, &session,
    )
    .await?;
    if account_id.station_id.as_str() != state.service_id() {
        return Err(AppError::param_invalid(
            "registration account must belong to this Station",
        ));
    }
    let public_confirmed = super::push_handoff::unregister(
        state,
        &account_id,
        &body.device_id,
        body.push_key.as_deref(),
        body.app_id.as_deref(),
    )
    .await?;
    let removed = state
        .deliveries()
        .unregister_push_device(
            &account_id,
            body.device_id.as_str(),
            body.push_key.as_deref(),
            body.app_id.as_deref(),
        )
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    append_audit_log(
        state,
        Some(&session.actor),
        "push.unregister_device",
        json!({
            "device_id": body.device_id,
            "app_id": body.app_id,
            "removed_count": removed,
            "public_handoffs_confirmed": public_confirmed,
        }),
        if removed == 0 && public_confirmed == 0 {
            "no_match"
        } else {
            "accepted"
        },
    )
    .await;
    res.status_code(StatusCode::NO_CONTENT);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn push_target_derivation_is_pairwise_and_stable() {
        let root_key = [7u8; 32];
        let epoch = "ak.push.salt_epoch.42";
        let first = derive_push_target_id(
            &root_key,
            &arkret_wire::AccountId::new(
                arkret_wire::DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
                arkret_wire::DidCoreId::new("ak:did_core:web:coland.example").unwrap(),
            ),
            "ak:device:01904100-0000-7000-8000-000000000001",
            "inkson.web",
            epoch,
        )
        .unwrap();
        let again = derive_push_target_id(
            &root_key,
            &arkret_wire::AccountId::new(
                arkret_wire::DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
                arkret_wire::DidCoreId::new("ak:did_core:web:coland.example").unwrap(),
            ),
            "ak:device:01904100-0000-7000-8000-000000000001",
            "inkson.web",
            epoch,
        )
        .unwrap();
        let other_route = derive_push_target_id(
            &root_key,
            &arkret_wire::AccountId::new(
                arkret_wire::DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
                arkret_wire::DidCoreId::new("ak:did_core:web:coland.example").unwrap(),
            ),
            "ak:device:01904100-0000-7000-8000-000000000001",
            "inkson.voip",
            epoch,
        )
        .unwrap();
        let other_service = derive_push_target_id(
            &root_key,
            &arkret_wire::AccountId::new(
                arkret_wire::DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
                arkret_wire::DidCoreId::new("ak:did_core:web:org.example").unwrap(),
            ),
            "ak:device:01904100-0000-7000-8000-000000000001",
            "inkson.web",
            epoch,
        )
        .unwrap();

        assert_eq!(first, again);
        assert_ne!(first, other_route);
        assert_ne!(first, other_service);
        assert!(!first.as_str().contains("alice"));
        assert!(!first.as_str().contains("device"));
    }
}
