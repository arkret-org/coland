#[cfg(any(test, feature = "conformance-harness"))]
use coland_services::identity::{
    DeviceIdentity, FindAccountByActorQuery, RegisterAccountCommand, SaveDeviceCommand,
    SessionIdentityState,
};

use super::*;

/// `device-lifecycle.md` §5 — only an accepted `ak.device.authorize` can put a
/// device into the authorized set, and §5.1 makes even the founding device go
/// through the PCR genesis unit. A session login therefore never promotes a
/// device: it may only preserve a verification state some accepted
/// authorization already established. Treating "this account has no device
/// yet" as authorization would mint exactly the row §5 calls a projection
/// integrity failure — `verified` with no `device_authorize_event_id` — which
/// every revocation-gate read then has to reject as an internal fault.
#[cfg(any(test, feature = "conformance-harness"))]
fn initial_session_device_verification_state<'a>(
    existing_devices: &'a [coland_services::identity::DeviceIdentity],
    device_id: &str,
) -> &'a str {
    if existing_devices
        .iter()
        .any(|device| device.device_id == device_id && device.verification_state == "verified")
    {
        "verified"
    } else {
        "unverified"
    }
}

#[cfg(any(test, feature = "conformance-harness"))]
fn account_new_session_error(state: &AppState, actor: &str) -> Option<AppError> {
    account_new_session_tuple(state, actor).map(|(_status, code, reason_detail, message)| {
        AppError::capability_denied(message)
            .with_wire_code(code)
            .with_reason_detail(reason_detail)
    })
}

/// Lifecycle gate for new session issuance. Wire codes come from the spec
/// error-code-registry. These are account-lifecycle denials rather than
/// generic policy denials, so the stable wire code names the lifecycle state.
#[cfg(any(test, feature = "conformance-harness"))]
pub(crate) fn account_new_session_tuple(
    state: &AppState,
    actor: &str,
) -> Option<(StatusCode, &'static str, &'static str, &'static str)> {
    match state.account_lifecycle_state(actor).as_str() {
        "locked" => Some((
            StatusCode::FORBIDDEN,
            ErrorCode::AccountLocked.as_str(),
            "account_status=locked",
            "account is locked",
        )),
        "suspended" => Some((
            StatusCode::FORBIDDEN,
            ErrorCode::AccountSuspended.as_str(),
            "account_status=suspended",
            "account is suspended",
        )),
        "deactivated" => Some((
            StatusCode::FORBIDDEN,
            ErrorCode::AccountDeactivated.as_str(),
            "account_status=deactivated",
            "account has been deactivated",
        )),
        "erasure_pending" => Some((
            StatusCode::UNAUTHORIZED,
            ErrorCode::AccountErased.as_str(),
            "account_status=erasure_pending",
            "account erasure is pending",
        )),
        _ => None,
    }
}

pub(crate) fn account_existing_session_error(
    state: &AppState,
    actor: &str,
) -> Option<(StatusCode, &'static str, &'static str)> {
    // account-lifecycle.md §3: soft_logged_out, locked, deactivated, and
    // erasure_pending invalidate existing session grants. Preserve the
    // lifecycle-specific code instead of collapsing to generic
    // unauthenticated. `suspended` deliberately stays valid here: §3 only
    // refuses new grant issuance for it.
    match state.account_lifecycle_state(actor).as_str() {
        "soft_logged_out" => Some((
            StatusCode::UNAUTHORIZED,
            ErrorCode::SoftLoggedOut.as_str(),
            "account session is logged out",
        )),
        "locked" => Some((
            StatusCode::UNAUTHORIZED,
            ErrorCode::AccountLocked.as_str(),
            "account is locked",
        )),
        "deactivated" => Some((
            StatusCode::UNAUTHORIZED,
            ErrorCode::AccountDeactivated.as_str(),
            "account has been deactivated",
        )),
        "erasure_pending" => Some((
            StatusCode::UNAUTHORIZED,
            ErrorCode::AccountErased.as_str(),
            "account erasure is pending",
        )),
        _ => None,
    }
}

#[cfg(any(test, feature = "conformance-harness"))]
#[salvo::oapi::endpoint(operation_id = "org.arkret.coland.auth.dev_login", tags("identity"))]
#[tracing::instrument(skip_all, fields(op = "org.arkret.coland.auth.dev_login"))]
pub(super) async fn dev_login(
    depot: &mut Depot,
    body: JsonBody<DevLoginRequestBody>,
) -> JsonResult<DevLoginResponseBody> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    if !state.config().development_harness_enabled() {
        return Err(AppError::not_found("endpoint not available"));
    }
    let body = body.into_inner();
    let actor = arkret_wire::DidCoreId::new(body.actor.clone());
    let device_id = validate_device_id(&body.device_id);
    let (actor, device_id) = match (actor, device_id) {
        (Ok(actor), Ok(device_id)) => (actor, device_id),
        _ => {
            return Err(AppError::param_invalid(
                "actor must be a DID core id and device_id is required",
            ));
        }
    };
    let actor_str = actor.as_str();
    let device_id_str = device_id.as_str();
    if device_id_str.trim().is_empty() {
        return Err(AppError::param_invalid(
            "actor must be a DID core id and device_id is required",
        ));
    }
    // Spec: A.3 — auth handlers consult the in-memory failed-login
    // counter before doing anything else. An actor that crossed the
    // threshold gets a 403 `policy_denied` (lockout) until the lockout window
    // expires, without revealing whether the credential would otherwise
    // have been valid.
    let station_id = arkret_wire::DidCoreId::new(state.service_id().clone())
        .map_err(|error| AppError::internal(format!("invalid local Station id: {error}")))?;
    let account_id = arkret_wire::AccountId::new(actor.clone(), station_id);
    let account = state
        .identities()
        .find_account_by_actor(FindAccountByActorQuery {
            account_id: account_id.clone(),
        })
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    if let Some(error) = account_new_session_error(state, actor_str) {
        return Err(error);
    }
    let account_pk = if let Some(account) = account {
        account.account_pk
    } else {
        let synthetic_handle = handle_for_did(actor_str);
        let synthetic_display = body
            .display_name
            .clone()
            .unwrap_or_else(|| synthetic_handle.trim_start_matches('@').to_owned());
        let localpart = normalize_localpart(&synthetic_handle);
        let record = RegisterAccountCommand {
            account_id,
            localpart: localpart.clone(),
            display_name: Some(synthetic_display),
            created_at: now(),
        };
        let registered = state
            .identities()
            .register_account(record.clone())
            .await
            .map_err(|error| AppError::internal(error.to_string()))?;
        append_audit_log(
            state,
            Some(actor_str),
            "account.register",
            json!({"handle": format!("@{localpart}"), "via": "dev_login"}),
            "accepted",
        )
        .await;
        registered.account_pk
    };

    let expires_at = now() + Duration::hours(12);
    let token = token_for(actor_str, device_id_str, expires_at.timestamp_millis());
    let token_hash = session_credential_hash(&token, state.service_id());
    let session = SessionIdentityState {
        token_hash,
        account_pk: Some(account_pk),
        actor: actor_str.to_owned(),
        endpoint: coland_services::identity::SessionEndpointState::HumanDevice {
            device_id: device_id_str.to_owned(),
        },
        audience: state.service_id().clone(),
        // dev-login does not carry a ak.session.grant signing key; bearer-only.
        session_public_key: None,
        session_grant: None,
        expires_at,
        created_at: now(),
        revoked_at: None,
    };
    state
        .sessions()
        .create_session(session)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    let seen_at = now();
    let existing_devices = state
        .identities()
        .devices_for_actor(actor_str)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    let device = session_device_inventory_record(
        &existing_devices,
        actor_str,
        device_id_str,
        body.display_name.clone(),
        seen_at,
    );
    state
        .identities()
        .save_device(SaveDeviceCommand {
            actor_id: actor_str.to_owned(),
            device_id: device_id_str.to_owned(),
            display_name: device.display_name.clone(),
            device,
        })
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    append_audit_log(
        state,
        Some(actor_str),
        "auth.dev_login",
        json!({"device_id": device_id_str}),
        "accepted",
    )
    .await;

    json_ok(DevLoginResponseBody {
        session_credential: token,
        token_type: "Bearer".to_owned(),
        actor: actor.to_string(),
        device_id: device_id.to_string(),
        expires_at,
    })
}

/// Refresh the session metadata for a device without replacing identity
/// material projected from `ak.device.authorize`. Development login is also
/// used by integration clients to obtain a bearer for an already-authorized
/// device, so it must not erase keys, authority bindings, or generation fences.
#[cfg(any(test, feature = "conformance-harness"))]
fn session_device_inventory_record(
    existing_devices: &[DeviceIdentity],
    actor: &str,
    device_id: &str,
    display_name: Option<String>,
    seen_at: chrono::DateTime<chrono::Utc>,
) -> DeviceIdentity {
    let existing = existing_devices
        .iter()
        .find(|device| device.device_id == device_id);
    let verification_state =
        initial_session_device_verification_state(existing_devices, device_id).to_owned();
    let mut payload = existing
        .map(|device| device.payload.clone())
        .filter(serde_json::Value::is_object)
        .unwrap_or_else(|| json!({}));
    let object = payload
        .as_object_mut()
        .expect("session device payload is an object");
    object.insert(
        "device_id".to_owned(),
        serde_json::Value::String(device_id.to_owned()),
    );
    if let Some(name) = display_name.as_ref() {
        object.insert(
            "display_name".to_owned(),
            serde_json::Value::String(name.clone()),
        );
    }
    object.insert(
        "verification".to_owned(),
        serde_json::Value::String(verification_state.clone()),
    );
    object.insert("last_seen_at".to_owned(), json!(seen_at));

    DeviceIdentity {
        actor_id: actor.to_owned(),
        device_id: device_id.to_owned(),
        display_name: display_name
            .or_else(|| existing.and_then(|device| device.display_name.clone())),
        verification_state,
        payload,
        created_at: existing.map_or(seen_at, |device| device.created_at),
        updated_at: seen_at,
        revoked_at: existing.and_then(|device| device.revoked_at),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_refresh_preserves_authorized_device_identity_material() {
        let created_at = now() - Duration::hours(1);
        let seen_at = now();
        let existing = DeviceIdentity {
            actor_id: "ak:did_core:example:alice".to_owned(),
            device_id: "ak:device:01904100-0000-7000-8000-000000000001".to_owned(),
            display_name: Some("Original".to_owned()),
            verification_state: "verified".to_owned(),
            payload: json!({
                "device_id": "ak:device:01904100-0000-7000-8000-000000000001",
                "device_public_key_did": "z6Mkexample",
                "authorized_generation_ref": 1
            }),
            created_at,
            updated_at: created_at,
            revoked_at: None,
        };

        let refreshed = session_device_inventory_record(
            std::slice::from_ref(&existing),
            &existing.actor_id,
            &existing.device_id,
            Some("Refreshed".to_owned()),
            seen_at,
        );

        assert_eq!(refreshed.created_at, created_at);
        assert_eq!(refreshed.verification_state, "verified");
        assert_eq!(refreshed.display_name.as_deref(), Some("Refreshed"));
        assert_eq!(
            refreshed
                .payload
                .get("authorized_generation_ref")
                .and_then(serde_json::Value::as_u64),
            Some(1)
        );
        assert_eq!(
            refreshed
                .payload
                .get("device_public_key_did")
                .and_then(serde_json::Value::as_str),
            Some("z6Mkexample")
        );
    }

    /// `device-lifecycle.md` §5: a session login is never a device
    /// authorization authority. A device with no prior accepted
    /// `ak.device.authorize` — whether the account has no devices at all or
    /// only other devices — stays `unverified` and gains no authorization
    /// binding.
    #[test]
    fn session_login_keeps_new_device_unverified() {
        let seen_at = now();
        let actor = "did:example:alice";
        let other = DeviceIdentity {
            actor_id: actor.to_owned(),
            device_id: "ak:device:01904100-0000-7000-8000-000000000002".to_owned(),
            display_name: Some("Existing".to_owned()),
            verification_state: "verified".to_owned(),
            payload: json!({
                "device_id": "ak:device:01904100-0000-7000-8000-000000000002",
                "device_authorize_event_id": "ak:event:ATyaOl1JkDDCC-6ZytsgoAKvlQJ6s6NJuDC_bmWKARBa",
                "authorized_generation_ref": 1
            }),
            created_at: seen_at,
            updated_at: seen_at,
            revoked_at: None,
        };
        let new_device_id = "ak:device:01904100-0000-7000-8000-000000000003";

        let absent = session_device_inventory_record(&[], actor, new_device_id, None, seen_at);
        assert_eq!(absent.verification_state, "unverified");
        assert!(
            absent.payload.get("device_authorize_event_id").is_none(),
            "login must not mint an authorization binding"
        );

        let alongside_verified = session_device_inventory_record(
            std::slice::from_ref(&other),
            actor,
            new_device_id,
            None,
            seen_at,
        );
        assert_eq!(alongside_verified.verification_state, "unverified");
        assert!(
            alongside_verified
                .payload
                .get("device_authorize_event_id")
                .is_none()
        );
    }

    /// A corrupted projection row — `verified` without its accepted
    /// `device_authorize_event_id` — is a `device-lifecycle.md` §5 projection
    /// integrity failure. Login must neither repair, downgrade nor overwrite
    /// it, and the revocation gate consuming that row MUST fail closed with a
    /// schema violation rather than treating the row as authorized.
    #[test]
    fn session_login_does_not_repair_corrupted_verified_device_row() {
        let created_at = now() - Duration::hours(1);
        let seen_at = now();
        let corrupted = DeviceIdentity {
            actor_id: "ak:did_core:example:alice".to_owned(),
            device_id: "ak:device:01904100-0000-7000-8000-000000000004".to_owned(),
            display_name: Some("Corrupted".to_owned()),
            verification_state: "verified".to_owned(),
            payload: json!({
                "device_id": "ak:device:01904100-0000-7000-8000-000000000004",
                "device_public_key_did": "z6Mkcorrupted"
            }),
            created_at,
            updated_at: created_at,
            revoked_at: None,
        };

        let refreshed = session_device_inventory_record(
            std::slice::from_ref(&corrupted),
            &corrupted.actor_id,
            &corrupted.device_id,
            None,
            seen_at,
        );

        assert_eq!(refreshed.verification_state, "verified");
        assert!(refreshed.payload.get("device_authorize_event_id").is_none());
        assert_eq!(
            refreshed
                .payload
                .get("device_public_key_did")
                .and_then(serde_json::Value::as_str),
            Some("z6Mkcorrupted")
        );
        let gate =
            crate::routing::identity::device_generation::verified_device_authorization_binding(
                &refreshed,
            );
        assert!(
            matches!(gate, Err(coland_services::ServiceError::SchemaViolation(_))),
            "gate must fail closed on the corrupted row: {gate:?}"
        );
    }
}
